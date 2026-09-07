'use strict';

// Admin routes own authorization. Resolve live membership again before dispatch.
const crypto = require('node:crypto');
const { targetsFor, laneEligible, eligibleLaneSql, seenAt } = require('./caldera-lane-agents');
const { defaultSettings } = require('./wazuh-client');
const { isMalwareLane } = require('./malware-analysis-state');
const { readableAgentName, keyFingerprint, rawKeyFingerprint } = require('./wazuh-agent-identity');

const JOB_TIMEOUT_MS = 15 * 60 * 1000;
const QUEUE_TIMEOUT_MS = 4 * 60 * 60 * 1000;
const MAX_BATCH_TARGETS = 200;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const object = value => typeof value === 'string' ? JSON.parse(value) : (value || {});
const jobForVm = (config, vmId) => object(config).wazuh_agent_jobs?.[String(vmId)] || null;
const agentNameFor = (name, vmId) => readableAgentName(name, vmId);
function legacyNameForLane(name, laneId, vmId) {
  const prefix = `cc-${laneId.replaceAll('-', '')}-${vmId}-`;
  return typeof name === 'string' && name.startsWith(prefix) && /^[a-f0-9]{32}$/.test(name.slice(prefix.length));
}
function targetDisplayName(lane, live, vmId) {
  const cfg = object(lane.config);
  const recorded = [...(cfg.vms || []), ...(cfg.workstations || []),
    ...(cfg.attached_modules || []).flatMap(module => module.vms || [])]
    .find(vm => Number(vm.vm_id || vm.vmid) === vmId);
  return recorded?.proxmox_name || recorded?.hostname || live.name
    || targetsFor(lane).find(target => target.vm_id === vmId)?.name || lane.name || 'VM';
}
function failure(status, message) { return Object.assign(new Error(message), { status, safe: true }); }
function runnableGuest(vm) {
  return !!vm && vm.type === 'qemu' && !vm.template && vm.status === 'running'
    && typeof vm.node === 'string' && /^[A-Za-z0-9_.-]+$/.test(vm.node);
}

function currentJob(job, now) {
  if (['running', 'queued'].includes(job?.status) && (!Number.isFinite(Date.parse(job.started_at))
    || now - Date.parse(job.started_at) > (job.status === 'queued' ? QUEUE_TIMEOUT_MS : JOB_TIMEOUT_MS))) {
    return { ...job, status: 'failed', error: 'Installation was interrupted or timed out. Retry to reconnect the managed agent.' };
  }
  return job || null;
}

function publicAgent(agent) {
  return { id: String(agent.id), name: agent.name, status: agent.status, lastKeepAlive: agent.lastKeepAlive || null };
}

function publicJob(job, now) {
  if (!job) return null;
  const safe = currentJob(job, now);
  return Object.fromEntries(['job_id', 'status', 'vm_id', 'platform', 'manager', 'agent_name', 'agent_id',
    'started_at', 'dispatched_at', 'finished_at', 'message', 'error'].filter(key => safe[key] !== undefined)
    .map(key => [key, safe[key]]));
}

// Every lane name across every deployer ends in `-<vxlanId>`; everything before
// that last hyphen is the lane's "family" (cle-cybr388, ciab-cochise101,
// crucible). See cle/utils/lane-provision.js:198 and ciab equivalent at :159.
const NAME_SUFFIX = /^(.*?)-(\d+)$/;

// One coarse label per deployment path, derived from flags the deployers
// already write. Order matters: a bake lane is also `ciab`, and a malware lane
// can also be a course lane, so the most specific test comes first.
function laneKind(cfg) {
  if (cfg.ciab_bake || cfg.staging) return 'staging';
  if (isMalwareLane(cfg)) return 'malware';
  if (cfg.goad) return 'goad';
  if (cfg.profile_lane_group || cfg.ciab) return 'ciab';
  if (cfg.cle && cfg.material_id) return 'course-lab';
  if (cfg.cle || cfg.course_id) return 'course';
  if (cfg.group_id) return 'group';
  if (cfg.challenge_key || cfg.challenge_id) return 'challenge';
  return 'lane';
}

// The grouping/sorting context the admin dialog needs, ENUMERATED BY NAME.
// Never spread cfg or the lane row: lane config carries owner emails and has
// historically carried guest credentials (challenge-lane-deployer.js:2383).
function publicLaneContext(lane, cfg, course) {
  const parsed = String(lane.name || '').match(NAME_SUFFIX);
  const courseId = typeof cfg.course_id === 'string' && UUID.test(cfg.course_id) ? cfg.course_id.toLowerCase() : null;
  return {
    vxlan_id: Number.isSafeInteger(lane.vxlan_id) ? lane.vxlan_id : null,
    lane_number: Number.isSafeInteger(lane.vxlan_id) ? lane.vxlan_id : parsed ? Number(parsed[2]) : null,
    family: parsed ? parsed[1] : null,
    // pg hands back a Date; a service test or a legacy row can hand back a
    // string or garbage. new Date(x).toISOString() would throw RangeError and
    // take the whole inventory response with it.
    created_at: Number.isFinite(Date.parse(lane.created_at)) ? new Date(lane.created_at).toISOString() : null,
    kind: laneKind(cfg),
    course_id: courseId,
    course_code: course?.courseCode || null,
    course_name: course?.courseName || (typeof cfg.course_name === 'string' ? cfg.course_name.slice(0, 120) : null),
    group_id: cfg.group_id != null && cfg.group_id !== '' ? String(cfg.group_id) : null,
    group_label: typeof cfg.group_name === 'string' && cfg.group_name.trim() ? cfg.group_name.trim().slice(0, 120) : null,
    material_id: typeof cfg.material_id === 'string' ? cfg.material_id : null,
  };
}

const INSTALL_ERRORS = {
  'preflight-failed': 'The Wazuh installer could not complete its initial guest checks. Review guest permissions and the existing installation.',
  'root-required': 'The Wazuh installer requires root privileges on this Linux VM.',
  'administrator-required': 'The Wazuh installer requires administrator privileges on this Windows VM.',
  'installation-busy': 'Another Wazuh installation is running on this VM. Wait for it to finish, then retry.',
  'manager-conflict': 'This VM is configured for another Wazuh manager. Review its existing configuration before retrying.',
  'identity-conflict': 'This VM already has a different Wazuh identity. Review its existing registration before retrying.',
  'existing-installation-invalid': 'The existing Wazuh installation is incomplete or uses an unexpected service path. Review it before retrying.',
  'unsafe-installation-path': 'The Wazuh installation or staging path is redirected or unsafe. Review guest directory permissions and links.',
  'dependency-missing': 'A required installer dependency is missing on this VM. Check its package tools and Python 3 on Linux.',
  'python3-missing': 'Python 3 is required on Linux to safely check and preserve Wazuh configuration. Install it and retry.',
  'systemd-required': 'This Linux installer requires systemd to manage the Wazuh service.',
  'manager-installation': 'The selected VM runs a Wazuh manager and cannot receive an agent installation.',
  'unsupported-package-manager': 'This Linux VM needs a supported Debian or RPM package manager.',
  'unsupported-architecture': 'This VM architecture is not supported by the Wazuh installer.',
  'unsupported-platform': 'The selected installer does not support this VM operating system. Review the platform selection.',
  'download-failed': 'Could not download the Wazuh package or checksum. Check guest HTTPS access to packages.wazuh.com and the configured agent version.',
  'checksum-invalid': 'The downloaded Wazuh checksum was invalid. Check package availability and any proxy filtering downloads.',
  'checksum-mismatch': 'The downloaded Wazuh package did not match its SHA-512 checksum. Retry the download and check any proxy or cache.',
  'package-install-failed': 'The Wazuh package could not be installed. Check guest package manager logs and retry.',
  'configuration-invalid': 'The existing Wazuh configuration could not be safely parsed. Review ossec.conf before retrying.',
  'configuration-failed': 'The Wazuh configuration could not be updated. Check guest file permissions and available disk space.',
  'key-import-failed': 'The Wazuh enrollment key could not be imported or verified. Check the existing agent installation and registration.',
  'service-stop-failed': 'The existing Wazuh agent service could not be stopped. Check its guest service status before retrying.',
  'service-start-failed': 'The Wazuh agent service could not be started. Check its guest service logs and ossec.conf.',
};
function installationError(stdout) {
  for (const match of String(stdout || '').matchAll(/^CYBERCORE_WAZUH_ERROR:([a-z0-9-]+)\r?$/gm)) {
    if (INSTALL_ERRORS[match[1]]) return INSTALL_ERRORS[match[1]];
  }
  return 'Agent installation failed. Check guest installer logs, package availability and connectivity to the Wazuh manager.';
}

function createService(deps = {}) {
  const query = deps.query || ((...args) => require('./cybercore-db').cybercoreQuery(...args));
  const settings = deps.settings || defaultSettings;
  const now = deps.now || Date.now;
  const sleep = deps.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const executor = () => deps.executor || require('./script-executor');
  const buildScript = args => (deps.buildInstallScript || require('./wazuh-agent-scripts').buildInstallScript)(args);
  const proxmox = (...args) => (deps.proxmox || require('./proxmox').proxmoxAPI)(...args);
  const ensureGatewayAccess = deps.ensureGatewayAccess || require('./wazuh-gateway-access').ensureWazuhGatewayAccess;
  // Course labels come from cle_db, which core cannot join. course-directory.js
  // is the sanctioned seam and degrades to null rather than throwing. The memo
  // is per SERVICE INSTANCE (not module level) so route/service tests start
  // cold, and it is keyed on the injectable now() so TTL expiry is testable.
  const courseDirectory = deps.courseDirectory || require('./course-directory');
  const deadline = deps.deadline || (ms => new Promise(resolve => {
    const timer = setTimeout(() => resolve(null), ms);
    if (timer.unref) timer.unref();
  }));
  const COURSE_HIT_TTL_MS = 60 * 1000;
  const COURSE_MISS_TTL_MS = 10 * 1000;
  const COURSE_DEADLINE_MS = 1500;
  const courseMemo = new Map();
  async function describeCourses(ids) {
    const out = new Map();
    // No provider registered (any non-CLE deployment) means every lookup would
    // resolve null anyway; skip the work rather than repeat it every 5 seconds.
    if (!ids.length || !courseDirectory.hasCourseDirectory()) return out;
    const at = now();
    if (courseMemo.size > 1000) courseMemo.clear();
    await Promise.all([...new Set(ids)].map(async id => {
      const hit = courseMemo.get(id);
      if (hit && at - hit.at < (hit.course ? COURSE_HIT_TTL_MS : COURSE_MISS_TTL_MS)) { out.set(id, hit.course); return; }
      let course = null;
      // A slow (rather than dead) cle_db must not hold up a polled inventory
      // request; a miss is cached briefly so recovery is still quick.
      try { course = await Promise.race([courseDirectory.describeCourse(id), deadline(COURSE_DEADLINE_MS)]); }
      catch (_) { course = null; }
      courseMemo.set(id, { course: course || null, at });
      out.set(id, course || null);
    }));
    return out;
  }
  const pending = [];
  let active = 0;
  function pump() {
    while (active < 4 && pending.length) {
      const task = pending.shift();
      active++;
      const run = async () => { try { await task(); } finally { active--; pump(); } };
      if (deps.schedule) deps.schedule(run); else setImmediate(run);
    }
  }
  function enqueue(task) { pending.push(task); pump(); }

  async function listAgents(config) {
    const agents = await config.client.listAgents();
    if (!Array.isArray(agents)) throw failure(502, 'Wazuh returned an invalid agent list.');
    return agents;
  }

  async function loadResources() {
    let resources;
    try { resources = await proxmox('GET', '/api2/json/cluster/resources?type=vm'); }
    catch (_) { throw failure(503, 'Could not verify VM power states in Proxmox. Refresh status and retry.'); }
    if (!Array.isArray(resources)) throw failure(503, 'Could not verify VM power states in Proxmox. Refresh status and retry.');
    return resources;
  }

  async function readLane(laneId) {
    return (await query('SELECT lane_id, name, status, vxlan_id, config FROM cybercore_lane WHERE lane_id = $1', [laneId])).rows[0];
  }

  function assertTarget(lane, vmId, job = null) {
    if (!laneEligible(lane) || !targetsFor(lane).some(t => t.vm_id === vmId)) {
      throw failure(409, 'The selected VM is no longer in an available lane.');
    }
    if (object(lane.config).wazuh_teardown_started === true) {
      throw failure(409, 'This lane is being destroyed. Wazuh installation is no longer available.');
    }
    if (object(lane.config).internet_enabled === false) {
      throw failure(409, 'Lane internet access is disabled. Enable Internet for this lane before installing a Wazuh agent.');
    }
    if (isMalwareLane(object(lane.config))) {
      throw failure(409, 'Central Wazuh deployment cannot open gateway access on a malware analysis lane.');
    }
    if (job) {
      const stored = currentJob(jobForVm(lane.config, vmId), now());
      if (stored?.job_id !== job.job_id || !['queued', 'running'].includes(stored.status)) {
        throw failure(409, 'This installation job expired or was replaced. Refresh status and retry.');
      }
    }
  }

  async function revalidate(laneId, job) {
    const live = (await loadResources()).find(vm => Number(vm.vmid) === job.vm_id);
    if (!runnableGuest(live)) throw failure(409, 'The selected VM must be a running QEMU guest. Refresh status after starting it.');
    assertTarget(await readLane(laneId), job.vm_id, job);
    return live;
  }

  async function status(lanes) {
    let config = null, configuration_error = null, agents_error = null, agents = [];
    let resources = [], power_error = null, courses = new Map();
    try { config = settings(); }
    catch (error) { configuration_error = error.safe ? error.message : 'The Wazuh manager and API connection are not configured correctly.'; }
    // Parsed once: every lane's config is read twice below (targets and context).
    const cfgs = lanes.map(lane => object(lane.config));
    await Promise.all([
      (async () => {
        if (!lanes.length) return;
        try { resources = await loadResources(); }
        catch (error) { power_error = error.message; }
      })(),
      (async () => {
        if (!config) return;
        try { agents = await listAgents(config); }
        catch (_) { agents_error = 'Could not read Wazuh check-ins. Check API connectivity, credentials and TLS trust.'; }
      })(),
      (async () => {
        // Labels are cosmetic. A directory outage degrades the dialog's group
        // headings to lane-name prefixes; it never becomes an inventory error.
        try {
          courses = await describeCourses(cfgs
            .map(cfg => typeof cfg.course_id === 'string' && UUID.test(cfg.course_id) ? cfg.course_id.toLowerCase() : null)
            .filter(Boolean));
        } catch (_) { courses = new Map(); }
      })(),
    ]);
    const byId = new Map(resources.map(vm => [Number(vm.vmid), vm]));
    return { manager: config?.manager || null, console_url: config?.consoleUrl || null,
      configuration_error, agents_error, power_error,
      lanes: lanes.map((lane, index) => {
        const cfg = cfgs[index];
        const targets = targetsFor(lane).map(target => {
          const live = byId.get(target.vm_id);
          const job = jobForVm(cfg, target.vm_id);
          const agent = job?.manager === config?.manager && agents.find(item => item.name === job.agent_name
            && (!job.agent_id || String(item.id) === String(job.agent_id)));
          return { vm_id: target.vm_id, name: target.name, platform: target.platform, type: target.type,
            role: target.role || '',
            power_state: live?.status || 'unknown', runnable: laneEligible(lane) && runnableGuest(live)
              && !isMalwareLane(cfg) && cfg.wazuh_teardown_started !== true,
            agent: agent ? publicAgent(agent) : null };
        });
        const targetIds = new Set(targets.map(target => target.vm_id));
        const jobs = Object.values(cfg.wazuh_agent_jobs || {}).filter(job => job && targetIds.has(Number(job.vm_id)));
        return { lane_id: lane.lane_id, name: lane.name, lane_status: lane.status,
          runnable: targets.some(target => target.runnable),
          internet_enabled: typeof cfg.internet_enabled === 'boolean' ? cfg.internet_enabled : null,
          ...publicLaneContext(lane, cfg, courses.get(typeof cfg.course_id === 'string' ? cfg.course_id.toLowerCase() : '')),
          targets, jobs: jobs.map(job => publicJob(job, now())),
          agents: agents.filter(agent => jobs.some(job => job.manager === config?.manager
            && job.agent_name === agent.name && (!job.agent_id || String(job.agent_id) === String(agent.id)))).map(publicAgent) };
      }) };
  }

  async function saveJob(laneId, job) {
    const result = await query(`UPDATE cybercore_lane SET config = jsonb_set(config, '{wazuh_agent_jobs}',
      COALESCE(config->'wazuh_agent_jobs', '{}'::jsonb) || jsonb_build_object($4::text, $2::jsonb)), updated_at = NOW()
      WHERE lane_id = $1 AND config->'wazuh_agent_jobs'->$4::text->>'job_id' = $3 RETURNING lane_id`,
    [laneId, JSON.stringify(job), job.job_id, String(job.vm_id)]);
    return !!result.rows.length;
  }

  async function saveOwned(laneId, job) {
    if (!await saveJob(laneId, job)) throw failure(409, 'This installation job was replaced or its lane was removed.');
  }

  async function enrollment(laneId, config, job) {
    if (config.agentGroup) await config.client.assertGroupExists(config.agentGroup);
    const agents = await listAgents(config);
    const prior = job.agent_id ? agents.find(agent => String(agent.id) === String(job.agent_id))
      : agents.find(agent => agent.name === job.agent_name);
    if (prior && prior.name !== job.agent_name) throw failure(409, 'The saved Wazuh agent ID belongs to a different identity. Review the registration before retrying.');
    if (job.agent_id && !prior) throw failure(409, 'The saved Wazuh agent registration is missing. Review the registration before retrying.');
    let previousKey;
    const groups = new Set(config.agentGroup ? [config.agentGroup] : []);
    if (job.previous_agent_name) {
      if (!legacyNameForLane(job.previous_agent_name, laneId, job.vm_id)) {
        throw failure(409, 'The previous Wazuh identity does not belong to this lane and VM.');
      }
      const old = job.previous_agent_id ? agents.find(agent => String(agent.id) === String(job.previous_agent_id))
        : agents.find(agent => agent.name === job.previous_agent_name);
      if (old && old.name !== job.previous_agent_name) {
        throw failure(409, 'The previous Wazuh registration ID belongs to a different identity.');
      }
      if (old) {
        job.previous_agent_id = String(old.id);
        await saveOwned(laneId, job);
        previousKey = await config.client.getAgentKey(job.previous_agent_id);
        keyFingerprint(previousKey, { name: job.previous_agent_name, id: job.previous_agent_id });
        if (old.group !== undefined && (!Array.isArray(old.group) || old.group.some(group => typeof group !== 'string'))) {
          throw failure(502, 'Wazuh did not return valid group membership for the previous registration.');
        }
        for (const group of old.group || []) if (group !== 'default') groups.add(group);
      } else if (!prior && job.previous_agent_id) {
        throw failure(409, 'The previous Wazuh registration is missing. Review the guest identity before renaming it.');
      } else if (!job.previous_agent_id) {
        // Legacy jobs saved a name before their first enrollment attempt. No
        // registration means this is a fresh install, with normal guest guards.
        delete job.previous_agent_name;
      }
    }
    const readable = job.name_version === 2;
    if (readable && (!UUID.test(job.registration_owner || '') || !Array.isArray(job.registration_key_hashes)
      || job.registration_key_hashes.length > 64
      || job.registration_key_hashes.some(hash => !/^[a-f0-9]{64}$/.test(hash)))) {
      throw failure(409, 'The saved Wazuh registration ownership could not be verified.');
    }
    let key;
    if (prior) {
      key = await config.client.getAgentKey(String(prior.id));
      if (readable && !job.registration_key_hashes.includes(keyFingerprint(key, { name: job.agent_name, id: String(prior.id) }))) {
        throw failure(409, 'This readable Wazuh name is already registered to another identity. Its registration was not changed.');
      }
      job.agent_id = String(prior.id);
      await saveOwned(laneId, job);
    } else {
      // Authorize the random key BEFORE creating a readable registration. A
      // later retry can prove ownership even if the API response was lost.
      let rawKey;
      if (readable) {
        if (job.registration_key_hashes.length >= 64) throw failure(409, 'This registration has too many interrupted attempts. Review it before retrying.');
        rawKey = crypto.randomBytes(32).toString('hex');
        job.registration_key_hashes.push(rawKeyFingerprint(rawKey));
        await saveOwned(laneId, job);
      }
      await revalidate(laneId, job);
      const created = await config.client.createAgent(job.agent_name, rawKey ? { key: rawKey } : undefined);
      job.agent_id = String(created.id);
      await saveOwned(laneId, job);
      key = created.key || await config.client.getAgentKey(job.agent_id);
    }
    if (typeof key !== 'string' || !key) throw failure(502, 'Wazuh did not return an enrollment key.');
    if (readable && !job.registration_key_hashes.includes(keyFingerprint(key, { name: job.agent_name, id: job.agent_id }))) {
      throw failure(502, 'Wazuh did not confirm the authorized registration key.');
    }
    for (const group of groups) {
      await revalidate(laneId, job);
      await config.client.ensureAgentGroup(job.agent_id, group);
    }
    return { key, previousKey };
  }

  async function execute(laneId, config, job) {
    try {
      const live = await revalidate(laneId, job);
      job.status = 'running'; job.started_at = new Date(now()).toISOString();
      job.message = 'Checking the VM guest agent.';
      await saveOwned(laneId, job);
      const exec = executor();
      if (!await exec.waitForGuestAgent(live.node, job.vm_id, 15000)) {
        throw failure(409, 'The QEMU guest agent is unavailable. Start or install it in the selected VM, then retry.');
      }
      await revalidate(laneId, job);
      job.message = 'Preparing Wazuh access on the lane gateway.';
      await saveOwned(laneId, job);
      const readAuthorizedLane = async () => {
        await revalidate(laneId, job);
        const lane = await readLane(laneId);
        assertTarget(lane, job.vm_id, job);
        return lane;
      };
      await ensureGatewayAccess({ lane: await readAuthorizedLane(), vmId: job.vm_id, manager: config.manager },
        { proxmox, readLane: readAuthorizedLane });
      await revalidate(laneId, job);
      const { key, previousKey } = await enrollment(laneId, config, job);
      const script = buildScript({ platform: job.platform, manager: config.manager, version: config.version,
        agentName: job.agent_name, agentKey: key,
        ...(previousKey ? { previousAgentName: job.previous_agent_name, previousAgentKey: previousKey } : {}) });
      job.message = 'Installing and starting the Wazuh agent.';
      await saveOwned(laneId, job);
      // Recheck power, lane membership and ownership after all enrollment/guest
      // readiness waits, immediately before any guest modification.
      const dispatch = await revalidate(laneId, job);
      job.dispatched_at = new Date(now()).toISOString();
      const argv = job.platform === 'windows'
        ? ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')]
        : ['/bin/sh', '-c', script];
      const started = job.platform === 'windows'
        ? await exec.agentExecArgv(dispatch.node, job.vm_id, argv)
        : await exec.proxmoxFormPOST(`/api2/json/nodes/${dispatch.node}/qemu/${job.vm_id}/agent/exec`, argv.map(arg => ['command', arg]));
      if (!started?.pid) throw failure(502, 'Guest execution did not return a process ID.');
      await saveOwned(laneId, job);
      const result = await exec.pollExecStatus(dispatch.node, job.vm_id, started.pid, 600000);
      if (!result.exited || result.exitcode !== 0 || !String(result.stdout || '').split(/\r?\n/).includes(`CYBERCORE_WAZUH_STARTED:${job.agent_name}`)) {
        throw failure(502, installationError(`${result.stdout || ''}\n${result.stderr || ''}`));
      }
      job.message = 'Agent started. Waiting for a fresh Wazuh check-in.';
      await saveOwned(laneId, job);
      for (let attempt = 0; attempt < 12; attempt++) {
        let agents = [];
        try { agents = await listAgents(config); } catch (_) { /* bounded retries */ }
        const agent = agents.find(item => String(item.id) === job.agent_id && item.name === job.agent_name
          && item.status === 'active' && seenAt(item.lastKeepAlive) > Date.parse(job.dispatched_at));
        if (agent) {
          if (job.previous_agent_id && job.previous_agent_name) {
            job.message = 'The renamed agent is active. Removing its previous registration.';
            await saveOwned(laneId, job);
            await revalidate(laneId, job);
            await config.client.deleteAgent(job.previous_agent_id, job.previous_agent_name);
            delete job.previous_agent_id;
            delete job.previous_agent_name;
          }
          job.status = 'completed'; job.message = 'Agent is active and sent a fresh Wazuh check-in.';
          job.finished_at = new Date(now()).toISOString();
          await saveOwned(laneId, job);
          return;
        }
        if (attempt < 11) await sleep(5000);
      }
      throw failure(504, 'Wazuh started, but no fresh active check-in was received. Check lane DNS, manager TCP 1514 access and guest service logs.');
    } catch (error) {
      job.status = 'failed';
      // Never publish upstream/guest exception text: it can include the entire
      // credential-bearing script, decoded enrollment key or API credentials.
      job.error = error.safe ? error.message : 'Wazuh deployment failed. Check server connectivity and guest installer logs, then retry.';
      job.message = job.error; job.finished_at = new Date(now()).toISOString();
      await saveJob(laneId, job);
    }
  }

  async function start(lane, input, preflight = null) {
    if (!lane || !UUID.test(lane.lane_id)) throw failure(409, 'This lane is unavailable for agent installation.');
    if (!Number.isSafeInteger(input.vm_id) || !['windows', 'linux'].includes(input.platform)) {
      throw failure(400, 'Choose a VM and its Windows or Linux platform.');
    }
    assertTarget(lane, input.vm_id);
    const config = preflight?.config || settings();
    if (!preflight) {
      if (config.agentGroup) await config.client.assertGroupExists(config.agentGroup);
      try { await listAgents(config); } catch (_) { throw failure(503, 'Wazuh is unavailable. Check API connectivity, credentials and TLS trust.'); }
    }
    const live = preflight?.byId.get(input.vm_id) || (!preflight && (await loadResources()).find(vm => Number(vm.vmid) === input.vm_id));
    if (!runnableGuest(live)) throw failure(409, 'The selected VM must be a running QEMU guest.');
    const current = await readLane(lane.lane_id);
    assertTarget(current, input.vm_id);
    const previous = jobForVm(current.config, input.vm_id);
    if (previous?.manager && previous.manager !== config.manager) {
      throw failure(409, 'This VM has a saved registration for another Wazuh manager. Review it before changing managers.');
    }
    const jobId = crypto.randomUUID();
    const renameLegacy = legacyNameForLane(previous?.agent_name, lane.lane_id, input.vm_id);
    const readable = !previous?.agent_name || renameLegacy || previous.name_version === 2;
    const job = { job_id: jobId, status: 'queued', vm_id: input.vm_id, platform: input.platform,
      manager: config.manager, agent_name: (!renameLegacy && previous?.agent_name)
        || agentNameFor(targetDisplayName(current, live, input.vm_id), input.vm_id),
      ...(!renameLegacy && previous?.agent_id ? { agent_id: previous.agent_id } : {}),
      ...(readable ? { name_version: 2,
        registration_owner: !renameLegacy && previous?.registration_owner || crypto.randomUUID(),
        registration_key_hashes: !renameLegacy && previous?.registration_key_hashes ? [...previous.registration_key_hashes] : [] } : {}),
      ...(renameLegacy ? { previous_agent_name: previous.agent_name,
        ...(previous.agent_id ? { previous_agent_id: previous.agent_id } : {}) }
        : previous?.previous_agent_name ? { previous_agent_name: previous.previous_agent_name,
          ...(previous.previous_agent_id ? { previous_agent_id: previous.previous_agent_id } : {}) } : {}),
      started_at: new Date(now()).toISOString(), message: 'Installation queued.' };
    const vmJob = "COALESCE(config->'wazuh_agent_jobs'->$3::text, '{}'::jsonb)";
    // Atomic claim across app workers, preserving unrelated lane fields and jobs.
    // The previous job ID also prevents a stale request from changing identities.
    const claimed = await query(`UPDATE cybercore_lane SET config = jsonb_set(config, '{wazuh_agent_jobs}',
      COALESCE(config->'wazuh_agent_jobs', '{}'::jsonb) || jsonb_build_object($3::text, $2::jsonb)), updated_at = NOW()
      WHERE lane_id = $1 AND ${eligibleLaneSql()}
        AND config->'internet_enabled' IS DISTINCT FROM 'false'::jsonb
        AND config->'wazuh_teardown_started' IS DISTINCT FROM 'true'::jsonb
        AND (${vmJob})->>'job_id' IS NOT DISTINCT FROM $6::text
        AND (COALESCE((${vmJob})->>'status', '') NOT IN ('running', 'queued')
          OR ((${vmJob})->>'status' = 'running' AND (${vmJob})->>'started_at' < $4)
          OR ((${vmJob})->>'status' = 'queued' AND (${vmJob})->>'started_at' < $5))
      RETURNING lane_id`, [lane.lane_id, JSON.stringify(job), String(input.vm_id),
      new Date(now() - JOB_TIMEOUT_MS).toISOString(), new Date(now() - QUEUE_TIMEOUT_MS).toISOString(), previous?.job_id || null]);
    if (!claimed.rows.length) throw failure(409, 'This lane is unavailable or an agent installation is already running or queued on this VM.');
    enqueue(() => execute(lane.lane_id, config, job).catch(() => {
      console.error('[Wazuh agents] Could not save installation status.');
    }));
    return publicJob(job, now());
  }

  async function startBatch(lanes, input = {}) {
    const targets = input.targets;
    if (!Array.isArray(targets) || !targets.length || targets.length > MAX_BATCH_TARGETS) {
      throw failure(400, `Select between 1 and ${MAX_BATCH_TARGETS} machines.`);
    }
    const byLane = new Map(lanes.map(lane => [lane.lane_id, lane]));
    const seen = new Set();
    for (const target of targets) {
      if (!target || !UUID.test(target.lane_id) || !Number.isSafeInteger(target.vm_id) || !['windows', 'linux'].includes(target.platform)) {
        throw failure(400, 'Every target needs a lane, VM and Windows or Linux platform.');
      }
      const lane = byLane.get(target.lane_id);
      if (!lane || !targetsFor(lane).some(vm => vm.vm_id === target.vm_id)) throw failure(404, 'A selected machine was not found in the available lanes.');
      const key = `${target.lane_id}:${target.vm_id}`;
      if (seen.has(key)) throw failure(400, 'A machine was selected more than once.');
      seen.add(key);
    }
    const config = settings();
    if (config.agentGroup) await config.client.assertGroupExists(config.agentGroup);
    try { await listAgents(config); } catch (_) { throw failure(503, 'Wazuh is unavailable. Check API connectivity, credentials and TLS trust.'); }
    const resources = await loadResources();
    const preflight = { config, byId: new Map(resources.map(vm => [Number(vm.vmid), vm])) };
    const results = [];
    for (const target of targets) {
      try { results.push({ lane_id: target.lane_id, vm_id: target.vm_id, job: await start(byLane.get(target.lane_id), target, preflight) }); }
      catch (error) { results.push({ lane_id: target.lane_id, vm_id: target.vm_id,
        error: error.safe ? error.message : 'Could not queue installation on this VM.', status: error.status || 500 }); }
    }
    return { results };
  }

  return { status, start, startBatch };
}

module.exports = { createService, targetsFor, laneEligible, eligibleLaneSql, defaultSettings,
  currentJob, jobForVm, agentNameFor, JOB_TIMEOUT_MS, QUEUE_TIMEOUT_MS, MAX_BATCH_TARGETS };
