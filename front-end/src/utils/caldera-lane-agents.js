'use strict';

// Course routes own authorization. This service only accepts lanes they resolved.
const crypto = require('node:crypto');
const { buildInstallScript } = require('./caldera-agent-scripts');

const JOB_TIMEOUT_MS = 5 * 60 * 1000;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const object = value => typeof value === 'string' ? JSON.parse(value) : (value || {});
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const groupFor = laneId => `lane-${laneId}`;
const pawFor = (laneId, vmId) => hashToken(`${laneId}:${vmId}`).slice(0, 24);
function failure(status, message) { return Object.assign(new Error(message), { status }); }

function targetsFor(lane) {
  const cfg = object(lane.config);
  const rows = [...(cfg.vms || []), ...(cfg.workstations || []),
    ...(cfg.attached_modules || []).flatMap(mod => mod.vms || [])];
  if (cfg.challenge_vm_id && !rows.length) rows.push({ vm_id: cfg.challenge_vm_id, name: cfg.challenge_key });
  if (cfg.attack_box_vm_id) rows.push({ vm_id: cfg.attack_box_vm_id, name: 'Attack box', os: 'linux' });
  const seen = new Set();
  return rows.flatMap(vm => {
    const id = Number(vm.vm_id || vm.vmid);
    const type = vm.type || vm.provider_type || 'qemu';
    if (!Number.isSafeInteger(id) || id <= 0 || id === Number(cfg.gateway_vm_id)
      || type === 'lxc' || seen.has(id)) return [];
    seen.add(id);
    const hint = [vm.os, vm.template_name, vm.templateName, vm.platform, vm.name].filter(Boolean).join(' ');
    const platform = /windows|win(?:10|11|201\d|202\d)/i.test(hint) ? 'windows'
      : /linux|ubuntu|debian|kali|rocky|centos|alpine|fedora/i.test(hint) ? 'linux' : null;
    return [{ vm_id: id, name: vm.name || vm.hostname || `VM ${id}`,
      node: vm.node || cfg.node || null, role: vm.role || '', type: 'qemu', platform }];
  });
}

function publicAgent(agent) {
  return { paw: agent.paw, host: agent.host, platform: agent.platform, group: agent.group,
    last_seen: agent.last_seen, trusted: agent.trusted };
}

function seenAt(value) {
  const raw = String(value || '').replace(' ', 'T');
  return Date.parse(/(?:Z|[+-]\d\d:\d\d)$/i.test(raw) ? raw : `${raw}Z`);
}

function currentJob(job, now) {
  if (job?.status === 'running' && now - Date.parse(job.started_at) > JOB_TIMEOUT_MS) {
    return { ...job, status: 'failed', error: 'Installation was interrupted or timed out. Retry to reconnect the managed agent.' };
  }
  return job || null;
}

function defaultSettings() {
  const { consoleConfig, authoringConfig } = require('../routes/caldera-authoring');
  const { resolveTarget } = require('../incident/caldera/authoring');
  const console = consoleConfig();
  const target = resolveTarget(authoringConfig());
  const url = console.url && new URL(console.url);
  if (!url || url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || url.pathname !== '/' || !target.client) {
    throw failure(503, 'Configure CALDERA_HOST with the HTTPS Caldera hostname, CALDERA_AUTHORING_UPSTREAM and the Caldera API key.');
  }
  return { serverUrl: url.origin, consoleUrl: url.href, client: target.client };
}

function createService(deps = {}) {
  const query = deps.query || ((...args) => require('./cybercore-db').cybercoreQuery(...args));
  const settings = deps.settings || defaultSettings;
  const now = deps.now || Date.now;
  const sleep = deps.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const executor = () => deps.executor || require('./script-executor');
  const proxmox = (...args) => (deps.proxmox || require('./proxmox').proxmoxAPI)(...args);

  async function listAgents(config) {
    const agents = await config.client.listAgents();
    if (!Array.isArray(agents)) throw failure(502, 'Caldera returned an invalid agent list.');
    return agents;
  }

  async function status(lanes) {
    let config = null, configuration_error = null, agents_error = null, agents = [];
    try { config = settings(); } catch (err) { configuration_error = err.message; }
    if (config) {
      try { agents = await listAgents(config); }
      catch (_) { agents_error = 'Could not read Caldera check-ins. Check the Caldera service and its API key.'; }
    }
    return {
      server_url: config?.serverUrl || null, console_url: config?.consoleUrl || null,
      configuration_error, agents_error,
      lanes: lanes.map(lane => {
        const cfg = object(lane.config);
        return { lane_id: lane.lane_id, name: lane.name, lane_status: lane.status,
          internet_enabled: typeof cfg.internet_enabled === 'boolean' ? cfg.internet_enabled : null, group: groupFor(lane.lane_id),
          targets: targetsFor(lane), agents: agents.filter(a => a.group === groupFor(lane.lane_id)).map(publicAgent),
          job: currentJob(cfg.caldera_agent_job, now()) };
      }),
    };
  }

  async function saveJob(laneId, job) {
    await query(`UPDATE cybercore_lane SET config = jsonb_set(config, '{caldera_agent_job}', $2::jsonb), updated_at = NOW()
      WHERE lane_id = $1 AND config->'caldera_agent_job'->>'job_id' = $3`, [laneId, JSON.stringify(job), job.job_id]);
  }

  async function execute(laneId, courseId, target, token, config, job) {
    try {
      // Re-read immediately before dispatch; a lane deleted or moved since the click cannot be used.
      const row = await query('SELECT lane_id, status, config FROM cybercore_lane WHERE lane_id = $1', [laneId]);
      const lane = row.rows[0];
      if (!lane || lane.status !== 'active' || object(lane.config).course_id !== courseId
        || object(lane.config).caldera_agent_job?.job_id !== job.job_id
        || !targetsFor(lane).some(t => t.vm_id === target.vm_id)) {
        throw failure(409, 'The selected VM is no longer in a running lane.');
      }
      const resources = await proxmox('GET', '/api2/json/cluster/resources?type=vm');
      const live = (resources || []).find(vm => Number(vm.vmid) === target.vm_id);
      if (!live || live.type !== 'qemu' || live.template || live.status !== 'running'
        || !/^[A-Za-z0-9_.-]+$/.test(live.node)) {
        throw failure(409, 'The selected VM must be a running QEMU guest.');
      }
      const exec = executor();
      job.message = 'Checking the VM guest agent.';
      await saveJob(laneId, job);
      if (!await exec.waitForGuestAgent(live.node, target.vm_id, 15000)) {
        throw failure(409, 'The QEMU guest agent is unavailable. Start or install it in the selected VM, then retry.');
      }
      const script = buildInstallScript({ platform: job.platform,
        serverUrl: `${config.serverUrl}/agent/${token}`, group: job.group, paw: job.paw });
      job.message = 'Downloading and starting Sandcat in the selected VM.';
      await saveJob(laneId, job);
      // Neither exec path logs the credential-bearing script text.
      const argv = job.platform === 'windows'
        ? ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')]
        : ['/bin/sh', '-c', script];
      const started = job.platform === 'windows'
        ? await exec.agentExecArgv(live.node, target.vm_id, argv)
        : await exec.proxmoxFormPOST(`/api2/json/nodes/${live.node}/qemu/${target.vm_id}/agent/exec`, argv.map(arg => ['command', arg]));
      if (!started?.pid) throw failure(502, 'Guest execution did not return a process ID.');
      const result = await exec.pollExecStatus(live.node, target.vm_id, started.pid, 120000);
      if (!result.exited || result.exitcode !== 0 || !result.stdout.includes(`CYBERCORE_CALDERA_STARTED:${job.paw}`)) {
        const detail = String(result.stderr || result.stdout || 'Guest execution timed out.').replaceAll(token, '[redacted]').slice(-900);
        throw failure(502, `Agent installation failed. ${detail}`);
      }
      job.message = 'Agent started. Waiting for its first Caldera check-in.';
      await saveJob(laneId, job);
      for (let attempt = 0; attempt < 12; attempt++) {
        let agents = [];
        try { agents = await listAgents(config); } catch (_) { /* bounded retries */ }
        const agent = agents.find(a => a.paw === job.paw && a.group === job.group
          && a.platform === job.platform && seenAt(a.last_seen) >= Date.parse(job.started_at) - 2000);
        if (agent) {
          job.status = 'completed'; job.message = 'Agent checked in to Caldera.';
          job.agent = publicAgent(agent); job.finished_at = new Date(now()).toISOString();
          await saveJob(laneId, job);
          return;
        }
        await sleep(5000);
      }
      throw failure(504, 'Sandcat started, but no fresh Caldera check-in was received. Check lane DNS, outbound HTTPS, the Caldera proxy and guest agent logs.');
    } catch (err) {
      job.status = 'failed'; job.error = String(err.message).replaceAll(token, '[redacted]').slice(0, 1200);
      job.message = job.error; job.finished_at = new Date(now()).toISOString();
      await saveJob(laneId, job);
    }
  }

  async function start(lane, input) {
    if (!UUID.test(lane.lane_id) || lane.status !== 'active') throw failure(409, 'Select a running lane.');
    if (object(lane.config).internet_enabled === false) {
      throw failure(409, 'Lane internet access is disabled. Enable Internet for this lane before installing a Caldera agent.');
    }
    if (!Number.isSafeInteger(input.vm_id) || !['windows', 'linux'].includes(input.platform)) {
      throw failure(400, 'Choose a VM and its Windows or Linux platform.');
    }
    const target = targetsFor(lane).find(t => t.vm_id === input.vm_id);
    if (!target) throw failure(404, 'VM not found in this lane.');
    const config = settings();
    // Validate server-side connectivity before modifying a VM or rotating its token.
    try { await listAgents(config); } catch (_) { throw failure(503, 'Caldera is unavailable or its API key is invalid.'); }
    const token = crypto.randomBytes(32).toString('hex');
    const job = { job_id: crypto.randomUUID(), status: 'running', vm_id: target.vm_id,
      platform: input.platform, group: groupFor(lane.lane_id), paw: pawFor(lane.lane_id, target.vm_id),
      started_at: new Date(now()).toISOString(), message: 'Installation queued.' };
    const access = { vm_id: target.vm_id, token_hash: hashToken(token), paw: job.paw, created_at: job.started_at };
    // Atomic claim: concurrent clicks and app workers cannot launch two installers.
    // JSONB updates retain unrelated lane fields and tokens for other VMs.
    const claimed = await query(`UPDATE cybercore_lane SET config =
      jsonb_set(jsonb_set(config, '{caldera_agent_access}', jsonb_build_object('tokens',
        COALESCE((SELECT jsonb_agg(t) FROM jsonb_array_elements(COALESCE(config->'caldera_agent_access'->'tokens', '[]'::jsonb)) t
          WHERE t->>'vm_id' <> $3::text), '[]'::jsonb) || jsonb_build_array($4::jsonb))),
        '{caldera_agent_job}', $2::jsonb), updated_at = NOW()
      WHERE lane_id = $1 AND status = 'active'
        AND config->>'course_id' IS NOT DISTINCT FROM $6::text
        AND (COALESCE(config->'caldera_agent_job'->>'status', '') <> 'running'
          OR config->'caldera_agent_job'->>'started_at' < $5)
      RETURNING lane_id`, [lane.lane_id, JSON.stringify(job), String(target.vm_id), JSON.stringify(access),
      new Date(now() - JOB_TIMEOUT_MS).toISOString(), object(lane.config).course_id || null]);
    if (!claimed.rows.length) throw failure(409, 'This lane is unavailable or an agent installation is already running.');
    const task = () => execute(lane.lane_id, object(lane.config).course_id, target, token, config, job).catch(() => {
      console.error('[Caldera agents] Could not save installation status.');
    });
    if (deps.schedule) deps.schedule(task); else setImmediate(task);
    return { ...job };
  }

  async function authorize(uri) {
    const match = /^\/agent\/([a-f0-9]{64})\/(?:beacon|file\/download|file\/upload)$/.exec(String(uri || ''));
    if (!match) return null;
    const result = await query(`SELECT l.lane_id, l.config, t->>'paw' AS paw, t->>'vm_id' AS vm_id FROM cybercore_lane l
      CROSS JOIN LATERAL jsonb_array_elements(COALESCE(l.config->'caldera_agent_access'->'tokens', '[]'::jsonb)) t
      WHERE l.status = 'active' AND t->>'token_hash' = $1 LIMIT 1`, [hashToken(match[1])]);
    const access = result.rows[0];
    if (!access || !UUID.test(access.lane_id) || !/^[a-f0-9]{24}$/.test(access.paw)) return null;
    if (!targetsFor(access).some(target => target.vm_id === Number(access.vm_id))) return null;
    return { paw: access.paw, group: groupFor(access.lane_id) };
  }

  return { status, start, authorize };
}

module.exports = { createService, targetsFor, hashToken, pawFor, groupFor, seenAt, currentJob, JOB_TIMEOUT_MS };
