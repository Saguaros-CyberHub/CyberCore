'use strict';

// Course routes own authorization. This service only accepts lanes they resolved.
const crypto = require('node:crypto');
const { buildInstallScript } = require('./caldera-agent-scripts');
// Pure at require time by design: this service is constructed at module load by
// the course routes and required verbatim by unit tests, so nothing it imports
// may open a database pool. See the docblock in lane-environment.js.
const { laneIdentity, studentOf, environmentOf, machineIdentity, createEnvironmentDirectory } = require('./lane-environment');
// The one list of roles that must never be handed an implant. It is the same
// set fact-source excludes from an authored adversary, and for the same reason:
// a machine on it is either lane plumbing, the student's own attack box, or the
// evidence plane the class is graded on reading.
const { INFRASTRUCTURE_ROLES } = require('../incident/caldera/fact-source');

const JOB_TIMEOUT_MS = 5 * 60 * 1000;
const QUEUE_TIMEOUT_MS = 4 * 60 * 60 * 1000;
const MAX_BATCH_TARGETS = 200;
// How long one guest execution is given to report completion.
const EXEC_DEADLINE_MS = 120000;
// Surfaced verbatim to the instructor and matched by the progress card's hint,
// so it must keep the phrase "did not report completion": that is how the card
// knows to explain the detached-agent case instead of repeating a bare timeout.
const EXEC_INCOMPLETE_NOTICE = `The install script did not report completion within ${EXEC_DEADLINE_MS / 1000} seconds. `
  + 'On Windows a detached agent holds the guest execution output open, so this is expected even when the install '
  + 'succeeded. Waiting for the Caldera check-in instead.';
// The window in which a Caldera check-in counts as "this machine is here now".
//
// MIRRORS untrusted_timer IN infrastructure/caldera/conf/agents.yml, and must.
// Caldera stops trusting an agent whose last_seen is older than untrusted_timer;
// freshAgent() below requires trusted === true AND last_seen inside this window,
// and launch() refuses a batch unless every lane has a fresh trusted agent. Set
// this below the beacon interval and every classroom launch is refused on every
// lane, naming agents that are actually healthy.
//
// test/caldera-beacon-coupling.test.js pins this against the beacon config.
const AGENT_FRESH_MS = 300000;
const AGENT_SKEW_MS = 30000;
// How the post-execution wait for a first check-in is bounded. Both bounds are
// needed and they guard different things: ATTEMPTS is the "give Sandcat a
// minute to reach the server" budget this loop has always had, while the
// deadline below is a hard promise to currentJob() and the atomic claim.
// Sized to outlast ONE full beacon interval. Sandcat registers on start, so the
// first check-in normally lands in seconds -- but "normally" is not a budget. If
// that first beacon is missed for any reason the next one is up to sleep_max
// away, and a window shorter than that reports a healthy agent as a failed
// install. 24 x 5 s = 120 s covers sleep_max (90 s) with margin, and still fits
// inside the checkInDeadline below (JOB_TIMEOUT_MS - CHECK_IN_MARGIN_MS = 270 s)
// so nothing here reaches into the job timeout or the atomic claim.
const CHECK_IN_ATTEMPTS = 24;
const CHECK_IN_INTERVAL_MS = 5000;
// Slack left between the last possible check-in read and job.started_at +
// JOB_TIMEOUT_MS. It has to cover one Caldera round trip that is already in
// flight when the deadline passes -- client.js caps that at DEFAULT_TIMEOUT_MS
// (20 s) -- plus the saveJob that records the verdict. Without it a slow
// Caldera pushes execute() past the timeout, where currentJob() rewrites this
// still-running job to the false "Installation was interrupted or timed out"
// failure this whole path exists to remove AND the claim SQL lets a retry steal
// the VM from the installer that is still working on it.
const CHECK_IN_MARGIN_MS = 30000;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const object = value => typeof value === 'string' ? JSON.parse(value) : (value || {});
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const groupFor = laneId => `lane-${laneId}`;
const pawFor = (laneId, vmId) => hashToken(`${laneId}:${vmId}`).slice(0, 24);
// Identity of one unit of queued work, so cancel() can drop it by name.
const queueKey = (laneId, vmId) => `${laneId}:${vmId}`;

/**
 * Machines that are infrastructure by NAME, when nothing else can say so.
 *
 * The role is the better answer and is tried first, but a GOAD deployer writes
 * `{vm_id, name, proxmox_name, type, node}` into lane config with no role at
 * all. So on a GOAD lane the role fallback is empty, and the only other source
 * is the challenge spec -- which the environment directory is explicitly built
 * to survive losing, and which fails for EVERY machine in a lane at once when
 * it does.
 *
 * In that window elk and wazuh look like ordinary servers, get auto-selected in
 * the Machines step, and are swept up by "Only missing agents" -- which installs
 * an implant onto the SIEM holding the evidence the class is graded on reading.
 *
 * EXACT names only, never a substring: a lane may legitimately hold a
 * `kali-workstation` a student is meant to use, and quietly refusing to target
 * it would be its own bug. These six are the fixed names the platform itself
 * assigns.
 */
const INFRASTRUCTURE_NAMES = new Set(['elk', 'wazuh', 'sensor', 'kali', 'loggen', 'log-generator']);
function failure(status, message) { return Object.assign(new Error(message), { status }); }

// Deployment failures retain running guests under 'suspended'. That lifecycle
// status must not be confused with a Proxmox guest's current power state.
function retainedAfterFailure(lane) {
  const cfg = object(lane.config);
  return lane.status === 'suspended' && (
    [cfg.error, cfg.provisioning_error].some(value => typeof value === 'string' && value.trim())
    || cfg.goad?.status === 'failed');
}

function laneEligible(lane) {
  return !!lane && (lane.status === 'active' || retainedAfterFailure(lane));
}

function eligibleLaneSql(alias = '') {
  if (alias && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) throw new TypeError('Invalid lane SQL alias');
  const prefix = alias ? `${alias}.` : '';
  const config = `${prefix}config`;
  const hasError = key => `(jsonb_typeof(${config}->'${key}') = 'string' AND BTRIM(${config}->>'${key}') <> '')`;
  return `(${prefix}status = 'active' OR (${prefix}status = 'suspended' AND (
    ${hasError('error')} OR ${hasError('provisioning_error')} OR ${config}->'goad'->>'status' = 'failed')))`;
}

function runnableGuest(vm) {
  return !!vm && vm.type === 'qemu' && !vm.template && vm.status === 'running'
    && typeof vm.node === 'string' && /^[A-Za-z0-9_.-]+$/.test(vm.node);
}

// Each source list is tagged BEFORE it is flattened, because the flattened row
// cannot say where it came from: a student desktop and a challenge guest are
// both `{vm_id, name}` in lane config, yet one is "Workstation 1" repeated
// across 44 lanes and the other is a named machine inside one environment.
function targetsFor(lane) {
  const cfg = object(lane.config);
  const tag = (list, source, moduleKey = null) =>
    (Array.isArray(list) ? list : []).map(vm => ({ vm, source, moduleKey }));
  const rows = [...tag(cfg.vms, 'environment'), ...tag(cfg.workstations, 'workstation'),
    ...(cfg.attached_modules || []).flatMap(mod => tag(mod.vms, 'attached',
      typeof mod.challenge_key === 'string' && mod.challenge_key.trim() ? mod.challenge_key.trim() : null))];
  if (cfg.challenge_vm_id && !rows.length) {
    rows.push({ vm: { vm_id: cfg.challenge_vm_id, name: cfg.challenge_key }, source: 'challenge', moduleKey: null });
  }
  if (cfg.attack_box_vm_id) {
    rows.push({ vm: { vm_id: cfg.attack_box_vm_id, name: 'Attack box', os: 'linux', role: 'attacker' }, source: 'attack_box', moduleKey: null });
  }
  const seen = new Set();
  return rows.flatMap(({ vm, source, moduleKey }) => {
    const id = Number(vm.vm_id || vm.vmid);
    const type = vm.type || vm.provider_type || 'qemu';
    if (!Number.isSafeInteger(id) || id <= 0 || id === Number(cfg.gateway_vm_id)
      || type === 'lxc' || seen.has(id)) return [];
    seen.add(id);
    const hint = [vm.os, vm.template_name, vm.templateName, vm.platform, vm.name].filter(Boolean).join(' ');
    const platform = /windows|win(?:10|11|201\d|202\d)/i.test(hint) ? 'windows'
      : /linux|ubuntu|debian|kali|rocky|centos|alpine|fedora/i.test(hint) ? 'linux' : null;
    return [{ vm_id: id, name: vm.name || vm.hostname || `VM ${id}`,
      node: vm.node || cfg.node || null, role: vm.role || '', type: 'qemu', platform, source,
      // Lanes provisioned before desktop slots were recorded carry no slot at
      // all, and `slot${undefined}` would fold every one of them into a single
      // bogus machine. Slot 0 is the first desktop, which is what they have.
      slot: Number.isSafeInteger(vm.slot) ? vm.slot : (source === 'workstation' ? 0 : null),
      template_name: vm.template_name || vm.templateName || null,
      module_key: moduleKey }];
  });
}

function publicAgent(agent) {
  return { paw: agent.paw, host: agent.host, platform: agent.platform, group: agent.group,
    last_seen: agent.last_seen, trusted: agent.trusted };
}

// Caldera stamps last_seen with the SERVER's clock, so a lab host running a few
// seconds ahead of it would otherwise look permanently absent; the window
// therefore reaches slightly forward as well as back. An unparseable timestamp
// yields NaN, which fails both comparisons and reads as "not checked in".
function freshAgent(agent, at) {
  return !!agent && agent.trusted === true
    && seenAt(agent.last_seen) >= at - AGENT_FRESH_MS && seenAt(agent.last_seen) <= at + AGENT_SKEW_MS;
}

// The per-VM view of an agent, and deliberately not publicAgent: this row is
// already joined to one machine, so `group` is noise, while `fresh` is the whole
// question the dialog's Agent column asks. Both are whitelists because a raw
// Caldera agent row carries its server address, contact channel and executors.
function publicTargetAgent(agent, at) {
  if (!agent) return null;
  return { paw: agent.paw, host: agent.host, platform: agent.platform,
    last_seen: agent.last_seen, trusted: agent.trusted === true, fresh: freshAgent(agent, at) };
}

// The per-machine job line: enumerated by name, absent keys omitted rather than
// emitted as null, so a job's `paw`, `group`, stored `agent` and prior-agent
// snapshot never ride along with a target row. `exec_incomplete` is carried so
// the dialog can explain the detached-Windows-agent case on the ONE machine it
// happened to, instead of reading the lane's single `job` and captioning every
// row in the lane with it.
const JOB_SUMMARY_KEYS = ['job_id', 'status', 'platform', 'started_at', 'finished_at', 'message', 'error', 'warnings', 'exec_incomplete'];
function publicJobSummary(job) {
  if (!job) return null;
  return Object.fromEntries(JOB_SUMMARY_KEYS.filter(key => job[key] !== undefined).map(key => [key, job[key]]));
}

/**
 * The fields of a Caldera agent row that change when a NEW Sandcat process
 * registers under an EXISTING paw.
 *
 * pawFor() is a hash of (lane, vm): it is deterministic and identical across
 * every reinstall of the same machine, groupFor() is per lane, and nothing in
 * this service or in Caldera ever deletes an agent row. A Sandcat left running
 * by an earlier install therefore keeps beaconing under exactly the paw, group
 * and platform the next install is waiting for, and `last_seen` moving forward
 * proves only that the OLD process is alive.
 *
 * These three are the row fields upstream documents as properties of the
 * REGISTERED PROCESS rather than of the beacon: its pid, the time the server
 * first saw it, and the executable it runs as. Nothing here is verified against
 * a live server (see the banner in caldera/client.js), so the comparison below
 * is written to answer "did something provably change?" and to say no when the
 * release ships none of them -- never to guess a change from a field it did not
 * receive.
 */
const AGENT_IDENTITY_KEYS = ['pid', 'created', 'exe_name'];
const identityValue = value => (value === undefined || value === null || value === '' ? undefined : String(value));

// Enumerated, and never the agent row itself: this snapshot is written into
// lane config, where a whole Caldera agent row would drag its server address,
// contact channel and executor list into a document the dialog polls.
function agentIdentity(agent) {
  if (!agent) return null;
  const identity = {};
  for (const key of AGENT_IDENTITY_KEYS) {
    const value = identityValue(agent[key]);
    if (value !== undefined) identity[key] = value;
  }
  return identity;
}

/**
 * Is this check-in evidence of the install that is running RIGHT NOW?
 *
 * `prior` absent means no agent held this paw when the install started, so any
 * matching agent can only be this one. Otherwise a distinguishing field has to
 * have actually moved. An agent row that carries none of them returns false:
 * "this release does not let me tell the two apart" is reported as a failure to
 * confirm, never as a success.
 */
function agentIsNew(agent, prior) {
  if (!prior) return true;
  return AGENT_IDENTITY_KEYS.some(key => {
    const before = prior[key] === undefined ? undefined : String(prior[key]);
    const after = identityValue(agent && agent[key]);
    return !(before === undefined && after === undefined) && before !== after;
  });
}

/**
 * Shorten a guest-execution error for an instructor-facing message.
 *
 * The middle goes, not the head: script-executor frames its answer as
 * "Timed out (last exec-status error: <proxmox message>)" and that framing is
 * the entire point of the field -- it is how a wedged QEMU guest agent
 * identifies itself instead of reporting a bare deadline. Keeping the tail of a
 * long Proxmox message dropped it every time. Every caller redacts the ingress
 * credential BEFORE calling this, so eliding text here cannot re-expose one.
 */
function trimDetail(text, limit) {
  const value = String(text == null ? '' : text);
  if (value.length <= limit) return value;
  const head = Math.ceil((limit - 3) * 0.6);
  return `${value.slice(0, head)}...${value.slice(head + 3 - limit)}`;
}

function seenAt(value) {
  const raw = String(value || '').replace(' ', 'T');
  return Date.parse(/(?:Z|[+-]\d\d:\d\d)$/i.test(raw) ? raw : `${raw}Z`);
}

function currentJob(job, now) {
  if (['running', 'queued'].includes(job?.status) && now - Date.parse(job.started_at) > (job.status === 'queued' ? QUEUE_TIMEOUT_MS : JOB_TIMEOUT_MS)) {
    return { ...job, status: 'failed', error: 'Installation was interrupted or timed out. Retry to reconnect the managed agent.' };
  }
  return job || null;
}

// specMachines defaults a spec row with no `os` to the literal string
// 'Unknown', so a spec that names a machine but never says what it runs would
// otherwise SHADOW the config's real template_name with a word that tells the
// instructor nothing. 'Unknown' is the absence of an answer, not an answer, and
// it has to fall through to the template name and then to null.
function knownOs(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  return text && text.toLowerCase() !== 'unknown' ? value : null;
}

function jobForVm(config, vmId) {
  const cfg = object(config);
  return cfg.caldera_agent_jobs?.[String(vmId)] || (Number(cfg.caldera_agent_job?.vm_id) === Number(vmId) ? cfg.caldera_agent_job : null);
}

/**
 * How one lane is named, grouped and sorted in a classroom dialog.
 *
 * Enumerated by name and never spread from the lane row or its config: config
 * carries the owner's email and has historically carried guest credentials, and
 * this response is polled into a browser every few seconds.
 */
function laneContext(lane, cfg, envs) {
  const provisional = environmentOf(lane, cfg);
  const described = provisional.challenge_key && envs && typeof envs.get === 'function'
    ? envs.get(provisional.challenge_key) : null;
  return {
    ...laneIdentity(lane, cfg),
    student: studentOf(lane),
    environment: {
      key: provisional.key,
      // The spec's title when a spec answered, the deployer's own label
      // otherwise, and null rather than the raw key when neither exists: the
      // dialog decides how an unlabelled environment is rendered.
      label: (described && described.label) || provisional.label || null,
      // A spec can reveal a GOAD lab the lane config never flagged.
      type: described && described.goad ? 'goad' : provisional.type,
      lab: (described && (described.labLabel || described.lab)) || null,
    },
  };
}

/**
 * Target rows carrying everything a classroom dialog needs to name a machine.
 *
 * The authored spec/lab roster WINS over the config row for role, OS and
 * platform. A GOAD deployer writes `{vm_id, name, proxmox_name, type, node}`
 * with no OS at all, so the name regex in targetsFor leaves DC01/DC02/SRV02/ws01
 * with platform null and an instructor has to hand-pick Windows or Linux for
 * every one of them, on every lane, every time.
 */
function enrichTargets(lane, cfg, envs, { byId = new Map(), agents = [], now = Date.now, withJobs = false } = {}) {
  const at = now();
  const group = groupFor(lane.lane_id);
  const laneEnv = environmentOf(lane, cfg);
  const eligible = laneEligible(lane);
  const lookup = key => (key && envs && typeof envs.get === 'function' ? envs.get(key) : null) || null;
  return targetsFor(lane).map(target => {
    // An attached module is its own roster under its own challenge_key; every
    // other row belongs to the lane's environment. A workstation lane resolves
    // to no key at all, deliberately: it carries the course's reserved-network
    // challenge_key, whose spec describes nothing that lane actually deploys.
    const attached = target.source === 'attached';
    const described = lookup(attached ? target.module_key : laneEnv.challenge_key);
    const env = { key: (attached && target.module_key) || laneEnv.key, machines: described && described.machines };
    const machine = env.machines && typeof env.machines.get === 'function'
      ? env.machines.get(String(target.name).toLowerCase()) : null;
    const live = byId.get(target.vm_id);
    // The lane-level group filter can only say "some agent in this lane".
    // pawFor is deterministic per (lane, vm) and is what the installer
    // registered, so this is the only way to say WHICH machine has an agent.
    const agent = agents.find(row => row.paw === pawFor(lane.lane_id, target.vm_id) && row.group === group) || null;
    const role = (machine && machine.role) || target.role;
    const row = { ...target, ...machineIdentity(target, env),
      node: (live && live.node) || target.node,
      role,
      platform: (machine && machine.platform) || target.platform,
      os: knownOs(machine && machine.os) || knownOs(target.template_name) || null,
      // The OR form deliberately, not `machine ? !!machine.infra : roleInfra`.
      // The two mistakes are not symmetric: a machine wrongly flagged as
      // infrastructure costs one manual tick, while a machine wrongly NOT
      // flagged is auto-selected in the Machines step and swept up by the "Only
      // missing agents" quick action -- which is how an instructor queues a
      // Sandcat install onto the SIEM holding the evidence the class is graded
      // on, or onto the red-team attack box. So a spec row that answers 'Server'
      // for a machine the config itself calls 'siem' loses to the role.
      //
      // The role is also the ONLY answer available when no spec row matched,
      // which is not an edge case. The synthesised attack box is named 'Attack
      // box' and can never match a roster keyed by spec machine name, and a
      // crucible_challenge read that fails -- the degradation the environment
      // directory is built to survive -- leaves EVERY machine in the lane
      // unmatched at once.
      // The name is the LAST resort and the one that covers a GOAD lane, where
      // the deployer records no role and a failed spec read leaves nothing else.
      infra: !!(machine && machine.infra) || INFRASTRUCTURE_ROLES.has(String(role || '').toLowerCase())
        || INFRASTRUCTURE_NAMES.has(String(target.name || '').trim().toLowerCase()),
      power_state: (live && live.status) || 'unknown',
      runnable: eligible && runnableGuest(live),
      agent: publicTargetAgent(agent, at) };
    if (withJobs) row.last_job = publicJobSummary(currentJob(jobForVm(cfg, target.vm_id), at));
    return row;
  });
}

function vmJobSql() {
  return `COALESCE(config->'caldera_agent_jobs'->$3::text,
    CASE WHEN config->'caldera_agent_job'->>'vm_id' = $3::text THEN config->'caldera_agent_job' ELSE '{}'::jsonb END)`;
}

function installationWarnings(stdout, token) {
  const warnings = [];
  for (const match of String(stdout || '').matchAll(/^CYBERCORE_CALDERA_WARNING:([^\r\n]*)/gm)) {
    const warning = match[1].replaceAll(token, '[redacted]')
      .replace(/[\u0000-\u001f\u007f-\u009f]/g, '').trim().slice(0, 1000);
    if (warning && !warnings.includes(warning)) warnings.push(warning);
    if (warnings.length === 5) break;
  }
  return warnings;
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
  // Per SERVICE INSTANCE, not module level, so route and service tests start
  // with a cold memo and TTL expiry is testable through the injected now().
  const environments = deps.environments
    || createEnvironmentDirectory({ query, now, deadline: deps.deadline, goad: deps.goad });
  // Queued work carries its (lane, VM) identity so cancel() can drop it. An
  // opaque closure could only ever be cancelled by throwing the whole queue
  // away, which is what a process restart already does badly: the in-memory
  // pending list vanishes while every row stays 'queued' in the database, and
  // the claim SQL then refuses to re-run any of them for QUEUE_TIMEOUT_MS.
  const pending = [];
  let active = 0;
  function enqueue(key, task) {
    pending.push({ key, task });
    pump();
  }
  /** Drop not-yet-started work. Returns the keys actually removed. */
  function dropPending(keys) {
    const wanted = new Set(keys);
    const dropped = [];
    for (let i = pending.length - 1; i >= 0; i--) {
      if (!wanted.has(pending[i].key)) continue;
      dropped.push(pending[i].key);
      pending.splice(i, 1);
    }
    return dropped;
  }
  function pump() {
    while (active < 4 && pending.length) {
      const { task } = pending.shift();
      active++;
      const run = async () => { try { await task(); } finally { active--; pump(); } };
      if (deps.schedule) deps.schedule(run); else setImmediate(run);
    }
  }

  async function listAgents(config) {
    const agents = await config.client.listAgents();
    if (!Array.isArray(agents)) throw failure(502, 'Caldera returned an invalid agent list.');
    return agents;
  }

  async function loadResources() {
    let resources;
    try { resources = await proxmox('GET', '/api2/json/cluster/resources?type=vm'); }
    catch (_) { throw failure(503, 'Could not verify VM power states in Proxmox. Refresh status and retry.'); }
    if (!Array.isArray(resources)) throw failure(503, 'Could not verify VM power states in Proxmox. Refresh status and retry.');
    return resources;
  }

  async function runningTarget(vmId) {
    const live = (await loadResources()).find(vm => Number(vm.vmid) === vmId);
    if (!runnableGuest(live)) throw failure(409, 'The selected VM must be a running QEMU guest. Refresh status after starting it.');
    return live;
  }

  async function status(lanes) {
    let config = null, configuration_error = null, agents_error = null, agents = [];
    let resources = [], power_error = null, envs = new Map();
    try { config = settings(); } catch (err) { configuration_error = err.message; }
    // Parsed once: every lane's config is read three times below (targets,
    // context and jobs).
    const cfgs = lanes.map(lane => object(lane.config));
    // Every remote read owns its own failure. None of these three may reject, or
    // one slow dependency takes the whole inventory poll down with it.
    await Promise.all([
      (async () => {
        if (!lanes.length) return;
        try { resources = await loadResources(); }
        catch (_) { power_error = 'Could not verify VM power states in Proxmox. Refresh status and retry.'; }
      })(),
      (async () => {
        if (!config) return;
        try { agents = await listAgents(config); }
        catch (_) { agents_error = 'Could not read Caldera check-ins. Check the Caldera service and its API key.'; }
      })(),
      (async () => {
        // Environment titles and the spec's machine roster are COSMETIC, so
        // this branch deliberately sets no error field. A challenge table
        // outage degrades group headings to raw keys and returns the dialog to
        // hand-picking each machine's OS; it never becomes an inventory error.
        try { envs = await environments.describeEnvironments(lanes); }
        catch (_) { envs = new Map(); }
      })(),
    ]);
    const byId = new Map(resources.map(vm => [Number(vm.vmid), vm]));
    return {
      server_url: config?.serverUrl || null, console_url: config?.consoleUrl || null,
      configuration_error, agents_error, power_error,
      lanes: lanes.map((lane, index) => {
        const cfg = cfgs[index];
        const group = groupFor(lane.lane_id);
        const targets = enrichTargets(lane, cfg, envs, { byId, agents, now, withJobs: true });
        // The VM each check-in belongs to, so the lane-level list can be read
        // per machine without recomputing a hash for every (agent, target) pair.
        const vmForPaw = new Map(targets.map(target => [pawFor(lane.lane_id, target.vm_id), target.vm_id]));
        return { lane_id: lane.lane_id, name: lane.name, lane_status: lane.status,
          lifecycle_eligible: laneEligible(lane), retained_after_failure: retainedAfterFailure(lane),
          runnable: targets.some(target => target.runnable),
          internet_enabled: typeof cfg.internet_enabled === 'boolean' ? cfg.internet_enabled : null, group,
          ...laneContext(lane, cfg, envs),
          targets,
          agents: agents.filter(a => a.group === group).map(a => ({ ...publicAgent(a),
            vm_id: vmForPaw.has(a.paw) ? vmForPaw.get(a.paw) : null, fresh: freshAgent(a, now()) })),
          job: currentJob(cfg.caldera_agent_job, now()),
          jobs: [...new Map([cfg.caldera_agent_job, ...Object.values(cfg.caldera_agent_jobs || {})]
            .filter(Boolean).map(job => [job.vm_id, currentJob(job, now())])).values()] };
      }),
    };
  }

  async function saveJob(laneId, job) {
    await query(`UPDATE cybercore_lane SET config = jsonb_set(jsonb_set(config, '{caldera_agent_job}', $2::jsonb),
      '{caldera_agent_jobs}', COALESCE(config->'caldera_agent_jobs', '{}'::jsonb) || jsonb_build_object($4::text, $2::jsonb)), updated_at = NOW()
      WHERE lane_id = $1 AND COALESCE(config->'caldera_agent_jobs'->$4::text, config->'caldera_agent_job')->>'job_id' = $3`,
    [laneId, JSON.stringify(job), job.job_id, String(job.vm_id)]);
  }

  /**
   * Drop the superseded token for this VM, once the new agent has actually
   * checked in.
   *
   * The claim deliberately keeps the previous token so that a FAILED install
   * leaves the existing agent working instead of stranding it. That retention
   * has to end the moment it is no longer needed, or a VM keeps two valid
   * credentials indefinitely.
   *
   * Never allowed to fail the install: by the time this runs the agent is
   * beaconing and the job is genuinely complete, so a prune error is a stale
   * credential to clean up later, not a reason to report failure.
   */
  async function prunePriorTokens(laneId, vmId, tokenHash) {
    try {
      await query(`UPDATE cybercore_lane SET config =
        jsonb_set(config, '{caldera_agent_access,tokens}',
          COALESCE((SELECT jsonb_agg(t) FROM jsonb_array_elements(
            COALESCE(config->'caldera_agent_access'->'tokens', '[]'::jsonb)) t
            WHERE t->>'vm_id' <> $2::text OR t->>'token_hash' = $3), '[]'::jsonb)), updated_at = NOW()
        WHERE lane_id = $1`, [laneId, String(vmId), tokenHash]);
    } catch (_) { /* a stale credential outlives its usefulness harmlessly */ }
  }

  /**
   * Watch for this install's first check-in while the guest execution is still
   * being polled. Resolves with the agent as soon as one appears, or null once
   * the exec settles and the ordinary path should take over.
   *
   * THE EXEC GETS A HEAD START, and that is load-bearing rather than cautious.
   * On Linux the script redirects the agent's output to a FILE rather than an
   * inherited pipe, so the exec really does complete in a second or two -- and
   * its result is what carries the startup marker, the exit code and the
   * installation warnings. Polling immediately would let a fast check-in beat a
   * fast exec and quietly discard all three. Sleeping one interval first means
   * the exec wins whenever it can, and the check-in only wins the case where
   * the exec never will.
   *
   * `agentIsNew` is required, not optional: paw, group and platform are stable
   * across reinstalls, so a leftover agent from an EARLIER install matches the
   * same predicate and would report success for an install that never started.
   */
  async function watchCheckIn(execState, config, job) {
    const startedAt = Date.parse(job.started_at);
    // Yield one turn before spending anything. An exec that has already settled
    // -- which is the Linux case, and every fast failure on either platform --
    // then wins without costing a poll interval or a single extra read, so this
    // path is invisible to everything except the Windows wait it exists for.
    await new Promise(resolve => setImmediate(resolve));
    while (!execState.done) {
      await sleep(CHECK_IN_INTERVAL_MS);
      if (execState.done) return null;
      let agents = [];
      // Bounded by the exec deadline, so a Caldera that is briefly unreachable
      // costs a retry rather than the install.
      try { agents = await listAgents(config); } catch (_) { continue; }
      const agent = agents.find(a => a.paw === job.paw && a.group === job.group
        && a.platform === job.platform && seenAt(a.last_seen) >= startedAt - 2000);
      if (agent && agentIsNew(agent, job.prior_agent)) return agent;
    }
    return null;
  }

  async function execute(laneId, courseId, target, token, config, job) {
    try {
      // Re-read immediately before dispatch; a lane deleted or moved since the click cannot be used.
      const row = await query('SELECT lane_id, status, config FROM cybercore_lane WHERE lane_id = $1', [laneId]);
      const lane = row.rows[0];
      if (!laneEligible(lane) || object(lane.config).course_id !== courseId
        || jobForVm(lane.config, target.vm_id)?.job_id !== job.job_id
        // Cancelled after this task was dequeued but before it reached a guest.
        || jobForVm(lane.config, target.vm_id)?.status === 'cancelled'
        || !targetsFor(lane).some(t => t.vm_id === target.vm_id)) {
        throw failure(409, 'The selected VM is no longer in a running lane.');
      }
      const live = await runningTarget(target.vm_id);
      const exec = executor();
      if (job.status === 'queued') { job.status = 'running'; job.started_at = new Date(now()).toISOString(); }
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
      // RACE THE EXEC AGAINST THE CHECK-IN, because on Windows the exec cannot
      // win. QGA withholds `exited` until both output channels close and the
      // detached agent holds them for its whole life, so every Windows install
      // used to pay EXEC_DEADLINE_MS in full -- measured at 121 s per batch of
      // four, of which 120 s was spent waiting for something that had already
      // happened. A 180-VM class took an hour and three quarters to install
      // agents that were each beaconing within seconds.
      //
      // The check-in is the honest success signal either way; this just stops
      // waiting once it arrives. The exec keeps running and is simply no longer
      // waited on.
      const execState = { done: false, value: null, error: null };
      const execPending = exec.pollExecStatus(live.node, target.vm_id, started.pid, EXEC_DEADLINE_MS)
        .then(value => { execState.done = true; execState.value = value; return value; },
          error => { execState.done = true; execState.error = error; throw error; });
      // Abandoned deliberately when the check-in wins; without this the walked
      // -away-from rejection would surface as an unhandled rejection.
      execPending.catch(() => {});
      const early = await watchCheckIn(execState, config, job);
      if (early) {
        job.status = 'completed'; job.message = 'Agent checked in to Caldera.';
        job.agent = publicAgent(early); job.finished_at = new Date(now()).toISOString();
        await saveJob(laneId, job);
        await prunePriorTokens(laneId, target.vm_id, hashToken(token));
        return;
      }
      if (execState.error) throw execState.error;
      const result = execState.value;
      const warnings = installationWarnings(result.stdout, token);
      if (warnings.length) job.warnings = warnings;
      // QGA reports an exec as exited only once BOTH captured output channels
      // close, not when the process ends (qga/commands.c, qmp_guest_exec_status;
      // the same trap is documented at malware-fakenet.js:41). The Windows
      // script launches Sandcat through Start-Process with output redirection,
      // which creates the child with bInheritHandles, so the detached agent
      // holds PowerShell's stdout/stderr pipes open for its whole life and the
      // exec NEVER reports exited. Treating that as a failure told instructors
      // "Agent installation failed. Timed out" about four agents that were
      // already beaconing. An unfinished exec is now only a doubt: the fresh
      // check-in below is the honest success signal. There is also no stdout to
      // inspect here -- QGA withholds out-data until it considers the exec
      // finished -- so the startup marker cannot be required in this branch.
      if (!result.exited) {
        job.warnings = [...(job.warnings || []), EXEC_INCOMPLETE_NOTICE];
        job.exec_incomplete = true;
      } else if (result.exitcode !== 0 || !result.stdout.includes(`CYBERCORE_CALDERA_STARTED:${job.paw}`)) {
        const detail = String(result.stderr || result.stdout || 'Guest execution timed out.').replaceAll(token, '[redacted]').slice(-900);
        throw failure(502, `Agent installation failed. ${detail}`);
      }
      job.message = result.exited ? 'Agent started. Waiting for its first Caldera check-in.' : EXEC_INCOMPLETE_NOTICE;
      await saveJob(laneId, job);
      // The wall-clock end of this job's own window, not a count of attempts.
      // started_at is stamped at the queued->running flip ABOVE, so everything
      // since (up to 15 s of guest-agent wait, then a pollExecStatus that
      // overshoots its 120 s deadline by one poll plus its trailing sleep) has
      // already been spent out of the same budget, and a Caldera that answers
      // slowly rather than not at all is exactly what makes the remaining
      // attempts expensive. Whichever bound is reached first ends the loop; the
      // first read always happens, so an instant deadline still gets one answer.
      const checkInDeadline = Date.parse(job.started_at) + JOB_TIMEOUT_MS - CHECK_IN_MARGIN_MS;
      // A matching check-in that is NOT evidence of this install. Remembered so
      // the failure below can say which of the two things went wrong.
      let priorAgentSeen = null;
      for (let attempt = 0; attempt < CHECK_IN_ATTEMPTS; attempt++) {
        let agents = [];
        try { agents = await listAgents(config); } catch (_) { /* bounded retries */ }
        const agent = agents.find(a => a.paw === job.paw && a.group === job.group
          && a.platform === job.platform && seenAt(a.last_seen) >= Date.parse(job.started_at) - 2000);
        // The exec REPORTED completion with the startup marker on the exited
        // path, so the check-in is only confirming what the script already
        // proved and today's predicate is the whole of it. On the
        // exec_incomplete path there is no such proof -- that branch exists
        // precisely because the script never said anything -- and the predicate
        // above matches a Sandcat that an EARLIER install left running just as
        // well as a new one, because paw, group and platform are all stable
        // across reinstalls. Declaring that "completed" would report success for
        // an install that actually stalled on the download or on Defender, while
        // the agent the instructor can see belongs to the previous attempt.
        if (agent && (result.exited || agentIsNew(agent, job.prior_agent))) {
          job.status = 'completed'; job.message = 'Agent checked in to Caldera.';
          job.agent = publicAgent(agent); job.finished_at = new Date(now()).toISOString();
          await saveJob(laneId, job);
          await prunePriorTokens(laneId, target.vm_id, hashToken(token));
          return;
        }
        if (agent) priorAgentSeen = agent;
        const remaining = checkInDeadline - now();
        if (remaining <= 0) break;
        await sleep(Math.min(CHECK_IN_INTERVAL_MS, remaining));
      }
      if (result.exited) {
        throw failure(504, 'Sandcat started, but no fresh Caldera check-in was received. Check lane DNS, outbound HTTPS, the Caldera proxy and guest agent logs.');
      }
      // Both facts have to be named, because a wedged guest agent reaches here
      // too and looks identical from the outside. script-executor keeps its last
      // exec-status error in stderr precisely so that failure can identify
      // itself instead of reporting a bare deadline.
      const execDetail = trimDetail(String(result.stderr || 'no guest execution status').replaceAll(token, '[redacted]'), 200);
      if (priorAgentSeen) {
        // The honest answer to "the script never reported completion and the
        // only agent here is one I cannot distinguish from the last install's".
        // Reported as a failure rather than a success because the instructor's
        // next action differs: the machine has to be checked, not ticked off.
        throw failure(504, `The install script did not report completion within ${EXEC_DEADLINE_MS / 1000} seconds and the `
          + 'only Caldera agent on this machine cannot be told apart from the one an earlier install left running, so this '
          + 'installation is unconfirmed. The machine may still be beaconing from the previous agent. Check the guest for a '
          + `stalled download or a Defender prompt before retrying. Guest execution: ${execDetail}`);
      }
      throw failure(504, `The install script did not report completion within ${EXEC_DEADLINE_MS / 1000} seconds and `
        + 'no Caldera agent checked in. Sandcat may still be starting, so check the Agent column before retrying; if it '
        + `stays empty, check lane DNS, outbound HTTPS, the Caldera proxy and the guest agent. Guest execution: ${execDetail}`);
    } catch (err) {
      job.status = 'failed'; job.error = String(err.message).replaceAll(token, '[redacted]').slice(0, 1200);
      job.message = job.error; job.finished_at = new Date(now()).toISOString();
      await saveJob(laneId, job);
    }
  }

  async function start(lane, input, batchPreflight = null) {
    if (!UUID.test(lane.lane_id) || !laneEligible(lane)) throw failure(409, 'This lane is unavailable for agent installation.');
    if (object(lane.config).internet_enabled === false) {
      throw failure(409, 'Lane internet access is disabled. Enable Internet for this lane before installing a Caldera agent.');
    }
    if (!Number.isSafeInteger(input.vm_id) || !['windows', 'linux'].includes(input.platform)) {
      throw failure(400, 'Choose a VM and its Windows or Linux platform.');
    }
    const target = targetsFor(lane).find(t => t.vm_id === input.vm_id);
    if (!target) throw failure(404, 'VM not found in this lane.');
    const config = batchPreflight?.config || settings();
    // Validate server-side connectivity before modifying a VM or rotating its token.
    // The agent list this read already costs is kept, not discarded: it is the
    // only "before" picture of this paw that exists, and execute() needs it to
    // tell a new Sandcat from the one a previous install left beaconing.
    let agentsAtStart = batchPreflight ? batchPreflight.agents : null;
    if (!batchPreflight) {
      try { agentsAtStart = await listAgents(config); } catch (_) { throw failure(503, 'Caldera is unavailable or its API key is invalid.'); }
    }
    // Verify the selected guest before rotating its credential; repeat at dispatch.
    if (batchPreflight) {
      if (!runnableGuest(batchPreflight.byId.get(target.vm_id))) throw failure(409, 'The selected VM must be a running QEMU guest.');
    } else await runningTarget(target.vm_id);
    const token = crypto.randomBytes(32).toString('hex');
    const job = { job_id: crypto.randomUUID(), status: 'queued', vm_id: target.vm_id,
      platform: input.platform, group: groupFor(lane.lane_id), paw: pawFor(lane.lane_id, target.vm_id),
      started_at: new Date(now()).toISOString(), message: 'Installation queued.' };
    // Matched on paw and group only, not platform: an agent installed as the
    // wrong platform last time still holds this paw, and the question here is
    // "was anything already here?", where a wider match is the safe direction.
    const priorAgent = (agentsAtStart || []).find(a => a.paw === job.paw && a.group === job.group);
    if (priorAgent) job.prior_agent = agentIdentity(priorAgent);
    const access = { vm_id: target.vm_id, token_hash: hashToken(token), paw: job.paw, created_at: job.started_at };
    // Atomic claim: concurrent clicks and app workers cannot launch two installers.
    // JSONB updates retain unrelated lane fields and tokens for other VMs.
    //
    // THE PREVIOUS TOKEN FOR THIS VM IS KEPT, and that is not untidiness.
    // This claim commits BEFORE the install script runs, so dropping the old
    // token here means any failure downstream — the existing agent refusing to
    // stop, a download error, Defender — leaves a HEALTHY agent still beaconing
    // with a credential the gate has already revoked. It is then alive, mute and
    // unrecoverable by retry, because every retry repeats the rotation. That is
    // how 72 agents were stranded at once.
    //
    // Exactly one prior token is retained (the highest ordinal for this vm_id),
    // so the array cannot grow without bound, and prunePriorTokens() drops it as
    // soon as the new agent actually checks in. A failed install is therefore
    // retryable, which is the property that was missing.
    const claimed = await query(`UPDATE cybercore_lane SET config =
      jsonb_set(jsonb_set(config, '{caldera_agent_access}', jsonb_build_object('tokens',
        COALESCE((SELECT jsonb_agg(t.value ORDER BY t.ord)
          FROM jsonb_array_elements(COALESCE(config->'caldera_agent_access'->'tokens', '[]'::jsonb))
               WITH ORDINALITY AS t(value, ord)
          WHERE t.value->>'vm_id' <> $3::text
             OR t.ord = (SELECT max(u.ord)
                  FROM jsonb_array_elements(COALESCE(config->'caldera_agent_access'->'tokens', '[]'::jsonb))
                       WITH ORDINALITY AS u(value, ord)
                 WHERE u.value->>'vm_id' = $3::text)), '[]'::jsonb) || jsonb_build_array($4::jsonb))),
        '{caldera_agent_job}', $2::jsonb) || jsonb_build_object('caldera_agent_jobs',
          COALESCE(config->'caldera_agent_jobs', '{}'::jsonb) || jsonb_build_object($3::text, $2::jsonb)), updated_at = NOW()
      WHERE lane_id = $1 AND ${eligibleLaneSql()}
        AND config->>'course_id' IS NOT DISTINCT FROM $6::text
        AND (COALESCE((${vmJobSql()})->>'status', '') NOT IN ('running', 'queued')
          OR ((${vmJobSql()})->>'status' = 'running' AND (${vmJobSql()})->>'started_at' < $5)
          OR ((${vmJobSql()})->>'status' = 'queued' AND (${vmJobSql()})->>'started_at' < $7))
      RETURNING lane_id`, [lane.lane_id, JSON.stringify(job), String(target.vm_id), JSON.stringify(access),
      new Date(now() - JOB_TIMEOUT_MS).toISOString(), object(lane.config).course_id || null,
      new Date(now() - QUEUE_TIMEOUT_MS).toISOString()]);
    if (!claimed.rows.length) throw failure(409, 'This lane is unavailable or an agent installation is already running or queued on this VM.');
    const task = () => execute(lane.lane_id, object(lane.config).course_id, target, token, config, job).catch(() => {
      console.error('[Caldera agents] Could not save installation status.');
    });
    enqueue(queueKey(lane.lane_id, target.vm_id), task);
    return { ...job };
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
      if (!lane || !targetsFor(lane).some(vm => vm.vm_id === target.vm_id)) throw failure(404, 'A selected machine was not found in this course.');
      const key = `${target.lane_id}:${target.vm_id}`;
      if (seen.has(key)) throw failure(400, 'A machine was selected more than once.');
      seen.add(key);
    }
    const config = settings();
    let agentsAtStart;
    try { agentsAtStart = await listAgents(config); } catch (_) { throw failure(503, 'Caldera is unavailable or its API key is invalid.'); }
    const resources = await loadResources();
    // The batch's single agent read is the "before" picture for every VM in it.
    const preflight = { config, byId: new Map(resources.map(vm => [Number(vm.vmid), vm])), agents: agentsAtStart };
    const results = [];
    for (const target of targets) {
      try { results.push({ lane_id: target.lane_id, vm_id: target.vm_id, job: await start(byLane.get(target.lane_id), target, preflight) }); }
      catch (error) { results.push({ lane_id: target.lane_id, vm_id: target.vm_id, error: error.status < 500 ? error.message : 'Could not queue installation on this VM.', status: error.status || 500 }); }
    }
    return { results };
  }

  async function authorize(uri) {
    const match = /^\/agent\/([a-f0-9]{64})\/(?:beacon|file\/download|file\/upload)$/.exec(String(uri || ''));
    if (!match) return null;
    const result = await query(`SELECT l.lane_id, l.status, l.config, t->>'paw' AS paw, t->>'vm_id' AS vm_id FROM cybercore_lane l
      CROSS JOIN LATERAL jsonb_array_elements(COALESCE(l.config->'caldera_agent_access'->'tokens', '[]'::jsonb)) t
      WHERE ${eligibleLaneSql('l')} AND t->>'token_hash' = $1 LIMIT 1`, [hashToken(match[1])]);
    const access = result.rows[0];
    if (!access || !laneEligible(access) || !UUID.test(access.lane_id) || !/^[a-f0-9]{24}$/.test(access.paw)) return null;
    if (!targetsFor(access).some(target => target.vm_id === Number(access.vm_id))) return null;
    // A retained deployment error must not authorize a guest that was stopped
    // later (e.g. by the administrative group suspension action).
    if (access.status === 'suspended') {
      try { await runningTarget(Number(access.vm_id)); } catch (_) { return null; }
    }
    return { paw: access.paw, group: groupFor(access.lane_id) };
  }

  /**
   * Cancel installations that have not started yet.
   *
   * QUEUED ONLY, deliberately. A running job has already put a script into a
   * guest; marking its row cancelled would not stop that script, it would only
   * make the record disagree with the machine. Those are left to finish or to
   * time out on their own.
   *
   * This exists because there was previously no way out of a large batch. The
   * pending list is in-memory, so the only way to stop one was to restart the
   * app -- which drops the queue but leaves every row saying 'queued', and the
   * claim SQL then refuses to re-run any of them until QUEUE_TIMEOUT_MS has
   * passed. Cancelling properly writes a terminal status, which the same claim
   * treats as free immediately, so the work can be re-issued at once.
   *
   * Both halves are needed and in this order: the database first, so a task
   * that has already been dequeued still aborts when execute() re-reads the
   * lane, then the in-memory queue, so nothing new starts.
   */
  async function cancelQueued(lanes, input = {}, { courseId } = {}) {
    const laneIds = Array.isArray(input.lane_ids) && input.lane_ids.length
      ? input.lane_ids : lanes.map(lane => lane.lane_id);
    if (!Array.isArray(laneIds) || !laneIds.length || laneIds.length > MAX_BATCH_TARGETS
      || laneIds.some(id => typeof id !== 'string' || !UUID.test(id))) {
      throw failure(400, `Select between 1 and ${MAX_BATCH_TARGETS} lanes to cancel.`);
    }
    const allowed = new Set(lanes.map(lane => lane.lane_id));
    if (laneIds.some(id => !allowed.has(id))) throw failure(404, 'A selected lane was not found in this course.');
    // Collected BEFORE the update, or there is nothing left reading 'queued' to
    // collect: the statement below is what changes that status.
    const keys = [];
    for (const lane of lanes) {
      if (!laneIds.includes(lane.lane_id)) continue;
      for (const [vmId, job] of Object.entries(object(lane.config).caldera_agent_jobs || {})) {
        if (job && job.status === 'queued') keys.push(queueKey(lane.lane_id, vmId));
      }
    }
    const stamp = new Date(now()).toISOString();
    const result = await query(`UPDATE cybercore_lane SET config = jsonb_set(config, '{caldera_agent_jobs}',
      COALESCE((SELECT jsonb_object_agg(e.key, CASE WHEN e.value->>'status' = 'queued'
          THEN e.value || jsonb_build_object('status', 'cancelled', 'finished_at', $3::text,
            'message', 'Installation cancelled before it started.')
          ELSE e.value END)
        FROM jsonb_each(COALESCE(config->'caldera_agent_jobs', '{}'::jsonb)) AS e), '{}'::jsonb)),
      updated_at = NOW()
      WHERE lane_id = ANY($1::uuid[])
        AND config->>'course_id' IS NOT DISTINCT FROM $2::text
        AND EXISTS (SELECT 1 FROM jsonb_each(COALESCE(config->'caldera_agent_jobs', '{}'::jsonb)) AS e
                     WHERE e.value->>'status' = 'queued')
      RETURNING lane_id, (SELECT count(*) FROM jsonb_each(COALESCE(config->'caldera_agent_jobs', '{}'::jsonb)) AS e
                           WHERE e.value->>'status' = 'cancelled') AS cancelled`,
    [laneIds, courseId || null, stamp]);
    return { lanes: result.rows.length, dropped: dropPending(keys).length };
  }

  return { status, start, startBatch, authorize, cancelQueued };
}

module.exports = { createService, targetsFor, hashToken, pawFor, groupFor, seenAt, currentJob, JOB_TIMEOUT_MS,
  retainedAfterFailure, laneEligible, eligibleLaneSql, jobForVm, QUEUE_TIMEOUT_MS, MAX_BATCH_TARGETS,
  AGENT_FRESH_MS, AGENT_SKEW_MS, freshAgent, publicTargetAgent, publicJobSummary, laneContext, enrichTargets,
  EXEC_DEADLINE_MS, EXEC_INCOMPLETE_NOTICE, CHECK_IN_ATTEMPTS, CHECK_IN_INTERVAL_MS, CHECK_IN_MARGIN_MS,
  agentIdentity, agentIsNew, trimDetail };
