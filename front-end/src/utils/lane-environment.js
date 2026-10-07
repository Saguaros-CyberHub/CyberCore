'use strict';

// Lane vocabulary shared by every classroom dialog: who a lane belongs to, what
// environment it deploys, and which physical machine a target VM actually is.
//
// THIS MODULE IS PURE AT REQUIRE TIME. It is imported by caldera-lane-agents.js
// and wazuh-lane-agents.js, both of which are constructed at module load by
// their routes and required verbatim (no stubbing) by unit tests. goad-deploy.js
// pulls script-executor and the cybercore connection pool on its first line, so
// a top-level require of it here would open a database pool inside every test
// process that touches a lane service. The resolver is lazy-required and
// injectable for exactly that reason.
const { isMalwareLane } = require('./malware-analysis-state');
const { classifyPlatform, INFRASTRUCTURE_ROLES } = require('../incident/caldera/fact-source');

const SHARED_CHALLENGE_TABLE = 'crucible_challenge';
const str = value => (value == null ? '' : String(value)).trim();
const slug = value => str(value).toLowerCase().replace(/\s+/g, '-');

// Lane config reaches here as a pg jsonb object, but a legacy row, a service
// test or a hand-edited column can still hand back a string. A parse failure
// must degrade to "this lane says nothing" rather than take an inventory poll
// down, because the caller is a 5-second poll over every lane in a course.
function object(value) {
  if (typeof value !== 'string') return value || {};
  try { return JSON.parse(value) || {}; }
  catch (_) { return {}; }
}

// classifyPlatform answers 'windows'|'linux'|'darwin'|'unknown'. Only the first
// two can receive a Sandcat or Wazuh install from this tree, and the UI reads a
// truthy platform as "we know what to run here", so 'unknown' and 'darwin' must
// both collapse to null rather than ride the wire as a plausible-looking string.
const INSTALLABLE_PLATFORMS = new Set(['windows', 'linux']);
const wirePlatform = value => INSTALLABLE_PLATFORMS.has(value) ? value : null;

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

/**
 * How one lane is identified and sorted in a classroom dialog.
 *
 * Enumerated by name, never spread from the row: the lane row carries `config`,
 * which holds owner emails and has historically held guest credentials
 * (challenge-lane-deployer.js:2383).
 */
function laneIdentity(lane, cfg) {
  const row = lane || {};
  const parsed = String(row.name || '').match(NAME_SUFFIX);
  return {
    vxlan_id: Number.isSafeInteger(row.vxlan_id) ? row.vxlan_id : null,
    lane_number: Number.isSafeInteger(row.vxlan_id) ? row.vxlan_id : parsed ? Number(parsed[2]) : null,
    family: parsed ? parsed[1] : null,
    // pg hands back a Date; a service test or a legacy row can hand back a
    // string or garbage. new Date(x).toISOString() would throw RangeError and
    // take the whole inventory response with it.
    created_at: Number.isFinite(Date.parse(row.created_at)) ? new Date(row.created_at).toISOString() : null,
    kind: laneKind(cfg || {}),
  };
}

/**
 * Who the lane belongs to, from the runner's `cybercore_user` JOIN and NOTHING
 * ELSE (scopeLanesSql in src/incident/runner.js).
 *
 * config.user_email is a SNAPSHOT the deployer wrote next to the lane password,
 * in the same object, and reading it here would put a name on the wire from a
 * structure that is not the authority on ownership and that no test can prove
 * safe field by field. A lane row that arrived without the join simply has no
 * student, which is the honest answer for every admin-scoped read.
 */
function studentOf(lane) {
  const row = lane || {};
  const first = str(row.first_name);
  const last = str(row.last_name);
  const email = str(row.student_email);
  if (!first && !last && !email) return null;
  return { name: [first, last].filter(Boolean).join(' ') || null, email: email || null };
}

/**
 * Which environment a lane deploys, decided by the SHAPE of its config.
 *
 * "Has a challenge_key" is NOT the test, and getting this wrong collapses a
 * whole course into one group: cle/utils/lane-provision.js:294-299 stamps the
 * course's reserved-network challenge_key onto every student WORKSTATION lane,
 * so 44 workstation lanes and the one GOAD environment lane can all carry the
 * same key while being completely different things. What separates them is
 * whether the lane deploys a challenge roster (`vms[]`) or student desktops
 * (`workstations[]`).
 */
function environmentOf(lane, cfg) {
  const config = cfg || {};
  const vms = Array.isArray(config.vms) ? config.vms : [];
  const workstations = Array.isArray(config.workstations) ? config.workstations : [];
  const challengeKey = str(config.challenge_key) || null;
  // String(cfg.material_id) is deliberately NOT the fallback: String(undefined)
  // is the truthy literal 'undefined', which would give every material-less lane
  // the same nonsense environment key.
  const materialKey = config.material_id != null && config.material_id !== ''
    ? String(config.material_id) : null;
  const key = challengeKey || materialKey || 'lane';
  // Both workstation spellings are read here as well as in the arm below: the
  // legacy single-desktop lane carries `workstation_vmid` next to a
  // `challenge_vm_id`, and reading only `workstations[]` would file it as a
  // challenge environment while its sibling arm calls it a desktop.
  const hasWorkstations = workstations.length > 0 || !!config.workstation_vmid;
  if (vms.length || (config.challenge_vm_id && !hasWorkstations)) {
    return {
      key,
      // The directory may upgrade a 'goad' type with the resolved lab name; the
      // config flag is what is knowable without a spec read.
      type: config.goad ? 'goad' : materialKey ? 'course-lab' : 'challenge',
      challenge_key: challengeKey,
      label: null,
    };
  }
  if (hasWorkstations) {
    return { key: 'workstation', type: 'workstation', challenge_key: null, label: 'Student workstations' };
  }
  return { key, type: 'challenge', challenge_key: challengeKey, label: null };
}

/**
 * The challenge keys worth a spec read for one lane.
 *
 * A workstation lane contributes nothing even though it carries a challenge_key
 * (see environmentOf): loading the course's reserved-network spec 44 times would
 * describe machines that lane does not have. Attached modules DO contribute —
 * attached-modules.js:356 stamps the module instance's own challenge_key, and
 * those VMs are a separate roster with separate names.
 */
function environmentKeysFor(lane, cfg) {
  const config = cfg || {};
  const env = environmentOf(lane, config);
  const keys = [];
  if (env.challenge_key && env.type !== 'workstation') keys.push(env.challenge_key);
  for (const mod of Array.isArray(config.attached_modules) ? config.attached_modules : []) {
    const key = str(mod && mod.challenge_key);
    if (key) keys.push(key);
  }
  return [...new Set(keys)];
}

/**
 * The authored machine roster of one challenge spec, keyed by lowercase name.
 *
 * This is the only place the OS of a GOAD machine is knowable. The lane config
 * rows a deployer writes are `{vm_id, name, proxmox_name, type, node}`
 * (challenge-lane-deployer.js:1383) with no os at all, so targetsFor()'s name
 * regex returns platform null for DC01/SRV02/ws01/elk and an instructor has to
 * hand-pick Windows or Linux for every one of them.
 *
 * @param {object} spec  the parsed challenge spec
 * @param {{resolveGoadLab: Function, getExtension: Function}} goad injected so
 *        this stays testable and so goad-deploy is never required at load time.
 */
function specMachines(spec, goad) {
  const source = spec && typeof spec === 'object' ? spec : {};
  const machines = new Map();
  const record = row => {
    const name = str(row && row.name);
    if (!name) return;
    const role = str(row.role) || 'Server';
    const os = str(row.os) || 'Unknown';
    machines.set(name.toLowerCase(), {
      name,
      role,
      os,
      // Fields enumerated rather than the row spread: classifyPlatform reads
      // five of them and a spec row can carry anything else beside.
      platform: wirePlatform(classifyPlatform({
        os, os_family: row.os_family, os_name: row.os_name, platform: row.platform, os_version: row.os_version })),
      infra: INFRASTRUCTURE_ROLES.has(role.toLowerCase()),
    });
  };
  for (const row of Array.isArray(source.vms) ? source.vms : []) record(row);
  if (source.goad && source.goad.enabled) {
    try {
      const resolved = goad.resolveGoadLab(source);
      // The lab roster OVERRIDES the spec rows, because it is what was actually
      // built: resolveGoadLab has already folded in-lab extensions (ws01) into
      // labDef.vms, and assertGoadRoster refuses a deploy whose spec.vms and lab
      // roster disagree, so the roster is the reconciled truth with the roles and
      // OS strings the spec rows lack.
      for (const row of Array.isArray(resolved && resolved.labDef && resolved.labDef.vms) ? resolved.labDef.vms : []) {
        record(row);
      }
      // External extensions sit OUTSIDE the forest, so they never appear in the
      // lab roster (resolveGoadExtensions keeps them in `external`). elk is the
      // one that matters: the SIEM is Ubuntu and an infrastructure role, and
      // without this it reads as an unknown-OS member server.
      for (const name of (resolved && resolved.extensions && resolved.extensions.external) || []) {
        const ext = goad.getExtension(name);
        if (ext) record({ name: ext.machine || name, role: ext.role, os: ext.os });
      }
    } catch (_) {
      // An unknown lab version combined with rename_forest or a generated tree is
      // a hard refusal in the deployer. Here it only costs labels, so the spec's
      // own rows stand rather than the whole inventory poll failing.
    }
  }
  return machines;
}

/**
 * The stable identity of the MACHINE a target VM is, across every lane.
 *
 * The key is namespaced by environment on purpose. Ticking "DC01" in the
 * Machines step selects that machine in every lane at once, so a bare lowercase
 * name would make DC01 in the GOAD environment and DC01 in an unrelated
 * challenge one checkbox that silently installs on both. Workstations are the
 * mirror problem: every student desktop has a unique hostname
 * (cle-cybr400-inperson-10882-ws1), so a name-keyed grid would list 44
 * single-lane machines instead of "Workstation 1" across 44 lanes.
 */
function machineIdentity(target, env) {
  const row = target || {};
  const environmentKey = (env && env.key) || 'lane';
  const name = str(row.name) || (row.vm_id != null ? `VM ${row.vm_id}` : 'VM');
  if (row.source === 'workstation') {
    // Lanes provisioned before slots were recorded carry no slot at all, and
    // `slot${undefined}` would fold every one of them into a single bogus
    // machine. Slot 0 is the first desktop, which is what those lanes have.
    const slot = Number.isSafeInteger(row.slot) ? row.slot : 0;
    const template = str(row.template_name);
    return {
      machine_key: `workstation::slot${slot}`,
      machine_label: `Workstation ${slot + 1}${template ? ` · ${template}` : ''}`,
      environment_key: environmentKey,
    };
  }
  if (row.source === 'attached') {
    return {
      machine_key: `${str(row.module_key) || 'attached'}::${slug(name)}`,
      machine_label: name,
      environment_key: environmentKey,
    };
  }
  if (row.source === 'attack_box') {
    return { machine_key: `${environmentKey}::attack-box`, machine_label: 'Attack box', environment_key: environmentKey };
  }
  const machine = env && env.machines && typeof env.machines.get === 'function'
    ? env.machines.get(name.toLowerCase()) : null;
  return {
    machine_key: `${environmentKey}::${slug(name)}`,
    // The spec's authored casing ("DC01") beats the deployer's recorded name,
    // which is often the lowercased proxmox hostname.
    machine_label: (machine && machine.name) || name,
    environment_key: environmentKey,
  };
}

/**
 * Spec labels and machine rosters for a set of lanes, memoised per instance.
 *
 * Structure copied from the course directory in wazuh-lane-agents.js: a
 * per-INSTANCE memo (so route and service tests start cold), keyed on the
 * injectable now() so TTL expiry is testable, with a short miss TTL so a
 * recovering database is picked up quickly and a 1.5 s race so a slow table
 * never holds up a polled inventory request.
 *
 * Labels are cosmetic. Nothing here may reject: the worst outcome of a spec
 * outage is a dialog that groups by challenge_key instead of by title.
 */
function createEnvironmentDirectory(deps = {}) {
  const query = deps.query || ((...args) => require('./cybercore-db').cybercoreQuery(...args));
  const now = deps.now || Date.now;
  const deadline = deps.deadline || (ms => new Promise(resolve => {
    const timer = setTimeout(() => resolve(null), ms);
    if (timer.unref) timer.unref();
  }));
  // Lazy and cached: require('./goad-deploy') pulls script-executor and the
  // database pool, which must not happen merely because a lane service was
  // constructed. Only the two sanctioned readers are picked off it, so no site
  // here can reach GOAD_LABS directly.
  let goadModule = deps.goad || null;
  const goad = () => {
    if (!goadModule) {
      const mod = require('./goad-deploy');
      goadModule = { resolveGoadLab: mod.resolveGoadLab, getExtension: mod.getExtension };
    }
    return goadModule;
  };
  const ENV_HIT_TTL_MS = 60 * 1000;
  const ENV_MISS_TTL_MS = 10 * 1000;
  const ENV_DEADLINE_MS = 1500;
  const envMemo = new Map();

  function describeSpec(key, row) {
    const spec = typeof row.spec === 'string' ? JSON.parse(row.spec) : (row.spec || {});
    const enabled = !!(spec.goad && spec.goad.enabled);
    let lab = null;
    let labLabel = null;
    if (enabled) {
      try {
        const resolved = goad().resolveGoadLab(spec);
        lab = (resolved && resolved.labName) || null;
        labLabel = (resolved && resolved.labDef && resolved.labDef.displayName) || null;
      } catch (_) { /* an unresolvable lab still has a usable spec roster */ }
    }
    return { label: str(row.name) || key, goad: enabled, lab, labLabel, machines: specMachines(spec, goad()) };
  }

  // The two-rung table ladder of src/incident/target.js:153-186. A module's own
  // challenge table is tried first when the lane names one, then the shared
  // table. "relation <module>_challenge does not exist" is the expected first
  // answer for most lanes, so only a failure that survives the LAST rung is
  // worth a log line -- and a clean miss is not a failure at all.
  async function loadEnvironment(key, moduleKey) {
    const safeModule = String(moduleKey || '').replace(/[^a-z0-9_]/gi, '');
    const tables = [];
    if (safeModule) tables.push(`${safeModule}_challenge`);
    if (!tables.includes(SHARED_CHALLENGE_TABLE)) tables.push(SHARED_CHALLENGE_TABLE);
    let lastErr = null;
    for (const table of tables) {
      try {
        const result = await query(`SELECT name, spec FROM ${table} WHERE challenge_key = $1`, [key]);
        lastErr = null;
        const row = result && result.rows && result.rows[0];
        if (!row) continue;
        return describeSpec(key, row);
      } catch (err) {
        lastErr = err;
      }
    }
    if (lastErr) {
      console.warn(`[LaneEnvironment] could not load challenge spec '${key}' `
        + `(tried ${tables.join(', ')}): ${lastErr.message}`);
    }
    return null;
  }

  async function describeEnvironments(lanes) {
    const out = new Map();
    // One entry per challenge key, carrying the first module key that named it:
    // the shared table answers for nearly every lane, and a per-lane read would
    // repeat the same query 44 times for one course.
    const wanted = new Map();
    for (const lane of lanes || []) {
      const cfg = object(lane && lane.config);
      const moduleKey = String((lane && lane.module_key) || cfg.module || '');
      for (const key of environmentKeysFor(lane, cfg)) {
        if (!wanted.has(key) || (!wanted.get(key) && moduleKey)) wanted.set(key, moduleKey);
      }
    }
    if (!wanted.size) return out;
    const at = now();
    if (envMemo.size > 1000) envMemo.clear();
    await Promise.all([...wanted].map(async ([key, moduleKey]) => {
      const hit = envMemo.get(key);
      if (hit && at - hit.at < (hit.environment ? ENV_HIT_TTL_MS : ENV_MISS_TTL_MS)) {
        out.set(key, hit.environment);
        return;
      }
      let environment = null;
      // A slow challenge table must not hold up a 5-second poll; a miss is
      // cached briefly so recovery is still quick.
      try { environment = await Promise.race([loadEnvironment(key, moduleKey), deadline(ENV_DEADLINE_MS)]); }
      catch (_) { environment = null; }
      envMemo.set(key, { environment: environment || null, at });
      out.set(key, environment || null);
    }));
    return out;
  }

  return { describeEnvironments };
}

module.exports = {
  NAME_SUFFIX,
  laneKind,
  laneIdentity,
  studentOf,
  environmentOf,
  environmentKeysFor,
  specMachines,
  machineIdentity,
  createEnvironmentDirectory,
};
