'use strict';

// Classroom operations use the central server and one existing group per lane.
// This service is separate from the lane-local incident/grading engine.
const crypto = require('node:crypto');
const { v5: uuidv5 } = require('uuid');
// freshAgent, laneContext and enrichTargets are imported rather than reproduced:
// the install dialog and the attack dialog stand side by side in the same course
// page, and two copies of "this machine has checked in" would eventually
// disagree about which lanes an instructor may launch on.
const { targetsFor, pawFor, groupFor, laneEligible, eligibleLaneSql, retainedAfterFailure,
  freshAgent, laneContext, enrichTargets } = require('./caldera-lane-agents');
const { environmentOf, machineIdentity, createEnvironmentDirectory } = require('./lane-environment');
const { normalizeAbility } = require('../incident/caldera/adversary');
const { laneFactsFor } = require('./caldera-lane-facts');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const MAX_LANES = 100;

/**
 * How the operation presents itself on the wire and on the host.
 *
 * OBFUSCATOR. Caldera encodes each command with the named obfuscator, and the
 * encoded form is what lands in 4688 and in PowerShell 4104 — so this is the
 * difference between a student reading the attacker's commands verbatim and
 * having to decode them, which is what real 4104 evidence looks like.
 *
 * The DEFAULT STAYS 'plain-text' on purpose. An obfuscator name Caldera does not
 * have is a failed createOperation, which fails the whole batch for the class,
 * and nothing in this repository has ever exercised these names against a live
 * server. `base64` is offered because it is the one stockpile has shipped
 * longest. Flip the default once a live launch has confirmed it; the allow-list
 * is the only thing that needs to change.
 *
 * JITTER is min/max seconds BETWEEN LINKS, not the agent beacon. 2/8 fired a
 * whole intrusion inside a minute, which reads as a script rather than an
 * intrusion; 4/16 spreads it without making an exercise outlast its class slot.
 */
const OBFUSCATORS = new Set(['plain-text', 'base64']);
const JITTER_PATTERN = /^([0-9]{1,4})\/([0-9]{1,4})$/;
const DEFAULT_OBFUSCATOR = 'plain-text';
const DEFAULT_JITTER = '4/16';
const TERMINAL = new Set(['finished', 'out_of_time', 'cleanup', 'stopped', 'failed']);
// The ability catalog is per-SERVER state that only changes when a plugin is
// installed or removed, while this dialog polls every five seconds. One read a
// minute keeps the profile card current without turning a 45-lane classroom into
// a dozen stockpile fetches a minute.
const ABILITY_TTL_MS = 60 * 1000;
// How long a FAILED catalog read is remembered. Without it every poll retried,
// so a stockpile that was already struggling received twelve requests a minute
// per open dialog; with it a broken catalog costs two a minute and a recovering
// one is still picked up inside half the success TTL.
const ABILITY_RETRY_MS = 30 * 1000;
// Long enough to say what a step does, short enough that 28 profiles do not turn
// a five-second poll into a megabyte.
const DESCRIPTION_CHARS = 240;
const MAX_EXECUTORS = 8;
// Caps on the rest of the upstream strings. The description used to be the ONLY
// bounded field, which measured badly: one plugin-authored row with a long name,
// tactic, technique name and platform list projected to 51 KB on its own, and
// `tactic` is copied again into the summary of every profile that references it,
// so a single row was multiplied across all 28 profiles in the payload. These
// are display strings in a dialog, not identifiers; a truncated one still reads.
const NAME_CHARS = 160;
const TACTIC_CHARS = 60;
const TECHNIQUE_CHARS = 40;
const PLATFORM_CHARS = 32;
const MAX_PLATFORMS = 12;
// An id is a lookup key, so it can never be truncated — a shortened id would
// stop matching the adversary's ordered list. A row whose id is longer than any
// real Caldera id simply does not enter the catalog. Same bound as the
// adversary id accepted by launch().
const MAX_ID_CHARS = 200;
// The only three platforms a summary counts. Fixed here rather than read from
// the row so a catalog claiming a platform named 'constructor' cannot reach a
// prototype property and ship NaN.
const COUNTED_PLATFORMS = ['windows', 'linux', 'darwin'];
// The placeholder that isolates the one reason a custom ability is rejected.
// normalizeAbility refuses a row for exactly two reasons — no id, or no
// technique id — and plugin-authored and hand-written classroom abilities
// routinely carry an empty technique_id. Re-running the SAME normaliser with a
// stand-in technique keeps platform, name, tactic and description handling
// identical for those rows instead of forking a second projection here that
// would drift; the stand-in is then dropped and never reaches the wire.
const NO_TECHNIQUE = 'no-technique';
const cfg = lane => typeof lane?.config === 'string' ? JSON.parse(lane.config) : lane?.config || {};
const fail = (status, message) => Object.assign(new Error(message), { status });
const operationId = (batch, lane) => uuidv5(`operation:${lane}`, batch);
const sourceId = (batch, lane) => uuidv5(`source:${lane}`, batch);

/**
 * Validate the launch's tradecraft, or refuse it BEFORE anything is created in
 * Caldera. A bad value rejected here costs a 400; the same value accepted here
 * fails at createOperation, which aborts the prepared batch for every lane.
 */
function resolveTradecraft(input) {
  const obfuscator = input.obfuscator === undefined || input.obfuscator === null
    ? DEFAULT_OBFUSCATOR : String(input.obfuscator);
  if (!OBFUSCATORS.has(obfuscator)) {
    throw fail(400, `Choose one of these obfuscators: ${[...OBFUSCATORS].join(', ')}.`);
  }
  const jitter = input.jitter === undefined || input.jitter === null
    ? DEFAULT_JITTER : String(input.jitter);
  const parts = JITTER_PATTERN.exec(jitter);
  if (!parts || Number(parts[1]) > Number(parts[2]) || Number(parts[2]) === 0) {
    throw fail(400, 'Jitter must be "min/max" seconds between steps, with min no greater than max.');
  }
  return { obfuscator, jitter };
}
const records = lane => Object.values(cfg(lane).caldera_operations || {});

/**
 * One upstream-authored ability description, safe to render in a list row.
 *
 * Control characters become a space rather than being deleted: a stockpile
 * description is usually several lines, and stripping the newline outright would
 * glue the last word of one line to the first word of the next.
 */
function abilityText(value, limit) {
  const text = String(value == null ? '' : value)
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim();
  return text ? text.slice(0, limit) : null;
}

/**
 * Executor platforms and names, projected HERE from the raw catalog row.
 *
 * Deliberately not obtained through normalizeAbility: that function's entire
 * contract is that an API row (`executors[]`) and a hand-written stockpile row
 * (`platforms[]`) normalise to the same object, so an `executors` field on its
 * output would make the two accepted shapes disagree
 * (test/caldera-adversary.test.js:607).
 */
function executorsOf(raw) {
  const seen = new Set();
  const out = [];
  for (const executor of Array.isArray(raw && raw.executors) ? raw.executors : []) {
    if (!executor || typeof executor !== 'object') continue;
    const platform = abilityText(executor.platform, PLATFORM_CHARS)?.toLowerCase() || null;
    const name = abilityText(executor.name, PLATFORM_CHARS);
    if (!platform && !name) continue;
    const key = `${platform}|${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ platform, name });
    if (out.length === MAX_EXECUTORS) break;
  }
  return out;
}

/**
 * One catalog row as the dialog receives it: every field bounded, nothing
 * upstream copied at whatever length it happened to have.
 *
 * Built ONCE per catalog read rather than per poll. The five-second poll used to
 * re-project the whole referenced set every time, so the cost of describing a
 * profile was paid twelve times a minute per open dialog for a stockpile that
 * only changes when a plugin is installed.
 */
function publicAbility(ability, raw) {
  return {
    ability_id: ability.id,
    name: abilityText(ability.name, NAME_CHARS) || ability.id,
    tactic: abilityText(ability.tactic, TACTIC_CHARS),
    technique_id: abilityText(ability.technique, TECHNIQUE_CHARS),
    technique_name: abilityText(ability.technique_name, NAME_CHARS),
    platforms: ability.platforms.slice(0, MAX_PLATFORMS)
      .map(platform => abilityText(platform, PLATFORM_CHARS)).filter(Boolean),
    executors: executorsOf(raw),
    description: abilityText(ability.description, DESCRIPTION_CHARS),
  };
}

/**
 * One catalog entry: the wire projection plus the three facts a summary needs.
 *
 * A row that normalizeAbility rejects for want of a technique id is projected
 * here WITH `technique_id: null` and counted as known. Custom and
 * plugin-authored abilities commonly carry an empty technique_id, and dropping
 * them made every profile that used one report `unknown_abilities`, so the card
 * told an instructor that a step was "not in the ability catalog" while it sat
 * in the catalog with a name and a tactic. `unknown_abilities` now means only
 * what it says: this id was not in the catalog at all.
 *
 * normalizeAbility itself is untouched — its contract is that the API and YAML
 * shapes normalise to the same object (test/caldera-adversary.test.js:607), and
 * relaxing it would let a technique-less row into the adversary compiler, where
 * a technique id is what scoring matches on.
 */
function catalogEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  let ability = normalizeAbility(raw);
  if (!ability) {
    if (!String(raw.ability_id == null ? raw.id == null ? '' : raw.id : raw.ability_id).trim()) return null;
    ability = normalizeAbility({ ...raw, technique_id: NO_TECHNIQUE, technique: NO_TECHNIQUE });
    if (!ability) return null;
    ability = { ...ability, technique: null };
  }
  if (ability.id.length > MAX_ID_CHARS) return null;
  const wire = publicAbility(ability, raw);
  return {
    tactic: wire.tactic,
    technique: wire.technique_id,
    // Counted from the FULL platform list rather than from the capped wire copy,
    // so a row that lists two hundred platforms is still counted as Windows.
    counted: COUNTED_PLATFORMS.filter(platform => ability.platforms.includes(platform)),
    wire,
  };
}

/**
 * The deterministic rollup behind the profile card.
 *
 * Computed SERVER-SIDE on purpose. Doing this arithmetic in the browser would
 * put the one part of the card an instructor actually reads beyond the reach of
 * a unit test, and a catalog outage would then render as a confident "0 tactics"
 * instead of degrading to the step count that `ability_count` always carries.
 * `null` here means "this server cannot describe its profiles", which the card
 * is expected to say out loud rather than paper over.
 */
function summarizeAbilities(abilityIds, catalog) {
  if (!catalog) return null;
  const tactics = new Map();
  const techniques = [];
  const platforms = { windows: 0, linux: 0, darwin: 0 };
  let unknown = 0;
  for (const id of abilityIds) {
    const entry = catalog.get(id);
    // An id the catalog cannot answer for is counted, never dropped: the card
    // has to be able to say "3 abilities could not be described" rather than
    // quietly shrinking a 13-step profile to 10 and looking authoritative.
    if (!entry) { unknown += 1; continue; }
    if (entry.tactic) tactics.set(entry.tactic, (tactics.get(entry.tactic) || 0) + 1);
    // A custom ability has no technique id at all. Pushing it unguarded would
    // put a bare null into a list the profile card renders as MITRE ids.
    if (entry.technique && !techniques.includes(entry.technique)) techniques.push(entry.technique);
    for (const platform of entry.counted) platforms[platform] += 1;
  }
  // First-appearance order, so the tactic list reads in the order the operation
  // will actually run its steps.
  return { tactics: [...tactics].map(([tactic, count]) => ({ tactic, count })),
    platforms, techniques, unknown_abilities: unknown };
}

async function parallel(items, limit, fn) {
  let index = 0;
  const result = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) { const i = index++; result[i] = await fn(items[i], i); }
  }));
  return result;
}

function defaultClient() {
  const { resolveTarget } = require('../incident/caldera/authoring');
  const { authoringConfig } = require('../routes/caldera-authoring');
  const target = resolveTarget(authoringConfig());
  if (!target.client) throw fail(503, 'Configure the central Caldera server and API key before launching an attack.');
  return target.client;
}

function createService(deps = {}) {
  const query = deps.query || ((...args) => require('./cybercore-db').cybercoreQuery(...args));
  const clientFor = deps.client || defaultClient;
  const now = deps.now || Date.now;
  const proxmox = (...args) => (deps.proxmox || require('./proxmox').proxmoxAPI)(...args);
  const schedule = deps.schedule || (task => setImmediate(task));
  const stamp = () => new Date(now()).toISOString();
  // Per SERVICE INSTANCE, not module level, so route and service tests start
  // with a cold memo and TTL expiry is testable through the injected now().
  const environments = deps.environments
    || createEnvironmentDirectory({ query, now, deadline: deps.deadline, goad: deps.goad });
  // Injected the same way every other seam in this file is, so a test can drive
  // a lane whose lab resolves without standing up the vendored sidecar.
  const laneFacts = deps.laneFacts || laneFactsFor;
  // The last catalog that answered. Kept across a failed read so a transient
  // Caldera outage degrades the profile card to stale descriptions rather than
  // to no descriptions at all.
  let abilityCache = null;
  let abilityCachedAt = 0;
  // The read that is happening RIGHT NOW, and when the last one failed. The TTL
  // used to be checked before the await while the stamp was written after it, so
  // every concurrent poll issued its own listAbilities: four browsers refreshing
  // a 45-lane course, or one browser whose 20-second client timeout outlives the
  // five-second poll, put four reads in flight against a stockpile that was
  // already slow — piling load on exactly when Caldera is struggling.
  let abilityInFlight = null;
  let abilityFailedAt = 0;

  function select(lanes, input, courseId) {
    if (!UUID.test(courseId) || !Array.isArray(input.lane_ids) || !input.lane_ids.length || input.lane_ids.length > MAX_LANES
      || new Set(input.lane_ids).size !== input.lane_ids.length || input.lane_ids.some(id => typeof id !== 'string' || !UUID.test(id))) {
      throw fail(400, `Select between 1 and ${MAX_LANES} distinct lanes.`);
    }
    const selected = input.lane_ids.map(id => lanes.find(lane => lane.lane_id === id && cfg(lane).course_id === courseId));
    if (selected.some(lane => !lane)) throw fail(404, 'A selected lane was not found in this course.');
    return selected;
  }

  // The two remote reads, once per request. Split out of roster() so status()
  // can share one inventory between the launch-eligibility rollup and the
  // per-machine target rows without reading Proxmox and Caldera twice.
  async function inventory(client) {
    const [allAgents, resources] = await Promise.all([
      client.listAgents(), proxmox('GET', '/api2/json/cluster/resources?type=vm'),
    ]);
    if (!Array.isArray(allAgents) || !Array.isArray(resources)) throw fail(503, 'Could not verify Caldera agents and VM power.');
    return { agents: allAgents, byId: new Map(resources.map(vm => [Number(vm.vmid), vm])) };
  }

  // Power alone, deliberately weaker than runnableGuest(): the launch preflight
  // only has to know the guest is up, and a cluster row that arrived without a
  // node name must not disqualify a lane whose agent is demonstrably beaconing.
  const poweredOn = vm => !!vm && vm.type === 'qemu' && !vm.template && vm.status === 'running';

  function rosterRow(lane, inv) {
    const config = cfg(lane);
    const group = groupFor(lane.lane_id);
    const env = environmentOf(lane, config);
    const targets = targetsFor(lane);
    // One clock sample for the whole lane, so two agents in the same lane can
    // never land on opposite sides of the freshness window.
    const at = now();
    const agents = inv.agents.filter(agent => agent.group === group && freshAgent(agent, at))
      .flatMap(agent => {
        const target = targets.find(vm => pawFor(lane.lane_id, vm.vm_id) === agent.paw && poweredOn(inv.byId.get(vm.vm_id)));
        return target ? [{ paw: agent.paw, host: agent.host, platform: agent.platform, last_seen: agent.last_seen,
          // The machine this check-in belongs to, so the dialog can say "DC01 is
          // here" instead of repeating a 24-character paw.
          vm_id: target.vm_id, name: target.name, machine_key: machineIdentity(target, env).machine_key }] : [];
      });
    return { lane_id: lane.lane_id, name: lane.name, group,
      runnable: laneEligible(lane) && config.internet_enabled !== false && agents.length > 0, agents };
  }

  async function roster(lanes, client) {
    const inv = await inventory(client);
    return new Map(lanes.map(lane => [lane.lane_id, rosterRow(lane, inv)]));
  }

  async function readAbilities(client) {
    const list = await client.listAbilities();
    // The Caldera client returns null for a 204 or an empty body and passes any
    // other JSON value straight through unchecked, so the shape check has to
    // happen here or a bad response poisons the memo for the next minute.
    if (!Array.isArray(list)) throw fail(502, 'Caldera returned an invalid ability catalog.');
    const catalog = new Map();
    for (const raw of list) {
      const entry = catalogEntry(raw);
      if (entry) catalog.set(entry.wire.ability_id, entry);
    }
    return catalog;
  }

  /**
   * The ability catalog: one read a minute, one read at a time, and one read per
   * retry interval while it is failing.
   *
   * Deliberately NOT an async function. The whole point is that the in-flight
   * promise is published before the request is awaited, and an async function
   * cannot hand out its own promise from inside itself.
   *
   * @returns {null|Promise<Map>} null when this server has no catalog endpoint.
   */
  function abilityCatalog(client) {
    // A Caldera build without the abilities endpoint — and every client double
    // written before the profile card existed — simply cannot describe a
    // profile. That is a capability gap, not a failure: it degrades to the step
    // count with no error banner and no memo write.
    if (typeof client.listAbilities !== 'function') return null;
    const at = now();
    if (abilityCache && at - abilityCachedAt < ABILITY_TTL_MS) return abilityCache;
    if (abilityInFlight) return abilityInFlight;
    // A rejection, not a silent degradation: the caller answers it by serving
    // the last good catalog and setting abilities_error, exactly as it does for
    // a live failure, so a suppressed retry is indistinguishable to the dialog
    // from the outage that caused it.
    if (abilityFailedAt && at - abilityFailedAt < ABILITY_RETRY_MS) {
      return Promise.reject(fail(503, 'The Caldera ability catalog could not be read recently.'));
    }
    const pending = readAbilities(client).then(catalog => {
      abilityCache = catalog;
      abilityCachedAt = now();
      abilityFailedAt = 0;
      return catalog;
    }, error => { abilityFailedAt = now(); throw error; });
    abilityInFlight = pending;
    // Cleared on both outcomes, and through a handler that cannot itself reject:
    // leaving a settled promise parked here would serve one failed read forever,
    // and a bare `.finally()` on a rejected promise would surface as an
    // unhandled rejection even though the caller handles the promise it got.
    const clear = () => { if (abilityInFlight === pending) abilityInFlight = null; };
    pending.then(clear, clear);
    return pending;
  }

  function publicRecord(record, remote) {
    let status = record.status;
    let error = record.error;
    if (remote) {
      if (remote.group !== record.group) { status = 'unknown'; error = 'The Caldera operation group changed. Review it in Caldera.'; }
      else if (record.status !== 'failed') status = remote.state || 'unknown';
    } else if (['running', 'paused', 'stopping'].includes(record.status)) {
      status = 'unknown'; error = 'This operation is unavailable in Caldera. Refresh status or inspect the console.';
    } else if (record.status === 'preparing' && now() - Date.parse(record.created_at) > 10 * 60 * 1000) {
      status = 'unknown'; error = 'Preparation was interrupted. Stop this batch before starting another.';
    }
    return { batch_id: record.batch_id, operation_id: record.operation_id, name: record.name,
      adversary_name: record.adversary_name, status, started_at: record.started_at || record.created_at,
      error: error || null, stop_requested: !!record.stop_requested };
  }

  function visibleRecords(lane, remote = new Map()) {
    let history = 0;
    return records(lane).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
      .map(record => publicRecord(record, remote.get(record.operation_id)))
      // Keep every active/uncertain operation: the UI uses these rows to stop
      // all lanes in a batch. Only terminal history may be truncated.
      .filter(record => !TERMINAL.has(record.status) || history++ < 20);
  }

  /**
   * One lane, enumerated by name.
   *
   * Nothing here spreads the lane row or its config: lane config carries the
   * owner's email and has historically carried guest credentials, and this
   * payload is polled into an instructor's browser every five seconds.
   */
  function publicLane(lane, config, envs, inv) {
    const base = inv ? rosterRow(lane, inv)
      : { lane_id: lane.lane_id, name: lane.name, group: groupFor(lane.lane_id), runnable: false, agents: [] };
    return { ...base,
      // `runnable` folds "the lane is off", "the internet is off" and "nothing
      // has checked in" into a single false, so the dialog used to label every
      // agent-less lane "lane not running" and could never reach the real
      // reason. These three separate the causes; runnable keeps its meaning
      // exactly, because the launch preflight is written against it.
      lane_status: lane.status,
      lifecycle_eligible: laneEligible(lane),
      retained_after_failure: retainedAfterFailure(lane),
      internet_enabled: typeof config.internet_enabled === 'boolean' ? config.internet_enabled : null,
      ...laneContext(lane, config, envs),
      // Emitted from config even when the inventory read failed. An empty
      // targets array would be indistinguishable from a lane that deploys no
      // machines, so a Proxmox outage would silently redraw a GOAD environment
      // as an empty one instead of as six machines whose power is unknown.
      targets: enrichTargets(lane, config, envs, {
        byId: inv ? inv.byId : new Map(), agents: inv ? inv.agents : [], now }),
    };
  }

  /**
   * One poll of the attack dialog.
   *
   * `adversaryId` is the profile the instructor has selected. Full ability
   * detail ships for that profile and for no other: the catalog is by far the
   * largest thing in this payload, the dialog only ever renders steps for the
   * selected card, and the payload grows with every profile an instructor
   * authors. Every profile still carries its own small `summary`, so the picker
   * stays fully described without the step-level detail behind it.
   */
  async function status(lanes, { courseId, adversaryId } = {}) {
    const scoped = lanes.filter(lane => cfg(lane).course_id === courseId);
    const configs = scoped.map(lane => cfg(lane));
    // Started here and awaited with the Caldera reads below, NOT before them.
    // The directory's own deadline is 1.5 s, so during a crucible_challenge
    // outage a serial await charged this poll the full 1.5 s on top of Caldera's
    // latency every ten seconds (the directory's miss TTL) for labels that are
    // cosmetic. The guard is here rather than at the await because the
    // degradation is "group by challenge key instead of by title", which carries
    // no error field of its own.
    const described = (async () => {
      try { return await environments.describeEnvironments(scoped); } catch (_) { return new Map(); }
    })();
    const project = (envs, inv, remote) => scoped.map((lane, index) => ({
      ...publicLane(lane, configs[index], envs, inv), operations: visibleRecords(lane, remote) }));
    const response = { adversaries: [], abilities: {} };
    // A selected profile is a display choice, so a malformed one is ignored
    // rather than refused: the payload then carries summaries only and the
    // dialog still renders its picker. Never interpolated anywhere.
    const selectedAdversary = typeof adversaryId === 'string' && adversaryId.trim() && adversaryId.length <= MAX_ID_CHARS
      ? adversaryId : null;
    let client;
    try { client = clientFor(); } catch (error) {
      return { ...response, lanes: project(await described, null), configuration_error: error.message };
    }
    const [envs, inv, adversaries, operations, abilities] = await Promise.allSettled([
      described, inventory(client), client.listAdversaries(), client.listOperations(), abilityCatalog(client)]);
    if (inv.status === 'rejected') response.agents_error = 'Could not verify online agents and VM power. Refresh status.';
    let catalog = null;
    if (abilities.status === 'fulfilled') catalog = abilities.value;
    else {
      // Serving the last good copy is the honest degradation: a stockpile only
      // changes when a plugin is installed, so a stale description is right far
      // more often than an empty card that reads as "this profile does nothing".
      catalog = abilityCache;
      response.abilities_error = 'Could not read the Caldera ability catalog. Ability details are unavailable.';
    }
    const referenced = new Set();
    if (adversaries.status === 'fulfilled' && Array.isArray(adversaries.value)) {
      response.adversaries = adversaries.value.filter(adv => typeof adv.adversary_id === 'string' && Array.isArray(adv.atomic_ordering) && adv.atomic_ordering.length)
        .map(adv => {
          // Caldera's own key name never reaches an instructor-facing payload.
          // `atomic_ordering` and the launch fingerprint are dispatch state, and
          // the leak assertion in this service's test refuses both by name.
          const abilityIds = adv.atomic_ordering.filter(id => typeof id === 'string' && id && id.length <= MAX_ID_CHARS);
          if (adv.adversary_id === selectedAdversary) for (const id of abilityIds) referenced.add(id);
          return { adversary_id: adv.adversary_id, name: adv.name || adv.adversary_id,
            description: adv.description || '', ability_count: adv.atomic_ordering.length,
            ability_ids: abilityIds, summary: summarizeAbilities(abilityIds, catalog) };
        }).sort((a, b) => a.name.localeCompare(b.name));
    } else response.configuration_error = 'Could not read Caldera adversary profiles.';
    // Only the abilities the SELECTED profile runs. Projecting every profile's
    // steps put 160 KB of catalog on a five-second no-store poll for a course
    // with 28 authored profiles — a payload that grew with every profile an
    // instructor added and that the dialog never rendered more than a
    // thirteenth of.
    if (catalog) {
      for (const id of referenced) {
        const entry = catalog.get(id);
        if (entry) response.abilities[id] = entry.wire;
      }
    }
    const remote = new Map(operations.status === 'fulfilled' && Array.isArray(operations.value) ? operations.value.map(op => [op.id, op]) : []);
    if (operations.status === 'rejected') response.operations_error = 'Could not refresh Caldera operation status.';
    response.lanes = project(envs.status === 'fulfilled' ? envs.value : new Map(),
      inv.status === 'fulfilled' ? inv.value : null, remote);
    return response;
  }

  async function loadLane(laneId, courseId) {
    const result = await query('SELECT lane_id, name, status, config FROM cybercore_lane WHERE lane_id = $1 AND config->>\'course_id\' = $2', [laneId, courseId]);
    return result.rows[0];
  }

  async function save(laneId, courseId, record) {
    await query(`UPDATE cybercore_lane SET config = jsonb_set(config, ARRAY['caldera_operations', $3::text],
      $4::jsonb || jsonb_build_object('stop_requested', COALESCE(config->'caldera_operations'->$3::text->'stop_requested', 'false'::jsonb))), updated_at = NOW()
      WHERE lane_id = $1 AND config->>'course_id' = $2 AND config->'caldera_operations'->$3::text->>'operation_id' = $5`,
    [laneId, courseId, record.batch_id, JSON.stringify(record), record.operation_id]);
  }

  async function stoppedOrChanged(laneId, courseId, record) {
    const current = await loadLane(laneId, courseId);
    return !current || !laneEligible(current) || cfg(current).caldera_operations?.[record.batch_id]?.operation_id !== record.operation_id
      || cfg(current).caldera_operations[record.batch_id].stop_requested === true;
  }

  async function stopRemote(client, record) {
    const remote = await client.getOperation(record.operation_id);
    if (remote?.tolerated && remote.status === 404) return;
    if (remote?.id !== record.operation_id || remote.group !== record.group) throw fail(409, 'The operation group could not be verified.');
    if (TERMINAL.has(remote.state)) return;
    try {
      const response = await client.abortOperation(record.operation_id);
      if (response?.tolerated && response.status === 404) return;
      if (response?.id === record.operation_id && response.group === record.group && TERMINAL.has(response.state)) return;
    } catch (_) { /* Re-read: the operation may have finished concurrently. */ }
    const confirmed = await client.getOperation(record.operation_id);
    if (confirmed?.tolerated && confirmed.status === 404) return;
    if (confirmed?.id !== record.operation_id || confirmed.group !== record.group || !TERMINAL.has(confirmed.state)) {
      throw fail(502, 'Caldera did not confirm that the operation stopped.');
    }
  }

  /**
   * This lane's seed facts, resolved through the same challenge-key lookup
   * laneContext uses — the environment directory is keyed by challenge key, not
   * by lane id, because one spec answers for a whole course.
   */
  function factsFor(lane, envs) {
    const config = cfg(lane);
    const provisional = environmentOf(lane, config);
    const described = provisional.challenge_key && envs && typeof envs.get === 'function'
      ? envs.get(provisional.challenge_key) : null;
    try { return laneFacts(lane, config, described); }
    // A seeder that throws must not take the lane's operation with it.
    catch (_) { return { facts: [], hosts: [], excluded: [], warnings: ['LANE_FACTS_FAILED'] }; }
  }

  async function runBatch(selected, courseId, entries, client, adversary, tradecraft) {
    const prepared = [];
    let prepareFailed = false;
    const batchId = entries[selected[0].lane_id].batch_id;
    const snapshot = { adversary_id: uuidv5('adversary', batchId), name: `Classroom ${batchId.slice(0, 8)}: ${adversary.name || adversary.adversary_id}`,
      description: 'Snapshot for a CyberCore classroom exercise.', atomic_ordering: [...adversary.atomic_ordering] };
    await client.createAdversary(snapshot);
    // One directory read for the whole batch. A failure here degrades every lane
    // to an unseeded source — today's behaviour — and never fails the launch:
    // seeding is a realism upgrade, not a new precondition for running a class.
    let envs = new Map();
    try { envs = await environments.describeEnvironments(selected); } catch (_) { envs = new Map(); }
    await parallel(selected, 4, async lane => {
      const record = entries[lane.lane_id];
      try {
        if (await stoppedOrChanged(lane.lane_id, courseId, record)) throw fail(409, 'Lane changed or batch stopped before preparation.');
        // The source is still per lane and per batch, so nothing leaks between
        // classes; what it now carries is THIS lane's own estate, so an ability
        // parameterised by a remote host has somewhere real to point. Host
        // identity only — see caldera-lane-facts.js for why no secret goes here.
        const seeded = factsFor(lane, envs);
        const source = { id: sourceId(record.batch_id, lane.lane_id), name: record.name,
          facts: seeded.facts, relationships: [], rules: [], adjustments: [] };
        await client.createSource(source);
        record.facts_seeded = seeded.facts.length;
        record.fact_hosts = seeded.hosts.map(host => host.hostname);
        if (seeded.warnings.length) record.fact_warnings = seeded.warnings;
        const created = await client.createOperation({ id: record.operation_id, name: record.name, group: record.group,
          adversary: { adversary_id: snapshot.adversary_id }, source: { id: source.id },
          state: 'paused', autonomous: 1, auto_close: true,
          obfuscator: tradecraft.obfuscator, jitter: tradecraft.jitter });
        if (created?.id !== record.operation_id || created?.group !== record.group || created?.state !== 'paused'
          || created?.adversary?.adversary_id !== snapshot.adversary_id || created?.source?.id !== source.id) {
          throw fail(502, 'Caldera did not confirm the requested paused operation, group, adversary and fact source.');
        }
        record.status = 'paused'; await save(lane.lane_id, courseId, record); prepared.push(lane);
      } catch (error) {
        prepareFailed = true; record.status = 'failed'; record.error = error.status === 409 ? error.message : 'Could not prepare this lane in Caldera. The batch was not released.';
        await save(lane.lane_id, courseId, record);
      }
    });
    // All lanes must prepare before any begins. Release requests are concurrent;
    // execution follows each agent's polling interval, not a synchronized clock.
    if (!prepareFailed) {
      const fresh = await Promise.all(selected.map(lane => loadLane(lane.lane_id, courseId)));
      if (fresh.some(lane => !lane || !laneEligible(lane))) prepareFailed = true;
      else {
        const live = await roster(fresh, client);
        if (fresh.some(lane => !live.get(lane.lane_id)?.runnable || cfg(lane).caldera_operations?.[entries[lane.lane_id].batch_id]?.stop_requested)) prepareFailed = true;
      }
    }
    if (prepareFailed) {
      await parallel(selected, 4, async lane => {
        const record = entries[lane.lane_id];
        try {
          await stopRemote(client, record);
          record.status = 'failed'; record.error ||= 'The batch was stopped because at least one lane could not be prepared.';
        } catch (_) { record.status = 'unknown'; record.error = 'Could not confirm this prepared operation was stopped. Inspect Caldera before retrying.'; }
        await save(lane.lane_id, courseId, record);
      });
      return;
    }
    const releasedAt = stamp();
    await Promise.all(prepared.map(async lane => {
      const record = entries[lane.lane_id];
      try {
        if (await stoppedOrChanged(lane.lane_id, courseId, record)) throw fail(409, 'Lane changed or batch stopped before launch.');
        const remote = await client.startOperation(record.operation_id);
        if (remote?.group !== record.group || remote?.id !== record.operation_id) throw fail(502, 'Caldera did not confirm the requested operation.');
        record.status = remote.state || 'running'; record.started_at = releasedAt;
        if (await stoppedOrChanged(lane.lane_id, courseId, record)) {
          await stopRemote(client, record); record.status = 'stopped';
        }
      } catch (_) { record.status = 'unknown'; record.error = 'Launch could not be confirmed. Refresh status before retrying; the operation may have started.'; }
      await save(lane.lane_id, courseId, record);
    }));
  }

  async function launch(lanes, input = {}, { courseId, label = 'Classroom' } = {}) {
    const selected = select(lanes, input, courseId);
    if (!UUID.test(input.request_id) || typeof input.adversary_id !== 'string' || !input.adversary_id.trim() || input.adversary_id.length > 200) {
      throw fail(400, 'Choose an adversary and provide a unique request ID.');
    }
    // Refused here, before the idempotency check and before anything exists in
    // Caldera: a bad value that reaches createOperation aborts the prepared
    // batch for every lane in the class.
    const tradecraft = resolveTradecraft(input);
    const batch = input.request_id.toLowerCase();
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify([input.adversary_id, [...input.lane_ids].sort()])).digest('hex');
    const existing = selected.map(lane => cfg(lane).caldera_operations?.[batch]);
    if (existing.some(Boolean)) {
      if (!existing.every(record => record?.fingerprint === fingerprint)) throw fail(409, 'This request ID was already used with different selections.');
      return { batch_id: batch, results: selected.map((lane, i) => ({ lane_id: lane.lane_id, ...publicRecord(existing[i]) })) };
    }
    const client = clientFor();
    const [available, catalog] = await Promise.all([roster(selected, client), client.listAdversaries()]);
    if (selected.some(lane => !available.get(lane.lane_id)?.runnable)) throw fail(409, 'Every selected lane needs a running VM with a trusted agent seen in the last two minutes. Refresh status.');
    const adversary = Array.isArray(catalog) && catalog.find(item => item.adversary_id === input.adversary_id);
    if (!adversary || !Array.isArray(adversary.atomic_ordering) || !adversary.atomic_ordering.length) throw fail(400, 'This adversary is unavailable or has no abilities.');
    const entries = Object.fromEntries(selected.map(lane => [lane.lane_id, {
      batch_id: batch, fingerprint, operation_id: operationId(batch, lane.lane_id), group: groupFor(lane.lane_id),
      name: `${String(label).slice(0, 80)} / ${String(lane.name || lane.lane_id).slice(0, 80)} / ${batch.slice(0, 8)}`,
      adversary_id: adversary.adversary_id, adversary_name: adversary.name || adversary.adversary_id,
      status: 'preparing', created_at: stamp(), stop_requested: false,
    }]));
    // One atomic statement reserves every selected lane, or none. Locks serialize retries.
    const claimed = await query(`WITH locked AS MATERIALIZED (
      SELECT l.lane_id, l.config, l.status FROM cybercore_lane l
      WHERE l.lane_id = ANY($1::uuid[]) AND l.config->>'course_id' = $2 ORDER BY l.lane_id FOR UPDATE
    ), allowed AS (
      SELECT COUNT(*) = cardinality($1::uuid[]) AND bool_and(${eligibleLaneSql()} AND NOT (COALESCE(config->'caldera_operations', '{}'::jsonb) ? $3::text)) AS ok FROM locked
    ) UPDATE cybercore_lane l SET config = jsonb_set(l.config, '{caldera_operations}',
      COALESCE(l.config->'caldera_operations', '{}'::jsonb) || jsonb_build_object($3::text, $4::jsonb->l.lane_id::text)), updated_at = NOW()
      FROM locked WHERE l.lane_id = locked.lane_id AND (SELECT ok FROM allowed) RETURNING l.lane_id`,
    [selected.map(lane => lane.lane_id), courseId, batch, JSON.stringify(entries)]);
    if (claimed.rows.length !== selected.length) {
      const refreshed = await Promise.all(selected.map(lane => loadLane(lane.lane_id, courseId)));
      const prior = refreshed.map(lane => cfg(lane).caldera_operations?.[batch]);
      if (prior.every(record => record?.fingerprint === fingerprint)) return { batch_id: batch,
        results: selected.map((lane, i) => ({ lane_id: lane.lane_id, ...publicRecord(prior[i]) })) };
      throw fail(409, 'A selected lane changed or this request is already being processed. Refresh status.');
    }
    schedule(() => runBatch(selected, courseId, entries, client, adversary, tradecraft).catch(async () => {
      // Never release after an interrupted preparation. Saved operation IDs make
      // uncertain outcomes visible and stoppable after a worker/server failure.
      await Promise.allSettled(selected.map(async lane => {
        const record = entries[lane.lane_id]; record.status = 'unknown'; record.error = 'Batch processing was interrupted. Refresh status and stop the batch before retrying.';
        await save(lane.lane_id, courseId, record);
      }));
    }));
    return { batch_id: batch, results: selected.map(lane => ({ lane_id: lane.lane_id, ...publicRecord(entries[lane.lane_id]) })) };
  }

  async function stop(lanes, input = {}, { courseId } = {}) {
    const selected = select(lanes, input, courseId);
    if (!UUID.test(input.batch_id)) throw fail(400, 'Choose the batch to stop.');
    const batch = input.batch_id.toLowerCase();
    if (selected.some(lane => !cfg(lane).caldera_operations?.[batch])) throw fail(404, 'Batch not found in a selected lane.');
    const client = clientFor();
    // Persist cancellation before touching Caldera so a preparing worker cannot release it.
    await query(`UPDATE cybercore_lane SET config = jsonb_set(config,
      ARRAY['caldera_operations', $3::text, 'stop_requested'], 'true'::jsonb), updated_at = NOW()
      WHERE lane_id = ANY($1::uuid[]) AND config->>'course_id' = $2 AND config->'caldera_operations' ? $3::text`,
    [selected.map(lane => lane.lane_id), courseId, batch]);
    const results = await parallel(selected, 8, async lane => {
      const record = { ...cfg(lane).caldera_operations[batch], stop_requested: true };
      try {
        await stopRemote(client, record);
        record.status = 'stopped';
        delete record.error;
      } catch (_) { record.status = 'unknown'; record.error = 'Could not confirm the operation stopped. Retry Stop or inspect Caldera.'; }
      await save(lane.lane_id, courseId, record);
      return { lane_id: lane.lane_id, ...publicRecord(record) };
    });
    return { batch_id: batch, results };
  }

  return { status, launch, stop };
}

module.exports = { createService, operationId, sourceId, MAX_LANES };
