/**
 * ============================================================================
 * INCIDENT ANSWER KEY — what the intrusion actually did
 * ============================================================================
 * The graded truth behind one run: which techniques fired, in what order, and
 * which concrete values (an attacker IP, a victim hostname, a service account)
 * belong to the attack rather than to the noise around it.
 *
 * WHY THIS IS COMPUTED AND NOT OBSERVED — the load-bearing idea
 * ----------------------------------------------------------------------------
 * The obvious implementation is to ask Elasticsearch what the run produced.
 * That implementation is wrong in this system, for four separate reasons, and
 * each one alone would sink it:
 *
 *   1. THERE IS NO ONE ELASTICSEARCH. Every lane has its own single-node
 *      cluster behind its own gateway. Thirty lanes means thirty queries from
 *      an app that has no route to any of them.
 *   2. THE INDEX IS THE STUDENT'S WORKSPACE. Grading against a store the
 *      student can write to and delete from is grading against evidence the
 *      examinee controls.
 *   3. BACKDATING IS BROKEN, so "when did it happen" cannot be read back out.
 *      cc-emit writes `timestamp`, which the ndjson parser lands as
 *      `loggen.timestamp`; the Kibana data view keys on `@timestamp`, which is
 *      INGEST time, and the agent config carries no timestamp processor.
 *   4. IT DOES NOT NEED TO BE OBSERVED. cc-emit is deterministic on the run id
 *      — `test/loggen-playbooks.test.js` pins that as "the same run id produces
 *      the same attack on every lane" — so re-running planTimeline() here, with
 *      the same seed the guest used, reproduces the exact event list every lane
 *      wrote. Zero Elasticsearch queries, zero guest round-trips, and a key
 *      that exists the instant the run row does.
 *
 * WHICH IS WHY THE KEY IS COMPILED AT LAUNCH, IN THE SAME STATEMENT AS THE RUN
 * INSERT. The seed IS the run id, so the key cannot be compiled before the row
 * exists — and compiling it later would mean a window in which a completed run
 * has no key and the board silently grades everything as a false positive.
 *
 * EXACT REPRODUCTION OF THE GUEST — the three inputs that must agree
 * ----------------------------------------------------------------------------
 *   seed       cc-emit.js:608  seedFrom(args['run-id'])
 *   requested  cc-emit.js:640  duration_seconds, or playbook.nominal_seconds
 *              when the wrapper passed a bare --duration (the CHAIN case)
 *   playbook   the same JSON the wrapper staged into the run directory
 *
 * Get any one of them wrong and the key is a plausible-looking description of
 * an attack that never ran, which grades every student's correct answer as a
 * false positive. There is no symptom short of reading the numbers.
 *
 * WHAT AN IOC IS, HERE
 * ----------------------------------------------------------------------------
 * A value the ATTACK plan used that the FLOOR plan does not. That differencing
 * is the same computation test/loggen-playbooks.test.js already performs to
 * prove no attack-only vocabulary leaks into the index — run in reverse: what
 * that test forbids as an oracle is exactly what a student is supposed to find
 * by correlation, so the values it hunts are the values worth grading.
 *
 * THE DIRECTION OF THE ERROR MATTERS. Over-collecting floor values costs a few
 * IOCs the key could have listed. UNDER-collecting them puts an ordinary
 * hostname in the key and then penalises every student who correctly ignores
 * it. So the floor universe is built from the floor playbook's DECLARED pools
 * and entities — every value it COULD draw — not from one sampled plan.
 *
 * STAFF ONLY. Nothing in this file is safe to serve to a student. The
 * projection that keeps it that way is src/incident/projection.js.
 * ============================================================================
 */

'use strict';

const fs = require('fs');
const path = require('path');

const emit = require('./cc-emit');

/**
 * Bumped when the SHAPE changes, not when a value does.
 *
 * A stored key carries its version so a scorer reading a key compiled by an
 * older build can refuse rather than mis-grade. src/incident/scoring.js reads
 * it; a mismatch there is a rescore, not a silent regrade.
 */
const ANSWER_KEY_VERSION = 1;

/** The baked benign floor. Overridable so E4's profile-derived floor can slot in. */
const DEFAULT_FLOOR_PLAYBOOK = path.join(__dirname, 'playbooks', 'host-baseline.json');

/**
 * Cap on how many floor values are carried into the key.
 *
 * The floor universe is a few hundred strings today, so this never fires — it
 * exists because E4's compiler derives the floor from a client profile, and a
 * profile with 200 assets could push the key into the megabytes. Truncation is
 * RECORDED (`floor_truncated`) rather than silent, because a truncated floor
 * makes the scorer stricter, and a scorer that got stricter for a reason nobody
 * can see is the kind of thing that gets blamed on the students.
 */
const FLOOR_VALUE_CAP = 2000;

/** Values shorter than this are never IOCs: they collide with everything. */
const MIN_IOC_LENGTH = 3;

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
const WINDOWS_PATH_RE = /^[a-zA-Z]:\\|^\\\\/;
const PROCESS_RE = /\.(exe|dll|ps1|bat|scr|vbs)$/i;

// ---------------------------------------------------------------------------
// Value collection
// ---------------------------------------------------------------------------

/**
 * Every string a playbook could ever put on the wire from its DECLARED pools,
 * entities and literal step fields.
 *
 * Deliberately a superset of what any single plan samples. See the header: the
 * cost of an extra floor value is one IOC the key does not list; the cost of a
 * missing one is a student penalised for correctly ignoring ordinary traffic.
 *
 * @returns {{values: Set<string>, prefixes: Set<string>}} prefixes are the /24
 *   bases of `ipv4Host` entities, whose last octet is drawn at plan time and so
 *   can never be compared literally.
 */
function collectDeclaredValues(playbook) {
  const values = new Set();
  const prefixes = new Set();
  const pb = playbook || {};

  const addString = (v) => {
    if (typeof v !== 'string') return;
    const s = v.trim();
    // A token is not a value — "{{users}}" is the NAME of a draw, and adding it
    // would put literal braces in the floor universe where nothing matches.
    if (!s || s.includes('{{')) return;
    values.add(s);
  };

  for (const list of Object.values(pb.pools || {})) {
    if (Array.isArray(list)) for (const v of list) addString(v);
  }

  for (const spec of Object.values(pb.entities || {})) {
    if (typeof spec === 'string' || typeof spec === 'number') addString(String(spec));
    else if (spec && Array.isArray(spec.oneOf)) for (const v of spec.oneOf) addString(String(v));
    else if (spec && typeof spec.ipv4Host === 'string') prefixes.add(spec.ipv4Host);
  }

  for (const step of pb.steps || []) {
    const src = step.source || {};
    addString(src.type); addString(src.name); addString(src.host);
    for (const v of Object.values(step.metadata || {})) addString(v);
    for (const tpl of step.templates || []) {
      for (const v of Object.values((tpl && tpl.metadata) || {})) addString(v);
    }
  }

  return { values, prefixes };
}

/**
 * One searchable blob per planned event, plus its technique.
 *
 * Built once and reused across every candidate rather than re-walking the plan
 * per candidate — a chain playbook plans several thousand events and there are
 * a few dozen candidates, so the difference is a scan versus a product.
 */
function indexEvents(plan) {
  return plan.events.map((ev) => {
    const src = ev.source || {};
    const parts = [ev.message || '', src.type || '', src.name || '', src.host || ''];
    for (const v of Object.values(ev.metadata || {})) {
      if (typeof v === 'string' || typeof v === 'number') parts.push(String(v));
    }
    // NUL as the separator: it cannot appear in a generated message, so a
    // candidate can never match across the join of two fields.
    //
    // WRITTEN AS THE ESCAPE \u0000, NEVER AS A RAW NUL BYTE IN THIS FILE.
    // A literal NUL in the source makes grep and ripgrep classify the whole
    // file as binary and skip its contents SILENTLY. This repo's test
    // doctrine is source-text gates (ciab-deploy-parity.test.js,
    // incident-engine-locality.test.js, incident-answer-key-leak.test.js),
    // so a future gate grepping for a leak in here would report PASS by
    // never having read the file at all.
    //
    // Worse, git's own binary sniff only inspects the first 8000 bytes. The
    // raw byte sat at offset 8192, so `git diff` rendered this file as text
    // purely by luck -- and any comment added above this point would have
    // pushed it under the window, flipping the file to "Binary files differ"
    // and making every later change to the answer key invisible in review.
    return { hay: parts.join('\u0000'), technique: ev.technique || null, offset: ev.offset };
  });
}

/**
 * What KIND of indicator a value is, from its shape and the name it was drawn
 * under.
 *
 * The vocabulary is cybercore_incident_finding.ioc_type's CHECK, exactly. A
 * value that fits nothing is typed 'host', which is the least wrong default:
 * every playbook's un-typeable draws are machine names.
 */
function classifyIoc(key, value) {
  const k = String(key || '').toLowerCase();
  const v = String(value);

  if (IPV4_RE.test(v)) return 'ip';
  if (HASH_RE.test(v)) return 'hash';
  if (/^\d{1,5}$/.test(v) && /port/.test(k)) return 'port';
  // A path is decided by the SEPARATOR first and the pool name second. Both
  // halves earn their place: `/tmp/.cache` has a separator and a pool called
  // `logs`; `secure` and `messages` are log paths with neither a separator nor
  // an extension, and only the pool name says so.
  if (WINDOWS_PATH_RE.test(v) || /[/\\]/.test(v)) return 'path';
  if (/(^|_)(log|file|path|dir|share|doc)/.test(k)) return 'path';
  if (PROCESS_RE.test(v) || /(^|_)(proc|process|cmd|image|tool|bin|svc|service|daemon)/.test(k)) return 'process';
  if (/(^|_)(user|account|actor|principal|group)/.test(k)) return 'user';
  if (/(^|_)(domain|fqdn|url|dns|site|host_name)/.test(k)) return 'domain';
  // A dotted name with a real-looking TLD is a domain; a dotted name that is an
  // address was caught above. `srv-prod-01` has no dot and stays a host.
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !/^\d/.test(v)) return 'domain';
  return 'host';
}

/** The /24 base of a dotted-quad, or null. */
function slash24(value) {
  const m = IPV4_RE.exec(String(value));
  return m ? `${m[1]}.${m[2]}.${m[3]}` : null;
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/**
 * Compile the graded truth for one synthetic run.
 *
 * @param {object}  opts
 * @param {string}  opts.runId            THE SEED. Not optional, not defaulted.
 * @param {object}  opts.playbook         the attack playbook, as staged
 * @param {object} [opts.floor]           the benign floor playbook; defaults to
 *                                        the baked host-baseline.json
 * @param {number} [opts.requestedSeconds] duration_seconds; falls back to the
 *                                        playbook's nominal_seconds exactly as
 *                                        cc-emit.js:640 does for a chain
 * @returns {{version, engine, run_id, techniques, iocs, timeline, floor_techniques,
 *            floor_values, floor_truncated, totals}}
 */
function compileAnswerKey(opts) {
  const o = opts || {};
  const runId = String(o.runId || '');
  if (!runId) {
    // Not a defaultable argument. A key seeded from '' describes an attack no
    // lane ran, and every symptom of that appears in a student's grade rather
    // than in a log.
    throw new Error('compileAnswerKey: runId is the seed and is required');
  }
  const playbook = o.playbook;
  if (!playbook || !Array.isArray(playbook.steps) || !playbook.steps.length) {
    throw new Error('compileAnswerKey: a playbook with steps is required');
  }

  const floor = o.floor || loadFloorPlaybook();

  // ── Reproduce the guest, exactly. See the header. ────────────────────────
  const requested = Number.isFinite(Number(o.requestedSeconds)) && Number(o.requestedSeconds) > 0
    ? Number(o.requestedSeconds)
    : Number(playbook.nominal_seconds);
  const plan = emit.planTimeline(playbook, {
    rng: emit.makeRng(emit.seedFrom(runId)),
    requested,
  });

  const indexed = indexEvents(plan);

  // ── Techniques ───────────────────────────────────────────────────────────
  const byTechnique = new Map();
  for (const ev of plan.events) {
    const id = ev.technique;
    if (!id) continue;
    let row = byTechnique.get(id);
    if (!row) {
      row = { id, tactic: ev.tactic || null, first_offset_s: ev.offset, event_count: 0 };
      byTechnique.set(id, row);
    }
    if (ev.offset < row.first_offset_s) row.first_offset_s = ev.offset;
    if (!row.tactic && ev.tactic) row.tactic = ev.tactic;
    row.event_count += 1;
  }
  const techniques = [...byTechnique.values()]
    .map((t) => ({ ...t, first_offset_s: Math.round(t.first_offset_s) }))
    // Ordered by when they first fire, then by id — this ordering IS the
    // timeline the student is graded against, so it must be total and stable.
    .sort((a, b) => (a.first_offset_s - b.first_offset_s) || a.id.localeCompare(b.id));

  // ── IOCs: attack values the floor cannot produce ─────────────────────────
  const floorUniverse = collectDeclaredValues(floor);
  const attackDeclared = collectDeclaredValues(playbook);

  /** @type {Map<string,{key:string,value:string}>} candidate value -> where it came from */
  const candidates = new Map();

  // (a) The resolved ENTITIES. These are the coherent adversary identities —
  //     one attacker IP and one victim per run, which is what makes an event
  //     pivotable at all — so they are the IOCs that matter most.
  for (const [key, value] of Object.entries(plan.entities || {})) {
    candidates.set(String(value), { key, value: String(value) });
  }

  // (b) Values from pools the ATTACK declares and the FLOOR does not. A pool
  //     name the floor also declares is shared vocabulary by construction
  //     (`users`, `lanips`) and nothing drawn from it can be attack-only.
  for (const [poolKey, list] of Object.entries(playbook.pools || {})) {
    if (Object.prototype.hasOwnProperty.call(floor.pools || {}, poolKey)) continue;
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      const value = String(raw);
      if (!candidates.has(value)) candidates.set(value, { key: poolKey, value });
    }
  }

  const iocs = [];
  for (const { key, value } of candidates.values()) {
    if (value.length < MIN_IOC_LENGTH) continue;
    if (value.includes('{{')) continue;                 // an unexpanded token
    if (floorUniverse.values.has(value)) continue;      // ordinary traffic
    // An address whose /24 the floor also draws from is NOT an indicator: the
    // floor's own random last octet lands in that space every run, so grading
    // it would penalise a student for reporting a machine that is always there.
    const net = slash24(value);
    if (net && floorUniverse.prefixes.has(net)) continue;
    // Same guard the other way: an attack value that the ATTACK also declares
    // as a shared pool the floor holds is caught above; this catches an entity
    // literal that happens to equal a floor pool member.
    if (attackDeclared.values.has(value) && floorUniverse.values.has(value)) continue;

    let count = 0;
    const techniqueIds = new Set();
    for (const ev of indexed) {
      if (!ev.hay.includes(value)) continue;
      count += 1;
      if (ev.technique) techniqueIds.add(ev.technique);
    }
    // A declared value the plan never actually emitted is not an indicator of
    // anything — it is a pool entry the RNG did not reach.
    if (count === 0) continue;

    iocs.push({
      type: classifyIoc(key, value),
      value,
      technique_ids: [...techniqueIds].sort(),
      event_count: count,
    });
  }
  iocs.sort((a, b) => a.type.localeCompare(b.type) || a.value.localeCompare(b.value));

  // ── Timeline: one entry per playbook STEP, at its planned start ───────────
  // Recomputed with the plan's own solved gapScale, so the offsets are the ones
  // the guest laid the events out on rather than an approximation of them.
  const starts = emit.layout(playbook.steps, plan.gapScale).starts;
  const timeline = playbook.steps.map((step, i) => {
    const src = step.source || {};
    const md = step.metadata || {};
    return {
      step: i + 1,
      technique: step.technique || playbook.technique || null,
      offset_s: Math.round(starts[i]),
      // The label is for a human reading the key, and it must never be
      // `step.action` or `step.detection_opportunity` — E4's compiler puts the
      // answer itself in those, and this object is one projection bug away from
      // a student.
      label: String(md.event_action || `${src.type || 'event'}/${src.name || 'unknown'}`),
    };
  });

  // ── The floor's own MITRE tags: the defensible-miss set ───────────────────
  // The floor deliberately tags 4-20% of its benign events with real technique
  // ids, precisely so "has a MITRE tag" is not itself the answer. A student who
  // reports one of these found what was planted for them; scoring.js gives them
  // 'partial' and zero, never a penalty. That rule is only possible because the
  // set travels with the key.
  const floorTechniques = new Set();
  for (const step of floor.steps || []) {
    if (step.technique) floorTechniques.add(String(step.technique));
  }
  if (floor.technique) floorTechniques.add(String(floor.technique));

  const floorValues = [...floorUniverse.values].map((v) => v.toLowerCase()).sort();
  const truncated = floorValues.length > FLOOR_VALUE_CAP;

  return {
    version: ANSWER_KEY_VERSION,
    engine: 'synthetic',
    run_id: runId,
    requested_seconds: Math.round(requested),
    techniques,
    iocs,
    timeline,
    floor_techniques: [...floorTechniques].sort(),
    // Lowercased because scoring.js matches IOCs case-insensitively; sorted so
    // recompiling the same run is byte-identical.
    floor_values: truncated ? floorValues.slice(0, FLOOR_VALUE_CAP) : floorValues,
    floor_truncated: truncated,
    totals: {
      events: plan.events.length,
      techniques: techniques.length,
      iocs: iocs.length,
    },
  };
}

/** The baked benign floor, read once and frozen. */
let _floorCache = null;
function loadFloorPlaybook() {
  if (_floorCache) return _floorCache;
  _floorCache = JSON.parse(fs.readFileSync(DEFAULT_FLOOR_PLAYBOOK, 'utf8'));
  return _floorCache;
}

/**
 * The key for a run, dispatched on its engine.
 *
 * Returns an EMPTY-but-shaped key for an engine that cannot predict what it
 * will produce. Caldera is exactly that case: real abilities run against real
 * hosts and what lands in Sysmon is whatever actually happened, so a compiled
 * key would be a guess. An empty key grades nothing and says so; a guessed one
 * mis-grades and does not.
 *
 * `reason` is staff-facing and exists so the board can render "this run is not
 * auto-graded" rather than a silent zero.
 */
function answerKeyForRun(run, opts) {
  const engine = (run && run.engine) || 'synthetic';
  if (engine !== 'synthetic') {
    return {
      version: ANSWER_KEY_VERSION,
      engine,
      run_id: run ? run.run_id : null,
      techniques: [], iocs: [], timeline: [],
      floor_techniques: [], floor_values: [], floor_truncated: false,
      totals: { events: 0, techniques: 0, iocs: 0 },
      reason: `engine '${engine}' does not compile an answer key ahead of execution`,
    };
  }
  return compileAnswerKey({
    runId: run.run_id,
    playbook: (opts && opts.playbook) || run.playbook,
    floor: opts && opts.floor,
    requestedSeconds: run.duration_seconds,
  });
}

module.exports = {
  ANSWER_KEY_VERSION,
  DEFAULT_FLOOR_PLAYBOOK,
  FLOOR_VALUE_CAP,
  compileAnswerKey,
  answerKeyForRun,
  loadFloorPlaybook,
  // Exported for the tests, which pin the classification vocabulary and the
  // floor-universe superset rule directly rather than through a whole key.
  collectDeclaredValues,
  classifyIoc,
};
