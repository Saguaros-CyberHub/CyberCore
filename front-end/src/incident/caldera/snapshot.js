/**
 * ============================================================================
 * CALDERA ADVERSARY SNAPSHOT — what was launched, frozen at launch
 * ============================================================================
 *
 * WHY THIS FILE EXISTS. THIS IS THE ONE THAT PROTECTS GRADES.
 * ----------------------------------------------------------------------------
 * A Caldera adversary is not ours. It lives on the authoring server, an
 * instructor edits it in a real web UI, and Caldera has NO per-object ownership
 * — conf/local.yml users are credentials in a 'red' or 'blue' GROUP, which is a
 * role, not tenancy — so every instructor who can open that UI can reorder,
 * extend or delete every adversary on it, including one that three sections have
 * already been graded against.
 *
 * The moment that happens, an adversary id stops identifying an exercise:
 *
 *   * src/incident/scoring.js grades a student's findings against the run's
 *     stored `answer_key`. Recompile a key from a LATER version of the adversary
 *     and it describes activity that never ran in that lane — every correct
 *     answer becomes a miss and every irrelevant one becomes a false positive.
 *     The grades were already issued. Nothing errors, nothing logs, and the only
 *     symptom is a cohort that all "failed" the same question.
 *   * Two sections running "the same" adversary a week apart get two different
 *     exercises, with no record anywhere of what the difference was. The second
 *     section's complaint is unanswerable, because there is nothing left to
 *     compare.
 *   * The ABILITY CATALOG drifts too, and independently: a plugin update changes
 *     what `ab-lsass-002` executes, or removes it. The adversary is untouched and
 *     the exercise still changed.
 *
 * cybercore_incident_run already answers exactly this problem for the synthetic
 * engine: it stores `playbook` and `answer_key` as JSONB so a run is
 * reproducible from its own row rather than from whatever the compiler happens
 * to produce today. A Caldera adversary MUST get the same treatment, and this
 * file is that treatment.
 *
 * THE PROPERTY THAT MAKES IT WORTH ANYTHING
 * ----------------------------------------------------------------------------
 * A snapshot must be SUFFICIENT TO RE-DERIVE THE ANSWER KEY WITHOUT CONTACTING
 * CALDERA AGAIN. Not "enough to describe what happened" — enough to RECOMPUTE
 * the graded truth, offline, months later, from the row alone. That is the
 * difference between a record and an audit trail, and it is asserted directly in
 * test/caldera-snapshot.test.js: a key re-derived from a snapshot must equal the
 * key the live compile produced, field for field.
 *
 * Exactly two of the compiler's inputs live on the Caldera side and therefore
 * MUST be captured here — the adversary (its ordered ability list) and the
 * resolved ability rows (technique, tactic, platforms, name). The scenario and
 * the compile options are CyberCore's own, but they are captured too, because a
 * record that needs three other rows to be interpreted is a record that stops
 * being interpretable the first time one of them is edited.
 *
 * WHY IT IS FROZEN, AND WHY A SHALLOW COPY IS NOT ENOUGH
 * ----------------------------------------------------------------------------
 * The adversary handed in is a live object a caller is still using; its
 * `atomic_ordering` is an array, and an array copied by reference is the same
 * array. A caller that later pushes one ability id onto it — a retry that
 * re-plans, a UI that lets an instructor tweak before a second launch — would
 * mutate the "immutable" record of what the FIRST run did, retroactively. So the
 * snapshot is deep-cloned (nothing shares a reference with the caller) and then
 * deep-frozen (nothing downstream can edit it either), and both halves are
 * tested.
 *
 * WHAT IS DELIBERATELY NOT IN IT
 * ----------------------------------------------------------------------------
 * `attack_path[].action` and `attack_path[].detection_opportunity` — the
 * scenario prose that IS the answer to the exercise. The scenario is stored in a
 * whitelisted, prose-stripped form carrying only what the compiler reads
 * (scenario_id, name, type, and per step: step, technique, target).
 *
 * That strip is provably free: compileAdversary reads those two fields for
 * nothing but its own leak guard, so a stripped scenario compiles to a
 * BYTE-IDENTICAL answer key — which is asserted, rather than assumed, in the
 * tests. Defence in depth is the point: the snapshot is much more likely than an
 * answer key to be handed to an authoring UI, exported as "what did this run
 * do", or attached to a support ticket, and every one of those paths is one
 * projection bug away from a student.
 *
 * PURITY. No network, no database, no fs, no clock, no RNG. `takenAt` is passed
 * in by the caller that has a clock, exactly as the adversary compiler takes its
 * run id rather than generating one: a module that stamps its own time cannot be
 * tested for equality against itself.
 *
 * THIS FILE IS ABOUT AUTHORING AND RECORD-KEEPING, NEVER ABOUT DISPATCH. It
 * registers no engine and launches nothing; engines/index.js still refuses
 * 'caldera'.
 * ============================================================================
 */

'use strict';

const crypto = require('crypto');

const { compileAdversary, normalizeAbility } = require('./adversary');

/**
 * Bumped when the SHAPE of a snapshot changes, not when a value does.
 *
 * A stored snapshot carries its version so a re-derivation running under a newer
 * build can refuse rather than mis-grade — the same contract ANSWER_KEY_VERSION
 * has with src/incident/scoring.js.
 */
const SNAPSHOT_VERSION = 1;

/** Prose fields that must never reach a snapshot. Both are the answer. */
const ANSWER_FIELDS = ['action', 'detection_opportunity'];

/**
 * Below this length a prose field is too short to check for as a substring, for
 * the same reason adversary.js gives: a six-character detection_opportunity like
 * "Sysmon" collides with an ability name and would make the guard throw on a
 * CORRECT snapshot.
 */
const MIN_LEAK_CHECK_LENGTH = 12;

/** `matched_by` for a timeline derived with no scenario. See deriveKeyFromOrdering. */
const MATCHED_BY_ADVERSARY = 'adversary';

/**
 * Thrown when a snapshot cannot reproduce what it claims to record.
 *
 * A throw, not a warning, and it is the only correct response: the value the
 * caller would otherwise receive is an answer key that does NOT describe the run
 * it is about to grade, and there is no symptom downstream — scoring.js accepts
 * any well-shaped key and marks students against it.
 */
class SnapshotDriftError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'SnapshotDriftError';
    this.code = 'CALDERA_SNAPSHOT_DRIFT';
    this.detail = detail || null;
  }
}

/** Thrown when scenario prose reached the snapshot. Same class of failure as AnswerLeakError. */
class SnapshotLeakError extends Error {
  constructor(field) {
    super(`snapshotAdversary: scenario '${field}' text reached the snapshot — that field is the `
      + 'answer to the exercise and is stripped by construction, so this means the whitelist was '
      + 'bypassed');
    this.name = 'SnapshotLeakError';
    this.code = 'CALDERA_SNAPSHOT_ANSWER_LEAK';
    this.field = field;
  }
}

// ---------------------------------------------------------------------------
// Plain data
// ---------------------------------------------------------------------------

const str = (v) => (v == null ? '' : String(v)).trim();

/**
 * A deep copy that shares NOTHING with its argument.
 *
 * A JSON round trip rather than structuredClone, and that is deliberate: the
 * snapshot's destination is a JSONB column, so anything that cannot survive
 * JSON.stringify could not be stored anyway. The clone is therefore also a
 * validation — a Map, a Date or a function in the input becomes visibly wrong
 * here rather than invisibly wrong three months later when the row is read back.
 */
function clonePlain(value) {
  if (value === undefined || value === null) return null;
  return JSON.parse(JSON.stringify(value));
}

/**
 * Freeze every object and array reachable from `value`.
 *
 * Object.freeze() alone is SHALLOW: it would leave `snapshot.adversary`,
 * `snapshot.abilities[0]` and every array inside them fully writable, which
 * means the one mutation this file exists to prevent — pushing an id onto
 * atomic_ordering — would still succeed on a "frozen" snapshot.
 */
function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * JSON with every object's keys in sorted order.
 *
 * The digest below has to be stable across two builds of the same record, and
 * key order in JavaScript follows insertion order — so a refactor that assigns
 * two fields in the other order would change the digest of an unchanged
 * snapshot and make every stored record look tampered with.
 */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

/**
 * The snapshot's content digest.
 *
 * EVIDENCE OF DRIFT, NOT A SIGNATURE. Anyone who can edit the stored row can
 * recompute this, and it is not claimed otherwise — what it catches is the case
 * that actually happens: a record edited by a migration, a partial write, or a
 * well-meaning fix applied to one field of a JSONB blob. Those leave the digest
 * behind, and a mismatch says "this is no longer the thing that was launched"
 * before anyone grades against it.
 */
function snapshotDigest(snapshot) {
  const s = snapshot && typeof snapshot === 'object' ? snapshot : {};
  const body = {};
  for (const key of Object.keys(s)) {
    if (key === 'digest') continue;
    body[key] = s[key];
  }
  return crypto.createHash('sha256').update(canonical(body), 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Whitelists
// ---------------------------------------------------------------------------

/**
 * The adversary, field by field, never spread.
 *
 * Same rule as adversary.js's buildAdversary: a whitelist cannot leak a field
 * the shape grows later, and "delete the fields we do not want" fails open the
 * first time upstream adds one.
 */
function snapshotAdversaryRecord(adversary) {
  const a = adversary && typeof adversary === 'object' ? adversary : {};
  const id = str(a.adversary_id || a.id);
  if (!id) {
    throw new SnapshotDriftError(
      'snapshotAdversary: the adversary must carry an adversary_id — without it the record cannot '
      + 'be tied back to the profile a later run would be launched from'
    );
  }
  const ordering = (Array.isArray(a.atomic_ordering) ? a.atomic_ordering : [])
    .map(str)
    .filter(Boolean);
  return {
    adversary_id: id,
    name: str(a.name) || null,
    description: str(a.description) || null,
    // Copied, not referenced. See the header.
    atomic_ordering: ordering.slice(),
    objective: a.objective == null ? null : str(a.objective) || null,
    tags: (Array.isArray(a.tags) ? a.tags : []).map(str).filter(Boolean),
  };
}

/**
 * The scenario, PROSE-STRIPPED, carrying exactly what compileAdversary reads.
 *
 * `action` and `detection_opportunity` are dropped BY CONSTRUCTION (this builds
 * a new object from named fields; it never deletes) and the result is re-checked
 * by assertNoAnswerText below. Belt and braces, because the failure is
 * unobservable and permanent.
 */
function snapshotScenarioRecord(scenario) {
  const s = scenario && typeof scenario === 'object' ? scenario : null;
  if (!s) return null;
  const path = Array.isArray(s.attack_path) ? s.attack_path : [];
  return {
    scenario_id: str(s.scenario_id) || null,
    name: str(s.name) || null,
    type: str(s.type) || null,
    attack_path: path
      .filter((step) => step && typeof step === 'object')
      .map((step) => ({
        // `step` stays whatever it was — orderSteps() treats a missing number
        // and a present one differently, and coercing here would change the
        // execution order the snapshot claims to record.
        step: Number.isFinite(Number(step.step)) ? Number(step.step) : null,
        technique: str(step.technique) || null,
        target: str(step.target) || null,
      })),
  };
}

/**
 * The resolved ability rows, in the order the adversary runs them, deduplicated.
 *
 * This is THE Caldera-side input the snapshot exists to capture. Re-derivation
 * feeds it back to compileAdversary as the injected catalog, which is why the
 * shape is the one normalizeAbility() accepts: id, technique, tactic, name,
 * platforms.
 *
 * An id in `atomic_ordering` that the catalog does not carry is recorded in
 * `missing_abilities` rather than dropped or thrown on. It is a real state — an
 * adversary hand-authored against an ability a later plugin update removed — and
 * refusing to record what was launched is worse than recording it with the gap
 * named.
 */
function snapshotAbilityRows(ordering, abilities) {
  const byId = new Map();
  for (const raw of (Array.isArray(abilities) ? abilities : [])) {
    const ab = normalizeAbility(raw);
    if (ab && !byId.has(ab.id)) byId.set(ab.id, ab);
  }

  const rows = [];
  const missing = [];
  const seen = new Set();
  for (const id of ordering) {
    if (seen.has(id)) continue;
    seen.add(id);
    const ab = byId.get(id);
    if (!ab) { missing.push(id); continue; }
    rows.push({
      id: ab.id,
      technique: ab.technique,
      tactic: ab.tactic,
      name: ab.name,
      // Already sorted by normalizeAbility, so two catalogs listing the same
      // platforms in a different order snapshot identically.
      platforms: ab.platforms.slice(),
    });
  }
  return { rows, missing };
}

/**
 * The fact source as it was AT LAUNCH — the class's host set, not today's.
 *
 * A whitelist again, and a narrow one: the extra keys buildFactSource() returns
 * (host roles, exclusion reasons, warnings) describe the derivation, while what
 * a re-derivation needs is what the operation was actually seeded with.
 */
function snapshotFactSourceRecord(factSource) {
  const f = factSource && typeof factSource === 'object' ? factSource : null;
  if (!f) return null;
  return {
    id: str(f.id) || null,
    name: str(f.name) || null,
    scope_label: str(f.scope_label) || null,
    facts: (Array.isArray(f.facts) ? f.facts : [])
      .filter((fact) => fact && typeof fact === 'object')
      .map((fact) => ({
        trait: str(fact.trait),
        value: str(fact.value),
        score: Number.isFinite(Number(fact.score)) ? Number(fact.score) : 1,
      }))
      .filter((fact) => fact.trait && fact.value),
    // {windows, linux, other} when the caller built one — "this class was 3
    // Windows and 1 Linux ON THE DAY", which is the context that explains why a
    // linux ability produced nothing and must not be re-read from a spec that
    // has since been redeployed.
    platforms: f.platforms && typeof f.platforms === 'object' ? clonePlain(f.platforms) : null,
  };
}

/**
 * The compile options, because they change the OUTPUT and not just the process.
 *
 * `maxAbilitiesPerStep` and `allowParentTechnique` in particular: re-deriving
 * with the defaults where the launch used 2 and true produces a shorter ability
 * list and a different technique set — a key that grades a different exercise.
 */
function snapshotOptionsRecord(options) {
  const o = options && typeof options === 'object' ? options : {};
  const platform = Array.isArray(o.platform)
    ? o.platform.map(str).filter(Boolean)
    : (str(o.platform) || null);
  return {
    platform,
    maxAbilitiesPerStep: Number.isFinite(Number(o.maxAbilitiesPerStep))
      && Number(o.maxAbilitiesPerStep) > 0 ? Math.floor(Number(o.maxAbilitiesPerStep)) : 1,
    allowParentTechnique: o.allowParentTechnique === true,
    name: str(o.name) || null,
    runId: str(o.runId) || null,
  };
}

/**
 * Refuse to return a snapshot carrying authoring prose.
 *
 * Never fires on a correct build — the scenario record is a whitelist. It exists
 * for the incorrect one: someone adds `notes: step.action` while debugging, or
 * spreads `...scenario` into the record, and the field that IS the answer is
 * stored in a blob that gets exported, ticketed and rendered.
 */
function assertNoAnswerText(record, scenario) {
  const path = Array.isArray(scenario && scenario.attack_path) ? scenario.attack_path : [];
  if (!path.length) return;
  const blob = JSON.stringify(record);
  for (const step of path) {
    if (!step || typeof step !== 'object') continue;
    for (const field of ANSWER_FIELDS) {
      const text = str(step[field]);
      if (text.length < MIN_LEAK_CHECK_LENGTH) continue;
      if (blob.includes(text)) throw new SnapshotLeakError(field);
    }
  }
}

// ---------------------------------------------------------------------------
// The snapshot
// ---------------------------------------------------------------------------

/**
 * Freeze what was launched.
 *
 * @param {object}   opts
 * @param {object}   opts.adversary    the compiled or hand-authored adversary.
 *                                     Needs `adversary_id` and `atomic_ordering`.
 * @param {object[]} opts.abilities     the ability catalog AS FETCHED AT LAUNCH.
 *                                     Only the rows the ordering names are kept.
 * @param {object}   [opts.factSource]  buildFactSource()'s result, or the wire
 *                                     shape — the class's host set at launch.
 * @param {object}   [opts.scenario]    the CyberCore scenario the adversary was
 *                                     compiled from, when there was one. STORED
 *                                     PROSE-STRIPPED. Absent for an adversary
 *                                     authored directly in Caldera's UI, which
 *                                     is what the authoring instance is for.
 * @param {object}   [opts.options]     the compile options used. See
 *                                     snapshotOptionsRecord — these change the
 *                                     output, so a re-derivation without them is
 *                                     a re-derivation of something else.
 * @param {string|number} [opts.takenAt] when. Passed in, never read from a clock:
 *                                     see the header on purity.
 * @returns {object} deep-cloned and DEEP-FROZEN
 * @throws {SnapshotDriftError} when the adversary carries no id
 * @throws {SnapshotLeakError}  when scenario prose reached the record
 */
function snapshotAdversary(opts) {
  const o = opts || {};

  const adversary = snapshotAdversaryRecord(o.adversary);
  const { rows, missing } = snapshotAbilityRows(adversary.atomic_ordering, o.abilities);
  const scenario = snapshotScenarioRecord(o.scenario);

  // Over the ABILITIES, not over the class: "what this adversary can run on".
  // The class's own mix is on fact_source.platforms, and the two are different
  // questions — an all-windows adversary against an all-linux class needs both
  // numbers to explain why nothing happened.
  const platforms = { windows: 0, linux: 0, darwin: 0, unspecified: 0 };
  for (const row of rows) {
    if (!row.platforms.length) { platforms.unspecified += 1; continue; }
    for (const p of row.platforms) {
      if (Object.prototype.hasOwnProperty.call(platforms, p) && p !== 'unspecified') {
        platforms[p] += 1;
      }
    }
  }

  const record = {
    version: SNAPSHOT_VERSION,
    taken_at: o.takenAt == null ? null : String(o.takenAt),
    adversary,
    // The ordering is repeated at the top level ON PURPOSE. It is the single
    // most important thing in the record — the exercise IS the ordered ability
    // list — and a reader should not have to know that it also lives inside the
    // adversary object to find it.
    ordering: adversary.atomic_ordering.slice(),
    abilities: rows,
    missing_abilities: missing,
    platforms,
    fact_source: snapshotFactSourceRecord(o.factSource),
    scenario,
    options: snapshotOptionsRecord(o.options),
  };

  assertNoAnswerText(record, o.scenario);
  record.digest = snapshotDigest(record);

  // clonePlain first so nothing in the result shares a reference with the
  // caller's objects, deepFreeze second so nothing downstream can edit the
  // result either. Either one alone leaves a mutation path open.
  return deepFreeze(clonePlain(record));
}

// ---------------------------------------------------------------------------
// Re-derivation — the property that makes the snapshot worth storing
// ---------------------------------------------------------------------------

/**
 * The answer key for an adversary with NO scenario behind it.
 *
 * An adversary authored directly in Caldera's UI has no attack path, no step
 * numbers and no targets — the ordered ability list is the whole of what was
 * asked for. So the key is derived straight from it: one timeline entry per
 * slot, `step` being the position, `target` null, and `matched_by` the honest
 * 'adversary' rather than 'exact' (nothing was matched; the instructor chose).
 *
 * WHY THIS IS NOT ROUTED THROUGH compileAdversary LIKE THE OTHER PATH. It was,
 * and it is wrong: the compiler resolves a step's technique to the
 * LOWEST-SORTING ability carrying it, so an adversary that uses `ab-lsass-002`
 * where the catalog also holds `ab-lsass-001` would re-derive as `ab-lsass-001`
 * — a key describing an ability the operation never ran. A synthesised scenario
 * cannot express "this slot, that ability", so this path builds the key
 * directly, and test/caldera-snapshot.test.js pins its shape against both
 * answer-key.js and a live compile so the two cannot drift apart unseen.
 */
function deriveKeyFromOrdering(snapshot, runId) {
  const byId = new Map(snapshot.abilities.map((a) => [a.id, a]));

  const techniqueRows = new Map();
  const timeline = [];
  let position = 0;

  for (const id of snapshot.ordering) {
    const ab = byId.get(id);
    // A missing ability contributes nothing to the key for the same reason an
    // unmapped step does not: the key describes what WILL run, and an ability
    // the server no longer carries will not.
    if (!ab) continue;
    position += 1;

    if (!techniqueRows.has(ab.technique)) {
      techniqueRows.set(ab.technique, {
        id: ab.technique, tactic: ab.tactic, first_offset_s: null, event_count: null,
      });
    }
    const row = techniqueRows.get(ab.technique);
    if (!row.tactic && ab.tactic) row.tactic = ab.tactic;

    timeline.push({
      step: position,
      technique: ab.technique,
      // NULL, never an estimate — a Caldera link runs when an agent next
      // beacons and takes as long as the command takes. adversary.js makes the
      // same point about the same field.
      offset_s: null,
      label: ab.name,
      ability_ids: [ab.id],
      matched_by: MATCHED_BY_ADVERSARY,
      target: null,
    });
  }

  const techniques = [...techniqueRows.values()].map((t) => ({ ...t }));

  return {
    version: 1,
    engine: 'caldera',
    run_id: runId || null,
    requested_seconds: null,
    techniques,
    iocs: [],
    timeline,
    floor_techniques: [],
    floor_values: [],
    floor_truncated: false,
    totals: { events: null, techniques: techniques.length, iocs: 0 },
    scenario_id: null,
    adversary_id: snapshot.adversary.adversary_id,
    // An ability the ordering names and the snapshot's catalog does not carry is
    // this path's version of an unmapped step: it is counted, and it is NOT
    // listed by technique, because with no catalog row there is no technique to
    // list. Naming a guess here would put an id in the key that nothing ran.
    unmapped_techniques: [],
    unmapped_step_count: snapshot.missing_abilities.length,
    reason: 'Caldera executes real abilities on real hosts, so the telemetry a run produces is not '
      + 'predictable from here: iocs and totals.events are empty by definition, and there is no '
      + 'benign floor, so an unlisted value scores as a false positive rather than a defensible '
      + 'miss. This key was re-derived from a launch snapshot of an adversary authored directly in '
      + 'Caldera, so it has no scenario: the timeline is the adversary\'s own ability order.',
  };
}

/**
 * Re-derive the graded truth from a snapshot. NO NETWORK, NO CALDERA.
 *
 * This is the function the whole file is for. Everything it needs from the
 * Caldera side — the ordering and the resolved ability rows — is in the
 * snapshot, so the key it returns is the key the launch produced even if the
 * adversary has since been rewritten, the ability deleted and the server
 * rebuilt.
 *
 * TWO PATHS, and which one runs depends on whether a scenario was captured:
 *
 *   scenario present  the snapshot's ability rows are fed BACK to
 *                     compileAdversary as the injected catalog. One compiler,
 *                     one key shape, no second implementation to drift — and
 *                     the recompiled ordering is checked against the snapshot's,
 *                     so a snapshot that cannot reproduce itself throws instead
 *                     of quietly grading something else.
 *   scenario absent   deriveKeyFromOrdering, above.
 *
 * @param {object} snapshot   as returned by snapshotAdversary()
 * @param {object} [overrides]
 * @param {string} [overrides.runId]   stamped into the key. Defaults to the run
 *                                     id captured at launch; supply it when the
 *                                     same snapshot is relaunched for a second
 *                                     section, which is precisely the case that
 *                                     must produce the SAME exercise.
 * @param {object} [overrides.scenario] for a caller holding the scenario
 *                                     elsewhere (the run row). The snapshot's
 *                                     own copy wins unless this is given.
 * @returns {object} an answer key in src/incident/answer-key.js's shape
 * @throws {SnapshotDriftError}
 */
function answerKeyFromSnapshot(snapshot, overrides) {
  const s = snapshot && typeof snapshot === 'object' ? snapshot : null;
  if (!s || !s.adversary || !Array.isArray(s.ordering) || !Array.isArray(s.abilities)) {
    throw new SnapshotDriftError(
      'answerKeyFromSnapshot: this is not a snapshot — it carries no adversary, ordering or '
      + 'ability list, so there is nothing to re-derive a key from'
    );
  }
  if (Number(s.version) > SNAPSHOT_VERSION) {
    // The same refusal scoring.js makes on a newer answer key: a record written
    // by a newer build may mean something this one does not know, and grading
    // against a guess is worse than refusing.
    throw new SnapshotDriftError(
      `answerKeyFromSnapshot: snapshot version ${s.version} was written by a newer build than this `
      + `one (${SNAPSHOT_VERSION}) — refusing to re-derive a key from a shape it may not understand`,
      { snapshot_version: s.version, supported: SNAPSHOT_VERSION }
    );
  }

  const o = overrides || {};
  const runId = str(o.runId) || str(s.options && s.options.runId) || null;
  const scenario = o.scenario || s.scenario || null;

  if (!scenario || !Array.isArray(scenario.attack_path) || !scenario.attack_path.length) {
    return deriveKeyFromOrdering(s, runId);
  }

  const opts = s.options || {};
  const { adversary, answerKey } = compileAdversary({
    scenario,
    // THE POINT OF THE WHOLE FILE: the catalog is the snapshot's, not the
    // server's. A recompile that fetched today's catalog would be exactly the
    // silent regrade this exists to prevent.
    abilities: s.abilities,
    options: {
      platform: opts.platform == null ? undefined : opts.platform,
      maxAbilitiesPerStep: opts.maxAbilitiesPerStep,
      allowParentTechnique: opts.allowParentTechnique === true,
      name: opts.name == null ? undefined : opts.name,
      runId,
    },
  });

  const before = s.ordering.join(',');
  const after = (adversary.atomic_ordering || []).join(',');
  if (before !== after) {
    // The snapshot does not reproduce itself. Something it captured is
    // incomplete — most likely the options, or an ability row edited in place —
    // and the key just compiled describes a DIFFERENT operation from the one
    // that ran. There is no safe fallback: return it and every student is graded
    // against activity their lane never performed.
    throw new SnapshotDriftError(
      'answerKeyFromSnapshot: re-deriving this snapshot produced a different ability ordering than '
      + `the one it recorded (recorded ${before || '(empty)'}; re-derived ${after || '(empty)'}). `
      + 'The key would describe an operation that did not run, and scoring.js would mark every '
      + 'student against it. Refusing.',
      { recorded: s.ordering.slice(), rederived: (adversary.atomic_ordering || []).slice() }
    );
  }

  return answerKey;
}

/**
 * Has a stored snapshot changed since it was taken?
 *
 * Returns true when the record's own digest still matches its contents. See
 * snapshotDigest: this is evidence, not a signature.
 */
function verifySnapshot(snapshot) {
  const s = snapshot && typeof snapshot === 'object' ? snapshot : null;
  if (!s || typeof s.digest !== 'string' || !s.digest) return false;
  return snapshotDigest(s) === s.digest;
}

module.exports = {
  snapshotAdversary,
  answerKeyFromSnapshot,
  verifySnapshot,
  snapshotDigest,
  SnapshotDriftError,
  SnapshotLeakError,
  SNAPSHOT_VERSION,
  MATCHED_BY_ADVERSARY,
  // Exported for the tests, which pin the freeze and the canonicalisation
  // directly rather than only through a whole snapshot.
  deepFreeze,
  clonePlain,
  canonical,
};
