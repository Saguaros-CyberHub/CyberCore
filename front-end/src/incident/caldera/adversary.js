/**
 * ============================================================================
 * CALDERA ADVERSARY COMPILER — threat scenario -> Caldera adversary profile
 * ============================================================================
 *
 * ############################################################################
 * # THIS FILE HAS NEVER BEEN RUN AGAINST A REAL CALDERA SERVER.              #
 * #                                                                          #
 * # There is no Caldera anywhere in this repository and no Caldera server    #
 * # exists on any cluster. Nothing here has been validated against a live    #
 * # instance, against an ability catalog fetched from one, or against an     #
 * # operation that actually executed. Every field name below is taken from   #
 * # upstream's documented v2 API and YAML profile shape and is UNVERIFIED.   #
 * #                                                                          #
 * # What IS verified is the part that needs no server: the mapping is pure,  #
 * # deterministic, and covered by test/caldera-adversary.test.js over an     #
 * # INJECTED catalog. Read this file as "the compiler is ready for the day a #
 * # server exists", never as "Caldera works".                                #
 * ############################################################################
 *
 * WHAT THIS DOES
 * ----------------------------------------------------------------------------
 * A CiAB client profile carries `threat_profile.scenarios[].attack_path[]`,
 * generated as prose plus a MITRE technique id per step:
 *
 *     { step, action, target, technique, detection_opportunity }
 *
 * Caldera does not execute prose. It executes an ADVERSARY PROFILE, which is
 * nothing but an ordered list of ability ids (`atomic_ordering`). So the whole
 * job is: technique id -> ability id, in order, losing nothing quietly.
 *
 * WHY THE ABILITY CATALOG IS INJECTED AND NOT FETCHED
 * ----------------------------------------------------------------------------
 * This module is PURE: no network, no database, no fs, no clock, no RNG. The
 * catalog arrives as an argument. Three reasons, and the third matters most
 * right now:
 *
 *   1. It is testable offline. A fetch here would make every test either a
 *      live-server test or a mock, and there is no live server to test against.
 *   2. The catalog is per-server state. Two Caldera servers with different
 *      plugin sets carry different ability ids for the same technique, so a
 *      compiler that fetched one server's catalog would silently produce an
 *      adversary the OTHER server rejects.
 *   3. It keeps the honest boundary visible. Everything that needs a real
 *      Caldera lives on the other side of this function signature, in the
 *      engine adapter a later phase writes. This file cannot pretend.
 *
 * THE MAPPING IS MANY-TO-ONE AND LOSSY, AND THAT IS THE ENTIRE RISK
 * ----------------------------------------------------------------------------
 * A profile's techniques are arbitrary real MITRE ids invented by a model to
 * fit a narrative. A Caldera catalog covers a few hundred of the ~800
 * techniques, unevenly, skewed hard toward whatever stockpile implements. So a
 * six-step attack path routinely maps to four abilities.
 *
 * A SILENTLY DROPPED STEP IS THE WORST DEFECT THIS FILE CAN HAVE. The scenario
 * says the actor dumped LSASS; the answer key says the actor dumped LSASS; the
 * operation never ran an LSASS ability; the student correctly finds nothing and
 * is graded as having missed it. Nothing errors, nothing logs, and the only
 * symptom is a class that all "failed" the same question.
 *
 * So every step that does not reach `atomic_ordering` is reported TWICE — once
 * in `warnings` as human prose and once in `unmapped` as a structured record —
 * and the answer key is compiled from the abilities that WILL run, never from
 * the scenario that was asked for.
 *
 * detection_opportunity NEVER LEAVES THIS FUNCTION
 * ----------------------------------------------------------------------------
 * `detection_opportunity` is literally the answer to the exercise: it is the
 * profile author telling a defender exactly which artifact to look for. It has
 * no business in an adversary definition — Caldera has no field for it and no
 * use for it — and a Caldera UI is one misconfigured Guacamole connection away
 * from a student. `step.action` is the same class of prose and gets the same
 * treatment.
 *
 * Both are stripped BY CONSTRUCTION (the adversary is built from a whitelist,
 * never by deleting fields off the input) and then re-checked by
 * assertNoAnswerText(), which throws rather than leaks. Belt and braces,
 * because the failure is unobservable and permanent.
 *
 * THE ANSWER KEY IS THE SAME SHAPE THE SYNTHETIC ENGINE PRODUCES
 * ----------------------------------------------------------------------------
 * `{version, engine, run_id, techniques, iocs, timeline, floor_techniques,
 *   floor_values, floor_truncated, totals}` — exactly src/incident/answer-key.js.
 * src/incident/board.js hands the key straight to src/incident/scoring.js, so
 * matching that shape is what makes a Caldera run scorable with ZERO changes to
 * either file.
 *
 * Two fields are deliberately empty, and both are honesty rather than laziness:
 *
 *   iocs: []            An IOC in this system is DEFINED as a value the ATTACK
 *                       plan uses that the FLOOR plan cannot produce. A Caldera
 *                       run has no compiled plan and no compiled floor — real
 *                       abilities run on real hosts and what lands in Sysmon is
 *                       whatever actually happened. Any value listed here would
 *                       be a guess, and a guessed IOC penalises every student
 *                       who correctly ignores it. answer-key.js:429 already
 *                       takes this position for every non-synthetic engine.
 *   totals.events: null Not 0. Zero asserts "this run produced no events",
 *                       which is false; null says "not predictable from here",
 *                       which is true.
 *
 * `techniques` is NOT empty, and that is the one place this key goes further
 * than answerKeyForRun()'s blanket empty one: Caldera runs exactly the
 * abilities in `atomic_ordering` and nothing else, so WHICH techniques fire is
 * knowable ahead of execution even though the telemetry is not. scoring.js
 * grades a key with techniques and no IOCs perfectly well — `graded` is an OR
 * at scoring.js:230.
 *
 * WHAT IS NOT HERE, DELIBERATELY
 * ----------------------------------------------------------------------------
 * No engine registration, no route, no HTTP client, no operation lifecycle.
 * src/incident/engines/index.js still refuses 'caldera' and must keep refusing
 * it until an adapter exists and the E8 cluster gate has passed. This file is a
 * pure function sitting on disk waiting for that adapter; requiring it changes
 * no behaviour anywhere.
 * ============================================================================
 */

'use strict';

const crypto = require('crypto');

/**
 * Must equal src/incident/answer-key.js's ANSWER_KEY_VERSION.
 *
 * Deliberately a literal rather than a require, so this module stays free of
 * even a transitive `fs` dependency (answer-key.js requires cc-emit.js, which
 * requires fs for its CLI half). test/caldera-adversary.test.js asserts the two
 * numbers are equal, so the copy cannot drift unseen — the drift surfaces as a
 * red test, which is the only place it is cheap to find. scoring.js throws
 * AnswerKeyVersionError only when a key's version is HIGHER than its own, so a
 * stale copy here would not refuse, it would mis-grade.
 */
const ANSWER_KEY_VERSION = 1;

/**
 * The UUIDv5 namespace every compiled adversary id is derived under.
 *
 * NEVER CHANGE THIS VALUE. It is not a secret and it is not a version — it is
 * the identity of every adversary this compiler has ever produced. Changing it
 * makes the same scenario compile to a different adversary id, which means a
 * relaunch creates a SECOND adversary on the Caldera server instead of updating
 * the first, and the server accumulates near-duplicates an instructor cannot
 * tell apart.
 */
const ADVERSARY_NAMESPACE = 'a7d4c9f2-3e61-4b08-9f5a-2c8e11d6b430';

/** MITRE ATT&CK technique id — the same regex ciab/ai/profile/validators.js:118 uses. */
const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

/**
 * Caldera's platform vocabulary.
 *
 * An ability claiming a platform outside this set is not rejected — upstream
 * plugins invent their own — but it can never satisfy a platform filter, which
 * is worth a warning rather than a silent non-match.
 */
const KNOWN_PLATFORMS = new Set(['windows', 'linux', 'darwin']);

/**
 * Below this length a prose field is too short to check for as a substring: a
 * six-character detection_opportunity like "Sysmon" would collide with an
 * ability name and make assertNoAnswerText() throw on a CORRECT compile.
 *
 * The leak guard is a backstop, not the primary defence — the adversary is
 * built from a whitelist, so nothing short slips through by another route.
 */
const MIN_LEAK_CHECK_LENGTH = 12;

/** Why a step never reached `atomic_ordering`. Stable strings; the tests pin them. */
const UNMAPPED_REASONS = {
  MISSING_TECHNIQUE: 'missing_technique',
  INVALID_TECHNIQUE: 'invalid_technique',
  NO_ABILITY: 'no_ability',
  SUBTECHNIQUE_ONLY_PARENT: 'no_ability_parent_exists',
  PLATFORM: 'no_ability_for_platform',
};

/**
 * Thrown when the leak guard finds authoring prose inside the compiled adversary.
 *
 * A throw, not a warning. The caller cannot usefully continue: the object it
 * would receive is the answer to the exercise wearing an adversary's shape, and
 * every path downstream of here writes it somewhere a browser can reach.
 */
class AnswerLeakError extends Error {
  constructor(field, step) {
    super(`compileAdversary: step ${step} '${field}' text reached the adversary definition — `
      + 'that field is the answer to the exercise and must never leave the answer key');
    this.name = 'AnswerLeakError';
    this.code = 'CALDERA_ADVERSARY_ANSWER_LEAK';
    this.field = field;
    this.step = step;
  }
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

const str = (v) => (v == null ? '' : String(v)).trim();

/** Uppercased technique id. scoring.js:121 normalises identically — exact match, no sub-technique collapsing. */
const normTechnique = (v) => str(v).toUpperCase();

/** `T1566.001` -> `T1566`; `T1566` -> null. */
function parentTechnique(id) {
  const m = /^(T\d{4})\.\d{3}$/.exec(normTechnique(id));
  return m ? m[1] : null;
}

/**
 * One catalog row, in whatever shape the caller had.
 *
 * A catalog fetched from `GET /api/v2/abilities` uses `ability_id`,
 * `technique_id` and `executors[].platform`; one hand-written for a test or
 * read out of a stockpile YAML uses `id`, `technique` and `platforms`. Both are
 * accepted, because rejecting either would mean the tests exercise a different
 * code path than production does — which is how a mapping bug survives a green
 * suite.
 *
 * @returns {{id: string, technique: string, platforms: string[], name: string,
 *            tactic: string|null}|null} null for a row with no id or no technique
 */
function normalizeAbility(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = str(raw.ability_id || raw.id);
  const technique = normTechnique(raw.technique_id || raw.technique);
  if (!id || !technique) return null;

  const platforms = new Set();
  const addPlatform = (p) => { const s = str(p).toLowerCase(); if (s) platforms.add(s); };
  if (Array.isArray(raw.platforms)) raw.platforms.forEach(addPlatform);
  else if (raw.platforms) addPlatform(raw.platforms);
  if (Array.isArray(raw.platform)) raw.platform.forEach(addPlatform);
  else if (raw.platform) addPlatform(raw.platform);
  if (Array.isArray(raw.executors)) {
    for (const ex of raw.executors) {
      if (ex && typeof ex === 'object') addPlatform(ex.platform);
    }
  }

  return {
    id,
    technique,
    // Sorted, so two catalogs listing the same platforms in a different order
    // still compile to the same adversary.
    platforms: [...platforms].sort(),
    name: str(raw.name || raw.ability_name) || id,
    tactic: str(raw.tactic) || null,
  };
}

/** `options.platform` as a lowercase set. Empty means "do not filter". */
function normalizePlatformFilter(v) {
  const out = new Set();
  const add = (p) => { const s = str(p).toLowerCase(); if (s) out.add(s); };
  if (Array.isArray(v)) v.forEach(add);
  else if (v) add(v);
  return out;
}

/**
 * technique id -> ability rows, each list sorted by ability id.
 *
 * Sorting HERE rather than at selection time is what makes the whole compile
 * deterministic. A catalog is an array off an HTTP response and its order is
 * whatever the server felt like; two identical catalogs in different orders must
 * produce byte-identical adversaries, or the same scenario becomes two different
 * operations on two different days.
 */
function indexAbilities(abilities, warnings) {
  const byTechnique = new Map();
  const list = Array.isArray(abilities) ? abilities : [];
  let skipped = 0;

  for (const raw of list) {
    const ab = normalizeAbility(raw);
    if (!ab) { skipped += 1; continue; }
    for (const p of ab.platforms) {
      if (!KNOWN_PLATFORMS.has(p)) {
        warnings.push(`CALDERA_ABILITY_UNKNOWN_PLATFORM: ability ${ab.id} declares platform `
          + `'${p}', outside Caldera's ${[...KNOWN_PLATFORMS].join('/')} vocabulary — it can `
          + 'never satisfy a platform filter');
      }
    }
    if (!byTechnique.has(ab.technique)) byTechnique.set(ab.technique, []);
    byTechnique.get(ab.technique).push(ab);
  }

  for (const rows of byTechnique.values()) rows.sort((a, b) => a.id.localeCompare(b.id));

  if (skipped) {
    warnings.push(`CALDERA_CATALOG_ROWS_SKIPPED: ${skipped} catalog row(s) carried no ability id `
      + 'or no technique id and were ignored — a catalog fetched from a server missing the '
      + 'stockpile plugin looks exactly like this');
  }
  if (!byTechnique.size) {
    warnings.push('CALDERA_CATALOG_EMPTY: the injected ability catalog has no usable rows, so '
      + 'every step of this scenario is unmapped and the compiled adversary does nothing');
  }
  return byTechnique;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * RFC 4122 UUIDv5 (SHA-1, name-based).
 *
 * Name-based rather than random because the adversary id must be a pure
 * function of the compile: relaunching the same scenario against the same
 * catalog has to address the SAME adversary, not create a second one. A v4 here
 * would leave an instructor choosing between fourteen identically named
 * adversaries with no way to tell which is current.
 */
function uuidv5(name, namespace) {
  const ns = Buffer.from(namespace.replace(/-/g, ''), 'hex');
  const h = crypto.createHash('sha1')
    .update(Buffer.concat([ns, Buffer.from(name, 'utf8')]))
    .digest();
  h[6] = (h[6] & 0x0f) | 0x50;   // version 5
  h[8] = (h[8] & 0x3f) | 0x80;   // RFC 4122 variant
  const hex = h.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// ---------------------------------------------------------------------------
// The leak guard
// ---------------------------------------------------------------------------

/**
 * Refuse to return an adversary carrying authoring prose.
 *
 * The adversary is assembled from a whitelist forty lines below, so in a correct
 * build this never fires. It exists for the INCORRECT build: someone adds
 * `notes: step.action` while debugging, or spreads `...step` into a tag map, and
 * the field that IS the answer ships to a server whose UI is not ours. That
 * change would look entirely reasonable in review.
 *
 * Short strings are skipped — see MIN_LEAK_CHECK_LENGTH.
 */
function assertNoAnswerText(adversary, steps) {
  const blob = JSON.stringify(adversary);
  for (const s of steps) {
    for (const field of ['detection_opportunity', 'action']) {
      const text = str(s[field]);
      if (text.length < MIN_LEAK_CHECK_LENGTH) continue;
      if (blob.includes(text)) throw new AnswerLeakError(field, s.step);
    }
  }
}

// ---------------------------------------------------------------------------
// The compiler
// ---------------------------------------------------------------------------

/**
 * Compile one threat scenario into a Caldera adversary plus its answer key.
 *
 * @param {object} opts
 * @param {object} opts.scenario    a `threat_profile.scenarios[]` entry. Needs
 *                                  `attack_path[]`; everything else is optional.
 * @param {object[]} opts.abilities the INJECTED ability catalog — rows from
 *                                  `GET /api/v2/abilities` or a stockpile YAML.
 *                                  See normalizeAbility() for accepted shapes.
 * @param {object} [opts.options]
 * @param {string|string[]} [opts.options.platform] keep only abilities that run
 *                                  on this platform. Omit to accept any.
 * @param {string} [opts.options.runId] stamped into the answer key exactly as
 *                                  answer-key.js does. NOT a seed here —
 *                                  nothing in a Caldera compile is random.
 * @param {number} [opts.options.maxAbilitiesPerStep=1] how many of a technique's
 *                                  abilities one step contributes.
 * @param {boolean} [opts.options.allowParentTechnique=false] opt in to running a
 *                                  parent-technique ability for a sub-technique
 *                                  step. OFF by default because it CHANGES WHAT
 *                                  THE STUDENT MUST REPORT — see the warning.
 * @param {string} [opts.options.name] adversary name override.
 * @returns {{adversary: object, answerKey: object, warnings: string[], unmapped: object[]}}
 * @throws {TypeError} on a structurally invalid scenario
 * @throws {AnswerLeakError} if authoring prose reached the adversary
 */
function compileAdversary(opts) {
  const o = opts || {};
  const scenario = o.scenario;
  const options = o.options || {};

  if (!scenario || typeof scenario !== 'object') {
    throw new TypeError('compileAdversary: scenario must be an object');
  }
  if (!Array.isArray(scenario.attack_path)) {
    // Not a warning. A scenario with no attack path is not a lossy compile, it
    // is a caller bug: there is nothing to turn into an operation, and handing
    // back an empty adversary would let it be launched.
    throw new TypeError('compileAdversary: scenario.attack_path must be an array');
  }

  /** @type {string[]} */
  const warnings = [];
  /** @type {object[]} */
  const unmapped = [];

  const byTechnique = indexAbilities(o.abilities, warnings);
  const platformFilter = normalizePlatformFilter(options.platform);
  const maxPerStep = Number.isFinite(Number(options.maxAbilitiesPerStep))
    && Number(options.maxAbilitiesPerStep) > 0
    ? Math.floor(Number(options.maxAbilitiesPerStep))
    : 1;
  const allowParent = options.allowParentTechnique === true;

  const steps = orderSteps(scenario.attack_path, warnings);

  const atomicOrdering = [];
  const timeline = [];
  const techniqueRows = new Map();

  for (const s of steps) {
    const technique = normTechnique(s.technique);
    const target = str(s.target) || null;

    if (!technique) {
      recordUnmapped(warnings, unmapped, s, null, target, UNMAPPED_REASONS.MISSING_TECHNIQUE,
        'the scenario step carries no technique id, so there is nothing to look up');
      continue;
    }
    if (!TECHNIQUE_RE.test(technique)) {
      recordUnmapped(warnings, unmapped, s, technique, target, UNMAPPED_REASONS.INVALID_TECHNIQUE,
        `'${technique}' is not a MITRE ATT&CK id of the form T#### or T####.###`);
      continue;
    }

    // ── Look it up, honestly ─────────────────────────────────────────────
    let candidates = byTechnique.get(technique) || [];
    let matchedBy = 'exact';

    if (!candidates.length) {
      const parent = parentTechnique(technique);
      const parentRows = parent ? (byTechnique.get(parent) || []) : [];

      if (parentRows.length && !allowParent) {
        // The safe default, and the reason it is the default is GRADING.
        recordUnmapped(warnings, unmapped, s, technique, target,
          UNMAPPED_REASONS.SUBTECHNIQUE_ONLY_PARENT,
          `no ability is tagged ${technique}; the catalog does carry ${parent}. Mapping to the `
          + `parent would put ${parent} in the answer key while the scenario — and therefore the `
          + `student — says ${technique}, and scoring.js matches technique ids EXACTLY (no `
          + 'sub-technique collapsing), so every correct answer would score as a false positive. '
          + 'Pass options.allowParentTechnique to take that trade deliberately');
        continue;
      }
      if (parentRows.length && allowParent) {
        candidates = parentRows;
        matchedBy = 'parent';
        warnings.push(`CALDERA_TECHNIQUE_MAPPED_BY_PARENT: step ${s.step} asked for ${technique} `
          + `and will run a ${parent} ability. The answer key carries ${parent}, NOT ${technique} `
          + "— brief the instructor, because a student reporting the scenario's sub-technique "
          + 'scores a false positive');
      }
    }

    if (!candidates.length) {
      recordUnmapped(warnings, unmapped, s, technique, target, UNMAPPED_REASONS.NO_ABILITY,
        `no ability in the injected catalog is tagged ${technique}`);
      continue;
    }

    // ── Platform ─────────────────────────────────────────────────────────
    if (platformFilter.size) {
      const before = candidates.length;
      candidates = candidates.filter((a) => a.platforms.some((p) => platformFilter.has(p)));
      if (!candidates.length) {
        recordUnmapped(warnings, unmapped, s, technique, target, UNMAPPED_REASONS.PLATFORM,
          `${before} ability/abilities are tagged ${technique} but none run on `
          + `${[...platformFilter].sort().join('/')}`);
        continue;
      }
    }

    // ── Many-to-one: choose deterministically, and say what was left out ──
    const chosen = candidates.slice(0, maxPerStep);
    if (candidates.length > chosen.length) {
      warnings.push(`CALDERA_ABILITY_ALTERNATIVES_DROPPED: step ${s.step} (${technique}) matched `
        + `${candidates.length} abilities; ${chosen.length} kept in ability-id order `
        + `(${chosen.map((a) => a.id).join(', ')}), dropped `
        + `${candidates.slice(chosen.length).map((a) => a.id).join(', ')}. The dropped ones are `
        + 'real activity this operation will NOT perform');
    }

    for (const ab of chosen) {
      atomicOrdering.push(ab.id);
      // What will ACTUALLY run, never what was asked for. This is the whole
      // point of compiling the key from the abilities: the key has to describe
      // the operation, not the narrative.
      const keyTechnique = ab.technique;
      let row = techniqueRows.get(keyTechnique);
      if (!row) {
        row = { id: keyTechnique, tactic: ab.tactic, first_offset_s: null, event_count: null };
        techniqueRows.set(keyTechnique, row);
      }
      if (!row.tactic && ab.tactic) row.tactic = ab.tactic;
    }

    timeline.push({
      step: s.step,
      technique: chosen[0].technique,
      // NULL, not 0 and not an estimate. cc-emit lays synthetic events out on a
      // planned timeline, which is why answer-key.js can state an offset.
      // Caldera links execute when an agent next beacons and take as long as the
      // command takes; a number here is one the board would render as fact.
      offset_s: null,
      // The ABILITY's own name. Never step.action and never
      // step.detection_opportunity — answer-key.js:365 makes the same point
      // about its own labels, for the same reason.
      label: chosen.map((a) => a.name).join(' + '),
      ability_ids: chosen.map((a) => a.id),
      matched_by: matchedBy,
      // Staff-only, and safe here for one specific reason: the answer key never
      // reaches a student (src/incident/projection.js), while the ADVERSARY may
      // reach a server whose UI is not ours. Targets stay on this side of that
      // line.
      target,
    });
  }

  const techniques = [...techniqueRows.values()].map((t) => ({ ...t }));

  if (!atomicOrdering.length) {
    warnings.push('CALDERA_ADVERSARY_EMPTY: not one step of this scenario mapped to an ability. '
      + 'The compiled adversary would run nothing — the caller must refuse to launch it rather '
      + 'than create an operation that completes instantly having done nothing');
  }

  const adversary = buildAdversary({ scenario, atomicOrdering, options });
  assertNoAnswerText(adversary, steps);

  const answerKey = buildAnswerKey({
    runId: str(options.runId) || null,
    scenario,
    adversary,
    techniques,
    timeline,
    unmapped,
  });

  return { adversary, answerKey, warnings, unmapped };
}

/**
 * The attack path in execution order.
 *
 * `step` is authored as an integer and is the author's declared order, so it
 * wins when EVERY entry has one. The moment any entry is missing it, array order
 * is used for ALL of them — mixing the two interleaves two different orderings
 * and produces a kill chain that runs impact before initial access.
 */
function orderSteps(attackPath, warnings) {
  const rows = attackPath
    .filter((s) => s && typeof s === 'object')
    .map((s, i) => ({ ...s, step: Number.isFinite(Number(s.step)) ? Number(s.step) : null, _i: i }));

  if (rows.length !== attackPath.length) {
    warnings.push(`CALDERA_STEP_NOT_AN_OBJECT: ${attackPath.length - rows.length} attack_path `
      + 'entr(ies) were not objects and were ignored');
  }

  const allNumbered = rows.length > 0 && rows.every((s) => s.step !== null);
  if (!allNumbered) {
    if (rows.some((s) => s.step !== null)) {
      warnings.push('CALDERA_STEP_ORDER_MIXED: some attack_path entries carry a step number and '
        + 'some do not, so array order is used for all of them');
    }
    return rows.map((s, i) => ({ ...s, step: s.step === null ? i + 1 : s.step }));
  }

  const seen = new Set();
  for (const s of rows) {
    if (seen.has(s.step)) {
      warnings.push(`CALDERA_STEP_ORDER_DUPLICATE: step number ${s.step} appears more than once; `
        + 'array order breaks the tie');
    }
    seen.add(s.step);
  }
  // Stable: `_i` breaks ties, so a duplicated step number cannot reorder under a
  // different engine's sort.
  return rows.slice().sort((a, b) => (a.step - b.step) || (a._i - b._i));
}

/**
 * The Caldera adversary profile.
 *
 * BUILT FROM A WHITELIST. Nothing is spread in from the scenario and nothing is
 * deleted afterwards, because "delete the answer fields" is a defence that fails
 * open the instant the profile schema grows a field.
 *
 * Field names follow upstream's documented v2 body for
 * `POST /api/v2/adversaries`. UNVERIFIED — see the file header. The YAML profile
 * form of the same object calls `adversary_id` simply `id`; which one the real
 * server wants is the engine adapter's problem, not this function's.
 */
function buildAdversary({ scenario, atomicOrdering, options }) {
  const scenarioId = str(scenario.scenario_id) || 'unknown-scenario';

  // Identity over the SCENARIO and the ABILITIES — never over the prose. Two
  // scenarios compiling to the same ordered ability list ARE the same operation
  // and should share one adversary row on the server.
  const adversaryId = uuidv5(`${scenarioId}\u0000${atomicOrdering.join(',')}`, ADVERSARY_NAMESPACE);

  // The scenario NAME is kept, and that is a considered call rather than an
  // oversight. The Caldera server is staff-only infrastructure by construction —
  // bake-caldera-server.sh's hand-off block forbids publishing a student console
  // for it — and an instructor who cannot tell four adversaries apart in the UI
  // will launch the wrong one. `action` and `detection_opportunity` are a
  // different class: they name the artifacts to hunt for, and they stay out.
  const name = str(options.name)
    || (str(scenario.name) ? `${str(scenario.name)} [${scenarioId}]` : `CyberCore ${scenarioId}`);

  return {
    adversary_id: adversaryId,
    name,
    description: `Compiled by CyberCore from threat scenario ${scenarioId}`
      + `${str(scenario.type) ? ` (${str(scenario.type)})` : ''}. `
      + `${atomicOrdering.length} ability/abilities. `
      + 'Narrative and detection guidance are held in the answer key, not here.',
    atomic_ordering: atomicOrdering.slice(),
    objective: null,
    tags: ['cybercore'],
  };
}

/**
 * The staff-only grading key, in src/incident/answer-key.js's exact shape.
 *
 * Every field that file emits is present here, INCLUDING the ones that are
 * structurally empty for this engine: src/incident/scoring.js reads
 * `floor_techniques` and `floor_values` unconditionally, and an absent array
 * would differ from an empty one only on the day someone drops the `|| []`.
 */
function buildAnswerKey({ runId, scenario, adversary, techniques, timeline, unmapped }) {
  const unmappedTechniques = [...new Set(unmapped.map((u) => u.technique).filter(Boolean))].sort();

  return {
    version: ANSWER_KEY_VERSION,
    engine: 'caldera',
    run_id: runId,
    // Caldera runs until its links are done. There is no requested duration to
    // reproduce, unlike cc-emit's planner.
    requested_seconds: null,
    // First-appearance order, which is the order Caldera will run them in and
    // therefore the order scoring.js's Kendall tau is measured against.
    techniques,
    // Empty BY DEFINITION, not by omission. See the file header.
    iocs: [],
    timeline,
    // A Caldera run has no synthetic benign floor to difference against, so
    // there is no defensible-miss set: scoring.js grades an unlisted value as a
    // false positive rather than a partial. That is said out loud in `reason`
    // below, because an instructor staring at a board full of false positives
    // needs to FIND this sentence rather than deduce it.
    floor_techniques: [],
    floor_values: [],
    floor_truncated: false,
    totals: {
      // null, not 0. See the file header.
      events: null,
      techniques: techniques.length,
      iocs: 0,
    },
    // ── Beyond answer-key.js's shape, and additive on purpose ─────────────
    // A superset is safe: scoring.js and board.js read by name. These exist so
    // an instructor console can show "4 of 6 scenario steps are executable"
    // instead of presenting a silently shortened attack as the whole scenario.
    scenario_id: str(scenario.scenario_id) || null,
    adversary_id: adversary.adversary_id,
    unmapped_techniques: unmappedTechniques,
    unmapped_step_count: unmapped.length,
    reason: 'Caldera executes real abilities on real hosts, so the telemetry a run produces is not '
      + 'predictable from here: iocs and totals.events are empty by definition, and there is no '
      + 'benign floor, so an unlisted value scores as a false positive rather than a defensible '
      + 'miss. The technique list IS predictable — an operation runs exactly the abilities in '
      + 'atomic_ordering — and is compiled from the abilities that will run, never from the '
      + 'scenario that was requested.',
  };
}

/** Push one dropped step to BOTH channels. Never one without the other. */
function recordUnmapped(warnings, unmapped, step, technique, target, reason, detail) {
  unmapped.push({
    step: step.step,
    technique: technique || null,
    target: target || null,
    reason,
  });
  warnings.push(`CALDERA_TECHNIQUE_UNMAPPED: step ${step.step}`
    + `${technique ? ` (${technique})` : ''}`
    + `${target ? ` against ${target}` : ''} will NOT run — ${detail}. `
    + 'The answer key omits it; the scenario narrative still claims it happened, so the instructor '
    + 'must either accept the shortened path or supply an ability for it.');
}

module.exports = {
  compileAdversary,
  AnswerLeakError,
  ANSWER_KEY_VERSION,
  ADVERSARY_NAMESPACE,
  UNMAPPED_REASONS,
  // Exported for the tests, which pin the normalisation and ordering rules
  // directly rather than only through a whole compile.
  normalizeAbility,
  orderSteps,
  uuidv5,
};
