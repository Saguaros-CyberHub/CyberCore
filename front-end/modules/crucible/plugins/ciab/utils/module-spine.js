/**
 * ============================================================================
 * module-spine.js — Track D, phase D1: ordered modules, prereqs, release and
 * per-student state, resolved by one pure gate
 * ----------------------------------------------------------------------------
 * A SECTION is a class. A MODULE is one unit of work an instructor sequences
 * inside it, bound to a CLIENT and an ENGAGEMENT, which resolve to an
 * ENVIRONMENT. This file answers exactly one question, twice: what may THIS
 * person see and do on THIS module, right now.
 *
 * NOTHING ABOUT AVAILABILITY IS STORED, AND THAT IS THE WHOLE DESIGN.
 * The obvious alternative — an is_open boolean flipped by a scheduled job — has
 * a failure mode nobody can debug: one missed tick leaves a module shut on the
 * morning it was meant to open, and the resulting row is INDISTINGUISHABLE from
 * a module the instructor deliberately closed. There is no evidence to look at
 * afterwards, because the evidence would have been the tick that never ran. So
 * "is this open" is a pure function of (release_state, release_at, close_at,
 * now) plus that one student's two override facts, computed on every read. The
 * clock moving is a state transition with no write, no row and no job behind
 * it, which is why `now` is a REQUIRED argument everywhere and never defaults.
 *
 * TWO ENTRY POINTS, ONE CORE. resolveForStudent and resolveForInstructor share
 * every pure part — the ordering, the graph, the phase, the completion and the
 * gate — and differ only in their PROJECTION. They are two functions rather
 * than one object a route then strips, because one forgotten key in a strip is
 * a leak, while a whitelist projection plus dropping drafts outright makes the
 * same mistake a test failure. A student never receives instructor_notes,
 * release_state, another student's state, or the module_id of a draft: an id
 * alone is enough to guess a URL, so hidden modules do not get returned with a
 * flag, they get dropped.
 *
 * FIXED QUERY COUNTS. The student view is at most 5 queries and the instructor
 * view at most 6, invariant under module count and roster size. Every loader
 * fetches a COLLECTION; none is ever called inside a loop. The instructor
 * rollup runs the same gate `modules x roster` times entirely in memory, and
 * that cross-product is affordable for a reason worth stating: prerequisite
 * satisfaction is NOT transitive. A module's completion is either an
 * instructor's stored decision or a direct read of that student's own
 * assessment_progress row — never a computed consequence of another module — so
 * `satisfied(M)` is a flat Map lookup and each gate call costs O(edges of M).
 * The topological pass exists only to DETECT cycles, once, shared across every
 * student. 50 modules against 500 students is ~25k trivial evaluations.
 *
 * WHAT LIVES HERE AND WHAT DOES NOT. D1 ships the reads, the pure gate and the
 * two per-student-state writers, and nothing else. There is no route file, no
 * mount and no boot hook in this phase. Creating, cloning, reordering and
 * editing prerequisite edges are D2's writes; deploy-on-open and
 * teardown-on-close are D5's; grading stays in assessment_progress, where it
 * already is.
 * ============================================================================
 */

const { query } = require('./db');
const S = require('./module-states');
const { getPartName } = require('./part-definitions');

/**
 * The prefix every console.* in this file must carry, exactly as the neighbouring
 * utils declare theirs. D1 emits none: nothing here degrades quietly. A bad
 * argument throws with a status, a bad clock throws 500, and a database error
 * propagates to the caller that owns the response — so there is no failure this
 * file could log and then carry on from, and inventing one would only teach the
 * next author that swallowing is normal here.
 */
const LOG = '[CIAB Module]';

/**
 * The sanitized engagement slug for a module's binding.
 *
 * LAZY REQUIRE, AND IT IS LOAD-BEARING — DO NOT HOIST IT. ./lane-reservation
 * requires src/utils/proxmox.js, src/utils/lab-network-provision.js AND
 * src/utils/lane-deployer.js at MODULE scope, so a top-level require here would
 * drag the Proxmox client and the whole batch deployer into every consumer of
 * this file — including each `node --test` child process, where that weight
 * surfaces as a whole-FILE "Unable to deserialize cloned data" crash with no
 * assertion attached to explain it. Deferring it to the one function that needs
 * it costs a cached require lookup. Same shape as the lazy require src/server.js
 * uses for recoverStrandedEngagements.
 *
 * Sanitizing defensively rather than trusting the column: engagement_type is the
 * slug half of ciab_engagement's UNIQUE (profile_id, engagement_type), and a
 * hand-inserted row holding 'External ' must not alias onto the key 'external'
 * actually names.
 *
 * @param {*} raw the stored engagement_type
 * @returns {string} the sanitized slug
 */
function engagementSlug(raw) {
  const { sanitizeEngagementType } = require('./lane-reservation');
  return sanitizeEngagementType(raw);
}

// ─── The clock ──────────────────────────────────────────────────────────────

/**
 * Coerce an injected clock to epoch milliseconds.
 *
 * REQUIRED. There is deliberately no default, and the omission is an error
 * rather than "now", because a defaulting clock produces two bugs that both
 * read as something else. First: two modules in ONE response get judged at two
 * different instants, so a module can be open in the list and closed on the
 * page it links to, in the same request, and the report will say "it flickers".
 * Second: a test that forgets the argument starts depending on wall time and
 * fails at 17:00 on the day someone set a close_at, which reads as flakiness and
 * gets retried rather than fixed.
 *
 * Status 500, not 400: no client can send this wrong. A missing clock is a
 * caller in this codebase forgetting to pass one.
 *
 * @param {Date|number|string} now a Date, epoch ms, or an ISO string
 * @returns {number} epoch milliseconds
 */
function toMs(now) {
  let ms = NaN;
  if (now instanceof Date) ms = now.getTime();
  else if (typeof now === 'number') ms = now;
  else if (typeof now === 'string') ms = Date.parse(now);

  if (!Number.isFinite(ms)) {
    throw Object.assign(
      new Error('now is required: pass a Date, epoch ms or an ISO string'),
      { status: 500 }
    );
  }
  return ms;
}

// ─── Mappers ────────────────────────────────────────────────────────────────

/**
 * A ciab_module row, whitelisted into a fresh object.
 *
 * EXPLICIT KEYS, NEVER A SPREAD OF THE pg ROW. The student projection has its
 * own whitelist downstream, but this is the other door into the same building:
 * a column added by a later migration that arrived here by spread would reach
 * instructorModuleView untouched, and the projection test only guards the
 * student side. Two whitelists, both cheap, and neither can be bypassed by an
 * ALTER TABLE nobody remembered to think about.
 *
 * @param {object|null} row
 * @returns {object|null}
 */
function rowToModule(row) {
  if (!row) return null;
  return {
    module_id:             row.module_id,
    section_id:            row.section_id,
    position:              row.position,
    title:                 row.title,
    brief:                 row.brief,
    instructor_notes:      row.instructor_notes,
    profile_id:            row.profile_id,
    engagement_type:       row.engagement_type,
    assessment_part:       row.assessment_part,
    release_state:         row.release_state,
    release_at:            row.release_at,
    close_at:              row.close_at,
    cloned_from_module_id: row.cloned_from_module_id,
    created_by:            row.created_by,
    updated_by:            row.updated_by,
    created_at:            row.created_at,
    updated_at:            row.updated_at,
  };
}

/**
 * A ciab_module_student row, whitelisted — or the default state, COPIED.
 *
 * Rows are SPARSE and nothing pre-creates them, so the absent row is not a
 * missing case to be handled: it is the real, complete state of most students on
 * most modules. Copying S.DEFAULT_STUDENT_STATE rather than returning it keeps a
 * caller from being handed a frozen singleton it then wants to annotate — and
 * keeps every caller from silently sharing one object.
 *
 * @param {object|null} row
 * @returns {object}
 */
function rowToStudentState(row) {
  if (!row) return { ...S.DEFAULT_STUDENT_STATE };
  return {
    module_id:        row.module_id,
    user_id:          row.user_id,
    completion:       row.completion,
    completed_at:     row.completed_at,
    completed_by:     row.completed_by,
    release_override: row.release_override,
    override_reason:  row.override_reason,
    override_by:      row.override_by,
    override_at:      row.override_at,
  };
}

// ─── Ordering ───────────────────────────────────────────────────────────────

/** A module's sort position. A non-finite or absent position sorts as 0. */
function positionOf(module) {
  const p = Number(module == null ? NaN : module.position);
  return Number.isFinite(p) ? p : 0;
}

/** A module's creation instant in ms. An unparseable created_at sorts LAST. */
function createdMsOf(module) {
  const raw = module == null ? null : module.created_at;
  const ms = raw instanceof Date ? raw.getTime() : Date.parse(raw);
  return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY;
}

/**
 * The section's display order: position, then created_at, then module_id.
 *
 * THE THIRD KEY IS WHAT MAKES THE ORDER TOTAL, and a total order is what makes
 * the deliberate absence of UNIQUE (section_id, position) safe. Two modules
 * cloned in the same millisecond at the same position still have exactly one
 * defined order; without module_id they would tie, Array.prototype.sort is only
 * required to be stable with respect to its INPUT, and the input is a pg result
 * set whose order at a tie is not promised either. The visible symptom of that
 * would be "the next module" swapping places between two page loads, which is
 * indistinguishable from a bug in the gate and would be investigated as one.
 *
 * migration 014's ORDER BY names these same three columns, so the database path
 * and the pure path cannot disagree.
 *
 * @returns {-1|0|1}
 */
function compareModules(a, b) {
  const pa = positionOf(a);
  const pb = positionOf(b);
  if (pa !== pb) return pa < pb ? -1 : 1;

  const ca = createdMsOf(a);
  const cb = createdMsOf(b);
  if (ca !== cb) return ca < cb ? -1 : 1;

  const ia = a && a.module_id != null ? String(a.module_id) : '';
  const ib = b && b.module_id != null ? String(b.module_id) : '';
  if (ia !== ib) return ia < ib ? -1 : 1;
  return 0;
}

/**
 * Sorted copy. NEVER mutates — a caller holding the loaded rows must not find
 * them reordered underneath it by a function it called to read them.
 *
 * @param {object[]} modules
 * @returns {object[]} a new array
 */
function sortModules(modules) {
  return [...(Array.isArray(modules) ? modules : [])].sort(compareModules);
}

// ─── The prereq graph ───────────────────────────────────────────────────────

/**
 * Index the section's modules and prerequisite edges once, for every student.
 *
 * CYCLE DETECTION IS KAHN'S ALGORITHM, AND IT IS ITERATIVE ON PURPOSE. A
 * recursive depth-first walk over a malformed graph blows the stack, and a
 * RangeError thrown out of a page-data builder is a 500 on a page a student is
 * trying to read — a worse outcome than the misconfiguration that caused it.
 * Peel every node with no unmet prerequisite; whatever cannot be peeled is on a
 * cycle OR downstream of one, and ALL of it is marked cyclic. Marking the
 * downstream nodes too is not sloppiness: they can never unlock, so reporting
 * them as merely "waiting on module 2" would be a lie the instructor then has to
 * disprove.
 *
 * A DANGLING EDGE IS NEVER DROPPED. The composite foreign key in migration 014
 * makes an edge naming a module outside this section structurally impossible on
 * a healthy database, so this branch is insurance against a hand-edited row —
 * but dropping such an edge would silently OPEN the module it was gating, which
 * is the one direction this file must never fail in. The edge stays in
 * requiresById (so the gate sees an unresolvable prerequisite and locks) while
 * being excluded from the in-degree count (so the module is reported as
 * PREREQ_MISSING rather than mislabelled a cycle).
 *
 * duplicatePositions is computed here so sectionIssues needs no second pass over
 * the same array. O(V+E), run ONCE per section.
 *
 * D2 NEEDS NO SEPARATE CYCLE-PREVENTION HELPER: to test a candidate edge before
 * inserting it, call buildGraph(modules, [...edges, candidate]) and check
 * cyclicIds.size > 0. One line at the call site, and no export D1 cannot
 * exercise.
 *
 * @param {object[]} modules
 * @param {{module_id:string, prereq_module_id:string}[]} edges
 * @returns {{byId:Map, requiresById:Map, dependentsById:Map, cyclicIds:Set,
 *           dangling:object[], duplicatePositions:object[]}}
 */
function buildGraph(modules, edges) {
  const list = Array.isArray(modules) ? modules : [];

  const byId = new Map();
  const requiresById = new Map();
  const dependentsById = new Map();
  for (const module of list) {
    if (!module || module.module_id == null) continue;
    const id = String(module.module_id);
    byId.set(id, module);
    requiresById.set(id, []);
    dependentsById.set(id, []);
  }

  const dangling = [];
  const seen = new Set();
  for (const edge of Array.isArray(edges) ? edges : []) {
    if (!edge || edge.module_id == null || edge.prereq_module_id == null) continue;
    const gated = String(edge.module_id);
    const prereq = String(edge.prereq_module_id);
    // An edge for a module outside this set describes someone else's section.
    if (!byId.has(gated)) continue;
    // The table's primary key already forbids a duplicate pair; a caller
    // concatenating a candidate edge onto the loaded ones can still produce one.
    const key = `${gated}\u0000${prereq}`;
    if (seen.has(key)) continue;
    seen.add(key);

    requiresById.get(gated).push(prereq);
    if (byId.has(prereq)) dependentsById.get(prereq).push(gated);
    else dangling.push({ module_id: gated, prereq_module_id: prereq });
  }

  // In-degree counts RESOLVABLE prerequisites only. An unresolvable one can
  // never be peeled, and counting it would report every dangling edge as a
  // cycle — the wrong reason, above the right one in the gate's rule order.
  const indegree = new Map();
  const ready = [];
  for (const id of byId.keys()) {
    let unmet = 0;
    for (const prereq of requiresById.get(id)) if (byId.has(prereq)) unmet += 1;
    indegree.set(id, unmet);
    if (unmet === 0) ready.push(id);
  }

  // Iterative Kahn. A read cursor rather than shift(), so peeling is O(V+E)
  // rather than O(V^2) on a wide section.
  const peeled = new Set();
  for (let cursor = 0; cursor < ready.length; cursor += 1) {
    const id = ready[cursor];
    peeled.add(id);
    for (const dependent of dependentsById.get(id)) {
      const left = indegree.get(dependent) - 1;
      indegree.set(dependent, left);
      if (left === 0) ready.push(dependent);
    }
  }

  const cyclicIds = new Set();
  for (const id of byId.keys()) if (!peeled.has(id)) cyclicIds.add(id);

  // Grouped in module order, so the reported list is deterministic rather than
  // whatever order the rows happened to arrive in.
  const byPosition = new Map();
  for (const module of list) {
    if (!module || module.module_id == null) continue;
    const position = positionOf(module);
    if (!byPosition.has(position)) byPosition.set(position, []);
    byPosition.get(position).push(String(module.module_id));
  }
  const duplicatePositions = [];
  for (const [position, moduleIds] of byPosition) {
    if (moduleIds.length > 1) duplicatePositions.push({ position, module_ids: moduleIds });
  }
  duplicatePositions.sort(
    (a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : 0)
  );

  return { byId, requiresById, dependentsById, cyclicIds, dangling, duplicatePositions };
}

// ─── The pure gate ──────────────────────────────────────────────────────────

/** A reason, advisory or issue payload. `detail` is null unless it is used. */
function reasonOf(code, message, detail) {
  return {
    code,
    message: message || S.messageFor(code),
    detail: detail === undefined ? null : detail,
  };
}

/**
 * The module-wide effective phase, from stored intent plus the clock.
 *
 * FIRST MATCH WINS, AND EVERY AMBIGUITY RESOLVES TOWARD CLOSED. Two orderings
 * here carry the whole policy:
 *
 *   close_at is tested BEFORE any release_at test, so an INVERTED window — a
 *   typo, or an instructor correcting a window in two PATCHes — resolves closed
 *   rather than open. migration 014 deliberately has no CHECK forbidding the
 *   inversion, because a CHECK would surface the instructor's first PATCH as a
 *   raw 23514 and a 500; the resolver fails closed and sectionIssues tells them.
 *
 *   an unrecognised release_state resolves 'draft', not 'open', and is tested
 *   ABOVE the close_at window rather than below it. A value written before the
 *   CHECK existed, or by a future migration this build has not seen, must hide
 *   the module rather than publish it — and 'closed' is MORE permissive than
 *   'draft' on the student path, because resolveForStudent drops only draft and
 *   archived while studentModuleView ships the brief of a closed module. Below
 *   the window, an unknown word with a past close_at would therefore publish the
 *   brief it was supposed to hide.
 *
 * @param {object} module a ciab_module row or rowToModule() output
 * @param {number} nowMs epoch ms
 * @returns {string} one of S.RELEASE_PHASES
 */
function releasePhase(module, nowMs) {
  const at = toMs(nowMs);
  const m = module || {};
  const state = m.release_state;

  if (state === 'draft') return 'draft';
  if (state === 'archived') return 'archived';
  if (state === 'closed') return 'closed';

  // Above the window on purpose — see the second ordering rule in the header.
  if (!S.isReleaseState(state)) return 'draft';

  if (m.close_at != null && toMs(m.close_at) <= at) return 'closed';

  if (state === 'scheduled') {
    // Never opens. sectionIssues raises SCHEDULED_WITHOUT_DATE so the
    // instructor sees a configuration error rather than a module that is
    // silently treated as "now".
    if (m.release_at == null) return 'pending';
    return toMs(m.release_at) > at ? 'pending' : 'open';
  }

  if (state === 'open') {
    if (m.release_at != null && toMs(m.release_at) > at) return 'pending';
    return 'open';
  }

  // Unreachable: the four remaining words are each answered above, and anything
  // else was already refused by the isReleaseState test. Defensive only.
  return 'draft';
}

/**
 * The resolved completion for one (module, student), and where it came from.
 *
 * THE STORED DECISION ALWAYS OUTRANKS THE DERIVATION, IN BOTH DIRECTIONS —
 * including the explicit rejection 'incomplete'. That is precisely what makes
 * 'auto' safe as the column default: an instructor can always say no, so
 * deferring to another tracker is never a loss of authority. And because the
 * ordinary, part-bound case stores nothing at all, this table does not become a
 * fourth progress tracker restating what assessment_progress already owns.
 *
 * No lookup happens here. `derivedComplete` is supplied by the caller — from
 * loadPartCompletions today, and from D6's objective signal later, through this
 * same argument and with zero schema change.
 *
 * @param {object|null} state a ciab_module_student row, or null
 * @param {boolean|null} derivedComplete true, false, or null for "no signal"
 * @returns {{completion:string, source:string}}
 */
function resolveCompletion(state, derivedComplete) {
  const decision = (state && state.completion) || S.DEFAULT_STUDENT_STATE.completion;

  if (decision === 'complete') return { completion: 'complete', source: 'decision' };
  if (decision === 'waived') return { completion: 'waived', source: 'decision' };
  if (decision === 'incomplete') return { completion: 'incomplete', source: 'decision' };

  if (derivedComplete === true) return { completion: 'complete', source: 'derived' };
  if (derivedComplete === false) return { completion: 'incomplete', source: 'derived' };
  return { completion: 'incomplete', source: 'default' };
}

/**
 * What this ONE student may do with this ONE module. THE ORDER IS THE POLICY.
 *
 * Every argument is plain data and every prerequisite has already been resolved
 * for this student by the caller, so this function performs no lookup, touches
 * no database and reads no clock. It is deliberately the smallest thing in the
 * phase that can be wrong, and the instructor rollup runs this exact function
 * rather than a second opinion — a cohort grid that disagrees with the page the
 * student is looking at is worse than no grid.
 *
 * The rule order, and why each pair sits the way it does:
 *
 *   0    a phase no build of this file knows is refused before anything else is
 *        asked. Every other unknown here already fails closed — an unrecognised
 *        release_state resolves 'draft', an absent state is the default row, an
 *        absent sectionActive or enrolled is falsy — and this was the one that
 *        did not, because rule 12 is an unguarded fall-through to 'open'. The
 *        hazard is designed into the vocabulary: RELEASE_PHASES and
 *        RELEASE_STATES share four of their five words, so a caller passing
 *        module.release_state where releasePhase(module, now) belongs hands this
 *        function 'scheduled' — which, without this rule, published every
 *        scheduled module's brief with no reason attached to explain it.
 *   1-2  section, then enrollment. Archiving a section must REVOKE, or 'archive'
 *        is a decorative label; only an 'active' enrollment grants anything, so
 *        an end-of-term roster does not silently keep access.
 *   3-4  draft and archived sit ABOVE the overrides, because you cannot grant
 *        access to a module that has not been written, and because the
 *        enrollment gate would refuse the request the UI would then be offering.
 *   5    an instructor's lock is checked before every open path, so it always
 *        wins, and override_reason is shown to the student verbatim.
 *   6    an instructor's unlock beats the release window AND the prerequisites.
 *        The make-up, the extension, the accommodation. A resolver that refuses
 *        this is a bug report on the Monday of week 3.
 *   7-8  a broken graph outranks the release tests: it is a misconfiguration the
 *        instructor must see, not an invitation.
 *   9-10 the release window outranks an unmet prerequisite, because it is the
 *        more actionable answer. Telling a student to finish module 2 when the
 *        module closed on Friday sends them somewhere that cannot help.
 *   11   and only then, the prerequisites, naming what is blocking.
 *
 * `reasons` is NEVER empty when access is not 'open': a lock with no reason is
 * unactionable in a UI and a support ticket in the making.
 *
 * @param {{module:object, phase:string, state:object|null, prereqs:object[],
 *          cyclic:boolean, sectionActive:boolean, enrolled:boolean}} input
 * @returns {{access:string, reasons:object[], advisories:object[]}}
 */
function evaluateGate(input) {
  const { module, phase, state, prereqs, cyclic, sectionActive, enrolled } = input || {};
  const m = module || {};
  const st = state || S.DEFAULT_STUDENT_STATE;
  const requirements = Array.isArray(prereqs) ? prereqs : [];
  const refuse = (access, reason) => ({ access, reasons: [reason], advisories: [] });

  if (!sectionActive) return refuse('locked', reasonOf(S.REASON.SECTION_ARCHIVED));
  if (!enrolled) return refuse('locked', reasonOf(S.REASON.NOT_ENROLLED));

  // 'scheduled' is the realistic mistake, and it must hide rather than publish.
  if (!S.isReleasePhase(phase)) return refuse('hidden', reasonOf(S.REASON.MODULE_DRAFT));

  if (phase === 'draft') return refuse('hidden', reasonOf(S.REASON.MODULE_DRAFT));
  if (phase === 'archived') return refuse('hidden', reasonOf(S.REASON.MODULE_ARCHIVED));

  if (st.release_override === 'lock') {
    return refuse('locked', reasonOf(S.REASON.INSTRUCTOR_LOCKED, st.override_reason || null));
  }
  if (st.release_override === 'unlock') {
    return {
      access: 'open',
      reasons: [],
      advisories: [reasonOf(S.ADVISORY.INSTRUCTOR_UNLOCKED)],
    };
  }

  if (cyclic) return refuse('locked', reasonOf(S.REASON.PREREQ_CYCLE));
  if (requirements.some((p) => p && p.missing)) {
    return refuse('locked', reasonOf(S.REASON.PREREQ_MISSING));
  }

  if (phase === 'closed') {
    return refuse('closed', reasonOf(S.REASON.MODULE_CLOSED, null, {
      close_at: m.close_at == null ? null : m.close_at,
    }));
  }
  if (phase === 'pending') {
    return refuse('locked', reasonOf(S.REASON.NOT_YET_RELEASED, null, {
      release_at: m.release_at == null ? null : m.release_at,
    }));
  }

  const blocking = requirements
    .filter((p) => p && !p.satisfied)
    .map((p) => ({ module_id: p.module_id, title: p.title, position: p.position }));
  if (blocking.length > 0) {
    return refuse('locked', reasonOf(S.REASON.PREREQ_INCOMPLETE, null, { blocking }));
  }

  return { access: 'open', reasons: [], advisories: [] };
}

// ─── Binding, environment and evidence ──────────────────────────────────────

/**
 * The environment this module resolves to, or null when no client is bound.
 *
 * (profile_id, engagement_type) and nothing else — the same pair that is
 * ciab_engagement's unique key and that ciab_profile_lane_groups already
 * carries. There is deliberately no engagement_id anywhere in D1: the
 * engagement row for a client reserved before Track A8 does not EXIST until
 * something reads it, so a module authored before the reservation could not name
 * an id at all.
 *
 * @param {object} module
 * @returns {string|null}
 */
function environmentKeyOf(module) {
  if (!module || module.profile_id == null) return null;
  return `${module.profile_id}:${engagementSlug(module.engagement_type)}`;
}

/**
 * Group modules by the environment they resolve to. Unbound modules are omitted.
 *
 * TWO MODULES UNDER ONE KEY SHARE AN ENVIRONMENT, and that is normal and
 * correct: "scope the client", then "report on the client", two units of work
 * against one client on one engagement, is the pedagogical shape the whole
 * program is built on. Migration 014 has no unique constraint forbidding it for
 * exactly that reason.
 *
 * D1's job is to make the sharing VISIBLE — as the instructor view's
 * shares_environment_with and the SHARED_ENVIRONMENT issue — so that when D5
 * hangs teardown off closing a module, it refcounts first instead of destroying
 * a sibling module's running machines.
 *
 * @param {object[]} modules
 * @returns {Map<string, object[]>}
 */
function groupByEnvironment(modules) {
  const groups = new Map();
  for (const module of Array.isArray(modules) ? modules : []) {
    const key = environmentKeyOf(module);
    if (key === null) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(module);
  }
  return groups;
}

/**
 * The tuple that names this module's deliverable in assessment_progress.
 *
 * Null unless BOTH halves are bound — a client with no part, or a part with no
 * client, addresses nothing. part_name is DERIVED from part-definitions and is
 * never read from a stored label: assessment_progress.part_name has already
 * drifted from the definitions once, which is why routes/progress.js re-derives
 * it on every read.
 *
 * This is the tuple D6 and D8 hand to assessment_progress. The module never
 * copies the deliverable, the status or the score back.
 *
 * @param {object} module
 * @returns {{profile_id:string, part_number:number, part_name:string}|null}
 */
function evidenceKeyFor(module) {
  if (!module || module.profile_id == null || module.assessment_part == null) return null;
  const partNumber = Number(module.assessment_part);
  if (!Number.isFinite(partNumber)) return null;
  return {
    profile_id: module.profile_id,
    part_number: partNumber,
    part_name: getPartName(partNumber),
  };
}

// ─── Projections ────────────────────────────────────────────────────────────

/**
 * Every key a student is ever handed for a module, sorted.
 *
 * A test deep-equals Object.keys(studentModuleView(...)).sort() against this, so
 * a column added to ciab_module by a later migration becomes a TEST FAILURE rather
 * than a silent leak. Absent by construction, and each for its own reason:
 * instructor_notes (staff prose about the student), release_state (instructor
 * release vocabulary, which a student must never be shown), section_id,
 * cloned_from_module_id, created_by, updated_by, created_at, updated_at, and
 * every other student's state.
 */
const STUDENT_VIEW_KEYS = Object.freeze([
  'access',
  'advisories',
  'assessment_part',
  'brief',
  'close_at',
  'completion',
  'completion_source',
  'engagement_type',
  'module_id',
  'position',
  'profile_id',
  'reasons',
  'release_at',
  'title',
]);

/**
 * One module as a student may see it.
 *
 * CONTENT GATING HAPPENS HERE, ON THE SERVER. `brief` is null unless the module
 * is open or closed for this student, so a locked or upcoming module ships its
 * title, its position and its release_at and nothing else — a student cannot
 * read next week's engagement brief out of the network tab. Scope filtering is
 * never element hiding in a browser; a page that renders the data and then hides
 * it has already shipped the data.
 *
 * @param {{module:object, gate:object, completion:string, completionSource:string}} input
 * @returns {object} exactly STUDENT_VIEW_KEYS
 */
function studentModuleView(input) {
  const { module, gate, completion, completionSource } = input || {};
  const m = module || {};
  const g = gate || { access: 'locked', reasons: [], advisories: [] };
  const readable = g.access === 'open' || g.access === 'closed';

  return {
    access:            g.access,
    advisories:        Array.isArray(g.advisories) ? g.advisories : [],
    assessment_part:   m.assessment_part == null ? null : m.assessment_part,
    brief:             readable && m.brief != null ? m.brief : null,
    close_at:          m.close_at == null ? null : m.close_at,
    completion:        completion,
    completion_source: completionSource,
    engagement_type:   m.engagement_type == null ? null : m.engagement_type,
    module_id:         m.module_id == null ? null : m.module_id,
    position:          m.position == null ? null : m.position,
    profile_id:        m.profile_id == null ? null : m.profile_id,
    reasons:           Array.isArray(g.reasons) ? g.reasons : [],
    release_at:        m.release_at == null ? null : m.release_at,
    title:             m.title == null ? null : m.title,
  };
}

/**
 * One module as the instructor who manages the section may see it.
 *
 * Everything rowToModule whitelists, plus the derived facts an instructor cannot
 * work out by looking: the effective phase, both directions of the prereq graph,
 * whether this module is caught in a broken one, the environment it resolves to
 * and who it shares that environment with, the deliverable it addresses, and the
 * cohort rollup.
 *
 * `students` is null rather than a zeroed rollup when no roster was supplied, so
 * "nobody is enrolled" and "the roster was not loaded" stay distinguishable.
 *
 * @param {{module:object, phase:string, graph:object, environmentPeers:string[],
 *          rollup:object|null}} input
 * @returns {object}
 */
function instructorModuleView(input) {
  const { module, phase, graph, environmentPeers, rollup } = input || {};
  const base = rowToModule(module) || {};
  const id = base.module_id == null ? null : String(base.module_id);

  const prereqProblems = [];
  if (graph && graph.cyclicIds && graph.cyclicIds.has(id)) prereqProblems.push('cycle');
  if (graph && Array.isArray(graph.dangling) && graph.dangling.some((e) => e.module_id === id)) {
    prereqProblems.push('dangling');
  }

  return {
    ...base,
    release_phase:           phase == null ? null : phase,
    requires_module_ids:     (graph && graph.requiresById && graph.requiresById.get(id)) || [],
    required_by_module_ids:  (graph && graph.dependentsById && graph.dependentsById.get(id)) || [],
    prereq_problems:         prereqProblems,
    environment_key:         environmentKeyOf(base),
    shares_environment_with: Array.isArray(environmentPeers) ? environmentPeers : [],
    evidence_key:            evidenceKeyFor(base),
    students:                rollup || null,
  };
}

/** An instructor-facing configuration problem. */
function issueOf(code, moduleId, detail) {
  return {
    severity: S.ISSUE_SEVERITY[code] || 'warning',
    code,
    message: S.messageFor(code),
    module_id: moduleId === undefined ? null : moduleId,
    detail: detail === undefined ? null : detail,
  };
}

/**
 * Everything about this section's configuration that its instructor can fix.
 *
 * NEVER RETURNED ON A STUDENT PATH. A student can act on none of these, and
 * several of them name modules the student must not know exist.
 *
 * Errors first, then warnings, then info, and within each kind in module order,
 * so the list an instructor reads is stable between page loads.
 *
 * ENGAGEMENT READINESS IS DELIBERATELY NOT HERE. "Are this module's bridges up"
 * needs resolveEngagement(), which is a database read into another concern, and
 * ciab_engagement.provision_status is volatile by construction — the boot sweep
 * flips every 'provisioning' row to 'failed' on every restart, so it must be
 * read live rather than folded into a pure function. That belongs to D3.
 *
 * `section` and `nowMs` are part of the documented call shape and are read by no
 * issue today; a future time-dependent issue therefore needs no call-site change.
 *
 * @param {{section:object|null, modules:object[], graph:object, nowMs:number}} input
 * @returns {object[]}
 */
function sectionIssues(input) {
  const { section, modules, graph, nowMs } = input || {};
  const list = Array.isArray(modules) ? modules : [];
  const g = graph || buildGraph(list, []);
  const issues = [];

  // Errors — a module can never open in its current configuration.
  for (const module of list) {
    const id = String(module.module_id);
    if (g.cyclicIds.has(id)) issues.push(issueOf(S.ISSUE.PREREQ_CYCLE, id));
  }
  for (const edge of g.dangling) {
    issues.push(issueOf(S.ISSUE.PREREQ_MISSING, edge.module_id, {
      prereq_module_id: edge.prereq_module_id,
    }));
  }
  // A published module gated on a draft or archived one is locked for the WHOLE
  // roster, forever, and this is the only surface that can say so. The draft is
  // invisible to every student, cannot be self-marked and derives no completion,
  // so the prerequisite can never be satisfied by anybody until it is published.
  // Without this the instructor sees blocked_by_prereq counting the entire class
  // and nothing else — the number is indistinguishable from a cohort that
  // simply has not finished the earlier work yet.
  for (const module of list) {
    if (module.release_state === 'draft') continue;
    const id = String(module.module_id);
    for (const prereqId of g.requiresById.get(id) || []) {
      const prereq = g.byId.get(prereqId);
      // A prerequisite outside the section is already PREREQ_MISSING above.
      if (!prereq) continue;
      if (prereq.release_state !== 'draft' && prereq.release_state !== 'archived') continue;
      issues.push(issueOf(S.ISSUE.PREREQ_UNPUBLISHED, id, { prereq_module_id: prereqId }));
    }
  }
  for (const module of list) {
    if (module.release_state === 'scheduled' && module.release_at == null) {
      issues.push(issueOf(S.ISSUE.SCHEDULED_WITHOUT_DATE, String(module.module_id)));
    }
  }
  for (const module of list) {
    if (module.release_at == null || module.close_at == null) continue;
    if (toMs(module.close_at) <= toMs(module.release_at)) {
      issues.push(issueOf(S.ISSUE.CLOSE_BEFORE_RELEASE, String(module.module_id), {
        release_at: module.release_at,
        close_at: module.close_at,
      }));
    }
  }

  // Warnings — probably not what was meant, but the section still works.
  for (const module of list) {
    if (module.release_state !== 'draft' && module.profile_id == null) {
      issues.push(issueOf(S.ISSUE.CLIENT_UNBOUND, String(module.module_id)));
    }
  }
  for (const duplicate of g.duplicatePositions) {
    issues.push(issueOf(S.ISSUE.DUPLICATE_POSITION, null, {
      position: duplicate.position,
      module_ids: duplicate.module_ids,
    }));
  }
  if (list.length > 0 && list.every((module) => module.release_state === 'draft')) {
    issues.push(issueOf(S.ISSUE.NO_PUBLISHED_MODULES, null));
  }

  // Info — legitimate, common, and worth knowing before something is torn down.
  for (const [environmentKey, shared] of groupByEnvironment(list)) {
    if (shared.length < 2) continue;
    issues.push(issueOf(S.ISSUE.SHARED_ENVIRONMENT, null, {
      environment_key: environmentKey,
      module_ids: shared.map((module) => String(module.module_id)),
    }));
  }

  return issues;
}

// ─── The two entry points ───────────────────────────────────────────────────

/**
 * Index a sparse set of ciab_module_student rows by module, for ONE student.
 *
 * `userId` IS THE GUARD, NOT AN OPTIMISATION. loadStudentStates(sectionId,
 * userId) and loadSectionStates(sectionId) sit next to each other in this file
 * and return identical column shapes; only the first is user-scoped. Keyed on
 * module_id alone, a caller that reached for the section-wide loader — a
 * "preview as student" endpoint, a page-data builder that already loaded the
 * cohort grid — would silently keep the LAST row per module whoever it belonged
 * to, and hand this student another student's release_override together with the
 * instructor's private override_reason about them, verbatim.
 *
 * A row for somebody else is a caller mistake with no safe reading, so it is
 * REFUSED rather than quietly dropped: dropping it would leave that same caller
 * shipping a subtly wrong page with nothing to find. Status 500, like the
 * missing clock — no client can send this wrong.
 *
 * @param {object[]} states
 * @param {string|null} [userId] whose rows these must be
 * @returns {Map<string, object>}
 */
function indexStates(states, userId) {
  const expected = userId == null ? null : String(userId);
  const byModule = new Map();
  for (const row of Array.isArray(states) ? states : []) {
    if (!row || row.module_id == null) continue;
    if (expected !== null && row.user_id != null && String(row.user_id) !== expected) {
      throw Object.assign(
        new Error('states holds another student\'s row: pass loadStudentStates(sectionId, userId)'),
        { status: 500 }
      );
    }
    byModule.set(String(row.module_id), rowToStudentState(row));
  }
  return byModule;
}

/**
 * This module's prerequisites, resolved for ONE student.
 *
 * A prerequisite whose module is not in the section's set is `missing`, and is
 * also not satisfied — belt and braces, so a caller that only looks at
 * `satisfied` still fails closed.
 *
 * `visibleIds` IS WHAT KEEPS A DRAFT OUT OF A STUDENT'S PAYLOAD. Dropping draft
 * and archived modules from the student's own list is not enough on its own: an
 * edge from a PUBLISHED module to a draft one is a legal row, and resolving it
 * by name here would put that draft's module_id and its title straight into the
 * gated module's PREREQ_INCOMPLETE detail — undoing, one field over, the whole
 * reason drafts are dropped rather than flagged. So the student path passes the
 * set of ids it is willing to name, and a prerequisite outside it is reported as
 * unresolvable with module_id null: evaluateGate answers PREREQ_MISSING, which
 * fails closed, is truthful, names nothing, and sends them to the one person who
 * can fix it. Telling them instead to "finish the module(s) this one follows
 * first" would name a module absent from their own list that can never clear.
 *
 * The instructor path passes NO set. The full blocking detail is exactly what
 * the rollup and the issue list exist to show, and it is also how
 * PREREQ_UNPUBLISHED gets reported at all.
 *
 * @param {object} graph buildGraph output
 * @param {string} moduleId
 * @param {Map<string,string>} completionByModule resolved completion per module
 * @param {Set<string>} [visibleIds] the module ids this reader may be told about
 * @returns {object[]}
 */
function prereqsFor(graph, moduleId, completionByModule, visibleIds) {
  const required = graph.requiresById.get(moduleId) || [];
  return required.map((prereqId) => {
    if (visibleIds && !visibleIds.has(prereqId)) {
      return { module_id: null, title: null, position: null, satisfied: false, missing: true };
    }
    const prereq = graph.byId.get(prereqId);
    if (!prereq) {
      return { module_id: prereqId, title: null, position: null, satisfied: false, missing: true };
    }
    return {
      module_id: prereqId,
      title: prereq.title == null ? null : prereq.title,
      position: prereq.position == null ? null : prereq.position,
      satisfied: S.satisfiesPrereq(completionByModule.get(prereqId)),
      missing: false,
    };
  });
}

/** The five section columns either view echoes back. */
function sectionSummary(section) {
  if (!section) return null;
  return {
    section_id: section.section_id,
    name: section.name,
    code: section.code,
    term: section.term,
    status: section.status,
  };
}

/**
 * Is there a derived completion signal for this module at all?
 *
 * A module bound to both a client and an assessment part HAS a signal, and its
 * absence is a real `false` (source 'derived') rather than silence. An unbound
 * module has no signal, and says so with null (source 'default'). Both resolve
 * to 'incomplete'; the difference is what an instructor UI is able to explain.
 */
function derivedSignalFor(module, completedIds) {
  const id = String(module.module_id);
  if (completedIds.has(id)) return true;
  return evidenceKeyFor(module) === null ? null : false;
}

/**
 * The whole of one section, as one student sees it.
 *
 * `enrolled` is SUPPLIED BY THE CALLER and never defaulted true — the resolver
 * must not infer eligibility for itself, because the one place that inference
 * could be wrong is the place that decides whether a stranger reads the class.
 *
 * DRAFT AND ARCHIVED MODULES ARE DROPPED, not returned with access 'hidden'.
 * Their module_id never crosses the wire, which is the strongest available form
 * of "a student cannot know a draft exists": an id alone is enough to guess a
 * URL.
 *
 * @param {{section:object|null, enrolled:boolean, userId:string|null,
 *          modules:object[], edges:object[], states:object[],
 *          derivedCompleteIds:Set<string>, now:*}} input
 * @returns {object}
 */
function resolveForStudent(input) {
  const {
    section, enrolled, userId, modules, edges, states, derivedCompleteIds, now,
  } = input || {};

  const nowMs = toMs(now);
  const ordered = sortModules(modules);
  const graph = buildGraph(ordered, edges);
  const stateByModule = indexStates(states, userId);
  const completedIds = derivedCompleteIds instanceof Set
    ? derivedCompleteIds
    : new Set(Array.isArray(derivedCompleteIds) ? derivedCompleteIds : []);
  const sectionActive = !!section && section.status === 'active';

  // Pass one. Every module's phase and completion, before any gate runs: a
  // gate reads the completion of OTHER modules, so no gate can be evaluated
  // until the whole map exists.
  const phaseByModule = new Map();
  const completionByModule = new Map();
  const sourceByModule = new Map();
  // The ids this reader may be told about, which is the same set pass two is
  // willing to return. A prerequisite outside it is reported as unresolvable
  // rather than by name — see prereqsFor.
  const visible = new Set();
  for (const module of ordered) {
    const id = String(module.module_id);
    const phase = releasePhase(module, nowMs);
    phaseByModule.set(id, phase);
    if (phase !== 'draft' && phase !== 'archived') visible.add(id);
    const resolved = resolveCompletion(
      stateByModule.get(id) || null,
      derivedSignalFor(module, completedIds)
    );
    completionByModule.set(id, resolved.completion);
    sourceByModule.set(id, resolved.source);
  }

  // Pass two. The gate, then the projection.
  const views = [];
  const counts = { total: 0, open: 0, locked: 0, closed: 0 };
  let nextModuleId = null;

  for (const module of ordered) {
    const id = String(module.module_id);
    const phase = phaseByModule.get(id);

    // Dropped for EVERY reader, before the gate is even asked. The gate answers
    // the section and enrollment questions FIRST — correctly, because they are
    // the more actionable refusal — so a student who has been dropped from the
    // class, or one whose section has since been archived, would otherwise be
    // handed 'locked' for a module that has not been written, and its module_id
    // with it. Dropping on the phase rather than on access==='hidden' is what
    // makes "a student cannot know a draft exists" hold for every reader rather
    // than only for the enrolled ones.
    if (phase === 'draft' || phase === 'archived') continue;

    const gate = evaluateGate({
      module,
      phase,
      state: stateByModule.get(id) || null,
      prereqs: prereqsFor(graph, id, completionByModule, visible),
      cyclic: graph.cyclicIds.has(id),
      sectionActive,
      enrolled: !!enrolled,
    });
    if (gate.access === 'hidden') continue;

    const completion = completionByModule.get(id);
    views.push(studentModuleView({
      module,
      gate,
      completion,
      completionSource: sourceByModule.get(id),
    }));

    counts.total += 1;
    if (counts[gate.access] !== undefined) counts[gate.access] += 1;
    if (nextModuleId === null && gate.access === 'open' && !S.satisfiesPrereq(completion)) {
      nextModuleId = module.module_id;
    }
  }

  return {
    section: sectionSummary(section),
    now: nowMs,
    enrolled: !!enrolled,
    modules: views,
    next_module_id: nextModuleId,
    counts,
  };
}

/**
 * The whole of one section, as the instructor who manages it sees it.
 *
 * The cohort rollup runs the SAME evaluateGate as the student view, modules x
 * roster times, entirely in memory over arrays already loaded — zero extra
 * queries. A second, "cheaper" opinion for the grid is how a grid comes to
 * disagree with the page a student is looking at, and the instructor is the one
 * who has to reconcile them.
 *
 * @param {{section:object|null, modules:object[], edges:object[], states:object[],
 *          roster:string[], derivedByUser:Map<string,Set<string>>, now:*}} input
 * @returns {object}
 */
function resolveForInstructor(input) {
  const {
    section, modules, edges, states, roster, derivedByUser, now,
  } = input || {};

  const nowMs = toMs(now);
  const ordered = sortModules(modules);
  const graph = buildGraph(ordered, edges);
  const environments = groupByEnvironment(ordered);
  const sectionActive = !!section && section.status === 'active';

  // SUPPLY, NOT LENGTH. `students` is null only when no roster was passed at
  // all; an EMPTY roster is a real answer — zero enrolled — and gets the zeroed
  // rollup. Branching on length instead made the two byte-identical, so a
  // brand-new section rendered as "the roster was not loaded" forever.
  const rosterSupplied = Array.isArray(roster);
  const rosterIds = [];
  for (const userId of rosterSupplied ? roster : []) {
    if (userId != null) rosterIds.push(String(userId));
  }
  const derivedMap = derivedByUser instanceof Map ? derivedByUser : new Map();
  const noIds = new Set();

  const phaseByModule = new Map();
  for (const module of ordered) {
    phaseByModule.set(String(module.module_id), releasePhase(module, nowMs));
  }

  // Every row in the section, indexed (user -> module -> state) in one pass.
  const stateByUser = new Map();
  for (const row of Array.isArray(states) ? states : []) {
    if (!row || row.user_id == null || row.module_id == null) continue;
    const userId = String(row.user_id);
    if (!stateByUser.has(userId)) stateByUser.set(userId, new Map());
    stateByUser.get(userId).set(String(row.module_id), rowToStudentState(row));
  }

  // Every roster member's completion for every module, before any gate runs —
  // same reason as the student view, and computed once rather than per gate
  // call, which is what keeps the cross-product to two flat passes.
  const completionByUser = new Map();
  for (const userId of rosterIds) {
    const completedIds = derivedMap.get(userId) || noIds;
    const userStates = stateByUser.get(userId);
    const perModule = new Map();
    for (const module of ordered) {
      const id = String(module.module_id);
      perModule.set(id, resolveCompletion(
        (userStates && userStates.get(id)) || null,
        derivedSignalFor(module, completedIds)
      ).completion);
    }
    completionByUser.set(userId, perModule);
  }

  const views = [];
  const counts = { total: 0, draft: 0, pending: 0, open: 0, closed: 0, archived: 0 };

  for (const module of ordered) {
    const id = String(module.module_id);
    const phase = phaseByModule.get(id);
    counts.total += 1;
    if (counts[phase] !== undefined) counts[phase] += 1;

    const environmentKey = environmentKeyOf(module);
    const peers = (environments.get(environmentKey) || [])
      .filter((peer) => String(peer.module_id) !== id)
      .map((peer) => String(peer.module_id));

    let rollup = null;
    if (rosterSupplied) {
      rollup = {
        enrolled: rosterIds.length,
        with_state: 0,
        completion: { incomplete: 0, complete: 0, waived: 0 },
        access: { hidden: 0, locked: 0, open: 0, closed: 0 },
        overridden: { unlock: 0, lock: 0 },
        blocked_by_prereq: 0,
      };
      const cyclic = graph.cyclicIds.has(id);
      for (const userId of rosterIds) {
        const userStates = stateByUser.get(userId);
        const state = (userStates && userStates.get(id)) || null;
        if (state) rollup.with_state += 1;
        if (state && rollup.overridden[state.release_override] !== undefined) {
          rollup.overridden[state.release_override] += 1;
        }

        const perModule = completionByUser.get(userId);
        const completion = perModule.get(id);
        if (rollup.completion[completion] !== undefined) rollup.completion[completion] += 1;

        const gate = evaluateGate({
          module,
          phase,
          state,
          prereqs: prereqsFor(graph, id, perModule),
          cyclic,
          sectionActive,
          enrolled: true,
        });
        if (rollup.access[gate.access] !== undefined) rollup.access[gate.access] += 1;
        if (gate.reasons.some((r) => r.code === S.REASON.PREREQ_INCOMPLETE)) {
          rollup.blocked_by_prereq += 1;
        }
      }
    }

    views.push(instructorModuleView({
      module, phase, graph, environmentPeers: peers, rollup,
    }));
  }

  return {
    section: sectionSummary(section),
    now: nowMs,
    roster_size: rosterIds.length,
    modules: views,
    issues: sectionIssues({ section, modules: ordered, graph, nowMs }),
    counts,
  };
}

// ─── Loaders ────────────────────────────────────────────────────────────────
// One query per COLLECTION, never one per student, and every SELECT lists its
// columns explicitly. `SELECT *` would let a column added by a later migration reach
// a response through a door the projection whitelists do not guard.

/**
 * The section a student is asking about, plus whether they may be there.
 *
 * THE SECTION'S OWN STATUS IS RETURNED, NOT PUT IN THE WHERE CLAUSE, so the gate
 * can distinguish "archived" (locked, with a sentence explaining why) from "does
 * not exist" (null, and the caller's 403). Only an 'active' enrollment grants
 * anything; 'completed' deliberately does not, or an end-of-term roster silently
 * keeps access.
 *
 * DELIBERATELY NOT enrollment.isEnrolled(userId). That helper takes ONE argument
 * and answers "any active enrollment on ANY active section", which would let any
 * enrolled student in the school read any other section's modules. Folding the
 * EXISTS in here is one round trip instead of two AND yields the
 * archived-versus-missing distinction. When a SECOND caller appears in D4,
 * promote this next to enrollment.js's ACTIVE_SQL rather than inlining a fourth
 * per-section predicate.
 *
 * @returns {Promise<object|null>}
 */
async function loadSectionForStudent(sectionId, userId) {
  const res = await query(
    `SELECT s.section_id, s.name, s.code, s.term, s.status,
            EXISTS (SELECT 1 FROM ciab_enrollment e
                     WHERE e.section_id = s.section_id
                       AND e.user_id    = $2
                       AND e.status     = 'active') AS enrolled
       FROM ciab_section s
      WHERE s.section_id = $1`,
    [sectionId, userId]
  );
  return res.rows[0] || null;
}

/**
 * The section a staff member is asking about.
 *
 * AUTHORIZATION IS THE CALLER'S JOB, and it is two checks in this order:
 * requireRole('instructor','admin') as a file-level const, THEN
 * enrollment.getManagedSection(sectionId, req.user, <a column list literal
 * defined in that route file>) returning non-null. Never req.user.role alone,
 * and never caller-supplied text in the columns argument, which getManagedSection
 * interpolates. The refusal is exactly
 * res.status(403).json({ error: 'Section not found or access denied' }) with no
 * 404 branch, so section ids cannot be enumerated by their error code.
 *
 * @returns {Promise<object|null>}
 */
async function loadSectionForStaff(sectionId) {
  const res = await query(
    `SELECT section_id, name, code, term, status
       FROM ciab_section
      WHERE section_id = $1`,
    [sectionId]
  );
  return res.rows[0] || null;
}

/**
 * Every module in the section, in the resolver's order.
 *
 * The ORDER BY names the same three columns as compareModules, so the database
 * path and the pure path can never disagree about which module is next.
 *
 * @returns {Promise<object[]>}
 */
async function loadModules(sectionId) {
  const res = await query(
    `SELECT module_id, section_id, position, title, brief, instructor_notes,
            profile_id, engagement_type, assessment_part,
            release_state, release_at, close_at,
            cloned_from_module_id, created_by, updated_by, created_at, updated_at
       FROM ciab_module
      WHERE section_id = $1
      ORDER BY position, created_at, module_id`,
    [sectionId]
  );
  return res.rows.map(rowToModule);
}

/**
 * Every prerequisite edge in the section — the whole graph in one query, after
 * which all the graph work is pure.
 *
 * @returns {Promise<{module_id:string, prereq_module_id:string}[]>}
 */
async function loadPrereqEdges(sectionId) {
  const res = await query(
    `SELECT module_id, prereq_module_id
       FROM ciab_module_prereq
      WHERE section_id = $1`,
    [sectionId]
  );
  return res.rows;
}

/**
 * One student's stored state across the section. Sparse by design.
 * @returns {Promise<object[]>}
 */
async function loadStudentStates(sectionId, userId) {
  const res = await query(
    `SELECT st.module_id, st.user_id, st.completion, st.completed_at,
            st.completed_by, st.release_override, st.override_reason,
            st.override_by, st.override_at
       FROM ciab_module_student st
       JOIN ciab_module m ON m.module_id = st.module_id
      WHERE m.section_id = $1 AND st.user_id = $2`,
    [sectionId, userId]
  );
  return res.rows;
}

/**
 * Every stored state in the section — the whole cohort grid in one query.
 * @returns {Promise<object[]>}
 */
async function loadSectionStates(sectionId) {
  const res = await query(
    `SELECT st.module_id, st.user_id, st.completion, st.completed_at,
            st.completed_by, st.release_override, st.override_reason,
            st.override_by, st.override_at
       FROM ciab_module_student st
       JOIN ciab_module m ON m.module_id = st.module_id
      WHERE m.section_id = $1`,
    [sectionId]
  );
  return res.rows;
}

/**
 * The user ids of every actively enrolled STUDENT. 'active' and nothing else,
 * and the 'student' role and nothing else.
 *
 * THE ROLE PREDICATE IS NOT TIDINESS. ciab_enrollment.enrollment_role is one of
 * student / ta / guest / observer (migration 008), and the roster import UI
 * exposes the whole selector, so staff on a section roster is an ordinary
 * shipped state. Without the predicate they would land in TWO places at once:
 * as the denominator of every module's rollup, so the cohort number an
 * instructor acts on counts people who were never meant to do the work; and as
 * an argument to loadPartCompletions, whose entire scoping contract is that the
 * instructor's answer key lives in assessment_progress under a STAFF user_id
 * against the same client and part. A TA who generated that key would then be
 * counted as having completed every part-bound module in the section.
 *
 * If D3 needs the staff list, return enrollment_role alongside user_id and let
 * resolveForInstructor partition — never by widening this roster.
 *
 * @returns {Promise<string[]>}
 */
async function loadActiveRoster(sectionId) {
  const res = await query(
    `SELECT user_id
       FROM ciab_enrollment
      WHERE section_id = $1 AND status = 'active' AND enrollment_role = 'student'`,
    [sectionId]
  );
  return res.rows.map((row) => row.user_id);
}

/**
 * Which (student, module) pairs are derived-complete. The ONE derived-completion
 * producer D1 ships.
 *
 * ZERO QUERIES when no module binds both a client and an assessment part, or
 * when there is nobody to ask about — the common case for a section that
 * sequences briefings and lab work without deliverables, and the reason the
 * student view's budget is "at most" 5 rather than exactly 5.
 *
 * Otherwise exactly ONE query for the whole section. The three ANY() arrays
 * over-select the cross product of users, clients and parts; JavaScript then
 * matches EXACT (user_id, profile_id, part_number) triples back to module ids.
 * One round trip instead of one per student per module, and the result set is at
 * most users x clients x parts.
 *
 * SCOPED BY user_id, AND THAT SCOPING IS LOAD-BEARING. The instructor answer key
 * lives in assessment_progress under the INSTRUCTOR's OWN user_id, against the
 * same client and the same part, with status 'reviewed', distinguished only by
 * JSON inside `content`. Passing the section's roster — or the single student —
 * is what stops a key from satisfying a student's prerequisite. NEVER call this
 * with a staff id while previewing a student's view.
 *
 * @param {object[]} modules
 * @param {string[]} userIds
 * @returns {Promise<Map<string, Set<string>>>} user_id -> completed module ids
 */
async function loadPartCompletions(modules, userIds) {
  const completedByUser = new Map();

  const users = [];
  const seenUsers = new Set();
  for (const userId of Array.isArray(userIds) ? userIds : []) {
    if (userId == null) continue;
    const id = String(userId);
    if (seenUsers.has(id)) continue;
    seenUsers.add(id);
    users.push(id);
  }

  const bound = (Array.isArray(modules) ? modules : []).filter((m) => evidenceKeyFor(m) !== null);
  if (users.length === 0 || bound.length === 0) return completedByUser;

  const profileIds = [...new Set(bound.map((m) => String(m.profile_id)))];
  const parts = [...new Set(bound.map((m) => Number(m.assessment_part)))];

  const res = await query(
    `SELECT ap.user_id, ap.profile_id, ap.part_number
       FROM assessment_progress ap
      WHERE ap.status      = ANY($1::text[])
        AND ap.user_id     = ANY($2::uuid[])
        AND ap.profile_id  = ANY($3::uuid[])
        AND ap.part_number = ANY($4::int[])`,
    [S.COMPLETING_PART_STATUSES, users, profileIds, parts]
  );

  const submitted = new Set();
  for (const row of res.rows) {
    submitted.add(`${row.user_id}\u0000${row.profile_id}\u0000${Number(row.part_number)}`);
  }

  for (const userId of users) {
    for (const module of bound) {
      const triple = `${userId}\u0000${module.profile_id}\u0000${Number(module.assessment_part)}`;
      if (!submitted.has(triple)) continue;
      if (!completedByUser.has(userId)) completedByUser.set(userId, new Set());
      completedByUser.get(userId).add(String(module.module_id));
    }
  }

  return completedByUser;
}

// ─── Composed reads ─────────────────────────────────────────────────────────
// These two functions are the ONLY places in this file that read the wall clock,
// and a test asserts the count from the file text. Everything above them takes
// the clock as an argument, so a test can pin a section to an instant, and a
// whole response is judged at ONE instant rather than at however many the calls
// inside it happened to span.

/**
 * One student's view of one section. AT MOST 5 QUERIES, invariant under the
 * number of modules — an N+1 shows up here as a number in a test rather than as
 * a slow page in production.
 *
 * DOES NOT THROW WHEN THE STUDENT IS NOT ENROLLED. It returns the full shape
 * with enrolled:false and every module locked, so the caller chooses between a
 * 403 and the friendlier "you are no longer on this class" — a distinction the
 * resolver has no business making.
 *
 * @returns {Promise<object|null>} null when the section does not exist
 */
async function studentSectionView(sectionId, userId, { now = Date.now() } = {}) {
  const section = await loadSectionForStudent(sectionId, userId);
  if (!section) return null;

  const [modules, edges, states] = await Promise.all([
    loadModules(sectionId),
    loadPrereqEdges(sectionId),
    loadStudentStates(sectionId, userId),
  ]);

  const completedByUser = await loadPartCompletions(modules, [userId]);

  return resolveForStudent({
    section,
    enrolled: section.enrolled === true,
    userId,
    modules,
    edges,
    states,
    derivedCompleteIds: completedByUser.get(String(userId)) || new Set(),
    now,
  });
}

/**
 * The instructor's view of one section. AT MOST 6 QUERIES, invariant under the
 * number of modules AND the size of the roster.
 *
 * AUTHORIZATION HAPPENS IN THE CALLER, before this is reached — see
 * loadSectionForStaff.
 *
 * @returns {Promise<object|null>} null when the section does not exist
 */
async function instructorSectionView(sectionId, { now = Date.now() } = {}) {
  const section = await loadSectionForStaff(sectionId);
  if (!section) return null;

  const [modules, edges, states, roster] = await Promise.all([
    loadModules(sectionId),
    loadPrereqEdges(sectionId),
    loadSectionStates(sectionId),
    loadActiveRoster(sectionId),
  ]);

  const derivedByUser = await loadPartCompletions(modules, roster);

  return resolveForInstructor({
    section, modules, edges, states, roster, derivedByUser, now,
  });
}

// ─── Writes ─────────────────────────────────────────────────────────────────
// Exactly two, and no more. "Per-student state" that cannot be written is not
// state, and the ON CONFLICT target below is the primary key migration 014
// actually creates, pinned by a test rather than by memory. Every other write —
// create, clone, reorder, release, prerequisite edges — belongs to D2, D5 and
// D8. Neither of these calls enrollment.invalidate(): they touch neither
// ciab_enrollment nor ciab_section.status, so the access gate's cache is
// unaffected by them.

/** The nine columns either writer returns. */
const STATE_RETURNING = `module_id, user_id, completion, completed_at, completed_by,
            release_override, override_reason, override_by, override_at`;

/**
 * Record (or clear) one student's completion decision for one module.
 *
 * RETURNING TO 'auto' OR 'incomplete' NULLS BOTH AUDIT COLUMNS. A completed_by
 * left behind from a decision that has since been reversed is worse than no
 * attribution at all: it names somebody as having marked work complete that the
 * row now says is not.
 *
 * actorId null alongside a marking decision means the student marked it
 * themselves, which is a legitimate configuration and not a missing value.
 *
 * @param {string} moduleId
 * @param {string} userId
 * @param {string} decision one of S.COMPLETION_DECISIONS
 * @param {{actorId?: string|null}} options
 * @returns {Promise<object>} the stored state
 */
async function setCompletion(moduleId, userId, decision, options = {}) {
  const { actorId = null } = options;
  if (!S.isCompletionDecision(decision)) {
    throw Object.assign(
      new Error(`completion must be one of: ${S.COMPLETION_DECISIONS.join(', ')}`),
      { status: 400 }
    );
  }

  const marking = decision === 'complete' || decision === 'waived';
  const res = await query(
    `INSERT INTO ciab_module_student
            (module_id, user_id, completion, completed_at, completed_by)
     VALUES ($1, $2, $3,
             CASE WHEN $4::boolean THEN now() ELSE NULL END,
             CASE WHEN $4::boolean THEN $5::uuid ELSE NULL END)
     ON CONFLICT (module_id, user_id) DO UPDATE
        SET completion   = EXCLUDED.completion,
            completed_at = EXCLUDED.completed_at,
            completed_by = EXCLUDED.completed_by,
            updated_at   = now()
     RETURNING ${STATE_RETURNING}`,
    [moduleId, userId, decision, marking, actorId]
  );
  return rowToStudentState(res.rows[0]);
}

/**
 * Set (or clear) one student's release override for one module.
 *
 * `override` may be null, which clears it and returns the student to whatever
 * the module's own release rules say. Clearing is a legitimate write rather than
 * a vocabulary member, which is why S.isReleaseOverride() rejects null and this
 * function branches on it explicitly.
 *
 * override_at is computed in the statement from the value being written, so an
 * override and its timestamp cannot disagree — and $3 is cast at the reference
 * that would otherwise leave its type undetermined, the mistake
 * test/sql-param-typing.test.js exists to catch.
 *
 * @param {string} moduleId
 * @param {string} userId
 * @param {string|null} override 'unlock', 'lock', or null to clear
 * @param {{reason?: string|null, actorId?: string|null}} options
 * @returns {Promise<object>} the stored state
 */
async function setReleaseOverride(moduleId, userId, override, options = {}) {
  const { reason = null, actorId = null } = options;
  if (!(override === null || S.isReleaseOverride(override))) {
    throw Object.assign(
      new Error(`release override must be null or one of: ${S.RELEASE_OVERRIDES.join(', ')}`),
      { status: 400 }
    );
  }

  const res = await query(
    `INSERT INTO ciab_module_student
            (module_id, user_id, release_override, override_reason,
             override_by, override_at)
     VALUES ($1, $2, $3, $4, $5,
             CASE WHEN $3::text IS DISTINCT FROM NULL THEN now() ELSE NULL END)
     ON CONFLICT (module_id, user_id) DO UPDATE
        SET release_override = EXCLUDED.release_override,
            override_reason  = EXCLUDED.override_reason,
            override_by      = EXCLUDED.override_by,
            override_at      = EXCLUDED.override_at,
            updated_at       = now()
     RETURNING ${STATE_RETURNING}`,
    [moduleId, userId, override, reason, actorId]
  );
  return rowToStudentState(res.rows[0]);
}

module.exports = {
  // Loaders
  loadSectionForStudent,
  loadSectionForStaff,
  loadModules,
  loadPrereqEdges,
  loadStudentStates,
  loadSectionStates,
  loadActiveRoster,
  loadPartCompletions,
  // Composed reads
  studentSectionView,
  instructorSectionView,
  // Writes
  setCompletion,
  setReleaseOverride,
  // Pure, so the whole gate is testable with no database and no clock.
  toMs,
  rowToModule,
  rowToStudentState,
  compareModules,
  sortModules,
  buildGraph,
  releasePhase,
  resolveCompletion,
  evaluateGate,
  environmentKeyOf,
  groupByEnvironment,
  evidenceKeyFor,
  studentModuleView,
  instructorModuleView,
  sectionIssues,
  resolveForStudent,
  resolveForInstructor,
  STUDENT_VIEW_KEYS,
};
