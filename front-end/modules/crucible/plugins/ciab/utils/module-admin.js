/**
 * ============================================================================
 * CIAB Plugin — Module administration: every decision the routes make
 * ============================================================================
 * Everything decision-shaped that routes/section-modules.js needs lives HERE,
 * so it is reachable with no HTTP server and no database — the convention this
 * plugin already states in utils/section-roster.js's header ("keep route
 * handlers thin; put the logic in utils").
 *
 * WHAT THAT BUYS, CONCRETELY: the reorder statement's exact SQL text, the clone
 * plan, the title-truncation rule and the before/after cycle diff are all
 * assertable by requiring this file. Folded into the route they would only be
 * inspectable by standing up an express server and a stubbed pool, which is
 * exactly the shape that makes a wrong cast or a wrong operand survive review.
 *
 * A MODULE IS ONE CLIENT, ONE ENGAGEMENT AND ONE PLACE IN A SEQUENCE. Nothing
 * here knows about environments, lanes or grades.
 *
 * CLONE_COPIES + CLONE_RESETS + 'section_id' IS EXACTLY MODULE_COLUMNS, and a
 * test asserts the partition. That is the server-side form of topology-seed's
 * exported stripUncloneableSpecKeys: it makes it structurally impossible for a
 * column added by a later migration to be silently omitted from the clone
 * decision — the omission fails a test rather than shipping as a copy that
 * quietly drops a field.
 */

const S = require('./module-states');
const spine = require('./module-spine');
const { PART_DEFINITIONS, getPartName } = require('./part-definitions');

/**
 * LAZY, AND LOAD-BEARING — DO NOT HOIST. ./lane-reservation pulls
 * src/utils/proxmox.js, lab-network-provision.js and lane-deployer.js in at
 * module scope; a top-level require here surfaces under `node --test` as a
 * whole-FILE "Unable to deserialize cloned data" crash with no assertion
 * attached to explain it. Deferring it costs one cached require lookup.
 *
 * Sanitizing rather than trusting the input: engagement_type is the slug half
 * of ciab_engagement's UNIQUE (profile_id, engagement_type), and ' External '
 * must not alias onto the key 'external' actually names.
 *
 * @param {*} raw
 * @returns {string} the sanitized slug
 */
function engagementSlug(raw) {
  const { sanitizeEngagementType } = require('./lane-reservation');
  return sanitizeEngagementType(raw);
}

// ── Constants ───────────────────────────────────────────────────────────────

/**
 * A term's sequence is authored by hand; migration 014's header says the worst
 * term anyone has described is about 40 modules. The cap exists so a reorder
 * cannot be handed ten thousand ids, and so the deliberate absence of
 * pagination is bounded by a refusal rather than by hope. It moves in ONE
 * constant, and it is enforced INSIDE both INSERTs so a section cannot race
 * past it and become unreorderable. Mirrors roster.MAX_ROWS living in a util
 * rather than in a route.
 */
const MAX_MODULES = 200;

/**
 * ciab_module.title is VARCHAR(255). A source already at 255 plus ' (copy)' is
 * 262 and raises 22001 string_data_right_truncation — a 500 for a clone that
 * looks entirely correct to the person who asked for it.
 */
const TITLE_MAX = 255;

/**
 * The SAME 17 columns spine.loadModules names, verbatim and in the same order,
 * so every RETURNING row goes through spine.rowToModule's whitelist unchanged.
 */
const MODULE_COLUMNS = 'module_id, section_id, position, title, brief, instructor_notes, '
  + 'profile_id, engagement_type, assessment_part, release_state, release_at, close_at, '
  + 'cloned_from_module_id, created_by, updated_by, created_at, updated_at';

/** The columns a clone carries across from its source. */
const CLONE_COPIES = Object.freeze([
  'title', 'brief', 'instructor_notes', 'profile_id', 'engagement_type', 'assessment_part',
]);

/** The columns a clone does NOT carry across — identity, provenance, sequence
 *  position and the release window, which is reset to an unpublished draft. */
const CLONE_RESETS = Object.freeze([
  'module_id', 'position', 'release_state', 'release_at', 'close_at',
  'cloned_from_module_id', 'created_by', 'updated_by', 'created_at', 'updated_at',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The order normalizeModuleInput emits its pairs in, so a create's params line
 *  up with its INSERT's SELECT list without the route re-sorting anything. */
const WRITABLE_COLUMNS = Object.freeze([
  'title', 'brief', 'instructor_notes', 'profile_id',
  'engagement_type', 'assessment_part', 'release_state', 'release_at', 'close_at',
]);

/** Every unsupplied column's create-mode default. */
const CREATE_DEFAULTS = Object.freeze({
  title: null,
  brief: null,
  instructor_notes: null,
  profile_id: null,
  engagement_type: 'default',
  assessment_part: null,
  release_state: 'draft',
  release_at: null,
  close_at: null,
});

// ── Refusals ────────────────────────────────────────────────────────────────

/** A thrown { status, code } that routes/section-modules.js's fail() answers
 *  verbatim, so the sentence is written once, here, next to the rule. */
function refuse(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

// ── Input normalisation ─────────────────────────────────────────────────────

/** '' and null both mean "no value"; undefined means "not supplied". */
const isBlank = (v) => v === null || v === undefined || (typeof v === 'string' && v.trim() === '');

/**
 * Turn a request body into `[column, value]` pairs in MODULE_COLUMNS order.
 *
 * partial:false (create) returns a COMPLETE record — every unsupplied column
 * filled with its default — so the INSERT's parameter list is positional and
 * cannot silently shift.
 *
 * partial:true (patch) returns ONLY the keys actually present in the body, so
 * an explicit null CLEARS a field and an absent key leaves it untouched. That
 * distinction is the whole reason this surface is PATCH and not PUT.
 *
 * Neither mode refuses 'scheduled' with no date, nor a close time on or before
 * the release time: migration 014 ships no CHECK for either on purpose, and
 * refusing them would make correcting an inverted window in two PATCHes
 * impossible and two of the resolver's nine issues unreachable. writeNotices()
 * echoes both back instead.
 *
 * @param {object} body
 * @param {{partial:boolean}} options
 * @returns {{values: Array<[string, *]>}}
 */
function normalizeModuleInput(body, { partial = false } = {}) {
  const src = body && typeof body === 'object' ? body : {};
  const values = [];
  const supplied = (col) => src[col] !== undefined;
  const emit = (col, val) => values.push([col, val]);

  for (const col of WRITABLE_COLUMNS) {
    if (partial && !supplied(col)) continue;
    const raw = supplied(col) ? src[col] : CREATE_DEFAULTS[col];

    switch (col) {
      case 'title': {
        const title = String(raw == null ? '' : raw).trim();
        if (!title) throw refuse(400, 'TITLE_REQUIRED', 'A module title is required');
        emit(col, title.slice(0, TITLE_MAX));
        break;
      }
      case 'brief':
      case 'instructor_notes': {
        emit(col, isBlank(raw) ? null : String(raw).trim() || null);
        break;
      }
      case 'profile_id': {
        if (isBlank(raw)) { emit(col, null); break; }
        const id = String(raw).trim();
        if (!UUID_RE.test(id)) throw refuse(400, 'PROFILE_ID_INVALID', 'That is not a valid client id');
        emit(col, id);
        break;
      }
      case 'engagement_type': {
        // ALWAYS through the slug function, on create, on patch and on clone.
        emit(col, engagementSlug(raw));
        break;
      }
      case 'assessment_part': {
        if (isBlank(raw)) { emit(col, null); break; }
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 1) {
          throw refuse(400, 'ASSESSMENT_PART_INVALID', 'assessment_part must be a whole number of 1 or more');
        }
        emit(col, n);
        break;
      }
      case 'release_state': {
        const state = String(raw == null ? '' : raw).trim();
        // The message is built from S.RELEASE_STATES, never hand-written: a
        // value missing from a hand-written list is a 23514 in production on a
        // deployment where every fresh-database test passed.
        if (!S.isReleaseState(state)) {
          throw refuse(400, 'RELEASE_STATE_INVALID',
            `release_state must be one of: ${S.RELEASE_STATES.join(', ')}`);
        }
        emit(col, state);
        break;
      }
      case 'release_at':
      case 'close_at': {
        if (isBlank(raw)) { emit(col, null); break; }
        const d = new Date(raw);
        if (!Number.isFinite(d.getTime())) {
          throw col === 'release_at'
            ? refuse(400, 'RELEASE_AT_INVALID', 'Opens at is not a valid date and time')
            : refuse(400, 'CLOSE_AT_INVALID', 'Closes at is not a valid date and time');
        }
        emit(col, d);
        break;
      }
      /* c8 ignore next */
      default: break;
    }
  }

  return { values };
}

// ── The request-scoped echo of the two accepted-but-wrong states ────────────

/**
 * warnings[] for a write: what this request just caused that the resolver will
 * also keep reporting in issues[]. Same { severity, code, message, module_id,
 * detail } shape as an issue, so ONE browser renderer draws both.
 *
 * @param {Array<[string,*]>} values
 * @returns {object[]}
 */
function writeNotices(values) {
  const row = Object.fromEntries(Array.isArray(values) ? values : []);
  const out = [];
  const moduleId = row.module_id || null;

  const at = (v) => {
    if (v === null || v === undefined) return null;
    const t = v instanceof Date ? v.getTime() : new Date(v).getTime();
    return Number.isFinite(t) ? t : null;
  };

  if (row.release_state === 'scheduled' && at(row.release_at) === null) {
    out.push({
      severity: S.ISSUE_SEVERITY[S.ISSUE.SCHEDULED_WITHOUT_DATE],
      code: S.ISSUE.SCHEDULED_WITHOUT_DATE,
      message: S.messageFor(S.ISSUE.SCHEDULED_WITHOUT_DATE),
      module_id: moduleId,
      detail: null,
    });
  }

  const release = at(row.release_at);
  const close = at(row.close_at);
  if (release !== null && close !== null && close <= release) {
    out.push({
      severity: S.ISSUE_SEVERITY[S.ISSUE.CLOSE_BEFORE_RELEASE],
      code: S.ISSUE.CLOSE_BEFORE_RELEASE,
      message: S.messageFor(S.ISSUE.CLOSE_BEFORE_RELEASE),
      module_id: moduleId,
      detail: null,
    });
  }

  return out;
}

// ── The assessment-part collision ───────────────────────────────────────────

/**
 * PURE, over the array spine.loadModules already returned — no extra round trip
 * and no SQL, so this rule is testable with no database at all.
 *
 * assessment_progress is UNIQUE (user_id, profile_id, part_number) with NO
 * section column, so two modules on one client and one part would complete each
 * other for every student on both.
 *
 * Same client + a different part, the same part + a different client, and two
 * modules on one client with a NULL part are ALL allowed — that repetition is
 * what the programme exists for.
 *
 * @returns {object|null} the offending module row, or null
 */
function conflictingPartBinding(modules, candidate) {
  if (!candidate) return null;
  const profileId = candidate.profile_id;
  const part = candidate.assessment_part;
  if (profileId === null || profileId === undefined) return null;
  if (part === null || part === undefined) return null;

  const ownId = candidate.module_id === null || candidate.module_id === undefined
    ? null
    : String(candidate.module_id).toLowerCase();
  const profileKey = String(profileId).toLowerCase();
  const partNumber = Number(part);

  for (const m of Array.isArray(modules) ? modules : []) {
    if (!m) continue;
    if (m.profile_id === null || m.profile_id === undefined) continue;
    if (m.assessment_part === null || m.assessment_part === undefined) continue;
    if (ownId !== null && String(m.module_id).toLowerCase() === ownId) continue;
    if (String(m.profile_id).toLowerCase() !== profileKey) continue;
    if (Number(m.assessment_part) !== partNumber) continue;
    return m;
  }
  return null;
}

// ── Prerequisites ───────────────────────────────────────────────────────────

/**
 * The three refusals a prerequisite insert needs before the database gets it,
 * plus the cycle verdict.
 *
 * THE CYCLE CHECK IS A BEFORE/AFTER DIFF, never the bare `cyclicIds.size > 0`
 * recipe. buildGraph marks everything DOWNSTREAM of a cycle as cyclic too, so
 * on a section that is ALREADY broken the bare recipe refuses every unrelated
 * edge and names the wrong module, the wrong edge and the wrong remedy. Adding
 * an edge is monotone on cyclicIds, so before is a subset of after and the size
 * comparison is exact.
 *
 * There is no second cycle detector here and there must never be one: D1
 * deliberately exported no wouldCreateCycle().
 *
 * @returns {{ok:boolean, status?:number, code?:string, error?:string, detail?:object}}
 */
function classifyPrereqCandidate({ modules, edges, moduleId, prereqModuleId }) {
  // LOWER-CASED ONCE, HERE, for the same reason checkReorderShape folds: ids
  // arrive from a request in whatever case the caller typed, PostgreSQL renders
  // uuid in lowercase canonical form, and buildGraph keys its map with the raw
  // DB value and DROPS any edge whose gated id is not in that map. Without the
  // fold an UPPER-CASED gated id silently vanishes from the candidate graph, the
  // before/after diff comes out equal, and the cycle check waves through the
  // exact loop it exists to refuse. The normalized pair is RETURNED so the route
  // inserts these values rather than the raw request ones.
  const gated = String(moduleId == null ? '' : moduleId).trim().toLowerCase();
  const prereq = String(prereqModuleId == null ? '' : prereqModuleId).trim().toLowerCase();

  // Refused in app code BEFORE ciab_module_prereq_self_chk turns it into a
  // 23514 and a 500.
  if (gated === prereq) {
    return { ok: false, status: 400, code: 'PREREQ_SELF', error: 'A module cannot be its own prerequisite' };
  }

  const list = Array.isArray(modules) ? modules : [];
  const has = (id) => list.some((m) => m && String(m.module_id).toLowerCase() === id);

  if (!has(gated)) {
    return { ok: false, status: 404, code: 'MODULE_NOT_IN_SECTION', error: 'That module is not in this section' };
  }
  // THIS is what prevents the composite-FK 23503, and the cycle check does NOT
  // cover it: buildGraph classes an edge to a module outside the set as
  // dangling, not cyclic.
  if (!has(prereq)) {
    return { ok: false, status: 404, code: 'PREREQ_NOT_IN_SECTION', error: 'That prerequisite is not in this section' };
  }

  const existing = Array.isArray(edges) ? edges : [];
  const candidate = { module_id: gated, prereq_module_id: prereq };
  const before = spine.buildGraph(list, existing).cyclicIds;
  const after = spine.buildGraph(list, [...existing, candidate]).cyclicIds;

  if (after.size > before.size) {
    return {
      ok: false,
      status: 409,
      code: 'PREREQ_CYCLE',
      error: 'That prerequisite would create a loop — this module would end up requiring itself. '
        + 'Remove one of the existing prerequisites first.',
      detail: { cyclic_module_ids: [...after].filter((id) => !before.has(id)) },
    };
  }
  if (before.size > 0) {
    return {
      ok: false,
      status: 409,
      code: 'PREREQ_SECTION_ALREADY_CYCLIC',
      error: 'This section already has a prerequisite loop. Fix that first, then add this one.',
    };
  }

  return { ok: true, moduleId: gated, prereqModuleId: prereq };
}

// ── Reorder ─────────────────────────────────────────────────────────────────

/**
 * Everything a reorder can refuse with NO database at all: a hostile payload
 * never builds a placeholder list, and a non-uuid never reaches the ::uuid
 * cast, where it would raise 22P02 and surface as a 500.
 *
 * Ids are LOWER-CASED here, because PostgreSQL renders uuid in lowercase
 * canonical form and the owned set is built from those rows — without folding,
 * an upper-cased body would land every id in not_in_section and the caller
 * would be told the modules are not in a section they are in.
 *
 * @returns {{ok:boolean, code?:string, error?:string, detail?:object, ids?:string[]}}
 */
function checkReorderShape(order) {
  const invalid = (error, detail) => ({ ok: false, code: 'ORDER_INVALID', error, ...(detail ? { detail } : {}) });

  if (!Array.isArray(order)) {
    return invalid('order must be an array of every module id in this section, in the new sequence');
  }
  if (!order.length) {
    return invalid('order must name at least one module');
  }
  if (order.length > MAX_MODULES) {
    return invalid(`A section is limited to ${MAX_MODULES} modules.`);
  }

  const ids = [];
  const bad = [];
  for (const entry of order) {
    if (typeof entry !== 'string' || !UUID_RE.test(entry.trim())) {
      bad.push(entry === null || typeof entry === 'object' ? String(entry) : entry);
      continue;
    }
    ids.push(entry.trim().toLowerCase());
  }
  if (bad.length) {
    return {
      ok: false,
      code: 'ORDER_INVALID',
      error: 'order contains something that is not a module id',
      detail: { invalid: bad },
    };
  }

  // A duplicated id is refused rather than tolerated: UPDATE … FROM (VALUES …)
  // with two rows naming one module applies an arbitrarily chosen source row
  // and reports no error, so the resulting position would be plan-dependent.
  const seen = new Set();
  const duplicates = [];
  for (const id of ids) {
    if (seen.has(id)) { if (!duplicates.includes(id)) duplicates.push(id); }
    seen.add(id);
  }
  if (duplicates.length) {
    return {
      ok: false,
      code: 'ORDER_INVALID',
      error: 'order names the same module more than once',
      detail: { duplicates },
    };
  }

  return { ok: true, ids };
}

/**
 * Set algebra, DB-free: the order must name every module in the section exactly
 * once. 409 rather than 400 — the request was well-formed and merely lost a
 * race with a co-instructor, and the client must be able to tell the two apart
 * in one round trip. The canonical current order is echoed back so the browser
 * can resync without a second GET.
 *
 * @returns {{ok:boolean, body?:object}}
 */
function checkReorderMembership(ids, ownedIds) {
  const owned = new Set((Array.isArray(ownedIds) ? ownedIds : []).map((id) => String(id).toLowerCase()));
  const given = new Set((Array.isArray(ids) ? ids : []).map((id) => String(id).toLowerCase()));

  const notInSection = [...given].filter((id) => !owned.has(id));
  const missingFromOrder = [...owned].filter((id) => !given.has(id));

  if (!notInSection.length && !missingFromOrder.length) return { ok: true };

  return {
    ok: false,
    body: {
      error: 'The sequence has changed. Reload the modules and try again.',
      code: 'ORDER_STALE',
      not_in_section: notInSection,
      missing_from_order: missingFromOrder,
      order: (Array.isArray(ownedIds) ? ownedIds : []).map((id) => String(id).toLowerCase()),
    },
  };
}

/**
 * A PURE builder, so the exact SQL and the exact casts are assertable with zero
 * HTTP. ONE statement, atomic without a transaction, scoped by section_id.
 *
 * A NAMED SUPERSET of migration 014's header statement, and a reviewer diffing
 * the two will stop at the first differing character, so: this adds exactly ONE
 * thing, `updated_by = $2::uuid` (shifting the ids to $3+) — attribution on a
 * row 014 forbids a trigger from maintaining. It preserves the one-statement
 * atomicity and the section scope.
 *
 * THE TRADE, RECORDED SO NOBODY RE-ADDS IT: an earlier draft also carried
 * `AND m.position IS DISTINCT FROM v.pos`, for an honest updated_at and a
 * rowCount that equalled the moved count. It is REMOVED, and must stay removed.
 * Under READ COMMITTED a row whose qual is false in the statement's snapshot is
 * never returned by the scan, so it is never locked and PostgreSQL's EvalPlanQual
 * re-check never runs on it — and that re-check is the entire mechanism that
 * makes one UPDATE a correct last-write-wins. Migration 014 line 229 deliberately
 * ships NO UNIQUE (section_id, position), so nothing else serializes two writers.
 * With the predicate, two co-instructors reordering the same section inside one
 * statement's window each skip the rows the other moved and commit an interleaved
 * order NEITHER of them asked for, reported as a 200. A bumped updated_at on a
 * row that did not move is strictly cheaper than a silently wrong persisted
 * sequence.
 *
 * A CONSEQUENCE OF DROPPING IT: rowCount is now n, so it is neither the moved
 * count nor a membership check. The caller computes the moved count in
 * JavaScript from the same loadModules read, and compares rowCount against the
 * id count to notice a concurrent delete.
 *
 * @returns {{text:string, params:Array}}
 */
function reorderStatement(sectionId, actorId, ids) {
  const list = Array.isArray(ids) ? ids : [];
  const params = [sectionId, actorId, ...list];
  const tuples = list.map((_, i) => `($${i + 3}::uuid, ${i + 1})`).join(', ');

  const text = `UPDATE ciab_module m
        SET position = v.pos, updated_at = now(), updated_by = $2::uuid
       FROM (VALUES ${tuples}) AS v(module_id, pos)
      WHERE m.module_id = v.module_id
        AND m.section_id = $1::uuid`;

  return { text, params };
}

// ── Clone ───────────────────────────────────────────────────────────────────

/**
 * SAME SHAPE, DIFFERENT CLIENT — the repetition mechanism the whole programme
 * is built on, decided here so the route only has to write it.
 *
 * The release columns are RESET UNCONDITIONALLY and no request-body value can
 * reach them: a copy that inherited 'open' would publish unreviewed work to the
 * whole roster the instant it was written.
 *
 * copy_prereqs is FALSE unconditionally when the target is a different section:
 * ciab_module_prereq's foreign keys are composite, so an edge naming a module
 * in the source section is a 23503 by construction. It is PREVENTED, never
 * caught.
 *
 * THE RETURNED COLUMN SET IS CLONE_COPIES ITSELF, iterated — so adding a name to
 * that list is what makes the clone carry the column, rather than a second
 * hand-written list that can disagree with it.
 *
 * @returns {{title, brief, instructor_notes, profile_id, engagement_type,
 *            assessment_part, copy_prereqs, notices: object[]}}
 */
function planClone(source, body, { crossSection = false } = {}) {
  const src = source || {};
  const req = body && typeof body === 'object' ? body : {};
  const notices = [];

  // An explicitly blank title is a refusal, not a silent fallback to the
  // source's: the instructor typed something and deleted it.
  let title;
  if (req.title !== undefined && req.title !== null) {
    title = String(req.title).trim();
    if (!title) throw refuse(400, 'TITLE_REQUIRED', 'A module title is required');
  } else {
    title = `${String(src.title == null ? '' : src.title).trim()} (copy)`;
  }
  if (title.length > TITLE_MAX) {
    // 255 + ' (copy)' is 262 and would raise 22001 — a 500 for a clone that
    // looks entirely correct. Shorten and say so.
    title = title.slice(0, TITLE_MAX);
    notices.push({ code: 'TITLE_TRUNCATED' });
  }

  let profileId;
  if (req.profile_id !== undefined) {
    if (isBlank(req.profile_id)) profileId = null;
    else {
      const id = String(req.profile_id).trim();
      if (!UUID_RE.test(id)) throw refuse(400, 'PROFILE_ID_INVALID', 'That is not a valid client id');
      profileId = id;
    }
  } else {
    profileId = src.profile_id === undefined ? null : src.profile_id;
  }

  // Through the slug function even when the value is INHERITED, so a
  // hand-inserted ' External ' cannot ride across a clone unsanitized.
  const engagementType = engagementSlug(
    req.engagement_type !== undefined && req.engagement_type !== null && String(req.engagement_type).trim() !== ''
      ? req.engagement_type
      : src.engagement_type
  );

  const copyPrereqs = crossSection
    ? false
    : req.include_prereqs === undefined || req.include_prereqs === null
      ? true
      : Boolean(req.include_prereqs);

  if (crossSection) notices.push({ code: 'PREREQ_NOT_COPIED' });

  // BUILT BY ITERATING CLONE_COPIES, never by hand-listing the six fields: the
  // partition test already forces a later author to classify a column added by a
  // migration, and this is what makes that classification actually DO something.
  // Hand-listing meant an author who correctly added a name to CLONE_COPIES got
  // a green suite and a clone that still dropped the column.
  const plan = {};
  for (const col of CLONE_COPIES) {
    plan[col] = src[col] === undefined ? null : src[col];
  }
  // The three the request may re-point, layered on top. Same client is allowed
  // — a different one is the point, but repetition on one client is legal too.
  plan.title = title;
  plan.profile_id = profileId;
  plan.engagement_type = engagementType;

  plan.copy_prereqs = copyPrereqs;
  plan.notices = notices;
  return plan;
}

// ── The vocabulary GET / ships to the browser ───────────────────────────────

/**
 * The server's frozen vocabulary, so the browser hand-writes no badge word and
 * cannot offer a release_state the CHECK constraint refuses. A wording change
 * then lands without any browser being right about a cached .js file.
 */
function vocabulary() {
  return {
    labels: {
      release: S.RELEASE_LABELS,
      access: S.ACCESS_LABELS,
      completion: S.COMPLETION_LABELS,
    },
    release_states: S.RELEASE_STATES,
    parts: Object.keys(PART_DEFINITIONS)
      .map(Number)
      .sort((a, b) => a - b)
      .map((n) => ({ number: n, name: getPartName(n) })),
  };
}

module.exports = {
  MAX_MODULES,
  TITLE_MAX,
  MODULE_COLUMNS,
  CLONE_COPIES,
  CLONE_RESETS,
  UUID_RE,
  engagementSlug,
  normalizeModuleInput,
  writeNotices,
  conflictingPartBinding,
  classifyPrereqCandidate,
  checkReorderShape,
  checkReorderMembership,
  reorderStatement,
  planClone,
  vocabulary,
};
