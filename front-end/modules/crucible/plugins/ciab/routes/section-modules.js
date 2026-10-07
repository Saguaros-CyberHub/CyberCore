/**
 * ============================================================================
 * CIAB Plugin — Section modules: the sequence an instructor authors
 * ============================================================================
 * Mounted at /api/instructor/sections/:sectionId/modules
 *
 * A MODULE is one client, one engagement and one place in a section's sequence.
 * It binds to its engagement by (profile_id, engagement_type) and to the
 * assessment by assessment_part, and nothing else.
 *
 *   GET    /                      the whole tab in one payload
 *   POST   /                      create, at the end of the sequence
 *   POST   /reorder               the full ordered id list, one statement
 *   PATCH  /:moduleId             edit
 *   DELETE /:moduleId             archive by default, ?hard=1 for an admin
 *   POST   /:moduleId/clone       SAME SHAPE, DIFFERENT CLIENT
 *   POST   /:moduleId/prereqs     add "this one follows that one"
 *   DELETE /:moduleId/prereqs/:prereqModuleId
 *
 * CLONE IS THE POINT OF THIS FILE. A term is many modules across many client
 * profiles; clone-a-module is what makes that repetition cheap, and it is why
 * cloned_from_module_id is written on every copy — that column is the only
 * input the cross-section repetition view has, and no later ALTER can backfill
 * it for a term that has already been taught.
 *
 * THE STUDENT'S VIEW OF THESE ROWS IS NOT HERE. Release, prerequisite and
 * completion resolution live in utils/module-spine.js and are projected to a
 * student on a different mount, by a different phase. There is deliberately no
 * ?as=student flag on this or any /api/instructor/* route: a query parameter
 * that flips a projection is one forgotten branch away from serving
 * instructor_notes and draft module ids to a student.
 *
 * A SIBLING MOUNT TO sections.js ON PURPOSE. That file owns
 * /:sectionId/students/:userId, and the literal verb /reorder here must never
 * have to out-race a /:moduleId pattern registered there — the same reason
 * section-roster.js is split out, and the reason cle/routes/api.js gives for
 * mounting its own /roster prefix first.
 *
 * AUTHORISATION, TWICE, DELIBERATELY:
 *   requireRole('instructor','admin')  are you staff at all
 *   getManagedSection(...)             may you touch THIS section
 * The second is admin-aware and answers "does it exist" and "may you" in one
 * call, so a route cannot accidentally answer the first without the second. A
 * module is then loaded WITH `AND section_id = $n`, so a module id belonging to
 * another section is a 404 rather than a leak.
 */

const express = require('express');

const router = express.Router({ mergeParams: true });

const { requireRole } = require('../../../../../src/middleware/auth');

const { query } = require('../utils/db');
const enrollment = require('../utils/enrollment');
const spine = require('../utils/module-spine');
const S = require('../utils/module-states');
const admin = require('../utils/module-admin');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * A FILE-LEVEL LITERAL. NEVER a request value: getManagedSection interpolates
 * `columns` into SQL on BOTH branches, and the non-admin branch additionally
 * does columns.split(',').map(c => 's.' + c.trim()).join(', ') — so a comma
 * inside an expression, or a bare function call, produces valid-looking SQL
 * that works for an admin (who takes the un-rewritten branch) and fails only
 * for an instructor, i.e. only in production. Plain column names only.
 */
const SECTION_COLUMNS = 'section_id, name, code, term, status, instructor_id';

/** The 17 columns spine.loadModules names, so every RETURNING row goes through
 *  spine.rowToModule's whitelist unchanged. */
const MODULE_COLUMNS = admin.MODULE_COLUMNS;

/** A term's sequence is authored by hand; the cap exists so a reorder cannot be
 *  handed ten thousand ids and so the deliberate absence of pagination is
 *  bounded by a refusal rather than by hope. Enforced INSIDE both INSERTs, so a
 *  section cannot race past it and become unreorderable. */
const MAX_MODULES = admin.MAX_MODULES;

/**
 * Instructor-only rewordings of two S.MESSAGE sentences. S.MESSAGE is ONE map
 * serving both reason.message (a student reads it) and issue.message (only an
 * instructor ever sees it), and these two say "your instructor" / "Ask your
 * instructor" — advice that reads as nonsense to the person who has to act.
 * Every other code passes through untouched, and so does an unknown one.
 */
const ISSUE_MESSAGE_OVERRIDE = Object.freeze({
  [S.ISSUE.PREREQ_CYCLE]:   'These modules require each other in a loop, so none of them can ever open. Remove one of the prerequisites.',
  [S.ISSUE.PREREQ_MISSING]: 'This module requires a module that is no longer in this section, so it can never open. Remove that prerequisite.',
});

/**
 * Facts about a REQUEST — what this write just did, or declined to do.
 * S.ISSUE stays for facts about the SECTION and keeps arriving in issues[].
 * Same { severity, code, message, module_id, detail } shape, so ONE browser
 * renderer draws both; two arrays, because one is transient and one persists.
 */
const NOTICE = Object.freeze({
  PREREQ_NOT_COPIED:    'PREREQ_NOT_COPIED',
  PREREQ_EDGES_REMOVED: 'PREREQ_EDGES_REMOVED',
  RELEASE_RESET:        'RELEASE_RESET',
  TITLE_TRUNCATED:      'TITLE_TRUNCATED',
  PREREQ_COPY_FAILED:   'PREREQ_COPY_FAILED',
});

const NOTICE_MESSAGE = Object.freeze({
  PREREQ_NOT_COPIED:    'Prerequisites were not copied: they name modules in the section this was cloned from. Set them again here.',
  PREREQ_EDGES_REMOVED: 'Modules that followed this one no longer have that prerequisite and are available now.',
  RELEASE_RESET:        'The copy was saved as a draft with no open or close time, so nobody sees it until you publish it.',
  TITLE_TRUNCATED:      'The title was shortened to fit.',
  PREREQ_COPY_FAILED:   'The prerequisites could not be copied. Add them on the new module.',
});

const NOTICE_SEVERITY = Object.freeze({
  PREREQ_NOT_COPIED:    'warning',
  PREREQ_EDGES_REMOVED: 'warning',
  RELEASE_RESET:        'info',
  TITLE_TRUNCATED:      'warning',
  PREREQ_COPY_FAILED:   'warning',
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * :sectionId arrives via the parent mount's res.locals (see routes/api.js).
 *
 * THE CHILD-MOUNT OPERAND ORDER, matching section-roster.js. Both channels are
 * needed: mergeParams for production, res.locals for a test that mounts this
 * router at a literal path carrying no :sectionId.
 */
const sectionIdOf = (req, res) => req.params.sectionId || res.locals.sectionId;

/**
 * 403 and a null return, so every call site is a bare `if (!section) return;`.
 *
 * IT SENDS THE RESPONSE ITSELF. A caller that writes `return res.status(403)…`
 * again double-sends and throws ERR_HTTP_HEADERS_SENT.
 *
 * There is NO 404 branch, ever: the refusal string is byte-identical to the one
 * sections.js and section-roster.js send, so section ids cannot be enumerated
 * by status code or by message. The `code` is additive, for the client.
 */
async function mustManage(req, res, columns = SECTION_COLUMNS) {
  const section = await enrollment.getManagedSection(sectionIdOf(req, res), req.user, columns);
  if (!section) {
    res.status(403).json({ error: 'Section not found or access denied', code: 'SECTION_NOT_MANAGED' });
    return null;
  }
  return section;
}

/**
 * A SECOND managed section, by explicit id, for a clone that crosses sections.
 * THE MOUNT'S GATE AUTHORISED THE SOURCE ONLY.
 *
 * IT TAKES THE ID EXPLICITLY. A helper that derived the id from
 * sectionIdOf(req, res) would re-authorise the SOURCE section — both
 * req.params.sectionId and the mount's res.locals.sectionId hold the source —
 * always pass, and let an instructor who manages A write a module into B.
 */
async function mustManageTarget(req, res, sectionId) {
  // A malformed target id is treated EXACTLY as an unmanaged one, with the
  // byte-identical string: getManagedSection's WHERE section_id = $1 runs against
  // a uuid column, so a non-uuid raises 22P02 and surfaces as a 500 where the
  // contract promises 403. Answering 403 here also keeps section ids
  // unenumerable — a distinct 400 would say "that one is at least well-formed".
  const target = admin.UUID_RE.test(String(sectionId == null ? '' : sectionId).trim())
    ? await enrollment.getManagedSection(sectionId, req.user, SECTION_COLUMNS)
    : null;
  if (!target) {
    res.status(403).json({ error: 'Section not found or access denied', code: 'TARGET_SECTION_NOT_MANAGED' });
    return null;
  }
  return target;
}

/** A module is NEVER loaded by id alone. The section predicate is what makes a
 *  module id from another section a 404 rather than a leak. */
async function mustModule(res, section, moduleId, columns = MODULE_COLUMNS) {
  // BEFORE THE QUERY, because $1::uuid raises 22P02 on anything that is not one
  // and 22P02 carries no `status`, so fail() answers a generic 500 for what is
  // simply a module that is not in this section. Same body, same code: a
  // malformed id must not be distinguishable from a foreign one.
  if (!admin.UUID_RE.test(String(moduleId == null ? '' : moduleId).trim())) {
    res.status(404).json({ error: 'That module is not in this section', code: 'MODULE_NOT_IN_SECTION' });
    return null;
  }
  const r = await query(
    `SELECT ${columns} FROM ciab_module WHERE module_id = $1::uuid AND section_id = $2::uuid`,
    [moduleId, section.section_id]
  );
  if (!r.rows[0]) {
    res.status(404).json({ error: 'That module is not in this section', code: 'MODULE_NOT_IN_SECTION' });
    return null;
  }
  return r.rows[0];
}

/** One entry of warnings[], in the same shape as an issue. */
function notice(code, moduleId = null, detail = null) {
  return {
    severity: NOTICE_SEVERITY[code] || 'warning',
    code,
    message: NOTICE_MESSAGE[code] || '',
    module_id: moduleId,
    detail,
  };
}

/**
 * Whatever module-admin hands back as a planned notice, rendered through the
 * maps above. A bare code string, a { code, detail } pair and an already-built
 * notice object are all accepted, so the two files cannot disagree about who
 * owns the sentence.
 */
function asNotice(entry) {
  if (!entry) return null;
  if (typeof entry === 'string') return notice(entry);
  if (entry.severity && entry.message) return entry;
  if (!entry.code) return null;
  return notice(entry.code, entry.module_id || null, entry.detail || null);
}

/** issues[] with the two instructor-voice rewordings applied. */
function overrideIssues(issues) {
  if (!Array.isArray(issues)) return [];
  return issues.map((issue) => (
    issue && ISSUE_MESSAGE_OVERRIDE[issue.code]
      ? { ...issue, message: ISSUE_MESSAGE_OVERRIDE[issue.code] }
      : issue
  ));
}

/**
 * Audit trail in clinic_db's own activity_log. BEST-EFFORT, NEVER AWAITED.
 *
 * A SIBLING of roster.logRosterActivity, never a reuse of it: that helper
 * hardcodes the `roster.` prefix and entity_type 'ciab_section', so calling it
 * would file `roster.module_created` against a section id — it reads as correct
 * in review and makes the trail unqueryable by module.
 *
 * activity_log.action_type is VARCHAR(50) with no CHECK enum, so the verbs
 * below need no migration; entity_id is a nullable UUID, and a reorder files
 * against the section because it is not about one module.
 *
 * Never awaited, with its own .catch: an awaited audit insert turns a transient
 * clinic_db hiccup into a failed reorder that the instructor reads as data
 * loss. `detail` carries IDS, COUNTS AND ENUM VALUES ONLY — nothing mechanical
 * catches a credential put in here, because the audit-hygiene scanner matches
 * the shared audit helpers by name and this one escapes it.
 */
function logModuleActivity({ actorId, sectionId, moduleId = null, action, detail = {} }) {
  return query(
    `INSERT INTO activity_log (user_id, action_type, entity_type, entity_id, metadata)
     VALUES ($1::uuid, $2::varchar, $3::varchar, $4::uuid, $5::jsonb)`,
    [
      actorId,
      `module.${action}`,
      moduleId ? 'ciab_module' : 'ciab_section',
      moduleId || sectionId,
      JSON.stringify({ section_id: sectionId, module_id: moduleId, ...detail }),
    ]
  ).catch((err) => console.warn(`[CIAB] Could not log module activity: ${err.message}`));
}

/**
 * A thrown { status } reaches the client as its own sentence; anything else is
 * a fixed 500. NEVER `error` itself, never a stack, and never error.message in
 * a 500 body — a client cannot act on it and it can name internals.
 */
function fail(res, error, verb, sentence) {
  if (error && error.status) {
    return res.status(error.status).json({
      error: error.message,
      ...(error.code ? { code: error.code } : {}),
    });
  }
  console.error(`[CIAB] ${verb}:`, error && error.message);
  return res.status(500).json({ error: sentence });
}

/** ?hard=1 / ?confirm=1, in the shape sections.js already accepts. */
const flag = (v) => v === '1' || v === 'true';

const PART_COLLISION = 'Another module in this section already uses that client and that assessment part. '
  + 'The two would complete each other.';

/**
 * THE SAME REFUSAL, WHEN THE CLASHING ROW IS THE SOURCE ITSELF — the default path
 * of the headline feature.
 *
 * A same-section clone counts the target's modules, and the target CONTAINS the
 * source, so a source that holds both a client and a Deliverable collides with
 * itself the moment the copy inherits both. PART_COLLISION's sentence names
 * "another module" and offers no remedy, so it reads as a server bug on the
 * exact click the tab exists to make cheap. The rule is genuinely real —
 * assessment_progress is UNIQUE (user_id, profile_id, part_number) with no
 * section column — so the refusal stays and only the sentence changes.
 */
const PART_COLLISION_WITH_SOURCE = 'This module already holds that deliverable for that client, and two modules '
  + 'cannot share one. Pick a different client for the copy — that is what cloning is for.';

// ---------------------------------------------------------------------------
// ROUTE ORDER: LITERALS BEFORE PATTERNS.
// /reorder is registered above /:moduleId so a future GET /reorder cannot be
// swallowed by a router.get('/:moduleId'). express.json() is applied PER
// body-carrying ROUTE and never router.use()d: src/server.js already parses
// every /api body, so this is belt-and-braces that keeps the router working
// when it is mounted standalone, which is how the tests drive it.
// ---------------------------------------------------------------------------

// GET / — the whole Modules tab in one payload
router.get('/', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    // ORDERING IS LOAD-BEARING. instructorSectionView calls loadSectionForStaff,
    // which performs NO authorization — its JSDoc says so and its signature does
    // not. It must never run before mustManage has returned non-null, or any
    // instructor reads any section's instructor_notes, module list and roster
    // rollup.
    const view = await spine.instructorSectionView(section.section_id, { now: Date.now() });
    if (!view) {
      // A concurrent delete between the two reads. Same string, so the answer
      // still cannot be used to tell "gone" from "not yours".
      return res.status(403).json({ error: 'Section not found or access denied', code: 'SECTION_NOT_MANAGED' });
    }

    // The union is required: GET /api/profiles is scoped to the caller's own
    // rows, so without the second disjunct a co-instructor sees a raw uuid where
    // a bound client's name belongs — and the edit modal's <select> cannot
    // re-select the current client, so saving a title change would write a null
    // profile_id and silently unbind the module. The disjunct is SECTION-SCOPED:
    // it resolves only clients already bound in a section this caller manages.
    const clients = await query(
      `SELECT id, company_name, client_type_name, industry, difficulty, hq_city
         FROM profiles
        WHERE user_id = $1::uuid
           OR id IN (SELECT profile_id FROM ciab_module
                      WHERE section_id = $2::uuid AND profile_id IS NOT NULL)
        ORDER BY company_name
        LIMIT 500`,
      [req.user.userId, section.section_id]
    );

    res.json({
      ...view,
      issues: overrideIssues(view.issues),
      clients: clients.rows,
      // labels / release_states / parts: the server's frozen vocabulary, so the
      // browser hand-writes no badge word and cannot offer a release_state the
      // CHECK constraint refuses.
      ...admin.vocabulary(),
      // The Delete control is rendered from this. The UI must never infer
      // "am I an admin" and offer a control the API refuses.
      capabilities: { hard_delete: req.user.role === 'admin' },
      warnings: [],
    });
  } catch (error) {
    fail(res, error, 'list modules', 'Failed to load modules');
  }
});

// POST / — create, at the end of the sequence
router.post('/', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    // Throws { status: 400, code } on any refusal, which fail() answers verbatim.
    const { values } = admin.normalizeModuleInput(req.body, { partial: false });
    const candidate = Object.fromEntries(values);

    // PURE, over the array loadModules already returned — no extra round trip
    // and no SQL. assessment_progress is UNIQUE (user_id, profile_id,
    // part_number) with no section, so two modules on one client and one part
    // would complete each other.
    const modules = await spine.loadModules(section.section_id);
    const clash = admin.conflictingPartBinding(modules, candidate);
    if (clash) {
      return res.status(409).json({
        error: PART_COLLISION,
        code: 'ASSESSMENT_PART_COLLISION',
        conflict: { module_id: clash.module_id, title: clash.title },
      });
    }

    // A FROM-less SELECT, so it produces exactly one row unless the cap
    // predicate is false — which makes rowCount === 0 UNAMBIGUOUS proof that the
    // cap fired rather than that a source row was missing. Position is computed
    // inside the statement: no read-then-write race and no second query.
    //
    // EVERY PARAMETER IS CAST AT ITS FIRST REFERENCE. sections.js uses a VALUES
    // list, where a parameter's type resolves from the target column; in a
    // SELECT output list it does not, and an uncast null profile_id or
    // assessment_part fails Parse with 42P18. $11 is reused for created_by and
    // updated_by, exactly as sections.js reuses $5.
    const ins = await query(
      `INSERT INTO ciab_module
         (section_id, position, title, brief, instructor_notes, profile_id,
          engagement_type, assessment_part, release_state, release_at, close_at,
          created_by, updated_by)
       SELECT $1::uuid,
              COALESCE((SELECT MAX(position) FROM ciab_module WHERE section_id = $1::uuid), 0) + 1,
              $2::varchar, $3::text, $4::text, $5::uuid, $6::varchar, $7::int,
              $8::varchar, $9::timestamptz, $10::timestamptz, $11::uuid, $11::uuid
        WHERE (SELECT COUNT(*) FROM ciab_module WHERE section_id = $1::uuid) < ${MAX_MODULES}
       RETURNING ${MODULE_COLUMNS}`,
      [
        section.section_id,
        candidate.title,
        candidate.brief,
        candidate.instructor_notes,
        candidate.profile_id,
        candidate.engagement_type,
        candidate.assessment_part,
        candidate.release_state,
        candidate.release_at,
        candidate.close_at,
        req.user.userId,
      ]
    );
    if (!ins.rowCount) {
      return res.status(409).json({
        error: `A section is limited to ${MAX_MODULES} modules.`,
        code: 'SECTION_MODULE_LIMIT',
      });
    }

    const module = spine.rowToModule(ins.rows[0]);
    logModuleActivity({
      actorId: req.user.userId,
      sectionId: section.section_id,
      moduleId: module.module_id,
      action: 'created',
      detail: {
        release_state: module.release_state,
        profile_id: module.profile_id,
        assessment_part: module.assessment_part,
      },
    });

    // 'scheduled' with no date, and a close time on or before the release time,
    // are ACCEPTED — migration 014 ships no CHECK for either on purpose, and
    // refusing them would break correcting an inverted window in two PATCHes.
    // Each is echoed back at the moment it is caused as well as persisting in
    // issues[].
    // Object.entries(module), NOT `values`: `values` is the normalized
    // [column, value] pair list and carries no module_id, so writeNotices set
    // module_id null and the browser titled the toast 'This section' — blaming
    // the whole section for a defect in one module, while the resolver's issues[]
    // named the module correctly on the very next repaint. PATCH and clone
    // already pass the identified row; this is the one that did not.
    res.status(201).json({ module, warnings: admin.writeNotices(Object.entries(module)) });
  } catch (error) {
    if (error && error.code === '23503') {
      return res.status(409).json({
        error: 'That client no longer exists. Pick another, or leave the module unbound.',
        code: 'CLIENT_GONE',
      });
    }
    fail(res, error, 'create module', 'Failed to create the module');
  }
});

// POST /reorder — the FULL ordered id list, applied in one statement
router.post('/reorder', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    // DB-FREE, AND FIRST. A hostile payload never builds a placeholder list, and
    // a non-uuid never reaches the ::uuid cast, where it would raise 22P02 and
    // surface as a 500. Ids are lower-cased here, because PostgreSQL renders
    // uuid in lowercase canonical form and the owned set is built from rows.
    const shape = admin.checkReorderShape((req.body || {}).order);
    if (!shape.ok) {
      return res.status(400).json({
        error: shape.error,
        code: shape.code,
        ...(shape.detail || {}),
      });
    }
    const ids = shape.ids;

    // THE MEMBERSHIP CHECK PRECEDES THE WRITE, and it has to: the statement's
    // section predicate silently SKIPS an id the section does not own, so
    // inspecting rowCount afterwards is too late — the update has half-applied.
    const modules = await spine.loadModules(section.section_id);
    const ownedIds = modules.map((m) => String(m.module_id).toLowerCase());

    // 409, not 400: the request was well-formed and merely lost a race with a
    // co-instructor, and the client must be able to tell the two apart in one
    // round trip. The canonical current order is echoed back so it can resync
    // without a second GET.
    const membership = admin.checkReorderMembership(ids, ownedIds);
    if (!membership.ok) return res.status(409).json(membership.body);

    // The expected count is computed HERE, from the same read, because the
    // statement's `position IS DISTINCT FROM v.pos` predicate means rowCount can
    // no longer be used as a membership check.
    const positionById = new Map(modules.map((m) => [String(m.module_id).toLowerCase(), m.position]));
    let expected = 0;
    for (let i = 0; i < ids.length; i += 1) {
      if (positionById.get(ids[i]) !== i + 1) expected += 1;
    }

    // ONE statement, atomic without a transaction, scoped by section_id — the
    // statement migration 014's header documents, plus two named additions:
    // `updated_by` (attribution on a row 014 forbids a trigger from maintaining)
    // and `position IS DISTINCT FROM v.pos` (an honest updated_at and a
    // meaningful `moved` count). Nothing in this plugin calls pool.connect(), so
    // a second statement would have no rollback. Built by module-admin so its
    // exact text is assertable with no HTTP server.
    const stmt = admin.reorderStatement(section.section_id, req.user.userId, ids);
    const wrote = await query(stmt.text, stmt.params);

    if (wrote.rowCount !== ids.length) {
      // A concurrent delete: the statement now touches EVERY named row, so a
      // short rowCount means a row named in the order no longer exists. The
      // survivors are still correctly renumbered, so this is a 200 with a log
      // line, not a 409 the instructor cannot act on.
      console.warn(`[CIAB] reorder wrote ${wrote.rowCount} of ${ids.length} rows in section ${section.section_id}`);
    }

    logModuleActivity({
      actorId: req.user.userId,
      sectionId: section.section_id,
      action: 'reordered',
      detail: { count: ids.length, moved: expected },
    });

    // `moved` is the JS-computed count, never rowCount: the statement no longer
    // carries `position IS DISTINCT FROM v.pos` (dropping it is what preserves
    // last-write-wins under READ COMMITTED — see reorderStatement's header), so
    // rowCount is now n and says nothing about how much actually moved.
    res.json({ success: true, order: ids, moved: expected, warnings: [] });
  } catch (error) {
    fail(res, error, 'reorder modules', 'Failed to reorder the modules');
  }
});

// PATCH /:moduleId — edit. PATCH, not PUT: PUT in this plugin means whole
// document replacement, and on a module that would make "clear the client
// binding" indistinguishable from "do not touch the client binding".
router.patch('/:moduleId', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    const body = req.body || {};

    // REFUSED, NOT SILENTLY IGNORED: a 200 on an ignored key makes the client
    // believe the write happened. A second writer for position would destroy the
    // single-statement reorder's guarantee, and a section move is a 23503 by
    // construction (migration 014's accepted side effect).
    if (body.position !== undefined) {
      return res.status(400).json({
        error: 'position is set by reordering the section, not by editing one module',
        code: 'POSITION_NOT_EDITABLE',
      });
    }
    if (body.section_id !== undefined) {
      return res.status(400).json({
        error: 'A module cannot be moved between sections. Clone it into the other section and delete this one.',
        code: 'SECTION_NOT_EDITABLE',
      });
    }

    const module = await mustModule(res, section, req.params.moduleId);
    if (!module) return;

    // Only keys actually present in the body, so an explicit null clears and an
    // absent key is untouched. module_id, cloned_from_module_id, created_by and
    // the timestamps are silently ignored: identity and provenance are not user
    // data.
    const { values } = admin.normalizeModuleInput(body, { partial: true });
    if (!values.length) {
      return res.status(400).json({ error: 'Nothing to update', code: 'NOTHING_TO_UPDATE' });
    }

    const patch = Object.fromEntries(values);
    const merged = { ...module, ...patch };

    if (patch.profile_id !== undefined || patch.assessment_part !== undefined) {
      const modules = await spine.loadModules(section.section_id);
      const clash = admin.conflictingPartBinding(modules, merged);
      if (clash) {
        return res.status(409).json({
          error: PART_COLLISION,
          code: 'ASSESSMENT_PART_COLLISION',
          conflict: { module_id: clash.module_id, title: clash.title },
        });
      }
    }

    // The column name inside set() is ALWAYS a hardcoded literal drawn from
    // `values`, never a request key. No casts needed: in `SET col = $n` the
    // parameter's type resolves from the target column.
    const sets = [];
    const params = [];
    const set = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };

    for (const [col, val] of values) set(col, val);

    // Both written by code: there is not one CREATE TRIGGER in any plugin
    // migration in this tree. They come AFTER the NOTHING_TO_UPDATE refusal, or
    // an empty PATCH would silently bump the timestamp.
    set('updated_by', req.user.userId);
    set('updated_at', new Date());

    params.push(module.module_id, section.section_id);

    const upd = await query(
      `UPDATE ciab_module SET ${sets.join(', ')}
        WHERE module_id = $${params.length - 1} AND section_id = $${params.length}
       RETURNING ${MODULE_COLUMNS}`,
      params
    );

    // A LOST RACE, NOT A SUCCESS. mustModule saw the row; an admin hard-delete
    // between that SELECT and this UPDATE leaves rowCount 0, and rowToModule
    // returns null for a falsy row — so without this the instructor is told
    // 'Saved' about a module that no longer exists and an audit row is filed for
    // a write that never happened. Same refusal mustModule would have sent, and
    // it comes BEFORE the audit call.
    if (!upd.rowCount) {
      return res.status(404).json({ error: 'That module is not in this section', code: 'MODULE_NOT_IN_SECTION' });
    }

    logModuleActivity({
      actorId: req.user.userId,
      sectionId: section.section_id,
      moduleId: module.module_id,
      action: 'updated',
      detail: { fields: values.map(([col]) => col) },
    });

    res.json({
      module: spine.rowToModule(upd.rows[0]),
      warnings: admin.writeNotices(Object.entries(merged)),
    });
  } catch (error) {
    if (error && error.code === '23503') {
      return res.status(409).json({
        error: 'That client no longer exists. Pick another, or leave the module unbound.',
        code: 'CLIENT_GONE',
      });
    }
    fail(res, error, 'update module', 'Failed to update the module');
  }
});

// DELETE /:moduleId?hard=1&confirm=1 — archive by default
router.delete('/:moduleId', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    const module = await mustModule(res, section, req.params.moduleId,
      'module_id, section_id, title, release_state');
    if (!module) return;

    // One query, served by idx_ciab_module_prereq_requires. The edge carries
    // section_id and both its foreign keys are composite, so a row naming this
    // module as a prerequisite can only belong to this section.
    const dependents = await query(
      `SELECT p.module_id, m.title
         FROM ciab_module_prereq p
         JOIN ciab_module m ON m.module_id = p.module_id AND m.section_id = p.section_id
        WHERE p.prereq_module_id = $1::uuid`,
      [module.module_id]
    );
    const dependentCount = dependents.rowCount;

    const hard = flag(req.query.hard);
    const confirmed = flag(req.query.confirm);

    // THE REFUSAL IS ENFORCED SERVER-SIDE ON BOTH PATHS, not only in the
    // browser's Confirm — a script, a retry or a future bulk action must hit the
    // same wall. Two opposite messages, because the consequences are opposite:
    // archiving a prerequisite LOCKS everything that follows it for the whole
    // roster, while deleting it removes the edges and OPENS them immediately.
    const dependentsRefusal = (message) => res.status(409).json({
      error: message,
      code: 'MODULE_HAS_DEPENDENTS',
      required_by: dependents.rows,
    });

    if (hard) {
      // Three gates, IN THIS ORDER.
      if (req.user.role !== 'admin') {
        // An instructor's remedy is Archive, which is also the better one.
        return res.status(403).json({
          error: 'Only an administrator can delete a module outright',
          code: 'ADMIN_ONLY',
        });
      }

      const records = await query(
        `SELECT 1 FROM ciab_module_student WHERE module_id = $1::uuid LIMIT 1`,
        [module.module_id]
      );
      if (records.rowCount) {
        // NO confirm override. Archiving is the only removal that keeps the rows
        // the grading phase reads.
        return res.status(409).json({
          error: 'This module has student records against it. Archive it instead — archiving keeps every completion and override.',
          code: 'MODULE_HAS_STUDENT_RECORDS',
        });
      }

      if (dependentCount && !confirmed) {
        return dependentsRefusal(
          `${dependentCount} module(s) follow this one. Deleting it removes those prerequisites, `
          + 'so they become available immediately. Archive it instead, or confirm to delete anyway.'
        );
      }

      await query(
        `DELETE FROM ciab_module WHERE module_id = $1::uuid AND section_id = $2::uuid`,
        [module.module_id, section.section_id]
      );

      logModuleActivity({
        actorId: req.user.userId,
        sectionId: section.section_id,
        moduleId: module.module_id,
        action: 'deleted',
        detail: { release_state: module.release_state, dependents_removed: dependentCount },
      });

      // Every response carries a JSON body, DELETE included: API.request parses
      // one unconditionally, so a 204 surfaces to the UI as a network error on a
      // request that in fact succeeded.
      return res.json({
        success: true,
        archived: false,
        module: null,
        deleted_module_id: module.module_id,
        warnings: dependentCount
          ? [notice(NOTICE.PREREQ_EDGES_REMOVED, module.module_id, { count: dependentCount })]
          : [],
      });
    }

    if (dependentCount && !confirmed) {
      return dependentsRefusal(
        `${dependentCount} module(s) follow this one and will be locked for the whole roster `
        + 'while it is archived. Remove those prerequisites first, or confirm to archive anyway.'
      );
    }

    // SOFT ARCHIVE is the default. It is the only removal that keeps the
    // per-student completion rows, and it keeps the prerequisite edges.
    const upd = await query(
      `UPDATE ciab_module SET release_state = 'archived', updated_at = now(), updated_by = $3::uuid
        WHERE module_id = $1::uuid AND section_id = $2::uuid
       RETURNING ${MODULE_COLUMNS}`,
      [module.module_id, section.section_id, req.user.userId]
    );

    // The same lost race as PATCH, and for the same reason: nothing between
    // mustModule's SELECT and this UPDATE holds a lock.
    if (!upd.rowCount) {
      return res.status(404).json({ error: 'That module is not in this section', code: 'MODULE_NOT_IN_SECTION' });
    }

    logModuleActivity({
      actorId: req.user.userId,
      sectionId: section.section_id,
      moduleId: module.module_id,
      action: 'archived',
      detail: { previous_release_state: module.release_state, dependents: dependentCount },
    });

    res.json({
      success: true,
      archived: true,
      module: spine.rowToModule(upd.rows[0]),
      warnings: [],
    });
  } catch (error) {
    fail(res, error, 'remove module', 'Failed to remove the module');
  }
});

// POST /:moduleId/clone — SAME SHAPE, DIFFERENT CLIENT. The repetition
// mechanism the whole programme is built on.
router.post('/:moduleId/clone', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    const source = await mustModule(res, section, req.params.moduleId);
    if (!source) return;

    const body = req.body || {};

    const requestedTarget = body.target_section_id === undefined
      || body.target_section_id === null
      || body.target_section_id === ''
      ? section.section_id
      : String(body.target_section_id);
    const crossSection = String(requestedTarget).toLowerCase() !== String(section.section_id).toLowerCase();

    // THE MOUNT'S GATE AUTHORISED THE SOURCE ONLY, so a cross-section clone
    // authorises the target independently, by explicit id, before any write.
    let target = section;
    if (crossSection) {
      target = await mustManageTarget(req, res, requestedTarget);
      if (!target) return;
    }

    // Forces a draft with no window whatever the source was and whatever the
    // body asks for; re-points client and engagement from the body when present
    // and inherits them otherwise; drops prerequisite copying unconditionally
    // when the target is a different section.
    const plan = admin.planClone(source, body, { crossSection });

    // Counted in the TARGET, because that is where the row lands.
    const targetModules = await spine.loadModules(target.section_id);
    const clash = admin.conflictingPartBinding(targetModules, {
      module_id: null,
      profile_id: plan.profile_id,
      assessment_part: plan.assessment_part,
    });
    if (clash) {
      // A same-section clone counts the target's modules and the target CONTAINS
      // the source, so the row it collides with is very often the source itself.
      // Saying "another module" there names nothing the instructor can act on.
      const isSource = String(clash.module_id).toLowerCase() === String(source.module_id).toLowerCase();
      return res.status(409).json({
        error: isSource ? PART_COLLISION_WITH_SOURCE : PART_COLLISION,
        code: 'ASSESSMENT_PART_COLLISION',
        conflict: { module_id: clash.module_id, title: clash.title, is_source: isSource },
      });
    }

    // How many edges the caller asked to bring across, so a cross-section clone
    // can honestly report what it declined to copy. Read only when asked.
    let prereqsRequested = 0;
    if (plan.copy_prereqs || plan.notices.some((n) => (typeof n === 'string' ? n : n && n.code) === NOTICE.PREREQ_NOT_COPIED)) {
      const counted = await query(
        `SELECT COUNT(*)::int AS n FROM ciab_module_prereq
          WHERE section_id = $1::uuid AND module_id = $2::uuid`,
        [section.section_id, source.module_id]
      );
      prereqsRequested = counted.rows[0].n;
    }

    // The release columns are LITERALS. No request-body value can reach them: a
    // clone that inherited 'open' would publish an unreviewed copy to the whole
    // roster the instant it was written.
    //
    // $8 IS THE SOURCE'S OWN module_id, never the source's cloned_from_module_id
    // — copying that would flatten the chain and lose a generation. This is the
    // one fact no later ALTER can backfill; without it the repetition view is
    // permanently blind for every module cloned this term.
    //
    // The position is computed inside the statement against the TARGET section,
    // and the cap predicate makes rowCount === 0 unambiguous, exactly as on
    // create. Every parameter is cast at its first reference.
    const ins = await query(
      `INSERT INTO ciab_module
         (section_id, position, title, brief, instructor_notes, profile_id,
          engagement_type, assessment_part, release_state, release_at, close_at,
          cloned_from_module_id, created_by, updated_by)
       SELECT $1::uuid,
              COALESCE((SELECT MAX(position) FROM ciab_module WHERE section_id = $1::uuid), 0) + 1,
              $2::varchar, $3::text, $4::text, $5::uuid, $6::varchar, $7::int,
              'draft', NULL::timestamptz, NULL::timestamptz,
              $8::uuid, $9::uuid, $9::uuid
        WHERE (SELECT COUNT(*) FROM ciab_module WHERE section_id = $1::uuid) < ${MAX_MODULES}
       RETURNING ${MODULE_COLUMNS}`,
      [
        target.section_id,
        plan.title,
        plan.brief,
        plan.instructor_notes,
        plan.profile_id,
        plan.engagement_type,
        plan.assessment_part,
        source.module_id,
        req.user.userId,
      ]
    );
    if (!ins.rowCount) {
      return res.status(409).json({
        error: `A section is limited to ${MAX_MODULES} modules.`,
        code: 'SECTION_MODULE_LIMIT',
      });
    }

    const module = spine.rowToModule(ins.rows[0]);

    const warnings = [];
    const seenNotice = new Set();
    const addNotice = (entry) => {
      const built = asNotice(entry);
      if (!built || seenNotice.has(built.code)) return;
      seenNotice.add(built.code);
      warnings.push(built);
    };

    // The route owns this one: the literals above are what reset the release.
    addNotice(notice(NOTICE.RELEASE_RESET, module.module_id, null));
    for (const entry of plan.notices || []) addNotice(entry);

    // THE MODULE IS WRITTEN BEFORE THE EDGES, and an edge failure is a 201 with
    // a warning rather than a 500. There is no transaction; a 500 after the
    // module row is committed tells the instructor nothing happened, and they
    // clone twice.
    let prereqsCopied = 0;
    if (plan.copy_prereqs) {
      try {
        // ONE statement. Expressing the remap in SQL rather than through a
        // JavaScript id array makes the mis-remapped-edge class of bug
        // unwritable. Only the REQUIRES edges: copying the dependents would gate
        // the whole rest of the term on brand-new draft work.
        const copied = await query(
          `INSERT INTO ciab_module_prereq (section_id, module_id, prereq_module_id, created_by)
           SELECT $1::uuid, $2::uuid, p.prereq_module_id, $3::uuid
             FROM ciab_module_prereq p
            WHERE p.section_id = $1::uuid AND p.module_id = $4::uuid
           ON CONFLICT (module_id, prereq_module_id) DO NOTHING`,
          [target.section_id, module.module_id, req.user.userId, source.module_id]
        );
        prereqsCopied = copied.rowCount;
      } catch (edgeError) {
        console.error('[CIAB] copy module prerequisites:', edgeError.message);
        addNotice(notice(NOTICE.PREREQ_COPY_FAILED, module.module_id, null));
      }
    }

    logModuleActivity({
      actorId: req.user.userId,
      sectionId: target.section_id,
      moduleId: module.module_id,
      action: 'cloned',
      detail: {
        cloned_from_module_id: source.module_id,
        source_section_id: section.section_id,
        prereqs_copied: prereqsCopied,
        prereqs_requested: prereqsRequested,
      },
    });

    res.status(201).json({
      module,
      source: { section_id: section.section_id, module_id: source.module_id },
      prereqs_copied: prereqsCopied,
      prereqs_requested: prereqsRequested,
      warnings: warnings.concat(admin.writeNotices(Object.entries(module))),
    });
  } catch (error) {
    if (error && error.code === '23503') {
      return res.status(409).json({
        error: 'That client no longer exists. Pick another, or leave the module unbound.',
        code: 'CLIENT_GONE',
      });
    }
    fail(res, error, 'clone module', 'Failed to clone the module');
  }
});

// POST /:moduleId/prereqs — "this module follows that one"
router.post('/:moduleId/prereqs', instructorOnly, express.json(), async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    const raw = (req.body || {}).prereq_module_id;
    const prereqModuleId = raw === undefined || raw === null ? '' : String(raw).trim();
    if (!prereqModuleId) {
      return res.status(400).json({
        error: 'A prerequisite module id is required',
        code: 'PREREQ_REQUIRED',
      });
    }

    const [modules, edges] = await Promise.all([
      spine.loadModules(section.section_id),
      spine.loadPrereqEdges(section.section_id),
    ]);

    // Holds three refusals the database would otherwise turn into a 500 or a
    // silent lock: the self-edge the CHECK constraint would answer with 23514;
    // an endpoint outside this section, which the composite foreign key would
    // answer with 23503 and which the cycle check does NOT cover (a dangling
    // edge is classed as dangling, not cyclic); and the cycle itself, decided as
    // a BEFORE/AFTER DIFF rather than the bare "is anything cyclic" recipe —
    // buildGraph marks everything DOWNSTREAM of a cycle as cyclic too, so on an
    // already-broken section the bare recipe would refuse every unrelated edge
    // and name the wrong module, the wrong edge and the wrong remedy.
    const verdict = admin.classifyPrereqCandidate({
      modules,
      edges,
      moduleId: req.params.moduleId,
      prereqModuleId,
    });
    if (!verdict.ok) {
      return res.status(verdict.status).json({
        error: verdict.error,
        code: verdict.code,
        ...(verdict.detail ? { detail: verdict.detail } : {}),
      });
    }

    // THE IDS THE VERDICT ACTUALLY JUDGED, lower-cased by classifyPrereqCandidate
    // — never req.params.moduleId and never the raw body value. buildGraph keys
    // its map with PostgreSQL's lowercase canonical uuid, so a candidate edge in
    // any other case is dropped from the graph and the cycle check passes; writing
    // the raw values would then commit the loop it just approved.
    const gatedId = verdict.moduleId;
    const prereqId = verdict.prereqModuleId;

    // The ON CONFLICT target is the PRIMARY KEY. Naming three columns would be a
    // 42P10 — there is no unique index on the triple.
    const ins = await query(
      `INSERT INTO ciab_module_prereq (section_id, module_id, prereq_module_id, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)
       ON CONFLICT (module_id, prereq_module_id) DO NOTHING`,
      [section.section_id, gatedId, prereqId, req.user.userId]
    );
    const created = ins.rowCount > 0;

    const requires = edges
      .filter((e) => String(e.module_id).toLowerCase() === gatedId)
      .map((e) => String(e.prereq_module_id));
    if (!requires.some((id) => id.toLowerCase() === prereqId)) {
      requires.push(prereqId);
    }

    logModuleActivity({
      actorId: req.user.userId,
      sectionId: section.section_id,
      moduleId: gatedId,
      action: 'prereq_added',
      detail: { prereq_module_id: prereqId, created },
    });

    // An edge that already existed is idempotent, not an error.
    res.status(created ? 201 : 200).json({
      success: true,
      created,
      requires,
      warnings: [],
    });
  } catch (error) {
    if (error && error.code === '23503') {
      // UNREACHABLE given the in-section check above, so if it fires the design
      // has a bug and a generic 500 would destroy the only signal that says so.
      console.error('[CIAB] add prerequisite crossed a section boundary:', error.message);
      return res.status(409).json({
        error: 'Both ends of a prerequisite must be modules in this section.',
        code: 'PREREQ_CROSS_SECTION',
      });
    }
    fail(res, error, 'add prerequisite', 'Failed to add the prerequisite');
  }
});

// DELETE /:moduleId/prereqs/:prereqModuleId
router.delete('/:moduleId/prereqs/:prereqModuleId', instructorOnly, async (req, res) => {
  try {
    const section = await mustManage(req, res, 'section_id');
    if (!section) return;

    // No mustModule: section_id is in the WHERE, so a foreign id deletes nothing
    // and answers 404. Removing an edge cannot create a cycle, so there is no
    // check — and this deliberately does NOT re-validate that the prerequisite
    // module still exists, because it is the only way to clear the dangling edge
    // that PREREQ_MISSING is reporting.
    //
    // BOTH path params are shape-checked first: each binds to a $n::uuid, and a
    // malformed one raises 22P02, which carries no `status` and so surfaces as a
    // generic 500 instead of the 404 this route already has a sentence for.
    const shaped = (v) => admin.UUID_RE.test(String(v == null ? '' : v).trim());
    if (!shaped(req.params.moduleId) || !shaped(req.params.prereqModuleId)) {
      return res.status(404).json({
        error: 'That module does not require the one you are removing',
        code: 'PREREQ_EDGE_NOT_FOUND',
      });
    }

    const removed = await query(
      `DELETE FROM ciab_module_prereq
        WHERE section_id = $1::uuid AND module_id = $2::uuid AND prereq_module_id = $3::uuid`,
      [section.section_id, req.params.moduleId, req.params.prereqModuleId]
    );
    if (!removed.rowCount) {
      return res.status(404).json({
        error: 'That module does not require the one you are removing',
        code: 'PREREQ_EDGE_NOT_FOUND',
      });
    }

    logModuleActivity({
      actorId: req.user.userId,
      sectionId: section.section_id,
      moduleId: req.params.moduleId,
      action: 'prereq_removed',
      detail: { prereq_module_id: req.params.prereqModuleId },
    });

    res.json({ success: true, warnings: [] });
  } catch (error) {
    fail(res, error, 'remove prerequisite', 'Failed to remove the prerequisite');
  }
});

module.exports = router;
