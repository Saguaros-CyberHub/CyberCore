/**
 * CLE Plugin — Blue-team board (CYBR 400)
 * Mounted at /api/cle/courses/:courseId/incidents
 * ============================================================================
 * The defensive half of the Attack Console. An instructor fires an intrusion
 * into every lane in the course; this is where the student records what they
 * concluded from hunting it, and where the instructor grades that.
 *
 * THIS FILE IS THIN ON PURPOSE. It answers exactly two questions — WHO is
 * asking, and WHICH scope are they asking about — and hands everything else to
 * src/incident/board.js, which is shared with the CiAB plugin. The board's SQL,
 * its projection, its scorer and its release gate exist once. cle_attack_run's
 * NOT NULL FK to cle_course is what this codebase looks like after the same
 * machinery has been written twice.
 *
 * ── The four contract notes, all of which are repeat bug classes here ────────
 *
 *   1. EVERY :runId READ IS SCOPED. board.readRunFor*() takes
 *      (run_id, scope_type, scope_id) and returns null for BOTH "no such run"
 *      and "not this course's run", which becomes the SAME 404. routes/labs.js
 *      documents the identical guard for :labId, and routes/attacks.js for its
 *      own :runId — it is a repeated defect in this plugin, not a hypothetical.
 *      A 403 here would confirm a run exists in another course, which across a
 *      department is an enumerable oracle.
 *
 *   2. /status IS NAMED /status ON PURPOSE. src/server.js exempts GETs matching
 *      /\/status$/ from the global API rate limiter, and the board polls while
 *      a run is in flight. Instructors are not admins, so without the exemption
 *      a class-length exercise would exhaust their bucket and start 429ing.
 *
 *   3. THE blue_team FEATURE GATE COVERS WRITES ONLY. Reads and /status stay
 *      open on a course that has since disabled the tab — the same doctrine
 *      attacks.js states for attack_console, and for a stronger reason here:
 *      findings are GRADED WORK. Gating reads would make a student's own
 *      submissions unreachable because an instructor unticked a checkbox, and
 *      would hide the record of an exercise that really happened. Disabling a
 *      feature stops new work; it does not retroactively unmake old work.
 *
 *      AND IT IS isFeatureEnabled(), NOT the requireCourseFeature middleware.
 *      That middleware resolves the course through getManagedCourse(), which
 *      returns null for anybody who does not MANAGE the course — so mounting it
 *      here would 404 every STUDENT write on a perfectly enabled board. It is a
 *      staff gate; routes/my-courses.js already reads the flag directly for the
 *      same reason. The course row this file resolves per request already
 *      carries `features`, so checking it costs nothing extra.
 *
 *   4. A STUDENT'S TIER IS DECIDED SERVER-SIDE, PER REQUEST. There is no
 *      "am I staff" flag in the body and none in the JWT beyond the role. An
 *      instructor of ANOTHER course is not staff here; they fall through to the
 *      enrollment check like anyone else, and out to a 404 if they are not in
 *      this course either.
 * ============================================================================
 */

const express = require('express');
const router = express.Router({ mergeParams: true });

const { query } = require('../utils/db');
const { getManagedCourse } = require('../utils/course-access');
const { isFeatureEnabled } = require('../utils/course-features');
const audit = require('../../../../../src/utils/audit');
const board = require('../../../../../src/incident/board');
const projection = require('../../../../../src/incident/projection');

/** Course id arrives via mergeParams; the res.locals shim in api.js is a backstop. */
function courseIdOf(req, res) {
  return req.params.courseId || res.locals.courseId;
}

/**
 * Who is this, relative to THIS course?
 *
 * 'staff'    can manage the course (its instructor, or an admin)
 * 'student'  enrolled in it
 * null       neither — the caller 404s, exactly as it does for a run that does
 *            not exist, so the two are indistinguishable from outside
 *
 * ENROLLMENT IS CLE'S SCOPE MEMBERSHIP, and that is the deliberate difference
 * from the CiAB route, which resolves a student through their LANE because an
 * engagement has no enrollment table to consult. cle_course_enrollment is a
 * first-class row here, so requiring a lane as well would lock out a student
 * whose lane was deployed through POST /api/admin/deploy-group — which writes
 * group_id and no course reference at all (routes/my-courses.js documents that
 * exact split). The run itself is still scoped by (scope_type, scope_id) on
 * every read, so a student can only ever reach their own course's runs.
 */
async function resolveTier(courseId, user) {
  if (!user) return { tier: null, course: null };
  const managed = await getManagedCourse(courseId, user, 'course_id, code, course_name, features');
  if (managed) return { tier: 'staff', course: managed };

  const enrolled = await query(
    `SELECT c.course_id, c.code, c.course_name, c.features
       FROM cle_course_enrollment e
       JOIN cle_course c ON c.course_id = e.course_id
      WHERE e.course_id = $1 AND e.user_id = $2 AND e.status IN ('active','completed')
      LIMIT 1`,
    [courseId, user.userId]
  );
  if (enrolled.rows.length) return { tier: 'student', course: enrolled.rows[0] };
  return { tier: null, course: null };
}

/** The scope pair every board call is addressed by. */
const scopeOf = (courseId) => ({ scopeType: 'course', scopeId: String(courseId) });

/**
 * One error renderer, reading BOTH `status` and `statusCode`.
 *
 * The producers in this graph disagree about the property name, and
 * public/js/app.js calls response.json() unconditionally on a failure — so a
 * body that is not JSON becomes APIError('Network error', 0) and the real
 * status never reaches a handler. JSON on every path, always.
 */
function fail(res, err, where) {
  const status = err && (err.status || err.statusCode);
  if (status && status >= 400 && status < 500) {
    return res.status(status).json({ error: err.message, code: err.code || null });
  }
  console.error(`[CLE incidents] ${where}: ${err && err.message}`);
  return res.status(500).json({ error: (err && err.message) || 'Internal error' });
}

/**
 * Resolve tier + run in one step, or send the response.
 *
 * @returns {Promise<{tier, course, run}|null>} null once it has answered
 */
async function loadRun(req, res, opts) {
  const courseId = courseIdOf(req, res);
  const { tier, course } = await resolveTier(courseId, req.user);
  if (!tier) {
    res.status(404).json({ error: 'Not found' });
    return null;
  }
  if (opts && opts.staffOnly && tier !== 'staff') {
    res.status(403).json({ error: 'Instructors only' });
    return null;
  }
  // The feature gate, on WRITES only. 404 rather than 403, matching the
  // middleware's own doctrine: to a caller, a course with the board off has no
  // board endpoint.
  if (opts && opts.write && !isFeatureEnabled(course, 'blue_team')) {
    res.status(404).json({ error: 'Blue Team Board is not enabled for this course' });
    return null;
  }
  const scope = scopeOf(courseId);
  const run = tier === 'staff'
    ? await board.readRunForStaff(req.params.runId, scope)
    : await board.readRunForStudent(req.params.runId, scope);
  if (!run) {
    // The same 404 for "no such run" and "another course's run". See note 1.
    res.status(404).json({ error: 'Not found' });
    return null;
  }
  return { tier, course, run, courseId, scope };
}

// ---------------------------------------------------------------------------
// Reads — ungated. See note 3.
// ---------------------------------------------------------------------------

/** GET / — runs in this course, newest first. */
router.get('/', async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    const { tier } = await resolveTier(courseId, req.user);
    if (!tier) return res.status(404).json({ error: 'Not found' });
    const runs = await board.listRunsForScope(scopeOf(courseId), { tier, limit: req.query.limit });
    // Belt and braces: the student list was already read with the student
    // column list, and it is projected again here. Two layers, deliberately.
    res.json({
      tier,
      runs: tier === 'staff' ? runs : projection.projectRunsForStudent(runs),
    });
  } catch (error) {
    fail(res, error, 'GET /');
  }
});

/** GET /:runId — the board itself. */
router.get('/:runId', async (req, res) => {
  try {
    const ctx = await loadRun(req, res);
    if (!ctx) return undefined;
    if (ctx.tier === 'staff') return res.json({ tier: 'staff', ...(await board.getStaffBoard(ctx.run)) });
    return res.json({ tier: 'student', ...(await board.getStudentBoard(ctx.run, req.user.userId)) });
  } catch (error) {
    return fail(res, error, 'GET /:runId');
  }
});

/**
 * GET /:runId/status — the poll target.
 *
 * The /status suffix is what exempts this from the global rate limiter; see
 * note 2. Deliberately tiny: status, whether the board is released, and how
 * much the caller has banked. Nothing derived from the answer key.
 */
router.get('/:runId/status', async (req, res) => {
  try {
    const ctx = await loadRun(req, res);
    if (!ctx) return undefined;
    const scores = await board.readScores(ctx.run.run_id, ctx.tier === 'staff' ? null : req.user.userId);
    const findings = await board.readFindings(ctx.run.run_id, ctx.tier === 'staff' ? null : req.user.userId);
    return res.json({
      run_id: ctx.run.run_id,
      status: ctx.run.status,
      finished_at: ctx.run.finished_at,
      released: ctx.tier === 'staff'
        ? scores.some((s) => s.released === true)
        : !!(scores[0] && scores[0].released === true),
      submitted: findings.filter((f) => !f.withdrawn_at).length,
    });
  } catch (error) {
    return fail(res, error, 'GET /:runId/status');
  }
});

// ---------------------------------------------------------------------------
// Writes — gated on the blue_team feature. See note 3.
// ---------------------------------------------------------------------------

/** POST /:runId/findings — bank one claim. */
router.post('/:runId/findings', async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { write: true });
    if (!ctx) return undefined;
    const row = await board.submitFinding(ctx.run, req.user.userId, req.body);
    return res.status(201).json({
      finding: projection.projectFindingForStudent(row, { released: false }),
    });
  } catch (error) {
    return fail(res, error, 'POST /:runId/findings');
  }
});

/** DELETE /:runId/findings/:findingId — withdraw one of your own. */
router.delete('/:runId/findings/:findingId', async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { write: true });
    if (!ctx) return undefined;
    // Scoped to req.user.userId inside board.withdrawFinding, so a student
    // cannot withdraw somebody else's claim by guessing an id.
    const row = await board.withdrawFinding(ctx.run, req.user.userId, req.params.findingId);
    if (!row) return res.status(404).json({ error: 'Not found' });
    return res.json({ finding: projection.projectFindingForStudent(row, { released: false }) });
  } catch (error) {
    return fail(res, error, 'DELETE /:runId/findings/:findingId');
  }
});

/** PATCH /:runId/findings/:findingId — the instructor's adjudication. */
router.patch('/:runId/findings/:findingId', async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { staffOnly: true, write: true });
    if (!ctx) return undefined;
    const row = await board.overrideFinding(ctx.run, req.params.findingId, req.user.userId, req.body);
    if (!row) return res.status(404).json({ error: 'Not found' });
    audit.log({
      req,
      action: 'incident.finding_overridden',
      source: 'cle',
      target: { type: 'course', id: ctx.courseId, label: ctx.course.code || ctx.course.course_name },
      // Names and ids only, never a spread of the body: override_note is
      // instructor-private text and does not belong in an audit row either.
      metadata: { run_id: ctx.run.run_id, finding_id: row.finding_id, verdict: row.override_verdict },
    }).catch(() => {});
    return res.json({ finding: row });
  } catch (error) {
    return fail(res, error, 'PATCH /:runId/findings/:findingId');
  }
});

/** POST /:runId/score — re-run the scorer. Idempotent; safe to press twice. */
router.post('/:runId/score', async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { staffOnly: true, write: true });
    if (!ctx) return undefined;
    const result = await board.scoreRun(ctx.run);
    return res.json(result);
  } catch (error) {
    return fail(res, error, 'POST /:runId/score');
  }
});

/** POST /:runId/release — open (or retract) the verdicts. */
router.post('/:runId/release', async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { staffOnly: true, write: true });
    if (!ctx) return undefined;
    const released = req.body && req.body.released === false ? false : true;
    const rows = await board.setRelease(ctx.run, released, req.user.userId, req.body && req.body.user_id);
    audit.log({
      req,
      action: released ? 'incident.released' : 'incident.release_retracted',
      source: 'cle',
      target: { type: 'course', id: ctx.courseId, label: ctx.course.code || ctx.course.course_name },
      metadata: { run_id: ctx.run.run_id, students: rows.length },
    }).catch(() => {});
    return res.json({ released, students: rows.length });
  } catch (error) {
    return fail(res, error, 'POST /:runId/release');
  }
});

module.exports = router;
