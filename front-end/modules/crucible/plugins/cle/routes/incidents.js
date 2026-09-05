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

/**
 * ATTACK AUTHORING. Core, both halves, and the split between them matters:
 *
 *   routes/caldera-authoring.js   owns WHERE the standalone authoring instance
 *                                 is and what public path it is served on. It
 *                                 holds no Caldera credential and never will.
 *   incident/caldera/authoring.js owns the API key, the client, the fact-source
 *                                 sync and the adversary list.
 *
 * NEITHER CAN DISPATCH. The client they build calls the source and adversary
 * endpoints only; src/incident/engines/index.js still refuses 'caldera', so no
 * run row can name it as an engine and there is no path from a picked adversary
 * to a launch. cle/routes/attacks.js — the file that CAN launch — is untouched
 * by this and gains no adversary parameter.
 *
 * These sit in the BOARD file rather than in attacks.js because the panel that
 * shows them (public/js/blue-team.js) already speaks to this collection and
 * already learns its own tier from it. A second base URL for two staff-only
 * reads would be a second thing to keep in step with routes/api.js — the exact
 * drift test/blueteam-mount.test.js exists to catch.
 */
const authoring = require('../../../../../src/incident/caldera/authoring');
const {
  authoringConfig,
  PUBLIC_PATH: AUTHORING_PATH,
} = require('../../../../../src/routes/caldera-authoring');

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

// ---------------------------------------------------------------------------
// Attack authoring — staff only, and registered BEFORE anything taking :runId
// ---------------------------------------------------------------------------
/**
 * WHAT THIS IS. One standalone Caldera "authoring" instance lives outside every
 * lane, with no agents and no implants. An instructor builds adversaries in its
 * own web UI; CyberCore reads them back out. Nothing inside a lane ever talks to
 * it, and nothing below launches anything.
 *
 * REGISTRATION ORDER IS LOAD-BEARING. Express matches in the order routes are
 * declared, and '/authoring/adversaries' would be read as a run id by
 * GET /:runId/status if that were declared first — resolving to run_id
 * 'authoring', which board.readRunFor*() refuses before SQL, so the symptom
 * would be a flat 404 that looks exactly like "this course has no incidents".
 * Declared here, above /:runId, it cannot happen.
 *
 * STAFF ONLY, AND THE TIER IS THE SERVER'S. resolveTier() answers 'staff' for
 * whoever MANAGES this course and 'student' for whoever is enrolled in it, per
 * request — so an instructor of another course is a student here and gets the
 * same 403 as anyone else. Caldera itself has no per-user and no per-object
 * ownership (its users are credentials in a 'red'/'blue' GROUP, which is a role,
 * not tenancy), so CYBERCORE OWNS ALL SCOPING and this is where it is owned.
 *
 * NOT GATED ON THE blue_team FEATURE. That flag governs student writes on the
 * board — see note 3 in this file's header. Authoring is neither a write to the
 * board nor a student action; gating it here would make an instructor unable to
 * prepare a course whose board they had merely not enabled yet.
 */

/** Staff on THIS course, or the response is already sent. */
async function loadStaffCourse(req, res) {
  const courseId = courseIdOf(req, res);
  const { tier, course } = await resolveTier(courseId, req.user);
  if (!tier) {
    // The same 404 a non-member gets everywhere else in this file: "no such
    // course" and "not your course" must stay indistinguishable from outside.
    res.status(404).json({ error: 'Not found' });
    return null;
  }
  if (tier !== 'staff') {
    res.status(403).json({ error: 'Instructors only' });
    return null;
  }
  return { courseId, course };
}

/**
 * POST /authoring/fact-source — the "Author attacks" click.
 *
 * THE ORDER IS THE POINT, and it is why this is a request at all rather than a
 * link the browser could just follow. The fact source Caldera seeds an operation
 * from is REFRESHED FROM THE DEPLOYED SPEC HERE, and console_path is present
 * only once the server has accepted that refresh. An instructor who reached the
 * authoring UI first would be authoring against the machines the PREVIOUS
 * deployment had: every ability aimed at one of them makes a link that can never
 * run, the operation finishes in seconds having done nothing, and the run row
 * reports success.
 *
 * A POST because it WRITES a row on a shared server — and safe to repeat,
 * because syncFactSource() matches this course's deterministic id first and its
 * name second, so pressing the button twice updates one row.
 *
 * ANSWERS 200 EVEN WHEN IT CANNOT BE DONE. `ready` is the discriminant and the
 * reasons are CODES; the panel writes the sentences, because the two products do
 * not share copy. A 4xx would reach the browser as a bare error message where
 * what is needed is "authoring is not set up, here is what an admin does".
 */
router.post('/authoring/fact-source', async (req, res) => {
  try {
    const ctx = await loadStaffCourse(req, res);
    if (!ctx) return undefined;

    // THE DEPLOYED SPEC, never a catalog entry. A course whose lanes are plain
    // workstation pairs has no challenge spec at all, which comes back as
    // no_spec — a state the panel explains rather than an error it reports.
    const { spec, lanes } = await authoring.loadScopeSpec(scopeOf(ctx.courseId));

    const target = authoring.resolveTarget(authoringConfig());
    const label = [ctx.course.code, ctx.course.course_name].filter(Boolean).join(' — ');

    const result = await authoring.prepareAuthoring({
      client: target.client,
      unavailable: target.unavailable,
      // The KEY is the course id and the LABEL is for humans. Two courses a
      // human called "Blue Team" are two scopes; the id is what keeps their fact
      // sources apart on a server that has no per-object ownership.
      scopeKey: ctx.courseId,
      scopeLabel: label || String(ctx.courseId),
      spec,
    });

    if (result.ready) {
      audit.log({
        req,
        action: 'incident.authoring_prepared',
        source: 'cle',
        target: { type: 'course', id: ctx.courseId, label: ctx.course.code || ctx.course.course_name },
        // Names and counts only. The host list describes an estate and has no
        // business in an audit blob admins browse.
        metadata: {
          fact_source: result.fact_source.name,
          action: result.fact_source.action,
          windows: result.platforms.windows,
          linux: result.platforms.linux,
          other: result.platforms.other,
        },
      }).catch(() => {});
    }

    return res.json({
      ...result,
      // The link, and ONLY on the ready path — the ordering rule made
      // structural. There is no branch in which the panel can render a link
      // without the platform summary that came back with it.
      console_path: result.ready ? `${AUTHORING_PATH}/` : null,
      upstream: target.upstream,
      lanes,
      execution: authoring.EXECUTION_GATE,
    });
  } catch (error) {
    return fail(res, error, 'POST /authoring/fact-source');
  }
});

/**
 * GET /authoring/adversaries — what the authoring instance holds.
 *
 * A read of a content store. Caldera has no per-object ownership, so this is
 * every adversary on the box and not "this course's" — inventing that boundary
 * in the payload would claim an isolation the server does not enforce.
 *
 * PICKING ONE CANNOT LAUNCH IT. Nothing in this router or in
 * cle/routes/attacks.js accepts an adversary id, and engineFor('caldera')
 * throws underneath all of it. `execution` travels in the payload so the panel
 * explains the gate instead of silently disabling a control.
 */
router.get('/authoring/adversaries', async (req, res) => {
  try {
    const ctx = await loadStaffCourse(req, res);
    if (!ctx) return undefined;
    const target = authoring.resolveTarget(authoringConfig());
    const result = await authoring.listAdversaryProfiles(target.client, {
      unavailable: target.unavailable,
    });
    // Uncached: the list changes the moment an instructor saves in Caldera's UI,
    // and a stale picker is how somebody prepares last week's adversary.
    res.set('Cache-Control', 'no-store');
    return res.json({ ...result, upstream: target.upstream });
  } catch (error) {
    return fail(res, error, 'GET /authoring/adversaries');
  }
});

/** GET /:runId — the board itself. */
// Manual agent management for the Blue Team Board. The incident engine remains
// separate; operations are controlled in the central Caldera console.
const laneAgents = require('../../../../../src/utils/caldera-lane-agents').createService();
async function courseAgentLanes(courseId) {
  return require('../../../../../src/incident/runner').findScopeLanes(scopeOf(courseId));
}

router.get('/caldera-agents/status', async (req, res) => {
  try {
    const ctx = await loadStaffCourse(req, res);
    if (!ctx) return;
    res.set('Cache-Control', 'no-store');
    res.json(await laneAgents.status(await courseAgentLanes(ctx.courseId)));
  } catch (error) { fail(res, error, 'GET /caldera-agents/status'); }
});

router.post('/caldera-agents', async (req, res) => {
  try {
    const ctx = await loadStaffCourse(req, res);
    if (!ctx) return;
    if (!isFeatureEnabled(ctx.course, 'blue_team')) {
      return res.status(404).json({ error: 'Blue Team Board is not enabled for this course' });
    }
    const input = req.body || {};
    const lane = (await courseAgentLanes(ctx.courseId)).find(l => l.lane_id === input.lane_id);
    if (!lane) return res.status(404).json({ error: 'Running lane not found in this course' });
    const job = await laneAgents.start(lane, input);
    audit.log({ req, action: 'caldera_agent_install', target: { type: 'lane', id: lane.lane_id },
      metadata: { course_id: ctx.courseId, vm_id: job.vm_id, job_id: job.job_id } }).catch(() => {});
    res.status(202).json({ job });
  } catch (error) { fail(res, error, 'POST /caldera-agents'); }
});

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
