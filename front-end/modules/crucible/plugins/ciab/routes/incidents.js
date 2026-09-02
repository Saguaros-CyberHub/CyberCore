/**
 * CIAB Plugin — Blue-team board
 * Mounted at /api/engagements/:engagementId/incidents
 * ============================================================================
 * The same board the CYBR 400 course gets, addressed by ENGAGEMENT instead of
 * by course. Every line of the board itself — the SQL, the projection, the
 * scorer, the release gate — is src/incident/board.js, shared. This file
 * resolves who is asking and which engagement they are asking about, and
 * nothing else.
 *
 * Vocabulary: Client / Engagement / Environment. No course, no cohort, no
 * CYBR — test/ciab-vocabulary.test.js is the gate on that, and an instructor
 * running a clinic never opens CLE.
 *
 * ── WHY THE MOUNT PATH IS /api/engagements AND NOT /api ─────────────────────
 * routes/api.js is mounted at '/' by the plugin loader, NOT at /ciab. So
 * `router.use('/api', ...)` in that file matches EVERY /api/* request in the
 * whole application — core's, the CLE plugin's, anything added later. There is
 * already a catch-all there, and it carries no enrollment gate for exactly that
 * reason: putting requireCiabAccess on the bare /api mount once cost every
 * student on no CIAB roster their CLE routes as well, because plugin load order
 * is readdir order and 'ciab' sorts before 'cle'.
 *
 * /api/engagements is a CIAB-OWNED PREFIX, so gating it is correctly scoped and
 * the full chain — authenticateToken, requireCiabAccess, checkSchedule — is
 * safe to apply at the mount.
 *
 * ── WHO IS A STUDENT HERE ───────────────────────────────────────────────────
 * An engagement has no enrollment table. The only link between a student and an
 * engagement is the LANE: cybercore_lane.config carries engagement_id (written
 * by ciab/utils/lane-provision.js) and the row carries user_id. So a student's
 * access IS "you hold an active lane in this engagement" — which is also
 * exactly the right rule, because a student with no lane has no SIEM to hunt in
 * and nothing to record.
 *
 * ── 404, NOT 403 ────────────────────────────────────────────────────────────
 * "No such engagement", "not your engagement" and "no such run" are all one
 * 404. A 403 confirms the resource exists, and engagement ids are UUIDs in a
 * URL — a distinguishable refusal turns the board into an enumeration oracle
 * for how many clinics are running.
 * ============================================================================
 */

const express = require('express');
const router = express.Router({ mergeParams: true });

const { requireRole } = require('../../../../../src/middleware/auth');
const audit = require('../../../../../src/utils/audit');
const board = require('../../../../../src/incident/board');
const projection = require('../../../../../src/incident/projection');

const instructorOnly = requireRole('instructor', 'admin');

/** Engagement id arrives via mergeParams; the res.locals shim in api.js backs it up. */
function engagementIdOf(req, res) {
  return req.params.engagementId || res.locals.engagementId;
}

const isStaff = (user) => !!user && (user.role === 'instructor' || user.role === 'admin');

// ---------------------------------------------------------------------------
// THE LAUNCHER, MOUNTED FIRST. Both halves of that sentence are load-bearing.
//
// MOUNTED, rather than written here, because POST / compiles the graded truth
// into the run INSERT and therefore names the `answer_key` column — a string
// test/incident-answer-key-leak.test.js forbids in every STUDENT-FACING
// incident file, and this is one: students read boards and bank findings
// through it. It is also the split CLE already has (board in
// cle/routes/incidents.js, launcher in cle/routes/attacks.js). See that file's
// header for the whole argument.
//
// FIRST, because Express matches in REGISTRATION ORDER and this router's
// `GET /:runId` would otherwise swallow `GET /catalog` and `GET /targets`. The
// symptom would not look like a routing bug either: board.readRunForStaff
// rejects a non-uuid before it reaches SQL, so both endpoints would answer a
// flat 404 and nothing would say why.
//
// Mounting from here rather than from routes/api.js keeps that ordering local
// and visible, leaves the URL surface unchanged, and holds api.js at zero diff
// — a file three tracks are editing at once.
router.use(require('./incident-launch'));

/** The scope pair every board call is addressed by. */
const scopeOf = (engagementId) => ({ scopeType: 'engagement', scopeId: String(engagementId) });

/**
 * One error renderer, reading BOTH `status` and `statusCode`.
 *
 * The producers in this plugin disagree about the property name — routes/
 * profile-deploy.js reads only one half, which is why assertEngagementDeployable's
 * 409 renders there as a bare 500. JSON on every path: public/js/app.js calls
 * response.json() unconditionally on a failure, so a non-JSON body becomes
 * APIError('Network error', 0) and the real status never reaches a handler.
 */
function fail(res, err, where) {
  const status = err && (err.status || err.statusCode);
  if (status && status >= 400 && status < 500) {
    return res.status(status).json({ error: err.message, code: err.code || null });
  }
  // 22P02 is invalid_text_representation — a malformed uuid, which is a CLIENT
  // error. pg's message quotes the offending value verbatim, so it is NOT
  // echoed back: that would put an attacker-chosen path segment into a toast.
  if (err && err.code === '22P02') {
    return res.status(400).json({ error: 'Malformed identifier', code: 'BAD_UUID' });
  }
  console.error(`[CIAB incidents] ${where}: ${err && err.message}`);
  return res.status(500).json({ error: (err && err.message) || 'Internal error' });
}

/**
 * Resolve tier + run, or answer.
 *
 * @returns {Promise<{tier, run, engagementId, scope}|null>} null once answered
 */
async function loadRun(req, res, opts) {
  const engagementId = engagementIdOf(req, res);
  const scope = scopeOf(engagementId);

  let tier = null;
  if (isStaff(req.user)) tier = 'staff';
  else if (await board.studentHasScopeLane(req.user.userId, scope)) tier = 'student';

  if (!tier) {
    res.status(404).json({ error: 'Not found' });
    return null;
  }
  if (opts && opts.staffOnly && tier !== 'staff') {
    res.status(403).json({ error: 'Instructors only' });
    return null;
  }

  const run = tier === 'staff'
    ? await board.readRunForStaff(req.params.runId, scope)
    : await board.readRunForStudent(req.params.runId, scope);
  if (!run) {
    res.status(404).json({ error: 'Not found' });
    return null;
  }
  return { tier, run, engagementId, scope };
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/** GET / — incidents in this engagement, newest first. */
router.get('/', async (req, res) => {
  try {
    const engagementId = engagementIdOf(req, res);
    const scope = scopeOf(engagementId);
    const tier = isStaff(req.user)
      ? 'staff'
      : ((await board.studentHasScopeLane(req.user.userId, scope)) ? 'student' : null);
    if (!tier) return res.status(404).json({ error: 'Not found' });
    const runs = await board.listRunsForScope(scope, { tier, limit: req.query.limit });
    return res.json({
      tier,
      runs: tier === 'staff' ? runs : projection.projectRunsForStudent(runs),
    });
  } catch (error) {
    return fail(res, error, 'GET /');
  }
});

/** GET /:runId — the board. */
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
 * The /status suffix is load-bearing: src/server.js exempts GETs matching
 * /\/status$/ from the global API rate limiter, and the board polls at 2s while
 * an incident is in flight. Rename it and a class-length exercise starts 429ing
 * for everyone who is not an admin.
 */
router.get('/:runId/status', async (req, res) => {
  try {
    const ctx = await loadRun(req, res);
    if (!ctx) return undefined;
    const forUser = ctx.tier === 'staff' ? null : req.user.userId;
    const scores = await board.readScores(ctx.run.run_id, forUser);
    const findings = await board.readFindings(ctx.run.run_id, forUser);
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
// Student writes
// ---------------------------------------------------------------------------

/** POST /:runId/findings — bank one claim. */
router.post('/:runId/findings', async (req, res) => {
  try {
    const ctx = await loadRun(req, res);
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
    const ctx = await loadRun(req, res);
    if (!ctx) return undefined;
    const row = await board.withdrawFinding(ctx.run, req.user.userId, req.params.findingId);
    if (!row) return res.status(404).json({ error: 'Not found' });
    return res.json({ finding: projection.projectFindingForStudent(row, { released: false }) });
  } catch (error) {
    return fail(res, error, 'DELETE /:runId/findings/:findingId');
  }
});

// ---------------------------------------------------------------------------
// Instructor sub-routes — requireRole on EVERY one of them.
//
// There is no requireCiabAccess-equivalent role gate at the mount for these,
// and this plugin has been bitten by that before: a route that forgets its own
// requireRole under a mount that only checks enrollment is open to every
// authenticated student. The gate is written per route, visibly, rather than
// inherited from a group.
// ---------------------------------------------------------------------------

/** PATCH /:runId/findings/:findingId — the instructor's adjudication. */
router.patch('/:runId/findings/:findingId', instructorOnly, async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { staffOnly: true });
    if (!ctx) return undefined;
    const row = await board.overrideFinding(ctx.run, req.params.findingId, req.user.userId, req.body);
    if (!row) return res.status(404).json({ error: 'Not found' });
    audit.log({
      req,
      action: 'incident.finding_overridden',
      source: 'ciab',
      target: { type: 'engagement', id: ctx.engagementId },
      // Ids and a verdict only. Never a spread of the body, and never the
      // instructor's private note.
      metadata: { run_id: ctx.run.run_id, finding_id: row.finding_id, verdict: row.override_verdict },
    }).catch(() => {});
    return res.json({ finding: row });
  } catch (error) {
    return fail(res, error, 'PATCH /:runId/findings/:findingId');
  }
});

/** POST /:runId/score — re-run the scorer. Idempotent; safe to press twice. */
router.post('/:runId/score', instructorOnly, async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { staffOnly: true });
    if (!ctx) return undefined;
    return res.json(await board.scoreRun(ctx.run));
  } catch (error) {
    return fail(res, error, 'POST /:runId/score');
  }
});

/** POST /:runId/release — open (or retract) the verdicts. */
router.post('/:runId/release', instructorOnly, async (req, res) => {
  try {
    const ctx = await loadRun(req, res, { staffOnly: true });
    if (!ctx) return undefined;
    const released = !(req.body && req.body.released === false);
    const rows = await board.setRelease(ctx.run, released, req.user.userId, req.body && req.body.user_id);
    audit.log({
      req,
      action: released ? 'incident.released' : 'incident.release_retracted',
      source: 'ciab',
      target: { type: 'engagement', id: ctx.engagementId },
      metadata: { run_id: ctx.run.run_id, students: rows.length },
    }).catch(() => {});
    return res.json({ released, students: rows.length });
  } catch (error) {
    return fail(res, error, 'POST /:runId/release');
  }
});

module.exports = router;
