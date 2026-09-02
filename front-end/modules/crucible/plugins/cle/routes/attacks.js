/**
 * CLE Plugin — Attack Console routes (CYBR 400)
 * Mounted at /api/cle/courses/:courseId/attacks
 * ============================================================================
 * Lets an instructor fire one log-generator attack into every student lane in a
 * course at the same moment, and watch what each lane did with it.
 *
 * WHICH DATABASE EACH STATEMENT IN THIS FILE TALKS TO
 * ----------------------------------------------------------------------------
 * TWO, and mixing them up is the one edit here that fails silently.
 *
 *   cybercoreQuery -> cybercore_db.cybercore_incident_run / _target
 *                     THE LIVE TABLES. Every run launched from now on.
 *   query          -> cle_db.cle_attack_run / cle_attack_target
 *                     LEGACY ONLY. Read once, in GET /, to keep pre-cutover
 *                     history visible; written once, by the one-shot boot sweep
 *                     at the bottom of this file. NEVER WRITTEN AGAIN, and never
 *                     migrated — a UUID primary key means the old rows can stay
 *                     where they are forever at zero cost, and a migration would
 *                     have to invent a scope_label for runs whose course may
 *                     since have been deleted.
 *
 * They are DIFFERENT POSTGRES DATABASES, which is why GET / does its union in
 * JavaScript. A SQL UNION across them is not merely discouraged here; it cannot
 * be expressed.
 *
 * Contract notes that are easy to get wrong:
 *
 *   - EVERY :runId handler re-checks the run's SCOPE against :courseId, as
 *     `scope_type = 'course' AND scope_id = $2`. Owning course A must not let
 *     you drive a run belonging to course B — and now also must not let you
 *     drive a CiAB ENGAGEMENT's run that happens to carry a colliding UUID,
 *     which is why scope_type is in the predicate and not assumed.
 *     cle/routes/labs.js documents the same guard for :labId; it is a repeated
 *     bug class in this plugin, not a hypothetical.
 *
 *   - The status endpoint is named /status ON PURPOSE. src/server.js exempts
 *     GETs matching /\/status$/ from the global API rate limiter, and the
 *     console polls at 2s. Instructors are not admins, so without the exemption
 *     a class-length exercise would exhaust their bucket and start 429ing.
 *
 *   - Launch is OPT-OUT (exclude_lane_ids), not opt-in. A lane deployed between
 *     the instructor opening the tab and pressing Launch is then included by
 *     default rather than silently left out of the exercise.
 *
 *   - THE attack_console FEATURE GATE COVERS LAUNCH AND RETRY ONLY. Reads,
 *     /status and abort stay open on a course that has since disabled the
 *     feature: a chain runs up to 45 minutes in the guest whether or not this
 *     app is interested, so gating the whole router would strand a live run
 *     with no way to watch or stop it, and would hide the history of runs that
 *     really happened. Disabling a feature stops new work; it does not
 *     retroactively unmake old work. utils/attack-worker.js is likewise
 *     ungated, or those runs would never reach a terminal state.
 * ============================================================================
 */

const express = require('express');
const router = express.Router({ mergeParams: true });

const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');                       // cle_db — LEGACY ONLY
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { getManagedCourse } = require('../utils/course-access');
const audit = require('../../../../../src/utils/audit');
// The engine moved to shared core in E1 and the re-export shims that stood in
// cle/utils/ were deleted in E2. A plugin requiring core is the allowed
// direction; the reverse is what test/incident-engine-locality.test.js forbids.
const catalogModule = require('../../../../../src/incident/catalog');
const runner = require('../../../../../src/incident/runner');
const { isFeatureEnabled } = require('../utils/course-features');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * This router's scope, for every call into the shared incident engine.
 *
 * A CLE course is one of the two shapes cybercore_incident_run.scope_type
 * declares; a CiAB engagement is the other. Built here rather than inlined at
 * six call sites so that "which scope is this router?" has exactly one answer.
 */
function scopeOf(courseId) {
  return { scopeType: 'course', scopeId: courseId };
}

/** Course id arrives via mergeParams; the res.locals shim in api.js is a backstop. */
function courseIdOf(req, res) {
  return req.params.courseId || res.locals.courseId;
}

/**
 * Load a run, but only if it belongs to the course in the URL. Returns null
 * for both "no such run" and "not your run" -- the caller 404s either way, so a
 * probe cannot distinguish a run that exists elsewhere from one that does not.
 */
async function getRunForCourse(runId, courseId) {
  if (!/^[0-9a-f-]{36}$/i.test(String(runId || ''))) return null;
  const r = await cybercoreQuery(
    // scope_type is part of the predicate, not an assumption. Both a course id
    // and an engagement id are UUIDs drawn from the same space, so matching on
    // scope_id alone would eventually let a CLE instructor abort a CiAB
    // engagement's run — the same collision the dispatch mutex is keyed against.
    `SELECT * FROM cybercore_incident_run
      WHERE run_id = $1 AND scope_type = 'course' AND scope_id = $2`,
    [runId, courseId]
  );
  return r.rows[0] || null;
}

/** Rebuild the argv contract for a stored run, for abort/retry. */
function selectionOf(run) {
  return runner.resolveSelection({
    mode: run.mode,
    technique_id: run.technique_id,
    tactic_id: run.tactic_id,
    chain_key: run.chain_key,
    duration_seconds: run.duration_seconds,
    speed: run.speed,
  });
}

// ---------------------------------------------------------------------------
// GET /catalog — what the instructor can choose from
// ---------------------------------------------------------------------------
router.get('/catalog', instructorOnly, async (req, res) => {
  try {
    if (!(await getManagedCourse(courseIdOf(req, res), req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
    // Static for the life of the process, but private: it names the exact
    // log-generator build the images run.
    res.set('Cache-Control', 'private, max-age=300');
    res.json(catalogModule.catalog());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// GET /targets — the lane picker
// ---------------------------------------------------------------------------
router.get('/targets', instructorOnly, async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    if (!(await getManagedCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
    // No guest probe here. This runs on every tab open, and rung 4 of the
    // resolver costs a guest exec per candidate VM -- acceptable when
    // launching, far too expensive for a page load. A lane only resolvable by
    // probe therefore shows as unresolved in the picker and is resolved for
    // real at launch.
    const targets = await runner.resolveScopeTargets(scopeOf(courseId));
    res.json({
      targets,
      resolvable: targets.filter((t) => t.resolvable).length,
      total: targets.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// GET / — recent runs, live + legacy, merged in JavaScript
// ---------------------------------------------------------------------------
/**
 * The column list the console has always been served, restated explicitly
 * instead of `r.*`.
 *
 * TWO reasons, and neither is style.
 *
 *  1. cybercore_incident_run is WIDER than cle_attack_run was. `r.*` would ship
 *     `playbook` and `answer_key` — the compiled attack and its grading key,
 *     marked STAFF ONLY in src/incident/schema.js — down a route whose response
 *     the browser caches and whose shape is the acceptance bar for this phase.
 *     Nobody would notice until a student had staff on their screen.
 *  2. `scope_id AS course_id` keeps the emitted shape identical to what
 *     cle_attack_run produced. A course-scoped run's scope_id IS its course id,
 *     so this is a rename and not a fudge, and it means the console JS did not
 *     have to change — which is what E2 is measured against.
 */
const RUN_LIST_COLUMNS = `
  r.run_id, r.scope_id AS course_id, r.launched_by, r.mode,
  r.technique_id, r.tactic_id, r.chain_key,
  r.duration_seconds, r.speed, r.catalog_version,
  r.lead_seconds, r.scheduled_start_at, r.status,
  r.event_group_id, r.error, r.created_at, r.finished_at`;

/**
 * How many runs the history list returns, per source and after the merge.
 *
 * Interpolated into both statements rather than bound. It is a module-level
 * integer literal that no request can reach, and binding it would make LIMIT's
 * argument an `unknown`-typed parameter — the class of type-deduction problem
 * test/sql-param-typing.test.js exists over. Keeping it a literal also leaves
 * the legacy statement byte-identical to the one it replaced.
 */
const RUN_LIST_LIMIT = 10;

/**
 * Pre-cutover history, from cle_db.
 *
 * Read-only and best-effort: this table is frozen, and a course that never ran
 * an attack before the cutover simply has none. A failure here must not take
 * the live history down with it — the legacy rows are a nicety, the shared ones
 * are the feature — so it returns [] and warns.
 */
async function legacyRunsFor(courseId) {
  try {
    const r = await query(
      `SELECT r.*,
              COUNT(t.target_id)                                       AS target_count,
              COUNT(t.target_id) FILTER (WHERE t.status = 'completed')  AS completed_count,
              COALESCE(SUM(t.event_count), 0)                          AS total_events
         FROM cle_attack_run r
         LEFT JOIN cle_attack_target t ON t.run_id = r.run_id
        WHERE r.course_id = $1
        GROUP BY r.run_id
        ORDER BY r.created_at DESC
        LIMIT ${RUN_LIST_LIMIT}`,
      [courseId]
    );
    // Tagged so a caller can tell a frozen row from a live one. Only the LEGACY
    // rows carry the flag: adding `legacy: false` to the live rows would change
    // the shape the console has always been served, for no reader's benefit.
    //
    // It matters because a legacy run cannot be driven: /status, /abort and
    // /retry all read cybercore_incident_run and will 404 on these ids. That is
    // the honest outcome — the run is over, the one-shot boot sweep below made
    // sure of it — but a UI that offers a Retry button on one would be lying.
    return r.rows.map((row) => ({ ...row, legacy: true }));
  } catch (err) {
    console.warn(`[Attacks] legacy run history unavailable for course ${courseId}: ${err.message}`);
    return [];
  }
}

router.get('/', instructorOnly, async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    if (!(await getManagedCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // A JS union, because these are two different DATABASES. cybercore_db holds
    // the live tables and cle_db holds the frozen ones; Postgres has no
    // cross-database query, so no amount of SQL can express this merge.
    const [live, legacy] = await Promise.all([
      cybercoreQuery(
        `SELECT ${RUN_LIST_COLUMNS},
                COUNT(t.target_id)                                       AS target_count,
                COUNT(t.target_id) FILTER (WHERE t.status = 'completed')  AS completed_count,
                COALESCE(SUM(t.event_count), 0)                          AS total_events
           FROM cybercore_incident_run r
           LEFT JOIN cybercore_incident_target t ON t.run_id = r.run_id
          WHERE r.scope_type = 'course' AND r.scope_id = $1
          GROUP BY r.run_id
          ORDER BY r.created_at DESC
          LIMIT ${RUN_LIST_LIMIT}`,
        [courseId]
      ),
      legacyRunsFor(courseId),
    ]);

    // Sorted into ONE created_at DESC list rather than concatenated, even though
    // every legacy row is by definition older than every live one today. The
    // ordering is what attack-console.js's loadLatestRun() depends on — it takes
    // runs[0] and re-attaches to it — so leaving it to an assumption about
    // cutover dates would be a bug waiting for a restored backup.
    const runs = [...live.rows, ...legacy]
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, RUN_LIST_LIMIT);

    res.json({ runs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// POST / — launch
// ---------------------------------------------------------------------------
router.post('/', instructorOnly, async (req, res) => {
  const courseId = courseIdOf(req, res);
  try {
    const course = await getManagedCourse(courseId, req.user, 'course_id, course_name, code, features');
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    if (!isFeatureEnabled(course, 'attack_console')) {
      return res.status(404).json({ error: 'Attack Console is not enabled for this course' });
    }

    // Throws on anything the catalog does not offer, before a run row exists.
    let selection;
    try {
      selection = selectionOf(req.body || {});
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    // Enforced by a CHECK too, but a 400 explains it and a constraint violation
    // does not.
    if (selection.mode === 'chain' && req.body.duration_seconds != null) {
      return res.status(400).json({
        error: 'Attack chains run for their own scripted length; a duration cannot be applied to them.',
      });
    }

    let run;
    try {
      const ins = await cybercoreQuery(
        // scope_label is a SNAPSHOT of the course's name at launch, not a join.
        // A run has to stay readable after the course is renamed or deleted —
        // there is no FK to it and there cannot be one, since cle_course lives
        // in a different database. Same reasoning as cybercore_ticket.course_name.
        //
        // `engine` is written explicitly rather than left to its DEFAULT so the
        // row says which adapter produced it even if the default ever changes.
        `INSERT INTO cybercore_incident_run
           (scope_type, scope_id, scope_label, engine, launched_by, mode,
            technique_id, tactic_id, chain_key,
            duration_seconds, speed, catalog_version, status)
         VALUES ('course',$1,$2,'synthetic',$3,$4,$5,$6,$7,$8,$9,$10,'scheduling')
         RETURNING *`,
        [courseId, course.code || course.course_name || null,
         req.user.userId, selection.mode,
         selection.mode === 'technique' ? selection.arg : null,
         selection.mode === 'tactic' ? selection.arg : null,
         selection.mode === 'chain' ? selection.arg : null,
         selection.durationSeconds,
         selection.mode === 'chain' ? selection.speed : null,
         catalogModule.CATALOG_VERSION]
      );
      run = ins.rows[0];
    } catch (err) {
      // ux_cc_incident_run_dispatching, the per-scope dispatch mutex — keyed on
      // the PAIR (scope_type, scope_id), so a CiAB engagement mid-dispatch can
      // never block this course. Unlike assertNoConflictingLabOperation's
      // in-memory registry it survives a restart, so the message says how to
      // clear it rather than implying it expires on its own.
      if (err.code === '23505') {
        return res.status(409).json({
          error: 'Another attack is already being dispatched for this course. Wait for it to finish, or abort it first.',
        });
      }
      throw err;
    }

    res.status(202).json({
      run_id: run.run_id,
      status: 'scheduling',
      label: selection.label,
      status_url: `/api/cle/courses/${courseId}/attacks/${run.run_id}/status`,
    });

    // Detached from here. The tables are the record, not this closure.
    launchInBackground({ req, run, course, courseId, selection }).catch((err) => {
      console.error(`[Attacks] run ${run.run_id} dispatch failed: ${err.message}`);
    });
  } catch (error) {
    if (!res.headersSent) res.status(500).json({ error: error.message });
  }
});

/**
 * Resolve, record and dispatch. Runs after the 202, so nothing here may throw
 * into a response -- every failure lands on the run row instead, where the
 * console can show it.
 */
async function launchInBackground({ req, run, course, courseId, selection }) {
  try {
    const exclude = new Set((req.body.exclude_lane_ids || []).map(String));
    // The probe rung IS used here, unlike /targets: at launch a few extra guest
    // execs are worth resolving a lane that would otherwise be skipped.
    const all = await runner.resolveScopeTargets(scopeOf(courseId), { probe: runner.makeGuestProbe() });
    const targets = all.filter((t) => !exclude.has(String(t.lane_id)));

    for (const t of targets) {
      await cybercoreQuery(
        `INSERT INTO cybercore_incident_target
           (run_id, lane_id, user_id, student_email, node, vmid, vm_name,
            resolved_by, status, skip_reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (run_id, lane_id) DO NOTHING`,
        [run.run_id, t.lane_id, t.user_id, t.student_email, t.node, t.vmid,
         t.vm_name, t.resolved_by, t.resolvable ? 'pending' : 'skipped', t.skip_reason]
      );
    }

    // One summary row plus one per lane, sharing an event_group_id, so "which
    // students did this instructor attack" stays answerable by target_user_id.
    const eventGroupId = await audit.batch({
      req,
      action: 'attack.launched',
      source: 'cle',
      target: { type: 'course', id: courseId, label: course.code || course.course_name },
      metadata: {
        run_id: run.run_id,
        mode: selection.mode,
        selection: selection.arg,
        label: selection.label,
        duration_seconds: selection.durationSeconds,
        catalog_version: catalogModule.CATALOG_VERSION,
        loggen_ref: catalogModule.LOGGEN_REF,
        lanes_targeted: targets.filter((t) => t.resolvable).length,
        lanes_skipped: targets.filter((t) => !t.resolvable).length,
      },
      targetAction: 'attack.launched_lane',
      targets: targets.map((t) => ({
        id: t.user_id,
        label: t.student_email,
        status: t.resolvable ? 'success' : 'denied',
        reason: t.skip_reason || null,
        metadata: { run_id: run.run_id, lane_id: t.lane_id, vmid: t.vmid },
      })),
    }).catch(() => null);

    if (eventGroupId) {
      await cybercoreQuery(`UPDATE cybercore_incident_run SET event_group_id = $2 WHERE run_id = $1`,
        [run.run_id, eventGroupId]);
    }

    await runner.dispatchRun({ runId: run.run_id, selection, targets });
  } catch (err) {
    await cybercoreQuery(
      `UPDATE cybercore_incident_run SET status = 'failed', error = $2, finished_at = NOW() WHERE run_id = $1`,
      [run.run_id, String(err.message || err).slice(0, 500)]
    ).catch(() => {});
    throw err;
  }
}

// ---------------------------------------------------------------------------
// GET /:runId/status — polled at 2s by the console
// ---------------------------------------------------------------------------
// The /status suffix is load-bearing: src/server.js exempts it from the global
// API rate limiter. Renaming this endpoint would start 429ing instructors
// mid-exercise, and the failure would look like the console hanging.
router.get('/:runId/status', instructorOnly, async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    if (!(await getManagedCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
    const run = await getRunForCourse(req.params.runId, courseId);
    if (!run) return res.status(404).json({ error: 'Attack run not found' });

    // The column list is explicit for the same reason RUN_LIST_COLUMNS is: the
    // shared target table carries `engine_ref` that cle_attack_target did not,
    // and this response's shape is what attack-console.js renders unchanged.
    const t = await cybercoreQuery(
      `SELECT lane_id, user_id, student_email, vm_name, vmid, node, resolved_by,
              status, skip_reason, guest_state, exit_code, event_count,
              clock_skew_s, late, attempt, error,
              dispatched_at, started_at, expected_finish_at, finished_at, last_checked_at
         FROM cybercore_incident_target
        WHERE run_id = $1
        ORDER BY student_email`,
      [req.params.runId]
    );

    const counts = t.rows.reduce((acc, row) => {
      acc[row.status] = (acc[row.status] || 0) + 1;
      return acc;
    }, {});

    res.json({
      run: {
        run_id: run.run_id,
        mode: run.mode,
        selection: run.technique_id || run.tactic_id || run.chain_key,
        duration_seconds: run.duration_seconds,
        speed: run.speed,
        status: run.status,
        lead_seconds: run.lead_seconds,
        scheduled_start_at: run.scheduled_start_at,
        created_at: run.created_at,
        finished_at: run.finished_at,
        error: run.error,
        catalog_version: run.catalog_version,
      },
      // Server time so the console's countdown cannot drift with the browser's
      // clock -- the one place a wrong clock would be visible to the class.
      server_time: new Date().toISOString(),
      counts,
      total_events: t.rows.reduce((s, r) => s + (Number(r.event_count) || 0), 0),
      targets: t.rows,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// POST /:runId/abort
// ---------------------------------------------------------------------------
router.post('/:runId/abort', instructorOnly, async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    const course = await getManagedCourse(courseId, req.user, 'course_id, course_name, code');
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    const run = await getRunForCourse(req.params.runId, courseId);
    if (!run) return res.status(404).json({ error: 'Attack run not found' });

    res.status(202).json({ run_id: run.run_id, status: 'aborting' });

    runner.abortRun(run.run_id)
      .then((r) => audit.log({
        req,
        action: 'attack.aborted',
        source: 'cle',
        target: { type: 'course', id: courseId, label: course.code || course.course_name },
        metadata: { run_id: run.run_id, lanes_signalled: r.aborted },
      }).catch(() => {}))
      .catch((err) => console.error(`[Attacks] abort ${run.run_id} failed: ${err.message}`));
  } catch (error) {
    if (!res.headersSent) res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// POST /:runId/retry — re-fire the lanes that missed, at a fresh common start
// ---------------------------------------------------------------------------
router.post('/:runId/retry', instructorOnly, async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    const course = await getManagedCourse(courseId, req.user, 'course_id, course_name, code, features');
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    // Retry re-fires lanes, i.e. it creates new work — gated like launch.
    if (!isFeatureEnabled(course, 'attack_console')) {
      return res.status(404).json({ error: 'Attack Console is not enabled for this course' });
    }
    const run = await getRunForCourse(req.params.runId, courseId);
    if (!run) return res.status(404).json({ error: 'Attack run not found' });

    let selection;
    try {
      selection = selectionOf(run);
    } catch (err) {
      // The catalog changed under a stored run -- re-firing it would not mean
      // what the original run meant.
      return res.status(409).json({ error: `This run can no longer be reproduced: ${err.message}` });
    }

    const laneIds = Array.isArray(req.body.lane_ids) && req.body.lane_ids.length
      ? req.body.lane_ids.filter((id) => /^[0-9a-f-]{36}$/i.test(String(id)))
      : null;

    res.status(202).json({ run_id: run.run_id, status: 'retrying' });

    runner.retryTargets({ runId: run.run_id, laneIds, selection })
      .then((r) => audit.log({
        req,
        action: 'attack.retried',
        source: 'cle',
        target: { type: 'course', id: courseId, label: course.code || course.course_name },
        metadata: { run_id: run.run_id, lanes_retried: r.retried },
      }).catch(() => {}))
      .catch((err) => console.error(`[Attacks] retry ${run.run_id} failed: ${err.message}`));
  } catch (error) {
    if (!res.headersSent) res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// One-shot boot sweep over the FROZEN legacy tables
// ---------------------------------------------------------------------------

/**
 * Terminalize any cle_attack_target still sitting at 'dispatching'.
 *
 * WHY THIS EXISTS AT ALL, given the legacy tables are never written again.
 * ----------------------------------------------------------------------------
 * There is exactly one moment it matters, and it is the cutover itself. A run
 * dispatched by the OLD build wrote its targets into cle_attack_target; the
 * process is then restarted onto the NEW build, whose worker sweeps
 * cybercore_incident_target and will never look at those rows again. Without
 * this they sit at 'dispatching' forever — non-terminal, so the run above them
 * stays 'running', so it never finishes and never shows an outcome. The guests
 * themselves are unaffected (the wrapper is detached and neither knows nor
 * cares), which is precisely why the stranded rows are invisible: nothing
 * breaks, a run simply never ends.
 *
 * 'unknown' rather than 'failed', and the distinction is the same one
 * src/incident/worker.js's header makes: we genuinely do not know whether the
 * wrapper was staged before the old process died. 'failed' would assert
 * something we did not observe.
 *
 * Runs ONCE per boot, sweeps the whole table rather than one course, and takes
 * no arguments — a boot has no list of courses, and every stranded row is
 * stranded for the same reason regardless of whose it was.
 *
 * WHY IT LIVES IN THE PLUGIN RATHER THAN IN src/incident/worker.js, where its
 * shared-table twin lives: cle_attack_target is in cle_db, and cle_db is
 * reachable only through this plugin's injected pool. Putting it in core would
 * mean core requiring into a module that can be disabled — the inversion E2
 * exists to remove. src/server.js calls both sweeps back to back; see there.
 *
 * Never throws. The table may not exist (a deployment that never ran CYBR 400),
 * the pool may not be injected (the plugin is disabled), or the database may be
 * unreachable — none of which is a reason to fail a boot.
 */
async function recoverLegacyAttackRuns() {
  try {
    const t = await query(
      `UPDATE cle_attack_target
          SET status = 'unknown',
              error = 'the control plane restarted while this lane was being dispatched',
              finished_at = NOW(), updated_at = NOW()
        WHERE status = 'dispatching'`
    );

    // The runs above them, in the same sweep and on the same reasoning: a run
    // left mid-dispatch by the old build has no sweeper left that would ever
    // finish it. 'scheduling' never got as far as inserting targets at all.
    //
    // These rows also still hold ux_cle_attack_run_dispatching, the OLD mutex.
    // That no longer gates anything — POST / writes cybercore_incident_run now —
    // but leaving a course's history showing a run that is permanently
    // "dispatching" is its own small lie.
    const r = await query(
      `UPDATE cle_attack_run
          SET status = 'failed',
              error = 'the control plane restarted before this run could be dispatched',
              finished_at = COALESCE(finished_at, NOW())
        WHERE status IN ('scheduling','dispatching')`
    );

    if (t.rowCount || r.rowCount) {
      console.log(
        `[Attacks] legacy cutover sweep: ${t.rowCount} target(s) and ${r.rowCount} run(s) `
        + 'left mid-dispatch by a pre-cutover build were closed out'
      );
    }
  } catch (err) {
    console.warn('[Attacks] legacy cutover sweep skipped:', err.message);
  }
}

module.exports = router;
// Named export alongside the router so src/server.js can run the boot sweep
// without importing the route table, exactly as routes/courses.js does for
// recoverStrandedCourseLabs.
module.exports.recoverLegacyAttackRuns = recoverLegacyAttackRuns;
