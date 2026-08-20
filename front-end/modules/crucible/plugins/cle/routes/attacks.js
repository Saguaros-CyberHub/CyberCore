/**
 * CLE Plugin — Attack Console routes (CYBR 400)
 * Mounted at /api/cle/courses/:courseId/attacks
 * ============================================================================
 * Lets an instructor fire one log-generator attack into every student lane in a
 * course at the same moment, and watch what each lane did with it.
 *
 * Contract notes that are easy to get wrong:
 *
 *   - EVERY :runId handler re-checks run.course_id against :courseId. Owning
 *     course A must not let you drive a run belonging to course B. cle/routes/
 *     labs.js documents the same guard for :labId; it is a repeated bug class
 *     in this plugin, not a hypothetical.
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
const { query } = require('../utils/db');
const { getManagedCourse } = require('../utils/course-access');
const audit = require('../../../../../src/utils/audit');
const catalogModule = require('../utils/loggen-catalog');
const runner = require('../utils/attack-runner');
const { isFeatureEnabled } = require('../utils/course-features');

const instructorOnly = requireRole('instructor', 'admin');

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
  const r = await query(
    `SELECT * FROM cle_attack_run WHERE run_id = $1 AND course_id = $2`,
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
    const targets = await runner.resolveCourseTargets(courseId);
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
// GET / — recent runs
// ---------------------------------------------------------------------------
router.get('/', instructorOnly, async (req, res) => {
  try {
    const courseId = courseIdOf(req, res);
    if (!(await getManagedCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
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
        LIMIT 10`,
      [courseId]
    );
    res.json({ runs: r.rows });
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
      const ins = await query(
        `INSERT INTO cle_attack_run
           (course_id, launched_by, mode, technique_id, tactic_id, chain_key,
            duration_seconds, speed, catalog_version, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'scheduling')
         RETURNING *`,
        [courseId, req.user.userId, selection.mode,
         selection.mode === 'technique' ? selection.arg : null,
         selection.mode === 'tactic' ? selection.arg : null,
         selection.mode === 'chain' ? selection.arg : null,
         selection.durationSeconds,
         selection.mode === 'chain' ? selection.speed : null,
         catalogModule.CATALOG_VERSION]
      );
      run = ins.rows[0];
    } catch (err) {
      // ux_cle_attack_run_dispatching. Unlike assertNoConflictingLabOperation's
      // in-memory registry this survives a restart, so the message says how to
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
    const all = await runner.resolveCourseTargets(courseId, { probe: runner.makeGuestProbe() });
    const targets = all.filter((t) => !exclude.has(String(t.lane_id)));

    for (const t of targets) {
      await query(
        `INSERT INTO cle_attack_target
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
      await query(`UPDATE cle_attack_run SET event_group_id = $2 WHERE run_id = $1`,
        [run.run_id, eventGroupId]);
    }

    await runner.dispatchRun({ runId: run.run_id, selection, targets });
  } catch (err) {
    await query(
      `UPDATE cle_attack_run SET status = 'failed', error = $2, finished_at = NOW() WHERE run_id = $1`,
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

    const t = await query(
      `SELECT lane_id, user_id, student_email, vm_name, vmid, node, resolved_by,
              status, skip_reason, guest_state, exit_code, event_count,
              clock_skew_s, late, attempt, error,
              dispatched_at, started_at, expected_finish_at, finished_at, last_checked_at
         FROM cle_attack_target
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

module.exports = router;
