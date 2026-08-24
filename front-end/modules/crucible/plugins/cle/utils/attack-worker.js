/**
 * CLE Plugin — attack run reconciler (CYBR 400)
 * ============================================================================
 * Background sweeper that asks the guests what actually happened and writes it
 * back to cle_attack_target. Shaped after src/utils/email-worker.js -- the only
 * durable background worker in this codebase: a setInterval whose handle is
 * unref'd so it never holds the process open, plus a module-level guard so a
 * slow sweep cannot overlap itself.
 *
 * WHY A SWEEPER AT ALL. The dispatch exec returns the moment the wrapper is
 * forked, because holding a QGA channel open for 45 minutes is exactly the
 * failure goad-deploy.js documents. So nothing else ever learns the outcome:
 * the guest writes a state file, and this is what reads it.
 *
 * ---------------------------------------------------------------------------
 * BOOT RECOVERY IS THE INVERSE OF recoverStrandedLanes()
 *
 * src/server.js sweeps every lane still 'deploying' at boot into 'error',
 * because a deploy lives inside the Node process and cannot survive a restart.
 * An attack is the opposite: it runs on the guest, detached, and a restart here
 * is invisible to it. Marking 'running' targets failed at boot would be a lie,
 * and would strand a class mid-exercise.
 *
 * So recoverAttackRuns() touches ONLY 'dispatching' -- the one state meaning
 * "an exec was in flight inside the process that just died", where we genuinely
 * do not know whether the wrapper was ever staged. Everything else is left for
 * the sweeper to reconcile. Please do not "fix" this to match the neighbouring
 * precedent.
 * ---------------------------------------------------------------------------
 *
 * COST CONTROL. Every check is one guest exec plus a poll: ~2 Proxmox calls and
 * a few seconds of wall time. Polling 30 lanes every 30s would be a permanent
 * load spike for no information, because for most of a 45-minute run the answer
 * is "still going". A target is only polled when the answer could plausibly
 * have changed -- see dueTargets().
 * ============================================================================
 */

const { query } = require('./db');
const runner = require('./attack-runner');
const attackTarget = require('./attack-target');
const {
  agentShellExec,
  pollExecStatus,
} = require('../../../../../src/utils/script-executor');

const POLL_MS = Number(process.env.CYBR400_SWEEP_MS) > 0
  ? Number(process.env.CYBR400_SWEEP_MS) : 30_000;

/** Most guests to poll in one sweep, so a large class cannot monopolise QGA. */
const MAX_CHECKS_PER_SWEEP = Number(process.env.CYBR400_SWEEP_BATCH) > 0
  ? Number(process.env.CYBR400_SWEEP_BATCH) : 40;

/** Consecutive unreachable checks before a target is called 'unknown'. */
const MAX_CHECK_FAILURES = 3;

/** Grace past the expected finish before an unreachable guest is given up on. */
const GIVE_UP_AFTER_MS = 10 * 60 * 1000;

let timer = null;
let running = false;

/**
 * Claim the targets whose state could plausibly have changed since we last
 * looked, and stamp them in the same statement.
 *
 * Three windows, and nothing else:
 *   - dispatching, 20s old       did the wrapper actually come up?
 *   - within 15s of the deadline  did it finish?
 *   - scheduled/running, 5min     liveness heartbeat, so a crashed generator is
 *                                 noticed long before its deadline
 *
 * The claim is ONE statement -- UPDATE ... WHERE target_id IN (SELECT ... FOR
 * UPDATE SKIP LOCKED) -- copied from mailer.drainOutbox. A bare SELECT ... FOR
 * UPDATE outside a transaction releases its lock the instant the statement
 * ends, so it would claim nothing at all; the row lock only means something
 * while the UPDATE that consumes it is still running. Stamping last_checked_at
 * here also doubles as backoff: a target that then fails to answer is not
 * re-selected on the very next sweep.
 */
async function dueTargets(limit) {
  const r = await query(
    `UPDATE cle_attack_target
        SET last_checked_at = NOW()
      WHERE target_id IN (
        SELECT target_id
          FROM cle_attack_target
         WHERE status IN ('dispatching','scheduled','running')
           AND node IS NOT NULL AND vmid IS NOT NULL
           AND (
                 (status = 'dispatching' AND dispatched_at < NOW() - INTERVAL '20 seconds')
              OR (expected_finish_at IS NOT NULL AND NOW() >= expected_finish_at - INTERVAL '15 seconds')
              OR (status IN ('scheduled','running')
                  AND (last_checked_at IS NULL OR last_checked_at < NOW() - INTERVAL '5 minutes'))
           )
         ORDER BY last_checked_at NULLS FIRST
         LIMIT $1
         FOR UPDATE SKIP LOCKED
      )
      RETURNING target_id, run_id, lane_id, node, vmid, status,
                expected_finish_at, check_failures, attempt`,
    [limit]
  );
  return r.rows;
}

/**
 * Ask one guest where it is, and write the answer down.
 *
 * Only ever records an outcome it OBSERVED. An unreachable guest increments
 * check_failures and is left in place; it becomes 'unknown' -- never
 * 'completed' -- once it is both repeatedly unreachable and past its deadline.
 * Reporting a clean finish we did not see would tell an instructor the class
 * has data that may not exist.
 */
async function checkTarget(t) {
  let parsed = null;
  try {
    const { pid } = await agentShellExec(t.node, t.vmid, runner.buildStateReadCommand(t.run_id));
    const status = await pollExecStatus(t.node, t.vmid, pid, 45000);
    if (!status.exited) throw new Error('state read timed out');
    parsed = runner.parseGuestState(status.stdout);
  } catch (err) {
    return recordCheckFailure(t, err);
  }

  // Empty state file: the wrapper has not written its first line yet. Normal
  // for a moment after dispatch -- unless the process is gone too, which means
  // it died before it could say anything.
  if (!parsed.phase) {
    if (t.status === 'dispatching' && !parsed.alive) {
      await query(
        `UPDATE cle_attack_target
            SET status = 'failed', error = 'wrapper exited before writing any state',
                finished_at = NOW(), last_checked_at = NOW(), check_failures = 0, updated_at = NOW()
          WHERE target_id = $1`,
        [t.target_id]
      );
    } else {
      await query(
        `UPDATE cle_attack_target SET last_checked_at = NOW(), check_failures = 0, updated_at = NOW()
          WHERE target_id = $1`,
        [t.target_id]
      );
    }
    return;
  }

  await applyPhase(t, parsed);
}

/** An unreachable guest is a fact about the network, not about the attack. */
async function recordCheckFailure(t, err) {
  const overdue = t.expected_finish_at
    && (Date.now() - new Date(t.expected_finish_at).getTime() > GIVE_UP_AFTER_MS);
  const failures = Number(t.check_failures || 0) + 1;

  if (failures >= MAX_CHECK_FAILURES && overdue) {
    await query(
      `UPDATE cle_attack_target
          SET status = 'unknown', check_failures = $2, last_checked_at = NOW(),
              finished_at = NOW(), error = $3, updated_at = NOW()
        WHERE target_id = $1`,
      [t.target_id, failures,
       `guest unreachable after ${failures} checks: ${String(err.message || err).slice(0, 300)}`]
    );
    return;
  }
  await query(
    `UPDATE cle_attack_target SET check_failures = $2, last_checked_at = NOW(), updated_at = NOW()
      WHERE target_id = $1`,
    [t.target_id, failures]
  );
}

/** Map one parsed guest state line onto the target row. */
async function applyPhase(t, p) {
  const guestState = p.raw ? p.raw.slice(0, 500) : null;
  const skew = Number.isInteger(p.skew) ? p.skew : null;

  if (p.phase === 'refused') {
    // The cached sensor VM is real but is not running log-generator, so the
    // cache is actively wrong. Clearing it makes the next run re-run the whole
    // resolver ladder rather than confidently aiming at the same wrong box.
    if (p.reason === 'notinstalled') {
      await attackTarget.invalidateLoggenCache(t.lane_id).catch(() => {});
    }
    await query(
      `UPDATE cle_attack_target
          SET status = 'failed', error = $2, guest_state = $3, clock_skew_s = $4,
              finished_at = NOW(), last_checked_at = NOW(), check_failures = 0, updated_at = NOW()
        WHERE target_id = $1`,
      [t.target_id, `guest refused: ${p.reason}`, guestState, skew]
    );
    return;
  }

  if (p.phase === 'aborted') {
    await query(
      `UPDATE cle_attack_target
          SET status = 'aborted', guest_state = $2, finished_at = NOW(),
              last_checked_at = NOW(), check_failures = 0, updated_at = NOW()
        WHERE target_id = $1`,
      [t.target_id, guestState]
    );
    return;
  }

  if (p.phase === 'done') {
    // 124 is coreutils timeout, 137 a SIGKILL after it: the hard cap fired and
    // the run was cut off rather than finishing on its own. Worth saying so.
    const timedOut = p.rc === 124 || p.rc === 137;
    await query(
      `UPDATE cle_attack_target
          SET status = $2, exit_code = $3, event_count = $4, clock_skew_s = $5,
              guest_state = $6, error = $7, finished_at = NOW(),
              last_checked_at = NOW(), check_failures = 0, updated_at = NOW()
        WHERE target_id = $1`,
      [t.target_id,
       p.rc === 0 ? 'completed' : 'failed',
       p.rc,
       Number.isInteger(p.lines) ? p.lines : null,
       skew, guestState,
       p.rc === 0 ? null : (timedOut ? 'hit the hard runtime cap' : `log-generator exited ${p.rc}`)]
    );
    return;
  }

  // 'scheduled' (still sleeping until the shared start) or 'running'.
  const next = p.phase === 'running' ? 'running' : 'scheduled';
  await query(
    `UPDATE cle_attack_target
        SET status = $2::text, clock_skew_s = $3, guest_state = $4,
            -- Both occurrences of $2 carry an explicit ::text, and they have to.
            -- Bare, the SET clause deduces $2 from the column (VARCHAR(24)) while
            -- the comparison against an unknown-type literal deduces text, and
            -- Postgres rejects the whole statement with "inconsistent types
            -- deduced for parameter $2" -- every sweep, so no target ever
            -- advanced past 'scheduled'. Same reason mailer.js writes $5::boolean.
            started_at = COALESCE(started_at, CASE WHEN $2::text = 'running' THEN NOW() ELSE NULL END),
            last_checked_at = NOW(), check_failures = 0, updated_at = NOW()
      WHERE target_id = $1`,
    [t.target_id, next, skew, guestState]
  );
}

/**
 * One sweep. Exported so tests can drive it without a timer.
 *
 * Targets are checked with bounded concurrency rather than serially: a class of
 * 30 finishing at once would otherwise take minutes to reconcile, and the run
 * would sit at 'running' long after every guest was done.
 */
async function runOnce() {
  const due = await dueTargets(MAX_CHECKS_PER_SWEEP);
  if (due.length === 0) return { checked: 0, runs: 0 };

  const CONCURRENCY = 5;
  let cursor = 0;
  const workers = Array.from({ length: Math.min(CONCURRENCY, due.length) }, async () => {
    while (cursor < due.length) {
      const t = due[cursor++];
      try {
        await checkTarget(t);
      } catch (err) {
        // One bad target must never abort the sweep for the other 29.
        console.warn(`[attack-worker] target ${t.target_id} check failed: ${err.message}`);
      }
    }
  });
  await Promise.all(workers);

  // Roll each touched run up. Cheap: one aggregate per run, not per target.
  const runIds = [...new Set(due.map((t) => t.run_id))];
  for (const runId of runIds) {
    try {
      await runner.finalizeRunStatus(runId);
    } catch (err) {
      console.warn(`[attack-worker] could not finalize run ${runId}: ${err.message}`);
    }
  }
  return { checked: due.length, runs: runIds.length };
}

async function tick() {
  if (running) return;              // previous sweep still in flight
  running = true;
  try {
    const summary = await runOnce();
    if (summary.checked) {
      console.log(`[attack-worker] checked ${summary.checked} target(s) across ${summary.runs} run(s)`);
    }
  } catch (err) {
    // Never let a sweep failure kill the interval -- the next tick may well
    // succeed, and a dead worker is a silent outage.
    console.warn('[attack-worker] sweep failed:', err.message);
  } finally {
    running = false;
  }
}

/**
 * Boot recovery. See this file's header for why it is deliberately narrow:
 * only 'dispatching' is ambiguous after a restart. A 'scheduled' or 'running'
 * guest is still going and the sweeper will find it.
 */
async function recoverAttackRuns() {
  try {
    const r = await query(
      `UPDATE cle_attack_target
          SET status = 'unknown',
              error = 'the control plane restarted while this lane was being dispatched',
              finished_at = NOW(), updated_at = NOW()
        WHERE status = 'dispatching'
        RETURNING run_id`
    );
    const runIds = [...new Set(r.rows.map((x) => x.run_id))];
    for (const runId of runIds) {
      await runner.finalizeRunStatus(runId).catch(() => {});
    }
    if (r.rowCount) {
      console.log(`[attack-worker] recovered ${r.rowCount} target(s) stranded mid-dispatch`);
    }
    // A run left 'scheduling' never got as far as inserting targets, so nothing
    // is running anywhere and it can be closed out honestly. Left in place it
    // would also hold the per-course dispatch mutex forever.
    const stuck = await query(
      `UPDATE cle_attack_run
          SET status = 'failed', error = 'the control plane restarted before dispatch began',
              finished_at = NOW()
        WHERE status = 'scheduling'`
    );
    if (stuck.rowCount) {
      console.log(`[attack-worker] closed ${stuck.rowCount} run(s) stranded before dispatch`);
    }
  } catch (err) {
    // The table may not exist yet on a first boot where the plugin migration
    // has not run. Non-fatal, exactly like ensureAuditLog's failure path.
    console.warn('[attack-worker] boot recovery skipped:', err.message);
  }
}

/** Idempotent. unref() so the timer never holds the process open. */
function startAttackWorker() {
  if (timer) return;
  timer = setInterval(tick, POLL_MS);
  if (typeof timer.unref === 'function') timer.unref();
  console.log(`[attack-worker] sweeping every ${Math.round(POLL_MS / 1000)}s`);
}

function stopAttackWorker() {
  if (timer) clearInterval(timer);
  timer = null;
}

module.exports = {
  startAttackWorker,
  stopAttackWorker,
  recoverAttackRuns,
  runOnce,
  // exported for tests
  dueTargets,
  checkTarget,
  applyPhase,
  POLL_MS,
  MAX_CHECKS_PER_SWEEP,
};
