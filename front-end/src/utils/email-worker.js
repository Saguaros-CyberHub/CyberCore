/**
 * ============================================================================
 * EMAIL WORKER
 * ============================================================================
 * Background sweeper that drains the outbox. Follows the in-repo sweeper shape
 * (see ciab/utils/vuln-app-builder.js): a setInterval whose handle is unref'd
 * so it never holds the process open, plus a module-level guard so a slow drain
 * cannot overlap itself.
 *
 * Overlap matters more than it looks. Two concurrent drains would each claim a
 * batch, and while FOR UPDATE SKIP LOCKED keeps them from claiming the SAME
 * rows, a relay that has gone slow would just accumulate in-flight sends until
 * the connection pool is exhausted and unrelated requests start failing.
 */

const mailer = require('./mailer');

const POLL_MS = Number(process.env.MAIL_POLL_MS) > 0
  ? Number(process.env.MAIL_POLL_MS) : 15_000;

const BATCH = Number(process.env.MAIL_RATE_PER_MIN) > 0
  // Convert a per-minute budget into a per-tick batch, so raising the rate
  // limit does not silently change the tick interval too.
  ? Math.max(1, Math.ceil(Number(process.env.MAIL_RATE_PER_MIN) / (60_000 / POLL_MS)))
  : 25;

// Once a day, in ticks.
const PRUNE_EVERY = Math.max(1, Math.floor(86_400_000 / POLL_MS));

let timer = null;
let running = false;
let ticks = 0;

async function tick() {
  if (running) return;          // previous drain still in flight
  running = true;
  try {
    const summary = await mailer.drainOutbox({ limit: BATCH });
    if (summary.sent || summary.failed || summary.deferred) {
      console.log(
        `[mail-worker] sent ${summary.sent}, deferred ${summary.deferred}, failed ${summary.failed}`
      );
    }

    if (++ticks % PRUNE_EVERY === 0) {
      const pruned = await mailer.pruneOutbox();
      if (pruned > 0) console.log(`[mail-worker] pruned ${pruned} old outbox row(s)`);
    }
  } catch (err) {
    // Never let a sweep failure kill the interval — the next tick may well
    // succeed, and a dead worker is a silent outage.
    console.warn('[mail-worker] sweep failed:', err.message);
  } finally {
    running = false;
  }
}

/**
 * Idempotent. A no-op when mail is not configured, so a deployment running
 * without email never spins a pointless timer.
 */
function startEmailWorker() {
  if (timer) return;
  if (!mailer.mailEnabled()) {
    console.log('ℹ️  Email worker not started (MAIL_ENABLED is not "true" or MAIL_HOST is unset)');
    return;
  }
  if (!mailer.mailKey()) {
    console.warn('⚠️  Email worker not started: no MAIL_ENCRYPT_KEY / MFA_ENCRYPT_KEY / GUAC_ENCRYPT_KEY, so message bodies cannot be stored securely.');
    return;
  }

  // Anything claimed by a process that died is ours to reclaim; nothing else
  // will ever pick those rows up.
  mailer.requeueStalledSends().catch(() => {});

  timer = setInterval(tick, POLL_MS);
  // Do not keep the event loop alive on shutdown.
  if (typeof timer.unref === 'function') timer.unref();
  console.log(`✅ Email worker started (every ${Math.round(POLL_MS / 1000)}s, up to ${BATCH} per sweep)`);
}

function stopEmailWorker() {
  if (timer) clearInterval(timer);
  timer = null;
  ticks = 0;
}

/** Test seam: run one sweep synchronously. */
async function runOnce() {
  return tick();
}

module.exports = { startEmailWorker, stopEmailWorker, runOnce, POLL_MS, BATCH };
