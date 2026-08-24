/**
 * ============================================================================
 * RECONCILE JOB STATE
 * ============================================================================
 * Single-flight lock, progress document and result cache for the Proxmox audit.
 *
 * WHY REDIS RATHER THAN THE global._batchDeployProgress REGISTRY
 * The deploy path keeps progress in process memory (utils/lane-deployer.js),
 * which is right there: a deploy that dies with its process has nothing left to
 * report. A finished AUDIT does. Three things need more than a Map:
 *
 *   1. The cached result must outlive `docker compose restart app` — that is
 *      the whole point of showing "Last audited 4m ago" on tab switch.
 *   2. Single-flight must be atomic. SET NX stays correct if the app is ever
 *      scaled past one replica; a module-level boolean silently degrades into
 *      two concurrent full scans hammering the same pveproxy.
 *   3. Key expiry IS the stale-job fix. The app registers no SIGTERM handler,
 *      so a restart is abrupt by definition; a TTL that a heartbeat refreshes
 *      means a dead job's lock evaporates on its own, with no sweeper.
 *
 * The in-process fallback exists because redisClient.connect() is fired and not
 * awaited (utils/redis.js), so a request in the first seconds after boot — or
 * during a Redis outage — would otherwise sit on the offline command queue
 * forever. Correctness degrades to single-process visibility, not to a hang.
 * ============================================================================
 */

const crypto = require('crypto');
const redisClient = require('./redis');

const K_LOCK = 'cc:reconcile:lock';
const K_JOB = id => `cc:reconcile:job:${id}`;
const K_RESULT = 'cc:reconcile:result';
const K_CURRENT = 'cc:reconcile:current';

const LOCK_TTL_MS = 120000;
const HEARTBEAT_MS = 10000;
const JOB_TTL_S = 3600;
const RESULT_TTL_S = 86400;
/** A job doc older than this with the lock still held is a zombie. */
const STALE_AFTER_MS = 150000;
/** Redis values above this are not worth the round trip on every poll. */
const MAX_RESULT_BYTES = 4_000_000;

const JOB_ID_RE = /^rc_[a-z0-9_]{8,48}$/;

/** In-process fallback tier. */
const MEM = { lock: null, lockExpires: 0, jobs: new Map(), result: null, current: null };

const heartbeats = new Map();

function newJobId() {
  return `rc_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
}

function isValidJobId(id) {
  return typeof id === 'string' && JOB_ID_RE.test(id);
}

const live = () => redisClient && redisClient.isReady === true;

/**
 * A Redis call with a hard ceiling and a fallback.
 * The offline command queue must never be allowed to hang an HTTP request.
 */
async function rc(fn, fallback) {
  if (!live()) return fallback();
  try {
    return await Promise.race([
      fn(redisClient),
      new Promise((_, rej) => {
        const t = setTimeout(() => rej(new Error('redis timeout')), 1500);
        if (typeof t.unref === 'function') t.unref();
      }),
    ]);
  } catch (e) {
    console.warn(`[Reconcile] Redis unavailable (${e.message}) — using in-process store`);
    return fallback();
  }
}

// A plain PEXPIRE would revive a lock that a NEW job already owns, and a plain
// DEL would release someone else's. Both are compare-and-act.
const LUA_REFRESH = `
  if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('pexpire', KEYS[1], ARGV[2])
  end
  return 0`;

const LUA_RELEASE = `
  if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
  end
  return 0`;

function memLockOwner() {
  if (MEM.lock && MEM.lockExpires > Date.now()) return MEM.lock;
  MEM.lock = null;
  return null;
}

async function getLockOwner() {
  return rc(c => c.get(K_LOCK), () => memLockOwner());
}

async function writeJob(doc) {
  doc.updated_at = new Date().toISOString();
  await rc(
    c => c.set(K_JOB(doc.job_id), JSON.stringify(doc), { EX: JOB_TTL_S }),
    () => { MEM.jobs.set(doc.job_id, doc); return 'OK'; }
  );
  return doc;
}

async function readJob(jobId) {
  const raw = await rc(c => c.get(K_JOB(jobId)), () => {
    const d = MEM.jobs.get(jobId);
    return d ? JSON.stringify(d) : null;
  });
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

function startHeartbeat(jobId) {
  const timer = setInterval(async () => {
    const held = await rc(
      c => c.eval(LUA_REFRESH, { keys: [K_LOCK], arguments: [jobId, String(LOCK_TTL_MS)] }),
      () => {
        if (memLockOwner() !== jobId) return 0;
        MEM.lockExpires = Date.now() + LOCK_TTL_MS;
        return 1;
      }
    );
    // Losing the lock means this process restarted and another job took over.
    // Stop writing so a zombie cannot overwrite a live job's progress.
    if (!held) {
      console.warn(`[Reconcile] Job ${jobId} no longer owns the scan lock — halting progress writes`);
      stopHeartbeat(jobId);
    }
  }, HEARTBEAT_MS);
  if (typeof timer.unref === 'function') timer.unref();
  heartbeats.set(jobId, timer);
}

function stopHeartbeat(jobId) {
  const t = heartbeats.get(jobId);
  if (t) { clearInterval(t); heartbeats.delete(jobId); }
}

/**
 * Claim the right to run a scan, or attach to the one already running.
 *
 * `force` clears a lock ONLY when the job holding it is demonstrably stale by
 * the same rule getJobStatus uses. It is not a way to run two scans at once.
 */
async function acquireJob({ force = false, startedBy = null } = {}) {
  if (force) {
    const owner = await getLockOwner();
    if (owner) {
      const doc = await readJob(owner);
      const stale = !doc || (Date.now() - Date.parse(doc.updated_at || 0) > STALE_AFTER_MS);
      if (stale) {
        await rc(
          c => c.eval(LUA_RELEASE, { keys: [K_LOCK], arguments: [owner] }),
          () => { if (memLockOwner() === owner) MEM.lock = null; return 1; }
        );
      }
    }
  }

  const jobId = newJobId();
  const acquired = await rc(
    c => c.set(K_LOCK, jobId, { NX: true, PX: LOCK_TTL_MS }),
    () => {
      if (memLockOwner()) return null;
      MEM.lock = jobId;
      MEM.lockExpires = Date.now() + LOCK_TTL_MS;
      return 'OK';
    }
  );

  if (acquired !== 'OK') {
    const owner = await getLockOwner();
    const existing = owner ? await readJob(owner) : null;
    if (existing) return { attached: true, job: existing };
    // Lock held but no readable doc — treat as claimable rather than deadlock.
    return { attached: true, job: { job_id: owner || 'unknown', state: 'running', phase: 'cluster' } };
  }

  const doc = {
    job_id: jobId,
    state: 'running',
    phase: 'cluster',
    phase_detail: null,
    done: 0,
    total: 1,
    started_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    finished_at: null,
    error: null,
    started_by: startedBy,
  };
  await writeJob(doc);
  await rc(c => c.set(K_CURRENT, jobId, { EX: JOB_TTL_S }), () => { MEM.current = jobId; return 'OK'; });
  startHeartbeat(jobId);
  return { attached: false, job: doc };
}

async function updateJob(jobId, patch) {
  if (!heartbeats.has(jobId)) return null;   // lost the lock; see startHeartbeat
  const doc = await readJob(jobId);
  if (!doc || doc.state !== 'running') return null;
  return writeJob({ ...doc, ...patch });
}

async function finishJob(jobId, result, durationMs) {
  const doc = (await readJob(jobId)) || { job_id: jobId };
  const payload = { ...result, generated_at: new Date().toISOString(), job_id: jobId, duration_ms: durationMs };
  const serialized = JSON.stringify(payload);

  if (serialized.length > MAX_RESULT_BYTES) {
    console.warn(`[Reconcile] Result is ${serialized.length} bytes — exceeds the ${MAX_RESULT_BYTES} cache ceiling, not caching`);
  } else {
    await rc(c => c.set(K_RESULT, serialized, { EX: RESULT_TTL_S }), () => { MEM.result = payload; return 'OK'; });
  }

  return writeJob({
    ...doc, state: 'done', phase: 'done', done: 1, total: 1,
    finished_at: new Date().toISOString(), error: null,
  });
}

async function failJob(jobId, message) {
  const doc = (await readJob(jobId)) || { job_id: jobId };
  return writeJob({ ...doc, state: 'error', error: message, finished_at: new Date().toISOString() });
}

async function releaseJob(jobId) {
  stopHeartbeat(jobId);
  await rc(
    c => c.eval(LUA_RELEASE, { keys: [K_LOCK], arguments: [jobId] }),
    () => { if (memLockOwner() === jobId) MEM.lock = null; return 1; }
  );
}

/**
 * A job's status, with liveness resolved at READ time rather than by a sweeper.
 *
 * A doc that still says `running` while the lock is gone (or has not been
 * touched in STALE_AFTER_MS) belongs to a process that died mid-scan. Reporting
 * that as "running" would leave the UI spinning forever.
 */
async function getJobStatus(jobId) {
  if (!isValidJobId(jobId)) return null;
  const doc = await readJob(jobId);
  if (!doc) return null;

  if (doc.state === 'running') {
    const owner = await getLockOwner();
    const stale = Date.now() - Date.parse(doc.updated_at || 0) > STALE_AFTER_MS;
    if (owner !== doc.job_id || stale) {
      const aborted = {
        ...doc, state: 'error', aborted: true,
        error: 'Scan aborted — the server restarted during the audit. Re-run it.',
      };
      await writeJob(aborted);     // best effort, so later polls agree
      return aborted;
    }
  }

  const started = Date.parse(doc.started_at || 0);
  const end = doc.finished_at ? Date.parse(doc.finished_at) : Date.now();
  return { ...doc, elapsed_s: started ? Math.max(0, Math.round((end - started) / 1000)) : 0 };
}

/** The last completed audit, or null. */
async function getCachedResult() {
  const raw = await rc(c => c.get(K_RESULT), () => (MEM.result ? JSON.stringify(MEM.result) : null));
  if (!raw) return null;
  try {
    const payload = JSON.parse(raw);
    const generated = Date.parse(payload.generated_at || 0);
    return {
      ...payload,
      age_seconds: generated ? Math.max(0, Math.round((Date.now() - generated) / 1000)) : null,
    };
  } catch (_) {
    return null;
  }
}

/** The in-flight (or most recent) job id, so a fresh page load can attach. */
async function getRunningJobId() {
  const owner = await getLockOwner();
  if (owner) return owner;
  return rc(c => c.get(K_CURRENT), () => MEM.current);
}

module.exports = {
  acquireJob, updateJob, finishJob, failJob, releaseJob,
  getJobStatus, getCachedResult, getRunningJobId, getLockOwner,
  isValidJobId, newJobId,
  LOCK_TTL_MS, STALE_AFTER_MS, MAX_RESULT_BYTES,
  _internals: { MEM, K_LOCK, K_RESULT, K_CURRENT, K_JOB },
};
