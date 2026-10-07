/**
 * reconcile-job.test.js — single-flight, heartbeat, and the zombie-job rule.
 *
 * THE CASE THAT MATTERS MOST
 * The app registers no SIGTERM handler, so `docker compose restart app` kills a
 * running audit mid-scan. The job document is left saying `running` forever,
 * and a UI that trusts it spins until someone reloads. There is deliberately no
 * sweeper: liveness is derived at READ time from the lock, which a heartbeat
 * refreshes and which expires on its own once the heartbeat stops. "the server
 * died mid-scan" below is that rule.
 *
 * The heartbeat is also compare-and-set rather than a plain PEXPIRE, because a
 * zombie that refreshed unconditionally would keep renewing a lock a NEW job
 * already owns, and then overwrite that job's progress.
 *
 * Run: node front-end/test/reconcile-job.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const Module = require('module');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
const REDIS_PATH = require.resolve(path.join(UTILS, 'redis.js'));

/**
 * A minimal Redis with the handful of commands this module uses, plus TTL
 * bookkeeping so expiry can be simulated without waiting.
 */
function fakeRedis({ ready = true } = {}) {
  const store = new Map();   // key -> { value, expiresAt|null }
  const alive = (e) => e && (e.expiresAt === null || e.expiresAt > Date.now());
  const get = (k) => (alive(store.get(k)) ? store.get(k).value : (store.delete(k), null));

  return {
    isReady: ready,
    _store: store,
    _expire: (k) => { const e = store.get(k); if (e) e.expiresAt = Date.now() - 1; },
    async get(k) { return get(k); },
    async set(k, v, opts = {}) {
      if (opts.NX && get(k) !== null) return null;
      const ttl = opts.PX ? opts.PX : (opts.EX ? opts.EX * 1000 : null);
      store.set(k, { value: v, expiresAt: ttl ? Date.now() + ttl : null });
      return 'OK';
    },
    async del(k) { return store.delete(k) ? 1 : 0; },
    async eval(script, { keys, arguments: args }) {
      const current = get(keys[0]);
      if (current !== args[0]) return 0;
      if (/pexpire/.test(script)) {
        store.get(keys[0]).expiresAt = Date.now() + Number(args[1]);
        return 1;
      }
      store.delete(keys[0]);
      return 1;
    },
  };
}

/** Load a pristine reconcile-job bound to a fresh fake Redis. */
function loadJobModule(redis) {
  delete require.cache[require.resolve(path.join(UTILS, 'reconcile-job.js'))];
  require.cache[REDIS_PATH] = {
    id: REDIS_PATH, filename: REDIS_PATH, loaded: true, exports: redis,
  };
  const mod = require(path.join(UTILS, 'reconcile-job.js'));
  return mod;
}

// ============================================================================

test('two admins clicking at once share ONE scan', async () => {
  const J = loadJobModule(fakeRedis());
  const first = await J.acquireJob({ startedBy: 'u1' });
  const second = await J.acquireJob({ startedBy: 'u2' });

  assert.strictEqual(first.attached, false);
  assert.strictEqual(second.attached, true);
  assert.strictEqual(second.job.job_id, first.job.job_id,
    'the second admin joins rather than doubling the load on pveproxy');
  await J.releaseJob(first.job.job_id);
});

test('releasing the lock lets the next scan start', async () => {
  const J = loadJobModule(fakeRedis());
  const a = await J.acquireJob({});
  await J.releaseJob(a.job.job_id);
  const b = await J.acquireJob({});
  assert.strictEqual(b.attached, false);
  assert.notStrictEqual(b.job.job_id, a.job.job_id);
});

test('a job cannot release a lock it does not own', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const a = await J.acquireJob({});
  await J.releaseJob('rc_someoneelse_00000000');
  assert.strictEqual(await J.getLockOwner(), a.job.job_id,
    'compare-and-delete, or a stale finisher frees a live scan');
});

test('THE RESTART CASE: a running doc with no lock resolves to aborted', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const { job } = await J.acquireJob({});

  // Simulate the process dying: the lock expires, the doc still says running.
  redis._expire(J._internals.K_LOCK);

  const status = await J.getJobStatus(job.job_id);
  assert.strictEqual(status.state, 'error');
  assert.strictEqual(status.aborted, true);
  assert.match(status.error, /server restarted/);

  const again = await J.getJobStatus(job.job_id);
  assert.strictEqual(again.state, 'error', 'the resolution is persisted, so polls agree');
});

test('a lock held by a DIFFERENT job also aborts the old one', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const a = await J.acquireJob({});
  redis._store.set(J._internals.K_LOCK, { value: 'rc_newowner_11111111', expiresAt: null });

  const status = await J.getJobStatus(a.job.job_id);
  assert.strictEqual(status.state, 'error');
  assert.strictEqual(status.aborted, true);
});

test('force clears a demonstrably stale lock, and only then', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const a = await J.acquireJob({});

  // Fresh job: force must NOT steal the lock.
  const blocked = await J.acquireJob({ force: true });
  assert.strictEqual(blocked.attached, true, 'force is not a way to run two scans at once');
  assert.strictEqual(blocked.job.job_id, a.job.job_id);

  // Age the doc past the staleness threshold.
  const key = J._internals.K_JOB(a.job.job_id);
  const doc = JSON.parse(redis._store.get(key).value);
  doc.updated_at = new Date(Date.now() - J.STALE_AFTER_MS - 5000).toISOString();
  redis._store.set(key, { value: JSON.stringify(doc), expiresAt: null });

  const forced = await J.acquireJob({ force: true });
  assert.strictEqual(forced.attached, false, 'a zombie lock must be reclaimable');
});

test('progress writes stop once the lock is lost', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const { job } = await J.acquireJob({});

  assert.ok(await J.updateJob(job.job_id, { phase: 'storage', done: 3, total: 11 }));
  let doc = JSON.parse(redis._store.get(J._internals.K_JOB(job.job_id)).value);
  assert.strictEqual(doc.done, 3);

  await J.releaseJob(job.job_id);   // stops the heartbeat, as a finished job does
  assert.strictEqual(await J.updateJob(job.job_id, { done: 9 }), null,
    'a zombie must not overwrite a live job that took over');
  doc = JSON.parse(redis._store.get(J._internals.K_JOB(job.job_id)).value);
  assert.strictEqual(doc.done, 3, 'the last owned write stands');
});

test('a finished job caches its result with an age', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const { job } = await J.acquireJob({});
  await J.finishJob(job.job_id, { summary: { orphaned_disks: 2 } }, 6400);
  await J.releaseJob(job.job_id);

  const cached = await J.getCachedResult();
  assert.strictEqual(cached.summary.orphaned_disks, 2);
  assert.strictEqual(cached.duration_ms, 6400);
  assert.strictEqual(cached.job_id, job.job_id);
  assert.strictEqual(typeof cached.age_seconds, 'number');

  const status = await J.getJobStatus(job.job_id);
  assert.strictEqual(status.state, 'done');
  assert.strictEqual(typeof status.elapsed_s, 'number');
});

test('an oversized result is skipped rather than cached', async () => {
  const redis = fakeRedis();
  const J = loadJobModule(redis);
  const { job } = await J.acquireJob({});
  await J.finishJob(job.job_id, { blob: 'x'.repeat(J.MAX_RESULT_BYTES + 10) }, 1);

  assert.strictEqual(await J.getCachedResult(), null, 'no cache entry');
  const status = await J.getJobStatus(job.job_id);
  assert.strictEqual(status.state, 'done', 'the job still completes cleanly');
});

test('a failed job records why', async () => {
  const J = loadJobModule(fakeRedis());
  const { job } = await J.acquireJob({});
  await J.failJob(job.job_id, 'Proxmox GET /api2/json/nodes timed out after 15s');
  await J.releaseJob(job.job_id);

  const status = await J.getJobStatus(job.job_id);
  assert.strictEqual(status.state, 'error');
  assert.match(status.error, /timed out after 15s/);
  assert.ok(!status.aborted, 'a real failure is not the restart case');
});

test('Redis being down falls back to memory rather than hanging', async () => {
  const J = loadJobModule(fakeRedis({ ready: false }));
  const { job, attached } = await J.acquireJob({ startedBy: 'u1' });
  assert.strictEqual(attached, false);

  assert.strictEqual((await J.acquireJob({})).attached, true, 'single-flight still holds in-process');
  await J.updateJob(job.job_id, { phase: 'storage', done: 2, total: 5 });
  assert.strictEqual((await J.getJobStatus(job.job_id)).done, 2);

  await J.finishJob(job.job_id, { summary: {} }, 100);
  await J.releaseJob(job.job_id);
  assert.ok(await J.getCachedResult(), 'the whole lifecycle works without Redis');
});

test('job ids are validated before they reach a Redis key', async () => {
  const J = loadJobModule(fakeRedis());
  assert.ok(J.isValidJobId(J.newJobId()));
  for (const bad of ['../../etc', 'rc_short', 'nope', '', null, 'rc_' + 'x'.repeat(60)]) {
    assert.ok(!J.isValidJobId(bad), `accepted a malformed id: ${bad}`);
  }
  assert.strictEqual(await J.getJobStatus('cc:reconcile:lock'), null);
});

test('an unknown job id reads as absent, not as an error', async () => {
  const J = loadJobModule(fakeRedis());
  assert.strictEqual(await J.getJobStatus('rc_deadbeef_00000000'), null);
});
