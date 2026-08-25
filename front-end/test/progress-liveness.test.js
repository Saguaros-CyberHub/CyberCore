/**
 * progress-liveness.test.js — the deploy progress registry as a mutex.
 *
 * THE BUG THIS PINS (reported from the UI)
 *
 *   Another operation on this lab is still running (0/1, Deploying lanes
 *   (5 at a time, max 4 concurrent clones)). Wait for it to finish — running
 *   both at once would leave machines behind with nothing pointing at them.
 *
 * ...for an operation that had already died. `global._batchDeployProgress` is
 * the only mutex this app has, and assertNoConflictingLabOperation refuses while
 * an entry sits in any phase other than 'complete'. The entry had no liveness of
 * any kind, so a deploy that threw between initProgress and finishProgress
 * locked its lab until someone restarted the process — and the UI could only
 * advise waiting for something that would never finish.
 *
 * WHY A HEARTBEAT AND NOT AN AGE BOUND
 * The slow steps are silent. A lane clone runs for minutes and a GOAD bake for
 * over an hour with nothing touching the entry, so "started more than N minutes
 * ago" cannot separate a dead operation from a healthy slow one. Getting that
 * wrong is not a cosmetic failure: it lets a teardown run against a live deploy,
 * which is precisely the case the mutex exists to prevent. So the owner beats,
 * and only silence counts.
 *
 * The asymmetry matters and is asserted below: a false positive here destroys
 * machines, a false negative just means waiting longer.
 *
 * Run: node front-end/test/progress-liveness.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stubModule(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

stubModule('cybercore-db.js', { cybercorePool: {}, cybercoreQuery: async () => ({ rows: [], rowCount: 0 }) });
stubModule('proxmox.js', {
  proxmoxAPI: async () => ({}), waitForTask: async () => ({}),
  forceDestroyVM: async () => true, findTemplateNode: async () => 'node1',
  waitForVmidsGone: async () => ({ surviving: [] }), PROXMOX_URL: 'https://x:8006',
});
stubModule('node-ssh.js', { nodeExec: async () => ({ stdout: '' }), pctExec: async () => ({ stdout: '' }), pctExecWithStdin: async () => ({ stdout: '' }), pctPushFromString: async () => ({ stdout: '' }) });
stubModule('node-selector.js', { selectBestNode: async () => ({ node: 'node1' }) });
stubModule('site-config.js', {
  getDefaultTemplateNode: () => 'node1', getSchedulingConfig: () => ({}),
  getClusterNodes: () => ['node1'], getNodeAddress: () => '10.0.0.1',
  getV2LabNetwork: () => ({ bridge: 'vmbr0', vlan_tag: 60, cidr: '/24', subnet_base: '100.100.60.0' }),
  getPhysicalClusterIps: () => ({ node1: '10.0.0.1' }),
});
stubModule('guacamole.js', { guacAPI: async () => ({}) });
stubModule('guac-credentials.js', { ensureGuacUser: async () => true, getGuacCredentials: async () => null });
stubModule('tailscale.js', { deleteLaneDevices: async () => 0, isEnabled: () => false });
stubModule('lane-wan-allocator.js', {
  allocateLaneWanIps: async () => [], releaseLaneWanIps: async () => {},
  recordLaneWanLease: async () => {}, findWanIpConflicts: async () => [],
});

const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));

const ID = 'lab-test-progress';
const raw = () => global._batchDeployProgress[ID];
/** Backdate the heartbeat, the only way to reach staleness without waiting. */
const silentFor = (ms) => { raw()._beatAtMs = Date.now() - ms; };

function fresh() {
  const p = laneDeployer.initProgress(ID, 'test', 1);
  laneDeployer.setPhase(p, 'deploying', 'Deploying lanes');
  return p;
}

// ── a live operation is never touched ───────────────────────────────────────

test('a freshly started operation is live', () => {
  fresh();
  const p = laneDeployer.readProgress(ID);
  assert.strictEqual(p.stale, false);
  assert.ok(p.idle_s < 5, `idle_s should be ~0, got ${p.idle_s}`);
  laneDeployer.finishProgress(ID);
});

test('an operation quiet for less than the bound is STILL live', () => {
  // The safety-critical direction. A lane clone is silent for minutes; calling
  // that dead would let a teardown run against a deploy that is mid-flight.
  fresh();
  silentFor(laneDeployer.PROGRESS_STALE_AFTER_MS - 5000);
  assert.strictEqual(laneDeployer.readProgress(ID).stale, false,
    'an operation still inside the bound must never be declared dead — a false '
    + 'positive here lets a teardown destroy a live deploy');
  laneDeployer.finishProgress(ID);
});

test('the bound is many missed beats, not one', () => {
  // A single missed interval must not be enough; the event loop can stall.
  assert.ok(laneDeployer.PROGRESS_STALE_AFTER_MS >= 60000,
    'the staleness bound must be generous relative to the 15s heartbeat — a '
    + 'false positive is destructive, a false negative only costs waiting');
});

// ── a dead one stops blocking ───────────────────────────────────────────────

test('an operation that stopped beating goes stale', () => {
  fresh();
  silentFor(laneDeployer.PROGRESS_STALE_AFTER_MS + 5000);
  const p = laneDeployer.readProgress(ID);
  assert.strictEqual(p.stale, true);
  assert.ok(p.idle_s > 100, `idle_s should report the silence, got ${p.idle_s}`);
  laneDeployer.finishProgress(ID);
});

test('a completed entry is never stale, however old', () => {
  // 'complete' entries linger an hour so a late poller can still read the
  // outcome. They are finished work; the caller skips them by phase, and they
  // must not also be reported as abandoned.
  fresh();
  laneDeployer.finishProgress(ID);
  raw()._beatAtMs = Date.now() - 86400000;
  const p = laneDeployer.readProgress(ID);
  assert.strictEqual(p.phase, 'complete');
  assert.strictEqual(p.stale, false);
});

test('finishing stops the heartbeat', () => {
  fresh();
  laneDeployer.finishProgress(ID);
  // Nothing may resurrect a finished entry's beat — that would keep a completed
  // operation looking alive forever.
  const beat = raw()._beatAtMs;
  assert.strictEqual(laneDeployer.readProgress(ID).phase, 'complete');
  assert.strictEqual(raw()._beatAtMs, beat);
});

// ── the accessor contract the mutex depends on ──────────────────────────────

test('staleness is computed in readProgress, not left to the caller', () => {
  // labOperationsInFlight only ever sees the read copy, and the destructure in
  // readProgress strips the underscore bookkeeping. If `stale` were derived by
  // the caller from _beatAtMs it would silently become undefined — and
  // `if (p.stale)` on undefined means "never stale", i.e. the bug returns with
  // no test failing.
  fresh();
  silentFor(laneDeployer.PROGRESS_STALE_AFTER_MS + 5000);
  const p = laneDeployer.readProgress(ID);
  assert.ok(!('_beatAtMs' in p), '_beatAtMs must not leak into the read copy');
  assert.ok(!('_startedAtMs' in p), '_startedAtMs must not leak either');
  assert.strictEqual(typeof p.stale, 'boolean', 'stale must always be a real boolean');
  laneDeployer.finishProgress(ID);
});

test('the mutex skips stale entries but keeps live ones', () => {
  // The consumer, exercised directly: labOperationsInFlight filters on p.stale.
  const src = require('fs').readFileSync(
    path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils', 'vuln-lab-provision.js'),
    'utf8');
  const at = src.indexOf('function labOperationsInFlight');
  assert.notStrictEqual(at, -1);
  const fn = src.slice(at, at + 1600);
  assert.match(fn, /if \(p\.stale\)/,
    'labOperationsInFlight must drop stale entries, or a dead deploy locks its lab forever');
  assert.match(fn, /p\.phase === 'complete'/,
    'and must still skip completed ones');
});
