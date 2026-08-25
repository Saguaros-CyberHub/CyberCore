/**
 * vxlan-allocation.test.js — two concurrent deploys must not get the same id.
 *
 * THE BUG THIS PINS (observed in production)
 *
 *   ERROR CyberCore query error: duplicate key value violates unique constraint
 *         "ux_cybercore_lane_vxlan_active"
 *   ERROR [ChallengeLane] [CYBRWarfare] Failed to create lane record for <student>
 *   ERROR [CLE] Redeploy failed for <user> on lab <lab>
 *
 * allocateVxlanIds reads COMMITTED rows. A caller does not become visible to
 * that query until its INSERT lands, and deployChallengeLanes allocates at the
 * top of the batch and inserts each row much later — after resolveVnets and the
 * WAN allocation. Everything in that window is invisible to a concurrent caller.
 *
 * The window is not narrow, and the lab mutex deliberately leaves it open:
 * assertNoConflictingLabOperation scopes its claim per STUDENT, precisely so one
 * student's redeploy does not block another's ("Another student's redeploy is
 * independent and must not block"). Both redeploys then draw from the same
 * challenge's VXLAN block, each asking for ONE id — so each runs
 * `ORDER BY gs LIMIT 1` and gets the same LOWEST free id. This is not a narrow
 * race; two redeploys seconds apart collide almost every time.
 *
 * The unique index catches it, which is why it surfaces as a failed deploy
 * rather than two lanes silently sharing an L2 segment. But the deploy is still
 * lost, half-built, and the student sees nothing.
 *
 * Run: node front-end/test/vxlan-allocation.test.js   (or npm test)
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

// The rows allocateVxlanIds would see. Nothing here commits, which is exactly
// the condition being modelled: allocation happens, the INSERT has not yet.
let committedVxlans = [];
let queryCount = 0;
/** Resolves the next query only when released, so overlap can be forced. */
let gate = null;

stubModule('cybercore-db.js', {
  cybercorePool: {},
  cybercoreQuery: async (sql, params) => {
    if (!/generate_series/.test(sql)) return { rows: [], rowCount: 0 };
    queryCount += 1;
    const [start, end, limit, reserved] = params;
    if (gate) await gate;
    const taken = new Set([...committedVxlans, ...(reserved || [])]);
    const rows = [];
    for (let id = start; id <= end && rows.length < limit; id += 1) {
      if (!taken.has(id)) rows.push({ vxlan_id: id });
    }
    return { rows, rowCount: rows.length };
  },
});

// lane-deployer pulls in a wide graph at require time; none of it is exercised
// by allocateVxlanIds, but it all has to load.
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

const BLOCK = { start: 10000, end: 10009 };

function reset() {
  committedVxlans = [];
  queryCount = 0;
  gate = null;
  // Ids parked by an earlier case must not leak into the next one.
  laneDeployer.releaseVxlanReservations(
    Array.from({ length: 20 }, (_, i) => BLOCK.start + i));
}

// ── the collision ───────────────────────────────────────────────────────────

test('two overlapping single-lane allocations never get the same id', async () => {
  reset();
  // Both calls start before either has inserted anything — the production
  // sequence exactly. Without the reservation set both would return 10000.
  let release;
  gate = new Promise((r) => { release = r; });

  const a = laneDeployer.allocateVxlanIds(BLOCK, 1);
  const b = laneDeployer.allocateVxlanIds(BLOCK, 1);
  release();
  const [first, second] = await Promise.all([a, b]);

  assert.strictEqual(first.length, 1);
  assert.strictEqual(second.length, 1);
  assert.notStrictEqual(first[0], second[0],
    'both deploys were handed the same VXLAN — the second INSERT dies on '
    + 'ux_cybercore_lane_vxlan_active and the deploy is lost half-built');
  assert.deepStrictEqual([first[0], second[0]].sort((x, y) => x - y), [10000, 10001]);
});

test('a batch and a single lane do not overlap either', async () => {
  reset();
  const batch = await laneDeployer.allocateVxlanIds(BLOCK, 3);
  const single = await laneDeployer.allocateVxlanIds(BLOCK, 1);
  assert.deepStrictEqual(batch, [10000, 10001, 10002]);
  assert.deepStrictEqual(single, [10003]);
  assert.strictEqual(batch.filter(id => single.includes(id)).length, 0);
});

test('allocation is serialized, not merely filtered', async () => {
  reset();
  // If the two bodies interleaved between the read and the reserve, both would
  // still see an empty reservation set. Overlapping ten callers is the cheap way
  // to catch a regression that removes the mutex but keeps the Map.
  const ids = (await Promise.all(
    Array.from({ length: 10 }, () => laneDeployer.allocateVxlanIds(BLOCK, 1))
  )).flat();
  assert.strictEqual(new Set(ids).size, 10, `ids collided: ${ids.join(', ')}`);
});

// ── giving them back ────────────────────────────────────────────────────────

test('released ids return to the pool', async () => {
  reset();
  const first = await laneDeployer.allocateVxlanIds(BLOCK, 2);
  assert.deepStrictEqual(first, [10000, 10001]);

  // The deploy finished: its rows are committed, so the reservation is dead
  // weight and holding it would only shrink the pool.
  committedVxlans = [10000, 10001];
  laneDeployer.releaseVxlanReservations(first);

  const next = await laneDeployer.allocateVxlanIds(BLOCK, 1);
  assert.deepStrictEqual(next, [10002], 'committed ids stay out, via the DB query');
});

test('a failed deploy hands its ids straight back', async () => {
  reset();
  const taken = await laneDeployer.allocateVxlanIds(BLOCK, 2);
  // Nothing was ever inserted, so the reservation is the ONLY thing holding
  // these — release must make them immediately reusable.
  laneDeployer.releaseVxlanReservations(taken);
  const retry = await laneDeployer.allocateVxlanIds(BLOCK, 2);
  assert.deepStrictEqual(retry, taken);
});

test('releasing is idempotent and tolerates ids it never held', () => {
  reset();
  assert.doesNotThrow(() => laneDeployer.releaseVxlanReservations([99999]));
  assert.doesNotThrow(() => laneDeployer.releaseVxlanReservations([99999]));
  assert.doesNotThrow(() => laneDeployer.releaseVxlanReservations(12345));
});

// ── capacity is still reported honestly ─────────────────────────────────────

test('an exhausted block returns fewer ids rather than reusing one', async () => {
  reset();
  const all = await laneDeployer.allocateVxlanIds(BLOCK, 10);
  assert.strictEqual(all.length, 10);
  const none = await laneDeployer.allocateVxlanIds(BLOCK, 1);
  assert.deepStrictEqual(none, [],
    'callers check `vxlans.length < users.length` and raise a capacity error; '
    + 'handing back a duplicate instead would turn that into a deploy failure');
});

test('the reservation set never hides an id the DB already rules out', async () => {
  reset();
  committedVxlans = [10000, 10001, 10002];
  const ids = await laneDeployer.allocateVxlanIds(BLOCK, 2);
  assert.deepStrictEqual(ids, [10003, 10004]);
  assert.ok(queryCount > 0, 'the DB must still be consulted, not just the Map');
});

// ── probes must not consume capacity ────────────────────────────────────────
//
// THE REGRESSION THIS PINS (observed in production, caused by the fix above):
//
//   Error deploying environments: 'Cyber Warfare CYBR480' has 0 free lane(s)
//   in its VXLAN block but 1 student(s) were selected.
//
// countFreeLanes (cle/utils/vuln-lab-provision.js) counts capacity by calling
// allocateVxlanIds for the WHOLE block and taking .length. Once allocation
// started reserving, merely opening the deploy dialog parked every free id for
// the reservation TTL — so the check that was supposed to report capacity was
// the thing destroying it, and the block read as full until the TTL expired.
//
// routes/admin/groups.js does the same thing for the group deploy preflight.

test('a probe reports capacity without consuming it', async () => {
  reset();
  const probe = await laneDeployer.allocateVxlanIds(BLOCK, 10, { reserve: false });
  assert.strictEqual(probe.length, 10, 'the probe must see the whole free block');

  // Reading capacity twice must give the same answer — it did not, before.
  const again = await laneDeployer.allocateVxlanIds(BLOCK, 10, { reserve: false });
  assert.deepStrictEqual(again, probe, 'a second probe must agree with the first');

  // And the deploy that follows must still find the block free.
  const real = await laneDeployer.allocateVxlanIds(BLOCK, 3);
  assert.deepStrictEqual(real, [10000, 10001, 10002]);
});

test('a probe still excludes ids another deploy is holding', async () => {
  reset();
  // Honest in the direction that matters: an id reserved for an in-flight
  // deploy is genuinely unavailable, so counting it as free would over-report.
  const held = await laneDeployer.allocateVxlanIds(BLOCK, 4);
  assert.strictEqual(held.length, 4);

  const probe = await laneDeployer.allocateVxlanIds(BLOCK, 10, { reserve: false });
  assert.strictEqual(probe.length, 6, 'the four in flight must not be counted free');
  assert.strictEqual(probe.filter(id => held.includes(id)).length, 0);
});

test('reserve defaults to true, so a claim is never silently a probe', async () => {
  reset();
  const first = await laneDeployer.allocateVxlanIds(BLOCK, 1);
  const second = await laneDeployer.allocateVxlanIds(BLOCK, 1, {});
  assert.notStrictEqual(first[0], second[0],
    'omitting the option must still reserve — the default protects every '
    + 'existing caller that was written before this option existed');
});

// ── capacity shortfall must not park the block ──────────────────────────────

test('asking for more than the block holds leaves nothing reserved', async () => {
  reset();
  // deployChallengeLanes and deployLanes both throw a capacity error here. Both
  // release first: without that, one oversized request parks every free id and
  // an immediate retry with a smaller selection is told the block is full.
  const short = await laneDeployer.allocateVxlanIds(BLOCK, 25);
  assert.strictEqual(short.length, 10, 'only the block is available');
  laneDeployer.releaseVxlanReservations(short);

  // Probe the WHOLE block, the way countFreeLanes does — the limit caps the
  // result, so asking for fewer would prove nothing about what is free.
  const retry = await laneDeployer.allocateVxlanIds(BLOCK, 10, { reserve: false });
  assert.strictEqual(retry.length, 10, 'a retry must see the full block again');
});

// ── the call sites ──────────────────────────────────────────────────────────

test('every read-only caller passes reserve:false', () => {
  // Source-level: the failure is silent and only shows up as a phantom "block
  // full" the next time someone deploys, which is a long way from the cause.
  const fs = require('fs');
  const ROOT = path.join(__dirname, '..');
  const PROBES = [
    ['modules/crucible/plugins/cle/utils/vuln-lab-provision.js', 'countFreeLanes'],
    ['src/routes/admin/groups.js', 'const free = await allocateVxlanIds'],
  ];
  for (const [rel, anchor] of PROBES) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const at = src.indexOf(anchor);
    assert.notStrictEqual(at, -1, `${rel}: anchor "${anchor}" not found`);
    const window = src.slice(at, at + 600);
    assert.match(window, /reserve:\s*false/,
      `${rel} calls allocateVxlanIds to COUNT, so it must pass reserve:false — `
      + 'otherwise checking capacity consumes it');
  }
});

test('both capacity-error paths release before throwing', () => {
  const fs = require('fs');
  const ROOT = path.join(__dirname, '..');
  for (const rel of ['src/utils/lane-deployer.js', 'src/utils/challenge-lane-deployer.js']) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const at = src.indexOf('if (vxlans.length < users.length) {');
    assert.notStrictEqual(at, -1, `${rel}: capacity guard not found`);
    const block = src.slice(at, at + 900);
    assert.match(block, /releaseVxlanReservations\(vxlans\)/,
      `${rel} must hand the ids back before raising a capacity error`);
  }
});
