/**
 * ciab-engagement-provision.test.js — Track A8: the VXLAN block is carved
 * BEFORE deploy day, and "ready" means something.
 *
 * Two properties are worth pinning, and neither is visible from source text:
 *
 *   A8c — verifyBridgesOnAllNodes must check EVERY online node, not one.
 *     A lane's node is chosen at DEPLOY time by distributeAcrossNodes, over
 *     whatever is online and above the memory floor — a set that can change
 *     between reserving a block and deploying from it. The check this replaces
 *     read `(await GET /nodes)[0].node`, polled only that node, and swallowed
 *     every error into a log line, so an offline first node silently produced
 *     bridgesUp:false with no indication why. Its result was then read by nobody.
 *
 *   A8a — the deploy gate must REFUSE, not fall back. Reserving inline "just
 *     this once" is how the cost became invisible in the first place: it works,
 *     so nobody notices the instructor waiting several minutes with no
 *     explanation. Each refusal has to name the state and the remedy.
 *
 * proxmox.js and site-config.js are stubbed through require.cache — the same
 * pattern console-designation.test.js uses — so no cluster is touched.
 *
 * Run: node --test front-end/test/ciab-engagement-provision.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');

// ── stubs ───────────────────────────────────────────────────────────────────

let PVE = { nodes: [], ifacesByNode: {}, failNodes: new Set(), calls: [] };
let SCHED = { max_concurrent_lanes: 5, max_concurrent_clones: 4 };

require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    // Mutable so the excluded_nodes test below can drain a node. Note the
    // DEFAULT shape has no excluded_nodes key at all — that is deliberate, and
    // every consumer must survive it: config/site.json is gitignored, so a
    // checkout has no scheduling block and getSchedulingConfig's own defaults
    // are what production sees until an operator adds one.
    getSchedulingConfig: () => SCHED,
    getDefaultTemplateNode: () => 'node-1',
    getClusterNodes: () => [],
    getPhysicalClusterIps: () => ({}),
    getV2LabNetwork: () => ({ network: '100.100.60.0', prefix_len: 22, reserved: [], host_range: { first: '100.100.60.10', last: '100.100.63.254' } }),
  },
};

require.cache[require.resolve(path.join(UTILS, 'proxmox.js'))] = {
  id: 'proxmox', filename: 'proxmox', loaded: true,
  exports: {
    PROXMOX_URL: 'https://stub',
    proxmoxAPI: async (method, apiPath) => {
      PVE.calls.push(`${method} ${apiPath}`);
      if (apiPath.startsWith('/api2/json/cluster/resources')) return PVE.nodes;
      const m = apiPath.match(/\/api2\/json\/nodes\/([^/]+)\/network/);
      if (m) {
        const node = m[1];
        if (PVE.failNodes.has(node)) throw new Error(`node ${node} unreachable`);
        return (PVE.ifacesByNode[node] || []).map(iface => ({ iface }));
      }
      return [];
    },
    waitForTask: async () => {},
    forceDestroyVM: async () => {},
  },
};

const { verifyBridgesOnAllNodes, encodeBase20 } =
  require(path.join(UTILS, 'lab-network-provision.js'));

function reset() {
  PVE = { nodes: [], ifacesByNode: {}, failNodes: new Set(), calls: [] };
  SCHED = { max_concurrent_lanes: 5, max_concurrent_clones: 4 };
}
const onlineNodes = (...names) => names.map(n => ({ type: 'node', status: 'online', node: n }));

// ── A8c: every node, not one ────────────────────────────────────────────────

test('A8c: a block is ready only when the bridges exist on EVERY online node', async () => {
  reset();
  const tags = [10000, 10001];
  const names = tags.map(encodeBase20);
  PVE.nodes = onlineNodes('n1', 'n2', 'n3');
  // n1 and n2 are fine; n3 is short one bridge. The old one-node check read
  // whichever node came back first — here n1 — and would have called this ready.
  PVE.ifacesByNode = { n1: names, n2: names, n3: [names[0]] };

  const r = await verifyBridgesOnAllNodes({ tags, timeoutMs: 50, intervalMs: 10 });
  assert.strictEqual(r.ready, false, 'one short node must make the whole block not-ready');
  assert.deepStrictEqual(r.nodesPending, ['n3']);
  assert.deepStrictEqual(r.missingByNode.n3, [names[1]]);
  assert.ok(r.nodesReady.includes('n1') && r.nodesReady.includes('n2'));
});

test('A8c: all nodes healthy is ready, and reports every node it confirmed', async () => {
  reset();
  const tags = [10000, 10001];
  const names = tags.map(encodeBase20);
  PVE.nodes = onlineNodes('n1', 'n2', 'n3');
  PVE.ifacesByNode = { n1: names, n2: names, n3: names };

  const r = await verifyBridgesOnAllNodes({ tags, timeoutMs: 1000, intervalMs: 10 });
  assert.strictEqual(r.ready, true);
  assert.strictEqual(r.nodesReady.length, 3);
  assert.strictEqual(r.expected, 2);
  assert.deepStrictEqual(r.missingByNode, {});
});

test('A8c: OFFLINE nodes are not checked — a lane can never be placed there', async () => {
  reset();
  const tags = [10000];
  const names = tags.map(encodeBase20);
  PVE.nodes = [
    { type: 'node', status: 'online', node: 'n1' },
    { type: 'node', status: 'offline', node: 'n2' },
  ];
  PVE.ifacesByNode = { n1: names };

  const r = await verifyBridgesOnAllNodes({ tags, timeoutMs: 1000, intervalMs: 10 });
  assert.strictEqual(r.ready, true, 'an offline node must not hold the block back');
  assert.deepStrictEqual(r.nodesReady, ['n1']);
});

test('A8c: a node in cluster.scheduling.excluded_nodes is not checked either', async () => {
  // Same rule as the offline case, for the same reason: distributeAcrossNodes
  // will never place a lane on an excluded node, so its bridges cannot matter.
  //
  // This one bites harder than offline, though. A node is normally excluded
  // BECAUSE it is unwell -- cyberhub-node-8 was drained while a Ceph backfill
  // made it lose the /dev/rbd-pve udev race and fail every `pct start` -- and an
  // unwell node is exactly the one whose SDN bridges may never appear. Left in
  // the set it would pin the whole block at ready:false for the full timeout and
  // refuse deploys onto the healthy nodes, which is the opposite of what
  // draining it was supposed to achieve.
  reset();
  const tags = [10000];
  const names = tags.map(encodeBase20);
  PVE.nodes = onlineNodes('n1', 'cyberhub-node-8');
  PVE.ifacesByNode = { n1: names };          // node-8 has NO bridges at all
  SCHED = { ...SCHED, excluded_nodes: ['cyberhub-node-8'] };

  const r = await verifyBridgesOnAllNodes({ tags, timeoutMs: 1000, intervalMs: 10 });
  assert.strictEqual(r.ready, true, 'an excluded node must not hold the block back');
  assert.deepStrictEqual(r.nodesReady, ['n1']);
  assert.deepStrictEqual(r.nodesPending, []);
  assert.ok(!PVE.calls.some(c => c.includes('cyberhub-node-8')),
    'an excluded node should never even be polled');
});

test('A8c: quarantine is SOFT, so a quarantined node is still bridge-checked', async () => {
  // The distinction that makes the exclusion above safe. node-health quarantine
  // is advisory -- node-selector drops it rather than leave the cluster with
  // nowhere to deploy -- so a quarantined node CAN still receive a lane and
  // therefore still needs its bridges. Only the hard, operator-set exclusion may
  // be skipped. Encoded here because the two look interchangeable from a
  // distance and are not.
  reset();
  const tags = [10000];
  const names = tags.map(encodeBase20);
  PVE.nodes = onlineNodes('n1', 'cyberhub-node-8');
  PVE.ifacesByNode = { n1: names };
  const nodeHealth = require(path.join(UTILS, 'node-health.js'));
  nodeHealth._resetForTests();
  nodeHealth.markNodeFault('cyberhub-node-8', 'gateway start failed');

  const r = await verifyBridgesOnAllNodes({ tags, timeoutMs: 50, intervalMs: 10 });
  nodeHealth._resetForTests();
  assert.strictEqual(r.ready, false, 'a quarantined node can still take a lane, so it must be checked');
  assert.deepStrictEqual(r.nodesPending, ['cyberhub-node-8']);
});

test('A8c: an unreachable node is reported as unreachable, NOT as missing bridges', async () => {
  // They need different operator responses: one is "SDN did not propagate",
  // the other is "that host is down". The check this replaces collapsed both
  // into a single swallowed exception.
  reset();
  const tags = [10000];
  PVE.nodes = onlineNodes('n1', 'n2');
  PVE.ifacesByNode = { n1: tags.map(encodeBase20) };
  PVE.failNodes = new Set(['n2']);

  const r = await verifyBridgesOnAllNodes({ tags, timeoutMs: 50, intervalMs: 10 });
  assert.strictEqual(r.ready, false);
  assert.deepStrictEqual(r.nodesUnreachable, ['n2']);
  assert.deepStrictEqual(r.nodesPending, []);
  assert.match(r.missingByNode.n2[0], /unreachable/);
});

test('A8c: it never throws — an unreachable CLUSTER returns not-ready', async () => {
  // The old check wrapped everything in a try whose handler was one log line,
  // so this case was indistinguishable from "bridges genuinely absent".
  reset();
  PVE.nodes = null;   // GET /cluster/resources returns nothing usable
  const r = await verifyBridgesOnAllNodes({ tags: [10000], timeoutMs: 50, intervalMs: 10 });
  assert.strictEqual(r.ready, false);
  assert.deepStrictEqual(r.nodesReady, []);
});

test('A8c: nodes are polled CONCURRENTLY, so one slow node cannot eat the deadline', async () => {
  // proxmoxAPI defaults to a 30s timeout and lab-network-provision passes none,
  // so a serial sweep of nine nodes could spend the whole budget on two dead
  // ones before checking a single healthy node.
  reset();
  const tags = [10000];
  PVE.nodes = onlineNodes('n1', 'n2', 'n3');
  PVE.ifacesByNode = { n1: tags.map(encodeBase20), n2: tags.map(encodeBase20), n3: tags.map(encodeBase20) };

  await verifyBridgesOnAllNodes({ tags, timeoutMs: 1000, intervalMs: 10 });
  const networkCalls = PVE.calls.filter(c => /\/network$/.test(c));
  assert.strictEqual(networkCalls.length, 3, 'one round should query all three nodes');
});

test('A8c: an empty tag set is trivially ready rather than a failure', async () => {
  reset();
  const r = await verifyBridgesOnAllNodes({ tags: [] });
  assert.strictEqual(r.ready, true);
  assert.strictEqual(PVE.calls.length, 0, 'must not call Proxmox at all');
});

// ── A8a: the deploy gate ────────────────────────────────────────────────────

const engagementProvision = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/engagement-provision.js'));

const { assertEngagementDeployable, expectedTagsFor } = engagementProvision;
const WHERE = { profileId: 'p1', engagementType: 'external_blackbox' };

test('A8a: no reservation refuses with 409 and names the remedy', () => {
  assert.throws(
    () => assertEngagementDeployable(null, WHERE),
    (e) => e.status === 409 && e.code === 'ENGAGEMENT_NOT_RESERVED'
        && /Reserve it first/.test(e.message));
});

test('A8a: a reservation still provisioning refuses rather than waiting or falling back', () => {
  assert.throws(
    () => assertEngagementDeployable(
      { provision_status: 'provisioning', max_students: 25 }, WHERE),
    (e) => e.status === 409 && e.code === 'ENGAGEMENT_PROVISIONING'
        && /still being reserved/.test(e.message));
});

test('A8a: a failed reservation refuses and points at Re-provision, quoting the reason', () => {
  assert.throws(
    () => assertEngagementDeployable(
      { provision_status: 'failed', provision_error: 'SDN provisioning incomplete: 3/25 VNet(s) missing' }, WHERE),
    (e) => e.status === 409 && e.code === 'ENGAGEMENT_FAILED'
        && /3\/25 VNet/.test(e.message) && /Re-provision/.test(e.message));
});

test('A8a: ready-but-no-challenge refuses instead of deploying onto nothing', () => {
  assert.throws(
    () => assertEngagementDeployable({ provision_status: 'ready', challenge_id: null }, WHERE),
    (e) => e.status === 409 && e.code === 'ENGAGEMENT_INCONSISTENT');
});

test('A8a: a ready reservation passes, and unconfirmed bridges are a warning not a block', () => {
  // An adopted pre-A8 reservation legitimately has lanes running on it and no
  // bridge evidence. Refusing those would break every existing profile.
  const eng = { provision_status: 'ready', challenge_id: 'c1', bridges_ready: false };
  assert.strictEqual(assertEngagementDeployable(eng, WHERE), eng);
});

test('A8a: v3 expects the internal tag for every lane, v2 does not', () => {
  // A v3 block is 2N VNets, not N — checking only the external half would call
  // a half-built segmented lane ready.
  assert.deepStrictEqual(expectedTagsFor({ start: 10000, end: 10001 }, 'v2'), [10000, 10001]);
  assert.deepStrictEqual(expectedTagsFor({ start: 10000, end: 10001 }, 'v3'),
    [10000, 4010000, 10001, 4010001]);
});

// ── shared state lives in cybercore_db, not twice in two plugin DBs ─────────

const fs = require('fs');
const readRepo = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

test('bridge readiness is stored ONCE, in cybercore_db', () => {
  // "Were this block's bridges verified, when, and on which nodes?" is a fact
  // about the RESERVATION — the crucible_challenge row — not about a CIAB
  // engagement or a CLE course. Both plugins reserve through the same shared
  // provisioner, so a per-plugin copy is one fact written twice, by two writers,
  // in two databases that cannot join.
  const shared = require(path.join(UTILS, 'lab-network-provision.js'));
  for (const fn of ['ensureLabReadinessTable', 'recordLabReadiness', 'getLabReadiness', 'getLabReadinessMap']) {
    assert.strictEqual(typeof shared[fn], 'function', `${fn} must be exported from the shared provisioner`);
  }
});

test('neither plugin re-declares a readiness column of its own', () => {
  const ciab = readRepo('modules/crucible/plugins/ciab/migrations/010_ciab_engagements.sql');
  const cle = readRepo('modules/crucible/plugins/cle/migrations/008_cle_provisioning_recovery.sql');
  // Strip comments — both files explain at length WHY they do not store it.
  const code = (sql) => sql.split(/\r?\n/).filter(l => !l.trim().startsWith('--')).join('\n');
  assert.ok(!/bridges_ready|bridge_report/.test(code(ciab)),
    'ciab_engagement must not carry its own readiness columns');
  assert.ok(!/bridges_ready|bridge_report/.test(code(cle)),
    'cle_course must not carry its own readiness columns');
});

test('reserveLabNetwork is the single writer, and both plugins read', () => {
  const shared = readRepo('src/utils/lab-network-provision.js');
  assert.ok(/await recordLabReadiness\(challengeId, infra\.bridgeReadiness\)/.test(shared),
    'reserveLabNetwork must record readiness for every reservation it makes');

  const ciab = readRepo('modules/crucible/plugins/ciab/utils/engagement-provision.js');
  assert.ok(/getLabReadiness/.test(ciab), 'CIAB must read readiness from the shared table');

  // The boot hook, not a migration: plugin migrations only run against that
  // plugin's own database, so neither could create a table in cybercore_db.
  const server = readRepo('src/server.js');
  assert.ok(/ensureLabReadinessTable\(\)/.test(server),
    'the shared readiness table must be created by a boot hook');
});

test('CLE gets the same VLAN upgrades: all-node check, boot sweep, re-provision', () => {
  const courses = readRepo('modules/crucible/plugins/cle/routes/courses.js');
  assert.ok(/recoverStrandedCourseLabs/.test(courses),
    'CLE needs a boot sweep — without one a restart mid-provision strands a course forever');
  assert.ok(/reprovision/.test(courses),
    'CLE needs a re-provision action — otherwise a failed course can only be deleted and recreated');
  const server = readRepo('src/server.js');
  assert.ok(/recoverStrandedCourseLabs\(\)/.test(server), 'the CLE sweep must run at boot');
});
