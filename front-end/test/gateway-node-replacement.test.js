/**
 * gateway-node-replacement.test.js -- a gateway that CLONES and then will not
 * START, and the lane surviving it.
 *
 * THE INCIDENT THIS EXISTS FOR
 * cyberhub-node-8 joined the cluster and immediately began a Ceph backfill.
 * Every challenge lane the scheduler placed on it died the same way. The gateway
 * LXC (VMID 100000+vxlan, e.g. 110881) cloned perfectly -- and then `pct start`
 * lost the race for the udev-created symlink
 * /dev/rbd-pve/<fsid>/<pool>/<image> and died in the pre-start hook:
 *
 *     lxc-start: ... Failed to run lxc.hook.pre-start for container "110881"
 *     ... exited with status 32
 *
 * Nobody found out for three to five minutes. The old deployLaneVms fired the
 * start, never awaited the UPID, slept five seconds, then wrote DHCP
 * reservations into a stopped container, swallowed THAT failure behind
 * "Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER", started every lane VM anyway,
 * cloned a GOAD controller, and finally surfaced as
 *
 *     ssh: connect to host 10.42.129.1 port 22: No route to host
 *
 * from inside the controller's prep.sh -- a message about the one machine that
 * was working correctly. Meanwhile node-selector kept choosing node-8 for the
 * next lane, and the one after that, because it scores on FREE cpu and ram and a
 * node whose only workload is Ceph backfill looks like the emptiest machine in
 * the cluster.
 *
 * WHAT EACH ASSERTION BELOW IS DEFENDING
 *   - the HAPPY PATH costs exactly one clone and one start, and moves nothing.
 *     A recovery path that taxes healthy deploys is a worse bug than the one it
 *     fixes.
 *   - a gateway that will not start is DESTROYED and RE-PLACED on another node,
 *     because the failure is the node's, not the lane's. The destroy is not
 *     optional: the VMID is cluster-unique, so the re-clone cannot even be
 *     attempted while the carcass exists, and waitForVmidsGone is what stops the
 *     second clone failing with "CT already exists" -- a completely different
 *     fault wearing the same clothes.
 *   - selectBestNode is called with exclude:[the failed node]. Without it the
 *     scheduler hands back node-8 again, for exactly the free-capacity reason
 *     above, and the "recovery" is a re-run of the failure.
 *   - the failed node is QUARANTINED, so the rest of the batch stops being
 *     steered into it.
 *   - TWO nodes failing is not a third hop. MAX_GATEWAY_REPLACEMENTS is 1: an
 *     unbounded chain turns one bad batch into a cluster-wide crawl.
 *   - the re-placements run AFTER every per-node clone loop has finished, and
 *     SERIALLY. Both are about the LXC template disk lock: Proxmox answers
 *     "CT is locked" to two concurrent clones of one template, and two lanes
 *     that both failed on node-8 will both be handed the same rescue node.
 *
 * Proxmox, the scheduler and the database are stubbed through require.cache the
 * way gateway-clone-recovery.test.js does it. node-health is the REAL module --
 * the quarantine is behaviour under test, not a fixture.
 *
 * Run: node --test test/gateway-node-replacement.test.js
 */

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stub(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// The deployer reads site.json at module load and site.json is gitignored, so
// it is absent in a plain checkout. Same stub gateway-clone-recovery.test.js
// uses; resolveLaneNetworking needs the real transit-VLAN shape to build the
// gateway's wan0.
stub('site-config.js', {
  getSchedulingConfig: () => ({
    min_free_mem_gb: 8, min_free_disk_gb: 20,
    max_concurrent_lanes: 5, max_concurrent_clones: 4,
    node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    excluded_nodes: [],
  }),
  getDefaultTemplateNode: () => 'cyberhub-node-1',
  getNodeAddress: () => null,
  getClusterNodes: () => ['cyberhub-node-1', 'cyberhub-node-5', 'cyberhub-node-8'],
  getV2LabNetwork: () => ({
    bridge: 'vmbr0', vlan_tag: 60, subnet: '100.100.60.0/22',
    gateway: '100.100.60.1',
    host_range: { first: '100.100.60.10', last: '100.100.63.254' },
    reserved: [],
  }),
});

// ── the stubbed cluster ──────────────────────────────────────────────────────

const ORIGIN_NODE = 'cyberhub-node-1';   // where the gateway template actually lives
const BAD_NODE    = 'cyberhub-node-8';   // the backfilling node from the incident
const RESCUE_NODE = 'cyberhub-node-5';   // what selectBestNode offers instead
const GW_TEMPLATE = 1694;                // the origin gateway template
const REPLICA_ID  = 169200;              // replicateGatewayTemplate's node-local copy

const calls = {
  clones: [], starts: [], statusReads: [], destroys: [], vmidsGone: [], configs: [],
  // ONE ordered log of everything that crossed the wire. The serialisation
  // assertions are about ORDER, and order is the thing a per-array count cannot
  // show: two clones that overlap and two that are strictly sequential produce
  // identical arrays.
  order: [],
};
let dbCalls = [];
let selectCalls = [];

// node name -> what GET .../status/current answers for a container on it,
// forever. 'stopped' is what Proxmox reports for a container whose pre-start
// hook died; anything not listed answers 'running'.
let statusByNode = {};
// When true, GET .../status/current answers an object with no `status` key at
// all -- readGatewayStatus reads that as UNREADABLE, which is deliberately not
// the same thing as 'stopped'.
let statusUnreadable = false;
// Make selectBestNode throw, i.e. "there is no other node".
let selectThrows = null;

stub('proxmox.js', {
  PROXMOX_URL: 'https://stub',
  async proxmoxAPI(method, url, body) {
    const clone = url.match(/nodes\/([^/]+)\/lxc\/(\d+)\/clone$/);
    if (clone) {
      const [, node, vmid] = clone;
      const rec = { node, vmid: Number(vmid), target: body && body.target };
      calls.clones.push(rec);
      calls.order.push(`clone:${rec.vmid}@${rec.node}->${rec.target}`);
      return 'UPID:clone::';
    }
    const start = url.match(/nodes\/([^/]+)\/lxc\/(\d+)\/status\/start$/);
    if (start) {
      const [, node, vmid] = start;
      calls.starts.push({ node, vmid: Number(vmid) });
      calls.order.push(`start:${vmid}@${node}`);
      return 'UPID:start::';
    }
    const current = url.match(/nodes\/([^/]+)\/lxc\/(\d+)\/status\/current$/);
    if (current) {
      const [, node, vmid] = current;
      calls.statusReads.push({ node, vmid: Number(vmid) });
      if (statusUnreadable) return {};
      return { status: statusByNode[node] || 'running' };
    }
    if (/\/config$/.test(url)) { calls.configs.push(url); return {}; }
    return {};
  },
  async waitForTask() { return true; },
  async forceDestroyVM(vmid, type, node) {
    calls.destroys.push({ vmid, type, node });
    calls.order.push(`destroy:${vmid}@${node}`);
    return true;
  },
  async findTemplateNode(vmid, hint) { return hint || ORIGIN_NODE; },
  async waitForVmidsGone(vmids) {
    calls.vmidsGone.push([...vmids]);
    calls.order.push(`gone:${vmids.join(',')}`);
    return { surviving: [] };
  },
});

stub('node-selector.js', {
  async selectBestNode(opts = {}) {
    selectCalls.push(opts);
    if (selectThrows) throw new Error(selectThrows);
    return { node: RESCUE_NODE, score: 0.1 };
  },
  // batch-deployer destructures this at load; nothing here calls it.
  filterSchedulableNodes: (rows) => rows,
});

stub('cybercore-db.js', {
  cybercorePool: null,
  async cybercoreQuery(sql, params) {
    dbCalls.push({ sql, params });
    return { rows: [] };
  },
});

stub('node-ssh.js', {
  pctExec: async () => ({ stdout: '', stderr: '', code: 0 }),
  pctPushFromString: async () => true,
});
stub('tailscale.js', { isEnabled: () => false });

const cld = require(path.join(UTILS, 'challenge-lane-deployer.js'));
// The REAL quarantine. Whether node-8 ends up in it is the point of two of the
// assertions below, so stubbing it would test the stub.
const nodeHealth = require(path.join(UTILS, 'node-health.js'));

// ── fixtures ─────────────────────────────────────────────────────────────────

function makeJob(n, node) {
  return {
    laneId: `lane-${n}`,
    user: { id: `u${n}`, email: `student${n}@example.edu` },
    vxlanId: 10880 + n,
    vnet: { vnet: 'aaaabgdc' },
    vnetInt: { vnet: 'aaaabgdd' },
    laneName: `cle-cy400-${10880 + n}`,
    targetNode: node,
    wanIp: '100.100.63.136/22',
  };
}
const gwIdOf = (job) => 100000 + job.vxlanId;

const CTX = {
  spec: {}, subnetScheme: 'v2', moduleKey: 'crucible', challengeKey: 'cy400',
  description: '', logTag: '[test]',
};

// startRetryMs/startPollMs 0 collapse gateway-lifecycle's three-attempt ladder
// (3 starts x 15 status polls at 2s) from ninety seconds to nothing. Production
// passes neither.
const runPhase = (jobs, overrides = {}) => cld.deployGatewayPhase({
  jobs,
  gwTemplateByNode: { [BAD_NODE]: REPLICA_ID },
  gwSourceNode: ORIGIN_NODE,
  gatewayVmid: GW_TEMPLATE,
  ctx: CTX, logTag: '[test]',
  startRetryMs: 0, startPollMs: 0,
  ...overrides,
});

const REAL_CONSOLE = { log: console.log, warn: console.warn, error: console.error };
const VERBOSE = !!process.env.GW_TEST_VERBOSE;

beforeEach(() => {
  calls.clones = []; calls.starts = []; calls.statusReads = [];
  calls.destroys = []; calls.vmidsGone = []; calls.configs = []; calls.order = [];
  dbCalls = []; selectCalls = [];
  statusByNode = {};
  statusUnreadable = false;
  selectThrows = null;
  // Quarantine is per-process and cumulative on purpose, so a test that did not
  // clear it would inherit the previous test's node-8.
  nodeHealth._resetForTests();
  if (!VERBOSE) {
    console.log = () => {}; console.warn = () => {}; console.error = () => {};
  }
});
afterEach(() => { Object.assign(console, REAL_CONSOLE); });

/** Indices in calls.order of every entry matching a predicate. */
const indicesOf = (pred) => calls.order.reduce((acc, e, i) => (pred(e) ? [...acc, i] : acc), []);

// ── the healthy case pays nothing ────────────────────────────────────────────

test('a gateway that starts costs one clone and one start, and moves nothing', async () => {
  // The recovery path must be invisible on a healthy node. A confirm loop that
  // polls, or a destroy "just in case", would be a worse regression than the
  // bug: every lane in every class pays it.
  const jobs = [makeJob(1, BAD_NODE)];
  const { gatewayResults, replacements } = await runPhase(jobs);

  assert.deepStrictEqual(calls.clones, [{ node: BAD_NODE, vmid: REPLICA_ID, target: BAD_NODE }]);
  assert.strictEqual(calls.starts.length, 1, 'exactly one start POST');
  assert.deepStrictEqual(calls.destroys, [], 'nothing is destroyed when nothing failed');
  assert.deepStrictEqual(calls.vmidsGone, [], 'and nothing waits on a VMID that was never freed');
  assert.strictEqual(selectCalls.length, 0, 'the scheduler is not consulted a second time');
  assert.strictEqual(jobs[0].targetNode, BAD_NODE, 'the lane stays where it was placed');
  assert.deepStrictEqual(gatewayResults['lane-1'], { success: true });
  assert.deepStrictEqual(replacements, []);
  assert.strictEqual(nodeHealth.isNodeQuarantined(BAD_NODE), false);
});

// ── THE FIX: the lane moves ──────────────────────────────────────────────────

test('THE FIX: a gateway that never reaches running is destroyed and re-placed', async () => {
  // node-8 answers 'stopped' forever -- the pre-start hook died. node-5 is fine.
  statusByNode = { [BAD_NODE]: 'stopped' };
  const jobs = [makeJob(1, BAD_NODE)];
  const gwId = gwIdOf(jobs[0]);

  const { gatewayResults, replacements } = await runPhase(jobs);

  assert.deepStrictEqual(gatewayResults['lane-1'], { success: true, movedFrom: BAD_NODE },
    'a re-placed lane reports SUCCESS — runBatch must deploy it, not skip it');
  assert.strictEqual(replacements.length, 1);
  assert.strictEqual(jobs[0].targetNode, RESCUE_NODE,
    'job.targetNode is the one node-bound field, and everything downstream reads it');

  // The carcass goes first. The VMID is cluster-unique.
  assert.ok(calls.destroys.some(d => d.vmid === gwId && d.type === 'lxc' && d.node === BAD_NODE),
    'the stopped gateway must be destroyed on the node that would not start it');
  assert.deepStrictEqual(calls.vmidsGone, [[gwId]],
    'and the re-clone must wait for the id to actually be gone, or it fails with "CT already exists"');

  // Without exclude the scheduler returns node-8 again: it ranks on free
  // capacity, and a backfilling node has plenty.
  assert.strictEqual(selectCalls.length, 1);
  assert.deepStrictEqual(selectCalls[0].exclude, [BAD_NODE]);
  // AND the rescue node must already have this lane's VNet bridges up. A gateway
  // that will not start has two causes that arrive here identically: the RBD/udev
  // race this file was written for, and `bridge '<vnet>' does not exist` on a node
  // whose post-apply "SRV Networking" reload has not finished. Re-placing onto a
  // second node that is also mid-reload spends the one allowed hop proving it.
  assert.deepStrictEqual(selectCalls[0].requireBridges, ['aaaabgdc', 'aaaabgdd'],
    'the re-placement must require both of this lane vnets: external and internal');

  // node-5 held no replica of the gateway template, so the second clone is a
  // cross-node copy from the ORIGIN. That is intended, not a fallback bug.
  assert.strictEqual(calls.clones.length, 2);
  assert.deepStrictEqual(calls.clones[1], {
    node: ORIGIN_NODE, vmid: GW_TEMPLATE, target: RESCUE_NODE,
  });

  // Persisted immediately: the row was INSERTed with config.node = node-8, and
  // if the lane dies before deployLaneVms rewrites it, teardown would hunt for
  // this VMID on the wrong node.
  const moved = dbCalls.filter(c => /cybercore_lane/.test(c.sql) && /placement_note/.test(c.params[1]));
  assert.strictEqual(moved.length, 1, 'exactly one placement UPDATE');
  assert.strictEqual(moved[0].params[0], 'lane-1');
  const patch = JSON.parse(moved[0].params[1]);
  assert.strictEqual(patch.node, RESCUE_NODE);
  assert.match(moved[0].params[1], /"node":"cyberhub-node-5"/);
  assert.match(patch.placement_note, /^moved from cyberhub-node-8: /);

  // And the scheduler is told, so the NEXT lane is not aimed at node-8 too.
  assert.strictEqual(nodeHealth.isNodeQuarantined(BAD_NODE), true);
  assert.strictEqual(nodeHealth.isNodeQuarantined(RESCUE_NODE), false);
});

// ── one hop, and only one ────────────────────────────────────────────────────

test('when the rescue node fails too, the lane fails — it does not keep hopping', async () => {
  // An unbounded hop chain turns one bad batch into a cluster-wide crawl: every
  // hop is a clone, a three-attempt start ladder, a destroy and a
  // waitForVmidsGone. Two nodes in a row is no longer a story about one bad node.
  statusByNode = { [BAD_NODE]: 'stopped', [RESCUE_NODE]: 'stopped' };
  const jobs = [makeJob(1, BAD_NODE)];
  const gwId = gwIdOf(jobs[0]);

  const { gatewayResults } = await runPhase(jobs);

  assert.strictEqual(gatewayResults['lane-1'].success, false);
  const err = gatewayResults['lane-1'].error;
  assert.match(err, /cyberhub-node-8/, 'names where it started');
  assert.match(err, /cyberhub-node-5/, 'and where it was moved to');
  // The one string that gets an operator to the actual evidence: the start task
  // log on the node, which is where "Failed to run lxc.hook.pre-start" lives.
  assert.match(err, new RegExp(`vzstart:${gwId}`),
    'the error must point at the start task log, not at SSH keys');

  assert.strictEqual(cld.MAX_GATEWAY_REPLACEMENTS, 1);
  assert.strictEqual(calls.clones.length, 2, 'one original + one re-placement, and no third');
  assert.strictEqual(selectCalls.length, 1, 'the scheduler is asked once, not once per hop');

  assert.ok(calls.destroys.some(d => d.vmid === gwId && d.node === BAD_NODE));
  assert.ok(calls.destroys.some(d => d.vmid === gwId && d.node === RESCUE_NODE),
    'the second carcass is cleaned up too, or the VMID stays taken cluster-wide');
  assert.strictEqual(nodeHealth.isNodeQuarantined(BAD_NODE), true);
  assert.strictEqual(nodeHealth.isNodeQuarantined(RESCUE_NODE), true);
});

test('with nowhere to move it, the lane fails naming the node that would not start it', async () => {
  // A one-node cluster, or every other node excluded/offline. The lane is lost
  // either way — but the message has to say WHY, because "gateway clone failed"
  // sent the original investigation to the clone path, which was working.
  statusByNode = { [BAD_NODE]: 'stopped' };
  selectThrows = 'No online nodes found in cluster';
  const jobs = [makeJob(1, BAD_NODE)];

  const { gatewayResults } = await runPhase(jobs);

  assert.strictEqual(gatewayResults['lane-1'].success, false);
  assert.match(gatewayResults['lane-1'].error,
    /gateway would not start on cyberhub-node-8 and no alternative node is available/);
  assert.match(gatewayResults['lane-1'].error, /No online nodes found in cluster/);
  assert.strictEqual(calls.clones.length, 1, 'no clone is attempted with nowhere to put it');
  assert.strictEqual(jobs[0].targetNode, BAD_NODE, 'and the job is not re-pointed at nothing');
});

// ── a whole node's worth of lanes ────────────────────────────────────────────

test('two lanes on the failing node: the second skips the replica, and both move afterwards', async () => {
  statusByNode = { [BAD_NODE]: 'stopped' };
  const jobs = [makeJob(1, BAD_NODE), makeJob(2, BAD_NODE)];
  const gw1 = gwIdOf(jobs[0]);
  const gw2 = gwIdOf(jobs[1]);

  const { gatewayResults, replacements } = await runPhase(jobs);

  assert.strictEqual(replacements.length, 2);
  assert.deepStrictEqual(gatewayResults['lane-1'], { success: true, movedFrom: BAD_NODE });
  assert.deepStrictEqual(gatewayResults['lane-2'], { success: true, movedFrom: BAD_NODE });

  // preferOrigin is sticky across the node's remaining lanes: once one gateway
  // on node-8 has failed, the next one does not pay the full replica ladder
  // again, it goes straight to the origin template.
  assert.deepStrictEqual(calls.clones[0], { node: BAD_NODE, vmid: REPLICA_ID, target: BAD_NODE });
  assert.deepStrictEqual(calls.clones[1], { node: ORIGIN_NODE, vmid: GW_TEMPLATE, target: BAD_NODE },
    'the second lane on a suspect node skips the node-local replica');

  // ORDER, not timing: both re-placements happen after the per-node loop has
  // finished with BOTH lanes. Running one while the loop is still cloning would
  // put two clones of one LXC template in flight and earn "CT is locked".
  const lastBadNodeWork = Math.max(...indicesOf(e =>
    (e.startsWith('start:') && e.endsWith(`@${BAD_NODE}`)) ||
    (e.startsWith('clone:') && e.endsWith(`->${BAD_NODE}`))));
  const rescueClones = indicesOf(e => e.startsWith('clone:') && e.endsWith(`->${RESCUE_NODE}`));
  assert.strictEqual(rescueClones.length, 2);
  assert.ok(lastBadNodeWork < rescueClones[0],
    'every clone and start on the failing node must precede the first re-placement');

  // SERIALISED, not concurrent: two lanes that failed on node-8 are both handed
  // node-5, so re-placing them in parallel recreates the same-template clone
  // collision on the rescue node. The second re-clone must not begin until the
  // first re-placement has already started its gateway.
  const firstRescueStart = calls.order.indexOf(`start:${gw1}@${RESCUE_NODE}`);
  assert.ok(firstRescueStart > rescueClones[0], 'sanity: lane 1 clones then starts');
  assert.ok(firstRescueStart < rescueClones[1],
    'lane 2 must not clone until lane 1 has started — these run sequentially, not in parallel');
  assert.ok(calls.order.indexOf(`start:${gw2}@${RESCUE_NODE}`) > rescueClones[1]);

  // Both carcasses cleared off node-8, both ids waited out before re-cloning.
  assert.deepStrictEqual(calls.vmidsGone, [[gw1], [gw2]]);
  assert.strictEqual(calls.destroys.filter(d => d.node === BAD_NODE).length, 2);
  assert.deepStrictEqual(selectCalls.map(o => o.exclude), [[BAD_NODE], [BAD_NODE]]);
  assert.deepStrictEqual(selectCalls.map(o => o.requireBridges),
    [['aaaabgdc', 'aaaabgdd'], ['aaaabgdc', 'aaaabgdd']],
    'every re-placement carries its own lane bridge requirement');
  assert.strictEqual(jobs[0].targetNode, RESCUE_NODE);
  assert.strictEqual(jobs[1].targetNode, RESCUE_NODE);
});

// ── the failures that are NOT "the gateway is down" ──────────────────────────

test('an unreadable cluster is not treated as a stopped gateway', async () => {
  // readGatewayStatus returns null when the answer cannot be read, and null is
  // NOT evidence. Destroying and re-placing a gateway because a status endpoint
  // answered oddly would turn one flaky API call into a moved, re-cloned lane.
  const jobs = [makeJob(1, BAD_NODE)];
  statusUnreadable = true;

  const { gatewayResults, replacements } = await runPhase(jobs);

  assert.deepStrictEqual(gatewayResults['lane-1'], { success: true },
    'no information is not a failure — the lane carries on');
  assert.deepStrictEqual(replacements, []);
  assert.deepStrictEqual(calls.destroys, []);
  assert.strictEqual(selectCalls.length, 0);
  assert.strictEqual(jobs[0].targetNode, BAD_NODE);
  assert.strictEqual(nodeHealth.isNodeQuarantined(BAD_NODE), false,
    'and a node is not quarantined on the strength of an endpoint we could not read');
});
