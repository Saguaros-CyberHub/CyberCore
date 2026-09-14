/**
 * node-bridge-placement.test.js -- keeping lanes off a node whose SDN reload has
 * not landed yet, and not making anyone wait hours for the slowest node.
 *
 * THE PROBLEM THIS EXISTS FOR
 * Creating an environment carves a VXLAN block -- a zone plus one VNet per lane,
 * two on v3 -- and commits it with ONE cluster-wide `PUT /cluster/sdn`. That
 * commit creates no bridges. It makes every node queue its own "SRV Networking"
 * reload (ifreload -a), and those run independently: with hundreds of VNets in
 * the shared zone, one node is finished in a minute and another is still working
 * an hour later. A lane placed on the second one clones perfectly and then dies:
 *
 *     bridge 'aaaabgdc' does not exist
 *
 * Placement was blind to it, so a deploy started minutes after an environment was
 * created sprayed lanes across every online node and lost every one that landed
 * on a node still reloading. The only workable answer was to wait out the slowest
 * node -- hours -- before deploying anything.
 *
 * WHAT EACH ASSERTION BELOW DEFENDS
 *   - a node without the bridge is SKIPPED, on BOTH placement paths, even when it
 *     scores best. The fixture makes the bridgeless node the emptiest machine in
 *     the cluster for the same reason node-placement-exclusion.test.js does: on a
 *     fixture where it merely scored mid-pack, this would pass while doing nothing.
 *   - ONE ready node is enough. That is the entire point: deployable in minutes.
 *   - a node without the bridge is NOT quarantined. It has done nothing wrong; it
 *     is mid-reload, and marking it would keep it out of the next deploy too, by
 *     which time it is probably the healthiest node in the cluster.
 *   - when nothing is ready it WAITS (briefly, bounded) and then fails with a
 *     named error that says which bridges and which nodes -- not "no eligible
 *     nodes", which sends an operator to the wrong system entirely.
 *   - passing no bridges costs ZERO Proxmox calls, so every placement that does
 *     not cable a lane to a VNet is exactly as cheap as before.
 *
 * node-health is the REAL module: "readiness never quarantines" is a property of
 * the two together, not of a fixture.
 *
 * Run: node --test test/node-bridge-placement.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stub(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// ── the stubbed cluster ──────────────────────────────────────────────────────

const GiB = 1024 ** 3;

function nodeRow(name, { cpu, memUsedGb, diskUsedGb, status = 'online' }) {
  return {
    type: 'node', node: name, status,
    maxcpu: 64, cpu,
    maxmem: 256 * GiB, mem: memUsedGb * GiB,
    maxdisk: 1000 * GiB, disk: diskUsedGb * GiB,
  };
}

// Same shape as node-placement-exclusion.test.js: node-8 is the emptiest machine
// and therefore the default winner on both paths.
const CLUSTER = [
  nodeRow('cyberhub-node-8', { cpu: 0.01, memUsedGb: 6, diskUsedGb: 40 }),
  nodeRow('cyberhub-node-5', { cpu: 0.30, memUsedGb: 96, diskUsedGb: 300 }),
  nodeRow('cyberhub-node-6', { cpu: 0.45, memUsedGb: 150, diskUsedGb: 420 }),
  nodeRow('cyberhub-node-7', { cpu: 0.62, memUsedGb: 200, diskUsedGb: 610 }),
];
const ONLINE = CLUSTER.map(n => n.node);

// A v3 lane needs BOTH: the external vnet and the internal one at tag+4000000.
const EXT = 'aaaabgdc';
const INT = 'aabfjcbc';

const NUMERIC_DEFAULTS = {
  min_free_mem_gb: 8, min_free_disk_gb: 20,
  max_concurrent_lanes: 5, max_concurrent_clones: 4,
  node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
  bridge_wait_s: 300,
};

let sched = { excluded_nodes: [], ...NUMERIC_DEFAULTS };
stub('site-config.js', {
  getSchedulingConfig: () => sched,
  getClusterNodes: () => ONLINE,
  getNodeAddress: () => null,
});

// node -> the bridge names that are UP there. Mutable mid-test, because "a node
// finishes its reload while we are waiting" is a case that has to be provable.
let bridgesByNode = {};
let downNodes = new Set();
let networkCalls = [];
let onNetworkCall = null;

stub('proxmox.js', {
  PROXMOX_URL: 'https://stub',
  async proxmoxAPI(method, url) {
    if (/\/cluster\/resources\?type=node$/.test(url)) return CLUSTER;
    const m = url.match(/\/api2\/json\/nodes\/([^/]+)\/network$/);
    if (m) {
      const node = m[1];
      networkCalls.push(node);
      if (onNetworkCall) onNetworkCall(node, networkCalls.length);
      if (downNodes.has(node)) throw new Error(`connect ETIMEDOUT ${node}`);
      // active: 1 is the evidence bridgeIsUp requires -- a row without it is a
      // VNet that is in the node's config and not yet in its kernel.
      return (bridgesByNode[node] || []).map(iface => ({ iface, active: 1 }));
    }
    throw new Error(`unexpected proxmox call: ${method} ${url}`);
  },
});

const { proxmoxAPI } = require(path.join(UTILS, 'proxmox.js'));
const { selectBestNode, keepBridgeReadyNodes } = require(path.join(UTILS, 'node-selector.js'));
const { distributeAcrossNodes } = require(path.join(UTILS, 'batch-deployer.js'));
const nodeHealth = require(path.join(UTILS, 'node-health.js'));

function reset(schedOverride) {
  sched = schedOverride || { excluded_nodes: [], ...NUMERIC_DEFAULTS };
  bridgesByNode = {};
  downNodes = new Set();
  networkCalls = [];
  onNetworkCall = null;
  nodeHealth._resetForTests();
}

/** every placement here uses a tiny budget; production reads bridge_wait_s */
const FAST = { waitMs: 40, intervalMs: 5 };

// ── the pathology, pinned ────────────────────────────────────────────────────

test('THE PATHOLOGY: the node with no bridge is the one that scores best', async () => {
  // If this stops being true, every assertion below goes green while proving
  // nothing -- the filter would be picking node-5 for reasons of its own.
  reset();
  for (const n of ONLINE) bridgesByNode[n] = [EXT];
  const best = await selectBestNode({ requireBridges: [EXT], ...FAST });
  assert.strictEqual(best.node, 'cyberhub-node-8');
  assert.deepStrictEqual(
    (await distributeAcrossNodes(proxmoxAPI, 6, { requireBridges: [EXT], ...FAST }))
      .filter(n => n === 'cyberhub-node-8').length > 0,
    true
  );
});

// ── the fix ──────────────────────────────────────────────────────────────────

test('THE FIX: a node whose reload has not landed is skipped, however well it scores', async () => {
  reset();
  // node-8 has finished nothing; 5, 6, 7 have the bridge.
  bridgesByNode = {
    'cyberhub-node-5': [EXT], 'cyberhub-node-6': [EXT], 'cyberhub-node-7': [EXT],
  };

  const best = await selectBestNode({ requireBridges: [EXT], ...FAST });
  assert.strictEqual(best.node, 'cyberhub-node-5', 'next best, not the bridgeless winner');

  const spread = await distributeAcrossNodes(proxmoxAPI, 6, { requireBridges: [EXT], ...FAST });
  assert.ok(!spread.includes('cyberhub-node-8'), `node-8 got lanes: ${spread.join(',')}`);
  assert.strictEqual(spread.length, 6);
});

test('ONE ready node is enough -- the whole point of the change', async () => {
  // Every other node is still reloading. Before this, the deploy had to wait for
  // them; now the block is usable the moment the first node finishes.
  reset();
  bridgesByNode = { 'cyberhub-node-7': [EXT] };

  assert.strictEqual((await selectBestNode({ requireBridges: [EXT], ...FAST })).node, 'cyberhub-node-7');
  const spread = await distributeAcrossNodes(proxmoxAPI, 5, { requireBridges: [EXT], ...FAST });
  assert.deepStrictEqual([...new Set(spread)], ['cyberhub-node-7']);
  assert.strictEqual(spread.length, 5);
});

test('a v3 lane needs BOTH vnets: the external bridge alone is not ready', async () => {
  reset();
  // node-8 is partway through its reload -- it has the external vnet and not the
  // internal one. ifreload brings interfaces up one at a time, so this is the
  // normal mid-reload state, not a contrived one.
  bridgesByNode = {
    'cyberhub-node-8': [EXT],
    'cyberhub-node-6': [EXT, INT],
  };
  const best = await selectBestNode({ requireBridges: [EXT, INT], ...FAST });
  assert.strictEqual(best.node, 'cyberhub-node-6');

  // and the same node IS eligible when only the external one is required
  assert.strictEqual(
    (await selectBestNode({ requireBridges: [EXT], ...FAST })).node, 'cyberhub-node-8'
  );
});

test('a batch requires the UNION, so a node holding half the block takes no lanes', async () => {
  reset();
  const A = 'aaaabgdc', B = 'aaaabgdd', C = 'aaaabgde';
  bridgesByNode = {
    'cyberhub-node-8': [A, B],            // still working through the block
    'cyberhub-node-5': [A, B, C],
    'cyberhub-node-6': [A, B, C],
  };
  const spread = await distributeAcrossNodes(proxmoxAPI, 6, { requireBridges: [A, B, C], ...FAST });
  assert.strictEqual(spread.length, 6);
  assert.ok(!spread.includes('cyberhub-node-8'),
    `the half-reloaded node took lanes: ${spread.join(',')}`);
  // Which of the two READY nodes each lane lands on is the existing weighted
  // round-robin's business, not this filter's -- assert only that every lane
  // landed on one of them.
  for (const n of spread) {
    assert.ok(['cyberhub-node-5', 'cyberhub-node-6'].includes(n), `unexpected node ${n}`);
  }
});

test('vnet ROWS work, not just names -- callers pass [vnet, vnetInt] straight through', async () => {
  reset();
  bridgesByNode = { 'cyberhub-node-6': [EXT, INT] };
  // v2 passes a null second element; it must not become a bridge nobody has.
  const best = await selectBestNode({ requireBridges: [{ vnet: EXT }, null], ...FAST });
  assert.strictEqual(best.node, 'cyberhub-node-6');
});

// ── the unhappy path ─────────────────────────────────────────────────────────

test('nothing ready anywhere: it waits, then fails NAMING the bridges and the nodes', async () => {
  reset();
  bridgesByNode = {};   // every node is still reloading

  await assert.rejects(
    () => selectBestNode({ requireBridges: [EXT, INT], ...FAST }),
    (e) => {
      assert.strictEqual(e.code, 'BRIDGES_NOT_ON_ANY_NODE');
      assert.strictEqual(e.status, 503, 'a route can answer 503 straight off err.status');
      assert.deepStrictEqual(e.requiredBridges, [EXT, INT]);
      // The message has to send an operator to the right system. "No eligible
      // nodes" sent them to Proxmox capacity; this names the SDN reload.
      assert.match(e.message, new RegExp(EXT));
      assert.match(e.message, new RegExp(INT));
      assert.match(e.message, /cyberhub-node-8/);
      assert.match(e.message, /srvreload|SRV Networking|reload/i);
      assert.deepStrictEqual(e.missingByNode['cyberhub-node-8'], [EXT, INT]);
      assert.deepStrictEqual(e.candidates.sort(), [...ONLINE].sort());
      return true;
    }
  );
  assert.ok(networkCalls.length > ONLINE.length,
    `it must POLL, not ask once: ${networkCalls.length} calls`);
});

test('the batch path fails the same way, with the same code', async () => {
  reset();
  await assert.rejects(
    () => distributeAcrossNodes(proxmoxAPI, 4, { requireBridges: [EXT], ...FAST }),
    (e) => {
      assert.strictEqual(e.code, 'BRIDGES_NOT_ON_ANY_NODE');
      assert.strictEqual(e.status, 503);
      return true;
    }
  );
});

test('a node that finishes its reload DURING the wait is picked up', async () => {
  reset();
  bridgesByNode = {};
  // After the first sweep of all four nodes, node-6's ifreload completes.
  onNetworkCall = (_node, n) => {
    if (n >= ONLINE.length) bridgesByNode['cyberhub-node-6'] = [EXT];
  };
  const best = await selectBestNode({ requireBridges: [EXT], waitMs: 2000, intervalMs: 5 });
  assert.strictEqual(best.node, 'cyberhub-node-6');
});

test('an unreachable node is not a ready node, and is reported as unreachable', async () => {
  reset();
  // A node mid-ifreload can simply stop answering. That means "not this node",
  // and it reads completely differently from "answered, and was short a bridge".
  downNodes = new Set(['cyberhub-node-8']);
  bridgesByNode = { 'cyberhub-node-5': [EXT] };

  assert.strictEqual((await selectBestNode({ requireBridges: [EXT], ...FAST })).node, 'cyberhub-node-5');

  downNodes = new Set(ONLINE);
  await assert.rejects(() => selectBestNode({ requireBridges: [EXT], ...FAST }), (e) => {
    assert.strictEqual(e.code, 'BRIDGES_NOT_ON_ANY_NODE');
    assert.match(e.unreachable['cyberhub-node-8'], /ETIMEDOUT/);
    assert.deepStrictEqual(e.missingByNode, {});
    assert.match(e.message, /unreachable/);
    return true;
  });
});

// ── what readiness must NOT do ───────────────────────────────────────────────

test('a node without the bridge is NOT quarantined -- it is mid-reload, not broken', async () => {
  reset();
  await assert.rejects(() => selectBestNode({ requireBridges: [EXT], ...FAST }));
  for (const n of ONLINE) {
    assert.strictEqual(nodeHealth.isNodeQuarantined(n), false,
      `${n} was quarantined for a reload it is still running; it would then be ` +
      `passed over by the NEXT deploy too, long after its bridges came up`);
  }
  assert.deepStrictEqual(nodeHealth.quarantinedNodes(), []);
});

test('a hard exclusion still wins: a bridge cannot resurrect a drained node', async () => {
  reset({ excluded_nodes: ['cyberhub-node-5'], ...NUMERIC_DEFAULTS });
  bridgesByNode = { 'cyberhub-node-5': [EXT] };   // the ONLY node that is ready
  await assert.rejects(
    () => selectBestNode({ requireBridges: [EXT], ...FAST }),
    (e) => e.code === 'BRIDGES_NOT_ON_ANY_NODE'
  );
  assert.ok(!networkCalls.includes('cyberhub-node-5'),
    'an excluded node should not even be probed');
});

test('a caller exclude and a bridge requirement compose', async () => {
  reset();
  bridgesByNode = { 'cyberhub-node-5': [EXT], 'cyberhub-node-6': [EXT] };
  const best = await selectBestNode({ exclude: ['cyberhub-node-5'], requireBridges: [EXT], ...FAST });
  assert.strictEqual(best.node, 'cyberhub-node-6');
});

// ── cost when unused ─────────────────────────────────────────────────────────

test('no requireBridges means NO probe at all, on both paths', async () => {
  // Everything that does not cable a lane to a VNet -- a bare workstation clone --
  // must be exactly as cheap as it was before this filter existed.
  reset();
  await selectBestNode();
  await selectBestNode({ exclude: ['cyberhub-node-8'] });
  await selectBestNode({ requireBridges: [] });
  await selectBestNode({ requireBridges: [null, undefined, ''] });
  await distributeAcrossNodes(proxmoxAPI, 4);
  await distributeAcrossNodes(proxmoxAPI, 4, {});
  assert.deepStrictEqual(networkCalls, []);
});

// ── the budget ───────────────────────────────────────────────────────────────

test('a zero budget asks exactly once and then fails', async () => {
  reset();
  await assert.rejects(() => selectBestNode({ requireBridges: [EXT], waitMs: 0 }));
  assert.strictEqual(networkCalls.length, ONLINE.length, 'one sweep, no poll');
});

test('the budget comes from cluster.scheduling.bridge_wait_s, and survives its absence', async () => {
  reset({ excluded_nodes: [], ...NUMERIC_DEFAULTS, bridge_wait_s: 0 });
  await assert.rejects(() => selectBestNode({ requireBridges: [EXT] }));
  assert.strictEqual(networkCalls.length, ONLINE.length, 'bridge_wait_s: 0 -> one sweep');

  // config/site.json is gitignored, so a checkout has no scheduling block at all
  // and getSchedulingConfig's own defaults are what production sees. An absent
  // key must not become NaN and skip the wait -- or hang forever.
  const noKey = { excluded_nodes: [], ...NUMERIC_DEFAULTS };
  delete noKey.bridge_wait_s;
  reset(noKey);
  bridgesByNode = { 'cyberhub-node-6': [EXT] };
  assert.strictEqual((await selectBestNode({ requireBridges: [EXT] })).node, 'cyberhub-node-6');
});

// ── the shared helper, directly ──────────────────────────────────────────────

test('keepBridgeReadyNodes returns the RAW rows, so each caller keeps its own scoring', async () => {
  reset();
  bridgesByNode = { 'cyberhub-node-6': [EXT], 'cyberhub-node-7': [EXT] };
  const kept = await keepBridgeReadyNodes(CLUSTER, { requireBridges: [EXT], ...FAST });
  assert.deepStrictEqual(kept.map(r => r.node), ['cyberhub-node-6', 'cyberhub-node-7']);
  assert.strictEqual(kept[0].maxmem, 256 * GiB, 'untouched resource rows, not scored ones');
});

test('keepBridgeReadyNodes on an empty candidate list is a no-op, not a throw', async () => {
  // filterSchedulableNodes answers [] for an empty cluster and lets its CALLER
  // raise "No online nodes found in cluster" -- this must not steal that error.
  reset();
  assert.deepStrictEqual(await keepBridgeReadyNodes([], { requireBridges: [EXT], ...FAST }), []);
  assert.deepStrictEqual(networkCalls, []);
});
