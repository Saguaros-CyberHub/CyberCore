/**
 * node-bridges.test.js -- "does this node actually have this SDN bridge yet?"
 *
 * WHAT THIS IS DEFENDING
 * Creating an environment commits a VXLAN block with one cluster-wide
 * `PUT /cluster/sdn`. That creates no bridges: it makes every node queue its OWN
 * "SRV Networking" reload (ifreload -a), and with hundreds of VNets in the shared
 * zone those land minutes to HOURS apart. A lane placed on a node whose reload has
 * not finished clones perfectly and then dies at `pct start`:
 *
 *     bridge 'aaaabgdc' does not exist
 *
 * So placement asks this module first. Two properties matter more than the rest:
 *
 *   1. THE PREDICATE IS STRICT. GET /nodes/<node>/network is built from the node's
 *      interface CONFIG, and that includes the generated interfaces.d/sdn, which is
 *      written at the START of the reload task. Proxmox marks a row active/exists
 *      only once the interface really is there. A "is it listed" check therefore
 *      reports every VNet as present for the whole hours-long window this exists
 *      for -- the exact false positive it is supposed to catch.
 *
 *   2. IT NEVER THROWS. A node mid-ifreload can simply stop answering. That means
 *      "not this node", which is a placement decision, not a failed deploy.
 *
 * Run: node --test test/node-bridges.test.js
 */

const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

// ── the stubbed cluster ──────────────────────────────────────────────────────

let rowsByNode = {};       // node -> the rows GET /nodes/<n>/network answers with
let failNodes = {};        // node -> error message it throws instead
let slowNodes = {};        // node -> ms before it answers
let calls = [];            // every path that crossed the wire
let optsSeen = [];         // the 4th argument, so the per-call timeout is provable
let inFlight = 0;
let peakInFlight = 0;

require.cache[require.resolve(path.join(UTILS, 'proxmox.js'))] = {
  id: 'proxmox', filename: 'proxmox', loaded: true,
  exports: {
    PROXMOX_URL: 'https://stub',
    async proxmoxAPI(method, apiPath, body, opts) {
      calls.push(apiPath);
      optsSeen.push(opts);
      const m = apiPath.match(/\/api2\/json\/nodes\/([^/]+)\/network$/);
      if (!m) throw new Error(`unexpected call: ${method} ${apiPath}`);
      const node = m[1];
      inFlight++;
      peakInFlight = Math.max(peakInFlight, inFlight);
      try {
        if (slowNodes[node]) await new Promise(r => setTimeout(r, slowNodes[node]));
        if (failNodes[node]) throw new Error(failNodes[node]);
        return rowsByNode[node] || [];
      } finally {
        inFlight--;
      }
    },
  },
};

const {
  bridgeIsUp, readNodeBridges, bridgeNames, probeNodesForBridges, BRIDGE_PROBE_MS,
} = require(path.join(UTILS, 'node-bridges.js'));

beforeEach(() => {
  rowsByNode = {}; failNodes = {}; slowNodes = {};
  calls = []; optsSeen = []; inFlight = 0; peakInFlight = 0;
});

const up = (...names) => names.map(iface => ({ iface, active: 1 }));

// ── the predicate ────────────────────────────────────────────────────────────

test('bridgeIsUp: active or exists is the evidence; being LISTED is not', () => {
  assert.strictEqual(bridgeIsUp({ iface: 'aaaabgdc', active: 1 }), true);
  assert.strictEqual(bridgeIsUp({ iface: 'aaaabgdc', exists: 1 }), true,
    'exists alone is kernel-level truth too -- active is not set for every type');
  assert.strictEqual(bridgeIsUp({ iface: 'aaaabgdc', active: 1, exists: 1 }), true);

  // THE CASE THIS MODULE EXISTS FOR: the vnet is in interfaces.d/sdn, written at
  // the start of the srvreload task, and ifreload has not created it yet.
  assert.strictEqual(bridgeIsUp({ iface: 'aaaabgdc' }), false,
    'listed with no active/exists means configured, NOT up');
  assert.strictEqual(bridgeIsUp({ iface: 'aaaabgdc', active: 0 }), false);
  assert.strictEqual(bridgeIsUp({ iface: 'aaaabgdc', active: 0, exists: 0 }), false);
});

test('bridgeIsUp: the API answers strings, so the comparison must not be ===1 on a string', () => {
  // pvesh/pveproxy hand numbers back as JSON numbers, but a proxy or an older
  // release can stringify them. Number() both sides rather than trust the type.
  assert.strictEqual(bridgeIsUp({ iface: 'x', active: '1' }), true);
  assert.strictEqual(bridgeIsUp({ iface: 'x', exists: '1' }), true);
  assert.strictEqual(bridgeIsUp({ iface: 'x', active: '0' }), false);
});

test('bridgeIsUp: junk is not a bridge', () => {
  for (const junk of [null, undefined, {}, { active: 1 }, { iface: '', active: 1 }, { iface: 42, active: 1 }]) {
    assert.strictEqual(bridgeIsUp(junk), false, `accepted ${JSON.stringify(junk)}`);
  }
});

// ── one node ─────────────────────────────────────────────────────────────────

test('readNodeBridges returns only the interfaces that are actually up', async () => {
  rowsByNode.n1 = [
    { iface: 'vmbr0', active: 1 },
    { iface: 'aaaabgdc', active: 1 },
    { iface: 'aaaabgdd' },              // configured, reload has not reached it
    { iface: 'aaaabgde', active: 0 },
  ];
  const seen = await readNodeBridges('n1');
  assert.deepStrictEqual([...seen].sort(), ['aaaabgdc', 'vmbr0']);
});

test('readNodeBridges carries its own timeout: a wedged node cannot hold the default 30s', async () => {
  rowsByNode.n1 = up('aaaabgdc');
  await readNodeBridges('n1', { perCallMs: 1234 });
  assert.deepStrictEqual(optsSeen[0], { timeoutMs: 1234 });

  optsSeen = [];
  await readNodeBridges('n1');
  assert.deepStrictEqual(optsSeen[0], { timeoutMs: BRIDGE_PROBE_MS },
    'and a default, so no caller can forget one');
});

test('readNodeBridges propagates a transport failure -- the CALLER decides what it means', async () => {
  failNodes.n1 = 'socket hang up';
  await assert.rejects(() => readNodeBridges('n1'), /socket hang up/);
});

test('readNodeBridges survives a node answering something that is not a list', async () => {
  rowsByNode.n1 = null;
  assert.strictEqual((await readNodeBridges('n1')).size, 0);
});

// ── names ────────────────────────────────────────────────────────────────────

test('bridgeNames takes vnet rows and strings, drops blanks, de-dupes, keeps order', () => {
  // The shape callers actually hold: [vnet, vnetInt] straight off
  // GET /cluster/sdn/vnets, where vnetInt is null on every v2 lane.
  assert.deepStrictEqual(bridgeNames([{ vnet: 'aaaabgdc' }, null]), ['aaaabgdc']);
  assert.deepStrictEqual(
    bridgeNames([{ vnet: 'b' }, 'a', { vnet: 'b' }, undefined, '', { vnet: '' }, 'a']),
    ['b', 'a'],
    'de-duped, blanks dropped, and NOT sorted -- the log line must be diffable'
  );
  assert.deepStrictEqual(bridgeNames(null), []);
  assert.deepStrictEqual(bridgeNames([]), []);
});

// ── many nodes ───────────────────────────────────────────────────────────────

test('probeNodesForBridges partitions every node into exactly one bucket', async () => {
  rowsByNode.n1 = up('aaaabgdc', 'aaaabgdd');
  rowsByNode.n2 = up('aaaabgdc');                 // halfway through its reload
  rowsByNode.n3 = [{ iface: 'aaaabgdc' }, { iface: 'aaaabgdd' }];  // configured, not up
  failNodes.n4 = 'connect ETIMEDOUT';

  const r = await probeNodesForBridges(['n1', 'n2', 'n3', 'n4'], ['aaaabgdc', 'aaaabgdd']);

  assert.deepStrictEqual(r.ready, ['n1']);
  assert.deepStrictEqual(r.missingByNode.n2, ['aaaabgdd']);
  assert.deepStrictEqual(r.missingByNode.n3, ['aaaabgdc', 'aaaabgdd']);
  assert.match(r.unreachable.n4, /ETIMEDOUT/);
  assert.deepStrictEqual(r.presentByNode.n2, ['aaaabgdc']);

  // exhaustive and disjoint: no node is in two buckets, none is in none
  const buckets = [
    ...r.ready, ...Object.keys(r.missingByNode), ...Object.keys(r.unreachable),
  ];
  assert.deepStrictEqual(buckets.sort(), ['n1', 'n2', 'n3', 'n4']);
  assert.strictEqual(new Set(buckets).size, 4);
});

test('probeNodesForBridges NEVER throws, however badly a node behaves', async () => {
  failNodes.n1 = 'ECONNREFUSED';
  failNodes.n2 = 'Could not resolve hostname n2';
  const r = await probeNodesForBridges(['n1', 'n2'], ['aaaabgdc']);
  assert.deepStrictEqual(r.ready, []);
  assert.strictEqual(Object.keys(r.unreachable).length, 2);
});

test('nodes are probed CONCURRENTLY -- two slow nodes cannot delay the rest', async () => {
  for (const n of ['n1', 'n2', 'n3', 'n4']) { rowsByNode[n] = up('aaaabgdc'); slowNodes[n] = 20; }
  const started = Date.now();
  const r = await probeNodesForBridges(['n1', 'n2', 'n3', 'n4'], ['aaaabgdc']);
  const elapsed = Date.now() - started;

  assert.strictEqual(r.ready.length, 4);
  assert.strictEqual(peakInFlight, 4, 'all four were in flight at once');
  assert.ok(elapsed < 60, `serial would be ~80ms; took ${elapsed}ms`);
  assert.strictEqual(calls.length, 4, 'and each node was asked exactly once');
});

test('ready is in INPUT order, not settle order, so two identical deploys log the same line', async () => {
  for (const n of ['n1', 'n2', 'n3']) rowsByNode[n] = up('aaaabgdc');
  slowNodes.n1 = 30;   // n1 answers last
  const r = await probeNodesForBridges(['n1', 'n2', 'n3'], ['aaaabgdc']);
  assert.deepStrictEqual(r.ready, ['n1', 'n2', 'n3']);
});

test('no names to require means every node is ready and NOTHING is asked', async () => {
  // This is what keeps every placement that does not cable a lane to a VNet --
  // a bare workstation clone -- exactly as cheap as it was before this existed.
  const r = await probeNodesForBridges(['n1', 'n2'], []);
  assert.deepStrictEqual(r.ready, ['n1', 'n2']);
  assert.strictEqual(calls.length, 0);

  const r2 = await probeNodesForBridges(['n1'], [null, undefined, '']);
  assert.deepStrictEqual(r2.ready, ['n1']);
  assert.strictEqual(calls.length, 0);
});

test('no nodes means no calls and no ready nodes', async () => {
  const r = await probeNodesForBridges([], ['aaaabgdc']);
  assert.deepStrictEqual(r.ready, []);
  assert.strictEqual(calls.length, 0);
});
