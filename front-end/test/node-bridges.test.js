/** Kernel bridge readiness, independent of Proxmox configuration inventory. */
const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const UTILS = path.join(__dirname, '..', 'src', 'utils');
let rowsByNode = {}, rawByNode = {}, failNodes = {}, slowNodes = {};
let calls = [], apiCalls = [], inFlight = 0, peakInFlight = 0;
function stub(file, exports) {
  const p = require.resolve(path.join(UTILS, file));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
}
stub('proxmox.js', {
  async proxmoxAPI(method, apiPath) {
    apiCalls.push(apiPath);
    // Proxmox's normal inventory omits existing SDN interfaces.
    if (/\/network$/.test(apiPath)) return [{ iface: 'vmbr0', active: 1 }];
    throw new Error(`unexpected API request: ${method} ${apiPath}`);
  },
});
stub('node-ssh.js', {
  async nodeExec(node, command, opts) {
    calls.push({ node, command, opts });
    inFlight++;
    peakInFlight = Math.max(peakInFlight, inFlight);
    try {
      if (slowNodes[node]) await new Promise(r => setTimeout(r, slowNodes[node]));
      if (failNodes[node]) throw new Error(failNodes[node]);
      const stdout = Object.hasOwn(rawByNode, node)
        ? rawByNode[node] : JSON.stringify(rowsByNode[node] || []);
      return { stdout, stderr: '' };
    } finally { inFlight--; }
  },
});
const { bridgeIsUp, readNodeBridges, bridgeNames, probeNodesForBridges, BRIDGE_PROBE_MS } =
  require(path.join(UTILS, 'node-bridges.js'));
beforeEach(() => {
  rowsByNode = {}; rawByNode = {}; failNodes = {}; slowNodes = {};
  calls = []; apiCalls = []; inFlight = 0; peakInFlight = 0;
});
const up = (...names) => names.map(ifname => ({
  ifname, flags: ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'], operstate: 'UP',
}));

test('bridgeIsUp requires a kernel interface name and administrative UP flag', () => {
  assert.strictEqual(bridgeIsUp(up('aaaabgdc')[0]), true);
  for (const row of [
    { ifname: 'aaaabgdc', flags: ['BROADCAST', 'MULTICAST'] },
    { ifname: 'aaaabgdc', operstate: 'UP' },
    { ifname: 'aaaabgdc', flags: 'UP' },
    { ifname: 'aaaabgdc', flags: ['LOWER_UP'] },
  ]) assert.strictEqual(bridgeIsUp(row), false);
});
test('an empty bridge is usable without carrier when administratively UP', () => {
  for (const operstate of ['DOWN', 'UNKNOWN']) {
    assert.strictEqual(bridgeIsUp({
      ifname: 'aaaabgdc', flags: ['NO-CARRIER', 'BROADCAST', 'MULTICAST', 'UP'], operstate,
    }), true);
  }
});
test('synthetic API active/exists values cannot prove kernel bridge readiness', () => {
  for (const row of [
    { iface: 'aaaabgdc', active: 1 }, { iface: 'aaaabgdc', exists: 1 },
    { ifname: 'aaaabgdc', active: 1, exists: 1 },
    { ifname: 'aaaabgdc', flags: [], active: 1 },
  ]) assert.strictEqual(bridgeIsUp(row), false);
});
test('bridgeIsUp rejects malformed rows', () => {
  for (const row of [null, undefined, {}, { flags: ['UP'] },
    { ifname: '', flags: ['UP'] }, { ifname: 42, flags: ['UP'] }]) {
    assert.strictEqual(bridgeIsUp(row), false);
  }
});
test('an SDN bridge absent from API inventory is ready when present in the kernel', async () => {
  rowsByNode.n1 = up('vmbr0', 'aaaabhed');
  const result = await probeNodesForBridges(['n1'], ['aaaabhed']);
  assert.deepStrictEqual(result.ready, ['n1']);
  assert.deepStrictEqual(result.missingByNode, {});
  assert.deepStrictEqual(apiCalls, [], 'configuration and task APIs cannot decide readiness');
  assert.deepStrictEqual(calls[0].command, ['ip', '-j', 'link', 'show', 'type', 'bridge']);
});
test('readNodeBridges returns only bridges with kernel UP flags', async () => {
  rowsByNode.n1 = [...up('vmbr0', 'aaaabgdc'),
    { ifname: 'aaaabgdd', flags: ['BROADCAST', 'MULTICAST'], operstate: 'DOWN' },
    { iface: 'aaaabgde', active: 1 }];
  assert.deepStrictEqual([...(await readNodeBridges('n1'))].sort(), ['aaaabgdc', 'vmbr0']);
});
test('legacy listed mode cannot admit a bridge without kernel evidence', async () => {
  rowsByNode.n1 = [{ ifname: 'aaaabgdc', flags: [] }];
  assert.strictEqual((await readNodeBridges('n1', { mode: 'listed' })).size, 0);
});
test('readNodeBridges forwards the bounded SSH timeout', async () => {
  rowsByNode.n1 = up('aaaabgdc');
  await readNodeBridges('n1', { perCallMs: 1234 });
  assert.deepStrictEqual(calls[0].opts, { timeoutMs: 1234 });
  await readNodeBridges('n1');
  assert.deepStrictEqual(calls[1].opts, { timeoutMs: BRIDGE_PROBE_MS });
});
test('readNodeBridges propagates SSH failures', async () => {
  failNodes.n1 = 'SSH connection timed out';
  await assert.rejects(() => readNodeBridges('n1'), /timed out/);
});
test('malformed SSH output is unreachable rather than missing or ready', async () => {
  for (const stdout of ['', 'not json', 'null', '{}']) {
    rawByNode.n1 = stdout;
    const result = await probeNodesForBridges(['n1'], ['aaaabgdc']);
    assert.deepStrictEqual(result.ready, [], stdout);
    assert.deepStrictEqual(result.missingByNode, {}, stdout);
    assert.ok(result.unreachable.n1, `must report malformed output: ${stdout}`);
  }
});
test('an explicitly down bridge cannot be promoted by lack of an active reload', async () => {
  rowsByNode.n1 = [{ ifname: 'aaaabgdc', flags: [], operstate: 'DOWN' }];
  const result = await probeNodesForBridges(['n1'], ['aaaabgdc']);
  assert.deepStrictEqual(result.ready, []);
  assert.deepStrictEqual(result.missingByNode.n1, ['aaaabgdc']);
  assert.deepStrictEqual(apiCalls, []);
});
test('bridgeNames accepts strings and VNet rows, skipping blanks and duplicates', () => {
  assert.deepStrictEqual(bridgeNames([{ vnet: 'b' }, 'a', { vnet: 'b' }, null,
    undefined, '', { vnet: '' }, 'a']), ['b', 'a']);
  assert.deepStrictEqual(bridgeNames(null), []);
  assert.deepStrictEqual(bridgeNames([]), []);
});
test('probeNodesForBridges partitions ready, missing, and unreachable nodes', async () => {
  rowsByNode.n1 = up('aaaabgdc', 'aaaabgdd');
  rowsByNode.n2 = up('aaaabgdc');
  rowsByNode.n3 = [{ ifname: 'aaaabgdc', flags: [] }];
  failNodes.n4 = 'connect ETIMEDOUT';
  const result = await probeNodesForBridges(['n1', 'n2', 'n3', 'n4'], ['aaaabgdc', 'aaaabgdd']);
  assert.deepStrictEqual(result.ready, ['n1']);
  assert.deepStrictEqual(result.missingByNode.n2, ['aaaabgdd']);
  assert.deepStrictEqual(result.missingByNode.n3, ['aaaabgdc', 'aaaabgdd']);
  assert.deepStrictEqual(result.presentByNode.n2, ['aaaabgdc']);
  assert.match(result.unreachable.n4, /ETIMEDOUT/);
  const buckets = [...result.ready, ...Object.keys(result.missingByNode), ...Object.keys(result.unreachable)];
  assert.deepStrictEqual(buckets.sort(), ['n1', 'n2', 'n3', 'n4']);
});
test('failed SSH probes never admit a node or throw from the cluster probe', async () => {
  failNodes.n1 = 'Permission denied (publickey)';
  failNodes.n2 = 'Could not resolve hostname n2';
  const result = await probeNodesForBridges(['n1', 'n2'], ['aaaabgdc']);
  assert.deepStrictEqual(result.ready, []);
  assert.strictEqual(Object.keys(result.unreachable).length, 2);
  assert.deepStrictEqual(result.missingByNode, {});
});
test('nodes are probed concurrently once each', async () => {
  for (const n of ['n1', 'n2', 'n3', 'n4']) { rowsByNode[n] = up('aaaabgdc'); slowNodes[n] = 20; }
  const result = await probeNodesForBridges(['n1', 'n2', 'n3', 'n4'], ['aaaabgdc']);
  assert.strictEqual(result.ready.length, 4);
  assert.strictEqual(peakInFlight, 4);
  assert.strictEqual(calls.length, 4);
});
test('ready nodes retain input order instead of completion order', async () => {
  for (const n of ['n1', 'n2', 'n3']) rowsByNode[n] = up('aaaabgdc');
  slowNodes.n1 = 30;
  assert.deepStrictEqual((await probeNodesForBridges(['n1', 'n2', 'n3'], ['aaaabgdc'])).ready,
    ['n1', 'n2', 'n3']);
});
test('empty requirements make no SSH or API calls', async () => {
  assert.deepStrictEqual((await probeNodesForBridges(['n1', 'n2'], [])).ready, ['n1', 'n2']);
  assert.deepStrictEqual((await probeNodesForBridges(['n1'], [null, undefined, ''])).ready, ['n1']);
  assert.deepStrictEqual(calls, []);
  assert.deepStrictEqual(apiCalls, []);
});
test('empty candidates make no SSH or API calls', async () => {
  assert.deepStrictEqual((await probeNodesForBridges([], ['aaaabgdc'])).ready, []);
  assert.deepStrictEqual(calls, []);
  assert.deepStrictEqual(apiCalls, []);
});
