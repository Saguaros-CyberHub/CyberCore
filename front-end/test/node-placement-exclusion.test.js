/**
 * node-placement-exclusion.test.js -- keeping new lanes off a node that cannot
 * start them, and keeping the two placement paths from disagreeing about it.
 *
 * THE INCIDENT THIS EXISTS FOR
 * cyberhub-node-8 joined the cluster and immediately began a Ceph backfill.
 * Every challenge lane the scheduler put there cloned fine and then died in
 * `pct start`:
 *
 *     lxc-start: ... Failed to run lxc.hook.pre-start for container "110881"
 *     ... exited with status 32
 *
 * -- the pre-start hook losing the race for the udev-created symlink
 * /dev/rbd-pve/<fsid>/<pool>/<image>. Nothing was wrong with the lane. The node
 * was wrong, and it stayed wrong for hours.
 *
 * WHY THE SCHEDULER MADE IT WORSE
 * node-selector ranks on FREE capacity. A node whose only workload is Ceph
 * backfill has idle CPU and free RAM, so node-8 scored BEST in the cluster and
 * every lane went straight into it. That is why the fixture below gives the
 * excluded node the lowest cpu/mem/disk usage of any node: a fixture where the
 * excluded node was merely mediocre would pass even if exclusion did nothing.
 * The first test pins that -- node-8 wins when nothing excludes it -- so the
 * rest of the file is actually proving something.
 *
 * AND WHY THERE WERE TWO ANSWERS
 * node-selector.selectBestNode filtered on online + free mem + free disk;
 * batch-deployer.distributeAcrossNodes filtered on online + free mem, inline
 * and separately. A single-lane deploy and a six-lane batch could therefore
 * disagree about which nodes were usable. Both now go through
 * node-selector.filterSchedulableNodes, and every assertion here is made
 * against BOTH paths for exactly that reason.
 *
 * The soft-quarantine rule from utils/node-health.js is exercised with the REAL
 * module (state reset between tests), because the rule that matters -- a
 * quarantine must never make the cluster undeployable -- is a property of the
 * two modules together.
 *
 * Run: node --test test/node-placement-exclusion.test.js
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
    type: 'node',
    node: name,
    status,
    maxcpu: 64,
    cpu,                       // Proxmox reports this as a 0..1 fraction
    maxmem: 256 * GiB,
    mem: memUsedGb * GiB,
    maxdisk: 1000 * GiB,
    disk: diskUsedGb * GiB,
  };
}

// node-8 is the emptiest machine in the cluster -- that is the whole problem.
// node-9 is offline and would otherwise be emptier still.
const CLUSTER = [
  nodeRow('cyberhub-node-8', { cpu: 0.01, memUsedGb:   6, diskUsedGb:  40 }),
  nodeRow('cyberhub-node-5', { cpu: 0.30, memUsedGb:  96, diskUsedGb: 300 }),
  nodeRow('cyberhub-node-6', { cpu: 0.45, memUsedGb: 150, diskUsedGb: 420 }),
  nodeRow('cyberhub-node-7', { cpu: 0.62, memUsedGb: 200, diskUsedGb: 610 }),
  nodeRow('cyberhub-node-9', { cpu: 0.00, memUsedGb:   2, diskUsedGb:  10, status: 'offline' }),
];

const ONLINE = CLUSTER.filter(n => n.status === 'online').map(n => n.node);

const WEIGHTS = { cpu: 0.35, mem: 0.55, disk: 0.10 };
const NUMERIC_DEFAULTS = {
  min_free_mem_gb: 8,
  min_free_disk_gb: 20,
  max_concurrent_lanes: 5,
  max_concurrent_clones: 4,
  node_score_weights: WEIGHTS,
};

// Mutable so each test can hand the code a different cluster.scheduling block.
let sched = { excluded_nodes: [], ...NUMERIC_DEFAULTS };

stub('site-config.js', {
  getSchedulingConfig: () => sched,
  getClusterNodes: () => ONLINE,
  getNodeAddress: () => null,
});

let resourceCalls = 0;

stub('proxmox.js', {
  PROXMOX_URL: 'https://stub',
  async proxmoxAPI(method, url) {
    if (/\/cluster\/resources\?type=node$/.test(url)) {
      resourceCalls++;
      return CLUSTER;
    }
    throw new Error(`unexpected proxmox call: ${method} ${url}`);
  },
});

const { proxmoxAPI } = require(path.join(UTILS, 'proxmox.js'));
const { selectBestNode, filterSchedulableNodes } = require(path.join(UTILS, 'node-selector.js'));
const { distributeAcrossNodes } = require(path.join(UTILS, 'batch-deployer.js'));

// The REAL quarantine module -- node-selector requires the same instance.
const nodeHealth = require(path.join(UTILS, 'node-health.js'));

function reset(schedOverride) {
  sched = schedOverride || { excluded_nodes: [], ...NUMERIC_DEFAULTS };
  nodeHealth._resetForTests();
  resourceCalls = 0;
}

// ── the fixture itself ───────────────────────────────────────────────────────

test('THE PATHOLOGY: the backfilling node scores best and wins by default', async () => {
  // If this ever stops being true, every exclusion test below goes green
  // without proving anything.
  reset();
  const best = await selectBestNode();
  assert.strictEqual(best.node, 'cyberhub-node-8');

  const spread = await distributeAcrossNodes(proxmoxAPI, 6);
  assert.ok(spread.includes('cyberhub-node-8'), 'batch placement also favours it');
});

// ── hard exclusion from config ───────────────────────────────────────────────

test('excluded_nodes keeps the best-scoring node out of single-lane placement', async () => {
  reset({ excluded_nodes: ['cyberhub-node-8'], ...NUMERIC_DEFAULTS });
  const best = await selectBestNode();
  assert.notStrictEqual(best.node, 'cyberhub-node-8');
  assert.strictEqual(best.node, 'cyberhub-node-5', 'next-best node instead');
});

test('excluded_nodes keeps the best-scoring node out of BATCH placement too', async () => {
  // The half of the bug that survived the first fix: batch deploys had their
  // own inline online-only filter, so six lanes still landed on node-8.
  reset({ excluded_nodes: ['cyberhub-node-8'], ...NUMERIC_DEFAULTS });
  const assignments = await distributeAcrossNodes(proxmoxAPI, 6);
  assert.strictEqual(assignments.length, 6);
  assert.ok(!assignments.includes('cyberhub-node-8'), `node-8 got lanes: ${assignments.join(',')}`);
  for (const a of assignments) assert.ok(ONLINE.includes(a));
});

test('a caller-supplied exclude is applied on top of the configured ones', async () => {
  reset({ excluded_nodes: ['cyberhub-node-8'], ...NUMERIC_DEFAULTS });
  const best = await selectBestNode({ exclude: ['cyberhub-node-5'] });
  assert.notStrictEqual(best.node, 'cyberhub-node-8');
  assert.notStrictEqual(best.node, 'cyberhub-node-5');
  assert.strictEqual(best.node, 'cyberhub-node-6');
});

test('selectBestNode() with no arguments still works', async () => {
  // Six production call sites call it bare; the options object must be optional.
  reset({ excluded_nodes: ['cyberhub-node-8'], ...NUMERIC_DEFAULTS });
  const best = await selectBestNode();
  assert.strictEqual(best.node, 'cyberhub-node-5');
});

test('a scheduling config with NO excluded_nodes key places lanes normally', async () => {
  // Several existing tests stub getSchedulingConfig with only the numeric keys.
  // An undefined excluded_nodes must not become a TypeError inside placement.
  reset({ ...NUMERIC_DEFAULTS });
  assert.strictEqual(sched.excluded_nodes, undefined);

  const best = await selectBestNode();
  assert.strictEqual(best.node, 'cyberhub-node-8');

  const assignments = await distributeAcrossNodes(proxmoxAPI, 4);
  assert.strictEqual(assignments.length, 4);
});

test('excluding every online node fails loudly, naming the setting', async () => {
  // An operator who drains the whole cluster gets an error that says WHY, not
  // "No online nodes found in cluster", which would send them to Proxmox.
  reset({ excluded_nodes: [...ONLINE], ...NUMERIC_DEFAULTS });

  await assert.rejects(() => selectBestNode(), (e) => {
    assert.match(e.message, /excluded_nodes/);
    assert.match(e.message, /No schedulable nodes/);
    return true;
  });

  await assert.rejects(() => distributeAcrossNodes(proxmoxAPI, 3), (e) => {
    assert.match(e.message, /excluded_nodes/);
    return true;
  });
});

// ── soft exclusion from an in-flight fault ───────────────────────────────────

test('a quarantined node is passed over even when it scores best', async () => {
  reset();
  nodeHealth.markNodeFault('cyberhub-node-8', 'clone failed');

  const best = await selectBestNode();
  assert.notStrictEqual(best.node, 'cyberhub-node-8');
  assert.strictEqual(best.node, 'cyberhub-node-5');

  const assignments = await distributeAcrossNodes(proxmoxAPI, 6);
  assert.ok(!assignments.includes('cyberhub-node-8'));
});

test('QUARANTINE IS SOFT: quarantining every node still places the lane', async () => {
  // Honouring a quarantine to the point of refusing to deploy would turn a
  // transient node fault into a cluster-wide outage. Losing one lane on a
  // suspect node is strictly better.
  reset();
  for (const n of ONLINE) nodeHealth.markNodeFault(n, 'clone failed: exit code 32');

  const best = await selectBestNode();
  assert.ok(ONLINE.includes(best.node), `placed nowhere: ${best && best.node}`);

  const assignments = await distributeAcrossNodes(proxmoxAPI, 3);
  assert.strictEqual(assignments.length, 3);
  for (const a of assignments) assert.ok(ONLINE.includes(a));
});

test('a hard exclusion beats a soft one: quarantine cannot resurrect an excluded node', async () => {
  // Everything online is quarantined AND node-8 is excluded. The soft rule
  // hands back the quarantined survivors, but node-8 must not be among them.
  reset({ excluded_nodes: ['cyberhub-node-8'], ...NUMERIC_DEFAULTS });
  for (const n of ONLINE) nodeHealth.markNodeFault(n, 'clone failed');

  const best = await selectBestNode();
  assert.notStrictEqual(best.node, 'cyberhub-node-8');
});

test('an expired quarantine puts the node back in rotation', async () => {
  reset();
  nodeHealth.markNodeFault('cyberhub-node-8', 'clone failed', { ttlMs: 1 });
  await new Promise(r => setTimeout(r, 5));

  const best = await selectBestNode();
  assert.strictEqual(best.node, 'cyberhub-node-8');
});

// ── the filter that both paths share ─────────────────────────────────────────

test('offline nodes are still dropped by both paths', async () => {
  // node-9 is offline and would score best of all if it were not.
  reset();
  for (let i = 0; i < 5; i++) {
    const best = await selectBestNode();
    assert.notStrictEqual(best.node, 'cyberhub-node-9');
  }
  const assignments = await distributeAcrossNodes(proxmoxAPI, 8);
  assert.ok(!assignments.includes('cyberhub-node-9'));
});

test('filterSchedulableNodes returns raw resource rows, so callers keep their own scoring', () => {
  reset({ excluded_nodes: ['cyberhub-node-8'], ...NUMERIC_DEFAULTS });
  const rows = filterSchedulableNodes(CLUSTER, { logTag: '[test]' });

  assert.deepStrictEqual(rows.map(r => r.node), ['cyberhub-node-5', 'cyberhub-node-6', 'cyberhub-node-7']);
  assert.strictEqual(rows[0].maxmem, 256 * GiB, 'untouched Proxmox row, not a scored object');
  assert.strictEqual(rows[0], CLUSTER.find(n => n.node === 'cyberhub-node-5'));
});

test('an empty cluster is reported as an empty cluster, not as a drained one', () => {
  // 'No online nodes found in cluster' has to stay reachable: "nothing is up"
  // and "you excluded everything" are different pages at 2am.
  reset();
  assert.deepStrictEqual(filterSchedulableNodes([], { logTag: '[test]' }), []);
  assert.deepStrictEqual(filterSchedulableNodes(null, { logTag: '[test]' }), []);
  assert.deepStrictEqual(
    filterSchedulableNodes(CLUSTER.filter(n => n.status !== 'online'), { logTag: '[test]' }),
    [],
  );
});
