/**
 * Tests for the resize capacity projection (src/middleware/deployment-guards.js)
 *
 * Raising RAM across a cohort is the one way this feature can hurt the cluster,
 * and it spends memory that OTHER courses — which the admin doing the resize
 * cannot see — are also drawing on. projectNodeMemory is the arithmetic that
 * decides whether the change is allowed, and it is wrong in both directions in
 * ways nobody notices until class starts:
 *
 *   too lax   -> a node is overcommitted, guests swap or fail to boot
 *   too strict-> a legitimate change is refused for no reason
 *
 * Three rules, all easy to get backwards:
 *
 *   1. THE DELTA IS WHAT LANDS ON THE NODE, not the new size. The machine's
 *      current memory is already counted in the node's usage. Summing the
 *      requested sizes instead would refuse a class that is already running
 *      happily at those sizes.
 *
 *   2. A STOPPED MACHINE CONTRIBUTES ZERO. It consumes no host memory now, and
 *      a resize deliberately leaves it stopped — so re-sizing a powered-off
 *      machine from 4 GB to 64 GB changes nothing on the node today. Counting
 *      it would block a whole batch on machines that are not even running.
 *
 *   3. A DECREASE NEVER BLOCKS, even on a node that is already over threshold.
 *      Refusing "make these smaller" because the node is full is precisely
 *      backwards, and it is exactly what a naive `projected > threshold` check
 *      does.
 *
 * site-config is stubbed because deployment-guards calls getSchedulingConfig()
 * at MODULE level for MAX_CONCURRENT_DEPLOYS.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const SRC_UTILS = path.join(__dirname, '..', 'src', 'utils');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

stub(path.join(SRC_UTILS, 'site-config.js'), {
  getSchedulingConfig: () => ({
    min_free_mem_gb: 8, min_free_disk_gb: 20,
    max_concurrent_lanes: 5, max_concurrent_clones: 4,
    node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
  }),
});

const {
  projectNodeMemory, buildResizePreview, MAX_NODE_MEMORY_PCT,
} = require(path.join(__dirname, '..', 'src', 'middleware', 'deployment-guards.js'));

/** A node with round numbers, so the percentages in the assertions are obvious. */
const node = (name, used_gb, total_gb = 100, maxcpu = 32) => ({
  node: name,
  mem_used_gb: used_gb,
  mem_total_gb: total_gb,
  mem_pct: Math.round((used_gb / total_gb) * 100),
  maxcpu,
});

const target = (nodeName, currentMb, running = true) => ({
  node: nodeName, running, current: { memory_mb: currentMb },
});

// ── rule 1: the delta, not the new size ─────────────────────────────────────

test('only the DIFFERENCE in memory is charged to the node', () => {
  // 50 GB used. One machine goes 4 GB -> 8 GB, so the node gains 4 GB, not 8.
  const rows = projectNodeMemory(
    [node('pve1', 50)],
    [target('pve1', 4096)],
    { memory_mb: 8192 }
  );
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].delta_gb, 4);
  assert.strictEqual(rows[0].projected_gb, 54);
  assert.strictEqual(rows[0].projected_pct, 54);
  assert.strictEqual(rows[0].over, false);
});

test('several machines on one node accumulate into a single delta', () => {
  const rows = projectNodeMemory(
    [node('pve1', 40)],
    [target('pve1', 4096), target('pve1', 4096), target('pve1', 4096)],
    { memory_mb: 8192 }
  );
  assert.strictEqual(rows[0].machines, 3);
  assert.strictEqual(rows[0].delta_gb, 12);   // 3 x 4 GB
  assert.strictEqual(rows[0].projected_gb, 52);
});

test('machines are charged to their OWN node, never pooled', () => {
  const rows = projectNodeMemory(
    [node('pve1', 10), node('pve2', 70)],
    [target('pve1', 4096), target('pve2', 4096)],
    { memory_mb: 65536 }
  );
  const by = Object.fromEntries(rows.map(r => [r.node, r]));
  assert.strictEqual(by.pve1.over, false, 'the empty node has room');
  assert.strictEqual(by.pve2.over, true, 'the full node does not');
});

test('a node with none of the selected machines is not reported at all', () => {
  const rows = projectNodeMemory(
    [node('pve1', 10), node('pve2', 10)],
    [target('pve1', 4096)],
    { memory_mb: 8192 }
  );
  assert.deepStrictEqual(rows.map(r => r.node), ['pve1']);
});

// ── rule 2: stopped machines are free ───────────────────────────────────────

test('a STOPPED machine contributes nothing, however large the request', () => {
  // 95 GB of 100 used. A stopped machine going to 64 GB must not block: it is
  // not running now, and the resize leaves it stopped.
  const rows = projectNodeMemory(
    [node('pve1', 95)],
    [target('pve1', 4096, false)],
    { memory_mb: 65536 }
  );
  assert.strictEqual(rows.length, 0, 'a stopped machine created a node row');
});

test('a mixed batch charges only the running machines', () => {
  const rows = projectNodeMemory(
    [node('pve1', 50)],
    [target('pve1', 4096, true), target('pve1', 4096, false), target('pve1', 4096, true)],
    { memory_mb: 8192 }
  );
  assert.strictEqual(rows[0].machines, 2);
  assert.strictEqual(rows[0].delta_gb, 8);
});

// ── rule 3: shrinking never blocks ──────────────────────────────────────────

test('a DECREASE never blocks, even on a node that is already over threshold', () => {
  const rows = projectNodeMemory(
    [node('pve1', 95)],                      // already at 95%, over the 80% rail
    [target('pve1', 16384)],
    { memory_mb: 4096 }                      // 16 GB -> 4 GB
  );
  assert.strictEqual(rows[0].delta_gb, -12);
  assert.strictEqual(rows[0].projected_gb, 83);
  assert.strictEqual(rows[0].over, false, 'freeing memory was treated as a violation');
});

// ── the threshold boundary ──────────────────────────────────────────────────

test('exactly at the threshold is allowed; a hair over is not', () => {
  assert.strictEqual(MAX_NODE_MEMORY_PCT, 80, 'these boundaries assume the 80% default');

  const at = projectNodeMemory(
    [node('pve1', 76)], [target('pve1', 0 + 4096)], { memory_mb: 8192 });
  assert.strictEqual(at[0].projected_gb, 80);
  assert.strictEqual(at[0].over, false, '80% of 80% must not be a violation');

  const over = projectNodeMemory(
    [node('pve1', 77)], [target('pve1', 4096)], { memory_mb: 8192 });
  assert.strictEqual(over[0].projected_gb, 81);
  assert.strictEqual(over[0].over, true);
});

// ── degenerate inputs ───────────────────────────────────────────────────────

test('a cores-only request charges no memory anywhere', () => {
  const rows = projectNodeMemory([node('pve1', 95)], [target('pve1', 4096)], { cores: 16 });
  assert.strictEqual(rows.length, 0);
});

test('missing nodes, targets or sizes never throw', () => {
  assert.deepStrictEqual(projectNodeMemory(null, null, null), []);
  assert.deepStrictEqual(projectNodeMemory([], [], {}), []);
  assert.deepStrictEqual(projectNodeMemory([node('pve1', 10)], [{ running: true }], { memory_mb: 8192 }), []);
});

// ── buildResizePreview ──────────────────────────────────────────────────────

/** Minimal /cluster/resources + /storage doubles for getClusterHealth. */
function fakeProxmox({ nodes, vms = [] }) {
  return async (method, p) => {
    if (p.startsWith('/api2/json/cluster/resources')) {
      return [
        ...nodes.map(n => ({
          type: 'node', status: 'online', node: n.node,
          cpu: 0.1, mem: n.mem_used_gb * 1073741824, maxmem: n.mem_total_gb * 1073741824,
          disk: 10 * 1073741824, maxdisk: 100 * 1073741824, maxcpu: n.maxcpu,
        })),
        ...vms,
      ];
    }
    if (p === '/api2/json/storage') return [];
    return [];
  };
}

test('a preview that overcommits a node cannot proceed and names the node', async () => {
  const p = await buildResizePreview({
    targets: [target('pve1', 4096), target('pve1', 4096)],
    resources: { memory_mb: 65536 },
    proxmoxAPI: fakeProxmox({ nodes: [node('pve1', 60)] }),
  });
  assert.strictEqual(p.canProceed, false);
  assert.match(p.errors[0], /pve1/);
  assert.match(p.errors[0], /2 of the selected machines/);
});

test('a preview within budget proceeds and counts running vs stopped', async () => {
  const p = await buildResizePreview({
    targets: [target('pve1', 4096), target('pve1', 4096, false)],
    resources: { memory_mb: 8192 },
    proxmoxAPI: fakeProxmox({ nodes: [node('pve1', 20)] }),
  });
  assert.strictEqual(p.canProceed, true);
  assert.strictEqual(p.summary.machines, 2);
  assert.strictEqual(p.summary.running, 1);
  assert.strictEqual(p.summary.stopped, 1);
});

test('asking for more cores than the node has warns but does not block', async () => {
  const p = await buildResizePreview({
    targets: [target('pve1', 4096)],
    resources: { cores: 64 },
    proxmoxAPI: fakeProxmox({ nodes: [node('pve1', 20, 100, 32)] }),
  });
  assert.strictEqual(p.canProceed, true, 'CPU overcommit is legal and must not block');
  assert.ok(p.warnings.some(w => /more than node pve1 physically has/.test(w)));
});

test('a memory size too small for a Windows desktop warns but does not block', async () => {
  const p = await buildResizePreview({
    targets: [target('pve1', 8192)],
    resources: { memory_mb: 1024 },
    proxmoxAPI: fakeProxmox({ nodes: [node('pve1', 20)] }),
  });
  assert.strictEqual(p.canProceed, true);
  assert.ok(p.warnings.some(w => /below what a Windows desktop needs/.test(w)));
});
