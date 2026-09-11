/**
 * gateway-clone-recovery.test.js -- surviving a transient node fault mid-deploy.
 *
 * THE INCIDENT THIS EXISTS FOR
 * `pct clone` maps the source RBD image and immediately mounts
 * /dev/rbd-pve/<fsid>/<pool>/<image> to copy from it. That path is a SYMLINK
 * created by udev, not by the kernel, so there is a race between the map and the
 * symlink existing. Most nodes win it. One node doing 282 MiB/s of Ceph backfill
 * lost it every single time:
 *
 *     mount: ... fsconfig() failed: /dev/rbd-pve/.../vm-169200-disk-0:
 *            Can't lookup blockdev ... exit code 32
 *
 * Measured on that node: the symlink was absent immediately after `rbd map` and
 * present after `udevadm settle`. So the very same clone succeeds moments later
 * -- but the deploy had no retry, and `replicateGatewayTemplate` falls back to
 * the origin template only when REPLICATION throws, never when a clone from a
 * SUCCESSFUL replica fails. So the lane just died, and node-selector kept
 * choosing that node because a backfilling machine has idle CPU and free RAM and
 * therefore scores best.
 *
 * Three rules are pinned here, each one a step the incident needed and lacked:
 *   1. a failed clone is retried against the same source (beats the race);
 *   2. a replica that keeps failing falls back to the ORIGIN template;
 *   3. the target VMID is cleared between attempts, or attempt 2 fails with
 *      "CT already exists" -- a different fault wearing the same clothes.
 *
 * Proxmox is stubbed through require.cache, the way lane-deployer-slots.test.js
 * does it. configureLaneTailscale no-ops when Tailscale is unconfigured, so the
 * clone path needs nothing else stood up.
 *
 * Run: node --test "test/*.test.js"
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

// batch-deployer reads site.json at module load; it is gitignored and absent in
// a plain checkout.
stub('site-config.js', {
  getSchedulingConfig: () => ({
    min_free_mem_gb: 8, min_free_disk_gb: 20,
    max_concurrent_lanes: 5, max_concurrent_clones: 4,
    node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
  }),
  getDefaultTemplateNode: () => 'node-5',
  getNodeAddress: () => null,
  getClusterNodes: () => ['node-5', 'node-8'],
  // resolveLaneNetworking needs the real transit-VLAN shape to build the
  // gateway's wan0. Mirrors config/example-site.json.
  getV2LabNetwork: () => ({
    bridge: 'vmbr0', vlan_tag: 60, subnet: '100.100.60.0/22',
    gateway: '100.100.60.1',
    host_range: { first: '100.100.60.10', last: '100.100.63.254' },
    reserved: [],
  }),
  getV1LanSubnet: () => '192.18.0.0/24',
  getModuleNetwork: () => null,
  getModuleNetworks: () => ({}),
});

// ── the stubbed cluster ──────────────────────────────────────────────────────
const calls = { clones: [], destroys: [], configs: [] };

// Each entry: (sourceNode, sourceVmid) -> how many more times it should fail.
let failuresLeft = new Map();

function keyOf(node, vmid) { return `${vmid}@${node}`; }

stub('proxmox.js', {
  PROXMOX_URL: 'https://stub',
  async proxmoxAPI(method, url) {
    const clone = url.match(/nodes\/([^/]+)\/lxc\/(\d+)\/clone$/);
    if (clone) {
      const [, node, vmid] = clone;
      calls.clones.push({ node, vmid: Number(vmid) });
      const k = keyOf(node, vmid);
      const left = failuresLeft.get(k) || 0;
      if (left > 0) {
        failuresLeft.set(k, left - 1);
        throw new Error(
          "clone failed: command 'mount -o ro /dev/rbd-pve/fsid/vmpool/vm-" + vmid +
          "-disk-0 /var/lib/lxc/110881/.copy-volume-2//' failed: exit code 32"
        );
      }
      return 'UPID:stub::';
    }
    if (/\/config$/.test(url)) { calls.configs.push(url); return {}; }
    return {};
  },
  async waitForTask() { return true; },
  async forceDestroyVM(vmid, type, node) {
    calls.destroys.push({ vmid, type, node });
    return true;
  },
  async findTemplateNode(vmid, hint) { return hint || 'node-5'; },
  async waitForVmidsGone() { return true; },
});

stub('node-ssh.js', { pctExec: async () => ({ stdout: '', stderr: '', code: 0 }), pctPushFromString: async () => true });
stub('tailscale.js', { isEnabled: () => false });

const cld = require(path.join(UTILS, 'challenge-lane-deployer.js'));

const GW_TEMPLATE = 1694;     // the origin gateway template
const GW_SOURCE_NODE = 'node-5';
const TARGET_NODE = 'node-8';
const REPLICA_ID = 169200;    // the node-local copy replicateGatewayTemplate made

const JOB = {
  laneId: 'lane-1',
  user: { id: 'u1', email: 'student@example.edu' },
  vxlanId: 10881,
  vnet: { vnet: 'aaaabgdc' },
  vnetInt: { vnet: 'aaaabgdd' },
  laneName: 'cle-cy400-10881',
  targetNode: TARGET_NODE,
  wanIp: '100.100.63.136/22',
};

const CTX = {
  spec: {}, subnetScheme: 'v2', moduleKey: 'crucible', challengeKey: 'cy400',
  description: '', logTag: '[test]',
};

function reset(failures = {}) {
  calls.clones = []; calls.destroys = []; calls.configs = [];
  failuresLeft = new Map(Object.entries(failures));
}

const run = (overrides = {}) => cld.cloneGatewayWithRecovery({
  job: JOB, node: TARGET_NODE, localTemplateId: REPLICA_ID,
  gwSourceNode: GW_SOURCE_NODE, gatewayVmid: GW_TEMPLATE,
  ctx: CTX, logTag: '[test]', retryMs: 0,
  ...overrides,
});

// ── rule 1: retry beats the race ─────────────────────────────────────────────

test('a clean clone happens once and does not touch the origin', () => {
  reset();
  return run().then((r) => {
    assert.strictEqual(r.attempts, 1);
    assert.strictEqual(r.usedOrigin, false);
    assert.deepStrictEqual(calls.clones, [{ node: TARGET_NODE, vmid: REPLICA_ID }]);
    assert.deepStrictEqual(calls.destroys, [], 'nothing to clean up when nothing failed');
  });
});

test('THE FIX: one transient failure is retried against the same source', async () => {
  // Exactly the incident: the udev symlink is missing on attempt 1 and present
  // on attempt 2. Before this, that cost the student their whole environment.
  reset({ [`${REPLICA_ID}@${TARGET_NODE}`]: 1 });
  const r = await run();
  assert.strictEqual(r.attempts, 2);
  assert.strictEqual(r.usedOrigin, false, 'the replica recovered — no cross-node copy needed');
  assert.deepStrictEqual(calls.clones.map((c) => c.vmid), [REPLICA_ID, REPLICA_ID]);
});

// ── rule 3: the target is cleared between attempts ───────────────────────────

test('the target VMID is destroyed before each retry', async () => {
  // A failed clone usually removes its own destination image. "Usually" is not
  // something a retry can be built on: a survivor makes attempt 2 fail with
  // "CT already exists", which looks like an entirely different fault.
  reset({ [`${REPLICA_ID}@${TARGET_NODE}`]: 1 });
  await run();
  assert.strictEqual(calls.destroys.length, 1, 'exactly one cleanup, before attempt 2');
  assert.deepStrictEqual(calls.destroys[0], {
    vmid: 100000 + JOB.vxlanId, type: 'lxc', node: TARGET_NODE,
  });
});

// ── rule 2: fall back to the origin ──────────────────────────────────────────

test('THE GAP: a replica that keeps failing falls back to the ORIGIN template', async () => {
  // replicateGatewayTemplate falls back only when REPLICATION throws. A clone
  // that fails from a SUCCESSFUL replica had no fallback at all, which is what
  // turned one bad node into a failed lane.
  reset({ [`${REPLICA_ID}@${TARGET_NODE}`]: 2 });
  const r = await run();
  assert.strictEqual(r.attempts, 3);
  assert.strictEqual(r.usedOrigin, true);
  assert.deepStrictEqual(calls.clones, [
    { node: TARGET_NODE, vmid: REPLICA_ID },
    { node: TARGET_NODE, vmid: REPLICA_ID },
    { node: GW_SOURCE_NODE, vmid: GW_TEMPLATE },   // cross-node, from where it lives
  ]);
});

test('the origin attempt is issued on the node that HOLDS the template', async () => {
  // Cloning 1694 from node-8 fails with "Configuration file does not exist" —
  // the template lives on node-5. Proxmox copies across nodes via `target`.
  reset({ [`${REPLICA_ID}@${TARGET_NODE}`]: 2 });
  await run();
  assert.strictEqual(calls.clones[2].node, GW_SOURCE_NODE);
});

// ── no wasted work when there is no replica ──────────────────────────────────

test('with no replica, the ladder is 2 attempts — not a third identical one', async () => {
  // When replication already fell back, localTemplateId IS the origin. A third
  // attempt would clone the same thing from the same place: a slower failure.
  reset({ [`${GW_TEMPLATE}@${GW_SOURCE_NODE}`]: 99 });
  await assert.rejects(() => run({ localTemplateId: GW_TEMPLATE }), /after 2 attempts/);
  assert.strictEqual(calls.clones.length, 2);
  assert.ok(calls.clones.every((c) => c.node === GW_SOURCE_NODE && c.vmid === GW_TEMPLATE));
});

// ── the error when everything fails ──────────────────────────────────────────

test('exhausting the ladder reports what was tried, not just the last error', async () => {
  reset({
    [`${REPLICA_ID}@${TARGET_NODE}`]: 99,
    [`${GW_TEMPLATE}@${GW_SOURCE_NODE}`]: 99,
  });
  await assert.rejects(() => run(), (err) => {
    // The API returns Proxmox's one-line summary; "Can't lookup blockdev" lives
    // in the task log, not here. Assert on what actually crosses the wire.
    assert.match(err.message, /exit code 32/, 'keeps the real cause');
    assert.match(err.message, /mount -o ro/, 'and the command that produced it');
    assert.match(err.message, /after 3 attempts on node-8/, 'says how hard it tried, and where');
    assert.match(err.message, /fallback to the origin/, 'says the origin was tried too');
    assert.strictEqual(err.attempts, 3);
    assert.strictEqual(err.node, TARGET_NODE);
    return true;
  });
});

// ── the production delay is real, and only failures pay it ───────────────────

test('the shipped retry delay is seconds, and only a failed clone waits', () => {
  assert.ok(cld.GATEWAY_CLONE_RETRY_MS >= 1000,
    'the udev race resolves in ms, but a too-short pause makes the retry pointless');
  assert.ok(cld.GATEWAY_CLONE_RETRY_MS <= 15000,
    'a whole class of lanes should not queue behind one slow node');
});

test('a successful first attempt never sleeps', async () => {
  // retryMs is only reachable from i > 0, so a healthy deploy is unchanged.
  reset();
  const started = process.hrtime.bigint();
  await cld.cloneGatewayWithRecovery({
    job: JOB, node: TARGET_NODE, localTemplateId: REPLICA_ID,
    gwSourceNode: GW_SOURCE_NODE, gatewayVmid: GW_TEMPLATE,
    ctx: CTX, logTag: '[test]',           // NO retryMs override — production value
  });
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(ms < 1000, `a clean clone waited ${Math.round(ms)}ms — it must not sleep at all`);
});
