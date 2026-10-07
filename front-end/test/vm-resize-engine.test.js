/**
 * Tests for the VM resize engine (src/utils/vm-resize.js)
 *
 * Two rules here cannot be got wrong, and both fail SILENTLY:
 *
 *   1. NEVER LEAVE A STUDENT'S MACHINE POWERED OFF. A resize is stop ->
 *      reconfigure -> start. Every way that sequence can go wrong ends with a
 *      machine that is off, and a student who cannot work at all is a far worse
 *      outcome than a resize that did not take. decidePowerPlan is extracted as
 *      a pure function precisely so the "start it back even when the resize
 *      FAILED" cell can be pinned without a cluster.
 *
 *      The inverse cell matters just as much: a machine that was ALREADY
 *      stopped must stay stopped. An instructor resizing thirty lanes has not
 *      asked to boot the three that were deliberately shut down, and a resize
 *      that switches machines on as a side effect is one an admin stops
 *      trusting.
 *
 *   2. NEVER REBOOT A MACHINE THAT IS ALREADY THE RIGHT SIZE. A bulk resize
 *      aimed at a whole course routinely includes machines that already match —
 *      a re-run after a partial failure, or lanes deployed later with the newer
 *      sizing. Rebooting those takes a student's machine away for no change at
 *      all. isNoOp is what prevents it, and its "an omitted field means leave
 *      it alone" contract is the part that is easy to invert.
 *
 * Nothing here touches Proxmox. site-config is stubbed through require.cache
 * because vm-resize -> lane-deployer -> batch-deployer calls
 * getSchedulingConfig() at MODULE level, and config/site.json is gitignored and
 * absent from a plain checkout — the same stub vm-bulk-mutex.test.js uses.
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
  getClusterNodes: () => [],
  getNodeAddress: () => '127.0.0.1',
  getDefaultTemplateNode: () => 'pve1',
});
stub(path.join(SRC_UTILS, 'cybercore-db.js'), {
  cybercoreQuery: async () => ({ rows: [], rowCount: 0 }),
});

/**
 * A fake cluster.
 *
 * proxmox.js and lane-deployer.js are BOTH stubbed, so nothing here opens a
 * socket. Without the proxmox stub these tests reach for the real
 * PROXMOX_API_URL and spend seconds timing out against a host that is not
 * there — slow, and green or red depending on the network rather than the code.
 *
 * The fake models the one behaviour the orchestration turns on: a config PUT
 * only takes effect while the guest is STOPPED. That is not a detail invented
 * for the test — it is why the sequence is stop -> apply -> start rather than a
 * single call, and a fake that applied writes to a running VM would let a
 * regression that skips the stop pass cleanly.
 */
let vm;
const calls = [];
function resetVm(over = {}) {
  calls.length = 0;
  vm = {
    status: 'running', cores: 4, memory: 8192, balloon: 0,
    refuseApply: false, refuseStart: false, ignoreShutdown: false,
    ...over,
  };
}

stub(path.join(SRC_UTILS, 'proxmox.js'), {
  proxmoxAPI: async (method, p) => {
    calls.push(`${method} ${p.replace(/^.*\/(qemu|lxc)\/\d+/, '')}`);
    if (p.endsWith('/config') && method === 'GET') {
      return { cores: vm.cores, memory: vm.memory, balloon: vm.balloon };
    }
    if (p.endsWith('/status/current')) return { status: vm.status };
    if (p.endsWith('/status/shutdown')) {
      if (!vm.ignoreShutdown) vm.status = 'stopped';
      return 'UPID:x';
    }
    if (p.endsWith('/status/stop')) { vm.status = 'stopped'; return 'UPID:x'; }
    if (p.endsWith('/status/start')) {
      if (vm.refuseStart) throw new Error('start refused');
      vm.status = 'running';
      return 'UPID:x';
    }
    return {};
  },
  getPowerState: async () => vm.status,
  waitForPowerState: async (n, v, pt, want) => {
    if (vm.status === want) return want;
    const e = new Error(`did not reach ${want}`);
    e.code = 'POWER_STATE_TIMEOUT';
    throw e;
  },
  waitForTask: async () => ({}),
  findTemplateNode: async () => 'pve1',
  forceDestroyVM: async () => true,
  waitForVmidsGone: async () => ({ surviving: [] }),
  PROXMOX_URL: 'https://example.invalid',
});

stub(path.join(SRC_UTILS, 'lane-deployer.js'), {
  applyResources: async ({ resources }) => {
    calls.push('applyResources');
    if (vm.refuseApply) return { applied: {}, warnings: ['Proxmox said no'] };
    // The rule the whole sequence exists for: a config write only lands while
    // the guest is stopped. On a running VM it goes to [PENDING] and the live
    // config is unchanged — which is exactly what a skipped stop looks like.
    if (vm.status !== 'running') {
      if (resources.cores) vm.cores = resources.cores;
      if (resources.memory_mb) vm.memory = resources.memory_mb;
    }
    return { applied: { ...resources }, warnings: [] };
  },
});

const {
  isNoOp, decidePowerPlan, describeMismatch, resizeOneVm, RESIZABLE_FIELDS,
} = require(path.join(SRC_UTILS, 'vm-resize.js'));

// ── isNoOp ──────────────────────────────────────────────────────────────────

test('an identical request is a no-op, so the machine is not rebooted for nothing', () => {
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, { cores: 4, memory_mb: 8192 }), true);
});

test('any difference in either field is not a no-op', () => {
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, { cores: 8, memory_mb: 8192 }), false);
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, { cores: 4, memory_mb: 16384 }), false);
});

test('an omitted field means "leave it alone" and cannot make a change look like a no-op', () => {
  // The inversion to guard against: treating an absent `cores` as 0 or as a
  // mismatch would reboot every machine on a memory-only resize.
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, { memory_mb: 8192 }), true);
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, { memory_mb: 16384 }), false);
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, { cores: 4 }), true);
});

test('a request with no resizable field at all is vacuously a no-op', () => {
  // resizeOneVm rejects this case before it can matter; isNoOp must not be the
  // thing that decides it, or an empty body would silently power-cycle a class.
  assert.strictEqual(isNoOp({ cores: 4, memory_mb: 8192 }, {}), true);
});

test('string and number sizings compare equal, because Proxmox returns strings', () => {
  assert.strictEqual(isNoOp({ cores: '4', memory_mb: '8192' }, { cores: 4, memory_mb: 8192 }), true);
});

test('disk is not a resizable field', () => {
  assert.deepStrictEqual(RESIZABLE_FIELDS, ['cores', 'memory_mb']);
});

// ── decidePowerPlan ─────────────────────────────────────────────────────────

test('a machine that was running and is now stopped gets started', () => {
  const p = decidePowerPlan({ wasRunning: true, endState: 'stopped' });
  assert.strictEqual(p.action, 'start');
});

test('a machine that was running and already came back needs no second start', () => {
  const p = decidePowerPlan({ wasRunning: true, endState: 'running' });
  assert.strictEqual(p.action, 'none');
  assert.strictEqual(p.restored, 'yes');
});

test('an unreadable end state is treated as "not running", so power is restored anyway', () => {
  // Failing closed here is the safe direction: an extra start against a running
  // VM is a no-op to Proxmox, whereas skipping one leaves a student stranded.
  const p = decidePowerPlan({ wasRunning: true, endState: 'unknown' });
  assert.strictEqual(p.action, 'start');
});

test('a machine that was already stopped is LEFT stopped', () => {
  // A resize must not switch machines on as a side effect.
  const p = decidePowerPlan({ wasRunning: false, endState: 'stopped' });
  assert.strictEqual(p.action, 'none');
  assert.strictEqual(p.restored, 'left_stopped');
});

test('a machine that was already stopped is left alone even if it is somehow running', () => {
  const p = decidePowerPlan({ wasRunning: false, endState: 'running' });
  assert.strictEqual(p.action, 'none');
  assert.strictEqual(p.restored, 'left_stopped');
});

// ── the orchestration, end to end ───────────────────────────────────────────

test('a running machine is shut down, re-sized, and started again', async () => {
  resetVm();
  const r = await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8, memory_mb: 16384 },
  });
  assert.strictEqual(r.status, 'resized');
  assert.deepStrictEqual(r.before, { cores: 4, memory_mb: 8192, balloon: 0 });
  assert.strictEqual(r.after.cores, 8);
  assert.strictEqual(r.after.memory_mb, 16384);
  assert.strictEqual(r.was_running, true);
  assert.strictEqual(r.power_restored, 'yes');
  assert.strictEqual(vm.status, 'running', 'the student is left with a machine that is ON');
  // The order is the mechanism, not an implementation detail.
  const seq = calls.filter(c => /shutdown|applyResources|start/.test(c));
  assert.deepStrictEqual(seq, ['POST /status/shutdown', 'applyResources', 'POST /status/start']);
});

test('the graceful shutdown is tried FIRST — a hard stop is never the opening move', async () => {
  resetVm();
  await resizeOneVm({ node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 } });
  assert.ok(!calls.includes('POST /status/stop'),
    'a guest that shuts down cleanly must never be power-pulled; unsaved work depends on it');
});

test('a guest that ignores the shutdown is escalated, and the loss is reported', async () => {
  resetVm({ ignoreShutdown: true });
  const r = await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 },
  });
  assert.strictEqual(r.status, 'resized');
  assert.strictEqual(r.forced, true);
  assert.ok(calls.includes('POST /status/stop'));
  assert.ok(r.warnings.some(w => /unsaved work/i.test(w)),
    'a power-pull loses in-memory work and must say so');
  assert.strictEqual(vm.status, 'running');
});

test('a machine that was ALREADY the right size is not touched at all', async () => {
  resetVm({ cores: 8, memory: 16384 });
  const r = await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8, memory_mb: 16384 },
  });
  assert.strictEqual(r.status, 'unchanged');
  assert.ok(!calls.some(c => /shutdown|stop|start|applyResources/.test(c)),
    'a no-op must not power-cycle a student off their machine for nothing');
});

test('a machine that was already stopped is re-sized and LEFT stopped', async () => {
  resetVm({ status: 'stopped' });
  const r = await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 },
  });
  assert.strictEqual(r.status, 'resized');
  assert.strictEqual(r.power_restored, 'left_stopped');
  assert.strictEqual(vm.status, 'stopped', 'a resize must not switch machines on as a side effect');
  assert.ok(!calls.includes('POST /status/start'));
});

test('THE GUARANTEE: a FAILED resize still leaves the machine running', async () => {
  // The single most important behaviour in this file. A student whose machine
  // is off cannot work at all, which is far worse than a machine that is merely
  // the wrong size — so the start is not conditional on success.
  resetVm({ refuseApply: true });
  const r = await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 },
  });
  assert.strictEqual(r.status, 'failed');
  assert.match(r.error, /Proxmox said no/);
  assert.strictEqual(r.power_restored, 'yes');
  assert.strictEqual(vm.status, 'running');
});

test('an LXC is re-sized live, with no power cycle', async () => {
  resetVm({ status: 'running' });
  // The fake only applies writes to a stopped guest, so an LXC that took the
  // QEMU path would come back 'failed' — which is the assertion.
  vm.status = 'stopped';
  const r = await resizeOneVm({
    node: 'pve1', vmid: 200, providerType: 'lxc', resources: { cores: 2 },
  });
  assert.strictEqual(r.status, 'resized');
  assert.ok(!calls.some(c => /status\/(shutdown|stop|start)/.test(c)),
    'containers take cores and memory live — interrupting the lane gateway is pointless');
});

// ── the durable marker ──────────────────────────────────────────────────────

test('onSettled says settled:true once the machine is back where it belongs', async () => {
  resetVm();
  const seen = [];
  await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 },
    onSettled: (o) => { seen.push(o); },
  });
  assert.deepStrictEqual(seen, [{ power_restored: 'yes', settled: true }]);
});

test('onSettled says settled:FALSE when the machine could not be started again', async () => {
  // The marker written before the stop is the ONLY durable record that
  // something owes this machine a power-on. Clearing it here would turn a
  // recoverable failure into a machine that stays off until a student complains.
  resetVm({ refuseStart: true });
  const seen = [];
  const r = await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 },
    onSettled: (o) => { seen.push(o); },
  });
  assert.strictEqual(r.power_restored, 'failed');
  assert.strictEqual(seen[0].settled, false, 'the recovery marker would have been dropped');
  assert.ok(r.warnings.some(w => /could not power the machine back on/i.test(w)));
});

test('onIntent runs BEFORE the guest is stopped, or the marker is useless', async () => {
  resetVm();
  let stateAtIntent = null;
  await resizeOneVm({
    node: 'pve1', vmid: 100, providerType: 'qemu', resources: { cores: 8 },
    onIntent: async ({ was_running }) => { stateAtIntent = { was_running, live: vm.status }; },
  });
  assert.deepStrictEqual(stateAtIntent, { was_running: true, live: 'running' },
    'a marker written after the stop cannot record that the machine WAS running');
});

// ── describeMismatch ────────────────────────────────────────────────────────

test('Proxmox\'s own refusal is preferred over a generic mismatch message', () => {
  const msg = describeMismatch({ cores: 4 }, { cores: 8 }, ['balloon 8192 exceeds memory 4096']);
  assert.match(msg, /balloon 8192 exceeds memory 4096/);
});

test('a silent mismatch names the field, because that is the [PENDING] case', () => {
  // A config write that lands in Proxmox's [PENDING] section reports success
  // and changes nothing. There is no warning to quote — only the read-back.
  const msg = describeMismatch({ cores: 4, memory_mb: 8192 }, { cores: 8 }, []);
  assert.match(msg, /cores is 4, expected 8/);
  assert.doesNotMatch(msg, /memory_mb/, 'a field that was not requested must not be reported');
});

// ── resizeOneVm guard clauses ───────────────────────────────────────────────

test('disk is refused by the engine, not just by the route', () => {
  // The route rejects disk_gb with a 400, but this is the belt: no future
  // caller should be able to reach the grow path, which would enlarge the
  // block device and leave the guest filesystem untouched.
  return resizeOneVm({ node: 'pve1', vmid: 100, resources: { disk_gb: 256 } })
    .then(r => {
      assert.strictEqual(r.status, 'failed');
      assert.match(r.error, /disk resizing is not supported/i);
    });
});

test('an empty sizing is refused before anything is powered off', () => {
  return resizeOneVm({ node: 'pve1', vmid: 100, resources: {} })
    .then(r => {
      assert.strictEqual(r.status, 'failed');
      assert.match(r.error, /nothing to change/i);
      // Never touched power, so there is nothing to restore.
      assert.strictEqual(r.was_running, null);
    });
});
