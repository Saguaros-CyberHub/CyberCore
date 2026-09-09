/**
 * Tests for the restart engine (src/utils/vm-power.js) and target resolution
 * (cle/utils/restart.js)
 *
 * What these protect:
 *
 *   1. NEVER LEAVE A MACHINE POWERED OFF. A restart is stop -> start, and every
 *      way that sequence can fail ends with a machine that is off. The start
 *      therefore runs in a finally, on the failure path too — an extra start
 *      against an already-running guest is a no-op to Proxmox, whereas a
 *      skipped one is a student who cannot work.
 *
 *   2. THE GRACEFUL SHUTDOWN IS TRIED FIRST. A hard stop is a power-pull: the
 *      disk survives, anything unsaved in an open application does not. It is
 *      the escalation, never the opening move.
 *
 *   3. `start_stopped` IS A PARAMETER, NOT A RULE. "Restart everything before
 *      class" wants machines that are off switched on; a targeted restart of
 *      two wedged boxes must not quietly boot the six a student deliberately
 *      shut down. Both behaviours are pinned.
 *
 *   4. A NOT-YET-RUNNING LANE IS SKIPPED, NEVER FATAL. The table polls every
 *      8s, so one lane a co-instructor touched three seconds ago must not fail
 *      the other forty-one.
 *
 * proxmox.js is stubbed through require.cache so nothing opens a socket, and
 * the fake models real power semantics rather than returning {} to everything.
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

let vm;
const calls = [];
function resetVm(over = {}) {
  calls.length = 0;
  vm = { status: 'running', refuseStart: false, ignoreShutdown: false, failStarts: 0, ...over };
}

stub(path.join(SRC_UTILS, 'proxmox.js'), {
  proxmoxAPI: async (method, p) => {
    calls.push(`${method} ${p.replace(/^.*\/(qemu|lxc)\/\d+/, '')}`);
    if (p.endsWith('/status/current')) return { status: vm.status };
    if (p.endsWith('/status/shutdown')) {
      if (!vm.ignoreShutdown) vm.status = 'stopped';
      return 'UPID:x';
    }
    if (p.endsWith('/status/stop')) { vm.status = 'stopped'; return 'UPID:x'; }
    if (p.endsWith('/status/start')) {
      // failStarts fails the FIRST n starts and then behaves, which is how the
      // finally-block recovery gets exercised: the happy-path start throws, and
      // only the guard afterwards can bring the machine back.
      if (vm.failStarts > 0) { vm.failStarts--; throw new Error('start refused'); }
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

const { restartOneVm } = require(path.join(SRC_UTILS, 'vm-power.js'));

const run = (over = {}) => restartOneVm({
  node: 'pve1', vmid: 610003, providerType: 'qemu', ...over,
});

// ── the happy path ──────────────────────────────────────────────────────────

test('a running machine is shut down and started again, in that order', () => {
  resetVm();
  return run().then(r => {
    assert.strictEqual(r.status, 'restarted');
    assert.strictEqual(r.was_running, true);
    assert.strictEqual(r.power_restored, 'yes');
    assert.strictEqual(vm.status, 'running');
    const seq = calls.filter(c => /shutdown|stop|start/.test(c));
    assert.deepStrictEqual(seq, ['POST /status/shutdown', 'POST /status/start']);
  });
});

test('the graceful shutdown is tried FIRST — a hard stop is never the opening move', () => {
  resetVm();
  return run().then(() => {
    assert.ok(!calls.includes('POST /status/stop'),
      'a guest that shuts down cleanly must never be power-pulled; unsaved work depends on it');
  });
});

test('a guest that ignores the shutdown is escalated, and the loss is reported', () => {
  resetVm({ ignoreShutdown: true });
  return run().then(r => {
    assert.strictEqual(r.status, 'restarted');
    assert.strictEqual(r.forced, true);
    assert.ok(calls.includes('POST /status/stop'));
    assert.ok(r.warnings.some(w => /unsaved work/i.test(w)));
    assert.strictEqual(vm.status, 'running');
  });
});

// ── start_stopped ───────────────────────────────────────────────────────────

test('a stopped machine is started when start_stopped is on', () => {
  // "Restart everything before class" means everything ends up running.
  resetVm({ status: 'stopped' });
  return run({ startIfStopped: true }).then(r => {
    assert.strictEqual(r.status, 'restarted');
    assert.strictEqual(r.was_running, false);
    assert.strictEqual(vm.status, 'running');
    assert.ok(!calls.includes('POST /status/shutdown'),
      'there is nothing to shut down — do not ask a stopped guest to stop');
  });
});

test('a stopped machine is left alone when start_stopped is off', () => {
  resetVm({ status: 'stopped' });
  return run({ startIfStopped: false }).then(r => {
    assert.strictEqual(r.status, 'skipped');
    assert.strictEqual(r.power_restored, 'left_stopped');
    assert.strictEqual(vm.status, 'stopped');
    assert.ok(!calls.some(c => /status\/(start|stop|shutdown)/.test(c)),
      'a skipped machine must not be touched at all');
  });
});

// ── the guarantee ───────────────────────────────────────────────────────────

test('THE GUARANTEE: a machine that was running is running again even when the run fails', () => {
  // The single most important behaviour here. A student whose machine is off
  // cannot work at all, which is worse than a restart that did not take.
  //
  // The first start throws, so the happy path cannot be what brings the machine
  // back — only the finally-block guard can.
  resetVm({ failStarts: 1 });
  return run().then(r => {
    assert.ok(r.error, 'the failure must be reported, not swallowed');
    assert.strictEqual(vm.status, 'running', 'the machine was left powered off');
    assert.strictEqual(r.power_restored, 'recovered');
    assert.strictEqual(calls.filter(c => c === 'POST /status/start').length, 2,
      'exactly one retry: the failed attempt and the recovery');
  });
});

test('a machine that cannot be started at all reports it rather than claiming success', () => {
  resetVm({ refuseStart: true });
  return run().then(r => {
    assert.strictEqual(r.power_restored, 'failed');
    assert.ok(r.warnings.some(w => /could not power the machine back on/i.test(w)));
  });
});

test('onSettled says settled:false when the machine may still be off', () => {
  // The durable marker written before the stop is the only record that
  // something owes this machine a power-on. Clearing it here would turn a
  // recoverable failure into a machine that stays off until someone complains.
  resetVm({ refuseStart: true });
  const seen = [];
  return run({ onSettled: (o) => { seen.push(o); } }).then(() => {
    assert.strictEqual(seen[0].settled, false);
  });
});

test('onIntent runs BEFORE the guest is stopped, or the marker is useless', () => {
  resetVm();
  let at = null;
  return run({ onIntent: async ({ was_running }) => { at = { was_running, live: vm.status }; } })
    .then(() => {
      assert.deepStrictEqual(at, { was_running: true, live: 'running' },
        'a marker written after the stop cannot record that the machine WAS running');
    });
});

test('a skipped machine writes no durable marker', () => {
  // Nothing was taken down, so nothing owes it a power-on — and a marker left
  // behind would have the boot sweep switch on a machine that was off on purpose.
  resetVm({ status: 'stopped' });
  const seen = [];
  return run({ startIfStopped: false, onIntent: () => seen.push('intent') })
    .then(() => assert.deepStrictEqual(seen, []));
});

// ── resolveRestartTargets ───────────────────────────────────────────────────

stub(path.join(SRC_UTILS, 'cybercore-db.js'), { cybercoreQuery: async () => ({ rows: [] }) });
stub(path.join(SRC_UTILS, 'site-config.js'), {
  getSchedulingConfig: () => ({
    min_free_mem_gb: 8, min_free_disk_gb: 20,
    max_concurrent_lanes: 5, max_concurrent_clones: 4,
    node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
  }),
  getClusterNodes: () => [], getNodeAddress: () => '127.0.0.1',
  getDefaultTemplateNode: () => 'pve1',
});

const { resolveRestartTargets, MAX_RESTART_TARGETS } = require(
  path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils', 'restart.js'));

const lane = (over = {}) => ({
  lane_id: 'a'.repeat(36),
  name: 'cle-cybv454-10003',
  vxlan_id: 10003,
  status: 'active',
  student_email: 'a@example.edu',
  user_id: 'u1',
  config: {
    workstations: [{ slot: 0, vmid: 610003 }, { slot: 1, vmid: 310221 }],
    attached_modules: [{ material_id: 'lab-a', vms: [{ vm_id: 800001 }] }],
  },
  ...over,
});
const threw = (fn) => { try { fn(); return null; } catch (e) { return e; } };

test('every non-gateway machine on the lane becomes a target', () => {
  const { targets } = resolveRestartTargets([lane()]);
  assert.deepStrictEqual(targets.map(t => t.vmid), [610003, 310221, 800001]);
  assert.ok(targets.every(t => t.vmid !== 100000 + 10003), 'the gateway must never be a target');
});

test('a lane mid-deploy is SKIPPED, not fatal to the batch', () => {
  const { targets, skipped } = resolveRestartTargets([
    lane({ lane_id: 'a'.repeat(36) }),
    lane({ lane_id: 'b'.repeat(36), status: 'deploying' }),
  ]);
  assert.strictEqual(targets.length, 3);
  assert.strictEqual(skipped.length, 1);
  assert.match(skipped[0].reason, /already running/i);
});

test('an ERROR lane is allowed, unlike a redeploy', () => {
  // A rebuild has to clone into a working gateway and cannot. A restart only
  // powers guests that already exist, and a half-built lane whose machines are
  // up is exactly what an instructor is trying to clear.
  const { targets } = resolveRestartTargets([lane({ status: 'error' })]);
  assert.strictEqual(targets.length, 3);
});

test('a lane with nothing but a gateway is skipped with a reason', () => {
  const { targets, skipped } = resolveRestartTargets([lane({ config: {} })]);
  assert.strictEqual(targets.length, 0);
  assert.match(skipped[0].reason, /other than its gateway/i);
});

test('materialId narrows to ONE environment, sparing the student\'s workstation', () => {
  const { targets } = resolveRestartTargets([lane()], { materialId: 'lab-a' });
  assert.deepStrictEqual(targets.map(t => t.vmid), [800001]);
});

test('a lane holding a different environment is skipped, not silently emptied', () => {
  const { targets, skipped } = resolveRestartTargets([lane()], { materialId: 'lab-zzz' });
  assert.strictEqual(targets.length, 0);
  assert.match(skipped[0].reason, /no machines for that environment/i);
});

test('an explicit machine list narrows to those vmids', () => {
  const { targets } = resolveRestartTargets([lane()], { machines: [{ vmid: 310221 }] });
  assert.deepStrictEqual(targets.map(t => t.vmid), [310221]);
});

test('an empty or unusable machine list is a 400, not "all machines"', () => {
  assert.strictEqual(threw(() => resolveRestartTargets([lane()], { machines: [] })).status, 400);
  assert.strictEqual(
    threw(() => resolveRestartTargets([lane()], { machines: [{ vmid: 'nope' }] })).status, 400);
});

test('over the cap is a hard 400 naming the count, never a silent truncation', () => {
  const many = Array.from({ length: 120 }, (_, i) =>
    lane({ lane_id: String(i).padStart(36, '0') }));   // 3 machines each = 360
  const e = threw(() => resolveRestartTargets(many));
  assert.strictEqual(e.status, 400);
  assert.match(e.message, new RegExp(`at most ${MAX_RESTART_TARGETS}`));
  assert.match(e.message, /got 360/);
});

test('each target carries its lane and the gateway it must not be', () => {
  // gateway_vmid rides along so a caller can assert the exclusion held rather
  // than trusting it.
  const t = resolveRestartTargets([lane()]).targets[0];
  assert.strictEqual(t.lane_id, 'a'.repeat(36));
  assert.strictEqual(t.student_email, 'a@example.edu');
  assert.strictEqual(t.gateway_vmid, 100000 + 10003);
});
