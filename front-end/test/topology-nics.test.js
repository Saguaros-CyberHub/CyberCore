/**
 * topology-nics.test.js — the Phase 0 equivalence gate.
 *
 * resolveVmNics() replaces five copy-pasted inline copies of "which VNet does
 * this VM attach to". This file transcribes the ORIGINAL inline implementation
 * from challenge-lane-deployer.js (lines 403-450 before the refactor) as
 * `legacyNets()` and asserts the new resolver emits byte-identical Proxmox
 * config for every shape a real spec produces.
 *
 * If a case here fails, do NOT update the expectation — one of the five copies
 * has diverged, and that divergence is a live bug.
 *
 * Run: node front-end/test/topology-nics.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
const goadDeploy = require(path.join(UTILS, 'goad-deploy'));
const { resolveVmNics, resolveVmSegments, resolveSegments, resolveSegmentBridges } =
  require(path.join(UTILS, 'lane-networking'));

const EXT = 'vx1234';
const INT = 'vx1234i';

// ── the pre-refactor implementation, transcribed verbatim ────────────────────
function legacyNets({ vmSpec, subnetScheme, goadVm, vnetExtName, vnetIntName }) {
  const isV3     = subnetScheme === 'v3';
  const vmType   = vmSpec.type || 'qemu';
  const goadMac  = goadVm?.mac;
  const isGoadVm = !!goadVm;
  const isDmz    = vmSpec.role === 'dmz';
  const vmVnet   = (isV3 && isGoadVm) ? vnetIntName : vnetExtName;

  if (vmType === 'lxc') {
    return { net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vmVnet, goadMac) };
  }
  if (isV3 && isDmz) {
    return {
      net0: `virtio,bridge=${vnetExtName}`,
      net1: `virtio,bridge=${vnetIntName}`,
    };
  }
  return { net0: goadDeploy.buildLaneNet0(vmSpec, vmVnet, goadMac, goadVm?.nic_model) };
}

// ── the shapes real specs actually produce ───────────────────────────────────
const GOAD_DC = { mac: '02:00:CC:04:D2:0A', nic_model: 'e1000', role: 'dc' };
const GOAD_LX = { mac: '02:00:CC:04:D2:14', nic_model: 'virtio', role: 'srv' };

const CASES = [
  ['v3 GOAD-matched qemu DC → internal',
    { name: 'DC01', type: 'qemu', vm_offset: 600000 }, 'v3', GOAD_DC],
  ['v3 GOAD-matched lxc → internal, net1',
    { name: 'LX01', type: 'lxc', vm_offset: 610000 }, 'v3', GOAD_LX],
  ['v3 dmz qemu → dual-homed ext+int',
    { name: 'web01', type: 'qemu', role: 'dmz', vm_offset: 620000 }, 'v3', null],
  ['v3 dmz lxc → single external NIC (lxc returns before dual-homing)',
    { name: 'web01', type: 'lxc', role: 'dmz', vm_offset: 630000 }, 'v3', null],
  ['v3 unmatched qemu (Kali) → external',
    { name: 'Kali', type: 'qemu', role: 'attacker', vm_offset: 640000 }, 'v3', null],
  ['v3 unmatched qemu with spec nic_model → external, model honoured',
    { name: 'target', type: 'qemu', nic_model: 'e1000', vm_offset: 650000 }, 'v3', null],
  ['v2 plain qemu → lane vnet',
    { name: 'dvwa', type: 'qemu', vm_offset: 600000 }, 'v2', null],
  ['v2 plain lxc → lane vnet, net1',
    { name: 'juice', type: 'lxc', vm_offset: 610000 }, 'v2', null],
  ['v2 dmz qemu → single NIC (dual-homing is v3-only)',
    { name: 'web01', type: 'qemu', role: 'dmz', vm_offset: 620000 }, 'v2', null],
  ['v2 GOAD-matched qemu → lane vnet (no internal segment exists)',
    { name: 'DC01', type: 'qemu', vm_offset: 630000 }, 'v2', GOAD_DC],
  ['v1 plain qemu → lane vnet',
    { name: 'metasploitable', type: 'qemu', vm_offset: 600000 }, 'v1', null],
];

for (const [label, vmSpec, subnetScheme, goadVm] of CASES) {
  test(`legacy equivalence — ${label}`, () => {
    const expected = legacyNets({ vmSpec, subnetScheme, goadVm, vnetExtName: EXT, vnetIntName: INT });
    const { nets } = resolveVmNics(vmSpec, {
      subnetScheme,
      bridges: resolveSegmentBridges(subnetScheme, EXT, INT),
      goadMac: goadVm?.mac,
      goadVm,
      isGoadVm: !!goadVm,
    });
    assert.deepStrictEqual(nets, expected, `${label}\n  legacy: ${JSON.stringify(expected)}\n  new:    ${JSON.stringify(nets)}`);
  });
}

// ── segment model ────────────────────────────────────────────────────────────
test('resolveSegments: v1/v2 have one segment, v3 has two', () => {
  assert.deepStrictEqual(resolveSegments('v1').map(s => s.id), ['lan']);
  assert.deepStrictEqual(resolveSegments('v2').map(s => s.id), ['lan']);
  assert.deepStrictEqual(resolveSegments('v3').map(s => s.id), ['ext', 'int']);
});

test('resolveSegmentBridges: non-v3 resolves every id to the single vnet', () => {
  assert.deepStrictEqual(resolveSegmentBridges('v3', EXT, INT), { ext: EXT, int: INT });
  assert.deepStrictEqual(resolveSegmentBridges('v2', EXT, EXT), { lan: EXT, ext: EXT, int: EXT });
});

test('dualHomed is set only for the multi-NIC case', () => {
  const ctx = { subnetScheme: 'v3', bridges: resolveSegmentBridges('v3', EXT, INT) };
  assert.strictEqual(resolveVmNics({ name: 'web01', role: 'dmz' }, ctx).dualHomed, true);
  assert.strictEqual(resolveVmNics({ name: 'Kali' }, ctx).dualHomed, false);
  assert.strictEqual(resolveVmNics({ name: 'LX01', type: 'lxc' }, ctx).dualHomed, false);
});

// ── the explicit path (what the canvas emits) ────────────────────────────────
test('explicit nics override the GOAD name derivation', () => {
  const ctx = {
    subnetScheme: 'v3',
    bridges: resolveSegmentBridges('v3', EXT, INT),
    goadMac: GOAD_DC.mac, goadVm: GOAD_DC, isGoadVm: true,
  };
  // Derivation would put a GOAD-matched host on int; the author pinned it to ext.
  const { nets, segments } = resolveVmNics(
    { name: 'DC01', type: 'qemu', nics: [{ segment: 'ext' }] }, ctx);
  assert.deepStrictEqual(segments, ['ext']);
  assert.ok(nets.net0.includes(`bridge=${EXT}`), nets.net0);
  assert.ok(nets.net0.includes(GOAD_DC.mac), 'GOAD MAC survives an explicit attachment');
});

test('explicit two-NIC attachment renders net0/net1 in authored order', () => {
  const ctx = { subnetScheme: 'v3', bridges: resolveSegmentBridges('v3', EXT, INT) };
  const { nets, segments } = resolveVmNics(
    { name: 'pivot', type: 'qemu', nics: [{ segment: 'int' }, { segment: 'ext' }] }, ctx);
  assert.deepStrictEqual(segments, ['int', 'ext']);
  assert.strictEqual(nets.net0, `virtio,bridge=${INT}`);
  assert.strictEqual(nets.net1, `virtio,bridge=${EXT}`);
});

test('an lxc with explicit nics still takes exactly net1', () => {
  const ctx = { subnetScheme: 'v3', bridges: resolveSegmentBridges('v3', EXT, INT) };
  const { nets, segments } = resolveVmNics(
    { name: 'lx', type: 'lxc', nics: [{ segment: 'int' }, { segment: 'ext' }] }, ctx);
  assert.deepStrictEqual(Object.keys(nets), ['net1']);
  assert.deepStrictEqual(segments, ['int']);
  assert.strictEqual(nets.net1, `name=lan0,bridge=${INT}`);
});

test('attaching to a segment the lane does not have is a clear error', () => {
  const ctx = { subnetScheme: 'v2', bridges: resolveSegmentBridges('v2', EXT, EXT) };
  assert.throws(
    () => resolveVmNics({ name: 'srv', nics: [{ segment: 'dmz2' }] }, ctx),
    /attaches to segment 'dmz2', which this lane does not have/
  );
});

test('empty or malformed nics[] falls back to derivation rather than throwing', () => {
  const ctx = { subnetScheme: 'v3', bridges: resolveSegmentBridges('v3', EXT, INT) };
  assert.deepStrictEqual(resolveVmSegments({ name: 'x', nics: [] }, ctx), ['ext']);
  assert.deepStrictEqual(resolveVmSegments({ name: 'x', nics: [{}, null] }, ctx), ['ext']);
});
