/**
 * Tests for lane machine enumeration (src/utils/lane-machines.js)
 *
 * THE GATEWAY EXCLUSION IS THE WHOLE POINT OF THIS FILE. Everything that calls
 * laneMachines() is about to do something to every machine it returns, and the
 * first caller is "restart all of these". Including the gateway would:
 *
 *   - drop every student's console, because the DNAT rules that publish RDP/SSH
 *     live on it;
 *   - take DHCP away from the machines rebooting alongside it, so they come
 *     back with no lease;
 *   - leave the whole lane unreachable until it boots.
 *
 * And it fails silently in the only way that matters: laneMachines returning
 * one extra row looks like nothing at all until a class is already down.
 *
 * The gateway is identified three ways because three deploy paths record it
 * differently, and a lane whose gateway is not RECOGNISED as the gateway is
 * exactly a lane whose gateway gets restarted.
 *
 * Pure module, no stubs needed — which is why it is a separate module from
 * lane-deployer rather than a function inside it.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const {
  laneMachines, laneGatewayVmid, GATEWAY_VMID_OFFSET,
} = require(path.join(__dirname, '..', 'src', 'utils', 'lane-machines.js'));

const lane = (config, over = {}) => ({
  lane_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  name: 'cle-cybv454-10003',
  vxlan_id: 10003,
  config,
  ...over,
});

const vmids = (l) => laneMachines(l).map(m => m.vmid);

// ── identifying the gateway ─────────────────────────────────────────────────

test('the gateway is derived from the VXLAN id when the config does not name it', () => {
  assert.strictEqual(laneGatewayVmid(lane({})), GATEWAY_VMID_OFFSET + 10003);
});

test('an explicitly recorded gateway wins over the derived one', () => {
  // A lane whose gateway was placed by hand, or migrated, is not 100000+vxlan.
  assert.strictEqual(laneGatewayVmid(lane({ gateway_vmid: 999 })), 999);
});

test('BOTH spellings of the key are honoured', () => {
  // Two deploy paths, two names. Missing one means the gateway is not
  // recognised, and the next "restart everything" takes the lane down.
  assert.strictEqual(laneGatewayVmid(lane({ gateway_vmid: 111 })), 111);
  assert.strictEqual(laneGatewayVmid(lane({ gateway_vm_id: 222 })), 222);
});

test('a lane with no vxlan and no recorded gateway yields null, not 100000', () => {
  // NaN arithmetic here would produce a garbage id that excludes nothing, or
  // worse, excludes a real machine.
  assert.strictEqual(laneGatewayVmid({ config: {} }), null);
  assert.strictEqual(laneGatewayVmid({ config: {}, vxlan_id: null }), null);
});

// ── the exclusion ───────────────────────────────────────────────────────────

test('the derived gateway is excluded from the machine list', () => {
  const l = lane({
    workstations: [
      { slot: 0, vmid: GATEWAY_VMID_OFFSET + 10003 },   // the gateway, mis-recorded
      { slot: 1, vmid: 610003 },
    ],
  });
  assert.deepStrictEqual(vmids(l), [610003]);
});

test('an explicitly recorded gateway is excluded wherever it appears', () => {
  const l = lane({
    gateway_vmid: 777,
    workstations: [{ slot: 0, vmid: 610003 }],
    attached_modules: [{ vms: [{ vm_id: 777 }, { vm_id: 800123 }] }],
  });
  assert.deepStrictEqual(vmids(l), [610003, 800123]);
});

test('the gateway is excluded even when it is the only thing on the lane', () => {
  assert.deepStrictEqual(vmids(lane({ vms: [{ vm_id: GATEWAY_VMID_OFFSET + 10003 }] })), []);
});

// ── all three config shapes ─────────────────────────────────────────────────

test('workstations, environment VMs and attached modules are all enumerated', () => {
  // A lane's machines are not in one list, and a caller that knew only one
  // shape would silently restart a third of them.
  const l = lane({
    workstations: [{ slot: 0, vmid: 610003, hostname: 'ws0', provider_type: 'qemu' }],
    vms: [{ vm_id: 310221, name: 'DC01' }],
    attached_modules: [{ material_id: 'lab-1', vms: [{ vm_id: 800123, name: 'dvwa' }] }],
  });
  assert.deepStrictEqual(vmids(l), [610003, 310221, 800123]);
  assert.deepStrictEqual(
    laneMachines(l).map(m => m.kind), ['workstation', 'environment', 'environment']);
});

test('a legacy lane with only the flat slot-0 keys still reports its machine', () => {
  // Without this branch every lane deployed before config.workstations[] existed
  // reports nothing, and a restart silently does nothing to it.
  const l = lane({ workstation_vmid: 610003, provider_type: 'qemu' });
  assert.deepStrictEqual(vmids(l), [610003]);
  assert.strictEqual(laneMachines(l)[0].slot, 0);
});

test('the flat fallback is ignored once workstations[] exists', () => {
  const l = lane({ workstation_vmid: 999999, workstations: [{ slot: 0, vmid: 610003 }] });
  assert.deepStrictEqual(vmids(l), [610003]);
});

test('LXC machines are INCLUDED — power control is not guest-agent exec', () => {
  // src/incident/target.js drops non-qemu because it dispatches over the guest
  // agent. Excluding containers here would silently skip machines that can be
  // powered perfectly well.
  const l = lane({ workstations: [{ slot: 0, vmid: 610003, provider_type: 'lxc' }] });
  assert.deepStrictEqual(vmids(l), [610003]);
  assert.strictEqual(laneMachines(l)[0].provider_type, 'lxc');
});

test('a VM listed twice is returned once', () => {
  // A duplicate means powering the same guest off twice: the second shutdown
  // lands on a machine already down and races the first one's start.
  const l = lane({
    workstations: [{ slot: 0, vmid: 610003 }],
    attached_modules: [{ vms: [{ vm_id: 610003 }] }],
  });
  assert.deepStrictEqual(vmids(l), [610003]);
});

test('malformed entries are dropped rather than producing NaN targets', () => {
  const l = lane({
    workstations: [{ slot: 0, vmid: null }, { slot: 1 }, null, { slot: 2, vmid: 'nope' }],
    vms: [{}, { vm_id: 0 }, { vm_id: -5 }],
    attached_modules: [null, { vms: null }, { vms: [{ vm_id: 610004 }] }],
  });
  assert.deepStrictEqual(vmids(l), [610004]);
});

test('an empty or missing config yields no machines and never throws', () => {
  assert.deepStrictEqual(laneMachines({}), []);
  assert.deepStrictEqual(laneMachines({ config: null }), []);
  assert.deepStrictEqual(laneMachines(null), []);
});

// ── material scoping ────────────────────────────────────────────────────────

test('attached machines carry the INSTANCE\'s material_id, not the VM\'s', () => {
  // attachLabToLane stamps material_id on the instance it appends to
  // attached_modules[], never on the individual VMs.
  const l = lane({
    attached_modules: [
      { material_id: 'lab-a', vms: [{ vm_id: 800001 }, { vm_id: 800002 }] },
      { material_id: 'lab-b', vms: [{ vm_id: 800003 }] },
    ],
  });
  const byId = Object.fromEntries(laneMachines(l).map(m => [m.vmid, m.material_id]));
  assert.deepStrictEqual(byId, { 800001: 'lab-a', 800002: 'lab-a', 800003: 'lab-b' });
});

test('a dedicated lab lane\'s own machines inherit the lane\'s material', () => {
  const l = lane({ material_id: 'lab-a', vms: [{ vm_id: 310221 }] });
  assert.strictEqual(laneMachines(l)[0].material_id, 'lab-a');
});

test('a student workstation carries NO material, so an environment restart skips it', () => {
  // This is what stops "restart this environment" power-cycling the student's
  // own Windows box, which shares the lane in attach mode.
  const l = lane({
    workstations: [{ slot: 0, vmid: 610003 }],
    attached_modules: [{ material_id: 'lab-a', vms: [{ vm_id: 800001 }] }],
  });
  const forLabA = laneMachines(l).filter(m => m.material_id === 'lab-a').map(m => m.vmid);
  assert.deepStrictEqual(forLabA, [800001]);
});
