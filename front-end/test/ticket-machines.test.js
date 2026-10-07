/**
 * ticket-machines.test.js — the "which machine is this about?" picker.
 *
 * The load-bearing test here is the material_id one. findCourseWorkstationLanes()
 * in cle/utils/lane-provision.js filters `config->>'material_id' IS NULL`, and
 * that predicate is a TEARDOWN SAFETY property — it keeps vulnerable-lab lane
 * ids away from teardownLanes(). Copying it into a read-only picker (which is
 * the obvious thing to do when cribbing that query) hides every assignment lab
 * machine, and assignment labs are exactly what students file tickets about.
 * The test exists to fail loudly if someone adds it.
 *
 * Run: node front-end/test/ticket-machines.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const M = require(path.join(__dirname, '..', 'src', 'utils', 'ticket-machines.js'));

/** A lane paired with the laneWorkstationRecords() output the route supplies. */
function lane(overrides = {}, slots = []) {
  return {
    lane: {
      lane_id: 'lane-1',
      name: 'cybr400-pat',
      status: 'active',
      vxlan_id: 501,
      config: { course_id: 'c-1' },
      ...overrides,
    },
    slots,
  };
}

const SLOT = (slot, extra = {}) => ({
  slot, vmid: 601000 + slot, hostname: `cybr400-pat-ws${slot}`, ip: `10.0.0.${50 + slot}`, ...extra,
});

// ── lane machines ───────────────────────────────────────────────────────────

test('a lane with three workstations yields three options', () => {
  const out = M.projectMachines([lane({}, [SLOT(0), SLOT(1), SLOT(2)])], []);
  assert.strictEqual(out.length, 3);
  assert.deepStrictEqual(out.map(o => o.key), ['lane:lane-1:0', 'lane:lane-1:1', 'lane:lane-1:2']);
  assert.deepStrictEqual(out.map(o => o.label),
    ['cybr400-pat-ws0', 'cybr400-pat-ws1', 'cybr400-pat-ws2']);
  assert.deepStrictEqual(out.map(o => o.vmid), [601000, 601001, 601002]);
});

test('config.course_id tags every slot of the lane', () => {
  const out = M.projectMachines([lane({}, [SLOT(0), SLOT(1)])], []);
  assert.ok(out.every(o => o.courseId === 'c-1'));
});

test('a lane carrying material_id is INCLUDED', () => {
  // The whole point of this file. A vulnerable-lab lane is a machine the
  // student uses and files tickets about; the material_id predicate belongs to
  // teardown, not to a read-only picker.
  const out = M.projectMachines(
    [lane({ config: { course_id: 'c-1', material_id: 'm-9' } }, [SLOT(0)])], []);
  assert.strictEqual(out.length, 1, 'a lab lane machine was hidden from the picker');
  assert.strictEqual(out[0].courseId, 'c-1');
});

test('a lane with no workstation records yields nothing and does not throw', () => {
  // laneWorkstationRecords() returns [] for a lane with no vxlan_id.
  assert.deepStrictEqual(M.projectMachines([lane({}, [])], []), []);
  assert.deepStrictEqual(M.projectMachines([lane({}, null)], []), []);
  assert.deepStrictEqual(M.projectMachines([{ lane: null, slots: [SLOT(0)] }], []), []);
});

test('a lane with no course_id still lists its machines', () => {
  // POST /api/admin/deploy-group writes group_id and no course reference. Those
  // machines are real and must be reportable.
  const out = M.projectMachines([lane({ config: { group_id: 'g-1' } }, [SLOT(0)])], []);
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].courseId, null);
});

// ── labels, which get snapshot onto the ticket ──────────────────────────────

test('a slot with no hostname falls back to the lane name, then to the VMID', () => {
  const out = M.projectMachines([lane({}, [
    SLOT(0, { hostname: null }),
    SLOT(1, { hostname: null }),
    { slot: 2, vmid: null, hostname: null },
  ])], []);
  assert.strictEqual(out[0].label, 'cybr400-pat');            // slot 0 clones under the lane name
  assert.strictEqual(out[1].label, 'cybr400-pat slot 1');
  // Still the lane-name fallback, not the VMID one: a name a student recognises
  // beats a number even when the slot has no VMID recorded yet.
  assert.strictEqual(out[2].label, 'cybr400-pat slot 2');
});

test('a slot with neither hostname, lane name nor VMID is still labelled', () => {
  const out = M.projectMachines(
    [lane({ name: null }, [{ slot: 3, vmid: null, hostname: null }])], []);
  assert.strictEqual(out[0].label, 'unnamed machine');
});

test('a nameless lane still produces a usable label', () => {
  const out = M.projectMachines(
    [lane({ name: null }, [SLOT(0, { hostname: null })])], []);
  assert.strictEqual(out[0].label, 'VM 601000');
});

// ── self-service workstations ───────────────────────────────────────────────

const WS = (over = {}) => ({
  vm_instance_id: 'vmi-1', vm_name: 'pat-kali', provider_vmid: 900001,
  ip_address: '10.9.0.5', ...over,
});

test('self-service workstations are listed after lane machines, with no course', () => {
  const out = M.projectMachines([lane({}, [SLOT(0)])], [WS()]);
  assert.deepStrictEqual(out.map(o => o.key), ['lane:lane-1:0', 'vm:vmi-1']);
  assert.strictEqual(out[1].kind, M.KIND_SELF);
  assert.strictEqual(out[1].courseId, null);
  assert.strictEqual(out[1].laneId, null);
});

test('a machine reachable down both paths appears once, as the lane entry', () => {
  // Lane workstations are ALSO registered as a cybercore_resource with an
  // allocation to the same student, so this is a real collision, not a
  // hypothetical. The lane entry wins because it is the one carrying courseId.
  const out = M.projectMachines(
    [lane({}, [SLOT(0)])],
    [WS({ vm_instance_id: 'vmi-dup', provider_vmid: 601000, vm_name: 'cybr400-pat-ws0' })]
  );
  assert.strictEqual(out.length, 1, 'the same machine was offered twice');
  assert.strictEqual(out[0].kind, M.KIND_LANE);
  assert.strictEqual(out[0].courseId, 'c-1');
});

test('two lanes sharing a slot number do not collide', () => {
  const out = M.projectMachines([
    lane({ lane_id: 'lane-1' }, [SLOT(0)]),
    lane({ lane_id: 'lane-2', name: 'ciab-pat', config: { course_id: 'c-2' } },
         [{ slot: 0, vmid: 602000, hostname: 'ciab-pat' }]),
  ], []);
  assert.deepStrictEqual(out.map(o => o.key), ['lane:lane-1:0', 'lane:lane-2:0']);
});

test('malformed input degrades to an empty list', () => {
  assert.deepStrictEqual(M.projectMachines(null, null), []);
  assert.deepStrictEqual(M.projectMachines(undefined, undefined), []);
  assert.deepStrictEqual(M.projectMachines([], [null, {}]), []);
});

// ── key resolution, the authorization-relevant half ────────────────────────

test('findMachine resolves only keys present in the list', () => {
  const out = M.projectMachines([lane({}, [SLOT(0), SLOT(1)])], [WS()]);
  assert.strictEqual(M.findMachine(out, 'lane:lane-1:1').vmid, 601001);
  assert.strictEqual(M.findMachine(out, 'vm:vmi-1').label, 'pat-kali');
  // Someone else's machine, guessed. The list is built per-user, so a key that
  // is not in it can never resolve.
  assert.strictEqual(M.findMachine(out, 'lane:someone-elses-lane:0'), null);
  assert.strictEqual(M.findMachine(out, 'lane:lane-1:9'), null);
  assert.strictEqual(M.findMachine(out, ''), null);
  assert.strictEqual(M.findMachine(out, null), null);
  assert.strictEqual(M.findMachine(null, 'lane:lane-1:0'), null);
});

test('findMachine does not coerce a partial or prefix match', () => {
  const out = M.projectMachines([lane({}, [SLOT(0)])], []);
  assert.strictEqual(M.findMachine(out, 'lane:lane-1'), null);
  assert.strictEqual(M.findMachine(out, 'lane:lane-1:0 '), null);
});

// ── snapshot ────────────────────────────────────────────────────────────────

test('machineSnapshot carries a label that survives the lane being torn down', () => {
  const out = M.projectMachines([lane({}, [SLOT(0)])], []);
  assert.deepStrictEqual(M.machineSnapshot(out[0]), {
    lane_id: 'lane-1',
    machine_key: 'lane:lane-1:0',
    machine_label: 'cybr400-pat-ws0',
    machine_vmid: 601000,
  });
});

test('machineSnapshot of nothing is all nulls, not a throw', () => {
  assert.deepStrictEqual(M.machineSnapshot(null), {
    lane_id: null, machine_key: null, machine_label: null, machine_vmid: null,
  });
});

test('a self-service snapshot carries no lane id', () => {
  const out = M.projectMachines([], [WS()]);
  assert.strictEqual(M.machineSnapshot(out[0]).lane_id, null);
  assert.strictEqual(M.machineSnapshot(out[0]).machine_vmid, 900001);
});

// ── course filtering (client convenience only) ─────────────────────────────

test('filtering by course keeps that course AND every course-less machine', () => {
  const out = M.projectMachines([
    lane({ lane_id: 'l1' }, [SLOT(0)]),
    lane({ lane_id: 'l2', config: { course_id: 'c-2' } }, [SLOT(0)]),
    lane({ lane_id: 'l3', config: {} }, [SLOT(0)]),
  ], [WS()]);

  const c1 = M.filterByCourse(out, 'c-1');
  assert.deepStrictEqual(c1.map(o => o.key), ['lane:l1:0', 'lane:l3:0', 'vm:vmi-1']);

  // No course selected: everything.
  assert.strictEqual(M.filterByCourse(out, null).length, 4);
  assert.strictEqual(M.filterByCourse(out, '').length, 4);
});

test('filterByCourse never mutates its input', () => {
  const out = M.projectMachines([lane({}, [SLOT(0)])], []);
  M.filterByCourse(out, 'c-2');
  assert.strictEqual(out.length, 1);
});
