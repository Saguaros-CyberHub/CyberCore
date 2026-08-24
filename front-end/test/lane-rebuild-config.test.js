/**
 * Tests for the pure halves of the in-place lane rebuild
 * (src/utils/lane-deployer.js — flatMirrorPatch, laneWorkstationRecords)
 *
 * The rebuild destroys and re-clones SOME machines inside a lane while leaving
 * the others running. Two pure functions decide whether the surviving machines
 * come through it intact, and both fail silently when they are wrong:
 *
 *   flatMirrorPatch — deployLaneWorkstations mirrors `deployed[0]` onto the flat
 *     slot-0 config keys (ip, console_*, guac_connection_id, workstation_user /
 *     _pass). That is correct THERE because it owns every slot. Copied into a
 *     subset rebuild it becomes a live grenade: on `slots: [3]`, `deployed[0]`
 *     is slot 3, and mirroring it overwrites a healthy slot 0's credentials and
 *     console with a different machine's. plugins/cle/routes/{vms,labs}.js and
 *     lane-credentials.resolveLaneWorkstationCredential all read those keys, so
 *     the instructor would be handed slot 3's password for slot 0's machine with
 *     nothing anywhere reporting an error.
 *
 *   laneWorkstationRecords — lanes deployed before config.workstations[] existed
 *     carry only the flat keys. Without the synthesis, every one of them would
 *     report "no machines to rebuild"; with a WRONG synthesis, the rebuild would
 *     destroy a VMID that is not theirs. Slot 0's id is derived (600000 + vxlan)
 *     and the admin group teardown in routes/admin/groups.js derives the same
 *     value with no shared code — so this is also what keeps that path working.
 *
 * No DB and no cluster: site-config is stubbed through require.cache the way
 * provision-slots.test.js does it, because batch-deployer calls
 * getSchedulingConfig() at module level and config/site.json is gitignored.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getDefaultTemplateNode: () => 'pve1',
    getClusterNodes: () => ['pve1'],
  },
};

// lane-deployer destructures the Proxmox client at require time, so reassigning
// the module's export later does nothing — it has to be replaced before the
// require below or the test reaches a real cluster and 401s.
let clusterVms = [];
require.cache[require.resolve(path.join(UTILS, 'proxmox.js'))] = {
  id: 'proxmox', filename: 'proxmox', loaded: true,
  exports: {
    proxmoxAPI: async () => clusterVms,
    waitForTask: async () => ({ status: 'stopped', exitstatus: 'OK' }),
    forceDestroyVM: async () => true,
    findTemplateNode: async (_vmid, fallback) => fallback || 'pve1',
    waitForVmidsGone: async () => ({ surviving: [] }),
    PROXMOX_URL: 'https://stub',
  },
};

const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));
const {
  flatMirrorPatch, laneWorkstationRecords, holdWorkstationVmids,
  reserveWorkstationVmids, WORKSTATION_VMID_OFFSET,
} = laneDeployer;

const src = fs.readFileSync(path.join(UTILS, 'lane-deployer.js'), 'utf8');

/** A deployed slot record, shaped the way deployOneWorkstation returns one. */
function rec(slot, over = {}) {
  return {
    slot, vmid: slot === 0 ? 610003 : 310220 + slot, octet: 50 + slot,
    ip: `10.39.16.${50 + slot}`, mac: `BC:24:11:00:00:${50 + slot}`,
    hostname: slot === 0 ? 'cle-cybv454-10003' : `cle-cybv454-10003-ws${slot}`,
    provider_type: 'qemu', template_id: `t-${slot}`, template_name: `Template ${slot}`,
    console_protocol: 'rdp', console_port: 3389 + slot,
    console_host: '100.100.60.136', console_via: 'gateway',
    guac_connection_id: `g-${slot}`, workspace_resource_id: `r-${slot}`,
    workstation_user: `user-${slot}`, workstation_pass: `PASS-${slot}`,
    credentials_source: 'cloudinit',
    resources: { cores: 4, memory_mb: 8192 },
    ...over,
  };
}

// ── flatMirrorPatch ─────────────────────────────────────────────────────────

test('the flat mirror is EMPTY unless slot 0 is among the rebuilt', () => {
  // THE assertion this whole file exists for. It fails the moment anyone copies
  // `const primary = deployed[0]` out of deployLaneWorkstations, which is the
  // single most likely implementation mistake in the feature.
  assert.deepStrictEqual(flatMirrorPatch([rec(3)]), {});
  assert.deepStrictEqual(flatMirrorPatch([rec(1), rec(2)]), {});
  assert.deepStrictEqual(flatMirrorPatch([]), {});
  assert.deepStrictEqual(flatMirrorPatch(null), {});
});

test('slot 0 anywhere in the set is found, not just first', () => {
  // A subset rebuild of slots [2, 0] hands them in slot order, but nothing
  // guarantees a caller does — and picking by position instead of by slot is
  // exactly the bug.
  const patch = flatMirrorPatch([rec(2), rec(0)]);
  assert.strictEqual(patch.workstation_vmid, 610003);
  assert.strictEqual(patch.workstation_pass, 'PASS-0');
  assert.strictEqual(patch.console_port, 3389);
});

test('the mirror writes exactly the documented key set', () => {
  // Asserted as a sorted list so adding a key to deployLaneWorkstations' mirror
  // without adding it here shows up as a visible diff rather than as a lane that
  // silently loses a field on every rebuild.
  const keys = Object.keys(flatMirrorPatch([rec(0)])).sort();
  assert.deepStrictEqual(keys, [
    'console_error', 'console_host', 'console_port', 'console_via',
    'credentials_source', 'guac_connection_id', 'ip', 'ip_confirmed',
    'resources', 'workspace_resource_id', 'workstation_mac', 'workstation_pass',
    'workstation_user', 'workstation_vmid',
  ]);
});

test('the mirror clears the stale lease confirmation and console error', () => {
  const patch = flatMirrorPatch([rec(0)]);
  // The machine is brand new — claiming its predecessor's confirmed lease would
  // hide a reservation that never applied.
  assert.strictEqual(patch.ip_confirmed, false);
  // confirmWorkstationIp may have downgraded the lane with a "took a pool lease"
  // message describing the machine that was just destroyed.
  assert.strictEqual(patch.console_error, null);
});

test('optional credential keys are omitted rather than written null', () => {
  // `??`-style omission matters: writing workstation_pass: null would blank a
  // usable flat credential for an LXC slot that legitimately has none recorded.
  const patch = flatMirrorPatch([rec(0, { workstation_pass: null, workstation_user: null, resources: null })]);
  assert.ok(!('workstation_pass' in patch));
  assert.ok(!('workstation_user' in patch));
  assert.ok(!('resources' in patch));
});

// ── laneWorkstationRecords ──────────────────────────────────────────────────

test('recorded slots come back in slot order', () => {
  const lane = { vxlan_id: 10003, name: 'cle-x-10003', config: { workstations: [rec(2), rec(0), rec(1)] } };
  assert.deepStrictEqual(laneWorkstationRecords(lane).map(r => r.slot), [0, 1, 2]);
});

test('a malformed entry with no slot is dropped', () => {
  const lane = { vxlan_id: 10003, name: 'l', config: { workstations: [rec(0), { vmid: 999 }] } };
  assert.deepStrictEqual(laneWorkstationRecords(lane).map(r => r.slot), [0]);
});

test('a pre-slots lane synthesizes exactly one slot 0 from the flat keys', () => {
  // These lanes exist: config.workstations[] was added after lane-deployer
  // shipped, and teardownLanes carries the same fallback.
  const lane = {
    vxlan_id: 10007, name: 'cle-old-10007',
    config: {
      workstation_vmid: 610007, workstation_ip: '10.39.20.50',
      template_id: 't-win', template_name: 'Windows 11', provider_type: 'qemu',
      console_protocol: 'rdp', console_port: 3389, console_host: '100.100.60.140',
      guac_connection_id: 'g-legacy', workspace_resource_id: 'r-legacy',
    },
  };
  const got = laneWorkstationRecords(lane);
  assert.strictEqual(got.length, 1);
  assert.strictEqual(got[0].slot, 0);
  assert.strictEqual(got[0].vmid, 610007);
  assert.strictEqual(got[0].octet, 50);
  assert.strictEqual(got[0].hostname, 'cle-old-10007', 'slot 0 clones under the bare lane name');
  assert.strictEqual(got[0].workspace_resource_id, 'r-legacy');
  assert.strictEqual(got[0]._synthesized, true);
});

test('a synthesized slot 0 derives the VMID the way teardown and groups.js do', () => {
  // WORKSTATION_VMID_OFFSET + vxlan_id is derived in three places that share no
  // code: here, teardownLanes, and routes/admin/groups.js. Disagreeing means the
  // group teardown destroys nothing and orphans the real machine.
  const lane = { vxlan_id: 10011, name: 'cle-x-10011', config: {} };
  const got = laneWorkstationRecords(lane);
  assert.strictEqual(got.length, 1);
  assert.strictEqual(got[0].vmid, WORKSTATION_VMID_OFFSET + 10011);
  assert.strictEqual(got[0].vmid, 610011);
  // The MAC is deterministic too, so the existing dnsmasq reservation still
  // describes the rebuilt machine.
  assert.ok(/^[0-9A-F:]{17}$/i.test(got[0].mac));
});

test('a lane with no vxlan yields nothing rather than a guessed VMID', () => {
  assert.deepStrictEqual(laneWorkstationRecords({ vxlan_id: null, config: {} }), []);
});

// ── holdWorkstationVmids ────────────────────────────────────────────────────

test('held VMIDs are withheld from the slot-1+ allocator', async () => {
  // Between the DELETE landing and the clone re-claiming the id, that id is free
  // in the cluster AND absent from the reservation map — so a concurrent
  // deployLanes in this same process would hand it to a different lane and both
  // would clone into it.
  clusterVms = [];   // an empty cluster: every id in the band looks free
  const first = await reserveWorkstationVmids(1);
  holdWorkstationVmids([first[0] + 1]);
  const next = await reserveWorkstationVmids(1);
  assert.notStrictEqual(next[0], first[0] + 1, 'a held id must not be handed out');
});

test('holdWorkstationVmids ignores non-integers instead of poisoning the map', () => {
  assert.doesNotThrow(() => holdWorkstationVmids([null, undefined, 'x', 1.5]));
  assert.doesNotThrow(() => holdWorkstationVmids(null));
});

// ── source-level guards ─────────────────────────────────────────────────────

function rebuildBlock() {
  const at = src.indexOf('async function rebuildLaneWorkstations(');
  assert.notStrictEqual(at, -1, 'rebuildLaneWorkstations not found — renamed?');
  const end = src.indexOf('\nmodule.exports', at);
  return src.slice(at, end === -1 ? src.length : end);
}

test('the rebuild never deletes workspace rows by lane', () => {
  // teardownLanes scopes its cleanup with `metadata->>'lane_id' = ANY(...)`,
  // which on a SUBSET rebuild would strip the workspace rows of every machine on
  // the lane — including the ones still running.
  const block = rebuildBlock();
  assert.ok(!/metadata->>'lane_id'\s*=\s*ANY/.test(block),
    'per-slot cleanup must be scoped by resource_id or provider_vmid, never by lane');
});

test('the rebuild never marks a lane with a live gateway as error', () => {
  // status='error' drops the lane out of ux_cybercore_lane_vxlan_active and
  // allocateVxlanIds while its gateway is still running and answering ARP on its
  // WAN address — so the next deployLanes could clone a gateway on top of it.
  const block = rebuildBlock();
  assert.ok(!/markLaneError\(/.test(block),
    'a partial rebuild must return the lane to active, not mark it error');
  assert.ok(/status = 'active'/.test(block),
    'the write-back must restore active');
});

test('the workspace cleanup compares lane_id as text, never cast to uuid', () => {
  // Postgres does not guarantee AND-evaluation order, so `(metadata->>'lane_id')::uuid`
  // blows up if ANY resource row anywhere holds a non-uuid there — the reason
  // teardownLanes avoids the cast and routes/admin/groups.js still has it.
  const at = src.indexOf('async function retireWorkspaceRowForSlot(');
  assert.notStrictEqual(at, -1);
  const fn = src.slice(at, src.indexOf('\n}', at));
  assert.ok(!/lane_id'\)::uuid/.test(fn), 'lane_id must be compared as text');
  assert.ok(/lane_id'\s*=\s*\$1::text/.test(fn));
});

test('the destroy path always waits for the VMID to actually be gone', () => {
  // Proxmox DELETE is asynchronous. Cloning into an id still being purged either
  // fails with "VM already exists" or lets the destroy task land after the clone
  // and eat the new disk.
  const at = src.indexOf('async function destroyWorkstationSlots(');
  assert.notStrictEqual(at, -1);
  const fn = src.slice(at, src.indexOf('\n}', at));
  assert.ok(/waitForVmidsGone\(/.test(fn), 'the wait-for-gone gate is mandatory');
  assert.ok(/sweepVmDisks\(/.test(fn),
    'a surviving disk volume makes the re-clone fail with "volume already exists"');
});
