/**
 * reconcile-audit.test.js — the rules the Proxmox audit decides by.
 *
 * WHY THIS FILE EXISTS
 * The audit grew inline inside routes/admin/cluster.js, where the only way to
 * exercise it was to point it at a live cluster. Two of the bugs pinned below
 * survived in that state for months precisely because nothing could reach them:
 *
 *   1. `stale_in_db` is NOT "every VM of the lane is gone" — it is "every
 *      WORKLOAD VM is gone", deliberately ignoring the gateway and attack box.
 *      A lane whose gateway LXC outlives its challenge VMs is still stale and
 *      must still offer Mark Deleted, because that is what frees the VXLAN.
 *      Collapsing the two VMID lists (they look interchangeable) would silently
 *      stop flagging exactly that lane. Case 26 is a byte-for-byte replay of
 *      the original inline logic to make that impossible to do by accident.
 *
 *   2. Every VNet in a non-vxlan zone was reported orphaned, with a Delete
 *      button, because activeZoneNames was built from the vxlan-FILTERED zone
 *      list.
 *
 * The module under test has zero require() statements, so this file needs no
 * stubs at all — that is the whole reason it is a separate module rather than
 * inline route code.
 *
 * Run: node front-end/test/reconcile-audit.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const A = require(path.join(__dirname, '..', 'src', 'utils', 'reconcile-audit.js'));

// Mirrors utils/attached-modules.js (base 800000, 10 slots, step 10000).
const RANGES = A.buildCyberhubRanges({ attachedBase: 800000, attachedSlots: 10, attachedStep: 10000 });

const ceph = (storage = 'ceph-vm') => ({ storage, type: 'rbd', shared: 1, content: 'images,rootdir', active: 1, enabled: 1 });
const local = (storage = 'local-lvm') => ({ storage, type: 'lvmthin', shared: 0, content: 'images,rootdir', active: 1, enabled: 1 });
const nodeEntry = (node, storages) => ({ node, online: true, storages, error: null });

// ============================================================================
// SCAN PLANNING — the shared-storage dedup that is the point of the rewrite
// ============================================================================

test('shared storage collapses to one job; locals stay per node', () => {
  const plan = A.planStorageScan([
    nodeEntry('n1', [ceph(), local()]),
    nodeEntry('n2', [ceph(), local()]),
    nodeEntry('n3', [ceph(), local()]),
  ]);
  assert.strictEqual(plan.jobs.length, 4, 'one shared + three local');
  const sharedJob = plan.jobs.find(j => j.shared);
  assert.deepStrictEqual(sharedJob.readers, ['n1', 'n2', 'n3'], 'every node is a candidate reader');
  assert.strictEqual(plan.jobs.filter(j => !j.shared).length, 3);
});

test('call math is reported and internally consistent', () => {
  const nodes = Array.from({ length: 6 }, (_, i) =>
    nodeEntry(`n${i}`, [ceph('ceph-a'), ceph('ceph-b'), local()]));
  const plan = A.planStorageScan(nodes);
  assert.strictEqual(plan.stats.calls_naive, 18, '6 nodes x 3 storages the old way');
  assert.strictEqual(plan.stats.calls_planned, 8, '2 shared + 6 local');
  assert.strictEqual(
    plan.stats.calls_naive - plan.stats.calls_planned, plan.stats.calls_saved);
});

test('offline node is skipped with a reason and never becomes a reader', () => {
  const plan = A.planStorageScan([
    nodeEntry('n1', [ceph()]),
    { node: 'n2', online: false, storages: null, error: null },
  ]);
  assert.deepStrictEqual(plan.skipped.nodes, [{ node: 'n2', reason: 'offline' }]);
  assert.deepStrictEqual(plan.jobs.find(j => j.shared).readers, ['n1']);
  assert.strictEqual(plan.stats.nodes_online, 1);
});

test('a node whose storage listing failed is a coverage hole, not silence', () => {
  const plan = A.planStorageScan([
    nodeEntry('n1', [ceph()]),
    { node: 'n2', online: true, storages: null, error: 'connect ETIMEDOUT' },
  ]);
  assert.match(plan.skipped.nodes[0].reason, /storage list failed: connect ETIMEDOUT/);
});

test('inactive and disabled storages are recorded; non-image storages are not', () => {
  const plan = A.planStorageScan([nodeEntry('n1', [
    { storage: 'dead', type: 'nfs', shared: 1, content: 'images', active: 0, enabled: 1 },
    { storage: 'off', type: 'nfs', shared: 1, content: 'images', active: 1, enabled: 0 },
    { storage: 'isos', type: 'dir', shared: 0, content: 'iso,vztmpl', active: 1, enabled: 1 },
  ])]);
  assert.strictEqual(plan.jobs.length, 0);
  const reasons = plan.skipped.storages.map(s => `${s.storage}:${s.reason}`).sort();
  assert.deepStrictEqual(reasons, ['dead:inactive', 'off:disabled'],
    'an ISO store holds no VM disks — a normal exclusion, not a failure to report');
});

test('shared flag beats the type table in both directions', () => {
  assert.strictEqual(A.isSharedStorage({ type: 'rbd' }), true, 'rbd defaults shared');
  assert.strictEqual(A.isSharedStorage({ type: 'lvmthin' }), false, 'lvmthin defaults local');
  assert.strictEqual(A.isSharedStorage({ type: 'rbd', shared: 0 }), false, 'explicit flag wins');
  assert.strictEqual(A.isSharedStorage({ type: 'dir', shared: 1 }), true, 'explicit flag wins');
});

test('preferred reader sorts to the head, and an offline one never appears', () => {
  const plan = A.planStorageScan([
    nodeEntry('n1', [ceph()]), nodeEntry('n2', [ceph()]), nodeEntry('n3', [ceph()]),
  ], { preferredNode: 'n3' });
  assert.strictEqual(plan.jobs[0].readers[0], 'n3');

  const plan2 = A.planStorageScan([
    nodeEntry('n1', [ceph()]),
    { node: 'n3', online: false, storages: null, error: null },
  ], { preferredNode: 'n3' });
  assert.ok(!plan2.jobs[0].readers.includes('n3'));
});

test('assumeShared:false restores per-node scanning (the escape hatch)', () => {
  const plan = A.planStorageScan(
    [nodeEntry('n1', [ceph()]), nodeEntry('n2', [ceph()])],
    { assumeShared: false });
  assert.strictEqual(plan.jobs.length, 2, 'same storage listed once per node');
});

test('two distinct shared storages stay two jobs', () => {
  const plan = A.planStorageScan([nodeEntry('n1', [ceph('ceph-a'), ceph('ceph-b')])]);
  assert.strictEqual(plan.jobs.length, 2);
});

// ============================================================================
// VOLID PARSING
// ============================================================================

test('parseVolid handles vm-, subvol- and cloudinit', () => {
  assert.deepStrictEqual(A.parseVolid('ceph-vm:vm-600123-disk-0'), { vmid: 600123, kind: 'disk' });
  assert.deepStrictEqual(A.parseVolid('local-lvm:vm-100123-cloudinit'), { vmid: 100123, kind: 'cloudinit' });
  assert.deepStrictEqual(A.parseVolid('local:subvol-100123-disk-0'), { vmid: 100123, kind: 'disk' },
    'LXC rootfs on ZFS/dir — lane gateways are LXCs and were invisible before');
});

test('parseVolid ignores backups, ISOs and template base disks', () => {
  assert.strictEqual(A.parseVolid('local:backup/vzdump-qemu-600123-2026_01_01.vma.zst'), null);
  assert.strictEqual(A.parseVolid('local:iso/ubuntu.iso'), null);
  assert.strictEqual(A.parseVolid('ceph-vm:base-9001-disk-0'), null,
    'deliberately unmatched: the cost of a wrong match is offering to delete a template');
  assert.strictEqual(A.parseVolid(undefined), null);
});

test('a storage id containing digits or "vm" does not confuse the parse', () => {
  assert.deepStrictEqual(A.parseVolid('ceph2:vm-600123-disk-0'), { vmid: 600123, kind: 'disk' });
  assert.deepStrictEqual(A.parseVolid('vm-1:vm-600123-disk-0'), { vmid: 600123, kind: 'disk' });
});

// ============================================================================
// ORPHAN DISK CLASSIFICATION
// ============================================================================

const vol = (node, storage, volid, size = 0, shared = true) => ({ node, storage, volid, size, shared });

test('a live VM protects its disk; out-of-range VMIDs are ignored', () => {
  const r = A.classifyOrphanDisks([
    vol('n1', 'ceph-vm', 'ceph-vm:vm-600123-disk-0'),
    vol('n1', 'ceph-vm', 'ceph-vm:vm-600999-disk-0'),
    vol('n1', 'ceph-vm', 'ceph-vm:vm-501-disk-0'),
  ], { liveVmIds: new Set([600123]), ranges: RANGES });
  assert.deepStrictEqual(r.disks.map(d => d.vmid), [600999]);
});

test('duplicate volid across nodes dedupes deterministically', () => {
  const pick = (order) => A.classifyOrphanDisks(
    order.map(n => vol(n, 'ceph-vm', 'ceph-vm:vm-600999-disk-0')),
    { liveVmIds: new Set(), ranges: RANGES }).disks[0].node;
  assert.strictEqual(pick(['n3', 'n1', 'n2']), 'n1');
  assert.strictEqual(pick(['n1', 'n2', 'n3']), 'n1',
    'parallel workers land in arbitrary order; the Destroy button must not follow suit');
});

test('roles and sizes', () => {
  const ids = [100123, 200123, 600123, 700123, 810123];
  const r = A.classifyOrphanDisks(
    ids.map(id => vol('n1', 's', `s:vm-${id}-disk-0`, 1073741824)),
    { liveVmIds: new Set(), ranges: RANGES });
  assert.deepStrictEqual(r.disks.map(d => d.role),
    ['gateway', 'goad_controller', 'challenge', 'attack_box', 'attached_module']);
  assert.strictEqual(r.disks[0].size_gb, '1.00');
  assert.strictEqual(r.total_bytes, 5 * 1073741824);
});

test('attached-module range boundary', () => {
  const inRange = A.classifyOrphanDisks([vol('n1', 's', 's:vm-899999-disk-0')],
    { liveVmIds: new Set(), ranges: RANGES });
  const outOfRange = A.classifyOrphanDisks([vol('n1', 's', 's:vm-900000-disk-0')],
    { liveVmIds: new Set(), ranges: RANGES });
  assert.strictEqual(inRange.disks.length, 1);
  assert.strictEqual(outOfRange.disks.length, 0);
});

test('zero-size volume reports 0.00, not NaN', () => {
  const r = A.classifyOrphanDisks([vol('n1', 's', 's:vm-600999-disk-0', 0)],
    { liveVmIds: new Set(), ranges: RANGES });
  assert.strictEqual(r.disks[0].size_gb, '0.00');
});

// ============================================================================
// LANE INDEX AND STALENESS — behavior preservation
// ============================================================================

const LANES = [
  { lane_id: 'L1', name: 'legacy', vxlan_id: 11, status: 'active', config: {} },
  { lane_id: 'L2', name: 'multi', vxlan_id: 12, status: 'active',
    config: { vms: [{ vm_id: 600012 }, { vm_id: 600112 }], gateway_vm_id: 100012 } },
  { lane_id: 'L3', name: 'attackbox', vxlan_id: 13, status: 'active', config: { attack_box: true } },
  { lane_id: 'L4', name: 'attached', vxlan_id: 14, status: 'active',
    config: { vms: [{ vm_id: 600014 }], attached_modules: [{ vms: [{ vm_id: 810014 }] }] } },
  { lane_id: 'L5', name: 'no-vxlan', vxlan_id: null, status: 'active', config: {} },
  { lane_id: 'L6', name: 'gateway-survivor', vxlan_id: 16, status: 'active',
    config: { vms: [{ vm_id: 600016 }], gateway_vm_id: 100016 } },
];

test('expected includes gateway and attack box; workload deliberately does not', () => {
  const idx = A.buildLaneVmIndex(LANES);
  assert.ok(idx.expectedVmIds.has(100011), 'derived gateway is expected');
  assert.deepStrictEqual(idx.workloadVmIdsByLane.get('L1'), [600011],
    'gateway is NOT a workload VM');
  assert.ok(idx.expectedVmIds.has(700013), 'attack_box:true derives 700000+vxlan');
  assert.ok(!idx.workloadVmIdsByLane.get('L3').includes(700013));
  assert.ok(idx.expectedVmIds.has(810014), 'attached-module VMs are expected');
  assert.ok(!idx.workloadVmIdsByLane.get('L4').includes(810014));
  assert.ok(!idx.workloadVmIdsByLane.has('L5'), 'a lane with no vxlan is skipped entirely');
});

test('a lane whose gateway survives but whose workload is gone is STILL stale', () => {
  const idx = A.buildLaneVmIndex(LANES);
  // gateway 100016 alive on Proxmox, challenge VM 600016 gone
  const stale = A.computeStaleLanes(LANES, idx, new Set([100016]));
  assert.ok(stale.some(l => l.lane_id === 'L6'),
    'this is the case a naive merge of the two VMID lists would silently drop, ' +
    'leaving the lane with no way to free its VXLAN');
});

test('GOLDEN: index and staleness match the original inline implementation', () => {
  // Verbatim replay of routes/admin/cluster.js L109-139 and L194-206 as they
  // stood before extraction. If a refactor changes what the audit reports, this
  // is what fails.
  const legacyExpected = new Set();
  for (const lane of LANES) {
    const vxlan = lane.vxlan_id;
    if (!vxlan) continue;
    const cfg = lane.config || {};
    const vmIds = [];
    if (Array.isArray(cfg.vms)) {
      cfg.vms.forEach(vm => { if (vm.vm_id) vmIds.push(vm.vm_id); });
    } else {
      vmIds.push(cfg.challenge_vm_id || (600000 + vxlan));
    }
    vmIds.push(cfg.gateway_vm_id || (100000 + vxlan));
    if (cfg.attack_box_vm_id) vmIds.push(cfg.attack_box_vm_id);
    else if (cfg.attack_box) vmIds.push(700000 + vxlan);
    if (Array.isArray(cfg.attached_modules)) {
      for (const mod of cfg.attached_modules) {
        for (const vm of (mod.vms || [])) { if (vm.vm_id) vmIds.push(vm.vm_id); }
      }
    }
    vmIds.forEach(id => legacyExpected.add(id));
  }

  const legacyStale = (pxVmIdSet) => LANES.filter(lane => {
    const vxlan = lane.vxlan_id;
    if (!vxlan) return false;
    const cfg = lane.config || {};
    const vmIds = [];
    if (Array.isArray(cfg.vms)) {
      cfg.vms.forEach(vm => { if (vm.vm_id) vmIds.push(vm.vm_id); });
    } else {
      vmIds.push(cfg.challenge_vm_id || (600000 + vxlan));
    }
    return vmIds.length > 0 && vmIds.every(id => !pxVmIdSet.has(id));
  }).map(l => l.lane_id);

  const idx = A.buildLaneVmIndex(LANES);
  assert.deepStrictEqual(
    [...idx.expectedVmIds].sort((a, b) => a - b),
    [...legacyExpected].sort((a, b) => a - b));

  for (const live of [[], [100016], [600012], [600011, 600012, 600014, 600016], [810014]]) {
    const set = new Set(live);
    assert.deepStrictEqual(
      A.computeStaleLanes(LANES, idx, set).map(l => l.lane_id),
      legacyStale(set),
      `staleness diverged for live set [${live}]`);
  }
});

test('a lane with an empty vms array is never stale', () => {
  const lanes = [{ lane_id: 'E', vxlan_id: 20, status: 'active', config: { vms: [] } }];
  const idx = A.buildLaneVmIndex(lanes);
  assert.deepStrictEqual(A.computeStaleLanes(lanes, idx, new Set()), [],
    'no workload VMs means nothing to conclude, not "all gone"');
});

// ============================================================================
// SDN
// ============================================================================

test('a VNet in a healthy non-vxlan zone is NOT orphaned', () => {
  const r = A.computeSdnOrphans({
    pxZonesAll: [{ zone: 'simplez', type: 'simple' }, { zone: 'vx1', type: 'vxlan' }],
    pxVNets: [{ vnet: 'v1', zone: 'simplez' }, { vnet: 'v2', zone: 'vx1' }],
    dbZoneNames: new Set(['vx1']),
  });
  assert.deepStrictEqual(r.orphanedVNets, [],
    'building activeZoneNames from the vxlan-filtered list offered to delete ' +
    'every VNet in a simple/evpn/qinq zone');
});

test('a VNet whose zone is genuinely gone is orphaned', () => {
  const r = A.computeSdnOrphans({
    pxZonesAll: [{ zone: 'vx1', type: 'vxlan' }],
    pxVNets: [{ vnet: 'ghost', zone: 'deleted-zone' }],
    dbZoneNames: new Set(['vx1']),
  });
  assert.deepStrictEqual(r.orphanedVNets.map(v => v.vnet), ['ghost']);
});

test('orphaned zones are vxlan-only and exclude localnetwork', () => {
  const r = A.computeSdnOrphans({
    pxZonesAll: [
      { zone: 'orphan', type: 'vxlan' },
      { zone: 'known', type: 'vxlan' },
      { zone: 'localnetwork', type: 'vxlan' },
      { zone: 'simplez', type: 'simple' },
    ],
    pxVNets: [],
    dbZoneNames: new Set(['known']),
  });
  assert.deepStrictEqual(r.orphanedZones.map(z => z.zone), ['orphan']);
});

// ============================================================================
// NODE DRIFT
// ============================================================================

const STATUS = [
  { type: 'cluster', name: 'cyberhub' },
  { type: 'node', name: 'n1', ip: '100.100.10.10', online: 1 },
  { type: 'node', name: 'n2', ip: '100.100.10.11', online: 1 },
  { type: 'node', name: 'n6', ip: '100.100.10.16', online: 1 },
];

test('undeclared, stale, mismatched and offline nodes are each reported once', () => {
  const d = A.diffClusterNodes({
    clusterStatus: [...STATUS, { type: 'node', name: 'n7', ip: '100.100.10.17', online: 0 }],
    declaredMap: { n1: '100.100.10.10', n2: '100.100.10.99', n7: '100.100.10.17', n9: '100.100.10.19' },
  });
  assert.deepStrictEqual(d.undeclared.map(n => n.node), ['n6']);
  assert.deepStrictEqual(d.stale_declared.map(n => n.node), ['n9']);
  assert.deepStrictEqual(d.ip_mismatch.map(n => n.node), ['n2']);
  assert.deepStrictEqual(d.offline.map(n => n.node), ['n7']);
  assert.strictEqual(d.live_count, 4);
  assert.strictEqual(d.declared_count, 4);
});

test('an undeclared node is flagged schedulable — that is the whole hazard', () => {
  const d = A.diffClusterNodes({ clusterStatus: STATUS, declaredMap: {} });
  assert.strictEqual(d.undeclared.length, 3);
  assert.ok(d.undeclared.every(n => n.schedulable === true),
    'node-selector reads the live cluster, so these already receive lanes while ' +
    'every SSH/pct call to them fails with exit 255');
});

test('declared IPs are trimmed and win over the live address', () => {
  const p = A.computeExpectedPeers(STATUS, { n1: '  10.0.0.1  ' });
  const n1 = p.peers.find(x => x.node === 'n1');
  assert.strictEqual(n1.ip, '10.0.0.1');
  assert.strictEqual(n1.source, 'site.json');
  assert.strictEqual(p.peers.find(x => x.node === 'n6').source, 'cluster_status',
    'an undeclared node still contributes its live IP — it is exactly the node ' +
    'whose peering is broken');
});

test('computeExpectedPeers throws rather than synthesizing an address', () => {
  assert.throws(
    () => A.computeExpectedPeers([{ type: 'node', name: 'nx', online: 1 }], {}),
    /refusing to guess/,
    'replaces a fallback that built 100.100.10.<10+index> from array position');
  assert.throws(() => A.computeExpectedPeers([], {}), /No online nodes/);
});

test('offline nodes contribute no peer', () => {
  const p = A.computeExpectedPeers(
    [...STATUS, { type: 'node', name: 'down', ip: '100.100.10.99', online: 0 }], {});
  assert.ok(!p.ips.includes('100.100.10.99'));
});

test('peer comparison is order- and whitespace-insensitive', () => {
  const zones = [{ zone: 'z', type: 'vxlan', peers: '100.100.10.11, 100.100.10.10' }];
  assert.deepStrictEqual(
    A.diffZonePeers(zones, ['100.100.10.10', '100.100.10.11'], []), [],
    'Proxmox returns peers in its own order; an order-sensitive compare would ' +
    'flag every zone on the cluster');
});

test('a missing peer is drift; a zone with unreadable peers offers no repair', () => {
  const drift = A.diffZonePeers(
    [{ zone: 'goadlab', type: 'vxlan', peers: '100.100.10.10', digest: 'abc' }],
    ['100.100.10.10', '100.100.10.16'],
    [{ zone: 'goadlab' }, { zone: 'goadlab' }]);
  assert.deepStrictEqual(drift[0].missing_peers, ['100.100.10.16']);
  assert.strictEqual(drift[0].vnet_count, 2);
  assert.strictEqual(drift[0].readable, true);

  const unreadable = A.diffZonePeers([{ zone: 'z', type: 'vxlan' }], ['100.100.10.10'], []);
  assert.strictEqual(unreadable[0].readable, false);
  assert.deepStrictEqual(unreadable[0].missing_peers, [],
    'an unreadable zone must not look like "every peer missing" — that would ' +
    'offer to overwrite a value nobody read');
});

test('non-vxlan zones are not peer-checked', () => {
  assert.deepStrictEqual(A.diffZonePeers([{ zone: 's', type: 'simple' }], ['1.2.3.4'], []), []);
});

// ============================================================================
// REPORTING
// ============================================================================

test('an incomplete scan names how much was covered', () => {
  const s = A.summarizeScan(
    { complete: false, nodes_total: 10, nodes_scanned: 8, storages_failed: [], stats: {} },
    { trusted: true, nodes_online: 10, nodes_total: 10 });
  assert.match(s.warnings[0], /8 of 10 nodes scanned/);
  assert.strictEqual(s.complete, false);
});

test('a degraded cluster view is untrusted and says why', () => {
  const s = A.summarizeScan(
    { complete: true, nodes_total: 10, nodes_scanned: 8, storages_failed: [], stats: {} },
    { trusted: false, nodes_online: 8, nodes_total: 10 });
  assert.strictEqual(s.trusted, false);
  assert.ok(s.warnings.some(w => /may belong to a live VM/.test(w)));
});

test('the audit budget leaves real margin under the 100s tunnel limit', () => {
  const budget = Number(process.env.RECONCILE_BUDGET_MS) || 45000;
  const guacWorstCase = 20000;   // utils/guacamole.js GUAC_TOTAL_TIMEOUT_MS
  assert.ok(budget + guacWorstCase < 90000,
    `budget ${budget}ms + Guac ${guacWorstCase}ms must stay well under Cloudflare's ` +
    `100s origin timeout, which returns an HTML page the admin UI cannot parse`);
});
