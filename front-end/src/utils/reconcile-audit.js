/**
 * ============================================================================
 * RECONCILE AUDIT — pure logic
 * ============================================================================
 * Every decision the Proxmox audit makes, with no I/O and NO REQUIRE STATEMENTS.
 *
 * The import-free rule is deliberate and load-bearing. Every plausible import
 * from here (proxmox.js, site-config.js, batch-deployer.js, attached-modules.js)
 * transitively reads config/site.json, which is gitignored and absent from a
 * plain checkout — so a test that required any of them would need the
 * require.cache stub the deploy tests carry. Staying import-free means the test
 * for this file needs no stubs at all, which is why the audit's actual rules
 * live here rather than inline in routes/admin/cluster.js.
 *
 * The caller does the I/O and hands the results in.
 * ============================================================================
 */

// ============================================================================
// VMID RANGES
// ============================================================================

/**
 * VMID ranges owned by CyberHub (mirrors the ranges in deploy/teardown logic).
 * A factory rather than a constant so the attached-module bounds come from
 * utils/attached-modules.js without this file importing it.
 */
function buildCyberhubRanges({ attachedBase, attachedSlots, attachedStep }) {
  return [
    { min: 100000, max: 199999, role: 'gateway' },
    { min: 200000, max: 299999, role: 'goad_controller' },
    { min: 600000, max: 699999, role: 'challenge' },
    { min: 700000, max: 799999, role: 'attack_box' },
    {
      min: attachedBase,
      max: attachedBase + (attachedSlots * attachedStep) - 1,
      role: 'attached_module'
    }
  ];
}

function vmidRole(vmid, ranges) {
  const hit = ranges.find(r => vmid >= r.min && vmid <= r.max);
  return hit ? hit.role : null;
}

function inCyberhubRange(vmid, ranges) {
  return ranges.some(r => vmid >= r.min && vmid <= r.max);
}

// ============================================================================
// STORAGE CLASSIFICATION AND SCAN PLANNING
// ============================================================================

/**
 * Storage types whose content is identical from every node, used ONLY when the
 * storage object carries no explicit `shared` flag. The flag always wins: an
 * operator who marked a storage shared in /etc/pve/storage.cfg knows something
 * this table does not.
 */
const SHARED_STORAGE_TYPES = new Set([
  'rbd', 'cephfs', 'nfs', 'cifs', 'glusterfs', 'iscsi', 'iscsidirect', 'pbs'
]);

function isSharedStorage(s) {
  if (s.shared === 1 || s.shared === true) return true;
  if (s.shared === 0 || s.shared === false) return false;
  return SHARED_STORAGE_TYPES.has(s.type);
}

/**
 * Scan key for a storage.
 *
 * Storage IDs are cluster-wide unique in Proxmox (/etc/pve/storage.cfg), so a
 * shared storage can be keyed by name alone and read exactly once. A LOCAL
 * storage shares its NAME across nodes ('local-lvm' everywhere) but not its
 * CONTENT, so it must stay keyed per node.
 */
function storageJobKey(node, s) {
  return isSharedStorage(s) ? `shared:${s.storage}` : `local:${node}/${s.storage}`;
}

/**
 * Turn per-node storage listings into the minimum set of content calls.
 *
 * This is the whole point of the rewrite. The old scan walked every (node,
 * storage) pair, so a Ceph cluster listed the same pool once per node and threw
 * N-1 of those listings away after paying full price for each. Here a shared
 * storage becomes ONE job with every node as a candidate reader.
 *
 * @param {Array<{node, online, storages, error}>} nodeStorages
 * @param {{preferredNode?: string, assumeShared?: boolean, storageFilter?: string}} opts
 */
function planStorageScan(nodeStorages, opts = {}) {
  const preferredNode = opts.preferredNode || null;
  const assumeShared = opts.assumeShared !== false;
  const storageFilter = opts.storageFilter || null;

  const jobs = new Map();
  const skipped = { nodes: [], storages: [] };
  let nodesOnline = 0;
  let naiveCalls = 0;

  for (const entry of nodeStorages) {
    const { node, online, storages, error } = entry;
    if (!online) {
      skipped.nodes.push({ node, reason: 'offline' });
      continue;
    }
    if (error || !Array.isArray(storages)) {
      skipped.nodes.push({ node, reason: `storage list failed: ${error || 'no storage list returned'}` });
      continue;
    }
    nodesOnline++;

    for (const s of storages) {
      // A storage that does not hold disk images is a legitimate exclusion, not
      // a coverage hole — tracked nowhere, unlike the failures below.
      if (s.content && !String(s.content).includes('images')) continue;
      if (storageFilter && s.storage !== storageFilter) continue;
      if (s.enabled === 0) { skipped.storages.push({ node, storage: s.storage, reason: 'disabled' }); continue; }
      if (s.active === 0) { skipped.storages.push({ node, storage: s.storage, reason: 'inactive' }); continue; }

      naiveCalls++;   // what the old per-(node,storage) scan would have cost

      const shared = assumeShared ? isSharedStorage(s) : false;
      const key = shared ? `shared:${s.storage}` : `local:${node}/${s.storage}`;
      const job = jobs.get(key) || { key, storage: s.storage, shared, readers: [] };
      job.readers.push(node);
      jobs.set(key, job);
    }
  }

  const jobList = [...jobs.values()];

  // Prefer the node the API URL points at: a request for /nodes/<other>/... is
  // forwarded pveproxy-to-pveproxy over the cluster link, a second internal TLS
  // hop and a common source of 596s under load.
  if (preferredNode) {
    for (const job of jobList) {
      if (job.shared && job.readers.includes(preferredNode)) {
        job.readers = [preferredNode, ...job.readers.filter(n => n !== preferredNode)];
      }
    }
  }

  return {
    jobs: jobList,
    skipped,
    stats: {
      nodes_total: nodeStorages.length,
      nodes_online: nodesOnline,
      images_storages: jobList.length,
      shared_storages: jobList.filter(j => j.shared).length,
      calls_planned: jobList.length,
      calls_naive: naiveCalls,
      calls_saved: naiveCalls - jobList.length
    }
  };
}

// ============================================================================
// VOLUME PARSING AND ORPHAN CLASSIFICATION
// ============================================================================

/**
 * Pull the owning VMID out of a volid.
 *
 * `subvol-` is how LXC volumes are named on ZFS and directory storage. The
 * original pattern matched only `vm-`, so a lane gateway (an LXC in the 100000
 * range) that left its rootfs behind on non-block storage was invisible to the
 * audit.
 *
 * `base-<vmid>-disk-N` (template disks) is deliberately NOT matched: templates
 * are protected by the live-VMID check anyway, and the cost of a wrong match
 * there is offering to delete a template.
 */
function parseVolid(volid) {
  if (typeof volid !== 'string') return null;
  const match = volid.match(/(?:vm|subvol)-(\d+)-(disk|cloudinit)/);
  if (!match) return null;
  return { vmid: parseInt(match[1], 10), kind: match[2] };
}

function toGb(bytes) {
  return bytes ? (bytes / (1024 ** 3)).toFixed(2) : '0.00';
}

/**
 * Volumes with no live VM, inside a CyberHub range.
 *
 * Dedup is deterministic by design. The old scan kept whichever node
 * /api2/json/nodes happened to list first; once the scan runs in parallel that
 * ordering is a race, and the row's Destroy button targets d.node. So: sort,
 * then keep the first. For shared storage the delete removes the underlying
 * object cluster-wide from any node that has the storage active, so which of
 * the candidate readers gets recorded does not change the outcome — only its
 * stability across runs.
 */
function classifyOrphanDisks(volumes, { liveVmIds, ranges }) {
  const byVolid = new Map();

  for (const v of volumes) {
    const parsed = parseVolid(v.volid);
    if (!parsed) continue;
    if (!inCyberhubRange(parsed.vmid, ranges)) continue;
    if (liveVmIds.has(parsed.vmid)) continue;

    const existing = byVolid.get(v.volid);
    if (existing && `${existing.node}/${existing.storage}` <= `${v.node}/${v.storage}`) continue;

    byVolid.set(v.volid, {
      node: v.node,
      storage: v.storage,
      shared: !!v.shared,
      volid: v.volid,
      vmid: parsed.vmid,
      kind: parsed.kind,
      role: vmidRole(parsed.vmid, ranges),
      size_bytes: v.size || 0,
      size_gb: toGb(v.size)
    });
  }

  const disks = [...byVolid.values()].sort((a, b) => a.volid.localeCompare(b.volid));
  const totalBytes = disks.reduce((sum, d) => sum + (d.size_bytes || 0), 0);
  return { disks, total_bytes: totalBytes, total_gb: (totalBytes / (1024 ** 3)).toFixed(2) };
}

// ============================================================================
// LANE INDEX
// ============================================================================

/**
 * Both VMID views of every lane, in ONE pass over each lane's config.
 *
 * The two are NOT the same list and must not be collapsed:
 *
 *   expectedVmIds       every VMID a lane owns — gateway and attack box
 *                       included. Used to decide whether a VM on Proxmox is
 *                       orphaned.
 *
 *   workloadVmIdsByLane the challenge/workload VMs ONLY, deliberately without
 *                       the gateway or attack box. Used to decide whether a
 *                       LANE is stale. A lane whose gateway LXC survives but
 *                       whose challenge VMs are gone is still stale, and must
 *                       still offer "Mark Deleted" — that is what frees the
 *                       VXLAN. Reusing expectedVmIds here would silently stop
 *                       flagging exactly that case.
 */
function buildLaneVmIndex(dbLanes) {
  const expectedVmIds = new Set();
  const laneVmMap = {};
  const workloadVmIdsByLane = new Map();

  for (const lane of dbLanes) {
    const vxlan = lane.vxlan_id;
    if (!vxlan) continue;
    const cfg = lane.config || {};

    const workload = [];
    if (Array.isArray(cfg.vms)) {
      cfg.vms.forEach(vm => { if (vm.vm_id) workload.push(vm.vm_id); });
    } else {
      workload.push(cfg.challenge_vm_id || (600000 + vxlan));
    }
    workloadVmIdsByLane.set(lane.lane_id, workload);

    const vmIds = [...workload];
    vmIds.push(cfg.gateway_vm_id || (100000 + vxlan));
    if (cfg.attack_box_vm_id) vmIds.push(cfg.attack_box_vm_id);
    else if (cfg.attack_box) vmIds.push(700000 + vxlan);

    if (Array.isArray(cfg.attached_modules)) {
      for (const mod of cfg.attached_modules) {
        for (const vm of (mod.vms || [])) {
          if (vm.vm_id) vmIds.push(vm.vm_id);
        }
      }
    }

    vmIds.forEach(id => {
      expectedVmIds.add(id);
      laneVmMap[id] = { lane_id: lane.lane_id, name: lane.name, vxlan_id: vxlan, status: lane.status };
    });
  }

  return { expectedVmIds, laneVmMap, workloadVmIdsByLane };
}

/** Lanes whose every workload VM is gone from Proxmox. */
function computeStaleLanes(dbLanes, laneIndex, pxVmIdSet) {
  return dbLanes
    .filter(lane => {
      if (!lane.vxlan_id) return false;
      const vmIds = laneIndex.workloadVmIdsByLane.get(lane.lane_id) || [];
      return vmIds.length > 0 && vmIds.every(id => !pxVmIdSet.has(id));
    })
    .map(lane => ({
      lane_id: lane.lane_id,
      name: lane.name,
      vxlan_id: lane.vxlan_id,
      status: lane.status,
      created_at: lane.created_at
    }));
}

function computeOrphanedVMs(pxVMs, expectedVmIds, ranges) {
  return pxVMs
    .filter(vm => inCyberhubRange(vm.vmid, ranges))
    .filter(vm => !expectedVmIds.has(vm.vmid))
    .map(vm => ({
      vmid: vm.vmid,
      name: vm.name,
      status: vm.status,
      node: vm.node,
      type: vm.type,
      role: vmidRole(vm.vmid, ranges),
      vxlan_inferred: vm.vmid % 100000
    }));
}

// ============================================================================
// SDN
// ============================================================================

/**
 * Orphaned SDN zones and VNets.
 *
 * `activeZoneNames` is built from ALL zones, not just the vxlan ones. Building
 * it from the vxlan-filtered list (as the inline version did) reported every
 * VNet in a simple/evpn/qinq zone as orphaned — complete with a Delete button —
 * even though its zone exists and is healthy.
 */
function computeSdnOrphans({ pxZonesAll, pxVNets, dbZoneNames }) {
  const vxlanZones = pxZonesAll.filter(z => z.type === 'vxlan');
  const zonesWithVnets = new Set(pxVNets.filter(v => v.zone).map(v => v.zone));

  const orphanedZones = vxlanZones
    .filter(z => !dbZoneNames.has(z.zone) && z.zone !== 'localnetwork')
    .map(z => ({
      zone: z.zone,
      type: z.type,
      has_vnets: zonesWithVnets.has(z.zone),
      vnet_count: pxVNets.filter(v => v.zone === z.zone).length
    }));

  const activeZoneNames = new Set(pxZonesAll.map(z => z.zone));
  const orphanedVNets = pxVNets
    .filter(v => v.zone && !activeZoneNames.has(v.zone))
    .map(v => ({ vnet: v.vnet, zone: v.zone, tag: v.tag, alias: v.alias }));

  return { vxlanZones, orphanedZones, orphanedVNets };
}

// ============================================================================
// CLUSTER NODE DRIFT
// ============================================================================

/**
 * The peer set a VXLAN zone should carry: one address per ONLINE cluster node.
 *
 * Declared IPs win. cluster.physical_cluster_ips is the operator's statement of
 * a node's management address and is what every socket in this codebase already
 * resolves through. An UNDECLARED node still contributes its live cluster IP,
 * because a node missing from site.json is exactly the node whose peering is
 * broken — deriving its peer from site.json would make it invisible here.
 *
 * THROWS rather than synthesizing. This replaces a fallback that built
 * `100.100.10.<10 + index>` from the node's position in an array whenever an
 * address could not be read, which produced a fabricated peer list that
 * happened to be right on the original six nodes and is wrong for anything
 * added since.
 */
function computeExpectedPeers(clusterStatus, declaredMap) {
  const online = (clusterStatus || []).filter(e => e.type === 'node' && e.online === 1);
  if (online.length === 0) {
    throw new Error('No online nodes reported by /cluster/status — refusing to compute peers');
  }

  const peers = [];
  const unresolved = [];
  for (const n of online) {
    const declared = declaredMap ? declaredMap[n.name] : null;
    const declaredIp = (typeof declared === 'string' && declared.trim()) ? declared.trim() : null;
    const ip = declaredIp || n.ip || null;
    if (!ip) { unresolved.push(n.name); continue; }
    peers.push({ node: n.name, ip, source: declaredIp ? 'site.json' : 'cluster_status' });
  }

  if (unresolved.length) {
    throw new Error(
      `Cannot determine an address for ${unresolved.join(', ')} — refusing to guess. ` +
      `Add them to cluster.physical_cluster_ips in config/site.json.`
    );
  }

  const ips = [...new Set(peers.map(p => p.ip))].sort();
  return { peers, ips, csv: ips.join(',') };
}

/** Peer CSV to a comparable set. Proxmox does not promise to preserve PUT order. */
function normalizePeers(peers) {
  if (peers === undefined || peers === null) return null;
  const list = Array.isArray(peers) ? peers : String(peers).split(',');
  return [...new Set(list.map(x => String(x).trim()).filter(Boolean))].sort();
}

/**
 * Live cluster nodes vs. what site.json declares.
 *
 * Node selection reads the LIVE cluster API, so a newly joined node receives
 * lane deployments immediately, while everything that opens a socket to it
 * (SSH, pct exec, pct push) resolves through physical_cluster_ips and fails
 * with exit 255 until it is declared there. That window is what this reports.
 */
function diffClusterNodes({ clusterStatus, declaredMap, vmCounts }) {
  const declared = declaredMap || {};
  const counts = vmCounts || {};
  const liveNodes = (clusterStatus || []).filter(e => e.type === 'node');
  const declaredNames = Object.keys(declared);
  const liveNames = new Set(liveNodes.map(n => n.name));

  const live = [];
  const undeclared = [];
  const ipMismatch = [];
  const offline = [];

  for (const n of liveNodes) {
    const rawDeclared = declared[n.name];
    const declaredIp = (typeof rawDeclared === 'string' && rawDeclared.trim()) ? rawDeclared.trim() : null;
    const status = n.online === 1 ? 'online' : 'offline';
    const row = {
      node: n.name,
      status,
      live_ip: n.ip || null,
      declared_ip: declaredIp,
      declared: !!declaredIp,
      vm_count: counts[n.name] || 0,
      peer_ip_source: declaredIp ? 'site.json' : 'cluster_status'
    };
    live.push(row);

    if (!declaredIp) {
      undeclared.push({ node: n.name, status, live_ip: n.ip || null, schedulable: status === 'online' });
    } else if (n.ip && n.ip !== declaredIp) {
      ipMismatch.push({ node: n.name, live_ip: n.ip, declared_ip: declaredIp });
    }
    if (status !== 'online') {
      offline.push({ node: n.name, status, declared_ip: declaredIp });
    }
  }

  const staleDeclared = declaredNames
    .filter(name => !liveNames.has(name))
    .map(name => ({ node: name, declared_ip: declared[name] }));

  return {
    live: live.sort((a, b) => a.node.localeCompare(b.node)),
    undeclared,
    stale_declared: staleDeclared,
    ip_mismatch: ipMismatch,
    offline,
    declared_count: declaredNames.length,
    live_count: liveNodes.length,
    issue_count: undeclared.length + staleDeclared.length + ipMismatch.length + offline.length
  };
}

/**
 * VXLAN zones whose peer list has drifted from the online node set.
 *
 * A zone whose peers could not be read is reported readable:false and carries
 * NO repair — never offer to overwrite a value you could not read. Comparison
 * is order-insensitive: Proxmox returns peers in its own order, and an
 * order-sensitive compare would flag every zone on the cluster.
 */
function diffZonePeers(zones, expectedIps, pxVNets) {
  const expected = normalizePeers(expectedIps) || [];
  const vnets = pxVNets || [];
  const out = [];

  for (const z of zones) {
    if (z.type !== 'vxlan') continue;
    const current = normalizePeers(z.peers);
    const vnetCount = vnets.filter(v => v.zone === z.zone).length;

    if (current === null) {
      out.push({
        zone: z.zone, type: z.type, readable: false,
        peers: null, peers_list: [], expected_peers: expected,
        missing_peers: [], extra_peers: [], vnet_count: vnetCount, digest: z.digest || null
      });
      continue;
    }

    const missing = expected.filter(ip => !current.includes(ip));
    const extra = current.filter(ip => !expected.includes(ip));
    if (missing.length === 0 && extra.length === 0) continue;

    out.push({
      zone: z.zone, type: z.type, readable: true,
      peers: current.join(','), peers_list: current,
      expected_peers: expected, missing_peers: missing, extra_peers: extra,
      vnet_count: vnetCount, digest: z.digest || null
    });
  }
  return out;
}

// ============================================================================
// REPORTING
// ============================================================================

/**
 * The disk_scan block, including whether the result can be acted on.
 *
 * `trusted` gates the destructive controls, and that is not cosmetic. Skipping
 * a node only hides orphans on it — but an offline node is precisely the
 * condition under which the CLUSTER-WIDE view stops being reliable. If pmxcfs
 * loses quorum, guests drop out of /cluster/resources while their RBD images
 * stay fully visible on shared storage, and every one of those disks then
 * renders as an orphan with a Delete button beside it. The same degradation
 * over-reports stale lanes, whose "Mark Deleted" frees a VXLAN that is still on
 * the wire and lets a later lane collide with it on the same L2.
 */
function summarizeScan(scan, clusterView) {
  const warnings = [];
  const nodesTotal = scan.nodes_total || 0;
  const nodesScanned = scan.nodes_scanned || 0;
  const skippedNodes = (scan.skipped && scan.skipped.nodes) || [];
  const failedStorages = scan.storages_failed || [];

  if (!scan.complete) {
    if (nodesScanned < nodesTotal) {
      warnings.push(
        `Disk scan incomplete — ${nodesScanned} of ${nodesTotal} nodes scanned; ` +
        `orphaned disks on the other ${nodesTotal - nodesScanned} are not listed.`
      );
    } else {
      warnings.push('Disk scan incomplete — it hit its time budget before finishing.');
    }
  }
  if (failedStorages.length) {
    warnings.push(
      `${failedStorages.length} storage listing(s) failed: ` +
      failedStorages.map(s => `${s.node}/${s.storage}`).join(', ')
    );
  }
  if (!clusterView.trusted) {
    warnings.push(
      `Cluster view is degraded (${clusterView.nodes_online} of ${clusterView.nodes_total} nodes online) — ` +
      `an orphan shown here may belong to a live VM. Destructive sweeps are disabled.`
    );
  }

  const callsNaive = (scan.stats && scan.stats.calls_naive) || 0;
  return {
    complete: !!scan.complete,
    trusted: !!clusterView.trusted,
    duration_ms: scan.duration_ms || 0,
    budget_ms: scan.budget_ms || 0,
    nodes_total: nodesTotal,
    nodes_scanned: nodesScanned,
    nodes_skipped: skippedNodes,
    storages_scanned: scan.storages_scanned || 0,
    storages_failed: failedStorages,
    shared_storages: (scan.stats && scan.stats.shared_storages) || 0,
    calls_made: scan.calls_made || 0,
    calls_naive: callsNaive,
    calls_saved: Math.max(0, callsNaive - (scan.calls_made || 0)),
    warnings
  };
}

module.exports = {
  buildCyberhubRanges,
  vmidRole,
  inCyberhubRange,
  SHARED_STORAGE_TYPES,
  isSharedStorage,
  storageJobKey,
  planStorageScan,
  parseVolid,
  classifyOrphanDisks,
  buildLaneVmIndex,
  computeStaleLanes,
  computeOrphanedVMs,
  computeSdnOrphans,
  computeExpectedPeers,
  normalizePeers,
  diffClusterNodes,
  diffZonePeers,
  summarizeScan
};
