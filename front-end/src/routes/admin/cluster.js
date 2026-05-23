/**
 * ============================================================================
 * Cluster & Reconcile Admin Routes
 * Cluster health, deploy preview, reconciliation, orphan sweeps,
 * activity log, and VM-level utilities.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { proxmoxAPI } = require('../../utils/proxmox');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { guacAPI } = require('../../utils/guacamole');
const { getClusterHealth, buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const attachedModules = require('../../utils/attached-modules');
const { waitForGuestAgent } = require('../../utils/script-executor');

const adminOnly = requireRole('admin');

// VMID ranges owned by CyberHub (mirrors the ranges in deploy/teardown logic)
const CYBERHUB_RANGES = [
  { min: 100000, max: 199999, role: 'gateway' },
  { min: 200000, max: 299999, role: 'goad_controller' },
  { min: 600000, max: 699999, role: 'challenge' },
  { min: 700000, max: 799999, role: 'attack_box' },
  {
    min: attachedModules.ATTACHED_VMID_BASE,
    max: attachedModules.ATTACHED_VMID_BASE + (attachedModules.ATTACHED_MAX_SLOTS * attachedModules.ATTACHED_VMID_STEP) - 1,
    role: 'attached_module'
  }
];


// ============================================================================
// CLUSTER HEALTH & DEPLOYMENT GUARDS
// ============================================================================

router.get('/proxmox/status', authenticateToken, adminOnly, async (req, res) => {
  try {
    await proxmoxAPI('GET', '/api2/json/version');
    res.json({ connected: true, url: process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006' });
  } catch (error) {
    res.status(502).json({ connected: false, error: error.message });
  }
});

router.get('/cluster/health', authenticateToken, adminOnly, async (req, res) => {
  try {
    const health = await getClusterHealth(proxmoxAPI);
    res.json(health);
  } catch (error) {
    res.status(502).json({ error: `Failed to fetch cluster health: ${error.message}` });
  }
});

router.post('/deploy-preview', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { num_lanes = 1, attack_boxes = false, challenge_vm_count = 1 } = req.body;
    const preview = await buildDeployPreview({
      numLanes: parseInt(num_lanes) || 1,
      attackBoxes: !!attack_boxes,
      challengeVmCount: parseInt(challenge_vm_count) || 1,
      proxmoxAPI,
      cybercoreQuery
    });
    res.json(preview);
  } catch (error) {
    res.status(502).json({ error: `Failed to build deploy preview: ${error.message}` });
  }
});


// ============================================================================
// RECONCILE — compare DB state against live Proxmox resources
// ============================================================================

router.get('/reconcile', authenticateToken, adminOnly, async (req, res) => {
  try {
    const pxResources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const pxVMs = (Array.isArray(pxResources) ? pxResources : []).map(vm => ({
      vmid: vm.vmid,
      name: vm.name || '',
      status: vm.status,
      node: vm.node,
      type: vm.type
    }));

    let pxVNets = [];
    try {
      const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      pxVNets = (Array.isArray(vnets) ? vnets : []).map(v => ({
        vnet: v.vnet, zone: v.zone, tag: v.tag, alias: v.alias || ''
      }));
    } catch (e) { /* SDN may not be configured */ }

    const dbLanes = (await cybercoreQuery(
      `SELECT lane_id, vxlan_id, name, status, config, created_at
       FROM cybercore_lane WHERE status NOT IN ('deleted')
       ORDER BY created_at DESC`
    )).rows;

    const dbGroups = (await query(
      `SELECT id, group_name, config, created_at FROM deployed_groups ORDER BY created_at DESC`
    )).rows;

    const dbExpectedVmIds = new Set();
    const laneVmMap = {};
    for (const lane of dbLanes) {
      const vxlan = lane.vxlan_id;
      if (!vxlan) continue;
      const cfg = lane.config || {};
      const vmIds = [];

      if (Array.isArray(cfg.vms)) {
        cfg.vms.forEach(vm => { if (vm.vm_id) vmIds.push(vm.vm_id); });
      } else {
        vmIds.push(cfg.challenge_vm_id || (600000 + vxlan));
      }
      const gwId = cfg.gateway_vm_id || (100000 + vxlan);
      vmIds.push(gwId);
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
        dbExpectedVmIds.add(id);
        laneVmMap[id] = { lane_id: lane.lane_id, name: lane.name, vxlan_id: vxlan, status: lane.status };
      });
    }

    let pxZones = [];
    try {
      const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
      pxZones = (Array.isArray(zones) ? zones : []).filter(z => z.type === 'vxlan');
    } catch (e) { /* SDN may not be configured */ }

    const dbChallenges = (await cybercoreQuery(
      `SELECT challenge_key, name, spec FROM crucible_challenge`
    )).rows;

    const dbZoneNames = new Set();
    for (const ch of dbChallenges) {
      const spec = typeof ch.spec === 'string' ? JSON.parse(ch.spec || '{}') : (ch.spec || {});
      const zoneName = spec.zone?.abbrev
        || ch.challenge_key?.substring(0, 8)?.replace(/[^a-z0-9]/gi, '').substring(0, 8);
      if (zoneName) dbZoneNames.add(zoneName);
    }

    const laneZoneNames = new Set();
    for (const vnet of pxVNets) {
      if (vnet.zone) laneZoneNames.add(vnet.zone);
    }

    const orphanedZones = pxZones
      .filter(z => !dbZoneNames.has(z.zone) && z.zone !== 'localnetwork')
      .map(z => ({
        zone: z.zone,
        type: z.type,
        has_vnets: laneZoneNames.has(z.zone),
        vnet_count: pxVNets.filter(v => v.zone === z.zone).length
      }));

    const activeZoneNames = new Set(pxZones.map(z => z.zone));
    const orphanedVNets = pxVNets.filter(v => v.zone && !activeZoneNames.has(v.zone))
      .map(v => ({ vnet: v.vnet, zone: v.zone, tag: v.tag, alias: v.alias }));

    const pxCyberhubVMs = pxVMs.filter(vm =>
      CYBERHUB_RANGES.some(r => vm.vmid >= r.min && vm.vmid <= r.max)
    );
    const pxVmIdSet = new Set(pxCyberhubVMs.map(vm => vm.vmid));

    const orphanedOnProxmox = pxCyberhubVMs
      .filter(vm => !dbExpectedVmIds.has(vm.vmid))
      .map(vm => ({
        vmid: vm.vmid,
        name: vm.name,
        status: vm.status,
        node: vm.node,
        type: vm.type,
        role: CYBERHUB_RANGES.find(r => vm.vmid >= r.min && vm.vmid <= r.max)?.role,
        vxlan_inferred: vm.vmid % 100000
      }));

    const staleInDB = dbLanes
      .filter(lane => {
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
      })
      .map(lane => ({
        lane_id: lane.lane_id,
        name: lane.name,
        vxlan_id: lane.vxlan_id,
        status: lane.status,
        created_at: lane.created_at
      }));

    // Orphaned disk audit
    const liveVmIdSet = new Set(pxVMs.map(v => v.vmid));
    const orphanedDisks = [];
    const seenDiskVolids = new Set();

    try {
      const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
      const nodeNames = (nodeList || []).map(n => n.node);

      for (const node of nodeNames) {
        let nodeStorages;
        try {
          nodeStorages = await proxmoxAPI('GET', `/api2/json/nodes/${node}/storage`);
        } catch (_) { continue; }

        for (const s of nodeStorages || []) {
          if (s.content && !s.content.includes('images')) continue;
          let contents;
          try {
            contents = await proxmoxAPI('GET',
              `/api2/json/nodes/${node}/storage/${s.storage}/content?content=images`);
          } catch (_) { continue; }

          for (const item of contents || []) {
            const match = item.volid?.match(/vm-(\d+)-(disk|cloudinit)/);
            if (!match) continue;
            const vmid = parseInt(match[1]);
            const kind = match[2];
            const inRange = CYBERHUB_RANGES.some(r => vmid >= r.min && vmid <= r.max);
            if (!inRange) continue;
            if (liveVmIdSet.has(vmid)) continue;
            if (seenDiskVolids.has(item.volid)) continue;
            seenDiskVolids.add(item.volid);
            orphanedDisks.push({
              node,
              storage: s.storage,
              volid: item.volid,
              vmid,
              kind,
              role: CYBERHUB_RANGES.find(r => vmid >= r.min && vmid <= r.max)?.role,
              size_bytes: item.size || 0,
              size_gb: item.size ? (item.size / (1024 ** 3)).toFixed(2) : '0.00'
            });
          }
        }
      }
    } catch (e) {
      console.warn(`[Reconcile] Disk scan failed: ${e.message}`);
    }

    const orphanedDiskTotalGb = orphanedDisks.reduce((sum, d) => sum + (d.size_bytes || 0), 0) / (1024 ** 3);

    // Orphaned Guacamole connection audit
    const orphanedGuacConnections = [];
    try {
      const allGuacConns = await guacAPI('GET', '/connections');
      const connList = Array.isArray(allGuacConns)
        ? allGuacConns
        : Object.values(allGuacConns || {});

      const trackedConnIds = new Set();
      for (const g of dbGroups) {
        const gCfg = typeof g.config === 'string' ? JSON.parse(g.config) : (g.config || {});
        for (const c of (gCfg.guac_connections || [])) {
          if (c?.id) trackedConnIds.add(String(c.id));
        }
      }

      const activeGuacGroupIds = new Set();
      for (const g of dbGroups) {
        const gCfg = typeof g.config === 'string' ? JSON.parse(g.config) : (g.config || {});
        if (gCfg.guac_group?.identifier) activeGuacGroupIds.add(String(gCfg.guac_group.identifier));
      }

      for (const c of connList) {
        const name = c.name || '';
        const id = String(c.identifier || c.id || '');
        const parent = String(c.parentIdentifier || 'ROOT');

        const looksLikeCyberhub = / - .* - (Kali|VulnWin|Target|Attack|RDP)/i.test(name)
          || trackedConnIds.has(id);
        if (!looksLikeCyberhub) continue;

        const isOrphan = !activeGuacGroupIds.has(parent) || parent === 'ROOT';
        if (isOrphan) {
          orphanedGuacConnections.push({
            id,
            name,
            protocol: c.protocol || '',
            parent,
            tracked: trackedConnIds.has(id)
          });
        }
      }
    } catch (e) {
      console.warn(`[Reconcile] Guac connection scan failed: ${e.message}`);
    }

    res.json({
      timestamp: new Date().toISOString(),
      summary: {
        proxmox_cyberhub_vms: pxCyberhubVMs.length,
        db_active_lanes: dbLanes.length,
        db_expected_vms: dbExpectedVmIds.size,
        orphaned_on_proxmox: orphanedOnProxmox.length,
        stale_in_db: staleInDB.length,
        sdn_zones: pxZones.length,
        orphaned_zones: orphanedZones.length,
        sdn_vnets: pxVNets.length,
        orphaned_vnets: orphanedVNets.length,
        deployed_groups: dbGroups.length,
        orphaned_disks: orphanedDisks.length,
        orphaned_disks_total_gb: orphanedDiskTotalGb.toFixed(2),
        orphaned_guac_connections: orphanedGuacConnections.length
      },
      orphaned_on_proxmox: orphanedOnProxmox,
      stale_in_db: staleInDB,
      orphaned_zones: orphanedZones,
      orphaned_vnets: orphanedVNets,
      orphaned_disks: orphanedDisks,
      orphaned_guac_connections: orphanedGuacConnections,
      sdn_vnets: pxVNets,
      all_proxmox_cyberhub_vms: pxCyberhubVMs
    });
  } catch (error) {
    console.error('[Reconcile] Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-vm', authenticateToken, adminOnly, async (req, res) => {
  const { vmid, node, type } = req.body;
  if (!vmid || !node) return res.status(400).json({ error: 'vmid and node required' });
  try {
    try {
      const stopPath = type === 'lxc'
        ? `/api2/json/nodes/${node}/lxc/${vmid}/status/stop`
        : `/api2/json/nodes/${node}/qemu/${vmid}/status/stop`;
      await proxmoxAPI('POST', stopPath);
      await new Promise(r => setTimeout(r, 3000));
    } catch (e) { /* may already be stopped */ }
    try {
      const cfgPath = type === 'lxc'
        ? `/api2/json/nodes/${node}/lxc/${vmid}/config`
        : `/api2/json/nodes/${node}/qemu/${vmid}/config`;
      await proxmoxAPI('PUT', cfgPath, { protection: 0 });
    } catch (e) { /* may not have protection set */ }
    const delPath = type === 'lxc'
      ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
      : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1`;
    await proxmoxAPI('DELETE', delPath);
    console.log(`[Reconcile] Destroyed orphaned VM ${vmid} on ${node}`);
    res.json({ ok: true, vmid, node });
  } catch (error) {
    console.error(`[Reconcile] Failed to destroy VM ${vmid}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/mark-deleted', authenticateToken, adminOnly, async (req, res) => {
  const { lane_id } = req.body;
  if (!lane_id) return res.status(400).json({ error: 'lane_id required' });
  try {
    await cybercoreQuery(
      `UPDATE cybercore_lane SET status = 'deleted', updated_at = NOW() WHERE lane_id = $1`,
      [lane_id]
    );
    console.log(`[Reconcile] Marked lane ${lane_id} as deleted (stale — no Proxmox VMs)`);
    res.json({ ok: true, lane_id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-disk', authenticateToken, adminOnly, async (req, res) => {
  const { node, storage, volid } = req.body;
  if (!node || !storage || !volid) return res.status(400).json({ error: 'node, storage, and volid required' });
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await proxmoxAPI('DELETE',
        `/api2/json/nodes/${node}/storage/${storage}/content/${encodeURIComponent(volid)}`);
      console.log(`[Reconcile] Destroyed orphaned disk ${volid} on ${node}/${storage}`);
      logActivity(req, 'destroy_orphan_disk', 'storage', null, { volid, node, storage });
      return res.json({ ok: true, volid, node, storage });
    } catch (e) {
      lastErr = e;
      if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
    }
  }
  console.error(`[Reconcile] Failed to destroy disk ${volid}: ${lastErr?.message}`);
  res.status(500).json({ error: lastErr?.message || 'Delete failed after 3 attempts' });
});

router.post('/reconcile/destroy-guac-connection', authenticateToken, adminOnly, async (req, res) => {
  const { id, name } = req.body;
  if (!id) return res.status(400).json({ error: 'id required' });
  try {
    await guacAPI('DELETE', `/connections/${encodeURIComponent(id)}`);
    console.log(`[Reconcile] Destroyed orphaned Guac connection ${id} (${name || '?'})`);
    logActivity(req, 'destroy_orphan_guac_connection', 'guacamole', null, { id, name });
    res.json({ ok: true, id });
  } catch (error) {
    console.error(`[Reconcile] Failed to destroy Guac connection ${id}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-zone', authenticateToken, adminOnly, async (req, res) => {
  const { zone } = req.body;
  if (!zone) return res.status(400).json({ error: 'zone required' });
  try {
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const zoneVnets = (Array.isArray(vnets) ? vnets : []).filter(v => v.zone === zone);
    for (const vnet of zoneVnets) {
      console.log(`[Reconcile] Deleting VNet '${vnet.vnet}' in zone '${zone}'`);
      await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet.vnet}`);
    }
    console.log(`[Reconcile] Deleting SDN zone '${zone}'`);
    await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zone}`);
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (e) { /* best effort */ }
    console.log(`[Reconcile] Zone '${zone}' destroyed (${zoneVnets.length} VNets removed)`);
    res.json({ ok: true, zone, vnets_removed: zoneVnets.length });
  } catch (error) {
    console.error(`[Reconcile] Failed to destroy zone ${zone}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-vnet', authenticateToken, adminOnly, async (req, res) => {
  const { vnet } = req.body;
  if (!vnet) return res.status(400).json({ error: 'vnet required' });
  try {
    await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet}`);
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (e) { /* best effort */ }
    console.log(`[Reconcile] Deleted orphaned VNet '${vnet}'`);
    res.json({ ok: true, vnet });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ORPHANED DISK SWEEP
// ============================================================================

router.post('/sweep-orphaned-disks', authenticateToken, adminOnly, async (req, res) => {
  const dry_run = req.body?.dry_run !== false;
  const storageFilter = req.body?.storage || null;
  const vmidPattern = req.body?.vmid_pattern ? new RegExp(req.body.vmid_pattern) : null;
  const orphans = [];
  const deleted = [];
  const errors = [];

  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
    const liveVmIds = new Set();
    for (const r of resources || []) {
      if (r.type === 'qemu' || r.type === 'lxc') {
        if (typeof r.vmid === 'number') liveVmIds.add(r.vmid);
      }
    }

    const nodes = await proxmoxAPI('GET', '/api2/json/nodes');

    for (const node of nodes || []) {
      let nodeStorages;
      try {
        nodeStorages = await proxmoxAPI('GET', `/api2/json/nodes/${node.node}/storage`);
      } catch (e) {
        errors.push(`List storages on ${node.node}: ${e.message}`);
        continue;
      }

      for (const s of nodeStorages || []) {
        if (storageFilter && s.storage !== storageFilter) continue;
        if (s.content && !s.content.includes('images')) continue;

        let contents;
        try {
          contents = await proxmoxAPI('GET',
            `/api2/json/nodes/${node.node}/storage/${s.storage}/content?content=images`);
        } catch (e) {
          errors.push(`Content of ${s.storage} on ${node.node}: ${e.message}`);
          continue;
        }

        for (const item of contents || []) {
          const match = item.volid?.match(/vm-(\d+)-disk/);
          if (!match) continue;
          const vmid = parseInt(match[1]);
          if (vmidPattern && !vmidPattern.test(String(vmid))) continue;
          if (liveVmIds.has(vmid)) continue;
          orphans.push({
            node: node.node,
            storage: s.storage,
            volid: item.volid,
            vmid,
            size_bytes: item.size || 0,
            size_gb: item.size ? (item.size / (1024 ** 3)).toFixed(2) : '0.00'
          });
        }
      }
    }

    const dedupedOrphans = [];
    const seenVolids = new Set();
    for (const o of orphans) {
      if (seenVolids.has(o.volid)) continue;
      seenVolids.add(o.volid);
      dedupedOrphans.push(o);
    }

    if (!dry_run) {
      for (const o of dedupedOrphans) {
        let ok = false;
        let lastErr = null;
        for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
          try {
            await proxmoxAPI('DELETE',
              `/api2/json/nodes/${o.node}/storage/${o.storage}/content/${encodeURIComponent(o.volid)}`);
            deleted.push(o);
            console.log(`[Orphan Sweep] Deleted ${o.volid} on ${o.node}/${o.storage}`);
            ok = true;
          } catch (e) {
            lastErr = e;
            if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
          }
        }
        if (!ok && lastErr) errors.push(`Delete ${o.volid} on ${o.node}: ${lastErr.message}`);
      }
    }

    const totalBytes = dedupedOrphans.reduce((sum, o) => sum + (o.size_bytes || 0), 0);
    const reclaimedBytes = deleted.reduce((sum, o) => sum + (o.size_bytes || 0), 0);

    logActivity(req, dry_run ? 'scan_orphaned_disks' : 'sweep_orphaned_disks', 'storage', null,
      { storage_filter: storageFilter || 'all', found: dedupedOrphans.length, deleted: deleted.length, total_gb: (totalBytes / (1024 ** 3)).toFixed(2) }
    );

    res.json({
      success: true,
      dry_run,
      storage_filter: storageFilter,
      vmid_pattern: req.body?.vmid_pattern || null,
      orphans_found: dedupedOrphans.length,
      orphans_deleted: deleted.length,
      total_orphan_size_gb: (totalBytes / (1024 ** 3)).toFixed(2),
      reclaimed_size_gb: (reclaimedBytes / (1024 ** 3)).toFixed(2),
      orphans: dedupedOrphans,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACTIVITY LOG
// ============================================================================

router.get('/activity-log', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { action_type, user_id: filterUserId, from, to, limit: lim, offset: off, search } = req.query;
    const limit = Math.min(parseInt(lim) || 50, 200);
    const offset = parseInt(off) || 0;

    let where = [];
    let params = [];
    let paramIdx = 1;

    if (action_type) { where.push(`a.action_type = $${paramIdx++}`); params.push(action_type); }
    if (filterUserId) { where.push(`a.user_id = $${paramIdx++}`); params.push(filterUserId); }
    if (from) { where.push(`a.created_at >= $${paramIdx++}`); params.push(from); }
    if (to) { where.push(`a.created_at <= $${paramIdx++}`); params.push(to); }
    if (search) {
      where.push(`(a.action_type ILIKE $${paramIdx} OR a.entity_type ILIKE $${paramIdx})`);
      params.push(`%${search}%`);
      paramIdx++;
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const [logs, countResult] = await Promise.all([
      query(
        `SELECT a.* FROM activity_log a ${whereClause} ORDER BY a.created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
        [...params, limit, offset]
      ),
      query(`SELECT COUNT(*) AS total FROM activity_log a ${whereClause}`, params)
    ]);

    res.json({
      logs: logs.rows,
      total: parseInt(countResult.rows[0].total),
      limit,
      offset
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// VM PROGRESS LOG
// ============================================================================

router.get('/vm-progress/:laneId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { vm_name } = req.query;
    const laneResult = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });

    const config = typeof laneResult.rows[0].config === 'string'
      ? JSON.parse(laneResult.rows[0].config) : laneResult.rows[0].config;

    let vm = (config.vms || []).find(v => v.name === vm_name);
    if (!vm && config.challenge_vm_id) {
      vm = { vm_id: config.challenge_vm_id, node: config.node };
    }
    if (!vm && config.vms?.length === 1) vm = config.vms[0];
    if (!vm) return res.json({ log: 'VM not found' });

    const result = await proxmoxAPI('POST',
      `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
        command: 'powershell.exe',
        'input-data': `if (Test-Path 'C:\\LabApps\\progress.log') { Get-Content 'C:\\LabApps\\progress.log' -Raw } else { Write-Host 'No progress log yet' }\n[Environment]::Exit(0)\n`
      }
    );

    if (result?.pid) {
      const { pollExecStatus } = require('../../utils/script-executor');
      const execResult = await pollExecStatus(vm.node, vm.vm_id, result.pid, 10000);
      return res.json({ log: execResult.stdout || 'No output' });
    }
    res.json({ log: 'Could not read progress' });
  } catch (e) {
    res.json({ log: `Error: ${e.message}` });
  }
});


// ============================================================================
// VULN ASSET LIST
// ============================================================================

router.get('/vuln-asset-list', authenticateToken, adminOnly, async (req, res) => {
  try {
    const assetsDir = require('path').join(__dirname, '../../../vuln-assets');
    const files = require('fs').readdirSync(assetsDir)
      .filter(f => !f.startsWith('.') && f !== 'download-assets.ps1')
      .map(f => {
        const stat = require('fs').statSync(require('path').join(assetsDir, f));
        return { name: f, size_mb: (stat.size / 1048576).toFixed(1), size_bytes: stat.size };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
    res.json(files);
  } catch (e) {
    res.json([]);
  }
});

module.exports = router;
