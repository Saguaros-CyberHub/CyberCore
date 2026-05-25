/**
 * ============================================================================
 * User Workstations
 * Self-service workstation VMs: browse templates, deploy, power control,
 * snapshots, and rollback. Only QEMU VMs registered as workstations are
 * controllable — lane gateways (LXC) are never exposed here.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { proxmoxAPI, waitForTask, findTemplateNode } = require('../utils/proxmox');
const { selectBestNode } = require('../utils/node-selector');
const { getDefaultTemplateNode } = require('../utils/site-config');

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/** Sanitize a string to a Proxmox-safe VM name: lowercase, hyphens only, max 63 chars. */
function sanitizeVmName(s) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 63);
}

/** Verify caller owns this workstation VM; returns the vm row or throws. */
async function getOwnedWorkstation(userId, vmId) {
  const result = await cybercoreQuery(`
    SELECT
      vi.vm_instance_id,
      vi.provider_node,
      vi.provider_vmid,
      vi.power_state,
      vi.metadata,
      r.resource_id,
      r.name         AS vm_name,
      r.module_key,
      r.status       AS resource_status
    FROM cybercore_vm_instance vi
    JOIN cybercore_resource r ON r.resource_id = vi.resource_id
    JOIN cybercore_allocation a
      ON  a.resource_id = r.resource_id
      AND a.user_id     = $1
      AND (a.ends_at IS NULL OR a.ends_at > NOW())
    WHERE vi.vm_instance_id = $2
      AND vi.destroyed_at   IS NULL
      AND (r.metadata->>'vm_category') = 'workstation'
  `, [userId, vmId]);

  if (!result.rows.length) throw Object.assign(new Error('Workstation not found or not yours'), { status: 404 });
  return result.rows[0];
}

/** Get next available VMID from Proxmox cluster. */
async function nextVmId() {
  const data = await proxmoxAPI('GET', '/api2/json/cluster/nextid');
  return parseInt(data.data ?? data, 10);
}

/**
 * Bulk-sync power_state for a list of vm_instance rows using a single
 * cluster/resources call.  Updates the DB in parallel; never throws — errors
 * are swallowed so callers always get a response even if Proxmox is unreachable.
 * Returns the same rows with power_state patched to the live value.
 */
async function syncPowerStates(rows) {
  if (!rows.length) return rows;
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const byVmid = {};
    for (const r of (resources || [])) byVmid[String(r.vmid)] = r;

    const now = new Date().toISOString();
    const updates = [];
    for (const row of rows) {
      const r = byVmid[String(row.provider_vmid)];
      if (!r) continue;
      // Proxmox reports 'running' or 'stopped'; surface anything else as-is
      const live = r.status === 'running' ? 'running' : r.status === 'stopped' ? 'stopped' : r.status;
      if (live !== row.power_state) {
        updates.push(cybercoreQuery(
          `UPDATE cybercore_vm_instance
             SET power_state = $1, last_seen_at = now(), last_state_change = now()
           WHERE vm_instance_id = $2`,
          [live, row.vm_instance_id]
        ));
        row.power_state = live;
      } else {
        updates.push(cybercoreQuery(
          `UPDATE cybercore_vm_instance SET last_seen_at = now() WHERE vm_instance_id = $1`,
          [row.vm_instance_id]
        ));
      }
    }
    await Promise.allSettled(updates);
  } catch (err) {
    console.warn('[workstations] Proxmox state sync failed, using cached states:', err.message);
  }
  return rows;
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/workstations/templates
// List active workstation templates visible to all authenticated users.
// ──────────────────────────────────────────────────────────────────────────────
router.get('/templates', authenticateToken, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        id              AS template_id,
        template_key,
        os_name         AS name,
        description,
        os_family,
        os_version,
        template_vmid,
        node,
        module_key,
        max_instances,
        metadata
      FROM cybercore_template_catalog
      WHERE template_type = 'workstation'
        AND is_active     = TRUE
        AND status        = 'active'
      ORDER BY os_name ASC
    `);
    res.json({ templates: result.rows });
  } catch (err) {
    console.error('[workstations] GET /templates error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/workstations/mine
// List the requesting user's deployed workstation VMs.
// ──────────────────────────────────────────────────────────────────────────────
router.get('/mine', authenticateToken, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        vi.vm_instance_id                         AS vm_instance_id,
        vi.vm_instance_id                         AS vm_id,
        r.name                                     AS vm_name,
        r.module_key,
        r.status                                   AS resource_status,
        vi.power_state,
        vi.provider_node,
        vi.provider_vmid,
        vi.created_at,
        vi.last_seen_at,
        r.metadata->>'template_name'               AS template_name,
        r.metadata->>'dev_deploy'                  AS dev_deploy,
        r.metadata->>'guac_connection_id'          AS guac_connection_id,
        vi.metadata->>'guac_connection_id'         AS guac_connection_id_vi
      FROM cybercore_vm_instance vi
      JOIN cybercore_resource r ON r.resource_id = vi.resource_id
      JOIN cybercore_allocation a
        ON  a.resource_id = r.resource_id
        AND a.user_id     = $1
        AND (a.ends_at IS NULL OR a.ends_at > NOW())
      WHERE vi.destroyed_at IS NULL
        AND (r.metadata->>'vm_category') = 'workstation'
      ORDER BY vi.created_at DESC
    `, [req.user.userId]);

    // Sync live power_state from Proxmox (single cluster/resources call)
    const synced = await syncPowerStates(result.rows);

    const vms = synced.map(r => ({
      vmId:         r.vm_id,
      name:         r.vm_name,
      moduleKey:    r.module_key,
      powerState:   r.power_state || 'unknown',
      node:         r.provider_node,
      vmid:         r.provider_vmid,
      templateName: r.template_name,
      devDeploy:    r.dev_deploy === 'true',
      createdAt:    r.created_at,
      lastSeenAt:   r.last_seen_at,
      hasConsole:   !!(r.guac_connection_id || r.guac_connection_id_vi),
    }));

    res.json({ vms });
  } catch (err) {
    console.error('[workstations] GET /mine error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/workstations/:vmId/status
// Live power state for a single VM — queries Proxmox and updates the DB.
// Used by the frontend to poll after power actions.
// ──────────────────────────────────────────────────────────────────────────────
router.get('/:vmId/status', authenticateToken, async (req, res) => {
  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const status = await proxmoxAPI(
      'GET',
      `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}/status/current`
    );
    const live = status.status === 'running' ? 'running'
               : status.status === 'stopped' ? 'stopped'
               : status.status || 'unknown';

    await cybercoreQuery(
      `UPDATE cybercore_vm_instance
         SET power_state       = $1,
             last_seen_at      = now(),
             last_state_change = CASE WHEN power_state != $1 THEN now() ELSE last_state_change END
       WHERE vm_instance_id = $2`,
      [live, req.params.vmId]
    );

    res.json({
      vmId:       req.params.vmId,
      powerState: live,
      uptime:     status.uptime ?? null,
      cpu:        status.cpu    ?? null,
      mem:        status.mem    ?? null,
      maxmem:     status.maxmem ?? null,
    });
  } catch (err) {
    console.error('[workstations] GET /status error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /api/workstations/:templateId/deploy
// Clone the template, register in DB, allocate to user, start the VM.
// ──────────────────────────────────────────────────────────────────────────────
router.post('/:templateId/deploy', authenticateToken, async (req, res) => {
  const { templateId } = req.params;
  const userId = req.user.userId;

  try {
    // 1. Fetch template
    const tplRes = await cybercoreQuery(`
      SELECT id, template_key, os_name, template_vmid, node, module_key, max_instances, metadata
      FROM cybercore_template_catalog
      WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'
    `, [templateId]);

    if (!tplRes.rows.length) return res.status(404).json({ error: 'Template not found' });
    const tpl = tplRes.rows[0];

    if (!tpl.template_vmid) return res.status(400).json({ error: 'Template has no Proxmox VMID configured' });
    if (!tpl.node)          return res.status(400).json({ error: 'Template has no node assigned — sync nodes in admin first' });

    // 2. Check max_instances across all users for this template
    const countRes = await cybercoreQuery(`
      SELECT COUNT(*) AS cnt
      FROM cybercore_resource
      WHERE (metadata->>'catalog_template_id') = $1
        AND status != 'retired'
    `, [templateId]);
    const currentCount = parseInt(countRes.rows[0].cnt, 10);
    if (tpl.max_instances && currentCount >= tpl.max_instances) {
      return res.status(409).json({ error: `Max instances (${tpl.max_instances}) reached for this template` });
    }

    // skipLane: admin-only dev flag — deploys on vmbr0 with no lane/VLAN isolation
    if (req.body.skipLane === true && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'skipLane is restricted to admins' });
    }
    const skipLane = req.body.skipLane === true && req.user.role === 'admin';

    // 3. Resolve source node (where template actually lives) and best target node
    const templateNode = await findTemplateNode(
      tpl.template_vmid,
      tpl.node || getDefaultTemplateNode()
    );
    const bestNodeInfo = await selectBestNode();
    const bestNode     = bestNodeInfo.node;
    console.log(`[workstations] Deploy node: template on ${templateNode}, placing on ${bestNode} (score ${bestNodeInfo.score})`);

    // 4. Get next VMID and build a Proxmox-safe name
    const newVmid  = await nextVmId();
    const rawName  = `wks-${tpl.template_key}-${userId.slice(0, 8)}`;
    const vmName   = sanitizeVmName(rawName);

    console.log(`[workstations] Cloning ${tpl.template_vmid} (${templateNode}) → ${newVmid} "${vmName}" on ${bestNode}${skipLane ? ' [DEV: skipLane]' : ''}`);
    const cloneUpid = await proxmoxAPI(
      'POST',
      `/api2/json/nodes/${templateNode}/qemu/${tpl.template_vmid}/clone`,
      {
        newid:       newVmid,
        name:        vmName,
        full:        1,
        target:      bestNode,
        description: `Workstation: ${tpl.os_name}\nUser: ${userId}\nTemplate: ${tpl.template_key}`,
      }
    );
    await waitForTask(templateNode, cloneUpid);

    // 4b. Dev mode: rewire network to local bridge, bypassing lane VLAN isolation
    if (skipLane) {
      console.warn(`[workstations] DEV DEPLOY by admin ${userId} — overriding net0 to vmbr0 (no lane isolation)`);
      await proxmoxAPI(
        'PUT',
        `/api2/json/nodes/${bestNode}/qemu/${newVmid}/config`,
        { net0: 'virtio,bridge=vmbr0,firewall=0' }
      );
    }

    // 5. Create DB records
    const resourceRes = await cybercoreQuery(`
      INSERT INTO cybercore_resource (type, module_key, name, status, metadata)
      VALUES ('vm', $1, $2, 'allocated', $3::jsonb)
      RETURNING resource_id
    `, [
      tpl.module_key || null,
      vmName,
      JSON.stringify({
        vm_category:         'workstation',
        catalog_template_id: templateId,
        template_name:       tpl.os_name,
        template_key:        tpl.template_key,
        deploy_node:         bestNode,
        ...(skipLane ? { dev_deploy: true, network_mode: 'local_dev' } : {}),
      }),
    ]);
    const resourceId = resourceRes.rows[0].resource_id;

    await cybercoreQuery(`
      INSERT INTO cybercore_vm_instance
        (resource_id, provider, provider_node, provider_vmid, power_state)
      VALUES ($1, 'proxmox', $2, $3, 'stopped')
    `, [resourceId, bestNode, String(newVmid)]);

    await cybercoreQuery(`
      INSERT INTO cybercore_allocation (resource_id, user_id, purpose)
      VALUES ($1, $2, 'workstation')
    `, [resourceId, userId]);

    // 6. Start the VM
    try {
      const startUpid = await proxmoxAPI(
        'POST',
        `/api2/json/nodes/${bestNode}/qemu/${newVmid}/status/start`
      );
      await waitForTask(bestNode, startUpid);
      await cybercoreQuery(
        `UPDATE cybercore_vm_instance SET power_state = 'running', started_at = now() WHERE resource_id = $1`,
        [resourceId]
      );
    } catch (startErr) {
      console.warn(`[workstations] VM started with warning: ${startErr.message}`);
    }

    // Return the newly created VM id
    const vmRes = await cybercoreQuery(
      `SELECT vm_instance_id FROM cybercore_vm_instance WHERE resource_id = $1`,
      [resourceId]
    );

    res.status(201).json({
      success: true,
      vmId: vmRes.rows[0].vm_instance_id,
      name: vmName,
      node: bestNode,
      vmid: newVmid,
    });
  } catch (err) {
    console.error('[workstations] Deploy error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /api/workstations/:vmId/action
// Power actions: start | stop | reboot | shutdown
// ──────────────────────────────────────────────────────────────────────────────
router.post('/:vmId/action', authenticateToken, async (req, res) => {
  const ALLOWED_ACTIONS = ['start', 'stop', 'reboot', 'shutdown'];
  const { action } = req.body;

  if (!ALLOWED_ACTIONS.includes(action)) {
    return res.status(400).json({ error: `action must be one of: ${ALLOWED_ACTIONS.join(', ')}` });
  }

  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);

    if (!vm.provider_node || !vm.provider_vmid) {
      return res.status(400).json({ error: 'VM has no Proxmox location recorded' });
    }

    const upid = await proxmoxAPI(
      'POST',
      `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}/status/${action}`
    );

    // Update power_state optimistically; don't await full task to keep response fast
    const newState = action === 'start' ? 'running' : (action === 'stop' || action === 'shutdown') ? 'stopped' : 'running';
    await cybercoreQuery(
      `UPDATE cybercore_vm_instance SET power_state = $1, last_state_change = now() WHERE vm_instance_id = $2`,
      [newState, req.params.vmId]
    );

    res.json({ success: true, action, upid });
  } catch (err) {
    console.error(`[workstations] Action ${action} error:`, err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/workstations/:vmId/snapshots
// List all snapshots for the VM.
// ──────────────────────────────────────────────────────────────────────────────
router.get('/:vmId/snapshots', authenticateToken, async (req, res) => {
  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const data = await proxmoxAPI(
      'GET',
      `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}/snapshot`
    );
    // Filter out the implicit 'current' node
    const snapshots = (data.data || data || []).filter(s => s.name !== 'current');
    res.json({ snapshots });
  } catch (err) {
    console.error('[workstations] GET /snapshots error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /api/workstations/:vmId/snapshot
// Create a new snapshot. Body: { name, description }
// ──────────────────────────────────────────────────────────────────────────────
router.post('/:vmId/snapshot', authenticateToken, async (req, res) => {
  const { name, description } = req.body;
  if (!name || !/^[a-zA-Z0-9_-]{1,40}$/.test(name)) {
    return res.status(400).json({ error: 'Snapshot name must be 1–40 alphanumeric/dash/underscore characters' });
  }

  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const upid = await proxmoxAPI(
      'POST',
      `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}/snapshot`,
      { snapname: name, description: description || '' }
    );
    await waitForTask(vm.provider_node, upid);
    res.json({ success: true, snapname: name });
  } catch (err) {
    console.error('[workstations] POST /snapshot error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /api/workstations/:vmId/rollback
// Roll back VM to a snapshot. Body: { snapname }
// ──────────────────────────────────────────────────────────────────────────────
router.post('/:vmId/rollback', authenticateToken, async (req, res) => {
  const { snapname } = req.body;
  if (!snapname) return res.status(400).json({ error: 'snapname is required' });

  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const upid = await proxmoxAPI(
      'POST',
      `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}/snapshot/${encodeURIComponent(snapname)}/rollback`
    );
    await waitForTask(vm.provider_node, upid);
    await cybercoreQuery(
      `UPDATE cybercore_vm_instance SET power_state = 'stopped', last_state_change = now() WHERE vm_instance_id = $1`,
      [req.params.vmId]
    );
    res.json({ success: true, snapname });
  } catch (err) {
    console.error('[workstations] POST /rollback error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /api/workstations/:vmId
// Destroy and deregister a user's workstation VM.
// ──────────────────────────────────────────────────────────────────────────────
router.delete('/:vmId', authenticateToken, async (req, res) => {
  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);

    // Stop VM first (ignore errors — it may already be stopped)
    try {
      const stopUpid = await proxmoxAPI(
        'POST',
        `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}/status/stop`,
        { timeout: 30 }
      );
      await waitForTask(vm.provider_node, stopUpid, 35000);
    } catch (_) {}

    // Delete from Proxmox (purge=1 removes disks; skiplock omitted — requires root)
    await proxmoxAPI(
      'DELETE',
      `/api2/json/nodes/${vm.provider_node}/qemu/${vm.provider_vmid}?purge=1`
    );

    // Mark destroyed in DB and end allocation
    await cybercoreQuery(`
      UPDATE cybercore_vm_instance SET destroyed_at = now(), power_state = 'stopped'
      WHERE vm_instance_id = $1
    `, [req.params.vmId]);

    await cybercoreQuery(`
      UPDATE cybercore_resource SET status = 'retired', updated_at = now()
      WHERE resource_id = $1
    `, [vm.resource_id]);

    await cybercoreQuery(`
      UPDATE cybercore_allocation SET ends_at = now()
      WHERE resource_id = $1 AND user_id = $2 AND (ends_at IS NULL OR ends_at > NOW())
    `, [vm.resource_id, req.user.userId]);

    res.json({ success: true });
  } catch (err) {
    console.error('[workstations] DELETE error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
