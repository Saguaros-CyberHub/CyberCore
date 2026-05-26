/**
 * ============================================================================
 * User Workstations
 * Self-service workstation VMs: browse templates, deploy, power control,
 * snapshots, and rollback. Supports both QEMU VMs and LXC containers —
 * provider_type in cybercore_template_catalog controls which API paths are used.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { proxmoxAPI, waitForTask, findTemplateNode } = require('../utils/proxmox');
const { selectBestNode } = require('../utils/node-selector');
const { guacAPI } = require('../utils/guacamole');
const { getDefaultTemplateNode } = require('../utils/site-config');
const { randomBytes } = require('crypto');
const createLogger = require('../utils/logger');
const log = createLogger('workstations');

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/** Sanitize a string to a Proxmox-safe VM/CT name: lowercase, hyphens only, max 63 chars. */
function sanitizeVmName(s) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 63);
}

/**
 * Returns the Proxmox API base path for a VM or container.
 * provider_type 'lxc' → /api2/json/nodes/{node}/lxc/{vmid}
 * anything else (or null/undefined) → /api2/json/nodes/{node}/qemu/{vmid}
 */
function vmApiBase(node, vmid, providerType) {
  const kind = providerType === 'lxc' ? 'lxc' : 'qemu';
  return `/api2/json/nodes/${node}/${kind}/${vmid}`;
}

/** Verify caller owns this workstation VM; returns the vm row or throws. */
async function getOwnedWorkstation(userId, vmId) {
  const result = await cybercoreQuery(`
    SELECT
      vi.vm_instance_id,
      vi.provider_node,
      vi.provider_vmid,
      vi.power_state,
      vi.metadata        AS vi_metadata,
      r.resource_id,
      r.name             AS vm_name,
      r.module_key,
      r.status           AS resource_status,
      r.metadata->>'provider_type' AS provider_type
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

/**
 * Fetch the first non-loopback IPv4 from the Proxmox guest agent or LXC interfaces API.
 * Polls with retries to wait for the guest agent to come online after boot.
 */
async function getVmIp(node, vmid, providerType, retries = 12, delayMs = 10000) {
  for (let i = 0; i < retries; i++) {
    try {
      if (providerType === 'lxc') {
        const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${node}/lxc/${vmid}/interfaces`);
        for (const iface of (Array.isArray(ifaces) ? ifaces : [])) {
          if (iface.name === 'lo') continue;
          const ip = (iface.inet || '').split('/')[0];
          if (ip && !ip.startsWith('127.') && !ip.startsWith('169.254.')) return ip;
        }
      } else {
        const data = await proxmoxAPI('GET', `/api2/json/nodes/${node}/qemu/${vmid}/agent/network-get-interfaces`);
        const ifaces = data?.result || (Array.isArray(data) ? data : []);
        for (const iface of ifaces) {
          if (iface.name === 'lo') continue;
          for (const addr of (iface['ip-addresses'] || [])) {
            const ip = addr['ip-address'];
            if (addr['ip-address-type'] === 'ipv4' && ip &&
                !ip.startsWith('127.') && !ip.startsWith('169.254.')) {
              return ip;
            }
          }
        }
      }
    } catch (_) {}
    if (i < retries - 1) await new Promise(r => setTimeout(r, delayMs));
  }
  return null;
}

/** Get next available VMID >= 800000 (keeps workstation VMIDs in a distinct high range). */
async function nextVmId() {
  const data = await proxmoxAPI('GET', '/api2/json/cluster/nextid?vmid=800000');
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
    // No ?type=vm filter — that returns both qemu and lxc in Proxmox
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const byVmid = {};
    for (const r of (resources || [])) byVmid[String(r.vmid)] = r;

    const updates = [];
    for (const row of rows) {
      // Skip VMs still being provisioned — background deploy task owns their state
      if (row.power_state === 'deploying' || !row.provider_vmid) continue;
      const r = byVmid[String(row.provider_vmid)];
      if (!r) continue;
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
    log.warn('Proxmox state sync failed, using cached states:', err.message);
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
        provider_type,
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
    log.error('GET /templates error:', err.message);
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
        r.metadata->>'provider_type'               AS provider_type,
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

    const synced = await syncPowerStates(result.rows);

    const vms = synced.map(r => ({
      vmId:         r.vm_id,
      name:         r.vm_name,
      moduleKey:    r.module_key,
      powerState:   r.power_state || 'unknown',
      providerType: r.provider_type || 'qemu',
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
    log.error('GET /mine error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/workstations/:vmId/status
// Live power state for a single VM — queries Proxmox and updates the DB.
// ──────────────────────────────────────────────────────────────────────────────
router.get('/:vmId/status', authenticateToken, async (req, res) => {
  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const status = await proxmoxAPI(
      'GET',
      `${vmApiBase(vm.provider_node, vm.provider_vmid, vm.provider_type)}/status/current`
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
    log.error('GET /status error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /api/workstations/:templateId/deploy
// Validates, creates DB records immediately, responds 202, then clones/starts
// in the background — same non-blocking pattern as DELETE.
// ──────────────────────────────────────────────────────────────────────────────
router.post('/:templateId/deploy', authenticateToken, async (req, res) => {
  const { templateId } = req.params;
  const userId = req.user.userId;

  try {
    // 1. Fetch and validate template
    const tplRes = await cybercoreQuery(`
      SELECT id, template_key, os_name, template_vmid, node, provider_type,
             module_key, max_instances, metadata
      FROM cybercore_template_catalog
      WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'
    `, [templateId]);

    if (!tplRes.rows.length) return res.status(404).json({ error: 'Template not found' });
    const tpl = tplRes.rows[0];

    if (!tpl.template_vmid) return res.status(400).json({ error: 'Template has no Proxmox VMID configured' });
    if (!tpl.node)          return res.status(400).json({ error: 'Template has no node assigned — sync nodes in admin first' });

    const providerType = tpl.provider_type || 'qemu';

    // 2. Check max_instances
    const countRes = await cybercoreQuery(`
      SELECT COUNT(*) AS cnt FROM cybercore_resource
      WHERE (metadata->>'catalog_template_id') = $1 AND status NOT IN ('retired', 'error')
    `, [templateId]);
    if (tpl.max_instances && parseInt(countRes.rows[0].cnt, 10) >= tpl.max_instances) {
      return res.status(409).json({ error: `Max instances (${tpl.max_instances}) reached for this template` });
    }

    // 3. Validate skipLane
    if (req.body.skipLane === true && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'skipLane is restricted to admins' });
    }
    const skipLane = req.body.skipLane === true && req.user.role === 'admin';

    // 4. Build VM name now (no Proxmox calls needed for this)
    const vmName = sanitizeVmName(`wks-${tpl.template_key}-${userId.slice(0, 8)}`);

    // 5. Create DB records immediately so the UI can show the deploying state
    const resourceRes = await cybercoreQuery(`
      INSERT INTO cybercore_resource (type, module_key, name, status, metadata)
      VALUES ('vm', $1, $2, 'provisioning', $3::jsonb)
      RETURNING resource_id
    `, [
      tpl.module_key || null,
      vmName,
      JSON.stringify({
        vm_category:         'workstation',
        provider_type:       providerType,
        catalog_template_id: templateId,
        template_name:       tpl.os_name,
        template_key:        tpl.template_key,
        ...(skipLane ? { dev_deploy: true, network_mode: 'local_dev' } : {}),
      }),
    ]);
    const resourceId = resourceRes.rows[0].resource_id;

    const vmRes = await cybercoreQuery(`
      INSERT INTO cybercore_vm_instance
        (resource_id, provider, power_state)
      VALUES ($1, 'proxmox', 'deploying')
      RETURNING vm_instance_id
    `, [resourceId]);
    const vmId = vmRes.rows[0].vm_instance_id;

    await cybercoreQuery(`
      INSERT INTO cybercore_allocation (resource_id, user_id, purpose)
      VALUES ($1, $2, 'workstation')
    `, [resourceId, userId]);

    // 6. Respond immediately — client shows "Deploying…" card
    res.status(202).json({ success: true, vmId, name: vmName, providerType });

    // 7. Clone + start in background
    (async () => {
      try {
        const templateNode = await findTemplateNode(
          tpl.template_vmid,
          tpl.node || getDefaultTemplateNode()
        );
        const bestNodeInfo = await selectBestNode();
        const bestNode     = bestNodeInfo.node;
        const newVmid      = await nextVmId();

        log.info(`Deploying ${tpl.template_vmid} (${providerType}) ${templateNode} → ${bestNode} VMID ${newVmid} "${vmName}"${skipLane ? ' [DEV]' : ''}`);

        const cloneBody = providerType === 'lxc'
          ? { newid: newVmid, hostname: vmName, full: 1, target: bestNode,
              description: `Workstation: ${tpl.os_name}\nUser: ${userId}\nTemplate: ${tpl.template_key}` }
          : { newid: newVmid, name: vmName, full: 1, target: bestNode,
              description: `Workstation: ${tpl.os_name}\nUser: ${userId}\nTemplate: ${tpl.template_key}` };

        const cloneUpid = await proxmoxAPI(
          'POST',
          `${vmApiBase(templateNode, tpl.template_vmid, providerType)}/clone`,
          cloneBody
        );
        // Cloning large templates can take 5–10 minutes — give it plenty of headroom
        await waitForTask(templateNode, cloneUpid, 600000);

        if (skipLane) {
          log.warn(`DEV DEPLOY by admin ${userId} — overriding net0 to vmbr0`);
          const net0Value = providerType === 'lxc'
            ? 'name=eth0,bridge=vmbr0,firewall=0'
            : 'virtio,bridge=vmbr0,firewall=0';
          await proxmoxAPI('PUT', `${vmApiBase(bestNode, newVmid, providerType)}/config`, { net0: net0Value });
        }

        // Update DB with real Proxmox location now that clone succeeded
        await cybercoreQuery(`
          UPDATE cybercore_vm_instance
             SET provider_node = $1, provider_vmid = $2
           WHERE vm_instance_id = $3
        `, [bestNode, String(newVmid), vmId]);
        await cybercoreQuery(`
          UPDATE cybercore_resource SET status = 'allocated', updated_at = now()
           WHERE resource_id = $1
        `, [resourceId]);

        // Start VM/CT
        try {
          const startUpid = await proxmoxAPI(
            'POST',
            `${vmApiBase(bestNode, newVmid, providerType)}/status/start`
          );
          await waitForTask(bestNode, startUpid);
        } catch (startErr) {
          log.warn(`Start after clone had a warning: ${startErr.message}`);
        }

        await cybercoreQuery(`
          UPDATE cybercore_vm_instance
             SET power_state = 'running', started_at = now()
           WHERE vm_instance_id = $1
        `, [vmId]);

        log.info(`Workstation deployed and running`, { vmId, vmid: newVmid, node: bestNode });

        // Create Guacamole RDP connection if Guacamole is enabled
        if (process.env.GUAC_ENABLED === 'true') {
          try {
            const vmIp = await getVmIp(bestNode, newVmid, providerType);
            if (vmIp) {
              const rdpUser = tpl.metadata?.default_rdp_user || null;
              const rdpPass = tpl.metadata?.default_rdp_pass || null;
              const conn = await guacAPI('POST', '/connections', {
                name: vmName,
                protocol: 'rdp',
                parentIdentifier: 'ROOT',
                parameters: {
                  hostname: vmIp,
                  port: '3389',
                  ...(rdpUser ? { username: rdpUser } : {}),
                  ...(rdpPass ? { password: rdpPass } : {}),
                  security: 'any',
                  'ignore-cert': 'true',
                  'enable-wallpaper': 'true',
                  'enable-theming': 'true',
                  'enable-font-smoothing': 'true',
                  'color-depth': '24',
                  'resize-method': 'display-update',
                },
                attributes: { 'max-connections': '5', 'max-connections-per-user': '2' },
              });
              const connId = conn?.identifier;
              if (connId) {
                await cybercoreQuery(
                  `UPDATE cybercore_vm_instance
                      SET metadata = jsonb_set(COALESCE(metadata, '{}'), '{guac_connection_id}', $1::jsonb)
                    WHERE vm_instance_id = $2`,
                  [JSON.stringify(connId), vmId]
                );
                // Grant the deploying user READ access to this connection
                try {
                  const userRes = await cybercoreQuery(
                    'SELECT email FROM cybercore_user WHERE user_id = $1', [userId]
                  );
                  const userEmail = userRes.rows[0]?.email;
                  if (userEmail) {
                    try {
                      await guacAPI('POST', '/users', {
                        username: userEmail,
                        password: randomBytes(24).toString('hex'),
                        attributes: {},
                      });
                    } catch (_) { /* user may already exist in Guacamole */ }
                    await guacAPI('PATCH', `/users/${encodeURIComponent(userEmail)}/permissions`, [
                      { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' },
                    ]);
                  }
                } catch (permErr) {
                  log.warn(`Could not grant Guac permissions for ${vmName}: ${permErr.message}`);
                }
                log.info(`Guacamole connection ${connId} created for ${vmName} (${vmIp})`, { vmId });
              }
            } else {
              log.warn(`VM ${vmName} IP not available after 2 min — Guac connection skipped`, { vmId });
            }
          } catch (guacErr) {
            log.warn(`Guacamole setup failed for ${vmName}: ${guacErr.message}`, { vmId });
          }
        }

      } catch (err) {
        log.error(`Background deploy failed for ${vmId}: ${err.message}`, err);
        await cybercoreQuery(`
          UPDATE cybercore_vm_instance SET power_state = 'failed' WHERE vm_instance_id = $1
        `, [vmId]).catch(() => {});
        await cybercoreQuery(`
          UPDATE cybercore_resource SET status = 'error', updated_at = now() WHERE resource_id = $1
        `, [resourceId]).catch(() => {});
      }
    })();

  } catch (err) {
    log.error('Deploy error:', err.message);
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
      `${vmApiBase(vm.provider_node, vm.provider_vmid, vm.provider_type)}/status/${action}`
    );

    const newState = action === 'start' ? 'running'
                   : (action === 'stop' || action === 'shutdown') ? 'stopped'
                   : 'running';
    await cybercoreQuery(
      `UPDATE cybercore_vm_instance SET power_state = $1, last_state_change = now() WHERE vm_instance_id = $2`,
      [newState, req.params.vmId]
    );

    res.json({ success: true, action, upid });
  } catch (err) {
    log.error(`Action ${action} error:`, err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/workstations/:vmId/snapshots
// ──────────────────────────────────────────────────────────────────────────────
router.get('/:vmId/snapshots', authenticateToken, async (req, res) => {
  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const data = await proxmoxAPI(
      'GET',
      `${vmApiBase(vm.provider_node, vm.provider_vmid, vm.provider_type)}/snapshot`
    );
    const snapshots = (data.data || data || []).filter(s => s.name !== 'current');
    res.json({ snapshots });
  } catch (err) {
    log.error('GET /snapshots error:', err.message);
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
      `${vmApiBase(vm.provider_node, vm.provider_vmid, vm.provider_type)}/snapshot`,
      { snapname: name, description: description || '' }
    );
    await waitForTask(vm.provider_node, upid);
    res.json({ success: true, snapname: name });
  } catch (err) {
    log.error('POST /snapshot error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /api/workstations/:vmId/rollback
// Roll back VM/CT to a snapshot. Body: { snapname }
// ──────────────────────────────────────────────────────────────────────────────
router.post('/:vmId/rollback', authenticateToken, async (req, res) => {
  const { snapname } = req.body;
  if (!snapname) return res.status(400).json({ error: 'snapname is required' });

  try {
    const vm = await getOwnedWorkstation(req.user.userId, req.params.vmId);
    const upid = await proxmoxAPI(
      'POST',
      `${vmApiBase(vm.provider_node, vm.provider_vmid, vm.provider_type)}/snapshot/${encodeURIComponent(snapname)}/rollback`
    );
    await waitForTask(vm.provider_node, upid);
    await cybercoreQuery(
      `UPDATE cybercore_vm_instance SET power_state = 'stopped', last_state_change = now() WHERE vm_instance_id = $1`,
      [req.params.vmId]
    );
    res.json({ success: true, snapname });
  } catch (err) {
    log.error('POST /rollback error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /api/workstations/:vmId
// Destroy and deregister a user's workstation VM/CT.
// ──────────────────────────────────────────────────────────────────────────────
router.delete('/:vmId', authenticateToken, async (req, res) => {
  const vmId   = req.params.vmId;
  const userId = req.user.userId;

  let vm;
  try {
    vm = await getOwnedWorkstation(userId, vmId);
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }

  const providerType = vm.provider_type || 'qemu';

  await cybercoreQuery(
    `UPDATE cybercore_vm_instance SET power_state = 'deleting' WHERE vm_instance_id = $1`,
    [vmId]
  );
  await cybercoreQuery(
    `UPDATE cybercore_resource SET status = 'deleting', updated_at = now() WHERE resource_id = $1`,
    [vm.resource_id]
  );

  res.json({ success: true, status: 'deleting' });

  (async () => {
    try {
      try {
        const stopUpid = await proxmoxAPI(
          'POST',
          `${vmApiBase(vm.provider_node, vm.provider_vmid, providerType)}/status/stop`,
          { timeout: 30 }
        );
        await waitForTask(vm.provider_node, stopUpid, 45000);
      } catch (stopErr) {
        log.warn(`Stop before delete did not complete cleanly (proceeding): ${stopErr.message}`);
      }

      try {
        const delUpid = await proxmoxAPI(
          'DELETE',
          `${vmApiBase(vm.provider_node, vm.provider_vmid, providerType)}?purge=1`
        );
        if (typeof delUpid === 'string' && delUpid.startsWith('UPID:')) {
          await waitForTask(vm.provider_node, delUpid, 180000);
        }
      } catch (delErr) {
        log.warn(`Proxmox delete returned an error (marking destroyed anyway): ${delErr.message}`);
      }

      await cybercoreQuery(
        `UPDATE cybercore_vm_instance SET destroyed_at = now(), power_state = 'stopped' WHERE vm_instance_id = $1`,
        [vmId]
      );
      await cybercoreQuery(
        `UPDATE cybercore_resource SET status = 'retired', updated_at = now() WHERE resource_id = $1`,
        [vm.resource_id]
      );
      await cybercoreQuery(
        `UPDATE cybercore_allocation SET ends_at = now()
         WHERE resource_id = $1 AND user_id = $2 AND (ends_at IS NULL OR ends_at > NOW())`,
        [vm.resource_id, userId]
      );

      // Clean up Guacamole connection
      const guacConnId = vm.vi_metadata?.guac_connection_id;
      if (guacConnId && process.env.GUAC_ENABLED === 'true') {
        try {
          await guacAPI('DELETE', `/connections/${encodeURIComponent(guacConnId)}`);
          log.info(`Guacamole connection ${guacConnId} deleted`, { vmId });
        } catch (guacErr) {
          log.warn(`Guac cleanup failed for ${vmId}: ${guacErr.message}`);
        }
      }

      log.info(`Workstation destroyed`, { vmId, node: vm.provider_node, vmid: vm.provider_vmid, providerType });

    } catch (err) {
      log.error(`Background delete failed for ${vmId}: ${err.message}`, err);
      await cybercoreQuery(
        `UPDATE cybercore_vm_instance SET destroyed_at = now(), power_state = 'stopped' WHERE vm_instance_id = $1`,
        [vmId]
      ).catch(() => {});
      await cybercoreQuery(
        `UPDATE cybercore_resource SET status = 'retired', updated_at = now() WHERE resource_id = $1`,
        [vm.resource_id]
      ).catch(() => {});
    }
  })();
});

module.exports = router;
