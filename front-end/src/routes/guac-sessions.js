/**
 * ============================================================================
 * GUACAMOLE SESSION ROUTES
 * Mediates access to externally-hosted Apache Guacamole for VM console
 * embedding. The backend is the authorization source of truth — the frontend
 * never receives credentials, VM IPs, or raw Guacamole connection parameters.
 *
 * Mounted at: /api/dashboard
 * Routes:
 *   GET  /vms                      — list VMs accessible to the user
 *   POST /vms/:vmId/guac-session   — authorize & return a safe iframe URL
 * ============================================================================
 */

'use strict';

const express = require('express');
const router = express.Router();
const { cybercoreQuery } = require('../utils/cybercore-db');
const { authenticateToken } = require('../middleware/auth');
const { guacAPI, getGuacToken, GUAC_DS, GUAC_URL } = require('../utils/guacamole');
const { proxmoxAPI } = require('../utils/proxmox');

const GUAC_ENABLED = process.env.GUAC_ENABLED === 'true';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ============================================================================
// Helpers
// ============================================================================

/**
 * Build the browser-loadable Guacamole iframe URL from a connection identifier.
 * Uses GUAC_PUBLIC_BASE_URL (e.g. "/guac") — the reverse-proxy path that the
 * browser can reach — rather than the internal API URL.
 */
function buildLaunchUrl(connId) {
  const base = (process.env.GUAC_PUBLIC_BASE_URL || '/guac').replace(/\/$/, '');
  // Guacamole client token: base64("<connId>\0c\0<datasource>")
  const clientToken = Buffer.from(`${connId}\0c\0${GUAC_DS}`).toString('base64');
  return `${base}/#/client/${clientToken}`;
}

/**
 * Recursively walk the Guacamole connection tree and return the identifier of
 * the first connection whose name matches. Used as a fallback when no
 * guac_connection_id is stored in metadata.
 */
function findConnectionByName(node, name) {
  if (!node) return null;
  for (const conn of node.childConnections || []) {
    if (conn.name === name) return String(conn.identifier);
  }
  for (const group of node.childConnectionGroups || []) {
    const found = findConnectionByName(group, name);
    if (found) return found;
  }
  return null;
}

/**
 * Single-attempt fetch of the VM's first non-loopback IPv4 from Proxmox.
 * Used for lazy IP refresh — no retry loop, VM is expected to already be running.
 */
async function fetchCurrentVmIps(node, vmid, providerType) {
  const ips = [];
  const usable = ip => ip && !ip.startsWith('127.') && !ip.startsWith('169.254.');
  try {
    if (providerType === 'lxc') {
      const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${node}/lxc/${vmid}/interfaces`);
      for (const iface of (Array.isArray(ifaces) ? ifaces : [])) {
        if (iface.name === 'lo') continue;
        const ip = (iface.inet || '').split('/')[0];
        if (usable(ip)) ips.push(ip);
      }
    } else {
      const data = await proxmoxAPI('GET', `/api2/json/nodes/${node}/qemu/${vmid}/agent/network-get-interfaces`);
      const ifaces = data?.result || (Array.isArray(data) ? data : []);
      for (const iface of ifaces) {
        if (iface.name === 'lo') continue;
        for (const addr of (iface['ip-addresses'] || [])) {
          const ip = addr['ip-address'];
          if (addr['ip-address-type'] === 'ipv4' && usable(ip)) ips.push(ip);
        }
      }
    }
  } catch (_) {}
  return ips;
}

// Lane-gateway WAN transit allocations live in 100.100.60.0/24. A VM with a
// transit leg reports that NIC alongside its real address; the transit IP is
// never the right RDP/VNC target for a workstation, so deprioritize it.
const TRANSIT_RANGE = /^100\.100\.60\./;

/**
 * Lazy IP refresh. Only rewrites the stored Guacamole hostname when the
 * stored IP is NO LONGER live on the VM — if it's still one of the VM's
 * current addresses (or the admin pinned a hostname via the
 * `cybercore-pin-hostname` connection attribute), leave it alone. This is
 * what stops every console launch from stomping a manually corrected
 * hostname back to whichever NIC the guest agent happens to list first.
 */
async function refreshGuacHostname(connId, currentIps) {
  try {
    if (!Array.isArray(currentIps) || currentIps.length === 0) return;
    // Parameters require a separate API call — GET /connections/:id alone returns only summary.
    const [conn, params] = await Promise.all([
      guacAPI('GET', `/connections/${connId}`),
      guacAPI('GET', `/connections/${connId}/parameters`),
    ]);
    if (!params) return;
    const storedIp = params.hostname;
    if (!storedIp) return;
    if (conn?.attributes?.['cybercore-pin-hostname'] === 'true') return;
    if (currentIps.includes(storedIp)) return;   // stored IP still valid — keep it

    // Stored IP is stale. Pick the best replacement: same /16 as the old IP
    // first, then any non-transit address, then whatever is left.
    const sameNet = storedIp.split('.').slice(0, 2).join('.') + '.';
    const newIp = currentIps.find(ip => ip.startsWith(sameNet) && !TRANSIT_RANGE.test(ip))
      || currentIps.find(ip => !TRANSIT_RANGE.test(ip))
      || currentIps[0];
    if (!newIp || newIp === storedIp) return;

    await guacAPI('PUT', `/connections/${connId}`, {
      ...conn,
      parameters: { ...params, hostname: newIp },
    });
    console.log(`[guac-sessions] Updated connection ${connId} hostname: ${storedIp} → ${newIp} (stale)`);
  } catch (err) {
    console.warn(`[guac-sessions] Could not refresh Guac hostname for ${connId}: ${err.message}`);
  }
}

/**
 * Authenticate to Guacamole as the VM's owner using the stored per-user
 * credentials, returning a scoped auth token the browser can use directly.
 * Returns null if credentials aren't stored or authentication fails.
 */
async function getUserGuacToken(guacUser, guacPassword) {
  if (!guacUser || !guacPassword) return null;
  try {
    const resp = await fetch(`${GUAC_URL}/api/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(guacUser)}&password=${encodeURIComponent(guacPassword)}`,
    });
    if (!resp.ok) return null;
    return await resp.json(); // { authToken, username, dataSource, availableDataSources }
  } catch (_) {
    return null;
  }
}

// ============================================================================
// GET /api/dashboard/vms
// Returns VMs that the requesting user is authorized to access.
// Admins/instructors see every active VM (with ownerEmail) by default. They
// can pass ?scope=mine to fall back to the per-user filter.
// Regular users always get the per-user filter regardless of query params.
// ============================================================================
router.get('/vms', authenticateToken, async (req, res) => {
  if (!GUAC_ENABLED) {
    return res.json({ vms: [] });
  }

  try {
    const userId = req.user.userId;
    const isPrivileged = ['admin', 'instructor'].includes(req.user.role);
    const showAll = isPrivileged && req.query.scope !== 'mine';
    let result;

    if (showAll) {
      // LEFT JOIN LATERAL pulls the first open allocation's user so the
      // admin UI can show who owns each VM. NULL when nobody is currently
      // allocated to the resource (rare — usually only for in-flight deploys).
      result = await cybercoreQuery(`
        SELECT
          vi.vm_instance_id        AS id,
          r.name,
          r.module_key,
          r.status                 AS resource_status,
          vi.power_state,
          vi.metadata->>'guac_connection_id' AS guac_connection_id,
          owner.email              AS owner_email,
          owner.user_id            AS owner_id
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        LEFT JOIN LATERAL (
          SELECT u.user_id, u.email
          FROM cybercore_allocation a
          JOIN cybercore_user u ON u.user_id = a.user_id
          WHERE a.resource_id = r.resource_id
            AND (a.ends_at IS NULL OR a.ends_at > NOW())
          ORDER BY a.starts_at ASC
          LIMIT 1
        ) owner ON TRUE
        WHERE r.type   = 'vm'
          AND r.status != 'retired'
          AND vi.destroyed_at IS NULL
        ORDER BY r.module_key, r.name
      `);
    } else {
      result = await cybercoreQuery(`
        SELECT
          vi.vm_instance_id        AS id,
          r.name,
          r.module_key,
          r.status                 AS resource_status,
          vi.power_state,
          COALESCE(
            vi.metadata->>'guac_connection_id',
            a.metadata->>'guac_connection_id'
          )                        AS guac_connection_id
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        JOIN cybercore_allocation a
          ON  a.resource_id = r.resource_id
          AND a.user_id     = $1
          AND (a.ends_at IS NULL OR a.ends_at > NOW())
        WHERE r.type   = 'vm'
          AND r.status != 'retired'
          AND vi.destroyed_at IS NULL
        ORDER BY r.module_key, r.name
      `, [userId]);
    }

    const vms = result.rows.map(row => ({
      id:             row.id,
      name:           row.name,
      moduleKey:      row.module_key,
      powerState:     row.power_state,
      resourceStatus: row.resource_status,
      hasConsole:     !!row.guac_connection_id,
      ...(showAll ? { ownerEmail: row.owner_email || null, ownerId: row.owner_id || null } : {}),
    }));

    res.json({ vms, scope: showAll ? 'all' : 'mine' });
  } catch (err) {
    console.error('[guac-sessions] GET /vms error:', err.message);
    res.status(500).json({ error: 'Failed to fetch VMs.' });
  }
});

// ============================================================================
// POST /api/dashboard/vms/:vmId/guac-session
// Verifies the user's access to the requested VM, resolves the Guacamole
// connection ID, and returns a safe iframe launch URL. Never exposes
// credentials, VM IPs, or raw Guacamole parameters to the frontend.
// ============================================================================
router.post('/vms/:vmId/guac-session', authenticateToken, async (req, res) => {
  if (!GUAC_ENABLED) {
    return res.status(503).json({ error: 'Remote console is not enabled on this instance.' });
  }

  const { vmId } = req.params;

  if (!UUID_RE.test(vmId)) {
    return res.status(400).json({ error: 'Invalid VM identifier.' });
  }

  const userId = req.user.userId;
  const isPrivileged = ['admin', 'instructor'].includes(req.user.role);

  try {
    let vmRow;

    if (isPrivileged) {
      const r = await cybercoreQuery(`
        SELECT
          vi.vm_instance_id,
          vi.power_state,
          vi.metadata,
          vi.provider_node,
          vi.provider_vmid,
          vi.metadata->>'provider_type' AS provider_type,
          vi.metadata->>'guac_user'     AS guac_user,
          COALESCE(
            CASE WHEN cu.guac_password IS NOT NULL
                 THEN pgp_sym_decrypt(cu.guac_password, $2)::text
            END,
            vi.metadata->>'guac_password'
          )                             AS guac_password,
          r.name,
          r.module_key,
          r.status AS resource_status,
          r.metadata->>'vm_category' AS vm_category
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        LEFT JOIN cybercore_user cu ON cu.email = (vi.metadata->>'guac_user')
        WHERE vi.vm_instance_id = $1
          AND vi.destroyed_at IS NULL
          AND r.status != 'retired'
      `, [vmId, process.env.GUAC_ENCRYPT_KEY || '']);
      vmRow = r.rows[0];
    } else {
      // Require an active allocation linking this user to this VM.
      const r = await cybercoreQuery(`
        SELECT
          vi.vm_instance_id,
          vi.power_state,
          vi.metadata,
          vi.provider_node,
          vi.provider_vmid,
          vi.metadata->>'provider_type' AS provider_type,
          vi.metadata->>'guac_user'     AS guac_user,
          COALESCE(
            CASE WHEN cu.guac_password IS NOT NULL
                 THEN pgp_sym_decrypt(cu.guac_password, $3)::text
            END,
            vi.metadata->>'guac_password'
          )                             AS guac_password,
          r.name,
          r.module_key,
          r.status        AS resource_status,
          r.metadata->>'vm_category' AS vm_category,
          a.metadata      AS alloc_metadata
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        JOIN cybercore_allocation a
          ON  a.resource_id = r.resource_id
          AND a.user_id     = $1
          AND (a.ends_at IS NULL OR a.ends_at > NOW())
        LEFT JOIN cybercore_user cu ON cu.email = (vi.metadata->>'guac_user')
        WHERE vi.vm_instance_id = $2
          AND vi.destroyed_at IS NULL
          AND r.status != 'retired'
      `, [userId, vmId, process.env.GUAC_ENCRYPT_KEY || '']);
      vmRow = r.rows[0];
    }

    if (!vmRow) {
      // 404 rather than 403 to avoid leaking whether a vmId exists.
      return res.status(404).json({ error: 'VM not found or access denied.' });
    }

    // Resolve Guacamole connection ID. Priority:
    //   1. vm_instance.metadata.guac_connection_id
    //   2. allocation.metadata.guac_connection_id (user path only)
    //   3. Guacamole API name lookup (fallback, requires GUAC_API_URL)
    let connId = vmRow.metadata?.guac_connection_id
      || vmRow.alloc_metadata?.guac_connection_id
      || null;

    if (!connId) {
      try {
        const tree = await guacAPI('GET', '/connectionGroups/ROOT/tree');
        // Try "{name}-{vmid}" first (workstation naming), then plain "{name}" (legacy/other modules)
        const qualifiedName = vmRow.provider_vmid
          ? `${vmRow.name}-${vmRow.provider_vmid}`
          : null;
        connId = (qualifiedName && findConnectionByName(tree, qualifiedName))
               || findConnectionByName(tree, vmRow.name);
      } catch (guacErr) {
        console.warn('[guac-sessions] Guacamole API fallback failed:', guacErr.message);
      }
    }

    if (!connId) {
      return res.status(404).json({
        error: 'No remote console is configured for this VM.',
      });
    }

    // Lazy IP refresh — if the VM's IP changed since the connection was
    // created, update the Guacamole connection hostname before returning the
    // URL.  Workstations are directly reachable so their guest-agent IP is
    // the correct hostname.  Lane VMs (vm_category='lane_vm') sit behind a
    // lane gateway; refreshing would overwrite the gateway WAN IP with the
    // lane-local IP, which isn't routable from outside the gateway.  Skip
    // refresh for lane VMs.
    const isLaneVm = vmRow.vm_category === 'lane_vm';
    if (!isLaneVm && vmRow.provider_node && vmRow.provider_vmid && vmRow.power_state === 'running') {
      const currentIps = await fetchCurrentVmIps(
        vmRow.provider_node,
        vmRow.provider_vmid,
        vmRow.provider_type || 'qemu'
      );
      if (currentIps.length > 0) await refreshGuacHostname(connId, currentIps);
    }

    // Authenticate to Guacamole so the browser never sees the login prompt.
    // Prefer a scoped per-user token; fall back to the admin token (CyberCore
    // already enforced authorization above, so admin-level Guac access is safe).
    // If both fail we still return the launchUrl — the client will clear any
    // stale GUAC_AUTH so the user gets a clean login prompt rather than an
    // "Invalid Login" flash from an expired cached token.
    let guacAuth = await getUserGuacToken(vmRow.guac_user, vmRow.guac_password);
    if (!guacAuth) {
      try {
        const adminToken = await getGuacToken();
        guacAuth = {
          authToken:            adminToken,
          dataSource:           GUAC_DS,
          username:             process.env.GUAC_ADMIN_USER || 'cactus-admin',
          availableDataSources: [GUAC_DS],
        };
      } catch (adminAuthErr) {
        console.warn('[guac-sessions] Admin Guacamole auth failed — returning URL without token:', adminAuthErr.message);
      }
    }

    res.json({
      launchUrl:            buildLaunchUrl(connId),
      ...(guacAuth ? {
        guacToken:            guacAuth.authToken,
        dataSource:           guacAuth.dataSource           || GUAC_DS,
        username:             guacAuth.username             || vmRow.guac_user,
        availableDataSources: guacAuth.availableDataSources || [GUAC_DS],
      } : { clearGuacAuth: true }),
    });
  } catch (err) {
    console.error('[guac-sessions] POST /vms/:vmId/guac-session error:', err.message, err.stack);
    // Admins/instructors get the real error message to make debugging tractable;
    // students get the generic fallback so we don't leak internals.
    const isPrivileged = ['admin', 'instructor'].includes(req.user.role);
    res.status(500).json({
      error: isPrivileged
        ? `Failed to create console session: ${err.message}`
        : 'Failed to create console session.'
    });
  }
});

module.exports = router;
