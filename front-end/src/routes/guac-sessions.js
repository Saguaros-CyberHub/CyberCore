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
const { guacAPI, GUAC_DS } = require('../utils/guacamole');

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

// ============================================================================
// GET /api/dashboard/vms
// Returns VMs that the requesting user is authorized to access.
// Admins/instructors see all VMs with a guac_connection_id; regular users see
// only VMs they have an active cybercore_allocation for.
// ============================================================================
router.get('/vms', authenticateToken, async (req, res) => {
  if (!GUAC_ENABLED) {
    return res.json({ vms: [] });
  }

  try {
    const userId = req.user.userId;
    const isPrivileged = ['admin', 'instructor'].includes(req.user.role);
    let result;

    if (isPrivileged) {
      result = await cybercoreQuery(`
        SELECT
          vi.vm_instance_id        AS id,
          r.name,
          r.module_key,
          r.status                 AS resource_status,
          vi.power_state,
          vi.metadata->>'guac_connection_id' AS guac_connection_id
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
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
    }));

    res.json({ vms });
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
          vi.provider_vmid,
          r.name,
          r.module_key,
          r.status AS resource_status
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        WHERE vi.vm_instance_id = $1
          AND vi.destroyed_at IS NULL
          AND r.status != 'retired'
      `, [vmId]);
      vmRow = r.rows[0];
    } else {
      // Require an active allocation linking this user to this VM.
      const r = await cybercoreQuery(`
        SELECT
          vi.vm_instance_id,
          vi.power_state,
          vi.metadata,
          vi.provider_vmid,
          r.name,
          r.module_key,
          r.status        AS resource_status,
          a.metadata      AS alloc_metadata
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        JOIN cybercore_allocation a
          ON  a.resource_id = r.resource_id
          AND a.user_id     = $1
          AND (a.ends_at IS NULL OR a.ends_at > NOW())
        WHERE vi.vm_instance_id = $2
          AND vi.destroyed_at IS NULL
          AND r.status != 'retired'
      `, [userId, vmId]);
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

    res.json({ launchUrl: buildLaunchUrl(connId) });
  } catch (err) {
    console.error('[guac-sessions] POST /vms/:vmId/guac-session error:', err.message);
    res.status(500).json({ error: 'Failed to create console session.' });
  }
});

module.exports = router;
