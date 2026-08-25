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
const { claimsSql } = require('../utils/lane-claims');
const { authenticateToken } = require('../middleware/auth');
const { guacAPI, guacFetchText, mintGuacToken, GUAC_DS, GUAC_URL } = require('../utils/guacamole');
const { proxmoxAPI } = require('../utils/proxmox');
const { getV2LabNetwork } = require('../utils/site-config');
const { ipInCidr } = require('../utils/ipv4');
const laneCreds = require('../utils/lane-credentials');
const audit = require('../utils/audit');

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

/**
 * Is this address a lane-gateway WAN transit allocation?
 *
 * A VM with a transit leg reports that NIC alongside its real address, and the
 * transit IP is never the right RDP/VNC target for a workstation, so it is
 * deprioritized below.
 *
 * Read from config rather than the hardcoded /^100\.100\.60\./ this used to be.
 * That regex was correct only while the pool was exactly one /24: widen it to a
 * /22 and every lane at 100.100.61.x stops being recognised as transit, so this
 * function can "helpfully" rewrite a working console hostname to an address
 * guacd has no route to. Failure is delayed and looks like a Guacamole bug.
 */
function isTransitIp(ip) {
  try {
    return ipInCidr(ip, getV2LabNetwork().subnet);
  } catch (_) {
    return /^100\.100\.60\./.test(ip);   // config unreadable: the historical pool
  }
}

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
    const newIp = currentIps.find(ip => ip.startsWith(sameNet) && !isTransitIp(ip))
      || currentIps.find(ip => !isTransitIp(ip))
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
    // guacFetchText, never a bare fetch: a Guacamole blocked on the Postgres
    // container it shares with CyberCore finishes the TCP handshake and then
    // never answers, and an untimed fetch would hold this request open for
    // undici's default 300s — on the console-launch path, where the user is
    // sitting and watching a spinner.
    const { ok, text } = await guacFetchText(`${GUAC_URL}/api/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(guacUser)}&password=${encodeURIComponent(guacPassword)}`,
    }, `POST /api/tokens (console login for ${guacUser})`);
    if (!ok) return null;
    return JSON.parse(text); // { authToken, username, dataSource, availableDataSources }
  } catch (err) {
    // Returning null stays the contract — the caller falls back to an admin
    // token. But a timeout here is a Guacamole outage, not a wrong password,
    // and the fully silent catch this used to be made the two identical.
    if (err && err.code === 'GUAC_TIMEOUT') console.warn(`[guac-sessions] ${err.message}`);
    return null;
  }
}

// ============================================================================
// Display naming + OS tagging for the workspace list
// ============================================================================

/**
 * cybercore_resource.name is a uniqueness key, not a label — the deployers
 * suffix it with the owner slug and the Proxmox VMID so the same template can
 * land in N lanes without tripping the (module_key, name) UNIQUE constraint
 * (see lane-deployer.js registerWorkspaceVm). That produces strings like
 * "windows-11-base-template-echum-610446", which is not what anyone sees in
 * Proxmox.
 *
 * The Proxmox guest name, in order of trustworthiness:
 *   1. vm_instance.metadata.proxmox_name — written at clone time by the
 *      deployers. Exact, but only present on VMs deployed after that landed.
 *   2. the lane's recorded workstation hostname for this VMID — lane-deployer
 *      writes config.workstations[].hostname alongside the VMID it cloned.
 *   3. the lane name — correct for slot 0, which clones under the bare lane name.
 *   4. the resource name — already the Proxmox name for standalone workstations
 *      (routes/workstations.js clones under exactly the name it stores).
 */
function resolveDisplayName(row) {
  if (row.proxmox_name) return row.proxmox_name;

  const laneWorkstations = row.lane_config?.workstations;
  if (row.provider_vmid && Array.isArray(laneWorkstations)) {
    const match = laneWorkstations.find(w => String(w?.vmid) === String(row.provider_vmid));
    if (match?.hostname) return match.hostname;
  }
  return row.lane_name || row.name;
}

// Matched in order against the template's OS name / key / the resource name, so
// the first entry that fits wins. Distro-specific patterns must come before the
// generic family ones — os_family only distinguishes windows/linux/macos, which
// is not enough to tell Kali from Ubuntu.
const OS_PATTERNS = [
  [/kali/i,                          'kali',    'Kali'],
  [/parrot/i,                        'parrot',  'Parrot'],
  [/win(dows)?[-_ ]?server|wsrv/i,   'windows', 'Windows Server'],
  [/windows|win(10|11)|\bwin\b/i,    'windows', 'Windows'],
  [/ubuntu/i,                        'ubuntu',  'Ubuntu'],
  [/rocky|rhel|red[-_ ]?hat|centos|alma/i, 'rhel', 'RHEL'],
  [/debian/i,                        'debian',  'Debian'],
  [/metasploitable/i,                'linux',   'Metasploitable'],
  [/macos|darwin/i,                  'macos',   'macOS'],
];

const OS_FAMILY_FALLBACK = {
  windows_client: ['windows', 'Windows'],
  windows_server: ['windows', 'Windows Server'],
  linux:          ['linux',   'Linux'],
  macos:          ['macos',   'macOS'],
};

/**
 * Best-effort OS identification for the workspace card's tag. Returns null when
 * nothing recognizable is available rather than guessing — an absent tag reads
 * better than a wrong one.
 */
function resolveOs(row) {
  // Sources are tried in order and never concatenated: the resource name ends
  // in the owner's email slug, so a student named "kalib" would otherwise tag
  // their Windows box as Kali. A template field, when present, always wins.
  for (const source of [row.os_name, row.template_name, row.template_key, row.name]) {
    if (!source) continue;
    for (const [re, key, label] of OS_PATTERNS) {
      if (re.test(source)) return { key, label };
    }
  }
  const fallback = OS_FAMILY_FALLBACK[row.os_family];
  return fallback ? { key: fallback[0], label: fallback[1] } : null;
}

// ============================================================================
// Defense-in-depth for the workspace list: a lane VM (metadata.vm_category =
// 'lane_vm') should only appear while its lane still exists and is not torn
// down. Even if a teardown path forgets to delete the cybercore_resource row,
// this hides the orphaned "ghost card" the moment the cybercore_lane row is
// gone or flips to deleted/error. Non-lane VMs (workstations) are unaffected.
// Text comparison (lane_id::text) avoids casting arbitrary metadata to uuid.
const LIVE_LANE_FILTER = `(
  r.metadata->>'vm_category' IS DISTINCT FROM 'lane_vm'
  OR EXISTS (
    SELECT 1 FROM cybercore_lane l
    WHERE l.lane_id::text = r.metadata->>'lane_id'
      AND ${claimsSql('l')}
  )
)`;

// Everything resolveDisplayName/resolveOs need, shared by both scope variants so
// the two branches can't drift. The lane join is aliased `dl` because
// LIVE_LANE_FILTER already uses `l` for its own correlated subquery.
const DISPLAY_JOINS = `
  LEFT JOIN cybercore_lane dl
    ON dl.lane_id::text = r.metadata->>'lane_id'
  LEFT JOIN cybercore_template_catalog tc
    ON tc.id::text = r.metadata->>'catalog_template_id'
`;

const DISPLAY_COLUMNS = `
  vi.provider_vmid,
  vi.metadata->>'proxmox_name' AS proxmox_name,
  dl.name                      AS lane_name,
  dl.config                    AS lane_config,
  tc.os_family,
  tc.os_name,
  r.metadata->>'template_name' AS template_name,
  r.metadata->>'template_key'  AS template_key
`;

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
          ${DISPLAY_COLUMNS},
          owner.email              AS owner_email,
          owner.user_id            AS owner_id
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        ${DISPLAY_JOINS}
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
          AND ${LIVE_LANE_FILTER}
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
          )                        AS guac_connection_id,
          ${DISPLAY_COLUMNS}
        FROM cybercore_vm_instance vi
        JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        ${DISPLAY_JOINS}
        JOIN cybercore_allocation a
          ON  a.resource_id = r.resource_id
          AND a.user_id     = $1
          AND (a.ends_at IS NULL OR a.ends_at > NOW())
        WHERE r.type   = 'vm'
          AND r.status != 'retired'
          AND vi.destroyed_at IS NULL
          AND ${LIVE_LANE_FILTER}
        ORDER BY r.module_key, r.name
      `, [userId]);
    }

    const vms = result.rows.map(row => {
      const os = resolveOs(row);
      return {
        id:             row.id,
        // `name` stays the unique resource name — callers that match on it keep
        // working. `displayName` is what the UI shows.
        name:           row.name,
        displayName:    resolveDisplayName(row),
        vmid:           row.provider_vmid || null,
        osKey:          os?.key || null,
        osLabel:        os?.label || null,
        moduleKey:      row.module_key,
        powerState:     row.power_state,
        resourceStatus: row.resource_status,
        hasConsole:     !!row.guac_connection_id,
        // Whether a Credentials button should render — never the credential
        // itself. The privileged branch of this query is cluster-wide, so a
        // password here would be disclosed to every instructor on every page
        // load, unlogged. The secret is fetched per-VM below instead.
        hasCredentials: laneCreds.resolveLaneWorkstationCredential(
                          row.lane_config, row.provider_vmid).available,
        ...(showAll ? { ownerEmail: row.owner_email || null, ownerId: row.owner_id || null } : {}),
      };
    });

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
        // A FRESH admin session, never the token this process caches for its own
        // API calls — see mintGuacToken. The browser owns whatever token it is
        // given and destroys it on logout.
        const adminToken = (await mintGuacToken()).authToken;
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

// ============================================================================
// GET /api/dashboard/vms/:vmId/credentials
// The OS login for one lane workstation, so the student who owns it can read it
// back instead of asking their instructor to look it up.
//
// Guacamole types this password into the guest for them, which is exactly why
// they never learn it — and then cannot get past a locked Windows session, a
// sudo prompt, or their own RDP client.
//
// GET, not POST: strictly read-only. Nothing here mints, rotates or writes, so
// the usual objection to a state-changing GET does not apply. (The CLE
// POST /credentials route is POST because it CREATES a Guacamole account.)
//
// Authorization lives in laneCreds.getLaneWorkstationCredentialForVm and is
// deliberately tighter than the console-launch route below it: owner or admin,
// NOT `isPrivileged`. That route's instructor branch is cluster-wide with no
// course scoping, and reusing it here would let any instructor read any other
// instructor's students' machine passwords.
// ============================================================================
router.get('/vms/:vmId/credentials', authenticateToken, async (req, res) => {
  const { vmId } = req.params;

  if (!UUID_RE.test(vmId)) {
    return res.status(400).json({ error: 'Invalid VM identifier.' });
  }

  const isAdmin = req.user.role === 'admin';

  try {
    const cred = await laneCreds.getLaneWorkstationCredentialForVm(vmId, {
      userId: req.user.userId,
      isAdmin,
    });

    if (!cred) {
      // 404 rather than 403, matching the console route: a caller must not be
      // able to use this endpoint to learn which vmIds exist.
      return res.status(404).json({ error: 'VM not found or access denied.' });
    }

    // Awaited, not fire-and-forget. This is a credential disclosure, so the row
    // has to be durable before the secret leaves the process — audit.log never
    // rejects, so this cannot fail the request. audit.redact() strips anything
    // matching /pass|cred|secret|.../ from metadata, so the password cannot land
    // in the log even if a future edit passes it in.
    await audit.log({
      req,
      action: 'access.credential_viewed',
      target: { type: 'lane_credential', id: vmId, label: cred.vmName },
      targetUser: { id: cred.ownerUserId },
      metadata: {
        // `kind`, not `credential`: audit.redact() blanks any key matching
        // /cred|pass|secret|.../, so the more natural name would log as
        // '[redacted]' and cost the row the one field that says WHICH kind of
        // credential was disclosed.
        kind: 'lane_workstation',
        source: cred.source,
        available: cred.available,
        shared: cred.shared,
        on_behalf_of: !!cred.ownerUserId && cred.ownerUserId !== req.user.userId,
      },
    });

    res.json({
      vmId,
      username:  cred.username,
      password:  cred.password,
      source:    cred.source,
      available: cred.available,
      // True when this password is the template's own built-in account rather
      // than one generated for this lane — the same secret on every student's
      // machine. The UI must say so; treating it as private is how a shared
      // bake credential ends up believed to be personal.
      shared:    cred.shared,
      ...(cred.reason ? { reason: cred.reason } : {}),
    });
  } catch (err) {
    console.error('[guac-sessions] GET /vms/:vmId/credentials error:', err.message);
    res.status(500).json({ error: 'Failed to read the workstation login.' });
  }
});

module.exports = router;
