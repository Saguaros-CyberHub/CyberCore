/*
 * ============================================================================
 * Admin Routes - CyberHub / Guacamole Management
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { getClusterHealth, buildDeployPreview } = require('../middleware/deployment-guards');
const { generatePassword } = require('../utils/password-generator');
const { logActivity } = require('../middleware/activity-logger');
const { waitForGuestAgent, executeScriptsOnVM, getVMIPs } = require('../utils/script-executor');
const { selectBestNode } = require('../utils/node-selector');
const { runBatch, distributeAcrossNodes, createCloneSemaphore } = require('../utils/batch-deployer');
const goadDeploy = require('../utils/goad-deploy');

const adminOnly = requireRole('admin');

// ============================================================================
// LANE UPLINK CONFIG — per-module transit gateway map
// ============================================================================
// Each module has its own SDN VNet (named after the module) carrying a
// dedicated /16 to a transit-gateway LXC. The transit GW NATs upward to
// vmbr0.10 (vlan060_lab). Lane gateway LXCs attach wan0 to the module's
// bridge and use the transit's IP as their default gateway.
//
//   crucible  -> bridge 'crucible',  GW 100.102.0.1, transit LXC 612 (running)
//   cyberlabs -> bridge 'cyberlabs', GW <tbd>,        transit LXC 611 (not yet up)
//   forge     -> bridge 'forge',     GW <tbd>,        transit LXC 613 (not yet up)
//
// Add cyberlabs/forge entries here when their transit GWs are live.
const TRANSIT_BY_MODULE = {
  crucible: { bridge: 'crucible', gateway: '100.102.0.1', subnetBase: '100.102', cidr: '/16' },
};

/**
 * Compute the lane gateway LXC's wan0 config from the module + vxlan_id.
 * Maps vxlan_id (uint16) deterministically into the module's /16:
 *   high octet = (vxlan >> 8) & 0xFF, low octet = vxlan & 0xFF.
 * For vxlan 10000 in crucible: 100.102.39.16. Unique per lane up to 65535.
 */
function laneUplinkConfig(module, vxlanId) {
  const t = TRANSIT_BY_MODULE[module];
  if (!t) {
    throw new Error(`No transit gateway configured for module '${module}'. ` +
      `Configured modules: ${Object.keys(TRANSIT_BY_MODULE).join(', ')}. ` +
      `Add an entry to TRANSIT_BY_MODULE in admin.js once the transit LXC is up.`);
  }
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  return {
    bridge: t.bridge,
    ip:     `${t.subnetBase}.${high}.${low}${t.cidr}`,
    gw:     t.gateway
  };
}

// ============================================================================
// V2 LANE NETWORKING (subnet_scheme='v2')
// ============================================================================
// In v2, each lane gets a globally-unique /24 in 10.0.0.0/8 (no reuse via
// VXLAN), and the lane gateway hangs directly off the lab network bridge —
// no module transit hop. Required for Tailscale BYOAB and multi-subnet labs.
//
// Cloned from VMID 1694 (subnet-agnostic, baked by bake-lane-gateway-v2.sh).
// admin.js sets net1's IP per-deploy; the LXC's firstboot hook reads lan0 at
// boot and renders dnsmasq/iptables from it. See bake-lane-gateway-v2.sh.

const V2_LANE_GATEWAY_VMID = 1694;
const V2_LAB_NETWORK = {
  bridge: 'vmbr0',
  subnetBase: '100.100.60',   // OPNsense lab gateway is .1
  gateway: '100.100.60.1',
  cidr: '/24'
};

/**
 * Compute v2 lane gateway WAN config from vxlan_id. WAN side hangs directly
 * off the lab network (vmbr0) at 100.100.60.<offset>/24.
 *
 * Allocates from 100.100.60.10..100.100.60.249 (240 simultaneous lanes —
 * sufficient for current scale; switch to DB-tracked allocation if we exceed).
 * Deterministic from vxlan_id so re-deploys land on the same IP.
 */
function v2WanConfig(vxlanId) {
  const offset = 10 + (vxlanId % 240);
  return {
    bridge: V2_LAB_NETWORK.bridge,
    ip:     `${V2_LAB_NETWORK.subnetBase}.${offset}${V2_LAB_NETWORK.cidr}`,
    gw:     V2_LAB_NETWORK.gateway
  };
}

/**
 * Compute v2 lane LAN subnet from vxlan_id.
 * Maps uint16 vxlan_id into 10.<high>.<low>.0/24:
 *   vxlan 10000 (0x2710) → 10.39.16.0/24
 *   vxlan 10001 (0x2711) → 10.39.17.0/24
 * 65536 unique lane subnets — globally unique within the cluster.
 */
function v2LaneSubnet(vxlanId) {
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  const base3 = `10.${high}.${low}`;
  return {
    base3,                              // "10.39.16"
    cidr:      `${base3}.0/24`,         // "10.39.16.0/24"
    gatewayIp: `${base3}.1`,            // "10.39.16.1" — lane gateway's lan0
    netmask24: '255.255.255.0'
  };
}

/**
 * Resolve the gateway VMID for a deploy based on subnet scheme.
 *   v1: 1691/1692/1693 by module (existing behavior).
 *   v2: always 1694 (subnet-agnostic, module not relevant — there's no
 *       per-module transit gateway in v2).
 */
function resolveGatewayVmid(module, subnetScheme, spec) {
  if (subnetScheme === 'v2') return V2_LANE_GATEWAY_VMID;
  const v1Map = { cyberlabs: 1691, crucible: 1692, forge: 1693 };
  return v1Map[module] || (spec && spec.gateway_vmid) || 1692;
}

/**
 * Resolve the per-lane networking config (wan + lan) based on subnet scheme.
 * Returns: { wan: {bridge, ip, gw}, lan: {gatewayIp, cidr, base3, netmask24} }
 *   - wan: net0 config for the lane gateway LXC
 *   - lan: net1 config + DHCP scope info for downstream consumers (goad-deploy)
 */
function resolveLaneNetworking(subnetScheme, module, vxlanId) {
  if (subnetScheme === 'v2') {
    return {
      wan: v2WanConfig(vxlanId),
      lan: v2LaneSubnet(vxlanId)
    };
  }
  // v1: shared 192.18.0.0/24 across all lanes (VXLAN-isolated)
  return {
    wan: laneUplinkConfig(module, vxlanId),
    lan: {
      base3:     '192.18.0',
      cidr:      '192.18.0.0/24',
      gatewayIp: '192.18.0.1',
      netmask24: '255.255.255.0'
    }
  };
}

// ============================================================================
// GUACAMOLE API HELPER
// ============================================================================

const GUAC_URL = process.env.GUAC_API_URL || 'http://100.100.70.10:8080/guacamole';
const GUAC_DS = process.env.GUAC_DATASOURCE || 'postgresql';

// Cache the Guac auth token (they last ~60 min)
let guacTokenCache = { token: null, expires: 0 };

async function getGuacToken() {
  // Return cached token if still valid (with 5-min buffer)
  if (guacTokenCache.token && Date.now() < guacTokenCache.expires - 300000) {
    return guacTokenCache.token;
  }

  const username = process.env.GUAC_ADMIN_USER || 'cactus-admin';
  const password = process.env.GUAC_ADMIN_PASSWORD;
  if (!password) throw new Error('GUAC_ADMIN_PASSWORD not set in .env');

  const resp = await fetch(`${GUAC_URL}/api/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Guacamole auth failed (${resp.status}): ${text}`);
  }

  const data = await resp.json();
  guacTokenCache = {
    token: data.authToken,
    expires: Date.now() + 55 * 60 * 1000 // ~55 min
  };
  return data.authToken;
}

// Generic Guac API call helper
async function guacAPI(method, path, body = null) {
  const token = await getGuacToken();
  const url = `${GUAC_URL}/api/session/data/${GUAC_DS}${path}?token=${token}`;

  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' }
  };
  if (body) opts.body = JSON.stringify(body);

  const resp = await fetch(url, opts);

  // Some DELETE calls return 204 with no body
  if (resp.status === 204) return null;

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`Guac API ${method} ${path} failed (${resp.status}): ${text}`);
  }

  try { return JSON.parse(text); } catch { return text; }
}


// ============================================================================
// GUACAMOLE STATUS / CONNECTION TREE
// ============================================================================

// GET /api/admin/guac/status — test connectivity & return basic info
router.get('/guac/status', authenticateToken, adminOnly, async (req, res) => {
  try {
    const token = await getGuacToken();
    res.json({ connected: true, datasource: GUAC_DS, guac_url: GUAC_URL });
  } catch (error) {
    res.status(502).json({ connected: false, error: error.message });
  }
});

// GET /api/admin/guac/tree — full connection tree from ROOT
router.get('/guac/tree', authenticateToken, adminOnly, async (req, res) => {
  try {
    const tree = await guacAPI('GET', '/connectionGroups/ROOT/tree');
    res.json(tree);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CONNECTIONS
// ============================================================================

// GET /api/admin/guac/connections — list all connections
router.get('/guac/connections', authenticateToken, adminOnly, async (req, res) => {
  try {
    const connections = await guacAPI('GET', '/connections');
    res.json(connections);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/guac/connections/:id — single connection details
router.get('/guac/connections/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const conn = await guacAPI('GET', `/connections/${req.params.id}`);
    const params = await guacAPI('GET', `/connections/${req.params.id}/parameters`);
    res.json({ ...conn, parameters: params });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/guac/connections — create a connection
router.post('/guac/connections', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, protocol, parentIdentifier, parameters, attributes } = req.body;
    if (!name || !protocol) return res.status(400).json({ error: 'name and protocol required' });

    const conn = await guacAPI('POST', '/connections', {
      name,
      protocol,
      parentIdentifier: parentIdentifier || 'ROOT',
      parameters: parameters || {},
      attributes: attributes || {}
    });
    res.json(conn);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/guac/connections/:id — delete a connection
router.delete('/guac/connections/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('DELETE', `/connections/${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CONNECTION GROUPS
// ============================================================================

// GET /api/admin/guac/groups — list connection groups
router.get('/guac/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const groups = await guacAPI('GET', '/connectionGroups');
    res.json(groups);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/guac/groups — create a connection group
router.post('/guac/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, type, parentIdentifier } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const group = await guacAPI('POST', '/connectionGroups', {
      name,
      type: type || 'ORGANIZATIONAL',
      parentIdentifier: parentIdentifier || 'ROOT',
      attributes: {}
    });
    res.json(group);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/guac/groups/:id — delete a connection group
router.delete('/guac/groups/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('DELETE', `/connectionGroups/${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// USERS
// ============================================================================

// GET /api/admin/guac/users — list all Guac users
router.get('/guac/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const users = await guacAPI('GET', '/users');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/guac/users/:username — user details
router.get('/guac/users/:username', authenticateToken, adminOnly, async (req, res) => {
  try {
    const user = await guacAPI('GET', `/users/${encodeURIComponent(req.params.username)}`);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/guac/users — create a Guac user
router.post('/guac/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { username, password, disabled } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const user = await guacAPI('POST', '/users', {
      username,
      password,
      attributes: {
        disabled: disabled ? '' : null,
        expired: null,
        timezone: 'America/Phoenix'
      }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/guac/users/:username/password — reset password
router.put('/guac/users/:username/password', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'password required' });

    await guacAPI('PUT', `/users/${encodeURIComponent(req.params.username)}`, {
      username: req.params.username,
      password,
      attributes: {}
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/guac/users/:username — delete a Guac user
router.delete('/guac/users/:username', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('DELETE', `/users/${encodeURIComponent(req.params.username)}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/guac/users/:username/permissions — user permissions
router.get('/guac/users/:username/permissions', authenticateToken, adminOnly, async (req, res) => {
  try {
    const perms = await guacAPI('GET', `/users/${encodeURIComponent(req.params.username)}/permissions`);
    res.json(perms);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/admin/guac/users/:username/permissions — update user permissions
router.patch('/guac/users/:username/permissions', authenticateToken, adminOnly, async (req, res) => {
  try {
    // body = array of permission patch operations
    // e.g. [{"op":"add","path":"/connectionPermissions/1","value":"READ"}]
    await guacAPI('PATCH', `/users/${encodeURIComponent(req.params.username)}/permissions`, req.body);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACTIVE SESSIONS
// ============================================================================

// GET /api/admin/guac/active — list active connections/sessions
router.get('/guac/active', authenticateToken, adminOnly, async (req, res) => {
  try {
    const active = await guacAPI('GET', '/activeConnections');
    res.json(active);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/guac/active/:id — kill an active session
router.delete('/guac/active/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const token = await getGuacToken();
    // Killing sessions uses a PATCH with an array
    const url = `${GUAC_URL}/api/session/data/${GUAC_DS}/activeConnections?token=${token}`;
    const resp = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{
        op: 'remove',
        path: `/${req.params.id}`
      }])
    });
    if (!resp.ok) throw new Error(`Kill session failed: ${resp.status}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// PROXMOX API HELPER
// ============================================================================

const PROXMOX_URL = process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006';
const PROXMOX_TOKEN_ID = process.env.PROXMOX_TOKEN_ID || 'root@pam!clinic-app-token';
const PROXMOX_TOKEN_SECRET = process.env.PROXMOX_TOKEN_SECRET || '';

async function proxmoxAPI(method, path, body = null) {
  const https = require('https');
  const url = new URL(`${PROXMOX_URL}${path}`);

  let bodyStr = null;
  if (body) {
    if (typeof body === 'string') {
      bodyStr = body;
    } else {
      bodyStr = Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    }
  }

  return new Promise((resolve, reject) => {
    const reqOpts = {
      hostname: url.hostname,
      port: url.port || 8006,
      path: url.pathname + url.search,
      method,
      headers: {
        'Authorization': `PVEAPIToken=${PROXMOX_TOKEN_ID}=${PROXMOX_TOKEN_SECRET}`,
        ...(bodyStr && { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(bodyStr) })
      },
      rejectUnauthorized: false  // Proxmox uses self-signed certs
    };

    const req = https.request(reqOpts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          return reject(new Error(`Proxmox ${method} ${url.pathname} failed (${res.statusCode}): ${data}`));
        }
        try {
          const json = JSON.parse(data);
          resolve(json.data !== undefined ? json.data : json);
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// Helper: wait for a Proxmox task to complete
async function waitForTask(node, upid, timeoutMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await proxmoxAPI('GET', `/api2/json/nodes/${node}/tasks/${encodeURIComponent(upid)}/status`);
    if (status.status === 'stopped') {
      if (status.exitstatus === 'OK') return status;
      throw new Error(`Proxmox task failed: ${status.exitstatus}`);
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error('Proxmox task timed out');
}


// ============================================================================
// CLUSTER HEALTH & DEPLOYMENT GUARDS
// ============================================================================

// GET /api/admin/cluster/health — current Proxmox resource usage
router.get('/cluster/health', authenticateToken, adminOnly, async (req, res) => {
  try {
    const health = await getClusterHealth(proxmoxAPI);
    res.json(health);
  } catch (error) {
    res.status(502).json({ error: `Failed to fetch cluster health: ${error.message}` });
  }
});

// POST /api/admin/deploy-preview — preview resource impact before deployment
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
// LANE DEPLOYMENT (Native — replaces N8N webhook)
// ============================================================================

// N8N Webhook URLs for lane deployment/teardown
const N8N_DEPLOY_WEBHOOK = process.env.N8N_DEPLOY_LANE_WEBHOOK || 'http://100.100.20.50:5678/webhook-test/6bcb6b80-01d9-41a4-86e5-c0747fef50db';
const N8N_TEARDOWN_WEBHOOK = process.env.N8N_TEARDOWN_LANE_WEBHOOK || 'http://100.100.20.50:5678/webhook-test/60949de5-d0f9-40bc-8441-5cf4f9b08048';

// Attack box (Kali) template
const KALI_TEMPLATE_VMID = 1699;
// VM ID scheme: Challenge=600000+vxlan, Gateway=100000+vxlan, AttackBox=700000+vxlan
const ATTACK_BOX_VMID_OFFSET = 700000;

// POST /api/admin/deploy-lane — deploy a CyberHub lane
router.post('/deploy-lane', authenticateToken, adminOnly, async (req, res) => {
  const { challenge_key, module, event_id, use_webhook, attack_boxes, confirm, vuln_scripts: selectedVulnScripts } = req.body;
  const user_id = req.body.user_id || req.user.userId;
  if (!challenge_key || !module) {
    return res.status(400).json({ error: 'challenge_key and module required' });
  }

  // ── Pre-flight resource check (skip if confirm: true) ──
  // Moved after challenge lookup below so we know the VM count

  // ── Webhook mode: forward to N8N instead of native deployment ──
  if (use_webhook) {
    try {
      console.log(`[Deploy] Using N8N webhook for ${challenge_key} (user: ${user_id})`);
      const webhookRes = await fetch(N8N_DEPLOY_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id,
          challenge_key,
          module,
          event_id: event_id || null
        })
      });
      if (!webhookRes.ok) {
        const errText = await webhookRes.text();
        throw new Error(`N8N webhook failed (${webhookRes.status}): ${errText}`);
      }
      const webhookData = await webhookRes.json();
      console.log(`[Deploy] N8N webhook response:`, webhookData);
      return res.json({
        success: true,
        method: 'webhook',
        lane_id: webhookData.lane_id || webhookData.laneId || 'pending',
        vxlan_id: webhookData.vxlan_id || webhookData.vxlanId || null,
        vnet: webhookData.vnet || null,
        challenge: challenge_key,
        message: 'Lane deployment triggered via N8N webhook.',
        webhook_response: webhookData
      });
    } catch (error) {
      console.error('[Deploy] N8N webhook error:', error.message);
      return res.status(502).json({ error: `Webhook failed: ${error.message}` });
    }
  }

  try {
    // 1. Validate module is installed
    const modResult = await cybercoreQuery(
      `SELECT EXISTS (SELECT 1 FROM cybercore_module WHERE key = $1) AS is_installed`,
      [module]
    );
    if (!modResult.rows[0].is_installed) {
      return res.status(400).json({ error: `Module '${module}' is not installed` });
    }

    // 2. Verify user exists in cybercore_user (single source of truth)
    const userResult = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role, organization FROM cybercore_user WHERE user_id = $1`, [user_id]
    );
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    // 3. Check user doesn't already have an active lane
    const laneCheck = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane WHERE user_id = $1 AND status IN ('active', 'deploying', 'pending') LIMIT 1`,
      [user_id]
    );
    if (laneCheck.rows.length > 0) {
      return res.status(409).json({ error: 'User already has an active lane', lane_id: laneCheck.rows[0].lane_id });
    }

    // 3. Query challenge details
    const challengeResult = await cybercoreQuery(
      `SELECT challenge_id, challenge_key, name, spec, difficulty, subnet_scheme
       FROM ${module}_challenge
       WHERE challenge_key = $1 AND status = 'active'`,
      [challenge_key]
    );
    if (challengeResult.rows.length === 0) {
      return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
    }
    const challenge = challengeResult.rows[0];
    const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : challenge.spec;
    const subnetScheme = challenge.subnet_scheme || 'v1';

    // v2 + GOAD is not yet supported: goad-deploy.js still hardcodes
    // 192.18.0.x in HOST_MAP, the controller's run.sh, and DHCP reservation
    // logic. Refuse the combo at deploy time rather than silently breaking
    // a long-running ansible run. (Follow-up: parameterize goad-deploy by
    // lane subnet base + bake controller template 1700 to read the lane
    // gateway IP from /etc/goad-lane.env.)
    if (subnetScheme === 'v2' && spec?.goad?.enabled) {
      return res.status(501).json({
        error: 'v2 lane subnet is not yet compatible with GOAD challenges',
        detail: 'GOAD playbooks still hardcode 192.18.0.0/24. Use subnet_scheme=v1 for GOAD challenges, or wait for the goad-deploy.js + controller bake follow-up.'
      });
    }

    // Pre-flight resource check (now that we know the VM count from spec)
    const specVmCount = (spec.vms || []).length || 1;
    if (!confirm) {
      try {
        const preview = await buildDeployPreview({
          numLanes: 1,
          attackBoxes: !!attack_boxes,
          challengeVmCount: specVmCount,
          proxmoxAPI,
          cybercoreQuery
        });
        return res.json({ preview: true, ...preview });
      } catch (err) {
        console.error('[Deploy] Pre-flight check failed:', err.message);
      }
    }

    // 4. Find next available VXLAN ID
    const vxlanBlock = {
      start: spec.vxlan_block?.start ?? 10000,
      end: spec.vxlan_block?.end ?? 10009
    };
    const vxlanResult = await cybercoreQuery(
      `WITH used AS (
        SELECT DISTINCT vxlan_id FROM cybercore_lane
        WHERE vxlan_id IS NOT NULL
          AND vxlan_id BETWEEN $1 AND $2
          AND status NOT IN ('error')
      )
      SELECT gs AS vxlan_id
      FROM generate_series($1::int, $2::int) AS gs
      LEFT JOIN used u ON u.vxlan_id = gs
      WHERE u.vxlan_id IS NULL
      ORDER BY gs LIMIT 1`,
      [vxlanBlock.start, vxlanBlock.end]
    );
    if (vxlanResult.rows.length === 0) {
      return res.status(503).json({ error: 'No available VXLAN IDs in this challenge block' });
    }
    const vxlanId = vxlanResult.rows[0].vxlan_id;

    // 5. Find the VNet matching this VXLAN tag from Proxmox SDN
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const vnet = vnets.find(v => v.tag === vxlanId);
    if (!vnet) {
      return res.status(503).json({ error: `No VNet found with tag ${vxlanId} in Proxmox SDN` });
    }

    // 6. Determine template location and best node
    const templateVmid = spec.template_vmid || 1600;
    // Gateway template depends on subnet scheme:
    //   v1 → module-specific 1691/1692/1693 (shared 192.18.0.0/24 lane subnet)
    //   v2 → 1694 (subnet-agnostic; firstboot renders dnsmasq from per-deploy lan0 IP)
    const gatewayVmid = resolveGatewayVmid(module, subnetScheme, spec);
    const templateNode = spec.template_node || 'cyberhub-node-5';
    console.log(`[Deploy] subnet_scheme=${subnetScheme} → gateway template=${gatewayVmid}`);
    // Select least-loaded node for deployment
    const bestNodeInfo = await selectBestNode();
    const bestNode = bestNodeInfo.node;
    console.log(`[Deploy] Selected node ${bestNode} for lane deployment (score: ${bestNodeInfo.score})`);

    // 7. Insert lane record with status 'deploying'
    const laneName = `${vnet.zone}-${vxlanId}`;
    const laneConfig = JSON.stringify({
      challenge_id: challenge.challenge_id,
      challenge_key: challenge.challenge_key,
      challenge_name: challenge.name,
      module
    });
    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
       RETURNING lane_id, user_id, vxlan_id, name, status, created_at`,
      [user_id, vxlanId, laneName, laneConfig, module]
    );
    const lane = laneInsert.rows[0];

    // Respond immediately — deployment continues in background
    res.json({
      success: true,
      lane_id: lane.lane_id,
      status: 'deploying',
      vxlan_id: vxlanId,
      vnet: vnet.vnet,
      challenge: challenge.name,
      message: 'Lane deployment started. Use GET /api/admin/lanes/:id to check status.'
    });

    logActivity(req, 'deploy_lane', 'lane', lane.lane_id, { challenge_key, module, vxlan_id: vxlanId, user_id });

    // ---- Background deployment (non-blocking) ----
    (async () => {
      try {
        // GOAD: per-lane MAC/IP lookup. No-op for non-GOAD specs.
        const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId);

        // Multi-VM support: if spec.vms exists, deploy each VM; otherwise fall back to single VM
        const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: templateVmid, type: 'qemu', vm_offset: 600000 }];
        const deployedVMs = [];

        for (const vmSpec of vmSpecs) {
          const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
          const vmType = vmSpec.type || 'qemu';
          const vmTemplate = vmSpec.template_vmid || templateVmid;
          const vmName = vmSpec.name || challenge_key;
          const goadMac = goadMacs[vmName]?.mac;

          console.log(`[Deploy] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName})`);

          if (vmType === 'lxc') {
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
              newid: vmId, hostname: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge: ${challenge_key}\nVM: ${vmName}\nLane: ${lane.lane_id}`,
              pool: `${module}-pool`
            });
            if (cloneResult) await waitForTask(templateNode, cloneResult);
            await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, {
              net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vnet.vnet, goadMac)
            });
          } else {
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
              newid: vmId, name: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge: ${challenge_key}\nVM: ${vmName}\nLane: ${lane.lane_id}`,
              pool: `${module}-pool`
            });
            if (cloneResult) await waitForTask(templateNode, cloneResult);
            await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
              net0: goadDeploy.buildLaneNet0(vmSpec, vnet.vnet, goadMac)
            });
          }

          deployedVMs.push({ vm_id: vmId, name: vmName, type: vmType, node: bestNode });
        }

        // Clone gateway LXC container
        const gatewayVmId = 100000 + vxlanId;
        const gwCloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
          newid: gatewayVmId,
          hostname: `${laneName}-gateway`,
          full: 1,
          target: bestNode,
          description: `Challenge: ${challenge_key}\nUser ID: ${user_id}\nLane ID: ${lane.lane_id}\nModule: ${module}`,
          pool: `${module}-pool`
        });

        if (gwCloneResult) await waitForTask(templateNode, gwCloneResult);

        // Wire up gateway networking. v1 routes through the module transit
        // gateway with a shared 192.18.0.0/24 lane subnet; v2 hangs wan0
        // directly off the lab network bridge and gives each lane its own
        // /24 in 10.0.0.0/8.
        const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
        await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`, {
          net0: `name=wan0,bridge=${net.wan.bridge},ip=${net.wan.ip},gw=${net.wan.gw},firewall=0,type=veth`,
          net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`
        });

        // Start gateway first, then all challenge VMs
        await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
        await new Promise(r => setTimeout(r, 5000));

        for (const vm of deployedVMs) {
          const startPath = vm.type === 'lxc'
            ? `/api2/json/nodes/${vm.node}/lxc/${vm.vm_id}/status/start`
            : `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`;
          await proxmoxAPI('POST', startPath);
        }

        // GOAD provisioning (no-op for non-GOAD specs). Runs after gateway+VMs
        // are up: writes DHCP reservations on the gateway, deploys the GOAD
        // controller LXC (template 1700), polls WinRM, runs the playbook,
        // then stops the controller. Any failure here is logged + marks the
        // lane's metadata.goad.status='failed' but doesn't tear down the VMs.
        if (spec.goad?.enabled) {
          try {
            await goadDeploy.deployGoadLane({
              lane, spec, module, vnet, vxlanId, gatewayVmId,
              bestNode, templateNode, deployedVMs,
              proxmoxAPI, waitForTask, query: cybercoreQuery
            });
          } catch (goadErr) {
            console.error(`[GOAD] Provisioning failed for lane ${lane.lane_id}:`, goadErr.message);
            // Lane stays 'deploying'/'active' per existing flow; metadata.goad
            // already records the failure for the admin UI.
          }
        }

        // Run vulnerability scripts if any were selected
        if (selectedVulnScripts && selectedVulnScripts.length > 0) {
          console.log(`[Deploy] Running ${selectedVulnScripts.length} vuln scripts on lane ${lane.lane_id}...`);

          // Create deployment tracking record
          const scriptEntries = selectedVulnScripts.map(s => ({
            script_slug: s.script_slug,
            vm_name: s.vm_name || deployedVMs[0]?.name || 'default',
            status: 'pending',
            error: null
          }));

          const dvsResult = await query(
            `INSERT INTO deployment_vuln_selections (lane_id, challenge_key, selected_scripts, status)
             VALUES ($1, $2, $3, 'running_scripts')
             RETURNING id`,
            [lane.lane_id, challenge_key, JSON.stringify(scriptEntries)]
          );
          const deploymentId = dvsResult.rows[0].id;

          // Wait for guest agent on each QEMU VM, then run scripts
          for (const vm of deployedVMs) {
            if (vm.type !== 'qemu') continue;

            console.log(`[Deploy] Waiting for guest agent on ${vm.name} (${vm.vm_id})...`);
            const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
            if (!agentReady) {
              console.error(`[Deploy] Guest agent not responding on ${vm.name} — skipping scripts`);
              continue;
            }

            // Get scripts assigned to this VM
            const vmScriptSlugs = selectedVulnScripts
              .filter(s => (s.vm_name || deployedVMs[0]?.name) === vm.name)
              .map(s => s.script_slug);

            if (vmScriptSlugs.length > 0) {
              const scriptRows = await query(
                `SELECT slug, script_content, os_target, depends_on, script_args FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`,
                [vmScriptSlugs]
              );
              if (scriptRows.rows.length > 0) {
                await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, scriptRows.rows, deploymentId);
              }
            }
          }

          // Collect IPs after scripts run
          const networkInfo = { vms: [] };
          for (const vm of deployedVMs) {
            const ips = vm.type === 'qemu' ? await getVMIPs(vm.node, vm.vm_id) : [];
            networkInfo.vms.push({ ...vm, ips, ip: ips[0] || null });
          }

          await query(
            `UPDATE deployment_vuln_selections SET deployed_network = $1, status = 'complete', updated_at = NOW() WHERE id = $2`,
            [JSON.stringify(networkInfo), deploymentId]
          );
          console.log(`[Deploy] Vuln scripts completed for lane ${lane.lane_id}`);
        }

        // Mark lane as active with deployment details in config
        const primaryVm = deployedVMs[0];
        const activeConfig = JSON.stringify({
          challenge_vm_id: primaryVm?.vm_id,
          gateway_vm_id: gatewayVmId,
          node: bestNode,
          challenge_key: challenge_key,
          module,
          vms: deployedVMs
        });
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
          [lane.lane_id, activeConfig]
        );
        console.log(`Lane ${lane.lane_id} deployed successfully (VXLAN ${vxlanId}, ${deployedVMs.length} VMs)`);
      } catch (err) {
        console.error(`Lane ${lane.lane_id} deployment failed:`, err.message);
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'error', config = $2, updated_at = NOW() WHERE lane_id = $1`,
          [lane.lane_id, JSON.stringify({ error: err.message })]
        ).catch(() => {});
      }
    })();

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// LANE DELETION — Stop & destroy VMs, update lane status
// ============================================================================

// DELETE /api/admin/lanes/:id — tear down a deployed lane
router.delete('/lanes/:id', authenticateToken, adminOnly, async (req, res) => {
  const useWebhook = req.query.webhook === 'true';

  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    // ── Webhook mode: forward teardown to N8N ──
    if (useWebhook) {
      const lane = laneResult.rows[0];
      try {
        console.log(`[Teardown] Using N8N webhook for lane ${lane.lane_id} (VXLAN ${lane.vxlan_id})`);
        const webhookRes = await fetch(N8N_TEARDOWN_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            lane_id: lane.lane_id,
            user_id: lane.user_id,
            vxlan_id: lane.vxlan_id,
            name: lane.name,
            config: typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config
          })
        });
        if (!webhookRes.ok) {
          const errText = await webhookRes.text();
          throw new Error(`N8N teardown webhook failed (${webhookRes.status}): ${errText}`);
        }
        const webhookData = await webhookRes.json();
        console.log(`[Teardown] N8N webhook response:`, webhookData);
        // Delete lane record after webhook succeeds
        await cybercoreQuery(`DELETE FROM cybercore_lane WHERE lane_id = $1`, [lane.lane_id]);
        return res.json({
          success: true,
          method: 'webhook',
          lane_id: lane.lane_id,
          vxlan_id: lane.vxlan_id,
          webhook_response: webhookData
        });
      } catch (error) {
        console.error('[Teardown] N8N webhook error:', error.message);
        return res.status(502).json({ error: `Teardown webhook failed: ${error.message}` });
      }
    }

    const lane = laneResult.rows[0];
    if (lane.status === 'deleted') {
      return res.status(400).json({ error: 'Lane already deleted' });
    }

    const vxlanId = lane.vxlan_id;
    const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

    // Build list of all VM IDs to destroy (multi-VM aware)
    const vmIdsToDestroy = [];

    // Multi-VM: iterate config.vms array if present
    if (Array.isArray(laneConfig.vms) && laneConfig.vms.length > 0) {
      for (const vm of laneConfig.vms) {
        vmIdsToDestroy.push({ vmid: vm.vm_id, type: vm.type || 'qemu', label: vm.name || `VM-${vm.vm_id}` });
      }
    } else {
      // Legacy single-VM: use the standard offset
      const challengeVmId = laneConfig.challenge_vm_id || (600000 + vxlanId);
      vmIdsToDestroy.push({ vmid: challengeVmId, type: 'qemu', label: 'challenge' });
    }

    // Always include gateway and attack box
    const gatewayVmId = laneConfig.gateway_vm_id || (100000 + vxlanId);
    vmIdsToDestroy.push({ vmid: gatewayVmId, type: 'lxc', label: 'gateway' });

    const attackBoxVmId = laneConfig.attack_box_vm_id || (ATTACK_BOX_VMID_OFFSET + vxlanId);
    vmIdsToDestroy.push({ vmid: attackBoxVmId, type: 'qemu', label: 'attack-box' });

    // GOAD controller VM (200000 + vxlanId). Always include — if the lane
    // wasn't a GOAD lane it just won't exist and gets filtered out by the
    // cluster-resources lookup below. Prevents orphan controller configs
    // (which block re-deploys at the same VMID with "File exists" errors).
    const goadControllerVmId = 200000 + vxlanId;
    vmIdsToDestroy.push({ vmid: goadControllerVmId, type: 'qemu', label: 'goad-controller' });

    const errors = [];

    // Find which node(s) the VMs are on
    const vmNodes = {}; // { vmid: node }
    const allVmIds = vmIdsToDestroy.map(v => v.vmid);
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of resources) {
        if (allVmIds.includes(r.vmid)) {
          vmNodes[r.vmid] = r.node;
        }
      }
    } catch (e) {
      errors.push(`Could not query cluster resources: ${e.message}`);
    }

    // Helper: forcefully destroy a VM/LXC — removes protection, stops, purges
    async function forceDestroyVM(vmid, type, knownNode) {
      // type: 'qemu' or 'lxc'
      const nodes = knownNode ? [knownNode] : [];
      // If not found in resources, try all nodes (handles ghost configs from failed clones)
      if (nodes.length === 0) {
        try {
          const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
          for (const n of nodeList) nodes.push(n.node);
        } catch (e) {
          nodes.push('cyberhub-node-5'); // fallback
        }
      }

      for (const node of nodes) {
        try {
          // Step 1: Remove protection (PUT for both qemu and lxc)
          try {
            await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { protection: 0 });
            console.log(`[Teardown] Removed protection from ${type} ${vmid} on ${node}`);
          } catch (_) {}

          // Step 2: Unlock if locked
          try {
            await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { lock: '' });
          } catch (_) {}

          // Step 3: Stop (LXC does not accept `timeout` parameter — use empty body for LXC)
          try {
            const stopBody = type === 'qemu' ? { timeout: 0 } : {};
            await proxmoxAPI('POST', `/api2/json/nodes/${node}/${type}/${vmid}/status/stop`, stopBody);
            await new Promise(r => setTimeout(r, 4000));
          } catch (_) {}

          // Step 4: Destroy — QEMU and LXC have different DELETE params:
          //   QEMU accepts purge + skiplock (rejects force with 400 error)
          //   LXC accepts purge + force (rejects skiplock on newer versions)
          const primaryUrl = type === 'lxc'
            ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
            : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1&skiplock=1`;
          try {
            await proxmoxAPI('DELETE', primaryUrl);
          } catch (deleteErr) {
            console.log(`[Teardown] Retry destroy ${type} ${vmid} with minimal params...`);
            const fallback = type === 'lxc'
              ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
              : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1`;
            await proxmoxAPI('DELETE', fallback);
          }

          console.log(`[Teardown] Destroyed ${type} ${vmid} on ${node}`);
          return true;
        } catch (e) {
          // Not an error if the config is already gone on this node — try the next one
          if (/unable to find configuration file/i.test(e.message)) {
            console.log(`[Teardown] ${type} ${vmid} not on ${node} (no config file) — checking next node`);
            continue;
          }
          console.log(`[Teardown] ${type} ${vmid} not destroyable on ${node}: ${e.message}`);
          continue;
        }
      }
      return false;
    }

    // Destroy all VMs in the lane (multi-VM aware)
    for (const vm of vmIdsToDestroy) {
      const destroyed = await forceDestroyVM(vm.vmid, vm.type, vmNodes[vm.vmid]);
      if (!destroyed && vmNodes[vm.vmid]) {
        errors.push(`${vm.label} (${vm.type} ${vm.vmid}): could not be destroyed`);
      }
    }

    // Delete the lane row so the VXLAN ID is freed for reuse
    await cybercoreQuery(
      `DELETE FROM cybercore_lane WHERE lane_id = $1`,
      [lane.lane_id]
    );

    logActivity(req, 'delete_lane', 'lane', lane.lane_id, { vxlan_id: vxlanId, errors: errors.length });

    res.json({
      success: true,
      lane_id: lane.lane_id,
      vxlan_id: vxlanId,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// LANE MANAGEMENT ENDPOINTS
// ============================================================================

// GET /api/admin/lanes — list all lanes
router.get('/lanes', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { status } = req.query;
    let sql = `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at, updated_at
               FROM cybercore_lane ORDER BY created_at DESC`;
    const params = [];
    if (status) {
      sql = `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at, updated_at
             FROM cybercore_lane WHERE status = $1 ORDER BY created_at DESC`;
      params.push(status);
    }
    const result = await cybercoreQuery(sql, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/lanes/:id — single lane details
router.get('/lanes/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at, updated_at
       FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/reconcile — compare DB state against live Proxmox resources
router.get('/reconcile', authenticateToken, adminOnly, async (req, res) => {
  try {
    // 1. Fetch all VMs from Proxmox
    const pxResources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const pxVMs = (Array.isArray(pxResources) ? pxResources : []).map(vm => ({
      vmid: vm.vmid,
      name: vm.name || '',
      status: vm.status,
      node: vm.node,
      type: vm.type
    }));

    // 2. Fetch SDN VNets from Proxmox
    let pxVNets = [];
    try {
      const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      pxVNets = (Array.isArray(vnets) ? vnets : []).map(v => ({
        vnet: v.vnet, zone: v.zone, tag: v.tag, alias: v.alias || ''
      }));
    } catch (e) { /* SDN may not be configured */ }

    // 3. Fetch all lanes from DB (non-deleted)
    const dbLanes = (await cybercoreQuery(
      `SELECT lane_id, vxlan_id, name, status, config, created_at
       FROM cybercore_lane WHERE status NOT IN ('deleted')
       ORDER BY created_at DESC`
    )).rows;

    // 4. Fetch deployed groups from DB
    const dbGroups = (await query(
      `SELECT id, group_name, config, created_at FROM deployed_groups ORDER BY created_at DESC`
    )).rows;

    // 5. Build set of VM IDs the DB expects to exist
    const dbExpectedVmIds = new Set();
    const laneVmMap = {};
    for (const lane of dbLanes) {
      const vxlan = lane.vxlan_id;
      if (!vxlan) continue;
      const cfg = lane.config || {};
      const vmIds = [];

      // Challenge VMs from config.vms array
      if (Array.isArray(cfg.vms)) {
        cfg.vms.forEach(vm => { if (vm.vm_id) vmIds.push(vm.vm_id); });
      } else {
        vmIds.push(cfg.challenge_vm_id || (600000 + vxlan));
      }
      // Gateway
      const gwId = cfg.gateway_vm_id || (100000 + vxlan);
      vmIds.push(gwId);
      // Attack box
      if (cfg.attack_box_vm_id) vmIds.push(cfg.attack_box_vm_id);
      else if (cfg.attack_box) vmIds.push(700000 + vxlan);

      vmIds.forEach(id => {
        dbExpectedVmIds.add(id);
        laneVmMap[id] = { lane_id: lane.lane_id, name: lane.name, vxlan_id: vxlan, status: lane.status };
      });
    }

    // 6. Audit SDN zones — cross-reference against challenge templates
    let pxZones = [];
    try {
      const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
      pxZones = (Array.isArray(zones) ? zones : []).filter(z => z.type === 'vxlan');
    } catch (e) { /* SDN may not be configured */ }

    const dbChallenges = (await cybercoreQuery(
      `SELECT challenge_key, name, spec FROM crucible_challenge`
    )).rows;

    // Build set of zone names the DB knows about (from challenge_key or spec.zone.abbrev)
    const dbZoneNames = new Set();
    for (const ch of dbChallenges) {
      const spec = typeof ch.spec === 'string' ? JSON.parse(ch.spec || '{}') : (ch.spec || {});
      const zoneName = spec.zone?.abbrev
        || ch.challenge_key?.substring(0, 8)?.replace(/[^a-z0-9]/gi, '').substring(0, 8);
      if (zoneName) dbZoneNames.add(zoneName);
    }

    // Also check if any active lane's VNets reference this zone
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

    // VNets whose zone no longer exists in SDN (truly orphaned, not just unused)
    const activeZoneNames = new Set(pxZones.map(z => z.zone));
    const orphanedVNets = pxVNets.filter(v => v.zone && !activeZoneNames.has(v.zone))
      .map(v => ({ vnet: v.vnet, zone: v.zone, tag: v.tag, alias: v.alias }));

    // 7. Build set of VM IDs that match CyberHub ID ranges on Proxmox
    const CYBERHUB_RANGES = [
      { min: 100000, max: 199999, role: 'gateway' },
      { min: 600000, max: 699999, role: 'challenge' },
      { min: 700000, max: 799999, role: 'attack_box' }
    ];
    const pxCyberhubVMs = pxVMs.filter(vm =>
      CYBERHUB_RANGES.some(r => vm.vmid >= r.min && vm.vmid <= r.max)
    );
    const pxVmIdSet = new Set(pxCyberhubVMs.map(vm => vm.vmid));

    // 7. Diff
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
        // Lane is stale if NONE of its expected VMs exist on Proxmox
        return vmIds.length > 0 && vmIds.every(id => !pxVmIdSet.has(id));
      })
      .map(lane => ({
        lane_id: lane.lane_id,
        name: lane.name,
        vxlan_id: lane.vxlan_id,
        status: lane.status,
        created_at: lane.created_at
      }));

    // 8. Audit orphaned disk images across all storages.
    //    An orphan disk = vm-<vmid>-disk-* whose VMID is in a CyberHub range but has no
    //    live VM config anywhere in the cluster. These leak when purge=1 fails on a
    //    multi-disk VM (common with Ceph RBD locks). We also dedupe by volid since
    //    shared storage shows the same disk on every node.
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
            const match = item.volid?.match(/vm-(\d+)-disk/);
            if (!match) continue;
            const vmid = parseInt(match[1]);

            // Only flag CyberHub-range disks (gateway 1xxxxx / challenge 6xxxxx / attack-box 7xxxxx)
            const inRange = CYBERHUB_RANGES.some(r => vmid >= r.min && vmid <= r.max);
            if (!inRange) continue;

            // If the VM exists anywhere in the cluster, not an orphan
            if (liveVmIdSet.has(vmid)) continue;

            // Dedupe shared-storage duplicates
            if (seenDiskVolids.has(item.volid)) continue;
            seenDiskVolids.add(item.volid);

            orphanedDisks.push({
              node,
              storage: s.storage,
              volid: item.volid,
              vmid,
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

    // 9. Audit Guacamole connections.
    //    A CyberHub connection is any RDP connection whose name matches our deploy pattern
    //    (contains " - " and " - Kali"), OR any connection tracked in deployed_groups.config.guac_connections.
    //    An orphan = a tracked-or-patterned connection whose parent group no longer exists
    //    OR whose parent lane/student no longer has a lane.
    const orphanedGuacConnections = [];
    try {
      const allGuacConns = await guacAPI('GET', '/connections');
      const connList = Array.isArray(allGuacConns)
        ? allGuacConns
        : Object.values(allGuacConns || {});

      // Known "tracked" connection IDs from all currently-deployed groups
      const trackedConnIds = new Set();
      for (const g of dbGroups) {
        const gCfg = typeof g.config === 'string' ? JSON.parse(g.config) : (g.config || {});
        for (const c of (gCfg.guac_connections || [])) {
          if (c?.id) trackedConnIds.add(String(c.id));
        }
      }

      // Known active Guac group identifiers
      const activeGuacGroupIds = new Set();
      for (const g of dbGroups) {
        const gCfg = typeof g.config === 'string' ? JSON.parse(g.config) : (g.config || {});
        if (gCfg.guac_group?.identifier) activeGuacGroupIds.add(String(gCfg.guac_group.identifier));
      }

      for (const c of connList) {
        const name = c.name || '';
        const id = String(c.identifier || c.id || '');
        const parent = String(c.parentIdentifier || 'ROOT');

        // Heuristic: CyberHub-generated connection names contain " - " and end in a VM role like "Kali", "VulnWin", etc.
        const looksLikeCyberhub = / - .* - (Kali|VulnWin|Target|Attack|RDP)/i.test(name)
          || trackedConnIds.has(id);
        if (!looksLikeCyberhub) continue;

        // Orphan if:
        //   - tracked in a group but that group's row is gone, OR
        //   - its parent connection group isn't one we still track, OR
        //   - its parent is ROOT (reparented after cascade-less group delete)
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

// POST /api/admin/reconcile/destroy-vm — destroy an orphaned VM on Proxmox
router.post('/reconcile/destroy-vm', authenticateToken, adminOnly, async (req, res) => {
  const { vmid, node, type } = req.body;
  if (!vmid || !node) return res.status(400).json({ error: 'vmid and node required' });
  try {
    // Stop VM first if running
    try {
      const stopPath = type === 'lxc'
        ? `/api2/json/nodes/${node}/lxc/${vmid}/status/stop`
        : `/api2/json/nodes/${node}/qemu/${vmid}/status/stop`;
      await proxmoxAPI('POST', stopPath);
      await new Promise(r => setTimeout(r, 3000));
    } catch (e) { /* may already be stopped */ }
    // Disable protection mode if enabled
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

// POST /api/admin/reconcile/mark-deleted — mark a stale lane as deleted in DB
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

// POST /api/admin/reconcile/destroy-disk — free a single orphaned disk image
// Called from the Proxmox Audit UI's per-row Delete button. Uses retry with backoff
// because cfs-lock and RBD contention both produce intermittent 5xx errors.
router.post('/reconcile/destroy-disk', authenticateToken, adminOnly, async (req, res) => {
  const { node, storage, volid } = req.body;
  if (!node || !storage || !volid) return res.status(400).json({ error: 'node, storage, and volid required' });
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await proxmoxAPI('DELETE',
        `/api2/json/nodes/${node}/storage/${storage}/content/${encodeURIComponent(volid)}`);
      console.log(`[Reconcile] Destroyed orphaned disk ${volid} on ${node}/${storage}`);
      // entity_id in activity_log is UUID — can't use "node/storage", stash it in metadata instead
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

// POST /api/admin/reconcile/destroy-guac-connection — delete an orphaned Guac connection
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

// POST /api/admin/reconcile/destroy-zone — remove an orphaned SDN zone and its VNets
router.post('/reconcile/destroy-zone', authenticateToken, adminOnly, async (req, res) => {
  const { zone } = req.body;
  if (!zone) return res.status(400).json({ error: 'zone required' });
  try {
    // First delete all VNets in the zone
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const zoneVnets = (Array.isArray(vnets) ? vnets : []).filter(v => v.zone === zone);
    for (const vnet of zoneVnets) {
      console.log(`[Reconcile] Deleting VNet '${vnet.vnet}' in zone '${zone}'`);
      await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet.vnet}`);
    }
    // Then delete the zone itself
    console.log(`[Reconcile] Deleting SDN zone '${zone}'`);
    await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zone}`);
    // Apply SDN changes
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (e) { /* best effort */ }
    console.log(`[Reconcile] Zone '${zone}' destroyed (${zoneVnets.length} VNets removed)`);
    res.json({ ok: true, zone, vnets_removed: zoneVnets.length });
  } catch (error) {
    console.error(`[Reconcile] Failed to destroy zone ${zone}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/reconcile/destroy-vnet — remove a single orphaned VNet
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

// PATCH /api/admin/lanes/:id/internet — toggle internet access on a lane (admin version)
router.patch('/lanes/:id/internet', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { enabled } = req.body;
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled (boolean) required' });
    }

    const laneResult = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane WHERE lane_id = $1`,
      [req.params.id]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });

    const lane = laneResult.rows[0];
    if (lane.status !== 'active') {
      return res.status(400).json({ error: `Lane must be active (current: ${lane.status})` });
    }

    const config = typeof lane.config === 'string' ? JSON.parse(lane.config) : lane.config;
    const node = config?.node;
    const gatewayVmId = config?.gateway_vm_id || (100000 + lane.vxlan_id);

    if (!node) return res.status(400).json({ error: 'Lane config missing node info' });

    // Interface names inside the gateway LXC come from the pct config:
    //   net0 -> name=wan0 (uplink, DHCP from vmbr99 on the Proxmox host)
    //   net1 -> name=lan0 (lane-side, 192.18.0.1/24)
    // Old code used eth0 / net1 which don't exist inside the container, so the
    // rules never matched and the toggle was effectively a no-op.
    const cmd = enabled
      ? 'iptables -t nat -C POSTROUTING -o wan0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o wan0 -j MASQUERADE; iptables -C FORWARD -i lan0 -o wan0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i lan0 -o wan0 -j ACCEPT; iptables -C FORWARD -i wan0 -o lan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wan0 -o lan0 -m state --state RELATED,ESTABLISHED -j ACCEPT; echo 1 > /proc/sys/net/ipv4/ip_forward'
      : 'iptables -t nat -D POSTROUTING -o wan0 -j MASQUERADE 2>/dev/null; iptables -D FORWARD -i lan0 -o wan0 -j ACCEPT 2>/dev/null; iptables -D FORWARD -i wan0 -o lan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; echo 0 > /proc/sys/net/ipv4/ip_forward';

    try {
      await proxmoxAPI('POST', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/exec`, {
        command: JSON.stringify(['sh', '-c', cmd])
      });
    } catch (execErr) {
      return res.status(502).json({
        error: `Could not execute command on gateway: ${execErr.message}`,
        hint: 'The Proxmox exec API may not be available.'
      });
    }

    const updatedConfig = { ...config, internet_enabled: enabled };
    await cybercoreQuery(
      `UPDATE cybercore_lane SET config = $1, updated_at = NOW() WHERE lane_id = $2`,
      [JSON.stringify(updatedConfig), lane.lane_id]
    );

    logActivity(req, 'toggle_internet', 'lane', lane.lane_id, { enabled, vxlan_id: lane.vxlan_id });

    res.json({ success: true, lane_id: lane.lane_id, internet_enabled: enabled });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/modules — list installed modules
router.get('/modules', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`SELECT * FROM cybercore_module ORDER BY key`);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/challenges/:module — list challenges for a module
router.get('/challenges/:module', authenticateToken, adminOnly, async (req, res) => {
  try {
    const mod = req.params.module.replace(/[^a-z0-9_]/gi, '');
    const result = await cybercoreQuery(
      `SELECT challenge_id, challenge_key, name, difficulty, status FROM ${mod}_challenge WHERE status = 'active' ORDER BY name`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// GROUP DEPLOYMENT — Batch create users + Guac group
// ============================================================================

// Legacy fallback — replaced by per-user random passwords via generatePassword()
const GROUP_PASSWORD_FALLBACK = 'ClinicP@ssw0rd123!!';

// POST /api/admin/deploy-group — create a group with instructor + student users
// Optional: deploy_lanes=true to also deploy CyberHub lanes per student
router.post('/deploy-group', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { group_name, num_instructors, num_students, attack_boxes, challenge_key, module, deploy_lanes, use_webhook, confirm, vuln_scripts: groupVulnScripts } = req.body;
    if (!group_name || !num_students) {
      return res.status(400).json({ error: 'group_name and num_students required' });
    }

    const numInst = parseInt(num_instructors) || 0;
    const numStud = parseInt(num_students) || 1;
    const shouldDeployLanes = !!deploy_lanes && !!challenge_key && !!module;

    // ── Pre-flight resource check (skip if confirm: true) — moved after spec lookup ──
    if (!confirm && shouldDeployLanes) {
      try {
        // Quick lookup to get VM count from challenge spec
        let preflightVmCount = 1;
        try {
          const pfResult = await cybercoreQuery(
            `SELECT spec FROM ${module}_challenge WHERE challenge_key = $1 AND status = 'active'`, [challenge_key]
          );
          if (pfResult.rows.length > 0) {
            const pfSpec = typeof pfResult.rows[0].spec === 'string' ? JSON.parse(pfResult.rows[0].spec) : pfResult.rows[0].spec;
            preflightVmCount = (pfSpec.vms || []).length || 1;
          }
        } catch (_) {}

        const preview = await buildDeployPreview({
          numLanes: numStud,
          attackBoxes: !!attack_boxes,
          challengeVmCount: preflightVmCount,
          proxmoxAPI,
          cybercoreQuery
        });
        return res.json({ preview: true, ...preview });
      } catch (err) {
        console.error('[Group Deploy] Pre-flight check failed:', err.message);
        // Non-blocking: allow deployment if health check fails
      }
    }

    // If deploying lanes, validate capacity before creating any accounts
    let spec = null;
    let vxlanBlock = null;
    let availableVxlans = [];
    let subnetScheme = 'v1';
    if (shouldDeployLanes) {
      // Validate module
      const modResult = await cybercoreQuery(
        `SELECT EXISTS (SELECT 1 FROM cybercore_module WHERE key = $1) AS is_installed`,
        [module]
      );
      if (!modResult.rows[0].is_installed) {
        return res.status(400).json({ error: `Module '${module}' is not installed` });
      }

      // Get challenge spec
      const challengeResult = await cybercoreQuery(
        `SELECT challenge_id, challenge_key, name, spec, subnet_scheme
         FROM ${module}_challenge
         WHERE challenge_key = $1 AND status = 'active'`,
        [challenge_key]
      );
      if (challengeResult.rows.length === 0) {
        return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
      }
      spec = typeof challengeResult.rows[0].spec === 'string'
        ? JSON.parse(challengeResult.rows[0].spec) : challengeResult.rows[0].spec;
      subnetScheme = challengeResult.rows[0].subnet_scheme || 'v1';

      // v2 + GOAD not yet supported (see single-deploy site for full reasoning)
      if (subnetScheme === 'v2' && spec?.goad?.enabled) {
        return res.status(501).json({
          error: 'v2 lane subnet is not yet compatible with GOAD challenges',
          detail: 'GOAD playbooks still hardcode 192.18.0.0/24. Use subnet_scheme=v1 for GOAD batch deploys, or wait for the goad-deploy.js + controller bake follow-up.'
        });
      }

      // Check VXLAN capacity
      vxlanBlock = {
        start: spec.vxlan_block?.start ?? 10000,
        end: spec.vxlan_block?.end ?? 10009
      };
      const vxlanResult = await cybercoreQuery(
        `WITH used AS (
          SELECT DISTINCT vxlan_id FROM cybercore_lane
          WHERE vxlan_id IS NOT NULL
            AND vxlan_id BETWEEN $1 AND $2
            AND status NOT IN ('error')
        )
        SELECT gs AS vxlan_id
        FROM generate_series($1::int, $2::int) AS gs
        LEFT JOIN used u ON u.vxlan_id = gs
        WHERE u.vxlan_id IS NULL
        ORDER BY gs`,
        [vxlanBlock.start, vxlanBlock.end]
      );
      availableVxlans = vxlanResult.rows.map(r => r.vxlan_id);

      if (availableVxlans.length < numStud) {
        return res.status(400).json({
          error: `Not enough VXLAN capacity. Need ${numStud} lanes but only ${availableVxlans.length} available (range ${vxlanBlock.start}-${vxlanBlock.end}).`
        });
      }
    }

    const groupId = uuidv4();
    const created = { instructors: [], students: [], guac_group: null, guac_users: [], guac_connections: [], lanes: [], credentials: [] };

    // 1. Create Guacamole connection group
    try {
      const guacGroup = await guacAPI('POST', '/connectionGroups', {
        name: group_name,
        type: 'ORGANIZATIONAL',
        parentIdentifier: 'ROOT',
        attributes: {}
      });
      created.guac_group = guacGroup;
    } catch (e) {
      created.guac_group_error = e.message;
    }

    // 2. Create instructor accounts (each with unique password)
    for (let i = 1; i <= numInst; i++) {
      const userId = uuidv4();
      const email = `${group_name.toLowerCase().replace(/[^a-z0-9]/g, '')}-instructor${i}@clinic.local`;
      const firstName = `Instructor`;
      const lastName = `${i}`;
      const password = generatePassword();
      const passwordHash = await bcrypt.hash(password, 12);

      await cybercoreQuery(
        `INSERT INTO cybercore_user (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
         VALUES ($1, $2, $3, $4, 'bcrypt', $5, $6, $7, $8, true, NOW())
         RETURNING user_id, email, first_name, last_name, role`,
        [userId, email, email, passwordHash, firstName, lastName, group_name, 'instructor']
      );
      created.instructors.push({ id: userId, email, name: `${firstName} ${lastName}` });
      created.credentials.push({ email, password, role: 'instructor' });

      try {
        await guacAPI('POST', '/users', {
          username: email,
          password: password,
          attributes: { disabled: null, timezone: 'America/Phoenix' }
        });
        created.guac_users.push(email);
      } catch (e) { /* skip if Guac unreachable */ }
    }

    // 3. Create student accounts (each with unique password)
    for (let i = 1; i <= numStud; i++) {
      const userId = uuidv4();
      const email = `${group_name.toLowerCase().replace(/[^a-z0-9]/g, '')}-student${i}@clinic.local`;
      const firstName = `Student`;
      const lastName = `${i}`;
      const password = generatePassword();
      const passwordHash = await bcrypt.hash(password, 12);

      await cybercoreQuery(
        `INSERT INTO cybercore_user (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
         VALUES ($1, $2, $3, $4, 'bcrypt', $5, $6, $7, $8, true, NOW())
         RETURNING user_id, email, first_name, last_name, role`,
        [userId, email, email, passwordHash, firstName, lastName, group_name, 'student']
      );
      created.students.push({ id: userId, email, name: `${firstName} ${lastName}` });
      created.credentials.push({ email, password, role: 'student' });

      try {
        await guacAPI('POST', '/users', {
          username: email,
          password: password,
          attributes: { disabled: null, timezone: 'America/Phoenix' }
        });
        created.guac_users.push(email);
      } catch (e) { /* skip if Guac unreachable */ }
    }

    // 3b. Grant all Guac users permission to see the connection group
    if (created.guac_group?.identifier) {
      const groupId_guac = created.guac_group.identifier;
      for (const guacUser of created.guac_users) {
        try {
          await guacAPI('PATCH', `/users/${encodeURIComponent(guacUser)}/permissions`, [
            { op: 'add', path: `/connectionGroupPermissions/${groupId_guac}`, value: 'READ' }
          ]);
        } catch (_) {} // Non-blocking
      }
      console.log(`[Group ${group_name}] Granted ${created.guac_users.length} users access to Guac group ${groupId_guac}`);
    }

    // 4. Store the group record
    await query(
      `INSERT INTO deployed_groups (id, group_name, config, created_by, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [groupId, group_name, JSON.stringify({
        instructors: created.instructors,
        students: created.students,
        credentials: created.credentials,
        guac_group: created.guac_group,
        guac_users: created.guac_users,
        attack_boxes: !!attack_boxes,
        challenge_key: challenge_key || null,
        module: module || null,
        deploy_lanes: shouldDeployLanes
      }), req.user.userId]
    );

    // 5. Deploy lanes per student (if enabled)
    if (shouldDeployLanes) {
      const templateVmid = spec.template_vmid || 1600;
      const gatewayVmid = resolveGatewayVmid(module, subnetScheme, spec);
      const templateNode = spec.template_node || 'cyberhub-node-5';
      console.log(`[Group Deploy] subnet_scheme=${subnetScheme} → gateway template=${gatewayVmid}`);

      // Distribute lanes across nodes (query cluster ONCE instead of per-lane)
      let nodeAssignments;
      try {
        nodeAssignments = await distributeAcrossNodes(proxmoxAPI, numStud);
      } catch (e) {
        console.warn(`[Group Deploy] Batch node distribution failed, falling back to single node: ${e.message}`);
        const bestNodeInfo = await selectBestNode();
        nodeAssignments = new Array(numStud).fill(bestNodeInfo.node);
      }

      // Find VNets once
      let vnets = [];
      try {
        vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      } catch (e) {
        console.error('Could not fetch VNets for group deploy:', e.message);
      }

      // Pre-create lane records and sync users (synchronous, before response)
      const laneJobs = [];
      for (let i = 0; i < created.students.length; i++) {
        const student = created.students[i];
        const vxlanId = availableVxlans[i];
        const vnet = vnets.find(v => v.tag === vxlanId);

        if (!vnet) {
          console.warn(`No VNet for VXLAN ${vxlanId}, skipping lane for ${student.email}`);
          continue;
        }

        try {
          // Sync student to cybercore_user (upsert by username to handle re-deploys)
          const studentCred = created.credentials.find(c => c.email === student.email);
          const studentPwHash = studentCred ? await bcrypt.hash(studentCred.password, 12) : null;
          await cybercoreQuery(
            `INSERT INTO cybercore_user (user_id, username, email, first_name, last_name, role, auth_provider, organization, password_hash, password_alg)
             VALUES ($1, $2, $3, $4, $5, 'student', 'local', $6, $7, 'bcrypt')
             ON CONFLICT (username) DO UPDATE SET user_id = $1, email = $3, organization = $6, password_hash = $7, password_alg = 'bcrypt'`,
            [student.id, student.email, student.email, `Student`, `${i + 1}`, group_name, studentPwHash]
          );

          // Insert lane record — include expected VM IDs so teardown can find them even if deploy fails
          const laneName = `${vnet.zone}-${vxlanId}`;
          const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: spec.template_vmid || 1600, type: 'qemu', vm_offset: 600000 }];
          const expectedVms = vmSpecs.map(vs => ({
            vm_id: (vs.vm_offset || 600000) + vxlanId,
            name: vs.name || challenge_key,
            type: vs.type || 'qemu'
          }));
          const laneConfig = JSON.stringify({
            challenge_key,
            module,
            group_id: groupId,
            group_name,
            gateway_vm_id: 100000 + vxlanId,
            attack_box_vm_id: attack_boxes ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null,
            vms: expectedVms
          });
          const laneInsert = await cybercoreQuery(
            `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
             VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
             RETURNING lane_id`,
            [student.id, vxlanId, laneName, laneConfig, module]
          );
          const laneId = laneInsert.rows[0].lane_id;
          created.lanes.push({ lane_id: laneId, student_email: student.email, vxlan_id: vxlanId });
          laneJobs.push({ laneId, student, vxlanId, vnet, laneName, targetNode: nodeAssignments[i] });
        } catch (err) {
          console.error(`Failed to create lane record for ${student.email}:`, err.message);
        }
      }

      // Background: deploy lanes in PARALLEL with concurrency control
      (async () => {
        const concurrency = parseInt(process.env.MAX_CONCURRENT_DEPLOYS) || 6;
        const cloneSem = createCloneSemaphore();
        console.log(`[Group ${group_name}] Starting parallel deployment of ${laneJobs.length} lanes (lane concurrency: ${concurrency}, max concurrent clones: ${cloneSem.max})...`);

        // Track progress for the status endpoint
        const batchId = groupId;
        if (!global._batchDeployProgress) global._batchDeployProgress = {};
        global._batchDeployProgress[batchId] = {
          group_name,
          total: laneJobs.length,
          completed: 0,
          succeeded: 0,
          failed: 0,
          started_at: new Date().toISOString(),
          phase: 'preparing',
          phase_detail: 'Replicating gateway templates',
          elapsed_s: 0,
          avg_lane_s: null,
          eta_s: null,
          eta_at: null,
          lanes: {},
          _laneTimes: []  // internal: track per-lane durations for ETA calc
        };
        const progress = global._batchDeployProgress[batchId];
        const deployStartTime = Date.now();

        // Helper to update timing fields
        function updateProgressTiming() {
          const now = Date.now();
          progress.elapsed_s = Math.round((now - deployStartTime) / 1000);

          if (progress._laneTimes.length > 0) {
            const avgMs = progress._laneTimes.reduce((a, b) => a + b, 0) / progress._laneTimes.length;
            progress.avg_lane_s = Math.round(avgMs / 1000);

            const remaining = progress.total - progress.completed;
            // Lanes run concurrently: remaining lanes / concurrency * avg lane time
            const etaMs = (remaining / concurrency) * avgMs;
            progress.eta_s = Math.round(etaMs / 1000);
            progress.eta_at = new Date(now + etaMs).toISOString();
          }
        }

        // ── Phase 1: Replicate gateway template to each target node, then clone all in parallel ──
        // LXC containers lock the source during clone, so we can't clone from one template concurrently.
        // Workaround: create a temporary copy of the gateway template on each unique target node,
        // then each node clones from its own local copy in parallel. Temp copies are deleted after.

        // Find unique target nodes (excluding the template's home node)
        const uniqueTargetNodes = [...new Set(laneJobs.map(j => j.targetNode))];
        const tempTemplateIds = {};  // node → temp template VMID
        const TEMP_GW_TEMPLATE_BASE = 169200;  // temp copies: 169200, 169201, ...
        let tempIdCounter = 0;

        progress.phase = 'gateway_replication';
        progress.phase_detail = `Replicating gateway template to ${uniqueTargetNodes.length} nodes`;
        console.log(`[Group ${group_name}] Phase 1a: Replicating gateway template ${gatewayVmid} to ${uniqueTargetNodes.length} nodes...`);

        // Clone gateway template to each target node sequentially (one LXC lock, but only N nodes not N lanes)
        for (const node of uniqueTargetNodes) {
          if (node === templateNode) {
            // Template already lives here, use it directly
            tempTemplateIds[node] = gatewayVmid;
            console.log(`[Group ${group_name}] Node ${node} is template home — using original ${gatewayVmid}`);
            continue;
          }

          const tempId = TEMP_GW_TEMPLATE_BASE + tempIdCounter++;
          try {
            console.log(`[Group ${group_name}] Replicating gateway template → ${tempId} on ${node}...`);
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
              newid: tempId,
              hostname: `gw-template-temp-${node}`,
              full: 1,
              target: node,
              description: `Temp gateway template for batch deploy (group: ${group_name})`
            });
            if (cloneResult) await waitForTask(templateNode, cloneResult);
            tempTemplateIds[node] = tempId;
            console.log(`[Group ${group_name}] Gateway template replicated to ${node} as ${tempId}`);
          } catch (err) {
            console.error(`[Group ${group_name}] Failed to replicate template to ${node}: ${err.message}`);
            // Fallback: this node's lanes will clone from the original (sequentially)
            tempTemplateIds[node] = gatewayVmid;
          }
        }

        // Phase 1b: Clone all gateways IN PARALLEL — each from its node-local template copy
        progress.phase = 'gateway_cloning';
        progress.phase_detail = `Cloning ${laneJobs.length} gateways in parallel`;
        updateProgressTiming();
        console.log(`[Group ${group_name}] Phase 1b: Cloning ${laneJobs.length} gateways in parallel from node-local templates...`);
        const gatewayResults = {};

        // Group lanes by target node so clones from the same local template are serialized
        // (the local temp template still has the LXC lock constraint),
        // but different nodes run fully in parallel
        const lanesByNode = {};
        for (const job of laneJobs) {
          if (!lanesByNode[job.targetNode]) lanesByNode[job.targetNode] = [];
          lanesByNode[job.targetNode].push(job);
        }

        await Promise.all(Object.entries(lanesByNode).map(async ([node, jobs]) => {
          const localTemplateId = tempTemplateIds[node];
          const sourceNode = node === templateNode ? templateNode : node;

          for (const job of jobs) {
            const { laneId, student, vxlanId, vnet } = job;
            const gatewayVmId = 100000 + vxlanId;
            try {
              console.log(`[Group ${group_name}] Cloning gateway LXC ${localTemplateId}@${sourceNode} → ${gatewayVmId} for ${student.email}`);
              const gwCloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${sourceNode}/lxc/${localTemplateId}/clone`, {
                newid: gatewayVmId,
                hostname: `${job.laneName}-gateway`,
                full: 1,
                target: node,
                description: `Group: ${group_name}\nStudent: ${student.email}\nLane: ${laneId}`,
                pool: `${module}-pool`
              });
              if (gwCloneResult) await waitForTask(sourceNode, gwCloneResult);
              // Wire up both NICs. Networking config is scheme-aware:
              //   v1: wan0 → module transit GW; lan0 → 192.18.0.1/24 (shared)
              //   v2: wan0 → lab network (vmbr0); lan0 → 10.<vxh>.<vxl>.1/24 (unique)
              const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
              await proxmoxAPI('PUT', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/config`, {
                net0: `name=wan0,bridge=${net.wan.bridge},ip=${net.wan.ip},gw=${net.wan.gw},firewall=0,type=veth`,
                net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`
              });
              gatewayResults[laneId] = { success: true };
              console.log(`[Group ${group_name}] Gateway ${gatewayVmId} cloned on ${node}`);
            } catch (err) {
              console.error(`[Group ${group_name}] Gateway clone failed for ${student.email}: ${err.message}`);
              gatewayResults[laneId] = { success: false, error: err.message };
            }
          }
        }));

        const gwSuccessCount = Object.values(gatewayResults).filter(r => r.success).length;
        console.log(`[Group ${group_name}] Phase 1b complete: ${gwSuccessCount}/${laneJobs.length} gateways cloned`);

        // Phase 1c: Delete temporary template copies (not the original)
        const tempIdsToDelete = Object.entries(tempTemplateIds)
          .filter(([_, id]) => id !== gatewayVmid)
          .map(([node, id]) => ({ node, id }));

        if (tempIdsToDelete.length > 0) {
          progress.phase_detail = 'Cleaning up temp gateway templates';
          console.log(`[Group ${group_name}] Phase 1c: Cleaning up ${tempIdsToDelete.length} temp gateway templates...`);
          await Promise.all(tempIdsToDelete.map(async ({ node, id }) => {
            try {
              await proxmoxAPI('DELETE', `/api2/json/nodes/${node}/lxc/${id}?purge=1&force=1`);
              console.log(`[Group ${group_name}] Deleted temp template ${id} on ${node}`);
            } catch (e) {
              console.warn(`[Group ${group_name}] Could not delete temp template ${id} on ${node}: ${e.message}`);
            }
          }));
        }

        // ── Phase 2: Clone QEMU VMs + Kali in PARALLEL (no LXC lock issue) ──
        progress.phase = 'deploying';
        progress.phase_detail = `Deploying lanes (${concurrency} at a time, max ${cloneSem.max} concurrent clones)`;
        updateProgressTiming();
        console.log(`[Group ${group_name}] Phase 2: Cloning challenge VMs and Kali in parallel (concurrency: ${concurrency})...`);

        const { results, errors } = await runBatch(laneJobs, async (job) => {
          const { laneId, student, vxlanId, vnet, targetNode } = job;
          const bestNode = targetNode;

          // Skip if gateway failed for this lane
          if (!gatewayResults[laneId]?.success) {
            throw new Error(`Skipped: gateway clone failed — ${gatewayResults[laneId]?.error}`);
          }

          progress.lanes[laneId] = { student: student.email, vxlan: vxlanId, node: bestNode, status: 'cloning', _startedAt: Date.now() };
          console.log(`[Group ${group_name}] Deploying lane ${laneId} for ${student.email} on ${bestNode} (VXLAN ${vxlanId})${use_webhook ? ' via webhook' : ''}...`);

          if (use_webhook) {
            // ── Webhook mode: forward each lane to N8N ──
            const webhookRes = await fetch(N8N_DEPLOY_WEBHOOK, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                user_id: student.id,
                challenge_key,
                module,
                event_id: null
              })
            });
            if (!webhookRes.ok) {
              const errText = await webhookRes.text();
              throw new Error(`N8N webhook failed (${webhookRes.status}): ${errText}`);
            }
            const webhookData = await webhookRes.json();
            if (webhookData.lane_id || webhookData.laneId) {
              console.log(`[Group ${group_name}] Webhook deployed lane for ${student.email}:`, webhookData);
            }
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', updated_at = NOW() WHERE lane_id = $1`,
              [laneId]
            );
          } else {
            // ── Native mode: direct Proxmox API calls (multi-VM aware) ──
            const gatewayVmId = 100000 + vxlanId;
            const deployedVMs = [];

            // GOAD: per-lane MAC/IP lookup. No-op for non-GOAD specs.
            const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId);

            // Clone all challenge VMs — each clone goes through the shared semaphore
            // so we never exceed MAX_CONCURRENT_CLONES across all lanes
            const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: templateVmid, type: 'qemu', vm_offset: 600000 }];
            const clonePromises = vmSpecs.map(async (vmSpec) => {
              const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
              const vmTemplate = vmSpec.template_vmid || templateVmid;
              const vmName = vmSpec.name || challenge_key;
              const vmType = vmSpec.type || 'qemu';
              const goadMac = goadMacs[vmName]?.mac;

              await cloneSem.run(async () => {
                console.log(`[Group ${group_name}] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName}) for ${student.email}`);

                if (vmType === 'lxc') {
                  const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
                    newid: vmId, hostname: `${vmName}-${student.email.split('@')[0]}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
                    description: `Group: ${group_name}\nVM: ${vmName}\nStudent: ${student.email}\nLane: ${laneId}`,
                    pool: `${module}-pool`
                  });
                  if (result) await waitForTask(templateNode, result);
                  await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, {
                    net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vnet.vnet, goadMac)
                  });
                } else {
                  const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
                    newid: vmId, name: `${vmName}-${student.email.split('@')[0]}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
                    description: `Group: ${group_name}\nVM: ${vmName}\nStudent: ${student.email}\nLane: ${laneId}`,
                    pool: `${module}-pool`
                  });
                  if (result) await waitForTask(templateNode, result);
                  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
                    net0: goadDeploy.buildLaneNet0(vmSpec, vnet.vnet, goadMac)
                  });
                }
              });

              return { vm_id: vmId, name: vmName, type: vmType, node: bestNode };
            });

            // Clone attack box (QEMU) — also through the semaphore
            const shouldDeployAttackBox = !!attack_boxes;
            let attackBoxVmId = shouldDeployAttackBox ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null;
            const studentUsername = student.email.split('@')[0].replace(/[^a-z0-9_-]/gi, '-');
            const studentCred = created.credentials.find(c => c.email === student.email);
            const studentPassword = studentCred ? studentCred.password : GROUP_PASSWORD_FALLBACK;

            const kaliClonePromise = shouldDeployAttackBox ? (async () => {
              await cloneSem.run(async () => {
                console.log(`[Group ${group_name}] Cloning Kali attack box → ${attackBoxVmId} for ${student.email}...`);
                const kaliClone = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${KALI_TEMPLATE_VMID}/clone`, {
                  newid: attackBoxVmId,
                  name: `kali-${studentUsername}`,
                  full: 1,
                  target: bestNode,
                  description: `Attack Box (Kali)\nGroup: ${group_name}\nStudent: ${student.email}\nLane: ${laneId}`,
                  pool: `${module}-pool`
                });
                if (kaliClone) await waitForTask(templateNode, kaliClone);
              });

              console.log(`[Group ${group_name}] Configuring cloud-init for ${attackBoxVmId} (user: ${studentUsername})...`);
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/config`, {
                net0: `virtio,bridge=${vnet.vnet}`,
                ciuser: studentUsername,
                cipassword: studentPassword
              });
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/cloudinit`);
            })() : Promise.resolve();

            // Wait for all clones to finish (gateway already done in Phase 1)
            // Lanes queue up for clone slots via the semaphore — no lock contention
            progress.lanes[laneId].status = 'cloning';
            const [clonedVMs] = await Promise.all([
              Promise.all(clonePromises),
              kaliClonePromise
            ]);
            deployedVMs.push(...clonedVMs);

            // Start gateway first, then all challenge VMs
            progress.lanes[laneId].status = 'starting';
            await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
            await new Promise(r => setTimeout(r, 5000));
            for (const dvm of deployedVMs) {
              const startPath = dvm.type === 'lxc'
                ? `/api2/json/nodes/${dvm.node}/lxc/${dvm.vm_id}/status/start`
                : `/api2/json/nodes/${dvm.node}/qemu/${dvm.vm_id}/status/start`;
              await proxmoxAPI('POST', startPath);
            }

            // GOAD provisioning (no-op for non-GOAD specs). Each lane gets its
            // own controller clone, runs the playbook over WinRM, then stops
            // the controller. Failures are logged + recorded in lane metadata
            // but don't fail the whole batch deploy.
            if (spec.goad?.enabled) {
              progress.lanes[laneId].status = 'provisioning_goad';
              try {
                await goadDeploy.deployGoadLane({
                  lane: { lane_id: laneId },
                  spec, module, vnet, vxlanId, gatewayVmId,
                  bestNode, templateNode, deployedVMs,
                  proxmoxAPI, waitForTask, query: cybercoreQuery
                });
              } catch (goadErr) {
                console.error(`[Group ${group_name}] GOAD provisioning failed for ${student.email}: ${goadErr.message}`);
              }
            }

            // Start attack box and create Guacamole connection
            if (attackBoxVmId) {
              progress.lanes[laneId].status = 'configuring_kali';
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/status/start`);
              console.log(`[Group ${group_name}] Kali attack box ${attackBoxVmId} started for ${student.email}`);

              console.log(`[Group ${group_name}] Waiting for Kali guest agent...`);
              await new Promise(r => setTimeout(r, 30000));

              let kaliIp = null;
              for (let attempt = 0; attempt < 10 && !kaliIp; attempt++) {
                try {
                  const agentData = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/agent/network-get-interfaces`);
                  const interfaces = agentData.result || agentData || [];
                  for (const iface of interfaces) {
                    if (iface.name === 'lo') continue;
                    const ipAddrs = iface['ip-addresses'] || [];
                    for (const addr of ipAddrs) {
                      if (addr['ip-address-type'] === 'ipv4' && !addr['ip-address'].startsWith('127.')) {
                        kaliIp = addr['ip-address'];
                        console.log(`[Group ${group_name}] Kali IP via guest agent: ${kaliIp} (${iface.name})`);
                        break;
                      }
                    }
                    if (kaliIp) break;
                  }
                } catch (agentErr) {
                  console.log(`[Group ${group_name}] Guest agent attempt ${attempt + 1}/10: ${agentErr.message}`);
                }
                if (!kaliIp && attempt < 9) {
                  await new Promise(r => setTimeout(r, 5000));
                }
              }

              if (!kaliIp) {
                console.warn(`[Group ${group_name}] Could not get Kali IP via guest agent — using fallback`);
                kaliIp = '192.18.0.100';
              }
              console.log(`[Group ${group_name}] Kali IP: ${kaliIp}`);

              let gatewayTransitIp = null;
              try {
                const gwConfig = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`);
                const net0 = gwConfig.net0 || '';
                const ipMatch = net0.match(/ip=([\d.]+)/);
                if (ipMatch) {
                  gatewayTransitIp = ipMatch[1];
                }
              } catch (_) {}

              if (!gatewayTransitIp) {
                try {
                  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/exec`, {
                    command: JSON.stringify(['sh', '-c', "ip -4 addr show wan0 | grep inet | awk '{print $2}' | cut -d/ -f1"])
                  });
                } catch (_) {}
              }

              if (!gatewayTransitIp) {
                try {
                  const gwInterfaces = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/interfaces`);
                  for (const iface of (gwInterfaces || [])) {
                    if (iface.name === 'wan0' && iface.inet) {
                      gatewayTransitIp = iface.inet.split('/')[0];
                      break;
                    }
                  }
                } catch (_) {}
              }

              const guacTargetIp = gatewayTransitIp || kaliIp;
              console.log(`[Group ${group_name}] Guac RDP target: ${guacTargetIp} (${gatewayTransitIp ? 'via gateway DNAT' : 'direct to Kali'})`);

              try {
                const guacParent = created.guac_group?.identifier || 'ROOT';
                const kaliConn = await guacAPI('POST', '/connections', {
                  name: `${group_name} - ${student.email.split('@')[0]} - Kali`,
                  protocol: 'rdp',
                  parentIdentifier: guacParent,
                  parameters: {
                    hostname: guacTargetIp,
                    port: '3389',
                    username: studentUsername,
                    password: studentPassword,
                    security: 'any',
                    'ignore-cert': 'true',
                    'enable-wallpaper': 'true',
                    'enable-theming': 'true',
                    'enable-font-smoothing': 'true',
                    'enable-full-window-drag': 'true',
                    'color-depth': '24',
                    'resize-method': 'display-update'
                  },
                  attributes: {
                    'max-connections': '2',
                    'max-connections-per-user': '1'
                  }
                });

                if (kaliConn?.identifier) {
                  const connId = kaliConn.identifier;
                  // Track the connection ID so teardown can delete it explicitly.
                  // Guacamole's connectionGroup DELETE does NOT cascade to child
                  // connections — without this they become orphans at ROOT.
                  created.guac_connections.push({
                    id: connId,
                    name: `${group_name} - ${student.email.split('@')[0]} - Kali`,
                    student_email: student.email
                  });
                  try {
                    await guacAPI('PATCH', `/users/${encodeURIComponent(student.email)}/permissions`, [
                      { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' }
                    ]);
                    console.log(`[Group ${group_name}] Guac connection ${connId} → ${student.email}`);
                  } catch (permErr) {
                    console.warn(`[Group ${group_name}] Student perm failed for ${student.email}: ${permErr.message}`);
                  }

                  for (const inst of created.instructors) {
                    try {
                      await guacAPI('PATCH', `/users/${encodeURIComponent(inst.email)}/permissions`, [
                        { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' }
                      ]);
                    } catch (_) {}
                  }
                }
              } catch (guacErr) {
                console.warn(`[Group ${group_name}] Could not create Guac connection for ${student.email}: ${guacErr.message}`);
              }
            }

            // Run vuln scripts if any were selected
            if (groupVulnScripts && groupVulnScripts.length > 0) {
              progress.lanes[laneId].status = 'running_scripts';
              console.log(`[Group ${group_name}] Running ${groupVulnScripts.length} vuln scripts for ${student.email}...`);
              const scriptEntries = groupVulnScripts.map(s => ({
                script_slug: s.script_slug,
                vm_name: s.vm_name || deployedVMs[0]?.name || 'default',
                status: 'pending', error: null
              }));

              const dvsResult = await query(
                `INSERT INTO deployment_vuln_selections (lane_id, selected_scripts, status)
                 VALUES ($1, $2, 'running_scripts') RETURNING id`,
                [laneId, JSON.stringify(scriptEntries)]
              );
              const deploymentId = dvsResult.rows[0].id;

              for (const vm of deployedVMs) {
                if (vm.type !== 'qemu') continue;
                const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
                if (!agentReady) { console.error(`[Group ${group_name}] Guest agent not responding on ${vm.name}`); continue; }

                const vmScriptSlugs = groupVulnScripts.filter(s => (s.vm_name || deployedVMs[0]?.name) === vm.name).map(s => s.script_slug);
                if (vmScriptSlugs.length > 0) {
                  const scriptRows = await query(`SELECT slug, script_content, os_target, depends_on, script_args FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`, [vmScriptSlugs]);
                  if (scriptRows.rows.length > 0) {
                    await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, scriptRows.rows, deploymentId);
                  }
                }
              }

              await query(`UPDATE deployment_vuln_selections SET status = 'complete', updated_at = NOW() WHERE id = $1`, [deploymentId]);
              console.log(`[Group ${group_name}] Vuln scripts completed for ${student.email}`);
            }

            // Mark active with full config (multi-VM aware)
            const activeConfig = {
              challenge_vm_id: deployedVMs[0]?.vm_id,
              gateway_vm_id: gatewayVmId,
              attack_box_vm_id: attackBoxVmId || null,
              node: bestNode,
              challenge_key,
              module,
              group_id: groupId,
              group_name,
              vms: deployedVMs
            };
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
              [laneId, JSON.stringify(activeConfig)]
            );
          }

          progress.lanes[laneId].status = 'active';
          console.log(`[Group ${group_name}] Lane ${laneId} deployed (VXLAN ${vxlanId}, node ${bestNode}, student ${student.email}${attack_boxes ? ' + Kali' : ''})`);
          return { laneId, student: student.email, vxlanId };
        }, {
          concurrency,
          onProgress: (completed, total, job, result) => {
            progress.completed = completed;
            if (result.success) progress.succeeded++;
            else progress.failed++;

            // Track lane duration for ETA calculation
            const laneProgress = progress.lanes[job.laneId];
            if (laneProgress && laneProgress._startedAt) {
              progress._laneTimes.push(Date.now() - laneProgress._startedAt);
            }
            updateProgressTiming();
            progress.phase_detail = `Deploying lanes: ${completed}/${total} complete`;

            const etaStr = progress.eta_s != null ? ` — ETA ${Math.ceil(progress.eta_s / 60)}min` : '';
            console.log(`[Group ${group_name}] Progress: ${completed}/${total} (${progress.succeeded} ok, ${progress.failed} failed)${etaStr}`);
          }
        });

        // Handle per-lane errors (mark failed lanes)
        for (const err of errors) {
          const job = laneJobs[err.index];
          if (job) {
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'error', config = config || $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
              [job.laneId, JSON.stringify({ error: err.error })]
            ).catch(() => {});
          }
        }

        progress.phase = 'complete';
        progress.phase_detail = `${progress.succeeded} succeeded, ${progress.failed} failed`;
        progress.finished_at = new Date().toISOString();
        progress.eta_s = 0;
        progress.eta_at = null;
        updateProgressTiming();
        console.log(`[Group ${group_name}] All ${laneJobs.length} lane deployments complete (${progress.succeeded} succeeded, ${progress.failed} failed) in ${progress.elapsed_s}s.`);

        // Persist guac_connections into deployed_groups.config so teardown can find them.
        // The group row was inserted before lane deploy, so guac_connections was empty then.
        try {
          await query(
            `UPDATE deployed_groups
             SET config = jsonb_set(config::jsonb, '{guac_connections}', $1::jsonb, true)
             WHERE id = $2`,
            [JSON.stringify(created.guac_connections || []), groupId]
          );
          console.log(`[Group ${group_name}] Persisted ${created.guac_connections.length} Guac connection IDs to group config`);
        } catch (e) {
          console.warn(`[Group ${group_name}] Failed to persist guac_connections: ${e.message}`);
        }

        // Clean up progress tracker after 1 hour
        setTimeout(() => { delete global._batchDeployProgress[batchId]; }, 3600000);
      })();
    }

    logActivity(req, 'deploy_group', 'group', groupId, {
      group_name, instructors: created.instructors.length, students: created.students.length,
      lanes: created.lanes.length, deploy_lanes: shouldDeployLanes
    });

    res.json({
      success: true,
      group_id: groupId,
      group_name,
      instructors_created: created.instructors.length,
      students_created: created.students.length,
      guac_users_created: created.guac_users.length,
      guac_group: created.guac_group ? 'created' : 'failed',
      lanes_deploying: created.lanes.length,
      lanes: created.lanes,
      credentials: created.credentials
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/deploy-group/:groupId/progress — batch deployment progress
router.get('/deploy-group/:groupId/progress', authenticateToken, adminOnly, (req, res) => {
  const progress = (global._batchDeployProgress || {})[req.params.groupId];
  if (!progress) {
    return res.status(404).json({ error: 'No active batch deployment found for this group' });
  }
  // Strip internal fields and per-lane _startedAt before sending
  const { _laneTimes, ...clean } = progress;
  const cleanLanes = {};
  for (const [id, lane] of Object.entries(clean.lanes || {})) {
    const { _startedAt, ...laneClean } = lane;
    cleanLanes[id] = laneClean;
  }
  res.json({ ...clean, lanes: cleanLanes });
});

// GET /api/admin/groups — list all deployed groups
router.get('/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, group_name, config, created_by, created_at FROM deployed_groups ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/groups/:id — tear down a deployed group (delete all users + Guac resources)
// Parallelized: stops/deletes all VMs concurrently instead of one-by-one
router.delete('/groups/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(`SELECT * FROM deployed_groups WHERE id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const group = result.rows[0];
    const config = typeof group.config === 'string' ? JSON.parse(group.config) : group.config;
    const allUsers = [...(config.instructors || []), ...(config.students || [])];
    const errors = [];
    const students = config.students || [];

    // ── Phase 1: Gather all VM IDs and lane IDs upfront (one cluster query) ──
    const allVmsToDestroy = [];    // { vmid, type, label, laneId }
    const laneIds = [];
    const vmNodeMap = {};          // vmid → node (from cluster resources)

    // Fetch cluster resources (VMs + LXC) and node list ONCE
    const [clusterResources, nodeList] = await Promise.all([
      proxmoxAPI('GET', '/api2/json/cluster/resources').catch(() => []),
      proxmoxAPI('GET', '/api2/json/nodes').catch(() => [])
    ]);
    const allNodeNames = nodeList.map(n => n.node);
    if (allNodeNames.length === 0) allNodeNames.push('cyberhub-node-5');

    for (const r of clusterResources) {
      if (r.type === 'qemu' || r.type === 'lxc') {
        vmNodeMap[r.vmid] = r.node;
      }
    }

    // Collect all lanes for all students in parallel
    const studentLaneResults = await Promise.all(
      students.map(student =>
        cybercoreQuery(
          `SELECT lane_id, vxlan_id, status, config FROM cybercore_lane WHERE user_id = $1`,
          [student.id]
        ).then(r => r.rows).catch(() => [])
      )
    );

    // Look up the challenge spec so we can compute all expected VM IDs even for failed lanes
    let groupChallengeSpec = null;
    const groupChallengeKey = config.challenge_key;
    const groupModule = config.module;
    if (groupChallengeKey && groupModule) {
      try {
        const specResult = await cybercoreQuery(
          `SELECT spec FROM ${groupModule}_challenge WHERE challenge_key = $1 AND status = 'active'`,
          [groupChallengeKey]
        );
        if (specResult.rows.length > 0) {
          groupChallengeSpec = typeof specResult.rows[0].spec === 'string'
            ? JSON.parse(specResult.rows[0].spec) : specResult.rows[0].spec;
        }
      } catch (_) {}
    }

    for (const lanes of studentLaneResults) {
      for (const lane of lanes) {
        laneIds.push(lane.lane_id);
        const vxlanId = lane.vxlan_id;
        if (!vxlanId || lane.status === 'deleted') continue;

        const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

        // Use lane config vms, or fall back to computing from the challenge spec
        if (Array.isArray(laneConfig.vms) && laneConfig.vms.length > 0) {
          for (const vm of laneConfig.vms) {
            allVmsToDestroy.push({ vmid: vm.vm_id, type: vm.type || 'qemu', label: vm.name || `VM-${vm.vm_id}`, laneId: lane.lane_id });
          }
        } else if (groupChallengeSpec && Array.isArray(groupChallengeSpec.vms) && groupChallengeSpec.vms.length > 0) {
          // Compute VM IDs from challenge spec (handles failed lanes with no vms array)
          for (const vmSpec of groupChallengeSpec.vms) {
            const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
            allVmsToDestroy.push({ vmid: vmId, type: vmSpec.type || 'qemu', label: vmSpec.name || `VM-${vmId}`, laneId: lane.lane_id });
          }
        } else {
          const challengeVmId = laneConfig.challenge_vm_id || (600000 + vxlanId);
          allVmsToDestroy.push({ vmid: challengeVmId, type: 'qemu', label: 'challenge', laneId: lane.lane_id });
        }

        const gatewayVmId = laneConfig.gateway_vm_id || (100000 + vxlanId);
        allVmsToDestroy.push({ vmid: gatewayVmId, type: 'lxc', label: 'gateway', laneId: lane.lane_id });

        const attackBoxVmId = laneConfig.attack_box_vm_id || (ATTACK_BOX_VMID_OFFSET + vxlanId);
        allVmsToDestroy.push({ vmid: attackBoxVmId, type: 'qemu', label: 'attack-box', laneId: lane.lane_id });

        // GOAD controller VM — always included defensively. Filtered out by
        // cluster-resources lookup if the lane wasn't a GOAD lane.
        const goadControllerVmId = 200000 + vxlanId;
        allVmsToDestroy.push({ vmid: goadControllerVmId, type: 'qemu', label: 'goad-controller', laneId: lane.lane_id });
      }
    }

    console.log(`[Group Teardown] ${group.group_name}: ${allVmsToDestroy.length} VMs to destroy across ${laneIds.length} lanes`);

    // Only operate on VMs that actually exist in the cluster
    const existingVms = allVmsToDestroy.filter(vm => vmNodeMap[vm.vmid]);
    const missingVms = allVmsToDestroy.length - existingVms.length;
    if (missingVms > 0) {
      console.log(`[Group Teardown] ${missingVms} VMs not found in cluster (already deleted or never created)`);
    }

    // ── Phase 2: Unprotect + force-stop all VMs in parallel ──
    console.log(`[Group Teardown] Phase 2: Unprotecting and force-stopping ${existingVms.length} VMs...`);
    await Promise.all(existingVms.map(async (vm) => {
      const node = vmNodeMap[vm.vmid];
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/config`, { protection: 0 }); } catch (_) {}
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/config`, { lock: '' }); } catch (_) {}
    }));

    // Force-stop: QEMU accepts timeout=0 for immediate kill; LXC does NOT accept `timeout`
    // (LXC stop is always immediate — passing timeout causes a 400 error, silently swallowed,
    // leaving the container running and blocking the subsequent DELETE). Pass per-type params.
    const stopTasks = [];
    await Promise.all(existingVms.map(async (vm) => {
      const node = vmNodeMap[vm.vmid];
      try {
        const stopBody = vm.type === 'qemu' ? { timeout: 0 } : {};
        const upid = await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/stop`, stopBody);
        if (upid) stopTasks.push({ node, upid, type: vm.type, vmid: vm.vmid });
      } catch (e) {
        console.warn(`[Group Teardown] Stop failed for ${vm.type} ${vm.vmid} on ${node}: ${e.message}`);
      }
    }));

    // Wait for stop tasks to actually complete (poll up to 30s)
    console.log(`[Group Teardown] Waiting for ${stopTasks.length} stop tasks to complete...`);
    const stopDeadline = Date.now() + 30000;
    let pendingStops = [...stopTasks];
    while (pendingStops.length > 0 && Date.now() < stopDeadline) {
      await new Promise(r => setTimeout(r, 3000));
      const stillPending = [];
      for (const task of pendingStops) {
        try {
          const status = await proxmoxAPI('GET', `/api2/json/nodes/${task.node}/tasks/${encodeURIComponent(task.upid)}/status`);
          if (status.status !== 'stopped') stillPending.push(task);
        } catch (_) {
          // Task query failed, assume done
        }
      }
      pendingStops = stillPending;
    }
    if (pendingStops.length > 0) {
      console.warn(`[Group Teardown] ${pendingStops.length} stop tasks still pending after 30s, proceeding with delete...`);
    }

    // ── Phase 3: Delete all VMs in parallel ──
    // Proxmox DELETE params are type-specific:
    //   QEMU: accepts `purge` and `skiplock` — REJECTS `force` (400 error)
    //   LXC:  accepts `purge` and `force` — REJECTS `skiplock` on recent versions
    // `force=1` is REQUIRED for LXC containers that are still running.
    const buildDeleteUrl = (node, type, vmid) => type === 'lxc'
      ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
      : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1&skiplock=1`;

    console.log(`[Group Teardown] Phase 3: Deleting ${existingVms.length} VMs...`);
    const { errors: destroyErrors } = await runBatch(existingVms, async (vm) => {
      const knownNode = vmNodeMap[vm.vmid];
      const nodesToTry = knownNode ? [knownNode, ...allNodeNames.filter(n => n !== knownNode)] : allNodeNames;

      for (const node of nodesToTry) {
        try {
          try {
            await proxmoxAPI('DELETE', buildDeleteUrl(node, vm.type, vm.vmid));
          } catch (_) {
            // Fallback: strip skiplock for QEMU (some older versions), keep force for LXC
            const fallback = vm.type === 'lxc'
              ? `/api2/json/nodes/${node}/lxc/${vm.vmid}?purge=1&force=1`
              : `/api2/json/nodes/${node}/qemu/${vm.vmid}?purge=1`;
            await proxmoxAPI('DELETE', fallback);
          }
          console.log(`[Group Teardown] Destroyed ${vm.type} ${vm.vmid} (${vm.label}) on ${node}`);
          return;
        } catch (e) {
          // "configuration file not found" just means the VM is already gone — treat as success
          if (/unable to find configuration file/i.test(e.message) || /does not exist/i.test(e.message)) {
            console.log(`[Group Teardown] ${vm.type} ${vm.vmid} already gone on ${node}`);
            return;
          }
          if (node === nodesToTry[nodesToTry.length - 1]) {
            throw new Error(`${vm.type} ${vm.vmid} (${vm.label}): failed on all nodes — ${e.message}`);
          }
        }
      }
    }, { concurrency: 15 });

    for (const err of destroyErrors) {
      errors.push(err.error);
    }

    // ── Phase 4: Verify and retry orphans (up to 3 rounds) ──
    let orphanedCount = 0;
    const allTargetVmIds = allVmsToDestroy.map(v => v.vmid);

    for (let round = 1; round <= 3; round++) {
      try {
        const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
        const stillAlive = resources.filter(r => (r.type === 'qemu' || r.type === 'lxc') && allTargetVmIds.includes(r.vmid));
        if (stillAlive.length === 0) {
          console.log(`[Group Teardown] All VMs confirmed destroyed${round > 1 ? ` (after ${round - 1} retry rounds)` : ''}`);
          break;
        }

        orphanedCount = stillAlive.length;
        console.warn(`[Group Teardown] Round ${round}: ${stillAlive.length} VMs still exist — retrying...`);

        // Force-stop + delete each orphan — use type-aware stop body (LXC rejects `timeout`)
        await Promise.all(stillAlive.map(async (vm) => {
          try {
            try { await proxmoxAPI('PUT', `/api2/json/nodes/${vm.node}/${vm.type}/${vm.vmid}/config`, { protection: 0 }); } catch (_) {}
            const stopBody = vm.type === 'qemu' ? { timeout: 0 } : {};
            try { await proxmoxAPI('POST', `/api2/json/nodes/${vm.node}/${vm.type}/${vm.vmid}/status/stop`, stopBody); } catch (_) {}
          } catch (_) {}
        }));

        await new Promise(r => setTimeout(r, 8000));

        await Promise.all(stillAlive.map(async (vm) => {
          try {
            try {
              await proxmoxAPI('DELETE', buildDeleteUrl(vm.node, vm.type, vm.vmid));
            } catch (_) {
              // Fallback with type-specific params (LXC needs force; QEMU rejects force)
              const fallback = vm.type === 'lxc'
                ? `/api2/json/nodes/${vm.node}/lxc/${vm.vmid}?purge=1&force=1`
                : `/api2/json/nodes/${vm.node}/qemu/${vm.vmid}?purge=1`;
              await proxmoxAPI('DELETE', fallback);
            }
            console.log(`[Group Teardown] Retry round ${round}: destroyed ${vm.type} ${vm.vmid} on ${vm.node}`);
          } catch (e) {
            if (/unable to find configuration file/i.test(e.message)) {
              console.log(`[Group Teardown] Retry round ${round}: ${vm.type} ${vm.vmid} already gone`);
              return;
            }
            if (round === 3) errors.push(`Orphaned VM ${vm.vmid} on ${vm.node}: ${e.message}`);
          }
        }));
      } catch (e) {
        console.error(`[Group Teardown] Verify round ${round} failed: ${e.message}`);
        break;
      }
    }

    // ── Phase 5: Cleanup DB and Guac in parallel ──
    const allUserIds = allUsers.map(u => u.id);
    const allUserEmails = allUsers.map(u => u.email);

    await Promise.all([
      laneIds.length > 0
        ? cybercoreQuery(`DELETE FROM cybercore_lane WHERE lane_id = ANY($1)`, [laneIds]).catch(e => errors.push(`Lane cleanup: ${e.message}`))
        : Promise.resolve(),

      allUserIds.length > 0
        ? cybercoreQuery(`DELETE FROM cybercore_user WHERE user_id = ANY($1) OR username = ANY($2)`, [allUserIds, allUserEmails]).catch(e => errors.push(`User cleanup: ${e.message}`))
        : Promise.resolve(),

      ...((config.guac_users || []).map(username =>
        guacAPI('DELETE', `/users/${encodeURIComponent(username)}`).catch(e => errors.push(`Guac delete ${username}: ${e.message}`))
      )),

      // Delete individual Guac connections FIRST — guacAPI DELETE on connectionGroup does
      // NOT cascade to child connections; leaving this out makes them orphans at ROOT.
      ...((config.guac_connections || []).map(conn =>
        guacAPI('DELETE', `/connections/${encodeURIComponent(conn.id)}`).catch(e => errors.push(`Guac connection ${conn.id} (${conn.name || '?'}): ${e.message}`))
      )),

      config.guac_group?.identifier
        ? guacAPI('DELETE', `/connectionGroups/${config.guac_group.identifier}`).catch(e => errors.push(`Guac group delete: ${e.message}`))
        : Promise.resolve()
    ]);

    // ── Phase 6: Sweep orphaned disks for any destroyed VMIDs ──
    // Even with purge=1, multi-disk VMs can leak disk images when the VM config is gone but
    // individual disk cleanups failed. Query every storage on every node and free any
    // vm-<destroyed_vmid>-disk-* entries that don't have a live VM.
    //
    // SERIALIZED: Parallel `DELETE /storage/*/content/*` calls fight over cfs-lock
    // (Proxmox cluster FS write lock) and RBD/Ceph rados locks, producing 500 errors
    // like "cfs-lock 'storage-vmpool'" and "rbd error: rbd: error op...". Deletes must
    // be serialized per-storage. We also skip duplicate volids across nodes (shared
    // storage like Ceph RBD shows the same disk on every node — delete once).
    const destroyedVmIdSet = new Set(allVmsToDestroy.map(v => v.vmid));
    let orphanDisksSwept = 0;
    const orphanDiskErrors = [];
    const sweptVolids = new Set();

    try {
      // Pass 1: discover orphan disks (safe to do in parallel — read-only)
      const orphanDisks = [];
      const discoveries = await Promise.all(allNodeNames.map(async (node) => {
        const found = [];
        let nodeStorages;
        try {
          nodeStorages = await proxmoxAPI('GET', `/api2/json/nodes/${node}/storage`);
        } catch (_) { return found; }

        for (const s of nodeStorages || []) {
          if (s.content && !s.content.includes('images')) continue;
          let contents;
          try {
            contents = await proxmoxAPI('GET',
              `/api2/json/nodes/${node}/storage/${s.storage}/content?content=images`);
          } catch (_) { continue; }

          for (const item of contents || []) {
            const match = item.volid?.match(/vm-(\d+)-disk/);
            if (!match) continue;
            const vmid = parseInt(match[1]);
            if (!destroyedVmIdSet.has(vmid)) continue;
            found.push({ node, storage: s.storage, volid: item.volid });
          }
        }
        return found;
      }));
      for (const arr of discoveries) orphanDisks.push(...arr);

      // Pass 2: delete serially — RBD/Ceph and cfs-lock contention forbid parallelism.
      // Retry each delete up to 3 times with a short backoff to tolerate brief cfs-lock contention.
      for (const d of orphanDisks) {
        if (sweptVolids.has(d.volid)) continue; // shared storage: same volid on multiple nodes
        sweptVolids.add(d.volid);

        let deleted = false;
        let lastErr = null;
        for (let attempt = 1; attempt <= 3 && !deleted; attempt++) {
          try {
            await proxmoxAPI('DELETE',
              `/api2/json/nodes/${d.node}/storage/${d.storage}/content/${encodeURIComponent(d.volid)}`);
            console.log(`[Group Teardown] Swept orphaned disk: ${d.volid} on ${d.node}/${d.storage}`);
            orphanDisksSwept++;
            deleted = true;
          } catch (e) {
            lastErr = e;
            // cfs-lock and RBD contention both benefit from a short wait
            if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
          }
        }
        if (!deleted && lastErr) {
          orphanDiskErrors.push(`${d.volid}: ${lastErr.message}`);
        }
      }
    } catch (e) {
      console.error(`[Group Teardown] Orphan disk sweep failed: ${e.message}`);
      orphanDiskErrors.push(`Sweep error: ${e.message}`);
    }

    if (orphanDisksSwept > 0) {
      console.log(`[Group Teardown] Swept ${orphanDisksSwept} orphaned disk images`);
    }
    if (orphanDiskErrors.length > 0) {
      errors.push(...orphanDiskErrors.map(e => `Disk sweep: ${e}`));
    }

    // 7. Remove group record
    await query(`DELETE FROM deployed_groups WHERE id = $1`, [req.params.id]);

    logActivity(req, 'delete_group', 'group', req.params.id, {
      group_name: group.group_name, users_deleted: allUsers.length, lanes_deleted: laneIds.length,
      vms_destroyed: allVmsToDestroy.length, orphaned_vms_found: orphanedCount,
      orphan_disks_swept: orphanDisksSwept, errors: errors.length
    });

    res.json({
      success: true,
      users_deleted: allUsers.length,
      lanes_deleted: laneIds.length,
      vms_destroyed: allVmsToDestroy.length,
      orphaned_vms_retried: orphanedCount,
      orphan_disks_swept: orphanDisksSwept,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ORPHANED DISK SWEEP
// ============================================================================
// Standalone cleanup for disk images whose parent VM no longer exists in the cluster.
// This happens when teardowns partially succeed — VM config destroyed, disks leaked.
//
// Usage:
//   POST /api/admin/sweep-orphaned-disks
//   Body: {
//     dry_run: true,                  // REQUIRED for safety on first call
//     vmid_pattern: "^(6|1|7)\\d{5}$", // optional regex to scope what counts as a "managed" VM
//     storage: "local-zfs"            // optional: limit to one storage name
//   }
//
// Default behavior: find every vm-XXXXX-disk-Y image on every storage on every node;
// if the VMID does NOT match a live VM in the cluster, it's an orphan. Returns a full
// report when dry_run=true, performs deletions when dry_run=false.

router.post('/sweep-orphaned-disks', authenticateToken, adminOnly, async (req, res) => {
  const dry_run = req.body?.dry_run !== false; // default to dry-run for safety
  const storageFilter = req.body?.storage || null;
  const vmidPattern = req.body?.vmid_pattern ? new RegExp(req.body.vmid_pattern) : null;
  const orphans = [];
  const deleted = [];
  const errors = [];

  try {
    // 1. Enumerate live VMs across the cluster (both qemu and lxc)
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
    const liveVmIds = new Set();
    for (const r of resources || []) {
      if (r.type === 'qemu' || r.type === 'lxc') {
        if (typeof r.vmid === 'number') liveVmIds.add(r.vmid);
      }
    }

    // 2. Enumerate nodes
    const nodes = await proxmoxAPI('GET', '/api2/json/nodes');

    // 3. Walk each node's storage
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

          // If caller supplied a VMID regex, only consider disks whose VMID matches
          // (lets you scope the sweep to "managed" ranges like 6xxxxx / 1xxxxx / 7xxxxx)
          if (vmidPattern && !vmidPattern.test(String(vmid))) continue;

          // If the VM is live, this disk is not an orphan
          if (liveVmIds.has(vmid)) continue;

          const orphan = {
            node: node.node,
            storage: s.storage,
            volid: item.volid,
            vmid,
            size_bytes: item.size || 0,
            size_gb: item.size ? (item.size / (1024 ** 3)).toFixed(2) : '0.00'
          };
          orphans.push(orphan);
        }
      }
    }

    // Deduplicate by volid (shared storage like Ceph RBD shows same disk on every node)
    const dedupedOrphans = [];
    const seenVolids = new Set();
    for (const o of orphans) {
      if (seenVolids.has(o.volid)) continue;
      seenVolids.add(o.volid);
      dedupedOrphans.push(o);
    }

    // Pass 2 — delete serially if not dry run. Ceph RBD rados locks and Proxmox cfs-lock
    // can't tolerate parallel DELETE calls on the same storage; they produce 500 errors
    // like "cfs-lock 'storage-vmpool' failed" and "rbd: error op...". Serial with retry works.
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

    // entity_id is UUID in activity_log — stash storage filter in metadata instead
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

// GET /api/admin/activity-log — paginated, filterable activity log
router.get('/activity-log', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { action_type, user_id: filterUserId, from, to, limit: lim, offset: off, search } = req.query;
    const limit = Math.min(parseInt(lim) || 50, 200);
    const offset = parseInt(off) || 0;

    let where = [];
    let params = [];
    let paramIdx = 1;

    if (action_type) {
      where.push(`a.action_type = $${paramIdx++}`);
      params.push(action_type);
    }
    if (filterUserId) {
      where.push(`a.user_id = $${paramIdx++}`);
      params.push(filterUserId);
    }
    if (from) {
      where.push(`a.created_at >= $${paramIdx++}`);
      params.push(from);
    }
    if (to) {
      where.push(`a.created_at <= $${paramIdx++}`);
      params.push(to);
    }
    if (search) {
      where.push(`(a.action_type ILIKE $${paramIdx} OR a.entity_type ILIKE $${paramIdx})`);
      params.push(`%${search}%`);
      paramIdx++;
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const [logs, countResult] = await Promise.all([
      query(
        `SELECT a.*
         FROM activity_log a
         ${whereClause}
         ORDER BY a.created_at DESC
         LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
        [...params, limit, offset]
      ),
      query(
        `SELECT COUNT(*) AS total FROM activity_log a ${whereClause}`,
        params
      )
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
// USER MANAGEMENT
// ============================================================================

// GET /api/admin/users — list all users from cybercore_user
router.get('/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    // Get users from cybercore_user (single source of truth)
    const usersResult = await cybercoreQuery(
      `SELECT user_id AS id, email, first_name, last_name, role, organization,
              active AS is_active, last_auth_at AS last_login, created_at
       FROM cybercore_user
       ORDER BY created_at DESC`
    );

    // Get deployed groups from clinic_db (if available) to enrich user data
    let groups = [];
    try {
      const groupsResult = await query(
        `SELECT id, group_name, config FROM deployed_groups`
      );
      groups = groupsResult.rows;
    } catch (e) { /* clinic_db may not be available if CIAB plugin not loaded */ }

    // Merge group info into users
    const users = usersResult.rows.map(u => {
      const group = groups.find(g => {
        const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
        const allMembers = [...(cfg.students || []), ...(cfg.instructors || [])];
        return allMembers.some(m => m.id === u.id);
      });
      return {
        ...u,
        group_name: group?.group_name || null,
        group_id: group?.id || null
      };
    });

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/admin/groups/:id/toggle-active — bulk toggle is_active for all students in a group
router.patch('/groups/:id/toggle-active', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { active } = req.body; // true or false
    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'active (boolean) required' });
    }

    const result = await query(`SELECT * FROM deployed_groups WHERE id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const config = typeof result.rows[0].config === 'string'
      ? JSON.parse(result.rows[0].config) : result.rows[0].config;
    const students = config.students || [];

    if (students.length === 0) {
      return res.status(400).json({ error: 'No students in this group' });
    }

    const studentIds = students.map(s => s.id);
    const updated = await cybercoreQuery(
      `UPDATE cybercore_user SET active = $1, status = CASE WHEN $1 THEN 'active' ELSE 'inactive' END, updated_at = NOW()
       WHERE user_id = ANY($2) AND role = 'student'
       RETURNING user_id, email, active`,
      [active, studentIds]
    );

    // Stop or start VMs for all student lanes
    let lanesToggled = 0;
    const vmErrors = [];

    for (const student of students) {
      try {
        const lanesResult = await cybercoreQuery(
          `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane
           WHERE user_id = $1 AND status IN ('active', 'suspended')`,
          [student.id]
        );

        for (const lane of lanesResult.rows) {
          const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
          const node = laneConfig.node;
          if (!node) continue;

          // Collect all VM IDs for this lane
          const vmsToToggle = [];
          if (Array.isArray(laneConfig.vms)) {
            for (const vm of laneConfig.vms) {
              vmsToToggle.push({ vmid: vm.vm_id, type: vm.type || 'qemu' });
            }
          } else if (laneConfig.challenge_vm_id) {
            vmsToToggle.push({ vmid: laneConfig.challenge_vm_id, type: 'qemu' });
          }
          const gatewayVmId = laneConfig.gateway_vm_id || laneConfig.lane_gateway_vm_id;
          if (gatewayVmId) vmsToToggle.push({ vmid: gatewayVmId, type: 'lxc' });
          if (laneConfig.attack_box_vm_id) vmsToToggle.push({ vmid: laneConfig.attack_box_vm_id, type: 'qemu' });

          if (!active) {
            // DISABLING: stop all VMs and mark lane as suspended
            for (const vm of vmsToToggle) {
              try {
                await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/stop`);
                console.log(`[Toggle] Stopped ${vm.type} ${vm.vmid} on ${node}`);
              } catch (e) {
                vmErrors.push(`Stop ${vm.type} ${vm.vmid}: ${e.message}`);
              }
            }
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'suspended', updated_at = NOW() WHERE lane_id = $1`,
              [lane.lane_id]
            );
          } else {
            // ENABLING: start all VMs and mark lane as active
            // Start gateway first, then challenge VMs
            const gateway = vmsToToggle.find(v => v.type === 'lxc');
            const others = vmsToToggle.filter(v => v !== gateway);

            if (gateway) {
              try {
                await proxmoxAPI('POST', `/api2/json/nodes/${node}/${gateway.type}/${gateway.vmid}/status/start`);
                console.log(`[Toggle] Started gateway ${gateway.vmid} on ${node}`);
              } catch (e) { vmErrors.push(`Start gateway ${gateway.vmid}: ${e.message}`); }
              await new Promise(r => setTimeout(r, 3000));
            }

            for (const vm of others) {
              try {
                await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/start`);
                console.log(`[Toggle] Started ${vm.type} ${vm.vmid} on ${node}`);
              } catch (e) { vmErrors.push(`Start ${vm.type} ${vm.vmid}: ${e.message}`); }
            }

            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', updated_at = NOW() WHERE lane_id = $1`,
              [lane.lane_id]
            );
          }
          lanesToggled++;
        }
      } catch (e) {
        vmErrors.push(`Lane lookup for ${student.email}: ${e.message}`);
      }
    }

    // Also kill active Guacamole sessions if disabling (so they disconnect immediately)
    if (!active) {
      try {
        const activeSessions = await guacAPI('GET', '/activeConnections');
        const studentEmails = students.map(s => s.email);
        const toKill = Object.entries(activeSessions || {})
          .filter(([, session]) => studentEmails.includes(session.username))
          .map(([connId]) => ({ op: 'remove', path: `/${connId}` }));

        if (toKill.length > 0) {
          const token = await getGuacToken();
          await fetch(`${GUAC_URL}/api/session/data/${GUAC_DS}/activeConnections?token=${token}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(toKill)
          });
          console.log(`[Toggle] Killed ${toKill.length} Guacamole sessions`);
        }
      } catch (e) {
        console.error('[Toggle] Failed to kill Guac sessions:', e.message);
      }
    }

    logActivity(req, 'toggle_accounts', 'group', req.params.id, {
      group_name: result.rows[0].group_name, active, students_updated: updated.rows.length
    });

    res.json({
      success: true,
      group_name: result.rows[0].group_name,
      active,
      students_updated: updated.rows.length,
      lanes_toggled: lanesToggled,
      vm_errors: vmErrors.length > 0 ? vmErrors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACCOUNT SCHEDULES
// ============================================================================

// GET /api/admin/groups/:id/schedule — get the access schedule for a group
router.get('/groups/:id/schedule', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM account_schedules WHERE group_id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.json({ group_id: req.params.id, schedule: null });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/groups/:id/schedule — create or update schedule
router.put('/groups/:id/schedule', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { active_days, active_start, active_end, timezone } = req.body;

    // Validate
    if (!Array.isArray(active_days) || active_days.some(d => d < 0 || d > 6)) {
      return res.status(400).json({ error: 'active_days must be array of 0-6 (Sun-Sat)' });
    }
    if (!active_start || !active_end) {
      return res.status(400).json({ error: 'active_start and active_end required (HH:MM format)' });
    }

    // Verify group exists
    const groupResult = await query(`SELECT id FROM deployed_groups WHERE id = $1`, [req.params.id]);
    if (groupResult.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const result = await query(
      `INSERT INTO account_schedules (group_id, active_days, active_start, active_end, timezone)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (group_id) DO UPDATE SET
         active_days = EXCLUDED.active_days,
         active_start = EXCLUDED.active_start,
         active_end = EXCLUDED.active_end,
         timezone = COALESCE(EXCLUDED.timezone, account_schedules.timezone),
         updated_at = NOW()
       RETURNING *`,
      [req.params.id, active_days, active_start, active_end, timezone || 'America/Chicago']
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/admin/groups/:id/schedule/override — instructor override for schedule
router.patch('/groups/:id/schedule/override', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { override_active } = req.body; // true, false, or null

    if (override_active !== true && override_active !== false && override_active !== null) {
      return res.status(400).json({ error: 'override_active must be true, false, or null' });
    }

    const result = await query(
      `UPDATE account_schedules
       SET override_active = $1,
           override_by = $2,
           override_at = NOW(),
           updated_at = NOW()
       WHERE group_id = $3
       RETURNING *`,
      [override_active, req.user.userId, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No schedule found for this group. Create one first.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CHALLENGE NETWORK DEPLOYMENT
// ============================================================================

// POST /api/admin/deploy-challenge-network — deploy VMs from a template, then run vuln scripts
router.post('/deploy-challenge-network', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { template_id, user_id: targetUserId, selected_scripts, module, confirm } = req.body;
    const userId = targetUserId || req.user.userId;

    if (!template_id) {
      return res.status(400).json({ error: 'template_id is required' });
    }

    // Load challenge from cybercore_db (crucible_challenge is the source of truth)
    const challengeModule = module || 'crucible';
    const mod = challengeModule.replace(/[^a-z0-9_]/gi, '');
    const tplResult = await cybercoreQuery(
      `SELECT * FROM ${mod}_challenge WHERE challenge_id = $1 AND status = 'active'`,
      [template_id]
    );
    if (tplResult.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });
    const template = tplResult.rows[0];
    const spec = typeof template.spec === 'string' ? JSON.parse(template.spec) : (template.spec || {});
    const vmSpecs = spec.vms || (spec.template_vmid ? [{ name: template.challenge_key, template_vmid: spec.template_vmid, type: 'qemu', vm_offset: 600000 }] : []);

    if (!vmSpecs || vmSpecs.length === 0) {
      return res.status(400).json({ error: 'Template has no VM specs defined' });
    }

    // Pre-flight resource check
    if (!confirm) {
      try {
        const preview = await buildDeployPreview({
          numLanes: 1,
          attackBoxes: false,
          challengeVmCount: vmSpecs.length,
          proxmoxAPI,
          cybercoreQuery
        });
        preview.template_name = template.name;
        preview.vm_count = vmSpecs.length;
        return res.json({ preview: true, ...preview });
      } catch (err) {
        console.error('[ChallengeNetwork] Pre-flight check failed:', err.message);
      }
    }

    // Build the spec object compatible with the existing deploy-lane flow
    const subnetScheme = template.subnet_scheme || 'v1';

    // v2 + GOAD not yet supported (see single-deploy site for full reasoning)
    if (subnetScheme === 'v2' && spec?.goad?.enabled) {
      return res.status(501).json({
        error: 'v2 lane subnet is not yet compatible with GOAD challenges',
        detail: 'GOAD playbooks still hardcode 192.18.0.0/24. Use subnet_scheme=v1 for GOAD challenges, or wait for the goad-deploy.js + controller bake follow-up.'
      });
    }

    const gatewayVmid = resolveGatewayVmid(challengeModule, subnetScheme, spec);
    const templateNode = vmSpecs[0]?.template_node || 'cyberhub-node-5';
    console.log(`[ChallengeNetwork] subnet_scheme=${subnetScheme} → gateway template=${gatewayVmid}`);
    const bestNodeInfo = await selectBestNode();
    const bestNode = bestNodeInfo.node;
    console.log(`[ChallengeNetwork] Selected node ${bestNode} for deployment (score: ${bestNodeInfo.score})`);

    // Allocate VXLAN from the challenge's VXLAN block (set by "Add New Crucible Challenge" N8N workflow)
    const vxlanBlock = (spec.vxlan_block?.start && spec.vxlan_block?.end)
      ? spec.vxlan_block
      : { start: 10000, end: 10009 };
    console.log(`[ChallengeNetwork] Using VXLAN block ${vxlanBlock.start}-${vxlanBlock.end} from challenge '${template.challenge_key}'`);

    const vxlanResult = await cybercoreQuery(
      `WITH used AS (
        SELECT DISTINCT vxlan_id FROM cybercore_lane
        WHERE vxlan_id IS NOT NULL AND vxlan_id BETWEEN $1 AND $2 AND status NOT IN ('error')
      )
      SELECT gs AS vxlan_id FROM generate_series($1::int, $2::int) AS gs
      LEFT JOIN used u ON u.vxlan_id = gs
      WHERE u.vxlan_id IS NULL ORDER BY gs LIMIT 1`,
      [vxlanBlock.start, vxlanBlock.end]
    );
    if (vxlanResult.rows.length === 0) {
      return res.status(503).json({ error: `No available VXLAN IDs in block ${vxlanBlock.start}-${vxlanBlock.end}` });
    }
    const vxlanId = vxlanResult.rows[0].vxlan_id;

    // Find VNet — if it doesn't exist, create the SDN zone + VNet (like the N8N workflow does)
    let vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    let vnet = vnets.find(v => v.tag === vxlanId);

    if (!vnet) {
      console.log(`[ChallengeNetwork] VNet for tag ${vxlanId} not found — creating SDN infrastructure...`);

      // Determine zone abbreviation from spec or challenge_key
      const zoneAbbrev = spec.zone?.abbrev || template.challenge_key?.substring(0, 8)?.replace(/[^a-z0-9]/gi, '').substring(0, 8) || 'chlng001';

      // Check if the SDN zone exists
      const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
      const zoneExists = zones.some(z => z.zone === zoneAbbrev);

      if (!zoneExists) {
        // Get cluster node info for VXLAN zone creation
        const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
        const nodeNames = nodeList.map(n => n.node).join(',');
        const nodeIps = nodeList.map(n => n.ip || `100.100.10.${10 + nodeList.indexOf(n)}`).join(',');

        console.log(`[ChallengeNetwork] Creating SDN zone '${zoneAbbrev}' with nodes: ${nodeNames}`);
        await proxmoxAPI('POST', '/api2/json/cluster/sdn/zones', {
          zone: zoneAbbrev,
          type: 'vxlan',
          peers: nodeIps,
          ipam: 'pve'
        });
      }

      // Create the VNet for this VXLAN ID
      const vnetName = `${zoneAbbrev}-${vxlanId}`;
      console.log(`[ChallengeNetwork] Creating VNet '${vnetName}' with tag ${vxlanId} in zone '${zoneAbbrev}'`);
      await proxmoxAPI('POST', '/api2/json/cluster/sdn/vnets', {
        vnet: vnetName,
        zone: zoneAbbrev,
        tag: vxlanId,
        alias: `${zoneAbbrev}-vnet-${vxlanId}`
      });

      // Reload SDN so the VNet becomes active
      console.log('[ChallengeNetwork] Reloading SDN configuration...');
      await proxmoxAPI('PUT', '/api2/json/cluster/sdn');

      // Wait a moment for SDN to propagate
      await new Promise(r => setTimeout(r, 5000));

      // Re-fetch VNets
      vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      vnet = vnets.find(v => v.tag === vxlanId);

      if (!vnet) {
        return res.status(503).json({ error: `Failed to create VNet for VXLAN tag ${vxlanId}. SDN may need manual reload.` });
      }

      console.log(`[ChallengeNetwork] SDN infrastructure created: zone=${zoneAbbrev}, vnet=${vnet.vnet}`);
    }

    // Verify user exists in cybercore_user
    const userResult = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role FROM cybercore_user WHERE user_id = $1`, [userId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = userResult.rows[0];

    // Create lane record
    const laneName = `challenge-${vnet.zone}-${vxlanId}`;
    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
       RETURNING lane_id`,
      [userId, vxlanId, laneName, JSON.stringify({ template_id: template.id, template_name: template.name, module: challengeModule }), challengeModule]
    );
    const laneId = laneInsert.rows[0].lane_id;

    // Build selected_scripts list for tracking
    const scriptsToRun = selected_scripts || [];
    const scriptEntries = scriptsToRun.map(s => ({
      script_slug: s.script_slug,
      vm_name: s.vm_name,
      status: 'pending',
      error: null,
      output: null
    }));

    // Create deployment tracking record (clinic_db)
    const dvsResult = await query(
      `INSERT INTO deployment_vuln_selections (lane_id, challenge_key, selected_scripts, status)
       VALUES ($1, $2, $3, 'deploying')
       RETURNING id`,
      [laneId, template.challenge_key, JSON.stringify(scriptEntries)]
    );
    const deploymentId = dvsResult.rows[0].id;

    // Respond immediately
    res.json({
      success: true,
      lane_id: laneId,
      deployment_id: deploymentId,
      vxlan_id: vxlanId,
      template: template.name,
      vm_count: vmSpecs.length,
      scripts_count: scriptEntries.length,
      message: 'Challenge network deployment started. Poll status endpoint for progress.'
    });

    logActivity(req, 'deploy_challenge_network', 'lane', laneId, {
      template_id: template.id, template_name: template.name, vxlan_id: vxlanId, vm_count: vmSpecs.length
    });

    // ---- Background deployment ----
    (async () => {
      try {
        const deployedVMs = [];

        // GOAD: per-lane MAC/IP lookup. No-op for non-GOAD specs.
        const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId);

        // Clone all VMs
        for (const vmSpec of vmSpecs) {
          const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
          const vmType = vmSpec.type || 'qemu';
          const vmTemplate = vmSpec.template_vmid;
          const vmName = vmSpec.name || `vm-${vmId}`;
          const goadMac = goadMacs[vmName]?.mac;

          if (!vmTemplate) {
            console.error(`[ChallengeNetwork] VM ${vmName} has no template_vmid, skipping`);
            continue;
          }

          console.log(`[ChallengeNetwork] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName})`);

          if (vmType === 'lxc') {
            const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
              newid: vmId, hostname: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge Network: ${template.name}\nVM: ${vmName}\nLane: ${laneId}`,
            });
            if (result) await waitForTask(templateNode, result);
            await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, {
              net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vnet.vnet, goadMac)
            });
          } else {
            const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
              newid: vmId, name: `${laneName}-${vmName}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
              description: `Challenge Network: ${template.name}\nVM: ${vmName}\nLane: ${laneId}`,
            });
            if (result) await waitForTask(templateNode, result);
            await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
              net0: goadDeploy.buildLaneNet0(vmSpec, vnet.vnet, goadMac)
            });
          }

          deployedVMs.push({
            vm_id: vmId, name: vmName, type: vmType, node: bestNode,
            role: vmSpec.role || '', os: vmSpec.os || '', services: vmSpec.services || [],
            default_scripts: vmSpec.default_scripts || []
          });
        }

        // Clone and start gateway
        const gatewayVmId = 100000 + vxlanId;
        const gwResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
          newid: gatewayVmId, hostname: `${laneName}-gateway`, full: 1, target: bestNode,
          description: `Challenge Network Gateway\nTemplate: ${template.name}\nLane: ${laneId}`,
        });
        if (gwResult) await waitForTask(templateNode, gwResult);
        // Networking is scheme-aware:
        //   v1 → wan0 via module transit; lan0 = 192.18.0.1/24 (shared)
        //   v2 → wan0 on lab network (vmbr0); lan0 = 10.<vxh>.<vxl>.1/24 (unique)
        const net = resolveLaneNetworking(subnetScheme, challengeModule, vxlanId);
        await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`, {
          net0: `name=wan0,bridge=${net.wan.bridge},ip=${net.wan.ip},gw=${net.wan.gw},firewall=0,type=veth`,
          net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`
        });

        // Start gateway first
        await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
        await new Promise(r => setTimeout(r, 5000));

        // Start all challenge VMs
        for (const vm of deployedVMs) {
          const startPath = vm.type === 'lxc'
            ? `/api2/json/nodes/${vm.node}/lxc/${vm.vm_id}/status/start`
            : `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`;
          await proxmoxAPI('POST', startPath);
        }

        console.log(`[ChallengeNetwork] All ${deployedVMs.length} VMs cloned and started`);

        // GOAD provisioning (no-op for non-GOAD specs).
        if (spec.goad?.enabled) {
          try {
            await goadDeploy.deployGoadLane({
              lane: { lane_id: laneId },
              spec, module: challengeModule, vnet, vxlanId, gatewayVmId,
              bestNode, templateNode, deployedVMs,
              proxmoxAPI, waitForTask, query: cybercoreQuery
            });
          } catch (goadErr) {
            console.error(`[ChallengeNetwork] GOAD provisioning failed for lane ${laneId}: ${goadErr.message}`);
          }
        }

        // Wait for guest agents on QEMU VMs, then run scripts
        await query(
          `UPDATE deployment_vuln_selections SET status = 'running_scripts', updated_at = NOW() WHERE id = $1`,
          [deploymentId]
        );

        for (const vm of deployedVMs) {
          if (vm.type !== 'qemu') continue;

          // Wait for guest agent
          console.log(`[ChallengeNetwork] Waiting for guest agent on ${vm.name} (${vm.vm_id})...`);
          const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
          if (!agentReady) {
            console.error(`[ChallengeNetwork] Guest agent not responding on ${vm.name}`);
            continue;
          }

          // Get scripts for this VM
          const vmScripts = scriptEntries
            .filter(s => s.vm_name === vm.name)
            .map(s => s.script_slug);

          if (vmScripts.length > 0) {
            // Load full script content
            const scriptResult = await query(
              `SELECT slug, script_content, os_target, depends_on, script_args FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`,
              [vmScripts]
            );
            if (scriptResult.rows.length > 0) {
              await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, scriptResult.rows, deploymentId);
            }
          }
        }

        // Collect IPs from all VMs
        const networkInfo = { vms: [], gateway_vm_id: gatewayVmId, vxlan_id: vxlanId };
        for (const vm of deployedVMs) {
          const ips = vm.type === 'qemu' ? await getVMIPs(vm.node, vm.vm_id) : [];
          networkInfo.vms.push({
            ...vm,
            ips: ips,
            ip: ips[0] || null
          });
        }

        // Update lane config and deployment record
        const activeConfig = JSON.stringify({
          template_id: template.id,
          template_name: template.name,
          module: challengeModule,
          gateway_vm_id: gatewayVmId,
          node: bestNode,
          vms: deployedVMs
        });

        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
          [laneId, activeConfig]
        );

        await query(
          `UPDATE deployment_vuln_selections SET deployed_network = $1, status = 'complete', updated_at = NOW() WHERE id = $2`,
          [JSON.stringify(networkInfo), deploymentId]
        );

        console.log(`[ChallengeNetwork] Lane ${laneId} fully deployed with ${deployedVMs.length} VMs`);

      } catch (err) {
        console.error(`[ChallengeNetwork] Deployment failed:`, err.message);
        await cybercoreQuery(
          `UPDATE cybercore_lane SET status = 'error', config = $2, updated_at = NOW() WHERE lane_id = $1`,
          [laneId, JSON.stringify({ error: err.message })]
        ).catch(() => {});
        await query(
          `UPDATE deployment_vuln_selections SET status = 'failed', updated_at = NOW() WHERE id = $1`,
          [deploymentId]
        ).catch(() => {});
      }
    })();

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/challenge-networks/:laneId/run-script — run a single script on a specific VM
router.post('/challenge-networks/:laneId/run-script', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { vm_name, script_slug } = req.body;
    if (!vm_name || !script_slug) {
      return res.status(400).json({ error: 'vm_name and script_slug required' });
    }

    // Get lane info
    const laneResult = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Active lane not found' });

    const config = typeof laneResult.rows[0].config === 'string'
      ? JSON.parse(laneResult.rows[0].config) : laneResult.rows[0].config;

    // Find the target VM — support both multi-VM (config.vms[]) and legacy single-VM (config.challenge_vm_id)
    let vm = (config.vms || []).find(v => v.name === vm_name);
    if (!vm) {
      // Fallback: if there's a challenge_vm_id, use it (single-VM lane)
      const challengeVmId = config.challenge_vm_id;
      if (challengeVmId) {
        vm = { vm_id: challengeVmId, name: vm_name, type: 'qemu', node: config.node };
      }
      // Also check if vms array has exactly one entry (just use it regardless of name)
      if (!vm && config.vms?.length === 1) {
        vm = config.vms[0];
      }
    }
    if (!vm) return res.status(404).json({ error: `VM not found in lane config` });
    if (vm.type !== 'qemu') return res.status(400).json({ error: 'Script execution only supported on QEMU VMs' });

    // Load script
    const scriptResult = await query(
      `SELECT * FROM vuln_scripts WHERE slug = $1 AND is_active = true`, [script_slug]
    );
    if (scriptResult.rows.length === 0) return res.status(404).json({ error: `Script '${script_slug}' not found` });
    const script = scriptResult.rows[0];

    // Respond immediately — script runs in background
    res.json({ success: true, message: `Running '${script.name}' on ${vm_name}...`, vm_id: vm.vm_id });

    // Background: find or create tracking record, then run script
    (async () => {
    try {
    let dvsResult = await query(
      `SELECT id FROM deployment_vuln_selections WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.params.laneId]
    );

    let deploymentId;
    if (dvsResult.rows.length > 0) {
      deploymentId = dvsResult.rows[0].id;
      // Append this script to existing selected_scripts
      const existing = await query(`SELECT selected_scripts FROM deployment_vuln_selections WHERE id = $1`, [deploymentId]);
      const scripts = existing.rows[0]?.selected_scripts || [];
      if (!scripts.some(s => s.script_slug === script_slug && s.vm_name === vm.name)) {
        scripts.push({ script_slug, vm_name: vm.name, status: 'pending', error: null, output: null });
        await query(`UPDATE deployment_vuln_selections SET selected_scripts = $1, updated_at = NOW() WHERE id = $2`,
          [JSON.stringify(scripts), deploymentId]);
      }
    } else {
      // Create a new record
      const newDvs = await query(
        `INSERT INTO deployment_vuln_selections (lane_id, selected_scripts, status)
         VALUES ($1, $2, 'running_scripts') RETURNING id`,
        [req.params.laneId,
         JSON.stringify([{ script_slug, vm_name: vm.name, status: 'pending', error: null, output: null }])]
      );
      deploymentId = newDvs.rows[0].id;
    }

    await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, [script], deploymentId);
    } catch (err) {
      console.error(`[RunScript] Background error: ${err.message}`);
    }
    })();

  } catch (error) {
    if (!res.headersSent) res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/challenge-networks/:laneId/generate-profile — generate challenge profile with real IPs
router.post('/challenge-networks/:laneId/generate-profile', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { client_type, industry, difficulty, company_name, llm_model } = req.body;

    // Get lane info from cybercore_db
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Active lane not found' });
    }
    const lane = laneResult.rows[0];
    const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
    const laneUserId = lane.user_id;

    // Try to get deployment tracking data (may not exist if no vuln scripts were run)
    let deployment = {};
    const dvsResult = await query(
      `SELECT * FROM deployment_vuln_selections WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.params.laneId]
    );
    if (dvsResult.rows.length > 0) {
      deployment = dvsResult.rows[0];
    }

    // Build VM list from deployment_vuln_selections.deployed_network OR lane config
    const dvsNetwork = typeof deployment.deployed_network === 'string'
      ? JSON.parse(deployment.deployed_network || '{}') : (deployment.deployed_network || {});

    // Prefer deployment network data (has IPs collected after boot), fall back to lane config
    let vms = (dvsNetwork.vms && dvsNetwork.vms.length > 0)
      ? dvsNetwork.vms
      : (laneConfig.vms || []);

    // If still no VMs, try single-VM fallback
    if (vms.length === 0 && laneConfig.challenge_vm_id) {
      vms = [{
        vm_id: laneConfig.challenge_vm_id,
        name: laneConfig.challenge_key || 'challenge',
        type: 'qemu',
        node: laneConfig.node,
        role: 'Primary Target',
        os: 'Windows'
      }];
    }

    if (vms.length === 0) {
      return res.status(400).json({ error: 'No VMs found in lane config. Is the lane deployed?' });
    }

    // If VMs don't have IPs yet, try to collect them now
    for (const vm of vms) {
      if (!vm.ip && !vm.ips?.length && vm.type === 'qemu' && vm.node && vm.vm_id) {
        try {
          const ips = await getVMIPs(vm.node, vm.vm_id);
          vm.ips = ips;
          vm.ip = ips[0] || null;
        } catch (_) {}
      }
    }

    // Get phantom assets from the challenge spec in cybercore_db
    let phantoms = [];
    const challengeKey = deployment.challenge_key || laneConfig.challenge_key;
    if (challengeKey) {
      try {
        const chalResult = await cybercoreQuery(
          `SELECT spec FROM crucible_challenge WHERE challenge_key = $1`, [challengeKey]
        );
        if (chalResult.rows.length > 0) {
          const chalSpec = typeof chalResult.rows[0].spec === 'string'
            ? JSON.parse(chalResult.rows[0].spec) : chalResult.rows[0].spec;
          phantoms = chalSpec.phantom_assets || [];
        }
      } catch (_) {}
    }

    // Build asset inventory from real VMs + phantom assets
    const realAssets = vms.map(vm => ({
      hostname: vm.name,
      ip: vm.ip || vm.ips?.[0] || 'pending',
      role: vm.role || 'Server',
      os: vm.os || 'Unknown',
      services: vm.services || [],
      is_real: true
    }));

    const phantomAssets = phantoms.map(p => ({
      hostname: p.hostname,
      ip: p.ip,
      role: p.role || 'Server',
      os: p.os || 'Unknown',
      notes: p.notes,
      is_real: false
    }));

    const allAssets = [...realAssets, ...phantomAssets];

    // Get deployed vuln info for the profile
    const deployedVulns = Array.isArray(deployment.selected_scripts)
      ? deployment.selected_scripts.filter(s => s.status === 'completed').map(s => s.script_slug)
      : [];

    // Build N8N payload for challenge profile generation
    const n8nWebhookUrl = process.env.N8N_CHALLENGE_PROFILE_WEBHOOK || 'http://localhost:5678/webhook-test/NetworkAIProfile';

    const payload = {
      user_id: laneUserId,
      profile_type: 'challenge_network',
      client_type: client_type || 'SMB',
      industry: industry || 'Technology',
      difficulty: difficulty || 'intermediate',
      company_name: company_name || null,
      llmModel: llm_model || 'gemini-2.5-flash',
      lane_id: req.params.laneId,
      asset_inventory: allAssets,
      deployed_vulnerabilities: deployedVulns,
      phantom_asset_count: phantomAssets.length,
      real_asset_count: realAssets.length,
      network_topology: {
        vxlan_id: lane.vxlan_id || dvsNetwork.vxlan_id,
        gateway_vm_id: laneConfig.gateway_vm_id || dvsNetwork.gateway_vm_id,
        total_vms: vms.length
      }
    };

    // Call N8N webhook
    console.log(`[ChallengeProfile] Triggering profile generation for lane ${req.params.laneId} with ${allAssets.length} assets`);
    console.log(`[ChallengeProfile] Real assets:`, realAssets.map(a => `${a.hostname}=${a.ip}`).join(', '));
    console.log(`[ChallengeProfile] Deployed vulns:`, deployedVulns.join(', ') || 'none');
    const webhookResp = await fetch(n8nWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!webhookResp.ok) {
      const errText = await webhookResp.text();
      throw new Error(`N8N webhook failed (${webhookResp.status}): ${errText}`);
    }

    const webhookData = await webhookResp.json();

    // If N8N returned a profile_id, link it
    if (webhookData.profile_id) {
      await query(
        `UPDATE deployment_vuln_selections SET profile_id = $1, updated_at = NOW() WHERE id = $2`,
        [webhookData.profile_id, deployment.id]
      );
    }

    logActivity(req, 'generate_challenge_profile', 'lane', req.params.laneId, {
      assets: allAssets.length, vulns: deployedVulns.length
    });

    res.json({
      success: true,
      profile_id: webhookData.profile_id || null,
      assets_included: allAssets.length,
      real_vms: realAssets.length,
      phantom_hosts: phantomAssets.length,
      webhook_response: webhookData
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// GET /api/admin/vm-progress/:laneId — read progress log from a VM
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

    // Read progress log via exec
    const result = await proxmoxAPI('POST',
      `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
        command: 'powershell.exe',
        'input-data': `if (Test-Path 'C:\\LabApps\\progress.log') { Get-Content 'C:\\LabApps\\progress.log' -Raw } else { Write-Host 'No progress log yet' }\n[Environment]::Exit(0)\n`
      }
    );

    if (result?.pid) {
      const { pollExecStatus } = require('../utils/script-executor');
      const execResult = await pollExecStatus(vm.node, vm.vm_id, result.pid, 10000);
      return res.json({ log: execResult.stdout || 'No output' });
    }
    res.json({ log: 'Could not read progress' });
  } catch (e) {
    res.json({ log: `Error: ${e.message}` });
  }
});

// LIST VULN ASSETS — List available files in vuln-assets/
router.get('/vuln-asset-list', authenticateToken, adminOnly, async (req, res) => {
  try {
    const assetsDir = require('path').join(__dirname, '../../vuln-assets');
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

// FILE PUSH — Push a file from vuln-assets/ to a VM via guest agent
// ============================================================================

const fs = require('fs');
const pathModule = require('path');

// POST /api/admin/push-file — push a local file to a VM via guest agent file-write
router.post('/push-file', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { lane_id, vm_name, filename, dest_path } = req.body;

    if (!lane_id || !filename || !dest_path) {
      return res.status(400).json({ error: 'lane_id, filename, and dest_path are required' });
    }

    const safeName = pathModule.basename(filename);
    const localPath = pathModule.join(__dirname, '../../vuln-assets', safeName);

    if (!fs.existsSync(localPath)) {
      return res.status(404).json({ error: `File '${safeName}' not found in vuln-assets/` });
    }

    const fileSize = fs.statSync(localPath).size;
    const fileSizeMB = (fileSize / 1048576).toFixed(1);

    // Get lane info
    const laneResult = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [lane_id]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Active lane not found' });

    const config = typeof laneResult.rows[0].config === 'string'
      ? JSON.parse(laneResult.rows[0].config) : laneResult.rows[0].config;

    let vm = (config.vms || []).find(v => v.name === vm_name);
    if (!vm && config.challenge_vm_id) {
      vm = { vm_id: config.challenge_vm_id, node: config.node, type: 'qemu' };
    }
    if (!vm && config.vms?.length === 1) vm = config.vms[0];
    if (!vm) return res.status(404).json({ error: 'VM not found in lane' });

    res.json({
      success: true,
      message: `Pushing ${safeName} (${fileSizeMB} MB) to ${dest_path} on VM ${vm.vm_id}...`,
      file_size_mb: fileSizeMB
    });

    // Background: push the file to the VM via Proxmox guest-agent file-write.
    // This deliberately uses the virtio-serial channel (not TCP) so a compromised
    // target VM cannot initiate any connection back to the orchestrator — the host
    // always drives the conversation. Proxmox caps `content` at 61,440 chars of
    // base64, so we chunk at 45 KB raw (~60,000 base64 chars) and reassemble on
    // the VM with a single PowerShell call.
    (async () => {
      try {
        const https = require('https');
        const PX_URL = process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006';
        const PX_TOKEN_ID = process.env.PROXMOX_TOKEN_ID || 'root@pam!clinic-app-token';
        const PX_TOKEN_SECRET = process.env.PROXMOX_TOKEN_SECRET || '';

        // Helper: write one binary chunk via the file-write JSON API.
        const writeChunk = (filePath, b64Data) => {
          return new Promise((resolve, reject) => {
            const url = new URL(`${PX_URL}/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/file-write`);
            const body = JSON.stringify({ file: filePath, content: b64Data });
            const req = https.request({
              hostname: url.hostname, port: url.port || 8006, path: url.pathname, method: 'POST',
              headers: {
                'Authorization': `PVEAPIToken=${PX_TOKEN_ID}=${PX_TOKEN_SECRET}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
              },
              rejectUnauthorized: false,
              timeout: 30000
            }, (res) => {
              let data = '';
              res.on('data', c => data += c);
              res.on('end', () => {
                if (res.statusCode >= 400) return reject(new Error(`file-write failed (${res.statusCode}): ${data}`));
                resolve();
              });
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
            req.write(body);
            req.end();
          });
        };

        // Proxmox caps agent/file-write `content` at 61,440 chars of base64.
        // 45 KB raw -> 60,000 base64 chars, leaving headroom under the cap.
        const CHUNK_SIZE = 45 * 1024;
        const fileBuffer = fs.readFileSync(localPath);
        const totalChunks = Math.ceil(fileBuffer.length / CHUNK_SIZE);
        const tempDir = 'C:\\Windows\\Temp\\push_' + Date.now();

        console.log(`[PushFile] Pushing ${safeName} (${fileSizeMB} MB, ${totalChunks} chunks of ${CHUNK_SIZE / 1024}KB) to VM ${vm.vm_id}`);

        // Create temp dir on VM
        const { pollExecStatus } = require('../utils/script-executor');
        const mkdirResult = await proxmoxAPI('POST',
          `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
            command: 'powershell.exe',
            'input-data': `New-Item -ItemType Directory -Path '${tempDir}' -Force | Out-Null\n[Environment]::Exit(0)\n`
          }
        );
        if (mkdirResult?.pid) await pollExecStatus(vm.node, vm.vm_id, mkdirResult.pid, 10000);

        // Write each chunk
        for (let i = 0; i < totalChunks; i++) {
          const start = i * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, fileBuffer.length);
          const chunkBuffer = fileBuffer.subarray(start, end);
          const b64 = chunkBuffer.toString('base64');
          const chunkPath = `${tempDir}\\chunk_${String(i).padStart(4, '0')}`;

          let retries = 3;
          while (retries > 0) {
            try {
              await writeChunk(chunkPath, b64);
              break;
            } catch (e) {
              retries--;
              if (retries === 0) throw new Error(`Chunk ${i} failed after 3 retries: ${e.message}`);
              console.log(`[PushFile] Chunk ${i} retry (${3 - retries}/3): ${e.message}`);
              await new Promise(r => setTimeout(r, 2000));
            }
          }

          if ((i + 1) % 20 === 0 || i === totalChunks - 1) {
            console.log(`[PushFile] Written ${i + 1}/${totalChunks} chunks (${Math.round((i + 1) / totalChunks * 100)}%)`);
          }
          if (i % 10 === 9) await new Promise(r => setTimeout(r, 300));
        }

        // Reassemble chunks on the VM using PowerShell
        console.log(`[PushFile] Reassembling ${totalChunks} chunks on VM...`);
        const assembleScript = `
$chunks = Get-ChildItem '${tempDir}\\chunk_*' | Sort-Object Name
$parent = Split-Path -Parent '${dest_path}'
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$outStream = [System.IO.File]::Create('${dest_path}')
foreach ($chunk in $chunks) {
    $b64 = [System.IO.File]::ReadAllText($chunk.FullName)
    $bytes = [Convert]::FromBase64String($b64)
    $outStream.Write($bytes, 0, $bytes.Length)
}
$outStream.Close()
Remove-Item '${tempDir}' -Recurse -Force -ErrorAction SilentlyContinue
$size = (Get-Item '${dest_path}').Length
Write-Host "File assembled: ${dest_path} ($size bytes)"
`;
        const assembleResult = await proxmoxAPI('POST',
          `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
            command: 'powershell.exe',
            'input-data': assembleScript + '\n[Environment]::Exit(0)\n'
          }
        );
        if (assembleResult?.pid) {
          const result = await pollExecStatus(vm.node, vm.vm_id, assembleResult.pid, 120000);
          console.log(`[PushFile] Assemble output: ${(result.stdout || '').trim()}`);
        }

        console.log(`[PushFile] Done: ${safeName} (${fileSizeMB} MB) -> ${dest_path} on VM ${vm.vm_id}`);
      } catch (err) {
        console.error(`[PushFile] Failed: ${err.message}`);
      }
    })();

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
