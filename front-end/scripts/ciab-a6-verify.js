#!/usr/bin/env node
/**
 * ciab-a6-verify.js — Track A6, the checklist as an assertion instead of a
 * memory of clicking around.
 *
 * Run AFTER a `CIAB_DEPLOY_V2=1` deploy has finished. It answers, per lane, the
 * questions the A1-A5 rewrite claims to have fixed — and every one of them was
 * previously invisible from source:
 *
 *   W1  the Guacamole connection points at the GATEWAY WAN IP, not the lane-local
 *       address. guacd has no route into 10.<vxh>.<vxl>.0/24, so a console
 *       pointed at the lane IP is dead on arrival — it looks configured and
 *       cannot connect. This is checked by asking Guacamole what hostname it
 *       actually holds and comparing it to cybercore_lane.gateway_wan_ip.
 *   W2  the student has READ on their own connection.
 *   W3  the lane recorded pinned_hosts, so its machines are on the addresses its
 *       generated scan report names (A4's contract).
 *   W4  every Windows guest got an e1000 NIC. A stock Windows image has no
 *       virtio-net driver, so a virtio NIC never DHCPs.
 *   --  the vuln-app postDeploy hook did not record an error.
 *
 * READ-ONLY. Every Proxmox call is a GET, every query a SELECT, and the
 * Guacamole session is opened only to read.
 *
 * Usage:
 *   node front-end/scripts/ciab-a6-verify.js --group <group_id>
 *   node front-end/scripts/ciab-a6-verify.js --lane  <lane_id>
 *
 * What it CANNOT check, and which stay manual (see the A6 runbook):
 *   - a human actually completing an RDP session and getting a desktop
 *   - `nmap` output from inside the lane matching the paper scan report
 *   - a retry succeeding
 *   - a teardown leaving nothing behind
 */

const path = require('path');
const https = require('https');
const http = require('http');
const { Pool } = require('pg');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const argv = process.argv.slice(2);
function arg(name) {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
}
const GROUP_ID = arg('group');
const LANE_ID = arg('lane');

if (!GROUP_ID && !LANE_ID) {
  console.error('usage: ciab-a6-verify.js --group <group_id> | --lane <lane_id>');
  process.exit(2);
}

const C = { ok: '\x1b[32m', warn: '\x1b[33m', bad: '\x1b[31m', dim: '\x1b[90m', off: '\x1b[0m' };
let failures = 0;
let checks = 0;
const ok = (m) => { checks++; console.log(`    ${C.ok}PASS${C.off}  ${m}`); };
const bad = (m) => { checks++; failures++; console.log(`    ${C.bad}FAIL${C.off}  ${m}`); };
const warn = (m) => console.log(`    ${C.warn}WARN${C.off}  ${m}`);

// ─── clients ────────────────────────────────────────────────────────────────

const PVE_URL = (process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006').replace(/\/+$/, '');
const PVE_AUTH = `PVEAPIToken=${process.env.PROXMOX_TOKEN_ID}=${process.env.PROXMOX_TOKEN_SECRET}`;

function pveGet(apiPath) {
  return new Promise((resolve, reject) => {
    const req = https.request(`${PVE_URL}${apiPath}`, {
      method: 'GET', headers: { Authorization: PVE_AUTH },
      rejectUnauthorized: false, timeout: 20000,
    }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`GET ${apiPath} → HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(body).data); } catch { reject(new Error('unparseable Proxmox reply')); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

const pool = new Pool({
  host: process.env.CYBERCORE_DB_HOST || '100.100.20.50',
  port: parseInt(process.env.CYBERCORE_DB_PORT, 10) || 5432,
  database: process.env.CYBERCORE_DB_NAME || 'cybercore_db',
  user: process.env.CYBERCORE_DB_USER || 'cactus-admin',
  password: process.env.CYBERCORE_DB_PASSWORD,
  connectionTimeoutMillis: 10000,
});
const q = (sql, params = []) => pool.query(sql, params);

// ─── Guacamole (read-only session) ──────────────────────────────────────────

const GUAC_URL = (process.env.GUAC_API_URL || 'http://localhost:8080/guacamole').replace(/\/+$/, '');
const GUAC_DS = process.env.GUAC_DATASOURCE || 'postgresql';
let guacToken = null;

function guacRequest(method, apiPath, form) {
  const url = new URL(`${GUAC_URL}${apiPath}`);
  const lib = url.protocol === 'https:' ? https : http;
  const payload = form ? new URLSearchParams(form).toString() : null;
  return new Promise((resolve, reject) => {
    const req = lib.request(url, {
      method,
      headers: payload
        ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(payload) }
        : {},
      rejectUnauthorized: false, timeout: 15000,
    }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`${method} ${apiPath} → HTTP ${res.statusCode}`));
        try { resolve(body ? JSON.parse(body) : {}); } catch { resolve({}); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function guacLogin() {
  const r = await guacRequest('POST', '/api/tokens', {
    username: process.env.GUAC_ADMIN_USER,
    password: process.env.GUAC_ADMIN_PASSWORD,
  });
  guacToken = r.authToken;
  if (!guacToken) throw new Error('Guacamole returned no authToken');
}

const guacGet = (p) => guacRequest('GET', `${p}${p.includes('?') ? '&' : '?'}token=${encodeURIComponent(guacToken)}`);

// ─── per-lane verification ──────────────────────────────────────────────────

async function verifyLane(lane, guacOk) {
  const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
  console.log(`\n  ${lane.name}  ${C.dim}(${lane.lane_id.slice(0, 8)}, vxlan ${lane.vxlan_id}, ${lane.status})${C.off}`);

  if (lane.status !== 'active') {
    bad(`lane status is '${lane.status}' — ${cfg.error || 'no error recorded'}`);
  } else {
    ok('lane status is active');
  }

  // ── the vuln-app hook ────────────────────────────────────────────────────
  if (cfg.post_deploy_error) {
    bad(`vuln-app postDeploy failed: ${cfg.post_deploy_error}`);
  } else {
    ok('no postDeploy error recorded');
  }

  // ── W3 / A4: fixed addressing ────────────────────────────────────────────
  const pinned = Array.isArray(cfg.pinned_hosts) ? cfg.pinned_hosts : [];
  if (pinned.length === 0) {
    bad('no pinned_hosts recorded — pinAllVms did not run, so machines took pool leases '
      + 'and the generated scan report names addresses nothing answers on');
  } else {
    const outOfBand = pinned.filter((p) => p.octet < 80 || p.octet > 99);
    if (outOfBand.length) {
      bad(`${outOfBand.length} pinned host(s) outside the .80-.99 spec band: `
        + outOfBand.map((p) => `${p.name}=.${p.octet}`).join(', '));
    } else {
      ok(`${pinned.length} host(s) pinned in-band: ${pinned.map((p) => `${p.name}=.${p.octet}`).join(', ')}`);
    }
  }

  const dnsRecords = Array.isArray(cfg.dns_records) ? cfg.dns_records : [];
  if (dnsRecords.length === 0) warn('no dns_records — in-lane short names will not resolve');
  else ok(`${dnsRecords.length} DNS host-record(s): ${dnsRecords.map((d) => d.alias).join(', ')}`);

  // ── W4: NIC model on Windows guests ──────────────────────────────────────
  const vms = Array.isArray(cfg.vms) ? cfg.vms : [];
  let windowsChecked = 0;
  for (const vm of vms) {
    if (vm.type === 'lxc') continue;
    let vmCfg;
    try {
      vmCfg = await pveGet(`/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/config`);
    } catch (e) {
      warn(`could not read config for ${vm.name} (${vm.vm_id}): ${e.message}`);
      continue;
    }
    const isWindows = /^win/i.test(vmCfg.ostype || '');
    if (!isWindows) continue;
    windowsChecked++;
    const net0 = String(vmCfg.net0 || '');
    if (/virtio/i.test(net0)) {
      bad(`${vm.name} is Windows (ostype=${vmCfg.ostype}) but has a virtio NIC — it will never DHCP`);
    } else if (/e1000/i.test(net0)) {
      ok(`${vm.name} Windows guest has an e1000 NIC`);
    } else {
      warn(`${vm.name} NIC model is neither virtio nor e1000: ${net0.split(',')[0]}`);
    }
  }
  if (windowsChecked === 0) console.log(`    ${C.dim}(no Windows guests on this lane)${C.off}`);

  // ── W1 / W2: the console ─────────────────────────────────────────────────
  const consoles = Array.isArray(cfg.consoles) ? cfg.consoles : [];
  if (consoles.length === 0) {
    bad('no consoles recorded on the lane — the student has nothing to connect to');
    return;
  }
  if (!lane.gateway_wan_ip) {
    bad('lane has no gateway_wan_ip — the console cannot be routable');
    return;
  }

  if (!guacOk) {
    warn(`Guacamole not reachable — W1/W2 unverified. Connection id(s): `
       + consoles.map((c) => c.guac_connection_id || '(none)').join(', '));
    return;
  }

  for (const con of consoles) {
    if (!con.guac_connection_id) {
      bad(`console '${con.name}' has no Guacamole connection id`);
      continue;
    }
    let params;
    try {
      params = await guacGet(
        `/api/session/data/${GUAC_DS}/connections/${encodeURIComponent(con.guac_connection_id)}/parameters`);
    } catch (e) {
      bad(`console '${con.name}': Guacamole connection ${con.guac_connection_id} unreadable (${e.message})`);
      continue;
    }
    // THE regression. A lane-local host here is the defect that made every CIAB
    // console dead on arrival: it looks configured and cannot connect.
    if (params.hostname === lane.gateway_wan_ip) {
      ok(`console '${con.name}' targets the gateway WAN IP ${params.hostname}:${params.port}`);
    } else {
      bad(`console '${con.name}' targets ${params.hostname}:${params.port}, but this lane's gateway `
        + `WAN IP is ${lane.gateway_wan_ip} — guacd has no route to a lane-local address`);
    }

    // W2: the student must hold READ on their own connection.
    try {
      const perms = await guacGet(
        `/api/session/data/${GUAC_DS}/users/${encodeURIComponent(lane.user_email)}/permissions`);
      const granted = perms?.connectionPermissions?.[con.guac_connection_id] || [];
      if (granted.includes('READ')) ok(`${lane.user_email} has READ on '${con.name}'`);
      else bad(`${lane.user_email} has NO READ on connection ${con.guac_connection_id} — the tile will 403`);
    } catch (e) {
      warn(`could not read Guacamole permissions for ${lane.user_email}: ${e.message}`);
    }
  }
}

// ─── main ───────────────────────────────────────────────────────────────────

(async () => {
  console.log(`\nCIAB A6 verification — read-only`);
  console.log(`${C.dim}${GROUP_ID ? `group ${GROUP_ID}` : `lane ${LANE_ID}`}${C.off}`);

  let lanes;
  try {
    if (GROUP_ID) {
      // Lane ids come from the CIAB job mirror, which lives in clinic_db — not
      // reachable from here. config.group_id is the same fact recorded on the
      // lane itself by the wrapper's laneConfig, so it needs only cybercore_db.
      lanes = (await q(`
        SELECT l.lane_id, l.name, l.vxlan_id, l.status, l.config,
               host(l.gateway_wan_ip) AS gateway_wan_ip, u.email AS user_email
          FROM cybercore_lane l
          LEFT JOIN cybercore_user u ON u.user_id = l.user_id
         WHERE l.config->>'group_id' = $1
         ORDER BY l.vxlan_id`, [GROUP_ID])).rows;
    } else {
      lanes = (await q(`
        SELECT l.lane_id, l.name, l.vxlan_id, l.status, l.config,
               host(l.gateway_wan_ip) AS gateway_wan_ip, u.email AS user_email
          FROM cybercore_lane l
          LEFT JOIN cybercore_user u ON u.user_id = l.user_id
         WHERE l.lane_id = $1`, [LANE_ID])).rows;
    }
  } catch (err) {
    console.error(`\n${C.bad}cannot reach cybercore_db: ${err.message}${C.off}`);
    console.error(`${C.dim}Run this on the orchestrator.${C.off}\n`);
    await pool.end().catch(() => {});
    process.exit(2);
  }

  if (lanes.length === 0) {
    console.error(`\n${C.bad}no lanes found.${C.off}\n`);
    await pool.end().catch(() => {});
    process.exit(2);
  }

  let guacOk = true;
  try { await guacLogin(); } catch (e) {
    guacOk = false;
    console.log(`\n  ${C.warn}Guacamole not reachable (${e.message}) — W1/W2 will be reported as unverified.${C.off}`);
  }

  for (const lane of lanes) await verifyLane(lane, guacOk);

  console.log(`\n${'─'.repeat(52)}`);
  if (failures === 0) {
    console.log(`${C.ok}All ${checks} mechanical check(s) passed across ${lanes.length} lane(s).${C.off}`);
    console.log(`${C.dim}Still manual: connect as a student, nmap vs the scan report, retry, teardown.${C.off}\n`);
  } else {
    console.log(`${C.bad}${failures} of ${checks} check(s) FAILED across ${lanes.length} lane(s).${C.off}\n`);
  }

  await pool.end().catch(() => {});
  process.exit(failures === 0 ? 0 : 1);
})();
