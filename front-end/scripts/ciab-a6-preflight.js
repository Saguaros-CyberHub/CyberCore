#!/usr/bin/env node
/**
 * ciab-a6-preflight.js — Track A6, the half that can be checked before anything
 * is built.
 *
 * A6 is the cluster gate for the CIAB deploy rewrite: it is the phase no amount
 * of unit testing substitutes for, because the defects A1-A5 fixed (a console
 * pointed at an unroutable address, a Windows guest that never DHCPs, a retry
 * that starts a container it just destroyed) are all invisible to source-text
 * assertions and only show up when a student tries to connect.
 *
 * But a five-lane deploy is expensive and hard to undo, and most of the ways it
 * fails are knowable in advance: a missing template, an SDN zone that never
 * materialised, a VXLAN block with no free ids, a WAN pool at its ceiling. This
 * script answers all of those READ-ONLY, so the real run starts from a known
 * state instead of discovering one 40 minutes in.
 *
 * IT CREATES NOTHING AND CHANGES NOTHING. Every Proxmox call is a GET and every
 * query is a SELECT.
 *
 * Usage:
 *   node front-end/scripts/ciab-a6-preflight.js [--lanes 5] [--profile <id8>]
 *
 * Reads front-end/.env for PROXMOX_API_URL / PROXMOX_TOKEN_ID /
 * PROXMOX_TOKEN_SECRET and the CYBERCORE_DB_* pair. Deliberately does NOT load
 * src/utils/proxmox.js or lane-wan-allocator.js: both pull site-config, which
 * reads a gitignored config/site.json that does not exist on every machine an
 * operator might run this from.
 */

const path = require('path');
const https = require('https');
const { Pool } = require('pg');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// ─── args ───────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
function arg(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
}
const WANT_LANES = parseInt(arg('lanes', '5'), 10);
const ONLY_PROFILE = arg('profile', null);

// ─── the machines a CIAB profile lane is built from ─────────────────────────
// Authority: ciab/utils/profile-to-spec.js (WEB_TEMPLATE_VMID), lane-networking.js
// (V2_LANE_GATEWAY_VMID, KALI_TEMPLATE_VMID) and the bake scripts in
// infrastructure/proxmox-templates/. A missing one does not fail the deploy up
// front — it fails per lane, mid-clone, after the gateway is already up.
const REQUIRED_TEMPLATES = [
  { vmid: 1694, what: 'v2 lane gateway (LXC)', critical: true },
  { vmid: 1699, what: 'Kali attack box',       critical: true },
  { vmid: 1005, what: 'Debian web / vuln-app', critical: true },
  { vmid: 1004, what: 'Windows Server 2019',   critical: false },
  { vmid: 1002, what: 'Windows 11 client',     critical: false },
];

// ─── output helpers ─────────────────────────────────────────────────────────

const problems = [];
const warnings = [];
const C = { ok: '\x1b[32m', warn: '\x1b[33m', bad: '\x1b[31m', dim: '\x1b[90m', off: '\x1b[0m' };
const ok   = (m) => console.log(`  ${C.ok}PASS${C.off}  ${m}`);
const warn = (m) => { warnings.push(m); console.log(`  ${C.warn}WARN${C.off}  ${m}`); };
const bad  = (m) => { problems.push(m); console.log(`  ${C.bad}FAIL${C.off}  ${m}`); };
const head = (m) => console.log(`\n${m}\n${'─'.repeat(m.length)}`);

// ─── Proxmox (GET only) ─────────────────────────────────────────────────────

const PVE_URL = (process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006').replace(/\/+$/, '');
const PVE_AUTH = `PVEAPIToken=${process.env.PROXMOX_TOKEN_ID}=${process.env.PROXMOX_TOKEN_SECRET}`;

function pveGet(apiPath) {
  return new Promise((resolve, reject) => {
    const req = https.request(`${PVE_URL}${apiPath}`, {
      method: 'GET',
      headers: { Authorization: PVE_AUTH },
      rejectUnauthorized: false,     // the cluster uses a self-signed cert
      timeout: 20000,
    }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`GET ${apiPath} → HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(body).data); } catch (e) { reject(new Error(`unparseable: ${body.slice(0, 200)}`)); }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`GET ${apiPath} timed out`)));
    req.on('error', reject);
    req.end();
  });
}

// ─── cybercore_db (SELECT only) ─────────────────────────────────────────────

const pool = new Pool({
  host: process.env.CYBERCORE_DB_HOST || '100.100.20.50',
  port: parseInt(process.env.CYBERCORE_DB_PORT, 10) || 5432,
  database: process.env.CYBERCORE_DB_NAME || 'cybercore_db',
  user: process.env.CYBERCORE_DB_USER || 'cactus-admin',
  password: process.env.CYBERCORE_DB_PASSWORD,
  connectionTimeoutMillis: 10000,
});
const q = (sql, params = []) => pool.query(sql, params);

// ─── checks ─────────────────────────────────────────────────────────────────

async function checkCluster() {
  head('Cluster');
  const nodes = await pveGet('/api2/json/nodes');
  const online = nodes.filter((n) => n.status === 'online');
  if (online.length === 0) { bad('no Proxmox node is online'); return []; }
  ok(`${online.length}/${nodes.length} node(s) online: ${online.map((n) => n.node).join(', ')}`);

  for (const n of online) {
    const memPct = n.maxmem ? Math.round((n.mem / n.maxmem) * 100) : 0;
    const diskPct = n.maxdisk ? Math.round((n.disk / n.maxdisk) * 100) : 0;
    // Thresholds mirror src/middleware/deployment-guards.js, which refuses a
    // deploy past them — so a node already over is a deploy that will be
    // rejected rather than merely slow.
    const line = `${n.node}: mem ${memPct}%, disk ${diskPct}%`;
    if (memPct >= 80 || diskPct >= 90) bad(`${line} — over the deploy guard threshold (mem 80% / disk 90%)`);
    else if (memPct >= 70 || diskPct >= 80) warn(`${line} — close to the guard threshold`);
    else ok(line);
  }
  return online.map((n) => n.node);
}

async function checkTemplates() {
  head('Templates');
  const resources = await pveGet('/api2/json/cluster/resources?type=vm');
  const byVmid = new Map(resources.map((r) => [Number(r.vmid), r]));

  for (const t of REQUIRED_TEMPLATES) {
    const row = byVmid.get(t.vmid);
    if (!row) {
      const msg = `template ${t.vmid} (${t.what}) not found on the cluster`;
      t.critical ? bad(msg) : warn(`${msg} — only needed if a profile selects that OS`);
      continue;
    }
    if (!row.template) {
      bad(`VMID ${t.vmid} (${t.what}) exists on ${row.node} but is NOT marked as a template — cloning it will fail`);
      continue;
    }
    ok(`${t.vmid} ${t.what} — on ${row.node}`);
  }
}

async function checkReservations() {
  head('CIAB reservations');
  const res = await q(`
    SELECT challenge_key, challenge_id, subnet_scheme, status,
           (spec->'vxlan_block'->>'start')::int AS vx_start,
           (spec->'vxlan_block'->>'end')::int   AS vx_end,
           spec->'zone'->>'abbrev'              AS zone,
           COALESCE(jsonb_array_length(spec->'vms'), 0) AS vm_count
      FROM crucible_challenge
     WHERE challenge_key LIKE 'ciab-profile-%'
     ORDER BY challenge_key`);

  if (res.rows.length === 0) {
    warn('no CIAB reservations exist yet — the first deploy will create one');
    return [];
  }

  const usable = [];
  for (const r of res.rows) {
    if (ONLY_PROFILE && !r.challenge_key.includes(ONLY_PROFILE)) continue;

    const size = (r.vx_end != null && r.vx_start != null) ? (r.vx_end - r.vx_start + 1) : 0;
    const live = await q(
      `SELECT COUNT(*)::int AS n FROM cybercore_lane
        WHERE vxlan_id BETWEEN $1 AND $2 AND status IN ('active','deploying')`,
      [r.vx_start, r.vx_end]);
    const used = live.rows[0].n;
    const free = size - used;

    console.log(`\n  ${r.challenge_key}  ${C.dim}(${r.subnet_scheme}, ${r.vm_count} VM(s) in spec)${C.off}`);

    // A1 made the key engagement-scoped. A key with no engagement suffix is a
    // pre-A1 row that getOrCreateProfileChallenge adopts lazily on read — worth
    // seeing, because until something reads it the old key is what teardown uses.
    const parts = r.challenge_key.split('-');
    if (parts.length < 4) warn(`  ${r.challenge_key}: pre-engagement key format, not yet adopted`);

    // teardownLabNetwork deletes the zone named by spec.zone.abbrev. A row
    // without one tears down its VNets and leaves the zone behind.
    if (!r.zone) bad(`  ${r.challenge_key}: spec.zone.abbrev is missing — teardown cannot name its SDN zone`);
    else ok(`  zone '${r.zone}', VXLAN ${r.vx_start}-${r.vx_end}`);

    if (r.vm_count === 0) warn('  spec declares no VMs — a deploy would adopt a fresh spec');

    if (free >= WANT_LANES) ok(`  ${free}/${size} VXLAN id(s) free — fits ${WANT_LANES} lane(s)`);
    else bad(`  only ${free}/${size} VXLAN id(s) free — ${WANT_LANES} lane(s) will not fit (${used} in use)`);

    if (free >= WANT_LANES && r.zone) usable.push({ ...r, free });
  }
  return usable;
}

async function checkSdn(reservations) {
  head('SDN');
  const [zones, vnets] = await Promise.all([
    pveGet('/api2/json/cluster/sdn/zones'),
    pveGet('/api2/json/cluster/sdn/vnets'),
  ]);
  const zoneNames = new Set(zones.map((z) => z.zone));
  const tags = new Set(vnets.map((v) => Number(v.tag)).filter(Number.isFinite));

  if (reservations.length === 0) {
    warn('no usable reservation to check VNets against');
    return;
  }
  for (const r of reservations) {
    if (!zoneNames.has(r.zone)) {
      bad(`zone '${r.zone}' is in the spec but not on the cluster — VNets cannot exist`);
      continue;
    }
    const missing = [];
    for (let id = r.vx_start; id <= r.vx_end; id++) if (!tags.has(id)) missing.push(id);
    if (missing.length === 0) {
      ok(`zone '${r.zone}': all ${r.vx_end - r.vx_start + 1} VNet(s) present`);
    } else if (missing.length > r.free) {
      // Fewer VNets than free ids means a deploy would reach resolveVnets and
      // throw partway through the batch.
      bad(`zone '${r.zone}': ${missing.length} VNet(s) missing (${missing.slice(0, 6).join(', ')}${missing.length > 6 ? '…' : ''})`);
    } else {
      warn(`zone '${r.zone}': ${missing.length} VNet(s) missing, but enough remain for ${WANT_LANES} lane(s)`);
    }
  }
}

async function checkWanPool() {
  head('Gateway WAN pool');
  // 100.100.60.0/22 is ONE address per live lane and is the hard ceiling on
  // concurrent lanes cluster-wide — not per course, not per profile.
  const res = await q(`
    SELECT
      (SELECT COUNT(*)::int FROM cybercore_lane
        WHERE gateway_wan_ip IS NOT NULL AND status IN ('active','deploying')) AS live,
      (SELECT COUNT(*)::int FROM lane_bootstrap_tokens
        WHERE consumed_at IS NULL AND expires_at > NOW())                      AS in_flight`)
    .catch((e) => { warn(`could not read the pool census: ${e.message}`); return null; });
  if (!res) return;

  const { live, in_flight } = res.rows[0];
  // /22 minus network+broadcast, minus the .1-.9 infrastructure band the site
  // config reserves. Approximate on purpose: the exact reserved list lives in
  // config/site.json, which this script deliberately does not require.
  const APPROX_USABLE = 1024 - 2 - 9;
  const free = APPROX_USABLE - live;
  if (free >= WANT_LANES) ok(`~${free} address(es) free of ~${APPROX_USABLE} (${live} live, ${in_flight} bootstrap token(s) in flight)`);
  else bad(`only ~${free} WAN address(es) free — ${WANT_LANES} lane(s) will not fit`);
  if (in_flight > 0) warn(`${in_flight} unconsumed bootstrap token(s) — those addresses are held until they expire`);
}

async function checkStaleState() {
  head('Stale state');
  // A lane stuck in 'deploying' holds both a VXLAN id and a WAN address, and
  // recoverStrandedLanes only sweeps them at boot. Worth seeing before a run
  // that is about to be blamed for a pool that was already short.
  const stuck = await q(`
    SELECT COUNT(*)::int AS n FROM cybercore_lane
     WHERE status = 'deploying' AND updated_at < NOW() - INTERVAL '2 hours'`);
  if (stuck.rows[0].n > 0) {
    warn(`${stuck.rows[0].n} lane(s) stuck in 'deploying' for >2h — they hold a VXLAN id and a WAN address each`);
  } else ok('no lanes stuck in deploying');

  const errored = await q(`
    SELECT COUNT(*)::int AS n FROM cybercore_lane
     WHERE status = 'error' AND module_key = 'ciab'`);
  if (errored.rows[0].n > 0) warn(`${errored.rows[0].n} CIAB lane(s) in 'error' — kept deliberately for retry`);
  else ok('no CIAB lanes in error');
}

// ─── main ───────────────────────────────────────────────────────────────────

(async () => {
  console.log(`\nCIAB A6 preflight — read-only`);
  console.log(`${C.dim}target: ${PVE_URL} · asking for ${WANT_LANES} lane(s)${C.off}`);

  if (!process.env.PROXMOX_TOKEN_SECRET) {
    console.error(`\n${C.bad}PROXMOX_TOKEN_SECRET is not set — check front-end/.env${C.off}\n`);
    process.exit(2);
  }

  // The Proxmox half and the database half fail independently, and they fail on
  // DIFFERENT machines: a developer workstation can usually reach the cluster
  // API but not cybercore_db (clinic_db is on localhost of the orchestrator, so
  // it is not reachable from anywhere else at all). Aborting the whole run on a
  // DB error would throw away the cluster answers, which are the expensive ones
  // to get. So each half reports on its own and the verdict says what was
  // actually checked.
  let dbReachable = true;
  try {
    await checkCluster();
    await checkTemplates();
  } catch (err) {
    console.error(`\n${C.bad}cluster checks aborted: ${err.message}${C.off}`);
    problems.push(`cluster checks could not run: ${err.message}`);
  }

  try {
    await q('SELECT 1');
  } catch (err) {
    dbReachable = false;
    head('Database');
    warn(`cybercore_db not reachable from here (${err.message.split('\n')[0]}) — `
       + `reservation, SDN, WAN-pool and stale-state checks SKIPPED. Re-run this on the orchestrator.`);
  }

  if (dbReachable) {
    try {
      const reservations = await checkReservations();
      await checkSdn(reservations);
      await checkWanPool();
      await checkStaleState();
    } catch (err) {
      console.error(`\n${C.bad}database checks aborted: ${err.message}${C.off}`);
      problems.push(`database checks could not run: ${err.message}`);
    }
  }

  head('Verdict');
  if (!dbReachable) {
    console.log(`  ${C.warn}PARTIAL — cluster checked, database not.${C.off}`);
    console.log(`  ${C.dim}This is the expected result on a workstation. The blocking questions`);
    console.log(`  (free VXLAN ids, SDN VNets, WAN pool headroom) all live in the database`);
    console.log(`  half, so re-run this on the orchestrator before deploying.${C.off}\n`);
  } else if (problems.length === 0 && warnings.length === 0) {
    console.log(`  ${C.ok}Clear to run the A6 deploy.${C.off}\n`);
  } else if (problems.length === 0) {
    console.log(`  ${C.warn}Clear, with ${warnings.length} warning(s) — read them before starting.${C.off}\n`);
  } else {
    console.log(`  ${C.bad}${problems.length} blocker(s). Fix these before deploying:${C.off}`);
    for (const p of problems) console.log(`    · ${p}`);
    console.log();
  }

  await pool.end().catch(() => {});
  process.exit(problems.length === 0 ? 0 : 1);
})();
