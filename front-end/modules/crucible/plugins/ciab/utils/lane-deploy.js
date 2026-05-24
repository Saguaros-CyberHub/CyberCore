/**
 * lane-deploy.js — Per-lane Proxmox orchestrator for CIAB profile-driven batches
 * ============================================================================
 * Modeled on front-end/src/routes/admin.js /deploy-group (lines 2266-3200) but
 * stripped down for the CIAB classroom case:
 *   - No instructor/student users (admin owns every lane)
 *   - v2 only by default (subnet-agnostic 10.x.x.x lanes — what CIAB servers
 *     actually live on). v3 is honored if the spec passes it but no GOAD.
 *   - No attached-modules / no use_webhook mode
 *   - Vuln-app installer runs as a post-clone step on its target VM
 *
 * Phases match admin.js for the LXC-lock workaround:
 *   1a — Replicate gateway template (1694 by default) to each unique target node
 *   1b — Clone N gateway LXCs in parallel from node-local copies
 *   1c — Delete temp template copies
 *   2  — Clone challenge VMs (+ optional Kali) in parallel via runBatch
 *
 * Per-lane Proxmox failures don't crash the batch — they get recorded in
 * ciab_profile_lane_jobs.status='error' so the UI's Retry button can re-run
 * the single failed lane via deployOneLaneFromSpec().
 */

const { pool, query } = require('./db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI, waitForTask } = require('../../../../../src/utils/proxmox');
const { waitForGuestAgent, executeScriptsOnVM, guestFileWrite, guestWriteLargeText, agentExec, pollExecStatus, getVMIPs } = require('../../../../../src/utils/script-executor');
const { selectBestNode } = require('../../../../../src/utils/node-selector');
const { runBatch, createCloneSemaphore, distributeAcrossNodes } = require('../../../../../src/utils/batch-deployer');
const { guacAPI } = require('../../../../../src/utils/guacamole');

const {
  V2_LANE_GATEWAY_VMID,
  V3_LANE_GATEWAY_VMID,
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  resolveGatewayVmid,
  resolveLaneNetworking,
  formatLaneGatewayNet0,
  formatLaneHostname,
  configureLaneTailscale,
  forceDestroyVM
} = require('./lane-networking');

const TEMP_GW_TEMPLATE_BASE = 169200; // 169200, 169201, ... — per-node temp copies
const DEFAULT_CONCURRENCY = parseInt(process.env.MAX_CONCURRENT_DEPLOYS) || 6;

// VXLAN search bounds for CIAB profile challenges. Each profile gets a
// contiguous block sized exactly to max_students, placed wherever there's a
// free gap inside this window. Same mechanism as crucible challenge templates —
// no special CIAB-only carve-out. Conservative default starts at 10100 (above
// the seeded crucible-base 10000-10009) and stops at the 16-bit boundary.
const VXLAN_SEARCH_MIN = parseInt(process.env.CIAB_VXLAN_SEARCH_MIN, 10) || 10100;
const VXLAN_SEARCH_MAX = parseInt(process.env.CIAB_VXLAN_SEARCH_MAX, 10) || 65535;

// ─── Progress tracking ─────────────────────────────────────────────────────
// In-process tracker keyed by group_id. Separate namespace from admin.js's
// _batchDeployProgress so CIAB and instructor flows don't collide.
function getProgress(groupId) {
  if (!global._ciabProfileLaneProgress) global._ciabProfileLaneProgress = {};
  return global._ciabProfileLaneProgress[groupId] || null;
}

function initProgress(groupId, total, groupName) {
  if (!global._ciabProfileLaneProgress) global._ciabProfileLaneProgress = {};
  global._ciabProfileLaneProgress[groupId] = {
    group_id: groupId,
    group_name: groupName,
    total,
    completed: 0,
    succeeded: 0,
    failed: 0,
    phase: 'preparing',
    phase_detail: '',
    started_at: new Date().toISOString(),
    finished_at: null,
    elapsed_s: 0,
    avg_lane_s: null,
    eta_s: null,
    eta_at: null,
    lanes: {},
    _laneTimes: [],
    _startMs: Date.now()
  };
  return global._ciabProfileLaneProgress[groupId];
}

function updateTiming(progress, concurrency) {
  const now = Date.now();
  progress.elapsed_s = Math.round((now - progress._startMs) / 1000);
  if (progress._laneTimes.length > 0) {
    const avgMs = progress._laneTimes.reduce((a, b) => a + b, 0) / progress._laneTimes.length;
    progress.avg_lane_s = Math.round(avgMs / 1000);
    const remaining = progress.total - progress.completed;
    const etaMs = (remaining / concurrency) * avgMs;
    progress.eta_s = Math.round(etaMs / 1000);
    progress.eta_at = new Date(now + etaMs).toISOString();
  }
}

// ─── VXLAN allocation ──────────────────────────────────────────────────────
async function allocateVxlanIds(vxlanBlock, count) {
  const result = await cybercoreQuery(
    `WITH used AS (
       SELECT DISTINCT vxlan_id FROM cybercore_lane
       WHERE vxlan_id IS NOT NULL
         AND vxlan_id BETWEEN $1 AND $2
         AND status NOT IN ('error','deleted')
     )
     SELECT gs AS vxlan_id
     FROM generate_series($1::int, $2::int) AS gs
     LEFT JOIN used u ON u.vxlan_id = gs
     WHERE u.vxlan_id IS NULL
     ORDER BY gs LIMIT $3`,
    [vxlanBlock.start, vxlanBlock.end, count]
  );
  return result.rows.map(r => r.vxlan_id);
}

// ─── Per-profile crucible_challenge reservation ────────────────────────────
/**
 * Each CIAB profile that has been deployed owns ONE crucible_challenge row in
 * cybercore_db, keyed deterministically by `challenge_key = 'ciab-profile-<id>'`.
 * The challenge's spec.vxlan_block IS the reservation — sized exactly to
 * max_students, placed wherever there's a free gap. Identical mechanism to
 * how crucible challenge templates work — no parallel reservation system, no
 * CIAB-side migration needed.
 *
 * Idempotent: if the challenge exists, return its existing vxlan_block.
 * Otherwise carve a fresh `requestedMax`-sized slice from the first free gap
 * in [VXLAN_SEARCH_MIN, VXLAN_SEARCH_MAX], create the challenge row, return.
 *
 * @param {object} args
 * @param {string} args.profileId
 * @param {number} args.requestedMax       max_students if no reservation exists
 * @param {string} args.companyName        used for the challenge display name
 * @param {object} args.spec               vm spec (from synthesizer) — only
 *                                         used when CREATING a new challenge.
 *                                         Existing challenges keep their spec.
 * @param {string} args.subnetScheme
 * @returns {Promise<{challenge_id, challenge_key, vxlan_block, max_students, was_existing, spec}>}
 */
async function getOrCreateProfileChallenge({ profileId, requestedMax, companyName, spec, subnetScheme = 'v2' }) {
  if (!profileId) throw new Error('getOrCreateProfileChallenge: profileId required');
  const challengeKey = `ciab-profile-${profileId.slice(0, 8)}`;

  // 1. Idempotent lookup — does this profile already have a challenge?
  const chRes = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, spec FROM crucible_challenge WHERE challenge_key = $1`,
    [challengeKey]
  );
  if (chRes.rows.length > 0) {
    const ch = chRes.rows[0];
    const existingSpec = typeof ch.spec === 'string' ? JSON.parse(ch.spec) : ch.spec;
    const block = existingSpec.vxlan_block || {};
    const blockSize = (block.end != null && block.start != null) ? (block.end - block.start + 1) : null;

    // If the caller wants a different size AND no lanes are bound to this
    // reservation, delete it and fall through to re-create. This is the recovery
    // path for the common case: a previous deploy attempt failed before any
    // lanes deployed, locking the reservation at the wrong size.
    if (Number.isFinite(requestedMax) && requestedMax !== blockSize
        && block.start != null && block.end != null) {
      const usedRes = await cybercoreQuery(
        `SELECT COUNT(*)::int AS n FROM cybercore_lane
          WHERE vxlan_id BETWEEN $1 AND $2 AND status NOT IN ('error','deleted')`,
        [block.start, block.end]
      );
      if ((usedRes.rows[0]?.n || 0) === 0) {
        console.log(`[CIAB Reservation] Profile ${profileId.slice(0,8)}: resizing empty reservation ${blockSize}→${requestedMax} (deleting challenge ${ch.challenge_id.slice(0,8)})`);
        await cybercoreQuery(`DELETE FROM crucible_challenge WHERE challenge_id = $1`, [ch.challenge_id]);
        // fall through to step 2 (re-allocate)
      } else {
        // Lanes exist — can't resize, return existing as-is
        return {
          challenge_id: ch.challenge_id,
          challenge_key: ch.challenge_key,
          vxlan_block: block,
          max_students: blockSize,
          was_existing: true,
          spec: existingSpec
        };
      }
    } else {
      return {
        challenge_id: ch.challenge_id,
        challenge_key: ch.challenge_key,
        vxlan_block: block,
        max_students: blockSize,                // derived from the spec — no separate column
        was_existing: true,
        spec: existingSpec
      };
    }
  }

  // 2. New — validate requestedMax and find a free gap
  if (!Number.isFinite(requestedMax) || requestedMax < 1) {
    throw new Error(`requestedMax must be >= 1 (got ${requestedMax})`);
  }
  const searchSize = VXLAN_SEARCH_MAX - VXLAN_SEARCH_MIN + 1;
  if (requestedMax > searchSize) {
    throw new Error(`requestedMax ${requestedMax} exceeds VXLAN search window ${searchSize}`);
  }

  // 3. Walk every existing challenge's vxlan_block + every live cybercore_lane's
  //    vxlan_id (lanes spawned outside any vxlan_block convention still take IDs).
  //    Single ordered list of forbidden intervals; first big-enough gap wins.
  // status enum: draft | active | retired | archived. Only 'active' challenges
  // are holding live reservations; the others have been pulled from rotation.
  const blockRes = await cybercoreQuery(
    `SELECT challenge_key,
            (spec->'vxlan_block'->>'start')::int AS start,
            (spec->'vxlan_block'->>'end')::int   AS end
       FROM crucible_challenge
      WHERE spec ? 'vxlan_block'
        AND status = 'active'
        AND (spec->'vxlan_block'->>'start') IS NOT NULL`
  );
  const intervals = blockRes.rows
    .filter(r => Number.isFinite(r.end) && r.end >= VXLAN_SEARCH_MIN && r.start <= VXLAN_SEARCH_MAX)
    .map(r => ({ start: Math.max(r.start, VXLAN_SEARCH_MIN), end: Math.min(r.end, VXLAN_SEARCH_MAX) }))
    .sort((a, b) => a.start - b.start);

  let cursor = VXLAN_SEARCH_MIN;
  let slot = null;
  for (const r of intervals) {
    if (cursor + requestedMax - 1 < r.start) {
      slot = { start: cursor, end: cursor + requestedMax - 1 };
      break;
    }
    if (r.end + 1 > cursor) cursor = r.end + 1;
  }
  if (!slot && cursor + requestedMax - 1 <= VXLAN_SEARCH_MAX) {
    slot = { start: cursor, end: cursor + requestedMax - 1 };
  }
  if (!slot) {
    throw new Error(
      `Cannot reserve ${requestedMax} contiguous VXLAN IDs in search window ${VXLAN_SEARCH_MIN}-${VXLAN_SEARCH_MAX} — ` +
      `${intervals.length} existing challenge blocks. Bump CIAB_VXLAN_SEARCH_MAX or pick a smaller max_students.`
    );
  }

  // 4. Create the crucible_challenge row in cybercore_db with this block
  const challengeName = `CIAB Profile: ${companyName || profileId.slice(0, 8)}`;
  const finalSpec = { ...(spec || {}), vxlan_block: slot };

  const chInsert = await cybercoreQuery(
    `INSERT INTO crucible_challenge
       (challenge_key, name, description, challenge_type, difficulty, module_key, spec, subnet_scheme, status)
     VALUES ($1, $2, $3, 'multi_vm', 3, 'crucible', $4::jsonb, $5, 'active')
     RETURNING challenge_id, challenge_key`,
    [
      challengeKey, challengeName,
      `CIAB profile-derived challenge (auto-managed). Profile ID: ${profileId}`,
      JSON.stringify(finalSpec), subnetScheme
    ]
  );
  const challenge = chInsert.rows[0];

  console.log(`[CIAB Reservation] Profile ${profileId.slice(0,8)} → challenge ${challenge.challenge_id.slice(0,8)} (${challengeKey}), VXLAN ${slot.start}-${slot.end} (${requestedMax} slots)`);

  return {
    challenge_id: challenge.challenge_id,
    challenge_key: challenge.challenge_key,
    vxlan_block: slot,
    max_students: requestedMax,
    was_existing: false,
    spec: finalSpec
  };
}

/**
 * Delete a profile's challenge from cybercore_db. NO-OP if the profile never
 * had one. Lookup is by deterministic challenge_key — no profile-side state.
 */
async function deleteProfileChallenge(profileId) {
  const challengeKey = `ciab-profile-${profileId.slice(0, 8)}`;
  const result = await cybercoreQuery(
    `DELETE FROM crucible_challenge WHERE challenge_key = $1 RETURNING challenge_id`,
    [challengeKey]
  );
  if (result.rows.length === 0) return { deleted: false, reason: 'no_challenge' };
  console.log(`[CIAB Reservation] Released profile ${profileId.slice(0,8)} challenge ${result.rows[0].challenge_id.slice(0,8)}`);
  return { deleted: true, challenge_id: result.rows[0].challenge_id };
}

/**
 * Lookup helper: returns the profile's challenge + reservation info without
 * creating one. Returns null if no challenge exists.
 */
async function findProfileChallenge(profileId) {
  const challengeKey = `ciab-profile-${profileId.slice(0, 8)}`;
  const chRes = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, created_at, spec,
            (spec->'vxlan_block'->>'start')::int AS vxlan_start,
            (spec->'vxlan_block'->>'end')::int   AS vxlan_end
       FROM crucible_challenge WHERE challenge_key = $1`,
    [challengeKey]
  );
  if (chRes.rows.length === 0) return null;
  const ch = chRes.rows[0];
  const blockSize = (ch.vxlan_end != null && ch.vxlan_start != null)
    ? (ch.vxlan_end - ch.vxlan_start + 1) : null;
  return {
    challenge_id: ch.challenge_id,
    challenge_key: ch.challenge_key,
    created_at: ch.created_at,
    spec: typeof ch.spec === 'string' ? JSON.parse(ch.spec) : ch.spec,
    vxlan_block: { start: ch.vxlan_start, end: ch.vxlan_end },
    max_students: blockSize
  };
}

// ─── Look up VNet(s) by VXLAN tag ──────────────────────────────────────────
async function resolveVnets(vxlanId, subnetScheme) {
  const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const vnet = vnets.find(v => v.tag === vxlanId);
  if (!vnet) {
    throw new Error(`No Proxmox SDN VNet with tag ${vxlanId} — provision a challenge zone first`);
  }
  let vnetInt = null;
  if (subnetScheme === 'v3') {
    const intTag = vxlanId + V3_INTERNAL_TAG_OFFSET;
    vnetInt = vnets.find(v => v.tag === intTag);
    if (!vnetInt) {
      throw new Error(`v3 lane needs internal VNet with tag ${intTag} too`);
    }
  }
  return { vnet, vnetInt };
}

// ─── Auto-provision SDN zone + VNets for the batch ────────────────────────
// Proxmox VNet IDs must be ≤8 alphanumeric chars (no hyphens), so we use the
// same base-20 encoding as front-end/src/routes/lab-templates.js for the VNet
// names. Zone names follow the same 8-char alphanumeric rule.
// Called once per batch before the per-lane resolveVnets loop, so we don't
// race N parallel zone/vnet creates.
const VNET_NAME_ALPHABET = 'abcdefghij0123456789';  // 20 chars, letters first
function encodeVnetName(n) {
  if (n === 0) return 'aaaaaaaa';
  let s = '';
  let x = n;
  while (x > 0) {
    s = VNET_NAME_ALPHABET[x % 20] + s;
    x = Math.floor(x / 20);
  }
  return s.padStart(8, 'a');
}

async function ensureSdnZoneAndVnets({ vxlanIds, subnetScheme, challengeKey, logTag }) {
  const tag = logTag || 'CIAB Deploy';
  const requiredTags = new Set();
  for (const id of vxlanIds) {
    requiredTags.add(id);
    if (subnetScheme === 'v3') requiredTags.add(id + V3_INTERNAL_TAG_OFFSET);
  }

  let vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const existingTags = new Set((vnets || []).map(v => v.tag));
  const missingTags = [...requiredTags].filter(t => !existingTags.has(t));
  if (missingTags.length === 0) return;

  // Zone name: 8-char alphanumeric, derived from challenge_key. Strip dashes,
  // truncate, lowercase. ('ciab-profile-abc12345' → 'ciabprof')
  const zoneAbbrev = ((challengeKey || 'ciabprof')
    .replace(/[^a-z0-9]/gi, '')
    .substring(0, 8)
    .toLowerCase()) || 'ciabprof';

  // Create zone if missing
  const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
  const zoneExists = (zones || []).some(z => z.zone === zoneAbbrev);
  if (!zoneExists) {
    const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
    const nodeIps = (nodeList || [])
      .map((n, i) => n.ip || `100.100.10.${10 + i}`)
      .join(',');
    console.log(`[${tag}] Creating SDN zone '${zoneAbbrev}' (vxlan, peers=${nodeIps})`);
    await proxmoxAPI('POST', '/api2/json/cluster/sdn/zones', {
      zone: zoneAbbrev,
      type: 'vxlan',
      peers: nodeIps,
      ipam: 'pve'
    });
  }

  // Create missing VNets — base-20 encoded name (matches lab-templates.js)
  for (const vxTag of missingTags) {
    const vnetName = encodeVnetName(vxTag);
    console.log(`[${tag}] Creating VNet '${vnetName}' (tag=${vxTag}, zone=${zoneAbbrev})`);
    await proxmoxAPI('POST', '/api2/json/cluster/sdn/vnets', {
      vnet: vnetName,
      zone: zoneAbbrev,
      tag: vxTag,
      alias: `${zoneAbbrev}-vnet-${vxTag}`
    });
  }

  // Reload SDN once for the whole batch
  console.log(`[${tag}] Reloading SDN (${missingTags.length} new VNets in '${zoneAbbrev}')`);
  await proxmoxAPI('PUT', '/api2/json/cluster/sdn');
  await new Promise(r => setTimeout(r, 5000));

  // Verify the requested tags now appear
  vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const stillMissing = [...requiredTags].filter(t => !vnets.some(v => v.tag === t));
  if (stillMissing.length > 0) {
    throw new Error(`SDN reload did not surface VNets for tags: ${stillMissing.join(',')} — may need manual reload`);
  }
}

// ─── Phase 1a — gateway template replication (LXC lock workaround) ────────
async function replicateGatewayTemplates({ gatewayVmid, templateNode, uniqueNodes, groupName }) {
  const tempIds = {};
  let counter = 0;
  for (const node of uniqueNodes) {
    if (node === templateNode) {
      tempIds[node] = gatewayVmid;
      continue;
    }
    const tempId = TEMP_GW_TEMPLATE_BASE + counter++;
    try {
      const cloneRes = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
        newid: tempId,
        hostname: `gw-template-temp-${node}`,
        full: 1,
        target: node,
        description: `Temp gateway template for CIAB profile-deploy (group: ${groupName})`
      });
      if (cloneRes) await waitForTask(templateNode, cloneRes);
      tempIds[node] = tempId;
    } catch (err) {
      console.warn(`[CIAB Deploy ${groupName}] Failed to replicate gateway to ${node}: ${err.message} — falling back to original`);
      tempIds[node] = gatewayVmid;
    }
  }
  return tempIds;
}

// ─── Phase 1b — clone N gateway LXCs ───────────────────────────────────────
async function cloneGateways({ laneJobs, tempTemplateIds, subnetScheme, module, vnetByLaneId, vnetIntByLaneId, groupName, templateNode }) {
  const lanesByNode = {};
  for (const job of laneJobs) {
    if (!lanesByNode[job.targetNode]) lanesByNode[job.targetNode] = [];
    lanesByNode[job.targetNode].push(job);
  }
  const results = {};

  await Promise.all(Object.entries(lanesByNode).map(async ([node, jobs]) => {
    const localTemplateId = tempTemplateIds[node];
    const sourceNode = node === templateNode ? templateNode : node;
    for (const job of jobs) {
      const { laneId, vxlanId, laneName } = job;
      const gatewayVmId = 100000 + vxlanId;
      const vnet = vnetByLaneId[laneId];
      const vnetInt = vnetIntByLaneId[laneId];
      try {
        const cloneRes = await proxmoxAPI('POST', `/api2/json/nodes/${sourceNode}/lxc/${localTemplateId}/clone`, {
          newid: gatewayVmId,
          hostname: `${laneName}-gw`.substring(0, 63).toLowerCase(),
          full: 1,
          target: node,
          description: `CIAB Profile Lane\nGroup: ${groupName}\nLane: ${laneId}`
        });
        if (cloneRes) await waitForTask(sourceNode, cloneRes);

        const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
        if (subnetScheme === 'v3') {
          await proxmoxAPI('PUT', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/config`, {
            net0: formatLaneGatewayNet0(net.wan),
            net1: `name=ext0,bridge=${vnet.vnet},ip=${net.lanExt.gatewayIp}/24,type=veth`,
            net2: `name=int0,bridge=${vnetInt.vnet},ip=${net.lanInt.gatewayIp}/24,type=veth`
          });
        } else {
          await proxmoxAPI('PUT', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/config`, {
            net0: formatLaneGatewayNet0(net.wan),
            net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`
          });
        }

        await configureLaneTailscale({
          subnetScheme,
          vxlanId,
          wanIp: net.wan.ip.split('/')[0],
          laneName,
          logTag: `[CIAB Deploy ${groupName}]`
        });

        results[laneId] = { success: true, gatewayVmId };
      } catch (err) {
        console.error(`[CIAB Deploy ${groupName}] Gateway clone failed for lane ${laneId}: ${err.message}`);
        results[laneId] = { success: false, error: err.message };
      }
    }
  }));

  return results;
}

// ─── Phase 1c — delete temp template copies ────────────────────────────────
async function cleanupTempTemplates(tempTemplateIds, originalGatewayVmid, groupName) {
  const toDelete = Object.entries(tempTemplateIds)
    .filter(([_, id]) => id !== originalGatewayVmid)
    .map(([node, id]) => ({ node, id }));
  await Promise.all(toDelete.map(async ({ node, id }) => {
    try {
      await proxmoxAPI('DELETE', `/api2/json/nodes/${node}/lxc/${id}?purge=1&force=1`);
    } catch (e) {
      console.warn(`[CIAB Deploy ${groupName}] Could not delete temp template ${id} on ${node}: ${e.message}`);
    }
  }));
}

// ─── Vuln-app installer execution ──────────────────────────────────────────
// Writes source_tree files via QEMU guest agent, then runs install_script.
async function installVulnAppOnVM({ node, vmId, vmName, vulnAppInstall, logTag }) {
  if (!vulnAppInstall) return { success: true, skipped: true };
  const { mode, install_script, source_tree, dockerfile } = vulnAppInstall;

  const targetDir = mode === 'docker' ? '/opt/vuln-app' : '/var/www/html';
  console.log(`${logTag} Installing vuln app on ${vmName} (mode=${mode}, dir=${targetDir})`);

  try {
    await agentExec(node, vmId, `mkdir -p ${targetDir}`);

    if (source_tree && typeof source_tree === 'object') {
      for (const [relPath, content] of Object.entries(source_tree)) {
        const safePath = relPath.replace(/\.\./g, '').replace(/^\/+/, '');
        const fullPath = `${targetDir}/${safePath}`;
        const writer = content.length > 8000 ? guestWriteLargeText : guestFileWrite;
        await writer(node, vmId, fullPath, content);
      }
    }
    if (dockerfile && mode === 'docker') {
      await guestFileWrite(node, vmId, `${targetDir}/Dockerfile`, dockerfile);
    }

    // Run install_script inline via agentExec → poll until exit
    const exec = await agentExec(node, vmId, install_script);
    const pid = exec && (exec.pid || (exec.result && exec.result.pid));
    if (pid) {
      const result = await pollExecStatus(node, vmId, pid, 15 * 60 * 1000);
      if (result && result['exit-code'] !== 0) {
        return { success: false, error: `install_script exited ${result['exit-code']}`, stderr: result['err-data'] || null };
      }
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Build /etc/hosts entries for Kali ─────────────────────────────────────
// For each deployed VM that has an IP, emit one entry. The web-server VM
// (the one matched by isWebServer in the synthesizer / vulnAppInstall) also
// gets the company's public domain as an alias, so visiting
// `http://meridianadvisors.com` on Kali hits the actual deployed web-01.
function buildKaliHostsEntries({ deployedVMs, domain }) {
  const out = [];
  const webServerNames = new Set();
  for (const vm of deployedVMs) {
    if (!vm.ip) continue;
    // Identify web-server VMs by either: role=server with HTTP/HTTPS service,
    // OR an exact role string match like 'web'.
    const services = Array.isArray(vm.services) ? vm.services : [];
    const isWeb = String(vm.role || '').toLowerCase() === 'server' &&
      services.some(s => /(^|\/)https?$/i.test(String(s)) || /^(80|443)\//.test(String(s)));
    if (isWeb) webServerNames.add(vm.name);
  }
  for (const vm of deployedVMs) {
    if (!vm.ip || !vm.name) continue;
    const aliases = [vm.name.toLowerCase()];
    if (domain && webServerNames.has(vm.name)) aliases.push(domain.toLowerCase());
    out.push({ ip: vm.ip, hostnames: aliases });
  }
  return out;
}

// ─── Post-clone vuln_scripts execution ─────────────────────────────────────
async function runPostCloneScripts({ node, vmId, vmName, scriptSlugs, logTag }) {
  if (!scriptSlugs || scriptSlugs.length === 0) return { ran: 0 };
  // vuln_scripts lives in clinic_db (CIAB pool), not cybercore_db.
  const rows = await query(
    `SELECT slug, script_content, os_target, depends_on, script_args
     FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`,
    [scriptSlugs]
  );
  if (rows.rows.length === 0) return { ran: 0 };

  // executeScriptsOnVM's deploymentId is a UUID FK into `deployment_vuln_selections`
  // (admin's challenge-template flow). CIAB doesn't use that table — pass null
  // so updateScriptStatus short-circuits instead of erroring on a non-UUID.
  await executeScriptsOnVM(node, vmId, vmName, rows.rows, null);
  console.log(`${logTag} Ran ${rows.rows.length} post-clone scripts on ${vmName}`);
  return { ran: rows.rows.length };
}

// ─── Collect deployed VM IPs via guest agent ───────────────────────────────
async function collectVmIp(node, vmId, attempts = 10, intervalMs = 5000) {
  for (let i = 0; i < attempts; i++) {
    try {
      const data = await proxmoxAPI('GET', `/api2/json/nodes/${node}/qemu/${vmId}/agent/network-get-interfaces`);
      const ifaces = data.result || data || [];
      for (const iface of ifaces) {
        if (iface.name === 'lo') continue;
        for (const addr of (iface['ip-addresses'] || [])) {
          if (addr['ip-address-type'] === 'ipv4' && !addr['ip-address'].startsWith('127.')) {
            return addr['ip-address'];
          }
        }
      }
    } catch (_) {}
    if (i < attempts - 1) await new Promise(r => setTimeout(r, intervalMs));
  }
  return null;
}

// ─── Tailscale bootstrap verification ─────────────────────────────────────
// After a gateway starts, the bake script's firstboot tries to fetch the
// bootstrap token. If that succeeds, the row's `consumed_at` is set. We poll
// for it and warn loudly if it never happens.
//
// Note: Proxmox has no HTTP-API equivalent of `pct exec` for LXC, so we
// can't re-trigger firstboot from here. The bake script needs a longer retry
// window for slow-WAN cases (see bake-lane-gateway-v2.sh).
async function verifyTailscaleBootstrap({ vxlanId, gatewayVmId, targetNode, logTag, maxWaitMs = 120000 }) {
  // No token row → Tailscale was never staged (env vars not set, or v1). Skip.
  const rowExists = await cybercoreQuery(
    `SELECT 1 FROM lane_bootstrap_tokens WHERE vxlan_id = $1`, [vxlanId]
  );
  if (rowExists.rows.length === 0) {
    console.log(`${logTag} No Tailscale bootstrap row for vxlan ${vxlanId} — skipping verification`);
    return;
  }

  const startedAt = Date.now();
  while (Date.now() - startedAt < maxWaitMs) {
    const r = await cybercoreQuery(
      `SELECT consumed_at FROM lane_bootstrap_tokens WHERE vxlan_id = $1`,
      [vxlanId]
    );
    if (r.rows.length > 0 && r.rows[0].consumed_at !== null) {
      console.log(`${logTag} ✓ Tailscale bootstrap consumed for vxlan ${vxlanId} — lane gateway should be on the tailnet`);
      return;
    }
    await new Promise(r => setTimeout(r, 5000));
  }

  const orchUrl = process.env.CYBERCORE_ORCHESTRATOR_URL || 'http://100.100.20.50:3000';
  console.warn(`${logTag} ✗ Tailscale bootstrap NOT consumed for vxlan ${vxlanId} after ${Math.round(maxWaitMs/1000)}s.\n` +
               `    Likely causes: (a) gateway WAN took longer than the bake-script firstboot retry window (3×5s), ` +
               `(b) gateway can't reach orchestrator at ${orchUrl}, or (c) firstboot service never ran.\n` +
               `    Diagnose: pct enter ${gatewayVmId} on ${targetNode} → tail /var/log/messages | grep firstboot, then run /etc/local.d/00-cybercore-firstboot.start manually.\n` +
               `    Permanent fix: re-bake the gateway template with a longer retry window in bake-lane-gateway-v2.sh.`);
}

// ─── Single-lane deploy (called by batch + retry endpoint) ─────────────────
async function deployOneLaneFromSpec({
  laneId, jobId, spec, vxlanId, vnet, vnetInt, gatewayVmId, targetNode, templateNode,
  groupId, groupName, vulnAppInstall, attackBoxes, subnetScheme, module, cloneSem,
  progress, domain
}) {
  const logTag = `[CIAB Deploy ${groupName}]`;
  const isV3 = subnetScheme === 'v3';
  const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
  const vnetExtName = vnet.vnet;
  const vnetIntName = isV3 ? vnetInt.vnet : vnet.vnet;
  const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;

  const startedAt = Date.now();
  await query(
    `UPDATE ciab_profile_lane_jobs SET status='cloning', started_at=NOW(), target_node=$2 WHERE id=$1`,
    [jobId, targetNode]
  );
  if (progress) progress.lanes[laneId] = { status: 'cloning', node: targetNode, vxlan: vxlanId, _startedAt: startedAt };

  const deployedVMs = [];
  const allVmIds = [gatewayVmId];

  // ── Pre-clone idempotency: destroy any stale VMs at expected target VMIDs ─
  // VMIDs are deterministic from vxlan_id, so a previous failed deploy on the
  // same vxlan can leave VMs that block fresh clones. Same pattern as
  // admin/lanes.js:508 — query cluster/resources once, then only destroy VMs
  // that actually exist (with the known node).
  //
  // IMPORTANT: do NOT include `gatewayVmId` here — Phase 1 (cloneGateways) just
  // created it and we're in Phase 2. Destroying it now would orphan the lane.
  const expectedVmIds = [
    ...(spec.vms || []).map(vmSpec => ({
      id: (vmSpec.vm_offset || 600000) + vxlanId,
      type: vmSpec.type || 'qemu'
    }))
  ];
  if (attackBoxes) {
    expectedVmIds.push({ id: ATTACK_BOX_VMID_OFFSET + vxlanId, type: 'qemu' });
  }
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const liveById = new Map();
    for (const r of (resources || [])) {
      liveById.set(Number(r.vmid), { node: r.node, type: r.type });  // r.type = 'qemu' | 'lxc'
    }
    const stale = expectedVmIds.filter(v => liveById.has(v.id));
    if (stale.length > 0) {
      console.log(`${logTag} Pre-clone: destroying ${stale.length} stale VM(s) from a prior failed attempt: ${stale.map(s => s.id).join(',')}`);
      for (const { id } of stale) {
        const live = liveById.get(id);
        await forceDestroyVM(id, live.type, live.node);
      }
    }
  } catch (e) {
    console.warn(`${logTag} Pre-clone cleanup query failed (continuing): ${e.message}`);
  }

  try {
    // ── Clone challenge VMs in parallel via the shared semaphore ────────
    const clonePromises = (spec.vms || []).map(async (vmSpec) => {
      const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
      allVmIds.push(vmId);
      const vmType = vmSpec.type || 'qemu';
      const vmName = vmSpec.name;
      const sourceNode = vmSpec.template_node || templateNode;

      await cloneSem.run(async () => {
        if (vmType === 'lxc') {
          const r = await proxmoxAPI('POST', `/api2/json/nodes/${sourceNode}/lxc/${vmSpec.template_vmid}/clone`, {
            newid: vmId,
            hostname: `${vmName}-${vxlanId}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(),
            full: 1, target: targetNode,
            description: `CIAB Profile Lane\nGroup: ${groupName}\nLane: ${laneId}\nVM: ${vmName}`
          });
          if (r) await waitForTask(sourceNode, r);
          await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/lxc/${vmId}/config`, {
            net1: `name=eth0,bridge=${vnetExtName},type=veth`
          });
        } else {
          const r = await proxmoxAPI('POST', `/api2/json/nodes/${sourceNode}/qemu/${vmSpec.template_vmid}/clone`, {
            newid: vmId,
            name: `${vmName}-${vxlanId}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(),
            full: 1, target: targetNode,
            description: `CIAB Profile Lane\nGroup: ${groupName}\nLane: ${laneId}\nVM: ${vmName}`
          });
          if (r) await waitForTask(sourceNode, r);
          await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${vmId}/config`, {
            net0: `virtio,bridge=${vnetExtName}`
          });
        }
      });

      return { vm_id: vmId, name: vmName, type: vmType, node: targetNode,
               role: vmSpec.role, services: vmSpec.services || [],
               post_clone_scripts: vmSpec.post_clone_scripts || [] };
    });

    // ── Kali attack box ─────────────────────────────────────────────────
    const attackBoxVmId = attackBoxes ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null;
    if (attackBoxVmId) allVmIds.push(attackBoxVmId);

    const kaliPromise = attackBoxVmId ? (async () => {
      await cloneSem.run(async () => {
        const r = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${KALI_TEMPLATE_VMID}/clone`, {
          newid: attackBoxVmId,
          name: `kali-${vxlanId}`,
          full: 1, target: targetNode,
          description: `CIAB Attack Box\nGroup: ${groupName}\nLane: ${laneId}`
        });
        if (r) await waitForTask(templateNode, r);
      });
      await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/config`, {
        net0: `virtio,bridge=${vnetExtName}`,
        nameserver: `${laneSubnetBase}.1`
      });
      await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/cloudinit`).catch(() => {});
    })() : Promise.resolve();

    await query(`UPDATE ciab_profile_lane_jobs SET vm_ids=$2 WHERE id=$1`, [jobId, allVmIds]);
    const [clonedVMs] = await Promise.all([Promise.all(clonePromises), kaliPromise]);
    deployedVMs.push(...clonedVMs);

    // ── Start gateway, then all VMs ─────────────────────────────────────
    await query(`UPDATE ciab_profile_lane_jobs SET status='firstboot', phase_detail='Starting VMs' WHERE id=$1`, [jobId]);
    if (progress) progress.lanes[laneId].status = 'starting';

    await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/status/start`);
    await new Promise(r => setTimeout(r, 5000));
    for (const dvm of deployedVMs) {
      const startPath = dvm.type === 'lxc'
        ? `/api2/json/nodes/${dvm.node}/lxc/${dvm.vm_id}/status/start`
        : `/api2/json/nodes/${dvm.node}/qemu/${dvm.vm_id}/status/start`;
      await proxmoxAPI('POST', startPath);
    }
    if (attackBoxVmId) {
      await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/status/start`);
    }

    // ── Verify Tailscale bootstrap was consumed; re-trigger firstboot if not ──
    // The bake script's firstboot only retries 3× over ~15s. If the gateway's
    // WAN comes up late or DNS/routing settles slowly, the bootstrap fetch
    // gives up silently and Tailscale never joins. Poll the token row; if
    // still unconsumed after ~75s, re-run firstboot via pct exec.
    await verifyTailscaleBootstrap({
      vxlanId, gatewayVmId, targetNode, logTag
    }).catch(err => {
      console.warn(`${logTag} Tailscale verification failed (deploy continues): ${err.message}`);
    });

    // ── Wait for guest agents + run post-clone scripts + install vuln app ──
    // Status stays 'firstboot' per the table CHECK constraint
    // (pending|cloning|firstboot|active|error); detail moves through phases.
    if (progress) progress.lanes[laneId].status = 'configuring';
    await query(`UPDATE ciab_profile_lane_jobs SET phase_detail='Waiting for guest agent' WHERE id=$1`, [jobId]);

    for (const dvm of deployedVMs) {
      if (dvm.type !== 'qemu') continue;
      await query(`UPDATE ciab_profile_lane_jobs SET phase_detail=$2 WHERE id=$1`,
                  [jobId, `Waiting for guest agent on ${dvm.name}`]);
      const ready = await waitForGuestAgent(dvm.node, dvm.vm_id, 240000);
      if (!ready) {
        console.warn(`${logTag} Guest agent did not come up on ${dvm.name} — skipping scripts`);
        continue;
      }

      // Per-VM post_clone_scripts (from synthesizer)
      if (Array.isArray(dvm.post_clone_scripts) && dvm.post_clone_scripts.length > 0) {
        await query(`UPDATE ciab_profile_lane_jobs SET phase_detail=$2 WHERE id=$1`,
                    [jobId, `Running ${dvm.post_clone_scripts.length} scripts on ${dvm.name}`]);
        await runPostCloneScripts({ node: dvm.node, vmId: dvm.vm_id, vmName: dvm.name,
                                    scriptSlugs: dvm.post_clone_scripts, logTag }).catch(err => {
          console.warn(`${logTag} post-clone scripts failed on ${dvm.name}: ${err.message}`);
        });
      }

      // Vuln-app install (only on the matched target VM)
      if (vulnAppInstall && vulnAppInstall.target_vm === dvm.name) {
        await query(`UPDATE ciab_profile_lane_jobs SET phase_detail=$2 WHERE id=$1`,
                    [jobId, `Installing vuln app on ${dvm.name} (${vulnAppInstall.mode})`]);
        const appResult = await installVulnAppOnVM({ node: dvm.node, vmId: dvm.vm_id, vmName: dvm.name,
                                                     vulnAppInstall, logTag });
        if (!appResult.success && !appResult.skipped) {
          console.warn(`${logTag} Vuln app install failed on ${dvm.name}: ${appResult.error}`);
        }
      }

      // Collect IP + write back into ciab_profile_lane_groups.lane_ip_writeback
      await query(`UPDATE ciab_profile_lane_jobs SET phase_detail=$2 WHERE id=$1`,
                  [jobId, `Collecting IP for ${dvm.name}`]);
      const ip = await collectVmIp(dvm.node, dvm.vm_id, 6, 4000);
      if (ip) {
        dvm.ip = ip;
        await query(
          `UPDATE ciab_profile_lane_groups
           SET lane_ip_writeback = jsonb_set(
             COALESCE(lane_ip_writeback, '{}'::jsonb),
             ARRAY[$2::text, $3::text],
             to_jsonb($4::text),
             true
           ), updated_at = NOW()
           WHERE id = $1`,
          [groupId, dvm.name, laneId, ip]
        );
      }
    }

    // ── Optional: create Guacamole connection for the Kali box ─────────
    let kaliIp = null;
    if (attackBoxVmId) {
      await query(`UPDATE ciab_profile_lane_jobs SET phase_detail='Configuring Kali attack box' WHERE id=$1`, [jobId]);
      kaliIp = await collectVmIp(targetNode, attackBoxVmId, 6, 4000);

      // ── Inject /etc/hosts entries on Kali so students can hit the company
      // ── domain (and each VM's hostname) without DNS. The company's
      // ── `domain_public` from the profile points at the web-server VM's
      // ── real IP; every other deployed VM is also added by hostname so
      // ── `ping dc-01` etc. works out of the box.
      if (kaliIp) {
        try {
          const ready = await waitForGuestAgent(targetNode, attackBoxVmId, 180000);
          if (ready) {
            const hostsEntries = buildKaliHostsEntries({ deployedVMs, domain });
            if (hostsEntries.length > 0) {
              const block = [
                '# === CIAB lane hosts (auto-injected) ===',
                ...hostsEntries.map(e => `${e.ip}\t${e.hostnames.join(' ')}`),
                '# === end CIAB block ==='
              ].join('\n');
              // tee -a is the safest way to append via guest agent (no shell quoting nightmare)
              const cmd = `bash -c "cat <<'CIAB_HOSTS_EOF' >> /etc/hosts\n${block}\nCIAB_HOSTS_EOF"`;
              await agentExec(targetNode, attackBoxVmId, cmd);
              console.log(`${logTag} Injected ${hostsEntries.length} /etc/hosts entries on Kali (lane ${vxlanId})`);
            }
          } else {
            console.warn(`${logTag} Kali guest agent not ready — skipping /etc/hosts injection`);
          }
        } catch (hostsErr) {
          console.warn(`${logTag} /etc/hosts injection failed on Kali: ${hostsErr.message}`);
        }
      }

      if (kaliIp) {
        try {
          await guacAPI('POST', '/connections', {
            name: `${groupName} - lane${vxlanId} - Kali`,
            protocol: 'rdp',
            parentIdentifier: 'ROOT',
            parameters: {
              hostname: kaliIp, port: '3389',
              username: 'kali', password: 'kali',
              security: 'any', 'ignore-cert': 'true',
              'enable-wallpaper': 'true', 'enable-font-smoothing': 'true',
              'color-depth': '24', 'resize-method': 'display-update'
            },
            attributes: { 'max-connections': '4', 'max-connections-per-user': '2' }
          });
        } catch (gErr) {
          console.warn(`${logTag} Guac connection failed for lane ${vxlanId}: ${gErr.message}`);
        }
      }
    }

    // ── Update cybercore_lane with the deployed config ──────────────────
    const activeConfig = {
      challenge_vm_id: deployedVMs[0]?.vm_id,
      gateway_vm_id: gatewayVmId,
      attack_box_vm_id: attackBoxVmId,
      node: targetNode,
      module,
      group_id: groupId,
      group_name: groupName,
      profile_lane_group: true,
      vms: deployedVMs,
      subnet_scheme: subnetScheme,
      lane_subnet_base: laneSubnetBase,
      vnet: vnetExtName,
      ...(isV3 ? { vnet_internal: vnetIntName, lane_subnet_internal: net.lanInt.base3 } : {})
    };
    await cybercoreQuery(
      `UPDATE cybercore_lane SET status='active', config=$2::jsonb, updated_at=NOW() WHERE lane_id=$1`,
      [laneId, JSON.stringify(activeConfig)]
    );

    await query(
      `UPDATE ciab_profile_lane_jobs SET status='active', phase_detail='Deployed', finished_at=NOW() WHERE id=$1`,
      [jobId]
    );

    if (progress) {
      progress.lanes[laneId].status = 'active';
      if (progress.lanes[laneId]._startedAt) {
        progress._laneTimes.push(Date.now() - progress.lanes[laneId]._startedAt);
      }
    }

    return { success: true, laneId, vxlanId, vmIds: allVmIds };
  } catch (err) {
    await query(
      `UPDATE ciab_profile_lane_jobs SET status='error', error_msg=$2, finished_at=NOW() WHERE id=$1`,
      [jobId, err.message]
    );
    await cybercoreQuery(
      `UPDATE cybercore_lane SET status='error', config = COALESCE(config,'{}'::jsonb) || $2::jsonb, updated_at=NOW() WHERE lane_id=$1`,
      [laneId, JSON.stringify({ error: err.message })]
    ).catch(() => {});
    if (progress) progress.lanes[laneId] = { ...(progress.lanes[laneId] || {}), status: 'error', error: err.message };
    throw err;
  }
}

// ─── Batch entrypoint ─────────────────────────────────────────────────────
/**
 * @param {object} args
 * @param {string} args.groupId
 * @param {string} args.groupName
 * @param {object} args.spec                 from synthesizeSpecFromProfile
 * @param {Array}  args.laneAllocations      [{ laneId, jobId, vxlanId }]
 * @param {string} args.subnetScheme         default 'v2'
 * @param {string} args.module               'ciab'
 * @param {boolean}args.attackBoxes
 * @param {object} [args.vulnAppInstall]     from spec.vuln_app_install
 * @returns {Promise<{succeeded, failed, errors}>}
 */
async function deployProfileLanesBatch({
  groupId, groupName, spec, laneAllocations,
  subnetScheme = 'v2', module: moduleKey = 'ciab',
  attackBoxes = true, vulnAppInstall = null, domain = null,
  challengeKey = null
}) {
  const templateNode = spec.template_node || 'cyberhub-node-5';
  const gatewayVmid = resolveGatewayVmid(moduleKey, subnetScheme, spec);
  const concurrency = DEFAULT_CONCURRENCY;
  const cloneSem = createCloneSemaphore();
  const progress = initProgress(groupId, laneAllocations.length, groupName);

  // ── Auto-provision SDN zone + VNets for the whole batch ────────────────
  // CIAB ephemeral challenges aren't created via /create-lab, so their SDN
  // infrastructure doesn't exist yet. Do this once up-front so the per-lane
  // resolveVnets loop is a plain lookup.
  try {
    await ensureSdnZoneAndVnets({
      vxlanIds: laneAllocations.map(a => a.vxlanId),
      subnetScheme,
      challengeKey: challengeKey || spec.challenge_key || `ciab-${groupId.slice(0,8)}`,
      logTag: `CIAB Deploy ${groupName}`
    });
  } catch (err) {
    console.error(`[CIAB Deploy ${groupName}] SDN provision failed: ${err.message}`);
    for (const a of laneAllocations) {
      await query(`UPDATE ciab_profile_lane_jobs SET status='error', error_msg=$2 WHERE id=$1`,
                  [a.jobId, `SDN provision failed: ${err.message}`]);
    }
    await query(`UPDATE ciab_profile_lane_groups SET status='error', updated_at=NOW() WHERE id=$1`, [groupId]);
    return { succeeded: 0, failed: laneAllocations.length, errors: [err.message] };
  }

  // ── Resolve VNets (now present after ensureSdnZoneAndVnets) ────────────
  const vnetByLaneId = {};
  const vnetIntByLaneId = {};
  for (const a of laneAllocations) {
    try {
      const { vnet, vnetInt } = await resolveVnets(a.vxlanId, subnetScheme);
      vnetByLaneId[a.laneId] = vnet;
      vnetIntByLaneId[a.laneId] = vnetInt;
    } catch (err) {
      await query(`UPDATE ciab_profile_lane_jobs SET status='error', error_msg=$2 WHERE id=$1`,
                  [a.jobId, err.message]);
    }
  }
  const validAllocations = laneAllocations.filter(a => vnetByLaneId[a.laneId]);

  // ── Distribute lanes across cluster nodes ──────────────────────────────
  let nodeAssignments;
  try {
    nodeAssignments = await distributeAcrossNodes(proxmoxAPI, validAllocations.length);
  } catch (err) {
    console.warn(`[CIAB Deploy ${groupName}] distributeAcrossNodes failed: ${err.message} — falling back to best-node-per-lane`);
    const best = await selectBestNode();
    nodeAssignments = validAllocations.map(() => best.node);
  }
  const laneJobs = validAllocations.map((a, i) => ({
    laneId: a.laneId,
    jobId: a.jobId,
    vxlanId: a.vxlanId,
    laneName: formatLaneHostname({ vxlanId: a.vxlanId, laneName: `ciab-${groupName}` }),
    targetNode: nodeAssignments[i] || 'cyberhub-node-5'
  }));

  // ── Phase 1: gateway template replication + parallel clone ─────────────
  progress.phase = 'gateway';
  progress.phase_detail = 'Replicating gateway template';
  const uniqueNodes = [...new Set(laneJobs.map(j => j.targetNode))];
  const tempTemplateIds = await replicateGatewayTemplates({
    gatewayVmid, templateNode, uniqueNodes, groupName
  });

  progress.phase_detail = `Cloning ${laneJobs.length} gateways`;
  const gatewayResults = await cloneGateways({
    laneJobs, tempTemplateIds, subnetScheme, module: moduleKey,
    vnetByLaneId, vnetIntByLaneId, groupName, templateNode
  });

  await cleanupTempTemplates(tempTemplateIds, gatewayVmid, groupName);

  // Mark lanes whose gateway clone failed as error before Phase 2
  for (const job of laneJobs) {
    if (!gatewayResults[job.laneId]?.success) {
      await query(
        `UPDATE ciab_profile_lane_jobs SET status='error', error_msg=$2 WHERE id=$1`,
        [job.jobId, `Gateway clone failed: ${gatewayResults[job.laneId]?.error || 'unknown'}`]
      );
    }
  }
  const deployableJobs = laneJobs.filter(j => gatewayResults[j.laneId]?.success);

  // ── Phase 2: per-lane VM clones + firstboot + IP writeback ─────────────
  progress.phase = 'deploying';
  progress.phase_detail = `Deploying ${deployableJobs.length} lanes (max ${concurrency} concurrent)`;

  const { results, errors } = await runBatch(deployableJobs, async (job) => {
    return await deployOneLaneFromSpec({
      laneId: job.laneId,
      jobId: job.jobId,
      spec,
      vxlanId: job.vxlanId,
      vnet: vnetByLaneId[job.laneId],
      vnetInt: vnetIntByLaneId[job.laneId],
      gatewayVmId: gatewayResults[job.laneId].gatewayVmId,
      targetNode: job.targetNode,
      templateNode,
      groupId,
      groupName,
      vulnAppInstall,
      attackBoxes,
      subnetScheme,
      module: moduleKey,
      cloneSem,
      progress,
      domain
    });
  }, {
    concurrency,
    onProgress: (completed, total, _job, result) => {
      progress.completed = completed;
      if (result && result.success) progress.succeeded++;
      else progress.failed++;
      updateTiming(progress, concurrency);
    }
  });

  // ── Finalize group status ──────────────────────────────────────────────
  const totalFailed = (laneJobs.length - deployableJobs.length) + progress.failed;
  let finalStatus;
  if (totalFailed === 0) finalStatus = 'active';
  else if (totalFailed === laneJobs.length) finalStatus = 'error';
  else finalStatus = 'partial';

  await query(
    `UPDATE ciab_profile_lane_groups SET status=$2, updated_at=NOW() WHERE id=$1`,
    [groupId, finalStatus]
  );

  progress.phase = 'complete';
  progress.phase_detail = `${progress.succeeded} succeeded, ${totalFailed} failed`;
  progress.finished_at = new Date().toISOString();
  progress.eta_s = 0;
  progress.eta_at = null;
  updateTiming(progress, concurrency);

  // GC progress after 1h
  setTimeout(() => {
    if (global._ciabProfileLaneProgress) delete global._ciabProfileLaneProgress[groupId];
  }, 3600000);

  return { succeeded: progress.succeeded, failed: totalFailed, errors };
}

// ─── Teardown a single lane (used by group DELETE + per-lane retry cleanup) ──
async function teardownLane({ laneId, vmIds }) {
  const errors = [];

  // Look up where VMs live (best effort)
  let nodeMap = {};
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    for (const r of resources) {
      if (vmIds && vmIds.includes(r.vmid)) nodeMap[r.vmid] = r.node;
    }
  } catch (e) {
    errors.push(`cluster/resources lookup failed: ${e.message}`);
  }

  for (const vmid of (vmIds || [])) {
    // Try LXC first if vmid is in the gateway range (100000-199999), else qemu
    const type = (vmid >= 100000 && vmid < 200000) ? 'lxc' : 'qemu';
    try {
      await forceDestroyVM(vmid, type, nodeMap[vmid]);
    } catch (e) {
      errors.push(`destroy ${type} ${vmid}: ${e.message}`);
    }
  }

  await cybercoreQuery(`DELETE FROM cybercore_lane WHERE lane_id=$1`, [laneId]).catch(() => {});
  return { errors };
}

module.exports = {
  deployProfileLanesBatch,
  deployOneLaneFromSpec,
  teardownLane,
  allocateVxlanIds,
  getOrCreateProfileChallenge,
  deleteProfileChallenge,
  findProfileChallenge,
  resolveVnets,
  ensureSdnZoneAndVnets,
  getProgress,
  installVulnAppOnVM,
  collectVmIp,
  VXLAN_SEARCH_MIN,
  VXLAN_SEARCH_MAX
};
