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
const { waitForGuestAgent, executeScriptsOnVM, guestFileWrite, agentExec, pollExecStatus, getVMIPs } = require('../../../../../src/utils/script-executor');
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

  // Pre-provision ALL VNets in the reservation block, not just on-demand per
  // deploy. Mirrors how challenge templates work: max_lanes = pre-created
  // SDN VNets ready before any lane deploys. Per-deploy ensureSdnZoneAndVnets
  // calls then become no-ops and the deploy proceeds without SDN-propagation
  // waits. Best-effort: if SDN provision fails, the per-deploy call will
  // retry; we don't fail the reservation creation just because SDN hiccupped.
  try {
    const allTagsInBlock = [];
    for (let id = slot.start; id <= slot.end; id++) allTagsInBlock.push(id);
    await ensureSdnZoneAndVnets({
      vxlanIds: allTagsInBlock,
      subnetScheme,
      challengeKey,
      logTag: `[CIAB Reservation ${profileId.slice(0,8)}]`
    });
  } catch (sdnErr) {
    console.warn(`[CIAB Reservation] Pre-provision of ${requestedMax} VNets failed (per-deploy will retry): ${sdnErr.message}`);
  }

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

  // 1. Read the challenge's spec first so we know which VXLAN block to free
  //    in Proxmox SDN (mirrors the regular challenge-delete teardown in
  //    front-end/src/routes/lab-templates.js — VNets + zone go too, not just
  //    the DB row).
  const chRes = await cybercoreQuery(
    `SELECT challenge_id, spec FROM crucible_challenge WHERE challenge_key = $1`,
    [challengeKey]
  );
  if (chRes.rows.length === 0) {
    return { deleted: false, reason: 'no_challenge' };
  }
  const ch = chRes.rows[0];
  const spec = typeof ch.spec === 'string' ? JSON.parse(ch.spec) : ch.spec;
  const block = (spec && spec.vxlan_block) || {};

  // 2. Tear down SDN VNets in the block range, then the zone if empty.
  let vnetsRemoved = 0;
  let zoneRemoved = false;
  if (Number.isFinite(block.start) && Number.isFinite(block.end)) {
    try {
      const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      const ours = (vnets || []).filter(v => {
        const t = Number(v.tag);
        if (!Number.isFinite(t)) return false;
        // External VNets (tag in block) AND v3 internal VNets (tag = block + V3_INTERNAL_TAG_OFFSET)
        return (t >= block.start && t <= block.end)
            || (t >= block.start + V3_INTERNAL_TAG_OFFSET && t <= block.end + V3_INTERNAL_TAG_OFFSET);
      });
      for (const v of ours) {
        try {
          await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${v.vnet}`);
          vnetsRemoved++;
        } catch (e) {
          console.warn(`[CIAB Reservation] Failed to delete VNet ${v.vnet}: ${e.message}`);
        }
      }

      // Derive zone the same way ensureSdnZoneAndVnets does, then drop it if empty.
      const zoneAbbrev = challengeKey
        .replace(/[^a-z0-9]/gi, '')
        .substring(0, 8)
        .toLowerCase();
      const remainingVnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      const zoneStillHasVnets = (remainingVnets || []).some(v => v.zone === zoneAbbrev);
      if (!zoneStillHasVnets && zoneAbbrev) {
        try {
          await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zoneAbbrev}`);
          zoneRemoved = true;
        } catch (e) {
          console.warn(`[CIAB Reservation] Failed to delete zone ${zoneAbbrev}: ${e.message}`);
        }
      }

      // Reload SDN so removals take effect cluster-wide.
      try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (_) {}
    } catch (sdnErr) {
      console.warn(`[CIAB Reservation] SDN cleanup for profile ${profileId.slice(0,8)} partial: ${sdnErr.message}`);
    }
  }

  // 3. Delete the challenge row last — once we're past SDN cleanup we don't
  //    care if SDN had partial failures; the DB row going away frees the
  //    VXLAN block to be re-used by future reservations.
  await cybercoreQuery(`DELETE FROM crucible_challenge WHERE challenge_id = $1`, [ch.challenge_id]);

  console.log(`[CIAB Reservation] Released profile ${profileId.slice(0,8)} challenge ${ch.challenge_id.slice(0,8)} — removed ${vnetsRemoved} VNet(s)${zoneRemoved ? ' + zone' : ''}`);
  return { deleted: true, challenge_id: ch.challenge_id, vnets_removed: vnetsRemoved, zone_removed: zoneRemoved };
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

  // Reload SDN once for the whole batch. Propagation time scales with the
  // number of VNets created — empirically ~5s base + 200ms per VNet works
  // for 1-50 VNets. Then poll for them to appear (up to 60s) instead of
  // failing on first miss.
  console.log(`[${tag}] Reloading SDN (${missingTags.length} new VNets in '${zoneAbbrev}')`);
  await proxmoxAPI('PUT', '/api2/json/cluster/sdn');
  const baseWait = Math.min(30000, 5000 + missingTags.length * 200);
  await new Promise(r => setTimeout(r, baseWait));

  // Poll for the requested tags to appear (up to another 60s for large batches)
  const pollDeadline = Date.now() + 60000;
  let stillMissing = [];
  while (Date.now() < pollDeadline) {
    vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    stillMissing = [...requiredTags].filter(t => !vnets.some(v => v.tag === t));
    if (stillMissing.length === 0) break;
    await new Promise(r => setTimeout(r, 3000));
  }
  if (stillMissing.length > 0) {
    throw new Error(`SDN reload did not surface VNets for tags: ${stillMissing.slice(0, 10).join(',')}${stillMissing.length > 10 ? ',...' : ''} — may need manual reload`);
  }
  console.log(`[${tag}] ✓ All ${requiredTags.size} VNets confirmed in SDN after ${Math.round((Date.now() - (Date.now() - baseWait))/1000)}s wait + poll`);
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

// ─── Shell out to curl for /agent/exec ─────────────────────────────────────
// Node's https.request consistently gets HTTP 596 (pveproxy 3-second backend
// timeout) on PVE 9.1.9, while curl with the same token + body + endpoint
// returns 200 in ~200ms. Hours of debugging (URL encoding, content-type,
// JSON vs form, keep-alive, Content-Length, etc.) yielded no Node-side fix.
// So we just exec curl. Reliable, defensible (curl ships in the orchestrator
// image), and the per-call overhead (~50ms forking curl) is irrelevant
// compared to the actual work the agent does.
async function proxmoxFormPOST(path, pairs) {
  const { spawn } = require('child_process');
  const { PROXMOX_URL } = require('../../../../../src/utils/proxmox');
  const tokenId = process.env.PROXMOX_TOKEN_ID;
  const tokenSecret = process.env.PROXMOX_TOKEN_SECRET;
  const url = `${PROXMOX_URL}${path}`;

  // Build curl args: one --data-urlencode per pair
  const args = [
    '-k', '-s',
    '-w', 'HTTP_STATUS:%{http_code}',
    '-X', 'POST',
    '-H', `Authorization: PVEAPIToken=${tokenId}=${tokenSecret}`
  ];
  for (const [k, v] of pairs) {
    args.push('--data-urlencode', `${k}=${v}`);
  }
  args.push(url);

  return new Promise((resolve, reject) => {
    const child = spawn('curl', args);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => stdout += d.toString());
    child.stderr.on('data', d => stderr += d.toString());
    child.on('error', err => reject(new Error(`curl spawn failed: ${err.message}`)));
    child.on('close', code => {
      if (code !== 0) {
        return reject(new Error(`curl exited ${code}: ${stderr.slice(0, 300)}`));
      }
      // Split body + status (we appended HTTP_STATUS:<code> via -w)
      const m = stdout.match(/^([\s\S]*)HTTP_STATUS:(\d+)$/);
      if (!m) return reject(new Error(`unparseable curl output: ${stdout.slice(0, 300)}`));
      const body = m[1];
      const status = parseInt(m[2], 10);
      if (status >= 400) {
        return reject(new Error(`Proxmox POST ${path} failed (${status}): ${body}`));
      }
      try {
        const json = JSON.parse(body);
        resolve(json.data !== undefined ? json.data : json);
      } catch {
        resolve(body);
      }
    });
  });
}

// ─── CIAB-local agent shell exec ───────────────────────────────────────────
// Mirrors what `qm guest exec <vmid> -- /bin/sh -c "..."` does: passes
// `command` as an ARRAY (path + args).
//
// IMPORTANT: We send this as JSON (Content-Type: application/json) rather
// than form-urlencoded. Per Proxmox forum / staff confirmation (PVE 8.x
// breaking change), the form-urlencoded "repeated `command=` field" wire
// format is ambiguous — many HTTP clients (incl. some Node behaviors)
// collapse/reorder duplicate keys or URL-encode `/` and `-` in ways the
// Perl backend mis-parses. The result is a hung guest-exec call that
// pveproxy times out as HTTP 596 with an empty body — which is EXACTLY
// the symptom we were chasing for hours. JSON sidesteps the entire
// serialization morass.
//   See: https://forum.proxmox.com/threads/issue-with-proxmox-8-2-4-qemu-guest-agent.151040/
//        https://forum.proxmox.com/threads/proxmox-ve-api-596-broken-pipe.137863/
//
// Retry behavior: 596s from pveproxy → pvedaemon → QMP timeouts still
// happen if back-to-back exec calls race on the agent's serial channel.
// The outer waitForAgentExecReady already polls exec-status to completion
// + adds a 2s settle delay, but we keep an internal 5-retry as belt-and-
// suspenders.
async function agentShellExec(node, vmId, shellCmd) {
  console.log(`[AgentShellExec] /bin/sh -c '${shellCmd.substring(0, 100).replace(/\n/g, ' ')}...' (${shellCmd.length} chars)`);

  // Three separate `command=...` form-urlencoded pairs with %20 for spaces
  // (matches curl --data-urlencode byte-for-byte). User verified this exact
  // shape returns HTTP 200 immediately via curl on PVE 9.1.9 with the same
  // token CIAB uses.
  const pairs = [
    ['command', '/bin/sh'],
    ['command', '-c'],
    ['command', shellCmd]
  ];

  let lastErr;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const result = await proxmoxFormPOST(
        `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
        pairs
      );
      const pid = result?.pid;
      if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);
      return { pid };
    } catch (err) {
      lastErr = err;
      // Retry on agent transient failures. Broadened the match to catch any
      // 596-ish status — sometimes the error message format varies. Also log
      // the full message on first failure so we can see exactly what's coming
      // back if the regex still doesn't match.
      const msg = String(err && err.message || err);
      const transient = /\(596\)/.test(msg)
        || /\b596\b/.test(msg)
        || /ECONNRESET|ETIMEDOUT|socket hang up|EPIPE/.test(msg);
      if (attempt === 1) {
        console.warn(`[AgentShellExec] vm=${vmId} attempt 1 raw error (transient=${transient}): ${msg.substring(0, 200)}`);
      }
      if (!transient || attempt === 5) throw err;
      const delayMs = 2000 * attempt;  // 2s, 4s, 6s, 8s
      console.warn(`[AgentShellExec] vm=${vmId} attempt ${attempt} got transient error, retrying in ${delayMs/1000}s`);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  throw lastErr;
}

// ─── Wait for the agent's exec channel to actually work ──────────────────
// waitForGuestAgent (in script-executor) only verifies guest-ping. The
// guest-exec RPC frequently 596's for several seconds afterward, especially
// on freshly-cloned Debian VMs. Probe with a real exec until success or
// timeout. Returns true if exec succeeded at least once, false on timeout.
async function waitForAgentExecReady(node, vmId, logTag, timeoutMs = 180000) {
  const startedAt = Date.now();
  let attempt = 0;
  while (Date.now() - startedAt < timeoutMs) {
    attempt++;
    try {
      const r = await agentShellExec(node, vmId, 'true');
      // CRITICAL: actually wait for the probe to COMPLETE on the agent side
      // before declaring ready. Without this, the API returns a PID instantly
      // but the agent may still be processing the previous command — the
      // immediate next call then 596s because the agent is busy.
      if (r && r.pid) {
        const status = await pollExecStatus(node, vmId, r.pid, 30000);
        if (!status || !status.exited) {
          throw new Error(`probe pid=${r.pid} did not complete within 30s`);
        }
      }
      console.log(`${logTag} ✓ Agent exec ready on vm=${vmId} (after ${attempt} attempt(s), ${Math.round((Date.now()-startedAt)/1000)}s)`);
      // Brief settle delay — empirically the agent rejects back-to-back calls
      // with 596 even after a verified-complete probe. 2s eliminates this.
      await new Promise(r => setTimeout(r, 2000));
      return true;
    } catch (err) {
      // agentShellExec already does its own internal 5-retry; if we get here
      // that means 5 quick retries all failed. Wait longer between rounds.
      if (Date.now() - startedAt >= timeoutMs) break;
      const waitMs = Math.min(15000, 5000 + attempt * 2000);
      console.warn(`${logTag} Agent exec not ready on vm=${vmId} (round ${attempt}): ${err.message.substring(0,120)} — waiting ${waitMs/1000}s`);
      await new Promise(r => setTimeout(r, waitMs));
    }
  }
  return false;
}

// ─── SSH-based vuln-app installer ──────────────────────────────────────────
// Sidesteps the chronically-flaky Proxmox /agent/exec endpoint (596 spam on
// any command after the first probe) by running the install via SSH instead.
// Requires the orchestrator to have IP reachability to the lane VM — works
// if the orchestrator host is on Tailscale (which has subnet routing for the
// lane via the gateway), or has a static route to 10.40.x.x.
//
// Uses sshpass for the bake-template's default 'web/bake-debug' credentials.
// (sshpass must be installed in the orchestrator container — add to Dockerfile.)
async function installVulnAppViaSSH({ node, vmId, vmName, vmIp, vulnAppInstall, logTag }) {
  if (!vulnAppInstall) return { success: true, skipped: true };
  if (!vmIp) return { success: false, error: 'no VM IP — cannot SSH' };
  const { mode, install_script, source_tree, dockerfile } = vulnAppInstall;
  const targetDir = mode === 'docker' ? '/opt/vuln-app' : '/var/www/html';
  console.log(`${logTag} Installing vuln app via SSH on ${vmName} (${vmIp}, mode=${mode}, dir=${targetDir})`);

  const fs = require('fs');
  const path = require('path');
  const { spawn } = require('child_process');

  const tmpDir = fs.mkdtempSync(`/tmp/ciab-vuln-${vmId}-`);
  try {
    // Materialize the bundle on disk so we can scp it
    fs.mkdirSync(path.join(tmpDir, 'files'), { recursive: true });
    if (source_tree && typeof source_tree === 'object') {
      for (const [relPath, content] of Object.entries(source_tree)) {
        const safe = relPath.replace(/\.\./g, '_').replace(/^\/+/, '');
        const full = path.join(tmpDir, 'files', safe);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content);
      }
    }
    if (dockerfile && mode === 'docker') {
      fs.writeFileSync(path.join(tmpDir, 'files', 'Dockerfile'), dockerfile);
    }
    fs.writeFileSync(path.join(tmpDir, 'install.sh'), install_script || '');

    // Tar the bundle so a single scp gets everything
    await runCommand('tar', ['czf', path.join(tmpDir, 'bundle.tar.gz'), '-C', tmpDir, 'install.sh', 'files']);

    const sshOpts = ['-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=10','-o','LogLevel=ERROR'];
    const sshpass = ['-p','bake-debug'];

    // 1. scp bundle to the VM
    await runCommand('sshpass', [...sshpass, 'scp', ...sshOpts,
      path.join(tmpDir, 'bundle.tar.gz'), `web@${vmIp}:/tmp/ciab-bundle.tar.gz`]);

    // 2. SSH in and install
    const remoteCmd = `set -e
sudo mkdir -p ${targetDir}
cd /tmp && rm -rf ciab-extract && mkdir ciab-extract && tar xzf ciab-bundle.tar.gz -C ciab-extract
sudo cp -rT ciab-extract/files/ ${targetDir}/
sudo chmod +x /tmp/ciab-extract/install.sh
sudo bash /tmp/ciab-extract/install.sh
echo "[ciab] install complete"
`;
    await runCommand('sshpass', [...sshpass, 'ssh', ...sshOpts, `web@${vmIp}`, remoteCmd]);

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
  }
}

function runCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    const child = require('child_process').spawn(cmd, args, { stdio: ['ignore','pipe','pipe'] });
    let stderr = '';
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} exited ${code}: ${stderr.slice(0, 500)}`));
    });
  });
}

// ─── File write via curl-based agent exec (bypasses broken guestFileWrite) ─
// The shared script-executor.js guestFileWrite uses proxmoxAPI's form-urlencoded
// serialization, which 596s on PVE 9.1.9. We bypass it entirely by base64-
// encoding the content and shipping it through a single `agentShellExec` call
// that does `base64 -d > file`. For >50KB files we chunk via append (>>) to
// avoid agent argv / Proxmox API body size limits.
async function writeFileViaShellExec({ node, vmId, fullPath, content, logTag }) {
  const buf = Buffer.from(content, 'utf8');
  const b64 = buf.toString('base64');
  const CHUNK = 48 * 1024;   // 48KB of base64 per agent call (~36KB binary)

  // Ensure parent dir exists, then truncate the file
  const dir = fullPath.replace(/\/[^/]+$/, '') || '/';
  await agentShellExec(node, vmId, `mkdir -p '${dir}' && : > '${fullPath}'`);

  if (b64.length <= CHUNK) {
    // Single-shot: echo base64 → decode → file
    await agentShellExec(node, vmId, `echo '${b64}' | base64 -d > '${fullPath}'`);
  } else {
    // Chunked: append each piece, decode at end into a different file, then mv
    const tmpPath = `${fullPath}.b64`;
    await agentShellExec(node, vmId, `: > '${tmpPath}'`);
    for (let i = 0; i < b64.length; i += CHUNK) {
      const piece = b64.slice(i, i + CHUNK);
      await agentShellExec(node, vmId, `printf %s '${piece}' >> '${tmpPath}'`);
    }
    await agentShellExec(node, vmId, `base64 -d < '${tmpPath}' > '${fullPath}' && rm -f '${tmpPath}'`);
  }
}

// ─── Vuln-app installer execution ──────────────────────────────────────────
// Writes source_tree files via QEMU guest agent, then runs install_script.
async function installVulnAppOnVM({ node, vmId, vmName, vulnAppInstall, logTag }) {
  if (!vulnAppInstall) return { success: true, skipped: true };
  const { mode, install_script, source_tree, dockerfile } = vulnAppInstall;

  const targetDir = mode === 'docker' ? '/opt/vuln-app' : '/var/www/html';
  console.log(`${logTag} Installing vuln app on ${vmName} (mode=${mode}, dir=${targetDir})`);

  try {
    console.log(`${logTag} [install:step1] mkdir ${targetDir}`);
    await agentShellExec(node, vmId, `mkdir -p ${targetDir}`);
    console.log(`${logTag} [install:step1] ✓ mkdir done`);

    if (source_tree && typeof source_tree === 'object') {
      const fileCount = Object.keys(source_tree).length;
      console.log(`${logTag} [install:step2] writing ${fileCount} source_tree file(s) via curl-based shell writes`);
      let i = 0;
      for (const [relPath, content] of Object.entries(source_tree)) {
        i++;
        const safePath = relPath.replace(/\.\./g, '').replace(/^\/+/, '');
        const fullPath = `${targetDir}/${safePath}`;
        // BYPASS the shared script-executor.js guestFileWrite — it uses the
        // broken proxmoxAPI (form-urlencoded) which 596s. Use base64+exec via
        // our working curl-based agentShellExec instead. Handles arbitrary
        // binary safely. Files >100KB get chunked at 64KB to stay under any
        // command-line / agent argv size limits.
        console.log(`${logTag} [install:step2] ${i}/${fileCount} ${fullPath} (${content.length} bytes)`);
        await writeFileViaShellExec({ node, vmId, fullPath, content, logTag });
      }
      console.log(`${logTag} [install:step2] ✓ source_tree written`);
    }
    if (dockerfile && mode === 'docker') {
      console.log(`${logTag} [install:step3] writing Dockerfile (${dockerfile.length} bytes)`);
      await writeFileViaShellExec({ node, vmId, fullPath: `${targetDir}/Dockerfile`, content: dockerfile, logTag });
      console.log(`${logTag} [install:step3] ✓ Dockerfile written`);
    }

    // Run install_script inline via sh on stdin → poll until exit
    console.log(`${logTag} [install:step4] running install_script (${(install_script||'').length} bytes)`);
    const exec = await agentShellExec(node, vmId, install_script);
    const pid = exec && (exec.pid || (exec.result && exec.result.pid));
    if (pid) {
      console.log(`${logTag} [install:step4] install_script pid=${pid}, polling for completion...`);
      const result = await pollExecStatus(node, vmId, pid, 15 * 60 * 1000);
      if (result && result['exit-code'] !== 0) {
        console.warn(`${logTag} [install:step4] ✗ install_script exited ${result['exit-code']}`);
        return { success: false, error: `install_script exited ${result['exit-code']}`, stderr: result['err-data'] || null };
      }
      console.log(`${logTag} [install:step4] ✓ install_script completed (exit ${result?.['exit-code']})`);
    }
    return { success: true };
  } catch (err) {
    console.warn(`${logTag} [install:CAUGHT] ${err.message}`);
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
        // Probe the agent's exec channel with a no-op until it actually
        // succeeds. waitForGuestAgent above only checks ping; exec often
        // 596s for several seconds after ping returns OK (especially on
        // Debian 13 / freshly-cloned VMs). Poll up to 3 minutes.
        await query(`UPDATE ciab_profile_lane_jobs SET phase_detail=$2 WHERE id=$1`,
                    [jobId, `Waiting for agent exec on ${dvm.name}`]);
        const ready = await waitForAgentExecReady(dvm.node, dvm.vm_id, logTag, 180000);
        if (!ready) {
          console.warn(`${logTag} Agent exec never became ready on ${dvm.name} after 180s — skipping vuln-app install`);
        } else {
          // Outer-level retry — even if agentShellExec's internal retry
          // doesn't fire (e.g. stale container), retry the WHOLE install
          // up to 3 times. The agent often goes from "ready" to 596 between
          // back-to-back calls; a small delay between attempts gives the
          // QMP channel time to recover.
          let appResult = { success: false };
          for (let attempt = 1; attempt <= 3; attempt++) {
            await query(`UPDATE ciab_profile_lane_jobs SET phase_detail=$2 WHERE id=$1`,
                        [jobId, `Installing vuln app on ${dvm.name} (${vulnAppInstall.mode}) [attempt ${attempt}/3]`]);
            appResult = await installVulnAppOnVM({ node: dvm.node, vmId: dvm.vm_id, vmName: dvm.name,
                                                   vulnAppInstall, logTag });
            if (appResult.success || appResult.skipped) break;
            // Retry only on transient agent errors. Hard application failures
            // (install script exited non-zero) shouldn't keep retrying.
            const transient = /\(596\)|\b596\b|ECONNRESET|ETIMEDOUT|socket hang up|EPIPE/.test(String(appResult.error || ''));
            if (!transient) {
              console.warn(`${logTag} Vuln app install failed on ${dvm.name} (non-transient, not retrying): ${appResult.error}`);
              break;
            }
            if (attempt < 3) {
              const waitMs = 10000 * attempt;
              console.warn(`${logTag} Vuln app install attempt ${attempt}/3 hit transient agent error (${appResult.error?.substring(0, 100)}); waiting ${waitMs/1000}s before retry`);
              await new Promise(r => setTimeout(r, waitMs));
              // Re-probe the exec channel before the next attempt
              await waitForAgentExecReady(dvm.node, dvm.vm_id, logTag, 60000);
            }
          }
          if (!appResult.success && !appResult.skipped) {
            console.warn(`${logTag} ✗ Vuln app install gave up on ${dvm.name} after 3 attempts: ${appResult.error}`);
          } else if (appResult.success) {
            console.log(`${logTag} ✓ Vuln app installed on ${dvm.name}`);
          }
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
              // Append the block to /etc/hosts via sh on stdin (agentShellExec
              // feeds the whole script to /bin/sh, no quoting required).
              const cmd = `cat >> /etc/hosts <<'CIAB_HOSTS_EOF'\n${block}\nCIAB_HOSTS_EOF\n`;
              await agentShellExec(targetNode, attackBoxVmId, cmd);
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
