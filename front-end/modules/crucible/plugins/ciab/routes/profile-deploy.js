/*
 * ============================================================================
 * Profile-Deploy Routes — admin deploys N cybercore lanes from one CIAB profile
 * ============================================================================
 * All endpoints are admin-only. Three intake paths into /deploy:
 *   (a) profile_id from CIAB profiles table (most common)
 *   (b) profile_id from a previously uploaded JSON  → /api/profiles/upload
 *   (c) one-step generate + deploy                  → /api/profiles/generate-and-deploy
 *
 * Lane deployment uses Proxmox API directly via lane-deploy.js — N8N is NOT
 * used here (N8N is only for profile/policy/scan generation in CIAB).
 *
 * Default subnet_scheme = 'v2' (subnet-agnostic 10.x.x.x lanes) — matches
 * where CIAB servers live today. v3 is honored if the admin explicitly picks
 * it, but no GOAD provisioning happens here.
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

const { pool, query } = require('../utils/db');
const { authenticateToken, requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');

const { synthesizeSpecFromProfile } = require('../utils/profile-to-spec');
const { getOrGenerateVulnApp } = require('../utils/vuln-app-generator');
const {
  deployProfileLanesBatch,
  deployOneLaneFromSpec,
  teardownLane,
  allocateVxlanIds,
  getOrCreateProfileChallenge,
  deleteProfileChallenge,
  findProfileChallenge,
  resolveVnets,
  getProgress,
  VXLAN_SEARCH_MIN,
  VXLAN_SEARCH_MAX
} = require('../utils/lane-deploy');
const {
  resolveGatewayVmid,
  forceDestroyVM
} = require('../utils/lane-networking');

const adminOnly = requireRole('admin');

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Load profile row + JSON file, normalize to a flat asset list.
 * Returns { profile, assets } or throws on not-found.
 */
async function loadProfileForDeploy(profileId) {
  const result = await pool.query(
    `SELECT id, user_id, company_name, industry, difficulty, client_type,
            json_file_path, html_file_path, run_id, generation_status
       FROM profiles
      WHERE id = $1`,
    [profileId]
  );
  if (result.rows.length === 0) {
    throw Object.assign(new Error('Profile not found'), { statusCode: 404 });
  }
  const profile = result.rows[0];

  // Load JSON from disk
  let json = null;
  if (profile.json_file_path) {
    const resolvedPath = path.join(process.cwd(), profile.json_file_path.replace(/^\//, ''));
    if (fs.existsSync(resolvedPath)) {
      const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
      json = Array.isArray(parsed) ? parsed[0] : parsed;
    }
  }
  if (!json) {
    throw Object.assign(new Error('Profile JSON file missing'), { statusCode: 422 });
  }

  // Normalize asset array out of the student_view.raw.threats.network.assets shape
  const assets = (json.student_view?.raw?.threats?.network?.assets) || json.assets || [];

  return {
    profile: { ...profile, assets, json_data: json },
    assets
  };
}

// (createEphemeralChallenge removed — challenges are now per-profile, managed
//  by getOrCreateProfileChallenge() in utils/lane-deploy.js)

/**
 * Build the default asset_selection from a list of assets: tick role==='server'.
 */
function defaultAssetSelection(assets) {
  return (Array.isArray(assets) ? assets : []).map(a => ({
    hostname: a.hostname,
    role: a.role,
    os: a.os,
    included: String(a.role || '').toLowerCase() === 'server'
  }));
}

// ─── Core: runProfileDeploy — invoked by /deploy AND generate-and-deploy ──
/**
 * Synthesizes spec, allocates VXLAN IDs, creates DB rows, kicks off background
 * deploy. Returns the group_id immediately (deployment runs async).
 *
 * @param {object} opts
 * @param {string} opts.profileId
 * @param {string} opts.userId             admin user_id
 * @param {number} opts.numLanes
 * @param {string} [opts.groupName]
 * @param {boolean}[opts.attackBoxes=true]
 * @param {string} [opts.subnetScheme='v2']
 * @param {Array}  [opts.assetSelection]   if omitted → default-server-only
 * @param {object} [opts.vulnAppOpts]      { enabled, delivery_mode, use_dedicated_vm, llm_model }
 * @returns {Promise<{group_id, profile_id, lanes:[...], service_gaps, template_misses}>}
 */
async function runProfileDeploy(opts) {
  const {
    profileId, userId, numLanes,
    maxStudents,                                           // ← NEW: total reservation size; defaults to numLanes
    groupName, attackBoxes = true, subnetScheme = 'v2',
    assetSelection: providedSelection, vulnAppOpts = {}
  } = opts;

  if (!profileId) throw Object.assign(new Error('profile_id required'), { statusCode: 400 });
  if (!Number.isFinite(numLanes) || numLanes < 1 || numLanes > 100) {
    throw Object.assign(new Error('num_lanes must be 1..100'), { statusCode: 400 });
  }
  if (!['v1', 'v2', 'v3'].includes(subnetScheme)) {
    throw Object.assign(new Error('subnet_scheme must be v1|v2|v3 (default v2)'), { statusCode: 400 });
  }
  // max_students reserves a VXLAN slice for future additions. Defaults to numLanes
  // (no headroom) for backward compatibility. Must be >= numLanes.
  const effectiveMaxStudents = Number.isFinite(maxStudents) && maxStudents > 0
    ? maxStudents
    : numLanes;
  if (effectiveMaxStudents < numLanes) {
    throw Object.assign(new Error(`max_students (${effectiveMaxStudents}) must be >= num_lanes (${numLanes})`), { statusCode: 400 });
  }
  if (effectiveMaxStudents > 200) {
    throw Object.assign(new Error('max_students cap is 200 per group'), { statusCode: 400 });
  }

  // 1. Load profile
  const { profile, assets } = await loadProfileForDeploy(profileId);

  // 2. Build asset selection
  const assetSelection = Array.isArray(providedSelection) && providedSelection.length > 0
    ? providedSelection
    : defaultAssetSelection(assets);

  // 3. Fetch catalogs — both tables live in clinic_db (CIAB pool), not cybercore_db.
  //    See front-end/migrations/013_vm_template_catalog.sql and 011_challenge_templates.sql.
  const [vmCatalogRes, vulnCatalogRes] = await Promise.all([
    query(`SELECT id, os_family, os_version, os_name, template_vmid, node, role_hints, is_active, preferred, created_at FROM vm_template_catalog WHERE is_active = true`),
    query(`SELECT id, slug, name, os_target, category, script_type, services_exposed, is_active FROM vuln_scripts WHERE is_active = true`)
  ]);
  const vmTemplateCatalog = vmCatalogRes.rows;
  const vulnScriptCatalog = vulnCatalogRes.rows;

  // 4. Get-or-generate vuln app (best-effort; skip if admin disabled)
  let vulnApp = null;
  if (vulnAppOpts.enabled !== false) {
    try {
      vulnApp = await getOrGenerateVulnApp({
        profile: { ...profile, assets },
        llmModel: vulnAppOpts.llm_model,
        preferMode: vulnAppOpts.delivery_mode || 'docker'
      });
    } catch (err) {
      console.warn(`[CIAB ProfileDeploy] vuln app generation failed (continuing): ${err.message}`);
    }
  }

  // 5. Synthesize the deploy spec (vxlan_block gets filled in by step 6 below)
  const { spec: rawSpec, service_gaps, template_misses } = synthesizeSpecFromProfile({
    profile: { ...profile, assets },
    assetSelection,
    vmTemplateCatalog,
    vulnScriptCatalog,
    vulnApp,
    options: {
      subnetScheme,
      attackBoxes,
      vxlanBlock: { start: VXLAN_SEARCH_MIN, end: VXLAN_SEARCH_MAX }  // placeholder, replaced by reservation
    }
  });
  if (rawSpec.vms.length === 0) {
    throw Object.assign(
      new Error('No deployable VMs after asset filter — every included asset failed template resolution'),
      { statusCode: 400, template_misses, service_gaps }
    );
  }

  // 6. Get-or-create the profile's persistent crucible_challenge in cybercore_db.
  //    The challenge's spec.vxlan_block IS the reservation. Idempotent — if
  //    this profile has been deployed before, we reuse the same challenge and
  //    its locked vxlan_block. New profiles get a freshly-carved slice.
  const reservation = await getOrCreateProfileChallenge({
    profileId,
    requestedMax: effectiveMaxStudents,
    companyName: profile.company_name,
    spec: rawSpec,
    subnetScheme
  });
  console.log(`[CIAB ProfileDeploy] Profile ${profileId.slice(0,8)} → challenge ${reservation.challenge_id.slice(0,8)} (${reservation.was_existing ? 'existing' : 'newly created'}), VXLAN ${reservation.vxlan_block.start}-${reservation.vxlan_block.end}, max_students=${reservation.max_students}`);

  // The spec we actually use is the challenge's stored spec (with the locked
  // vxlan_block), not the freshly-synthesized one.
  const spec = reservation.spec;

  if (numLanes > reservation.max_students) {
    throw Object.assign(
      new Error(`num_lanes (${numLanes}) exceeds this profile's max_students (${reservation.max_students}). ` +
                `The reservation was locked on first deploy. To grow it, delete the profile and re-create with a larger max_students.`),
      { statusCode: 400 }
    );
  }

  // 7. Allocate `numLanes` unused IDs from the reservation
  const vxlanIds = await allocateVxlanIds(reservation.vxlan_block, numLanes);
  if (vxlanIds.length < numLanes) {
    const usedCount = reservation.max_students - vxlanIds.length;
    throw Object.assign(
      new Error(`Only ${vxlanIds.length}/${numLanes} VXLAN IDs free in profile's reservation ` +
                `(${reservation.vxlan_block.start}-${reservation.vxlan_block.end}, ${usedCount}/${reservation.max_students} already in use). ` +
                `Tear down some lanes or pick a smaller num_lanes.`),
      { statusCode: 409 }
    );
  }

  // 8. Insert group row
  const finalGroupName = groupName || `${profile.company_name || 'profile'}-${new Date().toISOString().slice(0, 10)}`;
  const groupInsert = await query(
    `INSERT INTO ciab_profile_lane_groups
       (profile_id, group_name, created_by, num_lanes,
        asset_selection, service_gaps, template_misses, profile_snapshot, subnet_scheme,
        attack_boxes, vuln_app_id, ephemeral_challenge_id, status)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10, $11, $12, 'deploying')
     RETURNING id`,
    [
      profileId, finalGroupName, userId, numLanes,
      JSON.stringify(assetSelection),
      JSON.stringify(service_gaps),
      JSON.stringify(template_misses),
      JSON.stringify(assets),
      subnetScheme, attackBoxes,
      vulnApp ? vulnApp.id : null,
      reservation.challenge_id    // group points at the profile's challenge for backward compat
    ]
  );
  const groupId = groupInsert.rows[0].id;
  const challengeId = reservation.challenge_id;
  const challengeKey = reservation.challenge_key;

  // 9. Create cybercore_lane + ciab_profile_lane_jobs rows for each lane
  const laneAllocations = [];
  for (let i = 0; i < vxlanIds.length; i++) {
    const vxlanId = vxlanIds[i];
    const laneName = `ciab-${finalGroupName.toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 30)}-${i + 1}`;
    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane
         (user_id, vxlan_id, name, status, config, module_key, challenge_id, lane_group_id, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, 'crucible', $5, $6, NOW(), NOW())
       RETURNING lane_id`,
      [
        userId, vxlanId, laneName,
        JSON.stringify({
          challenge_id: challengeId,
          challenge_key: challengeKey,
          profile_lane_group: true,
          group_id: groupId
        }),
        challengeId,
        groupId
      ]
    );
    const laneId = laneInsert.rows[0].lane_id;

    const jobInsert = await query(
      `INSERT INTO ciab_profile_lane_jobs
         (group_id, lane_id, vxlan_id, lane_index, status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING id`,
      [groupId, laneId, vxlanId, i + 1]
    );
    laneAllocations.push({ laneId, jobId: jobInsert.rows[0].id, vxlanId });
  }

  // Extract the company's public domain from the profile JSON so the
  // orchestrator can inject it into Kali's /etc/hosts pointing at web-01.
  const profileDomain = profile.json_data?.student_view?.raw?.threats?.organization?.domain_public
    || profile.json_data?.student_view?.quick?.domain_public
    || null;

  // 10. Kick off background deploy (don't await)
  setImmediate(() => {
    deployProfileLanesBatch({
      groupId,
      groupName: finalGroupName,
      spec,
      laneAllocations,
      subnetScheme,
      module: 'ciab',
      attackBoxes,
      vulnAppInstall: spec.vuln_app_install,
      domain: profileDomain
    }).catch(err => {
      console.error(`[CIAB ProfileDeploy] Batch ${groupId} crashed:`, err);
      query(`UPDATE ciab_profile_lane_groups SET status='error', updated_at=NOW() WHERE id=$1`, [groupId])
        .catch(() => {});
    });
  });

  return {
    group_id: groupId,
    profile_id: profileId,
    num_lanes: numLanes,
    subnet_scheme: subnetScheme,
    lanes: laneAllocations,
    service_gaps,
    template_misses,
    vuln_app_id: vulnApp ? vulnApp.id : null
  };
}

// ─── Routes ─────────────────────────────────────────────────────────────────

// POST /api/profile-deploy/preview — pre-flight resource estimate
router.post('/preview', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { profile_id, num_lanes = 1, attack_boxes = true } = req.body;
    if (!profile_id) return res.status(400).json({ error: 'profile_id required' });

    const { assets } = await loadProfileForDeploy(profile_id);
    const serverCount = assets.filter(a => String(a.role || '').toLowerCase() === 'server').length;

    const preview = await buildDeployPreview({
      numLanes: parseInt(num_lanes) || 1,
      attackBoxes: !!attack_boxes,
      challengeVmCount: Math.max(serverCount, 1),
      proxmoxAPI,
      cybercoreQuery
    });
    res.json({
      ...preview,
      profile_asset_summary: {
        total: assets.length,
        servers: serverCount,
        will_deploy: serverCount
      }
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/deploy — the headline endpoint
router.post('/deploy', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      profile_id,
      num_lanes,
      group_name,
      attack_boxes,
      subnet_scheme,
      asset_selection,
      vuln_app
    } = req.body;

    const result = await runProfileDeploy({
      profileId: profile_id,
      userId: req.user.userId,
      numLanes: parseInt(num_lanes, 10),
      groupName: group_name,
      attackBoxes: attack_boxes !== false,
      subnetScheme: subnet_scheme || 'v2',
      assetSelection: asset_selection,
      vulnAppOpts: vuln_app || {}
    });
    res.status(202).json({ success: true, ...result });
  } catch (err) {
    const status = err.statusCode || 500;
    const body = { error: err.message };
    if (err.template_misses) body.template_misses = err.template_misses;
    if (err.service_gaps) body.service_gaps = err.service_gaps;
    res.status(status).json(body);
  }
});

// GET /api/profile-deploy/profiles/:profileId/reservation — show the VXLAN
// reservation status for a profile. Lets the UI display "12/25 slots used"
// and decide whether to enable the "Add lanes" button. Reservation lives
// entirely in cybercore_db; lookup by deterministic challenge_key.
router.get('/profiles/:profileId/reservation', authenticateToken, adminOnly, async (req, res) => {
  try {
    const pr = await query(`SELECT id, company_name FROM profiles WHERE id = $1`, [req.params.profileId]);
    if (pr.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
    const p = pr.rows[0];

    const ch = await findProfileChallenge(p.id);
    if (!ch) {
      return res.json({
        reserved: false,
        profile_id: p.id,
        company_name: p.company_name,
        search_window: { min: VXLAN_SEARCH_MIN, max: VXLAN_SEARCH_MAX }
      });
    }

    const usedRes = await cybercoreQuery(
      `SELECT COUNT(DISTINCT vxlan_id) AS used
         FROM cybercore_lane
        WHERE vxlan_id BETWEEN $1 AND $2
          AND status NOT IN ('error','deleted')`,
      [ch.vxlan_block.start, ch.vxlan_block.end]
    );
    const used = parseInt(usedRes.rows[0].used, 10) || 0;
    res.json({
      reserved: true,
      profile_id: p.id,
      company_name: p.company_name,
      challenge_id: ch.challenge_id,
      challenge_key: ch.challenge_key,
      max_students: ch.max_students,
      vxlan_range_start: ch.vxlan_block.start,
      vxlan_range_end: ch.vxlan_block.end,
      reserved_at: ch.created_at,
      slots_used: used,
      slots_free: ch.max_students - used,
      search_window: { min: VXLAN_SEARCH_MIN, max: VXLAN_SEARCH_MAX }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/groups/:groupId/add-lanes — deploy additional lanes
// to an existing group, pulling from the profile's VXLAN reservation.
router.post('/groups/:groupId/add-lanes', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { groupId } = req.params;
    const count = parseInt(req.body?.count, 10);
    if (!Number.isFinite(count) || count < 1 || count > 50) {
      return res.status(400).json({ error: 'count must be 1..50' });
    }

    // Load the group + its profile + the ephemeral challenge's spec (so we
    // can re-run the same deploy pipeline with the same VM specs).
    const grpRes = await query(`SELECT * FROM ciab_profile_lane_groups WHERE id=$1`, [groupId]);
    if (grpRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = grpRes.rows[0];
    if (group.status === 'deleted') return res.status(409).json({ error: 'Group is deleted' });

    // Look up the profile's persistent challenge (the reservation)
    const profRes = await query(`SELECT id, company_name FROM profiles WHERE id = $1`, [group.profile_id]);
    if (profRes.rows.length === 0) return res.status(409).json({ error: 'Source profile missing' });
    const prof = profRes.rows[0];

    const reservation = await findProfileChallenge(prof.id);
    if (!reservation) {
      return res.status(409).json({ error: 'Profile has no reservation — tear down everything and re-deploy' });
    }
    const spec = reservation.spec;
    const vxlanBlock = reservation.vxlan_block;

    // Allocate `count` unused IDs from the profile's reservation
    const vxlanIds = await allocateVxlanIds(vxlanBlock, count);
    if (vxlanIds.length < count) {
      return res.status(409).json({
        error: `Only ${vxlanIds.length}/${count} VXLAN IDs free in profile's reservation ` +
               `(${reservation.max_students} total, ${reservation.max_students - vxlanIds.length} already in use). ` +
               `Tear down some lanes first or request fewer.`
      });
    }

    // Create cybercore_lane + ciab_profile_lane_jobs rows for the new lanes.
    // Continue the lane_index sequence from the existing max.
    const idxRes = await query(`SELECT COALESCE(MAX(lane_index), 0) AS m FROM ciab_profile_lane_jobs WHERE group_id=$1`, [groupId]);
    const startIndex = parseInt(idxRes.rows[0].m, 10);

    const baseGroupName = group.group_name;
    const challengeKey = `ciab-profile-${group.profile_id.slice(0,8)}`;
    const laneAllocations = [];
    for (let i = 0; i < vxlanIds.length; i++) {
      const vxlanId = vxlanIds[i];
      const laneIndex = startIndex + i + 1;
      const laneName = `ciab-${baseGroupName.toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 30)}-${laneIndex}`;
      const laneInsert = await cybercoreQuery(
        `INSERT INTO cybercore_lane
           (user_id, vxlan_id, name, status, config, module_key, challenge_id, lane_group_id, created_at, updated_at)
         VALUES ($1, $2, $3, 'deploying', $4::jsonb, 'crucible', $5, $6, NOW(), NOW())
         RETURNING lane_id`,
        [
          req.user.userId, vxlanId, laneName,
          JSON.stringify({ challenge_id: reservation.challenge_id, challenge_key: challengeKey, profile_lane_group: true, group_id: groupId }),
          reservation.challenge_id, groupId
        ]
      );
      const laneId = laneInsert.rows[0].lane_id;
      const jobInsert = await query(
        `INSERT INTO ciab_profile_lane_jobs (group_id, lane_id, vxlan_id, lane_index, status)
         VALUES ($1, $2, $3, $4, 'pending') RETURNING id`,
        [groupId, laneId, vxlanId, laneIndex]
      );
      laneAllocations.push({ laneId, jobId: jobInsert.rows[0].id, vxlanId });
    }

    // Bump group num_lanes + flip status back to deploying
    await query(
      `UPDATE ciab_profile_lane_groups SET num_lanes = num_lanes + $2, status='deploying', updated_at=NOW() WHERE id=$1`,
      [groupId, vxlanIds.length]
    );

    res.status(202).json({
      success: true,
      group_id: groupId,
      added: laneAllocations.length,
      new_lanes: laneAllocations,
      total_lanes_now: parseInt(group.num_lanes, 10) + laneAllocations.length,
      reservation: { max_students: reservation.max_students, start: vxlanBlock.start, end: vxlanBlock.end }
    });

    // Pull domain from the group's frozen snapshot for the /etc/hosts injection
    const snapshotAssets = Array.isArray(group.profile_snapshot) ? group.profile_snapshot : [];
    const addLanesDomain = snapshotAssets.find(a => a.domain_public)?.domain_public || null;

    // Background: run the same deploy pipeline as the initial batch.
    setImmediate(() => {
      deployProfileLanesBatch({
        groupId,
        groupName: group.group_name,
        spec,
        laneAllocations,
        subnetScheme: group.subnet_scheme,
        module: 'crucible',
        attackBoxes: group.attack_boxes,
        vulnAppInstall: spec.vuln_app_install || null,
        domain: addLanesDomain
      }).catch(err => {
        console.error(`[CIAB AddLanes] group ${groupId} add-lanes batch crashed: ${err.message}`);
      });
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// GET /api/profile-deploy/groups — list groups created by the admin
router.get('/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT g.id, g.profile_id, g.group_name, g.num_lanes, g.status,
              g.subnet_scheme, g.attack_boxes, g.created_at, g.updated_at,
              jsonb_array_length(COALESCE(g.service_gaps,'[]'::jsonb))   AS gap_count,
              jsonb_array_length(COALESCE(g.template_misses,'[]'::jsonb)) AS miss_count,
              p.company_name AS profile_company
         FROM ciab_profile_lane_groups g
         LEFT JOIN profiles p ON p.id = g.profile_id
        WHERE g.status != 'deleted'
        ORDER BY g.created_at DESC
        LIMIT 100`
    );
    res.json({ groups: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/profile-deploy/groups/:groupId — full group detail
router.get('/groups/:groupId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const groupRes = await query(
      `SELECT * FROM ciab_profile_lane_groups WHERE id = $1`,
      [req.params.groupId]
    );
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const jobsRes = await query(
      `SELECT id, lane_id, vxlan_id, lane_index, status, phase_detail, error_msg,
              vm_ids, target_node, started_at, finished_at
         FROM ciab_profile_lane_jobs
        WHERE group_id = $1
        ORDER BY lane_index`,
      [req.params.groupId]
    );
    res.json({ group: groupRes.rows[0], jobs: jobsRes.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/profile-deploy/groups/:groupId/progress — UI polling endpoint
router.get('/groups/:groupId/progress', authenticateToken, adminOnly, async (req, res) => {
  const live = getProgress(req.params.groupId);
  if (live) return res.json(live);

  // No in-process progress (server restart or already-finalized) — fall back to DB
  try {
    const groupRes = await query(
      `SELECT id, group_name, num_lanes, status FROM ciab_profile_lane_groups WHERE id = $1`,
      [req.params.groupId]
    );
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const jobs = await query(
      `SELECT status FROM ciab_profile_lane_jobs WHERE group_id = $1`,
      [req.params.groupId]
    );
    const counts = jobs.rows.reduce((acc, j) => { acc[j.status] = (acc[j.status] || 0) + 1; return acc; }, {});
    res.json({
      group_id: req.params.groupId,
      group_name: groupRes.rows[0].group_name,
      total: groupRes.rows[0].num_lanes,
      succeeded: counts.active || 0,
      failed: counts.error || 0,
      completed: (counts.active || 0) + (counts.error || 0),
      phase: groupRes.rows[0].status === 'deploying' ? 'in_progress' : 'complete',
      from_db: true
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/groups/:groupId/retry/:laneId — re-deploy a failed lane
router.post('/groups/:groupId/retry/:laneId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { groupId, laneId } = req.params;
    const groupRes = await query(`SELECT * FROM ciab_profile_lane_groups WHERE id=$1`, [groupId]);
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = groupRes.rows[0];

    const jobRes = await query(
      `SELECT * FROM ciab_profile_lane_jobs WHERE group_id=$1 AND lane_id=$2`,
      [groupId, laneId]
    );
    if (jobRes.rows.length === 0) return res.status(404).json({ error: 'Lane job not found' });
    const job = jobRes.rows[0];

    // Re-fetch ephemeral challenge spec
    const challengeRes = await cybercoreQuery(
      `SELECT spec FROM crucible_challenge WHERE challenge_id=$1`,
      [group.ephemeral_challenge_id]
    );
    if (challengeRes.rows.length === 0) {
      return res.status(409).json({ error: 'Ephemeral challenge missing — cannot retry' });
    }
    const spec = typeof challengeRes.rows[0].spec === 'string'
      ? JSON.parse(challengeRes.rows[0].spec)
      : challengeRes.rows[0].spec;

    // Destroy any partial VMs from the failed attempt
    if (Array.isArray(job.vm_ids) && job.vm_ids.length > 0) {
      for (const vmid of job.vm_ids) {
        const type = (vmid >= 100000 && vmid < 200000) ? 'lxc' : 'qemu';
        await forceDestroyVM(vmid, type, job.target_node).catch(() => {});
      }
    }

    // Resolve VNets again (in case the SDN provisioning changed)
    const { vnet, vnetInt } = await resolveVnets(job.vxlan_id, group.subnet_scheme);
    const gatewayVmId = 100000 + job.vxlan_id;

    // Reset job + lane status, then run a single-lane deploy
    await query(`UPDATE ciab_profile_lane_jobs SET status='pending', error_msg=NULL, started_at=NULL, finished_at=NULL WHERE id=$1`, [job.id]);
    await cybercoreQuery(`UPDATE cybercore_lane SET status='deploying', updated_at=NOW() WHERE lane_id=$1`, [laneId]);

    res.status(202).json({ success: true, message: 'Retry started', lane_id: laneId, job_id: job.id });

    // Re-extract the company domain from the group's frozen profile snapshot
    // so the retried lane gets the same Kali /etc/hosts injection.
    const snapshotAssets = Array.isArray(group.profile_snapshot) ? group.profile_snapshot : [];
    const retryDomain = snapshotAssets.find(a => a.domain_public)?.domain_public
      || group.profile_snapshot?.domain_public
      || null;

    // Background: re-run that single lane
    const { createCloneSemaphore } = require('../../../../../src/utils/batch-deployer');
    setImmediate(() => {
      deployOneLaneFromSpec({
        laneId,
        jobId: job.id,
        spec,
        vxlanId: job.vxlan_id,
        vnet, vnetInt,
        gatewayVmId,
        targetNode: job.target_node || 'cyberhub-node-5',
        templateNode: spec.template_node || 'cyberhub-node-5',
        groupId,
        groupName: group.group_name,
        vulnAppInstall: spec.vuln_app_install || null,
        attackBoxes: group.attack_boxes,
        subnetScheme: group.subnet_scheme,
        module: 'ciab',
        domain: retryDomain,
        cloneSem: createCloneSemaphore(),
        progress: null
      }).catch(err => {
        console.error(`[CIAB ProfileDeploy] Retry of lane ${laneId} failed: ${err.message}`);
      });
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// DELETE /api/profile-deploy/groups/:groupId — tear down all lanes in the group
router.delete('/groups/:groupId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const groupRes = await query(
      `SELECT id, group_name, ephemeral_challenge_id FROM ciab_profile_lane_groups WHERE id=$1`,
      [req.params.groupId]
    );
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = groupRes.rows[0];

    const jobsRes = await query(
      `SELECT lane_id, vm_ids FROM ciab_profile_lane_jobs WHERE group_id=$1`,
      [req.params.groupId]
    );

    const errors = [];
    for (const job of jobsRes.rows) {
      const result = await teardownLane({ laneId: job.lane_id, vmIds: job.vm_ids || [] });
      if (result.errors && result.errors.length > 0) errors.push(...result.errors);
    }

    // NOTE: we DO NOT delete the crucible_challenge here. Challenges are now
    // per-PROFILE (managed by getOrCreateProfileChallenge / deleteProfileChallenge),
    // so other groups from the same profile may still reference it. The
    // challenge is only deleted when the profile itself is deleted — that
    // path lives in profiles.js's DELETE /api/profiles/:id handler, which
    // calls deleteProfileChallenge() from utils/lane-deploy.js.

    await query(`UPDATE ciab_profile_lane_groups SET status='deleted', updated_at=NOW() WHERE id=$1`,
                [req.params.groupId]);

    res.json({ success: true, group_id: req.params.groupId, errors: errors.length ? errors : undefined });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.runProfileDeploy = runProfileDeploy;
module.exports.loadProfileForDeploy = loadProfileForDeploy;
module.exports.defaultAssetSelection = defaultAssetSelection;
