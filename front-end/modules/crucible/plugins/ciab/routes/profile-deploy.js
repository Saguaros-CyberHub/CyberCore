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
const { resolveImageFile } = require('../utils/vuln-app-builder');
const { estimateDeployCost, DEFAULT_MODEL } = require('../utils/cost-estimator');
const { generatePassword } = require('../../../../../src/utils/password-generator');
const { guacAPI } = require('../../../../../src/utils/guacamole');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const {
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

  // 3. Fetch catalogs. vm catalog lives in cybercore_db; vuln scripts in clinic_db.
  const [vmCatalogRes, vulnCatalogRes] = await Promise.all([
    cybercoreQuery(`SELECT id, os_family, os_version, os_name, template_vmid, node, role_hints, is_active, preferred, created_at
                    FROM cybercore_template_catalog WHERE is_active = true AND template_type = 'os_template'`),
    query(`SELECT id, slug, name, os_target, category, script_type, services_exposed, is_active FROM vuln_scripts WHERE is_active = true`)
  ]);
  const vmTemplateCatalog = vmCatalogRes.rows;
  const vulnScriptCatalog = vulnCatalogRes.rows;

  // 4 + 6 in parallel. Vuln-app LLM generation can take ~4min on a fresh
  // profile, and SDN provisioning for a 25-slot reservation takes ~45s.
  // They're independent — kick both off, await both before continuing.
  //   - vulnApp generation needs: profile + assets
  //   - reservation+SDN needs: profileId + max + company name + subnetScheme
  //                            (spec is stored but not used for VNet creation;
  //                            we update it after synthesis via the "adopt
  //                            fresh spec" branch below)
  console.log(`[CIAB ProfileDeploy] Profile ${profileId.slice(0,8)}: starting vuln-app generation + reservation in parallel`);
  const vulnAppPromise = vulnAppOpts.enabled === false
    ? Promise.resolve(null)
    : getOrGenerateVulnApp({
        profile: { ...profile, assets },
        llmModel: vulnAppOpts.llm_model,
        preferMode: vulnAppOpts.delivery_mode || 'docker',
        // Per-deploy difficulty (easy|medium|hard) from the admin UI radio.
        // Drives the LLM prompt's vuln-pool selection. Defaults to easy so
        // existing callers (without the field) get the beginner-friendly
        // chain that the rest of the prompt now assumes.
        difficulty: vulnAppOpts.difficulty || 'easy'
      }).catch(err => {
        console.warn(`[CIAB ProfileDeploy] vuln app generation failed (continuing): ${err.message}`);
        return null;
      });

  const reservationPromise = getOrCreateProfileChallenge({
    profileId,
    requestedMax: effectiveMaxStudents,
    companyName: profile.company_name,
    spec: {},                            // synthesized spec filled in below
    subnetScheme
  });

  const [vulnApp, reservation] = await Promise.all([vulnAppPromise, reservationPromise]);

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
  console.log(`[CIAB ProfileDeploy] Profile ${profileId.slice(0,8)} → challenge ${reservation.challenge_id.slice(0,8)} (${reservation.was_existing ? 'existing' : 'newly created'}), VXLAN ${reservation.vxlan_block.start}-${reservation.vxlan_block.end}, max_students=${reservation.max_students}`);

  // Spec selection:
  //   - New reservation → stored spec is the rawSpec we just wrote, same thing.
  //   - New reservation (was_existing=false) → reservation was created with
  //     an empty stub spec (so SDN provision could run in parallel with the
  //     vuln-app LLM). Now that synthesis is done, persist the real spec.
  //   - Existing reservation with 0 live lanes → admin may have changed the
  //     asset selection since the prior (failed) attempt. Adopt the fresh spec
  //     and update the stored one so retry/add-lanes stay consistent.
  //   - Existing reservation with live lanes → must keep stored spec; changing
  //     VM offsets/templates now would collide with running lanes.
  let spec = reservation.spec;
  let shouldAdoptFreshSpec = !reservation.was_existing;   // always for new reservations
  const storedHasVms = Array.isArray(spec && spec.vms) && spec.vms.length > 0;

  if (reservation.was_existing) {
    const liveLanesRes = await cybercoreQuery(
      `SELECT COUNT(*)::int AS n FROM cybercore_lane
        WHERE vxlan_id BETWEEN $1 AND $2 AND status NOT IN ('error','deleted')`,
      [reservation.vxlan_block.start, reservation.vxlan_block.end]
    );
    const liveCount = liveLanesRes.rows[0]?.n || 0;

    if (!storedHasVms) {
      // Stored spec is empty/missing (e.g. created from the empty-stub during
      // the parallelized first deploy, or the previous deploy crashed before
      // synthesis). MUST adopt fresh regardless of live-lane count — keeping
      // an empty spec would just re-produce a broken deploy.
      shouldAdoptFreshSpec = true;
      console.log(`[CIAB ProfileDeploy] Stored spec is empty (${liveCount} live lane(s) ignored) — adopting fresh spec (${rawSpec.vms.length} VMs)`);
    } else if (liveCount === 0) {
      shouldAdoptFreshSpec = true;
      console.log(`[CIAB ProfileDeploy] Reservation has no live lanes — adopting fresh spec (${rawSpec.vms.length} VMs) from current asset selection`);
    } else {
      console.log(`[CIAB ProfileDeploy] Reservation has ${liveCount} live lane(s) — keeping stored spec (${spec.vms.length} VMs) to avoid collision`);
    }
  } else {
    console.log(`[CIAB ProfileDeploy] New reservation — persisting fresh spec (${rawSpec.vms.length} VMs)`);
  }

  if (shouldAdoptFreshSpec) {
    spec = { ...rawSpec, vxlan_block: reservation.vxlan_block };
    await cybercoreQuery(
      `UPDATE crucible_challenge SET spec = $1::jsonb WHERE challenge_id = $2`,
      [JSON.stringify(spec), reservation.challenge_id]
    );
  }

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

  // 8b. Auto-create student accounts (one per lane) + Guac users so each lane
  // appears in its owner's "My Workspaces" page. Mirrors the pattern from
  // /api/admin/deploy-group (src/routes/admin/groups.js:180-203). Pre-existing
  // students with the same username get their password rotated via ON CONFLICT,
  // so repeat deploys with the same group_name are safe — students keep their
  // identity, instructors get fresh credentials to hand out.
  const groupSlug = finalGroupName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const credentials = [];
  const students = [];
  for (let i = 1; i <= numLanes; i++) {
    const studentId = uuidv4();
    const email = `${groupSlug}-student${i}@clinic.local`;
    const password = generatePassword();
    const passwordHash = await bcrypt.hash(password, 12);

    // Upsert the user — re-deploys of the same group rotate the password but
    // keep the same user_id so prior workspaces/permissions stay associated.
    const userRow = await cybercoreQuery(
      `INSERT INTO cybercore_user
         (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
       VALUES ($1, $2, $3, $4, 'bcrypt', $5, $6, $7, 'student', true, NOW())
       ON CONFLICT (username) DO UPDATE SET
         password_hash = EXCLUDED.password_hash,
         password_alg  = 'bcrypt',
         organization  = EXCLUDED.organization
       RETURNING user_id`,
      [studentId, email, email, passwordHash, 'Student', String(i), finalGroupName]
    );
    const effectiveId = userRow.rows[0].user_id;
    students.push({ id: effectiveId, email, name: `Student ${i}`, index: i });
    credentials.push({ email, password, role: 'student' });

    // Best-effort Guac account — if Guac is down the deploy still completes
    // and the admin can create it manually later.
    try {
      await guacAPI('POST', '/users', {
        username: email,
        password,
        attributes: { disabled: null, timezone: 'America/Phoenix' }
      });
    } catch (_) {
      // Guac may already have this user from a previous deploy; PUT to refresh password.
      try {
        await guacAPI('PUT', `/users/${encodeURIComponent(email)}`, {
          username: email,
          password,
          attributes: { disabled: null, timezone: 'America/Phoenix' }
        });
      } catch (_) {}
    }
  }
  console.log(`[CIAB ProfileDeploy] Group ${finalGroupName}: provisioned ${students.length} student account(s) (1 per lane)`);

  // 9. Create cybercore_lane + ciab_profile_lane_jobs rows for each lane
  const laneAllocations = [];
  for (let i = 0; i < vxlanIds.length; i++) {
    const vxlanId = vxlanIds[i];
    const student = students[i];
    // Naming: matches the existing AZCYBR lane convention so My Workspaces
    // shows readable titles like `kali-cochise-student1-710265`. The trailing
    // VMID is the Kali VM ID (attack box offset + vxlan), making each lane
    // uniquely identifiable at a glance.
    const ATTACK_BOX_VMID_OFFSET = 700000;
    const kaliVmid = ATTACK_BOX_VMID_OFFSET + vxlanId;
    const laneName = `kali-${groupSlug}-student${student.index}-${kaliVmid}`;
    // cybercore_lane.user_id MUST be the student's ID so the lane appears in
    // that student's My Workspaces (the page filters by user_id). Previously
    // we set this to the admin's userId, which is why Cochise lanes never
    // appeared in any student's workspaces.
    const laneInsert = await cybercoreQuery(
      `INSERT INTO cybercore_lane
         (user_id, vxlan_id, name, status, config, module_key, challenge_id, created_at, updated_at)
       VALUES ($1, $2, $3, 'deploying', $4::jsonb, 'crucible', $5, NOW(), NOW())
       RETURNING lane_id`,
      [
        student.id, vxlanId, laneName,
        JSON.stringify({
          challenge_id: challengeId,
          challenge_key: challengeKey,
          profile_lane_group: true,
          group_id: groupId,
          student_email: student.email,
          student_index: student.index
        }),
        challengeId
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
      domain: profileDomain,
      challengeKey
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
    vuln_app_id: vulnApp ? vulnApp.id : null,
    // One-time display in the admin deploy UI — the instructor hands these to
    // students. Passwords are NOT stored in plaintext anywhere (hashes go to
    // cybercore_user); this is the only point in the lifetime the cleartext
    // password is visible. The admin UI surfaces a "save these now" warning.
    credentials,
    students: students.map(s => ({ email: s.email, name: s.name, index: s.index }))
  };
}

// ─── Routes ─────────────────────────────────────────────────────────────────

// Lab-internal source check for the unauthenticated image pull. The token is
// the real gate (24 random bytes); this is defense-in-depth so the endpoint
// can't be probed from the public internet. Lane egress SNATs to the gateway
// WAN IP (100.64.0.0/10 CGNAT) — same source lane-bootstrap trusts.
function isLabSourceIp(ip) {
  if (!ip) return false;
  if (/^127\./.test(ip) || ip === '::1') return true;            // loopback (local test)
  if (/^10\./.test(ip)) return true;                              // RFC1918
  if (/^192\.168\./.test(ip)) return true;                        // RFC1918
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;         // RFC1918 + docker bridge
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // 100.64/10 CGNAT (lab/Tailscale)
  return false;
}

// GET /api/profile-deploy/image/:token — UNAUTHENTICATED, token-gated.
// Lane web VMs pull their prebuilt vuln-app image tarball here (they have no
// JWT). Streamed gzip'd `docker save` output. See utils/vuln-app-builder.js.
router.get('/image/:token', (req, res) => {
  const ip = String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (!isLabSourceIp(ip)) {
    console.warn(`[CIAB ProfileDeploy] image pull rejected from non-lab source ${ip}`);
    return res.status(403).end();
  }
  const entry = resolveImageFile(req.params.token);
  if (!entry) return res.status(404).end();

  res.setHeader('Content-Type', 'application/gzip');
  const safeName = entry.imageTag.replace(/[^a-z0-9._-]/gi, '_');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}.tar.gz"`);
  const stream = fs.createReadStream(entry.filePath);
  stream.on('error', err => {
    console.error(`[CIAB ProfileDeploy] image stream error for ${req.params.token.slice(0, 8)}…: ${err.message}`);
    if (!res.headersSent) res.status(500).end(); else res.destroy();
  });
  stream.pipe(res);
});

// POST /api/profile-deploy/preview — pre-flight resource estimate
router.post('/preview', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      profile_id, num_lanes = 1, attack_boxes = true,
      vuln_app_enabled = true,
      model_id = DEFAULT_MODEL
    } = req.body;
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

    // Has this profile's vuln-app already been generated? If so, the deploy
    // won't re-run the LLM pipeline — cost is just infra.
    let vulnAppCached = false;
    try {
      const cached = await query(
        `SELECT 1 FROM ciab_profile_vuln_apps WHERE profile_id = $1 LIMIT 1`,
        [profile_id]
      );
      vulnAppCached = cached.rowCount > 0;
    } catch (_) { /* table missing in test envs — assume not cached */ }

    const cost = estimateDeployCost({
      modelId: model_id,
      vulnAppEnabled: !!vuln_app_enabled,
      vulnAppAlreadyCached: vulnAppCached,
      numLanes: parseInt(num_lanes) || 1,
      vmsPerLane: Math.max(serverCount, 1),
      attackBoxes: !!attack_boxes
    });

    res.json({
      ...preview,
      profile_asset_summary: {
        total: assets.length,
        servers: serverCount,
        will_deploy: serverCount
      },
      cost_estimate: cost
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
      max_students,
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
      maxStudents: max_students != null ? parseInt(max_students, 10) : undefined,
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
      // See note in runProfileDeploy — lane_group_id FKs to crucible_lane_group,
      // which CIAB does not populate. Group linkage lives in config.group_id.
      const laneInsert = await cybercoreQuery(
        `INSERT INTO cybercore_lane
           (user_id, vxlan_id, name, status, config, module_key, challenge_id, created_at, updated_at)
         VALUES ($1, $2, $3, 'deploying', $4::jsonb, 'crucible', $5, NOW(), NOW())
         RETURNING lane_id`,
        [
          req.user.userId, vxlanId, laneName,
          JSON.stringify({ challenge_id: reservation.challenge_id, challenge_key: challengeKey, profile_lane_group: true, group_id: groupId }),
          reservation.challenge_id
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
        domain: addLanesDomain,
        challengeKey: reservation.challenge_key
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

    // Re-fetch ephemeral challenge spec + key (key needed for SDN zone naming)
    const challengeRes = await cybercoreQuery(
      `SELECT spec, challenge_key FROM crucible_challenge WHERE challenge_id=$1`,
      [group.ephemeral_challenge_id]
    );
    if (challengeRes.rows.length === 0) {
      return res.status(409).json({ error: 'Ephemeral challenge missing — cannot retry' });
    }
    const spec = typeof challengeRes.rows[0].spec === 'string'
      ? JSON.parse(challengeRes.rows[0].spec)
      : challengeRes.rows[0].spec;
    const challengeKey = challengeRes.rows[0].challenge_key;

    // Destroy any partial VMs from the failed attempt
    if (Array.isArray(job.vm_ids) && job.vm_ids.length > 0) {
      for (const vmid of job.vm_ids) {
        const type = (vmid >= 100000 && vmid < 200000) ? 'lxc' : 'qemu';
        await forceDestroyVM(vmid, type, job.target_node).catch(() => {});
      }
    }

    // Make sure SDN zone+VNets exist (idempotent) — covers the case where the
    // initial batch never got past provisioning. Then look up the VNet objects.
    await ensureSdnZoneAndVnets({
      vxlanIds: [job.vxlan_id],
      subnetScheme: group.subnet_scheme,
      challengeKey,
      logTag: `CIAB Retry ${group.group_name}`
    });
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
