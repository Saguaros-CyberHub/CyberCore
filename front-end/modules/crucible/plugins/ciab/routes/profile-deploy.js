/*
 * ============================================================================
 * Profile-Deploy Routes — admin deploys N cybercore lanes from one CIAB profile
 * ============================================================================
 * All endpoints are admin-only. Three intake paths into /deploy:
 *   (a) profile_id from CIAB profiles table (most common)
 *   (b) profile_id from a previously uploaded JSON  → /api/profiles/upload
 *   (c) one-step generate + deploy                  → /api/profiles/generate-and-deploy
 *
 * Lane deployment goes through ../utils/lane-provision.js, a thin wrapper over
 * the shared spec deployer (src/utils/challenge-lane-deployer.js). This file
 * owns intake, validation and bookkeeping only — it clones nothing. The VXLAN
 * reservation lives in ../utils/lane-reservation.js.
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
const { claimsSql } = require('../../../../../src/utils/lane-claims');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');
const audit = require('../../../../../src/utils/audit');

const { synthesizeSpecFromProfile } = require('../utils/profile-to-spec');
const { getOrGenerateVulnApp } = require('../utils/vuln-app-generator');
const { resolveImageFile } = require('../utils/vuln-app-builder');
const { estimateDeployCost, DEFAULT_MODEL } = require('../utils/cost-estimator');
// Student accounts for profile lanes. Extracted in Track A3 — the identical
// loop existed at both call sites below and had already begun to drift. It
// still mints through src/utils/account-provisioning, so the create-or-rotate
// semantics this path depends on are unchanged; see profile-students.js.
const { provisionLaneStudents, slugForGroup } = require('../utils/profile-students');
const laneProvision = require('../utils/lane-provision');
const engagementProvision = require('../utils/engagement-provision');

const { guacAPI } = require('../../../../../src/utils/guacamole');
const {
  teardownLane,
  getOrCreateProfileChallenge,
  deleteProfileChallenge,
  findProfileChallenge,
  getProfileChallengeById,
  listProfileChallenges,
  DEFAULT_ENGAGEMENT_TYPE,
  sanitizeEngagementType,
  VXLAN_SEARCH_MIN,
  VXLAN_SEARCH_MAX
} = require('../utils/lane-reservation');

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
//  by getOrCreateProfileChallenge() in utils/lane-reservation.js)

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

/**
 * Merge a freshly synthesized spec onto a reservation, for the UPDATE that
 * replaces crucible_challenge.spec wholesale.
 *
 * vxlan_block and zone are RESERVATION-owned, not synthesizer-owned:
 * reserveLabNetwork writes both, and teardownLabNetwork reads spec.zone.abbrev to
 * decide which Proxmox SDN zone to remove. profile-to-spec emits neither, so
 * spreading rawSpec alone blanks the abbrev out on the first deploy of every
 * reservation — after which teardownSdnForBlock's `if (zone)` guard skips zone
 * deletion in silence and the zone can never be found again.
 *
 * src/routes/lab-templates.js:355-363 defends the same invariant on the admin
 * edit path, by name: PROTECTED_SPEC_KEYS = ['vxlan_block','zone','cle','course_id'].
 * This is that rule, on the deploy path.
 *
 * Pure and exported so ciab-reservation.test.js can assert the behaviour rather
 * than grep the source for the word "zone" — the comment above would satisfy
 * a source-text check while the code did the wrong thing.
 */
function adoptedSpec(rawSpec, reservation) {
  const zone = (reservation && reservation.spec && reservation.spec.zone)
    || (reservation && reservation.zone_abbrev ? { abbrev: reservation.zone_abbrev } : null);
  return {
    ...rawSpec,
    vxlan_block: reservation ? reservation.vxlan_block : undefined,
    ...(zone ? { zone } : {})
  };
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
 * @param {string} [opts.engagementType]   which engagement against this client
 *   these lanes are for. Reservations are keyed on (profile, engagement), so an
 *   external and an internal engagement against one company get separate VXLAN
 *   blocks instead of aliasing onto each other. Track B turns this into a row in
 *   ciab_engagement; until then it is a free slug defaulting to 'default'.
 * @returns {Promise<{group_id, profile_id, lanes:[...], service_gaps, template_misses}>}
 */
async function runProfileDeploy(opts) {
  const {
    profileId, userId, numLanes,
    maxStudents,                                           // ← NEW: total reservation size; defaults to numLanes
    groupName, attackBoxes = true, subnetScheme = 'v2',
    assetSelection: providedSelection, vulnAppOpts = {},
    engagementType
  } = opts;
  const engagement = sanitizeEngagementType(engagementType);

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

  // A8a: the reservation is NOT carved here any more.
  //
  // Carving it means 25-50 serial VNet POSTs, a CLUSTER-WIDE `PUT /cluster/sdn`
  // apply (which commits every pending SDN change on the cluster, not just
  // ours), up to three reconcile passes each with another apply, and then a wait
  // for the bridges to materialize on every node. Doing that here put all of it
  // in front of the lanes an instructor is waiting on — partly hidden behind the
  // vuln-app LLM call on a first deploy, and fully exposed on any deploy where
  // the app is a cache hit.
  //
  // It now happens when the ENGAGEMENT is created, usually days earlier. There
  // is deliberately NO inline fallback: reserving "just this once" here is
  // exactly how the cost became invisible in the first place.
  const engagementRow = await engagementProvision.resolveEngagement(profileId, engagement);
  engagementProvision.assertEngagementDeployable(engagementRow, {
    profileId, engagementType: engagement,
  });

  // Idempotent read of the block the engagement already reserved. requestedMax
  // is the engagement's own size, not the caller's — max_students locks with the
  // reservation, and passing a different number here would ask the resize path
  // to re-carve a block that lanes may already be sitting in.
  const reservationPromise = getOrCreateProfileChallenge({
    profileId,
    engagementType: engagement,
    requestedMax: engagementRow.max_students,
    companyName: profile.company_name,
    spec: {},                            // synthesized spec filled in below
    subnetScheme: engagementRow.subnet_scheme || subnetScheme
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
        WHERE vxlan_id BETWEEN $1 AND $2 AND ${claimsSql()}`,
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
    spec = adoptedSpec(rawSpec, reservation);
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

  // NOTE: there is deliberately no VXLAN allocation here. deployChallengeLanes
  // allocates from the challenge's own vxlan_block and releases what it does not
  // use. Allocating here as well would hand the same ids out twice — the
  // in-process reservation set is per-caller, so the deployer's allocator cannot
  // see ours, and the second INSERT dies on ux_cybercore_lane_vxlan_active.

  // 8. Insert group row
  const finalGroupName = groupName || `${profile.company_name || 'profile'}-${new Date().toISOString().slice(0, 10)}`;
  const groupInsert = await query(
    `INSERT INTO ciab_profile_lane_groups
       (profile_id, group_name, created_by, num_lanes,
        asset_selection, service_gaps, template_misses, profile_snapshot, subnet_scheme,
        attack_boxes, vuln_app_id, ephemeral_challenge_id, engagement_type, status)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13, 'deploying')
     RETURNING id`,
    [
      profileId, finalGroupName, userId, numLanes,
      JSON.stringify(assetSelection),
      JSON.stringify(service_gaps),
      JSON.stringify(template_misses),
      JSON.stringify(assets),
      subnetScheme, attackBoxes,
      vulnApp ? vulnApp.id : null,
      // The group's pointer at its reservation. Add-lanes and retry resolve the
      // reservation through THIS id rather than re-deriving a key — one profile
      // can now own several, so re-deriving would be a guess.
      reservation.challenge_id,
      engagement
    ]
  );
  const groupId = groupInsert.rows[0].id;
  const challengeId = reservation.challenge_id;
  const challengeKey = reservation.challenge_key;

  // 8b. Auto-create student accounts (one per lane) + Guac users so each lane
  // appears in its owner's "My Workspaces" page: that page filters on
  // cybercore_lane.user_id, so a lane owned by the deploying admin shows up in
  // nobody's workspace list.
  //
  // Shared with the add-lanes route below — see utils/profile-students.js for
  // why this is create-or-rotate rather than an insert, and why the slug has to
  // have exactly one owner.
  const { groupSlug, students, credentials } = await provisionLaneStudents({
    groupName: finalGroupName,
    groupId,
    indices: Array.from({ length: numLanes }, (_, i) => i + 1),
    // `userId` is the acting admin, passed in by the route — runProfileDeploy
    // has no req of its own.
    actingUserId: userId,
  });

  // ── Hand over to the shared deployer ─────────────────────────────────────
  // VXLAN allocation, gateway WAN addresses, cybercore_lane rows, the clone
  // sequence, Guacamole, DHCP reservations — deployChallengeLanes does all of
  // it. CIAB doing any of it a second time is what W1-W7 were, so this function
  // stops as soon as the students exist.
  {
    const spawnedAt = new Date().toISOString();
    setImmediate(() => {
      laneProvision.provisionProfileLanes({
        groupId,
        groupName: finalGroupName,
        groupSlug,
        challenge: {
          challenge_id: reservation.challenge_id,
          challenge_key: reservation.challenge_key,
          name: finalGroupName,
          spec,
          subnet_scheme: subnetScheme,
        },
        students,
        attackBoxes,
        vulnAppInstall: spec.vuln_app_install,
      }).catch(err => {
        console.error(`[CIAB ProfileDeploy] V2 batch ${groupId} crashed:`, err);
        query(`UPDATE ciab_profile_lane_groups SET status='error', updated_at=NOW() WHERE id=$1`, [groupId])
          .catch(() => {});
      });
    });

    return {
      group_id: groupId,
      profile_id: profileId,
      num_lanes: numLanes,
      subnet_scheme: subnetScheme,
      deploy_path: 'v2',
      // Deliberately empty: under V2 the lane rows do not exist yet — the shared
      // deployer creates them as it goes. The admin UI follows the deploy through
      // GET /groups/:groupId/progress, which reads the shared registry, and the
      // per-lane rows appear in ciab_profile_lane_jobs as each lane lands.
      lanes: [],
      progress_id: laneProvision.progressIdForGroup(groupId),
      started_at: spawnedAt,
      service_gaps,
      template_misses,
      vuln_app_id: vulnApp ? vulnApp.id : null,
      credentials,
      students: students.map(s => ({ email: s.email, name: s.name, index: s.index })),
    };
  }

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
      vuln_app,
      engagement_type
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
      vulnAppOpts: vuln_app || {},
      engagementType: engagement_type
    });
    audit.log({
      req,
      action: 'profile_lane.deployed',
      source: 'ciab',
      target: { type: 'group', id: result.group_id, label: group_name },
      metadata: {
        profile_id, num_lanes: parseInt(num_lanes, 10),
        max_students: max_students != null ? parseInt(max_students, 10) : null,
        attack_boxes: attack_boxes !== false,
        subnet_scheme: subnet_scheme || 'v2',
      },
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

    // One profile can hold a reservation per engagement. Absent a query param
    // this reports the default engagement's, which is also the one a
    // pre-engagement reservation is adopted into.
    const engagement = sanitizeEngagementType(req.query.engagement_type);
    const ch = await findProfileChallenge(p.id, engagement);
    // Split on the exact prefix, not on '-': an engagement slug may itself
    // contain hyphens (sanitizeEngagementType permits them), so indexing into
    // challenge_key.split('-') would truncate 'external-blackbox' to 'external'.
    const keyPrefix = `ciab-profile-${String(p.id).slice(0, 8)}-`;
    const allReservations = (await listProfileChallenges(p.id)).map(row => ({
      challenge_id: row.challenge_id,
      challenge_key: row.challenge_key,
      // null marks a not-yet-adopted pre-engagement row; it belongs to the
      // default engagement and is renamed on its next deploy.
      engagement_type: row.challenge_key.startsWith(keyPrefix)
        ? row.challenge_key.slice(keyPrefix.length)
        : null,
    }));
    if (!ch) {
      return res.json({
        reserved: false,
        profile_id: p.id,
        company_name: p.company_name,
        engagement_type: engagement,
        engagements: allReservations,
        search_window: { min: VXLAN_SEARCH_MIN, max: VXLAN_SEARCH_MAX }
      });
    }

    const usedRes = await cybercoreQuery(
      `SELECT COUNT(DISTINCT vxlan_id) AS used
         FROM cybercore_lane
        WHERE vxlan_id BETWEEN $1 AND $2
          AND ${claimsSql()}`,
      [ch.vxlan_block.start, ch.vxlan_block.end]
    );
    const used = parseInt(usedRes.rows[0].used, 10) || 0;
    res.json({
      reserved: true,
      profile_id: p.id,
      company_name: p.company_name,
      challenge_id: ch.challenge_id,
      challenge_key: ch.challenge_key,
      engagement_type: engagement,
      // Every reservation this profile holds, not just the one asked about. A
      // profile can now own one per engagement, and nothing else on the CIAB
      // surface can see them — without this an engagement other than the default
      // is invisible, and its VXLAN block and pre-created VNets look like a leak.
      // Releasing one individually is still only possible by deleting the profile;
      // a per-engagement teardown belongs with the Environments tab.
      engagements: allReservations,
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

// ─── A8: engagements — reserve the VXLAN block ahead of deploy day ──────────
// Carving a block is 25-50 serial VNet POSTs plus a CLUSTER-WIDE SDN apply plus
// a per-node bridge wait. These endpoints move that off the deploy path.

// GET /api/profile-deploy/profiles/:profileId/engagements — status per engagement
router.get('/profiles/:profileId/engagements', authenticateToken, adminOnly, async (req, res) => {
  try {
    const rows = await engagementProvision.listEngagements(req.params.profileId);
    // Nothing recorded yet may still mean a pre-A8 reservation exists — adopt it
    // so the UI shows the truth rather than offering to reserve a second block.
    if (rows.length === 0) {
      const adopted = await engagementProvision.resolveEngagement(
        req.params.profileId, DEFAULT_ENGAGEMENT_TYPE);
      return res.json({ engagements: adopted ? [adopted] : [] });
    }
    res.json({ engagements: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/engagements — create one and start carving in the background
router.post('/engagements', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { profile_id, engagement_type, subnet_scheme, max_students } = req.body || {};
    const profRes = await query(`SELECT id, company_name FROM profiles WHERE id = $1`, [profile_id]);
    if (profRes.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const engagement = await engagementProvision.createEngagement({
      profileId: profile_id,
      engagementType: engagement_type || DEFAULT_ENGAGEMENT_TYPE,
      subnetScheme: subnet_scheme || 'v2',
      maxStudents: max_students,
      companyName: profRes.rows[0].company_name,
      actingUserId: req.user.userId,
    });

    audit.log({
      req,
      action: 'profile_engagement.created',
      source: 'ciab',
      target: { type: 'engagement', id: engagement.engagement_id },
      metadata: {
        profile_id, engagement_type: engagement.engagement_type,
        max_students: engagement.max_students, subnet_scheme: engagement.subnet_scheme,
      },
    });

    // 202: the row exists, the network does not yet. The UI polls the GET above.
    res.status(202).json({ success: true, engagement });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/engagements/:id/reprovision — retry a failed reservation
router.post('/engagements/:engagementId/reprovision', authenticateToken, adminOnly, async (req, res) => {
  try {
    const existing = await engagementProvision.getEngagementById(req.params.engagementId);
    if (!existing) return res.status(404).json({ error: 'Engagement not found' });

    const profRes = await query(`SELECT company_name FROM profiles WHERE id = $1`, [existing.profile_id]);
    const engagement = await engagementProvision.reprovisionEngagement(req.params.engagementId, {
      companyName: profRes.rows[0] && profRes.rows[0].company_name,
      // Guarded on purpose: re-provisioning a HEALTHY block carves a second one,
      // because the allocator only ever climbs and never re-uses range.
      force: req.body && req.body.force === true,
    });

    audit.log({
      req,
      action: 'profile_engagement.reprovisioned',
      source: 'ciab',
      target: { type: 'engagement', id: req.params.engagementId },
      metadata: { profile_id: existing.profile_id, previous_status: existing.provision_status },
    });

    res.status(202).json({ success: true, engagement });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
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

    const grpRes = await query(`SELECT * FROM ciab_profile_lane_groups WHERE id=$1`, [groupId]);
    if (grpRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = grpRes.rows[0];
    if (group.status === 'deleted') return res.status(409).json({ error: 'Group is deleted' });

    // Through the group's own pointer, NOT by re-deriving a key from the
    // profile: reservations are keyed on (profile, engagement) now, and this
    // group's lanes belong to exactly one of them.
    const reservation = await getProfileChallengeById(group.ephemeral_challenge_id);
    if (!reservation) {
      return res.status(409).json({ error: 'Group has no reservation — tear down everything and re-deploy' });
    }

    // Continue the lane_index sequence. The index is the student's identity
    // within the group (`<slug>-studentN@clinic.local`), so restarting it would
    // hand a new lane to an existing student and rotate their password.
    const idxRes = await query(
      `SELECT COALESCE(MAX(lane_index), 0) AS m FROM ciab_profile_lane_jobs WHERE group_id=$1`,
      [groupId]
    );
    const startIndex = parseInt(idxRes.rows[0].m, 10);
    const indices = Array.from({ length: count }, (_, i) => startIndex + i + 1);

    const { groupSlug, students, credentials } = await provisionLaneStudents({
      groupName: group.group_name,
      groupId,
      indices,
      actingUserId: req.user.userId,
    });

    audit.log({
      req,
      action: 'profile_lane.lanes_added',
      source: 'ciab',
      target: { type: 'group', id: groupId },
      metadata: { count, first_index: indices[0], last_index: indices[indices.length - 1] },
    });

    res.status(202).json({
      success: true,
      group_id: groupId,
      added: count,
      lane_indices: indices,
      progress_id: laneProvision.progressIdForGroup(groupId),
      // One-time display, exactly as the first deploy does it: the cleartext
      // password exists nowhere else after this response.
      credentials,
      students: students.map(s => ({ email: s.email, name: s.name, index: s.index })),
    });

    // Background. Same wrapper as the first deploy — add-lanes was a second,
    // drifting copy of that pipeline before A7, and the group's VXLAN block,
    // spec and reservation are identical either way.
    setImmediate(() => {
      laneProvision.provisionProfileLanes({
        groupId,
        groupName: group.group_name,
        groupSlug,
        challenge: {
          challenge_id: reservation.challenge_id,
          challenge_key: reservation.challenge_key,
          name: group.group_name,
          spec: reservation.spec,
          subnet_scheme: group.subnet_scheme,
        },
        students,
        attackBoxes: group.attack_boxes,
        vulnAppInstall: (reservation.spec && reservation.spec.vuln_app_install) || null,
      }).catch(err => {
        console.error(`[CIAB AddLanes] group ${groupId} add-lanes crashed: ${err.message}`);
      });
    });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json({ error: err.message });
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
  // The SHARED progress registry — the one with a heartbeat and staleness
  // fields, and the one that doubles as this app's only mutex. CIAB's private
  // registry had neither and was deleted with the fourth copy in A7.
  const shared = laneProvision.readGroupProgress(req.params.groupId);
  if (shared) return res.json({ group_id: req.params.groupId, ...shared });

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

    const reservation = await getProfileChallengeById(group.ephemeral_challenge_id);
    if (!reservation) {
      return res.status(409).json({ error: 'Reservation missing — cannot retry' });
    }

    // The student who owns the failed lane, read from the lane row rather than
    // re-derived from the group slug. Re-deploying a group rotates the student's
    // password but keeps the user id, so the lane is the only record of WHICH
    // account this particular lane belongs to.
    const ownerRes = await cybercoreQuery(
      `SELECT l.user_id, u.email
         FROM cybercore_lane l
         LEFT JOIN cybercore_user u ON u.user_id = l.user_id
        WHERE l.lane_id = $1`,
      [laneId]
    );
    const owner = ownerRes.rows[0];
    if (!owner || !owner.user_id || !owner.email) {
      return res.status(409).json({
        error: 'That lane has no owning student account, so a retry would deploy it to nobody.'
      });
    }

    audit.log({
      req,
      action: 'profile_lane.retried',
      source: 'ciab',
      target: { type: 'lane', id: laneId },
      metadata: { group_id: groupId, job_id: job.id },
    });
    res.status(202).json({ success: true, message: 'Retry started', lane_id: laneId, job_id: job.id });

    // Background. The lane is destroyed and rebuilt, so it comes back under a
    // NEW lane_id — the job mirror re-keys on (group_id, lane_index).
    setImmediate(() => {
      laneProvision.retryProfileLane({
        groupId,
        groupName: group.group_name,
        groupSlug: slugForGroup(group.group_name),
        challenge: {
          challenge_id: reservation.challenge_id,
          challenge_key: reservation.challenge_key,
          name: group.group_name,
          spec: reservation.spec,
          subnet_scheme: group.subnet_scheme,
        },
        laneId,
        user: { id: owner.user_id, email: owner.email },
        laneIndex: job.lane_index,
        attackBoxes: group.attack_boxes,
        vulnAppInstall: (reservation.spec && reservation.spec.vuln_app_install) || null,
        // Machines whose lane-config write never landed are recorded nowhere
        // else. They go through teardownLanes' contested and ownership checks.
        extraVmIds: Array.isArray(job.vm_ids) ? job.vm_ids : [],
      }).catch(err => {
        console.error(`[CIAB ProfileDeploy] Retry of lane ${laneId} failed: ${err.message}`);
        query(`UPDATE ciab_profile_lane_jobs SET status='error', error_msg=$2 WHERE id=$1`,
              [job.id, err.message]).catch(() => {});
      });
    });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json({ error: err.message });
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

    // Refuse to tear down a group that is still deploying. The first thing a
    // teardown does is snapshot the lane rows, and a deploy in flight is still
    // creating them — so the lanes that appear after the snapshot are destroyed
    // by nothing and belong to no one. 409 rather than queueing: there is no job
    // queue, and the admin can simply wait.
    laneProvision.assertNoConflictingProfileOperation({ groupId: req.params.groupId });

    const jobsRes = await query(
      `SELECT lane_id, vxlan_id, vm_ids FROM ciab_profile_lane_jobs WHERE group_id=$1`,
      [req.params.groupId]
    );

    // Collect the auto-provisioned student accounts BEFORE tearing lanes down
    // (teardownLane deletes the cybercore_lane rows we'd otherwise read them
    // from). Two sources, deduped:
    //   1. cybercore_lane.user_id where the lane config marks it a
    //      profile-lane-group lane with a student_email — the normal case.
    //   2. cybercore_user rows whose organization is this group and whose
    //      username matches the @clinic.local pattern — catches students whose
    //      lane was already deleted individually via the admin Lanes tab.
    // Only @clinic.local accounts are ever deleted, so a lane assigned to a
    // real user can never take that user's account down with it.
    const studentUsers = new Map();   // user_id -> username/email
    const laneIds = jobsRes.rows.map(j => j.lane_id).filter(Boolean);
    if (laneIds.length > 0) {
      try {
        const laneRows = await cybercoreQuery(
          `SELECT l.user_id, l.config, u.username
             FROM cybercore_lane l
             JOIN cybercore_user u ON u.user_id = l.user_id
            WHERE l.lane_id = ANY($1::uuid[])`,
          [laneIds]
        );
        for (const row of laneRows.rows) {
          const cfg = typeof row.config === 'string' ? JSON.parse(row.config || '{}') : (row.config || {});
          if (cfg.profile_lane_group && /@clinic\.local$/i.test(row.username || '')) {
            studentUsers.set(row.user_id, row.username);
          }
        }
      } catch (e) {
        console.warn(`[CIAB Teardown] lane->student lookup failed: ${e.message}`);
      }
    }
    try {
      const orgRows = await cybercoreQuery(
        `SELECT user_id, username FROM cybercore_user
          WHERE role = 'student' AND organization = $1 AND username LIKE '%@clinic.local'`,
        [group.group_name]
      );
      for (const row of orgRows.rows) studentUsers.set(row.user_id, row.username);
    } catch (e) {
      console.warn(`[CIAB Teardown] org->student lookup failed: ${e.message}`);
    }

    const errors = [];
    // Populated by the cybercore_user DELETE further down — the only point at
    // which these auto-provisioned accounts still have names.
    let deletedStudents = [];
    let lanesKeptForRetry = 0;
    for (const job of jobsRes.rows) {
      const result = await teardownLane({ laneId: job.lane_id, vmIds: job.vm_ids || [] });
      if (result.errors && result.errors.length > 0) errors.push(...result.errors);
      if (result.keptForRetry) lanesKeptForRetry += 1;
    }

    // ── Delete the auto-provisioned students + their Guacamole artifacts ──
    //
    // Gated on every lane having actually gone. cybercore_lane.user_id is
    // ON DELETE CASCADE (config/postgres/001_init_db.sql), so deleting these
    // accounts would erase the very rows teardownLane just kept on purpose —
    // with no Proxmox interaction at all, orphaning every survivor permanently
    // and releasing its vxlan_id for the next deploy to collide with.
    const studentIds = [...studentUsers.keys()];
    const studentEmails = [...studentUsers.values()];
    if (lanesKeptForRetry > 0) {
      const msg =
        `${lanesKeptForRetry} lane(s) kept because machines survived the teardown — ` +
        `the auto-provisioned student accounts were NOT deleted, because removing them ` +
        `would cascade those rows away and orphan the survivors. Re-run once cleared.`;
      console.warn(`[CIAB Teardown] ${msg}`);
      errors.push(msg);
    }
    if (lanesKeptForRetry === 0 && studentIds.length > 0) {
      // cybercore_allocation has CHECK (user_id IS NOT NULL OR group_key IS NOT NULL)
      // and its user FK is ON DELETE SET NULL — deleting a user with allocations
      // would violate the check and roll the user delete back. Purge first
      // (same ordering as the group teardown in src/routes/admin/groups.js).
      try {
        await cybercoreQuery(
          `DELETE FROM cybercore_allocation WHERE user_id = ANY($1::uuid[])`, [studentIds]
        );
      } catch (e) {
        errors.push(`allocation cleanup: ${e.message}`);
      }
      try {
        const r = await cybercoreQuery(
          `DELETE FROM cybercore_user WHERE user_id = ANY($1::uuid[]) AND username LIKE '%@clinic.local'
           RETURNING user_id, email`,
          [studentIds]
        );
        // Captured here because this DELETE is the last moment these accounts
        // exist; afterwards there is nothing left to name in the audit row.
        deletedStudents = r.rows || [];
        console.log(`[CIAB Teardown] ${group.group_name}: deleted ${r.rowCount}/${studentIds.length} auto-provisioned student account(s)`);
        if (r.rowCount < studentIds.length) {
          errors.push(`only ${r.rowCount}/${studentIds.length} student accounts deleted — check FK constraints`);
        }
      } catch (e) {
        errors.push(`student account cleanup: ${e.message}`);
      }
      // Guacamole accounts are keyed by email; best-effort.
      for (const email of studentEmails) {
        await guacAPI('DELETE', `/users/${encodeURIComponent(email)}`).catch(() => {});
      }
    }

    // Guacamole Kali console connections are named "<group> - lane<vxlan> - Kali"
    // (see lane-provision.js). Delete every connection carrying this group's prefix.
    try {
      const conns = await guacAPI('GET', '/connections');
      const prefix = `${group.group_name} - lane`;
      for (const [id, conn] of Object.entries(conns || {})) {
        if (conn && typeof conn.name === 'string' && conn.name.startsWith(prefix)) {
          await guacAPI('DELETE', `/connections/${encodeURIComponent(id)}`).catch(e =>
            errors.push(`guac connection ${conn.name}: ${e.message}`));
        }
      }
    } catch (e) {
      errors.push(`guac connection sweep: ${e.message}`);
    }

    // NOTE: we DO NOT delete the crucible_challenge here. Challenges are now
    // per-PROFILE (managed by getOrCreateProfileChallenge / deleteProfileChallenge),
    // so other groups from the same profile may still reference it. The
    // challenge is only deleted when the profile itself is deleted — that
    // path lives in profiles.js's DELETE /api/profiles/:id handler, which
    // calls deleteProfileChallenge() from utils/lane-reservation.js.

    // 'deleted' only when the cluster is actually clear. Tombstoning a group whose
    // machines are still running hides the survivors behind a row that reads as
    // finished — the same mistake the lane teardowns made, one level up.
    await query(
      `UPDATE ciab_profile_lane_groups SET status=$2, updated_at=NOW() WHERE id=$1`,
      [req.params.groupId, lanesKeptForRetry > 0 ? 'error' : 'deleted']
    );

    audit.batch({
      req,
      source: 'ciab',
      action: 'profile_lane.group_destroyed',
      targetAction: 'user.deleted',
      target: { type: 'group', id: req.params.groupId, label: group.group_name },
      metadata: { group_name: group.group_name, reason: 'profile_lane_teardown', errors: errors.length },
      targets: deletedStudents.map(u => ({
        id: u.user_id, label: u.email,
        metadata: { group_name: group.group_name, auto_provisioned: true },
      })),
    });

    // 207 when machines survived: the lane rows, the student accounts and the
    // group row have all deliberately been kept so a retry can still find them.
    res.status(lanesKeptForRetry === 0 ? 200 : 207).json({
      success: lanesKeptForRetry === 0,
      group_id: req.params.groupId,
      students_deleted: deletedStudents.length,
      lanes_kept_for_retry: lanesKeptForRetry,
      errors: errors.length ? errors : undefined
    });
  } catch (err) {
    // assertNoConflictingProfileOperation throws a 409. Flattening it to 500
    // would tell the admin the teardown broke, when in fact it was correctly
    // refused and retrying in a minute is the answer.
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.runProfileDeploy = runProfileDeploy;
module.exports.adoptedSpec = adoptedSpec;
module.exports.loadProfileForDeploy = loadProfileForDeploy;
module.exports.defaultAssetSelection = defaultAssetSelection;
