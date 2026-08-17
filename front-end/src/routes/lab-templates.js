/**
 * ============================================================================
 * Challenge Templates & Vuln Script Library Routes
 * ============================================================================
 * vuln_scripts → clinic_db (query)
 * crucible_challenge → cybercore_db (cybercoreQuery)
 * cybercore_template_catalog → cybercore_db (cybercoreQuery)
 * deployment_vuln_selections → clinic_db (query)
 */

const express = require('express');
const router = express.Router();
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { proxmoxAPI } = require('../utils/proxmox');
const { getDefaultTemplateNode } = require('../utils/site-config');
const { authenticateToken, requireRole } = require('../middleware/auth');
const goadDeploy = require('../utils/goad-deploy');
const { reserveLabNetwork, teardownLabNetwork, sanitizeZoneAbbrev } = require('../utils/lab-network-provision');
const { validateTopology } = require('../utils/topology-validate');
const { buildSpecVm, buildSpecNetwork } = require('../utils/challenge-spec');

const adminOnly = requireRole('admin');

// GET /api/admin/goad/labs — single source of truth for the admin UI's
// GOAD version dropdown. Returns the lab catalog from goad-deploy.js.
router.get('/goad/labs', authenticateToken, adminOnly, (req, res) => {
  res.json({
    default_lab: goadDeploy.DEFAULT_LAB,
    // IPs shown here are ILLUSTRATIVE — the actual lane subnet is decided
    // per-deploy by the challenge's subnet_scheme (v1: 192.18.0.X shared,
    // v2: 10.<vxh>.<vxl>.X unique per lane). UI shows v1-style addresses
    // because the last-octet pattern is the relevant invariant; the /24
    // base is a deploy-time detail.
    labs: Object.entries(goadDeploy.GOAD_LABS).map(([key, lab]) => ({
      key,
      displayName: lab.displayName,
      description: lab.description,
      forestRoot:  lab.forestRoot,
      vms: lab.vms.map(v => ({
        name:          v.name,
        role:          v.role,
        os:            v.os,
        template_vmid: v.template_vmid,
        ip:            goadDeploy.buildIp('192.18.0', v.ipOctet),  // illustrative
        ip_octet:      v.ipOctet,                                  // authoritative
        nic_model:     v.nic_model
      }))
    })),
    infra_ips: Object.fromEntries(
      Object.entries(goadDeploy.INFRA_IP_OCTETS).map(([k, octet]) => [k, goadDeploy.buildIp('192.18.0', octet)])
    ),
    infra_ip_octets: goadDeploy.INFRA_IP_OCTETS  // authoritative (last-octet only)
  });
});

// ============================================================================
// VULNERABILITY SCRIPTS (clinic_db)
// ============================================================================

// GET /api/admin/vuln-scripts
router.get('/vuln-scripts', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { category, os_target, difficulty, script_type, active_only } = req.query;
    let where = [];
    let params = [];
    let idx = 1;

    if (category)    { where.push(`category = $${idx++}`);    params.push(category); }
    if (os_target)   { where.push(`os_target = $${idx++}`);   params.push(os_target); }
    if (difficulty)  { where.push(`difficulty = $${idx++}`);  params.push(difficulty); }
    if (script_type) { where.push(`script_type = $${idx++}`); params.push(script_type); }
    if (active_only !== 'false') { where.push(`is_active = true`); }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    // Baseline scripts sort ahead of vulnerable within each category, so the
    // admin-facing list naturally shows the "just make it work" options first.
    const result = await query(
      `SELECT id, slug, name, description, category, script_type, os_target, difficulty,
              services_exposed, depends_on, estimated_runtime_sec, is_active, created_at,
              LENGTH(script_content) AS script_length
       FROM vuln_scripts ${whereClause}
       ORDER BY category,
                CASE script_type WHEN 'baseline' THEN 0 WHEN 'vulnerable' THEN 1 ELSE 2 END,
                name`,
      params
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/vuln-scripts/:id
router.get('/vuln-scripts/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(`SELECT * FROM vuln_scripts WHERE id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Script not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/vuln-scripts
router.post('/vuln-scripts', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { slug, name, description, category, script_type, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, script_args } = req.body;
    if (!slug || !name || !category || !script_content) {
      return res.status(400).json({ error: 'slug, name, category, and script_content are required' });
    }
    const type = (script_type || 'vulnerable').toLowerCase();
    if (!['baseline','vulnerable'].includes(type)) {
      return res.status(400).json({ error: `script_type must be 'baseline' or 'vulnerable' (got '${script_type}')` });
    }

    const result = await query(
      `INSERT INTO vuln_scripts (slug, name, description, category, script_type, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, script_args)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [slug, name, description || null, category, type, os_target || 'windows', difficulty || 'intermediate',
       script_content, JSON.stringify(services_exposed || []), depends_on || [], estimated_runtime_sec || 60, script_args || '']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: `Script slug '${req.body.slug}' already exists` });
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/vuln-scripts/:id
router.put('/vuln-scripts/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { slug, name, description, category, script_type, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, is_active, script_args } = req.body;
    if (script_type !== undefined && !['baseline','vulnerable'].includes(String(script_type).toLowerCase())) {
      return res.status(400).json({ error: `script_type must be 'baseline' or 'vulnerable' (got '${script_type}')` });
    }
    const result = await query(
      `UPDATE vuln_scripts SET
        slug = COALESCE($2, slug), name = COALESCE($3, name), description = $4,
        category = COALESCE($5, category), script_type = COALESCE($6, script_type),
        os_target = COALESCE($7, os_target),
        difficulty = COALESCE($8, difficulty), script_content = COALESCE($9, script_content),
        services_exposed = COALESCE($10, services_exposed), depends_on = COALESCE($11, depends_on),
        estimated_runtime_sec = COALESCE($12, estimated_runtime_sec), is_active = COALESCE($13, is_active),
        script_args = COALESCE($14, script_args)
       WHERE id = $1 RETURNING *`,
      [req.params.id, slug, name, description, category,
       script_type ? String(script_type).toLowerCase() : null,
       os_target, difficulty,
       script_content, services_exposed ? JSON.stringify(services_exposed) : null,
       depends_on, estimated_runtime_sec, is_active, script_args]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Script not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/vuln-scripts/:id
router.delete('/vuln-scripts/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    await query(`UPDATE vuln_scripts SET is_active = false WHERE id = $1`, [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/vm-templates — list VM templates from cybercore_template_catalog
// ?template_type= filters by type (os_template, workstation, lane_networking, challenge)
// ?os_family= filters by OS family; ?active_only=false to include inactive rows
router.get('/vm-templates', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { os_family, active_only, template_type } = req.query;
    const where = [];
    const params = [];
    let idx = 1;
    if (template_type) { where.push(`template_type = $${idx++}`); params.push(template_type); }
    if (os_family)     { where.push(`os_family = $${idx++}`);     params.push(os_family); }
    if (active_only !== 'false') where.push(`is_active = true`);
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const result = await cybercoreQuery(
      `SELECT id, template_type, template_key, os_family, os_name, os_version,
              template_vmid, node, role_hints, preferred, module_key, max_instances,
              status, description, notes, is_active, created_at, updated_at
       FROM cybercore_template_catalog ${whereClause}
       ORDER BY template_type, os_family, os_name, os_version NULLS LAST`,
      params
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/vm-templates/sync-nodes
// Queries live Proxmox cluster resources and writes the actual node for every
// template VMID back into cybercore_template_catalog. Safe to call repeatedly.
router.post('/vm-templates/sync-nodes', authenticateToken, adminOnly, async (req, res) => {
  try {
    const [catalogResult, resources] = await Promise.all([
      cybercoreQuery(`SELECT id, template_vmid, node FROM cybercore_template_catalog`),
      proxmoxAPI('GET', '/api2/json/cluster/resources')
    ]);

    const vmMap = {};
    for (const r of resources) {
      if (r.type === 'qemu' || r.type === 'lxc') vmMap[Number(r.vmid)] = r.node;
    }

    const updated = [];
    const unchanged = [];
    const not_found = [];

    for (const row of catalogResult.rows) {
      const liveNode = vmMap[Number(row.template_vmid)];
      if (!liveNode) {
        not_found.push(row.template_vmid);
        continue;
      }
      if (liveNode !== row.node) {
        await cybercoreQuery(
          `UPDATE cybercore_template_catalog SET node = $1, updated_at = now() WHERE id = $2`,
          [liveNode, row.id]
        );
        updated.push({ vmid: row.template_vmid, from: row.node, to: liveNode });
      } else {
        unchanged.push(row.template_vmid);
      }
    }

    res.json({ updated, unchanged, not_found });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/vuln-scripts-categories
router.get('/vuln-scripts-categories', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT DISTINCT category, COUNT(*) AS count FROM vuln_scripts WHERE is_active = true GROUP BY category ORDER BY category`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CHALLENGE MANAGEMENT (crucible_challenge in cybercore_db)
// ============================================================================

// GET /api/admin/lab-templates — list challenges as "templates"
router.get('/lab-templates', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { module } = req.query;
    const mod = (module || 'crucible').replace(/[^a-z0-9_]/gi, '');
    const result = await cybercoreQuery(
      `SELECT challenge_id AS id, challenge_key, name, description, difficulty, spec, status, created_at
       FROM ${mod}_challenge
       WHERE status = 'active'
       ORDER BY created_at DESC`
    );

    // Enrich with VM count from spec
    const rows = result.rows.map(r => {
      const spec = typeof r.spec === 'string' ? JSON.parse(r.spec) : (r.spec || {});
      return {
        ...r,
        vm_count: (spec.vms || []).length || (spec.template_vmid ? 1 : 0),
        phantom_count: (spec.phantom_assets || []).length,
        vxlan_block: spec.vxlan_block || null
      };
    });

    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/lab-templates/:id
router.get('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT * FROM crucible_challenge WHERE challenge_id = $1`, [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/lab-templates/validate — check a spec before it is saved or
// deployed. Stateless: the caller posts the machines it currently has on the
// canvas, including unsaved edits, and gets findings keyed to machine names.
//
// The same validators run at deploy time (challenge-lane-deployer re-exports
// them), so this cannot drift into telling an author something different from
// what the deploy will do.
router.post('/lab-templates/validate', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { vms, spec, subnet_scheme, goad } = req.body || {};
    const specVms = Array.isArray(vms) ? vms : [];
    const merged = { ...(spec || {}) };
    if (goad) merged.goad = goad;

    // Warn about templates the catalog does not know. Best-effort: a catalog
    // read failure must not turn into a validation failure, because the catalog
    // is advisory here — Proxmox is the real authority on what exists.
    let catalogVmids = null;
    try {
      const rows = await cybercoreQuery(
        `SELECT template_vmid FROM cybercore_template_catalog WHERE is_active = true`
      );
      catalogVmids = new Set(rows.rows.map(r => Number(r.template_vmid)));
    } catch (e) {
      console.warn(`[LabTemplates] Catalog unavailable for validation (${e.message}) — skipping that check`);
    }

    res.json(validateTopology({
      spec: merged,
      subnetScheme: ['v1', 'v2', 'v3'].includes(subnet_scheme) ? subnet_scheme : 'v1',
      specVms,
      catalogVmids,
    }));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// crucible_challenge.difficulty is an INTEGER (1=easy … 5=impossible) while
// every UI that touches it speaks in labels. Both write paths must convert:
// passing 'intermediate' straight through fails the whole request with
// `invalid input syntax for type integer`, which is what made the challenge
// editor unusable. Returns null for absent/unrecognized input so callers can
// COALESCE to "leave it alone".
const DIFFICULTY_MAP = {
  beginner: 1, easy: 1, intermediate: 2, medium: 2, hard: 3, advanced: 3, expert: 4, impossible: 5,
};

function toDifficultyInt(value) {
  if (value === undefined || value === null || value === '') return null;
  if (Number.isFinite(Number(value))) return Number(value);
  return DIFFICULTY_MAP[String(value).toLowerCase()] ?? null;
}

// Spec keys that describe a challenge's RESERVED NETWORK, not its content. They
// are written once by reserveLabNetwork and are load-bearing afterwards:
// vxlan_block is how a CLE course finds its lanes' VXLAN ids (lane-provision
// resolveCourseLab) and zone.abbrev is what teardownLabNetwork deletes from the
// SDN. An edit that dropped them would strand the SDN zone and break every
// future provision for that course with "no reserved VXLAN block". They are
// carried over from the stored spec unconditionally — changing a reservation
// means tearing the lab down and re-creating it, not editing a JSON field.
const PROTECTED_SPEC_KEYS = ['vxlan_block', 'zone', 'cle', 'course_id'];

// PUT /api/admin/lab-templates/:id — update challenge spec (add VMs, phantom assets, vuln defaults)
router.put('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, description, difficulty, spec, vm_specs, phantom_assets } = req.body;

    const existing = await cybercoreQuery(
      `SELECT spec FROM crucible_challenge WHERE challenge_id = $1`, [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });

    const currentSpec = typeof existing.rows[0].spec === 'string'
      ? JSON.parse(existing.rows[0].spec || '{}')
      : (existing.rows[0].spec || {});

    // Merge rather than replace. `vm_specs`/`phantom_assets` are accepted as
    // top-level aliases because that is the shape the template editor posts;
    // before this they were silently dropped and an edit appeared to save while
    // changing nothing.
    let nextSpec = null;
    if (spec || vm_specs || phantom_assets) {
      nextSpec = { ...currentSpec, ...(spec || {}) };
      // Length-guarded: an empty array is truthy, and a client that posts one by
      // reflex (the editor does when it renders no VM rows) must not blank the
      // VM list of a challenge it never showed VMs for.
      if (Array.isArray(vm_specs) && vm_specs.length) nextSpec.vms = vm_specs;
      if (Array.isArray(phantom_assets) && phantom_assets.length) nextSpec.phantom_assets = phantom_assets;
      for (const key of PROTECTED_SPEC_KEYS) {
        if (key in currentSpec) nextSpec[key] = currentSpec[key];
        else delete nextSpec[key];
      }
    }

    const result = await cybercoreQuery(
      `UPDATE crucible_challenge SET
        name = COALESCE($2, name),
        description = COALESCE($3, description),
        difficulty = COALESCE($4, difficulty),
        spec = COALESCE($5::jsonb, spec),
        updated_at = NOW()
       WHERE challenge_id = $1
       RETURNING *`,
      [req.params.id, name, description, toDifficultyInt(difficulty), nextSpec ? JSON.stringify(nextSpec) : null]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// DELETE /api/admin/lab-templates/:id — delete challenge + clean up SDN
router.delete('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    // Remove VNets + SDN zone and delete the challenge (refuses if active lanes
    // still use the block). Shared with the CLE course-teardown path.
    const result = await teardownLabNetwork(req.params.id, {
      log: (m) => console.log(`[DeleteChallenge] ${m}`),
    });
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});


// ============================================================================
// CREATE CHALLENGE (DB + SDN Zone + VNets)
// ============================================================================

// POST /api/admin/create-lab — full challenge creation with SDN infrastructure
router.post('/create-lab', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      name, challenge_key, description, difficulty, zone_abbrev,
      template_vmid, vms: vmsList, max_lanes, module, challenge_type,
      goad, subnet_scheme, network, phantom_assets
    } = req.body;

    if (!name || !challenge_key || !max_lanes) {
      return res.status(400).json({
        error: 'name, challenge_key, and max_lanes are required'
      });
    }

    // Must have either vms array or a single template_vmid
    if ((!vmsList || vmsList.length === 0) && !template_vmid) {
      return res.status(400).json({ error: 'At least one VM with a template_vmid is required' });
    }

    // Derive the SDN zone id: ≤8 alphanumerics, letter-leading (Proxmox rejects
    // a leading digit). sanitizeZoneAbbrev coerces both admin input and the
    // challenge_key fallback into a valid id.
    const finalZone = sanitizeZoneAbbrev(zone_abbrev || challenge_key);
    if (!/^[a-z][a-z0-9]{0,7}$/.test(finalZone)) {
      return res.status(400).json({ error: 'zone_abbrev must be 1-8 alphanumeric characters starting with a letter' });
    }

    const moduleKey = (module || 'crucible').toLowerCase();

    // subnet_scheme: v1/v2 = single-subnet lanes; v3 = segmented "DMZ" lanes
    // (two SDN VNets per lane). Defaults to v1 for back-compat.
    const subnetScheme = ['v1', 'v2', 'v3'].includes(subnet_scheme) ? subnet_scheme : 'v1';

    const numLanes = parseInt(max_lanes);
    if (numLanes < 1 || numLanes > 200) {
      return res.status(400).json({ error: 'max_lanes must be between 1 and 200' });
    }

    const difficultyInt = toDifficultyInt(difficulty) ?? 2;

    const statusUpdates = [];
    const pushStatus = (msg) => { statusUpdates.push(msg); console.log(`[CreateChallenge] ${msg}`); };

    // Build VMs array from input (multi-VM support). buildSpecVm emits the same
    // nine keys this route always emitted, plus `nics`/`layout` when the caller
    // authored them on the canvas — omitted otherwise, so a caller that does not
    // send them gets byte-identical output (test/challenge-spec-create.test.js).
    const specVMs = (vmsList && vmsList.length > 0)
      ? vmsList.map((vm, idx) => buildSpecVm(vm, idx, challenge_key))
      : [{
          name: challenge_key,
          role: 'primary',
          os: 'Unknown',
          template_vmid: parseInt(template_vmid),
          type: 'qemu',
          vm_offset: 600000,
          hostname: `${challenge_key}.local`
        }];

    const spec = {
      template_vmid: specVMs[0].template_vmid, // backward compat for single-VM deploy
      template_node: getDefaultTemplateNode(),
      vms: specVMs,
      limits: { max_concurrent_lanes: numLanes }
    };

    // Segment list + canvas positions, when the challenge was authored on a
    // canvas. Written only if the caller sent a network, so a challenge created
    // through the flat form keeps its spec free of topology keys — the same rule
    // the editor follows for per-VM `nics`. The segment list itself is rebuilt
    // from subnet_scheme rather than trusted, see challenge-spec.js.
    const specNetwork = buildSpecNetwork(network, subnetScheme);
    if (specNetwork) spec.network = specNetwork;

    // Length-guarded for the same reason PUT /lab-templates/:id guards it: a
    // client that posts an empty array by reflex must not look like intent.
    if (Array.isArray(phantom_assets) && phantom_assets.length) {
      spec.phantom_assets = phantom_assets;
    }

    // GOAD: when goad.enabled=true, embed the GOAD config so deploy paths can
    // detect it and run the post-clone provisioning (controller LXC + ansible
    // playbook). Defaults match what bake-goad-controller.sh / template 1004
    // ship with so admins can toggle this on without filling in every field.
    if (goad && goad.enabled) {
      spec.goad = {
        enabled: true,
        version:          goad.version          || 'light',
        domain:           goad.domain           || 'cybersaguaros.local',
        child_subdomain:  goad.child_subdomain  || 'tumamoc',
        admin_user:       goad.admin_user       || 'Administrator',
        admin_password:   goad.admin_password   || 'vagrant',
        include_kali:     goad.include_kali !== false  // default true
      };
      // Pre-baked ("GOAD-Like") mode: clone golden images instead of running the
      // ~90-min ansible bake. fixed_subnet pins the base the images were
      // provisioned on so every lane reuses it (deployPrebakedGoadLane +
      // applyFixedSubnet rely on these two fields being present on the spec).
      if (goad.prebaked) {
        spec.goad.prebaked = true;
        if (goad.fixed_subnet && goad.fixed_subnet.int) {
          spec.goad.fixed_subnet = {
            int: String(goad.fixed_subnet.int).trim(),
            ext: String(goad.fixed_subnet.ext || goad.fixed_subnet.int).trim()
          };
        }
      }
    }

    // Reserve the VXLAN block, insert the challenge, and create the SDN zone +
    // VNets (one reload + bridge-materialization wait). Shared with CLE courses.
    const reservation = await reserveLabNetwork({
      challengeKey: challenge_key,
      name,
      description: description || null,
      difficulty: difficultyInt,
      subnetScheme,
      maxLanes: numLanes,
      spec,
      zoneAbbrev: finalZone,
      status: 'active',
      log: pushStatus,
    });

    pushStatus('Challenge creation complete!');

    res.json({
      success: true,
      challenge_id: reservation.challenge_id,
      challenge_key: reservation.challenge_key,
      zone_abbrev: reservation.zone,
      vxlan_block: reservation.vxlan_block,
      vnets_created: reservation.vnetsCreated,
      steps: statusUpdates
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: `Challenge '${req.body.challenge_key}' already exists` });
    }
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// DEPLOYMENT STATUS (deployment_vuln_selections in clinic_db)
// ============================================================================

// GET /api/admin/lab-networks/:laneId/status
router.get('/lab-networks/:laneId/status', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM deployment_vuln_selections WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.params.laneId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No challenge deployment found for this lane' });
    }

    const deployment = result.rows[0];
    const scripts = deployment.selected_scripts || [];
    const total = scripts.length;
    const completed = scripts.filter(s => s.status === 'completed').length;
    const failed = scripts.filter(s => s.status === 'failed').length;
    const running = scripts.filter(s => s.status === 'running').length;
    const pending = scripts.filter(s => s.status === 'pending').length;

    res.json({
      ...deployment,
      script_summary: { total, completed, failed, running, pending },
      all_complete: pending === 0 && running === 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
