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
const { isDeepStrictEqual } = require('node:util');
const router = express.Router();
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { proxmoxAPI } = require('../utils/proxmox');
const { getDefaultTemplateNode } = require('../utils/site-config');
const { authenticateToken, requireRole } = require('../middleware/auth');
const goadDeploy = require('../utils/goad-deploy');
const { reserveLabNetwork, teardownLabNetwork, sanitizeZoneAbbrev } = require('../utils/lab-network-provision');
const {
  validateTopology, findForestRenameRefusals, goadLabDomains, goadLabRebrandable,
} = require('../utils/topology-validate');
const { buildSpecVm, buildSpecNetwork } = require('../utils/challenge-spec');
const adDomainRules = require('../utils/ad-domain-rules');
const goadRebrand = require('../utils/goad-lab-rebrand');

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
      // The lab's own child domain LABEL, or null when it has one domain. The
      // Designer resets both fields from these on a version change: before they
      // were served, the card kept whatever the previous lab had left on screen
      // and stored THAT — so every lab but GOAD-Light persisted a domain it does
      // not have.
      childSubdomain: lab.childSubdomain === undefined ? null : lab.childSubdomain,
      // The compiler's manifest metadata determines supported identities.
      // No GOAD source tree is required on the web server for this catalog.
      domains:     goadLabDomains(lab),
      rebrandable: goadLabRebrandable(key, lab),
      // Which extensions may be offered for THIS lab, with the reason the rest
      // may not. Sent per-lab rather than making the client re-derive
      // compatibility, so there is one implementation of that rule.
      extensions: goadDeploy.extensionsForLab(key, lab)
        .map(e => ({ key: e.key, ok: e.ok, reason: e.reason })),
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

// GET /api/admin/goad/extensions — the optional machines an environment can add
// to a lab (GOAD's own extensions/<key>/ inventories). Sits beside /goad/labs
// and mirrors its shape deliberately: one catalog reader per table, so the
// Designer never derives placement rules of its own.
//
// `ip` is illustrative for the same reason it is on /goad/labs — the real base
// is chosen per deploy by subnet_scheme. `ip_octet` is the authoritative half.
router.get('/goad/extensions', authenticateToken, adminOnly, (req, res) => {
  res.json({
    extensions: Object.values(goadDeploy.GOAD_EXTENSIONS).map(ext => ({
      key:           ext.key,
      displayName:   ext.displayName,
      description:   ext.description,
      machine:       ext.machine,
      role:          ext.role,
      os:            ext.os,
      template_vmid: ext.template_vmid,
      nic_model:     ext.nic_model,
      ip:            goadDeploy.buildIp('192.18.0', ext.ipOctet),  // illustrative
      ip_octet:      ext.ipOctet,                                  // authoritative
      instruments:   ext.instruments,
      dns_aliases:   ext.dns_aliases || [],
      compatibility: ext.compatibility,       // null = every lab
      // Whether the machine joins the AD forest. The Designer shows it because
      // it is the difference between "gets a reserved IP from the GOAD layer"
      // and "gets one from resolveSpecAddressing" — and only the second yields
      // a resolvable <name>.cybercore.lan.
      in_lab:        !!ext.inLab,
      // No desktop, no xrdp: it cannot be the student's RDP console as baked.
      headless:      !!ext.headless
    })),
    // Repeated here so a client that fetched only this endpoint can still refuse
    // to place a machine on Kali's address.
    infra_ip_octets: goadDeploy.INFRA_IP_OCTETS
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

/**
 * The same spec with `goad.generated_lab.files` replaced by a count.
 *
 * `files` is a whole rewritten GOAD lab tree — every config.json, inventory and
 * template the controller is handed, tens of kilobytes per challenge — and it is
 * read at DEPLOY time by resolveGeneratedLab, never by anything holding a list
 * row. GET /lab-templates returns the full spec for EVERY active challenge and
 * the Designer calls it three times per create, so the tree was being serialized
 * and shipped a dozen times over to render a table of names and VM counts.
 *
 * Returns the caller's object BY IDENTITY when there is nothing to strip, which
 * is what lets the list route keep every other row byte-identical to what it has
 * always returned.
 */
function withoutGeneratedLabFiles(spec) {
  const goad = spec && typeof spec === 'object' ? spec.goad : null;
  const gen = goad && typeof goad === 'object' ? goad.generated_lab : null;
  if (!gen || typeof gen !== 'object' || !gen.files) return spec;
  const { files, ...rest } = gen;
  return {
    ...spec,
    goad: {
      ...goad,
      // file_count, not the paths: the list caller only needs to know a tree is
      // there. Both shapes normalizeFiles accepts are counted — an array of
      // { path, content } and a path -> content map.
      generated_lab: {
        ...rest,
        file_count: Array.isArray(files) ? files.length : Object.keys(files).length,
      },
    },
  };
}

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
      const lean = withoutGeneratedLabFiles(spec);
      return {
        ...r,
        // Only when something was actually stripped, so a row with no generated
        // lab is byte-identical to what this route has always returned — spec
        // included, in whatever shape the driver handed it over.
        ...(lean === spec ? {} : { spec: lean }),
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

// Compilers own these definitions. An ordinary editor may round-trip them or
// omit them, but cannot replace them with an arbitrary controller payload.
function preserveCompiledGoad(current, incoming) {
  const next = { ...incoming };
  for (const key of ['lab', 'generated_lab', 'rename_plan']) {
    if (Object.hasOwn(incoming, key)
        && !isDeepStrictEqual(incoming[key], current?.[key])) {
      throw new Error(`goad.${key} is server-owned; regenerate the environment to replace it.`);
    }
    if (Object.hasOwn(current || {}, key)) next[key] = current[key];
    else delete next[key];
  }
  if (current?.lab || current?.generated_lab || current?.rename_plan) {
    // A compiled tree and its authored identity must travel together. Keeping
    // the tree while accepting a different version/domain is also corruption.
    for (const key of ['version', 'domain', 'child_subdomain', 'prebaked']) {
      if (Object.hasOwn(incoming, key)
          && !isDeepStrictEqual(incoming[key] ?? null, current[key] ?? null)) {
        throw new Error(`goad.${key} belongs to the compiled environment; regenerate it to change this field.`);
      }
      if (Object.hasOwn(current, key)) next[key] = current[key];
    }
  }
  if (next.rename_forest !== true) delete next.rename_forest;
  return next;
}

// PUT /api/admin/lab-templates/:id — update challenge spec (add VMs, phantom assets, vuln defaults)
router.put('/lab-templates/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, description, difficulty, vm_specs, phantom_assets } = req.body;
    let spec = req.body.spec;

    const existing = await cybercoreQuery(
      `SELECT spec FROM crucible_challenge WHERE challenge_id = $1`, [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Challenge not found' });

    const currentSpec = typeof existing.rows[0].spec === 'string'
      ? JSON.parse(existing.rows[0].spec || '{}')
      : (existing.rows[0].spec || {});

    if (spec && Object.hasOwn(spec, 'goad') && spec.goad === null
        && (currentSpec.goad?.lab || currentSpec.goad?.generated_lab || currentSpec.goad?.rename_plan)) {
      const disabled = { ...currentSpec.goad, enabled: false };
      delete disabled.rename_forest;
      spec = { ...spec, goad: disabled };
    }
    // ── the goad guard, and it runs BEFORE the merge on purpose ─────────────
    if (spec && Object.hasOwn(spec, 'goad') && spec.goad && typeof spec.goad === 'object') {
      try {
        spec = { ...spec, goad: preserveCompiledGoad(currentSpec.goad, spec.goad) };
      } catch (error) {
        return res.status(400).json({ error: error.message, field: 'goad' });
      }
      const renameRefusals = findForestRenameRefusals({ ...currentSpec, ...spec })
        .filter(f => f.severity === 'error');
      if (renameRefusals.length) {
        return res.status(400).json({
          error: renameRefusals.map(f => f.message).join(' '), field: 'goad',
          errors: renameRefusals.map(f => f.message), findings: renameRefusals
        });
      }
      if (spec.goad.rename_forest === true) {
        const identity = goadRebrand.describeRebrand({ ...currentSpec, ...spec });
        if (identity.willRebrand) {
          spec.goad = { ...spec.goad, version: identity.baseLab,
            domain: identity.domain, child_subdomain: identity.childSubdomain };
        }
      }
    }

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

    const suppliedDefinition = goad
      && ['lab', 'generated_lab', 'rename_plan'].find(key => Object.hasOwn(goad, key));
    if (suppliedDefinition) {
      return res.status(400).json({
        error: `goad.${suppliedDefinition} is server-owned. Edit the original compiled environment or regenerate it; author the forest fields to create a new stock lab.`,
        field: 'goad'
      });
    }

    // Validate the authored request before legacy defaults or extension filters
    // can hide an invalid explicit opt-in. Only plan metadata is prepared here;
    // the controller reads and transforms its own GOAD checkout at deploy.
    const rawRenameRefusals = findForestRenameRefusals({ goad, vms: vmsList })
      .filter(f => f.severity === 'error');
    if (rawRenameRefusals.length) {
      return res.status(400).json({
        error: rawRenameRefusals.map(f => f.message).join(' '), field: 'goad',
        errors: rawRenameRefusals.map(f => f.message), findings: rawRenameRefusals
      });
    }

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
      // Forest root + child are AUTHORED now, not read-only labels, so they get
      // the same rulebook the Designer painted into #topoErrGoad and Track G's
      // compiler mints against. Errors 400 with the sentence the author already
      // saw; a reserved TLD is only a warning, because every lab CyberCore ships
      // is named under .local and those names live in a golden image's NTDS.
      //
      // The defaults below are the LEGACY ones and are kept exactly as they were
      // — a client that sends no domain at all still gets cybersaguaros.local /
      // tumamoc, so nothing that posted before this validation existed changes
      // shape. The per-lab defaults now come from GOAD_LABS.childSubdomain via
      // the catalog, which is what the Designer fills the fields from.
      const goadDomains = adDomainRules.validateGoadDomains({
        domain:          goad.domain          || 'cybersaguaros.local',
        child_subdomain: goad.child_subdomain === undefined
          ? (goad.rename_forest === true ? null : 'tumamoc') : goad.child_subdomain
      });
      if (goadDomains.errors.length) {
        return res.status(400).json({
          error: goadDomains.errors.join(' '),
          field: 'goad',
          errors: goadDomains.errors,
          warnings: goadDomains.warnings
        });
      }
      goadDomains.warnings.forEach(w => pushStatus(`GOAD domain warning: ${w}`));

      spec.goad = {
        enabled: true,
        version:          goad.version          || 'light',
        domain:           goadDomains.domain,
        // Stored as the LABEL, which is the shape this field has always held and
        // the shape ad-child_domain.yml wants. checkChild accepts a full FQDN
        // too and reduces it, so an author who types the whole name is not
        // punished — the spec still reads 'tumamoc'.
        child_subdomain:  goadDomains.child_label,
        // 'vagrant', not 'Administrator': the built-in Administrator does NOT stay enabled
        // through sysprep /generalize /oobe, and the Windows template bakes vagrant/vagrant in
        // Administrators precisely so there is an account that survives. goad-deploy.js has
        // always defaulted initialUser to 'vagrant' for this reason -- but this line wrote
        // 'Administrator' into every spec, so that default never applied and every lane
        // authored here handed run.sh an account that cannot log in.
        admin_user:       goad.admin_user       || 'vagrant',
        admin_password:   goad.admin_password   || 'vagrant',
        include_kali:     goad.include_kali !== false  // default true
      };
      if (goad.rename_forest === true) {
        const identity = goadRebrand.describeRebrand({ goad });
        spec.goad.version = identity.baseLab;
        spec.goad.domain = identity.domain;
        spec.goad.child_subdomain = identity.childSubdomain;
      }

      // Extensions: a DECLARATION of what the golden images already contain, not
      // an install instruction. Resolved through the same filter the catalog
      // endpoint serves, so an incompatible key cannot be stored — ws01 on NHA
      // would otherwise land in the lab roster and make assertGoadRoster fail
      // every deploy of the challenge. Written only when something survived, so
      // a spec authored without extensions stays byte-identical to one written
      // before they existed.
      if (Array.isArray(goad.extensions) && goad.extensions.length) {
        const labKey = goad.version || goadDeploy.DEFAULT_LAB;
        // No labDef argument: resolveGoadExtensions resolves the lab through
        // getLab itself, so this route is not a second place that indexes the
        // lab table. An unknown version yields "everything offerable" here, and
        // the deploy path re-filters against whatever resolveGoadLab actually
        // falls back to — so a bad key still cannot reach the roster.
        const resolved = goadDeploy.resolveGoadExtensions(goad.extensions, labKey);
        if (resolved.selected.length) spec.goad.extensions = resolved.selected;
        const dropped = goad.extensions.filter(
          k => !resolved.selected.includes(String(k || '').trim().toLowerCase()));
        if (dropped.length) {
          pushStatus(`Ignored GOAD extension(s) not available for ${labKey}: ${dropped.join(', ')}`);
        }
      }
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

      // Forest rename: WRITTEN ONLY WHEN TRUE, the same rule extensions and
      // prebaked follow above, and for a stronger reason than byte-identity.
      // The create route defaults every GOAD spec to cybersaguaros.local /
      // tumamoc whatever lab it names, so `domain !== forestRoot` is true for
      // essentially every spec already stored — a derived trigger would
      // recompile all of them into a forest nobody chose. A key that is absent
      // from every stored row cannot be produced by an edit, which is the whole
      // migration story.
      //
      // Placed after extensions and prebaked because the refusals are about the
      // ASSEMBLED spec: which extensions survived the compatibility filter, and
      // whether this is a pre-baked lane at all.
      if (goad.rename_forest === true) {
        spec.goad.rename_forest = true;
      }
      // Self-gating — it returns nothing at all unless rename_forest is true —
      // so it runs on every GOAD create and costs nothing on the ones that do
      // not ask for a rename. Errors only: a future rename finding that merely
      // warns must not start 400ing a save that works.
      const renameRefusals = findForestRenameRefusals(spec).filter(f => f.severity === 'error');
      if (renameRefusals.length) {
        return res.status(400).json({
          error: renameRefusals.map(f => f.message).join(' '),
          field: 'goad',
          errors: renameRefusals.map(f => f.message),
          findings: renameRefusals
        });
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
