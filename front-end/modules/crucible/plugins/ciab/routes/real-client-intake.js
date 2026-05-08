/**
 * CIAB Plugin — Real-Client Intake API
 *
 * Parallel to the assessment-mode intake. Accepts anonymized intake payloads
 * uploaded from the standalone HTML form. Admins see all intakes; students
 * see only their own uploads.
 *
 * Mount path (from api.js): /api/real-client/intake
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { pool } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { buildStudentView } = require('../utils/profile-filler');
const { normalizeIntake } = require('../utils/intake-normalizer');
const { resolveTemplate } = require('../../../../../src/utils/vm-template-resolver');
const { resolveScriptsForVm } = require('../../../../../src/utils/vuln-script-resolver');

// IG1 safeguard list (mirrors the one embedded in the intake form HTML).
const IG1_LIST = require('../utils/ig1-safeguards.json');

const SUPPORTED_SCHEMA_VERSIONS = ['1.0'];

// === Phantom substitution policy ===
// Phantoms (assets we can't deploy as a real VM) can be substituted with a
// deployable VM of a different OS family. Each substitution type defines what
// the resulting VM looks like; the synthesize endpoint applies a default
// policy and accepts per-row admin overrides via req.body.substitutions.
const PHANTOM_SUBSTITUTION_TYPES = {
  'phantom':             { os_family: null, role: null, default_services: [], label: 'Phantom (no VM)' },
  'linux-workstation':   { os_family: 'linux',          role: 'workstation', default_services: ['SSH'],         label: 'Linux workstation' },
  'linux-server':        { os_family: 'linux',          role: 'server',      default_services: ['SSH'],         label: 'Linux server' },
  'windows-workstation': { os_family: 'windows_client', role: 'workstation', default_services: ['SMB', 'RDP'],  label: 'Windows workstation' },
  'windows-server':      { os_family: 'windows_server', role: 'server',      default_services: ['SMB', 'RDP'],  label: 'Windows server' },
};

// Default substitution per phantom os_family. macOS is auto-substituted to a
// Linux workstation since there's no macOS template available; everything else
// stays phantom unless the admin opts in.
const DEFAULT_PHANTOM_POLICY = {
  macos: 'linux-workstation',
  linux: 'phantom',
  other: 'phantom',
};

const LINUX_FRIENDLY_DECLARED = new Set(['SMB', 'SSH', 'HTTP', 'FTP']);
const WINDOWS_FRIENDLY_DECLARED = new Set(['SMB', 'RDP']);

/**
 * Apply substitution decisions to the normalizer's phantom list. Mutates
 * `normalized.vms` (adds substituted VMs) and `normalized.phantoms` (filters
 * out the substituted ones). Returns { applied, warnings } where applied is
 * a map { phantomName: subType } reflecting the final choice for each phantom.
 */
function applyPhantomSubstitutions(normalized, requestedSubs) {
  const requested = requestedSubs && typeof requestedSubs === 'object' ? requestedSubs : {};
  const applied = {};
  const warnings = [];
  const remaining = [];

  for (const phantom of normalized.phantoms) {
    const explicit = requested[phantom.name];
    const defaultChoice = DEFAULT_PHANTOM_POLICY[phantom.os_family] || 'phantom';
    const choice = (explicit && PHANTOM_SUBSTITUTION_TYPES[explicit]) ? explicit : defaultChoice;
    applied[phantom.name] = choice;

    const sub = PHANTOM_SUBSTITUTION_TYPES[choice];
    if (choice === 'phantom' || !sub || !sub.os_family) {
      remaining.push(phantom);
      continue;
    }

    // Carry declared services that fit the substitution's OS.
    const friendlySet = sub.os_family === 'linux' ? LINUX_FRIENDLY_DECLARED : WINDOWS_FRIENDLY_DECLARED;
    const declared = normalized.services.filter(s => friendlySet.has(s.canonical));
    const svcSet = new Set(declared.map(s => s.canonical));
    sub.default_services.forEach(s => svcSet.add(s));
    const services = Array.from(svcSet);

    normalized.vms.push({
      name: phantom.name,
      role: sub.role,
      os_family: sub.os_family,
      os_version: null,
      services,
      suggested_script_services: services.map(c => {
        const d = declared.find(s => s.canonical === c);
        return { service: c, version: d?.version || null };
      }),
      substituted_from: phantom.os_family,
      substitution_type: choice,
    });
    warnings.push({
      code: 'phantom_substituted',
      msg: `${phantom.name}: ${phantom.os_family || 'unknown'} → ${sub.label}${explicit ? ' (admin override)' : ' (default policy)'}`,
    });
  }

  normalized.phantoms = remaining;
  return { applied, warnings };
}

function isAdmin(req)      { return req.user?.role === 'admin'; }
function isInstructor(req) { return req.user?.role === 'instructor'; }
function canSeeAll(req)    { return isAdmin(req) || isInstructor(req); }

/**
 * Validates the shape of an uploaded intake payload.
 * Returns { ok: true } on pass, { ok: false, error } on fail.
 */
function validatePayload(payload) {
  if (!payload || typeof payload !== 'object')        return { ok: false, error: 'Payload is not an object.' };
  if (!payload.schema_version)                        return { ok: false, error: 'Missing schema_version.' };
  if (!SUPPORTED_SCHEMA_VERSIONS.includes(payload.schema_version))
    return { ok: false, error: `Unsupported schema_version: ${payload.schema_version}` };
  if (!payload.sections || typeof payload.sections !== 'object')
    return { ok: false, error: 'Missing sections object.' };
  if (!payload.cover_name || !String(payload.cover_name).trim())
    return { ok: false, error: 'cover_name is required.' };
  if (String(payload.cover_name).length > 200)
    return { ok: false, error: 'cover_name exceeds 200 characters.' };
  return { ok: true };
}

/**
 * Computes a small summary used in list views without opening the full payload.
 */
function summarize(payload) {
  const net = payload.sections?.network || {};
  const ig1 = payload.sections?.ig1 || {};
  // endpoint_count is the current (v1.1) field; fall back to legacy ws+laptop for older intakes.
  const endpointCount = Number(net.endpoint_count) > 0
    ? Number(net.endpoint_count)
    : (Number(net.workstation_count) || 0) + (Number(net.laptop_count) || 0);
  const assetTotal = endpointCount + (Number(net.server_count) || 0);
  const ig1Keys = Object.keys(ig1).filter(k => k.startsWith('ig1_') && !k.endsWith('_notes'));
  const ig1Answered = ig1Keys.filter(k => ig1[k] && ig1[k] !== null).length;
  const ig1Total = 56;
  return {
    asset_total: assetTotal,
    ig1_answered: ig1Answered,
    ig1_total: ig1Total,
    ig1_coverage_pct: ig1Total ? Math.round((ig1Answered / ig1Total) * 100) : 0
  };
}

/**
 * POST /api/real-client/intake/upload
 * Accepts the JSON payload directly. The HTML form and the admin uploader
 * both send JSON (HTML files are parsed client-side before POST).
 */
router.post('/upload', express.json({ limit: '4mb' }), async (req, res) => {
  try {
    const userId = req.user.userId;
    const role   = req.user.role || 'student';
    const payload = req.body;

    const v = validatePayload(payload);
    if (!v.ok) return res.status(400).json({ error: v.error });

    const rawPreview = JSON.stringify(payload).slice(0, 4096);

    const result = await pool.query(
      `INSERT INTO real_client_intakes
         (uploaded_by, uploaded_role, cover_name, schema_version, payload, raw_preview, raw_format, status)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, 'json', 'uploaded')
       RETURNING id, cover_name, created_at`,
      [userId, role, payload.cover_name.trim(), payload.schema_version, JSON.stringify(payload), rawPreview]
    );

    const row = result.rows[0];

    // Phase 0 transition: mirror into unified `intakes` table so the CRA dashboard
    // and the new GET /api/intakes endpoints see this upload too. Best-effort —
    // legacy table write is the source of truth until pages are migrated.
    try {
      await pool.query(
        `INSERT INTO intakes
           (user_id, profile_id, source, schema_version, cover_name, payload,
            completion_percentage, status, raw_format, raw_preview,
            legacy_source_table, legacy_source_id, created_at, updated_at, completed_at)
         VALUES ($1, NULL, 'real_client', $2, $3, $4::jsonb, 100, 'complete', 'json', $5,
                 'real_client_intakes', $6, $7, $7, $7)`,
        [userId, payload.schema_version, payload.cover_name.trim(), JSON.stringify(payload),
         rawPreview, row.id, row.created_at]
      );
    } catch (mirrorErr) {
      console.warn('[real-client intake upload] mirror to intakes failed:', mirrorErr.message);
    }

    res.json({
      intake_id: row.id,
      cover_name: row.cover_name,
      created_at: row.created_at,
      summary: summarize(payload)
    });
  } catch (err) {
    console.error('[real-client intake upload]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/real-client/intake
 * List intakes — admins/instructors see all, students see their own.
 */
router.get('/', async (req, res) => {
  try {
    const userId = req.user.userId;
    let rows;
    if (canSeeAll(req)) {
      const r = await pool.query(
        `SELECT id, uploaded_by, uploaded_role, cover_name, schema_version,
                linked_profile_id, linked_challenge_id, status, created_at
         FROM real_client_intakes
         WHERE status <> 'archived'
         ORDER BY created_at DESC`
      );
      rows = r.rows;
    } else {
      const r = await pool.query(
        `SELECT id, uploaded_by, uploaded_role, cover_name, schema_version,
                linked_profile_id, linked_challenge_id, status, created_at
         FROM real_client_intakes
         WHERE uploaded_by = $1 AND status <> 'archived'
         ORDER BY created_at DESC`,
        [userId]
      );
      rows = r.rows;
    }
    res.json({ intakes: rows, role: req.user.role, can_see_all: canSeeAll(req) });
  } catch (err) {
    console.error('[real-client intake list]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/real-client/intake/:id
 * Fetch the full payload for viewing.
 */
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const r = await pool.query(`SELECT * FROM real_client_intakes WHERE id = $1`, [id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Intake not found' });
    const row = r.rows[0];
    if (!canSeeAll(req) && row.uploaded_by !== userId) {
      return res.status(403).json({ error: 'Not permitted to view this intake.' });
    }
    res.json({
      intake: row,
      summary: summarize(row.payload),
      can_edit: canSeeAll(req) || row.uploaded_by === userId
    });
  } catch (err) {
    console.error('[real-client intake get]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/real-client/intake/:id/link
 * Attach a challenge and/or profile to an intake.
 */
router.put('/:id/link', express.json(), async (req, res) => {
  try {
    const { id } = req.params;
    const { linked_profile_id, linked_challenge_id } = req.body || {};
    const fields = [];
    const values = [];
    let n = 1;
    if (linked_profile_id !== undefined) {
      fields.push(`linked_profile_id = $${n++}`); values.push(linked_profile_id || null);
    }
    if (linked_challenge_id !== undefined) {
      fields.push(`linked_challenge_id = $${n++}`); values.push(linked_challenge_id || null);
    }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update.' });
    fields.push(`status = 'linked'`);
    fields.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(id);
    const r = await pool.query(
      `UPDATE real_client_intakes SET ${fields.join(', ')} WHERE id = $${n} RETURNING *`,
      values
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Intake not found' });
    res.json({ intake: r.rows[0] });
  } catch (err) {
    console.error('[real-client intake link]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/real-client/intake/:id
 * Soft-archive. Admins only.
 */
router.delete('/:id', async (req, res) => {
  try {
    if (!canSeeAll(req)) return res.status(403).json({ error: 'Admin only' });
    const { id } = req.params;
    const r = await pool.query(
      `UPDATE real_client_intakes SET status = 'archived', updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 RETURNING id`,
      [id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Intake not found' });
    res.json({ archived: r.rows[0].id });
  } catch (err) {
    console.error('[real-client intake delete]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/real-client/intake/:id/generate-profile
 * Builds a deterministic profile from the intake + its linked (or provided) challenge
 * + admin-specified filler asset counts. Writes a JSON file, inserts a profiles row
 * with profile_source='real_intake', and links the intake to it.
 *
 * Body:
 *   {
 *     challenge_id: "<uuid>",             // required if intake has no linked challenge
 *     filler: { windows_desktop: 40, windows_laptop: 80, ... }
 *   }
 */
router.post('/:id/generate-profile', express.json({ limit: '1mb' }), async (req, res) => {
  try {
    if (!canSeeAll(req)) return res.status(403).json({ error: 'Admin/instructor only' });
    const { id } = req.params;
    const { challenge_id: bodyChallengeId, filler } = req.body || {};
    const userId = req.user.userId;

    // 1. Load intake
    const ir = await pool.query(`SELECT * FROM real_client_intakes WHERE id = $1`, [id]);
    if (!ir.rows.length) return res.status(404).json({ error: 'Intake not found' });
    const intake = ir.rows[0];

    // 2. Resolve challenge id (prefer body, fall back to linked)
    const challengeId = bodyChallengeId || intake.linked_challenge_id;
    if (!challengeId) return res.status(400).json({ error: 'No challenge_id provided and intake has no linked challenge.' });

    // 3. Load challenge spec from cybercore_db
    const cr = await cybercoreQuery(
      `SELECT challenge_id, challenge_key, name, description, difficulty, spec, status
       FROM crucible_challenge WHERE challenge_id = $1`,
      [challengeId]
    );
    if (!cr.rows.length) return res.status(404).json({ error: 'Challenge not found' });
    const challenge = cr.rows[0];

    // 4. Build student_view JSON
    const studentView = buildStudentView({
      intake,
      challenge,
      filler: filler || {},
      ig1List: IG1_LIST
    });

    // 5. Persist JSON file on disk (matches existing profile file layout)
    const runId = `RUN_${Date.now()}_${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const jsonFilename = `client_profile_${runId}.json`;
    const profilesDir  = path.join(process.cwd(), 'profiles');
    if (!fs.existsSync(profilesDir)) fs.mkdirSync(profilesDir, { recursive: true });
    const jsonAbsPath  = path.join(profilesDir, jsonFilename);
    fs.writeFileSync(jsonAbsPath, JSON.stringify([studentView], null, 2), 'utf-8');
    const jsonFilePath = `profiles/${jsonFilename}`;

    // 6. Insert profiles row
    const coverName = intake.cover_name;
    const network   = studentView.student_view.raw.threats.network;
    const org       = studentView.student_view.raw.threats.organization;
    const totalAssets = network.total_assets;
    const frameworks = Array.isArray(org.frameworks) ? org.frameworks : [];

    const pr = await pool.query(
      `INSERT INTO profiles
        (user_id, run_id, client_type, company_name, industry,
         difficulty, employee_count, endpoint_count, compliance_frameworks,
         json_filename, json_file_path, generation_status,
         profile_source, source_intake_id, filler_assets)
       VALUES
        ($1,      $2,    'real_client', $3,          $4,
         $5,      $6,             $7,             $8::jsonb,
         $9,     $10,            'complete',
         'real_intake', $11,           $12::jsonb)
       RETURNING id, company_name, client_type, industry, difficulty, json_file_path, created_at`,
      [
        userId, runId,
        coverName, org.industry,
        challenge.difficulty === 3 ? 'advanced' : (challenge.difficulty === 2 ? 'intermediate' : 'beginner'),
        null, totalAssets, JSON.stringify(frameworks),
        jsonFilename, jsonFilePath,
        intake.id, JSON.stringify(filler || {})
      ]
    );
    const profile = pr.rows[0];

    // 7. Link intake → profile (and challenge, if not already)
    await pool.query(
      `UPDATE real_client_intakes
         SET linked_profile_id = $1,
             linked_challenge_id = COALESCE(linked_challenge_id, $2),
             status = 'linked',
             updated_at = CURRENT_TIMESTAMP
       WHERE id = $3`,
      [profile.id, challengeId, intake.id]
    );

    res.json({
      success: true,
      profile: {
        id: profile.id,
        company_name: profile.company_name,
        total_assets: totalAssets,
        real_count: network.real_count,
        filler_count: network.filler_count,
        json_file_path: profile.json_file_path
      }
    });
  } catch (err) {
    console.error('[real-client generate-profile]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/real-client/intake/:id/synthesize-challenge
 * Dry-run: normalizes the intake, resolves VM templates + vuln scripts, and
 * returns a challenge-spec JSON the admin reviews before hitting
 * /api/admin/create-challenge. Writes nothing.
 *
 * Response:
 *   {
 *     cover_name, suggested_challenge_key, suggested_name,
 *     vms: [{ name, role, os, os_family, template_vmid, template_match, services[], default_scripts[], missing_scripts[] }],
 *     phantom_assets: [{ hostname, role, os, notes }],
 *     warnings: [{ code, msg }],
 *     stats: { deployable_vms, phantoms, warnings }
 *   }
 */
router.post('/:id/synthesize-challenge', express.json(), async (req, res) => {
  try {
    if (!canSeeAll(req)) return res.status(403).json({ error: 'Admin/instructor only' });
    const { id } = req.params;

    const ir = await pool.query(`SELECT * FROM real_client_intakes WHERE id = $1`, [id]);
    if (!ir.rows.length) return res.status(404).json({ error: 'Intake not found' });
    const intake = ir.rows[0];
    const payload = intake.payload;

    // 1. Normalize intake (pure).
    const normalized = normalizeIntake(payload);

    // 1b. Apply phantom-substitution policy + per-row admin overrides.
    // Body shape: { substitutions: { ws05: 'linux-workstation', ws07: 'phantom' } }
    const subResult = applyPhantomSubstitutions(normalized, req.body?.substitutions);
    normalized.warnings.push(...subResult.warnings);

    // 2. Fetch catalogs in parallel.
    const [templatesRes, scriptsRes] = await Promise.all([
      pool.query(`SELECT id, os_family, os_name, os_version, template_vmid, node, role_hints, preferred, is_active, created_at
                  FROM vm_template_catalog WHERE is_active = true`),
      pool.query(`SELECT id, slug, name, category, script_type, os_target, difficulty, services_exposed, depends_on, is_active
                  FROM vuln_scripts WHERE is_active = true ORDER BY category, name`)
    ]);
    const templates = templatesRes.rows;
    const scripts = scriptsRes.rows;

    // 3. Resolve template + scripts for every deployable VM.
    const specVms = [];
    const warnings = normalized.warnings.slice();

    for (const vm of normalized.vms) {
      const match = resolveTemplate({ os_family: vm.os_family, os_version: vm.os_version, role: vm.role }, templates);
      if (!match) {
        // No family match → demote to phantom.
        normalized.phantoms.push({
          name: vm.name,
          role: vm.role,
          os_family: vm.os_family,
          os_version: vm.os_version,
          reason: `no template available for os_family="${vm.os_family}" — rendered as phantom`
        });
        warnings.push({ code: 'template_missing', msg: `${vm.name}: no template for ${vm.os_family}${vm.os_version ? ' ' + vm.os_version : ''} — demoted to phantom.` });
        continue;
      }

      const { required, missing } = resolveScriptsForVm(vm, scripts);
      if (match.match_type !== 'exact') {
        warnings.push({ code: 'template_fuzzy', msg: `${vm.name}: using ${match.os_name} (${match.match_type} match) for ${vm.os_family}${vm.os_version ? ' ' + vm.os_version : ''}.` });
      }
      for (const miss of missing) {
        warnings.push({ code: 'script_missing', msg: `${vm.name}: no script for ${miss.service}${miss.version ? ' v' + miss.version : ''} on ${vm.os_family} — manual configuration or AI-gen (Phase 3) required.` });
      }

      specVms.push({
        name: vm.name,
        role: vm.role,
        os: match.os_name,
        os_family: vm.os_family,
        template_vmid: match.template_vmid,
        template_node: match.node,
        template_match: match.match_type,
        type: 'qemu',
        vm_offset: 600000 + specVms.length * 10000,
        services: vm.services,
        default_scripts: required,
        missing_scripts: missing
      });
    }

    // 4. Phantom assets — documented but not deployed.
    const phantomAssets = normalized.phantoms.map(p => ({
      hostname: p.name,
      role: p.role,
      os: p.os_family === 'macos' ? 'macOS' : (p.os_family === 'linux' ? 'Linux' : p.os_family),
      notes: p.reason
    }));

    // 5. Derive challenge key + name.
    const sanitizedCover = String(normalized.cover_name)
      .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
    const suggestedKey = sanitizedCover ? `rc-${sanitizedCover}` : `rc-intake-${String(intake.id).slice(0, 8)}`;

    // 6. Difficulty heuristic — more phantoms + more missing scripts = harder.
    const complexity = specVms.length + phantomAssets.length;
    const difficulty = complexity <= 3 ? 'beginner' : (complexity <= 8 ? 'intermediate' : 'advanced');

    return res.json({
      intake_id: intake.id,
      cover_name: normalized.cover_name,
      suggested_challenge_key: suggestedKey,
      suggested_name: normalized.cover_name,
      suggested_difficulty: difficulty,
      suggested_description: normalized.notes
        ? `Real-client challenge synthesized from intake ${intake.id.slice(0, 8)}. Client notes: ${normalized.notes}`
        : `Real-client challenge synthesized from intake ${intake.id.slice(0, 8)}.`,
      suggested_max_lanes: 10,
      vms: specVms,
      phantom_assets: phantomAssets,
      warnings,
      // Substitution context the UI needs to render per-row dropdowns.
      substitution_options: Object.entries(PHANTOM_SUBSTITUTION_TYPES).map(([key, def]) => ({ key, label: def.label })),
      applied_substitutions: subResult.applied,
      stats: {
        deployable_vms: specVms.length,
        phantoms: phantomAssets.length,
        warnings: warnings.length,
        total_devices_reported: normalized.deviceTotal + normalized.serverCount
      },
      catalog_sizes: { vm_templates: templates.length, vuln_scripts: scripts.length }
    });
  } catch (err) {
    console.error('[real-client synthesize-challenge]', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
