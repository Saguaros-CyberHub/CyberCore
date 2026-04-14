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
const { cybercoreQuery } = require('../../../src/utils/cybercore-db');
const { buildStudentView } = require('../utils/profile-filler');

// IG1 safeguard list (mirrors the one embedded in the intake form HTML).
const IG1_LIST = require('../utils/ig1-safeguards.json');

const SUPPORTED_SCHEMA_VERSIONS = ['1.0'];

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
  const assetTotal =
    (Number(net.workstation_count) || 0) +
    (Number(net.laptop_count)      || 0) +
    (Number(net.server_count)      || 0);
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

module.exports = router;
