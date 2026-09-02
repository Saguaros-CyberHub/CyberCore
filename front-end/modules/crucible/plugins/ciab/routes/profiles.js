/*
 * ============================================================================
 * Profiles Routes - FIXED ROUTE ORDER
 * ============================================================================
 * Routes are ordered with specific paths BEFORE parameterized paths
 * This prevents /stats from being caught by /:id
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { pool } = require('../utils/db');
const { authenticateToken, requireRole } = require('../../../../../src/middleware/auth');
const { SCAN_DOC_CSS } = require('../ai/scan-documents');

function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const adminOnly = requireRole('admin');
// Policy generation is handled by the inline policy generator (ai/policy)
// Template fallback available at: require('../../installed-plugins/crucible-plugins/ciab/utils/policy-templates')

// ============================================================================
// Helper Functions
// ============================================================================

function toCamelCase(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  
  const camelObj = {};
  for (const [key, value] of Object.entries(obj)) {
    const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
    camelObj[camelKey] = value;
  }
  
  // Add status alias for generation_status
  if (camelObj.generationStatus) {
    camelObj.status = camelObj.generationStatus;
  }
  
  return camelObj;
}

function profilesToCamelCase(profiles) {
  return profiles.map(toCamelCase);
}

/** Load the full profile JSON file from disk (for policy generation, document gen, etc.) */
function loadProfileJson(profileRow) {
  try {
    let jsonPath = profileRow.json_file_path;
    if (jsonPath) {
      const resolvedPath = path.join(process.cwd(), jsonPath.replace(/^\//, ''));
      if (fs.existsSync(resolvedPath)) {
        const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
        return Array.isArray(parsed) ? parsed[0] : parsed;
      }
    }
    // Fallback: find by run_id
    if (profileRow.run_id) {
      const profilesDir = path.join(process.cwd(), 'profiles');
      if (fs.existsSync(profilesDir)) {
        const files = fs.readdirSync(profilesDir);
        const matchFile = files.find(f => f.includes(profileRow.run_id) && f.endsWith('.json'));
        if (matchFile) {
          const parsed = JSON.parse(fs.readFileSync(path.join(profilesDir, matchFile), 'utf-8'));
          return Array.isArray(parsed) ? parsed[0] : parsed;
        }
      }
    }
  } catch (err) {
    console.warn('⚠️ Could not load profile JSON:', err.message);
  }
  return null;
}

// ============================================================================
// SPECIFIC ROUTES (MUST BE BEFORE /:id ROUTES)
// ============================================================================

// GET /api/profiles/test - Test database connection
router.get('/test', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as current_time, COUNT(*) as profile_count FROM profiles');
    res.json({ 
      success: true, 
      message: 'Database connected!',
      current_time: result.rows[0].current_time,
      total_profiles: result.rows[0].profile_count
    });
  } catch (error) {
    res.json({ 
      success: false, 
      error: error.message 
    });
  }
});
// GET /api/profiles/stats - Redirect to stats/summary
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_profiles,
        COUNT(*) FILTER (WHERE difficulty = 'beginner') as beginner_count,
        COUNT(*) FILTER (WHERE difficulty = 'intermediate') as intermediate_count,
        COUNT(*) FILTER (WHERE difficulty = 'advanced') as advanced_count,
        COUNT(*) FILTER (WHERE client_type = 'SMB') as smb_count,
        COUNT(*) FILTER (WHERE client_type = 'NonProfit') as nonprofit_count,
        COUNT(*) FILTER (WHERE client_type = 'Utility_IT_OT') as utility_count,
        COUNT(*) FILTER (WHERE client_type = 'K12') as k12_count
      FROM profiles
      WHERE user_id = $1
    `, [userId]);
    
    res.json({
      success: true,
      stats: toCamelCase(result.rows[0])
    });
    
  } catch (error) {
    console.error('Error fetching profile stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
  }
});
// GET /api/profiles/stats/summary - Get statistics for dashboard
router.get('/stats/summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_profiles,
        COUNT(*) FILTER (WHERE difficulty = 'beginner') as beginner_count,
        COUNT(*) FILTER (WHERE difficulty = 'intermediate') as intermediate_count,
        COUNT(*) FILTER (WHERE difficulty = 'advanced') as advanced_count,
        COUNT(*) FILTER (WHERE client_type = 'SMB') as smb_count,
        COUNT(*) FILTER (WHERE client_type = 'NonProfit') as nonprofit_count,
        COUNT(*) FILTER (WHERE client_type = 'Utility_IT_OT') as utility_count,
        COUNT(*) FILTER (WHERE client_type = 'K12') as k12_count
      FROM profiles
      WHERE user_id = $1
    `, [userId]);
    
    res.json({
      success: true,
      stats: toCamelCase(result.rows[0])
    });
    
  } catch (error) {
    console.error('Error fetching profile stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
  }
});

// GET /api/profiles/recent - Get recent profiles for dashboard
router.get('/recent', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const limit = req.query.limit || 5;
    
    const result = await pool.query(`
      SELECT 
        id,
        company_name,
        client_type,
        client_type_name,
        industry,
        difficulty,
        created_at,
        html_file_path,
        json_file_path,
        employee_count,
        hq_city
      FROM profiles
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2
    `, [userId, limit]);
    
    res.json({
      success: true,
      profiles: profilesToCamelCase(result.rows)
    });
    
  } catch (error) {
    console.error('Error fetching recent profiles:', error);
    res.status(500).json({ error: 'Failed to fetch recent profiles', details: error.message });
  }
});

// GET /api/profiles - List all profiles for a user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    console.log('📋 Fetching profiles for user:', userId);
    
    const { 
      client_type, 
      difficulty, 
      sort_by = 'created_at', 
      sort_order = 'DESC',
      limit = 50,
      offset = 0 
    } = req.query;
    
    let query = `
      SELECT 
        id,
        company_name,
        client_type,
        client_type_name,
        industry,
        difficulty,
        maturity_level,
        delivery_mode,
        hq_city,
        employee_count,
        stakeholder_count,
        endpoint_count,
        created_at,
        updated_at,
        run_id,
        html_filename,
        html_file_path,
        json_filename,
        json_file_path,
        generation_status,
        scaffolding_level,
        compliance_frameworks,
        key_risks,
        critical_systems
      FROM profiles
      WHERE user_id = $1
    `;
    
    const params = [userId];
    let paramCount = 1;
    
    if (client_type) {
      paramCount++;
      query += ` AND client_type = $${paramCount}`;
      params.push(client_type);
    }
    
    if (difficulty) {
      paramCount++;
      query += ` AND difficulty = $${paramCount}`;
      params.push(difficulty);
    }
    
    const allowedSortFields = ['created_at', 'updated_at', 'company_name', 'difficulty'];
    const sortField = allowedSortFields.includes(sort_by) ? sort_by : 'created_at';
    const sortDir = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
    query += ` ORDER BY ${sortField} ${sortDir}`;
    
    query += ` LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);
    
    const result = await pool.query(query, params);
    
    console.log(`✅ Found ${result.rows.length} profiles`);
    
    // Get total count
    let countQuery = 'SELECT COUNT(*) FROM profiles WHERE user_id = $1';
    const countParams = [userId];
    if (client_type) {
      countQuery += ' AND client_type = $2';
      countParams.push(client_type);
    }
    if (difficulty && client_type) {
      countQuery += ' AND difficulty = $3';
      countParams.push(difficulty);
    } else if (difficulty) {
      countQuery += ' AND difficulty = $2';
      countParams.push(difficulty);
    }
    
    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);
    
    // Convert to camelCase
    const profiles = profilesToCamelCase(result.rows);
    
    res.json({
      success: true,
      profiles: profiles,
      pagination: {
        page: Math.floor(parseInt(offset) / parseInt(limit)) + 1,
        limit: parseInt(limit),
        total: total,
        totalPages: Math.ceil(total / parseInt(limit)),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < total
      }
    });
    
  } catch (error) {
    console.error('❌ Error fetching profiles:', error);
    res.status(500).json({ error: 'Failed to fetch profiles', details: error.message });
  }
});

// ─── Inline Profile Generation Helper ──────────────────────────────────────
// Same signature as the legacy helper so admin's generate-and-deploy
// endpoint (and other internal callers) don't change.
const { generateProfile } = require('../ai/profile');

// ─── In-memory generation progress tracker ─────────────────────────────────
// Client sends `progress_id` with the generate request; while the server
// works through the phases (org/it/network/threats/combining/writing/intake),
// it pushes step + percent + message updates into this map. The client polls
// /api/profiles/run-status/:progressId every ~1s to render an honest
// progress bar instead of a faked timer. Entries TTL after 10 min.
const PROGRESS_TTL_MS = 10 * 60 * 1000;
if (!global._aiProfileProgress) global._aiProfileProgress = new Map();
function setProgress(progressId, patch) {
  if (!progressId) return;
  const prev = global._aiProfileProgress.get(progressId) || { startedAt: Date.now() };
  global._aiProfileProgress.set(progressId, { ...prev, ...patch, updatedAt: Date.now() });
}
function getProgress(progressId) {
  return progressId ? global._aiProfileProgress.get(progressId) || null : null;
}
// Periodic cleanup — cheap walk every 5 min
if (!global._aiProfileProgressGC) {
  global._aiProfileProgressGC = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of global._aiProfileProgress.entries()) {
      if (now - (v.updatedAt || v.startedAt || 0) > PROGRESS_TTL_MS) {
        global._aiProfileProgress.delete(k);
      }
    }
  }, 5 * 60 * 1000);
  global._aiProfileProgressGC.unref?.();
}

/** {min,max} from either a range object or a pair of scalars. */
function toRange(rangeLike, min, max) {
  if (rangeLike && typeof rangeLike === 'object' && ('min' in rangeLike || 'max' in rangeLike)) {
    return rangeLike;
  }
  if (min != null || max != null) {
    const lo = Number(min ?? max);
    const hi = Number(max ?? min);
    if (Number.isFinite(lo) && Number.isFinite(hi)) return { min: lo, max: hi };
  }
  return undefined;
}

async function callInlineGenerateProfile({
  userId,
  client_type = 'SMB',
  industry,
  difficulty = 'intermediate',
  maturity,
  delivery,
  employees,
  llmModel,
  temperature,
  custom_config = {},
  org_name,
  company_name,
  domain,
  hq_city,
  progress_id,         // optional — when provided, server pushes step updates under this key

  // ── Everything below used to be silently dropped ─────────────────────────
  // buildConfig() has always accepted these; this function simply never
  // destructured them, and nothing built custom_config, so they never arrived.
  // Effect: every profile got exactly 25 firewall rules and exactly 5
  // stakeholders, and custom_seed never landed — so no profile was
  // reproducible from its seed.
  //
  // Two callers with two vocabularies: admin-profile-lanes.js already sends
  // the canonical names; generator.html sends its own. Accept both.
  framework,
  stakeholder_count,
  stakeholders,                                  // generator.html
  endpoint_count,
  endpoint_range,
  endpoints,                                     // generator.html
  firewall_rules_range,
  min_firewall_rules, max_firewall_rules,        // generator.html
  weakness_range,
  min_weaknesses, max_weaknesses,                // generator.html
  cooperation,
  scaffolding,
  est_hours,
  custom_seed
} = {}) {
  const validClientTypes = ['SMB', 'NonProfit', 'Utility_IT_OT', 'K12', 'Library'];
  const validDifficulties = ['beginner', 'intermediate', 'advanced'];
  if (!validClientTypes.includes(client_type)) {
    throw Object.assign(new Error('Invalid client_type'), { statusCode: 400 });
  }
  if (!validDifficulties.includes(difficulty)) {
    throw Object.assign(new Error('Invalid difficulty'), { statusCode: 400 });
  }

  if (progress_id) {
    setProgress(progress_id, { step: 'queued', percent: 1, message: 'Queued…' });
  }

  return generateProfile({
    user_id: userId,
    client_type, industry, difficulty, maturity, delivery, employees,
    llmModel, temperature, custom_config,
    company_name: org_name || company_name || undefined,
    domain, hq_city,

    // Normalized to the names buildConfig() expects, accepting either
    // caller's vocabulary. `undefined` still means "let the sizing profile
    // decide", so omitting a field is not the same as pinning it.
    framework,
    stakeholder_count: toRange(stakeholders, null, null) || stakeholder_count,
    endpoint_count,
    endpoint_range: toRange(endpoints, null, null) || endpoint_range,
    firewall_rules_range: firewall_rules_range
      || toRange(null, min_firewall_rules, max_firewall_rules),
    weakness_range: weakness_range
      || toRange(null, min_weaknesses, max_weaknesses),
    cooperation, scaffolding, est_hours, custom_seed,

    onProgress: progress_id
      ? (ev) => setProgress(progress_id, { step: ev.step, percent: ev.percent, message: ev.message, run_id: ev.run_id })
      : undefined
  });
}

// Backward-compatible alias (any external file that imported the old name still works)
const callN8nGenerateProfile = callInlineGenerateProfile;

// POST /api/profiles/generate — thin wrapper around callInlineGenerateProfile
router.post('/generate', authenticateToken, async (req, res) => {
  const progressId = req.body?.progress_id || null;
  // Register the progress entry IMMEDIATELY so the client's poller always finds
  // it (even if generation fails fast on validation, the catch below flips it to
  // 'error'). Without this, a fast rejection leaves the poller hitting 404 in a
  // tight loop until it gives up. See setProgress/run-status below.
  if (progressId) {
    setProgress(progressId, { step: 'queued', percent: 1, message: 'Queued…' });
  }
  try {
    const profile = await callInlineGenerateProfile({ userId: req.user.userId, ...req.body });
    if (progressId) {
      setProgress(progressId, { step: 'complete', percent: 100, message: 'Profile generated successfully', profile_id: profile.id });
    }
    res.json({ success: true, message: 'Profile generated successfully', profile: toCamelCase(profile) });
  } catch (err) {
    console.error('❌ Error generating profile:', err.message);
    if (progressId) {
      setProgress(progressId, { step: 'error', percent: 100, message: `Error: ${err.message}`, error: err.message });
    }
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// GET /api/profiles/run-status/:progressId — poll the in-memory tracker.
// Returns { step, percent, message, run_id?, profile_id?, error? } or 404.
router.get('/run-status/:progressId', authenticateToken, (req, res) => {
  const entry = getProgress(req.params.progressId);
  if (!entry) return res.status(404).json({ error: 'No progress entry for that id (expired or never started)' });
  res.json({
    step:        entry.step || 'unknown',
    percent:     entry.percent || 0,
    message:     entry.message || '',
    run_id:      entry.run_id || null,
    profile_id:  entry.profile_id || null,
    error:       entry.error || null,
    started_at:  entry.startedAt || null,
    updated_at:  entry.updatedAt || null
  });
});

// ─── Admin: upload an existing profile JSON ─────────────────────────────────
// Multipart NOT used — admin POSTs raw JSON as body so we don't depend on
// multer (not currently in deps). Validates shape, writes to profiles/, then
// inserts a row so the admin can deploy from it.
router.post('/upload', authenticateToken, adminOnly, express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const json = req.body && (Array.isArray(req.body) ? req.body[0] : req.body);
    const assets = json?.student_view?.raw?.threats?.network?.assets || json?.assets;
    if (!Array.isArray(assets) || assets.length === 0) {
      return res.status(400).json({
        error: 'Invalid profile JSON: expected student_view.raw.threats.network.assets[] (or top-level assets[])'
      });
    }

    const meta = json?.student_view?.meta || {};
    const quick = json?.student_view?.quick || {};
    const orgInfo = json?.student_view?.raw?.threats?.organization || {};

    const runId = `UPLOAD_${Date.now().toString(36).toUpperCase()}_${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const profilesDir = path.join(process.cwd(), 'profiles');
    if (!fs.existsSync(profilesDir)) fs.mkdirSync(profilesDir, { recursive: true });

    const fileName = `admin_uploaded_${runId}.json`;
    const fullPath = path.join(profilesDir, fileName);
    const relPath = path.join('profiles', fileName).replace(/\\/g, '/');
    fs.writeFileSync(fullPath, JSON.stringify(json, null, 2));

    const insert = await pool.query(`
      INSERT INTO profiles (user_id, company_name, client_type, industry, difficulty,
                            json_file_path, run_id, generation_status, profile_type)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'complete', 'admin_uploaded')
      RETURNING id, company_name, run_id, json_file_path, created_at
    `, [
      req.user.userId,
      quick.company_name || orgInfo.company_name || meta.cover_name || 'Uploaded Profile',
      // Was hardcoded 'SMB', so an uploaded K12 or Utility profile was stored
      // as an SMB and every size/sector-aware consumer read it as one.
      (['SMB', 'NonProfit', 'Utility_IT_OT', 'K12', 'Library']
        .includes(meta.client_type) ? meta.client_type : 'SMB'),
      orgInfo.industry || quick.industry || null,
      meta.difficulty || 'intermediate',
      relPath,
      runId
    ]);

    res.status(201).json({
      success: true,
      message: 'Profile uploaded',
      profile: toCamelCase(insert.rows[0]),
      asset_count: assets.length
    });
  } catch (err) {
    console.error('❌ Profile upload failed:', err.message);
    res.status(500).json({ error: 'Profile upload failed', details: err.message });
  }
});

// ─── Admin: one-step generate + deploy ──────────────────────────────────────
// Generates a profile inline, then immediately calls runProfileDeploy() from
// the profile-deploy route module. Returns both profile_id and group_id so
// the UI can switch straight into the lane-group status view.
router.post('/generate-and-deploy', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      num_lanes,
      group_name,
      attack_boxes,
      subnet_scheme,
      asset_selection,
      vuln_app,
      engagement_type,
      ...generateParams
    } = req.body || {};

    if (!Number.isFinite(parseInt(num_lanes, 10)) || parseInt(num_lanes, 10) < 1) {
      return res.status(400).json({ error: 'num_lanes (>=1) required' });
    }

    const profile = await callN8nGenerateProfile({ userId: req.user.userId, ...generateParams });

    // Lazy-require profile-deploy to avoid a circular dependency at module load.
    const { runProfileDeploy } = require('./profile-deploy');
    // R1: the ONE default, imported — never a bare 'v2' literal. Lazy-required
    // alongside profile-deploy above so this route adds no module-load edge.
    const { DEFAULT_SUBNET_SCHEME } = require('../utils/profile-to-spec');
    const deployResult = await runProfileDeploy({
      profileId: profile.id,
      userId: req.user.userId,
      numLanes: parseInt(num_lanes, 10),
      groupName: group_name,
      // undefined when the body omits it, so runProfileDeploy's
      // engagement-dependent default can fire. `attack_boxes !== false` would
      // resolve an omitted field to true and silently give a defensive
      // engagement a Kali box, which then wins the console.
      attackBoxes: attack_boxes === undefined ? undefined : attack_boxes !== false,
      subnetScheme: subnet_scheme || DEFAULT_SUBNET_SCHEME,
      assetSelection: asset_selection,
      vulnAppOpts: vuln_app || {},
      engagementType: engagement_type
    });

    res.status(202).json({
      success: true,
      profile: toCamelCase(profile),
      deploy: deployResult
    });
  } catch (err) {
    console.error('❌ generate-and-deploy failed:', err.message);
    const status = err.statusCode || 500;
    const body = { error: err.message };
    if (err.n8n_response) body.n8n_response = err.n8n_response;
    if (err.template_misses) body.template_misses = err.template_misses;
    if (err.service_gaps) body.service_gaps = err.service_gaps;
    res.status(status).json(body);
  }
});

// (callN8nGenerateProfile is exported below, after `module.exports = router`)

// ============================================================================
// PARAMETERIZED ROUTES (MUST BE AFTER SPECIFIC ROUTES)
// ============================================================================

// GET /api/profiles/:id/policies - List all policies for a profile
router.get('/:id/policies', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    // Verify ownership
    const profileCheck = await pool.query(
      'SELECT id, company_name FROM profiles WHERE id = $1 AND user_id = $2', [id, userId]
    );
    if (profileCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    // Fetch policies document
    const docResult = await pool.query(
      'SELECT content, metadata, generated_at FROM generated_documents WHERE profile_id = $1 AND document_type = $2',
      [id, 'policies']
    );

    if (docResult.rows.length === 0) {
      // No row at all — generation was never triggered for this profile
      // (e.g. it predates auto-generation). Distinct from 'generating' so
      // the UI knows a manual "Generate" button is actually appropriate here.
      return res.json({ success: true, policies: [], company_name: profileCheck.rows[0].company_name, total_count: 0, status: 'not_started' });
    }

    // metadata is a JSONB column — node-postgres already parses it into a
    // real object, not a string. Calling JSON.parse() on it (as this code
    // used to) throws on the object, gets silently swallowed, and defaults
    // meta to {} every time — which is why status always fell back to
    // 'complete' regardless of what was actually stored.
    const meta = docResult.rows[0].metadata || {};
    const status = meta.status || 'complete'; // rows written before this field existed are already complete

    if (status === 'generating' || status === 'failed' || status === 'none') {
      return res.json({
        success: true,
        policies: [],
        company_name: profileCheck.rows[0].company_name,
        total_count: 0,
        status,
        error: meta.error,
        reason: meta.reason
      });
    }

    const parsed = JSON.parse(docResult.rows[0].content);
    // Return full policy data including HTML (frontend caches to avoid second request)
    const policies = (parsed.policies || []).map(p => ({
      name: p.name,
      slug: p.slug,
      html: p.html,
      generated_at: parsed.generated_at
    }));

    res.json({
      success: true,
      policies: policies,
      company_name: parsed.company_name || profileCheck.rows[0].company_name,
      total_count: policies.length,
      status: 'complete'
    });
  } catch (error) {
    console.error('Error fetching policies:', error);
    res.status(500).json({ error: 'Failed to fetch policies', details: error.message });
  }
});

// GET /api/profiles/:id/policies/:slug - Get single policy as HTML
// GET /api/profiles/:id/policies/print - ALL policies combined into one print/PDF view.
// Registered BEFORE /:id/policies/:slug below — otherwise Express would match
// "print" as a policy slug and 404 before this route is ever reached.
router.get('/:id/policies/print', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const role = req.user.role;

    let profileQuery;
    if (role === 'instructor' || role === 'admin') {
      profileQuery = await pool.query('SELECT id, company_name FROM profiles WHERE id = $1', [id]);
    } else {
      profileQuery = await pool.query(
        'SELECT id, company_name FROM profiles WHERE id = $1 AND user_id = $2', [id, userId]
      );
    }
    if (profileQuery.rows.length === 0) return res.status(404).send('Profile not found');
    const p = profileQuery.rows[0];

    const docResult = await pool.query(
      `SELECT content, metadata FROM generated_documents WHERE profile_id = $1 AND document_type = 'policies'`,
      [id]
    );
    if (docResult.rows.length === 0) {
      return res.status(404).send('<p style="font-family:sans-serif;padding:40px;">No policies have been generated yet for this profile.</p>');
    }

    // metadata is a JSONB column — already a real object, not a string.
    const meta = docResult.rows[0].metadata || {};
    if (meta.status && meta.status !== 'complete') {
      return res.status(409).send(`<p style="font-family:sans-serif;padding:40px;">Policies are not ready yet (status: ${escHtml(meta.status)}). Try again shortly.</p>`);
    }

    let policies = [];
    try {
      const parsed = JSON.parse(docResult.rows[0].content);
      policies = parsed.policies || [];
    } catch (e) {
      policies = [];
    }

    if (policies.length === 0) {
      return res.status(404).send('<p style="font-family:sans-serif;padding:40px;">No policy documents available for this profile.</p>');
    }

    // Every policy's HTML was built from the same template (ai/policy/index.js's
    // buildPolicyHTML) so they all carry the same embedded <style> block — reuse
    // it once instead of repeating it per policy.
    const styleMatch = (policies[0].html || '').match(/<style>([\s\S]*?)<\/style>/i);
    const sharedStyle = styleMatch ? styleMatch[1] : '';

    const sections = policies.map((pol, i) => {
      const bodyMatch = (pol.html || '').match(/<body[^>]*>([\s\S]*?)<\/body>/i);
      const inner = bodyMatch ? bodyMatch[1] : (pol.html || '');
      return `<section class="policy-section"${i > 0 ? ' style="page-break-before: always;"' : ''}>${inner}</section>`;
    }).join('\n');

    const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>${escHtml(p.company_name)} — Security Policies</title>
<style>
${sharedStyle}
.print-bar { position: sticky; top: 0; background: #fff; padding: 10px 0; margin-bottom: 10px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: flex-end; }
.print-bar button { background: #1a365d; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; font-size: 0.9em; cursor: pointer; }
.policy-toc { text-align: center; padding: 40px 0; }
.policy-section { margin-bottom: 20px; }
@media print { .print-bar { display: none; } }
</style></head><body>
<div class="print-bar"><button onclick="window.print()">🖨️ Print / Save as PDF</button></div>
<div class="policy-toc">
  <h1 style="border:none;">Security Policy Documents</h1>
  <p>${escHtml(p.company_name)}</p>
  <p style="color:#718096;font-size:0.85em;">${policies.length} polic${policies.length === 1 ? 'y' : 'ies'}: ${policies.map(pol => escHtml(pol.name)).join(', ')}</p>
</div>
${sections}
</body></html>`;

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (error) {
    console.error('Error building policies print view:', error);
    res.status(500).send('Failed to build policies view');
  }
});

router.get('/:id/policies/:slug', authenticateToken, async (req, res) => {
  try {
    const { id, slug } = req.params;
    const userId = req.user.userId;
    console.log(`📋 [policy/:slug] Fetching slug="${slug}" for profile=${id}`);

    // Verify ownership
    const profileCheck = await pool.query(
      'SELECT id FROM profiles WHERE id = $1 AND user_id = $2', [id, userId]
    );
    if (profileCheck.rows.length === 0) {
      console.log('📋 [policy/:slug] Profile not found');
      return res.status(404).json({ error: 'Profile not found' });
    }

    const docResult = await pool.query(
      'SELECT content FROM generated_documents WHERE profile_id = $1 AND document_type = $2',
      [id, 'policies']
    );

    if (docResult.rows.length === 0) {
      console.log('📋 [policy/:slug] No policies row in generated_documents');
      return res.status(404).json({ error: 'No policies generated for this profile' });
    }

    console.log(`📋 [policy/:slug] Found policies doc, content length=${docResult.rows[0].content?.length || 0}`);
    const parsed = JSON.parse(docResult.rows[0].content);
    const availableSlugs = (parsed.policies || []).map(p => p.slug);
    console.log(`📋 [policy/:slug] Available slugs: ${availableSlugs.join(', ')}`);
    const policy = (parsed.policies || []).find(p => p.slug === slug);

    if (!policy) {
      console.log(`📋 [policy/:slug] Slug "${slug}" not found in available: [${availableSlugs.join(', ')}]`);
      return res.status(404).json({ error: 'Policy not found' });
    }

    console.log(`📋 [policy/:slug] Serving "${policy.name}" (${policy.html?.length || 0} chars)`);
    res.setHeader('Content-Type', 'text/html');
    res.send(policy.html);
  } catch (error) {
    console.error('❌ [policy/:slug] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch policy', details: error.message });
  }
});

// POST /api/profiles/:id/policies/generate - Generate (or regenerate) policies via inline Claude
const { generatePolicies } = require('../ai/policy');
router.post('/:id/policies/generate', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const { model } = req.body || {};
    console.log(`📋 [policies/generate] Starting for profile ${id}, user ${userId}, model ${model || 'default'}`);

    const role = req.user.role;
    let profileResult;
    if (role === 'instructor' || role === 'admin') {
      profileResult = await pool.query(
        'SELECT id, company_name, difficulty, json_file_path, run_id FROM profiles WHERE id = $1', [id]
      );
    } else {
      profileResult = await pool.query(
        'SELECT id, company_name, difficulty, json_file_path, run_id FROM profiles WHERE id = $1 AND user_id = $2',
        [id, userId]
      );
    }
    if (profileResult.rows.length === 0) {
      console.log('📋 [policies/generate] Profile not found');
      return res.status(404).json({ error: 'Profile not found' });
    }

    const profile = profileResult.rows[0];
    const profileJson = loadProfileJson(profile);
    if (!profileJson) {
      console.log('📋 [policies/generate] Profile JSON file not found');
      return res.status(400).json({ error: 'Profile JSON file not found — cannot generate policies' });
    }

    // Mark as generating before the Claude calls start — covers the case
    // where a student has two tabs open and clicks Generate in one while
    // viewing the other, so the second tab doesn't also offer a Generate
    // button and trigger a duplicate, wasteful generation run.
    try {
      await pool.query(`
        INSERT INTO generated_documents (profile_id, document_type, filename, content, metadata, generated_by)
        VALUES ($1, 'policies', 'policies_pending.json', $2, $3, $4)
        ON CONFLICT (profile_id, document_type) DO UPDATE SET
          filename = EXCLUDED.filename, content = EXCLUDED.content, metadata = EXCLUDED.metadata, generated_at = NOW()
      `, [
        id,
        JSON.stringify({ policies: [], total_count: 0 }),
        JSON.stringify({ status: 'generating', started_at: new Date().toISOString() }),
        userId
      ]);
    } catch (markErr) {
      console.warn('⚠️ [policies/generate] Could not mark policy generation as started:', markErr.message);
    }

    const result = await generatePolicies({
      profileJson,
      difficulty: profile.difficulty,
      model,
      profileId: id
    });

    if (!result.policies || result.policies.length === 0) {
      try {
        await pool.query(`
          UPDATE generated_documents SET metadata = $2, generated_at = NOW()
          WHERE profile_id = $1 AND document_type = 'policies'
        `, [
          id,
          JSON.stringify({ status: 'none', reason: result.message || 'No policies applicable' })
        ]);
      } catch (markErr) {
        console.warn('⚠️ [policies/generate] Could not mark policy generation as none:', markErr.message);
      }
      return res.json({
        success: true,
        message: result.message || 'No policies generated (policies_present may be empty)',
        total_count: 0
      });
    }

    // Persist into generated_documents (non-blocking on DB failure — still return the result)
    const safeName = (profile.company_name || 'profile').replace(/[^a-z0-9]/gi, '_').toLowerCase();
    try {
      await pool.query(`
        INSERT INTO generated_documents (profile_id, document_type, filename, content, metadata, generated_by)
        VALUES ($1, 'policies', $2, $3, $4, $5)
        ON CONFLICT (profile_id, document_type) DO UPDATE SET
          filename = EXCLUDED.filename, content = EXCLUDED.content, metadata = EXCLUDED.metadata, generated_at = NOW()
      `, [
        id,
        `policies_${safeName}.json`,
        JSON.stringify(result),
        JSON.stringify({ status: 'complete', count: result.total_count, names: result.policies.map(p => p.name) }),
        userId
      ]);
      console.log(`📋 [policies/generate] Stored ${result.total_count} policies in DB`);
    } catch (dbError) {
      console.error('⚠️ [policies/generate] DB insert failed (policies still generated):', dbError.message);
    }

    console.log(`📋 Generated ${result.total_count} policy documents for profile ${id} (${(result.total_generation_time_ms / 1000).toFixed(1)}s)`);
    res.json({
      success: true,
      message: `Generated ${result.total_count} policy documents`,
      total_count: result.total_count,
      policies: result.policies.map(p => ({ name: p.name, slug: p.slug, error: p.error }))
    });
  } catch (error) {
    console.error('❌ [policies/generate] Error:', error.message);
    console.error(error.stack);
    try {
      await pool.query(`
        UPDATE generated_documents SET metadata = $2, generated_at = NOW()
        WHERE profile_id = $1 AND document_type = 'policies'
      `, [
        req.params.id,
        JSON.stringify({ status: 'failed', error: error.message })
      ]);
    } catch (markErr) {
      console.warn('⚠️ [policies/generate] Could not mark policy generation as failed:', markErr.message);
    }
    res.status(500).json({ error: 'Failed to generate policies', details: error.message });
  }
});

// GET /api/profiles/:id/documents - List generated documents for a profile (student-accessible)
router.get('/:id/documents', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    // Verify ownership
    const profile = await pool.query('SELECT id FROM profiles WHERE id = $1 AND user_id = $2', [id, userId]);
    if (profile.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const result = await pool.query(`
      SELECT document_type, filename, length(content) as size, generated_at
      FROM generated_documents
      WHERE profile_id = $1 AND document_type IN ('nessus', 'zap', 'nmap')
      ORDER BY generated_at
    `, [id]);

    res.json({
      success: true,
      documents: result.rows.map(d => ({
        type: d.document_type,
        filename: d.filename,
        size: parseInt(d.size) || 0,
        generated_at: d.generated_at,
        download_url: `/api/profiles/${id}/documents/${d.document_type}`
      }))
    });
  } catch (error) {
    console.error('Error fetching documents:', error);
    res.status(500).json({ error: 'Failed to fetch documents' });
  }
});

// GET /api/profiles/:id/documents/print - Combined NMAP + Nessus + ZAP print/PDF view.
// Real HTML (each scan type is now a styled HTML document \u2014 see ai/scan-documents)
// rendered as one page with a print button, so "Print > Save as PDF" produces a
// clean, consistent PDF without any hand-rolled per-format parsing.
router.get('/:id/documents/print', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const role = req.user.role;

    let profileQuery;
    if (role === 'instructor' || role === 'admin') {
      profileQuery = await pool.query('SELECT id, company_name FROM profiles WHERE id = $1', [id]);
    } else {
      profileQuery = await pool.query(
        'SELECT id, company_name FROM profiles WHERE id = $1 AND user_id = $2', [id, userId]
      );
    }
    if (profileQuery.rows.length === 0) return res.status(404).send('Profile not found');
    const p = profileQuery.rows[0];

    const docs = await pool.query(`
      SELECT document_type, filename, content
      FROM generated_documents
      WHERE profile_id = $1 AND document_type IN ('nmap', 'nessus', 'zap')
      ORDER BY CASE document_type
        WHEN 'nmap' THEN 1 WHEN 'nessus' THEN 2 WHEN 'zap' THEN 3 ELSE 4
      END
    `, [id]);

    if (docs.rows.length === 0) {
      return res.status(404).send('<p style="font-family:sans-serif;padding:40px;">No scan reports have been generated yet for this profile.</p>');
    }

    const docLabels = { nmap: 'NMAP Network Scan', nessus: 'Nessus Vulnerability Scan', zap: 'ZAP Web Application Scan' };

    const sections = docs.rows.map((d, i) => {
      const bodyMatch = (d.content || '').match(/<body[^>]*>([\s\S]*?)<\/body>/i);
      const inner = bodyMatch ? bodyMatch[1] : (d.content || '');
      return `
<section class="doc-section"${i > 0 ? ' style="page-break-before: always;"' : ''}>
  <div class="doc-section-label">${escHtml(docLabels[d.document_type] || d.document_type.toUpperCase())}</div>
  ${inner}
</section>`;
    }).join('\n');

    const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>${escHtml(p.company_name)} \u2014 Scan Reports</title>
<style>
${SCAN_DOC_CSS}
body { max-width: 950px; }
.print-bar { position: sticky; top: 0; background: #fff; padding: 10px 0; margin-bottom: 10px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: flex-end; }
.print-bar button { background: #2c5282; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; font-size: 0.9em; cursor: pointer; }
.cover { text-align: center; padding: 50px 0 30px; }
.cover h1 { border: none; }
.doc-section-label { font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px; color: #a0aec0; margin-bottom: 6px; }
@media print { .print-bar { display: none; } }
</style></head><body>
<div class="print-bar"><button onclick="window.print()">\ud83d\udda8\ufe0f Print / Save as PDF</button></div>
<div class="cover">
  <h1>Scan Reports</h1>
  <p>${escHtml(p.company_name)}</p>
  <p style="color:#a0aec0;font-size:0.85em;">${docs.rows.length} report(s): ${docs.rows.map(d => escHtml(docLabels[d.document_type] || d.document_type)).join(', ')}</p>
</div>
${sections}
</body></html>`;

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (error) {
    console.error('Error building scan reports print view:', error);
    res.status(500).send('Failed to build scan reports view');
  }
});

// GET /api/profiles/:id/documents/:docType - Download a single document (student-accessible)
router.get('/:id/documents/:docType', authenticateToken, async (req, res) => {
  try {
    const { id, docType } = req.params;
    const userId = req.user.userId;

    // Verify ownership
    const profile = await pool.query('SELECT id FROM profiles WHERE id = $1 AND user_id = $2', [id, userId]);
    if (profile.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const result = await pool.query(
      'SELECT filename, content, document_type FROM generated_documents WHERE profile_id = $1 AND document_type = $2',
      [id, docType]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const d = result.rows[0];
    const contentTypes = { zap: 'text/html', nessus: 'text/html', nmap: 'text/html' };
    res.setHeader('Content-Type', contentTypes[docType] || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${d.filename}"`);
    res.send(d.content);
  } catch (error) {
    console.error('Error downloading document:', error);
    res.status(500).json({ error: 'Failed to download document' });
  }
});

// GET /api/profiles/:id - Get single profile with full details
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    
    const result = await pool.query(`
      SELECT *
      FROM profiles
      WHERE id = $1 AND user_id = $2
    `, [id, userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    const profile = toCamelCase(result.rows[0]);

    // Embed the asset list from the profile JSON server-side, so callers (e.g.
    // the admin lane-deploy console) never need to fetch the raw JSON file
    // directly over HTTP.
    profile.assets = [];
    if (profile.jsonFilePath) {
      try {
        const resolvedPath = path.join(process.cwd(), profile.jsonFilePath.replace(/^\//, ''));
        if (fs.existsSync(resolvedPath)) {
          const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
          const data = Array.isArray(parsed) ? parsed[0] : parsed;
          const studentView = data?.student_view?.raw || {};
          profile.assets = studentView?.network?.assets
            || studentView?.threats?.network?.assets
            || [];
        }
      } catch (e) {
        console.warn('⚠️ [GET /profiles/:id] Could not load assets from profile JSON:', e.message);
      }
    }

    res.json({
      success: true,
      profile
    });

  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

// PUT /api/profiles/:id/name - Update profile name (company name)
router.put('/:id/name', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    const userId = req.user.userId;
    
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const result = await pool.query(`
      UPDATE profiles
      SET company_name = $1, updated_at = NOW()
      WHERE id = $2 AND user_id = $3
      RETURNING id, company_name
    `, [name.trim(), id, userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    res.json({
      success: true,
      profile: toCamelCase(result.rows[0])
    });
    
  } catch (error) {
    console.error('Error updating profile name:', error);
    res.status(500).json({ error: 'Failed to update profile name', details: error.message });
  }
});

// DELETE /api/profiles/:id - Delete a profile
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    // Free the profile's crucible_challenge reservations in cybercore_db BEFORE
    // deleting the profile row (so we still have the pointer). Safe if the
    // profile never had one — deleteProfileChallenge is a no-op then. With no
    // engagementType it releases EVERY engagement's reservation, which is what
    // deleting the client means; releasing only one would strand the rest of the
    // VXLAN blocks and their VNets forever.
    try {
      const { deleteProfileChallenge } = require('../utils/lane-reservation');
      const role = req.user.role;
      // Verify ownership/admin first so we don't free someone else's reservation
      const owned = await pool.query(
        role === 'admin' ? `SELECT id FROM profiles WHERE id=$1` : `SELECT id FROM profiles WHERE id=$1 AND user_id=$2`,
        role === 'admin' ? [id] : [id, userId]
      );
      if (owned.rows.length > 0) {
        await deleteProfileChallenge(id);
      }
    } catch (cleanupErr) {
      console.warn(`[profiles DELETE] Challenge cleanup for ${id} failed: ${cleanupErr.message} — continuing with profile delete`);
    }

    const result = await pool.query(`
      DELETE FROM profiles
      WHERE id = $1 AND user_id = $2
      RETURNING id, company_name
    `, [id, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    res.json({
      success: true,
      message: `Profile "${result.rows[0].company_name || 'Unnamed'}" deleted successfully`
    });
    
  } catch (error) {
    console.error('Error deleting profile:', error);
    res.status(500).json({ error: 'Failed to delete profile', details: error.message });
  }
});

module.exports = router;
// Expose the profile-generation helper as a property of the router so other modules
// (profile-deploy.js generate-and-deploy) can drive profile generation
// without going through HTTP.
module.exports.callN8nGenerateProfile = callN8nGenerateProfile;