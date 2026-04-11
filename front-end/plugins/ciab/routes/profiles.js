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
const { pool } = require('../utils/db');
const { authenticateToken } = require('../../../src/middleware/auth');
// Policy generation is handled by the N8N Policy Generator workflow
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

// POST /api/profiles/generate - Trigger N8N workflow to generate profile
router.post('/generate', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { 
      client_type = 'SMB',
      industry,
      difficulty = 'intermediate',
      maturity,
      delivery,
      employees,
      custom_config = {}
    } = req.body;
    
    console.log('🚀 Generating profile for user:', userId);
    console.log('   Config:', { client_type, industry, difficulty, maturity, delivery, employees });
    
    // Validate inputs
    const validClientTypes = ['SMB', 'NonProfit', 'Utility_IT_OT', 'K12'];
    const validDifficulties = ['beginner', 'intermediate', 'advanced'];
    
    if (!validClientTypes.includes(client_type)) {
      return res.status(400).json({ error: 'Invalid client_type' });
    }
    
    if (!validDifficulties.includes(difficulty)) {
      return res.status(400).json({ error: 'Invalid difficulty' });
    }
    
    // Build N8N webhook payload
    const webhookPayload = {
      user_id: userId,
      client_type,
      industry,
      difficulty,
      maturity,
      delivery,
      employees,
      ...custom_config
    };
    
    // Get N8N webhook URL from environment
    const n8nWebhookUrl = process.env.N8N_WEBHOOK_URL || 'http://localhost:5678/webhook/generate-profile';
    
    console.log('📡 Calling N8N webhook:', n8nWebhookUrl);
    
    // Call N8N workflow
    const n8nResponse = await fetch(n8nWebhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(webhookPayload),
      signal: AbortSignal.timeout(120000) // 2 minute timeout
    });
    
    if (!n8nResponse.ok) {
      console.error('❌ N8N webhook failed:', n8nResponse.status, n8nResponse.statusText);
      const errorText = await n8nResponse.text();
      console.error('   Error details:', errorText);
      return res.status(500).json({ 
        error: 'Profile generation failed',
        details: errorText
      });
    }
    
    const n8nResult = await n8nResponse.json();
    console.log('✅ N8N workflow completed');
    
    // The N8N workflow should have created the profile in the database
    if (n8nResult.success && n8nResult.profile_id) {
      // Fetch the created profile
      const profileResult = await pool.query(`
        SELECT
          id,
          company_name,
          client_type,
          industry,
          difficulty,
          created_at,
          run_id,
          html_file_path,
          json_file_path
        FROM profiles
        WHERE id = $1 AND user_id = $2
      `, [n8nResult.profile_id, userId]);

      if (profileResult.rows.length > 0) {
        const createdProfile = profileResult.rows[0];
        console.log('✅ Profile created successfully:', createdProfile.id);

        // Policy documents are generated on-demand via the N8N Policy Generator workflow
        // (triggered by the "Generate Policies" button on the student dashboard)

        return res.json({
          success: true,
          message: 'Profile generated successfully',
          profile: toCamelCase(createdProfile)
        });
      }
    }
    
    // If we get here, something went wrong
    console.error('⚠️ N8N completed but profile not found in database');
    res.status(500).json({ 
      error: 'Profile generation completed but profile not found',
      n8n_response: n8nResult
    });
    
  } catch (error) {
    console.error('❌ Error generating profile:', error);
    res.status(500).json({ 
      error: 'Failed to generate profile',
      details: error.message 
    });
  }
});

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
      return res.json({ success: true, policies: [], company_name: profileCheck.rows[0].company_name, total_count: 0 });
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
      total_count: policies.length
    });
  } catch (error) {
    console.error('Error fetching policies:', error);
    res.status(500).json({ error: 'Failed to fetch policies', details: error.message });
  }
});

// GET /api/profiles/:id/policies/:slug - Get single policy as HTML
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

// POST /api/profiles/:id/policies/generate - Generate (or regenerate) policies via N8N workflow
router.post('/:id/policies/generate', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    console.log(`📋 [policies/generate] Starting for profile ${id}, user ${userId}`);

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

    // Call the N8N Policy Generator workflow
    const n8nPolicyUrl = process.env.N8N_POLICY_WEBHOOK_URL || 'http://localhost:5678/webhook-test/generate-policies';
    console.log(`📋 [policies/generate] Calling N8N at ${n8nPolicyUrl}...`);

    const n8nResponse = await fetch(n8nPolicyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        profile_id: id,
        user_id: userId,
        profile_data: profileJson,
        difficulty: profile.difficulty,
      }),
      signal: AbortSignal.timeout(600000) // 10 minute timeout (LLM generation is slow)
    });

    console.log(`📋 [policies/generate] N8N responded: status=${n8nResponse.status}`);

    if (!n8nResponse.ok) {
      const errorText = await n8nResponse.text();
      console.error('❌ N8N policy webhook failed:', n8nResponse.status, errorText);
      return res.status(500).json({ error: 'Policy generation workflow failed', details: errorText });
    }

    const n8nResult = await n8nResponse.json();
    console.log(`📋 [policies/generate] N8N result type=${typeof n8nResult}, isArray=${Array.isArray(n8nResult)}`);
    // N8N returns array — get the first item
    const result = Array.isArray(n8nResult) ? n8nResult[0] : n8nResult;
    console.log(`📋 [policies/generate] Parsed result: success=${result.success}, policies=${result.policies?.length || 0}`);

    if (!result.success || !result.policies || result.policies.length === 0) {
      return res.json({
        success: true,
        message: result.message || 'No policies generated (policies_present may be empty)',
        total_count: 0
      });
    }

    // Store policies in generated_documents (non-blocking — don't fail the request if DB insert fails)
    const safeName = (profile.company_name || 'profile').replace(/[^a-z0-9]/gi, '_').toLowerCase();
    try {
      await pool.query(`
        INSERT INTO generated_documents (profile_id, document_type, filename, content, metadata, generated_by)
        VALUES ($1, 'policies', $2, $3, $4, $5)
        ON CONFLICT (profile_id, document_type) DO UPDATE SET
          content = EXCLUDED.content, metadata = EXCLUDED.metadata, generated_at = NOW()
      `, [
        id,
        `policies_${safeName}.json`,
        JSON.stringify(result),
        JSON.stringify({ count: result.total_count, names: result.policies.map(p => p.name) }),
        userId
      ]);
      console.log(`📋 [policies/generate] Stored ${result.total_count} policies in DB`);
    } catch (dbError) {
      console.error('⚠️ [policies/generate] DB insert failed (policies still generated):', dbError.message);
      // Continue — return policies even if DB storage fails
    }

    console.log(`📋 Generated ${result.total_count} policy documents for profile ${id} via N8N (${((result.total_generation_time_ms || 0) / 1000).toFixed(1)}s)`);
    res.json({
      success: true,
      message: `Generated ${result.total_count} policy documents`,
      total_count: result.total_count,
      policies: result.policies.map(p => ({ name: p.name, slug: p.slug }))
    });
  } catch (error) {
    console.error('❌ [policies/generate] Error:', error.message);
    console.error(error.stack);
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

// GET /api/profiles/:id/documents/pdf - Download all documents as a single PDF
router.get('/:id/documents/pdf', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    // Verify ownership or instructor/admin access
    const role = req.user.role;
    let profileQuery;
    if (role === 'instructor' || role === 'admin') {
      profileQuery = await pool.query(
        'SELECT id, company_name, industry, difficulty FROM profiles WHERE id = $1', [id]
      );
    } else {
      profileQuery = await pool.query(
        'SELECT id, company_name, industry, difficulty FROM profiles WHERE id = $1 AND user_id = $2',
        [id, userId]
      );
    }
    if (profileQuery.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
    const p = profileQuery.rows[0];

    const docs = await pool.query(`
      SELECT document_type, filename, content
      FROM generated_documents
      WHERE profile_id = $1 AND document_type IN ('nessus', 'zap', 'nmap', 'policies')
      ORDER BY CASE document_type
        WHEN 'nmap' THEN 1 WHEN 'nessus' THEN 2 WHEN 'zap' THEN 3 WHEN 'policies' THEN 4 ELSE 5
      END
    `, [id]);

    if (docs.rows.length === 0) {
      return res.status(404).json({ error: 'No documents generated yet for this profile' });
    }

    const PDFDocument = require('pdfkit');
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 50, bottom: 50, left: 50, right: 50 },
      info: {
        Title: `Security Assessment Documents - ${p.company_name}`,
        Author: 'Clinic-in-a-Box',
        Subject: 'Generated Security Scan Reports'
      }
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition',
      `attachment; filename="${p.company_name.replace(/[^a-zA-Z0-9 ]/g, '')}_Security_Documents.pdf"`);
    doc.pipe(res);

    const pageW = doc.page.width - doc.page.margins.left - doc.page.margins.right;
    const LEFT = doc.page.margins.left;

    // Helper: check page break
    function ensureSpace(needed) {
      if (doc.y > doc.page.height - doc.page.margins.bottom - (needed || 40)) {
        doc.addPage();
      }
    }

    // Helper: severity color
    function sevColor(sev) {
      const s = String(sev).toLowerCase();
      if (s === '4' || s === 'critical') return '#7b2d8e';
      if (s === '3' || s === 'high') return '#e53e3e';
      if (s === '2' || s === 'medium') return '#ed8936';
      if (s === '1' || s === 'low') return '#4299e1';
      return '#a0aec0';
    }
    function sevLabel(sev) {
      const map = { '4': 'CRITICAL', '3': 'HIGH', '2': 'MEDIUM', '1': 'LOW', '0': 'INFO' };
      return map[String(sev)] || String(sev).toUpperCase();
    }

    // Helper: decode HTML entities
    function decodeEntities(str) {
      return (str || '')
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&apos;/g, "'").replace(/&quot;/g, '"').replace(/&#039;/g, "'")
        .replace(/&#\d+;/g, '').replace(/&nbsp;/g, ' ');
    }

    // Helper: draw horizontal rule
    function drawHR(color) {
      doc.save();
      doc.moveTo(LEFT, doc.y).lineTo(LEFT + pageW, doc.y)
         .strokeColor(color || '#e2e8f0').lineWidth(0.5).stroke();
      doc.restore();
      doc.moveDown(0.3);
    }

    // Helper: draw a badge
    function drawBadge(x, y, text, bgColor, width) {
      const w = width || 55;
      doc.save();
      doc.roundedRect(x, y, w, 14, 3).fill(bgColor);
      doc.fontSize(7).font('Helvetica-Bold').fillColor('#ffffff')
         .text(text, x, y + 3, { width: w, align: 'center' });
      doc.restore();
    }

    // ========== COVER PAGE ==========
    doc.moveDown(4);
    doc.fontSize(32).font('Helvetica-Bold').fillColor('#1a365d')
       .text('Security Assessment', { align: 'center' });
    doc.fontSize(28).fillColor('#2d3748')
       .text('Document Package', { align: 'center' });
    doc.moveDown(1.5);
    drawHR('#3182ce');
    doc.moveDown(1);
    doc.fontSize(18).font('Helvetica').fillColor('#2d3748')
       .text(p.company_name, { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(11).fillColor('#718096')
       .text(`Industry: ${p.industry || 'N/A'}`, { align: 'center' })
       .text(`Difficulty Level: ${(p.difficulty || 'N/A').charAt(0).toUpperCase() + (p.difficulty || '').slice(1)}`, { align: 'center' })
       .text(`Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, { align: 'center' });
    doc.moveDown(3);

    // TOC
    doc.fillColor('#1a365d').fontSize(14).font('Helvetica-Bold')
       .text('Included Documents', { align: 'center' });
    doc.moveDown(0.5);
    const docLabels = { nmap: 'NMAP Network Discovery Scan', nessus: 'Nessus Vulnerability Scan', zap: 'ZAP Web Application Scan', policies: 'Security Policy Documents' };
    const docDescs = { nmap: 'Network Topology & Services', nessus: 'Vulnerability Assessment', zap: 'Web Application Security', policies: 'Organizational Security Policies' };
    doc.fontSize(11).font('Helvetica').fillColor('#4a5568');
    docs.rows.forEach((d, i) => {
      doc.text(`${i + 1}. ${docLabels[d.document_type] || d.document_type.toUpperCase()}`, { align: 'center' });
      doc.fontSize(9).fillColor('#a0aec0')
         .text(docDescs[d.document_type] || '', { align: 'center' });
      doc.fontSize(11).fillColor('#4a5568');
      doc.moveDown(0.3);
    });

    doc.moveDown(4);
    doc.fontSize(9).fillColor('#a0aec0')
       .text('This document package contains simulated security scan results', { align: 'center' })
       .text('generated for the Clinic-in-a-Box training platform.', { align: 'center' });

    // ========== RENDER EACH DOCUMENT ==========
    for (const d of docs.rows) {
      doc.addPage();
      const label = docLabels[d.document_type] || d.document_type.toUpperCase();
      const content = d.content || '';

      // Section title bar
      doc.save();
      doc.rect(LEFT - 10, doc.y - 5, pageW + 20, 35).fill('#1a365d');
      doc.fontSize(18).font('Helvetica-Bold').fillColor('#ffffff')
         .text(label, LEFT, doc.y + 2, { width: pageW });
      doc.restore();
      doc.y += 35;
      doc.fontSize(8).font('Helvetica').fillColor('#a0aec0')
         .text(`Source File: ${d.filename}`);
      doc.moveDown(0.8);

      // ====== NESSUS XML PARSER ======
      if (d.document_type === 'nessus') {
        const hosts = [];
        const hostRegex = /<ReportHost name="([^"]*)">([\s\S]*?)<\/ReportHost>/g;
        let hostMatch;
        while ((hostMatch = hostRegex.exec(content)) !== null) {
          const hostBlock = hostMatch[2];
          const host = { name: hostMatch[1], properties: {}, items: [] };

          const tagRegex = /<tag name="([^"]*)">([\s\S]*?)<\/tag>/g;
          let tagMatch;
          while ((tagMatch = tagRegex.exec(hostBlock)) !== null) {
            host.properties[tagMatch[1]] = decodeEntities(tagMatch[2].trim());
          }

          const itemRegex = /<ReportItem\s+([^>]*)>([\s\S]*?)<\/ReportItem>/g;
          let itemMatch;
          while ((itemMatch = itemRegex.exec(hostBlock)) !== null) {
            const attrs = {};
            const attrRegex = /(\w+)="([^"]*)"/g;
            let attrMatch;
            while ((attrMatch = attrRegex.exec(itemMatch[1])) !== null) {
              attrs[attrMatch[1]] = attrMatch[2];
            }
            const body = itemMatch[2];
            const extractField = (tag) => {
              const m = body.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`));
              return m ? decodeEntities(m[1].trim()) : '';
            };
            if (attrs.severity === '0') continue;
            host.items.push({
              port: attrs.port, protocol: attrs.protocol, severity: attrs.severity,
              pluginName: attrs.pluginName || '', pluginID: attrs.pluginID || '',
              pluginFamily: attrs.pluginFamily || '',
              cvss: extractField('cvss_base_score'), cvss3: extractField('cvss3_base_score'),
              risk: extractField('risk_factor'), description: extractField('description'),
              synopsis: extractField('synopsis'), solution: extractField('solution'),
              output: extractField('plugin_output'),
              cve: (body.match(/<cve>([\s\S]*?)<\/cve>/g) || []).map(c => c.replace(/<\/?cve>/g, '').trim())
            });
          }
          host.items.sort((a, b) => parseInt(b.severity) - parseInt(a.severity));
          hosts.push(host);
        }

        // Summary counts
        const allItems = hosts.flatMap(h => h.items);
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        allItems.forEach(item => {
          const s = parseInt(item.severity);
          if (s >= 4) counts.critical++;
          else if (s === 3) counts.high++;
          else if (s === 2) counts.medium++;
          else if (s === 1) counts.low++;
        });

        // Summary boxes
        doc.fontSize(13).font('Helvetica-Bold').fillColor('#1a365d').text('Scan Summary');
        doc.moveDown(0.4);
        const boxW = (pageW - 30) / 4;
        const boxY = doc.y;
        [
          { label: 'Critical', count: counts.critical, color: '#7b2d8e' },
          { label: 'High', count: counts.high, color: '#e53e3e' },
          { label: 'Medium', count: counts.medium, color: '#ed8936' },
          { label: 'Low', count: counts.low, color: '#4299e1' }
        ].forEach((s, i) => {
          const x = LEFT + i * (boxW + 10);
          doc.save();
          doc.roundedRect(x, boxY, boxW, 40, 4).fill(s.color);
          doc.fontSize(18).font('Helvetica-Bold').fillColor('#ffffff')
             .text(String(s.count), x, boxY + 5, { width: boxW, align: 'center' });
          doc.fontSize(8).font('Helvetica').fillColor('#ffffff')
             .text(s.label, x, boxY + 26, { width: boxW, align: 'center' });
          doc.restore();
        });
        doc.y = boxY + 50;
        doc.fontSize(9).font('Helvetica').fillColor('#718096')
           .text(`${hosts.length} host(s) scanned  |  ${allItems.length} total findings`);
        doc.moveDown(1);
        drawHR('#cbd5e0');
        doc.moveDown(0.5);

        // Each host
        for (const host of hosts) {
          ensureSpace(80);
          const fqdn = host.properties['host-fqdn'] || host.name;
          const os = host.properties['operating-system'] || 'Unknown OS';
          const ip = host.properties['host-ip'] || host.name;

          doc.save();
          doc.roundedRect(LEFT, doc.y, pageW, 28, 4).fill('#edf2f7');
          doc.fontSize(11).font('Helvetica-Bold').fillColor('#1a365d')
             .text(fqdn, LEFT + 8, doc.y + 4, { width: pageW - 16 });
          doc.fontSize(8).font('Helvetica').fillColor('#718096')
             .text(`IP: ${ip}  |  OS: ${os}  |  ${host.items.length} finding(s)`, LEFT + 8);
          doc.restore();
          doc.y += 34;

          for (const item of host.items) {
            ensureSpace(80);
            const sColor = sevColor(item.severity);

            // Measure title height first so bar and badge align properly
            const titleX = LEFT + 12;
            const titleY = doc.y;
            const titleH = doc.heightOfString(item.pluginName, { width: pageW - 80, font: 'Helvetica-Bold', size: 9.5 });
            const barH = Math.max(titleH + 6, 18);

            // Severity bar sized to title
            doc.save();
            doc.rect(LEFT, titleY, 4, barH).fill(sColor);
            doc.restore();

            doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#1a202c')
               .text(item.pluginName, titleX, titleY, { width: pageW - 80 });
            drawBadge(LEFT + pageW - 58, titleY, sevLabel(item.severity), sColor, 55);

            // Ensure cursor is below the title block
            if (doc.y < titleY + barH) doc.y = titleY + barH + 2;

            // Meta line
            doc.fontSize(7).font('Helvetica').fillColor('#718096');
            const metaParts = [];
            if (item.port && item.port !== '0') metaParts.push(`Port: ${item.port}/${item.protocol}`);
            if (item.pluginID) metaParts.push(`Plugin: ${item.pluginID}`);
            if (item.cvss3) metaParts.push(`CVSS3: ${item.cvss3}`);
            else if (item.cvss) metaParts.push(`CVSS: ${item.cvss}`);
            if (item.pluginFamily) metaParts.push(item.pluginFamily);
            if (item.cve.length > 0) metaParts.push(item.cve.slice(0, 3).join(', '));
            doc.text(metaParts.join('  |  '), titleX);
            doc.moveDown(0.3);

            if (item.description) {
              doc.fontSize(8).font('Helvetica').fillColor('#4a5568');
              const desc = item.description.length > 350 ? item.description.substring(0, 350) + '...' : item.description;
              doc.text(desc, titleX, doc.y, { width: pageW - 20 });
              doc.moveDown(0.2);
            }

            if (item.solution) {
              ensureSpace(25);
              doc.fontSize(7.5).font('Helvetica-Bold').fillColor('#2f855a')
                 .text('Solution: ', titleX, doc.y, { continued: true });
              doc.font('Helvetica').fillColor('#4a5568');
              const sol = item.solution.length > 250 ? item.solution.substring(0, 250) + '...' : item.solution;
              doc.text(sol, { width: pageW - 20 });
            }

            doc.moveDown(0.5);
            drawHR('#edf2f7');
          }
          doc.moveDown(0.5);
        }
      }

      // ====== ZAP HTML PARSER ======
      else if (d.document_type === 'zap') {
        // Extract scan metadata
        const metaRegex = /<div class="scan-meta-item">\s*<div class="scan-meta-label">([\s\S]*?)<\/div>\s*<div class="scan-meta-value">([\s\S]*?)<\/div>/g;
        const metadata = {};
        let metaMatch;
        while ((metaMatch = metaRegex.exec(content)) !== null) {
          metadata[decodeEntities(metaMatch[1]).trim()] = decodeEntities(metaMatch[2]).trim();
        }

        // Extract summary counts
        const summaryRegex = /<div class="summary-card\s+(\w+)">\s*<div class="count">(\d+)<\/div>\s*<div class="label">([\s\S]*?)<\/div>/g;
        const summaryCounts = [];
        let summMatch;
        while ((summMatch = summaryRegex.exec(content)) !== null) {
          summaryCounts.push({ level: summMatch[1], count: parseInt(summMatch[2]), label: decodeEntities(summMatch[3]).trim() });
        }

        // Extract stats
        const statRegex = /<div class="stat-value">(\d+)<\/div>\s*<div class="stat-label">([\s\S]*?)<\/div>/g;
        const zapStats = [];
        let statMatch;
        while ((statMatch = statRegex.exec(content)) !== null) {
          zapStats.push({ value: statMatch[1], label: decodeEntities(statMatch[2]).trim() });
        }

        // Extract alert summary table rows
        const alertRows = [];
        const rowRegex = /<tr>\s*<td><span class="risk-indicator (\w+)"><\/span>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>\s*<td>(\d+)<\/td>\s*<\/tr>/g;
        let rowMatch;
        while ((rowMatch = rowRegex.exec(content)) !== null) {
          alertRows.push({
            risk: decodeEntities(rowMatch[2]).trim(),
            riskClass: rowMatch[1],
            name: decodeEntities(rowMatch[3]).trim(),
            cwe: decodeEntities(rowMatch[4]).trim(),
            instances: parseInt(rowMatch[5])
          });
        }

        // Extract individual findings
        const findings = [];
        const findingRegex = /<div class="finding (\w+)">([\s\S]*?)(?=<div class="finding [\w]+">|<\/div>\s*<\/div>\s*(?:<div class="findings-section|<div class="report-footer|$))/g;
        let findMatch;
        while ((findMatch = findingRegex.exec(content)) !== null) {
          const block = findMatch[2];
          const riskClass = findMatch[1];
          const titleM = block.match(/<div class="finding-title">([\s\S]*?)<\/div>/);
          const title = titleM ? decodeEntities(titleM[1]).trim() : 'Unknown';

          const metaTags = [];
          const metaTagRegex = /<span class="meta-tag">([\s\S]*?)<\/span>/g;
          let mtMatch;
          while ((mtMatch = metaTagRegex.exec(block)) !== null) {
            metaTags.push(decodeEntities(mtMatch[1]).trim());
          }

          const details = {};
          const detailRegex = /<div class="detail-label">([\s\S]*?)<\/div>\s*<div class="detail-value">([\s\S]*?)<\/div>/g;
          let detMatch;
          while ((detMatch = detailRegex.exec(block)) !== null) {
            const dlabel = decodeEntities(detMatch[1]).trim();
            let dvalue = detMatch[2].replace(/<a[^>]*>([\s\S]*?)<\/a>/g, '$1')
              .replace(/<code>([\s\S]*?)<\/code>/g, '$1').replace(/<[^>]+>/g, '');
            details[dlabel] = decodeEntities(dvalue).trim();
          }

          const codeBlocks = [];
          const codeRegex = /<div class="code-block">([\s\S]*?)<\/div>/g;
          let codeMatch;
          while ((codeMatch = codeRegex.exec(block)) !== null) {
            codeBlocks.push(decodeEntities(codeMatch[1]).trim());
          }

          const instances = [];
          const instRegex = /<div class="instance">([\s\S]*?)<\/div>\s*<\/div>/g;
          let instMatch;
          while ((instMatch = instRegex.exec(block)) !== null) {
            instances.push(decodeEntities(instMatch[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()));
          }

          findings.push({ riskClass, title, metaTags, details, codeBlocks, instances });
        }

        // --- Render ZAP PDF ---

        // Scan info bar
        if (Object.keys(metadata).length > 0) {
          doc.save();
          doc.roundedRect(LEFT, doc.y, pageW, 22, 4).fill('#edf2f7');
          doc.fontSize(7.5).font('Helvetica').fillColor('#4a5568');
          const metaStr = Object.entries(metadata).slice(0, 5).map(([k, v]) => `${k}: ${v}`).join('   |   ');
          doc.text(metaStr, LEFT + 8, doc.y + 6, { width: pageW - 16 });
          doc.restore();
          doc.y += 28;
        }

        // Summary boxes
        if (summaryCounts.length > 0) {
          doc.fontSize(13).font('Helvetica-Bold').fillColor('#1a365d').text('Alert Summary');
          doc.moveDown(0.4);
          const boxW = (pageW - 30) / Math.max(summaryCounts.length, 1);
          const boxY = doc.y;
          const zapColors = { high: '#e53e3e', medium: '#ed8936', low: '#4299e1', info: '#a0aec0', informational: '#a0aec0' };
          summaryCounts.forEach((s, i) => {
            const x = LEFT + i * (boxW + 10);
            doc.save();
            doc.roundedRect(x, boxY, boxW, 40, 4).fill(zapColors[s.level] || '#718096');
            doc.fontSize(18).font('Helvetica-Bold').fillColor('#ffffff')
               .text(String(s.count), x, boxY + 5, { width: boxW, align: 'center' });
            doc.fontSize(8).font('Helvetica').fillColor('#ffffff')
               .text(s.label, x, boxY + 26, { width: boxW, align: 'center' });
            doc.restore();
          });
          doc.y = boxY + 50;
        }

        // Stats row
        if (zapStats.length > 0) {
          doc.save();
          doc.roundedRect(LEFT, doc.y, pageW, 20, 3).fill('#f7fafc');
          doc.fontSize(8).font('Helvetica').fillColor('#718096');
          const statsStr = zapStats.map(s => `${s.value} ${s.label}`).join('   |   ');
          doc.text(statsStr, LEFT + 8, doc.y + 5, { width: pageW - 16 });
          doc.restore();
          doc.y += 26;
        }
        doc.moveDown(0.5);

        // Alert summary table
        if (alertRows.length > 0) {
          drawHR('#cbd5e0');
          doc.fontSize(12).font('Helvetica-Bold').fillColor('#1a365d').text('Alert Summary Table');
          doc.moveDown(0.4);

          const colW = [70, pageW - 200, 60, 55];
          const tableX = LEFT;
          doc.save();
          doc.rect(tableX, doc.y, pageW, 16).fill('#edf2f7');
          const headerY = doc.y;
          doc.fontSize(8).font('Helvetica-Bold').fillColor('#2d3748');
          doc.text('Risk Level', tableX + 4, headerY + 4, { width: colW[0] });
          doc.text('Alert Name', tableX + colW[0] + 4, headerY + 4, { width: colW[1] });
          doc.text('CWE', tableX + colW[0] + colW[1] + 4, headerY + 4, { width: colW[2] });
          doc.text('Count', tableX + colW[0] + colW[1] + colW[2] + 4, headerY + 4, { width: colW[3], align: 'center' });
          doc.restore();
          doc.y = headerY + 18;

          const zapRiskColors = { high: '#e53e3e', medium: '#ed8936', low: '#4299e1', info: '#a0aec0', informational: '#a0aec0' };
          for (const row of alertRows) {
            ensureSpace(16);
            const rowY = doc.y;
            doc.save();
            doc.circle(tableX + 8, rowY + 6, 4).fill(zapRiskColors[row.riskClass] || '#a0aec0');
            doc.restore();
            doc.fontSize(7.5).font('Helvetica').fillColor('#4a5568');
            doc.text(row.risk, tableX + 16, rowY + 2, { width: colW[0] - 16 });
            doc.text(row.name, tableX + colW[0] + 4, rowY + 2, { width: colW[1] });
            doc.fontSize(7).fillColor('#718096');
            doc.text(row.cwe, tableX + colW[0] + colW[1] + 4, rowY + 2, { width: colW[2] });
            doc.text(String(row.instances), tableX + colW[0] + colW[1] + colW[2] + 4, rowY + 2, { width: colW[3], align: 'center' });
            doc.y = rowY + 14;
            doc.save();
            doc.moveTo(tableX, doc.y).lineTo(tableX + pageW, doc.y)
               .strokeColor('#edf2f7').lineWidth(0.3).stroke();
            doc.restore();
          }
          doc.moveDown(0.8);
        }

        // Detailed findings
        if (findings.length > 0) {
          drawHR('#cbd5e0');
          doc.fontSize(12).font('Helvetica-Bold').fillColor('#1a365d').text('Detailed Findings');
          doc.moveDown(0.5);

          const zapFindingColors = { high: '#e53e3e', medium: '#ed8936', low: '#4299e1', info: '#a0aec0', informational: '#a0aec0' };
          for (const finding of findings) {
            ensureSpace(70);
            const fColor = zapFindingColors[finding.riskClass] || '#a0aec0';

            const fX = LEFT + 12;
            const fTitleY = doc.y;
            const fTitleH = doc.heightOfString(finding.title, { width: pageW - 80, font: 'Helvetica-Bold', size: 9.5 });
            const fBarH = Math.max(fTitleH + 6, 18);

            doc.save();
            doc.rect(LEFT, fTitleY, 4, fBarH).fill(fColor);
            doc.restore();

            doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#1a202c')
               .text(finding.title, fX, fTitleY, { width: pageW - 80 });
            drawBadge(LEFT + pageW - 55, fTitleY, finding.riskClass.toUpperCase(), fColor, 50);

            if (doc.y < fTitleY + fBarH) doc.y = fTitleY + fBarH + 2;

            if (finding.metaTags.length > 0) {
              doc.fontSize(7).font('Helvetica').fillColor('#718096')
                 .text(finding.metaTags.join('  |  '), fX);
            }
            doc.moveDown(0.3);

            const detailOrder = ['CWE ID', 'Description', 'Other Information', 'Attack', 'Evidence', 'Solution', 'Reference'];
            for (const key of detailOrder) {
              if (!finding.details[key]) continue;
              ensureSpace(25);
              const labelColor = key === 'Solution' ? '#2f855a' : '#2d3748';
              doc.fontSize(7.5).font('Helvetica-Bold').fillColor(labelColor)
                 .text(`${key}:`, fX);
              doc.fontSize(8).font('Helvetica').fillColor('#4a5568');
              let val = finding.details[key];
              if (val.length > 400) val = val.substring(0, 400) + '...';
              doc.text(val, fX, doc.y, { width: pageW - 20 });
              doc.moveDown(0.15);
            }

            for (const code of finding.codeBlocks.slice(0, 2)) {
              ensureSpace(25);
              const codeStr = code.length > 250 ? code.substring(0, 250) + '...' : code;
              const codeH = doc.heightOfString(codeStr, { width: pageW - 40, font: 'Courier', size: 7 }) + 10;
              doc.save();
              doc.roundedRect(fX, doc.y, pageW - 20, codeH, 3).fill('#1a202c');
              const codeY = doc.y;
              doc.fontSize(7).font('Courier').fillColor('#e2e8f0')
                 .text(codeStr, fX + 6, codeY + 5, { width: pageW - 40 });
              doc.restore();
              doc.y = codeY + codeH + 4;
            }

            if (finding.instances.length > 0) {
              ensureSpace(18);
              doc.fontSize(7).font('Helvetica-Bold').fillColor('#718096')
                 .text(`Instances (${finding.instances.length}):`, fX);
              for (const inst of finding.instances.slice(0, 3)) {
                doc.fontSize(7).font('Courier').fillColor('#3182ce');
                const instStr = inst.length > 150 ? inst.substring(0, 150) + '...' : inst;
                doc.text(instStr, fX + 8, doc.y, { width: pageW - 30 });
              }
            }

            doc.moveDown(0.5);
            drawHR('#edf2f7');
          }
        }
      }

      // ====== NMAP MARKDOWN RENDERER ======
      else if (d.document_type === 'nmap') {
        const lines = content.split('\n');
        let inCodeBlock = false;

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          ensureSpace(14);

          if (line.trim().startsWith('```')) {
            inCodeBlock = !inCodeBlock;
            if (inCodeBlock) doc.moveDown(0.2);
            continue;
          }

          // Host section headers (### hostname)
          if (line.startsWith('### ')) {
            ensureSpace(60);
            doc.moveDown(0.5);
            const headerText = line.replace(/^###\s*/, '').replace(/\*\*/g, '');

            doc.save();
            doc.roundedRect(LEFT, doc.y, pageW, 22, 4).fill('#edf2f7');
            doc.rect(LEFT, doc.y, 4, 22).fill('#3182ce');
            doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#1a365d')
               .text(headerText, LEFT + 12, doc.y + 5, { width: pageW - 20 });
            doc.restore();
            doc.y += 26;
            continue;
          }

          if (line.startsWith('## ')) {
            ensureSpace(30);
            doc.moveDown(0.5);
            doc.fontSize(14).font('Helvetica-Bold').fillColor('#1a365d')
               .text(line.replace(/^##\s*/, ''));
            drawHR('#3182ce');
            continue;
          }

          // Blockquotes
          if (line.startsWith('> ')) {
            const bqText = line.replace(/^>\s*/, '').replace(/\*\*/g, '').replace(/\*/g, '');
            doc.save();
            doc.rect(LEFT, doc.y, 3, 12).fill('#3182ce');
            doc.fontSize(7.5).font('Helvetica-Oblique').fillColor('#4a5568')
               .text(bqText, LEFT + 10, doc.y + 1, { width: pageW - 20 });
            doc.restore();
            doc.moveDown(0.3);
            continue;
          }

          if (inCodeBlock) {
            const trimmed = line.trim();
            if (trimmed.startsWith('PORT') || trimmed.startsWith('Nmap scan report')) {
              doc.fontSize(8).font('Helvetica-Bold').fillColor('#1a365d')
                 .text(line, LEFT + 6, doc.y, { width: pageW - 12 });
            } else if (/^\d+\/tcp/.test(trimmed) || /^\d+\/udp/.test(trimmed)) {
              doc.save();
              doc.rect(LEFT + 4, doc.y, pageW - 8, 11).fill('#f7fafc');
              doc.restore();
              doc.fontSize(7.5).font('Courier-Bold').fillColor('#2d3748')
                 .text(line, LEFT + 6, doc.y + 1, { width: pageW - 12 });
              doc.moveDown(0.05);
            } else if (trimmed.startsWith('|')) {
              doc.fontSize(7).font('Courier').fillColor('#4a5568')
                 .text(line, LEFT + 10, doc.y, { width: pageW - 20 });
            } else if (trimmed.startsWith('TRACEROUTE')) {
              ensureSpace(20);
              doc.fontSize(8).font('Helvetica-Bold').fillColor('#1a365d')
                 .text(line, LEFT + 6, doc.y, { width: pageW - 12 });
            } else {
              doc.fontSize(7).font('Courier').fillColor('#4a5568')
                 .text(line, LEFT + 6, doc.y, { width: pageW - 12 });
            }
            continue;
          }

          // Regular text
          if (line.trim()) {
            const cleanLine = line.replace(/\*\*/g, '').replace(/\*/g, '');
            doc.fontSize(8).font('Helvetica').fillColor('#4a5568')
               .text(cleanLine, LEFT, doc.y, { width: pageW });
          } else {
            doc.moveDown(0.2);
          }
        }
      }

      // ====== POLICIES JSON/HTML RENDERER ======
      else if (d.document_type === 'policies') {
        let policies = [];
        try {
          const parsed = JSON.parse(content);
          policies = parsed.policies || [];
        } catch (e) {
          policies = [];
        }

        if (policies.length === 0) {
          doc.fontSize(10).font('Helvetica').fillColor('#718096')
             .text('No policy documents available.', { align: 'center' });
        } else {
          // Policy overview
          doc.fontSize(13).font('Helvetica-Bold').fillColor('#1a365d')
             .text(`${policies.length} Policy Document(s)`);
          doc.moveDown(0.4);

          // List all policies as a mini-TOC
          policies.forEach((pol, i) => {
            doc.fontSize(9).font('Helvetica').fillColor('#4a5568')
               .text(`${i + 1}. ${pol.name}`);
          });
          doc.moveDown(1);
          drawHR('#cbd5e0');

          // Render each policy
          for (const pol of policies) {
            doc.addPage();
            ensureSpace(40);

            // Policy title bar
            doc.save();
            doc.roundedRect(LEFT, doc.y, pageW, 26, 4).fill('#2d3748');
            doc.fontSize(12).font('Helvetica-Bold').fillColor('#ffffff')
               .text(pol.name, LEFT + 10, doc.y + 7, { width: pageW - 20 });
            doc.restore();
            doc.y += 32;

            // Strip HTML to text for PDF rendering
            let policyText = (pol.html || '')
              .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
              .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
              .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, '\n=== $1 ===\n')
              .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, '\n--- $1 ---\n')
              .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, '\n$1\n')
              .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, '  * $1\n')
              .replace(/<br\s*\/?>/gi, '\n')
              .replace(/<\/p>/gi, '\n\n')
              .replace(/<\/tr>/gi, '\n')
              .replace(/<\/th>/gi, ' | ')
              .replace(/<\/td>/gi, ' | ')
              .replace(/<[^>]+>/g, '')
              .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
              .replace(/&nbsp;/g, ' ').replace(/&#\d+;/g, '')
              .replace(/\n{3,}/g, '\n\n')
              .trim();

            const pLines = policyText.split('\n');
            for (const pLine of pLines) {
              ensureSpace(14);
              const trimmed = pLine.trim();

              // Section headers
              if (trimmed.startsWith('=== ') && trimmed.endsWith(' ===')) {
                doc.moveDown(0.3);
                doc.fontSize(13).font('Helvetica-Bold').fillColor('#1a365d')
                   .text(trimmed.replace(/^===\s*/, '').replace(/\s*===$/, ''));
                drawHR('#3182ce');
                continue;
              }
              if (trimmed.startsWith('--- ') && trimmed.endsWith(' ---')) {
                doc.moveDown(0.3);
                doc.fontSize(11).font('Helvetica-Bold').fillColor('#2d3748')
                   .text(trimmed.replace(/^---\s*/, '').replace(/\s*---$/, ''));
                doc.moveDown(0.2);
                continue;
              }

              // Bullet points
              if (trimmed.startsWith('* ')) {
                doc.fontSize(8).font('Helvetica').fillColor('#4a5568')
                   .text(`  \u2022  ${trimmed.substring(2)}`, LEFT + 8, doc.y, { width: pageW - 16 });
                continue;
              }

              // Regular text
              if (trimmed) {
                doc.fontSize(8.5).font('Helvetica').fillColor('#4a5568')
                   .text(trimmed, LEFT, doc.y, { width: pageW });
              } else {
                doc.moveDown(0.2);
              }
            }
          }
        }
      }

      // ====== FALLBACK: plain text ======
      else {
        doc.fontSize(8).font('Courier').fillColor('#333333');
        const lines = content.split('\n');
        for (const line of lines) {
          ensureSpace(12);
          doc.text(line, { width: pageW });
        }
      }
    }

    // Footer
    ensureSpace(40);
    doc.moveDown(2);
    drawHR('#cbd5e0');
    doc.fontSize(8).font('Helvetica').fillColor('#a0aec0')
       .text('Generated by Clinic-in-a-Box  |  Simulated security assessment documents for training purposes', { align: 'center' });

    doc.end();
  } catch (error) {
    console.error('Error generating PDF:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to generate PDF' });
    }
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
    const contentTypes = { zap: 'text/html', nessus: 'application/xml', nmap: 'text/markdown' };
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
    
    res.json({
      success: true,
      profile: toCamelCase(result.rows[0])
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