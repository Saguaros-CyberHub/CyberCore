/**
 * ============================================================================
 * API ROUTES - N8N Integration & Other Endpoints
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { query } = require('../utils/db');
const { authenticate, optionalAuth } = require('../../../../../src/middleware/auth');

// ============================================================================
// POST /api/generate - Trigger profile generation via N8N
// ============================================================================

router.post('/generate', authenticate, async (req, res) => {
  try {
    const config = {
      ...req.body,
      user_id: req.user.userId, // ✅ UUID already trusted
    };
	config.user_id = req.user.userId;   // UUID
	delete config.userId;   

    const n8nUrl =
      `${process.env.N8N_BASE_URL}${process.env.N8N_GENERATE_WEBHOOK}`;

    const response = await fetch(n8nUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(config),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`N8N returned ${response.status}: ${text}`);
    }

    res.json(await response.json());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Generation failed' });
  }
});



// ============================================================================
// POST /api/chat - Send message to AI assistant via N8N
// ============================================================================

router.post('/chat', optionalAuth, async (req, res) => {
  try {
    const { message, sessionId } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const n8nUrl = `${process.env.N8N_BASE_URL || 'http://localhost:5678'}${process.env.N8N_CHAT_WEBHOOK || '/webhook/0ff455fa-3bda-43db-a352-ba55517ad2b8/chat'}`;

    const response = await fetch(n8nUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'sendMessage',
        sessionId: sessionId || req.user?.userId || 'anonymous',
        chatInput: message
      })
    });

    if (!response.ok) {
      throw new Error(`N8N returned ${response.status}`);
    }

    const result = await response.json();

    // Clean up response (remove thinking tags)
    let reply = result.output || result.text || result.response || '';
    reply = reply.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();

    res.json({ 
      success: true,
      response: reply 
    });
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ 
      error: 'Failed to get response',
      details: error.message 
    });
  }
});

// ============================================================================
// POST /api/webhook/profile-complete - Callback from N8N when profile is done
// ============================================================================

router.post('/webhook/profile-complete', async (req, res) => {
  try {
    const {
      userId,
      runId,
      clientType,
      clientTypeName,
      industry,
      difficulty,
      companyName,
      hqCity,
      employeeCount,
      stakeholderCount,
      endpointCount,
      complianceFrameworks,
      keyRisks,
      criticalSystems,
      maturityLevel,
      deliveryMode,
      htmlFilename,
      jsonFilename,
      htmlFilePath,
      jsonFilePath,
      status = 'completed',
      intake_v12,  // Phase 0: optional canonical intake payload from n8n. If absent, we synthesize one.
    } = req.body;

    // Update or insert profile
    const result = await query(
      `INSERT INTO profiles (
        user_id, run_id, client_type, client_type_name, industry, difficulty,
        company_name, hq_city, employee_count, stakeholder_count, endpoint_count,
        compliance_frameworks, key_risks, critical_systems, maturity_level, delivery_mode,
        html_filename, json_filename, html_file_path, json_file_path,
        generation_status, created_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW()
      )
      ON CONFLICT (run_id) DO UPDATE SET
        generation_status = EXCLUDED.generation_status,
        html_filename = EXCLUDED.html_filename,
        json_filename = EXCLUDED.json_filename,
        html_file_path = EXCLUDED.html_file_path,
        json_file_path = EXCLUDED.json_file_path,
        updated_at = NOW()
      RETURNING id`,
      [
        userId, runId, clientType, clientTypeName, industry, difficulty,
        companyName, hqCity, employeeCount, stakeholderCount, endpointCount,
        JSON.stringify(complianceFrameworks || []),
        JSON.stringify(keyRisks || []),
        JSON.stringify(criticalSystems || []),
        maturityLevel, deliveryMode,
        htmlFilename, jsonFilename, htmlFilePath, jsonFilePath,
        status
      ]
    );
    const profileId = result.rows[0]?.id;

    // Phase 0: persist a v1.2 intake row alongside the profile so the unified
    // form/dashboard can render against it from first load. If n8n shipped a
    // structured `intake_v12` payload, prefer it; otherwise synthesize one from
    // the profile metadata. Either way, the student can edit/extend through the
    // unified form at /ciab/intake?profileId=…
    if (profileId) {
      try {
        const payload = intake_v12 && intake_v12.sections
          ? intake_v12
          : synthesizeIntakeFromProfile({
              companyName, industry, employeeCount, endpointCount,
              complianceFrameworks: complianceFrameworks || [],
            });
        await query(
          `INSERT INTO intakes
             (user_id, profile_id, source, schema_version, cover_name, payload,
              completion_percentage, status)
           VALUES ($1, $2, 'ai_simulated', $3, $4, $5::jsonb, $6, 'in_progress')
           ON CONFLICT (profile_id) WHERE profile_id IS NOT NULL DO NOTHING`,
          [
            userId, profileId,
            payload.schema_version || '1.2',
            payload.cover_name || companyName || 'Unknown Organization',
            JSON.stringify(payload),
            // Synthesized intakes are partial — let the student fill in the rest.
            intake_v12 ? 30 : 15,
          ]
        );
      } catch (intakeErr) {
        // Don't fail the whole webhook if the intake insert hiccups; profile is the load-bearing artifact.
        console.warn('[profile-complete] intake row insert skipped:', intakeErr.message);
      }
    }

    res.json({
      success: true,
      profileId,
      message: 'Profile saved successfully'
    });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

/**
 * Build a minimal v1.2 intake from profile metadata. Used when n8n hasn't yet
 * been updated to emit a structured `intake_v12` block. The student fills in
 * the rest via the unified intake form.
 */
function synthesizeIntakeFromProfile({ companyName, industry, employeeCount, endpointCount, complianceFrameworks }) {
  const employees_band = bandFromCount(employeeCount);
  return {
    schema_version: '1.2',
    cover_name: companyName || 'Unknown Organization',
    sections: {
      company: {
        cover_name: companyName || 'Unknown Organization',
        industry: industry || null,
        employees_band,
        frameworks: Array.isArray(complianceFrameworks) ? complianceFrameworks : [],
      },
      network: { endpoint_count: Number(endpointCount) || 0 },
      wireless: {}, endpoint: {}, email_web: {}, access: {}, data: {}, vuln_audit: {},
      ig1: {},
      notes: { free_text: '' },
    },
  };
}

function bandFromCount(n) {
  const x = Number(n) || 0;
  if (x === 0)        return null;
  if (x <= 10)        return '1-10';
  if (x <= 50)        return '11-50';
  if (x <= 250)       return '51-250';
  if (x <= 1000)      return '251-1000';
  return '1000+';
}

// ============================================================================
// GET /api/health - Health check endpoint
// ============================================================================

router.get('/health', async (req, res) => {
  try {
    // Check database connection
    await query('SELECT 1');
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        database: 'connected',
        server: 'running'
      }
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// ============================================================================
// GET /api/config - Get client configuration (non-sensitive)
// ============================================================================

router.get('/config', (req, res) => {
  res.json({
    clientTypes: [
      { value: 'SMB', label: 'Small-Medium Business', hours: 8 },
      { value: 'NonProfit', label: 'Non-Profit Organization', hours: 6 },
      { value: 'Utility_IT_OT', label: 'Utility Company (IT/OT)', hours: 12 },
      { value: 'K12', label: 'K-12 School District', hours: 8 }
    ],
    difficulties: [
      { value: 'beginner', label: 'Beginner' },
      { value: 'intermediate', label: 'Intermediate' },
      { value: 'advanced', label: 'Advanced' }
    ],
    maturityLevels: ['Low', 'Intermediate', 'High'],
    deliveryModes: ['On-Premises', 'Hybrid', 'Cloud']
  });
});

module.exports = router;
