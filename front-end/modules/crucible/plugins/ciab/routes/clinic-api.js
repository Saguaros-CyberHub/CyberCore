/**
 * ============================================================================
 * API ROUTES - Generation, chat, health, and config endpoints
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { query } = require('../utils/db');
const { authenticate, optionalAuth } = require('../../../../../src/middleware/auth');

// ============================================================================
// POST /api/generate - Trigger inline profile generation
// ============================================================================

// Generation now runs inline via /api/profiles/generate (which calls
// ai/profile/index.js). This wrapper forwards for backward compatibility.
const { generateProfile: aiGenerateProfile } = require('../ai/profile');
router.post('/generate', authenticate, async (req, res) => {
  try {
    const { userId, org_name, company_name, ...rest } = req.body || {};
    const profile = await aiGenerateProfile({
      user_id: req.user.userId,
      company_name: org_name || company_name || undefined,
      ...rest
    });
    res.json({ success: true, profile_id: profile.id, profile });
  } catch (err) {
    console.error('[clinic-api /generate]', err.message);
    res.status(err.statusCode || 500).json({ error: 'Generation failed', details: err.message });
  }
});



// ============================================================================
// POST /api/chat - Send message to the AI assistant
// ============================================================================

// Generic clinic chat — runs inline through Claude. Session-aware via the
// sessionId field on the client (we don't persist conversation server-side
// here; client manages history if it wants context across turns).
const llmClient = require('../../../../../src/utils/llm-client');
const CHAT_SYSTEM_PROMPT = `You are an AI assistant embedded in Clinic-in-a-Box, a cybersecurity assessment training platform. Help students with cyber-risk concepts, CIS Controls, NIST CSF, interview techniques, and general security questions. Be concise — 2–4 sentences per response unless the student explicitly asks for depth.`;

router.post('/chat', optionalAuth, async (req, res) => {
  try {
    const { message, sessionId, history } = req.body;
    if (!message) return res.status(400).json({ error: 'Message is required' });

    const priorMessages = Array.isArray(history)
      ? history.slice(-10).map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content || '') }))
      : [];

    const { text } = await llmClient.generate({
      system: llmClient.cachedSystem(CHAT_SYSTEM_PROMPT),
      messages: [...priorMessages, { role: 'user', content: message }],
      max_tokens: 768,
      temperature: 0.7,
      label: `chat:${(sessionId || 'anon').toString().slice(0, 12)}`
    });
    res.json({ success: true, response: (text || '').replace(/<think>[\s\S]*?<\/think>/gi, '').trim() });
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ error: 'Failed to get response', details: error.message });
  }
});

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
