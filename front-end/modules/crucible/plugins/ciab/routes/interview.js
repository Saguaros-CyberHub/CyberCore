/*
 * ============================================================================
 * Interview Routes - AI-Powered Stakeholder Briefing Simulation
 * ============================================================================
 * Supports "all stakeholders" mode where the AI picks the right respondent
 * based on the question context. Uses N8N workflow for AI generation.
 */

const express = require('express');
const router = express.Router();
const { query } = require('../utils/db');
const { authenticateToken } = require('../../../../../src/middleware/auth');
const fs = require('fs');
const path = require('path');

// ============================================================================
// HELPER: Load profile JSON from file
// ============================================================================
function loadProfileFromFile(jsonFilePath) {
  if (!jsonFilePath) throw new Error('No JSON file path provided');

  const possiblePaths = [
    jsonFilePath,
    path.join(__dirname, '..', '..', jsonFilePath.replace(/^\//, '')),
    path.join(__dirname, '..', '..', 'profiles', path.basename(jsonFilePath)),
    path.join(process.cwd(), jsonFilePath.replace(/^\//, '')),
    path.join(process.cwd(), 'profiles', path.basename(jsonFilePath)),
  ];

  for (const filePath of possiblePaths) {
    if (fs.existsSync(filePath)) {
      let jsonData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (Array.isArray(jsonData) && jsonData.length > 0) jsonData = jsonData[0];

      const studentView = jsonData.student_view || jsonData;
      const stakeholdersRaw = studentView.raw?.threats?.stakeholders || studentView.stakeholders || [];
      const org = studentView.raw?.threats?.organization || {};
      const itEnv = studentView.raw?.threats?.it_environment || {};
      const network = studentView.raw?.threats?.network || {};
      const governance = studentView.raw?.threats?.profiles?.governance_and_policy || {};

      return {
        ...studentView,
        quick: {
          ...studentView.quick,
          company_name: org.company_name || studentView.quick?.company_name,
          industry: org.industry || studentView.quick?.industry,
          employees_total: org.employees_total || studentView.quick?.employees_total,
          domain_public: org.domain_public || studentView.quick?.domain_public
        },
        stakeholders: stakeholdersRaw,
        organization: org,
        it_environment: itEnv,
        network: network,
        governance: governance
      };
    }
  }

  throw new Error(`Profile JSON file not found: ${jsonFilePath}`);
}

// ============================================================================
// HELPER: Pick the best stakeholder for a question
// ============================================================================
function pickStakeholder(question, stakeholders, hint) {
  if (!stakeholders || stakeholders.length === 0) return null;

  // If a specific hint was provided, try to match by role keyword
  if (hint && hint !== 'all') {
    const found = stakeholders.find(s =>
      s.role.toLowerCase().includes(hint.toLowerCase()) ||
      s.name.toLowerCase().includes(hint.toLowerCase())
    );
    if (found) return found;
  }

  const lower = question.toLowerCase();

  // Role-keyword mapping — most specific patterns first, broadest last
  const patterns = [
    { keywords: /budget|cost|financ|revenue|expense|investment|roi|funding|insurance|spend|money|dollar/, roles: ['cfo', 'finance', 'controller', 'accounting', 'treasurer'] },
    { keywords: /employee|staff|train|awareness|onboard|terminat|hr|hiring|personnel|workforce|background check|new hire|exit|separation/, roles: ['hr', 'human', 'people', 'talent', 'personnel'] },
    { keywords: /complian|regulat|hipaa|pci|sox|gdpr|nist|ferpa|nerc|cip|audit|policy|policies|governance|legal|privacy|data retention|data classif/, roles: ['compliance', 'legal', 'privacy', 'regulatory', 'governance', 'counsel'] },
    { keywords: /operation|process|workflow|production|supply|warehouse|logistics|manufactur|daily|downtime|business continu|disaster recover/, roles: ['operation', 'coo', 'director', 'warehouse', 'logistics', 'plant', 'facilities'] },
    { keywords: /customer|sales|client|market|growth|business develop|vendor|third.?party|contract/, roles: ['sales', 'marketing', 'business develop', 'account', 'vendor'] },
    { keywords: /server|network|firewall|vpn|cloud|backup|patch|endpoint|antivirus|infrastructure|database|siem|encryption|incident|breach|malware|ransomware|phishing|mfa|password|remote access|vulnerability|scan|monitor|port|dns|dhcp|active directory|domain controller/, roles: ['it', 'ciso', 'technology', 'security', 'information', 'sysadmin', 'network'] },
    { keywords: /strateg|mission|goal|objective|vision|board|leadership|company culture|acquisition|merger|expansion|overview|organization|industry/, roles: ['ceo', 'owner', 'president', 'executive', 'chief executive'] },
  ];

  for (const { keywords, roles } of patterns) {
    if (keywords.test(lower)) {
      const match = stakeholders.find(s =>
        roles.some(r => s.role.toLowerCase().includes(r))
      );
      if (match) return match;
    }
  }

  // Default: rotate through stakeholders based on question length as a simple hash
  // This avoids always defaulting to one person
  const idx = question.length % stakeholders.length;
  return stakeholders[idx];
}

// ============================================================================
// HELPER: Build organization context string for AI
// ============================================================================
function buildOrgContext(studentData) {
  const org = studentData.organization || {};
  const it = studentData.it_environment || {};
  const net = studentData.network || {};
  const gov = studentData.governance || {};
  const quick = studentData.quick || {};

  const parts = [];
  if (quick.company_name) parts.push(`Company: ${quick.company_name}`);
  if (quick.industry) parts.push(`Industry: ${quick.industry}`);
  if (quick.employees_total) parts.push(`Employees: ${quick.employees_total}`);
  if (org.annual_revenue) parts.push(`Revenue: ${org.annual_revenue}`);
  if (org.locations) parts.push(`Locations: ${JSON.stringify(org.locations)}`);
  if (it.servers && it.servers.length) parts.push(`Servers: ${it.servers.map(s => s.name || s.hostname || s).join(', ')}`);
  if (it.endpoint_protection) parts.push(`Endpoint: ${it.endpoint_protection}`);
  if (it.remote_access) parts.push(`Remote access: ${it.remote_access}`);
  if (it.backups) parts.push(`Backups: ${it.backups}`);
  if (net.firewall) parts.push(`Firewall: ${net.firewall}`);
  if (gov.policies_present && gov.policies_present.length) parts.push(`Policies: ${gov.policies_present.join(', ')}`);
  if (gov.policies_missing && gov.policies_missing.length) parts.push(`Missing policies: ${gov.policies_missing.join(', ')}`);

  return parts.join('\n');
}

// ============================================================================
// POST /api/interview/start - Start a new interview session
// ============================================================================
router.post('/start', authenticateToken, async (req, res) => {
  try {
    const { profile_id, stakeholder_id } = req.body;
    const userId = req.user.userId;

    const profileResult = await query(
      'SELECT json_file_path, json_filename, company_name FROM profiles WHERE id = $1',
      [profile_id]
    );
    if (profileResult.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const profile = profileResult.rows[0];
    const jsonPath = profile.json_file_path || profile.json_filename;

    let studentData;
    try {
      studentData = loadProfileFromFile(jsonPath);
    } catch (fileErr) {
      return res.status(500).json({ error: 'Could not load profile data', details: fileErr.message });
    }

    const stakeholders = studentData.stakeholders || [];
    const isAllMode = !stakeholder_id || stakeholder_id === 'all';

    // For "all" mode, use first stakeholder as session anchor but return all
    const anchorStakeholder = isAllMode
      ? (stakeholders[0] || { name: 'Unknown', role: 'Staff' })
      : stakeholders.find(s => (s.id || s.name) === stakeholder_id);

    if (!anchorStakeholder) {
      return res.status(404).json({ error: 'Stakeholder not found' });
    }

    const sessionResult = await query(`
      INSERT INTO interview_sessions
        (user_id, profile_id, stakeholder_id, stakeholder_name, stakeholder_role, transcript)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [
      userId, profile_id,
      isAllMode ? 'all' : (anchorStakeholder.id || anchorStakeholder.name),
      isAllMode ? 'All Stakeholders' : anchorStakeholder.name,
      isAllMode ? 'Group Briefing' : anchorStakeholder.role,
      JSON.stringify([])
    ]);

    res.json({
      success: true,
      session: sessionResult.rows[0],
      stakeholders: stakeholders.map(s => ({
        id: s.id || s.name,
        name: s.name,
        role: s.role,
        department: s.department,
        technical_fluency: s.technical_fluency
      }))
    });

  } catch (error) {
    console.error('[Interview] Error starting interview:', error);
    res.status(500).json({ error: 'Failed to start interview', details: error.message });
  }
});

// ============================================================================
// POST /api/interview/:sessionId/message - Send message in interview
// ============================================================================
router.post('/:sessionId/message', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { message, stakeholder_hint } = req.body;
    const userId = req.user.userId;

    const sessionResult = await query(`
      SELECT s.*, p.json_file_path, p.json_filename, p.company_name
      FROM interview_sessions s
      JOIN profiles p ON s.profile_id = p.id
      WHERE s.id = $1 AND s.user_id = $2 AND s.status = 'active'
    `, [sessionId, userId]);

    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Active interview session not found' });
    }

    const session = sessionResult.rows[0];
    const jsonPath = session.json_file_path || session.json_filename;

    let studentData;
    try {
      studentData = loadProfileFromFile(jsonPath);
    } catch (fileErr) {
      return res.status(500).json({ error: 'Could not load profile data', details: fileErr.message });
    }

    const stakeholders = studentData.stakeholders || [];
    const isAllMode = session.stakeholder_id === 'all';

    // Pick the right stakeholder to respond
    const respondent = isAllMode
      ? pickStakeholder(message, stakeholders, stakeholder_hint)
      : stakeholders.find(s => (s.id || s.name) === session.stakeholder_id) || stakeholders[0];

    if (!respondent) {
      return res.status(404).json({ error: 'No stakeholders available' });
    }

    // Get transcript
    const transcript = typeof session.transcript === 'string'
      ? JSON.parse(session.transcript) : session.transcript || [];

    transcript.push({ role: 'student', message, timestamp: new Date().toISOString() });

    // Generate AI response via N8N or Ollama fallback
    const orgContext = buildOrgContext(studentData);
    const aiResponse = await generateResponse(respondent, stakeholders, orgContext, transcript, message);

    transcript.push({
      role: 'stakeholder',
      message: aiResponse,
      stakeholder_name: respondent.name,
      stakeholder_role: respondent.role,
      timestamp: new Date().toISOString()
    });

    const updateResult = await query(`
      UPDATE interview_sessions
      SET transcript = $1, questions_asked = questions_asked + 1
      WHERE id = $2
      RETURNING *
    `, [JSON.stringify(transcript), sessionId]);

    res.json({
      success: true,
      response: aiResponse,
      stakeholder_name: respondent.name,
      stakeholder_role: respondent.role,
      questions_asked: updateResult.rows[0].questions_asked
    });

  } catch (error) {
    console.error('[Interview] Error processing message:', error);
    res.status(500).json({ error: 'Failed to process message', details: error.message });
  }
});

// ============================================================================
// POST /api/interview/:sessionId/end - End interview session
// ============================================================================
router.post('/:sessionId/end', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const userId = req.user.userId;

    const result = await query(`
      UPDATE interview_sessions
      SET status = 'completed', ended_at = NOW(),
          duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [sessionId, userId]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Interview session not found' });

    res.json({
      success: true,
      session: result.rows[0],
      summary: {
        duration_minutes: Math.round(result.rows[0].duration_seconds / 60),
        questions_asked: result.rows[0].questions_asked
      }
    });
  } catch (error) {
    console.error('[Interview] Error ending interview:', error);
    res.status(500).json({ error: 'Failed to end interview' });
  }
});

// ============================================================================
// GET /api/interview/sessions/:profileId - Get all sessions for a profile
// ============================================================================
router.get('/sessions/:profileId', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;

    const result = await query(`
      SELECT id, stakeholder_id, stakeholder_name, stakeholder_role,
             status, questions_asked, quality_score, started_at, ended_at, duration_seconds
      FROM interview_sessions
      WHERE user_id = $1 AND profile_id = $2
      ORDER BY started_at DESC
    `, [userId, profileId]);

    res.json({ success: true, sessions: result.rows });
  } catch (error) {
    console.error('[Interview] Error fetching sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// ============================================================================
// GET /api/interview/stakeholders/:profileId - Get stakeholders for a profile
// ============================================================================
router.get('/stakeholders/:profileId', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;

    const profileResult = await query(
      'SELECT json_file_path, json_filename FROM profiles WHERE id = $1', [profileId]
    );
    if (profileResult.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const jsonPath = profileResult.rows[0].json_file_path || profileResult.rows[0].json_filename;
    const studentData = loadProfileFromFile(jsonPath);
    const stakeholders = studentData.stakeholders || [];

    res.json({
      success: true,
      stakeholders: stakeholders.map(s => ({
        id: s.id || s.name,
        name: s.name,
        role: s.role,
        department: s.department,
        technical_fluency: s.technical_fluency,
        decision_power: s.decision_power
      }))
    });
  } catch (error) {
    console.error('[Interview] Error fetching stakeholders:', error);
    res.status(500).json({ error: 'Failed to fetch stakeholders' });
  }
});

// ============================================================================
// AI RESPONSE GENERATION - N8N with Ollama fallback
// ============================================================================
async function generateResponse(respondent, allStakeholders, orgContext, transcript, userMessage) {
  const conversationHistory = transcript.slice(-10).map(t => ({
    role: t.role === 'student' ? 'user' : 'assistant',
    content: t.role === 'stakeholder'
      ? `[${t.stakeholder_name || respondent.name}]: ${t.message}`
      : t.message
  }));

  const systemPrompt = buildSystemPrompt(respondent, allStakeholders, orgContext);

  // Try N8N first
  const n8nUrl = `${process.env.N8N_BASE_URL || 'http://localhost:5678'}${process.env.N8N_INTERVIEW_WEBHOOK || '/webhook-test/interview-chat'}`;
  try {
    const n8nResp = await fetch(n8nUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_prompt: systemPrompt,
        messages: conversationHistory,
        user_message: userMessage,
        stakeholder_name: respondent.name,
        stakeholder_role: respondent.role
      }),
      signal: AbortSignal.timeout(30000)
    });

    if (n8nResp.ok) {
      const n8nData = await n8nResp.json();
      const reply = (Array.isArray(n8nData) ? n8nData[0] : n8nData);
      const text = reply.response || reply.output || reply.text || reply.message;
      if (text) {
        return text.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
      }
    }
  } catch (n8nErr) {
    console.log('[Interview] N8N unavailable, trying Ollama fallback:', n8nErr.message);
  }

  // Ollama fallback
  try {
    const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434/api/chat';
    const ollamaResp = await fetch(ollamaUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: process.env.OLLAMA_MODEL || 'llama3.2',
        messages: [{ role: 'system', content: systemPrompt }, ...conversationHistory, { role: 'user', content: userMessage }],
        stream: false,
        options: { temperature: 0.7, num_predict: 100 }
      }),
      signal: AbortSignal.timeout(60000)
    });

    const data = await ollamaResp.json();
    const content = data.message?.content || '';
    return content.replace(/<think>[\s\S]*?<\/think>/g, '').trim() || fallbackResponse(respondent);
  } catch (ollamaErr) {
    console.error('[Interview] Ollama also unavailable:', ollamaErr.message);
    return fallbackResponse(respondent);
  }
}

function buildSystemPrompt(respondent, allStakeholders, orgContext) {
  const otherNames = allStakeholders
    .filter(s => s.name !== respondent.name)
    .map(s => `${s.name} (${s.role})`)
    .join(', ');

  return `/no_think
STRICT OUTPUT RULES — FOLLOW THESE EXACTLY:
- Write 2-3 short casual sentences. NOTHING MORE.
- Do NOT wrap your response in quotation marks.
- Do NOT use bullet points, bold, headers, or lists.
- Cover only ONE topic per response.
- Talk like a real person sitting in a conference room, not like a report.

Good: Yeah we've got most of our stuff on a domain controller and a NAS. The OT side is kind of its own thing though, I'd have to dig into specifics on that.
Good: Honestly that's more of a Linda question, she handles the compliance stuff. I just know we have some policies but I couldn't tell you which ones off the top of my head.
Good: We run Defender on the Windows machines and Sophos on the Macs. Patching is... well, we try to do it monthly but it doesn't always happen on time.
Good: I can jump in on that — we do quarterly Nessus scans but honestly remediation takes longer than it should.

Bad: "Data is classified as Public, Internal, and Confidential. Public includes customer contact info. Internal covers billing data."
Bad: Let me get James on the line.
Bad: Any response longer than 3 sentences.

You are ${respondent.name}, the ${respondent.role}.
Technical fluency: ${respondent.technical_fluency || 'Medium'}. Communication style: ${respondent.communication_style || 'Professional'}.

SETTING: You are all sitting together in a conference room for a group interview. Everyone can hear every question. You do NOT need to call, page, or "get someone on the line" — they are RIGHT HERE at the table. If a question isn't for you, just say something like "James can speak to that better" or "I'll let Linda take that one" — they're sitting right next to you.

People at the table with you: ${otherNames || 'none'}.
${respondent.concerns && respondent.concerns.length ? `Your main concerns: ${respondent.concerns.slice(0, 2).join('; ')}` : ''}
${respondent.likely_pushback && respondent.likely_pushback.length ? `You push back on: ${respondent.likely_pushback.slice(0, 2).join('; ')}` : ''}

Only share details when specifically asked. Make the student ask follow-ups. If you don't know something, say so.

Context (reveal gradually, not all at once):
${orgContext}
${(respondent.information_they_can_provide || []).slice(0, 5).map(i => `- ${i}`).join('\n')}

Things you don't know about: ${(respondent.information_they_lack || []).slice(0, 3).join(', ') || 'details outside your department'}`;
}

function fallbackResponse(respondent) {
  const fallbacks = [
    `That's a good question. Let me think about that from my perspective as ${respondent.role}. Could you be more specific about what you need?`,
    `I appreciate you asking. In my role as ${respondent.role}, I'd say we should discuss this further. What specifically concerns you?`,
    `Hmm, that's something I've been thinking about. As ${respondent.role}, I have some thoughts but I'd need to check with my team first.`,
  ];
  return fallbacks[Math.floor(Math.random() * fallbacks.length)];
}

module.exports = router;
