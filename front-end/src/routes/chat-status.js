/**
 * chat-status.js — Is the global AI assistant usable on this deployment?
 *
 * The chat widget is injected on every page by layout.js. It asks here first
 * and simply doesn't render its launcher when the answer is no — which also
 * drops the "AI Assistant" sidebar entry, because visibleItems() in layout.js
 * filters any item whose onclick opens the chat.
 *
 * TWO INDEPENDENT SWITCHES, deliberately.
 *
 *   AI_ASSISTANT_ENABLED  the deployment's INTENT. Off unless it reads exactly
 *                         "true", matching MAIL_ENABLED in src/utils/mailer.js.
 *                         Default-off so a deployment does not ship a chat
 *                         bubble nobody asked for.
 *   llmClient.isConfigured()  the CAPABILITY. Without a key every send fails
 *                         with a generic "having trouble connecting", so the
 *                         launcher is hidden rather than offered.
 *
 * It must NOT key off ANTHROPIC_API_KEY alone. That same key powers CIAB's
 * profile, interview, policy and vuln-app generation, so unsetting it to hide
 * the assistant would break the rest of Clinic-in-a-Box.
 *
 * Read per-request rather than captured at module load, so a test can flip
 * process.env without require-cache games.
 *
 * Mounted in core (before module/plugin routes load), so it resolves here while
 * `POST /api/chat` still falls through to the CIAB plugin that implements it.
 */

const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const llmClient = require('../utils/llm-client');

/** @returns {boolean} whether this deployment wants the global assistant at all. */
function aiAssistantEnabled() {
  return String(process.env.AI_ASSISTANT_ENABLED || '').toLowerCase() === 'true';
}

// GET /api/chat/status → { enabled }
router.get('/status', authenticateToken, (req, res) => {
  res.json({ enabled: aiAssistantEnabled() && llmClient.isConfigured() });
});

module.exports = router;
// Exported so POST /api/chat (CIAB plugin) can refuse on the same switch — a
// hidden launcher does not stop a curl from spending tokens.
module.exports.aiAssistantEnabled = aiAssistantEnabled;
