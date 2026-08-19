/**
 * chat-status.js — Is the global AI assistant usable on this deployment?
 *
 * The chat widget is injected on every page by layout.js, but the LLM it talks
 * to needs ANTHROPIC_API_KEY. Without it `POST /api/chat` 500s and the user just
 * sees "having trouble connecting" forever. The widget asks here first and
 * simply doesn't render its launcher when the answer is no.
 *
 * Mounted in core (before module/plugin routes load), so it resolves here while
 * `POST /api/chat` still falls through to the CIAB plugin that implements it.
 */

const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const llmClient = require('../utils/llm-client');

// GET /api/chat/status → { enabled }
router.get('/status', authenticateToken, (req, res) => {
  res.json({ enabled: llmClient.isConfigured() });
});

module.exports = router;
