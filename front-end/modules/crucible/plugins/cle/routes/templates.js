/**
 * CLE Plugin — Templates Routes
 * Handles VM and vulnerable machine templates available for provisioning
 */

const express = require('express');
const router = express.Router();
const { requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET /api/cle/templates/vm — List available workstation VM templates
 */
router.get('/vm', instructorOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        id          AS template_id,
        os_name     AS name,
        template_key,
        description,
        metadata,
        is_active
      FROM cybercore_template_catalog
      WHERE template_type = 'workstation'
        AND is_active = TRUE
      ORDER BY os_name ASC
    `);

    res.json({ templates: result.rows });
  } catch (error) {
    console.error('[CLE] Get VM templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/cle/templates/vulnerable — List available challenge/lab templates
 */
router.get('/vulnerable', instructorOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(`
      SELECT
        challenge_id  AS template_id,
        name,
        difficulty,
        description
      FROM crucible_challenge
      WHERE status = 'active'
      ORDER BY name ASC
    `);

    res.json({ templates: result.rows });
  } catch (error) {
    console.error('[CLE] Get vulnerable templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
