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
 * GET /api/cle/vm-templates — List available VM templates
 */
router.get('/vm', instructorOnly, async (req, res) => {
  try {
    const templatesResult = await cybercoreQuery(`
      SELECT
        template_id,
        name,
        description,
        os_type,
        disk_size,
        memory_mb,
        cpu_cores,
        is_active
      FROM cybercore_vm_template
      WHERE is_active = TRUE
      ORDER BY name ASC
    `);

    res.json({ templates: templatesResult.rows });
  } catch (error) {
    console.error('[CLE] Get VM templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/cle/vulnerable-templates — List available vulnerable machine templates
 */
router.get('/vulnerable', instructorOnly, async (req, res) => {
  try {
    const templatesResult = await cybercoreQuery(`
      SELECT
        template_id,
        name,
        description,
        learning_objective,
        difficulty_level,
        estimated_duration,
        tags,
        is_active
      FROM cybercore_challenge_template
      WHERE is_active = TRUE AND category = 'vulnerable'
      ORDER BY name ASC
    `);

    res.json({ templates: templatesResult.rows });
  } catch (error) {
    console.error('[CLE] Get vulnerable templates error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
