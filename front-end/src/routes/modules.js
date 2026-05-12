const express = require('express');
const router = express.Router();
const { cybercoreQuery } = require('../utils/cybercore-db');
const { authenticateToken } = require('../middleware/auth');
const moduleLoader = require('../module-loader');

// GET /api/modules — list all active modules grouped by category
router.get('/', async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT key, name, icon, description, entry_url, category, color
       FROM cybercore_module
       WHERE active = TRUE
       ORDER BY display_order, name`
    );

    const modules = result.rows.filter(r => r.category === 'module');
    const plugins = result.rows.filter(r => r.category === 'plugin');

    // Subnav configs from loaded modules (includes nested plugins)
    const subnavs = moduleLoader.getAllSubnavs();

    res.json({ modules, plugins, subnavs });
  } catch (error) {
    console.error('Error fetching modules:', error.message);
    res.status(500).json({ error: 'Failed to fetch modules' });
  }
});

module.exports = router;
