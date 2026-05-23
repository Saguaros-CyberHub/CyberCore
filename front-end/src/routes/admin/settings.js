/**
 * ============================================================================
 * Settings & User Management Routes
 * Site config, module/plugin toggles, and user CRUD.
 * All routes mounted at /api/admin/* via the admin aggregator.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { query } = require('../../utils/db');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { logActivity } = require('../../middleware/activity-logger');

const adminOnly = requireRole('admin');


// ============================================================================
// USER LIST
// ============================================================================

router.get('/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    // Get users from cybercore_user (single source of truth)
    const usersResult = await cybercoreQuery(
      `SELECT user_id AS id, email, first_name, last_name, role, organization,
              active AS is_active, last_auth_at AS last_login, created_at
       FROM cybercore_user
       ORDER BY created_at DESC`
    );

    // Get deployed groups from clinic_db (if available) to enrich user data
    let groups = [];
    try {
      const groupsResult = await query(
        `SELECT id, group_name, config FROM deployed_groups`
      );
      groups = groupsResult.rows;
    } catch (e) { /* clinic_db may not be available if CIAB plugin not loaded */ }

    // Merge group info into users
    const users = usersResult.rows.map(u => {
      const group = groups.find(g => {
        const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
        const allMembers = [...(cfg.students || []), ...(cfg.instructors || [])];
        return allMembers.some(m => m.id === u.id);
      });
      return {
        ...u,
        group_name: group?.group_name || null,
        group_id: group?.id || null
      };
    });

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// SETTINGS
// ============================================================================

router.get('/settings', authenticateToken, adminOnly, async (req, res) => {
  try {
    let siteName = 'CyberHub';
    let siteLogoUrl = null;
    let siteFaviconUrl = null;
    let siteDescription = null;

    try {
      const result = await cybercoreQuery('SELECT key, value FROM cybercore_site_settings');
      result.rows.forEach(row => {
        if (row.key === 'site_name') siteName = row.value;
        if (row.key === 'site_logo_url') siteLogoUrl = row.value;
        if (row.key === 'site_favicon_url') siteFaviconUrl = row.value;
        if (row.key === 'site_description') siteDescription = row.value;
      });
    } catch (err) {
      console.warn('[Settings] Could not fetch site settings:', err.message);
    }

    let modules = [];
    try {
      const result = await cybercoreQuery(
        'SELECT * FROM cybercore_module WHERE parent_module IS NULL ORDER BY display_order ASC, key ASC'
      );

      const moduleMap = {};
      result.rows.forEach(row => {
        moduleMap[row.key] = {
          key: row.key,
          name: row.name,
          description: row.description,
          enabled: row.active,
          plugins: []
        };
        modules.push(moduleMap[row.key]);
      });

      const pluginResult = await cybercoreQuery(
        'SELECT * FROM cybercore_module WHERE parent_module IS NOT NULL ORDER BY display_order ASC, key ASC'
      );
      pluginResult.rows.forEach(row => {
        const parent = moduleMap[row.parent_module];
        if (parent) {
          parent.plugins.push({
            key: row.key,
            name: row.name,
            description: row.description,
            enabled: row.active
          });
        }
      });
    } catch (err) {
      console.warn('[Settings] Could not fetch cybercore_module:', err.message);
    }

    res.json({ site_name: siteName, site_logo_url: siteLogoUrl, site_favicon_url: siteFaviconUrl, site_description: siteDescription, modules });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/settings/site-config', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { site_name, site_logo_url, site_favicon_url, site_description } = req.body;

    if (!site_name || typeof site_name !== 'string' || site_name.trim().length === 0) {
      return res.status(400).json({ error: 'site_name must be a non-empty string' });
    }

    // Ensure table exists
    try {
      await cybercoreQuery(`
        CREATE TABLE IF NOT EXISTS cybercore_site_settings (
          key VARCHAR(255) PRIMARY KEY,
          value TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
    } catch (err) {
      console.warn('[Settings] Could not create table:', err.message);
    }

    const updates = [
      { key: 'site_name', value: site_name.trim() },
      { key: 'site_logo_url', value: site_logo_url || null },
      { key: 'site_favicon_url', value: site_favicon_url || null },
      { key: 'site_description', value: site_description || null }
    ];

    for (const setting of updates) {
      try {
        const result = await cybercoreQuery(
          'UPDATE cybercore_site_settings SET value = $1, updated_at = NOW() WHERE key = $2 RETURNING key',
          [setting.value, setting.key]
        );

        if (result.rows.length === 0) {
          await cybercoreQuery(
            'INSERT INTO cybercore_site_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()',
            [setting.key, setting.value]
          );
        }
      } catch (err) {
        console.warn(`[Settings] Could not update ${setting.key}:`, err.message);
      }
    }

    logActivity(req, 'settings_update', 'site_config', null, { site_name, logo_url: site_logo_url, favicon_url: site_favicon_url });

    res.json({
      success: true,
      site_name: site_name.trim(),
      site_logo_url: site_logo_url || null,
      site_favicon_url: site_favicon_url || null,
      site_description: site_description || null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Public endpoint — no auth required
router.get('/site-config', async (req, res) => {
  try {
    let siteConfig = {
      site_name: 'CyberHub',
      site_logo_url: null,
      site_favicon_url: null,
      site_description: null
    };

    try {
      const result = await cybercoreQuery('SELECT key, value FROM cybercore_site_settings');
      result.rows.forEach(row => {
        if (row.key === 'site_name') siteConfig.site_name = row.value;
        if (row.key === 'site_logo_url') siteConfig.site_logo_url = row.value;
        if (row.key === 'site_favicon_url') siteConfig.site_favicon_url = row.value;
        if (row.key === 'site_description') siteConfig.site_description = row.value;
      });
    } catch (err) {
      console.warn('[Site Config] Could not fetch settings:', err.message);
    }

    res.json(siteConfig);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/settings/modules', authenticateToken, adminOnly, async (req, res) => {
  try {
    let modules = [];

    try {
      const result = await cybercoreQuery(
        'SELECT * FROM cybercore_module WHERE parent_module IS NULL ORDER BY display_order ASC, key ASC'
      );

      const moduleMap = {};
      result.rows.forEach(row => {
        moduleMap[row.key] = {
          key: row.key,
          name: row.name,
          description: row.description,
          enabled: row.active,
          plugins: []
        };
        modules.push(moduleMap[row.key]);
      });

      const pluginResult = await cybercoreQuery(
        'SELECT * FROM cybercore_module WHERE parent_module IS NOT NULL ORDER BY display_order ASC, key ASC'
      );
      pluginResult.rows.forEach(row => {
        if (moduleMap[row.parent_module]) {
          moduleMap[row.parent_module].plugins.push({
            key: row.key,
            name: row.name,
            description: row.description,
            enabled: row.active
          });
        }
      });
    } catch (err) {
      console.warn('[Settings] Could not fetch cybercore_module:', err.message);
    }

    res.json({ modules });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/settings/modules', authenticateToken, adminOnly, async (req, res) => {
  try {
    let { modules, plugins } = req.body;

    if (!Array.isArray(modules)) modules = [];
    if (!Array.isArray(plugins)) plugins = [];

    for (const mod of modules) {
      if (!mod.key) continue;
      try {
        await cybercoreQuery(
          'UPDATE cybercore_module SET active = $1 WHERE key = $2 AND parent_module IS NULL',
          [mod.enabled === true, mod.key]
        );
      } catch (err) {
        console.warn(`[Settings] Failed to update module ${mod.key}:`, err.message);
      }
    }

    for (const plugin of plugins) {
      if (!plugin.key) continue;
      try {
        await cybercoreQuery(
          'UPDATE cybercore_module SET active = $1 WHERE key = $2 AND parent_module IS NOT NULL',
          [plugin.enabled === true, plugin.key]
        );
      } catch (err) {
        console.warn(`[Settings] Failed to update plugin ${plugin.key}:`, err.message);
      }
    }

    logActivity(req, 'settings_update', 'cybercore_module', null,
      { modules_updated: modules.length, plugins_updated: plugins.length });

    res.json({
      success: true,
      modules_updated: modules.length,
      plugins_updated: plugins.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// USER MANAGEMENT
// ============================================================================

router.post('/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { username, email, firstName, lastName, organization, role, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'username, email, and password are required' });
    }

    if (!['user', 'student', 'instructor', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const existingUser = await cybercoreQuery(
      'SELECT user_id FROM cybercore_user WHERE LOWER(username) = LOWER($1)',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'User with this username already exists' });
    }

    const existingEmail = await cybercoreQuery(
      'SELECT user_id FROM cybercore_user WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    if (existingEmail.rows.length > 0) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const passwordHash = bcrypt.hashSync(password, 10);

    const result = await cybercoreQuery(
      `INSERT INTO cybercore_user
       (username, email, first_name, last_name, organization, role, password_hash, password_alg, status, active, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'bcrypt', 'active', TRUE, NOW(), NOW())
       RETURNING user_id, username, email, first_name, last_name, role`,
      [username, email, firstName || null, lastName || null, organization || 'Independent', role, passwordHash]
    );

    const newUser = result.rows[0];

    logActivity(req, 'user_created', 'cybercore_user', newUser.user_id, {
      username: newUser.username,
      email: newUser.email,
      role: newUser.role
    });

    res.status(201).json({
      success: true,
      user: newUser,
      message: `User "${username}" created successfully`
    });
  } catch (error) {
    console.error('[Users] Create error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
