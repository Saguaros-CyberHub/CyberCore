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
const { generatePassword } = require('../../utils/password-generator');

const adminOnly = requireRole('admin');

const VALID_ROLES = ['user', 'student', 'instructor', 'admin'];

// Derive a login username from an email local-part: lowercase, keep only safe
// characters. Caller is responsible for de-duplicating against existing names.
function deriveUsername(email) {
  const local = String(email || '').split('@')[0] || '';
  const base = local.toLowerCase().replace(/[^a-z0-9._-]/g, '');
  return base || 'user';
}


// ============================================================================
// USER LIST
// ============================================================================

router.get('/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    // Get users from cybercore_user (single source of truth)
    const usersResult = await cybercoreQuery(
      `SELECT user_id AS id, email, first_name, last_name, role, organization,
              active AS is_active, last_auth_at AS last_login, created_at, mfa_enabled
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
    let mfaRequiredScope = 'privileged';

    try {
      const result = await cybercoreQuery('SELECT key, value FROM cybercore_site_settings');
      result.rows.forEach(row => {
        if (row.key === 'site_name') siteName = row.value;
        if (row.key === 'site_logo_url') siteLogoUrl = row.value;
        if (row.key === 'site_favicon_url') siteFaviconUrl = row.value;
        if (row.key === 'site_description') siteDescription = row.value;
        if (row.key === 'mfa_required_scope') mfaRequiredScope = row.value === 'all' ? 'all' : 'privileged';
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

    res.json({ site_name: siteName, site_logo_url: siteLogoUrl, site_favicon_url: siteFaviconUrl, site_description: siteDescription, mfa_required_scope: mfaRequiredScope, modules });
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


// ============================================================================
// USER EDITING
// ----------------------------------------------------------------------------
// What an admin may change on an existing account, and what they may not.
//
// Everything a user OWNS — lanes, VM allocations, CLE courses, badges — is
// keyed by cybercore_user.user_id, so every field below is safe to edit as far
// as ownership goes. The one exception is `email`, which is not just a contact
// field on this system: it IS the Guacamole account name. Lanes record it as
// config.guac_user, guac-sessions.js joins sessions back to the user with
// `cybercore_user.email = vm_instance.metadata->>'guac_user'`, and the deployed
// group configs in clinic_db list members by email. Rename a user who holds any
// of that and their consoles keep pointing at a Guacamole account that no longer
// matches them — the machine still runs, they just can't reach it. So an email
// change is gated on the account holding no live console-bearing resources.
//
// Username is safe: login accepts `email = $1 OR username = $1`, and nothing
// else in the schema references it.
// ============================================================================

// Fields an admin may PATCH, mapped to their cybercore_user column.
const EDITABLE_USER_FIELDS = {
  first_name:   'first_name',
  last_name:    'last_name',
  organization: 'organization',
  username:     'username',
  email:        'email',
  role:         'role',
  active:       'active',
};

// Login names: the local-part character set POST /users already accepts via
// deriveUsername, so an edited account stays typeable at the login prompt.
const USERNAME_RE = /^[a-z0-9._-]+$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Count the resources that would be orphaned by an email change. Lanes and VM
 * allocations both carry the Guacamole identity; a non-zero count is what makes
 * a rename unsafe.
 *
 * CLE courses are deliberately NOT counted here: they live in the plugin's own
 * database behind a pool this route has no handle on, and they key off user_id
 * anyway, so a rename cannot orphan them.
 */
async function getUserOwnership(userId) {
  const res = await cybercoreQuery(
    `SELECT
       (SELECT COUNT(*) FROM cybercore_lane
         WHERE user_id = $1 AND status <> 'deleted')                    AS lanes,
       (SELECT COUNT(*) FROM cybercore_allocation a
          JOIN cybercore_resource r ON r.resource_id = a.resource_id
         WHERE a.user_id = $1 AND r.status <> 'retired')                AS allocations`,
    [userId]
  );
  const row = res.rows[0] || {};
  const lanes = Number(row.lanes) || 0;
  const allocations = Number(row.allocations) || 0;
  return { lanes, allocations, guac_linked: lanes + allocations };
}

/**
 * GET /api/admin/users/:id — one user plus what they own, so the edit form can
 * explain up front why the email field is locked instead of failing the save.
 */
router.get('/users/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT user_id AS id, username, email, first_name, last_name, organization,
              role, active AS is_active, status, mfa_enabled, auth_provider,
              created_at, updated_at, last_auth_at AS last_login
         FROM cybercore_user WHERE user_id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = result.rows[0];
    const ownership = await getUserOwnership(user.id);
    res.json({
      user,
      ownership,
      // Why the form should disable the email input, in the form's own words.
      email_locked_reason: ownership.guac_linked > 0
        ? `This account holds ${ownership.lanes} lane(s) and ${ownership.allocations} VM allocation(s) whose `
          + 'remote consoles are tied to the current email address. Tear those down first to change it.'
        : null,
    });
  } catch (error) {
    console.error('[Users] Get user error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * PATCH /api/admin/users/:id — edit an existing account.
 *
 * Only the keys present in the body are touched, so the form can send a partial
 * update without racing another admin's edit of a different field.
 */
router.patch('/users/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    const current = await cybercoreQuery(
      `SELECT user_id, username, email, first_name, last_name, organization, role, active, status
         FROM cybercore_user WHERE user_id = $1`,
      [id]
    );
    if (current.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = current.rows[0];

    // ── Collect and validate just the fields that were actually sent ────────
    const updates = {};
    const warnings = [];

    for (const field of Object.keys(EDITABLE_USER_FIELDS)) {
      if (!Object.prototype.hasOwnProperty.call(req.body, field)) continue;
      const raw = req.body[field];

      if (field === 'active') {
        if (typeof raw !== 'boolean') return res.status(400).json({ error: 'active must be true or false' });
        updates.active = raw;
        continue;
      }
      if (field === 'role') {
        if (!VALID_ROLES.includes(raw)) {
          return res.status(400).json({ error: `role must be one of: ${VALID_ROLES.join(', ')}` });
        }
        updates.role = raw;
        continue;
      }

      const value = raw === null ? null : String(raw).trim();

      if (field === 'username') {
        if (!value) return res.status(400).json({ error: 'username cannot be empty' });
        if (!USERNAME_RE.test(value)) {
          return res.status(400).json({ error: 'username may only contain letters, numbers, dot, underscore and hyphen' });
        }
        updates.username = value;
        continue;
      }
      if (field === 'email') {
        if (!value) return res.status(400).json({ error: 'email cannot be empty' });
        if (!EMAIL_RE.test(value)) return res.status(400).json({ error: 'email is not a valid address' });
        updates.email = value;
        continue;
      }
      // Free-text profile fields. An emptied optional field becomes NULL rather
      // than '' so it reads as "unset" everywhere, the way POST /users stores it.
      updates[field] = value || null;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No editable fields supplied' });
    }

    // ── Guards that depend on the CHANGE, not just the value ────────────────

    // The last admin must not be able to lock everyone out — of either their
    // role or their login. Checked before uniqueness so the message is the
    // useful one when an admin edits their own account.
    const losingAdmin = (updates.role !== undefined && user.role === 'admin' && updates.role !== 'admin')
                     || (updates.active === false && user.role === 'admin');
    if (losingAdmin) {
      const admins = await cybercoreQuery(
        `SELECT COUNT(*)::int AS n FROM cybercore_user
          WHERE role = 'admin' AND active = TRUE AND status = 'active' AND user_id <> $1`,
        [id]
      );
      if (admins.rows[0].n === 0) {
        return res.status(409).json({
          error: 'This is the last active admin — promote another admin before changing this one',
        });
      }
    }

    if (updates.username !== undefined && updates.username.toLowerCase() !== String(user.username).toLowerCase()) {
      const dupe = await cybercoreQuery(
        'SELECT user_id FROM cybercore_user WHERE LOWER(username) = LOWER($1) AND user_id <> $2',
        [updates.username, id]
      );
      if (dupe.rows.length > 0) return res.status(409).json({ error: 'That username is already taken' });
    }

    if (updates.email !== undefined && updates.email.toLowerCase() !== String(user.email).toLowerCase()) {
      const ownership = await getUserOwnership(id);
      if (ownership.guac_linked > 0) {
        return res.status(409).json({
          error: `Cannot change the email of an account that owns ${ownership.lanes} lane(s) and `
               + `${ownership.allocations} VM allocation(s): their remote consoles authenticate against `
               + 'the current address. Tear those down first, then rename.',
          ownership,
        });
      }
      const dupe = await cybercoreQuery(
        'SELECT user_id FROM cybercore_user WHERE LOWER(email) = LOWER($1) AND user_id <> $2',
        [updates.email, id]
      );
      if (dupe.rows.length > 0) return res.status(409).json({ error: 'That email is already in use' });

      // Their old Guacamole account keeps the old name; the next login mints a
      // fresh one under the new address. Harmless, but it leaves a stray account
      // an admin would otherwise have to notice on their own.
      warnings.push(
        `Guacamole still has an account named "${user.email}" — delete it from this page if it is no longer needed.`
      );
    }

    if (updates.role !== undefined && updates.role !== user.role
        && ['instructor', 'admin'].includes(user.role) && !['instructor', 'admin'].includes(updates.role)) {
      warnings.push(
        `${user.email} loses instructor access — any CLE courses they own stay theirs but become unreachable `
        + 'until their role is restored or the courses are reassigned.'
      );
    }

    // ── Apply ───────────────────────────────────────────────────────────────
    const sets = [];
    const values = [];
    for (const [field, column] of Object.entries(EDITABLE_USER_FIELDS)) {
      if (updates[field] === undefined) continue;
      values.push(updates[field]);
      sets.push(`${column} = $${values.length}`);
    }
    // Login requires active = TRUE **and** status = 'active' (see routes/auth.js),
    // so flipping one without the other would leave a re-enabled user still
    // locked out. Same idiom as the group enable/disable path in groups.js.
    if (updates.active !== undefined) {
      values.push(updates.active ? 'active' : 'inactive');
      sets.push(`status = $${values.length}`);
    }
    sets.push('updated_at = NOW()');
    values.push(id);

    const result = await cybercoreQuery(
      `UPDATE cybercore_user SET ${sets.join(', ')} WHERE user_id = $${values.length}
       RETURNING user_id AS id, username, email, first_name, last_name, organization,
                 role, active AS is_active, status, mfa_enabled`,
      values
    );

    // Log the before/after of only what moved, so the activity log stays legible.
    const changed = {};
    for (const field of Object.keys(updates)) {
      if (String(user[field]) !== String(updates[field])) {
        changed[field] = { from: user[field], to: updates[field] };
      }
    }
    logActivity(req, 'user_updated', 'cybercore_user', id, { email: user.email, changed });

    res.json({
      success: true,
      user: result.rows[0],
      ...(warnings.length ? { warnings } : {}),
      message: `Updated ${result.rows[0].email}`,
    });
  } catch (error) {
    console.error('[Users] Update error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// BATCH USER CREATION
// ----------------------------------------------------------------------------
// Create many users in one request (e.g. a roster pasted by an instructor).
// Each row is processed independently: a bad/duplicate row is reported in
// `failed` without aborting the rest. Auto-generates a username from the email
// and a random password when one isn't supplied — generated passwords are
// returned once so the admin can distribute them.
// ============================================================================

router.post('/users/batch', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { users, defaults } = req.body;

    if (!Array.isArray(users) || users.length === 0) {
      return res.status(400).json({ error: 'users must be a non-empty array' });
    }
    if (users.length > 500) {
      return res.status(400).json({ error: 'batch is limited to 500 users at a time' });
    }

    const defaultRole = (defaults && defaults.role) || 'student';
    const defaultOrg = (defaults && String(defaults.organization || '').trim()) || 'Independent';
    if (!VALID_ROLES.includes(defaultRole)) {
      return res.status(400).json({ error: `Invalid default role: ${defaultRole}` });
    }

    // Preload existing usernames/emails so we can de-dupe in memory (and across
    // rows within this same batch) without a query per row.
    const existing = await cybercoreQuery('SELECT LOWER(username) AS u, LOWER(email) AS e FROM cybercore_user');
    const usedUsernames = new Set(existing.rows.map(r => r.u));
    const usedEmails = new Set(existing.rows.map(r => r.e));

    const created = [];
    const failed = [];

    for (let i = 0; i < users.length; i++) {
      const row = users[i] || {};
      const lineNo = row.line || (i + 1);
      const email = String(row.email || '').trim();

      try {
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
          throw new Error('valid email is required');
        }
        const emailLc = email.toLowerCase();
        if (usedEmails.has(emailLc)) throw new Error('email already exists');

        const role = row.role ? String(row.role).toLowerCase() : defaultRole;
        if (!VALID_ROLES.includes(role)) throw new Error(`invalid role "${role}"`);

        const organization = (row.organization && String(row.organization).trim()) || defaultOrg;
        const firstName = row.firstName ? String(row.firstName).trim() : null;
        const lastName = row.lastName ? String(row.lastName).trim() : null;

        // Username: caller-supplied or derived from email, then made unique.
        let username = (row.username && String(row.username).trim().toLowerCase()) || deriveUsername(email);
        if (usedUsernames.has(username)) {
          let n = 2;
          while (usedUsernames.has(`${username}${n}`)) n++;
          username = `${username}${n}`;
        }

        const providedPassword = row.password ? String(row.password) : null;
        const password = providedPassword || generatePassword();
        const passwordHash = bcrypt.hashSync(password, 10);

        const result = await cybercoreQuery(
          `INSERT INTO cybercore_user
           (username, email, first_name, last_name, organization, role, password_hash, password_alg, status, active, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'bcrypt', 'active', TRUE, NOW(), NOW())
           RETURNING user_id, username, email, role`,
          [username, email, firstName, lastName, organization, role, passwordHash]
        );

        usedUsernames.add(username);
        usedEmails.add(emailLc);

        const u = result.rows[0];
        created.push({
          user_id: u.user_id,
          username: u.username,
          email: u.email,
          role: u.role,
          // Only surface auto-generated passwords; if the admin supplied one
          // they already have it and we avoid echoing it back.
          generated_password: providedPassword ? null : password,
        });
      } catch (e) {
        failed.push({ line: lineNo, email: email || '(blank)', error: e.message });
      }
    }

    logActivity(req, 'users_batch_created', 'cybercore_user', null, {
      total: users.length, created: created.length, failed: failed.length,
    });

    res.json({
      summary: { total: users.length, created: created.length, failed: failed.length },
      created,
      failed,
    });
  } catch (error) {
    console.error('[Users] Batch create error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// MFA ENFORCEMENT
// ============================================================================

// PATCH /api/admin/settings/mfa — set who must use MFA.
//   scope: 'privileged' (admins + instructors, default) | 'all'
router.patch('/settings/mfa', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { mfa_required_scope } = req.body;
    if (!['privileged', 'all'].includes(mfa_required_scope)) {
      return res.status(400).json({ error: "mfa_required_scope must be 'privileged' or 'all'" });
    }

    await cybercoreQuery(`
      CREATE TABLE IF NOT EXISTS cybercore_site_settings (
        key VARCHAR(255) PRIMARY KEY,
        value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await cybercoreQuery(
      `INSERT INTO cybercore_site_settings (key, value) VALUES ('mfa_required_scope', $1)
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
      [mfa_required_scope]
    );

    logActivity(req, 'settings_update', 'mfa_required_scope', null, { mfa_required_scope });
    res.json({ success: true, mfa_required_scope });
  } catch (error) {
    console.error('[Settings] MFA scope update error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// ADMIN PASSWORD RESET
// ----------------------------------------------------------------------------
// Sets a user's CyberHub login password without knowing the old one — the
// help-desk counterpart to PUT /api/auth/password, which requires the current
// password and so is useless when the user has forgotten it.
//
// This resets the PLATFORM login only. A user's Guacamole password is a
// separate credential (see PUT /api/admin/guac/users/:name/password); the two
// are deliberately not chained, because rewriting the Guac password invalidates
// the stored copy their existing lane consoles authenticate with.
//
// KNOWN LIMITATION: sessions are stateless JWTs (middleware/auth.js verifies the
// signature and never re-reads the row), so a reset does NOT end sessions the
// user — or an attacker — already holds. Those stay valid until the token
// expires, JWT_EXPIRES_IN, default 7 days. Callers are told so explicitly rather
// than being left to assume a reset locks anyone out.
// ============================================================================

// Same floor as the self-service change at PUT /api/auth/password. An admin
// should not be able to set a password weaker than the user could set for
// themselves; generatePassword()'s output always clears it.
const PASSWORD_MIN_LEN = 8;
const PASSWORD_COMPLEXITY_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/;

router.post('/users/:id/password', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const supplied = typeof req.body?.password === 'string' ? req.body.password : '';

    const found = await cybercoreQuery(
      'SELECT user_id, email, username, auth_provider FROM cybercore_user WHERE user_id = $1',
      [id]
    );
    if (found.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = found.rows[0];

    // A federated account authenticates at the identity provider; a local hash
    // would either do nothing or quietly become a second way in that bypasses
    // SSO. Neither is what an admin clicking "reset password" means.
    if (user.auth_provider && user.auth_provider !== 'local') {
      return res.status(409).json({
        error: `${user.email} signs in through ${user.auth_provider} — reset their password there instead.`,
      });
    }

    // Blank means "generate one for me", which is how the batch-create path
    // already hands out credentials. Returned once, in this response only.
    const generated = supplied ? null : generatePassword();
    const password = supplied || generated;

    if (supplied) {
      if (supplied.length < PASSWORD_MIN_LEN) {
        return res.status(400).json({ error: `Password must be at least ${PASSWORD_MIN_LEN} characters` });
      }
      if (!PASSWORD_COMPLEXITY_RE.test(supplied)) {
        return res.status(400).json({ error: 'Password must contain an uppercase letter, a lowercase letter, and a number' });
      }
    }

    // Cost 12, matching PUT /api/auth/password. POST /users still uses 10; this
    // is the stronger of the two and the right default for a credential reset.
    const passwordHash = await bcrypt.hash(password, 12);

    await cybercoreQuery(
      `UPDATE cybercore_user
          SET password_hash = $1, password_alg = 'bcrypt', updated_at = NOW()
        WHERE user_id = $2`,
      [passwordHash, id]
    );

    // Never log the password itself — only that a reset happened, and whether
    // the admin chose it or the server generated it.
    logActivity(req, 'user_password_reset', 'cybercore_user', id, {
      email: user.email,
      source: generated ? 'generated' : 'admin-supplied',
    });

    res.json({
      success: true,
      ...(generated ? { generated_password: generated } : {}),
      warnings: [
        'Sessions already signed in are not ended by this reset — their existing login stays '
        + 'valid until it expires (7 days by default).',
      ],
      message: `Password reset for ${user.email}`,
    });
  } catch (error) {
    console.error('[Users] Password reset error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


// POST /api/admin/users/:id/mfa/reset — clear a user's MFA, forcing
// re-enrollment at their next login (help-desk recovery for a lost device).
router.post('/users/:id/mfa/reset', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await cybercoreQuery(
      `UPDATE cybercore_user
          SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_recovery_codes = NULL, mfa_enrolled_at = NULL
        WHERE user_id = $1
        RETURNING user_id, email`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    logActivity(req, 'user_mfa_reset', 'cybercore_user', id, { email: result.rows[0].email });
    res.json({ success: true, message: `MFA reset for ${result.rows[0].email}` });
  } catch (error) {
    console.error('[Users] MFA reset error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


module.exports = router;
