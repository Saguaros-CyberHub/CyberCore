/**
 * ============================================================================
 * Guacamole Admin Routes
 * CRUD for connections, connection groups, users, and active sessions.
 * All routes mounted at /api/admin/guac/* via the admin aggregator.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { guacAPI, getGuacToken, GUAC_URL, GUAC_DS } = require('../../utils/guacamole');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const guacCreds = require('../../utils/guac-credentials');
const { logActivity } = require('../../middleware/activity-logger');

const adminOnly = requireRole('admin');


// ============================================================================
// CREDENTIAL RECOVERY
// Staff-only lookup of the Guacamole password CyberCore holds for a user, so a
// student who loses their console login can be given it back rather than having
// every one of their machines reprovisioned.
//
// Both routes log the disclosure: a Guacamole password reaches every console
// that user owns, so "who looked at this, and when" has to be answerable.
// ============================================================================

/**
 * GET /guac/users/:userId/credentials — the user's Guacamole login.
 *
 * ?peek=true reads without side effects; the default issues (and stores) a
 * password when none exists yet, so the answer is always usable.
 */
router.get('/guac/users/:userId/credentials', authenticateToken, adminOnly, async (req, res) => {
  try {
    const peek = req.query.peek === 'true' || req.query.peek === '1';
    // adminOnly already, but keep the guard explicit so the rule lives in one place.
    await guacCreds.assertCanDiscloseFor(req.params.userId, req.user);
    const cred = await guacCreds.getGuacCredential(req.params.userId, { create: !peek });
    logActivity(req, 'view_guac_credential', 'user', req.params.userId, {
      available: cred.available, source: cred.source, peek,
    });
    res.json(cred);
  } catch (err) {
    console.error('[admin/guac] credential lookup error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

/** POST /guac/users/:userId/credentials/reset — rotate the console password. */
router.post('/guac/users/:userId/credentials/reset', authenticateToken, adminOnly, async (req, res) => {
  try {
    const cred = await guacCreds.resetGuacCredential(req.params.userId);
    logActivity(req, 'reset_guac_credential', 'user', req.params.userId, { username: cred.username });
    res.json(cred);
  } catch (err) {
    console.error('[admin/guac] credential reset error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});


// ============================================================================
// USER SYNC
// Creates/resets Guacamole accounts for all active CyberCore users who don't
// yet have a guac_password stored on their user record. Useful for backfilling
// users created before registration-time account creation was added, including
// the seeded admin account.
// ============================================================================

router.post('/guac/sync-users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const users = await cybercoreQuery(`
      SELECT user_id, email
      FROM cybercore_user
      WHERE status = 'active' AND active = true
      ORDER BY created_at
    `);

    const results = [];

    // The backfill's job is "every active user HAS a Guacamole account, and we
    // have its password on record where we can". getGuacCredential does that
    // ladder — stored → legacy VM metadata → create-if-absent — and never
    // rotates a live account, so re-running this is safe.
    //
    // 'exists_no_password' is reported rather than silently reset: the account
    // is usable, we just cannot look its password up. Resetting it here would
    // disconnect whoever is using it.
    for (const user of users.rows) {
      const cred = await guacCreds.getGuacCredential(user.user_id).catch(() => null);
      const status = !cred                         ? 'failed'
                   : cred.source === 'stored'       ? 'already_synced'
                   : cred.source === 'migrated'     ? 'migrated_from_vm'
                   : cred.source === 'created'      ? 'created'
                   : cred.source === 'unrecoverable' ? 'exists_no_password'
                   : cred.source === 'undecryptable' ? 'undecryptable'
                   : 'failed';
      results.push({ email: user.email, status, ...(cred?.reason ? { reason: cred.reason } : {}) });
    }

    const summary = results.reduce((acc, r) => {
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    }, {});

    res.json({ summary, results });
  } catch (err) {
    console.error('[admin/guac] sync-users error:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// ============================================================================
// STATUS / CONNECTION TREE
// ============================================================================

router.get('/guac/status', authenticateToken, adminOnly, async (req, res) => {
  try {
    await getGuacToken();
    res.json({ connected: true, datasource: GUAC_DS, guac_url: GUAC_URL });
  } catch (error) {
    res.status(502).json({ connected: false, error: error.message });
  }
});

router.get('/guac/tree', authenticateToken, adminOnly, async (req, res) => {
  try {
    const tree = await guacAPI('GET', '/connectionGroups/ROOT/tree');
    res.json(tree);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CONNECTIONS
// ============================================================================

router.get('/guac/connections', authenticateToken, adminOnly, async (req, res) => {
  try {
    const connections = await guacAPI('GET', '/connections');
    res.json(connections);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/guac/connections/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const conn = await guacAPI('GET', `/connections/${req.params.id}`);
    const params = await guacAPI('GET', `/connections/${req.params.id}/parameters`);
    res.json({ ...conn, parameters: params });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/guac/connections', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, protocol, parentIdentifier, parameters, attributes } = req.body;
    if (!name || !protocol) return res.status(400).json({ error: 'name and protocol required' });

    const conn = await guacAPI('POST', '/connections', {
      name,
      protocol,
      parentIdentifier: parentIdentifier || 'ROOT',
      parameters: parameters || {},
      attributes: attributes || {}
    });
    res.json(conn);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/guac/connections/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('DELETE', `/connections/${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// CONNECTION GROUPS
// ============================================================================

router.get('/guac/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const groups = await guacAPI('GET', '/connectionGroups');
    res.json(groups);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/guac/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, type, parentIdentifier } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const group = await guacAPI('POST', '/connectionGroups', {
      name,
      type: type || 'ORGANIZATIONAL',
      parentIdentifier: parentIdentifier || 'ROOT',
      attributes: {}
    });
    res.json(group);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/guac/groups/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('DELETE', `/connectionGroups/${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// USERS
// ============================================================================

router.get('/guac/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const users = await guacAPI('GET', '/users');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/guac/users/:username', authenticateToken, adminOnly, async (req, res) => {
  try {
    const user = await guacAPI('GET', `/users/${encodeURIComponent(req.params.username)}`);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/guac/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { username, password, disabled } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const user = await guacAPI('POST', '/users', {
      username,
      password,
      attributes: {
        disabled: disabled ? '' : null,
        expired: null,
        timezone: 'America/Phoenix'
      }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/guac/users/:username/password', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'password required' });

    await guacAPI('PUT', `/users/${encodeURIComponent(req.params.username)}`, {
      username: req.params.username,
      password,
      attributes: {}
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/guac/users/:username', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('DELETE', `/users/${encodeURIComponent(req.params.username)}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/guac/users/:username/permissions', authenticateToken, adminOnly, async (req, res) => {
  try {
    const perms = await guacAPI('GET', `/users/${encodeURIComponent(req.params.username)}/permissions`);
    res.json(perms);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/guac/users/:username/permissions', authenticateToken, adminOnly, async (req, res) => {
  try {
    await guacAPI('PATCH', `/users/${encodeURIComponent(req.params.username)}/permissions`, req.body);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACTIVE SESSIONS
// ============================================================================

router.get('/guac/active', authenticateToken, adminOnly, async (req, res) => {
  try {
    const active = await guacAPI('GET', '/activeConnections');
    res.json(active);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/guac/active/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const token = await getGuacToken();
    const url = `${GUAC_URL}/api/session/data/${GUAC_DS}/activeConnections?token=${token}`;
    const resp = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ op: 'remove', path: `/${req.params.id}` }])
    });
    if (!resp.ok) throw new Error(`Kill session failed: ${resp.status}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
