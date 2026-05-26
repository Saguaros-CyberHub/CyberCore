/**
 * Crucible Events API
 * Mounted at "/" so routes resolve to /api/crucible/events/*.
 */
const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../src/utils/cybercore-db');

const adminOnly = requireRole('admin');

const EVENT_TYPES = ['weekly', 'vuln', 'groupctf', 'koth', 'redvsblue', 'ir', 'ctf_event', 'byoctf'];

// GET /api/crucible/events — list events (users see active+public; admins see all)
router.get('/api/crucible/events', authenticateToken, async (req, res) => {
  try {
    const { type } = req.query;
    const isAdmin = req.user.role === 'admin';

    const conditions = [`module_key = 'crucible'`];
    const params = [];

    if (type && EVENT_TYPES.includes(type)) {
      params.push(type);
      conditions.push(`event_type = $${params.length}`);
    }

    if (!isAdmin) {
      conditions.push(`status = 'active'`);
      conditions.push(`is_public = true`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const result = await cybercoreQuery(`
      SELECT
        e.event_id,
        e.name,
        e.description,
        e.event_type,
        e.status,
        e.starts_at,
        e.ends_at,
        e.max_players,
        e.is_public,
        e.created_at,
        e.updated_at,
        u.first_name || ' ' || u.last_name AS created_by_name,
        COUNT(DISTINCT s.user_id) AS participant_count
      FROM cybercore_event e
      LEFT JOIN cybercore_user u ON e.created_by = u.user_id
      LEFT JOIN crucible_score s ON e.event_id = s.event_id
      ${where}
      GROUP BY e.event_id, u.first_name, u.last_name
      ORDER BY e.starts_at DESC NULLS LAST, e.created_at DESC
    `, params);

    res.json({ events: result.rows });
  } catch (err) {
    console.error('[Crucible] List events error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/crucible/events — create event (admin only)
router.post('/api/crucible/events', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, description, event_type, starts_at, ends_at, max_players, is_public } = req.body;

    if (!name || !event_type) {
      return res.status(400).json({ error: 'name and event_type are required' });
    }
    if (!EVENT_TYPES.includes(event_type)) {
      return res.status(400).json({ error: `event_type must be one of: ${EVENT_TYPES.join(', ')}` });
    }

    const result = await cybercoreQuery(`
      INSERT INTO cybercore_event
        (name, description, event_type, status, starts_at, ends_at, max_players, is_public, created_by, module_key)
      VALUES ($1, $2, $3, 'draft', $4, $5, $6, $7, $8, 'crucible')
      RETURNING *
    `, [
      name,
      description || null,
      event_type,
      starts_at || null,
      ends_at || null,
      max_players || null,
      is_public !== false,
      req.user.userId,
    ]);

    res.status(201).json({ event: result.rows[0] });
  } catch (err) {
    console.error('[Crucible] Create event error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/crucible/events/:id — update event (admin only)
router.patch('/api/crucible/events/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, event_type, status, starts_at, ends_at, max_players, is_public } = req.body;

    if (event_type && !EVENT_TYPES.includes(event_type)) {
      return res.status(400).json({ error: `Invalid event_type` });
    }

    const result = await cybercoreQuery(`
      UPDATE cybercore_event SET
        name        = COALESCE($1, name),
        description = COALESCE($2, description),
        event_type  = COALESCE($3, event_type),
        status      = COALESCE($4, status),
        starts_at   = COALESCE($5, starts_at),
        ends_at     = COALESCE($6, ends_at),
        max_players = COALESCE($7, max_players),
        is_public   = COALESCE($8, is_public),
        updated_at  = now()
      WHERE event_id = $9 AND module_key = 'crucible'
      RETURNING *
    `, [name, description, event_type, status, starts_at, ends_at, max_players, is_public, id]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Event not found' });
    res.json({ event: result.rows[0] });
  } catch (err) {
    console.error('[Crucible] Update event error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/crucible/events/:id — delete event (admin only)
router.delete('/api/crucible/events/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `DELETE FROM cybercore_event WHERE event_id = $1 AND module_key = 'crucible' RETURNING event_id`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Event not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('[Crucible] Delete event error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
