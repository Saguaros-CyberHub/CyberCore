/**
 * Crucible Challenges API
 * Mounted at "/" so routes resolve to /api/crucible/challenges/*.
 *
 * Challenges are the catalog of reusable, playable Crucible ranges
 * (crucible_challenge). This is distinct from cybercore_event, which holds
 * human-run live events (scheduled CTFs, KotH matches, red-vs-blue sessions).
 */
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../src/utils/cybercore-db');

// crucible_challenge_type enum values (see config/postgres/modules/crucible.sql)
const CHALLENGE_TYPES = ['single_vm', 'multi_vm', 'koth', 'red_vs_blue', 'other'];

// GET /api/crucible/challenges — list challenges.
//   ?type=single_vm,multi_vm  filter to one or more challenge_type values.
//   Non-admins see only active challenges; admins see every status.
router.get('/api/crucible/challenges', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';

    const conditions = [`module_key = 'crucible'`];
    const params = [];

    const requested = String(req.query.type || '')
      .split(',')
      .map((t) => t.trim())
      .filter((t) => CHALLENGE_TYPES.includes(t));

    if (requested.length) {
      params.push(requested);
      conditions.push(`challenge_type = ANY($${params.length})`);
    }

    if (!isAdmin) {
      conditions.push(`status = 'active'`);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;

    const result = await cybercoreQuery(`
      SELECT
        challenge_id,
        challenge_key,
        name,
        description,
        challenge_type,
        difficulty,
        status,
        (spec->>'attachable')::boolean AS attachable,
        created_at,
        updated_at
      FROM crucible_challenge
      ${where}
      ORDER BY difficulty ASC NULLS LAST, name ASC
    `, params);

    res.json({ challenges: result.rows });
  } catch (err) {
    console.error('[Crucible] List challenges error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
