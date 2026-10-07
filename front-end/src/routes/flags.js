/**
 * ============================================================================
 * FLAG ROUTES
 * Student flag submission + progress, instructor/admin visibility.
 * ----------------------------------------------------------------------------
 * Mounted at /api/flags. The submit endpoint has its own rate limiter applied
 * in server.js — the global /api/ limiter is not protection here: it exempts
 * admins entirely and its ceiling is 5000/15min.
 *
 * All flag logic lives in src/utils/flag-manager.js; these handlers stay thin.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();

const { authenticateToken, requireRole } = require('../middleware/auth');
const { cybercoreQuery } = require('../utils/cybercore-db');
const flagManager = require('../utils/flag-manager');

const staffOnly = requireRole('instructor', 'admin');
const adminOnly = requireRole('admin');

// ============================================================================
// STUDENT
// ============================================================================

/**
 * POST /api/flags/submit  { flag }
 *
 * Checks the value against the submitting student's OWN lanes only. A real
 * flag from someone else's lane returns the identical "Incorrect Flag" as
 * random garbage — the response must never confirm that a shared value is
 * genuine. The attempt is logged as `foreign_lane` for the instructor.
 */
router.post('/submit', authenticateToken, async (req, res) => {
  try {
    const { flag } = req.body || {};
    if (typeof flag !== 'string' || flag.trim().length === 0) {
      return res.status(400).json({ error: 'flag is required' });
    }
    if (flag.length > 512) {
      return res.status(400).json({ error: 'flag is too long' });
    }

    const result = await flagManager.verifySubmission({
      userId: req.user.userId,
      value: flag,
      ip: req.ip || null
    });

    res.json(result);
  } catch (err) {
    console.error('[Flags] Submit error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/flags/mine
 * The student's own capture checklist. Never includes flag values.
 */
router.get('/mine', authenticateToken, async (req, res) => {
  try {
    const flags = await flagManager.getUserFlagProgress(req.user.userId);
    const captured = flags.filter(f => f.captured).length;
    res.json({ flags, captured, total: flags.length });
  } catch (err) {
    console.error('[Flags] Progress error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// INSTRUCTOR / ADMIN
// ============================================================================

/**
 * GET /api/flags/lane/:laneId
 * Full state for one lane, flag values included.
 */
router.get('/lane/:laneId', authenticateToken, staffOnly, async (req, res) => {
  try {
    const laneResult = await cybercoreQuery(
      `SELECT l.lane_id, l.name, l.status, u.email
         FROM cybercore_lane l
         LEFT JOIN cybercore_user u ON u.user_id = l.user_id
        WHERE l.lane_id = $1`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Lane not found' });
    }

    const flags = await flagManager.getLaneFlagState(req.params.laneId);
    res.json({ lane: laneResult.rows[0], flags });
  } catch (err) {
    console.error('[Flags] Lane state error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/flags/group/:groupId
 * Cohort matrix for a lane group (POST /api/admin/deploy-group). The CLE
 * course view is the same data reached through course enrollment instead —
 * see modules/crucible/plugins/cle/routes/flags.js.
 */
router.get('/group/:groupId', authenticateToken, staffOnly, async (req, res) => {
  try {
    const members = await cybercoreQuery(
      `SELECT DISTINCT user_id FROM cybercore_lane
        WHERE config->>'group_id' = $1 AND status <> 'deleted'`,
      [req.params.groupId]
    );
    const state = await flagManager.getFlagStateForUsers(members.rows.map(r => r.user_id));
    res.json({ students: flagManager.buildCohortRows(state) });
  } catch (err) {
    console.error('[Flags] Group state error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/flags/submissions/:userId
 * Submission audit trail for one student. Instructors use this to look at a
 * foreign-lane hit in context.
 */
router.get('/submissions/:userId', authenticateToken, staffOnly, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const result = await cybercoreQuery(
      `SELECT submission_id, lane_id, submitted_value, result, vm_name, flag_type,
              ip_address, created_at
         FROM cybercore_flag_submission
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [req.params.userId, limit]
    );
    res.json({ submissions: result.rows });
  } catch (err) {
    console.error('[Flags] Submissions error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/flags/lane/:laneId/rotate
 * Discard and regenerate a lane's flags, then replant. Resets capture state.
 * Runs in the background — planting waits on guest agents and can take minutes.
 */
router.post('/lane/:laneId/rotate', authenticateToken, adminOnly, async (req, res) => {
  try {
    const laneResult = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) {
      return res.status(404).json({ error: 'Active lane not found' });
    }

    // Respond immediately — replanting blocks on guest agents.
    res.json({ success: true, message: 'Rotating flags; check the lane view for status.' });

    flagManager.rotateLaneFlags({ laneId: req.params.laneId })
      .then(summary => {
        console.log(`[Flags] Rotate complete for lane ${req.params.laneId}: ` +
          `${summary.planted} planted, ${summary.failed} failed`);
      })
      .catch(err => {
        console.error(`[Flags] Rotate failed for lane ${req.params.laneId}: ${err.message}`);
      });
  } catch (err) {
    console.error('[Flags] Rotate error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
