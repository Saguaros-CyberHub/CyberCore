/**
 * CLE Plugin — Session Audit API
 * Queries Guacamole's connection_history table for student usage data.
 * All endpoints require instructor or admin role (applied by api.js).
 */

const express = require('express');
const router = express.Router();

const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

let guacDbQuery;
try {
  guacDbQuery = require('../../../../../src/utils/guacamole-db').guacDbQuery;
} catch (e) {
  guacDbQuery = null;
}

// ============================================================================
// HELPERS
// ============================================================================

async function getInstructorStudentEmails(userId, userRole) {
  // Get all courses the instructor teaches
  const coursesResult = await query(`
    SELECT course_id FROM cle_course
    WHERE instructor_id = $1 OR $2 = 'admin'
  `, [userId, userRole]);

  if (coursesResult.rows.length === 0) return [];

  const courseIds = coursesResult.rows.map(r => r.course_id);

  // Get all enrolled students across those courses
  const enrollmentsResult = await query(`
    SELECT DISTINCT user_id FROM cle_course_enrollment
    WHERE course_id = ANY($1) AND status = 'active'
  `, [courseIds]);

  // Get email addresses for those students
  const userIds = enrollmentsResult.rows.map(r => r.user_id);
  if (userIds.length === 0) return [];

  const emailsResult = await cybercoreQuery(`
    SELECT DISTINCT email FROM cybercore_user
    WHERE user_id = ANY($1)
  `, [userIds]);

  return emailsResult.rows.map(r => r.email);
}

// ============================================================================
// SESSION HISTORY (all students)
// ============================================================================

// GET / — session history for all instructor's students
router.get('/', async (req, res) => {
  if (!guacDbQuery) {
    return res.status(503).json({ error: 'Guacamole database not configured. Set GUAC_DB_HOST and GUAC_DB_PASSWORD.' });
  }

  try {
    const studentEmails = await getInstructorStudentEmails(req.user.userId, req.user.role);
    if (studentEmails.length === 0) return res.json({ sessions: [], summary: [] });

    const { from, to, limit: rawLimit } = req.query;
    const sessionLimit = Math.min(parseInt(rawLimit) || 200, 1000);

    let dateFilter = '';
    const params = [studentEmails];
    let paramIdx = 2;

    if (from) { dateFilter += ` AND h.start_date >= $${paramIdx++}`; params.push(from); }
    if (to) { dateFilter += ` AND h.start_date <= $${paramIdx++}`; params.push(to); }

    const sessionsResult = await guacDbQuery(
      `SELECT h.history_id, h.username, h.connection_name,
              h.start_date, h.end_date, h.remote_host,
              EXTRACT(EPOCH FROM (COALESCE(h.end_date, NOW()) - h.start_date)) AS duration_seconds
       FROM guacamole_connection_history h
       WHERE h.username = ANY($1) ${dateFilter}
       ORDER BY h.start_date DESC
       LIMIT ${sessionLimit}`,
      params
    );

    // Per-student summary
    const summaryResult = await guacDbQuery(
      `SELECT username,
              MAX(start_date) AS last_login,
              COUNT(*) AS session_count,
              SUM(EXTRACT(EPOCH FROM (COALESCE(end_date, NOW()) - start_date))) AS total_seconds
       FROM guacamole_connection_history
       WHERE username = ANY($1)
       GROUP BY username
       ORDER BY last_login DESC`,
      [studentEmails]
    );

    res.json({
      sessions: sessionsResult.rows,
      summary: summaryResult.rows,
      student_count: studentEmails.length
    });
  } catch (error) {
    console.error('[CLE] Sessions list error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// SINGLE STUDENT SUMMARY
// ============================================================================

// GET /:studentId/summary — per-student session summary
router.get('/:studentId/summary', async (req, res) => {
  if (!guacDbQuery) {
    return res.status(503).json({ error: 'Guacamole database not configured' });
  }

  try {
    // Look up student email
    const userResult = await cybercoreQuery(
      `SELECT email FROM cybercore_user WHERE user_id = $1`, [req.params.studentId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Student not found' });
    const email = userResult.rows[0].email;

    // Verify instructor has authority
    const studentEmails = await getInstructorStudentEmails(req.user.userId, req.user.role);
    if (!studentEmails.includes(email)) {
      return res.status(403).json({ error: 'Student not in your groups' });
    }

    const summaryResult = await guacDbQuery(
      `SELECT username,
              MAX(start_date) AS last_login,
              COUNT(*) AS session_count,
              SUM(EXTRACT(EPOCH FROM (COALESCE(end_date, NOW()) - start_date))) AS total_seconds,
              MIN(start_date) AS first_login
       FROM guacamole_connection_history
       WHERE username = $1
       GROUP BY username`,
      [email]
    );

    if (summaryResult.rows.length === 0) {
      return res.json({ email, last_login: null, session_count: 0, total_seconds: 0, first_login: null });
    }

    res.json({ email, ...summaryResult.rows[0] });
  } catch (error) {
    console.error('[CLE] Student summary error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// SINGLE STUDENT HISTORY
// ============================================================================

// GET /:studentId/history — detailed session list for one student
router.get('/:studentId/history', async (req, res) => {
  if (!guacDbQuery) {
    return res.status(503).json({ error: 'Guacamole database not configured' });
  }

  try {
    const userResult = await cybercoreQuery(
      `SELECT email FROM cybercore_user WHERE user_id = $1`, [req.params.studentId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Student not found' });
    const email = userResult.rows[0].email;

    const studentEmails = await getInstructorStudentEmails(req.user.userId, req.user.role);
    if (!studentEmails.includes(email)) {
      return res.status(403).json({ error: 'Student not in your groups' });
    }

    const historyResult = await guacDbQuery(
      `SELECT h.history_id, h.username, h.connection_name,
              h.start_date, h.end_date, h.remote_host,
              EXTRACT(EPOCH FROM (COALESCE(h.end_date, NOW()) - h.start_date)) AS duration_seconds
       FROM guacamole_connection_history h
       WHERE h.username = $1
       ORDER BY h.start_date DESC
       LIMIT 100`,
      [email]
    );

    res.json({ email, sessions: historyResult.rows });
  } catch (error) {
    console.error('[CLE] Student history error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
