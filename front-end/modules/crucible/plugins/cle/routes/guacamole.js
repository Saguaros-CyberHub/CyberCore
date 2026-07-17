/**
 * CLE Plugin — Guacamole Access Routes
 * Handles read-only RDP access for instructors to monitor students
 * Mounted at /api/cle/courses/:courseId/students/:studentId/guac
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { getGuacToken, GUAC_URL } = require('../../../../../src/utils/guacamole');
const { canManageCourse } = require('../utils/course-access');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET /token — Get a read-only Guacamole token for monitoring student's RDP session
 */
router.get('/token', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId, studentId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Verify student is enrolled in course
    const enrollmentCheck = await query(`
      SELECT e.user_id FROM cle_course_enrollment e
      WHERE e.user_id = $1 AND e.course_id = $2 AND e.status = 'active'
    `, [studentId, courseId]);

    if (enrollmentCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Student not found in course' });
    }

    // Get student's Guacamole user (email-based)
    const studentResult = await cybercoreQuery(`
      SELECT email FROM cybercore_user
      WHERE user_id = $1
    `, [studentId]);

    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentEmail = studentResult.rows[0].email;

    // Get instructor token
    const instructorToken = await getGuacToken();

    // Fetch student's Guacamole user to get their connections
    const guacUsersUrl = `${GUAC_URL}/api/users`;
    const guacUsersRes = await fetch(`${guacUsersUrl}?token=${instructorToken}`);
    const guacUsersData = await guacUsersRes.json();

    // Find the student's Guacamole user
    const studentGuacUser = guacUsersData[studentEmail];
    if (!studentGuacUser) {
      return res.status(404).json({ error: 'Student has no Guacamole account' });
    }

    // Get student's connections (RDP sessions)
    const connectionsUrl = `${GUAC_URL}/api/users/${studentEmail}/connections`;
    const connRes = await fetch(`${connectionsUrl}?token=${instructorToken}`);
    const connData = await connRes.json();

    // Get the first RDP connection (or find one manually)
    let connectionId = null;
    for (const [id, conn] of Object.entries(connData)) {
      if (conn.protocol === 'rdp') {
        connectionId = id;
        break;
      }
    }

    if (!connectionId) {
      return res.status(404).json({ error: 'No RDP connection available for this student' });
    }

    // Create a read-only connection token using the connection ID
    // Guacamole doesn't directly support "read-only" tokens, so we're passing
    // a token that the frontend can use with the ?readonly=true flag
    res.json({
      success: true,
      guac_token: instructorToken,
      connection_id: connectionId,
      username: studentEmail,
      guac_url: GUAC_URL,
      message: 'Guacamole session token. Use with ?readonly=true flag for monitoring.'
    });
  } catch (error) {
    console.error('[CLE] Get Guacamole token error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /active-sessions — Get list of active Guacamole sessions for a student
 */
router.get('/active-sessions', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId, studentId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Verify student is enrolled in course
    const enrollmentCheck = await query(`
      SELECT e.user_id FROM cle_course_enrollment e
      WHERE e.user_id = $1 AND e.course_id = $2 AND e.status = 'active'
    `, [studentId, courseId]);

    if (enrollmentCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Student not found in course' });
    }

    // Get student email
    const studentResult = await cybercoreQuery(`
      SELECT email FROM cybercore_user WHERE user_id = $1
    `, [studentId]);

    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentEmail = studentResult.rows[0].email;

    // Get activity log for student (from Guacamole audit trail in CyberCore)
    const activitiesResult = await query(`
      SELECT
        activity_id,
        user_id,
        action_type,
        entity_type,
        entity_id,
        metadata,
        created_at
      FROM cle_activity_log
      WHERE user_id = $1 AND entity_type = 'guac_session'
      AND created_at > NOW() - INTERVAL '1 hour'
      ORDER BY created_at DESC
      LIMIT 20
    `, [studentId]);

    res.json({
      success: true,
      student_email: studentEmail,
      active_sessions: activitiesResult.rows || []
    });
  } catch (error) {
    console.error('[CLE] Get active sessions error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
