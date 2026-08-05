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
const { mintGuacToken, GUAC_URL } = require('../../../../../src/utils/guacamole');
const { canManageCourse } = require('../utils/course-access');
const guacCreds = require('../../../../../src/utils/guac-credentials');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * Confirm the caller manages the course AND the student is in it. Every route
 * here has to check both — managing a course does not grant access to arbitrary
 * user ids, and being enrolled somewhere does not make a student this
 * instructor's to look at.
 */
async function assertStudentInCourse(courseId, studentId, user) {
  if (!(await canManageCourse(courseId, user))) {
    const err = new Error('Course not found or access denied');
    err.status = 403;
    throw err;
  }
  const enrollment = await query(
    `SELECT user_id FROM cle_course_enrollment
      WHERE user_id = $1 AND course_id = $2 AND status IN ('active', 'completed')`,
    [studentId, courseId]
  );
  if (enrollment.rows.length === 0) {
    const err = new Error('Student not found in course');
    err.status = 403;
    throw err;
  }
}

/**
 * Record a credential disclosure. cle_activity_log's action_type CHECK has no
 * value for this, so it is filed under the closest permitted one ('guac_session')
 * with the real action in metadata — a new enum value would need a migration and
 * would break older rows written by a previous deploy.
 */
function logCredentialAccess({ actorId, studentId, courseId, action, detail }) {
  return query(
    `INSERT INTO cle_activity_log (user_id, action_type, entity_type, entity_id, metadata)
     VALUES ($1, 'guac_session', 'guac_credential', $2, $3::jsonb)`,
    [actorId, studentId, JSON.stringify({ action, course_id: courseId, ...detail })]
  ).catch(err => console.warn(`[CLE] Could not log credential access: ${err.message}`));
}

/**
 * GET /credentials — the student's Guacamole console login, so an instructor can
 * give it back when the student loses it.
 *
 * Strictly read-only — it never creates or rotates anything, so a GET cannot
 * have side effects (a cross-site top-level navigation can trigger a GET, and
 * this route is cookie-or-bearer authenticated). Issuing is POST /credentials.
 *
 * Course membership alone is NOT sufficient authority: an instructor can enroll
 * any email address in their own course, so assertCanDiscloseFor also refuses
 * non-student accounts for non-admin callers.
 */
router.get('/credentials', instructorOnly, async (req, res) => {
  try {
    const { courseId, studentId } = req.params;
    await assertStudentInCourse(courseId, studentId, req.user);
    await guacCreds.assertCanDiscloseFor(studentId, req.user);

    const cred = await guacCreds.getGuacCredential(studentId, { create: false });

    logCredentialAccess({
      actorId: req.user.userId, studentId, courseId,
      action: 'view_credential',
      detail: { available: cred.available, source: cred.source },
    });

    res.json(cred);
  } catch (error) {
    console.error('[CLE] Get student Guac credentials error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * POST /credentials — issue a console login for a student who has no Guacamole
 * account yet. Never rotates an existing one; if the account exists but its
 * password isn't on record, that is reported so the instructor can choose the
 * (disruptive) reset explicitly.
 */
router.post('/credentials', instructorOnly, async (req, res) => {
  try {
    const { courseId, studentId } = req.params;
    await assertStudentInCourse(courseId, studentId, req.user);
    await guacCreds.assertCanDiscloseFor(studentId, req.user);

    const cred = await guacCreds.getGuacCredential(studentId, { create: true });

    logCredentialAccess({
      actorId: req.user.userId, studentId, courseId,
      action: 'issue_credential',
      detail: { available: cred.available, source: cred.source },
    });

    res.json(cred);
  } catch (error) {
    console.error('[CLE] Issue student Guac credentials error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * POST /credentials/reset — rotate the student's console password when the old
 * one has to be invalidated rather than recovered.
 */
router.post('/credentials/reset', instructorOnly, async (req, res) => {
  try {
    const { courseId, studentId } = req.params;
    await assertStudentInCourse(courseId, studentId, req.user);
    await guacCreds.assertCanDiscloseFor(studentId, req.user);

    const cred = await guacCreds.resetGuacCredential(studentId);
    logCredentialAccess({
      actorId: req.user.userId, studentId, courseId,
      action: 'reset_credential', detail: { username: cred.username },
    });

    res.json(cred);
  } catch (error) {
    console.error('[CLE] Reset student Guac credentials error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

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

    // A session of its own for this handoff. The response hands this token to
    // the browser, and a browser destroys its token on logout — so it must never
    // be the cached one this process uses for its own Guacamole calls, or that
    // logout takes the orchestrator's session down with it (403 PERMISSION_DENIED
    // on everything until the cache turns over). See mintGuacToken.
    const instructorToken = (await mintGuacToken()).authToken;

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
