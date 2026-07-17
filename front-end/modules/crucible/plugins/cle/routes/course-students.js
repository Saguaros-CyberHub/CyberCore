/**
 * CLE Plugin — Course Students Routes
 * Handles student enrollment: list, add, remove, manage
 * Mounted at /api/cle/courses/:courseId/students
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { canManageCourse } = require('../utils/course-access');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET / — List students in a course
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Get enrolled students
    // Step 1: Get enrollments from cle_db
    const enrollmentsResult = await query(`
      SELECT
        e.user_id,
        e.enrollment_role,
        e.enrolled_at,
        e.status
      FROM cle_course_enrollment e
      WHERE e.course_id = $1 AND e.status = 'active'
      ORDER BY e.enrolled_at DESC
    `, [courseId]);

    // Step 2: Get user details + workstation-lane counts from cybercore_db
    const userIds = enrollmentsResult.rows.map(r => r.user_id);
    let userMap = {};
    const laneCounts = {}; // user_id → count
    if (userIds.length > 0) {
      const usersResult = await cybercoreQuery(`
        SELECT user_id, email, first_name, last_name
        FROM cybercore_user
        WHERE user_id = ANY($1)
      `, [userIds]);
      usersResult.rows.forEach(u => {
        userMap[u.user_id] = u;
      });

      const lc = await cybercoreQuery(`
        SELECT user_id, COUNT(*)::int AS vm_count
          FROM cybercore_lane
         WHERE user_id = ANY($1) AND config->>'course_id' = $2 AND status <> 'deleted'
         GROUP BY user_id
      `, [userIds, courseId]).catch(() => ({ rows: [] }));
      lc.rows.forEach(r => { laneCounts[r.user_id] = r.vm_count; });
    }

    // Step 3: Merge user data with enrollments
    const students = enrollmentsResult.rows.map(e => ({
      user_id: e.user_id,
      email: userMap[e.user_id]?.email || 'unknown',
      first_name: userMap[e.user_id]?.first_name || '',
      last_name: userMap[e.user_id]?.last_name || '',
      enrollment_role: e.enrollment_role,
      enrolled_at: e.enrolled_at,
      status: e.status,
      vm_count: laneCounts[e.user_id] || 0
    }));

    res.json({ students });
  } catch (error) {
    console.error('[CLE] Get students error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST / — Add student to course
 */
router.post('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { user_email, enrollment_role } = req.body;

    if (!user_email) {
      return res.status(400).json({ error: 'user_email is required' });
    }

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Find user in cybercore_user by email
    const userResult = await cybercoreQuery(`
      SELECT user_id FROM cybercore_user
      WHERE LOWER(email) = LOWER($1)
    `, [user_email]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: `User not found: ${user_email}` });
    }

    const userId = userResult.rows[0].user_id;

    // Add or reactivate enrollment
    const enrollResult = await query(`
      INSERT INTO cle_course_enrollment
        (user_id, course_id, enrollment_role, status, enrolled_at)
      VALUES ($1, $2, $3, 'active', NOW())
      ON CONFLICT (user_id, course_id)
      DO UPDATE SET
        status = 'active',
        enrollment_role = EXCLUDED.enrollment_role,
        enrolled_at = NOW()
      RETURNING *
    `, [userId, courseId, enrollment_role || 'student']);

    res.json({ success: true, enrollment: enrollResult.rows[0] });
  } catch (error) {
    console.error('[CLE] Add student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /:studentId — Remove student from course
 */
router.delete('/:studentId', instructorOnly, async (req, res) => {
  try {
    const { courseId, studentId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Soft delete enrollment
    await query(`
      UPDATE cle_course_enrollment
      SET status = 'dropped', updated_at = NOW()
      WHERE user_id = $1 AND course_id = $2
    `, [studentId, courseId]);

    res.json({ success: true, message: 'Student removed from course' });
  } catch (error) {
    console.error('[CLE] Remove student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
