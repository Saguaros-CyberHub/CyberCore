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

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET / — List students in a course
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId } = req.params;

    // Verify instructor owns course
    const courseOwner = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseOwner.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Get enrolled students with VM assignments
    const studentsResult = await query(`
      SELECT
        u.user_id,
        u.email,
        u.first_name,
        u.last_name,
        e.enrollment_role,
        e.enrolled_at,
        e.status,
        COUNT(DISTINCT v.vm_instance_id) AS vm_count
      FROM cle_course_enrollment e
      JOIN cybercore_user u ON e.user_id = u.user_id
      LEFT JOIN cle_user_vm_assignment v ON e.user_id = v.user_id AND e.course_id = v.course_id
      WHERE e.course_id = $1 AND e.status = 'active'
      GROUP BY u.user_id, e.enrollment_role, e.enrolled_at, e.status
      ORDER BY e.enrolled_at DESC
    `, [courseId]);

    res.json({ students: studentsResult.rows });
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
    const instructorId = req.user.userId;
    const { courseId } = req.params;
    const { user_email, enrollment_role } = req.body;

    if (!user_email) {
      return res.status(400).json({ error: 'user_email is required' });
    }

    // Verify instructor owns course
    const courseOwner = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseOwner.rows.length === 0) {
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
    const instructorId = req.user.userId;
    const { courseId, studentId } = req.params;

    // Verify instructor owns course
    const courseOwner = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseOwner.rows.length === 0) {
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
