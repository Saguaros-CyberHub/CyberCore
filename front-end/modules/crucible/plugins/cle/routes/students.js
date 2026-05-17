/**
 * CLE Plugin — Students Management API
 * Manage student enrollments across instructor's courses
 * All endpoints require instructor or admin role (applied by api.js).
 */

const express = require('express');
const router = express.Router();

const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

// ============================================================================
// LIST STUDENTS (per instructor's courses)
// ============================================================================

// GET / — list all students enrolled in instructor's courses
router.get('/', async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const userRole = req.user.role;

    // Get instructor's courses (or all courses if admin)
    const coursesResult = await query(`
      SELECT course_id FROM cle_course
      WHERE instructor_id = $1 OR $2 = 'admin'
    `, [instructorId, userRole]);

    if (coursesResult.rows.length === 0) {
      return res.json({ students: [] });
    }

    const courseIds = coursesResult.rows.map(r => r.course_id);

    // Get all students enrolled in those courses
    const studentsResult = await query(`
      SELECT DISTINCT
        e.user_id,
        e.course_id,
        e.enrollment_role,
        e.status,
        e.enrolled_at,
        u.email,
        u.first_name,
        u.last_name,
        COUNT(DISTINCT v.assignment_id) AS vm_count
      FROM cle_course_enrollment e
      JOIN cybercore_user u ON e.user_id = u.user_id
      LEFT JOIN cle_user_vm_assignment v ON e.user_id = v.user_id AND e.course_id = v.course_id
      WHERE e.course_id = ANY($1)
      GROUP BY e.user_id, e.course_id, e.enrollment_role, e.status, e.enrolled_at, u.email, u.first_name, u.last_name
      ORDER BY e.enrolled_at DESC
    `, [courseIds]);

    res.json({ students: studentsResult.rows });
  } catch (error) {
    console.error('[CLE] Get students error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// GET SINGLE STUDENT PROFILE
// ============================================================================

// GET /:studentId — get student profile with enrollment details
router.get('/:studentId', async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const userRole = req.user.role;
    const { studentId } = req.params;

    // Get student user info
    const userResult = await cybercoreQuery(`
      SELECT user_id, email, first_name, last_name, role FROM cybercore_user
      WHERE user_id = $1
    `, [studentId]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const student = userResult.rows[0];

    // Get student's enrollments in instructor's courses
    const enrollmentsResult = await query(`
      SELECT
        e.enrollment_id,
        e.course_id,
        c.course_name,
        e.enrollment_role,
        e.status,
        e.enrolled_at,
        e.completion_date,
        COUNT(DISTINCT v.assignment_id) AS vm_count,
        COUNT(DISTINCT m.material_id) AS material_count
      FROM cle_course_enrollment e
      JOIN cle_course c ON e.course_id = c.course_id
      LEFT JOIN cle_user_vm_assignment v ON e.user_id = v.user_id AND e.course_id = v.course_id
      LEFT JOIN cle_course_material m ON c.course_id = m.course_id
      WHERE e.user_id = $1 AND (c.instructor_id = $2 OR $3 = 'admin')
      GROUP BY e.enrollment_id, e.course_id, c.course_name, e.enrollment_role, e.status, e.enrolled_at, e.completion_date
    `, [studentId, instructorId, userRole]);

    res.json({
      student: {
        ...student,
        enrollments: enrollmentsResult.rows
      }
    });
  } catch (error) {
    console.error('[CLE] Get student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// UPDATE STUDENT ENROLLMENT ROLE
// ============================================================================

// PATCH /:studentId/:courseId/role — change student's role in a course
router.patch('/:studentId/:courseId/role', async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { studentId, courseId } = req.params;
    const { enrollment_role } = req.body;

    // Validate role
    if (!['student', 'ta', 'guest', 'lab_assistant'].includes(enrollment_role)) {
      return res.status(400).json({ error: 'Invalid enrollment role' });
    }

    // Verify instructor owns course
    const courseResult = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseResult.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Update enrollment role
    const updateResult = await query(`
      UPDATE cle_course_enrollment
      SET enrollment_role = $1, updated_at = NOW()
      WHERE user_id = $2 AND course_id = $3
      RETURNING *
    `, [enrollment_role, studentId, courseId]);

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Enrollment not found' });
    }

    res.json({ enrollment: updateResult.rows[0] });
  } catch (error) {
    console.error('[CLE] Update enrollment role error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// SUSPEND/REACTIVATE STUDENT
// ============================================================================

// PATCH /:studentId/:courseId/status — change student's enrollment status
router.patch('/:studentId/:courseId/status', async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { studentId, courseId } = req.params;
    const { status } = req.body;

    // Validate status
    if (!['active', 'completed', 'dropped', 'pending', 'suspended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Verify instructor owns course
    const courseResult = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseResult.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Update enrollment status
    const updateResult = await query(`
      UPDATE cle_course_enrollment
      SET status = $1, updated_at = NOW(),
          completion_date = CASE WHEN $1 IN ('completed', 'dropped') THEN NOW() ELSE completion_date END
      WHERE user_id = $2 AND course_id = $3
      RETURNING *
    `, [status, studentId, courseId]);

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Enrollment not found' });
    }

    res.json({ enrollment: updateResult.rows[0] });
  } catch (error) {
    console.error('[CLE] Update enrollment status error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
