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
    // Step 1: Get enrollments from cle_db
    const enrollmentsResult = await query(`
      SELECT DISTINCT
        e.user_id,
        e.course_id,
        e.enrollment_role,
        e.status,
        e.enrolled_at,
        COUNT(DISTINCT v.assignment_id) AS vm_count
      FROM cle_course_enrollment e
      LEFT JOIN cle_user_vm_assignment v ON e.user_id = v.user_id AND e.course_id = v.course_id
      WHERE e.course_id = ANY($1)
      GROUP BY e.user_id, e.course_id, e.enrollment_role, e.status, e.enrolled_at
      ORDER BY e.enrolled_at DESC
    `, [courseIds]);

    // Step 2: Get user details from cybercore_db
    const userIds = [...new Set(enrollmentsResult.rows.map(r => r.user_id))];
    let userMap = {};
    if (userIds.length > 0) {
      const usersResult = await cybercoreQuery(`
        SELECT user_id, email, first_name, last_name
        FROM cybercore_user
        WHERE user_id = ANY($1)
      `, [userIds]);
      usersResult.rows.forEach(u => {
        userMap[u.user_id] = u;
      });
    }

    // Step 3: Merge user data with enrollments
    const students = enrollmentsResult.rows.map(e => ({
      user_id: e.user_id,
      course_id: e.course_id,
      email: userMap[e.user_id]?.email || 'unknown',
      first_name: userMap[e.user_id]?.first_name || '',
      last_name: userMap[e.user_id]?.last_name || '',
      enrollment_role: e.enrollment_role,
      status: e.status,
      enrolled_at: e.enrolled_at,
      vm_count: e.vm_count
    }));

    res.json({ students });
  } catch (error) {
    console.error('[CLE] Get students error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// LIST AVAILABLE STUDENTS TO ADD TO COURSE
// ============================================================================

// GET /available — list all students not yet actively enrolled in a specific course
router.get('/available/:courseId', async (req, res) => {
  try {
    const { courseId } = req.params;
    
    // Get all users who are students/lab assistants
    const allUsersResult = await cybercoreQuery(`
      SELECT 
        user_id,
        email,
        first_name,
        last_name,
        role
      FROM cybercore_user 
      WHERE role IN ('student', 'lab_assistant', 'guest')
      ORDER BY last_name, first_name
    `);

    // Get users with ACTIVE enrollments in this course
    // Students with 'dropped', 'deleted', or 'completed' status can be re-added
    const enrolledResult = await query(`
      SELECT DISTINCT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND status = 'active'
    `, [courseId]);

    const enrolledIds = new Set(enrolledResult.rows.map(r => r.user_id));

    // Filter out only actively enrolled users
    const availableStudents = allUsersResult.rows.filter(u => !enrolledIds.has(u.user_id));

    res.json({ students: availableStudents });
  } catch (error) {
    console.error('[CLE] Get available students error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// LIST ALL INSTRUCTORS (for course builder)
// ============================================================================

// GET /instructors — list all instructors (admin only)
router.get('/instructors', async (req, res) => {
  try {
    // Get all users with instructor role or admin role
    const instructorsResult = await cybercoreQuery(`
      SELECT 
        user_id,
        email,
        first_name,
        last_name,
        role,
        organization
      FROM cybercore_user 
      WHERE role IN ('instructor', 'admin')
      ORDER BY last_name, first_name
    `);

    res.json({ instructors: instructorsResult.rows });
  } catch (error) {
    console.error('[CLE] Get instructors error:', error.message);
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
