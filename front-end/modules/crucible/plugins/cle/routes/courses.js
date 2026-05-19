/**
 * CLE Plugin — Courses Routes
 * Handles course management: list, view, edit, delete
 */

const express = require('express');
const router = express.Router();
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

const instructorOnly = requireRole('instructor', 'admin');
const adminOnly = requireRole('admin');

/**
 * GET /api/cle/courses — List all courses assigned to the instructor
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const userRole = req.user.role;

    // Get courses where instructor is assigned or all courses if admin
    let coursesResult;
    if (userRole === 'admin') {
      coursesResult = await query(`
        SELECT
          c.course_id,
          c.course_name,
          c.code,
          c.description,
          c.instructor_id,
          c.is_active,
          c.created_at,
          COUNT(DISTINCT e.user_id) AS student_count,
          COUNT(DISTINCT v.assignment_id) AS vm_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
        LEFT JOIN cle_user_vm_assignment v ON c.course_id = v.course_id AND v.status != 'deleted'
        GROUP BY c.course_id
        ORDER BY c.created_at DESC
      `);
    } else {
      coursesResult = await query(`
        SELECT
          c.course_id,
          c.course_name,
          c.code,
          c.description,
          c.instructor_id,
          c.is_active,
          c.created_at,
          COUNT(DISTINCT e.user_id) AS student_count,
          COUNT(DISTINCT v.assignment_id) AS vm_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
        LEFT JOIN cle_user_vm_assignment v ON c.course_id = v.course_id AND v.status != 'deleted'
        WHERE c.instructor_id = $1
        GROUP BY c.course_id
        ORDER BY c.created_at DESC
      `, [instructorId]);
    }

    res.json({ courses: coursesResult.rows });
  } catch (error) {
    console.error('[CLE] Get courses error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/cle/courses/:courseId — Get single course details
 */
router.get('/:courseId', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const userRole = req.user.role;
    const { courseId } = req.params;

    let courseResult;
    if (userRole === 'admin') {
      courseResult = await query(`
        SELECT
          c.course_id,
          c.course_name,
          c.code,
          c.description,
          c.instructor_id,
          c.is_active,
          c.created_at,
          c.updated_at,
          COUNT(DISTINCT e.user_id) AS student_count,
          COUNT(DISTINCT v.assignment_id) AS vm_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
        LEFT JOIN cle_user_vm_assignment v ON c.course_id = v.course_id AND v.status != 'deleted'
        WHERE c.course_id = $1
        GROUP BY c.course_id
      `, [courseId]);
    } else {
      courseResult = await query(`
        SELECT
          c.course_id,
          c.course_name,
          c.code,
          c.description,
          c.instructor_id,
          c.is_active,
          c.created_at,
          c.updated_at,
          COUNT(DISTINCT e.user_id) AS student_count,
          COUNT(DISTINCT v.assignment_id) AS vm_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
        LEFT JOIN cle_user_vm_assignment v ON c.course_id = v.course_id AND v.status != 'deleted'
        WHERE c.course_id = $1 AND c.instructor_id = $2
        GROUP BY c.course_id
      `, [courseId, instructorId]);
    }

    if (courseResult.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or access denied' });
    }

    res.json(courseResult.rows[0]);
  } catch (error) {
    console.error('[CLE] Get course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/cle/courses — Create a new course
 */
router.post('/', adminOnly, async (req, res) => {
  try {
    const { course_name, description, code, instructor_id, is_active } = req.body;

    // Validate required fields
    if (!course_name) {
      return res.status(400).json({ error: 'course_name is required' });
    }

    if (!instructor_id) {
      return res.status(400).json({ error: 'instructor_id is required' });
    }

    // Create course
    const createResult = await query(`
      INSERT INTO cle_course (course_name, description, code, instructor_id, is_active)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING course_id, course_name, description, code, instructor_id, is_active, created_at
    `, [course_name, description || null, code || null, instructor_id, is_active !== false]);

    res.status(201).json(createResult.rows[0]);
  } catch (error) {
    console.error('[CLE] Create course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * PATCH /api/cle/courses/:courseId — Update course details
 */
router.patch('/:courseId', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const userRole = req.user.role;
    const { courseId } = req.params;
    const { course_name, description, code, instructor_id, is_active } = req.body;

    // Verify instructor owns this course or admin
    let ownerResult;
    if (userRole === 'admin') {
      ownerResult = await query(`
        SELECT course_id FROM cle_course
        WHERE course_id = $1
      `, [courseId]);
    } else {
      ownerResult = await query(`
        SELECT course_id FROM cle_course
        WHERE course_id = $1 AND instructor_id = $2
      `, [courseId, instructorId]);
    }

    if (ownerResult.rows.length === 0) {
      return res.status(403).json({ error: 'You do not have permission to modify this course' });
    }

    // Update course
    const updateResult = await query(`
      UPDATE cle_course
      SET
        course_name = COALESCE($1, course_name),
        description = COALESCE($2, description),
        code = COALESCE($3, code),
        instructor_id = COALESCE($4, instructor_id),
        is_active = COALESCE($5, is_active),
        updated_at = NOW()
      WHERE course_id = $6
      RETURNING course_id, course_name, description, code, instructor_id, is_active, updated_at
    `, [course_name, description, code, instructor_id, is_active, courseId]);

    res.json(updateResult.rows[0]);
  } catch (error) {
    console.error('[CLE] Update course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /api/cle/courses/:courseId — Delete course (hard delete)
 */
router.delete('/:courseId', adminOnly, async (req, res) => {
  try {
    const { courseId } = req.params;

    // Verify course exists
    const existsResult = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1
    `, [courseId]);

    if (existsResult.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }

    // Delete course (will cascade to related records due to foreign key constraints)
    await query(`
      DELETE FROM cle_course
      WHERE course_id = $1
    `, [courseId]);

    res.json({ success: true, message: 'Course deleted' });
  } catch (error) {
    console.error('[CLE] Delete course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
