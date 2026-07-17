/**
 * CLE Plugin — Labs Management Routes
 * Handles vulnerable machine deployments for courses
 * Mounted at /api/cle/courses/:courseId/labs
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { canManageCourse } = require('../utils/course-access');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET / — List vulnerable labs in course
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Get vulnerable labs deployed to this course
    const labsResult = await query(`
      SELECT
        m.material_id AS lab_id,
        m.course_id,
        m.template_id,
        m.title AS lab_name,
        m.description AS objective,
        m.created_at,
        m.created_by,
        COUNT(DISTINCT s.user_id) AS student_count,
        COUNT(DISTINCT s.submission_id) AS submission_count
      FROM cle_course_material m
      LEFT JOIN cle_student_submission s ON m.material_id = s.material_id
      WHERE m.course_id = $1 AND m.type = 'lab'
      GROUP BY m.material_id, m.template_id, m.title, m.description, m.created_at, m.created_by
      ORDER BY m.created_at DESC
    `, [courseId]);

    res.json({ labs: labsResult.rows });
  } catch (error) {
    console.error('[CLE] Get labs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /deploy — Deploy vulnerable lab to students
 */
router.post('/deploy', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId } = req.params;
    const { template_id, student_ids, learning_objective } = req.body;

    if (!template_id || !Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'template_id and non-empty student_ids array required' });
    }

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Get template details
    const templateResult = await cybercoreQuery(`
      SELECT template_id, name, description FROM cybercore_challenge_template
      WHERE template_id = $1
    `, [template_id]);

    if (templateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Challenge template not found' });
    }

    const template = templateResult.rows[0];
    const deployedLabs = [];

    // Create course material record linking template to course
    const labResult = await query(`
      INSERT INTO cle_course_material
        (course_id, template_id, title, type, description, created_by)
      VALUES ($1, $2, $3, 'lab', $4, $5)
      RETURNING material_id
    `, [courseId, template_id, template.name, learning_objective || template.description || '', instructorId]);

    const labId = labResult.rows[0].material_id;

    // Assign lab to each student via submission tracking
    for (const studentId of student_ids) {
      try {
        // Verify student is enrolled
        const enrollmentCheck = await query(`
          SELECT * FROM cle_course_enrollment
          WHERE user_id = $1 AND course_id = $2 AND status = 'active'
        `, [studentId, courseId]);

        if (enrollmentCheck.rows.length === 0) {
          console.warn(`[CLE] Student ${studentId} not enrolled in course ${courseId}`);
          continue;
        }

        // Record student assignment to lab (initially pending/unstarted)
        const submissionResult = await query(`
          INSERT INTO cle_student_submission
            (material_id, user_id)
          VALUES ($1, $2)
          ON CONFLICT (material_id, user_id) DO NOTHING
          RETURNING submission_id
        `, [labId, studentId]);

        deployedLabs.push({
          student_id: studentId,
          material_id: labId,
          template: template.name,
          status: 'assigned'
        });

      } catch (labError) {
        console.error(`[CLE] Error deploying lab to student ${studentId}:`, labError.message);
      }
    }

    res.json({
      success: true,
      message: `Lab assignment created for ${deployedLabs.length} students`,
      labs: deployedLabs
    });
  } catch (error) {
    console.error('[CLE] Deploy labs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /:labId — Remove lab assignment
 */
router.delete('/:labId', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId, labId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Delete lab material and all related submissions
    await query(`
      DELETE FROM cle_course_material
      WHERE material_id = $1 AND course_id = $2
    `, [labId, courseId]);

    res.json({ success: true, message: 'Lab removed' });
  } catch (error) {
    console.error('[CLE] Delete lab error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
