/**
 * CLE Plugin — VM Management Routes
 * Handles workstation VM provisioning for students
 * Mounted at /api/cle/courses/:courseId/vms
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET / — List provisioned VMs for course
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

    // Get VMs assigned to students in this course
    const vmsResult = await query(`
      SELECT
        v.assignment_id AS vm_id,
        v.user_id,
        u.email AS student_email,
        u.first_name,
        u.last_name,
        v.vm_instance_id,
        c.hostname AS vm_name,
        v.lane_id,
        v.access_level,
        v.status,
        v.expiration_date,
        v.created_at
      FROM cle_user_vm_assignment v
      JOIN cybercore_user u ON v.user_id = u.user_id
      LEFT JOIN cybercore_vm_instance c ON v.vm_instance_id = c.vm_instance_id
      WHERE v.course_id = $1
      ORDER BY v.created_at DESC
    `, [courseId]);

    res.json({ vms: vmsResult.rows });
  } catch (error) {
    console.error('[CLE] Get VMs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /provision — Provision workstation VMs for students
 */
router.post('/provision', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId } = req.params;
    const { template_id, student_ids, create_separate_lanes } = req.body;

    if (!template_id || !Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'template_id and non-empty student_ids array required' });
    }

    // Verify instructor owns course
    const courseOwner = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseOwner.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Get template details
    const templateResult = await cybercoreQuery(`
      SELECT * FROM cybercore_vm_template
      WHERE template_id = $1
    `, [template_id]);

    if (templateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Template not found' });
    }

    const template = templateResult.rows[0];
    const provisionedVMs = [];

    // Provision VM for each student
    for (const studentId of student_ids) {
      try {
        // Verify student is enrolled in this course
        const enrollmentCheck = await query(`
          SELECT * FROM cle_course_enrollment
          WHERE user_id = $1 AND course_id = $2 AND status = 'active'
        `, [studentId, courseId]);

        if (enrollmentCheck.rows.length === 0) {
          console.warn(`[CLE] Student ${studentId} not enrolled in course ${courseId}`);
          continue;
        }

        // Create lane if requested
        let laneId = null;
        if (create_separate_lanes) {
          const laneResult = await cybercoreQuery(`
            INSERT INTO cybercore_lane
              (course_id, user_id, status, created_at)
            VALUES ($1, $2, 'provisioning', NOW())
            RETURNING lane_id
          `, [courseId, studentId]);
          laneId = laneResult.rows[0].lane_id;
        }

        // Create VM instance in cybercore_vm_instance
        // TODO: Implement proper VM provisioning via Proxmox
        // For now, just create a placeholder record
        const vmResult = await cybercoreQuery(`
          SELECT vm_instance_id FROM cybercore_vm_instance
          WHERE template_id = $1
          LIMIT 1
        `, [template_id]);

        if (vmResult.rows.length === 0) {
          console.warn(`[CLE] No VM instances available for template ${template_id}`);
          continue;
        }

        const vmInstanceId = vmResult.rows[0].vm_instance_id;

        // Create assignment record
        const assignmentResult = await query(`
          INSERT INTO cle_user_vm_assignment
            (user_id, vm_instance_id, course_id, lane_id, access_level, status, created_at)
          VALUES ($1, $2, $3, $4, 'user', 'provisioning', NOW())
          RETURNING *
        `, [studentId, vmInstanceId, courseId, laneId]);

        provisionedVMs.push({
          student_id: studentId,
          vm_instance_id: vmInstanceId,
          lane_id: laneId,
          status: 'provisioning'
        });

      } catch (vmError) {
        console.error(`[CLE] Error provisioning VM for student ${studentId}:`, vmError.message);
      }
    }

    res.json({
      success: true,
      message: `Provisioning started for ${provisionedVMs.length} VMs`,
      vms: provisionedVMs
    });
  } catch (error) {
    console.error('[CLE] Provision VMs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /:vmId — Delete/deprovision a VM
 */
router.delete('/:vmId', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const { courseId, vmId } = req.params;

    // Verify instructor owns course
    const courseOwner = await query(`
      SELECT course_id FROM cle_course
      WHERE course_id = $1 AND instructor_id = $2
    `, [courseId, instructorId]);

    if (courseOwner.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Mark assignment as deleted
    await query(`
      UPDATE cle_user_vm_assignment
      SET status = 'deleted', updated_at = NOW()
      WHERE assignment_id = $1 AND course_id = $2
    `, [vmId, courseId]);

    res.json({ success: true, message: 'VM removed' });
  } catch (error) {
    console.error('[CLE] Delete VM error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
