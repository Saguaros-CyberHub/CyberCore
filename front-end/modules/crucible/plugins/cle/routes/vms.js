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
    // Step 1: Get VM assignments from cle_db
    const assignmentsResult = await query(`
      SELECT
        v.assignment_id AS vm_id,
        v.user_id,
        v.vm_instance_id,
        v.lane_id,
        v.access_level,
        v.status,
        v.expiration_date,
        v.created_at
      FROM cle_user_vm_assignment v
      WHERE v.course_id = $1
      ORDER BY v.created_at DESC
    `, [courseId]);

    // Step 2: Get user details from cybercore_db
    const userIds = [...new Set(assignmentsResult.rows.map(r => r.user_id))];
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

    // Step 3: Get VM instance details from cybercore_db
    const vmIds = [...new Set(assignmentsResult.rows.map(r => r.vm_instance_id).filter(Boolean))];
    let vmMap = {};
    if (vmIds.length > 0) {
      const vmsResult = await cybercoreQuery(`
        SELECT vm_instance_id, hostname
        FROM cybercore_vm_instance
        WHERE vm_instance_id = ANY($1)
      `, [vmIds]);
      vmsResult.rows.forEach(v => {
        vmMap[v.vm_instance_id] = v;
      });
    }

    // Step 4: Merge all data
    const vms = assignmentsResult.rows.map(v => ({
      vm_id: v.vm_id,
      user_id: v.user_id,
      student_email: userMap[v.user_id]?.email || 'unknown',
      first_name: userMap[v.user_id]?.first_name || '',
      last_name: userMap[v.user_id]?.last_name || '',
      vm_instance_id: v.vm_instance_id,
      vm_name: vmMap[v.vm_instance_id]?.hostname || 'unknown',
      lane_id: v.lane_id,
      access_level: v.access_level,
      status: v.status,
      expiration_date: v.expiration_date,
      created_at: v.created_at
    }));

    res.json({ vms });
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
    const { template_id, student_ids, create_separate_lanes, skip_lane } = req.body;

    // skip_lane is admin-only — enforce server-side
    const skipLane = skip_lane === true && req.user.role === 'admin';

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

        // Create lane if requested (skip_lane overrides create_separate_lanes)
        let laneId = null;
        if (create_separate_lanes && !skipLane) {
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
