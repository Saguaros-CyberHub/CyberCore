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
 * GET / — List provisioned workstation VMs for all students in this course.
 * Queries cybercore_allocation so it reflects VMs deployed via the workstations
 * deploy route (the actual Proxmox-backed flow).
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const isAdmin = req.user.role === 'admin';

    // Verify course access
    const courseCheck = await query(
      isAdmin
        ? `SELECT course_id FROM cle_course WHERE course_id = $1`
        : `SELECT course_id FROM cle_course WHERE course_id = $1 AND instructor_id = $2`,
      isAdmin ? [courseId] : [courseId, req.user.userId]
    );
    if (courseCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Get enrolled student IDs for this course
    const enrolledResult = await query(`
      SELECT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND status = 'active'
    `, [courseId]);
    const enrolledIds = enrolledResult.rows.map(r => r.user_id);

    if (enrolledIds.length === 0) return res.json({ vms: [] });

    // Fetch workstation VMs allocated to any enrolled student
    const vmsResult = await cybercoreQuery(`
      SELECT
        vi.vm_instance_id,
        vi.power_state,
        vi.provider_node,
        vi.provider_vmid,
        vi.ip_address::text AS ip_address,
        r.name              AS vm_name,
        r.status            AS resource_status,
        r.metadata,
        a.user_id,
        a.starts_at         AS allocated_at,
        u.email             AS student_email,
        u.first_name,
        u.last_name
      FROM cybercore_allocation a
      JOIN cybercore_resource r     ON r.resource_id = a.resource_id
      JOIN cybercore_vm_instance vi ON vi.resource_id = r.resource_id
      JOIN cybercore_user u         ON u.user_id = a.user_id
      WHERE a.user_id = ANY($1)
        AND (r.metadata->>'vm_category') = 'workstation'
        AND vi.destroyed_at IS NULL
        AND (a.ends_at IS NULL OR a.ends_at > NOW())
      ORDER BY a.starts_at DESC
    `, [enrolledIds]);

    res.json({ vms: vmsResult.rows });
  } catch (error) {
    console.error('[CLE] Get VMs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /provision — Provision workstation VMs for students
 * Delegates actual Proxmox provisioning to POST /api/workstations/:templateId/deploy
 * using forUserId so each VM is allocated to the student, not the instructor.
 */
router.post('/provision', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { template_id, student_ids, skip_lane } = req.body;
    const isAdmin = req.user.role === 'admin';
    const skipLane = skip_lane === true && isAdmin;

    if (!template_id || !Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'template_id and non-empty student_ids array required' });
    }

    // Verify course access — admins bypass the instructor_id ownership check
    const courseCheck = await query(
      isAdmin
        ? `SELECT course_id FROM cle_course WHERE course_id = $1`
        : `SELECT course_id FROM cle_course WHERE course_id = $1 AND instructor_id = $2`,
      isAdmin ? [courseId] : [courseId, req.user.userId]
    );
    if (courseCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Validate template exists in the workstation catalog
    const tplCheck = await cybercoreQuery(`
      SELECT id FROM cybercore_template_catalog
      WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'
    `, [template_id]);
    if (tplCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Template not found or not active' });
    }

    const PORT = process.env.PORT || 3000;
    const authHeader = req.headers.authorization;
    const provisionedVMs = [];
    const failed = [];

    for (const studentId of student_ids) {
      try {
        // Verify student is enrolled in this course
        const enrolled = await query(`
          SELECT 1 FROM cle_course_enrollment
          WHERE user_id = $1 AND course_id = $2 AND status = 'active'
        `, [studentId, courseId]);

        if (!enrolled.rows.length) {
          console.warn(`[CLE] Student ${studentId} not enrolled in course ${courseId} — skipping`);
          failed.push({ student_id: studentId, reason: 'not enrolled' });
          continue;
        }

        // Delegate to the workstations deploy endpoint; forUserId allocates the VM to the student
        const deployRes = await fetch(`http://127.0.0.1:${PORT}/api/workstations/${template_id}/deploy`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
          },
          body: JSON.stringify({ skipLane, forUserId: studentId }),
        });

        const result = await deployRes.json();
        if (!deployRes.ok) {
          console.error(`[CLE] Deploy failed for student ${studentId}:`, result.error);
          failed.push({ student_id: studentId, reason: result.error || deployRes.status });
          continue;
        }

        provisionedVMs.push({ student_id: studentId, vm_id: result.vmId, status: 'deploying' });
      } catch (vmError) {
        console.error(`[CLE] Error provisioning VM for student ${studentId}:`, vmError.message);
        failed.push({ student_id: studentId, reason: vmError.message });
      }
    }

    res.json({
      success: true,
      message: `Provisioning started for ${provisionedVMs.length} of ${student_ids.length} VMs`,
      vms: provisionedVMs,
      ...(failed.length ? { failed } : {}),
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
