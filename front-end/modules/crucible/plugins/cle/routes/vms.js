/**
 * CLE Plugin — VM Management Routes (lane-native)
 * Mounted at /api/cle/courses/:courseId/vms
 *
 * Workstations are provisioned as per-student cybercore_lane rows (gateway LXC +
 * workstation VM) drawn from the course's reserved VXLAN block. cybercore_lane
 * is the source of truth — no cybercore_resource / vm_instance / allocation.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { getGuacToken, GUAC_URL, GUAC_DS } = require('../../../../../src/utils/guacamole');
const laneProvision = require('../utils/lane-provision');
const { getManagedCourse: getManagedCourseRow } = require('../utils/course-access');

const instructorOnly = requireRole('instructor', 'admin');

/** Guacamole client launch URL (base64("<connId>\0c\0<datasource>")). */
function buildGuacLaunchUrl(connId) {
  const base = (process.env.GUAC_PUBLIC_BASE_URL || '/guac').replace(/\/$/, '');
  const clientToken = Buffer.from(`${connId}\0c\0${GUAC_DS}`).toString('base64');
  return `${base}/#/client/${clientToken}`;
}

/** Verify the course exists and the caller may manage it. Returns the course row
 *  (with its reserved-lab linkage) or null. Admin-aware via the shared helper. */
function getManagedCourse(courseId, user) {
  return getManagedCourseRow(courseId, user, 'course_id, challenge_id, challenge_key');
}

/**
 * GET / — List provisioned workstation lanes for all students in this course.
 * Reads cybercore_lane (source of truth) and live-syncs workstation power state.
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Enrolled students (CLE plugin DB) → look up their lanes (cybercore_db).
    const enrolled = await query(
      `SELECT user_id FROM cle_course_enrollment WHERE course_id = $1 AND status = 'active'`,
      [courseId]
    );
    const enrolledIds = enrolled.rows.map(r => r.user_id);
    if (enrolledIds.length === 0) return res.json({ vms: [] });

    const lanesResult = await cybercoreQuery(`
      SELECT l.lane_id, l.status, l.vxlan_id, l.config, l.created_at, l.user_id,
             u.email AS student_email, u.first_name, u.last_name
        FROM cybercore_lane l
        JOIN cybercore_user u ON u.user_id = l.user_id
       WHERE l.user_id = ANY($1)
         AND l.config->>'course_id' = $2
         AND l.status <> 'deleted'
       ORDER BY l.created_at DESC
    `, [enrolledIds, courseId]);

    // Live power-state for the workstation VMs via a single cluster call.
    let byVmid = {};
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of (resources || [])) byVmid[String(r.vmid)] = r;
    } catch (_) { /* fall back to lane status if Proxmox is unreachable */ }

    const vms = lanesResult.rows.map(row => {
      const cfg = row.config || {};
      const live = byVmid[String(cfg.workstation_vmid)];
      const powerState = live
        ? (live.status === 'running' ? 'running' : live.status === 'stopped' ? 'stopped' : live.status)
        : (row.status === 'active' ? 'unknown' : row.status);
      return {
        lane_id:        row.lane_id,
        lane_status:    row.status,                  // deploying | active | error
        power_state:    row.status === 'active' ? powerState : row.status,
        vxlan_id:       row.vxlan_id,
        user_id:        row.user_id,
        student_email:  row.student_email,
        first_name:     row.first_name,
        last_name:      row.last_name,
        template_id:    cfg.template_id || null,
        vm_name:        cfg.template_name || `cle-${row.vxlan_id}`,
        ip_address:     cfg.ip || null,
        has_console:    !!cfg.guac_connection_id,
        created_at:     row.created_at,
      };
    });

    res.json({ vms });
  } catch (error) {
    console.error('[CLE] Get VMs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /provision — Provision workstation lanes for students.
 * Each student gets a gateway LXC + workstation VM on their own VXLAN, drawn
 * from the course's reserved block. ≤3 deploy sequentially; >3 via the batch
 * deployer. Responds immediately; lanes appear as they reach 'deploying'.
 */
router.post('/provision', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { template_id, student_ids } = req.body;

    if (!template_id || !Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'template_id and non-empty student_ids array required' });
    }

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    if (!course.challenge_id) {
      return res.status(409).json({ error: 'Course has no reserved lab — recreate the course to provision its network' });
    }

    // Validate the workstation template.
    const tpl = await cybercoreQuery(`
      SELECT id, template_key, os_name, template_vmid, node, provider_type, metadata
        FROM cybercore_template_catalog
       WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'
    `, [template_id]);
    if (tpl.rows.length === 0) return res.status(404).json({ error: 'Template not found or not active' });
    const template = tpl.rows[0];

    // Resolve the course's reserved VXLAN block from its challenge.
    const chal = await cybercoreQuery(
      `SELECT challenge_key, spec FROM crucible_challenge WHERE challenge_id = $1`,
      [course.challenge_id]
    );
    if (chal.rows.length === 0) return res.status(409).json({ error: 'Reserved lab challenge missing for this course' });
    const spec = typeof chal.rows[0].spec === 'string' ? JSON.parse(chal.rows[0].spec) : (chal.rows[0].spec || {});
    const challenge = { challenge_key: chal.rows[0].challenge_key, vxlan_block: spec.vxlan_block };

    // Keep only enrolled students; pull their emails for Guac.
    const enrolledRows = await cybercoreQuery(`
      SELECT u.user_id, u.email
        FROM cybercore_user u
       WHERE u.user_id = ANY($1)
    `, [student_ids]);
    const emailById = {};
    for (const r of enrolledRows.rows) emailById[r.user_id] = r.email;

    const students = [];
    const failed = [];
    for (const sid of student_ids) {
      const ok = await query(
        `SELECT 1 FROM cle_course_enrollment WHERE user_id = $1 AND course_id = $2 AND status = 'active'`,
        [sid, courseId]
      );
      if (!ok.rows.length) { failed.push({ student_id: sid, reason: 'not enrolled' }); continue; }
      students.push({ id: sid, email: emailById[sid] || null });
    }

    if (!students.length) {
      return res.status(400).json({ error: 'No enrolled students to provision', failed });
    }

    // Respond now; deploy in the background (lanes surface via GET / polling).
    res.json({
      success: true,
      message: `Provisioning started for ${students.length} student(s)`,
      count: students.length,
      ...(failed.length ? { failed } : {}),
    });

    laneProvision.provisionLanes({ courseId, challenge, template, students })
      .then(result => console.log(`[CLE] Provision finished for course ${courseId}:`, JSON.stringify(result)))
      .catch(err => console.error(`[CLE] Provision failed for course ${courseId}: ${err.message}`));
  } catch (error) {
    console.error('[CLE] Provision VMs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /:laneId/console — Return a Guacamole launch URL for a student's
 * workstation, resolved from the lane's stored guac_connection_id.
 */
router.get('/:laneId/console', instructorOnly, async (req, res) => {
  try {
    const { courseId, laneId } = req.params;
    if (process.env.GUAC_ENABLED !== 'true') {
      return res.status(503).json({ error: 'Remote console is not enabled on this instance.' });
    }

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const laneRes = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND config->>'course_id' = $2 AND status <> 'deleted'`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    const connId = laneRes.rows[0].config?.guac_connection_id;
    if (!connId) return res.status(404).json({ error: 'No remote console is configured for this workstation yet' });

    let guacToken = null;
    try { guacToken = await getGuacToken(); } catch (e) {
      console.warn(`[CLE] Guac token fetch failed: ${e.message}`);
    }

    res.json({
      launchUrl: buildGuacLaunchUrl(connId),
      connection_id: connId,
      guac_url: GUAC_URL,
      ...(guacToken ? { guacToken, dataSource: GUAC_DS } : { clearGuacAuth: true }),
    });
  } catch (error) {
    console.error('[CLE] Console error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /:laneId — Tear down a student's workstation lane (workstation +
 * gateway + Guac connection + lane row).
 */
router.delete('/:laneId', instructorOnly, async (req, res) => {
  try {
    const { courseId, laneId } = req.params;

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Confirm the lane belongs to this course before destroying anything.
    const laneRes = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane WHERE lane_id = $1 AND config->>'course_id' = $2`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    await laneProvision.teardownLane(laneId);
    res.json({ success: true, message: 'Workstation lane removed' });
  } catch (error) {
    console.error('[CLE] Delete VM error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
