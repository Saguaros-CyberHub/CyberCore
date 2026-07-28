/**
 * CLE Plugin — VM Management Routes (lane-native)
 * Mounted at /api/cle/courses/:courseId/vms
 *
 * Workstations are provisioned as per-student cybercore_lane rows (gateway LXC +
 * workstation VM) drawn from the course's reserved VXLAN block, through the
 * shared src/utils/lane-deployer.js — the same sequence the admin group deploy
 * uses for its attack boxes. cybercore_lane is the source of truth for the lane;
 * lane-deployer additionally registers each workstation in cybercore_resource /
 * vm_instance / allocation so the STUDENT sees it on their own dashboard.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { getGuacToken, GUAC_URL, GUAC_DS } = require('../../../../../src/utils/guacamole');
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');
const laneProvision = require('../utils/lane-provision');
const { getManagedCourse: getManagedCourseRow } = require('../utils/course-access');

const instructorOnly = requireRole('instructor', 'admin');

// Columns every provision path needs. os_family drives the NIC model (stock
// Windows images have no virtio-net driver, so a virtio NIC never DHCPs) and
// metadata carries console protocol / RDP credentials — omitting either is how
// a Windows template ends up deployed but unreachable.
const TEMPLATE_COLS = `
  id, template_key, os_name, os_family, os_version,
  template_vmid, node, provider_type, metadata
`;

/** Guacamole client launch URL (base64("<connId>\0c\0<datasource>")). */
function buildGuacLaunchUrl(connId) {
  const base = (process.env.GUAC_PUBLIC_BASE_URL || '/guac').replace(/\/$/, '');
  const clientToken = Buffer.from(`${connId}\0c\0${GUAC_DS}`).toString('base64');
  return `${base}/#/client/${clientToken}`;
}

/** Verify the course exists and the caller may manage it. Returns the course row
 *  (with its reserved-lab linkage) or null. Admin-aware via the shared helper. */
function getManagedCourse(courseId, user) {
  return getManagedCourseRow(courseId, user, 'course_id, course_name, challenge_id, challenge_key');
}

/** Load + validate the workstation template a provision request names. */
async function loadWorkstationTemplate(templateId) {
  const tpl = await cybercoreQuery(`
    SELECT ${TEMPLATE_COLS}
      FROM cybercore_template_catalog
     WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'
  `, [templateId]);
  if (tpl.rows.length === 0) {
    const err = new Error('Template not found or not active');
    err.status = 404;
    throw err;
  }
  const template = tpl.rows[0];
  if (!template.template_vmid) {
    const err = new Error(`Template '${template.os_name}' has no Proxmox VMID configured`);
    err.status = 409;
    throw err;
  }
  return template;
}

/** Resolve the course's reserved lab (VXLAN block + challenge key). */
async function loadCourseLab(course) {
  if (!course.challenge_id) {
    const err = new Error('Course has no reserved lab — recreate the course to provision its network');
    err.status = 409;
    throw err;
  }
  const lab = await laneProvision.resolveCourseLab(course.challenge_id);
  if (!lab) {
    const err = new Error('Reserved lab challenge missing for this course');
    err.status = 409;
    throw err;
  }
  return { challenge_key: lab.challengeKey, vxlan_block: lab.vxlanBlock };
}

/**
 * Resolve the students to provision: actively enrolled, with an email (Guacamole
 * accounts are email-keyed), and not already holding a lane in this course.
 * Returns { students, skipped }.
 */
async function resolveTargetStudents(courseId, requestedIds) {
  const enrolled = await query(
    `SELECT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND status = 'active'`,
    [courseId]
  );
  const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

  const ids = requestedIds ? requestedIds.filter(Boolean) : [...enrolledIds];
  const skipped = [];
  const candidates = [];
  for (const id of ids) {
    if (!enrolledIds.has(id)) { skipped.push({ student_id: id, reason: 'not enrolled' }); continue; }
    candidates.push(id);
  }
  if (candidates.length === 0) return { students: [], skipped };

  const users = await cybercoreQuery(
    `SELECT user_id, email FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
    [candidates]
  );
  const emailById = {};
  for (const r of users.rows) emailById[r.user_id] = r.email;

  // Students who already have a live lane in this course — re-provisioning would
  // collide on the gateway/workstation VMIDs for their VXLAN.
  const existing = await cybercoreQuery(
    `SELECT user_id FROM cybercore_lane
      WHERE user_id = ANY($1::uuid[])
        AND config->>'course_id' = $2
        AND status NOT IN ('deleted', 'error')`,
    [candidates, courseId]
  );
  const alreadyDeployed = new Set(existing.rows.map(r => r.user_id));

  const students = [];
  for (const id of candidates) {
    if (alreadyDeployed.has(id)) { skipped.push({ student_id: id, reason: 'already has a workstation' }); continue; }
    if (!emailById[id]) { skipped.push({ student_id: id, reason: 'no email on account' }); continue; }
    students.push({ id, email: emailById[id] });
  }
  return { students, skipped };
}

/** Kick off the background deploy. Shared by /provision and /provision-all. */
function startProvision({ courseId, courseName, challenge, template, students }) {
  laneProvision.provisionLanes({ courseId, courseName, challenge, template, students })
    .then(result => console.log(`[CLE] Provision finished for course ${courseId}:`, JSON.stringify({
      provisioned: result.provisioned.length, failed: result.failed.length,
    })))
    .catch(err => console.error(`[CLE] Provision failed for course ${courseId}: ${err.message}`));
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
        ip_confirmed:   cfg.ip_confirmed === true,
        has_console:    !!cfg.guac_connection_id,
        // How the student reaches it. The endpoint is always the lane gateway's
        // WAN transit IP (guacd has no route into the lane subnet); console_via
        // says which DNAT carries it — 'gateway' (our per-lane rule),
        // 'gateway-baked-dnat' (ours failed, using the template's built-in 3389
        // rule), or 'unreachable' (no rule for this protocol).
        console_via:      cfg.console_via || null,
        console_protocol: cfg.console_protocol || null,
        console_endpoint: cfg.console_host ? `${cfg.console_host}:${cfg.console_port}` : null,
        workstation_user: cfg.workstation_user || null,
        workstation_pass: cfg.workstation_pass || null,
        error:            cfg.error || null,
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
 * POST /provision — Provision workstation lanes for the named students.
 * Each student gets their own isolated lane (gateway + workstation) on their own
 * VXLAN, drawn from the course's reserved block. Responds immediately; lanes
 * surface via GET / polling and GET /provision-progress.
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

    const template = await loadWorkstationTemplate(template_id);
    const challenge = await loadCourseLab(course);
    const { students, skipped } = await resolveTargetStudents(courseId, student_ids);

    if (!students.length) {
      return res.status(400).json({ error: 'No eligible students to provision', skipped });
    }

    res.json({
      success: true,
      message: `Provisioning started for ${students.length} student(s)`,
      count: students.length,
      progress_url: `/api/cle/courses/${courseId}/vms/provision-progress`,
      ...(skipped.length ? { skipped } : {}),
    });

    startProvision({ courseId, courseName: course.course_name, challenge, template, students });
  } catch (error) {
    console.error('[CLE] Provision VMs error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * POST /provision-all — Provision a workstation for every actively-enrolled
 * student who doesn't already have one. This is the "deploy the class" button.
 *
 * Runs the same cluster capacity pre-flight the admin group deploy uses: without
 * `confirm: true` it returns a preview instead of deploying, so the instructor
 * sees the resource impact before committing a whole cohort.
 */
router.post('/provision-all', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { template_id, confirm } = req.body;
    if (!template_id) return res.status(400).json({ error: 'template_id is required' });

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const template = await loadWorkstationTemplate(template_id);
    const challenge = await loadCourseLab(course);
    const { students, skipped } = await resolveTargetStudents(courseId, null);

    if (!students.length) {
      return res.status(400).json({
        error: 'Every enrolled student already has a workstation, or none are eligible',
        skipped,
      });
    }

    if (!confirm) {
      try {
        // One workstation per lane; the gateway is counted by the guard itself.
        const preview = await buildDeployPreview({
          numLanes: students.length,
          attackBoxes: false,
          challengeVmCount: 1,
          proxmoxAPI,
          cybercoreQuery,
        });
        return res.json({
          preview: true,
          student_count: students.length,
          template: template.os_name,
          ...(skipped.length ? { skipped } : {}),
          ...preview,
        });
      } catch (err) {
        // A failed pre-flight must not block the deploy — the admin path treats
        // it the same way. Fall through and provision.
        console.error('[CLE] Pre-flight check failed:', err.message);
      }
    }

    res.json({
      success: true,
      message: `Provisioning started for ${students.length} student(s)`,
      count: students.length,
      progress_url: `/api/cle/courses/${courseId}/vms/provision-progress`,
      ...(skipped.length ? { skipped } : {}),
    });

    startProvision({ courseId, courseName: course.course_name, challenge, template, students });
  } catch (error) {
    console.error('[CLE] Provision-all error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * GET /provision-progress — Live phase/ETA for an in-flight class deploy.
 * 404 once the deploy has finished and aged out; the client should fall back to
 * polling GET / for lane status.
 */
router.get('/provision-progress', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const progress = laneProvision.getProvisionProgress(courseId);
    if (!progress) return res.status(404).json({ error: 'No active deployment for this course' });
    res.json(progress);
  } catch (error) {
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
 * gateway + Guac connection + workspace records + lane row).
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

    const result = await laneProvision.teardownLane(laneId);
    res.json({ success: true, message: 'Workstation lane removed', ...result });
  } catch (error) {
    console.error('[CLE] Delete VM error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
