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
 *
 * Scope: WORKSTATION lanes only. Vulnerable-lab lanes (routes/labs.js) also carry
 * config.course_id — every CLE read path keys on it — so every query here also
 * requires config.material_id IS NULL. Without that, lab lanes would surface in
 * the Workstations tab and could be destroyed by DELETE /:laneId, which bypasses
 * the lab's own teardown and leaves the assignment pointing at nothing.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { resolveLaneWorkstationCredential } = require('../../../../../src/utils/lane-credentials');
const { mintGuacToken, GUAC_URL, GUAC_DS } = require('../../../../../src/utils/guacamole');
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');
const { normalizeResourceSpec } = require('../../../../../src/utils/lane-deployer');
const { buildLaneTopology } = require('../../../../../src/utils/lane-topology');
const laneProvision = require('../utils/lane-provision');
const audit = require('../../../../../src/utils/audit');
const { getManagedCourse: getManagedCourseRow } = require('../utils/course-access');
const {
  resolveTargetStudents: resolveStudents,
  excludeStudentsWithCourseLane,
} = require('../utils/students');

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
  // `code` names the lanes (cle-<code>-<vxlanId>) — see lane-provision.laneNamePrefix.
  return getManagedCourseRow(courseId, user, 'course_id, course_name, code, challenge_id, challenge_key');
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

/**
 * Load every workstation template a provision request names, in SLOT ORDER.
 *
 * `template_ids: [elk, sensor]` is the multi-machine form — slot 0 lands on
 * <lane>.50 with the gateway's baked wan0:3389 DNAT, slot 1 on .51, and so on
 * (lane-deployer.js octetForSlot). `template_id` remains accepted so every
 * existing caller and the single-machine UI path are unchanged.
 *
 * Loops the single-row loader rather than one `= ANY($1::uuid[])` query on
 * purpose: `id` is a UUID column, so a malformed value in the array would turn
 * today's clean 404 into a 500, and N is 2.
 */
async function loadWorkstationTemplates(body) {
  const ids = Array.isArray(body.template_ids) && body.template_ids.length
    ? body.template_ids
    : (body.template_id ? [body.template_id] : []);

  if (!ids.length) {
    const err = new Error('template_id, or a non-empty template_ids array, is required');
    err.status = 400;
    throw err;
  }
  // Two slots sharing one catalog row would make attack-target.js's
  // template-identity rung ambiguous (it requires exactly one match), and would
  // collide outright if that template ever pins metadata.console_wan_port.
  if (new Set(ids.map(String)).size !== ids.length) {
    const err = new Error('template_ids must be distinct — two machines cannot share one catalog row');
    err.status = 400;
    throw err;
  }

  const templates = [];
  for (const id of ids) templates.push(await loadWorkstationTemplate(id));
  return templates;
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
 * accounts are email-keyed), and not already holding a lane in this course —
 * re-provisioning would collide on the gateway/workstation VMIDs for their VXLAN.
 *
 * The filter itself lives in utils/students.js so the vulnerable-lab path applies
 * exactly the same rules.
 *
 * `selfId` is the caller, passed only by the routes that let an instructor build
 * a workstation for THEMSELVES. It exempts that one id from the enrollment
 * requirement and nothing else: they still need an email, and the
 * already-has-a-lane exclusion applies to them exactly as it does to a student.
 * Every route that passes it has already run getManagedCourse, so the id is one
 * the caller is authorised to act on.
 */
function resolveTargetStudents(courseId, requestedIds, selfId = null) {
  return resolveStudents(courseId, requestedIds, {
    excludeIf: excludeStudentsWithCourseLane(courseId),
    extraUserIds: selfId ? [selfId] : [],
  });
}

/**
 * Validate the instructor's optional hardware sizing for this deploy. Returns
 * { cores, memory_mb, disk_gb } with only the fields they actually set — the
 * rest keep the catalog template's own sizing. Throws a 400-shaped error so a
 * mistyped core count is rejected up front rather than after N lanes exist.
 *
 * Sizing is applied to each CLONE before its first boot; the catalog template is
 * never modified, so two courses can deploy the same image at different sizes.
 */
function parseRequestedResources(body, slotCount = 1) {
  const raw = body.resources;

  // Explicit per-slot sizing: one entry per machine, index-matched to
  // template_ids. deployLanes already supports this (resourcesFor); holes keep
  // that slot's own template sizing.
  if (Array.isArray(raw)) {
    if (raw.length > slotCount) {
      const err = new Error(`resources has ${raw.length} entries for ${slotCount} machine(s)`);
      err.status = 400;
      throw err;
    }
    const out = raw.map((entry) => {
      const { resources, errors } = normalizeResourceSpec(entry);
      if (errors.length) {
        const err = new Error(errors.join('; '));
        err.status = 400;
        throw err;
      }
      return resources;
    });
    return out.some(Boolean) ? out : null;
  }

  const { resources, errors } = normalizeResourceSpec(raw);
  if (errors.length) {
    const err = new Error(errors.join('; '));
    err.status = 400;
    throw err;
  }

  // A SCALAR spec sizes machine 1 only, never every machine.
  //
  // The provision modal PRE-FILLS its CPU/RAM/disk inputs from the selected
  // template's live Proxmox sizing (courses.html seedResourceInputs), so a
  // resources object is sent on essentially every deploy whether or not the
  // instructor touched it. Applying it to all slots would clone a 4 GB Linux
  // sensor at the ELK box's 16 GB — silently, and multiplied by the cohort.
  // Later slots fall through to their own template's sizing instead.
  if (resources && slotCount > 1) {
    const perSlot = new Array(slotCount).fill(null);
    perSlot[0] = resources;
    return perSlot;
  }
  return resources;
}

/** Kick off the background deploy. Shared by /provision and /provision-all. */
function startProvision({ courseId, courseName, courseCode, challenge, templates, students, resources }) {
  // `templates` only: deployLanes treats a 1-element array exactly as it treats
  // a single `template`, so the single-machine path is byte-identical.
  laneProvision.provisionLanes({ courseId, courseName, courseCode, challenge, templates, students, resources })
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

    // Scoped by config.course_id, NOT by the roster. A lane's owner need not be
    // an enrolled student: an instructor can provision a workstation for
    // themselves, and a student who is dropped after their lane is built stops
    // being enrolled while their VMs keep running. Listing by enrollment hid
    // both — and a hidden lane cannot be deleted from this tab either, since
    // Delete is reached from the row.
    const enrolled = await query(
      `SELECT user_id FROM cle_course_enrollment WHERE course_id = $1 AND status = 'active'`,
      [courseId]
    );
    const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

    const lanesResult = await cybercoreQuery(`
      SELECT l.lane_id, l.status, l.vxlan_id, l.config, l.created_at, l.user_id,
             u.email AS student_email, u.first_name, u.last_name
        FROM cybercore_lane l
        JOIN cybercore_user u ON u.user_id = l.user_id
       WHERE l.config->>'course_id' = $1
         AND l.config->>'material_id' IS NULL
         AND l.status <> 'deleted'
       ORDER BY l.created_at DESC
    `, [courseId]);

    // Live power-state for the workstation VMs via a single cluster call.
    // Live power state. Falling back to the lane's own status when Proxmox is
    // unreachable is correct, but swallowing the reason is not: every row then
    // renders 'unknown' with nothing anywhere saying why, which is
    // indistinguishable from "the VMID does not match". Say which it is.
    let byVmid = {};
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of (resources || [])) byVmid[String(r.vmid)] = r;
      if (Object.keys(byVmid).length === 0) {
        console.warn('[CLE] /cluster/resources returned no VMs — every lane will show power state "unknown". Check the Proxmox API token\'s read permission on /.');
      }
    } catch (e) {
      console.warn(`[CLE] Could not read live VM state from Proxmox (${e.message}) — lanes will show their stored status instead of live power state.`);
    }

    const vms = lanesResult.rows.map(row => {
      const cfg = row.config || {};
      const wsCred = resolveLaneWorkstationCredential(cfg, cfg.workstation_vmid);
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
        // False for an instructor's own machine and for a dropped student's
        // leftovers — the UI labels those rather than passing them off as class
        // members.
        enrolled:       enrolledIds.has(row.user_id),
        is_self:        row.user_id === req.user.userId,
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
        // Through the shared resolver rather than reading the two flattened
        // keys directly, so this list, the labs list and the student's own
        // card cannot disagree about which slot's login they are showing.
        workstation_user: wsCred.username,
        workstation_pass: wsCred.password,
        // 'template' means the password is the image's built-in one and is
        // identical on every lane from it — not this student's alone.
        credentials_shared: wsCred.shared,
        // How the machine was actually sized. While it's still deploying only
        // the request exists; `resource_warnings` says what Proxmox refused
        // (e.g. a disk target smaller than the template's image).
        resources:          cfg.resources || cfg.requested_resources || null,
        resource_warnings:  cfg.resource_warnings || null,
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
    const { student_ids } = req.body;

    if (!Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'non-empty student_ids array required' });
    }

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Templates BEFORE resources: a scalar sizing spec is scoped by slot count.
    const templates = await loadWorkstationTemplates(req.body);
    const resources = parseRequestedResources(req.body, templates.length);
    const challenge = await loadCourseLab(course);
    // req.user.userId: an instructor may tick themselves in the picker and get
    // their own workstation on this course's network. provision-all below
    // deliberately does NOT pass it — "the whole class" is the roster.
    const { students, skipped } = await resolveTargetStudents(courseId, student_ids, req.user.userId);

    if (!students.length) {
      return res.status(400).json({ error: 'No eligible students to provision', skipped });
    }

    res.json({
      success: true,
      message: `Provisioning started for ${students.length} student(s)`,
      count: students.length,
      progress_url: `/api/cle/courses/${courseId}/vms/provision-progress`,
      ...(resources ? { resources } : {}),
      ...(skipped.length ? { skipped } : {}),
    });

    audit.batch({
      req,
      source: 'cle',
      action: 'vm.provisioned',
      targetAction: 'vm.provisioned',
      target: { type: 'course', id: courseId, label: course.course_name },
      // template_id/template stay singular-shaped so existing audit readers keep
      // working; template_ids carries the full slot order.
      metadata: {
        course_id: courseId,
        template: templates.map(t => t.os_name).join(' + '),
        template_id: templates[0].id,
        template_ids: templates.map(t => t.id),
        scope: 'selected',
      },
      targets: students.map(st => ({
        id: st.id, label: st.email,
        metadata: { course_id: courseId, template_id: templates[0].id },
      })),
    });

    startProvision({ courseId, courseName: course.course_name, courseCode: course.code, challenge, templates, students, resources });
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
    const { confirm } = req.body;

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Templates BEFORE resources: a scalar sizing spec is scoped by slot count.
    const templates = await loadWorkstationTemplates(req.body);
    const resources = parseRequestedResources(req.body, templates.length);
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
        // One entry per workstation slot; the gateway is counted by the guard
        // itself. attackBoxes stays false — this path never deploys a Kali.
        const preview = await buildDeployPreview({
          numLanes: students.length,
          attackBoxes: false,
          challengeVmCount: templates.length,
          proxmoxAPI,
          cybercoreQuery,
        });
        return res.json({
          preview: true,
          student_count: students.length,
          // Joined rather than an array: the UI renders this with escHtml, so a
          // string needs no client change to describe a two-machine deploy.
          template: templates.map(t => t.os_name).join(' + '),
          // Echoed so the confirm step can show what the cohort will cost at the
          // chosen size. buildDeployPreview gates on node headroom, not per-VM
          // sizing, so this is informational only.
          ...(resources ? { resources } : {}),
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
      ...(resources ? { resources } : {}),
      ...(skipped.length ? { skipped } : {}),
    });

    audit.batch({
      req,
      source: 'cle',
      action: 'vm.provisioned_bulk',
      targetAction: 'vm.provisioned',
      target: { type: 'course', id: courseId, label: course.course_name },
      metadata: {
        course_id: courseId,
        template: templates.map(t => t.os_name).join(' + '),
        template_id: templates[0].id,
        template_ids: templates.map(t => t.id),
        scope: 'whole_class',
      },
      targets: students.map(st => ({
        id: st.id, label: st.email,
        metadata: { course_id: courseId, template_id: templates[0].id },
      })),
    });

    startProvision({ courseId, courseName: course.course_name, courseCode: course.code, challenge, templates, students, resources });
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
      `SELECT config FROM cybercore_lane
        WHERE lane_id = $1 AND config->>'course_id' = $2
          AND config->>'material_id' IS NULL AND status <> 'deleted'`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    const connId = laneRes.rows[0].config?.guac_connection_id;
    if (!connId) return res.status(404).json({ error: 'No remote console is configured for this workstation yet' });

    // mintGuacToken, NOT getGuacToken: the cached token is the one this process
    // uses for every Guacamole call it makes. Handing that same token to a
    // browser means the console tab's logout (or its session ending) destroys
    // the orchestrator's session too, and every subsequent Guac call — console
    // provisioning, and the connection cleanup in lane teardown — fails with
    // 403 PERMISSION_DENIED until the cache turns over ~50 minutes later.
    let guacToken = null;
    try { guacToken = (await mintGuacToken()).authToken; } catch (e) {
      console.warn(`[CLE] Guac token fetch failed: ${e.message}`);
    }

    // An instructor opening a console on a student's machine is exactly the
    // kind of access an admin needs to be able to review after the fact.
    audit.log({
      req,
      action: 'access.console_opened',
      source: 'cle',
      target: { type: 'lane', id: laneId },
      metadata: { course_id: courseId, connection_id: connId },
    });

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
 * GET /:laneId/topology — the live network diagram for one of this course's lanes.
 *
 * The instructor-scoped door onto the same builder the admin route uses, so an
 * instructor sees the identical picture without needing admin. It cannot simply
 * be the admin route with a relaxed role: that handler does NO course scoping and
 * will describe any laneId it is handed, so widening it to `instructor` would let
 * every instructor read every lane in the range.
 *
 * Unlike the rest of this file, the material_id guard is deliberately DROPPED.
 * The scope note at the top of this file exists because DELETE would destroy a
 * lab lane through the wrong teardown path; a read-only diagram has no such
 * hazard, and an instructor wants to see a vulnerable-lab lane's topology at
 * least as much as a workstation's.
 */
router.get('/:laneId/topology', instructorOnly, async (req, res) => {
  try {
    const { courseId, laneId } = req.params;

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const laneRes = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane
        WHERE lane_id = $1 AND config->>'course_id' = $2 AND status <> 'deleted'`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    res.json(await buildLaneTopology(laneId));
  } catch (error) {
    console.error('[CLE] Topology error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
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
      // material_id IS NULL: a vulnerable-lab lane must be removed through
      // DELETE /labs/:labId, which also clears the assignment it belongs to.
      `SELECT lane_id FROM cybercore_lane
        WHERE lane_id = $1 AND config->>'course_id' = $2 AND config->>'material_id' IS NULL`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    const result = await laneProvision.teardownLane(laneId);
    audit.log({
      req,
      action: 'vm.destroyed',
      source: 'cle',
      target: { type: 'lane', id: laneId },
      metadata: { course_id: courseId },
    });
    res.json({ success: true, message: 'Workstation lane removed', ...result });
  } catch (error) {
    console.error('[CLE] Delete VM error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
