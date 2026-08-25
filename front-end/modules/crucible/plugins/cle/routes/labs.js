/**
 * CLE Plugin — Vulnerable Lab Routes
 * Mounted at /api/cle/courses/:courseId/labs
 *
 * Deploys the vulnerable application an instructor assigns to students. Two
 * modes, both driven by utils/vuln-lab-provision.js:
 *
 *   'lane'   — a dedicated lab lane per student (gateway + challenge VMs + a
 *              Kali attack box) on the CHALLENGE'S OWN reserved VXLAN block.
 *              Identical to the admin Group Deploy, and the only mode that
 *              works for a v3/GOAD challenge such as CYBV 480.
 *   'attach' — graft the challenge onto the workstation lane the student
 *              already has in this course. No extra VXLAN, no second Kali.
 *
 * cle_course_material remains the assignment record students see; the lanes it
 * produced are found again by config.material_id.
 *
 * This endpoint used to insert those two bookkeeping rows and nothing else,
 * which is why "Deploy Labs" reported success while no VM ever appeared.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { resolveLaneWorkstationCredential } = require('../../../../../src/utils/lane-credentials');
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const challengeDeployer = require('../../../../../src/utils/challenge-lane-deployer');
const { getManagedCourse } = require('../utils/course-access');
const { resolveTargetStudents, excludeStudentsWithLab, combineExclusions, courseStaffIds } = require('../utils/students');
const vulnLab = require('../utils/vuln-lab-provision');
const audit = require('../../../../../src/utils/audit');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * Parse cle_course_material.content, which is a TEXT column holding JSON.
 * Legacy type='lab' rows predate that convention and can hold anything, so a
 * parse failure is normal and must not break the route reading it.
 */
function parseMaterialContent(content) {
  if (!content) return {};
  if (typeof content === 'object') return content;
  try {
    const parsed = JSON.parse(content);
    return (parsed && typeof parsed === 'object') ? parsed : {};
  } catch (_) {
    return {};
  }
}

/**
 * Record (or clear) why a student's redeploy failed, on the lab row.
 *
 * The 202 contract means the failure happens long after the response. In 'lane'
 * mode the lane goes 'error' and shows in the table, but in 'attach' mode there
 * is NO row to carry the error — the student's line would simply vanish and
 * never return. Persisting it here also survives a restart, which the in-memory
 * progress registry does not.
 */
async function setRedeployError(labId, userId, message) {
  // The ::text on the outside is not decorative — `content` is a TEXT column
  // holding JSON, so the jsonb result has to be rendered back to text on the way
  // in. NULLIF(content,'') guards the empty-string rows, which '' ::jsonb would
  // choke on. A legacy type='lab' row holding non-JSON still throws on the cast;
  // that is caught below, because failing to annotate an error must never be
  // louder than the error itself.
  const sql = message
    ? `UPDATE cle_course_material
          SET content = (COALESCE(NULLIF(content,''), '{}')::jsonb
                      || jsonb_build_object('redeploy_errors',
                           COALESCE(COALESCE(NULLIF(content,''), '{}')::jsonb->'redeploy_errors', '{}'::jsonb)
                           || jsonb_build_object($2::text, jsonb_build_object('message', $3::text, 'at', NOW()::text))))::text,
              updated_at = NOW()
        WHERE material_id = $1`
    : `UPDATE cle_course_material
          SET content = (COALESCE(NULLIF(content,''), '{}')::jsonb #- ARRAY['redeploy_errors', $2::text])::text,
              updated_at = NOW()
        WHERE material_id = $1`;
  const params = message ? [labId, userId, String(message).substring(0, 500)] : [labId, userId];
  await query(sql, params).catch(e =>
    console.error(`[CLE] Could not record redeploy state on lab ${labId}: ${e.message}`));
}

/** The course row every route here needs, or null when absent/denied. */
function getCourse(courseId, user) {
  return getManagedCourse(courseId, user, 'course_id, course_name, code, instructor_id');
}

/**
 * Emails to grant read-only Guacamole access alongside the student: the course's
 * own instructor plus anyone enrolled in a teaching role. cle_course_enrollment
 * has no 'instructor' role — the instructor lives on cle_course.instructor_id
 * and the enrollment roles are student / ta / guest / lab_assistant.
 */
async function courseInstructorEmails(courseId) {
  const rows = await query(
    `SELECT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND enrollment_role IN ('ta', 'lab_assistant') AND status = 'active'`,
    [courseId]
  ).catch(() => ({ rows: [] }));

  const course = await query(`SELECT instructor_id FROM cle_course WHERE course_id = $1`, [courseId])
    .catch(() => ({ rows: [] }));

  const ids = [
    ...rows.rows.map(r => r.user_id),
    ...(course.rows[0]?.instructor_id ? [course.rows[0].instructor_id] : []),
  ];
  if (ids.length === 0) return [];

  const users = await cybercoreQuery(
    `SELECT email FROM cybercore_user WHERE user_id = ANY($1::uuid[]) AND email IS NOT NULL`,
    [[...new Set(ids)]]
  ).catch(() => ({ rows: [] }));
  return users.rows.map(r => r.email);
}

/**
 * GET / — Vulnerable labs assigned in this course, with what each one actually
 * deployed. Assignment rows live in cle_db; the lanes and VMs live in
 * cybercore_db, so this is two queries stitched on material_id.
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    // The row, not just the access boolean: instructor_id labels a staff-owned
    // lane below.
    const course = await getCourse(courseId, req.user);
    if (!course) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    const labsResult = await query(`
      SELECT
        m.material_id AS lab_id,
        m.course_id,
        m.template_id,
        m.title AS lab_name,
        m.description AS objective,
        m.content,
        m.is_published,
        m.created_at,
        m.created_by,
        COUNT(DISTINCT s.user_id) AS student_count,
        COUNT(DISTINCT s.submission_id) AS submission_count
      FROM cle_course_material m
      LEFT JOIN cle_student_submission s ON m.material_id = s.material_id
      WHERE m.course_id = $1 AND m.type IN ('lab', 'vulnerable_lab')
      GROUP BY m.material_id, m.template_id, m.title, m.description, m.content,
               m.is_published, m.created_at, m.created_by
      ORDER BY m.created_at DESC
    `, [courseId]);

    const labs = labsResult.rows;
    if (labs.length === 0) return res.json({ labs: [] });

    // Every lane carrying one of these labs — either as its own lane
    // (config.material_id) or as an attached module on a workstation lane.
    const materialIds = labs.map(l => l.lab_id);
    const laneRows = await cybercoreQuery(`
      SELECT l.lane_id, l.user_id, l.vxlan_id, l.name, l.status, l.config,
             u.email AS student_email, u.first_name, u.last_name
        FROM cybercore_lane l
        JOIN cybercore_user u ON u.user_id = l.user_id
       WHERE l.status <> 'deleted'
         AND (
           l.config->>'material_id' = ANY($1::text[])
           OR (
             jsonb_typeof(l.config->'attached_modules') = 'array'
             AND EXISTS (
               SELECT 1 FROM jsonb_array_elements(l.config->'attached_modules') AS m
                WHERE m->>'material_id' = ANY($1::text[])
             )
           )
         )
       ORDER BY l.created_at DESC
    `, [materialIds]);

    // Live power state in one cluster call, so a stopped VM doesn't read as gone.
    let byVmid = {};
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of (resources || [])) byVmid[String(r.vmid)] = r;
    } catch (_) { /* fall back to lane status */ }

    const powerOf = (vmid) => byVmid[String(vmid)]?.status || 'unknown';

    // Flag-plant state per lane, so the instructor can see the lab is actually
    // capturable before a student reports it isn't.
    const laneIds = laneRows.rows.map(r => r.lane_id);
    const flagsByLane = {};
    if (laneIds.length > 0) {
      const flags = await cybercoreQuery(
        `SELECT lane_id, vm_name, flag_type, plant_status, captured_at
           FROM cybercore_lane_flag WHERE lane_id = ANY($1::uuid[])`,
        [laneIds]
      ).catch(() => ({ rows: [] }));
      for (const f of flags.rows) {
        const bucket = (flagsByLane[f.lane_id] ||= { planted: 0, failed: 0, pending: 0, captured: 0 });
        if (f.plant_status === 'planted') bucket.planted++;
        else if (f.plant_status === 'failed') bucket.failed++;
        else bucket.pending++;
        if (f.captured_at) bucket.captured++;
      }
    }

    // Who is actually on the roster. Lanes are found by material_id, which says
    // nothing about enrollment, so this is what separates a student's copy of
    // the lab from an instructor's own — and from a dropped student's leftovers.
    const enrolled = await query(
      `SELECT user_id FROM cle_course_enrollment WHERE course_id = $1 AND status = 'active'`,
      [courseId]
    ).catch(() => ({ rows: [] }));
    const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

    const deploymentsByMaterial = {};
    for (const row of laneRows.rows) {
      const cfg = row.config || {};
      // One resolve per lane, shared by both shapes below. A dedicated lab
      // lane has no workstations[] array at all (challenge-lane-deployer
      // writes only the flattened keys); an attached module rides a
      // workstation lane whose slot 0 is workstation_vmid.
      const wsCred = resolveLaneWorkstationCredential(cfg, cfg.workstation_vmid);
      const student = {
        lane_id: row.lane_id,
        user_id: row.user_id,
        student_email: row.student_email,
        first_name: row.first_name,
        last_name: row.last_name,
        enrolled: enrolledIds.has(row.user_id),
        is_self: row.user_id === req.user.userId,
        // Tells the instructor's own copy apart from a dropped student's
        // leftovers, which are the other reason a lane's owner is not enrolled.
        is_course_instructor: row.user_id === course.instructor_id,
        lane_status: row.status,
        vxlan_id: row.vxlan_id,
        flags: flagsByLane[row.lane_id] || null,
        error: cfg.error || null,
      };

      // Dedicated lab lane.
      if (cfg.material_id) {
        (deploymentsByMaterial[cfg.material_id] ||= []).push({
          ...student,
          mode: 'lane',
          vms: (cfg.vms || []).map(v => ({ ...v, power_state: powerOf(v.vm_id) })),
          attack_box_vm_id: cfg.attack_box_vm_id || null,
          attack_box_power: cfg.attack_box_vm_id ? powerOf(cfg.attack_box_vm_id) : null,
          workstation_user: wsCred.username,
          workstation_pass: wsCred.password,
          credentials_shared: wsCred.shared,
          has_console: !!cfg.guac_connection_id,
        });
      }

      // Attached module(s) on a workstation lane.
      for (const mod of (Array.isArray(cfg.attached_modules) ? cfg.attached_modules : [])) {
        if (!mod.material_id) continue;
        (deploymentsByMaterial[mod.material_id] ||= []).push({
          ...student,
          mode: 'attach',
          module_instance_id: mod.module_instance_id,
          vms: (mod.vms || []).map(v => ({ ...v, power_state: powerOf(v.vm_id) })),
          attack_box_vm_id: cfg.attack_box_vm_id || cfg.workstation_vmid || null,
          workstation_user: wsCred.username,
          workstation_pass: wsCred.password,
          credentials_shared: wsCred.shared,
          has_console: !!cfg.guac_connection_id,
        });
      }
    }

    // Per-student operations currently running. Needed for two reasons the lane
    // rows cannot cover: an 'attach' deploy never creates a lane in 'deploying'
    // at all, and a redeploy between teardown and re-create has no lane row of
    // any kind — so without this the poller stops, and the student's row silently
    // disappears from the table mid-rebuild.
    const inFlightByMaterial = {};
    const inFlightUserIds = new Set();
    for (const l of labs) {
      const ops = vulnLab.labOperationsInFlight(l.lab_id).filter(o => o.userId);
      inFlightByMaterial[l.lab_id] = ops;
      for (const o of ops) inFlightUserIds.add(o.userId);
    }
    const inFlightEmails = {};
    if (inFlightUserIds.size > 0) {
      const u = await cybercoreQuery(
        `SELECT user_id, email FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
        [[...inFlightUserIds]]
      ).catch(() => ({ rows: [] }));
      for (const r of u.rows) inFlightEmails[r.user_id] = r.email;
    }

    res.json({
      labs: labs.map(l => {
        const deployments = deploymentsByMaterial[l.lab_id] || [];
        const inFlight = inFlightByMaterial[l.lab_id] || [];
        return {
          ...l,
          deployments,
          deployed_count: deployments.length,
          in_flight: inFlight.map(o => ({
            user_id: o.userId,
            student_email: inFlightEmails[o.userId] || null,
            phase: o.phase,
            phase_detail: o.phase_detail,
          })),
          // Why a redeploy that failed after tearing down is still visible.
          redeploy_errors: parseMaterialContent(l.content).redeploy_errors || {},
          // A lane in 'deploying', or anything claimed in the progress registry,
          // means the poller should keep going.
          in_progress: deployments.some(d => d.lane_status === 'deploying') || inFlight.length > 0,
        };
      }),
    });
  } catch (error) {
    console.error('[CLE] Get labs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /deploy — Deploy a vulnerable lab to students.
 *
 * Responds 202 and deploys in the background, the same contract the workstation
 * path uses. Without `confirm: true` it returns a cluster-capacity preview
 * instead, so the resource cost is visible before a cohort is committed.
 *
 * Body: { template_id, student_ids[], learning_objective?, mode?, confirm? }
 */
router.post('/deploy', instructorOnly, async (req, res) => {
  try {
    // The CALLER — which is not necessarily this course's instructor. It was
    // called instructorId, and that name is precisely how an admin ended up
    // exempting themselves instead of the instructor they were deploying for.
    const callerId = req.user.userId;
    const { courseId } = req.params;
    const { template_id, student_ids, learning_objective, confirm } = req.body;
    const mode = req.body.mode || 'lane';
    // Absent means true. This path hardcoded `attackBoxes: true` before it was a
    // choice, so an older client and every course deployed before this field
    // existed must keep getting a Kali.
    const attackBoxes = req.body.attack_box === undefined ? true : req.body.attack_box === true;
    const consoleVm = req.body.console_vm || null;
    const extraWorkstations = Array.isArray(req.body.extra_workstations) ? req.body.extra_workstations : [];

    if (!template_id || !Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'template_id and non-empty student_ids array required' });
    }
    if (!vulnLab.MODES.includes(mode)) {
      return res.status(400).json({ error: `mode must be one of: ${vulnLab.MODES.join(', ')}` });
    }

    const course = await getCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const challenge = await vulnLab.loadChallenge(template_id);
    const caps = vulnLab.describeChallenge(challenge);

    // Reject an impossible combination up front rather than after the material
    // row exists — a 409 here leaves nothing behind to clean up.
    if (mode === 'lane' && !caps.can_deploy_lane) {
      return res.status(409).json({ error: `Cannot deploy '${challenge.name}' as its own environment: ${caps.lane_blockers.join('; ')}`, capabilities: caps });
    }
    if (mode === 'attach' && !caps.can_attach) {
      return res.status(409).json({ error: `Cannot attach '${challenge.name}' to an existing lane: ${caps.attach_blockers.join('; ')}`, capabilities: caps });
    }

    // Does this lab already exist for this course + challenge? Re-deploying to
    // more students must extend the existing assignment, not create a duplicate
    // one, or the student's board grows a second identical entry.
    const existing = await query(
      `SELECT material_id FROM cle_course_material
        WHERE course_id = $1 AND template_id = $2 AND type IN ('lab', 'vulnerable_lab')
        ORDER BY created_at DESC LIMIT 1`,
      [courseId, template_id]
    );
    const materialId = existing.rows[0]?.material_id || null;

    // excludeStudentsWithLab keys on the student's lane row, which a redeploy
    // deletes and then re-creates — so for those few seconds it cannot see them,
    // and a group deploy landing in that window would build a SECOND lane on a
    // second VXLAN while the redeploy is still working. excludeStudentsInFlight
    // covers exactly that gap.
    const { students, skipped } = await resolveTargetStudents(courseId, student_ids, {
      excludeIf: materialId
        ? combineExclusions(excludeStudentsWithLab(materialId), vulnLab.excludeStudentsInFlight(materialId))
        : undefined,
      // Course staff may be ticked in the picker and get their own copy of the
      // lab — an instructor walking it before assigning it, or an admin building
      // one FOR that instructor. getCourse above has already proved the caller
      // may manage this course; the exemption is from the ENROLLMENT check only,
      // and every collision exclusion still applies to them.
      extraUserIds: courseStaffIds(course, req.user),
    });
    if (!students.length) {
      return res.status(400).json({ error: 'No eligible students to deploy to', skipped });
    }

    // Capacity pre-flight. A failed check must not block the deploy — the admin
    // path treats it the same way — but a VXLAN shortfall in 'lane' mode is a
    // hard stop, because the deploy would fail partway with lanes already built.
    if (mode === 'lane') {
      const freeLanes = await vulnLab.countFreeLanes(caps.vxlan_block);
      if (freeLanes < students.length) {
        return res.status(409).json({
          error: `'${challenge.name}' has ${freeLanes} free lane(s) in its VXLAN block but ${students.length} student(s) were selected. `
               + `Tear down finished lanes, or recreate the environment with a larger max_lanes.`,
          free_lanes: freeLanes,
          required: students.length,
        });
      }

      if (!confirm) {
        try {
          const preview = await buildDeployPreview({
            numLanes: students.length,
            attackBoxes,
            challengeVmCount: caps.vm_count + extraWorkstations.length,
            proxmoxAPI,
            cybercoreQuery,
          });
          return res.json({
            preview: true,
            mode,
            student_count: students.length,
            free_lanes: freeLanes,
            challenge: caps,
            ...(skipped.length ? { skipped } : {}),
            ...preview,
          });
        } catch (err) {
          console.error('[CLE] Lab pre-flight check failed:', err.message);
        }
      }
    }

    // Create (or reuse) the assignment record. is_published must be TRUE or the
    // student-side board filters it out entirely — my-courses.loadAssignments
    // selects WHERE is_published = TRUE.
    let labId = materialId;
    if (!labId) {
      const labResult = await query(`
        INSERT INTO cle_course_material
          (course_id, template_id, title, type, description, content, is_published, created_by)
        VALUES ($1, $2, $3, 'vulnerable_lab', $4, $5, TRUE, $6)
        RETURNING material_id
      `, [
        courseId, template_id, challenge.name,
        learning_objective || challenge.description || '',
        JSON.stringify({
          challenge_key: challenge.challenge_key, mode,
          attack_box: attackBoxes, console_vm: consoleVm, extra_workstations: extraWorkstations,
        }),
        callerId,
      ]);
      labId = labResult.rows[0].material_id;
    } else {
      // Always force is_published on reuse, objective or not: my-courses filters
      // the student board on it, so a row created before this endpoint set it
      // (or unpublished by hand) would stay invisible to the students whose
      // machines are about to appear.
      // `content` is REWRITTEN, not left alone. The per-student redeploy route
      // reads its options back out of this column, so a blob written at first
      // deploy would make Redeploy rebuild a DIFFERENT environment than the one
      // the instructor last chose — silently, and only visible to the student.
      // The same staleness already bit `mode`; see the note in POST /:labId/redeploy.
      await query(
        `UPDATE cle_course_material
            SET description = COALESCE(NULLIF($2, ''), description),
                content = $3::jsonb,
                is_published = TRUE,
                updated_at = NOW()
          WHERE material_id = $1`,
        [labId, learning_objective || '', JSON.stringify({
          challenge_key: challenge.challenge_key, mode,
          attack_box: attackBoxes, console_vm: consoleVm, extra_workstations: extraWorkstations,
        })]
      );
    }

    // Track the assignment per student. This is what the gradebook reads — so a
    // self-deploying instructor is skipped: they are not on the roster, and a
    // submission row for them would put the instructor in their own gradebook
    // and inflate the lab's "Assigned to N".
    for (const student of students.filter(s => s.enrolled)) {
      await query(`
        INSERT INTO cle_student_submission (material_id, user_id)
        VALUES ($1, $2)
        ON CONFLICT (material_id, user_id) DO NOTHING
      `, [labId, student.id]).catch(err =>
        console.error(`[CLE] Could not record lab assignment for ${student.id}: ${err.message}`));
    }

    res.status(202).json({
      success: true,
      message: `Deploying '${challenge.name}' to ${students.length} student(s)`,
      lab_id: labId,
      mode,
      count: students.length,
      challenge: caps,
      progress_url: `/api/cle/courses/${courseId}/labs/${labId}/progress`,
      ...(skipped.length ? { skipped } : {}),
    });

    audit.batch({
      req,
      source: 'cle',
      action: 'lab.deployed',
      targetAction: 'lane.deployed',
      target: { type: 'material', id: labId, label: challenge.name },
      metadata: {
        course_id: courseId, mode, challenge_key: challenge.challenge_key,
        template_id, vm_count: caps.vm_count,
        ...(skipped.length ? { skipped: skipped.length } : {}),
      },
      targets: students.map(st => ({
        id: st.id,
        label: st.email,
        metadata: { course_id: courseId, material_id: labId, mode, challenge_key: challenge.challenge_key },
      })),
    });

    // The response is already sent, so a failure here can only be reported
    // through the lab's own state. Record it on the material row so GET /
    // can explain why nothing appeared, instead of showing an empty lab.
    const instructorEmails = await courseInstructorEmails(courseId).catch(() => []);
    vulnLab.deployVulnLab({
      course, challenge, students, materialId: labId, mode, instructorEmails,
      attackBoxes, consoleVm, extraWorkstations,
    })
      .then(result => console.log(
        `[CLE] Lab '${challenge.challenge_key}' (${mode}) for course ${courseId}: ` +
        `${result.provisioned.length} deployed, ${result.failed.length} failed`
      ))
      .catch(async (err) => {
        console.error(`[CLE] Lab deploy failed for course ${courseId}: ${err.message}`);
        await query(
          `UPDATE cle_course_material
              SET content = COALESCE(content, '{}')::jsonb || $2::jsonb, updated_at = NOW()
            WHERE material_id = $1`,
          [labId, JSON.stringify({ last_deploy_error: err.message, last_deploy_failed_at: new Date().toISOString() })]
        ).catch(e => console.error(`[CLE] Could not record deploy error on lab ${labId}: ${e.message}`));
      });
  } catch (error) {
    console.error('[CLE] Deploy labs error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * GET /:labId/progress — Live phase/ETA for an in-flight lab deploy.
 * 404 once it has finished and aged out; the client falls back to polling GET /.
 */
router.get('/:labId/progress', instructorOnly, async (req, res) => {
  try {
    const { courseId, labId } = req.params;
    if (!(await getCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
    // The lab must belong to THIS course. Progress records carry per-student
    // emails, and the id is a plain path parameter — without this an instructor
    // could read another course's deploy by pointing their own course at its id.
    const owned = await query(
      `SELECT material_id FROM cle_course_material WHERE material_id = $1 AND course_id = $2`,
      [labId, courseId]
    );
    if (owned.rows.length === 0) {
      return res.status(404).json({ error: 'Environment not found in this course' });
    }
    // ?user_id= reads one student's redeploy instead of the lab-wide deploy. No
    // extra authorization needed: a per-student key can only exist under a
    // material this course was just confirmed to own.
    const progress = vulnLab.getLabProgress(labId, req.query.user_id || null);
    if (!progress) return res.status(404).json({ error: 'No active deployment for this environment' });
    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /:labId — Remove a lab assignment AND everything it deployed.
 *
 * Teardown runs BEFORE the material row is deleted: the row is what ties the
 * lanes and attached modules back to this lab, so deleting it first (as this
 * route used to) would strand every VM with nothing left pointing at it.
 */
router.delete('/:labId', instructorOnly, async (req, res) => {
  try {
    const { courseId, labId } = req.params;
    if (!(await getCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    const owned = await query(
      `SELECT material_id FROM cle_course_material WHERE material_id = $1 AND course_id = $2`,
      [labId, courseId]
    );
    if (owned.rows.length === 0) {
      return res.status(404).json({ error: 'Environment not found in this course' });
    }

    const teardown = await vulnLab.teardownLab(labId);

    // Only drop the assignment once its infrastructure is gone. On failure BOTH
    // this row and the lane rows survive (teardownLanes marks the lanes 'error'
    // rather than deleting them), so Remove can genuinely be retried — and the
    // surviving VMs still have something pointing at them in the meantime.
    if (teardown.errors.length > 0) {
      return res.status(207).json({
        success: false,
        message: `Some machines could not be destroyed. The environment and its ${teardown.lanes_kept_for_retry} `
               + `lane record(s) were kept so you can press Remove again once the cause is cleared.`,
        ...teardown,
      });
    }

    await query(`DELETE FROM cle_course_material WHERE material_id = $1 AND course_id = $2`, [labId, courseId]);
    audit.log({
      req,
      action: 'lab.destroyed',
      source: 'cle',
      target: { type: 'material', id: labId },
      metadata: {
        course_id: courseId,
        lanes_destroyed: teardown.lanes_destroyed ?? null,
        vms_destroyed: teardown.vms_destroyed ?? null,
      },
    });
    res.json({ success: true, message: 'Environment removed', ...teardown });
  } catch (error) {
    console.error('[CLE] Delete lab error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

// ── per-student operations ───────────────────────────────────────────────────
//
// The class-wide DELETE above is all-or-nothing, which is too blunt for the
// common cases: one student's lane failed partway, one student broke their box.
// excludeStudentsWithLab deliberately refuses to redeploy on top of an existing
// lane (the VMIDs would collide), so without these two routes a single broken
// lane has no recovery short of tearing down the whole class.

/**
 * The lab row, if it belongs to this course. Every per-student route needs it,
 * and it is what proves the caller may touch the lanes underneath.
 */
async function getOwnedLab(labId, courseId) {
  const r = await query(
    `SELECT material_id, template_id, content FROM cle_course_material
      WHERE material_id = $1 AND course_id = $2`,
    [labId, courseId]
  );
  return r.rows[0] || null;
}

/** Which mode this student actually holds this lab in, or null if they hold none. */
async function probeStudentLabMode(materialId, userId) {
  const own = await cybercoreQuery(
    `SELECT 1 FROM cybercore_lane
      WHERE config->>'material_id' = $1 AND user_id = $2::uuid AND status <> 'deleted' LIMIT 1`,
    [materialId, userId]
  );
  if (own.rows.length > 0) return 'lane';

  const attached = await cybercoreQuery(
    `SELECT 1 FROM cybercore_lane
      WHERE user_id = $2::uuid AND status <> 'deleted'
        AND jsonb_typeof(config->'attached_modules') = 'array'
        AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(config->'attached_modules') AS m
           WHERE m->>'material_id' = $1
        ) LIMIT 1`,
    [materialId, userId]
  );
  return attached.rows.length > 0 ? 'attach' : null;
}

/**
 * DELETE /:labId/students/:userId — tear down ONE student's machines for this
 * lab, leaving the rest of the class and the assignment itself alone.
 *
 * Deliberately does NOT touch cle_student_submission. That row carries the
 * grade, the feedback and graded_at; destroying a student's machines is not a
 * reason to destroy their marks. The lab stays on their board, and Redeploy
 * below rebuilds it.
 *
 * Synchronous, like the class-wide DELETE — one student's teardown is short.
 */
router.delete('/:labId/students/:userId', instructorOnly, async (req, res) => {
  const { courseId, labId, userId } = req.params;
  let claimed = null;
  try {
    const course = await getCourse(courseId, req.user);
    if (!course) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
    if (!(await getOwnedLab(labId, courseId))) {
      return res.status(404).json({ error: 'Environment not found in this course' });
    }
    // extraUserIds: a staff copy of the lab has no enrollment row, so without
    // this it could be deployed and then never torn down from here. It must be
    // the same staff set POST /deploy used, or an admin can build the instructor
    // a lab that nobody can remove.
    const { students, skipped } = await resolveTargetStudents(courseId, [userId], {
      extraUserIds: courseStaffIds(course, req.user),
    });
    if (!students.length) {
      return res.status(404).json({
        error: skipped[0]?.reason
          ? `Cannot act on this student: ${skipped[0].reason}`
          : 'Student is not actively enrolled in this course',
      });
    }

    // Check and claim in ONE synchronous block, with every await already done.
    // Node cannot interleave two synchronous statements, so this is the only
    // arrangement that actually closes the double-click window — a check, an
    // await, then a claim would let two requests both pass the check.
    vulnLab.assertNoConflictingLabOperation({ materialId: labId, userId });
    claimed = vulnLab.progressIdForLabStudent(labId, userId);
    laneDeployer.initProgress(claimed, `Removing lab — ${students[0].email}`, 1);

    const teardown = await vulnLab.teardownLabForStudent({
      materialId: labId, userId, ignoreProgressId: claimed,
    });

    // Same two-grade contract as the class-wide route: on failure the lane rows
    // survive as 'error', still pointing at whatever is still running, so this
    // can genuinely be pressed again.
    if (teardown.errors.length > 0) {
      return res.status(207).json({
        success: false,
        message: `Some of ${students[0].email}'s machines could not be destroyed. `
               + `Their lane record was kept so you can press Tear down again once the cause is cleared.`,
        ...teardown,
      });
    }

    audit.log({
      req,
      action: 'lane.destroyed',
      source: 'cle',
      target:     { type: 'material', id: labId },
      targetUser: { id: userId, label: students[0].email },
      metadata: { course_id: courseId, material_id: labId, per_student: true },
    });

    res.json({
      success: true,
      message: `Tore down ${students[0].email}'s machines for this environment`,
      ...teardown,
    });
  } catch (error) {
    console.error('[CLE] Per-student lab teardown error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  } finally {
    // A leaked claim would 409 every future operation on this lab for an hour.
    if (claimed) laneDeployer.finishProgress(claimed);
  }
});

/**
 * Everything a rebuild needs to know about ONE student, resolved BEFORE
 * anything is destroyed.
 *
 * Split out so the single-student route and the bulk route cannot drift. Every
 * check here exists because doing it after teardown would leave the student
 * with nothing and no way back: a template deactivated since the original
 * deploy, a mode the challenge can no longer satisfy, an exhausted VXLAN block.
 *
 * @throws {Error & {status:number}}
 */
async function planStudentRedeploy({ courseId, course, lab, labId, userId, req }) {
  // extraUserIds: a staff copy of the lab has no enrollment row, and must
  // still be rebuildable. Same staff set POST /deploy used.
  const { students, skipped } = await resolveTargetStudents(courseId, [userId], {
    extraUserIds: courseStaffIds(course, req.user),
  });
  if (!students.length) {
    const e = new Error(skipped[0]?.reason
      ? `Cannot redeploy for this student: ${skipped[0].reason}`
      : 'Student is not actively enrolled in this course');
    e.status = 404; throw e;
  }
  const student = students[0];

  const challenge = await vulnLab.loadChallenge(lab.template_id);
  const caps = vulnLab.describeChallenge(challenge);

  // What the student ACTUALLY holds, not what content.mode claims: that field
  // is written once at material creation and never updated when the same lab is
  // later deployed in the other mode.
  const held = await probeStudentLabMode(labId, userId);
  const savedOptions = parseMaterialContent(lab.content);
  const declared = savedOptions.mode;
  const mode = held || (vulnLab.MODES.includes(declared) ? declared : 'lane');

  // Replay the SHAPE the instructor chose, not just the mode. Without these a
  // rebuild quietly hands the student a different environment than their
  // classmates have, with nothing in the UI saying so.
  const attackBoxes = savedOptions.attack_box === undefined ? true : savedOptions.attack_box === true;
  const consoleVm = savedOptions.console_vm || null;
  const extraWorkstations = Array.isArray(savedOptions.extra_workstations)
    ? savedOptions.extra_workstations : [];

  if (mode === 'lane' && !caps.can_deploy_lane) {
    const e = new Error(`Cannot rebuild '${challenge.name}' as its own environment: ${caps.lane_blockers.join('; ')}`);
    e.status = 409; e.capabilities = caps; throw e;
  }
  if (mode === 'attach' && !caps.can_attach) {
    const e = new Error(`Cannot re-attach '${challenge.name}': ${caps.attach_blockers.join('; ')}`);
    e.status = 409; e.capabilities = caps; throw e;
  }

  return { student, challenge, caps, mode, held, attackBoxes, consoleVm, extraWorkstations };
}

/**
 * Teardown then deploy for ONE student, in that order and never overlapped.
 *
 * Runs after the response is already sent, so failures can only be reported
 * through the progress entry and the persisted redeploy_errors.
 *
 * @returns {Promise<boolean>} true when the student ended up with machines
 */
async function executeStudentRedeploy({
  courseId, course, labId, userId, plan, resetFlags, progressId,
}) {
  const { student, challenge, mode, attackBoxes, consoleVm, extraWorkstations } = plan;
  const fail = async (message) => {
    const live = (global._batchDeployProgress || {})[progressId];
    if (live) { live.error = message; live.phase_detail = `Redeploy failed: ${message}`; }
    await setRedeployError(labId, userId, message);
    console.error(`[CLE] Redeploy failed for ${userId} on lab ${labId}: ${message}`);
  };

  try {
    const teardown = await vulnLab.teardownLabForStudent({
      materialId: labId, userId, ignoreProgressId: progressId,
    });

    // Refuse to build on top of survivors. Their VMIDs are derived from the
    // VXLAN, so the rebuild would clone straight into machines that are still
    // running and fail at the first clone with "VM already exists".
    if (!teardown.safe_to_redeploy) {
      await fail(
        `Could not fully tear down the current deployment, so it was not rebuilt: `
        + teardown.errors.slice(0, 3).join('; ')
      );
      return false;
    }

    // Flags CARRY OVER by default, so rebuilding a broken box never costs a
    // student work they already did. reset_flags inverts it.
    let flagSeeds = teardown.flag_snapshot || null;
    if (resetFlags) {
      flagSeeds = null;
      const deleted = await vulnLab.resetFlagsForDetached(teardown.detached_instances);
      if (deleted > 0) {
        console.log(`[CLE] Reset ${deleted} flag(s) for ${student.email} on lab ${labId}`);
      }
    }

    const instructorEmails = await courseInstructorEmails(courseId).catch(() => []);
    const result = await vulnLab.deployVulnLab({
      course, challenge, students: [student], materialId: labId, mode,
      instructorEmails, progressId,
      flagSeeds: mode === 'lane' ? flagSeeds : null,
      attackBoxes,
      ...(mode === 'lane' ? { consoleVm, extraWorkstations } : {}),
    });

    if ((result.failed || []).length > 0) {
      await fail(result.failed[0].reason || 'the rebuild did not complete');
      return false;
    }

    await setRedeployError(labId, userId, null);
    console.log(
      `[CLE] Redeployed ${student.email}'s '${challenge.challenge_key}' (${mode}) on lab ${labId}`);
    return true;
  } catch (err) {
    await fail(err.message);
    return false;
  }
}

// A bulk cluster operation is nothing like a bulk DB write. 50 students of a
// four-machine environment is 200 VMs; the per-student loop is sequential, so
// this is really a bound on how long one request may hold the lab lock.
const MAX_BULK_STUDENTS = 50;

/**
 * Validate and de-duplicate a bulk request's user_ids.
 *
 * @throws {Error & {status:400}}
 */
function parseBulkUserIds(body) {
  const raw = (body || {}).user_ids;
  if (!Array.isArray(raw) || raw.length === 0) {
    const e = new Error('non-empty user_ids array required'); e.status = 400; throw e;
  }
  const ids = [...new Set(raw.filter(v => typeof v === 'string' && v.trim()).map(v => v.trim()))];
  if (ids.length > MAX_BULK_STUDENTS) {
    const e = new Error(
      `select at most ${MAX_BULK_STUDENTS} students at a time (got ${ids.length})`);
    e.status = 400; throw e;
  }
  if (!ids.length) { const e = new Error('no valid user ids in the request'); e.status = 400; throw e; }
  return ids;
}

/**
 * POST /:labId/students/:userId/redeploy — rebuild one student's machines.
 *
 * Teardown then deploy, in that order and never overlapped. Blue/green would
 * avoid the window where the student has nothing, and is technically possible
 * for a dedicated lane (the rebuild draws a different VXLAN), but is impossible
 * in 'attach' mode: two instances of one challenge on one lane collide on
 * hostnames, on the dnsmasq reservation, and on the lane_flag uniqueness of
 * (lane_id, vm_name, flag_type). One uniform sequence beats two.
 *
 * FLAGS ARE PRESERVED BY DEFAULT — the point of this route is to rescue a broken
 * box, not to reset the exercise. See the flag handling below for how, and
 * `reset_flags: true` to opt out.
 *
 * Body: { reset_flags?: boolean }
 * Responds 202 and works in the background, matching POST /deploy.
 */
router.post('/:labId/students/:userId/redeploy', instructorOnly, async (req, res) => {
  const { courseId, labId, userId } = req.params;
  const resetFlags = req.body?.reset_flags === true;

  // Resolved during pre-flight and reused by the background block. Re-deriving
  // any of it afterwards would be wrong as well as wasteful: `mode` in
  // particular is probed from what the student currently holds, and after
  // teardown they hold nothing, so a second probe would always say 'lane'.
  let claimed = null;
  let ctx = null;
  try {
    const course = await getCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const lab = await getOwnedLab(labId, courseId);
    if (!lab) return res.status(404).json({ error: 'Environment not found in this course' });

    // extraUserIds: see the teardown route — a staff copy is not an enrollment,
    // and must still be rebuildable.
    // One shared pre-flight, so this route and the bulk one below cannot
    // disagree about what a rebuild replays.
    const plan = await planStudentRedeploy({ courseId, course, lab, labId, userId, req });
    const { student, challenge, caps, mode, held, attackBoxes, consoleVm, extraWorkstations } = plan;

    // Capacity, checked BEFORE teardown. Afterwards is too late: an exhausted
    // block would leave the student with their machines destroyed and no way to
    // rebuild them. The lane they currently hold releases its id on teardown, so
    // it counts toward what will be available.
    if (mode === 'lane') {
      const freeLanes = await vulnLab.countFreeLanes(caps.vxlan_block);
      const willBeReleased = held === 'lane' ? 1 : 0;
      if (freeLanes + willBeReleased < 1) {
        return res.status(409).json({
          error: `'${challenge.name}' has no free lanes in its VXLAN block, so this student's lane could not be `
               + `rebuilt after being torn down. Remove a finished lane first.`,
          free_lanes: freeLanes,
        });
      }
    }

    // Check and claim synchronously — see the note on the DELETE above.
    vulnLab.assertNoConflictingLabOperation({ materialId: labId, userId });
    claimed = vulnLab.progressIdForLabStudent(labId, userId);
    const progress = laneDeployer.initProgress(claimed, `Redeploy ${challenge.name} — ${student.email}`, 1);
    laneDeployer.setPhase(progress, 'preparing', 'Tearing down the current deployment');
    ctx = { course, plan };

    audit.log({
      req,
      action: 'lane.redeployed',
      source: 'cle',
      target:     { type: 'material', id: labId, label: challenge.name },
      targetUser: { id: userId, label: student.email },
      metadata: { course_id: courseId, mode, reset_flags: resetFlags, challenge_key: challenge.challenge_key },
    });

    res.status(202).json({
      success: true,
      message: `Rebuilding ${student.email}'s machines for '${challenge.name}'`,
      lab_id: labId,
      user_id: userId,
      mode,
      reset_flags: resetFlags,
      progress_url: `/api/cle/courses/${courseId}/labs/${labId}/progress?user_id=${encodeURIComponent(userId)}`,
    });
  } catch (error) {
    console.error('[CLE] Redeploy pre-flight error:', error.message);
    if (claimed) { laneDeployer.finishProgress(claimed); claimed = null; }
    // Only the 202 itself can throw with headers already sent. Replying again
    // would throw a second time, out of an async handler Express 4 does not
    // catch — and the claim is already released, so there is nothing else to do.
    if (res.headersSent) return;
    return res.status(error.status || 500).json({ error: error.message });
  }

  // ── background ─────────────────────────────────────────────────────────────
  // The response is already sent; from here failures can only be reported
  // through the progress entry and the persisted redeploy_errors.
  const claimedId = claimed;
  const { plan } = ctx;
  (async () => {
    try {
      await executeStudentRedeploy({
        courseId, course: ctx.course, labId, userId, plan, resetFlags,
        progressId: claimedId,
      });
    } finally {
      laneDeployer.finishProgress(claimedId);
    }
  })();
});

/**
 * POST /:labId/students/:userId/rebuild-machines — rebuild SOME of one
 * student's machines, in place.
 *
 * The whole-environment Redeploy destroys the lane and builds a new one, which
 * costs the student every machine including the ones that were fine. This keeps
 * the lane, the gateway, the DHCP reservations, the consoles and the Guacamole
 * connections, and re-clones only the machines named — so a broken web01 does
 * not cost a domain the student has already worked in.
 *
 * Their captured flags survive automatically: cybercore_lane_flag CASCADEs off
 * the LANE row, which is not deleted here, and ensureLaneFlags re-plants with
 * ON CONFLICT DO UPDATE SET flag_value = <existing>.
 *
 * Refused, with an actionable message, when the environment cannot support it:
 * an attached environment (its unit is the module instance, not a VM) and a
 * live-GOAD one (the domain is provisioned across every machine at once, so a
 * lone rebuilt DC would come back outside it). Both point at the whole-
 * environment rebuild instead.
 *
 * Body: { vm_names: string[] }   Responds 202.
 */
router.post('/:labId/students/:userId/rebuild-machines', instructorOnly, async (req, res) => {
  const { courseId, labId, userId } = req.params;
  let claimed = null;
  let ctx = null;
  try {
    const names = req.body?.vm_names;
    if (!Array.isArray(names) || names.length === 0) {
      return res.status(400).json({ error: 'non-empty vm_names array required' });
    }
    const vmNames = [...new Set(
      names.filter(v => typeof v === 'string' && v.trim()).map(v => v.trim()))];
    if (!vmNames.length) {
      return res.status(400).json({ error: 'no valid machine names in the request' });
    }

    const course = await getCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    const lab = await getOwnedLab(labId, courseId);
    if (!lab) return res.status(404).json({ error: 'Environment not found in this course' });

    // Same staff exemption every other per-student route uses.
    const { students, skipped } = await resolveTargetStudents(courseId, [userId], {
      extraUserIds: courseStaffIds(course, req.user),
    });
    if (!students.length) {
      return res.status(404).json({
        error: skipped[0]?.reason
          ? `Cannot rebuild for this student: ${skipped[0].reason}`
          : 'Student is not actively enrolled in this course',
      });
    }
    const student = students[0];

    // The student's OWN lane for this environment. An attached environment has
    // no lane of its own — it rides the student's workstation lane — so this
    // finding nothing is itself the "attach mode" answer.
    const laneRes = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane
        WHERE user_id = $1 AND config->>'material_id' = $2
          AND status <> 'deleted'
        ORDER BY created_at DESC LIMIT 1`,
      [userId, labId]
    );
    if (!laneRes.rows.length) {
      return res.status(409).json({
        error: 'This student\u2019s copy of the environment is attached to their workstation '
             + 'lane rather than having one of its own, so its machines cannot be rebuilt '
             + 'individually. Use the whole-environment Redeploy.',
      });
    }
    const laneId = laneRes.rows[0].lane_id;

    // Check and claim in ONE synchronous block — see the per-student redeploy.
    // Student scope: another student on this lab is independent, but this
    // student's own redeploy or teardown must not overlap.
    vulnLab.assertNoConflictingLabOperation({ materialId: labId, userId });
    claimed = vulnLab.progressIdForLabStudent(labId, userId);
    const progress = laneDeployer.initProgress(
      claimed, `Rebuild machines \u2014 ${student.email}`, 1);
    laneDeployer.setPhase(progress, 'preparing',
      `Rebuilding ${vmNames.join(', ')}`);

    audit.log({
      req,
      action: 'lane.redeployed',
      source: 'cle',
      target:     { type: 'material', id: labId },
      targetUser: { id: userId, label: student.email },
      metadata: {
        course_id: courseId, material_id: labId, mode: 'in_place_vms',
        vm_names: vmNames, lane_id: laneId,
      },
    });

    res.status(202).json({
      success: true,
      message: `Rebuilding ${vmNames.length} machine(s) for ${student.email}`,
      lab_id: labId, user_id: userId, lane_id: laneId, vm_names: vmNames,
      progress_url: `/api/cle/courses/${courseId}/labs/${labId}/progress?user_id=${encodeURIComponent(userId)}`,
    });

    ctx = { laneId, vmNames, progress, email: student.email };
  } catch (error) {
    console.error('[CLE] Machine rebuild pre-flight error:', error.message);
    if (claimed) { laneDeployer.finishProgress(claimed); claimed = null; }
    if (res.headersSent) return;
    return res.status(error.status || 500).json({ error: error.message });
  }

  // ── background ───────────────────────────────────────────────────────────
  const claimedId = claimed;
  const { laneId, vmNames, progress, email } = ctx;
  (async () => {
    try {
      const r = await challengeDeployer.rebuildLaneChallengeVms({
        laneId, vmNames, progress,
      });
      if (r.errors.length) {
        // Persisted, so it outlives the hour-long progress entry and a restart —
        // and so the Environments table can badge the row.
        await setRedeployError(labId, userId, r.errors[0]);
        progress.failed++;
      } else {
        await setRedeployError(labId, userId, null);
        progress.succeeded++;
      }
      progress.completed = 1;
    } catch (err) {
      // A pre-flight throw means nothing was destroyed and the student still
      // has every machine — say so rather than reporting a half-rebuild.
      const msg = err.destroyed === false
        ? `${err.message} Nothing was changed.`
        : err.message;
      await setRedeployError(labId, userId, msg);
      if (progress) { progress.error = msg; progress.failed++; progress.completed = 1; }
      console.error(`[CLE] Machine rebuild failed for ${email}: ${err.message}`);
    } finally {
      laneDeployer.finishProgress(claimedId);
    }
  })();
});

/**
 * POST /:labId/students/bulk-remove — tear down several students' machines.
 *
 * Synchronous, like the per-student DELETE it batches. The work is sequential
 * because teardownLabForStudent detaches module instances and re-reads lane
 * state; overlapping students on one lab is exactly what the mutex exists to
 * prevent.
 *
 * Claims the LAB-scoped progress key, not a per-student one. Group scope
 * conflicts with anything under this lab, which is precisely right: while a
 * bulk teardown runs, no per-student Redeploy or Tear down may start.
 */
router.post('/:labId/students/bulk-remove', instructorOnly, async (req, res) => {
  const { courseId, labId } = req.params;
  let claimed = null;
  try {
    const userIds = parseBulkUserIds(req.body);

    const course = await getCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    const lab = await getOwnedLab(labId, courseId);
    if (!lab) return res.status(404).json({ error: 'Environment not found in this course' });

    const { students, skipped } = await resolveTargetStudents(courseId, userIds, {
      extraUserIds: courseStaffIds(course, req.user),
    });
    if (!students.length) {
      return res.status(404).json({
        error: 'None of the selected students can be acted on in this course', skipped,
      });
    }

    // Check and claim in ONE synchronous block, every await already done.
    vulnLab.assertNoConflictingLabOperation({ materialId: labId, userId: null });
    claimed = vulnLab.progressIdForLab(labId);
    const progress = laneDeployer.initProgress(
      claimed, `Tearing down \u2014 ${students.length} student(s)`, students.length);
    laneDeployer.setPhase(progress, 'preparing',
      `Tearing down ${students.length} deployment(s)`);

    const results = [];
    let done = 0;
    for (const st of students) {
      try {
        const t = await vulnLab.teardownLabForStudent({
          materialId: labId, userId: st.id, ignoreProgressId: claimed,
        });
        const ok = (t.errors || []).length === 0;
        if (ok) progress.succeeded++; else progress.failed++;
        results.push({
          user_id: st.id, email: st.email, success: ok,
          errors: (t.errors || []).slice(0, 3),
        });
      } catch (e) {
        progress.failed++;
        results.push({ user_id: st.id, email: st.email, success: false, errors: [e.message] });
      }
      progress.completed = ++done;
      laneDeployer.setPhase(progress, 'deleting',
        `Tearing down: ${done}/${students.length} complete`);
    }

    const failed = results.filter(r => !r.success);

    audit.batch({
      req,
      source: 'cle',
      action: 'lane.destroyed_bulk',
      targetAction: 'lane.destroyed',
      // No label: getOwnedLab does not select a title, and the per-student
      // DELETE this batches omits it for the same reason.
      target: { type: 'material', id: labId },
      status: failed.length ? 'failure' : 'success',
      metadata: {
        course_id: courseId, material_id: labId,
        scope: 'selected', requested: students.length, failed: failed.length,
      },
      targets: results.map(r => ({
        id: r.user_id, label: r.email,
        status: r.success ? 'success' : 'failure',
        reason: r.success ? null : (r.errors[0] || null),
        metadata: { course_id: courseId, material_id: labId },
      })),
    });

    // 207 when any student kept machines: the same two-grade contract the
    // per-student DELETE uses, and their lane rows survive as 'error' still
    // pointing at whatever is running, so this can genuinely be pressed again.
    return res.status(failed.length ? 207 : 200).json({
      success: failed.length === 0,
      message: failed.length
        ? `${failed.length} of ${students.length} could not be fully torn down. Their lane records were kept so you can press Tear down again once the cause is cleared.`
        : `Tore down ${students.length} deployment(s) for this environment`,
      requested: students.length,
      torn_down: students.length - failed.length,
      results,
      ...(skipped.length ? { skipped } : {}),
    });
  } catch (error) {
    console.error('[CLE] Bulk lab teardown error:', error.message);
    return res.status(error.status || 500).json({ error: error.message });
  } finally {
    // A leaked claim would 409 every future operation on this lab for an hour.
    if (claimed) laneDeployer.finishProgress(claimed);
  }
});

/**
 * POST /:labId/students/bulk-redeploy — rebuild several students' machines.
 *
 * EVERY student is pre-flighted before ANY teardown starts. A deactivated
 * template or an exhausted VXLAN block must fail while the whole class still
 * has working machines, not after the first eight have been destroyed.
 *
 * Two levels of progress key, and both are load-bearing:
 *   - the LAB key is the mutex and the aggregate the banner polls. Group scope
 *     conflicts with everything under this lab, so no per-student operation can
 *     start underneath it.
 *   - each student additionally gets their own key for the actual work, because
 *     deployVulnLab calls initProgress AND finishProgress on whatever id it is
 *     handed. Sharing the lab key would reset the aggregate counters on every
 *     student and mark the whole batch complete after the first one. The
 *     per-student entries are also what light up each row's "working…" status
 *     in GET /, which comes from labOperationsInFlight.
 */
router.post('/:labId/students/bulk-redeploy', instructorOnly, async (req, res) => {
  const { courseId, labId } = req.params;
  const resetFlags = req.body?.reset_flags === true;
  let claimed = null;
  let ctx = null;
  try {
    const userIds = parseBulkUserIds(req.body);

    const course = await getCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });
    const lab = await getOwnedLab(labId, courseId);
    if (!lab) return res.status(404).json({ error: 'Environment not found in this course' });

    // Pre-flight EVERY student before anything is destroyed. One bad plan fails
    // the whole request while every machine is still running.
    const plans = [];
    const skipped = [];
    for (const userId of userIds) {
      try {
        plans.push({
          userId,
          plan: await planStudentRedeploy({ courseId, course, lab, labId, userId, req }),
        });
      } catch (e) {
        // A student who is simply not on the roster any more is a skip; anything
        // else is a real problem with the environment and fails the request.
        if (e.status === 404) skipped.push({ user_id: userId, reason: e.message });
        else throw e;
      }
    }
    if (!plans.length) {
      return res.status(404).json({
        error: 'None of the selected students can be rebuilt for this environment', skipped,
      });
    }

    // Capacity for the WHOLE batch, before any teardown. Each lane-mode student
    // releases their own lane, so that is what they need back.
    const laneMode = plans.filter(p => p.plan.mode === 'lane');
    if (laneMode.length) {
      const block = laneMode[0].plan.caps.vxlan_block;
      const free = await vulnLab.countFreeLanes(block);
      const released = laneMode.filter(p => p.plan.held === 'lane').length;
      if (free + released < laneMode.length) {
        const e = new Error(
          `Not enough free lanes to rebuild ${laneMode.length} student(s): ${free} free plus ${released} that would be released. Remove a finished environment first.`);
        e.status = 409; throw e;
      }
    }

    // Check and claim synchronously — see the per-student route.
    vulnLab.assertNoConflictingLabOperation({ materialId: labId, userId: null });
    claimed = vulnLab.progressIdForLab(labId);
    const progress = laneDeployer.initProgress(
      claimed, `Redeploy \u2014 ${plans.length} student(s)`, plans.length);
    laneDeployer.setPhase(progress, 'preparing', 'Rebuilding deployments');

    ctx = { course, lab, plans };

    audit.batch({
      req,
      source: 'cle',
      action: 'lane.redeployed_bulk',
      targetAction: 'lane.redeployed',
      target: { type: 'material', id: labId, label: plans[0].plan.challenge.name },
      metadata: {
        course_id: courseId, material_id: labId,
        scope: 'selected', reset_flags: resetFlags, student_count: plans.length,
        challenge_key: plans[0].plan.challenge.challenge_key,
      },
      targets: plans.map(p => ({
        id: p.userId, label: p.plan.student.email,
        metadata: { course_id: courseId, material_id: labId, mode: p.plan.mode },
      })),
    });

    res.status(202).json({
      success: true,
      message: `Rebuilding ${plans.length} student(s) for '${plans[0].plan.challenge.name}'`,
      lab_id: labId,
      count: plans.length,
      reset_flags: resetFlags,
      students: plans.map(p => ({ user_id: p.userId, email: p.plan.student.email, mode: p.plan.mode })),
      progress_url: `/api/cle/courses/${courseId}/labs/${labId}/progress`,
      ...(skipped.length ? { skipped } : {}),
    });
  } catch (error) {
    console.error('[CLE] Bulk redeploy pre-flight error:', error.message);
    if (claimed) { laneDeployer.finishProgress(claimed); claimed = null; }
    if (res.headersSent) return;
    return res.status(error.status || 500).json({ error: error.message });
  }

  // ── background ───────────────────────────────────────────────────────────
  const claimedId = claimed;
  const { course, plans } = ctx;
  (async () => {
    let done = 0;
    try {
      for (const { userId, plan } of plans) {
        // A per-student key, because deployVulnLab init/finishes whatever id it
        // is handed — the lab key must survive the whole batch.
        const studentKey = vulnLab.progressIdForLabStudent(labId, userId);
        laneDeployer.initProgress(
          studentKey, `Redeploy — ${plan.student.email}`, 1);
        try {
          const ok = await executeStudentRedeploy({
            courseId, course, labId, userId, plan, resetFlags,
            progressId: studentKey,
          });
          const agg = (global._batchDeployProgress || {})[claimedId];
          if (agg) { if (ok) agg.succeeded++; else agg.failed++; }
        } finally {
          laneDeployer.finishProgress(studentKey);
        }
        const agg = (global._batchDeployProgress || {})[claimedId];
        if (agg) {
          agg.completed = ++done;
          laneDeployer.setPhase(agg, 'cloning',
            `Rebuilding: ${done}/${plans.length} complete`);
        }
      }
    } catch (err) {
      const agg = (global._batchDeployProgress || {})[claimedId];
      if (agg) agg.error = err.message;
      console.error(`[CLE] Bulk redeploy on lab ${labId} failed: ${err.message}`);
    } finally {
      laneDeployer.finishProgress(claimedId);
    }
  })();
});

module.exports = router;
