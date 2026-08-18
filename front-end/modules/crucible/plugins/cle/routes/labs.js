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
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const { getManagedCourse } = require('../utils/course-access');
const { resolveTargetStudents, excludeStudentsWithLab, combineExclusions } = require('../utils/students');
const vulnLab = require('../utils/vuln-lab-provision');

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
    if (!(await getCourse(courseId, req.user))) {
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
      const student = {
        lane_id: row.lane_id,
        user_id: row.user_id,
        student_email: row.student_email,
        first_name: row.first_name,
        last_name: row.last_name,
        enrolled: enrolledIds.has(row.user_id),
        is_self: row.user_id === req.user.userId,
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
          workstation_user: cfg.workstation_user || null,
          workstation_pass: cfg.workstation_pass || null,
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
          workstation_user: cfg.workstation_user || null,
          workstation_pass: cfg.workstation_pass || null,
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
    const instructorId = req.user.userId;
    const { courseId } = req.params;
    const { template_id, student_ids, learning_objective, confirm } = req.body;
    const mode = req.body.mode || 'lane';

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
      return res.status(409).json({ error: `Cannot deploy '${challenge.name}' as a lab lane: ${caps.lane_blockers.join('; ')}`, capabilities: caps });
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
      // An instructor may tick themselves in the picker and get their own copy
      // of the lab — to walk it before assigning it, or to demo it. getCourse
      // above has already proved they may manage this course; the exemption is
      // from the ENROLLMENT check only, and every collision exclusion still
      // applies to them.
      extraUserIds: [instructorId],
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
               + `Tear down finished lanes, or recreate the challenge with a larger max_lanes.`,
          free_lanes: freeLanes,
          required: students.length,
        });
      }

      if (!confirm) {
        try {
          const preview = await buildDeployPreview({
            numLanes: students.length,
            attackBoxes: true,
            challengeVmCount: caps.vm_count,
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
        JSON.stringify({ challenge_key: challenge.challenge_key, mode }),
        instructorId,
      ]);
      labId = labResult.rows[0].material_id;
    } else {
      // Always force is_published on reuse, objective or not: my-courses filters
      // the student board on it, so a row created before this endpoint set it
      // (or unpublished by hand) would stay invisible to the students whose
      // machines are about to appear.
      await query(
        `UPDATE cle_course_material
            SET description = COALESCE(NULLIF($2, ''), description),
                is_published = TRUE,
                updated_at = NOW()
          WHERE material_id = $1`,
        [labId, learning_objective || '']
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

    // The response is already sent, so a failure here can only be reported
    // through the lab's own state. Record it on the material row so GET /
    // can explain why nothing appeared, instead of showing an empty lab.
    const instructorEmails = await courseInstructorEmails(courseId).catch(() => []);
    vulnLab.deployVulnLab({ course, challenge, students, materialId: labId, mode, instructorEmails })
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
      return res.status(404).json({ error: 'Lab not found in this course' });
    }
    // ?user_id= reads one student's redeploy instead of the lab-wide deploy. No
    // extra authorization needed: a per-student key can only exist under a
    // material this course was just confirmed to own.
    const progress = vulnLab.getLabProgress(labId, req.query.user_id || null);
    if (!progress) return res.status(404).json({ error: 'No active deployment for this lab' });
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
      return res.status(404).json({ error: 'Lab not found in this course' });
    }

    const teardown = await vulnLab.teardownLab(labId);

    // Only drop the assignment once its infrastructure is gone. On failure BOTH
    // this row and the lane rows survive (teardownLanes marks the lanes 'error'
    // rather than deleting them), so Remove can genuinely be retried — and the
    // surviving VMs still have something pointing at them in the meantime.
    if (teardown.errors.length > 0) {
      return res.status(207).json({
        success: false,
        message: `Some machines could not be destroyed. The lab and its ${teardown.lanes_kept_for_retry} `
               + `lane record(s) were kept so you can press Remove again once the cause is cleared.`,
        ...teardown,
      });
    }

    await query(`DELETE FROM cle_course_material WHERE material_id = $1 AND course_id = $2`, [labId, courseId]);
    res.json({ success: true, message: 'Lab removed', ...teardown });
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
    if (!(await getCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }
    if (!(await getOwnedLab(labId, courseId))) {
      return res.status(404).json({ error: 'Lab not found in this course' });
    }
    // extraUserIds: an instructor's own copy of the lab has no enrollment row,
    // so without this they could deploy one and never tear it down from here.
    const { students, skipped } = await resolveTargetStudents(courseId, [userId], {
      extraUserIds: [req.user.userId],
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

    res.json({
      success: true,
      message: `Tore down ${students[0].email}'s machines for this lab`,
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
    if (!lab) return res.status(404).json({ error: 'Lab not found in this course' });

    // extraUserIds: see the teardown route — the instructor's own copy is not
    // an enrollment, and must still be rebuildable.
    const { students, skipped } = await resolveTargetStudents(courseId, [userId], {
      extraUserIds: [req.user.userId],
    });
    if (!students.length) {
      return res.status(404).json({
        error: skipped[0]?.reason
          ? `Cannot redeploy for this student: ${skipped[0].reason}`
          : 'Student is not actively enrolled in this course',
      });
    }
    const student = students[0];

    // Resolve the challenge BEFORE destroying anything. A template deactivated
    // since the original deploy must fail here, while the student still has
    // working machines — not after teardown, which would leave them with none.
    const challenge = await vulnLab.loadChallenge(lab.template_id);
    const caps = vulnLab.describeChallenge(challenge);

    // What the student ACTUALLY holds, not what content.mode claims. That field
    // is written once at material creation and never updated when the same lab
    // is later deployed in the other mode, so it can disagree with reality.
    const held = await probeStudentLabMode(labId, userId);
    const declared = parseMaterialContent(lab.content).mode;
    const mode = held || (vulnLab.MODES.includes(declared) ? declared : 'lane');

    if (mode === 'lane' && !caps.can_deploy_lane) {
      return res.status(409).json({ error: `Cannot rebuild '${challenge.name}' as a lab lane: ${caps.lane_blockers.join('; ')}`, capabilities: caps });
    }
    if (mode === 'attach' && !caps.can_attach) {
      return res.status(409).json({ error: `Cannot re-attach '${challenge.name}': ${caps.attach_blockers.join('; ')}`, capabilities: caps });
    }

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
    ctx = { course, challenge, student, mode };

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
  const { course, challenge, student, mode } = ctx;
  (async () => {
    const fail = async (message) => {
      const live = (global._batchDeployProgress || {})[claimedId];
      if (live) { live.error = message; live.phase_detail = `Redeploy failed: ${message}`; }
      await setRedeployError(labId, userId, message);
      console.error(`[CLE] Redeploy failed for ${userId} on lab ${labId}: ${message}`);
    };

    try {
      const teardown = await vulnLab.teardownLabForStudent({
        materialId: labId, userId, ignoreProgressId: claimedId,
      });

      // Refuse to build on top of survivors. Their VMIDs are derived from the
      // VXLAN, so the rebuild would clone straight into machines that are still
      // running and fail at the first clone with "VM already exists".
      if (!teardown.safe_to_redeploy) {
        await fail(
          `Could not fully tear down the current deployment, so it was not rebuilt: `
          + `${teardown.errors.slice(0, 3).join('; ')}`
        );
        return;
      }

      // Capture flags. Default is to CARRY THEM OVER, so rebuilding a broken box
      // never costs a student work they already did:
      //   lane mode   — the lane row was deleted and cybercore_lane_flag CASCADEs
      //                 with it, so the values only still exist in the snapshot
      //                 teardown took. Replaying it is what preserves them.
      //   attach mode — the host lane survived, so its flag rows did too and
      //                 ensureLaneFlags will re-plant the same values on its own.
      // reset_flags inverts each: drop the snapshot, or delete the surviving rows.
      let flagSeeds = teardown.flag_snapshot || null;
      if (resetFlags) {
        flagSeeds = null;
        const deleted = await vulnLab.resetFlagsForDetached(teardown.detached_instances);
        if (deleted > 0) console.log(`[CLE] Reset ${deleted} flag(s) for ${student.email} on lab ${labId}`);
      }

      const instructorEmails = await courseInstructorEmails(courseId).catch(() => []);
      const result = await vulnLab.deployVulnLab({
        course, challenge, students: [student], materialId: labId, mode,
        instructorEmails, progressId: claimedId,
        // 'attach' ignores this — its host lane kept the rows already.
        flagSeeds: mode === 'lane' ? flagSeeds : null,
      });

      if ((result.failed || []).length > 0) {
        await fail(result.failed[0].reason || 'the rebuild did not complete');
        return;
      }

      await setRedeployError(labId, userId, null);
      console.log(`[CLE] Redeployed ${student.email}'s '${challenge.challenge_key}' (${mode}) on lab ${labId}`);
    } catch (err) {
      await fail(err.message);
    } finally {
      laneDeployer.finishProgress(claimedId);
    }
  })();
});

module.exports = router;
