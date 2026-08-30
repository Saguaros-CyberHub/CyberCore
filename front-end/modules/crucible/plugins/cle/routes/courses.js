/**
 * CLE Plugin — Courses Routes
 * Handles course management: list, view, edit, delete
 */

const express = require('express');
const router = express.Router();
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { reserveLabNetwork, teardownLabNetwork } = require('../../../../../src/utils/lab-network-provision');
const laneProvision = require('../utils/lane-provision');
const audit = require('../../../../../src/utils/audit');
const { attachFeatures, sanitizeFeaturesInput, defaultFeaturesForCode } = require('../utils/course-features');
// Lane counts live in cybercore_db and are needed by my-courses.js too, so the
// cross-DB count lives in utils/ rather than inline here.
const { attachLaneCounts } = require('../utils/course-lanes');

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
          c.provision_status,
          c.features,
          c.created_at,
          COUNT(DISTINCT e.user_id) AS student_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
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
          c.provision_status,
          c.features,
          c.created_at,
          COUNT(DISTINCT e.user_id) AS student_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
        WHERE c.instructor_id = $1
        GROUP BY c.course_id
        ORDER BY c.created_at DESC
      `, [instructorId]);
    }

    await attachLaneCounts(coursesResult.rows);
    // Raw column -> complete {key: boolean} map. Done here rather than in the
    // page so the defaulting rules live in exactly one place.
    attachFeatures(coursesResult.rows);
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
          c.provision_status,
          c.features,
          c.created_at,
          c.updated_at,
          COUNT(DISTINCT e.user_id) AS student_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
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
          c.provision_status,
          c.features,
          c.created_at,
          c.updated_at,
          COUNT(DISTINCT e.user_id) AS student_count
        FROM cle_course c
        LEFT JOIN cle_course_enrollment e ON c.course_id = e.course_id AND e.status = 'active'
        WHERE c.course_id = $1 AND c.instructor_id = $2
        GROUP BY c.course_id
      `, [courseId, instructorId]);
    }

    if (courseResult.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or access denied' });
    }

    await attachLaneCounts(courseResult.rows);
    attachFeatures(courseResult.rows);
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
    const { course_name, description, code, instructor_id, is_active, max_students, features } = req.body;

    // Validate required fields
    if (!course_name) {
      return res.status(400).json({ error: 'course_name is required' });
    }

    if (!instructor_id) {
      return res.status(400).json({ error: 'instructor_id is required' });
    }

    const maxStudents = parseInt(max_students, 10);
    if (!Number.isFinite(maxStudents) || maxStudents < 1 || maxStudents > 200) {
      return res.status(400).json({ error: 'max_students must be an integer between 1 and 200' });
    }

    // Create the course row up front in the 'provisioning' state and return
    // immediately. Reserving the lab (SDN zone + VNets + bridge-readiness wait)
    // takes tens of seconds to minutes — longer than the edge proxy will hold
    // the request open — so the reservation runs in the background and flips
    // provision_status to 'ready'/'failed' when it finishes. The UI shows an
    // "Initializing" label until then.
    // Absent features fall back to the per-code defaults, so a section created
    // as CYBR-480-* arrives with its Flags tab already on and does not need an
    // immediate follow-up edit.
    const newFeatures = sanitizeFeaturesInput(features) || defaultFeaturesForCode(code);

    const createResult = await query(`
      INSERT INTO cle_course (course_name, description, code, instructor_id, is_active, max_students, provision_status, features)
      VALUES ($1, $2, $3, $4, $5, $6, 'provisioning', $7::jsonb)
      RETURNING course_id, course_name, description, code, instructor_id, is_active, max_students, provision_status, features, created_at
    `, [course_name, description || null, code || null, instructor_id, is_active !== false, maxStudents,
        JSON.stringify(newFeatures)]);
    const course = createResult.rows[0];
    attachFeatures([course]);

    // Fire-and-forget: provision the lab network out of band.
    provisionCourseLab(course).catch((err) =>
      console.error('[CLE] Background lab provision crashed:', err.message)
    );

    audit.log({
      req,
      action: 'course.created',
      source: 'cle',
      target: { type: 'course', id: course.course_id, label: course.course_name },
      metadata: { code: course.code, instructor_id: course.instructor_id, max_students: course.max_students,
                  features: course.features },
    });

    res.status(201).json(course);
  } catch (error) {
    console.error('[CLE] Create course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Reserve a course's lab network in the background, then mark the course ready.
 * Runs detached from the create request (which has already returned). On
 * success: links the crucible_challenge + flips provision_status to 'ready'.
 * On failure: marks 'failed' — reserveLabNetwork self-cleans any partially
 * created SDN infra, so no challenge_id is left dangling on the course.
 */
async function provisionCourseLab(course) {
  const id8 = String(course.course_id).replace(/-/g, '').substring(0, 8);
  // Proxmox SDN zone IDs must start with a letter (regex [a-z][a-z0-9]{0,7}),
  // but a UUID's first hex char is a digit ~62.5% of the time. Prefix a fixed
  // letter and take 7 hex chars to stay within the 8-char limit.
  const zoneAbbrev = `cle-${id8.substring(0, 7)}`;
  try {
    const reservation = await reserveLabNetwork({
      challengeKey: `cle-course-${id8}`,
      name: `CLE: ${course.course_name}`,
      description: `Workstation lab for CLE course ${course.course_name}`,
      subnetScheme: 'v2',
      maxLanes: course.max_students,
      zoneAbbrev,
      spec: { cle: true, course_id: course.course_id, purpose: 'cle_course_workstations' },
      log: (m) => console.log(`[CLE] Course lab: ${m}`),
    });

    // reserveLabNetwork has always returned bridgesUp and this ignored it, so a
    // course flipped to 'ready' whether or not a single bridge came up. Track A8
    // made the underlying check honest (every ONLINE node, concurrently, instead
    // of whichever node Proxmox listed first); recording it here is what makes
    // that visible on the CLE side.
    // Readiness is recorded against the RESERVATION by reserveLabNetwork, in
    // cybercore_db, so it is not copied onto the course — CIAB reads the same
    // row through getLabReadiness(challenge_id).
    const readiness = reservation.bridgeReadiness || null;
    await query(`
      UPDATE cle_course
          SET challenge_id = $1, challenge_key = $2, subnet_scheme = $3,
              provision_status = 'ready', updated_at = NOW()
        WHERE course_id = $4
    `, [reservation.challenge_id, reservation.challenge_key, reservation.subnet_scheme, course.course_id]);
    if (reservation.bridgesUp) {
      console.log(`[CLE] Course lab ready: ${course.course_id}`);
    } else {
      // Still 'ready': the block exists and lanes can deploy onto the nodes that
      // DID come up. Blocking a whole course over one node that is down for
      // unrelated reasons would be worse than deploying with a warning.
      const short = readiness
        ? readiness.nodesPending.concat(readiness.nodesUnreachable).join(', ')
        : 'unknown';
      console.warn(`[CLE] Course lab ${course.course_id} reserved but bridges unconfirmed on ${short} — `
        + `workstations placed there will fail to cable`);
    }
  } catch (error) {
    console.error(`[CLE] Course lab provision failed for ${course.course_id}:`, error.message);
    await query(`
      UPDATE cle_course SET provision_status = 'failed', updated_at = NOW()
        WHERE course_id = $1
    `, [course.course_id]).catch(() => {});
    // Deliberately not swallowed silently: before Track A8 the ONLY remedy for a
    // failed course was deleting and recreating it, and the reason was in a log
    // line nobody would look for. POST /:courseId/reprovision now exists.
    console.error(`[CLE] Course ${course.course_id} can be retried: POST /api/cle/courses/${course.course_id}/reprovision`);
  }
}

/**
 * POST /api/cle/courses/:courseId/reprovision — retry a failed lab reservation.
 *
 * Track A8 parity. Before this, a course whose reservation failed could only be
 * DELETED and recreated — which is what both error strings still told operators
 * to do — and that throws away the roster and every enrollment with it.
 *
 * Guarded against the two ways a retry does damage:
 *   - already 'provisioning' → refuse, because allocateVxlanBlock always carves
 *     ABOVE the global maximum and never re-uses, so a concurrent second run
 *     permanently burns a second block.
 *   - already 'ready' → refuse for the same reason, unless explicitly forced.
 */
router.post('/:courseId/reprovision', adminOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const r = await query(
      `SELECT course_id, course_name, max_students, provision_status, challenge_id
         FROM cle_course WHERE course_id = $1`,
      [courseId]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Course not found' });
    const course = r.rows[0];

    if (course.provision_status === 'provisioning') {
      return res.status(409).json({
        error: 'This course is already being provisioned. Wait for it to finish.',
      });
    }
    if (course.provision_status === 'ready' && req.body?.force !== true) {
      return res.status(409).json({
        error: 'This course already has a lab network. Re-provisioning a healthy one would carve '
             + 'a second VXLAN block — blocks are only ever allocated above the highest in use, never reused.',
      });
    }

    await query(
      `UPDATE cle_course SET provision_status = 'provisioning', updated_at = NOW()
        WHERE course_id = $1`,
      [courseId]
    );

    audit.log({
      req,
      action: 'cle_course.reprovisioned',
      source: 'cle',
      target: { type: 'course', id: courseId, label: course.course_name },
      metadata: { previous_status: course.provision_status },
    });

    // Detached, exactly as the create path does it.
    provisionCourseLab(course)
      .catch((err) => console.error('[CLE] Re-provision crashed:', err.message));

    res.status(202).json({ success: true, course_id: courseId, provision_status: 'provisioning' });
  } catch (error) {
    console.error('[CLE] Reprovision error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Boot sweep for courses stranded mid-provision.
 *
 * Reserving a lab is fire-and-forget async work inside THIS process with no
 * resume, so any course still 'provisioning' at boot was abandoned by a previous
 * one. Without this it spins "Initializing" in the UI forever, its deploy stays
 * blocked on a null challenge_id, and the only exit is deleting the course —
 * which is exactly the state CLE could get stuck in before Track A8.
 *
 * Marks them 'failed' rather than auto-retrying: a half-built block may hold a
 * challenge row, and an operator pressing Re-provision is a decision where an
 * automatic retry at every boot is a loop.
 *
 * Exported for src/server.js, alongside recoverStrandedLanes.
 */
async function recoverStrandedCourseLabs() {
  try {
    const res = await query(
      `UPDATE cle_course SET provision_status = 'failed', updated_at = NOW()
        WHERE provision_status = 'provisioning'
        RETURNING course_id, course_name`
    );
    if (res.rows.length > 0) {
      console.warn(`[CLE] Marked ${res.rows.length} course lab(s) failed — stranded mid-provision by a `
        + `restart: ${res.rows.map(c => c.course_name || c.course_id).join(', ')}. Re-provision to retry.`);
    }
    return res.rows.length;
  } catch (err) {
    console.warn(`[CLE] stranded course-lab sweep skipped: ${err.message}`);
    return 0;
  }
}

/**
 * PATCH /api/cle/courses/:courseId — Update course details
 */
router.patch('/:courseId', instructorOnly, async (req, res) => {
  try {
    const instructorId = req.user.userId;
    const userRole = req.user.role;
    const { courseId } = req.params;
    const { course_name, description, code, instructor_id, is_active, features } = req.body;

    // Verify instructor owns this course or admin
    let ownerResult;
    const OWNER_COLUMNS = 'course_id, course_name, description, code, instructor_id, is_active, features';
    if (userRole === 'admin') {
      ownerResult = await query(`
        SELECT ${OWNER_COLUMNS} FROM cle_course
        WHERE course_id = $1
      `, [courseId]);
    } else {
      ownerResult = await query(`
        SELECT ${OWNER_COLUMNS} FROM cle_course
        WHERE course_id = $1 AND instructor_id = $2
      `, [courseId, instructorId]);
    }

    if (ownerResult.rows.length === 0) {
      return res.status(403).json({ error: 'You do not have permission to modify this course' });
    }
    // Prior values, for the audit row's from/to diff.
    const existing = ownerResult.rows[0];

    // Unknown keys are dropped and absent input becomes null, so COALESCE below
    // reads it as "leave the column alone" -- same contract as every other field.
    const nextFeatures = sanitizeFeaturesInput(features);

    // Update course
    const updateResult = await query(`
      UPDATE cle_course
      SET
        course_name = COALESCE($1, course_name),
        description = COALESCE($2, description),
        code = COALESCE($3, code),
        instructor_id = COALESCE($4, instructor_id),
        is_active = COALESCE($5, is_active),
        features = COALESCE($6::jsonb, features),
        updated_at = NOW()
      WHERE course_id = $7
      RETURNING course_id, course_name, description, code, instructor_id, is_active, features, updated_at
    `, [course_name, description, code, instructor_id, is_active,
        nextFeatures && JSON.stringify(nextFeatures), courseId]);

    const after = updateResult.rows[0];
    const changes = {};
    // features is jsonb -- pg hydrates it to an object, and String({}) is
    // '[object Object]' for every possible value, so a plain String() compare
    // would report every features change as no change and the audit row would
    // silently omit the one field this endpoint just learned to write.
    const cmp = (v) => (v !== null && typeof v === 'object' ? JSON.stringify(v) : String(v));
    for (const field of ['course_name', 'description', 'code', 'instructor_id', 'is_active', 'features']) {
      if (existing && cmp(existing[field]) !== cmp(after[field])) {
        changes[field] = { from: existing[field], to: after[field] };
      }
    }
    audit.log({
      req,
      action: 'course.updated',
      source: 'cle',
      target: { type: 'course', id: courseId, label: after.course_name },
      changes,
    });

    attachFeatures([after]);
    res.json(after);
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

    // Verify course exists + get its reserved-lab linkage
    const existsResult = await query(`
      SELECT course_id, challenge_id FROM cle_course
      WHERE course_id = $1
    `, [courseId]);

    if (existsResult.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }
    const { challenge_id } = existsResult.rows[0];

    // Tear down every student lane belonging to this course in one hardened
    // batch pass (parallel stop + delete, orphan retry rounds, orphan disk
    // sweep). The old per-lane loop took minutes for a full class and left
    // disk images behind on Ceph.
    let laneTeardown = { lanes_deleted: 0, vms_destroyed: 0, orphan_disks_swept: 0, errors: [] };
    try {
      laneTeardown = await laneProvision.teardownCourseLanes(courseId);
    } catch (e) {
      console.error(`[CLE] Lane teardown during course ${courseId} delete: ${e.message}`);
      laneTeardown.errors.push(e.message);
    }

    // Remove every reserved-lab challenge tied to this course (VNets + zone +
    // the crucible_challenge row). We match on the challenge's own
    // spec.course_id — the source of truth — as well as the course's stored
    // challenge_id, because a challenge can exist without cle_course.challenge_id
    // ever being linked: the challenge is created by the *background* provision,
    // and the link is written only after reserveLabNetwork returns. A course
    // deleted mid-provision (or a retried provision) therefore leaves a
    // challenge that challenge_id alone would miss, orphaning it in the
    // Challenge Templates list. Matching on spec.course_id also sweeps up any
    // duplicate challenges from repeated provisions.
    const challengeRows = await cybercoreQuery(
      `SELECT challenge_id FROM crucible_challenge
        WHERE spec->>'course_id' = $1 OR challenge_id = $2`,
      [courseId, challenge_id]   // challenge_id may be null; "= NULL" matches nothing, as intended
    );

    const challengeErrors = [];
    for (const { challenge_id: cid } of challengeRows.rows) {
      try {
        await teardownLabNetwork(cid, { force: true, log: (m) => console.log(`[CLE] Course lab teardown: ${m}`) });
      } catch (e) {
        console.warn(`[CLE] Challenge ${cid} teardown for course ${courseId}: ${e.message}`);
        challengeErrors.push({ challenge_id: cid, error: e.message });
      }
    }

    // Delete course (cascades to cle_* child records).
    await query(`DELETE FROM cle_course WHERE course_id = $1`, [courseId]);

    audit.log({
      req,
      action: 'course.deleted',
      source: 'cle',
      target: { type: 'course', id: courseId },
      metadata: {
        lanes_removed: laneTeardown.lanes_deleted,
        vms_destroyed: laneTeardown.vms_destroyed,
      },
    });

    res.json({
      success: true,
      message: 'Course and its reserved lab deleted',
      lanes_removed: laneTeardown.lanes_deleted,
      vms_destroyed: laneTeardown.vms_destroyed,
      orphan_disks_swept: laneTeardown.orphan_disks_swept,
      challenges_removed: challengeRows.rows.length - challengeErrors.length,
      ...(laneTeardown.errors.length ? { lane_errors: laneTeardown.errors } : {}),
      ...(challengeErrors.length ? { challenge_errors: challengeErrors } : {}),
    });
  } catch (error) {
    console.error('[CLE] Delete course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
// Named export alongside the router so src/server.js can run the boot sweep
// without importing the route table.
module.exports.recoverStrandedCourseLabs = recoverStrandedCourseLabs;
