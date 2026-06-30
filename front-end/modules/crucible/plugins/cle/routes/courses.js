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

const instructorOnly = requireRole('instructor', 'admin');
const adminOnly = requireRole('admin');

/**
 * Attach a live workstation-lane count to each course row. Lanes live in
 * cybercore_db (keyed by config.course_id), so this is a single cross-DB
 * grouped count merged onto the CLE-DB course rows.
 */
async function attachLaneCounts(courseRows) {
  if (!courseRows.length) return courseRows;
  const ids = courseRows.map(c => c.course_id);
  const counts = await cybercoreQuery(
    `SELECT config->>'course_id' AS course_id, COUNT(*)::int AS vm_count
        FROM cybercore_lane
      WHERE config->>'course_id' = ANY($1) AND status <> 'deleted'
      GROUP BY 1`,
    [ids]
  ).catch(() => ({ rows: [] }));
  const byId = {};
  for (const r of counts.rows) byId[r.course_id] = r.vm_count;
  for (const c of courseRows) c.vm_count = byId[c.course_id] || 0;
  return courseRows;
}

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
    const { course_name, description, code, instructor_id, is_active, max_students } = req.body;

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
    const createResult = await query(`
      INSERT INTO cle_course (course_name, description, code, instructor_id, is_active, max_students, provision_status)
      VALUES ($1, $2, $3, $4, $5, $6, 'provisioning')
      RETURNING course_id, course_name, description, code, instructor_id, is_active, max_students, provision_status, created_at
    `, [course_name, description || null, code || null, instructor_id, is_active !== false, maxStudents]);
    const course = createResult.rows[0];

    // Fire-and-forget: provision the lab network out of band.
    provisionCourseLab(course).catch((err) =>
      console.error('[CLE] Background lab provision crashed:', err.message)
    );

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

    await query(`
      UPDATE cle_course
          SET challenge_id = $1, challenge_key = $2, subnet_scheme = $3,
              provision_status = 'ready', updated_at = NOW()
        WHERE course_id = $4
    `, [reservation.challenge_id, reservation.challenge_key, reservation.subnet_scheme, course.course_id]);
    console.log(`[CLE] Course lab ready: ${course.course_id}`);
  } catch (error) {
    console.error(`[CLE] Course lab provision failed for ${course.course_id}:`, error.message);
    await query(`
      UPDATE cle_course SET provision_status = 'failed', updated_at = NOW()
        WHERE course_id = $1
    `, [course.course_id]).catch(() => {});
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
    const { course_name, description, code, instructor_id, is_active } = req.body;

    // Verify instructor owns this course or admin
    let ownerResult;
    if (userRole === 'admin') {
      ownerResult = await query(`
        SELECT course_id FROM cle_course
        WHERE course_id = $1
      `, [courseId]);
    } else {
      ownerResult = await query(`
        SELECT course_id FROM cle_course
        WHERE course_id = $1 AND instructor_id = $2
      `, [courseId, instructorId]);
    }

    if (ownerResult.rows.length === 0) {
      return res.status(403).json({ error: 'You do not have permission to modify this course' });
    }

    // Update course
    const updateResult = await query(`
      UPDATE cle_course
      SET
        course_name = COALESCE($1, course_name),
        description = COALESCE($2, description),
        code = COALESCE($3, code),
        instructor_id = COALESCE($4, instructor_id),
        is_active = COALESCE($5, is_active),
        updated_at = NOW()
      WHERE course_id = $6
      RETURNING course_id, course_name, description, code, instructor_id, is_active, updated_at
    `, [course_name, description, code, instructor_id, is_active, courseId]);

    res.json(updateResult.rows[0]);
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

    // Tear down every student lane belonging to this course (workstation +
    // gateway + Guac connection + lane row).
    const lanes = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane WHERE config->>'course_id' = $1`,
      [courseId]
    );
    for (const row of lanes.rows) {
      await laneProvision.teardownLane(row.lane_id).catch(
        (e) => console.warn(`[CLE] Lane ${row.lane_id} teardown during course delete: ${e.message}`));
    }

    // Remove the reserved lab network (VNets + zone) and the challenge row.
    if (challenge_id) {
      await teardownLabNetwork(challenge_id, { force: true, log: (m) => console.log(`[CLE] Course lab teardown: ${m}`) })
        .catch((e) => console.warn(`[CLE] Lab network teardown for course ${courseId}: ${e.message}`));
    }

    // Delete course (cascades to cle_* child records).
    await query(`DELETE FROM cle_course WHERE course_id = $1`, [courseId]);

    res.json({ success: true, message: 'Course and its reserved lab deleted', lanes_removed: lanes.rows.length });
  } catch (error) {
    console.error('[CLE] Delete course error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
