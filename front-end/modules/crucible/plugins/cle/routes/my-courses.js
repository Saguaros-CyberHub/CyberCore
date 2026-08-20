/**
 * CLE Plugin — Student-facing course view
 * Mounted at /api/cle/my
 *
 * This is the student's side of the course: the courses they are enrolled in,
 * and for each one, the capture-flag board for the lab machines in their lane.
 * Everything here is scoped to req.user.userId — a student can only ever see
 * their own enrollment and their own flags, and flag VALUES are never returned.
 *
 * Attributing lanes to courses
 * ----------------------------------------------------------------------------
 * The two provisioning paths stamp different keys onto cybercore_lane.config:
 * CLE's provisionLanes writes course_id, while POST /api/admin/deploy-group —
 * the path that actually deploys challenge targets, and therefore the one a
 * CYBV 480 class uses — writes group_id and no course reference at all.
 *
 * So: a lane carrying config.course_id belongs to that course. A lane without
 * one is attributed to the student's single enrolled course when they have
 * exactly one, which is the normal case and the only unambiguous one. If a
 * student is in several courses, un-attributed lanes are reported separately
 * rather than guessed at.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { query } = require('../utils/db');
const flagManager = require('../../../../../src/utils/flag-manager');
const { isFeatureEnabled } = require('../utils/course-features');

/**
 * Courses this student is enrolled in, with their assignments and flag
 * progress. Drives the course list the student picks from.
 */
async function loadEnrolledCourses(userId) {
  const courses = await query(
    `SELECT c.course_id, c.course_name, c.code, c.description,
            c.start_date, c.end_date, c.is_active, c.features,
            e.enrollment_role, e.status AS enrollment_status
       FROM cle_course_enrollment e
       JOIN cle_course c ON c.course_id = e.course_id
      WHERE e.user_id = $1
        AND e.status IN ('active', 'completed')
      ORDER BY c.is_active DESC, c.start_date DESC NULLS LAST, c.course_name`,
    [userId]
  );
  return courses.rows;
}

/**
 * Published lab/assignment materials for a set of courses. These are what the
 * student sees as "the assignment" the flags belong to.
 */
async function loadAssignments(courseIds) {
  if (courseIds.length === 0) return {};
  const materials = await query(
    `SELECT material_id, course_id, title, description, type, content, created_at
       FROM cle_course_material
      WHERE course_id = ANY($1::uuid[])
        AND is_published = TRUE
        AND type IN ('lab', 'vulnerable_lab', 'assignment')
      ORDER BY created_at`,
    [courseIds]
  );
  const byCourse = {};
  for (const m of materials.rows) {
    (byCourse[m.course_id] = byCourse[m.course_id] || []).push(m);
  }
  return byCourse;
}

/** Split the student's flag rows into per-course buckets. See header note. */
function attributeLanes(flagRows, courseIds) {
  const byCourse = {};
  const unattributed = [];

  for (const row of flagRows) {
    if (row.course_id && courseIds.includes(row.course_id)) {
      (byCourse[row.course_id] = byCourse[row.course_id] || []).push(row);
    } else {
      unattributed.push(row);
    }
  }

  // Exactly one enrolled course => no ambiguity, the lab machines are its.
  if (unattributed.length > 0 && courseIds.length === 1) {
    const only = courseIds[0];
    byCourse[only] = (byCourse[only] || []).concat(unattributed);
    return { byCourse, unattributed: [] };
  }

  return { byCourse, unattributed };
}

/**
 * GET /api/cle/my/courses
 * The student's enrolled courses with a flag-progress summary on each, so the
 * course list can show "4 / 12 flags" without a second round-trip per card.
 */
router.get('/courses', async (req, res) => {
  try {
    const userId = req.user.userId;
    const courses = await loadEnrolledCourses(userId);
    // ATTRIBUTE AGAINST EVERY ENROLLED COURSE, filter for display afterwards.
    // attributeLanes() folds un-attributed lanes into the sole course when
    // there is exactly one, so pre-filtering here would take a student enrolled
    // in two courses, one with Flags off, down to one course and hand that
    // course the other one's lanes.
    const courseIds = courses.map(c => c.course_id);

    const flagRows = await flagManager.getUserFlagRows(userId);
    const { byCourse, unattributed } = attributeLanes(flagRows, courseIds);
    const assignments = await loadAssignments(courseIds);

    // This endpoint feeds the student flag board's course picker and nothing
    // else, so a course whose instructor turned Flags off is dropped rather
    // than rendered as a card that 404s when tapped.
    const payload = courses.filter(c => isFeatureEnabled(c, 'flags')).map(c => {
      const rows = byCourse[c.course_id] || [];
      return {
        courseId: c.course_id,
        courseName: c.course_name,
        code: c.code,
        description: c.description,
        startDate: c.start_date,
        endDate: c.end_date,
        isActive: c.is_active,
        enrollmentRole: c.enrollment_role,
        assignmentCount: (assignments[c.course_id] || []).length,
        machineCount: new Set(rows.map(r => `${r.lane_id}:${r.vm_name}`)).size,
        captured: rows.filter(r => r.captured_at).length,
        total: rows.length
      };
    });

    res.json({
      courses: payload,
      // Non-empty only when a multi-course student has lanes we cannot pin to
      // a course. Surfaced so the flags aren't silently invisible.
      unattributedFlags: unattributed.length
    });
  } catch (err) {
    console.error('[CLE MyCourses] List error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/cle/my/courses/:courseId/flags
 * The flag board for one course: its assignments plus the per-machine
 * user/root checklist for this student's own lane. Never returns flag values.
 */
router.get('/courses/:courseId/flags', async (req, res) => {
  try {
    const userId = req.user.userId;
    const { courseId } = req.params;

    // Enrollment is the authorization check — a student may only read the
    // board for a course they are actually in.
    const enrollment = await query(
      `SELECT c.course_id, c.course_name, c.code, c.description, c.features
         FROM cle_course_enrollment e
         JOIN cle_course c ON c.course_id = e.course_id
        WHERE e.user_id = $1
          AND e.course_id = $2
          AND e.status IN ('active', 'completed')`,
      [userId, courseId]
    );
    if (enrollment.rows.length === 0) {
      return res.status(403).json({ error: 'You are not enrolled in this course' });
    }
    const course = enrollment.rows[0];

    // Enrollment says they may read this course; the feature says the course
    // has a board at all. 404 to match every other disabled-feature route.
    if (!isFeatureEnabled(course, 'flags')) {
      return res.status(404).json({ error: 'Flags is not enabled for this course' });
    }

    const allCourses = await loadEnrolledCourses(userId);
    const courseIds  = allCourses.map(c => c.course_id);

    const flagRows = await flagManager.getUserFlagRows(userId);
    const { byCourse } = attributeLanes(flagRows, courseIds);
    const board = flagManager.buildStudentBoard(byCourse[courseId] || []);

    const assignments = (await loadAssignments([courseId]))[courseId] || [];

    res.json({
      course: {
        courseId: course.course_id,
        courseName: course.course_name,
        code: course.code,
        description: course.description
      },
      assignments: assignments.map(a => ({
        materialId: a.material_id,
        title: a.title,
        description: a.description,
        type: a.type,
        content: a.content
      })),
      machines: board.machines,
      captured: board.captured,
      total: board.total
    });
  } catch (err) {
    console.error('[CLE MyCourses] Flag board error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
