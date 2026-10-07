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
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { isFeatureEnabled, resolveFeatures } = require('../utils/course-features');
const { laneCountsByCourse } = require('../utils/course-lanes');
const { buildOverviewCards } = require('../utils/course-overview');

/**
 * Courses this student is enrolled in, with their assignments and flag
 * progress. Drives the course list the student picks from.
 */
async function loadEnrolledCourses(userId) {
  const courses = await query(
    `SELECT c.course_id, c.course_name, c.code, c.description,
            c.start_date, c.end_date, c.is_active, c.features,
            c.instructor_id, c.provision_status,
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

/**
 * Courses this person TEACHES. cle_course.instructor_id is a scalar and there
 * is no instructor join table, so this one predicate is the whole relationship
 * — and it is why loadEnrolledCourses() can never answer "my courses" for a
 * professor: they are not enrolled in the course they run.
 */
async function loadTaughtCourses(userId) {
  const result = await query(
    `SELECT c.course_id, c.course_name, c.code, c.description,
            c.start_date, c.end_date, c.is_active, c.features,
            c.instructor_id, c.provision_status,
            COUNT(DISTINCT e.user_id)::int AS student_count
       FROM cle_course c
       LEFT JOIN cle_course_enrollment e
              ON e.course_id = c.course_id AND e.status = 'active'
      WHERE c.instructor_id = $1
      GROUP BY c.course_id
      ORDER BY c.is_active DESC, c.start_date DESC NULLS LAST, c.course_name`,
    [userId]
  );
  return result.rows;
}

/**
 * An admin is neither enrolled in nor teaching most courses. Rendering all of
 * them as cards would turn a personal home page into a fleet console, which
 * /cle/courses already is — so they get a single count and a link instead.
 */
async function loadAdminSummary() {
  const result = await query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE c.is_active)::int AS active
       FROM cle_course c`
  );
  const row = result.rows[0] || {};
  return { totalCourses: row.total || 0, activeCourses: row.active || 0 };
}

/**
 * Instructor display names. Courses live in cle_db and users in cybercore_db
 * with no FK between them, so this is the same two-step merge course-students.js
 * does, in the other direction — a single JOIN is not available.
 *
 * Failure resolves to {}: an unreachable core DB must cost the page a NAME,
 * not the page.
 */
async function loadInstructorProfiles(instructorIds) {
  const ids = [...new Set((instructorIds || []).filter(Boolean))];
  if (ids.length === 0) return {};
  const result = await cybercoreQuery(
    `SELECT user_id, email, first_name, last_name
       FROM cybercore_user
      WHERE user_id = ANY($1::uuid[])`,
    [ids]
  ).catch(() => ({ rows: [] }));

  const byId = {};
  for (const u of result.rows) {
    const name = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
    byId[u.user_id] = { userId: u.user_id, name: name || u.email || null, email: u.email || null };
  }
  return byId;
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

/**
 * GET /api/cle/my/overview
 *
 * Every course this person has a relationship with, for the CyberHub home page.
 * Enrollment for students; cle_course.instructor_id for professors. Deliberately
 * NOT filtered by the flags feature — that filter belongs to GET /courses, which
 * feeds a flag board and nothing else. Each card carries its resolved feature
 * map so the client picks the destination from the same rules the server uses.
 *
 * `?as=student` renders the professor's own home page the way a student's
 * looks, for lecture recordings: no taught-course cards, no admin summary,
 * just their enrollments.
 *
 * It is a PRESENTATION parameter, not an authorization one. Student View does
 * not change roles server-side — req.user.role is always the caller's real
 * role — so this can only ever return LESS than the caller is entitled to,
 * never more. Same shape as ?scope=mine on the workspace lists, and for the
 * same reason: the client has to ask, because the server has no idea the mode
 * is on.
 */
router.get('/overview', async (req, res) => {
  try {
    const userId = req.user.userId;
    // Presentation only: it can hide the caller's own staff cards, never
    // reveal anybody else's. See the note above.
    const asStudent = req.query.as === 'student';
    const role = asStudent ? 'student' : req.user.role;

    const enrolled = await loadEnrolledCourses(userId);
    // THE FULL ENROLLED LIST, and nothing narrower. attributeLanes() folds
    // un-attributed lanes into the sole course when there is exactly one, so
    // anything that filters before the call below hands one course another
    // course's lanes. Same constraint as GET /courses — see its note.
    const enrolledIds = enrolled.map(c => c.course_id);

    const taught = (role === 'instructor' || role === 'admin')
      ? await loadTaughtCourses(userId)
      : [];

    const flagRows = await flagManager.getUserFlagRows(userId);
    const { byCourse, unattributed } = attributeLanes(flagRows, enrolledIds);

    const allIds      = [...new Set([...enrolledIds, ...taught.map(c => c.course_id)])];
    const assignments = await loadAssignments(allIds);
    const laneCounts  = await laneCountsByCourse(taught.map(c => c.course_id));
    const instructors = await loadInstructorProfiles(
      [...enrolled, ...taught].map(c => c.instructor_id)
    );

    res.json({
      courses: buildOverviewCards({
        enrolled, taught, byCourse, assignments, laneCounts, instructors,
      }),
      unattributedFlags: unattributed.length,
      adminSummary: role === 'admin' ? await loadAdminSummary() : null,
      role,
      // Echoed so the client's empty state can say "you are previewing"
      // without a second round-trip to /auth/me.
      viewingAsStudent: asStudent,
    });
  } catch (err) {
    console.error('[CLE MyCourses] Overview error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/cle/my/courses/:courseId
 * One course as its STUDENT sees it: the published brief, plus the flag board
 * when the course has one.
 *
 * This exists alongside /courses/:courseId/flags because that route 404s when
 * the Flags feature is off, which left a student in a non-flags course (CYBR
 * 400, say) with no course view at all — and their home-page card with nowhere
 * to go. Here the board is CONDITIONAL rather than required.
 *
 * Enrollment is still the authorization check, and flag VALUES are still never
 * returned.
 */
router.get('/courses/:courseId', async (req, res) => {
  try {
    const userId = req.user.userId;
    const { courseId } = req.params;

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
    const course   = enrollment.rows[0];
    const features = resolveFeatures(course);

    const assignments = (await loadAssignments([courseId]))[courseId] || [];

    let board = { machines: [], captured: 0, total: 0 };
    if (features.flags) {
      const allCourses = await loadEnrolledCourses(userId);
      const courseIds  = allCourses.map(c => c.course_id);
      const flagRows   = await flagManager.getUserFlagRows(userId);
      const { byCourse } = attributeLanes(flagRows, courseIds);
      board = flagManager.buildStudentBoard(byCourse[courseId] || []);
    }

    res.json({
      course: {
        courseId: course.course_id,
        courseName: course.course_name,
        code: course.code,
        description: course.description
      },
      features,
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
    console.error('[CLE MyCourses] Course view error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
