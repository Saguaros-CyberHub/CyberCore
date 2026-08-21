/**
 * CLE Plugin — the CyberHub home page's course cards.
 *
 * A person has TWO possible relationships to a course and they come from two
 * different tables: students are rows in cle_course_enrollment, while a
 * professor is the scalar cle_course.instructor_id. There is no instructor
 * join table, so "my courses" cannot be one query and cannot be one endpoint's
 * existing shape — GET /api/cle/my/courses is enrollment-only (and additionally
 * filtered to courses with Flags on), GET /api/cle/courses is instructor-only.
 * A professor loading either sees nothing useful. This merges both.
 *
 * Kept pure and free of `query`/`cybercoreQuery` on purpose: the merge rules
 * below (who wins a duplicate, what a student is allowed to see) are the part
 * worth pinning in a test, and test/hub-course-overview.test.js runs them with
 * no database.
 */

const { resolveFeatures } = require('./course-features');

/**
 * @param {object}   input
 * @param {object[]} input.enrolled     rows from loadEnrolledCourses()
 * @param {object[]} input.taught       rows from loadTaughtCourses()
 * @param {object}   input.byCourse     course_id -> flag rows, from attributeLanes()
 * @param {object}   input.assignments  course_id -> published material rows
 * @param {object}   input.laneCounts   course_id -> live lane count
 * @param {object}   input.instructors  user_id   -> { userId, name, email }
 * @returns {object[]} card objects, ordered for display
 */
function buildOverviewCards({
  enrolled = [], taught = [], byCourse = {},
  assignments = {}, laneCounts = {}, instructors = {},
} = {}) {
  const merged = new Map();

  for (const row of enrolled) {
    merged.set(row.course_id, {
      row,
      relationship: 'student',
      enrollmentRole: row.enrollment_role || 'student',
      alsoEnrolled: false,
    });
  }

  // INSTRUCTOR WINS a duplicate. A TA who teaches their own section is both;
  // the badge can still say TA (enrollmentRole is preserved), but the
  // relationship — and therefore where the card's button goes — is instructor.
  for (const row of taught) {
    const prior = merged.get(row.course_id);
    merged.set(row.course_id, {
      row,
      relationship: 'instructor',
      enrollmentRole: prior ? prior.enrollmentRole : null,
      alsoEnrolled: !!prior,
    });
  }

  const cards = [];
  for (const { row, relationship, enrollmentRole, alsoEnrolled } of merged.values()) {
    const isStudent = relationship === 'student';
    // The complete {key: boolean} map, so the CLIENT picks the card's
    // destination from the same defaulting rules the server uses. Sending a
    // pre-computed action list instead would be a second source of truth for
    // one decision, which is how the two drift.
    const features = resolveFeatures(row);
    const flagRows = byCourse[row.course_id] || [];

    cards.push({
      courseId:        row.course_id,
      courseName:      row.course_name,
      code:            row.code || null,
      description:     row.description || null,
      // There is no term/semester column anywhere in cle_course. The period is
      // start_date/end_date (both nullable, and POST /courses never sets them),
      // and the term is embedded in `code`, e.g. CYBR-480-7W1-1.
      startDate:       row.start_date != null ? row.start_date : null,
      endDate:         row.end_date != null ? row.end_date : null,
      isActive:        row.is_active !== false,
      provisionStatus: row.provision_status || 'ready',

      relationship,
      enrollmentRole,
      alsoEnrolled,
      features,
      instructor: instructors[row.instructor_id] || null,

      // NEVER on a student's card. Class size and the course's cluster
      // footprint are not something a student should learn from their own
      // home page, and this endpoint has no role gate of its own.
      studentCount: isStudent ? null : (Number(row.student_count) || 0),
      vmCount:      isStudent ? null : (laneCounts[row.course_id] || 0),

      assignmentCount: (assignments[row.course_id] || []).length,

      // Only a student has flag progress, and only where the course has a
      // board at all — otherwise the card would advertise 0/0 forever.
      flags: (isStudent && features.flags === true)
        ? {
            captured:     flagRows.filter(r => r.captured_at).length,
            total:        flagRows.length,
            machineCount: new Set(flagRows.map(r => `${r.lane_id}:${r.vm_name}`)).size,
          }
        : null,
    });
  }

  // Active first, then the courses they run ahead of the ones they take, then
  // by name so the order is stable across reloads.
  const rank = (c) => (c.relationship === 'instructor' ? 0 : 1);
  cards.sort((a, b) =>
    (Number(b.isActive) - Number(a.isActive)) ||
    (rank(a) - rank(b)) ||
    String(a.courseName || '').localeCompare(String(b.courseName || ''))
  );

  return cards;
}

module.exports = { buildOverviewCards };
