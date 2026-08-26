/**
 * ============================================================================
 * CLE — course directory provider
 * ============================================================================
 * Core cannot see cle_db. This is the adapter that answers core's questions
 * about courses, registered into src/utils/course-directory.js from
 * routes/api.js at plugin load.
 *
 * WHY THE PREDICATES LIVE HERE AND NOT IN CORE
 * ----------------------------------------------------------------------------
 * "Enrolled" means `status IN ('active','completed')` and "teaches" means
 * `instructor_id = $1` with no join table. Those are CLE's rules about CLE's
 * schema. A copy of them in core would drift the first time this plugin changed
 * one, and the symptom would be a support form whose course dropdown is quietly
 * wrong for a semester. Core states the QUESTION; this file owns the ANSWER.
 *
 * Every function is a plain read. Nothing here writes, and nothing here decides
 * authorization — core's isEnrolled()/resolveTicketCourse() do that, using
 * these lists as their evidence.
 *
 * Errors are allowed to propagate: core wraps every call and degrades to an
 * empty list, and swallowing here as well would hide a real cle_db problem from
 * the one log line that reports it.
 * ============================================================================
 */

const { query } = require('./db');

/**
 * The columns core's toCourse() normalizer reads.
 *
 * Deliberately narrow. Returning `SELECT *` would publish features,
 * provision_status and dates through core's API and couple its wire format to
 * this plugin's schema.
 */
const COLUMNS = 'c.course_id, c.course_name, c.code, c.instructor_id';

/**
 * Courses this person is ENROLLED in.
 *
 * Same predicate as loadEnrolledCourses() in routes/my-courses.js, minus that
 * function's Flags-feature filter — a student whose instructor turned the flag
 * board off can still have a broken VM to report.
 *
 * 'completed' is included on purpose: a course that ended last week is exactly
 * the kind of thing a student still needs to ask about.
 */
async function coursesForStudent(userId) {
  const r = await query(
    `SELECT ${COLUMNS}
       FROM cle_course_enrollment e
       JOIN cle_course c ON c.course_id = e.course_id
      WHERE e.user_id = $1
        AND e.status IN ('active', 'completed')
      ORDER BY c.is_active DESC, c.start_date DESC NULLS LAST, c.course_name`,
    [userId]
  );
  return r.rows;
}

/**
 * Courses this person TEACHES.
 *
 * cle_course.instructor_id is a scalar and there is no instructor join table,
 * so this one predicate is the whole relationship — and it is why
 * coursesForStudent() can never answer "my courses" for a professor: an
 * instructor is never enrolled in the course they run.
 */
async function coursesForInstructor(userId) {
  const r = await query(
    `SELECT ${COLUMNS}
       FROM cle_course c
      WHERE c.instructor_id = $1
      ORDER BY c.is_active DESC, c.start_date DESC NULLS LAST, c.course_name`,
    [userId]
  );
  return r.rows;
}

/**
 * One course by id, with NO access check.
 *
 * Core uses this for two things only: an admin naming any course, and
 * re-resolving the CURRENT instructor when a ticket message needs a Cc. Both
 * are already-authorized paths, which is why this one is deliberately open —
 * see src/utils/course-directory.js resolveTicketCourse().
 */
async function describeCourse(courseId) {
  const r = await query(
    `SELECT ${COLUMNS} FROM cle_course c WHERE c.course_id = $1`,
    [courseId]
  );
  return r.rows[0] || null;
}

module.exports = { coursesForStudent, coursesForInstructor, describeCourse };
