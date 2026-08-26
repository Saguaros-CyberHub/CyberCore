/**
 * ============================================================================
 * COURSE DIRECTORY — core's read-only view of "what courses exist"
 * ============================================================================
 * Courses live in cle_db (the CLE plugin's own database); users, lanes and
 * tickets live in cybercore_db. There is no cross-database join in Postgres, so
 * anything in core that needs a course has to ask someone else.
 *
 * WHY A REGISTRY RATHER THAN require()ING THE PLUGIN
 * ----------------------------------------------------------------------------
 * This is the same seam, for the same reasons, as registerAccessGate() in
 * src/module-loader.js — read that function's docblock; the argument transfers
 * exactly. Specifically:
 *
 *   - Core naming a path like modules/crucible/plugins/cle/utils/db breaks the
 *     moment the plugin is moved, renamed, or disabled, and it inverts the
 *     dependency the whole plugin architecture exists to keep pointing one way.
 *
 *   - The plugin's pool is INJECTED during moduleLoader.loadAll(). A require at
 *     module-eval time therefore gets a null pool and every call throws
 *     'CLE database pool not initialized' — so the require would have to live
 *     inside every handler, in a try/catch, forever.
 *
 *   - Worst of all, core would end up writing CLE's SQL. "Enrolled" means
 *     `status IN ('active','completed')` (cle/routes/my-courses.js) and
 *     "teaches" means `instructor_id = $1` with no join table. A second copy of
 *     those predicates in core drifts silently the first time CLE changes one,
 *     and the symptom is an empty dropdown nobody notices for a semester.
 *
 * FAILURE POLICY: EVERY function here degrades rather than throws.
 * ----------------------------------------------------------------------------
 * No provider registered, a provider that throws, cle_db unreachable — all of
 * them produce [] or null. That is deliberate and it is the difference between
 * "the course dropdown is empty" and "a student cannot ask for help". The
 * ticket form works with no course attached; nothing here is allowed to become
 * a gate.
 *
 * The one consequence a caller must handle: an empty course list has two very
 * different causes — a student genuinely enrolled in nothing, and a directory
 * that is not answering. hasCourseDirectory() distinguishes them so the UI can
 * say which.
 *
 * NO IMPORTS, so this module can be required from anywhere at any point in boot.
 * ============================================================================
 */

/**
 * The single registered provider, or null.
 *
 * A Map keyed by plugin (as accessGates does) would be wrong here: two
 * providers would mean one student's course appearing twice with different
 * ids, and there is no sensible merge. One directory, or none.
 */
let provider = null;

/** The shape a provider must implement. All are async, all return plain data. */
const REQUIRED_METHODS = Object.freeze([
  'coursesForStudent',
  'coursesForInstructor',
  'describeCourse',
]);

/**
 * Install the course provider. Called by the CLE plugin from its route file,
 * which the loader require()s after the plugin's pool has been injected.
 *
 * Throws on a malformed provider — that is a programming error at boot, visible
 * in the log, not a runtime condition to swallow.
 */
function registerCourseDirectory(p) {
  for (const m of REQUIRED_METHODS) {
    if (!p || typeof p[m] !== 'function') {
      throw new TypeError(`course directory provider must implement ${m}()`);
    }
  }
  provider = p;
}

/** Is anyone answering? Lets a caller distinguish "none" from "unavailable". */
function hasCourseDirectory() {
  return !!provider;
}

/** Test seam, and the way a plugin reload starts from a known state. */
function resetCourseDirectory() {
  provider = null;
}

/**
 * Run a provider call, turning every failure into `fallback`.
 *
 * One place, so no caller can accidentally let a cle_db outage escape into a
 * 500 on the ticket form. The warn is rate-limited by nothing on purpose: if
 * cle_db is down this is the log line that says so, and it should be loud.
 */
async function safely(method, args, fallback) {
  if (!provider) return fallback;
  try {
    const out = await provider[method](...args);
    return out === undefined || out === null ? fallback : out;
  } catch (err) {
    console.warn(`[CourseDirectory] ${method} failed:`, err.message);
    return fallback;
  }
}

/**
 * Normalize whatever the provider returned into the shape core promises.
 *
 * Providers hand back their own rows; core must not spread a cle_course row
 * into an API response, because that publishes columns (features, provision
 * status, dates) nobody asked for and couples the wire format to a plugin's
 * schema.
 */
function toCourse(row) {
  if (!row) return null;
  const courseId = row.courseId || row.course_id;
  if (!courseId) return null;
  return {
    courseId: String(courseId),
    courseName: row.courseName || row.course_name || null,
    courseCode: row.courseCode || row.code || null,
    instructorUserId: row.instructorUserId || row.instructor_id || null,
  };
}

function toCourses(rows) {
  return (Array.isArray(rows) ? rows : []).map(toCourse).filter(Boolean);
}

/** Courses this person is ENROLLED in. Empty for an instructor's own course. */
async function coursesForStudent(userId) {
  if (!userId) return [];
  return toCourses(await safely('coursesForStudent', [String(userId)], []));
}

/**
 * Courses this person TEACHES.
 *
 * Not the complement of coursesForStudent: an instructor is never enrolled in
 * their own course (cle_course_enrollment.enrollment_role has no 'instructor'
 * value), so the two lists are disjoint and both are needed.
 */
async function coursesForInstructor(userId) {
  if (!userId) return [];
  return toCourses(await safely('coursesForInstructor', [String(userId)], []));
}

/** One course by id, or null. */
async function describeCourse(courseId) {
  if (!courseId) return null;
  return toCourse(await safely('describeCourse', [String(courseId)], null));
}

/**
 * THE AUTHORITY for "may this person file a ticket against this course".
 *
 * Resolved from the enrolled list rather than by asking the provider a yes/no
 * question, so there is exactly one definition of enrolment in play and it is
 * the same one that built the dropdown. A client-supplied courseId that is not
 * in this list is refused; the snapshot columns on the ticket then come from
 * the object returned here, never from the request body.
 */
async function isEnrolled(userId, courseId) {
  if (!userId || !courseId) return null;
  const wanted = String(courseId);
  const courses = await coursesForStudent(userId);
  return courses.find(c => c.courseId === wanted) || null;
}

/**
 * The course a ticket may be filed against by this person, whatever their role.
 *
 * An instructor filing a ticket about their own course is a real and common
 * case — "the lab template for CYBR 400 is broken" — and they are not enrolled
 * in it, so isEnrolled() alone would refuse them. Admins may name any course.
 */
async function resolveTicketCourse(user, courseId) {
  if (!user || !courseId) return null;
  if (user.role === 'admin') return describeCourse(courseId);

  const enrolled = await isEnrolled(user.userId, courseId);
  if (enrolled) return enrolled;

  if (user.role === 'instructor') {
    const wanted = String(courseId);
    const taught = await coursesForInstructor(user.userId);
    return taught.find(c => c.courseId === wanted) || null;
  }
  return null;
}

/**
 * Every course this person may attach a ticket to, for the form's dropdown.
 * Enrolled first — the common case is a student — then taught, deduped.
 */
async function coursesForTicketForm(user) {
  if (!user) return [];
  const enrolled = await coursesForStudent(user.userId);
  if (user.role !== 'instructor' && user.role !== 'admin') return enrolled;

  const taught = await coursesForInstructor(user.userId);
  const seen = new Set(enrolled.map(c => c.courseId));
  return enrolled.concat(taught.filter(c => !seen.has(c.courseId)));
}

module.exports = {
  REQUIRED_METHODS,
  registerCourseDirectory,
  hasCourseDirectory,
  resetCourseDirectory,
  coursesForStudent,
  coursesForInstructor,
  describeCourse,
  isEnrolled,
  resolveTicketCourse,
  coursesForTicketForm,
};
