/**
 * CLE Plugin — Course access control
 * ----------------------------------------------------------------------------
 * Admin-aware ownership check shared by every course-scoped route (students,
 * labs, VMs, RDP monitoring). Admins may manage any course; instructors only
 * the courses they are assigned to.
 *
 * Every nested course tab MUST gate on this. A strict `instructor_id = $2`
 * check with no admin branch makes the tab 403 ("Course not found or access
 * denied") for an admin viewing another instructor's course — even though the
 * Overview tab (which is admin-aware) loads fine.
 */

const { query } = require('./db');

/**
 * Fetch a course the caller may manage, or null. Admins match any course;
 * instructors only their own.
 *
 * @param {string} courseId
 * @param {{ role: string, userId: string }} user  req.user
 * @param {string} [columns]  columns to SELECT. MUST be a trusted static
 *   string (it is interpolated into the query) — never pass user input.
 * @returns {Promise<object|null>} the course row, or null if absent/denied
 */
async function getManagedCourse(courseId, user, columns = 'course_id') {
  const isAdmin = user.role === 'admin';
  const r = await query(
    isAdmin
      ? `SELECT ${columns} FROM cle_course WHERE course_id = $1`
      : `SELECT ${columns} FROM cle_course WHERE course_id = $1 AND instructor_id = $2`,
    isAdmin ? [courseId] : [courseId, user.userId]
  );
  return r.rows[0] || null;
}

/** Boolean convenience wrapper around {@link getManagedCourse}. */
async function canManageCourse(courseId, user) {
  return (await getManagedCourse(courseId, user)) !== null;
}

module.exports = { getManagedCourse, canManageCourse };
