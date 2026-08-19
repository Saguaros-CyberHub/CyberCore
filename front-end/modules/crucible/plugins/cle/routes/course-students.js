/**
 * CLE Plugin — Course Students Routes
 * Handles student enrollment: list, add, remove, manage
 * Mounted at /api/cle/courses/:courseId/students
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { canManageCourse } = require('../utils/course-access');
const { resolveSelfTarget } = require('../utils/students');
const guacCreds = require('../../../../../src/utils/guac-credentials');
const prov = require('../../../../../src/utils/account-provisioning');
const activation = require('../../../../../src/utils/activation');
const audit = require('../../../../../src/utils/audit');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET / — List students in a course
 *
 * ?include_self=1 appends the CALLER as an extra, clearly-marked row
 * (`is_self`, enrollment_role 'instructor'), so the deploy modals can offer an
 * instructor a machine of their own without them having to enrol in their own
 * course. The Students tab does not pass it, so the roster — and every count
 * derived from it — is unchanged.
 *
 * Appended only when they are NOT already actively enrolled: a TA teaching
 * their own section is in the roster already, and would otherwise be listed
 * twice with two checkboxes for one person.
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const includeSelf = req.query.include_self === '1' || req.query.include_self === 'true';

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Resolved before the roster queries so its id can ride along in the same
    // user / lane-count / activation lookups rather than costing three more.
    const self = includeSelf ? await resolveSelfTarget(courseId, req.user).catch(() => null) : null;
    const selfRow = (self && !self.enrolled) ? self : null;

    // Get enrolled students
    // Step 1: Get enrollments from cle_db
    const enrollmentsResult = await query(`
      SELECT
        e.user_id,
        e.enrollment_role,
        e.enrolled_at,
        e.status
      FROM cle_course_enrollment e
      WHERE e.course_id = $1 AND e.status = 'active'
      ORDER BY e.enrolled_at DESC
    `, [courseId]);

    // Step 2: Get user details + workstation-lane counts from cybercore_db
    const userIds = enrollmentsResult.rows.map(r => r.user_id);
    if (selfRow) userIds.push(selfRow.user_id);
    let userMap = {};
    const laneCounts = {}; // user_id → count
    let pendingActivation = {};
    if (userIds.length > 0) {
      // role/auth_provider/mfa/provenance are selected so the per-row
      // credential controls can be decided SERVER-SIDE. The UI must never infer
      // them, or it would offer buttons the API refuses.
      const usersResult = await cybercoreQuery(`
        SELECT user_id, email, username, first_name, last_name, role,
               auth_provider, mfa_enabled, provisioned_via, provisioned_ref, activated_at
        FROM cybercore_user
        WHERE user_id = ANY($1)
      `, [userIds]);
      usersResult.rows.forEach(u => {
        userMap[u.user_id] = u;
      });

      // "Invited but hasn't set a password yet" — otherwise an instructor has
      // no way to tell that apart from "invitation never arrived".
      pendingActivation = await activation.pendingActivationFor(userIds).catch(() => ({}));

      const lc = await cybercoreQuery(`
        SELECT user_id, COUNT(*)::int AS vm_count
          FROM cybercore_lane
         WHERE user_id = ANY($1) AND config->>'course_id' = $2 AND status <> 'deleted'
         GROUP BY user_id
      `, [userIds, courseId]).catch(() => ({ rows: [] }));
      lc.rows.forEach(r => { laneCounts[r.user_id] = r.vm_count; });
    }

    // Step 3: Merge user data with enrollments
    const students = enrollmentsResult.rows.map(e => {
      const u = userMap[e.user_id];
      return {
        user_id: e.user_id,
        email: u?.email || 'unknown',
        username: u?.username || null,
        first_name: u?.first_name || '',
        last_name: u?.last_name || '',
        enrollment_role: e.enrollment_role,
        enrolled_at: e.enrolled_at,
        status: e.status,
        vm_count: laneCounts[e.user_id] || 0,
        // Staff enrolled in a course are ordinary members of it, but the
        // instructor has no account-level power over them. Both flags are
        // computed here rather than in the browser, and can_regenerate is the
        // exact same predicate the credential routes enforce.
        elevated: u ? prov.isElevatedAccount(u) : false,
        can_regenerate: u ? prov.canManageAccount(u, req.user, courseId) : false,
        activation_pending: !!pendingActivation[e.user_id],
        activated: !!u?.activated_at,
      };
    });

    // The caller's own row, marked so the UI can label it "you" and keep it out
    // of anything that means "the class" (counts, Deploy Whole Class). It is
    // deliberately FIRST: it is the row the instructor is looking for when they
    // opened the modal to build themselves a machine.
    if (selfRow) {
      const u = userMap[selfRow.user_id];
      students.unshift({
        user_id: selfRow.user_id,
        email: selfRow.email,
        username: u?.username || null,
        first_name: selfRow.first_name,
        last_name: selfRow.last_name,
        enrollment_role: 'instructor',
        enrolled_at: null,
        status: 'active',
        vm_count: laneCounts[selfRow.user_id] || 0,
        elevated: u ? prov.isElevatedAccount(u) : true,
        // No account-management controls on your own row — the credential
        // routes refuse a self-target, so offering the buttons would only 403.
        can_regenerate: false,
        activation_pending: false,
        activated: true,
        is_self: true,
      });
    }

    res.json({ students });
  } catch (error) {
    console.error('[CLE] Get students error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /credentials — Guacamole console logins for the whole roster, so an
 * instructor can look one up whenever a student loses theirs instead of having
 * their machines reprovisioned.
 *
 * Read-only: it never issues an account. A student with no password yet reports
 * `available: false`, and the per-student endpoint
 * (GET .../students/:id/guac/credentials?issue=true) mints one on demand.
 *
 * Instructor/admin gated, and the disclosure is logged — a Guacamole password
 * reaches every console that student owns.
 */
router.get('/credentials', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Learner enrollments only. A Guacamole password is that account's whole
    // session, and an instructor can enroll any email address in their own
    // course — so the roster is not, by itself, authority to read a credential.
    // getGuacCredentialsForUsers applies the same rule again by account role.
    const enrolled = await query(
      `SELECT user_id FROM cle_course_enrollment
        WHERE course_id = $1
          AND status IN ('active', 'completed')
          AND enrollment_role IN ('student', 'guest')`,
      [courseId]
    );
    const userIds = enrolled.rows.map(r => r.user_id);
    if (userIds.length === 0) return res.json({ credentials: [] });

    const byUser = await guacCreds.getGuacCredentialsForUsers(userIds, req.user);

    await query(
      `INSERT INTO cle_activity_log (user_id, action_type, entity_type, entity_id, metadata)
       VALUES ($1, 'guac_session', 'guac_credential', NULL, $2::jsonb)`,
      [req.user.userId, JSON.stringify({ action: 'view_cohort_credentials', course_id: courseId, count: userIds.length })]
    ).catch(err => console.warn(`[CLE] Could not log cohort credential access: ${err.message}`));

    res.json({
      credentials: userIds.map(id => ({
        user_id: id,
        ...(byUser[id] || { username: null, password: null, available: false }),
      })),
      // Told once, at the top level: without the key nothing can be decrypted,
      // which is different from every student simply not having a password.
      ...(process.env.GUAC_ENCRYPT_KEY ? {} : {
        hint: 'GUAC_ENCRYPT_KEY is not configured on this server, so stored console passwords cannot be decrypted.',
      }),
    });
  } catch (error) {
    console.error('[CLE] Get cohort credentials error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST / — Add student to course
 */
router.post('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { user_email, enrollment_role } = req.body;

    if (!user_email) {
      return res.status(400).json({ error: 'user_email is required' });
    }

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Find user in cybercore_user by email
    const userResult = await cybercoreQuery(`
      SELECT user_id FROM cybercore_user
      WHERE LOWER(email) = LOWER($1)
    `, [user_email]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: `User not found: ${user_email}` });
    }

    const userId = userResult.rows[0].user_id;

    // Add or reactivate enrollment
    const enrollResult = await query(`
      INSERT INTO cle_course_enrollment
        (user_id, course_id, enrollment_role, status, enrolled_at)
      VALUES ($1, $2, $3, 'active', NOW())
      ON CONFLICT (user_id, course_id)
      DO UPDATE SET
        status = 'active',
        enrollment_role = EXCLUDED.enrollment_role,
        enrolled_at = NOW()
      RETURNING *
    `, [userId, courseId, enrollment_role || 'student']);

    audit.log({
      req,
      action: 'enrollment.student_added',
      source: 'cle',
      target:     { type: 'course', id: courseId },
      targetUser: { id: userId, label: user_email },
      metadata: { course_id: courseId, enrollment_role: enrollment_role || 'student' },
    });

    res.json({ success: true, enrollment: enrollResult.rows[0] });
  } catch (error) {
    console.error('[CLE] Add student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /:studentId — Remove student from course
 */
router.delete('/:studentId', instructorOnly, async (req, res) => {
  try {
    const { courseId, studentId } = req.params;

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    // Soft delete enrollment
    await query(`
      UPDATE cle_course_enrollment
      SET status = 'dropped', updated_at = NOW()
      WHERE user_id = $1 AND course_id = $2
    `, [studentId, courseId]);

    audit.log({
      req,
      action: 'enrollment.student_removed',
      source: 'cle',
      target:     { type: 'course', id: courseId },
      targetUser: { id: studentId },
      metadata: { course_id: courseId, soft_delete: true },
    });

    res.json({ success: true, message: 'Student removed from course' });
  } catch (error) {
    console.error('[CLE] Remove student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
