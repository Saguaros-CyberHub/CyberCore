/**
 * ============================================================================
 * CLE Plugin — Roster helpers
 * ============================================================================
 * Classification and enrollment logic for the roster import, kept out of the
 * route handlers per the repo convention ("keep route handlers thin; put logic
 * in utils").
 *
 * The interesting decision in here is the split between ENROLLMENT and ACCOUNT
 * POWER. Enrolling anyone — including an admin or another instructor — is
 * allowed and normal: staff sit in on courses, TAs take other sections. What
 * must be impossible is an instructor exercising account-level control over
 * someone who is not their own student. So classification records `elevated`
 * and `can_regenerate` per row, and every account-level action re-derives the
 * answer from cybercore_user rather than trusting the roster.
 */

const { query } = require('./db');
const prov = require('../../../../../src/utils/account-provisioning');

// Matches the cap on POST /api/admin/users/batch. A roster larger than this is
// a data-entry mistake far more often than a real class.
const MAX_ROWS = 500;

/** Row actions, in the order a preview lists them. */
const ACTIONS = {
  CREATE: 'create',                   // no account exists — mint one and invite
  ENROLL_EXISTING: 'enroll_existing', // account exists — enroll, don't touch it
  REACTIVATE: 'reactivate',           // previously dropped from this course
  ALREADY_ENROLLED: 'already_enrolled',
  SKIP: 'skip',                       // duplicate within the file
  INVALID: 'invalid',                 // unusable row
};

/**
 * Normalize and de-duplicate submitted rows.
 *
 * Duplicates within one file are common (a roster exported twice, or a student
 * listed in two sections) and must collapse to one action rather than racing
 * each other through account creation.
 */
function normalizeRows(rows) {
  const seen = new Map();   // normalized email -> first line number
  const out = [];

  (rows || []).forEach((raw, i) => {
    const line = Number(raw?.line) || i + 1;
    const rawEmail = String(raw?.email ?? '').trim();
    const email = prov.normalizeEmail(rawEmail);

    const base = {
      line,
      email: email || rawEmail,
      first_name: String(raw?.first_name ?? raw?.firstName ?? '').trim() || null,
      last_name: String(raw?.last_name ?? raw?.lastName ?? '').trim() || null,
    };

    if (!email || !prov.isEmailShaped(email)) {
      out.push({ ...base, action: ACTIONS.INVALID, reason: rawEmail ? 'not a valid email address' : 'no email address' });
      return;
    }
    if (seen.has(email)) {
      out.push({ ...base, action: ACTIONS.SKIP, reason: `duplicate of line ${seen.get(email)}` });
      return;
    }
    seen.set(email, line);
    out.push(base);
  });

  return out;
}

/**
 * Decide what would happen to each row, without changing anything.
 *
 * @param {Array}  rows        output of normalizeRows()
 * @param {string} courseId
 * @param {object} caller      req.user
 * @returns {Promise<Array>}   rows annotated with action / elevated / can_regenerate
 */
async function classifyRows(rows, courseId, caller) {
  const candidates = rows.filter(r => !r.action);
  const users = await prov.findUsersByEmails(candidates.map(r => r.email));

  // One query for the whole course rather than one per row.
  const enrollments = await query(
    `SELECT user_id, status FROM cle_course_enrollment WHERE course_id = $1`,
    [courseId]
  );
  const enrolledStatus = new Map(enrollments.rows.map(r => [r.user_id, r.status]));

  return rows.map(row => {
    if (row.action) return row;   // already invalid or a duplicate

    const user = users.get(row.email);
    if (!user) {
      return { ...row, action: ACTIONS.CREATE, elevated: false, can_regenerate: true };
    }

    const elevated = prov.isElevatedAccount(user);
    // Computed server-side from provenance, never inferred by the client: the
    // UI must not offer a button the API will refuse.
    const canRegenerate = prov.canManageAccount(user, caller, courseId);

    const annotated = {
      ...row,
      user_id: user.user_id,
      elevated,
      can_regenerate: canRegenerate,
      ...(elevated ? {
        warning: `This is a ${user.role} account. It will be enrolled in the course, but you have no password or credential controls over it.`,
      } : {}),
    };

    const status = enrolledStatus.get(user.user_id);
    if (status === 'active') return { ...annotated, action: ACTIONS.ALREADY_ENROLLED, reason: 'already enrolled' };
    if (status) return { ...annotated, action: ACTIONS.REACTIVATE, reason: `previously ${status}` };
    return { ...annotated, action: ACTIONS.ENROLL_EXISTING };
  });
}

// ============================================================================
// COHORT GENERATION
// ============================================================================

/**
 * Slug for generated usernames, derived from the course code.
 *
 * Hyphen-PRESERVING, unlike the group-deploy slug at admin/groups.js:142 which
 * strips every non-alphanumeric and flattens `CYBR-480-7W1-1` to `cybr4807w11`.
 * That loses exactly the readability an instructor wants when reading a name
 * off a printed sheet to a student. The result still satisfies the username
 * rule (`/^[a-z0-9._-]+$/i`, admin/settings.js:417), so the admin user editor
 * keeps accepting these accounts.
 */
function cohortSlug(course) {
  return String(course.code || course.course_name || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** `cybr-480-7w1-1-student7` */
function cohortUsername(course, index) {
  const slug = cohortSlug(course);
  return slug ? `${slug}-student${index}` : `student${index}`;
}

/**
 * Synthetic address for a generated account.
 *
 * cybercore_user.email is NOT NULL and Guacamole accounts are email-keyed
 * throughout, so these need one. It points at a reserved domain that can never
 * receive mail, and mailer.checkRecipient() hard-suppresses it regardless of
 * any other setting — a burst of undeliverable credential mail from a new IP is
 * the fastest way to lose a sending reputation.
 */
function cohortEmail(course, index) {
  const domain = process.env.CLE_COHORT_EMAIL_DOMAIN || 'cohort.invalid';
  return `${cohortUsername(course, index)}@${domain}`;
}

/**
 * Plan a cohort run: which indices to use, and which are already taken.
 *
 * Generation is resumable on purpose. An instructor who made 25 accounts and
 * needs 5 more should get student26..30, not a collision error — so occupied
 * indices are skipped rather than treated as a failure.
 */
async function planCohort(course, { count, startIndex = 1 }) {
  const slug = cohortSlug(course);
  const existing = await prov.findUsersByEmails(
    // Probe a generous window so a sparse range (some accounts deleted) still
    // resolves without a query per candidate.
    Array.from({ length: count + 200 }, (_, i) => cohortEmail(course, startIndex + i))
  );

  const planned = [];
  const skipped = [];
  let index = startIndex;
  let guard = 0;

  while (planned.length < count && guard++ < count + 500) {
    const email = cohortEmail(course, index);
    if (existing.has(email)) {
      skipped.push({ index, username: cohortUsername(course, index), reason: 'already exists' });
    } else {
      planned.push({ index, username: cohortUsername(course, index), email });
    }
    index++;
  }

  return { slug, planned, skipped };
}

/** How many active seats a course is currently using. */
async function seatsUsed(courseId) {
  const r = await query(
    `SELECT COUNT(*)::int AS n FROM cle_course_enrollment
      WHERE course_id = $1 AND status = 'active'`,
    [courseId]
  );
  return r.rows[0]?.n || 0;
}

/** Rows that would consume a seat: everything that is not already active. */
function willEnrollCount(classified) {
  return classified.filter(r =>
    r.action === ACTIONS.CREATE ||
    r.action === ACTIONS.ENROLL_EXISTING ||
    r.action === ACTIONS.REACTIVATE
  ).length;
}

/**
 * Build the blocking errors and non-blocking warnings for a run.
 *
 * The seat cap is a hard block, and the message says why in full: max_students
 * sized this course's VXLAN block once, at course creation (see
 * provisionCourseLab in routes/courses.js). An over-enrolled student can never
 * be given a workstation, so quietly enrolling them past the cap would trade a
 * clear error now for a confusing one at lab time.
 */
function assessRun(classified, course, used) {
  const errors = [];
  const warnings = [];

  const adding = willEnrollCount(classified);
  const after = used + adding;
  const max = Number(course.max_students) || 0;

  if (max > 0 && after > max) {
    errors.push(
      `Enrolling ${adding} student${adding === 1 ? '' : 's'} would put this course at ${after} of ${max} seats. ` +
      `The seat limit sized this course's lab network when the course was created, so a student past it could ` +
      `never be given a workstation. Remove ${after - max} from the roster, or ask an administrator to recreate ` +
      `the course with a higher limit.`
    );
  }

  if (course.provision_status && course.provision_status !== 'ready') {
    warnings.push(
      course.provision_status === 'failed'
        ? "This course's lab failed to provision, so workstations cannot be deployed yet. Enrollment still works."
        : "This course's lab is still provisioning. Enrollment works now; workstations can be deployed once it is ready."
    );
  }

  const elevated = classified.filter(r => r.elevated).length;
  if (elevated > 0) {
    warnings.push(
      `${elevated} address${elevated === 1 ? ' belongs' : 'es belong'} to staff accounts. They will be enrolled ` +
      `normally, but you will not have password or credential controls over them.`
    );
  }

  const invalid = classified.filter(r => r.action === ACTIONS.INVALID).length;
  if (invalid > 0) warnings.push(`${invalid} row${invalid === 1 ? '' : 's'} could not be read and will be skipped.`);

  return { errors, warnings };
}

/**
 * Enroll a user, or reactivate a previously dropped enrollment.
 *
 * Same ON CONFLICT shape the single-student route has always used, plus the
 * provenance mirror. Those two columns are for DISPLAY only — authorization
 * reads cybercore_user, because these are written by the same instructor-facing
 * routes that would be doing the asking.
 */
async function enroll(userId, courseId, { role = 'student', via = null, importId = null } = {}) {
  const r = await query(
    `INSERT INTO cle_course_enrollment
       (user_id, course_id, enrollment_role, status, enrolled_at, provisioned_via, provisioned_import_id)
     VALUES ($1, $2, $3, 'active', NOW(), $4, $5)
     ON CONFLICT (user_id, course_id)
     DO UPDATE SET
       status = 'active',
       enrollment_role = EXCLUDED.enrollment_role,
       enrolled_at = NOW(),
       provisioned_via = COALESCE(cle_course_enrollment.provisioned_via, EXCLUDED.provisioned_via),
       provisioned_import_id = COALESCE(EXCLUDED.provisioned_import_id, cle_course_enrollment.provisioned_import_id)
     RETURNING enrollment_id`,
    [userId, courseId, role, via, importId]
  );
  return r.rows[0];
}

/**
 * Record the run. `results` deliberately excludes passwords and activation
 * tokens — the point of this row is to explain what happened, and neither of
 * those explains anything.
 */
async function recordImport({ courseId, actorId, source, notify, summary, results }) {
  const r = await query(
    `INSERT INTO cle_roster_import
       (course_id, actor_id, source, total_rows, created_count, enrolled_count,
        skipped_count, failed_count, notify, results)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
     RETURNING import_id, created_at`,
    [
      courseId, actorId, source,
      summary.total || 0, summary.created || 0, summary.enrolled || 0,
      summary.skipped || 0, summary.failed || 0, notify !== false,
      JSON.stringify(results || []),
    ]
  );
  return r.rows[0];
}

/**
 * cle_activity_log.action_type has a CHECK enum with no value for this, so file
 * under the closest permitted one with the real action in metadata. Widening the
 * enum would need a migration and would break rows written by an older deploy —
 * the same workaround routes/guacamole.js documents.
 */
function logRosterActivity({ actorId, courseId, action, detail }) {
  return query(
    `INSERT INTO cle_activity_log (user_id, action_type, entity_type, entity_id, metadata)
     VALUES ($1, 'enrollment_change', 'roster_import', NULL, $2::jsonb)`,
    [actorId, JSON.stringify({ action, course_id: courseId, ...detail })]
  ).catch(err => console.warn(`[CLE] Could not log roster activity: ${err.message}`));
}

module.exports = {
  MAX_ROWS, ACTIONS,
  normalizeRows, classifyRows,
  cohortSlug, cohortUsername, cohortEmail, planCohort,
  seatsUsed, willEnrollCount, assessRun,
  enroll, recordImport, logRosterActivity,
};
