/**
 * ============================================================================
 * CIAB Plugin — Section roster helpers
 * ============================================================================
 * Classification and enrollment logic for the CIAB roster import, kept out of
 * the route handlers per the repo convention ("keep route handlers thin; put
 * logic in utils").
 *
 * A DELIBERATE COPY of cle/utils/roster.js, not a require() across plugins.
 * Reaching into a sibling plugin at runtime means deactivating CLE silently
 * breaks CIAB's importer -- the same reason the CSV parser was promoted to
 * public/js/csv.js rather than sourced from /cle/js/. Promoting this file to
 * src/utils/ parameterised by table name is the tidier end state, but it would
 * touch every CLE roster path, several of which have only partial test
 * coverage. Extract once ciab-section-roster.test.js covers both callers.
 *
 * The interesting decision, inherited verbatim, is the split between ENROLLMENT
 * and ACCOUNT POWER. Enrolling anyone -- including an admin or another
 * instructor -- is allowed and normal. What must be impossible is an instructor
 * exercising account-level control over someone who is not their own student.
 * So classification records `elevated` and `can_regenerate` per row, and every
 * account-level action re-derives the answer from cybercore_user rather than
 * trusting the roster.
 */

const { query } = require('./db');
const prov = require('../../../../../src/utils/account-provisioning');

// Matches the cap on POST /api/admin/users/batch and CLE's importer. A roster
// larger than this is a data-entry mistake far more often than a real class.
const MAX_ROWS = 500;

/** Row actions, in the order a preview lists them. */
const ACTIONS = {
  CREATE: 'create',                   // no account exists — mint one and invite
  ENROLL_EXISTING: 'enroll_existing', // account exists — enroll, don't touch it
  REACTIVATE: 'reactivate',           // previously dropped from this section
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
    const line = Number(raw && raw.line) || i + 1;
    const rawEmail = String((raw && raw.email) != null ? raw.email : '').trim();
    const email = prov.normalizeEmail(rawEmail);

    const base = {
      line,
      email: email || rawEmail,
      first_name: String((raw && (raw.first_name ?? raw.firstName)) ?? '').trim() || null,
      last_name: String((raw && (raw.last_name ?? raw.lastName)) ?? '').trim() || null,
    };

    if (!email || !prov.isEmailShaped(email)) {
      out.push({
        ...base,
        action: ACTIONS.INVALID,
        reason: rawEmail ? 'not a valid email address' : 'no email address',
      });
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
 * @param {Array}  rows       output of normalizeRows()
 * @param {string} sectionId
 * @param {object} caller     req.user
 * @returns {Promise<Array>}  rows annotated with action / elevated / can_regenerate
 */
async function classifyRows(rows, sectionId, caller) {
  const candidates = rows.filter((r) => !r.action);
  const users = await prov.findUsersByEmails(candidates.map((r) => r.email));

  // One query for the whole section rather than one per row.
  const enrollments = await query(
    `SELECT user_id, status FROM ciab_enrollment WHERE section_id = $1`,
    [sectionId]
  );
  const enrolledStatus = new Map(enrollments.rows.map((r) => [r.user_id, r.status]));

  return rows.map((row) => {
    if (row.action) return row;   // already invalid or a duplicate

    const user = users.get(row.email);
    if (!user) {
      return { ...row, action: ACTIONS.CREATE, elevated: false, can_regenerate: true };
    }

    const elevated = prov.isElevatedAccount(user);
    // Computed server-side from provenance, never inferred by the client: the
    // UI must not offer a button the API will refuse.
    const canRegenerate = prov.canManageAccount(user, caller, sectionId);

    // An account that already exists keeps whatever name it has, EXCEPT when it
    // has none and the roster supplies one. That is the repair path for
    // accounts created by an import that could not read the name column --
    // without it, re-importing a corrected file changes nothing, because
    // provisionAccount() short-circuits on an email that already exists.
    const fillsFirst = !String(user.first_name || '').trim() && !!row.first_name;
    const fillsLast = !String(user.last_name || '').trim() && !!row.last_name;

    const annotated = {
      ...row,
      user_id: user.user_id,
      elevated,
      can_regenerate: canRegenerate,
      ...(fillsFirst || fillsLast ? { name_backfill: true } : {}),
      ...(elevated ? {
        warning: `This is a ${user.role} account. It will be enrolled in the section, `
               + 'but you have no password or credential controls over it.',
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
 * Slug for generated usernames, derived from the section code.
 *
 * Hyphen-PRESERVING, unlike the group-deploy slug at admin/groups.js:142 and
 * CIAB's own profile-deploy.js:330, both of which strip every non-alphanumeric
 * and flatten `CYBR-480-7W1-1` to `cybr4807w11`. That loses exactly the
 * readability an instructor wants when reading a name off a printed sheet to a
 * student. The result still satisfies the username rule (/^[a-z0-9._-]+$/i,
 * admin/settings.js:417), so the admin user editor keeps accepting these.
 */
function cohortSlug(section) {
  return String((section && (section.code || section.name)) || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** `cybr-480-7w1-1-student7` */
function cohortUsername(section, index) {
  const slug = cohortSlug(section);
  return slug ? `${slug}-student${index}` : `student${index}`;
}

/**
 * Synthetic address for a generated account.
 *
 * cybercore_user.email is NOT NULL and Guacamole accounts are email-keyed
 * throughout, so these need one. `.invalid` is the RFC-reserved never-
 * deliverable TLD, and mailer.checkRecipient() hard-suppresses it regardless of
 * any other setting -- a burst of undeliverable credential mail from a new IP
 * is the fastest way to lose a sending reputation.
 *
 * Note this is NOT the @clinic.local pattern profile-deploy.js uses for lane
 * accounts. Those are a different population with a different lifecycle; a
 * shared domain would make the two indistinguishable in the admin user list.
 */
function cohortEmail(section, index) {
  const domain = process.env.CIAB_COHORT_EMAIL_DOMAIN || 'cohort.invalid';
  return `${cohortUsername(section, index)}@${domain}`;
}

/**
 * Plan a cohort run: which indices to use, and which are already taken.
 *
 * Generation is resumable on purpose. An instructor who made 25 accounts and
 * needs 5 more should get student26..30, not a collision error -- so occupied
 * indices are skipped rather than treated as a failure.
 */
async function planCohort(section, { count, startIndex = 1 }) {
  const slug = cohortSlug(section);
  const existing = await prov.findUsersByEmails(
    // Probe a generous window so a sparse range (some accounts deleted) still
    // resolves without a query per candidate.
    Array.from({ length: count + 200 }, (_, i) => cohortEmail(section, startIndex + i))
  );

  const planned = [];
  const skipped = [];
  let index = startIndex;
  let guard = 0;

  while (planned.length < count && guard++ < count + 500) {
    const email = cohortEmail(section, index);
    if (existing.has(email)) {
      skipped.push({ index, username: cohortUsername(section, index), reason: 'already exists' });
    } else {
      planned.push({ index, username: cohortUsername(section, index), email });
    }
    index++;
  }

  return { slug, planned, skipped };
}

// ============================================================================
// RUN ASSESSMENT
// ============================================================================

/** How many active seats a section is currently using. */
async function seatsUsed(sectionId) {
  const r = await query(
    `SELECT COUNT(*)::int AS n FROM ciab_enrollment
      WHERE section_id = $1 AND status = 'active'`,
    [sectionId]
  );
  return (r.rows[0] && r.rows[0].n) || 0;
}

/** Rows that would consume a seat: everything that is not already active. */
function willEnrollCount(classified) {
  return classified.filter((r) => (
    r.action === ACTIONS.CREATE
    || r.action === ACTIONS.ENROLL_EXISTING
    || r.action === ACTIONS.REACTIVATE
  )).length;
}

/**
 * Build the blocking errors and non-blocking warnings for a run.
 *
 * Unlike CLE, max_students here does NOT size a lab network -- a CIAB section
 * provisions nothing. It is a cap the instructor chose, so it is still a hard
 * block (silently exceeding a number someone typed is its own bug) but the
 * message says how to change it rather than implying something is impossible.
 */
function assessRun(classified, section, used) {
  const errors = [];
  const warnings = [];

  const adding = willEnrollCount(classified);
  const after = used + adding;
  const max = Number(section && section.max_students) || 0;

  if (max > 0 && after > max) {
    errors.push(
      `Enrolling ${adding} student${adding === 1 ? '' : 's'} would put this section at ${after} `
      + `of ${max} seats. Remove ${after - max} from the roster, or raise the seat limit in `
      + 'the section settings.'
    );
  }

  if (section && section.status === 'archived') {
    errors.push(
      'This section is archived, so its students have no Clinic-in-a-Box access. '
      + 'Reactivate it before enrolling anyone.'
    );
  }

  const elevated = classified.filter((r) => r.elevated).length;
  if (elevated > 0) {
    warnings.push(
      `${elevated} address${elevated === 1 ? ' belongs' : 'es belong'} to staff accounts. `
      + 'They will be enrolled normally, but you will not have password or credential '
      + 'controls over them.'
    );
  }

  const invalid = classified.filter((r) => r.action === ACTIONS.INVALID).length;
  if (invalid > 0) {
    warnings.push(`${invalid} row${invalid === 1 ? '' : 's'} could not be read and will be skipped.`);
  }

  return { errors, warnings };
}

// ============================================================================
// WRITES
// ============================================================================

/**
 * Enroll a user, or reactivate a previously dropped enrollment.
 *
 * The caller is responsible for enrollment.invalidate(userId) afterwards. It is
 * NOT done here because a bulk run enrolls hundreds of rows and should clear the
 * cache once at the end, not once per row -- and because this module has no
 * business reaching into the gate's internals.
 *
 * provisioned_via / provisioned_import_id are a DISPLAY mirror. Authorization
 * reads cybercore_user, because these are written by the same instructor-facing
 * routes that would be doing the asking.
 */
async function enroll(userId, sectionId, { role = 'student', via = null, importId = null } = {}) {
  const r = await query(
    `INSERT INTO ciab_enrollment
       (user_id, section_id, enrollment_role, status, enrolled_at, provisioned_via, provisioned_import_id)
     VALUES ($1, $2, $3, 'active', NOW(), $4, $5)
     ON CONFLICT (user_id, section_id)
     DO UPDATE SET
       status = 'active',
       enrollment_role = EXCLUDED.enrollment_role,
       enrolled_at = NOW(),
       updated_at = NOW(),
       completed_at = NULL,
       provisioned_via = COALESCE(ciab_enrollment.provisioned_via, EXCLUDED.provisioned_via),
       provisioned_import_id = COALESCE(EXCLUDED.provisioned_import_id, ciab_enrollment.provisioned_import_id)
     RETURNING enrollment_id`,
    [userId, sectionId, role, via, importId]
  );
  return r.rows[0];
}

/**
 * Record the run. `results` deliberately excludes passwords and activation
 * tokens -- the point of this row is to explain what happened, and neither of
 * those explains anything.
 */
async function recordImport({ sectionId, actorId, source, notify, summary, results, importId = null }) {
  // importId is supplied by the CSV path, which needs the id BEFORE the run so
  // it can stamp it onto every queued invitation's context. mailer
  // .statusForImport() looks the outbox up by context->>'import_id', so minting
  // the id only after the loop -- the obvious ordering -- would leave
  // GET /email-status permanently empty for exactly the runs that send mail.
  const r = await query(
    `INSERT INTO ciab_roster_import
       (import_id, section_id, actor_id, source, total_rows, created_count, enrolled_count,
        skipped_count, failed_count, notify, results)
     VALUES (COALESCE($1::uuid, uuid_generate_v4()), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
     RETURNING import_id, created_at`,
    [
      importId, sectionId, actorId, source,
      summary.total || 0, summary.created || 0, summary.enrolled || 0,
      summary.skipped || 0, summary.failed || 0, notify !== false,
      JSON.stringify(results || []),
    ]
  );
  return r.rows[0];
}

/**
 * Audit trail in clinic_db's own activity_log.
 *
 * CIAB's action_type is a plain VARCHAR(50) with no CHECK enum (001_ciab_schema
 * .sql:89), unlike cle_activity_log -- so the real action goes in the column
 * rather than being smuggled through metadata the way CLE has to.
 *
 * Best-effort: a failed audit write must never fail the enrollment it describes.
 */
function logRosterActivity({ actorId, sectionId, action, detail }) {
  return query(
    `INSERT INTO activity_log (user_id, action_type, entity_type, entity_id, metadata)
     VALUES ($1, $2, 'ciab_section', $3, $4::jsonb)`,
    [actorId, `roster.${action}`, sectionId, JSON.stringify({ section_id: sectionId, ...detail })]
  ).catch((err) => console.warn(`[CIAB] Could not log roster activity: ${err.message}`));
}

module.exports = {
  MAX_ROWS, ACTIONS,
  normalizeRows, classifyRows,
  cohortSlug, cohortUsername, cohortEmail, planCohort,
  seatsUsed, willEnrollCount, assessRun,
  enroll, recordImport, logRosterActivity,
};
