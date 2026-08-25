/**
 * ============================================================================
 * ACCOUNT PROVISIONING
 * ============================================================================
 * The one place local accounts are minted.
 *
 * Before this module the platform had four independent implementations —
 * admin single-create, admin batch, group deploy, and the CIAB profile deploy —
 * which disagreed about bcrypt cost (10 vs 12), username derivation, duplicate
 * handling, and whether the stored email was lowercased. That last disagreement
 * was a live bug: a roster row with a capitalized address produced an account
 * that could never sign in.
 *
 * It also owns PROVENANCE, which is not bookkeeping. `provisioned_via` and
 * `provisioned_ref` record which course minted an account, and that is the
 * authorization key which lets an instructor regenerate a password for an
 * account their own course created while making it impossible for them to touch
 * an account that existed beforehand. See assertCourseProvisionedStudent().
 */

const bcrypt = require('bcryptjs');
const { cybercoreQuery } = require('./cybercore-db');
const { generatePassword } = require('./password-generator');
const { normalizeEmail, isEmailShaped } = require('./email-normalize');
const guacCreds = require('./guac-credentials');
const audit = require('./audit');

/**
 * Auditing happens HERE, not in the six route handlers that call this module,
 * because this is the single path every local account is minted through. One
 * instrumentation point therefore covers self-registration, admin single and
 * batch create, group deploy, and the CLE roster import and cohort generator —
 * and every future caller for free.
 *
 * There is no `req` at this depth, so the actor comes from the provenance the
 * caller already supplies, and request context rides along in provenance.ctx
 * (built by audit.ctx(req)) when the caller has one.
 */
function auditProvision(provenance = {}, action, { user, status = 'success', reason = null, metadata = {} }) {
  return audit.log({
    actor:   { userId: provenance.by || null, type: provenance.by ? 'user' : 'system' },
    context: provenance.ctx || {},
    action,
    status,
    reason,
    target:     { type: 'user', id: user?.user_id, label: user?.email },
    targetUser: { id: user?.user_id, label: user?.email },
    metadata,
    source: provenance.source || 'core',
    eventGroupId: provenance.eventGroupId || null,
  });
}

// One cost for the whole platform. The old split (10 in admin batch, 12
// everywhere else) meant a roster-created account was measurably cheaper to
// crack than the same person's self-registered one, for no stated reason.
const BCRYPT_COST = 12;

// Same floor the self-service change at PUT /api/auth/password enforces. An
// admin must not be able to set a password weaker than the user could set for
// themselves; generatePassword()'s output always clears it.
const PASSWORD_MIN_LEN = 8;
const PASSWORD_COMPLEXITY_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/;

const VALID_ROLES = ['user', 'student', 'instructor', 'admin'];

// NULL means pre-existing or unknown. Validated here rather than by a CHECK
// constraint because the boot-time DDL re-runs on every start, and a CHECK
// evaluated against rows a newer deploy already wrote would fail outright.
const PROVISIONED_VIA = [
  'self_register', 'admin_single', 'admin_batch',
  'group_deploy', 'cle_import', 'cle_cohort',
  // Clinic-in-a-Box section rosters. Same two shapes as CLE: a CSV import
  // and a generated cohort.
  'ciab_import', 'ciab_cohort',
];

// Provenance values that grant an instructor credential control over the
// account. Anything else — including an account minted by a DIFFERENT course
// or section — is off limits.
//
// checkCourseProvisionedStudent() also compares provisioned_ref against the id
// the caller passes, so a CIAB instructor gets control over exactly the
// accounts their own section minted, with no extra authorization code.
const INSTRUCTOR_MANAGEABLE_VIA = [
  'cle_import', 'cle_cohort',
  'ciab_import', 'ciab_cohort',
];

// Postgres unique_violation. Both the email index and the username constraint
// surface as this; the `constraint` field distinguishes them.
const PG_UNIQUE_VIOLATION = '23505';

const USER_COLUMNS = `
  user_id, username, email, first_name, last_name, organization, role,
  status, active, auth_provider, mfa_enabled, email_verified,
  must_change_password, temp_password_expires_at, activated_at,
  provisioned_by, provisioned_via, provisioned_ref, created_at
`;

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

// ============================================================================
// USERNAMES
// ============================================================================

/**
 * Derive a login username from an email local-part: lowercase, keep only safe
 * characters. Moved verbatim from routes/admin/settings.js so every caller
 * derives the same name.
 *
 * Caller is responsible for de-duplicating — use allocateUsername() for that.
 */
function deriveUsername(email) {
  const local = String(email || '').split('@')[0] || '';
  const base = local.toLowerCase().replace(/[^a-z0-9._-]/g, '');
  return base || 'user';
}

/**
 * A unique username for `email`, de-duped against both the database and the
 * names already handed out in this batch.
 *
 * `taken` matters: a 300-row roster of `jsmith@…`, `jsmith@…` would otherwise
 * derive the same username twice, and only the second INSERT would discover it.
 *
 * @param {string} email
 * @param {{ taken?: Set<string>, base?: string }} [opts] `base` overrides derivation
 * @returns {Promise<string>}
 */
async function allocateUsername(email, opts = {}) {
  const taken = opts.taken instanceof Set ? opts.taken : new Set();
  const base = (opts.base || deriveUsername(email)).toLowerCase();

  const existing = await cybercoreQuery(
    `SELECT lower(username) AS u FROM cybercore_user
      WHERE lower(username) = $1 OR lower(username) LIKE $1 || '%'`,
    [base]
  );
  const used = new Set(existing.rows.map(r => r.u));
  for (const t of taken) used.add(String(t).toLowerCase());

  if (!used.has(base)) return base;
  let n = 2;
  while (used.has(`${base}${n}`)) n++;
  return `${base}${n}`;
}

// ============================================================================
// LOOKUP
// ============================================================================

/**
 * Load the guard-relevant row for an address, or null.
 *
 * Case-insensitive, using ux_cybercore_user_email_lower. Callers use this to
 * decide "create or enroll", so it must agree with what login sees — see
 * utils/email-normalize.js.
 */
async function findUserByEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;
  const result = await cybercoreQuery(
    `SELECT ${USER_COLUMNS} FROM cybercore_user WHERE lower(email) = $1`,
    [normalized]
  );
  return result.rows[0] || null;
}

/**
 * Batch form of findUserByEmail, keyed by normalized address.
 *
 * A 500-row roster classified one query at a time is 500 round trips before the
 * instructor sees a preview. One ANY() lookup is the difference between an
 * instant preview and a visibly slow one.
 *
 * @param {string[]} emails
 * @returns {Promise<Map<string, object>>} normalized email -> user row
 */
async function findUsersByEmails(emails) {
  const normalized = [...new Set(
    (emails || []).map(normalizeEmail).filter(Boolean)
  )];
  const out = new Map();
  if (normalized.length === 0) return out;

  const result = await cybercoreQuery(
    `SELECT ${USER_COLUMNS} FROM cybercore_user WHERE lower(email) = ANY($1::text[])`,
    [normalized]
  );
  for (const row of result.rows) out.set(normalizeEmail(row.email), row);
  return out;
}

/**
 * Fill in a name the account does not already have.
 *
 * WHY THIS EXISTS: provisionAccount() is idempotent on email -- it returns an
 * existing account untouched (see its `if (existing)` branch) -- and the roster
 * import's enroll-existing path never looked at names at all. So an account
 * created by an import that could not read the roster's name column stayed
 * nameless forever: re-importing a corrected file enrolled the same people
 * again and changed nothing, because they already existed.
 *
 * ONLY fills columns that are NULL or blank. A roster export is not
 * authoritative over a name someone has since corrected on their own profile,
 * and instructors re-run an import repeatedly across a semester.
 *
 * @returns {Promise<boolean>} true when something was actually written
 */
async function backfillMissingName(userId, { firstName = null, lastName = null } = {}) {
  const first = firstName ? String(firstName).trim() : '';
  const last = lastName ? String(lastName).trim() : '';
  if (!userId || (!first && !last)) return false;

  // The WHERE clause is what makes this a BACKFILL rather than an overwrite:
  // it matches only when at least one blank column has a value on offer.
  const result = await cybercoreQuery(
    `UPDATE cybercore_user
        SET first_name = COALESCE(NULLIF(first_name, ''), NULLIF($2::text, '')),
            last_name  = COALESCE(NULLIF(last_name,  ''), NULLIF($3::text, ''))
      WHERE user_id = $1
        AND ((NULLIF(first_name, '') IS NULL AND NULLIF($2::text, '') IS NOT NULL)
          OR (NULLIF(last_name,  '') IS NULL AND NULLIF($3::text, '') IS NOT NULL))
      RETURNING user_id`,
    [userId, first, last]
  );
  return result.rowCount > 0;
}

/** Load the guard-relevant row by id, or null. */
async function findUserById(userId) {
  const result = await cybercoreQuery(
    `SELECT ${USER_COLUMNS} FROM cybercore_user WHERE user_id = $1`,
    [userId]
  );
  return result.rows[0] || null;
}

// ============================================================================
// CREATE
// ============================================================================

/**
 * Create ONE local account.
 *
 * Idempotent by email: if an account already exists it is returned untouched as
 * `{ created: false }`. That is what makes a roster re-import safe — the second
 * run enrolls without disturbing anyone's password.
 *
 * @param {object}   spec
 * @param {string}   spec.email
 * @param {string}  [spec.firstName]
 * @param {string}  [spec.lastName]
 * @param {string}  [spec.username]              explicit, else derived from email
 * @param {string}  [spec.organization='Independent']
 * @param {string}  [spec.role='student']
 * @param {string}  [spec.password]              omit to generate one
 * @param {boolean} [spec.mustChangePassword]    defaults false for self_register, else true
 * @param {boolean} [spec.emailVerified=false]
 * @param {number}  [spec.tempPasswordTtlHours]  bounds a handed-out credential
 * @param {{by?: string, via: string, ref?: string}} spec.provenance
 * @param {Set}     [spec.takenUsernames]        batch de-dupe
 * @returns {Promise<{created: boolean, user: object, password: ?string, username: string}>}
 *   `password` is non-null ONLY when this call generated it. A caller-supplied
 *   password is never echoed back — the caller already has it. It is returned to
 *   the caller alone and never persisted in plaintext anywhere.
 */
async function provisionAccount(spec = {}) {
  const email = normalizeEmail(spec.email);
  if (!email || !isEmailShaped(email)) {
    throw httpError(400, 'valid email is required');
  }

  const provenance = spec.provenance || {};
  if (!PROVISIONED_VIA.includes(provenance.via)) {
    throw httpError(400, `invalid provenance "${provenance.via}"`);
  }

  const role = String(spec.role || 'student').toLowerCase();
  if (!VALID_ROLES.includes(role)) throw httpError(400, `invalid role "${role}"`);

  const existing = await findUserByEmail(email);
  if (existing) {
    return { created: false, user: existing, password: null, username: existing.username };
  }

  // A self-registrant chose their own password; nobody else has seen it, so
  // there is nothing to force a change of. Every other path hands a credential
  // to someone, so it must be rotated on first use.
  const mustChange = spec.mustChangePassword !== undefined
    ? !!spec.mustChangePassword
    : provenance.via !== 'self_register';

  const suppliedPassword = spec.password ? String(spec.password) : null;
  if (suppliedPassword) assertPasswordPolicy(suppliedPassword);
  const password = suppliedPassword || generatePassword();
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

  const expiresAt = spec.tempPasswordTtlHours
    ? new Date(Date.now() + spec.tempPasswordTtlHours * 3600 * 1000)
    : null;

  const taken = spec.takenUsernames instanceof Set ? spec.takenUsernames : new Set();
  let username = spec.username
    ? String(spec.username).trim().toLowerCase()
    : await allocateUsername(email, { taken });

  // Two callers can pass the same-shaped roster concurrently, so uniqueness is
  // ultimately settled by the database, not by the check above. Retry on a
  // username collision; treat an email collision as "someone else just created
  // it", which is the same answer as the idempotent path above.
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const result = await cybercoreQuery(
        `INSERT INTO cybercore_user
           (username, email, first_name, last_name, organization, role,
            password_hash, password_alg, status, active, email_verified,
            must_change_password, temp_password_expires_at,
            provisioned_by, provisioned_via, provisioned_ref,
            created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'bcrypt', 'active', TRUE, $8,
                 $9, $10, $11, $12, $13, NOW(), NOW())
         RETURNING ${USER_COLUMNS}`,
        [
          username, email,
          spec.firstName ? String(spec.firstName).trim() : null,
          spec.lastName ? String(spec.lastName).trim() : null,
          (spec.organization && String(spec.organization).trim()) || 'Independent',
          role, passwordHash, !!spec.emailVerified,
          mustChange, expiresAt,
          provenance.by || null, provenance.via, provenance.ref ? String(provenance.ref) : null,
        ]
      );

      taken.add(username);
      auditProvision(provenance, 'user.created', {
        user: result.rows[0],
        metadata: {
          via: provenance.via, ref: provenance.ref || null,
          role, username, must_change_password: mustChange,
          password_supplied: !!suppliedPassword,
        },
      });
      return {
        created: true,
        user: result.rows[0],
        password: suppliedPassword ? null : password,
        username,
      };
    } catch (err) {
      if (err.code !== PG_UNIQUE_VIOLATION) throw err;

      const constraint = String(err.constraint || '');
      if (constraint.includes('email')) {
        const raced = await findUserByEmail(email);
        if (raced) {
          return { created: false, user: raced, password: null, username: raced.username };
        }
        throw err;
      }

      // Username collision — take the next free suffix and try again.
      taken.add(username);
      username = await allocateUsername(email, { taken, base: deriveUsername(email) });
    }
  }

  throw httpError(409, `could not allocate a unique username for ${email}`);
}

/**
 * Create an account, or ROTATE the password of the one that already exists.
 *
 * Different from provisionAccount, which deliberately leaves an existing
 * account untouched. This is for the redeployable-lab-cohort case: running the
 * same deploy twice should hand the instructor a credential sheet that actually
 * works, while keeping each student's user_id so their prior workspaces and
 * Guacamole permissions stay associated.
 *
 * Using plain provisionAccount there would be a silent, nasty failure — the
 * instructor gets a fresh sheet of passwords, none of which log anyone in.
 *
 * @returns {Promise<{created: boolean, rotated: boolean, user: object, password: string, username: string}>}
 */
async function provisionOrRotateAccount(spec = {}) {
  const outcome = await provisionAccount(spec);
  if (outcome.created) return { ...outcome, rotated: false };

  const { password } = await setPassword(outcome.user.user_id, {
    password: spec.password || null,
    // These credentials go onto a printed sheet; forcing a rotation at first
    // sign-in would strand the copy the instructor is holding.
    mustChange: spec.mustChangePassword === true,
    actorId: spec.provenance?.by,
  });

  // The old upsert refreshed organization on conflict, so a redeploy under a
  // new group name re-labels the account. Preserved.
  let user = outcome.user;
  if (spec.organization) {
    const updated = await cybercoreQuery(
      `UPDATE cybercore_user SET organization = $1, updated_at = NOW()
        WHERE user_id = $2 RETURNING ${USER_COLUMNS}`,
      [String(spec.organization).trim(), outcome.user.user_id]
    );
    if (updated.rows[0]) user = updated.rows[0];
  }

  return { created: false, rotated: true, user, password, username: user.username };
}

/**
 * Batch wrapper with per-row isolation: a bad row lands in `failed` and the run
 * continues. Deliberately shaped like the contract of POST /api/admin/users/batch
 * so that route can be re-pointed here without changing its response.
 *
 * @param {Array<object>} rows    each merged over `defaults`
 * @param {object}        defaults
 * @returns {Promise<{created: Array, existing: Array, failed: Array}>}
 */
async function provisionAccounts(rows, defaults = {}) {
  const created = [];
  const existing = [];
  const failed = [];

  // Preload every username so allocateUsername doesn't issue a query per row,
  // and so names handed out earlier in THIS batch are also avoided.
  const preload = await cybercoreQuery('SELECT lower(username) AS u FROM cybercore_user');
  const taken = new Set(preload.rows.map(r => r.u));

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i] || {};
    const line = row.line || (i + 1);
    try {
      const outcome = await provisionAccount({
        ...defaults,
        ...row,
        provenance: row.provenance || defaults.provenance,
        takenUsernames: taken,
      });
      (outcome.created ? created : existing).push({ line, ...outcome });
    } catch (err) {
      failed.push({ line, email: row.email || '(blank)', error: err.message });
    }
  }

  return { created, existing, failed };
}

// ============================================================================
// PASSWORDS
// ============================================================================

function assertPasswordPolicy(password) {
  if (typeof password !== 'string' || password.length < PASSWORD_MIN_LEN) {
    throw httpError(400, `Password must be at least ${PASSWORD_MIN_LEN} characters`);
  }
  if (!PASSWORD_COMPLEXITY_RE.test(password)) {
    throw httpError(400, 'Password must contain uppercase, lowercase, and number');
  }
}

/**
 * Set a new password on an existing LOCAL account.
 *
 * KNOWN LIMITATION, inherited and worth restating at every call site: sessions
 * are stateless JWTs and middleware/auth.js never re-reads the row, so this does
 * NOT end sessions the user — or an attacker — already holds. Those stay valid
 * until the token expires (JWT_EXPIRES_IN, default 7 days).
 *
 * @returns {Promise<{password: string, expires_at: ?Date}>} plaintext returned once
 */
async function setPassword(userId, opts = {}) {
  const user = await findUserById(userId);
  if (!user) throw httpError(404, 'User not found');

  // A federated account authenticates at the identity provider; a local hash
  // would either do nothing or quietly become a second way in that bypasses
  // SSO. Neither is what "reset password" means.
  if (user.auth_provider && user.auth_provider !== 'local') {
    throw httpError(409, `${user.email} signs in through ${user.auth_provider} — reset their password there instead.`);
  }

  const supplied = opts.password ? String(opts.password) : null;
  if (supplied) assertPasswordPolicy(supplied);
  const password = supplied || generatePassword();
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

  const mustChange = opts.mustChange !== undefined ? !!opts.mustChange : true;
  const expiresAt = opts.ttlHours
    ? new Date(Date.now() + opts.ttlHours * 3600 * 1000)
    : null;

  await cybercoreQuery(
    `UPDATE cybercore_user
        SET password_hash = $1, password_alg = 'bcrypt',
            must_change_password = $2, temp_password_expires_at = $3,
            password_changed_at = NOW(), updated_at = NOW()
      WHERE user_id = $4`,
    [passwordHash, mustChange, expiresAt, userId]
  );

  auditProvision({ by: opts.actorId, via: 'setPassword', ctx: opts.ctx }, 'user.password_set', {
    user: { user_id: userId, email: user.email },
    metadata: { must_change: mustChange, ttl_hours: opts.ttlHours || null, self: opts.actorId === userId },
  });

  return { password, expires_at: expiresAt };
}

/**
 * Record that a user has set their own password: clears the forced-change gate
 * and stamps activation. Used by both the activation link and the forced-change
 * step, which is why it does not live inline in either.
 */
async function completePasswordChange(userId, newPassword) {
  assertPasswordPolicy(newPassword);
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_COST);
  const result = await cybercoreQuery(
    `UPDATE cybercore_user
        SET password_hash = $1, password_alg = 'bcrypt',
            must_change_password = FALSE,
            temp_password_expires_at = NULL,
            password_changed_at = NOW(),
            activated_at = COALESCE(activated_at, NOW()),
            email_verified = TRUE,
            last_auth_at = NOW(),
            updated_at = NOW()
      WHERE user_id = $2
      RETURNING ${USER_COLUMNS}`,
    [passwordHash, userId]
  );
  if (result.rows.length === 0) throw httpError(404, 'User not found');
  return result.rows[0];
}

// ============================================================================
// AUTHORIZATION
// ============================================================================

/**
 * Guard for a NON-ADMIN caller acting on another account's credential inside a
 * course — regenerating a password, resending an activation link.
 *
 * Course membership alone is NOT authority for this. An instructor can enroll
 * any address in their own course, so "manages the course AND target is
 * enrolled" is a two-step path from instructor to admin. That threat is already
 * documented at guac-credentials.js:333-343; this function composes that rule
 * with a provenance requirement rather than inventing a second one.
 *
 * Enrollment itself is deliberately NOT restricted — staff sit in on courses,
 * and an enrolled admin is harmless. What must be impossible is an instructor
 * exercising account-level power over anyone who is not their own student.
 *
 * A refusal here is an instructor reaching for account-level power over
 * somebody who is not their student — the clearest privilege-escalation signal
 * the platform has — so it is audited as status 'denied'. `opts.audit: false`
 * suppresses that for canManageAccount(), which calls this speculatively on
 * every row of a roster render and would otherwise fill the log with denials
 * nobody attempted.
 *
 * @throws {Error} with .status 403 or 409
 */
function assertCourseProvisionedStudent(targetUser, caller, courseId, opts = {}) {
  try {
    checkCourseProvisionedStudent(targetUser, caller, courseId);
  } catch (err) {
    if (opts.audit !== false) {
      audit.log({
        actor: { userId: caller?.userId || null, email: caller?.email || null, role: caller?.role || null },
        action: 'user.credential_action_denied',
        status: 'denied',
        reason: 'not_course_provisioned',
        target:     { type: 'user', id: targetUser?.user_id, label: targetUser?.email },
        targetUser: { id: targetUser?.user_id, label: targetUser?.email },
        metadata: {
          course_ref: courseId,
          actor_role: caller?.role || null,
          target_provisioned_via: targetUser?.provisioned_via || null,
          message: err.message,
        },
        // Defaults to 'cle' for the original caller; CIAB passes 'ciab' so a
        // denial is not filed against the wrong subsystem.
        source: opts.source || 'cle',
      });
    }
    throw err;
  }
}

function checkCourseProvisionedStudent(targetUser, caller, courseId) {
  if (!targetUser) throw httpError(404, 'User not found');

  // Admins already have POST /api/admin/users/:id/password; no reason to hold
  // them to a course's provenance.
  if (caller?.role === 'admin') return;

  // Role gate — the platform's existing rule, reused verbatim.
  guacCreds.assertDisclosable(targetUser, caller);

  if (targetUser.auth_provider && targetUser.auth_provider !== 'local') {
    throw httpError(409, `${targetUser.email} signs in through ${targetUser.auth_provider} — an administrator must reset it there.`);
  }

  // MFA-enabled is the strongest available signal of a real, privileged human
  // rather than a disposable lab identity.
  if (targetUser.mfa_enabled) {
    throw httpError(403, 'This account has multi-factor authentication enabled. An administrator must reset it.');
  }

  // The load-bearing check. An account this course minted is one whose
  // credential the instructor already controlled, so regenerating it grants
  // nothing new. An account that existed beforehand belongs to somebody who
  // set their own password.
  if (!INSTRUCTOR_MANAGEABLE_VIA.includes(targetUser.provisioned_via)) {
    throw httpError(403, 'This account was not created by this course, so its password cannot be changed here. The account holder can reset it themselves, or an administrator can.');
  }
  if (String(targetUser.provisioned_ref || '') !== String(courseId)) {
    throw httpError(403, 'This account was created by a different course. Only the course that created it can change its password.');
  }
}

/**
 * Non-throwing form for list rendering: may this caller act on this account?
 * The roster read uses it to decide whether to show the action buttons at all,
 * so the UI never offers something the API will refuse.
 */
function canManageAccount(targetUser, caller, courseId) {
  try {
    // audit: false — this runs per row on every roster render; a speculative
    // "would this be allowed" check is not an attempted action.
    assertCourseProvisionedStudent(targetUser, caller, courseId, { audit: false });
    return true;
  } catch {
    return false;
  }
}

/** True when the target outranks a student — used to badge staff on a roster. */
function isElevatedAccount(targetUser) {
  const role = String(targetUser?.role || 'student').toLowerCase();
  return role !== 'student' && role !== 'user';
}

// ============================================================================
// BOOT DDL
// ============================================================================

/**
 * Ensure the provisioning columns and lookup indexes exist.
 *
 * config/postgres/001_init_db.sql only runs on a fresh Postgres volume, so
 * existing deployments would never see these. Mirrors ensureMfaColumns() in
 * server.js — same pattern, same reason. Keep in sync with
 * front-end/migrations/027_user_provisioning_and_password_policy.sql.
 */
async function ensureProvisioningColumns() {
  try {
    await cybercoreQuery(`
      ALTER TABLE cybercore_user
        ADD COLUMN IF NOT EXISTS must_change_password     BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS password_changed_at      TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS temp_password_expires_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS activated_at             TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS provisioned_by           UUID,
        ADD COLUMN IF NOT EXISTS provisioned_via          TEXT,
        ADD COLUMN IF NOT EXISTS provisioned_ref          TEXT
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_cybercore_user_provisioned
        ON cybercore_user (provisioned_via, provisioned_ref)
        WHERE provisioned_via IS NOT NULL
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_cybercore_user_username_lower
        ON cybercore_user (lower(username))
    `);
    console.log('✅ Provisioning columns ensured on cybercore_user');
  } catch (err) {
    console.warn('⚠️  Could not ensure provisioning columns:', err.message);
  }

  // Separate try/catch: this one fails loudly and for a specific, actionable
  // reason. CREATE UNIQUE INDEX hard-fails when duplicates already exist, and
  // there is no safe automatic merge — both rows may own lanes, Guacamole
  // accounts and enrollments keyed on their distinct user_ids.
  try {
    await cybercoreQuery(`
      CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_user_email_lower
        ON cybercore_user (lower(email))
    `);
  } catch (err) {
    try {
      const dupes = await cybercoreQuery(`
        SELECT lower(email) AS email_lc, count(*)::int AS n, array_agg(user_id) AS user_ids
          FROM cybercore_user GROUP BY 1 HAVING count(*) > 1
      `);
      console.error(
        '❌ Cannot enforce unique email: this database holds duplicate addresses. ' +
        'Until they are merged by hand, two accounts can share an address and login ' +
        'will pick whichever the index returns first.\n' +
        dupes.rows.map(r => `   ${r.email_lc} → ${r.user_ids.join(', ')}`).join('\n')
      );
    } catch {
      console.warn('⚠️  Could not ensure unique email index:', err.message);
    }
  }
}

module.exports = {
  // constants
  BCRYPT_COST, PASSWORD_MIN_LEN, PASSWORD_COMPLEXITY_RE,
  VALID_ROLES, PROVISIONED_VIA, INSTRUCTOR_MANAGEABLE_VIA,
  // email (re-exported so callers need one require)
  normalizeEmail, isEmailShaped,
  // usernames
  deriveUsername, allocateUsername,
  // lookup
  findUserByEmail, findUsersByEmails, findUserById,
  // repair
  backfillMissingName,
  // create
  provisionAccount, provisionOrRotateAccount, provisionAccounts,
  // passwords
  assertPasswordPolicy, setPassword, completePasswordChange,
  // authorization
  assertCourseProvisionedStudent, canManageAccount, isElevatedAccount,
  // boot
  ensureProvisioningColumns,
};
