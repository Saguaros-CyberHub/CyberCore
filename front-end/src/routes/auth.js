/**
 * ============================================================================
 * AUTHENTICATION ROUTES
 * ============================================================================
 * Uses cybercore_user as the single source of truth for all users.
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const validator = require('validator');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { normalizeEmail, legacyNormalizeEmail } = require('../utils/email-normalize');
const { authenticate, authenticateStage, authenticateEnrollOrSession } = require('../middleware/auth');
const { ensureGuacAccount } = require('../utils/guacamole');
const mfa = require('../utils/mfa');
const accountProvisioning = require('../utils/account-provisioning');
const activation = require('../utils/activation');
const audit = require('../utils/audit');

const GUAC_ENABLED = process.env.GUAC_ENABLED === 'true';

/**
 * Audit an authentication event.
 *
 * Auth is the one place with no req.user to read an actor from — a failed
 * login knows only the string somebody typed — so every call here uses the
 * explicit-actor form. The typed identifier is recorded because "who is being
 * guessed at" is the whole value of a failed-login trail; the password never
 * is, in any form.
 */
function auditAuth(req, action, { user = null, email = null, status = 'success', reason = null, metadata = {} } = {}) {
  return audit.log({
    req,
    actor: {
      userId: user?.user_id ?? null,
      email:  user?.email ?? email ?? null,
      role:   user?.role ?? null,
      type:   user?.user_id ? 'user' : 'anonymous',
    },
    action,
    status,
    reason,
    target: user ? { type: 'user', id: user.user_id, label: user.email } : null,
    metadata,
    source: 'core',
  });
}

// ============================================================================
// VALIDATION RULES
// ============================================================================

// Sanitize with our own normalizer rather than express-validator's
// .normalizeEmail(). The built-in strips dots and +subaddresses for Gmail and
// friends, which rewrites the address into something the user never typed and
// no longer matches what a roster import or an admin stored. See
// utils/email-normalize.js.
const emailSanitizer = (value) => normalizeEmail(value) ?? value;

const registerValidation = [
  body('email')
    .isEmail()
    .customSanitizer(emailSanitizer)
    .withMessage('Please enter a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be 2-50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be 2-50 characters'),
  body('organization')
    .optional()
    .trim()
    .isLength({ max: 255 })
];

// The login lookup has always matched `email OR username`, but this chain used
// to require isEmail(), so a bare username was rejected before it ever reached
// the query — the username branch only worked because self-registration stores
// username = email. Cohort accounts break that assumption: they are handed out
// as `cybr-480-7w1-1-student1`, and telling a student to type
// `...@cohort.invalid` instead would be absurd. Accept either shape.
//
// Username shape mirrors USERNAME_RE at admin/settings.js:417.
const USERNAME_RE = /^[a-z0-9._-]+$/i;

const loginValidation = [
  body('email')
    .customSanitizer(emailSanitizer)
    .custom((value) => {
      const v = String(value || '').trim();
      if (!v) throw new Error('Email or username is required');
      if (v.includes('@')) {
        if (!validator.isEmail(v)) throw new Error('Please enter a valid email');
        return true;
      }
      if (!USERNAME_RE.test(v)) throw new Error('Please enter a valid email or username');
      return true;
    }),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateTokens(user) {
  const accessToken = jwt.sign(
    {
      sub: user.user_id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );

  return { accessToken };
}

// Short-lived token carrying a `stage` claim ('mfa' | 'enroll' | 'pwchange').
// It is NOT a session — the stage middleware refuses it on normal protected
// routes.
//
// 'pwchange' gets longer than the 5 minutes an authenticator code needs:
// choosing a password, having a manager generate one, and confirming it is a
// slower human task, and expiring mid-flow would drop the user back to a login
// screen with a temporary password they may have already discarded.
function generateStageToken(user, stage, expiresIn = '5m') {
  return jwt.sign(
    { sub: user.user_id, email: user.email, role: user.role, stage },
    process.env.JWT_SECRET,
    { expiresIn }
  );
}

const PWCHANGE_STAGE_TTL = '15m';

const TEMP_PASSWORD_EXPIRED_MESSAGE =
  'The temporary password for this account has expired. Ask your instructor to send you a new invitation.';

/**
 * Decide whether an authenticated user still owes a password change.
 *
 * Returns null when they may proceed to a session; `{ expired: true }` when the
 * handed-out credential is past its window; otherwise `{ token }` carrying a
 * pwchange-stage token.
 *
 * Callers shape their own response because the three session-issuing paths need
 * different envelopes — /login can return a bare gate, but /mfa/verify has just
 * generated recovery codes that must be shown exactly once and cannot be
 * dropped on the floor.
 */
function passwordChangeGate(user) {
  if (!user.must_change_password) return null;

  const expires = user.temp_password_expires_at;
  if (expires && new Date(expires).getTime() < Date.now()) {
    return { expired: true };
  }
  return { token: generateStageToken(user, 'pwchange', PWCHANGE_STAGE_TTL) };
}

/** The user shape every session-issuing route returns. */
function publicUser(user) {
  return {
    id: user.user_id,
    email: user.email,
    firstName: user.first_name,
    lastName: user.last_name,
    role: user.role,
    organization: user.organization,
  };
}

/**
 * The single choke point for issuing a session.
 *
 * The assertion is the point. A future login path that forgets the
 * password-change gate would otherwise hand out a full session to an account
 * still holding a credential somebody else chose — a silent hole opened by
 * omission rather than by a visible mistake. Failing loudly here means the gate
 * cannot be bypassed by simply not thinking about it.
 */
function issueSession(res, user) {
  if (user.must_change_password) {
    throw new Error(
      `issueSession() called for ${user.email} while must_change_password is still set — ` +
      'call passwordChangeGate() first and return its stage token instead.'
    );
  }
  const { accessToken } = generateTokens(user);
  setSessionCookie(res, accessToken);
  return { token: accessToken, user: publicUser(user) };
}

// Columns every session-issuing path needs. Kept in one place so a new login
// route cannot quietly omit one of the gates that reads them.
const LOGIN_USER_COLUMNS = `
  user_id, email, username, password_hash, first_name, last_name, role,
  organization, status, active, mfa_enabled,
  must_change_password, temp_password_expires_at
`;

/**
 * Find the account for a login attempt.
 *
 * Matching is case-insensitive on BOTH columns: accounts are minted by several
 * paths that disagreed about casing, so an exact match silently locked out
 * anyone whose roster row happened to be capitalized. lower(email) and
 * lower(username) are both indexed (see migrations/027).
 *
 * The second lookup is a compatibility shim, not a fallback for typos. Accounts
 * registered before Phase 0 were stored under express-validator's aggressive
 * normalization — `first.last@gmail.com` became `firstlast@gmail.com` — and
 * those rows still hold the stripped form. Trying it once, only after the
 * straightforward lookup found nothing, preserves exactly the behaviour those
 * users have always had without letting the mangling affect anyone else.
 *
 * @param {string} identifier already trimmed and lowercased by the sanitizer
 */
async function findUserForLogin(identifier) {
  const sql = `SELECT ${LOGIN_USER_COLUMNS}
                 FROM cybercore_user
                WHERE lower(email) = $1 OR lower(username) = $1`;

  const direct = await cybercoreQuery(sql, [identifier]);
  if (direct.rows.length > 0) return direct.rows[0];

  const legacy = legacyNormalizeEmail(identifier);
  if (legacy && legacy !== identifier) {
    const fallback = await cybercoreQuery(sql, [legacy]);
    if (fallback.rows.length > 0) return fallback.rows[0];
  }

  return null;
}

// Set the 7-day session cookie. Called only from issueSession() — every route
// that logs somebody in goes through there, so the options live in one place.
function setSessionCookie(res, accessToken) {
  res.cookie('token', accessToken, {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

// Enforcement scope from cybercore_site_settings: 'privileged' (admins +
// instructors, the default) or 'all'. Tolerates a missing settings table.
async function getMfaScope() {
  try {
    const r = await cybercoreQuery(
      `SELECT value FROM cybercore_site_settings WHERE key = 'mfa_required_scope'`
    );
    const v = r.rows[0]?.value;
    return v === 'all' ? 'all' : 'privileged';
  } catch {
    return 'privileged';
  }
}

function isMfaRequired(role, scope) {
  return scope === 'all' || role === 'admin' || role === 'instructor';
}

// ============================================================================
// ROUTES
// ============================================================================

/**
 * POST /api/auth/register
 */
router.post('/register', registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { email, password, firstName, lastName, organization } = req.body;

    // Case-insensitive, because ux_cybercore_user_email_lower is what actually
    // enforces uniqueness. An exact-match check here would let `Bob@x.com`
    // through when `bob@x.com` exists, and the INSERT would then fail on the
    // index — turning a clean 409 into a 500.
    const existingUser = await cybercoreQuery(
      'SELECT user_id FROM cybercore_user WHERE lower(email) = $1 OR lower(username) = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // Same shared minting path as every other account: one bcrypt cost, one
    // username derivation, and the address stored lowercased so the login
    // lookup can find it. username has always equalled the address here.
    const outcome = await accountProvisioning.provisionAccount({
      email,
      username: email,
      firstName,
      lastName,
      organization,
      role: 'student',
      password,
      // A self-registrant chose this password themselves, so there is nothing
      // for anyone else to know and nothing to force a rotation of.
      mustChangePassword: false,
      emailVerified: false,
      provenance: { by: null, via: 'self_register', ref: null },
    });

    const user = outcome.user;

    // Create a corresponding Guacamole account for the new user so they can
    // receive connection permissions without waiting for a first workstation deploy.
    if (GUAC_ENABLED) {
      setImmediate(async () => {
        try {
          const pw = await ensureGuacAccount(user.email);
          if (pw && process.env.GUAC_ENCRYPT_KEY) {
            await cybercoreQuery(
              'UPDATE cybercore_user SET guac_password = pgp_sym_encrypt($1, $2) WHERE user_id = $3',
              [pw, process.env.GUAC_ENCRYPT_KEY, user.user_id]
            );
          }
        } catch (err) {
          console.warn('[auth] Guac account creation failed for', user.email, ':', err.message);
        }
      });
    }

    // Same choke point as every other sign-in path. A self-registrant chose
    // their own password, so the gate never fires here — but routing through
    // issueSession keeps the cookie options in one place rather than a
    // hand-rolled copy that can drift.
    const session = issueSession(res, user);
    auditAuth(req, 'auth.register', { user, metadata: { via: 'self_register' } });

    res.status(201).json({
      message: 'Registration successful',
      user: session.user,
      token: session.token
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

/**
 * POST /api/auth/login
 */
router.post('/login', loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { email, password } = req.body;

    const user = await findUserForLogin(email);

    if (!user) {
      auditAuth(req, 'auth.login', { email, status: 'failure', reason: 'unknown_user' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if account is active
    if (!user.active || user.status !== 'active') {
      auditAuth(req, 'auth.login', { user, status: 'failure', reason: 'account_disabled' });
      return res.status(403).json({ error: 'Account is deactivated. Please contact support.' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      auditAuth(req, 'auth.login', { user, status: 'failure', reason: 'bad_password' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // ── Second factor gate ────────────────────────────────────────────────
    // Password is correct, but don't grant a session yet if MFA applies.
    if (user.mfa_enabled) {
      // User has TOTP — require the code. Step 2 lands at /auth/login/mfa.
      return res.json({ mfa_required: true, mfa_token: generateStageToken(user, 'mfa') });
    }

    const scope = await getMfaScope();
    if (isMfaRequired(user.role, scope)) {
      // Required but not enrolled — force enrollment before any session.
      return res.json({ enrollment_required: true, enroll_token: generateStageToken(user, 'enroll') });
    }
    // ──────────────────────────────────────────────────────────────────────

    // ── Forced password change ────────────────────────────────────────────
    // Deliberately AFTER both MFA gates. A password the account holder did not
    // choose is weak precisely because somebody else handed it over; letting
    // whoever holds it walk straight to "set a new password" without the second
    // factor would turn credential interception into full account takeover.
    // Prove the second factor first, then rotate the weak credential.
    const gate = passwordChangeGate(user);
    if (gate?.expired) {
      auditAuth(req, 'auth.login', { user, status: 'failure', reason: 'temp_password_expired' });
      return res.status(403).json({
        error: TEMP_PASSWORD_EXPIRED_MESSAGE,
        code: 'TEMP_PASSWORD_EXPIRED',
      });
    }
    if (gate) {
      return res.json({ password_change_required: true, password_change_token: gate.token });
    }
    // ──────────────────────────────────────────────────────────────────────

    // Update last auth timestamp
    await cybercoreQuery(
      'UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1',
      [user.user_id]
    );

    const session = issueSession(res, user);
    auditAuth(req, 'auth.login', { user, metadata: { mfa: false } });

    res.json({
      message: 'Login successful',
      user: session.user,
      token: session.token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

/**
 * POST /api/auth/login/mfa
 * Step 2 of login: verify a TOTP (or recovery) code using the short-lived
 * mfa-stage token from step 1, then issue the real session.
 */
router.post('/login/mfa', authenticateStage('mfa'), async (req, res) => {
  try {
    if (!mfa.mfaKey()) return res.status(500).json({ error: 'MFA encryption key not configured' });

    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Authentication code is required' });

    const userId = req.user.userId;
    const result = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role, organization, status, active, mfa_enabled,
              must_change_password, temp_password_expires_at,
              CASE WHEN mfa_secret IS NOT NULL THEN pgp_sym_decrypt(mfa_secret, $2)::text END AS mfa_secret,
              mfa_recovery_codes
       FROM cybercore_user WHERE user_id = $1`,
      [userId, mfa.mfaKey()]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid session' });

    const user = result.rows[0];
    if (!user.active || user.status !== 'active') {
      return res.status(403).json({ error: 'Account is deactivated. Please contact support.' });
    }
    if (!user.mfa_enabled || !user.mfa_secret) {
      return res.status(400).json({ error: 'MFA is not enabled for this account' });
    }

    let ok = mfa.verifyTotp(code, user.mfa_secret);
    let usedRecovery = false;
    if (!ok) {
      const idx = mfa.matchRecoveryCode(code, user.mfa_recovery_codes);
      if (idx >= 0) {
        ok = true;
        usedRecovery = true;
        const codes = user.mfa_recovery_codes;
        codes[idx].used = true;
        await cybercoreQuery(
          'UPDATE cybercore_user SET mfa_recovery_codes = $1 WHERE user_id = $2',
          [JSON.stringify(codes), userId]
        );
      }
    }
    if (!ok) {
      auditAuth(req, 'auth.mfa_failed', { user, status: 'failure', reason: 'bad_totp' });
      return res.status(401).json({ error: 'Invalid authentication code' });
    }

    // The second factor is now proven, so the forced-password-change gate
    // applies here exactly as it does at the end of /login. Without this check
    // an MFA-enabled account would complete step 2 and receive a full session,
    // silently skipping a rotation the /login path would have demanded.
    const recoveryInfo = usedRecovery ? {
      recovery_code_used: true,
      recovery_codes_remaining: user.mfa_recovery_codes.filter(c => !c.used).length
    } : {};

    const gate = passwordChangeGate(user);
    if (gate?.expired) {
      return res.status(403).json({
        error: TEMP_PASSWORD_EXPIRED_MESSAGE,
        code: 'TEMP_PASSWORD_EXPIRED',
        ...recoveryInfo,
      });
    }
    if (gate) {
      return res.json({
        password_change_required: true,
        password_change_token: gate.token,
        ...recoveryInfo,
      });
    }

    await cybercoreQuery('UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1', [userId]);

    const session = issueSession(res, user);
    auditAuth(req, 'auth.login', { user, metadata: { mfa: true, ...recoveryInfo } });

    res.json({
      message: 'Login successful',
      user: session.user,
      token: session.token,
      ...recoveryInfo
    });
  } catch (error) {
    console.error('MFA login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

/**
 * POST /api/auth/mfa/setup
 * Begin TOTP enrollment. Accepts a full session (self-enroll) or an enroll-stage
 * token (forced enrollment). Generates + stores an encrypted secret (not yet
 * enabled) and returns the otpauth URI + QR for the authenticator app.
 */
router.post('/mfa/setup', authenticateEnrollOrSession, async (req, res) => {
  try {
    if (!mfa.mfaKey()) return res.status(500).json({ error: 'MFA encryption key not configured' });

    const userId = req.user.userId;
    const r = await cybercoreQuery(
      `SELECT email, mfa_enabled,
              CASE WHEN mfa_secret IS NOT NULL THEN pgp_sym_decrypt(mfa_secret, $2)::text END AS mfa_secret
       FROM cybercore_user WHERE user_id = $1`,
      [userId, mfa.mfaKey()]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (r.rows[0].mfa_enabled) {
      return res.status(409).json({ error: 'MFA is already enabled. Disable or reset it first.' });
    }

    // Reuse the pending secret if enrollment was already started. Regenerating
    // it on every call silently invalidates whatever the user already scanned,
    // so a retried login (which re-triggers forced enrollment) never verifies.
    let secret = r.rows[0].mfa_secret;
    if (!secret) {
      secret = mfa.generateSecret();
      await cybercoreQuery(
        'UPDATE cybercore_user SET mfa_secret = pgp_sym_encrypt($1, $2) WHERE user_id = $3',
        [secret, mfa.mfaKey(), userId]
      );
    }

    const otpauthUri = mfa.keyUri(r.rows[0].email, secret);
    const qr = await mfa.qrDataUrl(otpauthUri);
    res.json({ otpauth_url: otpauthUri, qr_data_url: qr, secret });
  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({ error: 'Could not start MFA setup' });
  }
});

/**
 * POST /api/auth/mfa/verify
 * Finish enrollment: verify a code against the pending secret, flip mfa_enabled
 * on, generate recovery codes (returned once). On a forced (enroll-stage)
 * enrollment, also issues the real session so the user lands logged in.
 */
router.post('/mfa/verify', authenticateEnrollOrSession, async (req, res) => {
  try {
    if (!mfa.mfaKey()) return res.status(500).json({ error: 'MFA encryption key not configured' });

    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Authentication code is required' });

    const userId = req.user.userId;
    const r = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role, organization, mfa_enabled,
              must_change_password, temp_password_expires_at,
              CASE WHEN mfa_secret IS NOT NULL THEN pgp_sym_decrypt(mfa_secret, $2)::text END AS mfa_secret
       FROM cybercore_user WHERE user_id = $1`,
      [userId, mfa.mfaKey()]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = r.rows[0];
    if (user.mfa_enabled) return res.status(409).json({ error: 'MFA is already enabled' });
    if (!user.mfa_secret) return res.status(400).json({ error: 'Start MFA setup first' });
    if (!mfa.verifyTotp(code, user.mfa_secret)) {
      return res.status(401).json({ error: 'Invalid authentication code' });
    }

    const { plain, stored } = mfa.makeRecoveryCodes();
    await cybercoreQuery(
      'UPDATE cybercore_user SET mfa_enabled = TRUE, mfa_recovery_codes = $1, mfa_enrolled_at = NOW() WHERE user_id = $2',
      [JSON.stringify(stored), userId]
    );

    // Forced enrollment came in without a session — log them in now, unless the
    // account still owes a password change. Note this branch responds 200 even
    // when the gate fires: MFA really was enabled and `plain` holds recovery
    // codes that are shown exactly once and are unrecoverable afterwards.
    // Returning an error status here would enable MFA and destroy the codes in
    // the same breath, locking the user out of the account they just secured.
    let extra = {};
    if (req.mfaStage === 'enroll') {
      const gate = passwordChangeGate(user);
      if (gate?.expired) {
        extra = {
          password_change_required: true,
          password_change_expired: true,
          error: TEMP_PASSWORD_EXPIRED_MESSAGE,
          code: 'TEMP_PASSWORD_EXPIRED',
        };
      } else if (gate) {
        extra = { password_change_required: true, password_change_token: gate.token };
      } else {
        await cybercoreQuery('UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1', [userId]);
        const session = issueSession(res, user);
        extra = { token: session.token, user: session.user };
      }
    }

    res.json({ message: 'MFA enabled', recovery_codes: plain, ...extra });
  } catch (error) {
    console.error('MFA verify error:', error);
    res.status(500).json({ error: 'Could not enable MFA' });
  }
});

/**
 * POST /api/auth/mfa/disable
 * Turn off MFA for the logged-in user. Requires a current TOTP/recovery code,
 * and is refused when MFA is required for the user's role.
 */
router.post('/mfa/disable', authenticate, async (req, res) => {
  try {
    if (!mfa.mfaKey()) return res.status(500).json({ error: 'MFA encryption key not configured' });

    const { code } = req.body;
    const userId = req.user.userId;
    const r = await cybercoreQuery(
      `SELECT role, mfa_enabled,
              CASE WHEN mfa_secret IS NOT NULL THEN pgp_sym_decrypt(mfa_secret, $2)::text END AS mfa_secret,
              mfa_recovery_codes
       FROM cybercore_user WHERE user_id = $1`,
      [userId, mfa.mfaKey()]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = r.rows[0];
    if (!user.mfa_enabled) return res.status(400).json({ error: 'MFA is not enabled' });

    const scope = await getMfaScope();
    if (isMfaRequired(user.role, scope)) {
      return res.status(403).json({ error: 'MFA is required for your role and cannot be disabled.' });
    }

    let ok = mfa.verifyTotp(code, user.mfa_secret);
    if (!ok && mfa.matchRecoveryCode(code, user.mfa_recovery_codes) >= 0) ok = true;
    if (!ok) return res.status(401).json({ error: 'Invalid authentication code' });

    await cybercoreQuery(
      `UPDATE cybercore_user
          SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_recovery_codes = NULL, mfa_enrolled_at = NULL
        WHERE user_id = $1`,
      [userId]
    );
    auditAuth(req, 'auth.mfa_disabled', {
      user: { user_id: userId, email: req.user.email, role: req.user.role },
    });
    res.json({ message: 'MFA disabled' });
  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({ error: 'Could not disable MFA' });
  }
});

// ============================================================================
// SETTING A FIRST PASSWORD
// ----------------------------------------------------------------------------
// Two doors into the same room, for two different populations:
//
//   POST /password/initial  — the account holder signed in with a credential
//                             somebody handed them, and login refused to issue
//                             a session until they replace it. Authorized by a
//                             pwchange-stage token, so the password was already
//                             proven (and the second factor too, if any).
//
//   POST /activate          — the account holder has never signed in at all.
//                             Authorized by a single-use link from their email,
//                             which is what proves control of the address.
//
// Both end at completePasswordChange() and both issue a full session, so a
// student lands logged in rather than being bounced to a login form to retype
// the password they just chose.
// ============================================================================

const newPasswordValidation = [
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number')
];

/**
 * POST /api/auth/password/initial
 * Complete a forced password change. Bearer pwchange-stage token only.
 */
router.post('/password/initial', authenticateStage('pwchange'), newPasswordValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { newPassword } = req.body;
    const userId = req.user.userId;

    const result = await cybercoreQuery(
      `SELECT ${LOGIN_USER_COLUMNS}, auth_provider FROM cybercore_user WHERE user_id = $1`,
      [userId]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid session' });

    const user = result.rows[0];
    if (!user.active || user.status !== 'active') {
      return res.status(403).json({ error: 'Account is deactivated. Please contact support.' });
    }
    if (!user.must_change_password) {
      // Already done — most likely a double submit. Say so plainly rather than
      // silently setting a new password on an account that never asked for one.
      return res.status(409).json({ error: 'This account does not need to change its password. Please sign in normally.' });
    }

    // Without this, "you must change your password" is satisfied by setting the
    // same one again, and the rotation achieves nothing.
    if (await bcrypt.compare(newPassword, user.password_hash)) {
      return res.status(400).json({ error: 'Choose a password different from your temporary one.' });
    }

    const updated = await accountProvisioning.completePasswordChange(userId, newPassword);

    // Any invitation link still outstanding for this account is now moot, and
    // leaving it live would be a second way in that the user does not know about.
    await activation.revokeActivationTokens(userId, 'activate').catch(() => {});

    auditAuth(req, 'auth.password_initial_set', { user: updated });
    const session = issueSession(res, updated);
    auditAuth(req, 'auth.login', { user: updated, metadata: { via: 'password_initial' } });
    res.json({ message: 'Password set successfully', user: session.user, token: session.token });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('Initial password error:', error);
    res.status(500).json({ error: 'Could not set your password. Please try again.' });
  }
});

/**
 * POST /api/auth/activate
 * Redeem a single-use activation link and set a first password. Unauthenticated
 * by necessity — the token IS the authentication.
 */
router.post('/activate', newPasswordValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { token, newPassword } = req.body;

    // Consumed first, and atomically: a token that fails validation downstream
    // is still spent. That is the correct trade — replaying a link must be
    // impossible even if the request errors afterwards, and reissuing is a
    // single click for the instructor.
    const redeemed = await activation.consumeActivationToken(token);

    const result = await cybercoreQuery(
      `SELECT ${LOGIN_USER_COLUMNS} FROM cybercore_user WHERE user_id = $1`,
      [redeemed.userId]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'This link is no longer valid.' });

    const user = result.rows[0];
    if (!user.active || user.status !== 'active') {
      return res.status(403).json({ error: 'Account is deactivated. Please contact support.' });
    }

    const updated = await accountProvisioning.completePasswordChange(redeemed.userId, newPassword);

    // An activating account has, by construction, never enrolled in MFA. If
    // policy requires it for their role, send them through enrollment rather
    // than handing out a session that skips a mandatory control.
    const scope = await getMfaScope();
    if (!updated.mfa_enabled && isMfaRequired(updated.role, scope)) {
      return res.json({
        message: 'Password set successfully',
        enrollment_required: true,
        enroll_token: generateStageToken(updated, 'enroll'),
      });
    }

    await cybercoreQuery('UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1', [redeemed.userId]);

    auditAuth(req, 'auth.activated', { user: updated });
    const session = issueSession(res, updated);
    auditAuth(req, 'auth.login', { user: updated, metadata: { via: 'activation' } });
    res.json({ message: 'Password set successfully', user: session.user, token: session.token });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('Activation error:', error);
    res.status(500).json({ error: 'Could not activate your account. Please try again.' });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', authenticate, async (req, res) => {
  try {
    res.clearCookie('token');
    auditAuth(req, 'auth.logout', {
      user: { user_id: req.user.userId, email: req.user.email, role: req.user.role },
    });
    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name, role, organization, created_at, last_auth_at,
              mfa_enabled, must_change_password
       FROM cybercore_user WHERE user_id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    const mfaScope = await getMfaScope();

    res.json({
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: user.organization,
        createdAt: user.created_at,
        lastLogin: user.last_auth_at,
        mfaEnabled: user.mfa_enabled === true,
        mfaRequired: isMfaRequired(user.role, mfaScope),
        // Lets a page loaded with a session predating the flag redirect the
        // user to finish setting a password. The check is NOT in authenticate()
        // on purpose: putting it there would invalidate every live session the
        // moment this shipped, and the login gate already covers everyone who
        // actually has the flag set.
        mustChangePassword: user.must_change_password === true
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

/**
 * PUT /api/auth/profile
 */
router.put('/profile', authenticate, [
  body('firstName').optional().trim().isLength({ min: 2, max: 50 }),
  body('lastName').optional().trim().isLength({ min: 2, max: 50 }),
  body('organization').optional().trim().isLength({ max: 255 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { firstName, lastName, organization } = req.body;
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (firstName) {
      updates.push(`first_name = $${paramCount++}`);
      values.push(firstName);
    }
    if (lastName) {
      updates.push(`last_name = $${paramCount++}`);
      values.push(lastName);
    }
    if (organization !== undefined) {
      updates.push(`organization = $${paramCount++}`);
      values.push(organization || null);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(req.user.userId);

    const result = await cybercoreQuery(
      `UPDATE cybercore_user SET ${updates.join(', ')} WHERE user_id = $${paramCount}
       RETURNING user_id, email, first_name, last_name, role, organization`,
      values
    );

    const user = result.rows[0];

    res.json({
      message: 'Profile updated',
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: user.organization
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

/**
 * PUT /api/auth/password
 */
router.put('/password', authenticate, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must be at least 8 characters with uppercase, lowercase, and number')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { currentPassword, newPassword } = req.body;

    const result = await cybercoreQuery(
      'SELECT password_hash FROM cybercore_user WHERE user_id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isValid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Through the shared path, so this cannot drift from the admin reset or the
    // CLE regenerate — one bcrypt cost, one policy floor, one place that writes
    // a password_hash. mustChange stays false: the user chose this themselves,
    // so there is nothing to force a rotation of.
    await accountProvisioning.setPassword(req.user.userId, {
      password: newPassword,
      mustChange: false,
      actorId: req.user.userId,
    });

    auditAuth(req, 'auth.password_changed', {
      user: { user_id: req.user.userId, email: req.user.email, role: req.user.role },
    });
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

/**
 * GET /api/auth/verify
 */
router.get('/verify', authenticate, (req, res) => {
  res.json({
    valid: true,
    user: {
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role
    }
  });
});

module.exports = router;

// Exported for tests only. These carry the security properties that regress
// silently: the case-insensitive lookup with its compatibility fallback, the
// forced-password-change gate, and the single choke point for issuing a
// session. See test/auth-login-lookup.test.js and test/auth-password-gate.test.js.
module.exports.findUserForLogin = findUserForLogin;
module.exports.passwordChangeGate = passwordChangeGate;
module.exports.issueSession = issueSession;
module.exports.generateStageToken = generateStageToken;
