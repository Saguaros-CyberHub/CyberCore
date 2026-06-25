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
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { authenticate, authenticateStage, authenticateEnrollOrSession } = require('../middleware/auth');
const { ensureGuacAccount } = require('../utils/guacamole');
const mfa = require('../utils/mfa');

const GUAC_ENABLED = process.env.GUAC_ENABLED === 'true';

// ============================================================================
// VALIDATION RULES
// ============================================================================

const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
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

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email'),
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

// Short-lived (5 min) token carrying a `stage` claim ('mfa' | 'enroll'). It is
// NOT a session — the stage middleware refuses it on normal protected routes.
function generateStageToken(user, stage) {
  return jwt.sign(
    { sub: user.user_id, email: user.email, role: user.role, stage },
    process.env.JWT_SECRET,
    { expiresIn: '5m' }
  );
}

// Set the 7-day session cookie (same options used by register/login).
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

    // Check if email already exists
    const existingUser = await cybercoreQuery(
      'SELECT user_id FROM cybercore_user WHERE email = $1 OR username = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    const userId = uuidv4();

    // Insert into cybercore_user
    const result = await cybercoreQuery(
      `INSERT INTO cybercore_user
        (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
       RETURNING user_id, email, first_name, last_name, role, organization, created_at`,
      [userId, email, email, passwordHash, 'bcrypt', firstName, lastName, organization || 'Independent', 'student', false]
    );

    const user = result.rows[0];

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

    const { accessToken } = generateTokens(user);

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === 'true',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({
      message: 'Registration successful',
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: user.organization
      },
      token: accessToken
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

    const result = await cybercoreQuery(
      `SELECT user_id, email, password_hash, first_name, last_name, role, organization, status, active, mfa_enabled
       FROM cybercore_user WHERE email = $1 OR username = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Check if account is active
    if (!user.active || user.status !== 'active') {
      return res.status(403).json({ error: 'Account is deactivated. Please contact support.' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
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

    // Update last auth timestamp
    await cybercoreQuery(
      'UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1',
      [user.user_id]
    );

    const { accessToken } = generateTokens(user);
    setSessionCookie(res, accessToken);

    res.json({
      message: 'Login successful',
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: user.organization
      },
      token: accessToken
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
    if (!ok) return res.status(401).json({ error: 'Invalid authentication code' });

    await cybercoreQuery('UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1', [userId]);

    const { accessToken } = generateTokens(user);
    setSessionCookie(res, accessToken);

    res.json({
      message: 'Login successful',
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: user.organization
      },
      token: accessToken,
      ...(usedRecovery ? {
        recovery_code_used: true,
        recovery_codes_remaining: user.mfa_recovery_codes.filter(c => !c.used).length
      } : {})
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
      'SELECT email, mfa_enabled FROM cybercore_user WHERE user_id = $1', [userId]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (r.rows[0].mfa_enabled) {
      return res.status(409).json({ error: 'MFA is already enabled. Disable or reset it first.' });
    }

    const secret = mfa.generateSecret();
    await cybercoreQuery(
      'UPDATE cybercore_user SET mfa_secret = pgp_sym_encrypt($1, $2) WHERE user_id = $3',
      [secret, mfa.mfaKey(), userId]
    );

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
      `SELECT email, first_name, last_name, role, organization, mfa_enabled,
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

    // Forced enrollment came in without a session — log them in now.
    let extra = {};
    if (req.mfaStage === 'enroll') {
      await cybercoreQuery('UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1', [userId]);
      const { accessToken } = generateTokens({ user_id: userId, email: user.email, role: user.role });
      setSessionCookie(res, accessToken);
      extra = {
        token: accessToken,
        user: {
          id: userId, email: user.email, firstName: user.first_name,
          lastName: user.last_name, role: user.role, organization: user.organization
        }
      };
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
    res.json({ message: 'MFA disabled' });
  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({ error: 'Could not disable MFA' });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', authenticate, async (req, res) => {
  try {
    res.clearCookie('token');
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
      `SELECT user_id, email, first_name, last_name, role, organization, created_at, last_auth_at, mfa_enabled
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
        mfaRequired: isMfaRequired(user.role, mfaScope)
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

    const newHash = await bcrypt.hash(newPassword, 12);

    await cybercoreQuery(
      'UPDATE cybercore_user SET password_hash = $1, password_alg = $2, updated_at = NOW() WHERE user_id = $3',
      [newHash, 'bcrypt', req.user.userId]
    );

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
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
