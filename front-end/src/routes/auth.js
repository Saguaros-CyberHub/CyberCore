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
const { authenticate } = require('../middleware/auth');

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
      `SELECT user_id, email, password_hash, first_name, last_name, role, organization, status, active
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

    // Update last auth timestamp
    await cybercoreQuery(
      'UPDATE cybercore_user SET last_auth_at = NOW() WHERE user_id = $1',
      [user.user_id]
    );

    const { accessToken } = generateTokens(user);

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === 'true',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

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
      `SELECT user_id, email, first_name, last_name, role, organization, created_at, last_auth_at
       FROM cybercore_user WHERE user_id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    res.json({
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: user.organization,
        createdAt: user.created_at,
        lastLogin: user.last_auth_at
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
