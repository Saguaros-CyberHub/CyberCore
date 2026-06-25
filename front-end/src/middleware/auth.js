/**
 * ============================================================================
 * AUTHENTICATION MIDDLEWARE
 * ============================================================================
 */

const jwt = require('jsonwebtoken');

/**
 * Middleware to authenticate JWT token
 * Checks both Authorization header and cookie
 */
function authenticate(req, res, next) {
  try {
    let token = null;

    // Check Authorization header first
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    // Fall back to cookie
    if (!token && req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'NO_TOKEN'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user info to request
    req.user = {
      userId: decoded.sub,
      email: decoded.email,
      role: decoded.role
    };

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Session expired. Please login again.',
        code: 'TOKEN_EXPIRED'
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid authentication token',
        code: 'INVALID_TOKEN'
      });
    }
    console.error('Auth middleware error:', error);
    return res.status(500).json({ error: 'Authentication error' });
  }
}

/**
 * Middleware to check if user has required role
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const userRole = req.user.role || 'student';  // Added default role fallback
    
    if (!roles.includes(userRole)) {
      return res.status(403).json({ 
        error: 'Access denied. Insufficient permissions.',
        requiredRoles: roles,
        userRole: userRole
      });
    }
    next();
  };
}

/**
 * Optional authentication - doesn't fail if no token
 */
function optionalAuth(req, res, next) {
  try {
    let token = null;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    if (!token && req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = {
        userId: decoded.sub,
        email: decoded.email,
        role: decoded.role
      };
    }

    next();
  } catch (error) {
    // Token invalid but continue without user
    next();
  }
}

/**
 * Strictly authenticate a short-lived stage token (Authorization: Bearer only).
 * Stage tokens carry a `stage` claim ('mfa' or 'enroll') and must NEVER be
 * accepted as a full session — used for the second step of login.
 * Exposes req.user and req.mfaStage. Does not read the session cookie.
 */
function authenticateStage(stage) {
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
      if (!token) {
        return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
      }
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (decoded.stage !== stage) {
        return res.status(401).json({ error: 'Invalid token for this step', code: 'WRONG_STAGE' });
      }
      req.user = { userId: decoded.sub, email: decoded.email, role: decoded.role };
      req.mfaStage = decoded.stage;
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'This step expired. Please sign in again.', code: 'TOKEN_EXPIRED' });
      }
      return res.status(401).json({ error: 'Invalid authentication token', code: 'INVALID_TOKEN' });
    }
  };
}

/**
 * Accept EITHER a full session (cookie or bearer JWT with no stage claim) OR an
 * 'enroll' stage token. Lets MFA setup/verify serve both the self-enrolling
 * logged-in user and the forced-enrollment (not-yet-logged-in) user.
 * Sets req.user and req.mfaStage (null for a full session).
 */
function authenticateEnrollOrSession(req, res, next) {
  try {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) token = authHeader.substring(7);
    if (!token && req.cookies && req.cookies.token) token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.stage && decoded.stage !== 'enroll') {
      return res.status(401).json({ error: 'Invalid token for this step', code: 'WRONG_STAGE' });
    }
    req.user = { userId: decoded.sub, email: decoded.email, role: decoded.role };
    req.mfaStage = decoded.stage || null;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please sign in again.', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid authentication token', code: 'INVALID_TOKEN' });
  }
}

module.exports = {
  authenticate,
  authenticateToken: authenticate,
  requireRole,
  optionalAuth,
  authenticateStage,
  authenticateEnrollOrSession
};