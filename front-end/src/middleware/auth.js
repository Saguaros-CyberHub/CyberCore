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

module.exports = {
  authenticate,
  authenticateToken: authenticate,
  requireRole,
  optionalAuth
};