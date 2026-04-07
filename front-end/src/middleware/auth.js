/**
 * ============================================================================
 * AUTHENTICATION MIDDLEWARE
 * ============================================================================
 */

const jwt = require('jsonwebtoken');
const { query: dbQuery } = require('../utils/db');

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
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');

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
 * Middleware to check account schedule (time-based access windows).
 * Must run AFTER authenticate. Only applies to student accounts.
 * Checks account_schedules table for the student's group to see if
 * access is allowed at the current time.
 */
function checkSchedule(req, res, next) {
  // Only check students — instructors and admins always pass
  if (!req.user || req.user.role !== 'student') {
    return next();
  }

  // Run async schedule check
  checkScheduleAsync(req, res, next).catch(err => {
    console.error('Schedule check error:', err);
    // Fail open — if schedule check errors, allow access
    next();
  });
}

async function checkScheduleAsync(req, res, next) {
  // Find which group(s) this student belongs to via deployed_groups config
  const groupResult = await dbQuery(
    `SELECT dg.id AS group_id, s.active_days, s.active_start, s.active_end, s.timezone, s.override_active
     FROM deployed_groups dg
     JOIN account_schedules s ON s.group_id = dg.id
     WHERE dg.config::jsonb->'students' @> jsonb_build_array(jsonb_build_object('id', $1::text))`,
    [req.user.userId]
  );

  // No schedule found — allow access
  if (groupResult.rows.length === 0) {
    return next();
  }

  const schedule = groupResult.rows[0];

  // Check override first
  if (schedule.override_active === true) {
    return next(); // Instructor forced on
  }
  if (schedule.override_active === false) {
    return res.status(403).json({
      error: 'Account access has been disabled by your instructor.',
      code: 'SCHEDULE_OVERRIDE_OFF'
    });
  }

  // Check time-based schedule
  const tz = schedule.timezone || 'America/Chicago';
  const now = new Date();

  // Get current time in the schedule's timezone
  let localTime;
  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      weekday: 'short'
    });
    const parts = formatter.formatToParts(now);
    const hour = parseInt(parts.find(p => p.type === 'hour').value);
    const minute = parseInt(parts.find(p => p.type === 'minute').value);
    const weekdayStr = parts.find(p => p.type === 'weekday').value;

    // Map weekday string to 0-6 (Sun-Sat)
    const dayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    const dayOfWeek = dayMap[weekdayStr];

    localTime = { hour, minute, dayOfWeek };
  } catch (e) {
    console.error('Timezone parse error:', e);
    return next(); // Fail open on timezone error
  }

  // Check if current day is in active_days
  if (!schedule.active_days.includes(localTime.dayOfWeek)) {
    return res.status(403).json({
      error: `Account access is only available on scheduled days.`,
      code: 'SCHEDULE_WRONG_DAY',
      schedule: {
        active_days: schedule.active_days,
        active_start: schedule.active_start,
        active_end: schedule.active_end,
        timezone: tz
      }
    });
  }

  // Check time window
  const currentMinutes = localTime.hour * 60 + localTime.minute;
  const [startH, startM] = schedule.active_start.split(':').map(Number);
  const [endH, endM] = schedule.active_end.split(':').map(Number);
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;

  if (currentMinutes < startMinutes || currentMinutes >= endMinutes) {
    return res.status(403).json({
      error: `Account access is only available from ${schedule.active_start} to ${schedule.active_end} (${tz}).`,
      code: 'SCHEDULE_WRONG_TIME',
      schedule: {
        active_days: schedule.active_days,
        active_start: schedule.active_start,
        active_end: schedule.active_end,
        timezone: tz
      }
    });
  }

  next();
}

/**
 * Middleware to check if user has required role
 */
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
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
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
  optionalAuth,
  checkSchedule
};