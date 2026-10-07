/**
 * CIAB Plugin — Schedule-Based Access Control
 * Checks if a student is allowed access based on their group's time window.
 * Must run AFTER authenticateToken. Only applies to student accounts.
 */

const { query: dbQuery } = require('../utils/db');

function checkSchedule(req, res, next) {
  // Only check students — instructors and admins always pass
  if (!req.user || req.user.role !== 'student') {
    return next();
  }

  checkScheduleAsync(req, res, next).catch(err => {
    console.error('[CIAB] Schedule check error:', err);
    // Fail open — if schedule check errors, allow access
    next();
  });
}

async function checkScheduleAsync(req, res, next) {
  const groupResult = await dbQuery(
    `SELECT dg.id AS group_id, s.active_days, s.active_start, s.active_end, s.timezone, s.override_active
     FROM deployed_groups dg
     JOIN account_schedules s ON s.group_id = dg.id
     WHERE dg.config::jsonb->'students' @> jsonb_build_array(jsonb_build_object('id', $1::text))`,
    [req.user.userId]
  );

  if (groupResult.rows.length === 0) {
    return next();
  }

  const schedule = groupResult.rows[0];

  // Check override first
  if (schedule.override_active === true) {
    return next();
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

    const dayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    const dayOfWeek = dayMap[weekdayStr];

    localTime = { hour, minute, dayOfWeek };
  } catch (e) {
    console.error('[CIAB] Timezone parse error:', e);
    return next();
  }

  if (!schedule.active_days.includes(localTime.dayOfWeek)) {
    return res.status(403).json({
      error: 'Account access is only available on scheduled days.',
      code: 'SCHEDULE_WRONG_DAY',
      schedule: {
        active_days: schedule.active_days,
        active_start: schedule.active_start,
        active_end: schedule.active_end,
        timezone: tz
      }
    });
  }

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

module.exports = { checkSchedule };
