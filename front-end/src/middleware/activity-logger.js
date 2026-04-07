/**
 * ============================================================================
 * ACTIVITY LOGGER
 * Reusable utility for logging user actions to the activity_log table
 * ============================================================================
 */

const { query } = require('../utils/db');

/**
 * Log an activity to the activity_log table
 * @param {object} req - Express request object (for user info, IP, user-agent)
 * @param {string} actionType - e.g., 'login', 'deploy_lane', 'toggle_account'
 * @param {string} entityType - e.g., 'user', 'lane', 'group', 'profile'
 * @param {string|null} entityId - UUID of the entity being acted on
 * @param {object|null} metadata - Additional JSON metadata
 */
async function logActivity(req, actionType, entityType, entityId = null, metadata = null) {
  try {
    const userId = req?.user?.userId || null;
    const ipAddress = req?.ip || req?.connection?.remoteAddress || null;
    const userAgent = req?.headers?.['user-agent'] || null;

    await query(
      `INSERT INTO activity_log (user_id, action_type, entity_type, entity_id, metadata, ip_address, user_agent, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [userId, actionType, entityType, entityId, metadata ? JSON.stringify(metadata) : null, ipAddress, userAgent]
    );
  } catch (error) {
    // Never let logging failures break the main flow
    console.error('[ActivityLog] Failed to log:', actionType, entityType, error.message);
  }
}

module.exports = { logActivity };
