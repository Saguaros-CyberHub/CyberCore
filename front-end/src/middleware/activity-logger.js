/**
 * ============================================================================
 * ACTIVITY LOGGER — compatibility shim
 * ============================================================================
 * The real writer is src/utils/audit.js, which writes cybercore_audit_log in
 * cybercore_db. This file stays so the ~20 existing
 *   require('../../middleware/activity-logger')
 * paths keep resolving and their call sites need no edit; logActivity() maps
 * the old (req, actionType, entityType, entityId, metadata) signature onto the
 * new writer and runs the old action names through LEGACY_ACTION_MAP so the
 * table speaks one vocabulary from day one.
 *
 * Writes used to land in `activity_log` in clinic_db — the CIAB *plugin's*
 * database — which is why the admin console could never resolve an actor's
 * email and rendered every row as "system". Nothing writes there now.
 *
 * Migrate call sites to `require('../../utils/audit')` opportunistically; this
 * file can be deleted once none remain.
 */

const { logActivity } = require('../utils/audit');

module.exports = { logActivity };
