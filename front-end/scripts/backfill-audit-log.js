#!/usr/bin/env node
/**
 * ============================================================================
 * BACKFILL — legacy activity logs -> cybercore_audit_log
 * ============================================================================
 * A script, not a migration, because the sources live in different databases:
 *   activity_log      in clinic_db  (defined by the CIAB plugin)
 *   cle_activity_log  in cle_db     (defined by the CLE plugin)
 * and the destination is cybercore_db. No single .sql file can span those.
 *
 * WHAT IT COPIES
 *   - All of activity_log. It is small, entirely staff actions, and the only
 *     continuity the admin console has today.
 *   - With --include-cle, only the STAFF rows from cle_activity_log. That
 *     table's CHECK enum forced three call sites to mis-file what they did and
 *     stash the truth in metadata.action (cle/routes/guacamole.js:50,
 *     cle/utils/roster.js:319, cle/routes/course-students.js:187), so those
 *     rows are recovered exactly by reading metadata->>'action'. Everything
 *     else in that table is student telemetry (material_view, course_access,
 *     vm_start/stop) which would drown the admin view and is still queryable
 *     in place.
 *
 * Idempotent: rows are stamped metadata.legacy_id and inserted with
 * ON CONFLICT DO NOTHING against ux_audit_legacy_id (migrations/032). Re-runs
 * are safe and add nothing.
 *
 * Neither source table is altered or dropped.
 *
 * Usage:
 *   node scripts/backfill-audit-log.js --dry-run
 *   node scripts/backfill-audit-log.js
 *   node scripts/backfill-audit-log.js --include-cle
 * ============================================================================
 */

require('dotenv').config();

const { Pool } = require('pg');
const { cybercoreQuery } = require('../src/utils/cybercore-db');
const { LEGACY_ACTION_MAP, categoryOf } = require('../src/utils/audit');

const DRY_RUN = process.argv.includes('--dry-run');
const INCLUDE_CLE = process.argv.includes('--include-cle');
const PAGE = 500;

const clinicPool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'clinic_db',
  user: process.env.DB_USER || 'clinic_admin',
  password: process.env.DB_PASSWORD,
  max: 4,
});

const clePool = new Pool({
  host: process.env.CYBERCORE_DB_HOST || 'localhost',
  port: parseInt(process.env.CYBERCORE_DB_PORT) || 5432,
  database: process.env.CLE_DB_NAME || 'cle_db',
  user: process.env.CYBERCORE_DB_USER || process.env.CORE_DB_USER,
  password: process.env.CYBERCORE_DB_PASSWORD || process.env.CORE_DB_PASSWORD,
  max: 4,
});

const COLUMNS = [
  'occurred_at', 'actor_user_id', 'actor_email', 'actor_role', 'actor_type',
  'action', 'category', 'status', 'reason',
  'target_type', 'target_id', 'target_label', 'target_user_id',
  'event_group_id', 'source', 'metadata', 'changes',
  'ip_address', 'user_agent', 'http_method', 'route', 'request_id',
];

/**
 * Resolve actor email/role for a page of rows in one query. Unresolvable ids
 * are deleted accounts — the row still copies over, just without a name.
 */
async function resolveActors(userIds) {
  const ids = [...new Set(userIds.filter(Boolean))];
  if (!ids.length) return new Map();
  const res = await cybercoreQuery(
    `SELECT user_id, email, role FROM cybercore_user WHERE user_id = ANY($1)`, [ids]
  );
  return new Map(res.rows.map(r => [r.user_id, r]));
}

function sanitizeIp(raw) {
  if (!raw) return null;
  const ip = String(raw).replace(/^::ffff:/, '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip;
  if (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip)) return ip;
  return null;
}

async function insertRows(rows) {
  if (!rows.length) return 0;
  if (DRY_RUN) return rows.length;
  const width = COLUMNS.length;
  const groups = rows.map((_, r) =>
    `(${Array.from({ length: width }, (_, i) => `$${r * width + i + 1}`).join(', ')})`
  ).join(', ');
  const res = await cybercoreQuery(
    `INSERT INTO cybercore_audit_log (${COLUMNS.join(', ')}) VALUES ${groups}
     ON CONFLICT ((metadata->>'legacy_id')) WHERE metadata ? 'legacy_id' DO NOTHING`,
    rows.flat()
  );
  return res.rowCount;
}

async function backfillActivityLog() {
  console.log('\n— activity_log (clinic_db) —');
  let after = '1970-01-01T00:00:00Z';
  let seen = 0, written = 0;

  for (;;) {
    const page = await clinicPool.query(
      `SELECT id, user_id, action_type, entity_type, entity_id, metadata,
              ip_address, user_agent, created_at
         FROM activity_log
        WHERE created_at > $1
        ORDER BY created_at ASC
        LIMIT $2`,
      [after, PAGE]
    );
    if (!page.rows.length) break;

    const actors = await resolveActors(page.rows.map(r => r.user_id));
    const values = page.rows.map(r => {
      const actor = actors.get(r.user_id);
      const action = LEGACY_ACTION_MAP[r.action_type] || r.action_type;
      return [
        r.created_at,
        r.user_id || null,
        actor?.email || null,
        actor?.role || null,
        r.user_id ? 'user' : 'system',
        action,
        categoryOf(action),
        'success',
        null,
        r.entity_type || null,
        r.entity_id != null ? String(r.entity_id) : null,
        null,
        null,
        null,
        'core',
        JSON.stringify({ ...(r.metadata || {}), backfilled_from: 'activity_log', legacy_id: `al:${r.id}` }),
        null,
        sanitizeIp(r.ip_address),
        r.user_agent || null,
        null, null, null,
      ];
    });

    written += await insertRows(values);
    seen += page.rows.length;
    after = page.rows[page.rows.length - 1].created_at;
    process.stdout.write(`\r  read ${seen}, written ${written}`);
    if (page.rows.length < PAGE) break;
  }
  console.log(`\n  done: read ${seen}, written ${written}`);
}

async function backfillCleStaffRows() {
  console.log('\n— cle_activity_log (cle_db), staff rows only —');
  let after = '1970-01-01T00:00:00Z';
  let seen = 0, written = 0;

  for (;;) {
    // This predicate matches exactly the three deliberate enum workarounds and
    // nothing else: student telemetry never carries metadata.action.
    const page = await clePool.query(
      `SELECT activity_id, user_id, action_type, entity_type, entity_id,
              metadata, ip_address, created_at
         FROM cle_activity_log
        WHERE created_at > $1
          AND action_type IN ('guac_session','enrollment_change')
          AND metadata ? 'action'
        ORDER BY created_at ASC
        LIMIT $2`,
      [after, PAGE]
    );
    if (!page.rows.length) break;

    const actors = await resolveActors(page.rows.map(r => r.user_id));
    const values = page.rows.map(r => {
      const actor = actors.get(r.user_id);
      const trueAction = r.metadata?.action || r.action_type;
      // The recovered names are CLE-local verbs; give them a domain so they
      // land in the same vocabulary as everything else.
      const action = trueAction.includes('.') ? trueAction
        : (r.action_type === 'guac_session' ? `access.${trueAction}` : `enrollment.${trueAction}`);
      return [
        r.created_at,
        r.user_id || null,
        actor?.email || null,
        actor?.role || null,
        r.user_id ? 'user' : 'system',
        action,
        categoryOf(action),
        'success',
        null,
        r.entity_type || null,
        r.entity_id != null ? String(r.entity_id) : null,
        null,
        null,
        null,
        'cle',
        JSON.stringify({ ...(r.metadata || {}), backfilled_from: 'cle_activity_log', legacy_id: `cle:${r.activity_id}` }),
        null,
        sanitizeIp(r.ip_address),
        null, null, null, null,
      ];
    });

    written += await insertRows(values);
    seen += page.rows.length;
    after = page.rows[page.rows.length - 1].created_at;
    process.stdout.write(`\r  read ${seen}, written ${written}`);
    if (page.rows.length < PAGE) break;
  }
  console.log(`\n  done: read ${seen}, written ${written}`);
}

async function main() {
  console.log(DRY_RUN ? 'DRY RUN — nothing will be written' : 'Backfilling cybercore_audit_log');

  try {
    await backfillActivityLog();
  } catch (err) {
    console.error('  activity_log backfill failed:', err.message);
  }

  if (INCLUDE_CLE) {
    try {
      await backfillCleStaffRows();
    } catch (err) {
      console.error('  cle_activity_log backfill failed:', err.message);
    }
  } else {
    console.log('\n(skipping cle_activity_log — pass --include-cle to include staff rows)');
  }

  await clinicPool.end().catch(() => {});
  await clePool.end().catch(() => {});
  process.exit(0);
}

main();
