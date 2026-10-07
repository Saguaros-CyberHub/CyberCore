/**
 * ============================================================================
 * ADMIN — AUDIT LOG API
 * ============================================================================
 * Read side of cybercore_audit_log. Admin-only, by decision: instructors are
 * the subjects of this log, not its audience.
 *
 * Mounted with no path prefix by src/routes/admin.js, so every path below is
 * flat under /api/admin.
 *
 * The old GET /api/admin/activity-log (src/routes/admin/cluster.js:578) still
 * exists and still reads the old clinic_db table. It is deprecated and unused
 * once the Activity Log tab points here.
 */

const express = require('express');
const router = express.Router();

const { authenticateToken, requireRole } = require('../../middleware/auth');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const audit = require('../../utils/audit');

const adminOnly = requireRole('admin');

const MAX_LIMIT = 200;
const MAX_OFFSET = 10000;
const EXPORT_ROW_CAP = 50000;
const EXPORT_PAGE = 1000;

// ---------------------------------------------------------------------------
// Filter builder
// ---------------------------------------------------------------------------

/**
 * Turn a query object into a WHERE clause plus positional params.
 *
 * Exported for tests: the $n numbering as filters combine is the classic
 * off-by-one in this codebase's hand-rolled query builders, and it is much
 * easier to lock in here than through an HTTP round trip.
 *
 * `startIdx` lets the caller reserve earlier placeholders (the export's keyset
 * cursor uses $1/$2).
 */
function buildAuditWhere(q = {}, startIdx = 1) {
  const where = [];
  const params = [];
  let i = startIdx;

  // Repeatable filters collapse to = ANY($n) so the UI can select several
  // actions or several instructors at once.
  const asArray = v => (v == null ? [] : Array.isArray(v) ? v : [v]).filter(x => x !== '');

  const anyOf = (col, val) => {
    const arr = asArray(val);
    if (!arr.length) return;
    if (arr.length === 1) { where.push(`${col} = $${i++}`); params.push(arr[0]); }
    else { where.push(`${col} = ANY($${i++})`); params.push(arr); }
  };

  anyOf('a.action', q.action);
  anyOf('a.category', q.category);
  anyOf('a.status', q.status);
  anyOf('a.source', q.source);
  anyOf('a.actor_user_id', q.actor_user_id);
  anyOf('a.actor_role', q.actor_role);

  if (q.target_user_id) { where.push(`a.target_user_id = $${i++}`); params.push(q.target_user_id); }
  if (q.target_type)    { where.push(`a.target_type = $${i++}`);    params.push(q.target_type); }
  if (q.target_id)      { where.push(`a.target_id = $${i++}`);      params.push(String(q.target_id)); }
  if (q.event_group_id) { where.push(`a.event_group_id = $${i++}`); params.push(q.event_group_id); }

  if (q.from) { where.push(`a.occurred_at >= $${i++}`); params.push(q.from); }
  if (q.to)   { where.push(`a.occurred_at <= $${i++}`); params.push(q.to); }

  if (q.q) {
    // Matches the trigram index expression in migrations/032_audit_log.sql,
    // so it can use that index when pg_trgm is available and degrades to a
    // scan of the already-filtered subset when it is not.
    where.push(`(a.actor_email ILIKE $${i} OR a.target_label ILIKE $${i} OR a.action ILIKE $${i} OR a.reason ILIKE $${i} OR a.target_user_id::text ILIKE $${i})`);
    params.push(`%${q.q}%`);
    i++;
  }

  return {
    clause: where.length ? `WHERE ${where.join(' AND ')}` : '',
    params,
    nextIdx: i,
  };
}

function parseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Normalize the raw query string into the shape buildAuditWhere expects. */
function normalizeQuery(raw) {
  return {
    ...raw,
    from: parseDate(raw.from),
    to:   parseDate(raw.to),
  };
}

// The actor snapshot on the row always wins; the LEFT JOIN only fills a NULL
// actor_email for rows written before the snapshot existed (backfilled ones).
// It is free now that the audit log and cybercore_user share a database —
// which was the whole reason the old activity_log could never do it.
const SELECT_COLS = `
  a.audit_id, a.occurred_at,
  a.actor_user_id, COALESCE(a.actor_email, u.email) AS actor_email,
  a.actor_role, a.actor_type,
  a.action, a.category, a.status, a.reason,
  a.target_type, a.target_id, a.target_label, a.target_user_id,
  a.event_group_id, a.source, a.metadata, a.changes,
  a.ip_address, a.user_agent, a.http_method, a.route, a.request_id`;

const FROM_JOIN = `FROM cybercore_audit_log a
  LEFT JOIN cybercore_user u ON u.user_id = a.actor_user_id`;

// ---------------------------------------------------------------------------
// GET /api/admin/audit — the list
// ---------------------------------------------------------------------------

router.get('/audit', authenticateToken, adminOnly, async (req, res) => {
  try {
    const q = normalizeQuery(req.query);
    const limit  = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), MAX_LIMIT);
    const offset = Math.min(Math.max(parseInt(req.query.offset) || 0, 0), MAX_OFFSET);

    const { clause, params, nextIdx } = buildAuditWhere(q);

    const [rows, countResult] = await Promise.all([
      cybercoreQuery(
        `SELECT ${SELECT_COLS} ${FROM_JOIN} ${clause}
         ORDER BY a.occurred_at DESC, a.audit_id DESC
         LIMIT $${nextIdx} OFFSET $${nextIdx + 1}`,
        [...params, limit, offset]
      ),
      cybercoreQuery(`SELECT COUNT(*) AS total ${FROM_JOIN} ${clause}`, params),
    ]);

    const total = parseInt(countResult.rows[0].total, 10);
    res.json({
      rows:     rows.rows,
      total,
      limit,
      offset,
      has_more: offset + rows.rows.length < total,
      dropped:  audit.stats().dropped,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// GET /api/admin/audit/facets — populates the filter controls
// ---------------------------------------------------------------------------

/**
 * Replaces the hardcoded eleven-option dropdown at public/admin.html:485-497,
 * six of whose values were never written by anything and ~20 of whose written
 * values were missing. Built from the data, so it cannot go stale again.
 *
 * Cached in-process for 60s — it is three aggregates over the whole table and
 * the tab refetches it on every activation.
 */
let facetCache = { at: 0, data: null };
const FACET_TTL_MS = 60_000;

router.get('/audit/facets', authenticateToken, adminOnly, async (req, res) => {
  try {
    // Per-actor summary for the header card; not cached, it is filter-specific.
    if (req.query.actor_user_id) {
      const summary = await cybercoreQuery(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE action = 'enrollment.student_added')::int AS students_added,
                COUNT(*) FILTER (WHERE category = 'infra')::int                   AS infra_events,
                COUNT(*) FILTER (WHERE status <> 'success')::int                  AS problems,
                MAX(occurred_at) AS last_active
           FROM cybercore_audit_log WHERE actor_user_id = $1`,
        [req.query.actor_user_id]
      );
      return res.json({ actor_summary: summary.rows[0] });
    }

    if (facetCache.data && Date.now() - facetCache.at < FACET_TTL_MS) {
      return res.json({ ...facetCache.data, cached: true });
    }

    const [actions, actors, sources] = await Promise.all([
      cybercoreQuery(
        `SELECT action, category, COUNT(*)::int AS count
           FROM cybercore_audit_log
          GROUP BY action, category ORDER BY category, action`
      ),
      cybercoreQuery(
        `SELECT actor_user_id, actor_email, actor_role, COUNT(*)::int AS count,
                MAX(occurred_at) AS last_active
           FROM cybercore_audit_log
          WHERE actor_user_id IS NOT NULL
          GROUP BY actor_user_id, actor_email, actor_role
          ORDER BY count DESC LIMIT 500`
      ),
      cybercoreQuery(`SELECT source, COUNT(*)::int AS count FROM cybercore_audit_log GROUP BY source`),
    ]);

    const data = {
      actions:    actions.rows,
      actors:     actors.rows,
      sources:    sources.rows,
      categories: ['auth', 'user', 'enrollment', 'infra', 'content', 'config', 'access'],
      statuses:   ['success', 'failure', 'denied'],
      dropped:    audit.stats().dropped,
    };
    facetCache = { at: Date.now(), data };
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// GET /api/admin/audit/export.csv — streaming export
// ---------------------------------------------------------------------------

/**
 * An audit log is full of attacker-controlled strings: the email typed at a
 * failed login, a user agent, a lane name. Quote everything, double embedded
 * quotes, and neutralize the leading characters Excel and Sheets treat as a
 * formula.
 */
function csvCell(value) {
  if (value == null) return '""';
  let s = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

const EXPORT_COLUMNS = [
  'occurred_at', 'actor_email', 'actor_role', 'actor_type', 'action', 'category',
  'status', 'reason', 'target_type', 'target_label', 'target_id',
  'target_user_id', 'source', 'ip_address', 'http_method', 'route',
  'metadata', 'changes',
];

router.get('/audit/export.csv', authenticateToken, adminOnly, async (req, res) => {
  try {
    const q = normalizeQuery(req.query);

    // A date range is mandatory so an unfiltered export cannot try to stream
    // the whole table. Defaults to the last 30 days.
    if (!q.from) {
      const d = new Date();
      d.setDate(d.getDate() - 30);
      q.from = d.toISOString();
    }

    const fname = `audit-${q.from.slice(0, 10)}_${(q.to || new Date().toISOString()).slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.write('﻿');                                    // BOM, so Excel reads UTF-8
    res.write(EXPORT_COLUMNS.map(csvCell).join(',') + '\r\n');

    // Keyset paging, not LIMIT/OFFSET: pg-cursor is not a dependency and
    // OFFSET degrades badly precisely on the large exports this exists for.
    let cursor = null;
    let written = 0;

    while (written < EXPORT_ROW_CAP) {
      const keyParams = [];
      let idx = 1;
      let keyClause = '';
      if (cursor) {
        keyClause = `(a.occurred_at, a.audit_id) < ($1, $2)`;
        keyParams.push(cursor.occurred_at, cursor.audit_id);
        idx = 3;
      }
      const { clause, params, nextIdx } = buildAuditWhere(q, idx);
      const merged = [keyClause, clause.replace(/^WHERE /, '')].filter(Boolean).join(' AND ');

      const page = await cybercoreQuery(
        `SELECT ${SELECT_COLS} ${FROM_JOIN} ${merged ? `WHERE ${merged}` : ''}
         ORDER BY a.occurred_at DESC, a.audit_id DESC LIMIT $${nextIdx}`,
        [...keyParams, ...params, Math.min(EXPORT_PAGE, EXPORT_ROW_CAP - written)]
      );

      if (!page.rows.length) break;
      for (const row of page.rows) {
        res.write(EXPORT_COLUMNS.map(c => csvCell(row[c])).join(',') + '\r\n');
      }
      written += page.rows.length;
      const last = page.rows[page.rows.length - 1];
      cursor = { occurred_at: last.occurred_at, audit_id: last.audit_id };
      if (page.rows.length < EXPORT_PAGE) break;
    }

    res.end();

    // A bulk disclosure of the audit trail is itself worth a row.
    audit.log({
      req,
      action: 'config.audit_exported',
      target: { type: 'audit_log', label: `${written} rows` },
      metadata: { rows: written, filters: { ...req.query } },
    });
  } catch (error) {
    // Headers may already be sent mid-stream; only a fresh response can 500.
    if (!res.headersSent) res.status(500).json({ error: error.message });
    else res.end();
  }
});

// ---------------------------------------------------------------------------
// GET /api/admin/audit/:id — one row plus its bulk siblings
// ---------------------------------------------------------------------------

router.get('/audit/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid audit id' });

    const row = await cybercoreQuery(
      `SELECT ${SELECT_COLS} ${FROM_JOIN} WHERE a.audit_id = $1`, [id]
    );
    if (!row.rows.length) return res.status(404).json({ error: 'Not found' });

    const event = row.rows[0];
    let related = [];
    if (event.event_group_id) {
      const siblings = await cybercoreQuery(
        `SELECT ${SELECT_COLS} ${FROM_JOIN}
          WHERE a.event_group_id = $1 AND a.audit_id <> $2
          ORDER BY a.audit_id LIMIT 500`,
        [event.event_group_id, id]
      );
      related = siblings.rows;
    }

    res.json({ event, related });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
module.exports.buildAuditWhere = buildAuditWhere;
module.exports.csvCell = csvCell;
