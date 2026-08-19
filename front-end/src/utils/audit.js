/**
 * ============================================================================
 * AUDIT LOG WRITER
 * ============================================================================
 * The single write path for cybercore_audit_log (migrations/032_audit_log.sql).
 *
 * WHY THIS LIVES IN utils/ AND NOT middleware/
 * It is not Express middleware. It is called from route bodies, from
 * src/utils/account-provisioning.js (which has no `req` at all), and from
 * plugin code that reaches core by relative path the same way
 * cle/routes/api.js:10 reaches the auth middleware. The old
 * src/middleware/activity-logger.js is now a shim over this module so the
 * ~20 existing require paths keep resolving unchanged.
 *
 * DESIGN NOTES
 * - log() returns a promise that NEVER rejects. Callers who need the row
 *   durable before they act (disclosing a credential, say) can await it; the
 *   existing fire-and-forget call sites can keep ignoring it without ever
 *   producing an unhandled rejection.
 * - `category` is derived here from the action prefix and is never a
 *   parameter. That is what stops it drifting as the vocabulary grows.
 * - redact() is a net, not a licence. Call sites must still never pass a
 *   secret; this catches the ones that slip through.
 */

const crypto = require('crypto');
const { cybercoreQuery } = require('./cybercore-db');

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/**
 * Action prefix -> category. The four coverage areas the admin console filters
 * on map onto these: users+enrollment, infra, auth+access, config+content.
 *
 * An unknown prefix falls back to 'config' with a warning rather than throwing
 * — a typo should be visible, not a reason to lose the audit row.
 */
const CATEGORY_BY_PREFIX = {
  auth:          'auth',
  user:          'user',
  enrollment:    'enrollment',
  course:        'enrollment',
  lane:          'infra',
  vm:            'infra',
  lab:           'infra',
  workstation:   'infra',
  group:         'infra',
  storage:       'infra',
  guac:          'infra',
  profile_lane:  'infra',
  network:       'infra',
  access:        'access',
  flag:          'access',
  content:       'content',
  script:        'content',
  template:      'content',
  config:        'config',
};

function categoryOf(action) {
  const prefix = String(action || '').split('.')[0];
  const category = CATEGORY_BY_PREFIX[prefix];
  if (!category) {
    console.warn(`[Audit] unknown action prefix "${prefix}" in "${action}" — filed under config`);
    return 'config';
  }
  return category;
}

/**
 * Old action names -> new ones, so the ~20 untouched logActivity() call sites
 * produce rows in the same vocabulary as everything else. Without this the
 * table would be half 'deploy_lane' and half 'lane.deployed' on day one.
 */
const LEGACY_ACTION_MAP = {
  settings_update:                 'config.updated',
  user_created:                    'user.created',
  user_updated:                    'user.updated',
  users_batch_created:             'user.batch_created',
  user_password_reset:             'user.password_reset',
  user_mfa_reset:                  'user.mfa_reset',
  mail_test:                       'config.mail_tested',
  deploy_lane:                     'lane.deployed',
  delete_lane:                     'lane.destroyed',
  attach_module:                   'lane.module_attached',
  detach_module:                   'lane.module_detached',
  toggle_internet:                 'lane.internet_toggled',
  deploy_group:                    'group.deployed',
  delete_group:                    'group.destroyed',
  toggle_accounts:                 'group.accounts_toggled',
  destroy_orphan_disk:             'storage.orphan_destroyed',
  scan_orphaned_disks:             'storage.orphan_scanned',
  sweep_orphaned_disks:            'storage.orphan_swept',
  destroy_orphan_guac_connection:  'guac.orphan_connection_destroyed',
  deploy_challenge_network:        'lane.network_deployed',
  generate_challenge_profile:      'content.profile_generated',
  view_guac_credential:            'access.credential_viewed',
  reset_guac_credential:           'access.credential_reset',
};

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const SECRET_KEY_RE = /pass(word|wd)?|secret|token|hash|_key$|^key$|cred|otp|recovery|authorization|cookie|session|mfa/i;
const MAX_STRING = 2000;
const MAX_SERIALIZED = 16 * 1024;
const MAX_DEPTH = 6;

/**
 * Recursively strip anything that looks like a credential.
 *
 * The precedent is migrations/029_email_outbox.sql, which encrypts message
 * bodies precisely because activation links are working credentials until
 * redeemed — and adminer is published on 0.0.0.0:8181. This table is
 * plaintext, so it must never receive one.
 */
function redact(value, depth = 0) {
  if (value == null) return value;
  if (depth > MAX_DEPTH) return '[depth-limit]';

  if (typeof value === 'string') {
    return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…[truncated]` : value;
  }
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));

  const out = {};
  for (const [key, val] of Object.entries(value)) {
    out[key] = SECRET_KEY_RE.test(key) ? '[redacted]' : redact(val, depth + 1);
  }
  return out;
}

function boundedJson(obj) {
  if (obj == null) return null;
  const clean = redact(obj);
  const serialized = JSON.stringify(clean);
  if (serialized && serialized.length > MAX_SERIALIZED) {
    return JSON.stringify({ __truncated: true, __bytes: serialized.length });
  }
  return serialized;
}

// ---------------------------------------------------------------------------
// Request context
// ---------------------------------------------------------------------------

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

/**
 * An unparseable value must become NULL rather than an INET cast error that
 * kills the INSERT. `app.set('trust proxy')` at src/server.js:174 means req.ip
 * is meaningful, but a hostile X-Forwarded-For can still be anything.
 */
function sanitizeIp(raw) {
  if (!raw) return null;
  let ip = String(raw).trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (IPV4.test(ip) || (ip.includes(':') && IPV6.test(ip))) return ip;
  return null;
}

/**
 * Extract IP / user-agent / route from a request. Exported so callers with no
 * `req` downstream (account-provisioning) can capture it once and pass it on.
 *
 * Uses the route PATTERN, not req.originalUrl — signed-URL tokens ride in the
 * query string (src/server.js:400-407) and must never be written here.
 */
function ctx(req) {
  if (!req) return {};
  const routePattern = req.route?.path
    ? `${req.baseUrl || ''}${req.route.path}`
    : (req.baseUrl || null);
  return {
    ip:        sanitizeIp(req.ip || req.connection?.remoteAddress),
    userAgent: (req.headers?.['user-agent'] || '').slice(0, 512) || null,
    method:    req.method || null,
    route:     routePattern,
    requestId: req.id || req.headers?.['x-request-id'] || null,
  };
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

const COLUMNS = [
  'occurred_at', 'actor_user_id', 'actor_email', 'actor_role', 'actor_type',
  'action', 'category', 'status', 'reason',
  'target_type', 'target_id', 'target_label', 'target_user_id',
  'event_group_id', 'source', 'metadata', 'changes',
  'ip_address', 'user_agent', 'http_method', 'route', 'request_id',
];

let droppedCount = 0;

/**
 * Normalize one event into the positional value array matching COLUMNS.
 *
 * `req` and `actor` are independent and both optional. `req` supplies actor
 * and context; an explicit `actor` overrides it. A failed login has an email
 * string and nothing else; account-provisioning has a userId and a separate
 * `context` object.
 */
function buildValues(evt) {
  const {
    req, actor, context, action, status = 'success', reason = null,
    target = {}, targetUser = {}, metadata = null, changes = null,
    source = 'core', eventGroupId = null, occurredAt = null,
  } = evt;

  const c = { ...ctx(req), ...(context || {}) };

  const actorUserId = actor?.userId !== undefined ? actor.userId : (req?.user?.userId ?? null);
  const actorEmail  = actor?.email   !== undefined ? actor.email   : (req?.user?.email  ?? null);
  const actorRole   = actor?.role    !== undefined ? actor.role    : (req?.user?.role   ?? null);
  const actorType   = actor?.type || (actorUserId ? 'user' : 'anonymous');

  const canonicalAction = LEGACY_ACTION_MAP[action] || action;

  return [
    occurredAt || new Date(),
    actorUserId,
    actorEmail ? String(actorEmail).slice(0, 255) : null,
    actorRole,
    actorType,
    canonicalAction,
    categoryOf(canonicalAction),
    status,
    reason,
    target.type ?? null,
    target.id != null ? String(target.id) : null,
    target.label ?? targetUser.label ?? null,
    targetUser.id ?? null,
    eventGroupId,
    source,
    boundedJson(metadata) || '{}',
    boundedJson(changes),
    c.ip ?? null,
    c.userAgent ?? null,
    c.method ?? null,
    c.route ?? null,
    c.requestId ?? null,
  ];
}

function placeholders(rowCount) {
  const width = COLUMNS.length;
  const groups = [];
  for (let r = 0; r < rowCount; r++) {
    const slots = [];
    for (let i = 1; i <= width; i++) slots.push(`$${r * width + i}`);
    groups.push(`(${slots.join(', ')})`);
  }
  return groups.join(', ');
}

/**
 * Write one audit row.
 *
 * Never rejects. If cybercore_db is unreachable the event is emitted to the
 * file logger instead of vanishing — a deploy or a login must never fail
 * because the audit write did.
 */
async function log(evt) {
  try {
    const values = buildValues(evt);
    await cybercoreQuery(
      `INSERT INTO cybercore_audit_log (${COLUMNS.join(', ')}) VALUES ${placeholders(1)}`,
      values
    );
  } catch (error) {
    droppedCount++;
    // Degrade to the rotating file log (src/utils/logger.js) rather than
    // silence, so a failing writer is recoverable after the fact.
    console.error('[Audit] dropped:', evt?.action, error.message, JSON.stringify({
      actor: evt?.actor?.email || evt?.req?.user?.email || null,
      target: evt?.target || null,
    }));
  }
}

/**
 * Write many rows in one INSERT.
 *
 * A roster import creating 200 accounts must not become 200 round-trips, and
 * one statement also means the fan-out is atomic with respect to readers.
 */
async function logMany(events) {
  if (!Array.isArray(events) || events.length === 0) return;
  try {
    const values = events.flatMap(buildValues);
    await cybercoreQuery(
      `INSERT INTO cybercore_audit_log (${COLUMNS.join(', ')}) VALUES ${placeholders(events.length)}`,
      values
    );
  } catch (error) {
    droppedCount += events.length;
    console.error('[Audit] dropped batch:', events.length, events[0]?.action, error.message);
  }
}

/**
 * Summary row plus one row per affected target, sharing an event_group_id.
 *
 * Both are needed: per-target rows are what make "which students did this
 * instructor add" answerable by filtering target_user_id, while thirty rows
 * per click would swamp the list without a summary to collapse them into.
 *
 * Fan-out is capped — beyond the cap the summary records the true count and
 * flags the truncation rather than silently writing a partial trail.
 */
const MAX_FANOUT = 500;

async function batch({ targets = [], targetAction, ...summary }) {
  const eventGroupId = crypto.randomUUID();
  const capped = targets.slice(0, MAX_FANOUT);

  await log({
    ...summary,
    eventGroupId,
    metadata: {
      ...(summary.metadata || {}),
      affected_count: targets.length,
      ...(targets.length > capped.length ? { fanout_truncated: true, fanout_written: capped.length } : {}),
    },
  });

  if (capped.length) {
    await logMany(capped.map(t => ({
      req:       summary.req,
      actor:     summary.actor,
      context:   summary.context,
      source:    summary.source,
      status:    t.status || summary.status,
      reason:    t.reason || null,
      action:    targetAction,
      target:    t.target || { type: 'user', id: t.id, label: t.label },
      targetUser: t.targetUser || (t.id ? { id: t.id, label: t.label } : {}),
      metadata:  t.metadata || {},
      changes:   t.changes || null,
      eventGroupId,
    })));
  }

  return eventGroupId;
}

/**
 * Legacy shim: the exact signature the ~20 existing call sites use.
 * Keeping it means this change adds coverage without touching working code.
 */
function logActivity(req, actionType, entityType, entityId = null, metadata = null) {
  return log({
    req,
    action:   actionType,
    target:   { type: entityType, id: entityId },
    metadata,
    source:   'core',
  });
}

function stats() {
  return { dropped: droppedCount };
}

// ---------------------------------------------------------------------------
// Schema bootstrap
// ---------------------------------------------------------------------------

/**
 * Idempotent, mirroring ensureEmailOutbox() in src/utils/mailer.js — the
 * config/postgres scripts only run on a fresh volume, so an existing
 * deployment would otherwise never get this table.
 *
 * Keep in sync with front-end/migrations/032_audit_log.sql.
 *
 * Non-fatal by design: a DDL permission problem must degrade to "no audit
 * log", never to "server will not boot".
 */
async function ensureAuditLog() {
  try {
    await cybercoreQuery(`
      CREATE TABLE IF NOT EXISTS cybercore_audit_log (
        audit_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        actor_user_id   UUID,
        actor_email     TEXT,
        actor_role      TEXT,
        actor_type      TEXT NOT NULL DEFAULT 'user'
                        CHECK (actor_type IN ('user','system','anonymous')),
        action          TEXT NOT NULL,
        category        TEXT NOT NULL
                        CHECK (category IN ('auth','user','enrollment','infra','content','config','access')),
        status          TEXT NOT NULL DEFAULT 'success'
                        CHECK (status IN ('success','failure','denied')),
        reason          TEXT,
        target_type     TEXT,
        target_id       TEXT,
        target_label    TEXT,
        target_user_id  UUID,
        event_group_id  UUID,
        source          TEXT NOT NULL DEFAULT 'core'
                        CHECK (source IN ('core','cle','ciab','crucible','system')),
        metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
        changes         JSONB,
        ip_address      INET,
        user_agent      TEXT,
        http_method     TEXT,
        route           TEXT,
        request_id      TEXT
      )`);

    const indexes = [
      `CREATE INDEX IF NOT EXISTS idx_audit_occurred ON cybercore_audit_log (occurred_at DESC, audit_id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_actor ON cybercore_audit_log (actor_user_id, occurred_at DESC) WHERE actor_user_id IS NOT NULL`,
      `CREATE INDEX IF NOT EXISTS idx_audit_target_user ON cybercore_audit_log (target_user_id, occurred_at DESC) WHERE target_user_id IS NOT NULL`,
      `CREATE INDEX IF NOT EXISTS idx_audit_action ON cybercore_audit_log (action, occurred_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_category ON cybercore_audit_log (category, occurred_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_target ON cybercore_audit_log (target_type, target_id) WHERE target_id IS NOT NULL`,
      `CREATE INDEX IF NOT EXISTS idx_audit_not_success ON cybercore_audit_log (occurred_at DESC) WHERE status <> 'success'`,
      `CREATE INDEX IF NOT EXISTS idx_audit_event_group ON cybercore_audit_log (event_group_id) WHERE event_group_id IS NOT NULL`,
      // Arrow form, not `metadata ? 'legacy_id'` — see the note in
      // migrations/032_audit_log.sql. Must stay identical to the migration's
      // predicate or ON CONFLICT cannot infer this index.
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_legacy_id ON cybercore_audit_log ((metadata->>'legacy_id')) WHERE (metadata->>'legacy_id') IS NOT NULL`,
    ];
    for (const sql of indexes) await cybercoreQuery(sql);

    // Own try/catch: nothing else in the repo uses pg_trgm, so the app role
    // may not be allowed to create it. Losing this costs search speed only.
    try {
      await cybercoreQuery(`CREATE EXTENSION IF NOT EXISTS pg_trgm`);
      await cybercoreQuery(`
        CREATE INDEX IF NOT EXISTS idx_audit_search_trgm
          ON cybercore_audit_log USING gin (
            (coalesce(actor_email,'') || ' ' || coalesce(target_label,'') || ' ' ||
             action || ' ' || coalesce(reason,'')) gin_trgm_ops
          )`);
    } catch (err) {
      console.warn('⚠️  Audit search index unavailable (pg_trgm):', err.message);
    }

    console.log('✅ Audit log table ensured');
  } catch (err) {
    console.warn('⚠️  Could not ensure audit log table:', err.message);
  }
}

module.exports = {
  log,
  logMany,
  batch,
  ctx,
  logActivity,
  stats,
  ensureAuditLog,
  // Exported for tests.
  redact,
  sanitizeIp,
  categoryOf,
  LEGACY_ACTION_MAP,
  MAX_FANOUT,
};
