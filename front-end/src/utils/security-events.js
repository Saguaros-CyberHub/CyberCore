'use strict';

// This is the deliberately small SIEM feed, not a copy of application logs or
// audit metadata. Request bodies, headers, query strings and config values must
// never be added here. The host's Wazuh agent reads security-*.jsonl from the
// existing /app/logs bind mount; LOG_LEVEL does not suppress security events.
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTION = /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$/;
const CATEGORIES = new Set(['auth', 'user', 'enrollment', 'infra', 'access', 'content', 'config']);
const ROLES = new Set(['admin', 'instructor', 'student', 'system']);
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const REASONS = new Set(['unknown_user', 'account_disabled', 'bad_password', 'bad_totp',
  'temp_password_expired', 'self_registration_disabled', 'role_denied', 'last_admin',
  'not_course_provisioned', 'self_service', 'group_teardown']);
const NAMESPACES = ['/api/admin', '/api/auth', '/api/cle', '/api/ciab', '/api/crucible',
  '/api/workstations', '/api/caldera-authoring', '/api/caldera-agents', '/api', '/agent'];
const FILE_RE = /^security-(\d{4}-\d{2}-\d{2})\.jsonl$/;

function opaqueId(value) {
  return typeof value === 'string' && UUID.test(value) ? value.toLowerCase() : undefined;
}

function ipAddress(value) {
  if (typeof value !== 'string') return undefined;
  const ip = value.startsWith('::ffff:') ? value.slice(7) : value;
  return net.isIP(ip) ? ip : undefined;
}

function probeReason(req) {
  // Inspect only a bounded pathname and emit a fixed classification, never the
  // hostile string itself. Decoding catches routine percent-encoded probes.
  let value = String(req?.originalUrl || req?.url || '').split(/[?#]/, 1)[0].slice(0, 2048);
  try { value = decodeURIComponent(value); } catch (_) {}
  if (/(?:^|\/)\.env(?:[./]|$)/i.test(value)) return 'probe_environment';
  if (/(?:^|\/)\.(?:git|svn|hg)(?:\/|$)/i.test(value)) return 'probe_vcs';
  if (/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(value)) return 'probe_traversal';
  if (/(?:^|\/)(?:wp-login\.php|xmlrpc\.php|phpmyadmin|vendor\/phpunit|cgi-bin)(?:[/.]|$)/i.test(value)) return 'probe_common_exploit';
  return undefined;
}

function safeRequestPath(req) {
  const probe = probeReason(req);
  if (probe) return `/[${probe}]`;
  const route = req?.route?.path;
  // Express route patterns come from application code. req.baseUrl contains
  // substituted user input on nested routers and must not be used verbatim.
  if (typeof route !== 'string' || route.length > 256 || !/^\/[A-Za-z0-9_/:.*?(){}+\[\]-]*$/.test(route)) {
    return '/[unmatched]';
  }
  const original = String(req.originalUrl || req.url || '').split(/[?#]/, 1)[0];
  const namespace = NAMESPACES.find(n => original === n || original.startsWith(n + '/')) || '';
  return namespace && !route.startsWith(namespace + '/') && route !== namespace ? namespace + route : route;
}

function requestFields(req = {}) {
  return {
    request_id: opaqueId(req.id),
    actor_id: opaqueId(req.user?.userId),
    actor_role: ROLES.has(req.user?.role) ? req.user.role : undefined,
    srcip: ipAddress(req.ip || req.socket?.remoteAddress),
    http_method: METHODS.has(req.method) ? req.method : undefined,
    route: safeRequestPath(req),
  };
}

function buildAuditSummary(evt, canonicalAction, category) {
  const actor = evt?.actor || {};
  const context = evt?.context || {};
  const fields = requestFields(evt?.req);
  if (actor.userId !== undefined) fields.actor_id = opaqueId(actor.userId);
  if (actor.role !== undefined) fields.actor_role = ROLES.has(actor.role) ? actor.role : undefined;
  if (context.ip !== undefined) fields.srcip = ipAddress(context.ip);
  if (!evt?.req) delete fields.route;
  const targetId = evt?.target?.id;
  return {
    cybercore_event: 'audit',
    action: ACTION.test(canonicalAction || '') ? canonicalAction : 'audit.unknown_action',
    category: CATEGORIES.has(category) ? category : 'config',
    outcome: ['failure', 'denied'].includes(evt?.status) ? evt.status : 'success',
    reason: REASONS.has(evt?.reason) ? evt.reason : undefined,
    ...fields,
    event_group_id: opaqueId(evt?.eventGroupId),
    target_id: opaqueId(targetId) || (/^[1-9][0-9]{0,14}$/.test(String(targetId || '')) ? String(targetId) : undefined),
    target_type: typeof evt?.target?.type === 'string' && /^[a-z][a-z0-9_]{0,47}$/.test(evt.target.type) ? evt.target.type : undefined,
  };
}

function auditSummary(evt, canonicalAction, category) {
  try { return buildAuditSummary(evt, canonicalAction, category); } catch (_) {
    return { cybercore_event: 'audit', action: 'audit.invalid_event', category: 'config', outcome: 'failure' };
  }
}

function httpSummary(req, status) {
  const probe = probeReason(req);
  let reason = status >= 500 ? 'server_error' : ({ 401: 'authentication_required',
    403: 'access_denied', 404: 'not_found', 429: 'rate_limited' })[status];
  if (!probe && !reason) return null;
  reason = probe || reason;
  return { cybercore_event: 'http', action: 'http.request', category: 'access',
    outcome: status >= 400 ? 'failure' : 'success', reason, http_status: status,
    ...requestFields(req) };
}

function createWriter({ directory = process.env.LOG_DIR || path.join(process.cwd(), 'logs'),
  now = () => new Date(), maxDailyBytes = 64 * 1024 * 1024,
  retentionDays = 30, warn = () => process.stderr.write('[Security events] File unavailable or capacity exceeded; security events were dropped.\n') } = {}) {
  let date = '', stream, size = 0, paused = false, disabled = false;
  let dropped = 0, warned = false;
  const reservedBytes = Math.min(16 * 1024, Math.floor(maxDailyBytes / 2));
  let healthBytes = 0, lastHealthAt = null;
  function record(fields, stamp) {
    return JSON.stringify({ ...fields, integration: 'cybercore', schema_version: 1,
      event_id: crypto.randomUUID(), timestamp: stamp }) + '\n';
  }
  function drop(reason) {
    dropped++;
    if (!warned) { warned = true; try { warn(); } catch (_) {} }
    // Reserve room in the collected file for loss notifications, including
    // when normal writes hit their daily quota. A stalled buffer can accept
    // only this small, separately bounded reserve. A failed disk cannot; stderr
    // and stats remain the best-effort fallback in that case.
    try {
      if (disabled || !stream) return;
      const stamp = now().toISOString(), millis = Date.parse(stamp);
      if (stamp.slice(0, 10) !== date || (lastHealthAt !== null && millis - lastHealthAt < 3600000)) return;
      const line = record({ cybercore_event: 'health', action: 'telemetry.dropped',
        category: 'config', outcome: 'failure', reason, dropped_count: dropped }, stamp);
      const bytes = Buffer.byteLength(line);
      if (healthBytes + bytes > reservedBytes || size + bytes > maxDailyBytes) return;
      lastHealthAt = millis; healthBytes += bytes; size += bytes;
      stream.write(line);
    } catch (_) {}
  }
  function open(stamp) {
    stream?.end(); stream = undefined;
    date = stamp.slice(0, 10); size = 0; paused = false; disabled = false; warned = false;
    healthBytes = 0; lastHealthAt = null;
    fs.mkdirSync(directory, { recursive: true, mode: 0o750 });
    const target = path.join(directory, `security-${date}.jsonl`);
    const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT |
      fs.constants.O_APPEND | (fs.constants.O_NOFOLLOW || 0), 0o600);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile()) throw new Error('Not regular');
      fs.fchmodSync(fd, 0o600);
      size = stat.size;
      // A maximum-size roster fan-out fits without dropping its target rows.
      // Backpressure still bounds memory under sustained traffic/disk stalls.
      stream = fs.createWriteStream(target, { fd, autoClose: true, highWaterMark: 1024 * 1024 });
    } catch (error) { fs.closeSync(fd); throw error; }
    const opened = stream;
    opened.on('error', () => {
      if (stream === opened) { disabled = true; stream = undefined; }
      drop('file_unavailable');
    });
    // Only our own old, regular daily files are eligible for retention cleanup.
    // No recursive deletion, no symlink following, no other app logs touched.
    const cutoff = Date.parse(date) - retentionDays * 86400000;
    for (const entry of fs.readdirSync(directory)) {
      const match = FILE_RE.exec(entry);
      if (!match || !Number.isFinite(Date.parse(match[1])) || Date.parse(match[1]) >= cutoff) continue;
      try {
        const old = path.join(directory, entry);
        if (fs.lstatSync(old).isFile()) fs.unlinkSync(old);
      } catch (_) {}
    }
  }
  function write(fields) {
    try {
      const stamp = now().toISOString();
      if (date !== stamp.slice(0, 10)) open(stamp);
      if (disabled || !stream) { drop('file_unavailable'); return false; }
      if (paused) { drop('backpressure'); return false; }
      const line = record(fields, stamp);
      const bytes = Buffer.byteLength(line);
      if (bytes > 4096) { drop('event_rejected'); return false; }
      if (size + bytes > maxDailyBytes - reservedBytes) { drop('daily_capacity'); return false; }
      size += bytes;
      if (!stream.write(line)) {
        paused = true;
        const active = stream;
        active.once('drain', () => { if (stream === active) paused = false; });
      }
      return true;
    } catch (_) { disabled = true; drop('file_unavailable'); return false; }
  }
  return { write, stats: () => ({ dropped }), close: () => new Promise(resolve => {
    if (!stream) return resolve();
    stream.end(resolve);
  }) };
}

let writer;
function emit(fields) {
  try { writer ||= createWriter(); return writer.write(fields); } catch (_) { return false; }
}

module.exports = { auditSummary, httpSummary, safeRequestPath, emit, createWriter };
