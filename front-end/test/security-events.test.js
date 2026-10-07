'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const security = require('../src/utils/security-events');
const actorId = '01234567-89ab-4def-8123-456789abcdef';
const sentinel = 'DO_NOT_LOG_REAL_CREDENTIAL_FIXTURE';

function request(extra = {}) {
  return { id: actorId, user: { userId: actorId, role: 'admin', email: sentinel },
    ip: '::ffff:192.0.2.8', method: 'POST', originalUrl: '/api/admin/users/123?token=' + sentinel,
    baseUrl: '/api/admin', route: { path: '/users/:id' },
    headers: { authorization: sentinel, cookie: sentinel, 'user-agent': sentinel },
    body: { password: sentinel }, ...extra };
}

test('audit summaries allow only security facts and omit arbitrary metadata, values and credential context', () => {
  const summary = security.auditSummary({ req: request(), action: 'user.updated',
    status: 'denied', reason: 'last_admin', target: { type: 'user', id: actorId, label: sentinel },
    metadata: { harmlessLookingKey: sentinel }, changes: { site_name: { from: sentinel, to: sentinel } } },
  'user.updated', 'user');
  assert.equal(summary.actor_id, actorId);
  assert.equal(summary.actor_role, 'admin');
  assert.equal(summary.srcip, '192.0.2.8');
  assert.equal(summary.route, '/api/admin/users/:id');
  assert.equal(summary.reason, 'last_admin');
  assert.equal(summary.target_id, actorId);
  assert.ok(!JSON.stringify(summary).includes(sentinel));
  assert.equal(summary.user_agent, undefined);
});

test('unknown identifiers, reason strings, roles and IPs are not copied to the SIEM', () => {
  const summary = security.auditSummary({ req: request({ ip: sentinel,
    user: { userId: sentinel, role: sentinel } }), target: { type: 'secret/' + sentinel, id: sentinel },
    reason: sentinel, actor: { email: sentinel }, context: { requestId: sentinel } }, 'bad\n' + sentinel, 'arbitrary');
  assert.equal(summary.action, 'audit.unknown_action');
  for (const field of ['actor_id', 'actor_role', 'srcip', 'target_id', 'target_type', 'reason']) assert.equal(summary[field], undefined);
  assert.ok(!JSON.stringify(summary).includes(sentinel));
});

test('HTTP summaries classify failures and scanners with no raw path, query or nested router values', () => {
  for (const [url, reason] of [
    ['/.env?key=' + sentinel, 'probe_environment'],
    ['/.git/config', 'probe_vcs'], ['/assets/%2e%2e/' + sentinel, 'probe_traversal'],
    ['/wp-login.php?password=' + sentinel, 'probe_common_exploit']
  ]) {
    const summary = security.httpSummary(request({ originalUrl: url, route: undefined }), 404);
    assert.equal(summary.reason, reason);
    assert.ok(!JSON.stringify(summary).includes(sentinel));
  }
  for (const [status, reason] of [[401, 'authentication_required'], [403, 'access_denied'],
    [404, 'not_found'], [429, 'rate_limited'], [503, 'server_error']]) {
    assert.equal(security.httpSummary(request(), status).reason, reason);
  }
  assert.equal(security.httpSummary(request(), 200), null);
  assert.equal(security.safeRequestPath(request({ originalUrl: '/api/cle/courses/' + sentinel,
    baseUrl: '/api/cle/courses/' + sentinel, route: { path: '/students/:id' } })), '/api/cle/students/:id');
  assert.equal(security.safeRequestPath(request({ originalUrl: '/agent/' + sentinel, route: undefined })), '/[unmatched]');
});

function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cybercore-security-test-'));
  t.after(() => {
    for (const entry of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, entry));
    fs.rmdirSync(dir);
  });
  return dir;
}

test('writer emits separate restricted JSON lines, rotates daily, and prunes only owned old files', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'security-2026-01-01.jsonl'), '{}\n');
  fs.writeFileSync(path.join(directory, 'app-2026-01-01.log'), 'leave alone');
  let date = '2026-09-07T00:00:00Z';
  const writer = security.createWriter({ directory, now: () => new Date(date) });
  writer.write({ ...security.httpSummary(request(), 401) });
  date = '2026-09-08T00:00:00Z';
  writer.write({ ...security.auditSummary({ req: request() }, 'config.updated', 'config'), db_recorded: true });
  await writer.close();
  assert.equal(fs.existsSync(path.join(directory, 'security-2026-01-01.jsonl')), false);
  assert.equal(fs.existsSync(path.join(directory, 'app-2026-01-01.log')), true);
  const records = ['07', '08'].map(day => {
    const file = path.join(directory, `security-2026-09-${day}.jsonl`);
    if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    return JSON.parse(lines[0]);
  });
  assert.notEqual(records[0].event_id, records[1].event_id);
  assert.equal(records[0].integration, 'cybercore');
  assert.equal(records[0].schema_version, 1);
  assert.ok(!JSON.stringify(records).includes(sentinel));
});

test('disk caps, malformed events and unavailable storage fail safely without flooding diagnostics', async t => {
  const directory = temporary(t);
  let warnings = 0;
  const writer = security.createWriter({ directory, maxDailyBytes: 1024,
    now: () => new Date('2026-09-07T00:00:00Z'), warn: () => warnings++ });
  const event = { ...security.httpSummary(request(), 401), padding: 'x'.repeat(600) };
  assert.equal(writer.write(event), false);
  assert.equal(writer.write(event), false);
  assert.equal(warnings, 1);
  assert.equal(writer.stats().dropped, 2);
  await writer.close();
  const content = fs.readFileSync(path.join(directory, 'security-2026-09-07.jsonl'), 'utf8');
  assert.ok(Buffer.byteLength(content) <= 1024);
  const health = content.trim().split('\n').map(JSON.parse);
  assert.equal(health.length, 1);
  assert.equal(health[0].cybercore_event, 'health');
  assert.equal(health[0].action, 'telemetry.dropped');
  assert.equal(health[0].reason, 'daily_capacity');
  assert.equal(health[0].dropped_count, 1);
  const file = path.join(directory, 'not-a-directory'); fs.writeFileSync(file, 'x');
  const broken = security.createWriter({ directory: path.join(file, 'child'), warn: () => warnings++ });
  assert.doesNotThrow(() => broken.write({ cybercore_event: 'audit' }));
  assert.equal(broken.stats().dropped, 1);
  await broken.close();
});

test('loss notifications update at most hourly and remain inside the total daily cap', async t => {
  const directory = temporary(t);
  let millis = Date.parse('2026-09-07T00:00:00Z');
  const writer = security.createWriter({ directory, maxDailyBytes: 4096,
    now: () => new Date(millis), warn() {} });
  for (let i = 0; i < 1440; i++) {
    writer.write({ cybercore_event: 'http', padding: 'x'.repeat(3000) });
    millis += 60000;
  }
  await writer.close();
  const content = fs.readFileSync(path.join(directory, 'security-2026-09-07.jsonl'), 'utf8');
  const health = content.trim().split('\n').map(JSON.parse);
  assert.ok(health.length >= 2 && health.length <= 24);
  assert.ok(Buffer.byteLength(content) <= 4096);
  for (let i = 1; i < health.length; i++) {
    assert.ok(Date.parse(health[i].timestamp) - Date.parse(health[i - 1].timestamp) >= 3600000);
    assert.ok(health[i].dropped_count > health[i - 1].dropped_count);
  }
  assert.equal(writer.stats().dropped, 1440);
});

test('a stalled file buffer produces a bounded collected loss notification', async t => {
  const directory = temporary(t);
  const writer = security.createWriter({ directory,
    now: () => new Date('2026-09-07T00:00:00Z'), warn() {} });
  for (let i = 0; i < 5000; i++) writer.write(security.httpSummary(request(), 401));
  assert.ok(writer.stats().dropped > 0);
  await writer.close();
  const content = fs.readFileSync(path.join(directory, 'security-2026-09-07.jsonl'), 'utf8');
  const health = content.trim().split('\n').map(JSON.parse).filter(e => e.cybercore_event === 'health');
  assert.equal(health.length, 1);
  assert.equal(health[0].reason, 'backpressure');
  assert.ok(Buffer.byteLength(content) < 1024 * 1024 + 4096);
});

function load(relative, mocks) {
  const filename = path.join(__dirname, '../src', relative);
  const sandbox = { module: { exports: {} }, console: { error() {}, warn() {} },
    require: name => Object.hasOwn(mocks, name) ? mocks[name] : require(name),
    Date, JSON, Set, Map, Buffer, process };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), sandbox, { filename });
  return sandbox.module.exports;
}

test('audit single and bulk events remain available when database persistence fails', async () => {
  const events = [];
  let fail = false;
  const audit = load('utils/audit.js', {
    './security-events': { ...security, emit: event => events.push(event) },
    './cybercore-db': { cybercoreQuery: async () => { if (fail) throw new Error(sentinel); return { rows: [] }; } }
  });
  await audit.log({ req: request(), action: 'auth.login', status: 'failure', reason: 'bad_password' });
  assert.equal(events[0].db_recorded, true);
  assert.equal(events[0].outcome, 'failure');
  fail = true;
  await audit.log({ req: request(), action: 'settings_update', target: { label: sentinel } });
  await audit.logMany([{ req: request(), action: 'user.created' }, { req: request(), action: 'user.created' }]);
  assert.equal(events.length, 4);
  assert.equal(events[1].action, 'config.updated');
  assert.ok(events.slice(1).every(e => e.db_recorded === false));
  assert.ok(!JSON.stringify(events).includes(sentinel));
  await assert.doesNotReject(() => audit.log({ action: { toString: sentinel } }));
  await assert.doesNotReject(() => audit.log({ action: 'user.created', target: { id: { toString: sentinel } } }));
});

test('request middleware generates local correlation and logs security failures despite regular log filtering', () => {
  const events = [], text = [];
  const logger = load('middleware/request-logger.js', {
    '../utils/security-events': { ...security, emit: e => events.push(e) },
    '../utils/logger': () => ({ http() {}, warn: (line, meta) => text.push({ line, meta }), error() {} })
  });
  const req = request({ id: sentinel });
  const res = new EventEmitter(); res.statusCode = 401;
  let nextCalled = false;
  logger(req, res, () => { nextCalled = true; }); res.emit('finish');
  assert.equal(nextCalled, true);
  assert.match(req.id, /^[0-9a-f-]{36}$/);
  assert.equal(events[0].request_id, req.id);
  assert.equal(events[0].reason, 'authentication_required');
  assert.ok(!JSON.stringify([...events, ...text]).includes(sentinel));
});
