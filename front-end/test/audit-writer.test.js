/**
 * audit-writer.test.js — the write path for cybercore_audit_log.
 *
 * Locks in the properties the old activity_log writer did not have, and the
 * one it did have that must not be lost:
 *
 *   - The actor is SNAPSHOTTED onto the row (email + role, from req.user).
 *     activity_log stored only a user_id, in a different database from
 *     cybercore_user, which is why the admin console rendered every row as
 *     "system" (public/js/admin/admin-activity-log.js:51 read an `email` the
 *     API could not produce).
 *   - There is an explicit-actor form. A failed login has no req.user — it
 *     knows only the string somebody typed — and src/utils/account-provisioning.js
 *     has no `req` at all.
 *   - `category` is DERIVED from the action prefix, never passed in, so it
 *     cannot drift as the vocabulary grows.
 *   - Secrets are stripped in the writer. Call sites must not pass them, but
 *     the audit table is plaintext and adminer is published on 0.0.0.0:8181,
 *     so this is the backstop.
 *   - A failing INSERT NEVER rejects and never throws. The old writer's
 *     comment said "never let logging failures break the main flow"; that
 *     contract now covers a login and a VM deploy, so it is tested.
 *   - Bulk fan-out is ONE statement. A 200-student roster import must not
 *     become 200 round-trips.
 *
 * Run: node front-end/test/audit-writer.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const Module = require('module');

const DB_PATH = path.join(__dirname, '..', 'src', 'utils', 'cybercore-db.js');
const AUDIT_PATH = path.join(__dirname, '..', 'src', 'utils', 'audit.js');

// Captured statements, and a switch to make the next call blow up.
let calls = [];
let failNext = false;

// Intercept the pool module before audit.js requires it, so no connection is
// ever attempted. This mirrors how the repo's other unit tests avoid a live DB.
const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const resolved = (() => {
    try { return Module._resolveFilename(request, parent); } catch { return request; }
  })();
  if (resolved === DB_PATH) {
    return {
      cybercorePool: {},
      cybercoreQuery: async (text, params) => {
        if (failNext) throw new Error('connection refused');
        calls.push({ text, params });
        return { rows: [], rowCount: 0 };
      },
    };
  }
  return realLoad(request, parent, isMain);
};

const audit = require(AUDIT_PATH);
Module._load = realLoad;

/** Column order is fixed by the INSERT; index into a captured params array. */
function col(call, name) {
  const cols = call.text
    .slice(call.text.indexOf('(') + 1, call.text.indexOf(')'))
    .split(',').map(s => s.trim());
  return call.params[cols.indexOf(name)];
}

function reset() { calls = []; failNext = false; }

const REQ = {
  user: { userId: 'u-1', email: 'jane@example.edu', role: 'instructor' },
  ip: '10.0.0.7',
  method: 'POST',
  baseUrl: '/api/cle/courses/c-1/students',
  route: { path: '/' },
  headers: { 'user-agent': 'Mozilla/5.0' },
};

test('the actor is snapshotted from req.user, not left as a bare id', async () => {
  reset();
  await audit.log({ req: REQ, action: 'enrollment.student_added' });

  assert.strictEqual(calls.length, 1);
  assert.strictEqual(col(calls[0], 'actor_user_id'), 'u-1');
  assert.strictEqual(col(calls[0], 'actor_email'), 'jane@example.edu');
  assert.strictEqual(col(calls[0], 'actor_role'), 'instructor');
  assert.strictEqual(col(calls[0], 'actor_type'), 'user');
});

test('request context is captured as a route PATTERN, never the raw URL', async () => {
  reset();
  await audit.log({ req: REQ, action: 'enrollment.student_added' });

  assert.strictEqual(col(calls[0], 'ip_address'), '10.0.0.7');
  assert.strictEqual(col(calls[0], 'http_method'), 'POST');
  // The pattern, so a token in a query string can never reach the table.
  assert.strictEqual(col(calls[0], 'route'), '/api/cle/courses/c-1/students/');
  assert.strictEqual(col(calls[0], 'user_agent'), 'Mozilla/5.0');
});

test('explicit-actor form works with no req at all (failed login)', async () => {
  reset();
  await audit.log({
    actor: { userId: null, email: 'attacker@example.com', type: 'anonymous' },
    action: 'auth.login',
    status: 'failure',
    reason: 'unknown_user',
  });

  assert.strictEqual(col(calls[0], 'actor_user_id'), null);
  assert.strictEqual(col(calls[0], 'actor_email'), 'attacker@example.com');
  assert.strictEqual(col(calls[0], 'actor_type'), 'anonymous');
  assert.strictEqual(col(calls[0], 'status'), 'failure');
  assert.strictEqual(col(calls[0], 'reason'), 'unknown_user');
});

test('a missing actor id defaults actor_type to anonymous, not user', async () => {
  reset();
  await audit.log({ action: 'auth.login', status: 'failure' });
  assert.strictEqual(col(calls[0], 'actor_type'), 'anonymous');
});

test('category is derived from the action prefix and is never a parameter', () => {
  assert.strictEqual(audit.categoryOf('auth.login'), 'auth');
  assert.strictEqual(audit.categoryOf('enrollment.student_added'), 'enrollment');
  assert.strictEqual(audit.categoryOf('lane.deployed'), 'infra');
  assert.strictEqual(audit.categoryOf('vm.script_executed'), 'infra');
  assert.strictEqual(audit.categoryOf('access.console_opened'), 'access');
  assert.strictEqual(audit.categoryOf('config.updated'), 'config');
  // Unknown prefixes are filed, not dropped — a typo must not lose the row.
  assert.strictEqual(audit.categoryOf('wat.nope'), 'config');
});

test('legacy logActivity keeps its signature and maps onto the new vocabulary', async () => {
  reset();
  await audit.logActivity(REQ, 'deploy_lane', 'lane', 'lane-9', { vxlan_id: 42 });

  assert.strictEqual(col(calls[0], 'action'), 'lane.deployed');
  assert.strictEqual(col(calls[0], 'category'), 'infra');
  assert.strictEqual(col(calls[0], 'target_type'), 'lane');
  assert.strictEqual(col(calls[0], 'target_id'), 'lane-9');
  assert.strictEqual(col(calls[0], 'source'), 'core');
  assert.deepStrictEqual(JSON.parse(col(calls[0], 'metadata')), { vxlan_id: 42 });
});

test('every legacy action name maps to a known category', () => {
  for (const [, mapped] of Object.entries(audit.LEGACY_ACTION_MAP)) {
    const category = audit.categoryOf(mapped);
    assert.notStrictEqual(category, undefined, `${mapped} has no category`);
  }
});

test('target_id is stringified, so a Proxmox VMID is not lost', async () => {
  reset();
  // activity_log.entity_id is UUID, so admin/cluster.js:398 passes null for a
  // Ceph volid. This column is TEXT precisely so that stops happening.
  await audit.log({ req: REQ, action: 'vm.destroyed', target: { type: 'vm', id: 10432 } });
  assert.strictEqual(col(calls[0], 'target_id'), '10432');
});

test('secrets are stripped from metadata, recursively', () => {
  const out = audit.redact({
    password: 'hunter2',
    activation_token: 'abc',
    mfa_secret: 'JBSWY3DP',
    nested: { guac_password: 'x', deep: { api_key: 'k' } },
    list: [{ recovery_codes: ['a'] }],
    keep: 'visible',
    count: 3,
  });

  assert.strictEqual(out.password, '[redacted]');
  assert.strictEqual(out.activation_token, '[redacted]');
  assert.strictEqual(out.mfa_secret, '[redacted]');
  assert.strictEqual(out.nested.guac_password, '[redacted]');
  assert.strictEqual(out.nested.deep.api_key, '[redacted]');
  assert.strictEqual(out.list[0].recovery_codes, '[redacted]');
  assert.strictEqual(out.keep, 'visible');
  assert.strictEqual(out.count, 3);
});

test('redaction runs on the way into the INSERT, not just when called directly', async () => {
  reset();
  await audit.log({
    req: REQ,
    action: 'user.created',
    metadata: { email: 'new@example.edu', temp_password: 'hunter2' },
  });
  const meta = JSON.parse(col(calls[0], 'metadata'));
  assert.strictEqual(meta.temp_password, '[redacted]');
  assert.strictEqual(meta.email, 'new@example.edu');
});

test('an unparseable IP becomes NULL rather than an INET cast error', () => {
  assert.strictEqual(audit.sanitizeIp('10.0.0.7'), '10.0.0.7');
  assert.strictEqual(audit.sanitizeIp('::ffff:10.0.0.7'), '10.0.0.7');
  assert.strictEqual(audit.sanitizeIp('fe80::1'), 'fe80::1');
  // A hostile X-Forwarded-For must not be able to break the INSERT.
  assert.strictEqual(audit.sanitizeIp('not-an-ip'), null);
  assert.strictEqual(audit.sanitizeIp(''), null);
  assert.strictEqual(audit.sanitizeIp(undefined), null);
});

test('a failing database write never rejects and never throws', async () => {
  reset();
  failNext = true;
  // The contract the old writer stated and this one has to keep: a login, a
  // deploy or a teardown must not fail because the audit row could not be
  // written.
  await assert.doesNotReject(() => audit.log({ req: REQ, action: 'auth.login' }));
  assert.ok(audit.stats().dropped >= 1, 'the drop should be counted, not silent');
});

test('a failing batch write never rejects either', async () => {
  reset();
  failNext = true;
  await assert.doesNotReject(() => audit.logMany([
    { req: REQ, action: 'user.created' },
    { req: REQ, action: 'user.created' },
  ]));
});

test('logMany emits ONE statement for N rows', async () => {
  reset();
  await audit.logMany([
    { req: REQ, action: 'user.created', targetUser: { id: 's-1', label: 'a@x.edu' } },
    { req: REQ, action: 'user.created', targetUser: { id: 's-2', label: 'b@x.edu' } },
    { req: REQ, action: 'user.created', targetUser: { id: 's-3', label: 'c@x.edu' } },
  ]);

  assert.strictEqual(calls.length, 1, 'a roster import must not be N round-trips');
  // 22 columns x 3 rows.
  assert.strictEqual(calls[0].params.length, 66);
  assert.ok(calls[0].text.includes('$66'));
});

test('batch writes a summary row plus one row per target, sharing an event group', async () => {
  reset();
  await audit.batch({
    req: REQ,
    action: 'enrollment.roster_imported',
    targetAction: 'enrollment.student_added',
    target: { type: 'course', id: 'c-1', label: 'CYBV 480' },
    targets: [
      { id: 's-1', label: 'a@x.edu' },
      { id: 's-2', label: 'b@x.edu' },
    ],
  });

  assert.strictEqual(calls.length, 2, 'one summary INSERT, one fan-out INSERT');
  const summaryGroup = col(calls[0], 'event_group_id');
  assert.ok(summaryGroup, 'the summary row carries an event group');
  assert.strictEqual(col(calls[0], 'action'), 'enrollment.roster_imported');
  assert.strictEqual(JSON.parse(col(calls[0], 'metadata')).affected_count, 2);

  // Per-student rows are what make "which students did this instructor add"
  // answerable by filtering target_user_id.
  const fanout = calls[1];
  assert.strictEqual(fanout.params[5], 'enrollment.student_added');
  assert.ok(fanout.params.includes('s-1'));
  assert.ok(fanout.params.includes('s-2'));
  assert.ok(fanout.params.includes(summaryGroup), 'fan-out shares the summary event group');
});

test('a bulk event beyond the fan-out cap reports the true count and flags truncation', async () => {
  reset();
  const targets = Array.from({ length: audit.MAX_FANOUT + 5 }, (_, i) => ({ id: `s-${i}`, label: `s${i}@x.edu` }));
  await audit.batch({
    req: REQ,
    action: 'user.bulk_deleted',
    targetAction: 'user.deleted',
    targets,
  });

  const meta = JSON.parse(col(calls[0], 'metadata'));
  assert.strictEqual(meta.affected_count, audit.MAX_FANOUT + 5, 'the true count is recorded');
  assert.strictEqual(meta.fanout_truncated, true, 'truncation is visible, not silent');
  assert.strictEqual(meta.fanout_written, audit.MAX_FANOUT);
});

test('batch with no targets still writes the summary row', async () => {
  reset();
  await audit.batch({ req: REQ, action: 'user.bulk_deleted', targetAction: 'user.deleted', targets: [] });
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(JSON.parse(col(calls[0], 'metadata')).affected_count, 0);
});

test('an oversized metadata blob is bounded rather than written whole', async () => {
  reset();
  await audit.log({
    req: REQ,
    action: 'vm.script_executed',
    metadata: { blob: 'x'.repeat(64 * 1024) },
  });
  const raw = col(calls[0], 'metadata');
  assert.ok(raw.length < 20 * 1024, 'the row is bounded');
});
