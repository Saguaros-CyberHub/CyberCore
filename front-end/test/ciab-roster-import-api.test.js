/**
 * ciab-roster-import-api.test.js — the CSV import contract.
 *
 * This is the surface that MINTS ACCOUNTS, so the assertions here are about
 * what must never happen rather than about happy-path shape:
 *
 *  1. A request without `confirm` performs ZERO writes. The preview is the
 *     whole safety mechanism — an instructor sees the seat maths and the
 *     problem rows before 200 accounts exist. Asserted by counting calls to the
 *     provisioning stub, not by reading the response.
 *  2. `confirm: true` re-checks the blocking conditions and 409s. A client that
 *     skips the preview must get no further than one that ran it.
 *  3. One row that throws does not abort a run that has already created
 *     accounts. Without per-row isolation an instructor is left with half a
 *     roster and no record of which half.
 *  4. A password is returned ONLY when the invitation could not be delivered.
 *     Two copies of one secret is strictly worse than one.
 *  5. The audit row contains no password and no token. It exists to explain a
 *     run, and neither of those explains anything.
 *
 * No database, no mail: every dependency is stubbed through require.cache.
 *
 * Run: node --test "test/*.test.js"
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'ciab-roster-import-secret';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const express = require('express');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// ---- state the stubs read and the tests assert on --------------------------
let writes = [];          // every mutating SQL statement
let provisioned = [];     // every account creation attempted
let recordedImports = []; // ciab_roster_import rows
let enrollments = [];     // ciab_enrollment upserts
let section = { section_id: 'sec-1', name: 'CYBR 480', code: 'CYBR-480', max_students: null, status: 'active', instructor_id: 'ins-1' };
let existing = new Map();
let failEmails = new Set();   // emails whose provisioning throws
// Two independent switches, because the code treats them independently:
//   mailConfigured  drives canInvite(), i.e. HOW the account is provisioned
//                   (single-use link, or a temp password that must rotate)
//   mailQueued      drives enqueue()'s result, i.e. whether the password is
//                   disclosed to the instructor afterwards
let mailConfigured = true;
let mailQueued = true;

stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (sql, params) => {
    const s = String(sql);
    if (/^\s*(INSERT|UPDATE|DELETE)/i.test(s)) writes.push({ sql: s, params });
    if (/INSERT INTO ciab_enrollment/i.test(s)) {
      enrollments.push({ userId: params[0], sectionId: params[1] });
      return { rows: [{ enrollment_id: `e-${enrollments.length}` }], rowCount: 1 };
    }
    if (/INSERT INTO ciab_roster_import/i.test(s)) {
      recordedImports.push({ importId: params[0], results: JSON.parse(params[10]) });
      return { rows: [{ import_id: params[0] || 'imp-1', created_at: 'now' }], rowCount: 1 };
    }
    if (/FROM ciab_enrollment WHERE section_id/i.test(s)) return { rows: [], rowCount: 0 };
    if (/COUNT\(\*\)::int AS n FROM ciab_enrollment/i.test(s)) return { rows: [{ n: 0 }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  },
});

stub(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: async () => ({ rows: [] }) });

stub(path.join(CIAB, 'utils', 'enrollment.js'), {
  getManagedSection: async () => section,
  invalidate: () => {},
  invalidateAll: () => {},
  requireCiabAccess: (req, res, next) => next(),
});

stub(path.join(ROOT, 'src', 'utils', 'account-provisioning.js'), {
  normalizeEmail: (e) => String(e || '').trim().toLowerCase(),
  isEmailShaped: (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(e || '')),
  findUsersByEmails: async (emails) => {
    const out = new Map();
    for (const e of emails || []) if (existing.has(e)) out.set(e, existing.get(e));
    return out;
  },
  findUserByEmail: async (e) => existing.get(e) || null,
  findUserById: async () => null,
  backfillMissingName: async () => true,
  isElevatedAccount: (u) => !['student', 'user'].includes(String((u && u.role) || 'student')),
  canManageAccount: () => true,
  assertCourseProvisionedStudent: () => {},
  provisionAccount: async (spec) => {
    provisioned.push(spec);
    if (failEmails.has(spec.email)) throw new Error('username collision after 5 attempts');
    const user = { user_id: `u-${provisioned.length}`, email: spec.email, username: spec.email.split('@')[0], first_name: spec.firstName, last_name: spec.lastName };
    return { user, created: true, username: user.username, password: 'Generated-Pw-1!' };
  },
});

stub(path.join(ROOT, 'src', 'utils', 'activation.js'), {
  issueActivationToken: async () => ({ token: 'tok-secret', expiresAt: 'later' }),
  activationUrl: () => 'https://example.test/activate?token=tok-secret',
  pendingActivationFor: async () => ({}),
});

stub(path.join(ROOT, 'src', 'utils', 'mailer.js'), {
  mailEnabled: () => mailConfigured,
  mailKey: () => (mailConfigured ? 'a-key' : null),
  checkRecipient: () => ({ ok: mailConfigured, reason: 'mail is not configured' }),
  publicUrl: () => 'https://example.test',
  enqueue: async () => (mailQueued ? { status: 'queued' } : { status: 'suppressed', reason: 'mail is off' }),
  statusForImport: async () => [],
});

stub(path.join(ROOT, 'src', 'utils', 'email-templates.js'), {
  activation: () => ({ subject: 's', text: 't', html: '<p>t</p>' }),
  passwordReset: () => ({ subject: 's', text: 't', html: '<p>t</p>' }),
  courseAdded: () => ({ subject: 's', text: 't', html: '<p>t</p>' }),
});

const rosterRouter = require(path.join(CIAB, 'routes', 'section-roster.js'));

let server, port;

before(async () => {
  const app = express();
  app.use((req, res, next) => {
    // The real mount applies authenticateToken + requireCiabAccess above this
    // router and hands :sectionId down through res.locals.
    req.user = { userId: 'ins-1', email: 'ins@x.edu', role: 'instructor' };
    res.locals.sectionId = 'sec-1';
    next();
  });
  app.use('/roster', rosterRouter);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());

beforeEach(() => {
  writes = []; provisioned = []; recordedImports = []; enrollments = [];
  existing = new Map();
  failEmails = new Set();
  mailConfigured = true;
  mailQueued = true;
  section = { section_id: 'sec-1', name: 'CYBR 480', code: 'CYBR-480', max_students: null, status: 'active', instructor_id: 'ins-1' };
});

function post(pathname, body) {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      port, path: pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(raw); } catch (_) { /* not JSON */ }
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

const ROWS = [
  { line: 1, email: 'a@x.edu', first_name: 'A', last_name: 'One' },
  { line: 2, email: 'b@x.edu', first_name: 'B', last_name: 'Two' },
];

test('a preview writes NOTHING and says what would happen', async () => {
  const res = await post('/roster/import', { rows: ROWS });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.preview, true);
  assert.strictEqual(res.json.canProceed, true);
  assert.strictEqual(res.json.summary.will_create, 2);

  // The assertions that actually prove it is a dry run.
  assert.strictEqual(provisioned.length, 0, 'no account may be created by a preview');
  assert.strictEqual(writes.length, 0, 'no row may be written by a preview');
});

test('confirm creates the accounts and enrolls them', async () => {
  const res = await post('/roster/import', { rows: ROWS, confirm: true });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.summary.created, 2);
  assert.strictEqual(res.json.summary.enrolled, 2);
  assert.strictEqual(provisioned.length, 2);
  assert.strictEqual(enrollments.length, 2);
});

test('accounts are stamped with this section, which is what grants credential control later', async () => {
  await post('/roster/import', { rows: ROWS, confirm: true });
  for (const spec of provisioned) {
    assert.strictEqual(spec.provenance.via, 'ciab_import');
    assert.strictEqual(spec.provenance.ref, 'sec-1',
      'provisioned_ref must be the section id — checkCourseProvisionedStudent compares against it');
  }
});

test('confirm re-checks the blocking conditions and 409s', async () => {
  // A client that skips straight to confirm must get no further than one that
  // previewed. Here the seat cap is already full.
  section.max_students = 1;
  const res = await post('/roster/import', { rows: ROWS, confirm: true });
  assert.strictEqual(res.status, 409);
  assert.match(res.json.error, /seats/i);
  assert.strictEqual(provisioned.length, 0, 'a refused run must create nothing');
});

test('an archived section is refused', async () => {
  section.status = 'archived';
  const res = await post('/roster/import', { rows: ROWS, confirm: true });
  assert.strictEqual(res.status, 409);
  assert.match(res.json.error, /archived/i);
});

test('one failing row does not abort a run that already created accounts', async () => {
  // Without per-row isolation the instructor is left with half a roster and no
  // record of which half.
  failEmails.add('b@x.edu');
  const rows = [...ROWS, { line: 3, email: 'c@x.edu' }];
  const res = await post('/roster/import', { rows, confirm: true });

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.summary.created, 2, 'a and c still exist');
  assert.strictEqual(res.json.summary.failed, 1);
  assert.strictEqual(res.json.failed[0].email, 'b@x.edu');
  assert.match(res.json.failed[0].error, /collision/);
});

test('a password is returned ONLY when the invitation could not be delivered', async () => {
  // Two copies of one secret is strictly worse than one. When the invitation
  // reaches a mailbox, the activation link IS the credential and nothing is
  // echoed to the screen.
  mailQueued = true;
  let res = await post('/roster/import', { rows: ROWS, confirm: true });
  assert.ok(res.json.created.every((c) => !('temp_password' in c)),
    'a queued invitation must not also disclose a password');
  assert.ok(res.json.created.every((c) => c.activation_sent === true));

  // Now the same run with mail suppressed: the instructor has to hand the
  // credential over in person, so it must be shown.
  writes = []; provisioned = []; enrollments = []; recordedImports = [];
  mailConfigured = false;
  mailQueued = false;
  res = await post('/roster/import', { rows: ROWS, confirm: true });
  assert.ok(res.json.created.every((c) => c.temp_password === 'Generated-Pw-1!'),
    'a suppressed invitation must disclose the password once');
  assert.ok(res.json.created.every((c) => c.activation_sent === false));
});

test('an undeliverable address is provisioned to rotate and expire', async () => {
  // A credential handed over in person is a different exposure from a
  // single-use link, so it must not live forever.
  //
  // canInvite() is consulted BEFORE the INSERT precisely so the account is
  // provisioned correctly either way, rather than discovering afterwards that
  // nobody could be told.
  mailConfigured = false;
  mailQueued = false;
  await post('/roster/import', { rows: ROWS, confirm: true });
  for (const spec of provisioned) {
    assert.strictEqual(spec.mustChangePassword, true);
    assert.ok(Number(spec.tempPasswordTtlHours) > 0, 'a handed-over password needs a lifetime');
  }
});

test('the audit row carries no password and no token', async () => {
  mailConfigured = false;   // the case where a plaintext password exists at all
  mailQueued = false;
  await post('/roster/import', { rows: ROWS, confirm: true });
  assert.strictEqual(recordedImports.length, 1);

  const blob = JSON.stringify(recordedImports[0].results);
  assert.doesNotMatch(blob, /Generated-Pw-1!/, 'no password may reach the audit row');
  assert.doesNotMatch(blob, /tok-secret/, 'no activation token may reach the audit row');
  assert.doesNotMatch(blob, /password|token|secret/i, 'not even a field named like one');
});

test('the import id is minted before the run, so delivery status is traceable', async () => {
  // mailer.statusForImport() looks the outbox up by context->>'import_id'.
  // Generating the id after the loop — the obvious ordering — would leave
  // GET /email-status permanently empty for exactly the runs that sent mail.
  await post('/roster/import', { rows: ROWS, confirm: true });
  const id = recordedImports[0].importId;
  assert.ok(id, 'an id must be supplied by the route, not defaulted by the database');
  assert.match(id, /^[0-9a-f-]{36}$/i);
});

test('duplicate rows collapse and never race each other into account creation', async () => {
  const rows = [
    { line: 1, email: 'dup@x.edu' },
    { line: 2, email: 'DUP@X.EDU' },
  ];
  const res = await post('/roster/import', { rows, confirm: true });
  assert.strictEqual(provisioned.length, 1, 'one account, not two');
  assert.strictEqual(res.json.summary.skipped, 1);
});

test('an oversized roster is refused before anything is parsed', async () => {
  const rows = Array.from({ length: 501 }, (_, i) => ({ line: i + 1, email: `s${i}@x.edu` }));
  const res = await post('/roster/import', { rows, confirm: true });
  assert.strictEqual(res.status, 400);
  assert.match(res.json.error, /500 rows/);
  assert.strictEqual(provisioned.length, 0);
});

test('an empty body is a 400, not a successful no-op', async () => {
  const res = await post('/roster/import', {});
  assert.strictEqual(res.status, 400);
});
