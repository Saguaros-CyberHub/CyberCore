/**
 * ciab-page-access.test.js — who may load the Clinic-in-a-Box pages.
 *
 * Every /ciab/* page used to be served to ANYONE, unauthenticated included:
 * routes/pages.js registered plain router.get(route, handler) with no
 * middleware at all. /ciab/instructor and /ciab/admin-profile-lanes returned
 * their full shell to a stranger, and the only gate was a client-side
 * Auth.isRealInstructor() redirect the page ran on itself — which is a redirect
 * a page can simply be told not to run.
 *
 * The pages are gated server-side now, in four tiers, and they REDIRECT rather
 * than returning requireRole()'s JSON 403: these are browser navigations, and a
 * raw JSON error body in the window is its own dead end.
 *
 * The assertion most likely to be broken by a future edit is the PUBLIC one.
 * /ciab/real-client-intake loads neither app.js nor layout.js, keeps its answers
 * in localStorage and offers "Download filled form" — it is handed to an outside
 * client who has no account. Gating it would break that workflow and protect
 * nothing, since the page ships no data.
 *
 * Run: node --test "test/*.test.js"
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'ciab-page-access-test-secret';
// Deterministic: the gate must be asked every time, not answered from a cache
// a previous test warmed.
process.env.CIAB_ENROLLMENT_CACHE_MS = '0';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const CIAB = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

let enrolled = false;
let dbError = null;
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async () => {
    if (dbError) throw dbError;
    return enrolled ? { rows: [{ x: 1 }], rowCount: 1 } : { rows: [], rowCount: 0 };
  },
});

const pagesRouter = require(path.join(CIAB, 'routes', 'pages.js'));

const PUBLIC_PAGES = ['/ciab/intake', '/ciab/real-client-intake'];
const STUDENT_PAGES = [
  '/ciab/dashboard', '/ciab/generator', '/ciab/workspace', '/ciab/progress',
  '/ciab/interview', '/ciab/intake-form', '/ciab/guide', '/ciab/nice-framework',
  '/ciab/real-client-intakes', '/ciab/clinic-risk-assessment',
];
const INSTRUCTOR_PAGES = ['/ciab/instructor'];
const ADMIN_PAGES = ['/ciab/admin-profile-lanes'];

let server, port;

before(async () => {
  const app = express();
  app.use(cookieParser());
  app.use('/ciab', pagesRouter);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());

beforeEach(() => { enrolled = false; dbError = null; });

const tokenFor = (role) => jwt.sign({ sub: 'u1', email: 'a@b.c', role }, process.env.JWT_SECRET, { expiresIn: '1h' });

function fetchPage(pagePath, { bearer = null, cookie = null } = {}) {
  const headers = {};
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (cookie) headers.Cookie = `token=${cookie}`;
  return new Promise((resolve, reject) => {
    const req = http.get({ port, path: pagePath, headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location }));
    });
    req.on('error', reject);
  });
}

test('an anonymous visitor is sent to the login page', async () => {
  for (const page of [...STUDENT_PAGES, ...INSTRUCTOR_PAGES, ...ADMIN_PAGES]) {
    const res = await fetchPage(page);
    assert.strictEqual(res.status, 302, `${page} should redirect`);
    assert.strictEqual(res.location, '/login', `${page} should point at /login`);
  }
});

test('the offline intake form stays public — it is handed to people with no account', async () => {
  // It loads neither app.js nor layout.js, keeps answers in localStorage, and
  // offers "Download filled form". Everything it can POST to needs a JWT, so an
  // anonymous visitor can only fill-and-download, which IS the workflow.
  for (const page of PUBLIC_PAGES) {
    const res = await fetchPage(page);
    assert.strictEqual(res.status, 200, `${page} must not be gated`);
  }
});

test('a student on no roster is sent back to the hub, not shown a 403 body', async () => {
  const token = tokenFor('student');
  for (const page of STUDENT_PAGES) {
    const res = await fetchPage(page, { bearer: token });
    assert.strictEqual(res.status, 302, `${page} should redirect a non-enrolled student`);
    assert.strictEqual(res.location, '/hub', `${page} should point at /hub`);
  }
});

test('an enrolled student gets every student page', async () => {
  enrolled = true;
  const token = tokenFor('student');
  for (const page of STUDENT_PAGES) {
    const res = await fetchPage(page, { bearer: token });
    assert.strictEqual(res.status, 200, `${page} should open for an enrolled student`);
  }
});

test('an enrolled student still cannot reach the instructor or admin pages', async () => {
  enrolled = true;
  const token = tokenFor('student');
  for (const page of [...INSTRUCTOR_PAGES, ...ADMIN_PAGES]) {
    const res = await fetchPage(page, { bearer: token });
    assert.strictEqual(res.status, 302, `${page} should refuse a student`);
    assert.strictEqual(res.location, '/hub');
  }
});

test('an instructor gets the instructor page without being enrolled', async () => {
  // Staff pass on role alone — an instructor is not a student of their own
  // course, and requiring them to enrol would be a trap.
  const token = tokenFor('instructor');
  for (const page of [...STUDENT_PAGES, ...INSTRUCTOR_PAGES]) {
    const res = await fetchPage(page, { bearer: token });
    assert.strictEqual(res.status, 200, `${page} should open for an instructor`);
  }
});

test('an instructor is still not an admin', async () => {
  const res = await fetchPage(ADMIN_PAGES[0], { bearer: tokenFor('instructor') });
  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.location, '/hub');
});

test('an admin gets everything', async () => {
  const token = tokenFor('admin');
  for (const page of [...STUDENT_PAGES, ...INSTRUCTOR_PAGES, ...ADMIN_PAGES]) {
    const res = await fetchPage(page, { bearer: token });
    assert.strictEqual(res.status, 200, `${page} should open for an admin`);
  }
});

test('the cookie session is honoured, not just the Authorization header', async () => {
  // The hub signs users in with both; page navigations only carry the cookie.
  enrolled = true;
  const res = await fetchPage('/ciab/dashboard', { cookie: tokenFor('student') });
  assert.strictEqual(res.status, 200);
});

test('a half-finished sign-in cannot reach the pages', async () => {
  // A stage token proves one step of MFA / a forced password change.
  // optionalAuth refuses to treat it as a user, so this must land on /login.
  const stageToken = jwt.sign(
    { sub: 'u1', email: 'a@b.c', role: 'instructor', stage: 'mfa' },
    process.env.JWT_SECRET, { expiresIn: '1h' }
  );
  const res = await fetchPage('/ciab/instructor', { bearer: stageToken });
  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.location, '/login');
});

test('a token signed with the wrong secret is rejected', async () => {
  const forged = jwt.sign({ sub: 'u1', role: 'admin' }, 'not-the-real-secret', { expiresIn: '1h' });
  const res = await fetchPage('/ciab/instructor', { bearer: forged });
  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.location, '/login');
});

test('a database failure fails CLOSED for a student and open for staff', async () => {
  dbError = Object.assign(new Error('relation "ciab_enrollment" does not exist'), { code: '42P01' });
  const student = await fetchPage('/ciab/dashboard', { bearer: tokenFor('student') });
  assert.strictEqual(student.location, '/hub', 'a student must not be let in on an error');

  // Staff never consult the table at all, so an outage cannot lock out the
  // people who would fix it.
  const instructor = await fetchPage('/ciab/instructor', { bearer: tokenFor('instructor') });
  assert.strictEqual(instructor.status, 200);
});

test('the dynamic routes carry the right tiers too', async () => {
  enrolled = true;
  const student = tokenFor('student');
  // A student may read an intake…
  assert.strictEqual((await fetchPage('/ciab/real-client-intake/abc', { bearer: student })).status, 200);
  // …but synthesizing one builds VM specs, so it is instructor-tier.
  const synth = await fetchPage('/ciab/real-client-intake/abc/synthesize', { bearer: student });
  assert.strictEqual(synth.status, 302);
  assert.strictEqual(synth.location, '/hub');
  assert.strictEqual((await fetchPage('/ciab/real-client-intake/abc/synthesize', { bearer: tokenFor('instructor') })).status, 200);
});
