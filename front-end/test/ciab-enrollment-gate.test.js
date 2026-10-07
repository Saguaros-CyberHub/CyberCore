/**
 * ciab-enrollment-gate.test.js — who may use Clinic-in-a-Box.
 *
 * CIAB used to be open to every authenticated user: routes/pages.js had no
 * middleware at all and the API gate was `authenticateToken` alone, so a valid
 * JWT was full student access to the generator, workspace, interview simulator
 * and risk assessment. Migration 008 introduced sections and enrollments;
 * utils/enrollment.js is what turns them into an access decision.
 *
 * The assertions that carry weight here are the ones that are easy to get
 * subtly wrong:
 *
 *   1. Staff pass with ZERO database calls. A clinic_db outage must not lock
 *      instructors out of the pages they would use to diagnose it.
 *   2. A database error is 503, NOT 403. "You are not enrolled" sends a student
 *      to an instructor who cannot help and tells the client to stop retrying;
 *      it is a different fact from "we could not find out".
 *   3. The lookup joins ciab_section, so archiving a section revokes access.
 *      Without the join, "archive" is a label with no effect.
 *   4. A grant is visible immediately (invalidate()), a revocation within the
 *      TTL. Getting that backwards means an instructor enrolls someone and is
 *      told to wait a minute.
 *
 * No database: utils/db.js is stubbed through require.cache, the same way
 * deploy-targets.test.js does it.
 *
 * Run: node --test "test/*.test.js"
 */

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const CIAB = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'ciab');

let queries = [];
let handler = () => ({ rows: [], rowCount: 0 });

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (sql, params) => {
    queries.push({ sql, params });
    return handler(sql, params) || { rows: [], rowCount: 0 };
  },
});

// Caching is what makes the gate affordable, but it also makes test order
// matter. Pin the TTL high enough to assert reuse and rely on invalidate() /
// invalidateAll() rather than on time passing.
process.env.CIAB_ENROLLMENT_CACHE_MS = '60000';

const enrollment = require(path.join(CIAB, 'utils', 'enrollment.js'));
const { isEnrolled, requireCiabAccess, requireCiabPage, canSeeCiab, invalidateAll } = enrollment;

const STUDENT = { userId: 'stu-1', role: 'student' };
const INSTRUCTOR = { userId: 'ins-1', role: 'instructor' };
const ADMIN = { userId: 'adm-1', role: 'admin' };

/** Minimal express double: records what the handler answered. */
function fakeRes() {
  const res = { statusCode: null, body: null, redirected: null };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; return res; };
  res.redirect = (to) => { res.redirected = to; return res; };
  return res;
}

/** Run a middleware to completion and report which exit it took. */
function run(mw, user, { query = {} } = {}) {
  return new Promise((resolve) => {
    const res = fakeRes();
    let nexted = false;
    const done = () => resolve({ nexted, ...res });
    mw({ user, query }, res, () => { nexted = true; done(); });
    // The gate answers asynchronously on every path that touches the database.
    setTimeout(done, 25);
  });
}

const enrolledHandler = () => ({ rows: [{ '?column?': 1 }], rowCount: 1 });
const notEnrolledHandler = () => ({ rows: [], rowCount: 0 });
const brokenHandler = () => { const e = new Error('relation "ciab_enrollment" does not exist'); e.code = '42P01'; throw e; };

beforeEach(() => {
  queries = [];
  handler = notEnrolledHandler;
  invalidateAll();
  delete process.env.CIAB_ENROLLMENT_ENFORCE;
});

afterEach(() => { delete process.env.CIAB_ENROLLMENT_ENFORCE; });

test('an instructor and an admin pass without touching the database', async () => {
  handler = brokenHandler; // would throw if the gate consulted it
  for (const staff of [INSTRUCTOR, ADMIN]) {
    const r = await run(requireCiabAccess, staff);
    assert.strictEqual(r.nexted, true, `${staff.role} should pass`);
  }
  assert.strictEqual(queries.length, 0, 'staff must not cost a query');
});

test('an enrolled student passes', async () => {
  handler = enrolledHandler;
  const r = await run(requireCiabAccess, STUDENT);
  assert.strictEqual(r.nexted, true);
  assert.strictEqual(queries.length, 1);
});

test('a student on no roster gets 403 with the fix in the body', async () => {
  const r = await run(requireCiabAccess, STUDENT);
  assert.strictEqual(r.nexted, false);
  assert.strictEqual(r.statusCode, 403);
  assert.strictEqual(r.body.code, 'CIAB_NOT_ENROLLED');
  assert.match(r.body.error, /instructor/i, 'tell them who can fix it');
});

test('no token at all is 401, not 403', async () => {
  const r = await run(requireCiabAccess, undefined);
  assert.strictEqual(r.statusCode, 401);
  assert.strictEqual(r.body.code, 'NO_TOKEN');
});

test('a database failure is 503, NOT 403', async () => {
  // The distinction is the whole point: 403 tells a student to go ask an
  // instructor who cannot help, and tells the client not to retry.
  handler = brokenHandler;
  const r = await run(requireCiabAccess, STUDENT);
  assert.strictEqual(r.nexted, false);
  assert.strictEqual(r.statusCode, 503);
  assert.strictEqual(r.body.code, 'CIAB_ACCESS_CHECK_FAILED');
});

test('CIAB_ENROLLMENT_ENFORCE=false is the no-deploy rollback lever', async () => {
  // If migration 008 fails, the loader only warns and every check here throws
  // 42P01. This is what restores service in one restart.
  handler = brokenHandler;
  process.env.CIAB_ENROLLMENT_ENFORCE = 'false';
  const r = await run(requireCiabAccess, STUDENT);
  assert.strictEqual(r.nexted, true);
  assert.strictEqual(queries.length, 1, 'it still tries before giving up');
});

test('the answer is cached, and invalidate() makes a grant visible at once', async () => {
  handler = notEnrolledHandler;
  assert.strictEqual(await isEnrolled('stu-2'), false);
  assert.strictEqual(queries.length, 1);

  // Second read inside the TTL: no query.
  assert.strictEqual(await isEnrolled('stu-2'), false);
  assert.strictEqual(queries.length, 1, 'cached answers must not re-query');

  // An enroll route calls invalidate() on its way out, so the student does not
  // have to wait out the TTL to get in.
  handler = enrolledHandler;
  enrollment.invalidate('stu-2');
  assert.strictEqual(await isEnrolled('stu-2'), true);
  assert.strictEqual(queries.length, 2);
});

test('the lookup joins ciab_section, so archiving revokes access', async () => {
  handler = notEnrolledHandler;
  await isEnrolled('stu-3');
  const { sql } = queries[0];
  assert.match(sql, /ciab_enrollment/, 'reads enrollments');
  assert.match(sql, /JOIN\s+ciab_section/i, 'joins the section');
  assert.match(sql, /e\.status\s*=\s*'active'/, 'only active enrollments');
  assert.match(sql, /s\.status\s*=\s*'active'/, 'only active sections');
});

test('only status=active counts — completed is bookkeeping, not a grant', async () => {
  // Asserted on the SQL rather than on rows because the filter is what carries
  // the rule; a handler returning [] would pass vacuously.
  await isEnrolled('stu-4');
  assert.doesNotMatch(queries[0].sql, /completed/, 'completed must not grant access');
});

// ---------------------------------------------------------------------------
// Page gate — redirects, never a JSON body in the browser window.
// ---------------------------------------------------------------------------

test('an anonymous visitor is sent to /login, everyone else to /hub', async () => {
  assert.strictEqual((await run(requireCiabPage('student'), undefined)).redirected, '/login');
  assert.strictEqual((await run(requireCiabPage('student'), STUDENT)).redirected, '/hub');
});

test('the three page tiers admit exactly who they should', async () => {
  handler = enrolledHandler;
  const tiers = ['student', 'instructor', 'admin'];
  const expected = {
    // enrolled student, instructor, admin
    student:    [true,  true, true],
    instructor: [false, true, true],
    admin:      [false, false, true],
  };
  for (const tier of tiers) {
    const results = [];
    for (const user of [STUDENT, INSTRUCTOR, ADMIN]) {
      results.push((await run(requireCiabPage(tier), user)).nexted);
    }
    assert.deepStrictEqual(results, expected[tier], `tier ${tier}`);
  }
});

test('a page gate that cannot check fails closed', async () => {
  handler = brokenHandler;
  const r = await run(requireCiabPage('student'), STUDENT);
  assert.strictEqual(r.nexted, false);
  assert.strictEqual(r.redirected, '/hub');
});

// ---------------------------------------------------------------------------
// canSeeCiab — the predicate GET /api/modules uses to decide whether the whole
// module appears in the sidebar.
// ---------------------------------------------------------------------------

test('canSeeCiab hides the module from a student on no roster', async () => {
  assert.strictEqual(await canSeeCiab({ user: STUDENT, query: {} }), false);
  handler = enrolledHandler;
  enrollment.invalidateAll();
  assert.strictEqual(await canSeeCiab({ user: STUDENT, query: {} }), true);
});

test('canSeeCiab hides it from an anonymous request', async () => {
  assert.strictEqual(await canSeeCiab({ query: {} }), false);
});

test('canSeeCiab shows it to staff without a query', async () => {
  handler = brokenHandler;
  assert.strictEqual(await canSeeCiab({ user: INSTRUCTOR, query: {} }), true);
  assert.strictEqual(queries.length, 0);
});

test('Student View is judged on enrollment, so the preview stays honest', async () => {
  // ViewMode is a PRESENTATION mode -- "only what is DRAWN changes". An
  // instructor previewing as a student must see the sidebar a real student
  // gets, which for CIAB means being judged on enrollment rather than role.
  handler = notEnrolledHandler;
  assert.strictEqual(
    await canSeeCiab({ user: INSTRUCTOR, query: { view: 'student' } }), false,
    'a previewing instructor who is not enrolled should not see CIAB'
  );
});

test('a database blip during Student View does not blank the menu', async () => {
  handler = brokenHandler;
  assert.strictEqual(await canSeeCiab({ user: ADMIN, query: { view: 'student' } }), true);
});

test('canSeeCiab propagates a failure for a real student, so /api/modules can fail closed', async () => {
  handler = brokenHandler;
  await assert.rejects(() => canSeeCiab({ user: STUDENT, query: {} }), /does not exist/);
});
