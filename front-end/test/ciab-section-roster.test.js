/**
 * ciab-section-roster.test.js — the pure logic behind CIAB's roster importer.
 *
 * utils/section-roster.js is a deliberate copy of cle/utils/roster.js with the
 * table names swapped, so the risk is not that it was written wrong — it is that
 * a rule got lost or subtly changed in the copying. These assertions pin the
 * ones that matter:
 *
 *   - duplicates within one file collapse to a SKIP naming the earlier line,
 *     rather than racing each other through account creation
 *   - cohortSlug PRESERVES hyphens, unlike the group-deploy slug that flattens
 *     CYBR-480-7W1 to cybr4807w1 — an instructor reads these off a printed sheet
 *   - generation is RESUMABLE: 25 made and 5 more needed gives 26..30, not a
 *     collision error
 *   - the seat cap is a hard error and archived sections are refused, because
 *     enrolling onto an archived section grants nothing
 *
 * No database: utils/db.js and account-provisioning.js are stubbed through
 * require.cache, the same way deploy-targets.test.js does it.
 *
 * Run: node --test "test/*.test.js"
 */

const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

let dbHandler = () => ({ rows: [], rowCount: 0 });
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (sql, params) => dbHandler(sql, params) || { rows: [], rowCount: 0 },
});

// Only the pieces section-roster.js actually reaches for. The real module talks
// to cybercore_db.
let existingAccounts = new Map();
stub(path.join(ROOT, 'src', 'utils', 'account-provisioning.js'), {
  normalizeEmail: (e) => String(e || '').trim().toLowerCase(),
  isEmailShaped: (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(e || '')),
  findUsersByEmails: async (emails) => {
    const out = new Map();
    for (const e of emails || []) {
      const hit = existingAccounts.get(String(e).toLowerCase());
      if (hit) out.set(String(e).toLowerCase(), hit);
    }
    return out;
  },
  isElevatedAccount: (u) => !['student', 'user'].includes(String((u && u.role) || 'student')),
  canManageAccount: () => true,
});

const roster = require(path.join(CIAB, 'utils', 'section-roster.js'));
const { ACTIONS } = roster;

beforeEach(() => {
  existingAccounts = new Map();
  dbHandler = () => ({ rows: [], rowCount: 0 });
});

// ---------------------------------------------------------------------------
// normalizeRows
// ---------------------------------------------------------------------------

test('a duplicate within one file becomes a SKIP naming the earlier line', () => {
  const rows = roster.normalizeRows([
    { line: 2, email: 'a@x.edu', first_name: 'A' },
    { line: 7, email: 'A@X.EDU', first_name: 'A' },
  ]);
  assert.strictEqual(rows[0].action, undefined, 'the first occurrence is a real row');
  assert.strictEqual(rows[1].action, ACTIONS.SKIP);
  assert.match(rows[1].reason, /duplicate of line 2/);
});

test('an unusable row is INVALID and says which kind', () => {
  const rows = roster.normalizeRows([
    { line: 1, email: '' },
    { line: 2, email: 'not-an-email' },
  ]);
  assert.strictEqual(rows[0].action, ACTIONS.INVALID);
  assert.match(rows[0].reason, /no email/);
  assert.strictEqual(rows[1].action, ACTIONS.INVALID);
  assert.match(rows[1].reason, /valid email/);
});

test('camelCase and snake_case name columns are both accepted', () => {
  // D2L and Canvas exports disagree, and a roster that silently loses every
  // name is the bug the name_backfill path exists to repair afterwards.
  const [a, b] = roster.normalizeRows([
    { line: 1, email: 'a@x.edu', firstName: 'Jamie', lastName: 'Smith' },
    { line: 2, email: 'b@x.edu', first_name: 'Alex', last_name: 'Chen' },
  ]);
  assert.strictEqual(a.first_name, 'Jamie');
  assert.strictEqual(b.last_name, 'Chen');
});

// ---------------------------------------------------------------------------
// classifyRows
// ---------------------------------------------------------------------------

test('classification distinguishes create, enroll, reactivate and already-enrolled', async () => {
  existingAccounts.set('has@x.edu', { user_id: 'u-has', email: 'has@x.edu', role: 'student', first_name: 'H', last_name: 'A' });
  existingAccounts.set('back@x.edu', { user_id: 'u-back', email: 'back@x.edu', role: 'student', first_name: 'B', last_name: 'K' });
  existingAccounts.set('here@x.edu', { user_id: 'u-here', email: 'here@x.edu', role: 'student', first_name: 'H', last_name: 'R' });

  dbHandler = () => ({
    rows: [
      { user_id: 'u-back', status: 'dropped' },
      { user_id: 'u-here', status: 'active' },
    ],
    rowCount: 2,
  });

  const rows = roster.normalizeRows([
    { line: 1, email: 'new@x.edu' },
    { line: 2, email: 'has@x.edu' },
    { line: 3, email: 'back@x.edu' },
    { line: 4, email: 'here@x.edu' },
  ]);
  const out = await roster.classifyRows(rows, 'sec-1', { userId: 'ins-1', role: 'instructor' });

  assert.deepStrictEqual(out.map((r) => r.action), [
    ACTIONS.CREATE, ACTIONS.ENROLL_EXISTING, ACTIONS.REACTIVATE, ACTIONS.ALREADY_ENROLLED,
  ]);
});

test('a staff account is flagged elevated and warned about, not refused', async () => {
  // Enrolling an instructor is normal — staff sit in on courses. What must be
  // visible is that no credential control comes with it.
  existingAccounts.set('prof@x.edu', { user_id: 'u-p', email: 'prof@x.edu', role: 'instructor', first_name: 'P', last_name: 'R' });
  const rows = roster.normalizeRows([{ line: 1, email: 'prof@x.edu' }]);
  const [row] = await roster.classifyRows(rows, 'sec-1', { userId: 'ins-1', role: 'instructor' });
  assert.strictEqual(row.elevated, true);
  assert.match(row.warning, /no password or credential controls/i);
  assert.strictEqual(row.action, ACTIONS.ENROLL_EXISTING, 'still enrolled');
});

test('an existing account with no name is marked for backfill', async () => {
  existingAccounts.set('blank@x.edu', { user_id: 'u-b', email: 'blank@x.edu', role: 'student', first_name: '', last_name: '' });
  const rows = roster.normalizeRows([{ line: 1, email: 'blank@x.edu', first_name: 'Robin', last_name: 'Lee' }]);
  const [row] = await roster.classifyRows(rows, 'sec-1', { userId: 'i', role: 'instructor' });
  assert.strictEqual(row.name_backfill, true);
});

// ---------------------------------------------------------------------------
// Cohort naming and planning
// ---------------------------------------------------------------------------

test('the cohort slug PRESERVES hyphens, unlike the group-deploy slug', () => {
  // admin/groups.js:151 and ciab/routes/profile-deploy.js:330 both strip every
  // non-alphanumeric, turning CYBR-480-7W1 into cybr4807w1. An instructor reads
  // these names off a printed sheet to a student; the hyphens are the only
  // thing that makes them readable aloud.
  assert.strictEqual(roster.cohortSlug({ code: 'CYBR-480-7W1' }), 'cybr-480-7w1');
  assert.strictEqual(roster.cohortSlug({ code: 'CYBR 480' }), 'cybr-480');
  assert.strictEqual(roster.cohortSlug({ code: '  CYBR--480  ' }), 'cybr-480', 'no leading or trailing hyphens');
  assert.strictEqual(roster.cohortSlug({ code: '', name: 'Fall Clinic' }), 'fall-clinic', 'falls back to the name');
  assert.strictEqual(roster.cohortSlug({}), '');
});

test('a section with no code still produces usable names', () => {
  assert.strictEqual(roster.cohortUsername({}, 7), 'student7');
  assert.strictEqual(roster.cohortUsername({ code: 'CYBR-480' }, 7), 'cybr-480-student7');
});

test('generated addresses use a reserved, never-deliverable domain', () => {
  // .invalid is RFC-reserved and mailer.checkRecipient() hard-suppresses it, so
  // a cohort run can never emit a burst of undeliverable credential mail.
  assert.match(roster.cohortEmail({ code: 'CYBR-480' }, 3), /@cohort\.invalid$/);
});

test('cohort generation is resumable — taken numbers are skipped, not fatal', async () => {
  // 25 accounts already exist; asking for 5 more must give 26..30 rather than a
  // collision error, because "make me five more" is the normal second run.
  for (let i = 1; i <= 25; i++) existingAccounts.set(`cybr-480-student${i}@cohort.invalid`, { user_id: `u${i}` });

  const plan = await roster.planCohort({ code: 'CYBR-480' }, { count: 5, startIndex: 1 });
  assert.deepStrictEqual(plan.planned.map((p) => p.index), [26, 27, 28, 29, 30]);
  assert.strictEqual(plan.skipped.length, 25);
  assert.strictEqual(plan.planned[0].username, 'cybr-480-student26');
});

// ---------------------------------------------------------------------------
// Run assessment
// ---------------------------------------------------------------------------

const asIf = (n, action) => Array.from({ length: n }, () => ({ action }));

test('the seat cap is a blocking error that says how to fix it', () => {
  const { errors } = roster.assessRun(asIf(10, ACTIONS.CREATE), { max_students: 25, status: 'active' }, 20);
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /30 of 25 seats/);
  assert.match(errors[0], /Remove 5|raise the seat limit/i);
});

test('no seat limit means no cap', () => {
  const { errors } = roster.assessRun(asIf(400, ACTIONS.CREATE), { max_students: null, status: 'active' }, 0);
  assert.deepStrictEqual(errors, []);
});

test('an archived section refuses enrollment outright', () => {
  // Enrolling onto an archived section grants nothing: the access gate joins
  // ciab_section and requires it to be active. Silently accepting the run would
  // produce a roster full of students who still cannot open anything.
  const { errors } = roster.assessRun(asIf(3, ACTIONS.CREATE), { status: 'archived' }, 0);
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /archived/i);
});

test('already-enrolled rows consume no seat', () => {
  assert.strictEqual(roster.willEnrollCount(asIf(5, ACTIONS.ALREADY_ENROLLED)), 0);
  assert.strictEqual(roster.willEnrollCount(asIf(5, ACTIONS.SKIP)), 0);
  assert.strictEqual(roster.willEnrollCount(asIf(2, ACTIONS.REACTIVATE)), 2, 'a reactivation does');
});

test('elevated accounts and unreadable rows are warnings, never blocks', () => {
  const rows = [
    { action: ACTIONS.ENROLL_EXISTING, elevated: true },
    { action: ACTIONS.INVALID },
  ];
  const { errors, warnings } = roster.assessRun(rows, { status: 'active' }, 0);
  assert.deepStrictEqual(errors, [], 'neither should stop the run');
  assert.strictEqual(warnings.length, 2);
  assert.ok(warnings.some((w) => /staff accounts/i.test(w)));
  assert.ok(warnings.some((w) => /could not be read/i.test(w)));
});
