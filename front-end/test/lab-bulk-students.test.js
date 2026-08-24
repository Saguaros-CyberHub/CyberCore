/**
 * Tests for bulk student operations on an environment (cle/routes/labs.js)
 *
 * The Environments tab renders one card per environment, each with its own
 * student table, so "bulk" here means "several students of ONE lab". What these
 * pin:
 *
 *   parseBulkUserIds — the boundary between a client array and resolveTargetStudents.
 *
 *   The two-level progress keys. A bulk redeploy claims the LAB-scoped key as its
 *     mutex and aggregate, but each student gets their OWN key for the actual
 *     work — because deployVulnLab calls initProgress AND finishProgress on
 *     whatever id it is handed. Sharing the lab key would reset the aggregate
 *     counters on every student and mark the whole batch complete after the
 *     first one. This is the single most likely way the feature breaks, and it
 *     breaks silently: the work still happens, the banner just lies.
 *
 *   Pre-flight-everything-first. A deactivated template or an exhausted VXLAN
 *     block has to fail while the whole class still has working machines, not
 *     after the first eight have been destroyed. That is why planStudentRedeploy
 *     is called for every student before any teardown starts.
 *
 *   The shared helpers. planStudentRedeploy / executeStudentRedeploy exist so the
 *     single-student route and the bulk route cannot drift about what a rebuild
 *     replays — mode, attack box, console VM, extra workstations, flag carry-over.
 *
 * Lifted from the route source by brace-matching rather than requiring the
 * route, which pulls in the Proxmox client and both DB pools at require time.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROUTE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'labs.js'
);
const src = fs.readFileSync(ROUTE, 'utf8');

/**
 * These functions are all top level, so their closing brace is a lone `}` at
 * column 0.
 *
 * Brace-COUNTING from the first `{` is wrong here and fails silently: two of
 * them take a destructured parameter object, whose brace opens before the body's
 * and closes early — truncating the match to just the signature, so every
 * `assert.match` against the body passes vacuously or fails confusingly.
 */
function extractFn(name) {
  let start = src.indexOf(`async function ${name}(`);
  if (start === -1) start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in labs.js — did it get renamed?`);
  // `\n}` alone is not enough: it also matches the `}) {` that closes a
  // destructured parameter list. It has to be a `}` that is the whole line.
  const end = src.search(new RegExp(`\\n\\}\\r?\\n`, 'g')) === -1
    ? -1 : src.slice(start).search(/\n\}\r?\n/) + start;
  assert.notStrictEqual(end, -1, `${name} has no top-level close`);
  return src.slice(start, end + 2);
}

const MAX_BULK_STUDENTS = 50;
// eslint-disable-next-line no-new-func
const parseBulkUserIds = new Function(
  'MAX_BULK_STUDENTS',
  `${extractFn('parseBulkUserIds')} return parseBulkUserIds;`
)(MAX_BULK_STUDENTS);

function handler(pathLiteral) {
  const start = src.indexOf(pathLiteral);
  assert.notStrictEqual(start, -1, `${pathLiteral} not found`);
  const end = src.indexOf('\nrouter.', start + 10);
  return src.slice(start, end === -1 ? src.length : end);
}

// ── parseBulkUserIds ────────────────────────────────────────────────────────

test('a non-array or empty user_ids is a 400', () => {
  for (const body of [{}, { user_ids: [] }, { user_ids: 'abc' }, undefined]) {
    assert.throws(() => parseBulkUserIds(body), (e) => e.status === 400);
  }
});

test('duplicates collapse and blanks are dropped', () => {
  assert.deepStrictEqual(parseBulkUserIds({ user_ids: ['a', 'a', ' b ', ''] }), ['a', 'b']);
});

test('non-string entries are dropped rather than coerced', () => {
  // A coerced 0 or "[object Object]" would be handed to resolveTargetStudents
  // and silently resolve to nothing, which reads as "that student was skipped".
  assert.deepStrictEqual(parseBulkUserIds({ user_ids: ['a', 42, null, {}] }), ['a']);
});

test('an all-invalid list is a 400, not an empty success', () => {
  assert.throws(() => parseBulkUserIds({ user_ids: [null, 7] }), (e) => e.status === 400);
});

test('the cap is a hard 400, never a silent truncation', () => {
  const many = Array.from({ length: MAX_BULK_STUDENTS + 1 }, (_, i) => `u${i}`);
  assert.throws(() => parseBulkUserIds({ user_ids: many }), (e) => {
    assert.strictEqual(e.status, 400);
    assert.match(e.message, /at most 50/);
    return true;
  });
  const atCap = Array.from({ length: MAX_BULK_STUDENTS }, (_, i) => `u${i}`);
  assert.strictEqual(parseBulkUserIds({ user_ids: atCap }).length, MAX_BULK_STUDENTS);
});

// ── the two-level progress keys ─────────────────────────────────────────────

test('bulk redeploy claims the LAB key as its mutex', () => {
  // Group scope conflicts with anything under this lab, which is what stops a
  // per-student Redeploy starting underneath a running batch.
  const h = handler("router.post('/:labId/students/bulk-redeploy'");
  assert.match(h, /assertNoConflictingLabOperation\(\{ materialId: labId, userId: null \}\)/);
  assert.match(h, /claimed = vulnLab\.progressIdForLab\(labId\)/);
});

test('each student in a bulk redeploy gets their OWN progress key', () => {
  // deployVulnLab init/finishes whatever id it is handed. Passing the lab key
  // per student would reset the aggregate counters every time and mark the whole
  // batch complete after the first student — the work would still happen, but
  // the banner would lie.
  const h = handler("router.post('/:labId/students/bulk-redeploy'");
  assert.match(h, /const studentKey = vulnLab\.progressIdForLabStudent\(labId, userId\)/);
  assert.match(h, /progressId: studentKey/);
  assert.ok(!/progressId: claimedId/.test(h),
    'the lab key must never be handed to deployVulnLab — it has to survive the batch');
  // ...and the per-student key is released per student, the lab key once at the end.
  assert.match(h, /finishProgress\(studentKey\)/);
  assert.match(h, /finishProgress\(claimedId\)/);
});

test('bulk teardown claims the same lab-scoped key', () => {
  // One key for both destructive operations, so a teardown and a redeploy cannot
  // run against one environment at the same time.
  const h = handler("router.post('/:labId/students/bulk-remove'");
  assert.match(h, /assertNoConflictingLabOperation\(\{ materialId: labId, userId: null \}\)/);
  assert.match(h, /claimed = vulnLab\.progressIdForLab\(labId\)/);
  assert.match(h, /finally\s*\{[\s\S]*finishProgress\(claimed\)/,
    'a leaked claim 409s every operation on this lab for an hour');
});

// ── pre-flight ordering ─────────────────────────────────────────────────────

test('every student is planned before any teardown starts', () => {
  // The whole point: one deactivated template must fail the request while the
  // class still has machines, not after the first eight are destroyed.
  const h = handler("router.post('/:labId/students/bulk-redeploy'");
  const planAt = h.indexOf('planStudentRedeploy(');
  const claimAt = h.indexOf('assertNoConflictingLabOperation(');
  const workAt = h.indexOf('executeStudentRedeploy(');
  assert.ok(planAt !== -1 && claimAt !== -1 && workAt !== -1);
  assert.ok(planAt < claimAt, 'planning must precede the claim');
  assert.ok(claimAt < workAt, 'the claim must precede any destructive work');
  assert.ok(!/teardownLabForStudent/.test(h.slice(0, planAt)),
    'nothing may be torn down before the plans are built');
});

test('capacity for the whole batch is checked before the claim', () => {
  const h = handler("router.post('/:labId/students/bulk-redeploy'");
  const capAt = h.indexOf('countFreeLanes(');
  const workAt = h.indexOf('executeStudentRedeploy(');
  assert.ok(capAt !== -1 && capAt < workAt,
    'an exhausted block must fail before anything is destroyed');
  // It must account for the lanes the batch itself releases, or a full block
  // would refuse a rebuild that is actually possible.
  assert.match(h, /released/);
});

test('a student who is simply off the roster is skipped, not fatal', () => {
  // One dropped student must not block rebuilding the other twenty-four.
  const h = handler("router.post('/:labId/students/bulk-redeploy'");
  assert.match(h, /if \(e\.status === 404\) skipped\.push/);
  assert.match(h, /else throw e;/);
});

// ── the shared helpers ──────────────────────────────────────────────────────

test('the single-student route goes through the same helpers as the bulk one', () => {
  // If it does not, the two drift about what a rebuild replays — mode, attack
  // box, console VM, extra workstations, flag carry-over — and only one of them
  // gets fixed when that changes.
  const single = handler("router.post('/:labId/students/:userId/redeploy'");
  assert.match(single, /planStudentRedeploy\(/);
  assert.match(single, /executeStudentRedeploy\(/);
});

test('the shared plan still refuses a mode the challenge cannot satisfy', () => {
  const fn = extractFn('planStudentRedeploy');
  assert.match(fn, /can_deploy_lane/);
  assert.match(fn, /can_attach/);
  // And it probes what the student ACTUALLY holds rather than trusting the
  // material's declared mode, which is written once and never updated.
  assert.match(fn, /probeStudentLabMode\(/);
});

test('the shared execute still refuses to build on survivors', () => {
  // Their VMIDs are derived from the VXLAN, so a rebuild would clone straight
  // into machines that are still running.
  const fn = extractFn('executeStudentRedeploy');
  assert.match(fn, /safe_to_redeploy/);
  // Flags carry over by default — the point is to rescue a broken box, not to
  // reset the exercise.
  assert.match(fn, /flag_snapshot/);
  assert.match(fn, /if \(resetFlags\)/);
});
