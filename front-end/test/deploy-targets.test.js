/**
 * Tests for deploy-target resolution (cle/utils/students.js)
 *
 * The bug these pin: an admin could not deploy a workstation or an environment
 * FOR a course's instructor. Both deploy routes exempt a set of ids from the
 * "must be actively enrolled" rule, and that set used to be req.user.userId —
 * the CALLER. An instructor deploying for themselves therefore worked, while an
 * admin doing it for that same instructor exempted the ADMIN's own id, left the
 * instructor to be dropped as 'not enrolled', and 400'd with "No eligible
 * students to provision". courseStaffIds() is the whole rule instead: the caller
 * AND cle_course.instructor_id.
 *
 * The load-bearing assertions here are the ones that keep this from becoming a
 * privilege or a billing surprise rather than a fix:
 *
 *   1. "Deploy Whole Class" must NEVER pick up the exemption. A null
 *      requestedIds means the roster; quietly building the instructor a machine
 *      on every provision-all would consume a lane from the course's reserved
 *      VXLAN block, every time.
 *   2. Exemption is from the ENROLLMENT check only. An exempt id still needs an
 *      email (Guacamole accounts are email-keyed) and is still subject to every
 *      collision exclusion, or a staff deploy could double-book VMIDs.
 *   3. An instructor who IS also enrolled — a TA teaching their own section —
 *      must yield ONE row, not two checkboxes for one person.
 *
 * Nothing here touches a database: both db modules are stubbed through
 * require.cache, the same way roster-classify.test.js does it.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const SRC_UTILS = path.join(__dirname, '..', 'src', 'utils');
const CLE = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle');

let coreHandler = () => ({ rows: [] });
let cleHandler = () => ({ rows: [], rowCount: 0 });

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

stub(path.join(SRC_UTILS, 'cybercore-db.js'), {
  cybercoreQuery: async (sql, params) => coreHandler(sql, params) || { rows: [] },
});
stub(path.join(CLE, 'utils', 'db.js'), {
  query: async (sql, params) => cleHandler(sql, params) || { rows: [], rowCount: 0 },
});

const students = require(path.join(CLE, 'utils', 'students.js'));
const { courseStaffIds, resolveTargetStudents, resolveCourseStaffTargets } = students;

const COURSE_ID = 'course-A';
const INSTRUCTOR = 'inst-1';
const ADMIN = 'adm-1';
const STUDENT = 'stu-1';

const COURSE = { course_id: COURSE_ID, instructor_id: INSTRUCTOR };

/**
 * Wire both stubs. `enrolled` is the set of actively-enrolled user ids, `users`
 * the cybercore_user rows that exist, and `lanes` the ids that already hold a
 * workstation lane in this course.
 */
function given({ enrolled = [], users = [], lanes = [] } = {}) {
  cleHandler = (sql, params) => {
    if (!/FROM cle_course_enrollment/i.test(sql)) return { rows: [], rowCount: 0 };
    // resolveCourseStaffTargets narrows by user_id; resolveTargetStudents does not.
    const scoped = /user_id = ANY/i.test(sql) ? (params[1] || []) : null;
    const rows = enrolled
      .filter(id => !scoped || scoped.includes(id))
      .map(id => ({ user_id: id }));
    return { rows, rowCount: rows.length };
  };
  coreHandler = (sql, params) => {
    if (/FROM cybercore_lane/i.test(sql)) {
      const ids = params[0] || [];
      return { rows: lanes.filter(id => ids.includes(id)).map(id => ({ user_id: id })) };
    }
    if (/FROM cybercore_user/i.test(sql)) {
      const ids = params[0] || [];
      return { rows: users.filter(u => ids.includes(u.user_id)) };
    }
    return { rows: [] };
  };
}

const USER = (id, over = {}) => ({
  user_id: id, email: `${id}@arizona.edu`, first_name: 'First', last_name: 'Last', ...over,
});

// ============================================================================
// courseStaffIds — the definition of "who may be targeted without enrolling"
// ============================================================================

test('courseStaffIds returns the caller AND the course instructor, caller first', () => {
  // Caller-first is not cosmetic: the UI labels the first matching row "you",
  // so reversing this would badge an instructor's own row as someone else's.
  assert.deepStrictEqual(courseStaffIds(COURSE, { userId: ADMIN }), [ADMIN, INSTRUCTOR]);
});

test('courseStaffIds collapses to one id when the caller IS the instructor', () => {
  // Two entries here would offer the instructor two checkboxes for one person.
  assert.deepStrictEqual(courseStaffIds(COURSE, { userId: INSTRUCTOR }), [INSTRUCTOR]);
});

test('courseStaffIds degrades to the caller alone without a course row', () => {
  // A route that selects the course WITHOUT instructor_id must not crash and
  // must not silently exempt undefined — it just loses the instructor.
  assert.deepStrictEqual(courseStaffIds(null, { userId: ADMIN }), [ADMIN]);
  assert.deepStrictEqual(courseStaffIds({ course_id: COURSE_ID }, { userId: ADMIN }), [ADMIN]);
});

test('courseStaffIds never emits a falsy id', () => {
  assert.deepStrictEqual(courseStaffIds({ instructor_id: null }, { userId: null }), []);
});

// ============================================================================
// resolveTargetStudents — the enrollment gate and its exemption
// ============================================================================

test('an admin can target the course instructor once the staff set is passed', async () => {
  given({ enrolled: [STUDENT], users: [USER(INSTRUCTOR), USER(STUDENT)] });

  const { students: got, skipped } = await resolveTargetStudents(
    COURSE_ID, [INSTRUCTOR], { extraUserIds: courseStaffIds(COURSE, { userId: ADMIN }) }
  );

  assert.deepStrictEqual(skipped, []);
  assert.deepStrictEqual(got.map(s => s.id), [INSTRUCTOR]);
  // `enrolled: false` is what keeps them out of the gradebook and out of
  // anything the UI presents as class membership.
  assert.strictEqual(got[0].enrolled, false);
});

test('REGRESSION: the caller-only exemption drops the instructor for an admin', async () => {
  // This is the exact shape of the bug. Kept as a test so the old behaviour
  // cannot quietly return by someone "simplifying" the staff set back to self.
  given({ enrolled: [STUDENT], users: [USER(INSTRUCTOR), USER(ADMIN)] });

  const { students: got, skipped } = await resolveTargetStudents(
    COURSE_ID, [INSTRUCTOR], { extraUserIds: [ADMIN] }
  );

  assert.deepStrictEqual(got, []);
  assert.deepStrictEqual(skipped, [{ student_id: INSTRUCTOR, reason: 'not enrolled' }]);
});

test('the exemption covers exactly the ids passed and nobody else', async () => {
  given({ enrolled: [], users: [USER(INSTRUCTOR), USER('outsider')] });

  const { students: got, skipped } = await resolveTargetStudents(
    COURSE_ID, [INSTRUCTOR, 'outsider'], { extraUserIds: courseStaffIds(COURSE, { userId: ADMIN }) }
  );

  assert.deepStrictEqual(got.map(s => s.id), [INSTRUCTOR]);
  assert.deepStrictEqual(skipped, [{ student_id: 'outsider', reason: 'not enrolled' }]);
});

test('Deploy Whole Class never picks up the exemption', async () => {
  // requestedIds === null means "the roster". If the staff set leaked in here,
  // every provision-all would silently build the instructor another machine and
  // burn a lane from the course's reserved VXLAN block.
  given({ enrolled: [STUDENT], users: [USER(STUDENT), USER(INSTRUCTOR)] });

  const { students: got } = await resolveTargetStudents(
    COURSE_ID, null, { extraUserIds: courseStaffIds(COURSE, { userId: ADMIN }) }
  );

  assert.deepStrictEqual(got.map(s => s.id), [STUDENT]);
});

test('an exempt id still needs an email', async () => {
  // Guacamole accounts are email-keyed: such a machine would come up with no
  // console, so this must fail loudly at selection rather than half-deploy.
  given({ enrolled: [], users: [USER(INSTRUCTOR, { email: null })] });

  const { students: got, skipped } = await resolveTargetStudents(
    COURSE_ID, [INSTRUCTOR], { extraUserIds: courseStaffIds(COURSE, { userId: ADMIN }) }
  );

  assert.deepStrictEqual(got, []);
  assert.deepStrictEqual(skipped, [{ student_id: INSTRUCTOR, reason: 'no email on account' }]);
});

test('collision exclusions still apply to an exempt id', async () => {
  // The instructor already holds a workstation lane on this course. Re-deploying
  // would collide on the gateway/workstation VMIDs for their VXLAN, so the
  // exemption must not carry them past this.
  given({ enrolled: [], users: [USER(INSTRUCTOR)], lanes: [INSTRUCTOR] });

  const { students: got, skipped } = await resolveTargetStudents(
    COURSE_ID, [INSTRUCTOR], {
      excludeIf: students.excludeStudentsWithCourseLane(COURSE_ID),
      extraUserIds: courseStaffIds(COURSE, { userId: ADMIN }),
    }
  );

  assert.deepStrictEqual(got, []);
  assert.deepStrictEqual(skipped, [{ student_id: INSTRUCTOR, reason: 'already has a workstation' }]);
});

// ============================================================================
// resolveCourseStaffTargets — the rows the deploy modals show
// ============================================================================

test('an admin is offered the course instructor, flagged as such and not as self', async () => {
  given({ enrolled: [STUDENT], users: [USER(ADMIN), USER(INSTRUCTOR)] });

  const rows = await resolveCourseStaffTargets(COURSE_ID, { userId: ADMIN }, COURSE);

  assert.deepStrictEqual(rows.map(r => r.user_id), [ADMIN, INSTRUCTOR]);
  assert.deepStrictEqual(
    rows.map(r => ({ self: r.is_self, inst: r.is_course_instructor })),
    [{ self: true, inst: false }, { self: false, inst: true }]
  );
});

test('an instructor viewing their own course gets a single row flagged both ways', async () => {
  given({ enrolled: [STUDENT], users: [USER(INSTRUCTOR)] });

  const rows = await resolveCourseStaffTargets(COURSE_ID, { userId: INSTRUCTOR }, COURSE);

  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].is_self, true);
  assert.strictEqual(rows[0].is_course_instructor, true);
});

test('an already-enrolled instructor is reported enrolled, so the route can drop them', async () => {
  // A TA teaching their own section is in the roster already. The row is
  // returned rather than filtered here — the caller decides — but `enrolled`
  // must be true or they get two checkboxes.
  given({ enrolled: [INSTRUCTOR], users: [USER(INSTRUCTOR)] });

  const rows = await resolveCourseStaffTargets(COURSE_ID, { userId: ADMIN }, COURSE);
  const instructorRow = rows.find(r => r.user_id === INSTRUCTOR);

  assert.strictEqual(instructorRow.enrolled, true);
  assert.strictEqual(rows.filter(r => !r.enrolled).length, 0, 'nothing left to append');
});

test('a staff account with no email is not offered at all', async () => {
  given({ enrolled: [], users: [USER(ADMIN), USER(INSTRUCTOR, { email: '' })] });

  const rows = await resolveCourseStaffTargets(COURSE_ID, { userId: ADMIN }, COURSE);

  assert.deepStrictEqual(rows.map(r => r.user_id), [ADMIN]);
});

test('a course row without instructor_id yields only the caller', async () => {
  given({ enrolled: [], users: [USER(ADMIN), USER(INSTRUCTOR)] });

  const rows = await resolveCourseStaffTargets(COURSE_ID, { userId: ADMIN }, { course_id: COURSE_ID });

  assert.deepStrictEqual(rows.map(r => r.user_id), [ADMIN]);
  assert.strictEqual(rows[0].is_course_instructor, false);
});
