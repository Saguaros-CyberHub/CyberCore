/**
 * lane-credential-instructor-scope.test.js -- an instructor reading THEIR OWN
 * students' machine login, and nobody else's.
 *
 * THE REPORT
 * An instructor clicked the Credentials button on a student's workstation and
 * got "Credentials unavailable -- VM not found or access denied."
 *
 * THE TRAP IN FIXING IT
 * That refusal was deliberate. getLaneWorkstationCredentialForVm scoped to
 * owner-or-admin, and its docblock said reusing the console route's
 * `isPrivileged` (admin OR instructor) test "would let any instructor read any
 * other instructor's students' machines". So the one-line fix -- widening the
 * role test -- is the bug, not the fix, and it is the exact edit a future
 * "simplification" will reach for. Hence the second test.
 *
 * WHAT WAS ACTUALLY MISSING
 * A scope, not a role. `cybercore_lane.config->>'course_id'` says which course a
 * lane was deployed for, and cle_db says which courses a person teaches. The
 * intersection is "my students' machines". Courses live in a DIFFERENT DATABASE
 * (cle_db) from lanes (cybercore_db) with no join available, so this is two
 * queries and the course half goes through utils/course-directory.
 *
 * It discloses nothing new: cle/routes/vms.js GET / is instructorOnly +
 * getManagedCourse and ALREADY returns workstation_pass in plaintext for every
 * lane of a managed course. This reaches the same lanes by the same rule.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

// -- the stubbed cybercore_db -------------------------------------------------
// Recorded, not merely faked: several assertions below are about WHICH queries
// ran and which did not, because "does the common path cross into cle_db" and
// "can a student reach the course arm" are both questions about that.
const queries = [];
let rowsFor = () => [];

const dbPath = require.resolve(path.join(UTILS, 'cybercore-db.js'));
require.cache[dbPath] = {
  id: dbPath, filename: dbPath, loaded: true,
  exports: {
    cybercoreQuery: async (sql, params) => {
      queries.push({ sql, params });
      return { rows: rowsFor(sql, params) || [] };
    },
  },
};

// course-directory is the REAL module -- it has no imports and exposes
// registerCourseDirectory as its seam, so this drives the production path
// rather than a copy of it.
const courseDirectory = require(path.join(UTILS, 'course-directory.js'));
const { getLaneWorkstationCredentialForVm } = require(path.join(UTILS, 'lane-credentials.js'));

const VM = '11111111-1111-4111-8111-111111111111';
const MY_COURSE = 'AAAAAAAA-1111-4111-8111-AAAAAAAAAAAA';   // uppercase on purpose
const OTHER_COURSE = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';
const INSTRUCTOR = 'cccccccc-3333-4333-8333-cccccccccccc';
const STUDENT = 'dddddddd-4444-4444-8444-dddddddddddd';

/** A lane row as the deployers write it, stamped for `courseId`. */
function laneRow(courseId) {
  return {
    provider_vmid: '610581',
    lane_config: {
      cle: true,
      course_id: courseId,
      workstation_user: 'cactus-user',
      workstation_pass: 'STUDENT-PW',
      credentials_source: 'cloudinit',
    },
    vm_name: 'cle-cybr400-581-ws',
    proxmox_name: 'cle-cybr400-581-ws',
    owner_user_id: STUDENT,
  };
}

const isCourseArm = sql => /course_id/.test(sql);

/** Reset, and teach `taught` to the directory. `null` = no provider at all. */
function setup({ taught = [], providerThrows = false } = {}) {
  queries.length = 0;
  rowsFor = () => [];
  courseDirectory.resetCourseDirectory();
  if (taught !== null) {
    courseDirectory.registerCourseDirectory({
      coursesForStudent: async () => [],
      describeCourse: async () => null,
      coursesForInstructor: async () => {
        if (providerThrows) throw new Error('cle_db is down');
        return taught.map(id => ({ course_id: id, course_name: 'A course' }));
      },
    });
  }
}

const asInstructor = () => getLaneWorkstationCredentialForVm(VM, {
  userId: INSTRUCTOR, isAdmin: false, isPrivileged: true, role: 'instructor',
});

// -- the fix ------------------------------------------------------------------

test('THE BUG: an instructor reads the login for a lane in a course they teach', async () => {
  setup({ taught: [MY_COURSE] });
  rowsFor = sql => (isCourseArm(sql) ? [laneRow(MY_COURSE)] : []);

  const cred = await asInstructor();
  assert.ok(cred, 'this is the 404 the instructor reported');
  assert.strictEqual(cred.password, 'STUDENT-PW');
  assert.strictEqual(cred.username, 'cactus-user');
  assert.strictEqual(cred.ownerUserId, STUDENT, 'the owner travels, for the audit row');
});

test('the scope is reported, so an audit row can say HOW it was authorized', async () => {
  setup({ taught: [MY_COURSE] });
  rowsFor = sql => (isCourseArm(sql) ? [laneRow(MY_COURSE)] : []);
  // 'course' is the only scope where the reader is neither the owner nor an
  // admin. If that is not on the row, an investigation cannot find these reads.
  assert.strictEqual((await asInstructor()).via, 'course');
});

// -- the leak that must stay closed -------------------------------------------

test('THE TRAP: an instructor gets NOTHING for another instructor course', async () => {
  // The whole reason the original scope was narrow. If this ever hands back a
  // credential, every instructor on the cluster can read every other
  // instructor's students' machine passwords.
  setup({ taught: [OTHER_COURSE] });
  // The DB answers honestly: the arm binds OTHER_COURSE, the lane is MY_COURSE.
  rowsFor = (sql, params) => {
    if (!isCourseArm(sql)) return [];
    return (params[1] || []).includes(MY_COURSE.toLowerCase()) ? [laneRow(MY_COURSE)] : [];
  };

  assert.strictEqual(await asInstructor(), null);
});

test('the taught courses are BOUND, never interpolated, and carry no enrollment test', async () => {
  setup({ taught: [MY_COURSE, OTHER_COURSE] });
  await asInstructor();

  const arm = queries.find(q => isCourseArm(q.sql));
  assert.ok(arm, 'the course arm must have run');
  assert.match(arm.sql, /= ANY\(\$2::text\[\]\)/, 'bound as a text[] parameter');
  assert.strictEqual(arm.params.length, 2, 'exactly vmId and the course list');
  assert.deepStrictEqual(arm.params[1], [MY_COURSE.toLowerCase(), OTHER_COURSE.toLowerCase()]);
  // Scoped by the LANE's course, not by who is currently enrolled: a lane keeps
  // its course_id after its owner is dropped, and that machine still has to be
  // fixable. It also keeps this arm off cle_course_enrollment, which lives in
  // the other database anyway.
  assert.ok(!/enroll/i.test(arm.sql), 'no enrollment predicate belongs in this query');
});

test('the course arm keeps every guard the owner arm has', async () => {
  setup({ taught: [MY_COURSE] });
  await asInstructor();
  const sql = queries.find(q => isCourseArm(q.sql)).sql;

  // Dropping any of these widens "my students' workstations" quietly.
  assert.match(sql, /vm_category'\s*=\s*'lane_vm'/, 'lane VMs only');
  assert.match(sql, /destroyed_at IS NULL/, 'not a destroyed VM');
  assert.match(sql, /status != 'retired'/, 'not a retired resource');
  assert.match(sql, /EXISTS/, 'the live-lane filter must still apply');
});

// -- case folding: the silent-deny trap ---------------------------------------

test('THE SILENT FAILURE: the uuid comparison is case-folded on BOTH sides', async () => {
  // config->>'course_id' is TEXT holding whatever spelling the caller typed; the
  // provider returns pg's canonical lowercase. A bare `=` between those matches
  // nothing -- an authorization arm that looks implemented and denies every
  // instructor, indistinguishable from the bug it was meant to fix.
  setup({ taught: [MY_COURSE] });
  await asInstructor();

  const arm = queries.find(q => isCourseArm(q.sql));
  assert.match(arm.sql, /lower\(dl\.config->>'course_id'\)/, 'fold the column');
  assert.deepStrictEqual(arm.params[1], [MY_COURSE.toLowerCase()], 'and fold the binds');
});

// -- who never reaches this arm at all ----------------------------------------

test('a student never reaches the course arm', async () => {
  setup({ taught: [MY_COURSE] });

  const cred = await getLaneWorkstationCredentialForVm(VM, {
    userId: STUDENT, isAdmin: false, isPrivileged: false, role: 'student',
  });
  assert.strictEqual(cred, null);
  assert.ok(!queries.some(q => isCourseArm(q.sql)),
    'a student must not be able to drive a course-scoped lookup at all');
});

test('an admin is unchanged and asks cle_db nothing', async () => {
  setup({ taught: [] });
  rowsFor = () => [laneRow(MY_COURSE)];

  const cred = await getLaneWorkstationCredentialForVm(VM, {
    userId: 'admin-id', isAdmin: true, isPrivileged: true, role: 'admin',
  });
  assert.strictEqual(cred.password, 'STUDENT-PW');
  assert.strictEqual(cred.via, 'admin');
  assert.strictEqual(queries.length, 1, 'the admin arm answered; nothing else ran');
});

test('the owner path does not pay for a second database', async () => {
  // Laziness is the design, not an optimisation: the course lookup crosses into
  // cle_db, and a student opening their own machine must never wait for it.
  setup({ taught: [MY_COURSE] });
  rowsFor = () => [laneRow(MY_COURSE)];

  const cred = await getLaneWorkstationCredentialForVm(VM, {
    userId: STUDENT, isAdmin: false, isPrivileged: false, role: 'student',
  });
  assert.strictEqual(cred.via, 'owner');
  assert.strictEqual(queries.length, 1, 'one query, and no course lookup');
});

test('an instructor who owns the machine also skips the course lookup', async () => {
  setup({ taught: [MY_COURSE] });
  rowsFor = () => [laneRow(MY_COURSE)];
  const cred = await asInstructor();
  assert.strictEqual(cred.via, 'owner');
  assert.ok(!queries.some(q => isCourseArm(q.sql)), 'no cle_db round trip when arm 1 matched');
});

// -- failure policy -----------------------------------------------------------

test('a cle_db outage DENIES rather than grants', async () => {
  setup({ taught: [], providerThrows: true });
  rowsFor = sql => (isCourseArm(sql) ? [laneRow(MY_COURSE)] : []);

  // course-directory's safely() turns the throw into [], and an empty taught
  // list must mean "prove nothing", never "skip the check". Fail-closed is the
  // only correct direction for an authorization predicate, and it is also the
  // pre-change behaviour, so an outage is a non-event rather than a regression.
  assert.strictEqual(await asInstructor(), null);
  assert.ok(!queries.some(q => isCourseArm(q.sql)),
    'with no taught courses there is nothing to ask the database');
});

test('no course directory registered at all also denies', async () => {
  setup({ taught: null });
  rowsFor = sql => (isCourseArm(sql) ? [laneRow(MY_COURSE)] : []);
  assert.strictEqual(await asInstructor(), null);
});

test('an instructor who teaches nothing issues no course query', async () => {
  setup({ taught: [] });
  rowsFor = sql => (isCourseArm(sql) ? [laneRow(MY_COURSE)] : []);
  assert.strictEqual(await asInstructor(), null);
  assert.ok(!queries.some(q => isCourseArm(q.sql)));
});

// -- the shared helper --------------------------------------------------------

test('courseIdsForInstructor returns ids UNFOLDED, and nothing for a student', async () => {
  setup({ taught: [MY_COURSE] });
  // Folding here would break ticket scoping: utils/ticket-access.sameId compares
  // with String(a) === String(b), exactly. Case handling belongs at the SQL call
  // site, on both sides, which is where this fix put it.
  assert.deepStrictEqual(
    await courseDirectory.courseIdsForInstructor({ userId: INSTRUCTOR, role: 'instructor' }),
    [MY_COURSE]);
  assert.deepStrictEqual(
    await courseDirectory.courseIdsForInstructor({ userId: STUDENT, role: 'student' }), [],
    'a student must not be able to make this cross into cle_db');
  assert.deepStrictEqual(await courseDirectory.courseIdsForInstructor(null), []);
});
