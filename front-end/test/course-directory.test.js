/**
 * course-directory.test.js — core's read-only view of "what courses exist".
 *
 * WHY THIS FILE EXISTS
 * Courses are in cle_db and tickets are in cybercore_db, so core cannot join to
 * them and must ask a registered provider instead. The property that matters is
 * not that the happy path works — it is that EVERY failure of that provider
 * degrades to an empty list rather than an exception. A student whose cle_db is
 * down must still be able to file a ticket with no course attached; if this
 * module ever throws, the support form becomes the thing that breaks when
 * something is already broken.
 *
 * Run: node front-end/test/course-directory.test.js   (or npm test)
 */

const { test, beforeEach } = require('node:test');
const assert = require('assert');
const path = require('path');

const D = require(path.join(__dirname, '..', 'src', 'utils', 'course-directory.js'));

const ROW = { course_id: 'c-1', course_name: 'Security Operations', code: 'CYBR 400', instructor_id: 'u-teach' };
const ROW2 = { course_id: 'c-2', course_name: 'Network Defense', code: 'CYBR 300', instructor_id: 'u-teach' };

const STUDENT = { userId: 'u-stud', role: 'student' };
const TEACHER = { userId: 'u-teach', role: 'instructor' };
const ADMIN = { userId: 'u-admin', role: 'admin' };

/** A provider that answers, so the happy path has something to be. */
function workingProvider(over = {}) {
  return {
    coursesForStudent: async () => [ROW],
    coursesForInstructor: async () => [ROW2],
    describeCourse: async (id) => ([ROW, ROW2].find(r => r.course_id === id) || null),
    ...over,
  };
}

beforeEach(() => D.resetCourseDirectory());

// ── degradation: the reason this module exists ─────────────────────────────

test('with NO provider registered, everything returns empty and nothing throws', async () => {
  assert.strictEqual(D.hasCourseDirectory(), false);
  assert.deepStrictEqual(await D.coursesForStudent('u-stud'), []);
  assert.deepStrictEqual(await D.coursesForInstructor('u-teach'), []);
  assert.strictEqual(await D.describeCourse('c-1'), null);
  assert.strictEqual(await D.isEnrolled('u-stud', 'c-1'), null);
  assert.strictEqual(await D.resolveTicketCourse(STUDENT, 'c-1'), null);
  assert.deepStrictEqual(await D.coursesForTicketForm(STUDENT), []);
});

test('a provider that throws degrades to empty rather than propagating', async () => {
  // This is the cle_db-is-down path. It must not reach the ticket form.
  D.registerCourseDirectory({
    coursesForStudent: async () => { throw new Error('CLE database pool not initialized'); },
    coursesForInstructor: async () => { throw new Error('ECONNREFUSED'); },
    describeCourse: async () => { throw new Error('boom'); },
  });
  assert.deepStrictEqual(await D.coursesForStudent('u-stud'), []);
  assert.deepStrictEqual(await D.coursesForInstructor('u-teach'), []);
  assert.strictEqual(await D.describeCourse('c-1'), null);
  assert.strictEqual(await D.resolveTicketCourse(STUDENT, 'c-1'), null);
});

test('a provider returning null or a non-array degrades to empty', async () => {
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => null,
    coursesForInstructor: async () => 'not an array',
  }));
  assert.deepStrictEqual(await D.coursesForStudent('u-stud'), []);
  assert.deepStrictEqual(await D.coursesForInstructor('u-teach'), []);
});

test('hasCourseDirectory distinguishes "no courses" from "nobody answering"', async () => {
  // The one consequence callers must handle: both produce [], and the UI has to
  // say something different in each case.
  D.registerCourseDirectory(workingProvider({ coursesForStudent: async () => [] }));
  assert.strictEqual(D.hasCourseDirectory(), true);
  assert.deepStrictEqual(await D.coursesForStudent('u-stud'), []);
});

test('a malformed provider is refused loudly at registration', async () => {
  // A boot-time programming error, visible in the log — not a runtime condition.
  assert.throws(() => D.registerCourseDirectory(null), { name: 'TypeError' });
  assert.throws(() => D.registerCourseDirectory({}), { name: 'TypeError' });
  assert.throws(() => D.registerCourseDirectory({ coursesForStudent: async () => [] }),
    { name: 'TypeError' });
  assert.strictEqual(D.hasCourseDirectory(), false);
});

// ── normalization ───────────────────────────────────────────────────────────

test('provider rows are normalized, not spread, into the core shape', async () => {
  // Spreading a cle_course row would publish features, provision_status and
  // dates onto core's wire format and couple it to a plugin's schema.
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => [{ ...ROW, features: { flags: true }, provision_status: 'ready' }],
  }));
  const [c] = await D.coursesForStudent('u-stud');
  assert.deepStrictEqual(Object.keys(c).sort(),
    ['courseCode', 'courseId', 'courseName', 'instructorUserId']);
  assert.deepStrictEqual(c, {
    courseId: 'c-1', courseName: 'Security Operations',
    courseCode: 'CYBR 400', instructorUserId: 'u-teach',
  });
});

test('either naming convention is accepted from a provider', async () => {
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => [{ courseId: 'c-9', courseName: 'X', courseCode: 'Y', instructorUserId: 'u' }],
  }));
  assert.deepStrictEqual(await D.coursesForStudent('u-stud'),
    [{ courseId: 'c-9', courseName: 'X', courseCode: 'Y', instructorUserId: 'u' }]);
});

test('a row with no id is dropped rather than becoming an unusable option', async () => {
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => [ROW, { course_name: 'Orphan' }, null],
  }));
  const out = await D.coursesForStudent('u-stud');
  assert.deepStrictEqual(out.map(c => c.courseId), ['c-1']);
});

test('a missing userId short-circuits without calling the provider', async () => {
  let calls = 0;
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => { calls++; return [ROW]; },
  }));
  assert.deepStrictEqual(await D.coursesForStudent(null), []);
  assert.deepStrictEqual(await D.coursesForStudent(undefined), []);
  assert.strictEqual(calls, 0);
});

// ── enrolment, the authorization-relevant half ─────────────────────────────

test('isEnrolled resolves only courses in the caller\u2019s own enrolled list', async () => {
  D.registerCourseDirectory(workingProvider());
  assert.strictEqual((await D.isEnrolled('u-stud', 'c-1')).courseCode, 'CYBR 400');
  // c-2 is TAUGHT by someone, not enrolled in by this student.
  assert.strictEqual(await D.isEnrolled('u-stud', 'c-2'), null);
  assert.strictEqual(await D.isEnrolled('u-stud', 'c-nonexistent'), null);
  assert.strictEqual(await D.isEnrolled(null, 'c-1'), null);
  assert.strictEqual(await D.isEnrolled('u-stud', null), null);
});

test('a student may only file against a course they are enrolled in', async () => {
  D.registerCourseDirectory(workingProvider());
  assert.strictEqual((await D.resolveTicketCourse(STUDENT, 'c-1')).courseId, 'c-1');
  assert.strictEqual(await D.resolveTicketCourse(STUDENT, 'c-2'), null);
});

test('an instructor may file against a course they TEACH, though not enrolled in it', async () => {
  // "The lab template for CYBR 400 is broken" is a real ticket, and an
  // instructor is never enrolled in their own course — enrollment_role has no
  // 'instructor' value — so isEnrolled() alone would refuse them.
  D.registerCourseDirectory(workingProvider({ coursesForStudent: async () => [] }));
  assert.strictEqual((await D.resolveTicketCourse(TEACHER, 'c-2')).courseId, 'c-2');
  assert.strictEqual(await D.resolveTicketCourse(TEACHER, 'c-1'), null);
});

test('an admin may file against any course', async () => {
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => [], coursesForInstructor: async () => [],
  }));
  assert.strictEqual((await D.resolveTicketCourse(ADMIN, 'c-1')).courseId, 'c-1');
  assert.strictEqual(await D.resolveTicketCourse(ADMIN, 'c-nope'), null);
});

test('resolveTicketCourse refuses a missing user or course', async () => {
  D.registerCourseDirectory(workingProvider());
  assert.strictEqual(await D.resolveTicketCourse(null, 'c-1'), null);
  assert.strictEqual(await D.resolveTicketCourse(STUDENT, null), null);
});

// ── the form's dropdown ────────────────────────────────────────────────────

test('a student sees only their enrolled courses', async () => {
  D.registerCourseDirectory(workingProvider());
  assert.deepStrictEqual((await D.coursesForTicketForm(STUDENT)).map(c => c.courseId), ['c-1']);
});

test('an instructor sees enrolled and taught courses, deduped, enrolled first', async () => {
  D.registerCourseDirectory(workingProvider({
    coursesForStudent: async () => [ROW],
    coursesForInstructor: async () => [ROW, ROW2],   // ROW appears in both
  }));
  const out = await D.coursesForTicketForm(TEACHER);
  assert.deepStrictEqual(out.map(c => c.courseId), ['c-1', 'c-2']);
});

test('the form degrades to an empty list when the directory is unavailable', async () => {
  D.registerCourseDirectory({
    coursesForStudent: async () => { throw new Error('down'); },
    coursesForInstructor: async () => { throw new Error('down'); },
    describeCourse: async () => { throw new Error('down'); },
  });
  assert.deepStrictEqual(await D.coursesForTicketForm(TEACHER), []);
});
