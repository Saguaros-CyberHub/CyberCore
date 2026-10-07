/**
 * hub-course-overview.test.js — what the CyberHub home page shows, and to whom.
 *
 * The landing page used to be a grid of module cards, which the left sidebar
 * already listed. It now shows the courses a person is actually involved in —
 * and "involved in" means two different tables. A student is a row in
 * cle_course_enrollment; a professor is the scalar cle_course.instructor_id and
 * is NOT enrolled in the course they run. Merging those two is the whole job of
 * buildOverviewCards(), and the merge has three ways to go wrong:
 *
 *   1. A person who is both (a TA teaching their own section) shows up twice.
 *   2. A course gets silently dropped. GET /api/cle/my/courses does exactly this
 *      — it filters to courses with the Flags feature on, which is correct for a
 *      flag board and wrong for a home page. A CYBR 400 student would see an
 *      empty page and no error.
 *   3. A student's card leaks the class roster size or the course's cluster
 *      footprint. This endpoint has no role gate of its own — /api/cle/my is
 *      mounted with authenticateToken and nothing else, because it is
 *      self-scoped — so the shaping function is where that line is held.
 *
 * cardTarget() is the other half: where a card goes when clicked. A student
 * course with Flags off has no flag board, and an earlier design left that card
 * inert. It must still have somewhere to go.
 *
 * Both are pure over plain objects, so this runs with no database and no browser.
 *
 * Run: node --test front-end/test/hub-course-overview.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const { buildOverviewCards } = require(path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils', 'course-overview.js'
));

// hub-courses.js is a browser file, but its IIFE only defines functions at load
// time and it exports itself under a `typeof module` guard, so it requires here.
const { cardTarget } = require(path.join(__dirname, '..', 'public', 'js', 'hub-courses.js'));

// ---------------------------------------------------------------------------
// Fixtures. `code` matters: course-features.js defaults Flags on for CYBR480*
// and Attack Console on for CYBR400*, so the codes below pick the feature set.
// ---------------------------------------------------------------------------

const enrolledFlags = {
  course_id: 'c-480', course_name: 'Offensive Security', code: 'CYBR-480-7W1-1',
  is_active: true, instructor_id: 'prof-1', enrollment_role: 'student',
};
const enrolledNoFlags = {
  course_id: 'c-400', course_name: 'Network Defense', code: 'CYBR-400-1',
  is_active: true, instructor_id: 'prof-1', enrollment_role: 'student',
};
const taught = {
  course_id: 'c-teach', course_name: 'Digital Forensics', code: 'CYBR-310-1',
  is_active: true, instructor_id: 'me', student_count: 28,
};

const byId = (cards) => Object.fromEntries(cards.map(c => [c.courseId, c]));

// ---------------------------------------------------------------------------
// A person who is both enrolled and the instructor
// ---------------------------------------------------------------------------

test('enrolled + taught on the same course collapses to one instructor card', () => {
  const both = { ...taught, course_id: 'c-dual' };
  const cards = buildOverviewCards({
    enrolled: [{ ...both, enrollment_role: 'ta' }],
    taught: [both],
  });

  assert.strictEqual(cards.length, 1, 'the course must not appear twice');
  assert.strictEqual(cards[0].relationship, 'instructor', 'instructor wins the duplicate');
  assert.strictEqual(cards[0].alsoEnrolled, true);
  assert.strictEqual(cards[0].enrollmentRole, 'ta',
    'the TA badge survives even though the relationship is instructor');
});

test('a plain enrolled course is a student card, a plain taught course is not', () => {
  const cards = byId(buildOverviewCards({ enrolled: [enrolledFlags], taught: [taught] }));
  assert.strictEqual(cards['c-480'].relationship, 'student');
  assert.strictEqual(cards['c-480'].alsoEnrolled, false);
  assert.strictEqual(cards['c-teach'].relationship, 'instructor');
  assert.strictEqual(cards['c-teach'].enrollmentRole, null);
});

// ---------------------------------------------------------------------------
// Nothing is silently dropped — the bug the old endpoint has
// ---------------------------------------------------------------------------

test('a course with Flags off still gets a card', () => {
  const cards = buildOverviewCards({ enrolled: [enrolledFlags, enrolledNoFlags] });
  assert.strictEqual(cards.length, 2);
  const map = byId(cards);
  assert.strictEqual(map['c-400'].features.flags, false, 'CYBR400 defaults Flags off');
  assert.ok(map['c-400'], 'and it is STILL listed — this is the whole point');
});

test('a Flags-off course reports no flag progress rather than a fake 0 / 0', () => {
  const cards = byId(buildOverviewCards({ enrolled: [enrolledNoFlags] }));
  assert.strictEqual(cards['c-400'].flags, null);
});

test('a Flags-on student course reports captured / total / machineCount', () => {
  const cards = byId(buildOverviewCards({
    enrolled: [enrolledFlags],
    byCourse: {
      'c-480': [
        { captured_at: '2026-01-01', lane_id: 'L1', vm_name: 'web01' },
        { captured_at: null,         lane_id: 'L1', vm_name: 'web01' },
        { captured_at: null,         lane_id: 'L1', vm_name: 'db01'  },
      ],
    },
  }));
  assert.deepStrictEqual(cards['c-480'].flags, { captured: 1, total: 3, machineCount: 2 });
});

// ---------------------------------------------------------------------------
// A student card must not leak the roster size or the cluster footprint
// ---------------------------------------------------------------------------

test('studentCount and vmCount are null on every student card', () => {
  const cards = buildOverviewCards({
    enrolled: [{ ...enrolledFlags, student_count: 99 }],
    laneCounts: { 'c-480': 42 },
  });
  assert.strictEqual(cards[0].relationship, 'student');
  assert.strictEqual(cards[0].studentCount, null,
    'a student must not learn their class size from their own home page');
  assert.strictEqual(cards[0].vmCount, null);
});

test('an instructor card carries the counts a student card withholds', () => {
  const cards = buildOverviewCards({ taught: [taught], laneCounts: { 'c-teach': 56 } });
  assert.strictEqual(cards[0].studentCount, 28);
  assert.strictEqual(cards[0].vmCount, 56);
});

test('an instructor card with no lanes reports 0, not null', () => {
  const cards = buildOverviewCards({ taught: [{ ...taught, student_count: 0 }] });
  assert.strictEqual(cards[0].studentCount, 0);
  assert.strictEqual(cards[0].vmCount, 0);
});

// ---------------------------------------------------------------------------
// Instructor names come from the OTHER database, so they can be missing
// ---------------------------------------------------------------------------

test('the instructor name resolves, falls back to email, then to null', () => {
  const resolved = buildOverviewCards({
    enrolled: [enrolledFlags],
    instructors: { 'prof-1': { userId: 'prof-1', name: 'Jane Doe', email: 'j@x.edu' } },
  });
  assert.strictEqual(resolved[0].instructor.name, 'Jane Doe');

  // cybercore_db unreachable: loadInstructorProfiles resolves to {}, and the
  // page must lose a NAME, not the card.
  const missing = buildOverviewCards({ enrolled: [enrolledFlags], instructors: {} });
  assert.strictEqual(missing[0].instructor, null);
  assert.strictEqual(missing[0].courseName, 'Offensive Security');
});

// ---------------------------------------------------------------------------
// Ordering and defaults
// ---------------------------------------------------------------------------

test('active courses sort ahead of archived, instructor rows ahead of student', () => {
  const cards = buildOverviewCards({
    enrolled: [
      { ...enrolledFlags, course_id: 'z-archived', course_name: 'Zulu', is_active: false },
      { ...enrolledFlags, course_id: 'a-student',  course_name: 'Alpha' },
    ],
    taught: [{ ...taught, course_id: 'm-teach', course_name: 'Mike' }],
  });
  assert.deepStrictEqual(cards.map(c => c.courseId), ['m-teach', 'a-student', 'z-archived']);
});

test('missing optional columns fall back rather than emitting undefined', () => {
  const [card] = buildOverviewCards({ enrolled: [{ course_id: 'x', course_name: 'X' }] });
  assert.strictEqual(card.code, null);
  assert.strictEqual(card.description, null);
  assert.strictEqual(card.startDate, null);
  assert.strictEqual(card.endDate, null);
  // There is no term/semester column in cle_course; a course with no dates is
  // normal, because POST /courses never sets them.
  assert.strictEqual(card.isActive, true, 'absent is_active means active');
  assert.strictEqual(card.provisionStatus, 'ready');
  assert.strictEqual(card.assignmentCount, 0);
});

test('assignment counts come from the published-material map', () => {
  const cards = byId(buildOverviewCards({
    enrolled: [enrolledFlags, enrolledNoFlags],
    assignments: { 'c-400': [{ material_id: 'm1' }, { material_id: 'm2' }] },
  }));
  assert.strictEqual(cards['c-400'].assignmentCount, 2);
  assert.strictEqual(cards['c-480'].assignmentCount, 0);
});

test('no input at all is an empty list, not a throw', () => {
  assert.deepStrictEqual(buildOverviewCards(), []);
  assert.deepStrictEqual(buildOverviewCards({}), []);
});

// ---------------------------------------------------------------------------
// Where a card goes when it is clicked
// ---------------------------------------------------------------------------

test('an instructor card links to that course on the management page', () => {
  const t = cardTarget({ relationship: 'instructor', courseId: 'abc-123' });
  assert.strictEqual(t.kind, 'link');
  assert.strictEqual(t.href, '/cle/courses?course=abc-123');
  assert.strictEqual(t.label, 'Manage course');
});

test('the deep-link id is URL-encoded', () => {
  const t = cardTarget({ relationship: 'instructor', courseId: 'a b&c' });
  assert.strictEqual(t.href, '/cle/courses?course=a%20b%26c');
});

test('a student card opens in place, never leaving the hub', () => {
  const t = cardTarget({ relationship: 'student', courseId: 'c-480', features: { flags: true } });
  assert.strictEqual(t.kind, 'inline');
  assert.strictEqual(t.courseId, 'c-480');
  assert.strictEqual(t.label, 'Open flag board');
});

test('a student card for a Flags-off course is still openable', () => {
  // The failure this pins: an inert card. GET /api/cle/my/courses/:courseId
  // serves a course with no board, so there is always somewhere to go.
  const t = cardTarget({ relationship: 'student', courseId: 'c-400', features: { flags: false } });
  assert.strictEqual(t.kind, 'inline');
  assert.strictEqual(t.courseId, 'c-400');
  assert.strictEqual(t.label, 'View course');
});

test('every card built by buildOverviewCards has a usable target', () => {
  const cards = buildOverviewCards({
    enrolled: [enrolledFlags, enrolledNoFlags],
    taught: [taught],
  });
  for (const c of cards) {
    const t = cardTarget(c);
    assert.ok(t && (t.kind === 'link' || t.kind === 'inline'), `${c.courseId} has no target`);
    assert.ok(t.label, `${c.courseId} has no label`);
    if (t.kind === 'link') assert.ok(t.href.includes(c.courseId));
    else assert.strictEqual(t.courseId, c.courseId);
  }
});
