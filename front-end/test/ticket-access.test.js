/**
 * ticket-access.test.js — who may read a ticket, and which of its events.
 *
 * This is the security core of the ticket system. Two properties are asserted
 * here and nowhere else in the suite:
 *
 *   1. An internal note never reaches the person who filed the ticket. Staff
 *      annotate tickets for each other, and one leak makes the feature worse
 *      than not having it. The assertions below check the SERIALIZED JSON
 *      STRING, not the array length — a note that survives nested inside some
 *      other field is still a leak, and an array-length check would miss it.
 *
 *   2. An instructor sees their own courses' tickets and no others. Both arms
 *      of that rule are tested separately, because they fail in opposite
 *      directions: the snapshot arm alone locks out a new instructor when a
 *      course changes hands, and the live arm alone locks out the instructor
 *      who was actually Cc'd on the original mail.
 *
 * Run: node front-end/test/ticket-access.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const A = require(path.join(__dirname, '..', 'src', 'utils', 'ticket-access.js'));

const ADMIN      = { userId: 'u-admin',  role: 'admin',      email: 'admin@example.edu' };
const OWNER      = { userId: 'u-teach',  role: 'instructor', email: 'teach@example.edu' };
const NEW_TEACH  = { userId: 'u-teach2', role: 'instructor', email: 'teach2@example.edu' };
const OTHER      = { userId: 'u-other',  role: 'instructor', email: 'other@example.edu' };
const STUDENT    = { userId: 'u-stud',   role: 'student',    email: 'stud@example.edu' };
const STRANGER   = { userId: 'u-nobody', role: 'student',    email: 'nobody@example.edu' };

const TICKET = Object.freeze({
  ticket_id:          't-1',
  ticket_number:      42,
  subject:            'Cannot reach my Kali box',
  body:               'It times out.',
  status:             'open',
  requester_user_id:  'u-stud',
  requester_email:    'stud@example.edu',
  requester_name:     'Sam Student',
  course_id:          'c-1',
  course_name:        'Security Operations',
  course_code:        'CYBR 400',
  instructor_user_id: 'u-teach',
  created_at:         '2026-08-26T10:00:00Z',
  updated_at:         '2026-08-26T10:00:00Z',
});

const EVENTS = Object.freeze([
  { event_id: 'e1', kind: 'created', visibility: 'public',   body: 'It times out.',        created_at: 1 },
  { event_id: 'e2', kind: 'note',    visibility: 'internal', body: 'RADIOACTIVE-NOTE-BODY', author_name: 'Ada Admin', created_at: 2 },
  { event_id: 'e3', kind: 'reply',   visibility: 'public',   body: 'Rebuilding the node.', created_at: 3 },
  { event_id: 'e4', kind: 'status',  visibility: 'public',   from_status: 'open', to_status: 'in_progress', created_at: 4 },
]);

// ── visibility ──────────────────────────────────────────────────────────────

test('an admin can see any ticket', () => {
  assert.ok(A.canSeeTicket(ADMIN, TICKET, []));
  assert.ok(A.canManageTicket(ADMIN, TICKET, []));
});

test('the requester can see their own ticket but cannot manage it', () => {
  assert.ok(A.canSeeTicket(STUDENT, TICKET, []));
  // A student answers via POST /:id/comment, never via reply/note/status.
  assert.ok(!A.canManageTicket(STUDENT, TICKET, []));
});

test('the instructor named on the ticket can see it with no live course list', () => {
  // The snapshot arm on its own. This is the cle_db-is-down path.
  assert.ok(A.canSeeTicket(OWNER, TICKET, []));
  assert.ok(A.canManageTicket(OWNER, TICKET, []));
});

test('an instructor who now teaches the course can see it, though the snapshot names someone else', () => {
  // The live arm on its own — the course changed hands. Without this the new
  // instructor sees nothing at all for a course they are responsible for.
  assert.ok(A.canSeeTicket(NEW_TEACH, TICKET, ['c-1']));
  assert.ok(A.canManageTicket(NEW_TEACH, TICKET, ['c-1']));
});

test('an unrelated instructor is denied', () => {
  assert.ok(!A.canSeeTicket(OTHER, TICKET, ['c-99']));
  assert.ok(!A.canManageTicket(OTHER, TICKET, ['c-99']));
});

test('an unrelated student is denied', () => {
  assert.ok(!A.canSeeTicket(STRANGER, TICKET, []));
});

test('a ticket with no course is visible only to its requester and admins', () => {
  const noCourse = { ...TICKET, course_id: null, instructor_user_id: null };
  assert.ok(A.canSeeTicket(ADMIN, noCourse, []));
  assert.ok(A.canSeeTicket(STUDENT, noCourse, []));
  // An instructor holding an empty course_id must not match on null == null.
  assert.ok(!A.canSeeTicket(OWNER, noCourse, [null]));
  assert.ok(!A.canSeeTicket(OTHER, noCourse, ['c-1']));
});

test('null ids never match each other', () => {
  // The classic hole: a ticket with a null instructor and a user with a null
  // id would both be "equal" under a bare ===.
  const orphan = { ...TICKET, requester_user_id: null, instructor_user_id: null, course_id: null };
  assert.ok(!A.canSeeTicket({ userId: null, role: 'student' }, orphan, []));
  assert.ok(!A.canSeeTicket({ userId: undefined, role: 'instructor' }, orphan, []));
});

test('ids compare across string and non-string types', () => {
  // pg returns UUIDs as strings, but ticket_number-style numeric ids and any
  // future change must not silently deny access.
  const numeric = { ...TICKET, requester_user_id: 7 };
  assert.ok(A.canSeeTicket({ userId: '7', role: 'student' }, numeric, []));
});

test('missing user or ticket is denied, not thrown', () => {
  assert.ok(!A.canSeeTicket(null, TICKET, []));
  assert.ok(!A.canSeeTicket(ADMIN, null, []));
  assert.ok(!A.canSeeTicket(undefined, undefined, undefined));
});

test('a role the system does not know is treated as a student', () => {
  const weird = { userId: 'u-stud', role: 'wizard' };
  assert.ok(A.canSeeTicket(weird, TICKET, []));       // still the requester
  assert.ok(!A.canManageTicket(weird, TICKET, ['c-1'])); // but never staff
});

// ── the leak check ──────────────────────────────────────────────────────────

const NOTE = 'RADIOACTIVE-NOTE-BODY';

test('a student never receives an internal note, in any field, at any depth', () => {
  const payload = {
    ticket: A.serializeTicket(TICKET, STUDENT, []),
    events: A.serializeEvents(EVENTS, STUDENT, TICKET, []),
  };
  // Assert on the SERIALIZED STRING. An array-length check passes even when
  // the body survives nested somewhere else in the response.
  assert.ok(!JSON.stringify(payload).includes(NOTE),
    'the internal note body reached the requester');
  assert.ok(!JSON.stringify(payload).includes('internal'),
    'an internal event survived into the requester payload');
  assert.strictEqual(payload.events.length, 3);
  assert.deepStrictEqual(payload.events.map(e => e.eventId), ['e1', 'e3', 'e4']);
});

test('an unrelated instructor who somehow reaches serialize still gets no note', () => {
  // Defence in depth: even if a route forgets canSeeTicket, the serializer
  // must not hand a non-staff viewer an internal event.
  const out = A.serializeEvents(EVENTS, OTHER, TICKET, ['c-99']);
  assert.ok(!JSON.stringify(out).includes(NOTE));
});

test('an instructor who filed a ticket about their OWN course still sees notes', () => {
  // Both requester and staff. The staff arm must win, or an instructor loses
  // the internal thread on their own course.
  const t = { ...TICKET, requester_user_id: 'u-teach' };
  const out = A.serializeEvents(EVENTS, OWNER, t, []);
  assert.strictEqual(out.length, 4);
  assert.ok(JSON.stringify(out).includes(NOTE));
});

test('staff receive every event', () => {
  for (const [who, taught] of [[ADMIN, []], [OWNER, []], [NEW_TEACH, ['c-1']]]) {
    const out = A.serializeEvents(EVENTS, who, TICKET, taught);
    assert.strictEqual(out.length, 4, `${who.userId} lost an event`);
    assert.ok(JSON.stringify(out).includes(NOTE), `${who.userId} lost the note`);
  }
});

test('visibleEvents never mutates its input', () => {
  const copy = EVENTS.map(e => ({ ...e }));
  A.visibleEvents(copy, STUDENT, TICKET, []);
  assert.strictEqual(copy.length, 4);
  assert.strictEqual(copy[1].body, NOTE);
});

test('a malformed event list degrades to empty rather than throwing', () => {
  assert.deepStrictEqual(A.serializeEvents(null, STUDENT, TICKET, []), []);
  assert.deepStrictEqual(A.serializeEvents(undefined, ADMIN, TICKET, []), []);
  // A null entry must not crash the filter for everyone else.
  const out = A.visibleEvents([null, EVENTS[0]], STUDENT, TICKET, []);
  assert.strictEqual(out.length, 1);
});

test('an event with no explicit visibility is treated as public', () => {
  // Legacy or hand-inserted rows. Defaulting to internal would silently hide
  // a staff reply from the student it was written for.
  const out = A.visibleEvents([{ event_id: 'x', kind: 'reply', body: 'hi' }], STUDENT, TICKET, []);
  assert.strictEqual(out.length, 1);
});

// ── serialization shape ─────────────────────────────────────────────────────

test('serializeTicket whitelists fields — an unknown column cannot leak', () => {
  const withSecret = { ...TICKET, internal_triage_note: NOTE, some_new_column: 'x' };
  const out = A.serializeTicket(withSecret, STUDENT, []);
  assert.ok(!JSON.stringify(out).includes(NOTE));
  assert.ok(!('some_new_column' in out));
  assert.strictEqual(out.subject, 'Cannot reach my Kali box');
  assert.strictEqual(out.ticketNumber, 42);
});

test('canManage travels with the ticket and matches canManageTicket', () => {
  assert.strictEqual(A.serializeTicket(TICKET, ADMIN, []).canManage, true);
  assert.strictEqual(A.serializeTicket(TICKET, OWNER, []).canManage, true);
  assert.strictEqual(A.serializeTicket(TICKET, NEW_TEACH, ['c-1']).canManage, true);
  assert.strictEqual(A.serializeTicket(TICKET, STUDENT, []).canManage, false);
  assert.strictEqual(A.serializeTicket(TICKET, OTHER, ['c-99']).canManage, false);
});

test('numeric columns come back as numbers, not pg bigint strings', () => {
  // ticket_number is BIGINT; node-postgres hands those back as strings, and a
  // string "42" sorts and compares wrongly on the client.
  const out = A.serializeTicket({ ...TICKET, ticket_number: '42', machine_vmid: '601234' }, ADMIN, []);
  assert.strictEqual(out.ticketNumber, 42);
  assert.strictEqual(out.machineVmid, 601234);
});

test('absent optional fields serialize as null, not undefined', () => {
  const bare = { ticket_id: 't', subject: 's', body: 'b', status: 'open', created_at: 1, updated_at: 1 };
  const out = A.serializeTicket(bare, ADMIN, []);
  for (const k of ['courseId', 'courseName', 'laneId', 'machineLabel', 'resolvedAt']) {
    assert.strictEqual(out[k], null, `${k} should be null`);
  }
});
