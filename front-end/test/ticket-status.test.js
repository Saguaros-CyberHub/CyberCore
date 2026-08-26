/**
 * ticket-status.test.js — the ticket status vocabulary.
 *
 * The list of status names appears in the CHECK constraint, the PATCH
 * validator, the Admin page's filter chips, and the status-change email's
 * subject line. lane-claims.js exists because one predicate was spelled six
 * ways across the codebase and two spellings were wrong in opposite
 * directions; this file is the same guard applied to this list before it can
 * happen again.
 *
 * Run: node front-end/test/ticket-status.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const S = require(path.join(__dirname, '..', 'src', 'utils', 'ticket-status.js'));

// ── vocabulary ──────────────────────────────────────────────────────────────

test('the status list matches the CHECK constraint, in workflow order', () => {
  assert.deepStrictEqual(
    [...S.TICKET_STATUSES],
    ['open', 'in_progress', 'pending', 'resolved', 'closed']
  );
});

test('active and terminal statuses partition the list exactly', () => {
  // A status in neither bucket would vanish from the Admin page's default
  // filter without ever appearing under "closed" — invisible work.
  const union = [...S.ACTIVE_STATUSES, ...S.TERMINAL_STATUSES].sort();
  assert.deepStrictEqual(union, [...S.TICKET_STATUSES].sort());

  const overlap = S.ACTIVE_STATUSES.filter(s => S.TERMINAL_STATUSES.includes(s));
  assert.deepStrictEqual(overlap, [], 'a status cannot be both active and terminal');
});

test('every status has a label and a badge class', () => {
  for (const s of S.TICKET_STATUSES) {
    assert.strictEqual(typeof S.STATUS_LABELS[s], 'string', `${s} has no label`);
    assert.ok(S.STATUS_LABELS[s].length > 0, `${s} has an empty label`);
    assert.match(S.STATUS_BADGES[s], /^badge-/, `${s} has no badge class`);
  }
  // And nothing extra, which would be a name that never renders.
  assert.deepStrictEqual(Object.keys(S.STATUS_LABELS).sort(), [...S.TICKET_STATUSES].sort());
  assert.deepStrictEqual(Object.keys(S.STATUS_BADGES).sort(), [...S.TICKET_STATUSES].sort());
});

test('closed is not styled as a failure', () => {
  // Red for "closed" reads as "something went wrong". Closing a ticket is the
  // successful end of one.
  assert.notStrictEqual(S.STATUS_BADGES.closed, 'badge-danger');
});

test('the constants are frozen', () => {
  // Sloppy-mode assignment to a frozen object fails SILENTLY, so assert on the
  // value rather than on a throw -- the point is that a caller cannot mutate
  // shared vocabulary, not how loudly the attempt fails.
  assert.throws(() => { S.TICKET_STATUSES.push('archived'); });
  S.STATUS_LABELS.open = 'Nope';
  assert.strictEqual(S.STATUS_LABELS.open, 'Open');
});

// ── validation ──────────────────────────────────────────────────────────────

test('isValidStatus accepts only the five names', () => {
  for (const s of S.TICKET_STATUSES) assert.ok(S.isValidStatus(s), `${s} rejected`);
  for (const bad of ['Open', 'OPEN', 'in progress', 'archived', '', null, undefined, 0]) {
    assert.ok(!S.isValidStatus(bad), `${JSON.stringify(bad)} accepted`);
  }
});

test('statusLabel degrades to the raw value rather than undefined', () => {
  assert.strictEqual(S.statusLabel('in_progress'), 'In Progress');
  assert.strictEqual(S.statusLabel('nonsense'), 'nonsense');
  assert.strictEqual(S.statusLabel(null), '');
});

// ── transitions ─────────────────────────────────────────────────────────────

test('a transition to the same status is refused', () => {
  // THE load-bearing case. PATCH /status emails the student on every accepted
  // change, so without this a double-clicked Save sends two identical
  // "your ticket is now Pending" messages.
  for (const s of S.TICKET_STATUSES) {
    assert.ok(!S.canTransition(s, s), `${s} -> ${s} should be a no-op`);
  }
});

test('any status may reach any other status', () => {
  // Deliberately permissive: forbidding resolved -> in_progress would mean
  // staff cannot reopen something they closed by mistake.
  for (const from of S.TICKET_STATUSES) {
    for (const to of S.TICKET_STATUSES) {
      if (from === to) continue;
      assert.ok(S.canTransition(from, to), `${from} -> ${to} should be allowed`);
    }
  }
});

test('an unknown target status is refused', () => {
  assert.ok(!S.canTransition('open', 'archived'));
  assert.ok(!S.canTransition('open', undefined));
});

test('timestampFor names a column only for the terminal statuses', () => {
  assert.strictEqual(S.timestampFor('resolved'), 'resolved_at');
  assert.strictEqual(S.timestampFor('closed'), 'closed_at');
  assert.strictEqual(S.timestampFor('open'), null);
  assert.strictEqual(S.timestampFor('in_progress'), null);
  assert.strictEqual(S.timestampFor('pending'), null);
});

// ── auto-advance ────────────────────────────────────────────────────────────

test('a staff reply advances only a brand-new ticket', () => {
  assert.strictEqual(S.nextStatusAfterStaffReply('open'), 'in_progress');
  // Replying to a resolved ticket must not drag it back into the queue, and
  // replying while Pending must not claim the student answered.
  for (const s of ['in_progress', 'pending', 'resolved', 'closed']) {
    assert.strictEqual(S.nextStatusAfterStaffReply(s), null, `${s} should not advance`);
  }
});

test('a student comment takes a ticket off pending, and nothing else', () => {
  // Without this, "pending" is a black hole: staff mean "waiting on you", the
  // student answers, and nothing anywhere says so.
  assert.strictEqual(S.nextStatusAfterStudentComment('pending'), 'open');
  for (const s of ['open', 'in_progress', 'resolved', 'closed']) {
    assert.strictEqual(S.nextStatusAfterStudentComment(s), null, `${s} should not move`);
  }
});

test('auto-advance never produces a status outside the vocabulary', () => {
  for (const s of S.TICKET_STATUSES) {
    for (const next of [S.nextStatusAfterStaffReply(s), S.nextStatusAfterStudentComment(s)]) {
      if (next !== null) assert.ok(S.isValidStatus(next), `${next} is not a real status`);
    }
  }
});
