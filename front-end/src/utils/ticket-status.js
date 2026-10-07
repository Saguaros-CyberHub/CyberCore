/**
 * ============================================================================
 * TICKET STATUS — the vocabulary, and nothing else
 * ============================================================================
 * A support ticket moves open -> in_progress -> pending -> resolved -> closed,
 * and every one of those names appears in four places that must never disagree:
 *
 *   1. the CHECK constraint on cybercore_ticket.status (utils/tickets.js,
 *      migrations/034_support_tickets.sql, config/postgres/001_init_db.sql)
 *   2. the PATCH /api/tickets/:id/status validator (routes/tickets.js)
 *   3. the filter chips and badge classes on the Admin page
 *      (public/js/admin/admin-tickets.js)
 *   4. the subject line of the status-change email (utils/email-templates.js)
 *
 * lane-claims.js exists because one predicate was spelled six ways; this file
 * exists so the same thing never happens to this list.
 *
 * NO IMPORTS. That is what lets email-templates.js stay import-free — it takes
 * a pre-formatted LABEL rather than requiring this module, and the route that
 * calls it does the lookup.
 *
 * "pending" means WAITING ON THE STUDENT, not "not started yet". That reading is
 * the whole reason the state exists, and it is why a student comment moves a
 * ticket off it automatically.
 * ============================================================================
 */

/** Every value cybercore_ticket.status may take, in workflow order. */
const TICKET_STATUSES = Object.freeze([
  'open',
  'in_progress',
  'pending',
  'resolved',
  'closed',
]);

/** Statuses that still need someone's attention. Drives the default filter. */
const ACTIVE_STATUSES = Object.freeze(['open', 'in_progress', 'pending']);

/** Statuses that end the conversation. */
const TERMINAL_STATUSES = Object.freeze(['resolved', 'closed']);

/** Human labels. Used in email subjects, so they are Title Case, not snake. */
const STATUS_LABELS = Object.freeze({
  open:        'Open',
  in_progress: 'In Progress',
  pending:     'Pending',
  resolved:    'Resolved',
  closed:      'Closed',
});

/**
 * Badge class per status, from public/css/main.css.
 *
 * Deliberately NOT .badge-danger for closed: red reads as "something went
 * wrong", and closing a ticket is the successful end of one. `.badge-muted` is
 * added alongside the existing badge block for exactly this.
 */
const STATUS_BADGES = Object.freeze({
  open:        'badge-info',
  in_progress: 'badge-primary',
  pending:     'badge-warning',
  resolved:    'badge-success',
  closed:      'badge-muted',
});

const STATUS_SET = new Set(TICKET_STATUSES);

function isValidStatus(status) {
  return STATUS_SET.has(status);
}

function statusLabel(status) {
  return STATUS_LABELS[status] || String(status || '');
}

/**
 * Is this a real move?
 *
 * Any status may reach any other — a support queue is not a state machine worth
 * policing, and forbidding resolved -> in_progress would mean staff cannot
 * reopen something they closed by mistake. The ONE thing this rejects is a
 * transition to itself, and that is not pedantry: PATCH /status emails the
 * student on every change, so a double-clicked Save would otherwise send two
 * identical "your ticket is now Pending" messages.
 */
function canTransition(from, to) {
  if (!isValidStatus(to)) return false;
  return from !== to;
}

/**
 * Which timestamp column a move into `to` sets, or null.
 *
 * Returned as a name rather than applied, so the route builds one UPDATE and
 * this stays testable without a database.
 */
function timestampFor(to) {
  if (to === 'resolved') return 'resolved_at';
  if (to === 'closed') return 'closed_at';
  return null;
}

/**
 * A staff reply auto-advances a brand-new ticket to in_progress.
 *
 * ONLY from 'open'. Replying to something already Resolved must not drag it
 * back into the queue, and replying while Pending (waiting on the student)
 * must not claim the student answered.
 */
function nextStatusAfterStaffReply(current) {
  return current === 'open' ? 'in_progress' : null;
}

/**
 * A student comment takes a ticket OFF pending.
 *
 * Without this, "pending" is a black hole: staff set it to mean "waiting on
 * you", the student answers, and nothing anywhere says so. It moves to 'open'
 * rather than 'in_progress' because the answer has not been read yet.
 */
function nextStatusAfterStudentComment(current) {
  return current === 'pending' ? 'open' : null;
}

module.exports = {
  TICKET_STATUSES,
  ACTIVE_STATUSES,
  TERMINAL_STATUSES,
  STATUS_LABELS,
  STATUS_BADGES,
  isValidStatus,
  statusLabel,
  canTransition,
  timestampFor,
  nextStatusAfterStaffReply,
  nextStatusAfterStudentComment,
};
