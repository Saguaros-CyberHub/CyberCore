/**
 * ============================================================================
 * TICKET ACCESS — who may see a ticket, and which of its events
 * ============================================================================
 * This is the security core of the ticket system, and it is deliberately a
 * pure module over plain objects so it can be exhaustively tested without a
 * database.
 *
 * TWO GUARANTEES LIVE HERE, AND NOWHERE ELSE:
 *
 *   1. An internal note NEVER reaches the person who filed the ticket.
 *      Staff annotate tickets for each other ("this student has asked three
 *      times", "the node is being rebuilt, do not tell them yet"). If that
 *      leaks even once the feature is worse than not having it. The filtering
 *      happens in serializeEvents() and every route MUST go through it — a
 *      route that hand-rolls a visibility predicate is one forgotten WHERE
 *      clause away from disclosure, and there is no second layer to catch it.
 *
 *   2. An instructor sees their own courses' tickets and no others.
 *
 * WHY canSeeTicket TAKES taughtCourseIds RATHER THAN LOOKING THEM UP
 * ----------------------------------------------------------------------------
 * cle_course.instructor_id lives in cle_db and the ticket lives in
 * cybercore_db, so there is no join to make. The route resolves the taught
 * course list once per request (utils/course-directory.js) and passes it in.
 * That keeps this module pure, keeps the lookup to one call per request rather
 * than one per ticket, and — because the list arrives EMPTY when cle_db is
 * unreachable — makes the degraded path explicit rather than accidental.
 *
 * WHY BOTH instructor_user_id AND taughtCourseIds
 * ----------------------------------------------------------------------------
 * instructor_user_id is a snapshot taken when the ticket was filed. On its own
 * it goes stale the moment a course changes hands: the previous instructor
 * keeps their access and the new one has none. taughtCourseIds is resolved live
 * and fixes the second half. Keeping BOTH is deliberate:
 *
 *   - the snapshot is "I was a party to this conversation" — that instructor
 *     was Cc'd on the original email and can already read it in their mailbox,
 *     so hiding the ticket from them protects nothing
 *   - the live list is "I am responsible for this course now"
 *   - when cle_db is down only the snapshot survives, so the feature degrades
 *     to still-correct-but-narrower rather than failing shut
 *
 * To cut a previous instructor off entirely, drop the snapshot arm of
 * isTicketStaff(). It is one condition, on purpose.
 *
 * NO IMPORTS. Plain objects in, booleans and arrays out.
 * ============================================================================
 */

/** Roles that may act on tickets at all. Students may only act on their own. */
const STAFF_ROLES = Object.freeze(['admin', 'instructor']);

/** UUIDs arrive as strings from pg, but never assume it. */
function sameId(a, b) {
  if (a == null || b == null) return false;
  return String(a) === String(b);
}

function isAdmin(user) {
  return !!user && user.role === 'admin';
}

/**
 * Is this viewer STAFF ON THIS TICKET?
 *
 * Note what this is not: it is not "is this person an instructor". An
 * instructor who teaches a different course is not staff here, and gets exactly
 * the access a stranger gets.
 */
function isTicketStaff(user, ticket, taughtCourseIds = []) {
  if (!user || !ticket) return false;
  if (isAdmin(user)) return true;
  if (user.role !== 'instructor') return false;

  // Snapshot arm: they were Cc'd on this ticket when it was filed.
  if (sameId(ticket.instructor_user_id, user.userId)) return true;

  // Live arm: they teach the course now. Empty when cle_db is unreachable.
  if (!ticket.course_id) return false;
  return (taughtCourseIds || []).some(id => sameId(id, ticket.course_id));
}

/** Did this viewer file the ticket? */
function isRequester(user, ticket) {
  return !!user && !!ticket && sameId(ticket.requester_user_id, user.userId);
}

/**
 * May this viewer open the ticket at all?
 *
 * The caller must answer a MISS with 404, not 403: a 403 confirms to a stranger
 * that the id names a real ticket, which is exactly the thing they should not
 * be able to learn.
 */
function canSeeTicket(user, ticket, taughtCourseIds = []) {
  return isTicketStaff(user, ticket, taughtCourseIds) || isRequester(user, ticket);
}

/**
 * May this viewer change status, reply, or add a note?
 *
 * Being the requester is NOT enough. A student answers their own ticket through
 * POST /:id/comment, which is a different route with a different event kind — so
 * a student can never write a 'reply' (which is staff speaking on the record)
 * or a 'note' (which they must not even be able to read).
 */
function canManageTicket(user, ticket, taughtCourseIds = []) {
  return isTicketStaff(user, ticket, taughtCourseIds);
}

/**
 * Which of a ticket's events this viewer may read.
 *
 * Internal events are DROPPED, not blanked. A row with a null body still leaks
 * that a note exists, who wrote it and when — which is enough to tell a student
 * that staff are talking about them behind the ticket.
 *
 * Returns a new array; never mutates its input.
 */
function visibleEvents(events, user, ticket, taughtCourseIds = []) {
  const list = Array.isArray(events) ? events : [];
  if (isTicketStaff(user, ticket, taughtCourseIds)) return list.slice();
  return list.filter(e => e && e.visibility !== 'internal');
}

/**
 * The wire shape of one event.
 *
 * Whitelisting the fields is the point: a column added to
 * cybercore_ticket_event later cannot leak by default, it has to be added to
 * this list on purpose.
 */
function serializeEvent(row) {
  return {
    eventId:    row.event_id,
    kind:       row.kind,
    visibility: row.visibility,
    authorId:   row.author_user_id || null,
    authorName: row.author_name || row.author_email || null,
    authorRole: row.author_role || null,
    body:       row.body == null ? null : String(row.body),
    fromStatus: row.from_status || null,
    toStatus:   row.to_status || null,
    createdAt:  row.created_at,
  };
}

/**
 * Filter AND serialize in one call.
 *
 * These are one function rather than two because splitting them invites a
 * caller to serialize first and filter later — and a map() that has already
 * copied a note body into a response object is a leak waiting for someone to
 * forget the second step.
 */
function serializeEvents(events, user, ticket, taughtCourseIds = []) {
  return visibleEvents(events, user, ticket, taughtCourseIds).map(serializeEvent);
}

/**
 * The wire shape of a ticket. Same whitelist reasoning as serializeEvent().
 *
 * canManage travels with the payload so the client does not re-derive an
 * authorization decision the server has already made — the UI reads it to
 * decide whether to draw the status control, and the server enforces it again
 * on every mutation regardless.
 */
function serializeTicket(row, user, taughtCourseIds = []) {
  return {
    ticketId:        row.ticket_id,
    ticketNumber:    row.ticket_number == null ? null : Number(row.ticket_number),
    subject:         row.subject,
    body:            row.body,
    status:          row.status,
    requesterId:     row.requester_user_id || null,
    requesterName:   row.requester_name || row.requester_email || null,
    requesterEmail:  row.requester_email || null,
    courseId:        row.course_id || null,
    courseName:      row.course_name || null,
    courseCode:      row.course_code || null,
    instructorId:    row.instructor_user_id || null,
    laneId:          row.lane_id || null,
    machineKey:      row.machine_key || null,
    machineLabel:    row.machine_label || null,
    machineVmid:     row.machine_vmid == null ? null : Number(row.machine_vmid),
    firstResponseAt: row.first_response_at || null,
    resolvedAt:      row.resolved_at || null,
    closedAt:        row.closed_at || null,
    createdAt:       row.created_at,
    updatedAt:       row.updated_at,
    // Convenience for the UI; never trusted by the server.
    canManage:       canManageTicket(user, row, taughtCourseIds),
    eventCount:      row.event_count == null ? undefined : Number(row.event_count),
  };
}

module.exports = {
  STAFF_ROLES,
  isTicketStaff,
  isRequester,
  canSeeTicket,
  canManageTicket,
  visibleEvents,
  serializeEvent,
  serializeEvents,
  serializeTicket,
};
