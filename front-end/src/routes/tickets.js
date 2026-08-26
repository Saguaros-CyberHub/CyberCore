/**
 * ============================================================================
 * SUPPORT TICKET ROUTES
 * ============================================================================
 * Mounted at /api/tickets, in the CORE block of server.js.
 *
 * THE MOUNT POSITION IS LOAD-BEARING. The CIAB plugin's router is mounted at
 * '/' and carries an /api catch-all that matches every /api/* request in the
 * application (see the long comment in ciab/routes/api.js and
 * test/ciab-gate-scope.test.js). Core routes survive only because server.js
 * registers them BEFORE moduleLoader.loadAll(). Mounting this later would put
 * every ticket request behind CIAB's enrollment gate.
 *
 * ONE ROUTER, NOT TWO
 * ----------------------------------------------------------------------------
 * There is no /api/admin/tickets. The /admin PAGE is requireRole('admin'), so an
 * instructor can never load it — a second admin-only router would therefore
 * need a third instructor-facing copy of the same endpoints, and three copies of
 * an authorization rule is how one of them ends up wrong. Instead every endpoint
 * here scopes by role internally, through the single predicate in
 * utils/tickets.js scopeClause(), which mirrors utils/ticket-access.js exactly.
 *
 * WHAT NEVER COMES FROM THE CLIENT
 * ----------------------------------------------------------------------------
 *   - the recipient list (resolved from cybercore_user at send time)
 *   - the instructor (derived from the course, never posted)
 *   - the course (must appear in the caller's own enrolled/taught list)
 *   - the machine (must appear in a list rebuilt server-side for the caller)
 *   - anything about who may see a ticket
 *
 * Same invariant routes/admin/broadcast.js states at its top: the client sends a
 * SELECTOR, the server resolves it.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();

const { authenticateToken, requireRole } = require('../middleware/auth');
const { cybercoreQuery } = require('../utils/cybercore-db');
const { claimsSql } = require('../utils/lane-claims');
const { laneWorkstationRecords } = require('../utils/lane-deployer');

const tickets = require('../utils/tickets');
const access = require('../utils/ticket-access');
const machines = require('../utils/ticket-machines');
const courseDirectory = require('../utils/course-directory');
const status = require('../utils/ticket-status');
const mailer = require('../utils/mailer');
const templates = require('../utils/email-templates');
const audit = require('../utils/audit');

const staffOnly = requireRole('instructor', 'admin');

/** One POST fans out to every active admin. See countRecentByRequester(). */
const MAX_TICKETS_PER_HOUR = 10;

/**
 * The outbox stores subjects in PLAINTEXT — only bodies are pgp_sym_encrypt'd
 * (029_email_outbox.sql) — and relays log them. Capping is not just hygiene.
 */
const MAX_SUBJECT = 150;
const MAX_BODY = 10000;

// ============================================================================
// HELPERS
// ============================================================================

/**
 * The courses this instructor teaches, for the live half of ticket scoping.
 *
 * Resolved ONCE per request and threaded through, rather than per ticket: the
 * lookup crosses into cle_db, and a 50-row list would otherwise make 50 of them.
 * Always [] for a student, so nothing crosses databases on the common path.
 */
async function taughtIds(user) {
  if (!user || (user.role !== 'instructor' && user.role !== 'admin')) return [];
  const courses = await courseDirectory.coursesForInstructor(user.userId);
  return courses.map(c => c.courseId);
}

/** Every machine belonging to this user, rebuilt server-side. */
async function machinesFor(userId) {
  const laneRows = await cybercoreQuery(
    `SELECT lane_id, name, status, vxlan_id, config, created_at
       FROM cybercore_lane l
      WHERE l.user_id = $1 AND ${claimsSql('l')}
      ORDER BY created_at DESC`,
    [userId]
  );
  // laneWorkstationRecords() owns the fallback for lanes deployed before
  // config.workstations[] existed. A second copy here would drift.
  const lanes = laneRows.rows.map(lane => ({ lane, slots: laneWorkstationRecords(lane) }));

  // The DB-only half of GET /api/workstations/mine. Deliberately NOT that
  // route's handler: it calls syncPowerStates(), which talks to Proxmox, and a
  // support form must not stop working because the hypervisor is unreachable.
  const self = await cybercoreQuery(
    `SELECT vi.vm_instance_id, r.name AS vm_name, vi.provider_vmid, vi.ip_address
       FROM cybercore_vm_instance vi
       JOIN cybercore_resource r ON r.resource_id = vi.resource_id
       JOIN cybercore_allocation a
         ON a.resource_id = r.resource_id
        AND a.user_id = $1
        AND (a.ends_at IS NULL OR a.ends_at > NOW())
      WHERE vi.destroyed_at IS NULL
        AND (r.metadata->>'vm_category') = 'workstation'
      ORDER BY vi.created_at DESC`,
    [userId]
  );

  return machines.projectMachines(lanes, self.rows);
}

/** Trim and bound one text field, or throw a 400-shaped error. */
function requireText(value, field, max) {
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    const err = new Error(`${field} is required.`);
    err.statusCode = 400;
    throw err;
  }
  if (text.length > max) {
    const err = new Error(`${field} must be ${max} characters or fewer.`);
    err.statusCode = 400;
    throw err;
  }
  return text;
}

/**
 * Postgres throws "invalid input syntax for type uuid" on anything that is not
 * one, and an unhandled throw here is a 500 for what is really a not-found.
 * Worse, a 500 and a 404 are distinguishable, which hands an enumerator a
 * signal — so a malformed id takes exactly the same path as a real miss.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Load a ticket the caller may see, or answer 404. See the note below. */
async function loadVisible(req, res) {
  if (!UUID_RE.test(String(req.params.id || ''))) {
    res.status(404).json({ error: 'Ticket not found.' });
    return null;
  }
  const ticket = await tickets.getTicket(req.params.id);
  const taught = await taughtIds(req.user);

  // 404, NEVER 403, when the caller may not see it. A 403 confirms to a
  // stranger that the id names a real ticket, which is the one thing they
  // should not be able to learn by guessing.
  if (!ticket || !access.canSeeTicket(req.user, ticket, taught)) {
    if (ticket) {
      audit.log({
        req,
        action: 'ticket.access_denied',
        status: 'denied',
        reason: 'not a party to this ticket',
        target: { type: 'ticket', id: ticket.ticket_id, label: ticket.subject },
      });
    }
    res.status(404).json({ error: 'Ticket not found.' });
    return null;
  }
  return { ticket, taught };
}

/** "Ada Lovelace" -> "Ada". greeting() degrades to "Hi," on null. */
function firstNameOf(fullName) {
  const first = String(fullName || '').trim().split(/\s+/)[0];
  return first || null;
}

/** The author block every event carries, from the authenticated caller. */
function authorOf(req, profile) {
  return {
    userId: req.user.userId,
    email: req.user.email,
    name: profile ? tickets.displayName(profile) : req.user.email,
    role: req.user.role,
  };
}

/**
 * Queue one ticket message.
 *
 * Every send in this file goes through here, so the Cc rule has one definition:
 * the CURRENT instructor is re-resolved from the course directory on every
 * message, with the snapshot on the ticket as the fallback. A course that
 * changed hands therefore copies the new instructor from the next message on,
 * while a cle_db outage still copies the one recorded at submit time.
 */
async function notify(ticket, { templateKey, message, to, replyTo, ccInstructor = true, exclude = null, requestedBy = null }) {
  let cc = [];
  if (ccInstructor) {
    const live = ticket.course_id
      ? await courseDirectory.describeCourse(ticket.course_id).catch(() => null)
      : null;
    const instructorId = (live && live.instructorUserId) || ticket.instructor_user_id;
    const email = (instructorId && await tickets.loadInstructorEmail(instructorId))
      || ticket.instructor_email;
    // Never copy someone on their own message.
    if (email && String(email).toLowerCase() !== String(exclude || '').toLowerCase()) cc = [email];
  }

  return mailer.enqueue({
    to,
    cc,
    replyTo,
    templateKey,
    subject: message.subject,
    text: message.text,
    html: message.html,
    context: { ticket_id: ticket.ticket_id, ticket_number: ticket.ticket_number },
    requestedBy,
  });
}

/** Common template inputs, so the three messages cannot disagree about branding. */
async function messageBase(ticket) {
  return {
    siteName: await mailer.siteName(),
    publicUrl: mailer.publicUrl(),
    ticketNumber: ticket.ticket_number,
    ticketId: ticket.ticket_id,
    subject: ticket.subject,
  };
}

// ============================================================================
// THE FORM
// ============================================================================

/**
 * GET /api/tickets/form
 *
 * Bootstraps the modal: the courses this person may file against, the machines
 * they own, and — importantly — whether mail works at all.
 *
 * `notice` carries mailer.globalSuppression() VERBATIM so the form can say
 * "email is not configured on this server; your ticket will be recorded but
 * nobody will be notified" BEFORE the student writes it, rather than afterwards
 * via a suppressed row nobody looks at. Same precedent as the broadcast preview.
 */
router.get('/form', authenticateToken, async (req, res) => {
  try {
    const [courses, machineList] = await Promise.all([
      courseDirectory.coursesForTicketForm(req.user),
      machinesFor(req.user.userId),
    ]);
    res.json({
      courses: courses.map(c => ({
        courseId: c.courseId,
        courseName: c.courseName,
        courseCode: c.courseCode,
        label: [c.courseCode, c.courseName].filter(Boolean).join(' — ') || 'Course',
      })),
      machines: machineList,
      notice: mailer.globalSuppression(),
      // Lets the UI distinguish "you are enrolled in nothing" from "the course
      // service is not answering" — both arrive as an empty list.
      coursesUnavailable: !courseDirectory.hasCourseDirectory(),
      limits: { subject: MAX_SUBJECT, body: MAX_BODY },
    });
  } catch (err) {
    console.error('[Tickets] form error:', err.message);
    res.status(500).json({ error: 'Could not load the ticket form.' });
  }
});

// ============================================================================
// SUBMIT
// ============================================================================

/**
 * POST /api/tickets  { subject, body, courseId?, machineKey? }
 *
 * Order matters here, and the ordering IS the security model:
 *   1. validate the text
 *   2. rate-limit  — one POST fans out to every admin, so without a ceiling
 *      this is an admin-mailbox flooding primitive available to any account
 *   3. resolve the course from the CALLER'S OWN list, never from the body
 *   4. resolve the machine from a list rebuilt server-side for this caller
 *   5. write the ticket and its opening event in ONE transaction
 *   6. only AFTER the commit, queue the mail
 *
 * Step 6 is not a detail. Queuing inside the transaction would let a slow relay
 * probe or a mailer bug roll back a ticket the student has already been told was
 * filed, and losing a notification is far less bad than losing the report.
 */
router.post('/', authenticateToken, async (req, res) => {
  try {
    const subject = requireText(req.body.subject, 'Subject', MAX_SUBJECT);
    const body = requireText(req.body.body, 'Description', MAX_BODY);

    const recent = await tickets.countRecentByRequester(req.user.userId, 1);
    if (recent >= MAX_TICKETS_PER_HOUR) {
      return res.status(429).json({
        error: `You have opened ${recent} tickets in the last hour. Please add to an existing ticket instead.`,
      });
    }

    // The client sends a selector; the server resolves it. A courseId the
    // caller is neither enrolled in nor teaching is refused outright rather
    // than silently ignored — silently dropping it would file the ticket
    // without the instructor ever being copied.
    let course = null;
    if (req.body.courseId) {
      course = await courseDirectory.resolveTicketCourse(req.user, req.body.courseId);
      if (!course) {
        return res.status(400).json({ error: 'That is not one of your courses.' });
      }
    }

    let machine = null;
    if (req.body.machineKey) {
      machine = machines.findMachine(await machinesFor(req.user.userId), req.body.machineKey);
      if (!machine) {
        return res.status(400).json({ error: 'That is not one of your machines.' });
      }
    }

    const profile = await tickets.loadUserProfile(req.user.userId);
    const instructorId = course ? course.instructorUserId : null;
    const instructorEmail = await tickets.loadInstructorEmail(instructorId);

    const ticket = await tickets.createTicket({
      requester_user_id: req.user.userId,
      requester_email: (profile && profile.email) || req.user.email,
      requester_name: tickets.displayName(profile),
      requester_role: req.user.role,
      subject,
      body,
      course_id: course ? course.courseId : null,
      course_name: course ? course.courseName : null,
      course_code: course ? course.courseCode : null,
      instructor_user_id: instructorId,
      instructor_email: instructorEmail,
      ...machines.machineSnapshot(machine),
    });

    // Recipients are resolved HERE, from the database, at send time. A client
    // has no way to influence who is told about a ticket.
    const admins = await tickets.activeAdminRecipients();
    const notified = await notify(ticket, {
      templateKey: 'ticketSubmitted',
      to: admins.map(a => a.email),
      // Reply-All from an admin reaches the student. The template says so in
      // as many words, because the header alone is a surprise.
      replyTo: ticket.requester_email,
      exclude: ticket.requester_email,
      requestedBy: req.user.userId,
      message: templates.ticketSubmitted({
        ...(await messageBase(ticket)),
        bodyText: ticket.body,
        courseName: ticket.course_name,
        courseCode: ticket.course_code,
        machineLabel: ticket.machine_label,
        requesterName: ticket.requester_name,
        requesterEmail: ticket.requester_email,
      }),
    });

    audit.log({
      req,
      action: 'ticket.created',
      target: { type: 'ticket', id: ticket.ticket_id, label: ticket.subject },
      targetUser: { id: req.user.userId, label: ticket.requester_email },
      metadata: {
        ticket_number: ticket.ticket_number,
        course_id: ticket.course_id,
        machine_key: ticket.machine_key,
        admins_notified: admins.length,
        mail_status: notified.status,
      },
    });

    res.status(201).json({
      ticket: access.serializeTicket(ticket, req.user, []),
      notified: {
        admins: admins.length,
        status: notified.status,
        ...(notified.reason ? { reason: notified.reason } : {}),
        ...(notified.cc_dropped ? { ccDropped: notified.cc_dropped } : {}),
      },
    });
  } catch (err) {
    if (err.statusCode === 400) return res.status(400).json({ error: err.message });
    console.error('[Tickets] create error:', err.message);
    res.status(500).json({ error: 'Could not open the ticket.' });
  }
});

// ============================================================================
// LISTS
// ============================================================================
// NOTE ON ROUTE ORDER: /mine, /stats and /form are declared before /:id.
// Express matches in registration order, so a later /mine would be swallowed by
// /:id and answered as "ticket 'mine' not found".

/** Query string -> the filter shape utils/tickets.js listTickets() expects. */
function filtersFrom(query) {
  return {
    statuses: String(query.status || '').split(',').map(s => s.trim()).filter(Boolean),
    // Silently dropped rather than 400: a stale bookmark carrying a deleted
    // course id should show the unfiltered queue, not an error page. The cast
    // to ::uuid in listTickets() would otherwise throw.
    courseId: UUID_RE.test(String(query.courseId || '')) ? query.courseId : null,
    q: query.q || null,
    limit: query.limit,
    offset: query.offset,
  };
}

/**
 * GET /api/tickets/mine
 * The caller's own tickets, whatever their role. This is what backs the
 * "My Tickets" tab of the sidebar widget for students, instructors and admins
 * alike — an admin's own report is theirs, not part of the queue they manage.
 */
router.get('/mine', authenticateToken, async (req, res) => {
  try {
    // Scoped as a plain requester deliberately, by passing a student-shaped
    // viewer: an admin asking for "mine" wants their own, not all 400.
    const asRequester = { userId: req.user.userId, role: 'student', email: req.user.email };
    const { rows, total } = await tickets.listTickets(asRequester, [], filtersFrom(req.query));
    res.json({
      tickets: rows.map(r => access.serializeTicket(r, req.user, [])),
      total,
    });
  } catch (err) {
    console.error('[Tickets] mine error:', err.message);
    res.status(500).json({ error: 'Could not load your tickets.' });
  }
});

/**
 * GET /api/tickets
 * The staff queue. Admins get everything; an instructor gets their courses'
 * tickets and nothing else, decided server-side by scopeClause() — there is no
 * client-supplied scope parameter to get wrong.
 */
router.get('/', authenticateToken, staffOnly, async (req, res) => {
  try {
    const taught = await taughtIds(req.user);
    const { rows, total } = await tickets.listTickets(req.user, taught, filtersFrom(req.query));
    res.json({
      tickets: rows.map(r => access.serializeTicket(r, req.user, taught)),
      total,
      scope: req.user.role === 'admin' ? 'all' : 'courses',
      // Surfaced so an instructor whose course list failed to resolve sees why
      // their queue looks short, instead of assuming it is empty.
      coursesUnavailable: req.user.role !== 'admin' && !courseDirectory.hasCourseDirectory(),
    });
  } catch (err) {
    console.error('[Tickets] list error:', err.message);
    res.status(500).json({ error: 'Could not load tickets.' });
  }
});

/** GET /api/tickets/stats — per-status counts inside the same scope. */
router.get('/stats', authenticateToken, staffOnly, async (req, res) => {
  try {
    const taught = await taughtIds(req.user);
    res.json({ counts: await tickets.statusCounts(req.user, taught) });
  } catch (err) {
    console.error('[Tickets] stats error:', err.message);
    res.status(500).json({ error: 'Could not load ticket counts.' });
  }
});

/**
 * GET /api/tickets/:id
 * One ticket and its thread. Internal notes are removed for a requester by
 * serializeEvents(), which is the ONLY place that filtering happens.
 */
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const found = await loadVisible(req, res);
    if (!found) return;
    const events = await tickets.listEvents(found.ticket.ticket_id);
    res.json({
      ticket: access.serializeTicket(found.ticket, req.user, found.taught),
      events: access.serializeEvents(events, req.user, found.ticket, found.taught),
      statuses: status.TICKET_STATUSES.map(s => ({ value: s, label: status.statusLabel(s) })),
    });
  } catch (err) {
    console.error('[Tickets] detail error:', err.message);
    res.status(500).json({ error: 'Could not load the ticket.' });
  }
});

// ============================================================================
// MUTATIONS
// ============================================================================

/**
 * PATCH /api/tickets/:id/status  { status, note? }
 *
 * A move to the SAME status is a no-op that sends nothing. That is not
 * pedantry: this endpoint emails the student on every accepted change, so a
 * double-clicked Save would otherwise deliver two identical "your ticket is now
 * Pending" messages.
 */
router.patch('/:id/status', authenticateToken, staffOnly, async (req, res) => {
  try {
    const found = await loadVisible(req, res);
    if (!found) return;
    const { ticket, taught } = found;

    if (!access.canManageTicket(req.user, ticket, taught)) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const next = String(req.body.status || '');
    if (!status.isValidStatus(next)) {
      return res.status(400).json({ error: 'Unknown status.' });
    }
    if (!status.canTransition(ticket.status, next)) {
      // Already there. Answer with the ticket so the UI settles, and send nothing.
      return res.json({ ticket: access.serializeTicket(ticket, req.user, taught), changed: false });
    }

    const profile = await tickets.loadUserProfile(req.user.userId);
    const author = authorOf(req, profile);
    const note = req.body.note ? String(req.body.note).trim().slice(0, MAX_BODY) : null;
    const updated = await tickets.applyStatus(ticket.ticket_id, ticket.status, next, author);

    // No Cc on a status change: the instructor is usually the one making it,
    // and emailing someone their own action is noise. They see it in the UI.
    const notified = await notify(updated, {
      templateKey: 'ticketStatusChanged',
      to: updated.requester_email,
      ccInstructor: false,
      requestedBy: req.user.userId,
      message: templates.ticketStatusChanged({
        ...(await messageBase(updated)),
        // The REQUESTER's first name -- `profile` above is the staff member
        // making the change, and gating the greeting on it was simply wrong.
        firstName: firstNameOf(updated.requester_name),
        fromStatusLabel: status.statusLabel(ticket.status),
        toStatusLabel: status.statusLabel(next),
        actorName: author.name,
        note,
      }),
    });

    audit.log({
      req,
      action: 'ticket.status_changed',
      target: { type: 'ticket', id: ticket.ticket_id, label: ticket.subject },
      targetUser: { id: ticket.requester_user_id, label: ticket.requester_email },
      changes: { status: { from: ticket.status, to: next } },
      metadata: { ticket_number: ticket.ticket_number, mail_status: notified.status },
    });

    res.json({ ticket: access.serializeTicket(updated, req.user, taught), changed: true });
  } catch (err) {
    console.error('[Tickets] status error:', err.message);
    res.status(500).json({ error: 'Could not change the status.' });
  }
});

/**
 * POST /api/tickets/:id/reply  { body }   — staff speaking on the record.
 *
 * Auto-advances open -> in_progress, and ONLY from open. Replying to a Resolved
 * ticket must not drag it back into the queue, and replying while Pending must
 * not claim the student answered.
 */
router.post('/:id/reply', authenticateToken, staffOnly, async (req, res) => {
  try {
    const found = await loadVisible(req, res);
    if (!found) return;
    const { ticket, taught } = found;
    if (!access.canManageTicket(req.user, ticket, taught)) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const body = requireText(req.body.body, 'Reply', MAX_BODY);
    const profile = await tickets.loadUserProfile(req.user.userId);
    const author = authorOf(req, profile);

    const event = await tickets.addEvent(ticket.ticket_id, {
      kind: 'reply',
      visibility: 'public',
      author_user_id: author.userId,
      author_email: author.email,
      author_name: author.name,
      author_role: author.role,
      body,
    });
    await tickets.markFirstResponse(ticket.ticket_id);

    const advance = status.nextStatusAfterStaffReply(ticket.status);
    if (advance) await tickets.applyStatus(ticket.ticket_id, ticket.status, advance, author);

    const notified = await notify(ticket, {
      templateKey: 'ticketReplied',
      to: ticket.requester_email,
      // The instructor is copied so a course problem stays visible to them —
      // unless they are the one replying.
      exclude: author.email,
      requestedBy: req.user.userId,
      message: templates.ticketReplied({
        ...(await messageBase(ticket)),
        firstName: firstNameOf(ticket.requester_name),
        authorName: author.name,
        bodyText: body,
      }),
    });

    audit.log({
      req,
      action: 'ticket.replied',
      target: { type: 'ticket', id: ticket.ticket_id, label: ticket.subject },
      targetUser: { id: ticket.requester_user_id, label: ticket.requester_email },
      metadata: { event_id: event.event_id, advanced_to: advance, mail_status: notified.status },
    });

    const fresh = await tickets.getTicket(ticket.ticket_id);
    res.status(201).json({
      event: access.serializeEvent(event),
      ticket: access.serializeTicket(fresh, req.user, taught),
    });
  } catch (err) {
    if (err.statusCode === 400) return res.status(400).json({ error: err.message });
    console.error('[Tickets] reply error:', err.message);
    res.status(500).json({ error: 'Could not post the reply.' });
  }
});

/**
 * POST /api/tickets/:id/note  { body }   — staff annotating for each other.
 *
 * SENDS NO EMAIL, under any condition, and is the one event kind the requester
 * can never read. Both properties are enforced elsewhere too — visibility
 * 'internal' is filtered by serializeEvents() — but the absence of a notify()
 * call here is the first of them.
 *
 * The note body is deliberately NOT put in the audit metadata either: audit
 * rows are exportable to CSV by any admin, and redact() is a net, not a licence.
 */
router.post('/:id/note', authenticateToken, staffOnly, async (req, res) => {
  try {
    const found = await loadVisible(req, res);
    if (!found) return;
    const { ticket, taught } = found;
    if (!access.canManageTicket(req.user, ticket, taught)) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const body = requireText(req.body.body, 'Note', MAX_BODY);
    const profile = await tickets.loadUserProfile(req.user.userId);
    const author = authorOf(req, profile);

    const event = await tickets.addEvent(ticket.ticket_id, {
      kind: 'note',
      visibility: 'internal',
      author_user_id: author.userId,
      author_email: author.email,
      author_name: author.name,
      author_role: author.role,
      body,
    });

    audit.log({
      req,
      action: 'ticket.note_added',
      target: { type: 'ticket', id: ticket.ticket_id, label: ticket.subject },
      metadata: { event_id: event.event_id, length: body.length },
    });

    res.status(201).json({ event: access.serializeEvent(event) });
  } catch (err) {
    if (err.statusCode === 400) return res.status(400).json({ error: err.message });
    console.error('[Tickets] note error:', err.message);
    res.status(500).json({ error: 'Could not add the note.' });
  }
});

/**
 * POST /api/tickets/:id/comment  { body }   — the REQUESTER answering.
 *
 * Without this endpoint "Pending" is a black hole: staff set it to mean
 * "waiting on you", the student has nowhere to reply, and the ticket sits there
 * until someone gives up. So it exists, it moves the ticket off Pending, and it
 * tells the admins — a student's answer that nobody is notified about is a dead
 * ticket wearing a live status.
 *
 * Requester only, and by kind: a student can never write a 'reply' (staff
 * speaking on the record) or a 'note' (which they must not even be able to see).
 */
router.post('/:id/comment', authenticateToken, async (req, res) => {
  try {
    const found = await loadVisible(req, res);
    if (!found) return;
    const { ticket, taught } = found;

    if (!access.isRequester(req.user, ticket)) {
      // Staff have /reply and /note. Anyone else cannot see the ticket at all.
      return res.status(403).json({ error: 'Use a reply or an internal note instead.' });
    }

    const body = requireText(req.body.body, 'Message', MAX_BODY);
    const profile = await tickets.loadUserProfile(req.user.userId);
    const author = authorOf(req, profile);

    const event = await tickets.addEvent(ticket.ticket_id, {
      kind: 'comment',
      visibility: 'public',
      author_user_id: author.userId,
      author_email: author.email,
      author_name: author.name,
      author_role: author.role,
      body,
    });

    const advance = status.nextStatusAfterStudentComment(ticket.status);
    if (advance) await tickets.applyStatus(ticket.ticket_id, ticket.status, advance, author);

    // Back to the admins, with the instructor copied — the same audience the
    // original submission went to, resolved the same way.
    const admins = await tickets.activeAdminRecipients();
    const notified = await notify(ticket, {
      templateKey: 'ticketReplied',
      to: admins.map(a => a.email),
      replyTo: ticket.requester_email,
      exclude: author.email,
      requestedBy: req.user.userId,
      message: templates.ticketReplied({
        ...(await messageBase(ticket)),
        firstName: null,
        authorName: author.name,
        bodyText: body,
      }),
    });

    audit.log({
      req,
      action: 'ticket.comment_added',
      target: { type: 'ticket', id: ticket.ticket_id, label: ticket.subject },
      metadata: { event_id: event.event_id, advanced_to: advance, mail_status: notified.status },
    });

    const fresh = await tickets.getTicket(ticket.ticket_id);
    res.status(201).json({
      event: access.serializeEvent(event),
      ticket: access.serializeTicket(fresh, req.user, taught),
    });
  } catch (err) {
    if (err.statusCode === 400) return res.status(400).json({ error: err.message });
    console.error('[Tickets] comment error:', err.message);
    res.status(500).json({ error: 'Could not post your message.' });
  }
});

module.exports = router;
