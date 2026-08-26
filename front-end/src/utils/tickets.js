/**
 * ============================================================================
 * SUPPORT TICKETS — schema and data access
 * ============================================================================
 * Tickets live in cybercore_db, NOT in cle_db, and that is the first decision
 * worth defending:
 *
 *   - Every hot join is a core table. The requester and the admin recipient
 *     list are cybercore_user; the machine is cybercore_lane / vm_instance;
 *     the audit actor is cybercore_user again. Only the COURSE is remote.
 *   - The management UI is the core Admin page, so core owning the table means
 *     routes/tickets.js never has to require a plugin path.
 *   - "I cannot reach my VM" is a platform concern that must outlive the CLE
 *     plugin being disabled. In cle_db, the whole support history would vanish
 *     with a plugin uninstall and the Admin list would need a second database
 *     to be up before it could render at all.
 *
 * COURSE AND MACHINE ARE SNAPSHOTS, NOT REFERENCES
 * ----------------------------------------------------------------------------
 * cle_course is in another database, so there is no foreign key to be had — but
 * the snapshot columns are not merely a workaround, they are the right design
 * in both directions:
 *
 *   - a course renamed or deleted leaves the ticket still reading
 *     "CYBR 400 — Security Operations"
 *   - lanes are torn down routinely (teardownCourseLanes), and "ticket about
 *     lane a3f2… (gone)" is useless where "ticket about cybr400-pat-ws0
 *     (VM 601234)" is still diagnosable a month later
 *
 * There is deliberately NO foreign key to cybercore_lane. One would either
 * block teardownLanes() — a hot path — or, with ON DELETE CASCADE, silently
 * delete support history when a lane is recycled. Both are worse than a
 * dangling uuid beside a label that still means something.
 *
 * THREE COPIES OF THIS DDL EXIST, AND THEY MUST NOT DRIFT
 * ----------------------------------------------------------------------------
 *   1. ensureTicketTables() below — the ONLY one that runs on an existing
 *      deployment. front-end/migrations/ has no runner (see server.js), and
 *      config/postgres/ only executes on a fresh Docker volume.
 *   2. front-end/migrations/034_support_tickets.sql — the operator's paper
 *      trail, run by hand.
 *   3. config/postgres/001_init_db.sql — fresh volumes.
 *
 * test/ticket-schema.test.js pins the status CHECK list across all three.
 * ============================================================================
 */

const { cybercorePool, cybercoreQuery } = require('./cybercore-db');
const { TICKET_STATUSES, timestampFor } = require('./ticket-status');

/**
 * The status CHECK, written out rather than built from TICKET_STATUSES.
 *
 * Same reasoning as CLAIMS_SQL in utils/lane-claims.js: a literal constant is
 * greppable, cannot be reached by a caller-supplied value, and reads identically
 * in the two .sql files that carry the same constraint. The test is what keeps
 * the four copies honest.
 */
const STATUS_CHECK = `CHECK (status IN ('open','in_progress','pending','resolved','closed'))`;

/** Event kinds. 'comment' is the requester speaking; 'reply' is staff. */
const EVENT_KINDS = Object.freeze(['created', 'reply', 'note', 'comment', 'status']);

const TICKET_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS cybercore_ticket (
    ticket_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Human-facing "#42". A UUID is unusable in a subject line or a corridor
    -- conversation, and the subject line is where mail clients thread.
    ticket_number       BIGINT GENERATED ALWAYS AS IDENTITY,

    -- SET NULL, not CASCADE: deleting an account must not delete the record of
    -- what they reported. The snapshot columns below are what keep the row
    -- readable afterwards.
    requester_user_id   UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
    requester_email     TEXT NOT NULL,
    requester_name      TEXT,

    subject             TEXT NOT NULL,
    body                TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open'
                        ${STATUS_CHECK},

    -- Course: snapshot only. cle_course lives in cle_db; there is no FK to have.
    course_id           UUID,
    course_name         TEXT,
    course_code         TEXT,
    instructor_user_id  UUID,
    instructor_email    TEXT,

    -- Machine: deliberately NO FK to cybercore_lane. See the header.
    lane_id             UUID,
    machine_key         TEXT,
    machine_label       TEXT,
    machine_vmid        INTEGER,

    first_response_at   TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
  )
`;

const EVENT_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS cybercore_ticket_event (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id       UUID NOT NULL REFERENCES cybercore_ticket(ticket_id) ON DELETE CASCADE,

    -- One table for status changes, staff replies, internal notes and student
    -- comments, so the detail view is one ordered query rather than a merge of
    -- three. 'visibility' is the axis that matters and it is separate from
    -- 'kind' on purpose: a future kind must decide its visibility explicitly.
    kind            TEXT NOT NULL CHECK (kind IN ('created','reply','note','comment','status')),
    visibility      TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','internal')),

    author_user_id  UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
    author_email    TEXT,
    author_name     TEXT,
    author_role     TEXT,

    body            TEXT,
    from_status     TEXT,
    to_status       TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  )
`;

const TICKET_INDEX_SQL = [
  `CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_number
     ON cybercore_ticket (ticket_number)`,
  `CREATE INDEX IF NOT EXISTS idx_ticket_requester
     ON cybercore_ticket (requester_user_id, created_at DESC)`,
  // Partial: most tickets have no instructor, and the instructor scope query
  // hits this arm on every staff list load.
  `CREATE INDEX IF NOT EXISTS idx_ticket_instructor
     ON cybercore_ticket (instructor_user_id, created_at DESC)
   WHERE instructor_user_id IS NOT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ticket_course
     ON cybercore_ticket (course_id, created_at DESC)
   WHERE course_id IS NOT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ticket_status
     ON cybercore_ticket (status, created_at DESC)`,
  // The Admin page's default view is "everything still needing attention".
  `CREATE INDEX IF NOT EXISTS idx_ticket_active
     ON cybercore_ticket (created_at DESC)
   WHERE status IN ('open','in_progress','pending')`,
  `CREATE INDEX IF NOT EXISTS idx_ticket_event_ticket
     ON cybercore_ticket_event (ticket_id, created_at)`,
  // Backs the student's thread view, which is the one that must never
  // accidentally include an internal note.
  `CREATE INDEX IF NOT EXISTS idx_ticket_event_public
     ON cybercore_ticket_event (ticket_id, created_at)
   WHERE visibility = 'public'`,
];

/**
 * Idempotent boot DDL, structurally a copy of ensureAuditLog() in utils/audit.js.
 *
 * One try/catch around the lot, warning rather than throwing: if the app role
 * cannot run DDL, the right outcome is a server that starts with no ticket
 * system, not a server that will not start. The warning is the operator's cue
 * to run migrations/034_support_tickets.sql by hand.
 */
async function ensureTicketTables() {
  try {
    await cybercoreQuery(TICKET_TABLE_SQL);
    await cybercoreQuery(EVENT_TABLE_SQL);
    for (const sql of TICKET_INDEX_SQL) await cybercoreQuery(sql);
    console.log('✅ Support tickets ensured');
  } catch (err) {
    console.warn('⚠️  Could not ensure support tickets:', err.message);
  }
}

// ============================================================================
// SCOPE
// ============================================================================

/** Columns every list and detail read returns. Kept in one place so they agree. */
const TICKET_COLUMNS = `
  t.ticket_id, t.ticket_number, t.requester_user_id, t.requester_email, t.requester_name,
  t.subject, t.body, t.status,
  t.course_id, t.course_name, t.course_code, t.instructor_user_id, t.instructor_email,
  t.lane_id, t.machine_key, t.machine_label, t.machine_vmid,
  t.first_response_at, t.resolved_at, t.closed_at, t.created_at, t.updated_at
`;

/**
 * The WHERE arm that decides which tickets a caller may list.
 *
 * ONE definition, used by the list, the counts and the detail read, so the
 * three can never disagree about who sees what — the failure mode being a
 * ticket that shows in a count and 404s when clicked.
 *
 * The three arms mirror utils/ticket-access.js exactly; see that file's header
 * for why an instructor needs BOTH the snapshot and the live course list.
 * `taughtCourseIds` arrives empty when cle_db is unreachable, which narrows the
 * result rather than failing it.
 *
 * @returns {{ text: string, params: any[] }} params begin at $1
 */
function scopeClause(user, taughtCourseIds = []) {
  const isAdmin = !!user && user.role === 'admin';
  const isStaff = isAdmin || (!!user && user.role === 'instructor');
  const userId = user ? user.userId : null;

  if (isAdmin) return { text: 'TRUE', params: [] };

  if (isStaff) {
    return {
      text: `(t.instructor_user_id = $1 OR (t.course_id IS NOT NULL AND t.course_id = ANY($2::uuid[])))`,
      params: [userId, (taughtCourseIds || []).map(String)],
    };
  }

  // Students and everyone else: their own, and nothing else.
  return { text: `t.requester_user_id = $1`, params: [userId] };
}

/**
 * Renumber a clause's $n placeholders so it can be appended to a query that
 * already has parameters.
 *
 * Written out rather than hand-numbered at each call site because getting this
 * wrong silently shifts a scope predicate onto the wrong value — which in this
 * module means showing one person another person's tickets.
 */
function offsetPlaceholders(text, offset) {
  if (!offset) return text;
  return text.replace(/\$(\d+)/g, (_, n) => `$${Number(n) + offset}`);
}

// ============================================================================
// READS
// ============================================================================

/** One ticket by id, unscoped. The CALLER applies canSeeTicket() and 404s. */
async function getTicket(ticketId) {
  const r = await cybercoreQuery(
    `SELECT ${TICKET_COLUMNS} FROM cybercore_ticket t WHERE t.ticket_id = $1`,
    [ticketId]
  );
  return r.rows[0] || null;
}

/** Every event on a ticket, oldest first. Filtering is serializeEvents()' job. */
async function listEvents(ticketId) {
  const r = await cybercoreQuery(
    `SELECT event_id, ticket_id, kind, visibility,
            author_user_id, author_email, author_name, author_role,
            body, from_status, to_status, created_at
       FROM cybercore_ticket_event
      WHERE ticket_id = $1
      ORDER BY created_at, event_id`,
    [ticketId]
  );
  return r.rows;
}

/**
 * A page of tickets the caller may see, newest first.
 *
 * @param {object} user            req.user
 * @param {string[]} taughtCourseIds
 * @param {object} filters         { statuses, courseId, q, limit, offset }
 */
async function listTickets(user, taughtCourseIds, filters = {}) {
  const scope = scopeClause(user, taughtCourseIds);
  const params = [...scope.params];
  const where = [offsetPlaceholders(scope.text, 0)];

  const statuses = (filters.statuses || []).filter(s => TICKET_STATUSES.includes(s));
  if (statuses.length) {
    params.push(statuses);
    where.push(`t.status = ANY($${params.length}::text[])`);
  }
  if (filters.courseId) {
    params.push(String(filters.courseId));
    where.push(`t.course_id = $${params.length}::uuid`);
  }
  if (filters.q) {
    // ILIKE over the two fields staff actually search by. Deliberately NOT the
    // body: a full-text index is a different piece of work, and a sequential
    // ILIKE over every ticket body is the kind of query that is fine for a
    // semester and then is not.
    const esc = String(filters.q).replace(/[%_\\]/g, m => '\\' + m);
    params.push('%' + esc + '%');
    where.push(`(t.subject ILIKE $${params.length} OR t.requester_email ILIKE $${params.length})`);
  }

  const limit = Math.min(Math.max(1, Number(filters.limit) || 50), 200);
  const offset = Math.max(0, Number(filters.offset) || 0);
  params.push(limit, offset);

  const r = await cybercoreQuery(
    `SELECT ${TICKET_COLUMNS},
            (SELECT count(*) FROM cybercore_ticket_event e WHERE e.ticket_id = t.ticket_id)::int
              AS event_count,
            count(*) OVER ()::int AS total_count
       FROM cybercore_ticket t
      WHERE ${where.join(' AND ')}
      ORDER BY t.created_at DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  return {
    rows: r.rows,
    total: r.rows.length ? Number(r.rows[0].total_count) : 0,
  };
}

/** Per-status counts inside the caller's scope, for the filter chips. */
async function statusCounts(user, taughtCourseIds) {
  const scope = scopeClause(user, taughtCourseIds);
  const r = await cybercoreQuery(
    `SELECT t.status, count(*)::int AS n
       FROM cybercore_ticket t
      WHERE ${scope.text}
      GROUP BY t.status`,
    scope.params
  );
  const counts = Object.fromEntries(TICKET_STATUSES.map(s => [s, 0]));
  for (const row of r.rows) counts[row.status] = row.n;
  return counts;
}

/**
 * How many tickets this person filed in the last hour.
 *
 * One POST fans out to every active admin, so without a ceiling this endpoint
 * is an admin-mailbox flooding primitive that needs no privileges at all.
 */
async function countRecentByRequester(userId, hours = 1) {
  const r = await cybercoreQuery(
    `SELECT count(*)::int AS n
       FROM cybercore_ticket
      WHERE requester_user_id = $1
        AND created_at > now() - ($2 || ' hours')::interval`,
    [userId, String(hours)]
  );
  return r.rows[0] ? r.rows[0].n : 0;
}

// ============================================================================
// WRITES
// ============================================================================

/**
 * Insert a ticket and its opening event as ONE transaction.
 *
 * A ticket with no 'created' event renders as an empty thread — the student's
 * own words would be on the ticket row but missing from the timeline every
 * later reply appends to. They are written together or not at all.
 *
 * Note what is NOT in here: the email. enqueue() is called by the route AFTER
 * this commits. Queuing inside the transaction would mean a slow relay probe or
 * a mailer bug could roll back a ticket the student has already been told was
 * filed — and losing the notification is far less bad than losing the ticket.
 */
async function createTicket(fields) {
  const client = await cybercorePool.connect();
  try {
    await client.query('BEGIN');
    const t = await client.query(
      `INSERT INTO cybercore_ticket
         (requester_user_id, requester_email, requester_name,
          subject, body,
          course_id, course_name, course_code, instructor_user_id, instructor_email,
          lane_id, machine_key, machine_label, machine_vmid)
       VALUES ($1, $2, $3, $4, $5,
               $6::uuid, $7, $8, $9::uuid, $10,
               $11::uuid, $12, $13, $14::int)
       RETURNING ${TICKET_COLUMNS.replace(/t\./g, '')}`,
      [
        fields.requester_user_id || null, fields.requester_email, fields.requester_name || null,
        fields.subject, fields.body,
        fields.course_id || null, fields.course_name || null, fields.course_code || null,
        fields.instructor_user_id || null, fields.instructor_email || null,
        fields.lane_id || null, fields.machine_key || null,
        fields.machine_label || null, fields.machine_vmid == null ? null : fields.machine_vmid,
      ]
    );
    const ticket = t.rows[0];

    await client.query(
      `INSERT INTO cybercore_ticket_event
         (ticket_id, kind, visibility, author_user_id, author_email, author_name, author_role, body)
       VALUES ($1, 'created', 'public', $2::uuid, $3, $4, $5, $6)`,
      [
        ticket.ticket_id, fields.requester_user_id || null, fields.requester_email,
        fields.requester_name || null, fields.requester_role || 'student', fields.body,
      ]
    );

    await client.query('COMMIT');
    return ticket;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Append one event and bump the ticket's updated_at.
 *
 * updated_at moves for every event including an internal note, on purpose: it
 * means "when did anything happen here", which is what a staff queue sorts and
 * triages by. It is not a signal shown to the student.
 */
async function addEvent(ticketId, event) {
  const r = await cybercoreQuery(
    `INSERT INTO cybercore_ticket_event
       (ticket_id, kind, visibility, author_user_id, author_email, author_name, author_role,
        body, from_status, to_status)
     VALUES ($1::uuid, $2, $3, $4::uuid, $5, $6, $7, $8, $9, $10)
     RETURNING event_id, ticket_id, kind, visibility,
               author_user_id, author_email, author_name, author_role,
               body, from_status, to_status, created_at`,
    [
      ticketId, event.kind, event.visibility || 'public',
      event.author_user_id || null, event.author_email || null,
      event.author_name || null, event.author_role || null,
      event.body || null, event.from_status || null, event.to_status || null,
    ]
  );
  await cybercoreQuery(
    `UPDATE cybercore_ticket SET updated_at = now() WHERE ticket_id = $1`, [ticketId]
  );
  return r.rows[0];
}

/**
 * Move a ticket to a new status and record the move as an event.
 *
 * The timestamp column is named by utils/ticket-status.js rather than chosen
 * here, so "which move sets resolved_at" has one definition and is testable
 * without a database. Column names come from that whitelist and never from a
 * request, which is what makes the interpolation below safe.
 */
async function applyStatus(ticketId, fromStatus, toStatus, author) {
  const column = timestampFor(toStatus);
  const stamp = column ? `, ${column} = now()` : '';
  const r = await cybercoreQuery(
    `UPDATE cybercore_ticket
        SET status = $2, updated_at = now()${stamp}
      WHERE ticket_id = $1
      RETURNING ${TICKET_COLUMNS.replace(/t\./g, '')}`,
    [ticketId, toStatus]
  );
  if (!r.rows[0]) return null;

  await addEvent(ticketId, {
    kind: 'status',
    visibility: 'public',
    author_user_id: author && author.userId,
    author_email: author && author.email,
    author_name: author && author.name,
    author_role: author && author.role,
    from_status: fromStatus,
    to_status: toStatus,
  });
  return r.rows[0];
}

/**
 * Stamp the first staff response, once.
 *
 * COALESCE rather than a read-then-write: two admins answering the same ticket
 * within the same second would otherwise race, and the later write would move
 * the "time to first response" forward.
 */
async function markFirstResponse(ticketId) {
  await cybercoreQuery(
    `UPDATE cybercore_ticket
        SET first_response_at = COALESCE(first_response_at, now())
      WHERE ticket_id = $1`,
    [ticketId]
  );
}

/**
 * Every active admin, as recipients.
 *
 * The predicate matches buildFilterQuery() in utils/broadcast-audience.js
 * exactly, including its documented subtlety: `active` requires BOTH the
 * boolean flag AND status = 'active', because the two columns are not always
 * in lockstep and only admin/groups.js sets them together. The hard block on
 * deleted and banned accounts is unconditional there and here.
 *
 * status = 'active' already excludes 'deleted' and 'banned', so the explicit
 * block those two get in broadcast-audience.js is redundant here rather than
 * missing.
 *
 * Resolved server-side at send time, never supplied by a client — the same
 * invariant routes/admin/broadcast.js states at its top.
 */
async function activeAdminRecipients() {
  const r = await cybercoreQuery(
    `SELECT user_id, email, first_name, last_name
       FROM cybercore_user
      WHERE role = 'admin'
        AND active = TRUE
        AND status = 'active'
      ORDER BY lower(email)`
  );
  return r.rows;
}

/** Display name for a cybercore_user row. There is no `name` column. */
function displayName(row) {
  if (!row) return null;
  const name = [row.first_name, row.last_name].filter(Boolean).join(' ').trim();
  return name || row.email || null;
}

/** The requester's identity at submit time, for the snapshot columns. */
async function loadUserProfile(userId) {
  const r = await cybercoreQuery(
    `SELECT user_id, email, first_name, last_name, role
       FROM cybercore_user WHERE user_id = $1`,
    [userId]
  );
  return r.rows[0] || null;
}

/** One instructor's address, for the Cc. Null rather than throwing. */
async function loadInstructorEmail(instructorUserId) {
  if (!instructorUserId) return null;
  try {
    const r = await cybercoreQuery(
      `SELECT email FROM cybercore_user
        WHERE user_id = $1 AND status NOT IN ('deleted', 'banned')`,
      [instructorUserId]
    );
    return r.rows[0] ? r.rows[0].email : null;
  } catch {
    return null;
  }
}

module.exports = {
  // schema
  STATUS_CHECK,
  EVENT_KINDS,
  TICKET_TABLE_SQL,
  EVENT_TABLE_SQL,
  TICKET_INDEX_SQL,
  ensureTicketTables,
  // scope
  scopeClause,
  offsetPlaceholders,
  // reads
  getTicket,
  listEvents,
  listTickets,
  statusCounts,
  countRecentByRequester,
  // writes
  createTicket,
  addEvent,
  applyStatus,
  markFirstResponse,
  // people
  activeAdminRecipients,
  displayName,
  loadUserProfile,
  loadInstructorEmail,
};
