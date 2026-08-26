-- ============================================================================
-- 034_support_tickets.sql — the support ticket system
-- ============================================================================
-- WHAT THIS FILE IS, AND IS NOT
--
-- front-end/migrations/ has NO automatic runner. Nothing reads this directory:
-- module-loader.js only walks manifest.database.migrations inside modules/ and
-- plugins/, and docker-compose mounts only config/postgres/ into
-- /docker-entrypoint-initdb.d (which itself runs on a FRESH VOLUME ONLY).
--
-- So this file is the operator's paper trail and a hand-run repair, not the
-- mechanism. The mechanism is ensureTicketTables() in src/utils/tickets.js,
-- called from start() in src/server.js on every boot.
--
-- Run it by hand only when that boot DDL warned it could not apply — typically
-- because the app role lacks DDL rights:
--
--   psql -h <host> -U <superuser> -d cybercore_db -f migrations/034_support_tickets.sql
--
-- Every statement is idempotent. Keep it byte-identical to the DDL in
-- src/utils/tickets.js and config/postgres/001_init_db.sql —
-- test/ticket-schema.test.js pins the status CHECK across all three.
-- ============================================================================

-- ── tickets ─────────────────────────────────────────────────────────────────
-- Course and machine are SNAPSHOTS, not references. cle_course lives in cle_db
-- so there is no foreign key to be had, and there is deliberately none to
-- cybercore_lane either: an FK would either block teardownLanes() or, with
-- ON DELETE CASCADE, delete support history when a lane is recycled.
CREATE TABLE IF NOT EXISTS cybercore_ticket (
  ticket_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_number       BIGINT GENERATED ALWAYS AS IDENTITY,

  requester_user_id   UUID REFERENCES cybercore_user(user_id) ON DELETE SET NULL,
  requester_email     TEXT NOT NULL,
  requester_name      TEXT,

  subject             TEXT NOT NULL,
  body                TEXT NOT NULL,
  status              TEXT NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','in_progress','pending','resolved','closed')),

  course_id           UUID,
  course_name         TEXT,
  course_code         TEXT,
  instructor_user_id  UUID,
  instructor_email    TEXT,

  lane_id             UUID,
  machine_key         TEXT,
  machine_label       TEXT,
  machine_vmid        INTEGER,

  first_response_at   TIMESTAMPTZ,
  resolved_at         TIMESTAMPTZ,
  closed_at           TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── thread ──────────────────────────────────────────────────────────────────
-- One table for status changes, staff replies, internal notes and student
-- comments, so a detail view is one ordered query. `visibility` is a separate
-- axis from `kind` on purpose: a new kind must decide its visibility, and the
-- student-facing filter is one predicate rather than a list of kinds to
-- remember.
CREATE TABLE IF NOT EXISTS cybercore_ticket_event (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id       UUID NOT NULL REFERENCES cybercore_ticket(ticket_id) ON DELETE CASCADE,

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
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_number
  ON cybercore_ticket (ticket_number);
CREATE INDEX IF NOT EXISTS idx_ticket_requester
  ON cybercore_ticket (requester_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ticket_instructor
  ON cybercore_ticket (instructor_user_id, created_at DESC)
  WHERE instructor_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_course
  ON cybercore_ticket (course_id, created_at DESC)
  WHERE course_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_status
  ON cybercore_ticket (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ticket_active
  ON cybercore_ticket (created_at DESC)
  WHERE status IN ('open','in_progress','pending');
CREATE INDEX IF NOT EXISTS idx_ticket_event_ticket
  ON cybercore_ticket_event (ticket_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ticket_event_public
  ON cybercore_ticket_event (ticket_id, created_at)
  WHERE visibility = 'public';

-- ── outbox: multi-recipient support ─────────────────────────────────────────
-- Tickets are the first messages this platform sends to more than one person:
-- To: every active admin, Cc: the course instructor, Reply-To: the student.
-- Both columns are nullable with no default, so this is a metadata-only change
-- and safe on a live table.
--
-- mailer.js PROBES for these (ccColumnsPresent) rather than assuming them. If
-- this ALTER never runs, mail keeps flowing without a Cc instead of every send
-- on the platform failing — including activation links.
ALTER TABLE cybercore_email_outbox ADD COLUMN IF NOT EXISTS cc_address TEXT;
ALTER TABLE cybercore_email_outbox ADD COLUMN IF NOT EXISTS reply_to   TEXT;

CREATE INDEX IF NOT EXISTS idx_email_outbox_ticket
  ON cybercore_email_outbox ((context->>'ticket_id'));
