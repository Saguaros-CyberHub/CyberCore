-- ============================================================================
-- 029_email_outbox.sql
-- ----------------------------------------------------------------------------
-- Durable queue for outbound email.
--
-- Lives in cybercore_db rather than cle_db for two reasons: it serves core auth
-- flows (activation today, self-service password reset later), and cle_db
-- cannot reference cybercore_user across databases anyway.
--
-- WHY A QUEUE AT ALL
-- A roster import can create 200 accounts in one request. Sending inline would
-- hold that request open across 200 SMTP transactions, and a timeout partway
-- through would leave the instructor unable to tell which students were
-- notified. Rows go in, src/utils/email-worker.js takes them out.
--
-- WHY THE BODIES ARE ENCRYPTED
-- Bodies carry activation links, which are working credentials until redeemed.
-- adminer is published on 0.0.0.0:8181 (docker-compose.yml), so plaintext here
-- would be one weak database password away from disclosure. Same pgcrypto idiom
-- the schema already uses for guac_password and mfa_secret. The body is BLANKED
-- by the same UPDATE that marks a message sent — once delivered, a decryptable
-- copy is pure liability.
--
-- Applied at runtime by ensureEmailOutbox(); this file is for operators who
-- apply migrations by hand. Idempotent: safe to run repeatedly.
-- ============================================================================

CREATE TABLE IF NOT EXISTS cybercore_email_outbox (
  email_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  to_address       TEXT NOT NULL,
  to_user_id       UUID,
  template_key     TEXT NOT NULL,
  -- Plaintext, unlike the body: subjects are shown in the admin/instructor
  -- delivery report, and no template puts a secret in one.
  subject          TEXT NOT NULL,
  -- NULLable on purpose. A suppressed message (unconfigured mail, blocked
  -- recipient domain, synthetic cohort address) is recorded so the import UI
  -- can explain itself, but it has no body worth keeping — and when no
  -- encryption key is configured we must not store one at all.
  body_text_cipher BYTEA,
  body_html_cipher BYTEA,
  status           TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued','sending','sent','failed','suppressed')),
  attempts         INTEGER NOT NULL DEFAULT 0,
  max_attempts     INTEGER NOT NULL DEFAULT 5,
  next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error       TEXT,
  smtp_message_id  TEXT,
  -- Correlation only — e.g. { import_id, course_id }. NEVER a credential.
  context          JSONB NOT NULL DEFAULT '{}'::jsonb,
  requested_by     UUID,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at          TIMESTAMPTZ
);

-- Partial: the worker's claim query only ever looks at work still outstanding,
-- so delivered mail is dead weight in this index.
CREATE INDEX IF NOT EXISTS idx_email_outbox_due
  ON cybercore_email_outbox (next_attempt_at)
  WHERE status IN ('queued','sending');

CREATE INDEX IF NOT EXISTS idx_email_outbox_user
  ON cybercore_email_outbox (to_user_id);

-- Backs the per-import delivery report an instructor sees after a roster run.
CREATE INDEX IF NOT EXISTS idx_email_outbox_import
  ON cybercore_email_outbox ((context->>'import_id'));
