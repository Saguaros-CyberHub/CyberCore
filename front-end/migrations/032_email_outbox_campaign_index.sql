-- ============================================================================
-- 032_email_outbox_campaign_index.sql
-- ----------------------------------------------------------------------------
-- Index behind the admin broadcast delivery report.
--
-- WHY THERE IS NO CAMPAIGN TABLE
-- A broadcast is not a new kind of thing; it is a few hundred ordinary outbox
-- rows that happen to share a subject. Everything a delivery report needs -
-- per-recipient status, attempts, last_error, sent_at - is already on the row.
-- So the campaign id rides in the existing `context` JSONB, exactly as
-- import_id already does for roster imports (see 029), and both the per-
-- campaign report and the recent-broadcasts list are GROUP BY queries over
-- this index rather than joins against a table that would only ever duplicate
-- what the outbox already knows.
--
-- The trade this makes, stated plainly: the report is only as durable as the
-- rows, and pruneOutbox() deletes sent/suppressed mail after MAIL_RETENTION_DAYS
-- (default 30). The permanent record of "who sent what, to how many, when" is
-- the activity_log row written by POST /api/admin/broadcast/send, which mail
-- retention never touches.
--
-- Applied at runtime by ensureEmailOutbox() in src/utils/mailer.js; this file is
-- for operators who apply migrations by hand. Idempotent: safe to re-run.
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_email_outbox_campaign
  ON cybercore_email_outbox ((context->>'campaign_id'));
