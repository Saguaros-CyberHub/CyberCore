-- ============================================================================
-- 032_audit_log.sql
-- ----------------------------------------------------------------------------
-- One audit trail for every privileged action, in cybercore_db.
--
-- WHY A NEW TABLE
-- The existing activity_log is defined by a PLUGIN
-- (modules/crucible/plugins/ciab/migrations/001_ciab_schema.sql:89) and lives in
-- clinic_db, while users and lanes live here. That cross-database split is why
-- the admin console cannot show who did anything -- it has no way to turn a
-- user_id into an email, so every row renders as "system"
-- (public/js/admin/admin-activity-log.js:51). Meanwhile cle_activity_log, in a
-- third database, is where all instructor work goes -- invisible to admins
-- entirely. Instructors are now the majority of privileged actors, so that gap
-- is the whole problem this table exists to close.
--
-- WHY action HAS NO CHECK CONSTRAINT
-- cle_activity_log.action_type has one, and it is the direct cause of three
-- call sites deliberately mis-filing what they did and hiding the truth in
-- metadata (cle/routes/guacamole.js:43-54, cle/utils/roster.js:311-323,
-- cle/routes/course-students.js:186). A constraint that needs a migration to
-- extend gets worked around, not honoured. The vocabulary is enforced in
-- src/utils/audit.js instead, where adding a verb is a one-line change.
--
-- WHY THE ACTOR IS DENORMALIZED
-- actor_email/actor_role are snapshots taken at write time. They survive the
-- account being deleted -- which happens in bulk at admin/groups.js:599 and
-- ciab/routes/profile-deploy.js:1062 -- and they mean no query ever needs a
-- join to be readable. actor_role is the role the JWT CLAIMED (routes/auth.js:91,
-- 7-day default expiry, and a password reset does not invalidate sessions --
-- see admin/settings.js:818-822), so it can lag the live role. That is the
-- intent: the audit question is what authority the request presented, not what
-- the user row says today.
--
-- WHY target_id IS TEXT
-- Targets include Proxmox VMIDs, Guacamole integer ids, Ceph volids
-- ("ceph:vm-123-disk-0") and setting keys. activity_log.entity_id is UUID, so
-- all of those are logged as NULL today (admin/cluster.js:398). Nothing joins
-- on this column, so TEXT costs nothing and stops losing data.
--
-- RETENTION: none. Everything is kept, deliberately. There is no purge job.
-- If the table ever needs partitioning by month, the primary key must be
-- widened to (audit_id, occurred_at) first -- an accepted future cost.
--
-- Applied at runtime by ensureAuditLog() in src/utils/audit.js; this file is
-- for operators who apply migrations by hand. Idempotent: safe to re-run.
--
--   psql -h 100.100.20.50 -U cactus-admin -d cybercore_db -f migrations/032_audit_log.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS cybercore_audit_log (
  -- Monotonic rather than UUID, breaking the repo convention on purpose: it
  -- gives a stable tiebreaker for (occurred_at DESC, audit_id DESC), which a
  -- bulk roster import needs because it writes dozens of rows in one
  -- millisecond. Also what makes the CSV export's keyset paging correct.
  audit_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  -- Named occurred_at, not created_at: backfilled rows carry the original
  -- event time, which is not when the row was written.
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Actor. No FK on purpose: an FK would either block user deletion or, with
  -- ON DELETE SET NULL, erase the trail exactly when it matters most.
  actor_user_id   UUID,
  actor_email     TEXT,
  actor_role      TEXT,
  -- Disambiguates a NULL actor_user_id, which otherwise means three different
  -- things: a background job, an unauthenticated failed login, or a bug.
  actor_type      TEXT NOT NULL DEFAULT 'user'
                  CHECK (actor_type IN ('user','system','anonymous')),

  -- 'domain.verb', e.g. 'enrollment.student_added'. See ACTIONS in
  -- src/utils/audit.js for the full vocabulary.
  action          TEXT NOT NULL,
  -- Derived by the writer from the action prefix, never passed by callers, so
  -- it cannot drift. Turns "show me all VM activity" into one indexed equality
  -- test instead of a sixty-value action IN (...).
  category        TEXT NOT NULL
                  CHECK (category IN ('auth','user','enrollment','infra','content','config','access')),
  -- 'failure' = allowed to try, did not work (bad password, deploy error).
  -- 'denied'  = not allowed at all (requireRole 403, escalation guard). Kept
  -- separate because denial is the privilege-escalation signal and must not
  -- drown in wrong-password noise.
  status          TEXT NOT NULL DEFAULT 'success'
                  CHECK (status IN ('success','failure','denied')),
  -- Short machine code, never a stack trace: 'bad_password', 'role_denied'.
  reason          TEXT,

  target_type     TEXT,
  target_id       TEXT,
  -- Human name captured at write time so the list renders without joining
  -- three databases -- and still reads correctly after the target is deleted.
  target_label    TEXT,
  -- First-class and indexed because "which students is this instructor adding"
  -- is the question this table exists to answer. Set whenever the object of
  -- the action is a person, including deploy-on-behalf-of
  -- (src/routes/workstations.js:428).
  target_user_id  UUID,

  -- Correlates a bulk summary row with its per-target fan-out rows.
  event_group_id  UUID,
  source          TEXT NOT NULL DEFAULT 'core'
                  CHECK (source IN ('core','cle','ciab','crucible','system')),

  -- Free-form context. NEVER a credential: passwords, activation tokens, JWTs,
  -- MFA secrets, Guacamole passwords and flag plaintext are stripped by
  -- redact() in src/utils/audit.js. Same reasoning as 029_email_outbox.sql,
  -- which encrypts mail bodies because activation links are live credentials
  -- and adminer is published on 0.0.0.0:8181.
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- Only {field: {from, to}} diffs -- the shape admin/settings.js:656-661
  -- already builds. Separate from metadata because the detail drawer renders
  -- it as a before/after table and mixing the two would force every consumer
  -- to know a magic key.
  changes         JSONB,

  ip_address      INET,
  user_agent      TEXT,
  http_method     TEXT,
  -- The route PATTERN ('/api/cle/courses/:courseId/students'), never
  -- req.originalUrl -- signed-URL tokens ride in the query string
  -- (src/server.js:400-407) and must not be written here.
  route           TEXT,
  request_id      TEXT
);

-- Default list view, and the keyset cursor for CSV export.
CREATE INDEX IF NOT EXISTS idx_audit_occurred
  ON cybercore_audit_log (occurred_at DESC, audit_id DESC);

-- "Everything this instructor did" -- the headline question.
CREATE INDEX IF NOT EXISTS idx_audit_actor
  ON cybercore_audit_log (actor_user_id, occurred_at DESC)
  WHERE actor_user_id IS NOT NULL;

-- "Everything done TO this student." Partial: most rows have no target user.
CREATE INDEX IF NOT EXISTS idx_audit_target_user
  ON cybercore_audit_log (target_user_id, occurred_at DESC)
  WHERE target_user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_action
  ON cybercore_audit_log (action, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_category
  ON cybercore_audit_log (category, occurred_at DESC);

-- History of one lane / VM / course.
CREATE INDEX IF NOT EXISTS idx_audit_target
  ON cybercore_audit_log (target_type, target_id)
  WHERE target_id IS NOT NULL;

-- The security view. Failures and denials are a tiny fraction of rows, so a
-- partial index keeps "show me everything that went wrong" instant no matter
-- how large the table gets.
CREATE INDEX IF NOT EXISTS idx_audit_not_success
  ON cybercore_audit_log (occurred_at DESC)
  WHERE status <> 'success';

-- Drawer expansion of a bulk event (roster import, group teardown).
CREATE INDEX IF NOT EXISTS idx_audit_event_group
  ON cybercore_audit_log (event_group_id)
  WHERE event_group_id IS NOT NULL;

-- Makes scripts/backfill-audit-log.js re-runnable: the copy inserts with
-- ON CONFLICT DO NOTHING against this index.
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_legacy_id
  ON cybercore_audit_log ((metadata->>'legacy_id'))
  WHERE metadata ? 'legacy_id';

-- Free-text search across the fields a human actually types into the box.
-- Best effort: nothing else in the repo uses pg_trgm, so do not assume the app
-- role can create it. ensureAuditLog() wraps this pair in its own try/catch --
-- without the index, search falls back to a scan inside the already
-- date/actor-filtered subset, which is fine at teaching-lab volume.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_audit_search_trgm
  ON cybercore_audit_log USING gin (
    (coalesce(actor_email,'') || ' ' || coalesce(target_label,'') || ' ' ||
     action || ' ' || coalesce(reason,'')) gin_trgm_ops
  );

-- ROLLBACK
--   DROP TABLE IF EXISTS cybercore_audit_log;
