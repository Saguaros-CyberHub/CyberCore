-- ============================================================================
-- 027_user_provisioning_and_password_policy.sql
-- ----------------------------------------------------------------------------
-- Adds the columns the CLE roster import needs on cybercore_user:
--   * password policy   — forcing a password change at first login
--   * provenance        — WHO minted an account and FOR WHICH course/group
--   * case-insensitive lookup indexes
--
-- Provenance is not bookkeeping. It is the authorization key that lets an
-- instructor regenerate a password for an account their own course created,
-- while making it impossible for them to touch an account that existed
-- beforehand. See src/utils/account-provisioning.js.
--
-- NOTE ON HOW THIS ACTUALLY GETS APPLIED
-- This file is for operators who apply migrations by hand. The authoritative
-- mechanism is ensureProvisioningColumns() in src/utils/account-provisioning.js,
-- called from start() in src/server.js on every boot — the same pattern
-- ensureMfaColumns() uses, and for the same reason: config/postgres/*.sql only
-- runs on a fresh Postgres volume, so existing deployments would never see it.
-- The identical DDL therefore lives in three places by design.
--
-- Idempotent: safe to run repeatedly.
-- ============================================================================

-- === Password policy ========================================================
-- must_change_password     — login refuses to issue a session while TRUE and
--                            hands back a short-lived 'pwchange' stage token.
-- temp_password_expires_at — bounds a credential that was handed out rather
--                            than chosen. NULL means "no expiry".
-- activated_at             — first time the user set their own password.
ALTER TABLE cybercore_user
  ADD COLUMN IF NOT EXISTS must_change_password     BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS password_changed_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS temp_password_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS activated_at             TIMESTAMPTZ;

-- === Provenance =============================================================
-- provisioned_via ∈ self_register | admin_single | admin_batch | group_deploy
--                 | cle_import | cle_cohort.  NULL = pre-existing or unknown.
-- provisioned_ref  holds a course_id or group_id — TEXT so it takes either.
--
-- Deliberately NO CHECK constraint on provisioned_via: the boot-time function
-- re-runs this DDL on every start, and a CHECK evaluated against rows a newer
-- deploy already wrote would fail the whole statement. Validate in JS instead.
ALTER TABLE cybercore_user
  ADD COLUMN IF NOT EXISTS provisioned_by  UUID,
  ADD COLUMN IF NOT EXISTS provisioned_via TEXT,
  ADD COLUMN IF NOT EXISTS provisioned_ref TEXT;

CREATE INDEX IF NOT EXISTS idx_cybercore_user_provisioned
  ON cybercore_user (provisioned_via, provisioned_ref)
  WHERE provisioned_via IS NOT NULL;

-- === Case-insensitive lookup ================================================
-- ux_cybercore_user_email_lower is declared in config/postgres/001_init_db.sql,
-- but that file only runs on a fresh volume, so a database created before it
-- was added does not have the index. Recreate it here.
--
-- ⚠ RUN THIS FIRST, BY HAND, AND READ THE OUTPUT.
-- CREATE UNIQUE INDEX hard-fails if duplicates already exist, and there is no
-- safe automatic merge: both rows may own lanes, Guacamole accounts and CLE
-- enrollments keyed on their distinct user_ids. Deciding which row survives is
-- an operator judgement call, not something a migration should guess at.
--
--     SELECT lower(email) AS email_lc, count(*) AS n, array_agg(user_id) AS user_ids
--       FROM cybercore_user
--      GROUP BY 1 HAVING count(*) > 1;
--
CREATE UNIQUE INDEX IF NOT EXISTS ux_cybercore_user_email_lower
  ON cybercore_user (lower(email));

-- The login lookup matches `lower(email) = $1 OR lower(username) = $1`. Without
-- a matching expression index on username, that OR degrades to a sequential
-- scan on every sign-in attempt.
--
-- NOT unique: the username column carries a plain case-sensitive UNIQUE
-- constraint, so a pre-existing pair like 'Bob' and 'bob' is legal today and a
-- unique index here would fail on it. Uniqueness is enforced in application
-- code by allocateUsername().
CREATE INDEX IF NOT EXISTS idx_cybercore_user_username_lower
  ON cybercore_user (lower(username));
