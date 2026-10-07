-- ============================================================================
-- 028_activation_tokens.sql
-- ----------------------------------------------------------------------------
-- Single-use, time-bounded activation links.
--
-- When the CLE roster import creates an account for a student it does not email
-- them a password. It emails a link carrying a 32-byte random token, which the
-- student redeems once to set a password of their own choosing. Nothing that
-- functions as a credential ever comes to rest in a mailbox.
--
-- Only the SHA-256 of the token is stored. A read of this table — via adminer
-- (published on 0.0.0.0:8181), a backup, or a dump — must not yield a usable
-- link. See src/utils/activation.js.
--
-- Applied at runtime by ensureActivationTokens(); this file is for operators
-- who apply migrations by hand. Idempotent: safe to run repeatedly.
-- ============================================================================

CREATE TABLE IF NOT EXISTS cybercore_activation_token (
  token_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- No FK to cybercore_user: consistent with the rest of the schema, which
  -- keeps cross-table user references loose so a user row can be removed
  -- without a cascade storm. Orphans are pruned on the retention sweep.
  user_id      UUID NOT NULL,
  -- SHA-256 hex, not bcrypt. The token is 256 bits of uniform randomness, so
  -- there is no dictionary for a work factor to slow down; and the lookup needs
  -- an indexed equality match, which a per-row salt would make impossible.
  token_hash   TEXT NOT NULL UNIQUE,
  purpose      TEXT NOT NULL DEFAULT 'activate'
               CHECK (purpose IN ('activate','reset')),
  expires_at   TIMESTAMPTZ NOT NULL,
  -- Set by the same UPDATE that redeems the token, which is what makes
  -- single-use atomic rather than check-then-act.
  consumed_at  TIMESTAMPTZ,
  created_by   UUID,
  context      JSONB NOT NULL DEFAULT '{}'::jsonb,   -- e.g. { course_id }
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial: the only question ever asked of this table by user is "does this
-- person have a live invitation?", so consumed rows are dead weight in the index.
CREATE INDEX IF NOT EXISTS idx_activation_token_user
  ON cybercore_activation_token (user_id) WHERE consumed_at IS NULL;
