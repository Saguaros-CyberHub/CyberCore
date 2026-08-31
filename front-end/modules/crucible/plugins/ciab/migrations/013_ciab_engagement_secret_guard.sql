-- 013_ciab_engagement_secret_guard.sql — Track B, phase B0.
--
-- ONE constraint: no secret-shaped KEY may be stored in issued_credentials.
--
-- WHY IT IS ALONE IN ITS OWN FILE, AND THIS IS AN HONESTY NOTE, NOT A STYLE
-- CHOICE. The expression casts jsonb to text. A CHECK constraint requires
-- IMMUTABLE functions; jsonb's output function is immutable by pg_proc default,
-- so this should be accepted — but it could NOT be executed before merge (this
-- checkout has no psql binary and no running docker daemon). If Postgres
-- refuses it, the file raises, src/plugin-loader.js:141-146 console.errors it,
-- and NOTHING ELSE IS LOST: 011's columns and 012's guards are already
-- committed by then, because the runner sends one file per pool.query().
--
-- If it does fail, delete this file. The guarantee does not live here.
--
-- WHAT THE REAL GUARANTEE IS. engagement-model.normalizeCredentialSlot
-- CONSTRUCTS each entry from a whitelist of known keys and never copies an
-- unrecognised one through, so a caller passing a password field loses the key
-- before the INSERT — it is not merely flagged. This constraint catches the
-- writer that is not that normalizer: a psql session, a future import script,
-- adminer. It matches a KEY, never a value, so a note reading "the password
-- policy is weak" is fine and a `password` field is not — and it cannot stop
-- someone hiding a secret inside `note` or `username`.
--
-- The pattern is deliberately structural rather than a literal blocklist:
-- '"[a-z0-9_]*(pass|secret|token|key|cred)[a-z0-9_]*"' catches password_hash,
-- temp_password, guac_password, api_key and private_key, which an alternation
-- of bare words would not (a trailing "_hash" defeats '"password"[[:space:]]*:').
-- It deliberately does NOT collide with the FORBIDDEN list that
-- test/audit-hygiene.test.js:152-156 scans for inside audit call arguments,
-- because this file contains no JavaScript.
--
-- KNOWN EXEMPTION, and it is intended: 'slot_key' contains 'key' and is a
-- legitimate structural field — it is the stable handle the per-lane secret is
-- minted AGAINST, never the secret — so it is neutralised by name below.
-- 'account_kind' is neutralised alongside it as the other structural key of the
-- pair; it does not match the pattern today, and stripping both in one place
-- means a later rename cannot quietly start tripping the guard. Everything else
-- containing 'key' — 'private_key' included — is refused.
--
-- Prohibition precedent and wording: 008_ciab_enrollment.sql:159-161.
--   NEVER a password. NEVER an activation token.
--
-- Same boot-rerun rules as every file in this directory: guarded by
-- pg_constraint name AND SCOPED BY conrelid, no DROP CONSTRAINT, nothing that
-- can raise on boot #2. The conrelid scope is not decoration: a constraint name
-- is unique per TABLE, not per database, so an unscoped conname lookup that a
-- same-named constraint on some OTHER relation happened to satisfy would skip
-- this ADD silently and forever -- and this is the one guard whose absence is
-- invisible until a secret is already stored. 014_ciab_modules.sql:631-635
-- documents the same hazard. The regclass cast sits below the to_regclass
-- guard, which has already RETURNed on a database without the table.

DO $b0secret$
BEGIN
  IF to_regclass('ciab_engagement') IS NULL THEN
    RAISE NOTICE '013: ciab_engagement not present — skipping';
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_name = 'ciab_engagement' AND column_name = 'issued_credentials'
  ) THEN
    RAISE NOTICE '013: 011 columns not present — skipping';
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ciab_engagement_no_secrets_ck'
       AND conrelid = 'ciab_engagement'::regclass
  ) THEN
    ALTER TABLE ciab_engagement
      ADD CONSTRAINT ciab_engagement_no_secrets_ck
      CHECK (
        -- Strip the two legitimate structural key names, then look for anything
        -- left that names a credential.
        replace(replace(issued_credentials::text, '"slot_key"', '"sk"'),
                '"account_kind"', '"ak"')
          !~* '"[a-z0-9_]*(pass|secret|token|key|cred)[a-z0-9_]*"[[:space:]]*:'
      );
  END IF;

  RAISE NOTICE '013: issued_credentials secret guard present';
END
$b0secret$;
