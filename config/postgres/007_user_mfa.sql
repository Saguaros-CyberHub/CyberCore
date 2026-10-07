-- 007_user_mfa.sql
-- Adds TOTP multi-factor authentication state to cybercore_user.
--   mfa_enabled        — true once the user has verified their authenticator
--   mfa_secret         — the base32 TOTP secret, encrypted with pgp_sym_encrypt
--                        (pgcrypto). Key comes from MFA_ENCRYPT_KEY (falls back
--                        to GUAC_ENCRYPT_KEY) in the app environment — never the DB.
--   mfa_recovery_codes — JSONB array of { hash, used } one-time backup codes
--                        (bcrypt-hashed; plaintext is shown to the user once).
--   mfa_enrolled_at    — when MFA was activated.
-- These are also applied at runtime by ensureMfaColumns() in server.js so that
-- existing databases (where this init script does not re-run) get the columns.
ALTER TABLE cybercore_user
  ADD COLUMN IF NOT EXISTS mfa_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS mfa_secret         BYTEA,
  ADD COLUMN IF NOT EXISTS mfa_recovery_codes JSONB,
  ADD COLUMN IF NOT EXISTS mfa_enrolled_at    TIMESTAMPTZ;
