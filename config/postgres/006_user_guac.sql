-- 006_user_guac.sql
-- Adds a per-user Guacamole password column so that every CyberCore account has
-- a corresponding Guacamole user created at registration (not lazily at first
-- workstation deploy). The column is the single source of truth; vi.metadata
-- still carries guac_connection_id and guac_user for backward compat.
-- guac_password is stored encrypted with pgp_sym_encrypt (pgcrypto, already enabled).
-- The decryption key comes from GUAC_ENCRYPT_KEY in the app environment — never stored in the DB.
ALTER TABLE cybercore_user ADD COLUMN IF NOT EXISTS guac_password BYTEA;
