#!/bin/sh
# =============================================================================
# CyberHub — Default admin user bootstrap
# Runs once on fresh postgres volume via docker-entrypoint-initdb.d.
# Creates one admin user from CORE_DB_USER / CORE_DB_PASSWORD if no admin
# already exists. Safe to re-run — skips if an admin is already present.
# Password is hashed at insert time by pgcrypto (bcrypt, cost 12).
# =============================================================================
set -e

: "${CORE_DB_USER:?Missing CORE_DB_USER}"
: "${CORE_DB_PASSWORD:?Missing CORE_DB_PASSWORD}"
: "${ADMIN_EMAIL:?Missing ADMIN_EMAIL}"

POSTGRES_USER="${POSTGRES_USER:?Missing POSTGRES_USER}"
POSTGRES_DB="${POSTGRES_DB:?Missing POSTGRES_DB}"

# Escape single quotes for SQL string literal safety
USERNAME_SQL=$(printf "%s" "$CORE_DB_USER"     | sed "s/'/''/g")
PASSWORD_SQL=$(printf "%s" "$CORE_DB_PASSWORD" | sed "s/'/''/g")
EMAIL_SQL=$(printf "%s"    "$ADMIN_EMAIL"      | sed "s/'/''/g")

echo ">>> [005_admin_user] Seeding default admin user (${ADMIN_EMAIL})..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  INSERT INTO cybercore_user (
    username, email, first_name, last_name,
    organization, email_verified, auth_provider,
    password_hash, password_alg, status, active, role
  )
  SELECT
    '${USERNAME_SQL}',
    '${EMAIL_SQL}',
    'Admin',
    'User',
    'CyberHub',
    TRUE,
    'local',
    crypt('${PASSWORD_SQL}', gen_salt('bf', 12)),
    'bcrypt',
    'active',
    TRUE,
    'admin'
  WHERE NOT EXISTS (
    SELECT 1 FROM cybercore_user WHERE role = 'admin'
  );
EOSQL

echo ">>> [005_admin_user] Done."
