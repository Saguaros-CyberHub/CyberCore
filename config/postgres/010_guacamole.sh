#!/bin/bash
# =============================================================================
# Guacamole — PostgreSQL database and user bootstrap
# Runs once on fresh postgres volume via docker-entrypoint-initdb.d.
# Uses GUAC_DB_* env vars passed from docker-compose.yml.
# =============================================================================
set -e

echo ">>> [010_guacamole] Creating Guacamole database and user..."

# ON_ERROR_STOP=0 so the script doesn't abort if the DB or user already exists
# (e.g. re-running against a non-empty volume).
psql -v ON_ERROR_STOP=0 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE USER "${GUAC_DB_USER}" WITH ENCRYPTED PASSWORD '${GUAC_DB_PASSWORD}';
  CREATE DATABASE "${GUAC_DB_NAME}" OWNER "${GUAC_DB_USER}";
  GRANT ALL PRIVILEGES ON DATABASE "${GUAC_DB_NAME}" TO "${GUAC_DB_USER}";
EOSQL

echo ">>> [010_guacamole] Done — database '${GUAC_DB_NAME}' ready."