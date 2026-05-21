#!/bin/sh
# =============================================================================
# Guacamole — PostgreSQL schema initializer
# Runs once as the guacamole-init service (restart: "no").
# Applies the bundled schema SQL against guacamole_db. Safe to re-run —
# "already exists" errors are suppressed.
# =============================================================================
set -e

echo ">>> [guacamole-init] Applying schema to ${GUAC_DB_NAME} on ${GUAC_DB_HOST}..."

apply() {
  psql \
    -h "${GUAC_DB_HOST:-postgres}" \
    -U "${GUAC_DB_USER}" \
    -d "${GUAC_DB_NAME}" \
    -f "$1" 2>&1 \
  | grep -v "already exists" \
  | grep -v "^$" \
  || true
}

apply /schema/001-create-schema.sql
apply /schema/002-create-admin-user.sql

echo ">>> [guacamole-init] Schema ready."
echo ">>> [guacamole-init] Default credentials: guacadmin / guacadmin"
echo ">>> [guacamole-init] Change the guacadmin password immediately after first login."
