#!/bin/sh
# =============================================================================
# Guacamole — PostgreSQL schema initializer
# Runs once as the guacamole-init service (restart: "no").
# Downloads the official schema SQL from Apache's GitHub for the pinned
# Guacamole version and applies it against guacamole_db. Safe to re-run —
# "already exists" errors are suppressed.
# =============================================================================
set -e

GUAC_VERSION="${GUAC_VERSION:-1.5.5}"
SCHEMA_BASE="https://raw.githubusercontent.com/apache/guacamole-client/${GUAC_VERSION}/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-postgresql/schema"

echo ">>> [guacamole-init] Fetching schema for Guacamole ${GUAC_VERSION}..."
curl -fsSL -o /tmp/001-create-schema.sql     "${SCHEMA_BASE}/001-create-schema.sql"
curl -fsSL -o /tmp/002-create-admin-user.sql "${SCHEMA_BASE}/002-create-admin-user.sql"

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

apply /tmp/001-create-schema.sql
apply /tmp/002-create-admin-user.sql

echo ">>> [guacamole-init] Schema ready."
echo ">>> [guacamole-init] Default credentials: guacadmin / guacadmin"
echo ">>> [guacamole-init] Change the guacadmin password immediately after first login."
