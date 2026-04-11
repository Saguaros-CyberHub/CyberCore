#!/bin/sh
set -e

echo "[init-n8n] Creating n8n role + database (if missing)..."

: "${N8N_DB_USER:?Missing N8N_DB_USER}"
: "${N8N_DB_PASSWORD:?Missing N8N_DB_PASSWORD}"
: "${N8N_DB_NAME:?Missing N8N_DB_NAME}"

# Must ALWAYS specify DB or psql defaults to db=username
CORE_DB="${POSTGRES_DB:?Missing POSTGRES_DB}"
CORE_USER="${POSTGRES_USER:?Missing POSTGRES_USER}"

# ---- Recommendation enforcement:
# .env values should NOT be wrapped in quotes.
# If someone wrote CORE_DB_PASSWORD='pass' or N8N_DB_PASSWORD="pass",
# Docker/Compose will include the quotes literally. Normalize here.
strip_wrapping_quotes() {
  # Removes one leading and one trailing matching quote if present
  v="$1"
  case "$v" in
    \"*\") printf "%s" "${v#\"}" | sed 's/"$//' ;;
    \'*\') printf "%s" "${v#\'}" | sed "s/'$//" ;;
    *)     printf "%s" "$v" ;;
  esac
}

N8N_DB_USER="$(strip_wrapping_quotes "$N8N_DB_USER")"
N8N_DB_PASSWORD="$(strip_wrapping_quotes "$N8N_DB_PASSWORD")"
N8N_DB_NAME="$(strip_wrapping_quotes "$N8N_DB_NAME")"
CORE_DB="$(strip_wrapping_quotes "$CORE_DB")"
CORE_USER="$(strip_wrapping_quotes "$CORE_USER")"

# Escape single quotes for SQL string literal safety
N8N_DB_PASSWORD_SQL=$(printf "%s" "$N8N_DB_PASSWORD" | sed "s/'/''/g")

# 1. Create role if needed
psql -v ON_ERROR_STOP=1 \
  -U "$CORE_USER" \
  -d "$CORE_DB" <<-EOSQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${N8N_DB_USER}') THEN
    CREATE ROLE "${N8N_DB_USER}" LOGIN PASSWORD '${N8N_DB_PASSWORD_SQL}';
  END IF;
END
\$\$;
EOSQL

# 2. Check if DB exists
db_exists=$(psql -U "$CORE_USER" -d "$CORE_DB" -tAc \
  "SELECT 1 FROM pg_database WHERE datname='${N8N_DB_NAME}'")

if [ "$db_exists" != "1" ]; then
  echo "[init-n8n] Creating database ${N8N_DB_NAME} owned by ${N8N_DB_USER}..."
  psql -U "$CORE_USER" -d "$CORE_DB" <<-EOSQL
CREATE DATABASE "${N8N_DB_NAME}" OWNER "${N8N_DB_USER}";
GRANT ALL PRIVILEGES ON DATABASE "${N8N_DB_NAME}" TO "${N8N_DB_USER}";
EOSQL
else
  echo "[init-n8n] Database ${N8N_DB_NAME} already exists"
fi

echo "[init-n8n] Done."