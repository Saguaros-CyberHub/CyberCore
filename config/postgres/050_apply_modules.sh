#!/usr/bin/env bash
set -euo pipefail

echo "[modules] ENABLED_MODULES=${ENABLED_MODULES:-<none>}"

# If nothing is set, skip quietly
[ -z "${ENABLED_MODULES:-}" ] && { echo "[modules] No modules enabled. Skipping."; exit 0; }

# Target the CyberCore database. CYBERCORE_DB_NAME / CYBERCORE_DB_USER are the
# canonical app-level variables (see utils/cybercore-db.js). Fall back to the
# Docker-standard POSTGRES_* vars so this script also works during container
# initdb where the app-level vars may not yet be injected.
DB_NAME="${CYBERCORE_DB_NAME:-${POSTGRES_DB:-cybercore_db}}"
DB_USER="${CYBERCORE_DB_USER:-${POSTGRES_USER:-cactus-admin}}"

IFS=',' read -r -a _mods <<< "${ENABLED_MODULES}"
for mod in "${_mods[@]}"; do
  file="/docker-entrypoint-initdb.d/modules/${mod}.sql"
  if [ -f "$file" ]; then
    echo "[modules] Applying module: ${mod} -> ${file}"
    psql -v ON_ERROR_STOP=1 -U "${DB_USER}" -d "${DB_NAME}" -f "$file"
  else
    echo "[modules] WARNING: No file for module '${mod}' at ${file}; skipping."
  fi
done

echo "[modules] Done."