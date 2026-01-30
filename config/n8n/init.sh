#!/usr/bin/env sh
set -eu

# -------------------------------------------------------------------
# Expected docker-compose strategy:
#   Host: ./data/n8n        -> Container: /home/node            (RW persistent)
#   Host: ./config/n8n/*    -> Container: /home/node/.n8n/config/* (RO seed files)
# -------------------------------------------------------------------

DATA_ROOT="${N8N_DATA_ROOT:-/home/node}"

# IMPORTANT:
# Treat DATA_ROOT as the n8n "user folder" (the persistent mount root).
export N8N_USER_FOLDER="${N8N_USER_FOLDER:-$DATA_ROOT}"

# Import locations:
WF_DIR_DEFAULT_1="$N8N_USER_FOLDER/config/workflows"
CREDS_DIR_DEFAULT_1="$N8N_USER_FOLDER/config/credentials"

# Optional legacy fallbacks if you ever mount /config/*
WF_DIR_DEFAULT_2="/config/workflows"
CREDS_DIR_DEFAULT_2="/config/credentials"

pick_dir() {
  # Usage: pick_dir preferred fallback
  if [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null || true)" ]; then
    echo "$1"
  else
    echo "$2"
  fi
}

WF_DIR="${N8N_WORKFLOWS_DIR:-$(pick_dir "$WF_DIR_DEFAULT_1" "$WF_DIR_DEFAULT_2")}"
CREDS_DIR="${N8N_CREDENTIALS_DIR:-$(pick_dir "$CREDS_DIR_DEFAULT_1" "$CREDS_DIR_DEFAULT_2")}"

DB_HOST="${DB_POSTGRESDB_HOST:-postgres}"
DB_PORT="${DB_POSTGRESDB_PORT:-5432}"

REDIS_HOST="${QUEUE_BULL_REDIS_HOST:-redis}"
REDIS_PORT="${QUEUE_BULL_REDIS_PORT:-6379}"

SENTINEL="${N8N_USER_FOLDER}/.import_done"

echo "[n8n-init] DATA_ROOT:       $DATA_ROOT"
echo "[n8n-init] N8N_USER_FOLDER: $N8N_USER_FOLDER"
echo "[n8n-init] Workflows dir:   $WF_DIR"
echo "[n8n-init] Creds dir:       $CREDS_DIR"
echo "[n8n-init] Sentinel:        $SENTINEL"

# Ensure user folder exists (should be the persistent mount root)
mkdir -p "$N8N_USER_FOLDER"

wait_tcp() {
  host="$1"
  port="$2"
  name="$3"
  echo "[n8n-init] Waiting for $name at ${host}:${port}..."
  for i in $(seq 1 60); do
    nc -z "$host" "$port" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# --- Wait for Postgres TCP ---
wait_tcp "$DB_HOST" "$DB_PORT" "Postgres" || {
  echo "[n8n-init] ERROR: Postgres not reachable after retries."
  echo "[n8n-init] Starting n8n anyway so it can surface the underlying DB error..."
  exec n8n start
}

# --- If queue mode, wait for Redis TCP ---
if [ "${EXECUTIONS_MODE:-}" = "queue" ]; then
  wait_tcp "$REDIS_HOST" "$REDIS_PORT" "Redis" || {
    echo "[n8n-init] ERROR: Redis not reachable after retries."
    echo "[n8n-init] Starting n8n anyway so it can surface the underlying Redis error..."
    exec n8n start
  }
fi

# --- Verify DB is not just reachable, but ready (migrations done / schema usable) ---
echo "[n8n-init] Verifying n8n DB connectivity via CLI..."
DB_OK=0
for i in $(seq 1 90); do
  if n8n list:workflow >/dev/null 2>&1; then
    DB_OK=1
    break
  fi
  sleep 1
done

if [ "$DB_OK" -ne 1 ]; then
  echo "[n8n-init] ERROR: n8n CLI could not reach DB after retries. Not importing, not writing sentinel."
  echo "[n8n-init] Starting n8n anyway so it can surface the underlying DB error..."
  exec n8n start
fi

echo "[n8n-init] DB connectivity confirmed."

# --- Guard: on a brand-new instance, imports can fail before an owner/user exists ---
# In dev: open UI once, complete "Owner setup", then restart and imports will run.
HAS_USER=0
if n8n user-management:list >/dev/null 2>&1; then
  # If command exists, check if any users are present
  if [ "$(n8n user-management:list 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ]; then
    HAS_USER=1
  fi
else
  # If the CLI command isn't available in this build, just proceed (best-effort).
  HAS_USER=1
fi

if [ "$HAS_USER" -ne 1 ]; then
  echo "[n8n-init] No users detected yet (fresh install). Skipping import this boot."
  echo "[n8n-init] Complete Owner setup in the UI, then restart to import."
  exec n8n start
fi

# --- Import once (only after DB confirmed and user exists) ---
if [ -f "$SENTINEL" ]; then
  echo "[n8n-init] Sentinel exists; skipping import."
else
  IMPORT_FAILED=0

  if [ -d "$WF_DIR" ] && [ -n "$(ls -A "$WF_DIR" 2>/dev/null || true)" ]; then
    echo "[n8n-init] Importing workflows from: $WF_DIR"
    # NOTE: If your exports include IDs/publish history, you may still hit webhook/history issues.
    # Easiest dev fix: re-export workflows without history/IDs, or sanitize JSON (see notes below).
    if ! n8n import:workflow --input="$WF_DIR" --separate --yes; then
      echo "[n8n-init] Workflow import had errors."
      IMPORT_FAILED=1
    fi
  else
    echo "[n8n-init] No workflows to import."
  fi

  if [ -d "$CREDS_DIR" ] && [ -n "$(ls -A "$CREDS_DIR" 2>/dev/null || true)" ]; then
    echo "[n8n-init] Importing credentials from: $CREDS_DIR"
    if ! n8n import:credentials --input="$CREDS_DIR" --separate --yes; then
      echo "[n8n-init] Credential import had errors (often encryption key mismatch)."
      IMPORT_FAILED=1
    fi
  else
    echo "[n8n-init] No credentials to import."
  fi

  if [ "$IMPORT_FAILED" -eq 0 ]; then
    touch "$SENTINEL"
    echo "[n8n-init] Import complete; sentinel written."
  else
    echo "[n8n-init] Import had errors; sentinel NOT written so it will retry next boot."
  fi
fi

echo "[n8n-init] Starting n8n..."
exec n8n start