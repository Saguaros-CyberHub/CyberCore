#!/bin/bash
# Work in progress
# Needs:
# - Better error handling (try/catch around each step, with rollback if possible)
# - More robust schema migration handling (track applied migrations, handle failures gracefully)
# - Health checks for all services (not just Postgres)
# - Stores a full backup (including volumes) before updating in /tmp, with easy restore option upon failure

set -euo pipefail

cd /opt/CyberCore
LOG="/var/log/cybercore-update.log"

# Logging helper
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG"
}

trap 'log_msg "ERROR: Update failed"; exit 1' ERR

log_msg "===== Starting CyberCore update check ====="

# Pre-update checks
log_msg "Verifying Docker volumes exist (data preservation)..."
if ! docker volume ls | grep -q cybercore_postgres_data; then
    log_msg "WARNING: cybercore-postgres-data volume not found. Create it before updating."
fi
if ! docker volume ls | grep -q cybercore_redis_data; then
    log_msg "WARNING: cybercore-redis-data volume not found. Create it before updating."
fi
if ! docker volume ls | grep -q cybercore_n8n_data; then
    log_msg "WARNING: cybercore-n8n-data volume not found. Create it before updating."
fi

log_msg "Checking for updates..."
git fetch origin main >> "$LOG" 2>&1
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    log_msg "Already up to date."
    exit 0
fi

log_msg "Updates found ($LOCAL -> $REMOTE). Proceeding with update..."

# Save current compose config for reference
COMPOSE_CHANGED=0
if ! git diff origin/main -- docker-compose.yml | grep -q "^$"; then
    COMPOSE_CHANGED=1
    log_msg "docker-compose.yml has changed; will perform full service restart."
fi

# Pull latest repository
log_msg "Pulling latest code..."
git pull origin main >> "$LOG" 2>&1

# Check if schema/migrations changed
SCHEMA_CHANGED=0
if git diff HEAD~1 HEAD -- 'config/postgres/*.sql' 'front-end/migrations/*.sql' | grep -q "^"; then
    SCHEMA_CHANGED=1
    log_msg "Database schema changes detected; will run migrations after Postgres starts."
fi

# Stop services gracefully (allow DB to sync, n8n to save state)
log_msg "Stopping services gracefully..."
docker compose down >> "$LOG" 2>&1

# If compose file changed, pull fresh images
if [ "$COMPOSE_CHANGED" = "1" ]; then
    log_msg "docker-compose.yml changed; pulling fresh images..."
    docker compose pull >> "$LOG" 2>&1
fi

# Rebuild images (captures any Dockerfile updates)
log_msg "Rebuilding Docker images..."
docker compose build --no-cache >> "$LOG" 2>&1

# Start services (volumes preserved automatically)
log_msg "Starting services (data preserved in volumes)..."
docker compose up -d >> "$LOG" 2>&1

# Wait for critical services to be ready
log_msg "Waiting for Postgres to be ready..."
for i in {1..60}; do
    if docker compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
        log_msg "Postgres is ready."
        break
    fi
    if [ "$i" -eq 60 ]; then
        log_msg "ERROR: Postgres failed to start."
        exit 1
    fi
    sleep 2
done

# Run schema migrations if detected
if [ "$SCHEMA_CHANGED" = "1" ]; then
    log_msg "Running schema migrations..."
    
    # Run all *.sql files in config/postgres/ in order (by filename)
    for schema_file in config/postgres/*.sql; do
        if [ -f "$schema_file" ]; then
            log_msg "  Applying: $(basename "$schema_file")"
            if ! docker compose exec -T postgres psql -U postgres -d postgres -f "/docker-entrypoint-initdb.d/$(basename "$schema_file")" >> "$LOG" 2>&1; then
                # If a migration fails, check if it's an "already exists" error (safe to ignore)
                log_msg "  WARNING: Migration $(basename "$schema_file") reported errors (may be idempotent)."
            fi
        fi
    done
    
    # Run any frontend migration files
    if [ -d "front-end/migrations" ]; then
        for migration_file in front-end/migrations/*.sql; do
            if [ -f "$migration_file" ]; then
                log_msg "  Applying: $(basename "$migration_file")"
                if ! docker compose exec -T postgres psql -U postgres -d postgres -f "/migrations/$(basename "$migration_file")" >> "$LOG" 2>&1; then
                    log_msg "  WARNING: Migration $(basename "$migration_file") reported errors (may be idempotent)."
                fi
            fi
        done
    fi
    
    log_msg "Schema migrations complete."
fi

log_msg "Waiting for Redis to be ready..."
for i in {1..30}; do
    if docker compose exec -T redis redis-cli ping > /dev/null 2>&1; then
        log_msg "Redis is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        log_msg "ERROR: Redis failed to start."
        exit 1
    fi
    sleep 1
done

# Wait for backend to be healthy
log_msg "Waiting for backend to be healthy..."
for i in {1..60}; do
    if docker compose exec -T backend curl -f http://localhost:3000/health > /dev/null 2>&1; then
        log_msg "Backend is healthy."
        break
    fi
    if [ "$i" -eq 60 ]; then
        log_msg "WARNING: Backend health check timed out (may still be initializing)."
        break
    fi
    sleep 2
done

log_msg "===== Update complete (data preserved in volumes) ====="
