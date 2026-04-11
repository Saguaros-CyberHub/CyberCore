#!/bin/bash
set -euo pipefail

cd /opt/CyberCore
LOG="/var/log/cybercore-update.log"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Checking for updates..." >> "$LOG"

git fetch origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Already up to date." >> "$LOG"
    exit 0
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Updates found ($LOCAL -> $REMOTE). Pulling..." >> "$LOG"
git pull origin main >> "$LOG" 2>&1

# Rebuild and restart only changed services
docker compose up -d --build --remove-orphans >> "$LOG" 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') - Update complete." >> "$LOG"
