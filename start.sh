#!/usr/bin/env bash
# ============================================================================
# start.sh — bring the CyberCore environment up.
#
#   1. Docker compose stack (postgres, redis, app, caddy, guacamole, ...)
#   2. Module transit gateway LXCs (hostname *-gw) on a Proxmox node
#
# Run from the repo root. Safe to re-run. Mirrors stop.sh.
#
# Flags:
#   --stack-only     only the docker compose stack
#   --gateways-only  only the transit gateway LXCs
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}==>${NC} $*"; }
info() { echo -e "${BLUE}   ${NC} $*"; }
warn() { echo -e "${YELLOW}!! ${NC} $*" >&2; }
section() { echo; echo -e "${BOLD}### $* ###${NC}"; }

DO_STACK=1; DO_GW=1
for a in "$@"; do case "$a" in
  --stack-only)    DO_GW=0 ;;
  --gateways-only) DO_STACK=0 ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) warn "unknown flag: $a" ;;
esac; done

on_proxmox() { command -v pct >/dev/null 2>&1; }
gw_ctids() { pct list 2>/dev/null | awk 'NR>1 && $NF ~ /-gw$/ {print $1}'; }

start_stack() {
  [ "$DO_STACK" = "1" ] || return 0
  section "Docker stack"
  if ! command -v docker >/dev/null 2>&1; then warn "docker not on PATH — skipping stack."; return 0; fi
  [ -f "$SCRIPT_DIR/docker-compose.yml" ] || { warn "no docker-compose.yml here — skipping stack."; return 0; }
  docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d
  log "Stack started. Status:"
  docker compose -f "$SCRIPT_DIR/docker-compose.yml" ps || true
}

start_gateways() {
  [ "$DO_GW" = "1" ] || return 0
  section "Transit gateway LXCs"
  on_proxmox || { info "not a Proxmox node — no gateway LXCs here."; return 0; }
  local ids; ids="$(gw_ctids)"
  [ -n "$ids" ] || { info "no *-gw containers found."; return 0; }
  local id
  for id in $ids; do
    if [ "$(pct status "$id" 2>/dev/null)" = "status: running" ]; then
      info "CT $id already running."
    else
      log "Starting gateway CT $id..."; pct start "$id" || warn "failed to start CT $id"
    fi
  done
}

start_stack
start_gateways
log "start.sh done."
