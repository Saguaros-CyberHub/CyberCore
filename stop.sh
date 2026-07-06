#!/usr/bin/env bash
# ============================================================================
# stop.sh — bring the CyberCore environment down (reverse of start.sh).
#
#   1. Module transit gateway LXCs (hostname *-gw) on a Proxmox node
#   2. Docker compose stack
#
# Volumes/data are preserved (no `down -v`, no `pct destroy`). Run from the repo
# root. Safe to re-run.
#
# Flags:
#   --stack-only     only the docker compose stack
#   --gateways-only  only the transit gateway LXCs
#   --down           remove stack containers/networks ('docker compose down')
#                    instead of just stopping them (volumes still preserved)
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}==>${NC} $*"; }
info() { echo -e "${BLUE}   ${NC} $*"; }
warn() { echo -e "${YELLOW}!! ${NC} $*" >&2; }
section() { echo; echo -e "${BOLD}### $* ###${NC}"; }

DO_STACK=1; DO_GW=1; STACK_DOWN=0
for a in "$@"; do case "$a" in
  --stack-only)    DO_GW=0 ;;
  --gateways-only) DO_STACK=0 ;;
  --down)          STACK_DOWN=1 ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) warn "unknown flag: $a" ;;
esac; done

on_proxmox() { command -v pct >/dev/null 2>&1; }
gw_ctids() { pct list 2>/dev/null | awk 'NR>1 && $NF ~ /-gw$/ {print $1}'; }

stop_gateways() {
  [ "$DO_GW" = "1" ] || return 0
  section "Transit gateway LXCs"
  on_proxmox || { info "not a Proxmox node — no gateway LXCs here."; return 0; }
  local ids; ids="$(gw_ctids)"
  [ -n "$ids" ] || { info "no *-gw containers found."; return 0; }
  local id
  for id in $ids; do
    if [ "$(pct status "$id" 2>/dev/null)" = "status: running" ]; then
      log "Stopping gateway CT $id..."; pct stop "$id" || warn "failed to stop CT $id"
    else
      info "CT $id already stopped."
    fi
  done
}

stop_stack() {
  [ "$DO_STACK" = "1" ] || return 0
  section "Docker stack"
  if ! command -v docker >/dev/null 2>&1; then warn "docker not on PATH — skipping stack."; return 0; fi
  [ -f "$SCRIPT_DIR/docker-compose.yml" ] || { warn "no docker-compose.yml here — skipping stack."; return 0; }
  if [ "$STACK_DOWN" = "1" ]; then
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" down
    log "Stack removed (volumes preserved)."
  else
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" stop
    log "Stack stopped (containers preserved)."
  fi
}

stop_gateways
stop_stack
log "stop.sh done."
