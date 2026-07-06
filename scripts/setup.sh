#!/usr/bin/env bash
# ============================================================================
# setup.sh — post-install production hardening for CyberCore.
#
# Run AFTER install.sh, as root, from the repo root:
#
#   sudo ./scripts/install.sh      # provisions the host + orchestrator VM, writes .env
#   sudo ./scripts/setup.sh        # makes the environment prod-ready
#
# What this does (all idempotent, safe to re-run):
#   1. Preflight — repo root, required tools, .env present
#   2. Cleans dev artifacts that must not ship to prod:
#      (Anything removed is moved to .cybercore-backup/<ts>/, never hard-deleted
#       unless --purge is given.)
#   3. Normalizes malformed env files (strips spaces/quotes that break
#      Docker Compose env_file parsing).
#   4. Fills any remaining REPLACE_ME / weak-default secrets with freshly
#      generated values — WITHOUT overwriting real values install.sh already
#      wrote. API keys that can't be generated are reported, not invented.
#   5. Hardens file permissions (600 on every .env, +x on scripts).
#   6. Validates docker compose files and (best-effort) ansible playbooks.
#   7. Optionally brings the stack up and waits for healthchecks (--up).
#   8. Prints a readiness report + the manual TODOs that remain.
#
# On a Proxmox node it can also stand up the module transit gateways and the
# lab templates from infrastructure/proxmox-templates:
#   9. --gateways : for each enabled module, create an Alpine LXC transit
#      gateway (static wan0 + lan0 owning the module gateway IP), then run the
#      generic module-gateway.yml against it via a throwaway generated inventory.
#  10. --templates: build + configure + seal templates — the per-module lane
#      gateway LXCs and the rocky-base VM (from its cloud image). Templates that
#      need per-site input (mint, rocky-AD/CIS, kali, zabbix) are flagged, not built.
#      --infra = --gateways --templates. All idempotent (existing VMIDs skipped).
#
# Gateway model: the module transit gateway is an unprivileged Alpine LXC that
# owns the module gateway IP on lan0 and does DHCP/DNS/NAT/anti-breakout. The
# module bridge is pure L2 (install.sh no longer puts the IP on the bridge). If
# a legacy IP'd bridge is found, setup.sh moves the address off it automatically.
#
# Flags:
#   --yes          non-interactive; assume "yes" to cleanup prompts
#   --up           bring the docker compose stack up and wait for health
#   --gateways     create + configure module transit gateway LXCs (Proxmox node)
#   --templates    build + configure + seal lab templates (lane gateways, base VMs)
#   --infra        shorthand for --gateways --templates
#   --no-clean     skip the cleanup step
#   --purge        hard-delete cleaned artifacts instead of backing them up
#   --dry-run      print what would change, change nothing
# ============================================================================
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # this script lives in scripts/
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"                    # project root is one level up
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Output helpers (matched to install.sh)
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}==>${NC} $*"; }
info() { echo -e "${BLUE}   ${NC} $*"; }
warn() { echo -e "${YELLOW}!! ${NC} $*" >&2; }
err()  { echo -e "${RED}ERROR:${NC} $*" >&2; }
die()  { err "$*"; exit 1; }
section() { echo; echo -e "${BOLD}### $* ###${NC}"; }

gen_secret() { openssl rand -hex 32; }

# Things the user must supply themselves; surfaced in the final report.
declare -a MANUAL_TODOS=()
todo() { MANUAL_TODOS+=("$*"); }

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
ASSUME_YES=0; DO_UP=0; DO_CLEAN=1; PURGE=0; DRY_RUN=0; DO_GW=0; DO_TPL=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y)       ASSUME_YES=1 ;;
    --up)           DO_UP=1 ;;
    --gateways)     DO_GW=1 ;;
    --templates)    DO_TPL=1 ;;
    --infra)        DO_GW=1; DO_TPL=1 ;;
    --no-clean)     DO_CLEAN=0 ;;
    --purge)        PURGE=1 ;;
    --dry-run)      DRY_RUN=1 ;;
    -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown flag: $arg (try --help)" ;;
  esac
done

run() { # execute unless dry-run; echo either way
  if [ "$DRY_RUN" = "1" ]; then info "(dry-run) $*"; else eval "$@"; fi
}

confirm() { # confirm "prompt"  -> 0 yes / 1 no ; auto-yes with --yes
  [ "$ASSUME_YES" = "1" ] && return 0
  local reply; read -r -p "$(echo -e "${BOLD}$1${NC} [y/N]: ")" reply || true
  [[ "${reply,,}" == y* ]]
}

# ---------------------------------------------------------------------------
# .env helpers — tolerant of "KEY=VALUE" and "KEY = VALUE"
# ---------------------------------------------------------------------------
env_get() { # env_get FILE KEY
  [ -f "$1" ] || return 1
  awk -v k="$2" '
    $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*/, "")
      gsub(/^["'\'']+|["'\'']+[[:space:]]*$/, "")
      print; exit
    }' "$1"
}

env_set() { # env_set FILE KEY VALUE  (replace in place, or append if missing)
  local file="$1" key="$2" val="$3" tmp
  if [ "$DRY_RUN" = "1" ]; then info "(dry-run) set $key in ${file#$REPO_ROOT/}"; return 0; fi
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$val" '
    BEGIN { done=0 }
    $0 ~ "^[[:space:]]*"k"[[:space:]]*=" && !done { print k"="v; done=1; next }
    { print }
    END { if (!done) print k"="v }
  ' "$file" > "$tmp" && mv "$tmp" "$file"
}

# Rewrite "KEY = \"val\"" -> "KEY=val"; leaves comments/blank lines alone.
normalize_env() {
  local file="$1" tmp changed=0
  [ -f "$file" ] || return 0
  # Only rewrite if it actually contains spaced/quoted assignments.
  grep -qE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]+=|=[[:space:]]*["'\'']' "$file" || return 0
  changed=1
  if [ "$DRY_RUN" = "1" ]; then info "(dry-run) normalize ${file#$REPO_ROOT/}"; return 0; fi
  tmp="$(mktemp)"
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { print; next }
    /=/ {
      eq = index($0, "=")
      key = substr($0, 1, eq-1); val = substr($0, eq+1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      gsub(/^["'\'']|["'\'']$/, "", val)
      print key"="val; next
    }
    { print }
  ' "$file" > "$tmp" && mv "$tmp" "$file"
  [ "$changed" = "1" ] && info "normalized ${file#$REPO_ROOT/}"
}

# A value is a placeholder if empty or a known weak/template default.
is_placeholder() {
  case "$1" in
    ""|REPLACE_ME|ChangeMe|changeme|CHANGEME|admin|keycloak|guacadmin|cyberpass|password|changethis) return 0 ;;
    *) return 1 ;;
  esac
}

# Generate secrets for the given keys only if currently a placeholder.
fill_secrets() { # fill_secrets FILE KEY [KEY...]
  local file="$1"; shift
  [ -f "$file" ] || return 0
  local key cur
  for key in "$@"; do
    cur="$(env_get "$file" "$key" || true)"
    if is_placeholder "$cur"; then
      env_set "$file" "$key" "$(gen_secret)"
      [ "$DRY_RUN" = "1" ] || info "generated $key in ${file#$REPO_ROOT/}"
    fi
  done
}

# Warn (and record TODO) for keys that need a human-supplied value.
require_manual() { # require_manual FILE KEY "description"
  local file="$1" key="$2" desc="$3" cur
  [ -f "$file" ] || return 0
  cur="$(env_get "$file" "$key" || true)"
  if is_placeholder "$cur"; then
    warn "$key is unset in ${file#$REPO_ROOT/} — $desc"
    todo "Set ${key} in ${file#$REPO_ROOT/} ($desc)"
  fi
}

# ---------------------------------------------------------------------------
# 1. Preflight
# ---------------------------------------------------------------------------
preflight() {
  section "Preflight"
  [ -f "$REPO_ROOT/docker-compose.yml" ] || die "Run from the repo root (docker-compose.yml not found here)."
  for bin in openssl awk grep; do
    command -v "$bin" >/dev/null 2>&1 || die "Required tool '$bin' not found."
  done
  if [ ! -f "$REPO_ROOT/.env" ]; then
    warn ".env not found — has install.sh run yet? Copying from example.env so we can fill it."
    [ -f "$REPO_ROOT/example.env" ] && run "cp '$REPO_ROOT/example.env' '$REPO_ROOT/.env'" \
      || die "No .env and no example.env to seed from."
  fi
  command -v docker >/dev/null 2>&1 || warn "docker not on PATH — compose validation and --up will be skipped."
  [ "$DRY_RUN" = "1" ] && warn "DRY RUN — no files will be changed."
  log "Preflight OK."
}

# ---------------------------------------------------------------------------
# 2. Clean dev artifacts
# ---------------------------------------------------------------------------
BACKUP_DIR="$REPO_ROOT/.cybercore-backup/$(date +%Y%m%d-%H%M%S)"

stash() { # stash PATH  -> back up (or purge) a working-tree artifact
  local path="$1"
  [ -e "$path" ] || return 0
  local rel="${path#$REPO_ROOT/}"
  if [ "$PURGE" = "1" ]; then
    run "rm -rf '$path'"
    info "purged $rel"
  else
    run "mkdir -p '$BACKUP_DIR/$(dirname "$rel")'"
    run "mv '$path' '$BACKUP_DIR/$rel'"
    info "moved $rel -> ${BACKUP_DIR#$REPO_ROOT/}/$rel"
  fi
}

clean_artifacts() {
  [ "$DO_CLEAN" = "1" ] || { info "cleanup skipped (--no-clean)"; return 0; }
  section "Cleaning dev artifacts"

  local kcdb="$REPO_ROOT/infrastructure/authentication/data/keycloak-db"
  if [ -d "$kcdb" ]; then
    local sz; sz="$(du -sh "$kcdb" 2>/dev/null | cut -f1 || echo '?')"
    warn "Found a live Keycloak Postgres data dir ($sz). Shipping it makes Keycloak"
    warn "boot a stale cluster (old creds, no clean init). It should be removed."
    if confirm "Remove infrastructure/authentication/data/keycloak-db?"; then
      stash "$kcdb"
    else
      todo "Remove infrastructure/authentication/data/keycloak-db before going to prod (stale DB state)."
    fi
  fi

  # macOS cruft
  local ds count=0
  while IFS= read -r ds; do stash "$ds"; count=$((count+1)); done \
    < <(find "$REPO_ROOT/infrastructure" -name .DS_Store 2>/dev/null)
  [ "$count" -gt 0 ] && info "cleaned $count .DS_Store file(s)" || true
}

# ---------------------------------------------------------------------------
# 3+4. Env normalization & secret filling
# ---------------------------------------------------------------------------
harden_env() {
  section "Env: normalize + fill secrets"

  # Only the root .env matters: we use the stack's Guacamole and SSO is dropped,
  # so the standalone infrastructure/{authentication,external-services} envs are
  # not deployed and are left alone.
  local ROOT_ENV="$REPO_ROOT/.env"

  # Fill only what install.sh may have left as REPLACE_ME (never clobbers real values).
  fill_secrets "$ROOT_ENV" \
    CORE_DB_PASSWORD JWT_SECRET SESSION_SECRET VULN_ASSETS_SECRET \
    FTP_PASSWORD GUAC_ADMIN_PASSWORD GUAC_DB_PASSWORD GUAC_ENCRYPT_KEY MFA_ENCRYPT_KEY
  require_manual "$ROOT_ENV" ANTHROPIC_API_KEY            "Anthropic key for Crucible AI features"
  require_manual "$ROOT_ENV" PROXMOX_TOKEN_SECRET         "Proxmox API token secret from install.sh"
  require_manual "$ROOT_ENV" TAILSCALE_OAUTH_CLIENT_SECRET "Tailscale OAuth secret for lane VPN"
  local host; host="$(env_get "$ROOT_ENV" CYBERHUB_HOST || true)"
  case "$host" in
    ""|yourdomain.example.edu) todo "Set CYBERHUB_HOST in .env to your real domain (currently placeholder → no HTTPS)." ;;
    :80|*:80)                   warn "CYBERHUB_HOST is HTTP-only ($host) — fine for LAN/offline, no TLS." ;;
  esac
}

# ---------------------------------------------------------------------------
# 5. Permissions
# ---------------------------------------------------------------------------
harden_perms() {
  section "Hardening file permissions"
  local f
  while IFS= read -r f; do
    run "chmod 600 '$f'"
  done < <(find "$REPO_ROOT" -name '.env' -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
  info "chmod 600 on all .env files"

  while IFS= read -r f; do
    run "chmod +x '$f'"
  done < <(find "$REPO_ROOT/infrastructure" "$REPO_ROOT/scripts" -name '*.sh' 2>/dev/null)
  info "chmod +x on infrastructure/scripts shell scripts"
}

# ---------------------------------------------------------------------------
# 6. Validate configs
# ---------------------------------------------------------------------------
validate() {
  section "Validating configs"
  if command -v docker >/dev/null 2>&1; then
    if docker compose -f "$REPO_ROOT/docker-compose.yml" config -q 2>/dev/null; then
      log "root docker-compose.yml is valid."
    else
      warn "root docker-compose.yml failed 'docker compose config' — check env values."
    fi
  else
    warn "docker not available — skipped compose validation."
  fi

  if command -v ansible-playbook >/dev/null 2>&1; then
    local p ok=0 bad=0
    while IFS= read -r p; do
      if ansible-playbook --syntax-check "$p" >/dev/null 2>&1; then ok=$((ok+1)); else
        bad=$((bad+1)); warn "syntax-check failed: ${p#$REPO_ROOT/}"; fi
    done < <(find "$REPO_ROOT/infrastructure" -name '*.yml' -path '*playbook*' -o -name '*template*.yml' 2>/dev/null)
    info "ansible syntax-check: $ok ok, $bad failed"
  else
    info "ansible not installed — skipped playbook syntax-check."
  fi
}

# ---------------------------------------------------------------------------
# 7. Bring stack up (opt-in)
# ---------------------------------------------------------------------------
bring_up() {
  [ "$DO_UP" = "1" ] || { info "stack bring-up skipped (pass --up to enable)"; return 0; }
  command -v docker >/dev/null 2>&1 || { warn "docker not available — cannot bring stack up."; return 0; }
  section "Bringing up the stack"
  run "docker compose -f '$REPO_ROOT/docker-compose.yml' up -d"
  [ "$DRY_RUN" = "1" ] && return 0
  info "Waiting for containers to report healthy (up to 3 min)..."
  local i unhealthy
  for i in $(seq 1 36); do
    unhealthy="$(docker compose -f "$REPO_ROOT/docker-compose.yml" ps --format '{{.Health}}' 2>/dev/null \
      | grep -c -E 'starting|unhealthy' || true)"
    [ "${unhealthy:-0}" -eq 0 ] && { log "All containers healthy."; return 0; }
    sleep 5
  done
  warn "Some containers are still not healthy — check: docker compose ps"
}

# ---------------------------------------------------------------------------
# 7b. Infrastructure: transit gateways + templates (Proxmox node only)
# ---------------------------------------------------------------------------
SITE_JSON="$REPO_ROOT/config/site.json"
GW_DIR="$REPO_ROOT/infrastructure/proxmox-templates/gateway-templates"
INV_TMP=""
cleanup_inv() { [ -n "$INV_TMP" ] && rm -f "$INV_TMP" 2>/dev/null || true; }
trap cleanup_inv EXIT

on_proxmox() { command -v pct >/dev/null 2>&1 && command -v qm >/dev/null 2>&1 && command -v pvesh >/dev/null 2>&1; }
pve_node()  { pvecm nodename 2>/dev/null || hostname; }

# Pull "gateway"/"bridge" for a module out of the single-line module_networks
# entry install.sh writes to config/site.json.
site_module_field() { # site_module_field MODULE FIELD
  [ -f "$SITE_JSON" ] || return 1
  grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\{[^}]*\}" "$SITE_JSON" \
    | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 \
    | sed -E 's/.*"([^"]*)"$/\1/'
}

enabled_modules() { env_get "$REPO_ROOT/.env" CORE_ENABLED_MODULES 2>/dev/null | tr ',' ' '; }

next_free_vmid() { local v="$1"; while qm status "$v" >/dev/null 2>&1 || pct status "$v" >/dev/null 2>&1; do v=$((v+1)); done; echo "$v"; }

find_alpine_template() {
  local t
  t="$(pveam list local 2>/dev/null | awk '/alpine-[0-9].*default/{print $1}' | sort | tail -1)"
  if [ -z "$t" ] && [ "$DRY_RUN" != "1" ]; then
    info "No Alpine LXC template cached — fetching the latest..."
    pveam update >/dev/null 2>&1 || true
    local avail
    avail="$(pveam available --section system 2>/dev/null | awk '/alpine-[0-9].*default/{print $2}' | sort | tail -1)"
    [ -n "$avail" ] && pveam download local "$avail" >/dev/null 2>&1 || true
    t="$(pveam list local 2>/dev/null | awk '/alpine-[0-9].*default/{print $1}' | sort | tail -1)"
  fi
  echo "$t"
}

wait_ct_ssh() { # wait_ct_ssh IP KEY
  local ip="$1" key="$2" i
  for i in $(seq 1 40); do
    ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 "root@$ip" true 2>/dev/null && return 0
    sleep 3
  done
  return 1
}

# Give a freshly-created Alpine CT enough to be Ansible-reachable: python3,
# openssh, and the installer's public key in root's authorized_keys.
ct_bootstrap() { # ct_bootstrap VMID PUBKEYFILE
  local vmid="$1" pub; pub="$(cat "$2")"
  pct exec "$vmid" -- sh -c 'apk add --no-cache openssh python3 >/dev/null 2>&1 || true; rc-update add sshd default >/dev/null 2>&1 || true; mkdir -p /root/.ssh && chmod 700 /root/.ssh'
  pct exec "$vmid" -- sh -c "printf '%s\n' '$pub' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
  pct exec "$vmid" -- sh -c 'grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config; rc-service sshd restart >/dev/null 2>&1 || rc-service sshd start >/dev/null 2>&1 || true'
}

gen_inventory() { # gen_inventory IP KEY  -> sets INV_TMP
  INV_TMP="$(mktemp)"
  cat > "$INV_TMP" <<EOF
[gw]
$1 ansible_host=$1 ansible_user=root ansible_ssh_private_key_file=$2 ansible_python_interpreter=/usr/bin/python3 ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
EOF
  chmod 600 "$INV_TMP"
}

# Shared config for the infra phase, resolved once (env overrides > defaults).
INFRA_CONFIGURED=0
infra_config() {
  [ "$INFRA_CONFIGURED" = "1" ] && return 0
  STORAGE_POOL="${STORAGE_POOL:-vmpool}"
  WAN_BRIDGE="${WAN_BRIDGE:-vmbr0}"
  MGMT_BASE="${MGMT_BASE:-100.100.10}"           # /24 the gateway CTs sit on for mgmt
  MGMT_CIDR="${MGMT_CIDR:-24}"
  MGMT_GW="${MGMT_GW:-${MGMT_BASE}.1}"
  UPSTREAM_DNS="${UPSTREAM_DNS:-1.1.1.1}"
  ANSIBLE_KEY="${ANSIBLE_KEY:-$HOME/.ssh/cybercore_node_key}"
  if [ ! -f "$ANSIBLE_KEY" ]; then
    warn "Ansible key $ANSIBLE_KEY not found — generating one."
    run "ssh-keygen -t ed25519 -N '' -f '$ANSIBLE_KEY' -C cybercore-infra >/dev/null"
  fi

  # Guacamole runs inside the orchestrator stack — derive its IP from CyberCore's
  # own address (CYBERCORE_INTERNAL_URL) so the gateways' RDP DNAT points at the
  # real Guac, not a hardcoded default. Blank => playbook disables RDP forwarding.
  local cc; cc="$(env_get "$REPO_ROOT/.env" CYBERCORE_INTERNAL_URL 2>/dev/null | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
  GUAC_SERVER_IP="${GUAC_SERVER_IP:-$cc}"
  if [ -n "$GUAC_SERVER_IP" ]; then info "Guacamole (RDP DNAT source) = $GUAC_SERVER_IP"
  else warn "Could not derive Guacamole IP from .env (CYBERCORE_INTERNAL_URL) — gateways' RDP DNAT will be disabled."; fi

  NODE="$(pve_node)"
  INFRA_CONFIGURED=1
  info "storage=$STORAGE_POOL wan_bridge=$WAN_BRIDGE mgmt=${MGMT_BASE}.0/${MGMT_CIDR} dns=$UPSTREAM_DNS key=$ANSIBLE_KEY node=$NODE"
}

deploy_gateways() {
  [ "$DO_GW" = "1" ] || return 0
  section "Transit gateways (module LXCs)"
  on_proxmox || { warn "Not a Proxmox node (pct/qm/pvesh missing) — skipping."; todo "Run 'setup.sh --gateways' on a Proxmox node to create module transit gateways."; return 0; }
  command -v ansible-playbook >/dev/null 2>&1 || { warn "ansible-playbook not installed — skipping."; todo "apt/dnf install ansible, then re-run 'setup.sh --gateways'."; return 0; }
  infra_config
  local tmpl; tmpl="$(find_alpine_template)"
  [ -n "$tmpl" ] || { warn "No Alpine template available — skipping gateways."; return 0; }
  info "Alpine template: $tmpl"

  local idx=0 m
  for m in $(enabled_modules); do
    local play="$GW_DIR/${m}-gateway.yml"
    [ -f "$play" ] || { info "no ${m}-gateway.yml — skipping '$m'."; continue; }
    local gw br; gw="$(site_module_field "$m" gateway)"; br="$(site_module_field "$m" bridge)"
    if [ -z "$gw" ] || [ -z "$br" ]; then info "no gateway/bridge in site.json for '$m' — skipping."; continue; fi
    local base; base="$(printf '%s' "$gw" | cut -d. -f1-2)"   # e.g. 100.102

    # The LXC owns the gateway IP on lan0, so the module bridge must be pure L2.
    # install.sh now creates L2 bridges, but tolerate a legacy IP'd bridge by
    # moving the address off it (the LXC model is canonical).
    if ip -4 addr show dev "$br" 2>/dev/null | grep -q "inet ${gw}/"; then
      warn "Legacy: bridge '$br' holds $gw. Moving it off — the LXC gateway owns L3 now."
      run "pvesh set /nodes/$NODE/network/$br --delete address,netmask"
      run "ifreload -a 2>/dev/null || systemctl restart networking 2>/dev/null || true"
    fi

    local mgmt_ip="${MGMT_BASE}.$((121 + idx))"; idx=$((idx + 1))
    local vmid; vmid="$(next_free_vmid "$((920 + idx))")"

    if pct status "$vmid" >/dev/null 2>&1; then
      info "CT $vmid already exists for '$m' — reconfiguring only."
    else
      log "Creating '$m' gateway: CT $vmid (wan0 ${mgmt_ip}, lan0 ${gw}/16 on ${br})"
      # wan0 is an ordinary static LAN port; lan0 holds the gateway IP. Both are
      # Proxmox-managed (persist across reboot), so the playbook runs with
      # manage_interfaces=false and never flips wan0 to DHCP.
      run "pct create $vmid '$tmpl' --hostname ${m}-gw --cores 1 --memory 512 --swap 512 \
        --storage $STORAGE_POOL --onboot 1 --unprivileged 1 --features nesting=1 \
        --nameserver $UPSTREAM_DNS \
        --net0 name=wan0,bridge=$WAN_BRIDGE,ip=${mgmt_ip}/${MGMT_CIDR},gw=${MGMT_GW} \
        --net1 name=lan0,bridge=$br,ip=${gw}/16"
      run "pct start $vmid"
    fi
    [ "$DRY_RUN" = "1" ] && { info "(dry-run) would bootstrap + run ${m}-gateway.yml against ${mgmt_ip}"; continue; }

    sleep 4
    ct_bootstrap "$vmid" "${ANSIBLE_KEY}.pub"
    wait_ct_ssh "$mgmt_ip" "$ANSIBLE_KEY" || { warn "CT $vmid ($m) not SSH-reachable at $mgmt_ip — skipping config."; todo "Gateway '$m' (CT $vmid) created but unconfigured — check networking, then run ${m}-gateway.yml."; continue; }

    gen_inventory "$mgmt_ip" "$ANSIBLE_KEY"
    log "Configuring '$m' gateway via ${m}-gateway.yml (base $base)..."
    if ansible-playbook -i "$INV_TMP" "$play" \
         -e "module_name=${m}" -e "module_subnet_base=${base}" \
         -e "manage_interfaces=false" -e "wan_mode=static" \
         -e "guac_server_ip=${GUAC_SERVER_IP}"; then
      log "'$m' transit gateway ready (CT $vmid)."
    else
      warn "Playbook for '$m' failed — CT $vmid left running for inspection."
      todo "Re-run ${m}-gateway.yml against CT $vmid ($mgmt_ip) after fixing the failure."
    fi
  done
}

# Build an Alpine LXC template: create -> bootstrap -> configure -> seal.
build_lxc_template() { # build_lxc_template NAME VMID ALPINE_TMPL PLAYBOOK_PATH [extra -e kv...]
  local name="$1" vmid="$2" tmpl="$3" play_path="$4"; shift 4
  [ -f "$play_path" ] || { warn "template '$name': $(basename "$play_path") missing — skipping."; return 0; }
  if pct status "$vmid" >/dev/null 2>&1 || qm status "$vmid" >/dev/null 2>&1; then
    info "template '$name': VMID $vmid exists — skipping (pct destroy $vmid to rebuild)."; return 0; fi
  local ip="${MGMT_BASE}.$((200 + vmid % 50))"
  log "Building LXC template '$name' (CT $vmid)"
  run "pct create $vmid '$tmpl' --hostname $name --cores 1 --memory 512 --swap 512 \
    --storage $STORAGE_POOL --unprivileged 1 --features nesting=1 --nameserver $UPSTREAM_DNS \
    --net0 name=wan0,bridge=$WAN_BRIDGE,ip=${ip}/${MGMT_CIDR},gw=${MGMT_GW} \
    --net1 name=lan0,bridge=$WAN_BRIDGE,ip=manual"
  run "pct start $vmid"
  [ "$DRY_RUN" = "1" ] && { info "(dry-run) bootstrap + run $(basename "$play_path") + seal '$name'"; return 0; }
  sleep 4
  ct_bootstrap "$vmid" "${ANSIBLE_KEY}.pub"
  wait_ct_ssh "$ip" "$ANSIBLE_KEY" || { warn "template '$name' CT not reachable at $ip — left un-sealed."; todo "Finish LXC template '$name' (CT $vmid): run $(basename "$play_path"), then 'pct template $vmid'."; return 0; }
  gen_inventory "$ip" "$ANSIBLE_KEY"
  local eflags=(); local kv; for kv in "$@"; do eflags+=(-e "$kv"); done
  if ansible-playbook -i "$INV_TMP" "$play_path" "${eflags[@]}"; then
    run "pct stop $vmid"; run "pct template $vmid"
    log "Sealed LXC template '$name' (CT $vmid)."
  else
    warn "Playbook failed for '$name' — CT $vmid left running, not sealed."
    todo "Fix + re-run $(basename "$play_path") for '$name' (CT $vmid), then 'pct template $vmid'."
  fi
}

# Build a QEMU VM template from a cloud image (mirrors install.sh's VM pattern).
build_vm_template() { # build_vm_template NAME VMID IMAGE_URL PLAYBOOK_PATH
  local name="$1" vmid="$2" url="$3" play_path="$4"
  [ -f "$play_path" ] || { warn "template '$name': $(basename "$play_path") missing — skipping."; return 0; }
  if qm status "$vmid" >/dev/null 2>&1 || pct status "$vmid" >/dev/null 2>&1; then
    info "template '$name': VMID $vmid exists — skipping (qm destroy $vmid --purge to rebuild)."; return 0; fi
  local img="/var/lib/vz/template/iso/$(basename "$url")"
  local ip="${MGMT_BASE}.$((150 + vmid % 40))"
  log "Building VM template '$name' (VMID $vmid) from $(basename "$url")"
  if [ "$DRY_RUN" = "1" ]; then info "(dry-run) fetch $url; qm create $vmid; run $(basename "$play_path"); qm template"; return 0; fi
  if [ ! -f "$img" ]; then
    mkdir -p "$(dirname "$img")"
    wget --progress=dot:giga -O "${img}.tmp" "$url" && mv "${img}.tmp" "$img" \
      || { warn "download failed for '$name' — skipping."; rm -f "${img}.tmp"; return 0; }
  fi
  qm create "$vmid" --name "$name" --memory 2048 --cores 2 --cpu host --machine q35 \
    --scsihw virtio-scsi-pci --net0 "virtio,bridge=$WAN_BRIDGE" --serial0 socket --vga serial0 \
    --agent enabled=1,fstrim_cloned_disks=1 --ostype l26 \
    --description "CyberCore base template '$name' — built by setup.sh." \
    || { warn "qm create failed for '$name'."; return 0; }
  qm disk import "$vmid" "$img" "$STORAGE_POOL" >/dev/null
  qm set "$vmid" --scsi0 "${STORAGE_POOL}:vm-${vmid}-disk-0,discard=on,ssd=1" --boot order=scsi0
  qm resize "$vmid" scsi0 20G || true
  qm set "$vmid" --ide2 "${STORAGE_POOL}:cloudinit" --ciuser root \
    --sshkeys "${ANSIBLE_KEY}.pub" --ipconfig0 "ip=${ip}/${MGMT_CIDR},gw=${MGMT_GW}" --nameserver "$UPSTREAM_DNS"
  qm start "$vmid"
  wait_ct_ssh "$ip" "$ANSIBLE_KEY" || { warn "VM template '$name' not reachable at $ip — left un-sealed."; todo "Finish VM template '$name' (VMID $vmid): run $(basename "$play_path"), then 'qm template $vmid'."; return 0; }
  gen_inventory "$ip" "$ANSIBLE_KEY"
  if ansible-playbook -i "$INV_TMP" "$play_path"; then
    qm shutdown "$vmid" --timeout 120 2>/dev/null || qm stop "$vmid"
    qm set "$vmid" --delete sshkeys,ipconfig0 >/dev/null 2>&1 || true   # clone injects per-VM cloud-init
    qm template "$vmid"
    log "Sealed VM template '$name' (VMID $vmid)."
  else
    warn "Playbook failed for '$name' — VMID $vmid left running, not sealed."
    todo "Fix + re-run $(basename "$play_path") for '$name' (VMID $vmid), then 'qm template $vmid'."
  fi
}

deploy_templates() {
  [ "$DO_TPL" = "1" ] || return 0
  section "Lab templates"
  on_proxmox || { warn "Not a Proxmox node — skipping templates."; todo "Run 'setup.sh --templates' on a Proxmox node."; return 0; }
  command -v ansible-playbook >/dev/null 2>&1 || { warn "ansible-playbook not installed — skipping."; return 0; }
  infra_config
  local TPL_DIR="$REPO_ROOT/infrastructure/proxmox-templates"
  local tmpl; tmpl="$(find_alpine_template)"

  # 1) Lane gateway templates (Alpine LXC routers, cloned per-lane at runtime),
  #    one sealed template per enabled module from its {module}-lane-gw-template.yml.
  #    VMIDs 1600-1699 per the README template scheme.
  local idx=0 m
  for m in $(enabled_modules); do
    local lp="$GW_DIR/${m}-lane-gw-template.yml"
    if [ ! -f "$lp" ]; then info "no ${m}-lane-gw-template.yml — skipping '$m' lane gw."; idx=$((idx + 1)); continue; fi
    local base; base="$(printf '%s' "$(site_module_field "$m" gateway)" | cut -d. -f1-2)"
    [ -n "$base" ] || base="100.102"
    [ -n "$tmpl" ] && build_lxc_template "${m}-lane-gw" "$((1600 + idx))" "$tmpl" "$lp" \
      "module_name=${m}" "module_subnet_base=${base}" "manage_interfaces=false" "wan_mode=static"
    idx=$((idx + 1))
  done

  # 2) Base OS VM templates from cloud images. Only the clean, unattended one is
  #    auto-built; the rest need per-site input and are flagged below.
  build_vm_template rocky-base 1000 \
    "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2" \
    "$TPL_DIR/vm-templates/rocky-base-template.yml"

  # Deliberately NOT auto-built (need per-site input):
  #   mint-*            — playbook expects a manually-prepared base image
  #   rocky-AD/CIS/secure — need domain join / CIS vault vars
  #   kali              — challenge tooling: front-end/scripts/bake-kali-template.sh
  #   zabbix-proxy-lxc  — internal monitoring, deploy when the SIEM stack lands
  todo "Skipped templates needing manual input: mint (manual base), rocky-AD/CIS/secure (domain+vault vars), kali (use bake-kali-template.sh), zabbix. Build when needed."
}

# ---------------------------------------------------------------------------
# 8. Report
# ---------------------------------------------------------------------------
report() {
  section "Readiness report"
  echo
  echo -e "  ${BOLD}Automated hardening complete.${NC}"
  [ "$PURGE" = "1" ] || { [ -d "$BACKUP_DIR" ] && echo "  Backups of removed artifacts: ${BACKUP_DIR#$REPO_ROOT/}"; }
  echo
  echo -e "  ${BOLD}Still requires a human before prod:${NC}"
  if [ "${#MANUAL_TODOS[@]}" -eq 0 ]; then
    echo "    (nothing detected — double-check secrets and DNS anyway)"
  else
    local t; for t in "${MANUAL_TODOS[@]}"; do echo "    - $t"; done
  fi
  cat <<EOF

  Infra phase (--gateways/--templates) runs only on a Proxmox node.
  Challenge template baking is separate (front-end/scripts/bake-*.sh).

  Adding Proxmox nodes later: this only provisions the node it runs on. For a
  new node, re-run 'sudo ./scripts/setup.sh --gateways --templates' on it (or copy the
  gateway CTs/templates over) and recreate the module L2 bridges so lanes can
  schedule there — templates and bridges are per-node unless on shared storage.

EOF
}

# ---------------------------------------------------------------------------
main() {
  preflight
  clean_artifacts
  harden_env
  harden_perms
  validate
  bring_up
  deploy_gateways
  deploy_templates
  report
  log "setup.sh finished."
}

main "$@"
