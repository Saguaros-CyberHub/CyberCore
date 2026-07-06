#!/usr/bin/env bash
# ============================================================================
# install.sh — bootstrap a clean Proxmox VE host into a running CyberCore
# control plane.
#
# Run as root, from a git checkout of this repo that already lives on the
# target Proxmox host:
#
#   git clone <this repo> /root/CyberCore && cd /root/CyberCore
#   sudo ./install.sh
#
# What this does:
#   1. Preflight checks (root, Proxmox VE, vmbr0, SDN availability)
#   2. Interactive prompts for site config, networking, storage, which
#      modules/plugins to enable, credentials/secrets, and orchestrator VM sizing
#   3. Creates a dedicated Proxmox API user/role/token for the app, an SSH
#      keypair the app uses to reach this node, and (for v1-scheme modules)
#      dedicated NAT'd transit bridges
#   4. Generates config/site.json and .env
#   5. Creates a VM, installs Docker inside it, deploys this repo, and runs
#      `docker compose up -d`
#
# What this does NOT do (see printed summary at the end for details):
#   - Create a Ceph pool, configure OPNsense, or join additional Proxmox
#     nodes into a cluster — all assumed pre-existing/external infra.
#   - Bake any lab VM templates (front-end/scripts/bake-*.sh) — separate,
#     already-documented, and much longer-running (Windows especially).
#
# Idempotent: safe to re-run. Already-created Proxmox objects are detected
# and skipped rather than duplicated.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}==>${NC} $*"; }
info() { echo -e "${BLUE}   ${NC} $*"; }
warn() { echo -e "${YELLOW}!! ${NC} $*" >&2; }
err()  { echo -e "${RED}ERROR:${NC} $*" >&2; }
die()  { err "$*"; exit 1; }
section() { echo; echo -e "${BOLD}### $* ###${NC}"; }

# ask NAME "Prompt text" "default"  -> sets global var $NAME
ask() {
  local __var="$1" __prompt="$2" __default="${3:-}" __reply
  if [ -n "$__default" ]; then
    read -r -p "$__prompt [$__default]: " __reply || true
  else
    read -r -p "$__prompt: " __reply || true
  fi
  printf -v "$__var" '%s' "${__reply:-$__default}"
}

# ask_yn NAME "Prompt text" "Y|N" (default) -> sets global var $NAME to 0/1
ask_yn() {
  local __var="$1" __prompt="$2" __default="${3:-Y}" __reply __norm
  local __hint="y/N"; [ "$__default" = "Y" ] && __hint="Y/n"
  read -r -p "$__prompt [$__hint]: " __reply || true
  __reply="${__reply:-$__default}"
  __norm="$(echo "$__reply" | tr '[:upper:]' '[:lower:]')"
  if [[ "$__norm" == y* ]]; then printf -v "$__var" '1'; else printf -v "$__var" '0'; fi
}

# ask_secret NAME "Prompt text" -> sets global var $NAME, hidden input, blank = leave empty
ask_secret() {
  local __var="$1" __prompt="$2" __reply
  read -r -s -p "$__prompt (leave blank to skip): " __reply || true
  echo
  printf -v "$__var" '%s' "$__reply"
}

gen_secret() { openssl rand -hex 32; }

confirm_or_die() {
  local __reply
  read -r -p "$(echo -e "${BOLD}Type 'yes' to proceed and start making changes to this host:${NC} ")" __reply || true
  [ "$__reply" = "yes" ] || die "Aborted — nothing has been changed."
}

# ---------------------------------------------------------------------------
# 1. Preflight
# ---------------------------------------------------------------------------
preflight() {
  section "Preflight checks"

  [ "$(id -u)" -eq 0 ] || die "Must run as root (sudo ./install.sh)."
  command -v pveversion >/dev/null 2>&1 || die "pveversion not found — this doesn't look like a Proxmox VE host."
  command -v pvesh      >/dev/null 2>&1 || die "pvesh not found."
  command -v pveum       >/dev/null 2>&1 || die "pveum not found."
  command -v qm          >/dev/null 2>&1 || die "qm not found."
  for bin in openssl ssh scp rsync wget curl; do
    command -v "$bin" >/dev/null 2>&1 || die "Required tool '$bin' not found — install it first."
  done
  log "Running on: $(pveversion)"

  NODE_NAME="$(pvecm nodename 2>/dev/null || hostname)"
  log "Proxmox node name: $NODE_NAME"

  CLUSTER_NODES=("$NODE_NAME")
  if pvecm status >/dev/null 2>&1; then
    log "This host is part of an existing Proxmox cluster — picking up its node list."
    mapfile -t CLUSTER_NODES < <(pvecm nodes 2>/dev/null | awk 'NR>2 && NF>=3 {print $3}' | sed 's/[[:space:]]*(.*//' | sed '/^$/d')
    [ "${#CLUSTER_NODES[@]}" -eq 0 ] && CLUSTER_NODES=("$NODE_NAME")
    info "Cluster nodes: ${CLUSTER_NODES[*]}"
  else
    info "Single-node host (not clustered)."
  fi

  if ! ip link show vmbr0 >/dev/null 2>&1; then
    die "Bridge 'vmbr0' does not exist. This script does not create or modify your primary network bridge (too risky to automate over SSH) — configure vmbr0 first (Proxmox default during install), then re-run."
  fi
  log "vmbr0 present."

  if ! pvesh get /cluster/sdn/zones >/dev/null 2>&1; then
    warn "Proxmox SDN API not responding. On older PVE this needs: apt install libpve-network-perl (then reboot or restart pvedaemon/pveproxy). CyberCore creates SDN zones/VNets per-lab at runtime — it will fail to deploy labs until SDN works."
  else
    log "SDN API available."
  fi

  DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')"
  DETECTED_IP=""
  if [ -n "$DEFAULT_IFACE" ]; then
    DETECTED_IP="$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)"
  fi
}

# ---------------------------------------------------------------------------
# 2. Interactive prompts
# ---------------------------------------------------------------------------
collect_site_info() {
  section "Site"
  ask SITE_NAME     "Site name"                              "cyberhub-prod"
  ask CYBERHUB_HOST "Public domain (or ':80' for LAN/offline mode, see docs/offline-mode.md)" "cyberhub.example.edu"
  ask SITE_TZ       "Timezone"                                "America/Phoenix"
  ask ADMIN_EMAIL   "First admin account email"               "admin@${CYBERHUB_HOST}"
}

collect_networking() {
  section "Networking"
  ask MGMT_SUBNET     "Management subnet (Proxmox nodes)"          "100.100.10.0/24"
  ask NODE_MGMT_IP    "This node's management IP"                  "${DETECTED_IP:-100.100.10.10}"
  ask PROXMOX_API_URL "Proxmox API URL"                             "https://${NODE_MGMT_IP}:8006"

  ask V2_BRIDGE  "v2 lab network bridge"        "vmbr0"
  ask V2_VLAN    "v2 lab network VLAN tag"      "60"
  ask V2_SUBNET  "v2 lab network subnet base"   "100.100.60"
  ask V2_GATEWAY "v2 lab network gateway IP"    "100.100.60.1"

  info "v1-scheme module transit networks (dedicated NAT'd bridges this script creates)."
  ask CRUCIBLE_GW  "crucible transit gateway (/16)"  "100.102.0.1"
  ask CYBERLABS_GW "cyberlabs transit gateway (/16)" "100.103.0.1"
  ask FORGE_GW     "forge transit gateway (/16)"     "100.104.0.1"
}

collect_storage() {
  section "Storage"
  ask STORAGE_POOL "Proxmox storage pool for VM disks (must support 'images' content)" "vmpool"

  if ! pvesm status 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$STORAGE_POOL"; then
    warn "Storage '$STORAGE_POOL' not found."
    ask_yn CREATE_STORAGE "Create a directory-backed storage named '$STORAGE_POOL' now (NOT production-grade — use a real Ceph/LVM pool for real deployments)?" "Y"
    if [ "$CREATE_STORAGE" = "1" ]; then
      ask STORAGE_PATH "Directory path for '$STORAGE_POOL'" "/var/lib/vz/${STORAGE_POOL}"
    else
      die "Cannot continue without a valid storage pool. Create '$STORAGE_POOL' (or re-run and enter an existing pool's name), then re-run."
    fi
  else
    CREATE_STORAGE=0
    log "Storage '$STORAGE_POOL' found."
  fi
}

collect_modules() {
  section "Modules & plugins"
  MODULES=(crucible cyberlabs forge library university cyberwiki archive)
  ENABLED_MODULES=()
  for m in "${MODULES[@]}"; do
    local varname="EN_$m"
    ask_yn "$varname" "Enable module '$m'?" "Y"
    if [ "${!varname}" = "1" ]; then ENABLED_MODULES+=("$m"); fi
  done
  CORE_ENABLED_MODULES="$(IFS=,; echo "${ENABLED_MODULES[*]}")"

  CIAB_ACTIVE=1
  CLE_ACTIVE=1
  if [ "$EN_crucible" = "1" ]; then
    ask_yn CIAB_ACTIVE "  Enable crucible plugin 'ciab' (Clinic-in-a-Box)?" "Y"
    ask_yn CLE_ACTIVE  "  Enable crucible plugin 'cle' (Cyber Learning Environment)?" "Y"
  fi
}

collect_secrets() {
  section "Credentials & secrets"
  # config/postgres/005_admin_user.sh seeds the one-and-only admin account
  # straight from CORE_DB_USER/CORE_DB_PASSWORD (there is no separate
  # admin-specific credential in the schema) — so that's what we collect here.
  ask CORE_DB_USER "Admin login username (also the app DB user)" "cyberhub"

  ask SSH_PUBKEY_PATH "Path to an SSH public key to authorize on the orchestrator VM" "${HOME}/.ssh/id_ed25519.pub"
  [ -f "$SSH_PUBKEY_PATH" ] || die "SSH public key not found at $SSH_PUBKEY_PATH"

  ask_secret ANTHROPIC_API_KEY "Anthropic API key (enables AI features in the ciab plugin)"
  ask_secret TAILSCALE_OAUTH_CLIENT_ID     "Tailscale OAuth client ID (enables per-lane VPN)"
  if [ -n "$TAILSCALE_OAUTH_CLIENT_ID" ]; then
    ask_secret TAILSCALE_OAUTH_CLIENT_SECRET "Tailscale OAuth client secret"
    ask TAILSCALE_TAILNET "Tailscale tailnet name" ""
  else
    TAILSCALE_OAUTH_CLIENT_SECRET=""
    TAILSCALE_TAILNET=""
  fi

  ask FTP_USER "FTP username (profile delivery)" "cybercore"

  JWT_SECRET="$(gen_secret)";        SESSION_SECRET="$(gen_secret)"
  VULN_ASSETS_SECRET="$(gen_secret)"; GUAC_ENCRYPT_KEY="$(gen_secret)"
  MFA_ENCRYPT_KEY="$(gen_secret)";    CORE_DB_PASSWORD="$(gen_secret | cut -c1-32)"
  GUAC_DB_PASSWORD="$(gen_secret | cut -c1-32)"; GUAC_ADMIN_PASSWORD="$(gen_secret | cut -c1-20)"
  FTP_PASSWORD="$(gen_secret | cut -c1-20)"
  log "Generated JWT/session/Guacamole/MFA/DB/FTP secrets."
}

collect_orchestrator_vm() {
  section "Orchestrator VM (runs the docker compose stack)"
  VMID=100
  while qm status "$VMID" >/dev/null 2>&1 || pct status "$VMID" >/dev/null 2>&1; do
    VMID=$((VMID + 1))
  done
  ask VM_VMID    "VMID for the orchestrator VM" "$VMID"
  ask VM_NAME    "VM name"                      "cybercore-orchestrator"
  ask VM_CORES   "vCPUs"                        "4"
  ask VM_MEMORY  "Memory (MB)"                  "8192"
  ask VM_DISK_GB "Disk size (GB)"                "80"
  ask VM_IP      "Static IP for the VM (management subnet)" "$(echo "$NODE_MGMT_IP" | awk -F. '{print $1"."$2"."$3".20"}')"
  ask VM_CIDR    "CIDR suffix"                  "24"
  ask VM_GATEWAY "Gateway for the VM's network" "$(echo "$NODE_MGMT_IP" | awk -F. '{print $1"."$2"."$3".1"}')"
  ask CYBERCORE_INTERNAL_URL "Internal URL lane VMs use to pull vuln-app images" "http://${VM_IP}:80"
}

print_summary_and_confirm() {
  section "Summary — nothing has been changed yet"
  cat <<EOF
  Site:            $SITE_NAME  (domain: $CYBERHUB_HOST, tz: $SITE_TZ)
  Admin:           $ADMIN_EMAIL (login username: $CORE_DB_USER)
  Node:            $NODE_NAME ($NODE_MGMT_IP) — cluster: ${CLUSTER_NODES[*]}
  Proxmox API:     $PROXMOX_API_URL
  Storage pool:    $STORAGE_POOL $( [ "$CREATE_STORAGE" = "1" ] && echo "(will be created at $STORAGE_PATH)" )
  v2 lab network:  $V2_BRIDGE vlan $V2_VLAN, ${V2_SUBNET}.0/24 gw $V2_GATEWAY
  Module gateways: crucible=$CRUCIBLE_GW cyberlabs=$CYBERLABS_GW forge=$FORGE_GW
  Modules:         $CORE_ENABLED_MODULES
  ciab plugin:     $([ "$CIAB_ACTIVE" = "1" ] && echo enabled || echo disabled)
  cle plugin:      $([ "$CLE_ACTIVE" = "1" ] && echo enabled || echo disabled)
  Orchestrator VM: VMID $VM_VMID, ${VM_CORES}vCPU/${VM_MEMORY}MB/${VM_DISK_GB}GB, IP ${VM_IP}/${VM_CIDR} gw ${VM_GATEWAY}
  Anthropic API:   $([ -n "$ANTHROPIC_API_KEY" ] && echo "configured" || echo "skipped — ciab AI features disabled")
  Tailscale:       $([ -n "$TAILSCALE_OAUTH_CLIENT_ID" ] && echo "configured" || echo "skipped — per-lane VPN disabled")
EOF
  echo
  confirm_or_die
}

# ---------------------------------------------------------------------------
# 3. Proxmox-side provisioning
# ---------------------------------------------------------------------------

PVE_APP_USER="cybercore-app@pve"
PVE_APP_ROLE="CyberCoreApp"
PVE_APP_TOKEN_NAME="cybercore-token"
PVE_APP_PRIVS="Sys.Audit Datastore.Audit Datastore.AllocateSpace Datastore.AllocateTemplate VM.Audit VM.Allocate VM.Clone VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network VM.Config.Cloudinit VM.Config.CDROM VM.Config.Options VM.Config.HWType VM.PowerMgmt VM.Console VM.Monitor SDN.Audit SDN.Allocate"

create_pve_user_and_token() {
  section "Proxmox API user, role, and token"

  if pveum role list --output-format json 2>/dev/null | grep -q "\"roleid\":\"${PVE_APP_ROLE}\""; then
    log "Role '$PVE_APP_ROLE' already exists."
  else
    pveum role add "$PVE_APP_ROLE" -privs "$PVE_APP_PRIVS"
    log "Created role '$PVE_APP_ROLE'."
  fi

  if pveum user list --output-format json 2>/dev/null | grep -q "\"userid\":\"${PVE_APP_USER}\""; then
    log "User '$PVE_APP_USER' already exists."
  else
    pveum user add "$PVE_APP_USER" --comment "CyberCore app service account (created by install.sh)"
    log "Created user '$PVE_APP_USER'."
  fi

  pveum acl modify / -user "$PVE_APP_USER" -role "$PVE_APP_ROLE" >/dev/null
  log "Granted role '$PVE_APP_ROLE' on / to '$PVE_APP_USER'."

  # pvesh (not pveum) for token ops — it hits /access/users/.../token directly
  # and reliably supports --output-format json, which pveum's token subcommands
  # don't consistently do across PVE versions.
  PROXMOX_TOKEN_ID="${PVE_APP_USER}!${PVE_APP_TOKEN_NAME}"
  if pvesh get "/access/users/${PVE_APP_USER}/token" --output-format json 2>/dev/null | grep -q "\"tokenid\":\"${PVE_APP_TOKEN_NAME}\""; then
    warn "Token '$PROXMOX_TOKEN_ID' already exists. Proxmox only shows a token's secret once, at creation — this script cannot recover it."
    ask_secret PROXMOX_TOKEN_SECRET "Paste the existing token secret (or leave blank to delete + recreate it)"
    if [ -z "$PROXMOX_TOKEN_SECRET" ]; then
      pvesh delete "/access/users/${PVE_APP_USER}/token/${PVE_APP_TOKEN_NAME}" >/dev/null
      PROXMOX_TOKEN_SECRET="$(pvesh create "/access/users/${PVE_APP_USER}/token/${PVE_APP_TOKEN_NAME}" -privsep 0 --output-format json | grep -oP '"value"\s*:\s*"\K[^"]+')"
      log "Recreated token '$PROXMOX_TOKEN_ID'."
    fi
  else
    PROXMOX_TOKEN_SECRET="$(pvesh create "/access/users/${PVE_APP_USER}/token/${PVE_APP_TOKEN_NAME}" -privsep 0 --output-format json | grep -oP '"value"\s*:\s*"\K[^"]+')"
    log "Created token '$PROXMOX_TOKEN_ID'."
  fi
  [ -n "$PROXMOX_TOKEN_SECRET" ] || die "Failed to obtain a Proxmox API token secret."
}

# Two keypairs, two directions:
#   cybercore_install_key — install.sh (this host) -> orchestrator VM, for setup/rsync.
#   cybercore_node_key    — orchestrator VM (the app's node-ssh.js) -> this Proxmox
#                            node, for `pct exec` / DHCP file pushes. Public half
#                            goes in this node's authorized_keys; private half is
#                            delivered into the VM and referenced by PROXMOX_SSH_KEY.
setup_ssh_keys() {
  section "SSH keys"

  INSTALL_KEY="$HOME/.ssh/cybercore_install_key"
  if [ ! -f "$INSTALL_KEY" ]; then
    ssh-keygen -t ed25519 -N '' -f "$INSTALL_KEY" -C "cybercore-install" >/dev/null
    log "Generated installer SSH key: $INSTALL_KEY"
  else
    log "Reusing existing installer SSH key: $INSTALL_KEY"
  fi

  NODE_KEY="$HOME/.ssh/cybercore_node_key"
  if [ ! -f "$NODE_KEY" ]; then
    ssh-keygen -t ed25519 -N '' -f "$NODE_KEY" -C "cybercore-node-access" >/dev/null
    log "Generated node-access SSH key: $NODE_KEY"
  else
    log "Reusing existing node-access SSH key: $NODE_KEY"
  fi

  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  touch /root/.ssh/authorized_keys
  if ! grep -qF "$(cat "${NODE_KEY}.pub")" /root/.ssh/authorized_keys 2>/dev/null; then
    cat "${NODE_KEY}.pub" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    log "Authorized node-access key for root@${NODE_NAME}."
  else
    log "Node-access key already authorized on ${NODE_NAME}."
  fi
}

# Creates a dedicated Linux bridge (no physical ports — isolated/internal),
# assigns it the module's gateway IP, and NATs it out the default route
# interface. This is new, additive host networking (not touching vmbr0), so
# it can't cut off management/SSH connectivity the way editing vmbr0 could.
create_module_bridge() {
  local module="$1" bridge="$2" gateway="$3"
  if ip link show "$bridge" >/dev/null 2>&1; then
    log "Bridge '$bridge' ($module) already exists — leaving as-is."
    return
  fi
  log "Creating transit bridge '$bridge' for module '$module' ($gateway/16)..."
  pvesh create "/nodes/${NODE_NAME}/network" -type bridge -iface "$bridge" \
    -autostart 1 -address "$gateway" -netmask 16 >/dev/null
  local backup_path="/etc/network/interfaces.bak-$(date +%s)"
  cp -a /etc/network/interfaces "$backup_path"

  local egress
  egress="$(ip route show default | awk 'NR==1{print $5}')"
  # Append NAT hooks directly to the stanza pvesh just wrote.
  awk -v br="$bridge" -v eg="$egress" '
    { print }
    $0 ~ "^iface "br" inet static" && !done {
      print "    post-up   iptables -t nat -A POSTROUTING -o " eg " -j MASQUERADE"
      print "    post-down iptables -t nat -D POSTROUTING -o " eg " -j MASQUERADE"
      done=1
    }
  ' /etc/network/interfaces > /etc/network/interfaces.new
  mv /etc/network/interfaces.new /etc/network/interfaces

  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-cybercore.conf

  if command -v ifreload >/dev/null 2>&1; then
    if ! ifreload -a; then
      warn "ifreload failed applying '$bridge' — restoring previous /etc/network/interfaces. Check the bridge manually."
      cp -a "$backup_path" /etc/network/interfaces
      return
    fi
  else
    warn "ifreload not found — bridge '$bridge' is written to /etc/network/interfaces but not yet applied. Run 'systemctl restart networking' or reboot."
  fi
  log "Bridge '$bridge' up with NAT via $egress."
}

setup_module_bridges() {
  section "Module transit networks"
  [ "$EN_crucible" = "1" ]  && create_module_bridge crucible  crucible  "$CRUCIBLE_GW"
  [ "$EN_cyberlabs" = "1" ] && create_module_bridge cyberlabs cyberlabs "$CYBERLABS_GW"
  [ "$EN_forge" = "1" ]     && create_module_bridge forge     forge     "$FORGE_GW"
}

create_storage_pool_if_needed() {
  [ "${CREATE_STORAGE:-0}" = "1" ] || return 0
  section "Storage pool"
  mkdir -p "$STORAGE_PATH"
  pvesm add dir "$STORAGE_POOL" --path "$STORAGE_PATH" --content images,rootdir,snippets >/dev/null
  log "Created directory storage '$STORAGE_POOL' at $STORAGE_PATH (content: images, rootdir, snippets)."
  warn "'$STORAGE_POOL' is a plain directory, not Ceph/LVM — fine for testing, replace with a real pool for production."
}

# ---------------------------------------------------------------------------
# 4. Generate config
# ---------------------------------------------------------------------------
write_site_json() {
  section "Writing config/site.json"
  mkdir -p config
  local nodes_json="" first=1
  for n in "${CLUSTER_NODES[@]}"; do
    [ $first -eq 0 ] && nodes_json+=","
    nodes_json+=$'\n'"      \"${n}\": { \"ip\": \"$([ "$n" = "$NODE_NAME" ] && echo "$NODE_MGMT_IP" || echo "0.0.0.0")\" }"
    first=0
  done

  cat > config/site.json <<EOF
{
  "cluster": {
    "physical_cluster_details": {${nodes_json}
    },
    "networking": {
      "module_networks": {
        "crucible":  { "bridge": "crucible",  "gateway": "${CRUCIBLE_GW}",  "subnet_base": "$(echo "$CRUCIBLE_GW" | cut -d. -f1-2)",  "cidr": "/16" },
        "cyberlabs": { "bridge": "cyberlabs", "gateway": "${CYBERLABS_GW}", "subnet_base": "$(echo "$CYBERLABS_GW" | cut -d. -f1-2)", "cidr": "/16" },
        "forge":     { "bridge": "forge",     "gateway": "${FORGE_GW}",     "subnet_base": "$(echo "$FORGE_GW" | cut -d. -f1-2)",     "cidr": "/16" }
      },
      "v2_lab_network": {
        "bridge": "${V2_BRIDGE}", "vlan_tag": ${V2_VLAN}, "subnet_base": "${V2_SUBNET}",
        "gateway": "${V2_GATEWAY}", "cidr": "/24"
      },
      "v1_lane_subnet": {
        "base3": "192.18.0", "cidr": "192.18.0.0/24",
        "gateway_ip": "192.18.0.1", "netmask24": "255.255.255.0"
      }
    },
    "scheduling": {
      "min_free_mem_gb": 8, "min_free_disk_gb": 20,
      "max_concurrent_lanes": 5, "max_concurrent_clones": 4,
      "node_score_weights": { "cpu": 0.35, "mem": 0.55, "disk": 0.10 }
    }
  }
}
EOF
  log "Wrote config/site.json"
}

write_env_file() {
  section "Writing .env"
  cat > .env <<EOF
TZ=${SITE_TZ}
CYBERHUB_HOST=${CYBERHUB_HOST}

CORE_DB_USER=${CORE_DB_USER}
CORE_DB_PASSWORD=${CORE_DB_PASSWORD}
CORE_DB_NAME=cybercore_db
CORE_ENABLED_MODULES=${CORE_ENABLED_MODULES}

ADMIN_EMAIL=${ADMIN_EMAIL}

JWT_SECRET=${JWT_SECRET}
SESSION_SECRET=${SESSION_SECRET}
VULN_ASSETS_SECRET=${VULN_ASSETS_SECRET}

ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
LLM_DEFAULT_MODEL=claude-sonnet-4-5
LLM_MAX_CONCURRENT=6

FTP_USER=${FTP_USER}
FTP_PASSWORD=${FTP_PASSWORD}

GUAC_ADMIN_USER=guacadmin
GUAC_ADMIN_PASSWORD=${GUAC_ADMIN_PASSWORD}
GUAC_DB_NAME=guacamole_db
GUAC_DB_USER=guacamole_user
GUAC_DB_PASSWORD=${GUAC_DB_PASSWORD}
GUAC_ENCRYPT_KEY=${GUAC_ENCRYPT_KEY}
MFA_ENCRYPT_KEY=${MFA_ENCRYPT_KEY}

PROXMOX_API_URL=${PROXMOX_API_URL}
PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
PROXMOX_SSH_USER=root
PROXMOX_SSH_KEY=/root/.ssh/cybercore_node_key

TAILSCALE_OAUTH_CLIENT_ID=${TAILSCALE_OAUTH_CLIENT_ID}
TAILSCALE_OAUTH_CLIENT_SECRET=${TAILSCALE_OAUTH_CLIENT_SECRET}
TAILSCALE_TAILNET=${TAILSCALE_TAILNET}
TAILSCALE_LANE_TAG=tag:lane

CYBERCORE_INTERNAL_URL=${CYBERCORE_INTERNAL_URL}

RATE_LIMIT_MAX_REQUESTS=2000
RATE_LIMIT_WINDOW_MS=900000
EOF
  chmod 600 .env
  log "Wrote .env (mode 600)."
}

apply_plugin_selection() {
  section "Applying plugin selection"
  _set_plugin_active() {
    local manifest="$1" active="$2"
    [ -f "$manifest" ] || return 0
    node -e "
      const fs = require('fs');
      const p = '$manifest';
      const m = JSON.parse(fs.readFileSync(p, 'utf8'));
      m.active = $active;
      fs.writeFileSync(p, JSON.stringify(m, null, 4) + '\n');
    " 2>/dev/null || python3 -c "
import json
p = '$manifest'
with open(p) as f: m = json.load(f)
m['active'] = $active
with open(p, 'w') as f: json.dump(m, f, indent=4)
"
  }
  _set_plugin_active "front-end/modules/crucible/plugins/ciab/manifest.json" "$([ "$CIAB_ACTIVE" = "1" ] && echo true || echo false)"
  _set_plugin_active "front-end/modules/crucible/plugins/cle/manifest.json"  "$([ "$CLE_ACTIVE" = "1" ] && echo true || echo false)"
  log "ciab: $([ "$CIAB_ACTIVE" = "1" ] && echo enabled || echo disabled), cle: $([ "$CLE_ACTIVE" = "1" ] && echo enabled || echo disabled)"
}

# ---------------------------------------------------------------------------
# 5. Deploy the orchestrator VM
# ---------------------------------------------------------------------------
CLOUD_IMG_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-generic-amd64.qcow2"

create_orchestrator_vm() {
  section "Creating orchestrator VM ($VM_VMID)"

  if qm status "$VM_VMID" >/dev/null 2>&1; then
    log "VM $VM_VMID already exists — skipping creation, will (re)configure and start it."
  else
    if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
      log "Downloading Debian 13 cloud image (~350MB)..."
      mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
      wget --progress=dot:giga -O "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_URL"
      mv "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_LOCAL"
    fi

    qm create "$VM_VMID" \
      --name "$VM_NAME" --memory "$VM_MEMORY" --cores "$VM_CORES" --cpu host \
      --machine q35 --bios seabios --scsihw virtio-scsi-pci \
      --net0 "virtio,bridge=vmbr0" \
      --serial0 socket --vga serial0 \
      --agent enabled=1,fstrim_cloned_disks=1 \
      --ostype l26 \
      --description "CyberCore orchestrator VM — runs the docker compose stack. Created by install.sh."

    qm disk import "$VM_VMID" "$CLOUD_IMG_LOCAL" "$STORAGE_POOL"
    qm set "$VM_VMID" --scsi0 "${STORAGE_POOL}:vm-${VM_VMID}-disk-0,discard=on,ssd=1"
    qm set "$VM_VMID" --boot order=scsi0
    qm resize "$VM_VMID" scsi0 "${VM_DISK_GB}G" || true
    qm set "$VM_VMID" --ide2 "${STORAGE_POOL}:cloudinit"
  fi

  cat "$INSTALL_KEY.pub" "${SSH_PUBKEY_PATH}" > "/tmp/cybercore-vm-${VM_VMID}-keys.pub"
  qm set "$VM_VMID" \
    --ciuser root \
    --sshkeys "/tmp/cybercore-vm-${VM_VMID}-keys.pub" \
    --ipconfig0 "ip=${VM_IP}/${VM_CIDR},gw=${VM_GATEWAY}" \
    --nameserver "1.1.1.1"
  rm -f "/tmp/cybercore-vm-${VM_VMID}-keys.pub"

  qm start "$VM_VMID"
  log "VM $VM_VMID starting..."
}

wait_for_vm_ssh() {
  section "Waiting for orchestrator VM to boot"
  local deadline=$(( $(date +%s) + 300 ))
  until ssh -i "$INSTALL_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o BatchMode=yes "root@${VM_IP}" true 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      die "VM did not become SSH-reachable at ${VM_IP} within 5 minutes. Check 'qm terminal $VM_VMID' for cloud-init/boot issues."
    fi
    sleep 5
  done
  log "VM is SSH-reachable at ${VM_IP}."
}

_vm_ssh() { ssh -i "$INSTALL_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${VM_IP}" "$@"; }

deploy_repo_to_vm() {
  section "Deploying CyberCore to the orchestrator VM"

  # Deliver the node-access private key so PROXMOX_SSH_KEY resolves inside the VM.
  _vm_ssh "mkdir -p /root/.ssh && chmod 700 /root/.ssh"
  scp -i "$INSTALL_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$NODE_KEY" "root@${VM_IP}:/root/.ssh/cybercore_node_key"
  _vm_ssh "chmod 600 /root/.ssh/cybercore_node_key"

  _vm_ssh "mkdir -p /opt/cybercore"
  rsync -az --delete \
    -e "ssh -i $INSTALL_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
    --exclude '.git' --exclude 'node_modules' --exclude 'logs' \
    "$SCRIPT_DIR/" "root@${VM_IP}:/opt/cybercore/"
  log "Repo synced to /opt/cybercore on the orchestrator VM."
}

bring_up_stack() {
  section "Installing Docker and starting the stack"
  _vm_ssh 'command -v docker >/dev/null 2>&1 || (curl -fsSL https://get.docker.com | sh)'
  _vm_ssh "cd /opt/cybercore && docker compose up -d"
  log "docker compose up -d issued. This can take several minutes on first run (image builds, DB init)."
}

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
print_summary() {
  section "Done"
  cat <<EOF

  Orchestrator VM:  ${VM_NAME} (VMID ${VM_VMID}) at ${VM_IP}
  CyberHub URL:      http://${VM_IP}/  (or https://${CYBERHUB_HOST}/ once DNS points at it)
  Admin login:       ${CORE_DB_USER} / ${CORE_DB_PASSWORD}  (email on file: ${ADMIN_EMAIL})
  Adminer:           http://${VM_IP}:8181
  Guacamole:         http://${VM_IP}/guacamole/  (guacadmin / ${GUAC_ADMIN_PASSWORD})

  Generated secrets live in .env at $SCRIPT_DIR/.env (mode 600) — back it up.

  NOT done for you:
    - VM template baking (Windows/Kali/web/etc.) — see front-end/scripts/bake-*.sh
      and their headers for what each one does and how long it takes.
    - Ceph pool creation — '${STORAGE_POOL}' $( [ "${CREATE_STORAGE:-0}" = "1" ] && echo "was created as a plain directory, replace with real Ceph/LVM for production" || echo "was assumed to already exist and was verified present" ).
    - OPNsense firewall rules — assumed pre-existing external infrastructure.
    - Joining additional Proxmox nodes into a cluster.
    - DNS records for ${CYBERHUB_HOST}.

EOF
}

# ---------------------------------------------------------------------------
main() {
  preflight
  collect_site_info
  collect_networking
  collect_storage
  collect_modules
  collect_secrets
  collect_orchestrator_vm
  print_summary_and_confirm

  create_pve_user_and_token
  setup_ssh_keys
  create_storage_pool_if_needed
  setup_module_bridges

  write_site_json
  write_env_file
  apply_plugin_selection

  create_orchestrator_vm
  wait_for_vm_ssh
  deploy_repo_to_vm
  bring_up_stack

  print_summary
}

main "$@"
