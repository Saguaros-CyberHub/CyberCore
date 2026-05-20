#!/bin/bash
# ============================================================================
# bake-lane-gateway-v3.sh
# ----------------------------------------------------------------------------
# Builds the v3 "segmented" lane-gateway template at VMID 1695 by cloning the
# v2 gateway (1694) and turning it into a 3-NIC router for the segmented
# "DMZ" lane topology (subnet_scheme='v3').
#
# v2 (1694): one lane subnet. NICs wan0 + lan0. Firstboot renders dnsmasq +
# NAT from lan0's IP.
#
# v3 (1695, this script): TWO lane subnets per lane. NICs:
#   - wan0  — internet uplink (NAT)
#   - ext0  — EXTERNAL segment: Kali attacker box + Tailscale BYOD
#   - int0  — INTERNAL segment: GOAD Active Directory VMs + controller
# Firstboot reads BOTH ext0 and int0, renders a dnsmasq scope for each,
# NATs both out wan0, and — critically — installs FORWARD rules that DROP all
# traffic between ext0 and int0. The attacker can reach the internet and the
# dual-homed DMZ host, but never the GOAD subnet directly: they must exploit
# the DMZ host and pivot through it.
#
# This script does NOT modify 1694 — v1/v2 lanes keep working untouched.
# Challenges using subnet_scheme='v3' clone 1695.
#
# Run on a Proxmox node where 1694 lives. Refuses to clobber an existing 1695
# unless FORCE=1.
#
# Companion to:
#   - bake-lane-gateway-v2.sh    (v2 gateway 1694 — the clone source here)
#   - bake-goad-controller-vm.sh (GOAD controller template)
# ============================================================================
set -euo pipefail

SRC_VMID=${SRC_VMID:-1694}
NEW_VMID=${NEW_VMID:-1695}
TMP_VMID=${TMP_VMID:-9992}
VERIFY_VMID=${VERIFY_VMID:-9993}
STORAGE=${STORAGE:-vmpool}
DUMP_DIR=${DUMP_DIR:-/var/lib/vz/dump}
FORCE=${FORCE:-0}

# ---------- 0. Sanity ----------
if ! pct config "$SRC_VMID" >/dev/null 2>&1; then
  echo "ERROR: source template CT $SRC_VMID (v2 gateway) not found." >&2
  echo "       Bake it first with bake-lane-gateway-v2.sh." >&2
  exit 1
fi
SRC_IS_TEMPLATE="$(pct config "$SRC_VMID" | awk '/^template:/ {print $2}')"
if [ "$SRC_IS_TEMPLATE" != "1" ]; then
  echo "ERROR: CT $SRC_VMID is not flagged as a template; aborting." >&2
  exit 1
fi

if pct config "$NEW_VMID" >/dev/null 2>&1; then
  if [ "$FORCE" != "1" ]; then
    echo "ERROR: target $NEW_VMID already exists. Re-run with FORCE=1 to replace it." >&2
    exit 1
  fi
  echo "==> FORCE=1: existing $NEW_VMID will be destroyed before restore."
fi

for vid in "$TMP_VMID" "$VERIFY_VMID"; do
  if pct status "$vid" >/dev/null 2>&1; then
    echo "ERROR: scratch CTID $vid in use. Override with TMP_VMID/VERIFY_VMID env vars or destroy it." >&2
    exit 1
  fi
done

# ---------- 1. Clone 1694 -> temp ----------
echo "==> Cloning $SRC_VMID -> $TMP_VMID..."
pct clone "$SRC_VMID" "$TMP_VMID" --hostname lanegw-v3-bake --full --storage "$STORAGE"

# pct start renames veth pairs; a previous failed attempt may have left them.
ip link delete wan0 2>/dev/null || true
ip link delete ext0 2>/dev/null || true
ip link delete int0 2>/dev/null || true
ip link delete lan0 2>/dev/null || true

# ---------- 2. Patch the temp clone ----------
echo "==> Starting temp CT $TMP_VMID..."
pct start "$TMP_VMID"

for _ in 1 2 3 4 5 6 7 8 9 10; do
  pct exec "$TMP_VMID" -- /bin/sh -c "test -d /etc/local.d" 2>/dev/null && break
  sleep 1
done

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# 2a. Firstboot script — renders dnsmasq + iptables for BOTH lane segments.
#     Overwrites the v2 firstboot inherited from 1694. Runs every boot.
cat > "$STAGING/00-cybercore-firstboot.start" <<'FIRSTBOOT_EOF'
#!/bin/sh
# /etc/local.d/00-cybercore-firstboot.start  (v3 segmented gateway)
# ---------------------------------------------------------------
# Reads ext0 + int0 IPs and renders dnsmasq + iptables from them.
# Idempotent — safe to re-run every boot. Installed by the v3
# bake script (bake-lane-gateway-v3.sh).
# ---------------------------------------------------------------
set -e

ENV_FILE=/etc/cybercore-gateway.env
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

DNS_FORWARDER="${DNS_FORWARDER:-100.100.60.1}"   # OPNsense lab gateway
LANE_DOMAIN="${LANE_DOMAIN:-cybercore.lan}"
CONTROLLER_OCTET="${CONTROLLER_OCTET:-5}"        # GOAD controller — internal .5
DHCP_START_OCTET="${DHCP_START_OCTET:-10}"
DHCP_END_OCTET="${DHCP_END_OCTET:-200}"

# Read an interface's IPv4 CIDR, waiting up to 15s for it to appear
# (admin.js sets it via `pct set`, but there can be a cold-boot race).
read_cidr() {
  _cidr=""
  for _ in $(seq 1 15); do
    _cidr="$(ip -4 -o addr show "$1" 2>/dev/null | awk '{print $4}' | head -1)"
    [ -n "$_cidr" ] && break
    sleep 1
  done
  echo "$_cidr"
}

EXT_CIDR="$(read_cidr ext0)"
INT_CIDR="$(read_cidr int0)"

if [ -z "$EXT_CIDR" ] || [ -z "$INT_CIDR" ]; then
  echo "[cybercore-firstboot] ext0/int0 missing IPv4 (ext='$EXT_CIDR' int='$INT_CIDR') — skipping render" >&2
  exit 0
fi

EXT_IP="${EXT_CIDR%/*}";  EXT_PREFIX="${EXT_CIDR##*/}"
INT_IP="${INT_CIDR%/*}";  INT_PREFIX="${INT_CIDR##*/}"
EXT_BASE3="$(echo "$EXT_IP" | awk -F. '{print $1"."$2"."$3}')"
INT_BASE3="$(echo "$INT_IP" | awk -F. '{print $1"."$2"."$3}')"
EXT_NET="${EXT_BASE3}.0/${EXT_PREFIX}"
INT_NET="${INT_BASE3}.0/${INT_PREFIX}"
CONTROLLER_IP="${INT_BASE3}.${CONTROLLER_OCTET}"

# Render /etc/dnsmasq.conf — one DHCP scope per segment, options tagged so
# each segment's clients get their own subnet's router/DNS.
cat > /etc/dnsmasq.conf <<DNSMASQ_EOF
# Auto-generated at boot by /etc/local.d/00-cybercore-firstboot.start (v3).
# Hand edits will be overwritten on next boot. Override via
# /etc/cybercore-gateway.env (DNS_FORWARDER, LANE_DOMAIN, CONTROLLER_OCTET,
# DHCP_START_OCTET, DHCP_END_OCTET).

interface=ext0
interface=int0
bind-interfaces
domain-needed
bogus-priv
no-resolv
server=${DNS_FORWARDER}
local=/${LANE_DOMAIN}/
domain=${LANE_DOMAIN}
expand-hosts

# External segment — Kali attacker box / Tailscale BYOD / attached modules.
dhcp-range=set:extnet,${EXT_BASE3}.${DHCP_START_OCTET},${EXT_BASE3}.${DHCP_END_OCTET},255.255.255.0,12h
dhcp-option=tag:extnet,option:router,${EXT_BASE3}.1
dhcp-option=tag:extnet,option:dns-server,${EXT_BASE3}.1

# Internal segment — GOAD Active Directory VMs + controller.
dhcp-range=set:intnet,${INT_BASE3}.${DHCP_START_OCTET},${INT_BASE3}.${DHCP_END_OCTET},255.255.255.0,12h
dhcp-option=tag:intnet,option:router,${INT_BASE3}.1
dhcp-option=tag:intnet,option:dns-server,${INT_BASE3}.1

dhcp-authoritative

# Per-host reservations (admin.js / the GOAD controller drop files here):
conf-dir=/etc/dnsmasq.d/,*.conf

log-dhcp
log-queries
DNSMASQ_EOF

mkdir -p /etc/dnsmasq.d

# IPv4 forwarding (the gateway routes both lane subnets to the internet).
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# --- iptables ---
# Strip any stale CyberCore-tagged rules so re-runs stay clean.
iptables-save | grep -vE 'GOAD-CONTROLLER-SSH|CYBERCORE-SEG' | iptables-restore || true

# 1. Allow the GOAD controller (internal .CONTROLLER_OCTET) to SSH the
#    gateway over int0 — it writes DHCP reservations there.
iptables -I INPUT -i int0 -s "${CONTROLLER_IP}" -p tcp --dport 22 \
  -m comment --comment "GOAD-CONTROLLER-SSH" -j ACCEPT

# 2. SEGMENTATION — drop all traffic between the external and internal
#    segments. This is the v3 attack-path enforcement: Kali (ext0) reaches
#    the internet and the dual-homed DMZ host, but never the GOAD subnet
#    (int0) directly. The pivot is done at the application layer (a Ligolo
#    agent on the DMZ host), which is not affected by these FORWARD rules.
iptables -I FORWARD -i ext0 -o int0 -m comment --comment "CYBERCORE-SEG" -j DROP
iptables -I FORWARD -i int0 -o ext0 -m comment --comment "CYBERCORE-SEG" -j DROP

# 3. NAT both lane subnets out wan0 (FORWARD policy is ACCEPT, so ext0/int0
#    -> wan0 is allowed; only the ext0<->int0 DROP rules above restrict it).
for NET in "$EXT_NET" "$INT_NET"; do
  if ! iptables -t nat -C POSTROUTING -s "$NET" -o wan0 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$NET" -o wan0 -j MASQUERADE
  fi
done

mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules-save

# (Re)start dnsmasq with the new config.
rc-service dnsmasq restart >/dev/null 2>&1 \
  || /etc/init.d/dnsmasq restart >/dev/null 2>&1 \
  || rc-service dnsmasq start >/dev/null 2>&1 \
  || true

# --- Tailscale subnet router (BYOAB) — advertises the EXTERNAL segment ONLY ---
# BYOD users land where Kali lands; they get no route to the internal GOAD
# subnet (the firewall would block it anyway, but not advertising it keeps
# the topology honest). Auth key is pulled from the orchestrator's bootstrap
# endpoint, identified by this lane's WAN source IP.
ORCHESTRATOR_URL="${CYBERCORE_ORCHESTRATOR_URL:-http://100.100.20.50:3000}"
BOOTSTRAP_PATH="/api/lane-bootstrap"

echo "[cybercore-firstboot] Fetching bootstrap payload from ${ORCHESTRATOR_URL}${BOOTSTRAP_PATH}..." >&2
BOOTSTRAP_RESP=""
for _ in 1 2 3 4 5; do
  BOOTSTRAP_RESP="$(wget -qO- --timeout=5 "${ORCHESTRATOR_URL}${BOOTSTRAP_PATH}" 2>/dev/null || true)"
  [ -n "$BOOTSTRAP_RESP" ] && break
  sleep 2
done

if [ -z "$BOOTSTRAP_RESP" ]; then
  logger -t cybercore-firstboot "Bootstrap fetch FAILED or empty — skipping tailscale up"
elif echo "$BOOTSTRAP_RESP" | grep -q '"error"'; then
  logger -t cybercore-firstboot "Bootstrap returned error: $(echo "$BOOTSTRAP_RESP" | head -c 200)"
else
  json_field() {
    echo "$BOOTSTRAP_RESP" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
  }
  TS_AUTHKEY="$(json_field tailscale_authkey)"
  TS_TAGS="$(json_field tailscale_tags)"
  TS_HOSTNAME="$(json_field tailscale_hostname)"
  TS_HOSTNAME="${TS_HOSTNAME:-lane-gw-${EXT_BASE3//./-}}"

  if [ -n "$TS_AUTHKEY" ]; then
    rc-service tailscale start >/dev/null 2>&1 \
      || /etc/init.d/tailscale start >/dev/null 2>&1 \
      || true
    for _ in 1 2 3 4 5; do
      tailscale status >/dev/null 2>&1 && break
      sleep 1
    done

    TS_UP_ARGS="--authkey=${TS_AUTHKEY} --advertise-routes=${EXT_NET} --hostname=${TS_HOSTNAME} --reset --accept-dns=false"
    if [ -n "$TS_TAGS" ]; then
      TS_UP_ARGS="$TS_UP_ARGS --advertise-tags=${TS_TAGS}"
    fi
    if tailscale up $TS_UP_ARGS >/tmp/tailscale-up.log 2>&1; then
      logger -t cybercore-firstboot "tailscale up OK: hostname=${TS_HOSTNAME} routes=${EXT_NET} tags=${TS_TAGS}"
    else
      logger -t cybercore-firstboot "tailscale up FAILED — see /tmp/tailscale-up.log"
    fi
    unset TS_AUTHKEY
  else
    logger -t cybercore-firstboot "Bootstrap response had no tailscale_authkey field — skipping"
  fi
fi
unset BOOTSTRAP_RESP

logger -t cybercore-firstboot "rendered v3: ext0=${EXT_IP}/${EXT_PREFIX} int0=${INT_IP}/${INT_PREFIX} controller=${CONTROLLER_IP}"
echo "[cybercore-firstboot] v3: ext0=${EXT_IP} int0=${INT_IP} controller=${CONTROLLER_IP}" >&2
FIRSTBOOT_EOF

# 2b. Default env file (admin.js can overwrite per-deploy via `pct push`).
cat > "$STAGING/cybercore-gateway.env" <<'ENV_EOF'
# /etc/cybercore-gateway.env
# Overrides for /etc/local.d/00-cybercore-firstboot.start (v3 segmented gateway).

# Upstream DNS (defaults to OPNsense lab gateway)
DNS_FORWARDER=100.100.60.1

# Internal lane domain (suffix appended to short hostnames in dnsmasq)
LANE_DOMAIN=cybercore.lan

# Convention: the GOAD controller VM gets <internal-base>.5 in every lane
CONTROLLER_OCTET=5

# DHCP scope for lane VMs on BOTH segments (excludes .1 gateway / .5 controller)
DHCP_START_OCTET=10
DHCP_END_OCTET=200

# --- Tailscale subnet router (BYOAB) ---
# The auth key is NOT stored here — firstboot pulls it from the orchestrator
# at boot via GET <CYBERCORE_ORCHESTRATOR_URL>/api/lane-bootstrap. The v3
# gateway advertises only the EXTERNAL segment's route.
CYBERCORE_ORCHESTRATOR_URL=http://100.100.20.50:3000
ENV_EOF

# 2c. Placeholder dnsmasq.conf — replaced at boot by firstboot once ext0/int0
#     have IPs. Minimal config so dnsmasq survives a brief start window.
cat > "$STAGING/dnsmasq.conf.placeholder" <<'PLACEHOLDER_EOF'
# Placeholder dnsmasq.conf — replaced at boot by
# /etc/local.d/00-cybercore-firstboot.start once ext0/int0 have IPs.
interface=lo
bind-interfaces
PLACEHOLDER_EOF

echo "==> Pushing v3 firstboot script..."
pct push "$TMP_VMID" "$STAGING/00-cybercore-firstboot.start" /etc/local.d/00-cybercore-firstboot.start --perms 0755

echo "==> Pushing /etc/cybercore-gateway.env (defaults)..."
pct push "$TMP_VMID" "$STAGING/cybercore-gateway.env" /etc/cybercore-gateway.env --perms 0644

echo "==> Pushing placeholder /etc/dnsmasq.conf..."
pct push "$TMP_VMID" "$STAGING/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

# 2d. Rework /etc/network/interfaces: rename the inherited lan0 stanza to
#     ext0 and add an int0 stanza, both `inet manual` so Proxmox's per-deploy
#     netN IP is the only source of truth (firstboot reads the live IPs).
echo "==> Reworking /etc/network/interfaces for ext0 + int0..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  IF=/etc/network/interfaces
  if [ ! -f "$IF" ]; then
    echo "No $IF present — writing a fresh one."
    cat > "$IF" <<FRESH_EOF
auto lo
iface lo inet loopback

auto wan0
iface wan0 inet manual

auto ext0
iface ext0 inet manual

auto int0
iface int0 inet manual
FRESH_EOF
  else
    cp "$IF" "${IF}.v2.bak"
    # Rename any lan0 stanza/lines to ext0.
    sed "s/lan0/ext0/g" "${IF}.v2.bak" > "$IF"
    grep -q "iface ext0" "$IF" || printf "\nauto ext0\niface ext0 inet manual\n" >> "$IF"
    grep -q "iface int0" "$IF" || printf "\nauto int0\niface int0 inet manual\n" >> "$IF"
  fi
  echo "--- $IF ---"
  cat "$IF"
  echo "-----------"
'

# 2e. Re-push the placeholder dnsmasq.conf as the last pre-shutdown step so
#     1695 never ships a stale render (mirrors the v2 bake precaution).
echo "==> Re-pushing placeholder dnsmasq.conf..."
pct push "$TMP_VMID" "$STAGING/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

pct exec "$TMP_VMID" -- /bin/sh -c '
  if [ -f /var/log/messages ]; then
    grep -v "cybercore-firstboot" /var/log/messages > /var/log/messages.tmp 2>/dev/null && mv /var/log/messages.tmp /var/log/messages
  fi
' 2>/dev/null || true

echo "==> Stopping temp CT..."
pct stop "$TMP_VMID"

# ---------- 3. Backup, install as 1695 ----------
mkdir -p "$DUMP_DIR"
echo "==> Backing up temp CT to $DUMP_DIR..."
vzdump "$TMP_VMID" --dumpdir "$DUMP_DIR" --compress zstd >/dev/null
DUMP_FILE=$(ls -t "$DUMP_DIR"/vzdump-lxc-${TMP_VMID}-*.tar.zst | head -1)
echo "==> Backup: $DUMP_FILE"

if pct config "$NEW_VMID" >/dev/null 2>&1; then
  echo "==> Destroying existing $NEW_VMID (FORCE=1)..."
  pct destroy "$NEW_VMID" --purge
fi

echo "==> Restoring backup as $NEW_VMID..."
pct restore "$NEW_VMID" "$DUMP_FILE" --storage "$STORAGE" >/dev/null

# 3-NIC subnet-agnostic net config:
#   net0 (wan0) — admin.js overrides at deploy time (lab uplink).
#   net1 (ext0) — external segment VNet. admin.js sets ip per-deploy.
#   net2 (int0) — internal segment VNet. admin.js sets ip per-deploy.
echo "==> Setting 3-NIC subnet-agnostic net config..."
pct set "$NEW_VMID" --net0 'name=wan0,bridge=vmbr0,ip=dhcp,firewall=0,type=veth'
pct set "$NEW_VMID" --net1 'name=ext0,bridge=vmbr0,type=veth'
pct set "$NEW_VMID" --net2 'name=int0,bridge=vmbr0,type=veth'

pct set "$NEW_VMID" --description "CyberCore lane gateway v3 — segmented DMZ topology.
3 NICs: wan0 (uplink) + ext0 (external/attacker) + int0 (internal/GOAD).
Firstboot renders dnsmasq + NAT + ext0<->int0 DROP from the live NIC IPs.
Built from $SRC_VMID by bake-lane-gateway-v3.sh."

pct set "$NEW_VMID" --template 1

# ---------- 4. Cleanup ----------
echo "==> Cleanup..."
pct destroy "$TMP_VMID" --purge 2>/dev/null || true
rm -f "$DUMP_FILE"

# ---------- 5. Verify: clone, set fake ext0/int0 IPs, boot, check render ----------
echo "==> Verifying: cloning $NEW_VMID -> $VERIFY_VMID with fake ext0=10.99.0.1/24 int0=10.199.0.1/24..."
pct clone "$NEW_VMID" "$VERIFY_VMID" --hostname lanegw-v3-verify --full --storage "$STORAGE" >/dev/null
ip link delete wan0 2>/dev/null || true
ip link delete ext0 2>/dev/null || true
ip link delete int0 2>/dev/null || true
pct set "$VERIFY_VMID" --net1 'name=ext0,bridge=vmbr0,ip=10.99.0.1/24,type=veth'
pct set "$VERIFY_VMID" --net2 'name=int0,bridge=vmbr0,ip=10.199.0.1/24,type=veth'
pct start "$VERIFY_VMID"

# Firstboot: wait-for-IP loops (up to ~30s for both NICs) + render + dnsmasq
# restart + Tailscale startup. 45s is a safe margin on cold boot.
sleep 45

echo "==> Verifying rendered config inside $VERIFY_VMID..."
RENDERED_OK=1
pct exec "$VERIFY_VMID" -- /bin/sh -c "grep -q 'dhcp-range=set:extnet,10.99.0.10,10.99.0.200' /etc/dnsmasq.conf" \
  || { echo "FAIL: external dhcp-range not rendered"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "grep -q 'dhcp-range=set:intnet,10.199.0.10,10.199.0.200' /etc/dnsmasq.conf" \
  || { echo "FAIL: internal dhcp-range not rendered"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o wan0 -j MASQUERADE" 2>/dev/null \
  || { echo "FAIL: external NAT MASQUERADE rule missing"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -t nat -C POSTROUTING -s 10.199.0.0/24 -o wan0 -j MASQUERADE" 2>/dev/null \
  || { echo "FAIL: internal NAT MASQUERADE rule missing"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i ext0 -o int0 -m comment --comment CYBERCORE-SEG -j DROP" 2>/dev/null \
  || { echo "FAIL: ext0->int0 segmentation DROP rule missing"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i int0 -o ext0 -m comment --comment CYBERCORE-SEG -j DROP" 2>/dev/null \
  || { echo "FAIL: int0->ext0 segmentation DROP rule missing"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C INPUT -i int0 -s 10.199.0.5 -p tcp --dport 22 -m comment --comment GOAD-CONTROLLER-SSH -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: controller ACCEPT rule missing for 10.199.0.5"; RENDERED_OK=0; }

pct stop "$VERIFY_VMID"
pct destroy "$VERIFY_VMID" --purge

echo ""
if [ "$RENDERED_OK" = "1" ]; then
  echo "==================================================================="
  echo "  SUCCESS: lane gateway v3 (segmented) template baked at VMID $NEW_VMID"
  echo "==================================================================="
  echo "  Verification clone rendered correctly for ext0=10.99.0.1 int0=10.199.0.1:"
  echo "    - dnsmasq dhcp-range  external 10.99.0.10..200 / internal 10.199.0.10..200"
  echo "    - NAT MASQUERADE      both subnets -> wan0"
  echo "    - segmentation        ext0<->int0 FORWARD DROP"
  echo "    - controller ACCEPT   10.199.0.5 -> int0:22"
  echo ""
  echo "  Used automatically by admin.js for subnet_scheme='v3' challenges."
  echo "==================================================================="
else
  echo "==================================================================="
  echo "  WARNING: $NEW_VMID was created but the verification clone had failures."
  echo "  Inspect manually:"
  echo "    pct clone $NEW_VMID 9999 --full --storage $STORAGE"
  echo "    pct set 9999 --net1 'name=ext0,bridge=vmbr0,ip=10.99.0.1/24,type=veth' \\"
  echo "                 --net2 'name=int0,bridge=vmbr0,ip=10.199.0.1/24,type=veth'"
  echo "    pct start 9999 && pct exec 9999 -- cat /etc/dnsmasq.conf"
  echo "==================================================================="
  exit 1
fi
