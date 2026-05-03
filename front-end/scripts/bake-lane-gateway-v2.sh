#!/bin/bash
# ============================================================================
# bake-lane-gateway-v2.sh
# ----------------------------------------------------------------------------
# Builds the v2 lane-gateway template at VMID 1694 by cloning the proven 1692
# template and stripping out everything that hardcoded the old shared
# 192.18.0.0/24 lane subnet.
#
# v1 (1692, current): every lane uses 192.18.0.0/24 with .1 as the gateway and
# .5 as the GOAD controller. dnsmasq.conf is baked in with that specific
# scope. Lane uniqueness is enforced only by VXLAN, not by addressing.
#
# v2 (1694, this script): subnet-agnostic. admin.js sets net1's IP per-deploy
# (e.g., 10.42.0.1/24), and a firstboot hook inside the LXC reads lan0's
# actual address at every boot and (re)renders dnsmasq.conf, the controller
# SSH-allow rule, and the lan->wan masquerade rule from it. The same template
# image works for any /24 in 10.0.0.0/8.
#
# This script does NOT modify 1692 — v1 stays available so in-flight classes
# keep working. New challenges using subnet_scheme='v2' clone 1694 instead.
#
# Run on a Proxmox node where 1692 lives. Idempotent only at the boundaries:
# refuses to clobber an existing 1694 unless FORCE=1.
#
# Companion to:
#   - bake-goad-controller-vm.sh (controller template, baked once, unchanged)
#   - patch-goad-gateway-key.sh (adds controller pubkey — already applied to
#     1692 and inherited via this clone, so 1694 ships with it too)
# ============================================================================
set -euo pipefail

SRC_VMID=${SRC_VMID:-1692}
NEW_VMID=${NEW_VMID:-1694}
TMP_VMID=${TMP_VMID:-9994}
VERIFY_VMID=${VERIFY_VMID:-9995}
STORAGE=${STORAGE:-vmpool}
DUMP_DIR=${DUMP_DIR:-/var/lib/vz/dump}
FORCE=${FORCE:-0}

# ---------- 0. Sanity ----------
if ! pct config "$SRC_VMID" >/dev/null 2>&1; then
  echo "ERROR: source template CT $SRC_VMID not found." >&2
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

# ---------- 1. Clone 1692 -> temp ----------
echo "==> Cloning $SRC_VMID -> $TMP_VMID..."
pct clone "$SRC_VMID" "$TMP_VMID" --hostname lanegw-v2-bake --full --storage "$STORAGE"

# pct start renames veth pairs to wan0/lan0; a previous failed attempt may
# have left those names lingering on the host net namespace.
ip link delete lan0 2>/dev/null || true
ip link delete wan0 2>/dev/null || true

# ---------- 2. Patch the temp clone ----------
echo "==> Starting temp CT $TMP_VMID..."
pct start "$TMP_VMID"

# Wait for the rootfs / network namespace to be ready
for _ in 1 2 3 4 5 6 7 8 9 10; do
  pct exec "$TMP_VMID" -- /bin/sh -c "test -d /etc/local.d" 2>/dev/null && break
  sleep 1
done

# Stage all file payloads on the host first, then `pct push` them into the
# temp clone. pct push is purpose-built for this and avoids stdin-piping
# fragility (vs `pct exec ... <<EOF`).
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# 2a. Firstboot script — renders dnsmasq + iptables from lan0's actual IP.
#     Runs every boot, idempotent. Numbered 00-* so it runs before any
#     existing /etc/local.d/*.start hook (50-gateway.start, etc).
cat > "$STAGING/00-cybercore-firstboot.start" <<'FIRSTBOOT_EOF'
#!/bin/sh
# /etc/local.d/00-cybercore-firstboot.start
# ---------------------------------------------------------------
# Reads lan0's IP and renders dnsmasq + iptables config from it.
# Idempotent — safe to re-run every boot. Installed by the v2
# bake script (bake-lane-gateway-v2.sh).
# ---------------------------------------------------------------
set -e

ENV_FILE=/etc/cybercore-gateway.env
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

# Defaults (overridable via /etc/cybercore-gateway.env, which admin.js
# can drop in at deploy time via `pct push`):
DNS_FORWARDER="${DNS_FORWARDER:-100.100.60.1}"   # OPNsense lab gateway
LANE_DOMAIN="${LANE_DOMAIN:-cybercore.lan}"
CONTROLLER_OCTET="${CONTROLLER_OCTET:-5}"        # GOAD controller is .5 by convention
DHCP_START_OCTET="${DHCP_START_OCTET:-10}"
DHCP_END_OCTET="${DHCP_END_OCTET:-200}"

# Wait for lan0 to have an address (admin.js sets it via `pct set`, but
# there can still be a tiny race vs local.d on cold boot).
LAN_CIDR=""
for _ in $(seq 1 15); do
  LAN_CIDR="$(ip -4 -o addr show lan0 2>/dev/null | awk '{print $4}' | head -1)"
  [ -n "$LAN_CIDR" ] && break
  sleep 1
done

if [ -z "$LAN_CIDR" ]; then
  echo "[cybercore-firstboot] lan0 has no IPv4 after 15s — skipping render" >&2
  exit 0
fi

LAN_IP="${LAN_CIDR%/*}"
LAN_PREFIX="${LAN_CIDR##*/}"
LAN_BASE3="$(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3}')"
LAN_NET="${LAN_BASE3}.0/${LAN_PREFIX}"

DHCP_START="${LAN_BASE3}.${DHCP_START_OCTET}"
DHCP_END="${LAN_BASE3}.${DHCP_END_OCTET}"
CONTROLLER_IP="${LAN_BASE3}.${CONTROLLER_OCTET}"

# Render /etc/dnsmasq.conf
cat > /etc/dnsmasq.conf <<DNSMASQ_EOF
# Auto-generated at boot by /etc/local.d/00-cybercore-firstboot.start.
# Hand edits will be overwritten on next boot. To override values, set
# variables in /etc/cybercore-gateway.env (DNS_FORWARDER, LANE_DOMAIN,
# CONTROLLER_OCTET, DHCP_START_OCTET, DHCP_END_OCTET).

interface=lan0
bind-interfaces
domain-needed
bogus-priv
no-resolv
server=${DNS_FORWARDER}
local=/${LANE_DOMAIN}/
domain=${LANE_DOMAIN}
expand-hosts

dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,12h
dhcp-option=option:router,${LAN_IP}
dhcp-option=option:dns-server,${LAN_IP}
dhcp-authoritative

# Per-host reservations (admin.js or the GOAD controller drops files here):
conf-dir=/etc/dnsmasq.d/,*.conf

log-dhcp
log-queries
DNSMASQ_EOF

# Make sure the reservations directory exists (controller writes here)
mkdir -p /etc/dnsmasq.d

# --- iptables: dynamic rules driven by lan0's current IP ---

# 1. Allow GOAD controller (LAN_BASE3.<CONTROLLER_OCTET>) to SSH the gateway
#    over lan0. Strip any stale rule first (in case lan0 changed subnet).
iptables-save | grep -v "GOAD-CONTROLLER-SSH" | iptables-restore || true
iptables -I INPUT -i lan0 -s "${CONTROLLER_IP}" -p tcp --dport 22 \
  -m comment --comment "GOAD-CONTROLLER-SSH" -j ACCEPT

# 2. Masquerade lane subnet out wan0
if ! iptables -t nat -C POSTROUTING -s "${LAN_NET}" -o wan0 -j MASQUERADE 2>/dev/null; then
  iptables -t nat -A POSTROUTING -s "${LAN_NET}" -o wan0 -j MASQUERADE
fi

# Persist current rule set (Alpine iptables init reloads from here)
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules-save

# (Re)start dnsmasq with new config. `restart` is start-or-restart on Alpine.
rc-service dnsmasq restart >/dev/null 2>&1 \
  || /etc/init.d/dnsmasq restart >/dev/null 2>&1 \
  || rc-service dnsmasq start >/dev/null 2>&1 \
  || true

# --- Tailscale subnet router (BYOAB) ---
# If TAILSCALE_AUTHKEY is set in /etc/cybercore-gateway.env (admin.js drops
# it per-deploy), bring up Tailscale advertising this lane's /24 so the
# tailnet can route to lane VMs. Tag-driven ACLs in the tailnet decide
# which student tags can reach this lane's tag.
#
# tailscaled runs in userspace-networking mode (configured by the bake
# script in /etc/conf.d/tailscaled), so no TUN device or LXC capability
# tweaks are needed. Subnet routing still works.
if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
  TS_HOSTNAME="${TAILSCALE_HOSTNAME:-lane-gw-${LAN_BASE3//./-}}"
  TS_TAGS="${TAILSCALE_TAGS:-}"
  rc-service tailscale start >/dev/null 2>&1 \
    || /etc/init.d/tailscale start >/dev/null 2>&1 \
    || true
  # Give the daemon a moment to come up before `up`
  for _ in 1 2 3 4 5; do
    tailscale status >/dev/null 2>&1 && break
    sleep 1
  done
  TS_UP_ARGS="--authkey=${TAILSCALE_AUTHKEY} --advertise-routes=${LAN_NET} --hostname=${TS_HOSTNAME} --reset --accept-dns=false"
  if [ -n "$TS_TAGS" ]; then
    TS_UP_ARGS="$TS_UP_ARGS --advertise-tags=${TS_TAGS}"
  fi
  if tailscale up $TS_UP_ARGS >/tmp/tailscale-up.log 2>&1; then
    # Auth succeeded — the key is now consumed (one-shot, single-use), but
    # wipe it from /etc/cybercore-gateway.env anyway so a forensic snapshot
    # of the rootfs after first boot doesn't contain the key string.
    if [ -w /etc/cybercore-gateway.env ]; then
      sed -i 's|^TAILSCALE_AUTHKEY=.*|TAILSCALE_AUTHKEY=|' /etc/cybercore-gateway.env
    fi
    logger -t cybercore-firstboot "tailscale up OK: hostname=${TS_HOSTNAME} routes=${LAN_NET} tags=${TS_TAGS} (key wiped)"
  else
    logger -t cybercore-firstboot "tailscale up FAILED — see /tmp/tailscale-up.log"
  fi
else
  logger -t cybercore-firstboot "TAILSCALE_AUTHKEY not set — skipping tailscale up (BYOAB disabled for this lane)"
fi

logger -t cybercore-firstboot "rendered: lan0=${LAN_IP}/${LAN_PREFIX} net=${LAN_NET} dhcp=${DHCP_START}-${DHCP_END} controller=${CONTROLLER_IP} dns_fwd=${DNS_FORWARDER}"
echo "[cybercore-firstboot] lan0=${LAN_IP}/${LAN_PREFIX} controller=${CONTROLLER_IP}" >&2
FIRSTBOOT_EOF

# 2b. Default env file (admin.js can overwrite per-deploy via `pct push`).
cat > "$STAGING/cybercore-gateway.env" <<'ENV_EOF'
# /etc/cybercore-gateway.env
# Overrides for /etc/local.d/00-cybercore-firstboot.start.
# admin.js may overwrite this file at deploy time via `pct push`.

# Upstream DNS (defaults to OPNsense lab gateway)
DNS_FORWARDER=100.100.60.1

# Internal lane domain (suffix appended to short hostnames in dnsmasq)
LANE_DOMAIN=cybercore.lan

# Convention: the GOAD controller VM gets <lan-base>.5 in every lane
CONTROLLER_OCTET=5

# DHCP scope for lane VMs (excludes .1 gateway and .5 controller)
DHCP_START_OCTET=10
DHCP_END_OCTET=200

# --- Tailscale subnet router (BYOAB) ---
# Set TAILSCALE_AUTHKEY to enable Tailscale on this lane gateway. The
# firstboot hook will run `tailscale up` advertising the lane's /24.
# Generate keys at https://login.tailscale.com/admin/settings/keys —
# pre-approved + ephemeral + tagged keys are recommended (one-shot per
# lane, auto-cleanup on teardown).
#
# Leave TAILSCALE_AUTHKEY empty (default) to skip Tailscale setup.
TAILSCALE_AUTHKEY=
TAILSCALE_HOSTNAME=
TAILSCALE_TAGS=
ENV_EOF

# 2c. Placeholder dnsmasq.conf — replaced at boot by firstboot once lan0
#     has an IP. Empty config so dnsmasq survives a brief start window.
cat > "$STAGING/dnsmasq.conf.placeholder" <<'PLACEHOLDER_EOF'
# Placeholder dnsmasq.conf — replaced at boot by
# /etc/local.d/00-cybercore-firstboot.start once lan0 has an IP.
interface=lo
bind-interfaces
PLACEHOLDER_EOF

echo "==> Pushing firstboot script to /etc/local.d/00-cybercore-firstboot.start..."
pct push "$TMP_VMID" "$STAGING/00-cybercore-firstboot.start" /etc/local.d/00-cybercore-firstboot.start --perms 0755

echo "==> Pushing /etc/cybercore-gateway.env (defaults)..."
pct push "$TMP_VMID" "$STAGING/cybercore-gateway.env" /etc/cybercore-gateway.env --perms 0644

echo "==> Pushing placeholder /etc/dnsmasq.conf..."
pct push "$TMP_VMID" "$STAGING/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

# 2d. Strip the baked static IP from /etc/network/interfaces' lan0 stanza.
#     1692 has `iface lan0 inet static / address 192.18.0.1 / netmask ...` baked
#     in. Alpine's `networking` service runs ifup at boot and forces that IP
#     onto lan0, overriding whatever Proxmox set via `pct set --net1`. We
#     rewrite the stanza to `inet manual` so the Proxmox .conf is the only
#     source of truth — firstboot then reads the per-deploy IP correctly.
echo "==> Rewriting lan0 stanza in /etc/network/interfaces to 'inet manual'..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  IF_FILE=/etc/network/interfaces
  if [ ! -f "$IF_FILE" ]; then
    echo "No $IF_FILE present (fine)."
    exit 0
  fi
  cp "$IF_FILE" "${IF_FILE}.v1.bak"
  awk "
    BEGIN { in_lan0 = 0 }
    /^iface lan0[[:space:]]/ {
      in_lan0 = 1
      sub(/inet static/, \"inet manual\")
      sub(/inet dhcp/,   \"inet manual\")
      print
      next
    }
    /^(iface|auto|allow-)[[:space:]]/ && in_lan0 {
      in_lan0 = 0
    }
    in_lan0 && /^[[:space:]]+(address|netmask|gateway|broadcast|hwaddress|pre-up|post-up|up)[[:space:]]/ { next }
    { print }
  " "${IF_FILE}.v1.bak" > "$IF_FILE"
  echo "Rewrote lan0 stanza. Backup at ${IF_FILE}.v1.bak."
  echo "--- new $IF_FILE ---"
  cat "$IF_FILE"
  echo "--------------------"
'

# 2e. Neutralize /etc/local.d/50-gateway.start.
#     The v1 50-gateway.start applied lan0's IP (`ip addr add 192.18.0.1/24
#     dev lan0`), the lane->wan MASQUERADE for 192.18.0.0/24, and the
#     controller-SSH ACCEPT — all hardcoded to v1's shared subnet. Surgical
#     sed isn't enough because we'd have to know which lines to keep; we
#     instead back the original aside as `.v1.bak` and replace 50-gateway.start
#     with a no-op stub. Firstboot (00-cybercore-firstboot.start) now handles
#     every responsibility 50-gateway.start had, but driven by lan0's actual
#     per-deploy IP.
#
#     Defensive sweep: comment out any *remaining* 192.18.0 references inside
#     /etc/local.d/ and /etc/init.d/ — catches anything ansible or earlier
#     bake steps may have planted that we don't know about.
echo "==> Neutralizing /etc/local.d/50-gateway.start (firstboot now handles its job)..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  HOOK=/etc/local.d/50-gateway.start
  if [ -f "$HOOK" ]; then
    cp "$HOOK" "${HOOK}.v1.bak"
    echo "--- ORIGINAL $HOOK (preserved at ${HOOK}.v1.bak) ---"
    cat "${HOOK}.v1.bak"
    echo "----------------------------------------------------"
    cat > "$HOOK" <<STUB_EOF
#!/bin/sh
# /etc/local.d/50-gateway.start (v2 stub)
# ----------------------------------------------------------
# The v1 contents (192.18.0.1 IP setup, NAT, firewall) are
# preserved at /etc/local.d/50-gateway.start.v1.bak.
#
# All lane gateway responsibilities (lan IP awareness, dnsmasq
# render, controller SSH ACCEPT, lane MASQUERADE) are now in
# /etc/local.d/00-cybercore-firstboot.start, driven by lan0s
# actual per-deploy IP. This stub exists so any process still
# expecting this hook to be present finds something runnable.
exit 0
STUB_EOF
    chmod +x "$HOOK"
    echo "Replaced $HOOK with no-op stub."
  else
    echo "No $HOOK present (fine)."
  fi
'

echo "==> Defensive sweep: commenting out remaining 192.18.0.x in /etc/local.d/ and /etc/init.d/..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  for d in /etc/local.d /etc/init.d; do
    [ -d "$d" ] || continue
    # Skip our backup file and the firstboot script (firstboot has no 192.18 refs anyway)
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      case "$f" in
        *.v1.bak) continue ;;
        */00-cybercore-firstboot.start) continue ;;
      esac
      if grep -q "192\.18\.0" "$f" 2>/dev/null; then
        echo "  patching $f"
        sed -i "s|^\([^#]*192\.18\.0[^#]*\)$|# v2-disabled: \1|" "$f"
      fi
    done
  done
  echo "Sweep complete. Remaining 192.18.0 references (should all be in comments or .v1.bak):"
  grep -rn "192\.18\.0" /etc/local.d /etc/init.d 2>/dev/null || true
'

# 2f. Make sure dnsmasq + local services are enabled (no-op if already done in 1692).
pct exec "$TMP_VMID" -- /bin/sh -c "rc-update add dnsmasq default 2>/dev/null || true"
pct exec "$TMP_VMID" -- /bin/sh -c "rc-update add local default 2>/dev/null || true"

# 2g. Install Tailscale + configure userspace-networking mode.
#     Userspace mode means tailscaled doesn't need a TUN device — works in
#     unprivileged Proxmox LXCs without any LXC config tweaks. Subnet
#     routing (the BYOAB feature we want) still works in userspace mode.
#     Tailscale is installed but NOT auto-launched here. firstboot calls
#     `tailscale up` only when /etc/cybercore-gateway.env has a
#     TAILSCALE_AUTHKEY set (admin.js drops one in per-deploy).
echo "==> Installing Tailscale + configuring userspace-networking mode..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  # Make sure community repo is enabled (Tailscale lives there on Alpine 3.16+;
  # newer Alpine has it in main, but enabling community is harmless either way).
  if ! grep -q "^http.*community" /etc/apk/repositories 2>/dev/null; then
    # Mirror the alpine version line that already exists (use the same release)
    MAIN_LINE="$(grep "^http.*main$" /etc/apk/repositories 2>/dev/null | head -1)"
    if [ -n "$MAIN_LINE" ]; then
      COMMUNITY_LINE="$(echo "$MAIN_LINE" | sed "s|/main$|/community|")"
      echo "$COMMUNITY_LINE" >> /etc/apk/repositories
      echo "Enabled community repo: $COMMUNITY_LINE"
    fi
  fi
  apk update >/dev/null 2>&1 || true
  if ! command -v tailscale >/dev/null 2>&1; then
    apk add --no-cache tailscale 2>&1 | tail -5
  else
    echo "tailscale already installed."
  fi
  # Configure tailscaled to run in userspace-networking mode.
  mkdir -p /etc/conf.d
  cat > /etc/conf.d/tailscaled <<TSD_EOF
# Configured by bake-lane-gateway-v2.sh.
# Userspace mode means no TUN device needed — works in unprivileged LXC.
# Subnet routing still works (the BYOAB use case).
command_args="--tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state"
TSD_EOF
  rc-update add tailscale default 2>/dev/null || true
  echo "Tailscale install + config complete."
'

# 2h. CRITICAL: re-push the placeholder dnsmasq.conf as the absolute last
#     pre-shutdown step. During the temp-CT phase firstboot can get triggered
#     (mechanism unclear — possibly OpenRC re-asserts the local runlevel
#     after rc-update), and if it runs while lan0 still has 1692's inherited
#     192.18.0.1/24, it bakes a stale render into the rootfs that vzdump
#     captures. By over-writing dnsmasq.conf with the placeholder right
#     before pct stop, we guarantee 1694 ships with the placeholder no
#     matter what happened earlier — firstboot on user-deploys then renders
#     fresh from the per-deploy lan0 IP.
echo "==> Re-pushing placeholder dnsmasq.conf to clear any stale render..."
pct push "$TMP_VMID" "$STAGING/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

# Also wipe any old firstboot log lines from the temp CT so /var/log/messages
# in 1694 doesn't carry forward the bake-time render entry. Clones get a fresh
# log going forward.
pct exec "$TMP_VMID" -- /bin/sh -c '
  if [ -f /var/log/messages ]; then
    grep -v "cybercore-firstboot" /var/log/messages > /var/log/messages.tmp 2>/dev/null && mv /var/log/messages.tmp /var/log/messages
  fi
' 2>/dev/null || true

echo "==> Stopping temp CT..."
pct stop "$TMP_VMID"

# ---------- 3. Backup, install as 1694 ----------
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

# Subnet-agnostic net config:
#   net0 (wan0) — admin.js fully overrides at deploy time. Default left as
#                 vmbr0 with DHCP so a manual start is harmless.
#   net1 (lan0) — NO IP in the template. admin.js sets `ip=10.<C>.0.1/24`
#                 per-challenge. firstboot reads whatever it ends up being.
echo "==> Setting subnet-agnostic net config..."
pct set "$NEW_VMID" --net0 'name=wan0,bridge=vmbr0,ip=dhcp,firewall=0,type=veth'
pct set "$NEW_VMID" --net1 'name=lan0,bridge=vmbr0,type=veth'

pct set "$NEW_VMID" --description "CyberCore lane gateway v2 — subnet-agnostic.
admin.js sets net1 ip per-deploy; firstboot renders dnsmasq from lan0 IP.
Built from $SRC_VMID by bake-lane-gateway-v2.sh."

pct set "$NEW_VMID" --template 1

# ---------- 4. Cleanup ----------
echo "==> Cleanup..."
pct destroy "$TMP_VMID" --purge 2>/dev/null || true
rm -f "$DUMP_FILE"

# ---------- 5. Verify: clone, set a fake lan0 IP, boot, check render ----------
echo "==> Verifying: cloning $NEW_VMID -> $VERIFY_VMID with fake lan0=10.99.0.1/24..."
pct clone "$NEW_VMID" "$VERIFY_VMID" --hostname lanegw-v2-verify --full --storage "$STORAGE" >/dev/null
ip link delete lan0 2>/dev/null || true
ip link delete wan0 2>/dev/null || true
pct set "$VERIFY_VMID" --net1 'name=lan0,bridge=vmbr0,ip=10.99.0.1/24,type=veth'
pct start "$VERIFY_VMID"

# Give firstboot time to complete. Firstboot's wait-for-lan0-IP loop
# alone can take up to 15s, then it renders + restarts dnsmasq (~2s).
# 20s gives enough headroom on Ceph-backed clones.
sleep 20

echo "==> Verifying rendered config inside $VERIFY_VMID..."
RENDERED_OK=1
pct exec "$VERIFY_VMID" -- /bin/sh -c "grep -q 'dhcp-range=10.99.0.10,10.99.0.200' /etc/dnsmasq.conf" \
  || { echo "FAIL: dnsmasq.conf did not render expected dhcp-range"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C INPUT -i lan0 -s 10.99.0.5 -p tcp --dport 22 -m comment --comment GOAD-CONTROLLER-SSH -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: controller ACCEPT rule missing for 10.99.0.5"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o wan0 -j MASQUERADE" 2>/dev/null \
  || { echo "FAIL: lane NAT MASQUERADE rule missing for 10.99.0.0/24"; RENDERED_OK=0; }

pct stop "$VERIFY_VMID"
pct destroy "$VERIFY_VMID" --purge

echo ""
if [ "$RENDERED_OK" = "1" ]; then
  echo "==================================================================="
  echo "  SUCCESS: lane gateway v2 template baked at VMID $NEW_VMID"
  echo "==================================================================="
  echo "  Verification clone rendered correctly for lan0=10.99.0.1/24:"
  echo "    - dnsmasq dhcp-range  10.99.0.10 .. 10.99.0.200"
  echo "    - controller ACCEPT   10.99.0.5 -> lan0:22"
  echo "    - lane MASQUERADE     10.99.0.0/24 -> wan0"
  echo ""
  echo "  Use from admin.js:"
  echo "    pct clone $NEW_VMID <ctid> --full --storage $STORAGE"
  echo "    pct set <ctid> \\"
  echo "      --net0 'name=wan0,bridge=vmbr0,ip=100.100.60.<C>/24,gw=100.100.60.1,firewall=0,type=veth' \\"
  echo "      --net1 'name=lan0,bridge=<vnet>,ip=10.<C>.0.1/24,type=veth'"
  echo "    pct push <ctid> custom-env-file /etc/cybercore-gateway.env  # optional"
  echo "    pct start <ctid>"
  echo "==================================================================="
else
  echo "==================================================================="
  echo "  WARNING: $NEW_VMID was created but verification clone had failures."
  echo "  Inspect manually:"
  echo "    pct clone $NEW_VMID 9999 --full --storage $STORAGE"
  echo "    pct set 9999 --net1 'name=lan0,bridge=vmbr0,ip=10.99.0.1/24,type=veth'"
  echo "    pct start 9999 && pct exec 9999 -- cat /etc/dnsmasq.conf"
  echo "==================================================================="
  exit 1
fi
