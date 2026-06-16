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
# Tailscale runs in KERNEL networking mode here (the v2 template uses
# userspace mode). Kernel mode gives the gateway a real tailscale0 device,
# which is required both for subnet routing INTO the lane and for lane
# hosts to initiate connections back OUT into the Tailnet — e.g. a reverse
# shell from a lane host to a BYOD attacker laptop. This needs /dev/net/tun
# in the container; admin.js adds the passthrough at deploy time.
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

# The v3 gateway runs Tailscale in kernel mode and therefore needs
# /dev/net/tun passed into its CT. The `lxc.mount.entry` bind-mount added
# later requires the tun device to exist on THIS node first.
modprobe tun 2>/dev/null || true
if [ ! -e /dev/net/tun ]; then
  echo "ERROR: /dev/net/tun missing on this node and 'modprobe tun' failed." >&2
  echo "       Load the tun module, then re-run." >&2
  exit 1
fi

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
KALI_OCTET="${KALI_OCTET:-50}"                   # Kali attack box — external .50
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
# Reserve <ext-base>.<KALI_OCTET> for the Kali attack box on the EXTERNAL segment.
# Match is by the hostname the client sends in its DHCPREQUEST — Kali always
# identifies as "kali" — so it deterministically lands on .50 with no per-deploy
# setup, matching the CYBERCORE-KALI-RDP wan0:3389 DNAT installed below. v2 had
# this in its single scope; v3 was missing it, so the attack box DHCP'd a random
# ext IP and the .50 DNAT pointed at nothing. Mirrors bake-lane-gateway-v2.sh:167.
dhcp-host=kali,${EXT_BASE3}.${KALI_OCTET}

# Internal segment — GOAD Active Directory VMs + controller.
dhcp-range=set:intnet,${INT_BASE3}.${DHCP_START_OCTET},${INT_BASE3}.${DHCP_END_OCTET},255.255.255.0,12h
dhcp-option=tag:intnet,option:router,${INT_BASE3}.1
dhcp-option=tag:intnet,option:dns-server,${INT_BASE3}.1
# Pre-baked GOAD golden images keep their baked Windows hostnames and DHCP for
# their AD-expected internal IPs. Reserve by hostname (same mechanism as the
# Kali line above) so each lands on its exact octet DETERMINISTICALLY — not by
# DHCP-request order, which could otherwise swap the two DCs' IPs and break the
# baked AD. Octets match goad-deploy.js GOAD_LABS; hostnames come from the lab's
# config.json. Harmless on non-GOAD v3 lanes (no client sends these names).
# Add a line here for any other pre-baked lab's hosts.
dhcp-host=TUC-DC01,${INT_BASE3}.10
dhcp-host=TUC-DC02,${INT_BASE3}.11
dhcp-host=TUC-SRV02,${INT_BASE3}.22

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
# IMPORTANT: the lane-gateway template ships with `-P INPUT DROP` /
# `-P FORWARD DROP` and every allow-rule hard-keyed to the v1/v2 interface
# name `lan0`. v3's lane NICs are `ext0`/`int0`, so none of the baked rules
# match — without the rules below the gateway silently DROPs the lane's
# DHCP/DNS (INPUT) and all of its internet traffic (FORWARD). We add an
# explicit, comment-tagged rule set for ext0/int0; the dead lan0 rules are
# left in place (harmless — no lan0 exists to match them).
#
# Strip any stale CyberCore-tagged rules first so re-runs stay clean.
iptables-save | grep -vE 'GOAD-CONTROLLER-SSH|CYBERCORE-SEG|CYBERCORE-V3|CYBERCORE-LAB-DROP|CYBERCORE-LAB-DNS|CYBERCORE-IMAGE-PULL|CYBERCORE-KALI-RDP' | iptables-restore || true

# 1. INPUT — let lane VMs reach the gateway's own services (DHCP, DNS, NTP,
#    ping) on BOTH segments. Without the DHCP rule, `-P INPUT DROP` eats
#    every DHCPDISCOVER and lane VMs never get an address.
for LANIF in ext0 int0; do
  iptables -A INPUT -i "$LANIF" -p udp --dport 67:68 -m comment --comment "CYBERCORE-V3" -j ACCEPT
  iptables -A INPUT -i "$LANIF" -p udp --dport 53    -m comment --comment "CYBERCORE-V3" -j ACCEPT
  iptables -A INPUT -i "$LANIF" -p tcp --dport 53    -m comment --comment "CYBERCORE-V3" -j ACCEPT
  iptables -A INPUT -i "$LANIF" -p udp --dport 123   -m comment --comment "CYBERCORE-V3" -j ACCEPT
  iptables -A INPUT -i "$LANIF" -p icmp              -m comment --comment "CYBERCORE-V3" -j ACCEPT
done

# 2. INPUT — the GOAD controller (internal .CONTROLLER_OCTET) SSHes the
#    gateway over int0 to write DHCP reservations.
iptables -I INPUT -i int0 -s "${CONTROLLER_IP}" -p tcp --dport 22 \
  -m comment --comment "GOAD-CONTROLLER-SSH" -j ACCEPT

# 3. FORWARD — both segments out to the internet. Return traffic is handled by a
#    RELATED,ESTABLISHED accept added in section 4c, NOT here: it MUST sit ABOVE
#    the containment DROPs (4/4a), and those are inserted (`-I`) at the top of the
#    chain. Appending the stateful accept here left it BELOW the LAB-DROP, which
#    dropped the REPLY half of the Kali RDP DNAT (Kali on ext0 answering Guac on
#    the 100.100.0.0/16 backbone) — student RDP consoles showed "remote desktop
#    server unreachable" even though the inbound SYN reached Kali. See 4c.
#    `-P FORWARD DROP` is the default, so these explicit accepts are required.
iptables -A FORWARD -i ext0 -o wan0 -m comment --comment "CYBERCORE-V3" -j ACCEPT
iptables -A FORWARD -i int0 -o wan0 -m comment --comment "CYBERCORE-V3" -j ACCEPT

# 3a. FORWARD — let the EXTERNAL segment reach the Tailnet. This is what
#     lets a lane host on ext0 call back to a BYOD attacker laptop over
#     Tailscale (reverse shells / callbacks). int0 deliberately gets NO
#     such rule: the internal GOAD subnet must still pivot through the DMZ
#     host. Return traffic is covered by the RELATED,ESTABLISHED accept
#     above. tailscale0 does not exist yet at this point in firstboot —
#     iptables accepts rules naming a not-yet-present interface, and the
#     rule starts matching once tailscaled brings the device up below.
iptables -A FORWARD -i ext0 -o tailscale0 -m comment --comment "CYBERCORE-V3" -j ACCEPT

# 3b. Kali attack-box DNAT — forward wan0:3389 to the lane's Kali on ext0
#     (.KALI_OCTET, pinned by admin.js via cloud-init ipconfig0). The
#     group-deploy path points Guacamole at the gateway's wan0 IP:3389 and
#     RELIES on this DNAT ("via gateway DNAT" in the deploy log); without it,
#     student RDP to Kali fails. Mirrors v2's inline rule (bake-lane-gateway-v2.sh
#     section 3) but targets ext0 instead of lan0. Static dst (Kali is pinned to
#     .50), so no watcher is needed. The top-of-block strip removes any stale
#     copy, so a plain append stays idempotent across reboots.
KALI_IP="${EXT_BASE3}.${KALI_OCTET}"
# Idempotent + self-verifying DNAT install. The top-of-script
# `iptables-save | grep | iptables-restore` strip can mishandle the nat table on
# this nf_tables-backend gateway (a full `iptables -t nat -S` reports the table
# "incompatible", and `nft` isn't installed), and on at least one gateway
# firstbooted across BOTH v2 and v3 the DNAT ended up silently MISSING while the
# FORWARD accept survived — student RDP then dead-ends on an un-DNAT'd wan0:3389
# and Guac shows "remote desktop server unreachable". Per-chain ops DO work here,
# so don't trust the bulk strip for this rule: explicitly delete any stale copy,
# add fresh, then VERIFY and log an ERROR on failure so it can never vanish
# silently again (the missing rule is otherwise invisible until a student tries
# to connect).
DNAT_SPEC="-i wan0 -p tcp --dport 3389 -m comment --comment CYBERCORE-KALI-RDP -j DNAT --to-destination ${KALI_IP}:3389"
# Strip ANY pre-existing :3389 DNAT in PREROUTING — not just our own commented
# one. A stray, uncommented DNAT (observed once: a leftover wan0:3389 → srv02
# from this gateway's churn) sits AHEAD of ours in PREROUTING and silently eats
# every student RDP, sending it to the wrong host. The old narrow `-C/-D` loop
# only removed our exact rule, so it couldn't clear a stray. `iptables -S` prints
# each rule; swap -A→-D to delete it. Loop until no :3389 DNAT remains, then add
# ours as the sole one. (Idempotent across reboots: ours is stripped + re-added.)
while true; do
  _stray="$(iptables -t nat -S PREROUTING 2>/dev/null | grep -- '--dport 3389' | grep -m1 'DNAT')"
  [ -z "$_stray" ] && break
  iptables -t nat $(echo "$_stray" | sed 's/^-A /-D /') 2>/dev/null || break
done
iptables -t nat -A PREROUTING $DNAT_SPEC
iptables -A FORWARD -i wan0 -o ext0 -p tcp -d "${KALI_IP}" --dport 3389 \
  -m comment --comment "CYBERCORE-KALI-RDP" -j ACCEPT
if iptables -t nat -C PREROUTING $DNAT_SPEC 2>/dev/null; then
  logger -t cybercore-firstboot "iptables: CYBERCORE-KALI-RDP DNAT wan0:3389 -> ${KALI_IP}:3389 (ext0) [verified]"
else
  logger -t cybercore-firstboot "ERROR: CYBERCORE-KALI-RDP DNAT FAILED to install -> ${KALI_IP}:3389 (nat table state?); student RDP to Kali will NOT work"
fi

# 4. FORWARD SEGMENTATION — drop all traffic between the external and
#    internal segments. Inserted at the TOP of FORWARD so it wins over the
#    accepts above. This is the v3 attack-path enforcement: Kali (ext0)
#    reaches the internet and the dual-homed DMZ host, but never the GOAD
#    subnet (int0) directly. The Ligolo pivot is application-layer through
#    the DMZ host's own NICs, so it is unaffected by these FORWARD rules.
iptables -I FORWARD -i ext0 -o int0 -m comment --comment "CYBERCORE-SEG" -j DROP
iptables -I FORWARD -i int0 -o ext0 -m comment --comment "CYBERCORE-SEG" -j DROP

# 4a. LAB-PERIMETER CONTAINMENT + image-pull exception (mirrors v1/v2).
#     The broad ext0/int0 -> wan0 accepts above would otherwise let lane VMs
#     reach the ENTIRE lab — 100.100.0.0/16, which sits inside the Tailscale
#     CGNAT range 100.64.0.0/10: the orchestrator, OPNsense, DNS, other lanes.
#     v1/v2 block lane->lab at the perimeter; do the same here. Two critical
#     differences from v1/v2:
#       - Scope the DROP to `-o wan0` and to the LAB range (100.100.0.0/16),
#         NOT the whole 100.64.0.0/10. In kernel mode the Tailnet IS 100.64/10
#         reached via tailscale0 — a blanket /10 drop would kill ext0->tailscale0
#         reverse shells. `-o wan0 -d 100.100.0.0/16` contains only lab-over-uplink.
#       - These must sit ABOVE the broad ext0/int0 -> wan0 ACCEPTs, so they are
#         INSERTED (`-I`), not appended. Image-pull is inserted last so it ends
#         up above the lab DROP (lane -> orchestrator:80 wins).
#
#     dst MUST be the lab-internal IP (CYBERCORE_INTERNAL_URL, default
#     100.100.20.50:80) — the same value vuln-app-builder.js embeds into
#     install_script as LANE_ORCH_URL. The public CYBERCORE_ORCHESTRATOR_URL
#     hostname would resolve to the wrong dst and miss every packet. Reply
#     traffic rides the RELATED,ESTABLISHED accept above.
ORCH_INTERNAL_HOST_FOR_IPT="$(echo "${CYBERCORE_INTERNAL_URL:-http://100.100.20.50:80}" | sed -E 's|^https?://||; s|[:/].*$||')"
# Containment: drop both segments -> lab range over the uplink.
iptables -I FORWARD -i int0 -o wan0 -d 100.100.0.0/16 -m comment --comment "CYBERCORE-LAB-DROP" -j DROP
iptables -I FORWARD -i ext0 -o wan0 -d 100.100.0.0/16 -m comment --comment "CYBERCORE-LAB-DROP" -j DROP
# DNS exception — GOAD Windows VMs query a LAB resolver DIRECTLY during EARLY
# provisioning, before the GOAD common role repoints them at the lane gateway's
# dnsmasq. WHICH resolver varies across templates/runs (BAKE_DNS=100.100.0.1,
# OPNsense 100.100.60.1, sometimes FreeIPA 100.100.20.20), so instead of
# whitelisting each IP — and playing whack-a-mole when one is missed — allow DNS
# (:53 ONLY) to the WHOLE lab range above the DROP. A blackholed DNS query is
# exactly what made the GOAD "egress preflight" TIME OUT (DownloadString reported
# a timeout, not a resolve error — the signature of dropped DNS packets, not a
# dead resolver). Everything else to the lab (HTTP/SMB/orchestrator-admin/other
# lanes) stays blocked by the DROP below. :53 to lab resolvers is a tiny hole.
for SEG in int0 ext0; do
  iptables -I FORWARD -i "$SEG" -o wan0 -d 100.100.0.0/16 -p udp --dport 53 \
    -m comment --comment "CYBERCORE-LAB-DNS" -j ACCEPT
  iptables -I FORWARD -i "$SEG" -o wan0 -d 100.100.0.0/16 -p tcp --dport 53 \
    -m comment --comment "CYBERCORE-LAB-DNS" -j ACCEPT
done
# Exception: one hole per segment for the prebuilt vuln-app image pull. Inserted
# AFTER the drops so they land above them (lower position number wins).
iptables -I FORWARD -i int0 -o wan0 -s "${INT_NET}" -d "${ORCH_INTERNAL_HOST_FOR_IPT}" \
  -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m comment --comment "CYBERCORE-IMAGE-PULL" -j ACCEPT
iptables -I FORWARD -i ext0 -o wan0 -s "${EXT_NET}" -d "${ORCH_INTERNAL_HOST_FOR_IPT}" \
  -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m comment --comment "CYBERCORE-IMAGE-PULL" -j ACCEPT
logger -t cybercore-firstboot "iptables: CYBERCORE-LAB-DROP ext0/int0 -> 100.100.0.0/16 (-o wan0); CYBERCORE-IMAGE-PULL ext0/int0 -> ${ORCH_INTERNAL_HOST_FOR_IPT}:80"

# 4c. STATEFUL RETURN — accept established/related traffic ABOVE the containment
#     drops. Sections 4/4a inserted SEG/LAB-DROP at the top of FORWARD with `-I`,
#     which also placed them above the return accept that section 3 used to
#     append. That dropped the REPLY half of the Kali RDP DNAT (Kali ext0 ->
#     Guac on 100.100.0.0/16): the inbound SYN reached Kali but the SYN-ACK was
#     dropped, so RDP timed out ("remote desktop server unreachable"). Insert the
#     stateful accept LAST so it lands at position 1, above EVERY drop. NEW
#     lane->backbone connections still hit the DROP (only return traffic for
#     already-permitted flows passes), so the anti-pivot containment is intact.
iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED \
  -m comment --comment "CYBERCORE-V3" -j ACCEPT
logger -t cybercore-firstboot "iptables: CYBERCORE-V3 stateful return accept hoisted to FORWARD pos 1 (above LAB-DROP)"

# 5. NAT both lane subnets out wan0.
for NET in "$EXT_NET" "$INT_NET"; do
  if ! iptables -t nat -C POSTROUTING -s "$NET" -o wan0 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$NET" -o wan0 -j MASQUERADE
  fi
done

# 5a. NAT the EXTERNAL segment out tailscale0 too. Tailscale only SNATs
#     Tailnet->subnet traffic; subnet->Tailnet is NOT masqueraded by
#     Tailscale, so a lane host's reverse shell would egress tailscale0
#     with its private source IP and the BYOD laptop would have no route
#     back. Masquerading to the gateway's own Tailnet IP makes it look
#     like an ordinary peer connection. int0 is intentionally excluded.
if ! iptables -t nat -C POSTROUTING -s "$EXT_NET" -o tailscale0 -j MASQUERADE 2>/dev/null; then
  iptables -t nat -A POSTROUTING -s "$EXT_NET" -o tailscale0 -j MASQUERADE
fi

# 5b. Lab-range carve-out — applied EARLY here, and again after `tailscale up`
#     below. The carve-out re-accepts lab traffic (100.100.0.0/16) on wan0 that
#     Tailscale's kernel `ts-input` chain would otherwise drop (CGNAT anti-spoof;
#     see the post-tailscale block for the full rationale). Applying it here too
#     means the rule is PRESENT even when the Tailscale bootstrap can't reach the
#     orchestrator and the post-tailscale block is delayed (or never runs, e.g.
#     in the offline bake-verify clone). Idempotent delete+insert so the later
#     re-assert can hoist it back above ts-input. The full match spec (-i wan0
#     -s 100.100.0.0/16) makes the -D touch ONLY the carve-out, not the other
#     CYBERCORE-V3 INPUT rules.
iptables -D INPUT -i wan0 -s 100.100.0.0/16 -m comment --comment "CYBERCORE-V3" -j ACCEPT 2>/dev/null || true
iptables -I INPUT 1 -i wan0 -s 100.100.0.0/16 -m comment --comment "CYBERCORE-V3" -j ACCEPT

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
ORCHESTRATOR_URL="${CYBERCORE_ORCHESTRATOR_URL:-http://100.100.20.50:80}"
BOOTSTRAP_PATH="/api/lane-bootstrap"

# Per-lane claim secret. Orchestrator embeds a `b<16hex>` suffix in this LXC's
# hostname at clone time; we grep it back and pass it as ?secret=… so the
# endpoint can match without source-IP (Docker bridge on the orchestrator
# rewrites the source IP, breaking IP-based matching). Falls back to no
# querystring (IP-gated mode) if the suffix isn't present, for backward compat.
CLAIM_SECRET="$(hostname | grep -oE 'b[a-f0-9]{16}$' | sed 's/^b//')"
if [ -n "$CLAIM_SECRET" ]; then
  BOOTSTRAP_URL="${ORCHESTRATOR_URL}${BOOTSTRAP_PATH}?secret=${CLAIM_SECRET}"
else
  BOOTSTRAP_URL="${ORCHESTRATOR_URL}${BOOTSTRAP_PATH}"
fi

# Retry window: 60 attempts × (5s timeout + 5s sleep) = up to 10 minutes.
# Covers slow-WAN, late dnsmasq/DHCP, and orchestrator-restart races.
echo "[cybercore-firstboot] Fetching bootstrap payload from ${ORCHESTRATOR_URL}${BOOTSTRAP_PATH} (claim=${CLAIM_SECRET:+secret}${CLAIM_SECRET:-ip})..." >&2
BOOTSTRAP_RESP=""
for _ in $(seq 1 60); do
  BOOTSTRAP_RESP="$(wget -qO- --timeout=5 "${BOOTSTRAP_URL}" 2>/dev/null || true)"
  if [ -n "$BOOTSTRAP_RESP" ] && echo "$BOOTSTRAP_RESP" | grep -q '"tailscale_authkey"'; then
    break
  fi
  BOOTSTRAP_RESP=""
  sleep 5
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

# --- Lab-range carve-out for kernel-mode Tailscale (re-assert) ---
# Tailscale's kernel-mode `ts-input` chain DROPs any packet from
# 100.64.0.0/10 arriving on a non-tailscale0 interface (its CGNAT
# anti-spoof rule). The CyberCore lab is addressed in 100.100.0.0/16,
# which sits INSIDE 100.64.0.0/10 — so replies from lab infra (the DNS
# forwarder, the orchestrator) arriving on wan0 get dropped and dnsmasq
# can never resolve upstream. Re-accept the lab range on wan0. This MUST
# run after `tailscale up`: Tailscale inserts `-j ts-input` at INPUT
# position 1, so ours must be hoisted back to position 1 to sit above it.
# (An early copy was applied in step 5b; here we delete + re-insert so it
# lands above the ts-input that `tailscale up` just added.)
iptables -D INPUT -i wan0 -s 100.100.0.0/16 -m comment --comment "CYBERCORE-V3" -j ACCEPT 2>/dev/null || true
iptables -I INPUT 1 -i wan0 -s 100.100.0.0/16 -m comment --comment "CYBERCORE-V3" -j ACCEPT

# Kali DNAT (wan0:3389 -> ext0 .KALI_OCTET) is installed inline above in
# section 3b. (An earlier design moved it to a separate 01-cybercore-kali-dnat
# hook that was never delivered, which left v3 lanes with no RDP DNAT.)

logger -t cybercore-firstboot "rendered v3: ext0=${EXT_IP}/${EXT_PREFIX} int0=${INT_IP}/${INT_PREFIX} controller=${CONTROLLER_IP}"
echo "[cybercore-firstboot] v3: ext0=${EXT_IP} int0=${INT_IP} controller=${CONTROLLER_IP}" >&2

FIRSTBOOT_EOF

# 2b. Default env file (admin.js can overwrite per-deploy via `pct push`).
# Read CYBERCORE_ORCHESTRATOR_URL from bake env (override at bake time).
# HTTPS default — Caddy fronts the app with Let's Encrypt certs and the
# gateway has full wget + ca-certificates baked in.  Override at bake time
# with CYBERCORE_ORCHESTRATOR_URL=http://x.y.z.w:80 ./bake-... if running
# without TLS in front.
ORCH_URL_DEFAULT="${CYBERCORE_ORCHESTRATOR_URL:-https://saguaroscyberhub.org}"
# Lab-internal URL the LANE uses to pull prebuilt vuln-app images. MUST match
# vuln-app-builder.js's LANE_ORCH_URL — firstboot's CYBERCORE-IMAGE-PULL rule
# whitelists exactly this dst through the lab-perimeter DROP. If you change one,
# change both. (front-end/modules/crucible/plugins/ciab/utils/vuln-app-builder.js)
ORCH_INTERNAL_DEFAULT="${CYBERCORE_INTERNAL_URL:-http://100.100.20.50:80}"
# Unquoted heredoc tag → ${ORCH_URL_DEFAULT}/${ORCH_INTERNAL_DEFAULT} expand at bake time.
cat > "$STAGING/cybercore-gateway.env" <<ENV_EOF
# /etc/cybercore-gateway.env
# Overrides for /etc/local.d/00-cybercore-firstboot.start (v3 segmented gateway).

# Upstream DNS (defaults to OPNsense lab gateway)
DNS_FORWARDER=100.100.60.1

# Internal lane domain (suffix appended to short hostnames in dnsmasq)
LANE_DOMAIN=cybercore.lan

# Convention: the GOAD controller VM gets <internal-base>.5 in every lane
CONTROLLER_OCTET=5

# Convention: Kali gets <external-base>.50 (pinned by admin.js via cloud-init
# ipconfig0). Firstboot installs wan0:3389 DNAT to this IP on ext0.
KALI_OCTET=50

# DHCP scope for lane VMs on BOTH segments (excludes .1 gateway, .5 controller, .50 kali)
DHCP_START_OCTET=10
DHCP_END_OCTET=200

# --- Tailscale subnet router (BYOAB) ---
# The auth key is NOT stored here — firstboot pulls it from the orchestrator
# at boot via GET <CYBERCORE_ORCHESTRATOR_URL>/api/lane-bootstrap. The v3
# gateway advertises only the EXTERNAL segment's route.
CYBERCORE_ORCHESTRATOR_URL=${ORCH_URL_DEFAULT}

# Lab-internal URL the lane uses to pull prebuilt vuln-app images. Read by
# firstboot's iptables block (CYBERCORE-IMAGE-PULL) to whitelist this exact
# destination through the lab-perimeter DROP. Must match vuln-app-builder.js's
# LANE_ORCH_URL — if you change one, change both.
CYBERCORE_INTERNAL_URL=${ORCH_INTERNAL_DEFAULT}
ENV_EOF

# 2c. Placeholder dnsmasq.conf — replaced at boot by firstboot once ext0/int0
#     have IPs. Minimal config so dnsmasq survives a brief start window.
cat > "$STAGING/dnsmasq.conf.placeholder" <<'PLACEHOLDER_EOF'
# Placeholder dnsmasq.conf — replaced at boot by
# /etc/local.d/00-cybercore-firstboot.start once ext0/int0 have IPs.
interface=lo
bind-interfaces
PLACEHOLDER_EOF


# 2d. Tailscale conf — force KERNEL networking mode. The v2 template ships
#     /etc/conf.d/tailscale with `--tun=userspace-networking`; that mode has
#     no tailscale0 device, so the kernel cannot route or forward packets
#     into the Tailnet (subnet routing AND reverse shells from lane hosts
#     both silently fail). v3 drops the flag; tailscaled creates tailscale0
#     once /dev/net/tun is present (passed through to the CT — see step 3).
cat > "$STAGING/conf.d-tailscale" <<'TSCONF_EOF'
# /etc/conf.d/tailscale
# Configured by bake-lane-gateway-v3.sh.
# KERNEL networking mode: tailscaled creates the tailscale0 TUN device.
# Required both for subnet routing INTO the lane and for lane hosts to
# initiate connections back into the Tailnet (e.g. a reverse shell to a
# BYOD attacker laptop). The container must have /dev/net/tun passed
# through; the v3 bake script appends the lxc.* passthrough to 1695's
# config so every clone inherits it.
command_args="--state=/var/lib/tailscale/tailscaled.state"
TSCONF_EOF

echo "==> Pushing v3 firstboot script..."
pct push "$TMP_VMID" "$STAGING/00-cybercore-firstboot.start" /etc/local.d/00-cybercore-firstboot.start --perms 0755

echo "==> Pushing /etc/cybercore-gateway.env (defaults)..."
pct push "$TMP_VMID" "$STAGING/cybercore-gateway.env" /etc/cybercore-gateway.env --perms 0644

echo "==> Pushing placeholder /etc/dnsmasq.conf..."
pct push "$TMP_VMID" "$STAGING/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

echo "==> Pushing /etc/conf.d/tailscale (kernel networking mode)..."
pct push "$TMP_VMID" "$STAGING/conf.d-tailscale" /etc/conf.d/tailscale --perms 0644

# 2e. Rework /etc/network/interfaces: rename the inherited lan0 stanza to
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

# 2e2. Scrub stale v1 iptables rules from the persistent rule set. 1692
#      (and 1694 inherited from it) ships /etc/iptables/rules-save with DNATs
#      to 192.18.0.10:3389 and 100.100.70.10 (legacy single Guac VM / v1 lane
#      subnet). Those get reloaded BEFORE firstboot runs, end up first in the
#      PREROUTING chain, and silently swallow inbound 3389. Strip any rule
#      referencing the v1 subnet or the old Guac IP and re-persist.
# 2e1. Install full wget + ca-certificates so the bootstrap fetch in firstboot
#      can speak HTTPS. BusyBox's wget doesn't handshake correctly against
#      modern Caddy/Let's Encrypt, so without the GNU wget binary the gateway
#      silently fails bootstrap whenever the orchestrator is fronted by HTTPS.
echo "==> Installing full wget + ca-certificates for HTTPS bootstrap fetch..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  apk update >/dev/null 2>&1 || true
  apk add --no-cache wget ca-certificates 2>&1 | tail -5
  update-ca-certificates 2>/dev/null || true
  if wget -q --timeout=5 --spider https://www.google.com/generate_204 2>/dev/null; then
    echo "  HTTPS smoke test: OK"
  else
    echo "  HTTPS smoke test: FAILED (gateway may still need firewall/DNS fixes)"
  fi
'

echo "==> Scrubbing stale v1 iptables rules from /etc/iptables/rules-save..."
pct exec "$TMP_VMID" -- /bin/sh -c '
  set -e
  RULES=/etc/iptables/rules-save
  if [ -f "$RULES" ]; then
    cp "$RULES" "${RULES}.v1.bak"
    grep -vE "192\.18\.0|100\.100\.70\.10" "${RULES}.v1.bak" > "$RULES"
    echo "  Cleaned $RULES (backup at ${RULES}.v1.bak)"
  fi
  iptables-save | grep -vE "192\.18\.0|100\.100\.70\.10" | iptables-restore || true
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules-save
  echo "  Persistent + running iptables: stale v1 references purged"
'

# 2f. Re-push the placeholder dnsmasq.conf as the last pre-shutdown step so
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

# Pass /dev/net/tun through to the CT so Tailscale runs in kernel mode and
# creates a real tailscale0 device. Raw lxc.* keys cannot be set via
# `pct set` or the Proxmox API, so they are appended to the config file
# directly. `pct clone` copies them into every per-lane clone of 1695, so
# admin.js needs no change — the passthrough is inherited automatically.
echo "==> Adding /dev/net/tun passthrough to 1695's config..."
GW_CONF="/etc/pve/lxc/${NEW_VMID}.conf"
if ! grep -q 'dev/net/tun' "$GW_CONF"; then
  cat >> "$GW_CONF" <<'TUNCONF_EOF'
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
TUNCONF_EOF
fi

pct set "$NEW_VMID" --description "CyberCore lane gateway v3 — segmented DMZ topology.
3 NICs: wan0 (uplink) + ext0 (external/attacker) + int0 (internal/GOAD).
Firstboot renders dnsmasq + NAT + ext0<->int0 DROP from the live NIC IPs.
Tailscale runs in kernel mode (/dev/net/tun passed through); ext0 can reach
the Tailnet (reverse shells to BYOD), int0 deliberately cannot.
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
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C INPUT -i int0 -p udp --dport 67:68 -m comment --comment CYBERCORE-V3 -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: int0 DHCP INPUT-accept rule missing (lane VMs can't get an IP)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C INPUT -i ext0 -p udp --dport 67:68 -m comment --comment CYBERCORE-V3 -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: ext0 DHCP INPUT-accept rule missing (lane VMs can't get an IP)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i int0 -o wan0 -m comment --comment CYBERCORE-V3 -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: int0->wan0 FORWARD-accept rule missing (no internet for the lane)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i ext0 -o tailscale0 -m comment --comment CYBERCORE-V3 -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: ext0->tailscale0 FORWARD-accept rule missing (no Tailnet callbacks/reverse shells)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o tailscale0 -j MASQUERADE" 2>/dev/null \
  || { echo "FAIL: ext0->tailscale0 NAT MASQUERADE rule missing"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "! grep -q userspace-networking /etc/conf.d/tailscale" 2>/dev/null \
  || { echo "FAIL: /etc/conf.d/tailscale still forces Tailscale userspace mode"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "test -c /dev/net/tun" 2>/dev/null \
  || { echo "FAIL: /dev/net/tun not present in CT (TUN passthrough did not survive clone)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C INPUT -i wan0 -s 100.100.0.0/16 -m comment --comment CYBERCORE-V3 -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: lab-range carve-out missing (Tailscale ts-input would drop lab DNS replies)"; RENDERED_OK=0; }
# Lab-perimeter containment: both segments must be blocked from the lab range
# over the uplink (contains lane attackers off lab infra, mirroring v1/v2).
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i ext0 -o wan0 -d 100.100.0.0/16 -m comment --comment CYBERCORE-LAB-DROP -j DROP" 2>/dev/null \
  || { echo "FAIL: ext0 lab-perimeter DROP missing (lane could reach lab infra)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i int0 -o wan0 -d 100.100.0.0/16 -m comment --comment CYBERCORE-LAB-DROP -j DROP" 2>/dev/null \
  || { echo "FAIL: int0 lab-perimeter DROP missing (lane could reach lab infra)"; RENDERED_OK=0; }
# Lab DNS exception must sit ABOVE the DROP, else GOAD's early provisioning DNS
# (a lab resolver, exact IP varies) is blackholed and the egress preflight times out.
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i int0 -o wan0 -d 100.100.0.0/16 -p udp --dport 53 -m comment --comment CYBERCORE-LAB-DNS -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: int0 lab-DNS exception missing (GOAD preflight DNS would be dropped)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i ext0 -o wan0 -d 100.100.0.0/16 -p udp --dport 53 -m comment --comment CYBERCORE-LAB-DNS -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: ext0 lab-DNS exception missing (GOAD preflight DNS would be dropped)"; RENDERED_OK=0; }
# Image-pull exception: both segments must reach the orchestrator:80 for the
# prebuilt vuln-app image pull. Use the same INTERNAL default firstboot uses so
# a bake-time override (CYBERCORE_INTERNAL_URL=...) is verified against the real IP.
EXPECTED_IMG_PULL_DST="$(echo "${CYBERCORE_INTERNAL_URL:-http://100.100.20.50:80}" | sed -E 's|^https?://||; s|[:/].*$||')"
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i ext0 -o wan0 -s 10.99.0.0/24 -d ${EXPECTED_IMG_PULL_DST} -p tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment CYBERCORE-IMAGE-PULL -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: ext0 image-pull ACCEPT missing (lane→${EXPECTED_IMG_PULL_DST}:80)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -C FORWARD -i int0 -o wan0 -s 10.199.0.0/24 -d ${EXPECTED_IMG_PULL_DST} -p tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment CYBERCORE-IMAGE-PULL -j ACCEPT" 2>/dev/null \
  || { echo "FAIL: int0 image-pull ACCEPT missing (lane→${EXPECTED_IMG_PULL_DST}:80)"; RENDERED_OK=0; }
pct exec "$VERIFY_VMID" -- /bin/sh -c "iptables -t nat -C PREROUTING -i wan0 -p tcp --dport 3389 -m comment --comment CYBERCORE-KALI-RDP -j DNAT --to-destination 10.99.0.50:3389" 2>/dev/null \
  || { echo "FAIL: Kali DNAT rule missing for 10.99.0.50:3389"; RENDERED_OK=0; }

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
  echo "    - tailnet egress      ext0 -> tailscale0 ACCEPT + MASQUERADE"
  echo "    - tailscale mode      kernel (/dev/net/tun passed through to the CT)"
  echo "    - lab carve-out       wan0 100.100.0.0/16 ACCEPT above ts-input"
  echo "    - lab containment     ext0/int0 -> 100.100.0.0/16 (-o wan0) DROP"
  echo "    - lab DNS hole        ext0/int0 -> 100.100.0.0/16:53 ACCEPT (above DROP)"
  echo "    - image-pull hole     ext0/int0 -> orchestrator:80 ACCEPT (above DROP)"
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
