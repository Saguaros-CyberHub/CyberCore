#!/bin/bash
# ============================================================================
# bake.sh — build the v2 lane-gateway LXC template.
# ----------------------------------------------------------------------------
# Builds the v2 lane-gateway template at VMID 1694 by cloning the proven 1692
# template and stripping out everything that hardcoded the old shared
# 192.18.0.0/24 lane subnet.
#
# v1 (1692): every lane uses 192.18.0.0/24 with .1 as the gateway and .5 as the
# GOAD controller. dnsmasq.conf is baked in with that specific scope. Lane
# uniqueness is enforced only by VXLAN, not by addressing.
#
# v2 (1694, this build): subnet-agnostic. The deploy path sets net1's IP
# per-deploy (e.g. 10.42.0.1/24), and a firstboot hook inside the LXC reads
# lan0's actual address at every boot and (re)renders dnsmasq.conf, the
# controller SSH-allow rule, and the lan->wan masquerade rule from it. The same
# template image works for any /24 in 10.0.0.0/8.
#
# This build does NOT modify 1692 — v1 stays available so in-flight classes keep
# working. Challenges using subnet_scheme='v2' clone 1694 instead.
#
# WHY THIS ISN'T PACKER: Packer's Proxmox plugin (proxmox-iso / proxmox-clone)
# builds QEMU VMs only — it has no LXC/CT builder. The gateway is a container,
# so the build is driven by pct. The directory layout mirrors the Packer
# templates next door anyway: payloads under files/, build steps under
# scripts/, config in vars.env.
#
# Run as root on a Proxmox node where 1692 lives. Idempotent only at the
# boundaries: refuses to clobber an existing 1694 unless FORCE=1.
#
# Companion to:
#   - infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh (controller template)
#   - infrastructure/proxmox-templates/sdn-templates/patch-goad-gateway-key.sh  (controller pubkey — already
#     applied to 1692 and inherited via this clone, so 1694 ships with it too)
#   - infrastructure/proxmox-templates/sdn-templates/bake-lane-gateway-v3.sh    (clones the 1694 this builds)
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Capture whether the caller pinned the scratch IDs BEFORE vars.env fills in
# defaults. A pinned ID is honoured strictly (hard fail if taken); a default is
# free to move out of the way, because nobody cares which throwaway ID we used.
# shellcheck disable=SC2034  # read indirectly as ${slot}_PINNED in section 0
TMP_VMID_PINNED="${TMP_VMID:+1}"
# shellcheck disable=SC2034  # read indirectly as ${slot}_PINNED in section 0
VERIFY_VMID_PINNED="${VERIFY_VMID:+1}"

# shellcheck source=vars.env
. "$HERE/vars.env"

FILES="$HERE/files"
SCRIPTS="$HERE/scripts"
# Where the in-CT step scripts land inside the container.
CT_WORK=/tmp/cybercore-bake

# ---------- 0. Sanity ----------
for f in \
  "$FILES/local.d/00-cybercore-firstboot.start" \
  "$FILES/local.d/50-gateway.start.stub" \
  "$FILES/cybercore-gateway.env.tpl" \
  "$FILES/dnsmasq.conf.placeholder" \
  "$FILES/conf.d/tailscale" \
  "$SCRIPTS/10-rewrite-lan0-iface.sh" \
  "$SCRIPTS/20-neutralize-v1-hooks.sh" \
  "$SCRIPTS/30-sweep-dnsmasq-dropins.sh" \
  "$SCRIPTS/40-install-https-tooling.sh" \
  "$SCRIPTS/50-install-tailscale.sh" \
  "$SCRIPTS/60-scrub-v1-iptables.sh" \
  "$HERE/verify/assertions.sh" \
; do
  [ -f "$f" ] || { echo "ERROR: missing payload $f" >&2; exit 1; }
done

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

# Proxmox VMIDs are ONE namespace shared by LXC and QEMU, cluster-wide. A
# `pct status` check alone only sees containers on this node, so a VM parked on
# the scratch ID slips through preflight and only surfaces later as
# "VM 9995 already exists" — after 1694 has already been replaced. Check the
# cluster VMID registry first, then fall back to per-type probes.
vmid_exists() {
  if [ -r /etc/pve/.vmlist ] && grep -qE "\"$1\"[[:space:]]*:" /etc/pve/.vmlist; then
    return 0
  fi
  pct status "$1" >/dev/null 2>&1 && return 0
  qm status  "$1" >/dev/null 2>&1 && return 0
  return 1
}

for slot in TMP_VMID VERIFY_VMID; do
  cur="${!slot}"
  eval "pinned=\${${slot}_PINNED:-}"
  vmid_exists "$cur" || continue

  if [ -n "$pinned" ]; then
    echo "ERROR: $slot=$cur is already in use (LXC or VM, cluster-wide)." >&2
    echo "       Pick a free ID or destroy that guest." >&2
    exit 1
  fi

  next="$cur"
  while vmid_exists "$next"; do
    next=$((next + 1))
    if [ "$next" -gt $((cur + 50)) ]; then
      echo "ERROR: no free scratch VMID in ${cur}..$((cur + 50)). Set $slot explicitly." >&2
      exit 1
    fi
  done
  echo "==> scratch $slot: $cur is in use — using $next instead."
  printf -v "$slot" '%s' "$next"
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

# Render the env file from its template. Everything else ships verbatim.
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
sed -e "s|@CYBERCORE_ORCHESTRATOR_URL@|${CYBERCORE_ORCHESTRATOR_URL}|g" \
    -e "s|@CYBERCORE_INTERNAL_URL@|${CYBERCORE_INTERNAL_URL}|g" \
    "$FILES/cybercore-gateway.env.tpl" > "$STAGING/cybercore-gateway.env"

# `pct push` is purpose-built for getting files into a CT and avoids the
# stdin-piping fragility of `pct exec ... <<EOF`.
echo "==> Pushing firstboot script to /etc/local.d/00-cybercore-firstboot.start..."
pct push "$TMP_VMID" "$FILES/local.d/00-cybercore-firstboot.start" \
  /etc/local.d/00-cybercore-firstboot.start --perms 0755

echo "==> Pushing /etc/cybercore-gateway.env (orch=${CYBERCORE_ORCHESTRATOR_URL}, internal=${CYBERCORE_INTERNAL_URL})..."
pct push "$TMP_VMID" "$STAGING/cybercore-gateway.env" /etc/cybercore-gateway.env --perms 0644

echo "==> Pushing placeholder /etc/dnsmasq.conf..."
pct push "$TMP_VMID" "$FILES/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

# Stage the step scripts + the payloads they install into a scratch dir inside
# the CT. Wiped again in 2h so vzdump doesn't capture them.
pct exec "$TMP_VMID" -- /bin/sh -c "mkdir -p $CT_WORK"
for s in 10-rewrite-lan0-iface 20-neutralize-v1-hooks 30-sweep-dnsmasq-dropins \
         40-install-https-tooling 50-install-tailscale 60-scrub-v1-iptables; do
  pct push "$TMP_VMID" "$SCRIPTS/$s.sh" "$CT_WORK/$s.sh" --perms 0755
done
pct push "$TMP_VMID" "$FILES/local.d/50-gateway.start.stub" "$CT_WORK/50-gateway.start.stub" --perms 0644
pct push "$TMP_VMID" "$FILES/conf.d/tailscale" "$CT_WORK/conf.d-tailscale" --perms 0644

echo "==> Rewriting lan0 stanza in /etc/network/interfaces to 'inet manual'..."
pct exec "$TMP_VMID" -- /bin/sh "$CT_WORK/10-rewrite-lan0-iface.sh"

echo "==> Neutralizing /etc/local.d/50-gateway.start (firstboot now handles its job)..."
pct exec "$TMP_VMID" -- /bin/sh "$CT_WORK/20-neutralize-v1-hooks.sh" "$CT_WORK/50-gateway.start.stub"

echo "==> Sweeping /etc/dnsmasq.d/ for v1 drop-ins (50-gateway.conf etc.)..."
pct exec "$TMP_VMID" -- /bin/sh "$CT_WORK/30-sweep-dnsmasq-dropins.sh"

echo "==> Installing full wget + ca-certificates for HTTPS bootstrap fetch..."
pct exec "$TMP_VMID" -- /bin/sh "$CT_WORK/40-install-https-tooling.sh"

echo "==> Installing Tailscale + configuring userspace-networking mode..."
pct exec "$TMP_VMID" -- /bin/sh "$CT_WORK/50-install-tailscale.sh" "$CT_WORK/conf.d-tailscale"

echo "==> Scrubbing stale v1 iptables rules from /etc/iptables/rules-save..."
pct exec "$TMP_VMID" -- /bin/sh "$CT_WORK/60-scrub-v1-iptables.sh" "$V1_PATTERNS"

# 2h. CRITICAL: re-push the placeholder dnsmasq.conf as the absolute last
#     pre-shutdown step. During the temp-CT phase firstboot can get triggered
#     (mechanism unclear — possibly OpenRC re-asserts the local runlevel after
#     rc-update), and if it runs while lan0 still has 1692's inherited
#     192.18.0.1/24, it bakes a stale render into the rootfs that vzdump
#     captures. By over-writing dnsmasq.conf with the placeholder right before
#     pct stop, we guarantee 1694 ships with the placeholder no matter what
#     happened earlier — firstboot on user-deploys then renders fresh from the
#     per-deploy lan0 IP.
echo "==> Re-pushing placeholder dnsmasq.conf to clear any stale render..."
pct push "$TMP_VMID" "$FILES/dnsmasq.conf.placeholder" /etc/dnsmasq.conf --perms 0644

# Drop the bake scratch dir, and wipe any old firstboot log lines from the temp
# CT so /var/log/messages in 1694 doesn't carry forward the bake-time render
# entry. Clones get a fresh log going forward.
pct exec "$TMP_VMID" -- /bin/sh -c "rm -rf $CT_WORK" 2>/dev/null || true
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
#   net0 (wan0) — the deploy path fully overrides at deploy time. Default left
#                 as vmbr0 with DHCP so a manual start is harmless.
#   net1 (lan0) — NO IP in the template. The deploy path sets
#                 `ip=10.<C>.0.1/24` per-challenge. firstboot reads whatever it
#                 ends up being.
echo "==> Setting subnet-agnostic net config..."
pct set "$NEW_VMID" --net0 'name=wan0,bridge=vmbr0,ip=dhcp,firewall=0,type=veth'
pct set "$NEW_VMID" --net1 'name=lan0,bridge=vmbr0,type=veth'

pct set "$NEW_VMID" --description "CyberCore lane gateway v2 — subnet-agnostic.
Deploy path sets net1 ip per-deploy; firstboot renders dnsmasq from lan0 IP.
Built from $SRC_VMID by infrastructure/proxmox-templates/sdn-templates/v2_gateway/bake.sh."

pct set "$NEW_VMID" --template 1

# ---------- 4. Cleanup ----------
# The dump is NOT deleted here. It is the only way back to this build if
# verification fails, and 1692 → 1694 has already been replaced by this point.
# Removed after a passing verify; deliberately left behind after a failing one.
echo "==> Cleanup..."
pct destroy "$TMP_VMID" --purge 2>/dev/null || true

# ---------- 5. Verify: clone, set a fake lan0 IP, boot, check render ----------
# Split out so it can be re-run on its own against an already-built template —
# a bake that produces 1694 and then trips over something in verification
# should not have to rebuild the whole image to prove itself.
RENDERED_OK=1
VERIFY_VMID="$VERIFY_VMID" "$HERE/verify/verify-template.sh" "$NEW_VMID" || RENDERED_OK=0

if [ "$RENDERED_OK" = "1" ]; then
  rm -f "$DUMP_FILE"
fi

echo ""
if [ "$RENDERED_OK" = "1" ]; then
  echo "==================================================================="
  echo "  SUCCESS: lane gateway v2 template baked at VMID $NEW_VMID"
  echo "==================================================================="
  echo "  Nothing further to run — the template is ready."
  echo ""
  echo "  FOR REFERENCE ONLY, this is what the deploy path already does per lane"
  echo "  (useful for reproducing a lane by hand when debugging):"
  echo "    pct clone $NEW_VMID <ctid> --full --storage $STORAGE"
  echo "    pct set <ctid> \\"
  echo "      --net0 'name=wan0,bridge=vmbr0,ip=100.100.60.<C>/24,gw=100.100.60.1,firewall=0,type=veth' \\"
  echo "      --net1 'name=lan0,bridge=<vnet>,ip=10.<C>.0.1/24,type=veth'"
  echo "    pct push <ctid> custom-env-file /etc/cybercore-gateway.env  # optional"
  echo "    pct start <ctid>"
  echo "==================================================================="
else
  echo "==================================================================="
  echo "  WARNING: $NEW_VMID was created but verification did not pass."
  echo "==================================================================="
  echo "  The build dump has been KEPT so this image can be restored:"
  echo "    $DUMP_FILE"
  echo ""
  echo "  Re-run verification alone once you have a fix (no rebake needed):"
  echo "    ./verify/verify-template.sh $NEW_VMID"
  echo "==================================================================="
  exit 1
fi
