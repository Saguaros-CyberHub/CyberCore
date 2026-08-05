#!/bin/bash
# ============================================================================
# verify-template.sh — prove a baked gateway template is subnet-agnostic.
# ----------------------------------------------------------------------------
# Clones the finished template to a scratch CTID, gives it a deliberately fake
# lane address, boots it, and asserts that the firstboot hook rendered dnsmasq
# and iptables from THAT address. Passing against an arbitrary subnet is the
# proof — a template with anything hardcoded fails here.
#
# bake.sh calls this as its last step, but it is also runnable on its own,
# which is what you want when a bake produced a template and then fell over
# before verifying it (or when you want to re-check a template baked weeks ago):
#
#   ./verify/verify-template.sh                 # verify 1694 from vars.env
#   ./verify/verify-template.sh 1695            # verify some other template
#   VERIFY_LANE_BASE=10.77.0 ./verify/verify-template.sh
#
# The scratch clone is always destroyed, pass or fail. Read-only with respect
# to the template itself — safe to run against a live 1694.
#
# Exits 0 if every assertion passed, 1 otherwise.
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

VERIFY_VMID_PINNED="${VERIFY_VMID:+1}"
# shellcheck source=../vars.env
. "$ROOT/vars.env"

TARGET_VMID="${1:-$NEW_VMID}"

# Same cluster-wide VMID check bake.sh uses — LXC and QEMU share one namespace,
# so `pct status` alone would miss a VM parked on the scratch ID.
vmid_exists() {
  if [ -r /etc/pve/.vmlist ] && grep -qE "\"$1\"[[:space:]]*:" /etc/pve/.vmlist; then
    return 0
  fi
  pct status "$1" >/dev/null 2>&1 && return 0
  qm status  "$1" >/dev/null 2>&1 && return 0
  return 1
}

if ! pct config "$TARGET_VMID" >/dev/null 2>&1; then
  echo "ERROR: template CT $TARGET_VMID not found." >&2
  exit 1
fi

if vmid_exists "$VERIFY_VMID"; then
  if [ -n "$VERIFY_VMID_PINNED" ]; then
    echo "ERROR: VERIFY_VMID=$VERIFY_VMID is already in use (LXC or VM, cluster-wide)." >&2
    exit 1
  fi
  next="$VERIFY_VMID"
  while vmid_exists "$next"; do
    next=$((next + 1))
    if [ "$next" -gt $((VERIFY_VMID + 50)) ]; then
      echo "ERROR: no free scratch VMID near $VERIFY_VMID. Set VERIFY_VMID explicitly." >&2
      exit 1
    fi
  done
  echo "==> scratch VERIFY_VMID: $VERIFY_VMID is in use — using $next instead."
  VERIFY_VMID="$next"
fi

# Always clean the scratch clone up, however we leave — a failed assertion must
# not strand a running container holding the ID for the next run.
cleanup() {
  pct stop "$VERIFY_VMID" >/dev/null 2>&1 || true
  pct destroy "$VERIFY_VMID" --purge >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Verifying: cloning $TARGET_VMID -> $VERIFY_VMID with fake lan0=${VERIFY_LANE_BASE}.1/24..."
pct clone "$TARGET_VMID" "$VERIFY_VMID" --hostname lanegw-v2-verify --full --storage "$STORAGE" >/dev/null

# pct start renames veth pairs to wan0/lan0; a previous failed attempt may have
# left those names lingering on the host net namespace.
ip link delete lan0 2>/dev/null || true
ip link delete wan0 2>/dev/null || true

pct set "$VERIFY_VMID" --net1 "name=lan0,bridge=vmbr0,ip=${VERIFY_LANE_BASE}.1/24,type=veth"
pct start "$VERIFY_VMID"

# Give firstboot time to complete. Its wait-for-lan0-IP loop alone can take up
# to 15s, then it renders + restarts dnsmasq (~2s). 35s because Tailscale daemon
# startup + any failed-service retries can push openrc's `local` runlevel later
# than 20s on cold boot.
sleep 35

echo "==> Verifying rendered config inside $VERIFY_VMID..."
IMG_PULL_DST="$(echo "$CYBERCORE_INTERNAL_URL" | sed -E 's|^https?://||; s|[:/].*$||')"
RENDERED_OK=1
"$HERE/assertions.sh" "$VERIFY_VMID" "$VERIFY_LANE_BASE" "$IMG_PULL_DST" || RENDERED_OK=0

echo ""
if [ "$RENDERED_OK" = "1" ]; then
  echo "==================================================================="
  echo "  PASS: $TARGET_VMID rendered correctly for lan0=${VERIFY_LANE_BASE}.1/24"
  echo "==================================================================="
  echo "    - dnsmasq dhcp-range  ${VERIFY_LANE_BASE}.10 .. ${VERIFY_LANE_BASE}.200"
  echo "    - controller ACCEPT   ${VERIFY_LANE_BASE}.5 -> lan0:22"
  echo "    - lane MASQUERADE     ${VERIFY_LANE_BASE}.0/24 -> wan0"
  echo "    - Kali console DNAT   wan0:3389 -> ${VERIFY_LANE_BASE}.50:3389"
  echo "    - Kali RDP FORWARD    above the perimeter DROPs"
  echo "    - image-pull ACCEPT   ${VERIFY_LANE_BASE}.0/24 -> ${IMG_PULL_DST}:80, above the DROPs"
  echo "==================================================================="
else
  echo "==================================================================="
  echo "  FAIL: $TARGET_VMID did not render correctly — see failures above."
  echo "==================================================================="
  echo "  Reproduce by hand (the scratch clone has already been destroyed):"
  echo "    pct clone $TARGET_VMID 9999 --full --storage $STORAGE"
  echo "    pct set 9999 --net1 'name=lan0,bridge=vmbr0,ip=${VERIFY_LANE_BASE}.1/24,type=veth'"
  echo "    pct start 9999 && sleep 35"
  echo "    pct exec 9999 -- cat /etc/dnsmasq.conf"
  echo "    pct exec 9999 -- iptables -L FORWARD -n --line-numbers"
  echo "==================================================================="
fi

[ "$RENDERED_OK" = "1" ]
