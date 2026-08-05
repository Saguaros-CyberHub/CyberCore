#!/bin/bash
# ============================================================================
# patch-lane-gateway-rdp.sh
# ----------------------------------------------------------------------------
# Repairs the dead CYBERCORE-KALI-RDP forward rule on ALREADY-RUNNING lane
# gateways.
#
# THE BUG: the firstboot hook installed its RDP ACCEPT with `-A FORWARD`
# (append). The base template's FORWARD chain ends with a catch-all
# `-i wan0 -o lan0 -j DROP`, so the appended ACCEPT landed below it and never
# matched. The rule was visible in `iptables -S` but carried no traffic — RDP
# only worked via the deploy path's LANE-CONSOLE rules (which insert at
# position 2) or a blanket v1 leftover that accepts wan0→lan0:3389 for any
# destination.
#
# v2_gateway/bake.sh now inserts the rule correctly, but that only reaches NEW
# clones of 1694. This script applies the same fix to gateways already running,
# so in-flight classes don't have to be redeployed.
#
# Everything is derived from the container's live lan0 address, so this works
# on any lane without being told its subnet. Idempotent: strips the tag before
# re-adding, and re-persists /etc/iptables/rules-save.
#
# It ALSO replaces /etc/local.d/00-cybercore-firstboot.start with the fixed
# copy from v2_gateway/files/. That part is not optional cosmetics: the old
# hook strips every CYBERCORE-KALI-RDP rule before re-appending its own dead
# one, so it would undo this patch on the next boot. Set SKIP_HOOK=1 to patch
# only the live ruleset and accept that the fix lasts until reboot.
#
# Run as root on a Proxmox node.
#
#   ./patch-lane-gateway-rdp.sh 1234              # one gateway CTID
#   ./patch-lane-gateway-rdp.sh 1234 1235 1236    # several
#   ./patch-lane-gateway-rdp.sh --all             # every running CT whose
#                                                 # hostname looks like a lane gw
#   DRY_RUN=1 ./patch-lane-gateway-rdp.sh --all   # report only, change nothing
#   SKIP_HOOK=1 ./patch-lane-gateway-rdp.sh 1234  # ruleset only, leave the hook
#
# Companion to:
#   - v2_gateway/bake.sh          (the permanent fix, for new clones)
#   - bake-lane-gateway-v3.sh     (v3 gateways — see NOTE at the bottom)
# ============================================================================
set -euo pipefail

DRY_RUN=${DRY_RUN:-0}
SKIP_HOOK=${SKIP_HOOK:-0}
KALI_OCTET_DEFAULT=${KALI_OCTET:-50}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXED_HOOK="$HERE/v2_gateway/files/local.d/00-cybercore-firstboot.start"
if [ "$SKIP_HOOK" != "1" ] && [ ! -f "$FIXED_HOOK" ]; then
  echo "ERROR: fixed firstboot hook not found at $FIXED_HOOK" >&2
  echo "       Run from a checkout, or pass SKIP_HOOK=1 to patch rules only." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <ctid> [ctid...]   |   $0 --all   (DRY_RUN=1 to preview)" >&2
  exit 1
fi

# ---------- Resolve the target list ----------
TARGETS=""
if [ "$1" = "--all" ]; then
  # Lane gateways are the running CTs whose hostname carries the gateway
  # naming the deploy path uses. Anything else is left alone.
  while read -r ctid _; do
    [ -n "$ctid" ] || continue
    hn="$(pct config "$ctid" 2>/dev/null | awk '/^hostname:/ {print $2}')"
    case "$hn" in
      *gateway*|*lanegw*|*lane-gw*) TARGETS="$TARGETS $ctid" ;;
    esac
  done <<EOF
$(pct list 2>/dev/null | awk 'NR>1 && $2=="running" {print $1}')
EOF
  if [ -z "$TARGETS" ]; then
    echo "No running lane-gateway CTs found." >&2
    exit 0
  fi
  echo "==> Matched CTIDs:$TARGETS"
else
  TARGETS="$*"
fi

PATCHED=0
SKIPPED=0
FAILED=0

for CTID in $TARGETS; do
  echo ""
  echo "=== CT $CTID ==="

  if ! pct status "$CTID" 2>/dev/null | grep -q running; then
    echo "  SKIP: not running."
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  # lan0 is the v2 lane interface; v3 gateways use ext0 for the attacker
  # segment. Prefer lan0, fall back to ext0 so this covers both.
  LAN_IF=lan0
  LAN_CIDR="$(pct exec "$CTID" -- /bin/sh -c "ip -4 -o addr show lan0 2>/dev/null | awk '{print \$4}' | head -1" 2>/dev/null || true)"
  if [ -z "$LAN_CIDR" ]; then
    LAN_IF=ext0
    LAN_CIDR="$(pct exec "$CTID" -- /bin/sh -c "ip -4 -o addr show ext0 2>/dev/null | awk '{print \$4}' | head -1" 2>/dev/null || true)"
  fi
  if [ -z "$LAN_CIDR" ]; then
    echo "  SKIP: neither lan0 nor ext0 has an IPv4 address."
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  LAN_IP="${LAN_CIDR%/*}"
  BASE3="$(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3}')"
  KALI_IP="${BASE3}.${KALI_OCTET_DEFAULT}"
  echo "  ${LAN_IF}=${LAN_CIDR} → console target ${KALI_IP}:3389"

  # Report current placement so the log shows what was actually wrong.
  POS="$(pct exec "$CTID" -- /bin/sh -c \
    "iptables -L FORWARD --line-numbers -n 2>/dev/null | grep CYBERCORE-KALI-RDP | head -1 | awk '{print \$1}'" 2>/dev/null || true)"
  DROP="$(pct exec "$CTID" -- /bin/sh -c \
    "iptables -L FORWARD --line-numbers -n 2>/dev/null | grep -E '^[0-9]+ +DROP' | head -1 | awk '{print \$1}'" 2>/dev/null || true)"
  if [ -n "$POS" ] && [ -n "$DROP" ] && [ "$POS" -lt "$DROP" ]; then
    echo "  Already correct: CYBERCORE-KALI-RDP at FORWARD pos $POS, first DROP at $DROP."
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  if [ -n "$POS" ]; then
    echo "  BROKEN: CYBERCORE-KALI-RDP at FORWARD pos $POS, at/below first DROP at ${DROP:-none} — rule is dead."
  else
    echo "  BROKEN: no CYBERCORE-KALI-RDP rule in FORWARD at all."
  fi

  if [ "$DRY_RUN" = "1" ]; then
    echo "  DRY_RUN=1 — no changes made."
    continue
  fi

  # Strip the tag from both tables, re-add the DNAT, then INSERT the ACCEPT
  # above the perimeter DROPs. Mirrors the fixed firstboot hook exactly.
  if pct exec "$CTID" -- /bin/sh -c "
    set -e
    iptables-save | grep -v 'CYBERCORE-KALI-RDP' | iptables-restore
    iptables -t nat -A PREROUTING -i wan0 -p tcp --dport 3389 \
      -m comment --comment 'CYBERCORE-KALI-RDP' \
      -j DNAT --to-destination '${KALI_IP}:3389'
    iptables -I FORWARD 2 -i wan0 -o ${LAN_IF} -p tcp -d '${KALI_IP}' --dport 3389 \
      -m comment --comment 'CYBERCORE-KALI-RDP' -j ACCEPT \
      || iptables -I FORWARD -i wan0 -o ${LAN_IF} -p tcp -d '${KALI_IP}' --dport 3389 \
        -m comment --comment 'CYBERCORE-KALI-RDP' -j ACCEPT
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules-save
  "; then
    NEWPOS="$(pct exec "$CTID" -- /bin/sh -c \
      "iptables -L FORWARD --line-numbers -n 2>/dev/null | grep CYBERCORE-KALI-RDP | head -1 | awk '{print \$1}'" 2>/dev/null || true)"
    NEWDROP="$(pct exec "$CTID" -- /bin/sh -c \
      "iptables -L FORWARD --line-numbers -n 2>/dev/null | grep -E '^[0-9]+ +DROP' | head -1 | awk '{print \$1}'" 2>/dev/null || true)"
    if [ -n "$NEWPOS" ] && [ -n "$NEWDROP" ] && [ "$NEWPOS" -lt "$NEWDROP" ]; then
      echo "  FIXED: CYBERCORE-KALI-RDP now at FORWARD pos $NEWPOS (first DROP at $NEWDROP), persisted."

      # Make it survive a reboot. Without this the OLD hook strips the tag and
      # re-appends the dead rule on next boot, silently undoing the patch.
      #
      # v2 only: a v3 gateway (matched via ext0) runs a DIFFERENT firstboot hook
      # — two segments, kernel-mode Tailscale, ext0↔int0 isolation — and pushing
      # the v2 copy over it would break the lane. v3 gets the ruleset fix only.
      if [ "$SKIP_HOOK" = "1" ]; then
        echo "  SKIP_HOOK=1 — hook left as-is; patch lasts until this CT reboots."
      elif [ "$LAN_IF" != "lan0" ]; then
        echo "  NOTE: v3-style gateway (${LAN_IF}) — hook NOT replaced. Re-run after"
        echo "        a reboot, or apply the same insert fix to bake-lane-gateway-v3.sh."
      elif pct push "$CTID" "$FIXED_HOOK" /etc/local.d/00-cybercore-firstboot.start --perms 0755 2>/dev/null; then
        echo "  Hook refreshed: /etc/local.d/00-cybercore-firstboot.start (survives reboot)."
      else
        echo "  WARN: could not push the fixed hook — patch lasts until this CT reboots."
      fi
      PATCHED=$((PATCHED + 1))
    else
      echo "  FAILED: rule still misplaced (pos=${NEWPOS:-none}, drop=${NEWDROP:-none})."
      FAILED=$((FAILED + 1))
    fi
  else
    echo "  FAILED: iptables patch returned non-zero."
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "==================================================================="
echo "  patched: $PATCHED   skipped: $SKIPPED   failed: $FAILED"
echo "==================================================================="
echo ""
echo "  This repairs the running ruleset, /etc/iptables/rules-save, and (unless"
echo "  SKIP_HOOK=1) the firstboot hook itself, so the fix survives a reboot."
echo "  Redeploying from a freshly baked 1694 is still the clean end state."
[ "$FAILED" -eq 0 ]
