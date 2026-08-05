#!/bin/bash
# ============================================================================
# assertions.sh — runs on the PVE HOST against a booted verify clone.
#
#   assertions.sh <ctid> <lane-base3> <image-pull-dst>
#     ctid            CTID of the booted verify clone
#     lane-base3      first three octets of its fake lan0, e.g. 10.99.0
#     image-pull-dst  host the CYBERCORE-IMAGE-PULL rule should target
#
# Exits 0 if every assertion passes, 1 otherwise. Every check reads state the
# firstboot hook RENDERED — that's the whole point of v2, so if these pass for
# an arbitrary lane base, the template is subnet-agnostic.
# ============================================================================
set -uo pipefail

VMID="${1:?usage: assertions.sh <ctid> <lane-base3> <image-pull-dst>}"
BASE="${2:?usage: assertions.sh <ctid> <lane-base3> <image-pull-dst>}"
IMG_DST="${3:?usage: assertions.sh <ctid> <lane-base3> <image-pull-dst>}"

OK=1
fail() { echo "FAIL: $*"; OK=0; }

# An ACCEPT in FORWARD is only real if it sits ABOVE the perimeter DROP block —
# the chain ends with a catch-all `-i wan0 -o lan0 -j DROP`, so an appended rule
# shows up in `iptables -S` while carrying no traffic at all. Existence checks
# alone miss that, which is how the CYBERCORE-KALI-RDP fallback shipped dead.
assert_above_first_drop() {
  tag="$1"
  pos="$(pct exec "$VMID" -- /bin/sh -c \
    "iptables -L FORWARD --line-numbers -n 2>/dev/null | grep '$tag' | head -1 | awk '{print \$1}'" 2>/dev/null)"
  drop="$(pct exec "$VMID" -- /bin/sh -c \
    "iptables -L FORWARD --line-numbers -n 2>/dev/null | grep -E '^[0-9]+ +DROP' | head -1 | awk '{print \$1}'" 2>/dev/null)"
  if [ -z "$pos" ]; then
    fail "$tag has no rule in FORWARD at all"
  elif [ -n "$drop" ] && [ "$pos" -ge "$drop" ]; then
    fail "$tag is at FORWARD pos $pos, below the first DROP at pos $drop — the rule is dead"
  fi
}

# dnsmasq rendered the DHCP pool from lan0's actual address
pct exec "$VMID" -- /bin/sh -c "grep -q 'dhcp-range=${BASE}.10,${BASE}.200' /etc/dnsmasq.conf" \
  || fail "dnsmasq.conf did not render expected dhcp-range"

# GOAD controller may SSH the gateway over lan0
pct exec "$VMID" -- /bin/sh -c \
  "iptables -C INPUT -i lan0 -s ${BASE}.5 -p tcp --dport 22 -m comment --comment GOAD-CONTROLLER-SSH -j ACCEPT" 2>/dev/null \
  || fail "controller ACCEPT rule missing for ${BASE}.5"

# Lane egress is masqueraded out wan0
pct exec "$VMID" -- /bin/sh -c \
  "iptables -t nat -C POSTROUTING -s ${BASE}.0/24 -o wan0 -j MASQUERADE" 2>/dev/null \
  || fail "lane NAT MASQUERADE rule missing for ${BASE}.0/24"

# Fallback console DNAT points at the Kali reservation
pct exec "$VMID" -- /bin/sh -c \
  "iptables -t nat -C PREROUTING -i wan0 -p tcp --dport 3389 -m comment --comment CYBERCORE-KALI-RDP -j DNAT --to-destination ${BASE}.50:3389" 2>/dev/null \
  || fail "Kali DNAT rule missing for ${BASE}.50:3389"

# …and the FORWARD ACCEPT that lets the DNAT'd packet actually cross to lan0.
# The DNAT alone is not enough: without this the rewritten packet hits the
# catch-all wan0→lan0 DROP and RDP silently fails.
pct exec "$VMID" -- /bin/sh -c \
  "iptables -C FORWARD -i wan0 -o lan0 -p tcp -d ${BASE}.50 --dport 3389 -m comment --comment CYBERCORE-KALI-RDP -j ACCEPT" 2>/dev/null \
  || fail "Kali RDP FORWARD ACCEPT missing for ${BASE}.50:3389"
assert_above_first_drop CYBERCORE-KALI-RDP

# Image-pull hole exists. Its position matters as much as its existence — it
# has to sit ABOVE the base template's lan0 → 100.64.0.0/10 DROP block, or the
# vuln-app pull is dropped and every install dies with exit 11.
pct exec "$VMID" -- /bin/sh -c \
  "iptables -C FORWARD -i lan0 -o wan0 -s ${BASE}.0/24 -d ${IMG_DST} -p tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment CYBERCORE-IMAGE-PULL -j ACCEPT" 2>/dev/null \
  || fail "image-pull ACCEPT rule missing (lane→${IMG_DST}:80)"
assert_above_first_drop CYBERCORE-IMAGE-PULL

exit $(( OK == 1 ? 0 : 1 ))
