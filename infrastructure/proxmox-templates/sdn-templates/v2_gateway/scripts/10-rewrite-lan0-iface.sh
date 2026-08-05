#!/bin/sh
# ============================================================================
# 10-rewrite-lan0-iface.sh — runs INSIDE the CT being patched.
# ----------------------------------------------------------------------------
# Strip the baked static IP from /etc/network/interfaces' lan0 stanza.
#
# v1 has `iface lan0 inet static / address 192.18.0.1 / netmask ...` baked in.
# Alpine's `networking` service runs ifup at boot and forces that IP onto lan0,
# overriding whatever Proxmox set via `pct set --net1`. We rewrite the stanza to
# `inet manual` so the Proxmox .conf is the only source of truth — firstboot
# then reads the per-deploy IP correctly.
# ============================================================================
set -e

IF_FILE=/etc/network/interfaces
if [ ! -f "$IF_FILE" ]; then
  echo "No $IF_FILE present (fine)."
  exit 0
fi

cp "$IF_FILE" "${IF_FILE}.v1.bak"
awk '
  BEGIN { in_lan0 = 0 }
  /^iface lan0[[:space:]]/ {
    in_lan0 = 1
    sub(/inet static/, "inet manual")
    sub(/inet dhcp/,   "inet manual")
    print
    next
  }
  /^(iface|auto|allow-)[[:space:]]/ && in_lan0 {
    in_lan0 = 0
  }
  in_lan0 && /^[[:space:]]+(address|netmask|gateway|broadcast|hwaddress|pre-up|post-up|up)[[:space:]]/ { next }
  { print }
' "${IF_FILE}.v1.bak" > "$IF_FILE"

echo "Rewrote lan0 stanza. Backup at ${IF_FILE}.v1.bak."
echo "--- new $IF_FILE ---"
cat "$IF_FILE"
echo "--------------------"
