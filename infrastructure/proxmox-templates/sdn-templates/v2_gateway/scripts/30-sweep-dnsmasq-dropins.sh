#!/bin/sh
# ============================================================================
# 30-sweep-dnsmasq-dropins.sh — runs INSIDE the CT being patched.
# ----------------------------------------------------------------------------
# Sweep /etc/dnsmasq.d/ for v1 drop-ins.
#
# The v1 image ships a 50-gateway.conf in /etc/dnsmasq.d/ that hardcodes DHCP
# option 3 (router) and option 6 (DNS) to 192.18.0.1. dnsmasq merges drop-ins
# AFTER /etc/dnsmasq.conf, so the v1 drop-in OVERRIDES the v2 firstboot-rendered
# options — handing v1 addressing out to v2 DHCP clients (Windows VMs end up
# with default route + DNS = 192.18.0.1, which doesn't exist in
# 10.<vxh>.<vxl>.0/24, breaking all egress).
#
# The firstboot script's main dnsmasq.conf has `conf-dir=/etc/dnsmasq.d/` so we
# keep that mechanism intact (the deploy path writes lane-reservations.conf
# there per-lane), but we must clear any v1-hardcoded files at bake time.
# ============================================================================
set -e

D=/etc/dnsmasq.d
[ -d "$D" ] || { echo "  $D missing (fine)"; exit 0; }

for f in "$D"/*.conf; do
  [ -f "$f" ] || continue
  case "$f" in *.v1.bak) continue ;; esac
  # Match anything that hardcodes the v1 lane subnet — the canonical offender
  # is 50-gateway.conf, but be permissive so future v1 leftovers also get caught.
  if grep -q "192\.18\.0" "$f" 2>/dev/null; then
    echo "  Moving aside $f -> ${f}.v1.bak"
    mv "$f" "${f}.v1.bak"
  fi
done

echo "  /etc/dnsmasq.d/ contents after sweep:"
ls -la "$D" | sed "s/^/    /"
