#!/bin/sh
# ============================================================================
# 20-neutralize-v1-hooks.sh — runs INSIDE the CT being patched.
#   argv[1] — path to the 50-gateway.start stub, already pushed into the CT.
# ----------------------------------------------------------------------------
# Neutralize /etc/local.d/50-gateway.start.
#
# The v1 50-gateway.start applied lan0's IP (`ip addr add 192.18.0.1/24 dev
# lan0`), the lane->wan MASQUERADE for 192.18.0.0/24, and the controller-SSH
# ACCEPT — all hardcoded to v1's shared subnet. Surgical sed isn't enough
# because we'd have to know which lines to keep; we instead back the original
# aside as `.v1.bak` and replace 50-gateway.start with a no-op stub. Firstboot
# (00-cybercore-firstboot.start) now handles every responsibility
# 50-gateway.start had, but driven by lan0's actual per-deploy IP.
#
# Then a defensive sweep: comment out any *remaining* 192.18.0 references
# inside /etc/local.d/ and /etc/init.d/ — catches anything ansible or earlier
# bake steps may have planted that we don't know about.
# ============================================================================
set -e

STUB_SRC="${1:?usage: 20-neutralize-v1-hooks.sh <path-to-stub>}"
HOOK=/etc/local.d/50-gateway.start

if [ -f "$HOOK" ]; then
  cp "$HOOK" "${HOOK}.v1.bak"
  echo "--- ORIGINAL $HOOK (preserved at ${HOOK}.v1.bak) ---"
  cat "${HOOK}.v1.bak"
  echo "----------------------------------------------------"
  cp "$STUB_SRC" "$HOOK"
  chmod +x "$HOOK"
  echo "Replaced $HOOK with no-op stub."
else
  echo "No $HOOK present (fine)."
fi

echo "Defensive sweep: commenting out remaining 192.18.0.x in /etc/local.d/ and /etc/init.d/..."
for d in /etc/local.d /etc/init.d; do
  [ -d "$d" ] || continue
  # Skip our backup files and the firstboot script (firstboot has no 192.18
  # refs anyway).
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
