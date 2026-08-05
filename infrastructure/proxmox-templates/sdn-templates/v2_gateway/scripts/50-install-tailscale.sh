#!/bin/sh
# ============================================================================
# 50-install-tailscale.sh — runs INSIDE the CT being patched.
#   argv[1] — path to the /etc/conf.d/tailscale payload, already pushed in.
# ----------------------------------------------------------------------------
# Install Tailscale + configure userspace-networking mode.
#
# Userspace mode means tailscaled doesn't need a TUN device — works in
# unprivileged Proxmox LXCs without any LXC config tweaks. Subnet routing (the
# BYOAB feature we want) still works in userspace mode.
#
# Tailscale is installed but NOT auto-launched here. firstboot calls
# `tailscale up` only after it successfully fetches an auth key from the
# orchestrator's /api/lane-bootstrap endpoint.
# ============================================================================
set -e

CONF_SRC="${1:?usage: 50-install-tailscale.sh <path-to-conf.d-tailscale>}"

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

mkdir -p /etc/conf.d /var/lib/tailscale
cp "$CONF_SRC" /etc/conf.d/tailscale
chmod 0644 /etc/conf.d/tailscale

# Clean up the wrong-path file from earlier bakes if it exists — tailscaled
# never reads /etc/conf.d/tailscaled, so a stale one there is pure confusion.
rm -f /etc/conf.d/tailscaled
rc-update add tailscale default 2>/dev/null || true

# Smoke-test: actually start the daemon during bake to catch config errors now
# instead of at deploy time. If userspace mode is broken, this fails fast.
rc-service tailscale restart >/dev/null 2>&1 || true
sleep 2
if rc-service tailscale status 2>&1 | grep -q "started"; then
  echo "Tailscale daemon: started OK in userspace mode."
  rc-service tailscale stop >/dev/null 2>&1 || true
else
  echo "WARNING: tailscale daemon failed to start during bake — check /var/log/messages"
  rc-service tailscale status 2>&1 || true
fi
echo "Tailscale install + config complete."
