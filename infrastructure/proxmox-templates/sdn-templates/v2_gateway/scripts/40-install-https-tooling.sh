#!/bin/sh
# ============================================================================
# 40-install-https-tooling.sh — runs INSIDE the CT being patched.
# ----------------------------------------------------------------------------
# Install full wget + ca-certificates so the bootstrap fetch in firstboot can
# speak HTTPS. BusyBox's built-in wget either lacks TLS entirely or handshakes
# with the wrong cipher suite against modern Caddy/Let's Encrypt, so we replace
# it with the GNU wget binary (`apk add wget`) and ship the Mozilla CA bundle
# (`ca-certificates`). Without this, gateways behind a public-HTTPS orchestrator
# silently fail bootstrap and Tailscale never comes up — which is exactly the
# AZ-CYBR regression we hit.
#
# Also enables dnsmasq + local in the default runlevel (no-op if v1 already
# did it) — `local` is what runs /etc/local.d/*.start, so firstboot depends
# on it.
# ============================================================================
set -e

apk update >/dev/null 2>&1 || true
apk add --no-cache wget ca-certificates 2>&1 | tail -5

# Refresh the trust bundle so Let's Encrypt root is recognized.
update-ca-certificates 2>/dev/null || true

# Smoke-test: hit a known-HTTPS endpoint to confirm wget+TLS works.
if wget -q --timeout=5 --spider https://www.google.com/generate_204 2>/dev/null; then
  echo "  HTTPS smoke test: OK"
else
  echo "  HTTPS smoke test: FAILED (gateway may still need firewall/DNS fixes)"
fi

rc-update add dnsmasq default 2>/dev/null || true
rc-update add local default 2>/dev/null || true
echo "  dnsmasq + local enabled in default runlevel."
