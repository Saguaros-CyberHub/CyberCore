#!/bin/sh
# ============================================================================
# 60-scrub-v1-iptables.sh — runs INSIDE the CT being patched.
#   argv[1] — extended-regex alternation of v1-only addresses (V1_PATTERNS).
# ----------------------------------------------------------------------------
# Scrub stale v1 iptables rules from the persistent rule set.
#
# v1 ships /etc/iptables/rules-save with DNATs to 192.18.0.10:3389 and
# 100.100.70.10 (the legacy single Guac VM and the v1 lane subnet). Those get
# reloaded at every boot BEFORE firstboot runs, end up first in the PREROUTING
# chain, and silently swallow inbound 3389 → black hole. We drop any rule
# referencing those, then re-persist the cleaned ruleset.
# ============================================================================
set -e

PATTERNS="${1:?usage: 60-scrub-v1-iptables.sh <extended-regex>}"
RULES=/etc/iptables/rules-save

if [ -f "$RULES" ]; then
  cp "$RULES" "${RULES}.v1.bak"
  grep -vE "$PATTERNS" "${RULES}.v1.bak" > "$RULES"
  echo "  Cleaned $RULES (backup at ${RULES}.v1.bak)"
fi

# Also flush the running NAT table + any v1 FORWARD rules so the running state
# matches the persistent state. iptables-save | grep -v | iptables-restore is
# the standard idiom for surgical rule deletion.
iptables-save | grep -vE "$PATTERNS" | iptables-restore || true
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules-save
echo "  Persistent + running iptables: stale v1 references purged"
