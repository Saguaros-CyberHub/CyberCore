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

# The v1 blanket RDP forward: `-A FORWARD -i wan0 -o lan0 -p tcp --dport 3389
# -j ACCEPT`, with no destination and no comment tag. It sits above the
# perimeter DROPs and accepts inbound RDP to EVERY host on the lane, not just
# the console box. It is also what quietly carried RDP while firstboot's own
# CYBERCORE-KALI-RDP ACCEPT was being appended below the wan0→lan0 DROP (dead).
# Now that the tagged rule inserts above the DROPs, this is both redundant and
# broader than intended. Matched on exact shape so the tagged rules — which
# carry `-d <ip>` and `--comment` — are never touched.
BLANKET_RDP='^-A FORWARD -i wan0 -o lan0 -p tcp -m tcp --dport 3389 -j ACCEPT$'

if [ -f "$RULES" ]; then
  cp "$RULES" "${RULES}.v1.bak"
  grep -vE "$PATTERNS" "${RULES}.v1.bak" | grep -vE "$BLANKET_RDP" > "$RULES"
  echo "  Cleaned $RULES (backup at ${RULES}.v1.bak)"
fi

# Also flush the running NAT table + any v1 FORWARD rules so the running state
# matches the persistent state. iptables-save | grep -v | iptables-restore is
# the standard idiom for surgical rule deletion.
iptables-save | grep -vE "$PATTERNS" | grep -vE "$BLANKET_RDP" | iptables-restore || true
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules-save
echo "  Persistent + running iptables: stale v1 references purged"
