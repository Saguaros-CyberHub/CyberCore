#!/bin/sh
# ============================================================================
# cc-attack.sh — CyberCore CYBR 400 attack wrapper
# ----------------------------------------------------------------------------
# Staged onto the lane's log-generator host by cle/utils/attack-runner.js on
# every dispatch, so a guest can never be running a stale copy of this logic.
# Do not edit on the guest; edit here.
#
# usage: cc-attack.sh RUN_ID START_EPOCH REL_DELAY MODE ARG DURATION CAP_S SPEED
#
# Contract with the server:
#   - EVERY refusal writes its reason to the state file and exits 0. A refusal
#     is data the console renders on that lane's row ("log-generator is not
#     installed"), not a crash to be inferred from an exit code.
#   - State writes are atomic (write .tmp, mv -f). The reconciler reads this
#     file from another process every 30s; a half-written line parses as junk.
#   - This script is the process-group leader (the server launches it under
#     `nohup setsid`), so abort can kill the whole tree by negating our pid.
#
# POSIX sh, not bash. Rocky ships bash, but /bin/sh is what agentShellExec
# invokes and staying portable means this still works if the sensor image is
# ever rebased on something leaner.
# ============================================================================
set -u

RUN_ID="$1"; T="$2"; RELD="$3"; MODE="$4"; ARG="$5"; DUR="$6"; CAP="$7"; SPEED="$8"

BASE=/opt/cybercore
RD="$BASE/runs/$RUN_ID"
STATE="$RD/state"
MANIFEST="$BASE/loggen-manifest.json"
LG_BASE=/opt/log-generator
LG=/opt/log-generator-attack

mkdir -p "$RD" 2>/dev/null || true

say() {
  printf '%s\n' "$*" > "$STATE.tmp" 2>/dev/null && mv -f "$STATE.tmp" "$STATE" 2>/dev/null
}

# Which log-generator commit this image was baked at. Reported on every state
# line so an image/catalog mismatch is visible without a separate probe.
# grep|cut rather than a sed backref: no backslashes to survive three layers of
# quoting between here and the guest.
REF=$(grep -o '"ref"[^,}]*' "$MANIFEST" 2>/dev/null | head -1 | cut -d: -f2 | tr -d '" ')
[ -n "$REF" ] || REF=unknown

# The attack runs from a SECOND checkout. log-generator writes to a rotating
# ./logs/current/logs.json relative to its own tree, so sharing one checkout
# with the always-on baseline service means two independent rotating writers on
# one file: one renames, the other keeps its fd on the orphaned inode, and
# events silently vanish. A separate tree makes the relative path resolve
# elsewhere and costs one `cd`.
#
# Falling back to the single checkout keeps an older image working, but it DOES
# collide as described, so the state line reports split=0 and the console warns.
SPLIT=1
if [ ! -f "$LG/package.json" ]; then LG="$LG_BASE"; SPLIT=0; fi

if [ ! -f "$LG/package.json" ]; then say "refused notinstalled ref=$REF"; exit 0; fi
command -v npm >/dev/null 2>&1 || { say "refused nonpm ref=$REF"; exit 0; }

FREE=$(df -Pk "$LG" 2>/dev/null | awk 'NR==2{print $4}')
case "$FREE" in ''|*[!0-9]*) FREE=0 ;; esac
if [ "$FREE" -lt 2097152 ]; then say "refused nospace free_kb=$FREE ref=$REF"; exit 0; fi

# --- synchronized start ---------------------------------------------------
# Two clocks, because neither is trustworthy alone. T is an absolute epoch and
# gives sub-second agreement across the class WHEN the guests are NTP-synced --
# which nothing guarantees: the lane gateway is an Alpine LXC doing NAT and
# whether it forwards NTP egress is deployment-dependent, and Proxmox only syncs
# guest RTC on resume. RELD is the delay measured at the instant this lane's
# exec was issued, so it needs no shared clock at all. If T lands outside a sane
# window we conclude the guest clock is wrong and fall back to RELD.
#
# SKEW is measured BEFORE the fallback, deliberately. Computing it from the
# post-fallback delay makes it identically zero on exactly the guests whose
# clocks are wrong -- reporting "no drift" at the moment drift is maximal. FB=1
# records that we distrusted the epoch, which is the other half of the story.
NOW=$(date +%s)
RAW=$((T - NOW))
SKEW=$((RAW - RELD))
D="$RAW"
FB=0
if [ "$D" -lt 0 ] || [ "$D" -gt 300 ]; then D="$RELD"; FB=1; fi
say "scheduled start=$T delay=$D skew=$SKEW fb=$FB pid=$$ split=$SPLIT ref=$REF"
if [ "$D" -gt 0 ]; then sleep "$D"; fi

cd "$LG" 2>/dev/null || { say "refused nodir ref=$REF"; exit 0; }

# Count only what THIS run produced, and only what will actually SHIP.
#
# Counting every written line would report ~37,000 for a run that puts 76 events
# in Kibana: --mitre-technique filters which lines get TAGGED, not which get
# written, and the agent drops the untagged remainder before it leaves the box.
# The console's number has to mean the same thing the instructor sees, or it is
# worse than no number at all.
#
# Any tag here is the selected technique by construction -- the attack tree's
# config-level mitre blocks are stripped at bake time, so nothing else can tag.
#
# The output is append-and-rotate, so a before/after delta is the honest
# measure. A rotation mid-run would make it negative; clamp rather than report
# a nonsense number.
count_lines() { cat logs/current/*.json 2>/dev/null | grep -c '"technique":"' | tr -d ' ' || true; }
BEFORE=$(count_lines)
case "$BEFORE" in ''|*[!0-9]*) BEFORE=0 ;; esac

say "running start=$(date +%s) pid=$$ skew=$SKEW fb=$FB split=$SPLIT ref=$REF"

RUNLOG="$RD/run.log"

# Load-bearing, not tidiness: log-generator binds a health/metrics HTTP server
# on :3000 and the always-on baseline service already holds it. Without this the
# attack process collides on the port.
ENABLE_MONITORING=false
export ENABLE_MONITORING

# `timeout -k 30` is the hard ceiling that stops a runaway run filling the disk.
# It is what systemd RuntimeMaxSec would have bought, without needing systemd.
# The `--` after the npm script name is required: it forwards the flags to
# ts-node src/cli.ts rather than letting npm eat them.
case "$MODE" in
  technique)
    timeout -k 30 "${CAP}s" npm run generate -- --mitre-technique "$ARG" --duration "$DUR" > "$RUNLOG" 2>&1
    ;;
  tactic)
    timeout -k 30 "${CAP}s" npm run generate -- --mitre-tactic "$ARG" --duration "$DUR" > "$RUNLOG" 2>&1
    ;;
  chain)
    timeout -k 30 "${CAP}s" npm run attack-chains:execute -- "$ARG" --speed "$SPEED" > "$RUNLOG" 2>&1
    ;;
  *)
    say "refused badmode ref=$REF"; exit 0
    ;;
esac
RC=$?

AFTER=$(count_lines)
case "$AFTER" in ''|*[!0-9]*) AFTER=0 ;; esac
LINES=$((AFTER - BEFORE))
if [ "$LINES" -lt 0 ]; then LINES=0; fi

say "done rc=$RC end=$(date +%s) lines=$LINES skew=$SKEW fb=$FB ref=$REF"

# ELK ingestion never deletes what it reads, so without this the attack tree
# grows without bound across a semester.
find "$LG/logs" -type f -name '*.json*' -mtime +7 -delete 2>/dev/null || true
find "$BASE/runs" -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -rf {} + 2>/dev/null || true
exit 0
