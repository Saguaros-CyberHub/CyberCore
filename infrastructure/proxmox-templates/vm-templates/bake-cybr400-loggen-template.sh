#!/bin/bash
# ============================================================================
# bake-cybr400-loggen-template.sh
# ----------------------------------------------------------------------------
# Bakes the CYBR 400 sensor image: Rocky Linux + summved/log-generator (pinned
# to a commit) + Elastic Agent + an always-on benign baseline log stream.
#
# One of these sits in every student lane alongside their Windows ELK box. The
# CLE Attack Console (modules/crucible/plugins/cle/) fires the same MITRE
# technique or attack chain at every one of them simultaneously, over the
# Proxmox guest agent.
#
# WHY DERIVE FROM 1001 RATHER THAN A CLOUD IMAGE
#   Every other template here starts from a downloaded qcow2. This one clones
#   the existing rocky-linux-template (VMID 1001), which is hand-built and the
#   only catalog row in the repo with no bake script of its own. Cloning keeps
#   whatever cloud-init account contract and hardening 1001 already carries,
#   and means this script owns exactly one thing: the sensor layer.
#
# WHY THE LOG-GENERATOR COMMIT IS PINNED
#   cle/utils/loggen-catalog.js is a hand TRANSCRIPTION of log-generator's
#   MITRE map, because upstream's `mitre-list` has no --json and there is
#   nothing to fetch. A floating clone would drift from it silently: the console
#   would keep offering techniques the guest no longer recognises, and the only
#   symptom is a run that generates nothing. LOGGEN_REF is written into
#   /opt/cybercore/loggen-manifest.json, the attack wrapper reports it on every
#   state line, and the console flags a mismatch.
#
# WHY TWO CHECKOUTS
#   log-generator writes to a rotating ./logs/current/logs.json RELATIVE TO ITS
#   OWN TREE. The baseline service runs continuously, so sharing one checkout
#   with an instructor-fired attack means two independent rotating writers on
#   one file: one renames, the other keeps its fd on the orphaned inode, and
#   events silently vanish. /opt/log-generator-attack is the same commit with
#   its own logs/ directory. The Elastic Agent ships both paths.
#
# Run on a Proxmox node with internet access. Idempotent: refuses if VMID
# already exists. To re-bake: qm destroy 1006 --purge
# ============================================================================
set -euo pipefail

VMID=${VMID:-1007}
SRC_VMID=${SRC_VMID:-1001}                 # rocky-linux-template
NAME=${NAME:-cybr400-loggen-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
MEMORY=${MEMORY:-4096}                     # ts-node + two node processes
CORES=${CORES:-2}

TEMPLATE_USER="${TEMPLATE_USER:-sensor}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-bake-debug}"

# Pin. Bump together with CATALOG_VERSION in cle/utils/loggen-catalog.js, and
# re-read mitreMapper.ts + chains/templates/*.yaml when you do.
LOGGEN_REPO="${LOGGEN_REPO:-https://github.com/summved/log-generator.git}"
LOGGEN_REF="${LOGGEN_REF:-2db735a7a5c6fb56654187325bb36772d3c9c4d7}"
NODE_STREAM="${NODE_STREAM:-20}"

# The in-lane ELK box. Resolves identically in EVERY lane, which is what lets
# this config be baked once instead of templated per lane.
#
# The name is published by the LANE GATEWAY, not by the Windows box: set
# metadata.dns_aliases = ["elk"] on the ELK catalog row and lane-deployer.js
# writes a dnsmasq `host-record` into that lane's reservation file, pointing at
# whatever address the ELK box actually took.
#
# It deliberately does NOT rely on the Windows machine advertising 'elk' over
# DHCP. cloudbase-init's SetHostNamePlugin renames every clone to the Proxmox VM
# name, truncates it to the 15-char NetBIOS limit, and with allow_reboot=false
# applies it only at the next reboot — so that name is the baked one on first
# boot and the lane name afterwards. See NEXTSTEPS step 3.
ELK_HOST="${ELK_HOST:-elk.cybercore.lan}"
ELK_PORT="${ELK_PORT:-9200}"
# REQUIRED, and deliberately has no default: the agent must match the stack
# running on the lane's ELK box. Guessing produces an agent that installs
# cleanly and then fails to ship, which reads as a network or DNS problem.
# Find it with, on the ELK box:
#     Invoke-RestMethod http://localhost:9200 | Select -Expand version
ELASTIC_VERSION="${ELASTIC_VERSION:-}"

# SELinux mode written into the sensor image. See the runcmd note: enforcing
# breaks the Attack Console's guest-exec dispatch outright.
SELINUX_MODE="${SELINUX_MODE:-permissive}"

# ---------- Baseline generator rates ----------
# log-generator's "frequency" is LOGS PER MINUTE, but BaseGenerator only honours
# it exactly when frequency <= 20. calculateBatchConfig() at this commit reads:
#
#     const BATCH_THRESHOLD = 20;
#     if (targetFrequency <= BATCH_THRESHOLD)
#       return { logsPerBatch: 1, intervalMs: (60 / targetFrequency) * 1000 };
#     ... timerFrequencyHz = 10; intervalMs = 100;              // 21..1000
#     const logsPerBatch = Math.max(1, Math.round(targetLogsPerSecond / timerFrequencyHz));
#
# Math.max(1, ...) is the trap. Any generator in 21..1000 emits at least one log
# every 100 ms -- 10/sec, 600/min -- no matter how small its number is. Setting
# endpoint to 60 does not ask for 60/min, it asks for 600/min.
#
# Measured on a deployed lane: five generators sat above the threshold (endpoint
# 60, authentication 25, database 30, webserver 40, microservices 35), so
# 5 x 10/sec = 50/sec, plus ~1.5/sec from the seven below it. Kibana showed
# 30,869 documents per 10 minutes = 51.4/sec. The config claimed 288/min.
#
# So EVERY generator below is <= 20. On that path the interval is exactly
# 60000/frequency ms and the configured number is the real number. 20/min is
# therefore the per-generator ceiling; the shape (webserver and firewall busy,
# backup nearly idle) is what makes it read as a small business rather than as
# twelve identical faucets.
BASELINE_FREQ_WEBSERVER="${BASELINE_FREQ_WEBSERVER:-20}"
BASELINE_FREQ_FIREWALL="${BASELINE_FREQ_FIREWALL:-18}"
BASELINE_FREQ_ENDPOINT="${BASELINE_FREQ_ENDPOINT:-15}"
BASELINE_FREQ_AUTHENTICATION="${BASELINE_FREQ_AUTHENTICATION:-10}"
BASELINE_FREQ_DATABASE="${BASELINE_FREQ_DATABASE:-10}"
BASELINE_FREQ_MICROSERVICES="${BASELINE_FREQ_MICROSERVICES:-8}"
BASELINE_FREQ_APPLICATION="${BASELINE_FREQ_APPLICATION:-6}"
BASELINE_FREQ_SERVER="${BASELINE_FREQ_SERVER:-5}"
BASELINE_FREQ_CLOUD="${BASELINE_FREQ_CLOUD:-3}"
BASELINE_FREQ_EMAIL="${BASELINE_FREQ_EMAIL:-3}"
BASELINE_FREQ_IOT="${BASELINE_FREQ_IOT:-2}"
BASELINE_FREQ_BACKUP="${BASELINE_FREQ_BACKUP:-1}"
# Sum = 101 logs/min = 1.7/sec = ~145k/day, against 4.4M/day as measured.

# Whether to strip mitre: blocks from the BASELINE checkout. Default OFF, and
# that default is load-bearing for the exercise.
#
# Stock templates hang mitre: blocks off ordinary traffic -- a routine nginx
# request carries T1018, a rate-limit warning carries T1110. The instinct is to
# strip them so benign filler is not labelled with attack techniques. Doing that
# creates something worse than mislabelled noise: if ONLY attack events carry
# loggen.mitre.*, then the single query
#
#     loggen.mitre.technique : *
#
# returns the instructor's attack and nothing else, every time. A perfect oracle,
# and the first thing a student clicking through the field list will find.
#
# Left in place, roughly 15% of baseline events carry a technique across 16
# distinct IDs (T1190 T1110 T1110.001 T1071 T1078 T1496 T1499 T1562.004
# T1562.001 T1046 T1059.003 T1098 T1505.003 T1003 T1566 T1490). That is the
# false-positive floor a real analyst works against, and nine of those IDs are
# also in loggen-catalog.js -- so picking one of those nine for an assignment
# means the technique label alone cannot separate the attack from the noise.
#
# Set to 1 only if you want technique-labelled filler gone and accept that
# mitre.technique:* becomes the answer key.
BASELINE_STRIP_MITRE="${BASELINE_STRIP_MITRE:-0}"

# And the exact inverse for the ATTACK checkout. Default ON.
#
# The baseline KEEPS its mitre blocks so benign traffic carries a realistic
# false-positive floor. The attack tree must not, for a different reason: the
# agent drops every attack event that has no technique, so any tag left in that
# config would ship as though it were part of the instructor's run. A stock
# attack tree would emit T1190/T1110/T1071/T1499 alongside the selected
# technique and quietly corrupt the exercise.
#
# Stripped, the only tags left are the ones MitreMapper assigns at runtime,
# which the --mitre-technique filter has already constrained to the chosen
# technique. Confirmed on a deployed lane: 37,004 lines, exactly one distinct
# technique present.
ATTACK_STRIP_MITRE="${ATTACK_STRIP_MITRE:-1}"

# Rotate the baseline log at this size. log-generator appends to ONE file and
# never rotates: a deployed lane reached log.offset 2,490,538,083 -- 2.5 GB in
# a single logs.json in about twelve hours.
BASELINE_ROTATE_BYTES="${BASELINE_ROTATE_BYTES:-268435456}"

# Baseline rate. Deliberately modest: the point is that an instructor's attack
# arrives buried in ordinary traffic, not that the disk fills by Friday.
BASELINE_ARGS="${BASELINE_ARGS:---duration 24h}"

# Whether log-generator drives the benign baseline. Default OFF: cc-hostbase
# does, and log-generator is left installed only as a fallback.
#
# It was retired for four reasons, in order of how much they cost:
#
#  1. It never substitutes its metadata placeholders. Every event it emits ships
#     literal "clientIP":"{clientIP}", "method":"{method}" into Kibana --
#     obviously synthetic to anyone who opens an event, AND a discriminator,
#     since emitter events have clean metadata. Same class of leak as a dataset
#     name, sitting in the benign half where it is hardest to notice.
#  2. It is flat 24/7 and cannot be made otherwise without retuning and
#     restarting it hourly -- and a restart that does not first rename
#     logs.json risks filestream re-reading from offset 0.
#  3. Every workaround in this script exists to manage it: the frequency<=20
#     batch cliff, 54,609 .jsonl files stalling guest-exec, rotation: false,
#     the rename-and-restart dance.
#  4. cc-emit.js now covers all twelve of its source types with several message
#     templates each, so benign and hostile traffic come from ONE engine and are
#     identical in shape by construction rather than by hand-maintained parity.
#
# Set to 1 to put it back; the unit and both checkouts stay on the image.
LOGGEN_BASELINE_ENABLED="${LOGGEN_BASELINE_ENABLED:-0}"

# ---------- 0. Sanity ----------
if qm status $VMID >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status $VMID >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
  exit 1
fi
if ! qm status $SRC_VMID >/dev/null 2>&1; then
  echo "ERROR: source template $SRC_VMID (rocky-linux-template) not found on this node." >&2
  echo "       Run this on the node that holds it, or set SRC_VMID." >&2
  exit 1
fi
if [ -z "$ELASTIC_VERSION" ]; then
  echo "ERROR: ELASTIC_VERSION is required — the agent must match the ELK stack it ships to." >&2
  echo "       On the ELK box: Invoke-RestMethod http://localhost:9200 | Select -Expand version" >&2
  echo "       Then: ELASTIC_VERSION=<x.y.z> $0" >&2
  exit 1
fi
if ! printf '%s' "$ELASTIC_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "ERROR: ELASTIC_VERSION='$ELASTIC_VERSION' is not an x.y.z version." >&2
  exit 1
fi

pick_snippet_storage() {
  if [ -n "${SNIPPET_STORAGE:-}" ]; then
    if pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SNIPPET_STORAGE"; then
      echo "$SNIPPET_STORAGE"; return 0
    fi
    echo "ERROR: SNIPPET_STORAGE='$SNIPPET_STORAGE' set but missing 'snippets' content." >&2
    return 1
  fi
  local first
  first=$(pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then echo "$first"; return 0; fi
  echo "==> Enabling 'snippets' on local storage..." >&2
  local cur
  cur=$(awk '/^[a-z]+: local$/{flag=1} flag && /^\s*content/{print $2; flag=0}' /etc/pve/storage.cfg)
  [ -z "$cur" ] && cur="iso,vztmpl,backup"
  [[ "$cur" != *snippets* ]] && pvesm set local --content "${cur},snippets" >&2
  echo "local"
}
SNIPPET_STORAGE=$(pick_snippet_storage)

USERDATA_FILE="cybr400-loggen-bake-${VMID}.yaml"
case "$SNIPPET_STORAGE" in
  local)  USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  cephfs) USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
  *)      USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
esac
mkdir -p "$(dirname "$USERDATA_PATH")"

echo "==> Baking $NAME as VMID $VMID from source template $SRC_VMID"
echo "    log-generator @ ${LOGGEN_REF:0:12}"
echo "    ELK target    : http://${ELK_HOST}:${ELK_PORT} (no auth — lab stack runs with security disabled)"

# ---------- 0b. Guest helper scripts ----------
# Built here as real shell, then base64'd into cloud-init write_files. The
# userdata heredoc below is UNQUOTED so ${ELK_HOST} and friends expand, which
# means anything containing $, backticks or backslashes cannot be pasted into it
# literally -- and an awk script is nothing but $1 and backslashes. base64 with
# encoding: b64 sidesteps the whole class of escaping bug, the same reason
# cc-attack.sh is a file rather than a JS template literal.

TUNE_TMP="$(mktemp)"
cat > "$TUNE_TMP" <<'LOGGEN_TUNE_EOF'
#!/bin/sh
# loggen-tune.sh <default.yaml> [generator=frequency ...]
#
# Retunes a log-generator checkout for CYBR 400 baseline duty. Two edits:
#
#  1. frequency, per generator. Must be <= 20 to land on BaseGenerator's exact
#     setInterval(60000/f) path; above 20 a Math.max(1, ...) floor pins the
#     generator to 10 logs/second whatever the number says.
#
#  2. mitre: blocks, stripped when LOGGEN_STRIP_MITRE=1. Stock templates label
#     ordinary traffic with attack techniques, so the "benign" baseline is full
#     of T1018/T1110/T1190 and hunting by technique returns noise forever.
#
# Rewrites in place. Idempotent: safe to re-run against an already-tuned file.
set -e

CFG="$1"
[ -n "$CFG" ] || { echo "loggen-tune: usage: $0 <default.yaml> [name=freq ...]" >&2; exit 2; }
[ -f "$CFG" ] || { echo "loggen-tune: no such config: $CFG" >&2; exit 1; }
shift

for PAIR in "$@"; do
  NAME="${PAIR%%=*}"
  VAL="${PAIR#*=}"
  case "$VAL" in
    ''|*[!0-9]*) echo "loggen-tune: bad frequency '$PAIR'" >&2; exit 2 ;;
  esac
  # A frequency above 20 silently becomes 600/min. Refuse rather than bake it.
  if [ "$VAL" -gt 20 ] || [ "$VAL" -lt 1 ]; then
    echo "loggen-tune: $NAME=$VAL is outside 1..20; above 20 the batch floor" >&2
    echo "             pins the generator to 10 logs/sec. Refusing." >&2
    exit 2
  fi
  # Track the current generator by its 2-space key, rewrite the 4-space
  # frequency underneath it. Keyed on indent so a 'frequency' appearing inside
  # a template's metadata could never be hit by accident.
  awk -v g="$NAME" -v v="$VAL" '
    /^  [A-Za-z_][A-Za-z0-9_]*:[ \t]*$/ { cur = $1; sub(/:$/, "", cur) }
    cur == g && /^    frequency:[ \t]/   { print "    frequency: " v; next }
    { print }
  ' "$CFG" > "$CFG.tune" && mv "$CFG.tune" "$CFG"
done

# --- 3. log-generator's own file rotation ---
# output.file declares rotation: true, maxSize: 100MB, maxFiles: 10. The maxFiles
# cap is not enforced at this commit: it writes logs_<ISO>.jsonl roughly once a
# second and never reaps them. Measured on a deployed sensor: 54,609 files in
# /opt/log-generator/logs/current after ~15 hours.
#
# They are not even ingested -- the agent's glob is *.json and these end .jsonl --
# but filebeat still enumerates the directory on every scan to evaluate that
# glob, and 54k entries is enough to stall guest-exec long enough for the Attack
# Console's 60s staging poll to time out, on a box showing 0.00 load average.
#
# rotation: false stops them at the source; loggen-rotate.sh handles size instead,
# and also reaps any strays so this does not depend on the guess above being right.
if [ "${LOGGEN_DISABLE_FILE_ROTATION:-1}" = "1" ]; then
  sed -i 's/^    rotation: true$/    rotation: false/' "$CFG"
fi

if [ "${LOGGEN_STRIP_MITRE:-0}" = "1" ]; then
  # mitre: sits at 8 spaces under a template list item; its body is every
  # following line indented deeper than that.
  awk '
    /^        mitre:[ \t]*$/        { skip = 1; next }
    skip == 1 && /^          [^ ]/  { next }
    skip == 1 && /^          /      { next }
    { skip = 0; print }
  ' "$CFG" > "$CFG.tune" && mv "$CFG.tune" "$CFG"
fi

exit 0
LOGGEN_TUNE_EOF
sh -n "$TUNE_TMP" || { echo "ERROR: loggen-tune.sh failed syntax check" >&2; exit 1; }
LOGGEN_TUNE_B64="$(base64 -w0 "$TUNE_TMP")"
rm -f "$TUNE_TMP"

ROTATE_TMP="$(mktemp)"
cat > "$ROTATE_TMP" <<'LOGGEN_ROTATE_EOF'
#!/bin/sh
# loggen-rotate.sh [max-bytes]
#
# log-generator appends to ONE logs.json and never rotates it. A deployed lane
# reached log.offset 2,490,538,083 -- 2.5 GB in roughly twelve hours -- which
# fills the disk and leaves filestream a backlog it re-walks on every restart.
#
# Rotation has to be done in a way filestream survives:
#
#   * NOT copytruncate. Truncating makes the file shrink, filestream reads that
#     as a new file and re-ingests from offset 0. That is a duplicate storm, not
#     a rotation.
#   * NOT a rename to logs.json.1 either. The input glob is *.json, so the
#     rotated file would fall out of the glob mid-harvest and lose its tail.
#
# So: rename INTO the glob as logs-<epoch>.json, restart the generator so it
# opens a fresh handle, and delete the old file only after an hour -- long
# enough for filestream to finish it. Identity is by fingerprint, so the rename
# itself does not cause a re-read.
set -e

DIR=/opt/log-generator/logs/current
ATTACK_DIR=/opt/log-generator-attack/logs/current
F="$DIR/logs.json"
MAX="${1:-268435456}"
GRACE_MIN=60

# Reap log-generator's own rotation spam FIRST, unconditionally, and in BOTH
# checkouts -- it is the expensive problem even when logs.json is nowhere near
# the size cap. These are .jsonl, so the agent's *.json glob never ingested
# them; the cost is purely the directory enumeration filebeat does on every
# scan, and 54,609 entries was enough to stall guest-exec on an idle box.
#
# The attack tree matters as much as the baseline: it gains another file per
# second for the length of every attack run and nothing else ever cleans it.
for D in "$DIR" "$ATTACK_DIR"; do
  [ -d "$D" ] || continue
  find "$D" -maxdepth 1 -name 'logs_*.jsonl' -mmin +5 -delete 2>/dev/null || true
done

[ -f "$F" ] || exit 0
SZ="$(stat -c %s "$F" 2>/dev/null || echo 0)"

if [ "$SZ" -ge "$MAX" ]; then
  mv "$F" "$DIR/logs-$(date +%s).json"
  # Only if it is actually running. `systemctl restart` STARTS a stopped
  # unit, so an unguarded call here would silently resurrect the baseline
  # on every rotation after it was retired.
  systemctl is-active --quiet loggen-baseline && systemctl restart loggen-baseline
fi

# The benign host stream, written by cc-emit.js --daemon. Nothing else covers
# this file, and an uncovered append-only file on this image has already gone
# wrong twice: 2.5 GB of logs.json, and 54,609 logs_*.jsonl entries that stalled
# guest-exec on an idle box.
#
# No `systemctl restart` here, unlike the baseline above. log-generator holds its
# file handle open across a rename, so it has to be restarted to notice. The
# emitter appends with fs.appendFileSync, which reopens by path on every line --
# chosen for SIGTERM safety -- so a renamed host.json is simply recreated on the
# next write, with no gap and no lost events.
H="$DIR/host.json"
if [ -f "$H" ]; then
  HSZ="$(stat -c %s "$H" 2>/dev/null || echo 0)"
  case "$HSZ" in ''|*[!0-9]*) HSZ=0 ;; esac
  if [ "$HSZ" -ge "$MAX" ]; then
    mv "$H" "$DIR/host-$(date +%s).json"
  fi
fi

# Reap UNCONDITIONALLY, outside both size checks.
#
# These two lines used to sit inside the `if size >= MAX` blocks above, so an
# already-rotated file was only cleaned up when the NEXT rotation happened. That
# is a cleanup gated behind an event that may never come: once the live file sits
# below the threshold, nothing reaps, and every previously rotated file stays
# forever.
#
# Measured on a lane after eight days: 17 rotated files, 4.6 GB, on a 10 GB disk
# -- while host.json itself was only 157 MB and therefore never triggered another
# rotation to trip the cleanup. The attack wrapper then refused every run with
# "nospace" on a box that nothing was actively filling.
#
# It went unnoticed for as long as it did because the benign baseline used to
# produce ~35 MB/day. At the current ~800 MB/day it fills a 10 GB root in under a
# week, which is the difference between a latent bug and a weekly outage.
find "$DIR" -maxdepth 1 -name 'logs-*.json' -mmin "+$GRACE_MIN" -delete 2>/dev/null || true
find "$DIR" -maxdepth 1 -name 'host-*.json' -mmin "+$GRACE_MIN" -delete 2>/dev/null || true
exit 0
LOGGEN_ROTATE_EOF
sh -n "$ROTATE_TMP" || { echo "ERROR: loggen-rotate.sh failed syntax check" >&2; exit 1; }
LOGGEN_ROTATE_B64="$(base64 -w0 "$ROTATE_TMP")"
rm -f "$ROTATE_TMP"

# ---- BEGIN GENERATED PAYLOADS (sync_bake.py) ----
# cc-emit.js and host-baseline.json, embedded verbatim.
#
# The bake runs on a Proxmox node with no checkout, so the engine cannot be read
# from the repo the way attack-runner.js reads cc-attack.sh. Quoted heredocs, so
# every $, backtick and backslash in the JavaScript survives untouched, then
# base64 into cloud-init exactly like the other helpers.
#
# GENERATED. Do not edit between these markers -- run scripts/sync-bake-payloads
# and let bake-payloads.test.js prove the copies still match.

EMIT_TMP="$(mktemp)"
cat > "$EMIT_TMP" <<'CC_EMIT_EOF'
#!/usr/bin/env node
/* eslint-disable no-console */
// ============================================================================
// cc-emit.js — CYBR 400 attack telemetry emitter
// ----------------------------------------------------------------------------
// Writes technique-appropriate synthetic log events from a declarative playbook.
// Staged onto the lane by attack-runner.js on every dispatch, exactly like
// cc-attack.sh, so a guest can never run a stale copy. Do not edit on the guest.
//
// WHY THIS EXISTS
//   log-generator's --mitre-technique is a FILTER, not a simulator. It runs all
//   twelve generators at their configured rates and tags the lines whose message
//   text happens to match a keyword. Measured on a deployed lane, one T1005 run
//   wrote 37,004 lines of which 76 carried the technique -- 30,571 of them
//   API-gateway records from api.example.com. T1005 is "read files off a local
//   host". No filter over API gateway logs can represent that, and log-generator
//   has no process, file or registry source to filter in the first place.
//
// THE ENVELOPE IS NOT NEGOTIABLE
//   Output must be byte-compatible with log-generator's ND-JSON, because three
//   things downstream key off it and none of them fail loudly:
//     * the agent drops any attack event lacking `loggen.mitre.technique` (that
//       path exists only because the ndjson parser uses target: loggen)
//     * the dashboard's terms panels read loggen.source.{type,host} / .level
//     * the component template types ONLY loggen.{timestamp,level,message,
//       metadata,source.*,mitre.*}. Anything else falls to dynamic mapping under
//       ecs@mappings, where a name like `source.ip` gets typed `ip` and then
//       REJECTS every document whose value is not an address -- silently, with a
//       healthy agent and no error the console can see.
//   So: six top-level keys, never more. Extra structure goes under metadata.
//
// METADATA VALUES ARE ALL STRINGS
//   loggen.metadata is mapped `flattened`, so nothing in it can be summed or
//   range-queried in Lens. Quantities belong in the message text, which is what
//   real logs do anyway.
// ============================================================================
'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Deterministic RNG, seeded from the RUN ID.
//
// Every lane in a class runs the same run id, so every student sees the SAME
// attack: the instructor can say "there are 412 events, find them" and be right
// on all thirty machines. Unseeded randomness would silently turn one exercise
// into thirty different ones, and a retried lane would not match the other 29.
// ---------------------------------------------------------------------------
function makeRng(seed) {
  let a = (seed >>> 0) || 0x9e3779b9;
  return function rng() {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** FNV-1a over a string — turns a run UUID into a usable 32-bit seed. */
function seedFrom(str) {
  let h = 0x811c9dc5;
  const s = String(str || '');
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * Business rhythm.
 *
 * A dead-flat 24/7 histogram is the single most obvious synthetic tell there is
 * -- more obvious than volume, more obvious than field values. Real enterprise
 * telemetry has a shape: it climbs from about 07:00, peaks mid-morning, dips at
 * lunch, tails off after 18:00, and drops to a floor of batch jobs and
 * monitoring overnight. Weekends run at a fraction of a weekday.
 *
 * It also carries pedagogy that nothing else does. "Unusual hour" is a real
 * signal an analyst uses constantly, and it only exists if the ordinary hours
 * look ordinary. On a flat baseline, 03:00 means nothing.
 *
 * Applied to the benign daemon only. An instructor fires an attack whenever
 * they fire it; if that happens to be against the overnight floor it stands out
 * more, which is exactly true of real intrusions.
 */
function intensityAt(rhythm, date) {
  if (!rhythm) return 1;
  const offset = Number(rhythm.utc_offset || 0);
  const local = new Date(date.getTime() + offset * 3600 * 1000);
  const hour = local.getUTCHours();
  const day = local.getUTCDay(); // 0 Sun .. 6 Sat

  const curve = Array.isArray(rhythm.hourly) && rhythm.hourly.length === 24 ? rhythm.hourly : null;
  let factor = curve ? Number(curve[hour]) : 1;
  if (!Number.isFinite(factor) || factor < 0) factor = 1;

  if ((day === 0 || day === 6) && rhythm.weekend != null) {
    const w = Number(rhythm.weekend);
    if (Number.isFinite(w) && w >= 0) factor *= w;
  }
  return factor;
}

/**
 * One of a step's message templates, weighted.
 *
 * Without this a step emits one sentence over and over, and a benign stream
 * built from 25 such steps reads as 25 sentences on a loop — which is its own
 * kind of obviously-synthetic, just a different kind from a flat histogram.
 * Real sources say several things: nginx serves 200s and 404s and the odd 500,
 * sshd accepts keys and passwords and rejects some, postgres runs queries and
 * checkpoints and autovacuums.
 *
 * A template may override level and metadata as well as the message, because a
 * 500 is not an INFO and a failed logon is not a success.
 */
function pickTemplate(rng, step) {
  const t = step.templates;
  if (!Array.isArray(t) || !t.length) return step;
  let total = 0;
  for (const x of t) total += Number(x.weight) || 1;
  let r = rng() * total;
  for (const x of t) {
    r -= Number(x.weight) || 1;
    if (r <= 0) return x;
  }
  return t[t.length - 1];
}

const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];

/**
 * Sample a pool with a long tail instead of uniformly.
 *
 * Uniform sampling is the wrong shape for an estate. Measured on the flat
 * version: 48 addresses each appeared 377-463 times in a day, 9 accounts each
 * 11,458-11,848. Nothing was rare, so nothing could stand out by being rare --
 * and "read the bottom of the distribution, not the top" is the single most
 * useful habit a hunting exercise can build.
 *
 * Squaring a uniform draw concentrates it near the front of the list, so a pool
 * is read as roughly most-common-first and the entries at the end are genuinely
 * uncommon. Cheap, needs no per-entry weights, and the exponent is the only
 * knob: higher means a steeper head and a longer tail.
 */
const SKEW_EXPONENT = 2.2;

function pickSkewed(rng, arr) {
  const i = Math.floor(arr.length * Math.pow(rng(), SKEW_EXPONENT));
  return arr[Math.min(i, arr.length - 1)];
}
const randInt = (rng, lo, hi) => lo + Math.floor(rng() * (hi - lo + 1));

/** FNV-1a, reused to map a value onto a pool index deterministically. */
function poolIndexFor(str, len) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0) % len;
}

/**
 * Resolve a pool reference, honouring bindings.
 *
 * A BOUND pool is not sampled -- it is DERIVED from another pool's value, so
 * the same account always resolves to the same workstation address. Without
 * this, every pool draw is independent and the estate has no people in it: one
 * address shows thirty-five different accounts failing to log in, which is not
 * a workstation, it is a shuffle.
 *
 * The cost of getting this wrong is not just realism. "Many accounts, one
 * source" is the signature of a password spray, and on independently-sampled
 * pools that signature fits ordinary traffic BETTER than it fits the attack --
 * so a student who learns it would be led away from the answer every time.
 *
 * Derivation is by hash rather than by index so that adding an account to the
 * middle of the pool does not reshuffle everyone else's desk.
 */
function samplePool(key, ctx, rng, depth) {
  if (Object.prototype.hasOwnProperty.call(ctx.sampled, key)) return ctx.sampled[key];

  const bound = ctx.bindings && ctx.bindings[key];
  let value;
  if (bound && (depth || 0) < 4) {
    const pool = ctx.pools[bound.pool];
    if (!Array.isArray(pool) || !pool.length) return null;
    const driver = samplePool(bound.by, ctx, rng, (depth || 0) + 1);
    if (driver == null) return null;
    value = String(pool[poolIndexFor(`${bound.by}:${driver}`, pool.length)]);
  } else {
    const pool = ctx.pools[key];
    if (!Array.isArray(pool) || !pool.length) return null;
    value = String(ctx.skewed && ctx.skewed.has(key) ? pickSkewed(rng, pool) : pick(rng, pool));
  }
  ctx.sampled[key] = value;
  return value;
}

// ---------------------------------------------------------------------------
// Duration parsing — the SAME grammar loggen-catalog.js formatDuration() emits.
// The wrapper only ever holds the formatted string in $DUR; resolveSelection()
// never passes a seconds form down.
// ---------------------------------------------------------------------------
const DURATION_RE = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/;

function parseDuration(value) {
  const raw = String(value == null ? '' : value).trim();
  if (raw === '') return 0;
  if (/^\d+$/.test(raw)) return Number(raw);
  const m = DURATION_RE.exec(raw);
  if (!m || (!m[1] && !m[2] && !m[3])) {
    throw new Error(`cc-emit: unparseable duration ${JSON.stringify(value)}`);
  }
  return Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0);
}

// ---------------------------------------------------------------------------
// Entities resolve ONCE per run; pools are sampled per event.
//
// A run has to read as one adversary doing one thing: the same source IP across
// 180 failed logons, the same account in the success that follows. log-generator
// randomises every field of every line independently, which is why its output
// cannot be pivoted through and reads as noise even when the volume is right.
// ---------------------------------------------------------------------------
function resolveEntities(playbook, rng) {
  const out = {};
  for (const [key, spec] of Object.entries(playbook.entities || {})) {
    if (typeof spec === 'string' || typeof spec === 'number') {
      out[key] = String(spec);
    } else if (spec && Array.isArray(spec.oneOf)) {
      out[key] = String(pick(rng, spec.oneOf));
    } else if (spec && typeof spec.ipv4Host === 'string') {
      out[key] = `${spec.ipv4Host}.${randInt(rng, 2, 254)}`;
    } else {
      throw new Error(`cc-emit: unsupported entity spec for ${key}`);
    }
  }
  return out;
}

const TOKEN_RE = /\{\{([a-zA-Z0-9_]+)(?:\.(\d+))?(?::(\d+)-(\d+))?\}\}/g;

function expand(template, ctx, rng, seq, depth) {
  if (typeof template !== 'string') return template;
  const out = expandOnce(template, ctx, rng, seq);
  // Pool values may themselves contain tokens -- "/home/{{users}}/notes.md" is
  // the natural way to write a per-user path. Re-expand until stable, bounded so
  // a self-referential pool cannot spin. Leaving it at one pass ships literal
  // "{{users}}" to Kibana, which is exactly the "{clientIP}" tell log-generator
  // has at this commit and the thing this emitter exists to avoid.
  if (out !== template && /\{\{/.test(out) && (depth || 0) < 3) {
    return expand(out, ctx, rng, seq, (depth || 0) + 1);
  }
  return out;
}

function expandOnce(template, ctx, rng, seq) {
  return template.replace(TOKEN_RE, (whole, key, idx, lo, hi) => {
    if (key === 'rand' && lo != null) return String(randInt(rng, Number(lo), Number(hi)));
    if (key === 'port') return String(randInt(rng, 32768, 60999));
    if (key === 'pid') return String(randInt(rng, 400, 32000));
    if (key === 'seq') return String(seq);
    if (Object.prototype.hasOwnProperty.call(ctx.entities, key)) return ctx.entities[key];
    // An explicit index reads the pool directly: {{users.0}} means "that one",
    // not "one of these", so neither sampling nor binding applies.
    const direct = ctx.pools[key];
    if (idx != null && Array.isArray(direct) && direct.length) {
      return String(direct[Number(idx) % direct.length]);
    }
    // Sampled ONCE per event, then reused. Sampling per occurrence makes an
    // event contradict itself -- "Failed password for jsmith" carrying
    // metadata.user=svc_backup -- so a student pivoting on the structured
    // field gets a different answer than one reading the message. Both are
    // wrong, and nothing about the data says which.
    const sampled = samplePool(key, ctx, rng, 0);
    if (sampled != null) return sampled;
    // Left intact rather than "undefined". log-generator itself ships literal
    // "{clientIP}" in its metadata at this commit, and that is exactly the tell
    // we must not reproduce -- an unresolved token fails a unit test instead.
    return whole;
  });
}

function expandDeep(value, ctx, rng, seq) {
  if (typeof value === 'string') return expand(value, ctx, rng, seq);
  if (Array.isArray(value)) return value.map((v) => expandDeep(v, ctx, rng, seq));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = expandDeep(v, ctx, rng, seq);
    return out;
  }
  return value == null ? value : String(value);
}

// ---------------------------------------------------------------------------
// Timeline: RIGID bursts, ELASTIC dwell.
//
// This is the part that must not be a single uniform scale factor. A brute force
// is 200 attempts in 40 seconds. Stretch that uniformly to the console's 2-hour
// option and it becomes one attempt every 36 seconds -- not a brute force, no
// threshold rule will fire on it, and it is indistinguishable from the
// baseline's own authentication generator at 10/min. The exercise evaporates
// precisely for the techniques it matters most for.
//
// So each step has two independent parts:
//   spread  RIGID   how long the burst itself takes. Never scaled.
//   gap     ELASTIC dwell before the step. Absorbs all of the scaling.
//
// requested = sum(spread) + scaled(sum(gap)). Longer runs mean an adversary who
// waits longer between phases, which is what a longer intrusion actually looks
// like -- not one who types more slowly.
//
// If the rigid floor alone exceeds the requested duration the run REFUSES rather
// than compressing a burst into something physically absurd.
// ---------------------------------------------------------------------------
/**
 * Where each step starts, for a given dwell scale.
 *
 * Split out because the rigid floor cannot be computed arithmetically once
 * `overlap` exists: overlapping steps share wall-clock, so summing their spreads
 * over-counts. Laying the steps out at gapScale=0 gives the true floor whatever
 * the overlap topology, and the layout is monotonic in gapScale, so the scale
 * that lands the run on the requested duration can be solved for directly.
 */
function layout(steps, gapScale) {
  const starts = [];
  let cursor = 0;
  let prevStart = 0;
  for (const step of steps) {
    const gap = parseDuration(step.gap || '0s') * gapScale;
    const spread = parseDuration(step.spread || '0s');
    // overlap: run alongside the previous phase rather than after it. An
    // adversary does not politely finish discovery before starting collection,
    // and the benign host baseline's activity types all happen at once.
    const start = step.overlap ? prevStart + gap : cursor + gap;
    starts.push(start);
    prevStart = start;
    cursor = Math.max(cursor, start + spread);
  }
  return { starts, end: cursor };
}

function planTimeline(playbook, opts) {
  const rng = opts.rng;
  const steps = playbook.steps || [];
  if (!steps.length) throw new Error('cc-emit: playbook has no steps');

  const nominal = Number(playbook.nominal_seconds);
  if (!Number.isFinite(nominal) || nominal <= 0) {
    throw new Error('cc-emit: playbook nominal_seconds must be a positive number');
  }

  const requested = opts.requested == null ? nominal : opts.requested;
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new Error('cc-emit: requested duration must be a positive number');
  }

  const rigidTotal = layout(steps, 0).end;
  if (requested < rigidTotal) {
    throw new Error(
      `cc-emit: playbook needs at least ${Math.round(rigidTotal)}s of burst time `
      + `but was asked for ${Math.round(requested)}s`
    );
  }

  // Solve for the dwell scale that lands the run exactly on the requested
  // duration. Bisection rather than division because overlap makes the
  // relationship piecewise-linear -- monotonic, so this converges in ~40 steps.
  let gapScale = 0;
  if (layout(steps, 1).end < requested || layout(steps, 1).end > requested) {
    let lo = 0;
    let hi = 1;
    while (layout(steps, hi).end < requested && hi < 1e6) hi *= 2;
    for (let i = 0; i < 60; i += 1) {
      const mid = (lo + hi) / 2;
      if (layout(steps, mid).end < requested) lo = mid; else hi = mid;
    }
    gapScale = (lo + hi) / 2;
  }

  const { starts } = layout(steps, gapScale);
  const entities = resolveEntities(playbook, rng);
  const pools = playbook.pools || {};
  // Pools listed here are sampled with a long tail rather than uniformly.
  const skewed = new Set(playbook.skewed || []);
  // Derived pools: same account, same desk. See samplePool().
  const bindings = playbook.bindings || {};

  const events = [];

  for (let si = 0; si < steps.length; si += 1) {
    const step = steps[si];
    const spread = parseDuration(step.spread || '0s');
    const start = starts[si];
    // Intensity scales the COUNT, not the timing: a quiet hour means fewer
    // people doing things, not the same people doing them slower.
    const intensity = opts.intensity == null ? 1 : opts.intensity;
    const count = Math.round(Math.max(1, Number(step.count || 1)) * intensity);
    if (count < 1) continue; // an hour too quiet for this activity at all
    const technique = step.technique || playbook.technique || null;
    const tactic = step.tactic || playbook.tactic || null;

    for (let i = 0; i < count; i += 1) {
      // Jittered, not evenly spaced. A perfectly uniform interval is the single
      // most obvious synthetic tell there is, and real tooling is bursty.
      const frac = count === 1 ? 0 : i / (count - 1);
      const slot = spread / Math.max(count, 1);
      const jitter = spread > 0 ? (rng() - 0.5) * slot : 0;
      const seq = i + 1;
      const src = step.source || {};
      const tpl = pickTemplate(rng, step);
      // Fresh sample cache per event: pool draws are consistent WITHIN one
      // event and vary BETWEEN them, which is what a spray from one host
      // against many accounts actually looks like.
      const ctx = { entities, pools, skewed, bindings, sampled: {} };
      events.push({
        // Clamped to the requested window. Jitter on the final event of a step
        // can otherwise push it a few seconds past the deadline, and
        // attack-worker schedules its finishing poll off expected_finish_at --
        // an event landing after that is one the run gets no credit for.
        offset: Math.min(requested, Math.max(0, start + frac * spread + jitter)),
        level: tpl.level || step.level || 'INFO',
        source: {
          type: expand(src.type || 'server', ctx, rng, seq),
          name: expand(src.name || 'unknown', ctx, rng, seq),
          host: expand(src.host || 'localhost', ctx, rng, seq),
        },
        message: expand(tpl.message || step.message || '', ctx, rng, seq),
        // Template metadata MERGES over the step's rather than replacing it, so a
        // template only has to state what differs -- outcome=failure on the one
        // that failed -- instead of repeating every shared field and drifting.
        metadata: expandDeep(
          Object.assign({}, step.metadata || {}, tpl.metadata || {}), ctx, rng, seq
        ),
        technique,
        tactic,
        subtechnique: step.subtechnique || playbook.subtechnique || null,
      });
    }
  }

  events.sort((a, b) => a.offset - b.offset);
  return { events, entities, rigidTotal, requested, gapScale };
}

// ---------------------------------------------------------------------------
// The wire format. Matches log-generator's writer field for field.
// ---------------------------------------------------------------------------
function toLine(event, whenMs) {
  const doc = {
    timestamp: new Date(whenMs).toISOString(),
    level: event.level,
    source: event.source,
    message: event.message,
    metadata: event.metadata,
  };
  // Only tag when there IS a technique. The benign host baseline leaves most of
  // its events untagged, so that mitre.technique:* stays useless as an oracle
  // inside the host source too.
  if (event.technique) {
    doc.mitre = {
      technique: event.technique,
      tactic: event.tactic || null,
      subtechnique: event.subtechnique || null,
    };
  }
  return JSON.stringify(doc) + '\n';
}

// ---------------------------------------------------------------------------
// Writer.
//
// One writeSync of one newline-terminated line onto an O_APPEND fd. Linux
// serialises appends under i_rwsem, so two concurrent runs on one lane -- which
// migration 006 explicitly designs for, excluding only 'dispatching' from the
// mutex -- never interleave WITHIN a line. A buffered stream would split a
// logical line at a buffer boundary and splice two events into invalid JSON that
// the agent's parser then rejects.
//
// Synchronous also means nothing is lost when `timeout -k 30` escalates to
// SIGKILL, which is why this file registers no SIGTERM handler at all.
// ---------------------------------------------------------------------------
function openAppend(outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  // Repair a torn tail before appending. An aborted run can leave a partial
  // line; without this the next run's first event is glued onto it, producing
  // one invalid line with no mitre.technique that drop_event eats silently --
  // two events gone with no trace.
  try {
    const st = fs.statSync(outPath);
    if (st.size > 0) {
      const fd0 = fs.openSync(outPath, 'r');
      const buf = Buffer.alloc(1);
      fs.readSync(fd0, buf, 0, 1, st.size - 1);
      fs.closeSync(fd0);
      if (buf[0] !== 0x0a) fs.appendFileSync(outPath, '\n', 'utf8');
    }
  } catch (e) { /* file does not exist yet */ }
  return fs.openSync(outPath, 'a');
}

/**
 * Rotate the output if it has grown past the cap.
 *
 * Nothing else covers this file: loggen-rotate.sh's size branch is hardcoded to
 * the BASELINE directory, and the wrapper's `-mtime +7` reaper never fires on a
 * file that is appended to continuously. Safe to do here precisely because the
 * emitter is short-lived and no daemon holds the fd -- unlike log-generator,
 * which is why the baseline's rotation needs a systemctl restart.
 *
 * Renames INTO the agent's *.json glob so filestream finishes the old file.
 */
function rotateIfLarge(outPath, maxBytes, nowMs) {
  try {
    const st = fs.statSync(outPath);
    if (st.size >= maxBytes) {
      fs.renameSync(outPath, `${outPath.replace(/\.json$/, '')}-${Math.floor(nowMs / 1000)}.json`);
    }
  } catch (e) { /* nothing to rotate */ }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Emit a planned timeline.
 *
 * Scheduling is against a MONOTONIC base, never wall-clock. The wrapper's own
 * header documents that these guests' clocks are not trustworthy -- the lane
 * gateway may not forward NTP and Proxmox only syncs guest RTC on resume. A
 * chrony step backwards would stall a wall-clock scheduler until the hard cap
 * fired (rc=124, reported to the class as "hit the hard runtime cap"); a step
 * forwards, or a VM suspend/resume, would dump every missed event at once.
 */
async function emit(plan, opts) {
  const fd = openAppend(opts.out);
  const base = process.hrtime.bigint();
  const elapsedS = () => Number(process.hrtime.bigint() - base) / 1e9;

  let written = 0;
  const report = () => {
    if (!opts.countFile) return;
    try {
      fs.writeFileSync(`${opts.countFile}.tmp`, String(written), 'utf8');
      fs.renameSync(`${opts.countFile}.tmp`, opts.countFile);
    } catch (e) { /* the count is a convenience, never a reason to fail a run */ }
  };

  try {
    for (const ev of plan.events) {
      // Capped sleeps so a SIGKILL-less abort still lands promptly, and so a
      // long dwell does not sit in one enormous timer (delays over 2^31-1 ms
      // fire immediately in Node, which would burst the whole playbook).
      let guard = 0;
      while (elapsedS() < ev.offset && guard < 10_000_000) {
        await sleep(Math.min((ev.offset - elapsedS()) * 1000, 1000));
        guard += 1;
      }
      fs.writeSync(fd, toLine(ev, Date.now()));
      written += 1;
      if (written % 25 === 0) report();
    }
  } finally {
    report();
    try { fs.closeSync(fd); } catch (e) { /* already gone */ }
  }
  return written;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) { out[key] = next; i += 1; } else { out[key] = true; }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.playbook || !args.out) {
    console.error('usage: cc-emit.js --playbook <f> --out <f> [--duration 30m] [--run-id ID] [--daemon] [--count-file <f>] [--max-bytes N]');
    process.exit(2);
  }

  let playbook;
  try {
    playbook = JSON.parse(fs.readFileSync(args.playbook, 'utf8'));
  } catch (err) {
    console.error(`cc-emit: unreadable playbook: ${err.message}`);
    process.exit(3);
  }

  const maxBytes = Number(args['max-bytes'] || 268435456);
  rotateIfLarge(args.out, maxBytes, Date.now());

  // Seeded from the run id so every lane in the class emits an identical
  // attack. --seed exists for tests.
  const seed = args.seed ? Number(args.seed) : seedFrom(args['run-id'] || playbook.technique || 'cybr400');

  if (args.daemon) {
    // The benign host stream. Re-seeds each cycle so hosts and accounts drift
    // the way a real estate does rather than one machine looping forever.
    let s = seed;
    for (;;) {
      rotateIfLarge(args.out, maxBytes, Date.now());
      // Recomputed every cycle so the curve moves through the day on its own.
      const intensity = intensityAt(playbook.rhythm, new Date());
      const plan = planTimeline(playbook, {
        rng: makeRng(s),
        requested: playbook.nominal_seconds,
        intensity,
      });
      await emit(plan, { out: args.out });
      s = (s + 0x9e3779b9) >>> 0;
    }
  }

  // A bare --duration with no value means "run the playbook's own length", and
  // that is the CHAIN case, not a mistake: resolveSelection gives chains
  // duration:'' on purpose, because a chain runs its scripted length rather
  // than one the instructor picks. parseArgs turns a valueless flag into the
  // boolean true, so testing truthiness alone sends  to parseDuration and
  // throws -- every chain run exiting 4 with lines=0.
  const durArg = typeof args.duration === 'string' ? args.duration.trim() : '';
  let plan;
  try {
    // parseDuration lives INSIDE the try on purpose. Outside it, a bad duration
    // propagated to main().catch and exited 1 -- indistinguishable from any
    // other crash, and the console reported the generic failure rather than
    // "the playbook could not be planned".
    const requested = durArg ? parseDuration(durArg) : Number(playbook.nominal_seconds);
    plan = planTimeline(playbook, { rng: makeRng(seed), requested });
  } catch (err) {
    console.error(String(err.message).startsWith('cc-emit:') ? err.message : `cc-emit: ${err.message}`);
    process.exit(4);
  }

  const written = await emit(plan, {
    out: args.out,
    countFile: args['count-file'] || null,
  });
  console.log(`cc-emit: wrote ${written} event(s) over ${Math.round(plan.requested)}s `
    + `(rigid ${Math.round(plan.rigidTotal)}s, dwell x${plan.gapScale.toFixed(2)}, seed ${seed})`);
  process.exit(0);
}

/**
 * The shortest duration a playbook can honestly run in — the sum of its rigid
 * bursts once overlap is accounted for.
 *
 * The console must not offer a duration below this. Asking for 5 minutes of a
 * beacon whose whole point is 10 minutes of regular check-ins has no honest
 * answer: compress it and it is not a beacon, truncate it and half the story is
 * missing. Refusing is the only correct behaviour, so the picker disables the
 * option rather than letting the instructor discover it lane by lane.
 */
function minSecondsFor(playbook) {
  return Math.ceil(layout(playbook.steps || [], 0).end);
}

module.exports = {
  makeRng,
  seedFrom,
  parseDuration,
  resolveEntities,
  intensityAt,
  pickTemplate,
  pickSkewed,
  samplePool,
  poolIndexFor,
  layout,
  minSecondsFor,
  expand,
  expandDeep,
  planTimeline,
  toLine,
  openAppend,
  rotateIfLarge,
  emit,
  DURATION_RE,
};

// No SIGTERM/SIGINT handler, deliberately. Abort is `kill -TERM -$PGID` and the
// hard cap is `timeout -k 30`; Node's default terminates immediately, which is
// what makes both work. A handler doing async flush work can outlive the 30s
// grace and be SIGKILLed mid-write -- the torn-line case openAppend() repairs.
// Synchronous appends leave nothing to flush, so a handler buys nothing and
// risks exactly the corruption it would appear to prevent.

if (require.main === module) {
  main().catch((err) => { console.error(`cc-emit: ${err && err.message}`); process.exit(1); });
}
CC_EMIT_EOF
CC_EMIT_B64="$(base64 -w0 "$EMIT_TMP")"
rm -f "$EMIT_TMP"

HOST_PB_TMP="$(mktemp)"
cat > "$HOST_PB_TMP" <<'HOST_PB_EOF'
{
  "name": "Benign activity",
  "story": "An ordinary working week across the estate: sessions, queries, requests, packages, jobs.",
  "nominal_seconds": 300,
  "entities": {},
  "pools": {
    "srvpool": [
      "srv-prod-01",
      "app-server-01",
      "db-01",
      "web-01",
      "fileserv-01",
      "srv-prod-02",
      "app-server-02",
      "web-02",
      "build-01",
      "monitor-01",
      "backup-01",
      "db-02",
      "cache-01",
      "fileserv-02"
    ],
    "wspool": [
      "ws-042",
      "ws-071",
      "ws-113",
      "ws-128",
      "ws-014",
      "ws-025",
      "ws-033",
      "ws-058",
      "ws-066",
      "ws-081",
      "ws-094",
      "ws-107",
      "ws-119",
      "ws-133",
      "ws-146",
      "ws-152",
      "ws-168",
      "ws-171",
      "ws-185",
      "ws-196"
    ],
    "fwpool": [
      "firewall-01"
    ],
    "dbpool": [
      "db-01"
    ],
    "webpool": [
      "web-01",
      "app-server-01"
    ],
    "authpool": [
      "auth-01"
    ],
    "mailpool": [
      "app-server-01"
    ],
    "apppool": [
      "app-server-01"
    ],
    "hosts": [
      "srv-prod-01",
      "app-server-01",
      "db-01",
      "web-01",
      "fileserv-01",
      "srv-prod-02",
      "app-server-02",
      "web-02",
      "build-01",
      "monitor-01",
      "backup-01",
      "db-02",
      "cache-01",
      "fileserv-02",
      "ws-042",
      "ws-071",
      "ws-113",
      "ws-128",
      "ws-014",
      "ws-025",
      "ws-033",
      "ws-058",
      "ws-066",
      "ws-081",
      "ws-094",
      "ws-107",
      "ws-119",
      "ws-133",
      "ws-146",
      "ws-152",
      "ws-168",
      "ws-171",
      "ws-185",
      "ws-196"
    ],
    "users": [
      "jsmith",
      "mrodriguez",
      "kchen",
      "apatel",
      "dwilson",
      "tnguyen",
      "rbaker",
      "lgarcia",
      "pokafor",
      "schen",
      "mhaddad",
      "jwalsh",
      "nsingh",
      "ecarter",
      "bmurphy",
      "yilmaz",
      "dkowalski",
      "aroy",
      "tfischer",
      "cnguyen",
      "hpatel",
      "mokonkwo",
      "rlindqvist",
      "kbrennan",
      "jdelacruz",
      "sabbas",
      "wzhang",
      "mtorres",
      "ldubois",
      "ahassan",
      "admin",
      "operator",
      "helpdesk",
      "helpdesk2",
      "jdoe",
      "rsmith",
      "backupsvc",
      "monitor01",
      "sysadm",
      "guest",
      "svc_backup",
      "svc_report",
      "svc_deploy",
      "svc_scan",
      "svc_sync"
    ],
    "cmds": [
      "ls -la",
      "git status",
      "npm run build",
      "docker ps",
      "kubectl get pods",
      "tail -f /var/log/messages",
      "vim notes.md",
      "python3 report.py",
      "systemctl status nginx",
      "df -h",
      "top -b -n1",
      "grep -r TODO src/",
      "make test",
      "ssh app-server-01",
      "scp report.csv backup:/srv/",
      "htop"
    ],
    "files": [
      "/home/{{users}}/notes.md",
      "/var/log/messages",
      "/etc/hosts",
      "/srv/app/config.yaml",
      "/home/{{users}}/.bashrc",
      "/etc/resolv.conf",
      "/srv/app/package.json",
      "/var/lib/pgsql/data/postgresql.conf",
      "{{docdirs}}/{{docs}}",
      "{{docdirs}}/{{docs}}"
    ],
    "docdirs": [
      "/home/shared/finance",
      "/home/shared/hr",
      "/srv/contracts",
      "/var/backups"
    ],
    "docs": [
      "q3-forecast.xlsx",
      "payroll-2026.csv",
      "msa-signed.pdf",
      "passwords.kdbx",
      "board-minutes.docx",
      "customer-export.csv"
    ],
    "pkgs": [
      "openssl",
      "curl",
      "nginx",
      "python3-pip",
      "containerd.io",
      "kernel",
      "git",
      "sudo",
      "systemd",
      "glibc"
    ],
    "svcs": [
      "nginx",
      "postgresql",
      "containerd",
      "chronyd",
      "sshd",
      "crond",
      "firewalld"
    ],
    "tbls": [
      "orders",
      "sessions",
      "audit_log",
      "products",
      "customers",
      "invoices",
      "employees",
      "contracts",
      "card_tokens",
      "payroll"
    ],
    "senders": [
      "github.com",
      "atlassian.net",
      "okta.com",
      "zoom.us",
      "docusign.net"
    ],
    "agents": [
      "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/127.0.0.0 Safari/537.36",
      "curl/8.6.0",
      "python-requests/2.32.3",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    ],
    "paths": [
      "/",
      "/login",
      "/dashboard",
      "/api/reports",
      "/api/search",
      "/static/app.js",
      "/favicon.ico",
      "/api/v1/orders"
    ],
    "sites": [
      "updates.example.com",
      "registry.npmjs.org",
      "download.rockylinux.org",
      "api.github.com",
      "login.okta.com"
    ],
    "lanips": [
      "10.20.30.11",
      "10.20.30.12",
      "10.20.30.13",
      "10.20.30.14",
      "10.20.30.15",
      "10.20.30.16",
      "10.20.30.17",
      "10.20.30.18",
      "10.20.30.19",
      "10.20.30.20",
      "10.20.30.21",
      "10.20.30.22",
      "10.20.30.23",
      "10.20.30.24",
      "10.20.30.25",
      "10.20.30.26",
      "10.20.30.27",
      "10.20.30.28",
      "10.20.30.29",
      "10.20.30.30",
      "10.20.30.31",
      "10.20.30.32",
      "10.20.30.33",
      "10.20.30.34",
      "10.20.30.35",
      "10.20.30.36",
      "10.20.30.37",
      "10.20.30.38",
      "10.20.30.39",
      "10.20.30.40",
      "10.20.30.41",
      "10.20.30.42",
      "10.20.30.43",
      "10.20.30.44",
      "10.20.30.45",
      "10.20.30.46",
      "10.20.30.47",
      "10.20.30.48",
      "10.20.30.49",
      "10.20.30.50",
      "10.20.30.51",
      "10.20.30.52",
      "10.20.30.53",
      "10.20.30.54",
      "10.20.30.55",
      "10.20.30.56",
      "10.20.30.57",
      "10.20.30.58",
      "10.20.30.59",
      "10.20.30.60",
      "10.20.30.61",
      "10.20.30.62",
      "10.20.30.63",
      "10.20.30.64",
      "10.20.30.65",
      "10.20.30.66",
      "10.20.30.67",
      "10.20.30.68",
      "10.20.30.69",
      "10.20.30.70",
      "10.20.31.11",
      "10.20.31.12",
      "10.20.31.13",
      "10.20.31.14",
      "10.20.31.15",
      "10.20.31.16",
      "10.20.31.17",
      "10.20.31.18",
      "10.20.31.19",
      "10.20.31.20",
      "10.20.31.21",
      "10.20.31.22",
      "10.20.31.23",
      "10.20.31.24",
      "10.20.31.25",
      "10.20.31.26",
      "10.20.31.27",
      "10.20.31.28",
      "10.20.31.29",
      "10.20.31.30",
      "10.20.31.31",
      "10.20.31.32",
      "10.20.31.33",
      "10.20.31.34",
      "10.20.31.35",
      "10.20.31.36",
      "10.20.31.37",
      "10.20.31.38",
      "10.20.31.39",
      "10.20.31.40",
      "10.20.31.41",
      "10.20.31.42",
      "10.20.31.43",
      "10.20.31.44",
      "10.20.31.45",
      "10.20.31.46",
      "10.20.31.47",
      "10.20.31.48",
      "10.20.31.49",
      "10.20.31.50",
      "10.20.31.51",
      "10.20.31.52",
      "10.20.31.53",
      "10.20.31.54",
      "10.20.31.55",
      "10.20.31.56",
      "10.20.31.57",
      "10.20.31.58",
      "10.20.31.59",
      "10.20.31.60",
      "10.20.31.61",
      "10.20.31.62",
      "10.20.31.63",
      "10.20.31.64",
      "10.20.31.65",
      "10.20.31.66",
      "10.20.31.67",
      "10.20.31.68",
      "10.20.31.69",
      "10.20.31.70",
      "10.20.32.11",
      "10.20.32.12",
      "10.20.32.13",
      "10.20.32.14",
      "10.20.32.15",
      "10.20.32.16",
      "10.20.32.17",
      "10.20.32.18",
      "10.20.32.19",
      "10.20.32.20",
      "10.20.32.21",
      "10.20.32.22",
      "10.20.32.23",
      "10.20.32.24",
      "10.20.32.25",
      "10.20.32.26",
      "10.20.32.27",
      "10.20.32.28",
      "10.20.32.29",
      "10.20.32.30",
      "10.20.32.31",
      "10.20.32.32",
      "10.20.32.33",
      "10.20.32.34",
      "10.20.32.35",
      "10.20.32.36",
      "10.20.32.37",
      "10.20.32.38",
      "10.20.32.39",
      "10.20.32.40",
      "10.20.32.41",
      "10.20.32.42",
      "10.20.32.43",
      "10.20.32.44",
      "10.20.32.45",
      "10.20.32.46",
      "10.20.32.47",
      "10.20.32.48",
      "10.20.32.49",
      "10.20.32.50",
      "10.20.32.51",
      "10.20.32.52",
      "10.20.32.53",
      "10.20.32.54",
      "10.20.32.55",
      "10.20.32.56",
      "10.20.32.57",
      "10.20.32.58",
      "10.20.32.59",
      "10.20.32.60",
      "10.20.32.61",
      "10.20.32.62",
      "10.20.32.63",
      "10.20.32.64",
      "10.20.32.65",
      "10.20.32.66",
      "10.20.32.67",
      "10.20.32.68",
      "10.20.32.69",
      "10.20.32.70",
      "10.20.33.11",
      "10.20.33.12",
      "10.20.33.13",
      "10.20.33.14",
      "10.20.33.15",
      "10.20.33.16",
      "10.20.33.17",
      "10.20.33.18",
      "10.20.33.19",
      "10.20.33.20",
      "10.20.33.21",
      "10.20.33.22",
      "10.20.33.23",
      "10.20.33.24",
      "10.20.33.25",
      "10.20.33.26",
      "10.20.33.27",
      "10.20.33.28",
      "10.20.33.29",
      "10.20.33.30",
      "10.20.33.31",
      "10.20.33.32",
      "10.20.33.33",
      "10.20.33.34",
      "10.20.33.35",
      "10.20.33.36",
      "10.20.33.37",
      "10.20.33.38",
      "10.20.33.39",
      "10.20.33.40",
      "10.20.33.41",
      "10.20.33.42",
      "10.20.33.43",
      "10.20.33.44",
      "10.20.33.45",
      "10.20.33.46",
      "10.20.33.47",
      "10.20.33.48",
      "10.20.33.49",
      "10.20.33.50",
      "10.20.33.51",
      "10.20.33.52",
      "10.20.33.53",
      "10.20.33.54",
      "10.20.33.55",
      "10.20.33.56",
      "10.20.33.57",
      "10.20.33.58",
      "10.20.33.59",
      "10.20.33.60",
      "10.20.33.61",
      "10.20.33.62",
      "10.20.33.63",
      "10.20.33.64",
      "10.20.33.65",
      "10.20.33.66",
      "10.20.33.67",
      "10.20.33.68",
      "10.20.33.69",
      "10.20.33.70"
    ],
    "dstips": [
      "10.20.40.11",
      "10.20.40.12",
      "10.20.40.13",
      "10.20.40.14",
      "10.20.40.15",
      "10.20.40.16",
      "10.20.40.17",
      "10.20.40.18",
      "10.20.40.19",
      "10.20.40.20",
      "10.20.40.21",
      "10.20.40.22",
      "10.20.40.23",
      "10.20.40.24",
      "10.20.40.25",
      "10.20.40.26",
      "10.20.40.27",
      "10.20.40.28",
      "10.20.40.29",
      "10.20.40.30",
      "10.20.40.31",
      "10.20.40.32",
      "10.20.40.33",
      "10.20.40.34",
      "10.20.40.35",
      "10.20.40.36",
      "10.20.40.37",
      "10.20.40.38",
      "10.20.40.39",
      "10.20.40.40",
      "10.20.40.41",
      "10.20.40.42",
      "10.20.40.43",
      "10.20.40.44",
      "10.20.40.45",
      "10.20.40.46",
      "10.20.40.47",
      "10.20.40.48",
      "10.20.40.49",
      "10.20.40.50",
      "10.20.40.51",
      "10.20.40.52",
      "10.20.40.53",
      "10.20.40.54",
      "10.20.40.55",
      "10.20.40.56",
      "10.20.40.57",
      "10.20.40.58",
      "10.20.40.59",
      "10.20.40.60",
      "10.20.40.61",
      "10.20.40.62",
      "10.20.40.63",
      "10.20.40.64",
      "10.20.40.65",
      "10.20.40.66",
      "10.20.40.67",
      "10.20.40.68",
      "10.20.40.69",
      "10.20.40.70"
    ],
    "extips": [
      "203.0.113.20",
      "203.0.113.21",
      "203.0.113.22",
      "203.0.113.23",
      "203.0.113.24",
      "203.0.113.25",
      "203.0.113.26",
      "203.0.113.27",
      "203.0.113.28",
      "203.0.113.29",
      "203.0.113.30",
      "203.0.113.31",
      "203.0.113.32",
      "203.0.113.33",
      "203.0.113.34",
      "203.0.113.35",
      "203.0.113.36",
      "203.0.113.37",
      "203.0.113.38",
      "203.0.113.39",
      "203.0.113.40",
      "203.0.113.41",
      "203.0.113.42",
      "203.0.113.43",
      "203.0.113.44",
      "203.0.113.45",
      "198.51.100.20",
      "198.51.100.21",
      "198.51.100.22",
      "198.51.100.23",
      "198.51.100.24",
      "198.51.100.25",
      "198.51.100.26",
      "198.51.100.27",
      "198.51.100.28",
      "198.51.100.29",
      "198.51.100.30",
      "198.51.100.31",
      "198.51.100.32",
      "198.51.100.33",
      "198.51.100.34",
      "198.51.100.35",
      "198.51.100.36",
      "198.51.100.37",
      "198.51.100.38",
      "198.51.100.39",
      "198.51.100.40",
      "198.51.100.41",
      "198.51.100.42",
      "198.51.100.43",
      "198.51.100.44",
      "198.51.100.45",
      "192.0.2.20",
      "192.0.2.21",
      "192.0.2.22",
      "192.0.2.23",
      "192.0.2.24",
      "192.0.2.25",
      "192.0.2.26",
      "192.0.2.27",
      "192.0.2.28",
      "192.0.2.29",
      "192.0.2.30",
      "192.0.2.31",
      "192.0.2.32",
      "192.0.2.33",
      "192.0.2.34",
      "192.0.2.35",
      "192.0.2.36",
      "192.0.2.37",
      "192.0.2.38",
      "192.0.2.39",
      "192.0.2.40",
      "192.0.2.41",
      "192.0.2.42",
      "192.0.2.43"
    ],
    "shares": [
      "\\\\fileserv-01\\finance",
      "\\\\fileserv-01\\hr"
    ]
  },
  "bindings": {
    "userips": {
      "pool": "lanips",
      "by": "users"
    }
  },
  "skewed": [
    "users",
    "hosts",
    "lanips",
    "dstips",
    "extips",
    "srvpool",
    "wspool",
    "cmds",
    "files",
    "paths",
    "sites"
  ],
  "rhythm": {
    "utc_offset": -7,
    "hourly": [
      0.14,
      0.11,
      0.1,
      0.1,
      0.12,
      0.2,
      0.45,
      0.8,
      1,
      1.05,
      1,
      0.85,
      0.7,
      0.95,
      1.05,
      1,
      0.85,
      0.6,
      0.42,
      0.32,
      0.26,
      0.22,
      0.18,
      0.15
    ],
    "weekend": 0.22
  },
  "steps": [
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 238,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "sshd",
        "host": "{{srvpool}}"
      },
      "templates": [
        {
          "message": "Accepted publickey for {{users}} from {{userips}} port {{port}} ssh2",
          "level": "INFO",
          "weight": 5
        },
        {
          "message": "Accepted password for {{users}} from {{userips}} port {{port}} ssh2",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "Failed password for {{users}} from {{userips}} port {{port}} ssh2",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "outcome": "failure"
          }
        },
        {
          "message": "Connection closed by authenticating user {{users}} {{userips}} port {{port}} [preauth]",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "pam_unix(sshd:session): session opened for user {{users}} by (uid=0)",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "Disconnected from user {{users}} {{userips}} port {{port}}",
          "level": "INFO",
          "weight": 3
        }
      ],
      "metadata": {
        "event_action": "logon-success",
        "user": "{{users}}",
        "src_ip": "{{userips}}",
        "service": "sshd",
        "outcome": "success"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 87,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "login",
        "host": "{{srvpool}}"
      },
      "templates": [
        {
          "message": "pam_unix(login:session): session opened for user {{users}} by LOGIN(uid=0)",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "pam_unix(login:session): session closed for user {{users}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "LOGIN ON tty{{rand:1-4}} BY {{users}}",
          "level": "INFO",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "session-opened",
        "user": "{{users}}",
        "service": "login",
        "outcome": "success"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 151,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "auth-svc",
        "host": "{{authpool}}"
      },
      "templates": [
        {
          "message": "Token validated for {{users}} scope=read ttl={{rand:300-3600}}s",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "Token issued for {{users}} client_id=svc-{{rand:1000-9999}} scope=read,write",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "Token refreshed for {{users}} ttl={{rand:300-3600}}s",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "MFA challenge passed for {{users}} method=totp",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "Token rejected for {{users}} reason=expired",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "outcome": "failure",
            "event_action": "logon-failed"
          }
        }
      ],
      "metadata": {
        "event_action": "logon-success",
        "user": "{{users}}",
        "service": "auth-svc",
        "outcome": "success"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 87,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "rdp",
        "host": "{{wspool}}"
      },
      "templates": [
        {
          "message": "Remote desktop session established user={{users}} src={{userips}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "Remote desktop session disconnected user={{users}} duration={{rand:120-9000}}s",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "Remote desktop reconnected user={{users}} src={{userips}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "Remote desktop session failed user={{users}} src={{userips}} reason=idle_timeout",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "error",
            "outcome": "failure"
          }
        }
      ],
      "metadata": {
        "event_action": "logon-success",
        "user": "{{users}}",
        "src_ip": "{{userips}}",
        "service": "rdp",
        "outcome": "success"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 22,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "useradd",
        "host": "{{authpool}}"
      },
      "templates": [
        {
          "message": "new user: name=contractor{{rand:10-99}}, UID={{rand:2000-2400}}, GID=100, home=/home/contractor{{rand:10-99}}, shell=/bin/bash",
          "level": "INFO",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "account-created",
        "user": "{{users}}",
        "target_user": "contractor",
        "service": "useradd"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 22,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "usermod",
        "host": "{{authpool}}"
      },
      "templates": [
        {
          "message": "add \"{{users}}\" to group \"developers\"",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "add \"{{users}}\" to group \"docker\"",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "unable to remove \"{{users}}\" from group \"developers\": not a member",
          "level": "WARN",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "group-modified",
        "user": "{{users}}",
        "target_user": "{{users}}",
        "service": "usermod"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 2898,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "iptables",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "ACCEPT IN=eth0 OUT=eth1 SRC={{lanips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=443 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 6
        },
        {
          "message": "ACCEPT IN=eth0 OUT=eth1 SRC={{lanips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=22 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "ACCEPT IN=eth0 OUT=eth1 SRC={{lanips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=5432 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "ACCEPT IN=eth0 OUT=eth1 SRC={{lanips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=UDP SPT={{port}} DPT=53 WINDOW={{rand:501-65535}} RES=0x00 LEN=64 URGP=0",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "DROP IN=eth0 OUT=eth1 SRC={{lanips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:52-64}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT={{rand:1-1024}} WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "event_action": "connection-blocked"
          }
        }
      ],
      "metadata": {
        "event_action": "connection-allowed",
        "src_ip": "{{lanips}}",
        "dst_ip": "{{dstips}}",
        "protocol": "tcp"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 290,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "firewalld",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "Configuration reload requested by uid=0 pid={{pid}}",
          "level": "INFO",
          "weight": 1,
          "metadata": {
            "event_action": "config-reload"
          }
        },
        {
          "message": "Zone public: interface eth0 bound",
          "level": "INFO",
          "weight": 1,
          "metadata": {
            "event_action": "zone-changed"
          }
        },
        {
          "message": "Rule added: zone=internal source=10.20.30.0/24 service=postgresql accept",
          "level": "INFO",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "rule-added",
        "service": "firewalld"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 869,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "netflow",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "Flow record: {{srvpool}} -> {{dstips}}:443 proto=TCP bytes={{rand:2000-400000}} packets={{rand:8-900}} duration={{rand:2-300}}s flags=.AP.SF",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "Flow record: {{wspool}} -> {{dstips}}:5432 proto=TCP bytes={{rand:900-90000}} packets={{rand:6-400}} duration={{rand:2-300}}s flags=.AP.SF",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "Flow record: {{srvpool}} -> {{dstips}}:53 proto=UDP bytes={{rand:80-900}} packets={{rand:1-6}} duration={{rand:1-3}}s flags=......",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "Flow export buffer full, {{rand:10-400}} records dropped",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "flow-record",
        "src_ip": "{{lanips}}",
        "dst_ip": "{{dstips}}",
        "protocol": "tcp"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 811,
      "level": "INFO",
      "source": {
        "type": "webserver",
        "name": "nginx-proxy",
        "host": "{{webpool}}"
      },
      "templates": [
        {
          "message": "{{lanips}} - - \"GET {{paths}} HTTP/1.1\" 200 {{rand:800-9000}} \"-\" \"{{agents}}\"",
          "level": "INFO",
          "weight": 8
        },
        {
          "message": "{{lanips}} - - \"POST /api/v1/orders HTTP/1.1\" 201 {{rand:120-900}} \"-\" \"{{agents}}\"",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "{{lanips}} - - \"GET {{paths}} HTTP/1.1\" 304 0 \"-\" \"{{agents}}\"",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "{{lanips}} - - \"GET {{paths}} HTTP/1.1\" 404 {{rand:120-600}} \"-\" \"{{agents}}\"",
          "level": "WARN",
          "weight": 2
        },
        {
          "message": "{{lanips}} - - \"GET /api/reports HTTP/1.1\" 500 {{rand:120-600}} \"-\" \"{{agents}}\"",
          "level": "ERROR",
          "weight": 1,
          "metadata": {
            "event_action": "error",
            "status": "500"
          }
        },
        {
          "message": "{{lanips}} - - \"GET /api/v1/orders HTTP/1.1\" 503 {{rand:120-600}} \"-\" \"{{agents}}\"",
          "level": "ERROR",
          "weight": 1,
          "metadata": {
            "event_action": "error",
            "status": "503"
          }
        }
      ],
      "metadata": {
        "event_action": "http-request",
        "src_ip": "{{lanips}}",
        "status": "200",
        "path": "{{paths}}",
        "user_agent": "{{agents}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 477,
      "level": "INFO",
      "source": {
        "type": "webserver",
        "name": "squid-proxy",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "{{wspool}} TCP_MISS/200 {{rand:400-90000}} GET https://{{sites}}/index - DIRECT/{{sites}} text/html",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "{{wspool}} TCP_HIT/200 {{rand:400-40000}} GET https://{{sites}}/static/app.js - NONE/- application/javascript",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "{{wspool}} TCP_MISS/204 0 POST https://{{sites}}/api/telemetry - DIRECT/{{sites}} -",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "{{wspool}} TCP_DENIED/403 {{rand:200-900}} CONNECT {{sites}}:443 - NONE/- text/html",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "connection-blocked",
            "status": "403"
          }
        }
      ],
      "metadata": {
        "event_action": "http-request",
        "src_ip": "{{lanips}}",
        "dst_ip": "{{dstips}}",
        "status": "200",
        "protocol": "tcp"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 72,
      "level": "INFO",
      "source": {
        "type": "server",
        "name": "nginx",
        "host": "{{webpool}}"
      },
      "templates": [
        {
          "message": "signal process started, worker process {{pid}} reloaded configuration",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "using inherited sockets from {{rand:3-9}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "*{{rand:1000-99999}} client closed connection while waiting for request",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "rate-limit"
          }
        },
        {
          "message": "*{{rand:1000-99999}} upstream timed out (110: Connection timed out) while reading response header from upstream",
          "level": "ERROR",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "config-reload",
        "service": "nginx"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 192,
      "level": "INFO",
      "source": {
        "type": "server",
        "name": "node-exporter",
        "host": "{{srvpool}}"
      },
      "templates": [
        {
          "message": "CPU usage: {{rand:4-38}}% memory: {{rand:20-60}}% disk: {{rand:30-70}}%",
          "level": "INFO",
          "weight": 6
        },
        {
          "message": "Load average: 0.{{rand:10-90}} 0.{{rand:10-90}} 0.{{rand:10-90}} procs={{rand:80-400}}",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "Filesystem /dev/mapper/rl-root at {{rand:40-72}}% of {{rand:40-200}}G",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "Memory usage above threshold: {{rand:82-90}}%",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "metric",
        "metric": "cpu",
        "service": "node-exporter"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 528,
      "level": "INFO",
      "source": {
        "type": "database",
        "name": "postgres-primary",
        "host": "{{dbpool}}"
      },
      "templates": [
        {
          "message": "duration: {{rand:2-180}}ms  statement: SELECT id, name FROM {{tbls}} WHERE updated_at > now() - interval '1 hour'",
          "level": "INFO",
          "weight": 6
        },
        {
          "message": "duration: {{rand:2-90}}ms  statement: INSERT INTO {{tbls}} (id, payload) VALUES ($1, $2)",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "duration: {{rand:2-240}}ms  statement: UPDATE {{tbls}} SET updated_at = now() WHERE id = $1",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "checkpoint starting: time",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "checkpoint complete: wrote {{rand:200-9000}} buffers ({{rand:1-9}}.{{rand:0-9}}%); sync={{rand:0-2}}.{{rand:100-999}} s",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "automatic vacuum of table \"public.{{tbls}}\": index scans: 1",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "could not receive data from client: Connection reset by peer",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "query",
        "user": "{{users}}",
        "table": "{{tbls}}",
        "service": "postgresql"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 28,
      "level": "INFO",
      "source": {
        "type": "email",
        "name": "mail-gateway",
        "host": "{{mailpool}}"
      },
      "templates": [
        {
          "message": "Message accepted for {{users}}@corp.example from noreply@{{senders}} size={{rand:2000-90000}}",
          "level": "INFO",
          "weight": 5
        },
        {
          "message": "Message delivered to {{users}}@corp.example queue={{rand:100000-999999}} delay={{rand:1-40}}s",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "Message rejected from bounce@{{senders}} reason=spf_softfail",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "outcome": "failure",
            "event_action": "error"
          }
        },
        {
          "message": "Greylisted sender {{senders}}, retry in 300s",
          "level": "INFO",
          "weight": 2
        }
      ],
      "metadata": {
        "event_action": "email-delivered",
        "user": "{{users}}",
        "service": "postfix",
        "outcome": "success"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 92,
      "level": "INFO",
      "source": {
        "type": "application",
        "name": "reporting-api",
        "host": "{{apppool}}"
      },
      "templates": [
        {
          "message": "export completed user={{users}} rows={{rand:20-800}} format=csv",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "report scheduled user={{users}} cron=0 6 * * 1 name=weekly-{{tbls}}",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "cache warm for {{tbls}} in {{rand:40-900}}ms",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "export failed user={{users}} reason=timeout after {{rand:30-120}}s",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "outcome": "failure",
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "export",
        "user": "{{users}}",
        "table": "{{tbls}}",
        "service": "reporting-api"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 61,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "cmd",
        "host": "{{wspool}}"
      },
      "templates": [
        {
          "message": "pid={{pid}} user={{users}} cmd=cmd.exe /c gpupdate /target:user",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "pid={{pid}} user={{users}} cmd=cmd.exe /c net use Z: {{shares}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "pid={{pid}} user={{users}} cmd=powershell.exe -File C:\\Scripts\\Inventory.ps1",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "pid={{pid}} user={{users}} cmd=cmd.exe /c net use Z: {{shares}} - exited 0x80070056",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}",
        "shell": "cmd.exe"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 49,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "registry",
        "host": "{{wspool}}"
      },
      "templates": [
        {
          "message": "SetValue HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Update\\LastCheck = {{rand:100000-999999}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "SetValue HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\LastUsed = {{rand:100000-999999}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "DeleteValue HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\setup{{rand:10-99}}",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "SetValue HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Start failed - access denied",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "registry-set",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 12,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "usermod",
        "host": "{{srvpool}}"
      },
      "templates": [
        {
          "message": "usermod: change user contractor{{rand:10-99}} shell to /bin/bash",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "usermod: user contractor{{rand:10-99}} is currently logged in, changes deferred",
          "level": "WARN",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "account-modified",
        "user": "{{users}}",
        "target_user": "contractor",
        "service": "usermod"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 12,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "sudoers",
        "host": "{{srvpool}}"
      },
      "templates": [
        {
          "message": "sudoers file syntax check passed (visudo -c)",
          "level": "INFO",
          "weight": 1
        },
        {
          "message": "visudo: /etc/sudoers.d/90-ops busy, try again later",
          "level": "WARN",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "sudoers-changed",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 290,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "iptables",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "ACCEPT IN=eth0 OUT=eth1 SRC={{srvpool}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={{rand:1-65535}} PROTO=TCP SPT={{port}} DPT={{rand:1-1024}} WINDOW=1024 RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "ACCEPT IN=eth0 OUT=eth1 SRC={{srvpool}} DST={{dstips}} LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={{rand:1-65535}} PROTO=TCP SPT={{port}} DPT=445 WINDOW=1024 RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 1
        }
      ],
      "metadata": {
        "event_action": "connection-allowed",
        "src_ip": "{{lanips}}",
        "dst_ip": "{{dstips}}",
        "protocol": "tcp",
        "service": "monitoring"
      },
      "technique": "T1046",
      "tactic": "TA0007"
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 72,
      "level": "INFO",
      "source": {
        "type": "webserver",
        "name": "nginx-proxy",
        "host": "{{webpool}}"
      },
      "templates": [
        {
          "message": "{{dstips}} - - \"GET /wp-login.php HTTP/1.1\" 404 {{rand:120-600}} \"-\" \"Mozilla/5.0 (compatible; Nmap Scripting Engine)\"",
          "level": "WARN",
          "weight": 3
        },
        {
          "message": "{{dstips}} - - \"GET /.env HTTP/1.1\" 404 {{rand:120-600}} \"-\" \"python-requests/2.32.3\"",
          "level": "WARN",
          "weight": 3
        },
        {
          "message": "{{dstips}} - - \"POST /cgi-bin/luci HTTP/1.1\" 404 {{rand:120-600}} \"-\" \"curl/8.6.0\"",
          "level": "WARN",
          "weight": 2
        },
        {
          "message": "{{dstips}} - - \"GET /admin/config.php HTTP/1.1\" 403 {{rand:120-600}} \"-\" \"Mozilla/5.0 (compatible; Nmap Scripting Engine)\"",
          "level": "WARN",
          "weight": 2
        }
      ],
      "metadata": {
        "event_action": "http-request",
        "src_ip": "{{dstips}}",
        "status": "404",
        "path": "/wp-login.php",
        "user_agent": "curl/8.6.0"
      },
      "technique": "T1190",
      "tactic": "TA0001"
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 54,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "sshd",
        "host": "{{srvpool}}"
      },
      "templates": [
        {
          "message": "Failed password for {{users}} from {{userips}} port {{port}} ssh2",
          "level": "WARN",
          "weight": 4
        },
        {
          "message": "error: maximum authentication attempts exceeded for {{users}} from {{userips}} port {{port}} ssh2 [preauth]",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "event_action": "account-locked"
          }
        },
        {
          "message": "Accepted password for {{users}} from {{userips}} port {{port}} ssh2",
          "level": "INFO",
          "weight": 1,
          "metadata": {
            "outcome": "success",
            "event_action": "logon-success"
          }
        }
      ],
      "metadata": {
        "event_action": "logon-success",
        "user": "{{users}}",
        "src_ip": "{{userips}}",
        "service": "sshd",
        "outcome": "failure"
      },
      "technique": "T1110",
      "tactic": "TA0006"
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 36,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "systemd",
        "host": "{{hosts}}"
      },
      "templates": [
        {
          "message": "Stopping auditd.service - log rotation",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "event_action": "audit-stopped"
          }
        },
        {
          "message": "Reloading auditd.service configuration",
          "level": "INFO",
          "weight": 2,
          "metadata": {
            "event_action": "audit"
          }
        },
        {
          "message": "Disabled unit telemetry-agent.service (masked by policy)",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "service-disabled"
          }
        },
        {
          "message": "Stopped falcon-sensor.service - scheduled patching window",
          "level": "WARN",
          "weight": 1,
          "metadata": {
            "event_action": "service-stopped"
          }
        }
      ],
      "metadata": {
        "event_action": "service-started",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 49,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "auditd",
        "host": "{{hosts}}"
      },
      "templates": [
        {
          "message": "type=SYSCALL arch=c000003e syscall=257 success=yes exit={{rand:3-40}} comm=\"{{cmds}}\" key=\"file-write\"",
          "level": "INFO",
          "weight": 3,
          "metadata": {
            "event_action": "file-write"
          }
        },
        {
          "message": "type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid={{pid}} pid={{pid}} auid={{rand:1000-1010}} uid={{rand:1000-1010}} comm=\"{{cmds}}\" key=\"syscall\"",
          "level": "INFO",
          "weight": 3,
          "metadata": {
            "event_action": "syscall"
          }
        },
        {
          "message": "type=CONFIG_CHANGE op=add_rule key=\"privileged\" list=4 res=1",
          "level": "INFO",
          "weight": 1,
          "metadata": {
            "event_action": "audit"
          }
        }
      ],
      "metadata": {
        "event_action": "file-read",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 145,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "firewalld",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "Rule removed: zone=public port=8080/tcp accept (change request CHG-{{rand:1000-9999}})",
          "level": "INFO",
          "weight": 1,
          "metadata": {
            "event_action": "connection-attempt"
          }
        },
        {
          "message": "Zone drop: interface eth2 bound",
          "level": "INFO",
          "weight": 1,
          "metadata": {
            "event_action": "zone-changed"
          }
        },
        {
          "message": "Rule apply deferred: zone=public service=postgresql already present",
          "level": "WARN",
          "weight": 1
        },
        {
          "message": "Failed to apply direct rule, ipv4 filter chain missing",
          "level": "ERROR",
          "weight": 1,
          "metadata": {
            "event_action": "error"
          }
        }
      ],
      "metadata": {
        "event_action": "rule-added",
        "service": "firewalld"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 620,
      "level": "INFO",
      "source": {
        "type": "webserver",
        "name": "nginx-proxy",
        "host": "{{webpool}}"
      },
      "templates": [
        {
          "message": "{{extips}} - - \"GET / HTTP/1.1\" 200 {{rand:800-9000}} \"-\" \"{{agents}}\"",
          "level": "INFO",
          "weight": 6
        },
        {
          "message": "{{extips}} - - \"GET {{paths}} HTTP/1.1\" 200 {{rand:800-9000}} \"-\" \"{{agents}}\"",
          "level": "INFO",
          "weight": 5
        },
        {
          "message": "{{extips}} - - \"POST /api/v1/orders HTTP/1.1\" 201 {{rand:120-900}} \"-\" \"{{agents}}\"",
          "level": "INFO",
          "weight": 3
        },
        {
          "message": "{{extips}} - - \"GET {{paths}} HTTP/1.1\" 404 {{rand:120-600}} \"-\" \"{{agents}}\"",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "status": "404"
          }
        },
        {
          "message": "{{extips}} - - \"GET /api/reports HTTP/1.1\" 502 {{rand:120-600}} \"-\" \"{{agents}}\"",
          "level": "ERROR",
          "weight": 1,
          "metadata": {
            "event_action": "error",
            "status": "502"
          }
        }
      ],
      "metadata": {
        "event_action": "http-request",
        "src_ip": "{{extips}}",
        "status": "200",
        "path": "{{paths}}",
        "user_agent": "{{agents}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 1449,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "iptables",
        "host": "{{fwpool}}"
      },
      "templates": [
        {
          "message": "ACCEPT IN=eth1 OUT=eth0 SRC={{extips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:40-58}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=443 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 5
        },
        {
          "message": "ACCEPT IN=eth1 OUT=eth0 SRC={{extips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:40-58}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT=25 WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "INFO",
          "weight": 2
        },
        {
          "message": "DROP IN=eth1 OUT=eth0 SRC={{extips}} DST={{dstips}} LEN={{rand:44-1500}} TOS=0x00 PREC=0x00 TTL={{rand:40-58}} ID={{rand:1-65535}} DF PROTO=TCP SPT={{port}} DPT={{rand:1-1024}} WINDOW={{rand:501-65535}} RES=0x00 SYN URGP=0",
          "level": "WARN",
          "weight": 4,
          "metadata": {
            "event_action": "connection-blocked"
          }
        }
      ],
      "metadata": {
        "event_action": "connection-allowed",
        "src_ip": "{{extips}}",
        "dst_ip": "{{dstips}}",
        "protocol": "tcp"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 12,
      "level": "INFO",
      "source": {
        "type": "email",
        "name": "mail-gateway",
        "host": "{{mailpool}}"
      },
      "templates": [
        {
          "message": "Message accepted for {{users}}@corp.example from noreply@{{senders}} relay={{extips}} size={{rand:2000-90000}}",
          "level": "INFO",
          "weight": 4
        },
        {
          "message": "Message rejected from unknown@{{senders}} relay={{extips}} reason=dnsbl",
          "level": "WARN",
          "weight": 2,
          "metadata": {
            "event_action": "error",
            "outcome": "failure"
          }
        }
      ],
      "metadata": {
        "event_action": "email-delivered",
        "user": "{{users}}",
        "src_ip": "{{extips}}",
        "service": "postfix",
        "outcome": "success"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 1639,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "bash",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} uid={{rand:1000-1010}} user={{users}} cmd={{cmds}}",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}",
        "shell": "bash"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 728,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "auditd",
        "host": "{{hosts}}"
      },
      "message": "type=PATH item=0 name=\"{{files}}\" inode={{rand:100000-999999}} dev=fd:00 mode=0100644 ouid={{rand:1000-1010}} ogid={{rand:1000-1010}} rdev=00:00 nametype=NORMAL auid={{rand:1000-1010}} key=\"file-read\"",
      "metadata": {
        "event_action": "file-read",
        "user": "{{users}}",
        "path": "{{files}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 255,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "systemd",
        "host": "{{hosts}}"
      },
      "message": "Started {{svcs}}.service",
      "metadata": {
        "event_action": "service-started",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 146,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "dnf",
        "host": "{{hosts}}"
      },
      "message": "Upgraded: {{pkgs}}-{{rand:1-9}}.{{rand:0-30}}.el9",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 24,
      "level": "WARN",
      "source": {
        "type": "host",
        "name": "sudo",
        "host": "{{hosts}}"
      },
      "message": "{{users}} : user NOT in sudoers ; TTY=pts/{{rand:0-4}} ; PWD=/home/{{users}} ; USER=root ; COMMAND=/usr/bin/systemctl restart {{svcs}}",
      "metadata": {
        "event_action": "privilege-use",
        "user": "{{users}}",
        "shell": "bash"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 18,
      "level": "WARN",
      "source": {
        "type": "host",
        "name": "auditd",
        "host": "{{hosts}}"
      },
      "message": "type=DAEMON_ERR op=queue msg=audit backlog limit exceeded, lost={{rand:1-400}}",
      "metadata": {
        "event_action": "file-read",
        "user": "{{users}}",
        "path": "{{files}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 12,
      "level": "ERROR",
      "source": {
        "type": "host",
        "name": "auditd",
        "host": "{{hosts}}"
      },
      "message": "type=DAEMON_ABORT op=error reason=\"audit rate limit exceeded\" res=failed",
      "metadata": {
        "event_action": "file-read",
        "user": "{{users}}",
        "path": "{{files}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 182,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "sudo",
        "host": "{{hosts}}"
      },
      "message": "{{users}} : TTY=pts/{{rand:0-4}} ; PWD=/home/{{users}} ; USER=root ; COMMAND=/usr/bin/systemctl restart {{svcs}}",
      "metadata": {
        "event_action": "privilege-use",
        "user": "{{users}}",
        "shell": "bash"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 218,
      "level": "WARN",
      "source": {
        "type": "host",
        "name": "bash",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} uid={{rand:1000-1010}} user={{users}} cmd=uname -a",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}",
        "shell": "bash"
      },
      "technique": "T1082",
      "tactic": "TA0007"
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 146,
      "level": "WARN",
      "source": {
        "type": "host",
        "name": "systemd",
        "host": "{{hosts}}"
      },
      "message": "Stopping {{svcs}}.service - scheduled maintenance window",
      "metadata": {
        "event_action": "service-started",
        "user": "{{users}}"
      },
      "technique": "T1562.001",
      "tactic": "TA0005"
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 109,
      "level": "WARN",
      "source": {
        "type": "host",
        "name": "bash",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} uid={{rand:1000-1010}} user={{users}} cmd=tar -czf /var/backups/nightly.tgz /srv/app",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}",
        "shell": "bash"
      },
      "technique": "T1005",
      "tactic": "TA0009"
    }
  ]
}
HOST_PB_EOF
HOST_PB_B64="$(base64 -w0 "$HOST_PB_TMP")"
rm -f "$HOST_PB_TMP"
# ---- END GENERATED PAYLOADS ----

# ---------- 1. cloud-init user-data ----------
cat > "$USERDATA_PATH" <<CLOUDINIT
#cloud-config
hostname: cybr400-sensor
manage_etc_hosts: true

users:
  - name: ${TEMPLATE_USER}
    groups: [wheel]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: false

chpasswd:
  list: |
    ${TEMPLATE_USER}:${TEMPLATE_PASSWORD}
    root:${TEMPLATE_PASSWORD}
  expire: false

ssh_pwauth: true

write_files:
  # ------------------------------------------------------------------------
  # THE MOST IMPORTANT FILE IN THIS BAKE.
  #
  # Distro qemu-guest-agent packages ship a default that BLACKLISTS the
  # guest-exec and guest-file-* RPCs. With it in place every agentShellExec
  # call returns HTTP 596 while guest-ping and network-get-interfaces succeed
  # — so the VM looks perfectly healthy and the Attack Console can dispatch
  # nothing at all. bake-web-template.sh hit exactly this on Debian
  # (/etc/default/qemu-guest-agent, DAEMON_ARGS); on RHEL/Rocky the same
  # setting lives here under two different names depending on version.
  #
  # Both are cleared, because which one is honoured varies across qemu-ga
  # releases and setting the unused one is harmless.
  # ------------------------------------------------------------------------
  - path: /etc/sysconfig/qemu-ga
    permissions: '0644'
    content: |
      # Cleared by bake-cybr400-loggen-template.sh — the CYBR 400 Attack
      # Console dispatches every attack over guest-exec. Re-enabling either
      # list below silently disables the entire feature.
      BLACKLIST_RPC=
      BLOCK_RPCS=
      FSFREEZE_HOOK_PATHNAME=/etc/qemu-ga/fsfreeze-hook

  # Students reach the sensor through Guacamole, which authenticates over SSH
  # with the per-lane password lane-deployer generates. The base image ships
  # 'PasswordAuthentication no', and cloud-init's 'ssh_pwauth: true' does NOT
  # survive templating: 'cloud-init clean' at seal time discards this bake's
  # user-data, and the clone's deploy-time cloud-init never re-asserts it. A
  # drop-in file does survive, so the setting lives here rather than above.
  #
  # 00- so it sorts ahead of 50-redhat.conf. In sshd_config the FIRST
  # occurrence of a keyword wins, not the last -- the opposite of most configs.
  - path: /etc/ssh/sshd_config.d/00-cybercore.conf
    permissions: '0600'
    content: |
      PasswordAuthentication yes

  # Always-on benign traffic, so an instructor's attack has something to hide
  # in. Runs from the PRIMARY checkout; attacks run from the attack checkout.
  - path: /etc/systemd/system/loggen-baseline.service
    permissions: '0644'
    content: |
      [Unit]
      Description=CYBR 400 baseline log generation
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      WorkingDirectory=/opt/log-generator
      # log-generator self-exits when --duration elapses; Restart=always turns
      # that into a continuous stream without needing a timer unit.
      ExecStart=/usr/bin/npm run generate -- ${BASELINE_ARGS}
      Restart=always
      RestartSec=10
      User=root
      # The baseline OWNS the :3000 metrics port. Attack runs set
      # ENABLE_MONITORING=false precisely so they do not collide with it.
      Environment=NODE_ENV=production

      [Install]
      WantedBy=multi-user.target

  # Standalone Elastic Agent. Not Fleet-enrolled: an enrolled agent baked into
  # a template gives every clone the SAME agent id, and Fleet then sees one
  # host flapping between thirty machines. Standalone needs no enrollment step,
  # no per-lane token, and nothing reachable at deploy time.
  - path: /etc/elastic-agent/elastic-agent.yml
    permissions: '0600'
    content: |
      # Plain http, no credentials: the lab stack runs with
      # xpack.security.enabled=false, which removes TLS, service-account tokens
      # and enrollment in one move — and with them every failure mode that comes
      # from cloning a machine whose certs were issued to its old hostname.
      #
      # ${ELK_HOST} resolves in EVERY lane to that lane's own ELK box, because
      # lane-deployer publishes a dnsmasq host-record from the ELK template's
      # metadata.dns_aliases. Nothing here is per-lane, which is the point.
      outputs:
        default:
          type: elasticsearch
          hosts: ["http://${ELK_HOST}:${ELK_PORT}"]
      inputs:
        # BOTH trees. Shipping only the baseline path is the single easiest way
        # to make this whole feature look broken: attacks would run correctly
        # and never appear in Kibana.
        # ONE dataset for both inputs, deliberately.
        #
        # Splitting these into loggen.baseline and loggen.attack is the obvious
        # design and it destroys the exercise: Discover shows data_stream.dataset
        # as a one-click field, so a student "hunting" for the instructor's
        # attack just picks it from a dropdown. Same events, same fields, one
        # stream -- finding the attack has to be analysis, not a filter.
        #
        # log.file.path used to be the instructor's discriminator, on the
        # reasoning that it was less discoverable than a dataset dropdown. It is
        # now dropped from both inputs: "less discoverable" is not a property a
        # field in Discover's field list actually has, and with two values it was
        # a one-click answer key for every run of the whole semester. Runs are
        # verified through the Attack Console instead.
        - type: filestream
          id: loggen-baseline
          data_stream.dataset: loggen.events
          paths:
            - /opt/log-generator/logs/current/*.json
          # log-generator writes ND-JSON. Without a parser the whole object
          # lands in `message` as one opaque string and Kibana can filter on
          # NOTHING inside it: not source.type, not level, not mitre.technique.
          # Students would be reduced to full-text searching a wall of JSON,
          # which is the difference between a SIEM exercise and a text file.
          #
          # target: loggen namespaces the decoded fields instead of merging them
          # to the root. Merging looks tidier and is a trap -- log-generator
          # emits a `source` object of {type,name,host}, and ECS `source` is an
          # {ip,port,geo} object. A type conflict on a data stream does not warn
          # or coerce: Elasticsearch REJECTS the document, and the events simply
          # never appear.
          parsers:
            - ndjson:
                target: loggen
                add_error_key: true
          processors:
            # Dropped from BOTH inputs, and the pairing is the point. Removing it
            # from only the attack tree would replace a direct-match oracle with
            # an inverted one -- NOT _exists_ : log.file.path would then select
            # exactly the attack events, which is no better and harder to notice.
            - drop_fields:
                fields: ['log.file.path']
                ignore_missing: true
        # The attack tree ships ONLY technique-tagged events, and that single
        # processor is what makes the whole feature work.
        #
        # --mitre-technique is a FILTER over generic enterprise logs, not a
        # technique simulator: LogGeneratorManager runs every generator at its
        # configured rate and tags the lines that map, rather than restricting
        # what is written. Measured on a deployed lane, one T1005 run produced
        #
        #     37,004 lines written
        #         76 carrying "technique":"T1005"      (0.2%)
        #     30,571 of them from `endpoint` alone     (api.example.com)
        #
        # Shipping that raw is a 37k-event wall of API-gateway traffic with a
        # 76-event needle in it -- the opposite of an attack hidden in a
        # baseline, and nothing to do with reading files off a local disk.
        #
        # Lowering the attack tree's rates is the wrong fix and was my first
        # instinct: the volume is what PRODUCES the 76 matches. At the
        # baseline's ~1.7/sec a five-minute run would yield about one event.
        # So generate at full rate on the guest, and drop the untagged 99.8%
        # here, before it reaches Elasticsearch.
        #
        # This is sound only because the attack checkout has its config-level
        # mitre blocks STRIPPED (see ATTACK_STRIP_MITRE). Every remaining tag
        # comes from MitreMapper matching at runtime, so it is by construction
        # the technique the instructor selected -- verified on the lane above,
        # where T1005 was the only technique present in 37k lines.
        - type: filestream
          id: loggen-attack
          data_stream.dataset: loggen.events
          paths:
            - /opt/log-generator-attack/logs/current/*.json
          parsers:
            - ndjson:
                target: loggen
                add_error_key: true
          processors:
            # ORDER IS THE MECHANISM. Filebeat runs processors in declaration
            # order, so drop_event still sees the technique and uses it to
            # decide what ships -- then drop_fields removes it before the event
            # reaches Elasticsearch. Swap these two and every attack event is
            # discarded, because the field the filter tests no longer exists.
            - drop_event:
                when:
                  not:
                    has_fields: ['loggen.mitre.technique']
            # The label is the answer. An event that arrives stamped
            # "technique: T1005" has told the student what it is before they
            # have looked at it, and a run is then one filter away from being
            # fully enumerated.
            #
            # Removing it does NOT create the reverse oracle. Roughly 88% of
            # benign traffic is already untagged (log-generator labels ~15% of
            # its output, the host baseline ~10%), so `NOT loggen.mitre.technique:*`
            # returns overwhelmingly ordinary events with the attack a small
            # fraction inside it -- which is exactly the shape a hunt should have.
            #
            # The instructor's discriminator is unchanged and unaffected:
            #   log.file.path : "/opt/log-generator-attack/logs/current/attack-*.json"
            #
            # The wrapper's count is also unaffected: count_lines() greps the
            # FILE on the guest, which still carries the tag, and a playbook run
            # reports the emitter's own count anyway.
            - drop_fields:
                # log.file.path is added by filestream and is the LAST perfect
                # oracle in this design. The two trees give it exactly two value
                # families -- /opt/log-generator/... and
                # /opt/log-generator-attack/... -- so it sits in Discover's field
                # list with two values and a single click on the second one
                # enumerates the instructor's entire run. That is easier than the
                # event_action oracle it replaced, because it is a direct match
                # rather than a negation.
                #
                # It was kept deliberately as the instructor's discriminator, and
                # that trade is no longer worth it: the Attack Console already
                # reports the emitter's own event count per run over guest-exec,
                # which is admin-only and cannot leak into the student's index.
                # See the runbook section on verifying a run.
                fields: ['loggen.mitre', 'log.file.path']
                ignore_missing: true
      agent.logging.level: info

  # Helper scripts, base64'd so no $ or backslash has to survive this heredoc.
  - path: /opt/cybercore/loggen-tune.sh
    permissions: '0755'
    encoding: b64
    content: ${LOGGEN_TUNE_B64}

  - path: /opt/cybercore/loggen-rotate.sh
    permissions: '0755'
    encoding: b64
    content: ${LOGGEN_ROTATE_B64}

  # The attack emitter. Baked rather than staged per dispatch like cc-attack.sh:
  # inline it would take the dispatch command from ~19 KB to ~50 KB on a path
  # that already throws transient 596s. The playbook -- the half that changes --
  # still ships on every dispatch, so only an ENGINE change needs a re-bake.
  - path: /opt/cybercore/cc-emit.js
    permissions: '0755'
    encoding: b64
    content: ${CC_EMIT_B64}

  # Benign host/process/file activity, always on.
  #
  # This is what makes `source.type: host` ordinary. Without it every host event
  # in the index belongs to an instructor's attack and one terms click ends the
  # exercise -- the same oracle BASELINE_STRIP_MITRE=0 exists to prevent for
  # log-generator's own output. It also supplies the benign floor for every
  # (source.type, source.name) pair the attack playbooks use: sshd, iptables,
  # firewalld, postgres-primary and the rest. A pair that only ever appears
  # during an attack is a one-click answer key.
  - path: /opt/cybercore/host-baseline.json
    permissions: '0644'
    encoding: b64
    content: ${HOST_PB_B64}

  - path: /etc/systemd/system/cc-hostbase.service
    permissions: '0644'
    content: |
      [Unit]
      Description=CYBR 400 benign host activity
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      # Writes into the BASELINE tree on purpose. That input has no drop_event,
      # so untagged benign events ship; the attack tree drops anything without a
      # technique and would swallow this entirely.
      ExecStart=/usr/bin/node /opt/cybercore/cc-emit.js --daemon --playbook /opt/cybercore/host-baseline.json --out /opt/log-generator/logs/current/host.json
      Restart=always
      RestartSec=10
      User=root

      [Install]
      WantedBy=multi-user.target

  # A timer rather than logrotate: rotation here has to restart the generator so
  # it reopens its file handle, which is not something logrotate's postrotate
  # should be doing every hour on a schedule it picked.
  - path: /etc/systemd/system/loggen-rotate.service
    permissions: '0644'
    content: |
      [Unit]
      Description=CYBR 400 baseline log rotation
      After=loggen-baseline.service

      [Service]
      Type=oneshot
      ExecStart=/opt/cybercore/loggen-rotate.sh ${BASELINE_ROTATE_BYTES}

  - path: /etc/systemd/system/loggen-rotate.timer
    permissions: '0644'
    content: |
      [Unit]
      Description=CYBR 400 baseline log rotation (size check)

      [Timer]
      OnBootSec=10min
      OnUnitActiveSec=10min
      AccuracySec=1min

      [Install]
      WantedBy=timers.target
CLOUDINIT
echo "==> Wrote bake snippet: $USERDATA_PATH"

cat >> "$USERDATA_PATH" <<CLOUDINIT

runcmd:
  # ---- DNS first: everything below needs the internet ----
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver ${BAKE_DNS}\n" > /etc/resolv.conf' ]

  # ---- Claim the disk this script already paid for ----
  #
  # `qm resize scsi0 +12G` further down grows the BLOCK DEVICE, and nothing in
  # the guest ever claimed it. cloud-init's own growpart handles a plain
  # partition but does not traverse LVM, and 1001 is LVM (rl-root) -- so every
  # lane ran a 10 GB filesystem on a 22 GB disk, and the template was SEALED
  # that way, so every clone inherited it.
  #
  # Measured on a deployed lane: 10G total, 92% full, the attack wrapper
  # refusing every run with "nospace". Grown in place it returned 22G at 23%
  # used. The twelve gigabytes had been sitting there the whole time.
  #
  # Four steps because LVM needs all four -- partition, physical volume, logical
  # volume, filesystem -- and each is a no-op once done, so this is safe to
  # re-run and safe if a future base image already grows itself.
  - [ sh, -c, 'growpart /dev/sda 2 2>/dev/null || true' ]
  - [ sh, -c, 'pvresize /dev/sda2 2>/dev/null || true' ]
  - [ sh, -c, 'lvextend -l +100%FREE /dev/mapper/rl-root 2>/dev/null || true' ]
  - [ sh, -c, 'xfs_growfs / 2>/dev/null || resize2fs /dev/mapper/rl-root 2>/dev/null || true' ]

  # ---- Base packages. coreutils gives timeout, util-linux gives setsid; the
  #      attack wrapper refuses to launch without setsid because abort could
  #      not then reach the process group. ----
  - [ sh, -c, 'dnf install -y --allowerasing git tar coreutils util-linux qemu-guest-agent' ]

  # ---- SELinux. Clearing BLACKLIST_RPC above enables the guest-exec RPC, but
  #      that is only HALF the story on RHEL derivatives: qemu-ga also runs
  #      confined in the virt_qemu_ga_t domain, which cannot write files or
  #      fork detached processes. Measured on a deployed Rocky sensor:
  #
  #        context=system_u:system_r:virt_qemu_ga_t:s0
  #        /opt/cybercore/probe: Permission denied
  #        nohup setsid ... -> never ran
  #        pgrep/ausearch/getenforce -> denied
  #
  #      The Attack Console needs ALL of those: it stages cc-attack.sh, forks it
  #      under setsid, and reads /proc for liveness. Confined, every dispatch
  #      fails while the VM looks perfectly healthy.
  #
  #      The boolean is the narrow fix, but on its own it is not enough: the
  #      unconfined transition requires the script to carry the
  #      virt_qemu_ga_unconfined_exec_t label, and the wrapper is written fresh
  #      by each dispatch -- which is the very operation that is denied.
  #      Permissive is what actually makes this work. Defensible here: the
  #      sensor is a single-purpose synthetic-log box on an isolated per-student
  #      network with no sensitive data. Set SELINUX_MODE=enforcing to opt out
  #      and supply your own policy module.
  - [ sh, -c, 'setsebool -P virt_qemu_ga_run_unconfined 1 2>/dev/null || true' ]
  - [ sh, -c, 'sed -i "s/^SELINUX=.*/SELINUX=${SELINUX_MODE}/" /etc/selinux/config || true' ]
  - [ sh, -c, 'setenforce 0 2>/dev/null || true' ]

  # ---- Node. Rocky AppStream carries several streams; pin one so the pinned
  #      log-generator commit is not paired with a surprise runtime. ----
  - [ sh, -c, 'dnf module reset -y nodejs || true' ]
  - [ sh, -c, 'dnf module enable -y nodejs:${NODE_STREAM}' ]
  - [ sh, -c, 'dnf install -y nodejs npm' ]

  # ---- log-generator at the pinned commit. Clone then detach: a shallow clone
  #      of a branch cannot check out an arbitrary sha. ----
  - [ sh, -c, 'git clone ${LOGGEN_REPO} /opt/log-generator' ]
  - [ sh, -c, 'cd /opt/log-generator && git checkout --detach ${LOGGEN_REF}' ]
  # npm ci, NOT --omit=dev: the CLI runs through ts-node, which is a devDep.
  # Installing at bake time also keeps class-time deploys off the npm registry.
  - [ sh, -c, 'cd /opt/log-generator && npm ci' ]

  # ---- Second checkout for attacks. A copy rather than a second clone: same
  #      bytes, same commit, no second dependency install, and provably not a
  #      different revision.
  #
  #      ORDER MATTERS, and it was wrong here until measured: the copy has to
  #      happen BEFORE the baseline is retuned. Copying afterwards silently
  #      hands the attack checkout the baseline's rates and its stripped mitre
  #      blocks -- which is exactly what the previous comment claimed was not
  #      happening. ----
  - [ sh, -c, 'cp -a /opt/log-generator /opt/log-generator-attack' ]

  # ---- The attack checkout keeps stock RATES -- no frequency pairs are passed,
  #      and that is deliberate: the volume is what produces technique matches.
  #      It does NOT keep log-generator's broken file rotation, and it does NOT
  #      keep its config-level mitre blocks. See ATTACK_STRIP_MITRE. ----
  - [ sh, -c, 'LOGGEN_STRIP_MITRE=${ATTACK_STRIP_MITRE} /opt/cybercore/loggen-tune.sh /opt/log-generator-attack/src/config/default.yaml' ]

  # ---- Baseline RATE and MITRE labelling. See the BASELINE_FREQ_* block at the
  #      top of this script for why every value must be <= 20; the short version
  #      is that log-generator's batch path has a Math.max(1, ...) floor that
  #      pins anything above 20 to 10 logs/second regardless of its setting.
  #
  #      Retune the PRIMARY checkout only. The copy above keeps stock RATES,
  #      which is what the keyword-filter path wants, but its mitre blocks are
  #      stripped by the step above -- see ATTACK_STRIP_MITRE. (This comment
  #      claimed the opposite until the strip was added under it.)
  - [ sh, -c, 'LOGGEN_STRIP_MITRE=${BASELINE_STRIP_MITRE} /opt/cybercore/loggen-tune.sh /opt/log-generator/src/config/default.yaml webserver=${BASELINE_FREQ_WEBSERVER} firewall=${BASELINE_FREQ_FIREWALL} endpoint=${BASELINE_FREQ_ENDPOINT} authentication=${BASELINE_FREQ_AUTHENTICATION} database=${BASELINE_FREQ_DATABASE} microservices=${BASELINE_FREQ_MICROSERVICES} application=${BASELINE_FREQ_APPLICATION} server=${BASELINE_FREQ_SERVER} cloud=${BASELINE_FREQ_CLOUD} email=${BASELINE_FREQ_EMAIL} iot=${BASELINE_FREQ_IOT} backup=${BASELINE_FREQ_BACKUP}' ]
  - [ sh, -c, 'rm -rf /opt/log-generator-attack/logs/current/* /opt/log-generator-attack/logs/historical/*' ]
  - [ sh, -c, 'mkdir -p /opt/log-generator/logs/current /opt/log-generator-attack/logs/current' ]

  # ---- Manifest. The attack wrapper reads this and reports ref= on every
  #      state line, so a catalog/image mismatch surfaces without a probe. ----
  - [ sh, -c, 'mkdir -p /opt/cybercore' ]
  - [ sh, -c, 'printf "{ \"ref\": \"${LOGGEN_REF}\", \"baked_at\": \"\$(date -Is)\", \"node\": \"\$(node --version)\" }\n" > /opt/cybercore/loggen-manifest.json' ]

  # ---- Elastic Agent, standalone against the in-lane ELK box ----
  - [ sh, -c, 'curl -fsSL -o /tmp/ea.tar.gz https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz' ]
  - [ sh, -c, 'mkdir -p /opt/ea && tar xzf /tmp/ea.tar.gz -C /opt/ea --strip-components=1 && rm -f /tmp/ea.tar.gz' ]
  - [ sh, -c, 'cp /etc/elastic-agent/elastic-agent.yml /opt/ea/elastic-agent.yml' ]
  - [ sh, -c, 'cd /opt/ea && ./elastic-agent install -n --unprivileged=false || true' ]
  - [ sh, -c, 'cp -f /etc/elastic-agent/elastic-agent.yml /opt/Elastic/Agent/elastic-agent.yml 2>/dev/null || true' ]
  - [ systemctl, enable, elastic-agent ]

  # ---- Services ----
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, restart, qemu-guest-agent ]
  - [ sh, -c, 'if [ "${LOGGEN_BASELINE_ENABLED}" = "1" ]; then systemctl enable loggen-baseline; else systemctl disable loggen-baseline 2>/dev/null || true; fi' ]
  - [ systemctl, enable, loggen-rotate.timer ]
  - [ systemctl, enable, cc-hostbase ]
  - [ systemctl, daemon-reload ]

  # ---- Pre-seal markers, read back over the guest agent before sealing ----
  - [ sh, -c, 'systemctl is-enabled qemu-guest-agent >/dev/null && echo "GUEST_AGENT_ENABLED=yes" >> /etc/cybercore-bake.env || echo "GUEST_AGENT_ENABLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -Eq "^(BLACKLIST_RPC|BLOCK_RPCS)=\$" /etc/sysconfig/qemu-ga && echo "GUEST_AGENT_UNBLOCKED=yes" >> /etc/cybercore-bake.env || echo "GUEST_AGENT_UNBLOCKED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -f /opt/log-generator/package.json && echo "LOGGEN_PRIMARY=yes" >> /etc/cybercore-bake.env || echo "LOGGEN_PRIMARY=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -f /opt/log-generator-attack/package.json && echo "LOGGEN_ATTACK=yes" >> /etc/cybercore-bake.env || echo "LOGGEN_ATTACK=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -d /opt/log-generator/node_modules/ts-node && echo "TS_NODE=yes" >> /etc/cybercore-bake.env || echo "TS_NODE=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'cd /opt/log-generator && echo "LOGGEN_REF_ACTUAL=\$(git rev-parse HEAD)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'for B in setsid timeout nohup npm node git; do command -v \$B >/dev/null || { echo "MISSING_BIN=\$B" >> /etc/cybercore-bake.env; }; done; echo "BINS_CHECKED=yes" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled loggen-baseline >/dev/null && echo "BASELINE_ENABLED=yes" >> /etc/cybercore-bake.env || echo "BASELINE_ENABLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled elastic-agent >/dev/null 2>&1 && echo "ELASTIC_AGENT=yes" >> /etc/cybercore-bake.env || echo "ELASTIC_AGENT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'sshd -T 2>/dev/null | grep -qx "passwordauthentication yes" && echo "SSH_PASSWORD_AUTH=yes" >> /etc/cybercore-bake.env || echo "SSH_PASSWORD_AUTH=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "^SELINUX=${SELINUX_MODE}" /etc/selinux/config && echo "SELINUX_MODE_SET=yes" >> /etc/cybercore-bake.env || echo "SELINUX_MODE_SET=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -Eq "^    frequency: ([0-9]{3,}|[3-9][0-9]|2[1-9])" /opt/log-generator/src/config/default.yaml && echo "BASELINE_RATE_CAPPED=no" >> /etc/cybercore-bake.env || echo "BASELINE_RATE_CAPPED=yes" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "        mitre:" /opt/log-generator/src/config/default.yaml && echo "BASELINE_MITRE_STRIPPED=no" >> /etc/cybercore-bake.env || echo "BASELINE_MITRE_STRIPPED=yes" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "        mitre:" /opt/log-generator-attack/src/config/default.yaml && echo "ATTACK_MITRE_STRIPPED=no" >> /etc/cybercore-bake.env || echo "ATTACK_MITRE_STRIPPED=yes" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "drop_event" /etc/elastic-agent/elastic-agent.yml && echo "ATTACK_DROP_UNTAGGED=yes" >> /etc/cybercore-bake.env || echo "ATTACK_DROP_UNTAGGED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "drop_fields" /etc/elastic-agent/elastic-agent.yml && echo "ATTACK_STRIP_TAG=yes" >> /etc/cybercore-bake.env || echo "ATTACK_STRIP_TAG=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "ndjson" /etc/elastic-agent/elastic-agent.yml && echo "NDJSON_PARSER=yes" >> /etc/cybercore-bake.env || echo "NDJSON_PARSER=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled loggen-rotate.timer >/dev/null 2>&1 && echo "ROTATE_TIMER=yes" >> /etc/cybercore-bake.env || echo "ROTATE_TIMER=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -s /opt/cybercore/cc-emit.js && echo "CC_EMIT=yes" >> /etc/cybercore-bake.env || echo "CC_EMIT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'node --check /opt/cybercore/cc-emit.js >/dev/null 2>&1 && echo "CC_EMIT_PARSES=yes" >> /etc/cybercore-bake.env || echo "CC_EMIT_PARSES=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -s /opt/cybercore/host-baseline.json && grep -q nominal_seconds /opt/cybercore/host-baseline.json && echo "HOST_PB=yes" >> /etc/cybercore-bake.env || echo "HOST_PB=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled cc-hostbase >/dev/null 2>&1 && echo "HOSTBASE_SERVICE=yes" >> /etc/cybercore-bake.env || echo "HOSTBASE_SERVICE=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'df -Pk / | awk "NR==2{print \\"ROOT_FS_KB=\\" \$2}" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]
CLOUDINIT
echo "==> Appended runcmd"

# ---------- 2. Clone + configure ----------
echo "==> Cloning $SRC_VMID -> $VMID (full clone onto $STORAGE)"
qm clone "$SRC_VMID" "$VMID" --name "$NAME" --full 1 --storage "$STORAGE"

qm set $VMID \
  --memory "$MEMORY" \
  --cores "$CORES" \
  --agent enabled=1 \
  --net0 "virtio,bridge=${BAKE_BRIDGE},tag=${BAKE_VLAN}" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
  --ciuser "$TEMPLATE_USER" \
  --cipassword "$TEMPLATE_PASSWORD" \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/${USERDATA_FILE}"

# ts-node compiles the whole CLI on every invocation and npm ci pulls a large
# tree; 1001's default disk is sized for a bare OS.
echo "==> Growing disk by 12G"
qm resize $VMID scsi0 +12G 2>/dev/null || qm resize $VMID virtio0 +12G 2>/dev/null || \
  echo "WARNING: could not grow the disk — check free space before first use"

# ---------- 3. Boot + wait for the bake ----------
echo "==> Starting $VMID and waiting for cloud-init"
qm start $VMID

# Poll the marker file through the guest agent rather than mounting the disk.
# bake-web-template.sh maps the rbd image to verify, which only works on Ceph;
# reading it live works on any storage AND proves guest-exec itself is
# functional — which for this template is the single most important property,
# because the Attack Console can do nothing without it.
DEADLINE=$(( $(date +%s) + 2400 ))
BAKE_ENV=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if OUT=$(qm guest exec $VMID -- /bin/sh -c 'cat /etc/cybercore-bake.env 2>/dev/null' 2>/dev/null); then
    # `qm guest exec` returns JSON, and out-data is a JSON STRING: the file's real
    # newlines arrive as the two-character escape  \n. Decode them with printf %b,
    # or the whole marker file parses as ONE line and every marker after the first
    # reads as part of the first one's value -- which looks exactly like a bake
    # that did nothing, on a bake that did everything.
    # [^"] rather than .* so the match stops at out-data's own closing quote
    # instead of running on to the last quote in the JSON object.
    BAKE_ENV=$(printf '%s' "$OUT" | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [ -z "$BAKE_ENV" ] && BAKE_ENV="$OUT"
    BAKE_ENV=$(printf '%b' "$BAKE_ENV")
    if printf '%s' "$BAKE_ENV" | grep -q 'BAKE_COMPLETE=yes'; then
      echo "==> cloud-init finished"
      break
    fi
  fi
  echo "    ... still baking ($(( (DEADLINE - $(date +%s)) / 60 ))m budget left)"
  sleep 20
done

if ! printf '%s' "$BAKE_ENV" | grep -q 'BAKE_COMPLETE=yes'; then
  echo "ERROR: bake did not complete within the budget. VM $VMID left running for inspection:" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'cat /var/log/cloud-init-output.log | tail -50'" >&2
  exit 1
fi

# ---------- 4. Pre-seal verification ----------
echo "==> Verifying bake markers"
marker() { printf '%s' "$BAKE_ENV" | awk -F= -v k="$1" '$1==k {print $2; exit}'; }

FAIL=0
check() {  # check <marker> <expected> <explanation of what breaks>
  local got; got=$(marker "$1")
  printf '    %-22s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    FAIL=1
  fi
}

check GUEST_AGENT_ENABLED  yes "qemu-guest-agent is not enabled — the Attack Console cannot reach this VM at all"
check GUEST_AGENT_UNBLOCKED yes "guest-exec is still blacklisted in /etc/sysconfig/qemu-ga — every dispatch will return 596 while the VM looks healthy"
check LOGGEN_PRIMARY       yes "/opt/log-generator is missing — the baseline service has nothing to run"
check LOGGEN_ATTACK        yes "/opt/log-generator-attack is missing — attacks would share the baseline's output file and lose events"
check TS_NODE              yes "ts-node is absent — npm ci ran with --omit=dev, and every CLI invocation will fail"
EXPECT_LOGGEN_BASELINE=no
[ "$LOGGEN_BASELINE_ENABLED" = "1" ] && EXPECT_LOGGEN_BASELINE=yes
check BASELINE_ENABLED "$EXPECT_LOGGEN_BASELINE" "log-generator's baseline service does not match LOGGEN_BASELINE_ENABLED — with it OFF, cc-hostbase is the only benign traffic; with it ON, every benign event also carries literal {clientIP} placeholder metadata that emitter events do not"
check ELASTIC_AGENT        yes "elastic-agent is not enabled — events would land on disk and never reach Kibana"
check BINS_CHECKED         yes "binary check did not run"
check SELINUX_MODE_SET     yes "SELinux is still enforcing — guest-exec runs confined in virt_qemu_ga_t and CANNOT stage or fork the attack wrapper, so every dispatch fails silently"
check SSH_PASSWORD_AUTH    yes "sshd refuses password auth — the student's Guacamole SSH console for this box cannot authenticate, because Guacamole logs in with the per-lane password"
check BASELINE_RATE_CAPPED yes "a generator is still above frequency 20 — log-generator's batch floor pins anything over 20 to 10 logs/sec, so the baseline runs ~50/sec (4.4M events/day) no matter what the config says"
EXPECT_MITRE_STRIPPED=no
[ "$BASELINE_STRIP_MITRE" = "1" ] && EXPECT_MITRE_STRIPPED=yes
check BASELINE_MITRE_STRIPPED "$EXPECT_MITRE_STRIPPED" "the baseline's mitre labelling does not match BASELINE_STRIP_MITRE — benign filler tagged T1018/T1110/T1190 makes hunting by technique return noise forever"
EXPECT_ATTACK_STRIPPED=no
[ "$ATTACK_STRIP_MITRE" = "1" ] && EXPECT_ATTACK_STRIPPED=yes
check ATTACK_MITRE_STRIPPED "$EXPECT_ATTACK_STRIPPED" "the attack checkout still carries config-level mitre blocks — with drop_event shipping every tagged line, its stock T1190/T1110/T1499 templates would ship as though they were part of the instructor's run"
check ATTACK_DROP_UNTAGGED yes "the agent is not dropping untagged attack events — a single run would ship ~37,000 events of generic API-gateway traffic to carry roughly 76 real ones"
check ATTACK_STRIP_TAG     yes "the agent is not stripping loggen.mitre from attack events — every event would arrive stamped with the technique, and the run is then one filter away from being fully enumerated"
check NDJSON_PARSER        yes "the agent has no ndjson parser — every event lands in Kibana as one opaque JSON string with no filterable fields"
check ROTATE_TIMER         yes "loggen-rotate.timer is not enabled — logs.json grows without bound (measured: 2.5 GB in twelve hours)"
check CC_EMIT              yes "the attack emitter is missing — every playbook-backed technique refuses with 'noemitter' and the console falls back to nothing"
check CC_EMIT_PARSES       yes "the embedded cc-emit.js does not parse — the heredoc mangled it, and every attack run would exit non-zero"
check HOST_PB              yes "host-baseline.json is missing or malformed — no benign host traffic, so source.type:host appears ONLY during attacks and one terms click ends the exercise"
check HOSTBASE_SERVICE     yes "cc-hostbase is not enabled — same consequence as a missing host playbook"

MISSING=$(marker MISSING_BIN)
if [ -n "$MISSING" ]; then
  echo "    ERROR: required binary missing on the image: $MISSING" >&2
  echo "           setsid in particular is mandatory — without it the attack wrapper" >&2
  echo "           cannot be process-group-leader and abort cannot stop a run." >&2
  FAIL=1
fi

ROOT_KB=$(marker ROOT_FS_KB)
printf '    %-22s %s
' "ROOT_FS_KB:" "${ROOT_KB:-unset}"
case "$ROOT_KB" in ''|*[!0-9]*) ROOT_KB=0 ;; esac
# The disk is grown by +12G above, so a correctly-claimed root is ~22G. Anything
# under 15G means growpart/pvresize/lvextend/xfs_growfs did not take and the
# template would be sealed with a 10G filesystem on a 22G disk -- which is
# exactly how every lane ended up refusing attack runs with "nospace" after a
# week. Catching it here costs one check; catching it later costs thirty lanes.
if [ "$ROOT_KB" -lt 15728640 ]; then
  echo "    ERROR: root filesystem is only ${ROOT_KB}KB -- the +12G resize was not claimed inside the guest." >&2
  echo "           Check growpart/pvresize/lvextend/xfs_growfs in runcmd; the device is LVM (rl-root)," >&2
  echo "           and cloud-init's own growpart does not traverse LVM." >&2
  FAIL=1
fi

ACTUAL_REF=$(marker LOGGEN_REF_ACTUAL)
printf '    %-22s %s\n' "LOGGEN_REF_ACTUAL:" "${ACTUAL_REF:-unset}"
if [ "$ACTUAL_REF" != "$LOGGEN_REF" ]; then
  echo "    ERROR: checked out ${ACTUAL_REF:-nothing}, expected $LOGGEN_REF." >&2
  echo "           cle/utils/loggen-catalog.js is transcribed from that exact commit." >&2
  FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "ERROR: verification failed. VM $VMID left RUNNING and unsealed for inspection." >&2
  exit 1
fi
echo "==> All markers good"

# ---------- 5. Seal ----------
echo "==> Cleaning cloud-init state and sealing"
qm guest exec $VMID -- /bin/sh -c 'cloud-init clean --logs --seed 2>/dev/null || true' >/dev/null 2>&1 || true
# The baseline must not carry this bake's logs into every clone.
qm guest exec $VMID -- /bin/sh -c 'rm -rf /opt/log-generator/logs/current/* /opt/log-generator-attack/logs/current/* /opt/cybercore/runs' >/dev/null 2>&1 || true
# Elastic Agent writes a per-install id; leaving it makes every clone the same
# agent, which is the same failure as baking an enrolled agent.
qm guest exec $VMID -- /bin/sh -c 'rm -f /var/lib/elastic-agent/fleet.enc /opt/Elastic/Agent/fleet.enc 2>/dev/null; rm -rf /var/lib/elastic-agent/data/*/logs 2>/dev/null || true' >/dev/null 2>&1 || true
qm guest exec $VMID -- /bin/sh -c 'truncate -s 0 /etc/machine-id' >/dev/null 2>&1 || true

qm shutdown $VMID --timeout 120 || qm stop $VMID
for _ in $(seq 1 30); do
  [ "$(qm status $VMID | awk '{print $2}')" = "stopped" ] && break
  sleep 3
done

echo "==> Clearing bake-time cicustom + cloud-init fields"
qm set $VMID --delete cicustom
qm set $VMID --delete cipassword 2>/dev/null || true
rm -f "$USERDATA_PATH"

qm template $VMID
echo "==> Template $VMID ($NAME) sealed"

# ---------- 6. What still has to happen by hand ----------
cat <<NEXTSTEPS

============================================================================
 Template $VMID ($NAME) is built. Three things remain.

 1. REGISTER IT AS A WORKSTATION TEMPLATE, tagged 'loggen'.

    template_type MUST be 'workstation'. CYBR 400 lanes are built by the CLE
    provision path (lane-deployer.js), and its picker filters on
    template_type = 'workstation' — an 'os_template' row is invisible there and
    /provision 404s it. Add the row through Admin -> Workstation Templates:

        os_family      linux
        os_name        Rocky Linux (CYBR 400 sensor)
        template_vmid  $VMID
        template_key   cybr400-loggen-template
        template_type  workstation
        metadata       {"console_protocol": "ssh"}

    console_protocol=ssh is not cosmetic. resolveConsole() defaults to rdp, so
    leaving it unset publishes a gateway DNAT to port 3389 on a Linux box that
    is not listening there.

    Then POST /api/admin/vm-templates/sync-nodes so 'node' is filled in.
    Do NOT add a seed migration: front-end/migrations/ has no runner, so a file
    there would never execute.

 2. TAG IT 'loggen' SO THE ATTACK CONSOLE FINDS IT.
    The resolver looks for  WHERE 'loggen' = ANY(role_hints) AND is_active,
    which identifies the sensor deterministically instead of probing both
    machines. role_hints is NOT writable from any admin UI, so either:

        UPDATE cybercore_template_catalog
           SET role_hints = '{loggen}'
         WHERE template_key = 'cybr400-loggen-template';

    or skip SQL entirely and set, in the app environment:

        CYBR400_LOGGEN_TEMPLATE_KEY=cybr400-loggen-template

 3. GIVE THE WINDOWS ELK TEMPLATE THE 'elk' DNS ALIAS.
    The agent config baked in here targets ${ELK_HOST}, and that name is
    published by the LANE GATEWAY, not by the Windows box. On the ELK catalog
    row set:

        metadata    {"dns_aliases": ["elk"]}

    lane-deployer then writes a dnsmasq host-record per lane, so every lane
    resolves 'elk' to its OWN ELK box.

    Do NOT try to do this by naming the Windows machine 'elk'. cloudbase-init's
    SetHostNamePlugin renames every clone to the Proxmox VM name, truncates it
    to the 15-char NetBIOS limit, and with allow_reboot=false the rename only
    takes effect at the NEXT reboot — so the advertised name is the baked one on
    first boot and the lane name afterwards.

 4. DEPLOY BOTH MACHINES TOGETHER.
    In the course's Provision Workstation VM modal, pick the ELK image as the
    first machine and this sensor as the second. First machine = slot 0 = the
    lane's .50 address and the gateway's baked RDP console, which is what
    students connect to. This sensor lands on .51.

 Then, on a deployed lane, verify what this script cannot:

    getent hosts ${ELK_HOST}                        # gateway resolves it
    systemctl is-active loggen-baseline elastic-agent
    cd /opt/log-generator-attack && ENABLE_MONITORING=false \
      npm run generate -- --mitre-technique T1082 --duration 60s
    ls -li /opt/log-generator/logs/current /opt/log-generator-attack/logs/current
      # ^ MUST be different inodes, or baseline and attack will fight

 And confirm those events reach KIBANA, not just the disk. A TLS failure
 against a self-signed ELK cert fails closed and is indistinguishable, from
 the console's side, from an attack that generated nothing.

 Test clone: qm clone $VMID 9994 --name cybr400-test --full --storage $STORAGE
============================================================================
NEXTSTEPS
