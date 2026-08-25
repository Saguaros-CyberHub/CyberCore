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
  systemctl restart loggen-baseline
  find "$DIR" -maxdepth 1 -name 'logs-*.json' -mmin "+$GRACE_MIN" -delete 2>/dev/null || true
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
    find "$DIR" -maxdepth 1 -name 'host-*.json' -mmin "+$GRACE_MIN" -delete 2>/dev/null || true
  fi
fi
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

const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];
const randInt = (rng, lo, hi) => lo + Math.floor(rng() * (hi - lo + 1));

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
    const pool = ctx.pools[key];
    if (Array.isArray(pool) && pool.length) {
      if (idx != null) return String(pool[Number(idx) % pool.length]);
      // Sampled ONCE per event, then reused. Sampling per occurrence makes an
      // event contradict itself -- "Failed password for jsmith" carrying
      // metadata.user=svc_backup -- so a student pivoting on the structured
      // field gets a different answer than one reading the message. Both are
      // wrong, and nothing about the data says which.
      if (!Object.prototype.hasOwnProperty.call(ctx.sampled, key)) {
        ctx.sampled[key] = String(pick(rng, pool));
      }
      return ctx.sampled[key];
    }
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

  const events = [];

  for (let si = 0; si < steps.length; si += 1) {
    const step = steps[si];
    const spread = parseDuration(step.spread || '0s');
    const start = starts[si];
    const count = Math.max(1, Number(step.count || 1));
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
      // Fresh sample cache per event: pool draws are consistent WITHIN one
      // event and vary BETWEEN them, which is what a spray from one host
      // against many accounts actually looks like.
      const ctx = { entities, pools, sampled: {} };
      events.push({
        // Clamped to the requested window. Jitter on the final event of a step
        // can otherwise push it a few seconds past the deadline, and
        // attack-worker schedules its finishing poll off expected_finish_at --
        // an event landing after that is one the run gets no credit for.
        offset: Math.min(requested, Math.max(0, start + frac * spread + jitter)),
        level: step.level || 'INFO',
        source: {
          type: expand(src.type || 'server', ctx, rng, seq),
          name: expand(src.name || 'unknown', ctx, rng, seq),
          host: expand(src.host || 'localhost', ctx, rng, seq),
        },
        message: expand(step.message || '', ctx, rng, seq),
        metadata: expandDeep(step.metadata || {}, ctx, rng, seq),
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
      const plan = planTimeline(playbook, { rng: makeRng(s), requested: playbook.nominal_seconds });
      await emit(plan, { out: args.out });
      s = (s + 0x9e3779b9) >>> 0;
    }
  }

  const requested = args.duration ? parseDuration(args.duration) : Number(playbook.nominal_seconds);
  let plan;
  try {
    plan = planTimeline(playbook, { rng: makeRng(seed), requested });
  } catch (err) {
    console.error(`cc-emit: ${err.message}`);
    process.exit(4);
  }

  const written = await emit(plan, {
    out: args.out,
    countFile: args['count-file'] || null,
  });
  console.log(`cc-emit: wrote ${written} event(s) over ${Math.round(requested)}s `
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
  "name": "Benign host activity",
  "story": "Ordinary process, file, package and session activity across the estate.",
  "nominal_seconds": 300,
  "entities": {},
  "pools": {
    "hosts": [
      "srv-prod-01",
      "app-server-01",
      "db-01",
      "web-01",
      "fileserv-01",
      "ws-042",
      "ws-071",
      "ws-113",
      "ws-128"
    ],
    "users": [
      "jsmith",
      "mrodriguez",
      "kchen",
      "apatel",
      "dwilson",
      "tnguyen",
      "svc_backup",
      "svc_report",
      "svc_deploy"
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
      "psql -c \"\\dt\"",
      "systemctl status nginx",
      "df -h",
      "top -b -n1"
    ],
    "files": [
      "/home/{{users}}/notes.md",
      "/var/log/messages",
      "/etc/hosts",
      "/srv/app/config.yaml"
    ],
    "pkgs": [
      "openssl",
      "curl",
      "nginx",
      "python3-pip",
      "containerd.io"
    ],
    "svcs": [
      "nginx",
      "postgresql",
      "containerd",
      "chronyd",
      "sshd"
    ],
    "tbls": [
      "orders",
      "sessions",
      "audit_log",
      "products"
    ],
    "senders": [
      "github.com",
      "atlassian.net",
      "okta.com",
      "zoom.us"
    ]
  },
  "steps": [
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 90,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "bash",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} uid={{rand:1000-1010}} user={{users}} cmd={{cmds}}",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 40,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "auditd",
        "host": "{{hosts}}"
      },
      "message": "type=PATH name=\"{{files}}\" nametype=NORMAL auid={{rand:1000-1010}} key=\"file-read\"",
      "metadata": {
        "event_action": "file-read",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 14,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "systemd",
        "host": "{{hosts}}"
      },
      "message": "Started {{svcs}}.service",
      "metadata": {
        "event_action": "service-started"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 8,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "dnf",
        "host": "{{hosts}}"
      },
      "message": "Upgraded: {{pkgs}}-{{rand:1-9}}.{{rand:0-30}}.el9",
      "metadata": {
        "event_action": "package-upgrade"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 10,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "sudo",
        "host": "{{hosts}}"
      },
      "message": "{{users}} : TTY=pts/{{rand:0-4}} ; PWD=/home/{{users}} ; USER=root ; COMMAND=/usr/bin/systemctl restart {{svcs}}",
      "metadata": {
        "event_action": "privilege-use",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 12,
      "level": "WARN",
      "technique": "T1082",
      "tactic": "TA0007",
      "source": {
        "type": "host",
        "name": "bash",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} uid={{rand:1000-1010}} user={{users}} cmd=uname -a",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 8,
      "level": "WARN",
      "technique": "T1562.001",
      "tactic": "TA0005",
      "source": {
        "type": "host",
        "name": "systemd",
        "host": "{{hosts}}"
      },
      "message": "Stopping {{svcs}}.service - scheduled maintenance window",
      "metadata": {
        "event_action": "service-stopped",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 6,
      "level": "WARN",
      "technique": "T1005",
      "tactic": "TA0009",
      "source": {
        "type": "host",
        "name": "bash",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} uid={{rand:1000-1010}} user={{users}} cmd=tar -czf /var/backups/nightly.tgz /srv/app",
      "metadata": {
        "event_action": "process-start",
        "user": "{{users}}"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 6,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "sshd",
        "host": "{{hosts}}"
      },
      "message": "Accepted publickey for {{users}} from 10.20.30.{{rand:2-60}} port {{port}} ssh2",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 4,
      "level": "WARN",
      "source": {
        "type": "authentication",
        "name": "sshd",
        "host": "{{hosts}}"
      },
      "message": "Failed password for {{users}} from 10.20.30.{{rand:2-60}} port {{port}} ssh2",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 3,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "login",
        "host": "{{hosts}}"
      },
      "message": "pam_unix(login:session): session opened for user {{users}} by LOGIN(uid=0)",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 5,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "auth-svc",
        "host": "{{hosts}}"
      },
      "message": "Token validated for {{users}} scope=read ttl={{rand:300-3600}}s",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 3,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "rdp",
        "host": "{{hosts}}"
      },
      "message": "Remote desktop session established user={{users}} src={{hosts}}",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 1,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "useradd",
        "host": "{{hosts}}"
      },
      "message": "new user: name=contractor{{rand:10-99}}, UID={{rand:2000-2400}}, GID=100",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 1,
      "level": "INFO",
      "source": {
        "type": "authentication",
        "name": "usermod",
        "host": "{{hosts}}"
      },
      "message": "add \"{{users}}\" to group \"developers\"",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 10,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "iptables",
        "host": "{{hosts}}"
      },
      "message": "ACCEPT IN=eth0 SRC=10.20.30.{{rand:2-254}} DST=10.20.30.{{rand:2-254}} PROTO=TCP SPT={{port}} DPT=443 SYN",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 4,
      "level": "WARN",
      "source": {
        "type": "firewall",
        "name": "iptables",
        "host": "{{hosts}}"
      },
      "message": "DROP IN=eth0 SRC=10.20.30.{{rand:2-254}} DST=10.20.30.{{rand:2-254}} PROTO=TCP DPT={{rand:1-1024}} SYN",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 2,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "firewalld",
        "host": "{{hosts}}"
      },
      "message": "Configuration reload requested by uid=0 pid={{pid}}",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 4,
      "level": "INFO",
      "source": {
        "type": "firewall",
        "name": "netflow",
        "host": "{{hosts}}"
      },
      "message": "Flow record: {{hosts}} -> 10.20.30.{{rand:2-60}}:443 bytes={{rand:2000-400000}} packets={{rand:8-900}}",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 8,
      "level": "INFO",
      "source": {
        "type": "webserver",
        "name": "nginx-proxy",
        "host": "{{hosts}}"
      },
      "message": "10.20.30.{{rand:2-254}} - GET /api/reports 200 {{rand:800-9000}} - Duration: {{rand:12-240}}ms",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 6,
      "level": "INFO",
      "source": {
        "type": "webserver",
        "name": "squid-proxy",
        "host": "{{hosts}}"
      },
      "message": "{{hosts}} TCP_MISS/200 {{rand:400-90000}} GET https://updates.example.com/manifest - DIRECT/updates.example.com text/json",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 3,
      "level": "INFO",
      "source": {
        "type": "server",
        "name": "nginx",
        "host": "{{hosts}}"
      },
      "message": "signal process started, worker process {{pid}} reloaded configuration",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 6,
      "level": "INFO",
      "source": {
        "type": "server",
        "name": "node-exporter",
        "host": "{{hosts}}"
      },
      "message": "CPU usage: {{rand:4-38}}% memory: {{rand:20-60}}% disk: {{rand:30-70}}%",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 8,
      "level": "INFO",
      "source": {
        "type": "database",
        "name": "postgres-primary",
        "host": "{{hosts}}"
      },
      "message": "duration: {{rand:2-180}}ms  statement: SELECT id, name FROM {{tbls}} WHERE updated_at > now() - interval '1 hour'",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 5,
      "level": "INFO",
      "source": {
        "type": "email",
        "name": "mail-gateway",
        "host": "{{hosts}}"
      },
      "message": "Message accepted for {{users}}@corp.example from noreply@{{senders}} size={{rand:2000-90000}}",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 4,
      "level": "INFO",
      "source": {
        "type": "application",
        "name": "reporting-api",
        "host": "{{hosts}}"
      },
      "message": "export completed user={{users}} rows={{rand:20-800}} format=csv",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 1,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "usermod",
        "host": "{{hosts}}"
      },
      "message": "usermod: change user contractor{{rand:10-99}} shell to /bin/bash",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 1,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "sudoers",
        "host": "{{hosts}}"
      },
      "message": "sudoers file syntax check passed (visudo -c)",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 4,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "cmd",
        "host": "{{hosts}}"
      },
      "message": "pid={{pid}} user={{users}} cmd=cmd.exe /c gpupdate /target:user",
      "metadata": {
        "event_action": "routine"
      }
    },
    {
      "overlap": true,
      "gap": "1s",
      "spread": "280s",
      "count": 3,
      "level": "INFO",
      "source": {
        "type": "host",
        "name": "registry",
        "host": "{{hosts}}"
      },
      "message": "SetValue HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Update\\LastCheck = {{rand:100000-999999}}",
      "metadata": {
        "event_action": "routine"
      }
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
        # The instructor's discriminator is log.file.path, which still differs
        # (/opt/log-generator vs /opt/log-generator-attack). Discoverable by a
        # determined student, but it is not offered up the way a dataset name is.
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
            - drop_event:
                when:
                  not:
                    has_fields: ['loggen.mitre.technique']
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
      ExecStart=/usr/bin/node /opt/cybercore/cc-emit.js --daemon         --playbook /opt/cybercore/host-baseline.json         --out /opt/log-generator/logs/current/host.json
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
  - [ systemctl, enable, loggen-baseline ]
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
  - [ sh, -c, 'grep -q "ndjson" /etc/elastic-agent/elastic-agent.yml && echo "NDJSON_PARSER=yes" >> /etc/cybercore-bake.env || echo "NDJSON_PARSER=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled loggen-rotate.timer >/dev/null 2>&1 && echo "ROTATE_TIMER=yes" >> /etc/cybercore-bake.env || echo "ROTATE_TIMER=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -s /opt/cybercore/cc-emit.js && echo "CC_EMIT=yes" >> /etc/cybercore-bake.env || echo "CC_EMIT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'node --check /opt/cybercore/cc-emit.js >/dev/null 2>&1 && echo "CC_EMIT_PARSES=yes" >> /etc/cybercore-bake.env || echo "CC_EMIT_PARSES=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -s /opt/cybercore/host-baseline.json && grep -q nominal_seconds /opt/cybercore/host-baseline.json && echo "HOST_PB=yes" >> /etc/cybercore-bake.env || echo "HOST_PB=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled cc-hostbase >/dev/null 2>&1 && echo "HOSTBASE_SERVICE=yes" >> /etc/cybercore-bake.env || echo "HOSTBASE_SERVICE=no" >> /etc/cybercore-bake.env' ]
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
check BASELINE_ENABLED     yes "loggen-baseline is not enabled — lanes would boot silent, with no noise to hide an attack in"
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
