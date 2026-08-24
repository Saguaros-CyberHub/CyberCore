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
F="$DIR/logs.json"
MAX="${1:-268435456}"
GRACE_MIN=60

[ -f "$F" ] || exit 0
SZ="$(stat -c %s "$F" 2>/dev/null || echo 0)"

# Reap log-generator's own rotation spam FIRST, and unconditionally -- it is the
# expensive problem even when logs.json is nowhere near the size cap. These are
# .jsonl, so the agent's *.json glob never ingested them; the cost is purely the
# directory enumeration filebeat does on every scan.
find "$DIR" -maxdepth 1 -name 'logs_*.jsonl' -mmin +5 -delete 2>/dev/null || true

if [ "$SZ" -ge "$MAX" ]; then
  mv "$F" "$DIR/logs-$(date +%s).json"
  systemctl restart loggen-baseline
  find "$DIR" -maxdepth 1 -name 'logs-*.json' -mmin "+$GRACE_MIN" -delete 2>/dev/null || true
fi
exit 0
LOGGEN_ROTATE_EOF
sh -n "$ROTATE_TMP" || { echo "ERROR: loggen-rotate.sh failed syntax check" >&2; exit 1; }
LOGGEN_ROTATE_B64="$(base64 -w0 "$ROTATE_TMP")"
rm -f "$ROTATE_TMP"

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
        - type: filestream
          id: loggen-attack
          data_stream.dataset: loggen.events
          paths:
            - /opt/log-generator-attack/logs/current/*.json
          parsers:
            - ndjson:
                target: loggen
                add_error_key: true
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

  # ---- Baseline RATE and MITRE labelling. See the BASELINE_FREQ_* block at the
  #      top of this script for why every value must be <= 20; the short version
  #      is that log-generator's batch path has a Math.max(1, ...) floor that
  #      pins anything above 20 to 10 logs/second regardless of its setting.
  #
  #      Retune the PRIMARY checkout only -- the copy above already has stock
  #      rates and its mitre blocks intact, which is what an attack run wants.
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
  - [ sh, -c, 'grep -q "        mitre:" /opt/log-generator-attack/src/config/default.yaml && echo "ATTACK_MITRE_KEPT=yes" >> /etc/cybercore-bake.env || echo "ATTACK_MITRE_KEPT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "ndjson" /etc/elastic-agent/elastic-agent.yml && echo "NDJSON_PARSER=yes" >> /etc/cybercore-bake.env || echo "NDJSON_PARSER=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-enabled loggen-rotate.timer >/dev/null 2>&1 && echo "ROTATE_TIMER=yes" >> /etc/cybercore-bake.env || echo "ROTATE_TIMER=no" >> /etc/cybercore-bake.env' ]
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
check ATTACK_MITRE_KEPT    yes "the attack checkout lost its mitre blocks — attack runs would be unlabelled and indistinguishable from filler in Kibana"
check NDJSON_PARSER        yes "the agent has no ndjson parser — every event lands in Kibana as one opaque JSON string with no filterable fields"
check ROTATE_TIMER         yes "loggen-rotate.timer is not enabled — logs.json grows without bound (measured: 2.5 GB in twelve hours)"

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
