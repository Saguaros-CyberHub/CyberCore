#!/bin/bash
# ============================================================================
# seal-goad-wazuh-template.sh
# ----------------------------------------------------------------------------
# ############################################################################
# # THIS SCRIPT HAS NEVER BEEN EXECUTED.                                     #
# #                                                                          #
# # Not one line of it has run on a Proxmox node, against a real Wazuh       #
# # all-in-one install, or against any VM. No template with this VMID exists #
# # on any cluster and no staging lab has ever been sealed, so nothing here  #
# # has been validated end to end and NOTHING HERE SHOULD BE TRUSTED AS      #
# # WORKING. Specifically unverified:                                        #
# #                                                                          #
# #   - that a lane's wazuh VM answers 'qm guest exec' at all. Everything    #
# #     below is that one RPC; there is no fallback and no disk-mount path   #
# #   - that the /var/ossec paths cleaned in section 2 are the 4.8 layout.   #
# #     They are read off upstream's role and docs, not off a machine        #
# #   - that wazuh-db really does recreate queue/db/global.db from           #
# #     /var/ossec/templates/*.sql after it is deleted. If it does NOT, a    #
# #     sealed clone comes up with a manager that cannot register anything   #
# #   - that the admin credential in wazuh-install-output.txt still          #
# #     authenticates against the indexer at seal time. Section 2.2 REFUSES  #
# #     on a non-200 rather than reporting a wipe it did not perform         #
# #   - whether Wazuh 4.8 stores alerts as plain indices or as data streams. #
# #     Both paths are attempted; neither has been watched                   #
# #   - whether the SOCFortress rules are present AT ALL. Upstream's role    #
# #     gates them on 'when: not ossec_folder.stat.exists', where            #
# #     ossec_folder is a stat of /var/ossec taken AFTER the manager is      #
# #     installed - so the condition is false every time and the rules step  #
# #     is SKIPPED. Section 1 checks for them and refuses; read the comment  #
# #     there before assuming your staging install was broken                #
# #   - that MIN_RULE_XML=20 is the right bar. It is a guess anchored on     #
# #     "stock ships one file"                                               #
# #   - that a clone of the template this produces boots with all three      #
# #     services healthy. That is the FIRST thing to check by hand           #
# #                                                                          #
# # Treat the FIRST run of this script as the experiment, not the deploy.    #
# # Every check below exists so that experiment fails loudly at seal time    #
# # instead of quietly in a classroom, in every lane at once.                #
# ############################################################################
#
# Takes a RUNNING, already-installed lane VM - the wazuh box from a staging
# GOAD lab that 'install_extension wazuh' has finished against - and produces a
# clean Proxmox TEMPLATE at a new VMID that clones correctly into any number of
# lanes.
#
# ----------------------------------------------------------------------------
# WHY THIS IS A SEAL SCRIPT AND NOT A BAKE SCRIPT
# ----------------------------------------------------------------------------
# GOAD ships wazuh as an EXTENSION (GOAD-main/extensions/wazuh/). Upstream's
# flow is 'install_extension wazuh', which adds an Ubuntu 22.04 server and runs
# roles/wazuh_manager on it, plus roles/wazuh_agent on every host in [domain]
# and roles/wazuh_agent_linux on [linux_domain]. CyberCore lanes DO have
# internet (bake-lane-gateway-v3.sh MASQUERADEs both subnets out wan0; the only
# FORWARD drops are scoped -d 100.100.0.0/16, the lab backbone), so that install
# genuinely runs in-lane.
#
# It costs ~25-40 minutes and ~2 GB of download EACH TIME. So the shape chosen
# is: run it ONCE against a staging lab, snapshot the result into a golden
# template, clone that forever.
#
# "Install then template" WITHOUT CORRECT CLEANUP produces failures that only
# appear ACROSS MULTIPLE LANES, which is the hardest kind to diagnose. That is
# the entire reason this file exists, and section 2 is the whole of the point.
#
# ----------------------------------------------------------------------------
# THE ONE THAT SILENTLY BREAKS MULTI-LANE: /var/ossec/etc/client.keys
# ----------------------------------------------------------------------------
# client.keys holds the agents that registered during the STAGING install. Seal
# it populated and EVERY cloned manager starts life already knowing the staging
# lab's hosts. Real lane agents then collide on agent IDs with those ghosts, and
# the symptom is agents showing as disconnected or flapping in the dashboard -
# in every lane at once, with nothing in any log explaining why.
#
# It is emptied by TRUNCATION, not deletion: ossec expects the file to exist,
# with its owner and mode intact, and a missing client.keys is its own failure.
# Section 3 verifies both facts, because a clean that silently no-ops is
# indistinguishable from one that worked right up until a classroom.
#
# The same reasoning covers everything client.keys does NOT cover but that
# outlives it: queue/rids (per-agent counters - a stale counter for an ID a lane
# agent later reuses makes that agent fail to connect, complaining about
# duplicate counters), queue/db/*.db (per-agent FIM/SCA/inventory state and the
# global agent table), queue/agents-timestamp, queue/agent-groups.
#
# ----------------------------------------------------------------------------
# WHY CLONE RATHER THAN CONVERT IN PLACE
# ----------------------------------------------------------------------------
# The staging lane VM is destroyed when the lane is torn down. Converting it in
# place would couple the golden template's existence to a lane's lifecycle -
# somebody tears down a lab and every future cohort's SIEM goes with it.
#
# Cloning also leaves the source intact, so a seal that fails at the template
# step can be retried without redoing the whole staging install. Note honestly
# that the CLEAN in section 2 happens to the SOURCE, in place: a retry works,
# but section 1's agent-history check will read zero on the second pass because
# this script already emptied it. That is expected, not a regression.
#
# ----------------------------------------------------------------------------
# THE CREDENTIAL IS THE SAME IN EVERY CLONE, AND IS WRITTEN DOWN HERE
# ----------------------------------------------------------------------------
# wazuh-install.sh generated an admin password and it is now baked into the
# image. Every clone has the same one, along with the same indexer certificates.
# That is acceptable on isolated per-student lanes and matches this repo's
# 'bake-debug' template convention - but it must be WRITTEN DOWN rather than
# discovered. Section 2.1 extracts it, persists it to
# /opt/cybercore/wazuh-credentials (0600, root), echoes it in this script's
# output, and then DELETES /opt/wazuh/wazuh-install-output.txt so the password
# lives in exactly one place inside the image rather than two.
#
# Run on the Proxmox node that holds the staging lane's wazuh VM.
# Idempotent: refuses if the target VMID already exists.
# To re-seal: qm destroy 1013 --purge
# ============================================================================
set -euo pipefail

# ---------- Source: REQUIRED, no default ----------
# The staging lane's wazuh VM, RUNNING, with the extension install finished.
# No default on purpose. A defaulted source VMID is a script that seals whatever
# happens to live at that ID on whatever node it was run on, and the failure
# mode of that is a golden template built from the wrong machine.
SRC_VMID="${SRC_VMID:-}"

# ---------- Target ----------
# 1013 is the golden WAZUH template. The neighbours matter and are refused by
# name below:
#   1011  ubuntu-lab-template   the PLAIN Ubuntu 22.04 base, no SIEM at all
#                               (bake-ubuntu-lab-template.sh; goad-deploy.js
#                               points elk, wazuh AND lx01 at it today)
#   1012  golden ELK template   (the sibling seal script)
#   1013  golden WAZUH template (this file)
VMID="${VMID:-1013}"
NAME="${NAME:-goad-wazuh-template}"
STORAGE="${STORAGE:-vmpool}"
FULL_CLONE="${FULL_CLONE:-1}"

# Resources stamped onto the CLONE. Wazuh all-in-one - manager + indexer
# (OpenSearch 2.x) + dashboard on one box - wants roughly 4 CPU / 8 GB / 50 GB
# for ~25 agents. The indexer is a JVM and it is the whole of the memory story;
# an under-provisioned clone does not fail, it stops indexing under load, which
# reads as "alerts stopped arriving" hours into a class.
TEMPLATE_MEMORY="${TEMPLATE_MEMORY:-8192}"
TEMPLATE_CORES="${TEMPLATE_CORES:-4}"
MIN_ROOT_GB="${MIN_ROOT_GB:-45}"          # warn below this; 50 GB nominal

# ---------- Where things live in the guest ----------
CRED_FILE="${CRED_FILE:-/opt/cybercore/wazuh-credentials}"
INSTALL_OUTPUT="${INSTALL_OUTPUT:-/opt/wazuh/wazuh-install-output.txt}"
STAMP_FILE="${STAMP_FILE:-/etc/cybercore-wazuh-template.env}"
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
DASHBOARD_URL="${DASHBOARD_URL:-https://127.0.0.1/}"

# ---------- Verification bars ----------
# Stock Wazuh ships ONE file in /var/ossec/etc/rules/ (local_rules.xml); the
# SOCFortress pack drops in dozens. 20 is a deliberately loose bar for
# "substantially more than a stock install" - it is a guess, not a measurement.
MIN_RULE_XML="${MIN_RULE_XML:-20}"
REQUIRE_SOCFORTRESS="${REQUIRE_SOCFORTRESS:-1}"
# Agent history is a WARNING, not a refusal. See section 1 for the judgement.
REQUIRE_AGENT_HISTORY="${REQUIRE_AGENT_HISTORY:-0}"
# Non-loopback IP literals in the indexer/filebeat/dashboard configs mean the
# staging lane's address is baked in. Set to 0 to seal anyway.
REQUIRE_LOOPBACK_CONFIG="${REQUIRE_LOOPBACK_CONFIG:-1}"
# Group DEFINITIONS under /var/ossec/etc/shared are config, not staging state,
# so non-default ones are reported and KEPT unless this is set. The per-agent
# ASSIGNMENTS in queue/agent-groups are pure staging state and always go.
REMOVE_CUSTOM_GROUPS="${REMOVE_CUSTOM_GROUPS:-0}"

# ---------- Timeouts ----------
GUEST_TIMEOUT="${GUEST_TIMEOUT:-120}"              # default per guest-exec call
GUEST_TIMEOUT_LONG="${GUEST_TIMEOUT_LONG:-600}"    # index deletes, service stops
SHUTDOWN_TIMEOUT="${SHUTDOWN_TIMEOUT:-180}"

# ============================================================================
# 0. Sanity
# ============================================================================
FAIL_ARGS=0

if [ -z "$SRC_VMID" ]; then
  echo "ERROR: SRC_VMID is required and has no default." >&2
  echo "       It is the RUNNING wazuh VM from the staging lane - the box that" >&2
  echo "       'install_extension wazuh' finished against. Find it with:" >&2
  echo "           qm list | grep -i wazuh" >&2
  echo "       Then:  SRC_VMID=<vmid> $0" >&2
  FAIL_ARGS=1
fi

if ! printf '%s' "$VMID" | grep -Eq '^[0-9]{3,9}$'; then
  echo "ERROR: VMID='$VMID' is not a VMID." >&2
  FAIL_ARGS=1
fi

# The two neighbours, refused by name. Sealing onto 1011 would overwrite the
# plain Ubuntu base that elk, wazuh AND lx01 all clone from - one command that
# takes out three machine types in every future lane. Sealing onto 1012 would
# put a Wazuh all-in-one behind the id every deploy resolves to ELK, and the
# symptom of that is a lane whose "Kibana" answers on 443 with a Wazuh login.
case "$VMID" in
  1011)
    echo "ERROR: VMID 1011 is ubuntu-lab-template - the PLAIN Ubuntu 22.04 base with" >&2
    echo "       no SIEM in it at all (bake-ubuntu-lab-template.sh). elk, wazuh and" >&2
    echo "       lx01 all clone from it. Sealing a Wazuh all-in-one onto that id takes" >&2
    echo "       out three machine types in every future lane at once." >&2
    echo "       The golden wazuh template is 1013." >&2
    FAIL_ARGS=1
    ;;
  1012)
    echo "ERROR: VMID 1012 is the golden ELK template, not the wazuh one. A Wazuh" >&2
    echo "       all-in-one sitting behind the id every deploy resolves to ELK gives" >&2
    echo "       you a lane whose 'Kibana' answers with a Wazuh login and an incident" >&2
    echo "       pipeline that ships to nothing." >&2
    echo "       The golden wazuh template is 1013." >&2
    FAIL_ARGS=1
    ;;
esac

if [ -n "$SRC_VMID" ] && [ "$SRC_VMID" = "$VMID" ]; then
  echo "ERROR: SRC_VMID and VMID are both '$VMID'. This script CLONES the source to a" >&2
  echo "       NEW id and templates the clone; it never converts the source in place." >&2
  echo "       See the header for why that separation is deliberate." >&2
  FAIL_ARGS=1
fi

case "$SRC_VMID" in
  1011|1012|1013)
    echo "ERROR: SRC_VMID=$SRC_VMID is a TEMPLATE id, not a staging lane VM." >&2
    echo "       The source must be a running, already-installed lane machine." >&2
    FAIL_ARGS=1
    ;;
esac

[ "$FAIL_ARGS" -ne 0 ] && exit 1

command -v qm >/dev/null 2>&1 || {
  echo "ERROR: 'qm' not found. Run this on the Proxmox node that holds the staging lane." >&2
  exit 1
}

if ! qm status "$SRC_VMID" >/dev/null 2>&1; then
  echo "ERROR: source VM $SRC_VMID does not exist on this node." >&2
  echo "       Run this on the node that holds the staging lane, or set SRC_VMID." >&2
  echo "       Check:  qm list ; pvesh get /cluster/resources --type vm" >&2
  exit 1
fi

SRC_STATUS="$(qm status "$SRC_VMID" | awk '{print $2}')"
if [ "$SRC_STATUS" != "running" ]; then
  echo "ERROR: source VM $SRC_VMID is '$SRC_STATUS', not running." >&2
  echo "       Every check and every clean below goes over the guest agent, which needs" >&2
  echo "       a booted guest. Start it, let the three Wazuh services come up, then" >&2
  echo "       re-run:" >&2
  echo "           qm start $SRC_VMID" >&2
  exit 1
fi

if qm config "$SRC_VMID" 2>/dev/null | grep -q '^template:[[:space:]]*1'; then
  echo "ERROR: source VM $SRC_VMID is already a TEMPLATE." >&2
  echo "       Templates do not run and cannot be cleaned. Point SRC_VMID at the" >&2
  echo "       staging lane's live wazuh VM." >&2
  exit 1
fi

if qm status "$VMID" >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy it first, deliberately:" >&2
  echo "           qm destroy $VMID --purge" >&2
  echo "       This script never overwrites an existing template - a half-replaced" >&2
  echo "       golden image is worse than no golden image." >&2
  exit 1
fi
if pct status "$VMID" >/dev/null 2>&1; then
  echo "ERROR: an LXC container already exists at VMID $VMID." >&2
  exit 1
fi

echo "==> Sealing wazuh staging VM $SRC_VMID -> template $VMID ($NAME)"
echo "    Storage         : $STORAGE  (full clone: $FULL_CLONE)"
echo "    Credential file : $CRED_FILE  (inside the image, 0600 root)"

# ============================================================================
# 0b. Guest-exec plumbing
# ----------------------------------------------------------------------------
# Everything this script does to the guest goes through 'qm guest exec', which
# returns JSON on stdout, pretty-printed one key per line:
#
#     {
#        "exitcode" : 0,
#        "exited" : 1,
#        "out-data" : "KEY=value\nKEY2=value2\n"
#     }
#
# TWO TRAPS, both of which produce a silent wrong answer rather than an error:
#
#  1. out-data is a JSON STRING. The file's real newlines arrive as the
#     two-character escape \n. Decode with printf %b or the whole payload parses
#     as ONE line, and every marker after the first reads as part of the first
#     one's value - which looks exactly like a clean that did nothing, on a
#     clean that did everything.
#
#  2. 'qm guest exec' ITSELF succeeds when the guest command fails. The guest's
#     status is in the JSON "exitcode" field, not in $?. A check written as
#     'qm guest exec ... && echo ok' says ok for a command that did not exist.
#     So every call below reads GUEST_RC explicitly.
#
# The out-data capture uses an escape-aware match rather than [^"]* so that a
# value containing a quote does not truncate the payload at the quote. It still
# assumes one key per line. GUEST SCRIPTS MUST NOT EMIT DOUBLE QUOTES: every
# marker below is a bare KEY=value for that reason.
# ----------------------------------------------------------------------------
GUEST_OUT=""
GUEST_RC=""
GUEST_RAW=""

gexec() {  # gexec <timeout> <sh -c command string>   -> GUEST_OUT, GUEST_RC
  local timeout="$1" cmd="$2"
  GUEST_OUT=""; GUEST_RC=""; GUEST_RAW=""
  if ! GUEST_RAW="$(qm guest exec "$SRC_VMID" --timeout "$timeout" -- /bin/sh -c "$cmd" 2>&1)"; then
    GUEST_RC="qm-failed"
    return 1
  fi
  GUEST_OUT="$(printf '%s\n' "$GUEST_RAW" \
    | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\(\(\\.\|[^"\\]\)*\)".*/\1/p' | head -1)"
  GUEST_OUT="$(printf '%b' "$GUEST_OUT")"
  GUEST_RC="$(printf '%s\n' "$GUEST_RAW" \
    | sed -n 's/.*"exitcode"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9]\{1,\}\).*/\1/p' | head -1)"
  [ -n "$GUEST_RC" ] || GUEST_RC="no-exitcode"
  return 0
}

# Run a multi-line script in the guest. base64 on the HOST so that no quote,
# dollar sign or backtick in the script has to survive a shell command line -
# the same reasoning bake-caldera-server.sh and bake-cybr400-loggen-template.sh
# use for their cloud-init payloads. The staged file is removed whether the
# script succeeded or not, and the guest's exit status is preserved through it.
GUEST_STAGE="/tmp/.cybercore-seal.sh"
gscript() {  # gscript <timeout> <script text>   -> GUEST_OUT, GUEST_RC
  local timeout="$1" script="$2" b64
  b64="$(printf '%s\n' "$script" | base64 -w0)"
  gexec "$timeout" "printf %s '$b64' | base64 -d > $GUEST_STAGE && /bin/sh $GUEST_STAGE; rc=\$?; rm -f $GUEST_STAGE; exit \$rc"
}

# Host-side marker reader. Values may contain '=' (URLs, config fragments), so
# the split is on the FIRST '=' only.
mval() {  # mval <key> <marker blob>
  printf '%s\n' "$2" | awk -F= -v k="$1" '$1==k { sub(/^[^=]*=/, ""); print; exit }'
}

# Values the guest scripts need. Passed as a prelude of shell assignments
# prepended to the script text rather than interpolated into it, so a path with
# a space or a shell metacharacter cannot rewrite the script around it.
guest_prelude() {
  cat <<PRELUDE
CRED_FILE='${CRED_FILE}'
INSTALL_OUTPUT='${INSTALL_OUTPUT}'
STAMP_FILE='${STAMP_FILE}'
INDEXER_URL='${INDEXER_URL}'
DASHBOARD_URL='${DASHBOARD_URL}'
REMOVE_CUSTOM_GROUPS='${REMOVE_CUSTOM_GROUPS}'
SEAL_SRC_VMID='${SRC_VMID}'
SEAL_TEMPLATE_VMID='${VMID}'
PRELUDE
}

# Prove the guest agent answers BEFORE any of the interesting work. A VM that is
# 'running' with a dead or RPC-blacklisted agent looks perfectly healthy from
# the outside and fails every single step below with an empty result.
echo "==> Checking the guest agent answers"
if ! gexec 30 'echo GUEST_AGENT_OK'; then
  echo "ERROR: 'qm guest exec $SRC_VMID' failed outright." >&2
  echo "       qm agent $SRC_VMID ping" >&2
  echo "       Inside the guest: systemctl status qemu-guest-agent" >&2
  echo "       If ping works and exec does not, the agent package's RPC blacklist is" >&2
  echo "       in force - clear BLACKLIST_RPC / BLOCK_RPCS in the guest's qemu-ga" >&2
  echo "       config and restart the agent. Every step in this script is guest-exec." >&2
  exit 1
fi
if [ "$GUEST_OUT" != "GUEST_AGENT_OK" ] || [ "$GUEST_RC" != "0" ]; then
  echo "ERROR: the guest agent answered but did not run the command (rc=$GUEST_RC)." >&2
  echo "       Raw response:" >&2
  printf '%s\n' "$GUEST_RAW" >&2
  exit 1
fi

# ============================================================================
# 1. PRE-CLEAN VERIFICATION
# ----------------------------------------------------------------------------
# Confirm this really is the machine we think it is, and that the install
# actually succeeded, BEFORE touching anything.
#
# Sealing a half-installed box into a golden template is the worst outcome
# available here, because IT LOOKS LIKE IT WORKED: the clone boots, the
# dashboard loads, and the thing that is missing (rules, a decoder, a service
# that is running but not enabled) only shows up when a student asks the SIEM a
# question it cannot answer.
#
# Everything in this section that does NOT depend on the clean is checked HERE
# rather than after it, on purpose: a refusal at this point costs nothing, while
# the same refusal after section 2 leaves a staging lab whose agent history has
# already been deleted.
# ============================================================================
echo "==> Pre-clean verification"

read -r -d '' PRECLEAN_SH <<'PRECLEAN_EOF' || true
# Markers are bare KEY=value, one per line, and MUST NOT contain double quotes
# (the host's out-data parser stops at the first unescaped one).
m()  { printf '%s=%s\n' "$1" "$2"; }
yn() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }
svc() { m "${1}_ACTIVE" "$(yn systemctl is-active --quiet "$2")"
        m "${1}_ENABLED" "$(yn systemctl is-enabled --quiet "$2")"; }

# ---- Identity: is this the machine we think it is ----
m SEAL_HOSTNAME "$(hostname 2>/dev/null)"
m OS_PRETTY     "$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}" | tr -d '"')"
m OSSEC_DIR     "$(yn test -d /var/ossec)"
m OSSEC_CONF    "$(yn test -f /var/ossec/etc/ossec.conf)"
m WAZUH_CONTROL "$(yn test -x /var/ossec/bin/wazuh-control)"
INFO="$(/var/ossec/bin/wazuh-control info 2>/dev/null | tr -d '"')"
m WAZUH_VERSION  "$(printf '%s\n' "$INFO" | sed -n 's/^WAZUH_VERSION=//p'  | head -1)"
m WAZUH_REVISION "$(printf '%s\n' "$INFO" | sed -n 's/^WAZUH_REVISION=//p' | head -1)"
# WAZUH_TYPE is 'server' on a manager and 'agent' on an agent. It is the one
# cheap way to catch SRC_VMID pointing at the wrong box entirely.
m WAZUH_TYPE     "$(printf '%s\n' "$INFO" | sed -n 's/^WAZUH_TYPE=//p'     | head -1)"

# ---- The three services of the all-in-one, plus the two that carry it ----
# ACTIVE proves the install finished. ENABLED is what decides whether a CLONE
# comes up as a SIEM or as an Ubuntu box with a dashboard nobody can reach -
# and a service that is running-but-not-enabled looks identical to a healthy
# one from every angle except a reboot.
svc MANAGER   wazuh-manager
svc INDEXER   wazuh-indexer
svc DASHBOARD wazuh-dashboard
# filebeat is how the manager's alerts reach the indexer. Not one of the three
# the install script names, and warned about rather than refused for that
# reason - but a clone without it has a dashboard that never shows an alert.
svc FILEBEAT  filebeat
# Without an enabled guest agent, nothing can reach a clone to configure it.
svc QGA       qemu-guest-agent

# ---- Do the two web surfaces answer ----
m DASHBOARD_HTTP "$(curl -sk -o /dev/null -m 25 -w '%{http_code}' "$DASHBOARD_URL" 2>/dev/null)"
# 401 here is a PASS: the indexer is listening and its security plugin is up.
# A connection failure gives an empty body and 000.
m INDEXER_HTTP   "$(curl -sk -o /dev/null -m 25 -w '%{http_code}' "$INDEXER_URL" 2>/dev/null)"

# ---- Did the SOCFortress rules land ----
# Stock ships exactly one file here (local_rules.xml). The pack drops in dozens
# and also MOVES a handful of decoders into etc/decoders, which is why
# decoder-linux-sysmon.xml is a second, independent witness.
m RULES_XML_COUNT     "$(find /var/ossec/etc/rules     -maxdepth 1 -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')"
m DECODERS_XML_COUNT  "$(find /var/ossec/etc/decoders  -maxdepth 1 -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')"
m SOCFORTRESS_DECODER "$(yn test -f /var/ossec/etc/decoders/decoder-linux-sysmon.xml)"

# ---- The rootkit_trojans /bin/diff false positive (wazuh issue 19000) ----
# The role patches [^n] to [^nf] with lineinfile. A missing patch means the role
# did not get that far. A patch that is present ALONGSIDE the original means
# lineinfile appended instead of replacing, and the false positive still fires.
RK=/var/ossec/etc/rootcheck/rootkit_trojans.txt
m ROOTKIT_FILE "$(yn test -f $RK)"
m ROOTKIT_FIX  "$(yn grep -qF '/dev/[^nf]' $RK)"
m ROOTKIT_OLD  "$(yn grep -qF '/dev/[^n]|' $RK)"

# ---- Did any agent ever enrol ----
# client.keys is the ground truth; agent_control is the cross-check. ID 000 is
# the manager itself and is counted by agent_control but never appears in
# client.keys, so the two numbers differ by one on a healthy box.
CK=/var/ossec/etc/client.keys
m CLIENT_KEYS_FILE  "$(yn test -f $CK)"
m CLIENT_KEYS_LINES "$(awk 'NF { n++ } END { print n+0 }' $CK 2>/dev/null || echo 0)"
m CLIENT_KEYS_META  "$(stat -c %U:%G:%a $CK 2>/dev/null)"
m CLIENT_KEYS_NAMES "$(awk '{ printf "%s ", $2 }' $CK 2>/dev/null)"
m AGENT_CONTROL_IDS "$(/var/ossec/bin/agent_control -l 2>/dev/null | awk '/ID:/ { n++ } END { print n+0 }')"

# ---- Is anything in this image pointed at the STAGING lane's address ----
# wazuh-install.sh -a wires the all-in-one to 127.0.0.1 throughout. A non-loop-
# back literal in any of these three files is the staging lane's own IP baked
# into every clone - and the staging lane will not exist when the clone boots.
FOREIGN="$(grep -rhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
             /etc/wazuh-indexer/opensearch.yml \
             /etc/filebeat/filebeat.yml \
             /etc/wazuh-dashboard/opensearch_dashboards.yml 2>/dev/null \
           | grep -vE '^(127\.|0\.0\.0\.0$)' | sort -u | tr '\n' ' ')"
m FOREIGN_IPS "${FOREIGN:--}"

# ---- Addressing: DHCP and nothing but DHCP ----
# The lane's MAC-pinned dnsmasq reservation is the only thing that decides this
# machine's IP. A static address baked into the image that disagrees with the
# reservation produces no error anywhere - just a healthy machine at the wrong
# address that every agent in the lane tries to ship past.
#
# Parsed as YAML rather than grepped, because a netplan 'nameservers:' block
# ALSO contains the key 'addresses:' and a naive grep calls every DHCP image
# static.
NETPLAN_RESULT="$(python3 - <<'PY' 2>/dev/null || true
import glob, yaml
static, dhcp = [], []
for path in sorted(glob.glob('/etc/netplan/*.yaml') + glob.glob('/etc/netplan/*.yml')):
    try:
        doc = yaml.safe_load(open(path)) or {}
    except Exception:
        print('PARSE_ERROR'); raise SystemExit
    net = doc.get('network') or {}
    for kind in ('ethernets', 'bonds', 'bridges', 'vlans'):
        for name, cfg in (net.get(kind) or {}).items():
            cfg = cfg or {}
            if cfg.get('addresses'):
                static.append('%s/%s' % (path, name))
            if cfg.get('dhcp4') in (True, 'true', 'yes', 'on'):
                dhcp.append(name)
print('static=%s dhcp=%s' % (','.join(static) or '-', ','.join(dhcp) or '-'))
PY
)"
case "$NETPLAN_RESULT" in
  ""|PARSE_ERROR*) m NETPLAN_PARSED no ;;
  *)               m NETPLAN_PARSED yes ;;
esac
case "$NETPLAN_RESULT" in
  *"static=-"*) m NETPLAN_STATIC no ;;
  *)            m NETPLAN_STATIC yes ;;
esac
case "$NETPLAN_RESULT" in
  *"dhcp=-"*) m NETPLAN_DHCP4 no ;;
  *dhcp=*)    m NETPLAN_DHCP4 yes ;;
  *)          m NETPLAN_DHCP4 unknown ;;
esac
m NETPLAN_DETAIL "${NETPLAN_RESULT:-none}"
# The other two places a static address hides on a Debian-family image.
m NETWORKD_STATIC "$(yn grep -rhqE '^[[:space:]]*Address=' /etc/systemd/network/)"
m ENI_STATIC      "$(yn grep -rhqE '^[[:space:]]*iface[[:space:]]+.*[[:space:]]static' /etc/network/interfaces /etc/network/interfaces.d/)"
# If cloud-init's network handling is disabled in the image, the clone keeps
# whatever netplan this staging lane left behind instead of rendering its own
# lane's 'ipconfig0: ip=dhcp' - a static-by-accident, on an interface name that
# may not even exist in the clone.
m CI_NET_DISABLED "$(yn grep -rlqE 'network:[[:space:]]*\{?[[:space:]]*config:[[:space:]]*disabled' /etc/cloud/cloud.cfg.d/)"

# ---- Capacity, measured rather than assumed ----
m ROOT_FS_GB  "$(df -BG --output=size / 2>/dev/null | awk 'NR==2 { gsub(/[^0-9]/, ""); print }')"
m MEM_TOTAL_MB "$(awk '/MemTotal/ { printf "%d", $2/1024 }' /proc/meminfo)"
m CPU_COUNT   "$(nproc 2>/dev/null)"

# ---- Where the credential currently lives, and whether this box was sealed before
m INSTALL_OUTPUT_PRESENT "$(yn test -f "$INSTALL_OUTPUT")"
m CRED_FILE_PRESENT      "$(yn test -f "$CRED_FILE")"
m ALREADY_SEALED         "$(yn test -f "$STAMP_FILE")"
# wazuh-install.sh also drops a tar holding EVERY certificate and password it
# generated. Reported, never deleted blindly: see the hand-off block.
m INSTALL_FILES_TAR "$(find /root /home /opt /tmp /var/tmp -maxdepth 3 -name 'wazuh-install-files.tar' 2>/dev/null | tr '\n' ' ')"
exit 0
PRECLEAN_EOF

if ! gscript "$GUEST_TIMEOUT" "$(guest_prelude)
$PRECLEAN_SH"; then
  echo "ERROR: could not run the pre-clean checks in the guest." >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl status wazuh-manager'" >&2
  exit 1
fi
PRE_ENV="$GUEST_OUT"
if [ -z "$PRE_ENV" ]; then
  echo "ERROR: the pre-clean check produced no output at all (rc=$GUEST_RC)." >&2
  echo "       Raw guest response:" >&2
  printf '%s\n' "$GUEST_RAW" >&2
  echo "       Nothing has been changed. Do not seal on the strength of an empty result:" >&2
  echo "       an empty marker set passes no check and fails no check." >&2
  exit 1
fi

FAIL=0
WARN=0
pget() { mval "$1" "$PRE_ENV"; }
check() {  # check <marker> <expected> <what breaks if it is wrong>
  local got; got="$(pget "$1")"
  printf '    %-24s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    FAIL=1
  fi
}
warn() {  # warn <marker> <expected> <why it matters>
  local got; got="$(pget "$1")"
  printf '    %-24s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    WARNING: $3" >&2
    WARN=1
  fi
}
show() { printf '    %-24s %s\n' "$1:" "$(pget "$1")"; }

show SEAL_HOSTNAME
show OS_PRETTY
show WAZUH_VERSION
show WAZUH_REVISION

# ---- Identity ----
check OSSEC_DIR     yes "there is no /var/ossec on VM $SRC_VMID. This is not a Wazuh machine at all - check SRC_VMID against 'qm list'"
check OSSEC_CONF    yes "/var/ossec/etc/ossec.conf is missing, so whatever is on this box is not a working Wazuh install"
check WAZUH_CONTROL yes "/var/ossec/bin/wazuh-control is missing or not executable - the install did not finish"
check WAZUH_TYPE    server "this box reports WAZUH_TYPE='$(pget WAZUH_TYPE)', not 'server'. SRC_VMID is pointing at a wazuh AGENT, not the manager. Sealing an agent as the golden manager template gives every lane a SIEM that is itself an agent of a machine that no longer exists"

# ---- The three services ----
# ACTIVE and ENABLED are separate failures with separate symptoms, so they are
# separate checks. A clone of an image whose services are active-but-disabled
# comes up with nothing listening and nothing in any log to say why.
check MANAGER_ACTIVE    yes "wazuh-manager is not running. Read 'journalctl -u wazuh-manager -n 80' and /var/ossec/logs/ossec.log on the source before anything else - a manager that will not start is the install failing, not the seal"
check MANAGER_ENABLED   yes "wazuh-manager is not ENABLED. It happens to be running now; a clone would boot with no manager at all, and the dashboard would load and show nothing forever"
check INDEXER_ACTIVE    yes "wazuh-indexer is not running. Nothing can be wiped through its API in section 2.2, which means the staging lab's alerts would ship inside the template"
check INDEXER_ENABLED   yes "wazuh-indexer is not ENABLED - a clone boots with no index and the dashboard shows a red cluster"
check DASHBOARD_ACTIVE  yes "wazuh-dashboard is not running"
check DASHBOARD_ENABLED yes "wazuh-dashboard is not ENABLED - a clone boots with nothing on 443, which reads to a student as 'the lane is broken'"
check QGA_ENABLED       yes "qemu-guest-agent is not enabled. It answers now, but a CLONE would boot with no agent and nothing could reach it to configure, inspect or repair it"
warn  FILEBEAT_ACTIVE   yes "filebeat is not running. It is what carries the manager's alerts into the indexer, so a clone would have a healthy manager, a healthy dashboard, and no alert ever appearing in it. Not one of the three services the installer names, which is the only reason this is a warning"
warn  FILEBEAT_ENABLED  yes "filebeat is not enabled - same failure as above, one reboot later"

# ---- The dashboard actually answers ----
DASH_HTTP="$(pget DASHBOARD_HTTP)"
printf '    %-24s %s\n' "DASHBOARD_HTTP:" "${DASH_HTTP:-unset}"
case "$DASH_HTTP" in
  200|302) : ;;
  *)
    echo "    ERROR: https://127.0.0.1/ answered '${DASH_HTTP:-nothing}', expected 200 or 302." >&2
    echo "           000 means nothing is listening on 443. Anything else means the" >&2
    echo "           dashboard is up but broken - usually it cannot reach the indexer," >&2
    echo "           which is the one failure a clone inherits perfectly." >&2
    echo "           journalctl -u wazuh-dashboard -n 80 --no-pager" >&2
    FAIL=1
    ;;
esac
IDX_HTTP="$(pget INDEXER_HTTP)"
printf '    %-24s %s\n' "INDEXER_HTTP:" "${IDX_HTTP:-unset}"
case "$IDX_HTTP" in
  # 401 is the healthy answer: it is listening and its security plugin is up.
  200|401) : ;;
  *)
    echo "    ERROR: the indexer answered '${IDX_HTTP:-nothing}' on $INDEXER_URL." >&2
    echo "           Section 2.2 wipes the staging lab's alerts through that API. If it" >&2
    echo "           is not answering, this seal cannot clean the data and must not run." >&2
    FAIL=1
    ;;
esac

# ---- The SOCFortress rules ----
RULES_N="$(pget RULES_XML_COUNT)"
printf '    %-24s %s (bar: %s)\n' "RULES_XML_COUNT:" "${RULES_N:-unset}" "$MIN_RULE_XML"
show DECODERS_XML_COUNT
show SOCFORTRESS_DECODER
if [ "$REQUIRE_SOCFORTRESS" = "1" ]; then
  if ! printf '%s' "${RULES_N:-0}" | grep -Eq '^[0-9]+$' || [ "${RULES_N:-0}" -lt "$MIN_RULE_XML" ]; then
    echo "    ERROR: only ${RULES_N:-0} .xml files in /var/ossec/etc/rules/ (bar: $MIN_RULE_XML)." >&2
    echo "           A stock install has ONE (local_rules.xml). This install has close to" >&2
    echo "           stock, which means the SOCFortress pack never landed." >&2
    echo "" >&2
    echo "           READ THIS BEFORE BLAMING YOUR STAGING RUN. Upstream's role gates the" >&2
    echo "           rules on:" >&2
    echo "               when: not ossec_folder.stat.exists" >&2
    echo "           where ossec_folder is a stat of /var/ossec registered AFTER the" >&2
    echo "           manager has been installed and started. /var/ossec therefore always" >&2
    echo "           exists by then, the condition is always false, and BOTH SOCFortress" >&2
    echo "           tasks are skipped on every run. Upstream ships this; your lab did" >&2
    echo "           not break it." >&2
    echo "" >&2
    echo "           Fix it on the staging box by hand, then re-run this seal:" >&2
    echo "               qm guest exec $SRC_VMID -- /bin/sh -c 'apt-get install -y git'" >&2
    echo "               # copy roles/wazuh_manager/files/wazuh_socfortress_rules.sh in," >&2
    echo "               # then: bash /opt/wazuh/wazuh_socfortress_rules.sh" >&2
    echo "           Or seal without the pack deliberately: REQUIRE_SOCFORTRESS=0" >&2
    echo "           - the manager works, it just detects a great deal less." >&2
    FAIL=1
  fi
  if [ "$(pget SOCFORTRESS_DECODER)" != "yes" ]; then
    echo "    ERROR: /var/ossec/etc/decoders/decoder-linux-sysmon.xml is absent." >&2
    echo "           The rules script MOVES that decoder out of the rules directory as its" >&2
    echo "           last act, so its absence with a high rule count means the pack was" >&2
    echo "           half-applied - rules present, decoders missing, and every rule that" >&2
    echo "           depends on them silently never fires." >&2
    FAIL=1
  fi
else
  echo "    NOTE: REQUIRE_SOCFORTRESS=0 - sealing a manager with stock rules only." >&2
fi

# ---- The rootkit_trojans false-positive fix ----
check ROOTKIT_FILE yes "/var/ossec/etc/rootcheck/rootkit_trojans.txt does not exist, so the role's patch task could not have run and the install did not complete"
check ROOTKIT_FIX  yes "the /bin/diff false-positive fix (wazuh issue 19000) is NOT present in rootkit_trojans.txt. The role patches that line; a missing patch means roles/wazuh_manager did not run to completion, and everything after it in the role - including the credential extraction this seal depends on - is equally suspect"
warn  ROOTKIT_OLD  no  "the ORIGINAL unpatched line is still present alongside the fixed one. Ansible's lineinfile appended instead of replacing, so rootcheck still matches /bin/diff and every clone will raise the same false positive on every Linux agent, forever"

# ---- Did agents actually enrol during staging ----
# JUDGEMENT, stated plainly: this is a WARNING, not a refusal. Unlike the elk
# side - where winlogbeat's index templates and dashboards are loaded into
# Elasticsearch BY the agents during the install, so an elk box with no agent
# history is genuinely missing something - a Wazuh manager with no agent history
# is still a perfectly good manager. Agents re-enrol in each lane anyway, and
# nothing about a lane agent depends on a staging agent having existed.
#
# It is still worth knowing, loudly: no enrolment means roles/wazuh_agent never
# reached a single Windows host, so the staging install did not work end to end
# and whatever broke it will break again in the lane.
CK_LINES="$(pget CLIENT_KEYS_LINES)"
printf '    %-24s %s\n' "CLIENT_KEYS_LINES:" "${CK_LINES:-unset}"
show CLIENT_KEYS_NAMES
show AGENT_CONTROL_IDS
show CLIENT_KEYS_META
check CLIENT_KEYS_FILE yes "/var/ossec/etc/client.keys does not exist. ossec expects that file to be present even when empty; its absence means this is not a completed manager install"
if [ "${CK_LINES:-0}" = "0" ]; then
  echo "" >&2
  echo "    ****************************************************************" >&2
  echo "    * NO AGENT EVER ENROLLED ON THIS MANAGER.                      *" >&2
  echo "    ****************************************************************" >&2
  echo "    client.keys is empty, so roles/wazuh_agent never successfully reached a" >&2
  echo "    single Windows host during the staging install. The manager itself is" >&2
  echo "    fine and this template will work - agents re-enrol per lane and carry" >&2
  echo "    nothing over from staging - so this is NOT a reason to discard the" >&2
  echo "    install. It IS a sign the staging run did not complete end to end, and" >&2
  echo "    whatever stopped the agents there will stop them in a lane too." >&2
  echo "" >&2
  echo "    Check on the staging controller before you rely on this template:" >&2
  echo "      - did install_extension wazuh report failures on the [domain] hosts" >&2
  echo "      - can the Windows hosts reach the manager on 1514/1515" >&2
  echo "      - did the agent MSI install at all (services.msc -> WazuhSvc)" >&2
  echo "    Set REQUIRE_AGENT_HISTORY=1 to make this a refusal instead." >&2
  echo "" >&2
  WARN=1
  if [ "$REQUIRE_AGENT_HISTORY" = "1" ]; then
    echo "    ERROR: REQUIRE_AGENT_HISTORY=1 and no agent ever enrolled." >&2
    FAIL=1
  fi
fi

# ---- Nothing pointed at the staging lane's own address ----
FOREIGN_IPS="$(pget FOREIGN_IPS)"
printf '    %-24s %s\n' "FOREIGN_IPS:" "${FOREIGN_IPS:--}"
if [ -n "$FOREIGN_IPS" ] && [ "$FOREIGN_IPS" != "-" ]; then
  echo "    WARNING: non-loopback IP literals appear in the indexer/filebeat/dashboard" >&2
  echo "             configs: $FOREIGN_IPS" >&2
  echo "             wazuh-install.sh -a wires an all-in-one to 127.0.0.1 throughout, so" >&2
  echo "             these are almost certainly the STAGING LANE's own address - baked" >&2
  echo "             into every clone, pointing at a machine that will not exist when" >&2
  echo "             the clone boots. The symptom is a dashboard that loads and a" >&2
  echo "             cluster that is permanently red." >&2
  echo "             Fix the config on the source and re-run, or seal anyway with" >&2
  echo "             REQUIRE_LOOPBACK_CONFIG=0." >&2
  WARN=1
  [ "$REQUIRE_LOOPBACK_CONFIG" = "1" ] && FAIL=1
fi

# ---- DHCP and nothing but DHCP ----
check NETPLAN_PARSED yes "netplan could not be parsed, so the static-address check below proved NOTHING. Install python3-yaml on the source or read /etc/netplan/*.yaml by hand before sealing - this check is the only thing standing between a baked-in address and a set of lanes where every agent ships nowhere"
show  NETPLAN_DETAIL
check NETPLAN_STATIC no  "a STATIC address is configured in netplan. The lane's MAC-pinned dnsmasq reservation is what decides this machine's IP; an address baked into the template that disagrees with the reservation produces no error anywhere - just a healthy machine at the wrong address that every agent in the lane tries to ship past"
check NETWORKD_STATIC no "a static Address= is configured under /etc/systemd/network/. Same failure as a static netplan, in the other place it hides"
check ENI_STATIC     no  "a static iface is configured in /etc/network/interfaces. Same failure again"
check CI_NET_DISABLED no "cloud-init network configuration is DISABLED in this image. Clones would keep the STAGING LANE's netplan instead of rendering their own lane's 'ipconfig0: ip=dhcp' - a static-by-accident, on an interface name that may not even exist in the clone"
warn  NETPLAN_DHCP4  yes "netplan declares no dhcp4 interface at all. If neither DHCP nor a static address is configured, the clone comes up with no network and there is nothing in the image to say so"

# ---- Capacity ----
ROOT_GB="$(pget ROOT_FS_GB)"
printf '    %-24s %s GB (bar: %s GB)\n' "ROOT_FS_GB:" "${ROOT_GB:-?}" "$MIN_ROOT_GB"
show MEM_TOTAL_MB
show CPU_COUNT
if printf '%s' "${ROOT_GB:-0}" | grep -Eq '^[0-9]+$' && [ "${ROOT_GB:-0}" -lt "$MIN_ROOT_GB" ]; then
  echo "    WARNING: the root filesystem is ${ROOT_GB} GB. A Wazuh all-in-one wants ~50 GB" >&2
  echo "             for ~25 agents; the indexer is what fills it. A disk that is a floor" >&2
  echo "             for every clone is worth getting right BEFORE the template exists," >&2
  echo "             because growing a template's disk after the fact does not grow the" >&2
  echo "             filesystems of the clones already made from it." >&2
  WARN=1
fi

# ---- Prior seal ----
if [ "$(pget ALREADY_SEALED)" = "yes" ]; then
  echo "    NOTE: $STAMP_FILE already exists - this box has been through this script" >&2
  echo "          before. That is fine (a retry after a failed clone is exactly the" >&2
  echo "          supported case) but the agent-history check above will read zero on" >&2
  echo "          every pass after the first, because this script emptied it." >&2
fi
show INSTALL_OUTPUT_PRESENT
show INSTALL_FILES_TAR

if [ "$FAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: pre-clean verification failed. NOTHING HAS BEEN CHANGED." >&2
  echo "       VM $SRC_VMID is untouched and still running; no clone and no template" >&2
  echo "       has been created. Fix the source, then re-run." >&2
  echo "" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'journalctl -u wazuh-manager -n 80 --no-pager'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'tail -60 /var/ossec/logs/ossec.log'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c '/var/ossec/bin/wazuh-control status'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'ls -la /var/ossec/etc/rules | head -30'" >&2
  exit 1
fi
if [ "$WARN" -ne 0 ]; then
  echo "==> Pre-clean verification passed, WITH WARNINGS above. Read them."
else
  echo "==> Pre-clean verification passed"
fi

# ============================================================================
# 2. CLEAN
# ----------------------------------------------------------------------------
# ORDER MATTERS HERE AND THE ORDER IS NOT THE OBVIOUS ONE.
#
#   2.0  stop the manager, filebeat and the dashboard - but LEAVE THE INDEXER UP
#   2.1  extract the credential while its source file still exists
#   2.2  wipe the staging lab's alert data through the indexer API (needs it up)
#   2.3  clear the agent registry and every scrap of per-agent state on disk
#   2.4  stop the indexer, so it flushes
#   2.5  delete the installer output, stamp the image
#   2.6  wipe /var/ossec/logs, once nothing is left to write to it
#   2.7  image hygiene: machine-id, host keys, cloud-init, journal, histories
#
# WHY THE MANAGER GOES FIRST: wazuh-authd and wazuh-db hold the agent registry
# in memory and rewrite client.keys and queue/db on shutdown. Truncating those
# files under a live manager is a clean that undoes itself thirty seconds later,
# at shutdown, with nothing anywhere reporting that it happened.
#
# WHY THE INDEXER GOES LAST: section 2.2 talks to its REST API. Stopping it
# first would leave the only workable path to the staging lab's alerts closed,
# and the fallback - deleting its data directory - destroys far more than
# alerts (see 2.2).
# ============================================================================

# ---------- 2.0 Stop the writers, keep the indexer ----------
echo "==> [2.0] Stopping wazuh-manager, filebeat and wazuh-dashboard"
gscript "$GUEST_TIMEOUT_LONG" '
# The dashboard first so nothing is querying, then filebeat so nothing is
# shipping, then the manager itself. The indexer stays up for 2.2.
systemctl stop wazuh-dashboard 2>/dev/null || true
systemctl stop filebeat        2>/dev/null || true
systemctl stop wazuh-manager   2>/dev/null || true
# wazuh-control stop is the supported way to be sure every ossec daemon is down
# (analysisd, remoted, authd, db, modulesd), not just the unit wrapper.
/var/ossec/bin/wazuh-control stop >/dev/null 2>&1 || true
echo STOPPED_WRITERS=yes
' || true
printf '    %s\n' "${GUEST_OUT:-<no output>}"

# ---------- 2.1 The credential, before its source file is deleted ----------
# The installer generated an admin password and it is now baked into the image,
# identical in every clone, along with the indexer certificates. That is
# acceptable on isolated per-student lanes and matches this repo's 'bake-debug'
# convention - but only if it is WRITTEN DOWN rather than discovered.
echo "==> [2.1] Extracting and persisting the admin credential"
read -r -d '' CRED_SH <<'CRED_EOF' || true
m() { printf '%s=%s\n' "$1" "$2"; }
umask 077
CRED_DIR="$(dirname "$CRED_FILE")"
mkdir -p "$CRED_DIR"
chmod 700 "$CRED_DIR" 2>/dev/null || true
chown root:root "$CRED_DIR" 2>/dev/null || true

if [ ! -r "$INSTALL_OUTPUT" ]; then
  # The retry case: a previous pass of this script already moved the credential
  # and deleted the installer output. Reuse rather than report a failure that
  # would send whoever runs it looking for a file this script itself removed.
  if [ -s "$CRED_FILE" ] && grep -q '^WAZUH_ADMIN_PASSWORD=..*' "$CRED_FILE"; then
    m CRED_STATUS reused
  else
    m CRED_STATUS missing
  fi
else
  # Same extraction the role performs: the FIRST User: and the FIRST Password:
  # the installer printed. Every pair it printed is kept below them as comments,
  # because 4.x has changed how many it emits between point releases and a
  # seal that silently drops one is a credential nobody can find later.
  U="$(grep -E 'User:' "$INSTALL_OUTPUT" | awk '{ print $NF }' | head -1)"
  P="$(grep -E 'Password:' "$INSTALL_OUTPUT" | awk '{ print $NF }' | head -1)"
  if [ -z "$P" ]; then
    m CRED_STATUS no-password-in-output
  else
    {
      echo "# Wazuh all-in-one credentials for the CyberCore golden template ${SEAL_TEMPLATE_VMID}."
      echo "# Written at seal time by seal-goad-wazuh-template.sh, from"
      echo "#   ${INSTALL_OUTPUT}"
      echo "# which was DELETED immediately afterwards so this is the only copy in"
      echo "# the image."
      echo "#"
      echo "# THIS CREDENTIAL IS IDENTICAL IN EVERY CLONE OF THIS TEMPLATE, as are the"
      echo "# indexer certificates. That is acceptable only because lanes are"
      echo "# per-student and isolated. To rotate, see the hand-off block of the seal"
      echo "# script; it is a wazuh-passwords-tool run plus three restarts."
      echo "WAZUH_ADMIN_USER=${U:-admin}"
      echo "WAZUH_ADMIN_PASSWORD=${P}"
      echo "# Every User:/Password: line the installer printed:"
      grep -E 'User:|Password:' "$INSTALL_OUTPUT" | sed 's/^[[:space:]]*/#   /'
    } > "$CRED_FILE"
    chown root:root "$CRED_FILE" 2>/dev/null || true
    chmod 600 "$CRED_FILE"
    m CRED_STATUS written
  fi
fi

# Read back rather than echo what was written: this is the value the rest of the
# seal (and every human after it) will actually get.
m CRED_USER     "$(sed -n 's/^WAZUH_ADMIN_USER=//p' "$CRED_FILE" 2>/dev/null | head -1)"
m CRED_PASSWORD "$(sed -n 's/^WAZUH_ADMIN_PASSWORD=//p' "$CRED_FILE" 2>/dev/null | head -1)"
m CRED_MODE     "$(stat -c %a "$CRED_FILE" 2>/dev/null)"
m CRED_OWNER    "$(stat -c %U:%G "$CRED_FILE" 2>/dev/null)"
exit 0
CRED_EOF

if ! gscript "$GUEST_TIMEOUT" "$(guest_prelude)
$CRED_SH"; then
  echo "ERROR: could not extract the credential from the guest." >&2
  exit 1
fi
CRED_ENV="$GUEST_OUT"
CRED_STATUS="$(mval CRED_STATUS "$CRED_ENV")"
WAZUH_USER="$(mval CRED_USER "$CRED_ENV")"
WAZUH_PASS="$(mval CRED_PASSWORD "$CRED_ENV")"
printf '    %-24s %s\n' "CRED_STATUS:" "${CRED_STATUS:-unset}"
printf '    %-24s %s\n' "CRED_MODE:"   "$(mval CRED_MODE "$CRED_ENV")"
printf '    %-24s %s\n' "CRED_OWNER:"  "$(mval CRED_OWNER "$CRED_ENV")"

if [ -z "$WAZUH_PASS" ]; then
  echo "ERROR: no admin password could be recovered (status: ${CRED_STATUS:-unknown})." >&2
  echo "       Section 2.2 authenticates to the indexer with it to wipe the staging" >&2
  echo "       lab's alerts, and without it that wipe cannot happen - so every clone" >&2
  echo "       would open on this bake lab's alert history. Refusing to continue." >&2
  echo "" >&2
  echo "       Look for the installer output on the source:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'ls -la /opt/wazuh/'" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c \"grep -E 'User:|Password:' $INSTALL_OUTPUT\"" >&2
  echo "       If it is genuinely gone, recover the password with the indexer's own" >&2
  echo "       tool and write it to $CRED_FILE by hand before re-running:" >&2
  echo "           /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --help" >&2
  echo "       Nothing has been deleted yet; the source is still usable." >&2
  exit 1
fi
echo "    Admin credential recovered (echoed again at the end of this run)."

# ---------- 2.2 Wipe the indexer's staging data ----------
# UNLIKE ELK, THERE IS NO KEEP-OR-DELETE TENSION HERE. Wazuh's dashboards and
# index patterns ship with the product (the wazuh-dashboard package and its
# plugin), and the alert index template is installed by filebeat at install
# time - not generated by agents the way winlogbeat's templates are. So there is
# nothing in the indexer that only exists because a staging agent created it,
# and the alert data can go without losing anything the product needs.
#
# DELETE BY API, NOT BY CLEARING THE DATA DIRECTORY, and the difference matters:
# /var/lib/wazuh-indexer also holds .opendistro_security (the internal users and
# roles the admin password lives in) and .kibana (every saved object the
# dashboard renders). Clearing the directory gives a clone whose indexer rejects
# every login and whose dashboard has no saved objects - a far worse outcome
# than the alerts it was meant to remove, and one that looks like a corrupted
# image rather than a bad clean.
#
# Indices are enumerated and deleted BY NAME rather than with a wildcard DELETE,
# because a cluster with action.destructive_requires_name=true silently refuses
# wildcard deletes and the loop would otherwise report success having done
# nothing.
echo "==> [2.2] Wiping the staging lab's data out of the indexer"
read -r -d '' INDEXWIPE_SH <<'INDEXWIPE_EOF' || true
m() { printf '%s=%s\n' "$1" "$2"; }
U="$(sed -n 's/^WAZUH_ADMIN_USER=//p' "$CRED_FILE" | head -1)"
P="$(sed -n 's/^WAZUH_ADMIN_PASSWORD=//p' "$CRED_FILE" | head -1)"
[ -n "$U" ] || U=admin

# Credentials go to curl through a config file on STDIN, never in argv. printf
# is a shell builtin, so the password never appears in /proc anywhere, and this
# is the same rule the rest of this repo's bake scripts apply to secrets.
# (If a generated password ever contains a double quote this breaks; wazuh's
# generator uses A-Za-z0-9.*+? and does not, but it is worth knowing.)
curlk() { printf 'user = "%s:%s"\n' "$U" "$P" | curl -sk -K - -m 120 "$@"; }

# AUTHENTICATE FIRST AND REFUSE IF IT FAILS. This is the trap the whole section
# turns on: with a bad credential every _cat call below returns an error body
# instead of index names, the name filter drops it, the delete loop runs zero
# times, and the verification at the end counts zero remaining indices. A total
# failure and a total success produce the SAME numbers. So the HTTP status of a
# plain authenticated GET is checked before anything is trusted.
AUTH="$(curlk -o /dev/null -w '%{http_code}' "$INDEXER_URL/")"
m INDEXER_AUTH_HTTP "$AUTH"
if [ "$AUTH" != "200" ]; then
  m INDEXER_WIPE aborted-auth
  exit 0
fi

# wazuh-alerts-*     the alerts themselves
# wazuh-archives-*   every event, alerting or not, if archives were enabled
# wazuh-monitoring-* agent connection status over time - literally a per-agent
#                    record of the staging lab's hosts
# wazuh-statistics-* manager/daemon statistics from the staging run
# wazuh-states-*     4.8's vulnerability-detector state, keyed per agent
PATTERNS='wazuh-alerts-* wazuh-archives-* wazuh-monitoring-* wazuh-statistics-* wazuh-states-*'

BEFORE=0
DELETED=0
for pat in $PATTERNS; do
  # The name filter is what keeps a JSON error body from being treated as a list
  # of index names.
  for i in $(curlk "$INDEXER_URL/_cat/indices/$pat?h=index&expand_wildcards=all" 2>/dev/null \
             | tr -d '\r' | grep -E '^[A-Za-z0-9._+-]+$'); do
    BEFORE=$((BEFORE + 1))
    if curlk -o /dev/null -w '%{http_code}' -X DELETE "$INDEXER_URL/$i" | grep -q '^2'; then
      DELETED=$((DELETED + 1))
    fi
  done
done

# Whether 4.8 writes alerts as plain indices or as data streams depends on the
# release and on whether filebeat's template was applied. Both are swept; on a
# cluster that has neither, both loops are simply empty.
DS_DELETED=0
for d in $(curlk "$INDEXER_URL/_data_stream/wazuh-*" 2>/dev/null \
           | tr ',' '\n' \
           | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'); do
  case "$d" in
    wazuh-*)
      if curlk -o /dev/null -w '%{http_code}' -X DELETE "$INDEXER_URL/_data_stream/$d" | grep -q '^2'; then
        DS_DELETED=$((DS_DELETED + 1))
      fi
      ;;
  esac
done

m INDEXER_INDICES_BEFORE "$BEFORE"
m INDEXER_INDICES_DELETED "$DELETED"
m INDEXER_DATASTREAMS_DELETED "$DS_DELETED"

# ---- Verify, rather than assume ----
REMAIN=0
for pat in $PATTERNS; do
  n="$(curlk "$INDEXER_URL/_cat/indices/$pat?h=index&expand_wildcards=all" 2>/dev/null \
       | tr -d '\r' | grep -cE '^[A-Za-z0-9._+-]+$')"
  REMAIN=$((REMAIN + n))
done
m INDEXER_INDICES_REMAINING "$REMAIN"
# A second, independent witness: zero documents behind the alert pattern. It
# fails differently from the index count - a re-created empty index would pass
# the count check and this one too, while a surviving index full of staging
# alerts fails both.
m INDEXER_ALERT_DOCS "$(curlk "$INDEXER_URL/wazuh-alerts-*/_count?ignore_unavailable=true" 2>/dev/null \
                        | sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)"

# ---- Confirm we removed DATA and not MAPPINGS ----
# The alert index template is what makes the first alert in a lane land with the
# right field types. Deleting indices must not have touched it; if it is gone,
# lane alerts index as dynamic strings and every dashboard aggregation silently
# returns nothing.
m INDEXER_TEMPLATE_HTTP        "$(curlk -o /dev/null -w '%{http_code}' "$INDEXER_URL/_index_template/wazuh")"
m INDEXER_TEMPLATE_LEGACY_HTTP "$(curlk -o /dev/null -w '%{http_code}' "$INDEXER_URL/_template/wazuh")"
# .kibana holds the dashboard's saved objects. It must survive - it is the
# reason this section uses the API instead of clearing the data directory.
m INDEXER_KIBANA_INDEX "$(curlk "$INDEXER_URL/_cat/indices/.kibana*?h=index&expand_wildcards=all" 2>/dev/null \
                          | tr -d '\r' | grep -cE '^[A-Za-z0-9._+-]+$')"
m INDEXER_WIPE done
exit 0
INDEXWIPE_EOF

if ! gscript "$GUEST_TIMEOUT_LONG" "$(guest_prelude)
$INDEXWIPE_SH"; then
  echo "ERROR: the indexer wipe could not be run in the guest." >&2
  exit 1
fi
IDX_ENV="$GUEST_OUT"
for k in INDEXER_AUTH_HTTP INDEXER_INDICES_BEFORE INDEXER_INDICES_DELETED \
         INDEXER_DATASTREAMS_DELETED INDEXER_INDICES_REMAINING INDEXER_ALERT_DOCS \
         INDEXER_TEMPLATE_HTTP INDEXER_TEMPLATE_LEGACY_HTTP INDEXER_KIBANA_INDEX; do
  printf '    %-30s %s\n' "$k:" "$(mval "$k" "$IDX_ENV")"
done

IDX_AUTH="$(mval INDEXER_AUTH_HTTP "$IDX_ENV")"
if [ "$IDX_AUTH" != "200" ]; then
  echo "ERROR: the indexer refused the admin credential (HTTP ${IDX_AUTH:-none})." >&2
  echo "       NOTHING WAS WIPED. This is refused rather than warned about because a" >&2
  echo "       failed authentication and a perfect wipe produce identical counts: with" >&2
  echo "       a bad credential every query returns an error body, no index name is" >&2
  echo "       ever parsed, and 'zero remaining' means 'zero visible', not 'zero'." >&2
  echo "       Sealing here would ship the bake lab's alerts to every student." >&2
  echo "" >&2
  echo "       Check by hand on the source:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'curl -sk -u admin:PASS $INDEXER_URL/_cat/indices'" >&2
  echo "       If the password in $CRED_FILE is wrong, reset it:" >&2
  echo "           /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p <new>" >&2
  exit 1
fi

IDX_REMAIN="$(mval INDEXER_INDICES_REMAINING "$IDX_ENV")"
if [ "${IDX_REMAIN:-x}" != "0" ]; then
  echo "ERROR: ${IDX_REMAIN:-?} wazuh-* indices are still present after the wipe." >&2
  echo "       Every clone of this template would open the dashboard onto the staging" >&2
  echo "       lab's alerts - a student's first view of 'their' SIEM would be somebody" >&2
  echo "       else's incident, in every lane, identically." >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'curl -sk -u admin:PASS $INDEXER_URL/_cat/indices/wazuh-*'" >&2
  exit 1
fi
IDX_DOCS="$(mval INDEXER_ALERT_DOCS "$IDX_ENV")"
if [ -n "$IDX_DOCS" ] && [ "$IDX_DOCS" != "0" ]; then
  echo "ERROR: the alert pattern still holds $IDX_DOCS documents." >&2
  echo "       The indices were removed but something re-created and re-filled one -" >&2
  echo "       almost certainly filebeat or the manager is still running and shipping." >&2
  echo "       Confirm section 2.0 actually stopped them:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl is-active wazuh-manager filebeat'" >&2
  exit 1
fi
IDX_TPL="$(mval INDEXER_TEMPLATE_HTTP "$IDX_ENV")"
IDX_TPL_LEG="$(mval INDEXER_TEMPLATE_LEGACY_HTTP "$IDX_ENV")"
if [ "$IDX_TPL" != "200" ] && [ "$IDX_TPL_LEG" != "200" ]; then
  echo "    WARNING: no wazuh index template is registered (composable $IDX_TPL, legacy $IDX_TPL_LEG)." >&2
  echo "             Alert data was removed, which is what this section is for - but the" >&2
  echo "             MAPPING that makes the first alert in a lane index correctly is also" >&2
  echo "             absent. Alerts then land as dynamic strings and dashboard" >&2
  echo "             aggregations come back empty with no error anywhere." >&2
  echo "             Restore it on the source before sealing:" >&2
  echo "                 filebeat setup --index-management" >&2
  WARN=1
fi
if [ "$(mval INDEXER_KIBANA_INDEX "$IDX_ENV")" = "0" ]; then
  echo "    WARNING: no .kibana index is present. The dashboard's saved objects live" >&2
  echo "             there; without them a clone opens on an empty dashboard app." >&2
  WARN=1
fi

# ---------- 2.3 The agent registry and everything that outlives it ----------
echo "==> [2.3] Clearing the agent registry and per-agent state"
read -r -d '' AGENTSTATE_SH <<'AGENTSTATE_EOF' || true
m() { printf '%s=%s\n' "$1" "$2"; }

# INVENTORY FIRST. Nothing below is deleted from a list written in advance:
# what is actually on this box is reported, then removed, so that a layout that
# has moved between Wazuh releases shows up as an empty inventory rather than as
# a clean that quietly matched nothing.
m INV_RIDS         "$(ls -1 /var/ossec/queue/rids 2>/dev/null | wc -l | tr -d ' ')"
m INV_DB           "$(ls -1 /var/ossec/queue/db 2>/dev/null | grep -c '\.db$')"
m INV_AGENT_GROUPS "$(ls -1 /var/ossec/queue/agent-groups 2>/dev/null | wc -l | tr -d ' ')"
m INV_DIFF         "$(ls -1 /var/ossec/queue/diff 2>/dev/null | wc -l | tr -d ' ')"
m INV_MULTIGROUPS  "$(ls -1 /var/ossec/var/multigroups 2>/dev/null | wc -l | tr -d ' ')"
m INV_TIMESTAMP    "$(test -f /var/ossec/queue/agents-timestamp && echo present || echo absent)"
m INV_GROUPS       "$(ls -1 /var/ossec/etc/shared 2>/dev/null | tr '\n' ' ')"

CK=/var/ossec/etc/client.keys
m CK_META_BEFORE  "$(stat -c %U:%G:%a "$CK" 2>/dev/null)"
m CK_BYTES_BEFORE "$(stat -c %s "$CK" 2>/dev/null)"

# ---- client.keys: TRUNCATE, never delete ----
# This is the file that breaks multi-lane. It holds the agents that registered
# during the staging install; sealed populated, every cloned manager starts life
# already knowing the staging lab's hosts, real lane agents collide with those
# ghosts on agent IDs, and the symptom is agents flapping between connected and
# disconnected in every lane at once with nothing in any log to explain it.
#
# Truncated rather than removed because ossec expects the file to exist, with
# its owner and mode intact - a missing client.keys is its own, different
# failure. ':' redirects onto the existing inode, so uid/gid/mode are untouched
# by construction; section 3 checks that they really were.
: > "$CK"
# The manager keeps rotating backups of it alongside. They hold the same ghosts.
rm -f "$CK".bck* "$CK".tmp 2>/dev/null || true

# ---- rids: per-agent message counters ----
# Not covered by client.keys and not regenerated from it. A stale counter for an
# ID that a lane agent later reuses makes that agent fail to connect, and the
# manager logs it as a duplicate counter - which reads like a network problem
# rather than a stale file, and sends whoever debugs it a long way from here.
rm -f /var/ossec/queue/rids/* 2>/dev/null || true

# ---- queue/db: the agent database ----
# global.db holds the agent table itself; NNN.db is one file per agent, holding
# its FIM baseline, SCA results and inventory. wazuh-db recreates global.db from
# /var/ossec/templates/ at start and re-populates it from client.keys, which is
# now empty - which is exactly the intended end state.
# The glob deliberately does not match dotfiles: .template.db, if this release
# has one, is the SCHEMA new agent databases are created from, and deleting it
# would break registration in every clone.
rm -f /var/ossec/queue/db/*.db /var/ossec/queue/db/*.db-shm /var/ossec/queue/db/*.db-wal /var/ossec/queue/db/*.db-journal 2>/dev/null || true

# ---- agents-timestamp: registration times for agents that will not exist ----
rm -f /var/ossec/queue/agents-timestamp 2>/dev/null || true

# ---- agent-groups: per-agent group ASSIGNMENTS, keyed by agent id ----
# Pure staging state: files named for agent IDs that are about to be handed to
# different machines in a different lane. Always removed.
rm -f /var/ossec/queue/agent-groups/* 2>/dev/null || true

# ---- diff / multigroups: FIM change snapshots and cached merged group configs
rm -rf /var/ossec/queue/diff/* 2>/dev/null || true
rm -rf /var/ossec/var/multigroups/* 2>/dev/null || true

# ---- Group DEFINITIONS are config, not state ----
# /var/ossec/etc/shared/<group>/ holds agent.conf - configuration somebody may
# have written on purpose. 'default' always stays. Anything else is REPORTED and
# kept unless REMOVE_CUSTOM_GROUPS=1, because deleting an instructor's group
# config is not a cleanup, it is data loss with a tidy name.
REMOVED_GROUPS=""
KEPT_GROUPS=""
for g in /var/ossec/etc/shared/*; do
  [ -d "$g" ] || continue
  b="$(basename "$g")"
  [ "$b" = "default" ] && continue
  if [ "$REMOVE_CUSTOM_GROUPS" = "1" ]; then
    rm -rf "$g" && REMOVED_GROUPS="$REMOVED_GROUPS $b"
  else
    KEPT_GROUPS="$KEPT_GROUPS $b"
  fi
done
m GROUPS_REMOVED "${REMOVED_GROUPS:--}"
m GROUPS_KEPT    "${KEPT_GROUPS:--}"
# merged.mg is a cache of the group config; the manager rebuilds it at start.
rm -f /var/ossec/etc/shared/*/merged.mg 2>/dev/null || true

# ---- filebeat's read position ----
# It records where in alerts.json filebeat had got to. Kept alongside a wiped
# alerts.json it is merely stale; removed, the first lane alert is shipped from
# byte zero with no ambiguity.
rm -rf /var/lib/filebeat/registry 2>/dev/null || true

m CK_META_AFTER  "$(stat -c %U:%G:%a "$CK" 2>/dev/null)"
m CK_BYTES_AFTER "$(stat -c %s "$CK" 2>/dev/null)"
exit 0
AGENTSTATE_EOF

if ! gscript "$GUEST_TIMEOUT" "$(guest_prelude)
$AGENTSTATE_SH"; then
  echo "ERROR: could not clear the agent state in the guest." >&2
  exit 1
fi
AG_ENV="$GUEST_OUT"
for k in INV_RIDS INV_DB INV_AGENT_GROUPS INV_DIFF INV_MULTIGROUPS INV_TIMESTAMP \
         INV_GROUPS GROUPS_REMOVED GROUPS_KEPT CK_META_BEFORE CK_BYTES_BEFORE \
         CK_META_AFTER CK_BYTES_AFTER; do
  printf '    %-30s %s\n' "$k:" "$(mval "$k" "$AG_ENV")"
done
GROUPS_KEPT="$(mval GROUPS_KEPT "$AG_ENV")"
if [ -n "$GROUPS_KEPT" ] && [ "$GROUPS_KEPT" != "-" ]; then
  echo "    NOTE: non-default agent groups kept:$GROUPS_KEPT" >&2
  echo "          Their per-agent ASSIGNMENTS were removed, so no clone starts with an" >&2
  echo "          agent in them - but the group config itself travels into every clone." >&2
  echo "          Re-run with REMOVE_CUSTOM_GROUPS=1 if that is staging leftovers." >&2
fi

# ---------- 2.4 Stop the indexer so it flushes ----------
echo "==> [2.4] Stopping wazuh-indexer"
gscript "$GUEST_TIMEOUT_LONG" '
# Last of the three, and stopped through systemd rather than by the shutdown
# that follows: a JVM killed mid-write hands every clone a half-flushed
# translog, and the symptom of that is a clone whose cluster comes up red for
# reasons that have nothing to do with the lane it is in.
systemctl stop wazuh-indexer 2>/dev/null || true
echo INDEXER_STOPPED=yes
' || true
printf '    %s\n' "${GUEST_OUT:-<no output>}"

# ---------- 2.5 Delete the installer output; stamp the image ----------
echo "==> [2.5] Removing the installer output and stamping the image"
read -r -d '' STAMP_SH <<'STAMP_EOF' || true
m() { printf '%s=%s\n' "$1" "$2"; }

# The password now lives in exactly one place inside this image. Two copies is
# one more thing to rotate and one more thing to miss.
rm -f "$INSTALL_OUTPUT"
m INSTALL_OUTPUT_REMOVED "$(test -f "$INSTALL_OUTPUT" && echo no || echo yes)"

# The installer's own script is dead weight in a golden image and re-running it
# on a clone would be actively wrong, but it is left in place: it carries the
# version that was installed, and this script does not delete things it was not
# asked to. Reported instead.
m INSTALL_SCRIPT_PRESENT "$(test -f /opt/wazuh/wazuh-install.sh && echo yes || echo no)"

INFO="$(/var/ossec/bin/wazuh-control info 2>/dev/null | tr -d '"')"
{
  echo "# Written by seal-goad-wazuh-template.sh. Facts about this image, frozen at"
  echo "# seal time. Everything below is what a CLONE of this template runs; none of"
  echo "# it updates itself, and none of it is re-installed per lane."
  echo "CYBERCORE_TEMPLATE=goad-wazuh-template"
  echo "CYBERCORE_TEMPLATE_VMID=${SEAL_TEMPLATE_VMID}"
  echo "CYBERCORE_SEALED_FROM_VMID=${SEAL_SRC_VMID}"
  echo "CYBERCORE_SEALED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "$INFO" | grep '^WAZUH_VERSION='  || echo "WAZUH_VERSION=unknown"
  printf '%s\n' "$INFO" | grep '^WAZUH_REVISION=' || echo "WAZUH_REVISION=unknown"
  echo "WAZUH_RULES_XML_COUNT=$(find /var/ossec/etc/rules -maxdepth 1 -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')"
  echo "WAZUH_CREDENTIALS_FILE=${CRED_FILE}"
} > "$STAMP_FILE"
chmod 644 "$STAMP_FILE"
m STAMP_WRITTEN "$(test -s "$STAMP_FILE" && echo yes || echo no)"
exit 0
STAMP_EOF

if ! gscript "$GUEST_TIMEOUT" "$(guest_prelude)
$STAMP_SH"; then
  echo "ERROR: could not remove the installer output / stamp the image." >&2
  exit 1
fi
printf '    %-30s %s\n' "INSTALL_OUTPUT_REMOVED:" "$(mval INSTALL_OUTPUT_REMOVED "$GUEST_OUT")"
printf '    %-30s %s\n' "STAMP_WRITTEN:"          "$(mval STAMP_WRITTEN "$GUEST_OUT")"

# ---------- 2.6 / 2.7 Logs and image hygiene ----------
echo "==> [2.6/2.7] Wiping logs and sealing the image identity"
read -r -d '' HYGIENE_SH <<'HYGIENE_EOF' || true
m() { printf '%s=%s\n' "$1" "$2"; }

# ---- 2.6 The manager's own logs, now that nothing is left to write them ----
# A student's box should not ship with the staging lab's ossec.log, its alert
# archive, or its API access log. The DIRECTORIES are recreated and re-owned
# afterwards: wazuh writes dated files inside them and will not create the
# parents itself, so a clean that removed the tree would give every clone a
# manager that fails to start - a cleanup that breaks the product.
find /var/ossec/logs -mindepth 1 -type f -delete 2>/dev/null || true
rm -rf /var/ossec/logs/alerts/* /var/ossec/logs/archives/* \
       /var/ossec/logs/api/* /var/ossec/logs/firewall/* 2>/dev/null || true
mkdir -p /var/ossec/logs/alerts /var/ossec/logs/archives /var/ossec/logs/api /var/ossec/logs/firewall
chown -R wazuh:wazuh /var/ossec/logs 2>/dev/null || true
chmod 750 /var/ossec/logs 2>/dev/null || true

# ---- 2.7a machine-id ----
# NOT hygiene. systemd-networkd (and netplan on top of it) derives its DHCP
# client identifier - the DUID - from /etc/machine-id. Clones that share one
# present as the same DHCP client to the lane's dnsmasq. The lane pins addresses
# with dhcp-host=<MAC>,<IP> and a MAC is per-clone, so the address still lands,
# but a shared DUID still produces lease churn across lanes.
# TRUNCATE, do not delete: systemd repopulates an EMPTY /etc/machine-id at boot
# and treats a MISSING one as a first-boot condition some images handle badly.
truncate -s 0 /etc/machine-id 2>/dev/null || true
rm -f /var/lib/dbus/machine-id 2>/dev/null || true

# ---- 2.7b SSH host keys ----
# One host key shared across twenty student lanes is both a real problem and a
# confusing one: the fingerprint is identical everywhere, so any change looks
# deliberate and no change looks like anything at all. cloud-init regenerates
# them per clone once its per-instance state is cleared, which is 2.7c.
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true

# ---- 2.7c cloud-init ----
# --seed as well as --logs, so the clone is a NEW instance and re-runs every
# per-instance module - including the one that puts SSH host keys back.
cloud-init clean --logs --seed >/dev/null 2>&1 || true
rm -rf /var/lib/cloud/instances/* /var/lib/cloud/instance 2>/dev/null || true

# ---- 2.7d the journal and /var/log ----
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
rm -rf /var/log/journal/* /run/log/journal/* 2>/dev/null || true
# Rotated logs are deleted; live ones are truncated rather than removed, because
# a daemon holding an open handle to a deleted file writes to nothing and never
# says so.
find /var/log -type f \( -name '*.gz' -o -name '*.xz' -o -name '*.[0-9]' -o -name '*.old' \) -delete 2>/dev/null || true
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true

# ---- 2.7e shell history, for every user ----
for h in /root /home/*; do
  [ -d "$h" ] || continue
  rm -f "$h/.bash_history" "$h/.zsh_history" "$h/.ash_history" \
        "$h/.python_history" "$h/.lesshst" "$h/.viminfo" \
        "$h/.sudo_as_admin_successful" "$h/.wget-hsts" 2>/dev/null || true
done
history -c 2>/dev/null || true

# ---- 2.7f package cache, stale DHCP leases, scratch ----
apt-get clean >/dev/null 2>&1 || true
rm -f /var/lib/dhcp/*.leases /var/lib/dhcp/*.leases~ 2>/dev/null || true
rm -rf /var/lib/NetworkManager/*.lease 2>/dev/null || true
rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
# The SOCFortress script clones into /tmp/Wazuh-Rules and backs the old rules up
# to /tmp/wazuh_rules_backup; both are covered by the line above, and named here
# so nobody re-adds them thinking they were missed.

m HYGIENE done
exit 0
HYGIENE_EOF

if ! gscript "$GUEST_TIMEOUT_LONG" "$(guest_prelude)
$HYGIENE_SH"; then
  echo "ERROR: the hygiene pass could not be run in the guest." >&2
  exit 1
fi
printf '    %-30s %s\n' "HYGIENE:" "$(mval HYGIENE "$GUEST_OUT")"

# ============================================================================
# 3. POST-CLEAN VERIFICATION
# ----------------------------------------------------------------------------
# Re-check that each clean in section 2 actually took effect.
#
# This section exists because A CLEAN THAT SILENTLY NO-OPS IS INDISTINGUISHABLE
# FROM ONE THAT WORKED - right up until a classroom. 'rm -f' on a path that
# moved between releases succeeds. A truncate on a file a running daemon
# rewrites succeeds. An API delete against an unauthenticated endpoint returns
# a tidy 401 body that a name filter throws away. Every one of those is a
# success at the shell and a failure in thirty lanes.
#
# The indexer is stopped by now, so 2.2's result cannot be re-queried here. It
# was verified INSIDE 2.2, against a connection that had already proved it was
# authenticated, and that verdict is carried forward rather than re-taken.
# ============================================================================
echo "==> Post-clean verification"

read -r -d '' POSTCLEAN_SH <<'POSTCLEAN_EOF' || true
m()  { printf '%s=%s\n' "$1" "$2"; }
yn() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }
cnt() { ls -1 "$1" 2>/dev/null | wc -l | tr -d ' '; }

CK=/var/ossec/etc/client.keys
m CK_EXISTS "$(yn test -f $CK)"
m CK_BYTES  "$(stat -c %s $CK 2>/dev/null)"
m CK_META   "$(stat -c %U:%G:%a $CK 2>/dev/null)"
m CK_BACKUPS "$(ls -1 /var/ossec/etc/client.keys.* 2>/dev/null | wc -l | tr -d ' ')"

m RIDS_COUNT        "$(cnt /var/ossec/queue/rids)"
m DB_COUNT          "$(ls -1 /var/ossec/queue/db 2>/dev/null | grep -c '\.db$')"
m AGENT_GROUPS_COUNT "$(cnt /var/ossec/queue/agent-groups)"
m DIFF_COUNT        "$(cnt /var/ossec/queue/diff)"
m MULTIGROUPS_COUNT "$(cnt /var/ossec/var/multigroups)"
m TIMESTAMP_GONE    "$(test -f /var/ossec/queue/agents-timestamp && echo no || echo yes)"
# The schema template new agent DBs are created from must have SURVIVED the
# delete in 2.3. If the glob ate it, registration breaks in every clone.
m DB_TEMPLATES_INTACT "$(yn test -d /var/ossec/templates)"

m OSSEC_LOG_FILES "$(find /var/ossec/logs -type f 2>/dev/null | wc -l | tr -d ' ')"
m OSSEC_LOG_DIRS  "$(yn sh -c 'test -d /var/ossec/logs/alerts && test -d /var/ossec/logs/archives && test -d /var/ossec/logs/api && test -d /var/ossec/logs/firewall')"
m OSSEC_LOG_OWNER "$(stat -c %U:%G /var/ossec/logs 2>/dev/null)"

# Services: STOPPED now, but still ENABLED. Those are opposite requirements and
# both matter - a template whose services are disabled clones into a lane that
# boots with no SIEM, and one whose services are left running gets snapshotted
# mid-write.
for pair in MANAGER:wazuh-manager INDEXER:wazuh-indexer DASHBOARD:wazuh-dashboard FILEBEAT:filebeat QGA:qemu-guest-agent; do
  k="${pair%%:*}"; u="${pair#*:}"
  m "${k}_ACTIVE"  "$(yn systemctl is-active --quiet "$u")"
  m "${k}_ENABLED" "$(yn systemctl is-enabled --quiet "$u")"
done

m MACHINE_ID_EMPTY  "$(test -s /etc/machine-id && echo no || echo yes)"
m MACHINE_ID_EXISTS "$(yn test -f /etc/machine-id)"
m DBUS_MACHINE_ID   "$(test -e /var/lib/dbus/machine-id && echo present || echo absent)"
m HOSTKEYS          "$(ls /etc/ssh/ssh_host_* >/dev/null 2>&1 && echo present || echo none)"
m CLOUD_INIT_STATE  "$(ls /var/lib/cloud/instances 2>/dev/null | head -1 | grep -q . && echo dirty || echo clean)"
m JOURNAL_FILES     "$(find /var/log/journal /run/log/journal -type f 2>/dev/null | wc -l | tr -d ' ')"
m HISTORY_FILES     "$(ls /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history 2>/dev/null | wc -l | tr -d ' ')"
m VARLOG_BYTES      "$(du -sk /var/log 2>/dev/null | awk '{ print $1 }')"

m INSTALL_OUTPUT_GONE "$(test -f "$INSTALL_OUTPUT" && echo no || echo yes)"
m CRED_FILE_EXISTS    "$(yn test -s "$CRED_FILE")"
m CRED_FILE_MODE      "$(stat -c %a "$CRED_FILE" 2>/dev/null)"
m CRED_FILE_OWNER     "$(stat -c %U:%G "$CRED_FILE" 2>/dev/null)"
m CRED_FILE_HAS_PW    "$(yn grep -q '^WAZUH_ADMIN_PASSWORD=..*' "$CRED_FILE")"
m STAMP_EXISTS        "$(yn test -s "$STAMP_FILE")"
# Reported, never removed by this script: it holds every certificate and every
# password the installer generated. See the hand-off block.
m INSTALL_FILES_TAR   "$(find /root /home /opt /tmp /var/tmp -maxdepth 3 -name 'wazuh-install-files.tar' 2>/dev/null | tr '\n' ' ')"
exit 0
POSTCLEAN_EOF

if ! gscript "$GUEST_TIMEOUT" "$(guest_prelude)
$POSTCLEAN_SH"; then
  echo "ERROR: could not run the post-clean checks in the guest." >&2
  echo "       The VM has been CLEANED but NOT sealed. It is left running; re-run this" >&2
  echo "       script against it once the guest agent answers again." >&2
  exit 1
fi
POST_ENV="$GUEST_OUT"
if [ -z "$POST_ENV" ]; then
  echo "ERROR: the post-clean check produced no output (rc=$GUEST_RC)." >&2
  printf '%s\n' "$GUEST_RAW" >&2
  echo "       Refusing to seal on an empty result: an empty marker set passes no" >&2
  echo "       check and fails no check, and this is the section that exists to catch" >&2
  echo "       a clean that did nothing." >&2
  exit 1
fi

SFAIL=0
qget() { mval "$1" "$POST_ENV"; }
qcheck() {  # qcheck <marker> <expected> <what breaks>
  local got; got="$(qget "$1")"
  printf '    %-24s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    SFAIL=1
  fi
}
qwarn() {  # qwarn <marker> <expected> <why it matters>
  local got; got="$(qget "$1")"
  printf '    %-24s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    WARNING: $3" >&2
    WARN=1
  fi
}

# ---- client.keys: empty, present, and with its ownership untouched ----
# Three separate facts, and they fail in three different ways. Empty-but-deleted
# is a manager that will not start. Empty-but-root-owned is a manager that
# starts and cannot register an agent, and says so only in ossec.log. Populated
# is the multi-lane failure this whole script exists to prevent.
qcheck CK_EXISTS yes "/var/ossec/etc/client.keys was DELETED rather than truncated. ossec expects the file to exist; every clone would come up with a manager that cannot register an agent"
qcheck CK_BYTES  0   "client.keys is NOT empty - the truncate did not take, almost certainly because a wazuh daemon was still running and rewrote it from memory. Every cloned manager would start life knowing the staging lab's hosts, real lane agents would collide with those ghosts on agent IDs, and the symptom is agents flapping in every lane at once with nothing in any log to explain it. THIS IS THE FAILURE THIS SCRIPT EXISTS TO PREVENT"
CK_BEFORE="$(mval CK_META_BEFORE "$AG_ENV")"
CK_AFTER="$(qget CK_META)"
printf '    %-24s %s -> %s\n' "CK_META (owner:group:mode):" "${CK_BEFORE:-?}" "${CK_AFTER:-?}"
if [ -n "$CK_BEFORE" ] && [ "$CK_BEFORE" != "$CK_AFTER" ]; then
  echo "    ERROR: client.keys changed owner or mode during the clean ($CK_BEFORE -> $CK_AFTER)." >&2
  echo "           It must be the SAME file with the SAME ownership, only empty. A" >&2
  echo "           root-owned client.keys gives a manager that starts, looks healthy," >&2
  echo "           and cannot register a single agent - and says so only in ossec.log." >&2
  echo "           Fix on the source:  chown wazuh:wazuh $CK ; chmod 640 $CK" >&2
  SFAIL=1
fi
qcheck CK_BACKUPS 0 "rotated client.keys backups are still present. They hold the same staging agents as the file that was just emptied, and the manager will read one back after any failed write"

# ---- per-agent state that outlives client.keys ----
qcheck RIDS_COUNT         0 "queue/rids is not empty. Those are per-agent message counters; a stale counter for an ID a lane agent later reuses makes that agent fail to connect, logged as a duplicate counter, which reads like a network fault and sends whoever debugs it a long way from here"
qcheck DB_COUNT           0 "queue/db still holds agent databases. global.db is the agent table itself and NNN.db is one file per staging agent, carrying its FIM baseline and inventory into every lane"
qcheck AGENT_GROUPS_COUNT 0 "queue/agent-groups still holds per-agent group assignments, keyed by agent IDs that are about to be handed to different machines"
qcheck TIMESTAMP_GONE     yes "queue/agents-timestamp survived - registration times for agents that will not exist in any lane"
qwarn  DIFF_COUNT         0 "queue/diff still holds FIM change snapshots from the staging lab"
qwarn  MULTIGROUPS_COUNT  0 "var/multigroups still holds cached merged group configs from the staging lab"
qcheck DB_TEMPLATES_INTACT yes "/var/ossec/templates is missing. That is the SCHEMA wazuh-db creates global.db and each agent database from; without it the manager cannot rebuild the registry that section 2.3 deliberately emptied, and no clone can register anything"

# ---- the manager's logs ----
qcheck OSSEC_LOG_FILES 0   "/var/ossec/logs still holds files - a student's box would ship with the staging lab's ossec.log, alert archive and API access log"
qcheck OSSEC_LOG_DIRS  yes "one of /var/ossec/logs/{alerts,archives,api,firewall} is missing. wazuh writes dated files INSIDE those directories and does not create the parents, so the manager fails to start in every clone - a cleanup that broke the product"
qwarn  OSSEC_LOG_OWNER wazuh:wazuh "/var/ossec/logs is not owned by wazuh:wazuh, so the manager may not be able to write its own log"

# ---- services: stopped, but still enabled ----
for k in MANAGER INDEXER DASHBOARD; do
  qcheck "${k}_ACTIVE"  no  "wazuh-$(printf '%s' "$k" | tr 'A-Z' 'a-z') is STILL RUNNING. The clone would be snapshotted mid-write; for the indexer specifically that means a half-flushed translog and a cluster that comes up red in every lane"
  qcheck "${k}_ENABLED" yes "wazuh-$(printf '%s' "$k" | tr 'A-Z' 'a-z') is not ENABLED. Stopping a service does not disable it, so this means it was never enabled - and a clone boots with no SIEM and nothing anywhere saying why"
done
qcheck QGA_ENABLED yes "qemu-guest-agent is not enabled - nothing could reach a clone to configure, inspect or repair it"
qwarn  FILEBEAT_ENABLED yes "filebeat is not enabled; a clone's manager would generate alerts that never reach the indexer"

# ---- image identity ----
qcheck MACHINE_ID_EXISTS yes "/etc/machine-id was DELETED rather than truncated. systemd treats a missing machine-id as a first-boot condition that some images handle badly; an empty one it simply repopulates"
qcheck MACHINE_ID_EMPTY  yes "/etc/machine-id still has content - every clone would share it, and systemd-networkd derives its DHCP client identifier from it, so every clone presents the same DUID to the lane's dnsmasq"
qcheck DBUS_MACHINE_ID   absent "/var/lib/dbus/machine-id survived, which re-seeds the shared identity /etc/machine-id was just cleared of"
qcheck HOSTKEYS          none "SSH host keys are still in the image. Every student lane would share one host identity: any lane can impersonate any other to anything that trusts it, and the fingerprint is identical everywhere so nothing ever looks wrong"
qcheck CLOUD_INIT_STATE  clean "cloud-init still holds this staging lane's instance state. The clone would be treated as the SAME instance and would skip every per-instance module, including the one that regenerates the SSH host keys just deleted"
qwarn  JOURNAL_FILES     0 "journal files survived - a student's box would ship with the staging lab's system journal"
qwarn  HISTORY_FILES     0 "shell history files survived"
printf '    %-24s %s KB\n' "VARLOG_BYTES:" "$(qget VARLOG_BYTES)"

# ---- the credential ----
qcheck INSTALL_OUTPUT_GONE yes "$INSTALL_OUTPUT is still present. The admin password would then exist in TWO places in the image - and the copy nobody rotates is the one that stays valid"
qcheck CRED_FILE_EXISTS    yes "$CRED_FILE is missing or empty. The password is then baked into the image and written down nowhere, which is the worst of both arrangements"
qcheck CRED_FILE_MODE      600 "$CRED_FILE is not 0600 - the SIEM admin credential readable by any local account on the box"
qcheck CRED_FILE_OWNER     root:root "$CRED_FILE is not owned by root"
qcheck CRED_FILE_HAS_PW    yes "$CRED_FILE has no WAZUH_ADMIN_PASSWORD line with a value"
qwarn  STAMP_EXISTS        yes "$STAMP_FILE was not written - the image would carry no record of which Wazuh version is frozen inside it"

TARFOUND="$(qget INSTALL_FILES_TAR)"
if [ -n "$TARFOUND" ]; then
  echo "" >&2
  echo "    NOTE: wazuh-install-files.tar is present at:$TARFOUND" >&2
  echo "          It holds EVERY certificate and EVERY password the installer" >&2
  echo "          generated, and it travels into every clone. It is reported and NOT" >&2
  echo "          deleted, because those certificates are what the all-in-one uses and" >&2
  echo "          deleting a bundle this script did not create is not this script's" >&2
  echo "          call to make. Decide deliberately, then:" >&2
  echo "              qm guest exec $SRC_VMID -- /bin/sh -c 'rm -f <path>'" >&2
fi

if [ "$SFAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: post-clean verification failed. NOTHING HAS BEEN SEALED." >&2
  echo "       No clone was made and no template exists. VM $SRC_VMID is left RUNNING" >&2
  echo "       and CLEANED so the failures above can be inspected and fixed in place;" >&2
  echo "       re-running this script against it afterwards is supported." >&2
  echo "" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'ls -la /var/ossec/etc/client.keys /var/ossec/queue/db /var/ossec/queue/rids'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl is-enabled wazuh-manager wazuh-indexer wazuh-dashboard'" >&2
  exit 1
fi
echo "==> Post-clean verification passed"

# ============================================================================
# 4. Stop, clone, template
# ----------------------------------------------------------------------------
# CLONE RATHER THAN CONVERT IN PLACE. The staging lane VM is destroyed when the
# lane is torn down; converting it in place would couple the golden template's
# existence to a lane's lifecycle - somebody tears down a lab and every future
# cohort's SIEM goes with it. Cloning also leaves the source intact, so a seal
# that fails at the template step can be retried without redoing the whole
# staging install.
# ============================================================================
if [ "$FULL_CLONE" != "1" ]; then
  echo "ERROR: FULL_CLONE=$FULL_CLONE, but the source is a VM and not a template." >&2
  echo "       Proxmox only permits LINKED clones from a template, so a linked clone" >&2
  echo "       of $SRC_VMID cannot be made. Leave FULL_CLONE=1." >&2
  exit 1
fi

SNAPS="$(qm listsnapshot "$SRC_VMID" 2>/dev/null | awk '!/current/ && NF { n++ } END { print n+0 }')"
if [ "${SNAPS:-0}" -gt 0 ]; then
  echo "    NOTE: the source has snapshots. The clone is taken from its CURRENT state," >&2
  echo "          which is the cleaned state verified above - not from any snapshot." >&2
fi

echo "==> Shutting down source VM $SRC_VMID"
qm shutdown "$SRC_VMID" --timeout "$SHUTDOWN_TIMEOUT" || qm stop "$SRC_VMID"
for _ in $(seq 1 60); do
  [ "$(qm status "$SRC_VMID" | awk '{print $2}')" = "stopped" ] && break
  sleep 3
done
if [ "$(qm status "$SRC_VMID" | awk '{print $2}')" != "stopped" ]; then
  echo "ERROR: $SRC_VMID did not stop. Refusing to clone a running VM into a golden" >&2
  echo "       template: a disk copied out from under a live indexer is a half-flushed" >&2
  echo "       index in every clone." >&2
  echo "           qm stop $SRC_VMID" >&2
  exit 1
fi

echo "==> Cloning $SRC_VMID -> $VMID (full clone onto $STORAGE)"
qm clone "$SRC_VMID" "$VMID" --name "$NAME" --full 1 --storage "$STORAGE"

# ---- Strip the staging lane's per-deploy configuration off the clone --------
# cicustom points at a cloud-init snippet that belongs to the STAGING LANE and
# that is deleted when that lane is torn down. Left in place, every clone of
# this template boots against a user-data file that no longer exists.
# cipassword is the staging lane's generated password sitting in the template's
# config; the ACCOUNT keeps whatever chpasswd wrote into /etc/shadow, which is
# this repo's bake-debug convention.
echo "==> Clearing the staging lane's cloud-init configuration off the clone"
qm set "$VMID" --delete cicustom   >/dev/null 2>&1 || true
qm set "$VMID" --delete cipassword >/dev/null 2>&1 || true
# DHCP, explicitly. challenge-lane-deployer.js only overwrites ipconfig0 when
# findCloudInitDrive() succeeds; a static pin inherited from the staging lane
# would otherwise race the guest's own DHCP client and win, putting the machine
# at an address the lane's dnsmasq reservation knows nothing about.
# Tolerated rather than fatal here: the explicit ipconfig0 check below gives a
# far better message than an aborted 'qm set' would.
qm set "$VMID" --ipconfig0 ip=dhcp >/dev/null 2>&1 || true

# Capacity, stamped rather than inherited. See the note on TEMPLATE_MEMORY.
qm set "$VMID" --memory "$TEMPLATE_MEMORY" --cores "$TEMPLATE_CORES" --agent enabled=1 >/dev/null

# ---- Things that are cheap to check now and expensive to discover later -----
CI_DRIVE="$(qm config "$VMID" | grep -E '^(ide|sata|scsi|virtio)[0-9]+:.*cloudinit' | head -1)"
if [ -z "$CI_DRIVE" ]; then
  echo "    WARNING: the clone has NO cloud-init drive. findCloudInitDrive() in" >&2
  echo "             challenge-lane-deployer.js looks for one, and without it the" >&2
  echo "             deployer falls back to the baked accounts and publishes" >&2
  echo "             credentials that do not match the machine. Add one before use:" >&2
  echo "                 qm set $VMID --ide2 ${STORAGE}:cloudinit" >&2
  WARN=1
else
  printf '    %-24s %s\n' "cloud-init drive:" "$CI_DRIVE"
fi

SRC_MAC="$(qm config "$SRC_VMID" | sed -n 's/^net0:.*\([0-9A-Fa-f:]\{17\}\).*/\1/p' | head -1)"
NEW_MAC="$(qm config "$VMID"     | sed -n 's/^net0:.*\([0-9A-Fa-f:]\{17\}\).*/\1/p' | head -1)"
printf '    %-24s %s -> %s\n' "net0 MAC:" "${SRC_MAC:-none}" "${NEW_MAC:-none}"
if [ -n "$SRC_MAC" ] && [ "$SRC_MAC" = "$NEW_MAC" ]; then
  echo "    WARNING: the clone kept the source's MAC address. Proxmox normally" >&2
  echo "             regenerates it. The lane deployer sets a deterministic MAC per" >&2
  echo "             clone anyway (goadDeploy.macForOctet), so this is survivable - but" >&2
  echo "             any clone made by hand would collide with the staging lane's" >&2
  echo "             dnsmasq reservation." >&2
  WARN=1
fi

IPCFG="$(qm config "$VMID" | awk -F': ' '/^ipconfig0:/ { print $2; exit }')"
printf '    %-24s %s\n' "ipconfig0:" "${IPCFG:-unset}"
if [ "$IPCFG" != "ip=dhcp" ]; then
  echo "ERROR: the clone's ipconfig0 is '${IPCFG:-unset}', not 'ip=dhcp'." >&2
  echo "       Clones inherit it, and the lane's MAC-pinned reservation is what is" >&2
  echo "       supposed to decide this machine's address." >&2
  exit 1
fi

echo "==> Converting $VMID to a template"
qm template "$VMID"
echo "==> Template $VMID ($NAME) sealed"

# ============================================================================
# 5. What still has to happen by hand
# ============================================================================
WAZUH_VERSION_SEALED="$(pget WAZUH_VERSION)"
RULES_SEALED="$(pget RULES_XML_COUNT)"

cat <<NEXTSTEPS
============================================================================
 Template $VMID ($NAME) is sealed, from staging VM $SRC_VMID.

 Wazuh version frozen inside it : ${WAZUH_VERSION_SEALED:-unknown}
 Rule .xml files in etc/rules   : ${RULES_SEALED:-unknown}
 Admin credential file          : $CRED_FILE  (0600, root)
 Image facts                    : $STAMP_FILE

 ------------------------------------------------------------------------
 THE ADMIN CREDENTIAL, WRITTEN DOWN HERE BECAUSE IT IS BAKED IN.

     user     : ${WAZUH_USER:-admin}
     password : ${WAZUH_PASS}

 THIS IS THE SAME PASSWORD IN EVERY CLONE OF THIS TEMPLATE, and so are the
 indexer certificates that came out of the same installer run. That is
 acceptable for the same reason the repo's 'bake-debug' convention is: lanes
 are per-student and isolated, and nothing in a lane is reachable from
 another. It is written down here rather than discovered later.

 It logs into the dashboard (https://<lane ip>/) and into the indexer API on
 9200. /opt/wazuh/wazuh-install-output.txt has been DELETED, so
 $CRED_FILE is the only copy inside the image.

 TO ROTATE IT, per lane or per cohort, on a running clone:

     /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \\
         -u admin -p '<new password>'
     systemctl restart wazuh-indexer wazuh-dashboard filebeat
     # then update the record inside the image, or nobody will find it again:
     sed -i 's|^WAZUH_ADMIN_PASSWORD=.*|WAZUH_ADMIN_PASSWORD=<new password>|' \\
         $CRED_FILE

 Rotating on the TEMPLATE is not possible - a template's disk is
 snapshot-protected, so the edit silently lands on a clone instead. Rotate on
 a clone, or re-seal.
NEXTSTEPS

cat <<'NEXTSTEPS'

 ------------------------------------------------------------------------
 1. VERIFY A CLONE BEFORE ANY OF THIS REACHES A CLASSROOM.

    This is the only thing in this document that is not optional, and it is
    four facts. Clone once, into any lane or onto the bake VLAN:

        qm clone TEMPLATE_VMID 9994 --name wazuh-test --full --storage STORAGE
        qm set 9994 --net0 virtio,bridge=vmbr0,tag=20 --ipconfig0 ip=dhcp
        qm start 9994

    a. THE SERVICES CAME UP BY THEMSELVES.
           qm guest exec 9994 -- /bin/sh -c \
             'systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat'
       All active. If any is 'inactive' the seal enabled nothing and this
       template is an Ubuntu box with a lot of software on it.

    b. THE DASHBOARD LOADS.
           qm guest exec 9994 -- /bin/sh -c \
             "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/"
       200 or 302. Then open it in a browser and log in with the credential
       above - a dashboard that answers on localhost and rejects the login is
       a clone whose indexer security index did not survive, and that is worth
       finding here rather than in a lane.

    c. ZERO AGENTS ARE LISTED.
           qm guest exec 9994 -- /bin/sh -c '/var/ossec/bin/agent_control -l'
       Exactly one entry, ID 000, the manager itself. ANY OTHER ENTRY MEANS
       THE SEAL FAILED and this template will produce agents that flap across
       every lane at once. Do not use it; re-seal.

    d. ZERO ALERTS.
       Open the dashboard's alert view. It must be empty. An alert dated
       before today is the staging lab's, and every student would open their
       SIEM onto somebody else's incident.

    Then: qm destroy 9994 --purge

 ------------------------------------------------------------------------
 2. THIS TEMPLATE PAIRS WITH WINDOWS IMAGES WHOSE AGENT IS INSTALLED BUT
    NOT REGISTERED. THIS IS THE OTHER HALF OF THE SAME FAILURE.

    Everything section 2.3 of this script did to the MANAGER has an exact
    counterpart on the AGENT side, and getting the manager right does not
    save you from getting the agent wrong.

    A Windows golden image that was snapshotted with a registered agent
    carries /Program Files (x86)/ossec-agent/client.keys with an agent ID and
    key in it. Every clone of that image is then THE SAME AGENT. They all
    present the same ID to their lane's manager, and because a manager only
    keeps one connection per ID, they take turns: connected, disconnected,
    connected - in every lane, simultaneously, with nothing in any log naming
    the cause.

    So the Windows images this template is deployed alongside must have the
    agent INSTALLED and NOT REGISTERED:

      - the MSI may be installed at bake time (that is the slow part, and it
        is the part worth baking)
      - WAZUH_MANAGER may be baked in as a lane-published NAME, never an
        address: the lane gateway's dnsmasq publishes 'wazuh' as a host-record
        exactly as it publishes 'elk', so every clone resolves its OWN lane's
        manager and nothing in the image is per-lane
      - client.keys must be EMPTY and the service must be STOPPED and set to
        start automatically. Enrolment then happens on first boot, in the lane
      - if a Windows image was ever booted with a registered agent, empty its
        client.keys before sealing it. The same rule, the same reason

    Upstream's roles/wazuh_agent installs the MSI with WAZUH_MANAGER and
    WAZUH_REGISTRATION_SERVER pointing at the manager's address and starts the
    service, so an agent baked by running that role IS registered. Empty it.

 ------------------------------------------------------------------------
 3. VERSIONS ARE FROZEN AT SEAL TIME. ALL OF THEM.

    Nothing in this image updates itself and nothing is re-installed per lane.
    Frozen here: the Wazuh manager, the indexer (OpenSearch 2.x), the
    dashboard, filebeat, the SOCFortress rule pack as it existed on the day
    the staging install ran, and the Ubuntu package set underneath all of it.

    That is the WHOLE POINT - it is what makes a lane deploy take a minute
    instead of forty - and it is also the cost. Consequences worth writing on
    the runbook:

      - the agent MSI version baked into the Windows images must stay
        compatible with this manager. Wazuh supports agents older than the
        manager and NOT the reverse; an agent newer than the manager is
        unsupported and fails in ways that look like network faults
      - security updates for this image happen by RE-SEALING, not by apt.
        Running apt upgrade on a clone is fine and helps nobody else
      - re-running this script against a fresh staging lab is the supported
        refresh path. It is also the only way the rule pack moves forward
      - the frozen facts are recorded inside the image, so a clone can be
        interrogated months later without guessing:
            cat /etc/cybercore-wazuh-template.env

 ------------------------------------------------------------------------
 4. CAPACITY. THIS IS THREE PRODUCTS ON ONE BOX.

    Wazuh all-in-one - manager + indexer + dashboard - wants roughly

        4 vCPU / 8 GB RAM / 50 GB disk   for about 25 agents

    The indexer is a JVM and it is the whole of the memory story. This script
    stamped the clone with the memory and cores above; the DISK is inherited
    from the staging VM and cannot be grown after the fact for clones that
    already exist, so check it before you build a cohort on this template.

    An under-provisioned clone does not fail. It stops indexing under load,
    and the symptom is 'alerts stopped arriving' several hours into a class,
    which is the worst possible time to discover a sizing decision.

    A GOAD lane has 4-5 Windows hosts plus a Linux member, so ~25 agents is
    several lanes' worth of headroom for one lane's box. If a lane is smaller
    than that, TEMPLATE_MEMORY=4096 is defensible - but measure a real class
    before shrinking it, not a idle one.

 ------------------------------------------------------------------------
 5. REGISTER THE TEMPLATE.

    goad-deploy.js currently points GOAD_EXTENSIONS.wazuh.template_vmid at
    1011, the PLAIN Ubuntu base, because until now the extension installed
    itself in-lane. Pointing it here is what makes the golden-image path
    actually get used, and it is the one change that turns a 40-minute deploy
    into a clone:

        GOAD_EXTENSIONS.wazuh.template_vmid = <this template>

    THAT CHANGE ALSO MEANS THE IN-LANE INSTALL MUST NOT STILL RUN. A lane that
    clones this image AND runs install_extension wazuh gets roles arriving at
    a machine that already has everything they install, in a version they did
    not choose - and the tasks 'succeed' against state they did not create.
    Whoever flips the VMID owns turning the extension install off for wazuh.

    Admin -> Workstation Templates (or the os_template path):

        os_family      linux
        os_name        Ubuntu 22.04 (Wazuh all-in-one)
        template_vmid  <this template>
        template_key   goad-wazuh-template
        metadata       {"console_protocol": "ssh", "dns_aliases": ["wazuh"]}

    console_protocol=ssh is not cosmetic: resolveConsole() defaults to rdp, so
    leaving it unset publishes a gateway DNAT to 3389 on a headless Linux box
    that is not listening there.

    dns_aliases is what lets the Windows agents find their own lane's manager
    by name instead of by an address baked into their image. Without it they
    resolve nothing and the symptom is a healthy manager with no agents - the
    same silent failure the loggen sensor documents for 'elk'.

    Then POST /api/admin/vm-templates/sync-nodes so 'node' is filled in.
    Do NOT add a seed migration: front-end/migrations/ has no runner, so a file
    there would never execute.

 ------------------------------------------------------------------------
 6. WHAT THIS SCRIPT COULD NOT VERIFY, AND WHO HAS TO.

    a. That a clone boots and comes up healthy. Section 1 above. Nothing in
       this script has ever seen a clone of anything it produced.
    b. That the agents in a real lane enrol against it. That needs a lane,
       Windows images prepared as in section 2, and the dnsmasq alias.
    c. That the frozen manager version accepts the agent version baked into
       the Windows images. Manager >= agent; check both.
    d. That the SOCFortress rules present at seal time actually fire. The
       count was verified; behaviour was not.
    e. That the lane gateway publishes 'wazuh'. That is a deploy-time property
       of the lane, not a property of this image.

 ------------------------------------------------------------------------
 7. THE SOURCE VM.

    It is STOPPED and it has been CLEANED IN PLACE - its client.keys is empty,
    its indexer holds no alerts and its logs are gone. It is still a perfectly
    good machine and re-running this seal against it works, but it is no
    longer a staging lab with history: the agent-enrolment check will read
    zero on every pass from now on, and that is this script's doing, not a
    regression.

    Restart it if the lane is still wanted, or let the lane teardown remove
    it. The template no longer depends on it either way - that is why this
    script cloned instead of converting in place.
NEXTSTEPS

cat <<NEXTSTEPS

        qm start $SRC_VMID          # if the staging lane is still wanted
        qm destroy $VMID --purge    # to re-seal from scratch

 Overridable variables (all as VAR=value before the script):
   SRC_VMID (required)  VMID=$VMID  NAME=$NAME  STORAGE=$STORAGE
   FULL_CLONE=$FULL_CLONE  TEMPLATE_MEMORY=$TEMPLATE_MEMORY  TEMPLATE_CORES=$TEMPLATE_CORES
   MIN_ROOT_GB=$MIN_ROOT_GB  CRED_FILE=$CRED_FILE
   INSTALL_OUTPUT=$INSTALL_OUTPUT  STAMP_FILE=$STAMP_FILE
   INDEXER_URL=$INDEXER_URL  DASHBOARD_URL=$DASHBOARD_URL
   MIN_RULE_XML=$MIN_RULE_XML  REQUIRE_SOCFORTRESS=$REQUIRE_SOCFORTRESS
   REQUIRE_AGENT_HISTORY=$REQUIRE_AGENT_HISTORY
   REQUIRE_LOOPBACK_CONFIG=$REQUIRE_LOOPBACK_CONFIG
   REMOVE_CUSTOM_GROUPS=$REMOVE_CUSTOM_GROUPS
   GUEST_TIMEOUT=$GUEST_TIMEOUT  GUEST_TIMEOUT_LONG=$GUEST_TIMEOUT_LONG
   SHUTDOWN_TIMEOUT=$SHUTDOWN_TIMEOUT

 REMINDER: this script has never been executed. Section 1 above is the
 experiment that decides whether any of it worked.
============================================================================
NEXTSTEPS

if [ "$WARN" -ne 0 ]; then
  echo ""
  echo "NOTE: the run above produced WARNINGS. The template was sealed anyway because"
  echo "      none of them makes it wrong, but read them before a cohort depends on it."
fi
