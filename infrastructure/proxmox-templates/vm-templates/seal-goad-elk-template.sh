#!/bin/bash
# ============================================================================
# seal-goad-elk-template.sh
# ----------------------------------------------------------------------------
# ############################################################################
# # THIS SCRIPT HAS NEVER BEEN EXECUTED.                                     #
# #                                                                          #
# # Not one line of it has run on a Proxmox node, against an installed ELK    #
# # box, or against any VM. No template 1012 exists on any cluster and no     #
# # staging lab has ever been sealed, so nothing here has been validated end  #
# # to end and NOTHING HERE SHOULD BE TRUSTED AS WORKING. Specifically        #
# # unverified:                                                              #
# #                                                                          #
# #   - WHICH TEMPLATE NAMESPACE winlogbeat actually writes into. Beats 7.x   #
# #     installs a LEGACY template (GET _template/winlogbeat-7.17.6); beats   #
# #     8.x installs a COMPOSABLE one (GET _index_template/...). Section 1    #
# #     accepts EITHER and has been run against NEITHER. If both come back    #
# #     zero on a box whose Kibana visibly has the dashboards, the QUERY is   #
# #     what is wrong — fix the query, do not lower the bar.                  #
# #   - that `qm guest exec` returns a whole `_cat/indices` listing from a    #
# #     box with hundreds of indices inside GX_TIMEOUT                        #
# #   - that Elasticsearch stops, restarts and re-serves inside               #
# #     ES_RESTART_WAIT at this image's sizing                                #
# #   - that Kibana comes back inside KBN_RESTART_WAIT. Kibana's cold start   #
# #     is minutes, not seconds, and that budget is a guess                   #
# #   - that the temporary INPUT DROP rules in section 2 are accepted (a box  #
# #     using nftables natively still answers iptables-nft, but nobody has    #
# #     watched it happen) and that removing them leaves nothing behind       #
# #   - every Kibana API path used below. /api/status and                     #
# #     /api/saved_objects/_find are documented as stable across 7.x and 8.x; #
# #     that is reading, not measuring                                        #
# #   - that a clone of the template this produces boots at all               #
# #                                                                          #
# # Treat the FIRST run of this script as the experiment, not the deploy.     #
# # Every check below exists so that experiment fails loudly HERE instead of  #
# # quietly, in twenty lanes, in a classroom.                                 #
# ############################################################################
#
# Turns ONE already-installed ELK box from a staging GOAD lab into a golden
# Proxmox template that clones correctly into any number of student lanes.
#
# Input : SRC_VMID — a RUNNING lane VM that `install_extension elk` has already
#                    finished against. REQUIRED. No default.
# Output: a template at VMID (default 1012), cloned from it, cleaned, verified.
#
# ----------------------------------------------------------------------------
# WHY THIS IS A SEAL SCRIPT AND NOT A BAKE SCRIPT
# ----------------------------------------------------------------------------
# GOAD ships elk as an EXTENSION (GOAD-main/extensions/elk/). Upstream's flow is
# `install_extension elk`, which adds an Ubuntu 22.04 server and runs the
# extension's own Ansible: roles/elk on that server, plus roles/logs_windows —
# Sysmon + winlogbeat — on every host in [domain].
#
# CyberCore lanes DO have internet (bake-lane-gateway-v3.sh MASQUERADEs both
# lane subnets out wan0; the only FORWARD drops are scoped -d 100.100.0.0/16,
# the lab backbone), so that install genuinely runs in-lane. It is merely
# expensive: ~25-40 minutes and ~2 GB of download EVERY TIME. The per-host half
# is worse — roles/logs_windows REBOOTS every Windows host (win_reboot,
# post_reboot_delay: 100) and runs `winlogbeat setup -e` once per host with no
# run_once, which is identical GLOBAL work repeated three or four times.
#
# So: run it ONCE against a staging lab, snapshot the result, clone forever.
#
# That is strictly better than a standalone ELK bake for one specific reason,
# and that reason is also why the CLEAN below is delicate: the elk box
# snapshotted from a REAL lab already has winlogbeat's index templates, its ILM
# policy and its DASHBOARDS loaded into its own Elasticsearch and Kibana — the
# agents did that themselves during the install, via `winlogbeat setup -e`
# against setup.kibana. A standalone bake cannot produce any of it without a
# Windows host to run setup from. Sealing from a real lab is how those artifacts
# get into the image at all.
#
# ----------------------------------------------------------------------------
# THE ONE THING THIS SCRIPT IS FOR: DELETE THE DATA, KEEP THE SETUP
# ----------------------------------------------------------------------------
# Both live in the SAME Elasticsearch. Get it backwards and you get one of two
# failures, and both of them ship:
#
#   too little deleted -> every student opens Kibana on the STAGING LAB'S LOGS.
#                         In a defensive_monitoring exercise those logs ARE the
#                         answer key: the bake lab's intrusion, its hostnames,
#                         its alerts, sitting in Discover on day one.
#   too much deleted   -> the index templates, the ILM policy and the dashboards
#                         go with the data, and the image is now worth exactly
#                         what a standalone bake is worth — which is to say the
#                         entire reason for sealing from a real lab is gone and
#                         nothing says so. Kibana still loads. It is just empty
#                         of everything that made it worth freezing.
#
# So the contract is explicit, enforced by NAME, and enforced in both
# directions:
#
#   DELETE  the data indices and data streams, by name: winlogbeat-*,
#           .ds-winlogbeat-*, logs-*, .ds-logs-*, filebeat-*, metrics-*,
#           .ds-metrics-*, and the detection engine's own signal/alert stores
#           (.siem-signals-*, .alerts-*, .internal.alerts-*), which hold the
#           staging lab's ALERTS and are therefore answer key too.
#           Data streams go FIRST, via _data_stream, because Elasticsearch
#           refuses to delete a backing index out from under a live data stream;
#           whatever concrete indices remain after that are deleted by name.
#   KEEP    .kibana* (the dashboards, the index patterns, every saved object),
#           the index TEMPLATES (composable and legacy), the ILM policies, the
#           component templates, and everything else the setup installed.
#
#   NEVER   `rm -rf /var/lib/elasticsearch`. That is the blunt version of this
#           script and it destroys .kibana* along with the rest. For the same
#           reason nothing here deletes Elasticsearch's node state directory:
#           the cluster metadata IS where index templates and ILM policies live.
#
#   NEVER   a wildcard in a DELETE URL. Every deletion below names one exact
#           index or one exact data stream, enumerated first and printed before
#           it happens. A wildcard DELETE is one typo away from .kibana, and
#           `action.destructive_requires_name` is not set in GOAD's shipped
#           elasticsearch.yml, so nothing in the cluster would stop it.
#
# The KEEP list is a VETO and it is tested FIRST: a name matching both lists is
# KEPT. That is what makes DELETE_PATTERNS safe for a future toucher to widen.
#
# Section 3 then RE-STARTS Elasticsearch and asserts both halves — winlogbeat's
# template still present, winlogbeat data gone, .kibana* still present. That
# pair of assertions is what makes this script trustworthy rather than hopeful,
# and it is why the clean does not simply end in a shutdown.
#
# ----------------------------------------------------------------------------
# WHY CLONE, AND NOT `qm template` THE STAGING VM IN PLACE
# ----------------------------------------------------------------------------
# The staging lane is a lane. It gets torn down — by a re-bake, by the boot
# sweep, by somebody tidying up. Converting its elk VM in place would couple the
# golden template's existence to that lane's lifecycle: destroy the lane and the
# thing every future cohort clones from goes with it.
#
# Cloning also leaves the source INTACT, so a failed seal is retryable without
# redoing a 40-minute staging install. That matters more here than usual,
# because this script deletes things.
#
# The clone is FULL, never linked, and that is not a preference: a linked clone
# keeps a reference to the staging VM's disk, which is precisely the coupling
# this section exists to remove. (Clones OF THE TEMPLATE, later, can be linked.)
#
# ----------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES NOT DO
# ----------------------------------------------------------------------------
#   - It does not install anything. If `install_extension elk` has not finished
#     against SRC_VMID, section 1 refuses rather than sealing half a stack.
#   - It does not touch the Windows hosts. Their winlogbeat/Sysmon install is
#     sealed into the Windows golden images by whoever seals those; hand-off
#     section 4 says what must be true of them for this template to be useful.
#   - It does not register anything in CyberCore. Hand-off section 2.
#   - It does not choose the stack version. Whatever the staging install landed
#     is what gets FROZEN, which is why section 1 prints it in large letters.
#
# Run on the Proxmox node that holds SRC_VMID: `qm` and `qm guest exec` are both
# node-local. Idempotent in the way that matters: it refuses if VMID already
# exists. To re-seal: qm destroy 1012 --purge, then run it again.
# ============================================================================
set -euo pipefail

# ============================================================================
# Tunables. Every one is VAR="${VAR:-default}" except SRC_VMID, which has no
# default on purpose — there is no sane guess for "which VM is the staging
# lab's elk", and a wrong guess seals the wrong machine forever.
# ============================================================================
SRC_VMID="${SRC_VMID:-}"
VMID="${VMID:-1012}"
NAME="${NAME:-goad-elk-golden-template}"
STORAGE="${STORAGE:-vmpool}"

# `qm guest exec` waits synchronously. GX_TIMEOUT covers the ordinary checks;
# GX_LONG covers deleting every index on a busy staging box, and waiting for
# Elasticsearch or Kibana to come back — either of which is minutes, not
# seconds.
GX_TIMEOUT="${GX_TIMEOUT:-120}"
GX_LONG="${GX_LONG:-900}"

# Where the guest reaches its own stack. 127.0.0.1 on purpose: the subject here
# is the MACHINE, not the lane. Querying through the lane address would prove
# something about the lane's DNS instead, which is a different question and is
# the hand-off block's job.
ES_SCHEME="${ES_SCHEME:-http}"
ES_HOST="${ES_HOST:-127.0.0.1}"
ES_PORT="${ES_PORT:-9200}"
KBN_SCHEME="${KBN_SCHEME:-http}"
KBN_HOST="${KBN_HOST:-127.0.0.1}"
KBN_PORT="${KBN_PORT:-5601}"
CURL_MAX="${CURL_MAX:-25}"

# Extra curl options, word-split inside the guest. Needed only if the staging
# install turned Elasticsearch security ON — then '-u elastic:...' or '-k' goes
# here. NOTE THE EXPOSURE: it lands in the guest's argv and is visible to `ps`
# on that box for the duration of each call. On a staging VM that is about to be
# destroyed that is an acceptable trade; anywhere else it is not.
ES_CURL_OPTS="${ES_CURL_OPTS:-}"
KBN_CURL_OPTS="${KBN_CURL_OPTS:-}"

# ---- The delete/keep contract. See the header. ----
# Shell globs, space separated, matched with `case` against each index and data
# stream NAME. KEEP is a veto and is tested first.
DELETE_PATTERNS="${DELETE_PATTERNS:-winlogbeat winlogbeat-* .ds-winlogbeat-* logs-* .ds-logs-* filebeat-* .ds-filebeat-* metrics-* .ds-metrics-* metricbeat-* packetbeat-* auditbeat-* heartbeat-* .siem-signals-* .ds-.siem-signals-* .alerts-* .ds-.alerts-* .internal.alerts-* .ds-.internal.alerts-* .monitoring-* .ds-.monitoring-* .logs-endpoint.* .ds-.logs-endpoint.*}"
# Everything that IS the setup, plus every system index whose loss would make
# the image worse in a way nobody notices until a clone. .kibana* is first
# because protecting it is the reason this script exists.
KEEP_PATTERNS="${KEEP_PATTERNS:-.kibana .kibana* .ds-.kibana* .apm-agent-configuration .apm-custom-link .security* .ds-.security* .fleet* .ds-.fleet* .tasks .geoip_databases .async-search* .ml-* .transform* .watches .triggered_watches .slm-history* .ds-.slm-history* .lists-* .items-*}"

# ---- Refusal levers. Every one defaults to the SAFE side. ----
# The staging lab shipped no winlogbeat DATA. Set to 1 only when the index
# TEMPLATE is present (so `winlogbeat setup` demonstrably ran) and you are
# knowingly sealing without end-to-end proof that events flow.
ALLOW_NO_DATA="${ALLOW_NO_DATA:-0}"
# Kibana auto-generating its encryptedSavedObjects key is a WARNING by default,
# because it does not break plain dashboards. Set to 1 to make it a refusal —
# which is the correct setting the moment detection rules are part of the image,
# since their own API keys are encrypted saved objects.
REQUIRE_KIBANA_ENC_KEY="${REQUIRE_KIBANA_ENC_KEY:-0}"
# The staging lab's Windows hosts are still up and still shipping while this
# runs. Deleting an index that an agent re-creates four seconds later is the
# failure this guards against: temporary INPUT DROP rules on 9200/5601/5044 for
# non-loopback traffic, inserted before the delete and removed before the clone.
# They are RUNTIME state only — nothing here calls iptables-save — so a reboot
# clears them even if this script dies half way. Set to 0 if you have already
# powered the Windows hosts off, which is the better answer when you can.
SEAL_ISOLATE="${SEAL_ISOLATE:-1}"
# Seconds between the two document counts that prove the agents have gone quiet.
QUIESCE_WAIT="${QUIESCE_WAIT:-20}"

# ---- Section 3 budgets ----
ES_RESTART_WAIT="${ES_RESTART_WAIT:-300}"
VERIFY_KIBANA="${VERIFY_KIBANA:-1}"
KBN_RESTART_WAIT="${KBN_RESTART_WAIT:-420}"

# ---- Section 4 ----
SHUTDOWN_TIMEOUT="${SHUTDOWN_TIMEOUT:-300}"
# A hard `qm stop` is a power cut. Elasticsearch has already been stopped
# cleanly by then, so the risk is a half-written ext4 journal rather than a torn
# shard — but that journal is inherited by every lane, so this is opt-in.
ALLOW_FORCE_STOP="${ALLOW_FORCE_STOP:-0}"
# The clone inherits the staging lane's net0: its SDN vnet AND its pinned MAC.
# Both are wrong in a template. The vnet is deleted with the lane, so a
# hand-clone of this template would fail to start; the MAC is the staging elk's,
# so a hand-clone would collide with that lane's dnsmasq reservation and take
# the staging box's address. challenge-lane-deployer.js OVERWRITES net0 on every
# clone it makes (cloneExtraWorkstation: one PUT with the lane vnet and a
# deterministic MAC), so this only bites clones made by hand — which is exactly
# what the smoke test in the hand-off block is.
NORMALIZE_NET0="${NORMALIZE_NET0:-1}"
TEMPLATE_BRIDGE="${TEMPLATE_BRIDGE:-vmbr0}"
TEMPLATE_VLAN="${TEMPLATE_VLAN:-}"
TEMPLATE_NIC_MODEL="${TEMPLATE_NIC_MODEL:-virtio}"
# `qm set --protection 1` on the finished template. Off by default because
# protection also blocks `qm destroy`, and re-sealing means destroying.
PROTECT="${PROTECT:-0}"

# Print the plan, change nothing, exit 0. The source VM is left exactly as it
# was found: running, isolated only if it was already, still holding its data.
DRY_RUN="${DRY_RUN:-0}"

ES_BASE="${ES_SCHEME}://${ES_HOST}:${ES_PORT}"
KBN_BASE="${KBN_SCHEME}://${KBN_HOST}:${KBN_PORT}"

# ============================================================================
# 0. Sanity — everything refusable before anything is touched
# ============================================================================
FAIL_ARGS=0

if [ -z "$SRC_VMID" ]; then
  echo "ERROR: SRC_VMID is required and has no default." >&2
  echo "" >&2
  echo "       It is the VMID of the RUNNING staging-lab elk VM that" >&2
  echo "       'install_extension elk' has already finished against. There is no" >&2
  echo "       sane default, and a wrong guess seals the wrong machine into a" >&2
  echo "       golden image that every future lane clones from." >&2
  echo "" >&2
  echo "       Find it on this node:" >&2
  echo "           qm list | grep -i elk" >&2
  echo "       Then:" >&2
  echo "           SRC_VMID=<vmid> $0" >&2
  FAIL_ARGS=1
fi

for pair in "SRC_VMID:$SRC_VMID" "VMID:$VMID"; do
  pname="${pair%%:*}"; pval="${pair#*:}"
  [ -z "$pval" ] && continue
  if ! printf '%s' "$pval" | grep -Eq '^[0-9]{3,9}$'; then
    echo "ERROR: $pname='$pval' is not a VMID." >&2
    FAIL_ARGS=1
  fi
done

if [ -n "$SRC_VMID" ] && [ "$SRC_VMID" = "$VMID" ]; then
  echo "ERROR: SRC_VMID and VMID are both $VMID." >&2
  echo "       This script CLONES the source to a new VMID and templates the clone;" >&2
  echo "       it never converts the source in place. See the header for why that" >&2
  echo "       distinction is the difference between a golden template that outlives" >&2
  echo "       the staging lane and one that is destroyed with it." >&2
  FAIL_ARGS=1
fi

# ---- 1011 IS NOT AVAILABLE, and this is the loud one ----
# 1011 is bake-ubuntu-lab-template.sh's output: the BLANK Ubuntu 22.04 base with
# no SIEM software in it at all. It is what this elk box was itself cloned from,
# and it is still what wazuh and lx01 clone from. Overwriting it with a sealed
# ELK image would put a 5 GB Elasticsearch inside every future wazuh and lx01
# machine, and roles/wazuh_manager would then arrive at a box already running a
# JVM on the ports its all-in-one installer wants. Nothing about that fails
# loudly: it fails as a Wazuh role that installs cleanly and a service that will
# not start, weeks later.
if [ "$VMID" = "1011" ]; then
  echo "ERROR: VMID=1011 is the PLAIN UBUNTU BASE (ubuntu-lab-template)." >&2
  echo "       It must NOT be overwritten." >&2
  echo "" >&2
  echo "       1011 carries NO SIEM software by design (see the header of" >&2
  echo "       bake-ubuntu-lab-template.sh: 'DO NOT ADD ELASTICSEARCH'). It is the" >&2
  echo "       image this staging elk box was cloned from, and GOAD_EXTENSIONS.wazuh" >&2
  echo "       and .lx01 in front-end/src/utils/goad-deploy.js still point at it." >&2
  echo "       Sealing an installed ELK on top of it hands every future wazuh box an" >&2
  echo "       Elasticsearch it did not ask for, on the ports wazuh-install.sh wants." >&2
  echo "" >&2
  echo "       The golden ELK template is 1012. Re-run with VMID unset." >&2
  FAIL_ARGS=1
fi

# The rest of the reserved block, for a fresh node where those templates do not
# exist yet and the `qm status` collision check below would therefore pass.
# 1001-1008 OS/base templates; 1011 above; 1699/1700/1701/1702/1710 Kali, the
# GOAD controller, its frozen rollback, DVWA/Juice-Shop, CyberSaguaros.
case " 1001 1002 1003 1004 1005 1006 1007 1008 1699 1700 1701 1702 1710 " in
  *" $VMID "*)
    echo "ERROR: VMID=$VMID is a RESERVED template id on this platform." >&2
    echo "       Taken: 1001-1008 (OS/base), 1011 (ubuntu-lab), 1699 (Kali)," >&2
    echo "       1700 (GOAD controller), 1701 (its frozen rollback), 1702" >&2
    echo "       (DVWA/Juice-Shop), 1710 (CyberSaguaros). The golden ELK is 1012." >&2
    FAIL_ARGS=1
    ;;
esac

[ "$FAIL_ARGS" -ne 0 ] && exit 1

command -v qm >/dev/null 2>&1 || {
  echo "ERROR: qm not found. Run this ON the Proxmox node that holds $SRC_VMID —" >&2
  echo "       qm and 'qm guest exec' are both node-local." >&2
  exit 1
}

if qm status "$VMID" >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists on this node." >&2
  echo "       Refusing to overwrite a template that lanes may already clone from." >&2
  echo "       To re-seal deliberately:  qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status "$VMID" >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
  exit 1
fi
if ! qm status "$SRC_VMID" >/dev/null 2>&1; then
  echo "ERROR: source VM $SRC_VMID not found ON THIS NODE." >&2
  echo "       Find which node holds it:" >&2
  echo "           pvesh get /cluster/resources --type vm --output-format json | grep -i elk" >&2
  echo "       then run this script there." >&2
  exit 1
fi

SRC_STATE="$(qm status "$SRC_VMID" | awk '{print $2}')"
if [ "$SRC_STATE" != "running" ]; then
  echo "ERROR: source VM $SRC_VMID is '$SRC_STATE', not running." >&2
  echo "       Every check and every clean below goes over 'qm guest exec', which" >&2
  echo "       needs a running guest. Sealing a stopped box would silently skip ALL" >&2
  echo "       of it and produce a template indistinguishable from a correct one." >&2
  echo "           qm start $SRC_VMID     # then wait for the guest agent" >&2
  exit 1
fi

if qm config "$SRC_VMID" 2>/dev/null | grep -qE '^template:[[:space:]]*1'; then
  echo "ERROR: source VM $SRC_VMID is already a TEMPLATE." >&2
  echo "       A template does not run, so nothing here can inspect or clean it. If a" >&2
  echo "       previous attempt converted it in place, that is the mistake this" >&2
  echo "       script's header exists to prevent: clone it to a scratch VMID, boot" >&2
  echo "       that, and point SRC_VMID at the clone." >&2
  exit 1
fi

# ---- The guest agent has to answer, and answer the EXEC rpc specifically ----
# `qm agent ping` succeeding while guest-exec returns 596 is a real state (the
# RPC blacklist that bake-caldera-server.sh clears at bake time), and it is the
# one that looks perfectly healthy from outside.
if ! qm agent "$SRC_VMID" ping >/dev/null 2>&1; then
  echo "ERROR: the guest agent on $SRC_VMID does not answer a ping." >&2
  echo "       Nothing below can run. Check, in order:" >&2
  echo "           qm config $SRC_VMID | grep agent        # wants agent: enabled=1" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/true" >&2
  echo "       and inside the guest: systemctl status qemu-guest-agent" >&2
  exit 1
fi

# ============================================================================
# 0b. guest_sh — run a script inside the guest and get its output back
# ----------------------------------------------------------------------------
# Lifted from scripts/verify-track-e-lane.sh for the reason that file gives:
# `qm guest exec` returns JSON and out-data is a JSON STRING, so real newlines
# arrive as the two characters backslash-n and every quote arrives escaped. The
# bake scripts' sed idiom stops at the first quote, which cannot survive output
# that is ITSELF JSON — and every Elasticsearch and Kibana response below is
# exactly that.
#
# So the guest base64s its own output before handing it back. That alphabet is
# [A-Za-z0-9+/=]: no quotes, no backslashes, so the sed idiom is then exact. The
# script we send goes over in base64 too, which is what lets these payloads
# contain single quotes, dollars, JSON and Python with no escaping analysis at
# all.
#
# The guest's exit code travels INSIDE the payload as a __RC= line and becomes
# this function's return value: `qm guest exec` succeeds whenever it managed to
# RUN something, which is a different question from whether that thing worked.
#
# 97/98/99 are TRANSPORT failures (nothing came back / no out-data / no __RC),
# deliberately outside the range any guest payload here returns.
# ============================================================================
guest_sh() {   # guest_sh <script text> [timeout] -> guest stdout+stderr on ours
  local script="$1" tmo="${2:-$GX_TIMEOUT}" enc raw b64 txt rc
  enc=$(printf '%s' "$script" | base64 | tr -d '\n\r')
  raw=$(qm guest exec "$SRC_VMID" --timeout "$tmo" -- /bin/sh -c \
    "echo $enc | base64 -d > /tmp/.cc-seal.sh; sh /tmp/.cc-seal.sh > /tmp/.cc-seal.out 2>&1; echo \"__RC=\$?\" >> /tmp/.cc-seal.out; base64 /tmp/.cc-seal.out | tr -d '\n'; rm -f /tmp/.cc-seal.sh /tmp/.cc-seal.out" 2>/dev/null) || true
  if [ -z "$raw" ]; then
    echo "    (guest_sh: nothing came back from 'qm guest exec $SRC_VMID' within ${tmo}s)" >&2
    return 97
  fi
  b64=$(printf '%s' "$raw" | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -z "$b64" ]; then
    echo "    (guest_sh: no out-data in the guest-exec reply: ${raw:0:200})" >&2
    return 98
  fi
  txt=$(printf '%s' "$b64" | tr -d ' \r\n\\' | base64 -d 2>/dev/null || true)
  if [ -z "$txt" ]; then
    echo "    (guest_sh: out-data did not decode as base64)" >&2
    return 98
  fi
  rc=$(printf '%s\n' "$txt" | sed -n 's/^__RC=\([0-9][0-9]*\)$/\1/p' | tail -1)
  [ -n "$rc" ] || rc=99
  printf '%s\n' "$txt" | grep -v '^__RC=' || true
  return "$rc"
}

# Fail the whole run on a transport failure, with the command to run next. A
# guest that stopped answering half way through a CLEAN is the one situation
# where carrying on is worse than stopping.
transport_die() {   # transport_die <rc> <what was being done>
  echo "" >&2
  echo "ERROR: lost the guest agent while $2 (guest_sh rc=$1)." >&2
  echo "       VM $SRC_VMID is left RUNNING and NOTHING has been templated." >&2
  echo "       Check it by hand before re-running:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl is-active elasticsearch kibana'" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'iptables -S INPUT | grep CYBERCORE-SEAL'" >&2
  echo "       If those iptables rules are present, this run inserted them and did not" >&2
  echo "       get to remove them. They are runtime-only (nothing was saved), so a" >&2
  echo "       reboot clears them; or delete them by hand before re-running." >&2
  exit 1
}

# The configuration every guest payload needs, prepended to each one. Built here
# with host expansion; the payloads themselves are QUOTED heredocs, so nothing
# inside them expands until the guest runs it.
GUEST_ENV="ES_BASE='${ES_BASE}'
KBN_BASE='${KBN_BASE}'
CURL_OPTS='${ES_CURL_OPTS}'
KBN_OPTS='${KBN_CURL_OPTS}'
CURL_MAX='${CURL_MAX}'
"

# The shared preamble: curl wrappers and a JSON reader, so there is exactly one
# definition of "ask Elasticsearch something" in this file.
read -r -d '' GUEST_LIB <<'GUEST_LIB_EOF' || true
set -u
T=/tmp/.cc-seal-json
mkdir -p "$T" 2>/dev/null || true
m() { printf '%s=%s\n' "$1" "$2"; }
yn() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

# $CURL_OPTS and $KBN_OPTS are deliberately UNQUOTED: they are operator-supplied
# option lists ('-u elastic:pw', '-k') and must word-split to be options at all.
# Everything else in this file is quoted.
es_get()  { curl -s --max-time "$CURL_MAX" $CURL_OPTS "$ES_BASE$1" 2>/dev/null; }
es_code() { curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_MAX" $CURL_OPTS "$ES_BASE$1" 2>/dev/null; }
es_del()  { curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_MAX" $CURL_OPTS -X DELETE "$ES_BASE$1" 2>/dev/null; }
es_post() { curl -s --max-time "$CURL_MAX" $CURL_OPTS -X POST -H 'Content-Type: application/json' "$ES_BASE$1" -d "$2" 2>/dev/null; }
kb_get()  { curl -s --max-time "$CURL_MAX" $KBN_OPTS "$KBN_BASE$1" 2>/dev/null; }
kb_code() { curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_MAX" $KBN_OPTS "$KBN_BASE$1" 2>/dev/null; }

# jget <json-file> <python expression over d>. Prints '' on ANY error, including
# a body that is an Elasticsearch error object rather than the shape expected —
# which is why every caller treats '' as "could not tell", never as "zero".
jget() {
  python3 -c "
import json,sys
try:
    d = json.load(open(sys.argv[1]))
    print($2)
except Exception:
    print('')
" "$1"
}

# One config line out of a YAML file, unquoted. Deliberately dumb: these files
# are Elastic's own shipped configs plus GOAD's copies, all flat key: value.
cfg() { grep -E "^[[:space:]]*$2[[:space:]]*:" "$1" 2>/dev/null | head -1 | sed "s/^[^:]*:[[:space:]]*//; s/[\"']//g"; }
GUEST_LIB_EOF

echo "============================================================================"
echo " seal-goad-elk-template.sh"
echo "   source VM  : $SRC_VMID   (staging lab elk, running)"
echo "   template   : $VMID  ($NAME)  on $STORAGE"
echo "   stack seen : $ES_BASE  /  $KBN_BASE   (from inside the guest)"
echo "   isolate    : SEAL_ISOLATE=$SEAL_ISOLATE      dry run: DRY_RUN=$DRY_RUN"
echo "============================================================================"

# ============================================================================
# 1. PRE-CLEAN VERIFICATION
# ----------------------------------------------------------------------------
# Prove the install worked BEFORE preserving it forever. Sealing a
# half-installed box is the worst outcome available here, because it looks
# exactly like a success: a template appears, lanes clone it, and every one of
# them is broken in the same way at the same time.
# ============================================================================
read -r -d '' PRECHECK_SH <<'PRECHECK_EOF' || true
m HOSTNAME "$(hostname 2>/dev/null)"
ID=""; VERSION_ID=""
[ -r /etc/os-release ] && . /etc/os-release
m OS_ID "${ID:-unknown}"
m OS_VERSION_ID "${VERSION_ID:-unknown}"

# ---- tools the rest of this script needs INSIDE the guest ----
m HAS_CURL     "$(yn command -v curl)"
m HAS_PYTHON3  "$(yn command -v python3)"
m HAS_IPTABLES "$(yn command -v iptables)"

# ---- services ----
m ES_SERVICE_ACTIVE    "$(yn systemctl is-active elasticsearch)"
m ES_SERVICE_ENABLED   "$(yn systemctl is-enabled elasticsearch)"
m KBN_SERVICE_ACTIVE   "$(yn systemctl is-active kibana)"
m KBN_SERVICE_ENABLED  "$(yn systemctl is-enabled kibana)"
m LOGSTASH_ACTIVE      "$(yn systemctl is-active logstash)"
m GUEST_AGENT_ENABLED  "$(yn systemctl is-enabled qemu-guest-agent)"
m GUEST_AGENT_ACTIVE   "$(yn systemctl is-active qemu-guest-agent)"
m HOSTKEY_UNIT_ENABLED "$(yn systemctl is-enabled cybercore-ssh-hostkeys.service)"

# ---- Elasticsearch: is it there, and WHICH VERSION is about to be frozen ----
m ES_HTTP_CODE "$(es_code /)"
es_get / > "$T/root.json" 2>/dev/null || true
m ES_VERSION      "$(jget "$T/root.json" "d.get('version',{}).get('number','')")"
m ES_BUILD_FLAVOR "$(jget "$T/root.json" "d.get('version',{}).get('build_flavor','')")"
m ES_CLUSTER_NAME "$(jget "$T/root.json" "d.get('cluster_name','')")"
m ES_TAGLINE      "$(jget "$T/root.json" "d.get('tagline','')")"
es_get /_cluster/health > "$T/health.json" 2>/dev/null || true
m ES_HEALTH "$(jget "$T/health.json" "d.get('status','')")"
m ES_NODES  "$(jget "$T/health.json" "d.get('number_of_nodes','')")"

# ---- config facts that decide whether a CLONE works, not this box ----
# network.host must be a non-loopback bind or every clone's agents ship nowhere;
# elasticsearch.hosts in kibana.yml must be localhost, or every clone's Kibana
# talks to THIS staging box, which will not exist. The CYBR400 runbook records
# the setup wizard hardcoding an IP there, which is exactly this trap.
EYML=/etc/elasticsearch/elasticsearch.yml
KYML=/etc/kibana/kibana.yml
m ES_NETWORK_HOST "$(cfg $EYML 'network\.host')"
m ES_HTTP_PORT    "$(cfg $EYML 'http\.port')"
m ES_SECURITY     "$(cfg $EYML 'xpack\.security\.enabled')"
m ES_DISCOVERY    "$(cfg $EYML 'discovery\.type')"
m KBN_SERVER_HOST "$(cfg $KYML 'server\.host')"
m KBN_ES_HOSTS    "$(cfg $KYML 'elasticsearch\.hosts')"
m KBN_PUBLIC_URL  "$(cfg $KYML 'server\.publicBaseUrl')"

# ---- Kibana ----
m KBN_HTTP_CODE "$(kb_code /api/status)"
kb_get /api/status > "$T/kbstatus.json" 2>/dev/null || true
m KBN_VERSION "$(jget "$T/kbstatus.json" "d.get('version',{}).get('number','')")"
m KBN_STATE   "$(jget "$T/kbstatus.json" "(d.get('status',{}).get('overall') or {}).get('level') or (d.get('status',{}).get('overall') or {}).get('state','')")"

# ---- THE ONE THAT MATTERS MOST: did winlogbeat's setup actually land here ----
# BOTH namespaces are asked, because beats 7.x installs a LEGACY template and
# beats 8.x a COMPOSABLE one, and which of those the staging lab produced
# depends on a version this script does not choose.
es_get '/_index_template/winlogbeat*' > "$T/tpl.json" 2>/dev/null || true
m WLB_INDEX_TEMPLATES      "$(jget "$T/tpl.json" "len(d.get('index_templates',[]))")"
m WLB_INDEX_TEMPLATE_NAMES "$(jget "$T/tpl.json" "','.join(t.get('name','') for t in d.get('index_templates',[]))[:200]")"
es_get '/_template/winlogbeat*' > "$T/legtpl.json" 2>/dev/null || true
m WLB_LEGACY_TEMPLATES      "$(jget "$T/legtpl.json" "len([k for k in d if 'winlogbeat' in k.lower()])")"
m WLB_LEGACY_TEMPLATE_NAMES "$(jget "$T/legtpl.json" "','.join(sorted(k for k in d if 'winlogbeat' in k.lower()))[:200]")"
es_get '/_component_template' > "$T/ct.json" 2>/dev/null || true
m WLB_COMPONENT_TEMPLATES "$(jget "$T/ct.json" "len([c for c in d.get('component_templates',[]) if 'winlogbeat' in c.get('name','').lower()])")"
es_get '/_ilm/policy' > "$T/ilm.json" 2>/dev/null || true
m WLB_ILM_POLICIES   "$(jget "$T/ilm.json" "len([k for k in d if 'winlogbeat' in k.lower()])")"
m ILM_POLICIES_TOTAL "$(jget "$T/ilm.json" "len(d)")"

# ---- and did the agents actually SHIP ----
es_get '/winlogbeat-*,.ds-winlogbeat-*/_count?ignore_unavailable=true&allow_no_indices=true' > "$T/wcount.json" 2>/dev/null || true
m WLB_DOC_COUNT "$(jget "$T/wcount.json" "d.get('count','')")"
es_get '/_cat/indices/winlogbeat-*,.ds-winlogbeat-*?format=json&bytes=b&expand_wildcards=all' > "$T/widx.json" 2>/dev/null || true
m WLB_DATA_INDICES "$(jget "$T/widx.json" "len(d) if isinstance(d,list) else ''")"
m WLB_STORE_BYTES  "$(jget "$T/widx.json" "sum(int(i.get('store.size') or 0) for i in d) if isinstance(d,list) else ''")"
es_get '/_data_stream/winlogbeat*' > "$T/wds.json" 2>/dev/null || true
m WLB_DATA_STREAMS "$(jget "$T/wds.json" "len(d.get('data_streams',[]))")"

# WHICH hosts shipped, by name. A template plus data plus three hostnames is
# proof the whole roles/logs_windows pass worked; a template plus data from ONE
# host is a lab where two of the agents failed and nobody noticed.
es_post '/winlogbeat-*,.ds-winlogbeat-*/_search?size=0&ignore_unavailable=true&allow_no_indices=true' '{"size":0,"aggs":{"h":{"terms":{"field":"host.name","size":25}}}}' > "$T/hosts.json" 2>/dev/null || true
m WLB_HOSTS      "$(jget "$T/hosts.json" "len(d.get('aggregations',{}).get('h',{}).get('buckets',[]))")"
m WLB_HOST_NAMES "$(jget "$T/hosts.json" "','.join(str(b.get('key')) for b in d.get('aggregations',{}).get('h',{}).get('buckets',[]))[:300]")"

# ---- the whole index picture, so the plan in section 2 is readable ----
es_get '/_cat/indices?format=json&bytes=b&expand_wildcards=all' > "$T/allidx.json" 2>/dev/null || true
m INDICES_TOTAL  "$(jget "$T/allidx.json" "len(d) if isinstance(d,list) else ''")"
m KIBANA_INDICES "$(jget "$T/allidx.json" "len([i for i in d if i.get('index','').startswith('.kibana')]) if isinstance(d,list) else ''")"

# ---- the dashboards being frozen in ----
tot=0
for t in dashboard visualization index-pattern search lens map config; do
  kb_get "/api/saved_objects/_find?type=$t&per_page=1" > "$T/so.json" 2>/dev/null || true
  n="$(jget "$T/so.json" "d.get('total','')")"
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  m "SO_$(printf '%s' "$t" | tr 'a-z-' 'A-Z_')" "$n"
  tot=$((tot + n))
done
m SAVED_OBJECTS_TOTAL "$tot"

# ---- Kibana's encryption key. See the hand-off block. ----
# Three questions, because they answer differently: is it pinned in the yml, is
# it pinned in the keystore, and did Kibana say out loud that it generated one.
if grep -Eq '^[[:space:]]*xpack\.encryptedSavedObjects\.encryptionKey[[:space:]]*:[[:space:]]*[^[:space:]]' "$KYML" 2>/dev/null; then
  m KBN_ENC_KEY_YML yes
else
  m KBN_ENC_KEY_YML no
fi
KS=/usr/share/kibana/bin/kibana-keystore
if [ -x "$KS" ] && "$KS" list 2>/dev/null | grep -q 'encryptedSavedObjects\.encryptionKey'; then
  m KBN_ENC_KEY_KEYSTORE yes
else
  m KBN_ENC_KEY_KEYSTORE no
fi
if journalctl -u kibana -n 20000 --no-pager 2>/dev/null | grep -qi 'random key for xpack\.encryptedSavedObjects' \
   || grep -rqi 'random key for xpack\.encryptedSavedObjects' /var/log/kibana/ 2>/dev/null; then
  m KBN_ENC_KEY_RANDOM yes
else
  m KBN_ENC_KEY_RANDOM no
fi

# ---- ADDRESSING: DHCP and nothing but DHCP ----
# The lane's MAC-pinned dnsmasq reservation is what decides this machine's IP in
# every clone. A static address baked into the image disagrees with it, and that
# disagreement produces no error anywhere — just a machine that is up, healthy,
# and at the wrong address, which every agent in the lane ships past. The
# netplan parse is python-yaml rather than grep for the reason
# bake-ubuntu-lab-template.sh gives: a netplan `nameservers:` block ALSO
# contains the key `addresses:`, so a naive grep calls every DHCP image static.
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
  ''|PARSE_ERROR*) m NETPLAN_PARSED no ;;
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

# The other two places a static address hides on a Debian-family image, plus
# cloud-init's network handling being switched off (which freezes whatever
# netplan this box happens to have, on an interface name a clone may not have).
if grep -rhqE '^[[:space:]]*Address[[:space:]]*=' /etc/systemd/network/ 2>/dev/null; then
  m SYSTEMD_NET_STATIC yes
else
  m SYSTEMD_NET_STATIC no
fi
if grep -rhqE '^[[:space:]]*iface[[:space:]]+.*[[:space:]]static' /etc/network/interfaces /etc/network/interfaces.d/ 2>/dev/null; then
  m ENI_STATIC yes
else
  m ENI_STATIC no
fi
if grep -rlqE 'network:[[:space:]]*\{?[[:space:]]*config:[[:space:]]*disabled' /etc/cloud/cloud.cfg.d/ 2>/dev/null; then
  m CI_NET_DISABLED yes
else
  m CI_NET_DISABLED no
fi
m IPV4_ADDRS "$(ip -4 -o addr show scope global 2>/dev/null | awk '{printf "%s=%s ", $2, $4}')"
# A stale /etc/hosts entry pinning a lane address is the same class of trap as a
# static address, and it survives everything cloud-init does.
m HOSTS_EXTRA "$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -vE '^(127\.|::1|ff02::|fe00::)' | awk '{printf "%s; ", $0}' | cut -c1-200)"

# ---- room, and the controller key that must survive the clean ----
m ROOT_FS_GB   "$(df -BG --output=size / 2>/dev/null | awk 'NR==2 {gsub(/[^0-9]/,"",$1); print $1}')"
m ROOT_FREE_GB "$(df -BG --output=avail / 2>/dev/null | awk 'NR==2 {gsub(/[^0-9]/,"",$1); print $1}')"
m ES_DATA_MB   "$(du -sm /var/lib/elasticsearch 2>/dev/null | cut -f1)"
m CTRL_KEY_PRESENT "$(yn test -s /etc/ssh/cybercore-controller-authorized_keys)"
exit 0
PRECHECK_EOF

echo ""
echo "==> 1. Pre-clean verification (is this really the machine, and did the install work)"
rc=0
MARKERS="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${PRECHECK_SH}" "$GX_TIMEOUT")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "collecting pre-clean markers"

marker() { printf '%s\n' "$MARKERS" | awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}'; }

FAIL=0
show()  { printf '    %-26s %s\n' "$1:" "$(marker "$1")"; }
check() {  # check <marker> <expected> <what breaks when it is wrong>
  local got; got="$(marker "$1")"
  printf '    %-26s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    FAIL=1
  fi
}

show HOSTNAME
show OS_ID
show OS_VERSION_ID

check HAS_CURL    yes "curl is missing in the guest — every check and every delete below is a curl. apt-get install -y curl, then re-run"
check HAS_PYTHON3 yes "python3 is missing in the guest — the JSON parsing and the netplan check both need it. apt-get install -y python3 python3-yaml, then re-run"

# ---- The stack has to be running AND set to come back on a clone's first boot
check ES_SERVICE_ACTIVE   yes "elasticsearch is not running — either the install never finished or it died. 'journalctl -u elasticsearch -n 100' in the guest"
check ES_SERVICE_ENABLED  yes "elasticsearch is not ENABLED — this box works today and every clone boots without a SIEM. That failure appears once, in a lane, and looks like a broken image"
check KBN_SERVICE_ACTIVE  yes "kibana is not running — 'journalctl -u kibana -n 100'. A stopped Kibana here means the saved-object count below is a lie, not a zero"
check KBN_SERVICE_ENABLED yes "kibana is not ENABLED — every clone boots with Elasticsearch up and no console to look at it through"
check ES_HTTP_CODE    200 "Elasticsearch does not answer on ${ES_BASE}. If this is 401, the staging install turned security ON: pass ES_CURL_OPTS='-u elastic:<pw>' (and read the note by that variable about argv exposure)"
check KBN_HTTP_CODE   200 "Kibana's /api/status is not 200 — it is not serving, so nothing can confirm the dashboards this seal exists to preserve"

ES_VERSION="$(marker ES_VERSION)"
KBN_VERSION="$(marker KBN_VERSION)"
show ES_TAGLINE
show ES_CLUSTER_NAME
show ES_HEALTH
show KBN_STATE
if [ -z "$ES_VERSION" ]; then
  echo "    ERROR: Elasticsearch returned no version.number. The banner is what proves this" >&2
  echo "           is Elasticsearch and not something else answering on 9200." >&2
  FAIL=1
fi
case "$(marker ES_HEALTH)" in
  green|yellow) : ;;
  *)
    echo "    ERROR: cluster health is '$(marker ES_HEALTH)'. RED means shards are unassigned;" >&2
    echo "           sealing now freezes a broken cluster into every lane." >&2
    FAIL=1
    ;;
esac

# ---- The config facts that only bite a CLONE ----
show ES_NETWORK_HOST
show KBN_SERVER_HOST
show KBN_ES_HOSTS
case "$(marker ES_NETWORK_HOST)" in
  0.0.0.0|""|*::*) : ;;
  127.0.0.1|localhost)
    echo "    ERROR: elasticsearch.yml binds network.host=$(marker ES_NETWORK_HOST) — LOOPBACK ONLY." >&2
    echo "           Every clone would come up healthy and no winlogbeat agent anywhere could" >&2
    echo "           reach it. GOAD's shipped elasticsearch.yml sets 0.0.0.0; something has" >&2
    echo "           changed it. Fix it in the guest and re-run rather than sealing this." >&2
    FAIL=1
    ;;
  *) : ;;
esac
case "$(marker KBN_ES_HOSTS)" in
  ''|*localhost*|*127.0.0.1*) : ;;
  *)
    echo "    ERROR: kibana.yml points elasticsearch.hosts at '$(marker KBN_ES_HOSTS)' — an address" >&2
    echo "           that is not localhost. In a clone that address is THIS staging box, which" >&2
    echo "           will not exist, so Kibana never becomes available and the whole image" >&2
    echo "           looks broken. (CYBR400-ELK-RUNBOOK section 3 documents the setup wizard" >&2
    echo "           hardcoding an IP here.) Set it to http://localhost:9200 and re-run." >&2
    FAIL=1
    ;;
esac
[ -n "$(marker HOSTS_EXTRA)" ] && show HOSTS_EXTRA

# ---- THE ONE THAT MATTERS MOST ----
echo "    -- winlogbeat setup artifacts (the reason for sealing from a real lab) --"
show WLB_INDEX_TEMPLATES
show WLB_INDEX_TEMPLATE_NAMES
show WLB_LEGACY_TEMPLATES
show WLB_LEGACY_TEMPLATE_NAMES
show WLB_COMPONENT_TEMPLATES
show WLB_ILM_POLICIES
show WLB_DATA_INDICES
show WLB_DATA_STREAMS
show WLB_DOC_COUNT
show WLB_HOSTS
show WLB_HOST_NAMES

num() { case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac; }
TPL_COMPOSABLE="$(num "$(marker WLB_INDEX_TEMPLATES)")"
TPL_LEGACY="$(num "$(marker WLB_LEGACY_TEMPLATES)")"
TPL_TOTAL=$(( TPL_COMPOSABLE + TPL_LEGACY ))
WLB_DOCS="$(num "$(marker WLB_DOC_COUNT)")"
WLB_IDX="$(num "$(marker WLB_DATA_INDICES)")"
WLB_DS="$(num "$(marker WLB_DATA_STREAMS)")"
WLB_DATA=$(( WLB_IDX + WLB_DS ))

if [ "$TPL_TOTAL" -eq 0 ] && [ "$WLB_DATA" -eq 0 ] && [ "$WLB_DOCS" -eq 0 ]; then
  echo "" >&2
  echo "ERROR: NEITHER a winlogbeat index template NOR any winlogbeat data exists on this" >&2
  echo "       box. THE STAGING LAB'S AGENTS NEVER SHIPPED." >&2
  echo "" >&2
  echo "       roles/logs_windows is what installs winlogbeat on every host in [domain]" >&2
  echo "       and runs 'winlogbeat setup -e', and that setup is the ONLY thing that puts" >&2
  echo "       the index template, the ILM policy and the dashboards into this stack. If" >&2
  echo "       none of it is here, this machine is a bare Elasticsearch + Kibana — which" >&2
  echo "       is exactly what a standalone bake would have produced, and sealing it now" >&2
  echo "       produces a golden image that will make EVERY future lane look broken:" >&2
  echo "       agents ship, nothing maps them, Kibana has no dashboards, and the only" >&2
  echo "       symptom is 'the SIEM does not work' in twenty lanes at once." >&2
  echo "" >&2
  echo "       Fix the staging lab, do not fix this script:" >&2
  echo "           on the GOAD controller:  ./goad.sh -t install_extension -e elk ..." >&2
  echo "           then in the guest:       curl -s $ES_BASE/_cat/indices | grep winlogbeat" >&2
  echo "       and re-run this seal once the Windows hosts have shipped." >&2
  FAIL=1
elif [ "$TPL_TOTAL" -eq 0 ]; then
  echo "" >&2
  echo "ERROR: winlogbeat DATA is present but NO winlogbeat index template is." >&2
  echo "       Both namespaces were asked: GET _index_template/winlogbeat* (beats 8.x)" >&2
  echo "       and GET _template/winlogbeat* (beats 7.x), and both came back empty." >&2
  echo "" >&2
  echo "       The template is the artifact this whole seal exists to preserve — without" >&2
  echo "       it the clone maps every field dynamically and half the dashboards break on" >&2
  echo "       types. Two possibilities, and they need opposite fixes:" >&2
  echo "         a. 'winlogbeat setup' never ran (agents wrote with dynamic mapping)." >&2
  echo "            Fix the staging lab and re-run." >&2
  echo "         b. THIS QUERY IS WRONG for the stack version in play. Check by hand:" >&2
  echo "               qm guest exec $SRC_VMID -- /bin/sh -c 'curl -s $ES_BASE/_cat/templates'" >&2
  echo "            If a winlogbeat template is listed there, fix the query above." >&2
  FAIL=1
elif [ "$WLB_DATA" -eq 0 ] || [ "$WLB_DOCS" -eq 0 ]; then
  if [ "$ALLOW_NO_DATA" = "1" ]; then
    echo "    WARNING: the winlogbeat template is present but there is NO winlogbeat data." >&2
    echo "             ALLOW_NO_DATA=1, so this is being sealed on the strength of the" >&2
    echo "             template alone: 'winlogbeat setup' demonstrably ran, but nothing" >&2
    echo "             proves events actually flow end to end. That proof now has to come" >&2
    echo "             from the first real lane." >&2
  else
    echo "" >&2
    echo "ERROR: the winlogbeat index template is present but NO winlogbeat data is." >&2
    echo "       Setup ran; the agents then shipped nothing. That is usually winlogbeat" >&2
    echo "       installed and not started, or an output host the agents cannot reach." >&2
    echo "       Check on a Windows host:  Get-Service winlogbeat" >&2
    echo "       and in its winlogbeat.yml: output.elasticsearch.hosts" >&2
    echo "" >&2
    echo "       To seal anyway, on the strength of the template alone: ALLOW_NO_DATA=1" >&2
    FAIL=1
  fi
fi

if [ "$(num "$(marker WLB_HOSTS)")" -eq 1 ]; then
  echo "    WARNING: only ONE host ever shipped ($(marker WLB_HOST_NAMES))." >&2
  echo "             roles/logs_windows runs against every host in [domain]; one shipper" >&2
  echo "             means the others failed. The setup artifacts are still valid, so this" >&2
  echo "             is a warning and not a refusal — but the staging lab is not what it" >&2
  echo "             looks like." >&2
fi

# ---- the dashboards about to be frozen in ----
echo "    -- Kibana saved objects being frozen in --"
show SO_DASHBOARD
show SO_VISUALIZATION
show SO_INDEX_PATTERN
show SO_SEARCH
show SO_LENS
show SO_MAP
show SO_CONFIG
show SAVED_OBJECTS_TOTAL
SO_TOTAL_PRE="$(num "$(marker SAVED_OBJECTS_TOTAL)")"
if [ "$SO_TOTAL_PRE" -eq 0 ]; then
  echo "    WARNING: Kibana reports ZERO saved objects. If 'winlogbeat setup -e' ran, the" >&2
  echo "             winlogbeat dashboards should be here. Zero means either setup skipped" >&2
  echo "             the dashboard step or this API path is wrong for $KBN_VERSION. Check:" >&2
  echo "               qm guest exec $SRC_VMID -- /bin/sh -c \"curl -s '$KBN_BASE/api/saved_objects/_find?type=dashboard&per_page=1'\"" >&2
fi

# ---- Kibana's encryption key: reported, not invented ----
echo "    -- Kibana encrypted saved objects --"
show KBN_ENC_KEY_YML
show KBN_ENC_KEY_KEYSTORE
show KBN_ENC_KEY_RANDOM
if [ "$(marker KBN_ENC_KEY_YML)" = "yes" ] || [ "$(marker KBN_ENC_KEY_KEYSTORE)" = "yes" ]; then
  echo "    OK: xpack.encryptedSavedObjects.encryptionKey is EXPLICITLY SET. Encrypted"
  echo "        saved objects stay decryptable across restarts and across clones."
else
  MSG_ENC="xpack.encryptedSavedObjects.encryptionKey is NOT explicitly set, so Kibana generates a random one at every start. Every encrypted saved object — detection rules' API keys, alerting rules, action connectors — becomes UNDECRYPTABLE on the next restart, which for a golden image means: it worked at seal time and is dead in every clone, silently. Plain dashboards and visualizations are unaffected."
  if [ "$REQUIRE_KIBANA_ENC_KEY" = "1" ]; then
    echo "    ERROR: $MSG_ENC" >&2
    echo "           REQUIRE_KIBANA_ENC_KEY=1, so this is a refusal. Set a key in" >&2
    echo "           /etc/kibana/kibana.yml (32+ chars), restart kibana, re-run:" >&2
    echo "             xpack.encryptedSavedObjects.encryptionKey: \"<32+ chars>\"" >&2
    echo "           This script does NOT invent one: a key it generated would be" >&2
    echo "           identical in every clone and recorded nowhere." >&2
    FAIL=1
  else
    echo "    WARNING: $MSG_ENC" >&2
    echo "             Not a refusal by default because it does not break plain dashboards." >&2
    echo "             Set REQUIRE_KIBANA_ENC_KEY=1 to make it one — which is the right" >&2
    echo "             setting the moment detection rules are part of this image." >&2
    echo "             (docs/track-e-cluster-gate.md P9 item 6 calls this the" >&2
    echo "             highest-consequence line in the whole GOAD prebake.)" >&2
  fi
fi

# ---- addressing ----
echo "    -- addressing (DHCP and nothing but DHCP) --"
show IPV4_ADDRS
show NETPLAN_DETAIL
check NETPLAN_PARSED     yes "the netplan files could not be parsed as YAML, so the static-address check below proved nothing. Read them by hand: cat /etc/netplan/*.yaml"
check NETPLAN_STATIC     no  "a STATIC address is configured in netplan. The lane's MAC-pinned dnsmasq reservation is what decides this machine's IP; an address baked into the image disagrees with it and produces no error anywhere — just a box that is up, healthy, at the wrong address, that every agent in the lane ships past"
check SYSTEMD_NET_STATIC no  "a static Address= is set in /etc/systemd/network/. Same failure as netplan, different file — and this one survives cloud-init entirely"
check ENI_STATIC         no  "a static iface is configured in /etc/network/interfaces. Same failure again"
check CI_NET_DISABLED    no  "cloud-init's network config is DISABLED in this image. A clone then keeps whatever netplan this box has instead of rendering the lane's 'ipconfig0: ip=dhcp' — static by accident, on an interface name the clone may not even have"
show NETPLAN_DHCP4

# ---- context ----
echo "    -- context --"
show ROOT_FS_GB
show ROOT_FREE_GB
show ES_DATA_MB
show LOGSTASH_ACTIVE
show GUEST_AGENT_ENABLED
show HOSTKEY_UNIT_ENABLED
show CTRL_KEY_PRESENT
check GUEST_AGENT_ENABLED yes "qemu-guest-agent is not enabled — a clone of this template is OPAQUE to the orchestrator: it looks perfectly healthy in Proxmox and nothing can be dispatched into it"
if [ "$(marker HOSTKEY_UNIT_ENABLED)" != "yes" ]; then
  echo "    WARNING: cybercore-ssh-hostkeys.service is not enabled. Section 3d strips the" >&2
  echo "             SSH host keys (it must — one host identity shared by twenty lanes)," >&2
  echo "             and that unit is what regenerates them on a clone whose cloud-init" >&2
  echo "             did not run. Without it, such a clone has no host keys and sshd" >&2
  echo "             refuses to start. It ships with base template 1011; if it is gone," >&2
  echo "             something removed it." >&2
fi
if [ "$(marker CTRL_KEY_PRESENT)" != "yes" ]; then
  echo "    WARNING: /etc/ssh/cybercore-controller-authorized_keys is missing or empty." >&2
  echo "             That is the GOAD controller's key from base template 1011. Without it" >&2
  echo "             no in-lane Ansible can reach a clone of this image — which matters if" >&2
  echo "             anything is ever re-run against these boxes." >&2
fi
if [ "$(marker LOGSTASH_ACTIVE)" = "yes" ]; then
  echo "    NOTE: logstash is running. GOAD's roles/elk installs and starts it and never" >&2
  echo "          configures it (winlogbeat ships straight to Elasticsearch:9200), so this" >&2
  echo "          freezes an idle JVM into every clone. Not a refusal — but if you want it" >&2
  echo "          gone, remove it from the staging box and re-run, or drop the task from" >&2
  echo "          roles/elk before the next staging install (track-e gate P9 item 4)." >&2
fi

if [ "$FAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: pre-clean verification failed. NOTHING has been changed and NOTHING has" >&2
  echo "       been templated. VM $SRC_VMID is left exactly as it was found." >&2
  echo "" >&2
  echo "       This is the refusal that matters most: a half-installed box sealed into a" >&2
  echo "       golden template looks like a success and fails in every lane at once." >&2
  echo "" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'journalctl -u elasticsearch -n 100 --no-pager'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'journalctl -u kibana -n 100 --no-pager'" >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'curl -s $ES_BASE/_cat/indices?v'" >&2
  exit 1
fi

echo ""
echo "    ####################################################################"
printf '    # FREEZING STACK VERSION: Elasticsearch %-27s#\n' "${ES_VERSION:-unknown}"
printf '    #                         Kibana        %-27s#\n' "${KBN_VERSION:-unknown}"
printf '    # %-65s#\n' ""
printf '    # %-65s#\n' "Everything cloned from template $VMID runs THIS version, forever,"
printf '    # %-65s#\n' "until somebody redoes the staging install. The sensor bake's"
printf '    # %-65s#\n' "ELASTIC_VERSION and the winlogbeat on the Windows images must"
printf '    # %-65s#\n' "match it. See hand-off section 3."
echo "    ####################################################################"

# ============================================================================
# 2. CLEAN
# ----------------------------------------------------------------------------
# 2a  isolate the box from the staging lab's still-running agents
# 2b  prove they have gone quiet
# 2c  print the delete plan, and (unless DRY_RUN) execute it by exact name
# 2d  stop Kibana, flush, stop Elasticsearch — so the clone does not boot into
#     recovery on a dirty translog
#
# The image hygiene (machine-id, host keys, cloud-init, logs) is deliberately
# NOT here. It lives at the END of section 3, after the verification restart,
# because a restart writes logs: cleaning them first would mean shipping the
# verification run's own journal in the golden image. Section 3d says so again
# where it happens.
# ============================================================================
echo ""
echo "==> 2. Clean"

# ---- 2a. Isolation ----------------------------------------------------------
# The staging lab's Windows hosts are STILL RUNNING and STILL SHIPPING while
# this script works. Without this, an index deleted at T is re-created by the
# next event at T+4s, the post-clean assertion then fails (or, worse, passes and
# the data lands a second later), and the golden image ships with a handful of
# the staging lab's events in it.
read -r -d '' ISOLATE_SH <<'ISOLATE_EOF' || true
if ! command -v iptables >/dev/null 2>&1; then
  m ISOLATE_SUPPORTED no
  m ISOLATE_RULES 0
  exit 0
fi
m ISOLATE_SUPPORTED yes
for p in 9200 5601 5044; do
  iptables -C INPUT ! -i lo -p tcp --dport "$p" -m comment --comment CYBERCORE-SEAL -j DROP 2>/dev/null \
    || iptables -I INPUT 1 ! -i lo -p tcp --dport "$p" -m comment --comment CYBERCORE-SEAL -j DROP 2>/dev/null \
    || true
done
m ISOLATE_RULES "$(iptables -S INPUT 2>/dev/null | grep -c CYBERCORE-SEAL || true)"
exit 0
ISOLATE_EOF

read -r -d '' UNISOLATE_SH <<'UNISOLATE_EOF' || true
if ! command -v iptables >/dev/null 2>&1; then
  m ISOLATE_REMAINING 0
  m IPTABLES_PERSIST no
  exit 0
fi
i=0
while [ "$i" -lt 6 ]; do
  iptables -S INPUT 2>/dev/null | grep -q CYBERCORE-SEAL || break
  for p in 9200 5601 5044; do
    iptables -D INPUT ! -i lo -p tcp --dport "$p" -m comment --comment CYBERCORE-SEAL -j DROP 2>/dev/null || true
  done
  i=$((i + 1))
done
m ISOLATE_REMAINING "$(iptables -S INPUT 2>/dev/null | grep -c CYBERCORE-SEAL || true)"
# Nothing here ever calls iptables-save, so these rules are runtime-only and a
# reboot clears them regardless. This marker exists so that claim is checked
# rather than asserted: if a rules file exists, somebody else's tooling may
# persist whatever is loaded at shutdown.
m IPTABLES_PERSIST "$(yn test -e /etc/iptables/rules.v4)"
exit 0
UNISOLATE_EOF

if [ "$SEAL_ISOLATE" = "1" ]; then
  rc=0
  ISO_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${ISOLATE_SH}" "$GX_TIMEOUT")" || rc=$?
  [ "$rc" -ge 97 ] && transport_die "$rc" "isolating the box from the staging agents"
  ISO_SUPPORTED="$(printf '%s\n' "$ISO_OUT" | awk -F= '$1=="ISOLATE_SUPPORTED"{print $2; exit}')"
  ISO_RULES="$(printf '%s\n' "$ISO_OUT" | awk -F= '$1=="ISOLATE_RULES"{print $2; exit}')"
  if [ "$ISO_SUPPORTED" != "yes" ]; then
    echo "    WARNING: iptables is not present in the guest, so the staging agents cannot" >&2
    echo "             be shut out. The quiesce check below is now the only protection." >&2
  else
    echo "    isolated: $ISO_RULES INPUT DROP rule(s) on 9200/5601/5044 (non-loopback only)"
    echo "              runtime state only — nothing was saved, a reboot clears it"
  fi
else
  echo "    SEAL_ISOLATE=0 — not touching the firewall. The quiesce check below is the"
  echo "    only thing standing between a delete and an agent re-creating what it deleted."
fi

# ---- 2b. Quiesce ------------------------------------------------------------
read -r -d '' QUIESCE_SH <<'QUIESCE_EOF' || true
es_get '/winlogbeat-*,.ds-winlogbeat-*/_count?ignore_unavailable=true&allow_no_indices=true' > "$T/q1.json" 2>/dev/null || true
c1="$(jget "$T/q1.json" "d.get('count','')")"
sleep "$QUIESCE_WAIT"
es_get '/winlogbeat-*,.ds-winlogbeat-*/_count?ignore_unavailable=true&allow_no_indices=true' > "$T/q2.json" 2>/dev/null || true
c2="$(jget "$T/q2.json" "d.get('count','')")"
m QUIESCE_BEFORE "${c1:-unknown}"
m QUIESCE_AFTER  "${c2:-unknown}"
exit 0
QUIESCE_EOF

rc=0
Q_OUT="$(guest_sh "${GUEST_ENV}QUIESCE_WAIT='${QUIESCE_WAIT}'
${GUEST_LIB}
${QUIESCE_SH}" "$(( QUIESCE_WAIT + GX_TIMEOUT ))")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "measuring whether the agents have gone quiet"
Q_BEFORE="$(printf '%s\n' "$Q_OUT" | awk -F= '$1=="QUIESCE_BEFORE"{print $2; exit}')"
Q_AFTER="$(printf '%s\n' "$Q_OUT" | awk -F= '$1=="QUIESCE_AFTER"{print $2; exit}')"
printf '    %-26s %s -> %s over %ss\n' "winlogbeat doc count:" "${Q_BEFORE:-?}" "${Q_AFTER:-?}" "$QUIESCE_WAIT"
case "$Q_BEFORE$Q_AFTER" in
  *unknown*|'') : ;;
  *)
    if [ "$Q_AFTER" -gt "$Q_BEFORE" ] 2>/dev/null; then
      echo "" >&2
      echo "ERROR: the staging lab's agents are STILL SHIPPING ($Q_BEFORE -> $Q_AFTER in ${QUIESCE_WAIT}s)." >&2
      echo "       Deleting now is pointless and worse than pointless: an index deleted at T" >&2
      echo "       is re-created by the next event, the verification in section 3 then fails" >&2
      echo "       — or passes, and the data lands a second later and ships to every lane." >&2
      echo "" >&2
      if [ "$SEAL_ISOLATE" = "1" ]; then
        echo "       SEAL_ISOLATE=1 was set and the DROP rules were inserted, so either" >&2
        echo "       iptables did not take effect or something inside this box is writing." >&2
        echo "       Check:  qm guest exec $SRC_VMID -- /bin/sh -c 'iptables -S INPUT'" >&2
      else
        echo "       Either power the staging lab's Windows hosts off:" >&2
        echo "           qm stop <dc-vmid> <member-vmid> ..." >&2
        echo "       or re-run with SEAL_ISOLATE=1, which inserts temporary INPUT DROP rules" >&2
        echo "       for 9200/5601/5044 on non-loopback traffic and removes them before the" >&2
        echo "       clone." >&2
      fi
      echo "" >&2
      echo "       Nothing has been deleted. VM $SRC_VMID is unchanged apart from those" >&2
      echo "       runtime firewall rules, which a reboot clears." >&2
      exit 1
    fi
    ;;
esac

# ---- 2c. The plan, then the deletion ---------------------------------------
# ONE payload, run twice with MODE=plan then MODE=apply, so the thing printed
# and the thing executed are the same code. Data streams first (Elasticsearch
# refuses to delete a backing index out from under a live one), then whatever
# concrete indices remain. Every deletion names ONE index. No wildcards reach a
# DELETE URL — see the header.
read -r -d '' PLAN_SH <<'PLAN_EOF' || true
# -f: the pattern lists below are word-split on purpose, but must NOT be
# pathname-expanded against the guest filesystem on the way through.
set -uf

keep_veto() { for k in $KEEP_PATTERNS; do case "$1" in $k) return 0 ;; esac; done; return 1; }
del_match() { for p in $DELETE_PATTERNS; do case "$1" in $p) return 0 ;; esac; done; return 1; }

# ---- data streams ----
es_get '/_data_stream' > "$T/ds1.json" 2>/dev/null || true
es_get '/_data_stream/*?expand_wildcards=all' > "$T/ds2.json" 2>/dev/null || true
python3 - "$T/ds1.json" "$T/ds2.json" > "$T/ds.txt" <<'PYDS'
import json, sys
names = set()
for path in sys.argv[1:]:
    try:
        d = json.load(open(path))
    except Exception:
        continue
    for s in (d.get('data_streams') or []):
        n = s.get('name')
        if n:
            names.add(n)
print('\n'.join(sorted(names)))
PYDS

nds=0; nkeep=0
while IFS= read -r n; do
  [ -z "$n" ] && continue
  if keep_veto "$n"; then echo "KEEP_DS  $n"; nkeep=$((nkeep + 1)); continue; fi
  if del_match "$n"; then
    echo "PLAN_DS  $n"
    nds=$((nds + 1))
    if [ "$MODE" = apply ]; then
      code="$(es_del "/_data_stream/$n")"
      echo "DONE_DS  $n $code"
    fi
  else
    echo "SKIP_DS  $n"
  fi
done < "$T/ds.txt"

# ---- concrete indices, enumerated AFTER the data streams are gone ----
es_get '/_cat/indices?format=json&bytes=b&expand_wildcards=all' > "$T/idx.json" 2>/dev/null || true
python3 - "$T/idx.json" > "$T/idx.txt" <<'PYIDX'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = []
if isinstance(d, list):
    for i in d:
        print('%s %s %s' % (i.get('index', ''), i.get('docs.count') or 0, i.get('store.size') or 0))
PYIDX

nidx=0; ndocs=0
while IFS=' ' read -r n docs bytes; do
  [ -z "$n" ] && continue
  if keep_veto "$n"; then echo "KEEP_IDX $n $docs"; nkeep=$((nkeep + 1)); continue; fi
  if del_match "$n"; then
    echo "PLAN_IDX $n $docs docs ${bytes}b"
    nidx=$((nidx + 1))
    case "$docs" in ''|*[!0-9]*) : ;; *) ndocs=$((ndocs + docs)) ;; esac
    if [ "$MODE" = apply ]; then
      code="$(es_del "/$n")"
      echo "DONE_IDX $n $code"
    fi
  else
    echo "SKIP_IDX $n $docs"
  fi
done < "$T/idx.txt"

echo "SUMMARY_DS=$nds"
echo "SUMMARY_IDX=$nidx"
echo "SUMMARY_DOCS=$ndocs"
echo "SUMMARY_KEEP=$nkeep"
exit 0
PLAN_EOF

PATTERN_ENV="DELETE_PATTERNS='${DELETE_PATTERNS}'
KEEP_PATTERNS='${KEEP_PATTERNS}'
"

echo ""
echo "    -- the plan: DELETE the staging lab's data, KEEP the setup --"
rc=0
PLAN_OUT="$(guest_sh "${GUEST_ENV}${PATTERN_ENV}MODE=plan
${GUEST_LIB}
${PLAN_SH}" "$GX_LONG")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "building the delete plan"

printf '%s\n' "$PLAN_OUT" | grep -E '^(PLAN_|KEEP_)' | sed 's/^/      /' || true
PLAN_DS="$(printf '%s\n' "$PLAN_OUT"  | awk -F= '$1=="SUMMARY_DS"{print $2; exit}')"
PLAN_IDX="$(printf '%s\n' "$PLAN_OUT" | awk -F= '$1=="SUMMARY_IDX"{print $2; exit}')"
PLAN_DOCS="$(printf '%s\n' "$PLAN_OUT" | awk -F= '$1=="SUMMARY_DOCS"{print $2; exit}')"
PLAN_KEEP="$(printf '%s\n' "$PLAN_OUT" | awk -F= '$1=="SUMMARY_KEEP"{print $2; exit}')"
echo ""
printf '      to delete: %s data stream(s), %s index(es), %s document(s)\n' "${PLAN_DS:-?}" "${PLAN_IDX:-?}" "${PLAN_DOCS:-?}"
printf '      vetoed by KEEP_PATTERNS (never deleted): %s\n' "${PLAN_KEEP:-?}"

# The .kibana veto is the single assertion that separates this script from the
# destructive version of itself. Checked on the PLAN, before anything happens.
if printf '%s\n' "$PLAN_OUT" | grep -qE '^PLAN_(DS|IDX) +\.kibana'; then
  echo "" >&2
  echo "ERROR: the plan contains a .kibana index. That is the dashboards, the index" >&2
  echo "       patterns and every saved object 'winlogbeat setup' installed — the entire" >&2
  echo "       reason for sealing from a real lab rather than baking a bare stack." >&2
  echo "       Something has been added to DELETE_PATTERNS or removed from" >&2
  echo "       KEEP_PATTERNS. Nothing has been deleted. Refusing." >&2
  exit 1
fi

if [ "$DRY_RUN" = "1" ]; then
  echo ""
  echo "==> DRY_RUN=1 — stopping here. Nothing was deleted, nothing was cloned."
  if [ "$SEAL_ISOLATE" = "1" ]; then
    rc=0
    UN_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${UNISOLATE_SH}" "$GX_TIMEOUT")" || rc=$?
    printf '%s\n' "$UN_OUT" | sed 's/^/    /'
  fi
  echo "    VM $SRC_VMID is left running and unchanged."
  exit 0
fi

echo ""
echo "    -- applying --"
rc=0
APPLY_OUT="$(guest_sh "${GUEST_ENV}${PATTERN_ENV}MODE=apply
${GUEST_LIB}
${PLAN_SH}" "$GX_LONG")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "deleting the staging data (SOME INDICES MAY ALREADY BE GONE)"

printf '%s\n' "$APPLY_OUT" | grep -E '^DONE_' | sed 's/^/      /' || true

# Every DELETE must have answered 200 (deleted) or 404 (already gone between the
# plan and the apply). Anything else — 400, 403 on a system index, 503 — means a
# deletion silently did not happen, and a clean that silently no-ops is
# indistinguishable from one that worked until a classroom.
BAD_DELETES="$(printf '%s\n' "$APPLY_OUT" | grep -E '^DONE_' | awk '$3 != "200" && $3 != "404" {print}' || true)"
if [ -n "$BAD_DELETES" ]; then
  echo "" >&2
  echo "ERROR: some deletions did not succeed:" >&2
  printf '%s\n' "$BAD_DELETES" | sed 's/^/       /' >&2
  echo "" >&2
  echo "       Every one of those indices still holds the staging lab's data and would" >&2
  echo "       ship to every lane. Section 3 would catch it, but stopping here is" >&2
  echo "       cheaper. VM $SRC_VMID is left running and unsealed." >&2
  echo "       Read the body of one by hand:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'curl -s -X DELETE $ES_BASE/<index>'" >&2
  exit 1
fi

# ---- 2d. Stop the stack cleanly, in the right order -------------------------
# Kibana FIRST: it writes to .kibana_task_manager every few seconds, and a
# Kibana still running while Elasticsearch stops is a guaranteed dirty write.
# Then flush, so the translog is committed to the segments and the clone does
# not boot into recovery.
read -r -d '' STOPSTACK_SH <<'STOPSTACK_EOF' || true
systemctl stop kibana >/dev/null 2>&1 || true
sleep 3
# Plain _flush, not _flush/synced: synced flush is deprecated in 7.6 and removed
# in 8.0, and this script does not choose the version.
es_post '/_flush' '' > "$T/flush.json" 2>/dev/null || true
m FLUSH_FAILED "$(jget "$T/flush.json" "d.get('_shards',{}).get('failed','')")"
systemctl stop elasticsearch >/dev/null 2>&1 || true
i=0
while [ "$i" -lt 120 ]; do
  systemctl is-active elasticsearch >/dev/null 2>&1 || break
  sleep 3; i=$((i + 3))
done
m ES_STOP_SECONDS "$i"
m ES_ACTIVE  "$(yn systemctl is-active elasticsearch)"
m KBN_ACTIVE "$(yn systemctl is-active kibana)"
m ES_ENABLED  "$(yn systemctl is-enabled elasticsearch)"
m KBN_ENABLED "$(yn systemctl is-enabled kibana)"
exit 0
STOPSTACK_EOF

echo ""
echo "    -- stopping the stack (kibana, flush, elasticsearch) --"
rc=0
STOP_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${STOPSTACK_SH}" "$GX_LONG")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "stopping the stack"
printf '%s\n' "$STOP_OUT" | sed 's/^/      /'
STOP_ES_ACTIVE="$(printf '%s\n' "$STOP_OUT" | awk -F= '$1=="ES_ACTIVE"{print $2; exit}')"
if [ "$STOP_ES_ACTIVE" != "no" ]; then
  echo "ERROR: elasticsearch did not stop. Templating it now snapshots a live shard write," >&2
  echo "       and every clone boots into translog recovery on a half-written segment." >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl status elasticsearch'" >&2
  exit 1
fi

# ============================================================================
# 3. POST-CLEAN VERIFICATION
# ----------------------------------------------------------------------------
# The check that makes the delete/keep split trustworthy rather than hopeful.
# Elasticsearch is STARTED AGAIN, briefly, and asked both halves of the
# question: is the setup still here, and is the data really gone. Then it is
# stopped again.
#
# The restart is genuinely implemented — it is not a claim. What it CANNOT prove
# is stated where it matters: no restart on this box can show whether Kibana's
# encrypted saved objects survive in a CLONE, because that depends on a key
# regenerating at a start this script never performs.
# ============================================================================
echo ""
echo "==> 3. Post-clean verification (restart Elasticsearch and check both halves)"

read -r -d '' POSTCHECK_SH <<'POSTCHECK_EOF' || true
set -uf
keep_veto() { for k in $KEEP_PATTERNS; do case "$1" in $k) return 0 ;; esac; done; return 1; }
del_match() { for p in $DELETE_PATTERNS; do case "$1" in $p) return 0 ;; esac; done; return 1; }

systemctl start elasticsearch >/dev/null 2>&1 || true
i=0; code=000
while [ "$i" -lt "$ES_RESTART_WAIT" ]; do
  code="$(es_code /)"
  [ "$code" = "200" ] && break
  sleep 5; i=$((i + 5))
done
m ES_BACK_CODE    "$code"
m ES_BACK_SECONDS "$i"
[ "$code" = "200" ] || exit 0

es_get /_cluster/health > "$T/h2.json" 2>/dev/null || true
m POST_ES_HEALTH "$(jget "$T/h2.json" "d.get('status','')")"

# ---- KEPT: the setup ----
es_get '/_index_template/winlogbeat*' > "$T/tpl2.json" 2>/dev/null || true
m POST_WLB_INDEX_TEMPLATES "$(jget "$T/tpl2.json" "len(d.get('index_templates',[]))")"
es_get '/_template/winlogbeat*' > "$T/legtpl2.json" 2>/dev/null || true
m POST_WLB_LEGACY_TEMPLATES "$(jget "$T/legtpl2.json" "len([k for k in d if 'winlogbeat' in k.lower()])")"
es_get '/_component_template' > "$T/ct2.json" 2>/dev/null || true
m POST_WLB_COMPONENT_TEMPLATES "$(jget "$T/ct2.json" "len([c for c in d.get('component_templates',[]) if 'winlogbeat' in c.get('name','').lower()])")"
es_get '/_ilm/policy' > "$T/ilm2.json" 2>/dev/null || true
m POST_WLB_ILM_POLICIES "$(jget "$T/ilm2.json" "len([k for k in d if 'winlogbeat' in k.lower()])")"

# ---- DELETED: the data ----
es_get '/winlogbeat-*,.ds-winlogbeat-*/_count?ignore_unavailable=true&allow_no_indices=true' > "$T/c2.json" 2>/dev/null || true
m POST_WLB_DOC_COUNT "$(jget "$T/c2.json" "d.get('count','')")"
es_get '/_data_stream' > "$T/ds3.json" 2>/dev/null || true
m POST_DATA_STREAMS "$(jget "$T/ds3.json" "len(d.get('data_streams',[]))")"

es_get '/_cat/indices?format=json&bytes=b&expand_wildcards=all' > "$T/idx3.json" 2>/dev/null || true
m POST_INDICES_TOTAL  "$(jget "$T/idx3.json" "len(d) if isinstance(d,list) else ''")"
m POST_KIBANA_INDICES "$(jget "$T/idx3.json" "len([i for i in d if i.get('index','').startswith('.kibana')]) if isinstance(d,list) else ''")"
python3 - "$T/idx3.json" > "$T/idx3.txt" <<'PYI3'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = []
if isinstance(d, list):
    for i in d:
        print(i.get('index', ''))
PYI3
left=""
while IFS= read -r n; do
  [ -z "$n" ] && continue
  keep_veto "$n" && continue
  if del_match "$n"; then left="$left $n"; fi
done < "$T/idx3.txt"
m POST_LEFTOVERS "$(printf '%s' "$left" | cut -c1-400)"
exit 0
POSTCHECK_EOF

rc=0
POST_OUT="$(guest_sh "${GUEST_ENV}${PATTERN_ENV}ES_RESTART_WAIT='${ES_RESTART_WAIT}'
${GUEST_LIB}
${POSTCHECK_SH}" "$(( ES_RESTART_WAIT + GX_TIMEOUT ))")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "restarting Elasticsearch for post-clean verification"

pmark() { printf '%s\n' "$POST_OUT" | awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}'; }
pshow() { printf '    %-30s %s\n' "$1:" "$(pmark "$1")"; }

pshow ES_BACK_CODE
pshow ES_BACK_SECONDS
if [ "$(pmark ES_BACK_CODE)" != "200" ]; then
  echo "" >&2
  echo "ERROR: Elasticsearch did not come back within ${ES_RESTART_WAIT}s, so NOTHING about" >&2
  echo "       the clean has been verified. Refusing to seal an unverified image — the" >&2
  echo "       whole point of this section is that a clean which silently no-opped is" >&2
  echo "       indistinguishable from one that worked until a classroom." >&2
  echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'journalctl -u elasticsearch -n 100 --no-pager'" >&2
  echo "       Then either fix it and re-run, or raise ES_RESTART_WAIT." >&2
  exit 1
fi

echo "    -- KEPT (the setup: this is what sealing from a real lab bought) --"
pshow POST_ES_HEALTH
pshow POST_WLB_INDEX_TEMPLATES
pshow POST_WLB_LEGACY_TEMPLATES
pshow POST_WLB_COMPONENT_TEMPLATES
pshow POST_WLB_ILM_POLICIES
pshow POST_KIBANA_INDICES
echo "    -- DELETED (the staging lab's data) --"
pshow POST_WLB_DOC_COUNT
pshow POST_DATA_STREAMS
pshow POST_INDICES_TOTAL
pshow POST_LEFTOVERS

POST_FAIL=0
POST_TPL=$(( $(num "$(pmark POST_WLB_INDEX_TEMPLATES)") + $(num "$(pmark POST_WLB_LEGACY_TEMPLATES)") ))
if [ "$POST_TPL" -eq 0 ]; then
  echo "" >&2
  echo "ERROR: THE WINLOGBEAT INDEX TEMPLATE IS GONE." >&2
  echo "       It was present before the clean (${TPL_TOTAL} template(s)) and is absent after." >&2
  echo "       This seal was DESTRUCTIVE: it deleted the setup along with the data, which" >&2
  echo "       is the exact failure the KEEP list exists to prevent, and it is the one" >&2
  echo "       that would otherwise ship — Kibana still loads, the dashboards are just" >&2
  echo "       gone and nothing says so." >&2
  echo "" >&2
  echo "       NOTHING HAS BEEN TEMPLATED. The source VM $SRC_VMID still exists, but its" >&2
  echo "       Elasticsearch no longer holds what made it worth sealing: the staging" >&2
  echo "       install has to be redone (roles/logs_windows must run 'winlogbeat setup'" >&2
  echo "       again) before another attempt." >&2
  echo "       Check what is left:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'curl -s $ES_BASE/_cat/templates?v'" >&2
  POST_FAIL=1
fi
if [ "$(num "$(pmark POST_KIBANA_INDICES)")" -eq 0 ]; then
  echo "" >&2
  echo "ERROR: there are no .kibana* indices left. Every saved object — every dashboard," >&2
  echo "       every index pattern winlogbeat installed — is gone. Same failure as above," >&2
  echo "       different half. NOTHING HAS BEEN TEMPLATED." >&2
  POST_FAIL=1
fi
if [ "$(num "$(pmark POST_WLB_DOC_COUNT)")" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: winlogbeat data is still present ($(pmark POST_WLB_DOC_COUNT) documents) after the clean." >&2
  echo "       Either a delete silently no-opped, or the staging lab's agents re-created" >&2
  echo "       an index during the verification restart. Every student would open Kibana" >&2
  echo "       on the bake lab's logs, which in a defensive_monitoring exercise is the" >&2
  echo "       answer key." >&2
  echo "       If SEAL_ISOLATE=0, that is the first thing to change." >&2
  POST_FAIL=1
fi
if [ -n "$(pmark POST_LEFTOVERS)" ]; then
  echo "" >&2
  echo "ERROR: indices matching DELETE_PATTERNS survived the clean:" >&2
  echo "         $(pmark POST_LEFTOVERS)" >&2
  echo "       They hold the staging lab's data and would ship to every lane." >&2
  POST_FAIL=1
fi
if [ "$POST_FAIL" -ne 0 ]; then
  echo "" >&2
  echo "       VM $SRC_VMID is left STOPPED-STACK and UNSEALED for inspection. Restart the" >&2
  echo "       stack by hand to look around:" >&2
  echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl start elasticsearch kibana'" >&2
  exit 1
fi
echo "    OK: setup kept, data gone. That pair is what this script exists to guarantee."

# ---- 3b. Kibana: the dashboards really are still there ----------------------
if [ "$VERIFY_KIBANA" = "1" ]; then
  read -r -d '' KBNCHECK_SH <<'KBNCHECK_EOF' || true
systemctl start kibana >/dev/null 2>&1 || true
i=0; code=000
while [ "$i" -lt "$KBN_RESTART_WAIT" ]; do
  code="$(kb_code /api/status)"
  [ "$code" = "200" ] && break
  sleep 10; i=$((i + 10))
done
m KBN_BACK_CODE    "$code"
m KBN_BACK_SECONDS "$i"
[ "$code" = "200" ] || exit 0
tot=0
for t in dashboard visualization index-pattern search lens map config; do
  kb_get "/api/saved_objects/_find?type=$t&per_page=1" > "$T/so2.json" 2>/dev/null || true
  n="$(jget "$T/so2.json" "d.get('total','')")"
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  tot=$((tot + n))
done
m POST_SAVED_OBJECTS_TOTAL "$tot"
exit 0
KBNCHECK_EOF

  echo ""
  echo "    -- restarting Kibana to confirm the dashboards survived --"
  rc=0
  KBN_OUT="$(guest_sh "${GUEST_ENV}KBN_RESTART_WAIT='${KBN_RESTART_WAIT}'
${GUEST_LIB}
${KBNCHECK_SH}" "$(( KBN_RESTART_WAIT + GX_TIMEOUT ))")" || rc=$?
  [ "$rc" -ge 97 ] && transport_die "$rc" "restarting Kibana for post-clean verification"
  printf '%s\n' "$KBN_OUT" | sed 's/^/      /'
  KBN_BACK="$(printf '%s\n' "$KBN_OUT" | awk -F= '$1=="KBN_BACK_CODE"{print $2; exit}')"
  SO_TOTAL_POST="$(num "$(printf '%s\n' "$KBN_OUT" | awk -F= '$1=="POST_SAVED_OBJECTS_TOTAL"{print $2; exit}')")"
  if [ "$KBN_BACK" != "200" ]; then
    echo "" >&2
    echo "ERROR: Kibana did not come back within ${KBN_RESTART_WAIT}s after the clean." >&2
    echo "       A clone of this image would behave the same way, and 'Kibana never becomes" >&2
    echo "       available' is the single most common way a sealed SIEM image fails." >&2
    echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'journalctl -u kibana -n 120 --no-pager'" >&2
    echo "       Raise KBN_RESTART_WAIT if it is merely slow, or set VERIFY_KIBANA=0 once" >&2
    echo "       you have confirmed by hand that it does come up. Do not set it to 0 to" >&2
    echo "       make this message go away." >&2
    exit 1
  fi
  printf '    %-30s %s -> %s\n' "saved objects (before -> after):" "$SO_TOTAL_PRE" "$SO_TOTAL_POST"
  if [ "$SO_TOTAL_POST" -lt "$SO_TOTAL_PRE" ]; then
    echo "" >&2
    echo "ERROR: saved objects went DOWN across the clean ($SO_TOTAL_PRE -> $SO_TOTAL_POST)." >&2
    echo "       The dashboards are what sealing from a real lab bought. Refusing to" >&2
    echo "       template an image that has lost some of them." >&2
    exit 1
  fi
else
  echo "    VERIFY_KIBANA=0 — Kibana was NOT restarted, so nothing here proves the saved" >&2
  echo "    objects survived. The .kibana* indices are present (asserted above), which is" >&2
  echo "    the on-disk half of the same question and the strongest statement available" >&2
  echo "    without a restart." >&2
fi

# ---- 3c. Stop the stack again ----------------------------------------------
echo ""
echo "    -- stopping the stack again --"
rc=0
STOP2_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${STOPSTACK_SH}" "$GX_LONG")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "stopping the stack after verification"
printf '%s\n' "$STOP2_OUT" | sed 's/^/      /'
if [ "$(printf '%s\n' "$STOP2_OUT" | awk -F= '$1=="ES_ACTIVE"{print $2; exit}')" != "no" ]; then
  echo "ERROR: elasticsearch is still running after the second stop. See section 2d." >&2
  exit 1
fi

# ---- 3d. Image hygiene, deliberately LAST -----------------------------------
# This is the part of the clean that has to happen after everything else has
# stopped writing. Doing it in section 2 would mean the verification restart
# above wrote a fresh journal, a fresh /var/log/elasticsearch, and a fresh set
# of Kibana logs INTO the golden image — the staging lab's logs would be gone
# and this script's own would have replaced them.
#
# Two things are deliberately NOT touched here, and both would be tempting:
#   /root/.ssh/authorized_keys and /etc/ssh/cybercore-controller-authorized_keys
#       — the GOAD controller's key from base template 1011. Removing it means
#         no in-lane Ansible can ever reach a clone again.
#   /var/lib/elasticsearch (node state)
#       — that directory IS the cluster metadata holding the index templates and
#         ILM policies this whole script fought to keep. The node UUID inside it
#         travels to every clone, which is harmless: each clone is its own
#         single-node cluster and they never meet.
read -r -d '' HYGIENE_SH <<'HYGIENE_EOF' || true
# Assert rather than assume: hygiene while the stack is up would truncate logs
# that are open, and worse, imply the flush already happened.
m HYG_ES_ACTIVE  "$(yn systemctl is-active elasticsearch)"
m HYG_KBN_ACTIVE "$(yn systemctl is-active kibana)"

# cloud-init: --seed as well as --logs, so a clone is a NEW instance and re-runs
# every per-instance module, including the one that regenerates host keys.
cloud-init clean --logs --seed >/dev/null 2>&1 || true
rm -rf /var/lib/cloud/instances/* >/dev/null 2>&1 || true

# machine-id. NOT hygiene: systemd-networkd derives its DHCP client identifier
# (an RFC 4361 DUID) from it, so clones sharing one present as the same client
# to the lane's dnsmasq. The lane pins addresses with dhcp-host=<MAC>,<IP> and a
# MAC is per-clone, so the reservation still matches — but a shared DUID still
# produces lease churn. TRUNCATE, never delete: systemd repopulates an EMPTY
# /etc/machine-id at boot and treats a MISSING one as a first-boot condition
# some images handle badly.
truncate -s 0 /etc/machine-id >/dev/null 2>&1 || true
rm -f /var/lib/dbus/machine-id >/dev/null 2>&1 || true

# SSH host keys. One host identity shared across twenty student lanes is both a
# real problem and a confusing one: the fingerprint is the same everywhere, so
# any change looks deliberate and no change looks like anything at all.
rm -f /etc/ssh/ssh_host_* >/dev/null 2>&1 || true

# Kibana's own instance UUID. Regenerated on start; identical in every clone
# otherwise, which makes Stack Monitoring show twenty lanes as one instance.
rm -f /var/lib/kibana/uuid >/dev/null 2>&1 || true

# Shell history and per-user junk, for every user.
rm -f /root/.bash_history /root/.python_history /root/.viminfo /root/.lesshst /root/.wget-hsts >/dev/null 2>&1 || true
rm -rf /root/.ansible >/dev/null 2>&1 || true
for h in /home/*; do
  [ -d "$h" ] || continue
  rm -f "$h/.bash_history" "$h/.python_history" "$h/.viminfo" "$h/.lesshst" "$h/.sudo_as_admin_successful" >/dev/null 2>&1 || true
  rm -rf "$h/.ansible" >/dev/null 2>&1 || true
done
apt-get clean >/dev/null 2>&1 || true

# The journal and /var/log. A student's box must not ship with the staging lab's
# logs in it — they name the bake lab's hosts, its intrusion and its addresses.
# TRUNCATE rather than delete the live files, so ownership and permissions
# survive for elasticsearch and kibana to keep writing on the next boot; delete
# only the rotated ones.
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
rm -rf /var/log/journal/* >/dev/null 2>&1 || true
find /var/log -type f \( -name '*.gz' -o -name '*.xz' -o -name '*.old' -o -name '*.[0-9]' \) -delete >/dev/null 2>&1 || true
find /var/log -type f ! -path '/var/log/journal/*' -exec truncate -s 0 {} + >/dev/null 2>&1 || true

# This script's own scratch.
rm -rf /tmp/.cc-seal-json >/dev/null 2>&1 || true
exit 0
HYGIENE_EOF

echo ""
echo "    -- image hygiene (machine-id, host keys, cloud-init, history, logs) --"
rc=0
HYG_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${HYGIENE_SH}" "$GX_LONG")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "running image hygiene"
printf '%s\n' "$HYG_OUT" | sed 's/^/      /'

# ---- 3e. Verify the hygiene, while the agent still answers ------------------
# A clean that silently no-ops is indistinguishable from one that worked, until
# a classroom. These are checked HERE because they are only true AFTER the
# clean, and because after the shutdown nothing can check them at all.
read -r -d '' SEALCHECK_SH <<'SEALCHECK_EOF' || true
m HOSTKEYS        "$(ls /etc/ssh/ssh_host_* >/dev/null 2>&1 && echo present || echo none)"
m MACHINE_ID      "$(test -s /etc/machine-id && echo nonempty || echo empty)"
m DBUS_MACHINE_ID "$(test -e /var/lib/dbus/machine-id && echo present || echo none)"
m CLOUD_INIT      "$(ls /var/lib/cloud/instances 2>/dev/null | head -1 | grep -q . && echo dirty || echo clean)"
m HISTORY         "$(ls /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1 | grep -q . && echo present || echo none)"
m JOURNAL_KB      "$(du -sk /var/log/journal 2>/dev/null | cut -f1)"
m VARLOG_BIG      "$(find /var/log -type f -size +64k 2>/dev/null | head -3 | tr '\n' ' ')"
m CTRL_KEY_PRESENT "$(yn test -s /etc/ssh/cybercore-controller-authorized_keys)"
m HOSTKEY_UNIT_ENABLED "$(yn systemctl is-enabled cybercore-ssh-hostkeys.service)"
m ES_ACTIVE   "$(yn systemctl is-active elasticsearch)"
m KBN_ACTIVE  "$(yn systemctl is-active kibana)"
m ES_ENABLED  "$(yn systemctl is-enabled elasticsearch)"
m KBN_ENABLED "$(yn systemctl is-enabled kibana)"
m GUEST_AGENT_ENABLED "$(yn systemctl is-enabled qemu-guest-agent)"
# Addressing, re-asserted after the clean: 'cloud-init clean' does not rewrite
# netplan, but this is the last chance to notice if something did.
if grep -rhqE '^[[:space:]]*addresses:' /etc/netplan/ 2>/dev/null; then
  m NETPLAN_ADDRESSES_SEEN yes
else
  m NETPLAN_ADDRESSES_SEEN no
fi
exit 0
SEALCHECK_EOF

rc=0
SEAL_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${SEALCHECK_SH}" "$GX_TIMEOUT")" || rc=$?
[ "$rc" -ge 97 ] && transport_die "$rc" "verifying the hygiene"

smark() { printf '%s\n' "$SEAL_OUT" | awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}'; }
SEAL_FAIL=0
scheck() {  # scheck <marker> <expected> <what breaks>
  local got; got="$(smark "$1")"
  printf '    %-30s %s\n' "$1:" "${got:-<empty>}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    SEAL_FAIL=1
  fi
}
scheck HOSTKEYS   none  "SSH host keys are still in the image. Every student lane would share one host identity — any lane can impersonate any other to anything that trusts it, and because the fingerprint is identical everywhere, nothing ever looks wrong"
scheck MACHINE_ID empty "/etc/machine-id still has content. Every clone would share it, so every clone presents the same systemd-networkd DHCP client identifier to the lane's dnsmasq"
scheck DBUS_MACHINE_ID none "/var/lib/dbus/machine-id survived and would re-seed the same identity on first boot, undoing the truncate above"
scheck CLOUD_INIT clean "cloud-init still holds this box's instance state. A clone is then treated as the SAME instance and skips every per-instance module — including the one that regenerates SSH host keys, which section 3d just removed"
scheck HISTORY    none  "shell history survived — the staging lab's commands, hostnames and any password typed during the install, in every student's image"
scheck ES_ACTIVE  no    "elasticsearch is running again. Templating now snapshots live shard writes"
scheck KBN_ACTIVE no    "kibana is running again. Same problem"
scheck ES_ENABLED  yes  "elasticsearch is no longer ENABLED — every clone would boot with no SIEM"
scheck KBN_ENABLED yes  "kibana is no longer ENABLED — every clone would boot with no console"
scheck GUEST_AGENT_ENABLED yes "qemu-guest-agent is not enabled — clones would be opaque to the orchestrator"
scheck CTRL_KEY_PRESENT yes "the GOAD controller's key did not survive the clean. No in-lane Ansible could reach a clone of this image"
scheck NETPLAN_ADDRESSES_SEEN no "a netplan file now contains an 'addresses:' key. Note this is the BLUNT grep — a nameservers block also has one — so check it by hand before believing it: qm guest exec $SRC_VMID -- /bin/sh -c 'cat /etc/netplan/*.yaml'"
printf '    %-30s %s\n' "JOURNAL_KB:" "$(smark JOURNAL_KB)"
printf '    %-30s %s\n' "VARLOG_BIG:" "$(smark VARLOG_BIG)"
if [ -n "$(smark VARLOG_BIG)" ]; then
  echo "    NOTE: those /var/log files are still larger than 64k after truncation. Worth a" >&2
  echo "          look — a log that regrew means something is still writing." >&2
fi

if [ "$SEAL_ISOLATE" = "1" ]; then
  rc=0
  UNISO_OUT="$(guest_sh "${GUEST_ENV}${GUEST_LIB}
${UNISOLATE_SH}" "$GX_TIMEOUT")" || rc=$?
  [ "$rc" -ge 97 ] && transport_die "$rc" "removing the temporary firewall rules"
  printf '%s\n' "$UNISO_OUT" | sed 's/^/    /'
  ISO_LEFT="$(printf '%s\n' "$UNISO_OUT" | awk -F= '$1=="ISOLATE_REMAINING"{print $2; exit}')"
  if [ "$(num "$ISO_LEFT")" -ne 0 ]; then
    echo "" >&2
    echo "ERROR: the temporary CYBERCORE-SEAL firewall rules could not be removed" >&2
    echo "       ($ISO_LEFT left). They block 9200/5601/5044 from everything except" >&2
    echo "       loopback. They are runtime-only, so a clone would NOT inherit them —" >&2
    echo "       but this box is about to be shut down and cloned, and a rule this" >&2
    echo "       script cannot account for is not a rule to template around." >&2
    echo "       qm guest exec $SRC_VMID -- /bin/sh -c 'iptables -S INPUT'" >&2
    SEAL_FAIL=1
  fi
  if [ "$(printf '%s\n' "$UNISO_OUT" | awk -F= '$1=="IPTABLES_PERSIST"{print $2; exit}')" = "yes" ]; then
    echo "    WARNING: /etc/iptables/rules.v4 exists on this box. Nothing here wrote it and" >&2
    echo "             nothing here calls iptables-save, but if some other tooling persists" >&2
    echo "             the running ruleset at shutdown, check that file before cloning." >&2
  fi
fi

if [ "$SEAL_FAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: seal verification failed. VM $SRC_VMID is left RUNNING and UNSEALED." >&2
  echo "       Nothing has been cloned and nothing has been converted to a template, so" >&2
  echo "       nothing can be deployed from this attempt." >&2
  exit 1
fi
echo "    OK: the clean took effect."

# ============================================================================
# 4. Stop, clone, template
# ----------------------------------------------------------------------------
# CLONE RATHER THAN CONVERT IN PLACE. The staging lane VM is destroyed when the
# lane is torn down, and converting it in place would couple the golden
# template's existence to a lane's lifecycle. Cloning also leaves the source
# intact, so a failed seal can be retried without redoing the whole staging
# install.
# ============================================================================
echo ""
echo "==> 4. Stop, clone to $VMID, convert the clone to a template"

qm shutdown "$SRC_VMID" --timeout "$SHUTDOWN_TIMEOUT" >/dev/null 2>&1 || true
i=0
while [ "$i" -lt "$SHUTDOWN_TIMEOUT" ]; do
  [ "$(qm status "$SRC_VMID" | awk '{print $2}')" = "stopped" ] && break
  sleep 5; i=$((i + 5))
done
if [ "$(qm status "$SRC_VMID" | awk '{print $2}')" != "stopped" ]; then
  if [ "$ALLOW_FORCE_STOP" = "1" ]; then
    echo "    WARNING: clean shutdown timed out; ALLOW_FORCE_STOP=1, pulling the plug." >&2
    qm stop "$SRC_VMID"
    sleep 5
  else
    echo "" >&2
    echo "ERROR: VM $SRC_VMID did not shut down within ${SHUTDOWN_TIMEOUT}s." >&2
    echo "       Refusing to force it off. Elasticsearch is already stopped cleanly, so a" >&2
    echo "       power cut here would not tear a shard — but it can leave a half-written" >&2
    echo "       ext4 journal, and that journal is inherited by EVERY lane cloned from the" >&2
    echo "       resulting template while still booting fine, so nothing reports it." >&2
    echo "       Look at the guest, then either fix it or re-run with ALLOW_FORCE_STOP=1:" >&2
    echo "           qm guest exec $SRC_VMID -- /bin/sh -c 'systemctl list-jobs'" >&2
    exit 1
  fi
fi
echo "    source VM $SRC_VMID is stopped"

echo "    cloning $SRC_VMID -> $VMID (FULL clone onto $STORAGE)"
# --full 1 unconditionally. A linked clone would keep a reference to the staging
# VM's disk, which is exactly the coupling this section exists to remove — and a
# linked clone is only possible from a template anyway.
qm clone "$SRC_VMID" "$VMID" --name "$NAME" --full 1 --storage "$STORAGE"

# ---- the clone's config, which every lane inherits -------------------------
qm set "$VMID" --agent enabled=1 >/dev/null
# ip=dhcp: the lane's MAC-pinned dnsmasq reservation is what decides a clone's
# address. A static pin here races the guest's own DHCP client and loses.
qm set "$VMID" --ipconfig0 ip=dhcp >/dev/null
# cicustom points at the STAGING LANE's snippet file. That file is deleted with
# the lane, and Proxmox refuses to start a VM whose cicustom snippet is missing.
qm set "$VMID" --delete cicustom >/dev/null 2>&1 || true
# The staging student's cloud-init password has no business in a golden template.
qm set "$VMID" --delete cipassword >/dev/null 2>&1 || true
# NOTE: the cloud-init DRIVE (ide2) is deliberately NOT removed.
# challenge-lane-deployer.js's findCloudInitDrive() looks for it, and a template
# without one makes the deployer fall back to baked accounts and publish
# credentials that do not match the machine.

if [ "$NORMALIZE_NET0" = "1" ]; then
  NET0="${TEMPLATE_NIC_MODEL},bridge=${TEMPLATE_BRIDGE}"
  [ -n "$TEMPLATE_VLAN" ] && NET0="${NET0},tag=${TEMPLATE_VLAN}"
  qm set "$VMID" --net0 "$NET0" >/dev/null
  echo "    net0 normalised to '$NET0' (the staging lane's vnet and PINNED MAC are gone)"
else
  echo "    NORMALIZE_NET0=0 — net0 keeps the staging lane's vnet and MAC:" >&2
  qm config "$VMID" | grep '^net0:' | sed 's/^/      /' >&2
  echo "      A hand-clone of this template will fail to start once that vnet is deleted," >&2
  echo "      and would take the staging elk's DHCP reservation if it did start." >&2
fi

qm set "$VMID" --description "GOAD ELK golden template (sealed).
Elasticsearch ${ES_VERSION:-unknown} / Kibana ${KBN_VERSION:-unknown} — FROZEN at seal time.
Sealed from staging VM ${SRC_VMID} on $(date -u +%Y-%m-%dT%H:%M:%SZ) by seal-goad-elk-template.sh.
winlogbeat setup artifacts KEPT (templates, ILM, ${SO_TOTAL_PRE} saved objects); staging data DELETED.
Pairs with Windows images whose winlogbeat points at elk.cybercore.lan. DHCP only." >/dev/null 2>&1 || true

IPCFG="$(qm config "$VMID" | awk -F': ' '/^ipconfig0:/ {print $2; exit}')"
printf '    %-30s %s\n' "ipconfig0 (template):" "${IPCFG:-unset}"
if [ "$IPCFG" != "ip=dhcp" ]; then
  echo "ERROR: the template's ipconfig0 is '${IPCFG:-unset}', not 'ip=dhcp'. Clones inherit" >&2
  echo "       it, and challenge-lane-deployer.js only overwrites it when" >&2
  echo "       findCloudInitDrive() succeeds. A static pin here races the guest's own DHCP" >&2
  echo "       client and loses." >&2
  exit 1
fi

qm template "$VMID"
# CONFIRMED, not assumed. This is the step whose failure mode is a seal that
# reports success while lanes clone from something that is still a VM.
if ! qm config "$VMID" | grep -qE '^template:[[:space:]]*1'; then
  echo "ERROR: $VMID did not become a template — Proxmox accepted the conversion and it" >&2
  echo "       is still a VM. Refusing to report this as sealed: a lane cloning from it" >&2
  echo "       would get a running machine's disk, or nothing at all." >&2
  exit 1
fi
if [ "$PROTECT" = "1" ]; then
  qm set "$VMID" --protection 1 >/dev/null
  echo "    protection ON (blocks destroy — and therefore blocks re-sealing)"
fi
echo "==> Template $VMID ($NAME) sealed"

# ============================================================================
# 5. What still has to happen by hand
# ============================================================================
cat <<NEXTSTEPS
============================================================================
 Template $VMID ($NAME) exists: an ELK box with winlogbeat's index templates,
 ILM policy and ${SO_TOTAL_PRE} Kibana saved objects, and with the staging lab's
 data deleted. Nothing about it is wired into CyberCore yet.

 Source VM $SRC_VMID is STOPPED and otherwise intact. Its Elasticsearch no
 longer holds the staging data (that was the point), but its setup is still
 there — so a re-seal to a different VMID does not need another staging
 install. It IS still a lane VM: whatever tears that lane down destroys it.

 1. VERIFY A CLONE BEFORE ANY STUDENT SEES ONE.

    This is the only proof that exists. Everything section 3 checked was
    checked on the machine that was sealed, not on a clone of it.

      qm clone $VMID 9994 --name elk-seal-test --full --storage $STORAGE
      qm set 9994 --net0 ${TEMPLATE_NIC_MODEL},bridge=${TEMPLATE_BRIDGE}
      qm set 9994 --ipconfig0 ip=dhcp
      qm start 9994

      # Kibana takes minutes on a cold boot. Wait for it, do not conclude early.
      qm guest exec 9994 -- /bin/sh -c 'systemctl is-active elasticsearch kibana'
      qm guest exec 9994 -- /bin/sh -c 'curl -s -o /dev/null -w "%{http_code}" $KBN_BASE/api/status'
        -> 200

      # THE PAIR THAT MATTERS: dashboards present, zero documents.
      qm guest exec 9994 -- /bin/sh -c "curl -s '$KBN_BASE/api/saved_objects/_find?type=dashboard&per_page=1'"
        -> "total" >= the ${SO_TOTAL_PRE} this seal froze in
      qm guest exec 9994 -- /bin/sh -c 'curl -s $ES_BASE/_cat/indices?v'
        -> .kibana* present, NO winlogbeat-* data indices
      qm guest exec 9994 -- /bin/sh -c 'curl -s $ES_BASE/_cat/templates | grep winlogbeat'
        -> the winlogbeat template IS listed

      # per-clone identity really is per-clone
      qm guest exec 9994 -- /bin/sh -c 'cat /etc/machine-id; ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'
        -> both differ from every other clone
      qm guest exec 9994 -- /bin/sh -c 'ip -4 -o addr show scope global'
        -> an address from DHCP, not a baked one

      qm stop 9994 && qm destroy 9994 --purge

 2. REGISTER THE TEMPLATE, AND POINT THE ELK EXTENSION AT IT.

    Admin -> Workstation Templates:

        os_family      linux
        os_name        Ubuntu 22.04 (GOAD ELK, sealed)
        os_version     22.04
        template_vmid  $VMID
        template_key   goad-elk-golden-template
        metadata       {"console_protocol": "ssh", "dns_aliases": ["elk"], "headless": true}

    console_protocol=ssh is not cosmetic: resolveConsole() defaults to rdp, so
    leaving it unset publishes a gateway DNAT to 3389 on a headless Linux box
    that is not listening there.

    dns_aliases ["elk"] is what makes elk.cybercore.lan resolve inside a lane —
    resolveSpecAddressing is the only source of that host-record, and it skips
    a machine when goadMacs[name] exists. So keep elk OUT of GOAD_LABS: as a
    plain spec VM it gets the MAC pin, the DHCP reservation and the host-record;
    added to the lab roster it loses all three in one move.

    Then POST /api/admin/vm-templates/sync-nodes so 'node' is filled in. Do NOT
    add a seed migration: front-end/migrations/ has no runner.

    front-end/src/utils/goad-deploy.js:
        GOAD_EXTENSIONS.elk.template_vmid   1011 -> $VMID

    AND THEN STOP RUNNING THE EXTENSION INSTALL FOR ELK. That is the whole
    trade this seal makes: the golden image already has Elasticsearch, Kibana,
    the templates and the dashboards, so running 'install_extension elk' against
    a lane cloned from it means roles/elk arrives at a machine that already has
    what it installs, in a version it did not choose. The Windows half
    (roles/logs_windows) is a separate question and belongs with whoever seals
    the Windows images — see 4.

    Leave GOAD_EXTENSIONS.wazuh and .lx01 pointing at 1011. That template is the
    blank base and has no SIEM in it, which is exactly what those two need.

 3. THE STACK VERSION IS NOW FROZEN, AND THREE THINGS HAVE TO AGREE.

        Elasticsearch  ${ES_VERSION:-unknown}
        Kibana         ${KBN_VERSION:-unknown}

    Every lane cloned from $VMID runs those, forever. Refreshing them is not a
    patch on this template — it is: stand a new staging lab, run
    install_extension elk again, and re-run this script to a new VMID.

    Three consumers must match this version, and each fails differently:
      a. bake-cybr400-loggen-template.sh takes ELASTIC_VERSION as a required
         argument, for its elastic-agent. A mismatched agent ships to a stack
         that rejects its documents.
      b. winlogbeat on the Windows golden images. GOAD's own defaults pin
         winlogbeat 7.17.6 against elasticsearch 7.x; those two are
         self-consistent, and neither is consistent with an 8.x sensor.
         docs/track-e-cluster-gate.md P9 item 1 is the authority.
      c. anything reading these indices by name later.

 4. THIS TEMPLATE IS HALF OF A PAIR. THE OTHER HALF IS THE WINDOWS IMAGES.

    A sealed ELK is useless on its own: it holds the mappings and the
    dashboards, and the EVENTS come from winlogbeat on the Windows hosts. Those
    agents were installed by roles/logs_windows during the same staging install,
    so they belong in the Windows golden images sealed from the same lab.

    CHECK ONE LINE ON EACH WINDOWS IMAGE before trusting any of this:

        C:\\Program Files\\Elastic\\winlogbeat\\winlogbeat-<ver>-windows-x86_64\\winlogbeat.yml
          output.elasticsearch.hosts:  MUST be ["elk.cybercore.lan:9200"]
          setup.kibana.host:                    elk.cybercore.lan

    GOAD's shipped winlogbeat.yml.j2 renders {{ hostvars['elk'].ansible_host }}
    there — an IP LITERAL, the staging lane's. A NAME survives being cloned into
    a lane with a different address; an IP does not, and the only symptom is
    "the agents ship nowhere", which is exceptionally hard to diagnose from the
    Windows end. track-e gate P9 item 5 is that fix, two lines in the template.

    (If every lane is pinned to one fixed subnet — the CiAB golden-template flow
    asserts exactly that — an IP literal happens to keep working. Do not rely on
    the accident: the name is what the design guarantees, and it is what the
    dns_aliases in step 2 exist to publish.)

 5. WHAT THIS SCRIPT COULD NOT CHECK, AND WHO HAS TO.

    a. That a clone boots. Section 1 above.
    b. That Kibana's encrypted saved objects survive in a clone. No restart on
       the sealed box can answer that: it depends on the encryption key being
       stable across a start this script never performed. The pre-clean report
       above says whether a key is explicitly set. If it is not, plain
       dashboards are fine and anything encrypted — detection rules' API keys,
       alerting rules, connectors — is dead in every clone, silently.
       Re-run with REQUIRE_KIBANA_ENC_KEY=1 to make that a refusal.
    c. That the lane's dnsmasq publishes elk.cybercore.lan. That is a deploy
       time property of the lane, not of this image:
           getent hosts elk.cybercore.lan     # from another lane machine
    d. That detection rules, if any were installed during the staging run, are
       still enabled. They were frozen exactly as they were — including the
       fact that a deployed lane has no EPR access to download rule packages
       later (track-e gate P9 item 8).
    e. That $VMID exists on every node that will clone it. A template lives on
       one node; a lane deploying elsewhere needs it migrated or copied there,
       and 'sync-nodes' in step 2 is what records where it is.

 6. EVERY KNOB THIS RUN USED (all overridable; SRC_VMID is required).

    identity   SRC_VMID=$SRC_VMID  VMID=$VMID  NAME=$NAME  STORAGE=$STORAGE
    guest exec GX_TIMEOUT=$GX_TIMEOUT  GX_LONG=$GX_LONG
    stack urls ES_SCHEME=$ES_SCHEME ES_HOST=$ES_HOST ES_PORT=$ES_PORT
               KBN_SCHEME=$KBN_SCHEME KBN_HOST=$KBN_HOST KBN_PORT=$KBN_PORT
               CURL_MAX=$CURL_MAX ES_CURL_OPTS='$ES_CURL_OPTS' KBN_CURL_OPTS='$KBN_CURL_OPTS'
    contract   DELETE_PATTERNS / KEEP_PATTERNS (KEEP is a veto, tested first)
    refusals   ALLOW_NO_DATA=$ALLOW_NO_DATA  REQUIRE_KIBANA_ENC_KEY=$REQUIRE_KIBANA_ENC_KEY
    isolation  SEAL_ISOLATE=$SEAL_ISOLATE  QUIESCE_WAIT=$QUIESCE_WAIT
    verify     ES_RESTART_WAIT=$ES_RESTART_WAIT  VERIFY_KIBANA=$VERIFY_KIBANA  KBN_RESTART_WAIT=$KBN_RESTART_WAIT
    seal       SHUTDOWN_TIMEOUT=$SHUTDOWN_TIMEOUT  ALLOW_FORCE_STOP=$ALLOW_FORCE_STOP
               NORMALIZE_NET0=$NORMALIZE_NET0  TEMPLATE_BRIDGE=$TEMPLATE_BRIDGE
               TEMPLATE_VLAN='$TEMPLATE_VLAN'  TEMPLATE_NIC_MODEL=$TEMPLATE_NIC_MODEL
               PROTECT=$PROTECT  DRY_RUN=$DRY_RUN

 To re-seal:  qm destroy $VMID --purge   then run this again.
============================================================================
NEXTSTEPS
