#!/bin/sh
# =============================================================================
# verify-track-e-lane.sh — the Track E cluster gate (E8), automated
# =============================================================================
# Run this ON THE PROXMOX NODE that hosts one deployed `defensive_monitoring`
# lane, after an incident run has finished. It checks everything in
# docs/track-e-cluster-gate.md that a machine can check, prints PASS/FAIL per
# item with what breaks when it fails, prints MANUAL: for the handful that
# genuinely need a browser, and exits non-zero if anything failed.
#
# It is modelled on the verification block inside
# infrastructure/proxmox-templates/vm-templates/bake-cybr400-loggen-template.sh:
# one check() helper, one FAIL counter, and an explanation attached to every
# check rather than to a document somebody has to go and find.
#
# WHY IT RUNS ON THE NODE AND NOT FROM A LAPTOP
# ---------------------------------------------
# Three of the four things it inspects are only reachable from there:
#   * the gateway is an LXC        — `pct exec` is node-local;
#   * the sensor is a QEMU guest   — `qm guest exec` is node-local;
#   * Elasticsearch lives INSIDE the lane's VXLAN, which has no route from
#     anywhere else on the cluster. Every ES query below is therefore issued
#     BY THE SENSOR over guest-exec — which is also the honest place to issue
#     it from, because the sensor is the machine that has to reach ES for the
#     exercise to work at all. A query that succeeds from the node and fails
#     from the sensor is the exact failure this gate exists to catch.
# The database is the exception and is optional: with no psql or no password
# those checks print MANUAL: carrying the exact SQL.
#
# POSIX sh. No bashisms, no arrays, no [[ ]], no `local`. Parses under both
# `sh -n` and `bash -n`.
# =============================================================================

set -u

# ---------------------------------------------------------------------------
# Defaults. Everything is overridable by a flag or an environment variable;
# nothing about one site's cluster is hardcoded.
# ---------------------------------------------------------------------------
LANE_ID=""
NODE=""
SENSOR_VMID=""
GATEWAY_VMID=""
RUN_ID=""
ELK_HOST="${ELK_HOST:-elk.cybercore.lan}"
ELK_PORT="${ELK_PORT:-9200}"
GX_TIMEOUT="${GX_TIMEOUT:-120}"
STACK="${STACK:-elastic}"                # elastic | wazuh | both
HOST_TELEMETRY="${HOST_TELEMETRY:-0}"    # 1 once E3b/E3c landed

DB_HOST="${CYBERCORE_DB_HOST:-100.100.20.50}"
DB_PORT="${CYBERCORE_DB_PORT:-5432}"
DB_NAME="${CYBERCORE_DB_NAME:-cybercore_db}"
DB_USER="${CYBERCORE_DB_USER:-cactus-admin}"
DB_PASS="${CYBERCORE_DB_PASSWORD:-${PGPASSWORD:-}}"

# The index the sensor's baked elastic-agent writes to. ONE dataset for both
# the benign floor and the attack, deliberately — see the bake script's
# `data_stream.dataset: loggen.events` comment. If this ever becomes two, the
# dataset dropdown in Discover IS the answer key, and A1 below fails.
ES_INDEX="${ES_INDEX:-logs-loggen.*-*}"
ES_DATASET="${ES_DATASET:-loggen.events}"

# Fixed paths, all set at bake time and none of them per-lane.
EMITTER=/opt/cybercore/cc-emit.js
FLOOR=/opt/cybercore/host-baseline.json
RUNS_DIR=/opt/cybercore/runs
ATTACK_LOGS=/opt/log-generator-attack/logs/current
DNSMASQ_CONF=/etc/dnsmasq.d/lane-reservations.conf

# Hostnames the BAKED generic floor draws from. Their presence in the index is
# the single clearest proof that the profile-derived floor swap did NOT land.
# Transcribed from front-end/src/incident/playbooks/host-baseline.json pools.
GENERIC_HOSTS="srv-prod-01 app-server-01 db-01 web-01 fileserv-01 srv-prod-02 app-server-02 web-02 build-01 monitor-01 backup-01 db-02 cache-01 fileserv-02 ws-042 ws-071 ws-113 ws-128 ws-014 ws-025 firewall-01 auth-01"

PASS=0
FAIL=0
MANUAL=0
SKIPPED=0

# Filled in by the R section when the database is reachable, and read again
# by the D section. Initialised here because `set -u` makes an unset read a
# hard error, and the D section legitimately runs on paths where the R
# section did not.
key_techs=""
key_events=""

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat >&2 <<'USAGE'
usage: verify-track-e-lane.sh --lane <lane_id> --node <pve-node> --sensor-vmid <vmid>
                              [--gateway-vmid <vmid>] [--run <run_id>]
                              [--stack elastic|wazuh|both] [--host-telemetry]

REQUIRED
  --lane          cybercore_lane.lane_id of the lane under test (a UUID).
  --node          the Proxmox node hosting that lane. Must be the node you are
                  running this on: pct exec and qm guest exec are node-local.
  --sensor-vmid   the vmid of that lane's `sensor` VM. Find it with:
                    qm list | grep -i sensor

OPTIONAL
  --gateway-vmid  the lane's gateway LXC. Derived as 100000 + vxlan_id when the
                  database is reachable; otherwise you must pass it.
  --run           the incident run to grade against. Defaults to the most
                  recent run targeting this lane (requires the database).
  --stack         which SIEM(s) the engagement deployed. Default: elastic.
  --host-telemetry
                  set once the GOAD ELK prebake (E3b) and the detection rules
                  (E3c) have landed: adds assertions 9-12.

ENVIRONMENT
  CYBERCORE_DB_PASSWORD   enables every database check. Without it those checks
                          print MANUAL: with the exact SQL instead of failing.
  ELK_HOST / ELK_PORT     default elk.cybercore.lan / 9200
  GX_TIMEOUT              seconds allowed per guest-exec. Default 120.
USAGE
  exit 2
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Argument parsing. Fails loudly and specifically: a gate that runs against the
# wrong lane and reports PASS is worse than one that refuses to start.
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --lane)           [ $# -ge 2 ] || die "--lane needs a value"; LANE_ID="$2"; shift 2 ;;
    --node)           [ $# -ge 2 ] || die "--node needs a value"; NODE="$2"; shift 2 ;;
    --sensor-vmid)    [ $# -ge 2 ] || die "--sensor-vmid needs a value"; SENSOR_VMID="$2"; shift 2 ;;
    --gateway-vmid)   [ $# -ge 2 ] || die "--gateway-vmid needs a value"; GATEWAY_VMID="$2"; shift 2 ;;
    --run)            [ $# -ge 2 ] || die "--run needs a value"; RUN_ID="$2"; shift 2 ;;
    --stack)          [ $# -ge 2 ] || die "--stack needs a value"; STACK="$2"; shift 2 ;;
    --host-telemetry) HOST_TELEMETRY=1; shift ;;
    -h|--help)        usage ;;
    *) die "unknown argument '$1'. Run with --help." ;;
  esac
done

[ -n "$LANE_ID" ] || die "--lane is required. It is the UUID in cybercore_lane.lane_id, and every database check keys on it."
[ -n "$NODE" ]    || die "--node is required. pct exec and qm guest exec are node-local, so this script must not guess."
[ -n "$SENSOR_VMID" ] || die "--sensor-vmid is required. Nothing here works without a sensor: it is the machine that ships to Elasticsearch, and the machine every ES query below is issued from."

case "$LANE_ID" in
  ????????-????-????-????-????????????) ;;
  *) die "--lane '$LANE_ID' is not a UUID. Copy it from the Environments table or from: SELECT lane_id FROM cybercore_lane WHERE config->>'engagement_id' = '<engagement>';" ;;
esac
case "$SENSOR_VMID" in ''|*[!0-9]*) die "--sensor-vmid '$SENSOR_VMID' is not a number." ;; esac
if [ -n "$GATEWAY_VMID" ]; then
  case "$GATEWAY_VMID" in ''|*[!0-9]*) die "--gateway-vmid '$GATEWAY_VMID' is not a number." ;; esac
fi
case "$STACK" in elastic|wazuh|both) ;; *) die "--stack must be elastic, wazuh or both (got '$STACK')" ;; esac

command -v qm  >/dev/null 2>&1 || die "qm is not on PATH — this is not a Proxmox node."
command -v pct >/dev/null 2>&1 || die "pct is not on PATH — this is not a Proxmox node."

THIS_NODE=$(hostname -s 2>/dev/null || hostname)
if [ "$THIS_NODE" != "$NODE" ]; then
  die "you are on node '$THIS_NODE' but --node says '$NODE'.
       qm guest exec and pct exec do not cross nodes. Copy this script over and run it there:
         scp $0 root@$NODE:/root/verify-track-e-lane.sh
         ssh root@$NODE \"sh /root/verify-track-e-lane.sh --lane $LANE_ID --node $NODE --sensor-vmid $SENSOR_VMID\""
fi

# ---------------------------------------------------------------------------
# Reporting helpers. One line per assertion, and every failure carries the
# consequence — the bake script's convention, for the same reason: the operator
# reading this output is the person who has to decide whether to ship the lane.
# ---------------------------------------------------------------------------
check() {   # check <label> <got> <want> <what breaks when it fails>
  if [ "$2" = "$3" ]; then
    printf 'PASS  %-46s %s\n' "$1" "$2"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %-46s got=[%s] want=[%s]\n' "$1" "${2:-<empty>}" "$3" >&2
    printf '      WHAT BREAKS: %s\n' "$4" >&2
    FAIL=$((FAIL + 1))
  fi
}

check_true() {  # check_true <label> <0|1> <what breaks>
  if [ "$2" = "1" ]; then
    printf 'PASS  %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %s\n' "$1" >&2
    printf '      WHAT BREAKS: %s\n' "$3" >&2
    FAIL=$((FAIL + 1))
  fi
}

check_range() {  # check_range <label> <value> <min> <max> <what breaks>
  case "$2" in
    ''|*[!0-9]*)
      printf 'FAIL  %-46s got=[%s] (not a number)\n' "$1" "${2:-<empty>}" >&2
      printf '      WHAT BREAKS: %s\n' "$5" >&2
      FAIL=$((FAIL + 1))
      return ;;
  esac
  if [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; then
    printf 'PASS  %-46s %s (want %s..%s)\n' "$1" "$2" "$3" "$4"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %-46s %s (want %s..%s)\n' "$1" "$2" "$3" "$4" >&2
    printf '      WHAT BREAKS: %s\n' "$5" >&2
    FAIL=$((FAIL + 1))
  fi
}

manual() {  # manual <what to click> <what must be true>
  printf 'MANUAL  %s\n' "$1"
  printf '        EXPECT: %s\n' "$2"
  MANUAL=$((MANUAL + 1))
}

skip() {    # skip <label> <why it could not run>. NEVER silent, NEVER a PASS.
  printf 'SKIP  %-46s %s\n' "$1" "$2" >&2
  SKIPPED=$((SKIPPED + 1))
}

section() { printf '\n=== %s ===\n' "$1"; }

# ---------------------------------------------------------------------------
# guest_sh — run a shell script inside the sensor and get its output back
#
# `qm guest exec` returns JSON, and out-data is a JSON STRING: real newlines
# arrive as the two characters backslash-n, quotes arrive escaped, and the
# bake script's sed idiom (which stops at the first quote) therefore cannot
# survive output that is itself JSON — which is exactly what every
# Elasticsearch query below produces.
#
# So the guest base64s its own output before handing it back. The alphabet is
# [A-Za-z0-9+/=] with no quotes and no backslashes, so the same sed idiom is
# then exact. The script we send goes in base64 too, which is what lets these
# checks contain single quotes, dollars and JSON without any escaping analysis.
#
# The guest's exit code is carried inside the payload as a __RC= line rather
# than inferred: `qm guest exec` succeeds whenever it managed to RUN something,
# which is not the same question.
# ---------------------------------------------------------------------------
GX_RC=0
guest_sh() {   # guest_sh <script text>  -> guest stdout+stderr on our stdout
  gs_enc=$(printf '%s' "$1" | base64 | tr -d '\n\r')
  gs_raw=$(qm guest exec "$SENSOR_VMID" --timeout "$GX_TIMEOUT" -- /bin/sh -c \
    "echo $gs_enc | base64 -d > /tmp/.cc-tracke.sh; sh /tmp/.cc-tracke.sh > /tmp/.cc-tracke.out 2>&1; echo \"__RC=\$?\" >> /tmp/.cc-tracke.out; base64 /tmp/.cc-tracke.out | tr -d '\n'; rm -f /tmp/.cc-tracke.sh /tmp/.cc-tracke.out" 2>/dev/null)
  if [ -z "$gs_raw" ]; then GX_RC=97; return 97; fi
  gs_b64=$(printf '%s' "$gs_raw" | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -z "$gs_b64" ]; then GX_RC=98; return 98; fi
  gs_txt=$(printf '%s' "$gs_b64" | tr -d ' \r\n\\' | base64 -d 2>/dev/null)
  if [ -z "$gs_txt" ]; then GX_RC=98; return 98; fi
  GX_RC=$(printf '%s\n' "$gs_txt" | sed -n 's/^__RC=\([0-9][0-9]*\)$/\1/p' | tail -1)
  [ -n "$GX_RC" ] || GX_RC=99
  printf '%s\n' "$gs_txt" | grep -v '^__RC=' || true
  return "$GX_RC"
}

# es <method> <path> [body] — an Elasticsearch call issued BY THE SENSOR.
es() {
  if [ $# -ge 3 ]; then
    guest_sh "curl -s --max-time 25 -H 'Content-Type: application/json' -X $1 'http://$ELK_HOST:$ELK_PORT$2' -d '$3'"
  else
    guest_sh "curl -s --max-time 25 -X $1 'http://$ELK_HOST:$ELK_PORT$2'"
  fi
}

# gw <shell command> — run inside the lane gateway LXC. pct exec streams
# straight to stdout, so no decoding is needed on this path.
gw() { pct exec "$GATEWAY_VMID" -- /bin/sh -c "$1" 2>/dev/null; }

# sql <statement> — one value or one row set, tuples-only and unaligned.
DB_OK=0
sql() { PGPASSWORD="$DB_PASS" psql -qtAX -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$1" 2>/dev/null; }

trim() { printf '%s' "$1" | tr -d ' \t\r\n'; }

printf '=============================================================\n'
printf ' Track E cluster gate — lane %s\n' "$LANE_ID"
printf ' node %s   sensor vmid %s   stack %s   host-telemetry %s\n' "$NODE" "$SENSOR_VMID" "$STACK" "$HOST_TELEMETRY"
printf '=============================================================\n'

# ---------------------------------------------------------------------------
# 0. Database reachability, and the two ids we can derive from it
# ---------------------------------------------------------------------------
section "0. Context"

if command -v psql >/dev/null 2>&1 && [ -n "$DB_PASS" ]; then
  if [ "$(trim "$(sql 'SELECT 1')")" = "1" ]; then
    DB_OK=1
  fi
fi

if [ "$DB_OK" = "1" ]; then
  printf 'INFO  database %s@%s:%s/%s reachable\n' "$DB_USER" "$DB_HOST" "$DB_PORT" "$DB_NAME"
  if [ -z "$GATEWAY_VMID" ]; then
    vx=$(trim "$(sql "SELECT vxlan_id FROM cybercore_lane WHERE lane_id = '$LANE_ID'")")
    case "$vx" in
      ''|*[!0-9]*) : ;;
      *) GATEWAY_VMID=$((100000 + vx)); printf 'INFO  gateway LXC derived from vxlan_id %s -> %s\n' "$vx" "$GATEWAY_VMID" ;;
    esac
  fi
  if [ -z "$RUN_ID" ]; then
    RUN_ID=$(trim "$(sql "SELECT r.run_id FROM cybercore_incident_run r JOIN cybercore_incident_target t ON t.run_id = r.run_id WHERE t.lane_id = '$LANE_ID' ORDER BY r.created_at DESC LIMIT 1")")
    [ -n "$RUN_ID" ] && printf 'INFO  most recent run for this lane: %s\n' "$RUN_ID"
  fi
else
  printf 'INFO  database checks disabled (psql missing, or CYBERCORE_DB_PASSWORD unset)\n'
fi

[ -n "$GATEWAY_VMID" ] || printf 'INFO  no --gateway-vmid and none derivable: gateway checks will be skipped\n'
[ -n "$RUN_ID" ]       || printf 'INFO  no --run and none derivable: run-scoped checks will be skipped\n'

# ---------------------------------------------------------------------------
# G. GATEWAY — DNS and the console DNAT
#
# GATE ASSERTION (plan, "Gateway"): lane-reservations.conf has BOTH a dhcp-host
# and a host-record line for elk and for sensor, and there is exactly ONE
# installConsoleDnat tag carrying the complete target list.
# ---------------------------------------------------------------------------
section "G. Gateway"

if [ -z "$GATEWAY_VMID" ]; then
  skip "gateway checks" "no --gateway-vmid and the database was not reachable to derive it"
else
  gw_conf=$(gw "cat $DNSMASQ_CONF 2>/dev/null")
  if [ -z "$gw_conf" ]; then
    check_true "gateway $GATEWAY_VMID has $DNSMASQ_CONF" 0 \
      "the deployer never wrote the lane's reservations. Every guest then takes a pool address instead of its pinned one, elk.cybercore.lan resolves to nothing, and the sensor's agent — which hard-codes ELK_HOST at bake time — reports HEALTHY while shipping zero events."
  else
    printf 'PASS  gateway %s has %s\n' "$GATEWAY_VMID" "$DNSMASQ_CONF"
    PASS=$((PASS + 1))

    for nm in elk sensor; do
      [ "$nm" = "elk" ] && [ "$STACK" = "wazuh" ] && continue
      have_dhcp=0
      printf '%s\n' "$gw_conf" | grep -qi "^dhcp-host=.*,${nm}\$" && have_dhcp=1
      check_true "dhcp-host line for '$nm'" "$have_dhcp" \
        "$nm has no MAC reservation, so it takes whatever the DHCP pool hands out. Its address then disagrees with the host-record below, and every agent aimed at it by name lands on the wrong machine or on nothing."

      have_hr=0
      printf '%s\n' "$gw_conf" | grep -qi "^host-record=${nm},${nm}\..*," && have_hr=1
      check_true "host-record line for '$nm'" "$have_hr" \
        "the alias does not resolve inside the lane. For elk this is risk 4 exactly: the sensor's baked elastic-agent.yml hard-codes ELK_HOST=$ELK_HOST, so an unresolvable name leaves a HEALTHY agent shipping nothing, with no error anywhere a console can see."
    done

    if [ "$STACK" = "wazuh" ] || [ "$STACK" = "both" ]; then
      have_wz=0
      printf '%s\n' "$gw_conf" | grep -qi '^host-record=wazuh,wazuh\..*,' && have_wz=1
      check_true "host-record line for 'wazuh'" "$have_wz" \
        "a wazuh or both stack was deployed but the manager has no name in the lane, so every wazuh-agent enrolls against an unresolvable host and retries forever — which reads as a broken lane rather than a missing DNS record."
    fi

    dnsmasq_up=$(trim "$(gw 'pgrep dnsmasq >/dev/null 2>&1 && echo up || echo down')")
    check "dnsmasq is running on the gateway" "$dnsmasq_up" "up" \
      "dnsmasq refuses to start when two dhcp-host lines claim one IP — the gateway template bakes 'dhcp-host=kali,<ext>.50' and the lane writes its own. With it down NOTHING on the lane gets an address, while the lane still reports active."
  fi

  dnat_count=$(trim "$(gw 'iptables-save -t nat 2>/dev/null | grep -c LANE-CONSOLE')")
  case "$dnat_count" in ''|*[!0-9]*) dnat_count=0 ;; esac
  if [ "$dnat_count" -ge 1 ]; then
    printf 'PASS  %-46s %s DNAT rule(s) tagged LANE-CONSOLE\n' "console DNAT installed" "$dnat_count"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %-46s no LANE-CONSOLE rules in the nat table\n' "console DNAT installed" >&2
    printf '      WHAT BREAKS: %s\n' "the lane has no published console at all. resolveConsolePlan returns primary=null when attackBoxes is false and no spec VM declares console_role, and the deployer treats an empty target list as success (consoleDnatOk = consoleTargets.length === 0) — so a lane with NO way for the student to reach Kibana deploys, reports active, and looks correct. See docs/track-e-cluster-gate.md, precondition P9." >&2
    FAIL=$((FAIL + 1))
  fi
fi

# ---------------------------------------------------------------------------
# S. SENSOR — name resolution, the ES banner, and the services
# ---------------------------------------------------------------------------
section "S. Sensor"

sensor_state=$(qm status "$SENSOR_VMID" 2>/dev/null | awk '{print $2}')
check "sensor VM $SENSOR_VMID is running" "$sensor_state" "running" \
  "a stopped sensor emits no benign floor, so loggen.source.type:host would appear ONLY during the attack and one terms click would end the exercise."

# A sentinel probe, NOT guest_sh's return code. guest_sh is always called
# inside a command substitution, which is a subshell, so a GX_RC set in
# there never reaches this scope. Asking the guest to echo a known string is
# the only reading that survives the subshell boundary.
gx_probe=$(guest_sh "echo cc-guest-ok" 2>/dev/null)
if ! printf '%s' "$gx_probe" | grep -q 'cc-guest-ok'; then
  check_true "guest-exec reaches the sensor" 0 \
    "qemu-guest-agent is not answering. The incident engine dispatches every run over guest-exec, so nothing can be launched into this lane at all — and the bake pins GUEST_AGENT_UNBLOCKED for exactly this reason: guest-exec blacklisted in /etc/sysconfig/qemu-ga returns 596 while the VM looks healthy."
else
  printf 'PASS  guest-exec reaches the sensor\n'
  PASS=$((PASS + 1))

  getent_out=$(guest_sh "getent hosts $ELK_HOST" 2>/dev/null)
  elk_ip=$(printf '%s' "$getent_out" | awk 'NR==1{print $1}')
  # Shape-checked, not just non-empty. guest_sh folds the guest's stderr into
  # its stdout, so a failed lookup hands back an error SENTENCE whose first
  # word would otherwise read as an address and pass this check.
  case "$elk_ip" in
    *[!0-9.]*|'') elk_ip='' ;;
  esac
  if [ -n "$elk_ip" ]; then
    printf 'PASS  %-46s %s -> %s\n' "sensor resolves $ELK_HOST" "$ELK_HOST" "$elk_ip"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %-46s no answer\n' "sensor resolves $ELK_HOST" >&2
    printf '      WHAT BREAKS: %s\n' "risk 4, the silent one. The agent config baked into template 1007 points at $ELK_HOST and nothing else. An unresolvable name leaves elastic-agent HEALTHY, its own log clean, and the index empty. Check the gateway host-record above, and check that the sensor's nameserver is the gateway." >&2
    FAIL=$((FAIL + 1))
  fi

  banner=$(es GET "/" 2>/dev/null)
  got_banner=0
  printf '%s' "$banner" | grep -q 'You Know, for Search' && got_banner=1
  printf '%s' "$banner" | grep -q '"cluster_name"' && got_banner=1
  check_true "sensor gets the Elasticsearch banner from $ELK_HOST:$ELK_PORT" "$got_banner" \
    "the name resolves but Elasticsearch does not answer the sensor. Either the SIEM has not finished booting, or security was turned on (E3c) and the sensor still posts unauthenticated — risk 5d: it 401s while staying HEALTHY, so the console shows a run that generated events and Kibana shows nothing."

  for unit in cc-hostbase elastic-agent; do
    st=$(trim "$(guest_sh "systemctl is-active $unit 2>/dev/null || true")")
    if [ "$unit" = "cc-hostbase" ]; then
      why="cc-hostbase IS the benign floor. With it dead the index contains the attack and almost nothing else, and the hunt is a single terms aggregation."
    else
      why="events land on the sensor's disk and never reach Kibana. The run completes, the console reports its event count, and the student's index is empty."
    fi
    check "systemctl is-active $unit" "$st" "active" "$why"
  done

  rot=$(trim "$(guest_sh "systemctl is-active loggen-rotate.timer 2>/dev/null || true")")
  if [ "$rot" = "active" ]; then
    printf 'PASS  %-46s active\n' "loggen-rotate.timer"
    PASS=$((PASS + 1))
  else
    skip "loggen-rotate.timer" "is-active returned '$rot' — not a gate failure, but logs.json grows without bound (measured: 2.5 GB in twelve hours)"
  fi

  # THE FLOOR SWAP, read at its source. The ES aggregation below is the real
  # assertion; this one says WHY it failed when it fails.
  floor_probe=$(guest_sh "test -s $FLOOR && node -e \"var p=require('$FLOOR');var h=[].concat(p.pools&&p.pools.hosts||[]);console.log('HOSTS='+h.length);console.log('SAMPLE='+h.slice(0,6).join(','));\" 2>&1")
  floor_hosts=$(printf '%s' "$floor_probe" | sed -n 's/^HOSTS=\([0-9]*\)$/\1/p')
  floor_sample=$(printf '%s' "$floor_probe" | sed -n 's/^SAMPLE=//p')
  if [ -n "$floor_hosts" ] && [ "$floor_hosts" -gt 0 ] 2>/dev/null; then
    generic_in_floor=0
    for g in $GENERIC_HOSTS; do
      case ",$floor_sample," in *",$g,"*) generic_in_floor=1 ;; esac
    done
    if [ "$generic_in_floor" = "1" ]; then
      printf 'FAIL  %-46s %s\n' "$FLOOR is the CLIENT's floor" "$floor_sample" >&2
      printf '      WHAT BREAKS: %s\n' "the sensor is still running the BAKED generic floor. blueteam-postdeploy.makeFloorSwapPostDeploy never ran, or it threw — check cybercore_lane.config->>'post_deploy_error'. The attack will then name the client's own machines while the floor names web-01 and ws-042, and one terms aggregation on loggen.source.host ends the exercise. This is risk 5, and it reviews as working." >&2
      FAIL=$((FAIL + 1))
    else
      printf 'PASS  %-46s %s hosts, e.g. %s\n' "$FLOOR is the CLIENT's floor" "$floor_hosts" "$floor_sample"
      PASS=$((PASS + 1))
    fi
  else
    check_true "$FLOOR is readable and has a hosts pool" 0 \
      "cc-hostbase cannot parse its playbook, so the benign floor is not running. The swap script validates the staged file with node before mv-ing it, so a broken file here means the swap was never attempted — look for config.post_deploy_error on the lane row."
  fi
fi

# ---------------------------------------------------------------------------
# A. ELASTICSEARCH — assertions 1 through 3, and the strip check for 4
# ---------------------------------------------------------------------------
section "A. Elasticsearch (queried from the sensor)"

agg_ds=$(es POST "/$ES_INDEX/_search" '{"size":0,"track_total_hits":true,"aggs":{"ds":{"terms":{"field":"data_stream.dataset","size":20}}}}' 2>/dev/null)

if [ -z "$agg_ds" ] || printf '%s' "$agg_ds" | grep -q '"error"'; then
  check_true "A1  documents have arrived in $ES_INDEX" 0 \
    "no index, or Elasticsearch refused the query. If the error says index_not_found_exception then NOTHING has ever shipped: work back through the sensor checks above. If it says 'Fielddata is disabled on text fields' then the logs@custom component template was never applied — on the Windows ELK box that is Import-CybrDashboard.ps1's job at boot; on a prebaked Linux ELK you must apply it in the bake, or every terms panel and every assertion below renders empty."
else
  total=$(printf '%s' "$agg_ds" | sed -n 's/.*"hits":{"total":{"value":\([0-9]*\).*/\1/p')
  [ -n "$total" ] || total=0
  if [ "$total" -gt 0 ] 2>/dev/null; then
    printf 'PASS  %-46s %s documents\n' "A1  documents have arrived" "$total"
    PASS=$((PASS + 1))
  else
    check_true "A1  documents have arrived" 0 \
      "the index exists but is empty. The agent resolves and connects but ships nothing — check that cc-hostbase is actually writing to /opt/log-generator/logs/current/host.json, and that the floor swap used rm rather than truncate (a zeroed inode strands filestream's registry offset past EOF and the lane silently ships nothing for the rest of its life)."
  fi

  ds_keys=$(printf '%s' "$agg_ds" | tr ',' '\n' | sed -n 's/.*"key":"\([a-z0-9_.]*\)".*/\1/p' | sort -u | tr '\n' ' ')
  ds_n=$(printf '%s' "$ds_keys" | wc -w | tr -d ' ')
  check "A1  exactly one data_stream.dataset" "$ds_n" "1" \
    "two datasets means the benign floor and the attack are separable from Discover's dataset dropdown in one click. The bake ships BOTH filestream inputs under data_stream.dataset: loggen.events precisely to prevent this; if it has drifted, the whole exercise is a filter."
  check "A1  the dataset is $ES_DATASET" "$(trim "$ds_keys")" "$ES_DATASET" \
    "the sensor is writing somewhere the Kibana data view (logs-loggen.*-*) does not cover, so the student's Discover is empty even though documents exist."
fi

agg_host=$(es POST "/$ES_INDEX/_search" '{"size":0,"aggs":{"h":{"terms":{"field":"loggen.source.host","size":200}}}}' 2>/dev/null)
if printf '%s' "$agg_host" | grep -q '"buckets"'; then
  host_keys=$(printf '%s' "$agg_host" | tr ',' '\n' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p' | sort -u)
  leaked=""
  for g in $GENERIC_HOSTS; do
    printf '%s\n' "$host_keys" | grep -qx "$g" && leaked="$leaked $g"
  done
  n_hosts=$(printf '%s\n' "$host_keys" | grep -c . | tr -d ' ')
  if [ -n "$leaked" ]; then
    printf 'FAIL  %-46s baked generic hosts present:%s\n' "A2  loggen.source.host is the client's estate" "$leaked" >&2
    printf '      WHAT BREAKS: %s\n' "the floor swap did not land on this lane (or landed after cc-hostbase had already written a few hundred generic events — check whether the generic names are a handful of documents or a steady stream). While a generic hostname and a client hostname coexist in the index, the client's own machine names ARE the attack, and one terms aggregation ends the hunt. Fix the swap and re-deploy the lane; a best-effort _delete_by_query for the pre-swap window is the documented cleanup." >&2
    FAIL=$((FAIL + 1))
  else
    printf 'PASS  %-46s %s hostnames, none from the baked pool\n' "A2  loggen.source.host is the client's estate" "$n_hosts"
    PASS=$((PASS + 1))
  fi
else
  check_true "A2  terms aggregation on loggen.source.host" 0 \
    "the aggregation returned no buckets. Either nothing has shipped, or loggen.source.host is mapped as text rather than keyword — which happens whenever the logs@custom component template was not applied before the first write. A text field is not aggregatable, so every terms panel on both dashboards also renders empty, and the lane looks fine."
fi

cnt_all=$(es POST "/$ES_INDEX/_count" '{"query":{"match_all":{}}}' 2>/dev/null | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
cnt_tagged=$(es POST "/$ES_INDEX/_count" '{"query":{"exists":{"field":"loggen.mitre.technique"}}}' 2>/dev/null | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
if [ -n "$cnt_all" ] && [ -n "$cnt_tagged" ] && [ "$cnt_all" -gt 0 ] 2>/dev/null; then
  pct10=$(( cnt_tagged * 1000 / cnt_all ))
  check_range "A3  MITRE-tagged share (tenths of a %)" "$pct10" 40 200 \
    "the benign floor's own technique labelling is outside 4-20%. Too low and 'has a technique' is effectively an attack selector; too high and hunting by technique returns noise forever. The scorer also depends on this band: a claim that matches the floor's tagged set is graded a DEFENSIBLE MISS rather than a false positive, and with no tagged floor that mercy rule never fires."
  printf 'INFO  %s of %s documents carry loggen.mitre.technique\n' "$cnt_tagged" "$cnt_all"
else
  skip "A3  MITRE-tagged share" "could not count documents — see A1"
fi

# ---------------------------------------------------------------------------
# R. THE RUN — assertions 4 to 7, graded where they are actually decidable
#
# CORRECTION TO THE PLAN, AND IT IS LOAD-BEARING.
# The plan's assertion 4 says the post-run technique set in Kibana equals
# answer_key.techniques. It cannot, and it must not: the sensor's baked agent
# config drops loggen.mitre (and log.file.path) from every ATTACK event before
# it leaves the box — bake marker ATTACK_STRIP_TAG, pinned by
# test/bake-payloads.test.js. An attack event that arrived stamped with its
# technique would put the whole run one filter away from full enumeration.
#
# So the assertion is graded in the two places where it IS decidable:
#   * in Elasticsearch, the technique set must NOT have gained the attack's
#     techniques (proof the strip worked);
#   * on the sensor, the raw attack file still carries them, and that set must
#     equal the answer key's — proof the run emitted what was graded.
# ---------------------------------------------------------------------------
section "R. The run"

if [ -z "$RUN_ID" ]; then
  skip "run-scoped checks (A4-A7)" "no --run and the database was not reachable to find the latest run for this lane"
else
  printf 'INFO  run %s\n' "$RUN_ID"

  # The answer key, from the database. STAFF ONLY — it never reaches a student
  # route, and this script is an operator tool run on the cluster.
  key_techs=""
  key_events=""
  if [ "$DB_OK" = "1" ]; then
    key_techs=$(trim "$(sql "SELECT string_agg(t, ' ' ORDER BY t) FROM (SELECT DISTINCT jsonb_array_elements(answer_key->'techniques')->>'technique_id' AS t FROM cybercore_incident_run WHERE run_id = '$RUN_ID') s")")
    if [ -z "$key_techs" ]; then
      key_techs=$(trim "$(sql "SELECT string_agg(t, ' ' ORDER BY t) FROM (SELECT DISTINCT jsonb_array_elements_text(answer_key->'techniques') AS t FROM cybercore_incident_run WHERE run_id = '$RUN_ID') s")")
    fi
    key_events=$(trim "$(sql "SELECT answer_key->'totals'->>'events' FROM cybercore_incident_run WHERE run_id = '$RUN_ID'")")
  fi

  # The attack, as it was actually emitted on this lane. cc-attack.sh stages it
  # at /opt/cybercore/runs/<run>/playbook.json and writes its own event count to
  # .../count; the raw events land in the attack tree still carrying the tag.
  atk_probe=$(guest_sh "R=$RUNS_DIR/$RUN_ID; test -d \"\$R\" || { echo MISSING; exit 1; }; echo COUNT=\$(cat \"\$R/count\" 2>/dev/null | tr -d ' \n'); echo LINES=\$(cat $ATTACK_LOGS/attack-$RUN_ID.json 2>/dev/null | grep -c '\"technique\":\"' | tr -d ' '); echo TECHS=\$(cat $ATTACK_LOGS/attack-$RUN_ID.json 2>/dev/null | sed -n 's/.*\"technique\":\"\\([^\"]*\\)\".*/\\1/p' | sort -u | tr '\n' ' ')")
  if printf '%s' "$atk_probe" | grep -q '^MISSING$'; then
    check_true "R  the run was staged onto this sensor" 0 \
      "there is no $RUNS_DIR/$RUN_ID on the sensor, so this lane never received the dispatch. Look at cybercore_incident_target.status and .skip_reason for this lane — a 'skipped' target means resolveLoggenTarget could not identify the sensor and DELIBERATELY refused to guess rather than fire an attack at the student's SIEM."
  else
    atk_count=$(printf '%s' "$atk_probe" | sed -n 's/^COUNT=//p' | tr -d ' ')
    atk_lines=$(printf '%s' "$atk_probe" | sed -n 's/^LINES=//p' | tr -d ' ')
    atk_techs=$(trim "$(printf '%s' "$atk_probe" | sed -n 's/^TECHS=//p')")
    atk_techs_sorted=$(printf '%s' "$atk_techs" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')
    atk_techs_sorted=$(trim "$atk_techs_sorted")
    printf 'INFO  emitter count=%s tagged lines on disk=%s techniques=[%s]\n' "${atk_count:-?}" "${atk_lines:-?}" "$atk_techs_sorted"

    if [ -n "$key_events" ] && [ -n "$atk_count" ]; then
      check "A4  emitted events == answer_key.totals.events" "$atk_count" "$key_events" \
        "the run did not emit what it was graded against. answer_key is compiled server-side from the run id with the same deterministic seed the guest uses, so a mismatch means the guest ran a DIFFERENT playbook — a stale staged file, a truncated transfer, or a run that hit the timeout cap. Every score on this run is measured against events that were never written."
    else
      skip "A4  emitted events == answer_key.totals.events" "needs the database for the answer key"
    fi

    if [ -n "$key_techs" ]; then
      # Compare as sorted, space-separated sets.
      k=$(printf '%s' "$key_techs" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')
      k=$(trim "$k")
      a=$(trim "$atk_techs_sorted")
      check "A4  emitted technique set == answer key" "$a" "$k" \
        "the board grades a technique set the lane never produced. Every correct answer scores as a false positive and every missing one as a miss, and nothing in the UI reveals it."
    else
      skip "A4  emitted technique set == answer key" "needs the database for the answer key"
    fi

    # The strip. This is the half the plan's assertion 4 was reaching for.
    if [ -n "$atk_techs_sorted" ]; then
      es_techs=$(es POST "/$ES_INDEX/_search" '{"size":0,"aggs":{"t":{"terms":{"field":"loggen.mitre.technique","size":100}}}}' 2>/dev/null | tr ',' '\n' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p' | sort -u)
      leak=""
      for t in $atk_techs_sorted; do
        printf '%s\n' "$es_techs" | grep -qx "$t" && leak="$leak $t"
      done
      if [ -n "$leak" ]; then
        printf 'FAIL  %-46s attack techniques visible in ES:%s\n' "A4  the attack's tag never reaches Kibana" "$leak" >&2
        printf '      WHAT BREAKS: %s\n' "the agent's drop_fields on loggen.mitre is not running for the attack tree, so every attack event arrives stamped with its technique and the whole run is one filter away from being fully enumerated. Note the ORDER dependency the bake documents: drop_event must come BEFORE drop_fields, or every attack event is discarded instead. (A technique the FLOOR also plants is not a leak — compare against answer_key.floor_techniques before re-baking.)" >&2
        FAIL=$((FAIL + 1))
      else
        printf 'PASS  %-46s no attack technique is queryable\n' "A4  the attack's tag never reaches Kibana"
        PASS=$((PASS + 1))
      fi
    fi

    # A5/A6/A7 — the three anti-oracle subset checks, run against the two
    # playbooks that are BOTH on this sensor, using the sensor's own baked
    # cc-emit.js to expand them. This is the same contract
    # front-end/test/helpers/playbook-contract.js asserts offline; running it
    # here proves the pair that actually deployed satisfies it, not the pair
    # that was compiled in CI.
    contract=$(guest_sh "node -e \"
var E=require('$EMITTER');
var fs=require('fs');
var floor=JSON.parse(fs.readFileSync('$FLOOR','utf8'));
var atk=JSON.parse(fs.readFileSync('$RUNS_DIR/$RUN_ID/playbook.json','utf8'));
function plan(p){return E.planTimeline(p,{rng:E.makeRng(E.seedFrom('$RUN_ID')),requested:p.nominal_seconds||300});}
function lines(pl){return pl.events.map(function(e){return JSON.parse(E.toLine(e));});}
var fl=lines(plan(floor)), al=lines(plan(atk));
var fp={},fh={},fv={},fs2={};
fl.forEach(function(e){fp[e.source.type+'/'+e.source.name]=1;fh[e.source.host]=1;
  Object.keys(e.metadata||{}).forEach(function(k){var v=String(e.metadata[k]);fv[v]=1;
    if(k==='src_ip'||k==='dst_ip')fs2[v.split('.')[0]]=1;});});
var bp=[],bh=[],bv=[],bs=[];
al.forEach(function(e){var pr=e.source.type+'/'+e.source.name;
  if(!fp[pr]&&bp.indexOf(pr)<0)bp.push(pr);
  if(!fh[e.source.host]&&bh.indexOf(e.source.host)<0)bh.push(e.source.host);
  Object.keys(e.metadata||{}).forEach(function(k){var v=String(e.metadata[k]);
    if(k==='src_ip'||k==='dst_ip'){var sp=v.split('.')[0];if(!fs2[sp]&&bs.indexOf(sp)<0)bs.push(sp);return;}
    if(v.length>40)return;
    if(!fv[v]&&bv.indexOf(k+'='+v)<0)bv.push(k+'='+v);});});
console.log('PAIRS='+bp.slice(0,6).join(','));
console.log('HOSTS='+bh.slice(0,6).join(','));
console.log('VALUES='+bv.slice(0,6).join(','));
console.log('SPACES='+bs.slice(0,6).join(','));
\" 2>&1")
    if printf '%s' "$contract" | grep -q '^PAIRS='; then
      c_pairs=$(printf '%s' "$contract" | sed -n 's/^PAIRS=//p')
      c_hosts=$(printf '%s' "$contract" | sed -n 's/^HOSTS=//p')
      c_vals=$(printf '%s' "$contract" | sed -n 's/^VALUES=//p')
      c_spaces=$(printf '%s' "$contract" | sed -n 's/^SPACES=//p')
      check "A5  attack source pairs occur in the floor" "$(trim "$c_pairs")" "" \
        "a (loggen.source.type, loggen.source.name) pair the intrusion uses never occurs in ordinary traffic, so one terms aggregation selects the attack. The compiler is supposed to draw the attack's sources ONLY from the floor's own pairs; a leak here means the two were compiled from different scenarios, or the floor swap did not land."
      check "A5  attack hosts occur in the floor" "$(trim "$c_hosts")" "" \
        "the intrusion names a machine the benign floor never mentions. This is the same one-click oracle in its most obvious form and it is the reason the floor is compiled from the client's assets at all."
      check "A6  no attack-only metadata value" "$(trim "$c_vals")" "" \
        "a closed-vocabulary metadata field separates attack from benign. Every one of the fourteen metadata fields is mapped as an explicit keyword, so it sits in Discover's field list with a top-values popover: one value that only the attack uses is 100% precision and 100% recall, all semester."
      check "A7  no attack-only address space" "$(trim "$c_spaces")" "" \
        "the intrusion comes from a /8 ordinary traffic never uses, so 'NOT loggen.metadata.src_ip:10.*' is a perfect filter. Worse than the filter is the habit: a student who learns 'the intruder is the unfamiliar address' has learned something that fails on every intrusion that matters."
    else
      skip "A5-A7 anti-oracle subset checks" "could not expand the two playbooks on the sensor: ${contract:-no output}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# D. DATABASE — the run row, the target rows, the score rows
# ---------------------------------------------------------------------------
section "D. Database"

if [ "$DB_OK" != "1" ]; then
  manual "run this SQL against cybercore_db yourself (psql or CYBERCORE_DB_PASSWORD was unavailable):
          SELECT run_id, engine, mode, status, jsonb_array_length(answer_key->'techniques') AS key_techniques,
                 answer_key->'totals'->>'events' AS key_events
            FROM cybercore_incident_run WHERE run_id = '${RUN_ID:-<run>}';
          SELECT lane_id, status, event_count, exit_code, clock_skew_s, late
            FROM cybercore_incident_target WHERE run_id = '${RUN_ID:-<run>}';
          SELECT user_id, techniques_total, techniques_found, auto_points, override_points, final_points, released
            FROM cybercore_incident_score WHERE run_id = '${RUN_ID:-<run>}';" \
    "one run row engine=synthetic mode=scenario status=completed; two target rows both 'completed' with EQUAL event_count; score rows whose techniques_total equals the answer key's technique count."
elif [ -z "$RUN_ID" ]; then
  skip "database run checks" "no run id"
else
  r_engine=$(trim "$(sql "SELECT engine FROM cybercore_incident_run WHERE run_id = '$RUN_ID'")")
  r_mode=$(trim "$(sql "SELECT mode FROM cybercore_incident_run WHERE run_id = '$RUN_ID'")")
  r_status=$(trim "$(sql "SELECT status FROM cybercore_incident_run WHERE run_id = '$RUN_ID'")")
  check "D  run.engine" "$r_engine" "synthetic" \
    "the gate is for the synthetic engine. A 'caldera' row here means E9 shipped before E8 passed, which the plan explicitly forbids."
  check "D  run.mode" "$r_mode" "scenario" \
    "the gate must exercise the profile-derived path. A technique or chain run proves the dispatcher works and proves nothing about the compiler, the floor swap or the answer key."
  check "D  run.status" "$r_status" "completed" \
    "'partial' means at least one lane never reached a terminal state; 'failed' or 'aborted' means the run did not finish. Read cybercore_incident_target.error and .exit_code per lane. A run stuck in 'scheduling' or 'dispatching' also HOLDS THE ENGAGEMENT'S DISPATCH MUTEX (the unique index is partial on exactly those two statuses), so nothing else can be launched until it is swept."

  t_total=$(trim "$(sql "SELECT count(*) FROM cybercore_incident_target WHERE run_id = '$RUN_ID'")")
  t_done=$(trim "$(sql "SELECT count(*) FROM cybercore_incident_target WHERE run_id = '$RUN_ID' AND status = 'completed'")")
  check "D  every target reached 'completed'" "$t_done" "$t_total" \
    "a target left in 'dispatching', 'running' or 'unknown' is a student with no incident in their lane and a board that will grade them against one. The sweeper indexes exactly those statuses; if they persist, the worker is not running."

  t_counts=$(sql "SELECT DISTINCT event_count FROM cybercore_incident_target WHERE run_id = '$RUN_ID' AND status = 'completed'" | grep . | tr '\n' ' ')
  t_distinct=$(printf '%s' "$t_counts" | wc -w | tr -d ' ')
  check "D  all targets emitted the same event_count" "$t_distinct" "1" \
    "the same run id seeds the same attack on every lane — that determinism is what lets one answer key grade every student. Different counts mean one lane ran a different playbook, ran short, or hit the timeout cap, and the two students are being graded against different realities. Values seen: $t_counts"

  if [ -n "$key_events" ] && [ "$t_distinct" = "1" ]; then
    check "D  target.event_count == answer_key.totals.events" "$(trim "$t_counts")" "$key_events" \
      "the guest emitted a different number of events from the one the key was compiled for. See A4 above — this is the same failure seen from the database side."
  fi

  skewed=$(trim "$(sql "SELECT count(*) FROM cybercore_incident_target WHERE run_id = '$RUN_ID' AND clock_skew_s IS NOT NULL AND abs(clock_skew_s) > 120")")
  check "D  no target reports >120s clock skew" "$skewed" "0" \
    "the guest clocks disagree with the orchestrator. Live emission is still correct (cc-emit sleeps to each offset against a monotonic base), but any DETECTION RULE with a lookback window finds nothing on a skewed clone and looks broken — risk noted in E3b. Proxmox only syncs guest RTC on resume, so confirm NTP/chrony works through the lane gateway before blaming the rules."

  late=$(trim "$(sql "SELECT count(*) FROM cybercore_incident_target WHERE run_id = '$RUN_ID' AND late = TRUE")")
  if [ "$late" = "0" ]; then
    printf 'PASS  %-46s 0\n' "D  no target was dispatched late"
    PASS=$((PASS + 1))
  else
    skip "D  no target was dispatched late" "$late target(s) flagged late — not a gate failure, but the run started after its scheduled window on those lanes and TTD is measured from the SCHEDULED start"
  fi

  s_rows=$(trim "$(sql "SELECT count(*) FROM cybercore_incident_score WHERE run_id = '$RUN_ID'")")
  if [ "$s_rows" = "0" ]; then
    skip "D  score rows" "no score rows yet — the scorer runs on POST /:runId/score, or when the instructor releases. Run the gate again after scoring."
  else
    if [ -n "$key_techs" ]; then
      kn=$(printf '%s' "$key_techs" | tr ' ' '\n' | grep -c . | tr -d ' ')
      st=$(trim "$(sql "SELECT DISTINCT techniques_total FROM cybercore_incident_score WHERE run_id = '$RUN_ID'")")
      check "D  score.techniques_total == |answer_key.techniques|" "$(trim "$st")" "$kn" \
        "the scorer is grading against a different key from the one on the run row. Since the key is compiled in the same statement as the run INSERT and never recompiled, a mismatch means something rewrote it."
    fi
    ov=$(trim "$(sql "SELECT count(*) FROM cybercore_incident_score WHERE run_id = '$RUN_ID' AND override_points IS NOT NULL AND final_points IS DISTINCT FROM auto_points")")
    printf 'INFO  %s score row(s), %s carrying an instructor override that moved final_points\n' "$s_rows" "$ov"
  fi
fi

# ---------------------------------------------------------------------------
# H. HOST TELEMETRY — assertions 9 to 12, only once E3b/E3c have landed
# ---------------------------------------------------------------------------
if [ "$HOST_TELEMETRY" = "1" ]; then
  section "H. Real host telemetry (E3b/E3c)"

  win_total=$(es POST "/logs-*,winlogbeat-*/_count" '{"query":{"exists":{"field":"winlog.event_id"}}}' 2>/dev/null | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
  if [ -n "$win_total" ] && [ "$win_total" -gt 0 ] 2>/dev/null; then
    printf 'PASS  %-46s %s documents\n' "A9  winlog.event_id documents exist" "$win_total"
    PASS=$((PASS + 1))
    manual "In Discover, run  _exists_: winlog.event_id  over a window spanning BOTH the pre-run hour and the run itself." \
      "documents from both periods. If it returns only run-window documents, the synthetic floor is still claiming source.type:host on Windows hostnames and _exists_:winlog.event_id separates real from synthetic in one click — risk 5b. The compiler must cede host telemetry when hostTelemetry is set."
  else
    check_true "A9  winlog.event_id documents exist" 0 \
      "--host-telemetry was passed but no Windows host telemetry has arrived. Either winlogbeat is not running on the domain machines, or it is pointed at an address rather than $ELK_HOST, or the version pins collided (GOAD ships 7.x / winlogbeat 7.17.6 and the loggen sensor's agent cannot ship to a 7.x Elasticsearch; 8.19 is the common floor)."
  fi

  agg_hn=$(es POST "/logs-*,winlogbeat-*/_search" '{"size":0,"aggs":{"h":{"terms":{"field":"host.name","size":50}}}}' 2>/dev/null)
  hn=$(printf '%s' "$agg_hn" | tr ',' '\n' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ')
  if [ -n "$(trim "$hn")" ]; then
    printf 'PASS  %-46s %s\n' "A10 host.name terms returns Windows hosts" "$hn"
    PASS=$((PASS + 1))
    manual "Compare that host list against the lane's actual Windows machines (qm list on this node)." \
      "every Windows machine in the lane present, each with pre-run benign volume. A machine missing from the list is a dark box in the middle of a hunting exercise — worse than not having it at all."
  else
    check_true "A10 host.name terms returns Windows hosts" 0 \
      "no host.name buckets. Sysmon/winlogbeat are not reporting, or host.name is unmapped in this index pattern."
  fi

  rules=$(es GET "/_cat/indices/.alerts-security*?h=index,docs.count" 2>/dev/null)
  if [ -n "$(trim "$rules")" ]; then
    printf 'PASS  %-46s %s\n' "A11 detection alert indices exist" "$(trim "$rules")"
    PASS=$((PASS + 1))
  else
    skip "A11 detection alert indices exist" "no .alerts-security* index. Either E3c was skipped, or the rules never enabled — with TLS off you MUST also set xpack.security.authc.api_key.enabled: true, because rules run as background tasks that mint API keys."
  fi
  manual "Open Kibana -> Security -> Alerts on the ELK box." \
    "prebuilt rules enabled, at least one alert raised by this run, and at least one benign false positive in the same window. A completely empty Alerts page with rules 'enabled' is almost always clock skew (see the D-section skew check) or an index-pattern mismatch — verify the enabled rules' index patterns actually match where winlogbeat writes."

  sensor_after=$(es POST "/$ES_INDEX/_count" '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}' 2>/dev/null | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
  if [ -n "$sensor_after" ] && [ "$sensor_after" -gt 0 ] 2>/dev/null; then
    printf 'PASS  %-46s %s documents in the last hour\n' "A12 the synthetic stream still arrives" "$sensor_after"
    PASS=$((PASS + 1))
  else
    check_true "A12 the synthetic stream still arrives" 0 \
      "risk 5d, exactly. Turning on xpack.security while the standalone agent still posts unauthenticated to http://$ELK_HOST:$ELK_PORT leaves a HEALTHY agent 401ing forever with no error the console can see. If security is on, the sensor must be re-baked with credentials in the same change."
  fi
fi

# ---------------------------------------------------------------------------
# M. WHAT A MACHINE CANNOT CHECK
# ---------------------------------------------------------------------------
section "M. Manual"

manual "Open the student console for this lane and browse to http://$ELK_HOST:5601. Open Dashboards." \
  "two dashboards: 'CYBR 400 - Log Activity' and 'CYBR 400 - Hunting Workbench', both rendering data. Empty terms panels mean the logs@custom component template was not applied before the first write. NOTE: those titles carry a CLE course code into a CiAB student's screen — cosmetic, but it is a vocabulary leak the CiAB rule forbids everywhere else."

manual "Read every panel on both dashboards." \
  "no panel aggregates loggen.mitre.*, splits on data_stream.dataset, or filters log.file.path. The workbench must look identical on a day with no attack at all. test/bake-payloads.test.js pins this in the shipped ndjson; this check catches a dashboard edited on the box."

manual "Log in to /ciab/workspace as one of the two students BEFORE the instructor releases." \
  "their own submissions only: no verdicts, no points, and NO TECHNIQUE COUNT anywhere on the page. Knowing 'there are six' tells a student when to stop hunting, which is most of the exercise — the release gate is a column for exactly that reason."

manual "Have the instructor override one finding's verdict, then release, then reload the student page." \
  "verdicts and misses appear; final_points reflects the override while auto_points is unchanged, so re-running the scorer is non-destructive."

manual "curl the student endpoint with a STUDENT token and grep the response." \
  "grep -i 'answer_key|technique_id|playbook|scenario_ref|catalog_version' returns nothing. projection.js builds a new object from an 8-key whitelist; a hit here means a route bypassed it."

manual "Tear the environment down, then re-check the WAN lease table." \
  "SELECT * FROM cybercore_lane_wan_lease WHERE lane_id = '$LANE_ID'; returns no live holder, and the 100.100.60.0/22 address this lane held is available again. The allocator only ever climbs, so a lease that is not released is capacity gone for good."

if [ "$STACK" = "both" ]; then
  manual "Check the node's memory headroom against the lane count." \
    "'both' is roughly 25% more RAM per lane than a single stack (about 41 GiB idle against 33). It is a legitimate choice and never a default; confirm the cohort size you deployed actually fits."
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
printf '\n=============================================================\n'
printf ' PASS %s   FAIL %s   MANUAL %s   SKIPPED %s\n' "$PASS" "$FAIL" "$MANUAL" "$SKIPPED"
printf '=============================================================\n'

if [ "$SKIPPED" -gt 0 ]; then
  printf 'NOTE: %s check(s) could not run. A skipped check is not a passed check —\n' "$SKIPPED"
  printf '      supply the missing argument or credential and run again.\n'
fi
if [ "$MANUAL" -gt 0 ]; then
  printf 'NOTE: %s item(s) need a browser. The gate is not passed until they are done.\n' "$MANUAL"
fi

if [ "$FAIL" -ne 0 ]; then
  printf 'GATE FAILED: %s check(s) failed. Do not ship this lane shape.\n' "$FAIL" >&2
  exit 1
fi
printf 'Automated checks all passed.\n'
exit 0
