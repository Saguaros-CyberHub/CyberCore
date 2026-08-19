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

VMID=${VMID:-1006}
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

# The in-lane ELK box. Resolvable identically in EVERY lane because the lane
# gateway's dnsmasq runs with `domain=cybercore.lan` + `expand-hosts`, so a DHCP
# client's advertised hostname becomes a name — see
# sdn-templates/bake-lane-gateway-v3.sh. That is what lets this config be baked
# once instead of templated per lane. The Windows ELK box MUST have its computer
# name set to match ELK_HOST's first label.
ELK_HOST="${ELK_HOST:-elk.cybercore.lan}"
ELK_PORT="${ELK_PORT:-9200}"
ELK_USER="${ELK_USER:-elastic}"
ELK_PASS="${ELK_PASS:-changeme}"
# Self-signed is the norm for a lab stack. Set to 'full' if you bake a real CA.
ELK_SSL_VERIFY="${ELK_SSL_VERIFY:-none}"
ELASTIC_VERSION="${ELASTIC_VERSION:-8.15.3}"

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
echo "    ELK target    : ${ELK_HOST}:${ELK_PORT} (ssl verification: ${ELK_SSL_VERIFY})"

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
      outputs:
        default:
          type: elasticsearch
          hosts: ["https://${ELK_HOST}:${ELK_PORT}"]
          username: "${ELK_USER}"
          password: "${ELK_PASS}"
          ssl.verification_mode: ${ELK_SSL_VERIFY}
      inputs:
        # BOTH trees. Shipping only the baseline path is the single easiest way
        # to make this whole feature look broken: attacks would run correctly
        # and never appear in Kibana.
        - type: filestream
          id: loggen-baseline
          data_stream.dataset: loggen.baseline
          paths:
            - /opt/log-generator/logs/current/*.json
        - type: filestream
          id: loggen-attack
          data_stream.dataset: loggen.attack
          paths:
            - /opt/log-generator-attack/logs/current/*.json
      agent.logging.level: info
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
  #      different revision. ----
  - [ sh, -c, 'cp -a /opt/log-generator /opt/log-generator-attack' ]
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
    BAKE_ENV=$(printf '%s' "$OUT" | sed -n 's/.*"out-data" : "\(.*\)"/\1/p')
    # qm guest exec returns JSON; fall back to the raw text if the shape differs
    [ -z "$BAKE_ENV" ] && BAKE_ENV="$OUT"
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

 1. REGISTER IT IN THE CATALOG, tagged 'loggen'.

    The Attack Console's target resolver looks for
        WHERE 'loggen' = ANY(role_hints) AND is_active
    and that tag is what makes it identify the sensor deterministically
    instead of falling back to elimination. Add the row through
    Admin -> Workstation Templates (POST /api/admin/vm-templates), with:

        os_family      linux
        os_name        Rocky Linux (CYBR 400 sensor)
        template_vmid  $VMID
        template_key   cybr400-loggen-template
        template_type  os_template
        role_hints     {loggen}

    Then run POST /api/admin/vm-templates/sync-nodes so 'node' is filled in.
    Do NOT add a seed migration for this: front-end/migrations/ has no
    runner, so a file there would never execute.

 2. POINT THE CYBR 400 CHALLENGE SPEC AT IT.
    Set the Rocky machine's template_vmid to $VMID, then redeploy ONE lane
    and confirm the console resolves it (resolved_by should read 'template').

 3. NAME THE WINDOWS ELK BOX 'elk'.
    The agent config baked in here targets ${ELK_HOST}. That resolves in every
    lane only because the gateway's dnsmasq runs expand-hosts with
    domain=cybercore.lan, and it indexes the name the box advertises in DHCP —
    i.e. its Windows computer name. Set it on that template via sysprep /
    cloudbase-init, not per deploy.

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
