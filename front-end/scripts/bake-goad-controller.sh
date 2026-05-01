#!/bin/bash
# ============================================================================
# bake-goad-controller.sh
# ----------------------------------------------------------------------------
# Bakes LXC template 1700: the GOAD-Light ansible controller, using upstream
# GOAD's playbooks + roles + lab data verbatim. Each lane clones 1700 and
# runs the upstream playbook chain against the lane's DC01/DC02/SRV02 VMs,
# then stops the controller.
#
# Upstream GOAD is git-cloned directly inside the container at bake time
# (no local copy required). Pin to a specific ref via GOAD_REF env var.
#
# Base: Debian 13 (Trixie). Run on any Proxmox node with internet access.
# Idempotent: refuses if 1700 already exists. To re-bake, destroy first:
#   pct destroy 1700 --purge
# ============================================================================
set -euo pipefail

CTID=1700
HOSTNAME="goad-controller-template"
STORAGE="vmpool"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-cephfs}"   # override with env if templates live elsewhere
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"              # bridge for the bake-time uplink (needs internet)
BAKE_VLAN="${BAKE_VLAN:-20}"                     # VLAN tag on $BAKE_BRIDGE (set empty to disable: BAKE_VLAN= )
GOAD_REPO="${GOAD_REPO:-https://github.com/Orange-Cyberdefense/GOAD.git}"
GOAD_REF="${GOAD_REF:-main}"                      # branch/tag/commit to pin
MEMORY=2048                                       # bumped: upstream playbooks + roles use more RAM
CORES=2

# Build net0 string with optional VLAN tag
NET0="name=eth0,bridge=${BAKE_BRIDGE},ip=dhcp,firewall=0"
if [ -n "${BAKE_VLAN:-}" ]; then
  NET0="${NET0},tag=${BAKE_VLAN}"
fi
echo "==> Bake-time net0: $NET0"

# ---------- 0. Sanity ----------
if pct status $CTID >/dev/null 2>&1; then
  echo "ERROR: CT $CTID already exists. Destroy first: pct destroy $CTID --purge"
  exit 1
fi

echo "==> GOAD source: $GOAD_REPO @ $GOAD_REF (cloned inside the container)"

# Find a Debian 13 LXC template (prefer $TEMPLATE_STORAGE, fall back to local)
find_template() {
  for store in "$TEMPLATE_STORAGE" local; do
    local match
    match=$(pveam list "$store" 2>/dev/null | awk '/debian-13/ {print $1}' | sort -V | tail -1 || true)
    if [ -n "$match" ]; then
      echo "$match"
      return 0
    fi
  done
  return 1
}

LOCAL_TMPL=$(find_template || true)
if [ -z "${LOCAL_TMPL:-}" ]; then
  echo "==> No Debian 13 template found locally — downloading to local..."
  REMOTE=$(pveam available --section system | awk '/debian-13-standard.*amd64/ {print $2}' | sort -V | tail -1)
  if [ -z "$REMOTE" ]; then
    echo "ERROR: No debian-13-standard available from pveam. Check 'pveam update; pveam available'."
    exit 1
  fi
  pveam download local "$REMOTE"
  LOCAL_TMPL="local:vztmpl/${REMOTE}"
fi
echo "==> Using template: $LOCAL_TMPL"

# ---------- 1. Create CT ----------
echo "==> Creating CT $CTID ($HOSTNAME)..."
pct create $CTID "$LOCAL_TMPL" \
  --hostname "$HOSTNAME" \
  --storage "$STORAGE" \
  --rootfs "${STORAGE}:8" \
  --memory $MEMORY \
  --cores $CORES \
  --swap 512 \
  --net0 "$NET0" \
  --features nesting=1 \
  --ostype debian \
  --unprivileged 1 \
  --password "$(openssl rand -hex 16)"

echo "==> Starting CT..."
pct start $CTID
sleep 6

# Wait for network (apt needs internet)
for i in 1 2 3 4 5 6 7 8 9 10; do
  if pct exec $CTID -- /bin/sh -c "getent hosts deb.debian.org >/dev/null 2>&1"; then
    break
  fi
  sleep 2
done

# ---------- 2. OS packages ----------
# Upstream GOAD uses ansible.windows + community.* + chocolatey + scicore.guacamole
# (see GOAD-main/ansible/requirements.yml). We need their full collection set.
echo "==> apt update + install (ansible + Windows + extras for upstream GOAD)..."
pct exec $CTID -- /bin/sh -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ansible \
    python3-winrm \
    python3-requests-kerberos \
    python3-requests-ntlm \
    python3-cryptography \
    python3-yaml \
    python3-jmespath \
    python3-netaddr \
    krb5-user \
    openssh-server openssh-client \
    git curl jq rsync ca-certificates \
    locales unzip
  apt-get clean
  rm -rf /var/lib/apt/lists/*
'

# ---------- 3. Locale (must be set BEFORE ansible runs) ----------
echo "==> Configuring locale..."
pct exec $CTID -- /bin/sh -c '
  set -e
  echo "LANG=C.UTF-8" > /etc/default/locale
  echo "LC_ALL=C.UTF-8" >> /etc/default/locale
  update-locale LANG=C.UTF-8 LC_ALL=C.UTF-8 || true
  grep -q "^LANG=" /etc/environment 2>/dev/null || echo "LANG=C.UTF-8" >> /etc/environment
  grep -q "^LC_ALL=" /etc/environment 2>/dev/null || echo "LC_ALL=C.UTF-8" >> /etc/environment
'

# ---------- 4. Clone upstream GOAD inside the container ----------
echo "==> Cloning upstream GOAD ($GOAD_REPO @ $GOAD_REF) into /opt/goad..."
pct exec $CTID -- /bin/sh -c "
  set -e
  # Belt-and-suspenders: ensure git is present even if the apt step above
  # ever drops it. The first invocation is a no-op if it's already installed.
  if ! command -v git >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y --no-install-recommends git ca-certificates
  fi
  rm -rf /opt/goad
  git clone --depth 1 --branch '$GOAD_REF' '$GOAD_REPO' /opt/goad || \
    git clone '$GOAD_REPO' /opt/goad
  cd /opt/goad
  # If GOAD_REF wasn't a branch (e.g. it's a commit SHA or tag), pin it now
  git rev-parse '$GOAD_REF' >/dev/null 2>&1 && git checkout '$GOAD_REF' || true
  echo 'Cloned commit:'
  git log -1 --oneline
"

# ---------- 5. Install upstream ansible-galaxy collections + roles ----------
echo "==> Installing ansible-galaxy collections from upstream requirements..."
pct exec $CTID -- /bin/sh -c '
  set -e
  export LANG=C.UTF-8 LC_ALL=C.UTF-8
  cd /opt/goad/ansible
  ansible-galaxy install -r requirements.yml
'

# ---------- 6. Services ----------
echo "==> Enabling ssh..."
pct exec $CTID -- /bin/sh -c 'systemctl enable ssh'

echo "==> Generating SSH keypair..."
pct exec $CTID -- /bin/sh -c '
  set -e
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  [ -f /root/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "goad-controller@cyberhub"
'

# ---------- 7. Wrapper: run.sh + render-inventory.sh ----------
# Per-deploy logic: render the inventory with our IPs and Administrator
# credential (the local one we baked into template 1004), copy upstream's
# GOAD-Light data into a writable runtime dir, override the per-host
# local_admin_password in config.json so settings/admin_password is a no-op
# (otherwise upstream rotates it and we lose authentication mid-playbook).
# Then invoke upstream main.yml.
echo "==> Writing /opt/goad-light/run.sh wrapper..."
pct exec $CTID -- mkdir -p /opt/goad-light

pct exec $CTID -- tee /opt/goad-light/run.sh >/dev/null << 'EOF'
#!/bin/bash
# Render per-lab inventory + patch config.json + run upstream playbook chain.
#
# Usage: run.sh LAB HOST_MAP ADMIN_USER ADMIN_PASSWORD
#   LAB         — one of: GOAD-Light, GOAD, GOAD-Mini, NHA, SCCM, DRACARYS
#   HOST_MAP    — comma-separated "vmName:ip" pairs, e.g.
#                 "DC01:192.18.0.10,DC02:192.18.0.11,SRV02:192.18.0.22"
#   ADMIN_USER  — local Administrator user (typically "Administrator")
#   ADMIN_PASSWORD — local admin pwd baked into the Windows template
#
# Mirrors upstream's documented Proxmox flow:
#   ansible-playbook -i ../ad/<LAB>/data/inventory \
#                    -i ../ad/<LAB>/providers/proxmox/inventory \
#                    <playbook>
#
# Per-lab playbook chain comes from upstream's playbooks.yml.
#
# Notes:
#  - Windows VMs MUST use e1000 NICs (admin.js sets this for GOAD VMs).
#    virtio breaks ansible domain join per upstream documentation.
#  - Upstream's domain admin passwords (config.json) are NOT overridden —
#    that's the lab's intended attack surface for students.
#  - local_admin_password IS overridden per-host so settings/admin_password
#    is idempotent (matches the password baked into our Windows templates).
set -e

if [ $# -lt 4 ]; then
  echo "Usage: $0 LAB HOST_MAP ADMIN_USER ADMIN_PASSWORD"
  echo "  LAB         — GOAD-Light | GOAD | GOAD-Mini | NHA | SCCM | DRACARYS"
  echo "  HOST_MAP    — comma-separated 'vmName:ip' pairs"
  echo "  ADMIN_USER  — typically 'Administrator'"
  echo "  ADMIN_PASSWORD — local admin password (matches Windows template)"
  exit 1
fi

LAB="$1"
HOST_MAP="$2"
ADMIN_USER="$3"
ADMIN_PASSWORD="$4"

GOAD_ROOT=/opt/goad
LAB_DATA="$GOAD_ROOT/ad/$LAB/data"
LAB_PROVIDER="$GOAD_ROOT/ad/$LAB/providers/proxmox"
ANSIBLE_DIR="$GOAD_ROOT/ansible"
PLAYBOOKS_YML="$GOAD_ROOT/playbooks.yml"

if [ ! -d "$LAB_DATA" ] || [ ! -d "$LAB_PROVIDER" ]; then
  echo "ERROR: Lab '$LAB' not found at $LAB_DATA / $LAB_PROVIDER"
  echo "Available labs:"
  ls "$GOAD_ROOT/ad/" | grep -v TEMPLATE
  exit 1
fi

# Derive the /24 prefix from the FIRST ip in HOST_MAP
FIRST_IP="$(echo "$HOST_MAP" | awk -F'[:,]' '{print $2}')"
IP_RANGE="$(echo "$FIRST_IP" | awk -F. '{print $1"."$2"."$3}')"
GW_IP="${IP_RANGE}.1"

RUNTIME=/var/lib/goad-run
rm -rf "$RUNTIME"
mkdir -p "$RUNTIME"

# 1. Patched config.json — set local_admin_password to ours for every host
#    in this lab so settings/admin_password is a no-op (idempotent).
python3 - <<PY > "$RUNTIME/config.json"
import json, sys
with open("$LAB_DATA/config.json") as f:
    data = json.load(f)
hosts = data.get("lab", {}).get("hosts", {})
for h in hosts.values():
    if isinstance(h, dict):
        h["local_admin_password"] = "$ADMIN_PASSWORD"
print(json.dumps(data, indent=2))
PY

# 2. Rendered proxmox provider inventory — upstream uses {{ip_range}} as a
#    sed placeholder, not Jinja.
sed -e "s|{{ip_range}}|${IP_RANGE}|g" \
    "$LAB_PROVIDER/inventory" > "$RUNTIME/inventory_proxmox"

# 3. Override layer: our admin creds + reaffirm dns_server. -i merges this
#    on top of data/inventory + provider/inventory.
cat > "$RUNTIME/inventory_overrides" <<OVR
[all:vars]
ansible_user=${ADMIN_USER}
ansible_password=${ADMIN_PASSWORD}
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=400
ansible_winrm_read_timeout_sec=500
ansible_connection=winrm
force_dns_server=yes
dns_server=${GW_IP}
two_adapters=no
OVR

export ANSIBLE_CONFIG=$ANSIBLE_DIR/ansible.cfg
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

cd "$ANSIBLE_DIR"

# 4. Read the per-lab playbook chain from upstream's playbooks.yml.
#    Falls back to the "default" chain if the lab doesn't have its own.
PLAYBOOKS=$(python3 - <<PY
import yaml
with open("$PLAYBOOKS_YML") as f:
    data = yaml.safe_load(f)
chain = data.get("$LAB") or data.get("default") or []
print(" ".join(chain))
PY
)
if [ -z "$PLAYBOOKS" ]; then
  echo "ERROR: no playbook chain found for lab '$LAB' in $PLAYBOOKS_YML"
  exit 1
fi

INV_FLAGS="-i $LAB_DATA/inventory -i $RUNTIME/inventory_proxmox -i $RUNTIME/inventory_overrides"
EXTRA_VARS="domain_name=$LAB data_path=$RUNTIME admin_user=${ADMIN_USER} enable_http_proxy=no"

echo "================================================================="
echo " GOAD provisioning: $LAB"
echo " Lane subnet: ${IP_RANGE}.0/24   Gateway: ${GW_IP}"
echo " Hosts: ${HOST_MAP}"
echo " Playbook chain: ${PLAYBOOKS}"
echo "================================================================="

for pb in $PLAYBOOKS; do
  echo ""
  echo ">>>>>>>>>>>>>>>>>>>>>> $pb <<<<<<<<<<<<<<<<<<<<<<"
  ansible-playbook $INV_FLAGS "$pb" --extra-vars "$EXTRA_VARS"
done

echo "================================================================="
echo " $LAB provisioning complete."
echo "================================================================="
EOF
pct exec $CTID -- chmod +x /opt/goad-light/run.sh

# ---------- 8. README inside the controller ----------
pct exec $CTID -- tee /opt/goad-light/README.md >/dev/null << 'EOF'
# GOAD-Light Controller (upstream-backed)

This LXC clones from template 1700 once per lane. It carries upstream
GOAD's `ansible/` and `ad/GOAD-Light/` directories under /opt/goad/, plus
a thin wrapper at /opt/goad-light/run.sh that renders the per-lane
inventory and runs `main.yml`.

## Layout
- /opt/goad/ansible/        — upstream playbooks + roles (read-only at runtime)
- /opt/goad/ad/GOAD-Light/  — upstream lab data (config.json, data files)
- /opt/goad-light/run.sh    — per-lane wrapper (renders inventory, patches
                              config.json with the local admin password,
                              invokes ansible-playbook main.yml)
- /var/lib/goad-run/        — runtime working dir (recreated each invocation)

## Usage
```
/opt/goad-light/run.sh 192.18.0.10 192.18.0.11 192.18.0.22 Administrator 'YourPass'
```

## Re-bake source of truth
This template is rebuilt from `front-end/scripts/bake-goad-controller.sh`,
which git-clones upstream GOAD at bake time (default
https://github.com/Orange-Cyberdefense/GOAD.git, branch `main`).
Override with `GOAD_REPO=...` and/or `GOAD_REF=<branch|tag|sha>`.
EOF

# ---------- 9. Cleanup + template flag ----------
echo "==> Cleaning caches..."
pct exec $CTID -- /bin/sh -c '
  apt-get clean
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache 2>/dev/null || true
'

echo "==> Stopping CT..."
pct stop $CTID

echo "==> Setting template flag..."
pct set $CTID --template 1

echo ""
echo "==================================================================="
echo "  GOAD controller template $CTID baked (upstream GOAD-Light)"
echo "==================================================================="
echo "  Verify:        pct config $CTID"
echo "  Test clone:    pct clone $CTID 9994 --hostname goad-test --full --storage vmpool"
echo "  Inspect:       pct exec 9994 -- ls /opt/goad/ /opt/goad-light/"
echo "  Sanity:        pct exec 9994 -- bash -c 'cd /opt/goad/ansible && ansible-playbook --syntax-check main.yml'"
echo "  Cleanup test:  pct stop 9994 && pct destroy 9994 --purge"
echo "==================================================================="
