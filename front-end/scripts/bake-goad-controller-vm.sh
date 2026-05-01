#!/bin/bash
# ============================================================================
# bake-goad-controller-vm.sh
# ----------------------------------------------------------------------------
# Bakes QEMU VM template 1700: the GOAD ansible controller, using upstream
# GOAD's playbooks/roles/lab data. Each lane clones this template, gets its
# admin credentials/network injected via Proxmox cloud-init, and runs the
# upstream playbook chain over WinRM against the lane's Windows VMs.
#
# This is the VM version of the controller (was previously an LXC). VMs
# expose the qemu-guest-agent /agent/exec endpoint over the Proxmox HTTPS
# API, so admin.js can drive provisioning without SSH-to-node — same auth
# path as Kali and the Windows lane VMs.
#
# Run on any Proxmox node with internet access. Idempotent: refuses if 1700
# already exists. To re-bake, destroy first:
#   qm destroy 1700 --purge
# (or `pct destroy 1700 --purge` if the old LXC version is still there)
# ============================================================================
set -euo pipefail

VMID=1700
NAME="goad-controller-template"
STORAGE="vmpool"                                  # where the VM disk + cloudinit drive live
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"            # auto-detected if empty; override to force a specific storage
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"                      # bake-time VLAN for internet (set empty to disable)
GOAD_REPO="${GOAD_REPO:-https://github.com/Orange-Cyberdefense/GOAD.git}"
GOAD_REF="${GOAD_REF:-main}"
MEMORY=2048
CORES=2
DISK_GB=10
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-genericcloud-amd64.qcow2"

# A throwaway password baked into the template's default user. Per-clone,
# admin.js can override via cloud-init `cipassword`. Mostly we don't log in
# to this VM at all — qemu-guest-agent does the work.
TEMPLATE_PASSWORD="$(openssl rand -base64 24)"

# ---------- 0. Sanity ----------
if qm status $VMID >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge"
  exit 1
fi
if pct status $VMID >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists (likely the old LXC controller template)."
  echo "       Destroy first: pct destroy $VMID --purge"
  exit 1
fi

# ---------- Pick a storage with 'snippets' content enabled ----------
# Cloud-init custom user-data has to live on a storage with content=snippets.
# Default Proxmox storages don't have it on. We auto-detect; if none has it,
# enable on `local` (the safe default that always exists).
pick_snippet_storage() {
  # User override always wins
  if [ -n "${SNIPPET_STORAGE:-}" ]; then
    if pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SNIPPET_STORAGE"; then
      echo "$SNIPPET_STORAGE"; return 0
    fi
    echo "ERROR: SNIPPET_STORAGE='$SNIPPET_STORAGE' set but that storage doesn't have 'snippets' content enabled." >&2
    echo "       Run: pvesm set $SNIPPET_STORAGE --content <existing>,snippets" >&2
    return 1
  fi

  # Otherwise: pick the first storage advertising snippets
  local first
  first=$(pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then
    echo "$first"; return 0
  fi

  # No storage has snippets enabled — turn it on for `local`.
  echo "==> No storage has 'snippets' content enabled. Enabling on 'local'..." >&2
  local cur
  cur=$(awk '/^[a-z]+: local$/{flag=1} flag && /^\s*content/{print $2; flag=0}' /etc/pve/storage.cfg)
  if [ -z "$cur" ]; then cur="iso,vztmpl,backup"; fi
  if [[ "$cur" != *snippets* ]]; then
    pvesm set local --content "${cur},snippets" >&2
  fi
  echo "local"
}

SNIPPET_STORAGE=$(pick_snippet_storage)
echo "==> Snippet storage: $SNIPPET_STORAGE"

# ---------- Generate the controller<->gateway SSH keypair ----------
# This keypair is the trust link used by run.sh inside the controller to
# talk to the lane's gateway (192.18.0.1) and write DHCP reservations.
# The private key is baked into the controller template; the public key
# must be added to the gateway template's /root/.ssh/authorized_keys.
# Persist the keypair on this Proxmox node so re-runs are consistent.
DEPLOY_KEY_DIR=/root/.ssh
DEPLOY_KEY_PATH="$DEPLOY_KEY_DIR/goad-controller-deploy.key"
mkdir -p "$DEPLOY_KEY_DIR"
chmod 700 "$DEPLOY_KEY_DIR"
if [ ! -f "$DEPLOY_KEY_PATH" ]; then
  echo "==> Generating GOAD controller→gateway SSH keypair at $DEPLOY_KEY_PATH..."
  ssh-keygen -t ed25519 -N "" -f "$DEPLOY_KEY_PATH" -C "goad-controller-deploy" >/dev/null
fi
chmod 600 "$DEPLOY_KEY_PATH"
DEPLOY_PRIVKEY="$(cat "$DEPLOY_KEY_PATH")"
DEPLOY_PUBKEY="$(cat "${DEPLOY_KEY_PATH}.pub")"
echo "==> Using SSH keypair: $DEPLOY_KEY_PATH (public: ${DEPLOY_PUBKEY:0:50}...)"
echo "==> GOAD source: $GOAD_REPO @ $GOAD_REF"
echo "==> Bake-time NIC: bridge=$BAKE_BRIDGE${BAKE_VLAN:+ vlan=$BAKE_VLAN}"

# ---------- 1. Download cloud image (cached) ----------
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  echo "==> Downloading Debian 13 genericcloud qcow2..."
  mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
  wget --progress=dot:giga -O "$CLOUD_IMG_LOCAL.tmp" "$CLOUD_IMG_URL"
  mv "$CLOUD_IMG_LOCAL.tmp" "$CLOUD_IMG_LOCAL"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL ($(du -h "$CLOUD_IMG_LOCAL" | cut -f1))"

# ---------- 2. Build cloud-init user-data snippet ----------
# Cloud-init runs this on first boot inside the VM: install packages, clone
# upstream GOAD, install ansible-galaxy collections, write our run.sh, then
# power off. The bake script waits for the power-off and converts to template.
# `pvesm path <storage>:snippets/<file>` returns the host filesystem path
# even for files that don't exist yet, which is what we need to write to.
USERDATA_FILE="goad-controller-bake-${VMID}.yml"
USERDATA_PATH="$(pvesm path "${SNIPPET_STORAGE}:snippets/${USERDATA_FILE}" 2>/dev/null)"
if [ -z "$USERDATA_PATH" ]; then
  # Fallback for storages where pvesm path doesn't synthesize for missing files
  case "$SNIPPET_STORAGE" in
    local)   USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
    cephfs)  USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
    *)       USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  esac
fi
mkdir -p "$(dirname "$USERDATA_PATH")"

cat > "$USERDATA_PATH" << SNIPPET
#cloud-config
hostname: $NAME
manage_etc_hosts: true

# qemu-guest-agent ships in the genericcloud image but isn't enabled by default.
package_update: true
packages:
  - ansible
  - python3-winrm
  - python3-requests-kerberos
  - python3-requests-ntlm
  - python3-cryptography
  - python3-yaml
  - python3-jmespath
  - python3-netaddr
  - krb5-user
  - openssh-server
  - git
  - curl
  - jq
  - rsync
  - locales
  - qemu-guest-agent

# Default locale (matches the LXC version — ansible refuses to start without UTF-8)
locale: C.UTF-8

write_files:
  - path: /etc/profile.d/locale.sh
    permissions: '0755'
    content: |
      export LANG=C.UTF-8
      export LC_ALL=C.UTF-8
      export PYTHONUTF8=1

  - path: /etc/environment
    append: true
    content: |
      LANG=C.UTF-8
      LC_ALL=C.UTF-8

  # SSH private key for the controller→gateway link. Used by run.sh to
  # write DHCP reservations on the lane gateway (192.18.0.1) without the
  # orchestrator needing any SSH access. The corresponding public key
  # must be in the gateway template's /root/.ssh/authorized_keys (added
  # by scripts/patch-goad-gateway-key.sh).
  - path: /root/.ssh/id_ed25519
    permissions: '0600'
    content: |
$(echo "$DEPLOY_PRIVKEY" | sed 's/^/      /')

  - path: /root/.ssh/id_ed25519.pub
    permissions: '0644'
    content: |
      $DEPLOY_PUBKEY

  - path: /opt/goad-light/run.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # 1) SSH to lane gateway, write DHCP reservations + reload dnsmasq.
      # 2) Render per-lab config.json + inventory.
      # 3) Run upstream playbook chain over WinRM.
      #
      # Usage: run.sh LAB HOST_MAP ADMIN_USER ADMIN_PASSWORD
      #   HOST_MAP = "name|ip|mac,name|ip|mac,..." (pipe-separated triples)
      set -e
      if [ \$# -lt 4 ]; then
        echo "Usage: \$0 LAB HOST_MAP ADMIN_USER ADMIN_PASSWORD"
        echo "  LAB         — GOAD-Light | GOAD | GOAD-Mini | NHA | SCCM | DRACARYS"
        echo "  HOST_MAP    — comma-separated 'name|ip|mac' triples"
        echo "  ADMIN_USER  — typically 'Administrator'"
        echo "  ADMIN_PASSWORD — local admin password (matches Windows template)"
        exit 1
      fi
      LAB="\$1"; HOST_MAP="\$2"; ADMIN_USER="\$3"; ADMIN_PASSWORD="\$4"

      GOAD_ROOT=/opt/goad
      LAB_DATA="\$GOAD_ROOT/ad/\$LAB/data"
      LAB_PROVIDER="\$GOAD_ROOT/ad/\$LAB/providers/proxmox"
      ANSIBLE_DIR="\$GOAD_ROOT/ansible"
      PLAYBOOKS_YML="\$GOAD_ROOT/playbooks.yml"

      if [ ! -d "\$LAB_DATA" ] || [ ! -d "\$LAB_PROVIDER" ]; then
        echo "ERROR: Lab '\$LAB' not found at \$LAB_DATA / \$LAB_PROVIDER"
        ls "\$GOAD_ROOT/ad/" | grep -v TEMPLATE
        exit 1
      fi

      FIRST="\$(echo "\$HOST_MAP" | cut -d',' -f1)"
      FIRST_IP="\$(echo "\$FIRST" | cut -d'|' -f2)"
      IP_RANGE="\$(echo "\$FIRST_IP" | awk -F. '{print \$1"."\$2"."\$3}')"
      GW_IP="\${IP_RANGE}.1"

      RUNTIME=/var/lib/goad-run
      rm -rf "\$RUNTIME"
      mkdir -p "\$RUNTIME"

      # ---- Step 1: write DHCP reservations on the gateway via SSH ----
      echo "[run.sh] Writing DHCP reservations to gateway \${GW_IP}..."
      SSH_OPTS="-i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/root/.ssh/known_hosts -o ConnectTimeout=15 -o BatchMode=yes"
      RESV_FILE="\$RUNTIME/lane-reservations.conf"
      {
        echo "# GOAD lane DHCP reservations — written by /opt/goad-light/run.sh"
        echo "\$HOST_MAP" | tr ',' '\n' | while IFS='|' read -r hname hip hmac; do
          [ -z "\$hname" ] && continue
          echo "dhcp-host=\$hmac,\$hip,\$hname"
        done
      } > "\$RESV_FILE"
      cat "\$RESV_FILE"
      # Push the file and reload dnsmasq on the gateway. Try gateway service
      # managers in order (openrc on Alpine, systemd otherwise).
      ssh \$SSH_OPTS root@\$GW_IP "cat > /etc/dnsmasq.d/lane-reservations.conf && (rc-service dnsmasq restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true)" < "\$RESV_FILE"
      echo "[run.sh] Reservations applied."

      # Patched config.json — set local_admin_password to ours for every host
      python3 - <<PY > "\$RUNTIME/config.json"
      import json
      with open("\$LAB_DATA/config.json") as f:
          data = json.load(f)
      hosts = data.get("lab", {}).get("hosts", {})
      for h in hosts.values():
          if isinstance(h, dict):
              h["local_admin_password"] = "\$ADMIN_PASSWORD"
      print(json.dumps(data, indent=2))
      PY

      # Render proxmox provider inventory ({{ip_range}} is a sed placeholder)
      sed -e "s|{{ip_range}}|\${IP_RANGE}|g" "\$LAB_PROVIDER/inventory" > "\$RUNTIME/inventory_proxmox"

      # Override layer with our admin creds + dns_server
      cat > "\$RUNTIME/inventory_overrides" <<OVR
      [all:vars]
      ansible_user=\${ADMIN_USER}
      ansible_password=\${ADMIN_PASSWORD}
      ansible_winrm_transport=ntlm
      ansible_winrm_server_cert_validation=ignore
      ansible_winrm_operation_timeout_sec=400
      ansible_winrm_read_timeout_sec=500
      ansible_connection=winrm
      force_dns_server=yes
      dns_server=\${GW_IP}
      two_adapters=no
      OVR

      export ANSIBLE_CONFIG=\$ANSIBLE_DIR/ansible.cfg
      export LANG=C.UTF-8
      export LC_ALL=C.UTF-8
      cd "\$ANSIBLE_DIR"

      # Read the per-lab playbook chain from upstream's playbooks.yml
      PLAYBOOKS=\$(python3 - <<PY
      import yaml
      with open("\$PLAYBOOKS_YML") as f:
          data = yaml.safe_load(f)
      chain = data.get("\$LAB") or data.get("default") or []
      print(" ".join(chain))
      PY
      )
      if [ -z "\$PLAYBOOKS" ]; then
        echo "ERROR: no playbook chain found for lab '\$LAB' in \$PLAYBOOKS_YML"
        exit 1
      fi

      INV_FLAGS="-i \$LAB_DATA/inventory -i \$RUNTIME/inventory_proxmox -i \$RUNTIME/inventory_overrides"
      EXTRA_VARS="domain_name=\$LAB data_path=\$RUNTIME admin_user=\${ADMIN_USER} enable_http_proxy=no"

      echo "================================================================="
      echo " GOAD provisioning: \$LAB"
      echo " Lane subnet: \${IP_RANGE}.0/24   Gateway: \${GW_IP}"
      echo " Hosts: \${HOST_MAP}"
      echo " Playbook chain: \${PLAYBOOKS}"
      echo "================================================================="

      for pb in \$PLAYBOOKS; do
        echo ""
        echo ">>>>>>>>>>>>>>>>>>>>>> \$pb <<<<<<<<<<<<<<<<<<<<<<"
        ansible-playbook \$INV_FLAGS "\$pb" --extra-vars "\$EXTRA_VARS"
      done

      echo "================================================================="
      echo " \$LAB provisioning complete."
      echo "================================================================="

  - path: /opt/goad-light/README.md
    content: |
      # GOAD Controller (VM, upstream-backed)
      Per-lane VM cloned from template $VMID. Carries upstream GOAD's
      ansible/ + ad/ at /opt/goad/. Run with /opt/goad-light/run.sh.
      Source of truth: front-end/scripts/bake-goad-controller-vm.sh
      Re-bake to update.

runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ update-locale, LANG=C.UTF-8, LC_ALL=C.UTF-8 ]
  - [ git, clone, --depth, '1', --branch, '$GOAD_REF', '$GOAD_REPO', /opt/goad ]
  - bash -c 'cd /opt/goad/ansible && export LANG=C.UTF-8 LC_ALL=C.UTF-8 && ansible-galaxy install -r requirements.yml'
  - bash -c 'cd /opt/goad && git log -1 --oneline > /opt/goad-light/upstream-commit.txt'
  - [ apt-get, clean ]
  - bash -c 'rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache 2>/dev/null || true'
  - [ touch, /var/lib/cloud/instance/bake-complete ]

# When cloud-init finishes, power off so the bake script can convert
# the VM to a template. The instance ID changes on clone, so this
# user-data won't re-run on per-lane clones.
power_state:
  mode: poweroff
  delay: '+1'
  message: 'GOAD bake complete'
  timeout: 900
SNIPPET

echo "==> Wrote bake-time cloud-init snippet: $USERDATA_PATH"

# ---------- 3. Create VM ----------
echo "==> Creating VM $VMID ($NAME)..."

# Bake-time NIC: virtio + optional VLAN tag
NET0="virtio,bridge=${BAKE_BRIDGE},firewall=0"
[ -n "${BAKE_VLAN:-}" ] && NET0="${NET0},tag=${BAKE_VLAN}"

qm create $VMID \
  --name "$NAME" \
  --memory $MEMORY \
  --cores $CORES \
  --cpu host \
  --machine q35 \
  --bios ovmf \
  --efidisk0 "${STORAGE}:0,efitype=4m,pre-enrolled-keys=1" \
  --scsihw virtio-scsi-pci \
  --net0 "$NET0" \
  --serial0 socket --vga serial0 \
  --agent enabled=1,fstrim_cloned_disks=1 \
  --ostype l26 \
  --description "GOAD controller (VM). Baked from front-end/scripts/bake-goad-controller-vm.sh."

# Import the cloud image disk
echo "==> Importing cloud image as VM disk..."
qm disk import $VMID "$CLOUD_IMG_LOCAL" "$STORAGE"
qm set $VMID --scsi0 "${STORAGE}:vm-${VMID}-disk-1,discard=on,ssd=1"
qm set $VMID --boot order=scsi0

# Resize to target disk size (cloud image ships ~3GB)
echo "==> Resizing disk to ${DISK_GB}G..."
qm resize $VMID scsi0 ${DISK_GB}G || true   # idempotent: skip if already at size

# Cloud-init drive
echo "==> Adding cloud-init drive..."
qm set $VMID --ide2 "${STORAGE}:cloudinit"

# Bake-time cloud-init: default user, our snippet for the bake-only setup
qm set $VMID \
  --ciuser root \
  --cipassword "$TEMPLATE_PASSWORD" \
  --ipconfig0 ip=dhcp \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/$(basename "$USERDATA_PATH")"

# ---------- 4. Boot, wait for cloud-init to finish ----------
echo "==> Starting VM (cloud-init will install everything; this takes ~5–10 min)..."
qm start $VMID

echo "==> Waiting for cloud-init to complete and VM to power off..."
DEADLINE=$(( $(date +%s) + 1500 ))   # 25 min ceiling
while true; do
  STATUS=$(qm status $VMID | awk '{print $2}')
  if [ "$STATUS" = "stopped" ]; then
    echo "==> VM powered off (cloud-init done)."
    break
  fi
  if [ $(date +%s) -ge $DEADLINE ]; then
    echo "ERROR: cloud-init did not finish in 25 minutes. Check console:"
    echo "       qm terminal $VMID  (then ^O to exit)"
    exit 1
  fi
  sleep 10
done

# ---------- 5. Strip the bake-time cloud-init custom config ----------
# Per-lane clones will get their OWN cloud-init config from admin.js
# (hostname, ssh key, etc.). The bake snippet should not apply to them.
echo "==> Clearing bake-time cicustom (clones get fresh cloud-init from admin.js)..."
qm set $VMID --delete cicustom
# Regenerate the cloud-init drive so it's empty for the template
qm cloudinit dump $VMID user 2>/dev/null > /dev/null || true

# Optionally remove the snippet file — keep for re-bake debugging
# rm -f "$USERDATA_PATH"

# ---------- 6. Convert to template ----------
echo "==> Converting VM to template..."
qm template $VMID

echo ""
echo "==================================================================="
echo "  GOAD controller VM template $VMID baked successfully"
echo "==================================================================="
echo "  Verify:        qm config $VMID"
echo "  Test clone:    qm clone $VMID 9994 --name goad-test --full --storage $STORAGE"
echo "  Then start:    qm set 9994 --net0 virtio,bridge=$BAKE_BRIDGE,tag=$BAKE_VLAN"
echo "                 qm start 9994 && sleep 60"
echo "  Inspect:       qm guest exec 9994 -- /bin/sh -c 'ls /opt/goad /opt/goad-light'"
echo "  Sanity:        qm guest exec 9994 -- /bin/sh -c 'cat /opt/goad-light/upstream-commit.txt'"
echo "  Cleanup test:  qm stop 9994 && qm destroy 9994 --purge"
echo "==================================================================="
