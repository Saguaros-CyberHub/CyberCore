#!/bin/bash
# ============================================================================
# bake-web-template.sh
# ----------------------------------------------------------------------------
# Bakes QEMU VM template 1005: Debian 13 + Docker + Apache + PHP + SQLite,
# QEMU guest agent enabled. This is the canonical "web-01" template — the
# CIAB profile deploy pipeline clones this every time it needs a Linux web
# server (any asset whose hostname matches /web\d*/ — see ciab/utils/
# profile-to-spec.js::isWebServer).
#
# Why pre-install Docker + Apache + PHP?
#   The CIAB vuln-app generator emits one of three install_script flavors:
#     - 'docker'        → curl get-docker.sh; docker build; docker run
#     - 'apache_vhost'  → apt install apache2 php …; cp files /var/www/html
#     - 'standalone_vm' → only used when there's NO web server (shouldn't
#                         happen now that the synthesizer always prefers
#                         the matched web-01 over creating a redundant VM)
#   Preinstalling means each lane deploy spends ~30s configuring + starting,
#   not 5+ minutes downloading packages. Lane time-to-active drops a lot.
#
# Why Debian 13 not Rocky?
#   The CIAB vuln-app install_script and fallback recipe both use apt-get,
#   not dnf. Standardizing on Debian keeps the orchestrator simple. (The
#   vm_template_catalog row originally said Rocky — see "Catalog update"
#   note at the bottom of this script's output.)
#
# Companion to:
#   - bake-juice-shop-template.sh   (sibling attached-module pattern)
#   - bake-dvwa-template.sh         (sibling, sames base image)
#
# Run on a Proxmox node with internet access. Idempotent: refuses if VMID
# already exists. To re-bake: qm destroy 1005 --purge
# ============================================================================
set -euo pipefail

VMID=${VMID:-1005}
NAME=${NAME:-web-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
MEMORY=${MEMORY:-2048}
CORES=${CORES:-2}
DISK_GB=${DISK_GB:-12}

# Debian 13 (trixie) generic-cloud qcow2. Pin a release tag for reproducible
# bakes; override CLOUD_IMG_URL to track a different snapshot.
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2}"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-generic-amd64.qcow2"

TEMPLATE_USER="${TEMPLATE_USER:-web}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-bake-debug}"

# ---------- 0. Sanity ----------
if qm status $VMID >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status $VMID >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
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
echo "==> Snippet storage: $SNIPPET_STORAGE"
echo "==> Bake-time NIC: bridge=$BAKE_BRIDGE${BAKE_VLAN:+ vlan=$BAKE_VLAN}"

# ---------- 1. Download cloud image (cached) ----------
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  echo "==> Downloading Debian 13 cloud image (~350MB)..."
  mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
  wget --progress=dot:giga -O "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_URL"
  mv "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_LOCAL"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL ($(du -h "$CLOUD_IMG_LOCAL" | cut -f1))"

# ---------- 2. Build cloud-init user-data ----------
USERDATA_FILE="web-template-bake-${VMID}.yml"
case "$SNIPPET_STORAGE" in
  local)  USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  cephfs) USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
  *)      USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
esac
mkdir -p "$(dirname "$USERDATA_PATH")"

cat > "$USERDATA_PATH" << SNIPPET
#cloud-config
hostname: $NAME
manage_etc_hosts: true

# bake-time DNS only — wiped before seal so clones use DHCP-provided DNS.
bootcmd:
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf; exit 0' ]

users:
  - name: $TEMPLATE_USER
    groups: [sudo, docker, www-data]
    shell: /bin/bash
    sudo: 'ALL=(ALL) NOPASSWD:ALL'
    lock_passwd: false
    plain_text_passwd: $TEMPLATE_PASSWORD

chpasswd:
  list: |
    root:$TEMPLATE_PASSWORD
    $TEMPLATE_USER:$TEMPLATE_PASSWORD
  expire: false
ssh_pwauth: true
disable_root: false

locale: en_US.UTF-8
timezone: America/Phoenix

package_update: true
package_upgrade: false
# Docker-CE comes from Docker's apt repo (registered in runcmd). Everything
# else is base Debian. Apache + PHP + SQLite cover the apache_vhost install
# mode; docker-ce covers the docker mode. Both modes will see all deps already
# present and skip their package install steps, dropping deploy time ~5 min.
packages:
  - qemu-guest-agent
  - openssh-server
  - curl
  - wget
  - vim
  - net-tools
  - ca-certificates
  - resolvconf
  - gnupg
  - sudo
  # apache_vhost install mode prerequisites
  - apache2
  - php
  - libapache2-mod-php
  - php-sqlite3
  - php-mysql
  - php-curl
  - php-xml
  - sqlite3
  - unzip
  - git

write_files:
  - path: /etc/cybercore-bake.env
    permissions: '0644'
    content: |
      BAKE_NAME=$NAME
      BAKE_VMID=$VMID
      BAKE_KIND=web-template
      BAKE_BASE=debian-13

  # Clear qemu-guest-agent's default blacklist. Debian cloud images ship
  # /etc/default/qemu-guest-agent with DAEMON_ARGS that blacklist guest-exec
  # and guest-file-* for security — but the CIAB orchestrator requires both
  # to drop the vuln-app onto web-01 over the agent channel. Without this
  # override, every agentShellExec call returns 596 even though the agent
  # itself is running and ping/network-get-interfaces succeed.
  - path: /etc/default/qemu-guest-agent
    permissions: '0644'
    content: |
      # Cleared by bake-web-template.sh — orchestrator needs guest-exec +
      # guest-file-* RPCs to install the vuln-app on first boot.
      DAEMON_ARGS=""

  # Disable Apache's default vhost so CIAB's install_script can drop its own
  # files into /var/www/html without conflicting. Apache stays enabled but
  # serves an empty document root at boot (a lane that doesn't install a
  # vuln-app will just see "It works!" or a 403).
  - path: /etc/apache2/sites-available/000-default.conf
    permissions: '0644'
    content: |
      <VirtualHost *:80>
          ServerAdmin webmaster@localhost
          DocumentRoot /var/www/html
          ErrorLog \${APACHE_LOG_DIR}/error.log
          CustomLog \${APACHE_LOG_DIR}/access.log combined
          <Directory /var/www/html>
              Options Indexes FollowSymLinks
              AllowOverride All
              Require all granted
          </Directory>
      </VirtualHost>

runcmd:
  # ---- Restore bake-time DNS before any internet ops ----
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf' ]

  # ---- Install Docker via signed-by keyring (Debian 13 dropped apt-key) ----
  - [ sh, -c, 'install -m 0755 -d /etc/apt/keyrings' ]
  - [ sh, -c, 'curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg' ]
  - [ sh, -c, 'chmod a+r /etc/apt/keyrings/docker.gpg' ]
  - [ sh, -c, 'echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable" > /etc/apt/sources.list.d/docker.list' ]
  - [ sh, -c, 'DEBIAN_FRONTEND=noninteractive apt-get update' ]
  - [ sh, -c, 'DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io' ]

  # ---- Enable services so they auto-start on lane boot ----
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ systemctl, enable, docker ]
  - [ systemctl, enable, apache2 ]
  - [ systemctl, start, docker ]
  - [ systemctl, start, apache2 ]

  # ---- Pre-pull common base images so docker-mode vuln-app builds work on
  # lane VMs that have no outbound DNS/internet (the lane subnet is isolated
  # behind the gateway, and apt/registry mirrors aren't reachable). Add more
  # bases here if the LLM commonly emits FROM stanzas using them.
  - [ sh, -c, 'docker pull node:20-alpine    || echo WARN: failed to pre-pull node:20-alpine' ]
  - [ sh, -c, 'docker pull python:3-slim     || echo WARN: failed to pre-pull python:3-slim' ]
  - [ sh, -c, 'docker pull php:8.2-apache    || echo WARN: failed to pre-pull php:8.2-apache' ]
  - [ sh, -c, 'docker pull nginx:alpine      || echo WARN: failed to pre-pull nginx:alpine' ]
  - [ sh, -c, 'docker pull ruby:3-alpine     || echo WARN: failed to pre-pull ruby:3-alpine' ]

  # ---- Make Apache's docroot writable by the cloned-template user too,
  # so install_script can drop files there via guest-agent without sudo ----
  - [ sh, -c, 'mkdir -p /var/www/html && chown -R $TEMPLATE_USER:www-data /var/www/html && chmod 0775 /var/www/html' ]

  # ---- Restart qemu-guest-agent so the cleared blacklist takes effect ----
  - [ systemctl, restart, qemu-guest-agent ]

  # ---- Pre-seal sanity ----
  - [ sh, -c, 'systemctl is-enabled qemu-guest-agent && echo "GUEST_AGENT_ENABLED=yes" >> /etc/cybercore-bake.env || echo "GUEST_AGENT_ENABLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "^DAEMON_ARGS=\"\"" /etc/default/qemu-guest-agent && echo "GUEST_AGENT_UNBLOCKED=yes" >> /etc/cybercore-bake.env || echo "GUEST_AGENT_UNBLOCKED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'command -v docker >/dev/null && echo "DOCKER_INSTALLED=yes" >> /etc/cybercore-bake.env || echo "DOCKER_INSTALLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'command -v apache2 >/dev/null && echo "APACHE_INSTALLED=yes" >> /etc/cybercore-bake.env || echo "APACHE_INSTALLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'command -v php >/dev/null && echo "PHP_INSTALLED=yes" >> /etc/cybercore-bake.env || echo "PHP_INSTALLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "DOCKER_BASES_CACHED=$(docker images --format={{.Repository}}:{{.Tag}} | grep -cE \"^(node:20-alpine|python:3-slim|php:8.2-apache|nginx:alpine|ruby:3-alpine)$\")" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # Restore resolv.conf symlink so clones use DHCP-provided DNS.
  - [ sh, -c, 'rm -f /etc/resolv.conf; ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf' ]
  - [ sh, -c, 'cp /var/log/cloud-init-output.log /etc/cybercore-cloud-init.log 2>/dev/null || true' ]
  - [ sh, -c, 'rm -f /etc/netplan/50-cloud-init.yaml /etc/network/interfaces.d/50-cloud-init 2>/dev/null || true' ]
  - [ cloud-init, clean, --logs, --seed ]

power_state:
  mode: poweroff
  delay: '+1'
  message: 'Web template bake complete'
  timeout: 1800
SNIPPET

echo "==> Wrote bake snippet: $USERDATA_PATH"

# ---------- 3. Create VM ----------
echo "==> Creating VM $VMID ($NAME)..."
NET0="virtio,bridge=${BAKE_BRIDGE},firewall=0"
[ -n "${BAKE_VLAN:-}" ] && NET0="${NET0},tag=${BAKE_VLAN}"

qm create $VMID \
  --name "$NAME" \
  --memory $MEMORY \
  --cores $CORES \
  --cpu host \
  --machine q35 \
  --bios seabios \
  --scsihw virtio-scsi-pci \
  --net0 "$NET0" \
  --serial0 socket --vga serial0 \
  --agent enabled=1,fstrim_cloned_disks=1 \
  --ostype l26 \
  --description "CIAB web-01 template (Debian 13 + Docker + Apache + PHP). Baked from bake-web-template.sh."

echo "==> Importing cloud image as VM disk..."
qm disk import $VMID "$CLOUD_IMG_LOCAL" "$STORAGE"
qm set $VMID --scsi0 "${STORAGE}:vm-${VMID}-disk-0,discard=on,ssd=1"
qm set $VMID --boot order=scsi0
qm resize $VMID scsi0 ${DISK_GB}G || true
qm set $VMID --ide2 "${STORAGE}:cloudinit"

qm set $VMID \
  --ciuser "$TEMPLATE_USER" \
  --cipassword "$TEMPLATE_PASSWORD" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/$(basename "$USERDATA_PATH")"

# ---------- 4. Boot + wait ----------
echo "==> Starting VM (cloud-init installs Docker + Apache + PHP; ~8-12 min)..."
qm start $VMID

DEADLINE=$(( $(date +%s) + 1200 ))
echo "==> Waiting up to 20 min for cloud-init + power-off..."
while true; do
  STATUS=$(qm status $VMID | awk '{print $2}')
  [ "$STATUS" = "stopped" ] && { echo "==> VM powered off."; break; }
  if [ $(date +%s) -ge $DEADLINE ]; then
    echo "ERROR: cloud-init did not finish in time. Inspect: qm terminal $VMID" >&2
    exit 1
  fi
  sleep 15
done

# ---------- 4b. Pre-seal verification ----------
echo "==> Verifying bake markers..."
VERIFY_DEV=""
case "$STORAGE" in
  *ceph*|vmpool|rbd*)
    VERIFY_DEV=$(rbd map ${STORAGE}/vm-${VMID}-disk-0 --id admin 2>/dev/null) || VERIFY_DEV=""
    ;;
esac

if [ -z "$VERIFY_DEV" ]; then
  echo "WARNING: skipping marker verification (storage '$STORAGE' not a Ceph rbd pool)."
else
  for _ in 1 2 3 4 5; do
    partprobe "$VERIFY_DEV" 2>/dev/null || true
    udevadm settle 2>/dev/null || true
    [ -b "${VERIFY_DEV}p1" ] && break
    sleep 2
  done
  VERIFY_MOUNT=$(mktemp -d)
  if mount -o ro "${VERIFY_DEV}p1" "$VERIFY_MOUNT" 2>/dev/null; then
    BAKE_ENV="$VERIFY_MOUNT/etc/cybercore-bake.env"
    FAIL=0
    if [ -f "$BAKE_ENV" ]; then
      BAKE_COMPLETE=$(awk -F= '/^BAKE_COMPLETE=/{print $2}' "$BAKE_ENV")
      GUEST_AGENT=$(awk -F= '/^GUEST_AGENT_ENABLED=/{print $2}' "$BAKE_ENV")
      GUEST_AGENT_UNBLOCKED=$(awk -F= '/^GUEST_AGENT_UNBLOCKED=/{print $2}' "$BAKE_ENV")
      DOCKER=$(awk -F= '/^DOCKER_INSTALLED=/{print $2}' "$BAKE_ENV")
      APACHE=$(awk -F= '/^APACHE_INSTALLED=/{print $2}' "$BAKE_ENV")
      PHP=$(awk -F= '/^PHP_INSTALLED=/{print $2}' "$BAKE_ENV")
      DOCKER_BASES=$(awk -F= '/^DOCKER_BASES_CACHED=/{print $2}' "$BAKE_ENV")
      echo "    bake complete:    ${BAKE_COMPLETE:-no}"
      echo "    guest agent:      ${GUEST_AGENT:-unknown}"
      echo "    agent unblocked:  ${GUEST_AGENT_UNBLOCKED:-unknown}"
      echo "    docker:           ${DOCKER:-unknown}"
      echo "    docker bases:     ${DOCKER_BASES:-0}/5 cached"
      echo "    apache:           ${APACHE:-unknown}"
      echo "    php:              ${PHP:-unknown}"
      [ "$BAKE_COMPLETE" != "yes" ]         && { echo "ERROR: runcmd did not complete"; FAIL=1; }
      [ "$GUEST_AGENT" != "yes" ]           && { echo "ERROR: qemu-guest-agent not enabled"; FAIL=1; }
      [ "$GUEST_AGENT_UNBLOCKED" != "yes" ] && { echo "ERROR: qemu-guest-agent blacklist not cleared (guest-exec will return 596)"; FAIL=1; }
      [ "$DOCKER" != "yes" ]                && { echo "ERROR: docker not installed"; FAIL=1; }
      [ "$APACHE" != "yes" ]                && { echo "ERROR: apache not installed"; FAIL=1; }
      [ "$PHP" != "yes" ]                   && { echo "ERROR: php not installed"; FAIL=1; }
    else
      echo "ERROR: /etc/cybercore-bake.env not found"
      FAIL=1
    fi

    if [ "$FAIL" = "1" ]; then
      LOG_FILE="$VERIFY_MOUNT/etc/cybercore-cloud-init.log"
      [ -f "$LOG_FILE" ] || LOG_FILE="$VERIFY_MOUNT/var/log/cloud-init-output.log"
      echo ""
      echo "==================================================================="
      echo "  Last 80 lines of cloud-init log inside the VM:"
      echo "==================================================================="
      tail -80 "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (no log)"
      umount "$VERIFY_MOUNT"; rmdir "$VERIFY_MOUNT"
      rbd unmap "$VERIFY_DEV" 2>/dev/null || true
      echo ""
      echo "Refusing to seal a broken template. VM $VMID left intact for inspection."
      exit 1
    fi
    umount "$VERIFY_MOUNT"
    echo "==> All bake markers OK."
  else
    echo "WARNING: could not mount ${VERIFY_DEV}p1 — skipping verification."
  fi
  rmdir "$VERIFY_MOUNT" 2>/dev/null || true
  rbd unmap "$VERIFY_DEV" 2>/dev/null || true
fi

# ---------- 5. Strip bake-time cloud-init config ----------
echo "==> Clearing bake-time cicustom + cloud-init fields..."
qm set $VMID --delete cicustom
qm set $VMID --delete nameserver 2>/dev/null || true
qm set $VMID --delete searchdomain 2>/dev/null || true

# ---------- 6. Convert to template ----------
echo "==> Converting VM to template..."
qm template $VMID

echo ""
echo "==================================================================="
echo "  Web template $VMID baked successfully"
echo "==================================================================="
echo "  Verify:        qm config $VMID"
echo "  Test clone:    qm clone $VMID 9995 --name web-test --full --storage $STORAGE"
echo ""
echo "  ---- vm_template_catalog row ----"
echo "  Run this on the orchestrator's clinic_db so CIAB picks it up:"
echo ""
echo "    UPDATE vm_template_catalog SET"
echo "      os_name    = 'Debian 13 web',"
echo "      os_version = '13',"
echo "      role_hints = '{web}',"
echo "      preferred  = true,"
echo "      notes      = 'web-template (debian13 + docker + apache + php). Baked from bake-web-template.sh — CIAB profile deploys land web-01 here.'"
echo "    WHERE template_vmid = $VMID;"
echo ""
echo "  If the row doesn't exist yet (no migration 013 ran):"
echo ""
echo "    INSERT INTO vm_template_catalog (os_family, os_name, os_version, template_vmid, role_hints, preferred, notes)"
echo "    VALUES ('linux', 'Debian 13 web', '13', $VMID, '{web}', true, 'web-template (debian13 + docker + apache + php). Baked from bake-web-template.sh.');"
echo ""
