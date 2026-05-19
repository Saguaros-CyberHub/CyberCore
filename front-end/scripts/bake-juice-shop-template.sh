#!/bin/bash
# ============================================================================
# bake-juice-shop-template.sh
# ----------------------------------------------------------------------------
# Bakes QEMU VM template 1701: Debian 13 + Docker + OWASP Juice Shop preloaded
# and configured to autostart on boot. Each lane clones this template via the
# attach-module path (POST /api/admin/lanes/:id/modules) and reaches it on the
# lane subnet at <base>.<ip_octet>:80.
#
# Companion to:
#   - bake-kali-template.sh    (attack box, same bake pattern)
#   - bake-dvwa-template.sh    (DVWA, sibling attached-module template)
#
# Why a VM and not an LXC: Juice Shop's lessons stand on their own without
# LinPE — but baking as a full VM means the same template format slots into
# the existing clone pipeline without special-casing LXC vs QEMU in admin.js.
# Also gives instructors the option to plant LinPE artifacts later without
# re-baking from a different base.
#
# Run on a Proxmox node with internet access. Idempotent: refuses if 1701
# already exists. To re-bake: qm destroy 1701 --purge
# ============================================================================
set -euo pipefail

VMID=${VMID:-1701}
NAME=${NAME:-juice-shop-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
MEMORY=${MEMORY:-2048}
CORES=${CORES:-2}
DISK_GB=${DISK_GB:-12}

# Debian 13 (trixie) generic-cloud qcow2 — direct download, no tar wrapping.
# Pin a release tag rather than 'latest' for reproducible bakes; override
# CLOUD_IMG_URL to track a different snapshot.
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2}"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-generic-amd64.qcow2"

TEMPLATE_USER="${TEMPLATE_USER:-juice}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-bake-debug}"

# Pin a specific Juice Shop release for reproducible bakes. Override to track
# 'latest' if you want each bake to pull the newest published image.
JUICE_SHOP_IMAGE="${JUICE_SHOP_IMAGE:-bkimminich/juice-shop:v17.3.0}"

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
echo "==> Juice Shop image: $JUICE_SHOP_IMAGE"

# ---------- 1. Download cloud image (cached) ----------
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  echo "==> Downloading Debian 13 cloud image (~350MB)..."
  mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
  wget --progress=dot:giga -O "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_URL"
  mv "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_LOCAL"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL ($(du -h "$CLOUD_IMG_LOCAL" | cut -f1))"

# ---------- 2. Build cloud-init user-data ----------
USERDATA_FILE="juice-shop-template-bake-${VMID}.yml"
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
    groups: [sudo, docker]
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
# Docker packages are intentionally NOT in this list — they live in Docker's
# own apt repo which we register in runcmd below. cloud-init's apt.sources
# block uses the deprecated apt-key machinery, which Debian 13 dropped, so
# putting the docker repo there fails the entire packages: batch.
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

write_files:
  # systemd unit that runs Juice Shop as a docker container on boot.
  # --restart unless-stopped survives container crashes; the unit itself
  # handles VM reboots. Bind to 0.0.0.0:80 → container's 3000 so students
  # hit it on the standard HTTP port without remembering an offbeat one.
  - path: /etc/systemd/system/juice-shop.service
    permissions: '0644'
    content: |
      [Unit]
      Description=OWASP Juice Shop (attached-module template)
      After=docker.service network-online.target
      Wants=docker.service network-online.target

      [Service]
      Type=simple
      Restart=always
      RestartSec=10
      ExecStartPre=-/usr/bin/docker stop juice-shop
      ExecStartPre=-/usr/bin/docker rm juice-shop
      ExecStart=/usr/bin/docker run --rm --name juice-shop -p 80:3000 $JUICE_SHOP_IMAGE
      ExecStop=/usr/bin/docker stop juice-shop

      [Install]
      WantedBy=multi-user.target

  - path: /etc/cybercore-bake.env
    permissions: '0644'
    content: |
      BAKE_NAME=$NAME
      BAKE_VMID=$VMID
      BAKE_KIND=juice-shop
      JUICE_SHOP_IMAGE=$JUICE_SHOP_IMAGE

runcmd:
  # ---- Restore bake-time DNS before any internet ops ----
  # The packages: phase installed resolvconf, which on Debian 13 replaces
  # /etc/resolv.conf with a symlink to /run/resolvconf/resolv.conf. That
  # file is empty because dhclient ran BEFORE resolvconf existed, so the
  # DHCP-pushed DNS never went through resolvconf's hooks. Net effect:
  # by the time runcmd starts, the box has no DNS. Overwrite the symlink
  # with a regular file containing the bake-time DNS so curl + apt-get
  # update below can resolve. The tail cleanup re-creates the symlink so
  # lane clones still get DHCP DNS via resolvconf.
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf' ]

  # ---- Install Docker via the modern signed-by keyring pattern ----
  # Debian 13 dropped apt-key, so cloud-init's apt.sources keyid: doesn't
  # work. We fetch the dearmored key into /etc/apt/keyrings and reference
  # it from the .list file directly. \$ escapes deliberate — runcmd shell,
  # not bake heredoc.
  - [ sh, -c, 'install -m 0755 -d /etc/apt/keyrings' ]
  - [ sh, -c, 'curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg' ]
  - [ sh, -c, 'chmod a+r /etc/apt/keyrings/docker.gpg' ]
  - [ sh, -c, 'echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable" > /etc/apt/sources.list.d/docker.list' ]
  - [ sh, -c, 'DEBIAN_FRONTEND=noninteractive apt-get update' ]
  - [ sh, -c, 'DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io' ]

  # Pre-pull the Juice Shop image so first lane-boot doesn't wait on docker hub.
  - [ sh, -c, 'docker pull $JUICE_SHOP_IMAGE' ]

  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ systemctl, enable, docker ]
  - [ systemctl, enable, juice-shop ]
  - [ systemctl, start, docker ]
  - [ systemctl, start, juice-shop ]

  # Pre-seal sanity: confirm the container is up and bound to :80.
  # \$ escapes deliberate — runcmd shell, not bake heredoc.
  - [ sh, -c, 'sleep 20; ss -ltn "( sport = :80 )" | grep -q LISTEN && echo "PORT_80_LISTEN=yes" >> /etc/cybercore-bake.env || echo "PORT_80_LISTEN=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'docker ps --filter name=juice-shop --format "{{.Status}}" | grep -q "^Up" && echo "JUICE_SHOP_UP=yes" >> /etc/cybercore-bake.env || echo "JUICE_SHOP_UP=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # Restore resolv.conf symlink so clones use DHCP-provided DNS.
  - [ sh, -c, 'rm -f /etc/resolv.conf; ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf' ]
  - [ sh, -c, 'cp /var/log/cloud-init-output.log /etc/cybercore-cloud-init.log 2>/dev/null || true' ]
  - [ sh, -c, 'rm -f /etc/netplan/50-cloud-init.yaml /etc/network/interfaces.d/50-cloud-init 2>/dev/null || true' ]
  - [ cloud-init, clean, --logs, --seed ]

power_state:
  mode: poweroff
  delay: '+1'
  message: 'Juice Shop template bake complete'
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
  --description "OWASP Juice Shop template (Docker). Baked from bake-juice-shop-template.sh."

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
echo "==> Starting VM (cloud-init installs Docker + pulls Juice Shop; ~10 min)..."
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
      PORT_80=$(awk -F= '/^PORT_80_LISTEN=/{print $2}' "$BAKE_ENV")
      JUICE_UP=$(awk -F= '/^JUICE_SHOP_UP=/{print $2}' "$BAKE_ENV")
      echo "    bake complete:   ${BAKE_COMPLETE:-no}"
      echo "    :80 listening:   ${PORT_80:-unknown}"
      echo "    juice-shop up:   ${JUICE_UP:-unknown}"
      [ "$BAKE_COMPLETE" != "yes" ] && { echo "ERROR: runcmd did not complete"; FAIL=1; }
      [ "$PORT_80" != "yes" ]      && { echo "ERROR: :80 not listening"; FAIL=1; }
      [ "$JUICE_UP" != "yes" ]     && { echo "ERROR: juice-shop container not running"; FAIL=1; }
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
echo "  Juice Shop template $VMID baked successfully"
echo "==================================================================="
echo "  Verify:        qm config $VMID"
echo "  Test clone:    qm clone $VMID 9996 --name juice-test --full --storage $STORAGE"
echo "  Reach via:     http://<lane-subnet>.<ip_octet>:80"
echo "==================================================================="
