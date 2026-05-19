#!/bin/bash
# ============================================================================
# bake-dvwa-template.sh
# ----------------------------------------------------------------------------
# Bakes QEMU VM template 1702: Debian 13 + Apache + PHP + MariaDB + DVWA
# installed natively (NOT containerized). Native install is the load-bearing
# choice — popping DVWA's Command Injection module drops a `www-data` shell
# directly on the VM, with all the standard LinPE primitives in scope
# (SUID, sudo misconfigs, writable cron, etc.).
#
# The template ships with intentional LinPE misconfigurations planted by
# this script. They are listed in /etc/cybercore-bake.env so the verifier
# can confirm they survived the bake. To change which artifacts ship, edit
# the write_files / runcmd blocks in the cloud-init snippet below — do NOT
# add them post-clone (you'd have to re-snapshot every lane).
#
# Companion to:
#   - bake-juice-shop-template.sh   (sibling attached-module template)
#   - bake-kali-template.sh         (attack box, same bake pattern)
#
# Run on a Proxmox node with internet access. Idempotent: refuses if 1702
# already exists. To re-bake: qm destroy 1702 --purge
# ============================================================================
set -euo pipefail

VMID=${VMID:-1702}
NAME=${NAME:-dvwa-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
MEMORY=${MEMORY:-1024}
CORES=${CORES:-1}
DISK_GB=${DISK_GB:-8}

CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2}"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-generic-amd64.qcow2"

# The template ships with DVWA's canonical default creds preserved (admin /
# password). Students discover these the same way they would on a real
# pentest — guessing common defaults. Don't change without updating the
# lesson plan.
DVWA_ADMIN_USER="admin"
DVWA_ADMIN_PASS="password"
DVWA_DB_NAME="dvwa"
DVWA_DB_USER="dvwa"
DVWA_DB_PASS="p@ssw0rd"

# Linux account on the box (NOT the DVWA admin) — gets sudo NOPASSWD on tar
# for the GTFObins LinPE chain. Separate from www-data so students need
# lateral movement before privesc.
TEMPLATE_USER="${TEMPLATE_USER:-devops}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-Spring2026!}"

DVWA_REPO="${DVWA_REPO:-https://github.com/digininja/DVWA.git}"

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
    return 1
  fi
  local first
  first=$(pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then echo "$first"; return 0; fi
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
echo "==> Cloud image: $CLOUD_IMG_LOCAL"

# ---------- 2. Build cloud-init user-data ----------
USERDATA_FILE="dvwa-template-bake-${VMID}.yml"
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

bootcmd:
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf; exit 0' ]

users:
  - name: $TEMPLATE_USER
    groups: [sudo]
    shell: /bin/bash
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
packages:
  - qemu-guest-agent
  - openssh-server
  - apache2
  - mariadb-server
  - mariadb-client
  - php
  - php-mysql
  - php-gd
  - php-mbstring
  - php-xml
  - php-cli
  - libapache2-mod-php
  - git
  - curl
  - wget
  - vim
  - net-tools
  - ca-certificates
  - resolvconf
  - cron

write_files:
  # DVWA needs allow_url_include enabled for the File Inclusion module's
  # RFI chain. Default php.ini ships with allow_url_include=Off, which
  # neuters one of the three shell-yielding modules. Override here.
  - path: /etc/php/8.2/apache2/conf.d/99-dvwa.ini
    permissions: '0644'
    content: |
      allow_url_include = On
      allow_url_fopen = On

  # ---- LinPE artifact 1: world-writable cron script run as root ----
  # Students with a www-data shell can write to /opt/maintenance.sh; cron
  # executes it as root every minute. Classic privesc primitive.
  - path: /etc/cron.d/maintenance
    permissions: '0644'
    content: |
      # Maintenance task — runs every minute as root.
      # DO NOT remove. Maintained by devops@.
      * * * * * root /opt/maintenance.sh >/dev/null 2>&1

  - path: /opt/maintenance.sh
    permissions: '0777'
    content: |
      #!/bin/bash
      # Placeholder — fill in once we wire monitoring.
      :

  # ---- LinPE artifact 2: planted credentials hint ----
  # Plaintext password in a file readable by www-data. Mentions a domain
  # account ('jdoe') so the artifact also foreshadows an AD pivot in
  # later weeks when GOAD is in scope.
  - path: /opt/credentials.txt
    permissions: '0644'
    content: |
      # Internal credentials reference (rotate quarterly)
      #
      # Database (DVWA app):
      #   user: dvwa
      #   pass: $DVWA_DB_PASS
      #
      # Linux deploy account (this box):
      #   user: $TEMPLATE_USER
      #   pass: $TEMPLATE_PASSWORD
      #
      # AD domain (for backup script — see /opt/backup.sh):
      #   user: jdoe
      #   pass: Summer2025!

  - path: /opt/backup.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/bin/bash
      # Nightly backup to the file server. Run by cron. Credentials are in
      # /opt/credentials.txt — keep in sync if you rotate the AD account.
      smbclient //fileserver/backups -U jdoe%Summer2025! -c 'put /var/backups/db.sql' || true

  # ---- LinPE artifact 3: sudo NOPASSWD on tar (GTFObins) ----
  # The 'devops' user can run tar as root without a password. GTFObins tar
  # entry: --checkpoint=1 --checkpoint-action=exec=/bin/sh → root shell.
  # Students reach this via creds in /opt/credentials.txt → SSH as devops →
  # sudo tar privesc.
  - path: /etc/sudoers.d/devops-backup
    permissions: '0440'
    content: |
      $TEMPLATE_USER ALL=(root) NOPASSWD: /usr/bin/tar

  # ~/notes.txt for the devops user — hints at AD pivot.
  - path: /home/$TEMPLATE_USER/notes.txt
    permissions: '0644'
    content: |
      TODO
      ----
      * migrate /opt/backup.sh to use the new fileserver (talk to jdoe re: SMB creds)
      * the lab DC is dc01.sevenkingdoms.local — kerberos works from this box once
        DNS is pointed at it
      * remember to remove /etc/sudoers.d/devops-backup after the tar workflow
        is replaced (Ana asked twice already)

  - path: /etc/cybercore-bake.env
    permissions: '0644'
    content: |
      BAKE_NAME=$NAME
      BAKE_VMID=$VMID
      BAKE_KIND=dvwa

runcmd:
  # ---- Restore bake-time DNS before any internet ops ----
  # The packages: phase installed resolvconf, which on Debian 13 replaces
  # /etc/resolv.conf with a symlink to /run/resolvconf/resolv.conf. That
  # file is empty because dhclient ran BEFORE resolvconf existed, so the
  # DHCP-pushed DNS never went through resolvconf's hooks. Net effect:
  # by the time runcmd starts, the box has no DNS. Overwrite the symlink
  # with a regular file containing the bake-time DNS so `git clone` of
  # DVWA below can resolve github.com. The tail cleanup re-creates the
  # symlink so lane clones still get DHCP DNS via resolvconf.
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf' ]

  # ---- 1. MariaDB: create DVWA database + user ----
  - [ systemctl, enable, mariadb ]
  - [ systemctl, start, mariadb ]
  - [ sh, -c, "mysql -e \"CREATE DATABASE IF NOT EXISTS $DVWA_DB_NAME;\"" ]
  - [ sh, -c, "mysql -e \"CREATE USER IF NOT EXISTS '$DVWA_DB_USER'@'localhost' IDENTIFIED BY '$DVWA_DB_PASS';\"" ]
  - [ sh, -c, "mysql -e \"GRANT ALL PRIVILEGES ON $DVWA_DB_NAME.* TO '$DVWA_DB_USER'@'localhost';\"" ]
  - [ sh, -c, 'mysql -e "FLUSH PRIVILEGES;"' ]

  # ---- 2. Clone DVWA into /var/www/html ----
  - [ sh, -c, 'rm -rf /var/www/html/index.html /var/www/html/*' ]
  - [ sh, -c, 'git clone --depth 1 $DVWA_REPO /tmp/dvwa' ]
  - [ sh, -c, 'cp -a /tmp/dvwa/. /var/www/html/' ]
  - [ sh, -c, 'rm -rf /tmp/dvwa' ]
  - [ sh, -c, 'cp /var/www/html/config/config.inc.php.dist /var/www/html/config/config.inc.php' ]
  - [ sh, -c, "sed -i \"s/p@ssw0rd/$DVWA_DB_PASS/\" /var/www/html/config/config.inc.php" ]
  - [ sh, -c, 'chown -R www-data:www-data /var/www/html' ]
  - [ sh, -c, 'chmod -R 755 /var/www/html' ]

  # DVWA's Setup page initializes the schema + admin user on first hit. We
  # call it from inside the VM at bake time so clones come up with the DB
  # already populated (no "click reset database" needed on first lane boot).
  - [ systemctl, enable, apache2 ]
  - [ systemctl, start, apache2 ]
  - [ sh, -c, 'sleep 3; curl -s -c /tmp/cookies http://127.0.0.1/setup.php >/dev/null' ]
  - [ sh, -c, 'curl -s -b /tmp/cookies -d "create_db=Create / Reset Database" http://127.0.0.1/setup.php >/dev/null' ]
  - [ sh, -c, 'rm -f /tmp/cookies' ]

  # ---- 3. LinPE artifact 4: SUID find ----
  # Classic shell escape: find /etc/passwd -exec /bin/sh \; → root shell.
  # Done in runcmd (not write_files) because SUID bit needs chmod after
  # the binary is already in place.
  - [ sh, -c, 'chmod u+s /usr/bin/find' ]

  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ systemctl, enable, cron ]

  # Pre-seal sanity checks. \$ escapes deliberate — runcmd shell.
  - [ sh, -c, 'sleep 5; ss -ltn "( sport = :80 )" | grep -q LISTEN && echo "PORT_80_LISTEN=yes" >> /etc/cybercore-bake.env || echo "PORT_80_LISTEN=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/login.php > /tmp/code; rc=\$(cat /tmp/code); if [ "\$rc" = "200" ]; then echo "DVWA_HTTP=yes" >> /etc/cybercore-bake.env; else echo "DVWA_HTTP=no (got \$rc)" >> /etc/cybercore-bake.env; fi; rm -f /tmp/code' ]
  - [ sh, -c, 'stat -c "%a %U" /usr/bin/find | grep -q "^[47][0-9][0-9][0-9]\? root" && echo "SUID_FIND=yes" >> /etc/cybercore-bake.env || echo "SUID_FIND=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, '[ -f /etc/cron.d/maintenance ] && [ -w /opt/maintenance.sh ] && echo "CRON_ARTIFACT=yes" >> /etc/cybercore-bake.env || echo "CRON_ARTIFACT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, '[ -f /etc/sudoers.d/devops-backup ] && echo "SUDO_TAR=yes" >> /etc/cybercore-bake.env || echo "SUDO_TAR=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # Cleanup
  - [ sh, -c, 'rm -f /etc/resolv.conf; ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf' ]
  - [ sh, -c, 'cp /var/log/cloud-init-output.log /etc/cybercore-cloud-init.log 2>/dev/null || true' ]
  - [ sh, -c, 'rm -f /etc/netplan/50-cloud-init.yaml /etc/network/interfaces.d/50-cloud-init 2>/dev/null || true' ]
  - [ cloud-init, clean, --logs, --seed ]

power_state:
  mode: poweroff
  delay: '+1'
  message: 'DVWA template bake complete'
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
  --description "DVWA template (native Apache+PHP+MariaDB). Baked from bake-dvwa-template.sh."

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
echo "==> Starting VM (cloud-init installs LAMP + DVWA; ~8 min)..."
qm start $VMID

DEADLINE=$(( $(date +%s) + 900 ))
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
      DVWA_HTTP=$(awk -F= '/^DVWA_HTTP=/{print $2}' "$BAKE_ENV")
      SUID_FIND=$(awk -F= '/^SUID_FIND=/{print $2}' "$BAKE_ENV")
      CRON_ART=$(awk -F= '/^CRON_ARTIFACT=/{print $2}' "$BAKE_ENV")
      SUDO_TAR=$(awk -F= '/^SUDO_TAR=/{print $2}' "$BAKE_ENV")
      echo "    bake complete:    ${BAKE_COMPLETE:-no}"
      echo "    :80 listening:    ${PORT_80:-unknown}"
      echo "    DVWA HTTP 200:    ${DVWA_HTTP:-unknown}"
      echo "    SUID find:        ${SUID_FIND:-unknown}"
      echo "    cron artifact:    ${CRON_ART:-unknown}"
      echo "    sudo tar artifact:${SUDO_TAR:-unknown}"
      [ "$BAKE_COMPLETE" != "yes" ] && { echo "ERROR: runcmd did not complete"; FAIL=1; }
      [ "$PORT_80" != "yes" ]      && { echo "ERROR: :80 not listening"; FAIL=1; }
      [ "$DVWA_HTTP" != "yes" ]    && { echo "ERROR: DVWA login page not serving 200"; FAIL=1; }
      [ "$SUID_FIND" != "yes" ]    && { echo "ERROR: SUID find artifact missing"; FAIL=1; }
      [ "$CRON_ART" != "yes" ]     && { echo "ERROR: cron artifact missing"; FAIL=1; }
      [ "$SUDO_TAR" != "yes" ]     && { echo "ERROR: sudo tar artifact missing"; FAIL=1; }
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
echo "  DVWA template $VMID baked successfully"
echo "==================================================================="
echo "  DVWA admin:    $DVWA_ADMIN_USER / $DVWA_ADMIN_PASS"
echo "  SSH user:      $TEMPLATE_USER / $TEMPLATE_PASSWORD"
echo "  LinPE primitives baked in:"
echo "    - SUID /usr/bin/find"
echo "    - world-writable /opt/maintenance.sh run by root cron"
echo "    - sudo NOPASSWD on /usr/bin/tar for $TEMPLATE_USER (GTFObins)"
echo "    - planted /opt/credentials.txt readable by www-data"
echo "  Reach via:     http://<lane-subnet>.<ip_octet>/login.php"
echo "==================================================================="
