#!/bin/bash
# ============================================================================
# bake-cybersaguaros-template.sh
# ----------------------------------------------------------------------------
# Bakes QEMU VM template 1703: the "CyberSaguaros Research Portal" — a custom
# vulnerable web app on Debian 13 LNMP (nginx + PHP-FPM + MariaDB). Deployed
# as an attachable module via POST /api/admin/lanes/:id/modules.
#
# Attack chain delivered by this template:
#   SSRF (SaguaroBot dataset verifier) -> internal admin-session provisioning
#   -> admin panel -> file-upload webshell (weak Content-Type filter) -> RCE
#   as `saguarobot` -> Linux privesc to root.
#
# App source is BUNDLED in the CyberCore repo at challenges/cybersaguaros/.
# This script must be run from inside a CyberCore checkout (it lives in the
# repo). It tars that directory, base64-embeds it in the cloud-init payload,
# and the VM unpacks it on first boot — so the VM itself needs no repo access.
#
# Companion to:
#   - bake-dvwa-template.sh        (sibling attached-module template, 1702)
#   - bake-juice-shop-template.sh  (sibling attached-module template, 1701)
#
# Run on a Proxmox node with internet access. Idempotent: refuses if 1703
# already exists. To re-bake: qm destroy 1703 --purge
# ============================================================================
set -euo pipefail

VMID=${VMID:-1703}
NAME=${NAME:-cybersaguaros-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
MEMORY=${MEMORY:-2048}
CORES=${CORES:-2}
DISK_GB=${DISK_GB:-12}

CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2}"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-generic-amd64.qcow2"

# Linux accounts on the box.
#   saguarobot — PHP-FPM pool user; the webshell / reverse-shell foothold.
#   dvalmont   — researcher; has sudo NOPASSWD on tar (GTFObins privesc).
#   root       — bake-debug password for instructor inspection.
SAGUAROBOT_PASSWORD="${SAGUAROBOT_PASSWORD:-bake-debug-bot}"
DVALMONT_PASSWORD="Desert-Bloom-77"
ROOT_PASSWORD="${ROOT_PASSWORD:-bake-debug}"

# Must match DB_PASS in challenges/cybersaguaros/app/includes/config.php.
DB_APP_PASSWORD="Pr1ckly-Pear-Access-2026"

# ---------- 0. Sanity ----------
if qm status $VMID >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status $VMID >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
  exit 1
fi

# Locate the bundled app source relative to this script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CHALLENGE_DIR="$REPO_ROOT/challenges/cybersaguaros"
if [ ! -d "$CHALLENGE_DIR/app" ]; then
  echo "ERROR: app source not found at $CHALLENGE_DIR/app" >&2
  echo "       Run this script from inside a CyberCore checkout." >&2
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
  local cur
  cur=$(awk '/^[a-z]+: local$/{flag=1} flag && /^\s*content/{print $2; flag=0}' /etc/pve/storage.cfg)
  [ -z "$cur" ] && cur="iso,vztmpl,backup"
  [[ "$cur" != *snippets* ]] && pvesm set local --content "${cur},snippets" >&2
  echo "local"
}

SNIPPET_STORAGE=$(pick_snippet_storage)
echo "==> Snippet storage: $SNIPPET_STORAGE"
echo "==> App source:      $CHALLENGE_DIR"
echo "==> Bake-time NIC:   bridge=$BAKE_BRIDGE${BAKE_VLAN:+ vlan=$BAKE_VLAN}"

# ---------- 1. Download cloud image (cached) ----------
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  echo "==> Downloading Debian 13 cloud image (~350MB)..."
  mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
  wget --progress=dot:giga -O "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_URL"
  mv "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_LOCAL"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL"

# ---------- 1b. Pack the app source into a base64 blob ----------
# tar the whole challenges/cybersaguaros dir (app/ + deploy/ + README.md);
# the VM unpacks it under /opt/cybersaguaros-src on first boot.
echo "==> Packing app source into the cloud-init payload..."
APP_B64="$(tar czf - -C "$REPO_ROOT/challenges" cybersaguaros | base64 -w 76 | sed 's/^/      /')"

# ---------- 2. Build cloud-init user-data ----------
USERDATA_FILE="cybersaguaros-template-bake-${VMID}.yml"
case "$SNIPPET_STORAGE" in
  local)  USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  cephfs) USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
  *)      USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
esac
mkdir -p "$(dirname "$USERDATA_PATH")"

cat > "$USERDATA_PATH" << SNIPPET
#cloud-config
hostname: cybersaguaros
manage_etc_hosts: true

bootcmd:
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf; exit 0' ]

users:
  - name: saguarobot
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: $SAGUAROBOT_PASSWORD
  - name: dvalmont
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: $DVALMONT_PASSWORD

chpasswd:
  list: |
    root:$ROOT_PASSWORD
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
  - curl
  - wget
  - vim
  - net-tools
  - ca-certificates
  - resolvconf
  - cron
  - nginx
  - mariadb-server
  - php-fpm
  - php-mysql
  - php-curl
  - php-gd
  - php-xml
  - php-mbstring

write_files:
  # The bundled CyberSaguaros app source, base64-packed at bake time.
  - path: /tmp/cybersaguaros-src.tar.gz
    encoding: b64
    permissions: '0600'
    content: |
$APP_B64

  # ---- LinPE artifact: world-writable cron script run as root ----
  - path: /etc/cron.d/saguaro-datasync
    permissions: '0644'
    content: |
      # CyberSaguaros dataset sync — runs every minute as root.
      * * * * * root /opt/saguaro/datasync.sh >/dev/null 2>&1

  - path: /opt/saguaro/datasync.sh
    permissions: '0777'
    content: |
      #!/bin/bash
      # Placeholder dataset sync job. TODO: wire to the field station mirror.
      :

  # ---- LinPE artifact: planted research notes (creds + AD-pivot hint) ----
  - path: /opt/saguaro/research-notes.txt
    permissions: '0644'
    content: |
      CyberSaguaros field station — research notes
      --------------------------------------------
      * portal DB app user: saguaro_app / $DB_APP_PASSWORD
      * my workstation login (dvalmont): $DVALMONT_PASSWORD
      * dvalmont can run 'sudo tar' on this box for the nightly archive job.
      * TODO: migrate the backup job to the internal domain. The lab DC is
        dc01.cybersaguaros.local; a Ligolo agent on 10.0.0.0/24 reaches it.

  # ---- LinPE artifact: sudo NOPASSWD tar for dvalmont (GTFObins) ----
  - path: /etc/sudoers.d/dvalmont-tar
    permissions: '0440'
    content: |
      dvalmont ALL=(root) NOPASSWD: /usr/bin/tar

  - path: /etc/cybercore-bake.env
    permissions: '0644'
    content: |
      BAKE_NAME=$NAME
      BAKE_VMID=$VMID
      BAKE_KIND=cybersaguaros

runcmd:
  # ---- Restore bake-time DNS (resolvconf re-symlinks /etc/resolv.conf) ----
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf' ]

  # ---- Unpack the bundled app ----
  - [ sh, -c, 'mkdir -p /opt/cybersaguaros-src && tar xzf /tmp/cybersaguaros-src.tar.gz -C /opt/cybersaguaros-src' ]
  - [ sh, -c, 'mkdir -p /var/www/cybersaguaros && cp -r /opt/cybersaguaros-src/cybersaguaros/app/. /var/www/cybersaguaros/' ]

  # ---- nginx site ----
  - [ sh, -c, 'cp /opt/cybersaguaros-src/cybersaguaros/deploy/nginx-cybersaguaros.conf /etc/nginx/sites-available/cybersaguaros' ]
  - [ sh, -c, 'ln -sf /etc/nginx/sites-available/cybersaguaros /etc/nginx/sites-enabled/cybersaguaros' ]
  - [ sh, -c, 'rm -f /etc/nginx/sites-enabled/default' ]

  # ---- PHP-FPM pool (version-detected) running as saguarobot ----
  - [ sh, -c, 'PHPVER=\$(ls /etc/php/ | head -1); cp /opt/cybersaguaros-src/cybersaguaros/deploy/php-fpm-pool.conf /etc/php/\$PHPVER/fpm/pool.d/cybersaguaros.conf' ]

  # ---- MariaDB: database, app user, schema + seed ----
  - [ systemctl, enable, mariadb ]
  - [ systemctl, start, mariadb ]
  - [ sh, -c, 'mysql -e "CREATE DATABASE IF NOT EXISTS cybersaguaros;"' ]
  - [ sh, -c, "mysql -e \"CREATE USER IF NOT EXISTS 'saguaro_app'@'localhost' IDENTIFIED BY '$DB_APP_PASSWORD';\"" ]
  - [ sh, -c, "mysql -e \"GRANT ALL PRIVILEGES ON cybersaguaros.* TO 'saguaro_app'@'localhost';\"" ]
  - [ sh, -c, 'mysql -e "FLUSH PRIVILEGES;"' ]
  - [ sh, -c, 'mysql cybersaguaros < /var/www/cybersaguaros/db/schema.sql' ]
  - [ sh, -c, 'mysql cybersaguaros < /var/www/cybersaguaros/db/seed.sql' ]

  # ---- Permissions ----
  # App owned by root; only the uploads dir is writable by the PHP-FPM user
  # (so the upload works) — uploads dir doubles as the RCE landing zone.
  - [ sh, -c, 'chown -R root:root /var/www/cybersaguaros' ]
  - [ sh, -c, 'chown -R saguarobot:saguarobot /var/www/cybersaguaros/public/uploads' ]
  - [ sh, -c, 'chmod 755 /var/www/cybersaguaros/public/uploads' ]

  # ---- LinPE artifact: SUID find ----
  - [ sh, -c, 'chmod u+s /usr/bin/find' ]

  # ---- Enable + start services ----
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ systemctl, enable, cron ]
  - [ systemctl, enable, nginx ]
  - [ sh, -c, 'PHPVER=\$(ls /etc/php/ | head -1); systemctl enable php\${PHPVER}-fpm; systemctl restart php\${PHPVER}-fpm' ]
  - [ systemctl, restart, nginx ]

  # ---- Pre-seal sanity markers. \$ escapes = runtime shell, not bake heredoc ----
  - [ sh, -c, 'sleep 5; ss -ltn "( sport = :80 )" | grep -q LISTEN && echo "PORT_80_LISTEN=yes" >> /etc/cybercore-bake.env || echo "PORT_80_LISTEN=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'code=\$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/); [ "\$code" = "200" ] && echo "SITE_HTTP=yes" >> /etc/cybercore-bake.env || echo "SITE_HTTP=no (\$code)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'code=\$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/api/verify.php); [ "\$code" = "400" ] && echo "SSRF_ENDPOINT=yes" >> /etc/cybercore-bake.env || echo "SSRF_ENDPOINT=no (\$code)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'curl -s http://127.0.0.1/api/internal/provision.php | grep -q admin_session && echo "INTERNAL_OK=yes" >> /etc/cybercore-bake.env || echo "INTERNAL_OK=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'printf "%s" "<?php echo 92837465;" > /var/www/cybersaguaros/public/uploads/baketest.php; out=\$(curl -s http://127.0.0.1/uploads/baketest.php); rm -f /var/www/cybersaguaros/public/uploads/baketest.php; echo "\$out" | grep -q 92837465 && echo "UPLOAD_EXEC=yes" >> /etc/cybercore-bake.env || echo "UPLOAD_EXEC=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'stat -c "%a" /usr/bin/find | grep -qE "^[46]" && echo "SUID_FIND=yes" >> /etc/cybercore-bake.env || echo "SUID_FIND=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, '[ -f /etc/cron.d/saguaro-datasync ] && [ -w /opt/saguaro/datasync.sh ] && echo "CRON_ARTIFACT=yes" >> /etc/cybercore-bake.env || echo "CRON_ARTIFACT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, '[ -f /etc/sudoers.d/dvalmont-tar ] && echo "SUDO_TAR=yes" >> /etc/cybercore-bake.env || echo "SUDO_TAR=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # ---- Cleanup ----
  - [ sh, -c, 'rm -f /tmp/cybersaguaros-src.tar.gz' ]
  - [ sh, -c, 'rm -f /etc/resolv.conf; ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf' ]
  - [ sh, -c, 'cp /var/log/cloud-init-output.log /etc/cybercore-cloud-init.log 2>/dev/null || true' ]
  - [ sh, -c, 'rm -f /etc/netplan/50-cloud-init.yaml /etc/network/interfaces.d/50-cloud-init 2>/dev/null || true' ]
  - [ cloud-init, clean, --logs, --seed ]

power_state:
  mode: poweroff
  delay: '+1'
  message: 'CyberSaguaros template bake complete'
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
  --description "CyberSaguaros SSRF portal template (nginx+PHP-FPM+MariaDB). Baked from bake-cybersaguaros-template.sh."

echo "==> Importing cloud image as VM disk..."
qm disk import $VMID "$CLOUD_IMG_LOCAL" "$STORAGE"
qm set $VMID --scsi0 "${STORAGE}:vm-${VMID}-disk-0,discard=on,ssd=1"
qm set $VMID --boot order=scsi0
qm resize $VMID scsi0 ${DISK_GB}G || true
qm set $VMID --ide2 "${STORAGE}:cloudinit"

qm set $VMID \
  --ciuser saguarobot \
  --cipassword "$SAGUAROBOT_PASSWORD" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/$(basename "$USERDATA_PATH")"

# ---------- 4. Boot + wait ----------
echo "==> Starting VM (cloud-init installs LNMP + the portal; ~8-12 min)..."
qm start $VMID

DEADLINE=$(( $(date +%s) + 1200 ))
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
      get() { awk -F= "/^$1=/{print \$2}" "$BAKE_ENV"; }
      BAKE_COMPLETE=$(get BAKE_COMPLETE)
      PORT_80=$(get PORT_80_LISTEN)
      SITE_HTTP=$(get SITE_HTTP)
      SSRF_EP=$(get SSRF_ENDPOINT)
      INTERNAL_OK=$(get INTERNAL_OK)
      UPLOAD_EXEC=$(get UPLOAD_EXEC)
      SUID_FIND=$(get SUID_FIND)
      CRON_ART=$(get CRON_ARTIFACT)
      SUDO_TAR=$(get SUDO_TAR)
      echo "    bake complete:     ${BAKE_COMPLETE:-no}"
      echo "    :80 listening:     ${PORT_80:-unknown}"
      echo "    site HTTP 200:     ${SITE_HTTP:-unknown}"
      echo "    SSRF endpoint:     ${SSRF_EP:-unknown}"
      echo "    internal API:      ${INTERNAL_OK:-unknown}"
      echo "    uploads exec PHP:  ${UPLOAD_EXEC:-unknown}"
      echo "    SUID find:         ${SUID_FIND:-unknown}"
      echo "    cron artifact:     ${CRON_ART:-unknown}"
      echo "    sudo tar artifact: ${SUDO_TAR:-unknown}"
      [ "$BAKE_COMPLETE" != "yes" ] && { echo "ERROR: runcmd did not complete"; FAIL=1; }
      [ "$PORT_80" != "yes" ]      && { echo "ERROR: :80 not listening"; FAIL=1; }
      [ "$SITE_HTTP" != "yes" ]    && { echo "ERROR: portal not serving HTTP 200"; FAIL=1; }
      [ "$SSRF_EP" != "yes" ]      && { echo "ERROR: SSRF verify endpoint not responding"; FAIL=1; }
      [ "$INTERNAL_OK" != "yes" ]  && { echo "ERROR: internal provisioning API not working"; FAIL=1; }
      [ "$UPLOAD_EXEC" != "yes" ]  && { echo "ERROR: uploads dir does not execute PHP (RCE path broken)"; FAIL=1; }
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
echo "  CyberSaguaros template $VMID baked successfully"
echo "==================================================================="
echo "  Portal admin:  dr.prickle / Sunset-Saguaro-2026"
echo "  Linux foothold: saguarobot (PHP-FPM pool user)"
echo "  Privesc user:  dvalmont / Desert-Bloom-77  (sudo NOPASSWD tar)"
echo "  Reach via:     http://<lane-subnet>.<ip_octet>/"
echo "  Attach with:   POST /api/admin/lanes/<laneId>/modules"
echo "                 { \"challenge_key\": \"cybersaguaros-ssrf\", \"module\": \"crucible\" }"
echo "==================================================================="
