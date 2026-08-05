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
# Explicit DNS for the bake VM — avoids depending on whatever DHCP advertises
# (FreeIPA at 100.100.20.20 has been the default and dies sometimes; OPNsense
# Unbound at 100.100.0.1 is the orchestrator's resolver and recurses externally).
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
# CyberSaguaros fork of GOAD — carries the re-themed GOAD-Light lab data
# (ad/GOAD-Light/). Override with GOAD_REPO=... to bake from a different repo.
GOAD_REPO="${GOAD_REPO:-https://github.com/joshmp087/GOAD.git}"
GOAD_REF="${GOAD_REF:-main}"
MEMORY=2048
CORES=2
DISK_GB=10
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/debian-13-genericcloud-amd64.qcow2"

# A throwaway password baked into the template's default user. Per-clone,
# admin.js can override via cloud-init `cipassword`. Mostly we don't log in
# to this VM at all — qemu-guest-agent does the work.
TEMPLATE_PASSWORD="bake-debug"

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

# Force /etc/resolv.conf to a known-good resolver. manage_resolv_conf gets
# cloud-init to write resolv.conf in modules:config — backup if bootcmd missed.
manage_resolv_conf: true
resolv_conf:
  nameservers:
    - $BAKE_DNS
    - 1.1.1.1
  searchdomains: []
  domain: ""

# bootcmd MUST be fast and non-blocking. Any blocking command (e.g.,
# `systemctl reload`) will hang cloud-init at init-local stage, since cloud-init
# runs bootcmd synchronously with capture=False. We intentionally do NOT do:
#   - systemctl operations  (can block on service deps at this early stage)
#   - operations that need network  (network not fully up yet)
# Just set the root password (debug login) and force resolv.conf (so subsequent
# package install at modules:final can resolve hosts).
bootcmd:
  - [ sh, -c, 'echo "root:$TEMPLATE_PASSWORD" | chpasswd; rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\nnameserver 1.1.1.1\n" > /etc/resolv.conf; exit 0' ]

# chpasswd as defense-in-depth — if bootcmd missed for any reason, this
# config-stage run sets it again. Plus enables ssh password auth properly.
chpasswd:
  list: |
    root:$TEMPLATE_PASSWORD
  expire: false
ssh_pwauth: true
disable_root: false

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
  # write DHCP reservations on the lane gateway (whatever \${GW_IP} resolves
  # to per-lane — v1: 192.18.0.1 shared, v2: 10.<vxh>.<vxl>.1 unique) without
  # the orchestrator needing any SSH access. The corresponding public key
  # must be in the gateway template's /root/.ssh/authorized_keys (added by
  # scripts/patch-goad-gateway-key.sh for 1692; bake-lane-gateway-v2.sh
  # inherits it for 1694 via the clone-from-1692 chain).
  - path: /root/.ssh/id_ed25519
    permissions: '0600'
    content: |
$(echo "$DEPLOY_PRIVKEY" | sed 's/^/      /')

  - path: /root/.ssh/id_ed25519.pub
    permissions: '0644'
    content: |
      $DEPLOY_PUBKEY

  # ----- Python helper scripts called by run.sh -----
  # These live in standalone files (not inline heredocs in run.sh) so the
  # outer YAML block scalar doesn't choke on column-0 Python lines. The
  # `content: |` block stripped by 6 spaces gives Python source at column 0
  # — correct for module-level statements.
  - path: /opt/goad-light/patch-mssql.py
    permissions: '0755'
    content: |
      #!/usr/bin/env python3
      # Two patches to upstream's mssql role:
      #
      # (1) Replace win_template (which silently fails to render Jinja in
      #     ansible-core 2.20+) with: render locally then win_copy. The
      #     lambda passed to re.sub avoids Python's re module trying to
      #     interpret backslash escapes (\\s, \\1) in the replacement when
      #     it contains Windows paths.
      #
      # (2) Make the SQL Server install task tolerant of the benign
      #     "No features were installed" exit (rc=2226323458 / 0x84B40002).
      #     The Windows VM template (vmid 1004) ships with SQLEXPRESS
      #     already pre-installed, so the bootstrapper has nothing to
      #     install and bails. Subsequent role tasks (service config, db
      #     seed, GPO for ports) still run against the pre-installed
      #     instance and that's what makes Kerberoasting actually
      #     exploitable end-to-end.
      import re, sys
      path = sys.argv[1]
      content = open(path).read()

      # ---------- Patch 1: win_template -> template + win_copy ----------
      old1 = re.compile(
          r'- name: create the configuration file\s*\n'
          r'\s*win_template:\s*\n'
          r'\s*src:.*\n'
          r'\s*dest:.*sql_conf\.ini',
      )
      NEW1 = """- name: create the configuration file (rendered locally)
        ansible.builtin.template:
          src: sql_conf.ini.{{sql_version}}.j2
          dest: "/tmp/sql_conf.ini.{{ inventory_hostname }}"
        delegate_to: localhost

      - name: copy rendered configuration file to windows
        ansible.windows.win_copy:
          src: "/tmp/sql_conf.ini.{{ inventory_hostname }}"
          dest: 'c:\\setup\\mssql\\sql_conf.ini'
          force: yes"""
      content_v1 = old1.sub(lambda m: NEW1, content)
      if content_v1 != content:
          print(f"  Patch 1: replaced win_template with template+win_copy in {path}", file=sys.stderr)
      else:
          print(f"  Patch 1: WARNING — win_template pattern not matched (may already be patched)", file=sys.stderr)
      content = content_v1

      # ---------- Patch 2: tolerate "No features were installed" ----------
      # Match the install task by its NAME ("Install the database") rather
      # than by command content, since upstream's setup.exe invocation may
      # span multiple lines or use template vars (no literal "setup.exe" +
      # "sql_conf.ini" on the same line).
      #
      # If the task already has its own `register:` (upstream typically
      # registers as something like 'install_result'), reuse that name in
      # our failed_when expression — this avoids the duplicate-mapping-key
      # warning that would otherwise appear at task evaluation.
      lines = content.splitlines(keepends=True)
      task_start = None
      for i, line in enumerate(lines):
          if re.match(r'^[ \t]*- name:\s*Install the database\s*$', line):
              task_start = i
              break

      if task_start is None:
          print(f"  Patch 2: 'Install the database' task not found in {path} — skipping", file=sys.stderr)
      else:
          task_indent = re.match(r'^([ \t]*)-', lines[task_start]).group(1)
          attr_indent = task_indent + '  '

          # Walk down to the end of this task (next sibling at same indent,
          # first dedented line, or EOF).
          task_end = task_start
          j = task_start + 1
          while j < len(lines):
              if re.match(rf'^{re.escape(task_indent)}-[ \t]', lines[j]):
                  break
              if lines[j].strip() and not lines[j].startswith((' ', '\t')):
                  break
              if lines[j].strip():
                  task_end = j
              j += 1

          task_block = ''.join(lines[task_start:task_end + 1])
          if 'cybercore-mssql-tolerate' in task_block:
              print(f"  Patch 2: install task already tolerant (skip)", file=sys.stderr)
          else:
              # Detect existing `register: <var>` inside the task body and
              # reuse the var name. Falls back to our own name if upstream
              # doesn't register this task.
              existing_register = None
              for k in range(task_start + 1, task_end + 1):
                  m = re.match(r'^\s+register:\s+(\S+)\s*$', lines[k])
                  if m:
                      existing_register = m.group(1)
                      break

              register_name = existing_register or 'cybercore_mssql_install'

              # Detect existing failed_when — if upstream already has one,
              # don't add a duplicate (we'd create a YAML duplicate-key error).
              has_failed_when = any(
                  re.match(r'^\s+failed_when:', lines[k])
                  for k in range(task_start + 1, task_end + 1)
              )

              addition = [
                  f"{attr_indent}# cybercore-mssql-tolerate: SQLEXPRESS already in template\n",
              ]
              if existing_register is None:
                  addition.append(f"{attr_indent}register: {register_name}\n")
              if not has_failed_when:
                  addition.append(f"{attr_indent}failed_when:\n")
                  addition.append(f"{attr_indent}  - {register_name}.rc not in [0, 2226323458]\n")
                  addition.append(f"{attr_indent}  - \"'No features were installed' not in {register_name}.stdout\"\n")
                  lines[task_end + 1:task_end + 1] = addition
                  content = ''.join(lines)
                  msg_register = (
                      f"reused existing register='{existing_register}'"
                      if existing_register else "added register"
                  )
                  print(f"  Patch 2: added failed_when tolerance ({msg_register})", file=sys.stderr)
              else:
                  # Upstream has its own failed_when — leave it alone, just
                  # drop a marker comment so we don't keep retrying.
                  lines[task_end + 1:task_end + 1] = addition
                  content = ''.join(lines)
                  print(f"  Patch 2: upstream already has failed_when; left alone (added marker)", file=sys.stderr)

      open(path, 'w').write(content)

  - path: /opt/goad-light/patch-child-domain.py
    permissions: '0755'
    content: |
      #!/usr/bin/env python3
      # Replace upstream's win_reboot in child_domain role with wait_for_connection,
      # so we don't try a fresh WinRM session while the SAM is sealed pending reboot.
      import re, sys
      path = sys.argv[1]
      content = open(path).read()
      old = re.compile(
          r'- name:\s*Reboot\s*\n\s*win_reboot:\s*\n(?:\s*\w+:.*\n)+\s*when:\s*child_result\.changed',
      )
      new = (
          '- name: "cybercore: wait for child DC to reboot post-promotion"\n'
          '  ansible.builtin.wait_for_connection:\n'
          '    delay: 60\n'
          '    timeout: 900\n'
          '  when: child_result.changed'
      )
      out = old.sub(new, content)
      if out != content:
          open(path, 'w').write(out)
          print(f"  Replaced win_reboot with wait_for_connection in {path}", file=sys.stderr)

  # prep.sh writes DHCP reservations on the gateway. Run BEFORE the
  # Windows VMs come up (or before they renew DHCP) so they pick up
  # their reserved IPs. Orchestrator (admin.js / goad-deploy.js) calls
  # this before waitForWinRM, then restarts the Windows VMs to force
  # fresh DHCP, then runs run.sh for the actual playbook.
  - path: /opt/goad-light/prep.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Usage: prep.sh HOST_MAP
      #   HOST_MAP = "name|ip|mac,name|ip|mac,..." (pipe-separated triples)
      set -e
      if [ \$# -lt 1 ]; then
        echo "Usage: \$0 HOST_MAP"
        echo "  HOST_MAP — comma-separated 'name|ip|mac' triples"
        exit 1
      fi
      HOST_MAP="\$1"

      FIRST="\$(echo "\$HOST_MAP" | cut -d',' -f1)"
      FIRST_IP="\$(echo "\$FIRST" | cut -d'|' -f2)"
      IP_RANGE="\$(echo "\$FIRST_IP" | awk -F. '{print \$1"."\$2"."\$3}')"
      GW_IP="\${IP_RANGE}.1"

      RUNTIME=/var/lib/goad-run
      mkdir -p "\$RUNTIME"

      echo "[prep.sh] Writing DHCP reservations to gateway \${GW_IP}..."
      SSH_OPTS="-i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/root/.ssh/known_hosts -o ConnectTimeout=15 -o BatchMode=yes"
      RESV_FILE="\$RUNTIME/lane-reservations.conf"
      {
        echo "# GOAD lane DHCP reservations — written by /opt/goad-light/prep.sh"
        echo "\$HOST_MAP" | tr ',' '\n' | while IFS='|' read -r hname hip hmac; do
          [ -z "\$hname" ] && continue
          echo "dhcp-host=\$hmac,\$hip,\$hname"
        done
      } > "\$RESV_FILE"
      cat "\$RESV_FILE"

      # Push the reservations file + reload dnsmasq on the gateway. Also clear
      # any existing leases so dynamic-DHCPed clients can't keep their old
      # (wrong) IPs after a renewal — they'll be forced to re-request.
      ssh \$SSH_OPTS root@\$GW_IP "
        cat > /etc/dnsmasq.d/lane-reservations.conf
        # Wipe stale leases so renewals can't return to dynamic IPs.
        : > /var/lib/misc/dnsmasq.leases 2>/dev/null || true
        rc-service dnsmasq restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true
      " < "\$RESV_FILE"
      echo "[prep.sh] Reservations applied."

  - path: /opt/goad-light/run.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Render per-lab inventory, run upstream playbook chain over WinRM.
      # Assumes prep.sh has already been called (DHCP reservations on gateway,
      # Windows VMs at correct IPs).
      #
      # Architecture: follows upstream GOAD's two-account scheme (with one
      # tweak — see password note below).
      #   - Windows VM template ships with Administrator (bake-time password)
      #   - We use Administrator ONLY for an initial 'preflight-vagrant.yml'
      #     play that creates a 'vagrant' user in Administrators group.
      #   - All subsequent plays (preflight-dns + upstream chain) connect as
      #     'vagrant' with a policy-compliant password (BootstrapPwd!1 — the
      #     literal upstream value 'vagrant' fails Windows local password
      #     policy: too short, no complexity, contains username substring).
      #     The vagrant user is the scaffolding that survives ad-servers.yml's
      #     password rotation of the Administrator account (which gets rotated
      #     to lab.hosts[X].local_admin_password from upstream's config.json —
      #     different per host, preserving PTH teaching value).
      #   - We do NOT patch config.json. Per-host local_admin_password and
      #     per-domain domain_password come from upstream's data verbatim.
      #
      # Usage: run.sh LAB HOST_MAP INITIAL_USER INITIAL_PASSWORD
      #   HOST_MAP        = "name|ip|mac,name|ip|mac,..." (pipe-separated triples)
      #   INITIAL_USER    = bake-time Administrator user, typically 'Administrator'
      #   INITIAL_PASSWORD= bake-time Administrator password from the Win template
      set -e
      if [ \$# -lt 4 ]; then
        echo "Usage: \$0 LAB HOST_MAP INITIAL_USER INITIAL_PASSWORD"
        echo "  LAB              — GOAD-Light | GOAD | GOAD-Mini | NHA | SCCM | DRACARYS"
        echo "  HOST_MAP         — comma-separated 'name|ip|mac' triples"
        echo "  INITIAL_USER     — bake-time Win template admin user (typically 'Administrator')"
        echo "  INITIAL_PASSWORD — bake-time Win template admin password"
        exit 1
      fi
      LAB="\$1"; HOST_MAP="\$2"; INITIAL_USER="\$3"; INITIAL_PASSWORD="\$4"

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
      mkdir -p "\$RUNTIME"

      # NOTE: we deliberately do NOT modify upstream's config.json. Each host's
      # local_admin_password and each domain's domain_password are upstream's
      # per-host static values (e.g. dc01='8dCT-DJjgScp', dc02='NgtI75cKV+Pu').
      # The upstream invariant lab.hosts[parent_dc].local_admin_password ==
      # lab.domains[parent_domain].domain_password is what makes child-DC
      # dcpromo authentication work; touching either side breaks it.

      # Render proxmox provider inventory ({{ip_range}} is a sed placeholder)
      sed -e "s|{{ip_range}}|\${IP_RANGE}|g" "\$LAB_PROVIDER/inventory" > "\$RUNTIME/inventory_proxmox"

      # Two override files for two phases:
      #
      #   inventory_overrides_initial — used ONLY for preflight-vagrant.yml.
      #     Connects as the bake-time Administrator account to create the
      #     vagrant scaffolding user. After that one play, this inventory is
      #     never used again.
      #
      #   inventory_overrides — used for everything else (preflight-dns +
      #     full upstream chain). Connects as vagrant/vagrant. The vagrant
      #     user persists through ad-servers.yml's password rotation of
      #     Administrator (because ad-servers.yml only touches Administrator,
      #     not vagrant), so WinRM keeps working all the way through.
      #
      # ansible_port=5985 is critical — without it pywinrm picks port based
      # on transport defaults (which can resolve to 5986/HTTPS even when
      # ansible_winrm_transport=ntlm is set), and our gateway only opens 5985.
      cat > "\$RUNTIME/inventory_overrides_initial" <<INIT
      [all:vars]
      ansible_user=\${INITIAL_USER}
      ansible_password=\${INITIAL_PASSWORD}
      ansible_connection=winrm
      ansible_port=5985
      ansible_winrm_scheme=http
      ansible_winrm_transport=ntlm
      ansible_winrm_server_cert_validation=ignore
      ansible_winrm_operation_timeout_sec=400
      ansible_winrm_read_timeout_sec=500

      [localhost]
      localhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3
      INIT

      cat > "\$RUNTIME/inventory_overrides" <<OVR
      [all:vars]
      ansible_user=vagrant
      # NOTE: Windows local password policy requires 8+ chars + 3-of-4 char
      # classes (upper/lower/digit/symbol) and rejects passwords containing
      # the username (case-insensitive). 'vagrant' fails on every count, so
      # we use a policy-compliant string that doesn't contain 'vagrant'.
      ansible_password=BootstrapPwd!1
      ansible_connection=winrm
      ansible_port=5985
      ansible_winrm_scheme=http
      ansible_winrm_transport=ntlm
      ansible_winrm_server_cert_validation=ignore
      ansible_winrm_operation_timeout_sec=400
      ansible_winrm_read_timeout_sec=500
      force_dns_server=yes
      dns_server=\${GW_IP}
      two_adapters=no

      # Carve out localhost — upstream's wait*.yml playbooks target localhost
      # for sleep tasks, but [all:vars] above would otherwise force ansible to
      # WinRM-connect to localhost:5985 (which doesn't run WinRM here).
      [localhost]
      localhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3
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

      # Build an extra-vars file (YAML for safe handling of special chars in
      # the password). --extra-vars beats inventory vars at any level, which
      # we need because upstream's data/inventory may try to override our
      # connection settings via host_vars / play vars.
      cat > "\$RUNTIME/extra_vars.yml" <<EXTRA
      domain_name: "\$LAB"
      # NOTE: do NOT set data_path here. Each upstream playbook sets it via
      # 'import_playbook: data.yml vars: data_path: "../ad/{{domain_name}}/data/"'
      # so that data.yml's 'vars_files: {{data_path}}/config.json' loads the
      # upstream config. --extra-vars has the highest precedence, so any value
      # here overrides the per-playbook data_path and breaks 'lab' loading.
      # admin_user is what upstream's plays use as the prefix for domain admin
      # principals (admin_user@domain). After ad-parent_domain.yml promotes
      # DC01, the domain admin account is named 'administrator' (from the
      # local Administrator account that became the domain admin during
      # promotion). Always lowercase 'administrator' in upstream's data.
      admin_user: "administrator"
      enable_http_proxy: "no"
      # Single-NIC topology: upstream's data.yml expects a "nat_adapter" (the
      # second NIC for outbound NAT) plus a "domain_adapter" (the lane NIC).
      # Our Windows VMs only have one NIC, so we hardcode both to "Ethernet"
      # (the default connection name on fresh Win Server 2019 with virtio/
      # e1000) and force two_adapters=false. Bypasses the adapter detection
      # logic, which has a string-vs-bool bug for single-NIC.
      nat_adapter: "Ethernet"
      domain_adapter: "Ethernet"
      two_adapters: false
      number_of_interfaces: 1
      # Defensive defaults for vars referenced by upstream plays but missing
      # from GOAD-Light's data/inventory. Mirrors upstream's globalsettings.ini
      # (the canonical fallback values). Other lab variants (GOAD-Mini, full
      # GOAD, NHA) include these in their own data/inventory; GOAD-Light's
      # is just an upstream omission.
      add_route: "no"
      # GW_IP is computed earlier in run.sh from the FIRST HOST_MAP triple's
      # /24 base + ".1" — works for v1 (192.18.0.1) and v2 (10.<vxh>.<vxl>.1)
      # without modification. The literal \${GW_IP} below is preserved
      # through the cloud-init heredoc into run.sh, which expands it at
      # runtime to whatever the lane's actual gateway IP is.
      route_gateway: "\${GW_IP}"
      route_network: "10.0.0.0/8"
      http_proxy: "no"
      # DNS forwarder must be the lane gateway (\${GW_IP}), NOT a public
      # resolver. After DC promotion Windows pins DC's primary DNS to
      # 127.0.0.1; that local DNS service then forwards externally to
      # whatever dns_server_forwarder we set. The lane gateway's FORWARD
      # chain only allows lan0 → upstream via dnsmasq; lan0 → 1.1.1.1:53
      # is dropped. Routing through the lane gateway's dnsmasq keeps DNS
      # in the allowed path.
      dns_server_forwarder: "\${GW_IP}"
      # Keyboard layout hex codes — first one is the default. US only here;
      # add other codes (e.g. "0000040C" for French) if needed.
      keyboard_layouts: ["00000409"]
      # Proxy defaults (unused since enable_http_proxy=no, but referenced)
      proxy_ip: "x.x.x.x"
      proxy_port: "8080"
      ad_http_proxy: "http://x.x.x.x:8080"
      ad_https_proxy: "http://x.x.x.x:8080"
      EXTRA

      INV_FLAGS_INITIAL="-i \$LAB_DATA/inventory -i \$RUNTIME/inventory_proxmox -i \$RUNTIME/inventory_overrides_initial"
      INV_FLAGS="-i \$LAB_DATA/inventory -i \$RUNTIME/inventory_proxmox -i \$RUNTIME/inventory_overrides"

      # ---------- Patch upstream's mssql role: broken win_template + bad path ----
      # Two stacked bugs in upstream's mssql role:
      #   (1) sql_conf.ini.MSSQL_*.j2 lives in roles/mssql/files/ but
      #       win_template looks in templates/. Wrong location.
      #   (2) Even after moving to templates/, win_template + ansible-core 2.20+
      #       silently fails to render Jinja for this .ini (the {% if %} block
      #       and {{ var }} placeholders pass through verbatim, evidenced by
      #       Templar.do_template / set_temporary_context deprecation warnings).
      # Fix: use Linux 'template' on the controller (which renders Jinja
      # correctly) then 'win_copy' the rendered file to Windows.
      MSSQL_ROLE=\$GOAD_ROOT/ansible/roles/mssql
      if [ -d "\$MSSQL_ROLE/files" ] && ls "\$MSSQL_ROLE/files"/*.j2 >/dev/null 2>&1; then
        echo "==> Relocating mssql .j2 templates from files/ to templates/..."
        mkdir -p "\$MSSQL_ROLE/templates"
        mv "\$MSSQL_ROLE/files"/*.j2 "\$MSSQL_ROLE/templates/" 2>/dev/null || true
      fi
      # Replace the buggy win_template task with: render locally → win_copy.
      # The Python script lives at /opt/goad-light/patch-mssql.py (written by
      # cloud-init at bake time). Calling it from a file avoids the YAML-vs-
      # Python indentation conflict that breaks inline heredocs in user-data.
      if grep -q 'win_template:' "\$MSSQL_ROLE/tasks/main.yml" 2>/dev/null; then
        echo "==> Patching mssql role: render config locally then win_copy..."
        python3 /opt/goad-light/patch-mssql.py "\$MSSQL_ROLE/tasks/main.yml"
      fi

      # ---------- Patch upstream's child_domain role for self-healing reboot ----
      # After Install-ADDSDomain on DC02, the local SAM seals pending reboot —
      # any new WinRM session as 'vagrant' gets "credentials rejected". Upstream's
      # win_reboot task opens a fresh session for the reboot command and dies
      # there. Fix: schedule the reboot from INSIDE the running win_powershell
      # session (where vagrant still works), then replace win_reboot with
      # wait_for_connection. Idempotent — sed exits 0 if pattern already gone.
      CHILD_ROLE=\$GOAD_ROOT/ansible/roles/child_domain/tasks/main.yml
      if [ -f "\$CHILD_ROLE" ] && grep -q 'NoRebootOnCompletion' "\$CHILD_ROLE" && \\
         ! grep -q 'cybercore-self-reboot' "\$CHILD_ROLE"; then
        echo "==> Patching child_domain role for post-promotion self-reboot..."
        # Append a reboot trigger inside the same win_powershell session,
        # right before the script exits (after Install-ADDSDomain succeeds).
        sed -i 's|-Force -NoRebootOnCompletion|-Force -NoRebootOnCompletion\\n        # cybercore-self-reboot: schedule reboot from in-session\\n        Start-Process shutdown -ArgumentList "/r","/t","30","/f" -NoNewWindow -ErrorAction SilentlyContinue|' "\$CHILD_ROLE"
        # Replace win_reboot with wait_for_connection (no auth needed).
        python3 /opt/goad-light/patch-child-domain.py "\$CHILD_ROLE"
      fi

      echo "================================================================="
      echo " GOAD provisioning: \$LAB"
      echo " Lane subnet: \${IP_RANGE}.0/24   Gateway: \${GW_IP}"
      echo " Hosts: \${HOST_MAP}"
      echo " Playbook chain: \${PLAYBOOKS}"
      echo "================================================================="

      # Preflight #0: clean stale baked default route, verify egress.
      # The Windows VM template (vmid 1004) was baked while attached to the
      # v1 lane subnet (192.18.0.0/24) with gateway 192.18.0.1. That stale
      # default route persists in clones even after DHCP hands out a fresh IP
      # in the v2 subnet (10.<vxh>.<vxl>.0/24), so all internet egress dies
      # in routing — Install-PackageProvider/NuGet bootstrap fails silently
      # in the upstream chain ("NoMatchFoundForProvider").
      #
      # This preflight self-derives the correct lane gateway from each host's
      # own IPv4 (.1 of its /24), so it works for v1 and v2 without depending
      # on extra_vars or knowing the subnet ahead of time. Connects via the
      # bake-time Administrator (vagrant scaffolding user doesn't exist yet).
      # NOTE on \$ escaping: the outer cloud-init heredoc is unquoted (<< SNIPPET),
      # so EVERY PowerShell \$var inside this YAML body must be escaped as \\\$
      # in the bake source. After bake-time bash expansion, run.sh sees \$var.
      # The inner heredoc terminator <<'PFN' is single-quoted so no further
      # expansion happens at run.sh execution time — \$var lands literally in
      # preflight-network.yml as PowerShell expects.
      cat > "\$RUNTIME/preflight-network.yml" <<'PFN'
      ---
      - name: "Preflight: fix stale default route, verify egress"
        hosts: domain
        gather_facts: no
        tasks:
          # Some Windows hosts (notably srv02) bring WinRM up later than the
          # DCs. If the play starts before a host's WinRM listener is ready,
          # Ansible marks it `unreachable` on the very first task and the whole
          # GOAD chain fails — even though the host comes up fine seconds later.
          # wait_for_connection polls the connection and rides out a slow boot
          # (it catches the not-yet-reachable state and retries to `timeout`),
          # so a laggy host is WAITED FOR instead of instantly failed. Runs
          # per-host in parallel, so hosts already up don't pay the wait.
          - name: Wait for WinRM to come up (slow boots get marked unreachable, e.g. srv02)
            ansible.builtin.wait_for_connection:
              delay: 5
              sleep: 10
              timeout: 300

          - name: Compute lane gateway from host's IPv4 (.1 of /24)
            win_shell: |
              \$ip = (Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { \$_.IPAddress -like '10.*' -or \$_.IPAddress -like '192.*' } |
                Where-Object { \$_.PrefixOrigin -ne 'WellKnown' } |
                Select-Object -First 1).IPAddress
              if (-not \$ip) { throw "no usable IPv4 address found on host" }
              \$parts = \$ip.Split('.')
              "\$(\$parts[0]).\$(\$parts[1]).\$(\$parts[2]).1"
            register: lane_gw_out
            changed_when: false

          - name: Set lane_gw fact
            set_fact:
              lane_gw: "{{ lane_gw_out.stdout_lines[0] }}"

          - name: Show computed lane gateway
            debug:
              msg: "Lane gateway computed as {{ lane_gw }} (from this host's IPv4 /24)"

          - name: Remove stale default routes (any nexthop that isn't the lane gateway)
            win_shell: |
              \$expected = '{{ lane_gw }}'
              \$stale = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { \$_.NextHop -ne \$expected -and \$_.NextHop -ne '0.0.0.0' }
              foreach (\$r in \$stale) {
                Write-Host "Removing stale default route via \$(\$r.NextHop) on ifIndex \$(\$r.ifIndex)"
                Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop \$r.NextHop -Confirm:\$false -ErrorAction SilentlyContinue
              }
              if (-not \$stale) { Write-Host "No stale default routes" }

          - name: Ensure correct default route exists via the lane gateway
            win_shell: |
              \$expected = '{{ lane_gw }}'
              \$exists = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { \$_.NextHop -eq \$expected }
              if (-not \$exists) {
                \$iface = Get-NetIPAddress -AddressFamily IPv4 |
                  Where-Object { \$_.IPAddress -like '10.*' -or \$_.IPAddress -like '192.*' } |
                  Where-Object { \$_.PrefixOrigin -ne 'WellKnown' } |
                  Select-Object -First 1
                Write-Host "Adding default route via \$expected on ifIndex \$(\$iface.InterfaceIndex)"
                New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex \$iface.InterfaceIndex -NextHop \$expected -RouteMetric 0 -ErrorAction SilentlyContinue | Out-Null
              } else {
                Write-Host "Default route via \$expected already present"
              }

          # The Windows template (1004) bakes a STATIC DNS of 8.8.8.8 (see
          # bake-win-server-template.sh) so the VM is reachable during packer
          # build. In a deployed lane that public resolver is usually
          # unreachable — the lab's OPNsense egress filter blocks outbound DNS
          # to anything but its own resolver — so name resolution times out and
          # the egress check below fails even though the gateway has internet.
          # Point DNS at the lane gateway (its dnsmasq forwards to the lab's
          # sanctioned resolver). This is the SAME thing the GOAD common role
          # does later (force_dns_server / dns_server=GW_IP); the preflight just
          # needs it FIRST, before it tests egress.
          - name: Point DNS at the lane gateway (template bakes 8.8.8.8, which the lab blocks)
            win_shell: |
              \$gw = '{{ lane_gw }}'
              \$ifs = Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { \$_.IPAddress -like '10.*' -or \$_.IPAddress -like '192.*' } |
                Where-Object { \$_.PrefixOrigin -ne 'WellKnown' }
              foreach (\$i in \$ifs) {
                Set-DnsClientServerAddress -InterfaceIndex \$i.InterfaceIndex -ServerAddresses \$gw -ErrorAction SilentlyContinue
              }
              Clear-DnsClientCache -ErrorAction SilentlyContinue
              Write-Host "DNS set to \$gw on \$((\$ifs | Measure-Object).Count) adapter(s)"
            changed_when: false

          # Egress to PSGallery is INTERMITTENT on a cold lane: a deployed lane
          # resolves + egresses fine once settled (verified by hand), but the
          # preflight runs in an early-boot window — gateway still finishing its
          # Tailscale bootstrap / netfilter reconcile, DC's route+DNS just
          # changed — and the first attempt can hang past the timeout. Don't
          # fail the whole 30-min GOAD chain on one cold-start blip: RETRY.
          # Invoke-WebRequest -TimeoutSec keeps each attempt short (the old
          # WebClient.DownloadString had a ~100s default timeout, so a single
          # miss burned ~100s); `until`/retries rides out the transient.
          - name: Verify outbound HTTPS to PSGallery (TLS 1.2, retried through cold-start)
            win_shell: |
              [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
              Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/' -TimeoutSec 15 | Out-Null
              'EGRESS_OK'
            register: egress_test
            until: egress_test is succeeded
            retries: 10
            delay: 12
            changed_when: false
            # On final exhaustion the task fails with the IWR error; that, plus
            # this name, makes a genuine (non-transient) egress outage obvious.

          - name: Show egress result
            debug:
              msg: "{{ egress_test.stdout_lines | join(' | ') }}"

          # ROOT CAUSE of the GOAD regression: GOAD "used to deploy fine" because
          # the OLD Windows template had NuGet + PowerShellGet + the DSC/PKI
          # modules PRE-INSTALLED, so upstream's online installs were all no-ops.
          # The new sysprep-generalized template (bake-win-server-template.sh,
          # vmid 1004) is clean, so those tasks now RUN online — and the very
          # first, `Install-PackageProvider -Name NuGet -Force`, FAILS headlessly
          # ("NoMatchFoundForProvider" + "NonInteractive mode ... Prompt
          # functionality is not available"): bare `-Force` does NOT bootstrap the
          # provider non-interactively — it needs `-ForceBootstrap`.
          #
          # Fix in ONE place: as Administrator (before the upstream roles run as
          # vagrant), bootstrap NuGet correctly, trust PSGallery, and PRE-STAGE
          # every PSGallery module the GOAD chain installs, machine-wide. The
          # upstream `win_psmodule` / `Install-Module` tasks then find each module
          # already present (state: present) and no-op — restoring the old
          # template's behavior without re-baking Windows. Module list = every
          # name from `grep win_psmodule|Install-Module` across the GOAD roles:
          #   common:               ComputerManagementDsc, xNetworking
          #   domain_controller/child_domain: xDnsServer, ActiveDirectoryDSC
          #   adcs:                 PSPKI, xAdcsDeployment
          # (PowerShellGet upgrade is left to upstream — it succeeds once NuGet is
          # present.) PSGallery egress is verified just above. Retried for the
          # same cold-start reason as the egress check.
          - name: Pre-stage GOAD PS deps (NuGet + DSC/PKI modules) so upstream installs no-op
            win_shell: |
              [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
              Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Scope AllUsers | Out-Null
              Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
              foreach (\$m in 'ComputerManagementDsc','xNetworking','xDnsServer','ActiveDirectoryDSC','PSPKI','xAdcsDeployment') {
                if (-not (Get-Module -ListAvailable -Name \$m)) {
                  Install-Module -Name \$m -Repository PSGallery -Force -AllowClobber -Scope AllUsers -ErrorAction Stop | Out-Null
                }
              }
              'PSDEPS_OK'
            register: psdeps
            until: psdeps is succeeded
            retries: 5
            delay: 12
            changed_when: false
      PFN
      echo ""
      echo ">>>>>>>>>>>>>>>>>>>>>> preflight-network.yml <<<<<<<<<<<<<<<<<<<<<<"
      ansible-playbook \$INV_FLAGS_INITIAL "\$RUNTIME/preflight-network.yml" --extra-vars "@\$RUNTIME/extra_vars.yml"

      # Preflight #1: create the 'vagrant' scaffolding user on every Windows
      # host. This connects via the bake-time Administrator account (the only
      # account that exists at this point). After this play succeeds, ALL
      # subsequent plays connect as vagrant/vagrant, so we never depend on
      # the Administrator account again — and ad-servers.yml is free to
      # rotate the Administrator password to per-host upstream values.
      cat > "\$RUNTIME/preflight-vagrant.yml" <<PFV
      ---
      - name: "Preflight: create 'vagrant' scaffolding user on all Windows hosts"
        hosts: domain
        gather_facts: no
        tasks:
          - name: Ensure vagrant local user exists in Administrators
            win_user:
              name: vagrant
              # Must satisfy Windows local password policy: 8+ chars,
              # 3-of-4 char classes, and no 'vagrant' substring (the user-
              # name check is case-insensitive). MUST match ansible_password
              # in inventory_overrides — these are the connection credentials
              # for every play after this preflight.
              password: BootstrapPwd!1
              state: present
              password_never_expires: yes
              account_disabled: no
              groups:
                - Administrators
              groups_action: add
      PFV
      echo ""
      echo ">>>>>>>>>>>>>>>>>>>>>> preflight-vagrant.yml <<<<<<<<<<<<<<<<<<<<<<"
      ansible-playbook \$INV_FLAGS_INITIAL "\$RUNTIME/preflight-vagrant.yml" --extra-vars "@\$RUNTIME/extra_vars.yml"

      # Preflight #2: ensure DNS Server feature is installed on every DC.
      # Upstream's child_domain role assumes Get-DnsServerForwarder is available
      # immediately after the child DC's first reboot, but Install-ADDSDomain
      # doesn't always pull in DNS-Server-Tools. Install it explicitly so the
      # 'Configure DNS Forwarders' task doesn't blow up.
      # Upstream's inventory groups DCs under [dc]; targeting that group catches
      # every DC across all lab variants. Connects as vagrant (so this also
      # validates the scaffolding user works before the long chain runs).
      cat > "\$RUNTIME/preflight-dns.yml" <<PREFLIGHT
      ---
      - name: "Preflight: ensure DNS Server feature on all DCs"
        hosts: dc
        gather_facts: no
        tasks:
          - name: Install DNS Server + tools
            win_feature:
              name: DNS,RSAT-DNS-Server
              include_management_tools: yes
              state: present
      PREFLIGHT
      echo ""
      echo ">>>>>>>>>>>>>>>>>>>>>> preflight-dns.yml <<<<<<<<<<<<<<<<<<<<<<"
      ansible-playbook \$INV_FLAGS "\$RUNTIME/preflight-dns.yml" --extra-vars "@\$RUNTIME/extra_vars.yml" || \\
        echo "WARNING: DNS preflight failed — continuing anyway, may fail later"

      for pb in \$PLAYBOOKS; do
        echo ""
        echo ">>>>>>>>>>>>>>>>>>>>>> \$pb <<<<<<<<<<<<<<<<<<<<<<"
        ansible-playbook \$INV_FLAGS "\$pb" --extra-vars "@\$RUNTIME/extra_vars.yml"
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
  # Allow root password login (bootcmd set the password but didn't touch sshd
  # config because systemctl reload at init-local can block). Safe here in
  # final stage — sshd is up.
  - [ sh, -c, 'sed -i "s/^#*PermitRootLogin.*/PermitRootLogin yes/; s/^#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config && systemctl reload ssh' ]
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

# Bake-time cloud-init: default user, our snippet for the bake-only setup.
# --nameserver overrides whatever DHCP advertises — survives a FreeIPA outage.
qm set $VMID \
  --ciuser root \
  --cipassword "$TEMPLATE_PASSWORD" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
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

# ---------- 4b. VERIFY cloud-init actually completed (not just user kill) ----------
# The poll above only knows the VM stopped; it can't tell "power_state: poweroff
# fired naturally after cloud-init finished" from "user `qm stop`'d a hung VM".
# Mount the rootfs and check for the bake-complete marker (written by runcmd).
# Without this guard, a half-baked template can ship: packages not installed,
# /opt/goad missing, runcmd never executed.
echo "==> Verifying cloud-init wrote the bake-complete marker..."
VERIFY_DEV=$(rbd map ${STORAGE}/vm-${VMID}-disk-1 --id admin 2>/dev/null) || {
  # Fallback for non-Ceph storages: just trust the stop and warn
  echo "WARNING: could not map ${STORAGE}/vm-${VMID}-disk-1 for verification — proceeding without marker check"
  VERIFY_DEV=""
}
if [ -n "$VERIFY_DEV" ]; then
  # rbd map + partprobe is racy: the device node appears before the kernel
  # finishes re-reading the partition table. Retry until p1 surfaces (or give
  # up after ~10s and warn).
  for _ in 1 2 3 4 5; do
    partprobe "$VERIFY_DEV" 2>/dev/null || true
    udevadm settle 2>/dev/null || true
    [ -b "${VERIFY_DEV}p1" ] && break
    sleep 2
  done
  VERIFY_MOUNT=$(mktemp -d)
  if mount "${VERIFY_DEV}p1" "$VERIFY_MOUNT" 2>/dev/null; then
    # /var/lib/cloud/instance is an ABSOLUTE symlink ('-> /var/lib/cloud/instances/<iid>')
    # that resolves against the HOST'S filesystem when accessed via $VERIFY_MOUNT,
    # not the mounted disk's. Search the actual instance dirs instead.
    MARKER_FOUND=$(find "$VERIFY_MOUNT/var/lib/cloud/instances/" -maxdepth 2 -name bake-complete 2>/dev/null | head -1)
    if [ -z "$MARKER_FOUND" ]; then
      echo ""
      echo "==================================================================="
      echo "  ERROR: bake-complete marker missing — cloud-init did NOT finish"
      echo "==================================================================="
      echo "  The VM stopped but cloud-init never reached the runcmd that writes"
      echo "  /var/lib/cloud/instance/bake-complete. Causes:"
      echo "    - Network hang during apt install / git clone / ansible-galaxy"
      echo "    - User manually qm-stop'd a still-running VM"
      echo "    - YAML parse error (unlikely if you ran the python yaml check)"
      echo ""
      echo "  Last 80 lines of cloud-init-output.log:"
      tail -80 "$VERIFY_MOUNT/var/log/cloud-init-output.log" 2>/dev/null \
        | sed 's/^/    /'
      echo "==================================================================="
      umount "$VERIFY_MOUNT"
      rmdir "$VERIFY_MOUNT"
      rbd unmap "$VERIFY_DEV"
      exit 1
    fi
    echo "==> bake-complete marker present at $MARKER_FOUND — cloud-init ran to completion."
    umount "$VERIFY_MOUNT"
  else
    echo "WARNING: could not mount ${VERIFY_DEV}p1 — proceeding without marker check"
    echo "         (verify manually: rbd map ${STORAGE}/vm-${VMID}-disk-1 --id admin"
    echo "                           partprobe /dev/rbdN; mount /dev/rbdNp1 /mnt/...)"
  fi
  rmdir "$VERIFY_MOUNT" 2>/dev/null || true
  # rbd may have auto-released; tolerate unmap failure so set -e doesn't abort
  # the bake before we strip cicustom + template the VM.
  rbd unmap "$VERIFY_DEV" 2>/dev/null || true
fi

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
