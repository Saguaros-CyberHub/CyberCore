#!/bin/bash
# ============================================================================
# bake-ubuntu-lab-template.sh
# ----------------------------------------------------------------------------
# ############################################################################
# # THIS SCRIPT HAS NEVER BEEN EXECUTED.                                     #
# #                                                                          #
# # Not one line of it has run on a Proxmox node, against a real Ubuntu      #
# # cloud image, or against any VM. No template with this VMID exists on any #
# # cluster, so nothing here has been validated end to end and NOTHING HERE  #
# # SHOULD BE TRUSTED AS WORKING. Specifically unverified:                   #
# #                                                                          #
# #   - that the jammy cloud image boots at all under the q35 + OVMF machine #
# #     shape copied from bake-goad-controller-vm.sh (the image ships both a #
# #     bios_grub and an ESP partition, so it SHOULD; nobody has watched it) #
# #   - that `qm disk import` leaves the volume as `unused0` on this cluster's#
# #     storage, which is what section 3 keys the scsi0 attach off           #
# #   - that DISK_GROW's +58G survives growpart/resize2fs into a root        #
# #     filesystem >= MIN_ROOT_GB. The pre-seal check MEASURES it rather     #
# #     than assuming, and that check has itself never run                   #
# #   - that Ubuntu's qemu-guest-agent answers `qm guest exec` on this VLAN  #
# #     within the boot budget. The whole marker-polling loop in section 4   #
# #     depends on it and has no fallback                                    #
# #   - that python3-yaml is present early enough for the netplan static-    #
# #     address check in bake-markers.sh (cloud-init depends on it, so it    #
# #     should be in the image before our packages land; unproven)           #
# #   - that GOAD's elk / wazuh roles are actually happy on this image. This #
# #     script installs NO SIEM SOFTWARE (see below), so the first proof of  #
# #     that is a real `install_extension` run in a real lane                #
# #                                                                          #
# # Treat the FIRST run of this script as the experiment, not the deploy.    #
# # Every pre-seal marker below exists so that experiment fails loudly at    #
# # bake time instead of quietly in a classroom.                             #
# ############################################################################
#
# ONE generic Ubuntu 22.04 cloud-init template. It is the machine GOAD's `elk`
# and `wazuh` extensions land on, and it is also a perfectly good `lx01` Linux
# domain member. There is exactly one image because there is nothing in it that
# differs between those three roles.
#
# ----------------------------------------------------------------------------
# WHY THERE IS NO SIEM SOFTWARE IN THIS IMAGE, AND WHY THAT IS THE POINT
# ----------------------------------------------------------------------------
# Upstream GOAD's flow is: install a lab, `load <instance_id>`, then
# `install_extension elk`. That adds ONE Ubuntu 22.04 server (elk at
# {{ip_range}}.50, wazuh at .51) and runs the extension's own Ansible —
# roles/elk on the server plus roles/logs_windows on every host in [domain]; or
# roles/wazuh_manager plus roles/wazuh_agent on [domain] and
# roles/wazuh_agent_linux on [linux_domain].
#
# CyberCore is going to run that IN THE LANE, at deploy time, exactly as
# upstream intends. So this image must be a blank Ubuntu server that Ansible can
# reach — not a pre-cooked SIEM. Baking Elasticsearch or Wazuh in here would
# mean the extension's roles arrive at a machine that already has half of what
# they install, in a version they did not choose, and the resulting divergence
# surfaces as role tasks that "succeed" against state they did not create.
#
# DO NOT ADD ELASTICSEARCH. DO NOT ADD WAZUH. If you find yourself wanting to,
# what you actually want is a golden-image deploy path, and that is a different
# design from this one — not a bigger version of this file.
#
# ----------------------------------------------------------------------------
# THE LANE HAS INTERNET, AND EVERYTHING ABOVE DEPENDS ON THAT
# ----------------------------------------------------------------------------
# Several comments in front-end/src/utils/goad-deploy.js (around the mssql
# offline-install fixes) assert "the lane has no internet". THAT IS FALSE, and
# it is the single most misleading claim in this codebase. Verified in
# infrastructure/proxmox-templates/sdn-templates/bake-lane-gateway-v3.sh:
#
#   - wan0 is described as "internet uplink (NAT)"
#   - iptables -t nat -A POSTROUTING -s "$NET" -o wan0 -j MASQUERADE, for BOTH
#     lane subnets
#   - iptables -A FORWARD -i ext0 -o wan0 -j ACCEPT
#     iptables -A FORWARD -i int0 -o wan0 -j ACCEPT
#   - the only DROPs are scoped '-d 100.100.0.0/16' (CYBERCORE-LAB-DROP), which
#     contains LAB-BACKBONE traffic, not internet traffic
#
# A deployed lane has full internet egress. That is why `install_extension` can
# genuinely run in-lane at deploy time, and it is why this image can stay empty:
# GOAD's roles/elk pulls artifacts.elastic.co and roles/wazuh_manager pulls
# wazuh-install.sh, both from inside the lane, at deploy time.
#
# If you are reading this because an in-lane install failed with a DNS or
# routing error, check the lane's gateway before you check this image. The
# image has no opinion about egress at all.
#
# ----------------------------------------------------------------------------
# THE OCTET PROBLEM IS NOT SOLVED HERE, AND MUST NOT BE
# ----------------------------------------------------------------------------
# Upstream's GOAD-main/extensions/elk/inventory pins 'elk
# ansible_host={{ip_range}}.50'. INFRA_IP_OCTETS.Kali is ALSO 50. On v3 those
# are different segments and never met; on v1/v2 there is ONE flat lan0 and they
# are the same address on the same subnet. Two dhcp-host lines claiming one
# address make dnsmasq REFUSE TO START, which takes DHCP down for the WHOLE
# lane. CyberCore therefore places elk at .24 (GOAD_EXTENSIONS.elk.ipOctet in
# front-end/src/utils/goad-deploy.js).
#
# That rewrite belongs in the controller's run.sh, in the same sed pass that
# already renders {{ip_range}} into inventory_proxmox — NOT in this image and
# NOT in the vendored upstream inventory. There is nothing address-shaped in
# this template on purpose: see "DHCP, AND NOTHING BUT DHCP" below.
#
# wazuh at .51 is upstream's own octet and is free on v1/v2 — no rewrite needed.
#
# ----------------------------------------------------------------------------
# DHCP, AND NOTHING BUT DHCP
# ----------------------------------------------------------------------------
# This image carries NO static address, and section 5's pre-seal check refuses
# to seal one that does.
#
# The lane's MAC-pinned dnsmasq reservation is the only thing that decides this
# machine's IP: challenge-lane-deployer.js clones with a deterministic MAC
# (goadDeploy.macForOctet) and sets `ipconfig0: ip=dhcp`, and the gateway hands
# out the reserved address for that MAC. A static address baked into the image
# and a reservation on the gateway that disagrees with it do not produce an
# error anywhere. They produce a machine that is up, healthy, pingable at the
# wrong address, and that every agent in the lane ships its logs past. "The
# agents ship nowhere" is exceptionally hard to diagnose from that end, which is
# why it is checked HERE, where it is cheap.
#
# One related trap, documented rather than papered over: Ubuntu's netplan/
# systemd-networkd sends an RFC 4361 client identifier derived from
# /etc/machine-id, not the raw MAC. dnsmasq still matches `dhcp-host=<MAC>,<IP>`
# on the hardware address, so the reservation works — but two clones sharing one
# machine-id would share one DUID, and that IS a lease collision. The seal in
# section 6 truncates /etc/machine-id so every clone generates its own, and
# MACHINE_ID_EMPTY is verified after the clean rather than assumed. If a future
# lane ever does exhibit lease weirdness, the next lever is
# `dhcp-identifier: mac` in the clone's netplan — deliberately NOT done here,
# because editing cloud-init's rendered netplan from inside the image is
# fragile in a way this failure has not yet earned.
#
# ----------------------------------------------------------------------------
# HOW THE CONTROLLER REACHES THIS MACHINE
# ----------------------------------------------------------------------------
# Upstream's extension inventory says `ansible_connection=ssh` with NO
# credentials — upstream supplies those from its global inventory. Ours come
# from run.sh's inventory_overrides on the GOAD controller, which is where every
# other connection variable is already set. This file's only job is to make sure
# the key those overrides name actually opens the door.
#
# KEY-BASED, NOT PASSWORD-BASED. The controller already has a keypair for its
# controller->gateway trust link (bake-goad-controller-vm.sh generates it at
# /root/.ssh/goad-controller-deploy.key on the Proxmox node and bakes the
# private half into template 1700). This image bakes the PUBLIC half, so the
# controller can SSH here with no password anywhere.
#
# GOAD_CONTROLLER_PUBKEY is REQUIRED and has NO DEFAULT. A silently absent key
# produces a lane where the SIEM box boots fine and Ansible cannot reach it at
# all — `install_extension` then fails on the very first task of roles/elk, in a
# lane, in front of a class. Section 0 refuses to bake without it; the hand-off
# block at the bottom says exactly where to get the value.
#
# The key is installed THREE ways, on purpose, because they fail differently:
#
#   /etc/ssh/cybercore-controller-authorized_keys   named by an sshd_config
#       drop-in as a second AuthorizedKeysFile. This one is outside every home
#       directory, so it works for whatever per-lane username `ciuser` invents
#       (challenge-lane-deployer.js sets ciuser/cipassword per clone), and
#       cloud-init cannot rewrite it.
#   /root/.ssh/authorized_keys                      the ordinary path, so the
#       key still works if the drop-in is ever lost or overridden.
#   ~${TEMPLATE_USER}/.ssh/authorized_keys          same, for the unprivileged
#       account, since both extension playbooks run `become: yes` and the bake
#       user has NOPASSWD sudo.
#
# sshpass is installed too, because upstream's docs list it as a prerequisite
# and a future extension may want it. NOTHING HERE DEPENDS ON IT.
#
# ----------------------------------------------------------------------------
# SIZING: THE TEMPLATE IS SIZED FOR THE HEAVIEST TENANT
# ----------------------------------------------------------------------------
# GOAD's roles/wazuh_manager runs `wazuh-install.sh -a -i` — the ALL-IN-ONE
# installer: manager plus indexer plus dashboard on one box. Wazuh's own sizing
# guidance for roughly 25 agents is ~50 GB of disk, 4 CPU and 8 GB RAM. ELK is
# lighter (roles/elk installs elasticsearch/kibana/logstash at 7.x), and lx01 is
# lighter still.
#
# One image serves all three, so it is sized for the heavy case: DISK_GROW
# defaults to +58G on top of the ~2.2 GB cloud image, and the pre-seal check
# refuses to seal a root filesystem smaller than MIN_ROOT_GB (50).
#
# WHAT CYBERCORE CAN OVERRIDE PER VM, AND WHAT IT CANNOT:
#   CPU and RAM  — freely, in both directions. lane-deployer.js applyResources()
#                  PUTs cores/memory, so `spec.vms[].resources` can size an lx01
#                  clone back down to 2 vCPU / 2 GB.
#   DISK         — GROW ONLY. applyResources() reads Proxmox's own limitation
#                  and turns a smaller disk_gb into a no-op with a warning
#                  ("disk stays at the template's NNG"). So this template's disk
#                  size is a FLOOR for every clone, lx01 included. On thin
#                  storage (vmpool/Ceph RBD) an untouched 58 GB costs
#                  essentially nothing; on a thick-provisioned storage it costs
#                  all of it. If a site is thick-provisioned and lx01 clones are
#                  numerous, bake a SECOND template from this same script with
#                  DISK_GROW=8G under a different VMID rather than shrinking
#                  this one, and point GOAD_EXTENSIONS.lx01.template_vmid there.
#
# Run on a Proxmox node with internet access. Idempotent: refuses if VMID
# already exists. To re-bake: qm destroy 1011 --purge
# ============================================================================
set -euo pipefail

# ---------- Identity ----------
# 1011. 1001-1008 are taken by the OS/base templates (see
# front-end/migrations/013_vm_template_catalog.sql and the sibling bake
# scripts); 1699/1700/1701/1702/1710 are Kali, the GOAD controller, its frozen
# rollback, DVWA/Juice-Shop and CyberSaguaros. 1009 and 1010 are NOT part of
# this design and are left free deliberately.
#
# COLLISION CHECK PERFORMED AT AUTHORING TIME: nothing in this repository
# registers 1011 — not a bake script, not a catalog seed, not goad-deploy.js.
# The only appearances of 1009/1010 anywhere are two in-memory unit-test
# fixtures (front-end/test/console-designation.test.js and
# front-end/test/ciab-v3-default.test.js) that invent VMIDs to exercise a
# resolver; they name no real template. Re-check on the cluster before baking —
# a repo grep cannot see a template somebody made by hand.
VMID=${VMID:-1011}
NAME=${NAME:-ubuntu-lab-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"

# ---------- Base image ----------
# UBUNTU 22.04 SPECIFICALLY, and the version is not incidental. Upstream's
# Ludus provider note for BOTH extensions pins `ubuntu-22.04-x64-server`
# (extensions/elk/providers/ludus/config.yml and the wazuh equivalent), Wazuh
# 4.8's all-in-one installer supports 22.04, and Elastic 8.x supports it too.
# Moving to 24.04 means re-proving all three, and the way that failure shows up
# is a role that installs cleanly and a service that will not start.
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img}"
CLOUD_IMG_LOCAL="${CLOUD_IMG_LOCAL:-/var/lib/vz/template/iso/jammy-server-cloudimg-amd64.img}"
# Set to 1 to bake from an image that does not look like 22.04. The guest-side
# OS_VERSION_ID check in section 5 still runs and still fails the bake unless
# this is set, so this is one switch, not two.
ALLOW_NON_JAMMY="${ALLOW_NON_JAMMY:-0}"

# ---------- Bake-time plumbing ----------
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"            # bake-time VLAN for internet (empty to disable)
# Explicit DNS for the bake VM rather than trusting whatever DHCP advertises.
# Same reasoning as the other bakes on this cluster: FreeIPA at 100.100.20.20
# has been the DHCP-advertised default and dies sometimes; OPNsense Unbound at
# 100.100.0.1 is the orchestrator's resolver and recurses externally.
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
BAKE_TIMEOUT="${BAKE_TIMEOUT:-1500}"    # seconds to wait for cloud-init

# ---------- Sizing (see the header) ----------
MEMORY=${MEMORY:-8192}                  # Wazuh all-in-one, ~25 agents
CORES=${CORES:-4}                       # ditto
DISK_GROW=${DISK_GROW:-58G}             # on top of the ~2.2G cloud image
MIN_ROOT_GB=${MIN_ROOT_GB:-50}          # pre-seal floor; Wazuh's own guidance

# ---------- Accounts ----------
# The repo's lab convention: user and root both get `bake-debug`. This is a lab
# template that lives on an isolated lane behind a NAT gateway and is never
# published to the internet; it is written down here rather than discovered
# later. Per-clone, challenge-lane-deployer.js overrides ciuser/cipassword.
TEMPLATE_USER="${TEMPLATE_USER:-ubuntu}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-bake-debug}"

# ---------- The controller's public key: REQUIRED, no default ----------
# See the header. Where to get it is in hand-off section 1.
GOAD_CONTROLLER_PUBKEY="${GOAD_CONTROLLER_PUBKEY:-}"

# The sshd_config drop-in names this file as a second AuthorizedKeysFile so the
# controller key is valid for EVERY account, including whatever username the
# per-lane `ciuser` invents.
CTRL_KEY_FILE=/etc/ssh/cybercore-controller-authorized_keys

# ============================================================================
# 0. Sanity — everything that can be refused before spending 20 minutes
# ============================================================================
if qm status "$VMID" >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status "$VMID" >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
  exit 1
fi

FAIL_ARGS=0

# ---- The controller public key ----
if [ -z "$GOAD_CONTROLLER_PUBKEY" ]; then
  echo "ERROR: GOAD_CONTROLLER_PUBKEY is required and has no default." >&2
  echo "" >&2
  echo "       Without it this bake produces a lane where the SIEM box boots" >&2
  echo "       perfectly and Ansible cannot reach it at all. 'install_extension elk'" >&2
  echo "       then dies on the first task of roles/elk, in a lane, at deploy time." >&2
  echo "       A defaulted or absent key is exactly the failure this refusal exists" >&2
  echo "       to prevent, so there is no way to proceed without one." >&2
  echo "" >&2
  echo "       The value is the PUBLIC half of the controller->gateway keypair that" >&2
  echo "       bake-goad-controller-vm.sh generates. On the Proxmox node where that" >&2
  echo "       script ran:" >&2
  echo "" >&2
  echo "           cat /root/.ssh/goad-controller-deploy.key.pub" >&2
  echo "" >&2
  echo "       (that path is DEPLOY_KEY_PATH in bake-goad-controller-vm.sh; the" >&2
  echo "        matching private half is baked into controller template 1700 at" >&2
  echo "        /root/.ssh/id_ed25519, and the same public half is already in the" >&2
  echo "        lane gateway's authorized_keys via" >&2
  echo "        ../sdn-templates/patch-goad-gateway-key.sh)" >&2
  echo "" >&2
  echo "       Then:" >&2
  echo "" >&2
  echo "           GOAD_CONTROLLER_PUBKEY=\"\$(cat /root/.ssh/goad-controller-deploy.key.pub)\" \\" >&2
  echo "             $0" >&2
  echo "" >&2
  echo "       If that file does not exist, bake the controller FIRST. Generating a" >&2
  echo "       fresh keypair here would produce a key no controller holds." >&2
  FAIL_ARGS=1
else
  # Strict syntactic validation. The key is interpolated into a shell heredoc
  # and into YAML further down; base64 delivery covers the escaping, but a
  # malformed key is worth catching as a named error rather than as an sshd that
  # silently ignores an unparseable authorized_keys line at deploy time.
  if printf '%s' "$GOAD_CONTROLLER_PUBKEY" | grep -q '[[:cntrl:]]'; then
    echo "ERROR: GOAD_CONTROLLER_PUBKEY contains a newline or control character." >&2
    echo "       An authorized_keys entry is exactly one line. Did you paste the" >&2
    echo "       PRIVATE key by mistake?" >&2
    FAIL_ARGS=1
  elif printf '%s' "$GOAD_CONTROLLER_PUBKEY" | grep -q 'PRIVATE KEY'; then
    echo "ERROR: GOAD_CONTROLLER_PUBKEY looks like a PRIVATE key." >&2
    echo "       Use the .pub half. The private half belongs in the controller" >&2
    echo "       template and nowhere else — least of all in an image every" >&2
    echo "       student's lane gets a copy of." >&2
    FAIL_ARGS=1
  elif ! printf '%s' "$GOAD_CONTROLLER_PUBKEY" \
        | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,3}( [A-Za-z0-9@._+-]*)?$'; then
    echo "ERROR: GOAD_CONTROLLER_PUBKEY is not a well-formed OpenSSH public key." >&2
    echo "       Expected: '<type> <base64>[ <comment>]', where the optional comment is" >&2
    echo "       limited to [A-Za-z0-9@._+-]." >&2
    echo "       Got     : ${GOAD_CONTROLLER_PUBKEY:0:60}..." >&2
    echo "" >&2
    echo "       The comment charset is narrower than OpenSSH allows ON PURPOSE. This" >&2
    echo "       string is interpolated into a YAML plain scalar (the user's" >&2
    echo "       ssh_authorized_keys entry) inside an UNQUOTED shell heredoc; a ': ' or" >&2
    echo "       a ' #' or a quote in the comment re-parses the whole cloud-config, and" >&2
    echo "       cloud-init's response to that is to skip the module and carry on." >&2
    echo "       ssh-keygen's default comment is user@host, which passes. If yours does" >&2
    echo "       not, strip it — the comment has no operational meaning here:" >&2
    echo "           GOAD_CONTROLLER_PUBKEY=\"\$(awk '{print \$1, \$2}' \\" >&2
    echo "             /root/.ssh/goad-controller-deploy.key.pub)\"" >&2
    FAIL_ARGS=1
  fi
fi

# ---- The base image really is 22.04 ----
case "$CLOUD_IMG_URL" in
  *jammy*|*22.04*|*22_04*) : ;;
  *)
    if [ "$ALLOW_NON_JAMMY" != "1" ]; then
      echo "ERROR: CLOUD_IMG_URL does not look like Ubuntu 22.04 (jammy):" >&2
      echo "         $CLOUD_IMG_URL" >&2
      echo "       Upstream GOAD pins ubuntu-22.04-x64-server for BOTH the elk and" >&2
      echo "       wazuh extensions, and Wazuh 4.8 / Elastic 8.x support is what that" >&2
      echo "       pin is buying. A newer release does not fail at bake time; it fails" >&2
      echo "       weeks later as a role that installs cleanly and a service that will" >&2
      echo "       not start." >&2
      echo "       If this URL is a local mirror of jammy, re-run with ALLOW_NON_JAMMY=1." >&2
      FAIL_ARGS=1
    else
      echo "WARNING: ALLOW_NON_JAMMY=1 — baking from a non-jammy-looking URL." >&2
    fi
    ;;
esac

# ---- Nothing SIEM-shaped is welcome here ----
# Not a tombstone (this script never had these); a guard. Someone reaching for
# them has misread the design, and the fix is upstream's install_extension, not
# a bigger bake. Refusing is cheap and the alternative is an image that quietly
# disagrees with the roles that land on it.
for BADVAR in INSTALL_ELK INSTALL_WAZUH ELK_VERSION WAZUH_VERSION ELASTIC_VERSION; do
  if [ -n "$(eval "printf '%s' \"\${$BADVAR:-}\"")" ]; then
    echo "ERROR: $BADVAR is set. This template installs NO SIEM software." >&2
    echo "       GOAD's own Ansible installs Elasticsearch/Wazuh IN THE LANE at deploy" >&2
    echo "       time (roles/elk, roles/wazuh_manager), which is the entire point of" >&2
    echo "       the design. Pre-cooking any of it here makes those roles arrive at a" >&2
    echo "       machine that already has half of what they install, in a version they" >&2
    echo "       did not choose. Unset $BADVAR and re-run." >&2
    FAIL_ARGS=1
  fi
done

[ "$FAIL_ARGS" -ne 0 ] && exit 1

# ---- Snippet storage ----
# Cloud-init custom user-data has to live on a storage with content=snippets.
# Default Proxmox storages don't have it on. Same helper as the sibling bakes.
pick_snippet_storage() {
  if [ -n "${SNIPPET_STORAGE:-}" ]; then
    if pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SNIPPET_STORAGE"; then
      echo "$SNIPPET_STORAGE"; return 0
    fi
    echo "ERROR: SNIPPET_STORAGE='$SNIPPET_STORAGE' set but that storage has no 'snippets' content." >&2
    echo "       Run: pvesm set $SNIPPET_STORAGE --content <existing>,snippets" >&2
    return 1
  fi
  local first
  first=$(pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then echo "$first"; return 0; fi
  echo "==> No storage has 'snippets' content enabled. Enabling on 'local'..." >&2
  local cur
  cur=$(awk '/^[a-z]+: local$/{flag=1} flag && /^\s*content/{print $2; flag=0}' /etc/pve/storage.cfg)
  [ -z "$cur" ] && cur="iso,vztmpl,backup"
  [[ "$cur" != *snippets* ]] && pvesm set local --content "${cur},snippets" >&2
  echo "local"
}
SNIPPET_STORAGE=$(pick_snippet_storage)

USERDATA_FILE="ubuntu-lab-bake-${VMID}.yaml"
USERDATA_PATH="$(pvesm path "${SNIPPET_STORAGE}:snippets/${USERDATA_FILE}" 2>/dev/null || true)"
if [ -z "$USERDATA_PATH" ]; then
  case "$SNIPPET_STORAGE" in
    local)  USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
    cephfs) USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
    *)      USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  esac
fi
mkdir -p "$(dirname "$USERDATA_PATH")"
umask 077

CTRL_KEY_FP="$(printf '%s\n' "$GOAD_CONTROLLER_PUBKEY" | ssh-keygen -lf - 2>/dev/null || echo 'unreadable')"

echo "==> Baking $NAME as VMID $VMID"
echo "    Base image    : $CLOUD_IMG_URL"
echo "    Snippet store : $SNIPPET_STORAGE ($USERDATA_PATH)"
echo "    Sizing        : ${CORES} vCPU / ${MEMORY} MB / +${DISK_GROW} (floor ${MIN_ROOT_GB}G)"
echo "    Controller key: $CTRL_KEY_FP"
echo "    SIEM software : NONE. GOAD's Ansible installs it in-lane. This is by design."

# ============================================================================
# 0b. Guest helper: collect every pre-seal marker in one place
# ============================================================================
# Written here as real shell, then base64'd into cloud-init write_files, for the
# same reason bake-cybr400-loggen-template.sh and bake-caldera-server.sh do it:
# the userdata heredoc below is UNQUOTED so ${VAR} expands, which means anything
# containing $, backticks or backslashes cannot be pasted into it literally.
# `encoding: b64` sidesteps the entire class of escaping bug.
#
# It also leaves a re-runnable diagnostic in the guest: after the bake, or in a
# lane months later, `/opt/cybercore/bake-markers.sh && cat /etc/cybercore-bake.env`
# answers "is this image still shaped the way the bake sealed it?".
read -r -d '' MARKERS_SH <<'MARKERS_EOF' || true
#!/bin/sh
# Collect pre-seal markers into /etc/cybercore-bake.env. Idempotent: truncates
# and rewrites. Writes NOTHING named BAKE_COMPLETE — the bake host polls for
# that separately, appended by runcmd after this script returns, so a marker run
# that dies halfway can never look like a finished bake.
set -u

OUT=/etc/cybercore-bake.env
: > "$OUT"
m() { printf '%s=%s\n' "$1" "$2" >> "$OUT"; }
yn() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

# ---- Which OS actually got baked ----
ID=""; VERSION_ID=""
[ -r /etc/os-release ] && . /etc/os-release
m OS_ID "${ID:-unknown}"
m OS_VERSION_ID "${VERSION_ID:-unknown}"

# ---- The guest agent. CyberCore dispatches to lane VMs over guest-exec; a VM
#      without it is opaque to the orchestrator — it looks perfectly healthy
#      from Proxmox and nothing can be run inside it. ----
m GUEST_AGENT_INSTALLED "$(yn command -v qemu-ga)"
m GUEST_AGENT_ENABLED   "$(yn systemctl is-enabled qemu-guest-agent)"
m GUEST_AGENT_ACTIVE    "$(yn systemctl is-active qemu-guest-agent)"
# Debian/Ubuntu's package does not blacklist RPCs the way the RHEL one does, but
# /etc/default/qemu-guest-agent can carry --blacklist / --block-rpcs in
# DAEMON_ARGS, and if it ever does, every dispatch returns HTTP 596 while
# guest-ping and network-get-interfaces keep succeeding. Cheap to assert.
if grep -qE '(--blacklist|--block-rpcs|-b[[:space:]])' /etc/default/qemu-guest-agent 2>/dev/null; then
  m GUEST_AGENT_ARGS_CLEAN no
else
  m GUEST_AGENT_ARGS_CLEAN yes
fi

# ---- An interpreter for Ansible. Every GOAD role that touches this box needs
#      one, and python3-apt is what the `apt:` module actually binds to —
#      roles/elk is nothing but apt/apt_key/apt_repository tasks. ----
m PYTHON3      "$(command -v python3 2>/dev/null || echo none)"
m PYTHON3_APT  "$(yn python3 -c 'import apt')"
m PYTHON3_YAML "$(yn python3 -c 'import yaml')"

# ---- SSH: the controller must get in without a password, and staff must be
#      able to get in with one. ----
# sshd is in /usr/sbin, which is on root's PATH but not on every PATH a
# cloud-init runcmd or a later diagnostic might carry. Resolve it once.
SSHD_BIN="$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)"
m SSHD_CONFIG_VALID "$(yn "$SSHD_BIN" -t)"
SSHD_T="$("$SSHD_BIN" -T 2>/dev/null || true)"
m SSHD_PWAUTH   "$(printf '%s\n' "$SSHD_T" | awk '/^passwordauthentication /{print $2; exit}')"
m SSHD_ROOTLOGIN "$(printf '%s\n' "$SSHD_T" | awk '/^permitrootlogin /{print $2; exit}')"
# The shared file must be NAMED by sshd, or the per-lane ciuser account cannot
# use the controller key and only the root/bake-user paths remain.
if printf '%s\n' "$SSHD_T" | grep -q '^authorizedkeysfile .*/etc/ssh/cybercore-controller-authorized_keys'; then
  m SSHD_AUTHKEYS_SHARED yes
else
  m SSHD_AUTHKEYS_SHARED no
fi

CTRL=/etc/ssh/cybercore-controller-authorized_keys
if [ -s "$CTRL" ] && grep -qE '^(ssh-|ecdsa-|sk-ssh-)' "$CTRL"; then
  m CTRL_KEY_SHARED yes
else
  m CTRL_KEY_SHARED no
fi
m CTRL_KEY_FP "$(ssh-keygen -lf "$CTRL" 2>/dev/null | awk '{print $2}' || echo none)"
m CTRL_KEY_ROOT "$(yn grep -qxFf "$CTRL" /root/.ssh/authorized_keys)"
BAKE_USER_HOME="$(getent passwd "${CYBERCORE_BAKE_USER:-ubuntu}" 2>/dev/null | cut -d: -f6)"
if [ -n "$BAKE_USER_HOME" ] && [ -f "$BAKE_USER_HOME/.ssh/authorized_keys" ] \
   && grep -qxFf "$CTRL" "$BAKE_USER_HOME/.ssh/authorized_keys" 2>/dev/null; then
  m CTRL_KEY_USER yes
else
  m CTRL_KEY_USER no
fi
# Both extension playbooks run `become: yes`, so the account the controller logs
# in as must be able to escalate without a password prompt Ansible cannot answer.
m SUDO_NOPASSWD "$(yn sh -c "sudo -l -U '${CYBERCORE_BAKE_USER:-ubuntu}' 2>/dev/null | grep -q NOPASSWD")"

# ---- Host keys: present now (sshd -T needs them), regenerated per clone later.
#      The seal removes them; the unit below is what puts them back on a clone
#      that cloud-init did not get to first. ----
m HOSTKEY_UNIT_ENABLED "$(yn systemctl is-enabled cybercore-ssh-hostkeys.service)"

# ---- Addressing. See the header: a static address in the image and a
#      MAC-pinned reservation on the gateway disagreeing is invisible until
#      "the agents ship nowhere". Parsed as YAML rather than grepped, because a
#      netplan `nameservers:` block ALSO contains the key `addresses:` and a
#      naive grep reports every DHCP image as static. ----
NETPLAN_RESULT="$(python3 - <<'PY' 2>/dev/null || true
import glob, yaml
static, dhcp = [], []
for path in sorted(glob.glob('/etc/netplan/*.yaml') + glob.glob('/etc/netplan/*.yml')):
    try:
        doc = yaml.safe_load(open(path)) or {}
    except Exception:
        print('PARSE_ERROR'); raise SystemExit
    net = doc.get('network') or {}
    for kind in ('ethernets', 'bonds', 'bridges', 'vlans'):
        for name, cfg in (net.get(kind) or {}).items():
            cfg = cfg or {}
            if cfg.get('addresses'):
                static.append('%s/%s' % (path, name))
            if cfg.get('dhcp4') in (True, 'true', 'yes', 'on'):
                dhcp.append(name)
print('static=%s dhcp=%s' % (','.join(static) or '-', ','.join(dhcp) or '-'))
PY
)"
case "$NETPLAN_RESULT" in
  "")             m NETPLAN_PARSED no ;;
  PARSE_ERROR*)   m NETPLAN_PARSED no ;;
  *)              m NETPLAN_PARSED yes ;;
esac
case "$NETPLAN_RESULT" in
  *"static=-"*) m NETPLAN_STATIC no ;;
  *)            m NETPLAN_STATIC yes ;;
esac
case "$NETPLAN_RESULT" in
  *"dhcp=-"*) m NETPLAN_DHCP4 no ;;
  *dhcp=*)    m NETPLAN_DHCP4 yes ;;
  *)          m NETPLAN_DHCP4 unknown ;;
esac
m NETPLAN_DETAIL "${NETPLAN_RESULT:-none}"
# The other place a static address can hide on a Debian-family image.
if grep -rhqE '^[[:space:]]*iface[[:space:]]+.*[[:space:]]static' /etc/network/interfaces /etc/network/interfaces.d/ 2>/dev/null; then
  m ENI_STATIC yes
else
  m ENI_STATIC no
fi
# If cloud-init's network handling is disabled in the image, the clone keeps
# whatever netplan this bake left behind instead of rendering the lane's
# `ipconfig0: ip=dhcp` — which is a static-by-accident, on an interface name
# that may not even exist in the clone.
if grep -rlqE 'network:[[:space:]]*\{?[[:space:]]*config:[[:space:]]*disabled' /etc/cloud/cloud.cfg.d/ 2>/dev/null; then
  m CI_NET_DISABLED yes
else
  m CI_NET_DISABLED no
fi

# ---- Disk. Sized for a Wazuh all-in-one installed later, in-lane. Measured,
#      not assumed: DISK_GROW only matters if growpart+resize2fs actually made
#      it into the root filesystem. ----
m ROOT_FS_GB "$(df -BG --output=size / 2>/dev/null | awk 'NR==2 {gsub(/[^0-9]/,"",$1); print $1}')"

# ---- Convenience for whoever reads this in a lane six months from now ----
m SSHPASS_PRESENT "$(yn command -v sshpass)"
m BAKED_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exit 0
MARKERS_EOF

MARKERS_B64="$(printf '%s\n' "$MARKERS_SH" | base64 -w0)"
CTRL_KEY_B64="$(printf '%s\n' "$GOAD_CONTROLLER_PUBKEY" | base64 -w0)"

# ============================================================================
# 1. cloud-init user-data
# ============================================================================
# NOTE ON PROXMOX SEMANTICS: `--cicustom user=...` REPLACES the user-data
# Proxmox would otherwise generate, which means --ciuser and --cipassword are
# IGNORED for the duration of the bake. The account therefore has to be created
# here, in this snippet. (--ipconfig0 and --nameserver feed the separate
# NETWORK-config drive and are unaffected, which is why DHCP still comes from
# the qm set in section 3.)
cat > "$USERDATA_PATH" <<CLOUDINIT
#cloud-config
# Neutral hostname on purpose. One image serves elk, wazuh AND lx01, so pinning
# it to any one of those would be wrong in two lanes out of three. Per clone the
# hostname comes from Proxmox's generated user-data (VM name), because the seal
# in section 6 deletes this cicustom.
hostname: ubuntu-lab
manage_etc_hosts: true

# Ubuntu cloud images default to disable_root: true, which puts a forced-command
# stanza in front of every key cloud-init installs for root. Our root key is
# written by runcmd rather than by cloud-init so it would survive either way —
# but leaving the default in place means the NEXT person to add a root key
# through the datasource gets a silent no-op, and that is worth not setting up.
disable_root: false

# Declaring users: at all drops the distro default user, so the account is
# spelled out in full rather than relying on '- default'.
users:
  - name: ${TEMPLATE_USER}
    groups: [adm, sudo]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: false
    # cloud-init's users module installs this with correct ownership and mode.
    # write_files CANNOT be used for a home-directory path here: write-files
    # runs BEFORE users-groups in cloud_init_modules, so it would create
    # /home/${TEMPLATE_USER}/.ssh root-owned, and sshd's StrictModes would then
    # ignore the file entirely — a key that is present and does not work.
    ssh_authorized_keys:
      - ${GOAD_CONTROLLER_PUBKEY}

chpasswd:
  list: |
    ${TEMPLATE_USER}:${TEMPLATE_PASSWORD}
    root:${TEMPLATE_PASSWORD}
  expire: false

ssh_pwauth: true

# Cheap insurance for the bake itself: if the bake VLAN's DHCP hands out a
# resolver that is down (FreeIPA has been that, and has died), every apt call
# below fails and the only symptom is a bake that never completes. bootcmd runs
# in cloud-init's network stage — network is up, config/final stages have not
# run yet — which is the one window where this can still help.
bootcmd:
  - [ sh, -c, 'getent hosts archive.ubuntu.com >/dev/null 2>&1 || { rm -f /etc/resolv.conf; printf "nameserver ${BAKE_DNS}\nnameserver 1.1.1.1\n" > /etc/resolv.conf; }' ]

package_update: true
# Deliberately NOT package_upgrade. An upgrade makes the image un-reproducible
# from this file alone — two bakes a month apart differ by whatever landed in
# jammy-updates in between — and the extensions pull their own pinned
# repositories anyway. Patch level is a re-bake decision, not a silent one.
packages:
  - qemu-guest-agent      # CyberCore dispatches to lane VMs over guest-exec
  - python3               # Ansible needs an interpreter on the target
  - python3-apt           # ...and the apt: module binds to this, not to apt-get
  - python3-yaml          # bake-markers.sh parses netplan with it
  - sudo
  - ca-certificates       # roles/elk adds an https apt repo; roles/wazuh curls one
  - gnupg                 # apt_key / gpg --dearmor in roles/elk
  - curl
  - acl                   # silences Ansible's become-to-unprivileged-user warning
# sshpass is NOT in this list on purpose. apt-get installs the list as ONE
# transaction, so a single unavailable package takes the guest agent down with
# it — and sshpass lives in universe, which is enabled on the stock cloud image
# and is exactly the kind of thing a site mirror trims. It is installed on its
# own, tolerating failure, in runcmd below. NOTHING HERE DEPENDS ON IT.

write_files:
  # ------------------------------------------------------------------------
  # The controller's public key, outside every home directory.
  #
  # challenge-lane-deployer.js sets ciuser/cipassword per clone, so the account
  # names on a deployed lane are not knowable from here. An AuthorizedKeysFile
  # that lives in /etc is valid for all of them at once, and cloud-init — which
  # rewrites the default user's ~/.ssh/authorized_keys on every new instance —
  # has no opinion about it.
  # ------------------------------------------------------------------------
  - path: ${CTRL_KEY_FILE}
    permissions: '0644'
    owner: root:root
    encoding: b64
    content: ${CTRL_KEY_B64}

  # 00- so it sorts first: Ubuntu's /etc/ssh/sshd_config carries its
  # 'Include /etc/ssh/sshd_config.d/*.conf' at the TOP, and in sshd_config the
  # FIRST occurrence of a keyword wins — the opposite of most config formats.
  #
  # AuthorizedKeysFile is RESTATED with the default first. Naming only the
  # shared file would REPLACE the default, and every ordinary ~/.ssh key on
  # every account in every lane would stop working at once.
  - path: /etc/ssh/sshd_config.d/00-cybercore.conf
    permissions: '0600'
    owner: root:root
    content: |
      # Lab template. See bake-ubuntu-lab-template.sh.
      PasswordAuthentication yes
      PubkeyAuthentication yes
      PermitRootLogin yes
      AuthorizedKeysFile .ssh/authorized_keys ${CTRL_KEY_FILE}

  # ------------------------------------------------------------------------
  # SSH host keys are removed at seal time so that every clone generates its
  # own. One host key shared across every student lane is both a real problem
  # (any lane can impersonate any other to anything that trusts it) and a
  # confusing one (the fingerprint is identical everywhere, so a change nobody
  # made looks like a change somebody made).
  #
  # cloud-init's ssh module regenerates them on a new instance, and the seal
  # gives every clone a new instance-id. This unit is the belt to that braces:
  # it costs nothing when cloud-init already ran, and it is the difference
  # between "sshd will not start" and "sshd starts" on a clone whose datasource
  # went missing.
  # ------------------------------------------------------------------------
  - path: /etc/systemd/system/cybercore-ssh-hostkeys.service
    permissions: '0644'
    owner: root:root
    content: |
      [Unit]
      Description=Regenerate missing SSH host keys (CyberCore lab template)
      Before=ssh.service ssh.socket
      ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key

      [Service]
      Type=oneshot
      ExecStart=/usr/bin/ssh-keygen -A
      RemainAfterExit=yes

      [Install]
      WantedBy=multi-user.target

  - path: /opt/cybercore/bake-markers.sh
    permissions: '0700'
    owner: root:root
    encoding: b64
    content: ${MARKERS_B64}
CLOUDINIT

cat >> "$USERDATA_PATH" <<CLOUDINIT

runcmd:
  # ---- The packages, again. cloud-config module failures are LOGGED, not
  #      fatal: a failed 'packages:' still lets cloud-final run, which would
  #      write BAKE_COMPLETE over an image with no guest agent in it. This retry
  #      is a no-op on the happy path and the difference between a caught and an
  #      uncaught failure on the unhappy one. ----
  - [ sh, -c, 'for i in 1 2 3; do DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-guest-agent python3 python3-apt python3-yaml sudo ca-certificates gnupg curl acl && break; sleep 15; done' ]

  # ---- sshpass, separately and tolerantly. Upstream's docs list it as a
  #      prerequisite and a future extension may want it; nothing in THIS
  #      design does, and it is not worth losing the guest agent over. ----
  - [ sh, -c, 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sshpass || echo "sshpass unavailable — continuing, nothing here depends on it"' ]

  # ---- The guest agent. Without it this machine is opaque to the
  #      orchestrator: Proxmox reports it healthy and nothing can be dispatched
  #      into it, which is also how THIS script reads its own markers back. ----
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, restart, qemu-guest-agent ]

  # ---- Host-key regeneration unit ----
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, cybercore-ssh-hostkeys.service ]

  # ---- The controller key for root. Done here, not in write_files: runcmd runs
  #      in the final stage, so /root exists and ownership is right. ----
  - [ sh, -c, 'install -d -m 0700 -o root -g root /root/.ssh' ]
  - [ sh, -c, 'touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && chown root:root /root/.ssh/authorized_keys' ]
  - [ sh, -c, 'grep -qxFf ${CTRL_KEY_FILE} /root/.ssh/authorized_keys || cat ${CTRL_KEY_FILE} >> /root/.ssh/authorized_keys' ]

  # ---- Re-read the sshd config now that the drop-in is in place. cloud-init
  #      does not abort runcmd on a failure, so this does not stop the bake —
  #      it puts the parse error in cloud-init-output.log, where it is next to
  #      the thing that caused it, and the SSHD_CONFIG_VALID marker turns it
  #      into a refusal in section 5. Both, because a config error and a
  #      dependency error look identical from outside. ----
  - [ sh, -c, 'sshd -t' ]
  - [ systemctl, restart, ssh ]

  # ---- Markers. CYBERCORE_BAKE_USER tells the script which account to check
  #      for the key and for NOPASSWD sudo. ----
  - [ sh, -c, 'CYBERCORE_BAKE_USER=${TEMPLATE_USER} /opt/cybercore/bake-markers.sh' ]
CLOUDINIT

# BAKE_COMPLETE is written LAST, on its own, and the host polls for it. Anything
# appended after this line would run after the host has already decided the bake
# is finished.
cat >> "$USERDATA_PATH" <<'CLOUDINIT'

  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]
CLOUDINIT

echo "==> Wrote bake snippet: $USERDATA_PATH"

# ============================================================================
# 2. Cloud image (cached)
# ============================================================================
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  echo "==> Downloading Ubuntu 22.04 (jammy) server cloud image..."
  mkdir -p "$(dirname "$CLOUD_IMG_LOCAL")"
  wget --progress=dot:giga -O "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_URL"
  mv "${CLOUD_IMG_LOCAL}.tmp" "$CLOUD_IMG_LOCAL"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL ($(du -h "$CLOUD_IMG_LOCAL" | cut -f1))"

# ============================================================================
# 3. Create the VM
# ============================================================================
echo "==> Creating VM $VMID ($NAME)..."

NET0="virtio,bridge=${BAKE_BRIDGE},firewall=0"
[ -n "${BAKE_VLAN:-}" ] && NET0="${NET0},tag=${BAKE_VLAN}"

# Machine shape copied from bake-goad-controller-vm.sh rather than invented:
# q35 + OVMF + virtio-scsi + a serial console. The jammy cloud image ships both
# a bios_grub partition and an ESP, so it boots either way; matching the sibling
# bake means one shape to debug on this cluster instead of two.
qm create "$VMID" \
  --name "$NAME" \
  --memory "$MEMORY" \
  --cores "$CORES" \
  --cpu host \
  --machine q35 \
  --bios ovmf \
  --efidisk0 "${STORAGE}:0,efitype=4m,pre-enrolled-keys=1" \
  --scsihw virtio-scsi-pci \
  --net0 "$NET0" \
  --serial0 socket --vga serial0 \
  --agent enabled=1,fstrim_cloned_disks=1 \
  --ostype l26 \
  --description "Generic Ubuntu 22.04 lab template. Serves GOAD's elk / wazuh extensions and lx01. NO SIEM software baked in — GOAD's Ansible installs it in-lane. Baked from infrastructure/proxmox-templates/vm-templates/bake-ubuntu-lab-template.sh."

echo "==> Importing cloud image as VM disk..."
qm disk import "$VMID" "$CLOUD_IMG_LOCAL" "$STORAGE" 2>/dev/null \
  || qm importdisk "$VMID" "$CLOUD_IMG_LOCAL" "$STORAGE"

# The imported volume lands in the config as `unusedN`. Read it back rather than
# assuming a name: efidisk0 already consumed disk-0, so the import is usually
# disk-1 — but "usually" is how a bake breaks on the one storage backend that
# numbers differently, and it breaks by silently attaching a volume that does
# not exist.
IMPORTED_VOL="$(qm config "$VMID" | awk -F': ' '/^unused[0-9]+:/ {print $2; exit}')"
if [ -z "$IMPORTED_VOL" ]; then
  echo "WARNING: no 'unused' volume in the config after import — falling back to the conventional name." >&2
  IMPORTED_VOL="${STORAGE}:vm-${VMID}-disk-1"
fi
echo "==> Attaching $IMPORTED_VOL as scsi0"
qm set "$VMID" --scsi0 "${IMPORTED_VOL},discard=on,ssd=1"
qm set "$VMID" --boot order=scsi0

# Grow BEFORE the first boot, so cloud-init's growpart/resize2fs sees the larger
# disk on the run that matters. Growing afterwards leaves a big volume with a
# small filesystem on it, which reads as "the resize didn't work".
echo "==> Growing disk by ${DISK_GROW} (sized for a Wazuh all-in-one installed later, in-lane)"
qm resize "$VMID" scsi0 "+${DISK_GROW}"

# The cloud-init drive is NOT optional and is NOT removed at seal time.
# challenge-lane-deployer.js calls findCloudInitDrive() before it will set
# ciuser/cipassword/ipconfig0 on a clone; a template without one makes it fall
# back to the baked accounts and log "no cloud-init drive", which is a lane whose
# published credentials do not match the machine.
echo "==> Adding cloud-init drive..."
qm set "$VMID" --ide2 "${STORAGE}:cloudinit"

# ipconfig0=dhcp feeds the NETWORK-config drive, which --cicustom user= does not
# replace. This is the only place addressing is set, and it is DHCP.
qm set "$VMID" \
  --ciuser "$TEMPLATE_USER" \
  --cipassword "$TEMPLATE_PASSWORD" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/${USERDATA_FILE}"

# ============================================================================
# 4. Boot and wait for the bake
# ============================================================================
echo "==> Starting $VMID and waiting for cloud-init (budget ${BAKE_TIMEOUT}s)"
qm start "$VMID"

# Poll the marker file through the guest agent rather than mounting the disk.
# Reading it live works on any storage AND proves guest-exec itself is
# functional — which for this template is not a side benefit: CyberCore reaches
# every lane VM this way, and a SIEM box the orchestrator cannot dispatch into
# is one nobody can fix from outside the lane.
DEADLINE=$(( $(date +%s) + BAKE_TIMEOUT ))
BAKE_ENV=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if OUT=$(qm guest exec "$VMID" -- /bin/sh -c 'cat /etc/cybercore-bake.env 2>/dev/null' 2>/dev/null); then
    # `qm guest exec` returns JSON, and out-data is a JSON STRING: the file's
    # real newlines arrive as the two-character escape \n. Decode them with
    # printf %b, or the whole marker file parses as ONE line and every marker
    # after the first reads as part of the first one's value — which looks
    # exactly like a bake that did nothing, on a bake that did everything.
    # [^"] rather than .* so the match stops at out-data's own closing quote
    # instead of running on to the last quote in the JSON object.
    BAKE_ENV=$(printf '%s' "$OUT" | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [ -z "$BAKE_ENV" ] && BAKE_ENV="$OUT"
    BAKE_ENV=$(printf '%b' "$BAKE_ENV")
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
  echo "       qm terminal $VMID                     (then ^O to exit)" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'tail -80 /var/log/cloud-init-output.log'" >&2
  echo "" >&2
  echo "  REMINDER: this script has never been executed. A first-run failure here is the" >&2
  echo "  expected outcome, not an anomaly. Most likely causes, in order:" >&2
  echo "    1. the guest agent never answered, so the poll above never saw anything —" >&2
  echo "       check 'qm terminal $VMID' for a login prompt; if the VM is up and the" >&2
  echo "       agent is not, that is the finding" >&2
  echo "    2. no DNS or no egress on VLAN ${BAKE_VLAN:-<none>} — apt cannot reach" >&2
  echo "       archive.ubuntu.com and every package task fails" >&2
  echo "    3. the image did not boot under q35+OVMF at all — 'qm terminal' shows" >&2
  echo "       nothing; try --bios seabios --machine pc" >&2
  echo "    4. a YAML error in the snippet: cat $USERDATA_PATH" >&2
  exit 1
fi

# ============================================================================
# 5. Pre-seal verification
# ============================================================================
echo "==> Verifying bake markers"
marker() { printf '%s' "$BAKE_ENV" | awk -F= -v k="$1" '$1==k {print $2; exit}'; }

FAIL=0
check() {  # check <marker> <expected> <what breaks if it is wrong>
  local got; got=$(marker "$1")
  printf '    %-24s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    FAIL=1
  fi
}
show() { printf '    %-24s %s\n' "$1:" "$(marker "$1")"; }

# ---- The OS is the one the extensions were pinned against ----
show OS_ID
if [ "$ALLOW_NON_JAMMY" = "1" ]; then
  show OS_VERSION_ID
  echo "    (ALLOW_NON_JAMMY=1 — release not enforced)"
else
  check OS_VERSION_ID 22.04 "this is not Ubuntu 22.04. Upstream GOAD pins ubuntu-22.04-x64-server for BOTH extensions and Wazuh 4.8 / Elastic 8.x support rides on that pin. Set ALLOW_NON_JAMMY=1 only if you have re-proved both roles on this release"
fi

# ---- The guest agent: the orchestrator's only way into this machine ----
check GUEST_AGENT_INSTALLED yes "qemu-guest-agent is not installed — CyberCore dispatches to lane VMs over guest-exec, so without it this machine is opaque to the orchestrator: Proxmox reports it healthy and nothing can be run inside it"
check GUEST_AGENT_ENABLED   yes "qemu-guest-agent is installed but not enabled — it works right now and stops working on the first reboot of every clone, which is to say in every lane"
check GUEST_AGENT_ACTIVE    yes "qemu-guest-agent is not running"
check GUEST_AGENT_ARGS_CLEAN yes "/etc/default/qemu-guest-agent blocks RPCs — every dispatch then returns HTTP 596 while guest-ping and network-get-interfaces keep succeeding, so the VM looks perfectly healthy and nothing can be sent into it"

# ---- An interpreter for Ansible ----
if [ -z "$(marker PYTHON3)" ] || [ "$(marker PYTHON3)" = "none" ]; then
  echo "    PYTHON3:                 none"
  echo "    ERROR: no python3 — Ansible needs an interpreter on the target, so EVERY task of roles/elk, roles/wazuh_manager and roles/wazuh_agent_linux fails on this host before it starts" >&2
  FAIL=1
else
  show PYTHON3
fi
check PYTHON3_APT yes "python3-apt is missing — Ansible's apt: module binds to it, and roles/elk is almost nothing but apt/apt_key/apt_repository tasks. Ansible will try to bootstrap it itself, which needs a working become and a working apt, which is exactly what is in doubt when this is missing"

# ---- SSH: the controller must get in with a key, and staff with a password ----
check SSHD_CONFIG_VALID yes "sshd -t fails — sshd will not start in any lane cloned from this template"
check SSHD_PWAUTH       yes "password authentication is off — the repo's bake-debug convention does not work and there is no way onto the console when the key path is what is broken"
check CTRL_KEY_SHARED   yes "${CTRL_KEY_FILE} has no public key in it. This is the failure the GOAD_CONTROLLER_PUBKEY refusal exists to prevent, arriving late: the box boots, and Ansible cannot reach it at all"
check SSHD_AUTHKEYS_SHARED yes "sshd does not name ${CTRL_KEY_FILE} as an AuthorizedKeysFile — the controller key then only works for root and ${TEMPLATE_USER}, and NOT for whatever per-lane account challenge-lane-deployer.js creates via ciuser"
check CTRL_KEY_ROOT     yes "the controller key is not in /root/.ssh/authorized_keys — the shared file may still cover it, but the fallback path is gone and nothing will say so"
check CTRL_KEY_USER     yes "the controller key is not in ${TEMPLATE_USER}'s authorized_keys"
check SUDO_NOPASSWD     yes "${TEMPLATE_USER} has no NOPASSWD sudo — both extension playbooks run 'become: yes', and Ansible cannot answer a password prompt it was never given a password for"
show CTRL_KEY_FP
echo "    (expected fingerprint:   $CTRL_KEY_FP)"
check HOSTKEY_UNIT_ENABLED yes "cybercore-ssh-hostkeys.service is not enabled — after the seal strips the host keys, a clone whose cloud-init did not run has no host keys and sshd refuses to start"

# ---- Addressing: DHCP, and no static address anywhere ----
check NETPLAN_PARSED yes "netplan could not be parsed, so the static-address check below proved NOTHING. Fix python3-yaml or read /etc/netplan by hand before sealing — this check is the only thing standing between a baked-in address and a lane where the agents ship nowhere"
check NETPLAN_STATIC no  "a STATIC address is configured in netplan. The lane's MAC-pinned dnsmasq reservation is what decides this machine's IP; an address baked into the image that disagrees with the reservation produces no error anywhere — just a healthy machine at the wrong address that every agent in the lane ships past"
check NETPLAN_DHCP4  yes "no interface is configured for DHCP"
check ENI_STATIC     no  "a static iface is configured in /etc/network/interfaces — same failure as above, hiding in the other place a Debian-family image keeps addressing"
check CI_NET_DISABLED no  "cloud-init network configuration is DISABLED in this image. The clone would then keep this bake's netplan instead of rendering the lane's 'ipconfig0: ip=dhcp' — a static-by-accident, on an interface name that may not even exist in the clone"
show NETPLAN_DETAIL

# ---- Disk: measured, not assumed ----
ROOT_GB="$(marker ROOT_FS_GB)"
printf '    %-24s %s\n' "ROOT_FS_GB:" "${ROOT_GB:-unset} (floor ${MIN_ROOT_GB})"
if ! printf '%s' "$ROOT_GB" | grep -Eq '^[0-9]+$'; then
  echo "    ERROR: could not measure the root filesystem" >&2
  FAIL=1
elif [ "$ROOT_GB" -lt "$MIN_ROOT_GB" ]; then
  echo "    ERROR: root filesystem is ${ROOT_GB}G, below the ${MIN_ROOT_GB}G floor." >&2
  echo "           roles/wazuh_manager runs wazuh-install.sh -a -i — manager, indexer AND" >&2
  echo "           dashboard on this one box — and Wazuh's own guidance for ~25 agents is" >&2
  echo "           ~50 GB. A short disk does not fail the install; it fails the indexer," >&2
  echo "           weeks later, mid-class. Either DISK_GROW did not take or growpart did" >&2
  echo "           not run. Raise DISK_GROW (currently ${DISK_GROW}) and re-bake." >&2
  FAIL=1
fi

show SSHPASS_PRESENT
show BAKED_AT

if [ "$FAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: verification failed. VM $VMID left RUNNING and unsealed for inspection." >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'cat /etc/cybercore-bake.env'" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'tail -100 /var/log/cloud-init-output.log'" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'cat /etc/netplan/*.yaml'" >&2
  echo "       (re-run the collector after a fix: /opt/cybercore/bake-markers.sh)" >&2
  exit 1
fi
echo "==> All markers good"

# ---- Host-side: the template's own config must say DHCP ----
# The guest can be perfect and the TEMPLATE still ship a static pin, because
# ipconfig0 lives in the VM config, not in the image.
IPCFG="$(qm config "$VMID" | awk -F': ' '/^ipconfig0:/ {print $2; exit}')"
printf '    %-24s %s\n' "ipconfig0 (host):" "${IPCFG:-unset}"
if [ "$IPCFG" != "ip=dhcp" ]; then
  echo "ERROR: the template's ipconfig0 is '${IPCFG:-unset}', not 'ip=dhcp'." >&2
  echo "       Clones inherit it, and challenge-lane-deployer.js only overwrites it when" >&2
  echo "       findCloudInitDrive() succeeds. A static pin here races the guest's own" >&2
  echo "       DHCP client and loses — the same bug the Kali clone in that file carries" >&2
  echo "       its own note about." >&2
  exit 1
fi

# ============================================================================
# 6. Seal
# ============================================================================
echo "==> Cleaning cloud-init state and sealing"

# cloud-init state first: --seed as well as --logs, so the clone is a NEW
# instance and re-runs every per-instance module (including the ssh one that
# regenerates host keys).
qm guest exec "$VMID" -- /bin/sh -c 'cloud-init clean --logs --seed 2>/dev/null || true' >/dev/null 2>&1 || true

# A machine-id that travels is a DUID that travels: netplan/systemd-networkd
# derives its DHCP client identifier from it, so two clones sharing one would
# present as the same client to the lane's dnsmasq. Truncate rather than delete
# — systemd repopulates an EMPTY /etc/machine-id at boot, and treats a MISSING
# one as a first-boot condition that some images handle badly.
qm guest exec "$VMID" -- /bin/sh -c 'truncate -s 0 /etc/machine-id' >/dev/null 2>&1 || true
qm guest exec "$VMID" -- /bin/sh -c 'rm -f /var/lib/dbus/machine-id' >/dev/null 2>&1 || true

# SSH host keys. One host key shared across every student lane is both a real
# problem and a confusing one — the fingerprint is identical everywhere, so any
# change looks deliberate and no change looks like anything at all.
qm guest exec "$VMID" -- /bin/sh -c 'rm -f /etc/ssh/ssh_host_*' >/dev/null 2>&1 || true

# Bake-time noise that should not travel into thirty lanes.
qm guest exec "$VMID" -- /bin/sh -c 'rm -f /root/.bash_history /home/*/.bash_history 2>/dev/null || true' >/dev/null 2>&1 || true
qm guest exec "$VMID" -- /bin/sh -c 'apt-get clean 2>/dev/null || true' >/dev/null 2>&1 || true
qm guest exec "$VMID" -- /bin/sh -c 'rm -rf /var/log/cloud-init*.log /var/lib/cloud/instances/* 2>/dev/null || true' >/dev/null 2>&1 || true

# ---- Verify the SEAL itself, while the agent is still reachable ----
# These four are checked here rather than in section 5 because they are only
# true AFTER the clean, and a seal that silently did nothing is exactly the kind
# of failure that ships.
echo "==> Verifying the seal"
SEAL_FAIL=0
seal_check() {  # seal_check <label> <guest sh -c command> <expected stdout> <what breaks>
  local got
  got=$(qm guest exec "$VMID" -- /bin/sh -c "$2" 2>/dev/null \
        | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  got=$(printf '%b' "$got" | tr -d '\r\n')
  printf '    %-24s %s\n' "$1:" "${got:-<empty>}"
  if [ "$got" != "$3" ]; then
    echo "    ERROR: $4" >&2
    SEAL_FAIL=1
  fi
}
seal_check HOSTKEYS_REMOVED \
  'ls /etc/ssh/ssh_host_* >/dev/null 2>&1 && echo present || echo none' \
  none \
  "SSH host keys are still in the image. Every student lane would then share one host identity: any lane can impersonate any other to anything that trusts it, and the fingerprint is the same everywhere so nothing ever looks wrong"
seal_check MACHINE_ID_EMPTY \
  'test -s /etc/machine-id && echo nonempty || echo empty' \
  empty \
  "/etc/machine-id still has content — every clone would share it, which means every clone presents the same DHCP client identifier to the lane's dnsmasq"
seal_check CLOUD_INIT_CLEAN \
  'ls /var/lib/cloud/instances 2>/dev/null | head -1 | grep -q . && echo dirty || echo clean' \
  clean \
  "cloud-init still holds this bake's instance state — the clone would be treated as the SAME instance and would skip every per-instance module, including the one that regenerates SSH host keys"
seal_check CTRL_KEY_SURVIVED \
  "test -s ${CTRL_KEY_FILE} && echo present || echo missing" \
  present \
  "the controller key did not survive the clean. Ansible cannot reach this machine in any lane, which is the one failure this whole template exists to avoid"

if [ "$SEAL_FAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: seal verification failed. VM $VMID left RUNNING and UNSEALED." >&2
  echo "       Nothing has been converted to a template, so nothing can be cloned yet." >&2
  exit 1
fi

qm shutdown "$VMID" --timeout 120 || qm stop "$VMID"
for _ in $(seq 1 40); do
  [ "$(qm status "$VMID" | awk '{print $2}')" = "stopped" ] && break
  sleep 3
done
if [ "$(qm status "$VMID" | awk '{print $2}')" != "stopped" ]; then
  echo "ERROR: $VMID did not stop. Refusing to template a running VM." >&2
  exit 1
fi

echo "==> Clearing bake-time cicustom + cloud-init fields"
# cicustom goes so per-lane clones get their OWN generated user-data from
# challenge-lane-deployer.js. cipassword goes so the bake password is not
# sitting in the template config; the ACCOUNT still has it (chpasswd wrote it
# into /etc/shadow), which is the repo's bake-debug convention.
#
# ide2 (the cloud-init drive) is deliberately NOT deleted — findCloudInitDrive()
# looks for it, and a template without one makes the deployer fall back to the
# baked accounts and publish credentials that do not match the machine.
qm set "$VMID" --delete cicustom
qm set "$VMID" --delete cipassword 2>/dev/null || true

rm -f "$USERDATA_PATH"

qm template "$VMID"
echo "==> Template $VMID ($NAME) sealed"

# ============================================================================
# 7. What still has to happen by hand
# ============================================================================
cat <<NEXTSTEPS
============================================================================
 Template $VMID ($NAME) is built: a blank Ubuntu 22.04 server with a guest
 agent, python3, DHCP and the GOAD controller's key. Nothing is wired into
 CyberCore yet, and there is no SIEM software in it — GOAD's own Ansible
 installs that IN THE LANE, which is the entire point.

 1. WHERE THE CONTROLLER KEY CAME FROM, AND HOW TO CHECK IT MATCHES.

    This bake used:
        $CTRL_KEY_FP

    That value is the PUBLIC half of the keypair bake-goad-controller-vm.sh
    generates on the Proxmox node it runs on:

        /root/.ssh/goad-controller-deploy.key       (private — baked into
                                                     controller template 1700 at
                                                     /root/.ssh/id_ed25519)
        /root/.ssh/goad-controller-deploy.key.pub   (public  — what you passed
                                                     in as GOAD_CONTROLLER_PUBKEY)

    The SAME public half is already in the lane gateway's authorized_keys, put
    there by ../sdn-templates/patch-goad-gateway-key.sh. So the controller
    reaches the gateway and this machine with one key and no password anywhere.

    Confirm the two agree, on the node that holds the keypair:

        ssh-keygen -lf /root/.ssh/goad-controller-deploy.key.pub

    If that fingerprint is not the one above, this template will not be
    reachable by the controller and 'install_extension elk' dies on the first
    task of roles/elk. RE-BAKE with the right key; do not patch it in by hand
    on a template, because a template's disk is snapshot-protected and the
    "fix" silently lands on a clone instead.

    IF THE CONTROLLER IS EVER RE-BAKED and generates a NEW keypair, this
    template is stale and must be re-baked too. That is a real coupling and it
    is worth writing on the runbook: bake-goad-controller-vm.sh only generates
    when the key file is absent, so an existing node keeps its keypair across
    re-bakes — but a NEW node does not.

 2. REGISTER THE TEMPLATE.

    Admin -> Workstation Templates:

        os_family      linux
        os_name        Ubuntu Server 22.04 (lab)
        os_version     22.04
        template_vmid  $VMID
        template_key   ubuntu-lab-template
        metadata       {"console_protocol": "ssh"}

    console_protocol=ssh is not cosmetic: resolveConsole() defaults to rdp, so
    leaving it unset publishes a gateway DNAT to 3389 on a headless Linux box
    that is not listening there. GOAD_EXTENSIONS.elk and .wazuh in
    front-end/src/utils/goad-deploy.js already carry headless: true for the same
    reason — a student handed an RDP console here gets a black screen.

    Then POST /api/admin/vm-templates/sync-nodes so 'node' is filled in.
    Do NOT add a seed migration: front-end/migrations/ has no runner, so a file
    there would never execute.

 3. POINT THE EXTENSIONS AT IT.

    front-end/src/utils/goad-deploy.js, GOAD_EXTENSIONS:

        elk.template_vmid    null  ->  $VMID
        wazuh.template_vmid  null  ->  $VMID

    lx01.template_vmid is currently 1003 (the older Ubuntu-Template). This
    image serves lx01 perfectly well and moving it here consolidates three
    machines onto one bake — but read the sizing note in this script's header
    first: applyResources() can size CPU and RAM DOWN per clone and CANNOT size
    the disk down, so an lx01 clone from this template carries the Wazuh-sized
    disk. On thin storage that is free. On thick storage it is not, and the
    answer there is a second bake of THIS script with DISK_GROW=8G under its own
    VMID, not a smaller disk here.

    Do not touch the OCTETS. elk stays at .24 and wazuh at .51 in that file, and
    the .50 -> .24 rewrite of upstream's extensions/elk/inventory belongs in the
    controller's run.sh sed pass, next to the {{ip_range}} substitution that
    already renders inventory_proxmox. Editing GOAD-main/extensions/elk/inventory
    would work exactly once and be lost on the next re-vendor.

 4. WHAT THIS TEMPLATE DOES NOT DO, SO NOBODY LOOKS FOR IT HERE.

    - It does not install Elasticsearch, Kibana, Logstash, Wazuh, Sysmon or
      winlogbeat. GOAD's roles/elk, roles/logs_windows, roles/wazuh_manager,
      roles/wazuh_agent and roles/wazuh_agent_linux do all of that at deploy
      time, from inside the lane, over the lane's NAT egress.
    - It does not know its own address. DHCP against the lane's MAC-pinned
      dnsmasq reservation decides that, and nothing in this image has an opinion.
    - It does not carry the run.sh EXTENSIONS argument contract. That is
        run.sh LAB HOST_MAP INITIAL_USER INITIAL_PASSWORD [EXTENSIONS]
      where EXTENSIONS is an optional comma-separated list, and absent-or-empty
      must behave byte-identically to today. It lives on the controller and in
      the wiring, not here.
    - It does not supply Ansible's connection variables. ansible_user,
      ansible_ssh_private_key_file and friends come from run.sh's
      inventory_overrides, the same place every other connection variable is set.
      This image only guarantees the key those overrides name will open the door
      — for root, for $TEMPLATE_USER, and for whatever per-lane account ciuser
      creates.

 5. SMOKE TEST BEFORE ANY STUDENT SEES IT.

     qm clone $VMID 9995 --name ubuntu-lab-test --full --storage $STORAGE
     qm set 9995 --net0 virtio,bridge=$BAKE_BRIDGE${BAKE_VLAN:+,tag=$BAKE_VLAN}
     qm set 9995 --ipconfig0 ip=dhcp --ciuser $TEMPLATE_USER --cipassword $TEMPLATE_PASSWORD
     qm start 9995 && sleep 90

     # the orchestrator's path in, and the one that matters most
     qm guest exec 9995 -- /bin/sh -c 'hostname; python3 -V; systemctl is-active qemu-guest-agent'

     # host keys really are per-clone, not the template's
     qm guest exec 9995 -- /bin/sh -c 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'
     #   -> must NOT match any other clone

     # DHCP, from the reservation, with no static anywhere
     qm guest exec 9995 -- /bin/sh -c 'ip -4 -o addr show scope global; cat /etc/netplan/*.yaml'

     # the whole point: the controller's key opens the door
     qm guest exec 1700 -- /bin/sh -c 'ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no root@<clone-ip> "id; python3 -V"'

     qm stop 9995 && qm destroy 9995 --purge

 6. THEN, AND ONLY THEN, THE REAL PROOF.

    Deploy one lane with spec.goad.extensions = ["elk"], let run.sh render the
    extension inventory and run extensions/elk/ansible/install.yml, and watch
    winlogbeat data arrive from a domain machine. Nothing before that step
    proves this template works — it proves only that it is shaped right.
============================================================================
NEXTSTEPS
