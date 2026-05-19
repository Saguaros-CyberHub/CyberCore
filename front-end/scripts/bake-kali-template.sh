#!/bin/bash
# ============================================================================
# bake-kali-template.sh
# ----------------------------------------------------------------------------
# Bakes QEMU VM template 1699: a fresh Kali Rolling box with xrdp working,
# baked from Kali's official cloud-generic qcow2 + cloud-init unattended.
#
# Each lane clones this template and gets per-student credentials/network
# injected via Proxmox cloud-init (admin.js). xrdp listens on 3389 and is
# reached through Guacamole (rdp.saguaroscyberhub.org).
#
# Run on a Proxmox node with internet access. Idempotent: refuses if 1699
# already exists. To re-bake, destroy first:
#   qm destroy 1699 --purge
#
# Why a script rather than cloning an existing template:
#   - Prior 1699 lineage shipped a 0-byte /usr/lib/x86_64-linux-gnu/libjpeg.so.62.4.0
#     which made xrdp fail with "error while loading shared libraries: file too short".
#   - The bake includes a pre-seal sanity check that aborts if libjpeg is
#     truncated or xrdp can't bind to 3389, so this class of corruption
#     can't ship again.
#
# Companion to:
#   - bake-goad-controller-vm.sh (controller template, same pattern)
#   - bake-lane-gateway-v2.sh (lane gateway template)
# ============================================================================
set -euo pipefail

VMID=${VMID:-1699}
NAME=${NAME:-kali-template}
STORAGE=${STORAGE:-vmpool}                          # where the VM disk + cloudinit drive live
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"              # auto-detected if empty
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"                        # bake-time VLAN for internet (set empty to disable)
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"                 # OPNsense Unbound — the lab firewall blocks outbound :53 to public resolvers from the bake-time VLAN, so this is the only DNS that works during bake. The value is cleared from the template before seal (truncate /etc/resolv.conf + qm set --delete nameserver), so clones never inherit it.
MEMORY=${MEMORY:-4096}
CORES=${CORES:-2}
DISK_GB=${DISK_GB:-32}

# Kali publishes a generic-cloud qcow2 wrapped in tar.xz. URL pattern is the
# "current" symlink that always points at the latest weekly snapshot.
# Override CLOUD_IMG_URL if you need a pinned release.
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://kali.download/cloud-images/current/kali-linux-current-cloud-generic-amd64.tar.xz}"
CLOUD_IMG_TARBALL="/var/lib/vz/template/iso/kali-linux-current-cloud-generic-amd64.tar.xz"
CLOUD_IMG_LOCAL="/var/lib/vz/template/iso/kali-linux-current-cloud-generic-amd64.qcow2"

# Default user baked into the template. admin.js can override per-clone via
# cloud-init `ciuser`/`cipassword`. The template password is intentionally
# weak — it's reset on every clone and the template itself is never exposed.
TEMPLATE_USER="${TEMPLATE_USER:-kali}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-bake-debug}"

# Toolset: 'minimal' = just the desktop + xrdp (~3GB).
#          'default' = kali-linux-default metapackage (~12GB, common pentest tools).
#          'large'   = kali-linux-large (everything; ~25GB, takes ~30 min to bake).
KALI_TOOLSET="${KALI_TOOLSET:-default}"

# ---------- 0. Sanity ----------
if qm status $VMID >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status $VMID >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
  echo "       Destroy first: pct destroy $VMID --purge" >&2
  exit 1
fi

# ---------- Pick a storage with 'snippets' content enabled ----------
pick_snippet_storage() {
  if [ -n "${SNIPPET_STORAGE:-}" ]; then
    if pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SNIPPET_STORAGE"; then
      echo "$SNIPPET_STORAGE"; return 0
    fi
    echo "ERROR: SNIPPET_STORAGE='$SNIPPET_STORAGE' set but that storage doesn't have 'snippets' content enabled." >&2
    echo "       Run: pvesm set $SNIPPET_STORAGE --content <existing>,snippets" >&2
    return 1
  fi

  local first
  first=$(pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then
    echo "$first"; return 0
  fi

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
echo "==> Bake-time NIC: bridge=$BAKE_BRIDGE${BAKE_VLAN:+ vlan=$BAKE_VLAN}"
echo "==> Toolset: $KALI_TOOLSET"

# ---------- 1. Download + extract Kali cloud image (cached) ----------
# Kali's tarball contains a raw .img on some releases, .qcow2 on others. We
# accept either, and convert to qcow2 with qemu-img if needed so the rest of
# the script (qm disk import) sees a stable filename + format.
if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
  if [ ! -f "$CLOUD_IMG_TARBALL" ]; then
    echo "==> Downloading Kali cloud-generic image (tar.xz; ~200MB)..."
    mkdir -p "$(dirname "$CLOUD_IMG_TARBALL")"
    wget --progress=dot:giga -O "${CLOUD_IMG_TARBALL}.tmp" "$CLOUD_IMG_URL"
    mv "${CLOUD_IMG_TARBALL}.tmp" "$CLOUD_IMG_TARBALL"
  else
    echo "==> Reusing cached tarball: $CLOUD_IMG_TARBALL"
  fi

  echo "==> Inspecting tarball contents..."
  tar -tJf "$CLOUD_IMG_TARBALL" | sed 's/^/    /' | head -10

  echo "==> Extracting disk image from tarball..."
  EXTRACT_DIR=$(mktemp -d)
  tar -xJf "$CLOUD_IMG_TARBALL" -C "$EXTRACT_DIR"
  EXTRACTED=$(find "$EXTRACT_DIR" -maxdepth 3 \( -name '*.qcow2' -o -name '*.img' -o -name '*.raw' \) | head -1)
  if [ -z "$EXTRACTED" ]; then
    echo "ERROR: no .qcow2 / .img / .raw found inside $CLOUD_IMG_TARBALL" >&2
    echo "       Tarball contents:" >&2
    tar -tJf "$CLOUD_IMG_TARBALL" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
  fi

  if [[ "$EXTRACTED" == *.qcow2 ]]; then
    echo "==> Got qcow2 directly: $(basename "$EXTRACTED")"
    mv "$EXTRACTED" "$CLOUD_IMG_LOCAL"
  else
    echo "==> Got $(basename "$EXTRACTED") (raw); converting to qcow2 with qemu-img..."
    qemu-img convert -O qcow2 -o compat=1.1 "$EXTRACTED" "$CLOUD_IMG_LOCAL"
    rm -f "$EXTRACTED"
  fi
  rm -rf "$EXTRACT_DIR"
fi
echo "==> Cloud image: $CLOUD_IMG_LOCAL ($(du -h "$CLOUD_IMG_LOCAL" | cut -f1))"

# ---------- 2. Build cloud-init user-data snippet ----------
USERDATA_FILE="kali-template-bake-${VMID}.yml"
USERDATA_PATH="$(pvesm path "${SNIPPET_STORAGE}:snippets/${USERDATA_FILE}" 2>/dev/null)"
if [ -z "$USERDATA_PATH" ]; then
  case "$SNIPPET_STORAGE" in
    local)   USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
    cephfs)  USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
    *)       USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  esac
fi
mkdir -p "$(dirname "$USERDATA_PATH")"

# Pick the toolset metapackage. 'minimal' skips the metapackage entirely.
# We pre-build the full shell command so the heredoc below can embed it as a
# single string — avoids the trap where ${VAR:+...} expands to empty inside
# the YAML and produces invalid `sh -c ' || true'` for the minimal toolset.
# DPKG_CONF: pass these on every apt invocation that runs from runcmd —
# without them dpkg prompts on conffile conflicts (e.g., /etc/xrdp/startwm.sh
# from write_files), reads EOF from closed stdin, and the install errors
# out leaving the package half-configured. cloud-init's packages: does
# this for us automatically; runcmd does not.
DPKG_CONF='-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'

case "$KALI_TOOLSET" in
  minimal) TOOLSET_RUNCMD='echo "minimal toolset: skipping metapackage install"' ;;
  default) TOOLSET_RUNCMD="DEBIAN_FRONTEND=noninteractive apt-get install -y $DPKG_CONF kali-linux-default || true" ;;
  large)   TOOLSET_RUNCMD="DEBIAN_FRONTEND=noninteractive apt-get install -y $DPKG_CONF kali-linux-large || true" ;;
  *)       echo "ERROR: KALI_TOOLSET must be minimal|default|large (got: $KALI_TOOLSET)" >&2; exit 1 ;;
esac

cat > "$USERDATA_PATH" << SNIPPET
#cloud-config
hostname: $NAME
manage_etc_hosts: true

# IMPORTANT: do NOT set manage_resolv_conf / resolv_conf here. Those persist
# DNS state to disk so every clone inherits the bake-time DNS server, which
# is only reachable from the bake-time VLAN. Lane clones need DHCP-provided
# DNS from the lane gateway's dnsmasq. Use bootcmd (transient) only, then
# nuke /etc/resolv.conf in runcmd before sealing so DHCP fills it on clone
# boot.
bootcmd:
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf; exit 0' ]

users:
  - name: $TEMPLATE_USER
    groups: [sudo]
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
# cloud-init's packages: invokes apt with --force-confdef + --force-confold,
# which auto-resolves conffile conflicts (keeps the version write_files
# wrote). Don't try to "harden" this with an extra apt-get install in
# runcmd — that runs without those flags and dpkg will prompt forever on
# /etc/xrdp/startwm.sh, leaving xrdp half-configured and not listening.
# Keep package names current with Kali rolling: policykit-1 → polkitd,
# dnsutils → bind9-dnsutils (transitional packages can disappear at any
# weekly snapshot).
packages:
  - qemu-guest-agent
  - openssh-server
  - kali-desktop-xfce
  - xrdp
  - xorgxrdp
  - libjpeg62-turbo
  - dbus-x11
  - polkitd
  - sudo
  - curl
  - wget
  - vim
  - net-tools
  - bind9-dnsutils
  # resolvconf wires dhclient → /etc/resolv.conf (option 6 from DHCP, plus
  # the dns-nameservers field cloud-init writes into /etc/network/interfaces).
  # Without it, /etc/resolv.conf stays empty on lane clones even though IP
  # and routing work.
  - resolvconf
  - ca-certificates

write_files:
  # Make xrdp launch xfce4 instead of the default (which usually fails to
  # find a session and lands at a blank screen).
  - path: /etc/xrdp/startwm.sh
    permissions: '0755'
    content: |
      #!/bin/sh
      if test -r /etc/profile; then . /etc/profile; fi
      if test -r ~/.profile; then . ~/.profile; fi
      export XDG_SESSION_DESKTOP=xfce
      export XDG_CURRENT_DESKTOP=XFCE
      exec /usr/bin/startxfce4

  # Polkit rule so xrdp users don't get prompted for "auth required" dialogs
  # for color-manager/network-manager/packagekit on session start. Without
  # this the desktop hangs waiting for an admin password no one will type.
  - path: /etc/polkit-1/rules.d/50-xrdp-no-prompt.rules
    permissions: '0644'
    content: |
      polkit.addRule(function(action, subject) {
          if ((action.id == "org.freedesktop.color-manager.create-device" ||
               action.id == "org.freedesktop.color-manager.create-profile" ||
               action.id == "org.freedesktop.color-manager.delete-device" ||
               action.id == "org.freedesktop.color-manager.delete-profile" ||
               action.id == "org.freedesktop.color-manager.modify-device" ||
               action.id == "org.freedesktop.color-manager.modify-profile" ||
               action.id == "org.freedesktop.NetworkManager.network-control" ||
               action.id == "org.freedesktop.packagekit.system-network-proxy-configure")) {
              return polkit.Result.YES;
          }
      });

  # Bake-complete marker. Pre-seal verifier checks for this file's existence
  # and the libjpeg integrity flag below before converting to template.
  - path: /etc/cybercore-bake.env
    permissions: '0644'
    content: |
      BAKE_NAME=$NAME
      BAKE_VMID=$VMID
      BAKE_TOOLSET=$KALI_TOOLSET

runcmd:
  # Install the Kali toolset metapackage (separate from cloud-init 'packages:'
  # so the failure mode is isolated; toolset install can take 20+ minutes).
  # Pass --force-confdef + --force-confold so dpkg auto-resolves conffile
  # conflicts the same way cloud-init's packages: step does — keeps any
  # files write_files wrote (e.g., /etc/xrdp/startwm.sh) and skips the
  # interactive prompt that would otherwise hang the install.
  - [ sh, -c, '$TOOLSET_RUNCMD' ]

  # Disable the graphical display manager — templates are headless on the
  # console; xrdp creates X sessions on demand. Also stops the "boot lands
  # at lightdm greeter on noVNC" UX confusion.
  - [ sh, -c, 'systemctl set-default multi-user.target' ]
  - [ sh, -c, 'systemctl disable lightdm.service 2>/dev/null || true' ]
  - [ sh, -c, 'systemctl disable gdm3.service 2>/dev/null || true' ]

  # xrdp wants its user in the ssl-cert group to read /etc/ssl/private/.
  - [ sh, -c, 'adduser xrdp ssl-cert || true' ]

  # Enable + start xrdp now so the bake-time check below has something to
  # probe. (systemctl enable persists across the template->clone transition.)
  - [ systemctl, enable, xrdp ]
  - [ systemctl, enable, xrdp-sesman ]
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, enable, ssh ]
  - [ systemctl, start, xrdp ]
  - [ systemctl, start, xrdp-sesman ]

  # ---- Pre-seal sanity: catch the libjpeg-truncation class of corruption
  # ----                  BEFORE the bake script converts to template.
  # If libjpeg.so.62.4.0 is 0 bytes (or anything <50KB), apt's mirror gave
  # us a torn write and xrdp will fail to load. Mark this in the env file so
  # the host-side verifier can see it.
  # Note: \$ escapes here are deliberate — we want the VM's shell to expand
  # \$sz and \$(...) at runcmd time, not the bake script's heredoc.
  - [ sh, -c, 'sz=\$(stat -c %s /usr/lib/x86_64-linux-gnu/libjpeg.so.62.* 2>/dev/null | sort -n | head -1); echo "LIBJPEG_SIZE=\$sz" >> /etc/cybercore-bake.env' ]

  # Confirm xrdp is bound to 3389 (sesman on 3350).
  - [ sh, -c, 'sleep 3; ss -ltn "( sport = :3389 )" | grep -q LISTEN && echo "XRDP_LISTEN=yes" >> /etc/cybercore-bake.env || echo "XRDP_LISTEN=no" >> /etc/cybercore-bake.env' ]

  # Mark the bake as complete BEFORE the cleanup steps below — the verifier
  # checks /etc/cybercore-bake.env (which survives cloud-init clean), unlike
  # /var/lib/cloud/instances/<iid>/bake-complete which gets wiped.
  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]

  # Reset /etc/resolv.conf to its proper symlink form so the template
  # doesn't ship with bake-time DNS baked in. resolvconf's postinst sets
  # /etc/resolv.conf as a symlink to /run/resolvconf/resolv.conf — but
  # bootcmd's `printf "nameserver $BAKE_DNS\n" > /etc/resolv.conf` followed
  # by anything that opens that path with O_TRUNC will replace the symlink
  # with a regular file. After that, resolvconf still tracks DHCP-provided
  # DNS internally but has nowhere to publish it, so /etc/resolv.conf stays
  # empty on every clone (the precise bug we hit).
  #
  # Removing and re-symlinking restores resolvconf's view of the world.
  # /run is tmpfs so the target gets recreated on each boot anyway.
  - [ sh, -c, 'rm -f /etc/resolv.conf; ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf' ]

  # Preserve cloud-init logs in /etc/ before clean wipes them. The host-side
  # verifier reads /etc/cybercore-cloud-init.log when a bake fails, so we
  # have something to look at when packages: silently fails (apt+DNS issues
  # are otherwise invisible after clean).
  - [ sh, -c, 'cp /var/log/cloud-init-output.log /etc/cybercore-cloud-init.log 2>/dev/null || true' ]

  # Drop cached cloud-init state + network configs so the per-clone cidata
  # drive is the sole source of truth on next boot. cloud-init clean removes
  # /var/lib/cloud/instances/* (including any prior instance-id), forcing
  # cloud-init to treat the clone as a brand-new instance.
  - [ sh, -c, 'rm -f /etc/netplan/50-cloud-init.yaml /etc/network/interfaces.d/50-cloud-init 2>/dev/null || true' ]
  - [ cloud-init, clean, --logs, --seed ]

# Power off so the bake script knows we're done. Cloud-init's instance-id
# changes on clone, so this user-data won't re-run on per-lane clones.
power_state:
  mode: poweroff
  delay: '+1'
  message: 'Kali template bake complete'
  timeout: 1800
SNIPPET

echo "==> Wrote bake-time cloud-init snippet: $USERDATA_PATH"

# ---------- 3. Create VM ----------
echo "==> Creating VM $VMID ($NAME)..."

NET0="virtio,bridge=${BAKE_BRIDGE},firewall=0"
[ -n "${BAKE_VLAN:-}" ] && NET0="${NET0},tag=${BAKE_VLAN}"

# SeaBIOS, not OVMF — Kali cloud images are configured for legacy BIOS boot.
# Switching to OVMF requires repartitioning the qcow2 with an ESP and that's
# not what the cloud image ships with.
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
  --description "Kali Rolling template (xfce + xrdp). Baked from front-end/scripts/bake-kali-template.sh."

echo "==> Importing cloud image as VM disk..."
qm disk import $VMID "$CLOUD_IMG_LOCAL" "$STORAGE"
qm set $VMID --scsi0 "${STORAGE}:vm-${VMID}-disk-0,discard=on,ssd=1"
qm set $VMID --boot order=scsi0

echo "==> Resizing disk to ${DISK_GB}G..."
qm resize $VMID scsi0 ${DISK_GB}G || true

echo "==> Adding cloud-init drive..."
qm set $VMID --ide2 "${STORAGE}:cloudinit"

qm set $VMID \
  --ciuser "$TEMPLATE_USER" \
  --cipassword "$TEMPLATE_PASSWORD" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/$(basename "$USERDATA_PATH")"

# ---------- 4. Boot, wait for cloud-init to finish ----------
echo "==> Starting VM (cloud-init installs xfce + xrdp + toolset; ~10–30 min)..."
qm start $VMID

# Toolset 'large' can take 30+ minutes; ceiling generously.
case "$KALI_TOOLSET" in
  minimal) DEADLINE_SECS=900 ;;     # 15 min
  default) DEADLINE_SECS=1800 ;;    # 30 min
  large)   DEADLINE_SECS=3600 ;;    # 60 min
esac
DEADLINE=$(( $(date +%s) + DEADLINE_SECS ))
echo "==> Waiting up to $((DEADLINE_SECS/60)) min for cloud-init + power-off..."
while true; do
  STATUS=$(qm status $VMID | awk '{print $2}')
  if [ "$STATUS" = "stopped" ]; then
    echo "==> VM powered off (cloud-init done)."
    break
  fi
  if [ $(date +%s) -ge $DEADLINE ]; then
    echo "ERROR: cloud-init did not finish in time. Inspect:" >&2
    echo "       qm terminal $VMID  (then ^O to exit)" >&2
    exit 1
  fi
  sleep 15
done

# ---------- 4b. Pre-seal verification ----------
# Mount the rootfs read-only, check the bake-complete marker AND the
# libjpeg/xrdp sanity flags written by runcmd. Refusing to seal a corrupt
# template is the whole point of this section.
echo "==> Verifying bake markers (libjpeg integrity + xrdp listen + cloud-init complete)..."
VERIFY_DEV=""
case "$STORAGE" in
  *ceph*|vmpool|rbd*)
    VERIFY_DEV=$(rbd map ${STORAGE}/vm-${VMID}-disk-0 --id admin 2>/dev/null) || VERIFY_DEV=""
    ;;
esac

if [ -z "$VERIFY_DEV" ]; then
  echo "WARNING: storage '$STORAGE' isn't a Ceph rbd pool; skipping marker verification."
  echo "         Manually verify before relying on the template:"
  echo "           qm start $VMID && qm guest exec $VMID -- cat /etc/cybercore-bake.env"
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
    [ -f "$BAKE_ENV" ] || BAKE_ENV=""

    FAIL=0
    if [ -n "$BAKE_ENV" ]; then
      BAKE_COMPLETE=$(awk -F= '/^BAKE_COMPLETE=/{print $2}' "$BAKE_ENV")
      LIBJPEG_SIZE=$(awk -F= '/^LIBJPEG_SIZE=/{print $2}' "$BAKE_ENV")
      XRDP_LISTEN=$(awk -F= '/^XRDP_LISTEN=/{print $2}' "$BAKE_ENV")
      echo "    bake complete:      ${BAKE_COMPLETE:-no}"
      echo "    libjpeg.so.62 size: ${LIBJPEG_SIZE:-unknown} bytes"
      echo "    xrdp listening:     ${XRDP_LISTEN:-unknown}"
      if [ "$BAKE_COMPLETE" != "yes" ]; then
        echo "ERROR: BAKE_COMPLETE!=yes — runcmd didn't reach the end."
        FAIL=1
      fi
      if [ -z "$LIBJPEG_SIZE" ] || [ "$LIBJPEG_SIZE" -lt 50000 ]; then
        echo "ERROR: libjpeg.so.62 is missing or truncated (<50KB) — same corruption that broke the prior template."
        FAIL=1
      fi
      if [ "$XRDP_LISTEN" != "yes" ]; then
        echo "ERROR: xrdp did not bind to 3389 inside the bake VM."
        FAIL=1
      fi
    else
      echo "ERROR: /etc/cybercore-bake.env not found — runcmd didn't run."
      FAIL=1
    fi

    if [ "$FAIL" = "1" ]; then
      echo ""
      echo "==================================================================="
      echo "  Last 80 lines of cloud-init-output.log inside the VM:"
      echo "==================================================================="
      # /var/log/cloud-init-output.log gets wiped by `cloud-init clean --logs`
      # at the end of bake-time runcmd, so the runcmd preserves it at
      # /etc/cybercore-cloud-init.log. Try the preserved copy first, fall
      # back to the canonical location for legacy templates without the copy.
      LOG_FILE="$VERIFY_MOUNT/etc/cybercore-cloud-init.log"
      [ -f "$LOG_FILE" ] || LOG_FILE="$VERIFY_MOUNT/var/log/cloud-init-output.log"
      tail -80 "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (no cloud-init log captured)"
      umount "$VERIFY_MOUNT"
      rmdir "$VERIFY_MOUNT"
      rbd unmap "$VERIFY_DEV" 2>/dev/null || true
      echo ""
      echo "Refusing to seal a broken template. VM $VMID left intact for inspection."
      echo "After fixing root cause: qm destroy $VMID --purge && rerun this script."
      exit 1
    fi
    umount "$VERIFY_MOUNT"
    echo "==> All bake markers OK."
  else
    echo "WARNING: could not mount ${VERIFY_DEV}p1 — skipping marker verification."
  fi
  rmdir "$VERIFY_MOUNT" 2>/dev/null || true
  rbd unmap "$VERIFY_DEV" 2>/dev/null || true
fi

# ---------- 5. Strip the bake-time cloud-init config ----------
# Proxmox stores cloud-init params at the VM-config level (separate from the
# cicustom snippet). They INHERIT to clones — including --nameserver, which
# is exactly what bit us: every clone got the bake-time DNS burned into
# /etc/resolv.conf on first boot, with no upstream visibility. Strip
# everything bake-specific so per-clone admin.js settings are the only
# source of truth.
echo "==> Clearing bake-time cicustom + cloud-init fields (nameserver/searchdomain)..."
qm set $VMID --delete cicustom
qm set $VMID --delete nameserver 2>/dev/null || true
qm set $VMID --delete searchdomain 2>/dev/null || true
qm cloudinit dump $VMID user 2>/dev/null > /dev/null || true

# ---------- 6. Convert to template ----------
echo "==> Converting VM to template..."
qm template $VMID

echo ""
echo "==================================================================="
echo "  Kali template $VMID baked successfully"
echo "==================================================================="
echo "  Verify:        qm config $VMID"
echo "  Test clone:    qm clone $VMID 9994 --name kali-test --full --storage $STORAGE"
echo "  Then start:    qm set 9994 --net0 virtio,bridge=$BAKE_BRIDGE${BAKE_VLAN:+,tag=$BAKE_VLAN}"
echo "                 qm start 9994"
echo "  RDP via:       Guacamole at rdp.saguaroscyberhub.org (user: $TEMPLATE_USER)"
echo "==================================================================="
