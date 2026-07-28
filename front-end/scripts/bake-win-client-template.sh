#!/bin/bash
# ============================================================================
# bake-win-client-template.sh
# ----------------------------------------------------------------------------
# Builds a sysprep-generalized Windows 11 (25H2) CLIENT template for use as a
# student workstation / attack box. The result is a Proxmox VM template at
# VMID 1002 that the orchestrator can clone per-lane.
#
# Unlike bake-win-server-template.sh this is SELF-CONTAINED: no packer, no GOAD
# repo. It drives `qm` directly and does the whole install through an
# Autounattend.xml on a generated ISO. Fewer moving parts, and nothing here
# depends on upstream GOAD's packer templates keeping a Win11 config.
#
# What the finished template has, and why each piece matters:
#
#   - sysprep /generalize  — every clone gets a fresh machine SID. Without this
#     all 30 students' machines share one SID; it breaks any future domain join
#     and confuses anything that keys off SID.
#   - cloudbase-init       — this is what makes per-student credentials work.
#     The orchestrator sets ciuser/cipassword on the clone
#     (src/utils/lane-deployer.js) and cloudbase-init creates that account on
#     first boot. WITHOUT IT the deploy still runs but every student lands at a
#     login prompt they have no password for.
#   - ostype win11         — Proxmox derives the cloud-init format from ostype:
#     configdrive2 for Windows, nocloud for Linux. cloudbase-init only reads
#     configdrive2. Get this wrong and credential injection silently no-ops.
#   - virtio guest tools   — NetKVM (network), balloon, and qemu-guest-agent.
#     Stock Windows has no virtio-net driver at all; the orchestrator gives
#     Windows guests an e1000 NIC for exactly that reason, but the agent is what
#     lets the IP-confirmation check see the lease.
#   - RDP enabled + firewall rule — the console path is RDP through the lane
#     gateway's DNAT. A template with RDP off produces a lane that deploys
#     "successfully" and refuses every connection.
#
# ---------------------------------------------------------------------------
# ON PRODUCT KEYS: you do not need one to build or use this template.
#
# Windows 11 installs and runs fine unactivated. WIN_PRODUCT_KEY is empty by
# default and the answer file tells Setup never to prompt, so the build is fully
# unattended either way. The EDITION is chosen by name from the ISO
# (/IMAGE/NAME), which is a completely separate mechanism from licensing — no
# key is involved in picking Pro vs Home.
#
# What "unactivated" actually costs you in a lab:
#   - a watermark in the bottom-right corner
#   - Personalization settings (wallpaper/theme) are locked
#   - occasional "activate Windows" nags
#   - everything else — RDP, networking, tooling, domain join — works normally
#
# If you later get keys (most universities have an Education/Volume agreement,
# and Azure Education gives students Windows client keys), you do NOT need to
# rebake. Activate the running template or its clones with:
#     slmgr /ipk <key> && slmgr /ato
# Or set WIN_PRODUCT_KEY=<key> and rebake to have it baked in.
#
# If you'd rather have a legitimately-licensed image with no watermark, use the
# Windows 11 Enterprise *Evaluation* ISO from the Microsoft Evaluation Center —
# it's free, needs no key, and runs 90 days (rearmable). That's the same pattern
# the server bake uses: your 2019_SERVER_EVAL ISO is an eval image.
# ---------------------------------------------------------------------------
#
# Run as root on a Proxmox node. Takes ~40-70 min, mostly unattended Windows
# setup. The script polls the guest agent and prints progress.
#
# Usage:
#   bash bake-win-client-template.sh
#   FORCE=1 bash bake-win-client-template.sh          # replace an existing 1002
#   OS_DISK_BUS=sata bash bake-win-client-template.sh # if virtio-scsi injection fails
#
# Env vars (override defaults):
#   PROXMOX_NODE      — node name                     (default: $(hostname))
#   PROXMOX_STORAGE   — where the template disk lands (default: vmpool)
#   PROXMOX_BRIDGE    — build-time network bridge     (default: vmbr0)
#   PROXMOX_BUILD_VLAN— VLAN tag for build internet   (default: 10)
#   ISO_STORAGE       — storage holding the ISOs      (default: auto-detect cephfs > local)
#   WIN_ISO_NAME      — Windows 11 ISO filename       (default: auto-detect *Windows*11*.iso)
#   VIRTIO_ISO_NAME   — virtio-win ISO filename       (default: newest virtio-win*.iso)
#   WIN_EDITION       — image name to install         (default: "Windows 11 Pro")
#   WIN_PRODUCT_KEY   — optional product key          (default: none — see below)
#   FINAL_VMID        — template VMID                 (default: 1002)
#   BUILD_VMID        — scratch VMID used for install (default: 9902)
#   ADMIN_PASSWORD    — bake-time local admin password(default: CyberCore!Bake1)
#   OS_DISK_BUS       — scsi | sata                   (default: scsi)
#   DISK_GB           — template disk size            (default: 64)
#   BUILD_CORES/BUILD_MEM — build VM resources        (default: 4 / 8192)
#   KEEP_BUILD_VM=1   — don't destroy the scratch VM (for debugging a failure)
# ============================================================================
set -euo pipefail

PROXMOX_NODE="${PROXMOX_NODE:-$(hostname)}"
PROXMOX_STORAGE="${PROXMOX_STORAGE:-vmpool}"
PROXMOX_BRIDGE="${PROXMOX_BRIDGE:-vmbr0}"
PROXMOX_BUILD_VLAN="${PROXMOX_BUILD_VLAN:-10}"
ISO_STORAGE="${ISO_STORAGE:-}"
WIN_ISO_NAME="${WIN_ISO_NAME:-}"
VIRTIO_ISO_NAME="${VIRTIO_ISO_NAME:-}"
WIN_EDITION="${WIN_EDITION:-Windows 11 Pro}"
# Empty = install unattended with no key (runs unactivated). See the note above.
WIN_PRODUCT_KEY="${WIN_PRODUCT_KEY:-}"
FINAL_VMID="${FINAL_VMID:-1002}"
BUILD_VMID="${BUILD_VMID:-9902}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-CyberCore!Bake1}"
# Secure Boot OFF by default. The VM still gets UEFI + a real vTPM 2.0, which is
# what Windows 11 actually checks for.
#
# To be clear about why, since an earlier revision of this script blamed Secure
# Boot for a boot failure it did not cause: the observed failure was the CD boot
# PROMPT timing out (see section 1c), which proves the ISO's signed loader ran
# fine. Secure Boot is off here only to keep one less variable in a lab image,
# not as a workaround. Set SECURE_BOOT=1 if you want it.
SECURE_BOOT="${SECURE_BOOT:-0}"
OS_DISK_BUS="${OS_DISK_BUS:-scsi}"
DISK_GB="${DISK_GB:-64}"
BUILD_CORES="${BUILD_CORES:-4}"
BUILD_MEM="${BUILD_MEM:-8192}"
FORCE="${FORCE:-0}"
KEEP_BUILD_VM="${KEEP_BUILD_VM:-0}"
CLOUDBASE_URL="${CLOUDBASE_URL:-https://cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi}"
TEMPLATE_NAME="${TEMPLATE_NAME:-Win11-25H2-Workstation}"

# Windows setup can sit on a single step for a long time; total install budget.
INSTALL_TIMEOUT_MIN="${INSTALL_TIMEOUT_MIN:-70}"

echo "=========================================================================="
echo " Windows 11 client workstation template baker"
echo "=========================================================================="
echo " Node          : $PROXMOX_NODE"
echo " VM storage    : $PROXMOX_STORAGE"
echo " ISO storage   : ${ISO_STORAGE:-auto-detect}"
echo " Bridge / VLAN : $PROXMOX_BRIDGE${PROXMOX_BUILD_VLAN:+ / vlan $PROXMOX_BUILD_VLAN}"
echo " Edition       : $WIN_EDITION"
echo " Disk bus/size : $OS_DISK_BUS / ${DISK_GB}G"
echo " Build VMID    : $BUILD_VMID  (scratch)"
echo " Final VMID    : $FINAL_VMID  ($TEMPLATE_NAME)"
echo "=========================================================================="

# ---------- 0. Sanity ----------
if [ "$(id -u)" != "0" ]; then
  echo "ERROR: must run as root on a Proxmox node." >&2
  exit 1
fi
if ! command -v qm >/dev/null 2>&1; then
  echo "ERROR: 'qm' not found — this must run on a Proxmox VE node." >&2
  exit 1
fi

if qm status "$FINAL_VMID" >/dev/null 2>&1; then
  if [ "$FORCE" != "1" ]; then
    echo "ERROR: VMID $FINAL_VMID already exists. Re-run with FORCE=1 to replace it," >&2
    echo "       or destroy it first:  qm destroy $FINAL_VMID --purge" >&2
    exit 1
  fi
  echo "==> FORCE=1: existing $FINAL_VMID will be destroyed at the end of the build."
fi
if qm status "$BUILD_VMID" >/dev/null 2>&1; then
  echo "ERROR: scratch VMID $BUILD_VMID is in use. Set BUILD_VMID=<free id> or destroy it." >&2
  exit 1
fi

# ADMIN_PASSWORD is injected verbatim into Autounattend.xml. An XML-special
# character there produces malformed XML, and Setup responds by silently
# ignoring the whole answer file — which surfaces as a mysteriously interactive
# install rather than an error.
case "$ADMIN_PASSWORD" in
  *'<'*|*'>'*|*'&'*|*'"'*|*"'"*)
    echo "ERROR: ADMIN_PASSWORD contains an XML-special character ( < > & \" ' )." >&2
    echo "       Pick one without those — it is written straight into Autounattend.xml." >&2
    exit 1 ;;
esac

need_install=()
command -v genisoimage >/dev/null 2>&1 || command -v mkisofs >/dev/null 2>&1 || need_install+=("genisoimage")
command -v wget >/dev/null 2>&1 || need_install+=("wget")
if [ ${#need_install[@]} -gt 0 ]; then
  echo "==> Installing: ${need_install[*]}"
  apt-get update -qq
  apt-get install -qq -y "${need_install[@]}" >/dev/null
fi
MKISO=$(command -v genisoimage || command -v mkisofs)

# ---------- 1. Resolve ISO storage + the two source ISOs ----------
pick_iso_storage() {
  if [ -n "$ISO_STORAGE" ]; then echo "$ISO_STORAGE"; return 0; fi
  local cephfs first
  cephfs=$(pvesm status -content iso 2>/dev/null | awk 'NR>1 && $1=="cephfs" {print $1}' | head -1)
  if [ -n "$cephfs" ]; then echo "$cephfs"; return 0; fi
  first=$(pvesm status -content iso 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then echo "$first"; return 0; fi
  echo "local"
}
ISO_STORAGE=$(pick_iso_storage)
echo "==> ISO storage: $ISO_STORAGE"

# Find an ISO already present in ISO_STORAGE. `pvesm list` returns volids like
# "cephfs:iso/Windows_11_25H2.iso". Sorted descending so a version-suffixed
# match (virtio-win-0.1.285) beats older copies.
find_iso() {
  local pattern="$1" override="$2"
  if [ -n "$override" ]; then
    local volid="${ISO_STORAGE}:iso/${override}"
    if pvesm list "$ISO_STORAGE" 2>/dev/null | awk '{print $1}' | grep -qx "$volid"; then
      echo "$volid"; return 0
    fi
    echo "ERROR: override ISO '$override' not found in $ISO_STORAGE" >&2
    return 1
  fi
  pvesm list "$ISO_STORAGE" 2>/dev/null | awk '{print $1}' \
    | grep -iE "$pattern" | sort -Vr | head -1
}

WIN_ISO=$(find_iso 'iso/.*windows.*11.*\.iso$' "$WIN_ISO_NAME" || true)
if [ -z "$WIN_ISO" ]; then
  echo "ERROR: no Windows 11 ISO found in $ISO_STORAGE." >&2
  echo "       Available ISOs:" >&2
  pvesm list "$ISO_STORAGE" 2>/dev/null | awk 'NR>1 {print "         " $1}' >&2
  echo "       Set WIN_ISO_NAME=<filename> to pick one explicitly." >&2
  exit 1
fi

VIRTIO_ISO=$(find_iso 'iso/virtio-win.*\.iso$' "$VIRTIO_ISO_NAME" || true)
if [ -z "$VIRTIO_ISO" ]; then
  echo "ERROR: no virtio-win ISO found in $ISO_STORAGE." >&2
  echo "       Set VIRTIO_ISO_NAME=<filename> or download one from" >&2
  echo "       https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/" >&2
  exit 1
fi

echo "==> Windows ISO : $WIN_ISO"
echo "==> virtio ISO  : $VIRTIO_ISO"

# Resolve the on-disk path + directory once; both the edition check and the
# no-prompt repack below need them, and so does the answer-ISO copy later.
WIN_ISO_PATH=$(pvesm path "$WIN_ISO" 2>/dev/null || true)
if [ -z "$WIN_ISO_PATH" ] || [ ! -f "$WIN_ISO_PATH" ]; then
  echo "ERROR: could not resolve a filesystem path for $WIN_ISO" >&2
  exit 1
fi
ISO_DIR=$(dirname "$WIN_ISO_PATH")

# ---------- 1b. Verify WIN_EDITION exists in this ISO ----------
# A wrong edition name is the single most expensive failure mode here: Setup
# stops on the "Select the operating system" picker, nothing is on the console
# to see it, and the script only finds out when the 70-minute timeout expires.
# Reading the image list up front turns that into a 5-second error.
#
# Best-effort: if the ISO can't be loop-mounted or wimlib isn't available we
# warn and continue rather than blocking the build.
check_edition() {
  local mnt wim
  # NOTE: do not write this as `[ A ] || [ B ] && { ...; }`. When both tests are
  # false — i.e. the SUCCESS path — that list's exit status is 1, and `set -e`
  # then kills the script before the build ever starts.

  if ! command -v wiminfo >/dev/null 2>&1; then
    echo "==> Installing wimtools (to read the ISO's edition list)..."
    apt-get install -qq -y wimtools >/dev/null 2>&1 || {
      echo "    (wimtools unavailable — skipping edition check)"; return 0; }
  fi

  mnt=$(mktemp -d)
  if ! mount -o loop,ro "$WIN_ISO_PATH" "$mnt" 2>/dev/null; then
    rmdir "$mnt"; echo "    (could not mount ISO — skipping edition check)"; return 0
  fi

  # if/elif, not `[ test ] && assign` — a false test makes that list return 1,
  # which under `set -e` exits the whole script instead of falling through.
  wim=""
  if   [ -f "$mnt/sources/install.wim" ]; then wim="$mnt/sources/install.wim"
  elif [ -f "$mnt/sources/install.esd" ]; then wim="$mnt/sources/install.esd"
  fi
  if [ -z "$wim" ]; then
    umount "$mnt"; rmdir "$mnt"
    echo "    (no sources/install.wim|esd on the ISO — skipping edition check)"; return 0
  fi

  local editions
  editions=$(wiminfo "$wim" 2>/dev/null | sed -n 's/^Name:[[:space:]]*//p')
  umount "$mnt"; rmdir "$mnt"

  if [ -z "$editions" ]; then
    echo "    (could not read image names — skipping edition check)"; return 0
  fi

  echo "==> Editions in this ISO:"
  echo "$editions" | sed 's/^/      /'

  if ! printf '%s\n' "$editions" | grep -qxF "$WIN_EDITION"; then
    echo "" >&2
    echo "ERROR: WIN_EDITION '$WIN_EDITION' is not in this ISO." >&2
    echo "       Setup would stall on the edition picker with nothing watching the" >&2
    echo "       console, and this script would only notice at the timeout." >&2
    echo "       Re-run with one of the names listed above, e.g.:" >&2
    echo "         WIN_EDITION='$(printf '%s\n' "$editions" | head -1)' bash \$0" >&2
    exit 1
  fi
  echo "==> Edition '$WIN_EDITION' found in ISO."
}
check_edition

# ---------- 1c. Remove the "Press any key to boot from CD" prompt ----------
# THE fix for the failure that cost several build cycles.
#
# Microsoft's ISOs boot via an El Torito EFI image at efi/microsoft/boot/
# efisys.bin, whose loader prints "Press any key to boot from CD or DVD..." and
# gives up after ~5 seconds. In an unattended build nothing answers it, so OVMF
# walks on to the empty disk and then PXE — which is exactly the boot-menu and
# PXE-E16 screens this script produced before.
#
# Microsoft ships the answer on the same ISO: efisys_noprompt.bin, an identical
# boot image whose loader boots straight in. Swapping it and repacking removes
# the race entirely instead of trying to win it with well-timed keystrokes.
#
# The result is cached next to the source ISO, so this ~5 minute repack happens
# once, not on every bake. Failure here is non-fatal: we fall back to the
# original ISO and the sendkey loop, which is what we had before.
NOPROMPT_REPACK="${NOPROMPT_REPACK:-1}"
REPACK_TMPDIR="${REPACK_TMPDIR:-/var/tmp}"
BOOT_ISO="$WIN_ISO"          # what ide0 actually gets

prepare_noprompt_iso() {
  local base out_name out_path label mnt extract src_bytes need_kb free_kb noprompt efisys

  if [ "$NOPROMPT_REPACK" != "1" ]; then
    echo "==> NOPROMPT_REPACK=0 — using the original ISO (relying on sendkey alone)"
    return 0
  fi

  base=$(basename "$WIN_ISO_PATH")
  out_name="cybercore-noprompt-${base}"
  out_path="${ISO_DIR}/${out_name}"

  if [ -f "$out_path" ] && [ "$out_path" -nt "$WIN_ISO_PATH" ]; then
    echo "==> No-prompt ISO (cached): ${ISO_STORAGE}:iso/${out_name}"
    BOOT_ISO="${ISO_STORAGE}:iso/${out_name}"
    return 0
  fi

  if ! command -v xorriso >/dev/null 2>&1; then
    echo "==> Installing xorriso (to repack the ISO without the boot prompt)..."
    if ! apt-get install -qq -y xorriso >/dev/null 2>&1; then
      echo "    WARNING: xorriso unavailable — keeping the original ISO." >&2
      echo "             The build will depend on the sendkey loop winning a ~5s race." >&2
      return 0
    fi
  fi

  # Extract + rebuild needs roughly 2x the ISO size.
  src_bytes=$(stat -c %s "$WIN_ISO_PATH")
  need_kb=$(( (src_bytes / 1024) * 2 + 1048576 ))
  free_kb=$(df -Pk "$REPACK_TMPDIR" | awk 'NR==2 {print $4}')
  if [ "$free_kb" -lt "$need_kb" ]; then
    echo "    WARNING: need ~$((need_kb/1048576))G free in $REPACK_TMPDIR, have $((free_kb/1048576))G." >&2
    echo "             Skipping repack (set REPACK_TMPDIR=<roomier path> to enable)." >&2
    return 0
  fi

  mnt=$(mktemp -d)
  if ! mount -o loop,ro "$WIN_ISO_PATH" "$mnt" 2>/dev/null; then
    rmdir "$mnt"
    echo "    WARNING: could not mount the ISO — skipping repack." >&2
    return 0
  fi

  # Path case varies between ISO releases; find both files case-insensitively.
  noprompt=$(find "$mnt" -ipath '*/efi/microsoft/boot/efisys_noprompt.bin' | head -1)
  efisys=$(find "$mnt"   -ipath '*/efi/microsoft/boot/efisys.bin'          | head -1)
  if [ -z "$noprompt" ] || [ -z "$efisys" ]; then
    umount "$mnt"; rmdir "$mnt"
    echo "    WARNING: efisys_noprompt.bin not present on this ISO — keeping the original." >&2
    return 0
  fi

  label=$(blkid -o value -s LABEL "$WIN_ISO_PATH" 2>/dev/null || echo "CCWIN11")

  extract="${REPACK_TMPDIR}/cybercore-win11-repack.$$"
  echo "==> Repacking the Windows ISO without the boot prompt (one-time, ~5 min)..."
  rm -rf "$extract"; mkdir -p "$extract"

  if ! xorriso -osirrox on -indev "$WIN_ISO_PATH" -extract / "$extract" >/dev/null 2>&1; then
    umount "$mnt"; rmdir "$mnt"; rm -rf "$extract"
    echo "    WARNING: ISO extract failed — keeping the original." >&2
    return 0
  fi
  umount "$mnt"; rmdir "$mnt"

  # xorriso extracts read-only; make the tree writable before swapping.
  chmod -R u+w "$extract" 2>/dev/null || true

  local rel_efisys rel_noprompt
  rel_efisys=$(cd "$extract" && find . -ipath './efi/microsoft/boot/efisys.bin'          | head -1)
  rel_noprompt=$(cd "$extract" && find . -ipath './efi/microsoft/boot/efisys_noprompt.bin' | head -1)
  if [ -z "$rel_efisys" ] || [ -z "$rel_noprompt" ]; then
    rm -rf "$extract"
    echo "    WARNING: boot images missing after extract — keeping the original." >&2
    return 0
  fi
  cp -f "${extract}/${rel_noprompt#./}" "${extract}/${rel_efisys#./}"
  echo "    Swapped $(basename "$rel_efisys") <- $(basename "$rel_noprompt")"

  # UEFI-only El Torito. -iso-level 4 + -udf keeps the >4GB install.wim intact,
  # which a plain ISO9660 build would refuse or silently truncate.
  if ! xorriso -as mkisofs \
        -iso-level 4 -udf \
        -V "$label" \
        -J -joliet-long -rational-rock \
        -e "${rel_efisys#./}" -no-emul-boot \
        -o "${out_path}.tmp" "$extract" >/dev/null 2>&1; then
    rm -rf "$extract" "${out_path}.tmp"
    echo "    WARNING: ISO rebuild failed — keeping the original." >&2
    return 0
  fi

  mv -f "${out_path}.tmp" "$out_path"
  rm -rf "$extract"
  BOOT_ISO="${ISO_STORAGE}:iso/${out_name}"
  echo "==> No-prompt ISO ready: $BOOT_ISO"
}
prepare_noprompt_iso

# ---------- 2. Stage cloudbase-init + build the answer/scripts ISO ----------
# Everything the guest needs goes on ONE ISO: Autounattend.xml at the root (where
# Windows Setup looks for it) plus the cloudbase-init MSI and our provisioning
# script. That avoids a fourth CD-ROM and avoids the guest needing internet.
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

CLOUDBASE_CACHE="/var/cache/cybercore/CloudbaseInitSetup_Stable_x64.msi"
mkdir -p "$(dirname "$CLOUDBASE_CACHE")"
if [ ! -s "$CLOUDBASE_CACHE" ]; then
  echo "==> Downloading cloudbase-init MSI..."
  wget --progress=dot:giga -O "${CLOUDBASE_CACHE}.tmp" "$CLOUDBASE_URL"
  mv "${CLOUDBASE_CACHE}.tmp" "$CLOUDBASE_CACHE"
else
  echo "==> cloudbase-init MSI (cached): $CLOUDBASE_CACHE"
fi
cp "$CLOUDBASE_CACHE" "$STAGING/CloudbaseInitSetup_x64.msi"

# Product key block. With no key we emit ONLY <WillShowUI>Never</WillShowUI>,
# which is what makes Setup skip the "enter your product key" page instead of
# blocking a supposedly-unattended install. An empty <Key></Key> element is NOT
# equivalent — Setup treats it as an invalid key and stops.
if [ -n "$WIN_PRODUCT_KEY" ]; then
  PRODUCT_KEY_XML="<ProductKey><Key>${WIN_PRODUCT_KEY}</Key><WillShowUI>Never</WillShowUI></ProductKey>"
  echo "==> Product key: supplied via WIN_PRODUCT_KEY"
else
  PRODUCT_KEY_XML="<ProductKey><WillShowUI>Never</WillShowUI></ProductKey>"
  echo "==> Product key: none — Windows will install and run unactivated (fine for lab use)"
fi

# ---- 2a. Autounattend.xml -------------------------------------------------
# Notes on the Win11-specific bits:
#   - The LabConfig/BypassXxxCheck keys let setup proceed even if the VM's
#     TPM/SecureBoot/RAM presentation isn't what setup expects. We DO give the
#     VM a real vTPM + UEFI below, so these are belt-and-braces — but they cost
#     nothing and they're the difference between a build that works and one that
#     dies on a "This PC can't run Windows 11" dialog with no console attached.
#   - BypassNRO + a local account in oobeSystem is what skips 25H2's "connect to
#     the internet / sign in with a Microsoft account" wall. Without it OOBE
#     blocks forever and the build times out.
#   - DriverPaths lists several candidate drive letters because WinPE assigns
#     them unpredictably when three CDs are attached. Setup ignores paths that
#     don't resolve.
cat > "$STAGING/Autounattend.xml" <<UNATTEND_EOF
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">

  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>

    <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DriverPaths>
        <PathAndCredentials wcm:action="add" wcm:keyValue="1" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>D:\vioscsi\w11\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="2" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>E:\vioscsi\w11\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="3" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>F:\vioscsi\w11\amd64</Path>
        </PathAndCredentials>
        <!-- w10 fallbacks: if a virtio-win release ever ships without a w11
             directory, Setup finds no vioscsi driver, sees no disk, and stops on
             "no drives were found" - a dead end with nobody at the console. The
             w10 drivers load fine on Windows 11. Paths that don't resolve are
             ignored, so listing both costs nothing. -->
        <PathAndCredentials wcm:action="add" wcm:keyValue="4" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>D:\vioscsi\w10\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="5" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>E:\vioscsi\w10\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="6" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>F:\vioscsi\w10\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="7" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>D:\NetKVM\w11\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="8" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>E:\NetKVM\w11\amd64</Path>
        </PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="9" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Path>F:\NetKVM\w11\amd64</Path>
        </PathAndCredentials>
      </DriverPaths>
    </component>

    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Path>reg add HKLM\System\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>2</Order>
          <Path>reg add HKLM\System\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>3</Order>
          <Path>reg add HKLM\System\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>4</Order>
          <Path>reg add HKLM\System\Setup\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>5</Order>
          <Path>reg add HKLM\System\Setup\LabConfig /v BypassStorageCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>6</Order>
          <Path>reg add HKLM\System\Setup\LabConfig /v BypassNRO /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>

      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <!-- UEFI/GPT layout: ESP + MSR + Windows -->
            <CreatePartition wcm:action="add">
              <Order>1</Order><Type>EFI</Type><Size>260</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order><Type>MSR</Type><Size>16</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order><Type>Primary</Type><Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order><PartitionID>1</PartitionID>
              <Label>System</Label><Format>FAT32</Format>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order><PartitionID>2</PartitionID>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>3</Order><PartitionID>3</PartitionID>
              <Label>Windows</Label><Letter>C</Letter><Format>NTFS</Format>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>

      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
              <Key>/IMAGE/NAME</Key>
              <Value>${WIN_EDITION}</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>

      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>CyberCore</FullName>
        <Organization>CyberCore</Organization>
        ${PRODUCT_KEY_XML}
      </UserData>
    </component>
  </settings>

  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>

    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <TimeZone>UTC</TimeZone>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
        <NetworkLocation>Work</NetworkLocation>
      </OOBE>

      <UserAccounts>
        <AdministratorPassword>
          <Value>${ADMIN_PASSWORD}</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>

      <!-- Auto-logon as Administrator exactly twice: once to run the provisioning
           script, and a spare in case a driver install forces a reboot. sysprep
           at the end of provisioning wipes this, so the finished template never
           auto-logs-in. -->
      <AutoLogon>
        <Enabled>true</Enabled>
        <LogonCount>2</LogonCount>
        <Username>Administrator</Username>
        <Password><Value>${ADMIN_PASSWORD}</Value><PlainText>true</PlainText></Password>
      </AutoLogon>

      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Description>CyberCore provisioning</Description>
          <!-- Deliberately a cmd drive-scan and not PowerShell: this heredoc is
               shell-expanded by the baker, so any PowerShell '\$var' here would be
               eaten by bash before it ever reached the XML. A 'for' over candidate
               letters also survives WinPE assigning CD letters unpredictably. -->
          <CommandLine>cmd /c "for %i in (D E F G H I) do @if exist %i:\provision.ps1 powershell.exe -NoProfile -ExecutionPolicy Bypass -File %i:\provision.ps1"</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
UNATTEND_EOF

# The heredoc above is expanded by bash (WIN_EDITION / ADMIN_PASSWORD), so a
# stray non-ASCII byte from an editor would silently corrupt the XML. Strip
# anything outside printable ASCII + CR/LF/TAB before it ships.
if LC_ALL=C grep -qP '[^\x09\x0A\x0D\x20-\x7E]' "$STAGING/Autounattend.xml" 2>/dev/null; then
  echo "==> Stripping non-ASCII bytes from Autounattend.xml"
  LC_ALL=C tr -d '\000-\010\013\014\016-\037\177-\377' < "$STAGING/Autounattend.xml" > "$STAGING/Autounattend.clean" \
    && mv "$STAGING/Autounattend.clean" "$STAGING/Autounattend.xml"
fi

# ---- 2b. provision.ps1 — runs inside the guest at first logon ---------------
# Ends with sysprep /generalize /shutdown, so a clean shutdown IS the success
# signal the host waits for.
cat > "$STAGING/provision.ps1" <<'PS_EOF'
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\cybercore-provision.log'
function Log($m) { $s = "[{0}] {1}" -f (Get-Date -Format o), $m; Add-Content -Path $log -Value $s; Write-Host $s }

Log 'CyberCore Windows 11 workstation provisioning starting'

# Locate our own CD (label CYBERCORE) and the virtio CD, by content rather than
# by drive letter — letters shift depending on how many CDs are attached.
$me = (Get-Volume | Where-Object { $_.FileSystemLabel -eq 'CYBERCORE' } | Select-Object -First 1).DriveLetter
$virtio = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' } |
           Where-Object { $_.DriveLetter -and (Test-Path ("{0}:\virtio-win-guest-tools.exe" -f $_.DriveLetter)) } |
           Select-Object -First 1).DriveLetter
Log "CYBERCORE drive=$me  virtio drive=$virtio"

# ---- virtio guest tools (NetKVM + balloon + qemu-guest-agent in one) --------
# The orchestrator gives Windows lanes an e1000 NIC, so networking does not
# depend on NetKVM — but qemu-guest-agent is what lets the deploy confirm the
# guest actually took its reserved DHCP lease.
if ($virtio) {
  Log 'Installing virtio guest tools (silent)...'
  $p = Start-Process -FilePath ("{0}:\virtio-win-guest-tools.exe" -f $virtio) `
       -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
  Log ("virtio guest tools exit code: {0}" -f $p.ExitCode)
} else {
  Log 'WARNING: virtio ISO not found — qemu-guest-agent will be missing'
}

# ---- cloudbase-init --------------------------------------------------------
# THE critical component: the orchestrator injects per-student credentials as
# cloud-init ciuser/cipassword and this is what applies them. Installed with
# RUN_SERVICE_AS_LOCAL_SYSTEM so it can create local accounts.
if ($me) {
  $msi = "{0}:\CloudbaseInitSetup_x64.msi" -f $me
  Log "Installing cloudbase-init from $msi ..."
  $p = Start-Process -FilePath 'msiexec.exe' `
       -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart', 'RUN_SERVICE_AS_LOCAL_SYSTEM=1' `
       -Wait -PassThru
  Log ("cloudbase-init MSI exit code: {0}" -f $p.ExitCode)
}

# Point cloudbase-init at Proxmox's ConfigDrive. Proxmox serves Windows guests
# configdrive2 (it picks the format from the VM's ostype), so the ConfigDrive
# service is the one that must be enabled. Writing the conf explicitly rather
# than trusting installer defaults, because a wrong metadata service here fails
# silently — the service starts, finds nothing, and no account is ever created.
$cbDir = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf'
if (Test-Path $cbDir) {
  $conf = @"
[DEFAULT]
username=Admin
groups=Administrators
inject_user_password=true
; Do NOT force a password change at first logon. cloudbase-init's default
; (clear_text_injected_only) flags the injected account "must change password at
; next logon" -- which lands the student on a change-password screen that
; Guacamole's auto-login cannot get past, making a correctly-deployed lane look
; like the credentials are wrong. This single line is the difference between the
; RDP console working and not.
first_logon_behaviour=no
config_drive_raw_hhd=true
config_drive_cdrom=true
config_drive_vfat=true
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
verbose=true
debug=true
logdir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init.log
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN,requests=WARN
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
metadata_services=cloudbaseinit.metadata.services.configdrive.ConfigDriveService
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.windows.createuser.CreateUserPlugin,cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
allow_reboot=false
stop_service_on_exit=false
"@
  Set-Content -Path (Join-Path $cbDir 'cloudbase-init.conf') -Value $conf -Encoding ASCII
  Copy-Item (Join-Path $cbDir 'cloudbase-init.conf') (Join-Path $cbDir 'cloudbase-init-unattend.conf') -Force
  Log 'Wrote cloudbase-init.conf (ConfigDrive + CreateUser/SetUserPassword)'
} else {
  Log 'WARNING: cloudbase-init conf dir not found — credential injection WILL NOT work'
}

# ---- RDP: the student's only way in ----------------------------------------
# The lane gateway DNATs wan0:3389 to this machine. RDP off = a lane that
# deploys clean and refuses every connection.
Log 'Enabling RDP + firewall rule...'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
# NLA on is correct and Guacamole negotiates it (the connection is created with
# security=any). Left enabled deliberately — turning it off to "make RDP easier"
# would weaken every student box.
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'CyberCore RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -ErrorAction SilentlyContinue | Out-Null

# Allow ping — makes lane troubleshooting far less painful.
Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction SilentlyContinue

# ---- Lab-friendly tweaks ---------------------------------------------------
Log 'Applying lab tweaks (power, hibernate, first-run prompts)...'
powercfg /setactive SCHEME_MIN 2>$null
powercfg /change monitor-timeout-ac 0 2>$null
powercfg /change standby-timeout-ac 0 2>$null
powercfg /hibernate off 2>$null   # reclaims ~RAM-sized disk in every clone

# Skip the Edge/OOBE first-run nags students would otherwise click through.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'HideFirstRunExperience' -Value 1
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'DisableSearchBoxSuggestions' -Value 1

# ---- Windows Update: leave OFF during bake ---------------------------------
# A background update run during sysprep is a classic way to produce a template
# that fails to generalize. Students' clones can update at runtime if wanted.
Log 'Disabling Windows Update service for the bake...'
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

# ---- sysprep /generalize ---------------------------------------------------
# Fresh machine SID per clone. cloudbase-init ships an Unattend.xml that
# re-arms its own service on the generalized image — use it if present so the
# service actually runs on first boot of every clone.
$cbUnattend = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml'
$sysprepArgs = '/generalize','/oobe','/shutdown','/mode:vm'
if (Test-Path $cbUnattend) {
  Log "Using cloudbase-init Unattend.xml for sysprep"
  $sysprepArgs = '/generalize','/oobe','/shutdown','/mode:vm',"/unattend:$cbUnattend"
}
Log ("Running sysprep: {0}" -f ($sysprepArgs -join ' '))
Copy-Item $log 'C:\Windows\Temp\cybercore-provision-presysprep.log' -Force -ErrorAction SilentlyContinue
Start-Process -FilePath 'C:\Windows\System32\Sysprep\sysprep.exe' -ArgumentList $sysprepArgs -Wait
PS_EOF

# Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so a UTF-8 em-dash in a
# comment decodes as mojibake. Harmless where they currently sit, but strip to
# pure ASCII so a future edit can't drop a non-ASCII byte somewhere that matters
# (the cloudbase-init.conf here-string, for instance).
LC_ALL=C tr -d '\000-\010\013\014\016-\037\177-\377' \
  < "$STAGING/provision.ps1" > "$STAGING/provision.ascii.ps1" \
  && mv "$STAGING/provision.ascii.ps1" "$STAGING/provision.ps1"

echo "==> Building CYBERCORE answer/scripts ISO..."
UNATTEND_ISO_FILE="cybercore-win11-unattend.iso"
"$MKISO" -quiet -J -r -V CYBERCORE -o "$STAGING/$UNATTEND_ISO_FILE" \
  "$STAGING/Autounattend.xml" "$STAGING/provision.ps1" "$STAGING/CloudbaseInitSetup_x64.msi"

# Copy it into ISO_STORAGE so `qm` can reference it as a volid. ISO_DIR was
# resolved alongside WIN_ISO_PATH above.
cp -f "$STAGING/$UNATTEND_ISO_FILE" "$ISO_DIR/$UNATTEND_ISO_FILE"
UNATTEND_ISO="${ISO_STORAGE}:iso/${UNATTEND_ISO_FILE}"
echo "==> Answer ISO: $UNATTEND_ISO"

# ---------- 3. Create the build VM ----------
# Win11 wants UEFI + Secure Boot + TPM 2.0. Proxmox provides all three; giving
# the VM real ones (rather than relying only on the LabConfig bypasses) keeps
# the image closer to what Windows expects and avoids upgrade-time surprises.
echo "==> Creating build VM $BUILD_VMID..."
NET_OPTS="e1000,bridge=${PROXMOX_BRIDGE}"
# if/fi, not `[ test ] && assign`: with PROXMOX_BUILD_VLAN="" (a documented,
# valid setting) that one-liner returns 1 and `set -e` would abort the build here.
if [ -n "$PROXMOX_BUILD_VLAN" ]; then
  NET_OPTS="${NET_OPTS},tag=${PROXMOX_BUILD_VLAN}"
fi

if [ "$SECURE_BOOT" = "1" ]; then
  EFIDISK_OPTS="${PROXMOX_STORAGE}:1,efitype=4m,pre-enrolled-keys=1"
  echo "==> Secure Boot: ENABLED (if the ISO's loader isn't signed with a trusted"
  echo "    cert, OVMF will skip the DVD silently and fall through to PXE)"
else
  EFIDISK_OPTS="${PROXMOX_STORAGE}:1,efitype=4m,pre-enrolled-keys=0"
  echo "==> Secure Boot: disabled (UEFI + vTPM 2.0 still present)"
fi

qm create "$BUILD_VMID" \
  --name "win11-bake" \
  --machine q35 \
  --bios ovmf \
  --efidisk0 "$EFIDISK_OPTS" \
  --tpmstate0 "${PROXMOX_STORAGE}:1,version=v2.0" \
  --cpu host \
  --cores "$BUILD_CORES" \
  --sockets 1 \
  --memory "$BUILD_MEM" \
  --ostype win11 \
  --scsihw virtio-scsi-single \
  --net0 "$NET_OPTS" \
  --agent enabled=1 \
  --description "Scratch VM for bake-win-client-template.sh — safe to destroy"

# OS disk. virtio-scsi is the fast path and needs the vioscsi driver injected in
# WinPE (handled by DriverPaths above). OS_DISK_BUS=sata is the escape hatch if
# that injection ever fails on a new ISO: no driver needed, slightly slower.
if [ "$OS_DISK_BUS" = "sata" ]; then
  echo "==> OS disk on SATA (driver-free install path)"
  qm set "$BUILD_VMID" --sata1 "${PROXMOX_STORAGE}:${DISK_GB},cache=writeback"
  BOOT_DISK="sata1"
else
  qm set "$BUILD_VMID" --scsi0 "${PROXMOX_STORAGE}:${DISK_GB},cache=writeback,discard=on,ssd=1"
  BOOT_DISK="scsi0"
fi

# Three CD-ROMs: Windows installer, our answer/scripts ISO, virtio drivers.
# BOOT_ISO is the no-prompt repack when one was built, else the original.
qm set "$BUILD_VMID" \
  --ide0 "${BOOT_ISO},media=cdrom" \
  --ide2 "${UNATTEND_ISO},media=cdrom" \
  --sata0 "${VIRTIO_ISO},media=cdrom" \
  --boot "order=ide0;${BOOT_DISK}"

echo "==> Starting build VM (unattended Windows install begins now)..."
qm start "$BUILD_VMID"

# Dismiss "Press any key to boot from CD or DVD...".
#
# Microsoft's retail ISOs ship the PROMPTING cdboot loader. In an unattended
# build nothing presses a key, the prompt times out, UEFI falls through to the
# (empty) disk, and OVMF drops to its boot-device menu — where the VM then sits
# until the script's timeout expires. This is THE classic automated-Windows
# install trap, and it WILL happen without this block.
#
# 1s interval, not 3s: the prompt is only up for about five seconds, so a coarse
# interval can miss the window entirely (observed in practice). At 1s we get
# ~90 attempts against a ~5s target.
#
# Enter is also the right key if OVMF's boot menu is already showing — it
# selects the highlighted entry, which is the DVD-ROM. So the same loop recovers
# from both states.
#
# Why this is safe: Windows Setup ignores stray Enters (the answer file drives
# every dialog), and the window closes long before Setup's first reboot several
# minutes in. Pressing a key at THAT reboot would restart the install from
# scratch in a loop — which is exactly why this stops at 90s and is not simply
# left running for the whole build.
(
  sleep 3   # let the VM POST before the first keystroke
  for _ in $(seq 1 90); do
    qm sendkey "$BUILD_VMID" ret >/dev/null 2>&1 || true
    sleep 1
  done
) &
SENDKEY_PID=$!
echo "==> Sending Enter for the first ~90s to clear the 'Press any key to boot' prompt..."

# ---------- 4. Wait for provisioning to finish ----------
# provision.ps1 ends with `sysprep /shutdown`, so the VM powering itself off IS
# the completion signal. Anything else that stops it is a failure we surface.
echo "==> Waiting for install + provisioning + sysprep (up to ${INSTALL_TIMEOUT_MIN} min)."
echo "    Watch the console:  qm terminal $BUILD_VMID   (or the Proxmox web console)"
STARTED_AT=$(date +%s)
DEADLINE=$(( STARTED_AT + INSTALL_TIMEOUT_MIN * 60 ))
AGENT_SEEN=0
TICK=0
while true; do
  NOW=$(date +%s)
  if [ "$NOW" -gt "$DEADLINE" ]; then
    echo "ERROR: build timed out after ${INSTALL_TIMEOUT_MIN} min." >&2
    echo "       The scratch VM $BUILD_VMID has been left running for inspection." >&2
    echo "       Look at its console first (Proxmox UI -> $BUILD_VMID -> Console):" >&2
    echo "         - stuck at 'Press any key to boot from CD'  -> qm sendkey $BUILD_VMID ret" >&2
    echo "         - OVMF 'Please select boot device' menu     -> qm sendkey $BUILD_VMID ret" >&2
    echo "           (the Windows ISO is ide0 = 'UEFI QEMU DVD-ROM QM00001', the" >&2
    echo "            first entry, which OVMF highlights by default — so a plain" >&2
    echo "            Enter picks it. The other two DVD-ROMs are the answer ISO" >&2
    echo "            and virtio, neither of which is bootable.)" >&2
    echo "         - an edition picker or any dialog           -> answer file not applied" >&2
    echo "       Then clean up:  qm destroy $BUILD_VMID --purge" >&2
    exit 1
  fi

  STATUS=$(qm status "$BUILD_VMID" 2>/dev/null | awk '{print $2}')
  if [ "$STATUS" = "stopped" ]; then
    echo "==> Build VM powered off — sysprep completed."
    break
  fi

  # The guest agent only answers once Windows is installed AND our provisioning
  # script has installed the virtio tools — so it's a genuine milestone, not
  # just "the VM is on".
  if [ "$AGENT_SEEN" = "0" ] && qm guest cmd "$BUILD_VMID" ping >/dev/null 2>&1; then
    AGENT_SEEN=1
    echo "    [$(date +%H:%M:%S)] guest agent responding — Windows is up, provisioning running"
  fi

  # Heartbeat every ~2 min. Without this the script prints nothing for 20-40
  # minutes and looks hung, which is indistinguishable from actually being hung.
  TICK=$((TICK + 1))
  if [ $((TICK % 6)) = 1 ]; then
    ELAPSED_MIN=$(( (NOW - STARTED_AT) / 60 ))
    if [ "$AGENT_SEEN" = "1" ]; then
      PHASE="provisioning (virtio + cloudbase-init + sysprep)"
    else
      PHASE="windows setup"
    fi
    echo "    [$(date +%H:%M:%S)] ${ELAPSED_MIN}m elapsed — ${PHASE}; VM is ${STATUS}" \
         "(console: Proxmox UI -> $BUILD_VMID -> Console)"
  fi
  sleep 20
done

wait "$SENDKEY_PID" 2>/dev/null || true

# ---------- 5. Convert to the final template ----------
# Detach every CD and add the cloud-init drive the orchestrator writes
# ciuser/cipassword into. ide2 is Proxmox's conventional cloud-init slot and is
# now free (the answer ISO is gone).
echo "==> Stripping install media, attaching cloud-init drive..."
qm set "$BUILD_VMID" --delete ide0 >/dev/null
qm set "$BUILD_VMID" --delete sata0 >/dev/null
qm set "$BUILD_VMID" --delete ide2 >/dev/null
qm set "$BUILD_VMID" --ide2 "${PROXMOX_STORAGE}:cloudinit"
qm set "$BUILD_VMID" --boot "order=${BOOT_DISK}"

# ostype win11 is what makes Proxmox serve configdrive2 rather than nocloud.
# lane-deployer.js deliberately does NOT pass citype, so this value is the only
# thing deciding the format cloudbase-init sees. Do not change it to l26.
qm set "$BUILD_VMID" --ostype win11

if [ "$FORCE" = "1" ] && qm status "$FINAL_VMID" >/dev/null 2>&1; then
  echo "==> FORCE=1: destroying existing $FINAL_VMID..."
  qm stop "$FINAL_VMID" >/dev/null 2>&1 || true
  sleep 3
  qm destroy "$FINAL_VMID" --purge
fi

echo "==> Cloning $BUILD_VMID -> $FINAL_VMID (full clone)..."
qm clone "$BUILD_VMID" "$FINAL_VMID" --full --name "$TEMPLATE_NAME" --storage "$PROXMOX_STORAGE"
qm set "$FINAL_VMID" --description "Windows 11 ${WIN_EDITION} workstation template.
sysprep-generalized (fresh SID per clone), cloudbase-init + virtio guest tools,
RDP enabled. Built by front-end/scripts/bake-win-client-template.sh.

Register in CyberCore: Admin -> Workstation Templates
  template_type   workstation
  template_vmid   ${FINAL_VMID}
  os_family       windows_client
  then press Verify to populate node + provider_type."
qm template "$FINAL_VMID"

if [ "$KEEP_BUILD_VM" = "1" ]; then
  echo "==> KEEP_BUILD_VM=1: leaving scratch VM $BUILD_VMID in place."
else
  echo "==> Destroying scratch VM $BUILD_VMID..."
  qm destroy "$BUILD_VMID" --purge
fi

rm -f "$ISO_DIR/$UNATTEND_ISO_FILE"

# ---------- 6. Summary ----------
echo ""
echo "=========================================================================="
echo "  Windows 11 workstation template baked at VMID $FINAL_VMID"
echo "=========================================================================="
echo "  Name          : $TEMPLATE_NAME"
echo "  Edition       : $WIN_EDITION"
echo "  Bake-time admin password: $ADMIN_PASSWORD"
echo "    (sysprep cleared the auto-logon; per-student accounts come from"
echo "     cloud-init at deploy time, so this is only a break-glass local login)"
if [ -z "$WIN_PRODUCT_KEY" ]; then
echo ""
echo "  Activation: NOT activated (no key supplied). Expect a desktop watermark"
echo "  and locked Personalization settings. Nothing that affects lab use."
echo "  To activate later — no rebake needed, works on the template or a clone:"
echo "    slmgr /ipk <key>  &&  slmgr /ato"
fi
echo ""
echo "  Smoke-test the credential path BEFORE using it for a class:"
echo "    qm clone $FINAL_VMID 9903 --name win11test --full --storage $PROXMOX_STORAGE"
echo "    qm set 9903 --net0 e1000,bridge=$PROXMOX_BRIDGE${PROXMOX_BUILD_VLAN:+,tag=$PROXMOX_BUILD_VLAN} \\"
echo "                --ciuser teststudent --cipassword 'Test!Pass123' --ipconfig0 ip=dhcp"
echo "    qm start 9903"
echo "    # give it 3-5 min (specialize + OOBE + cloudbase-init), then:"
echo "    qm guest cmd 9903 network-get-interfaces"
echo "    # RDP in as teststudent/Test!Pass123 to confirm the account was created"
echo "    qm stop 9903 && qm destroy 9903 --purge"
echo ""
echo "  If the account was NOT created, check inside the clone:"
echo "    C:\\Program Files\\Cloudbase Solutions\\Cloudbase-Init\\log\\cloudbase-init.log"
echo "    and confirm  qm config $FINAL_VMID | grep ostype  says win11"
echo ""
echo "  Then register it in CyberCore:"
echo "    Admin -> Workstation Templates -> Add"
echo "      name          Windows 11 Workstation"
echo "      template_key  win11-workstation"
echo "      template_vmid $FINAL_VMID"
echo "      os_family     windows_client"
echo "      status        active"
echo "    -> press Verify (populates node + provider_type)"
echo "  It then appears in the CLE course workstation picker."
echo "=========================================================================="
