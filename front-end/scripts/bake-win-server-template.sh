#!/bin/bash
# ============================================================================
# bake-win-server-template.sh
# ----------------------------------------------------------------------------
# Builds a properly sysprep-generalized Windows Server 2019 template for GOAD,
# using upstream GOAD's packer config from the Orange-Cyberdefense/GOAD repo.
# The result is a Proxmox VM template named WinServer2019x64-cloudinit that
# we then renumber to VMID 1004 for our orchestrator.
#
# Why this exists: A non-sysprepped Win VM template causes every clone to
# share the same machine SID. AD rejects duplicate SIDs (error 1356), which
# silently breaks dcpromo on the second-and-later DCs. Symptoms: NTDS service
# stays Disabled even though Install-ADDSDomain "succeeds". This is the
# canonical fix — generalize the template so each clone gets a fresh SID.
#
# Workflow follows: https://mayfly277.github.io/posts/GOAD-on-proxmox-part2-packer/
#
# Run from any Proxmox node with internet access. Takes ~45-90 min end-to-end:
#   - 5-10 min: tool install + ISO downloads (cached, so re-runs are fast)
#   - 30-60 min: packer build (Win Server 2019 install + sysprep + cloudbase-init)
#
# Usage:
#   bash bake-win-server-template.sh
#
# Env vars (override defaults):
#   PROXMOX_NODE       — current node name (default: $(hostname))
#   PROXMOX_STORAGE    — where templates land (default: vmpool)
#   PROXMOX_BRIDGE     — network bridge for build-time access (default: vmbr0)
#   PROXMOX_BUILD_VLAN — VLAN tag for build-time internet (default: empty = none)
#   GOAD_DIR           — local clone of GOAD repo (default: /root/GOAD)
#   FINAL_VMID         — VMID to renumber the final template to (default: 1004)
#   PACKER_USER_PW     — password for the dedicated packer Proxmox user
#   ISO_STORAGE        — Proxmox storage holding ISOs (default: auto-detect cephfs > local)
#   WIN_ISO_NAME       — exact filename of Win Server ISO inside ISO_STORAGE
#                        (default: auto-detect any *2019*.iso or *2022*.iso)
#   VIRTIO_ISO_NAME    — exact filename of virtio-win ISO inside ISO_STORAGE
#                        (default: auto-detect *virtio-win*.iso)
# ============================================================================
set -euo pipefail

PROXMOX_NODE="${PROXMOX_NODE:-$(hostname)}"
PROXMOX_STORAGE="${PROXMOX_STORAGE:-vmpool}"
PROXMOX_BRIDGE="${PROXMOX_BRIDGE:-vmbr0}"
PROXMOX_BUILD_VLAN="${PROXMOX_BUILD_VLAN:-10}"
# Static IP + subnet the build VM will assign itself during first-logon. MUST
# be reachable from the Proxmox host (host needs an IP on the same subnet/VLAN
# so it can talk to the build VM via the bridge). With PROXMOX_BUILD_VLAN=10
# and host's vmbr0.10 = 100.100.10.15/24, BUILD_STATIC_IP=100.100.10.250 works.
# Override via env if your network differs.
BUILD_STATIC_IP="${BUILD_STATIC_IP:-100.100.10.250}"
BUILD_STATIC_PREFIX="${BUILD_STATIC_PREFIX:-24}"
GOAD_DIR="${GOAD_DIR:-/root/GOAD}"
GOAD_REPO="${GOAD_REPO:-https://github.com/Orange-Cyberdefense/GOAD.git}"
GOAD_REF="${GOAD_REF:-main}"
FINAL_VMID="${FINAL_VMID:-1004}"
ISO_STORAGE="${ISO_STORAGE:-}"
WIN_ISO_NAME="${WIN_ISO_NAME:-}"
VIRTIO_ISO_NAME="${VIRTIO_ISO_NAME:-}"
PACKER_USER="infra_as_code@pve"
PACKER_USER_PW="${PACKER_USER_PW:-$(openssl rand -base64 18)}"
WIN2019_ISO_URL="https://software-download.microsoft.com/download/pr/17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso"
WIN2019_FALLBACK_NAME="windows_server_2019_17763.737_eval_x64.iso"
VIRTIO_ISO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
VIRTIO_FALLBACK_NAME="virtio-win.iso"
CLOUDBASE_URL="https://cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi"

PACKER_VERSION="${PACKER_VERSION:-1.11.2}"

echo "=========================================================================="
echo " Win Server 2019 GOAD template baker"
echo "=========================================================================="
echo " Node          : $PROXMOX_NODE"
echo " VM storage    : $PROXMOX_STORAGE   (final template lands here)"
echo " ISO storage   : ${ISO_STORAGE:-auto-detect}   (where ISOs live + autounattend ISOs go)"
echo " Bridge / VLAN : $PROXMOX_BRIDGE${PROXMOX_BUILD_VLAN:+ / vlan $PROXMOX_BUILD_VLAN}"
echo " Build IP      : $BUILD_STATIC_IP/$BUILD_STATIC_PREFIX  (assigned at first logon, must be reachable from host)"
echo " GOAD dir      : $GOAD_DIR"
echo " Final VMID    : $FINAL_VMID"
echo " Packer user   : $PACKER_USER"
echo "=========================================================================="

# ---------- 0. Sanity ----------
if qm status "$FINAL_VMID" >/dev/null 2>&1; then
  echo "ERROR: VMID $FINAL_VMID already exists."
  echo "       Destroy it first if you really want to replace it:"
  echo "         qm destroy $FINAL_VMID --purge"
  exit 1
fi

# ---------- 1. Install packer + helpers ----------
need_install=()
command -v packer  >/dev/null 2>&1 || need_install+=("packer")
command -v mkisofs >/dev/null 2>&1 || command -v genisoimage >/dev/null 2>&1 || need_install+=("genisoimage")
command -v wget    >/dev/null 2>&1 || need_install+=("wget")
command -v git     >/dev/null 2>&1 || need_install+=("git")

if [ ${#need_install[@]} -gt 0 ]; then
  echo "==> Installing missing tools: ${need_install[*]}"
  apt-get update -qq
  for tool in "${need_install[@]}"; do
    case "$tool" in
      packer)
        # packer isn't in Debian repos — pull official binary
        echo "==> Installing packer $PACKER_VERSION..."
        cd /tmp
        wget -q "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip"
        apt-get install -qq -y unzip >/dev/null
        unzip -o "packer_${PACKER_VERSION}_linux_amd64.zip" >/dev/null
        mv -f packer /usr/local/bin/packer
        chmod +x /usr/local/bin/packer
        rm -f "packer_${PACKER_VERSION}_linux_amd64.zip"
        ;;
      *)
        apt-get install -qq -y "$tool" >/dev/null
        ;;
    esac
  done
fi
echo "==> packer: $(packer version)"

# ---------- 2. Clone / refresh GOAD repo ----------
if [ ! -d "$GOAD_DIR/.git" ]; then
  echo "==> Cloning GOAD into $GOAD_DIR..."
  git clone --depth 1 --branch "$GOAD_REF" "$GOAD_REPO" "$GOAD_DIR"
else
  echo "==> GOAD already cloned at $GOAD_DIR (skipping)"
fi
GOAD_PACKER_DIR="$GOAD_DIR/packer/proxmox"
[ -d "$GOAD_PACKER_DIR" ] || { echo "ERROR: $GOAD_PACKER_DIR not found in repo"; exit 1; }

# ---------- 3. Discover (or download) ISOs across Proxmox storages ----------
# Prefer ISOs already uploaded to Proxmox storage (cephfs is common for clusters
# since all nodes can read it). Auto-detects by filename pattern. If nothing
# matches, falls back to downloading into 'local' storage.

# pick_iso_storage: returns the first storage advertising 'iso' content,
# preferring user override > cephfs > any > local
pick_iso_storage() {
  if [ -n "$ISO_STORAGE" ]; then
    echo "$ISO_STORAGE"; return 0
  fi
  local first cephfs other
  cephfs=$(pvesm status -content iso 2>/dev/null | awk 'NR>1 && $1=="cephfs" {print $1}' | head -1)
  if [ -n "$cephfs" ]; then echo "$cephfs"; return 0; fi
  first=$(pvesm status -content iso 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then echo "$first"; return 0; fi
  echo "local"
}

# find_iso_in_storage <storage> <pattern>: print the first volid matching
find_iso_in_storage() {
  local storage="$1" pattern="$2"
  pvesm list "$storage" 2>/dev/null | awk -v p="$pattern" 'tolower($1) ~ tolower(p) {print $1; exit}'
}

# resolve_iso <var_name> <pattern> <fallback_url> <fallback_filename>
# Sets the named variable to "<storage>:iso/<filename>" (the volid form packer
# wants), downloading to ISO_STORAGE if no match found.
resolve_iso() {
  local var_name="$1" pattern="$2" fallback_url="$3" fallback_filename="$4"
  local override_name="${5:-}"
  local volid

  if [ -n "$override_name" ]; then
    volid="${ISO_STORAGE}:iso/${override_name}"
    if pvesm list "$ISO_STORAGE" 2>/dev/null | awk '{print $1}' | grep -qx "$volid"; then
      echo "==> $var_name (override): $volid"
      eval "$var_name=\"$volid\""
      return 0
    fi
    echo "WARNING: $var_name override '$override_name' not found in $ISO_STORAGE"
  fi

  # Try every storage with iso content for a pattern match (let user keep ISOs anywhere)
  local s match
  for s in $(pvesm status -content iso 2>/dev/null | awk 'NR>1 {print $1}'); do
    match=$(find_iso_in_storage "$s" "$pattern")
    if [ -n "$match" ]; then
      echo "==> $var_name (auto-detected): $match"
      eval "$var_name=\"$match\""
      return 0
    fi
  done

  # No match anywhere — fall back to downloading into ISO_STORAGE
  local target_dir
  case "$ISO_STORAGE" in
    local)   target_dir="/var/lib/vz/template/iso" ;;
    cephfs)  target_dir="/mnt/pve/cephfs/template/iso" ;;
    *)
      target_dir=$(pvesm path "${ISO_STORAGE}:iso/${fallback_filename}" 2>/dev/null | xargs dirname || true)
      [ -z "$target_dir" ] && target_dir="/var/lib/vz/template/iso"
      ;;
  esac
  mkdir -p "$target_dir"
  local target_file="${target_dir}/${fallback_filename}"
  echo "==> $var_name not found in any iso storage. Downloading to $target_file..."
  wget --progress=dot:giga -O "${target_file}.tmp" "$fallback_url"
  mv "${target_file}.tmp" "$target_file"
  volid="${ISO_STORAGE}:iso/${fallback_filename}"
  echo "==> $var_name (downloaded): $volid"
  eval "$var_name=\"$volid\""
}

ISO_STORAGE=$(pick_iso_storage)
echo "==> ISO storage: $ISO_STORAGE"

resolve_iso WIN_ISO_VOLID    '2019.*server.*\.iso|server.*2019.*\.iso|2019_SERVER_EVAL.*\.iso' \
            "$WIN2019_ISO_URL" "$WIN2019_FALLBACK_NAME" "$WIN_ISO_NAME"
resolve_iso VIRTIO_ISO_VOLID 'virtio-win.*\.iso' \
            "$VIRTIO_ISO_URL" "$VIRTIO_FALLBACK_NAME" "$VIRTIO_ISO_NAME"

# cloudbase-init MSI lives inside the GOAD repo (not Proxmox storage), so we
# still download it directly there. Small file (~25 MB).
CLOUDBASE_MSI="$GOAD_PACKER_DIR/scripts/sysprep/CloudbaseInitSetup_Stable_x64.msi"
if [ ! -f "$CLOUDBASE_MSI" ]; then
  echo "==> Downloading cloudbase-init MSI..."
  wget --progress=dot:giga -O "${CLOUDBASE_MSI}.tmp" "$CLOUDBASE_URL"
  mv "${CLOUDBASE_MSI}.tmp" "$CLOUDBASE_MSI"
fi
echo "==> cloudbase-init MSI: $CLOUDBASE_MSI"

# ---------- 4. Create dedicated Proxmox user + role for packer ----------
# Always (re)set the password so it stays in sync with config.auto.pkrvars.hcl,
# which we regenerate every run with a fresh random PACKER_USER_PW. Skipping
# the password set on re-runs causes a 401 from packer because the config has
# this run's random password but Proxmox still has the previous run's.
if pveum user list 2>/dev/null | awk '{print $2}' | grep -qx "$PACKER_USER"; then
  echo "==> Packer user $PACKER_USER already exists (resetting password to match new config)"
else
  echo "==> Creating Proxmox user $PACKER_USER..."
  pveum useradd "$PACKER_USER" --comment "GOAD packer build user (auto-created)"
fi
echo -e "$PACKER_USER_PW\n$PACKER_USER_PW" | pveum passwd "$PACKER_USER" 2>&1 | grep -v -i "password" || true

if pveum role list 2>/dev/null | awk '{print $2}' | grep -qx "Packer"; then
  echo "==> Packer role exists (refreshing privileges to current set)"
  pveum rolemod Packer -privs "VM.Config.Disk VM.Config.CPU VM.Config.Memory Datastore.AllocateTemplate Datastore.Audit Datastore.AllocateSpace Sys.Modify VM.Config.Options VM.Allocate VM.Audit VM.Console VM.Config.CDROM VM.Config.Cloudinit VM.Config.Network VM.PowerMgmt VM.Config.HWType SDN.Use"
else
  echo "==> Creating Packer role..."
  pveum roleadd Packer -privs "VM.Config.Disk VM.Config.CPU VM.Config.Memory Datastore.AllocateTemplate Datastore.Audit Datastore.AllocateSpace Sys.Modify VM.Config.Options VM.Allocate VM.Audit VM.Console VM.Config.CDROM VM.Config.Cloudinit VM.Config.Network VM.PowerMgmt VM.Config.HWType SDN.Use"
fi

echo "==> Granting Packer role to $PACKER_USER on /..."
pveum acl modify / -user "$PACKER_USER" -role Packer

# ---------- 5. Generate config.auto.pkrvars.hcl ----------
# Upstream (current main) uses TWO storage vars in variables.pkr.hcl:
#   proxmox_vm_storage  — where the VM disk lands (we use $PROXMOX_STORAGE)
#   proxmox_iso_storage — where cloud-init ISOs land (we use $ISO_STORAGE)
PKVARS_AUTO="$GOAD_PACKER_DIR/config.auto.pkrvars.hcl"
echo "==> Writing $PKVARS_AUTO..."
cat > "$PKVARS_AUTO" << HCL
proxmox_url             = "https://127.0.0.1:8006/api2/json"
proxmox_username        = "$PACKER_USER"
proxmox_password        = "$PACKER_USER_PW"
proxmox_skip_tls_verify = "true"
proxmox_node            = "$PROXMOX_NODE"
proxmox_pool            = ""
proxmox_vm_storage      = "$PROXMOX_STORAGE"
proxmox_iso_storage     = "$ISO_STORAGE"
HCL
chmod 600 "$PKVARS_AUTO"

# ---------- 5b. Inject static-IP + qga script into GOAD's scripts/ ----------
# Why: the build VM lands on a network with no DHCP, and Win Server 2019 ships
# without qemu-guest-agent. Without one of those, packer's proxmox plugin
# can't discover the VM's IP and 'Waiting for WinRM...' hangs forever.
# Upstream's Autounattend.xml has a broken qga install step (it tries to run
# the .msi as a powershell command, which doesn't actually install).
#
# This script runs at first logon (added as a SynchronousCommand below). It:
#   1. Sets a static IP that's reachable from the Proxmox host
#   2. Properly installs qemu-guest-agent via msiexec from the virtio CD
# After this runs, packer's plugin sees a usable IP via qga AND can connect
# directly to BUILD_STATIC_IP (we also set winrm_host below).
echo "==> Writing cybercore build-network script into GOAD scripts/..."
mkdir -p "$GOAD_PACKER_DIR/scripts"
cat > "$GOAD_PACKER_DIR/scripts/cybercore-build-network.ps1" <<PS1
\$ErrorActionPreference = "Continue"
\$BuildIP = "$BUILD_STATIC_IP"
\$BuildPrefix = "$BUILD_STATIC_PREFIX"
\$logFile = "C:\\cybercore-build.log"
"\$(Get-Date) cybercore-build-network.ps1 starting" | Out-File \$logFile -Append

# Wait for the network adapter to come Up (DHCP timeout takes a bit on first boot)
\$adapter = \$null
for (\$i = 0; \$i -lt 30; \$i++) {
    \$adapter = Get-NetAdapter | Where-Object { \$_.Status -eq 'Up' } | Select-Object -First 1
    if (\$adapter) { break }
    Start-Sleep 2
}
if (-not \$adapter) {
    "\$(Get-Date) ERROR: no Up adapter after 60s; aborting" | Out-File \$logFile -Append
    exit 1
}
"\$(Get-Date) Found adapter: \$(\$adapter.Name)" | Out-File \$logFile -Append

# Wipe APIPA / any existing IP, set static
Remove-NetIPAddress -InterfaceAlias \$adapter.Name -AddressFamily IPv4 -Confirm:\$false -ErrorAction SilentlyContinue
Remove-NetRoute    -InterfaceAlias \$adapter.Name -AddressFamily IPv4 -Confirm:\$false -ErrorAction SilentlyContinue
try {
    New-NetIPAddress -InterfaceAlias \$adapter.Name -IPAddress \$BuildIP -PrefixLength \$BuildPrefix -ErrorAction Stop | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias \$adapter.Name -ServerAddresses 8.8.8.8
    "\$(Get-Date) Set static IP \$BuildIP/\$BuildPrefix" | Out-File \$logFile -Append
} catch {
    "\$(Get-Date) ERROR setting static IP: \$(\$_.Exception.Message)" | Out-File \$logFile -Append
}

# Install qemu-guest-agent properly (upstream's Autounattend Order=16 is broken)
\$cdDrives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=5"
\$installed = \$false
foreach (\$cd in \$cdDrives) {
    \$msi = "\$(\$cd.DeviceID)\\guest-agent\\qemu-ga-x86_64.msi"
    if (Test-Path \$msi) {
        "\$(Get-Date) Installing qga from \$msi" | Out-File \$logFile -Append
        Start-Process msiexec.exe -ArgumentList "/i","\`"\$msi\`"","/quiet","/norestart" -Wait
        \$installed = \$true
        break
    }
}
if (-not \$installed) {
    "\$(Get-Date) WARNING: qga MSI not found on any CD drive" | Out-File \$logFile -Append
}
Start-Service "QEMU Guest Agent" -ErrorAction SilentlyContinue
\$svc = Get-Service "QEMU Guest Agent" -ErrorAction SilentlyContinue
"\$(Get-Date) qga service status: \$(if (\$svc) { \$svc.Status } else { 'not installed' })" | Out-File \$logFile -Append
PS1
echo "    Wrote $GOAD_PACKER_DIR/scripts/cybercore-build-network.ps1"

# ---------- 5c. Inject SynchronousCommand into Autounattend.xml ----------
# Use python for safe XML-aware string replacement (idempotent — no-op if our
# block is already in the file).
AUTOUNATTEND_XML="$GOAD_PACKER_DIR/answer_files/2019_proxmox_cloudinit/Autounattend.xml"
[ -f "$AUTOUNATTEND_XML" ] || { echo "ERROR: $AUTOUNATTEND_XML not found"; exit 1; }
echo "==> Injecting cybercore SynchronousCommand into Autounattend.xml..."
python3 - <<PY
import re, sys
path = "$AUTOUNATTEND_XML"
content = open(path).read()

# Remove any previous cybercore block so re-runs replace it cleanly. Earlier
# versions of this script wrote Order=0 (invalid; bombs OOBE parsing). A simple
# "skip if marker exists" check would leave that broken block in place forever.
old = re.compile(
    r'\s*<SynchronousCommand[^>]*>'
    r'(?:(?!</SynchronousCommand>).)*?'
    r'cybercore-build-network\.ps1'
    r'(?:(?!</SynchronousCommand>).)*?'
    r'</SynchronousCommand>',
    re.DOTALL,
)
content_new = old.sub('', content)
if content_new != content:
    print(f"    Removed previous cybercore block from {path}", file=sys.stderr)
    content = content_new

# Order must be >= 1 (Microsoft requires positive integers; Order=0 makes
# Windows reject the entire answer file with "could not parse" at oobeSystem
# pass). Pick 50 — into the gap between upstream's used ranges (1-16 and
# 97-99), so we run after fixnetwork/disable-winrm but before the final
# Install-WMF/ConfigureRemoting/enable-winrm chain. That ordering means our
# static IP is set before WinRM's listener comes up, exactly what we need.
inject = '''            <SynchronousCommand wcm:action="add">
                <Order>50</Order>
                <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -File G:\\\\cybercore-build-network.ps1</CommandLine>
                <Description>CyberCore: set static IP and install qga so packer can find this VM</Description>
            </SynchronousCommand>
'''
needle = "</FirstLogonCommands>"
if needle not in content:
    print(f"ERROR: {needle} not in {path}", file=sys.stderr)
    sys.exit(1)
content = content.replace(needle, inject + "            " + needle, 1)
open(path, "w").write(content)
print(f"    Injected into {path}", file=sys.stderr)
PY

# ---------- 5c2. Patch cloudbase-init.ps1 to use msiexec directly ----------
# Upstream's cloudbase-init.ps1 invokes the .msi via Start-Process with the
# msi as FilePath, relying on Windows' file-association to call msiexec.
# In non-interactive packer contexts that's unreliable — the MSI install
# silently fails (no error, but cloudbase-init isn't installed). The next
# script (p2) then dies because the cloudbase-init service doesn't exist.
# Fix: invoke msiexec.exe directly with proper args, and verify exit code.
P1_PATH="$GOAD_PACKER_DIR/scripts/sysprep/cloudbase-init.ps1"
if [ -f "$P1_PATH" ] && ! grep -q 'msiexec.exe' "$P1_PATH"; then
  echo "==> Patching $P1_PATH to install MSI via msiexec.exe directly..."
  cat > "$P1_PATH" <<'PS1A'
# Patched by bake-win-server-template.sh — install Cloudbase-Init reliably.
# Uses msiexec.exe directly (upstream's "Start-Process -FilePath foo.msi"
# pattern silently fails in non-interactive contexts).
mkdir "c:\setup" -Force | Out-Null
Write-Host "Copy CloudbaseInitSetup_Stable_x64.msi"
copy-item "G:\sysprep\CloudbaseInitSetup_Stable_x64.msi" "c:\setup\CloudbaseInitSetup_Stable_x64.msi" -force
if (-not (Test-Path "c:\setup\CloudbaseInitSetup_Stable_x64.msi")) {
  Write-Error "MSI not found at c:\setup\CloudbaseInitSetup_Stable_x64.msi after copy"
  exit 1
}

Write-Host "Installing CloudbaseInit MSI via msiexec..."
$proc = Start-Process -FilePath "msiexec.exe" `
  -ArgumentList "/i","c:\setup\CloudbaseInitSetup_Stable_x64.msi","/qn","/norestart","/l*v","C:\setup\cloud-init.log" `
  -Wait -PassThru
Write-Host "msiexec exit code: $($proc.ExitCode)"
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
  Write-Error "Cloudbase-Init MSI install failed with exit $($proc.ExitCode)"
  Get-Content "C:\setup\cloud-init.log" -Tail 80 -ErrorAction SilentlyContinue
  exit $proc.ExitCode
}

Write-Host "Verify cloudbase-init service is registered"
$svc = Get-Service -Name cloudbase-init -ErrorAction SilentlyContinue
if (-not $svc) {
  Write-Error "cloudbase-init service NOT found after MSI install"
  exit 1
}
Write-Host "cloudbase-init service: $($svc.Status) ($($svc.StartType))"
PS1A
fi

# ---------- 5d. Patch cloudbase-init-p2.ps1 to drop /mode:vm + capture logs ----------
# Upstream's script invokes:
#   sysprep.exe /generalize /oobe /mode:vm /unattend:cloudbase-init-unattend.xml
# /mode:vm is a Win10/Server 2019+ flag that asks sysprep to skip a few non-VM
# cleanup steps. On Proxmox/QEMU it sometimes returns cryptic non-zero exit
# codes (e.g. 267014) even when sysprep technically succeeded — packer then
# treats it as a failure and destroys the build VM, taking the sysprep log
# with it. We drop /mode:vm (sysprep figures out it's a VM anyway from
# hypervisor enlightenments) and dump the sysprep logs to C: so we can
# survive a re-run failure.
P2_PATH="$GOAD_PACKER_DIR/scripts/sysprep/cloudbase-init-p2.ps1"
if grep -q '/mode:vm\|/generalize /oobe /unattend' "$P2_PATH" 2>/dev/null; then
  echo "==> Patching $P2_PATH for sysprep flags + log capture..."
  # Remove /mode:vm; it's the most common cause of bogus sysprep exit codes
  sed -i 's| /mode:vm||g' "$P2_PATH"
  # Add /shutdown flag if missing — without it, sysprep generalizes then
  # immediately runs OOBE which assigns a fresh SID to THIS VM. We then
  # template that state, and every clone shares this VM's SID — same dup-SID
  # bug that started this whole packer adventure. /shutdown powers the VM
  # off before OOBE, so the template is in a "ready-for-fresh-OOBE" state
  # and each clone gets its own unique SID at first boot.
  if ! grep -q '/shutdown' "$P2_PATH"; then
    sed -i 's|/generalize /oobe /unattend|/generalize /oobe /shutdown /unattend|g' "$P2_PATH"
  fi
  # Replace the sysprep call with one that uses a no-spaces unattend path.
  # Upstream points at "C:\Program Files\Cloudbase Solutions\...\unattend.xml"
  # which sysprep can't parse correctly through cmd.exe argument splitting
  # (it fails with "Malformed command line detected; no dash or slash present
  # in option" because the spaces split the path into multiple tokens). Copy
  # the file to C:\unattend.xml first and reference that.
  python3 - "$P2_PATH" <<'PYFIX'
import sys, re
path = sys.argv[1]
with open(path) as f:
    content = f.read()
old_cmd = re.compile(
    r'start-process\s+-FilePath\s+"C:/Windows/system32/sysprep/sysprep\.exe"\s+'
    r'-ArgumentList\s+"[^"]*"\s+-wait',
    re.IGNORECASE,
)
new_cmd = (
    'Copy-Item "C:\\Program Files\\Cloudbase Solutions\\Cloudbase-Init\\conf\\cloudbase-init-unattend.xml" "C:\\unattend.xml" -Force\n'
    'start-process -FilePath "C:\\Windows\\System32\\Sysprep\\sysprep.exe" '
    '-ArgumentList "/generalize","/oobe","/shutdown","/unattend:C:\\unattend.xml" -wait'
)
content_new = old_cmd.sub(new_cmd, content)
if content_new != content:
    with open(path, 'w') as f:
        f.write(content_new)
    print(f"    Patched sysprep call in {path} to use no-spaces unattend path", file=sys.stderr)
PYFIX
  # If the file doesn't already capture logs, append a tee + log save block
  if ! grep -q 'cybercore-sysprep-log' "$P2_PATH"; then
    cat >> "$P2_PATH" <<'PSAPPEND'

# === CyberCore: capture sysprep result regardless of exit code ===========
# Packer destroys the VM on a non-zero exit, so dump everything useful to a
# place we can clone the disk to inspect (or that survives a retry).
$marker = "C:\cybercore-sysprep-log"
mkdir $marker -Force | Out-Null
Copy-Item -Path "C:\Windows\System32\Sysprep\Panther\*.log" -Destination $marker -ErrorAction SilentlyContinue
Copy-Item -Path "C:\Windows\Panther\*.log" -Destination $marker -ErrorAction SilentlyContinue
Get-WinEvent -LogName "Setup" -MaxEvents 50 -ErrorAction SilentlyContinue |
  Format-List | Out-File "$marker\setup-events.txt" -ErrorAction SilentlyContinue
"sysprep run completed" | Out-File "$marker\done.txt"
PSAPPEND
  fi
fi

# ---------- 6. Build the packer-side ISOs (autounattend + scripts) ----------
echo "==> Running build_proxmox_iso.sh to generate autounattend / scripts ISOs..."
cd "$GOAD_PACKER_DIR"
chmod +x build_proxmox_iso.sh
./build_proxmox_iso.sh

# ---------- 7. Copy the scripts ISO + autounattend ISO into ISO_STORAGE ----------
# These were just generated by build_proxmox_iso.sh. Packer references them
# via the Proxmox storage path (e.g., "cephfs:iso/scripts_withcloudinit.iso"),
# so they need to live where pvesm can see them.

# Resolve the on-disk path for ISO_STORAGE (works for local, cephfs, and dir-
# based storages). For cephfs the conventional path is /mnt/pve/cephfs/template/iso.
ISO_STORAGE_DIR=$(pvesm path "${ISO_STORAGE}:iso/_probe" 2>/dev/null | xargs dirname 2>/dev/null || true)
if [ -z "$ISO_STORAGE_DIR" ] || [ ! -d "$ISO_STORAGE_DIR" ]; then
  case "$ISO_STORAGE" in
    local)  ISO_STORAGE_DIR="/var/lib/vz/template/iso" ;;
    cephfs) ISO_STORAGE_DIR="/mnt/pve/cephfs/template/iso" ;;
    *)      ISO_STORAGE_DIR="/var/lib/vz/template/iso" ;;
  esac
fi
mkdir -p "$ISO_STORAGE_DIR"

SCRIPTS_ISO_SRC="$GOAD_PACKER_DIR/iso/scripts_withcloudinit.iso"
SCRIPTS_ISO_DEST="$ISO_STORAGE_DIR/scripts_withcloudinit.iso"
if [ ! -f "$SCRIPTS_ISO_SRC" ]; then
  echo "ERROR: build_proxmox_iso.sh did not produce $SCRIPTS_ISO_SRC"
  exit 1
fi
echo "==> Copying scripts ISO to $SCRIPTS_ISO_DEST..."
cp -f "$SCRIPTS_ISO_SRC" "$SCRIPTS_ISO_DEST"

AUTOUNATTEND_ISO_SRC="$GOAD_PACKER_DIR/iso/Autounattend_winserver2019_cloudinit.iso"
AUTOUNATTEND_ISO_DEST="$ISO_STORAGE_DIR/Autounattend_winserver2019_cloudinit.iso"
if [ -f "$AUTOUNATTEND_ISO_SRC" ]; then
  echo "==> Copying autounattend ISO to $AUTOUNATTEND_ISO_DEST..."
  cp -f "$AUTOUNATTEND_ISO_SRC" "$AUTOUNATTEND_ISO_DEST"
fi

# ---------- 8. Patch the pkvars file paths ----------
# IMPORTANT: do NOT change autounattend_iso. Upstream sets it to a relative
# local file path ("./iso/Autounattend_winserver2019_cloudinit.iso"). Packer's
# proxmox plugin uses that as a 'iso_url' which it reads from disk and then
# re-uploads to iso_storage_pool. Changing it to "cephfs:iso/..." makes the
# plugin try to *download* it as a URL — fails with 'error downloading ISO'.
# (For the same reason we don't strictly need to copy it to cephfs ourselves,
# but it's harmless and makes manual inspection easier.)
PKVARS_FILE="$GOAD_PACKER_DIR/windows_server2019_proxmox_cloudinit.pkvars.hcl"
[ -f "$PKVARS_FILE" ] || { echo "ERROR: $PKVARS_FILE not found"; exit 1; }
echo "==> Patching $PKVARS_FILE for our environment..."

# Reset autounattend_iso back to the upstream local-path value in case a
# previous run of this script mutated it to a "cephfs:iso/..." form (which
# made packer's iso_url-based fetch fail with 'error downloading ISO').
sed -i 's|^autounattend_iso *=.*|autounattend_iso      = "./iso/Autounattend_winserver2019_cloudinit.iso"|' "$PKVARS_FILE"

# Point iso_file (Windows install media) at our auto-detected ISO volid
sed -i "s|^iso_file *=.*|iso_file              = \"${WIN_ISO_VOLID}\"|" "$PKVARS_FILE"

# ---------- 9. Patch packer.json.pkr.hcl to use our bridge/vlan + ISO_STORAGE ----------
# Upstream's main packer file is named packer.json.pkr.hcl (despite being HCL,
# the .json. infix is leftover from when it converted from .json format).
PKRHCL="$GOAD_PACKER_DIR/packer.json.pkr.hcl"
[ -f "$PKRHCL" ] || PKRHCL="$GOAD_PACKER_DIR/packer.pkr.hcl"  # fallback for older repo layouts
[ -f "$PKRHCL" ] || { echo "ERROR: cannot find packer.json.pkr.hcl or packer.pkr.hcl in $GOAD_PACKER_DIR"; exit 1; }
echo "==> Patching $PKRHCL for our environment..."

# bridge replacement
sed -i "s|bridge = \"vmbr3\"|bridge = \"$PROXMOX_BRIDGE\"|" "$PKRHCL"
# Set/restore the vlan_tag line. Using awk for robustness — replaces any
# existing vlan_tag line (whatever value) inside the network_adapters block,
# OR adds the line right after 'model = "virtio"' if it's been deleted by
# a previous run with PROXMOX_BUILD_VLAN="" (which used to drop the line
# unconditionally and break re-runs).
if [ -n "$PROXMOX_BUILD_VLAN" ]; then
  if grep -q 'vlan_tag *=' "$PKRHCL"; then
    sed -i "s|vlan_tag *= *\"[^\"]*\"|vlan_tag = \"$PROXMOX_BUILD_VLAN\"|" "$PKRHCL"
  else
    sed -i "/model *= *\"virtio\"/a\\    vlan_tag = \"$PROXMOX_BUILD_VLAN\"" "$PKRHCL"
  fi
else
  # Truly no VLAN — drop any existing vlan_tag line
  sed -i '/vlan_tag *=/d' "$PKRHCL"
fi

# Replace the hardcoded "local:iso/virtio-win.iso" reference with our auto-detected
# virtio volid (could be cephfs:iso/virtio-win-0.1.262.iso or similar).
sed -i "s|iso_file = \"local:iso/virtio-win.iso\"|iso_file = \"${VIRTIO_ISO_VOLID}\"|" "$PKRHCL"

# Replace the hardcoded "local:iso/scripts_withcloudinit.iso" reference too —
# we copied that ISO into ISO_STORAGE above.
sed -i "s|iso_file = \"local:iso/scripts_withcloudinit.iso\"|iso_file = \"${ISO_STORAGE}:iso/scripts_withcloudinit.iso\"|" "$PKRHCL"

# autounattend uses iso_storage_pool which is referenced separately — set it
# to our ISO_STORAGE so packer can write its ad-hoc ISO there if needed.
sed -i "s|iso_storage_pool = \"local\"|iso_storage_pool = \"$ISO_STORAGE\"|" "$PKRHCL"

# Add a winrm_host = BUILD_STATIC_IP line so packer connects directly to our
# known IP after the cybercore-build-network.ps1 script has set it. Without
# this, packer falls back to qga IP discovery — works in theory but flaky if
# the VM has APIPA + static IP both visible. Idempotent: skips if already set.
if ! grep -q '^[[:space:]]*winrm_host[[:space:]]*=' "$PKRHCL"; then
  echo "==> Adding winrm_host = \"$BUILD_STATIC_IP\" to packer config..."
  sed -i "/winrm_username[[:space:]]*=/a\\  winrm_host           = \"$BUILD_STATIC_IP\"" "$PKRHCL"
else
  sed -i "s|^[[:space:]]*winrm_host[[:space:]]*=.*|  winrm_host           = \"$BUILD_STATIC_IP\"|" "$PKRHCL"
fi

# ---------- 10. packer init / validate / build ----------
echo "==> packer init..."
packer init "$GOAD_PACKER_DIR"
echo "==> packer validate..."
packer validate -var-file=windows_server2019_proxmox_cloudinit.pkvars.hcl "$GOAD_PACKER_DIR"
echo "==> packer build (this is the long step — ~30-60 min)..."
# -on-error=abort keeps the build VM around if the build fails, so we can
# log in via VNC / clone the disk to inspect logs (especially the sysprep
# Panther logs at C:\Windows\System32\Sysprep\Panther\setupact.log). Without
# this, packer auto-deletes the VM on error and we lose all forensics.
# Override with PACKER_ON_ERROR=cleanup if you want auto-cleanup back.
packer build -on-error="${PACKER_ON_ERROR:-abort}" \
  -var-file=windows_server2019_proxmox_cloudinit.pkvars.hcl "$GOAD_PACKER_DIR"

# ---------- 11. Renumber the resulting template to FINAL_VMID ----------
# packer creates a VM whose name comes from vm_name in the pkvars file (e.g.
# "WinServer2019x64-cloudinit-qcow2" in current upstream). Read it dynamically
# instead of hardcoding so we don't break when upstream renames it.
PACKER_TEMPLATE_NAME=$(awk -F'"' '/^[[:space:]]*vm_name[[:space:]]*=/ {print $2; exit}' "$PKVARS_FILE")
if [ -z "$PACKER_TEMPLATE_NAME" ]; then
  echo "ERROR: could not read vm_name from $PKVARS_FILE"
  exit 1
fi
echo "==> Looking for packer-built template named: $PACKER_TEMPLATE_NAME"
SRC_VMID=$(qm list | awk -v n="$PACKER_TEMPLATE_NAME" '$2==n {print $1}' | head -1)
if [ -z "$SRC_VMID" ]; then
  echo "ERROR: packer didn't produce a template named $PACKER_TEMPLATE_NAME"
  echo "       (qm list output:)"
  qm list
  exit 1
fi
echo "==> packer-built template: VMID $SRC_VMID"

# Proxmox doesn't have a direct "renumber" — we backup and restore as the new VMID
DUMP_DIR=/var/lib/vz/dump
mkdir -p "$DUMP_DIR"
echo "==> Backing up template $SRC_VMID..."
vzdump "$SRC_VMID" --dumpdir "$DUMP_DIR" --compress zstd >/dev/null
DUMP_FILE=$(ls -t "$DUMP_DIR"/vzdump-qemu-${SRC_VMID}-*.vma.zst 2>/dev/null | head -1)
if [ -z "$DUMP_FILE" ]; then
  DUMP_FILE=$(ls -t "$DUMP_DIR"/vzdump-qemu-${SRC_VMID}-*.tar.zst 2>/dev/null | head -1)
fi
[ -n "$DUMP_FILE" ] || { echo "ERROR: vzdump did not produce an archive for VMID $SRC_VMID"; exit 1; }
echo "==> Backup: $DUMP_FILE"

echo "==> Destroying packer-side template $SRC_VMID..."
qm destroy "$SRC_VMID" --purge

echo "==> Restoring as $FINAL_VMID..."
qmrestore "$DUMP_FILE" "$FINAL_VMID" --storage "$PROXMOX_STORAGE"
qm set "$FINAL_VMID" --name "WinServer2019-GOAD" \
  --description "Win Server 2019 — GOAD packer build, sysprep-generalized, cloudbase-init enabled. Source: front-end/scripts/bake-win-server-template.sh"
qm template "$FINAL_VMID"

echo "==> Cleanup..."
rm -f "$DUMP_FILE"

# ---------- 12. Summary ----------
echo ""
echo "=========================================================================="
echo "  Win Server 2019 GOAD template baked at VMID $FINAL_VMID"
echo "=========================================================================="
echo "  Verify:           qm config $FINAL_VMID"
echo "  Test clone:       qm clone $FINAL_VMID 9994 --name wintest --full --storage $PROXMOX_STORAGE"
echo "  Then start:       qm set 9994 --net0 virtio,bridge=$PROXMOX_BRIDGE${PROXMOX_BUILD_VLAN:+,tag=$PROXMOX_BUILD_VLAN}"
echo "                    qm start 9994 && sleep 90"
echo "  Inspect WinRM:    qm guest exec 9994 -- ipconfig"
echo "  Cleanup test:     qm stop 9994 && qm destroy 9994 --purge"
echo ""
echo "  Default credentials baked in:"
echo "    Administrator / vagrant"
echo "    vagrant / vagrant   (Administrators group; preserved through DC promotion)"
echo ""
echo "  IMPORTANT: spec.goad.admin_password in your challenge config should now"
echo "  be 'vagrant' (the bake-time admin password set by Autounattend.xml)."
echo "  Each clone gets a unique machine SID via sysprep — duplicate-SID issue"
echo "  that broke child DC promotion is now fixed at the template level."
echo "=========================================================================="
