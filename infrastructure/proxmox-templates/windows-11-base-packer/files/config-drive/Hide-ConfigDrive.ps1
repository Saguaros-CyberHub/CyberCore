# =============================================================================
# TEMPORARY -- see "Hiding the config drive" in README.md before extending this.
#
# This is a speed bump, NOT a security boundary. It removes the drive letter from
# the Proxmox cloud-init config drive so the cleartext Cloud-Init password in
# openstack/latest/user_data is not sitting in Explorer for every student who
# opens This PC. The account it hides from is a local Administrator, so anyone
# who knows to run `mountvol` or read \\.\CdRom0 gets it back. That is a known
# and accepted trade for now: the real fix is to stop putting a reusable credential
# on the drive, and to strip the drive at the hypervisor after Cloudbase-Init
# has applied it.
#
# The drive is deliberately left ATTACHED at the Proxmox level. Cloudbase-Init
# re-reads it on every boot, and a changed Cloud-Init field (new instance ID)
# is the only thing that makes a password change take effect -- so removing the
# device would break "change password in the portal, reboot, log in".
# Cloudbase-Init finds the drive by enumerating volumes, not by drive letter,
# so hiding the letter does not interfere with that.
# =============================================================================

$ErrorActionPreference = "Stop"

$LogFile = "C:\Windows\Temp\hide-config-drive.log"

function Write-Log {
    param([string]$Message)

    $Line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message

    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line -ErrorAction SilentlyContinue
}

Write-Log "Hide-ConfigDrive starting"

# Wait for Cloudbase-Init to finish before touching anything. cloudbase-init.conf
# sets stop_service_on_exit=true, so Stopped means the run is over rather than
# not yet started -- but on a boot where the service has not been reached yet it
# is also Stopped, hence the Running check first. On boots where the instance ID
# is unchanged every plugin is already marked done and this returns almost
# immediately.
$Deadline = (Get-Date).AddMinutes(10)
$Service  = Get-Service -Name "cloudbase-init" -ErrorAction SilentlyContinue

if ($Service) {
    while ((Get-Date) -lt $Deadline) {
        $Service.Refresh()

        if ($Service.Status -eq "Stopped" -and $Service.StartType -ne "Disabled") {
            # Give a not-yet-started service a chance to come up before deciding
            # the run is finished.
            Start-Sleep -Seconds 5
            $Service.Refresh()

            if ($Service.Status -eq "Stopped") {
                break
            }
        }

        Start-Sleep -Seconds 5
    }

    Write-Log "Cloudbase-Init service status: $($Service.Status)"
}
else {
    Write-Log "WARNING: cloudbase-init service not found, continuing anyway"
}

# Identify the config drive by what is on it rather than by drive letter or bus.
# Proxmox presents it as an ISO9660 CD-ROM on ide2 today, but the Cloudbase-Init
# config also accepts vfat/hdd/partition, and the letter is whatever happens to
# be free (D: on a stock clone). The openstack/ directory is the invariant.
$Volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DriveLetter -and $_.DriveLetter -ne $env:SystemDrive
    }

$Found = $false

foreach ($Volume in $Volumes) {
    $Marker = Join-Path -Path "$($Volume.DriveLetter)\" -ChildPath "openstack"

    if (-not (Test-Path -Path $Marker -ErrorAction SilentlyContinue)) {
        continue
    }

    $Found = $true

    Write-Log "Config drive found at $($Volume.DriveLetter) (label: $($Volume.Label))"

    mountvol.exe $Volume.DriveLetter /D 2>&1 | ForEach-Object { Write-Log $_ }

    if ($LASTEXITCODE -ne 0) {
        Write-Log "WARNING: mountvol exited $LASTEXITCODE for $($Volume.DriveLetter)"
        continue
    }

    # mountvol reports success even in cases where the mount manager reassigns
    # the letter, so confirm rather than trust the exit code.
    if (Test-Path -Path $Marker -ErrorAction SilentlyContinue) {
        Write-Log "WARNING: $($Volume.DriveLetter) is still readable after mountvol /D"
    }
    else {
        Write-Log "Removed drive letter $($Volume.DriveLetter)"
    }
}

if (-not $Found) {
    # Expected on a VM whose cloud-init drive was detached at the hypervisor, and
    # on any boot after a previous run already removed the letter.
    Write-Log "No lettered config drive present, nothing to do"
}

Write-Log "Hide-ConfigDrive complete"
