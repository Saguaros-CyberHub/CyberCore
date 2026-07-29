# Final provisioner. Generalizes the image so the clone gets a fresh SID,
# hostname and machine identity, and hands first boot to Cloudbase-Init via
# sysprep-unattend.xml.
#
# /quit, not /shutdown. The proxmox builder exposes no shutdown_command hook and
# powers the VM off itself once the last provisioner returns; /shutdown would
# drop the WinRM connection while this script was still running and Packer would
# report the build as failed. With /quit, Sysprep runs to completion, this script
# returns an exit code Packer can act on, and the builder does the shutdown.

$ErrorActionPreference = "Stop"

$SysprepRoot = "C:\Windows\System32\Sysprep"
$UnattendSource = "C:\Windows\Setup\Scripts\sysprep-unattend.xml"
$UnattendTarget = Join-Path $SysprepRoot "unattend.xml"

if (-not (Test-Path $UnattendSource)) {
    throw "Missing $UnattendSource. Without it Sysprep still generalizes the image, but the template boots into OOBE instead of handing off to Cloudbase-Init."
}

Copy-Item -Path $UnattendSource -Destination $UnattendTarget -Force

# Windows 11 turns Device Encryption on by itself on hardware that qualifies, and
# this VM qualifies: TPM 2.0 plus Secure Boot, both of which the template wants
# for other reasons. Sysprep then refuses to generalize:
#   SYSPRP BitLocker-Sysprep: BitLocker is on for the OS volume. (0x80310039)
# The specialize pass of autounattend.xml sets PreventDeviceEncryption, so on a
# clean build this loop finds nothing to do. It stays as a safety net for images
# where encryption started before that key was written.
$SystemDrive = $env:SystemDrive

if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    $Volume = Get-BitLockerVolume -MountPoint $SystemDrive -ErrorAction SilentlyContinue

    if ($Volume -and $Volume.VolumeStatus -ne "FullyDecrypted") {
        Write-Host "BitLocker is $($Volume.VolumeStatus) on $SystemDrive; decrypting before Sysprep"

        Disable-BitLocker -MountPoint $SystemDrive -ErrorAction Stop | Out-Null

        # Decryption is asynchronous and Sysprep will not wait for it.
        $Deadline = (Get-Date).AddMinutes(90)

        while ((Get-Date) -lt $Deadline) {
            Start-Sleep -Seconds 15

            $Volume = Get-BitLockerVolume -MountPoint $SystemDrive -ErrorAction SilentlyContinue

            if (-not $Volume -or $Volume.VolumeStatus -eq "FullyDecrypted") {
                break
            }

            Write-Host "  $($Volume.VolumeStatus), $($Volume.EncryptionPercentage)% encrypted"
        }

        if ($Volume -and $Volume.VolumeStatus -ne "FullyDecrypted") {
            throw "BitLocker on $SystemDrive is still $($Volume.VolumeStatus) after 90 minutes; Sysprep cannot generalize an encrypted volume"
        }

        Write-Host "$SystemDrive is fully decrypted"
    }
    else {
        Write-Host "BitLocker is not enabled on $SystemDrive"
    }
}
else {
    Write-Host "BitLocker cmdlets unavailable; skipping the decryption check"
}

# Logs from the build's own install confuse the generalize pass and are the usual
# cause of "a fatal error occurred while trying to sysprep the machine".
Remove-Item `
    -Path (Join-Path $SysprepRoot "Panther\*") `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Remove-Item `
    -Path (Join-Path $SysprepRoot "Sysprep_succeeded.tag") `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "Running Sysprep"

$Process = Start-Process `
    -FilePath (Join-Path $SysprepRoot "Sysprep.exe") `
    -ArgumentList "/generalize", "/oobe", "/quit", "/quiet", "/unattend:$UnattendTarget" `
    -Wait `
    -PassThru

if ($Process.ExitCode -ne 0) {
    $Log = "C:\Windows\System32\Sysprep\Panther\setuperr.log"

    if (Test-Path $Log) {
        Write-Host "--- setuperr.log ---"
        Get-Content -Path $Log -Tail 40
        Write-Host "--- end setuperr.log ---"
    }

    throw "Sysprep failed with exit code $($Process.ExitCode)"
}

# Sysprep_succeeded.tag is written on the shutdown/reboot path. A /quit run can
# return before it exists, so its absence proves nothing and checking for it
# fails builds that actually generalized cleanly. The authoritative signal is the
# generalization state the generalize pass writes to the registry:
#   4 = generalized, specialize pending on next boot  <- what we want
#   7 = fully configured, i.e. generalize never ran
$StatusKey = "HKLM:\SYSTEM\Setup\Status\SysprepStatus"

$State = (Get-ItemProperty `
        -Path $StatusKey `
        -Name GeneralizationState `
        -ErrorAction SilentlyContinue).GeneralizationState

if ($State -ne 4) {
    $Log = Join-Path $SysprepRoot "Panther\setupact.log"

    if (Test-Path $Log) {
        Write-Host "--- setupact.log ---"
        Get-Content -Path $Log -Tail 40
        Write-Host "--- end setupact.log ---"
    }

    throw "Sysprep exited 0 but GeneralizationState is '$State' (expected 4); the image is not generalized"
}

Write-Host "GeneralizationState is 4; the image is generalized"

Write-Host "Sysprep complete. The builder will now shut the VM down and convert it to a template."
