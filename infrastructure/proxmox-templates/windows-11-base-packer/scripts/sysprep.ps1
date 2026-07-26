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

if (-not (Test-Path (Join-Path $SysprepRoot "Sysprep_succeeded.tag"))) {
    throw "Sysprep returned 0 but did not write Sysprep_succeeded.tag; the image is not generalized"
}

Write-Host "Sysprep complete. The builder will now shut the VM down and convert it to a template."
