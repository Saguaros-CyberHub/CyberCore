# Runs once, from the PACKERDATA CD, as the first logon command in
# autounattend.xml. Everything Packer needs in order to connect at all happens
# here: the QEMU guest agent (so Proxmox can report an IP) and the WinRM
# listener. Output is captured to C:\Windows\Temp\bootstrap.log.

$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Find-VirtioRoot {
    foreach ($Drive in (Get-PSDrive -PSProvider FileSystem)) {
        $Root = $Drive.Root

        if (Test-Path (Join-Path $Root "virtio-win-guest-tools.exe")) {
            return $Root
        }
    }

    return $null
}

Write-Host "Locating virtio-win media"

$VirtioRoot = Find-VirtioRoot

if (-not $VirtioRoot) {
    throw "virtio-win-guest-tools.exe not found on any drive. Check that virtio_iso is attached and readable."
}

Write-Host "Found virtio-win media at $VirtioRoot"
Write-Host "Installing virtio-win-guest-tools"

$Installer = Join-Path $VirtioRoot "virtio-win-guest-tools.exe"

# Recent builds are Advanced Installer bundles (/install /quiet /norestart);
# older ones are NSIS (/S). Try the modern switches first.
$Process = Start-Process `
    -FilePath $Installer `
    -ArgumentList "/install", "/quiet", "/norestart" `
    -Wait `
    -PassThru

if ($Process.ExitCode -notin @(0, 3010)) {
    Write-Host "Modern switches returned $($Process.ExitCode), retrying with /S"

    $Process = Start-Process `
        -FilePath $Installer `
        -ArgumentList "/S" `
        -Wait `
        -PassThru

    if ($Process.ExitCode -notin @(0, 3010)) {
        throw "virtio-win-guest-tools installation failed with code $($Process.ExitCode)"
    }
}

Write-Host "Staging the full virtio driver set into the driver store"

# virtio-win-guest-tools installs the whole suite plus the guest agent, but PnP
# only *binds* drivers for hardware present at build time. Adding every w11/amd64
# INF to the driver store as well means a clone handed a device this VM never had
# -- virtio-blk instead of virtio-scsi, a balloon device, an RNG, a serial port --
# binds it on first boot instead of sitting in Device Manager with a yellow bang.
$DriverInfs = Get-ChildItem `
    -Path $VirtioRoot `
    -Recurse `
    -Filter *.inf `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\w11\\amd64\\' }

$Staged = 0

foreach ($Inf in $DriverInfs) {
    & pnputil.exe /add-driver $Inf.FullName /install 2>&1 | Out-Null

    # pnputil returns 259 (ERROR_NO_MORE_ITEMS) when a driver is already staged,
    # which is a no-op rather than a failure.
    if ($LASTEXITCODE -in @(0, 259)) {
        $Staged++
    }
    else {
        Write-Host "  WARNING: pnputil returned $LASTEXITCODE for $($Inf.Name)"
    }
}

Write-Host "Staged $Staged of $($DriverInfs.Count) virtio drivers"

Write-Host "Waiting for the QEMU guest agent service"

$Deadline = (Get-Date).AddMinutes(5)

while ((Get-Date) -lt $Deadline) {
    $Service = Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue

    if ($Service) {
        Set-Service -Name "QEMU-GA" -StartupType Automatic

        if ($Service.Status -ne "Running") {
            Start-Service -Name "QEMU-GA"
        }

        Write-Host "QEMU guest agent is running"
        break
    }

    Start-Sleep -Seconds 5
}

if (-not (Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue)) {
    # Not fatal on its own, but Packer resolves the VM's IP through the agent,
    # so the WinRM connection will almost certainly time out after this.
    Write-Host "WARNING: QEMU guest agent service never appeared"
}

Write-Host "Configuring WinRM"

& (Join-Path $ScriptRoot "configure-winrm.ps1")

Write-Host "Bootstrap complete"
