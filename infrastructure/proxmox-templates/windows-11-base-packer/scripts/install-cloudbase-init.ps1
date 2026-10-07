$ErrorActionPreference = "Stop"

$InstallRoot = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init"
$ConfigSource = "C:\Windows\Temp\cloudbase-init"
$StagedInstaller = "C:\Windows\Temp\installers\CloudbaseInitSetup_Stable_x64.msi"
$InstallerPath = "C:\Windows\Temp\CloudbaseInitSetup.msi"
$InstallerUrl = "https://cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi"

if (Test-Path $StagedInstaller) {
    Write-Host "Using pre-staged installer $StagedInstaller"
    Copy-Item -Path $StagedInstaller -Destination $InstallerPath -Force
}
else {
    Write-Host "Downloading Cloudbase-Init from $InstallerUrl"

    # Server 2022/Win11 default to TLS 1.2 already, but the build VLAN may sit
    # behind a proxy that renegotiates.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        Invoke-WebRequest `
            -Uri $InstallerUrl `
            -OutFile $InstallerPath `
            -UseBasicParsing
    }
    catch {
        throw "Could not download Cloudbase-Init. If the build VLAN has no outbound HTTPS, drop CloudbaseInitSetup_Stable_x64.msi into files/installers/ instead. Error: $($_.Exception.Message)"
    }
}

Write-Host "Installing Cloudbase-Init"

# RUN_SERVICE_AS_LOCAL_SYSTEM avoids the MSI creating its own service account,
# whose password would be baked into the template.
$Arguments = @(
    "/i"
    "`"$InstallerPath`""
    "/qn"
    "/norestart"
    "/L*v"
    "`"C:\Windows\Temp\cloudbase-init-install.log`""
    "RUN_SERVICE_AS_LOCAL_SYSTEM=1"
)

$Process = Start-Process `
    -FilePath "msiexec.exe" `
    -ArgumentList $Arguments `
    -PassThru `
    -Wait

if ($Process.ExitCode -notin @(0, 3010)) {
    throw "Cloudbase-Init installation failed: $($Process.ExitCode). See C:\Windows\Temp\cloudbase-init-install.log"
}

if (-not (Test-Path $InstallRoot)) {
    throw "Cloudbase-Init reported success but $InstallRoot does not exist"
}

# The stock conf points at the OpenStack HTTP metadata service, which Proxmox
# does not run. Without this the template boots with no account and no hostname.
Write-Host "Applying Proxmox Cloudbase-Init configuration"

$ConfigFiles = @(
    "cloudbase-init.conf"
    "cloudbase-init-unattend.conf"
)

foreach ($ConfigFile in $ConfigFiles) {
    $Source = Join-Path $ConfigSource $ConfigFile

    if (-not (Test-Path $Source)) {
        throw "Missing config file $Source. It should have been uploaded from files/cloudbase-init/."
    }

    Copy-Item `
        -Path $Source `
        -Destination (Join-Path $InstallRoot "conf\$ConfigFile") `
        -Force
}

New-Item `
    -ItemType Directory `
    -Force `
    -Path (Join-Path $InstallRoot "LocalScripts") | Out-Null

New-Item `
    -ItemType Directory `
    -Force `
    -Path (Join-Path $InstallRoot "log") | Out-Null

# The service must not run during the build -- it would consume the (absent)
# config drive and mark itself complete before the template is ever cloned.
Write-Host "Configuring the Cloudbase-Init service for first boot"

Stop-Service -Name cloudbase-init -Force -ErrorAction SilentlyContinue

Set-Service `
    -Name cloudbase-init `
    -StartupType Automatic
