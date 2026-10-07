$ErrorActionPreference = "Stop"

$InstallerDir = "C:\Windows\Temp\installers"

function Install-Msi {
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [string[]]$Arguments = @()
    )

    if (-not (Test-Path $Path)) {
        throw "Installer not found: $Path"
    }

    Write-Host "Installing $([System.IO.Path]::GetFileName($Path))"

    $MsiArguments = @("/i", "`"$Path`"", "/qn", "/norestart") + $Arguments

    $Process = Start-Process `
        -FilePath "msiexec.exe" `
        -ArgumentList $MsiArguments `
        -Wait `
        -PassThru

    if ($Process.ExitCode -notin @(0, 3010)) {
        throw "MSI installation failed with code $($Process.ExitCode): $Path"
    }
}

Write-Host "Installing optional Windows features"

# Add-WindowsCapability pulls from Windows Update. On an isolated build VLAN that
# fails, and it is not worth failing the whole build over -- the template is
# still usable without OpenSSH.
$Capabilities = @(
    "OpenSSH.Client~~~~0.0.1.0"
    "OpenSSH.Server~~~~0.0.1.0"
)

foreach ($Capability in $Capabilities) {
    try {
        $Current = Get-WindowsCapability -Online -Name $Capability

        if ($Current.State -ne "Installed") {
            Add-WindowsCapability -Online -Name $Capability | Out-Null
            Write-Host "Installed $Capability"
        }
        else {
            Write-Host "$Capability already present"
        }
    }
    catch {
        Write-Host "WARNING: could not install $Capability -- $($_.Exception.Message)"
    }
}

if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
    Set-Service -Name sshd -StartupType Automatic
    Start-Service -Name sshd

    # Sysprep /generalize does not regenerate these, so a template built with
    # them would hand every clone the same host identity.
    Write-Host "Removing SSH host keys so each clone generates its own"

    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue

    Remove-Item `
        -Path "C:\ProgramData\ssh\ssh_host_*" `
        -Force `
        -ErrorAction SilentlyContinue
}
else {
    Write-Host "sshd not present, skipping SSH configuration"
}

# Anything dropped into files/installers/ is installed here, in filename order.
# Keeps air-gapped builds working without editing this script.
if (Test-Path $InstallerDir) {
    $Msis = Get-ChildItem -Path $InstallerDir -Filter *.msi -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike "CloudbaseInitSetup*" } |
        Sort-Object Name

    foreach ($Msi in $Msis) {
        Install-Msi -Path $Msi.FullName
    }

    if (-not $Msis) {
        Write-Host "No additional MSIs staged in $InstallerDir"
    }
}
