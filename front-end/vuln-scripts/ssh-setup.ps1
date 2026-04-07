$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# ── Install OpenSSH Server ──
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if (-not $cap) {
    throw "OpenSSH.Server capability not found on this system."
}

if ($cap.State -ne "Installed") {
    Write-Step "Installing OpenSSH Server"
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
} else {
    Write-Step "OpenSSH Server already installed"
}

# ── Configure sshd ──
Write-Step "Configuring sshd service"
Set-Service -Name sshd -StartupType Automatic

# Set default shell to PowerShell
New-ItemProperty `
    -Path "HKLM:\SOFTWARE\OpenSSH" `
    -Name "DefaultShell" `
    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String `
    -Force | Out-Null

# ── Firewall rule ──
Write-Step "Ensuring SSH firewall rule"
$rule = Get-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule `
        -Name "sshd" `
        -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -Action Allow `
        -LocalPort 22 | Out-Null
}

# ── Ensure sshd_config exists and has password auth enabled ──
$sshdConfig = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshdConfig) {
    $content = Get-Content $sshdConfig -Raw

    # Enable password auth
    $content = $content -replace '(?m)^\s*#?\s*PasswordAuthentication\s+.*$', 'PasswordAuthentication yes'

    # Enable pubkey auth
    $content = $content -replace '(?m)^\s*#?\s*PubkeyAuthentication\s+.*$', 'PubkeyAuthentication yes'

    Set-Content -Path $sshdConfig -Value $content -Encoding ASCII
    Write-Step "Updated sshd_config (password + pubkey auth enabled)"
} else {
    Write-Step "sshd_config not found — using defaults"
}

# ── Set network to Private (required for SSH) ──
Write-Step "Setting network profile to Private"
Get-NetConnectionProfile | ForEach-Object {
    if ($_.NetworkCategory -ne "Private") {
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
    }
}

# ── Start sshd ──
Write-Step "Starting sshd"
Restart-Service sshd -Force

# ── Verify ──
$svc = Get-Service sshd
$listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -eq 22 }

Write-Host ""
Write-Host "=== SSH Setup Complete ==="
Write-Host "Service:  $($svc.Status) ($($svc.StartType))"
Write-Host "Port 22:  $(if ($listener) { 'LISTENING' } else { 'NOT LISTENING' })"
Write-Host "Shell:    PowerShell"
Write-Host ""
Write-Host 'Test with: ssh username@this-vm-ip'
