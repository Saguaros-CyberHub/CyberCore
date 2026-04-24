$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline OpenSSH: install + start sshd with stock sshd_config.
# No seeded keys, no relaxed auth. Use ssh-config.ps1 for the artifact-rich variant.

Write-Step "Installing OpenSSH Server Windows capability"
try {
    $cap = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
    if ($cap -and $cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $cap.Name -ErrorAction SilentlyContinue | Out-Null
    }
} catch { Write-Host "OpenSSH capability install: $($_.Exception.Message)" }

Write-Step "Starting sshd service"
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name sshd -ErrorAction SilentlyContinue

# Also start the agent so pubkey workflows work if admin uses them later
Set-Service -Name 'ssh-agent' -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue

Write-Step "Opening TCP/22 in firewall"
Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Lab-SSH-22-Allow" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# Use the shipped sshd_config defaults -- no permissive overrides here.
# (The OpenSSH-Server capability installs a sane default config.)

Write-Step "Ensuring default shell is PowerShell for SSH sessions"
try {
    $regPath = "HKLM:\SOFTWARE\OpenSSH"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name DefaultShell -PropertyType String -Value (Get-Command powershell.exe).Source -Force | Out-Null
} catch {}

Write-Host ""
Write-Host "=== ssh-baseline complete ==="
Write-Host "Service   : sshd + ssh-agent started (auto)"
Write-Host "Port      : 22/TCP"
Write-Host "Config    : stock (no relaxed auth)"
