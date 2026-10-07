$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline RDP: enable with NLA + TLS, grant specific users only.
# Use rdp-config.ps1 for the NLA-off / low-security-layer variant.

Write-Step "Enabling Remote Desktop"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force

Write-Step "Requiring Network Level Authentication"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Force
# SecurityLayer = 2 means SSL (TLS 1.0) required
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer"     -Value 2 -Force
# MinEncryptionLevel = 3 means High encryption required (128-bit)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Force

Write-Step "Enabling Remote Desktop firewall group"
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Out-Null

Write-Step "Granting RDP access to student (only)"
try { Add-LocalGroupMember -Group "Remote Desktop Users" -Member "student" -ErrorAction SilentlyContinue } catch {}

Write-Step "Starting Remote Desktop Services"
Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name TermService -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== rdp-baseline complete ==="
Write-Host "Port 3389     : open"
Write-Host "NLA           : required"
Write-Host "Security      : TLS + high encryption"
Write-Host "RDP users     : student"
