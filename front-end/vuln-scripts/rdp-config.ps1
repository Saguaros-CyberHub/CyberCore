$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- Enable RDP at the registry level ---
Write-Step "Enabling Remote Desktop (fDenyTSConnections = 0)"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
# Disable Network Level Authentication so older clients (and brute-force tools) can connect
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force
# Keep RDP security layer low (RDP classic, not TLS-enforced)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 1 -Force
# Don't force strong encryption
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 1 -Force

# --- Firewall rule ---
Write-Step "Enabling Remote Desktop firewall group"
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Lab-RDP-3389-Allow" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# --- Allow the student + svcbackup accounts to RDP in ---
Write-Step "Granting RDP access to student + svcbackup"
foreach ($u in @("student","svcbackup")) {
    try { Add-LocalGroupMember -Group "Remote Desktop Users" -Member $u -ErrorAction SilentlyContinue } catch {}
}

# --- Weaken: allow password caching client-side (removes the warning dialog) ---
Write-Step "Disabling 'Always prompt for password' on RDP"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fPromptForPassword" -Value 0 -Force

# --- Ensure TermService is running and set to automatic ---
Write-Step "Starting Remote Desktop Services"
Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name TermService -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== rdp-config complete ==="
Write-Host "Port 3389 : open"
Write-Host "NLA       : disabled (deliberate lab weakness)"
Write-Host "RDP users : student, svcbackup"
