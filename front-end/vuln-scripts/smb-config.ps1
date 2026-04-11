$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

$BasePath = "C:\LabShare"

# Set network to Private
Write-Step "Setting network profile to Private"
Get-NetConnectionProfile | ForEach-Object {
    if ($_.NetworkCategory -ne "Private") {
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
    }
}

# Enable SMB firewall rules
Write-Step "Enabling SMB / File Sharing firewall rules"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Out-Null

# Create folders
Write-Step "Creating share folders"
foreach ($folder in @($BasePath, "$BasePath\Public", "$BasePath\Users", "$BasePath\Drop", "$BasePath\Legacy")) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
}

# Set NTFS permissions
Write-Step "Setting NTFS permissions"
icacls "$BasePath\Public" /inheritance:r /grant:r "Everyone:(OI)(CI)RX" "Administrators:(OI)(CI)F" | Out-Null
icacls "$BasePath\Users" /inheritance:r /grant:r "Users:(OI)(CI)RX" "Administrators:(OI)(CI)F" | Out-Null
icacls "$BasePath\Drop" /inheritance:r /grant:r "Users:(OI)(CI)M" "Administrators:(OI)(CI)F" | Out-Null

# Remove existing shares
Write-Step "Creating SMB shares"
foreach ($name in @("Public","Users","Drop")) {
    $existing = Get-SmbShare -Name $name -ErrorAction SilentlyContinue
    if ($existing) { Remove-SmbShare -Name $name -Force }
}

New-SmbShare -Name "Public" -Path "$BasePath\Public" -ReadAccess "Everyone" -FullAccess "Administrators" | Out-Null
New-SmbShare -Name "Users" -Path "$BasePath\Users" -ReadAccess "Users" -FullAccess "Administrators" | Out-Null
New-SmbShare -Name "Drop" -Path "$BasePath\Drop" -ChangeAccess "Users" -FullAccess "Administrators" | Out-Null

# Enable null session (deliberate weakness)
Write-Step "Enabling anonymous/null-session access (lab weakness)"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -PropertyType MultiString -Value @("Public") -Force | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -PropertyType DWord -Value 0 -Force | Out-Null

# Seed files
Write-Step "Seeding share content"
Set-Content "$BasePath\Public\IT-Onboarding.txt" @"
IT Onboarding
Welcome to the internal training network.
Common internal services: SMB shares, WinRM, SSH, Training web applications.
If you need access to legacy deployment content, check the Legacy folder.
"@ -Encoding UTF8

Set-Content "$BasePath\Legacy\deploy.bat" @"
@echo off
echo Starting legacy deployment routine...
copy C:\ProgramData\Ops\migration_todo.txt C:\LabShare\Public\migration_todo.txt >nul 2>&1
echo Done.
"@ -Encoding UTF8

Set-Content "$BasePath\Legacy\readme.txt" @"
Legacy Folder Notes
These files were copied from an older support share.
Items in this folder should be reviewed before reuse.
"@ -Encoding UTF8

Write-Host ""
Write-Host "=== SMB Setup Complete ==="
Write-Host "Shares: Public (Everyone read, null session), Users (auth read), Drop (auth write)"
Write-Host "Null session enabled on Public share"
