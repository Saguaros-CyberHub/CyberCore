$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline SMB: enable file sharing with authenticated-only access.
# NO null session, NO anonymous enumeration, NO guest access.
# Use smb-config.ps1 if you want the vulnerable variant.

$BasePath = "C:\LabShare"

Write-Step "Setting network profile to Private"
Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.NetworkCategory -ne "Private") {
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue
    }
}

Write-Step "Enabling File and Printer Sharing firewall rules"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Out-Null

Write-Step "Creating share folders"
foreach ($folder in @($BasePath, "$BasePath\Public", "$BasePath\Users")) {
    if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
}

Write-Step "Setting NTFS permissions (authenticated users only)"
icacls "$BasePath\Public" /inheritance:r /grant:r "Authenticated Users:(OI)(CI)RX" "Administrators:(OI)(CI)F" | Out-Null
icacls "$BasePath\Users"  /inheritance:r /grant:r "Users:(OI)(CI)M"                "Administrators:(OI)(CI)F" | Out-Null

Write-Step "Creating SMB shares"
foreach ($name in @("Public","Users")) {
    $existing = Get-SmbShare -Name $name -ErrorAction SilentlyContinue
    if ($existing) { Remove-SmbShare -Name $name -Force -ErrorAction SilentlyContinue }
}
New-SmbShare -Name "Public" -Path "$BasePath\Public" -ReadAccess  "Authenticated Users" -FullAccess "Administrators" -ErrorAction SilentlyContinue | Out-Null
New-SmbShare -Name "Users"  -Path "$BasePath\Users"  -ChangeAccess "Users"               -FullAccess "Administrators" -ErrorAction SilentlyContinue | Out-Null

Write-Step "Enforcing secure SMB settings (signing required, no null session)"
# Server-side: require signing, deny null sessions
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"                      -Name "RestrictAnonymous"     -Value 1 -Type DWord -Force

# Disable SMBv1 entirely (current best practice)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -ErrorAction SilentlyContinue

Write-Step "Seeding a small amount of realistic content"
Set-Content "$BasePath\Public\README.txt" @"
Public share. Read-only for authenticated users.
For team files, use the Users share.
"@ -Encoding UTF8

Write-Host ""
Write-Host "=== smb-baseline complete ==="
Write-Host "Shares    : Public (auth read), Users (auth RW)"
Write-Host "SMB1      : disabled"
Write-Host "Signing   : required"
Write-Host "Null sess : blocked"
