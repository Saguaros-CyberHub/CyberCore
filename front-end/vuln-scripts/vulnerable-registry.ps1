$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- AlwaysInstallElevated (classic MSI-based privesc) ---
Write-Step "Setting AlwaysInstallElevated in HKLM and HKCU"
$paths = @(
    "HKLM:\Software\Policies\Microsoft\Windows\Installer",
    "HKCU:\Software\Policies\Microsoft\Windows\Installer"
)
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name "AlwaysInstallElevated" -PropertyType DWord -Value 1 -Force | Out-Null
}

# --- Auto-logon (plaintext credentials in the registry) ---
Write-Step "Configuring AutoAdminLogon with plaintext credentials"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
New-ItemProperty -Path $winlogon -Name "AutoAdminLogon"    -PropertyType String -Value "1"                  -Force | Out-Null
New-ItemProperty -Path $winlogon -Name "DefaultUserName"   -PropertyType String -Value "Administrator"       -Force | Out-Null
New-ItemProperty -Path $winlogon -Name "DefaultPassword"   -PropertyType String -Value "Autumn2024!Admin"   -Force | Out-Null
New-ItemProperty -Path $winlogon -Name "DefaultDomainName" -PropertyType String -Value $env:COMPUTERNAME     -Force | Out-Null

# --- Writable autorun key for low-priv users (Users can drop a payload) ---
Write-Step "Weakening ACL on HKLM Run key (Users:Write)"
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
try {
    $acl = Get-Acl $runKey
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Users","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $runKey -AclObject $acl
} catch { Write-Host "ACL tweak on Run key failed: $($_.Exception.Message)" }

# --- UAC bypass aids: disable prompt for admins, disable secure desktop ---
Write-Step "Weakening UAC (ConsentPromptBehaviorAdmin=0, PromptOnSecureDesktop=0)"
$sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
New-ItemProperty -Path $sys -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $sys -Name "PromptOnSecureDesktop"      -PropertyType DWord -Value 0 -Force | Out-Null
# EnableLUA stays at 1 so the box still looks "UAC-enabled" in a cursory check, but prompts are silent for admins.

# --- Cached interactive logons (DCC2 hashes extractable offline) ---
Write-Step "Setting CachedLogonsCount=25 (leaves more DCC2 hashes on disk)"
New-ItemProperty -Path $winlogon -Name "CachedLogonsCount" -PropertyType String -Value "25" -Force | Out-Null

Write-Host ""
Write-Host "=== vulnerable-registry complete ==="
Write-Host "AlwaysInstallElevated : 1 (both hives)"
Write-Host "AutoAdminLogon        : plaintext creds stored"
Write-Host "UAC prompts           : silent for admins"
Write-Host "Run key ACL           : Users:Write"
