<#
.SYNOPSIS
    Creates local user accounts and group memberships for MedAlliance-WIN T1.

.NOTES
    Users:
      m.chen         — standard user, RDP + WinRM access, primary student target
      MedHealthSvc   — service account for the Health Monitor service
      Administrator  — built-in, strong-ish password (accessed via privesc only)

    The m.chen password matches credentials planted on the Linux target's
    /root/.admin_creds.txt — this is the credential-reuse bridge.
#>

$ErrorActionPreference = "Continue"

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][Users] $Msg"
}

# ── Helper: create local user safely ──
function New-LabUser {
    param(
        [string]$Username,
        [string]$Password,
        [string]$FullName,
        [string]$Description,
        [switch]$PasswordNeverExpires,
        [switch]$CannotChangePassword
    )

    $secPass = ConvertTo-SecureString $Password -AsPlainText -Force

    # Remove existing user if present (idempotency)
    Remove-LocalUser -Name $Username -ErrorAction SilentlyContinue

    $params = @{
        Name        = $Username
        Password    = $secPass
        FullName    = $FullName
        Description = $Description
    }

    New-LocalUser @params -ErrorAction Stop
    if ($PasswordNeverExpires) {
        Set-LocalUser -Name $Username -PasswordNeverExpires $true
    }

    Write-Phase "Created user: $Username ($FullName)"
}

# ═══════════════════════════════════════════════════════════════
#  1. SET ADMINISTRATOR PASSWORD
# ═══════════════════════════════════════════════════════════════
Write-Phase "Setting Administrator password..."

$adminPass = ConvertTo-SecureString 'MedAll!ance#Adm1n2024' -AsPlainText -Force
Set-LocalUser -Name "Administrator" -Password $adminPass -PasswordNeverExpires $true
# This password is NOT planted anywhere — students must escalate to find it
# (or crack it from SAM dump after getting SYSTEM)

Write-Phase "Administrator password set (strong — not planted, must escalate)."

# ═══════════════════════════════════════════════════════════════
#  2. CREATE m.chen — NETWORK ADMINISTRATOR
# ═══════════════════════════════════════════════════════════════
New-LabUser -Username "m.chen" `
    -Password "MedAlliance2024!" `
    -FullName "Marcus Chen" `
    -Description "IT Network Administrator — MedAlliance Health Partners" `
    -PasswordNeverExpires

# Add to groups for RDP and WinRM access
Add-LocalGroupMember -Group "Remote Desktop Users"     -Member "m.chen" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Remote Management Users"  -Member "m.chen" -ErrorAction SilentlyContinue
# NOT in Administrators — this is a standard user (privesc required)

Write-Phase "m.chen added to Remote Desktop Users + Remote Management Users."

# ═══════════════════════════════════════════════════════════════
#  3. CREATE MedHealthSvc — SERVICE ACCOUNT
# ═══════════════════════════════════════════════════════════════
New-LabUser -Username "MedHealthSvc" `
    -Password "H3althM0n!tor2024" `
    -FullName "Health Monitor Service" `
    -Description "Service account for MedAlliance Health Monitor agent" `
    -PasswordNeverExpires -CannotChangePassword

# Grant SeImpersonatePrivilege (inherent to service accounts running services)
# This gets set properly when the service is created in Plant-Vulns.ps1

Write-Phase "MedHealthSvc service account created."

# ═══════════════════════════════════════════════════════════════
#  4. ENABLE GUEST ACCOUNT (for SMB anonymous access)
# ═══════════════════════════════════════════════════════════════
Write-Phase "Enabling Guest account for SMB share access..."

# Enable Guest
net user Guest /active:yes 2>&1 | Out-Null

# Allow network access for Guest (needed for "Everyone" SMB shares)
# Disable the policy that blocks guest access to SMB
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Set-ItemProperty -Path $regPath -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord -ErrorAction SilentlyContinue

Write-Phase "Guest account enabled."

# ═══════════════════════════════════════════════════════════════
#  5. CONFIGURE SAVED CREDENTIALS (for privesc W-PRIV-04)
# ═══════════════════════════════════════════════════════════════
Write-Phase "Planting saved credential (cmdkey)..."

# Store a credential that m.chen can use via runas /savecred
# This simulates someone having saved RDP creds to the server
cmdkey /generic:MEDALLIANCE-WIN /user:Administrator /pass:MedAll!ance#Adm1n2024 2>&1 | Out-Null

# Note: cmdkey stores in the current user's credential manager.
# We need to run this as m.chen for it to be in m.chen's vault.
# Since we're running as SYSTEM/admin during deployment, we'll create
# a scheduled task that runs once as m.chen to plant the credential.

$plantCredScript = @"
cmdkey /generic:MEDALLIANCE-WIN /user:Administrator /pass:MedAll!ance#Adm1n2024
"@
Set-Content -Path "C:\LabSetup\plant_cred.bat" -Value $plantCredScript -Encoding ASCII

# Create a RunOnce task as m.chen to plant the saved cred on first login
$action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\LabSetup\plant_cred.bat"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "m.chen"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "PlantCred" -Action $action -Trigger $trigger `
    -Settings $settings -User "m.chen" -Password "MedAlliance2024!" `
    -RunLevel Highest -Force -ErrorAction SilentlyContinue

Write-Phase "Saved credential will be planted on m.chen's first login."

# Also plant it in the default user profile's credential store via registry
# (backup method in case login-trigger doesn't fire)
Write-Phase "Users and groups fully configured."

# ═══════════════════════════════════════════════════════════════
#  6. CREATE USER PROFILE DIRECTORIES AND CONTENT
# ═══════════════════════════════════════════════════════════════
Write-Phase "Creating user profile content..."

# Ensure m.chen's profile directory exists
$mchenProfile = "C:\Users\m.chen"
$mchenDesktop = "$mchenProfile\Desktop"
$mchenDocs    = "$mchenProfile\Documents"
New-Item -Path $mchenDesktop -ItemType Directory -Force | Out-Null
New-Item -Path $mchenDocs    -ItemType Directory -Force | Out-Null

# Plant personal files in m.chen's Documents
@"
MedAlliance Health Partners — Personal Notes
=============================================
Marcus Chen — Network Administrator

Todo:
- [ ] Rotate SQL SA password (it's been the same for 8 months... yikes)
- [ ] Disable xp_cmdshell on SQLEXPRESS (why was this ever enabled??)
- [ ] Fix the Health Monitor service — it keeps running as SYSTEM
- [ ] Talk to j.thompson about the Linux server backups
- [ ] Check if the daily_report.bat script is still world-writable
- [x] Set up RDP access for the new hires
- [x] Configure WinRM for remote management

Passwords I need to remember:
- My Windows login: MedAlliance2024! (same across all systems... I know, I know)
- SQL SA: SQLAdmin2024!
- Health Monitor dashboard: admin/admin (need to change this)
- Linux SSH: j.thompson / Fall2024Med!

Note to self: Stop reusing passwords across systems. Set up a password
manager for the team before the next audit.

Last updated: 2024-11-10
"@ | Set-Content -Path "$mchenDocs\personal_notes.txt" -Encoding UTF8

# Grant m.chen ownership of their profile
$acl = Get-Acl $mchenProfile
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "m.chen", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $mchenProfile $acl -ErrorAction SilentlyContinue

Write-Phase "User profile content planted."
