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
$script:SectionFailures = @()

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][Users] $Msg"
}

# ── Load deploy-context marker (written by Install-Services.ps1) ──
$ctxPath = "C:\ProgramData\MedAlliance\deploy-context.json"
if (Test-Path $ctxPath) {
    try {
        $ctx = Get-Content $ctxPath -Raw | ConvertFrom-Json
        $script:IsServer = [bool]$ctx.IsServer
        Write-Phase "Loaded deploy context: IsServer=$script:IsServer ($($ctx.OSCaption))"
    } catch {
        $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
    }
} else {
    $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
    Write-Phase "No deploy context marker — detected IsServer=$script:IsServer"
}

# ── Helper: create local user safely (idempotent) ──
# If the user already exists we update password + attributes instead of erroring.
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
    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue

    if ($existing) {
        Set-LocalUser -Name $Username -Password $secPass -FullName $FullName -Description $Description -ErrorAction SilentlyContinue
        if ($PasswordNeverExpires) {
            Set-LocalUser -Name $Username -PasswordNeverExpires $true -ErrorAction SilentlyContinue
        }
        Write-Phase "Updated existing user: $Username ($FullName)"
    } else {
        $params = @{
            Name        = $Username
            Password    = $secPass
            FullName    = $FullName
            Description = $Description
        }
        New-LocalUser @params -ErrorAction SilentlyContinue | Out-Null
        if ($PasswordNeverExpires) {
            Set-LocalUser -Name $Username -PasswordNeverExpires $true -ErrorAction SilentlyContinue
        }
        Write-Phase "Created user: $Username ($FullName)"
    }
}

# ── Helper: add to group only if not already a member ──
function Add-LabGroupMember {
    param([string]$Group, [string]$Member)
    try {
        $already = Get-LocalGroupMember -Group $Group -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like "*\$Member" -or $_.Name -eq $Member }
        if (-not $already) {
            Add-LocalGroupMember -Group $Group -Member $Member -ErrorAction SilentlyContinue
            Write-Phase "  Added $Member to '$Group'."
        } else {
            Write-Phase "  $Member already in '$Group'."
        }
    } catch {
        Write-Warning "  Could not add $Member to $Group : $_"
    }
}

# ═══════════════════════════════════════════════════════════════
#  1. SET ADMINISTRATOR PASSWORD
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Setting Administrator password..."

    $adminPass = ConvertTo-SecureString 'MedAll!ance#Adm1n2024' -AsPlainText -Force
    if (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name "Administrator" -Password $adminPass -PasswordNeverExpires $true -ErrorAction SilentlyContinue
    }
    # Not planted anywhere — students must escalate to find it
    # (or crack from SAM dump after getting SYSTEM)

    Write-Phase "Administrator password set (strong — not planted, must escalate)."
    Write-Phase "[Section] Administrator password completed."
} catch {
    Write-Warning "[Section] Administrator password failed: $_"
    $script:SectionFailures += 'AdminPassword'
}

# ═══════════════════════════════════════════════════════════════
#  2. CREATE m.chen — NETWORK ADMINISTRATOR
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating m.chen..."
    New-LabUser -Username "m.chen" `
        -Password "MedAlliance2024!" `
        -FullName "Marcus Chen" `
        -Description "IT Network Admin - MedAlliance Health" `
        -PasswordNeverExpires

    # Add to groups for RDP and WinRM access
    Add-LabGroupMember -Group "Remote Desktop Users"    -Member "m.chen"
    Add-LabGroupMember -Group "Remote Management Users" -Member "m.chen"
    # NOT in Administrators — this is a standard user (privesc required)

    Write-Phase "[Section] m.chen completed."
} catch {
    Write-Warning "[Section] m.chen failed: $_"
    $script:SectionFailures += 'm.chen'
}

# ═══════════════════════════════════════════════════════════════
#  3. CREATE MedHealthSvc — SERVICE ACCOUNT
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating MedHealthSvc service account..."
    New-LabUser -Username "MedHealthSvc" `
        -Password "H3althM0n!tor2024" `
        -FullName "Health Monitor Service" `
        -Description "MedAlliance Health Monitor service" `
        -PasswordNeverExpires -CannotChangePassword

    # SeImpersonatePrivilege is granted automatically when the service is created
    # in Plant-Vulns.ps1 (inherent to service accounts running as a service).

    Write-Phase "[Section] MedHealthSvc completed."
} catch {
    Write-Warning "[Section] MedHealthSvc failed: $_"
    $script:SectionFailures += 'MedHealthSvc'
}

# ═══════════════════════════════════════════════════════════════
#  4. ENABLE GUEST ACCOUNT (for SMB anonymous access)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Enabling Guest account for SMB share access..."

    net user Guest /active:yes 2>&1 | Out-Null

    # Allow network access for Guest (needed for "Everyone" SMB shares)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

    Write-Phase "Guest account enabled."
    Write-Phase "[Section] Guest completed."
} catch {
    Write-Warning "[Section] Guest failed: $_"
    $script:SectionFailures += 'Guest'
}

# ═══════════════════════════════════════════════════════════════
#  5. CONFIGURE SAVED CREDENTIALS (for privesc W-PRIV-04)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Planting saved credential (cmdkey)..."

    # Store a credential that m.chen can use via runas /savecred
    # This simulates someone having saved RDP creds to the server
    cmdkey /generic:MEDALLIANCE-WIN /user:Administrator /pass:MedAll!ance#Adm1n2024 2>&1 | Out-Null

    # cmdkey stores in the *current* user's vault. We also schedule a run-as-m.chen
    # task to plant it in m.chen's vault on first login.
    $labSetup = "C:\LabSetup"
    if (-not (Test-Path $labSetup)) {
        New-Item -Path $labSetup -ItemType Directory -Force | Out-Null
    }

    $plantCredScript = @"
cmdkey /generic:MEDALLIANCE-WIN /user:Administrator /pass:MedAll!ance#Adm1n2024
"@
    Set-Content -Path "$labSetup\plant_cred.bat" -Value $plantCredScript -Encoding ASCII -Force

    # Create a RunOnce task as m.chen to plant the saved cred on first login
    $action   = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\LabSetup\plant_cred.bat"
    $trigger  = New-ScheduledTaskTrigger -AtLogOn -User "m.chen"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    # Idempotency: remove any prior copy of the task before re-registering.
    Unregister-ScheduledTask -TaskName "PlantCred" -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask -TaskName "PlantCred" -Action $action -Trigger $trigger `
        -Settings $settings -User "m.chen" -Password "MedAlliance2024!" `
        -RunLevel Highest -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Phase "Saved credential will be planted on m.chen's first login."
    Write-Phase "[Section] Saved credential completed."
} catch {
    Write-Warning "[Section] Saved credential failed: $_"
    $script:SectionFailures += 'SavedCred'
}

Write-Phase "Users and groups fully configured."

# ═══════════════════════════════════════════════════════════════
#  6. CREATE USER PROFILE DIRECTORIES AND CONTENT
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating user profile content..."

    $mchenProfile = "C:\Users\m.chen"
    $mchenDesktop = "$mchenProfile\Desktop"
    $mchenDocs    = "$mchenProfile\Documents"
    if (-not (Test-Path $mchenDesktop)) { New-Item -Path $mchenDesktop -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $mchenDocs))    { New-Item -Path $mchenDocs    -ItemType Directory -Force | Out-Null }

    # Plant personal_notes.txt — load-bearing: content referenced in lab guides.
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
"@ | Set-Content -Path "$mchenDocs\personal_notes.txt" -Encoding UTF8 -Force

    # Grant m.chen ownership of their profile (best-effort)
    try {
        $acl  = Get-Acl $mchenProfile
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "m.chen", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl $mchenProfile $acl -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "  Could not set ACL on $mchenProfile : $_"
    }

    Write-Phase "User profile content planted."
    Write-Phase "[Section] Profile content completed."
} catch {
    Write-Warning "[Section] Profile content failed: $_"
    $script:SectionFailures += 'ProfileContent'
}

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
if ($script:SectionFailures.Count -eq 0) {
    Write-Phase "Configure-Users completed successfully."
    exit 0
} else {
    Write-Warning "Completed with failures in: $($script:SectionFailures -join ', ')"
    exit 1
}
