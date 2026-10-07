$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-LocalUser {
    param([string]$Username, [string]$Password, [switch]$AddToAdministrators)
    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Step "Creating local user $Username"
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Username -Password $secure -FullName $Username -Description "Lab account $Username" -PasswordNeverExpires -AccountNeverExpires | Out-Null
    } else {
        Write-Step "User $Username already exists"
    }
    if ($AddToAdministrators) {
        $isMember = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\\$Username$" }
        if (-not $isMember) {
            Write-Step "Adding $Username to Administrators"
            Add-LocalGroupMember -Group "Administrators" -Member $Username
        }
    }
}

function Write-TextFile {
    param([string]$Path, [string]$Content)
    $parent = Split-Path $Path -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Set-Content -Path $Path -Value $Content -Encoding UTF8
}

# Create users
Ensure-LocalUser -Username "USER2" -Password "User2Pass123!"
Ensure-LocalUser -Username "ADMIN" -Password "AdminPass123!" -AddToAdministrators

# Create profile folders
Write-Step "Creating profile folders"
foreach ($u in @("USER2","ADMIN")) {
    foreach ($folder in @("C:\Users\$u", "C:\Users\$u\Desktop", "C:\Users\$u\Documents", "C:\Users\$u\Documents\scripts", "C:\Users\$u\Downloads")) {
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    }
}

foreach ($folder in @("C:\LabShare", "C:\LabShare\Public", "C:\LabShare\Legacy", "C:\ProgramData\Ops")) {
    if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
}

# Seed USER2 artifacts
Write-Step "Seeding USER2 artifacts"
Write-TextFile -Path "C:\Users\USER2\Documents\vpn_notes.txt" -Content @"
VPN Notes
Primary concentrator: vpn-gw01
Fallback concentrator: vpn-gw02
Split tunnel exceptions requested for: 10.20.14.0/24, 10.30.5.0/24
Need to verify whether old inventory portal is still reachable internally.
"@

Write-TextFile -Path "C:\Users\USER2\Documents\hosts_to_check.txt" -Content @"
Hosts to check
10.20.14.15    filesrv-old
10.20.14.22    print-core
10.30.5.18     backup-util
10.30.5.41     web-training
"@

Write-TextFile -Path "C:\Users\USER2\Desktop\Q1-Inventory.csv" -Content @"
Hostname,Role,Owner,Status
WIN11LAB-EDGE,Training Workstation,IT Ops,Active
filesrv-old,Legacy File Server,Infrastructure,Pending Migration
backup-util,Backup Utility Host,Ops,Review
web-training,Training Web Node,Security,Active
"@

# Seed ADMIN artifacts
Write-Step "Seeding ADMIN artifacts"
Write-TextFile -Path "C:\Users\ADMIN\Desktop\Maintenance Notes.txt" -Content @"
Maintenance Notes
- Legacy training apps moved to local bootstrap script.
- Backup utility review still pending.
- Remove temporary exceptions after migration window closes.
- Confirm old deployment batch files no longer used by support.
- Revisit local admin assignments on training systems.
"@

Write-TextFile -Path "C:\Users\ADMIN\Documents\scripts\restart-services.ps1" -Content @'
$services = @("W3SVC","WinRM","sshd")
foreach ($svc in $services) {
    try { Restart-Service -Name $svc -Force -ErrorAction Stop } catch { Write-Host "Failed to restart $svc" }
}
'@

# Seed shared artifacts
Write-Step "Seeding shared artifacts"
Write-TextFile -Path "C:\ProgramData\Ops\migration_todo.txt" -Content @"
Migration TODO
- Validate training app startup after reboot.
- Review old support scripts in LabShare\Legacy.
- Confirm backup utility host list is still accurate.
- Remove leftover temporary admin changes after QA signoff.
"@

# Set basic ownership
try { icacls "C:\Users\USER2" /grant "USER2:(OI)(CI)F" /T | Out-Null } catch {}
try { icacls "C:\Users\ADMIN" /grant "ADMIN:(OI)(CI)F" /T | Out-Null } catch {}

Write-Host ""
Write-Host "=== Life Artifacts Complete ==="
Write-Host "Users: USER2 (standard), ADMIN (local administrator)"
Write-Host "Artifacts seeded in: C:\Users\USER2, C:\Users\ADMIN, C:\LabShare, C:\ProgramData\Ops"
