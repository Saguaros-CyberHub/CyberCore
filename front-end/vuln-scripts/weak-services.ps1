$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Create a service with weak permissions (privesc vector)
Write-Step "Creating vulnerable service: LabUpdateSvc"

$svcPath = "C:\LabApps\LabUpdateService"
if (-not (Test-Path $svcPath)) { New-Item -ItemType Directory -Path $svcPath -Force | Out-Null }

# Create a dummy service binary
Set-Content "$svcPath\updater.bat" @"
@echo off
:loop
timeout /t 60 /nobreak >nul
goto loop
"@ -Encoding ASCII

# Create the service with an unquoted path (classic privesc)
$unquotedPath = "C:\Program Files\Lab Update Service\updater.bat"
$unquotedDir = "C:\Program Files\Lab Update Service"
if (-not (Test-Path $unquotedDir)) { New-Item -ItemType Directory -Path $unquotedDir -Force | Out-Null }
Copy-Item "$svcPath\updater.bat" "$unquotedDir\updater.bat" -Force

# Create the service (unquoted path weakness)
Write-Step "Creating service with unquoted path"
try {
    sc.exe create LabUpdateSvc binPath= "C:\Program Files\Lab Update Service\updater.bat" start= auto DisplayName= "Lab Update Service" | Out-Null
} catch {}

# Set weak DACL on the service binary (Users can modify)
Write-Step "Setting weak permissions on service binary"
icacls "$unquotedDir\updater.bat" /grant "Users:(F)" | Out-Null
icacls "$unquotedDir" /grant "Users:(OI)(CI)(M)" | Out-Null

# Create a writable scheduled task (another privesc vector)
Write-Step "Creating scheduled task with weak permissions"

$taskScript = "C:\ProgramData\Maintenance\daily-cleanup.ps1"
$taskDir = Split-Path $taskScript -Parent
if (-not (Test-Path $taskDir)) { New-Item -ItemType Directory -Path $taskDir -Force | Out-Null }

Set-Content $taskScript @'
# Daily cleanup script
Get-ChildItem "C:\Windows\Temp\*" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
'@ -Encoding UTF8

# Make the script writable by Users (weakness)
icacls $taskScript /grant "Users:(F)" | Out-Null
icacls $taskDir /grant "Users:(OI)(CI)(M)" | Out-Null

# Register the scheduled task running as SYSTEM
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScript`""
$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "DailyMaintenance" -Action $action -Trigger $trigger -Principal $principal -Description "Daily system cleanup" -Force | Out-Null

# Create a service running as LocalSystem with weak registry permissions
Write-Step "Creating service with weak registry ACL"
try {
    sc.exe create LabMonitorSvc binPath= "C:\Windows\System32\cmd.exe /c timeout /t 999999" start= demand DisplayName= "Lab Monitor Service" | Out-Null
    # Set weak registry permissions on the service key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LabMonitorSvc"
    if (Test-Path $regPath) {
        $acl = Get-Acl $regPath
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl $regPath $acl
    }
} catch {}

Write-Host ""
Write-Host "=== Weak Services Setup Complete ==="
Write-Host "Vulnerabilities:"
Write-Host "  1. LabUpdateSvc: unquoted service path + writable binary"
Write-Host "  2. DailyMaintenance: scheduled task runs as SYSTEM, script writable by Users"
Write-Host "  3. LabMonitorSvc: service registry key writable by Users"
