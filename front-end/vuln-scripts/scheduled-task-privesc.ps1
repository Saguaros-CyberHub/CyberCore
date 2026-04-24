$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- 1. A SYSTEM task whose XML definition is Users-writable ---
Write-Step "Creating SYSTEM task 'LabHealthCheck' with a writable task XML"
$taskFolder = "C:\ProgramData\LabOps"
if (-not (Test-Path $taskFolder)) { New-Item -ItemType Directory -Path $taskFolder -Force | Out-Null }

$healthScript = "$taskFolder\health-check.ps1"
Set-Content $healthScript @'
# Hourly health check - just pings internal services
Test-NetConnection -ComputerName 127.0.0.1 -Port 80 -InformationLevel Quiet | Out-Null
Write-Output "[$(Get-Date)] health check ok"
'@ -Encoding UTF8

# Make the SCRIPT writable by Users - classic privesc: replace contents, wait for next tick
icacls $healthScript /grant "Users:(F)" | Out-Null

$action    = New-ScheduledTaskAction    -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$healthScript`""
$trigger   = New-ScheduledTaskTrigger   -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "LabHealthCheck" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

# --- 2. A Users task that calls into C:\ProgramData\Deploy\deploy.bat (also Users-writable) ---
Write-Step "Creating interactive-user task 'LabDeploy' with Users-writable .bat"
$deployDir = "C:\ProgramData\Deploy"
if (-not (Test-Path $deployDir)) { New-Item -ItemType Directory -Path $deployDir -Force | Out-Null }
Set-Content "$deployDir\deploy.bat" "@echo off`r`necho Deploy stub.`r`nexit /b 0" -Encoding ASCII
icacls "$deployDir"            /grant "Users:(OI)(CI)M" | Out-Null
icacls "$deployDir\deploy.bat" /grant "Users:(F)"       | Out-Null

$dpAction  = New-ScheduledTaskAction -Execute "$deployDir\deploy.bat"
$dpTrigger = New-ScheduledTaskTrigger -AtLogOn
$dpPrinc   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "LabDeploy" -Action $dpAction -Trigger $dpTrigger -Principal $dpPrinc -Force | Out-Null

# --- 3. Ensure Users can list and read task definitions (so enumeration works) ---
Write-Step "Granting Users read on Tasks folder"
icacls "C:\Windows\System32\Tasks" /grant "Users:(OI)(CI)R" /T 2>$null | Out-Null

Write-Host ""
Write-Host "=== scheduled-task-privesc complete ==="
Write-Host "Task: LabHealthCheck (SYSTEM, every 15m)  -> $healthScript (Users:F)"
Write-Host "Task: LabDeploy      (SYSTEM, at logon)   -> $deployDir\deploy.bat (Users:F)"
