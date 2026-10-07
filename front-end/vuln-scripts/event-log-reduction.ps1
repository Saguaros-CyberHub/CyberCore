$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- Shrink log file sizes so rotation destroys forensic evidence quickly ---
Write-Step "Shrinking Application/Security/System logs to 1MB each"
foreach ($log in @("Application","Security","System","Setup")) {
    try {
        wevtutil sl $log /ms:1048576 /rt:false /ab:false 2>$null
    } catch {}
}

# --- Disable PowerShell script-block + module logging (evasion) ---
Write-Step "Disabling PowerShell module + script-block logging"
$psLog = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
if (-not (Test-Path $psLog))                         { New-Item -Path $psLog -Force | Out-Null }
if (-not (Test-Path "$psLog\ScriptBlockLogging"))    { New-Item -Path "$psLog\ScriptBlockLogging" -Force | Out-Null }
if (-not (Test-Path "$psLog\ModuleLogging"))         { New-Item -Path "$psLog\ModuleLogging"      -Force | Out-Null }
New-ItemProperty -Path "$psLog\ScriptBlockLogging" -Name "EnableScriptBlockLogging"              -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path "$psLog\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging"    -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path "$psLog\ModuleLogging"      -Name "EnableModuleLogging"                   -PropertyType DWord -Value 0 -Force | Out-Null

# --- Disable command-line process auditing ---
Write-Step "Disabling 4688 command-line auditing"
$cmdAudit = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $cmdAudit)) { New-Item -Path $cmdAudit -Force | Out-Null }
New-ItemProperty -Path $cmdAudit -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 0 -Force | Out-Null

# --- Clear existing logs so students start with nothing to pivot off of ---
Write-Step "Clearing existing logs (Application/Security/System/Windows PowerShell)"
foreach ($log in @("Application","Security","System","Windows PowerShell")) {
    try { wevtutil cl $log 2>$null } catch {}
}

# --- Disable Sysmon if present (service name may or may not exist) ---
$sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($sysmon) {
    Write-Step "Disabling Sysmon service"
    foreach ($s in $sysmon) { Stop-Service $s -Force -ErrorAction SilentlyContinue; Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host "=== event-log-reduction complete ==="
Write-Host "Log sizes         : 1MB each (rotation destroys ~30s of activity)"
Write-Host "Script-block log  : disabled"
Write-Host "Module log        : disabled"
Write-Host "4688 cmdline      : disabled"
Write-Host "Existing logs     : cleared"
