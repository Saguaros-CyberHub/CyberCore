$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Run Key persistence (HKCU)
Write-Step "Adding Run key persistence (HKCU)"
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $runKeyPath -Name "DunderCorpSync" -Value "powershell.exe -WindowStyle Hidden -Command Start-Sleep 1" -PropertyType String -Force | Out-Null

# Run Key persistence (HKLM - machine level)
Write-Step "Adding Run key persistence (HKLM)"
$runKeyLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $runKeyLM -Name "LabHealthCheck" -Value "C:\ProgramData\Maintenance\health-check.bat" -PropertyType String -Force | Out-Null

# Create the health-check script
$hcDir = "C:\ProgramData\Maintenance"
if (-not (Test-Path $hcDir)) { New-Item -ItemType Directory -Path $hcDir -Force | Out-Null }
Set-Content "$hcDir\health-check.bat" @"
@echo off
REM Lab health check - runs at logon
echo Health check ran at %date% %time% >> C:\ProgramData\Maintenance\health.log
"@ -Encoding ASCII

# Startup folder persistence
Write-Step "Adding Startup folder persistence"
$startupAll = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
Set-Content "$startupAll\sync-agent.bat" @"
@echo off
REM DunderCorp sync agent - persists via Startup folder
echo Sync agent started at %date% %time% >> C:\ProgramData\Maintenance\sync.log
"@ -Encoding ASCII

# Scheduled task persistence (different from weak-services - this one is stealthy)
Write-Step "Adding scheduled task persistence"
$persistScript = "C:\Windows\Temp\telemetry-update.ps1"
Set-Content $persistScript @'
# Telemetry update collector
$logPath = "C:\ProgramData\Maintenance\telemetry.log"
Add-Content $logPath "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Telemetry collected"
'@ -Encoding UTF8

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$persistScript`""
$trigger = New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "WindowsTelemetryUpdate" -Action $action -Trigger $trigger -Settings $settings -Description "Windows Telemetry Update Service" -Force | Out-Null

# WMI event subscription (advanced persistence)
Write-Step "Adding WMI event subscription persistence"
try {
    $filterName = "LabWMIFilter"
    $consumerName = "LabWMIConsumer"

    # Create event filter (triggers every 300 seconds)
    $filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
        Name = $filterName
        EventNamespace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    }

    # Create event consumer
    $consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
        Name = $consumerName
        CommandLineTemplate = "cmd.exe /c echo WMI persistence active >> C:\ProgramData\Maintenance\wmi.log"
    }

    # Bind them
    Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
        Filter = $filter
        Consumer = $consumer
    } | Out-Null

    Write-Host "  WMI persistence installed"
} catch {
    Write-Host "  WMI persistence skipped: $_"
}

Write-Host ""
Write-Host "=== Persistence Mechanisms Complete ==="
Write-Host "Installed:"
Write-Host "  1. HKCU Run key: DunderCorpSync"
Write-Host "  2. HKLM Run key: LabHealthCheck"
Write-Host "  3. Startup folder: sync-agent.bat"
Write-Host "  4. Scheduled task: WindowsTelemetryUpdate (at logon, hidden)"
Write-Host "  5. WMI event subscription: LabWMIFilter/LabWMIConsumer"
