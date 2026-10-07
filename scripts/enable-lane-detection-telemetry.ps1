#requires -Version 5.1
<#
.SYNOPSIS
Enable detection telemetry on ONE running Windows lab-lane host.
.DESCRIPTION
Run in 64-bit Windows PowerShell as Administrator on each lane Windows host,
including every domain controller. Copy/paste the whole file, or save and run:
  .\enable-lane-detection-telemetry.ps1
Inspect without changing policies or creating backups:
  .\enable-lane-detection-telemetry.ps1 -CheckOnly

This is an optional lab preparation step, not a golden-image or domain GPO
change. Existing Winlogbeat/Sysmon configuration and service state are preserved.
Windows PowerShell 5.x logging is configured; PowerShell Core needs its own
channel and collector configuration. Run after any event-log-reduction exercise.
New PowerShell sessions pick up script-block logging. An advanced audit GPO can
override these local settings later; use CheckOnly again after policy refresh.

Backups include the prior audit policy, just the registry values touched here,
event-channel settings and a rollback script. Rollback restores the COMPLETE
audit policy snapshot, so use it before making other audit-policy changes.
Script blocks and process command lines become readable by log readers.

Sources for GUIDs, policy behavior and PowerShell logging:
https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [string]$BackupRoot = (Join-Path $env:ProgramData 'CyberCore\telemetry-backups')
)

$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell for this script.' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator on the lane Windows host.'
}

function Invoke-LaneAudit {
    param([string[]]$Arguments)
    $result = & "$env:SystemRoot\System32\auditpol.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed: $($result -join ' ')" }
    $result
}

function Get-LaneRegistryState {
    param([string]$Path, [string]$Name)
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $exists = $null -ne $key -and $key.GetValueNames() -contains $Name
    [pscustomobject]@{
        Path = $Path; Name = $Name; Exists = $exists
        Value = $(if ($exists) { $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') } else { $null })
        Kind = $(if ($exists) { $key.GetValueKind($Name).ToString() } else { 'DWord' })
    }
}

$domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDomainController = $domainRole -in @(4, 5)
# Success-only entries leave existing failure auditing unchanged.
$auditPolicies = @(
    @{ Name = 'Process Creation'; Id = '0cce922b'; Failure = $false },
    @{ Name = 'Logon'; Id = '0cce9215'; Failure = $true },
    @{ Name = 'Special Logon'; Id = '0cce921b'; Failure = $false },
    @{ Name = 'Account Lockout'; Id = '0cce9217'; Failure = $true },
    @{ Name = 'Credential Validation'; Id = '0cce923f'; Failure = $true },
    @{ Name = 'User Account Management'; Id = '0cce9235'; Failure = $true },
    @{ Name = 'Security Group Management'; Id = '0cce9237'; Failure = $false },
    @{ Name = 'Security System Extension (services)'; Id = '0cce9211'; Failure = $false },
    @{ Name = 'Other Object Access (scheduled tasks)'; Id = '0cce9227'; Failure = $false },
    @{ Name = 'Audit Policy Change'; Id = '0cce922f'; Failure = $true }
)
if ($isDomainController) {
    $auditPolicies += @(
        @{ Name = 'Kerberos Service Ticket Operations'; Id = '0cce9240'; Failure = $true },
        @{ Name = 'Kerberos Authentication Service'; Id = '0cce9242'; Failure = $true }
    )
}
$registryPolicies = @(
    @{ Path = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging' },
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy' }
)
$channelTargets = @(
    @{ Name = 'Security'; MinimumBytes = 128MB },
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; MinimumBytes = 64MB },
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; MinimumBytes = 64MB }
)
$channels = @()
foreach ($target in $channelTargets) {
    $channel = Get-WinEvent -ListLog $target.Name -ErrorAction SilentlyContinue
    if ($channel) {
        $channels += [pscustomobject]@{
            Name = $target.Name; Enabled = $channel.IsEnabled
            MaximumSizeInBytes = $channel.MaximumSizeInBytes
            MinimumBytes = $target.MinimumBytes
        }
    } elseif ($target.Name -eq 'Microsoft-Windows-Sysmon/Operational') {
        Write-Warning 'Sysmon channel is missing. Install the existing goad-elk-agent on this lane host.'
    } else {
        throw "Required Windows event channel is unavailable: $($target.Name)"
    }
}

if (-not $CheckOnly) {
    $backupDir = Join-Path $BackupRoot ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Invoke-LaneAudit @('/backup', "/file:$(Join-Path $backupDir 'audit-policy.csv')") | Out-Null
    $auditBackup = Get-Item -LiteralPath (Join-Path $backupDir 'audit-policy.csv')
    if ($auditBackup.Length -eq 0) { throw 'Audit backup is empty; no telemetry settings were changed.' }
    $snapshot = [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
        Registry = @($registryPolicies | ForEach-Object { Get-LaneRegistryState $_.Path $_.Name })
        Channels = $channels
    }
    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $backupDir 'before.json') -Encoding UTF8
    # A standalone rollback keeps copy/paste installs reversible too. No log data
    # or registry trees are deleted; only the exact values changed are restored.
    @'
#requires -Version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
$state = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'before.json') -Raw | ConvertFrom-Json
if ($state.ComputerName -ne $env:COMPUTERNAME) { throw 'This backup belongs to another computer.' }
foreach ($entry in $state.Registry) {
    if ($entry.Exists) {
        if (-not (Test-Path -LiteralPath $entry.Path)) { New-Item -Path $entry.Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.Value -PropertyType $entry.Kind -Force | Out-Null
    } elseif (Test-Path -LiteralPath $entry.Path) {
        Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
    }
}
foreach ($entry in $state.Channels) {
    $log = Get-WinEvent -ListLog $entry.Name
    if ($entry.Name -ne 'Security') { $log.IsEnabled = [bool]$entry.Enabled }
    $log.MaximumSizeInBytes = [long]$entry.MaximumSizeInBytes
    $log.SaveChanges()
}
& "$env:SystemRoot\System32\auditpol.exe" /restore "/file:$(Join-Path $PSScriptRoot 'audit-policy.csv')"
if ($LASTEXITCODE -ne 0) { throw 'Audit policy restore failed.' }
Write-Host 'Prior local telemetry policies restored. Start new PowerShell sessions to pick up the change.'
'@ | Set-Content -LiteralPath (Join-Path $backupDir 'rollback.ps1') -Encoding UTF8
    Write-Host "Backup and rollback: $backupDir"

    # Every backup must succeed before the first policy mutation.
    foreach ($policy in $registryPolicies) {
        if (-not (Test-Path -LiteralPath $policy.Path)) { New-Item -Path $policy.Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -Value 1 -PropertyType DWord -Force | Out-Null
    }
    foreach ($policy in $auditPolicies) {
        $arguments = @('/set', "/subcategory:{$($policy.Id)-69ae-11d9-bed3-505054503030}", '/success:enable')
        if ($policy.Failure) { $arguments += '/failure:enable' }
        Invoke-LaneAudit $arguments | Out-Null
    }
    foreach ($entry in $channels) {
        $log = Get-WinEvent -ListLog $entry.Name
        if ($entry.Name -ne 'Security') { $log.IsEnabled = $true }
        if ($log.MaximumSizeInBytes -lt $entry.MinimumBytes) { $log.MaximumSizeInBytes = $entry.MinimumBytes }
        $log.SaveChanges()
    }
}

Write-Host "Host: $env:COMPUTERNAME; domain controller: $isDomainController"
foreach ($policy in $registryPolicies) {
    $state = Get-LaneRegistryState $policy.Path $policy.Name
    $value = if ($state.Exists) { $state.Value } else { '(not configured)' }
    Write-Host "$($policy.Name): $value"
    if ($value -ne 1) { Write-Warning "$($policy.Name) must be 1 for the intended telemetry." }
}
foreach ($policy in $auditPolicies) {
    Write-Host "Audit: $($policy.Name)"
    Invoke-LaneAudit @('/get', "/subcategory:{$($policy.Id)-69ae-11d9-bed3-505054503030}") | Write-Host
}
foreach ($entry in $channels) {
    $log = Get-WinEvent -ListLog $entry.Name
    Write-Host "$($entry.Name): enabled=$($log.IsEnabled), capacity=$($log.MaximumSizeInBytes) bytes"
}
foreach ($serviceName in @('winlogbeat', 'Sysmon64')) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne 'Running') {
        Write-Warning "$serviceName is missing or stopped. Events will not have the full expected collection path."
    } else { Write-Host "$serviceName service: Running" }
}
foreach ($probe in @(
    @{ LogName = 'Security'; Id = 4688 },
    @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 },
    @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 }
)) {
    # Only timestamps are printed; event bodies may contain exercise credentials.
    $event = Get-WinEvent -FilterHashtable $probe -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "$($probe.LogName) / $($probe.Id): newest local event $($event.TimeCreated.ToUniversalTime().ToString('o'))"
    } else {
        Write-Warning "$($probe.LogName) / $($probe.Id): no local sample yet; run new activity and check again."
    }
}
Write-Host 'Winlogbeat/Sysmon configuration was preserved. Confirm fresh events in Kibana after a new exercise.'
Write-Host 'The bundled SwiftOnSecurity policy does not log Sysmon ProcessAccess (10), ImageLoad (7) or pipes (17/18).'
Write-Host 'For those detections, explicitly extend your Sysmon policy and apply it with Sysmon64.exe -c <config.xml>.'
Write-Host 'Directory-service access (4662), file access (4663), and detailed SMB (5145) are not enabled by this script.'
Write-Host 'Windows PowerShell 5.x: launch a fresh session after setup; no reboot is required.'
if (-not $CheckOnly) {
    Write-Host "To roll back before further policy changes: & '$backupDir\rollback.ps1'"
}
