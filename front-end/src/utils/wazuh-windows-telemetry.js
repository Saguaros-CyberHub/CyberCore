'use strict';

// Microsoft-supported sources and installation paths:
// https://learn.microsoft.com/windows/security/operating-system-security/sysmon/how-to-enable-sysmon
// https://learn.microsoft.com/sysinternals/downloads/sysmon
// https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
// https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/win-defender-logs-collection.html
// Enrollment credentials must already have been moved out of executable script
// text and process arguments before these functions are used. Nothing below
// disables an existing logger, Defender policy, or security product.
const SYSMON_PROFILE_XML = `<Sysmon schemaversion="4.82">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <DnsLookup>false</DnsLookup>
  <EventFiltering>
    <RuleGroup name="CyberCore basic endpoint activity" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
      <NetworkConnect onmatch="exclude" />
      <DnsQuery onmatch="exclude" />
      <ImageLoad onmatch="include" />
      <ProcessAccess onmatch="include" />
      <FileCreate onmatch="include" />
      <FileDelete onmatch="include" />
      <ClipboardChange onmatch="include" />
    </RuleGroup>
  </EventFiltering>
</Sysmon>`;

const TELEMETRY_CHANNELS = Object.freeze({
  sysmon: 'Microsoft-Windows-Sysmon/Operational',
  powershell: 'Microsoft-Windows-PowerShell/Operational',
  powershellCore: 'PowerShellCore/Operational',
  defender: 'Microsoft-Windows-Windows Defender/Operational',
});
const TELEMETRY_WARNINGS = Object.freeze({
  'sysmon-existing-profile': 'Existing Sysmon configuration was preserved; its event coverage may differ from the CyberCore profile.',
  'sysmon-setup-failed': 'Sysmon setup could not be completed. Existing installations were preserved; review its service, optional feature, download access and publisher signature.',
  'powershell-setup-failed': 'Windows PowerShell script-block logging or its event channel could not be enabled.',
  'powershell-core-unavailable': 'PowerShell 7 event channel is unavailable; if PowerShell 7 is installed, register its event manifest and retry.',
  'powershell-core-setup-failed': 'PowerShell 7 script-block policy or its event channel could not be configured.',
  'defender-inactive': 'Defender is not active; its existing protection mode and exclusions were preserved.',
  'defender-unavailable': 'Defender telemetry is unavailable on this Windows image; its existing protection settings were preserved.',
  'defender-setup-failed': 'An installed Defender event channel could not be enabled or queried; its protection settings were preserved.',
  'collector-existing-filter': 'An existing event-channel query was preserved; it may limit the events collected by this profile.',
  'collector-existing-format': 'An existing telemetry collector uses a different log format and was preserved; review it before relying on that source.',
});

function buildWindowsTelemetryFunctions() {
  const profile = Buffer.from(SYSMON_PROFILE_XML, 'utf8').toString('base64');
  return String.raw`
function Test-CyberCoreEventChannel {
  param([string]$Channel)
  try { $log = Get-WinEvent -ListLog $Channel -ErrorAction Stop; return [bool]$log.IsEnabled } catch { return $false }
}
function Enable-CyberCoreEventChannel {
  param([string]$Channel)
  $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Channel)
  try {
    $changed = $false
    if (-not $log.IsEnabled) { $log.IsEnabled = $true; $changed = $true }
    $minimum = if ($Channel -eq '${TELEMETRY_CHANNELS.sysmon}') { 134217728 } else { 67108864 }
    if ($log.MaximumSizeInBytes -lt $minimum) { $log.MaximumSizeInBytes = $minimum; $changed = $true }
    if ($changed) { $log.SaveChanges() }
  } finally { $log.Dispose() }
  if (-not (Test-CyberCoreEventChannel $Channel)) { throw 'telemetry-channel-unavailable' }
}
function Test-CyberCoreMicrosoftBinary {
  param([string]$Path)
  if (-not [IO.File]::Exists($Path)) { return $false }
  try {
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    return $signature.Status -eq 'Valid' -and $signature.SignerCertificate -and
      $signature.SignerCertificate.Subject -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'
  } catch { return $false }
}
function Get-CyberCoreSysmonServices {
  $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
  foreach ($service in $services) {
    $known = $service.Name -match '^Sysmon(?:64|64a)?$' -or $service.DisplayName -match '^Sysmon(?:64|64a)?$|^System Monitor'
    $binary = $null
    if ($service.PathName -match '^\s*"([^"]+\.exe)"(?:\s|$)') { $binary = $matches[1] }
    elseif ($service.PathName -match '^\s*(.+?\.exe)(?:\s|$)') { $binary = $matches[1] }
    if (-not $known -and $binary -and [IO.File]::Exists($binary)) {
      try { $known = [Diagnostics.FileVersionInfo]::GetVersionInfo($binary).OriginalFilename -match '^Sysmon(?:64|64a)?\.exe$' } catch {}
    }
    if ($known) { [PSCustomObject]@{ Name = $service.Name; State = $service.State; Binary = $binary } }
  }
}
function Get-CyberCoreNativeSysmonBinary { return (Join-Path ([Environment]::SystemDirectory) 'Sysmon.exe') }
function Invoke-CyberCoreSysmonInstall {
  param([string]$Binary, [string]$ProfilePath, [switch]$UpdateExisting)
  if (-not (Test-CyberCoreMicrosoftBinary $Binary)) { throw 'sysmon-signature-invalid' }
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $Binary
  $mode = if ($UpdateExisting) { '-c' } else { '-i' }
  $start.Arguments = '-accepteula ' + $mode + ' "' + $ProfilePath + '"'
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start
  try {
    if (-not $process.Start()) { throw 'sysmon-start-failed' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) { try { $process.Kill() } catch {}; throw 'sysmon-install-timeout' }
    $null = $stdout.GetAwaiter().GetResult()
    $null = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw 'sysmon-install-failed' }
  } finally { $process.Dispose() }
}
function Install-CyberCoreSysmon {
  param([string]$AgentRoot)
  $root = Get-Item -LiteralPath $AgentRoot -ErrorAction Stop
  if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'telemetry-agent-root-invalid' }
  $existing = @(Get-CyberCoreSysmonServices)
  if ($existing.Count) {
    # Existing installations, including renamed services, keep their own policy.
    # Do not start a stopped third-party service or reset its configuration.
    if (@($existing | Where-Object State -eq 'Running').Count -eq 0) { throw 'sysmon-existing-service-stopped' }
    Enable-CyberCoreEventChannel '${TELEMETRY_CHANNELS.sysmon}'
    return 'existing-preserved'
  }
  $feature = $null
  $featureSupported = $false
  if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    try { $feature = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction Stop; $featureSupported = $true } catch {}
  }
  $nativeBinary = Get-CyberCoreNativeSysmonBinary
  # An orphaned/renamed provider is not permission to overwrite someone else's
  # install. A native enabled feature with no service can finish its own setup.
  $provider = Get-WinEvent -ListProvider 'Microsoft-Windows-Sysmon' -ErrorAction SilentlyContinue
  if ($provider -and -not ($featureSupported -and $feature.State -eq 'Enabled' -and [IO.File]::Exists($nativeBinary))) {
    throw 'sysmon-existing-provider-needs-review'
  }
  if ($featureSupported -and $feature.State -match 'Pending') { throw 'sysmon-feature-restart-pending' }
  $stage = Join-Path $root.FullName ('.cybercore-sysmon-' + [Guid]::NewGuid().ToString('N'))
  $stageCreated = $false
  try {
    $directory = New-Item -ItemType Directory -Path $stage -ErrorAction Stop
    $stageCreated = $true
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
      $identity = New-Object Security.Principal.SecurityIdentifier($sid)
      $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
      $null = $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory.FullName -AclObject $acl -ErrorAction Stop
    $profilePath = Join-Path $stage 'cybercore-sysmon.xml'
    [IO.File]::WriteAllBytes($profilePath, [Convert]::FromBase64String('${profile}'))
    $mode = 'builtin-installed'
    $featureStartedSysmon = $false
    if ($featureSupported) {
      if ($feature.State -ne 'Enabled') {
        $enabled = Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -NoRestart -ErrorAction Stop
        if ($enabled.RestartNeeded) { throw 'sysmon-feature-restart-pending' }
        # Some feature revisions may create/start the service themselves. It is
        # ours only because no Sysmon service existed before this enable call.
        $featureStartedSysmon = @(Get-CyberCoreSysmonServices).Count -gt 0
      }
      if (-not [IO.File]::Exists($nativeBinary)) { throw 'sysmon-native-binary-missing' }
      $binary = $nativeBinary
    } else {
      $arch = if ([Environment]::Is64BitOperatingSystem) { $env:PROCESSOR_ARCHITEW6432; if (-not $env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITECTURE } } else { 'x86' }
      if ($arch -notin @('AMD64', 'x86')) { throw 'sysmon-architecture-unsupported' }
      $filename = if ($arch -eq 'AMD64') { 'Sysmon64.exe' } else { 'Sysmon.exe' }
      $archivePath = Join-Path $stage 'Sysmon.zip'
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $archivePath -TimeoutSec 60 -MaximumRedirection 3 -ErrorAction Stop
      if ((Get-Item -LiteralPath $archivePath).Length -gt 104857600) { throw 'sysmon-package-too-large' }
      Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
      $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
      try {
        $entry = $archive.GetEntry($filename)
        if (-not $entry -or $entry.Length -gt 52428800 -or $entry.Length -lt 1) { throw 'sysmon-package-invalid' }
        $binary = Join-Path $stage $filename
        # Extract only the exact executable, preventing archive path traversal.
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $binary, $false)
      } finally { $archive.Dispose() }
      $mode = 'standalone-installed'
    }
    Invoke-CyberCoreSysmonInstall -Binary $binary -ProfilePath $profilePath -UpdateExisting:$featureStartedSysmon
    if (@(Get-CyberCoreSysmonServices | Where-Object State -eq 'Running').Count -eq 0) { throw 'sysmon-service-not-running' }
    Enable-CyberCoreEventChannel '${TELEMETRY_CHANNELS.sysmon}'
    return $mode
  } finally {
    if ($stageCreated -and [IO.Directory]::Exists($stage)) {
      $resolved = Get-Item -LiteralPath $stage -ErrorAction Stop
      $expected = [IO.Path]::GetFullPath($stage)
      $parent = [IO.Path]::GetDirectoryName($expected)
      if ($resolved.FullName -eq $expected -and $parent -eq $root.FullName -and
          $resolved.Name -match '^\.cybercore-sysmon-[a-f0-9]{32}$' -and
          -not ($resolved.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Remove-Item -LiteralPath $resolved.FullName -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}
function Enable-CyberCoreScriptBlockPolicy {
  param([string]$Path)
  if ($Path -notin @('Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'Software\Policies\Microsoft\PowerShellCore\ScriptBlockLogging')) { throw 'telemetry-policy-path-invalid' }
  $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Default }
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
  try {
    $key = $base.CreateSubKey($Path)
    try { $key.SetValue('EnableScriptBlockLogging', 1, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $key.Dispose() }
  } finally { $base.Dispose() }
  # Existing invocation, module, transcription, and protected-event policies are
  # preserved. This profile does not enable those higher-volume settings.
}
function Enable-CyberCoreWindowsTelemetry {
  param([string]$AgentRoot)
  $channels = New-Object 'System.Collections.Generic.List[string]'
  $warnings = New-Object 'System.Collections.Generic.List[string]'
  $result = [ordered]@{ Channels = @(); Warnings = @(); Sysmon = 'failed'; PowerShell = 'failed'; PowerShellCore = 'unavailable'; Defender = 'unavailable'; Complete = $true }
  try {
    $result.Sysmon = Install-CyberCoreSysmon -AgentRoot $AgentRoot
    $channels.Add('${TELEMETRY_CHANNELS.sysmon}')
    if ($result.Sysmon -eq 'existing-preserved') { $warnings.Add('sysmon-existing-profile') }
  } catch { $result.Complete = $false; $warnings.Add('sysmon-setup-failed') }
  try {
    Enable-CyberCoreScriptBlockPolicy 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    Enable-CyberCoreEventChannel '${TELEMETRY_CHANNELS.powershell}'
    $channels.Add('${TELEMETRY_CHANNELS.powershell}')
    $result.PowerShell = 'script-block-enabled'
  } catch { $result.Complete = $false; $warnings.Add('powershell-setup-failed') }
  try {
    # Set the Core policy without installing PowerShell or overwriting its JSON
    # configuration. A future managed PowerShell 7 install can consume it too.
    Enable-CyberCoreScriptBlockPolicy 'Software\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
    $coreLog = Get-WinEvent -ListLog '${TELEMETRY_CHANNELS.powershellCore}' -ErrorAction SilentlyContinue
    if ($coreLog) {
      Enable-CyberCoreEventChannel '${TELEMETRY_CHANNELS.powershellCore}'
      $channels.Add('${TELEMETRY_CHANNELS.powershellCore}')
      $result.PowerShellCore = 'script-block-enabled'
    } else { $warnings.Add('powershell-core-unavailable') }
  } catch { $warnings.Add('powershell-core-setup-failed'); $result.Complete = $false }
  try {
    $defenderLog = Get-WinEvent -ListLog '${TELEMETRY_CHANNELS.defender}' -ErrorAction SilentlyContinue
    if (-not $defenderLog) { $warnings.Add('defender-unavailable') }
    else {
      Enable-CyberCoreEventChannel '${TELEMETRY_CHANNELS.defender}'
      $channels.Add('${TELEMETRY_CHANNELS.defender}')
      $result.Defender = 'channel-enabled-policy-preserved'
      if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if (-not $status.AntivirusEnabled) { $warnings.Add('defender-inactive') }
      }
    }
  } catch { $warnings.Add('defender-setup-failed'); $result.Complete = $false }
  $result.Channels = $channels.ToArray()
  $result.Warnings = $warnings.ToArray()
  return [PSCustomObject]$result
}
function Set-CyberCoreWindowsTelemetryCollectors {
  param([xml]$Document, [string[]]$Channels)
  $allowed = @('${TELEMETRY_CHANNELS.sysmon}', '${TELEMETRY_CHANNELS.powershell}', '${TELEMETRY_CHANNELS.powershellCore}', '${TELEMETRY_CHANNELS.defender}')
  $roots = @($Document.SelectNodes('//ossec_config'))
  if ($roots.Count -eq 0) { throw 'telemetry-agent-config-invalid' }
  $warnings = New-Object 'System.Collections.Generic.List[string]'
  $complete = $true
  $changed = $false
  $unique = @($Channels | Select-Object -Unique)
  foreach ($channel in $unique) { if ($channel -notin $allowed) { throw 'telemetry-channel-invalid' } }
  foreach ($channel in $unique) {
    $existing = @($Document.SelectNodes('//ossec_config/localfile')) | Where-Object { $_.location -eq $channel }
    if ($existing) {
      if (@($existing | Where-Object { $_.log_format -ne 'eventchannel' }).Count) { $warnings.Add('collector-existing-format'); $complete = $false }
      if (@($existing | Where-Object { $_.query }).Count) { $warnings.Add('collector-existing-filter') }
      continue
    }
    $localfile = $Document.CreateElement('localfile')
    foreach ($pair in @(@('location', $channel), @('log_format', 'eventchannel'), @('only-future-events', 'yes'))) {
      $child = $Document.CreateElement($pair[0]); $child.InnerText = $pair[1]; $null = $localfile.AppendChild($child)
    }
    $null = $roots[0].AppendChild($localfile)
    $changed = $true
  }
  return [PSCustomObject]@{ Warnings = @($warnings.ToArray() | Select-Object -Unique); Complete = $complete; Changed = $changed }
}
`;
}

module.exports = { buildWindowsTelemetryFunctions, SYSMON_PROFILE_XML, TELEMETRY_CHANNELS, TELEMETRY_WARNINGS };
