'use strict';

// Sandcat's flags and download architecture header are defined upstream in
// https://github.com/mitre/sandcat/blob/master/gocat/sandcat.go and
// https://github.com/mitre/sandcat/blob/master/app/sand_svc.py.
// These scripts start a session agent; they do not install a service or task.

const GROUP_PATTERN = /^lane-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const PAW_PATTERN = /^[a-f0-9]{24}$/;
const SERVER_PATTERN = /^https:\/\/[a-zA-Z0-9.-]+(?::[0-9]{1,5})?(?:\/agent\/[a-f0-9]{64})?\/?$/;

function validateOptions({ platform, serverUrl, group, paw } = {}) {
  if (platform !== 'windows' && platform !== 'linux') {
    throw new TypeError('Caldera agent platform must be windows or linux');
  }
  if (typeof serverUrl !== 'string' || !SERVER_PATTERN.test(serverUrl)) {
    throw new TypeError('Caldera agent server must be an HTTPS origin or an HTTPS /agent/<token> URL');
  }
  let parsed;
  try { parsed = new URL(serverUrl); } catch (_) {
    throw new TypeError('Caldera agent server URL is invalid');
  }
  if (!parsed.hostname.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))) {
    throw new TypeError('Caldera agent server hostname is invalid');
  }
  if (typeof group !== 'string' || !GROUP_PATTERN.test(group)) {
    throw new TypeError('Caldera agent group must be lane-<UUID> in lowercase');
  }
  if (typeof paw !== 'string' || !PAW_PATTERN.test(paw)) {
    throw new TypeError('Caldera agent paw must contain 24 lowercase hexadecimal characters');
  }
  return { platform, serverUrl: serverUrl.replace(/\/$/, ''), group, paw };
}

function buildLinuxScript({ serverUrl, group, paw }) {
  return `#!/bin/sh
set -eu
umask 077
server='${serverUrl}'
group='${group}'
paw='${paw}'
agent_dir="/opt/CyberCore/Caldera/$group/$paw"
binary="$agent_dir/mitre-sandcat"
pid_file="$agent_dir/agent.pid"
log_file="$agent_dir/agent.log"
download="$agent_dir/mitre-sandcat.download"
fail() { printf '%s\\n' "CyberCore Caldera: $*" >&2; exit 1; }
for dependency in curl uname od tr mkdir chmod mv rm rmdir readlink nohup sleep cat; do
  command -v "$dependency" >/dev/null 2>&1 || fail "Required command missing: $dependency"
done
case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *) fail 'Only amd64 and arm64 Linux machines are supported' ;;
esac
mkdir -p "$agent_dir"
chmod 700 "$agent_dir"
mkdir "$agent_dir/install.lock" 2>/dev/null || fail 'An installation is already running for this agent'
cleanup() {
  rm -f "$download"
  rmdir "$agent_dir/install.lock" 2>/dev/null || true
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
printf '%s\\n' 'CyberCore Caldera: downloading MITRE Sandcat'
curl --fail --silent --show-error --connect-timeout 15 --max-time 90 \\
  --proto '=https' --request POST \\
  --header 'platform:linux' --header 'file:sandcat.go' \\
  --header "architecture:$architecture" \\
  --output "$download" "$server/file/download" || fail 'Sandcat download failed; check the Caldera server connection and certificate'
[ -s "$download" ] || fail 'Caldera returned an empty agent download'
magic=$(od -An -tx1 -N4 "$download" | tr -d ' \\n')
[ "$magic" = '7f454c46' ] || fail 'Caldera did not return a Linux executable'
chmod 700 "$download"
if [ -f "$pid_file" ]; then
  managed_pid=$(cat "$pid_file")
  case "$managed_pid" in
    ''|*[!0-9]*) fail 'The managed agent PID file is invalid' ;;
  esac
  if kill -0 "$managed_pid" 2>/dev/null; then
    managed_exe=$(readlink "/proc/$managed_pid/exe") || fail 'Cannot verify the existing managed process'
    [ "$managed_exe" = "$binary" ] || fail 'The saved PID belongs to another process; refusing to stop it'
    kill "$managed_pid" || fail 'Cannot stop the existing managed agent'
    attempt=0
    while kill -0 "$managed_pid" 2>/dev/null; do
      attempt=$((attempt + 1))
      [ "$attempt" -lt 10 ] || fail 'The existing managed agent did not stop'
      sleep 1
    done
  fi
fi
mv -f "$download" "$binary"
nohup "$binary" -server "$server" -group "$group" -paw "$paw" -v </dev/null >>"$log_file" 2>&1 &
managed_pid=$!
printf '%s\\n' "$managed_pid" >"$pid_file"
sleep 2
kill -0 "$managed_pid" 2>/dev/null || fail "Sandcat exited during startup; inspect $log_file"
printf '%s\\n' "CyberCore Caldera: MITRE Sandcat started; log: $log_file"
printf '%s\\n' "CYBERCORE_CALDERA_STARTED:$paw"
`;
}

function buildWindowsScript({ serverUrl, group, paw }) {
  return `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$server = '${serverUrl}'
$group = '${group}'
$paw = '${paw}'
$installLock = $null
$download = $null
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $machineArchitecture = $env:PROCESSOR_ARCHITEW6432
  if (-not $machineArchitecture) { $machineArchitecture = $env:PROCESSOR_ARCHITECTURE }
  switch ($machineArchitecture) {
    'AMD64' { $architecture = 'amd64' }
    'ARM64' { $architecture = 'arm64' }
    default { throw 'Only amd64 and arm64 Windows machines are supported' }
  }
  if (-not $env:ProgramData) { throw 'ProgramData is unavailable' }
  $agentDir = Join-Path $env:ProgramData ('CyberCore\\Caldera\\' + $group + '\\' + $paw)
  New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
  $binary = Join-Path $agentDir 'mitre-sandcat.exe'
  $pidFile = Join-Path $agentDir 'agent.pid'
  $stdoutLog = Join-Path $agentDir 'agent.stdout.log'
  $stderrLog = Join-Path $agentDir 'agent.stderr.log'
  $lockPath = Join-Path $agentDir 'install.lock'
  $installLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $defenderCommands = @('Get-MpComputerStatus', 'Get-MpPreference', 'Set-MpPreference', 'Add-MpPreference')
  $missingDefenderCommands = @($defenderCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
  if ($missingDefenderCommands.Count -eq 0) {
    try {
      $defenderSettings = @{
        DisableRealtimeMonitoring = $true
        DisableBehaviorMonitoring = $true
        DisableIOAVProtection = $true
        DisableScriptScanning = $true
        DisableBlockAtFirstSeen = $true
        PUAProtection = 0
      }
      $defenderSettingsMatch = {
        param($preferences)
        foreach ($setting in $defenderSettings.Keys) {
          $actual = $preferences.$setting
          if ($null -eq $actual -or $actual -ne $defenderSettings[$setting]) { return $false }
          if ($defenderSettings[$setting] -is [bool] -and $actual -isnot [bool]) { return $false }
        }
        return $true
      }
      $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
      if ($defenderStatus.RealTimeProtectionEnabled -isnot [bool]) { throw 'Defender did not report its real-time protection state.' }
      $defenderPreferences = Get-MpPreference -ErrorAction Stop
      if ($defenderStatus.RealTimeProtectionEnabled -or -not (& $defenderSettingsMatch $defenderPreferences)) {
        Write-Output 'CyberCore Caldera: turning off Microsoft Defender scanning and blocking settings on this lab VM'
        Set-MpPreference @defenderSettings -ErrorAction Stop
      }
      if ($defenderPreferences.ExclusionPath -notcontains $agentDir) {
        Add-MpPreference -ExclusionPath $agentDir -ErrorAction Stop
      }
      $defenderReady = $false
      for ($attempt = 0; $attempt -lt 5; $attempt++) {
        if ($attempt -gt 0) { Start-Sleep -Seconds 1 }
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        $defenderPreferences = Get-MpPreference -ErrorAction Stop
        if ($defenderStatus.RealTimeProtectionEnabled -is [bool] -and -not $defenderStatus.RealTimeProtectionEnabled -and
            (& $defenderSettingsMatch $defenderPreferences) -and $defenderPreferences.ExclusionPath -contains $agentDir) {
          $defenderReady = $true
          break
        }
      }
      if (-not $defenderReady) { throw 'Defender scanning settings or the agent folder exclusion could not be verified.' }
      Write-Output ('CyberCore Caldera: Defender scanning and blocking settings are off; excluded agent folder: ' + $agentDir)
    } catch {
      throw ('Could not turn off Microsoft Defender protections for the Caldera lab agent. Check Tamper Protection or managed policy on this VM. ' + $_.Exception.Message)
    }
  } else {
    Write-Output 'CyberCore Caldera: Microsoft Defender management commands are unavailable; continuing without changing security settings'
  }
  $download = Join-Path $agentDir ('mitre-sandcat-' + [Guid]::NewGuid().ToString('N') + '.download')
  Write-Output 'CyberCore Caldera: downloading MITRE Sandcat'
  $headers = @{ 'platform' = 'windows'; 'file' = 'sandcat.go'; 'architecture' = $architecture }
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($server + '/file/download') -Headers $headers -OutFile $download -TimeoutSec 90 -MaximumRedirection 0
  if (-not (Test-Path -LiteralPath $download) -or (Get-Item -LiteralPath $download).Length -lt 2) { throw 'Caldera returned an empty agent download' }
  $stream = [IO.File]::OpenRead($download)
  try {
    if ($stream.ReadByte() -ne 77 -or $stream.ReadByte() -ne 90) { throw 'Caldera did not return a Windows executable' }
  } finally { $stream.Dispose() }
  if (Test-Path -LiteralPath $pidFile) {
    $pidText = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    if ($pidText -notmatch '^[0-9]+$') { throw 'The managed agent PID file is invalid' }
    $managedPid = [int]$pidText
    $existing = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $managedPid)
    if ($existing) {
      if (-not [string]::Equals($existing.ExecutablePath, $binary, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The saved PID belongs to another process; refusing to stop it'
      }
      Stop-Process -Id $managedPid -Force -ErrorAction Stop
      Wait-Process -Id $managedPid -Timeout 10 -ErrorAction SilentlyContinue
      if (Get-Process -Id $managedPid -ErrorAction SilentlyContinue) { throw 'The existing managed agent did not stop' }
    }
  }
  Move-Item -LiteralPath $download -Destination $binary -Force
  $agentArguments = @('-server', $server, '-group', $group, '-paw', $paw, '-v')
  $agentProcess = Start-Process -FilePath $binary -ArgumentList $agentArguments -WorkingDirectory $agentDir -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
  [IO.File]::WriteAllText($pidFile, [string]$agentProcess.Id)
  Start-Sleep -Seconds 2
  $agentProcess.Refresh()
  if ($agentProcess.HasExited) { throw ('Sandcat exited during startup; inspect ' + $stderrLog) }
  Write-Output ('CyberCore Caldera: MITRE Sandcat started; logs: ' + $agentDir)
  Write-Output ('CYBERCORE_CALDERA_STARTED:' + $paw)
} catch {
  $exception = $_.Exception
  $message = $exception.Message
  while ($exception) {
    # ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED, including PowerShell's wrapped IO errors.
    $blockedBySecurity = $exception.HResult -eq -2147024671 -or $exception.HResult -eq -2147024670
    if ($exception -is [ComponentModel.Win32Exception]) {
      $blockedBySecurity = $blockedBySecurity -or $exception.NativeErrorCode -eq 225 -or $exception.NativeErrorCode -eq 226
    }
    if ($blockedBySecurity) {
      $message = 'Windows security software blocked MITRE Sandcat as malware or potentially unwanted software. Review Windows Security > Virus & threat protection > Protection history (or your endpoint security console) on this VM. Allow this lab agent under your approved lab policy, then retry Install Agent. Agent folder: ' + $agentDir
      break
    }
    $exception = $exception.InnerException
  }
  [Console]::Error.WriteLine('CyberCore Caldera: ' + $message)
  exit 1
} finally {
  if ($download -and (Test-Path -LiteralPath $download)) { Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue }
  if ($installLock) { $installLock.Dispose() }
}
`;
}

function buildInstallScript(options) {
  const validated = validateOptions(options);
  return validated.platform === 'windows' ? buildWindowsScript(validated) : buildLinuxScript(validated);
}

module.exports = { buildInstallScript };
