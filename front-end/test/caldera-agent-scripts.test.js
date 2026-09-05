'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildInstallScript } = require('../src/utils/caldera-agent-scripts');

const group = 'lane-11111111-2222-4333-8444-555555555555';
const paw = '0123456789abcdef01234567';
const serverUrl = 'https://caldera.saguaroscyberhub.org/agent/' + 'a'.repeat(64);
const options = { platform: 'linux', serverUrl, group, paw };

test('rejects unsupported platforms and shell-bearing or malformed install arguments', () => {
  for (const platform of [undefined, 'darwin', 'Windows', {}, 'linux;id']) {
    assert.throws(() => buildInstallScript({ ...options, platform }), /platform/);
  }
  for (const value of ['', 'http://caldera.example', 'https://user:pass@caldera.example',
    'https://caldera.example/other', 'https://caldera.example/?x=y', 'https://caldera.example/#fragment',
    'https://caldera.example/agent/' + 'a'.repeat(63), 'https://caldera.example/agent/' + 'A'.repeat(64),
    'https://caldera.example/agent/../', "https://caldera.example/'$(id)", 'https://caldera.example\n',
    'https://caldera.example\\evil', 'https://caldera.example:99999', 'https://-invalid.example']) {
    assert.throws(() => buildInstallScript({ ...options, serverUrl: value }), /server/);
  }
  for (const value of [null, 'red', group.toUpperCase(), group + "'; id", 'lane-../target']) {
    assert.throws(() => buildInstallScript({ ...options, group: value }), /group/);
  }
  for (const value of [null, 'a'.repeat(23), 'a'.repeat(25), 'A'.repeat(24), paw + '\n', 'x'.repeat(24)]) {
    assert.throws(() => buildInstallScript({ ...options, paw: value }), /paw/);
  }
});

test('both installers retain the ingress prefix, explicit identity, certificate validation and logs', () => {
  for (const platform of ['linux', 'windows']) {
    const script = buildInstallScript({ ...options, platform, serverUrl: serverUrl + '/' });
    assert.ok(script.includes("'" + serverUrl + "'"));
    assert.ok(script.includes(group));
    assert.ok(script.includes(paw));
    assert.match(script, /file\/download/);
    assert.match(script, /sandcat\.go/);
    assert.match(script, /architecture/);
    assert.match(script, /amd64/);
    assert.match(script, /arm64/);
    assert.match(script, /-server/);
    assert.match(script, /-group/);
    assert.match(script, /-paw/);
    assert.match(script, /CYBERCORE_CALDERA_STARTED:/);
    assert.match(script, /CyberCore[\\/]Caldera/);
    assert.doesNotMatch(script, /--insecure|curl\s+-[a-z]*k|SkipCertificateCheck|ServerCertificateValidationCallback|DisableTamperProtection|Exclusion(?:Process|Extension)|Stop-Service|KEY:|api_key|pkill|killall|New-Service|Register-ScheduledTask/i);
  }
  assert.doesNotThrow(() => buildInstallScript({ ...options, serverUrl: 'https://caldera.example:8443/' }));
});

test('Linux detaches all standard streams and verifies the saved process executable before stopping it', () => {
  const script = buildInstallScript(options);
  assert.match(script, /nohup "\$binary"[^\n]+<\/dev\/null[^\n]+2>&1 &/);
  assert.match(script, /readlink "\/proc\/\$managed_pid\/exe"/);
  assert.ok(script.indexOf('[ "$managed_exe" = "$binary" ]') < script.indexOf('kill "$managed_pid"'));
  assert.match(script, /--max-time 90/);
  assert.match(script, /7f454c46/);
});

const shell = process.platform === 'win32'
  ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'].find(candidate => fs.existsSync(candidate))
  : '/bin/sh';

test('Linux installer parses as a shell script', { skip: !shell }, () => {
  const result = spawnSync(shell, ['-n'], { input: buildInstallScript(options), encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
});

for (const download of ['failure', 'html']) {
  test(`Linux ${download} download fails and cleans up before launching an agent`, { skip: !shell }, t => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'caldera-installer-test-'));
    t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
    const mockedDownload = download === 'failure' ? 'return 22' : 'printf %s "<html>Login</html>" > "$download"';
    const harness = `curl() { ${mockedDownload}; }\nuname() { printf '%s\\n' x86_64; }\n`;
    const script = harness + buildInstallScript(options).replace('agent_dir="/opt/CyberCore/Caldera/$group/$paw"', 'agent_dir="$CALDERA_TEST_DIRECTORY"');
    const result = spawnSync(shell, [], {
      input: script, encoding: 'utf8', timeout: 10000,
      env: { ...process.env, CALDERA_TEST_DIRECTORY: temporary.replace(/\\/g, '/') },
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, download === 'failure' ? /Sandcat download failed/ : /did not return a Linux executable/);
    assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_STARTED/);
    assert.deepEqual(fs.readdirSync(temporary), []);
  });
}

// Exercise the Windows installer with Defender, download and process launch mocked.
// All filesystem writes are restricted to an isolated temporary ProgramData.
// No test may change the host's Defender settings or start a Sandcat agent.
function runMockWindowsInstall(t, { download = 'binary', existing = false, readError = '', launchError = '', defender = 'off' } = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'caldera-installer-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const agentDir = path.join(temporary, 'CyberCore', 'Caldera', group, paw);
  if (existing) {
    fs.mkdirSync(agentDir, { recursive: true });
    fs.writeFileSync(path.join(agentDir, 'agent.pid'), '2147483646');
  }
  const harness = `
$script:mockRealTimeEnabled = $env:CALDERA_TEST_DEFENDER -ne 'off'
$script:mockDisableRequested = $false
$script:mockStatusReads = 0
$script:mockAgentDir = Join-Path $env:ProgramData 'CyberCore\\Caldera\\${group}\\${paw}'
$script:mockPreferences = @{
  DisableRealtimeMonitoring = $env:CALDERA_TEST_DEFENDER -eq 'off'
  DisableBehaviorMonitoring = $env:CALDERA_TEST_DEFENDER -eq 'off'
  DisableIOAVProtection = $env:CALDERA_TEST_DEFENDER -eq 'off'
  DisableScriptScanning = $env:CALDERA_TEST_DEFENDER -eq 'off'
  DisableBlockAtFirstSeen = $env:CALDERA_TEST_DEFENDER -eq 'off'
  PUAProtection = 1
  ExclusionPath = @('C:\\Unrelated\\existing-exclusion')
}
if ($env:CALDERA_TEST_DEFENDER -eq 'off') {
  $script:mockPreferences.PUAProtection = 0
  $script:mockPreferences.ExclusionPath += $script:mockAgentDir.ToUpperInvariant()
}
if ($env:CALDERA_TEST_DEFENDER -eq 'tamper_partial') {
  $script:mockPreferences.DisableBlockAtFirstSeen = $true
  $script:mockPreferences.PUAProtection = 0
  $script:mockPreferences.ExclusionPath += $script:mockAgentDir
}
function Write-CalderaTestEvent {
  param($Event)
  [IO.File]::AppendAllText((Join-Path $env:ProgramData 'events.txt'), $Event + [Environment]::NewLine)
}
function Get-Command {
  param([string[]]$Name, $ErrorAction)
  if ($Name -contains 'Get-MpComputerStatus' -and $env:CALDERA_TEST_DEFENDER -in @('missing_get', 'missing_both')) { return $null }
  if ($Name -contains 'Get-MpPreference' -and $env:CALDERA_TEST_DEFENDER -in @('missing_preferences', 'missing_both')) { return $null }
  if ($Name -contains 'Set-MpPreference' -and $env:CALDERA_TEST_DEFENDER -in @('missing_set', 'missing_both')) { return $null }
  if ($Name -contains 'Add-MpPreference' -and $env:CALDERA_TEST_DEFENDER -in @('missing_add', 'missing_both')) { return $null }
  return Microsoft.PowerShell.Core\\Get-Command -Name $Name -ErrorAction SilentlyContinue
}
function Get-MpComputerStatus {
  param($ErrorAction)
  if ($env:CALDERA_TEST_DEFENDER -like 'missing*') { throw 'Unavailable Defender commands must not be called' }
  if ($ErrorAction -ne 'Stop') { throw 'Defender status errors must be terminating' }
  if ($script:mockDisableRequested) { $script:mockStatusReads++ }
  Write-CalderaTestEvent 'defender-status'
  if ($env:CALDERA_TEST_DEFENDER -eq 'unknown' -or ($env:CALDERA_TEST_DEFENDER -eq 'unknown_after_disable' -and $script:mockDisableRequested)) {
    return [pscustomobject]@{ RealTimeProtectionEnabled = $null }
  }
  if ($env:CALDERA_TEST_DEFENDER -eq 'string_state') { return [pscustomobject]@{ RealTimeProtectionEnabled = 'False' } }
  if ($env:CALDERA_TEST_DEFENDER -eq 'delayed' -and $script:mockDisableRequested -and $script:mockStatusReads -ge 2) { $script:mockRealTimeEnabled = $false }
  return [pscustomobject]@{
    RealTimeProtectionEnabled = $script:mockRealTimeEnabled
    IsTamperProtected = $env:CALDERA_TEST_DEFENDER -eq 'tamper_partial'
  }
}
function Get-MpPreference {
  param($ErrorAction)
  if ($env:CALDERA_TEST_DEFENDER -like 'missing*') { throw 'Unavailable Defender commands must not be called' }
  if ($ErrorAction -ne 'Stop') { throw 'Defender preference errors must be terminating' }
  Write-CalderaTestEvent 'defender-preferences'
  return [pscustomobject]$script:mockPreferences
}
function Set-MpPreference {
  param($DisableRealtimeMonitoring, $DisableBehaviorMonitoring, $DisableIOAVProtection, $DisableScriptScanning, $DisableBlockAtFirstSeen, $PUAProtection, $ErrorAction)
  if ($env:CALDERA_TEST_DEFENDER -like 'missing*') { throw 'Unavailable Defender commands must not be called' }
  foreach ($flag in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableBlockAtFirstSeen')) {
    if ($PSBoundParameters[$flag] -isnot [bool] -or $PSBoundParameters[$flag] -ne $true) { throw ('Unexpected Defender setting or restore attempt: ' + $flag) }
  }
  if ($PUAProtection -ne 0 -or $ErrorAction -ne 'Stop') { throw 'Unexpected Defender PUA or error action setting' }
  Write-CalderaTestEvent 'defender-disable'
  if ($env:CALDERA_TEST_DEFENDER -eq 'policy_error') { throw 'mock Defender policy rejected change' }
  $script:mockDisableRequested = $true
  if ($env:CALDERA_TEST_DEFENDER -notin @('no_op', 'delayed', 'tamper_partial')) { $script:mockRealTimeEnabled = $false }
  if ($env:CALDERA_TEST_DEFENDER -notin @('no_op', 'preferences_no_op', 'tamper_partial')) {
    foreach ($flag in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableBlockAtFirstSeen')) { $script:mockPreferences[$flag] = $true }
    $script:mockPreferences.PUAProtection = 0
  }
}
function Add-MpPreference {
  param($ExclusionPath, $ErrorAction)
  if ($env:CALDERA_TEST_DEFENDER -like 'missing*') { throw 'Unavailable Defender commands must not be called' }
  if (@($ExclusionPath).Count -ne 1 -or $ExclusionPath -cne $script:mockAgentDir -or $ErrorAction -ne 'Stop') { throw 'Exclusion must be exactly the managed agent directory' }
  Write-CalderaTestEvent 'defender-exclude-agent'
  if ($env:CALDERA_TEST_DEFENDER -eq 'exclusion_policy_error') { throw 'mock Defender policy rejected exclusion' }
  if ($env:CALDERA_TEST_DEFENDER -notin @('no_op', 'exclusion_no_op')) { $script:mockPreferences.ExclusionPath += $ExclusionPath }
}
function Invoke-WebRequest {
  param([switch]$UseBasicParsing, $Method, $Uri, $Headers, $OutFile, $TimeoutSec, $MaximumRedirection)
  Write-CalderaTestEvent 'download'
  [IO.File]::WriteAllText((Join-Path $env:ProgramData 'defender-at-download.json'), (ConvertTo-Json $script:mockPreferences))
  if ($Method -ne 'Post' -or $Headers.platform -ne 'windows' -or $Headers.file -ne 'sandcat.go' -or $Headers.architecture -ne 'amd64') { throw 'Unexpected download contract' }
  if ($env:CALDERA_TEST_DOWNLOAD -eq 'failure') { throw 'mock download failed' }
  if ($env:CALDERA_TEST_DOWNLOAD -eq 'html') { [IO.File]::WriteAllText($OutFile, '<html>Login</html>') }
  else { [IO.File]::WriteAllBytes($OutFile, [byte[]]@(77, 90, 0, 0)) }
}
function Open-CalderaTestDownload {
  param($Path)
  if ($env:CALDERA_TEST_READ_ERROR) {
    $inner = [IO.IOException]::new('mock file read failed', [int]$env:CALDERA_TEST_READ_ERROR)
    throw [InvalidOperationException]::new('mock wrapped file read failed', $inner)
  }
  return [IO.File]::OpenRead($Path)
}
function Start-Process {
  param($FilePath, $ArgumentList, $WorkingDirectory, $WindowStyle, $RedirectStandardOutput, $RedirectStandardError, [switch]$PassThru)
  if ($WindowStyle -ne 'Hidden' -or -not $RedirectStandardOutput -or -not $RedirectStandardError) { throw 'Process must detach with logs' }
  if ($env:CALDERA_TEST_LAUNCH_ERROR) { throw [ComponentModel.Win32Exception]::new([int]$env:CALDERA_TEST_LAUNCH_ERROR, 'mock process launch failed') }
  Write-CalderaTestEvent 'launch'
  [IO.File]::WriteAllText((Join-Path $env:ProgramData 'launch.json'), (ConvertTo-Json @{ file = $FilePath; arguments = $ArgumentList }))
  $mock = [pscustomobject]@{ Id = 2147483646; HasExited = $false }
  $mock | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
  return $mock
}
function Start-Sleep { param($Seconds) Write-CalderaTestEvent ('sleep:' + $Seconds) }
function Get-CimInstance { param($ClassName, $Filter) return [pscustomobject]@{ ExecutablePath = 'C:\\Unrelated\\process.exe' } }
function Stop-Process { throw 'Unrelated process must never be stopped' }
`;
  const script = harness + buildInstallScript({ ...options, platform: 'windows' }).replace(
    '$stream = [IO.File]::OpenRead($download)',
    '$stream = Open-CalderaTestDownload -Path $download',
  );
  const scriptPath = path.join(temporary, 'installer-harness.ps1');
  fs.writeFileSync(scriptPath, script, 'utf8');
  // Keep the expanded harness below Windows' command-line length limit.
  const loader = '& ([scriptblock]::Create([IO.File]::ReadAllText($env:CALDERA_TEST_SCRIPT)))';
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(loader, 'utf16le').toString('base64')], {
    encoding: 'utf8', timeout: 20000,
    env: { ...process.env, ProgramData: temporary, PROCESSOR_ARCHITECTURE: 'AMD64', PROCESSOR_ARCHITEW6432: 'AMD64', CALDERA_TEST_DOWNLOAD: download, CALDERA_TEST_READ_ERROR: String(readError), CALDERA_TEST_LAUNCH_ERROR: String(launchError), CALDERA_TEST_DEFENDER: defender, CALDERA_TEST_SCRIPT: scriptPath },
  });
  assert.ifError(result.error);
  const eventsPath = path.join(temporary, 'events.txt');
  const events = fs.existsSync(eventsPath) ? fs.readFileSync(eventsPath, 'utf8').trim().split(/\r?\n/) : [];
  return { ...result, temporary, agentDir, events };
}

test('Windows prepares Defender settings and exact agent folder before downloading without restoring them', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { defender: 'active' });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.events.indexOf('defender-disable') < result.events.indexOf('download'), result.events.join(', '));
  assert.ok(result.events.indexOf('defender-exclude-agent') < result.events.indexOf('download'), result.events.join(', '));
  assert.ok(result.events.lastIndexOf('defender-status') > result.events.indexOf('defender-disable'), result.events.join(', '));
  assert.ok(result.events.lastIndexOf('defender-preferences') > result.events.indexOf('defender-disable'), result.events.join(', '));
  assert.equal(result.events.filter(event => event === 'defender-disable').length, 1);
  assert.equal(result.events.filter(event => event === 'defender-exclude-agent').length, 1);
  const preferences = JSON.parse(fs.readFileSync(path.join(result.temporary, 'defender-at-download.json'), 'utf8'));
  for (const flag of ['DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableBlockAtFirstSeen']) assert.equal(preferences[flag], true, flag);
  assert.equal(preferences.PUAProtection, 0);
  assert.deepEqual(preferences.ExclusionPath, ['C:\\Unrelated\\existing-exclusion', result.agentDir]);
  assert.match(result.stdout, new RegExp('CYBERCORE_CALDERA_STARTED:' + paw));
  assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_WARNING:/);
});

test('Windows waits for Defender to report real-time monitoring disabled before downloading', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { defender: 'delayed' });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.events.filter(event => event === 'defender-status').length >= 2);
  assert.ok(result.events.indexOf('sleep:1') < result.events.indexOf('download'), result.events.join(', '));
  assert.ok(result.events.lastIndexOf('defender-status') < result.events.indexOf('download'), result.events.join(', '));
});

test('Windows leaves already configured Defender settings and case-insensitive agent exclusion alone', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { defender: 'off' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.events.includes('defender-disable'), false);
  assert.equal(result.events.includes('defender-exclude-agent'), false);
  assert.ok(result.events.includes('download'));
  assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_WARNING:/);
});

test('Windows attempts installation with the verified exact exclusion when Tamper Protection keeps scanning enabled', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { defender: 'tamper_partial' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.events.filter(event => event === 'defender-disable').length, 1);
  assert.equal(result.events.includes('defender-exclude-agent'), false);
  assert.ok(result.events.includes('download'));
  assert.ok(result.events.includes('launch'));
  assert.match(result.stdout, /CYBERCORE_CALDERA_WARNING:/);
  assert.match(result.stdout, /Tamper(?: Protection|Protected|Protection)/i);
  assert.match(result.stdout, /RealTimeProtectionEnabled\s*=\s*True/i);
  for (const flag of ['DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning']) {
    assert.match(result.stdout, new RegExp(flag + '\\s*=\\s*False', 'i'));
  }
  assert.doesNotMatch(result.stdout, /Defender scanning and blocking settings are off/);
  assert.match(result.stdout, new RegExp('CYBERCORE_CALDERA_STARTED:' + paw));
  const preferences = JSON.parse(fs.readFileSync(path.join(result.temporary, 'defender-at-download.json'), 'utf8'));
  assert.equal(preferences.DisableRealtimeMonitoring, false);
  assert.equal(preferences.DisableBehaviorMonitoring, false);
  assert.equal(preferences.DisableIOAVProtection, false);
  assert.equal(preferences.DisableScriptScanning, false);
  assert.equal(preferences.DisableBlockAtFirstSeen, true);
  assert.equal(preferences.PUAProtection, 0);
  assert.deepEqual(preferences.ExclusionPath, ['C:\\Unrelated\\existing-exclusion', result.agentDir]);
});

test('Windows reports unapplied preferences while attempting installation in its verified excluded folder', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { defender: 'preferences_no_op' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /CYBERCORE_CALDERA_WARNING:/);
  assert.match(result.stdout, /DisableRealtimeMonitoring\s*=\s*False/i);
  assert.match(result.stdout, /PUAProtection\s*=\s*1/);
  assert.doesNotMatch(result.stdout, /Defender scanning and blocking settings are off/);
  assert.ok(result.events.includes('download'));
  assert.ok(result.events.includes('launch'));
  assert.match(result.stdout, new RegExp('CYBERCORE_CALDERA_STARTED:' + paw));
});

for (const defender of ['missing_get', 'missing_preferences', 'missing_set', 'missing_add', 'missing_both']) {
  test(`Windows continues installation when Defender commands are unavailable: ${defender}`, { skip: process.platform !== 'win32' }, t => {
    const result = runMockWindowsInstall(t, { defender });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Defender[^\r\n]*(?:unavailable|not available)/i);
    assert.equal(result.events.some(event => event.startsWith('defender-')), false);
    assert.ok(result.events.includes('download'));
    assert.ok(result.events.includes('launch'));
  });
}

for (const defender of ['policy_error', 'no_op', 'exclusion_no_op', 'exclusion_policy_error', 'unknown', 'string_state', 'unknown_after_disable']) {
  test(`Windows stops before download when Defender cannot be disabled safely: ${defender}`, { skip: process.platform !== 'win32' }, t => {
    const result = runMockWindowsInstall(t, { defender });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Defender/i);
    if (defender === 'policy_error') assert.match(result.stderr, /mock Defender policy rejected change/);
    if (defender === 'exclusion_policy_error') assert.match(result.stderr, /mock Defender policy rejected exclusion/);
    if (defender === 'no_op') {
      assert.ok(result.events.filter(event => event === 'defender-status').length <= 6, result.events.join(', '));
      assert.match(result.stderr, /RealTimeProtectionEnabled=True/);
      assert.match(result.stderr, /DisableIOAVProtection=False/);
    }
    if (defender === 'no_op' || defender === 'exclusion_no_op') assert.match(result.stderr, /AgentFolderExcluded=unverified/);
    if (defender === 'unknown_after_disable') assert.match(result.stderr, /RealTimeProtectionEnabled=unknown/);
    if (defender === 'unknown' || defender === 'string_state') assert.equal(result.events.includes('defender-disable'), false);
    assert.equal(result.events.includes('download'), false);
    assert.equal(result.events.includes('launch'), false);
    assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_STARTED/);
    assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
  });
}

test('PowerShell 5.1 executes install flow with the expected detached command', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp('CYBERCORE_CALDERA_STARTED:' + paw));
  const launch = JSON.parse(fs.readFileSync(path.join(result.temporary, 'launch.json'), 'utf8'));
  assert.equal(launch.file, path.join(result.agentDir, 'mitre-sandcat.exe'));
  assert.deepEqual(launch.arguments, ['-server', serverUrl, '-group', group, '-paw', paw, '-v']);
  assert.equal(fs.readFileSync(path.join(result.agentDir, 'agent.pid'), 'utf8'), '2147483646');
});

for (const download of ['failure', 'html']) {
  test(`Windows ${download} download fails before launching an agent`, { skip: process.platform !== 'win32' }, t => {
    const result = runMockWindowsInstall(t, { download });
    assert.equal(result.status, 1);
    assert.match(result.stderr, download === 'failure' ? /mock download failed/ : /did not return a Windows executable/);
    assert.doesNotMatch(result.stderr, /Windows security software blocked MITRE Sandcat/);
    assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_STARTED/);
    assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
    assert.equal(fs.readdirSync(result.agentDir).some(name => name.endsWith('.download')), false);
  });
}

for (const [stage, code] of [
  ['read', -2147024671], ['read', -2147024670],
  ['launch', 225], ['launch', 226],
]) {
  test(`Windows explains security block at ${stage} with error ${code}`, { skip: process.platform !== 'win32' }, t => {
    const result = runMockWindowsInstall(t, stage === 'read' ? { readError: code } : { launchError: code });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Windows security software blocked MITRE Sandcat/);
    assert.match(result.stderr, /Protection history/);
    assert.match(result.stderr, /approved lab policy/);
    assert.ok(result.stderr.includes(result.agentDir), result.stderr);
    assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_STARTED/);
    assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
    assert.equal(fs.existsSync(path.join(result.agentDir, 'agent.pid')), false);
    assert.equal(fs.readdirSync(result.agentDir).some(name => name.endsWith('.download')), false);
  });
}

test('Windows preserves ordinary access-denied errors without labeling them as antivirus', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { readError: -2147024891 });
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /mock wrapped file read failed/);
  assert.doesNotMatch(result.stderr, /Windows security software blocked MITRE Sandcat/);
  assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_STARTED/);
  assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
  assert.equal(fs.readdirSync(result.agentDir).some(name => name.endsWith('.download')), false);
});

test('Windows refuses a stale PID belonging to an unrelated executable', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { existing: true });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /saved PID belongs to another process/);
  assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
});
