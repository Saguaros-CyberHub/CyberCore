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
    assert.doesNotMatch(script, /--insecure|curl\s+-[a-z]*k|SkipCertificateCheck|ServerCertificateValidationCallback|Add-MpPreference|Set-MpPreference|KEY:|api_key|pkill|killall|New-Service|Register-ScheduledTask/i);
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

// Exercise the Windows installer with only download/process launch replaced.
// All filesystem writes are restricted to an isolated temporary ProgramData.
// This verifies control flow without downloading or starting a Sandcat agent.
function runMockWindowsInstall(t, { download = 'binary', existing = false } = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'caldera-installer-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const agentDir = path.join(temporary, 'CyberCore', 'Caldera', group, paw);
  if (existing) {
    fs.mkdirSync(agentDir, { recursive: true });
    fs.writeFileSync(path.join(agentDir, 'agent.pid'), '2147483646');
  }
  const harness = `
function Invoke-WebRequest {
  param([switch]$UseBasicParsing, $Method, $Uri, $Headers, $OutFile, $TimeoutSec, $MaximumRedirection)
  if ($Method -ne 'Post' -or $Headers.platform -ne 'windows' -or $Headers.file -ne 'sandcat.go' -or $Headers.architecture -ne 'amd64') { throw 'Unexpected download contract' }
  if ($env:CALDERA_TEST_DOWNLOAD -eq 'failure') { throw 'mock download failed' }
  if ($env:CALDERA_TEST_DOWNLOAD -eq 'html') { [IO.File]::WriteAllText($OutFile, '<html>Login</html>') }
  else { [IO.File]::WriteAllBytes($OutFile, [byte[]]@(77, 90, 0, 0)) }
}
function Start-Process {
  param($FilePath, $ArgumentList, $WorkingDirectory, $WindowStyle, $RedirectStandardOutput, $RedirectStandardError, [switch]$PassThru)
  if ($WindowStyle -ne 'Hidden' -or -not $RedirectStandardOutput -or -not $RedirectStandardError) { throw 'Process must detach with logs' }
  [IO.File]::WriteAllText((Join-Path $env:ProgramData 'launch.json'), (ConvertTo-Json @{ file = $FilePath; arguments = $ArgumentList }))
  $mock = [pscustomobject]@{ Id = 2147483646; HasExited = $false }
  $mock | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
  return $mock
}
function Start-Sleep { param($Seconds) }
function Get-CimInstance { param($ClassName, $Filter) return [pscustomobject]@{ ExecutablePath = 'C:\\Unrelated\\process.exe' } }
function Stop-Process { throw 'Unrelated process must never be stopped' }
`;
  const script = harness + buildInstallScript({ ...options, platform: 'windows' });
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
    encoding: 'utf8', timeout: 20000,
    env: { ...process.env, ProgramData: temporary, PROCESSOR_ARCHITECTURE: 'AMD64', PROCESSOR_ARCHITEW6432: 'AMD64', CALDERA_TEST_DOWNLOAD: download },
  });
  return { ...result, temporary, agentDir };
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
    assert.doesNotMatch(result.stdout, /CYBERCORE_CALDERA_STARTED/);
    assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
    assert.equal(fs.readdirSync(result.agentDir).some(name => name.endsWith('.download')), false);
  });
}

test('Windows refuses a stale PID belonging to an unrelated executable', { skip: process.platform !== 'win32' }, t => {
  const result = runMockWindowsInstall(t, { existing: true });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /saved PID belongs to another process/);
  assert.equal(fs.existsSync(path.join(result.temporary, 'launch.json')), false);
});
