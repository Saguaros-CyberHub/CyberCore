'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildInstallScript } = require('../src/utils/wazuh-agent-scripts');
const { WINDOWS_BOOTSTRAP } = require('../src/utils/wazuh-guest-dispatch');

const agentName = 'enhanced-fixture-vm-100';
const rawKey = '7'.repeat(64);
const record = `017 ${agentName} any ${rawKey}`;
const agentKey = Buffer.from(record).toString('base64');
const base = { manager: 'wazuh.example.test', version: '4.14.1-1', agentName, agentKey };
const windows = buildInstallScript({ ...base, platform: 'windows', windowsTelemetry: true });
const linux = buildInstallScript({ ...base, platform: 'linux', linuxSuricata: true });
const pythonSource = linux.split("exec python3 - 3<&0 <<'CYBERCORE_WAZUH_PY'\n")[1].split('\nCYBERCORE_WAZUH_PY\n')[0];
const powershell = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
const hasPowerShell = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { timeout: 10000, windowsHide: true }).status === 0;
const python = ['python3', 'python'].find(binary => spawnSync(binary, ['--version'], { timeout: 5000 }).status === 0);
const shell = process.platform === 'win32'
  ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'].find(file => fs.existsSync(file)) : '/bin/sh';

function noSecrets(text) {
  for (const secret of [agentKey, record, rawKey]) assert.equal(String(text).includes(secret), false, 'fixture credential appeared in source, argv or output');
}

function fixture(t, platform, extraCollector = '') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-enhanced-test-'));
  const configDirectory = platform === 'linux' ? path.join(directory, 'etc') : directory;
  fs.mkdirSync(configDirectory, { recursive: true });
  if (platform === 'linux') {
    fs.mkdirSync(path.join(directory, 'bin'));
    fs.writeFileSync(path.join(directory, 'bin', 'manage_agents'), 'fixture only; never execute');
  }
  const configFile = path.join(configDirectory, platform === 'linux' ? 'ossec.conf' : 'ossec.conf');
  fs.writeFileSync(configFile, `<!-- preserve-existing-collector-comment -->
<ossec_config><client><server><address>${base.manager}</address><port>1514</port><protocol>tcp</protocol></server><enrollment><enabled>yes</enabled></enrollment><config-profile>fixture</config-profile></client>
<localfile><log_format>syslog</log_format><location>/fixture/retained.log</location></localfile>${extraCollector}</ossec_config>
<ossec_config><syscheck><disabled>no</disabled><directories>/fixture/retained-directory</directories></syscheck></ossec_config>`);
  fs.writeFileSync(path.join(configDirectory, 'client.keys'), record + '\n');
  t.after(() => {
    // Delete only individual files in this fixture's verified generated directory.
    for (const child of [configDirectory, ...(platform === 'linux' ? [path.join(directory, 'bin')] : [])]) {
      assert.ok(child === directory || child.startsWith(directory + path.sep));
      for (const name of fs.readdirSync(child)) if (fs.statSync(path.join(child, name)).isFile()) fs.unlinkSync(path.join(child, name));
      if (child !== directory) fs.rmdirSync(child);
    }
    for (const name of fs.readdirSync(directory)) fs.unlinkSync(path.join(directory, name));
    fs.rmdirSync(directory);
  });
  return { directory, configFile };
}

function preserveConfig(config) {
  assert.ok(config.includes('preserve-existing-collector-comment'));
  assert.ok(config.includes('/fixture/retained.log'));
  assert.ok(config.includes('/fixture/retained-directory'));
  assert.equal((config.match(/<ossec_config>/g) || []).length, 2);
  assert.match(config, /<enrollment>\s*<enabled>no<\/enabled>\s*<\/enrollment>/);
  assert.match(config, /<config-profile>fixture<\/config-profile>/);
}

test('complete enhanced Windows and Linux sources contain no credentials and stay within dispatch bounds', () => {
  for (const source of [windows, linux]) {
    noSecrets(source);
    assert.ok(Buffer.byteLength(source) < 96 * 1024);
    assert.equal(/[^\x09\x0a\x0d\x20-\x7e]/.test(source), false);
  }
  assert.match(windows, /function Enable-CyberCoreWindowsTelemetry/);
  assert.match(pythonSource, /def configure_suricata\(\):/);
});

test('fully generated enhanced Windows source parses in PowerShell', { skip: !hasPowerShell }, () => {
  const command = '$source=[Console]::In.ReadToEnd(); $tokens=$null; $errors=$null; $null=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors); if($errors.Count) { $errors | ForEach-Object { $_.Message }; exit 1 }';
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(command, 'utf16le').toString('base64')], {
    input: windows, encoding: 'utf8', timeout: 15000, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('fully generated enhanced Linux source parses as shell and Python', { skip: !python || !shell }, () => {
  const sh = spawnSync(shell, ['-n'], { input: linux, encoding: 'utf8', timeout: 10000 });
  assert.equal(sh.status, 0, sh.stderr);
  const py = spawnSync(python, ['-c', 'import ast,sys; ast.parse(sys.stdin.read())'], { input: pythonSource, encoding: 'utf8', timeout: 10000 });
  assert.equal(py.status, 0, py.stderr);
});

function windowsLifecycle(t, outcome, extraCollector = '') {
  const { directory, configFile } = fixture(t, 'windows', extraCollector);
  // Execute the actual generated configuration functions and service lifecycle.
  // Package/preflight code is excluded; platform services and telemetry setup are
  // mocked. All filesystem writes stay inside this test's temporary directory.
  const helpers = windows.slice(0, windows.indexOf('\ntry {\n$identity ='));
  const lifecycleStart = windows.indexOf("$script:stage = 'service-stop-failed'\n$service =");
  assert.ok(lifecycleStart > 0);
  const lifecycle = windows.slice(lifecycleStart).replace(
    '} finally {\nforeach ($temporary',
    "} finally {\n[Console]::Out.WriteLine('FIXTURE_STATE:' + (@{status=[string]$script:fixtureService.Status; events=@($script:fixtureEvents)} | ConvertTo-Json -Compress))\nforeach ($temporary");
  const mocks = `
Add-Type -AssemblyName System.ServiceProcess
$agentDir = $env:WAZUH_FIXTURE_DIRECTORY
$workDir = $agentDir
$configFile = Join-Path $agentDir 'ossec.conf'
$script:fixtureEvents = New-Object 'Collections.Generic.List[string]'
$script:fixtureService = [PSCustomObject]@{ Status = 'Running' }
$script:fixtureService | Add-Member ScriptMethod Stop { $script:fixtureEvents.Add('stop'); $this.Status = 'Stopped' }
$script:fixtureService | Add-Member ScriptMethod Start { $script:fixtureEvents.Add('start'); $this.Status = 'Running' }
$script:fixtureService | Add-Member ScriptMethod Refresh { $script:fixtureEvents.Add('refresh') }
$script:fixtureService | Add-Member ScriptMethod WaitForStatus { param($Status, $Timeout); if ([string]$Status -ne $this.Status) { throw 'mock-service-not-ready' }; $script:fixtureEvents.Add('ready-' + [string]$Status) }
function Get-Service { param($Name); if ($Name -ne 'WazuhSvc') { throw 'unexpected-service' }; return $script:fixtureService }
function Set-Service { param($Name, $StartupType); if ($Name -ne 'WazuhSvc' -or $StartupType -ne 'Automatic') { throw 'unexpected-service' }; $script:fixtureEvents.Add('enable') }
function Get-Acl { param($LiteralPath); return [PSCustomObject]@{ Fixture = $true } }
function Set-Acl { param($LiteralPath, $AclObject); if (-not $LiteralPath.StartsWith($env:WAZUH_FIXTURE_DIRECTORY)) { throw 'unsafe-test-path' } }
function Enable-CyberCoreWindowsTelemetry {
  param($AgentRoot)
  $script:fixtureEvents.Add('telemetry-' + [string]$script:fixtureService.Status)
  if ($script:fixtureService.Status -ne 'Running') { throw 'monitoring-not-restored-before-telemetry' }
  if ($env:WAZUH_FIXTURE_OUTCOME -eq 'throw') { throw 'private-upstream-detail' }
  return [PSCustomObject]@{ Complete = ($env:WAZUH_FIXTURE_OUTCOME -eq 'complete'); Channels = @('Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational'); Warnings = @() }
}
try {
`;
  const source = helpers + mocks + lifecycle;
  noSecrets(source);
  const argv = ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(WINDOWS_BOOTSTRAP, 'utf16le').toString('base64')];
  noSecrets(argv.join(' '));
  const result = spawnSync(powershell, argv, { input: `${agentKey}\n\n${source}`, encoding: 'utf8', timeout: 20000, windowsHide: true,
    env: { ...process.env, WAZUH_FIXTURE_DIRECTORY: directory, WAZUH_FIXTURE_OUTCOME: outcome } });
  noSecrets(result.stdout + result.stderr);
  assert.equal((result.stdout + result.stderr).includes('private-upstream-detail'), false);
  const stateLine = result.stdout.split(/\r?\n/).find(line => line.startsWith('FIXTURE_STATE:'));
  assert.ok(stateLine, result.stdout + result.stderr);
  return { ...result, state: JSON.parse(stateLine.slice('FIXTURE_STATE:'.length)), config: fs.readFileSync(configFile, 'utf8') };
}

for (const outcome of ['complete', 'incomplete', 'throw']) {
  test(`enhanced Windows ${outcome}: baseline monitoring runs during setup and survives final outcome`, { skip: !hasPowerShell }, t => {
    const result = windowsLifecycle(t, outcome);
    assert.equal(result.status, outcome === 'complete' ? 0 : 1, result.stdout + result.stderr);
    assert.equal(result.state.status, 'Running');
    assert.ok(result.state.events.includes('telemetry-Running'));
    assert.equal(result.state.events.filter(event => event === 'start').length, 2);
    assert.ok(result.state.events.indexOf('start') < result.state.events.indexOf('telemetry-Running'));
    assert.match(result.stdout, new RegExp(`CYBERCORE_WAZUH_STARTED:${agentName}`));
    assert.match(result.stdout, new RegExp(`CYBERCORE_WAZUH_TELEMETRY:${outcome === 'complete' ? 'configured' : 'incomplete'}`));
    if (outcome !== 'complete') assert.match(result.stderr, /CYBERCORE_WAZUH_ERROR:windows-telemetry-incomplete/);
    preserveConfig(result.config);
    if (outcome !== 'throw') {
      assert.equal((result.config.match(/<location>Microsoft-Windows-Sysmon\/Operational<\/location>/g) || []).length, 1);
      assert.equal((result.config.match(/<location>Microsoft-Windows-PowerShell\/Operational<\/location>/g) || []).length, 1);
    }
  });
}

test('enhanced Windows preserves existing filtered collectors and reports an incompatible collector', { skip: !hasPowerShell }, t => {
  const extra = '<localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>syslog</log_format><query>fixture-filter</query></localfile>';
  const result = windowsLifecycle(t, 'complete', extra);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.state.status, 'Running');
  assert.match(result.stdout, /CYBERCORE_WAZUH_TELEMETRY_WARNING:collector-existing-format/);
  assert.match(result.stdout, /CYBERCORE_WAZUH_TELEMETRY_WARNING:collector-existing-filter/);
  assert.equal((result.config.match(/Microsoft-Windows-Sysmon\/Operational/g) || []).length, 1);
  assert.ok(result.config.includes('<query>fixture-filter</query>'));
  preserveConfig(result.config);
});

function linuxLifecycle(t, outcome, extraCollector = '') {
  const { directory, configFile } = fixture(t, 'linux', extraCollector);
  // Feed the real fd3 key reader with a pipe. Source stays on stdin; keys remain
  // the first two lines, exactly as guest dispatch supplies them. fcntl is mocked
  // on Windows so the same Python fixture runs on developer PCs and Linux CI.
  const bootstrap = [
    'import os, sys, types',
    "key_input = sys.stdin.readline() + sys.stdin.readline()",
    'source = sys.stdin.read()',
    'reader, writer = os.pipe()',
    "os.write(writer, key_input.encode('ascii')); os.close(writer)",
    'if reader != 3: os.dup2(reader, 3); os.close(reader)',
    "sys.modules['fcntl'] = types.SimpleNamespace(flock=lambda *a: None, LOCK_EX=1, LOCK_NB=2)",
    "exec(compile(source, '<enhanced-fixture>', 'exec'), {'__name__': '__main__'})",
  ].join('\n');
  const mocks = `
import atexit, builtins
AGENT_DIR = Path(os.environ['WAZUH_FIXTURE_DIRECTORY'])
os.geteuid = lambda: 0
os.chown = lambda *args: None
platform.system = lambda: 'Linux'
platform.machine = lambda: 'x86_64'
shutil.which = lambda command: '/fixture/' + command
_original_is_dir = Path.is_dir
Path.is_dir = lambda value: True if str(value).replace('\\\\', '/') == '/run/systemd/system' else _original_is_dir(value)
_original_open = builtins.open
def open(file, *args, **kwargs):
    if str(file) == '/run/cybercore-wazuh-install.lock': file = AGENT_DIR / 'fixture.lock'
    return _original_open(file, *args, **kwargs)
fixture_state = {'status': 'Running', 'events': []}
def run(args, timeout=60, input_data=None, env=None):
    if args[0] != 'systemctl': raise AssertionError('unexpected process')
    action = args[1]
    fixture_state['events'].append(action)
    if action == 'stop': fixture_state['status'] = 'Stopped'
    if action in ('start', 'restart'): fixture_state['status'] = 'Running'
    if action == 'is-active' and fixture_state['status'] != 'Running': raise AssertionError('service not running')
    return subprocess.CompletedProcess(args, 0, b'')
def configure_suricata():
    global SURICATA_RESULT
    fixture_state['events'].append('telemetry-' + fixture_state['status'])
    if fixture_state['status'] != 'Running': raise AssertionError('monitoring not restored')
    if os.environ['WAZUH_FIXTURE_OUTCOME'] == 'throw': raise RuntimeError('private-upstream-detail')
    SURICATA_RESULT = {'complete': os.environ['WAZUH_FIXTURE_OUTCOME'] == 'complete', 'warnings': []}
    return SURICATA_RESULT
atexit.register(lambda: print('FIXTURE_STATE:' + json.dumps(fixture_state)))
`;
  const source = pythonSource.replace("if __name__ == '__main__':", mocks + "\nif __name__ == '__main__':");
  noSecrets(source);
  noSecrets(bootstrap);
  const result = spawnSync(python, ['-c', bootstrap], { input: `${agentKey}\n\n${source}`, encoding: 'utf8', timeout: 20000,
    env: { ...process.env, WAZUH_FIXTURE_DIRECTORY: directory, WAZUH_FIXTURE_OUTCOME: outcome } });
  noSecrets(result.stdout + result.stderr);
  assert.equal((result.stdout + result.stderr).includes('private-upstream-detail'), false);
  const stateLine = result.stdout.split(/\r?\n/).find(line => line.startsWith('FIXTURE_STATE:'));
  assert.ok(stateLine, result.stdout + result.stderr);
  return { ...result, state: JSON.parse(stateLine.slice('FIXTURE_STATE:'.length)), config: fs.readFileSync(configFile, 'utf8') };
}

for (const outcome of ['complete', 'incomplete', 'throw']) {
  test(`enhanced Linux ${outcome}: full main restores monitoring before sensor setup and final markers`, { skip: !python }, t => {
    const result = linuxLifecycle(t, outcome);
    assert.equal(result.status, outcome === 'complete' ? 0 : 1, result.stdout + result.stderr);
    assert.equal(result.state.status, 'Running');
    assert.ok(result.state.events.includes('telemetry-Running'));
    assert.ok(result.state.events.indexOf('start') < result.state.events.indexOf('telemetry-Running'));
    assert.ok(result.state.events.indexOf('restart') > result.state.events.indexOf('telemetry-Running'));
    assert.match(result.stdout, new RegExp(`CYBERCORE_WAZUH_STARTED:${agentName}`));
    assert.match(result.stdout, new RegExp(`CYBERCORE_WAZUH_TELEMETRY:${outcome === 'complete' ? 'configured' : 'incomplete'}`));
    if (outcome !== 'complete') assert.match(result.stderr, /CYBERCORE_WAZUH_ERROR:suricata-incomplete/);
    preserveConfig(result.config);
    if (outcome === 'complete') {
      assert.equal((result.config.match(/cybercore-suricata[\\/]eve\.json/g) || []).length, 1);
      assert.match(result.config, /<log_format>json<\/log_format>/);
    }
  });
}

test('enhanced Linux preserves an incompatible existing sensor collector and reports incomplete setup', { skip: !python }, t => {
  const extra = '<localfile><location>*cybercore-suricata*eve.json</location><log_format>syslog</log_format></localfile>';
  const result = linuxLifecycle(t, 'complete', extra);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.state.status, 'Running');
  assert.match(result.stdout, /CYBERCORE_WAZUH_TELEMETRY_WARNING:suricata-collector-conflict/);
  assert.match(result.stdout, /CYBERCORE_WAZUH_TELEMETRY:incomplete/);
  assert.ok(result.config.includes('<location>*cybercore-suricata*eve.json</location>'));
  assert.equal((result.config.match(/cybercore-suricata/g) || []).length, 1);
  preserveConfig(result.config);
});
