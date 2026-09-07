'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildInstallScript } = require('../src/utils/wazuh-agent-scripts');

const agentName = 'cc-11111111222243338444555555555555-100-0123456789abcdef';
const record = '001 ' + agentName + ' any ' + 'a'.repeat(64);
const agentKey = Buffer.from(record).toString('base64');
const options = { platform: 'linux', manager: 'wazuh.example.test', version: '4.14.7-1', agentName, agentKey };
const linux = buildInstallScript(options);
const windows = buildInstallScript({ ...options, platform: 'windows' });

test('installer rejects malformed, mismatched and shell-bearing arguments', () => {
  const invalid = {
    platform: [undefined, {}, 'darwin', 'linux;id'],
    manager: [null, '', 'https://wazuh.example.test', 'host:1514', 'bad_host', 'bad..name',
      'host/path', 'host\n', 'host\r', "host';whoami", 'host$(id)', 'host`whoami`', 'fe80::1%evil', 'a'.repeat(254)],
    version: [undefined, 'latest', '4.14.7', '5.0.0-1', '4.14.7-1\n', "4.14.7-1';id", '4.014.7-1'],
    agentName: [null, 'agent-1', '../lane', 'cc-a\n', "cc-a';id", 'cc-' + 'a'.repeat(126)],
    agentKey: [null, '', agentKey + '\n', agentKey + ';id', agentKey + '=',
      Buffer.from('001 unrelated any ' + 'a'.repeat(64)).toString('base64'),
      Buffer.from('000 ' + agentName + ' any ' + 'a'.repeat(64)).toString('base64'),
      Buffer.from(record + '\n').toString('base64'),
      Buffer.from(record.replace('001 ', '001\n ')).toString('base64'),
      Buffer.from(record.replace(' any ', ' 10.0.0.1 ')).toString('base64'),
      Buffer.from(record.replace(/a$/, 'x')).toString('base64')],
  };
  for (const [field, values] of Object.entries(invalid)) {
    for (const value of values) {
      assert.throws(() => buildInstallScript({ ...options, [field]: value }), TypeError, field + ': ' + String(value));
    }
  }
  for (const manager of ['10.0.0.5', '2001:db8::1', 'wazuh', 'wazuh.example.test']) {
    assert.doesNotThrow(() => buildInstallScript({ ...options, manager }));
  }
});

test('both installers pin official packages, verify SHA512 and import keys through stdin', () => {
  for (const script of [linux, windows]) {
    assert.match(script, /https:\/\/packages\.wazuh\.com\/4\.x\//);
    assert.match(script, /sha512/i);
    assert.match(script, /4\.14\.7-1/);
    assert.match(script, /manage_agents/);
    assert.match(script, /CYBERCORE_WAZUH_STARTED:/);
    assert.match(script, /CYBERCORE_WAZUH_ERROR:/);
    assert.match(script, /identity-conflict/);
    assert.match(script, /manager-conflict/);
    assert.match(script, /installation-busy/);
    assert.doesNotMatch(script, /Set-MpPreference|Add-MpPreference|DisableRealtime|SkipCertificateCheck|ServerCertificateValidationCallback|Bearer|api_key|password/i);
    assert.doesNotMatch(script, /['"]-i['"]/);
  }
  assert.match(linux, /input_data=\('I\\n' \+ AGENT_KEY/);
  assert.match(windows, /StandardInput\.Write\(\$InputText\)/);
  assert.match(linux, /enrollment = add\(client, 'enrollment'\)\n    add\(enrollment, 'enabled', 'no'\)/);
  assert.match(windows, /\$enabled.InnerText = 'no'/);
  assert.match(linux, /'amd64'.*'x86_64'/);
  assert.match(linux, /'arm64'.*'aarch64'|'aarch64'.*'arm64'/);
  assert.match(windows, /@\('AMD64', 'x86'\)/);
  assert.match(windows, /\/norestart REBOOT=ReallySuppress/);
  assert.match(linux, /--no-remove/);
});

const shell = process.platform === 'win32'
  ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'].find(candidate => fs.existsSync(candidate))
  : '/bin/sh';
const python = ['python3', 'python'].find(command => spawnSync(command, ['--version'], { encoding: 'utf8', timeout: 5000 }).status === 0);
const powershell = process.platform === 'win32' ? 'powershell.exe' : null;
const pythonSource = linux.split("exec python3 - <<'CYBERCORE_WAZUH_PY'\n")[1].split('\nCYBERCORE_WAZUH_PY\n')[0];

test('Linux downloads published package/checksum paths and rejects a corrupted package', { skip: !python }, () => {
  const script = buildInstallScript({ ...options, version: '4.14.1-1' });
  const source = script.split("exec python3 - <<'CYBERCORE_WAZUH_PY'\n")[1].split('\nCYBERCORE_WAZUH_PY\n')[0];
  const downloadSection = source.slice(source.indexOf('            deb_arch ='), source.indexOf("                STAGE = 'package-install-failed'"));
  const helpers = source.split("if __name__ == '__main__':")[0].replace('import fcntl', 'fcntl = None');
  for (const [packageManager, architecture, filename, packageDirectory] of [
    ['deb', 'x86_64', 'wazuh-agent_4.14.1-1_amd64.deb', 'apt/pool/main/w/wazuh-agent'],
    ['deb', 'aarch64', 'wazuh-agent_4.14.1-1_arm64.deb', 'apt/pool/main/w/wazuh-agent'],
    ['rpm', 'x86_64', 'wazuh-agent-4.14.1-1.x86_64.rpm', 'yum'],
    ['rpm', 'aarch64', 'wazuh-agent-4.14.1-1.aarch64.rpm', 'yum'],
  ]) {
    for (const corrupt of [false, true]) {
      const code = helpers + `
import json, textwrap
architecture = ${JSON.stringify(architecture)}
shutil.which = lambda command: command if command in ${packageManager === 'deb' ? "('dpkg', 'apt-get')" : "('rpm',)"} else None
requested = []
def download(url, destination, max_bytes):
    requested.append(url)
    payload = b'fixture package'
    if url.endswith('.sha512'):
        # Published files contain a hash followed by a filename or /tmp/filename.
        payload = (hashlib.sha512(payload).hexdigest() + '  /tmp/${filename}\\n').encode()
    elif ${corrupt ? 'True' : 'False'}:
        payload += b'corrupted'
    Path(destination).write_bytes(payload)
try:
    exec(textwrap.dedent(${JSON.stringify(downloadSection)}))
    error = None
except InstallError as exception:
    error = str(exception)
print(json.dumps({'requested': requested, 'error': error}))
`;
      const result = spawnSync(python, ['-'], { input: code, encoding: 'utf8', timeout: 10000 });
      assert.equal(result.status, 0, result.stdout + result.stderr);
      const data = JSON.parse(result.stdout);
      assert.deepEqual(data.requested, [
        `https://packages.wazuh.com/4.x/${packageDirectory}/${filename}`,
        `https://packages.wazuh.com/4.x/checksums/wazuh/4.14.1/${filename}.sha512`,
      ]);
      assert.equal(data.error, corrupt ? 'checksum-mismatch' : null);
    }
  }
});

test('Windows downloads the published checksum path and rejects a corrupted MSI', { skip: !powershell }, t => {
  const script = buildInstallScript({ ...options, platform: 'windows', version: '4.14.1-1' });
  const downloadSection = script.slice(script.indexOf("    $package = Join-Path $workDir"), script.indexOf("    $script:stage = 'package-install-failed'"));
  const helpers = script.split('\ntry {\n  $identity =')[0];
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-download-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  for (const corrupt of [false, true]) {
    const code = helpers + `
$workDir = $env:WAZUH_TEST_DIRECTORY
$requested = New-Object 'Collections.Generic.List[string]'
function Invoke-WebRequest($Uri, $OutFile, $TimeoutSec, $MaximumRedirection, [switch]$UseBasicParsing) {
  $requested.Add([string]$Uri)
  $payload = [Text.Encoding]::ASCII.GetBytes('fixture package')
  if ($Uri.EndsWith('.sha512')) {
    $hasher = [Security.Cryptography.SHA512]::Create()
    try { $hash = ([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace('-', '').ToLowerInvariant() } finally { $hasher.Dispose() }
    $payload = [Text.Encoding]::ASCII.GetBytes($hash + '  /tmp/wazuh-agent-4.14.1-1.msi' + [Environment]::NewLine)
  } elseif ($${corrupt}) { $payload = [Text.Encoding]::ASCII.GetBytes('corrupted') }
  [IO.File]::WriteAllBytes($OutFile, $payload)
}
try {
${downloadSection}
} catch { if (-not $script:publicError) { throw } }
@{ requested = @($requested); error = $script:publicError } | ConvertTo-Json -Compress
`;
    const scriptFile = path.join(temporary, 'download-fixture.ps1');
    fs.writeFileSync(scriptFile, code);
    const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptFile], {
      encoding: 'utf8', timeout: 15000, env: { ...process.env, WAZUH_TEST_DIRECTORY: temporary },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const data = JSON.parse(result.stdout);
    assert.deepEqual(data.requested, [
      'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi',
      'https://packages.wazuh.com/4.x/checksums/wazuh/4.14.1/wazuh-agent-4.14.1-1.msi.sha512',
    ]);
    assert.equal(data.error, corrupt ? 'checksum-mismatch' : null);
  }
});

test('generated Linux shell and Python parse without execution', { skip: !shell || !python }, () => {
  const shellResult = spawnSync(shell, ['-n'], { input: linux, encoding: 'utf8', timeout: 10000 });
  assert.equal(shellResult.status, 0, shellResult.stderr);
  const pythonResult = spawnSync(python, ['-c', 'import ast,sys; ast.parse(sys.stdin.read())'], { input: pythonSource, encoding: 'utf8', timeout: 10000 });
  assert.equal(pythonResult.status, 0, pythonResult.stderr);
});

test('generated Windows script parses in PowerShell without execution', { skip: !powershell }, t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-syntax-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const scriptFile = path.join(temporary, 'installer.ps1');
  fs.writeFileSync(scriptFile, windows);
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    '$tokens=$null; $errors=$null; $null=[Management.Automation.Language.Parser]::ParseFile($env:WAZUH_TEST_SCRIPT,[ref]$tokens,[ref]$errors); if($errors.Count) { $errors | ForEach-Object { $_.Message }; exit 1 }'], {
    encoding: 'utf8', timeout: 10000, env: { ...process.env, WAZUH_TEST_SCRIPT: scriptFile },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

const initialConfig = manager => `<!-- fixture collector comment -->
<ossec_config><client><server><address>${manager}</address><port>1514</port><protocol>tcp</protocol></server><enrollment><enabled>yes</enabled></enrollment><config-profile>linux</config-profile></client>
<localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile></ossec_config>
<ossec_config><syscheck><disabled>no</disabled><directories>/etc</directories></syscheck></ossec_config>`;

function fixture(t, platform, manager, key = record, sourceConfig) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-config-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const configDirectory = platform === 'linux' ? path.join(temporary, 'etc') : temporary;
  fs.mkdirSync(configDirectory, { recursive: true });
  if (platform === 'linux') {
    fs.mkdirSync(path.join(temporary, 'bin'));
    fs.writeFileSync(path.join(temporary, 'bin', 'manage_agents'), 'fixture-only; never execute');
  }
  const configFile = path.join(configDirectory, 'ossec.conf');
  fs.writeFileSync(configFile, sourceConfig ?? initialConfig(manager));
  fs.writeFileSync(path.join(configDirectory, 'client.keys'), key ? key + '\n' : '');
  return { temporary, configFile };
}

// Only configuration helper definitions run here. No main entry point, package
// installer, download, key-import process, host service or prevention setting.
function runConfigurationHelpers(t, platform, { manager = options.manager, key = record, action = 'configure', sourceConfig } = {}) {
  const { temporary, configFile } = fixture(t, platform, manager, key, sourceConfig);
  let result;
  if (platform === 'linux') {
    const code = pythonSource.split("if __name__ == '__main__':")[0].replace('import fcntl', 'fcntl = None') + `
AGENT_DIR = Path(os.environ['WAZUH_TEST_DIRECTORY'])
os.chown = lambda *args: None
try:
    check_existing()
    if os.environ['WAZUH_TEST_ACTION'] == 'configure':
        configure()
        first = (AGENT_DIR / 'etc/ossec.conf').read_text()
        configure()
        assert first == (AGENT_DIR / 'etc/ossec.conf').read_text()
        check_existing()
    print('fixture-ok')
except InstallError as error:
    print(str(error))
    sys.exit(2)
`;
    result = spawnSync(python, ['-'], { input: code, encoding: 'utf8', timeout: 10000,
      env: { ...process.env, WAZUH_TEST_DIRECTORY: temporary, WAZUH_TEST_ACTION: action } });
  } else {
    const helpers = windows.split('\ntry {\n  $identity =')[0];
    const code = helpers + `
$agentDir = $env:WAZUH_TEST_DIRECTORY
$configFile = Join-Path $agentDir 'ossec.conf'
try {
  Assert-WazuhOwnership
  if ($env:WAZUH_TEST_ACTION -eq 'configure') {
    Set-WazuhConfiguration
    $first = [IO.File]::ReadAllText($configFile)
    Set-WazuhConfiguration
    if ($first -cne [IO.File]::ReadAllText($configFile)) { throw 'configuration is not idempotent' }
    Assert-WazuhOwnership
  }
  Write-Output 'fixture-ok'
} catch {
  Write-Output $script:publicError
  if (-not $script:publicError) { Write-Output $_.Exception.Message }
  exit 2
}
`;
    const fixtureScript = path.join(temporary, 'fixture.ps1');
    fs.writeFileSync(fixtureScript, code);
    result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fixtureScript], {
      encoding: 'utf8', timeout: 15000, env: { ...process.env, WAZUH_TEST_DIRECTORY: temporary, WAZUH_TEST_ACTION: action },
    });
  }
  return { result, config: fs.readFileSync(configFile, 'utf8') };
}

// Client stanza and event-channel settings from the official Windows 4.14.1
// default: https://github.com/wazuh/wazuh/blob/v4.14.1/src/win32/ossec.conf
const windowsDefaultConfig = `<ossec_config>
  <client>
    <server>
      <address>0.0.0.0</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>
  <localfile><location>Application</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>System</location><log_format>eventchannel</log_format></localfile>
</ossec_config>`;

test('Windows configures the actual unregistered MSI default and preserves event collection', { skip: !powershell }, t => {
  const { result, config } = runConfigurationHelpers(t, 'windows', { key: '', sourceConfig: windowsDefaultConfig });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(config, /<address>0\.0\.0\.0<\/address>/);
  assert.match(config, /<address>wazuh\.example\.test<\/address>/);
  assert.match(config, /<enabled>no<\/enabled>/);
  for (const value of ['<notify_time>20</notify_time>', '<time-reconnect>60</time-reconnect>',
    '<auto_restart>yes</auto_restart>', '<location>Application</location>', '<location>System</location>']) {
    assert.ok(config.includes(value), value);
  }
  assert.equal((config.match(/<log_format>eventchannel<\/log_format>/g) || []).length, 2);
});

test('Windows default-manager exception cannot take over an existing identity or real manager', { skip: !powershell }, t => {
  for (const [key, sourceConfig, expected] of [
    [record, windowsDefaultConfig, 'manager-conflict'],
    [record.replace('001 ', '002 '), windowsDefaultConfig, 'identity-conflict'],
    ['', windowsDefaultConfig.replace('0.0.0.0', 'lane-siem.example.test'), 'manager-conflict'],
  ]) {
    const { result, config } = runConfigurationHelpers(t, 'windows', { key, sourceConfig });
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.match(result.stdout, new RegExp(expected));
    assert.equal(config, sourceConfig);
  }
});

for (const platform of ['linux', 'windows']) {
  const skip = platform === 'linux' ? !python : !powershell;
  test(`${platform} retains collection settings and safely reconciles the same key on retries`, { skip }, t => {
    const { result, config } = runConfigurationHelpers(t, platform);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(config, /fixture collector comment/);
    assert.match(config, /<location>\/var\/log\/auth.log<\/location>/);
    assert.match(config, /<directories>\/etc<\/directories>/);
    assert.equal((config.match(/<ossec_config>/g) || []).length, 2);
    assert.equal((config.match(/<server>/g) || []).length, 1);
    assert.match(config, /<enabled>no<\/enabled>/);
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp(agentKey));
  });

  test(`${platform} configures an installed but unregistered agent`, { skip }, t => {
    const { result, config } = runConfigurationHelpers(t, platform, { manager: 'MANAGER_IP', key: '' });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(config, new RegExp('<address>' + options.manager.replaceAll('.', '\\.') + '</address>'));
    assert.match(config, /<enabled>no<\/enabled>/);
  });

  for (const conflict of ['manager', 'identity']) {
    test(`${platform} refuses a different ${conflict} before changing configuration`, { skip }, t => {
      const manager = conflict === 'manager' ? 'lane-siem.example.test' : options.manager;
      const key = conflict === 'identity' ? record.replace('001 ', '002 ') : record;
      const { result, config } = runConfigurationHelpers(t, platform, { manager, key });
      assert.equal(result.status, 2, result.stdout + result.stderr);
      assert.match(result.stdout, new RegExp(conflict + '-conflict'));
      assert.equal(config, initialConfig(manager));
      assert.doesNotMatch(result.stdout + result.stderr, new RegExp(agentKey));
    });
  }
}
