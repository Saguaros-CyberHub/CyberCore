'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildWindowsTelemetryFunctions, SYSMON_PROFILE_XML, TELEMETRY_CHANNELS, TELEMETRY_WARNINGS } = require('../src/utils/wazuh-windows-telemetry');

const functions = buildWindowsTelemetryFunctions();
const powershell = process.platform === 'win32' ? 'powershell.exe' : null;
const bootstrap = "$ErrorActionPreference='Stop'; $source=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($source))";
function runPowerShell(body, prefix = functions) {
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(bootstrap, 'utf16le').toString('base64')], {
    input: prefix + '\n' + body, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(result.status, 0, `PowerShell helper failed: ${result.stderr || result.stdout}`);
  return JSON.parse(result.stdout.trim());
}
const psText = text => `([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(text).toString('base64')}')))`;

test('telemetry profile uses three principal activity sources and excludes expensive collection', () => {
  assert.match(SYSMON_PROFILE_XML, /<HashAlgorithms>SHA256<\/HashAlgorithms>/);
  for (const event of ['ProcessCreate', 'NetworkConnect', 'DnsQuery']) assert.match(SYSMON_PROFILE_XML, new RegExp(`<${event} onmatch="exclude" />`));
  for (const event of ['ImageLoad', 'ProcessAccess', 'FileCreate', 'FileDelete', 'ClipboardChange']) assert.match(SYSMON_PROFILE_XML, new RegExp(`<${event} onmatch="include" />`));
  assert.doesNotMatch(functions, /Set-MpPreference|Add-MpPreference|DisableRealtime|Start-Transcript|Set-ExecutionPolicy|EnableScriptBlockInvocationLogging.*SetValue|SkipCertificateCheck|ServerCertificateValidationCallback|DownloadString|Invoke-Expression/i);
  assert.doesNotMatch(functions, /sysmon[^\n]*\s-u\b|sysmon[^\n]*\s-c\b/i);
  assert.match(functions, /-NoRestart/);
  assert.match(functions, /-TimeoutSec 60/);
  assert.match(functions, /WaitForExit\(60000\)/);
  assert.match(functions, /Get-AuthenticodeSignature -LiteralPath/);
  assert.match(functions, /ExtractToFile\(\$entry, \$binary, \$false\)/);
  assert.doesNotMatch(functions, /Expand-Archive|ExtractToDirectory/);
});

test('generated functions and Sysmon XML parse under Windows PowerShell 5.1', { skip: !powershell }, () => {
  const result = runPowerShell(`
    $tokens=$null; $errors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseInput(${psText(functions)},[ref]$tokens,[ref]$errors)
    [xml]$profile=${psText(SYSMON_PROFILE_XML)}
    [PSCustomObject]@{ Errors=@($errors | ForEach-Object Message); Profile=$profile.Sysmon.schemaversion; Version=$PSVersionTable.PSVersion.Major } | ConvertTo-Json -Compress
  `);
  assert.deepEqual(result.Errors, []);
  assert.equal(result.Profile, '4.82');
  assert.equal(result.Version, 5);
});

test('collectors merge idempotently while preserving existing queries and multiple configuration roots', { skip: !powershell }, () => {
  const result = runPowerShell(`
    [xml]$document='<wrapper><ossec_config><localfile><location>Security</location><log_format>eventchannel</log_format><query>existing-audit-filter</query></localfile><syscheck><disabled>no</disabled></syscheck></ossec_config><ossec_config><localfile><location>${TELEMETRY_CHANNELS.sysmon}</location><log_format>eventchannel</log_format><query>existing-sysmon-filter</query></localfile></ossec_config></wrapper>'
    $channels=@('${TELEMETRY_CHANNELS.sysmon}','${TELEMETRY_CHANNELS.powershell}','${TELEMETRY_CHANNELS.powershellCore}','${TELEMETRY_CHANNELS.defender}','${TELEMETRY_CHANNELS.defender}')
    $first=Set-CyberCoreWindowsTelemetryCollectors -Document $document -Channels $channels
    $once=$document.OuterXml
    $second=Set-CyberCoreWindowsTelemetryCollectors -Document $document -Channels $channels
    [PSCustomObject]@{ First=$first; Second=$second; Same=($once -eq $document.OuterXml); Sources=@($document.SelectNodes('//localfile') | ForEach-Object { [PSCustomObject]@{ Location=$_.location; Format=$_.log_format; Query=$_.query; Future=$_.'only-future-events' } }); Syscheck=$document.SelectSingleNode('//syscheck/disabled').InnerText; Roots=$document.SelectNodes('//ossec_config').Count } | ConvertTo-Json -Compress -Depth 5
  `);
  assert.equal(result.Same, true);
  assert.deepEqual(result.First, { Warnings: ['collector-existing-filter'], Complete: true, Changed: true });
  assert.deepEqual(result.Second, { Warnings: ['collector-existing-filter'], Complete: true, Changed: false });
  assert.equal(result.Roots, 2);
  assert.equal(result.Syscheck, 'no');
  assert.equal(result.Sources.length, 5);
  assert.equal(result.Sources.find(source => source.Location === 'Security').Query, 'existing-audit-filter');
  assert.equal(result.Sources.find(source => source.Location === TELEMETRY_CHANNELS.sysmon).Query, 'existing-sysmon-filter');
  for (const channel of [TELEMETRY_CHANNELS.powershell, TELEMETRY_CHANNELS.powershellCore, TELEMETRY_CHANNELS.defender]) {
    const source = result.Sources.find(item => item.Location === channel);
    assert.equal(source.Format, 'eventchannel');
    assert.equal(source.Future, 'yes');
  }
});

test('unknown channels fail before changing the document', { skip: !powershell }, () => {
  const result = runPowerShell(`
    [xml]$document='<ossec_config><client /></ossec_config>'
    $before=$document.OuterXml; $code=''
    try { Set-CyberCoreWindowsTelemetryCollectors $document @('${TELEMETRY_CHANNELS.sysmon}','Security') } catch { $code=$_.Exception.Message }
    [PSCustomObject]@{ Unchanged=($before -eq $document.OuterXml); Error=$code } | ConvertTo-Json -Compress
  `);
  assert.equal(result.Unchanged, true);
  assert.equal(result.Error, 'telemetry-channel-invalid');
});

test('an existing wrong-format collector is preserved and reported as incomplete', { skip: !powershell }, () => {
  const result = runPowerShell(`
    [xml]$document='<ossec_config><localfile><location>${TELEMETRY_CHANNELS.sysmon}</location><log_format>eventlog</log_format><query>existing</query></localfile></ossec_config>'
    $before=$document.OuterXml
    $state=Set-CyberCoreWindowsTelemetryCollectors $document @('${TELEMETRY_CHANNELS.sysmon}')
    [PSCustomObject]@{ Same=($before -eq $document.OuterXml); State=$state } | ConvertTo-Json -Depth 5 -Compress
  `);
  assert.equal(result.Same, true);
  assert.equal(result.State.Complete, false);
  assert.equal(result.State.Changed, false);
  assert.deepEqual(result.State.Warnings, ['collector-existing-format', 'collector-existing-filter']);
});

test('existing running Sysmon is preserved without download, install or policy replacement', { skip: !powershell }, () => {
  const result = runPowerShell(`
    function Get-CyberCoreSysmonServices { [PSCustomObject]@{Name='CustomSysmon'; State='Running'; Binary='unused'} }
    function Enable-CyberCoreEventChannel { param($Channel); $script:channel=$Channel }
    function Invoke-WebRequest { throw 'unexpected download' }
    function Invoke-CyberCoreSysmonInstall { throw 'unexpected install' }
    function Get-WindowsOptionalFeature { throw 'unexpected feature change' }
    $state=Install-CyberCoreSysmon -AgentRoot ${psText(os.tmpdir())}
    [PSCustomObject]@{ State=$state; Channel=$script:channel } | ConvertTo-Json -Compress
  `);
  assert.equal(result.State, 'existing-preserved');
  assert.equal(result.Channel, TELEMETRY_CHANNELS.sysmon);
});

test('a stopped existing Sysmon is reported instead of being replaced or started', { skip: !powershell }, () => {
  const result = runPowerShell(`
    function Get-CyberCoreSysmonServices { [PSCustomObject]@{Name='Sysmon64'; State='Stopped'; Binary='unused'} }
    function Start-Service { throw 'unexpected restart' }
    function Invoke-WebRequest { throw 'unexpected download' }
    $code=''; try { $null=Install-CyberCoreSysmon -AgentRoot ${psText(os.tmpdir())} } catch { $code=$_.Exception.Message }
    [PSCustomObject]@{ Error=$code } | ConvertTo-Json -Compress
  `);
  assert.equal(result.Error, 'sysmon-existing-service-stopped');
});

test('telemetry orchestration reports all enabled channels and separate PowerShell policies without raw output', { skip: !powershell }, () => {
  const result = runPowerShell(`
    $script:policies=New-Object 'System.Collections.Generic.List[string]'
    function Install-CyberCoreSysmon { return 'standalone-installed' }
    function Enable-CyberCoreScriptBlockPolicy { param($Path); $script:policies.Add($Path) }
    function Enable-CyberCoreEventChannel { param($Channel) }
    function Get-WinEvent { [PSCustomObject]@{IsEnabled=$true} }
    function Get-MpComputerStatus { [PSCustomObject]@{AntivirusEnabled=$true} }
    $state=Enable-CyberCoreWindowsTelemetry -AgentRoot 'unused'
    [PSCustomObject]@{ State=$state; Policies=$script:policies.ToArray() } | ConvertTo-Json -Depth 5 -Compress
  `);
  assert.equal(result.State.Complete, true);
  assert.deepEqual(result.State.Channels, Object.values(TELEMETRY_CHANNELS));
  assert.deepEqual(result.State.Warnings, []);
  assert.deepEqual(result.Policies, ['Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging', 'Software\\Policies\\Microsoft\\PowerShellCore\\ScriptBlockLogging']);
});

test('partial source failures return safe warnings and preserve successful sources for the final agent restart', { skip: !powershell }, () => {
  const result = runPowerShell(`
    function Install-CyberCoreSysmon { throw 'sensitive-exception-detail' }
    function Enable-CyberCoreScriptBlockPolicy { param($Path) }
    function Enable-CyberCoreEventChannel { param($Channel); if($Channel -eq '${TELEMETRY_CHANNELS.defender}'){throw 'sensitive-exception-detail'} }
    function Get-WinEvent { return $null }
    Enable-CyberCoreWindowsTelemetry -AgentRoot 'unused' | ConvertTo-Json -Depth 5 -Compress
  `);
  assert.equal(result.Complete, false);
  assert.deepEqual(result.Channels, [TELEMETRY_CHANNELS.powershell]);
  assert.equal(result.Warnings.length, 3);
  for (const code of result.Warnings) assert.ok(TELEMETRY_WARNINGS[code]);
  assert.doesNotMatch(JSON.stringify(result), /sensitive-exception-detail/);
  assert.equal(result.PowerShell, 'script-block-enabled');
});

test('missing optional Defender and PowerShell 7 channels warn without failing the Windows profile', { skip: !powershell }, () => {
  const result = runPowerShell(`
    function Install-CyberCoreSysmon { return 'existing-preserved' }
    function Enable-CyberCoreScriptBlockPolicy { param($Path) }
    function Enable-CyberCoreEventChannel { param($Channel) }
    function Get-WinEvent { return $null }
    Enable-CyberCoreWindowsTelemetry -AgentRoot 'unused' | ConvertTo-Json -Depth 5 -Compress
  `);
  assert.equal(result.Complete, true);
  assert.deepEqual(result.Channels, [TELEMETRY_CHANNELS.sysmon, TELEMETRY_CHANNELS.powershell]);
  assert.deepEqual(result.Warnings, ['sysmon-existing-profile', 'powershell-core-unavailable', 'defender-unavailable']);
});

test('a native feature that starts Sysmon receives the profile without a second installation', { skip: !powershell }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cybercore-telemetry-test-'));
  const file = path.join(directory, 'native-fixture.exe');
  fs.writeFileSync(file, 'test fixture only; never executed');
  try {
    const result = runPowerShell(`
      $script:enabled=$false; $script:update=$false
      function Get-CyberCoreSysmonServices { if($script:enabled){ [PSCustomObject]@{Name='Sysmon'; State='Running'; Binary='unused'} } }
      function Get-WindowsOptionalFeature { [PSCustomObject]@{State='Disabled'} }
      function Enable-WindowsOptionalFeature { param([switch]$Online,$FeatureName,[switch]$NoRestart); if(-not $NoRestart){throw 'unexpected reboot'}; $script:enabled=$true; [PSCustomObject]@{RestartNeeded=$false} }
      function Get-CyberCoreNativeSysmonBinary { return ${psText(file)} }
      function Get-WinEvent { return $null }
      function Set-Acl { param($LiteralPath,$AclObject) }
      function Enable-CyberCoreEventChannel { param($Channel) }
      function Invoke-WebRequest { throw 'unexpected download' }
      function Invoke-CyberCoreSysmonInstall { param($Binary,$ProfilePath,[switch]$UpdateExisting); $script:update=[bool]$UpdateExisting; [xml]$config=Get-Content -LiteralPath $ProfilePath; $script:schema=$config.Sysmon.schemaversion }
      $state=Install-CyberCoreSysmon -AgentRoot ${psText(directory)}
      [PSCustomObject]@{ State=$state; Update=$script:update; Schema=$script:schema } | ConvertTo-Json -Compress
    `);
    assert.deepEqual(result, { State: 'builtin-installed', Update: true, Schema: '4.82' });
    assert.deepEqual(fs.readdirSync(directory), ['native-fixture.exe']);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('binary validation requires both a valid signature and the Microsoft publisher', { skip: !powershell }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cybercore-telemetry-test-'));
  const file = path.join(directory, 'signature-fixture.exe');
  fs.writeFileSync(file, 'test fixture only; never executed');
  try {
    const result = runPowerShell(`
      $script:valid='Valid'; $script:subject='CN=Microsoft Windows, O=Microsoft Corporation, C=US'
      function Get-AuthenticodeSignature { [PSCustomObject]@{Status=$script:valid; SignerCertificate=[PSCustomObject]@{Subject=$script:subject}} }
      $valid=Test-CyberCoreMicrosoftBinary ${psText(file)}
      $script:valid='NotSigned'; $unsigned=Test-CyberCoreMicrosoftBinary ${psText(file)}
      $script:valid='Valid'; $script:subject='CN=Example, O=Not Microsoft Corporation, C=US'; $other=Test-CyberCoreMicrosoftBinary ${psText(file)}
      [PSCustomObject]@{ Valid=$valid; Unsigned=$unsigned; Other=$other } | ConvertTo-Json -Compress
    `);
    assert.deepEqual(result, { Valid: true, Unsigned: false, Other: false });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
