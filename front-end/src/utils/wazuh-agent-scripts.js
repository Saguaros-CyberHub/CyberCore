'use strict';

const { isIP } = require('node:net');
const { isAgentName } = require('./wazuh-agent-identity');

// Official package URLs and API key import workflow:
// https://documentation.wazuh.com/current/installation-guide/packages-list.html
// Checksums live under /4.x/checksums/wazuh/<version>/, separately from packages.
// https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-manager-API/importing-the-key.html
// manage_agents also supports interactive I / key / y / Q on stdin. This keeps
// the per-agent credential out of child process arguments and temporary files:
// https://github.com/wazuh/wazuh/blob/v4.14.0/src/addagent/main.c
// https://github.com/wazuh/wazuh/blob/v4.14.0/src/addagent/manage_keys.c

function validateKeyRecord(agentName, agentKey) {
  if (typeof agentKey !== 'string' || agentKey.length > 2048 || !/^[a-zA-Z0-9+/]+={0,2}$/.test(agentKey) ||
      Buffer.from(agentKey, 'base64').toString('base64') !== agentKey) {
    throw new TypeError('Wazuh agent key must be canonical base64');
  }
  const record = Buffer.from(agentKey, 'base64').toString('utf8');
  const fields = record.split(' ');
  if (/[^\x20-\x7e]/.test(record) || fields.length !== 4 || !/^\d{1,8}$/.test(fields[0]) || Number(fields[0]) === 0 ||
      fields[1] !== agentName || fields[2] !== 'any' || !/^[a-fA-F0-9]{64}$/.test(fields[3]) || record.trim() !== record) {
    throw new TypeError('Wazuh agent key must contain the requested agent identity and any source IP');
  }
}

function validateOptions({ platform, manager, version, agentName, agentKey, previousAgentName, previousAgentKey } = {}) {
  if (platform !== 'linux' && platform !== 'windows') throw new TypeError('Wazuh agent platform must be windows or linux');
  if (typeof manager !== 'string' || manager.length > 253 || /[^a-zA-Z0-9.:-]/.test(manager) ||
      (!isIP(manager) && !manager.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)))) {
    throw new TypeError('Wazuh manager must be a hostname or IP address without a scheme, port or path');
  }
  if (typeof version !== 'string' || version.trim() !== version || !/^4\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d{0,2})-[1-9]\d{0,2}$/.test(version)) {
    throw new TypeError('Wazuh version must be a pinned 4.x package version with release, for example 4.14.7-1');
  }
  if (!isAgentName(agentName)) {
    throw new TypeError('Wazuh agent name must be a safe managed identity of at most 128 characters');
  }
  validateKeyRecord(agentName, agentKey);
  if (previousAgentName !== undefined || previousAgentKey !== undefined) {
    const legacy = typeof previousAgentName === 'string'
      && /^cc-[a-f0-9]{32}-([1-9][0-9]{0,15})-[a-f0-9]{32}$/.exec(previousAgentName);
    const readable = /-vm-([1-9][0-9]*)$/.exec(agentName);
    if (!legacy || !Number.isSafeInteger(Number(legacy[1])) || previousAgentName === agentName
        || !readable || Number(readable[1]) !== Number(legacy[1])) {
      throw new TypeError('Wazuh replacement requires a legacy identity and a readable name for the same VM');
    }
    validateKeyRecord(previousAgentName, previousAgentKey);
  }
  return { platform, manager, version, agentName, agentKey, previousAgentName, previousAgentKey };
}

function buildLinuxScript({ manager, version, agentName, agentKey, previousAgentKey }) {
  // Python's XML parser preserves Wazuh's multiple ossec_config roots and its
  // collection settings. No ad-hoc XML substitution and no Python dependencies.
  return `#!/bin/sh
set -eu
umask 077
command -v python3 >/dev/null 2>&1 || { printf '%s\\n' 'CYBERCORE_WAZUH_ERROR:python3-missing' >&2; exit 1; }
exec python3 - <<'CYBERCORE_WAZUH_PY'
import base64
import fcntl
import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from xml.dom import minidom

MANAGER = '${manager}'
VERSION = '${version}'
CHECKSUM_BASE = 'https://packages.wazuh.com/4.x/checksums/wazuh/${version.split('-')[0]}/'
AGENT_NAME = '${agentName}'
AGENT_KEY = '${agentKey}'
EXPECTED_RECORD = base64.b64decode(AGENT_KEY).decode('ascii').split()
PREVIOUS_RECORD = base64.b64decode('${previousAgentKey || ''}').decode('ascii').split()
AGENT_DIR = Path('/var/ossec')
STAGE = 'preflight-failed'

class InstallError(Exception):
    pass

def require(condition, code):
    if not condition:
        raise InstallError(code)

def run(args, timeout=60, input_data=None, env=None):
    if env is None:
        env = {key: value for key, value in os.environ.items() if not key.startswith(('WAZUH_', 'OSSEC_'))}
    return subprocess.run(args, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=True, env=env)

def key_rows():
    key_file = AGENT_DIR / 'etc/client.keys'
    if not key_file.exists():
        return []
    return [line.split() for line in key_file.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]

def read_config():
    config_file = AGENT_DIR / 'etc/ossec.conf'
    require(config_file.is_file() and not config_file.is_symlink(), 'existing-installation-invalid')
    raw = config_file.read_text(encoding='utf-8-sig')
    require(not re.search(r'<!DOCTYPE|<!ENTITY', raw, re.I), 'configuration-invalid')
    raw = re.sub(r'^\\s*<\\?xml[^?]*\\?>', '', raw, count=1)
    try:
        document = minidom.parseString('<cybercore>' + raw + '</cybercore>')
    except Exception:
        raise InstallError('configuration-invalid')
    clients = document.getElementsByTagName('client')
    require(len(clients) == 1, 'configuration-invalid')
    return document, clients[0]

def node_text(node):
    return ''.join(child.data for child in node.childNodes if child.nodeType == child.TEXT_NODE).strip()

def check_existing():
    require(not (AGENT_DIR / 'bin/wazuh-remoted').exists(), 'manager-installation')
    for local_path in (AGENT_DIR, AGENT_DIR / 'etc', AGENT_DIR / 'bin', AGENT_DIR / 'etc/client.keys'):
        require(not local_path.is_symlink(), 'unsafe-installation-path')
    if not AGENT_DIR.exists():
        return False
    require((AGENT_DIR / 'bin/manage_agents').is_file(), 'existing-installation-invalid')
    document, client = read_config()
    rows = key_rows()
    require(not rows or rows == [EXPECTED_RECORD] or (PREVIOUS_RECORD and rows == [PREVIOUS_RECORD]), 'identity-conflict')
    addresses = []
    for tag in ('server', 'enrollment'):
        for section in client.getElementsByTagName(tag):
            for address in section.getElementsByTagName('address' if tag == 'server' else 'manager_address'):
                addresses.append(node_text(address))
    addresses.extend(node_text(node) for node in client.getElementsByTagName('server-ip'))
    placeholders = ('', 'MANAGER_IP', 'MANAGER_IP_ADDRESS', 'WAZUH_MANAGER') if not rows else ()
    require(all(address in placeholders or address.lower() == MANAGER.lower() for address in addresses), 'manager-conflict')
    require(not rows or any(address.lower() == MANAGER.lower() for address in addresses), 'manager-conflict')
    return True

def configure():
    document, client = read_config()
    for child in list(client.childNodes):
        if child.nodeType == child.ELEMENT_NODE and child.tagName in ('server', 'server-ip', 'enrollment'):
            client.removeChild(child)
    def add(parent, tag, value=None):
        node = document.createElement(tag)
        parent.appendChild(node)
        if value is not None:
            node.appendChild(document.createTextNode(value))
        return node
    server = add(client, 'server')
    add(server, 'address', MANAGER)
    add(server, 'port', '1514')
    add(server, 'protocol', 'tcp')
    enrollment = add(client, 'enrollment')
    add(enrollment, 'enabled', 'no')
    config_file = AGENT_DIR / 'etc/ossec.conf'
    metadata = config_file.stat()
    handle, staging = tempfile.mkstemp(prefix='.cybercore-wazuh-', dir=str(config_file.parent))
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as output:
            output.write(''.join(child.toxml() for child in document.documentElement.childNodes))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(staging, stat.S_IMODE(metadata.st_mode))
        os.chown(staging, metadata.st_uid, metadata.st_gid)
        os.replace(staging, str(config_file))
    finally:
        if os.path.exists(staging):
            os.unlink(staging)

class OfficialPackagesOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        require(parsed.scheme == 'https' and parsed.netloc == 'packages.wazuh.com', 'download-failed')
        return super().redirect_request(request, response, code, message, headers, new_url)

def download(url, destination, max_bytes):
    deadline = time.monotonic() + 120
    opener = urllib.request.build_opener(OfficialPackagesOnly())
    with opener.open(url, timeout=30) as response, open(destination, 'wb') as output:
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= max_bytes and time.monotonic() < deadline, 'download-failed')
            output.write(block)
        require(total > 0, 'download-failed')

def main():
    global STAGE
    require(os.geteuid() == 0, 'root-required')
    require(platform.system() == 'Linux', 'unsupported-platform')
    architecture = platform.machine().lower()
    require(architecture in ('x86_64', 'amd64', 'aarch64', 'arm64'), 'unsupported-architecture')
    require(shutil.which('systemctl') and Path('/run/systemd/system').is_dir(), 'systemd-required')
    with open('/run/cybercore-wazuh-install.lock', 'a') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError('installation-busy')
        existing = check_existing()
        if not existing:
            deb_arch = 'amd64' if architecture in ('amd64', 'x86_64') else 'arm64'
            rpm_arch = 'x86_64' if deb_arch == 'amd64' else 'aarch64'
            if shutil.which('dpkg') and shutil.which('apt-get'):
                filename = 'wazuh-agent_' + VERSION + '_' + deb_arch + '.deb'
                url = 'https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/' + filename
                installer = ['apt-get', '-y', '--no-remove', '--no-install-recommends', 'install']
            elif shutil.which('rpm'):
                filename = 'wazuh-agent-' + VERSION + '.' + rpm_arch + '.rpm'
                url = 'https://packages.wazuh.com/4.x/yum/' + filename
                installer = ['rpm', '--install']
            else:
                raise InstallError('unsupported-package-manager')
            with tempfile.TemporaryDirectory(prefix='cybercore-wazuh-') as temporary:
                package = Path(temporary) / filename
                checksum = Path(temporary) / 'package.sha512'
                STAGE = 'download-failed'
                download(url, str(package), 200 * 1024 * 1024)
                download(CHECKSUM_BASE + filename + '.sha512', str(checksum), 8192)
                expected = checksum.read_text().split()[0].lower()
                require(re.fullmatch('[a-f0-9]{128}', expected) is not None, 'checksum-invalid')
                require(hashlib.sha512(package.read_bytes()).hexdigest() == expected, 'checksum-mismatch')
                STAGE = 'package-install-failed'
                environment = os.environ.copy()
                # A new package remains unregistered until its API key is imported.
                for key in list(environment):
                    if key.startswith('WAZUH_') or key.startswith('OSSEC_'):
                        del environment[key]
                environment['DEBIAN_FRONTEND'] = 'noninteractive'
                run(installer + [str(package)], timeout=300, env=environment)
            check_existing()
        STAGE = 'service-stop-failed'
        run(['systemctl', 'stop', 'wazuh-agent'])
        STAGE = 'configuration-failed'
        configure()
        if key_rows() != [EXPECTED_RECORD]:
            STAGE = 'key-import-failed'
            run([str(AGENT_DIR / 'bin/manage_agents')], timeout=30,
                input_data=('I\\n' + AGENT_KEY + '\\ny\\nQ\\n').encode('ascii'))
            require(key_rows() == [EXPECTED_RECORD], 'key-import-failed')
        STAGE = 'service-start-failed'
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', 'wazuh-agent'])
        run(['systemctl', 'restart', 'wazuh-agent'])
        run(['systemctl', 'is-active', '--quiet', 'wazuh-agent'])
        print('CYBERCORE_WAZUH_STARTED:' + AGENT_NAME)

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print subprocess output, decoded keys, or exception details.
        code = str(error) if isinstance(error, InstallError) else STAGE
        print('CYBERCORE_WAZUH_ERROR:' + code, file=sys.stderr)
        sys.exit(1)
CYBERCORE_WAZUH_PY
`;
}

function buildWindowsScript({ manager, version, agentName, agentKey, previousAgentKey }) {
  // Strip only indentation and blank lines to keep the UTF-16 encoded command
  // below Windows limits. The generated script contains no multiline literals.
  return `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$manager = '${manager}'
$version = '${version}'
$checksumBase = 'https://packages.wazuh.com/4.x/checksums/wazuh/${version.split('-')[0]}/'
$agentName = '${agentName}'
$agentKey = '${agentKey}'
$expectedRecord = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($agentKey))
$previousRecord = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('${previousAgentKey || ''}'))
$script:stage = 'preflight-failed'
$script:publicError = $null
$installLock = $null
$package = $null
$checksumFile = $null
$configStaging = $null

function Stop-WazuhInstall([string]$Code) {
  $script:publicError = $Code
  throw 'Wazuh deployment stopped'
}
function Assert-RegularPath([string]$Path) {
  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-WazuhInstall 'unsafe-installation-path' }
    }
    $current = [IO.Path]::GetDirectoryName($current)
  }
}
function Invoke-WazuhProcess([string]$FilePath, [string]$Arguments, [string]$InputText, [int]$Timeout = 60) {
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName = $FilePath
  $info.Arguments = $Arguments
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  foreach ($name in @($info.EnvironmentVariables.Keys)) {
    if ($name -match '^(WAZUH_|OSSEC_)') { $info.EnvironmentVariables.Remove($name) }
  }
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $info
  try {
    if (-not $process.Start()) { Stop-WazuhInstall $script:stage }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($InputText) { $process.StandardInput.Write($InputText) }
    $process.StandardInput.Close()
    if (-not $process.WaitForExit($Timeout * 1000)) {
      $process.Kill()
      Stop-WazuhInstall $script:stage
    }
    # Drain all output without exposing the imported key or installer details.
    $null = $stdout.GetAwaiter().GetResult()
    $null = $stderr.GetAwaiter().GetResult()
    return $process.ExitCode
  } finally { $process.Dispose() }
}
function Read-WazuhKeys {
  $keyFile = Join-Path $agentDir 'client.keys'
  Assert-RegularPath $keyFile
  if (-not (Test-Path -LiteralPath $keyFile)) { return @() }
  return @(Get-Content -LiteralPath $keyFile | Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') } | ForEach-Object { ($_.Trim() -split '\\s+') -join ' ' })
}
function Read-WazuhConfiguration {
  if (-not (Test-Path -LiteralPath $configFile)) { Stop-WazuhInstall 'existing-installation-invalid' }
  Assert-RegularPath $configFile
  $raw = [IO.File]::ReadAllText($configFile)
  if ($raw -match '(?i)<!DOCTYPE|<!ENTITY') { Stop-WazuhInstall 'configuration-invalid' }
  $raw = [regex]::Replace($raw, '^\\s*<\\?xml[^?]*\\?>', '')
  $document = New-Object Xml.XmlDocument
  $document.XmlResolver = $null
  $document.PreserveWhitespace = $true
  try { $document.LoadXml('<cybercore>' + $raw + '</cybercore>') } catch { Stop-WazuhInstall 'configuration-invalid' }
  if ($document.SelectNodes('//client').Count -ne 1) { Stop-WazuhInstall 'configuration-invalid' }
  return ,$document
}
function Assert-WazuhOwnership {
  $keys = @(Read-WazuhKeys)
  if ($keys.Count -gt 0 -and ($keys.Count -ne 1 -or ($keys[0] -cne $expectedRecord -and $keys[0] -cne $previousRecord))) { Stop-WazuhInstall 'identity-conflict' }
  $document = Read-WazuhConfiguration
  $addresses = @($document.SelectNodes('//client/server/address | //client/server-ip | //client/enrollment/manager_address') | ForEach-Object { $_.InnerText.Trim() })
  foreach ($address in $addresses) {
    # The official Windows MSI ships 0.0.0.0 before enrollment; it is a
    # placeholder only while client.keys contains no agent registration.
    $placeholder = $keys.Count -eq 0 -and $address -cin @('', '0.0.0.0', 'MANAGER_IP', 'MANAGER_IP_ADDRESS', 'WAZUH_MANAGER')
    if (-not $placeholder -and $address -ine $manager) { Stop-WazuhInstall 'manager-conflict' }
  }
  if ($keys.Count -gt 0 -and $addresses -inotcontains $manager) { Stop-WazuhInstall 'manager-conflict' }
}
function Set-WazuhConfiguration {
  $document = Read-WazuhConfiguration
  $client = $document.SelectSingleNode('//client')
  foreach ($node in @($client.SelectNodes('server | server-ip | enrollment'))) { $null = $client.RemoveChild($node) }
  $server = $document.CreateElement('server')
  foreach ($entry in @(@('address', $manager), @('port', '1514'), @('protocol', 'tcp'))) {
    $node = $document.CreateElement($entry[0]); $node.InnerText = $entry[1]; $null = $server.AppendChild($node)
  }
  $null = $client.AppendChild($server)
  $enrollment = $document.CreateElement('enrollment')
  $enabled = $document.CreateElement('enabled'); $enabled.InnerText = 'no'
  $null = $enrollment.AppendChild($enabled); $null = $client.AppendChild($enrollment)
  $script:configStaging = Join-Path $agentDir ('.cybercore-wazuh-' + [Guid]::NewGuid().ToString('N') + '.conf')
  [IO.File]::WriteAllText($script:configStaging, $document.DocumentElement.InnerXml, (New-Object Text.UTF8Encoding($false)))
  Set-Acl -LiteralPath $script:configStaging -AclObject (Get-Acl -LiteralPath $configFile)
  [IO.File]::Replace($script:configStaging, $configFile, [NullString]::Value)
}

try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-WazuhInstall 'administrator-required' }
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $machineArchitecture = $env:PROCESSOR_ARCHITEW6432
  if (-not $machineArchitecture) { $machineArchitecture = $env:PROCESSOR_ARCHITECTURE }
  if ($machineArchitecture -notin @('AMD64', 'x86')) { Stop-WazuhInstall 'unsupported-architecture' }
  $programFiles = if ($machineArchitecture -eq 'AMD64') { [Environment]::GetEnvironmentVariable('ProgramFiles(x86)') } else { $env:ProgramFiles }
  if (-not $programFiles -or -not $env:ProgramData) { Stop-WazuhInstall 'unsafe-installation-path' }
  $agentDir = Join-Path $programFiles 'ossec-agent'
  $configFile = Join-Path $agentDir 'ossec.conf'
  $workDir = Join-Path $env:ProgramData 'CyberCore\\Wazuh'
  Assert-RegularPath $agentDir
  Assert-RegularPath $workDir
  $null = New-Item -ItemType Directory -Path $workDir -Force
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $account = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $workDir -AclObject $acl
  $lockPath = Join-Path $workDir 'install.lock'
  Assert-RegularPath $lockPath
  $script:stage = 'installation-busy'
  $installLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $script:stage = 'preflight-failed'
  $service = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $agentDir) {
    if (-not $service -or -not (Test-Path -LiteralPath (Join-Path $agentDir 'manage_agents.exe'))) { Stop-WazuhInstall 'existing-installation-invalid' }
    Assert-WazuhOwnership
  } elseif ($service) { Stop-WazuhInstall 'existing-installation-invalid' }
  if (-not $service) {
    $script:stage = 'download-failed'
    $package = Join-Path $workDir ('wazuh-agent-' + [Guid]::NewGuid().ToString('N') + '.msi')
    $filename = 'wazuh-agent-' + $version + '.msi'
    $url = 'https://packages.wazuh.com/4.x/windows/' + $filename
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $package -TimeoutSec 120 -MaximumRedirection 0
    $checksumFile = $package + '.sha512'
    Invoke-WebRequest -UseBasicParsing -Uri ($checksumBase + $filename + '.sha512') -OutFile $checksumFile -TimeoutSec 30 -MaximumRedirection 0
    $expectedHash = ([IO.File]::ReadAllText($checksumFile).Trim() -split '\\s+')[0]
    if ($expectedHash -notmatch '^[a-fA-F0-9]{128}$') { Stop-WazuhInstall 'checksum-invalid' }
    if ((Get-FileHash -LiteralPath $package -Algorithm SHA512).Hash -ine $expectedHash) { Stop-WazuhInstall 'checksum-mismatch' }
    $script:stage = 'package-install-failed'
    $logFile = Join-Path $workDir 'install.log'
    $arguments = '/i "' + $package + '" /qn /norestart REBOOT=ReallySuppress /L*v "' + $logFile + '"'
    $exitCode = Invoke-WazuhProcess -FilePath (Join-Path $env:SystemRoot 'System32\\msiexec.exe') -Arguments $arguments -Timeout 300
    if ($exitCode -notin @(0, 3010)) { Stop-WazuhInstall 'package-install-failed' }
    Assert-WazuhOwnership
  }
  $script:stage = 'existing-installation-invalid'
  $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'WazuhSvc'"
  $expectedBinary = Join-Path $agentDir 'wazuh-agent.exe'
  if (-not $serviceInfo -or $serviceInfo.PathName.Trim('"') -ine $expectedBinary) { Stop-WazuhInstall 'existing-installation-invalid' }
  $script:stage = 'service-stop-failed'
  $service = Get-Service -Name 'WazuhSvc'
  if ($service.Status -ne 'Stopped') {
    $service.Stop()
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(60))
  }
  $script:stage = 'configuration-failed'
  Set-WazuhConfiguration
  $keys = @(Read-WazuhKeys)
  if ($keys.Count -ne 1 -or $keys[0] -cne $expectedRecord) {
    $script:stage = 'key-import-failed'
    $inputText = 'I' + [Environment]::NewLine + $agentKey + [Environment]::NewLine + 'y' + [Environment]::NewLine + 'Q' + [Environment]::NewLine
    $exitCode = Invoke-WazuhProcess -FilePath (Join-Path $agentDir 'manage_agents.exe') -InputText $inputText -Timeout 30
    $keys = @(Read-WazuhKeys)
    if ($exitCode -ne 0 -or $keys.Count -ne 1 -or $keys[0] -cne $expectedRecord) { Stop-WazuhInstall 'key-import-failed' }
  }
  $script:stage = 'service-start-failed'
  Set-Service -Name 'WazuhSvc' -StartupType Automatic
  $service.Start()
  $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
  Write-Output ('CYBERCORE_WAZUH_STARTED:' + $agentName)
} catch {
  $code = if ($script:publicError) { $script:publicError } else { $script:stage }
  [Console]::Error.WriteLine('CYBERCORE_WAZUH_ERROR:' + $code)
  exit 1
} finally {
  foreach ($temporary in @($package, $checksumFile, $configStaging)) {
    if ($temporary -and (Test-Path -LiteralPath $temporary)) {
      # Only individual generated files in the known staging/install directories.
      $resolved = [IO.Path]::GetFullPath($temporary)
      $parent = [IO.Path]::GetDirectoryName($resolved)
      if ($parent -ieq [IO.Path]::GetFullPath($workDir) -or $parent -ieq [IO.Path]::GetFullPath($agentDir)) {
        Remove-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue
      }
    }
  }
  if ($installLock) { $installLock.Dispose() }
}
`.replace(/^[ \t]+/gm, '').replace(/^\r?\n/gm, '');
}

function buildInstallScript(options) {
  const validated = validateOptions(options);
  return validated.platform === 'windows' ? buildWindowsScript(validated) : buildLinuxScript(validated);
}

module.exports = { buildInstallScript };
