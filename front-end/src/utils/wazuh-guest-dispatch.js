'use strict';

const crypto = require('node:crypto');
const { isAgentName, keyFingerprint } = require('./wazuh-agent-identity');

// PVE accepts plain input-data and base64-encodes it for QGA. Its API limit is
// 64 KiB, including an older 64 KiB HTTP POST limit. Keep requests below both.
// Large guest-exec stdin has also wedged Windows QGA in this deployment. Stage
// only nonsecret source when needed; enrollment records always travel on stdin.
// https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu/Agent.pm
// https://github.com/proxmox/qemu-server/blob/master/src/PVE/QemuServer/Agent.pm
const MAX_FORM_BYTES = 60 * 1024;
const MAX_STDIN_BYTES = 8 * 1024;
// A staged Linux source is eventually one sh -c argument. Stay below Linux's
// per-argument 128 KiB limit as well as bounding the number of staging writes.
const MAX_SOURCE_BYTES = 96 * 1024;
const SOURCE_CHUNK_BYTES = 24 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const WINDOWS_BOOTSTRAP = [
  "$ErrorActionPreference = 'Stop'",
  "$ProgressPreference = 'SilentlyContinue'",
  'try {',
  '  $agentKey = [Console]::In.ReadLine()',
  '  $previousAgentKey = [Console]::In.ReadLine()',
  '  $installerSource = [Console]::In.ReadToEnd()',
  '  if ([String]::IsNullOrEmpty($agentKey) -or $null -eq $previousAgentKey -or [String]::IsNullOrEmpty($installerSource)) { throw "input" }',
  '  & ([ScriptBlock]::Create($installerSource))',
  '} catch {',
  "  [Console]::Error.WriteLine('CYBERCORE_WAZUH_ERROR:dispatch')",
  '  exit 1',
  '}',
].join('\n');

function dispatchError(code = 'WAZUH_GUEST_DISPATCH_FAILED') {
  const error = new Error(code === 'WAZUH_GUEST_DISPATCH_TIMEOUT'
    ? 'Wazuh guest dispatch timed out. Check the guest before retrying.'
    : 'Wazuh guest dispatch failed. Check guest agent connectivity and permissions.');
  error.code = code;
  return error;
}

function invalidOptions() {
  const error = new TypeError('Wazuh guest dispatch options are invalid.');
  error.code = 'WAZUH_GUEST_DISPATCH_INVALID';
  return error;
}

function validateOptions(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw invalidOptions();
  const { node, vmId, platform, script, agentName, agentKey, previousAgentName, previousAgentKey } = options;
  if (typeof node !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$/.test(node)
      || !Number.isSafeInteger(vmId) || vmId < 100 || vmId > 999999999
      || !['windows', 'linux'].includes(platform) || !isAgentName(agentName)
      || typeof script !== 'string' || !script.trim() || script.length > MAX_SOURCE_BYTES
      || /[^\x09\x0a\x0d\x20-\x7e]/.test(script)) throw invalidOptions();
  const keys = [agentKey];
  try {
    keyFingerprint(agentKey, { name: agentName });
    if (previousAgentName !== undefined || previousAgentKey !== undefined) {
      if (!isAgentName(previousAgentName) || previousAgentName === agentName) throw invalidOptions();
      keyFingerprint(previousAgentKey, { name: previousAgentName });
      keys.push(previousAgentKey);
    }
  } catch {
    throw invalidOptions();
  }
  // Fail closed if a future installer accidentally restores secret interpolation.
  // Check all three representations that have previously been used by installers.
  for (const key of keys) {
    const record = Buffer.from(key, 'base64').toString('ascii');
    if ([key, record, record.split(' ')[3]].some(secret => script.includes(secret))) throw invalidOptions();
  }
  return { node, vmId, platform, script, agentKey, previousAgentKey: previousAgentKey || '' };
}

function form(pairs) {
  const body = pairs.map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join('&');
  if (Buffer.byteLength(body) > MAX_FORM_BYTES) throw invalidOptions();
  return body;
}

function execBody(argv, input) {
  if (Buffer.byteLength(input) > MAX_STDIN_BYTES) throw invalidOptions();
  return form([...argv.map(arg => ['command', arg]), ['input-data', input]]);
}

function quoteConfig(value) {
  // curl --config's quoted strings recognize precisely these backslash escapes.
  return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/\t/g, '\\t').replace(/\r/g, '\\r').replace(/\n/g, '\\n') + '"';
}

function curlSettings(env) {
  let url;
  try { url = new URL(env.PROXMOX_API_URL || 'https://100.100.10.10:8006'); } catch { throw invalidOptions(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw invalidOptions();
  const tokenId = env.PROXMOX_TOKEN_ID;
  const tokenSecret = env.PROXMOX_TOKEN_SECRET;
  if (typeof tokenId !== 'string' || !tokenId || tokenId.length > 256 || /[^\x21-\x7e]/.test(tokenId)
      || typeof tokenSecret !== 'string' || !tokenSecret || tokenSecret.length > 2048 || /[^\x21-\x7e]/.test(tokenSecret)) throw invalidOptions();
  const binary = env.CURL_BIN || '/usr/bin/curl';
  if (typeof binary !== 'string' || !binary || /[\x00\r\n]/.test(binary)) throw invalidOptions();
  return { origin: url.origin, tokenId, tokenSecret, binary };
}

function curlPost(path, body, { spawn, settings, timeoutMs }) {
  // Preserve the established Proxmox integration's TLS policy. Unlike its shared
  // curl helper, neither the authorization header nor the request body is argv.
  // -q must be first: user curlrc files must not enable tracing or redirects.
  const config = [
    'silent', 'show-error', 'insecure',
    'proto = "=https"',
    'request = "POST"',
    `url = ${quoteConfig(settings.origin + path)}`,
    `header = ${quoteConfig(`Authorization: PVEAPIToken=${settings.tokenId}=${settings.tokenSecret}`)}`,
    'header = "Content-Type: application/x-www-form-urlencoded"',
    `data-binary = ${quoteConfig(body)}`,
    `connect-timeout = "${Math.min(10, timeoutMs / 1000)}"`,
    `max-time = "${timeoutMs / 1000}"`,
    'max-redirs = "0"',
    'write-out = "\\nCYBERCORE_HTTP_STATUS:%{http_code}\\n"',
    '',
  ].join('\n');
  return new Promise((resolve, reject) => {
    let child;
    let output = '';
    let outputBytes = 0;
    let errorBytes = 0;
    let finished = false;
    let timer;
    function finish(error, value) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      output = '';
      if (error) {
        try { child?.kill(); } catch { /* Never forward process errors. */ }
        reject(error);
      } else resolve(value);
    }
    try {
      child = spawn(settings.binary, ['-q', '--config', '-'], {
        stdio: ['pipe', 'pipe', 'pipe'], shell: false, windowsHide: true,
      });
      timer = setTimeout(() => finish(dispatchError('WAZUH_GUEST_DISPATCH_TIMEOUT')), timeoutMs);
      child.once('error', () => finish(dispatchError()));
      child.stdin.on('error', () => finish(dispatchError()));
      child.stdout.on('data', chunk => {
        if (finished) return;
        outputBytes += Buffer.byteLength(chunk);
        if (outputBytes > MAX_RESPONSE_BYTES) return finish(dispatchError());
        output += chunk.toString();
      });
      child.stderr.on('data', chunk => {
        // Upstream errors may echo input-data; never retain or expose stderr.
        errorBytes += Buffer.byteLength(chunk);
        if (errorBytes > MAX_RESPONSE_BYTES) finish(dispatchError());
      });
      child.once('close', code => {
        if (finished) return;
        const match = output.match(/^([\s\S]*)\nCYBERCORE_HTTP_STATUS:(\d{3})\n$/);
        if (code !== 0 || !match || Number(match[2]) !== 200) return finish(dispatchError());
        let result;
        try { result = JSON.parse(match[1]); } catch { return finish(dispatchError()); }
        if (!result || typeof result !== 'object' || Array.isArray(result)
            || !Object.hasOwn(result, 'data')) return finish(dispatchError());
        finish(null, result.data);
      });
      child.stdin.end(config);
    } catch {
      finish(dispatchError());
    }
  });
}

async function nativePost(path, body, api, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => api('POST', path, body, { timeoutMs, signal: controller.signal })),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(dispatchError('WAZUH_GUEST_DISPATCH_TIMEOUT'));
        }, timeoutMs);
      }),
    ]);
  } catch {
    // Shared proxmoxAPI errors include server response bodies; discard them.
    throw dispatchError(controller.signal.aborted ? 'WAZUH_GUEST_DISPATCH_TIMEOUT' : undefined);
  } finally { clearTimeout(timer); }
}

function stagedWindowsSource(paths, digest) {
  const list = paths.map(path => `'${path}'`).join(',');
  return [
    `$sourcePaths = @(${list})`,
    'try {',
    '  $sourceBytes = New-Object IO.MemoryStream',
    '  foreach ($sourcePath in $sourcePaths) {',
    '    $chunk = [IO.File]::ReadAllBytes($sourcePath)',
    '    $sourceBytes.Write($chunk, 0, $chunk.Length)',
    '  }',
    '  $verifiedBytes = $sourceBytes.ToArray()',
    '  $sourceBytes.Dispose()',
    '  $sha = [Security.Cryptography.SHA256]::Create()',
    "  $actualHash = ([BitConverter]::ToString($sha.ComputeHash($verifiedBytes))).Replace('-', '').ToLowerInvariant()",
    '  $sha.Dispose()',
    `  if ($actualHash -cne '${digest}') { throw 'source' }`,
    '  $verifiedSource = [Text.Encoding]::ASCII.GetString($verifiedBytes)',
    '} finally {',
    '  foreach ($sourcePath in $sourcePaths) { [IO.File]::Delete($sourcePath) }',
    '}',
    // Execute the exact bytes already hashed, never reopen a mutable file.
    '& ([ScriptBlock]::Create($verifiedSource))',
  ].join('\n');
}

function stagedLinuxArgv(paths, digest) {
  const bootstrap = [
    'import hashlib, os, sys',
    `paths = ${JSON.stringify(paths)}`,
    'try:',
    '    try:',
    "        source = b''.join(open(path, 'rb').read() for path in paths)",
    `        if hashlib.sha256(source).hexdigest() != '${digest}': raise ValueError('source')`,
    "        script = source.decode('ascii')",
    '    finally:',
    '        for path in paths: os.unlink(path)',
    // fd0 is still untouched: the installer duplicates it onto fd3 itself.
    "    os.execv('/bin/sh', ['/bin/sh', '-c', script])",
    'except BaseException:',
    "    sys.stderr.write('CYBERCORE_WAZUH_ERROR:dispatch\\n')",
    '    sys.exit(1)',
  ].join('\n');
  return ['python3', '-c', bootstrap];
}

/**
 * Dispatch exactly one Wazuh installer. Never retry an uncertain guest-exec.
 * `script` must contain no enrollment credentials. Windows consumes both key
 * lines in the fixed bootstrap; Linux installers must read those lines from
 * fd0 (or duplicate fd0 onto fd3 before a source heredoc replaces stdin).
 *
 * deps.beforeExec can revalidate lane ownership after nonsecret file staging.
 * Only {pid} is returned: no guest output, request body, or API error escapes.
 */
async function dispatchWazuhGuest(options, deps = {}) {
  const { node, vmId, platform, script, agentKey, previousAgentKey } = validateOptions(options);
  const timeoutMs = deps.timeoutMs === undefined ? 30000 : deps.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000
      || (deps.beforeExec !== undefined && typeof deps.beforeExec !== 'function')) throw invalidOptions();
  const base = `/api2/json/nodes/${node}/qemu/${vmId}/agent`;
  let post;
  if (platform === 'windows') {
    const api = deps.api || require('./proxmox').proxmoxAPI;
    if (typeof api !== 'function') throw invalidOptions();
    post = (path, body) => nativePost(path, body, api, timeoutMs);
  } else {
    const settings = curlSettings(deps.env || process.env);
    const spawn = deps.spawn || require('node:child_process').spawn;
    if (typeof spawn !== 'function') throw invalidOptions();
    post = (path, body) => curlPost(path, body, { spawn, settings, timeoutMs });
  }
  const keyInput = `${agentKey}\n${previousAgentKey}\n`;
  const windowsArgv = ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(WINDOWS_BOOTSTRAP, 'utf16le').toString('base64')];
  let body;
  try {
    body = platform === 'windows'
      ? execBody(windowsArgv, keyInput + script)
      : execBody(['/bin/sh', '-c', script], keyInput);
  } catch {
    // Only source is staged, under random generated paths. QGA file-write's
    // encode=0 explicitly means that content is already base64-encoded.
    const nonce = crypto.randomBytes(16).toString('hex');
    const paths = [];
    for (let offset = 0; offset < script.length; offset += SOURCE_CHUNK_BYTES) {
      const path = platform === 'windows'
        ? `C:\\Windows\\Temp\\cybercore-wazuh-${nonce}-${paths.length}.part`
        : `/tmp/cybercore-wazuh-${nonce}-${paths.length}.part`;
      paths.push(path);
      const content = Buffer.from(script.slice(offset, offset + SOURCE_CHUNK_BYTES), 'ascii').toString('base64');
      const written = await post(`${base}/file-write`, form([['file', path], ['content', content], ['encode', '0']]));
      if (written !== null && written !== undefined) throw dispatchError();
    }
    const digest = crypto.createHash('sha256').update(script, 'ascii').digest('hex');
    body = platform === 'windows'
      ? execBody(windowsArgv, keyInput + stagedWindowsSource(paths, digest))
      : execBody(stagedLinuxArgv(paths, digest), keyInput);
  }
  // This trusted callback may carry the service's own safe authorization errors.
  if (deps.beforeExec) await deps.beforeExec();
  const result = await post(`${base}/exec`, body);
  if (!result || !Number.isSafeInteger(result.pid) || result.pid <= 0) throw dispatchError();
  return { pid: result.pid };
}

module.exports = { dispatchWazuhGuest, WINDOWS_BOOTSTRAP };
