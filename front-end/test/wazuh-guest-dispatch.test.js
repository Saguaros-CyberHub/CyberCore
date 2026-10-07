'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { dispatchWazuhGuest, WINDOWS_BOOTSTRAP } = require('../src/utils/wazuh-guest-dispatch');

const agentName = 'training-Windows-vm-100';
const previousAgentName = 'cc-11111111222243338444555555555555-100-0123456789abcdef0123456789abcdef';
const rawKey = 'a'.repeat(64);
const previousRawKey = 'B'.repeat(64);
const record = `017 ${agentName} any ${rawKey}`;
const previousRecord = `016 ${previousAgentName} any ${previousRawKey}`;
const agentKey = Buffer.from(record).toString('base64');
const previousAgentKey = Buffer.from(previousRecord).toString('base64');
const options = { node: 'cyberhub-node-5', vmId: 100, platform: 'windows', agentName, agentKey, script: "Write-Output 'SAFE_SOURCE'" };
const migration = { ...options, previousAgentName, previousAgentKey };
const env = { PROXMOX_API_URL: 'https://pve.example.test:8006', PROXMOX_TOKEN_ID: 'root@pam!fixture', PROXMOX_TOKEN_SECRET: 'fixture-token-secret', CURL_BIN: '/fixture/curl' };
const secrets = [agentKey, previousAgentKey, record, previousRecord, rawKey, previousRawKey, env.PROXMOX_TOKEN_SECRET];

function assertNoSecrets(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) assert.equal(text.includes(secret), false, 'a credential escaped its input channel');
}

function nativeHarness(handler) {
  const calls = [];
  return {
    calls,
    api: async (method, endpoint, body, opts) => {
      const call = { method, endpoint, body, opts, form: new URLSearchParams(body) };
      calls.push(call);
      return handler ? handler(call, calls) : endpoint.endsWith('/file-write') ? null : { pid: 812, extra: agentKey };
    },
  };
}

function parseConfig(config) {
  const pairs = [];
  for (const line of config.split('\n').filter(Boolean)) {
    const match = line.match(/^([^=]+?) = (.*)$/);
    pairs.push(match ? [match[1], JSON.parse(match[2])] : [line, true]);
  }
  return pairs;
}

function curlHarness(handler) {
  const calls = [];
  function spawn(binary, argv, opts) {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = new EventEmitter();
    child.kill = () => { child.killed = true; };
    child.stdin.end = config => {
      const values = parseConfig(config);
      const call = { binary, argv, opts, config, values, child,
        form: new URLSearchParams(values.find(([key]) => key === 'data-binary')[1]),
        url: values.find(([key]) => key === 'url')[1] };
      calls.push(call);
      queueMicrotask(() => {
        const result = handler ? handler(call, calls) : {};
        if (result.hang) return;
        if (result.error) return child.emit('error', new Error(agentKey));
        if (result.stdinError) return child.stdin.emit('error', new Error(agentKey));
        if (result.stderr) child.stderr.emit('data', Buffer.from(result.stderr));
        const data = Object.hasOwn(result, 'data') ? result.data : call.url.endsWith('/file-write') ? null : { pid: 813 };
        child.stdout.emit('data', Buffer.from(result.output === undefined
          ? JSON.stringify({ data }) + `\nCYBERCORE_HTTP_STATUS:${result.status || 200}\n` : result.output));
        child.emit('close', result.code || 0);
      });
    };
    return child;
  }
  return { calls, spawn, env };
}

test('Windows uses the same small encoded bootstrap and sends both keys only through input-data', async () => {
  for (const settings of [options, migration]) {
    const h = nativeHarness();
    assert.deepEqual(await dispatchWazuhGuest(settings, h), { pid: 812 });
    assert.equal(h.calls.length, 1);
    const call = h.calls[0];
    assert.equal(call.method, 'POST');
    assert.equal(call.endpoint, '/api2/json/nodes/cyberhub-node-5/qemu/100/agent/exec');
    const argv = call.form.getAll('command');
    assert.deepEqual(argv.slice(0, -1), ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
    assert.equal(Buffer.from(argv.at(-1), 'base64').toString('utf16le'), WINDOWS_BOOTSTRAP);
    assertNoSecrets(argv);
    assertNoSecrets(WINDOWS_BOOTSTRAP);
    assert.equal(call.form.get('input-data'), `${agentKey}\n${settings.previousAgentKey || ''}\n${settings.script}`);
    assert.ok(Buffer.byteLength(call.body) < 60 * 1024);
    assert.equal(call.opts.timeoutMs, 30000);
    assert.ok(call.opts.signal instanceof AbortSignal);
  }
});

test('Linux uses curl config stdin for authorization and key-bearing HTTP body', async () => {
  const h = curlHarness();
  const script = "#!/bin/sh\nprintf 'installer source is nonsecret\\n'\n";
  assert.deepEqual(await dispatchWazuhGuest({ ...migration, platform: 'linux', script }, h), { pid: 813 });
  const call = h.calls[0];
  assert.equal(call.binary, '/fixture/curl');
  assert.deepEqual(call.argv, ['-q', '--config', '-']);
  assert.equal(call.opts.shell, false);
  assert.equal(call.opts.windowsHide, true);
  assertNoSecrets(call.argv);
  assert.deepEqual(call.form.getAll('command'), ['/bin/sh', '-c', script]);
  assertNoSecrets(call.form.getAll('command'));
  assert.equal(call.form.get('input-data'), `${agentKey}\n${previousAgentKey}\n`);
  assert.equal(call.values.find(([key]) => key === 'header')[1], `Authorization: PVEAPIToken=${env.PROXMOX_TOKEN_ID}=${env.PROXMOX_TOKEN_SECRET}`);
  assert.equal(call.values.filter(([key]) => /trace|output|location|retry/.test(key)).length, 0);
  assert.equal(call.values.find(([key]) => key === 'proto')[1], '=https');
});

test('curl config preserves literal quotes and backslashes without adding directives', async () => {
  const h = curlHarness();
  h.env = { ...env, PROXMOX_TOKEN_SECRET: 'fixture-"quoted"\\backslash' };
  await dispatchWazuhGuest({ ...options, platform: 'linux' }, h);
  const call = h.calls[0];
  assert.equal(call.values.find(([key]) => key === 'header')[1], `Authorization: PVEAPIToken=${env.PROXMOX_TOKEN_ID}=${h.env.PROXMOX_TOKEN_SECRET}`);
  assert.equal(call.values.filter(([key]) => key === 'url').length, 1);
  assert.equal(call.values.filter(([key]) => key === 'data-binary').length, 1);
});

test('large Windows source is staged without credentials and verified before execution', async () => {
  const script = '# nonsecret padding\n'.repeat(2400) + options.script;
  const events = [];
  const h = nativeHarness(call => {
    events.push(call.endpoint.endsWith('/exec') ? 'exec' : 'write');
    return call.endpoint.endsWith('/file-write') ? null : { pid: 55 };
  });
  h.beforeExec = () => events.push('guard');
  assert.deepEqual(await dispatchWazuhGuest({ ...migration, script }, h), { pid: 55 });
  const writes = h.calls.filter(call => call.endpoint.endsWith('/file-write'));
  assert.ok(writes.length >= 2);
  assert.equal(writes.map(call => Buffer.from(call.form.get('content'), 'base64').toString('ascii')).join(''), script);
  for (const call of writes) {
    assert.equal(call.form.get('encode'), '0');
    assert.match(call.form.get('file'), /^C:\\Windows\\Temp\\cybercore-wazuh-[0-9a-f]{32}-\d+\.part$/);
    assertNoSecrets(Buffer.from(call.form.get('content'), 'base64').toString('ascii'));
    assertNoSecrets(call.body);
    assert.ok(call.body.length < 60 * 1024);
  }
  const exec = h.calls.at(-1);
  const input = exec.form.get('input-data');
  assert.ok(Buffer.byteLength(input) < 8 * 1024);
  const stub = input.slice(`${agentKey}\n${previousAgentKey}\n`.length);
  assertNoSecrets(stub);
  assert.ok(stub.includes(crypto.createHash('sha256').update(script).digest('hex')));
  assert.match(stub, /ComputeHash\(\$verifiedBytes\)/);
  assert.ok(stub.indexOf('[IO.File]::Delete') < stub.indexOf('ScriptBlock]::Create($verifiedSource)'));
  assert.deepEqual(events.slice(-2), ['guard', 'exec']);
});

test('large Linux source uses bounded source-only file writes and leaves key stdin untouched', async () => {
  const h = curlHarness();
  const script = '# ; nonsecret padding\n'.repeat(3200);
  await dispatchWazuhGuest({ ...migration, script, platform: 'linux' }, h);
  const writes = h.calls.slice(0, -1);
  assert.ok(writes.length >= 2);
  assert.equal(writes.map(call => Buffer.from(call.form.get('content'), 'base64').toString('ascii')).join(''), script);
  for (const call of writes) {
    assert.match(call.form.get('file'), /^\/tmp\/cybercore-wazuh-[0-9a-f]{32}-\d+\.part$/);
    assert.equal(call.form.get('encode'), '0');
    assertNoSecrets(call.form.toString());
  }
  const exec = h.calls.at(-1);
  assert.equal(exec.form.get('input-data'), `${agentKey}\n${previousAgentKey}\n`);
  const argv = exec.form.getAll('command');
  assert.deepEqual(argv.slice(0, 2), ['python3', '-c']);
  assertNoSecrets(argv);
  assert.match(argv[2], /hashlib\.sha256\(source\)/);
  assert.match(argv[2], /os\.execv\('\/bin\/sh', \['\/bin\/sh', '-c', script\]\)/);
  assert.ok(argv[2].indexOf('os.unlink') < argv[2].indexOf('os.execv'));
});

test('a failed fresh authorization guard prevents key-bearing execution after staging', async () => {
  const h = nativeHarness();
  const safeGuardError = new Error('Lane was removed.');
  h.beforeExec = () => { throw safeGuardError; };
  await assert.rejects(dispatchWazuhGuest({ ...options, script: '# public source\n'.repeat(1000) }, h), error => error === safeGuardError);
  assert.ok(h.calls.length);
  assert.ok(h.calls.every(call => call.endpoint.endsWith('/file-write')));
  for (const call of h.calls) assertNoSecrets(call.body);
});

test('invalid destinations, keys, source interpolation and oversize source fail before transport', async () => {
  const invalid = [
    null, [], { ...options, node: '../other' }, { ...options, node: 'node\r\n' },
    { ...options, vmId: 0 }, { ...options, vmId: '100' }, { ...options, vmId: 1.5 },
    { ...options, platform: 'darwin' }, { ...options, agentName: 'unrelated' },
    { ...options, agentKey: agentKey + '\n' }, { ...options, agentKey: previousAgentKey },
    { ...migration, previousAgentName: undefined }, { ...migration, previousAgentKey: undefined },
    { ...migration, previousAgentName: agentName }, { ...migration, previousAgentKey: agentKey },
    ...[agentKey, record, rawKey, previousAgentKey, previousRecord, previousRawKey].map(secret => ({ ...migration, script: '# ' + secret })),
    { ...options, script: '' }, { ...options, script: '   ' }, { ...options, script: '\u00e9' },
    { ...options, script: 'x\0y' }, { ...options, script: '# x\n'.repeat(65537) },
  ];
  for (const settings of invalid) {
    const h = nativeHarness();
    await assert.rejects(dispatchWazuhGuest(settings, h), error => {
      assert.equal(error.code, 'WAZUH_GUEST_DISPATCH_INVALID');
      assertNoSecrets(error.stack);
      return true;
    });
    assert.equal(h.calls.length, 0);
  }
});

test('Linux transport rejects injected credentials and non-HTTPS endpoints before spawning', async () => {
  for (const changes of [
    { PROXMOX_API_URL: 'http://pve.example.test' }, { PROXMOX_API_URL: 'https://user:secret@pve.example.test' },
    { PROXMOX_API_URL: 'https://pve.example.test/prefix' }, { PROXMOX_API_URL: 'https://pve.example.test?x=y' },
    { PROXMOX_TOKEN_ID: '' }, { PROXMOX_TOKEN_SECRET: '' }, { PROXMOX_TOKEN_SECRET: 'bad\nurl = "https://other"' },
    { CURL_BIN: 'curl\n' },
  ]) {
    const h = curlHarness();
    await assert.rejects(dispatchWazuhGuest({ ...options, platform: 'linux' }, { ...h, env: { ...env, ...changes } }), { code: 'WAZUH_GUEST_DISPATCH_INVALID' });
    assert.equal(h.calls.length, 0);
  }
});

test('native API failures, malformed PIDs and deadline errors never expose upstream responses', async () => {
  for (const handler of [
    () => { throw new Error(agentKey); },
    () => ({ pid: agentKey }), () => ({ pid: 0, detail: agentKey }),
    () => ({ pid: 1.5, detail: agentKey }), () => null,
  ]) {
    const h = nativeHarness(handler);
    await assert.rejects(dispatchWazuhGuest(options, h), error => {
      assertNoSecrets(error.stack);
      assert.equal(error.cause, undefined);
      return error.code === 'WAZUH_GUEST_DISPATCH_FAILED';
    });
    assert.equal(h.calls.length, 1, 'uncertain dispatch must not be retried');
  }
  const h = nativeHarness(() => new Promise(() => {}));
  await assert.rejects(dispatchWazuhGuest(options, { ...h, timeoutMs: 10 }), { code: 'WAZUH_GUEST_DISPATCH_TIMEOUT' });
  assert.equal(h.calls[0].opts.signal.aborted, true);
});

test('curl errors, redirects, malformed output and excessive output fail without retry or secret output', async () => {
  for (const response of [
    { status: 401, data: agentKey }, { status: 302, data: { pid: 1, location: agentKey } },
    { code: 7, stderr: agentKey }, { error: true }, { stdinError: true },
    { data: { pid: 0, secret: agentKey } }, { output: agentKey },
    { output: JSON.stringify({ data: { pid: 1 } }) + agentKey },
    { output: 'x'.repeat(65537) }, { stderr: 'x'.repeat(65537) },
  ]) {
    const h = curlHarness(() => response);
    await assert.rejects(dispatchWazuhGuest({ ...options, platform: 'linux' }, h), error => {
      assertNoSecrets(error.stack);
      assert.equal(error.cause, undefined);
      return error.code === 'WAZUH_GUEST_DISPATCH_FAILED';
    });
    assert.equal(h.calls.length, 1);
  }
  const h = curlHarness(() => ({ hang: true }));
  await assert.rejects(dispatchWazuhGuest({ ...options, platform: 'linux' }, { ...h, timeoutMs: 10 }), { code: 'WAZUH_GUEST_DISPATCH_TIMEOUT' });
  assert.equal(h.calls[0].child.killed, true);
});

test('failed or malformed source staging never submits enrollment keys', async () => {
  for (const handler of [() => { throw new Error(agentKey); }, () => ({ unexpected: agentKey })]) {
    const h = nativeHarness(handler);
    await assert.rejects(dispatchWazuhGuest({ ...options, script: '# public source\n'.repeat(1000) }, h), error => {
      assertNoSecrets(error.stack);
      return error.code === 'WAZUH_GUEST_DISPATCH_FAILED';
    });
    assert.ok(h.calls.every(call => call.endpoint.endsWith('/file-write')));
  }
});

const ps = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
const hasPowerShell = spawnSync(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { windowsHide: true, timeout: 10000 }).status === 0;
const scopeSource = [
  `$expectedName = '${agentName}'`,
  `$expectedPreviousName = '${previousAgentName}'`,
  '& {',
  "  $parts = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($agentKey)).Split(' ')",
  "  $old = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($previousAgentKey)).Split(' ')",
  "  if ($parts[1] -cne $expectedName -or $old[1] -cne $expectedPreviousName -or $parts[3].Length -ne 64) { throw 'scope' }",
  "  Write-Output 'BOOTSTRAP_OK'",
  '}',
].join('\n');

test('real PowerShell receives key variables through inherited scopes without argv or output disclosure', { skip: !hasPowerShell }, async () => {
  const h = nativeHarness();
  await dispatchWazuhGuest({ ...migration, script: scopeSource }, h);
  const call = h.calls.at(-1);
  const argv = call.form.getAll('command');
  const result = spawnSync(ps, argv.slice(1), { input: call.form.get('input-data'), encoding: 'utf8', timeout: 15000, windowsHide: true });
  assertNoSecrets(argv);
  assertNoSecrets(result.stdout + result.stderr);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'BOOTSTRAP_OK');
  assert.equal(result.stderr, '');
});

test('real PowerShell verifies staged bytes, deletes sources, and refuses tampered source', { skip: !hasPowerShell }, async () => {
  for (const tamper of [false, true]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wazuh-dispatch-test-'));
    const files = new Map();
    const h = nativeHarness(call => {
      if (call.endpoint.endsWith('/file-write')) {
        const remote = call.form.get('file');
        const local = path.join(directory, path.win32.basename(remote));
        files.set(remote, local);
        fs.writeFileSync(local, Buffer.from(call.form.get('content'), 'base64'));
        return null;
      }
      return { pid: 123 };
    });
    try {
      await dispatchWazuhGuest({ ...migration, script: '# nonsecret padding\n'.repeat(1600) + scopeSource }, h);
      if (tamper) fs.appendFileSync([...files.values()][0], '\nWrite-Output "TAMPERED_EXECUTED"');
      const call = h.calls.at(-1);
      let input = call.form.get('input-data');
      for (const [remote, local] of files) input = input.split(remote).join(local.replace(/'/g, "''"));
      const argv = call.form.getAll('command');
      assertNoSecrets(argv);
      const result = spawnSync(ps, argv.slice(1), { input, encoding: 'utf8', timeout: 15000, windowsHide: true });
      assertNoSecrets(result.stdout + result.stderr);
      assert.equal(result.status, tamper ? 1 : 0);
      assert.equal(result.stdout.trim(), tamper ? '' : 'BOOTSTRAP_OK');
      assert.equal(result.stderr.trim(), tamper ? 'CYBERCORE_WAZUH_ERROR:dispatch' : '');
      assert.ok([...files.values()].every(file => !fs.existsSync(file)));
    } finally {
      // Remove only this test's individual generated files; no recursive delete.
      for (const file of files.values()) if (fs.existsSync(file)) fs.unlinkSync(file);
      fs.rmdirSync(directory);
    }
  }
});

test('real PowerShell bootstrap suppresses exception text containing a credential', { skip: !hasPowerShell }, () => {
  const result = spawnSync(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(WINDOWS_BOOTSTRAP, 'utf16le').toString('base64')], {
    input: `${agentKey}\n\nthrow $agentKey`, encoding: 'utf8', timeout: 15000, windowsHide: true,
  });
  assert.equal(result.status, 1);
  assertNoSecrets(result.stdout + result.stderr);
  assert.equal(result.stderr.trim(), 'CYBERCORE_WAZUH_ERROR:dispatch');
});
