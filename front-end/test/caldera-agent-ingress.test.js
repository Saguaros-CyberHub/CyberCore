'use strict';

// Exercise the production snippets with the pinned Caddy binary and two local
// mock services. Run with CADDY_BIN=/path/to/caddy node --test <this file>.
// This verifies proxy behavior without requiring Docker, Caldera, or a lane.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const caddyBinary = process.env.CADDY_BIN;
const caddySource = fs.readFileSync(path.join(__dirname, '../../config/caddy/Caddyfile'), 'utf8').replace(/\r\n/g, '\n');
const token = 'a'.repeat(64);
const paw = 'c'.repeat(24);
const group = 'lane-12345678-abcd-abcd-abcd-123456789abc';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

function request(port, requestPath, { method = 'POST', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: requestPath, method, headers }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: text }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('agent ingress authenticates exact contacts, removes privileged headers, and preserves the console gate', {
  skip: !caddyBinary && 'set CADDY_BIN to run the real Caddy integration test',
  timeout: 20000,
}, async (t) => {
  const authRequests = [];
  const upstreamRequests = [];
  const auth = http.createServer((req, res) => {
    authRequests.push({ url: req.url, method: req.method, headers: req.headers });
    const agentPath = new RegExp('^/agent/' + token + '/(beacon|file/download|file/upload)$');
    const endpoint = new URL(req.url, 'http://localhost').pathname;
    if (endpoint === '/api/caldera-agents/authorize') {
      if (agentPath.test(req.headers['x-forwarded-uri'] || '')) {
        res.writeHead(204, { 'X-Caldera-Paw': paw, 'X-Caldera-Group': group });
      } else res.writeHead(403);
    } else if (endpoint === '/api/caldera-authoring/authorize') {
      res.writeHead(req.headers['x-console-session'] === 'staff' ? 204 : 401);
    } else {
      res.writeHead(404);
    }
    res.end();
  });
  const upstream = http.createServer(async (req, res) => {
    let body = '';
    for await (const part of req) body += part;
    upstreamRequests.push({ url: req.url, method: req.method, headers: req.headers, body });
    res.writeHead(200);
    res.end('upstream');
  });
  const authPort = await listen(auth);
  const upstreamPort = await listen(upstream);
  const reservation = http.createServer();
  const proxyPort = await listen(reservation);
  await new Promise((resolve) => reservation.close(resolve));
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'cybercore-caldera-ingress-'));
  const config = path.join(temporary, 'Caddyfile');
  // Read both complete production snippets, not a reconstruction of their rules.
  const snippetStart = caddySource.indexOf('(caldera_gate) {');
  const snippetEnd = caddySource.indexOf('# --- Public site');
  assert.ok(snippetStart >= 0 && snippetEnd > snippetStart);
  const snippets = caddySource.slice(snippetStart, snippetEnd).replaceAll('app:3000', '127.0.0.1:' + authPort);
  const globalStart = caddySource.indexOf('\n{\n') + 1;
  const globalEnd = caddySource.indexOf('\n}\n', globalStart) + 2;
  assert.ok(globalStart > 0 && globalEnd > globalStart);
  const globalOptions = caddySource.slice(globalStart, globalEnd)
    .replace('auto_https disable_redirects', 'admin off\n    auto_https off');
  fs.writeFileSync(config, globalOptions + '\n' + snippets
    + '\nhttp://127.0.0.1:' + proxyPort + ' {\n import caldera_agent_ingress\n handle {\n import caldera_gate\n }\n}\n');
  const proc = spawn(caddyBinary, ['run', '--config', config, '--adapter', 'caddyfile'], {
    windowsHide: true,
    env: {
      ...process.env,
      CALDERA_AUTHORING_UPSTREAM: '127.0.0.1:' + upstreamPort,
      CALDERA_API_KEY_RED: 'console-test-key',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let diagnostics = '';
  proc.stderr.on('data', (part) => { diagnostics += part; });
  proc.stdout.resume();
  t.after(async () => {
    proc.kill();
    if (proc.exitCode === null) await once(proc, 'exit');
    auth.closeAllConnections();
    upstream.closeAllConnections();
    await Promise.all([auth, upstream].map((s) => new Promise((resolve) => s.close(resolve))));
    fs.rmSync(temporary, { recursive: true, force: true });
  });
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await request(proxyPort, '/', { method: 'GET' });
      ready = true;
      break;
    } catch {
      if (proc.exitCode !== null) break;
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
  }
  assert.ok(ready, 'Caddy failed to start: ' + diagnostics);
  authRequests.length = 0;

  const beacon = '/agent/' + token + '/beacon';
  const hostileHeaders = {
    KEY: 'attacker-key', Cookie: 'session=attacker', Authorization: 'Bearer attacker',
    'X-CyberCore-Auth': 'forged', 'Remote-User': 'admin',
    'X-Caldera-Paw': 'forged-paw', 'X-Caldera-Group': 'forged-group',
    'X-Forwarded-Uri': '/api/v2/agents',
  };
  assert.equal((await request(proxyPort, beacon, { body: 'YmVhY29u', headers: hostileHeaders })).status, 200);
  assert.equal(authRequests.at(-1).method, 'GET');
  assert.equal(authRequests.at(-1).headers['x-forwarded-uri'], beacon);
  const checkin = upstreamRequests.at(-1);
  assert.equal(checkin.url, '/beacon');
  assert.equal(checkin.method, 'POST');
  assert.equal(checkin.body, 'YmVhY29u');
  assert.equal(authRequests.at(-1).headers['x-caldera-paw'], undefined);
  assert.equal(authRequests.at(-1).headers['x-caldera-group'], undefined);
  assert.equal(checkin.headers['x-caldera-paw'], paw);
  assert.equal(checkin.headers['x-caldera-group'], group);
  for (const header of ['key', 'authorization', 'cookie', 'x-cybercore-auth', 'remote-user', 'x-forwarded-uri']) {
    assert.equal(checkin.headers[header], undefined, 'agent supplied privileged ' + header);
  }

  const download = '/agent/' + token + '/file/download';
  assert.equal((await request(proxyPort, download, { headers: {
    file: 'sandcat.go', platform: 'windows', architecture: 'amd64',
    server: 'https://attacker.example', group: 'other-lane', 'gocat-extensions': 'shared',
  } })).status, 200);
  const binary = upstreamRequests.at(-1);
  assert.equal(binary.url, '/file/download');
  assert.equal(binary.headers.file, 'sandcat.go');
  assert.equal(binary.headers.platform, 'windows');
  assert.equal(binary.headers.architecture, 'amd64');
  for (const header of ['server', 'group', 'gocat-extensions']) assert.equal(binary.headers[header], undefined);
  assert.equal((await request(proxyPort, download, { headers: { file: 'ability-payload.ps1', platform: 'windows' } })).status, 200);
  assert.equal((await request(proxyPort, download, { headers: { file: 'sandcat.go', platform: 'linux' } })).status, 200);
  assert.equal(upstreamRequests.at(-1).headers.architecture, 'amd64');

  const accepted = upstreamRequests.length;
  for (const [file, status] of [['../conf/local.yml', 400], ['conf/local.yml', 400], ['packer:sandcat.go', 400], ['shared.go', 403]]) {
    assert.equal((await request(proxyPort, download, { headers: { file } })).status, status);
  }
  for (const headers of [{ file: 'sandcat.go', platform: 'other' }, { file: 'sandcat.go', platform: 'linux', architecture: 'bad' }]) {
    assert.equal((await request(proxyPort, download, { headers })).status, 400);
  }
  assert.equal(upstreamRequests.length, accepted);

  assert.equal((await request(proxyPort, '/agent/' + token + '/file/upload', { headers: {
    Directory: 'payloads', 'X-Request-Id': 'training-abc123', 'X-Paw': 'abc123', 'X-Host': 'training',
  } })).status, 200);
  assert.equal(upstreamRequests.at(-1).headers.directory, undefined);
  assert.equal(upstreamRequests.at(-1).headers['x-paw'], paw);
  assert.equal(upstreamRequests.at(-1).headers['x-request-id'], paw);

  const beforeDenied = upstreamRequests.length;
  assert.equal((await request(proxyPort, '/agent/' + 'b'.repeat(64) + '/beacon')).status, 403);
  assert.equal((await request(proxyPort, beacon + '?extra=1')).status, 403);
  for (const suffix of ['/api/v2/agents', '/file/download_exfil', '/beacon/extra', '/beacon/']) {
    assert.equal((await request(proxyPort, '/agent/' + token + suffix, { headers: hostileHeaders })).status, 404);
  }
  assert.equal((await request(proxyPort, beacon, { method: 'GET' })).status, 404);
  for (const endpoint of ['/api/v2/agents', '/beacon', '/file/download', '/']) {
    assert.equal((await request(proxyPort, endpoint, { headers: hostileHeaders })).status, 401);
  }
  assert.equal(upstreamRequests.length, beforeDenied);
  assert.equal((await request(proxyPort, '/api/v2/agents', { headers: { 'X-Console-Session': 'staff', KEY: 'attacker-key' } })).status, 200);
  assert.equal(upstreamRequests.at(-1).headers.key, 'console-test-key');

  // A stopped authorizer must fail closed for agent and instructor requests.
  auth.closeAllConnections();
  await new Promise((resolve) => auth.close(resolve));
  const beforeOutage = upstreamRequests.length;
  assert.equal((await request(proxyPort, beacon)).status, 502);
  assert.equal((await request(proxyPort, '/api/v2/agents')).status, 502);
  assert.equal(upstreamRequests.length, beforeOutage);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(!diagnostics.includes(token), 'proxy error logs must not contain agent credentials');
});
