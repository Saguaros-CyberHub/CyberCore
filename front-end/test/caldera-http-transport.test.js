'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { createCalderaClient, CalderaError } = require('../src/incident/caldera/client');

async function localClient(t, handler, timeoutMs = 200) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  }));
  return createCalderaClient({
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    apiKey: 'local-test-only', timeoutMs,
  });
}

test('HTTP transport reads a complete JSON profile response', { timeout: 5000 }, async (t) => {
  const profiles = [{ adversary_id: 'local-profile', name: 'Profile', atomic_ordering: ['step'] }];
  const client = await localClient(t, (req, res) => {
    assert.equal(req.url, '/api/v2/adversaries');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(profiles));
  }, 2000);
  assert.deepEqual(await client.listAdversaries(), profiles);
});

test('HTTP transport classifies a timeout before response headers', { timeout: 5000 }, async (t) => {
  let requested = false;
  const client = await localClient(t, () => { requested = true; });
  await assert.rejects(client.listAdversaries(), (error) => {
    assert.ok(error instanceof CalderaError);
    assert.equal(error.code, 'CALDERA_TIMEOUT');
    assert.equal(error.operation, 'GET /adversaries');
    return true;
  });
  assert.equal(requested, true);
});

test('HTTP transport classifies a stalled body after successful headers as a timeout', { timeout: 5000 }, async (t) => {
  let bodyStarted = false;
  const client = await localClient(t, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.flushHeaders();
    res.write('[');
    bodyStarted = true;
    // Deliberately leave the body open until the request deadline aborts it.
  });
  await assert.rejects(client.listAdversaries(), (error) => {
    assert.ok(error instanceof CalderaError);
    assert.equal(error.code, 'CALDERA_TIMEOUT');
    assert.equal(error.operation, 'GET /adversaries');
    assert.ok(['AbortError', 'TimeoutError'].includes(error.cause.name));
    return true;
  });
  assert.equal(bodyStarted, true);
});

test('HTTP transport classifies a body disconnected before completion as unreachable', { timeout: 5000 }, async (t) => {
  const client = await localClient(t, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 100 });
    res.flushHeaders();
    res.write('[');
    setImmediate(() => res.destroy());
  }, 2000);
  await assert.rejects(client.listAdversaries(), (error) => {
    assert.ok(error instanceof CalderaError);
    assert.equal(error.code, 'CALDERA_UNREACHABLE');
    assert.equal(error.operation, 'GET /adversaries');
    return true;
  });
});
