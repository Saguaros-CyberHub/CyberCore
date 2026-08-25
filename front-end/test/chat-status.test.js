/**
 * chat-status.test.js — the global AI assistant's on/off switch.
 *
 * The assistant used to be gated by ANTHROPIC_API_KEY alone, which made "turn
 * the chat bubble off" and "break profile generation, the interview simulator,
 * policy generation and the vuln-app builder" the same action. They are now two
 * independent switches:
 *
 *     AI_ASSISTANT_ENABLED     the deployment's INTENT   (default off)
 *     llmClient.isConfigured() the CAPABILITY            (is there a key)
 *
 * Both must hold. The assertions that matter are the two asymmetric ones: a key
 * with no flag must stay OFF (or nothing changed), and a flag with no key must
 * stay OFF (or the launcher appears and fails on every send).
 *
 * The 404 on POST /api/chat is not decoration. Hiding the launcher does not stop
 * a curl, and the endpoint spends tokens.
 *
 * Run: node --test "test/*.test.js"
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'chat-status-test-secret';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// clinic-api.js pulls in the CIAB pool and the profile generator at require
// time. Neither is exercised by the chat route; stub them so this test needs no
// database and no API key.
stub(path.join(CIAB, 'utils', 'db.js'), { query: async () => ({ rows: [], rowCount: 0 }) });
stub(path.join(CIAB, 'ai', 'profile'), { generateProfile: async () => ({}) });

// If the guard ever regresses, the handler must not be able to reach a live
// client — so the stub throws rather than returning plausible text.
let llmCalls = 0;
stub(path.join(ROOT, 'src', 'utils', 'llm-client.js'), {
  isConfigured: () => !!process.env.ANTHROPIC_API_KEY,
  cachedSystem: (s) => s,
  generate: async () => { llmCalls += 1; throw new Error('llm-client should not be reached'); },
});

const chatStatus = require(path.join(ROOT, 'src', 'routes', 'chat-status.js'));
const clinicApi = require(path.join(CIAB, 'routes', 'clinic-api.js'));

let server, port;

before(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/chat', chatStatus);
  app.use('/api', clinicApi);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());

const ORIGINAL = {
  flag: process.env.AI_ASSISTANT_ENABLED,
  key: process.env.ANTHROPIC_API_KEY,
};
after(() => {
  if (ORIGINAL.flag === undefined) delete process.env.AI_ASSISTANT_ENABLED;
  else process.env.AI_ASSISTANT_ENABLED = ORIGINAL.flag;
  if (ORIGINAL.key === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = ORIGINAL.key;
});

beforeEach(() => {
  llmCalls = 0;
  delete process.env.AI_ASSISTANT_ENABLED;
  delete process.env.ANTHROPIC_API_KEY;
});

const token = () => jwt.sign({ sub: 'u1', email: 'a@b.c', role: 'student' }, process.env.JWT_SECRET, { expiresIn: '1h' });

function request(pathname, { method = 'GET', body = null } = {}) {
  const payload = body == null ? null : JSON.stringify(body);
  const headers = { Authorization: `Bearer ${token()}` };
  if (payload) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload);
  }
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path: pathname, method, headers }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(raw); } catch (_) { /* not JSON */ }
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const status = () => request('/api/chat/status');

test('unset means off, even on a deployment that HAS an API key', async () => {
  // The whole point of the change: this used to report enabled:true.
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  assert.deepStrictEqual((await status()).json, { enabled: false });
});

test('the flag alone is not enough — no key, no launcher', async () => {
  // Otherwise the bubble renders and every send fails with "having trouble
  // connecting", which is worse than no bubble.
  process.env.AI_ASSISTANT_ENABLED = 'true';
  assert.deepStrictEqual((await status()).json, { enabled: false });
});

test('flag plus key turns it on', async () => {
  process.env.AI_ASSISTANT_ENABLED = 'true';
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  assert.deepStrictEqual((await status()).json, { enabled: true });
});

test('the flag is case-insensitive but not truthy-ish', async () => {
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  for (const on of ['true', 'TRUE', 'True']) {
    process.env.AI_ASSISTANT_ENABLED = on;
    assert.strictEqual((await status()).json.enabled, true, `${on} should enable`);
  }
  // '1' and 'yes' read as "on" to a human and must NOT be, matching
  // MAIL_ENABLED in src/utils/mailer.js. A deployment that half-enables the
  // assistant is worse than one that clearly did not.
  for (const off of ['1', 'yes', 'on', 'false', '']) {
    process.env.AI_ASSISTANT_ENABLED = off;
    assert.strictEqual((await status()).json.enabled, false, `${JSON.stringify(off)} should not enable`);
  }
});

test('the flag is read per request, not captured at module load', async () => {
  // Otherwise flipping it needs a redeploy rather than a restart, and this test
  // file could not assert anything above.
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  process.env.AI_ASSISTANT_ENABLED = 'true';
  assert.strictEqual((await status()).json.enabled, true);
  process.env.AI_ASSISTANT_ENABLED = 'false';
  assert.strictEqual((await status()).json.enabled, false);
});

test('POST /api/chat is 404 while the assistant is off, and spends nothing', async () => {
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  const res = await request('/api/chat', { method: 'POST', body: { message: 'hello' } });
  assert.strictEqual(res.status, 404);
  assert.match(res.json.error, /not enabled/i);
  assert.strictEqual(llmCalls, 0, 'the LLM must not be called for a refused request');
});

test('the guard runs before the empty-message check', async () => {
  // Both answer without an LLM call, so ordering is only observable here — but
  // it is the difference between "this deployment has no assistant" and
  // "your message was malformed", and only one of those is true.
  const res = await request('/api/chat', { method: 'POST', body: {} });
  assert.strictEqual(res.status, 404);
});


test('aiAssistantEnabled is exported so the CIAB route can share the switch', async () => {
  assert.strictEqual(typeof chatStatus.aiAssistantEnabled, 'function');
  process.env.AI_ASSISTANT_ENABLED = 'true';
  assert.strictEqual(chatStatus.aiAssistantEnabled(), true);
});
