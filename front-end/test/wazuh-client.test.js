'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createClient, defaultSettings, managerHostname } = require('../src/utils/wazuh-client');

const SECRET = 'private-api-password';
const KEY = Buffer.from(`001 cc-test any ${'a'.repeat(64)}`).toString('base64');
const TOKEN = `header.${Buffer.from(JSON.stringify({ exp: 9999999999 })).toString('base64url')}.signature`;
const emptyAgents = { error: 0, data: { affected_items: [], total_affected_items: 0, total_failed_items: 0 } };
const options = { apiUrl: 'https://wazuh.example.test:55000', username: 'api-user', password: SECRET };

// Inject only Node's request transport; the production request/auth/pagination
// code still runs, including headers, TLS options and its wall-clock deadline.
function harness(handler = () => emptyAgents, overrides = {}) {
  const state = { calls: [], destroyed: 0 };
  const request = (url, opts, callback) => {
    const req = new EventEmitter();
    req.destroy = () => { state.destroyed++; };
    req.end = body => {
      state.calls.push({ url, opts, body });
      setImmediate(() => {
        const answer = handler(url, opts, body, state);
        if (answer?.hang) return;
        if (answer?.error instanceof Error) { req.emit('error', answer.error); return; }
        const res = new EventEmitter();
        res.statusCode = answer?.statusCode || 200;
        res.resume = () => {};
        res.destroy = () => { state.destroyed++; };
        callback(res);
        if (res.statusCode < 200 || res.statusCode >= 300) return;
        const payload = url.pathname === '/security/user/authenticate' && !answer?.authBody
          ? TOKEN : (answer?.authBody || answer?.body || answer);
        res.emit('data', Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)));
        res.emit('end');
      });
    };
    return req;
  };
  return { state, client: createClient({ ...options, ...overrides.options }, { request, ...overrides.deps }) };
}

test('authentication uses HTTPS Basic once, cached Bearer thereafter, with verified TLS and optional private CA', async () => {
  const ca = Buffer.from('private-ca-pem');
  const h = harness(undefined, { options: { caFile: '/test/ca.pem' }, deps: {
    readFileSync: path => { assert.equal(path, '/test/ca.pem'); return ca; },
  } });
  await Promise.all([h.client.listAgents(), h.client.listAgents()]);
  assert.equal(h.state.calls.filter(call => call.url.pathname === '/security/user/authenticate').length, 1);
  const auth = h.state.calls[0];
  assert.equal(auth.url.href, 'https://wazuh.example.test:55000/security/user/authenticate?raw=true');
  assert.equal(auth.opts.method, 'POST');
  assert.equal(auth.opts.headers.Authorization, `Basic ${Buffer.from(`api-user:${SECRET}`).toString('base64')}`);
  for (const call of h.state.calls) {
    assert.equal(call.url.protocol, 'https:');
    assert.equal(call.opts.rejectUnauthorized, true);
    assert.equal(call.opts.ca, ca);
    assert.equal(Object.hasOwn(call.opts, 'servername'), false);
    if (call.url.pathname === '/agents') assert.equal(call.opts.headers.Authorization, `Bearer ${TOKEN}`);
  }
});

test('explicit TLS server name preserves the connection address, CA and standard certificate verification', async () => {
  const ca = Buffer.from('trusted-server-certificate-pem');
  const h = harness(undefined, { options: { apiUrl: 'https://192.0.2.5:55000', serverName: 'localhost', caFile: '/test/server.pem' },
    deps: { readFileSync: () => ca } });
  await h.client.listAgents();
  for (const call of h.state.calls) {
    assert.equal(call.url.hostname, '192.0.2.5');
    assert.equal(call.url.port, '55000');
    assert.equal(call.opts.servername, 'localhost');
    assert.equal(call.opts.ca, ca);
    assert.equal(call.opts.rejectUnauthorized, true);
    assert.equal(Object.hasOwn(call.opts, 'checkServerIdentity'), false);
  }
});

test('TLS server name remains optional and can use the default CA store', async () => {
  for (const serverName of [undefined, '', 'api.wazuh.example.test']) {
    const h = harness(undefined, { options: { serverName } });
    await h.client.listAgents();
    for (const call of h.state.calls) {
      assert.equal(call.opts.servername, serverName || undefined);
      assert.equal(Object.hasOwn(call.opts, 'ca'), false);
      assert.equal(call.opts.rejectUnauthorized, true);
      assert.equal(Object.hasOwn(call.opts, 'checkServerIdentity'), false);
    }
  }
});

test('TLS server name accepts DNS names and rejects unsafe or non-DNS values before making requests', () => {
  for (const serverName of ['localhost', 'api.wazuh.example.test', 'Wazuh-API', 'xn--bcher-kva.example']) {
    assert.doesNotThrow(() => createClient({ ...options, serverName }));
  }
  for (const serverName of ['https://localhost', 'localhost:55000', 'localhost/path', 'user@localhost',
    '127.0.0.1', '2001:db8::1', '[::1]', 'localhost?query', 'localhost#fragment', '*.example.test',
    ' localhost', 'localhost ', 'localhost\n', 'local\rhost', 'local\0host', '-host', 'host-', '.host',
    'host..test', 'host_name', 'host;command', 'host$(command)', 'a'.repeat(64),
    Array(5).fill('a'.repeat(63)).join('.'), null, 123, {}]) {
    let requested = false;
    assert.throws(() => createClient({ ...options, serverName }, { request: () => { requested = true; } }),
      error => error.status === 503 && error.safe === true && error.message.includes('WAZUH_API_SERVER_NAME'));
    assert.equal(requested, false);
  }
});

test('agent listing reads every page with stable sorting and a restricted field selection', async () => {
  const agents = Array.from({ length: 501 }, (_, index) => ({ id: String(index).padStart(3, '0'), name: `agent-${index}` }));
  const h = harness(url => ({ error: 0, data: { total_affected_items: agents.length, total_failed_items: 0,
    affected_items: agents.slice(Number(url.searchParams.get('offset')), Number(url.searchParams.get('offset')) + 500) } }));
  assert.deepEqual(await h.client.listAgents(), agents);
  const calls = h.state.calls.filter(call => call.url.pathname === '/agents');
  assert.deepEqual(calls.map(call => call.url.searchParams.get('offset')), ['0', '500']);
  assert.equal(calls[0].url.searchParams.get('select'), 'id,name,status,lastKeepAlive');
  assert.equal(calls[0].url.searchParams.get('sort'), '+id');
});

test('create and retrieve enrollment keys match the official Wazuh response shapes', async () => {
  const h = harness((url, opts, body) => {
    if (url.pathname === '/agents') {
      assert.equal(opts.method, 'POST');
      assert.deepEqual(JSON.parse(body), { name: 'cc-test', ip: 'any' });
      // https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-manager-API/requesting-the-key.html
      return { error: 0, data: { id: '001', key: KEY } };
    }
    // https://github.com/wazuh/wazuh/blob/v4.14.0/api/api/spec/spec.yaml
    return { error: 0, data: { affected_items: [{ id: '001', key: KEY }], total_affected_items: 1, total_failed_items: 0 } };
  });
  assert.deepEqual(await h.client.createAgent('cc-test'), { id: '001', key: KEY });
  assert.equal(await h.client.getAgentKey('001'), KEY);
  assert.equal(h.state.calls.at(-1).url.pathname, '/agents/001/key');
});

test('creation without an inline key allows service to retrieve the key subsequently', async () => {
  const h = harness(() => ({ error: 0, data: { id: '001' } }));
  assert.deepEqual(await h.client.createAgent('cc-test'), { id: '001', key: null });
});

test('invalid or mismatched registration IDs and keys fail without publishing response content', async () => {
  const invalid = [
    { error: 0, data: { affected_items: [{ id: '999', key: KEY }], total_failed_items: 0 } },
    { error: 0, data: { affected_items: [{ id: '001', key: `${SECRET} invalid` }], total_failed_items: 0 } },
    { error: 0, data: { affected_items: [{ id: '001', key: KEY }], total_failed_items: 1, failed_items: [{ message: SECRET }] } },
  ];
  for (const response of invalid) {
    const h = harness(() => response);
    await assert.rejects(h.client.getAgentKey('001'), error => error.status === 502 && !error.message.includes(SECRET) && !error.message.includes(KEY));
  }
  const h = harness();
  for (const id of ['000', '../001', '001?leak=secret']) await assert.rejects(h.client.getAgentKey(id));
  for (const name of ['unowned', 'cc-invalid name', `cc-${'x'.repeat(126)}`]) await assert.rejects(h.client.createAgent(name));
  assert.equal(h.state.calls.length, 0);
});

test('redirects are refused without sending credentials to another endpoint', async () => {
  const h = harness(() => ({ statusCode: 302, body: { location: `https://attacker.example/${SECRET}` } }));
  await assert.rejects(h.client.listAgents(), error => error.status === 502 && !error.message.includes(SECRET));
  assert.equal(h.state.calls.length, 1);
  assert.equal(h.state.calls[0].url.hostname, 'wazuh.example.test');
});

test('network/TLS errors, remote error bodies and malformed JSON are redacted', async () => {
  for (const answer of [{ error: new Error(`certificate failure ${SECRET}`) },
    { statusCode: 403, body: SECRET }, { authBody: SECRET }]) {
    const h = harness(() => answer);
    await assert.rejects(h.client.listAgents(), error => !error.message.includes(SECRET));
  }
  for (const answer of [{ body: `invalid-json ${SECRET}` }, { error: 1000, message: SECRET }]) {
    const h = harness(() => answer);
    await assert.rejects(h.client.listAgents(), error => error.status === 502 && !error.message.includes(SECRET));
  }
});

test('request wall-clock timeout destroys a hung connection', async () => {
  const h = harness(() => ({ hang: true }), { deps: { timeoutMs: 15 } });
  await assert.rejects(h.client.listAgents(), { status: 504 });
  assert.equal(h.state.destroyed, 1);
});

test('an expired Bearer token is refreshed once and the authenticated operation is retried', async () => {
  let failed = false;
  const h = harness(url => {
    if (url.pathname === '/agents' && !failed) { failed = true; return { statusCode: 401, body: SECRET }; }
    return emptyAgents;
  });
  assert.deepEqual(await h.client.listAgents(), []);
  assert.equal(h.state.calls.filter(call => call.url.pathname === '/security/user/authenticate').length, 2);
  assert.equal(h.state.calls.filter(call => call.url.pathname === '/agents').length, 2);
});

test('incomplete pagination and an oversized response fail rather than returning partial inventory', async () => {
  const h = harness(() => ({ error: 0, data: { affected_items: [], total_affected_items: 1 } }));
  await assert.rejects(h.client.listAgents(), /incomplete agent list/);
  const large = harness(url => url.pathname === '/agents' ? { body: 'x'.repeat(8 * 1024 * 1024 + 1) } : emptyAgents);
  await assert.rejects(large.client.listAgents(), /exceeded the supported size/);
  assert.equal(large.state.destroyed, 1);
});

test('configuration requires a safe manager, HTTPS origin, API credentials and pinned supported agent version', () => {
  const env = { WAZUH_MANAGER: 'wazuh.example.test', WAZUH_API_URL: options.apiUrl,
    WAZUH_API_USERNAME: options.username, WAZUH_API_PASSWORD: SECRET,
    WAZUH_AGENT_VERSION: '4.14.0-1', WAZUH_DASHBOARD_URL: 'https://wazuh.example.test/app/wz-home' };
  const config = defaultSettings(env);
  assert.equal(config.manager, 'wazuh.example.test');
  assert.equal(config.version, '4.14.0-1');
  assert.equal(config.agentGroup, null);
  assert.equal(config.consoleUrl, env.WAZUH_DASHBOARD_URL);
  assert.doesNotThrow(() => defaultSettings({ ...env, WAZUH_API_SERVER_NAME: 'localhost' }));
  for (const changes of [{ WAZUH_AGENT_VERSION: '' }, { WAZUH_AGENT_VERSION: 'latest' }, { WAZUH_AGENT_VERSION: '5.0.0-1' },
    { WAZUH_API_URL: 'http://wazuh.example.test' }, { WAZUH_API_URL: `https://user:${SECRET}@wazuh.example.test` },
    { WAZUH_API_URL: 'https://wazuh.example.test/api' }, { WAZUH_API_URL: 'https://wazuh.example.test/?query' },
    { WAZUH_API_PASSWORD: '' }, { WAZUH_API_USERNAME: 'bad:username' }, { WAZUH_API_SERVER_NAME: 'localhost:55000' },
    { WAZUH_DASHBOARD_URL: 'javascript:alert(1)' }, { WAZUH_MANAGER: 'https://wazuh.example.test' }]) {
    assert.throws(() => defaultSettings({ ...env, ...changes }), error => error.status === 503 && !error.message.includes(SECRET));
  }
  for (const manager of ['wazuh.example.test', '192.0.2.5', '2001:db8::1']) assert.equal(managerHostname(manager), manager);
  for (const manager of ['name;touch', 'name$(secret)', '<xml>', 'server:1514', '-host', '.host']) assert.throws(() => managerHostname(manager));
  assert.throws(() => createClient({ ...options, caFile: '/private/missing' }, { readFileSync: () => { throw new Error(SECRET); } }), error => !error.message.includes(SECRET));
});

test('optional agent group accepts exact Wazuh names and rejects unsafe or ambiguous values', async () => {
  const env = { WAZUH_MANAGER: 'wazuh.example.test', WAZUH_API_URL: options.apiUrl,
    WAZUH_API_USERNAME: options.username, WAZUH_API_PASSWORD: SECRET, WAZUH_AGENT_VERSION: '4.14.1-1' };
  assert.equal(defaultSettings({ ...env, WAZUH_AGENT_GROUP: '' }).agentGroup, null);
  for (const group of ['StudentVM', 'student-vm_1.2', 'a'.repeat(128)]) {
    assert.equal(defaultSettings({ ...env, WAZUH_AGENT_GROUP: group }).agentGroup, group);
  }
  for (const group of ['.', '..', 'StudentVM,default', 'all/groups', ' StudentVM', 'StudentVM ',
    'StudentVM\n', 'student?group', 'x'.repeat(129), null, 123]) {
    assert.throws(() => defaultSettings({ ...env, WAZUH_AGENT_GROUP: group }), /WAZUH_AGENT_GROUP/);
    const h = harness();
    await assert.rejects(h.client.assertGroupExists(group), /WAZUH_AGENT_GROUP/);
    await assert.rejects(h.client.ensureAgentGroup('001', group), /WAZUH_AGENT_GROUP/);
    assert.equal(h.state.calls.length, 0);
  }
});

test('configured group preflight requires exactly the named existing group and never creates it', async () => {
  const h = harness(url => {
    if (url.pathname === '/groups') {
      assert.equal(url.searchParams.get('groups_list'), 'StudentVM');
      assert.equal(url.searchParams.get('select'), 'name');
    }
    return { error: 0, data: { affected_items: [{ name: 'StudentVM' }], total_affected_items: 1, total_failed_items: 0 } };
  });
  await h.client.assertGroupExists('StudentVM');
  assert.equal(h.state.calls.filter(call => call.url.pathname === '/groups').every(call => call.opts.method === 'GET'), true);
  for (const answer of [emptyAgents,
    { error: 0, data: { affected_items: [{ name: 'studentvm' }], total_affected_items: 1 } },
    { error: 1710, message: SECRET }, { statusCode: 403, body: SECRET }]) {
    const denied = harness(url => url.pathname === '/groups' ? answer : emptyAgents);
    await assert.rejects(denied.client.assertGroupExists('StudentVM'), error => error.status === 503
      && error.safe && /WAZUH_AGENT_GROUP/.test(error.message) && !error.message.includes(SECRET));
    assert.equal(denied.state.calls.some(call => call.url.pathname === '/groups' && call.opts.method !== 'GET'), false);
  }
});

test('group assignment targets one registered agent, preserves its other groups and verifies membership', async () => {
  const groups = ['default', 'servers'];
  const h = harness((url, opts, body) => {
    if (url.pathname === '/agents') {
      assert.equal(opts.method, 'GET');
      assert.equal(url.searchParams.get('agents_list'), '001');
      assert.equal(url.searchParams.get('select'), 'id,group');
      return { error: 0, data: { affected_items: [{ id: '001', group: [...groups] }], total_affected_items: 1 } };
    }
    if (url.pathname === '/agents/001/group/StudentVM') {
      assert.equal(opts.method, 'PUT');
      assert.equal(url.searchParams.get('force_single_group'), 'false');
      assert.equal(body, undefined);
      groups.push('StudentVM');
      return { error: 0, data: { affected_items: ['001'], total_affected_items: 1, total_failed_items: 0 } };
    }
    return emptyAgents;
  });
  await h.client.ensureAgentGroup('001', 'StudentVM');
  await h.client.ensureAgentGroup('001', 'StudentVM');
  assert.deepEqual(groups, ['default', 'servers', 'StudentVM']);
  assert.equal(h.state.calls.filter(call => call.opts.method === 'PUT').length, 1);
  assert.equal(h.state.calls.filter(call => call.url.pathname === '/agents').length, 3);
});

test('group retry tolerates already-assigned or lost responses only when a fresh read proves membership', async () => {
  for (const assignmentReply of [{ error: 2, data: { total_failed_items: 1,
    failed_items: [{ error: { code: 1751, message: SECRET }, id: ['001'] }] } },
  { error: new Error(SECRET) }]) {
    for (const confirmed of [false, true]) {
      let reads = 0;
      const h = harness(url => {
        if (url.pathname === '/agents') {
          const group = ++reads > 1 && confirmed ? ['default', 'StudentVM'] : ['default'];
          return { error: 0, data: { affected_items: [{ id: '001', group }], total_affected_items: 1 } };
        }
        return url.pathname.includes('/group/') ? assignmentReply : emptyAgents;
      });
      if (confirmed) await h.client.ensureAgentGroup('001', 'StudentVM');
      else await assert.rejects(h.client.ensureAgentGroup('001', 'StudentVM'), error => error.safe
        && /WAZUH_AGENT_GROUP/.test(error.message) && !error.message.includes(SECRET));
      assert.equal(reads, 2);
      assert.equal(h.state.calls.filter(call => call.opts.method === 'PUT').length, 1);
    }
  }
});

test('never-connected registrations may omit group until their first verified assignment', async () => {
  for (const confirmed of [true, false]) {
    let assigned = false;
    const h = harness((url, opts) => {
      if (url.pathname === '/agents') {
        return { error: 0, data: { affected_items: [{ id: '016',
          ...(assigned && confirmed ? { group: ['StudentVM'] } : {}) }], total_affected_items: 1, total_failed_items: 0 } };
      }
      if (url.pathname === '/agents/016/group/StudentVM') {
        assert.equal(opts.method, 'PUT');
        assert.equal(url.searchParams.get('force_single_group'), 'false');
        assigned = true;
        return { error: 0, data: { affected_items: ['016'], total_affected_items: 1, total_failed_items: 0 } };
      }
      return emptyAgents;
    });
    if (confirmed) await h.client.ensureAgentGroup('016', 'StudentVM');
    else await assert.rejects(h.client.ensureAgentGroup('016', 'StudentVM'), /WAZUH_AGENT_GROUP/);
    assert.equal(h.state.calls.filter(call => call.opts.method === 'PUT').length, 1);
    assert.equal(h.state.calls.filter(call => call.url.pathname === '/agents').length, 2);
  }
});

test('group assignment refuses invalid IDs and mismatched or malformed membership before mutation', async () => {
  const h = harness();
  for (const id of ['000', '../001', '001?agents_list=all']) await assert.rejects(h.client.ensureAgentGroup(id, 'StudentVM'));
  for (const group of [undefined, '']) await assert.rejects(h.client.assertGroupExists(group));
  assert.equal(h.state.calls.length, 0);
  for (const item of [{ id: '999', group: ['StudentVM'] }, { id: '001', group: 'StudentVM' }, { id: '001', group: [123] }, { id: '001', group: null }]) {
    const malformed = harness(() => ({ error: 0, data: { affected_items: [item], total_affected_items: 1 } }));
    await assert.rejects(malformed.client.ensureAgentGroup('001', 'StudentVM'), /WAZUH_AGENT_GROUP/);
    assert.equal(malformed.state.calls.some(call => call.opts.method === 'PUT'), false);
  }
});
