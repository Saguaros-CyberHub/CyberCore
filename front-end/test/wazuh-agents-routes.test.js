'use strict';

const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

const LANE = '11111111-2222-4333-8444-555555555555';
const OTHER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const state = {};
const audit = { log: async event => { state.audits.push(event); } };
const auditPath = require.resolve('../src/utils/audit');
require.cache[auditPath] = { id: auditPath, filename: auditPath, loaded: true, exports: audit };
process.env.JWT_SECRET = 'wazuh-route-test-signing-key';

const { createRouter } = require('../src/routes/admin/wazuh-agents');
const clone = value => structuredClone(value);

function reset() {
  Object.assign(state, { queries: [], calls: [], audits: [], failQuery: false, failService: null,
    lanes: [{ lane_id: LANE, name: 'Course lane', status: 'active', config: {
      course_id: OTHER, vms: [{ vm_id: 101 }], password: 'private-lane-password',
    } }, { lane_id: OTHER, name: 'Challenge lane', status: 'active', config: { vms: [{ vm_id: 201 }] } }],
    results: [{ lane_id: LANE, vm_id: 101, job: { job_id: 'job-one', status: 'queued' } }],
  });
}
reset();
beforeEach(reset);
const router = createRouter({ audit,
  query: async (sql, args) => {
    state.queries.push({ sql, args });
    if (state.failQuery) throw new Error('database-password-do-not-disclose');
    assert.match(sql, /status = 'active'/);
    assert.match(sql, /status = 'suspended'/);
    return { rows: clone(args ? state.lanes.filter(lane => args[0].includes(lane.lane_id)) : state.lanes) };
  },
  service: {
    status: async lanes => {
      state.calls.push({ action: 'status', lanes });
      if (state.failService) throw state.failService;
      return { manager: 'wazuh.example', configuration_error: null, lanes: lanes.map(lane => ({ lane_id: lane.lane_id, name: lane.name })) };
    },
    startBatch: async (lanes, input) => {
      state.calls.push({ action: 'startBatch', lanes, input });
      if (state.failService) throw state.failService;
      return { results: clone(state.results) };
    },
  },
});

function request(method, url, { role = 'admin', body = {}, stage, cookie = false } = {}) {
  const token = role ? jwt.sign({ sub: 'admin-user', role, ...(stage ? { stage } : {}) }, process.env.JWT_SECRET, { expiresIn: '1h' }) : null;
  return new Promise((resolve, reject) => {
    const req = { method, url, originalUrl: url, baseUrl: '', headers: token && !cookie ? { authorization: `Bearer ${token}` } : {},
      cookies: token && cookie ? { token } : {}, params: {}, query: {}, body };
    const res = { statusCode: 200, headers: {},
      status(code) { this.statusCode = code; return this; },
      set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
      setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
      getHeader(name) { return this.headers[name.toLowerCase()]; },
      json(data) { resolve({ status: this.statusCode, body: clone(data), headers: this.headers }); return this; },
    };
    router(req, res, error => error ? reject(error) : resolve({ status: 404 }));
  });
}
const target = () => ({ lane_id: LANE, vm_id: 101, platform: 'windows' });
const post = (body = { targets: [target()] }, options = {}) => request('POST', '/wazuh-agents/batch', { body, ...options });

test('status and install require a completed admin sign-in before accessing inventory or Wazuh', async () => {
  for (const role of [null, 'student', 'instructor']) {
    for (const [method, url] of [['GET', '/wazuh-agents'], ['POST', '/wazuh-agents/batch']]) {
      assert.equal((await request(method, url, { role })).status, role ? 403 : 401);
    }
  }
  assert.equal((await post(undefined, { stage: 'mfa' })).status, 401);
  assert.deepEqual(state.queries, []);
  assert.deepEqual(state.calls, []);
});

test('admin status spans course and challenge lanes and prevents response caching', async () => {
  const result = await request('GET', '/wazuh-agents', { cookie: true });
  assert.equal(result.status, 200);
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.deepEqual(result.body.lanes.map(lane => lane.lane_id), [LANE, OTHER]);
  assert.equal(state.calls[0].lanes[0].config.course_id, OTHER);
  // Grouping/sort context for the dialog. Projected by the service's allowlist.
  assert.match(state.queries[0].sql, /vxlan_id, created_at/);
  assert.doesNotMatch(JSON.stringify(result.body), /private-lane-password/);
});

test('invalid, oversized and duplicate selections never query inventory or queue jobs', async () => {
  const badBodies = [{}, null, { targets: [] }, { targets: Array.from({ length: 201 }, target) },
    { targets: [{ ...target(), lane_id: "' OR true --" }] },
    { targets: [{ ...target(), vm_id: '101' }] }, { targets: [{ ...target(), vm_id: -1 }] },
    { targets: [{ ...target(), platform: 'shell' }] }, { targets: [target(), target()] },
    { targets: [{ ...target(), lane_id: OTHER }, { ...target(), lane_id: OTHER.toUpperCase() }] }];
  for (const body of badBodies) assert.equal((await post(body)).status, 400);
  assert.deepEqual(state.queries, []);
  assert.deepEqual(state.calls, []);
});

test('batch resolves only selected lanes and strips browser-supplied scripts, configuration and credentials', async () => {
  const result = await post({ targets: [{ ...target(), script: 'malicious', manager: 'other.example' }],
    api_password: 'browser-secret', config: { vms: [{ vm_id: 999 }] } });
  assert.equal(result.status, 202);
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.deepEqual(state.calls[0].lanes.map(lane => lane.lane_id), [LANE]);
  assert.deepEqual(state.calls[0].input, { targets: [target()] });
  assert.deepEqual(state.queries[0].args, [[LANE]]);
  assert.match(state.queries[0].sql, /ANY\(\$1::uuid\[\]\)/);
  // startBatch needs no display context; only the status query carries it.
  assert.doesNotMatch(state.queries[0].sql, /created_at/);
  assert.equal(state.audits[0].action, 'lane.wazuh_agents_queued');
  assert.doesNotMatch(JSON.stringify(state.audits[0].metadata), /browser-secret|private-lane-password|malicious/);
});

test('a disappeared lane prevents the whole request from queueing any sibling', async () => {
  state.lanes = state.lanes.filter(lane => lane.lane_id === LANE);
  const result = await post({ targets: [target(), { lane_id: OTHER, vm_id: 201, platform: 'linux' }] });
  assert.equal(result.status, 409);
  assert.deepEqual(state.calls, []);
  assert.deepEqual(state.audits, []);
});

test('per-VM queue failures are retained in the accepted batch response', async () => {
  state.results.push({ lane_id: OTHER, vm_id: 201, status: 409, error: 'VM stopped.' });
  const result = await post({ targets: [target(), { lane_id: OTHER, vm_id: 201, platform: 'linux' }] });
  assert.equal(result.status, 202);
  assert.equal(result.body.results[1].error, 'VM stopped.');
  assert.equal(state.audits[0].metadata.results[1].status, 'rejected');
});

test('unexpected infrastructure errors are hidden and safe service errors remain actionable', async () => {
  state.failQuery = true;
  const failed = await post();
  assert.equal(failed.status, 500);
  assert.doesNotMatch(JSON.stringify(failed.body), /database-password/);
  state.failQuery = false;
  state.failService = Object.assign(new Error('Configure the central Wazuh manager.'), { status: 503, safe: true });
  const unavailable = await post();
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.error, 'Configure the central Wazuh manager.');
  state.failService = Object.assign(new Error('upstream-api-password-do-not-disclose'), { status: 502 });
  const upstream = await post();
  assert.equal(upstream.status, 502);
  assert.doesNotMatch(JSON.stringify(upstream.body), /upstream-api-password/);
});
