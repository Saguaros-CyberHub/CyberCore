'use strict';

// Real Express handlers and lane-agent service; fake DB/Caldera and queued
// execution. No live VM, authentication service or remote server is contacted.
const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CLE = path.join(ROOT, 'modules/crucible/plugins/cle');
const { createService, hashToken, groupFor, pawFor } = require('../src/utils/caldera-lane-agents');
const COURSE = '11111111-1111-1111-1111-111111111111';
const OTHER_COURSE = '22222222-2222-2222-2222-222222222222';
const LANE = '33333333-3333-3333-3333-333333333333';
const OTHER_LANE = '44444444-4444-4444-4444-444444444444';
const TOKEN = 'a'.repeat(64);
const API_KEY = 'private-red-api-key';
const state = {};
const clone = value => JSON.parse(JSON.stringify(value));

function reset() {
  state.course = { course_id: COURSE, code: 'CYBR400-01', course_name: 'Blue Team', features: { blue_team: true } };
  state.lanes = [{ lane_id: LANE, name: 'Own lane', status: 'active', config: {
    course_id: COURSE, internet_enabled: true, gateway_vm_id: 100,
    vms: [{ vm_id: 100, name: 'Gateway', type: 'qemu' }, { vm_id: 101, name: 'Windows 11', type: 'qemu', node: 'node-one' }],
    caldera_agent_access: { tokens: [{ vm_id: 101, token_hash: hashToken(TOKEN), paw: pawFor(LANE, 101) }] },
    unrelated_secret: 'private-lane-config',
  } }, { lane_id: OTHER_LANE, name: 'Foreign lane', status: 'active', config: {
    course_id: OTHER_COURSE, vms: [{ vm_id: 201, name: 'Linux', type: 'qemu' }],
  } }];
  state.agents = [{ paw: 'agent-one', host: 'DC01', group: groupFor(LANE), platform: 'windows', trusted: true,
    last_seen: '2026-09-05T01:00:00Z', executors: ['psh'], secret: API_KEY,
  }, { paw: 'foreign-agent', host: 'OTHER-DC', group: groupFor(OTHER_LANE), platform: 'windows' }];
  state.scopeCalls = [];
  state.queries = [];
  state.tasks = [];
  state.audits = [];
  state.agentReads = 0;
  state.runReads = 0;
  state.dbError = false;
}
reset();

const service = createService({
  now: () => Date.parse('2026-09-05T01:00:00Z'),
  settings: () => ({ serverUrl: 'https://agents.test.example', consoleUrl: 'https://console.test.example/', apiKey: API_KEY,
    client: { listAgents: async () => { state.agentReads++; return clone(state.agents); } },
  }),
  schedule: task => state.tasks.push(task),
  query: async (sql, params) => {
    state.queries.push({ sql, params });
    if (state.dbError) throw new Error('private database failure');
    if (/UPDATE cybercore_lane/.test(sql) && /RETURNING lane_id/.test(sql)) {
      const lane = state.lanes.find(row => row.lane_id === params[0] && row.status === 'active');
      if (!lane || lane.config.caldera_agent_job?.status === 'running') return { rows: [] };
      lane.config.caldera_agent_job = JSON.parse(params[1]);
      const token = JSON.parse(params[3]);
      lane.config.caldera_agent_access = { tokens: [token] };
      return { rows: [{ lane_id: lane.lane_id }] };
    }
    if (/SELECT l\.lane_id/.test(sql)) {
      const wanted = params[0];
      const lane = state.lanes.find(row => row.status === 'active'
        && row.config.caldera_agent_access?.tokens.some(token => token.token_hash === wanted));
      const token = lane?.config.caldera_agent_access.tokens.find(item => item.token_hash === wanted);
      return { rows: lane ? [{ lane_id: lane.lane_id, config: clone(lane.config), paw: token.paw, vm_id: String(token.vm_id) }] : [] };
    }
    throw new Error('Unexpected database query in route test');
  },
});

function put(relative, exports) {
  const filename = require.resolve(path.join(ROOT, relative));
  require.cache[filename] = { id: filename, filename, loaded: true, exports, children: [], paths: [] };
}
put('src/utils/caldera-lane-agents', { createService: () => service });
put('src/utils/audit', { log: async item => { state.audits.push(item); } });
put('src/incident/runner', { findScopeLanes: async scope => {
  state.scopeCalls.push(scope);
  return clone(state.lanes.filter(lane => lane.config.course_id === scope.scopeId && lane.status === 'active'));
} });
put('src/incident/board', {
  readRunForStaff: async () => { state.runReads++; return null; },
  readRunForStudent: async () => { state.runReads++; return null; },
});
put('src/incident/caldera/authoring', {});
put('src/routes/caldera-authoring', { authoringConfig: () => ({}), PUBLIC_PATH: '/caldera' });
put('modules/crucible/plugins/cle/utils/db', { query: async (sql, params) => ({
  rows: params[0] === COURSE && ['student', 'enrolled-instructor'].includes(params[1]) ? [clone(state.course)] : [],
}) });
put('modules/crucible/plugins/cle/utils/course-access', { getManagedCourse: async (courseId, user) =>
  courseId === COURSE && (user?.role === 'admin' || user?.userId === 'owner') ? clone(state.course) : null,
});
const courseRouter = require(path.join(CLE, 'routes/incidents'));
const { createRouter } = require('../src/routes/caldera-agents');
const callbackRouter = createRouter(service);

function request(router, method, url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '', params: {}, query: {},
      body: options.body || {}, headers: options.headers || {},
      user: options.user === null ? undefined : options.user || { role: 'instructor', userId: 'owner' },
      get(name) { return Object.entries(this.headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]; },
    };
    const res = {
      statusCode: 200, headers: {}, locals: { courseId: options.courseId || COURSE },
      status(code) { this.statusCode = code; return this; },
      set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
      setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
      getHeader(name) { return this.headers[name.toLowerCase()]; },
      json(body) { resolve({ status: this.statusCode, body: clone(body), headers: this.headers }); return this; },
      end() { resolve({ status: this.statusCode, body: null, headers: this.headers }); return this; },
    };
    router(req, res, error => error ? reject(error) : resolve({ status: 404, body: null, headers: res.headers }));
  });
}
const getStatus = options => request(courseRouter, 'GET', '/caldera-agents/status', options);
const install = (body = {}, options = {}) => request(courseRouter, 'POST', '/caldera-agents', {
  ...options, body: { lane_id: LANE, vm_id: 101, platform: 'windows', ...body },
});
const authorize = uri => request(callbackRouter, 'GET', '/authorize', { user: null, headers: { 'X-Forwarded-Uri': uri } });
beforeEach(reset);

test('course staff and admins read only scoped lanes and projected agents, with no callback credentials', async () => {
  for (const user of [{ role: 'instructor', userId: 'owner' }, { role: 'admin', userId: 'admin' }]) {
    const response = await getStatus({ user });
    assert.equal(response.status, 200);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.body.server_url, 'https://agents.test.example');
    assert.equal(response.body.lanes.length, 1);
    const lane = response.body.lanes[0];
    assert.equal(lane.lane_id, LANE);
    assert.equal(lane.group, groupFor(LANE));
    assert.deepEqual(lane.targets.map(vm => vm.vm_id), [101]);
    assert.deepEqual(lane.agents.map(agent => agent.paw), ['agent-one']);
    const wire = JSON.stringify(response.body);
    for (const secret of [TOKEN, hashToken(TOKEN), API_KEY, 'private-lane-config', 'OTHER-DC', 'executors']) {
      assert.ok(!wire.includes(secret), secret + ' leaked in status');
    }
  }
  assert.deepEqual(state.scopeCalls, [{ scopeType: 'course', scopeId: COURSE }, { scopeType: 'course', scopeId: COURSE }]);
});

test('students and instructors enrolled as students are refused before any Caldera call', async () => {
  for (const user of [{ role: 'student', userId: 'student' }, { role: 'instructor', userId: 'enrolled-instructor' }]) {
    assert.equal((await getStatus({ user })).status, 403);
    assert.equal((await install({}, { user })).status, 403);
  }
  assert.equal(state.agentReads, 0);
  assert.equal(state.scopeCalls.length, 0);
  assert.equal(state.tasks.length, 0);
});

test('unrelated courses and unknown courses give outsiders the same 404', async () => {
  const foreign = await getStatus({ courseId: OTHER_COURSE });
  const missing = await getStatus({ courseId: '55555555-5555-5555-5555-555555555555' });
  assert.equal(foreign.status, 404);
  assert.deepEqual(foreign.body, missing.body);
  assert.equal((await install({}, { courseId: OTHER_COURSE })).status, 404);
  assert.equal((await getStatus({ user: null })).status, 404);
  assert.equal(state.scopeCalls.length, 0);
  assert.equal(state.tasks.length, 0);
});

test('disabling the Blue Team feature blocks installation while staff can still read status', async () => {
  state.course.features.blue_team = false;
  assert.equal((await getStatus()).status, 200);
  const response = await install();
  assert.equal(response.status, 404);
  assert.match(response.body.error, /not enabled/);
  assert.equal(state.tasks.length, 0);
  assert.equal(state.audits.length, 0);
});

test('foreign and missing lane ids are indistinguishable and never reach installation', async () => {
  const foreign = await install({ lane_id: OTHER_LANE });
  const missing = await install({ lane_id: '55555555-5555-5555-5555-555555555555' });
  assert.equal(foreign.status, 404);
  assert.deepEqual(foreign.body, missing.body);
  assert.equal(state.agentReads, 0);
  assert.equal(state.queries.length, 0);
});

test('VM membership and platform validation survive the HTTP route and refuse gateway and arbitrary VMs', async () => {
  for (const vm_id of [100, 201, 999999]) assert.equal((await install({ vm_id })).status, 404);
  for (const body of [{ vm_id: '101' }, { platform: 'darwin' }, { vm_id: 101.5 }]) {
    assert.equal((await install(body)).status, 400);
  }
  assert.equal(state.agentReads, 0);
  assert.equal(state.tasks.length, 0);
});

test('explicitly disabled lane Internet blocks installation; a missing Internet flag remains unknown', async () => {
  state.lanes[0].config.internet_enabled = false;
  const refused = await install();
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /internet access is disabled/i);
  assert.equal(state.tasks.length, 0);
  assert.equal(state.agentReads, 0);
  delete state.lanes[0].config.internet_enabled;
  const status = await getStatus();
  assert.equal(status.body.lanes[0].internet_enabled, null);
  assert.equal((await install()).status, 202);
});

test('installation returns 202 with a public job, ignores caller destinations, and duplicates return 409', async () => {
  const first = await install({ server_url: 'https://arbitrary.example/', group: 'foreign-group', api_key: 'caller-key' });
  assert.equal(first.status, 202);
  assert.deepEqual(Object.keys(first.body), ['job']);
  assert.equal(first.body.job.status, 'running');
  assert.equal(first.body.job.vm_id, 101);
  assert.equal(first.body.job.group, groupFor(LANE));
  assert.equal(state.tasks.length, 1);
  assert.equal(state.audits.length, 1);
  assert.deepEqual(state.audits[0].metadata, { course_id: COURSE, vm_id: 101, job_id: first.body.job.job_id });
  const savedToken = state.lanes[0].config.caldera_agent_access.tokens[0].token_hash;
  const status = await getStatus();
  const wire = JSON.stringify([first.body, status.body, state.audits[0].metadata]);
  for (const secret of [savedToken, API_KEY, 'caller-key', 'arbitrary.example', 'token_hash', 'caldera_agent_access']) {
    assert.ok(!wire.includes(secret), secret + ' leaked in response');
  }
  const duplicate = await install();
  assert.equal(duplicate.status, 409);
  assert.match(duplicate.body.error, /already running/);
  assert.equal(state.tasks.length, 1);
  assert.equal(state.audits.length, 1);
});

test('agent status wins Express matching before the incident run status route', async () => {
  const response = await getStatus();
  assert.equal(response.status, 200);
  assert.ok(Array.isArray(response.body.lanes));
  assert.equal(state.runReads, 0);
  const paths = courseRouter.stack.filter(layer => layer.route).map(layer => layer.route.path);
  assert.ok(paths.indexOf('/caldera-agents/status') < paths.indexOf('/:runId/status'));
});

test('callback authorization accepts only a known token on the three agent routes and never console paths', async () => {
  for (const suffix of ['beacon', 'file/download', 'file/upload']) {
    const response = await authorize(`/agent/${TOKEN}/${suffix}`);
    assert.equal(response.status, 204);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['x-caldera-paw'], pawFor(LANE, 101));
    assert.equal(response.headers['x-caldera-group'], groupFor(LANE));
    assert.equal(response.body, null);
  }
  for (const uri of [undefined, '/login', `/agent/${TOKEN}/`, `/agent/${TOKEN}/api/v2/agents`,
    `/agent/${TOKEN}/beacon?next=/login`, `/agent/${'b'.repeat(64)}/beacon`]) {
    const response = await authorize(uri);
    assert.equal(response.status, 403, String(uri));
    assert.equal(response.body, null);
    assert.equal(response.headers['x-caldera-paw'], undefined);
    assert.equal(response.headers['x-caldera-group'], undefined);
  }
});

test('a stored callback token stops authorizing when its VM leaves the lane', async () => {
  assert.equal((await authorize(`/agent/${TOKEN}/beacon`)).status, 204);
  state.lanes[0].config.vms = state.lanes[0].config.vms.filter(vm => vm.vm_id !== 101);
  const response = await authorize(`/agent/${TOKEN}/beacon`);
  assert.equal(response.status, 403);
  assert.equal(response.headers['x-caldera-paw'], undefined);
  assert.equal(response.headers['x-caldera-group'], undefined);
});

test('callback authorization refuses inactive lanes and fails closed on database errors', async () => {
  state.lanes[0].status = 'deleted';
  assert.equal((await authorize(`/agent/${TOKEN}/beacon`)).status, 403);
  state.dbError = true;
  const response = await authorize(`/agent/${TOKEN}/beacon`);
  assert.equal(response.status, 503);
  assert.equal(response.body, null);
  assert.equal(response.headers['cache-control'], 'no-store');
});
