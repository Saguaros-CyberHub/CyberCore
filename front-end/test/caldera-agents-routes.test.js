'use strict';

// Real Express handlers and lane-agent service; fake DB/Caldera and queued
// execution. No live VM, authentication service or remote server is contacted.
const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CLE = path.join(ROOT, 'modules/crucible/plugins/cle');
const { createService, hashToken, groupFor, pawFor } = require('../src/utils/caldera-lane-agents');
// Required BEFORE the require.cache overrides at the bottom of this preamble.
// This module destructures caldera-lane-agents at load time, so resolving it
// after that module has been replaced by the `{ createService }` stub would
// leave targetsFor, laneContext and enrichTargets undefined.
const operationsModule = require('../src/utils/caldera-lane-operations');
const COURSE = '11111111-1111-1111-1111-111111111111';
const OTHER_COURSE = '22222222-2222-2222-2222-222222222222';
const LANE = '33333333-3333-3333-3333-333333333333';
const OTHER_LANE = '44444444-4444-4444-4444-444444444444';
const GOAD_LANE = '66666666-6666-6666-6666-666666666666';
const TOKEN = 'a'.repeat(64);
const API_KEY = 'private-red-api-key';
const state = {};
const clone = value => JSON.parse(JSON.stringify(value));

// The GOAD lab roster is INJECTED, never required: goad-deploy pulls the script
// executor and the database pool at load time, so a route test that let the
// environment directory reach the real module would open a connection pool for
// the sake of two machine labels.
const goadLab = {
  resolveGoadLab: () => ({
    labName: 'GOAD-Light',
    labDef: { displayName: 'GOAD Light', vms: [
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019' },
      { name: 'ws01', role: 'workstation', os: 'Windows 11' },
    ] },
    extensions: { external: ['elk'] },
  }),
  getExtension: name => name === 'elk' ? { machine: 'elk', role: 'siem', os: 'Ubuntu 22.04' } : null,
};
// One authored spec, registered under a different key per test. The environment
// directory memoises for a minute against the injected clock, which never moves,
// so two tests sharing a key would make the second one's read count depend on
// the order the runner happened to pick.
const GOAD_SPEC = { name: 'GOAD Active Directory', spec: { goad: { enabled: true, lab: 'GOAD-Light' } } };
const SPECS = { 'goad-agents': GOAD_SPEC, 'goad-operations': GOAD_SPEC, 'goad-leak': GOAD_SPEC };

// A lane carrying everything the runner's JOIN adds (vxlan_id, created_at and
// the student's name) beside a config that names a challenge, plus two config
// fields that must never reach the wire.
function goadLane(challengeKey, config = {}) {
  return { lane_id: GOAD_LANE, name: 'cle-cybr400-inperson-10882', status: 'active',
    vxlan_id: 10882, created_at: '2026-09-01T00:00:00.000Z',
    first_name: 'Ada', last_name: 'Lovelace', student_email: 'ada@example.test',
    config: { course_id: COURSE, internet_enabled: true, challenge_key: challengeKey,
      goad: { lab: 'GOAD-Light' },
      user_email: 'owner-private@example.test', lane_password: 'private-lane-password',
      vms: [{ vm_id: 901, name: 'DC01', type: 'qemu', node: 'node-one' },
        { vm_id: 902, name: 'elk', type: 'qemu', node: 'node-one' }],
      ...config } };
}

// Registers the GOAD lane in the course and gives its two guests live power.
function addGoadLane(challengeKey, config) {
  state.lanes.push(goadLane(challengeKey, config));
  state.resources.push({ vmid: 901, type: 'qemu', status: 'running', node: 'node-one' },
    { vmid: 902, type: 'qemu', status: 'running', node: 'node-one' });
}

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
  // Every challenge-spec lookup the environment directory issued, table and all.
  // A lane that names no challenge must add nothing here.
  state.specReads = [];
  state.tasks = [];
  state.audits = [];
  state.agentReads = 0;
  state.operationCalls = [];
  state.runReads = 0;
  state.dbError = false;
  state.powerError = false;
  state.resources = [101, 201].map(vmid => ({ vmid, type: 'qemu', status: 'running', node: 'node-one' }));
}
reset();

// Model the lane lifecycle predicate independently from the service. Live power
// is checked separately by the real service against the Proxmox fake below.
function eligibleLane(lane) {
  return lane.status === 'active' || (lane.status === 'suspended'
    && ((typeof lane.config.error === 'string' && lane.config.error.trim().length > 0)
      || (typeof lane.config.provisioning_error === 'string' && lane.config.provisioning_error.trim().length > 0)
      || lane.config.goad?.status === 'failed'));
}

// Shared by both classroom services, so one Proxmox outage and one recorded
// statement log cover the install dialog and the attack dialog alike.
async function fakeProxmox(method, endpoint) {
  assert.equal(method, 'GET');
  assert.equal(endpoint, '/api2/json/cluster/resources?type=vm');
  if (state.powerError) throw new Error('private Proxmox failure');
  return clone(state.resources);
}

async function fakeQuery(sql, params) {
  state.queries.push({ sql, params });
  if (state.dbError) throw new Error('private database failure');
  // The environment directory's two-rung table ladder. Recorded separately so
  // a test can prove a lane without a challenge_key never reaches it: the
  // directory swallows its own failures, so an unwanted lookup would otherwise
  // be invisible.
  const spec = /SELECT name, spec FROM (\w+) WHERE challenge_key = \$1/.exec(sql);
  if (spec) {
    state.specReads.push({ table: spec[1], key: params[0] });
    return { rows: SPECS[params[0]] ? [clone(SPECS[params[0]])] : [] };
  }
  if (/UPDATE cybercore_lane/.test(sql) && /RETURNING lane_id/.test(sql)) {
    const lane = state.lanes.find(row => row.lane_id === params[0] && eligibleLane(row));
    const prior = lane?.config.caldera_agent_jobs?.[params[2]] || lane?.config.caldera_agent_job;
    if (!lane || (String(prior?.vm_id) === params[2] && ['queued', 'running'].includes(prior?.status))) return { rows: [] };
    lane.config.caldera_agent_job = JSON.parse(params[1]);
    lane.config.caldera_agent_jobs ||= {};
    lane.config.caldera_agent_jobs[params[2]] = lane.config.caldera_agent_job;
    const token = JSON.parse(params[3]);
    lane.config.caldera_agent_access = { tokens: (lane.config.caldera_agent_access?.tokens || []).filter(row => row.vm_id !== token.vm_id).concat(token) };
    return { rows: [{ lane_id: lane.lane_id }] };
  }
  if (/SELECT l\.lane_id/.test(sql)) {
    const wanted = params[0];
    const lane = state.lanes.find(row => eligibleLane(row)
      && row.config.caldera_agent_access?.tokens.some(token => token.token_hash === wanted));
    const token = lane?.config.caldera_agent_access.tokens.find(item => item.token_hash === wanted);
    return { rows: lane ? [{ lane_id: lane.lane_id, status: lane.status, config: clone(lane.config), paw: token.paw, vm_id: String(token.vm_id) }] : [] };
  }
  throw new Error('Unexpected database query in route test');
}

const service = createService({
  now: () => Date.parse('2026-09-05T01:00:00Z'),
  settings: () => ({ serverUrl: 'https://agents.test.example', consoleUrl: 'https://console.test.example/', apiKey: API_KEY,
    client: { listAgents: async () => { state.agentReads++; return clone(state.agents); } },
  }),
  schedule: task => state.tasks.push(task),
  goad: goadLab,
  proxmox: fakeProxmox,
  query: fakeQuery,
});

// The REAL operations service, so the attack dialog's payload is asserted as the
// route actually emits it rather than as a hand-written stub imagines it. Its
// Caldera read deliberately does NOT touch state.agentReads: that counter is the
// install dialog's evidence that a refused request reached no remote service, and
// sharing it would make those assertions depend on the attack dialog's traffic.
const operations = operationsModule.createService({
  now: () => Date.parse('2026-09-05T01:00:00Z'),
  goad: goadLab,
  proxmox: fakeProxmox,
  query: fakeQuery,
  client: () => ({
    listAgents: async () => clone(state.agents),
    listAdversaries: async () => [{ adversary_id: 'discovery', name: 'Discovery', description: 'Look around.', atomic_ordering: ['one'] }],
    listOperations: async () => [],
  }),
});

function put(relative, exports) {
  const filename = require.resolve(path.join(ROOT, relative));
  require.cache[filename] = { id: filename, filename, loaded: true, exports, children: [], paths: [] };
}
put('src/utils/caldera-lane-agents', { createService: () => service });
put('src/utils/audit', { log: async item => { state.audits.push(item); } });
put('src/incident/runner', { findScopeLanes: async (scope, options = {}) => {
  state.scopeCalls.push({ scope, options });
  return clone(state.lanes.filter(lane => lane.config.course_id === scope.scopeId
    && (lane.status === 'active' || (options.includeSuspended === true && lane.status === 'suspended'))));
} });
put('src/incident/board', {
  readRunForStaff: async () => { state.runReads++; return null; },
  readRunForStudent: async () => { state.runReads++; return null; },
});
put('src/incident/caldera/authoring', {});
put('src/routes/caldera-authoring', { authoringConfig: () => ({}), PUBLIC_PATH: '/caldera' });
// status() delegates to the real service; launch and stop stay fakes because
// those tests are about which lanes the route resolves and hands over, not about
// dispatching an operation to Caldera.
put('src/utils/caldera-lane-operations', { createService: () => ({
  status: async (lanes, context) => {
    state.operationCalls.push({ action: 'status', lanes, context });
    return operations.status(lanes, context);
  },
  ...Object.fromEntries(['launch', 'stop'].map(action => [action, async (lanes, body, context) => {
    if (!Array.isArray(body.lane_ids) || body.lane_ids.some(id => !lanes.some(lane => lane.lane_id === id))) {
      throw Object.assign(new Error('Lane not found'), { status: 404 });
    }
    state.operationCalls.push({ action, lanes, body, context });
    return { batch_id: body.request_id || body.batch_id, results: body.lane_ids.map(lane_id => ({ lane_id, status: 'preparing' })) };
  }])),
}) });
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

test('classroom bulk endpoints enforce staff access before calling services', async () => {
  for (const user of [{ role: 'student', userId: 'student' }, { role: 'instructor', userId: 'enrolled-instructor' }]) {
    for (const [method, url] of [['POST', '/caldera-agents/batch'], ['POST', '/caldera-operations'], ['POST', '/caldera-operations/stop'], ['GET', '/caldera-operations/status']]) {
      assert.equal((await request(courseRouter, method, url, { user })).status, 403);
    }
  }
  assert.equal(state.operationCalls.length, 0);
  assert.equal(state.agentReads, 0);
});

test('bulk installer refuses any foreign target before claiming the valid sibling', async () => {
  const response = await request(courseRouter, 'POST', '/caldera-agents/batch', { body: { targets: [
    { lane_id: LANE, vm_id: 101, platform: 'windows' }, { lane_id: OTHER_LANE, vm_id: 201, platform: 'linux' },
  ] } });
  assert.equal(response.status, 404);
  assert.equal(state.tasks.length, 0);
  assert.equal(state.agentReads, 0);
});

test('bulk installer queues course targets and reports duplicate active VM failures', async () => {
  const body = { targets: [{ lane_id: LANE, vm_id: 101, platform: 'windows' }] };
  const response = await request(courseRouter, 'POST', '/caldera-agents/batch', { body });
  assert.equal(response.status, 202);
  assert.equal(response.body.results[0].job.status, 'queued');
  const repeated = await request(courseRouter, 'POST', '/caldera-agents/batch', { body });
  assert.equal(repeated.body.results[0].status, 409);
  assert.equal(state.tasks.length, 1);
});

test('operation routes pass only resolved course lanes and preserve stop after disabling feature', async () => {
  const body = { lane_ids: [LANE], request_id: COURSE, adversary_id: 'discovery', batch_id: COURSE };
  assert.equal((await request(courseRouter, 'POST', '/caldera-operations', { body })).status, 202);
  assert.equal(state.operationCalls[0].context.courseId, COURSE);
  assert.deepEqual(state.operationCalls[0].lanes.map(lane => lane.lane_id), [LANE]);
  assert.equal((await request(courseRouter, 'POST', '/caldera-operations', { body: { ...body, lane_ids: [OTHER_LANE] } })).status, 404);
  state.course.features.blue_team = false;
  assert.equal((await request(courseRouter, 'POST', '/caldera-operations', { body })).status, 404);
  assert.equal((await request(courseRouter, 'POST', '/caldera-agents/batch', { body: { targets: [] } })).status, 404);
  assert.equal((await request(courseRouter, 'POST', '/caldera-operations/stop', { body })).status, 200);
  const status = await request(courseRouter, 'GET', '/caldera-operations/status');
  assert.equal(status.status, 200);
  assert.equal(status.headers['cache-control'], 'no-store');
  assert.equal(state.operationCalls.at(-1).action, 'status');
  assert.equal(state.runReads, 0);
});

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
  assert.deepEqual(state.scopeCalls, [1, 2].map(() => ({
    scope: { scopeType: 'course', scopeId: COURSE }, options: { includeSuspended: true },
  })));
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

test('a retained deployment failure is discovered only in its course and can install on its running guest', async () => {
  state.lanes[0].status = 'suspended';
  state.lanes[0].config.error = 'private deployment failure details';
  state.lanes[1].status = 'suspended';
  state.lanes[1].config.error = 'foreign deployment failure';
  const status = await getStatus();
  assert.equal(status.status, 200);
  assert.deepEqual(status.body.lanes.map(lane => lane.lane_id), [LANE]);
  assert.equal(status.body.lanes[0].lane_status, 'suspended');
  assert.equal(status.body.lanes[0].lifecycle_eligible, true);
  assert.equal(status.body.lanes[0].retained_after_failure, true);
  assert.equal(status.body.lanes[0].runnable, true);
  assert.equal(status.body.lanes[0].targets[0].runnable, true);
  assert.doesNotMatch(JSON.stringify(status.body), /private deployment failure details|foreign deployment failure/);
  const response = await install();
  assert.equal(response.status, 202);
  assert.equal(state.tasks.length, 1);
  assert.equal(state.lanes[0].status, 'suspended', 'agent installation must not rewrite deployment readiness');
  assert.equal((await install({ lane_id: OTHER_LANE })).status, 404);
});

test('ordinary suspension stays blocked even if the guest happens to be running', async () => {
  state.lanes[0].status = 'suspended';
  const lane = (await getStatus()).body.lanes[0];
  assert.equal(lane.lane_status, 'suspended');
  assert.equal(lane.lifecycle_eligible, false);
  assert.equal(lane.retained_after_failure, false);
  assert.equal(lane.runnable, false);
  assert.equal(lane.targets[0].runnable, false);
  assert.equal((await install()).status, 409);
  assert.equal((await authorize(`/agent/${TOKEN}/beacon`)).status, 403);
  assert.equal(state.tasks.length, 0);
});

for (const [reason, mutate] of [
  ['stopped', () => { state.resources[0].status = 'stopped'; }],
  ['missing', () => { state.resources = state.resources.filter(vm => vm.vmid !== 101); }],
  ['unknown power', () => { state.powerError = true; }],
]) {
  test(`retained deployment failures cannot install or authenticate with ${reason} guest power`, async () => {
    state.lanes[0].status = 'suspended';
    state.lanes[0].config.provisioning_error = 'retained deployment failure';
    mutate();
    const status = await getStatus();
    assert.equal(status.status, 200);
    assert.equal(status.body.lanes[0].runnable, false);
    assert.equal(status.body.lanes[0].targets[0].runnable, false);
    const response = await install();
    assert.ok(response.status >= 400);
    assert.doesNotMatch(JSON.stringify([status.body, response.body]), /private Proxmox failure/);
    assert.equal(state.tasks.length, 0);
    assert.ok((await authorize(`/agent/${TOKEN}/beacon`)).status >= 400);
  });
}

test('a retained GOAD failure permits its known callback token only while the guest is running', async () => {
  state.lanes[0].status = 'suspended';
  state.lanes[0].config.goad = { status: 'failed' };
  assert.equal((await authorize(`/agent/${TOKEN}/beacon`)).status, 204);
  state.resources[0].status = 'stopped';
  assert.equal((await authorize(`/agent/${TOKEN}/beacon`)).status, 403);
  assert.equal(state.lanes[0].status, 'suspended');
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
  assert.equal(first.body.job.status, 'queued');
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

test('the install dialog names each lane, its student and its machines from the challenge spec', async () => {
  addGoadLane('goad-agents');
  const response = await getStatus();
  assert.equal(response.status, 200);
  const lane = response.body.lanes.find(row => row.lane_id === GOAD_LANE);
  assert.equal(lane.vxlan_id, 10882);
  assert.equal(lane.lane_number, 10882);
  assert.equal(lane.family, 'cle-cybr400-inperson');
  assert.equal(lane.kind, 'goad');
  assert.equal(lane.created_at, '2026-09-01T00:00:00.000Z');
  assert.deepEqual(lane.student, { name: 'Ada Lovelace', email: 'ada@example.test' });
  assert.deepEqual(lane.environment, { key: 'goad-agents', label: 'GOAD Active Directory', type: 'goad', lab: 'GOAD Light' });
  // The deployer writes {vm_id, name, proxmox_name, type, node} with no OS, so
  // every one of these answers comes from the spec join the route now performs.
  const [dc, elk] = lane.targets;
  assert.deepEqual([dc.platform, dc.role, dc.os, dc.infra, dc.machine_key],
    ['windows', 'dc', 'Windows Server 2019', false, 'goad-agents::dc01']);
  assert.deepEqual([elk.platform, elk.role, elk.os, elk.infra, elk.machine_key],
    ['linux', 'siem', 'Ubuntu 22.04', true, 'goad-agents::elk']);
  // The install dialog is the endpoint that carries per-machine job history; the
  // key is present and null here, which is what makes its ABSENCE on the attack
  // endpoint below a real assertion rather than a missing-property tautology.
  assert.ok('last_job' in dc);
  assert.equal(dc.last_job, null);
  assert.deepEqual(state.specReads, [{ table: 'crucible_challenge', key: 'goad-agents' }],
    'one spec read for the whole course, not one per lane');
});

test('a lane that names no challenge reads no challenge spec at all', async () => {
  const response = await getStatus();
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.lanes.map(row => row.lane_id), [LANE]);
  const lane = response.body.lanes[0];
  assert.equal(lane.student, null, 'an admin-scoped row without the runner JOIN has no student');
  assert.deepEqual(lane.environment, { key: 'lane', label: null, type: 'challenge', lab: null });
  assert.equal(lane.targets[0].machine_key, 'lane::windows-11');
  // Workstation lanes carry the course's reserved-network challenge_key, so a
  // directory keyed on "has a challenge_key" would fire this lookup 44 times per
  // poll for a spec that describes none of those machines. The query fake
  // records every statement before rejecting an unrecognised one, so a lookup
  // fired here would be visible even though the directory swallows its failures.
  assert.deepEqual(state.specReads, []);
  assert.deepEqual(state.queries, []);
});

test('the attack dialog receives lane lifecycle, internet and enriched machine rows', async () => {
  state.agents[0].paw = pawFor(LANE, 101);
  addGoadLane('goad-operations', { internet_enabled: false });
  const response = await request(courseRouter, 'GET', '/caldera-operations/status');
  assert.equal(response.status, 200);
  assert.equal(state.operationCalls.at(-1).action, 'status');
  const own = response.body.lanes.find(row => row.lane_id === LANE);
  assert.equal(own.lane_status, 'active');
  assert.equal(own.lifecycle_eligible, true);
  assert.equal(own.retained_after_failure, false);
  assert.equal(own.internet_enabled, true);
  assert.equal(own.runnable, true);
  assert.deepEqual(own.targets.map(vm => [vm.vm_id, vm.power_state, vm.runnable]), [[101, 'running', true]]);
  assert.deepEqual(own.agents.map(agent => [agent.vm_id, agent.machine_key]), [[101, 'lane::windows-11']]);
  const goad = response.body.lanes.find(row => row.lane_id === GOAD_LANE);
  // The three causes stay separate. Folding them into `runnable` is what made
  // every agent-less lane report "lane not running" and made "internet off"
  // unreachable in the dialog.
  assert.equal(goad.lifecycle_eligible, true);
  assert.equal(goad.internet_enabled, false);
  assert.equal(goad.runnable, false);
  assert.deepEqual(goad.student, { name: 'Ada Lovelace', email: 'ada@example.test' });
  assert.deepEqual(goad.environment, { key: 'goad-operations', label: 'GOAD Active Directory', type: 'goad', lab: 'GOAD Light' });
  assert.deepEqual(goad.targets.map(vm => [vm.machine_key, vm.platform, vm.power_state]),
    [['goad-operations::dc01', 'windows', 'running'], ['goad-operations::elk', 'linux', 'running']]);
  assert.ok(!('last_job' in goad.targets[0]), 'the attack dialog never asks for install job history');
  assert.deepEqual(state.specReads, [{ table: 'crucible_challenge', key: 'goad-operations' }]);
});

test('neither classroom status route emits a lane config field that was never enumerated', async () => {
  addGoadLane('goad-leak');
  const agents = await getStatus();
  const attack = await request(courseRouter, 'GET', '/caldera-operations/status');
  assert.equal(agents.status, 200);
  assert.equal(attack.status, 200);
  const wire = JSON.stringify([agents.body, attack.body]);
  // Lane config carries the owner's email next to the lane password and has
  // historically carried guest credentials, and both of these payloads are
  // polled into an instructor's browser every five seconds.
  assert.doesNotMatch(wire, /owner-private@example|private-lane-password|private-lane-config|private-red-api-key/);
  assert.doesNotMatch(wire, /user_email|lane_password|caldera_agent_access|token_hash|unrelated_secret|executors/);
  // The student's own address is the one identity this payload may carry, and it
  // comes from the runner's cybercore_user JOIN rather than from config.
  assert.ok(wire.includes('ada@example.test'));
});

test('agent status wins Express matching before the incident run status route', async () => {
  const response = await getStatus();
  assert.equal(response.status, 200);
  assert.ok(Array.isArray(response.body.lanes));
  assert.equal(state.runReads, 0);
  const paths = courseRouter.stack.filter(layer => layer.route).map(layer => layer.route.path);
  assert.ok(paths.indexOf('/caldera-agents/status') < paths.indexOf('/:runId/status'));
  // Every classroom route is a literal path registered ahead of the run-id
  // wildcard. One of them landing after '/:runId' would be answered by the board
  // handler with 'caldera-operations' as a run id.
  for (const literal of ['/caldera-agents/status', '/caldera-agents', '/caldera-agents/batch',
    '/caldera-operations/status', '/caldera-operations', '/caldera-operations/stop']) {
    assert.ok(paths.includes(literal), `${literal} is not registered`);
    assert.ok(paths.indexOf(literal) < paths.indexOf('/:runId'), `${literal} must precede /:runId`);
  }
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
