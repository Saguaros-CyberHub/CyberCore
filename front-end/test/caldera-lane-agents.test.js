'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createService, targetsFor, hashToken, pawFor, groupFor, seenAt, JOB_TIMEOUT_MS } = require('../src/utils/caldera-lane-agents');

const LANE_ID = '11111111-2222-4333-8444-555555555555';
const COURSE_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const START = Date.parse('2026-09-05T20:00:00.000Z');
const clone = value => structuredClone(value);
const laneFixture = () => ({ lane_id: LANE_ID, name: 'Lab lane', status: 'active', config: {
  course_id: COURSE_ID, internet_enabled: true, node: 'outdated-node', gateway_vm_id: 900,
  password: 'lane-password-private', vms: [{ vm_id: 901, name: 'Windows workstation', os: 'windows' }],
} });

// Model the database lifecycle gate independently from the production helper.
const eligibleFixture = lane => !!lane && (lane.status === 'active' || (lane.status === 'suspended'
  && [lane.config.error, lane.config.provisioning_error, lane.config.goad?.status === 'failed' ? 'failed' : '']
    .some(value => typeof value === 'string' && value.trim().length > 0)));

function assertLifecycleSql(sql, alias = '') {
  const prefix = alias ? `${alias}.` : '';
  assert.ok(sql.includes(`(${prefix}status = 'active' OR (${prefix}status = 'suspended' AND (`));
  for (const key of ['error', 'provisioning_error']) {
    assert.ok(sql.includes(`jsonb_typeof(${prefix}config->'${key}') = 'string' AND BTRIM(${prefix}config->>'${key}') <> ''`));
  }
  assert.ok(sql.includes(`${prefix}config->'goad'->>'status' = 'failed')))`));
}

// The fake models the atomic UPDATE and conditional save, including rejection of
// an occupied lane. Assertions on its SQL conditions keep the fake honest about
// the concurrency and scope guarantees production PostgreSQL must enforce.
function harness(options = {}) {
  const state = { lane: laneFixture(), clock: START, scheduled: [], sql: [], calls: [],
    agentReads: 0, sleepCalls: [], script: null, token: null,
    resources: [{ vmid: 901, node: 'actual-node', type: 'qemu', status: 'running' }] };
  Object.assign(state, options.state);
  const query = async (sql, args) => {
    state.sql.push({ sql, args: clone(args) });
    if (state.dbFailure) throw new Error('database unavailable');
    if (sql.includes('RETURNING lane_id')) {
      assert.match(sql, /WHERE lane_id = \$1 AND /);
      assertLifecycleSql(sql);
      assert.match(sql, /course_id' IS NOT DISTINCT FROM \$6::text/);
      assert.match(sql, /started_at' < \$5/);
      assert.match(sql, /status', ''\) <> 'running'/);
      const [laneId, jobJson, vmId, accessJson, cutoff, courseId] = args;
      const lane = state.lane;
      const prior = lane?.config.caldera_agent_job;
      if (!eligibleFixture(lane) || lane.lane_id !== laneId
        || (lane.config.course_id || null) !== courseId
        || (prior?.status === 'running' && !(prior.started_at < cutoff))) return { rows: [] };
      const tokens = lane.config.caldera_agent_access?.tokens || [];
      lane.config.caldera_agent_access = { tokens: tokens.filter(t => String(t.vm_id) !== vmId).concat(JSON.parse(accessJson)) };
      lane.config.caldera_agent_job = JSON.parse(jobJson);
      return { rows: [{ lane_id: laneId }] };
    }
    if (sql.startsWith('UPDATE')) {
      assert.match(sql, /job_id' = \$3/);
      if (state.lane?.lane_id === args[0] && state.lane.config.caldera_agent_job?.job_id === args[2]) {
        state.lane.config.caldera_agent_job = JSON.parse(args[1]);
      }
      return { rows: [] };
    }
    if (sql.includes('token_hash')) {
      assertLifecycleSql(sql, 'l');
      assert.match(sql, /SELECT l.lane_id, l.status, l.config/);
      assert.match(sql, /t->>'token_hash' = \$1/);
      assert.match(args[0], /^[a-f0-9]{64}$/);
      const access = eligibleFixture(state.lane)
        && state.lane.config.caldera_agent_access?.tokens.find(token => token.token_hash === args[0]);
      return { rows: access ? [{ lane_id: state.lane.lane_id, status: state.lane.status, config: clone(state.lane.config),
        paw: access.paw, vm_id: String(access.vm_id) }] : [] };
    }
    assert.match(sql, /^SELECT lane_id, status, config FROM cybercore_lane WHERE lane_id = \$1$/);
    return { rows: state.lane?.lane_id === args[0] ? [clone(state.lane)] : [] };
  };
  const freshAgent = () => ({ paw: pawFor(LANE_ID, 901), group: groupFor(LANE_ID), platform: 'windows',
    last_seen: new Date(state.clock).toISOString().replace('T', ' ').replace('Z', ''),
    host: 'LAB-WKS', trusted: true, server: 'private-server', contact: 'private-contact',
    pending_contact: 'private-pending', executors: ['private-executor'], ...state.agentOverride });
  const client = { listAgents: async () => {
    state.agentReads++;
    if (state.calderaFailure) throw new Error('private-api-key=do-not-publish');
    if (options.agents) return options.agents(state, freshAgent);
    return [freshAgent()];
  } };
  function captureScript(script) {
    state.script = script;
    state.token = /\/agent\/([a-f0-9]{64})/.exec(script)?.[1];
    assert.ok(state.token, 'executor must receive the scoped ingress credential');
    return { pid: 4321 };
  }
  const executor = {
    waitForGuestAgent: async (...args) => { state.calls.push(['guest', ...args]); return state.guestAvailable !== false; },
    agentExecArgv: async (node, vmId, argv) => {
      state.calls.push(['windows', node, vmId, argv]);
      assert.deepEqual(argv.slice(0, -1), ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
      return captureScript(Buffer.from(argv.at(-1), 'base64').toString('utf16le'));
    },
    proxmoxFormPOST: async (endpoint, pairs) => {
      state.calls.push(['linux', endpoint, pairs]);
      assert.equal(endpoint, '/api2/json/nodes/actual-node/qemu/901/agent/exec');
      assert.deepEqual(pairs.slice(0, 2), [['command', '/bin/sh'], ['command', '-c']]);
      assert.equal(pairs[2][0], 'command');
      return captureScript(pairs[2][1]);
    },
    pollExecStatus: async (...args) => {
      state.calls.push(['poll', ...args]);
      if (options.result) return options.result(state);
      return { exited: true, exitcode: 0, stdout: `CYBERCORE_CALDERA_STARTED:${pawFor(LANE_ID, 901)}`, stderr: '' };
    },
  };
  const service = createService({ query, executor,
    settings: () => ({ serverUrl: 'https://caldera.saguaroscyberhub.org', consoleUrl: 'https://caldera.saguaroscyberhub.org/', client }),
    now: () => state.clock,
    sleep: async ms => { state.sleepCalls.push(ms); state.clock += ms; },
    schedule: task => state.scheduled.push(task),
    proxmox: async (...args) => {
      state.calls.push(['proxmox', ...args]);
      if (state.proxmoxFailure) throw new Error('private-proxmox-credential');
      return state.resources;
    },
  });
  return { state, service, start: (input = { vm_id: 901, platform: 'windows' }) => service.start(clone(state.lane), input),
    run: async () => { while (state.scheduled.length) await state.scheduled.shift()(); },
    job: () => state.lane?.config.caldera_agent_job };
}

test('targets include lane guests, attached modules and attack box, excluding gateways, containers and duplicates', () => {
  const lane = laneFixture();
  lane.config.vms.push({ vm_id: 900, os: 'linux' }, { vm_id: 902, type: 'lxc' }, { vm_id: -1 });
  lane.config.workstations = [{ vmid: 903, name: 'Ubuntu workstation' }, { vm_id: 901 }];
  lane.config.attached_modules = [{ vms: [{ vm_id: 904, template_name: 'win2022' }, { vm_id: 905, name: 'Unknown OS' }] }];
  lane.config.attack_box_vm_id = 906;
  const targets = targetsFor(lane);
  assert.deepEqual(targets.map(t => [t.vm_id, t.platform]), [[901, 'windows'], [903, 'linux'], [904, 'windows'], [905, null], [906, 'linux']]);
  assert.equal(targets.every(t => t.type === 'qemu'), true);
  assert.doesNotMatch(JSON.stringify(targets), /lane-password-private/);
  assert.deepEqual(targetsFor({ config: JSON.stringify({ challenge_vm_id: 907, challenge_key: 'Challenge' }) }).map(t => t.vm_id), [907]);
});

test('invalid platform, VM outside the lane and inactive lane fail before any database claim or execution', async () => {
  const h = harness();
  for (const input of [{ vm_id: '901', platform: 'windows' }, { vm_id: 901, platform: 'darwin' },
    { vm_id: 999, platform: 'linux' }, { vm_id: 900, platform: 'linux' }]) {
    await assert.rejects(h.start(input), err => [400, 404].includes(err.status));
  }
  h.state.lane.status = 'stopped';
  await assert.rejects(h.start(), { status: 409 });
  assert.equal(h.state.agentReads, 0);
  assert.deepEqual(h.state.sql, []);
  assert.deepEqual(h.state.calls, []);
});

test('unavailable Caldera fails before token rotation or guest modification', async () => {
  const h = harness({ state: { calderaFailure: true } });
  await assert.rejects(h.start(), err => err.status === 503 && !err.message.includes('private-api-key'));
  assert.deepEqual(h.state.sql, []);
  assert.deepEqual(h.state.calls, []);
});

test('explicitly disabled lane internet fails before checking Caldera, claiming a job or modifying a guest', async () => {
  const h = harness();
  h.state.lane.config.internet_enabled = false;
  await assert.rejects(h.start(), err => err.status === 409 && /internet access is disabled/i.test(err.message));
  assert.equal(h.state.agentReads, 0);
  assert.deepEqual(h.state.sql, []);
  assert.deepEqual(h.state.calls, []);
  assert.equal(h.state.scheduled.length, 0);
});

test('an absent internet flag is reported as unknown and allows the installer to check actual connectivity', async () => {
  const h = harness();
  delete h.state.lane.config.internet_enabled;
  assert.equal((await h.service.status([h.state.lane])).lanes[0].internet_enabled, null);
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
});

for (const platform of ['windows', 'linux']) {
  test(`${platform} installer uses the live node and completes only on its fresh UTC check-in`, async () => {
    const h = harness({ state: { agentOverride: { platform } } });
    const queued = await h.start({ vm_id: 901, platform });
    assert.equal(queued.status, 'running');
    assert.deepEqual(h.state.calls, [['proxmox', 'GET', '/api2/json/cluster/resources?type=vm']]);
    await h.run();
    assert.equal(h.job().status, 'completed');
    assert.deepEqual(h.state.calls.find(c => c[0] === 'guest'), ['guest', 'actual-node', 901, 15000]);
    assert.deepEqual(h.state.calls.find(c => c[0] === 'poll'), ['poll', 'actual-node', 901, 4321, 120000]);
    assert.ok(h.state.calls.some(c => c[0] === platform));
    assert.equal(h.state.sleepCalls.length, 0);
    const [access] = h.state.lane.config.caldera_agent_access.tokens;
    assert.equal(access.token_hash, hashToken(h.state.token));
    assert.equal(access.paw, queued.paw);
    assert.equal(access.token, undefined);
    const status = await h.service.status([h.state.lane]);
    const exposed = JSON.stringify({ queued, status, sql: h.state.sql });
    assert.equal(exposed.includes(h.state.token), false);
    assert.doesNotMatch(exposed, /lane-password-private|private-server|private-contact|private-pending|private-executor/);
    assert.deepEqual(Object.keys(h.job().agent).sort(), ['group', 'host', 'last_seen', 'paw', 'platform', 'trusted']);
  });
}

test('timezone-free upstream last_seen timestamps are interpreted as UTC', () => {
  assert.equal(seenAt('2026-09-05 20:00:00.000'), START);
  assert.equal(seenAt('2026-09-05T20:00:00Z'), START);
  assert.equal(seenAt('2026-09-05T13:00:00-07:00'), START);
  assert.equal(Number.isNaN(seenAt('invalid')), true);
});

for (const [reason, agentOverride] of [
  ['stale', { last_seen: '2026-09-05 19:00:00' }],
  ['wrong group', { group: 'red' }],
  ['wrong paw', { paw: 'other-agent' }],
  ['wrong platform', { platform: 'linux' }],
  ['invalid timestamp', { last_seen: 'invalid' }],
]) {
  test(`${reason} check-in cannot complete the install`, async () => {
    const h = harness({ state: { agentOverride } });
    await h.start(); await h.run();
    assert.equal(h.job().status, 'failed');
    assert.match(h.job().error, /no fresh Caldera check-in/);
    assert.equal(h.state.sleepCalls.length, 12);
    assert.equal(h.state.agentReads, 13);
  });
}

test('a stale check-in is retried until a matching fresh check-in arrives', async () => {
  const h = harness({ agents: (state, fresh) => [{ ...fresh(), last_seen: state.agentReads < 3 ? '2026-09-05 19:00:00' : '2026-09-05 20:00:05' }] });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.deepEqual(h.state.sleepCalls, [5000]);
});

for (const [reason, result] of [
  ['nonzero exit', state => ({ exited: true, exitcode: 1, stdout: '', stderr: 'download failed: /agent/' + state.token })],
  ['timeout', () => ({ exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' })],
  ['missing startup marker', () => ({ exited: true, exitcode: 0, stdout: 'started maybe', stderr: '' })],
]) {
  test(`${reason} cannot succeed and guest errors redact the agent credential`, async () => {
    const h = harness({ result });
    await h.start(); await h.run();
    assert.equal(h.job().status, 'failed');
    assert.match(h.job().error, /Agent installation failed/);
    assert.equal(JSON.stringify(h.job()).includes(h.state.token), false);
    assert.equal(h.state.agentReads, 1);
  });
}

test('concurrent start requests atomically claim one job and dispatch one installer', async () => {
  const h = harness();
  h.state.lane.config.caldera_agent_access = { tokens: [{ vm_id: 902, token_hash: 'other-vm-hash' }] };
  const results = await Promise.allSettled([h.start(), h.start()]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.find(r => r.status === 'rejected').reason.status, 409);
  assert.equal(h.state.scheduled.length, 1);
  await h.run();
  assert.equal(h.state.calls.filter(c => c[0] === 'windows').length, 1);
  assert.equal(h.state.lane.config.caldera_agent_access.tokens.find(t => t.vm_id === 902).token_hash, 'other-vm-hash');
  assert.equal(h.state.lane.config.password, 'lane-password-private');
});

test('the atomic claim rejects a lane moved to a different course during the Caldera preflight', async () => {
  const h = harness({ agents: state => { state.lane.config.course_id = 'different-course'; return []; } });
  await assert.rejects(h.start(), { status: 409 });
  assert.equal(h.state.scheduled.length, 0);
  assert.deepEqual(h.state.calls.map(c => c[0]), ['proxmox']);
  assert.equal(h.state.lane.config.caldera_agent_access, undefined);
});

test('the atomic claim rejects a lane genuinely suspended during the Caldera preflight', async () => {
  const h = harness({ agents: state => { state.lane.status = 'suspended'; return []; } });
  await assert.rejects(h.start(), { status: 409 });
  assert.equal(h.state.scheduled.length, 0);
  assert.equal(h.state.lane.config.caldera_agent_access, undefined);
  assert.equal(h.state.lane.config.caldera_agent_job, undefined);
});

test('reinstall rotates only the selected VM credential and keeps its stable Caldera identity', async () => {
  const h = harness();
  const first = await h.start(); await h.run();
  const oldToken = h.state.token;
  assert.deepEqual(await h.service.authorize(`/agent/${oldToken}/beacon`), { paw: first.paw, group: first.group });
  const second = await h.start();
  assert.equal(second.paw, first.paw);
  assert.notEqual(second.job_id, first.job_id);
  assert.equal(await h.service.authorize(`/agent/${oldToken}/beacon`), null);
  await h.run();
  assert.notEqual(h.state.token, oldToken);
  assert.deepEqual(await h.service.authorize(`/agent/${h.state.token}/beacon`), { paw: second.paw, group: second.group });
  assert.equal(h.state.lane.config.caldera_agent_access.tokens.length, 1);
});

test('a timed-out queued job cannot execute or overwrite the replacement job', async () => {
  const h = harness();
  const old = await h.start();
  h.state.clock += JOB_TIMEOUT_MS + 1;
  const replacement = await h.start();
  assert.notEqual(old.job_id, replacement.job_id);
  const callsBeforeOldTask = clone(h.state.calls);
  await h.state.scheduled.shift()();
  assert.deepEqual(h.state.calls, callsBeforeOldTask);
  assert.equal(h.job().job_id, replacement.job_id);
  assert.equal(h.job().status, 'running');
  await h.run();
  assert.equal(h.state.calls.filter(c => c[0] === 'windows').length, 1);
  assert.equal(h.job().status, 'completed');
});

for (const [change, mutate] of [
  ['deleted', state => { state.lane = null; }],
  ['stopped', state => { state.lane.status = 'stopped'; }],
  ['VM removed', state => { state.lane.config.vms = []; }],
  ['moved to another course', state => { state.lane.config.course_id = 'different-course'; }],
]) {
  test(`a lane ${change} after queueing cannot dispatch the installer`, async () => {
    const h = harness(); await h.start(); mutate(h.state); await h.run();
    assert.deepEqual(h.state.calls.map(c => c[0]), ['proxmox']);
    if (h.state.lane) assert.equal(h.job().status, 'failed');
  });
}

for (const live of [[], [{ vmid: 901, type: 'qemu', status: 'stopped', node: 'actual-node' }],
  [{ vmid: 901, type: 'lxc', status: 'running', node: 'actual-node' }],
  [{ vmid: 901, type: 'qemu', status: 'running', node: 'actual-node', template: 1 }],
  [{ vmid: 901, type: 'qemu', status: 'running', node: '../wrong-node' }]]) {
  test(`unavailable or ineligible live guest ${JSON.stringify(live)} fails before token rotation`, async () => {
    const h = harness({ state: { resources: live } });
    h.state.lane.config.caldera_agent_access = { tokens: [{ vm_id: 901, token_hash: 'existing-token-hash' }] };
    const before = clone(h.state.lane);
    await assert.rejects(h.start(), err => err.status === 409 && /running QEMU guest/.test(err.message));
    assert.deepEqual(h.state.lane, before);
    assert.deepEqual(h.state.sql, []);
    assert.equal(h.state.scheduled.length, 0);
    assert.deepEqual(h.state.calls.map(c => c[0]), ['proxmox']);
  });
}

for (const state of [{ resources: null }, { proxmoxFailure: true }]) {
  test(`unverified Proxmox inventory ${JSON.stringify(state)} cannot rotate an existing credential`, async () => {
    const h = harness({ state });
    h.state.lane.config.caldera_agent_access = { tokens: [{ vm_id: 901, token_hash: 'existing-token-hash' }] };
    const before = clone(h.state.lane);
    await assert.rejects(h.start(), err => err.status === 503 && /verify VM power/.test(err.message)
      && !err.message.includes('private-proxmox-credential'));
    assert.deepEqual(h.state.lane, before);
    assert.deepEqual(h.state.sql, []);
    assert.deepEqual(h.state.calls.map(c => c[0]), ['proxmox']);
    assert.equal(h.state.scheduled.length, 0);
  });
}

test('a VM stopped after a successful preflight cannot dispatch the installer', async () => {
  const h = harness();
  await h.start();
  h.state.resources[0].status = 'stopped';
  await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /running QEMU guest/);
  assert.deepEqual(h.state.calls.map(c => c[0]), ['proxmox', 'proxmox']);
});

for (const marker of [{ error: 'Deployment failed; VMs retained' }, { provisioning_error: 'Guest setup failed' },
  { goad: { status: 'failed' } }]) {
  test(`a suspended deployment with ${JSON.stringify(marker)} installs on a live VM and permits fresh check-ins`, async () => {
    const h = harness();
    h.state.lane.status = 'suspended';
    Object.assign(h.state.lane.config, marker);
    const before = (await h.service.status([h.state.lane])).lanes[0];
    assert.equal(before.lane_status, 'suspended');
    assert.equal(before.lifecycle_eligible, true);
    assert.equal(before.retained_after_failure, true);
    assert.equal(before.runnable, true);
    assert.equal(before.targets[0].runnable, true);
    assert.equal(before.targets[0].power_state, 'running');
    await h.start(); await h.run();
    assert.equal(h.job().status, 'completed');
    assert.deepEqual(await h.service.authorize(`/agent/${h.state.token}/beacon`), {
      paw: h.job().paw, group: h.job().group,
    });
    assert.equal(h.state.lane.status, 'suspended', 'installing an agent must preserve the deployment lifecycle');
    assert.deepEqual(Object.fromEntries(Object.keys(marker).map(key => [key, h.state.lane.config[key]])), marker);
  });
}

test('genuinely suspended lanes remain blocked even if their VM is still running', async () => {
  for (const marker of [{}, { error: '' }, { error: '   ', provisioning_error: '\t' },
    { error: false }, { error: { message: 'failed' } }, { provisioning_error: [] }, { goad: { status: 'running' } }]) {
    const h = harness(); const token = 'a'.repeat(64);
    h.state.lane.status = 'suspended';
    Object.assign(h.state.lane.config, marker);
    h.state.lane.config.caldera_agent_access = { tokens: [{ token_hash: hashToken(token), vm_id: 901, paw: pawFor(LANE_ID, 901) }] };
    await assert.rejects(h.start(), { status: 409 });
    assert.equal(h.state.agentReads, 0);
    assert.deepEqual(h.state.calls, []);
    assert.deepEqual(h.state.sql, []);
    assert.equal(await h.service.authorize(`/agent/${token}/beacon`), null);
    const laneStatus = (await h.service.status([h.state.lane])).lanes[0];
    assert.equal(laneStatus.lifecycle_eligible, false);
    assert.equal(laneStatus.retained_after_failure, false);
    assert.equal(laneStatus.runnable, false);
    assert.equal(laneStatus.targets[0].power_state, 'running');
    assert.equal(laneStatus.targets[0].runnable, false);
    assert.equal(h.state.scheduled.length, 0);
  }
});

test('retained deployment credentials stop authorizing whenever live guest power cannot be confirmed', async () => {
  const h = harness();
  h.state.lane.status = 'suspended';
  h.state.lane.config.error = 'Historical provisioning failure';
  await h.start(); await h.run();
  const uri = `/agent/${h.state.token}/beacon`;
  const identity = { paw: h.job().paw, group: h.job().group };
  const live = clone(h.state.resources);
  assert.deepEqual(await h.service.authorize(uri), identity);
  h.state.resources[0].status = 'stopped';
  assert.equal(await h.service.authorize(uri), null);
  h.state.resources[0].status = 'unknown';
  assert.equal(await h.service.authorize(uri), null);
  h.state.resources = [];
  assert.equal(await h.service.authorize(uri), null);
  h.state.resources = live;
  h.state.proxmoxFailure = true;
  assert.equal(await h.service.authorize(uri), null);
  h.state.proxmoxFailure = false;
  assert.deepEqual(await h.service.authorize(uri), identity);
  delete h.state.lane.config.error;
  assert.equal(await h.service.authorize(uri), null, 'removing the retained-failure condition revokes the exception');
});

test('guest-agent failure is recorded without dispatching an installer', async () => {
  const h = harness({ state: { guestAvailable: false } });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /QEMU guest agent is unavailable/);
  assert.deepEqual(h.state.calls.map(c => c[0]), ['proxmox', 'proxmox', 'guest']);
});

test('authorization permits only recognized endpoints with a matching token hash on an active lane', async () => {
  const h = harness(); const token = 'a'.repeat(64);
  const paw = pawFor(LANE_ID, 901);
  h.state.lane.config.caldera_agent_access = { tokens: [{ token_hash: hashToken(token), vm_id: 901, paw }] };
  for (const endpoint of ['beacon', 'file/download', 'file/upload']) {
    assert.deepEqual(await h.service.authorize(`/agent/${token}/${endpoint}`), { paw, group: groupFor(LANE_ID) });
  }
  assert.deepEqual(h.state.calls, [], 'active-lane check-ins retain the existing database-only authorization path');
  assert.equal(JSON.stringify(h.state.sql).includes(token), false);
  assert.equal(await h.service.authorize(`/agent/${'b'.repeat(64)}/beacon`), null);
  h.state.lane.status = 'stopped';
  assert.equal(await h.service.authorize(`/agent/${token}/beacon`), null);
  const queries = h.state.sql.length;
  for (const uri of ['/beacon', `/agent/${token}/api/v2/agents`, `/agent/${token}/beacon?x=1`, `/agent/${token.toUpperCase()}/beacon`, `/agent/${token}/../beacon`]) {
    assert.equal(await h.service.authorize(uri), null);
  }
  assert.equal(h.state.sql.length, queries);
  h.state.dbFailure = true;
  await assert.rejects(h.service.authorize(`/agent/${token}/beacon`), /database unavailable/);
});

test('an installed agent loses authorization immediately when its VM leaves the lane', async () => {
  const h = harness();
  await h.start(); await h.run();
  const uri = `/agent/${h.state.token}/beacon`;
  assert.deepEqual(await h.service.authorize(uri), { paw: h.job().paw, group: h.job().group });
  h.state.lane.config.vms = [];
  assert.equal(await h.service.authorize(uri), null);
  assert.equal(h.state.lane.config.caldera_agent_access.tokens.length, 1, 'membership check must revoke even before stale token cleanup');
});

for (const vmId of [0, -1, 900, 999, '901oops', '9007199254740992']) {
  test(`token authorization rejects ineligible or invalid VM ID ${vmId}`, async () => {
    const h = harness(); const token = 'a'.repeat(64);
    h.state.lane.config.caldera_agent_access = { tokens: [{ token_hash: hashToken(token), vm_id: vmId, paw: pawFor(LANE_ID, 901) }] };
    assert.equal(await h.service.authorize(`/agent/${token}/beacon`), null);
  });
}

test('public status scopes agents to each lane and converts abandoned jobs to failed without leaking API errors', async () => {
  const h = harness();
  await h.start();
  h.state.clock += JOB_TIMEOUT_MS + 1;
  h.state.calderaFailure = true;
  const status = await h.service.status([h.state.lane]);
  assert.equal(status.lanes[0].job.status, 'failed');
  assert.match(status.lanes[0].job.error, /interrupted or timed out/);
  assert.match(status.agents_error, /Could not read Caldera/);
  assert.doesNotMatch(JSON.stringify(status), /private-api-key|lane-password-private|token_hash/);
  assert.equal(h.job().status, 'running', 'viewing status must not write a replacement job');
  const other = harness({ state: { agentOverride: { group: 'another-lane' } } });
  assert.deepEqual((await other.service.status([other.state.lane])).lanes[0].agents, []);
});

test('status distinguishes lifecycle eligibility from live power using one inventory read for all lanes', async () => {
  const h = harness();
  h.state.lane.config.vms.push({ vm_id: 902, name: 'Stopped guest' }, { vm_id: 903, name: 'Missing guest' });
  h.state.resources.push({ vmid: 902, node: 'actual-node', type: 'qemu', status: 'stopped' });
  const inactive = { ...clone(h.state.lane), lane_id: COURSE_ID, status: 'stopped' };
  const status = await h.service.status([h.state.lane, inactive]);
  assert.equal(status.power_error, null);
  assert.deepEqual(h.state.calls, [['proxmox', 'GET', '/api2/json/cluster/resources?type=vm']]);
  assert.equal(status.lanes[0].lifecycle_eligible, true);
  assert.equal(status.lanes[0].retained_after_failure, false);
  assert.equal(status.lanes[0].runnable, true);
  assert.deepEqual(status.lanes[0].targets.map(t => [t.vm_id, t.power_state, t.runnable]), [
    [901, 'running', true], [902, 'stopped', false], [903, 'unknown', false],
  ]);
  assert.equal(status.lanes[0].targets[0].node, 'actual-node');
  assert.equal(status.lanes[1].lifecycle_eligible, false);
  assert.equal(status.lanes[1].runnable, false);
  assert.equal(status.lanes[1].targets.every(target => !target.runnable), true);
});

test('failed power discovery reports unknown power and cannot advertise runnable targets', async () => {
  const h = harness({ state: { proxmoxFailure: true } });
  h.state.lane.status = 'suspended';
  h.state.lane.config.goad = { status: 'failed' };
  const status = await h.service.status([h.state.lane]);
  assert.match(status.power_error, /Could not verify VM power/);
  assert.equal(status.lanes[0].lifecycle_eligible, true);
  assert.equal(status.lanes[0].runnable, false);
  assert.equal(status.lanes[0].targets[0].runnable, false);
  assert.equal(status.lanes[0].targets[0].power_state, 'unknown');
  assert.doesNotMatch(JSON.stringify(status), /private-proxmox-credential/);
});
