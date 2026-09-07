'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createService, currentJob, JOB_TIMEOUT_MS, QUEUE_TIMEOUT_MS } = require('../src/utils/wazuh-lane-agents');

const LANE_ID = '11111111-2222-4333-8444-555555555555';
const OTHER_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const START = Date.parse('2026-09-07T20:00:00.000Z');
const KEY = 'private-per-agent-enrollment-key';
const registrationKey = (id, name, rawKey = 'a'.repeat(64)) => Buffer.from(`${id} ${name} any ${rawKey}`).toString('base64');
const clone = value => structuredClone(value);
const eligible = lane => !!lane && (lane.status === 'active' || (lane.status === 'suspended'
  && ([lane.config.error, lane.config.provisioning_error].some(value => typeof value === 'string' && value.trim())
    || lane.config.goad?.status === 'failed')));

function harness(options = {}) {
  const state = { lane: { lane_id: LANE_ID, name: 'Lab', status: 'active', config: {
    internet_enabled: true, password: 'private-lane-password', gateway_vm_id: 900,
    vms: [{ vm_id: 901, name: 'Windows workstation', os: 'windows' }],
  } }, resources: [{ vmid: 901, node: 'live-node', type: 'qemu', status: 'running' }],
  clock: START, scheduled: [], sql: [], calls: [], registrations: [], keys: {}, scripts: [], creates: 0, agentReads: 0 };
  Object.assign(state, options.state);
  const query = async (sql, args) => {
    state.sql.push({ sql, args: clone(args) });
    if (sql.startsWith('SELECT')) return { rows: state.lane ? [clone(state.lane)] : [] };
    assert.match(sql, /jsonb_set\(config, '\{wazuh_agent_jobs\}'/);
    if (sql.includes("NOT IN ('running', 'queued')")) {
      assert.match(sql, /internet_enabled' IS DISTINCT FROM 'false'::jsonb/);
      assert.match(sql, /wazuh_teardown_started' IS DISTINCT FROM 'true'::jsonb/);
      assert.match(sql, /job_id' IS NOT DISTINCT FROM \$6::text/);
      assert.match(sql, /status = 'active' OR \(status = 'suspended'/);
      assert.doesNotMatch(sql, /course_id/);
      const [laneId, jobJson, vmId, cutoff, queueCutoff, priorId] = args;
      const previous = state.lane?.config.wazuh_agent_jobs?.[vmId];
      if (!eligible(state.lane) || state.lane.lane_id !== laneId || state.lane.config.internet_enabled === false
        || state.lane.config.wazuh_teardown_started === true
        || (previous?.job_id || null) !== priorId
        || (previous?.status === 'running' && !(previous.started_at < cutoff))
        || (previous?.status === 'queued' && !(previous.started_at < queueCutoff))) return { rows: [] };
      state.lane.config.wazuh_agent_jobs ||= {};
      state.lane.config.wazuh_agent_jobs[vmId] = JSON.parse(jobJson);
      return { rows: [{ lane_id: laneId }] };
    }
    assert.match(sql, /job_id' = \$3 RETURNING lane_id/);
    const [laneId, jobJson, jobId, vmId] = args;
    if (state.lane?.lane_id !== laneId || state.lane.config.wazuh_agent_jobs?.[vmId]?.job_id !== jobId) return { rows: [] };
    state.lane.config.wazuh_agent_jobs[vmId] = JSON.parse(jobJson);
    return { rows: [{ lane_id: laneId }] };
  };
  const client = {
    async listAgents() {
      state.agentReads++;
      if (state.apiFailure) throw new Error('private-api-password');
      return clone(state.registrations);
    },
    async createAgent(name, createOptions) {
      state.creates++;
      const id = String(state.creates).padStart(3, '0');
      state.registrations.push({ id, name, status: 'never_connected', lastKeepAlive: null });
      state.keys[id] = registrationKey(id, name, createOptions?.key);
      if (options.createHook) await options.createHook(state);
      return { id, key: state.keys[id] };
    },
    async getAgentKey(id) { state.calls.push(['key', id]); return state.keys[id]; },
    async deleteAgent(id, name) {
      state.calls.push(['delete', id, name]);
      if (state.deleteFailure) throw new Error('private-deletion-error');
      if (options.deleteHook) await options.deleteHook(state, id, name);
      state.registrations = state.registrations.filter(agent => agent.id !== id || agent.name !== name);
      return { id, name };
    },
    async assertGroupExists(group) {
      state.calls.push(['group-check', group]);
      if (state.groupMissing) throw Object.assign(new Error('Could not verify WAZUH_AGENT_GROUP.'), { status: 503, safe: true });
    },
    async ensureAgentGroup(id, group) {
      state.calls.push(['group-assign', id, group]);
      assert.ok(Object.values(state.lane.config.wazuh_agent_jobs).some(job => job.agent_id === id));
      if (options.groupHook) await options.groupHook(state);
      if (state.groupFailure) throw Object.assign(new Error('Could not assign the agent to WAZUH_AGENT_GROUP.'), { status: 502, safe: true });
      const agent = state.registrations.find(item => item.id === id);
      agent.group = [...new Set([...(agent.group || ['default']), group])];
    },
  };
  const executor = {
    async waitForGuestAgent(...args) {
      state.calls.push(['guest', ...args]);
      if (options.guestHook) await options.guestHook(state);
      return state.guestAvailable !== false;
    },
    async agentExecArgv(...args) {
      state.calls.push(['windows', ...args]);
      if (state.execFailure) throw new Error(`private-api-password ${KEY}`);
      return { pid: args[1] };
    },
    async proxmoxFormPOST(...args) {
      state.calls.push(['linux', ...args]);
      return { pid: Number(args[0].match(/qemu\/(\d+)/)[1]) };
    },
    async pollExecStatus(node, vmId, pid, timeout) {
      assert.equal(timeout, 600000);
      const job = state.lane.config.wazuh_agent_jobs[String(vmId)];
      const agent = state.registrations.find(item => item.id === job.agent_id);
      agent.status = options.agentStatus || 'active';
      agent.lastKeepAlive = new Date(state.clock + (options.stale ? -1000 : 1000)).toISOString();
      if (options.result) return options.result(state, job);
      return { exited: true, exitcode: 0, stdout: `CYBERCORE_WAZUH_STARTED:${job.agent_name}\n`, stderr: '' };
    },
  };
  const service = createService({ query, executor, settings: () => {
    if (state.configFailure) throw new Error('private-api-password');
    return { manager: state.manager || 'wazuh.example.test', consoleUrl: 'https://wazuh.example.test/', version: '4.14.0-1', client,
      agentGroup: state.agentGroup || null };
  }, now: () => state.clock, sleep: async ms => { state.clock += ms; }, schedule: run => state.scheduled.push(run),
  ensureGatewayAccess: async (request, dependencies) => {
    state.calls.push(['gateway', request.vmId, request.manager]);
    assert.equal((await dependencies.readLane()).lane_id, LANE_ID);
    if (options.gatewayHook) await options.gatewayHook(state);
    if (state.gatewayFailure) throw Object.assign(new Error('Could not prepare Wazuh TCP 1514 access on the lane gateway.'), { status: 409, safe: true });
  },
  buildInstallScript: args => { state.scripts.push(args); return `installation ${args.agentKey}`; },
  courseDirectory: options.courseDirectory,
  deadline: options.deadline,
  proxmox: async (...args) => {
    state.calls.push(['proxmox', ...args]);
    if (state.powerFailure) throw new Error('private-proxmox-password');
    return clone(state.resources);
  } });
  return { state, service, job: (id = 901) => state.lane.config.wazuh_agent_jobs?.[String(id)],
    start: (input = { vm_id: 901, platform: 'windows' }) => service.start(clone(state.lane), input),
    run: async () => { while (state.scheduled.length) await Promise.all(state.scheduled.splice(0).map(run => run())); } };
}

function addMachines(h, count) {
  h.state.lane.config.vms = Array.from({ length: count }, (_, index) => ({ vm_id: 901 + index, name: 'Reused hostname', os: 'linux' }));
  h.state.resources = h.state.lane.config.vms.map(vm => ({ vmid: vm.vm_id, node: 'live-node', type: 'qemu', status: 'running' }));
  return h.state.lane.config.vms.map(vm => ({ lane_id: LANE_ID, vm_id: vm.vm_id, platform: 'linux' }));
}

test('Windows enrollment persists identity and requires a fresh active server check-in without storing keys', async () => {
  const h = harness();
  const response = await h.start();
  assert.equal(response.status, 'queued');
  assert.equal(response.agent_name, 'Windows-workstation-vm-901');
  await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.job().agent_id, '001');
  assert.equal(h.state.creates, 1);
  assert.deepEqual(h.state.scripts[0], { platform: 'windows', manager: 'wazuh.example.test', version: '4.14.0-1', agentName: h.job().agent_name, agentKey: h.state.keys['001'] });
  const dispatch = h.state.calls.find(call => call[0] === 'windows');
  assert.equal(dispatch[1], 'live-node');
  assert.deepEqual(dispatch[3].slice(0, 5), ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
  assert.doesNotMatch(JSON.stringify(h.state.sql), /private-per-agent-enrollment-key/);
  assert.equal(JSON.stringify(h.state.sql).includes(h.state.keys['001']), false);
  assert.equal(JSON.stringify(h.state.sql).includes(Buffer.from(h.state.keys['001'], 'base64').toString().split(' ')[3]), false);
  const status = await h.service.status([h.state.lane]);
  assert.equal(status.lanes[0].agents[0].id, '001');
  assert.doesNotMatch(JSON.stringify(status), /private-|agentKey|password/);
});

test('retry uses saved registration and key without creating or deleting an agent', async () => {
  const h = harness();
  const first = await h.start(); await h.run();
  const next = await h.start(); await h.run();
  assert.notEqual(next.job_id, first.job_id);
  assert.equal(next.agent_name, first.agent_name);
  assert.equal(h.state.creates, 1);
  assert.ok(h.state.calls.some(call => call[0] === 'key' && call[1] === '001'));
  assert.equal(h.job().status, 'completed');
});

test('retry recovers a registration created when the API response was lost', async () => {
  let fail = true;
  const h = harness({ createHook: () => { if (fail) { fail = false; throw new Error(`lost response ${KEY}`); } } });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.equal(h.job().agent_id, undefined);
  const name = h.job().agent_name;
  await h.start(); await h.run();
  assert.equal(h.job().agent_name, name);
  assert.equal(h.job().agent_id, '001');
  assert.equal(h.state.creates, 1);
  assert.equal(h.job().status, 'completed');
});

test('readable names use the recorded user-facing hostname or live Proxmox name and retain VMID', async () => {
  for (const [recorded, liveName, expected] of [
    [{ proxmox_name: 'cle-cybr400-inperson-10811' }, 'other', 'cle-cybr400-inperson-10811-vm-901'],
    [{ hostname: 'Student Windows' }, 'other', 'Student-Windows-vm-901'],
    [{}, 'deployed-win11', 'deployed-win11-vm-901'],
  ]) {
    const h = harness();
    Object.assign(h.state.lane.config.vms[0], recorded);
    h.state.resources[0].name = liveName;
    assert.equal((await h.start()).agent_name, expected);
  }
});

test('readable enrollment persists proof before creation and retains it and the name across retries', async () => {
  const { keyFingerprint } = require('../src/utils/wazuh-agent-identity');
  const h = harness({ createHook: state => {
    const job = state.lane.config.wazuh_agent_jobs['901'];
    assert.equal(job.name_version, 2);
    assert.match(job.registration_owner, /^[a-f0-9-]{36}$/);
    assert.deepEqual(job.registration_key_hashes, [keyFingerprint(state.keys['001'])]);
  } });
  await h.start(); await h.run();
  const first = clone(h.job());
  h.state.resources[0].name = 'renamed-after-enrollment';
  await h.start(); await h.run();
  assert.equal(h.job().agent_name, first.agent_name);
  assert.equal(h.job().registration_owner, first.registration_owner);
  assert.deepEqual(h.job().registration_key_hashes, first.registration_key_hashes);
  assert.equal(h.state.creates, 1);
  assert.doesNotMatch(JSON.stringify(await h.service.status([h.state.lane])), /registration_owner|registration_key_hashes/);
});

test('a reused readable name or changed key cannot be adopted or sent to a guest', async () => {
  const h = harness();
  h.state.registrations.push({ id: '018', name: 'Windows-workstation-vm-901', status: 'active' });
  h.state.keys['018'] = registrationKey('018', 'Windows-workstation-vm-901');
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /another identity/);
  assert.equal(h.job().agent_id, undefined);
  assert.equal(h.state.creates, 0);
  assert.equal(h.state.scripts.length, 0);

  const changed = harness({ createHook: state => {
    state.keys['001'] = registrationKey('001', state.registrations[0].name, 'b'.repeat(64));
  } });
  await changed.start(); await changed.run();
  assert.equal(changed.job().status, 'failed');
  assert.match(changed.job().error, /authorized registration key/);
  assert.equal(changed.state.scripts.length, 0);
});

function legacyRegistration(h, { enrolled = true } = {}) {
  const name = `cc-${LANE_ID.replaceAll('-', '')}-901-${OTHER_ID.replaceAll('-', '')}`;
  h.state.lane.config.wazuh_agent_jobs = { '901': {
    job_id: OTHER_ID, vm_id: 901, status: 'failed', manager: 'wazuh.example.test',
    agent_name: name, ...(enrolled ? { agent_id: '016' } : {}),
  } };
  if (enrolled) {
    h.state.registrations.push({ id: '016', name, status: 'active', group: ['default', 'StudentVM', 'Exercise'] });
    h.state.keys['016'] = registrationKey('016', name);
  }
  return name;
}

test('legacy rename transfers group policy and removes the old registration only after the new check-in', async () => {
  const h = harness({ deleteHook: (state, id, name) => {
    assert.equal(id, '016');
    assert.match(name, /^cc-/);
    const next = state.registrations.find(agent => agent.id === '001');
    assert.equal(next.status, 'active');
    assert.ok(Date.parse(next.lastKeepAlive) > Date.parse(state.lane.config.wazuh_agent_jobs['901'].dispatched_at));
  } });
  const oldName = legacyRegistration(h);
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.job().agent_name, 'Windows-workstation-vm-901');
  assert.equal(h.job().agent_id, '001');
  assert.equal(h.state.scripts[0].previousAgentName, oldName);
  assert.equal(h.state.scripts[0].previousAgentKey, h.state.keys['016']);
  assert.deepEqual(h.state.registrations[0].group, ['default', 'StudentVM', 'Exercise']);
  assert.equal(h.job().previous_agent_id, undefined);
  assert.equal(h.job().previous_agent_name, undefined);
  assert.equal(h.state.registrations.length, 1);
  assert.equal(JSON.stringify(h.state.sql).includes(h.state.keys['016']), false);
});

test('legacy jobs that never enrolled can retry as a fresh readable registration', async () => {
  const h = harness();
  legacyRegistration(h, { enrolled: false });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.state.creates, 1);
  assert.equal(h.state.scripts[0].previousAgentKey, undefined);
  assert.equal(h.job().previous_agent_name, undefined);
});

test('failed migration keeps both registrations for retry and lane destruction', async () => {
  const h = harness({ stale: true });
  const oldName = legacyRegistration(h);
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.equal(h.job().previous_agent_name, oldName);
  assert.equal(h.job().previous_agent_id, '016');
  assert.equal(h.job().agent_id, '001');
  assert.equal(h.state.registrations.length, 2);
  assert.equal(h.state.calls.some(call => call[0] === 'delete'), false);
});

test('interrupted retirement retries the same readable registration and then retires the old one', async () => {
  const h = harness({ state: { deleteFailure: true } });
  legacyRegistration(h);
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.equal(h.job().previous_agent_id, '016');
  h.state.deleteFailure = false;
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.state.creates, 1);
  assert.equal(h.state.registrations.length, 1);
  assert.equal(h.job().previous_agent_id, undefined);
});

test('saved identity is not migrated to another manager or a reused agent ID', async () => {
  const h = harness();
  await h.start(); await h.run();
  h.state.manager = 'different.example.test';
  await assert.rejects(h.start(), { status: 409 });
  h.state.manager = 'wazuh.example.test';
  h.state.registrations[0].name = 'someone-else';
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /different identity/);
  assert.equal(h.state.calls.filter(call => call[0] === 'windows').length, 1);
});

test('concurrent requests atomically claim one job and retain other lane configuration', async () => {
  const h = harness();
  const results = await Promise.allSettled([h.start(), h.start()]);
  assert.equal(results.filter(item => item.status === 'fulfilled').length, 1);
  assert.equal(results.find(item => item.status === 'rejected').reason.status, 409);
  assert.equal(h.state.scheduled.length, 1);
  assert.equal(h.state.lane.config.password, 'private-lane-password');
  await h.run();
  assert.equal(h.state.creates, 1);
});

for (const [label, mutate] of [
  ['removed lane', state => { state.lane = null; }],
  ['suspended lane', state => { state.lane.status = 'suspended'; }],
  ['removed VM', state => { state.lane.config.vms = []; }],
  ['disabled Internet', state => { state.lane.config.internet_enabled = false; }],
  ['lane destruction', state => { state.lane.config.wazuh_teardown_started = true; }],
  ['stopped guest', state => { state.resources[0].status = 'stopped'; }],
  ['replaced job', state => { state.lane.config.wazuh_agent_jobs['901'].job_id = OTHER_ID; }],
]) {
  test(`${label} after guest readiness prevents enrollment and guest modification`, async () => {
    const h = harness({ guestHook: mutate });
    await h.start(); await h.run();
    assert.equal(h.state.creates, 0);
    assert.equal(h.state.calls.some(call => ['windows', 'linux'].includes(call[0])), false);
  });
}

test('membership and job ownership are checked again after registration before changing the VM', async () => {
  const h = harness({ createHook: state => { state.lane.config.vms = []; } });
  await h.start(); await h.run();
  assert.equal(h.state.creates, 1);
  assert.equal(h.state.calls.some(call => call[0] === 'windows'), false);
  assert.equal(h.job().status, 'failed');
});

test('gateway access is prepared before enrollment and installation, and failure prevents both', async () => {
  const h = harness({ createHook: state => assert.ok(state.calls.some(call => call[0] === 'gateway')) });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.ok(h.state.calls.findIndex(call => call[0] === 'gateway') < h.state.calls.findIndex(call => call[0] === 'windows'));
  const blocked = harness({ state: { gatewayFailure: true } });
  await blocked.start(); await blocked.run();
  assert.equal(blocked.job().status, 'failed');
  assert.match(blocked.job().error, /TCP 1514/);
  assert.equal(blocked.state.creates, 0);
  assert.equal(blocked.state.scripts.length, 0);
});

test('lane destruction disables inventory targets and blocks claims before infrastructure access', async () => {
  const h = harness();
  h.state.lane.config.wazuh_teardown_started = true;
  await assert.rejects(h.start(), /being destroyed/);
  assert.equal(h.state.scheduled.length, 0);
  assert.equal(h.state.sql.length, 0);
  const status = await h.service.status([h.state.lane]);
  assert.equal(status.lanes[0].runnable, false);
});

test('destruction during registration preserves the identity for cleanup and prevents guest execution', async () => {
  const h = harness({ createHook: state => { state.lane.config.wazuh_teardown_started = true; } });
  await h.start(); await h.run();
  assert.equal(h.state.creates, 1);
  assert.equal(h.job().agent_id, '001');
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /being destroyed/);
  assert.equal(h.state.calls.some(call => call[0] === 'windows'), false);
});

for (const [label, mutate] of [
  ['disabled Internet', state => { state.lane.config.internet_enabled = false; }],
  ['removed VM', state => { state.lane.config.vms = []; }],
  ['replaced job', state => { state.lane.config.wazuh_agent_jobs['901'].job_id = OTHER_ID; }],
]) {
  test(`${label} while preparing gateway access prevents enrollment and guest installation`, async () => {
    const h = harness({ gatewayHook: mutate });
    await h.start(); await h.run();
    assert.equal(h.state.creates, 0);
    assert.equal(h.state.scripts.length, 0);
    assert.equal(h.state.calls.some(call => call[0] === 'windows'), false);
  });
}

test('malware analysis lanes cannot queue central gateway access or advertise runnable targets', async () => {
  const h = harness();
  h.state.lane.config.analysis_profile = 'malware';
  await assert.rejects(h.start(), /malware analysis lane/);
  assert.equal(h.state.scheduled.length, 0);
  assert.equal(h.state.calls.some(call => call[0] === 'gateway'), false);
  const status = await h.service.status([h.state.lane]);
  assert.equal(status.lanes[0].targets[0].runnable, false);
});

test('replaced queue jobs cannot execute or overwrite their replacement', async () => {
  const h = harness();
  const old = await h.start();
  h.state.clock += QUEUE_TIMEOUT_MS + 1;
  const next = await h.start();
  await h.state.scheduled.shift()();
  assert.equal(h.job().job_id, next.job_id);
  assert.equal(h.job().status, 'queued');
  assert.equal(h.state.creates, 0);
  assert.notEqual(old.job_id, next.job_id);
  await h.run();
  assert.equal(h.job().status, 'completed');
});

test('running and queued expiry use separate bounds and malformed timestamps fail closed', () => {
  for (const [status, limit] of [['running', JOB_TIMEOUT_MS], ['queued', QUEUE_TIMEOUT_MS]]) {
    const job = { status, started_at: new Date(START).toISOString() };
    assert.equal(currentJob(job, START + limit - 1).status, status);
    assert.equal(currentJob(job, START + limit + 1).status, 'failed');
    assert.equal(currentJob({ ...job, started_at: 'invalid' }, START).status, 'failed');
  }
});

for (const options of [{ stale: true }, { agentStatus: 'disconnected' }]) {
  test(`stale/inactive check-ins never count as completion ${JSON.stringify(options)}`, async () => {
    const h = harness(options);
    await h.start(); await h.run();
    assert.equal(h.job().status, 'failed');
    assert.match(h.job().error, /no fresh active check-in/);
  });
}

test('guest exceptions and failed output cannot leak encoded or decoded credentials', async () => {
  for (const options of [{ state: { execFailure: true } }, { result: () => ({ exited: true, exitcode: 1, stdout: KEY, stderr: `decoded-key private-api-password ${KEY}` }) }]) {
    const h = harness(options);
    await h.start(); await h.run();
    assert.equal(h.job().status, 'failed');
    assert.doesNotMatch(JSON.stringify(h.state.lane.config.wazuh_agent_jobs), /private-|decoded-key/);
  }
});

test('controlled installer refusal markers show a useful message without publishing guest output', async () => {
  const h = harness({ result: () => ({ exited: true, exitcode: 1, stdout: KEY, stderr: `CYBERCORE_WAZUH_ERROR:identity-conflict\n${KEY}` }) });
  await h.start(); await h.run();
  assert.match(h.job().error, /different Wazuh identity/);
  assert.doesNotMatch(h.job().error, /private-/);
  const missing = harness({ result: () => ({ exited: true, exitcode: 1, stdout: '', stderr: 'CYBERCORE_WAZUH_ERROR:python3-missing\n' }) });
  await missing.start(); await missing.run();
  assert.match(missing.job().error, /Python 3/);
});

test('download, integrity and service failures identify the stage without exposing guest details', async () => {
  for (const [code, message] of [
    ['download-failed', /package or checksum.*packages\.wazuh\.com/],
    ['checksum-invalid', /checksum was invalid/],
    ['checksum-mismatch', /did not match its SHA-512 checksum/],
    ['key-import-failed', /enrollment key could not be imported/],
    ['service-start-failed', /service could not be started/],
  ]) {
    const h = harness({ result: () => ({ exited: true, exitcode: 1,
      stdout: `private-api-password ${KEY}`, stderr: `CYBERCORE_WAZUH_ERROR:${code}\r\nprivate-guest-exception` }) });
    await h.start(); await h.run();
    assert.equal(h.job().status, 'failed');
    assert.match(h.job().error, message);
    assert.doesNotMatch(JSON.stringify(h.state.lane.config.wazuh_agent_jobs), /private-/);
  }
});

test('unknown or malformed installer markers stay generic and never publish guest text', async () => {
  for (const output of ['CYBERCORE_WAZUH_ERROR:private-unknown-stage',
    'CYBERCORE_WAZUH_ERROR:download-failed private-api-password',
    'private-prefix CYBERCORE_WAZUH_ERROR:download-failed']) {
    const h = harness({ result: () => ({ exited: true, exitcode: 1, stdout: output, stderr: KEY }) });
    await h.start(); await h.run();
    assert.match(h.job().error, /^Agent installation failed\./);
    assert.doesNotMatch(JSON.stringify(h.state.lane.config.wazuh_agent_jobs), /private-/);
  }
});

test('status associates duplicate hostnames to persisted lane identities and strips private fields', async () => {
  const h = harness();
  await h.start(); await h.run();
  h.state.registrations.push({ id: '999', name: 'Windows workstation', status: 'active', key: KEY });
  h.job().agentKey = KEY;
  const other = { ...clone(h.state.lane), lane_id: OTHER_ID, config: { vms: [{ vm_id: 902, name: 'Windows workstation' }] } };
  const status = await h.service.status([h.state.lane, other]);
  assert.equal(status.lanes[0].agents.length, 1);
  assert.equal(status.lanes[0].agents[0].id, '001');
  assert.equal(status.lanes[0].targets[0].agent.id, '001');
  assert.deepEqual(status.lanes[1].agents, []);
  assert.equal(status.lanes[1].targets[0].power_state, 'unknown');
  assert.equal(status.lanes[1].runnable, false);
  assert.doesNotMatch(JSON.stringify(status), /private-|agentKey|password/);
});

test('status projects allowlisted lane context and resolves course labels through the directory', async () => {
  const calls = [];
  const h = harness({
    courseDirectory: { hasCourseDirectory: () => true, describeCourse: async id => {
      calls.push(id);
      return { courseId: id, courseName: 'Network Defense', courseCode: 'CYBR388' };
    } },
    deadline: () => new Promise(() => {}),
    state: { lane: { lane_id: LANE_ID, name: 'cle-cybr388-10447', status: 'active', vxlan_id: 10447,
      created_at: '2026-09-01T00:00:00.000Z', config: {
        internet_enabled: true, cle: true, course_id: OTHER_ID, group_id: 'g1', group_name: '  Cochise 101  ',
        user_email: 'snapshot@example.test', password: 'private-lane-password', gateway_vm_id: 900,
        vms: [{ vm_id: 901, name: 'Windows workstation', os: 'windows', role: 'dc' }],
      } } },
  });
  const lane = (await h.service.status([h.state.lane])).lanes[0];
  assert.equal(lane.course_code, 'CYBR388');
  assert.equal(lane.course_name, 'Network Defense');
  assert.equal(lane.course_id, OTHER_ID.toLowerCase());
  assert.equal(lane.kind, 'course');
  assert.equal(lane.family, 'cle-cybr388');
  assert.equal(lane.lane_number, 10447);
  assert.equal(lane.vxlan_id, 10447);
  assert.equal(lane.group_id, 'g1');
  assert.equal(lane.group_label, 'Cochise 101');
  assert.equal(lane.created_at, '2026-09-01T00:00:00.000Z');
  assert.equal(lane.targets[0].role, 'dc');
  // The owner email snapshot and the lane password live in the same config
  // object the context is derived from; enumerating fields keeps them out.
  assert.doesNotMatch(JSON.stringify(lane), /private-|password|snapshot@example|gateway_vm_id|user_email/);

  await h.service.status([h.state.lane]);
  assert.deepEqual(calls, [OTHER_ID.toLowerCase()], 'a second poll inside the TTL reuses the memo');
  h.state.clock += 61 * 1000;
  await h.service.status([h.state.lane]);
  assert.equal(calls.length, 2, 'an expired memo entry is refetched');
});

test('lane context degrades to nulls without a course directory, a name suffix or a usable timestamp', async () => {
  const h = harness({ state: { lane: { lane_id: LANE_ID, name: 'Lab', status: 'active',
    created_at: 'garbage', config: { internet_enabled: true, analysis_profile: 'malware',
      vms: [{ vm_id: 901, name: 'Windows workstation' }] } } } });
  const lane = (await h.service.status([h.state.lane])).lanes[0];
  assert.equal(lane.course_code, null);
  assert.equal(lane.course_name, null);
  assert.equal(lane.course_id, null);
  assert.equal(lane.family, null);
  assert.equal(lane.lane_number, null);
  assert.equal(lane.vxlan_id, null);
  assert.equal(lane.created_at, null);
  assert.equal(lane.kind, 'malware');
});

test('API, TLS configuration and power outages produce safe status and block claims', async () => {
  for (const flag of ['apiFailure', 'powerFailure', 'configFailure']) {
    const h = harness({ state: { [flag]: true } });
    const status = await h.service.status([h.state.lane]);
    assert.ok(status.agents_error || status.power_error || status.configuration_error);
    assert.doesNotMatch(JSON.stringify(status), /private-/);
    if (flag === 'powerFailure') assert.equal(status.lanes[0].targets[0].runnable, false);
    await assert.rejects(h.start());
    assert.equal(h.state.sql.length, 0);
    assert.equal(h.state.scheduled.length, 0);
  }
});

test('retained failed deployments support live VMs while ordinary suspended lanes stay blocked', async () => {
  const h = harness();
  h.state.lane.status = 'suspended';
  await assert.rejects(h.start(), { status: 409 });
  h.state.lane.config.provisioning_error = 'Provisioning failed';
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.state.lane.status, 'suspended');
});

test('batch rejects malformed, repeated, unknown and oversized targets before side effects', async () => {
  const h = harness(); const targets = addMachines(h, 2);
  for (const bad of [[], [...targets, targets[0]], [{ ...targets[0], lane_id: OTHER_ID }],
    [{ ...targets[0], vm_id: 999 }], [{ ...targets[0], platform: 'unknown' }], Array(201).fill(targets[0])]) {
    await assert.rejects(h.service.startBatch([h.state.lane], { targets: bad }), error => [400, 404].includes(error.status));
  }
  assert.equal(h.state.sql.length, 0);
  assert.equal(h.state.calls.length, 0);
  assert.equal(h.state.agentReads, 0);
});

test('batch returns independent busy/stopped errors and shares one API and live power preflight', async () => {
  const h = harness(); const targets = addMachines(h, 3);
  await h.start({ vm_id: 901, platform: 'linux' });
  h.state.resources[2].status = 'stopped';
  const before = h.state.agentReads;
  const reads = h.state.calls.filter(call => call[0] === 'proxmox').length;
  const result = await h.service.startBatch([h.state.lane], { targets });
  assert.equal(result.results[0].status, 409);
  assert.equal(result.results[1].job.status, 'queued');
  assert.equal(result.results[2].status, 409);
  assert.equal(h.state.agentReads, before + 1);
  assert.equal(h.state.calls.filter(call => call[0] === 'proxmox').length, reads + 1);
});

test('batch limits concurrent installers to four and preserves sibling jobs and Linux form execution', async () => {
  let active = 0, maximum = 0;
  const release = [];
  const h = harness({ result: (state, job) => new Promise(resolve => {
    active++; maximum = Math.max(maximum, active);
    release.push(() => { active--; resolve({ exited: true, exitcode: 0, stdout: `CYBERCORE_WAZUH_STARTED:${job.agent_name}` }); });
  }) });
  const targets = addMachines(h, 7);
  await h.service.startBatch([h.state.lane], { targets });
  assert.equal(h.state.scheduled.length, 4);
  while (h.state.scheduled.length) {
    const running = h.state.scheduled.splice(0).map(run => run());
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(active <= 4);
    release.splice(0).forEach(resolve => resolve());
    await Promise.all(running);
  }
  assert.equal(maximum, 4);
  assert.equal(h.state.creates, 7);
  assert.ok(Object.values(h.state.lane.config.wazuh_agent_jobs).every(job => job.status === 'completed'));
  assert.equal(h.state.calls.filter(call => call[0] === 'linux').length, 7);
  assert.doesNotMatch(JSON.stringify(h.state.sql), /private-per-agent/);
});

test('optional group assignment runs before guest installation for a new registration and its retry', async () => {
  const h = harness({ state: { agentGroup: 'StudentVM' } });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.deepEqual(h.state.registrations[0].group, ['default', 'StudentVM']);
  const assignment = h.state.calls.findIndex(call => call[0] === 'group-assign');
  assert.ok(assignment > -1 && assignment < h.state.calls.findIndex(call => call[0] === 'windows'));
  h.state.registrations[0].group.push('servers');
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.state.creates, 1);
  assert.deepEqual(h.state.registrations[0].group, ['default', 'StudentVM', 'servers']);
  assert.equal(h.state.calls.filter(call => call[0] === 'group-assign').length, 2);
  assert.equal(h.state.calls.filter(call => call[0] === 'group-check').length, 4);
  const noGroup = harness();
  await noGroup.start(); await noGroup.run();
  assert.equal(noGroup.state.calls.some(call => call[0].startsWith('group-')), false);
});

test('missing configured group blocks standalone and batch claims without creating registrations', async () => {
  for (const batch of [false, true]) {
    const h = harness({ state: { agentGroup: 'StudentVM', groupMissing: true } });
    const request = batch ? h.service.startBatch([h.state.lane], {
      targets: [{ lane_id: LANE_ID, vm_id: 901, platform: 'windows' }],
    }) : h.start();
    await assert.rejects(request, /WAZUH_AGENT_GROUP/);
    assert.equal(h.state.sql.length, 0);
    assert.equal(h.state.creates, 0);
    assert.equal(h.state.scheduled.length, 0);
  }
});

test('a group removed after queuing is rejected before enrollment or guest installation', async () => {
  const h = harness({ state: { agentGroup: 'StudentVM' } });
  await h.start();
  h.state.groupMissing = true;
  await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /WAZUH_AGENT_GROUP/);
  assert.equal(h.state.creates, 0);
  assert.equal(h.state.scripts.length, 0);
  assert.equal(h.state.calls.some(call => call[0] === 'windows'), false);
});

test('failed group assignment preserves the saved registration and retries it before guest modification', async () => {
  const h = harness({ state: { agentGroup: 'StudentVM', groupFailure: true } });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /WAZUH_AGENT_GROUP/);
  assert.equal(h.job().agent_id, '001');
  assert.equal(h.state.calls.some(call => call[0] === 'windows'), false);
  h.state.groupFailure = false;
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.state.creates, 1);
  assert.equal(h.job().agent_id, '001');
  assert.deepEqual(h.state.registrations[0].group, ['default', 'StudentVM']);
});

test('lane access is revalidated after waiting on manager-side group assignment', async () => {
  const h = harness({ state: { agentGroup: 'StudentVM' }, groupHook: async state => { state.lane.config.internet_enabled = false; } });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /internet access is disabled/);
  assert.equal(h.state.calls.some(call => call[0] === 'windows'), false);
});
