'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createService, targetsFor, hashToken, pawFor, groupFor, seenAt, JOB_TIMEOUT_MS, QUEUE_TIMEOUT_MS,
  CHECK_IN_ATTEMPTS, CHECK_IN_INTERVAL_MS } = require('../src/utils/caldera-lane-agents');

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
  // agentPid models the ONE thing that separates a Sandcat this install started
  // from one an earlier install left running: pawFor is a hash of (lane, vm) and
  // groupFor is per lane, so both register under identical paw, group and
  // platform for ever. captureScript advances it, because that is the moment the
  // installer actually reaches the guest. A test that wants the "the agent here
  // is the old one" case simply pins it.
  const state = { lane: laneFixture(), clock: START, scheduled: [], sql: [], calls: [],
    agentReads: 0, sleepCalls: [], script: null, token: null, agentPid: 3100, agentPidFrozen: false,
    resources: [{ vmid: 901, node: 'actual-node', type: 'qemu', status: 'running' }] };
  Object.assign(state, options.state);
  const query = async (sql, args) => {
    state.sql.push({ sql, args: clone(args) });
    if (state.dbFailure) throw new Error('database unavailable');
    // Cancelling queued work. Modelled before the claim branch below because
    // it also RETURNs lane_id but is addressed by lane ARRAY, not by $1 alone.
    if (sql.includes("'cancelled'")) {
      const [laneIds, courseId, stamp] = args;
      const lane = state.lane;
      if (!lane || !laneIds.includes(lane.lane_id) || (lane.config.course_id || null) !== courseId) return { rows: [] };
      let cancelled = 0;
      for (const job of Object.values(lane.config.caldera_agent_jobs || {})) {
        if (job.status !== 'queued') continue;
        Object.assign(job, { status: 'cancelled', finished_at: stamp, message: 'Installation cancelled before it started.' });
        cancelled += 1;
      }
      if (cancelled && String(lane.config.caldera_agent_job?.status) === 'queued') lane.config.caldera_agent_job.status = 'cancelled';
      return { rows: cancelled ? [{ lane_id: lane.lane_id, cancelled }] : [] };
    }
    if (sql.includes('RETURNING lane_id')) {
      assert.match(sql, /WHERE lane_id = \$1 AND /);
      assertLifecycleSql(sql);
      assert.match(sql, /course_id' IS NOT DISTINCT FROM \$6::text/);
      assert.match(sql, /started_at' < \$5/);
      assert.match(sql, /NOT IN \('running', 'queued'\)/);
      const [laneId, jobJson, vmId, accessJson, cutoff, courseId, queueCutoff] = args;
      const lane = state.lane;
      const prior = lane?.config.caldera_agent_jobs?.[vmId] || (String(lane?.config.caldera_agent_job?.vm_id) === vmId ? lane.config.caldera_agent_job : null);
      if (!eligibleFixture(lane) || lane.lane_id !== laneId
        || (lane.config.course_id || null) !== courseId
        || (prior?.status === 'running' && !(prior.started_at < cutoff))
        || (prior?.status === 'queued' && !(prior.started_at < queueCutoff))) return { rows: [] };
      const tokens = lane.config.caldera_agent_access?.tokens || [];
      lane.config.caldera_agent_access = { tokens: tokens.filter(t => String(t.vm_id) !== vmId).concat(JSON.parse(accessJson)) };
      lane.config.caldera_agent_job = JSON.parse(jobJson);
      lane.config.caldera_agent_jobs ||= {};
      lane.config.caldera_agent_jobs[vmId] = lane.config.caldera_agent_job;
      return { rows: [{ lane_id: laneId }] };
    }
    if (sql.startsWith('UPDATE')) {
      assert.match(sql, /job_id' = \$3/);
      if (state.lane?.lane_id === args[0] && (state.lane.config.caldera_agent_jobs?.[args[3]] || state.lane.config.caldera_agent_job)?.job_id === args[2]) {
        state.lane.config.caldera_agent_job = JSON.parse(args[1]);
        state.lane.config.caldera_agent_jobs ||= {};
        state.lane.config.caldera_agent_jobs[args[3]] = state.lane.config.caldera_agent_job;
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
    host: 'LAB-WKS', trusted: true, pid: state.agentPid, server: 'private-server', contact: 'private-contact',
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
    // The install reached the guest, so the Sandcat that registers next is a new
    // process. Pinning agentPidFrozen is how a test says "the install stalled
    // and the only agent on this machine is still the previous one".
    if (!state.agentPidFrozen) state.agentPid += 1;
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
      if (options.result) return options.result(state, args);
      return { exited: true, exitcode: 0, stdout: `CYBERCORE_CALDERA_STARTED:${pawFor(LANE_ID, 901)}`, stderr: '' };
    },
  };
  const service = createService({ query, executor,
    settings: () => ({ serverUrl: 'https://caldera.saguaroscyberhub.org', consoleUrl: 'https://caldera.saguaroscyberhub.org/', client }),
    // Left undefined by nearly every test on purpose: the default directory then
    // runs against the query fake above, whose fall-through rejects any SQL that
    // is not the dispatch re-read, so an environment lookup firing for a lane
    // with no challenge_key shows up as a recorded query rather than passing.
    environments: options.environments,
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
  lane.config.attached_modules = [{ challenge_key: 'forensics-mod', vms: [{ vm_id: 904, template_name: 'win2022' }, { vm_id: 905, name: 'Unknown OS' }] }];
  lane.config.attack_box_vm_id = 906;
  const targets = targetsFor(lane);
  assert.deepEqual(targets.map(t => [t.vm_id, t.platform]), [[901, 'windows'], [903, 'linux'], [904, 'windows'], [905, null], [906, 'linux']]);
  assert.equal(targets.every(t => t.type === 'qemu'), true);
  assert.doesNotMatch(JSON.stringify(targets), /lane-password-private/);
  assert.deepEqual(targetsFor({ config: JSON.stringify({ challenge_vm_id: 907, challenge_key: 'Challenge' }) }).map(t => t.vm_id), [907]);
  // The row cannot say where it came from once the lists are flattened, so the
  // provenance every classroom dialog groups on is stamped on before that.
  assert.deepEqual(targets.map(t => [t.vm_id, t.source, t.slot, t.template_name, t.module_key]), [
    [901, 'environment', null, null, null],
    [903, 'workstation', 0, null, null],
    [904, 'attached', null, 'win2022', 'forensics-mod'],
    [905, 'attached', null, null, 'forensics-mod'],
    [906, 'attack_box', null, null, null],
  ]);
  assert.equal(targets.at(-1).role, 'attacker');
  assert.deepEqual(targetsFor({ config: JSON.stringify({ challenge_vm_id: 907, challenge_key: 'Challenge' }) })
    .map(t => [t.source, t.slot, t.module_key]), [['challenge', null, null]]);
  assert.deepEqual(targetsFor({ config: { workstations: [{ vm_id: 910, name: 'Desk', slot: 2, templateName: 'win11' }] } })
    .map(t => [t.source, t.slot, t.template_name, t.platform]), [['workstation', 2, 'win11', 'windows']]);
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
    assert.equal(queued.status, 'queued');
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
    assert.equal(h.state.sleepCalls.length, CHECK_IN_ATTEMPTS);
    assert.equal(h.state.agentReads, CHECK_IN_ATTEMPTS + 1);
  });
}

test('a stale check-in is retried until a matching fresh check-in arrives', async () => {
  const h = harness({ agents: (state, fresh) => [{ ...fresh(), last_seen: state.agentReads < 3 ? '2026-09-05 19:00:00' : '2026-09-05 20:00:05' }] });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.deepEqual(h.state.sleepCalls, [5000]);
});

// A run that DID report completion is still held to both of its promises. Only
// the never-reported case below is reconciled against the check-in.
for (const [reason, result] of [
  ['nonzero exit', state => ({ exited: true, exitcode: 1, stdout: '', stderr: 'download failed: /agent/' + state.token })],
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

// A detached Windows agent inherits the guest-exec output handles, so QGA never
// reports the exec as exited and pollExecStatus returns its deadline verdict
// with no stdout at all. Reporting that as a failed install is what told
// instructors "Agent installation failed. Timed out" about agents that were
// already beaconing, and the single-lane dialog showed the contradiction.
test('an unfinished guest execution is reconciled by a fresh Caldera check-in', async () => {
  const h = harness({ result: () => ({ exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' }) });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.job().message, 'Agent checked in to Caldera.');
  assert.equal(h.job().exec_incomplete, true);
  assert.equal(h.job().error, undefined);
  assert.match(h.job().warnings.at(-1), /did not report completion within 120 seconds/);
  assert.doesNotMatch(JSON.stringify(h.job()), /Agent installation failed/);
  assert.deepEqual(Object.keys(h.job().agent).sort(), ['group', 'host', 'last_seen', 'paw', 'platform', 'trusted']);
  assert.equal(h.state.agentReads, 2, 'the preflight plus the one check-in that settled it');
  assert.equal(h.state.sleepCalls.length, 0);
  assert.deepEqual(h.state.calls.find(c => c[0] === 'poll'), ['poll', 'actual-node', 901, 4321, 120000]);
  const status = await h.service.status([h.state.lane]);
  assert.equal(status.lanes[0].job.status, 'completed');
  assert.equal(status.lanes[0].targets[0].last_job.status, 'completed');
  assert.equal(status.lanes[0].targets[0].last_job.exec_incomplete, true,
    'the per-machine job line carries it so the dialog can explain the ONE machine it happened to');
});

// The trap under the reconciliation above. pawFor is a hash of (lane, vm) and
// groupFor is per lane, so a Sandcat left running by an EARLIER install keeps
// beaconing under exactly the paw, group and platform this install is waiting
// for, and nothing ever deletes a Caldera agent row. The Windows script only
// stops the old agent after the Defender block and after the download, so an
// install that stalls there finds the previous agent sitting in the very first
// listAgents call -- and reporting that as a completed install tells the
// instructor a machine is done when nothing was installed on it.
test('an unfinished guest execution is not completed by an agent that predates this install', async () => {
  const h = harness({ state: { agentPidFrozen: true },
    result: () => ({ exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' }) });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.equal(h.job().exec_incomplete, true);
  assert.equal(h.job().agent, undefined, 'an unconfirmed install must not record a previous install\'s agent');
  assert.match(h.job().error, /did not report completion within 120 seconds/);
  assert.match(h.job().error, /cannot be told apart from the one an earlier install left running/);
  assert.deepEqual(h.job().prior_agent, { pid: '3100' });
});

test('an unfinished guest execution completes when no agent held the paw before it started', async () => {
  const h = harness({
    // A first install: Caldera has nothing under this paw until the script runs.
    agents: (state, fresh) => (state.script ? [fresh()] : []),
    result: () => ({ exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' }),
  });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.job().prior_agent, undefined);
  assert.equal(h.job().message, 'Agent checked in to Caldera.');
});

// The refusal to guess. If the server's agent rows carry none of the fields that
// separate one registered process from the next, the honest answer is "I cannot
// confirm this", not a success invented from a beacon timestamp the old agent
// moves forward on its own.
test('an unfinished guest execution stays unconfirmed when the agent row has no distinguishing field', async () => {
  const h = harness({ state: { agentOverride: { pid: undefined } },
    result: () => ({ exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' }) });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.deepEqual(h.job().prior_agent, {});
  assert.match(h.job().error, /this installation is unconfirmed/);
});

// The exited path is untouched by any of that: the script reported its own
// completion WITH the startup marker, so the check-in is confirming a fact that
// is already proved and the predicate stays exactly what it was.
test('a run that reported completion still settles on the same check-in predicate', async () => {
  const h = harness({ state: { agentPidFrozen: true } });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.job().exec_incomplete, undefined);
  assert.equal(h.state.agentReads, 2);
});

// job.started_at is stamped BEFORE the guest-agent wait and the 120 s exec
// deadline, so the check-in loop spends what is left of the SAME window that
// currentJob() and the atomic claim police. A fixed twelve iterations against a
// Caldera whose round trip approaches client.js's 20 s ceiling runs the job past
// JOB_TIMEOUT_MS, where currentJob() rewrites this very verdict to the false
// "interrupted or timed out" failure and a retry can steal the VM from the
// installer that is still running.
test('a slow Caldera cannot push the check-in wait past the job timeout window', async () => {
  const h = harness({
    agents: state => { state.clock += 21000; return []; },
    result: () => ({ exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' }),
  });
  await h.start(); await h.run();
  const job = h.job();
  assert.equal(job.status, 'failed');
  assert.ok(h.state.agentReads > 2, 'the loop must still make several attempts while time remains');
  const elapsed = Date.parse(job.finished_at) - Date.parse(job.started_at);
  assert.ok(elapsed < JOB_TIMEOUT_MS, `the job has to reach a terminal state inside its own window, took ${elapsed}ms`);
  h.state.clock = Date.parse(job.started_at) + JOB_TIMEOUT_MS + 1;
  const shown = (await h.service.status([h.state.lane])).lanes[0].job;
  assert.match(shown.error, /did not report completion/, 'the honest verdict must survive the timeout sweep');
  assert.doesNotMatch(shown.error, /interrupted or timed out/);
});

test('an execution that has already spent the whole window still gets one check-in attempt', async () => {
  const h = harness({ agents: () => [],
    result: state => { state.clock += JOB_TIMEOUT_MS; return { exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' }; } });
  await h.start(); await h.run();
  assert.equal(h.state.agentReads, 2, 'the preflight plus one attempt: never zero');
  assert.deepEqual(h.state.sleepCalls, []);
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /no Caldera agent checked in/);
});

// script-executor frames its answer as "Timed out (last exec-status error: ...)"
// and that framing is the whole reason the field exists -- it is how a wedged
// QEMU guest agent identifies itself. Keeping only the last 200 characters threw
// it away for exactly the long Proxmox messages that needed explaining.
test('a long guest-execution error keeps both its framing and its end', async () => {
  const h = harness({ agents: () => [],
    result: state => ({ exited: false, exitcode: -1, stdout: '',
      stderr: `Timed out (last exec-status error: proxmox said ${'q'.repeat(400)} for /agent/${state.token})` }) });
  await h.start(); await h.run();
  assert.match(h.job().error, /Guest execution: Timed out \(last exec-status error: proxmox said q+\.\.\./);
  assert.match(h.job().error, /\.\.\.q* for \/agent\/\[redacted\]\)$/, 'the end of the guest message survives the elision');
  assert.equal(JSON.stringify({ job: h.job(), sql: h.state.sql }).includes(h.state.token), false);
});

test('an unfinished guest execution with no check-in fails naming both facts and redacts the credential', async () => {
  const h = harness({
    agents: () => [],
    result: state => ({ exited: false, exitcode: -1, stdout: '',
      stderr: 'Timed out (last exec-status error: got 500 for /agent/' + state.token + ')' }),
  });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /did not report completion within 120 seconds/);
  assert.match(h.job().error, /no Caldera agent checked in/);
  assert.match(h.job().error, /last exec-status error/, 'a wedged guest agent must still identify itself');
  assert.doesNotMatch(h.job().error, /^Agent installation failed/);
  assert.equal(JSON.stringify({ job: h.job(), sql: h.state.sql }).includes(h.state.token), false);
  assert.equal(h.state.agentReads, CHECK_IN_ATTEMPTS + 1);
  assert.equal(h.state.sleepCalls.length, CHECK_IN_ATTEMPTS);
});

for (const outcome of ['completed', 'guest failed', 'no check-in', 'missing startup marker']) {
  test(`installation notices survive ${outcome} without replacing startup and check-in requirements`, async () => {
    const h = harness({
      agents: outcome === 'no check-in' ? () => [] : undefined,
      result: state => ({ exited: true, exitcode: outcome === 'guest failed' ? 1 : 0,
        stdout: `CYBERCORE_CALDERA_WARNING: Tamper Protection=True; using verified folder exclusion. /agent/${state.token}\r\n`
          + (outcome === 'missing startup marker' ? '' : `CYBERCORE_CALDERA_STARTED:${pawFor(LANE_ID, 901)}`),
        stderr: outcome === 'guest failed' ? 'Download blocked' : '' }),
    });
    await h.start(); await h.run();
    assert.equal(h.job().status, outcome === 'completed' ? 'completed' : 'failed');
    assert.deepEqual(h.job().warnings, ['Tamper Protection=True; using verified folder exclusion. /agent/[redacted]']);
    if (outcome === 'guest failed') assert.match(h.job().error, /Download blocked/);
    if (outcome === 'no check-in') assert.match(h.job().error, /no fresh Caldera check-in/);
    if (outcome === 'missing startup marker') assert.equal(h.state.agentReads, 1);
    const status = await h.service.status([h.state.lane]);
    assert.deepEqual(status.lanes[0].job.warnings, h.job().warnings);
    assert.equal(JSON.stringify({ status, sql: h.state.sql }).includes(h.state.token), false);
  });
}

test('installation notices only accept their stdout prefix and are sanitized, deduplicated and bounded', async () => {
  const h = harness({ result: state => ({ exited: true, exitcode: 0,
    stdout: [
      'Ordinary guest output',
      'not-a-prefix CYBERCORE_CALDERA_WARNING:ignore this',
      'CYBERCORE_CALDERA_WARNING: \t\x00 \x7f',
      'CYBERCORE_CALDERA_WARNING: \tTamper\x00 Protection remains on.\x7f ',
      'CYBERCORE_CALDERA_WARNING:Tamper Protection remains on.',
      'CYBERCORE_CALDERA_WARNING:' + 'x'.repeat(970) + state.token + 'y'.repeat(100),
      ...Array.from({ length: 7 }, (_, index) => `CYBERCORE_CALDERA_WARNING:Notice ${index}`),
      `CYBERCORE_CALDERA_STARTED:${pawFor(LANE_ID, 901)}`,
    ].join('\r\n'), stderr: 'CYBERCORE_CALDERA_WARNING:ignore stderr' }) });
  await h.start(); await h.run();
  assert.equal(h.job().status, 'completed');
  assert.deepEqual(h.job().warnings, [
    'Tamper Protection remains on.', 'x'.repeat(970) + '[redacted]' + 'y'.repeat(20),
    'Notice 0', 'Notice 1', 'Notice 2',
  ]);
  assert.equal(JSON.stringify(h.state.sql).includes(h.state.token), false);
});

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
  h.state.clock += QUEUE_TIMEOUT_MS + 1;
  const replacement = await h.start();
  assert.notEqual(old.job_id, replacement.job_id);
  const callsBeforeOldTask = clone(h.state.calls);
  await h.state.scheduled.shift()();
  assert.deepEqual(h.state.calls, callsBeforeOldTask);
  assert.equal(h.job().job_id, replacement.job_id);
  assert.equal(h.job().status, 'queued');
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
  h.state.clock += QUEUE_TIMEOUT_MS + 1;
  h.state.calderaFailure = true;
  const status = await h.service.status([h.state.lane]);
  assert.equal(status.lanes[0].job.status, 'failed');
  assert.match(status.lanes[0].job.error, /interrupted or timed out/);
  assert.match(status.agents_error, /Could not read Caldera/);
  assert.doesNotMatch(JSON.stringify(status), /private-api-key|lane-password-private|token_hash/);
  assert.equal(h.job().status, 'queued', 'viewing status must not write a replacement job');
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

// The case the classroom dialog exists for: a GOAD lane whose VM rows carry no
// OS at all, whose student identity lives in the runner's user JOIN, and whose
// machine names only mean anything against the authored challenge spec.
const goadEnvironment = () => ({ label: 'GOAD Active Directory', goad: true, lab: 'GOAD-Light', labLabel: 'GOAD Light',
  machines: new Map([
    ['dc01', { name: 'DC01', role: 'dc', os: 'Windows Server 2019', platform: 'windows', infra: false }],
    ['elk', { name: 'elk', role: 'siem', os: 'Ubuntu 22.04', platform: 'linux', infra: true }],
  ]) });

function goadHarness(options = {}) {
  return harness({
    environments: { describeEnvironments: async () => new Map([['goad-ad', goadEnvironment()]]) },
    agents: (state, fresh) => [
      { ...fresh(), paw: pawFor(LANE_ID, 901), platform: 'windows' },
      { ...fresh(), paw: pawFor(LANE_ID, 902), platform: 'linux', host: 'elk', last_seen: '2026-09-05 19:00:00' },
    ],
    ...options,
    state: {
      lane: { lane_id: LANE_ID, name: 'cle-cybr400-inperson-10882', status: 'active', vxlan_id: 10882,
        created_at: '2026-09-01T00:00:00.000Z',
        first_name: 'Ada', last_name: 'Lovelace', student_email: 'ada@example.test',
        config: { course_id: COURSE_ID, internet_enabled: true, goad: { lab: 'GOAD-Light' }, challenge_key: 'goad-ad',
          password: 'lane-password-private', user_email: 'owner-private@example.test',
          vms: [{ vm_id: 901, name: 'DC01' }, { vm_id: 902, name: 'elk' }, { vm_id: 903, name: 'ws01' }] } },
      resources: [901, 902, 903].map(vmid => ({ vmid, node: 'actual-node', type: 'qemu', status: 'running' })),
      ...options.state,
    },
  });
}

test('status names the lane, its student and its GOAD machines from the environment directory', async () => {
  const h = goadHarness();
  await h.start({ vm_id: 901, platform: 'windows' });
  const lane = (await h.service.status([h.state.lane])).lanes[0];
  assert.equal(lane.lane_number, 10882);
  assert.equal(lane.vxlan_id, 10882);
  assert.equal(lane.family, 'cle-cybr400-inperson');
  assert.equal(lane.kind, 'goad');
  assert.equal(lane.created_at, '2026-09-01T00:00:00.000Z');
  assert.deepEqual(lane.student, { name: 'Ada Lovelace', email: 'ada@example.test' });
  assert.deepEqual(lane.environment, { key: 'goad-ad', label: 'GOAD Active Directory', type: 'goad', lab: 'GOAD Light' });
  const [dc, elk, ws] = lane.targets;
  assert.deepEqual([dc.platform, dc.role, dc.os, dc.infra], ['windows', 'dc', 'Windows Server 2019', false]);
  assert.deepEqual([elk.platform, elk.role, elk.os, elk.infra], ['linux', 'siem', 'Ubuntu 22.04', true]);
  assert.deepEqual([dc.machine_key, dc.machine_label, dc.environment_key], ['goad-ad::dc01', 'DC01', 'goad-ad']);
  assert.equal(elk.machine_key, 'goad-ad::elk');
  // ws01 is deployed in the lane but absent from this roster: it keeps the
  // config's own (unknown) answer rather than inheriting a neighbour's.
  assert.deepEqual([ws.platform, ws.os, ws.infra, ws.machine_key], [null, null, false, 'goad-ad::ws01']);
  assert.deepEqual(Object.keys(dc.agent).sort(), ['fresh', 'host', 'last_seen', 'paw', 'platform', 'trusted']);
  assert.equal(dc.agent.fresh, true);
  assert.equal(dc.agent.host, 'LAB-WKS');
  assert.equal(elk.agent.fresh, false, 'a stale beacon is reported as stale, not hidden');
  assert.equal(ws.agent, null, 'an agent belongs to the VM whose paw it carries, not to the lane at large');
  assert.deepEqual(Object.keys(dc.last_job).sort(), ['job_id', 'message', 'platform', 'started_at', 'status']);
  assert.equal(dc.last_job.status, 'queued');
  assert.equal(elk.last_job, null);
  assert.deepEqual(lane.agents.map(agent => [agent.vm_id, agent.fresh]), [[901, true], [902, false]]);
  assert.doesNotMatch(JSON.stringify(lane),
    /lane-password-private|owner-private@example|user_email|token_hash|private-server|private-contact|private-pending|private-executor/);
});

test('a failing environment directory degrades labels without failing the poll or naming an error', async () => {
  const h = goadHarness({ environments: { describeEnvironments: async () => { throw new Error('private-spec-table-failure'); } } });
  const status = await h.service.status([h.state.lane]);
  const lane = status.lanes[0];
  assert.equal(lane.environment.key, 'goad-ad');
  assert.equal(lane.environment.label, null);
  assert.equal(lane.environment.type, 'goad', 'the lane config still classifies the environment');
  assert.equal(lane.targets[0].platform, null, 'without the spec the OS is unknown again, never guessed');
  assert.equal(lane.targets[0].machine_key, 'goad-ad::dc01');
  assert.equal(lane.runnable, true);
  assert.equal(status.power_error, null);
  assert.equal(status.agents_error, null);
  assert.equal(status.environments_error, undefined, 'cosmetic labels must not surface as an inventory error');
  assert.doesNotMatch(JSON.stringify(status), /private-spec-table-failure/);
});

// The UI branches on `infra`: infrastructure machines are listed but never
// auto-selected, and "Only missing agents" selects the non-infra VMs. Deriving
// the flag from the spec roster ALONE therefore aims those actions at the
// machines the flag exists to protect. The synthesised attack box is the
// permanent case -- targetsFor names it 'Attack box' while the roster is keyed
// by spec machine name, so it can never match -- and a lane VM the spec does not
// list is the general one.
test('a machine the spec roster does not name is flagged as infrastructure by its own role', async () => {
  const h = goadHarness();
  h.state.lane.config.vms.push({ vm_id: 904, name: 'sensor-01', role: 'sensor' });
  h.state.lane.config.attack_box_vm_id = 906;
  h.state.resources.push({ vmid: 904, node: 'actual-node', type: 'qemu', status: 'running' },
    { vmid: 906, node: 'actual-node', type: 'qemu', status: 'running' });
  const targets = new Map((await h.service.status([h.state.lane])).lanes[0].targets.map(t => [t.name, t]));
  assert.equal(targets.get('Attack box').infra, true, 'a Sandcat install must never be aimed at the student\'s own attack box');
  assert.equal(targets.get('Attack box').role, 'attacker');
  assert.equal(targets.get('sensor-01').infra, true);
  assert.equal(targets.get('elk').infra, true, 'the roster still answers for the machines it does name');
  assert.equal(targets.get('DC01').infra, false, 'a domain controller is a target, not infrastructure');
  assert.equal(targets.get('ws01').infra, false);
});

test('a spec outage cannot turn the attack box into an auto-selected target', async () => {
  const h = goadHarness({ environments: { describeEnvironments: async () => { throw new Error('private-spec-table-failure'); } } });
  h.state.lane.config.attack_box_vm_id = 906;
  h.state.resources.push({ vmid: 906, node: 'actual-node', type: 'qemu', status: 'running' });
  const targets = new Map((await h.service.status([h.state.lane])).lanes[0].targets.map(t => [t.name, t]));
  assert.equal(targets.get('Attack box').infra, true);
  // THE GAP THIS USED TO PIN IS CLOSED, by exact name rather than by heuristic.
  // The GOAD deployer writes {vm_id, name, proxmox_name, type, node} and no role
  // at all, so with the spec unreadable nothing was left to say elk is the
  // evidence plane -- and it was auto-selected in the Machines step and swept up
  // by "Only missing agents", which installs an implant onto the store the class
  // is graded on reading.
  //
  // The objection recorded here was against a name HEURISTIC, and it was right:
  // `elk-training-vm` is not a SIEM. Exact matching does not carry it. Only the
  // six fixed names the platform assigns itself are treated this way, and the
  // test below pins that a merely similar name is still a target.
  assert.equal(targets.get('elk').infra, true);
  assert.equal(targets.get('elk').role, '', 'nothing in lane config claims a role for it');
});

// specMachines defaults a spec row with no os to the literal string 'Unknown',
// so a spec that names a machine but never says what it runs used to overwrite
// the config's real template name with a word that answers nothing.
test('a spec row with no operating system falls through to the template name, then to null', async () => {
  const h = goadHarness({ environments: { describeEnvironments: async () => new Map([['goad-ad', {
    label: 'GOAD Active Directory', goad: true, machines: new Map([
      ['dc01', { name: 'DC01', role: 'dc', os: 'Unknown', platform: 'windows', infra: false }],
      ['elk', { name: 'elk', role: 'siem', os: 'unknown', platform: 'linux', infra: true }],
    ]) }]]) } });
  h.state.lane.config.vms[0].template_name = 'win2019-goad-base';
  const [dc, elk] = (await h.service.status([h.state.lane])).lanes[0].targets;
  assert.equal(dc.os, 'win2019-goad-base');
  assert.equal(dc.platform, 'windows', 'the roster still answers the platform question it did answer');
  assert.equal(elk.os, null, 'no template either, so the honest answer is that the OS is unknown');
  assert.equal(elk.infra, true);
});

test('a lane without join fields or a challenge key has no student and reads no challenge spec', async () => {
  const h = harness();
  const lane = (await h.service.status([h.state.lane])).lanes[0];
  assert.equal(lane.student, null);
  assert.equal(lane.lane_number, null);
  assert.equal(lane.family, null);
  assert.equal(lane.created_at, null);
  assert.equal(lane.kind, 'course');
  assert.deepEqual(lane.environment, { key: 'lane', label: null, type: 'challenge', lab: null });
  assert.equal(lane.targets[0].machine_key, 'lane::windows-workstation');
  assert.equal(lane.targets[0].infra, false);
  assert.equal(lane.targets[0].agent.fresh, true);
  assert.equal(lane.agents[0].vm_id, 901);
  // This harness uses the real environment directory against the query fake,
  // which records every statement before rejecting an unrecognised one. A spec
  // lookup for a lane that names no challenge would be recorded here even
  // though the directory swallows its own failures.
  assert.deepEqual(h.state.sql, []);
});

function addBatchMachines(h, count) {
  h.state.lane.config.vms = Array.from({ length: count }, (_, i) => ({ vm_id: 901 + i, name: `Machine ${i}`, os: 'windows' }));
  h.state.resources = h.state.lane.config.vms.map(vm => ({ vmid: vm.vm_id, node: 'actual-node', type: 'qemu', status: 'running' }));
  return h.state.lane.config.vms.map(vm => ({ lane_id: LANE_ID, vm_id: vm.vm_id, platform: 'windows' }));
}

test('batch validation completes before any credential claims or guest execution', async () => {
  const h = harness(); const targets = addBatchMachines(h, 2);
  for (const bad of [[], [...targets, targets[0]], [...targets, { ...targets[0], lane_id: COURSE_ID }],
    [...targets, { ...targets[0], vm_id: 999 }], [...targets, { ...targets[0], platform: 'unknown' }], Array(201).fill(targets[0])]) {
    await assert.rejects(h.service.startBatch([h.state.lane], { targets: bad }), error => [400, 404].includes(error.status));
  }
  assert.equal(h.state.sql.length, 0);
  assert.equal(h.state.calls.length, 0);
  assert.equal(h.state.agentReads, 0);
});

test('different VMs claim independent jobs and credentials while duplicate VM claims stay blocked', async () => {
  const h = harness(); const targets = addBatchMachines(h, 2);
  const batch = await h.service.startBatch([h.state.lane], { targets });
  assert.ok(batch.results.every(row => row.job.status === 'queued'));
  assert.equal(Object.keys(h.state.lane.config.caldera_agent_jobs).length, 2);
  assert.equal(h.state.lane.config.caldera_agent_access.tokens.length, 2);
  await assert.rejects(h.start({ vm_id: 901, platform: 'windows' }), { status: 409 });
  const status = await h.service.status([h.state.lane]);
  assert.deepEqual(status.lanes[0].jobs.map(job => job.vm_id).sort(), [901, 902]);
  assert.doesNotMatch(JSON.stringify(batch), /token_hash|\/agent\//);
});

test('batch reports unavailable and busy targets independently and reuses one preflight inventory', async () => {
  const h = harness(); const targets = addBatchMachines(h, 3);
  await h.start({ vm_id: 901, platform: 'windows' });
  h.state.resources[2].status = 'stopped';
  const reads = h.state.agentReads;
  const powerReads = h.state.calls.filter(call => call[0] === 'proxmox').length;
  const result = await h.service.startBatch([h.state.lane], { targets });
  assert.equal(result.results[0].status, 409);
  assert.equal(result.results[1].job.status, 'queued');
  assert.equal(result.results[2].status, 409);
  assert.equal(h.state.agentReads, reads + 1);
  assert.equal(h.state.calls.filter(call => call[0] === 'proxmox').length, powerReads + 1);
});

test('batch dispatch is limited to four VMs and sibling job completion is preserved', async () => {
  let active = 0; let maximum = 0; const release = [];
  const h = harness({
    agents: (state, fresh) => state.lane.config.vms.map(vm => ({ ...fresh(), paw: pawFor(LANE_ID, vm.vm_id) })),
    result: (state, args) => new Promise(resolve => {
      active++; maximum = Math.max(maximum, active);
      release.push(() => { active--; resolve({ exited: true, exitcode: 0, stderr: '', stdout: `CYBERCORE_CALDERA_STARTED:${pawFor(LANE_ID, args[1])}` }); });
    }),
  });
  const targets = addBatchMachines(h, 7);
  await h.service.startBatch([h.state.lane], { targets });
  assert.equal(h.state.scheduled.length, 4);
  while (h.state.scheduled.length) {
    const work = h.state.scheduled.splice(0).map(task => task());
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(active <= 4);
    release.splice(0).forEach(resolve => resolve());
    await Promise.all(work);
  }
  assert.equal(maximum, 4);
  assert.ok(Object.values(h.state.lane.config.caldera_agent_jobs).every(job => job.status === 'completed'));
  assert.equal(h.state.lane.config.caldera_agent_access.tokens.length, 7);
});

/**
 * A Windows install completes on the check-in WITHOUT waiting out the guest
 * execution.
 *
 * QGA reports an exec as exited only once both captured output channels close,
 * and the Windows script launches the agent through Start-Process with output
 * redirection, so the detached agent holds those pipes for its whole life and
 * the exec NEVER reports exited. Before the race, every Windows install paid
 * EXEC_DEADLINE_MS in full: measured on a live cluster at 121 s per batch of
 * four, of which 120 s was spent waiting for something that had already
 * happened. A 180-VM class took an hour and three quarters.
 *
 * The exec here never settles at all, which is the honest model of that.
 */
test('a Windows install finishes on its check-in instead of waiting out the exec', async () => {
  const h = harness({ result: () => new Promise(() => {}) });
  await h.start({ vm_id: 901, platform: 'windows' });
  await h.run();
  assert.equal(h.job().status, 'completed');
  assert.equal(h.job().message, 'Agent checked in to Caldera.');
  // One poll interval, not the 120 s deadline.
  assert.deepEqual(h.state.sleepCalls, [CHECK_IN_INTERVAL_MS]);
  // And the superseded token is pruned on this path too, exactly as it is on
  // the ordinary one -- the retained credential must not outlive its purpose
  // just because the install finished early.
  assert.equal(h.state.lane.config.caldera_agent_access.tokens.length, 1);
});

/**
 * ...but an exec that CAN finish still wins, because its result is what carries
 * the startup marker, the exit code and the installation warnings. On Linux the
 * script redirects to a file rather than an inherited pipe, so the exec really
 * does complete -- and a check-in that beat it would discard all three.
 */
test('an exec that completes still decides the outcome', async () => {
  const h = harness({ result: () => ({ exited: true, exitcode: 1, stdout: '', stderr: 'Defender blocked it' }) });
  await h.start({ vm_id: 901, platform: 'windows' });
  await h.run();
  assert.equal(h.job().status, 'failed');
  assert.match(h.job().error, /Defender blocked it/);
  assert.deepEqual(h.state.sleepCalls, [], 'a settled exec must cost no poll interval at all');
});

/**
 * The name fallback is EXACT, and that boundary is the whole reason it is
 * defensible.
 *
 * A heuristic here would be wrong in the way the earlier comment described: a
 * machine called `elk-training-vm` is a lab box a student is meant to attack,
 * and silently refusing to target it would be its own bug. Only the fixed names
 * the platform assigns itself are treated as infrastructure.
 */
test('a machine whose name merely resembles infrastructure is still a target', async () => {
  const lane = laneFixture();
  lane.config.vms = [{ vm_id: 901, name: 'elk-training-vm' }, { vm_id: 902, name: 'ELK' }];
  const h = harness({ state: { lane } });
  const targets = new Map((await h.service.status([h.state.lane])).lanes[0].targets.map(t => [t.name, t]));
  assert.equal(targets.get('elk-training-vm').infra, false, 'a similar name must not disqualify a real target');
  // Case is not significance: the platform's own name, differently cased.
  assert.equal(targets.get('ELK').infra, true);
});

/**
 * Cancelling queued work.
 *
 * Before this there was no way out of a large batch. The pending list is
 * in-memory, so the only way to stop one was to restart the app -- which drops
 * the queue but leaves every row saying 'queued', and the claim SQL then refuses
 * to re-run any of them until QUEUE_TIMEOUT_MS. Writing a terminal status is
 * what makes the work immediately re-issuable.
 */
test('cancelling drops queued work and frees the VM to be re-queued at once', async () => {
  const h = harness();
  const queued = await h.start({ vm_id: 901, platform: 'windows' });
  assert.equal(queued.status, 'queued');

  const result = await h.service.cancelQueued([h.state.lane], {}, { courseId: COURSE_ID });
  assert.equal(result.lanes, 1);
  // `dropped` is 0 here, and that is the design rather than a miss: pump()
  // eagerly dequeues up to the concurrency limit the moment work is enqueued,
  // so the first four tasks of any batch are already scheduled and never sit in
  // `pending` to be removed. Those are stopped by the status written above,
  // which execute() re-reads before it touches a guest. Dropping is what saves
  // the other 176 of a 180-machine batch, which do queue.
  assert.equal(result.dropped, 0);
  assert.equal(h.job().status, 'cancelled');

  // The dequeued task, had one already been taken, must abort rather than reach
  // a guest. Running the queue now must touch nothing.
  await h.run();
  assert.equal(h.state.calls.some(c => c[0] === 'windows'), false, 'no script may reach a guest after cancelling');

  // And the VM is immediately claimable again -- the property the four-hour
  // queue timeout otherwise denies.
  const again = await h.start({ vm_id: 901, platform: 'windows' });
  assert.equal(again.status, 'queued');
});

test('cancelling leaves a running install alone', async () => {
  const h = harness();
  await h.start({ vm_id: 901, platform: 'windows' });
  h.state.lane.config.caldera_agent_jobs['901'].status = 'running';
  const result = await h.service.cancelQueued([h.state.lane], {}, { courseId: COURSE_ID });
  assert.equal(result.lanes, 0, 'a running job has already put a script in a guest');
  assert.equal(h.job().status, 'running');
});
