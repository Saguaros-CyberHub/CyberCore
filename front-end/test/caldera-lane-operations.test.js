'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createService, operationId } = require('../src/utils/caldera-lane-operations');
const { pawFor, groupFor } = require('../src/utils/caldera-lane-agents');
const { createCalderaClient } = require('../src/incident/caldera/client');
const COURSE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const IDS = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];
const BATCH = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOW = Date.parse('2026-09-06T18:00:00Z');
const clone = value => structuredClone(value);

function harness(options = {}) {
  const lanes = IDS.map((id, i) => ({ lane_id: id, name: `Student ${i + 1}`, status: 'active', config: {
    course_id: COURSE, internet_enabled: true, vms: [{ vm_id: 101 + i, name: 'ws01', os: 'windows' }],
  } }));
  const state = { lanes, scheduled: [], calls: [], ops: new Map(), sources: [], snapshots: [], queries: [], clock: NOW,
    agents: IDS.map((id, i) => ({ paw: pawFor(id, 101 + i), group: groupFor(id), trusted: true, last_seen: new Date(NOW).toISOString(), host: 'ws01', platform: 'windows', secret: 'private' })),
    resources: [101, 102].map(vmid => ({ vmid, type: 'qemu', status: 'running' })) };
  const query = async (sql, args) => {
    state.queries.push([sql, clone(args)]);
    if (sql.startsWith('SELECT')) return { rows: clone(lanes.filter(lane => lane.lane_id === args[0] && lane.config.course_id === args[1])) };
    if (sql.startsWith('WITH locked')) {
      assert.match(sql, /FOR UPDATE/);
      assert.match(sql, /cardinality\(\$1::uuid\[\]\)/);
      assert.match(sql, /NOT \(COALESCE\(config->'caldera_operations'/);
      const [ids, course, batch, recordsJson] = args;
      const selected = lanes.filter(lane => ids.includes(lane.lane_id) && lane.config.course_id === course);
      if (selected.length !== ids.length || selected.some(lane => lane.status !== 'active' || lane.config.caldera_operations?.[batch])) return { rows: [] };
      const records = JSON.parse(recordsJson);
      for (const lane of selected) { lane.config.caldera_operations ||= {}; lane.config.caldera_operations[batch] = records[lane.lane_id]; }
      return { rows: selected.map(lane => ({ lane_id: lane.lane_id })) };
    }
    if (Array.isArray(args[0])) {
      assert.match(sql, /stop_requested/);
      for (const lane of lanes.filter(lane => args[0].includes(lane.lane_id) && lane.config.course_id === args[1])) {
        if (lane.config.caldera_operations?.[args[2]]) lane.config.caldera_operations[args[2]].stop_requested = true;
      }
      return { rows: [] };
    }
    const lane = lanes.find(lane => lane.lane_id === args[0] && lane.config.course_id === args[1]);
    const prior = lane?.config.caldera_operations?.[args[2]];
    if (prior?.operation_id === args[4]) lane.config.caldera_operations[args[2]] = { ...JSON.parse(args[3]), stop_requested: prior.stop_requested };
    return { rows: [] };
  };
  const client = {
    listAgents: async () => { state.calls.push('agents'); return clone(state.agents); },
    listAdversaries: async () => [{ adversary_id: 'discovery', name: 'Discovery', description: 'Two steps', atomic_ordering: ['one', 'two'] }],
    listOperations: async () => [...state.ops.values()].map(clone),
    createAdversary: async body => { state.snapshots.push(clone(body)); return clone(body); },
    createSource: async body => { state.sources.push(clone(body)); return clone(body); },
    createOperation: async body => {
      state.calls.push(['prepare', body.group]);
      if (options.prepareFailure && body.group === groupFor(IDS[1])) throw new Error('private upstream failure');
      const saved = { ...clone(body), id: body.id };
      state.ops.set(body.id, saved);
      if (options.afterPrepare) await options.afterPrepare(state, saved);
      return clone(saved);
    },
    startOperation: async id => {
      assert.equal([...state.ops.values()].filter(op => ['paused', 'running'].includes(op.state)).length, 2, 'both lanes prepare before either starts');
      state.calls.push(['start', id]);
      state.ops.get(id).state = 'running';
      if (options.startFailure) throw new Error('ambiguous upstream timeout');
      return clone(state.ops.get(id));
    },
    getOperation: async id => state.ops.has(id) ? clone(state.ops.get(id)) : { tolerated: true, status: 404 },
    abortOperation: async id => {
      state.calls.push(['stop', id]);
      if (!options.ignoreStop) state.ops.get(id).state = 'finished';
      return clone(state.ops.get(id));
    },
  };
  const service = createService({ query, client: () => client, now: () => state.clock,
    proxmox: async () => clone(state.resources), schedule: fn => state.scheduled.push(fn) });
  const input = { request_id: BATCH, adversary_id: 'discovery', lane_ids: IDS };
  return { state, service, input, launch: (body = input) => service.launch(clone(lanes), body, { courseId: COURSE, label: 'CYBR400' }),
    run: async () => { while (state.scheduled.length) await state.scheduled.shift()(); },
    status: () => service.status(clone(lanes), { courseId: COURSE }),
    stop: () => service.stop(clone(lanes), { batch_id: BATCH, lane_ids: IDS }, { courseId: COURSE }) };
}

test('central client uses the verified v2 summary and state-update contracts', async () => {
  const calls = [];
  const client = createCalderaClient({ baseUrl: 'http://caldera:8888', apiKey: 'test-private-key',
    transport: async request => { calls.push(request); return { status: 200, ok: true, text: '{}' }; } });
  await client.listOperations(); await client.startOperation(BATCH);
  assert.equal(calls[0].method, 'GET');
  assert.equal(calls[0].url, 'http://caldera:8888/api/v2/operations/summary');
  assert.equal(calls[1].method, 'PATCH');
  assert.equal(calls[1].url, `http://caldera:8888/api/v2/operations/${BATCH}`);
  assert.deepEqual(JSON.parse(calls[1].body), { state: 'running' });
  assert.equal(calls[1].headers.KEY, 'test-private-key');
});

test('classroom creates a fixed profile and separate paused lane operations before concurrent release', async () => {
  const h = harness();
  const result = await h.launch();
  assert.deepEqual(result.results.map(row => row.status), ['preparing', 'preparing']);
  assert.equal(h.state.ops.size, 0);
  await h.run();
  assert.equal(h.state.snapshots.length, 1);
  assert.deepEqual(h.state.snapshots[0].atomic_ordering, ['one', 'two']);
  assert.equal(new Set(h.state.sources.map(source => source.id)).size, 2);
  assert.ok(h.state.sources.every(source => !source.facts.length && !source.relationships.length));
  assert.deepEqual([...h.state.ops.values()].map(op => op.group).sort(), IDS.map(groupFor).sort());
  assert.ok([...h.state.ops.values()].every(op => op.state === 'running' && op.adversary.adversary_id === h.state.snapshots[0].adversary_id));
  const timeline = h.state.calls.filter(Array.isArray).map(row => row[0]);
  assert.deepEqual(timeline, ['prepare', 'prepare', 'start', 'start']);
  const status = await h.status();
  assert.equal(status.lanes[0].agents[0].vm_id, 101);
  assert.equal(status.lanes[0].operations[0].status, 'running');
  assert.doesNotMatch(JSON.stringify(status), /private|atomic_ordering|fingerprint/);
});

test('invalid, duplicated and cross-course selections fail before reserving or contacting Caldera', async () => {
  const h = harness();
  for (const body of [{ ...h.input, lane_ids: [] }, { ...h.input, lane_ids: [IDS[0], IDS[0]] },
    { ...h.input, lane_ids: ['cccccccc-cccc-4ccc-8ccc-cccccccccccc'] }, { ...h.input, request_id: 'bad' }]) {
    await assert.rejects(h.launch(body), error => [400, 404].includes(error.status));
  }
  assert.equal(h.state.calls.length, 0);
  assert.equal(h.state.queries.length, 0);
});

for (const condition of ['stale', 'untrusted', 'foreign-group', 'foreign-paw', 'stopped', 'future']) {
  test(`classroom preflight rejects ${condition} agent without creating operations`, async () => {
    const h = harness();
    if (condition === 'stale') h.state.agents[0].last_seen = '2020-01-01T00:00:00Z';
    if (condition === 'future') h.state.agents[0].last_seen = '2030-01-01T00:00:00Z';
    if (condition === 'untrusted') h.state.agents[0].trusted = false;
    if (condition === 'foreign-group') h.state.agents[0].group = 'red';
    if (condition === 'foreign-paw') h.state.agents[0].paw = 'unmanaged-agent';
    if (condition === 'stopped') h.state.resources[0].status = 'stopped';
    await assert.rejects(h.launch(), { status: 409 });
    assert.equal(h.state.queries.length, 0);
    assert.equal(h.state.ops.size, 0);
  });
}

test('a repeated or concurrent request ID never duplicates operation dispatch', async () => {
  const h = harness();
  const results = await Promise.all([h.launch(), h.launch()]);
  assert.equal(h.state.scheduled.length, 1);
  assert.deepEqual(results[0].results.map(row => row.operation_id), results[1].results.map(row => row.operation_id));
  await h.run();
  await h.launch();
  assert.equal(h.state.scheduled.length, 0);
  assert.equal(h.state.ops.size, 2);
  await assert.rejects(h.launch({ ...h.input, adversary_id: 'changed' }), { status: 409 });
});

test('one preparation failure prevents release and stops other prepared operations', async () => {
  const h = harness({ prepareFailure: true });
  await h.launch(); await h.run();
  assert.ok(!h.state.calls.some(row => row[0] === 'start'));
  assert.ok([...h.state.ops.values()].every(op => op.state === 'finished'));
  assert.ok(h.state.lanes.every(lane => lane.config.caldera_operations[BATCH].status === 'failed'));
});

test('stopping before preparation prevents any operation from starting', async () => {
  const h = harness(); await h.launch(); await h.stop(); await h.run();
  assert.ok(!h.state.calls.some(row => row[0] === 'start'));
  assert.equal(h.state.ops.size, 0);
});

test('course reassignment after preparation prevents batch release', async () => {
  const h = harness({ afterPrepare: state => { state.lanes[0].config.course_id = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'; } });
  await h.launch(); await h.run();
  assert.ok(!h.state.calls.some(row => row[0] === 'start'));
  assert.ok([...h.state.ops.values()].every(op => op.state === 'finished'));
});

test('an uncertain launch can be reconciled by status and does not retry dispatch', async () => {
  const h = harness({ startFailure: true }); await h.launch(); await h.run();
  assert.ok(h.state.lanes.every(lane => lane.config.caldera_operations[BATCH].status === 'unknown'));
  assert.ok((await h.status()).lanes.every(lane => lane.operations[0].status === 'running'));
  await h.launch(); assert.equal(h.state.scheduled.length, 0);
});

test('operation history retains every active batch lane beyond the terminal history limit', async () => {
  const h = harness(); await h.launch(); await h.run();
  for (const lane of h.state.lanes) {
    for (let i = 0; i < 25; i++) {
      const id = `${lane.lane_id}-history-${i}`;
      lane.config.caldera_operations[id] = { ...lane.config.caldera_operations[BATCH], batch_id: id,
        operation_id: id, status: 'finished', created_at: new Date(NOW + (i + 1) * 1000).toISOString() };
      h.state.ops.set(id, { id, group: groupFor(lane.lane_id), state: 'finished' });
    }
  }
  const status = await h.status();
  for (const lane of status.lanes) {
    assert.equal(lane.operations.length, 21);
    assert.equal(lane.operations.filter(op => op.status === 'finished').length, 20);
    assert.equal(lane.operations.find(op => op.batch_id === BATCH)?.status, 'running');
  }
});

test('stop only addresses saved operations in selected lanes and confirms terminal state', async () => {
  const h = harness(); await h.launch(); await h.run();
  const result = await h.stop();
  assert.ok(result.results.every(row => row.status === 'stopped'));
  assert.deepEqual(h.state.calls.filter(row => row[0] === 'stop').map(row => row[1]).sort(), IDS.map(id => operationId(BATCH, id)).sort());
});

test('an ignored stop or changed group is reported as unknown rather than stopped', async () => {
  for (const changedGroup of [false, true]) {
    const h = harness({ ignoreStop: true }); await h.launch(); await h.run();
    if (changedGroup) h.state.ops.get(operationId(BATCH, IDS[0])).group = 'another-lane';
    const result = await h.stop();
    assert.equal(result.results[0].status, 'unknown');
    if (changedGroup) assert.ok(!h.state.calls.some(row => row[0] === 'stop' && row[1] === operationId(BATCH, IDS[0])));
  }
});
