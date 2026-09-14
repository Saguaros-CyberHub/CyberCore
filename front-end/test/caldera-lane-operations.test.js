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

// A real stockpile description is multi-line prose with the occasional stray
// control byte, and plenty of them run to several kilobytes.
const MESSY_DESCRIPTION = `Enumerates accounts.${String.fromCharCode(7, 0)}
Second line. ${'x'.repeat(300)}`;

// The shape `GET /api/v2/abilities` returns: `ability_id`, `technique_id` and
// `executors[].platform`. `unused` is in the catalog but referenced by no
// profile and must never reach the wire; the last row has no id at all.
const abilityRows = () => ([
  { ability_id: 'one', name: 'Find domain accounts', tactic: 'discovery', technique_id: 't1087',
    technique_name: 'Account Discovery', description: MESSY_DESCRIPTION,
    executors: [{ platform: 'windows', name: 'psh' }, { platform: 'Windows', name: 'psh' }, { platform: 'linux', name: 'sh' }] },
  { ability_id: 'two', name: 'Copy a file', tactic: 'lateral-movement', technique_id: 'T1021',
    technique_name: 'Remote Services', description: '   \n  ',
    executors: [{ platform: 'windows', name: 'cmd' }] },
  { ability_id: 'unused', name: 'Never selected', tactic: 'discovery', technique_id: 'T1057',
    executors: [{ platform: 'darwin', name: 'sh' }] },
  { name: 'A row with no ability id', technique_id: 'T1057' },
]);

function harness(options = {}) {
  const lanes = IDS.map((id, i) => ({ lane_id: id, name: `Student ${i + 1}`, status: 'active', config: {
    course_id: COURSE, internet_enabled: true, vms: [{ vm_id: 101 + i, name: 'ws01', os: 'windows' }],
  } }));
  const state = { lanes, scheduled: [], calls: [], ops: new Map(), sources: [], snapshots: [], queries: [], clock: NOW,
    abilityReads: 0, abilityFailure: false, proxmoxFailure: false, specReads: [], specGate: null, abilityGate: null,
    agents: IDS.map((id, i) => ({ paw: pawFor(id, 101 + i), group: groupFor(id), trusted: true, last_seen: new Date(NOW).toISOString(), host: 'ws01', platform: 'windows', secret: 'private' })),
    resources: [101, 102].map(vmid => ({ vmid, type: 'qemu', status: 'running' })) };
  const query = async (sql, args) => {
    state.queries.push([sql, clone(args)]);
    // The environment directory's challenge-spec read. `specGate` models the
    // crucible_challenge outage the directory is built to survive: the statement
    // never answers until the test releases it.
    if (/SELECT name, spec FROM/.test(sql)) {
      state.specReads.push(args[0]);
      if (state.specGate) await state.specGate;
      return { rows: [] };
    }
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
    listAdversaries: async () => [
      { adversary_id: 'discovery', name: 'Discovery', description: 'Two steps', atomic_ordering: ['one', 'two'] },
      // Referenced ability the catalog cannot describe, plus a non-string entry
      // some Caldera releases put in atomic_ordering.
      { adversary_id: 'worm', name: 'Worm', description: 'Spreads', atomic_ordering: ['one', 'missing-ability', 7] },
    ],
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
  // Omitted entirely for the "older server" case: a Caldera build without the
  // abilities endpoint must still produce a usable payload.
  if (!options.noAbilities) {
    client.listAbilities = async () => {
      state.abilityReads += 1;
      // A stockpile that answers slowly is the case in-flight dedupe exists for:
      // the browser polls every five seconds and gives up after twenty, so a
      // read that outlives a poll must not turn into a second read.
      if (state.abilityGate) await state.abilityGate;
      if (state.abilityFailure) throw new Error('private catalog failure');
      return options.abilities ? options.abilities(state) : abilityRows();
    };
  }
  const service = createService({ query, client: () => client, now: () => state.clock,
    proxmox: async () => {
      if (state.proxmoxFailure) throw new Error('private proxmox failure');
      return clone(state.resources);
    },
    schedule: fn => state.scheduled.push(fn),
    ...(options.laneFacts ? { laneFacts: options.laneFacts } : {}) });
  const input = { request_id: BATCH, adversary_id: 'discovery', lane_ids: IDS };
  return { state, service, input, launch: (body = input) => service.launch(clone(lanes), body, { courseId: COURSE, label: 'CYBR400' }),
    run: async () => { while (state.scheduled.length) await state.scheduled.shift()(); },
    status: (context = {}) => service.status(clone(lanes), { courseId: COURSE, ...context }),
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
  // A lane whose lab does not resolve seeds nothing, which is exactly what this
  // harness's lanes are. Relationships stay empty on EVERY path: seeding an
  // isAccessibleFrom relationship is an unhandled IndexError inside Caldera
  // 5.3.0's link generation, not a skipped ability. See caldera-lane-facts.js.
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

test('adversary profiles carry ordered ability ids, a deterministic summary and only the selected profile\'s abilities', async () => {
  const h = harness();
  const status = await h.status({ adversaryId: 'discovery' });
  const [discovery, worm] = status.adversaries;
  assert.equal(discovery.adversary_id, 'discovery');
  assert.deepEqual(discovery.ability_ids, ['one', 'two']);
  assert.equal(discovery.ability_count, 2, 'the step count the profile list has always shown survives');
  assert.deepEqual(discovery.summary.tactics, [{ tactic: 'discovery', count: 1 }, { tactic: 'lateral-movement', count: 1 }]);
  assert.deepEqual(discovery.summary.platforms, { windows: 2, linux: 1, darwin: 0 });
  assert.deepEqual(discovery.summary.techniques, ['T1087', 'T1021']);
  assert.equal(discovery.summary.unknown_abilities, 0);
  // A non-string atomic_ordering entry is dropped from the ordered ids but is
  // still counted, so the card cannot silently under-report a profile's length.
  assert.deepEqual(worm.ability_ids, ['one', 'missing-ability']);
  assert.equal(worm.ability_count, 3);
  assert.equal(worm.summary.unknown_abilities, 1);
  assert.deepEqual(worm.summary.tactics, [{ tactic: 'discovery', count: 1 }]);
  assert.deepEqual(Object.keys(status.abilities).sort(), ['one', 'two'], 'an unreferenced catalog row never ships');
  const one = status.abilities.one;
  assert.equal(one.ability_id, 'one');
  assert.equal(one.technique_id, 'T1087', 'the technique id is normalised from the catalog spelling');
  assert.equal(one.technique_name, 'Account Discovery');
  assert.deepEqual(one.platforms, ['linux', 'windows']);
  assert.deepEqual(one.executors, [{ platform: 'windows', name: 'psh' }, { platform: 'linux', name: 'sh' }]);
  assert.equal(one.description.length, 240, 'a long description is capped');
  assert.ok(one.description.startsWith('Enumerates accounts. Second line. xxx'));
  assert.ok(![...one.description].some(ch => ch.codePointAt(0) < 32), 'control characters are replaced, not deleted');
  assert.equal(status.abilities.two.description, null, 'a whitespace-only description is null, not an empty string');
  assert.equal(status.abilities_error, undefined);
});

test('ability detail ships for the selected profile only, and never for the whole stockpile', async () => {
  const h = harness();
  // The default poll, before an instructor has picked anything. Every profile is
  // fully described by its summary; not one step's detail is on the wire.
  const unselected = await h.status();
  assert.deepEqual(unselected.abilities, {});
  assert.equal(unselected.adversaries.length, 2);
  assert.ok(unselected.adversaries.every(adv => adv.summary && adv.ability_ids.length),
    'the picker is still fully described without the catalog behind it');
  assert.equal(unselected.abilities_error, undefined, 'an empty map by request is not an outage');

  // Selecting the second profile ships that profile's steps and NOT the step
  // 'two', which only the first profile runs. The dialog renders detail for one
  // card, so 28 authored profiles must not cost 28 profiles' worth of catalog.
  const worm = await h.status({ adversaryId: 'worm' });
  assert.deepEqual(Object.keys(worm.abilities), ['one']);
  assert.equal(worm.adversaries.find(adv => adv.adversary_id === 'discovery').summary.tactics.length, 2,
    'an unselected profile keeps its summary');

  // A selection Caldera does not have, and shapes Express hands back for a
  // repeated or bracketed query parameter, degrade to summaries rather than
  // failing the poll.
  for (const adversaryId of ['no-such-profile', ['discovery'], { id: 'discovery' }, '', 'x'.repeat(400)]) {
    assert.deepEqual((await h.status({ adversaryId })).abilities, {}, `${JSON.stringify(adversaryId)} selects nothing`);
  }
});

test('every upstream string that reaches the wire is bounded, in the summary as well as the catalog', async () => {
  // One plugin-authored row with no bounds on it measured at 51 KB by itself,
  // and its tactic was copied again into the summary of every profile that
  // referenced it.
  const h = harness({ abilities: () => [{
    ability_id: 'one', name: 'N'.repeat(5000), tactic: 'T'.repeat(5000), technique_id: 'T1087',
    technique_name: 'W'.repeat(5000), description: 'D'.repeat(5000),
    platforms: Array.from({ length: 400 }, (_, i) => `platform-${i}`).concat('windows'),
    executors: Array.from({ length: 40 }, (_, i) => ({ platform: 'windows', name: `exec-${i}-${'E'.repeat(200)}` })),
  }] });
  const wire = await h.status({ adversaryId: 'discovery' });
  const one = wire.abilities.one;
  assert.equal(one.name.length, 160);
  assert.equal(one.tactic.length, 60);
  assert.equal(one.technique_name.length, 160);
  assert.equal(one.description.length, 240);
  assert.equal(one.platforms.length, 12);
  assert.equal(one.executors.length, 8);
  assert.ok(one.executors.every(executor => executor.name.length <= 32));
  assert.equal(wire.adversaries[0].summary.tactics[0].tactic.length, 60,
    'the summary carries the same bounded tactic, not the raw one, for every profile');
  // The ceiling for one entry, with every cap simultaneously saturated by data
  // no real stockpile produces: 240 description + 160 name + 160 technique name
  // + 60 tactic + 40 technique id + 200 id + 12 platforms + 8 executors. A
  // measured classroom row is around 690 bytes.
  assert.ok(Buffer.byteLength(JSON.stringify(one)) < 2000, 'one entry cannot exceed its stated budget');
  assert.deepEqual(wire.adversaries[0].summary.platforms, { windows: 1, linux: 0, darwin: 0 },
    'windows is counted from the full platform list even though the wire copy is capped');
});

test('a custom ability with no technique id is described, not reported as missing from the catalog', async () => {
  // Custom and plugin-authored abilities commonly carry an empty technique_id.
  // normalizeAbility refuses those rows — its contract is that a technique id is
  // what scoring matches on — so they used to fall out of the catalog entirely
  // and the card told the instructor an ability it can see was "not in the
  // ability catalog".
  const h = harness({ abilities: () => [
    { ability_id: 'one', technique_id: '', tactic: 'discovery', name: 'Custom classroom step',
      description: 'Written by the instructor.', executors: [{ platform: 'windows', name: 'psh' }] },
    { ability_id: 'two', technique_id: null, name: 'Another custom step' },
    { name: 'No id at all', technique_id: '' },
  ] });
  const status = await h.status({ adversaryId: 'discovery' });
  assert.deepEqual(Object.keys(status.abilities).sort(), ['one', 'two']);
  assert.equal(status.abilities.one.technique_id, null, 'the placeholder used to reuse the normaliser never ships');
  assert.equal(status.abilities.one.name, 'Custom classroom step');
  assert.equal(status.abilities.one.tactic, 'discovery');
  assert.deepEqual(status.abilities.one.platforms, ['windows']);
  assert.deepEqual(status.abilities.one.executors, [{ platform: 'windows', name: 'psh' }]);
  assert.equal(status.abilities.two.name, 'Another custom step');
  const [discovery, worm] = status.adversaries;
  assert.equal(discovery.summary.unknown_abilities, 0, 'unknown means "not in the catalog", nothing else');
  assert.deepEqual(discovery.summary.tactics, [{ tactic: 'discovery', count: 1 }]);
  assert.deepEqual(discovery.summary.techniques, [], 'a null technique is absent, never a null entry in the list');
  assert.doesNotMatch(JSON.stringify(status), /no-technique/, 'the placeholder technique never reaches the wire');
  assert.equal(worm.summary.unknown_abilities, 1, 'an id the catalog really does not hold is still counted');
});

test('the ability catalog is read once a minute, not once a poll', async () => {
  const h = harness();
  await h.status();
  await h.status();
  assert.equal(h.state.abilityReads, 1, 'a second poll inside the TTL reuses the memo');
  h.state.clock += 61 * 1000;
  await h.status();
  assert.equal(h.state.abilityReads, 2, 'an expired memo entry is refetched');
});

test('a failing ability catalog degrades to the last good copy without failing the poll', async () => {
  const h = harness();
  h.state.abilityFailure = true;
  const first = await h.status({ adversaryId: 'discovery' });
  assert.match(first.abilities_error, /Could not read the Caldera ability catalog/);
  assert.deepEqual(first.abilities, {});
  assert.equal(first.adversaries[0].summary, null, 'no catalog means no summary, never a wrong-looking zero');
  assert.equal(first.adversaries[0].ability_count, 2);
  assert.deepEqual(first.adversaries[0].ability_ids, ['one', 'two']);
  assert.equal(first.lanes.length, 2, 'the rest of the poll is unaffected');
  assert.doesNotMatch(JSON.stringify(first), /private/);

  h.state.abilityFailure = false;
  h.state.clock += 31 * 1000;
  const good = await h.status({ adversaryId: 'discovery' });
  assert.equal(good.abilities_error, undefined);
  assert.equal(good.abilities.one.name, 'Find domain accounts');

  h.state.clock += 61 * 1000;
  h.state.abilityFailure = true;
  const stale = await h.status({ adversaryId: 'discovery' });
  assert.match(stale.abilities_error, /Ability details are unavailable/);
  assert.equal(stale.abilities.one.name, 'Find domain accounts', 'the last good catalog is still served');
  assert.equal(stale.adversaries[0].summary.unknown_abilities, 0);
});

test('concurrent polls share one catalog read instead of each starting their own', async () => {
  const h = harness();
  // A stockpile that has not answered yet. Four dialogs (or one dialog whose
  // twenty-second client timeout outlives its five-second poll) used to put four
  // reads in flight at once, adding load to the server that was already slow.
  let release;
  h.state.abilityGate = new Promise(resolve => { release = resolve; });
  const polls = [h.status({ adversaryId: 'discovery' }), h.status({ adversaryId: 'discovery' }),
    h.status({ adversaryId: 'discovery' }), h.status({ adversaryId: 'discovery' })];
  release();
  h.state.abilityGate = null;
  const results = await Promise.all(polls);
  assert.equal(h.state.abilityReads, 1, 'four concurrent polls, one stockpile read');
  assert.ok(results.every(status => status.abilities.one.name === 'Find domain accounts'),
    'every waiting poll is answered from the one read');
  assert.ok(results.every(status => status.abilities_error === undefined));
});

test('a failing catalog is retried on an interval, not on every five-second poll', async () => {
  const h = harness();
  h.state.abilityFailure = true;
  for (let i = 0; i < 5; i++) {
    const status = await h.status({ adversaryId: 'discovery' });
    assert.match(status.abilities_error, /Ability details are unavailable/,
      'a suppressed retry looks exactly like the outage that caused it');
    h.state.clock += 5 * 1000;
  }
  assert.equal(h.state.abilityReads, 1, 'five polls inside the retry interval cost one read');
  h.state.clock += 10 * 1000;
  await h.status({ adversaryId: 'discovery' });
  assert.equal(h.state.abilityReads, 2, 'the interval expires and the catalog is tried again');
  h.state.abilityFailure = false;
  h.state.clock += 31 * 1000;
  const recovered = await h.status({ adversaryId: 'discovery' });
  assert.equal(h.state.abilityReads, 3);
  assert.equal(recovered.abilities_error, undefined, 'a recovered catalog is served on the next attempt');
  assert.equal(recovered.abilities.one.name, 'Find domain accounts');
});

test('challenge labels are resolved alongside the Caldera reads, not before them', async () => {
  const h = harness();
  // A lane that names a challenge, and a challenge table that does not answer.
  // The directory's own deadline is 1.5 s and its miss TTL is 10 s, so awaiting
  // it first charged every tenth poll that full deadline on top of Caldera's own
  // latency for labels that are cosmetic.
  h.state.lanes[0].config.challenge_key = 'goad-x';
  let release;
  h.state.specGate = new Promise(resolve => { release = resolve; });
  const poll = h.status({ adversaryId: 'discovery' });
  // status() runs synchronously up to its one combined await, so the Caldera
  // read is already issued here while the challenge query is still hanging.
  assert.ok(h.state.calls.includes('agents'), 'Caldera is contacted without waiting for the challenge table');
  assert.deepEqual(h.state.specReads, ['goad-x']);
  release();
  h.state.specGate = null;
  const status = await poll;
  assert.equal(status.lanes.length, 2, 'an unanswerable spec costs labels, not the poll');
  assert.equal(status.lanes[0].environment.key, 'goad-x');
  assert.equal(status.lanes[0].environment.label, null);
  assert.equal(status.abilities.one.name, 'Find domain accounts');
});

test('a catalog that is not a list is an outage, not an empty stockpile', async () => {
  const h = harness({ abilities: () => null });
  const status = await h.status();
  assert.match(status.abilities_error, /ability catalog/);
  assert.equal(status.adversaries[0].summary, null);
  assert.deepEqual(status.abilities, {});
});

test('a Caldera server without an ability endpoint still returns a well-formed payload', async () => {
  const h = harness({ noAbilities: true });
  const status = await h.status();
  assert.equal(status.abilities_error, undefined, 'a missing endpoint is a capability gap, not an outage');
  assert.deepEqual(status.abilities, {});
  assert.equal(status.adversaries[0].summary, null);
  assert.equal(status.adversaries[0].ability_count, 2);
  assert.deepEqual(status.adversaries[0].ability_ids, ['one', 'two']);
  assert.equal(status.lanes.length, 2);
  assert.equal(status.lanes[0].targets.length, 1);
});

test('every lane names its machines and says why it is launchable', async () => {
  const h = harness();
  const status = await h.status();
  const lane = status.lanes[0];
  assert.equal(lane.lane_status, 'active');
  assert.equal(lane.lifecycle_eligible, true);
  assert.equal(lane.retained_after_failure, false);
  assert.equal(lane.internet_enabled, true);
  assert.equal(lane.runnable, true);
  assert.equal(lane.kind, 'course');
  assert.equal(lane.student, null, 'this harness hands over rows without the cybercore_user join');
  assert.equal(lane.lane_number, null, 'a lane name with no -<vxlan> suffix has no number');
  assert.deepEqual(lane.environment, { key: 'lane', label: null, type: 'challenge', lab: null });
  assert.deepEqual(lane.targets.map(vm => [vm.vm_id, vm.machine_key, vm.power_state, vm.platform]),
    [[101, 'lane::ws01', 'running', 'windows']]);
  assert.equal(lane.targets[0].agent.fresh, true);
  assert.equal(lane.targets[0].agent.host, 'ws01');
  assert.equal(lane.targets[0].last_job, undefined, 'install job history belongs to the other dialog');
  assert.equal(lane.agents[0].machine_key, 'lane::ws01', 'a check-in names the machine it came from');
  assert.equal(h.state.queries.length, 0, 'a lane with no challenge key reads no challenge spec');
});

test('a lane that is up with nothing checked in is distinguishable from one that is off', async () => {
  const h = harness();
  h.state.agents[0].last_seen = '2020-01-01T00:00:00Z';
  h.state.lanes[1].config.internet_enabled = false;
  const status = await h.status();
  const [stale, offline] = status.lanes;
  assert.equal(stale.runnable, false);
  assert.equal(stale.lifecycle_eligible, true, 'the lane is running; nothing has checked in');
  assert.equal(stale.internet_enabled, true);
  assert.deepEqual(stale.agents, []);
  assert.equal(stale.targets[0].agent.fresh, false, 'the old check-in is still reported, just not as fresh');
  assert.equal(offline.runnable, false);
  assert.equal(offline.lifecycle_eligible, true);
  assert.equal(offline.internet_enabled, false);
  assert.equal(offline.agents.length, 1, 'internet, not the agent, is what makes this lane unlaunchable');
});

test('a lane retained after a deployment failure is eligible and says so', async () => {
  const h = harness();
  h.state.lanes[0].status = 'suspended';
  h.state.lanes[0].config.error = 'private deployment failure details';
  const lane = (await h.status()).lanes[0];
  assert.equal(lane.lane_status, 'suspended');
  assert.equal(lane.lifecycle_eligible, true);
  assert.equal(lane.retained_after_failure, true);
  assert.doesNotMatch(JSON.stringify(lane), /private/, 'the failure text itself never reaches the dialog');
});

test('a failed inventory read still reports every machine, with power unknown', async () => {
  const h = harness();
  h.state.proxmoxFailure = true;
  const status = await h.status();
  assert.match(status.agents_error, /Could not verify online agents and VM power/);
  assert.equal(status.lanes.length, 2);
  const lane = status.lanes[0];
  assert.equal(lane.runnable, false);
  assert.deepEqual(lane.agents, []);
  assert.deepEqual(lane.targets.map(vm => [vm.vm_id, vm.machine_key, vm.power_state, vm.runnable, vm.agent]),
    [[101, 'lane::ws01', 'unknown', false, null]]);
  assert.equal(lane.lifecycle_eligible, true, 'a Proxmox outage is not a lane lifecycle fact');
  assert.doesNotMatch(JSON.stringify(status), /private/);
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

/**
 * The seeded source is the whole reason an ability parameterised by a remote
 * host has anywhere to point. Before this, every classroom operation got
 * `facts: []` and any such ability was SKIPPED while the operation still
 * reported success — a silent hole in the exercise.
 *
 * The source stays per lane and per batch, so seeding buys targets without
 * reopening the cross-class leak the empty source was preventing.
 */
test('a resolvable lab seeds its own estate into that lane\'s fact source', async () => {
  const h = harness({
    laneFacts: (lane, config, described) => ({
      facts: [{ trait: 'remote.host.name', value: `HOST-${lane.lane_id.slice(0, 4)}`, score: 1 }],
      hosts: [{ roster_name: 'DC01', hostname: `HOST-${lane.lane_id.slice(0, 4)}`, fqdn: '', ip: null }],
      excluded: [], warnings: [],
    }),
  });
  await h.launch();
  await h.run();
  assert.equal(h.state.sources.length, 2);
  // Every source carries facts, and no two lanes carry the same ones.
  assert.ok(h.state.sources.every(source => source.facts.length === 1));
  assert.equal(new Set(h.state.sources.map(source => source.facts[0].value)).size, 2);
  // Relationships stay empty even when facts are seeded.
  assert.ok(h.state.sources.every(source => !source.relationships.length));
  // The operation still binds to the source it was given.
  assert.ok([...h.state.ops.values()].every(op => h.state.sources.some(source => source.id === op.source.id)));
});

/**
 * Tradecraft is refused BEFORE anything exists in Caldera. The same bad value
 * accepted here would fail at createOperation, which aborts the prepared batch
 * for every lane — one instructor typo costing the whole class its exercise.
 */
test('an unusable obfuscator or jitter is refused before anything is created', async () => {
  for (const bad of [{ obfuscator: 'rot13' }, { obfuscator: '' }, { jitter: '9/2' },
    { jitter: 'fast' }, { jitter: '0/0' }, { jitter: '1/0' }]) {
    const h = harness();
    await assert.rejects(() => h.launch({ ...h.input, ...bad }),
      err => err.status === 400, `${JSON.stringify(bad)} was accepted`);
    assert.equal(h.state.snapshots.length, 0, `${JSON.stringify(bad)} created an adversary anyway`);
    assert.equal(h.state.sources.length, 0, `${JSON.stringify(bad)} created a fact source anyway`);
    assert.equal(h.state.ops.size, 0, `${JSON.stringify(bad)} created an operation anyway`);
  }
});

test('the operation carries the chosen tradecraft, and a safe default otherwise', async () => {
  const fallback = harness();
  await fallback.launch();
  await fallback.run();
  // plain-text is the deliberate default: an obfuscator name Caldera does not
  // have fails createOperation, and these names have never been exercised
  // against a live server from this repository.
  assert.ok([...fallback.state.ops.values()].every(op => op.obfuscator === 'plain-text' && op.jitter === '4/16'));

  const chosen = harness();
  await chosen.launch({ ...chosen.input, obfuscator: 'base64', jitter: '30/120' });
  await chosen.run();
  assert.ok([...chosen.state.ops.values()].every(op => op.obfuscator === 'base64' && op.jitter === '30/120'));
});

/**
 * Seeding is a realism upgrade, never a new precondition for running a class. A
 * seeder that throws must degrade the lane to the unseeded source it would have
 * had anyway, not fail the launch for a whole section.
 */
test('a seeder that throws degrades to an unseeded source and still launches', async () => {
  const h = harness({ laneFacts: () => { throw new Error('sidecar unreadable'); } });
  const result = await h.launch();
  assert.deepEqual(result.results.map(row => row.status), ['preparing', 'preparing']);
  await h.run();
  assert.equal(h.state.sources.length, 2);
  assert.ok(h.state.sources.every(source => !source.facts.length));
  assert.ok([...h.state.ops.values()].every(op => op.state === 'running'));
});
