/**
 * caldera-engine.test.js — the E9 engine adapter, without a Caldera server.
 *
 * ############################################################################
 * # THERE IS NO CALDERA SERVER ANYWHERE AND NOTHING HERE PROVES ONE WORKS.   #
 * #                                                                          #
 * # Every request in this file is answered by a fake defined at the bottom.  #
 * # It answers with the shapes upstream's v2 API is DOCUMENTED to produce,   #
 * # which nobody in this repository has ever observed. If the real API       #
 * # differs, these tests stay green and the adapter is still wrong — and the #
 * # honest scope of that risk is exactly one file, because                   #
 * # src/incident/caldera/client.js is the only place a socket is opened.     #
 * #                                                                          #
 * # What these tests DO prove is everything on this side of that seam: the   #
 * # contract's full method set, a whole run lifecycle, that a failed link    #
 * # fails the target instead of completing silently, that engine_ref round-  #
 * # trips through jsonb, and that readTargetState returns the SAME object    #
 * # src/incident/worker.js already consumes — which is what makes the engine #
 * # abstraction real rather than aspirational.                               #
 * ############################################################################
 *
 * Run: node --test front-end/test/caldera-engine.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const engines = require('../src/incident/engines');
const calderaEngine = require('../src/incident/engines/caldera');
const { createCalderaClient, CalderaError } = require('../src/incident/caldera/client');

const INCIDENT = path.join(__dirname, '..', 'src', 'incident');

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RUN_ID = '11111111-2222-4333-8444-555555555555';

/**
 * A catalog in the "fetched from a server" spelling (ability_id/technique_id),
 * not the stockpile-YAML one. adversary.js accepts both; using the HTTP spelling
 * here means these tests exercise the path production will actually take.
 */
const ABILITIES = [
  { ability_id: 'ab-phish', technique_id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access', platforms: ['windows'] },
  { ability_id: 'ab-psh', technique_id: 'T1059.001', name: 'PowerShell', tactic: 'execution', platforms: ['windows'] },
  { ability_id: 'ab-cred', technique_id: 'T1003.001', name: 'LSASS Memory', tactic: 'credential-access', platforms: ['windows'] },
  { ability_id: 'ab-linux', technique_id: 'T1059.004', name: 'Unix Shell', tactic: 'execution', platforms: ['linux'] },
];

/** A client profile's threat scenario, in the shape adversary.js compiles. */
function scenarioFixture() {
  return {
    scenario_id: 'TS-001',
    name: 'Invoice fraud into credential theft',
    type: 'ransomware',
    attack_path: [
      { step: 1, action: 'Sends a fake invoice', target: 'WKS-01', technique: 'T1566.001', detection_opportunity: 'attachment in mail logs' },
      { step: 2, action: 'Runs an encoded command', target: 'WKS-01', technique: 'T1059.001', detection_opportunity: 'powershell 4104' },
      { step: 3, action: 'Dumps LSASS', target: 'WKS-01', technique: 'T1003.001', detection_opportunity: 'sysmon 10 against lsass' },
      // Deliberately unmappable against ABILITIES, so the lossy path is live in
      // every lifecycle test rather than only in its own.
      { step: 4, action: 'Exfiltrates over DNS', target: 'DC-01', technique: 'T1048.003', detection_opportunity: 'dns volume' },
    ],
  };
}

function runRow(over) {
  return {
    run_id: RUN_ID,
    engine: 'caldera',
    mode: 'scenario',
    scenario_id: 'TS-001',
    scenario_ref: { profile_id: 'p-1', engagement_id: 'e-1', scenario_id: 'TS-001', name: 'Invoice fraud' },
    duration_seconds: 1800,
    ...(over || {}),
  };
}

function targetRow(over) {
  return {
    target_id: 't-1',
    run_id: RUN_ID,
    lane_id: 'lane-1',
    status: 'dispatching',
    event_count: null,
    caldera_url: 'http://100.100.60.9:8888',
    engine_ref: null,
    ...(over || {}),
  };
}

/** An engine wired to one fake server. Real client, real adapter, fake socket. */
function engineOn(server, over) {
  return calderaEngine.createCalderaEngine({
    settings: { api_key: 'test-red-key', ...(over || {}) },
    createClient: (o) => createCalderaClient({ ...o, transport: server.transport }),
    now: () => server.nowMs,
  });
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

test('the caldera adapter satisfies the engine contract in full', () => {
  assert.strictEqual(calderaEngine.key, 'caldera');
  for (const m of engines.ENGINE_METHODS) {
    assert.strictEqual(typeof calderaEngine[m], 'function',
      `the caldera adapter must implement ${m}()`);
  }
  // ENGINE_METHODS is exactly what registerEngine() checks, so passing this loop
  // is passing that check. It is asserted this way rather than by calling
  // registerEngine(), which would write 'caldera' into the process-wide REGISTRY
  // and make the very next test — that engineFor('caldera') still refuses —
  // depend on test ordering.
});

test('caldera is implemented and still NOT registered — engineFor() keeps refusing it', () => {
  // The E9 decision, asserted rather than described. registeredEngines() exists
  // to feed an engine picker; registering here would make a C2 that has never
  // spoken to a real server selectable the moment a console grows one, with no
  // further edit and no review. test/incident-engine-locality.test.js asserts
  // the same thing from the other direction.
  assert.ok(!engines.registeredEngines().includes('caldera'),
    'caldera must not register until the E8 cluster gate has passed');
  assert.throws(() => engines.engineFor('caldera'), (err) => {
    assert.strictEqual(err.code, 'UNKNOWN_INCIDENT_ENGINE');
    return true;
  });
  // ...but it IS reachable by name, so a dispatcher can be wired without a
  // registry change turning it into a UI option in the same commit.
  assert.strictEqual(engines.calderaEngineUnregistered.key, 'caldera');
});

test('supportsMode is the exact complement of the log generator: scenario only', () => {
  assert.strictEqual(calderaEngine.supportsMode('scenario'), true);
  for (const mode of ['technique', 'tactic', 'chain', '', null, undefined, 'SCENARIO']) {
    assert.strictEqual(calderaEngine.supportsMode(mode), false,
      `${JSON.stringify(mode)} must not be claimed: technique/tactic/chain are cc-emit's catalog`);
  }
});

// ---------------------------------------------------------------------------
// resolveSelection
// ---------------------------------------------------------------------------

test('resolveSelection validates the scenario columns and derives a CAP, not a plan', () => {
  const sel = calderaEngine.resolveSelection(runRow());
  assert.strictEqual(sel.mode, 'scenario');
  assert.strictEqual(sel.arg, 'TS-001');
  assert.strictEqual(sel.scenarioId, 'TS-001');
  assert.strictEqual(sel.durationSeconds, 1800);
  // 20% headroom plus two minutes, the same shape runner.resolveSelection uses.
  assert.strictEqual(sel.capSeconds, Math.ceil(1800 * 1.2) + 120);
  assert.deepStrictEqual(sel.scenarioRef.profile_id, 'p-1');
});

test('resolveSelection throws rather than sanitizes — these selections become real commands', () => {
  assert.throws(() => calderaEngine.resolveSelection(runRow({ mode: 'technique', scenario_id: null })),
    /unsupported mode/);
  for (const bad of ['', null, 'TS 001', 'TS-001;rm -rf /', '../etc/passwd', 'x'.repeat(65)]) {
    assert.throws(() => calderaEngine.resolveSelection(runRow({ scenario_id: bad })),
      /invalid scenario id/, `scenario id ${JSON.stringify(bad)} must be refused`);
  }
  for (const bad of [null, 0, 29, 28801, 12.5, 'later', {}]) {
    assert.throws(() => calderaEngine.resolveSelection(runRow({ duration_seconds: bad })),
      /duration_seconds/, `duration ${JSON.stringify(bad)} must be refused`);
  }
  // A NUMERIC STRING IS ACCEPTED, matching runner.assertInt exactly — it does
  // Number(value) then Number.isInteger. Two engines disagreeing about whether
  // '1800' is a duration would be a far worse trap than either answer, so this
  // pins the agreement rather than inventing a stricter rule here.
  assert.strictEqual(calderaEngine.resolveSelection(runRow({ duration_seconds: '1800' })).durationSeconds, 1800);
});

test('resolveSelection parses scenario_ref whether jsonb arrived as an object or a string', () => {
  const asString = calderaEngine.resolveSelection(runRow({
    scenario_ref: JSON.stringify({ profile_id: 'p-9' }),
  }));
  assert.strictEqual(asString.scenarioRef.profile_id, 'p-9');
  const asNull = calderaEngine.resolveSelection(runRow({ scenario_ref: null }));
  assert.strictEqual(asNull.scenarioRef, null);
});

// ---------------------------------------------------------------------------
// compileAnswerKey
// ---------------------------------------------------------------------------

test('compileAnswerKey with a catalog produces answer-key.js\'s shape, so scoring.js needs no change', () => {
  const sel = { ...calderaEngine.resolveSelection(runRow()), scenario: scenarioFixture(), abilities: ABILITIES };
  const key = calderaEngine.compileAnswerKey(runRow(), sel);

  // Every field src/incident/answer-key.js emits, present.
  for (const f of ['version', 'engine', 'run_id', 'techniques', 'iocs', 'timeline',
                   'floor_techniques', 'floor_values', 'floor_truncated', 'totals']) {
    assert.ok(Object.prototype.hasOwnProperty.call(key, f), `answer key is missing ${f}`);
  }
  assert.strictEqual(key.engine, 'caldera');
  assert.strictEqual(key.run_id, RUN_ID);
  assert.deepStrictEqual(key.techniques.map((t) => t.id).sort(),
    ['T1003.001', 'T1059.001', 'T1566.001']);
  // Empty BY DEFINITION for this engine, not by omission: a Caldera run has no
  // compiled plan and no benign floor to difference against.
  assert.deepStrictEqual(key.iocs, []);
  assert.strictEqual(key.totals.events, null, 'null, not 0 — the count is not predictable');
  // The unmapped step is REPORTED, never silently dropped. adversary.js's header
  // is explicit that a silent drop grades a correct student as having missed it.
  assert.ok(key.unmapped_techniques.includes('T1048.003'));
  assert.ok(key.warnings.some((w) => w.includes('T1048.003')));
});

test('compileAnswerKey without a catalog returns the empty-but-shaped key and names prepare()', () => {
  const key = calderaEngine.compileAnswerKey(runRow(), calderaEngine.resolveSelection(runRow()));
  assert.strictEqual(key.engine, 'caldera');
  assert.deepStrictEqual(key.techniques, []);
  assert.deepStrictEqual(key.iocs, []);
  assert.match(key.reason, /prepare\(\)/);
  // scoring.js reads a key with no techniques and no iocs as "not auto-graded".
  // That is the honest answer at launch; a guessed key mis-grades silently.
  assert.strictEqual(key.totals.techniques, 0);
});

// ---------------------------------------------------------------------------
// The lifecycle, against a fake transport
// ---------------------------------------------------------------------------

test('a whole run lifecycle: prepare -> dispatch -> poll -> finish', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const target = targetRow();

  // ── prepare ──────────────────────────────────────────────────────────────
  const prepared = await engine.prepare({ run, targets: [target], resolved: sel });
  assert.deepStrictEqual(prepared.adversary.atomic_ordering, ['ab-phish', 'ab-psh', 'ab-cred']);
  assert.strictEqual(prepared.catalogFrom, 'http://100.100.60.9:8888');
  assert.strictEqual(prepared.abilityCount, ABILITIES.length);
  assert.strictEqual(prepared.answerKey.engine, 'caldera');

  // Safe to call twice — the contract says a retry re-enters. Same adversary id,
  // because it is a uuidv5 over the scenario and the ordered ability list.
  const again = await engine.prepare({ run, targets: [target], resolved: sel });
  assert.strictEqual(again.adversary.adversary_id, prepared.adversary.adversary_id);

  // ── dispatch ─────────────────────────────────────────────────────────────
  const dispatch = await engine.dispatchTarget({ run, target, resolved: sel, prepared });
  assert.strictEqual(dispatch.dispatched, true);
  assert.strictEqual(dispatch.engineRef.engine, 'caldera');
  assert.strictEqual(dispatch.engineRef.operation_id, 'op-1');
  assert.strictEqual(dispatch.engineRef.paw, 'paw-aaa');
  assert.strictEqual(dispatch.engineRef.server, 'http://100.100.60.9:8888');
  assert.strictEqual(dispatch.engineRef.adversary_id, prepared.adversary.adversary_id);
  assert.ok(server.state.adversaries.some((a) => a.adversary_id === prepared.adversary.adversary_id));

  // The operation name carries the run id and NO scenario prose. The compiler
  // strips `action`/`detection_opportunity` by construction; leaking the same
  // text through an operation name would walk straight around that.
  const created = server.state.operations.get('op-1');
  assert.ok(created.name.includes(RUN_ID));
  assert.ok(!/invoice|LSASS|Exfiltrates/i.test(created.name));

  // ── poll: scheduled ──────────────────────────────────────────────────────
  const live = targetRow({ status: 'scheduled', engine_ref: dispatch.engineRef });
  let state = await engine.readTargetState({ run, target: live });
  assert.strictEqual(state.phase, 'scheduled');
  assert.strictEqual(state.lines, 0);

  // ── poll: running ────────────────────────────────────────────────────────
  server.state.links.set('op-1', [
    { id: 'l1', paw: 'paw-aaa', ability: { ability_id: 'ab-phish' }, status: 0, finish: '2026-09-01T10:00:00Z' },
    { id: 'l2', paw: 'paw-aaa', ability: { ability_id: 'ab-psh' }, status: -3 },
  ]);
  state = await engine.readTargetState({ run, target: live });
  assert.strictEqual(state.phase, 'running');
  assert.strictEqual(state.lines, 1, 'one finished link; the queued one does not count');
  assert.strictEqual(state.rc, null);

  // ── poll: done ───────────────────────────────────────────────────────────
  server.state.links.set('op-1', [
    { id: 'l1', paw: 'paw-aaa', ability: { ability_id: 'ab-phish' }, status: 0, finish: '2026-09-01T10:00:00Z' },
    { id: 'l2', paw: 'paw-aaa', ability: { ability_id: 'ab-psh' }, status: 0, finish: '2026-09-01T10:01:00Z' },
    { id: 'l3', paw: 'paw-aaa', ability: { ability_id: 'ab-cred' }, status: 0, finish: '2026-09-01T10:02:00Z' },
  ]);
  server.state.operations.get('op-1').state = 'finished';
  state = await engine.readTargetState({ run, target: live });
  assert.strictEqual(state.phase, 'done');
  assert.strictEqual(state.rc, 0, 'worker.js writes status=completed only for rc 0');
  assert.strictEqual(state.lines, 3);
  assert.strictEqual(state.alive, false);

  // ── finalize ─────────────────────────────────────────────────────────────
  const done = engine.finalize({ run, targets: [targetRow({ status: 'completed', event_count: 3 })] });
  assert.strictEqual(done.status, 'completed');
});

test('a failed link fails the TARGET — it must never report a silent completion', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });
  const dispatch = await engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared });
  const live = targetRow({ status: 'running', engine_ref: dispatch.engineRef });

  // Two abilities ran, one was blocked and exited 3 — the operation itself
  // closed perfectly happily, which is precisely the trap.
  server.state.links.set('op-1', [
    { id: 'l1', paw: 'paw-aaa', ability: { ability_id: 'ab-phish' }, status: 0, finish: '2026-09-01T10:00:00Z' },
    { id: 'l2', paw: 'paw-aaa', ability: { ability_id: 'ab-psh' }, status: 3, finish: '2026-09-01T10:01:00Z' },
  ]);
  server.state.operations.get('op-1').state = 'finished';

  const state = await engine.readTargetState({ run, target: live });
  assert.strictEqual(state.phase, 'done');
  assert.strictEqual(state.rc, 3,
    'the FAILING LINK\'S OWN exit code, so worker.js can render a number that came from the host');
  assert.ok(state.raw.includes('failed=1'));

  // And worker.js's own arithmetic on that: rc !== 0 => status 'failed'.
  // Asserted here rather than assumed, because this is the entire point.
  assert.notStrictEqual(state.rc, 0);
});

test('a discarded or queued link is neither finished nor failed', () => {
  const { linkIsFinished, linkIsFailed } = calderaEngine.__pure;
  assert.strictEqual(linkIsFinished({ status: 0 }), true);
  assert.strictEqual(linkIsFinished({ status: 7 }), true);
  assert.strictEqual(linkIsFinished({ status: -3 }), false);
  assert.strictEqual(linkIsFinished({ status: -3, finish: '2026-09-01T10:00:00Z' }), true);
  assert.strictEqual(linkIsFailed({ status: 0 }), false);
  assert.strictEqual(linkIsFailed({ status: -2 }), false, 'discarded is not failed');
  assert.strictEqual(linkIsFailed({ status: 1 }), true);
  assert.strictEqual(calderaEngine.__pure.failedRc([{ status: 5 }, { status: 9 }]), 5);
  assert.strictEqual(calderaEngine.__pure.failedRc([{}]), 1, 'a failure with no code is still a failure');
});

test('a lane with no agent fails at DISPATCH, not forty-five minutes later', async () => {
  const server = fakeCaldera();
  server.state.agents = [];
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });

  await assert.rejects(
    () => engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared }),
    (err) => {
      assert.strictEqual(err.code, 'CALDERA_NO_AGENT');
      return true;
    }
  );
  assert.strictEqual(server.state.operations.size, 0, 'no operation may be created without an agent');
});

test('a stale agent row does not count as a live agent', () => {
  const cfg = { agentGroup: 'red', agentMaxAgeS: 600 };
  const nowMs = Date.parse('2026-09-01T10:00:00Z');
  const picked = calderaEngine.__pure.selectAgents([
    { paw: 'fresh', group: 'red', last_seen: '2026-09-01T09:59:00Z' },
    { paw: 'stale', group: 'red', last_seen: '2026-09-01T08:00:00Z' },
    { paw: 'blue', group: 'blue', last_seen: '2026-09-01T09:59:30Z' },
    { paw: 'nots', group: 'red', last_seen: 'not-a-timestamp' },
    { group: 'red', last_seen: '2026-09-01T09:59:30Z' },
  ], cfg, nowMs);
  // An unparseable timestamp is ACCEPTED on purpose: it is a field shape nobody
  // has ever seen, and refusing on it would fail every dispatch on the first
  // real server whose format differs.
  assert.deepStrictEqual(picked.map((a) => a.paw), ['fresh', 'nots']);
});

test('a scenario that compiles to nothing is refused, never launched', async () => {
  const server = fakeCaldera();
  server.state.abilities = [];
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };

  await assert.rejects(
    () => engine.prepare({ run, targets: [targetRow()], resolved: sel }),
    (err) => {
      assert.strictEqual(err.code, 'CALDERA_ADVERSARY_EMPTY');
      // The warnings say WHICH steps will not happen. An operation that runs
      // nothing and reports success is the worst outcome available, because it
      // looks like a working exercise.
      assert.ok(err.warnings.length);
      return true;
    }
  );
});

test('prepare() refuses when core would have to reach into a plugin for the scenario', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  await assert.rejects(
    () => engine.prepare({ run: runRow(), targets: [targetRow()], resolved: calderaEngine.resolveSelection(runRow()) }),
    (err) => {
      assert.strictEqual(err.code, 'CALDERA_NO_SCENARIO');
      return true;
    }
  );
});

// ---------------------------------------------------------------------------
// engine_ref
// ---------------------------------------------------------------------------

test('engine_ref round-trips through jsonb — object or string, same behaviour', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });
  const { engineRef } = await engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared });

  // The column is JSONB. node-postgres hands it back as an object; a row that
  // has been through JSON.stringify (a fixture, a cached payload) hands back a
  // string. Both must resolve to the same server and the same operation.
  const asObject = targetRow({ status: 'running', engine_ref: engineRef });
  const asString = targetRow({ status: 'running', engine_ref: JSON.stringify(engineRef) });

  server.state.operations.get('op-1').state = 'finished';
  server.state.links.set('op-1', [{ id: 'l1', status: 0, finish: '2026-09-01T10:00:00Z' }]);

  const a = await engine.readTargetState({ run, target: asObject });
  const b = await engine.readTargetState({ run, target: asString });
  assert.deepStrictEqual(a, b);
  assert.strictEqual(a.ref, 'op-1');

  // And the recorded server is what the next poll talks to, even with no
  // caldera_url left on the row — a lane keeps talking to the same box.
  const refOnly = { target_id: 't-1', lane_id: 'lane-1', status: 'running', engine_ref: engineRef };
  assert.strictEqual(calderaEngine.__pure.endpointFor(refOnly, { scheme: 'http', port: 8888 }),
    'http://100.100.60.9:8888');
});

test('an unresolvable endpoint is a NAMED refusal, never a guessed address', () => {
  assert.throws(
    () => calderaEngine.__pure.endpointFor({ lane_id: 'lane-9' }, { scheme: 'http', port: 8888 }),
    (err) => {
      assert.strictEqual(err.code, 'CALDERA_ENDPOINT_UNKNOWN');
      // The message has to say the design question is OPEN, because a reader
      // who thinks this is a config gap will invent a shared server.
      assert.match(err.message, /unsolved design question/i);
      return true;
    }
  );
});

test('there is no default API key, and there must not be', () => {
  assert.throws(() => calderaEngine.__pure.resolveSettings({}), (err) => {
    assert.strictEqual(err.code, 'CALDERA_NOT_CONFIGURED');
    return true;
  });
  const cfg = calderaEngine.__pure.resolveSettings({ api_key: 'k' });
  assert.strictEqual(cfg.port, 8888);
  assert.strictEqual(cfg.agentGroup, 'red');
  assert.strictEqual(cfg.plannerId, 'atomic');
});

// ---------------------------------------------------------------------------
// The shape worker.js consumes
// ---------------------------------------------------------------------------

test('readTargetState returns EXACTLY runner.parseGuestState\'s object — no worker branch', async () => {
  // Derived from the real function rather than a copied list, so the day
  // parseGuestState grows a field this fails instead of drifting.
  const expected = Object.keys(require('../src/incident/runner').parseGuestState('')).sort();

  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });
  const { engineRef } = await engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared });

  const states = [
    await engine.readTargetState({ run, target: targetRow() }),                       // never dispatched
    await engine.readTargetState({ run, target: targetRow({ engine_ref: engineRef }) }), // live
    await engine.readTargetState({ run, target: targetRow({ engine_ref: { ...engineRef, aborted_at: '2026-09-01T10:00:00Z' } }) }),
  ];
  for (const s of states) {
    assert.deepStrictEqual(Object.keys(s).sort(), expected);
    // worker.js binds several of these straight into an UPDATE and
    // node-postgres treats undefined differently from null.
    for (const [k, v] of Object.entries(s)) {
      assert.notStrictEqual(v, undefined, `${k} must be null, never undefined`);
    }
  }
  assert.strictEqual(states[0].phase, '');
  assert.strictEqual(states[0].alive, false);
  assert.strictEqual(states[2].phase, 'aborted');
});

test('a vanished operation is a refusal the instructor can read, not an endless check failure', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });
  const { engineRef } = await engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared });

  server.state.operations.delete('op-1');
  const state = await engine.readTargetState({ run, target: targetRow({ engine_ref: engineRef }) });
  assert.strictEqual(state.phase, 'refused');
  // NOT 'notinstalled': worker.js treats that one reason as a signal to
  // invalidate the LOG-GENERATOR target cache, which has nothing to do with
  // this engine.
  assert.strictEqual(state.reason, 'nooperation');
  assert.notStrictEqual(state.reason, 'notinstalled');
});

test('a server that does not answer PROPAGATES, so the worker\'s check_failures ladder runs', async () => {
  const server = fakeCaldera();
  server.state.offline = true;
  const engine = engineOn(server);
  const target = targetRow({
    engine_ref: { engine: 'caldera', server: 'http://100.100.60.9:8888', operation_id: 'op-1' },
  });
  await assert.rejects(() => engine.readTargetState({ run: runRow(), target }), (err) => {
    assert.ok(err instanceof CalderaError);
    assert.strictEqual(err.code, 'CALDERA_UNREACHABLE');
    return true;
  });
});

// ---------------------------------------------------------------------------
// Abort and finalize
// ---------------------------------------------------------------------------

test('abort is idempotent, tolerates a vanished operation, and never throws on an unreachable lane', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });
  const { engineRef } = await engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared });
  const live = targetRow({ status: 'running', engine_ref: engineRef });

  const first = await engine.abortTarget({ run, target: live });
  assert.strictEqual(first.aborted, true);
  assert.strictEqual(server.state.operations.get('op-1').state, 'finished');

  // Twice. Abort races the sweeper by construction.
  const second = await engine.abortTarget({ run, target: live });
  assert.strictEqual(second.aborted, true);

  // Gone entirely: already stopped is stopped.
  server.state.operations.delete('op-1');
  const third = await engine.abortTarget({ run, target: live });
  assert.strictEqual(third.aborted, true);

  // Never dispatched: nothing to stop is success, which is exactly the shape of
  // an abort racing a dispatch that had not yet created an operation.
  const nothing = await engine.abortTarget({ run, target: targetRow() });
  assert.strictEqual(nothing.aborted, true);
  assert.strictEqual(nothing.operationId, null);

  // Unreachable: reported, not thrown. runner.abortRun makes the same call — a
  // lane we cannot reach is one we also cannot verify, and refusing to record
  // the abort would leave the run live forever.
  server.state.offline = true;
  const dead = await engine.abortTarget({ run, target: live });
  assert.strictEqual(dead.aborted, false);
  assert.strictEqual(dead.unreachable, true);
});

test('abortRun never lets one unreachable lane take the others down', async () => {
  const server = fakeCaldera();
  const engine = engineOn(server);
  const run = runRow();
  const sel = { ...calderaEngine.resolveSelection(run), scenario: scenarioFixture() };
  const prepared = await engine.prepare({ run, targets: [targetRow()], resolved: sel });
  const { engineRef } = await engine.dispatchTarget({ run, target: targetRow(), resolved: sel, prepared });

  const summary = await engine.abortRun({
    run,
    targets: [
      targetRow({ target_id: 't-1', engine_ref: engineRef }),
      targetRow({ target_id: 't-2', engine_ref: null }),
      // No endpoint at all: endpointFor throws inside, and abortTarget swallows
      // it into a reported failure rather than aborting the abort.
      { target_id: 't-3', lane_id: 'lane-3', engine_ref: { operation_id: 'op-x' } },
    ],
  });
  assert.strictEqual(summary.results.length, 3);
  assert.strictEqual(summary.aborted, 2);
  assert.strictEqual(summary.results[2].aborted, false);
});

test('finalize: a lane that completed having executed nothing is NOT a completed lane', () => {
  const f = (targets) => calderaEngine.finalize({ run: runRow(), targets }).status;

  assert.strictEqual(f([{ status: 'running' }, { status: 'completed', event_count: 4 }]), 'running');
  assert.strictEqual(f([{ status: 'completed', event_count: 4 }]), 'completed');
  // null is "we never learned", which is not zero.
  assert.strictEqual(f([{ status: 'completed', event_count: null }]), 'completed');
  assert.strictEqual(f([{ status: 'completed', event_count: 4 }, { status: 'failed' }]), 'partial');

  // THE ENGINE-SPECIFIC RULE. For the synthetic engine a completed target with
  // no events is nearly impossible; for Caldera it is the single most likely
  // failure in the design — the agent never beaconed, the operation closed
  // cleanly having run nothing at all.
  assert.strictEqual(f([{ status: 'completed', event_count: 4 }, { status: 'completed', event_count: 0 }]), 'partial');
  const barren = calderaEngine.finalize({ run: runRow(), targets: [{ status: 'completed', event_count: 0 }] });
  assert.strictEqual(barren.status, 'failed');
  assert.match(barren.reason, /without executing a single ability/);

  assert.strictEqual(f([{ status: 'aborted' }]), 'aborted');
  assert.strictEqual(f([{ status: 'failed' }, { status: 'unknown' }]), 'failed');
  // Every status this returns must be legal in cybercore_incident_run's CHECK.
  const legal = new Set(['scheduling', 'dispatching', 'running', 'completed', 'partial', 'failed', 'aborted']);
  for (const s of ['running', 'completed', 'partial', 'failed', 'aborted']) assert.ok(legal.has(s));
});

// ---------------------------------------------------------------------------
// The gates that prove the abstraction held
// ---------------------------------------------------------------------------

/** Source with comments removed, so documentation stays legal and code does not. */
function codeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

function incidentCode(file) {
  return codeOnly(fs.readFileSync(path.join(INCIDENT, file), 'utf8'));
}

test('THE E9 EXIT CRITERION: worker.js and board.js know nothing about Caldera', () => {
  // The whole justification for writing the engine contract in E0 before there
  // was a second engine. If adding a real C2 had needed a line in either of
  // these files, the seam would have failed and the next engine would be a
  // rewrite rather than a file.
  //
  // Asserted on CODE with comments stripped: a comment naming Caldera is
  // documentation and welcome; an identifier is coupling.
  for (const file of ['worker.js', 'board.js']) {
    const code = incidentCode(file);
    assert.ok(!/caldera/i.test(code),
      `src/incident/${file} must not mention caldera — the engine adapter is where that lives`);
    assert.ok(!/cc-attack/.test(code),
      `src/incident/${file} must not name the synthetic wrapper either`);
  }
  // board.js additionally never touches the guest agent: it reads rows.
  assert.ok(!/agentShellExec/.test(incidentCode('board.js')),
    'src/incident/board.js must not execute anything in a guest');
});

test('TRIPWIRE, EXPECTED TO GO RED AT E9-SHIP: worker.js still calls the guest agent directly', () => {
  // This asserts the CURRENT state, deliberately, in the same spirit as the
  // supportsMode('scenario') tripwire the synthetic engine carried through E4.
  //
  // The E9 exit criterion is that src/incident/worker.js contains no
  // 'agentShellExec'. It still does — checkTarget() calls agentShellExec() plus
  // runner.parseGuestState() directly instead of engineFor(run.engine)
  // .readTargetState(), which is a piece of wiring E9 explicitly does NOT do:
  // routing the sweeper through the adapter changes the dispatch path for every
  // CYBR 400 run in flight, and this phase ships a seam nobody can invoke.
  //
  // WHEN THIS TEST FAILS, that wiring has landed. Delete this test and move
  // 'agentShellExec' into the gate above — do not "fix" it by restoring the
  // call. The adapter is already shaped for it: readTargetState() returns
  // parseGuestState's exact object, asserted above.
  const code = incidentCode('worker.js');
  assert.ok(/agentShellExec/.test(code),
    'worker.js no longer calls agentShellExec — the sweeper has been routed through the engine '
    + 'adapter. Delete this tripwire and add agentShellExec to the exit-criterion gate above.');
});

test('only client.js opens a socket — that is what makes the rest of this testable', () => {
  const engineSrc = codeOnly(fs.readFileSync(path.join(INCIDENT, 'engines', 'caldera.js'), 'utf8'));
  const advSrc = codeOnly(fs.readFileSync(path.join(INCIDENT, 'caldera', 'adversary.js'), 'utf8'));
  for (const [name, src] of [['engines/caldera.js', engineSrc], ['caldera/adversary.js', advSrc]]) {
    for (const forbidden of [/\bfetch\s*\(/, /https?\.request/, /require\(['"]https?['"]\)/, /XMLHttpRequest/]) {
      assert.ok(!forbidden.test(src),
        `${name} must not make a request itself — every call goes through caldera/client.js, `
        + 'which is the only reason this adapter can be tested with no server in existence');
    }
  }
});

test('the honesty banners are present in every file this phase added', () => {
  // Not decoration. No Caldera server exists; anyone reading these files months
  // from now must not be able to mistake them for working code, and a banner
  // that can be deleted without a test noticing will be.
  const files = [
    path.join(INCIDENT, 'engines', 'caldera.js'),
    path.join(INCIDENT, 'caldera', 'client.js'),
    path.join(INCIDENT, 'caldera', 'adversary.js'),
    __filename,
  ];
  for (const f of files) {
    const head = fs.readFileSync(f, 'utf8').slice(0, 4000);
    assert.ok(/NEVER (BEEN RUN|TALKED TO|EXECUTED)|NO CALDERA SERVER|HAS EVER RUN AGAINST/i.test(head),
      `${path.basename(f)} must say at the top that it has never met a real Caldera server`);
  }
});

test('the DDL E9 relies on was already there — no migration, no constraint surgery', () => {
  // Confirmed against the schema rather than taken on trust, because "engine_ref
  // already exists" is the entire reason this phase adds no DDL to a
  // CREATE-TABLE-IF-NOT-EXISTS path that re-runs on every boot.
  const schema = require('../src/incident/schema');
  assert.match(schema.RUN_TABLE_SQL, /engine IN \('synthetic','caldera'\)/);
  assert.match(schema.TARGET_TABLE_SQL, /engine_ref\s+JSONB/);
});

// ---------------------------------------------------------------------------
// The fake
// ---------------------------------------------------------------------------

/**
 * A Caldera server that never was.
 *
 * Answers upstream's DOCUMENTED v2 shapes — see this file's banner for how much
 * that is worth. It is a transport function, not a patched global, because a
 * patched global survives a throw and poisons every other suite in the process.
 */
function fakeCaldera() {
  const state = {
    abilities: ABILITIES.slice(),
    adversaries: [],
    agents: [{ paw: 'paw-aaa', group: 'red', platform: 'windows', host: 'WKS-01', last_seen: '2026-09-01T09:59:00Z' }],
    operations: new Map(),
    links: new Map(),
    requests: [],
    offline: false,
    nextOperationId: 1,
    nowMs: Date.parse('2026-09-01T10:00:00Z'),
  };

  const json = (status, body) => ({ status, ok: status >= 200 && status < 300, text: JSON.stringify(body) });

  async function transport(req) {
    if (state.offline) {
      // Exactly what the real transport raises for ECONNREFUSED, so the
      // adapter's handling of it is the handling production will get.
      const err = new CalderaError(`Caldera unreachable — ${req.operation}: connect ECONNREFUSED`,
        { code: 'CALDERA_UNREACHABLE', operation: req.operation });
      throw err;
    }
    const url = new URL(req.url);
    const p = url.pathname;
    state.requests.push({ method: req.method, path: p, body: req.body ? JSON.parse(req.body) : null, key: req.headers.KEY });

    if (req.method === 'GET' && p === '/api/v2/health') return json(200, { access: 'red' });
    if (req.method === 'GET' && p === '/api/v2/abilities') return json(200, state.abilities);
    if (req.method === 'GET' && p === '/api/v2/agents') return json(200, state.agents);

    if (req.method === 'POST' && p === '/api/v2/adversaries') {
      const adv = JSON.parse(req.body);
      if (!state.adversaries.some((a) => a.adversary_id === adv.adversary_id)) state.adversaries.push(adv);
      return json(200, adv);
    }

    if (req.method === 'POST' && p === '/api/v2/operations') {
      const body = JSON.parse(req.body);
      const id = `op-${state.nextOperationId++}`;
      const op = { id, name: body.name, state: 'running', adversary: body.adversary, group: body.group };
      state.operations.set(id, op);
      state.links.set(id, []);
      return json(200, op);
    }

    const opMatch = p.match(/^\/api\/v2\/operations\/([^/]+)(\/links)?$/);
    if (opMatch) {
      const id = decodeURIComponent(opMatch[1]);
      const op = state.operations.get(id);
      if (!op) return json(404, { error: 'not found' });
      if (opMatch[2]) return json(200, state.links.get(id) || []);
      if (req.method === 'PATCH') {
        Object.assign(op, JSON.parse(req.body));
        return json(200, op);
      }
      return json(200, op);
    }

    return json(404, { error: `no route for ${req.method} ${p}` });
  }

  return { state, transport, get nowMs() { return state.nowMs; } };
}
