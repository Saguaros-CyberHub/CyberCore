/**
 * incident-answer-key.test.js — Track E, phase E5: the compiled answer key.
 *
 * The key is what every grade in this feature is measured against, and it is
 * computed rather than observed — re-running cc-emit's planner server-side with
 * the SAME SEED the guest used, which is the run id. So the property that has
 * to hold is not "the key looks reasonable", it is "the key IS the event list
 * the lane wrote".
 *
 * There is no symptom if it is wrong. A key compiled from the wrong seed, the
 * wrong duration or the wrong playbook is a plausible description of an attack
 * that never ran, and it grades every student's correct answer as a false
 * positive. Nothing crashes and nothing logs.
 *
 * WHAT EACH SECTION DEFENDS
 *
 *   §1  EXACT REPRODUCTION. The key's totals and offsets equal a direct
 *       planTimeline() call with makeRng(seedFrom(runId)) — the three inputs
 *       cc-emit.js:608/640 uses, verbatim.
 *   §2  THE SEED IS THE RUN ID. Same id, byte-identical key; different id,
 *       different key. If the first fails, thirty lanes are being graded
 *       against thirty different truths. If the second fails, the seed is not
 *       reaching the planner and every run in the course is the same exercise.
 *   §3  DURATION. duration_seconds when there is one, nominal_seconds when
 *       there is not — the chain case, where resolveSelection deliberately
 *       gives duration:'' because a chain runs its own scripted length.
 *   §4  IOCs ARE A DIFFERENCE, NOT A LIST. Every value in the key is one the
 *       floor cannot produce. The failure direction matters: an ordinary
 *       hostname in the key penalises every student who correctly ignores it.
 *   §5  THE KEY DOES NOT CARRY THE PROSE ANSWER. `action` and
 *       `detection_opportunity` are E4's authoring fields and the second one is
 *       literally the answer; neither may reach a label.
 *   §6  EVERY PLAYBOOK ON DISK COMPILES, at every duration the console offers.
 *
 * Run: node --test test/incident-answer-key.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const P = path.join(__dirname, '..', 'src', 'incident');
const PLAYBOOK_DIR = path.join(P, 'playbooks');
const emit = require(path.join(P, 'cc-emit.js'));
const answerKey = require(path.join(P, 'answer-key.js'));

const load = (f) => JSON.parse(fs.readFileSync(path.join(PLAYBOOK_DIR, f), 'utf8'));
const files = fs.readdirSync(PLAYBOOK_DIR).filter((f) => f.endsWith('.json') && f !== 'host-baseline.json');

const RUN_A = '11111111-1111-1111-1111-111111111111';
const RUN_B = '22222222-2222-2222-2222-222222222222';

/** The five durations the Attack Console offers. */
const UI_DURATIONS = [300, 900, 1800, 3600, 7200];

// ---------------------------------------------------------------------------
// §1 Exact reproduction
// ---------------------------------------------------------------------------

test('E5-K1: a compiled key reproduces planTimeline exactly', () => {
  for (const f of ['T1110.001.json', 'T1496.json', 'chain-ransomware-ryuk.json']) {
    const pb = load(f);
    const requested = pb.nominal_seconds;

    // The three inputs, spelled out the way cc-emit.js:608 and :640 spell them.
    const plan = emit.planTimeline(pb, {
      rng: emit.makeRng(emit.seedFrom(RUN_A)),
      requested,
    });
    const key = answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb, requestedSeconds: requested });

    assert.strictEqual(key.totals.events, plan.events.length,
      `${f}: the key must count the events the lane actually wrote`);

    // Technique roll-up, recomputed independently from the same plan.
    const expected = new Map();
    for (const ev of plan.events) {
      if (!ev.technique) continue;
      const row = expected.get(ev.technique) || { count: 0, first: Infinity };
      row.count += 1;
      row.first = Math.min(row.first, ev.offset);
      expected.set(ev.technique, row);
    }
    assert.strictEqual(key.techniques.length, expected.size, `${f}: technique count`);
    for (const t of key.techniques) {
      const want = expected.get(t.id);
      assert.ok(want, `${f}: ${t.id} is not in the plan at all`);
      assert.strictEqual(t.event_count, want.count, `${f}: ${t.id} event_count`);
      assert.strictEqual(t.first_offset_s, Math.round(want.first), `${f}: ${t.id} first_offset_s`);
    }

    // The techniques are ordered by when they FIRST fire. That ordering is the
    // truth the timeline score correlates against, so it has to be total and
    // it has to be this one.
    const offsets = key.techniques.map((t) => t.first_offset_s);
    assert.deepStrictEqual(offsets, offsets.slice().sort((a, b) => a - b),
      `${f}: the key's technique order must be chronological`);

    // One timeline entry per step, at the step's planned start — recomputed
    // with the plan's own solved dwell scale, not an approximation of it.
    const starts = emit.layout(pb.steps, plan.gapScale).starts;
    assert.strictEqual(key.timeline.length, pb.steps.length, `${f}: one entry per step`);
    key.timeline.forEach((entry, i) => {
      assert.strictEqual(entry.step, i + 1);
      assert.strictEqual(entry.offset_s, Math.round(starts[i]), `${f}: step ${i + 1} offset`);
    });
  }
});

// ---------------------------------------------------------------------------
// §2 The seed is the run id
// ---------------------------------------------------------------------------

test('E5-K2: the same run id compiles the same key, twice and forever', () => {
  // The instructor-facing promise is "there are N events, find them", said once
  // to thirty lanes. If this fails, a retried lane is graded against a
  // different attack from the twenty-nine that did not fail.
  const pb = load('chain-apt29-cozy-bear.json');
  const once = () => JSON.stringify(answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb }));
  assert.strictEqual(once(), once());
});

test('E5-K3: two run ids on the same playbook compile DIFFERENT keys', () => {
  // The mirror of the test above, and the one that catches the seed never
  // reaching the planner: if this fails, every run in the course is the same
  // exercise and last semester's answers still work.
  const pb = load('chain-apt29-cozy-bear.json');
  const a = answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb });
  const b = answerKey.compileAnswerKey({ runId: RUN_B, playbook: pb });
  assert.notStrictEqual(JSON.stringify(a), JSON.stringify(b));
  // Specifically: the adversary's own identity moved. The entities are what
  // make one run pivotable as one adversary, so they are what must differ.
  assert.notDeepStrictEqual(a.iocs, b.iocs);
  // The STRUCTURE is stable across runs even though the values are not — the
  // same techniques in the same order, because that is the playbook's script.
  assert.deepStrictEqual(a.techniques.map((t) => t.id), b.techniques.map((t) => t.id));
});

test('E5-K4: a key cannot be compiled without a run id', () => {
  // Not a defaultable argument: a key seeded from '' describes an attack no
  // lane ran, and every symptom of that appears in a grade rather than a log.
  assert.throws(
    () => answerKey.compileAnswerKey({ playbook: load('T1110.001.json') }),
    /runId is the seed/
  );
});

// ---------------------------------------------------------------------------
// §3 Duration
// ---------------------------------------------------------------------------

test('E5-K5: the key uses duration_seconds, and falls back the way cc-emit does', () => {
  const pb = load('T1110.001.json');

  const short = answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb, requestedSeconds: 300 });
  const long = answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb, requestedSeconds: 1800 });
  assert.strictEqual(short.requested_seconds, 300);
  assert.strictEqual(long.requested_seconds, 1800);
  assert.notStrictEqual(short.timeline[1].offset_s, long.timeline[1].offset_s,
    'a longer run spreads the same steps further apart');

  // A CHAIN has no duration: resolveSelection gives it duration:'' on purpose,
  // because a chain runs its own scripted length. cc-emit.js:640 then falls
  // back to nominal_seconds, and so must this.
  const chain = load('chain-ransomware-ryuk.json');
  const fallback = answerKey.compileAnswerKey({ runId: RUN_A, playbook: chain });
  assert.strictEqual(fallback.requested_seconds, Math.round(chain.nominal_seconds));
  const explicit = answerKey.compileAnswerKey({
    runId: RUN_A, playbook: chain, requestedSeconds: chain.nominal_seconds,
  });
  assert.strictEqual(JSON.stringify(fallback), JSON.stringify(explicit));
});

// ---------------------------------------------------------------------------
// §4 IOCs are a difference
// ---------------------------------------------------------------------------

test('E5-K6: no key IOC is a value the benign floor can also produce', () => {
  // The direction of this error is what matters. An extra floor value costs one
  // IOC the key does not list. A MISSING one puts an ordinary hostname in the
  // key and then penalises every student who correctly ignores it — and there
  // is no way to tell from the outside which happened.
  const floor = answerKey.loadFloorPlaybook();
  const floorUniverse = answerKey.collectDeclaredValues(floor);

  for (const f of files) {
    const key = answerKey.compileAnswerKey({ runId: RUN_A, playbook: load(f) });
    for (const ioc of key.iocs) {
      assert.ok(!floorUniverse.values.has(ioc.value),
        `${f}: ${ioc.value} is in the key AND in the floor's own vocabulary`);
      // An address whose /24 the floor draws from at random is likewise not an
      // indicator: the floor lands in that space every run.
      const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/.exec(ioc.value);
      if (m) {
        assert.ok(!floorUniverse.prefixes.has(m[1]),
          `${f}: ${ioc.value} sits in a /24 the floor generates into`);
      }
      assert.ok(ioc.event_count > 0, `${f}: ${ioc.value} is in the key but was never emitted`);
      assert.ok(
        ['host', 'user', 'ip', 'path', 'process', 'domain', 'hash', 'port'].includes(ioc.type),
        `${f}: ${ioc.value} has type ${ioc.type}, which is not in the column's CHECK`
      );
    }
  }
});

test('E5-K7: the floor tagged set travels with the key, because the scorer needs it', () => {
  // src/incident/scoring.js reads floor_techniques to award 'partial' instead
  // of a penalty. Without it in the key, every student who correctly notices
  // the floor's deliberately-tagged benign events is penalised, and the floor's
  // 4-20% MITRE band becomes a trap instead of a feature.
  const key = answerKey.compileAnswerKey({ runId: RUN_A, playbook: load('T1110.001.json') });
  const floor = answerKey.loadFloorPlaybook();
  const expected = new Set();
  for (const step of floor.steps) if (step.technique) expected.add(step.technique);
  assert.ok(expected.size >= 3, 'the floor should carry a real MITRE tag set');
  assert.deepStrictEqual(key.floor_techniques, [...expected].sort());
  assert.ok(key.floor_values.length > 0, 'the floor value universe is what makes an IOC defensible');
  // Lowercased and sorted, so a recompile is byte-identical and the scorer's
  // case-insensitive match works without re-normalising on every lookup.
  assert.deepStrictEqual(key.floor_values, key.floor_values.slice().sort());
  for (const v of key.floor_values) assert.strictEqual(v, v.toLowerCase());
});

// ---------------------------------------------------------------------------
// §5 The prose answer never reaches the key's labels
// ---------------------------------------------------------------------------

test('E5-K8: step.action and step.detection_opportunity never reach the key', () => {
  // E4's compiler authors both on its steps. `detection_opportunity` is
  // LITERALLY the answer — "look for six failed logons followed by a success
  // from the same source" — and this object is one projection bug away from a
  // student. They belong in the compiler's own output, not in a label.
  const pb = {
    technique: 'T1110.001',
    tactic: 'TA0006',
    nominal_seconds: 300,
    entities: { source_ip: { ipv4Host: '198.51.100' } },
    pools: { users: ['alice'] },
    steps: [{
      gap: '10s', spread: '30s', count: 5,
      technique: 'T1110.001', tactic: 'TA0006',
      source: { type: 'authentication', name: 'sshd', host: 'auth-01' },
      message: 'Failed password for {{users}} from {{source_ip}} port {{port}} ssh2',
      metadata: { event_action: 'logon-failed', user: '{{users}}' },
      action: 'SECRET-ACTION-TEXT',
      detection_opportunity: 'SECRET-DETECTION-TEXT',
    }],
  };
  const key = answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb });
  const asText = JSON.stringify(key);
  assert.ok(!asText.includes('SECRET-ACTION-TEXT'), 'step.action leaked into the key');
  assert.ok(!asText.includes('SECRET-DETECTION-TEXT'), 'step.detection_opportunity leaked into the key');
  assert.strictEqual(key.timeline[0].label, 'logon-failed');
});

// ---------------------------------------------------------------------------
// §6 Everything on disk compiles
// ---------------------------------------------------------------------------

test('E5-K9: every playbook compiles at every duration the console offers', () => {
  for (const f of files) {
    const pb = load(f);
    const min = emit.minSecondsFor(pb);
    const durations = /^chain-/.test(f) ? [null] : UI_DURATIONS.filter((d) => d >= min);
    assert.ok(durations.length, `${f}: nothing to compile`);
    for (const d of durations) {
      const key = answerKey.compileAnswerKey({ runId: RUN_A, playbook: pb, requestedSeconds: d });
      assert.strictEqual(key.version, answerKey.ANSWER_KEY_VERSION);
      assert.strictEqual(key.engine, 'synthetic');
      assert.ok(key.totals.events > 0, `${f} at ${d}s produced no events`);
      assert.ok(key.techniques.length > 0, `${f} at ${d}s tagged no technique`);
      assert.strictEqual(key.totals.techniques, key.techniques.length);
      assert.strictEqual(key.totals.iocs, key.iocs.length);
    }
  }
});

test('E5-K11: the synthetic ADAPTER compiles the key, so the launch path has a seam', () => {
  // The engine contract is what a launch route calls; if this stayed a stub
  // returning {}, every run would have an empty key and the board would grade
  // nothing while looking entirely healthy.
  const engine = require(path.join(P, 'engines', 'synthetic.js'));
  const runner = require(path.join(P, 'runner.js'));

  const technique = runner.resolveSelection({
    mode: 'technique', technique_id: 'T1110.001', duration_seconds: 300,
  });
  const key = engine.compileAnswerKey({ run_id: RUN_A, duration_seconds: 300 }, technique);
  const direct = answerKey.compileAnswerKey({
    runId: RUN_A, playbook: load('T1110.001.json'), requestedSeconds: 300,
  });
  assert.deepStrictEqual(key, direct, 'the adapter must not compile a DIFFERENT key');

  // A CHAIN carries no duration_seconds -- migration 006's correlated CHECK
  // forbids one -- so the adapter has to fall back to nominal_seconds exactly
  // as cc-emit.js:640 does, rather than refusing or defaulting to something.
  const chain = runner.resolveSelection({ mode: 'chain', chain_key: 'ransomware-ryuk' });
  const chainKey = engine.compileAnswerKey({ run_id: RUN_A, duration_seconds: null }, chain);
  assert.ok(chainKey.totals.events > 0);
  assert.deepStrictEqual(
    chainKey,
    answerKey.compileAnswerKey({ runId: RUN_A, playbook: load('chain-ransomware-ryuk.json') })
  );

  // TACTIC mode has no playbook, and that is not an error: a tactic is a dozen
  // unrelated behaviours with no single honest story to script, so it stays on
  // the generator's keyword filter and there is no event list to predict. An
  // empty key means "not auto-graded" to the scorer, which is the honest answer.
  const tactic = runner.resolveSelection({
    mode: 'tactic', tactic_id: 'TA0006', duration_seconds: 300,
  });
  assert.deepStrictEqual(engine.compileAnswerKey({ run_id: RUN_A }, tactic), {});
});

test('E5-K10: a non-synthetic engine returns an EMPTY key that says why', () => {
  // Caldera runs real abilities against real hosts; what lands in Sysmon is
  // whatever actually happened, so a compiled key would be a guess. An empty
  // key grades nothing and says so (scoring.js then marks every claim
  // 'unscored'); a guessed one mis-grades and does not.
  const key = answerKey.answerKeyForRun({ run_id: RUN_A, engine: 'caldera' });
  assert.deepStrictEqual(key.techniques, []);
  assert.deepStrictEqual(key.iocs, []);
  assert.match(key.reason, /caldera/);
});
