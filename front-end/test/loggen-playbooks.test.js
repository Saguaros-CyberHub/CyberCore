// ============================================================================
// Playbook contract tests.
//
// These enforce the properties no human review reliably catches, and every one
// of them guards a failure that is SILENT in production:
//
//   * an unresolved {{token}} ships literal braces to Kibana -- exactly the
//     "{clientIP}" tell log-generator itself has at the pinned commit
//   * a seventh top-level key falls to dynamic mapping under ecs@mappings,
//     where a name like source.ip is typed `ip` and then REJECTS every document
//     whose value is not an address. No warning, no error, no events.
//   * an untagged attack event is dropped by the agent's drop_event processor
//   * a (source.type, source.name) pair that only ever appears during an attack
//     is a one-click answer key -- one terms agg and the exercise is over
//
// The last one is the reason this file exists. It is not enough for source.type
// to occur in benign traffic: loggen.source.name and loggen.source.host are
// mapped keywords sitting in Discover's field list right beside it.
//
// E4 NOTE. The assertions themselves now live in test/helpers/playbook-contract.js,
// unchanged, so that the SAME contract can be pointed at a playbook the compiler
// produced at runtime -- which is never on disk, is never read by a human, and is
// therefore the artefact that needs it most. This file is what it always was: the
// contract applied to the fifteen playbooks and one floor that ship in the repo,
// plus the checks that are coupled to the CATALOG rather than to the wire format
// and so have no meaning for a compiled scenario.
// ============================================================================
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const contract = require('./helpers/playbook-contract.js');

// E1 moved the engine, the emitter and the playbooks out of the CLE plugin
// into shared core. Same files, same assertions, one directory.
const P = path.join(__dirname, '..', 'src', 'incident');
const PLAYBOOK_DIR = path.join(P, 'playbooks');
const emit = require(path.join(P, 'cc-emit.js'));
const catalog = require(path.join(P, 'catalog.js'));

/** The five durations the Attack Console offers. */
const UI_DURATIONS = contract.UI_DURATIONS;

const files = fs.readdirSync(PLAYBOOK_DIR).filter((f) => f.endsWith('.json')).sort();
const load = (f) => JSON.parse(fs.readFileSync(path.join(PLAYBOOK_DIR, f), 'utf8'));

const FLOOR = 'host-baseline.json';
const attacks = () => files.filter((f) => f !== FLOOR);

/** Every playbook the repo ships, labelled by filename so failures name it. */
const subjectsOf = (names) => names.map((f) => ({ playbook: load(f), label: f }));

// ---------------------------------------------------------------------------
// Catalog coupling. These have no analogue for a compiled scenario -- there is
// no catalog entry for a client profile -- so they stay here rather than moving
// into the shared contract.
// ---------------------------------------------------------------------------

test('every catalog technique has a playbook, and every playbook a catalog entry', () => {
  const onDisk = new Set(files.filter((f) => /^T\d/.test(f)).map((f) => f.replace('.json', '')));
  const inCatalog = new Set(catalog.TECHNIQUES.map((t) => t.id));

  const missing = [...inCatalog].filter((id) => !onDisk.has(id));
  assert.deepStrictEqual(missing, [], `catalog techniques with no playbook: ${missing}`);

  // The reverse direction matters just as much: a playbook for a technique the
  // console cannot offer is dead content that will rot without anyone noticing.
  const orphan = [...onDisk].filter((id) => !inCatalog.has(id));
  assert.deepStrictEqual(orphan, [], `playbooks with no catalog entry: ${orphan}`);
});

test('every chain in the catalog has a playbook', () => {
  for (const c of catalog.CHAINS) {
    assert.ok(files.includes(`chain-${c.key}.json`), `no playbook for chain ${c.key}`);
  }
});

test('a chain playbook only uses techniques the catalog says that chain contains', () => {
  // Otherwise the console advertises one campaign and the lane generates a
  // different one, and the mismatch is only visible by reading both lists.
  for (const c of catalog.CHAINS) {
    const pb = load(`chain-${c.key}.json`);
    const declared = new Set(c.techniques);
    const used = new Set(pb.steps.map((s) => s.technique).filter(Boolean));
    const extra = [...used].filter((t) => !declared.has(t));
    assert.deepStrictEqual(extra, [], `chain ${c.key} emits ${extra} which its catalog entry does not list`);
  }
});

// ---------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------

test('no playbook ships an unresolved {{token}}', () => {
  for (const f of files) contract.assertNoUnresolvedTokens(load(f), { label: f });
});

test('every event carries exactly the six envelope keys and nothing more', () => {
  for (const f of files) contract.assertSixKeyEnvelope(load(f), { label: f });
});

test('every attack event is tagged, or the agent silently drops it', () => {
  for (const f of attacks()) contract.assertEveryAttackEventTagged(load(f), { label: f });
});

test('the serialization the wrapper greps for is exactly what is emitted', () => {
  contract.assertGrepSerialization(load('T1110.001.json'), { label: 'T1110.001.json' });
});

// ---------------------------------------------------------------------------
// The anti-oracle assertions
// ---------------------------------------------------------------------------

test('the benign floor covers every field value the attacks use', () => {
  // THE anti-oracle test. A (type/name) pair or a host that appears only during
  // an attack is a single terms aggregation away from ending the exercise.
  contract.assertSourceVocabularySubset(load(FLOOR), { attacks: subjectsOf(attacks()) });
});

test('the host baseline keeps a false-positive floor of MITRE labels', () => {
  contract.assertBenignMitreFloor(load(FLOOR), { label: FLOOR, min: 4, max: 20 });
});

test('no metadata field has a vocabulary the benign floor never uses', () => {
  contract.assertMetadataVocabularySubset(load(FLOOR), { attacks: subjectsOf(attacks()) });
});

test('the benign floor uses every address space the attacks use', () => {
  contract.assertAddressSpaceSubset(load(FLOOR), { attacks: subjectsOf(attacks()) });
});

test('no event states the conclusion a student is meant to reach', () => {
  for (const f of files) contract.assertStatesNoConclusion(load(f), { label: f });
});

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

test('bursts stay rigid while dwell absorbs the requested duration', () => {
  contract.assertRigidBurstsElasticDwell(load('T1110.001.json'), {
    label: 'T1110.001.json', match: /^Failed password/, durations: UI_DURATIONS,
  });
});

test('a playbook plans at every duration it advertises and refuses the rest', () => {
  for (const f of attacks()) contract.assertPlansAtEveryDuration(load(f), { label: f });
});

// ---------------------------------------------------------------------------
// Coherence
// ---------------------------------------------------------------------------

test('the same run id produces the same attack on every lane', () => {
  contract.assertDeterministicPerRunId(load('T1110.001.json'), {
    label: 'T1110.001.json',
    runId: '11111111-2222-3333-4444-555555555555',
    requested: 300,
  });
});

test('one run reads as one adversary, not a shuffle', () => {
  contract.assertOneAdversaryNotAShuffle(load('T1110.001.json'), {
    label: 'T1110.001.json', requested: 300,
  });
});

test('the emitter registers no SIGTERM handler', () => {
  // Abort is `kill -TERM -$PGID` and the cap is `timeout -k 30`. Node's default
  // terminates immediately, which is what makes both work. A handler doing async
  // flush work can outlive the 30s grace and be SIGKILLed mid-write, producing
  // the torn line openAppend() has to repair.
  assert.strictEqual(process.listenerCount('SIGTERM'), 0);
});

test('an event never contradicts itself about who or what it describes', () => {
  for (const f of files) contract.assertNoSelfContradiction(load(f), { label: f });
});

test('a pool still varies between events, or a spray is one account repeated', () => {
  contract.assertPoolVariesBetweenEvents(load('T1110.001.json'), {
    label: 'T1110.001.json', requested: 300, min: 3,
  });
});

// ---------------------------------------------------------------------------
// Wrapper coupling. Both of these read cc-emit.js / the catalog rather than a
// planned timeline, so they have nothing to lift into the shared contract.
// ---------------------------------------------------------------------------

test('a chain runs its own scripted length, not a duration the console picked', () => {
  // resolveSelection gives chains duration:'' on purpose — the product decision
  // is that a chain runs its scripted length. The wrapper passes that through
  // as `--duration ''`, and parseArgs turns a valueless flag into boolean true.
  // Testing truthiness alone therefore sent `true` to parseDuration and threw,
  // so EVERY chain exited 4 with lines=0 while the console showed it running.
  const emitPath = path.join(P, 'cc-emit.js');
  const src = fs.readFileSync(emitPath, 'utf8');
  assert.ok(/typeof args\.duration === 'string'/.test(src),
    'a valueless --duration must fall back to the playbook length, not be parsed');
  assert.throws(() => emit.parseDuration(true), /unparseable/,
    'parseDuration should still reject a non-string, so the guard above is load-bearing');
});

test('every chain playbook plans at its own nominal length', () => {
  for (const c of catalog.CHAINS) {
    const pb = load(`chain-${c.key}.json`);
    const plan = emit.planTimeline(pb, {
      rng: emit.makeRng(1), requested: Number(pb.nominal_seconds),
    });
    assert.ok(plan.events.length > 0, `chain ${c.key} produced no events`);
    assert.ok(Number(pb.nominal_seconds) >= emit.minSecondsFor(pb),
      `chain ${c.key} declares a nominal length shorter than its own bursts`);
  }
});
