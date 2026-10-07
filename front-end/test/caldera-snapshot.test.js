/**
 * caldera-snapshot.test.js — Track E, phase E9: the launch snapshot.
 *
 * ############################################################################
 * # NOTHING IN THIS SUITE HAS TOUCHED A REAL CALDERA SERVER, BECAUSE THERE   #
 * # IS NONE. Every ability catalog below is a fixture written by hand. What  #
 * # a green run proves is the one property the snapshot exists for: a key    #
 * # re-derived from a stored record equals the key the launch produced, with #
 * # no server in the loop. It proves nothing about Caldera itself.           #
 * ############################################################################
 *
 * WHAT THIS DEFENDS, AND WHY IT IS ABOUT GRADES
 *
 * A Caldera adversary lives on a shared authoring server that has NO per-object
 * ownership: any instructor who can open the UI can reorder, extend or delete
 * one that three sections have already been graded against. src/incident/
 * scoring.js grades a student's findings against the run's stored answer_key, so
 * a key recompiled from a LATER version of that adversary describes activity
 * that never ran in the lane — every correct answer becomes a miss, every
 * irrelevant one a false positive, and the grades were already issued. Nothing
 * errors and nothing logs.
 *
 *   §1  RE-DERIVATION. A key re-derived from the snapshot equals the live
 *       compile's, WITHOUT the catalog, the server or the adversary still
 *       existing. This is the property; everything else supports it.
 *   §2  THE FREEZE. Mutating the source adversary afterwards must not change the
 *       snapshot. A shallow copy shares its arrays and is not a snapshot.
 *   §3  DRIFT REFUSES. A record that cannot reproduce itself throws rather than
 *       returning a key that grades a different exercise.
 *   §4  THE ANSWER IS NOT IN IT. detection_opportunity and action are stripped,
 *       and the strip provably does not change the key.
 *   §5  THE DIGEST. Evidence that a stored record is still what was launched.
 *   §6  THE NO-SCENARIO PATH, for an adversary authored in Caldera's own UI —
 *       which is what the standalone authoring instance is FOR.
 *   §7  PURITY AND THE STANDING GATES, as source text.
 *
 * Run: node --test test/caldera-snapshot.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SNAPSHOT_PATH = path.join(ROOT, 'src', 'incident', 'caldera', 'snapshot.js');
const snap = require(SNAPSHOT_PATH);
const {
  snapshotAdversary,
  answerKeyFromSnapshot,
  verifySnapshot,
  snapshotDigest,
  canonical,
  clonePlain,
  SnapshotDriftError,
  SNAPSHOT_VERSION,
  MATCHED_BY_ADVERSARY,
} = snap;

const { compileAdversary } = require(path.join(ROOT, 'src', 'incident', 'caldera', 'adversary.js'));
const { buildFactSource } = require(path.join(ROOT, 'src', 'incident', 'caldera', 'fact-source.js'));
const answerKeyMod = require(path.join(ROOT, 'src', 'incident', 'answer-key.js'));

const RUN_ID = '11111111-1111-1111-1111-111111111111';
const OTHER_RUN_ID = '22222222-2222-2222-2222-222222222222';

// ---------------------------------------------------------------------------
// Fixtures — the same shapes test/caldera-adversary.test.js uses
// ---------------------------------------------------------------------------

/** Two abilities share T1003.001 on purpose: ordering is not recoverable from a technique alone. */
function catalog() {
  return [
    {
      ability_id: 'ab-phish-001', technique_id: 'T1566.001', name: 'Spearphishing Attachment',
      tactic: 'initial-access', executors: [{ platform: 'windows' }],
    },
    {
      ability_id: 'ab-psh-001', technique_id: 'T1059.001', name: 'PowerShell one-liner',
      tactic: 'execution', platforms: ['windows'],
    },
    {
      ability_id: 'ab-lsass-002', technique_id: 'T1003.001', name: 'Dump LSASS with comsvcs',
      tactic: 'credential-access', platforms: ['windows'],
    },
    {
      ability_id: 'ab-lsass-001', technique_id: 'T1003.001', name: 'Dump LSASS with procdump',
      tactic: 'credential-access', platforms: ['windows'],
    },
    {
      ability_id: 'ab-discover-001', technique_id: 'T1082', name: 'System information discovery',
      tactic: 'discovery', platforms: ['windows', 'linux'],
    },
    {
      // Parent-only, and LINUX — so it is reachable only with no platform filter
      // and allowParentTechnique on. Both are options the snapshot must capture.
      ability_id: 'ab-validaccount-001', technique_id: 'T1078', name: 'Use a valid account',
      tactic: 'defense-evasion', platforms: ['linux'],
    },
  ];
}

const SCENARIO = {
  scenario_id: 'TS-001',
  name: 'Ransomware via a phished finance user',
  type: 'ransomware',
  attack_path: [
    {
      step: 1, target: 'WS-FIN-01', technique: 'T1566.001',
      action: 'Send an invoice-themed attachment to the finance mailbox',
      detection_opportunity: 'Mail gateway records a macro-enabled attachment from an external sender',
    },
    {
      step: 2, target: 'WS-FIN-01', technique: 'T1059.001',
      action: 'The macro launches an encoded PowerShell downloader',
      detection_opportunity: 'Sysmon event 1 shows winword.exe spawning powershell.exe with -enc',
    },
    {
      step: 3, target: 'WS-FIN-01', technique: 'T1082',
      action: 'Enumerate the host before moving',
      detection_opportunity: 'A burst of systeminfo and whoami inside one second',
    },
    {
      step: 4, target: 'WS-FIN-01', technique: 'T1003.001',
      action: 'Harvest cached credentials from memory',
      detection_opportunity: 'Sysmon event 10 ProcessAccess against lsass.exe from a non-system process',
    },
    {
      step: 5, target: 'FILE-01', technique: 'T1021.001',
      action: 'Move to the file server over RDP',
      detection_opportunity: 'A 4624 type 10 logon to FILE-01 from a workstation that never does that',
    },
    {
      step: 6, target: 'FILE-01', technique: 'T1486',
      action: 'Encrypt the departmental share',
      detection_opportunity: 'Thousands of file renames to a single new extension on one share',
    },
  ],
};

const SPEC = {
  vms: [
    { name: 'DC01', hostname: 'DC01', role: 'dc', os: 'Windows Server 2019' },
    { name: 'FILE01', hostname: 'FILE01', role: 'server', os_family: 'windows_server' },
  ],
  dns: { ad_domain: 'corp.acme.local' },
};

const DEFAULT_OPTIONS = { platform: 'windows', runId: RUN_ID };

/** Compile, then snapshot exactly what was compiled. The launch path, in miniature. */
function launch(over) {
  const o = over || {};
  const abilities = o.abilities || catalog();
  const scenario = 'scenario' in o ? o.scenario : SCENARIO;
  const options = o.options || DEFAULT_OPTIONS;
  const live = compileAdversary({ scenario, abilities, options });
  const factSource = buildFactSource({ scopeLabel: 'CYBR 400 Section 02', scopeKey: 'sec-2', spec: SPEC });
  const record = snapshotAdversary({
    adversary: live.adversary,
    abilities,
    factSource,
    scenario,
    options,
    takenAt: '2026-09-01T12:00:00.000Z',
  });
  return { live, record, abilities, factSource, options };
}

/** Every string anywhere in a value, at any depth, keys included. */
function allStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => allStrings(v, out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) { out.push(k); allStrings(v, out); }
  }
  return out;
}

/** Every KEY anywhere in a value, at any depth. */
function keysOf(value, out = []) {
  if (Array.isArray(value)) value.forEach((v) => keysOf(v, out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) { out.push(k); keysOf(v, out); }
  }
  return out;
}

/** Is every object and array reachable from here frozen? */
function deeplyFrozen(value) {
  if (!value || typeof value !== 'object') return true;
  if (!Object.isFrozen(value)) return false;
  return Object.values(value).every(deeplyFrozen);
}

// ---------------------------------------------------------------------------
// §1 Re-derivation — the property
// ---------------------------------------------------------------------------

test('E9-K1: a key re-derived from the snapshot equals the live compile, field for field', () => {
  const { live, record } = launch();
  assert.deepStrictEqual(answerKeyFromSnapshot(record), live.answerKey);
});

test('E9-K2: re-derivation needs NO catalog, NO server and NO adversary — only the record', () => {
  // The two inputs that live on the Caldera side are the ordering and the
  // resolved ability rows. Both are IN the snapshot, so emptying the catalog and
  // rewriting the adversary must change nothing.
  const abilities = catalog();
  const live = compileAdversary({ scenario: SCENARIO, abilities, options: DEFAULT_OPTIONS });
  const record = snapshotAdversary({
    adversary: live.adversary, abilities, scenario: SCENARIO, options: DEFAULT_OPTIONS,
  });
  const expected = clonePlain(live.answerKey);

  // The server is rebuilt: the catalog is gone, the ability rows with it.
  abilities.length = 0;
  // The instructor edits the adversary in the UI: two more abilities, reordered.
  live.adversary.atomic_ordering.unshift('ab-validaccount-001');
  live.adversary.name = 'renamed mid-term';

  assert.deepStrictEqual(answerKeyFromSnapshot(record), expected);
});

test('E9-K3: two sections a week apart get the SAME exercise under a different run id', () => {
  // This is the second half of what the snapshot buys. Without it, section two's
  // key is compiled from whatever the adversary looks like next Tuesday, and
  // nothing anywhere records what the difference was.
  const { record } = launch();
  const first = answerKeyFromSnapshot(record, { runId: RUN_ID });
  const second = answerKeyFromSnapshot(record, { runId: OTHER_RUN_ID });

  assert.strictEqual(first.run_id, RUN_ID);
  assert.strictEqual(second.run_id, OTHER_RUN_ID);
  assert.deepStrictEqual(second.techniques, first.techniques);
  assert.deepStrictEqual(second.timeline, first.timeline);
  assert.deepStrictEqual(second.adversary_id, first.adversary_id);
});

test('E9-K4: the record carries the resolved ability list, the ordering, platforms and facts', () => {
  const { live, record } = launch();

  assert.deepStrictEqual(record.ordering, live.adversary.atomic_ordering);
  assert.deepStrictEqual(record.abilities.map((a) => a.id), live.adversary.atomic_ordering);
  for (const ability of record.abilities) {
    assert.deepStrictEqual(Object.keys(ability).sort(),
      ['id', 'name', 'platforms', 'tactic', 'technique']);
  }
  // Platforms of the ABILITIES — what this adversary can run on...
  assert.deepStrictEqual(record.platforms, { windows: 4, linux: 1, darwin: 0, unspecified: 0 });
  // ...and the class's own mix, which is the other half of "why did nothing
  // happen" and must not be re-read from a spec that has since been redeployed.
  assert.deepStrictEqual(record.fact_source.platforms, { windows: 2, linux: 0, other: 0 });
  assert.deepStrictEqual(
    record.fact_source.facts.filter((f) => f.trait === 'remote.host.fqdn').map((f) => f.value),
    ['dc01.corp.acme.local', 'file01.corp.acme.local']
  );
  assert.strictEqual(record.taken_at, '2026-09-01T12:00:00.000Z');
  assert.strictEqual(record.version, SNAPSHOT_VERSION);
});

test('E9-K5: an ability the catalog no longer carries is RECORDED, not dropped and not thrown on', () => {
  // A hand-authored adversary can name an ability a later plugin update removed.
  // Refusing to record what was launched is worse than recording the gap.
  const record = snapshotAdversary({
    adversary: { adversary_id: 'adv-1', atomic_ordering: ['ab-psh-001', 'ab-vanished'] },
    abilities: catalog(),
  });
  assert.deepStrictEqual(record.missing_abilities, ['ab-vanished']);
  assert.deepStrictEqual(record.abilities.map((a) => a.id), ['ab-psh-001']);

  const key = answerKeyFromSnapshot(record, { runId: RUN_ID });
  assert.deepStrictEqual(key.techniques.map((t) => t.id), ['T1059.001']);
  assert.strictEqual(key.unmapped_step_count, 1,
    'the gap is graded as an unmapped step, not as activity the student should have found');
});

// ---------------------------------------------------------------------------
// §2 The freeze
// ---------------------------------------------------------------------------

test('E9-K6: mutating the source adversary afterwards does not change the snapshot', () => {
  const abilities = catalog();
  const adversary = compileAdversary({
    scenario: SCENARIO, abilities, options: DEFAULT_OPTIONS,
  }).adversary;
  const record = snapshotAdversary({ adversary, abilities, scenario: SCENARIO, options: DEFAULT_OPTIONS });
  const before = JSON.stringify(record);

  // A shallow copy shares this array, and this is the exact mutation a retry
  // that re-plans, or a UI that lets an instructor tweak before a second launch,
  // performs. It must not rewrite the record of what the FIRST run did.
  adversary.atomic_ordering.push('ab-validaccount-001');
  adversary.atomic_ordering[0] = 'ab-tampered';
  adversary.tags.push('edited');
  abilities[0].name = 'renamed upstream';

  assert.strictEqual(JSON.stringify(record), before);
  assert.strictEqual(record.ordering[0], 'ab-phish-001');
  assert.strictEqual(record.abilities[0].name, 'Spearphishing Attachment');
});

test('E9-K7: the snapshot is DEEPLY frozen — a shallow freeze leaves every array writable', () => {
  const { record } = launch();
  assert.ok(deeplyFrozen(record), 'every object and array in the record must be frozen');

  // Strict mode, so a write to a frozen object throws rather than being ignored.
  assert.throws(() => { record.ordering.push('ab-extra'); }, TypeError);
  assert.throws(() => { record.adversary.atomic_ordering[0] = 'ab-other'; }, TypeError);
  assert.throws(() => { record.abilities[0].technique = 'T9999'; }, TypeError);
  assert.throws(() => { record.digest = 'forged'; }, TypeError);
});

// ---------------------------------------------------------------------------
// §3 Drift refuses
// ---------------------------------------------------------------------------

test('E9-K8: a snapshot that cannot reproduce its own ordering THROWS', () => {
  const { record } = launch();
  const tampered = clonePlain(record);
  tampered.ordering = record.ordering.slice().reverse();

  // There is no safe fallback. Returning the key would grade every student
  // against an operation that did not run.
  assert.throws(
    () => answerKeyFromSnapshot(tampered),
    (err) => {
      assert.ok(err instanceof SnapshotDriftError);
      assert.strictEqual(err.code, 'CALDERA_SNAPSHOT_DRIFT');
      assert.deepStrictEqual(err.detail.recorded, tampered.ordering);
      return true;
    }
  );
});

test('E9-K9: maxAbilitiesPerStep is captured, and it is load-bearing', () => {
  // With 2, the LSASS step contributes BOTH abilities. Re-deriving at the
  // default 1 produces a shorter ability list and a different exercise.
  const options = { platform: 'windows', runId: RUN_ID, maxAbilitiesPerStep: 2 };
  const { live, record } = launch({ options });

  assert.strictEqual(record.options.maxAbilitiesPerStep, 2);
  assert.deepStrictEqual(record.ordering,
    ['ab-phish-001', 'ab-psh-001', 'ab-discover-001', 'ab-lsass-001', 'ab-lsass-002']);
  assert.deepStrictEqual(answerKeyFromSnapshot(record), live.answerKey);

  const forgotten = clonePlain(record);
  forgotten.options.maxAbilitiesPerStep = 1;
  assert.throws(() => answerKeyFromSnapshot(forgotten), SnapshotDriftError);
});

test('E9-K10: allowParentTechnique is captured, and it is load-bearing too', () => {
  // It CHANGES WHAT THE STUDENT MUST REPORT: the key carries the parent
  // technique while the scenario says the sub-technique, and scoring.js matches
  // ids exactly. A snapshot that forgot the flag would re-derive a key missing
  // the step entirely.
  const scenario = {
    scenario_id: 'TS-002',
    name: 'Valid accounts',
    attack_path: [
      { step: 1, technique: 'T1078.003', target: 'FILE-01', action: 'Log in with a local account' },
      { step: 2, technique: 'T1082', target: 'FILE-01', action: 'Look around' },
    ],
  };
  const options = { runId: RUN_ID, allowParentTechnique: true };
  const { live, record } = launch({ scenario, options });

  assert.strictEqual(record.options.allowParentTechnique, true);
  assert.deepStrictEqual(record.ordering, ['ab-validaccount-001', 'ab-discover-001']);
  assert.deepStrictEqual(answerKeyFromSnapshot(record), live.answerKey);

  const forgotten = clonePlain(record);
  forgotten.options.allowParentTechnique = false;
  assert.throws(() => answerKeyFromSnapshot(forgotten), SnapshotDriftError);
});

test('E9-K11: a snapshot written by a NEWER build is refused, not guessed at', () => {
  const { record } = launch();
  const future = clonePlain(record);
  future.version = SNAPSHOT_VERSION + 1;
  assert.throws(
    () => answerKeyFromSnapshot(future),
    (err) => err instanceof SnapshotDriftError && err.detail.supported === SNAPSHOT_VERSION
  );
});

test('E9-K12: something that is not a snapshot is refused before it can grade anything', () => {
  for (const bad of [null, {}, { adversary: {} }, { ordering: [], abilities: [] }]) {
    assert.throws(() => answerKeyFromSnapshot(bad), SnapshotDriftError);
  }
});

// ---------------------------------------------------------------------------
// §4 The answer is not in it
// ---------------------------------------------------------------------------

test('E9-K13: scenario prose never reaches the snapshot, at any depth', () => {
  const { record } = launch();
  const strings = allStrings(record);

  // detection_opportunity is LITERALLY the answer to the exercise — it names the
  // artifact the student is being graded on finding. `action` is the same class
  // of prose.
  for (const step of SCENARIO.attack_path) {
    for (const field of ['action', 'detection_opportunity']) {
      assert.ok(!strings.some((s) => s.includes(step[field])),
        `step ${step.step} ${field} reached the snapshot — that field IS the answer`);
    }
  }
  assert.ok(!keysOf(record).includes('detection_opportunity'), 'no prose KEY survives either');
  assert.ok(!keysOf(record).includes('action'));

  // What the compiler actually reads DOES survive, because re-derivation needs it.
  assert.deepStrictEqual(record.scenario.attack_path[0], {
    step: 1, technique: 'T1566.001', target: 'WS-FIN-01',
  });
  assert.strictEqual(record.scenario.scenario_id, 'TS-001');
});

test('E9-K14: stripping the prose provably does not change the key', () => {
  // This is what makes the strip free rather than a trade: compileAdversary
  // reads action and detection_opportunity for nothing but its own leak guard.
  const abilities = catalog();
  const withProse = compileAdversary({ scenario: SCENARIO, abilities, options: DEFAULT_OPTIONS });
  const stripped = {
    scenario_id: SCENARIO.scenario_id,
    name: SCENARIO.name,
    type: SCENARIO.type,
    attack_path: SCENARIO.attack_path.map((s) => ({
      step: s.step, technique: s.technique, target: s.target,
    })),
  };
  const withoutProse = compileAdversary({ scenario: stripped, abilities, options: DEFAULT_OPTIONS });
  assert.deepStrictEqual(withoutProse.answerKey, withProse.answerKey);
});

// ---------------------------------------------------------------------------
// §5 The digest
// ---------------------------------------------------------------------------

test('E9-K15: a stored record carries a digest of itself, and an edited one fails it', () => {
  const { record } = launch();
  assert.ok(verifySnapshot(record));

  const edited = clonePlain(record);
  edited.ordering[0] = 'ab-swapped';
  assert.ok(!verifySnapshot(edited),
    'a migration or a partial write that changed one field must be visible');

  assert.ok(!verifySnapshot({ ordering: [] }), 'a record with no digest verifies as nothing');
});

test('E9-K16: the digest is stable under key ORDER, so a refactor does not fake a tamper', () => {
  // Key order in JavaScript follows insertion order, so a refactor that assigned
  // two fields the other way round would change the digest of an unchanged
  // record and make every stored snapshot look tampered with.
  assert.strictEqual(
    canonical({ a: 1, b: [2, { d: 4, c: 3 }] }),
    canonical({ b: [2, { c: 3, d: 4 }], a: 1 })
  );
  const one = { version: 1, adversary: { name: 'x', adversary_id: 'y' } };
  const two = { adversary: { adversary_id: 'y', name: 'x' }, version: 1 };
  assert.strictEqual(snapshotDigest(one), snapshotDigest(two));
});

// ---------------------------------------------------------------------------
// §6 The no-scenario path — an adversary authored in Caldera's own UI
// ---------------------------------------------------------------------------

test('E9-K17: an adversary with no scenario still yields a key, from its own ability order', () => {
  // This is the case the standalone authoring instance exists for: the
  // instructor built the adversary in Caldera, so there is no attack path, no
  // step numbers and no targets — the ordered ability list is the whole of it.
  const abilities = catalog();
  const record = snapshotAdversary({
    adversary: {
      adversary_id: 'adv-authored-1',
      name: 'Hand-authored',
      // ab-lsass-002 SORTS AFTER ab-lsass-001 under the same technique. A
      // re-derivation that resolved technique -> ability would silently return
      // ab-lsass-001 here and describe an ability the operation never ran.
      atomic_ordering: ['ab-psh-001', 'ab-lsass-002', 'ab-discover-001'],
    },
    abilities,
  });

  const key = answerKeyFromSnapshot(record, { runId: RUN_ID });
  assert.deepStrictEqual(key.timeline.map((t) => t.ability_ids[0]),
    ['ab-psh-001', 'ab-lsass-002', 'ab-discover-001']);
  assert.deepStrictEqual(key.timeline.map((t) => t.step), [1, 2, 3]);
  assert.ok(key.timeline.every((t) => t.matched_by === MATCHED_BY_ADVERSARY && t.target === null));
  assert.deepStrictEqual(key.techniques.map((t) => t.id), ['T1059.001', 'T1003.001', 'T1082']);
  assert.strictEqual(key.adversary_id, 'adv-authored-1');
  assert.strictEqual(key.scenario_id, null);
});

test('E9-K18: both key paths carry answer-key.js\'s shape — board.js reads them by name', () => {
  // src/incident/board.js hands the key straight to scoring.js. A key that sheds
  // a field grades wrong rather than failing.
  const { live, record } = launch();
  const compiled = answerKeyFromSnapshot(record);
  const authored = answerKeyFromSnapshot(
    snapshotAdversary({ adversary: { adversary_id: 'adv-2', atomic_ordering: ['ab-psh-001'] }, abilities: catalog() }),
    { runId: RUN_ID }
  );

  assert.deepStrictEqual(Object.keys(authored).sort(), Object.keys(live.answerKey).sort());
  assert.deepStrictEqual(Object.keys(compiled).sort(), Object.keys(live.answerKey).sort());

  for (const field of ['version', 'engine', 'run_id', 'techniques', 'iocs', 'timeline',
    'floor_techniques', 'floor_values', 'floor_truncated', 'totals']) {
    assert.ok(field in authored, `answer-key.js emits ${field}; a Caldera key must too`);
  }
  assert.strictEqual(authored.version, answerKeyMod.ANSWER_KEY_VERSION,
    'a stale version here would not refuse at scoring time, it would mis-grade');
  assert.strictEqual(authored.engine, 'caldera');
  // Empty BY DEFINITION for this engine, never by omission — real abilities on
  // real hosts, so the telemetry is not predictable from here.
  assert.deepStrictEqual(authored.iocs, []);
  assert.strictEqual(authored.totals.events, null);
});

// ---------------------------------------------------------------------------
// §7 Purity and the standing gates
// ---------------------------------------------------------------------------

test('E9-K19: the snapshot reaches for no network, no database, no disk, no clock', () => {
  // takenAt is passed IN by the caller that has a clock. A module that stamps
  // its own time cannot be tested for equality against itself.
  const code = fs.readFileSync(SNAPSHOT_PATH, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n');

  const forbidden = [
    ["require('fs')", 'the snapshot must not read the disk'],
    ["require('http", 'the snapshot must not speak HTTP — the record is self-contained'],
    ["require('net')", 'the snapshot must not open sockets'],
    ['fetch(', 're-derivation must never reach back to Caldera'],
    ['axios', 're-derivation must never reach back to Caldera'],
    ['cybercoreQuery', 'the snapshot must not touch a database'],
    ['Date.now(', 'a clock makes the record non-reproducible'],
    ['new Date(', 'a clock makes the record non-reproducible'],
    ['Math.random', 'an RNG makes the digest change on every take'],
  ];
  for (const [needle, why] of forbidden) {
    assert.ok(!code.includes(needle),
      `src/incident/caldera/snapshot.js contains ${JSON.stringify(needle)} — ${why}`);
  }
});

test('E9-K20: core does not require into a plugin, and caldera is still unregistered', () => {
  const code = fs.readFileSync(SNAPSHOT_PATH, 'utf8');
  assert.ok(!/require\(['"][^'"]*modules\/crucible\/plugins\//.test(code),
    'core must never require into a plugin');

  // Snapshotting is record-keeping. It must not make execution reachable.
  const engines = require(path.join(ROOT, 'src', 'incident', 'engines'));
  assert.ok(!engines.registeredEngines().includes('caldera'),
    'recording an adversary must not register an engine — execution waits on the E8 cluster gate');
});

test('E9-K21: no NUL byte in the source', () => {
  // A literal NUL makes grep and ripgrep skip the file SILENTLY, so every
  // source-text gate above would report PASS by never having read it.
  assert.ok(!fs.readFileSync(SNAPSHOT_PATH).includes(0),
    'src/incident/caldera/snapshot.js contains a raw NUL byte');
});
