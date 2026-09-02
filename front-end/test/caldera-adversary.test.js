/**
 * caldera-adversary.test.js — Track E, phase E9: the pure adversary compiler.
 *
 * ############################################################################
 * # NOTHING IN THIS SUITE HAS TOUCHED A REAL CALDERA SERVER, BECAUSE THERE   #
 * # IS NONE. Every ability catalog below is a fixture written by hand from   #
 * # upstream's documented field names. A green run here proves the MAPPING   #
 * # is correct and lossless-in-reporting. It proves NOTHING about whether a  #
 * # real Caldera accepts the adversary this compiler emits — that can only   #
 * # be established against a server, after the E8 cluster gate passes.       #
 * ############################################################################
 *
 * WHAT EACH SECTION DEFENDS
 *
 *   §1  NOTHING IS DROPPED QUIETLY. Every attack-path step that does not reach
 *       `atomic_ordering` appears in BOTH `warnings` and `unmapped`, and its
 *       technique is absent from the answer key. A silently dropped step is an
 *       exercise whose key describes activity that never happened — the class
 *       all "misses" the same question and nothing anywhere logs why.
 *   §2  THE ANSWER NEVER REACHES THE ADVERSARY. `detection_opportunity` is
 *       literally the artifact to hunt for. It must not appear in the adversary
 *       at any depth, and the compiler's own guard must throw rather than
 *       return one that carries it.
 *   §3  SHAPE PARITY WITH answer-key.js. board.js hands the key straight to
 *       scoring.js. If the key sheds a field, a Caldera run grades wrong rather
 *       than failing.
 *   §4  DETERMINISM. Same scenario, same catalog -> byte-identical output,
 *       including when the catalog array arrives in a different order. A
 *       non-deterministic adversary id means a second adversary row on the
 *       server for every relaunch.
 *   §5  ORDERING. The kill chain is the exercise. Impact before initial access
 *       is not a cosmetic defect.
 *   §6  PURITY, as a source-text gate. The catalog is injected precisely so
 *       this module never reaches for a network, a database or the disk.
 *   §7  NO INVENTED ABILITY IDS. Every id in `atomic_ordering` came out of the
 *       injected catalog. An id this compiler made up is a 404 at operation
 *       time, hours after an instructor pressed launch.
 *
 * Run: node --test test/caldera-adversary.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ADVERSARY_PATH = path.join(ROOT, 'src', 'incident', 'caldera', 'adversary.js');
const adversaryMod = require(ADVERSARY_PATH);
const { compileAdversary, AnswerLeakError, UNMAPPED_REASONS } = adversaryMod;

const answerKeyMod = require(path.join(ROOT, 'src', 'incident', 'answer-key.js'));

const RUN_ID = '11111111-1111-1111-1111-111111111111';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * A hand-written catalog in the shape `GET /api/v2/abilities` documents.
 *
 * DELIBERATELY INCOMPLETE. T1486 (ransomware's whole point) and T1021.001 have
 * no ability, because a catalog that covers every technique a profile invents
 * is the one case this compiler never has to survive.
 */
const CATALOG = [
  {
    ability_id: 'ab-phish-001',
    technique_id: 'T1566.001',
    name: 'Spearphishing Attachment',
    tactic: 'initial-access',
    executors: [{ platform: 'windows' }],
  },
  {
    ability_id: 'ab-psh-001',
    technique_id: 'T1059.001',
    name: 'PowerShell one-liner',
    tactic: 'execution',
    platforms: ['windows'],
  },
  {
    ability_id: 'ab-lsass-002',
    technique_id: 'T1003.001',
    name: 'Dump LSASS with comsvcs',
    tactic: 'credential-access',
    platforms: ['windows'],
  },
  {
    ability_id: 'ab-lsass-001',
    technique_id: 'T1003.001',
    name: 'Dump LSASS with procdump',
    tactic: 'credential-access',
    platforms: ['windows'],
  },
  {
    ability_id: 'ab-discover-001',
    technique_id: 'T1082',
    name: 'System information discovery',
    tactic: 'discovery',
    platforms: ['windows', 'linux'],
  },
  {
    // Parent-only. A T1078.003 step must NOT silently ride this one.
    ability_id: 'ab-validaccount-001',
    technique_id: 'T1078',
    name: 'Use a valid account',
    tactic: 'defense-evasion',
    platforms: ['linux'],
  },
];

/** The shape ciab/ai/profile/prompts.js:1169 asks the model for. */
const SCENARIO = {
  scenario_id: 'TS-001',
  name: 'Ransomware via a phished finance user',
  type: 'ransomware',
  threat_actor: 'Opportunistic criminal crew',
  initial_vector: 'Invoice-themed phishing email',
  attack_path: [
    {
      step: 1,
      action: 'Send an invoice-themed attachment to the finance mailbox',
      target: 'WS-FIN-01',
      technique: 'T1566.001',
      detection_opportunity: 'Mail gateway records a macro-enabled attachment from an external sender',
    },
    {
      step: 2,
      action: 'The macro launches an encoded PowerShell downloader',
      target: 'WS-FIN-01',
      technique: 'T1059.001',
      detection_opportunity: 'Sysmon event 1 shows winword.exe spawning powershell.exe with -enc',
    },
    {
      step: 3,
      action: 'Enumerate the host before moving',
      target: 'WS-FIN-01',
      technique: 'T1082',
      detection_opportunity: 'A burst of systeminfo and whoami inside one second',
    },
    {
      step: 4,
      action: 'Harvest cached credentials from memory',
      target: 'WS-FIN-01',
      technique: 'T1003.001',
      detection_opportunity: 'Sysmon event 10 ProcessAccess against lsass.exe from a non-system process',
    },
    {
      step: 5,
      action: 'Move to the file server over RDP',
      target: 'FILE-01',
      technique: 'T1021.001',
      detection_opportunity: 'A 4624 type 10 logon to FILE-01 from a workstation that never does that',
    },
    {
      step: 6,
      action: 'Encrypt the departmental share',
      target: 'FILE-01',
      technique: 'T1486',
      detection_opportunity: 'Thousands of file renames to a single new extension on one share',
    },
  ],
  impacted_assets: ['WS-FIN-01', 'FILE-01'],
  potential_impact: 'Loss of the finance share and several days of downtime',
  likelihood: 'High',
  difficulty_to_detect: 'Medium',
};

const compile = (over = {}) => compileAdversary({
  scenario: over.scenario || SCENARIO,
  abilities: 'abilities' in over ? over.abilities : CATALOG,
  options: { platform: 'windows', runId: RUN_ID, ...(over.options || {}) },
});

/** Every string anywhere in a value, at any depth, keys included. */
function allStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => allStrings(v, out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) { out.push(k); allStrings(v, out); }
  }
  return out;
}

// ---------------------------------------------------------------------------
// §1 Nothing is dropped quietly
// ---------------------------------------------------------------------------

test('E9-A1: every unmapped technique appears in BOTH warnings and unmapped', () => {
  const { warnings, unmapped, adversary, answerKey } = compile();

  // T1021.001 and T1486 have no ability in CATALOG. Both must surface.
  const unmappedTechniques = unmapped.map((u) => u.technique).sort();
  assert.deepStrictEqual(unmappedTechniques, ['T1021.001', 'T1486'],
    'exactly the two uncovered techniques must be reported as unmapped');

  for (const t of unmappedTechniques) {
    assert.ok(warnings.some((w) => w.includes(t)),
      `${t} is in unmapped but no warning names it — a caller that only logs warnings would `
      + 'ship a shortened attack with no sign anything was lost');
    assert.ok(!adversary.atomic_ordering.some((id) => id.includes(t)),
      `${t} must not reach atomic_ordering`);
    assert.ok(!answerKey.techniques.some((k) => k.id === t),
      `${t} must not reach the answer key — the key describes what RUNS, and this does not. `
      + 'A key claiming it would grade every student who correctly found nothing as a miss.');
  }

  // And the inverse direction: nothing was invented into unmapped either.
  const asked = new Set(SCENARIO.attack_path.map((s) => s.technique));
  for (const u of unmapped) assert.ok(asked.has(u.technique), `${u.technique} was never asked for`);
});

test('E9-A2: mapped + unmapped accounts for every attack_path step', () => {
  // The conservation law. If a step is neither in the timeline nor in unmapped,
  // it evaporated — which is precisely the defect this whole file exists for.
  const { answerKey, unmapped } = compile();
  const accounted = new Set([
    ...answerKey.timeline.map((t) => t.step),
    ...unmapped.map((u) => u.step),
  ]);
  for (const s of SCENARIO.attack_path) {
    assert.ok(accounted.has(s.step),
      `step ${s.step} (${s.technique}) is in neither the timeline nor unmapped — it vanished`);
  }
  assert.strictEqual(accounted.size, SCENARIO.attack_path.length);
});

test('E9-A3: an empty catalog unmaps everything and says the adversary is empty', () => {
  const { adversary, warnings, unmapped, answerKey } = compile({ abilities: [] });
  assert.deepStrictEqual(adversary.atomic_ordering, []);
  assert.strictEqual(unmapped.length, SCENARIO.attack_path.length);
  assert.deepStrictEqual(answerKey.techniques, []);
  assert.ok(warnings.some((w) => w.startsWith('CALDERA_CATALOG_EMPTY')),
    'an empty catalog is the exact symptom of a server missing the stockpile plugin and must be named');
  assert.ok(warnings.some((w) => w.startsWith('CALDERA_ADVERSARY_EMPTY')),
    'an adversary that runs nothing must say so — otherwise the operation completes instantly '
    + 'and looks like a successful run in which the student found nothing');
});

test('E9-A4: a sub-technique does NOT silently ride its parent ability', () => {
  // CATALOG carries T1078 but not T1078.003. Mapping the child onto the parent
  // would put T1078 in the key while the student, reading the scenario, reports
  // T1078.003 — and scoring.js:121 matches ids exactly, with no sub-technique
  // collapsing, so every correct answer would score as a false positive.
  const scenario = {
    scenario_id: 'TS-002',
    name: 'Local account abuse',
    attack_path: [{ step: 1, action: 'Reuse a local admin', target: 'SRV-01', technique: 'T1078.003' }],
  };
  const off = compileAdversary({ scenario, abilities: CATALOG, options: { platform: 'linux' } });
  assert.deepStrictEqual(off.adversary.atomic_ordering, []);
  assert.strictEqual(off.unmapped[0].reason, UNMAPPED_REASONS.SUBTECHNIQUE_ONLY_PARENT);
  assert.ok(off.warnings.some((w) => w.includes('T1078') && w.includes('false positive')),
    'the warning must state the grading consequence, not just "unmapped"');

  // Opt in, and the trade is taken loudly and the key carries the PARENT.
  const on = compileAdversary({
    scenario,
    abilities: CATALOG,
    options: { platform: 'linux', allowParentTechnique: true },
  });
  assert.deepStrictEqual(on.adversary.atomic_ordering, ['ab-validaccount-001']);
  assert.deepStrictEqual(on.answerKey.techniques.map((t) => t.id), ['T1078'],
    'the key must carry what the ABILITY runs, not what the scenario asked for');
  assert.ok(on.warnings.some((w) => w.startsWith('CALDERA_TECHNIQUE_MAPPED_BY_PARENT')));
});

test('E9-A5: a technique with abilities on the wrong platform is unmapped, not silently kept', () => {
  const scenario = {
    scenario_id: 'TS-003',
    attack_path: [{ step: 1, technique: 'T1078', target: 'SRV-01' }],
  };
  // ab-validaccount-001 is linux-only; asking for windows must lose the step.
  const out = compileAdversary({ scenario, abilities: CATALOG, options: { platform: 'windows' } });
  assert.deepStrictEqual(out.adversary.atomic_ordering, []);
  assert.strictEqual(out.unmapped[0].reason, UNMAPPED_REASONS.PLATFORM);
  assert.ok(out.warnings.some((w) => w.includes('windows')));
});

test('E9-A6: many-to-one truncation is reported, never silent', () => {
  // T1003.001 has two abilities; maxAbilitiesPerStep defaults to 1. The one left
  // behind is real activity the operation will not perform, and an instructor
  // reading only the adversary would never know it was considered.
  const { warnings } = compile();
  const dropped = warnings.find((w) => w.startsWith('CALDERA_ABILITY_ALTERNATIVES_DROPPED'));
  assert.ok(dropped, 'dropping an alternative ability must produce a warning');
  assert.ok(dropped.includes('ab-lsass-002'), 'the warning must name what was dropped');

  const both = compile({ options: { maxAbilitiesPerStep: 2 } });
  assert.deepStrictEqual(
    both.adversary.atomic_ordering.filter((id) => id.startsWith('ab-lsass')),
    ['ab-lsass-001', 'ab-lsass-002'],
    'raising the cap keeps both, in ability-id order');
  assert.ok(!both.warnings.some((w) => w.startsWith('CALDERA_ABILITY_ALTERNATIVES_DROPPED')));
});

test('E9-A7: a malformed technique id is unmapped with its own reason', () => {
  const scenario = {
    scenario_id: 'TS-004',
    attack_path: [
      { step: 1, technique: 'TA0001', target: 'A' },   // a TACTIC id, not a technique
      { step: 2, technique: '', target: 'B' },
      { step: 3, technique: 'T1082', target: 'C' },
    ],
  };
  const { unmapped, adversary } = compileAdversary({ scenario, abilities: CATALOG });
  assert.deepStrictEqual(unmapped.map((u) => u.reason), [
    UNMAPPED_REASONS.INVALID_TECHNIQUE,
    UNMAPPED_REASONS.MISSING_TECHNIQUE,
  ]);
  assert.deepStrictEqual(adversary.atomic_ordering, ['ab-discover-001']);
});

// ---------------------------------------------------------------------------
// §2 The answer never reaches the adversary
// ---------------------------------------------------------------------------

test('E9-B1: detection_opportunity appears nowhere in the compiled adversary', () => {
  const { adversary } = compile();
  const blob = JSON.stringify(adversary);
  for (const s of SCENARIO.attack_path) {
    assert.ok(!blob.includes(s.detection_opportunity),
      `step ${s.step}'s detection_opportunity is in the adversary. That string IS the answer to `
      + 'the exercise, and the adversary is posted to a server whose UI is not ours.');
  }
  // The key name too — a `detection_opportunity: null` placeholder is one edit
  // away from being populated.
  assert.ok(!allStrings(adversary).includes('detection_opportunity'),
    'the adversary must not even carry the FIELD NAME');
});

test('E9-B2: neither detection_opportunity nor action reaches ANY returned surface', () => {
  // Not only the adversary. `warnings` is the surface most likely to be echoed
  // into an instructor UI and from there into a shared screen, and `unmapped` is
  // the one most likely to be rendered next to a student's board.
  const out = compile();
  const surfaces = { adversary: out.adversary, warnings: out.warnings, unmapped: out.unmapped };
  for (const [name, surface] of Object.entries(surfaces)) {
    const strings = allStrings(surface).join('\u0000');
    for (const s of SCENARIO.attack_path) {
      assert.ok(!strings.includes(s.detection_opportunity),
        `step ${s.step}'s detection_opportunity leaked into ${name}`);
      assert.ok(!strings.includes(s.action),
        `step ${s.step}'s action leaked into ${name} — it is authoring prose describing the `
        + 'intrusion and belongs only in the answer key');
    }
  }
});

test('E9-B3: the answer key carries no prose either — labels come from the ability', () => {
  // answer-key.js:365 makes the same point about its own timeline labels. The
  // key is staff-only, but it is exactly one projection bug from a student, and
  // a label that IS the answer removes the whole exercise rather than part of it.
  const { answerKey } = compile();
  const strings = allStrings(answerKey).join('\u0000');
  for (const s of SCENARIO.attack_path) {
    assert.ok(!strings.includes(s.detection_opportunity),
      `step ${s.step}'s detection_opportunity reached the answer key`);
    assert.ok(!strings.includes(s.action),
      `step ${s.step}'s action reached the answer key`);
  }
  const byStep = new Map(answerKey.timeline.map((t) => [t.step, t]));
  assert.strictEqual(byStep.get(2).label, 'PowerShell one-liner',
    'the label must be the ability name');
});

test('E9-B4: the leak guard THROWS rather than returning a leaking adversary', () => {
  // Simulates the reasonable-looking future edit: an author puts the detection
  // text into a field the adversary happens to carry through. The guard is a
  // backstop for the whitelist, and a backstop that returned a warning would be
  // one nobody reads.
  const leaky = {
    scenario_id: 'TS-005',
    // The NAME is carried into the adversary on purpose (see buildAdversary).
    // If an author puts the detection text there, the compile must refuse.
    name: 'Sysmon event 10 ProcessAccess against lsass.exe from a non-system process',
    attack_path: [{
      step: 1,
      technique: 'T1082',
      target: 'WS-01',
      detection_opportunity: 'Sysmon event 10 ProcessAccess against lsass.exe from a non-system process',
    }],
  };
  assert.throws(() => compileAdversary({ scenario: leaky, abilities: CATALOG }), (err) => {
    assert.ok(err instanceof AnswerLeakError);
    assert.strictEqual(err.code, 'CALDERA_ADVERSARY_ANSWER_LEAK');
    assert.strictEqual(err.field, 'detection_opportunity');
    return true;
  });
});

// ---------------------------------------------------------------------------
// §3 Shape parity with answer-key.js
// ---------------------------------------------------------------------------

test('E9-C1: the caldera key has every field answer-key.js emits', () => {
  // board.js:580 reads the stored key and hands it to scoring.js unchanged, so a
  // missing field does not throw — it grades wrong. That is why this is pinned
  // against a REAL synthetic key rather than a hand-written list.
  const playbookPath = path.join(ROOT, 'src', 'incident', 'playbooks', 'T1082.json');
  const synthetic = answerKeyMod.compileAnswerKey({
    runId: RUN_ID,
    playbook: JSON.parse(fs.readFileSync(playbookPath, 'utf8')),
    requestedSeconds: 300,
  });
  const { answerKey } = compile();

  for (const field of Object.keys(synthetic)) {
    assert.ok(Object.prototype.hasOwnProperty.call(answerKey, field),
      `the caldera key is missing '${field}', which the synthetic key carries and scoring.js reads`);
  }
  for (const field of ['techniques', 'iocs', 'timeline', 'floor_techniques', 'floor_values']) {
    assert.ok(Array.isArray(answerKey[field]), `${field} must be an array, never absent or null`);
  }
  assert.deepStrictEqual(Object.keys(answerKey.totals).sort(),
    Object.keys(synthetic.totals).sort(), 'totals must carry the same three sub-keys');
});

test('E9-C2: the key version is the SAME NUMBER answer-key.js uses', () => {
  // adversary.js holds a literal copy so it stays free of a transitive fs
  // require. scoring.js:227 throws only when a key's version is HIGHER than its
  // own, so a stale copy here would not refuse — it would silently mis-grade
  // against an older shape. This assertion is the only thing that catches it.
  assert.strictEqual(adversaryMod.ANSWER_KEY_VERSION, answerKeyMod.ANSWER_KEY_VERSION,
    'src/incident/caldera/adversary.js ANSWER_KEY_VERSION has drifted from answer-key.js');
});

test('E9-C3: the key is honest about what it cannot predict', () => {
  const { answerKey } = compile();
  assert.strictEqual(answerKey.engine, 'caldera');
  assert.deepStrictEqual(answerKey.iocs, [],
    'an IOC is a value the attack plan uses that the floor cannot produce; a Caldera run has '
    + 'neither plan nor floor, so any listed value would be a guess that penalises a student');
  assert.strictEqual(answerKey.totals.iocs, 0);
  assert.strictEqual(answerKey.totals.events, null,
    'null, not 0 — zero asserts "no events", which is false');
  assert.deepStrictEqual(answerKey.floor_values, []);
  assert.ok(/not predictable/i.test(answerKey.reason),
    'the key must say in its own text why it is partial');

  // But the techniques ARE knowable — an operation runs exactly its abilities —
  // and scoring.js:230 treats a key with techniques and no IOCs as gradable.
  assert.ok(answerKey.techniques.length > 0);
  assert.strictEqual(answerKey.totals.techniques, answerKey.techniques.length);
});

test('E9-C4: the key records what was lost, so a console can show 4-of-6', () => {
  const { answerKey } = compile();
  assert.deepStrictEqual(answerKey.unmapped_techniques, ['T1021.001', 'T1486']);
  assert.strictEqual(answerKey.unmapped_step_count, 2);
  assert.strictEqual(answerKey.adversary_id, compile().adversary.adversary_id);
});

// ---------------------------------------------------------------------------
// §4 Determinism
// ---------------------------------------------------------------------------

test('E9-D1: the same inputs compile byte-identically', () => {
  const a = JSON.stringify(compile());
  const b = JSON.stringify(compile());
  assert.strictEqual(a, b, 'compileAdversary must be a pure function of its arguments');
});

test('E9-D2: catalog ARRAY ORDER does not change the output', () => {
  // A catalog is an array off an HTTP response; its order is whatever the server
  // felt like. If order leaked into the result, the same scenario would compile
  // to two different adversaries on two different days and the server would grow
  // a duplicate for each.
  const reversed = CATALOG.slice().reverse();
  assert.strictEqual(
    JSON.stringify(compile()),
    JSON.stringify(compile({ abilities: reversed })),
    'reversing the injected catalog changed the compile');
});

test('E9-D3: the adversary id is derived from the compile, not from a clock or an RNG', () => {
  const id = compile().adversary.adversary_id;
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    'a name-based (v5) UUID, so relaunching addresses the same adversary instead of making a second');
  assert.strictEqual(compile().adversary.adversary_id, id);

  // A different ability list is a different operation and must be a different id.
  const shorter = compile({
    scenario: { ...SCENARIO, attack_path: SCENARIO.attack_path.slice(0, 2) },
  });
  assert.notStrictEqual(shorter.adversary.adversary_id, id);
});

// ---------------------------------------------------------------------------
// §5 Ordering
// ---------------------------------------------------------------------------

test('E9-E1: atomic_ordering follows the declared step order, not array order', () => {
  const shuffled = {
    ...SCENARIO,
    attack_path: [
      SCENARIO.attack_path[3],   // step 4, T1003.001
      SCENARIO.attack_path[0],   // step 1, T1566.001
      SCENARIO.attack_path[2],   // step 3, T1082
      SCENARIO.attack_path[1],   // step 2, T1059.001
    ],
  };
  const { adversary, answerKey } = compile({ scenario: shuffled });
  assert.deepStrictEqual(adversary.atomic_ordering,
    ['ab-phish-001', 'ab-psh-001', 'ab-discover-001', 'ab-lsass-001'],
    'a kill chain that runs credential dumping before initial access is not a cosmetic defect');
  assert.deepStrictEqual(answerKey.timeline.map((t) => t.step), [1, 2, 3, 4]);
});

test('E9-E2: with any step number missing, ARRAY order is used for all of them', () => {
  // Mixing the two orderings interleaves them, which is worse than either.
  const mixed = {
    scenario_id: 'TS-006',
    attack_path: [
      { step: 9, technique: 'T1082' },
      { technique: 'T1059.001' },
      { step: 1, technique: 'T1566.001' },
    ],
  };
  const { adversary, warnings } = compileAdversary({ scenario: mixed, abilities: CATALOG });
  assert.deepStrictEqual(adversary.atomic_ordering,
    ['ab-discover-001', 'ab-psh-001', 'ab-phish-001']);
  assert.ok(warnings.some((w) => w.startsWith('CALDERA_STEP_ORDER_MIXED')));
});

test('E9-E3: the key techniques are in first-appearance order', () => {
  // scoring.js correlates the student's claimed ordering against key.techniques'
  // order with Kendall tau, so this array IS the graded truth about sequence.
  const { answerKey } = compile();
  assert.deepStrictEqual(answerKey.techniques.map((t) => t.id),
    ['T1566.001', 'T1059.001', 'T1082', 'T1003.001']);
});

// ---------------------------------------------------------------------------
// §6 Purity, as a source-text gate
// ---------------------------------------------------------------------------

test('E9-F1: the compiler reaches for no network, no database, no disk, no clock', () => {
  // The catalog is INJECTED precisely so this holds. A fetch added here would
  // make the module untestable without a server that does not exist, and would
  // couple the compiler to one server's plugin set.
  //
  // Comments are stripped first, the same doctrine as ciab-deploy-parity.test.js
  // and incident-engine-locality.test.js: this file's own header discusses
  // "no network, no database, no fs" at length and would otherwise fail itself.
  const code = fs.readFileSync(ADVERSARY_PATH, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n');

  const forbidden = [
    ["require('fs')", 'the compiler must not read the disk'],
    ["require('http", 'the compiler must not speak HTTP — the catalog is injected'],
    ["require('net')", 'the compiler must not open sockets'],
    ['fetch(', 'the compiler must not fetch the ability catalog'],
    ['axios', 'the compiler must not fetch the ability catalog'],
    ['cybercoreQuery', 'the compiler must not touch a database'],
    ['Date.now(', 'a clock makes the compile non-deterministic'],
    ['new Date(', 'a clock makes the compile non-deterministic'],
    ['Math.random', 'an RNG makes the adversary id change on every launch'],
  ];
  for (const [needle, why] of forbidden) {
    assert.ok(!code.includes(needle),
      `src/incident/caldera/adversary.js contains ${JSON.stringify(needle)} — ${why}`);
  }
});

test('E9-F2: core does not require into a plugin, and caldera is still unregistered', () => {
  // The first half is the standing rule for everything under src/. The second is
  // this phase's own guard rail: E9 ships the bake and the compiler ONLY. An
  // engine adapter must not appear until the E8 cluster gate has passed, and
  // registering 'caldera' early would let a route dispatch a run against a
  // server nobody has stood up.
  const code = fs.readFileSync(ADVERSARY_PATH, 'utf8');
  assert.ok(!/require\(['"][^'"]*modules\/crucible\/plugins\//.test(code),
    'core must never require into a plugin');

  const engines = require(path.join(ROOT, 'src', 'incident', 'engines'));
  assert.ok(!engines.registeredEngines().includes('caldera'),
    'compiling an adversary must not register an engine — the adapter is a later phase');
});

// ---------------------------------------------------------------------------
// §7 No invented ability ids
// ---------------------------------------------------------------------------

test('E9-G1: every id in atomic_ordering came out of the injected catalog', () => {
  // An invented id is a 404 at operation-create time, hours after an instructor
  // pressed launch and with the class already sitting in front of Kibana.
  const known = new Set(CATALOG.map((a) => a.ability_id));
  const { adversary, answerKey } = compile();
  for (const id of adversary.atomic_ordering) {
    assert.ok(known.has(id), `${id} is not in the injected catalog`);
  }
  for (const entry of answerKey.timeline) {
    for (const id of entry.ability_ids) assert.ok(known.has(id), `${id} is not in the catalog`);
  }
  assert.strictEqual(
    adversary.atomic_ordering.length,
    answerKey.timeline.reduce((n, t) => n + t.ability_ids.length, 0),
    'the timeline must account for exactly the abilities the adversary will run');
});

test('E9-G2: both documented catalog shapes normalize to the same ability', () => {
  // A catalog from GET /api/v2/abilities and one read out of a stockpile YAML
  // use different field names. Accepting only one would mean the tests exercise
  // a different code path than production, which is how a mapping bug survives
  // a green suite.
  const fromApi = adversaryMod.normalizeAbility({
    ability_id: 'x', technique_id: 't1082', name: 'Discovery',
    tactic: 'discovery', executors: [{ platform: 'Windows' }, { platform: 'linux' }],
  });
  const fromYaml = adversaryMod.normalizeAbility({
    id: 'x', technique: 'T1082', name: 'Discovery',
    tactic: 'discovery', platforms: ['linux', 'windows'],
  });
  assert.deepStrictEqual(fromApi, fromYaml);
  assert.deepStrictEqual(fromApi.platforms, ['linux', 'windows'], 'platforms are sorted');
  assert.strictEqual(adversaryMod.normalizeAbility({ id: 'y' }), null,
    'a row with no technique cannot be mapped and must be dropped, with a warning from the caller');
});

test('E9-G3: a structurally invalid scenario throws rather than compiling to nothing', () => {
  // The distinction that matters: "no step mapped" is a real outcome the caller
  // must handle, so it warns. "there is no attack path" is a caller bug, and
  // returning an empty adversary for it would let something launch an operation
  // built from nothing at all.
  assert.throws(() => compileAdversary({ scenario: null, abilities: CATALOG }), TypeError);
  assert.throws(() => compileAdversary({ scenario: { scenario_id: 'x' }, abilities: CATALOG }),
    /attack_path must be an array/);
});
