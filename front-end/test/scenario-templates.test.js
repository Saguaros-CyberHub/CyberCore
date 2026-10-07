// ============================================================================
// scenario-templates: the tactic table stays inside the benign floor.
//
// src/incident/scenario-templates.js is the raw material the E4 compiler turns
// into playbook steps for techniques that have no hand-written playbook. It is a
// hand-maintained mirror of facts that live in host-baseline.json -- which pairs
// the floor emits, which host pool it emits them on, which metadata values it
// already uses -- and a mirror drifts.
//
// So this file does NOT re-state those facts. It DERIVES them from the floor and
// fails if the table has wandered outside. A source pair, a metadata value or an
// address space that only ever occurs during an attack is one terms aggregation
// away from ending the exercise (see test/helpers/playbook-contract.js), and the
// table is where that mistake would be made.
//
// The last two tests assemble a PROBE playbook out of every variant in the table
// at once and put it through the shared contract. That is not the compiler -- it
// is the cheapest possible stand-in for one, and it catches an unresolvable
// token or a message that states its own conclusion here, in this file, rather
// than on a lane in week nine.
// ============================================================================
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const contract = require('./helpers/playbook-contract.js');

const P = path.join(__dirname, '..', 'src', 'incident');
const T = require(path.join(P, 'scenario-templates.js'));

const floor = JSON.parse(
  fs.readFileSync(path.join(P, 'playbooks', 'host-baseline.json'), 'utf8')
);

// ---------------------------------------------------------------------------
// What the floor actually is, sampled once. Everything below is measured
// against THIS, never against a list copied out of the playbook by hand.
// ---------------------------------------------------------------------------
const floorPlan = contract.planOf(floor, { label: 'host-baseline.json' });

const FLOOR_PAIRS = new Set(floorPlan.events.map((e) => `${e.source.type}/${e.source.name}`));
const FLOOR_HOSTS = new Set(floorPlan.events.map((e) => e.source.host));
const FLOOR_POOLS = new Set(Object.keys(floor.pools || {}));

const FLOOR_VOCAB = new Map();
const FLOOR_ALL_VALUES = new Set();
for (const ev of floorPlan.events) {
  for (const [k, v] of Object.entries(ev.metadata || {})) {
    if (typeof v !== 'string' && typeof v !== 'number') continue;
    if (!FLOOR_VOCAB.has(k)) FLOOR_VOCAB.set(k, new Set());
    FLOOR_VOCAB.get(k).add(String(v));
    FLOOR_ALL_VALUES.add(String(v));
  }
}

const entries = () => T.KILL_CHAIN.map((id) => [id, T.TACTIC_TEMPLATES[id]]);
const variants = function* () {
  for (const [id, entry] of entries()) {
    for (const [i, v] of entry.variants.entries()) yield [`${id}#${i}`, v, entry];
  }
};

/**
 * One playbook containing every variant in the table.
 *
 * Entities are bound exactly as REQUIRED_ENTITIES says the compiler must bind
 * them -- adversary in a space the floor already uses, foothold in the lane
 * band, victim and account out of the floor's own pools. A probe that cheated on
 * any of those would prove nothing, because those bindings are half the contract.
 */
function probePlaybook() {
  const steps = [];
  for (const [, v, entry] of variants()) {
    const d = Object.assign({}, entry.defaults, v.defaults || {});
    steps.push({
      gap: '0s',
      spread: d.spread,
      // Not d.count: the probe exists to exercise every TEMPLATE, not to
      // reproduce a realistic burst, and 44 steps at full count is 3,000 events
      // of nothing new.
      count: 30,
      level: d.level,
      source: v.source,
      metadata: v.metadata,
      templates: v.templates,
      technique: 'T1059',
      tactic: entry.id,
      subtechnique: null,
      overlap: false,
    });
  }
  return {
    name: 'tactic-template probe',
    story: 'Every variant in TACTIC_TEMPLATES, once.',
    nominal_seconds: steps.reduce((a, s) => a + contract.emit.parseDuration(s.spread), 0),
    entities: {
      source_ip: { ipv4Host: '203.0.113' },
      pivot_ip: { ipv4Host: '10.20.30' },
      target: { oneOf: floor.pools.hosts },
      actor: { oneOf: floor.pools.users },
    },
    pools: floor.pools,
    bindings: floor.bindings,
    skewed: floor.skewed,
    steps,
  };
}

// ---------------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------------

test('every kill-chain tactic has a template entry, and every entry a chain slot', () => {
  // A tactic in the chain with no entry is a step the compiler cannot build; an
  // entry outside the chain is one it will never reach. Both are silent.
  for (const id of T.KILL_CHAIN) {
    assert.ok(T.TACTIC_TEMPLATES[id], `KILL_CHAIN lists ${id} but there is no template entry`);
  }
  for (const id of Object.keys(T.TACTIC_TEMPLATES)) {
    assert.ok(T.KILL_CHAIN.includes(id), `TACTIC_TEMPLATES has ${id}, which is not in KILL_CHAIN`);
    assert.strictEqual(T.TACTIC_TEMPLATES[id].id, id, `${id} entry disagrees about its own id`);
    assert.strictEqual(T.TACTIC_TEMPLATES[id].phase, T.KILL_CHAIN.indexOf(id),
      `${id}.phase disagrees with its position in KILL_CHAIN`);
  }
});

test('every variant carries the timing and weighting a step needs', () => {
  for (const [label, v, entry] of variants()) {
    const d = Object.assign({}, entry.defaults, v.defaults || {});
    assert.ok(Number(d.count) > 0, `${label} has no usable count`);
    assert.ok(['INFO', 'WARN', 'ERROR'].includes(d.level), `${label} level ${d.level}`);
    // gap is ELASTIC and spread is RIGID. A step with no spread collapses its
    // whole burst onto one instant, which is not a burst, it is a spike.
    assert.ok(contract.emit.parseDuration(d.spread) > 0, `${label} has no spread`);
    assert.ok(contract.emit.parseDuration(d.gap) >= 0, `${label} has an unparseable gap`);
    assert.ok(Array.isArray(v.templates) && v.templates.length > 0, `${label} has no templates`);
    for (const tpl of v.templates) {
      assert.ok(typeof tpl.message === 'string' && tpl.message.length > 0, `${label} empty message`);
      assert.ok(Number(tpl.weight) > 0, `${label} template weight must be positive`);
    }
  }
});

// ---------------------------------------------------------------------------
// Inside the floor. These are the anti-oracle assertions, applied statically.
// ---------------------------------------------------------------------------

test('every template source is a (type, name) pair the benign floor already emits', () => {
  // The pair is what a student sees in Discover's field list. A pair that only
  // occurs during an attack is one terms agg away from ending the exercise, and
  // it would review as working.
  for (const [label, v] of variants()) {
    const pair = `${v.source.type}/${v.source.name}`;
    assert.ok(FLOOR_PAIRS.has(pair),
      `${label} emits ${pair}, which never occurs in benign traffic`);
  }
});

test('every template host is a floor pool or the victim entity, never a bare name', () => {
  // Bare hostnames are the trap E4 exists to avoid: a compiled scenario naming
  // DC01 directly, on an estate whose floor only ever says web-01, hands the
  // answer over on loggen.source.host.
  for (const [label, v] of variants()) {
    const host = v.source.host;
    const m = /^\{\{([a-zA-Z0-9_]+)\}\}$/.exec(String(host));
    assert.ok(m, `${label} host ${host} is not a single token`);
    const name = m[1];
    assert.ok(FLOOR_POOLS.has(name) || Object.prototype.hasOwnProperty.call(T.REQUIRED_ENTITIES, name),
      `${label} draws its host from {{${name}}}, which is neither a floor pool nor a declared entity`);
    if (FLOOR_POOLS.has(name)) {
      for (const value of floor.pools[name]) {
        assert.ok(FLOOR_HOSTS.has(String(value)),
          `${label} host pool ${name} contains ${value}, which the floor never emits as a source.host`);
      }
    }
  }
});

test('every token is a floor pool, a declared entity, or a cc-emit builtin', () => {
  // An unresolvable token ships literal "{{users}}" to Kibana -- exactly the
  // "{clientIP}" tell log-generator has at the pinned commit. cc-emit leaves it
  // intact rather than printing "undefined", so it fails loudly here instead.
  for (const [id, entry] of entries()) {
    for (const token of T.tokensIn(entry)) {
      const known = FLOOR_POOLS.has(token)
        || Object.prototype.hasOwnProperty.call(T.REQUIRED_ENTITIES, token)
        || T.BUILTIN_TOKENS.includes(token);
      assert.ok(known, `${id} references {{${token}}}, which nothing will resolve`);
    }
  }
});

test('every literal metadata value already occurs in the benign floor', () => {
  // The oracle that ran for a semester: the floor shipped event_action:"routine"
  // on every step while the playbooks used 33 other values, so
  //     NOT loggen.metadata.event_action : "routine"
  // returned every attack event and no benign one. Subset, not overlap -- ONE
  // attack-only value is a complete filter by itself.
  const leaks = [];
  const check = (label, md) => {
    for (const [k, v] of Object.entries(md || {})) {
      const value = String(v);
      if (value.includes('{{')) continue; // resolved from a floor pool at plan time
      const perField = FLOOR_VOCAB.get(k) || new Set();
      if (!perField.has(value) && !FLOOR_ALL_VALUES.has(value)) {
        leaks.push(`${label} ${k}=${value}`);
      }
    }
  };
  for (const [label, v] of variants()) {
    check(label, v.metadata);
    for (const [i, tpl] of v.templates.entries()) check(`${label} tpl${i}`, tpl.metadata);
  }
  assert.deepStrictEqual(leaks, [],
    `attack-only metadata values are one-click answer keys:\n  ${leaks.join('\n  ')}`);
});

test('no template message or metadata states the conclusion', () => {
  // Checked statically as well as on planned events, because this failure is
  // about the WORDS -- naming it here points at the template that has to change,
  // not at one of 1,300 expanded events that happened to sample it.
  for (const [label, v] of variants()) {
    for (const tpl of v.templates) {
      assert.ok(!contract.VERDICT.test(tpl.message),
        `${label} states its own conclusion: ${tpl.message.slice(0, 110)}`);
      for (const [k, val] of Object.entries(tpl.metadata || {})) {
        assert.ok(!contract.VERDICT.test(String(val)), `${label} template metadata ${k}=${val}`);
      }
    }
    for (const [k, val] of Object.entries(v.metadata || {})) {
      assert.ok(!contract.VERDICT.test(String(val)), `${label} metadata ${k}=${val}`);
    }
  }
});

// ---------------------------------------------------------------------------
// TECHNIQUE_TO_TACTIC
// ---------------------------------------------------------------------------

test('the technique map is well formed end to end', () => {
  for (const [tech, tactic] of Object.entries(T.TECHNIQUE_TO_TACTIC)) {
    assert.strictEqual(T.normalizeTechnique(tech), tech, `${tech} is not a canonical technique id`);
    assert.ok(T.TACTIC_TEMPLATES[tactic], `${tech} maps to ${tactic}, which has no templates`);
  }
});

test('a sample of real technique ids resolves to the tactic that tells its story', () => {
  // A profile names arbitrary real IDs. Most have no playbook in playbooks/ --
  // that is the whole reason this table exists, so the sample is deliberately
  // weighted toward techniques we have never written a file for.
  const expected = {
    'T1566.001': 'TA0001', // spearphishing attachment -- no playbook
    T1190: 'TA0001',
    'T1078.003': 'TA0001',
    'T1059.001': 'TA0002', // PowerShell -- no playbook
    'T1053.005': 'TA0003',
    'T1547.001': 'TA0003',
    'T1548.003': 'TA0004',
    'T1562.001': 'TA0005',
    'T1070.004': 'TA0005',
    'T1003.001': 'TA0006', // LSASS dumping -- no playbook
    'T1110.003': 'TA0006',
    'T1558.003': 'TA0006',
    T1082: 'TA0007',
    T1018: 'TA0007',
    'T1021.001': 'TA0008',
    'T1550.002': 'TA0008',
    T1005: 'TA0009',
    T1213: 'TA0009',
    'T1071.001': 'TA0011',
    T1105: 'TA0011',
    T1041: 'TA0010',
    'T1048.003': 'TA0010',
    T1486: 'TA0040', // ransomware -- no playbook
    T1490: 'TA0040',
    T1496: 'TA0040',
  };
  for (const [tech, tactic] of Object.entries(expected)) {
    const got = T.tacticFor(tech);
    assert.strictEqual(got.tactic, tactic, `${tech} resolved to ${got.tactic}, want ${tactic}`);
    assert.strictEqual(got.mapped, true, `${tech} should be a mapped technique, not a guess`);
    assert.ok(/^TA\d{4}$/.test(got.tactic));
  }
});

test('an unlisted sub-technique inherits its parent rather than being guessed', () => {
  // T1566.009 is not in the map and never will be; T1566 is. Inheriting keeps a
  // profile that names a niche sub-technique out of the fallback path entirely.
  const got = T.tacticFor('T1566.009');
  assert.strictEqual(got.tactic, 'TA0001');
  assert.strictEqual(got.reason, 'parent');
  assert.strictEqual(got.mapped, true);

  // Humans type profiles. Normalisation is what turns most would-be fallbacks
  // back into exact hits.
  assert.strictEqual(T.tacticFor(' t1486 ').tactic, 'TA0040');
  assert.strictEqual(T.tacticFor('T1003.001 (LSASS Memory)').reason, 'exact');
  assert.strictEqual(T.normalizeTechnique('not-a-technique'), null);
});

test('the fallback is deterministic, lands in the kill chain, and says it guessed', () => {
  const unknown = 'T9998.001';
  assert.strictEqual(T.TECHNIQUE_TO_TACTIC[unknown], undefined, 'fixture must stay unmapped');

  // No position hint: the documented default, every time.
  const bare = T.tacticFor(unknown);
  assert.strictEqual(bare.tactic, T.FALLBACK_TACTIC);
  assert.strictEqual(bare.reason, 'default');
  assert.strictEqual(bare.mapped, false, 'a guess must be reported as a guess so the compiler can warn');
  assert.deepStrictEqual(T.tacticFor(unknown), bare, 'same input, same answer');

  // With a position hint: spread evenly across TA0001..TA0040. First slot is the
  // entry vector, last is impact -- an unknown technique a profile lists first is
  // far more likely to be how they got in than how it ended.
  const total = 6;
  const first = T.tacticFor(unknown, { position: 0, total });
  const last = T.tacticFor(unknown, { position: total - 1, total });
  assert.strictEqual(first.tactic, T.FALLBACK_CHAIN[0]);
  assert.strictEqual(last.tactic, T.FALLBACK_CHAIN[T.FALLBACK_CHAIN.length - 1]);
  assert.strictEqual(first.reason, 'position');
  assert.strictEqual(first.mapped, false);

  for (let i = 0; i < total; i += 1) {
    const got = T.tacticFor(unknown, { position: i, total });
    assert.deepStrictEqual(T.tacticFor(unknown, { position: i, total }), got, 'not deterministic');
    assert.ok(T.FALLBACK_CHAIN.includes(got.tactic), `fallback produced ${got.tactic}`);
    // Never Recon or Resource Development: those happen on the adversary's own
    // kit and would compile to a phase that emits almost nothing.
    assert.ok(!['TA0043', 'TA0042'].includes(got.tactic));
    assert.ok(T.TACTIC_TEMPLATES[got.tactic], 'fallback must land on a tactic we can build');
  }

  // Garbage in still yields a buildable tactic. "The profile said something odd"
  // must degrade to a slightly generic exercise, never to a 500.
  for (const bad of [null, undefined, '', 'TTPs?', 42, {}]) {
    const got = T.tacticFor(bad);
    assert.ok(T.TACTIC_TEMPLATES[got.tactic], `tacticFor(${JSON.stringify(bad)}) must still build`);
    assert.strictEqual(got.mapped, false);
  }
});

test('kill-chain order narrates a campaign, and C2 precedes exfiltration', () => {
  // The channel exists before anything leaves through it. TA0010 sorts before
  // TA0011 numerically, which is why this is asserted rather than assumed.
  assert.ok(T.tacticIndex('TA0011') < T.tacticIndex('TA0010'));
  assert.ok(T.tacticIndex('TA0001') < T.tacticIndex('TA0040'));
  assert.strictEqual(T.tacticIndex('ta0006'), T.KILL_CHAIN.indexOf('TA0006'));
  assert.strictEqual(T.tacticIndex('TA9999'), -1);
});

// ---------------------------------------------------------------------------
// The whole table, through the shared contract
// ---------------------------------------------------------------------------

test('a playbook built from every variant clears the playbook contract', () => {
  const pb = probePlaybook();
  const opts = { label: 'tactic-template probe' };
  contract.assertNoUnresolvedTokens(pb, opts);
  contract.assertSixKeyEnvelope(pb, opts);
  contract.assertEveryAttackEventTagged(pb, opts);
  contract.assertGrepSerialization(pb, opts);
  contract.assertNoSelfContradiction(pb, opts);
  contract.assertStatesNoConclusion(pb, opts);
  contract.assertDeterministicPerRunId(pb, opts);
});

test('a playbook built from every variant hides inside the benign floor', () => {
  // The composite: source pairs, metadata vocabularies AND address spaces, all
  // three against the shipped floor. If the compiler can only ever draw on this
  // table, then clearing this is what makes a compiled scenario un-filterable.
  contract.assertFloorCoversAttackValues(floor, {
    floorPlan,
    attacks: [{ playbook: probePlaybook(), label: 'tactic-template probe' }],
  });
});
