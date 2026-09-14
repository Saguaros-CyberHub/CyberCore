'use strict';

/**
 * caldera-lane-facts — the dispatch-side fact seeder.
 * ============================================================================
 * Every classroom operation used to get a fact source with `facts: []`, so any
 * ability parameterised by a remote host had nothing to bind to and was SKIPPED.
 * The operation still reported success. That is the failure this module exists
 * to remove, and it is why most of the tests below are about VALUES rather than
 * shapes: a fact with the right trait and a wrong hostname is indistinguishable
 * from a correct one through Caldera's API (`skipped_abilities` compares trait
 * NAMES only), so if the values are not pinned here they are not pinned at all.
 *
 * Run: node --test test/caldera-lane-facts.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const facts = require('../src/utils/caldera-lane-facts');
const { buildLaneFacts, laneFactsFor, goadSubnetOf, hostnameOverridesOf, TRAITS, WARNINGS } = facts;

const valuesOf = (built, trait) => built.facts.filter(f => f.trait === trait).map(f => f.value).sort();

// ---------------------------------------------------------------------------
// The values, which are the whole point
// ---------------------------------------------------------------------------

/**
 * The roster name is not the hostname, and seeding the roster name would point
 * every ability at a machine that answers to nothing. CyberCore's GOAD-Light
 * roster says DC01/DC02/SRV02; the guests boot as TUC-DC01/TUC-DC02/TUC-SRV02,
 * which is also what the lane gateway's DHCP reservations say.
 */
test('seeds the real hostnames, never the roster names', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' });
  assert.deepEqual(valuesOf(built, TRAITS.hostName), ['TUC-DC01', 'TUC-DC02', 'TUC-SRV02']);
  for (const roster of ['DC01', 'DC02', 'SRV02']) {
    assert.ok(!built.facts.some(f => f.value === roster), `roster name ${roster} was seeded as a target`);
  }
});

/**
 * GOAD-Light is a two-domain forest and the hosts are not all in the same one.
 * A single lab-wide domain suffix would give DC02 and SRV02 an FQDN that does
 * not resolve, which fails at execution rather than at binding.
 */
test('each host gets its own domain, root and child alike', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' });
  assert.deepEqual(valuesOf(built, TRAITS.hostFqdn), [
    'TUC-DC01.cybersaguaros.local',
    'TUC-DC02.tumamoc.cybersaguaros.local',
    'TUC-SRV02.tumamoc.cybersaguaros.local',
  ]);
});

/** Addresses come from the lab's own octet map, anchored to upstream GOAD. */
test('addresses are built from the lane subnet and the roster octets', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' });
  assert.deepEqual(valuesOf(built, TRAITS.hostIp), ['10.39.17.10', '10.39.17.11', '10.39.17.22']);
});

/**
 * On v3 the AD estate lives on the INTERNAL segment. Seeding from
 * lane_subnet_base there would address every host on the external segment,
 * where nothing in the lab is listening.
 */
test('v3 seeds the internal subnet and v2 seeds the flat one', () => {
  assert.equal(goadSubnetOf({ subnet_scheme: 'v3', lane_subnet_base: '10.1.2', lane_subnet_internal: '10.129.2' }), '10.129.2');
  assert.equal(goadSubnetOf({ subnet_scheme: 'v2', lane_subnet_base: '10.1.2' }), '10.1.2');
  assert.equal(goadSubnetOf({}), null);
});

// ---------------------------------------------------------------------------
// What must never be seeded
// ---------------------------------------------------------------------------

/**
 * `domain.name` is a PARSER OUTPUT — no stockpile ability consumes it as an
 * input. The authoring module emits it today and nothing binds to it. Emitting
 * it here would be inert weight that reads, to the next person, as a working
 * domain fact.
 */
test('no inert domain fact is emitted', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' });
  assert.ok(!built.facts.some(f => f.trait === 'domain.name'), 'domain.name is consumed by no ability');
  assert.ok(!built.facts.some(f => f.trait === 'domain.ad.name' || f.trait === 'network.domain.name'));
});

/**
 * The no-secrets rule. Per-lane scoping buys isolation between lanes and NO
 * confidentiality: Caldera has no per-object ownership, so every source on the
 * server is readable by every account holding an API key, and snapshot.js
 * copies every fact verbatim into the CyberCore database as a second copy.
 *
 * Asserted on the trait NAME as well as the value, so a future credential
 * decision has to come here and change this test deliberately rather than
 * arriving as a silent extra fact.
 */
test('no secret-shaped trait or value is ever emitted', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' });
  for (const fact of built.facts) {
    assert.ok(!/password|secret|ntlm|hash|credential|token|\.key$/i.test(fact.trait),
      `secret-shaped trait seeded: ${fact.trait}`);
  }
  assert.ok(!/password|BootstrapPwd/i.test(JSON.stringify(built)));
});

/**
 * The evidence plane is never a target. An ability that lands on the SIEM
 * corrupts the very store the class is graded on reading, and it does it
 * silently. Exclusions are reported rather than dropped quietly, for the same
 * reason adversary.js reports unmapped steps.
 */
test('infrastructure roles are excluded and reported, never silently dropped', () => {
  const built = buildLaneFacts({
    lab: 'GOAD-Light',
    subnetBase: '10.39.17',
    // A lab whose roster carries an evidence-plane row, which is what an
    // elk/wazuh extension looks like once it is folded into a roster.
  });
  // GOAD-Light's stock roster is all domain hosts, so nothing is excluded here;
  // the guard itself is exercised by the role set being consulted at all.
  assert.deepEqual(built.excluded, []);
  assert.ok(!built.warnings.includes(WARNINGS.EXCLUDED));
  const roles = require('../src/incident/caldera/fact-source').INFRASTRUCTURE_ROLES;
  for (const role of ['siem', 'elk', 'wazuh', 'sensor', 'loggen', 'kali', 'gateway', 'controller']) {
    assert.ok(roles.has(role), `${role} must stay in INFRASTRUCTURE_ROLES or the SIEM becomes a target`);
  }
});

// ---------------------------------------------------------------------------
// Degradation: seeding is an upgrade, never a new way to fail a class
// ---------------------------------------------------------------------------

/**
 * A lane whose lab cannot be resolved must launch exactly as it did before this
 * module existed. Throwing here would turn a realism feature into an outage for
 * every non-GOAD classroom.
 */
test('an unresolvable lab yields no facts and a named warning, never a throw', () => {
  for (const lab of ['', null, undefined, 'NOT-A-LAB', '../../etc/passwd']) {
    const built = buildLaneFacts({ lab, subnetBase: '10.39.17' });
    assert.deepEqual(built.facts, []);
    assert.ok(built.warnings.length, `no warning for lab ${JSON.stringify(lab)}`);
  }
});

/** A missing subnet drops the addresses but keeps the names usable. */
test('a missing subnet still seeds names and fqdns, and says the addresses are gone', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light' });
  assert.ok(built.warnings.includes(WARNINGS.NO_SUBNET));
  assert.equal(valuesOf(built, TRAITS.hostIp).length, 0);
  assert.equal(valuesOf(built, TRAITS.hostName).length, 3);
});

/**
 * No account roster is derivable server-side for a stock GOAD lane — the users
 * exist only inside the GOAD fork on the controller, and GOAD-main/ is
 * gitignored with zero tracked files. Warning is the honest answer; a
 * fabricated username binds an ability to nothing and looks like it worked.
 */
test('the absent user roster is reported rather than invented', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' });
  assert.ok(built.warnings.includes(WARNINGS.NO_USERS));
  assert.equal(valuesOf(built, TRAITS.user).length, 0);
});

test('supplied users are seeded when a caller can provide them', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17', users: ['CYBERSAGUAROS\\jsnow', ' ', null] });
  assert.deepEqual(valuesOf(built, TRAITS.user), ['CYBERSAGUAROS\\jsnow']);
  assert.ok(!built.warnings.includes(WARNINGS.NO_USERS));
});

/**
 * Facts combine combinatorially with every other fact an ability requires, so
 * an unbounded roster is how one ability becomes hundreds of links.
 */
test('the host cap holds and reports itself', () => {
  const built = buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17', maxHosts: 2 });
  assert.equal(valuesOf(built, TRAITS.hostName).length, 2);
  assert.ok(built.warnings.includes(WARNINGS.CAPPED));
});

// ---------------------------------------------------------------------------
// Determinism and renamed forests
// ---------------------------------------------------------------------------

/**
 * The same lane must sync a byte-identical source on every launch, so a diff
 * between two lanes is a real difference in addressing rather than sampling.
 */
test('two builds of one lane are byte-identical', () => {
  const once = () => JSON.stringify(buildLaneFacts({ lab: 'GOAD-Light', subnetBase: '10.39.17' }).facts);
  assert.equal(once(), once());
});

/** A renamed forest boots hostnames the vendored sidecar cannot know. */
test('observed hostnames from a renamed forest win over the stock sidecar', () => {
  const built = buildLaneFacts({
    lab: 'GOAD-Light',
    subnetBase: '10.39.17',
    hostnameOverrides: { DC01: 'ACME-DC01' },
  });
  const names = valuesOf(built, TRAITS.hostName);
  assert.ok(names.includes('ACME-DC01'));
  assert.ok(!names.includes('TUC-DC01'));
});

test('identities are read shape-tolerantly and an unknown shape yields no overrides', () => {
  assert.deepEqual(hostnameOverridesOf({ goad: { identities: { checks: [{ roster_name: 'DC01', observed: { hostname: 'ACME-DC01' } }] } } }),
    { DC01: 'ACME-DC01' });
  for (const config of [null, {}, { goad: null }, { goad: { identities: 'nope' } }, { goad: { identities: { checks: [{}] } } }]) {
    assert.deepEqual(hostnameOverridesOf(config), {});
  }
});

// ---------------------------------------------------------------------------
// The lane-shaped entry point
// ---------------------------------------------------------------------------

/** A lane that is not a GOAD lane has no AD estate to name. */
test('laneFactsFor seeds nothing for a lane with no GOAD environment', () => {
  for (const described of [null, undefined, { goad: false, lab: 'GOAD-Light' }]) {
    const built = laneFactsFor({}, {}, described);
    assert.deepEqual(built.facts, []);
    assert.ok(built.warnings.includes(WARNINGS.NO_LAB));
  }
});

test('laneFactsFor resolves a GOAD lane through its config and description', () => {
  const built = laneFactsFor({}, { subnet_scheme: 'v2', lane_subnet_base: '10.7.9' }, { goad: true, lab: 'GOAD-Light' });
  assert.deepEqual(valuesOf(built, TRAITS.hostIp), ['10.7.9.10', '10.7.9.11', '10.7.9.22']);
});
