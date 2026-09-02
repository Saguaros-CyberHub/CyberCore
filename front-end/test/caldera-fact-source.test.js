/**
 * caldera-fact-source.test.js — Track E, phase E9: per-class scoping.
 *
 * ############################################################################
 * # NOTHING IN THIS SUITE HAS TOUCHED A REAL CALDERA SERVER, BECAUSE THERE   #
 * # IS NONE. Every client below is a fake and every trait name is taken from #
 * # upstream's documented stockpile vocabulary. A green run proves that what #
 * # gets DERIVED from a spec is right and that a re-sync updates instead of  #
 * # duplicating. It proves NOTHING about whether a real Caldera accepts the  #
 * # body — that can only be established against a server, after the E8       #
 * # cluster gate passes.                                                     #
 * ############################################################################
 *
 * WHAT EACH SECTION DEFENDS
 *
 *   §1  THE SPEC IS THE ESTATE. Facts come from what was DEPLOYED, never from
 *       the profile's paper asset list. An adversary authored against a machine
 *       that exists only on paper creates a link that can never run, and the
 *       answer key then describes activity nothing performed.
 *   §2  IDENTITY. The name and id are stable across rebuilds and collision-free
 *       across two scopes a human gave the same label. Caldera has no per-object
 *       ownership, so the name is the ONLY handle an instructor has, and two
 *       sections sharing one row is one section's adversary running against the
 *       other's hosts.
 *   §3  IDEMPOTENCE. Re-syncing a class updates its row. Thirty near-identical
 *       rows on a server with no tenancy is an instructor picking the wrong one,
 *       and picking the wrong one is unobservable.
 *   §4  THE PLATFORM SUMMARY IS TRUE. "3 Windows, 1 Linux" is what an instructor
 *       decides with; counting the ELK box would make an all-Windows estate look
 *       like it has a Linux target.
 *   §5  AN ABSENT PLATFORM WARNS. A linux-only adversary against an all-Windows
 *       class does not fail — it succeeds instantly having created no links, and
 *       the run row says completed.
 *   §6  PURITY AND THE STANDING GATES, as source text.
 *   §7  NOTHING SECRET BECOMES A FACT. A fact source on a shared staff server is
 *       legible to every account on it.
 *
 * Run: node --test test/caldera-fact-source.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const FACT_SOURCE_PATH = path.join(ROOT, 'src', 'incident', 'caldera', 'fact-source.js');
const mod = require(FACT_SOURCE_PATH);
const {
  buildFactSource,
  syncFactSource,
  summarizePlatforms,
  checkAdversaryPlatforms,
  hostsFromSpec,
  domainsFromSpec,
  classifyPlatform,
  toWire,
  TRAITS,
  WARNINGS,
  FactSourceError,
} = mod;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * A GOAD-Light-shaped spec: three Windows hosts in one forest with a child
 * domain, plus the two machines that are NOT part of the estate.
 *
 * The vms/goad.lab overlap is deliberate and is what a real spec looks like:
 * goad-deploy.assertGoadRoster REFUSES to deploy a spec whose vms and lab
 * roster disagree, so both carry the same three machines.
 */
const GOAD_SPEC = {
  vms: [
    { name: 'DC01', hostname: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
    { name: 'DC02', hostname: 'DC02', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
    { name: 'SRV02', hostname: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004 },
    { name: 'lane-gw', hostname: 'lane-gw', role: 'gateway', os_family: 'linux', type: 'lxc' },
    { name: 'kali', hostname: 'kali', role: 'attacker', os_family: 'linux' },
  ],
  goad: {
    enabled: true,
    version: 'GOAD-Light',
    lab: {
      forestRoot: 'cybersaguaros.local',
      childSubdomain: 'tumamoc',
      vms: [
        { name: 'DC01', role: 'dc', os: 'Windows Server 2019', ipOctet: 10 },
        { name: 'DC02', role: 'dc', os: 'Windows Server 2019', ipOctet: 11 },
        { name: 'SRV02', role: 'member', os: 'Windows Server 2019', ipOctet: 22 },
      ],
    },
  },
};

/** A CiAB profile-derived spec: Windows AD plus a Linux web host and the telemetry plane. */
const MIXED_SPEC = {
  vms: [
    { name: 'DC01', hostname: 'DC01', role: 'server', os_family: 'windows_server' },
    { name: 'FILE01', hostname: 'FILE01', role: 'server', os_family: 'windows_server' },
    { name: 'WEB01', hostname: 'WEB01', role: 'server', os_family: 'linux' },
    { name: 'MAC01', hostname: 'MAC01', role: 'workstation', os: 'macOS 14 Sonoma' },
    { name: 'HMI01', hostname: 'HMI01', role: 'ot' },
    { name: 'cc-sensor', hostname: 'cc-sensor', role: 'sensor', os_family: 'linux' },
    { name: 'cc-elk', hostname: 'cc-elk', role: 'siem', os_family: 'linux' },
  ],
  dns: { ad_domain: 'corp.acme.local', ad_dc: 'DC01' },
};

/** What the profile DESCRIBED. FILE02 and PRINT01 were never deployed. */
const ASSETS = [
  { hostname: 'DC01', ip: '10.1.1.10', role: 'server', os: 'Windows Server 2019 Standard' },
  { hostname: 'HMI01', ip: '10.1.1.30', role: 'ot', os: 'Windows 10 IoT Enterprise' },
  { hostname: 'FILE02', ip: '10.1.1.21', role: 'server', os: 'Windows Server 2016' },
  { hostname: 'PRINT01', ip: '10.1.1.40', role: 'server', os: 'Windows Server 2016' },
];

/** The same hand-written catalog shape test/caldera-adversary.test.js uses. */
const CATALOG = [
  {
    ability_id: 'ab-psh-001', technique_id: 'T1059.001', name: 'PowerShell one-liner',
    tactic: 'execution', platforms: ['windows'],
  },
  {
    ability_id: 'ab-bash-001', technique_id: 'T1059.004', name: 'Bash one-liner',
    tactic: 'execution', platforms: ['linux'],
  },
  {
    ability_id: 'ab-discover-001', technique_id: 'T1082', name: 'System information discovery',
    tactic: 'discovery', platforms: ['windows', 'linux'],
  },
  {
    ability_id: 'ab-nodecl-001', technique_id: 'T1087', name: 'Account discovery (no platform declared)',
    tactic: 'discovery',
  },
];

const codesOf = (warnings) => warnings.map((w) => w.split(':')[0]);
const clone = (v) => JSON.parse(JSON.stringify(v));

/**
 * A Caldera that remembers. Records every call so a test can assert HOW the
 * server was reached, not only what came back.
 */
function fakeServer(seed) {
  const store = new Map();
  for (const row of (seed || [])) store.set(row.id, clone(row));
  const calls = [];
  return {
    store,
    calls,
    client: {
      async listSources() {
        calls.push({ op: 'list' });
        return [...store.values()].map(clone);
      },
      async createSource(body) {
        calls.push({ op: 'create', body: clone(body) });
        if (store.has(body.id)) throw new Error('a real server would 409 here');
        store.set(body.id, clone(body));
        return { id: body.id };
      },
      async updateSource(id, body) {
        calls.push({ op: 'update', id, body: clone(body) });
        if (!store.has(id)) throw new Error('no such source');
        store.set(id, clone({ ...body, id }));
        return { id };
      },
    },
  };
}

// ---------------------------------------------------------------------------
// §1 The spec is the estate
// ---------------------------------------------------------------------------

test('E9-S1: host facts are the DEPLOYED spec, one fact per host, FQDN under the domain', () => {
  const built = buildFactSource({ scopeLabel: 'CYBR 400 · 02', scopeKey: 'sec-2', spec: GOAD_SPEC });

  const hosts = built.facts.filter((f) => f.trait === TRAITS.host).map((f) => f.value);
  assert.deepStrictEqual(hosts, [
    'dc01.cybersaguaros.local',
    'dc02.cybersaguaros.local',
    'srv02.cybersaguaros.local',
  ], 'the three forest machines, each exactly once, fully qualified');

  // ONE fact per host. Two (a short name and an FQDN) would make the operation
  // run every lateral-movement ability twice against the same machine.
  assert.strictEqual(hosts.length, new Set(hosts).size);
  assert.strictEqual(hosts.length, 3);
});

test('E9-S2: the gateway, the attack box and the evidence plane are excluded — and SAID so', () => {
  const built = buildFactSource({ scopeLabel: 'Mixed', spec: MIXED_SPEC });
  const values = built.facts.map((f) => f.value).join(' ');

  for (const off of ['lane-gw', 'kali', 'cc-sensor', 'cc-elk']) {
    assert.ok(!values.includes(off), `${off} must never be seeded as a target`);
  }
  // An ability that lands on the SIEM corrupts the store the student is graded
  // on reading. Excluding it silently would be indistinguishable from a bug.
  assert.deepStrictEqual(built.excluded, ['cc-sensor', 'cc-elk']);
  assert.ok(codesOf(built.warnings).includes(WARNINGS.INFRASTRUCTURE_EXCLUDED));

  const goad = buildFactSource({ scopeLabel: 'GOAD', spec: GOAD_SPEC });
  assert.deepStrictEqual(goad.excluded, ['lane-gw', 'kali']);
});

test('E9-S3: an asset the profile describes but the lane never deployed is NOT a fact', () => {
  const built = buildFactSource({ scopeLabel: 'Mixed', spec: MIXED_SPEC, assets: ASSETS });
  const values = built.facts.map((f) => f.value).join(' ');

  // FILE02 and PRINT01 are in the profile and not in the spec. Seeding them
  // would let an instructor author "move to FILE02" against a machine that does
  // not exist: the link never runs, and the answer key describes activity
  // nothing performed.
  assert.ok(!values.includes('file02'), 'a paper-only asset must not be seeded');
  assert.ok(!values.includes('print01'), 'a paper-only asset must not be seeded');

  const warning = built.warnings.find((w) => w.startsWith(WARNINGS.PAPER_ONLY_ASSET));
  assert.ok(warning, 'the omission must be reported, not silent');
  assert.ok(warning.includes('file02') && warning.includes('print01'));
});

test('E9-S4: assets ENRICH a spec row that records no OS — they never add a host', () => {
  // HMI01 is in the spec with no os_family and no os. Unclassifiable alone.
  const bare = hostsFromSpec(MIXED_SPEC).find((h) => h.name === 'HMI01');
  assert.strictEqual(bare.platform, 'unknown');

  // The profile says it is Windows 10 IoT. That resolves the platform WITHOUT
  // making the profile the source of the host set.
  const enriched = hostsFromSpec(MIXED_SPEC, { assets: ASSETS }).find((h) => h.name === 'HMI01');
  assert.strictEqual(enriched.platform, 'windows');

  // ...and an unresolved one is kept and reported, never dropped: dropping it
  // would silently shrink the class's estate.
  const warnings = [];
  const hosts = hostsFromSpec(MIXED_SPEC, { warn: (code, msg) => warnings.push(`${code}: ${msg}`) });
  assert.ok(hosts.some((h) => h.name === 'HMI01' && !h.excluded));
  assert.ok(codesOf(warnings).includes(WARNINGS.UNKNOWN_PLATFORM));
});

test('E9-S5: the AD domain and its CHILD are seeded; a trust partner is not invented', () => {
  const built = buildFactSource({ scopeLabel: 'GOAD', spec: GOAD_SPEC });
  const domains = built.facts.filter((f) => f.trait === TRAITS.domain).map((f) => f.value);
  assert.deepStrictEqual(domains, ['cybersaguaros.local', 'tumamoc.cybersaguaros.local']);

  // NHA's second domain (academy.ninja.lan) is NOT a suffix of its forest root
  // (ninja.hack): it is reached by a TRUST, and ad-child_domain.yml can only
  // build `<label>.<parent>`. Naming it as a child produces a domain the forest
  // does not have — src/utils/ad-domain-rules.js refuses for the same reason.
  const nha = domainsFromSpec({
    goad: { lab: { forestRoot: 'ninja.hack', childSubdomain: 'academy.ninja.lan' } },
  });
  assert.deepStrictEqual(nha, ['ninja.hack']);

  // GOAD_LABS records childSubdomain: null for exactly those labs.
  assert.deepStrictEqual(
    domainsFromSpec({ goad: { lab: { forestRoot: 'sccm.lab', childSubdomain: null } } }),
    ['sccm.lab']
  );
});

test('E9-S6: the domain source precedence is explicit override > dns > goad > lab', () => {
  const spec = {
    dns: { ad_domain: 'corp.acme.local' },
    goad: { domain: 'generated.local', lab: { forestRoot: 'builtin.local' } },
  };
  assert.strictEqual(domainsFromSpec(spec)[0], 'corp.acme.local');
  assert.strictEqual(domainsFromSpec(spec, 'override.local')[0], 'override.local');
  assert.strictEqual(domainsFromSpec({ goad: spec.goad })[0], 'generated.local');
  assert.strictEqual(domainsFromSpec({ goad: { lab: spec.goad.lab } })[0], 'builtin.local');
});

test('E9-S7: no domain means bare hostnames and a warning, never an invented forest', () => {
  const built = buildFactSource({
    scopeLabel: 'Workstation lane',
    spec: { vms: [{ name: 'WS01', hostname: 'WS01', os_family: 'windows_client' }] },
  });
  assert.deepStrictEqual(built.facts.map((f) => f.value), ['ws01']);
  assert.ok(codesOf(built.warnings).includes(WARNINGS.NO_DOMAIN));
});

test('E9-S8: nothing in this tree writes a user set, so an absent one is REPORTED', () => {
  // goad-lab-compile builds lab.domains[fqdn].users while compiling a forest,
  // but what reaches the spec is goad.generated_lab.files — YAML TEXT — and
  // profile-to-spec emits no users at all. Inventing accounts here would put
  // names in a fact source that no domain controller has ever heard of.
  const none = buildFactSource({ scopeLabel: 'GOAD', spec: GOAD_SPEC });
  assert.deepStrictEqual(none.users, []);
  assert.ok(!none.facts.some((f) => f.trait === TRAITS.user));
  assert.ok(codesOf(none.warnings).includes(WARNINGS.NO_USERS));

  // A caller that DOES know the roster supplies it, in any of the shapes one
  // arrives in: a list of names, a list of objects, or a {sam: {...}} block.
  const supplied = buildFactSource({
    scopeLabel: 'GOAD',
    spec: GOAD_SPEC,
    users: ['jsmith', { sam: 'svc_backup' }, { username: 'jsmith' }],
  });
  assert.deepStrictEqual(
    supplied.facts.filter((f) => f.trait === TRAITS.user).map((f) => f.value),
    ['jsmith', 'svc_backup'],
    'deduplicated case-insensitively, in first-seen order after the sort'
  );

  const fromSpec = buildFactSource({
    scopeLabel: 'GOAD',
    spec: { ...GOAD_SPEC, users: { jsnow: { groups: ['Domain Admins'] }, arya: {} } },
  });
  assert.deepStrictEqual(
    fromSpec.facts.filter((f) => f.trait === TRAITS.user).map((f) => f.value).sort(),
    ['arya', 'jsnow']
  );
});

test('E9-S9: one machine declared twice is seeded once, and the duplicate is reported', () => {
  // GOAD_SPEC declares its three forest hosts in BOTH spec.vms and goad.lab.vms,
  // which is what assertGoadRoster requires. A second host fact would run every
  // ability against that machine twice.
  const warnings = [];
  const hosts = hostsFromSpec(GOAD_SPEC, { warn: (c, m) => warnings.push(`${c}: ${m}`) });
  assert.strictEqual(hosts.filter((h) => h.name === 'DC01').length, 1);
  assert.strictEqual(codesOf(warnings).filter((c) => c === WARNINGS.DUPLICATE_HOST).length, 3);
});

test('E9-S10: an empty scope seeds nothing and says so out loud', () => {
  const built = buildFactSource({ scopeLabel: 'Empty', spec: { vms: [] } });
  assert.deepStrictEqual(built.facts, []);
  assert.ok(codesOf(built.warnings).includes(WARNINGS.NO_HOSTS));
});

// ---------------------------------------------------------------------------
// §2 Identity
// ---------------------------------------------------------------------------

test('E9-S11: the name and id are STABLE — rebuilding a class addresses the same row', () => {
  const a = buildFactSource({ scopeLabel: 'CYBR 400 · 02', scopeKey: 'section-42', spec: GOAD_SPEC });
  const b = buildFactSource({ scopeLabel: 'CYBR 400 · 02', scopeKey: 'section-42', spec: GOAD_SPEC });
  assert.strictEqual(a.id, b.id);
  assert.strictEqual(a.name, b.name);
  // Byte-identical facts, so a re-sync is a no-op a reviewer can see is a no-op.
  assert.deepStrictEqual(a.facts, b.facts);
});

test('E9-S12: two scopes a human gave the SAME label do not collide', () => {
  // Caldera has no per-object ownership. If both sections resolved to one row,
  // the second sync would overwrite the first — and section one's adversary
  // would then be authored against section two's hosts, silently.
  const one = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-1', spec: GOAD_SPEC });
  const two = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-2', spec: MIXED_SPEC });
  assert.notStrictEqual(one.id, two.id);
  assert.notStrictEqual(one.name, two.name);
  assert.ok(one.name.startsWith('CyberCore: Section A ['));
  assert.ok(two.name.startsWith('CyberCore: Section A ['));
});

test('E9-S13: a label stays ONE LINE — it cannot become two rows in the server\'s list', () => {
  // The name is rendered in a list on a shared server. A label carrying a
  // newline (or a NUL, or a DEL) makes two rows out of one for anyone reading
  // it, and one of the two is a row nobody can account for.
  const built = buildFactSource({
    scopeLabel: 'Section A\r\n\tCyberCore: Section B',
    scopeKey: 'sec-1',
    spec: GOAD_SPEC,
  });
  assert.ok(!/[\r\n\t]/.test(built.name), 'no line breaks survive into the name');
  // eslint-disable-next-line no-control-regex
  assert.ok(!/[\u0000-\u001f\u007f]/.test(built.name), 'no control character survives either');
  assert.ok(built.name.startsWith('CyberCore: Section A '));
  assert.ok(/ \[[0-9a-f]{8}\]$/.test(built.name), 'the scope digest still terminates the name');
});

test('E9-S14: a scope with no label is refused rather than defaulted', () => {
  assert.throws(
    () => buildFactSource({ spec: GOAD_SPEC }),
    (err) => err instanceof FactSourceError && err.code === 'CALDERA_FACT_SOURCE_NO_SCOPE'
  );
});

// ---------------------------------------------------------------------------
// §3 Idempotence
// ---------------------------------------------------------------------------

test('E9-S15: syncing the same class twice UPDATES — it never creates a second row', async () => {
  const server = fakeServer();
  const built = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-1', spec: GOAD_SPEC });

  const first = await syncFactSource(server.client, built);
  assert.strictEqual(first.action, 'created');
  assert.strictEqual(server.store.size, 1);

  const second = await syncFactSource(server.client, built);
  assert.strictEqual(second.action, 'updated');
  assert.strictEqual(second.id, first.id);
  assert.strictEqual(server.store.size, 1, 'a second row is an instructor picking the wrong one');

  // Re-syncing a rebuilt-but-unchanged source sends the same body. A reviewer
  // diffing two syncs sees a real change or nothing.
  const rebuilt = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-1', spec: GOAD_SPEC });
  await syncFactSource(server.client, rebuilt);
  assert.strictEqual(server.store.size, 1);
  const bodies = server.calls.filter((c) => c.op === 'update').map((c) => JSON.stringify(c.body));
  assert.strictEqual(new Set(bodies).size, 1);
});

test('E9-S16: a row created by hand under this class\'s name is adopted, not duplicated', async () => {
  const built = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-1', spec: GOAD_SPEC });
  // Someone made it in the UI, so its id is not the one we would have chosen.
  const server = fakeServer([{ id: 'hand-made-0001', name: built.name, facts: [] }]);

  const res = await syncFactSource(server.client, built);
  assert.strictEqual(res.action, 'updated');
  assert.strictEqual(res.id, 'hand-made-0001');
  assert.strictEqual(server.store.size, 1);
});

test('E9-S17: duplicate names resolve deterministically and are reported', async () => {
  const built = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-1', spec: GOAD_SPEC });
  const server = fakeServer([
    { id: 'zzz-second', name: built.name, facts: [] },
    { id: 'aaa-first', name: built.name, facts: [] },
  ]);

  const res = await syncFactSource(server.client, built);
  // Lowest id, every time. Taking whichever the server listed first would make
  // the same re-sync update a different row on different days.
  assert.strictEqual(res.id, 'aaa-first');
  assert.ok(codesOf(res.warnings).includes(WARNINGS.DUPLICATE_SOURCE));
});

test('E9-S18: getSource short-circuits the listing when the client offers one', async () => {
  const built = buildFactSource({ scopeLabel: 'Section A', scopeKey: 'sec-1', spec: GOAD_SPEC });
  const server = fakeServer([{ id: built.id, name: built.name, facts: [] }]);
  server.client.getSource = async (id) => {
    server.calls.push({ op: 'get', id });
    return server.store.has(id) ? clone(server.store.get(id)) : null;
  };

  const res = await syncFactSource(server.client, built);
  assert.strictEqual(res.action, 'updated');
  assert.ok(server.calls.some((c) => c.op === 'get'));
  assert.ok(!server.calls.some((c) => c.op === 'list'));
});

test('E9-S19: a client with no source API refuses with a named code, and names the methods', async () => {
  // src/incident/caldera/client.js does not implement them yet. Reaching around
  // it would put a second HTTP call site in the adapter and break the one rule
  // that makes any of it testable.
  const built = buildFactSource({ scopeLabel: 'Section A', spec: GOAD_SPEC });
  await assert.rejects(
    () => syncFactSource({ listAbilities: () => [] }, built),
    (err) => {
      assert.ok(err instanceof FactSourceError);
      assert.strictEqual(err.code, 'CALDERA_CLIENT_NO_SOURCE_API');
      assert.ok(/listSources/.test(err.message) && /createSource/.test(err.message));
      assert.ok(/client\.js/.test(err.message), 'it must say where the methods belong');
      return true;
    }
  );
});

test('E9-S20: the wire body is a WHITELIST — staff-facing derivation never leaves the app', async () => {
  const built = buildFactSource({ scopeLabel: 'Section A', spec: MIXED_SPEC, assets: ASSETS });
  const server = fakeServer();
  await syncFactSource(server.client, built);

  const body = server.calls.find((c) => c.op === 'create').body;
  assert.deepStrictEqual(
    Object.keys(body).sort(),
    ['adjustments', 'facts', 'id', 'name', 'relationships', 'rules'].sort()
  );
  // `hosts`, `warnings`, `excluded` and `scope_label` describe a class's estate
  // to STAFF. They have no business on a server every instructor shares.
  for (const leaked of ['hosts', 'warnings', 'excluded', 'scope_label', 'platforms', 'version']) {
    assert.ok(!(leaked in body), `${leaked} must not reach the server`);
  }
  for (const fact of body.facts) {
    assert.deepStrictEqual(Object.keys(fact).sort(), ['score', 'trait', 'value']);
  }
});

// ---------------------------------------------------------------------------
// §4 The platform summary
// ---------------------------------------------------------------------------

test('E9-S21: an all-Windows GOAD-shaped spec summarises as all Windows', () => {
  assert.deepStrictEqual(summarizePlatforms(GOAD_SPEC), { windows: 3, linux: 0, other: 0 });
});

test('E9-S22: a mixed spec is counted per platform, and the telemetry plane is not counted', () => {
  // DC01 + FILE01 windows, WEB01 linux, MAC01 darwin and HMI01 unknown -> other.
  // cc-sensor and cc-elk are Linux machines that are NOT targets: counting them
  // would tell an instructor this class has three Linux boxes to attack.
  assert.deepStrictEqual(summarizePlatforms(MIXED_SPEC), { windows: 2, linux: 1, other: 2 });
});

test('E9-S23: the platform is read from what the spec RECORDS, never from the hostname', () => {
  assert.strictEqual(classifyPlatform({ os_family: 'windows_server' }), 'windows');
  assert.strictEqual(classifyPlatform({ os_family: 'windows_client' }), 'windows');
  assert.strictEqual(classifyPlatform({ os: 'Windows Server 2019' }), 'windows');
  assert.strictEqual(classifyPlatform({ os: 'Ubuntu 22.04 LTS' }), 'linux');
  assert.strictEqual(classifyPlatform({ os_family: 'linux' }), 'linux');
  assert.strictEqual(classifyPlatform({ os: 'macOS 14 Sonoma' }), 'darwin');
  assert.strictEqual(classifyPlatform({ os: 'VxWorks 7' }), 'unknown');
  assert.strictEqual(classifyPlatform({}), 'unknown');

  // A machine called `winston-01` is not Windows. A heuristic that says it is
  // puts a Windows-only ability on a Linux box, where it fails at execution
  // rather than never running.
  assert.strictEqual(classifyPlatform({ hostname: 'winston-01', name: 'WINSTON' }), 'unknown');
});

// ---------------------------------------------------------------------------
// §5 An absent platform warns
// ---------------------------------------------------------------------------

test('E9-S24: a linux ability against an all-Windows class WARNS — it does not silently pass', () => {
  const res = checkAdversaryPlatforms({
    adversary: { atomic_ordering: ['ab-psh-001', 'ab-bash-001'] },
    abilities: CATALOG,
    spec: GOAD_SPEC,
  });

  assert.deepStrictEqual(res.unreachable, [{ ability_id: 'ab-bash-001', platforms: ['linux'] }]);
  assert.strictEqual(res.reachable, 1);
  const warning = res.warnings.find((w) => w.startsWith(WARNINGS.PLATFORM_ABSENT));
  assert.ok(warning, 'the mismatch must surface as a warning');
  assert.ok(warning.includes('ab-bash-001'));
  // The instructor needs the numbers, not just the verdict.
  assert.ok(warning.includes('3 windows, 0 linux, 0 other'));
});

test('E9-S25: an adversary that can run NOTHING here is called out separately', () => {
  // This is the failure the whole check exists for: the operation does not fail,
  // it SUCCEEDS instantly having created no links, and the run row says
  // completed. The first evidence otherwise is a class that all found nothing.
  const res = checkAdversaryPlatforms({
    adversary: { atomic_ordering: ['ab-bash-001'] },
    abilities: CATALOG,
    spec: GOAD_SPEC,
  });
  assert.strictEqual(res.reachable, 0);
  assert.ok(codesOf(res.warnings).includes(WARNINGS.NOTHING_RUNNABLE));
});

test('E9-S26: a matching platform, a cross-platform ability and an undeclared one all pass', () => {
  const res = checkAdversaryPlatforms({
    adversary: { atomic_ordering: ['ab-psh-001', 'ab-discover-001', 'ab-nodecl-001'] },
    abilities: CATALOG,
    spec: GOAD_SPEC,
  });
  assert.deepStrictEqual(res.warnings, []);
  assert.strictEqual(res.reachable, 3);
});

test('E9-S27: an ability id the catalog does not carry is reported as unknown, not as a platform miss', () => {
  const res = checkAdversaryPlatforms({
    adversary: { atomic_ordering: ['ab-psh-001', 'ab-does-not-exist'] },
    abilities: CATALOG,
    spec: GOAD_SPEC,
  });
  assert.deepStrictEqual(res.unknown, ['ab-does-not-exist']);
  assert.deepStrictEqual(res.unreachable, []);
  assert.ok(codesOf(res.warnings).includes(WARNINGS.ABILITY_UNKNOWN));
});

test('E9-S28: `other` grants nothing — a class of darwin and unclassified hosts is not a free pass', () => {
  // MAC01 and HMI01 are 'other'. Treating that as "any platform is fine" would
  // rubber-stamp exactly the specs that most need the check.
  const res = checkAdversaryPlatforms({
    adversary: { atomic_ordering: ['ab-bash-001'] },
    abilities: CATALOG,
    platforms: { windows: 0, linux: 0, other: 2 },
  });
  assert.strictEqual(res.reachable, 0);
  assert.strictEqual(res.unreachable.length, 1);
});

// ---------------------------------------------------------------------------
// §6 Purity and the standing gates
// ---------------------------------------------------------------------------

test('E9-S29: the derivation reaches for no network, no database, no disk, no clock', () => {
  // The client is INJECTED precisely so this holds. A fetch here would make the
  // module untestable without a server that does not exist.
  //
  // Comments are stripped first, the same doctrine as ciab-deploy-parity.test.js
  // and caldera-adversary.test.js: this file's own header discusses "no network,
  // no database, no fs" at length and would otherwise fail itself.
  const code = fs.readFileSync(FACT_SOURCE_PATH, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n');

  const forbidden = [
    ["require('fs')", 'the derivation must not read the disk'],
    ["require('http", 'the derivation must not speak HTTP — the client is injected'],
    ["require('net')", 'the derivation must not open sockets'],
    ['fetch(', 'the derivation must not reach a server directly'],
    ['axios', 'the derivation must not reach a server directly'],
    ['cybercoreQuery', 'the derivation must not touch a database'],
    ['Date.now(', 'a clock makes the derivation non-deterministic'],
    ['new Date(', 'a clock makes the derivation non-deterministic'],
    ['Math.random', 'an RNG makes the fact-source id change on every sync'],
  ];
  for (const [needle, why] of forbidden) {
    assert.ok(!code.includes(needle),
      `src/incident/caldera/fact-source.js contains ${JSON.stringify(needle)} — ${why}`);
  }
});

test('E9-S30: core does not require into a plugin, and caldera is still unregistered', () => {
  const code = fs.readFileSync(FACT_SOURCE_PATH, 'utf8');
  assert.ok(!/require\(['"][^'"]*modules\/crucible\/plugins\//.test(code),
    'core must never require into a plugin');

  // Building a fact source is AUTHORING. It must not make execution reachable.
  const engines = require(path.join(ROOT, 'src', 'incident', 'engines'));
  assert.ok(!engines.registeredEngines().includes('caldera'),
    'scoping an adversary must not register an engine — execution waits on the E8 cluster gate');
});

test('E9-S31: no NUL byte in the source', () => {
  // A literal NUL makes grep and ripgrep classify the file as binary and skip it
  // SILENTLY, so every source-text gate above would report PASS by never having
  // read the file. Scanned with node for exactly that reason.
  const bytes = fs.readFileSync(FACT_SOURCE_PATH);
  assert.ok(!bytes.includes(0), 'src/incident/caldera/fact-source.js contains a raw NUL byte');
});

// ---------------------------------------------------------------------------
// §7 Nothing secret becomes a fact
// ---------------------------------------------------------------------------

test('E9-S32: passwords on a spec or a roster never become facts', () => {
  // A fact source on a shared staff server is legible to every account on it,
  // and bake-caldera-server.sh goes to real lengths (a 0600 file in the guest,
  // never a script_arg) to keep lane credentials off exactly such surfaces.
  const spec = {
    ...GOAD_SPEC,
    goad: {
      ...GOAD_SPEC.goad,
      admin_user: 'Administrator',
      admin_password: 'Sup3rSecret!Bake',
      lab: { ...GOAD_SPEC.goad.lab, domain_password: 'Forest!Pass1' },
    },
  };
  const built = buildFactSource({
    scopeLabel: 'GOAD',
    spec,
    users: [{ sam: 'jsnow', password: 'Winter1sC0ming', spns: ['MSSQLSvc/dc01'] }],
  });

  const blob = JSON.stringify(built);
  for (const secret of ['Sup3rSecret!Bake', 'Forest!Pass1', 'Winter1sC0ming']) {
    assert.ok(!blob.includes(secret), 'a credential must never reach a fact source');
  }
  assert.deepStrictEqual(
    built.facts.filter((f) => f.trait === TRAITS.user).map((f) => f.value),
    ['jsnow'],
    'the account name is the fact; the password is not'
  );
  assert.ok(!built.facts.some((f) => /password/i.test(f.trait)));
});

test('E9-S33: toWire refuses a source with no identity rather than posting an unnamed row', () => {
  assert.throws(
    () => toWire({ facts: [] }),
    (err) => err instanceof FactSourceError && err.code === 'CALDERA_FACT_SOURCE_MALFORMED'
  );
});
