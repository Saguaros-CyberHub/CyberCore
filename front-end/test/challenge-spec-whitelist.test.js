/**
 * challenge-spec-whitelist.test.js — the seven keys buildSpecVm used to drop.
 *
 * ── The regression this file exists for ─────────────────────────────────────
 * buildSpecVm is an ENUMERATED whitelist. That is deliberate: entries are rebuilt
 * key by key so client bookkeeping (`__topoId`, `ip`, `mac`, whatever a future
 * editor adds) cannot ride along into crucible_challenge.spec. But the enumeration
 * had gone stale against the Topology Designer, and seven keys the canvas
 * genuinely authors were being silently discarded on CREATE while surviving on
 * EDIT:
 *
 *   console_role · console_protocol · console_port · ipOctet · os_family ·
 *   post_clone_scripts · dns_aliases
 *
 * The most visible symptom is the student-console picker. topology-editor.js:335
 * offers it, readTopoDesignState() sends it, POST /api/admin/create-lab threw it
 * away — and PUT /lab-templates/:id, which merges the whole object, kept it. So
 * "create a challenge with a designated console" produced a lane with no console
 * designation, and "create then immediately edit" produced one with. Nothing
 * errored either way.
 *
 * The QUIETEST symptom was `dns_aliases`, which is why it outlived the other
 * six by a pass. A SIEM authored on the canvas as
 * `{ name:'elk', role:'siem', ipOctet:24, dns_aliases:['elk'] }` came up with
 * its pinned address and its DHCP reservation but no host-record, so the CYBR
 * 400 sensor's baked `ELK_HOST=elk.cybercore.lan` resolved nothing while the
 * agent reported healthy and shipped zero events. Section 8 pins it, and pins it
 * against the deploy path's own validator rather than a transcription of it.
 *
 * ── The rule these tests pin ────────────────────────────────────────────────
 * Every added key is OMIT-WHEN-ABSENT and OMIT-WHEN-INVALID. Never coerced: a
 * coerced value is a lane that is silently wrong (a console port of 0, a
 * reservation for .1 which is the gateway), whereas an absent key falls back to a
 * documented default. test/challenge-spec-create.test.js separately asserts the
 * byte-identical equivalence with the pre-refactor 9-key literal, and it must
 * keep passing — that is why "invalid means omitted" rather than "invalid means
 * throw" or "invalid means null".
 *
 * Run: node front-end/test/challenge-spec-whitelist.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

// challenge-spec is pure, but the cross-checks below reach into
// challenge-lane-deployer, which pulls site-config at module load (via
// batch-deployer) and reads a gitignored config/site.json. Same require.cache
// stub challenge-lane-addressing.test.js and console-designation.test.js use.
require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getDefaultTemplateNode: () => 'node-1',
  },
};

const { buildSpecVm } = require(path.join(UTILS, 'challenge-spec'));

// The nine keys the pre-refactor literal emitted. Anything else on the output is
// one of the additive keys, so tests can assert "nothing extra" precisely.
const LEGACY_KEYS = [
  'name', 'role', 'os', 'template_vmid', 'type', 'vm_offset',
  'services', 'default_scripts', 'hostname',
];
const extraKeys = (out) => Object.keys(out).filter(k => !LEGACY_KEYS.includes(k)).sort();

// ── 1. all seven survive ─────────────────────────────────────────────────────

test('all seven previously-dropped keys survive buildSpecVm', () => {
  const out = buildSpecVm({
    name: 'ws01', role: 'workstation', os: 'Windows 11', template_vmid: 1002,
    type: 'qemu', vm_offset: 600000,
    console_role: 'primary',
    console_protocol: 'rdp',
    console_port: 3389,
    ipOctet: 31,
    os_family: 'windows_client',
    post_clone_scripts: ['init-setup', 'win-smb-vuln'],
    dns_aliases: ['ws01-console'],
  }, 0, 'blueteam');

  assert.strictEqual(out.console_role, 'primary');
  assert.strictEqual(out.console_protocol, 'rdp');
  assert.strictEqual(out.console_port, 3389);
  assert.strictEqual(out.ipOctet, 31);
  assert.strictEqual(out.os_family, 'windows_client');
  assert.deepStrictEqual(out.post_clone_scripts, ['init-setup', 'win-smb-vuln']);
  assert.deepStrictEqual(out.dns_aliases, ['ws01-console']);
});

test('a caller that sends none of them gets none of them', () => {
  // The back-compat half. The flat Create Challenge form and the CLE course
  // provisioner send none of these, and their stored spec must not grow a key.
  const out = buildSpecVm({ name: 'web01', template_vmid: 1601, vm_offset: 600000 }, 0, 'k');
  assert.deepStrictEqual(extraKeys(out), []);
});

// ── 2. console_role: exactly two values are meaningful ───────────────────────
//
// resolveConsolePlan throws when two machines claim 'primary' and puts only
// 'primary'/'secondary' machines in the console list. A third value would store
// a spec that designates nothing while looking like it designates something.

for (const role of ['primary', 'secondary']) {
  test(`console_role '${role}' is accepted`, () => {
    const out = buildSpecVm({ name: 'a', template_vmid: 1, console_role: role }, 0, 'k');
    assert.strictEqual(out.console_role, role);
  });
}

for (const bad of ['admin', 'PRIMARY ', 'true', '', null, 0, 1, true, {}, ['primary']]) {
  test(`console_role ${JSON.stringify(bad)} is omitted, not coerced`, () => {
    const out = buildSpecVm({ name: 'a', template_vmid: 1, console_role: bad }, 0, 'k');
    // 'PRIMARY ' is the one that must NOT be omitted — trimmed + lowercased it
    // is a real value, and an author who typed it meant it.
    if (String(bad).trim().toLowerCase() === 'primary') {
      assert.strictEqual(out.console_role, 'primary');
    } else {
      assert.ok(!('console_role' in out), `console_role should be absent for ${JSON.stringify(bad)}`);
    }
  });
}

// ── 3. console_port: an integer in the TCP range ─────────────────────────────

test('console_port accepts the range boundaries and a numeric string', () => {
  assert.strictEqual(buildSpecVm({ console_port: 1 }, 0, 'k').console_port, 1);
  assert.strictEqual(buildSpecVm({ console_port: 65535 }, 0, 'k').console_port, 65535);
  assert.strictEqual(buildSpecVm({ console_port: '3390' }, 0, 'k').console_port, 3390);
});

for (const bad of [0, -1, 65536, 3389.5, '80abc', 'ssh', '', null, undefined, true, NaN, Infinity]) {
  test(`console_port ${JSON.stringify(bad)} is omitted`, () => {
    const out = buildSpecVm({ name: 'a', console_port: bad }, 0, 'k');
    assert.ok(!('console_port' in out), `console_port should be absent for ${JSON.stringify(bad)}`);
  });
}

test('console_port uses Number, not parseInt — a typo is rejected not truncated', () => {
  // parseInt('3389abc') is 3389, which would store a plausible-looking port for
  // a value the author clearly fat-fingered. Number() gives NaN and it is
  // dropped, so the template catalog's default applies instead.
  assert.ok(!('console_port' in buildSpecVm({ console_port: '3389abc' }, 0, 'k')));
});

// ── 4. ipOctet: 2-254, mirroring resolveSpecAddressing PASS 1 ────────────────
//
// The deployer THROWS on an out-of-range octet, naming the machine. This omits
// instead: a create-time throw would reject a whole challenge over one field,
// and an omitted octet simply draws from the .80-.99 band like every other
// unpinned machine. The RANGE must be identical either way, or the two paths
// disagree about which specs are legal.

test('ipOctet accepts the same 2-254 range the deployer enforces', () => {
  assert.strictEqual(buildSpecVm({ ipOctet: 2 }, 0, 'k').ipOctet, 2);
  assert.strictEqual(buildSpecVm({ ipOctet: 24 }, 0, 'k').ipOctet, 24);
  assert.strictEqual(buildSpecVm({ ipOctet: 254 }, 0, 'k').ipOctet, 254);
  assert.strictEqual(buildSpecVm({ ipOctet: '85' }, 0, 'k').ipOctet, 85);
});

for (const bad of [0, 1, 255, 300, -5, 80.5, '', null, true, 'x', NaN]) {
  test(`ipOctet ${JSON.stringify(bad)} is omitted rather than masked`, () => {
    // Number() maps '' and null to 0 and true to 1; every one of those reaches
    // macForOctet(octet & 0xFF) in the deployer and produces a reservation for
    // an address that is not the one requested — or claims .1, the gateway.
    const out = buildSpecVm({ name: 'a', ipOctet: bad }, 0, 'k');
    assert.ok(!('ipOctet' in out), `ipOctet should be absent for ${JSON.stringify(bad)}`);
  });
}

test('the ipOctet range agrees with the deployer, boundary for boundary', () => {
  // Cross-checked against the real range check rather than a transcription of
  // it, so the two cannot drift.
  const { resolveSpecAddressing } = require(path.join(UTILS, 'challenge-lane-deployer.js'));
  const addressing = (ipOctet) => resolveSpecAddressing({
    specVms: [{ name: 'a', type: 'qemu', ipOctet }],
    subnetScheme: 'v2', laneSubnetBase: '10.39.16', goadSubnetBase: '10.39.16',
    pinAllVms: true,
  });
  for (const ok of [2, 254]) {
    assert.ok(buildSpecVm({ ipOctet: ok }, 0, 'k').ipOctet === ok);
    assert.doesNotThrow(() => addressing(ok), `deployer must accept .${ok}`);
  }
  for (const no of [1, 255]) {
    assert.ok(!('ipOctet' in buildSpecVm({ ipOctet: no }, 0, 'k')));
    assert.throws(() => addressing(no), /not a usable host address/, `deployer must reject .${no}`);
  }
});

// ── 5. os_family and console_protocol: free-form passthrough ─────────────────

test('os_family survives, and is what flips a Windows machine to e1000', () => {
  const { resolveSpecNicModel } = require(path.join(UTILS, 'lane-networking.js'));
  const out = buildSpecVm({ name: 'dc01', template_vmid: 1004, os_family: 'windows_server' }, 0, 'k');
  assert.strictEqual(out.os_family, 'windows_server');
  assert.strictEqual(resolveSpecNicModel(out), 'e1000',
    'a stock Windows guest on virtio has no driver and never DHCPs');
});

test('os_family is trimmed, and a blank or non-string one is omitted', () => {
  // A leading space would break resolveSpecNicModel's startsWith('windows'),
  // which is how a Windows box quietly gets a virtio NIC it has no driver for.
  assert.strictEqual(buildSpecVm({ os_family: '  windows_server ' }, 0, 'k').os_family, 'windows_server');
  for (const bad of ['', '   ', null, undefined, 7, {}, ['linux']]) {
    assert.ok(!('os_family' in buildSpecVm({ os_family: bad }, 0, 'k')),
      `os_family should be absent for ${JSON.stringify(bad)}`);
  }
});

test('console_protocol is passed through without an enum, deliberately', () => {
  // lane-deployer.resolveConsole owns the protocol allowlist and already falls
  // back to 'rdp' for anything it does not know. Restating that set here would
  // be a second source of truth that drops a protocol the deployer supports the
  // day one is added — and it would make CREATE store something different from
  // PUT, which merges the whole object.
  for (const pr of ['rdp', 'ssh', 'vnc']) {
    assert.strictEqual(buildSpecVm({ console_protocol: pr }, 0, 'k').console_protocol, pr);
  }
  assert.strictEqual(buildSpecVm({ console_protocol: ' spice ' }, 0, 'k').console_protocol, 'spice');
  for (const bad of ['', '  ', null, undefined, 3389, {}]) {
    assert.ok(!('console_protocol' in buildSpecVm({ console_protocol: bad }, 0, 'k')),
      `console_protocol should be absent for ${JSON.stringify(bad)}`);
  }
});

// ── 6. post_clone_scripts: an array of non-empty strings ─────────────────────

test('post_clone_scripts keeps its order and drops the junk entries', () => {
  const out = buildSpecVm({
    post_clone_scripts: ['init-setup', '', '  win-smb-vuln  ', null, 42, {}, 'lin-apache-2449'],
  }, 0, 'k');
  assert.deepStrictEqual(out.post_clone_scripts,
    ['init-setup', 'win-smb-vuln', 'lin-apache-2449'],
    'order is the order the deployer runs them in');
});

test('an empty or non-array post_clone_scripts is omitted', () => {
  // lane-provision reads `vm.post_clone_scripts || []`, so an empty array and an
  // absent key are indistinguishable downstream — omitting keeps a spec that
  // declares none byte-identical to one written before the key existed.
  for (const bad of [[], ['', '  '], null, undefined, 'init-setup', {}]) {
    assert.ok(!('post_clone_scripts' in buildSpecVm({ post_clone_scripts: bad }, 0, 'k')),
      `post_clone_scripts should be absent for ${JSON.stringify(bad)}`);
  }
});

test('post_clone_scripts is rebuilt, not aliased — the input array is untouched', () => {
  // The "rebuilt entry by entry" doctrine applies to arrays too: the route
  // JSON-stringifies immediately, but a caller that reuses its payload must not
  // observe buildSpecVm having edited it.
  const input = ['a', '', 'b'];
  const out = buildSpecVm({ post_clone_scripts: input }, 0, 'k');
  assert.deepStrictEqual(input, ['a', '', 'b']);
  assert.notStrictEqual(out.post_clone_scripts, input);
});

// ── 7. the Designer round trip — the regression that motivates the phase ─────

test('a Designer-shaped payload round-trips with console_role intact', () => {
  // The shape readTopoDesignState() posts to POST /api/admin/create-lab: canvas
  // layout, explicit nics, the console picker's three fields, plus the palette
  // drop's os_family. Every one of these was dropped before; the console
  // designation is the one an author can SEE on the canvas (the
  // '▸ student console' badge), which is what made the loss so confusing.
  const designerVms = [
    { __topoId: 'n1', name: 'ws01', role: 'workstation', os: 'Windows 11',
      os_family: 'windows_client', template_vmid: 1002, type: 'qemu', vm_offset: 600000,
      services: [], default_scripts: [],
      nics: [{ segment: 'lan' }], layout: { x: 120.4, y: 61.8 },
      console_role: 'primary', console_protocol: 'rdp', console_port: 3389 },
    { __topoId: 'n2', name: 'elk', role: 'siem', os: 'Ubuntu 22.04',
      os_family: 'linux', template_vmid: 1701, type: 'qemu', vm_offset: 610000,
      services: [], default_scripts: [], ipOctet: 24,
      nics: [{ segment: 'lan' }], layout: { x: 300, y: 61 } },
  ];

  const built = designerVms.map((vm, i) => buildSpecVm(vm, i, 'blueteam'));

  // The console survives creation — this is what fails without the fix.
  assert.strictEqual(built[0].console_role, 'primary');
  assert.strictEqual(built[0].console_protocol, 'rdp');
  assert.strictEqual(built[0].console_port, 3389);
  assert.strictEqual(built[1].ipOctet, 24);
  assert.ok(!('console_role' in built[1]), 'only one machine was designated');

  // And the editor's bookkeeping key still does not reach the database. That is
  // the whole point of keeping this an enumerated whitelist rather than a spread.
  assert.ok(built.every(v => !('__topoId' in v)));

  // Exactly one primary, which is what resolveConsolePlan requires. Asserted
  // against the real planner rather than by counting, so the two cannot drift.
  const { resolveConsolePlan } = require(path.join(UTILS, 'challenge-lane-deployer.js'));
  const plan = resolveConsolePlan({ specVms: built, attackBoxes: false });
  assert.strictEqual(plan.primary && plan.primary.name, 'ws01',
    'the machine the author designated on the canvas is the one the student opens');
});

test('two primaries in one Designer payload still reach the deploy-time guard', () => {
  // buildSpecVm does not enforce single-primary — resolveConsolePlan does, by
  // throwing and naming both. Preserving the field faithfully is what lets that
  // guard fire at all; before the fix a two-primary spec was "fixed" by the
  // whitelist dropping both, which is worse than the throw.
  const { resolveConsolePlan } = require(path.join(UTILS, 'challenge-lane-deployer.js'));
  const built = [
    buildSpecVm({ name: 'a', template_vmid: 1, console_role: 'primary' }, 0, 'k'),
    buildSpecVm({ name: 'b', template_vmid: 2, console_role: 'primary' }, 1, 'k'),
  ];
  assert.throws(() => resolveConsolePlan({ specVms: built }),
    /Two machines both declare console_role 'primary'/);
});

// ── 8. dns_aliases: the create path must agree with the deploy path ──────────
//
// These become `host-record=` lines in a dnsmasq config on the lane gateway, and
// ONE malformed line stops dnsmasq from starting — which takes DHCP down for
// every machine on the lane, not just the one with the bad alias. That is why
// lane-deployer.resolveDnsAliases drops invalid labels rather than writing them
// through, and it is why buildSpecVm must drop exactly the same ones: a spec
// that stores an alias the deployer will refuse is a canvas lying about what the
// lane answers to.

// The deployer warns on every dropped alias (by design — it is writing a real
// config). In here that is just noise across a table-driven parity check, so it
// is silenced per-call rather than globally, so a genuine warn from elsewhere
// still shows.
function deployerAliases(input) {
  const { resolveDnsAliases } = require(path.join(UTILS, 'lane-deployer.js'));
  const warn = console.warn;
  console.warn = () => {};
  try {
    return resolveDnsAliases({ template_key: 'test', metadata: { dns_aliases: input } });
  } finally {
    console.warn = warn;
  }
}

const specAliases = (input) => buildSpecVm({ name: 'elk01', dns_aliases: input }, 0, 'k').dns_aliases;

test('valid aliases survive, lowercased and de-duplicated', () => {
  assert.deepStrictEqual(specAliases(['elk']), ['elk']);
  assert.deepStrictEqual(specAliases(['elk', 'siem', 'log-01']), ['elk', 'siem', 'log-01'],
    'order is preserved — it is the order the host-record lines are written in');

  // Lowercasing is load-bearing, not cosmetic: 'ELK' is PUBLISHED as 'elk', so a
  // spec that stored 'ELK' would not equal the record the lane actually serves.
  assert.deepStrictEqual(specAliases([' ELK ']), ['elk']);
  assert.deepStrictEqual(specAliases(['elk', 'ELK', ' elk']), ['elk'],
    'two host-record lines for one name is exactly what dnsmasq refuses to start on');
});

test('an invalid label is dropped without taking the valid ones with it', () => {
  // The failure mode this rules out is all-or-nothing: one fat-fingered alias
  // must not cost the machine its working ones, and must not be passed through
  // either. `a.b` is the interesting case — it is a valid DNS *name* but not a
  // single *label*, and host-record wants a label.
  assert.deepStrictEqual(specAliases(['elk', 'not a label', 'a.b', '', 'siem']), ['elk', 'siem']);
  assert.deepStrictEqual(specAliases(['-lead', 'trail-', 'ok']), ['ok'],
    'a leading or trailing hyphen is not a legal label');
  assert.deepStrictEqual(specAliases(['x'.repeat(63), 'y'.repeat(64)]), ['x'.repeat(63)],
    '63 octets is the label ceiling');
});

test('an all-invalid list omits the key entirely, like every other additive key', () => {
  // Omitted, not `[]`. Downstream reads `vm.dns_aliases` through
  // resolveDnsAliases, which treats a non-array as none — so an empty array and
  // an absent key are indistinguishable, and omitting keeps a spec that declares
  // no aliases byte-identical to one written before the key existed.
  for (const bad of [[], ['', '   '], ['a.b', 'not a label'], [null, undefined, {}],
                     null, undefined, 'elk', {}, 42]) {
    const out = buildSpecVm({ name: 'a', dns_aliases: bad }, 0, 'k');
    assert.ok(!('dns_aliases' in out), `dns_aliases should be absent for ${JSON.stringify(bad)}`);
  }
});

test('the input array is rebuilt, not aliased', () => {
  const input = ['elk', 'a.b'];
  const out = buildSpecVm({ name: 'a', dns_aliases: input }, 0, 'k');
  assert.deepStrictEqual(input, ['elk', 'a.b'], 'a caller that reuses its payload sees it untouched');
  assert.notStrictEqual(out.dns_aliases, input);
});

test('buildSpecVm accepts exactly what lane-deployer.resolveDnsAliases accepts', () => {
  // THE point of this section. The label rule has ONE owner — DNS_LABEL_RE in
  // lane-deployer.js — and challenge-spec.js mirrors it because it is pure by
  // contract and cannot require a module that pulls cybercore-db, site-config,
  // guacamole and tailscale at load. A mirror can drift, so the agreement is
  // asserted against the REAL function rather than against a second copy of the
  // regex: run both over the same inputs and demand the same output. When these
  // disagree, a challenge stores DNS the lane will never serve.
  const cases = [
    ['elk'],
    ['ELK', 'elk'],
    [' siem '],
    ['elk', 'not a label', 'a.b', '', 'siem'],
    ['-lead', 'trail-', 'ok'],
    ['x'.repeat(63), 'y'.repeat(64)],
    ['a'],
    ['log-01', 'log_01'],
    ['192-168-1-1'],
    [42, 'elk'],
    [null, undefined, {}, [], true],
    ['a.b', 'not a label'],
    [],
  ];
  for (const input of cases) {
    // The create path omits the key where the deploy path returns []; that is
    // the only permitted difference, and it is the omit-when-empty contract.
    const created = specAliases(input) || [];
    assert.deepStrictEqual(created, deployerAliases(input),
      `create and deploy paths disagree about ${JSON.stringify(input)}`);
  }
});

test('a spec alias built here reaches the gateway as a host-record', () => {
  // End to end through the real line builder, so this pins the format too. The
  // FILE the challenge path writes is separate from the workstation path's (two
  // *.conf claiming one address stops dnsmasq), but the LINE must not be, or
  // `elk.cybercore.lan` means one thing on a workstation lane and another on a
  // challenge lane.
  const { hostRecordLine } = require(path.join(UTILS, 'lane-deployer.js'));
  const built = buildSpecVm(
    { name: 'elk', role: 'siem', ipOctet: 24, dns_aliases: ['ELK'] }, 0, 'blueteam');
  assert.deepStrictEqual(built.dns_aliases, ['elk']);
  assert.strictEqual(
    hostRecordLine(built.dns_aliases[0], `10.39.16.${built.ipOctet}`),
    'host-record=elk,elk.cybercore.lan,10.39.16.24');
});
