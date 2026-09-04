/**
 * topology-validate.test.js — spec checks that run before a lane is built.
 *
 * Two halves:
 *   1. The legacy single-string checks (findGoadHostMismatch,
 *      findVmOffsetCollision) still behave exactly as they did inside
 *      challenge-lane-deployer.js — the CLE picker and the deploy path both
 *      depend on their wording and their null-means-fine contract.
 *   2. validateTopology, which reports the same problems per-machine so the
 *      canvas can badge the offending node, plus the new checks.
 *
 * Run: node front-end/test/topology-validate.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
const {
  findGoadHostMismatch,
  findVmOffsetCollision,
  goadHostNames,
  validateTopology,
} = require(path.join(UTILS, 'topology-validate'));

// GOAD-Light defines DC01, DC02, SRV02.
const GOAD_SPEC = { goad: { enabled: true, version: 'GOAD-Light' } };
const vm = (name, extra = {}) => ({ name, type: 'qemu', template_vmid: 1601, vm_offset: 600000, ...extra });

const codes = (r) => r.findings.map(f => f.code).sort();
const has = (r, code) => r.findings.some(f => f.code === code);

// ── 1. legacy contracts ──────────────────────────────────────────────────────

test('findVmOffsetCollision: null when every offset is distinct', () => {
  assert.strictEqual(findVmOffsetCollision([
    vm('a', { vm_offset: 600000 }), vm('b', { vm_offset: 610000 }),
  ]), null);
});

test('findVmOffsetCollision: names both VMs and the shared offset', () => {
  const msg = findVmOffsetCollision([vm('web01'), vm('db01')]);
  assert.match(msg, /'web01' and 'db01' share vm_offset 600000/);
  assert.match(msg, /distinct vm_offset/);
});

test('findVmOffsetCollision: a missing vm_offset defaults to 600000 and can collide', () => {
  const msg = findVmOffsetCollision([{ name: 'a' }, vm('b', { vm_offset: 600000 })]);
  assert.match(msg, /share vm_offset 600000/);
});

test('findGoadHostMismatch: null when GOAD is off', () => {
  assert.strictEqual(findGoadHostMismatch({}, [vm('anything')]), null);
});

test('findGoadHostMismatch: null when every host matches the lab', () => {
  assert.strictEqual(
    findGoadHostMismatch(GOAD_SPEC, [vm('DC01'), vm('DC02'), vm('SRV02')]), null);
});

test('findGoadHostMismatch: matching is case-insensitive', () => {
  assert.strictEqual(findGoadHostMismatch(GOAD_SPEC, [vm('dc01'), vm('srv02')]), null);
});

test('findGoadHostMismatch: reports SRV01 against a lab that defines SRV02', () => {
  const msg = findGoadHostMismatch(GOAD_SPEC, [vm('DC01'), vm('SRV01')]);
  assert.match(msg, /^SRV01 is not part of the 'GOAD-Light' GOAD lab/);
  assert.match(msg, /DC01, DC02, SRV02/);
  assert.match(msg, /EXTERNAL segment/);
});

test('findGoadHostMismatch: role dmz is deliberately external and never reported', () => {
  assert.strictEqual(
    findGoadHostMismatch(GOAD_SPEC, [vm('DC01'), vm('web01', { role: 'dmz' })]), null);
});

// THE CLE DEPLOY PICKER REGRESSION. This is the surface an instructor sees right
// before committing a cohort, and it was telling them their correctly authored
// environment was broken: "elk, ws01 are not part of the 'GOAD-Mini' GOAD lab".
// Same root cause as validateTopology's -- reading GOAD_LABS[version] directly
// instead of resolveGoadLab -- but a SECOND reader, fixed later than the first.
// The advice it gave ("rename them to match the lab") would have broken the spec.

test('findGoadHostMismatch: ticked extensions are not strays', () => {
  const spec = { goad: { enabled: true, version: 'GOAD-Mini', extensions: ['elk', 'ws01'] } };
  const out = findGoadHostMismatch(spec, [
    vm('DC01'),
    vm('ws01', { role: 'workstation' }),   // inLab -> composed into the roster
    vm('elk',  { role: 'siem' }),          // external -> deliberately not a GOAD host
  ]);
  assert.strictEqual(out, null, out || '');
});

test('findGoadHostMismatch: an UNTICKED extension machine is still reported', () => {
  // The exemption comes from what the spec SELECTED, never from the catalog at
  // large -- an `elk` on a lane with no elk extension really is unaddressed.
  const out = findGoadHostMismatch(
    { goad: { enabled: true, version: 'GOAD-Mini' } },
    [vm('DC01'), vm('elk', { role: 'siem' })]);
  assert.match(out || '', /^elk is not part of the 'GOAD-Mini' GOAD lab/);
});

test('findGoadHostMismatch: the roster it names keeps the lab own casing', () => {
  // `roster` is lowercased because it exists to be matched against; a human
  // reading "this lab defines dc01" when every other surface says DC01 is a
  // small avoidable confusion, so the message uses rosterNames.
  const out = findGoadHostMismatch(
    { goad: { enabled: true, version: 'GOAD-Mini' } }, [vm('stray')]);
  // NOTE: no backslash-b in this pattern. Written through a generator it becomes a
  // literal BACKSPACE (0x08) and the regex then matches nothing -- it cost a red
  // test here already. A plain includes() says the same thing and cannot rot.
  assert.ok((out || '').includes('which defines DC01.'), out || '');
  assert.ok(!/which defines dc01/.test(out || ''), out || '');
});

test('findGoadHostMismatch: a ticked inLab extension JOINS the named roster', () => {
  const out = findGoadHostMismatch(
    { goad: { enabled: true, version: 'GOAD-Mini', extensions: ['ws01'] } },
    [vm('stray')]);
  assert.match(out || '', /which defines DC01, ws01/,
    'the roster the message names must be the COMPOSED one the deployer uses');
});

test('goadHostNames: null unless GOAD is enabled, lowercased sets otherwise', () => {
  assert.strictEqual(goadHostNames({}), null);
  const g = goadHostNames(GOAD_SPEC);
  assert.deepStrictEqual([...g.roster].sort(), ['dc01', 'dc02', 'srv02']);
  assert.deepStrictEqual([...g.external], []);
});

// ── extensions: the validator must agree with resolveGoadLab ─────────────────
//
// These pin the bug that made the findings panel lie on every environment with
// extensions ticked. goadHostNames used to read GOAD_LABS[version] directly,
// which knows nothing about spec.goad.extensions, so the deploy path and the
// validator disagreed about two machines at once — and the validator's advice
// ("rename it to match the lab") would have BROKEN a correctly authored spec.

test('goadHostNames: an inLab extension joins the roster, an external one does not', () => {
  const g = goadHostNames({
    ...GOAD_SPEC,
    goad: { ...GOAD_SPEC.goad, version: 'GOAD-Light', extensions: ['ws01', 'elk'] },
  });
  // ws01 is domain-joined, so resolveGoadLab composes it into the lab roster —
  // that membership is what earns it the deterministic MAC and the heal.
  assert.ok(g.roster.has('ws01'), [...g.roster].join(','));
  // elk is deliberately NOT a GOAD host: being absent from goadMacs is the only
  // reason resolveSpecAddressing still sees it and emits its host-record.
  assert.ok(!g.roster.has('elk'));
  assert.ok(g.external.has('elk'));
});

test('extension machines draw no goad-name-mismatch warning', () => {
  const r = validateTopology({
    spec: { ...GOAD_SPEC, goad: { ...GOAD_SPEC.goad, version: 'GOAD-Light', extensions: ['ws01', 'elk'] } },
    subnetScheme: 'v2',
    specVms: [
      vm('DC01', { vm_offset: 600000 }),
      vm('ws01', { vm_offset: 610000, role: 'workstation', template_vmid: 1002 }),
      vm('elk',  { vm_offset: 620000, role: 'siem', template_vmid: 9001, ipOctet: 24 }),
    ],
  });
  assert.ok(!r.findings.some(f => f.code === 'goad-name-mismatch'),
    JSON.stringify(r.findings.filter(f => f.code === 'goad-name-mismatch'), null, 2));
});

test('an UNTICKED extension machine is still a stray — the exemption is per-spec', () => {
  // The exemption comes from what this spec SELECTED, never from the catalog at
  // large. A machine named `elk` on a lane with no elk extension really is
  // unaddressed, and saying so is the whole value of the check.
  const r = validateTopology({
    spec: GOAD_SPEC,
    subnetScheme: 'v2',
    specVms: [vm('DC01', { vm_offset: 600000 }), vm('elk', { vm_offset: 610000, role: 'siem' })],
  });
  assert.ok(r.warnings.some(f => f.code === 'goad-name-mismatch' && f.vm === 'elk'));
});

test('missing-template on an extension names the catalog VMID and says what that image is', () => {
  // WHAT CHANGED AND WHY. This assertion used to demand the words "registered per
  // site" and "never installs anything" — the prebaked-SIEM design, where elk was
  // a golden image each site baked and ticking the extension installed nothing.
  // That design is gone: elk and wazuh clone ONE generic Ubuntu base and GOAD's
  // own extensions/<key>/ansible builds the stack in the lane at deploy time. The
  // old wording is now a falsehood, so the test that pinned it had to move with
  // the message rather than keep it alive.
  const r = validateTopology({
    spec: { ...GOAD_SPEC, goad: { ...GOAD_SPEC.goad, version: 'GOAD-Light', extensions: ['elk'] } },
    subnetScheme: 'v2',
    specVms: [vm('elk', { vm_offset: 600000, role: 'siem', template_vmid: null, ipOctet: 24 })],
  });
  const f = r.errors.find(x => x.code === 'missing-template' && x.vm === 'elk');
  assert.ok(f, JSON.stringify(r.errors, null, 2));
  // It must name the VMID the catalog already knows — the generic "nothing to
  // clone" sent an author looking for a broken catalog instead of a blank field.
  assert.match(f.message, /template 1011/);
  // …and it must say the image is PLAIN, or an author bakes a SIEM nobody needs.
  assert.match(f.message, /plain/i);
  assert.match(f.message, /install_extension elk/);
  assert.ok(!/never installs anything/.test(f.message),
    'the message must not carry the replaced design forward');
});

// ── extensions on a pre-baked lane ──────────────────────────────────────────
//
// THE ONE COMBINATION THAT DEPLOYS GREEN AND DOES NOTHING. Extensions are
// installed by /opt/goad-light/run.sh, which only a LIVE lane ever runs — a
// pre-baked lane clones golden images and heals secure channels, and
// challenge-lane-deployer's liveGoadController is literally
// `enabled && !prebaked`. So a ticked extension on a pre-baked environment does every
// visible thing (clone, address, DNS record, console) and the one that matters
// not at all, and the lane still reports active.

test('prebaked-extension: an extension still on the PLAIN base is an ERROR', () => {
  const r = validateTopology({
    spec: {
      goad: {
        enabled: true, version: 'GOAD-Light', prebaked: true,
        fixed_subnet: { int: '10.9.9', ext: '10.9.9' },
        extensions: ['elk'],
      },
    },
    subnetScheme: 'v2',
    specVms: [
      vm('DC01', { vm_offset: 600000, role: 'dc' }),
      vm('elk', { vm_offset: 610000, role: 'siem', template_vmid: 1011, ipOctet: 24 }),
    ],
  });
  const f = r.errors.find(x => x.code === 'prebaked-extension');
  assert.ok(f, 'expected a prebaked-extension error: ' + JSON.stringify(r.findings, null, 2));
  // It has to name BOTH halves of the pair, because either one alone is fine and
  // an author reading only "elk is wrong" would go looking at the elk machine.
  assert.match(f.message, /'elk'/);
  assert.match(f.message, /spec\.goad\.prebaked/);
  assert.match(f.message, /run\.sh/);
  // Badged on the offending node, so the canvas can point at it.
  assert.strictEqual(f.vm, 'elk');
});

test('prebaked-extension: a SEALED template clears it — pre-baked is the destination', () => {
  // The rule is not "is this lane pre-baked". Once the stack is sealed into a
  // golden image (seal-goad-elk-template.sh -> 1012), pre-baked is exactly the
  // mode you want, and nothing needs to install because the image carries it.
  const r = validateTopology({
    spec: {
      goad: {
        enabled: true, version: 'GOAD-Light', prebaked: true,
        fixed_subnet: { int: '10.9.9', ext: '10.9.9' },
        extensions: ['elk'],
      },
    },
    subnetScheme: 'v2',
    specVms: [
      vm('DC01', { vm_offset: 600000, role: 'dc' }),
      vm('elk', { vm_offset: 610000, role: 'siem', template_vmid: 1012, ipOctet: 24 }),
    ],
  });
  assert.ok(!r.findings.some(f => f.code === 'prebaked-extension'),
    'a sealed image must not be reported: ' + JSON.stringify(r.findings, null, 2));
});

test('prebaked-extension reports one finding per ticked extension', () => {
  const r = validateTopology({
    spec: {
      goad: {
        enabled: true, version: 'GOAD-Light', prebaked: true,
        extensions: ['elk', 'wazuh'],
      },
    },
    subnetScheme: 'v2',
    specVms: [vm('DC01', { vm_offset: 600000, role: 'dc' })],
  });
  const found = r.errors.filter(x => x.code === 'prebaked-extension');
  assert.strictEqual(found.length, 2, JSON.stringify(r.errors, null, 2));
  assert.deepStrictEqual(found.map(f => f.vm), [null, null],
    'an extension can be ticked before its machine row exists; a finding pinned to a node that is not on '
    + 'the canvas renders nowhere, so it stays a whole-topology finding until the row appears');
});

test('a LIVE lane with the same extensions draws no prebaked-extension finding', () => {
  // Live is the default and the mode that installs. The check must fire on the
  // PAIR and never on the extension alone, or it becomes a permanent false
  // positive on the normal path — which trains authors to ignore the panel.
  const r = validateTopology({
    spec: { ...GOAD_SPEC, goad: { ...GOAD_SPEC.goad, extensions: ['elk', 'wazuh'] } },
    subnetScheme: 'v2',
    specVms: [
      vm('DC01', { vm_offset: 600000, role: 'dc' }),
      vm('elk', { vm_offset: 610000, role: 'siem', template_vmid: 1011, ipOctet: 24 }),
    ],
  });
  assert.ok(!has(r, 'prebaked-extension'), JSON.stringify(r.findings, null, 2));
});

test('a pre-baked lane with NO extensions draws no prebaked-extension finding', () => {
  const r = validateTopology({
    spec: { goad: { enabled: true, version: 'GOAD-Light', prebaked: true } },
    subnetScheme: 'v2',
    specVms: [vm('DC01', { vm_offset: 600000, role: 'dc' })],
  });
  assert.ok(!has(r, 'prebaked-extension'), JSON.stringify(r.findings, null, 2));
});

test('missing-template stays generic for an ordinary machine', () => {
  const r = validateTopology({
    spec: {}, subnetScheme: 'v1',
    specVms: [vm('box01', { vm_offset: 600000, template_vmid: null })],
  });
  const f = r.errors.find(x => x.code === 'missing-template');
  assert.ok(f);
  assert.match(f.message, /nothing to clone/);
});

// ── 2. validateTopology ──────────────────────────────────────────────────────

test('a sound v3 GOAD topology reports no errors', () => {
  const r = validateTopology({
    spec: GOAD_SPEC,
    subnetScheme: 'v3',
    specVms: [
      vm('DC01', { vm_offset: 600000 }),
      vm('SRV02', { vm_offset: 610000 }),
      vm('web01', { vm_offset: 620000, role: 'dmz' }),
      vm('Kali', { vm_offset: 630000, role: 'attacker' }),
    ],
  });
  assert.deepStrictEqual(r.errors, [], JSON.stringify(r.errors, null, 2));
  assert.deepStrictEqual(r.warnings, [], JSON.stringify(r.warnings, null, 2));
});

test('an empty spec is an error, not a crash', () => {
  const r = validateTopology({ specVms: [] });
  assert.ok(has(r, 'no-vms'));
});

test('offset collision is reported against the second machine', () => {
  const r = validateTopology({ subnetScheme: 'v2', specVms: [vm('web01'), vm('db01')] });
  const f = r.errors.find(x => x.code === 'offset-collision');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'db01');
  assert.match(f.message, /same VMID/);
});

test('duplicate names and missing templates are per-machine errors', () => {
  const r = validateTopology({
    subnetScheme: 'v2',
    specVms: [
      vm('web01', { vm_offset: 600000 }),
      vm('web01', { vm_offset: 610000 }),
      { name: 'db01', vm_offset: 620000 },
    ],
  });
  assert.ok(has(r, 'duplicate-name'));
  assert.ok(has(r, 'missing-template'));
});

test('spec.template_vmid satisfies the template check for a legacy single-VM spec', () => {
  const r = validateTopology({
    spec: { template_vmid: 1700 },
    subnetScheme: 'v1',
    specVms: [{ name: 'metasploitable', vm_offset: 600000 }],
  });
  assert.ok(!has(r, 'missing-template'), codes(r));
});

test('GOAD name mismatch is reported against the specific machine', () => {
  const r = validateTopology({
    spec: GOAD_SPEC,
    subnetScheme: 'v3',
    specVms: [
      vm('DC01', { vm_offset: 600000 }),
      vm('SRV01', { vm_offset: 610000 }),
      vm('web01', { vm_offset: 620000, role: 'dmz' }),
    ],
  });
  // A warning, not an error — the deploy path only console.warns this.
  const f = r.warnings.find(x => x.code === 'goad-name-mismatch');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'SRV01');
  assert.ok(!r.errors.some(x => x.code === 'goad-name-mismatch'));
});

test('the default Kali row does not trip the GOAD name check', () => {
  // The template editor pushes { name: 'Kali', role: 'attacker' } into every
  // GOAD challenge, so flagging it would be a permanent false positive.
  const r = validateTopology({
    spec: GOAD_SPEC,
    subnetScheme: 'v3',
    specVms: [
      vm('DC01', { vm_offset: 600000 }),
      vm('web01', { vm_offset: 610000, role: 'dmz' }),
      vm('Kali', { vm_offset: 620000, role: 'attacker' }),
    ],
  });
  assert.ok(!has(r, 'goad-name-mismatch'), codes(r));
});

test('an explicit attachment suppresses the GOAD name-mismatch warning', () => {
  // Naming is only load-bearing because it drives placement. Once the author
  // has said where the machine goes, a non-lab name is a deliberate choice.
  const r = validateTopology({
    spec: GOAD_SPEC,
    subnetScheme: 'v3',
    specVms: [
      vm('DC01', { vm_offset: 600000 }),
      vm('FILESRV', { vm_offset: 610000, nics: [{ segment: 'int' }] }),
      vm('web01', { vm_offset: 620000, role: 'dmz' }),
    ],
  });
  assert.ok(!has(r, 'goad-name-mismatch'), codes(r));
});

test('attaching to a segment the scheme does not have is an error', () => {
  const r = validateTopology({
    subnetScheme: 'v2',
    specVms: [vm('srv', { nics: [{ segment: 'int' }] })],
  });
  const f = r.errors.find(x => x.code === 'unknown-segment');
  assert.ok(f, codes(r));
  assert.match(f.message, /a v2 lane does not have \(lan\)/);
});

test('a nics list with no usable segment is an error', () => {
  const r = validateTopology({ subnetScheme: 'v3', specVms: [vm('srv', { nics: [{}, null] })] });
  assert.ok(has(r, 'malformed-nics'));
});

test('v3 with nothing internal and no pivot warns, but does not error', () => {
  const r = validateTopology({
    subnetScheme: 'v3',
    specVms: [vm('Kali', { vm_offset: 600000 }), vm('web01', { vm_offset: 610000 })],
  });
  assert.deepStrictEqual(r.errors, [], JSON.stringify(r.errors, null, 2));
  assert.ok(has(r, 'empty-internal-segment'));
  assert.ok(has(r, 'no-pivot-host'));
});

test('a dual-homed host clears the pivot warning', () => {
  const r = validateTopology({
    subnetScheme: 'v3',
    specVms: [
      vm('Kali', { vm_offset: 600000 }),
      vm('web01', { vm_offset: 610000, role: 'dmz' }),
    ],
  });
  assert.ok(!has(r, 'no-pivot-host'), codes(r));
  assert.ok(!has(r, 'empty-internal-segment'), codes(r));
});

test('v1/v2 never emit the v3-only segment warnings', () => {
  for (const scheme of ['v1', 'v2']) {
    const r = validateTopology({ subnetScheme: scheme, specVms: [vm('solo')] });
    assert.ok(!has(r, 'empty-internal-segment'), scheme);
    assert.ok(!has(r, 'no-pivot-host'), scheme);
  }
});

test('catalog check is a warning, and is skipped entirely when no catalog is passed', () => {
  const specVms = [vm('web01', { template_vmid: 9999 })];
  assert.ok(!has(validateTopology({ subnetScheme: 'v2', specVms }), 'template-not-in-catalog'));

  const r = validateTopology({ subnetScheme: 'v2', specVms, catalogVmids: new Set([1601, 1700]) });
  const f = r.warnings.find(x => x.code === 'template-not-in-catalog');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'web01');
  assert.deepStrictEqual(r.errors, []);
});

test('validateTopology tolerates being called with nothing at all', () => {
  const r = validateTopology();
  assert.ok(Array.isArray(r.errors) && Array.isArray(r.warnings) && Array.isArray(r.findings));
});

// ── 3. the blue-team findings ────────────────────────────────────────────────
//
// Three codes added for the defensive/SIEM environments Track E authors. Each
// describes a topology that LOOKS right on the canvas and is either useless or
// undeployable in the lane — the class of failure this validator exists for.

// ── no-nic: the empty-nics contract, stated loudly ──────────────────────────
//
// The full four-layer round trip lives in test/topology-nics-contract.test.js.
// These are the validator's half of it.

test('no-nic: an empty nics list is an error, not a silent re-attach', () => {
  const r = validateTopology({ subnetScheme: 'v2', specVms: [vm('DC01', { nics: [] })] });
  const f = r.errors.find(x => x.code === 'no-nic');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'DC01');
  // The message has to name the CONSEQUENCE. "This machine has no NICs" reads as
  // a harmless omission; "it deploys attached anyway" is the actual problem.
  assert.match(f.message, /silently deploy attached/);
  assert.match(f.message, /no DHCP lease/);
});

test('no-nic: a nics list of junk entries raises BOTH it and malformed-nics', () => {
  // Two true statements about one machine: the entries are unusable, AND the
  // machine therefore resolves to no segment at all and would re-attach.
  const r = validateTopology({ subnetScheme: 'v3', specVms: [vm('srv', { nics: [{}, null] })] });
  assert.ok(has(r, 'malformed-nics'), codes(r));
  assert.ok(has(r, 'no-nic'), codes(r));
});

test('no-nic: an absent nics key is NOT flagged — omit means derive', () => {
  // Every pre-canvas challenge is this shape. Flagging it would put an error on
  // every legacy spec the moment the Designer opens it.
  assert.ok(!has(validateTopology({ subnetScheme: 'v2', specVms: [vm('web01')] }), 'no-nic'));
  assert.ok(!has(validateTopology({
    subnetScheme: 'v2', specVms: [vm('web01', { nics: [{ segment: 'lan' }] })],
  }), 'no-nic'));
});

// ── siem-blind-host: ELK instruments [domain] only ──────────────────────────

const ELK = (extra = {}) => vm('elk', { role: 'siem', vm_offset: 610000, ...extra });
const WAZUH = (extra = {}) => vm('wazuh', { role: 'siem', vm_offset: 620000, ...extra });
const LX = (extra = {}) => vm('lx01', { role: 'linux', vm_offset: 630000, ...extra });

test('siem-blind-host: a Linux host on an ELK-only lane is a warning', () => {
  const r = validateTopology({ subnetScheme: 'v2', specVms: [ELK(), LX()] });
  const f = r.warnings.find(x => x.code === 'siem-blind-host');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'lx01');
  assert.deepStrictEqual(r.errors, [], 'the lane still deploys — this is not an error');
  // The message must explain WHY, because the reason is a detail of GOAD's
  // inventory that nobody reading the canvas can be expected to know.
  assert.match(f.message, /\[domain\] group only/);
  assert.match(f.message, /never \[linux_domain\]/);
  assert.match(f.message, /DARK BOX/);
});

test('siem-blind-host: adding wazuh clears it — its extension does cover Linux', () => {
  const r = validateTopology({ subnetScheme: 'v2', specVms: [ELK(), WAZUH(), LX()] });
  assert.ok(!has(r, 'siem-blind-host'), codes(r));
});

test('siem-blind-host: no ELK machine, no finding', () => {
  // A lane with a Linux box and no SIEM at all is just a lane with a Linux box.
  assert.ok(!has(validateTopology({ subnetScheme: 'v2', specVms: [LX()] }), 'siem-blind-host'));
  assert.ok(!has(validateTopology({ subnetScheme: 'v2', specVms: [WAZUH(), LX()] }), 'siem-blind-host'));
});

test('siem-blind-host: it is the NAME plus role siem, not either alone', () => {
  // 'elk' is the name the golden images and the baked agent configs agree on
  // (ELK_HOST=elk.cybercore.lan), so a differently-named SIEM is not GOAD's elk
  // extension and this rule says nothing about it.
  const notElk = vm('siem01', { role: 'siem', vm_offset: 610000 });
  assert.ok(!has(validateTopology({ subnetScheme: 'v2', specVms: [notElk, LX()] }), 'siem-blind-host'));
  const notSiem = vm('elk', { role: 'server', vm_offset: 610000 });
  assert.ok(!has(validateTopology({ subnetScheme: 'v2', specVms: [notSiem, LX()] }), 'siem-blind-host'));
});

test('siem-blind-host: every Linux host is named, not just the first', () => {
  const r = validateTopology({
    subnetScheme: 'v2',
    specVms: [ELK(), LX(), vm('lx02', { role: 'linux', vm_offset: 640000 })],
  });
  assert.deepStrictEqual(
    r.warnings.filter(f => f.code === 'siem-blind-host').map(f => f.vm), ['lx01', 'lx02']);
});

// ── siem-octet-collision: .50 is Kali, and v2 has one flat subnet ───────────

const GOAD_V2 = { goad: { enabled: true, version: 'GOAD-Light' } };

test('siem-octet-collision: .50 with Kali on a flat subnet is an error', () => {
  const r = validateTopology({
    spec: GOAD_V2, subnetScheme: 'v2',
    specVms: [vm('DC01'), ELK({ ipOctet: 50 })],
  });
  const f = r.errors.find(x => x.code === 'siem-octet-collision');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'elk');
  assert.match(f.message, /\.50/);
  assert.match(f.message, /Kali attack box/);
  assert.match(f.message, /dnsmasq refuses to start/);
});

test('siem-octet-collision: include_kali defaults to TRUE, matching the deploy path', () => {
  // goad-deploy tests `include_kali !== false` in three places, so a GOAD spec
  // that never mentions Kali still gets one. A check that required the key to be
  // explicitly true would miss every spec the UI actually writes.
  const specVms = [ELK({ ipOctet: 50 })];
  assert.ok(has(validateTopology({ spec: GOAD_V2, subnetScheme: 'v2', specVms }), 'siem-octet-collision'));
  assert.ok(has(validateTopology({
    spec: { goad: { enabled: true, version: 'GOAD-Light', include_kali: true } },
    subnetScheme: 'v2', specVms,
  }), 'siem-octet-collision'));
});

test('siem-octet-collision: include_kali false frees the octet', () => {
  const r = validateTopology({
    spec: { goad: { enabled: true, version: 'GOAD-Light', include_kali: false } },
    subnetScheme: 'v2', specVms: [ELK({ ipOctet: 50 })],
  });
  assert.ok(!has(r, 'siem-octet-collision'), codes(r));
});

test('siem-octet-collision: v3 puts them on different segments, so no finding', () => {
  // This is why the program plan called it a non-collision. It is only real on
  // v1/v2, where ext and int are the same flat lan0.
  const r = validateTopology({
    spec: GOAD_V2, subnetScheme: 'v3', specVms: [ELK({ ipOctet: 50 })],
  });
  assert.ok(!has(r, 'siem-octet-collision'), codes(r));
});

test('siem-octet-collision: v1 collides exactly as v2 does', () => {
  const r = validateTopology({ spec: GOAD_V2, subnetScheme: 'v1', specVms: [ELK({ ipOctet: 50 })] });
  assert.ok(has(r, 'siem-octet-collision'), codes(r));
});

test('siem-octet-collision: no GOAD block, no Kali, no finding', () => {
  const r = validateTopology({ subnetScheme: 'v2', specVms: [ELK({ ipOctet: 50 })] });
  assert.ok(!has(r, 'siem-octet-collision'), codes(r));
});

test('siem-octet-collision: any octet but .50 is fine, and .24 is the ELK slot', () => {
  for (const octet of [24, 31, 51, 85]) {
    const r = validateTopology({ spec: GOAD_V2, subnetScheme: 'v2', specVms: [ELK({ ipOctet: octet })] });
    assert.ok(!has(r, 'siem-octet-collision'), `.${octet}: ${codes(r)}`);
  }
});

test('siem-octet-collision: it is not SIEM-only — any machine pinned to .50 collides', () => {
  // The code is named for the case that motivated it (GOAD's elk inventory pins
  // .50), but the collision is about the ADDRESS, not the role. A workstation
  // pinned there breaks DHCP for the lane in exactly the same way.
  const r = validateTopology({
    spec: GOAD_V2, subnetScheme: 'v2',
    specVms: [vm('ws01', { role: 'workstation', ipOctet: 50 })],
  });
  assert.ok(has(r, 'siem-octet-collision'), codes(r));
});

test('the three new codes stay silent on a plain, sound topology', () => {
  // The regression that matters most for a validator painted live on a canvas:
  // a finding that fires on ordinary specs trains authors to ignore all of them.
  const r = validateTopology({
    spec: GOAD_V2, subnetScheme: 'v2',
    specVms: [vm('DC01'), vm('DC02', { vm_offset: 610000 }), vm('SRV02', { vm_offset: 620000 })],
  });
  for (const code of ['no-nic', 'siem-blind-host', 'siem-octet-collision']) {
    assert.ok(!has(r, code), `${code} fired on a sound spec: ${codes(r)}`);
  }
});

// ── student console: the lane where everything ran and nothing was reachable ─

const GOAD_MINI_WS01 = {
  goad: { enabled: true, version: 'GOAD-Mini', extensions: ['elk', 'ws01'] },
};

test('goad-host-console: a GOAD roster machine cannot be the student console', () => {
  // The authored shape that produced the incident: GOAD-Mini + elk + ws01, Kali
  // off, ws01 marked primary. Every machine deployed Running; the Guacamole
  // connection carried no credentials and pointed at a console-band address
  // while GOAD booted ws01 at its lab octet.
  const r = validateTopology({
    spec: { ...GOAD_MINI_WS01, goad: { ...GOAD_MINI_WS01.goad, include_kali: false } },
    subnetScheme: 'v2',
    specVms: [
      vm('DC01'),
      ELK({ ipOctet: 24, vm_offset: 610000 }),
      vm('ws01', { role: 'workstation', vm_offset: 620000, console_role: 'primary' }),
    ],
  });
  const f = r.errors.find(x => x.code === 'goad-host-console');
  assert.ok(f, codes(r));
  assert.strictEqual(f.vm, 'ws01');
  assert.match(f.message, /no username or password/);
  assert.match(f.message, /Leave it as a target/);
});

test('goad-host-console: an EXTERNAL extension is exempt — it is an ordinary spec VM', () => {
  // elk is placed by resolveSpecAddressing like any pinnable machine, so its
  // explicit ipOctet is honoured and the address half of the bug cannot apply.
  // It is a poor console for its own reason (headless Ubuntu), which is not
  // this rule's business.
  const r = validateTopology({
    spec: GOAD_MINI_WS01, subnetScheme: 'v2',
    specVms: [vm('DC01'), ELK({ ipOctet: 24, vm_offset: 610000, console_role: 'primary' })],
  });
  assert.ok(!has(r, 'goad-host-console'), codes(r));
});

test('no-student-console: Kali off and nothing designated is a warning', () => {
  const r = validateTopology({
    spec: { goad: { enabled: true, version: 'GOAD-Mini', include_kali: false } },
    subnetScheme: 'v2',
    specVms: [vm('DC01')],
  });
  const f = r.warnings.find(x => x.code === 'no-student-console');
  assert.ok(f, codes(r));
  assert.match(f.message, /no way in/);
});

test('no-student-console: silent when Kali is on, or when a machine is designated', () => {
  // include_kali defaults TRUE, matching the deploy path — so an unedited GOAD
  // spec already has a console and must not be flagged.
  assert.ok(!has(validateTopology({
    spec: { goad: { enabled: true, version: 'GOAD-Mini' } },
    subnetScheme: 'v2', specVms: [vm('DC01')],
  }), 'no-student-console'));

  assert.ok(!has(validateTopology({
    spec: { goad: { enabled: true, version: 'GOAD-Mini', include_kali: false } },
    subnetScheme: 'v2',
    specVms: [vm('DC01'), vm('analyst', { vm_offset: 610000, console_role: 'primary' })],
  }), 'no-student-console'));
});

test('no-student-console: never fires on a non-GOAD challenge', () => {
  // A plain lane gets its console from a deploy-time added workstation, which
  // the spec cannot see. Firing here would flag nearly every non-GOAD spec.
  const r = validateTopology({ subnetScheme: 'v2', specVms: [vm('web01')] });
  assert.ok(!has(r, 'no-student-console'), codes(r));
});
