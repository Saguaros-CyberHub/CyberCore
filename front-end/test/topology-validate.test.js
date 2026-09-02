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

test('missing-template on an extension explains that the image is registered per site', () => {
  const r = validateTopology({
    spec: { ...GOAD_SPEC, goad: { ...GOAD_SPEC.goad, version: 'GOAD-Light', extensions: ['elk'] } },
    subnetScheme: 'v2',
    specVms: [vm('elk', { vm_offset: 600000, role: 'siem', template_vmid: null, ipOctet: 24 })],
  });
  const f = r.errors.find(x => x.code === 'missing-template' && x.vm === 'elk');
  assert.ok(f, JSON.stringify(r.errors, null, 2));
  // It must say WHERE the VMID comes from and that ticking installs nothing —
  // the generic "nothing to clone" sent an author looking for a broken catalog.
  assert.match(f.message, /registered per site/);
  assert.match(f.message, /never installs anything/);
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
