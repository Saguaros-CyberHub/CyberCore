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

test('goadHostNames: null unless GOAD is enabled, lowercased set otherwise', () => {
  assert.strictEqual(goadHostNames({}), null);
  assert.deepStrictEqual([...goadHostNames(GOAD_SPEC)].sort(), ['dc01', 'dc02', 'srv02']);
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
