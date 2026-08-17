/**
 * challenge-spec-create.test.js — the equivalence gate for POST /create-lab.
 *
 * create-lab used to build each spec VM from a fixed 9-key object literal inline
 * in the route (lab-templates.js lines 480-491). That whitelist silently dropped
 * `nics` and `layout`, so a topology authored on the canvas deployed with derived
 * placement and lost every position — invisible until deploy time.
 *
 * buildSpecVm() replaces that literal. This file transcribes the ORIGINAL literal
 * as `legacySpecVm()` and asserts the new helper emits a byte-identical object for
 * every shape a caller that sends no `nics`/`layout` produces. That is the whole
 * back-compat guarantee: the flat Create Challenge form and the CLE course
 * provisioner both go through this path and must not change behaviour.
 *
 * If an equivalence case here fails, do NOT update the expectation — the refactor
 * changed existing behaviour, which is the one thing it must not do.
 *
 * Run: node front-end/test/challenge-spec-create.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
const { buildSpecVm, buildSpecNetwork } = require(path.join(UTILS, 'challenge-spec'));
const { resolveSegments } = require(path.join(UTILS, 'lane-networking'));

// ── the pre-refactor literal, transcribed verbatim from lab-templates.js ──────
function legacySpecVm(vm, idx, challenge_key) {
  return {
    name: vm.name || `vm${idx + 1}`,
    role: vm.role || 'Server',
    os: vm.os || 'Unknown',
    template_vmid: parseInt(vm.template_vmid),
    type: vm.type || 'qemu',
    vm_offset: parseInt(vm.vm_offset) || 600000,
    services: vm.services || [],
    default_scripts: vm.default_scripts || [],
    hostname: `${vm.name || challenge_key}.local`,
  };
}

// ── shapes real callers actually post ────────────────────────────────────────
const LEGACY_CASES = [
  ['fully populated',
    { name: 'web01', role: 'dmz', os: 'Linux (Debian)', template_vmid: 1601, type: 'qemu',
      vm_offset: 620000, services: ['80/HTTP'], default_scripts: ['smb-config'] }],
  ['no name — falls back to vmN and challenge_key hostname',
    { role: 'dc', os: 'Windows', template_vmid: 1004, vm_offset: 600000 }],
  ['no role/os — Server/Unknown defaults',
    { name: 'srv', template_vmid: 1600, vm_offset: 610000 }],
  ['template_vmid as a string (the form posts strings)',
    { name: 'a', template_vmid: '1601', vm_offset: 600000 }],
  ['template_vmid absent — parseInt(undefined) is NaN, which JSON-serialises to null',
    { name: 'b', vm_offset: 600000 }],
  ['vm_offset absent — defaults to 600000',
    { name: 'c', template_vmid: 1601 }],
  ['vm_offset as a string',
    { name: 'd', template_vmid: 1601, vm_offset: '640000' }],
  ['vm_offset 0 — falsy, so the || default applies (legacy quirk, preserved)',
    { name: 'e', template_vmid: 1601, vm_offset: 0 }],
  ['lxc',
    { name: 'lx01', type: 'lxc', template_vmid: 1600, vm_offset: 630000 }],
  ['GOAD row shape',
    { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, type: 'qemu',
      vm_offset: 600000, services: [], default_scripts: [] }],
  ['empty arrays stay empty arrays',
    { name: 'f', template_vmid: 1601, vm_offset: 600000, services: [], default_scripts: [] }],
];

for (const [label, vm] of LEGACY_CASES) {
  test(`buildSpecVm matches the pre-refactor literal — ${label}`, () => {
    const idx = 3;
    const key = 'dundercorp';
    assert.deepStrictEqual(buildSpecVm(vm, idx, key), legacySpecVm(vm, idx, key), label);
  });
}

test('a caller that sends no nics/layout gets neither key', () => {
  const out = buildSpecVm({ name: 'a', template_vmid: 1601, vm_offset: 600000 }, 0, 'k');
  assert.ok(!('nics' in out), 'nics must be absent, not empty');
  assert.ok(!('layout' in out), 'layout must be absent, not null');
});

// ── nics ─────────────────────────────────────────────────────────────────────

test('nics are carried through in order — NIC order is net0..netN', () => {
  const out = buildSpecVm(
    { name: 'web01', template_vmid: 1601, vm_offset: 600000, nics: [{ segment: 'ext' }, { segment: 'int' }] },
    0, 'k');
  assert.deepStrictEqual(out.nics, [{ segment: 'ext' }, { segment: 'int' }]);
});

test('nics are normalised to { segment } only — client bookkeeping is dropped', () => {
  const out = buildSpecVm(
    { name: 'a', template_vmid: 1601, nics: [{ segment: 'int', __topoId: 'r1', ip: '10.0.0.5', mac: 'aa:bb' }] },
    0, 'k');
  assert.deepStrictEqual(out.nics, [{ segment: 'int' }]);
});

test('segment ids are stringified', () => {
  const out = buildSpecVm({ name: 'a', nics: [{ segment: 7 }] }, 0, 'k');
  assert.deepStrictEqual(out.nics, [{ segment: '7' }]);
});

test('an all-empty nics list omits the key rather than writing []', () => {
  // validateTopology flags `nics: []` as malformed-nics, so an empty result must
  // read as "not authored" (fall back to derivation), not as "attached to nothing".
  for (const nics of [[], [{}, null], [{ segment: '' }], [{ segment: null }], 'ext', 42]) {
    const out = buildSpecVm({ name: 'a', nics }, 0, 'k');
    assert.ok(!('nics' in out), `nics: ${JSON.stringify(nics)} should omit the key`);
  }
});

test('partially-empty nics keep only the real entries', () => {
  const out = buildSpecVm({ name: 'a', nics: [{ segment: 'ext' }, {}, { segment: 'int' }] }, 0, 'k');
  assert.deepStrictEqual(out.nics, [{ segment: 'ext' }, { segment: 'int' }]);
});

// ── layout ───────────────────────────────────────────────────────────────────

test('layout is rounded to whole pixels', () => {
  const out = buildSpecVm({ name: 'a', layout: { x: 300.4, y: 200.6 } }, 0, 'k');
  assert.deepStrictEqual(out.layout, { x: 300, y: 201 });
});

test('layout accepts negatives and zero — the canvas pans', () => {
  const out = buildSpecVm({ name: 'a', layout: { x: -40, y: 0 } }, 0, 'k');
  assert.deepStrictEqual(out.layout, { x: -40, y: 0 });
});

test('a non-finite or partial layout omits the key', () => {
  for (const layout of [{ x: 'a', y: 2 }, { x: 1 }, { y: 1 }, {}, null, 'x', { x: NaN, y: 0 }, { x: Infinity, y: 0 }]) {
    const out = buildSpecVm({ name: 'a', layout }, 0, 'k');
    assert.ok(!('layout' in out), `layout: ${JSON.stringify(layout)} should omit the key`);
  }
});

test('layout carries no extra keys', () => {
  const out = buildSpecVm({ name: 'a', layout: { x: 1, y: 2, w: 99, locked: true } }, 0, 'k');
  assert.deepStrictEqual(out.layout, { x: 1, y: 2 });
});

// ── the editor handle must never reach the database ───────────────────────────

test('__topoId is never emitted, at any depth', () => {
  const out = buildSpecVm(
    { __topoId: 'r7', name: 'a', template_vmid: 1601, nics: [{ segment: 'ext', __topoId: 'r7' }],
      layout: { x: 1, y: 2 } },
    0, 'k');
  assert.ok(!JSON.stringify(out).includes('__topoId'), JSON.stringify(out));
});

test('unknown client-supplied keys are not passed through', () => {
  const out = buildSpecVm({ name: 'a', evil: 'x', vxlan_block: { start: 1 } }, 0, 'k');
  assert.ok(!('evil' in out));
  assert.ok(!('vxlan_block' in out));
});

test('the input object is not mutated', () => {
  const input = { name: 'a', nics: [{ segment: 'ext', ip: '1.2.3.4' }], layout: { x: 1.5, y: 2.5 } };
  const before = JSON.stringify(input);
  buildSpecVm(input, 0, 'k');
  assert.strictEqual(JSON.stringify(input), before);
});

// ── buildSpecNetwork ─────────────────────────────────────────────────────────

test('segments are regenerated from the scheme, never trusted from the client', () => {
  // A client-supplied id that no lane has makes resolveVmNics throw mid-deploy,
  // deep inside a half-built lane. Segment ids are derived from subnet_scheme.
  const out = buildSpecNetwork(
    { version: 1, segments: [{ id: 'wan', role: 'nonsense', label: 'Injected' }], layout: {} },
    'v3');
  assert.deepStrictEqual(out.segments, resolveSegments('v3'));
  assert.strictEqual(out.version, 1);
});

test('segments follow the scheme for every scheme', () => {
  for (const scheme of ['v1', 'v2', 'v3']) {
    const out = buildSpecNetwork({ segments: [{ id: 'x' }] }, scheme);
    assert.deepStrictEqual(out.segments, resolveSegments(scheme), scheme);
  }
});

test('layout is preserved — it is cosmetic and safe to accept', () => {
  const out = buildSpecNetwork(
    { segments: [{ id: 'ext' }], layout: { ext: { x: 120, y: 80 }, int: { x: 120, y: 420 }, __gw: { x: 400, y: 250 } } },
    'v3');
  assert.deepStrictEqual(out.layout, { ext: { x: 120, y: 80 }, int: { x: 120, y: 420 }, __gw: { x: 400, y: 250 } });
});

test('layout entries are rounded and non-finite ones dropped', () => {
  const out = buildSpecNetwork(
    { segments: [{ id: 'ext' }], layout: { ext: { x: 1.4, y: 2.6 }, int: { x: 'a', y: 1 }, lan: null } },
    'v3');
  assert.deepStrictEqual(out.layout, { ext: { x: 1, y: 3 } });
});

test('an absent or segment-less network returns null', () => {
  for (const net of [null, undefined, {}, { segments: [] }, { segments: 'ext' }, 'network', 42]) {
    assert.strictEqual(buildSpecNetwork(net, 'v3'), null, JSON.stringify(net));
  }
});

test('a network with segments but no layout still returns a usable object', () => {
  const out = buildSpecNetwork({ segments: [{ id: 'ext' }] }, 'v3');
  assert.deepStrictEqual(out, { version: 1, segments: resolveSegments('v3'), layout: {} });
});

test('buildSpecNetwork does not mutate its input', () => {
  const input = { version: 9, segments: [{ id: 'bogus' }], layout: { ext: { x: 1.5, y: 1.5 } } };
  const before = JSON.stringify(input);
  buildSpecNetwork(input, 'v3');
  assert.strictEqual(JSON.stringify(input), before);
});
