/**
 * topology-editor-derive.test.js — keeps two copies of one rule in step.
 *
 * The canvas has to know where a machine sits the moment it opens, including
 * for a legacy spec that has no explicit `nics`. That means the placement rule
 * exists twice: in lane-networking.resolveVmSegments (Node, authoritative, used
 * by the deploy paths) and in topology-editor.deriveSegments (browser).
 *
 * The duplication is deliberate — the alternative is a server round-trip before
 * the canvas can draw anything, including for unsaved rows the server has never
 * seen. This file is the price of that decision: every case is run through BOTH
 * implementations and asserted equal, so a change to one that is not mirrored in
 * the other fails here rather than silently drawing the wrong picture.
 *
 * Run: node front-end/test/topology-editor-derive.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const { resolveVmSegments, resolveSegments } =
  require(path.join(__dirname, '..', 'src', 'utils', 'lane-networking'));

// topology-editor.js only needs `window` at load time; everything DOM-facing
// lives inside mount(), which this file never calls.
function loadEditor() {
  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'topology', 'topology-editor.js'), 'utf8'),
    sandbox, { filename: 'topology-editor.js' });
  return sandbox.CyberCoreTopologyEditor;
}

const Editor = loadEditor();

// Every shape the placement rule distinguishes, across every scheme.
const CASES = [];
for (const scheme of ['v1', 'v2', 'v3']) {
  for (const isGoadVm of [false, true]) {
    for (const type of ['qemu', 'lxc']) {
      for (const role of ['', 'dmz', 'attacker', 'dc']) {
        CASES.push({ scheme, isGoadVm, spec: { name: 'host', type, role } });
      }
    }
  }
}
// Explicit attachments must win identically in both.
CASES.push(
  { scheme: 'v3', isGoadVm: true,  spec: { name: 'DC01', type: 'qemu', nics: [{ segment: 'ext' }] } },
  { scheme: 'v3', isGoadVm: false, spec: { name: 'p', type: 'qemu', nics: [{ segment: 'int' }, { segment: 'ext' }] } },
  { scheme: 'v2', isGoadVm: false, spec: { name: 'p', type: 'qemu', nics: [{ segment: 'lan' }] } },
  { scheme: 'v3', isGoadVm: false, spec: { name: 'p', type: 'qemu', nics: [] } },
  { scheme: 'v3', isGoadVm: false, spec: { name: 'p', type: 'qemu', nics: [{}, null] } },
  { scheme: 'v3', isGoadVm: true,  spec: { name: 'x', type: 'lxc', role: 'dmz' } },
);

for (const c of CASES) {
  const label = `${c.scheme} goad=${c.isGoadVm} ${c.spec.type || 'qemu'}` +
    `${c.spec.role ? ' role=' + c.spec.role : ''}` +
    `${c.spec.nics ? ' nics=' + JSON.stringify(c.spec.nics) : ''}`;

  test(`derivation agrees with the server — ${label}`, () => {
    const server = resolveVmSegments(c.spec, { subnetScheme: c.scheme, isGoadVm: c.isGoadVm });
    const client = Editor.deriveSegments(c.spec, c.scheme, c.isGoadVm);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(client)), server, label);
  });
}

test('segment lists agree with the server', () => {
  for (const scheme of ['v1', 'v2', 'v3']) {
    const server = resolveSegments(scheme).map(s => s.id);
    const client = JSON.parse(JSON.stringify(Editor.segmentsForScheme(scheme))).map(s => s.id);
    assert.deepStrictEqual(client, server, scheme);
  }
});

test('segment roles agree with the server too', () => {
  for (const scheme of ['v1', 'v2', 'v3']) {
    const server = resolveSegments(scheme).map(s => s.id + ':' + s.role);
    const client = JSON.parse(JSON.stringify(Editor.segmentsForScheme(scheme))).map(s => s.id + ':' + s.role);
    assert.deepStrictEqual(client, server, scheme);
  }
});

test('stripInternal removes the editor handle and nothing else', () => {
  const rows = [{ __topoId: 'r1', name: 'web01', vm_offset: 600000, nics: [{ segment: 'ext' }] }];
  const out = JSON.parse(JSON.stringify(Editor.stripInternal(rows)));
  assert.deepStrictEqual(out, [{ name: 'web01', vm_offset: 600000, nics: [{ segment: 'ext' }] }]);
  // Original untouched — the editor keeps using its handle after a save.
  assert.strictEqual(rows[0].__topoId, 'r1');
});
