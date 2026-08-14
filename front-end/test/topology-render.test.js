/**
 * topology-render.test.js — the browser renderer, exercised headlessly.
 *
 * topology-render.js is frontend code with no build step and no browser in CI,
 * so the data → graph mapping would otherwise be unverified until someone
 * clicked it. Cytoscape runs headless when given no container, which is enough
 * to assert the part most likely to be wrong: that segments, machines, NIC
 * edges and their net0/net1 ordering come out of setData() correctly, and that
 * getData() round-trips.
 *
 * The DOM surface used by the renderer is small (documentElement,
 * getComputedStyle, MutationObserver), so it is shimmed rather than pulling in
 * jsdom — this repo has no frontend test dependencies and should not grow one
 * for three functions.
 *
 * What this does NOT cover: painting, hit-testing, edgehandles drag gestures.
 * Those need a real browser and are in the plan's manual verification steps.
 *
 * Run: node front-end/test/topology-render.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

// ── a browser-shaped sandbox with the three DOM bits the renderer touches ────
function makeWindow(theme) {
  const sandbox = { console, setTimeout, clearTimeout, setInterval, clearInterval };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;

  const docEl = {
    _theme: theme || 'light',
    getAttribute(name) { return name === 'data-theme' ? this._theme : null; },
    setAttribute(name, v) { if (name === 'data-theme') this._theme = v; },
  };
  sandbox.document = {
    documentElement: docEl,
    // Cytoscape probes for these during headless init.
    createElement: () => ({ style: {}, appendChild() {}, setAttribute() {} }),
    addEventListener() {}, removeEventListener() {},
    head: { appendChild() {} }, body: { appendChild() {} },
  };
  // Empty values → the renderer falls back to its hard-coded defaults, which is
  // exactly what we want to assert against deterministically.
  sandbox.getComputedStyle = () => ({ getPropertyValue: () => '' });
  sandbox.MutationObserver = class { observe() {} disconnect() {} };
  sandbox.navigator = { userAgent: 'node' };

  vm.createContext(sandbox);
  for (const f of ['vendor/lodash.min.js', 'vendor/cytoscape.min.js',
                   'vendor/cytoscape-edgehandles.js',
                   'js/topology/topology-icons.js', 'js/topology/topology-render.js']) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  return sandbox;
}

/**
 * Values built inside the vm sandbox carry that realm's prototypes, so
 * deepStrictEqual rejects structurally identical arrays. Round-trip anything
 * crossing the boundary before comparing it to a literal in this file.
 */
const plain = (v) => JSON.parse(JSON.stringify(v));

const V3_SEGMENTS = [
  { id: 'ext', role: 'external', label: 'External / Attacker' },
  { id: 'int', role: 'internal', label: 'Internal / Corp' },
];

const SAMPLE = {
  segments: V3_SEGMENTS,
  gateway: { label: 'Lane gateway' },
  nodes: [
    { id: 'a', name: 'DC01',  role: 'dc',       os_family: 'windows_server', segments: ['int'] },
    { id: 'b', name: 'web01', role: 'dmz',      os_family: 'linux',          segments: ['ext', 'int'] },
    { id: 'c', name: 'Kali',  role: 'attacker', os_family: 'linux',          segments: ['ext'] },
  ],
};

function instance(win, mode) {
  // No container → Cytoscape headless.
  return win.CyberCoreTopology.create(null, { mode: mode || 'view' });
}

// ── globals load ─────────────────────────────────────────────────────────────

test('vendored bundle registers every global the renderer needs', () => {
  const win = makeWindow();
  assert.strictEqual(typeof win._.memoize, 'function');
  assert.strictEqual(typeof win._.throttle, 'function');
  assert.strictEqual(typeof win.cytoscape, 'function');
  assert.strictEqual(typeof win.cytoscapeEdgehandles, 'function');
  assert.strictEqual(typeof win.CyberCoreTopologyIcons, 'object');
  assert.strictEqual(typeof win.CyberCoreTopology.create, 'function');
});

// ── icons ────────────────────────────────────────────────────────────────────

test('icons: role beats OS family, and OS strings are sniffed as a fallback', () => {
  const I = makeWindow().CyberCoreTopologyIcons;
  assert.strictEqual(I.glyphKey({ role: 'dmz', os_family: 'linux' }), 'dmz');
  assert.strictEqual(I.glyphKey({ role: 'attacker', os_family: 'linux' }), 'attacker');
  assert.strictEqual(I.glyphKey({ role: 'dc' }), 'dc');
  assert.strictEqual(I.glyphKey({ os_family: 'windows_server' }), 'windows_server');
  assert.strictEqual(I.glyphKey({ kind: 'segment' }), 'segment');
  assert.strictEqual(I.glyphKey({ kind: 'gateway' }), 'gateway');
  // Hand-typed VM rows have only a free-text `os`.
  assert.strictEqual(I.glyphKey({ os: 'Windows Server 2022' }), 'windows_server');
  assert.strictEqual(I.glyphKey({ os: 'Windows 11 25H2' }), 'windows_client');
  assert.strictEqual(I.glyphKey({ os: 'Kali Linux' }), 'attacker');
  assert.strictEqual(I.glyphKey({ os: 'Debian 13' }), 'linux');
  assert.strictEqual(I.glyphKey({}), 'unknown');
});

test('icons: data URI is CSP-safe and carries the requested colour', () => {
  const I = makeWindow().CyberCoreTopologyIcons;
  const uri = I.for({ os_family: 'linux' }, '#ff0000');
  assert.ok(uri.startsWith('data:image/svg+xml;utf8,'), uri.slice(0, 40));
  assert.ok(decodeURIComponent(uri).includes('stroke="#ff0000"'));
});

// ── graph construction ───────────────────────────────────────────────────────

test('setData builds one node per segment, machine and gateway', () => {
  const t = instance(makeWindow());
  t.setData(SAMPLE);
  assert.strictEqual(t.cy.nodes('[kind="segment"]').length, 2);
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 3);
  assert.strictEqual(t.cy.nodes('[kind="gateway"]').length, 1);
});

test('NIC edges are one per attachment and labelled net0, net1 in order', () => {
  const t = instance(makeWindow());
  t.setData(SAMPLE);

  const nics = t.cy.edges('[kind="nic"]');
  assert.strictEqual(nics.length, 4); // 1 + 2 + 1

  const web01 = nics.filter(e => e.data('vmId') === 'b')
    .map(e => ({ seg: e.data('segId'), label: e.data('label') }))
    .sort((x, y) => x.label.localeCompare(y.label));
  assert.deepStrictEqual(plain(web01), [
    { seg: 'ext', label: 'net0' },
    { seg: 'int', label: 'net1' },
  ]);
});

test('the gateway is wired to every segment with dotted uplinks', () => {
  const t = instance(makeWindow());
  t.setData(SAMPLE);
  const uplinks = t.cy.edges('[kind="uplink"]');
  assert.strictEqual(uplinks.length, 2);
  assert.deepStrictEqual(plain(uplinks.map(e => e.data('target')).sort()), ['seg:ext', 'seg:int']);
});

test('an attachment to a segment that does not exist is dropped, not rendered', () => {
  const t = instance(makeWindow());
  t.setData({
    segments: [{ id: 'lan', role: 'lan', label: 'Lane Network' }],
    nodes: [{ id: 'a', name: 'srv', segments: ['lan', 'int'] }],
  });
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 1);
});

test('machines without an id get one, so a rename cannot orphan attachments', () => {
  const t = instance(makeWindow());
  t.setData({ segments: V3_SEGMENTS, nodes: [{ name: 'web01', segments: ['ext'] }] });
  const [n] = t.getNodes();
  assert.ok(n.id, 'expected a generated id');

  t.updateNode(n.id, { name: 'web02' });
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 1);
  assert.strictEqual(t.getNodes()[0].name, 'web02');
});

// ── mutation API ─────────────────────────────────────────────────────────────

test('addNode / removeNode keep the graph and state in step', () => {
  const win = makeWindow();
  let changes = 0;
  const t = win.CyberCoreTopology.create(null, { mode: 'edit', onChange: () => { changes += 1; } });
  t.setData({ segments: V3_SEGMENTS, nodes: [] });
  assert.strictEqual(changes, 0, 'setData must not fire onChange');

  const added = t.addNode({ name: 'srv01', segments: ['int'] });
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 1);
  assert.strictEqual(changes, 1);

  t.removeNode(added.id);
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 0);
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 0);
  assert.strictEqual(changes, 2);
});

test('setSegments drops attachments to segments that no longer exist', () => {
  // The v3 → v2 switch: the internal segment disappears, and nothing may be
  // left wired to a vanished network.
  const t = instance(makeWindow(), 'edit');
  t.setData(SAMPLE);
  t.setSegments([{ id: 'lan', role: 'lan', label: 'Lane Network' }]);

  const data = t.getData();
  assert.deepStrictEqual(plain(data.nodes.map(n => n.segments)), [[], [], []]);
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 0);
});

test('setValidation paints severity, and error beats warning on one machine', () => {
  const t = instance(makeWindow());
  t.setData(SAMPLE);
  t.setValidation([
    { vm: 'DC01', severity: 'warning' },
    { vm: 'DC01', severity: 'error' },
    { vm: 'Kali', severity: 'warning' },
    { vm: null, severity: 'warning' },        // topology-wide, belongs to no node
  ]);
  const sev = (name) => t.cy.nodes('[kind="vm"]')
    .filter(n => n.data('label').startsWith(name))[0].data('severity');
  assert.strictEqual(sev('DC01'), 'error');
  assert.strictEqual(sev('Kali'), 'warning');
  assert.strictEqual(sev('web01'), '');
});

test('getData round-trips through setData unchanged', () => {
  const win = makeWindow();
  const a = instance(win);
  a.setData(SAMPLE);
  const out = a.getData();

  const b = instance(win);
  b.setData(out);
  assert.deepStrictEqual(plain(b.getData()), plain(out));
});

test('getData is a copy — mutating it cannot corrupt the canvas', () => {
  const t = instance(makeWindow());
  t.setData(SAMPLE);
  const snapshot = t.getData();
  snapshot.nodes[0].name = 'MUTATED';
  snapshot.nodes.length = 0;
  assert.strictEqual(t.getNodes()[0].name, 'DC01');
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 3);
});

test('a live-lane payload with IPs renders them into the label', () => {
  const t = instance(makeWindow());
  t.setData({
    segments: [{ id: 'lan', role: 'lan', label: 'Lane Network', cidr: '10.4.12.0/24' }],
    nodes: [{ id: 'a', name: 'dvwa', ip: '10.4.12.14', segments: ['lan'] }],
  });
  assert.strictEqual(t.cy.nodes('[kind="vm"]')[0].data('label'), 'dvwa\n10.4.12.14');
  assert.strictEqual(t.cy.nodes('[kind="segment"]')[0].data('label'),
    'Lane Network\n10.4.12.0/24');
});

test('view mode renders the same graph as edit mode', () => {
  const win = makeWindow();
  const view = win.CyberCoreTopology.create(null, { mode: 'view' });
  const edit = win.CyberCoreTopology.create(null, { mode: 'edit' });
  view.setData(SAMPLE);
  edit.setData(SAMPLE);
  assert.strictEqual(view.cy.nodes().length, edit.cy.nodes().length);
  assert.strictEqual(view.cy.edges().length, edit.cy.edges().length);
});
