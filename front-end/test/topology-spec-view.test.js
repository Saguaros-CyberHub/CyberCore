/**
 * topology-spec-view.test.js — drawing a challenge SPEC, headlessly.
 *
 * The Topology tab's viewer has two modes. The live-lane one is fed a payload the
 * server already shaped. The spec one is not: it derives every attachment in the
 * browser from spec.vms, which means the picture an admin uses to reason about a
 * challenge is only as good as specToGraph. A machine drawn on the wrong segment
 * here would look authoritative and be wrong.
 *
 * So this drives the REAL path — CyberCoreTopologySeed.specToGraph feeding
 * CyberCoreTopology.setData — through headless Cytoscape, and asserts what comes
 * out the far end: node counts, which segment each machine landed on, and NIC
 * ordering, which is load-bearing because nics[] order IS net0..netN.
 *
 * The DOM shim is the same three-method one topology-render.test.js uses; this
 * repo has no frontend test dependencies and should not grow jsdom for it.
 *
 * Run: node front-end/test/topology-spec-view.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

function makeWindow(files) {
  const sandbox = { console, setTimeout, clearTimeout, setInterval, clearInterval };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;

  const docEl = {
    _theme: 'light',
    getAttribute(name) { return name === 'data-theme' ? this._theme : null; },
    setAttribute(name, v) { if (name === 'data-theme') this._theme = v; },
  };
  sandbox.document = {
    documentElement: docEl,
    createElement: () => ({ style: {}, appendChild() {}, setAttribute() {} }),
    addEventListener() {}, removeEventListener() {},
    head: { appendChild() {} }, body: { appendChild() {} },
  };
  sandbox.getComputedStyle = () => ({ getPropertyValue: () => '' });
  sandbox.MutationObserver = class { observe() {} disconnect() {} };
  sandbox.navigator = { userAgent: 'node' };

  vm.createContext(sandbox);
  // Same order admin.html loads them in. topology-seed.js resolves the editor
  // global at call time, but loading it after is what the page does.
  for (const f of files || ADMIN_ASSETS) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  return sandbox;
}

const ADMIN_ASSETS = [
  'vendor/lodash.min.js', 'vendor/cytoscape.min.js', 'vendor/cytoscape-edgehandles.js',
  'js/topology/topology-icons.js', 'js/topology/topology-render.js',
  'js/topology/topology-editor.js', 'js/topology/topology-seed.js',
];

/**
 * What the CLE instructor page loads. Deliberately WITHOUT edgehandles and its
 * lodash dependency: those are only reachable behind `mode === 'edit'` in the
 * renderer, and an instructor authors nothing. Asserting the reduced set actually
 * works is the point — otherwise the omission is a guess that fails in a browser.
 */
const CLE_VIEW_ASSETS = [
  'vendor/cytoscape.min.js',
  'js/topology/topology-icons.js',
  'js/topology/topology-render.js',
];

const WIN = makeWindow();
const Seed = WIN.CyberCoreTopologySeed;
const plain = (v) => JSON.parse(JSON.stringify(v));

/** Build the graph and render it, exactly as the viewer does. */
function draw(row, opts) {
  const built = Seed.specToGraph(row, opts || {});
  const t = WIN.CyberCoreTopology.create(null, { mode: 'view' });
  t.setData(built.graph, built.runLayout);
  return { built, t };
}

/** Which segments a machine ended up wired to, read off the rendered graph. */
function segmentsOf(t, name) {
  const node = t.cy.nodes('[kind="vm"]').filter(n => n.data('label').split('\n')[0] === name)[0];
  assert.ok(node, `no rendered node named ${name}`);
  return t.cy.edges('[kind="nic"]')
    .filter(e => e.data('vmId') === node.id().replace(/^vm:/, ''))
    .sort((a, b) => a.data('label').localeCompare(b.data('label')))
    .map(e => e.data('segId'));
}

// ── v3: the dual-homed pivot ─────────────────────────────────────────────────

test('a v3 dmz qemu host with NO explicit nics draws dual-homed, ext then int', () => {
  // This is the case the whole v3 scheme turns on: role dmz + qemu + v3 derives
  // ['ext','int'], so a legacy spec that predates the canvas still draws the
  // pivot correctly without anyone having authored nics[].
  const { t } = draw({
    subnet_scheme: 'v3',
    spec: { vms: [{ name: 'web01', role: 'dmz', type: 'qemu', template_vmid: 1601 }] },
  });
  assert.strictEqual(t.cy.nodes('[kind="segment"]').length, 2);
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 2);

  const nics = t.cy.edges('[kind="nic"]')
    .map(e => ({ seg: e.data('segId'), label: e.data('label') }))
    .sort((a, b) => a.label.localeCompare(b.label));
  // NIC order is net0..netN, and net0 must be the external side.
  assert.deepStrictEqual(plain(nics), [
    { seg: 'ext', label: 'net0' },
    { seg: 'int', label: 'net1' },
  ]);
});

test('an LXC dmz host is NOT dual-homed — the type guard is not cosmetic', () => {
  const { t } = draw({
    subnet_scheme: 'v3',
    spec: { vms: [{ name: 'lx01', role: 'dmz', type: 'lxc', template_vmid: 1600 }] },
  });
  assert.deepStrictEqual(plain(segmentsOf(t, 'lx01')), ['ext']);
});

test('explicit nics win over the derivation, in the order authored', () => {
  const { t } = draw({
    subnet_scheme: 'v3',
    spec: {
      vms: [{ name: 'odd01', role: 'dc', type: 'qemu', nics: [{ segment: 'int' }, { segment: 'ext' }] }],
    },
  });
  const nics = t.cy.edges('[kind="nic"]')
    .map(e => ({ seg: e.data('segId'), label: e.data('label') }))
    .sort((a, b) => a.label.localeCompare(b.label));
  assert.deepStrictEqual(plain(nics), [
    { seg: 'int', label: 'net0' },
    { seg: 'ext', label: 'net1' },
  ]);
});

// ── GOAD ─────────────────────────────────────────────────────────────────────

test('GOAD-matched hosts land on internal; unmatched ones on external', () => {
  const { t, built } = draw({
    subnet_scheme: 'v3',
    spec: {
      goad: { enabled: true, version: 'GOAD-Light' },
      vms: [
        { name: 'DC01', role: 'dc', type: 'qemu', template_vmid: 1004 },
        { name: 'SRV02', role: 'srv', type: 'qemu', template_vmid: 1004 },
        { name: 'Kali', role: 'attacker', type: 'qemu', template_vmid: 1699 },
      ],
    },
  }, { goadHostNames: ['DC01', 'DC02', 'SRV02'] });

  assert.deepStrictEqual(plain(segmentsOf(t, 'DC01')), ['int']);
  assert.deepStrictEqual(plain(segmentsOf(t, 'SRV02')), ['int']);
  assert.deepStrictEqual(plain(segmentsOf(t, 'Kali')), ['ext']);
  // Lab-pinned hosts render locked (double border); Kali does not.
  assert.deepStrictEqual(plain(built.graph.nodes.map(n => n.locked)), [true, true, false]);
});

test('GOAD host matching is case-insensitive', () => {
  const { built } = draw({
    subnet_scheme: 'v3',
    spec: { vms: [{ name: 'dc01', type: 'qemu' }] },
  }, { goadHostNames: ['DC01'] });
  assert.strictEqual(built.graph.nodes[0].locked, true);
  assert.deepStrictEqual(plain(built.graph.nodes[0].segments), ['int']);
});

test('with no GOAD names supplied, nothing is locked or forced internal', () => {
  const { built } = draw({
    subnet_scheme: 'v3',
    spec: { vms: [{ name: 'DC01', type: 'qemu' }] },
  });
  assert.strictEqual(built.graph.nodes[0].locked, false);
  assert.deepStrictEqual(plain(built.graph.nodes[0].segments), ['ext']);
});

// ── layout ───────────────────────────────────────────────────────────────────

test('stored positions are used verbatim and suppress the auto-layout', () => {
  const { built, t } = draw({
    subnet_scheme: 'v3',
    spec: {
      vms: [{ name: 'web01', role: 'dmz', type: 'qemu', layout: { x: 300, y: 200 } }],
      network: { version: 1, segments: [{ id: 'ext' }, { id: 'int' }],
                 layout: { ext: { x: 120, y: 80 }, int: { x: 120, y: 420 }, __gw: { x: 400, y: 250 } } },
    },
  });
  assert.strictEqual(built.runLayout, false, 'a spec with stored positions must not be re-arranged');
  assert.deepStrictEqual(plain(built.graph.nodes[0].layout), { x: 300, y: 200 });
  assert.deepStrictEqual(plain(built.graph.gateway.layout), { x: 400, y: 250 });

  const ext = built.graph.segments.find(s => s.id === 'ext');
  assert.deepStrictEqual(plain(ext.layout), { x: 120, y: 80 });
  // ...and the renderer actually placed it there.
  assert.deepStrictEqual(plain(t.cy.$id('seg:ext').position()), { x: 120, y: 80 });
});

test('a spec with no stored positions asks for an auto-layout', () => {
  const { built } = draw({ subnet_scheme: 'v3', spec: { vms: [{ name: 'a', type: 'qemu' }] } });
  assert.strictEqual(built.runLayout, true);
  assert.strictEqual(built.graph.nodes[0].layout, null);
});

// ── schemes ──────────────────────────────────────────────────────────────────

test('v1 draws one lan segment with every machine on it', () => {
  const { t } = draw({
    subnet_scheme: 'v1',
    spec: {
      vms: [
        { name: 'a', type: 'qemu' },
        { name: 'b', role: 'dmz', type: 'qemu' },   // dmz is meaningless without segments
        { name: 'c', type: 'lxc' },
      ],
    },
  });
  assert.strictEqual(t.cy.nodes('[kind="segment"]').length, 1);
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 3);
  for (const n of ['a', 'b', 'c']) assert.deepStrictEqual(plain(segmentsOf(t, n)), ['lan']);
});

test('an absent subnet_scheme falls back to v1, not v3', () => {
  const { built } = draw({ spec: { vms: [{ name: 'a' }] } });
  assert.strictEqual(built.scheme, 'v1');
  assert.deepStrictEqual(plain(built.graph.segments.map(s => s.id)), ['lan']);
});

test('the gateway is wired to every segment', () => {
  const { t } = draw({ subnet_scheme: 'v3', spec: { vms: [{ name: 'a', type: 'qemu' }] } });
  const uplinks = t.cy.edges('[kind="uplink"]');
  assert.strictEqual(uplinks.length, 2);
  assert.deepStrictEqual(plain(uplinks.map(e => e.data('target')).sort()), ['seg:ext', 'seg:int']);
});

// ── row shapes the endpoint really returns ───────────────────────────────────

test('a spec that arrives as a JSON string is parsed', () => {
  const { built } = draw({
    subnet_scheme: 'v3',
    spec: JSON.stringify({ vms: [{ name: 'web01', role: 'dmz', type: 'qemu' }] }),
  });
  assert.strictEqual(built.vms.length, 1);
  assert.deepStrictEqual(plain(built.graph.nodes[0].segments), ['ext', 'int']);
});

test('a legacy row falls back to vm_specs when spec.vms is empty', () => {
  const { built } = draw({
    subnet_scheme: 'v1',
    spec: {},
    vm_specs: JSON.stringify([{ name: 'legacy01', template_vmid: 1600 }]),
  });
  assert.strictEqual(built.vms.length, 1);
  assert.strictEqual(built.graph.nodes[0].name, 'legacy01');
});

test('an unnamed machine still renders, labelled', () => {
  const { built } = draw({ subnet_scheme: 'v1', spec: { vms: [{ template_vmid: 1601 }] } });
  assert.strictEqual(built.graph.nodes[0].name, '(unnamed)');
});

test('a reserved lab network reports itself instead of looking broken', () => {
  const { built, t } = draw({
    subnet_scheme: 'v2',
    spec: { vxlan_block: { start: 10000, end: 10009 }, zone: { abbrev: 'cybsag' }, cle: true, vms: [] },
  });
  assert.strictEqual(built.isReservation, true);
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 0);
  // The segments and gateway still draw — that IS what the reservation owns.
  assert.strictEqual(t.cy.nodes('[kind="segment"]').length, 1);
  assert.strictEqual(t.cy.nodes('[kind="gateway"]').length, 1);
});

test('a normal empty-VM challenge is not mistaken for a reservation', () => {
  const { built } = draw({ subnet_scheme: 'v1', spec: { vms: [] } });
  assert.strictEqual(built.isReservation, false);
});

test('node ids are unique even when two machines share a name', () => {
  // Duplicate names are a validateTopology error, but the viewer must still draw
  // the spec rather than collapsing the two into one node and hiding the problem.
  const { t } = draw({
    subnet_scheme: 'v1',
    spec: { vms: [{ name: 'dup', type: 'qemu' }, { name: 'dup', type: 'qemu' }] },
  });
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 2);
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 2);
});

// ── the CLE instructor page's reduced asset set ──────────────────────────────

test('view mode works WITHOUT lodash or edgehandles — the CLE page omits both', () => {
  const win = makeWindow(CLE_VIEW_ASSETS);
  assert.strictEqual(typeof win._, 'undefined', 'lodash should not be needed');
  assert.strictEqual(typeof win.cytoscapeEdgehandles, 'undefined', 'edgehandles should not be needed');
  assert.strictEqual(typeof win.CyberCoreTopology.create, 'function');

  // The exact payload GET /:laneId/topology returns, drawn the way the modal draws it.
  const t = win.CyberCoreTopology.create(null, { mode: 'view' });
  t.setData({
    segments: [
      { id: 'ext', role: 'external', label: 'External / Attacker', cidr: '10.39.161.0/24' },
      { id: 'int', role: 'internal', label: 'Internal / Corp', cidr: '10.167.161.0/24' },
    ],
    gateway: { label: 'Lane gateway\n1695' },
    nodes: [
      { id: '620001', name: 'web01', role: 'dmz', os: 'Linux', ip: '10.39.161.240', segments: ['ext', 'int'] },
      { id: '600001', name: 'DC01', role: 'dc', os: 'Windows Server 2019', ip: '10.167.161.10',
        segments: ['int'], severity: 'warning' },
    ],
  }, true);

  assert.strictEqual(t.cy.nodes('[kind="segment"]').length, 2);
  assert.strictEqual(t.cy.nodes('[kind="vm"]').length, 2);
  assert.strictEqual(t.cy.nodes('[kind="gateway"]').length, 1);
  assert.strictEqual(t.cy.edges('[kind="nic"]').length, 3);
  // A stopped machine still paints its amber border.
  const dc = t.cy.nodes('[kind="vm"]').filter(n => n.data('label').startsWith('DC01'))[0];
  assert.strictEqual(dc.data('severity'), 'warning');

  // And it tears down cleanly — destroy() is what disconnects the theme observer.
  t.destroy();
});

test('specToGraph does not mutate the row it was given', () => {
  const row = {
    subnet_scheme: 'v3',
    spec: { vms: [{ name: 'web01', role: 'dmz', type: 'qemu' }],
            network: { segments: [{ id: 'ext' }], layout: { ext: { x: 1, y: 2 } } } },
  };
  const before = JSON.stringify(row);
  Seed.specToGraph(row, {});
  assert.strictEqual(JSON.stringify(row), before);
});
