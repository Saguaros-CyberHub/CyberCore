/**
 * topology-console-badge.test.js -- the "student console" highlight.
 *
 * The Deploy Environment screen has to answer one question at a glance: which
 * machine does the student's Guacamole session actually open onto? That is
 * carried as a `badge: 'console'` field on a node, and this file pins the three
 * properties that make it trustworthy:
 *
 *   1. it survives setData/getData, so a re-render does not lose it;
 *   2. it does NOT collide with `severity`, which the CLE lane-topology modal
 *      already sets on the very same nodes for "not running" -- overloading one
 *      field would paint "this is your box" and "this box is off" identically;
 *   3. the reduced asset set the CLE page loads is enough to draw it, WITHOUT
 *      lodash or cytoscape-edgehandles. Those are reachable only behind
 *      mode === 'edit' and the deploy modal authors nothing -- but it DOES need
 *      topology-editor.js and topology-seed.js, which the lane-topology modal
 *      does not. Asserting the exact set is the point: otherwise the script tags
 *      on courses.html are a guess that fails in a browser.
 *
 * Run: node front-end/test/topology-console-badge.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

/**
 * What courses.html loads for the DEPLOY modal -- the lane-topology modal's
 * three files plus the two specToGraph needs. Kept in this shape so the
 * assertion below reads as the script-tag list it mirrors.
 */
const CLE_DEPLOY_ASSETS = [
  'vendor/cytoscape.min.js',
  'js/topology/topology-icons.js',
  'js/topology/topology-render.js',
  'js/topology/topology-editor.js',
  'js/topology/topology-seed.js',
];

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
  for (const f of files || CLE_DEPLOY_ASSETS) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  return sandbox;
}

const WIN = makeWindow();

const SEGMENTS = [
  { id: 'ext', role: 'external', label: 'External / Attacker' },
  { id: 'int', role: 'internal', label: 'Internal / Corp' },
];

/** Render a node list headlessly and hand back the instance. */
function draw(nodes, win) {
  const t = (win || WIN).CyberCoreTopology.create(null, { mode: 'view' });
  t.setData({ segments: SEGMENTS, gateway: { label: 'Lane gateway' }, nodes }, false);
  return t;
}

const vmNode = (t, name) =>
  t.cy.nodes().filter((n) => n.data('kind') === 'vm'
    && n.data('label').split('\n')[0] === name)[0];

// -- the badge itself --------------------------------------------------------

test('badge:console reaches the graph and leaves severity alone', () => {
  const t = draw([
    { id: 'a', name: 'elk01', os_family: 'windows_server', segments: ['int'], badge: 'console' },
    { id: 'b', name: 'sensor', os_family: 'linux', segments: ['int'] },
  ]);
  assert.strictEqual(vmNode(t, 'elk01').data('badge'), 'console');
  assert.strictEqual(vmNode(t, 'elk01').data('severity'), '',
    'the console badge must not imply a severity');
  assert.strictEqual(vmNode(t, 'sensor').data('badge'), '',
    'an unbadged node gets the empty string, not undefined -- the selector is node[badge="console"]');
});

test('a console that is ALSO broken keeps its severity', () => {
  // The CLE lane-topology modal sets severity:'warning' for a stopped machine.
  // Both must survive: the stylesheet declares the console rule first precisely
  // so the severity border wins on a node carrying both.
  const t = draw([
    { id: 'a', name: 'elk01', os_family: 'windows_server', segments: ['int'],
      badge: 'console', severity: 'warning' },
  ]);
  assert.strictEqual(vmNode(t, 'elk01').data('badge'), 'console');
  assert.strictEqual(vmNode(t, 'elk01').data('severity'), 'warning');
});

test('the console rule is declared BEFORE the severity rules', () => {
  // Ordering IS the mechanism -- Cytoscape applies later matching rules last, so
  // a console that is also in error must still paint as an error.
  const src = fs.readFileSync(path.join(PUBLIC, 'js/topology/topology-render.js'), 'utf8');
  const sel = (attr, val) => `selector: 'node[${attr}="${val}"]'`;
  const iBadge = src.indexOf(sel('badge', 'console'));
  const iError = src.indexOf(sel('severity', 'error'));
  const iWarn = src.indexOf(sel('severity', 'warning'));
  assert.ok(iBadge > -1, 'the console selector should exist');
  assert.ok(iBadge < iError && iBadge < iWarn,
    'node[badge="console"] must be declared before the severity selectors');
});

test('the label names the console, so the graph reads without the legend', () => {
  const t = draw([
    { id: 'a', name: 'elk01', ip: '10.5.3.60', os_family: 'windows_server', segments: ['int'], badge: 'console' },
    { id: 'b', name: 'sensor', ip: '10.5.3.61', os_family: 'linux', segments: ['int'] },
  ]);
  assert.strictEqual(vmNode(t, 'elk01').data('label'), 'elk01\n10.5.3.60\n\u25b8 student console');
  assert.strictEqual(vmNode(t, 'sensor').data('label'), 'sensor\n10.5.3.61',
    'an unbadged node must be untouched -- the suffix is not a layout constant');
});

test('badge survives a data round-trip', () => {
  const t = draw([
    { id: 'a', name: 'elk01', os_family: 'windows_server', segments: ['int'], badge: 'console' },
  ]);
  assert.strictEqual(JSON.parse(JSON.stringify(t.getData())).nodes[0].badge, 'console');
});

test('moving the badge is a plain setData, not a rebuild', () => {
  // The deploy modal re-renders on every console-radio change, so this is the
  // hot path: the marker must move without the graph being torn down.
  const t = draw([
    { id: 'a', name: 'elk01', os_family: 'windows_server', segments: ['int'], badge: 'console' },
    { id: 'b', name: 'kali', role: 'attacker', segments: ['ext'] },
  ]);
  t.setData({
    segments: SEGMENTS,
    gateway: { label: 'Lane gateway' },
    nodes: [
      { id: 'a', name: 'elk01', os_family: 'windows_server', segments: ['int'] },
      { id: 'b', name: 'kali', role: 'attacker', segments: ['ext'], badge: 'console' },
    ],
  }, false);
  assert.strictEqual(vmNode(t, 'elk01').data('badge'), '');
  assert.strictEqual(vmNode(t, 'kali').data('badge'), 'console');
  assert.strictEqual(vmNode(t, 'kali').data('role'), 'attacker',
    'the badge must not have displaced role -- role drives the icon');
});

// -- the asset set the deploy modal actually loads ---------------------------

test('specToGraph + the console badge work on the CLE deploy asset set', () => {
  const win = makeWindow(CLE_DEPLOY_ASSETS);
  assert.strictEqual(typeof win._, 'undefined', 'lodash is edit-mode only');
  assert.strictEqual(typeof win.cytoscapeEdgehandles, 'undefined', 'edgehandles is edit-mode only');
  assert.strictEqual(typeof win.CyberCoreTopologySeed.specToGraph, 'function');

  // Exactly what the deploy modal does: a spec that has never been deployed,
  // with the console machine badged after the graph is built.
  const built = win.CyberCoreTopologySeed.specToGraph({
    subnet_scheme: 'v2',
    spec: {
      vms: [
        { name: 'elk01', role: 'siem', os_family: 'windows_server', template_vmid: 1005 },
        { name: 'sensor', role: 'sensor', os_family: 'linux', template_vmid: 1007 },
      ],
    },
  });
  built.graph.nodes.forEach((n) => { if (n.name === 'elk01') n.badge = 'console'; });

  const t = win.CyberCoreTopology.create(null, { mode: 'view' });
  t.setData(built.graph, built.runLayout);

  const badged = t.cy.nodes().filter((n) => n.data('badge') === 'console');
  assert.strictEqual(badged.length, 1);
  assert.ok(badged[0].data('label').startsWith('elk01'));
});

test('an instructor-added machine merged into the spec lands on a real segment', () => {
  // The modal merges add-ons into spec.vms BEFORE specToGraph, so placement comes
  // from CyberCoreTopologyEditor.deriveSegments -- the same rule the server's
  // lane-networking.resolveVmSegments uses. A separate client-side rule here
  // would have nothing pinning the two together.
  const built = WIN.CyberCoreTopologySeed.specToGraph({
    subnet_scheme: 'v2',
    spec: {
      vms: [
        { name: 'web01', role: 'web', os_family: 'linux', template_vmid: 1601 },
        { name: 'kali', role: 'attacker', os_family: 'linux', template_vmid: 1699 },
      ],
    },
  });
  const kali = built.graph.nodes.find((n) => n.name === 'kali');
  assert.ok(kali.segments.length > 0,
    'an added machine with no explicit nics must still derive a segment, or it draws detached');
});
