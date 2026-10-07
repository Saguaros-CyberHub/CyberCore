/**
 * admin-profile-lanes-topo.test.js — the live lane blueprint's browser half.
 *
 * WHY THIS FILE EXISTS
 * Two of the three things that make this feature work are invisible to every
 * behavioural test, because getting them wrong produces a diagram that renders
 * happily and is quietly wrong or quietly broken:
 *
 *   1. WHICH SCRIPTS THE PAGE LOADS. topology-seed.js's specToGraph is the only
 *      caller of topology-editor.js's deriveSegments, and deriveSegments places
 *      a non-dmz machine on 'ext' under v3 — the exact inverse of what this
 *      client's applyV3Topology does. Placement arrives from POST /plan already
 *      decided, so the guarantee that nothing second-guesses it is simply that
 *      the module which could is NOT LOADED. That is a property of a <script>
 *      list, and only a source assertion can hold it.
 *
 *   2. THAT NOTHING SITS AT (0,0), AND THAT IDS ARE STABLE. topology-render.js
 *      computes `needsLayout = runLayout || cy.nodes().some(p.x === 0 && p.y ===
 *      0)`, so a single element left at the origin silently re-triggers the full
 *      cose pass that placeGraph exists to avoid — and layout() ends in cy.fit(),
 *      throwing away the operator's zoom and pan on every keystroke. render()
 *      restores positions BY ID, so an id that shifts when the selection changes
 *      makes every machine jump.
 *
 * placeGraph is pure, so it is exercised directly rather than through a browser.
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const PAGE = path.join(CIAB, 'public', 'pages', 'admin-profile-lanes.html');
const TOPO_JS = path.join(CIAB, 'public', 'js', 'admin-profile-lanes-topo.js');

const html = fs.readFileSync(PAGE, 'utf8');

// ── 1. the bundle ───────────────────────────────────────────────────────────

test('the page loads the read-only renderer and nothing that could re-derive placement', () => {
  for (const src of [
    '/vendor/cytoscape.min.js',
    '/js/topology/topology-icons.js',
    '/js/topology/topology-render.js',
    '/css/topology.css',
  ]) {
    assert.ok(html.includes(src), `${src} must be loaded — the diagram needs it`);
  }

  for (const [src, why] of [
    ['/js/topology/topology-seed.js',
     'specToGraph would derive placement in the browser; POST /plan already decided it'],
    ['/js/topology/topology-editor.js',
     'deriveSegments puts a non-dmz machine on ext under v3, the inverse of applyV3Topology'],
    ['/vendor/lodash.min.js', 'edit-mode only'],
    ['/vendor/cytoscape-edgehandles.js', 'edit-mode only'],
  ]) {
    assert.ok(!html.includes(src), `${src} must NOT be loaded: ${why}`);
  }
});

test('the renderer is loaded before the page script that drives it', () => {
  assert.ok(html.indexOf('/vendor/cytoscape.min.js') < html.indexOf('/js/topology/topology-render.js'),
    'topology-render.js calls cytoscape() at create()');
  assert.ok(html.indexOf('/js/topology/topology-icons.js') < html.indexOf('/js/topology/topology-render.js'),
    'topology-render.js reads CyberCoreTopologyIcons at module scope');
  assert.ok(html.indexOf('/js/topology/topology-render.js')
    < html.indexOf('"/ciab/js/admin-profile-lanes-topo.js"'),
    'LaneTopo calls CyberCoreTopology.create at mount');
});

test('the tab-visibility rules survive — main.css has no .tab-content rule', () => {
  // Deleting the page-local style block wholesale would render both tabs at once
  // and mount Cytoscape against a container of the wrong size.
  assert.match(html, /\.tab-content\s*\{[^}]*display:\s*none/,
    '.tab-content { display:none } is page-local and load-bearing');
  assert.match(html, /\.tab-content\.active\s*\{[^}]*display:\s*block/);
});

test('the subnet-scheme select keeps a bare opening tag, so its pinned regex still matches', () => {
  // ciab-v3-default.test.js matches the literal `<select id="dep-subnet-scheme">`.
  // An onchange= or data-plan-input on it would drop the match. The live redraw
  // is wired with addEventListener instead.
  assert.ok(html.includes('<select id="dep-subnet-scheme">'),
    'no attribute may be added to this tag; wire it from JS');
  const topo = fs.readFileSync(TOPO_JS, 'utf8');
  assert.match(topo, /el\('dep-subnet-scheme'\)|getElementById\('dep-subnet-scheme'\)/,
    'and it must actually be wired, or changing the scheme would not redraw');
});

test('the canvas and its mount point exist', () => {
  assert.ok(html.includes('id="depTopoCanvas"'));
  assert.ok(html.includes('id="depTopoMeta"'));
  assert.ok(html.includes('class="dep-split"'));
  assert.ok(html.includes('id="dep-controls"'));
});

// ── 2. placeGraph, in a sandbox ─────────────────────────────────────────────

function loadLaneTopo() {
  const src = fs.readFileSync(TOPO_JS, 'utf8');
  const listeners = {};
  const sandbox = {
    module: { exports: {} },
    document: {
      getElementById: () => null,
      querySelector: () => null,
      addEventListener: (ev, fn) => { listeners[ev] = fn; },
    },
    window: { addEventListener: () => {} },
    requestAnimationFrame: () => {},
    setTimeout: () => {}, clearTimeout: () => {},
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox, { filename: 'admin-profile-lanes-topo.js' });
  return sandbox.module.exports;
}

const LaneTopo = loadLaneTopo();

/** A plan response in the shape POST /plan returns. */
function planFixture(overrides) {
  return Object.assign({
    scheme: { requested: 'v3', effective: 'v3', locked_by_engagement: false },
    segments: [
      { id: 'ext', role: 'external', label: 'External / Attacker', cidr: '10.39.16.0/24' },
      { id: 'int', role: 'internal', label: 'Internal / Corp', cidr: '10.167.16.0/24' },
    ],
    gateway: { label: 'Lane gateway', octet: 1 },
    machines: [
      { id: 'm:web-01', name: 'web-01', view_role: 'dmz', os_family: 'linux',
        segments: ['ext', 'int'], ip_octet: 240, is_pivot: true, is_console: false, severity: '' },
      { id: 'm:dc01', name: 'dc01', view_role: 'dc', os_family: 'windows_server',
        segments: ['int'], ip_octet: 80, is_pivot: false, is_console: false, severity: '' },
      { id: 'm:file01', name: 'file01', view_role: 'server', os_family: 'windows_server',
        segments: ['int'], ip_octet: 81, is_pivot: false, is_console: false, severity: '' },
      { id: 'm:kali', name: 'kali', view_role: 'attacker', os_family: 'linux',
        segments: ['ext'], ip_octet: 50, is_pivot: false, is_console: true, severity: '' },
    ],
    ghosts: [{ id: 'ghost:ot-hmi-01', name: 'ot-hmi-01', reason: 'no_family_match' }],
    counts: { machines_per_lane: 4, ghosts: 1, num_lanes: 3 },
    problems: [], notices: [],
  }, overrides || {});
}

test('nothing is placed at exactly (0,0) — that re-triggers the layout it avoids', () => {
  for (const plan of [planFixture(), planFixture({
    segments: [{ id: 'lan', role: 'lan', label: 'Lane Network', cidr: null }],
    machines: planFixture().machines.map((m) => Object.assign({}, m, {
      segments: ['lan'], is_pivot: false,
    })),
  })]) {
    const g = LaneTopo.placeGraph(plan);
    const all = g.segments.concat([g.gateway]).concat(g.nodes);
    for (const e of all) {
      assert.ok(e.layout, 'every element carries explicit coordinates');
      assert.ok(!(e.layout.x === 0 && e.layout.y === 0),
        `${e.id || e.label} sits at the origin, which forces a full cose pass`);
    }
  }
});

test('every node gets a stable, server-supplied id', () => {
  const g = LaneTopo.placeGraph(planFixture());
  const ids = g.nodes.map((n) => n.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate ids collapse nodes in the renderer');
  assert.ok(ids.includes('m:web-01'));
  assert.ok(ids.includes('ghost:ot-hmi-01'));
  // Not index-derived: topology-seed's `'spec:' + i` shifts on every untick,
  // which is exactly why this page does not use it.
  assert.ok(!ids.some((id) => /^spec:\d+$/.test(id)));
});

test('unticking one asset moves nothing else', () => {
  const before = LaneTopo.placeGraph(planFixture());
  const trimmed = planFixture();
  trimmed.machines = trimmed.machines.filter((m) => m.name !== 'file01');
  const after = LaneTopo.placeGraph(trimmed);

  const posOf = (g) => Object.fromEntries(g.nodes.map((n) => [n.id, n.layout.x + ',' + n.layout.y]));
  const a = posOf(before);
  const b = posOf(after);

  assert.ok(!(('m:file01') in b), 'the unticked machine is gone');
  for (const id of Object.keys(b)) {
    assert.equal(b[id], a[id],
      `${id} moved when a DIFFERENT machine was unticked — render() restores by id, so this jumps`);
  }
});

test('the pivot is centred between the bands and keeps both NICs, in order', () => {
  const g = LaneTopo.placeGraph(planFixture());
  const pivot = g.nodes.find((n) => n.id === 'm:web-01');
  // Edge order is NIC order (net0, net1), so the array must survive untouched.
  assert.deepEqual(pivot.segments, ['ext', 'int']);
  const ext = g.segments.find((s) => s.id === 'ext');
  const int = g.segments.find((s) => s.id === 'int');
  assert.ok(pivot.layout.x > ext.layout.x && pivot.layout.x < int.layout.x,
    'the pivot sits between the two segments it bridges');
});

test('a ghost is unwired and error-severity, so it reads red AND dashed', () => {
  const g = LaneTopo.placeGraph(planFixture());
  const ghost = g.nodes.find((n) => n.id === 'ghost:ot-hmi-01');
  assert.equal(ghost.segments.length, 0,
    'segments:[] is what paints the [!attached] dashed ring');
  assert.equal(ghost.severity, 'error',
    'and error colours it red without resetting border-style');
  assert.ok(!ghost.locked,
    'locked would force border-style:double and clobber the dashed ring');
  assert.match(ghost.name, /no template/);
});

test('only the machine the console plan named carries the console badge', () => {
  const g = LaneTopo.placeGraph(planFixture());
  const badged = g.nodes.filter((n) => n.badge === 'console');
  assert.deepEqual(badged.map((n) => n.id), ['m:kali']);
  // The badge appends a literal '▸ student console' to the label, so putting it
  // on the pivot would caption the web host as the machine students open.
  assert.notEqual(g.nodes.find((n) => n.id === 'm:web-01').badge, 'console');
});

test('a machine naming a segment the lane does not have is refused, not drawn', () => {
  // It would otherwise render attached with ZERO edges and no warning ring —
  // the failure mode of a v3 -> v2 flip that leaves stale ids on nodes.
  const bad = planFixture();
  bad.segments = [{ id: 'lan', role: 'lan', label: 'Lane Network', cidr: null }];
  assert.throws(() => LaneTopo.assertNoDanglingSegments(LaneTopo.placeGraph(bad)),
    /names segment/);
});

test('octets are shown on the node label, since they are what the deploy pins', () => {
  const g = LaneTopo.placeGraph(planFixture());
  assert.match(g.nodes.find((n) => n.id === 'm:kali').name, /\.50/);
  assert.match(g.nodes.find((n) => n.id === 'm:web-01').name, /\.240/);
});

// ── 3. the page after the rebuild ───────────────────────────────────────────

const laneJs = fs.readFileSync(path.join(CIAB, 'public', 'js', 'admin-profile-lanes.js'), 'utf8');

test('the Generate + Deploy tab is gone, and the generator is linked instead', () => {
  // Generation already had full parity on /ciab/generator; this page is a deploy
  // console. The server endpoint stays — only the UI tab was removed.
  assert.ok(!html.includes('id="tab-generate"'));
  assert.ok(!html.includes('gen-subnet-scheme'), 'and with it the second scheme selector');
  assert.ok(!/\bgen-[a-z-]+\b/.test(html), 'no #gen-* field may survive its tab');
  assert.ok(!laneJs.includes('generateAndDeploy'), 'and neither may its handler');
  assert.ok(!laneJs.includes('switchSubTab'), 'the sub-tabs went with it');
  assert.ok(html.includes('href="/ciab/generator"'), 'there must be a way to make a profile');
  assert.ok(html.includes('<div class="tab-content active" id="tab-existing">'),
    'Deploy Lanes is now the tab that opens');
});

test('the inert "Force dedicated VM" control is gone, not merely disabled', () => {
  // It sent delivery_mode:'standalone_vm', and vuln-app-generator.js overrides
  // effectiveMode = 'docker' before anything reads it. A page that exists to
  // predict the deploy must not offer a switch that changes nothing.
  assert.ok(!html.includes('dep-vuln-app-dedicated'));
  assert.ok(!laneJs.includes('dep-vuln-app-dedicated'));
  assert.ok(!laneJs.includes("'standalone_vm'"),
    'and nothing may still send a delivery mode the generator discards');
});

test('the deploy names the machines that will not be built, before it commits', () => {
  assert.match(laneJs, /LaneTopo\.ghosts\(\)/);
  assert.match(laneJs, /Some selected assets will not be built/);
  const gate = laneJs.indexOf('LaneTopo.ghosts()');
  const post = laneJs.indexOf("apiCall('/profile-deploy/deploy'");
  assert.ok(gate !== -1 && post !== -1 && gate < post,
    'the warning has to come BEFORE the request, or it is a report rather than a gate');
});

test('the scheme selector is locked to the carve once a block exists', () => {
  // runProfileDeploy builds at engagementRow.subnet_scheme, so a live dropdown
  // after the carve invites a choice that cannot be honoured.
  assert.match(laneJs, /function lockSchemeToCarve/);
  assert.match(laneJs, /lockSchemeToCarve\(r\.subnet_scheme \|\| null\)/);
  assert.ok(html.includes('id="dep-scheme-note"'), 'and the reason is shown, not just enforced');
});

test('a deployed lane can be drawn by the same renderer as the prediction', () => {
  assert.ok(html.includes('id="laneTopologyModal"'));
  assert.ok(html.includes('id="laneTopologyCanvas"'));
  const topo = fs.readFileSync(TOPO_JS, 'utf8');
  assert.match(topo, /\/admin\/lanes\/'\s*\+\s*encodeURIComponent\(laneId\)\s*\+\s*'\/topology/,
    'GET /api/admin/lanes/:laneId/topology already returns setData\u2019s exact shape');
  assert.match(topo, /LIVE_TOPO\.destroy\(\)/,
    'the modal instance MUST be destroyed — create() registers a theme MutationObserver '
    + 'that only destroy() disconnects, and this modal opens once per lane');
  assert.match(laneJs, /data-group-action="topology"/, 'and every lane row offers it');
});

test('the preview instance is created once and never destroyed on tab change', () => {
  const topo = fs.readFileSync(TOPO_JS, 'utf8');
  assert.match(topo, /if \(TOPO\) \{ TOPO\.resize\(\); return; \}/,
    'mount() must be idempotent: a create() per tab entry leaks one observer per entry');
  assert.match(topo, /pagehide/, 'the one destroy happens when the page goes away');
});

test('the tab the page opens on fetches its own data', () => {
  // Deploy Lanes used to be tab 2, so refreshProfiles() arrived via
  // switchTab('existing'). Now that it is the tab that opens, nothing calls
  // switchTab at all and the picker would render empty forever.
  const boot = laneJs.slice(laneJs.indexOf('─── boot'));
  assert.match(boot, /refreshProfiles\(\);/,
    'the default tab must load its own list at boot');
});
