/**
 * topology-context-menu.test.js — E3e: the right-click menu, and the three
 * canvas gestures it replaces.
 *
 * WHAT CHANGED AND WHY
 *
 *  1. CLICK-TO-DETACH IS RETIRED. `cy.on('tap', 'edge[kind="nic"]', …)` stripped
 *     a NIC on a single stray click — no confirmation, no undo — and then the
 *     machine deployed ATTACHED anyway, because an authored `nics: []` is
 *     indistinguishable from an absent key everywhere downstream. Three layers
 *     each did something locally reasonable and composed into a silent lie. An
 *     edge tap now SELECTS.
 *
 *  2. THE LAST DETACH IS REFUSED, WITH THE REASON SHOWN. A machine must keep
 *     ≥1 NIC: no network here means no DHCP lease, no Guacamole target and no
 *     post-clone scripts. At one NIC the operation offered is "Move to…".
 *
 *  3. GOAD HOSTS CANNOT BE RENAMED OR REMOVED. prepareGoadMacs matches AD hosts
 *     BY NAME, so a rename converts a domain controller into a machine the GOAD
 *     layer has never heard of — and assertGoadRoster refuses the deploy in
 *     BOTH directions, so a removal is the same failure.
 *
 *  4. AN UNATTACHED MACHINE LOOKS UNATTACHED. Before this, a detached DC01 was
 *     pixel-identical to an attached one, which is how (1) stayed invisible.
 *
 * The menu itself is DOM and hit-testing, which this repo deliberately does not
 * test headlessly (see topology-render.test.js's own note). So the GUARDS were
 * extracted into a pure `menuGuards()` and are tested directly, the renderer's
 * data-level behaviour is exercised headlessly, and the wiring between them is
 * pinned by source text.
 *
 * Run: node front-end/test/topology-context-menu.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

// ── the renderer, headless (topology-render.test.js's harness) ──────────────
function makeWindow() {
  const sandbox = { console, setTimeout, clearTimeout, setInterval, clearInterval };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;
  const docEl = { getAttribute: () => null, setAttribute() {} };
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
  for (const f of ['vendor/lodash.min.js', 'vendor/cytoscape.min.js',
    'vendor/cytoscape-edgehandles.js',
    'js/topology/topology-icons.js', 'js/topology/topology-render.js']) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  return sandbox;
}

/** topology-editor.js only needs `window` at load; mount() is never called here. */
function loadEditor() {
  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-editor.js'), 'utf8'),
    sandbox, { filename: 'topology-editor.js' });
  return sandbox.CyberCoreTopologyEditor;
}

const Editor = loadEditor();
const EDITOR_SRC = fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-editor.js'), 'utf8');
const RENDER_SRC = fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-render.js'), 'utf8');

// ── 1. THE LAST-NIC REFUSAL ─────────────────────────────────────────────────

test('detach is offered at 2 NICs and refused at 1', () => {
  assert.strictEqual(Editor.menuGuards({ name: 'web01', nicCount: 2 }).detach.allowed, true);
  const one = Editor.menuGuards({ name: 'DC01', nicCount: 1 });
  assert.strictEqual(one.detach.allowed, false,
    'a machine must keep at least one NIC — "Detach" is only offered from 2 up');
  assert.ok(one.detach.reason, 'and the refusal must SAY why, which is the whole point of refusing');
});

test('the refusal names the consequence, not just the rule', () => {
  const r = Editor.menuGuards({ name: 'DC01', nicCount: 1 }).detach.reason;
  assert.match(r, /DHCP lease/, 'a VM with no network gets no lease');
  assert.match(r, /not authored/, 'and an empty nics list is read downstream as "unspecified"');
  assert.match(r, /deploy attached anyway/,
    'THE SENTENCE: accepting the detach would produce a machine that deploys attached while the canvas '
    + 'shows it floating. That is what made the old silent no-op possible.');
  assert.match(r, /Move to/, 'and it points at the operation the author actually wanted');
  assert.match(r, /DC01/, 'named, so a menu on the wrong machine is obvious');
});

test('zero NICs is also refused, with a different sentence', () => {
  // Reachable from an import or an older editor, which is exactly why
  // validateTopology gained `no-nic` as well: the canvas refuses to CREATE the
  // state, the validator catches it ARRIVING.
  const r = Editor.menuGuards({ name: 'orphan', nicCount: 0 });
  assert.strictEqual(r.detach.allowed, false);
  assert.match(r.detach.reason, /not attached to anything/);
});

test('a nonsense nicCount cannot accidentally enable detach', () => {
  for (const bad of [undefined, null, NaN, -3, 'two', {}]) {
    assert.strictEqual(Editor.menuGuards({ nicCount: bad }).detach.allowed, false,
      `nicCount=${JSON.stringify(bad)} must not be read as "plenty of NICs"`);
  }
});

// ── 2. GOAD NAME LOCKS ──────────────────────────────────────────────────────

test('rename and remove are DISABLED for a GOAD-locked host, both with the reason', () => {
  const g = Editor.menuGuards({ name: 'DC01', nicCount: 2, locked: true });
  assert.strictEqual(g.rename.allowed, false);
  assert.strictEqual(g.remove.allowed, false);
  assert.strictEqual(g.rename.reason, g.remove.reason, 'it is one rule, so it is one sentence');
  assert.match(g.rename.reason, /matches AD hosts by name/,
    'the reason has to explain WHY a rename is not just a label change');
  assert.match(g.rename.reason, /Untick the lab/, 'and offer the operation that actually removes it');
});

test('an unlocked machine may be renamed and removed', () => {
  const g = Editor.menuGuards({ name: 'jump', nicCount: 2, locked: false });
  assert.strictEqual(g.rename.allowed, true);
  assert.strictEqual(g.remove.allowed, true);
  assert.strictEqual(g.rename.reason, null);
});

test('the locks are independent of the NIC count, and vice versa', () => {
  // A GOAD host with two NICs may still be detached from one of them (the v3
  // pivot shape); an unlocked host with one NIC still may not.
  const lockedTwoNics = Editor.menuGuards({ nicCount: 2, locked: true });
  assert.strictEqual(lockedTwoNics.detach.allowed, true);
  assert.strictEqual(lockedTwoNics.rename.allowed, false);

  const freeOneNic = Editor.menuGuards({ nicCount: 1, locked: false });
  assert.strictEqual(freeOneNic.detach.allowed, false);
  assert.strictEqual(freeOneNic.rename.allowed, true);
});

test('both menus that offer Detach read the SAME guard', () => {
  // The machine menu and the NIC-edge menu are two entry points to one
  // operation. Two copies of the rule is how one of them ends up permissive.
  const uses = EDITOR_SRC.match(/menuGuards\(\{ name: vm\.name, nicCount: on\.length, locked: isGoadVm\(vm\) \}\)/g);
  assert.strictEqual((uses || []).length, 2,
    'buildMachineMenu and buildNicMenu must each call menuGuards, not re-derive the rule');
  assert.match(EDITOR_SRC, /disabled: !guards\.detach\.allowed,\s*\n\s*reason: guards\.detach\.reason/);
  assert.match(EDITOR_SRC, /disabled: !guards\.rename\.allowed/);
  assert.match(EDITOR_SRC, /disabled: !guards\.remove\.allowed/);
});

test('a disabled item keeps its row and prints the reason — it is not hidden', () => {
  assert.match(EDITOR_SRC, /if \(it\.disabled && it\.reason\) \{/,
    'hiding the item would remove the only place the reason could be said');
  const html = fs.readFileSync(path.join(PUBLIC, 'admin.html'), 'utf8');
  assert.match(html, /\.topo-ctxmenu-item\.is-disabled \{ cursor:not-allowed; opacity:0\.5; \}/);
  assert.match(html, /\.topo-ctxmenu-reason \{/);
});

// ── 3. CLICK-TO-DETACH IS GONE ──────────────────────────────────────────────

/** Source with comment lines dropped — the retired handler is quoted in prose on purpose. */
function code(src) {
  return src.split('\n').filter((l) => {
    const t = l.trim();
    return t && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
  }).join('\n');
}

test('THE RETIRED GESTURE: no tap handler on a NIC edge mutates the graph', () => {
  assert.ok(!/cy\.on\('tap', 'edge\[kind="nic"\]'/.test(code(RENDER_SRC)),
    'a single stray click must no longer strip a NIC. Detach lives in the context menu, where it can '
    + 'be refused with a reason. (The old handler is QUOTED in a comment there, deliberately, so this '
    + 'scan ignores comment lines.)');
  assert.match(RENDER_SRC, /Click-to-detach is RETIRED/,
    'and the comment explaining why must stay — it is the whole story of the bug');
  // The edge stays selectable and now has a visible selected style, so the tap
  // still does something rather than reading as dead.
  assert.match(RENDER_SRC, /selectable: mode === 'edit'/);
  assert.match(RENDER_SRC, /\{ selector: 'edge:selected', style: \{ 'line-color': theme\.primary/);
});

test('drag-to-attach is kept — it is the good half of the old interaction', () => {
  assert.match(RENDER_SRC, /cy\.on\('ehcomplete'/);
  assert.match(RENDER_SRC, /eh = cy\.edgehandles\(/);
});

test('Escape cancels a drag in flight, and the listener is removed on destroy', () => {
  assert.match(RENDER_SRC, /if \(ev\.key !== 'Escape' && ev\.keyCode !== 27\) return;/);
  assert.match(RENDER_SRC, /if \(eh && eh\.stop\)/,
    'without this the only way out of a half-drawn NIC is to complete it and then detach — the '
    + 'accidental edit this phase removes');
  assert.match(RENDER_SRC, /if \(onKeyDown\) document\.removeEventListener\('keydown', onKeyDown\);/,
    'the listener is on `document`, so it outlives the canvas unless destroy() takes it down');
});

// ── 4. cxttap wiring ────────────────────────────────────────────────────────

test('the four right-click targets are all wired, natively — no plugin is vendored', () => {
  for (const sel of ["'node\\[kind=\"vm\"\\]'", "'edge\\[kind=\"nic\"\\]'", "'node\\[kind=\"segment\"\\]'"]) {
    assert.match(RENDER_SRC, new RegExp(`cy\\.on\\('cxttap', ${sel}`), `missing cxttap for ${sel}`);
  }
  assert.match(RENDER_SRC, /cy\.on\('cxttap', function \(evt\) \{/, 'and the core (background) menu');
  assert.match(RENDER_SRC, /if \(evt\.target !== cy\) return;/,
    'a cxttap on an element bubbles to the core too — without this guard the background menu would '
    + 'replace the machine menu a moment later');

  const vendor = fs.readdirSync(path.join(PUBLIC, 'vendor')).filter(f => f.endsWith('.js')).sort();
  assert.deepStrictEqual(vendor,
    ['cytoscape-edgehandles.js', 'cytoscape.min.js', 'lodash.min.js'],
    'there is no build step, so a context-menu plugin would be a fourth file to maintain forever for '
    + 'markup the editor builds in twenty lines');
});

test('right-clicking a machine selects it, so the panel and the menu agree', () => {
  assert.match(RENDER_SRC, /cy\.\$\('node:selected'\)\.unselect\(\);\s*\n\s*evt\.target\.select\(\);/);
});

test('the menu is positioned against <body>, in page coordinates', () => {
  // The canvas lives inside a CSS grid with overflow; a menu clipped by its own
  // container is worse than no menu.
  assert.match(RENDER_SRC, /pageX: oe\.pageX != null \? oe\.pageX : \(oe\.clientX \|\| 0\)/);
  assert.match(EDITOR_SRC, /document\.body\.appendChild\(menuEl\);/);
  const html = fs.readFileSync(path.join(PUBLIC, 'admin.html'), 'utf8');
  assert.match(html, /\.topo-ctxmenu \{[\s\S]{0,200}position:absolute/);
});

test('the menu is torn down with the canvas and closes on Escape or an outside click', () => {
  assert.match(EDITOR_SRC, /destroy: function \(\) \{[\s\S]{0,400}closeMenu\(\);/,
    'the menu is on <body>, so a remount would otherwise leave an orphan wired to a destroyed graph');
  assert.match(EDITOR_SRC, /document\.addEventListener\('mousedown', onDocDown, true\)/);
  assert.match(EDITOR_SRC, /document\.removeEventListener\('keydown', onMenuKey, true\)/);
});

// ── 5. AN UNATTACHED MACHINE LOOKS UNATTACHED ───────────────────────────────

test('a machine on no segment carries attached:false; an attached one carries true', () => {
  const win = makeWindow();
  const topo = win.CyberCoreTopology.create(null, { mode: 'view' });
  topo.setData({
    segments: [{ id: 'lan', role: 'lan', label: 'Lane Network' }],
    nodes: [
      { id: 'a', name: 'DC01', segments: ['lan'] },
      { id: 'b', name: 'orphan', segments: [] },
    ],
  });
  const byLabel = {};
  topo.cy.nodes('[kind="vm"]').forEach((n) => { byLabel[n.data('label')] = n.data('attached'); });
  assert.strictEqual(byLabel.DC01, true);
  assert.strictEqual(byLabel.orphan, false,
    'a detached DC01 used to be pixel-identical to an attached one, which is how the silent no-op '
    + 'stayed invisible');
});

test('the warning ring is styled off that flag, and errors still win', () => {
  assert.match(RENDER_SRC, /selector: 'node\[kind="vm"\]\[!attached\]'/);
  assert.match(RENDER_SRC, /'border-color': theme\.warning, 'border-width': 3, 'border-style': 'dashed'/);
  // Rule order is load-bearing: severity is declared AFTER, so a machine that is
  // both unattached and invalid reads as invalid.
  const unattachedAt = RENDER_SRC.indexOf("node[kind=\"vm\"][!attached]");
  const severityAt = RENDER_SRC.indexOf("node[severity=\"error\"]");
  assert.ok(unattachedAt > 0 && severityAt > unattachedAt,
    'the severity rules must come after, so a broken machine still reads as broken');
});

// ── 6. one creation path, and new machines are born attached ────────────────

test('the palette drop and the menu\'s "Add machine" share one creation path', () => {
  assert.match(EDITOR_SRC, /function addFromTemplate\(tpl, renderedPos\)/);
  assert.match(EDITOR_SRC, /addFromTemplate\(tpl, \{ x: ev\.clientX - rect\.left, y: ev\.clientY - rect\.top \}\)/,
    'the drop handler must call it, not keep its own copy');
  assert.match(EDITOR_SRC, /addFromTemplate\(t, ev\.renderedPosition\)/,
    'and so must the background menu');
  assert.match(EDITOR_SRC, /segments: \[scheme === 'v3' \? 'ext' : 'lan'\]/,
    'a new machine is born ON a segment — a second creation path is a second place to forget that');
});

test('Duplicate copies the source\'s attachments, and never lands on nothing', () => {
  assert.match(EDITOR_SRC,
    /segments: \(src\.segments && src\.segments\.length\) \? src\.segments\.slice\(\) : \[all\[0\]\.id\],/,
    'a copy that landed on no segment would be born holding the very zero-NIC state this menu refuses '
    + 'to create by hand');
});

// ── 7. the toolbar no longer advertises the retired gesture ─────────────────

test('the UI text stops telling people to click a link to detach', () => {
  const html = fs.readFileSync(path.join(PUBLIC, 'admin.html'), 'utf8');
  assert.ok(!/click a link to detach/.test(html), 'the toolbar hint described the retired gesture');
  assert.match(html, /right-click anything for its menu/);
  assert.ok(!/click a link to detach/.test(EDITOR_SRC), 'and so did the empty property panel');
  assert.match(EDITOR_SRC, /Right-click anything — machine, link, network, background —/);
});
