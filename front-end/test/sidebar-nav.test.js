/**
 * sidebar-nav.test.js — what the left navigation actually renders.
 *
 * The sidebar is built entirely client-side by public/js/layout.js, so this
 * evaluates that file in a stubbed browser context and asserts on the HTML
 * buildNavHTML() produces. It locks in the behaviour a course instructor
 * reported as broken or confusing:
 *
 *   - Home is the first entry (previously only the logo went home).
 *   - Modules and plugins are ONE list ordered by display_order, so the Cyber
 *     Learning Environment can sit above The Crucible. The old code emitted a
 *     "Modules" section then a "Plugins" section, which made that impossible.
 *   - Every entry renders its children, collapsed, with a real toggle button.
 *     Previously only the module you were already inside had any children in
 *     the DOM, so there was nothing for the arrow to collapse.
 *   - An entry whose children are all instructor-gated is hidden from students
 *     (this is what keeps CLE off a student's menu), and it fails CLOSED while
 *     Auth is still resolving.
 *
 * Run: node front-end/test/sidebar-nav.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const LAYOUT_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'js', 'layout.js'), 'utf8'
);

const SUBNAVS = {
  crucible: { items: [
    { label: 'Weekly', page: 'weekly', url: '/crucible/dashboard?type=weekly' },
    { label: 'Leaderboard', page: 'leaderboard', url: '/crucible/dashboard?type=leaderboard' }
  ] },
  ciab: { items: [
    { label: 'Dashboard', page: 'dashboard', url: '/ciab/dashboard' },
    { label: 'Instructor', page: 'instructor', url: '/ciab/instructor', roles: ['instructor', 'admin'] },
    { label: 'AI Assistant', page: 'ai-assistant', url: '#', onclick: 'Layout.openChat(); return false;' }
  ] },
  cle: { items: [
    { label: 'Instructor Dashboard', page: 'dashboard', url: '/cle/dashboard', roles: ['instructor', 'admin'] },
    { label: 'Courses', page: 'courses', url: '/cle/courses', roles: ['instructor', 'admin'] }
  ] }
};

// Mirrors the live manifests: cle=1, crucible=2, ciab=3.
const MODULES = [{ key: 'crucible', name: 'The Crucible', entry_url: '/crucible/dashboard', display_order: 2 }];
const PLUGINS = [
  { key: 'ciab', name: 'Clinic-in-a-Box', entry_url: '/ciab/dashboard', display_order: 3 },
  { key: 'cle', name: 'Cyber Learning Environment', entry_url: '/cle/dashboard', display_order: 1 }
];

/** Evaluate layout.js against a stub DOM and return the rendered nav HTML. */
function renderNav({ page = '/hub', role = 'student', openSections = null, chatEnabled = 'true' } = {}) {
  const local = {};
  if (openSections !== null) local['cyberhub-nav-open'] = JSON.stringify(openSections);
  const session = { 'cyberhub-chat-enabled': chatEnabled };
  const noop = () => {};

  const ctx = {
    console,
    URLSearchParams,
    setTimeout: noop,
    requestAnimationFrame: noop,
    window: { location: { pathname: page, search: '' }, addEventListener: noop },
    document: {
      addEventListener: noop,
      getElementById: () => null,
      querySelector: () => null,
      documentElement: { getAttribute: () => null }
    },
    localStorage: {
      getItem: k => (k in local ? local[k] : null),
      setItem: (k, v) => { local[k] = v; },
      removeItem: k => { delete local[k]; }
    },
    sessionStorage: {
      getItem: k => (k in session ? session[k] : null),
      setItem: (k, v) => { session[k] = v; }
    },
    Auth: { getUser: () => (role ? { role, email: 'a@b.c' } : null) },
    API: {}
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(LAYOUT_SRC + ';globalThis.__Layout = Layout;', ctx);

  const Layout = ctx.__Layout;
  Layout.currentPage = page;
  Layout._subnavs = SUBNAVS;
  return { html: Layout.buildNavHTML(MODULES, PLUGINS), Layout };
}

const labels = html => (html.match(/<span>([^<]+)<\/span>/g) || []).map(s => s.replace(/<\/?span>/g, ''));

test('Home is the first entry in the menu', () => {
  const { html } = renderNav();
  assert.strictEqual(labels(html)[0], 'Home');
  assert.match(html, /href="\/hub"/);
});

test('entries are one flat list ordered by display_order, not Modules-then-Plugins', () => {
  const { html } = renderNav({ role: 'instructor' });
  assert.ok(!html.includes('nav-section-title'), 'no section headings should remain');
  assert.ok(
    html.indexOf('Cyber Learning Environment') < html.indexOf('The Crucible'),
    'CLE (display_order 1) must sort above Crucible (2) despite being a plugin'
  );
  assert.ok(html.indexOf('The Crucible') < html.indexOf('Clinic-in-a-Box'));
});

test('a student never sees the instructor-only Cyber Learning Environment', () => {
  const { html } = renderNav({ role: 'student' });
  assert.ok(!html.includes('Cyber Learning Environment'));
  assert.ok(html.includes('The Crucible'), 'ungated entries still render');
});

test('role filtering also applies to individual child items', () => {
  const { html } = renderNav({ role: 'student' });
  assert.ok(!html.includes('>Instructor<'), 'CIAB instructor page is hidden from students');
  assert.ok(html.includes('Clinic-in-a-Box'), 'but the module itself stays visible');
});

test('role gating fails closed while Auth is still resolving', () => {
  // The first paint happens before /auth/me returns, so getUser() is null.
  // Showing the entry then hiding it would flash CLE at every student.
  const { html } = renderNav({ role: null });
  assert.ok(!html.includes('Cyber Learning Environment'));
});

test('every entry renders its children, so there is something to collapse', () => {
  const { html } = renderNav({ role: 'student', page: '/hub' });
  assert.match(html, /id="subnav-crucible"/);
  assert.match(html, /id="subnav-ciab"/);
});

test('the module you are inside is expanded; the others are collapsed', () => {
  const { html } = renderNav({ role: 'student', page: '/crucible/dashboard' });
  assert.ok(/id="subnav-crucible"(?! hidden)/.test(html), 'active module expanded');
  assert.match(html, /id="subnav-ciab" hidden/);
});

test('the toggle is a real button carrying disclosure semantics', () => {
  const { html } = renderNav({ role: 'student', page: '/crucible/dashboard' });
  assert.match(html, /<button type="button" class="nav-toggle"/);
  assert.match(html, /aria-controls="subnav-crucible"/);
  assert.match(html, /aria-expanded="true"/);
  assert.match(html, /aria-expanded="false"/);
});

test('remembered open/closed state survives a page load', () => {
  const { html } = renderNav({ role: 'student', page: '/hub', openSections: ['ciab'] });
  assert.ok(/id="subnav-ciab"(?! hidden)/.test(html), 'remembered section reopens');
  assert.match(html, /id="subnav-crucible" hidden/);
});

test('nav open-state round-trips through storage', () => {
  const { Layout } = renderNav();
  Layout.setOpenNavKeys(['crucible', 'ciab']);
  // Array comes back from the vm realm, so compare by value not by prototype.
  assert.deepStrictEqual([...Layout.getOpenNavKeys()], ['crucible', 'ciab']);
});

test('a child item that only opens the chat is dropped when no LLM is configured', () => {
  assert.ok(renderNav({ chatEnabled: 'true' }).html.includes('AI Assistant'));
  assert.ok(!renderNav({ chatEnabled: 'false' }).html.includes('AI Assistant'));
});

test('a child is only marked active inside its own module', () => {
  // getActiveSubPage() is substring-based, so '/ciab/dashboard' would otherwise
  // also light up CLE's 'dashboard' child.
  const { html } = renderNav({ role: 'instructor', page: '/ciab/dashboard' });
  const cleSubnav = html.slice(html.indexOf('id="subnav-cle"'));
  assert.ok(!/subnav-item active/.test(cleSubnav.slice(0, cleSubnav.indexOf('</div>'))));
});
