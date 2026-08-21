/**
 * view-mode-nav.test.js — Student View, as the sidebar actually renders it.
 *
 * The two client-side gates that decide what an instructor can SEE are
 * `visibleItems()` and `isEntryVisible()` in layout.js, and both key off
 * `Auth.getUser()?.role`. Student View works by making that role read
 * 'student', so the nav is where the whole feature is either real or cosmetic.
 *
 * The strongest assertion here is the byte-comparison: the sidebar an admin
 * gets while previewing must be IDENTICAL to the sidebar a genuine student
 * gets. Anything less and "Student View" is a guess rather than a preview.
 *
 * The subnav fixtures are read from the real manifest.json files rather than
 * copied, so this test tracks the menus as they change instead of asserting
 * against a stale snapshot.
 *
 * Run: node front-end/test/view-mode-nav.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');
const PLUGINS = path.join(ROOT, 'modules', 'crucible', 'plugins');

const readManifest = (name) =>
  JSON.parse(fs.readFileSync(path.join(PLUGINS, name, 'manifest.json'), 'utf8'));

const CIAB = readManifest('ciab');
const CLE = readManifest('cle');

// Shaped like the rows /api/modules returns from cybercore_module.
const PLUGIN_ROWS = [CIAB, CLE].map((m) => ({
  key: m.key, name: m.name, entry_url: m.entry_url, category: m.category, display_order: 1,
}));

function makeStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
}

/** app.js + layout.js in one context, on a given page path. */
function makeWindow(pathname = '/ciab/dashboard') {
  const sandbox = { console, setTimeout, clearTimeout, setInterval, clearInterval, JSON };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;

  sandbox.location = { protocol: 'https:', pathname, href: pathname, search: '', reload() {} };
  sandbox.addEventListener = () => {};
  sandbox.removeEventListener = () => {};
  sandbox.dispatchEvent = () => {};
  sandbox.Event = class { constructor(type) { this.type = type; } };
  sandbox.URLSearchParams = URLSearchParams;
  sandbox.requestAnimationFrame = (fn) => fn();

  sandbox.document = {
    addEventListener() {}, removeEventListener() {},
    createElement: () => ({ style: {}, appendChild() {}, setAttribute() {}, classList: { add() {}, remove() {} }, innerHTML: '' }),
    querySelector: () => null,
    querySelectorAll: () => [],
    getElementById: () => null,
    head: { appendChild() {} },
    body: { appendChild() {}, classList: { add() {}, remove() {} } },
    documentElement: { getAttribute: () => null, setAttribute() {}, removeAttribute() {} },
  };

  sandbox.localStorage = makeStorage();
  sandbox.sessionStorage = makeStorage();
  sandbox.navigator = { userAgent: 'node' };
  sandbox.fetch = () => Promise.reject(new Error('fetch not stubbed'));

  vm.createContext(sandbox);
  for (const f of ['js/app.js', 'js/layout.js']) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  // Both files declare their globals with `const`, which lives in the context's
  // lexical scope rather than on the global object.
  for (const name of ['Auth', 'ViewMode', 'Layout', 'Utils']) {
    sandbox[name] = vm.runInContext(name, sandbox);
  }

  sandbox.Layout._subnavs = { ciab: CIAB.subnav, cle: CLE.subnav };
  return sandbox;
}

/** Put the sandbox into the state Auth.check() would leave it in. */
function signIn(sb, { role, previewing = false }) {
  const server = { id: 'u1', email: 'pat@clinic.local', firstName: 'Pat', lastName: 'Kim', role };
  sb.Auth.realUser = server;
  sb.Auth.user = previewing
    ? { ...server, role: 'student', realRole: role, viewingAsStudent: true }
    : server;
}

const nav = (sb) => sb.Layout.buildNavHTML([], PLUGIN_ROWS);

// ---------------------------------------------------------------------------
// Baseline: the nav really is role-sensitive
// ---------------------------------------------------------------------------

test('an admin sees CLE, the CIAB instructor page and Deploy Lanes', () => {
  const sb = makeWindow();
  signIn(sb, { role: 'admin' });
  const html = nav(sb);

  assert.match(html, /\/cle\/dashboard/);
  assert.match(html, /\/ciab\/instructor/);
  assert.match(html, /\/ciab\/admin-profile-lanes/);
});

test('an instructor sees CLE and the instructor page but not Deploy Lanes', () => {
  const sb = makeWindow();
  signIn(sb, { role: 'instructor' });
  const html = nav(sb);

  assert.match(html, /\/cle\/dashboard/);
  assert.match(html, /\/ciab\/instructor/);
  assert.doesNotMatch(html, /\/ciab\/admin-profile-lanes/);
});

// ---------------------------------------------------------------------------
// Student View
// ---------------------------------------------------------------------------

test('previewing hides every privileged entry', () => {
  const sb = makeWindow();
  signIn(sb, { role: 'admin', previewing: true });
  const html = nav(sb);

  // Gone.
  assert.doesNotMatch(html, /\/cle\//, 'the whole CLE entry should vanish, not just its children');
  assert.doesNotMatch(html, /\/ciab\/instructor/);
  assert.doesNotMatch(html, /\/ciab\/admin-profile-lanes/);

  // Still there — a student is not locked out of the ordinary app.
  assert.match(html, /\/ciab\/dashboard/);
  assert.match(html, /\/ciab\/generator/);
  assert.match(html, /\/ciab\/progress/);
});

test('the CLE module row itself disappears, via isEntryVisible', () => {
  // Every CLE child is gated, so the parent entry has nothing left to show.
  // This is the behaviour that makes CLE instructor-only without a schema
  // change, and it is what a student genuinely sees.
  const sb = makeWindow();
  signIn(sb, { role: 'admin', previewing: true });
  assert.doesNotMatch(nav(sb), /Cyber Learning Environment/);
});

test('previewing nav is byte-identical to a genuine student nav', () => {
  // The strongest assertion in the suite. If these ever diverge, Student View
  // has stopped being a preview and become an approximation.
  for (const realRole of ['admin', 'instructor']) {
    const preview = makeWindow();
    signIn(preview, { role: realRole, previewing: true });

    const student = makeWindow();
    signIn(student, { role: 'student' });

    assert.strictEqual(nav(preview), nav(student),
      `previewing ${realRole} nav differs from a real student's`);
  }
});

// ---------------------------------------------------------------------------
// The sidebar footer: gear out, toggle in
// ---------------------------------------------------------------------------

test('the admin gear is hidden while previewing', () => {
  const sb = makeWindow();

  signIn(sb, { role: 'admin' });
  assert.match(sb.Layout.getSidebarHTML(), /href="\/admin"/);

  signIn(sb, { role: 'admin', previewing: true });
  assert.doesNotMatch(sb.Layout.getSidebarHTML(), /href="\/admin"/);
});

test('the toggle is offered to staff and labelled by state', () => {
  const sb = makeWindow();

  signIn(sb, { role: 'admin' });
  let html = sb.Layout.getSidebarHTML();
  assert.match(html, /student-view-btn/);
  assert.match(html, />Student View</);
  assert.doesNotMatch(html, /Exit Student View/);

  signIn(sb, { role: 'admin', previewing: true });
  html = sb.Layout.getSidebarHTML();
  assert.match(html, /Exit Student View/);
  assert.match(html, /is-on/);
  // The role pill reads what a student's reads. The amber toggle right above it
  // is the only thing telling the instructor the mode is on — deliberately, so
  // the recording is not covered in Student View labelling.
  assert.match(html, />Student</);
  assert.doesNotMatch(html, />Admin</);
});

test('a genuine student is offered no toggle at all', () => {
  const sb = makeWindow();
  signIn(sb, { role: 'student' });
  const html = sb.Layout.getSidebarHTML();

  assert.doesNotMatch(html, /student-view-btn/);
  assert.doesNotMatch(html, /Student View/);
  assert.doesNotMatch(html, /href="\/admin"/);
});

test('the toggle is absent on first paint, before /auth/me answers', () => {
  // Auth.realUser is null until authReady. The toggle must not flash in, the
  // same way the Admin gear does not.
  const sb = makeWindow();
  sb.Auth.user = null;
  sb.Auth.realUser = null;
  assert.doesNotMatch(sb.Layout.getSidebarHTML(), /student-view-btn/);
});
