/**
 * view-mode-client.test.js — Student View's state and the real/effective split.
 *
 * Student View is a PRESENTATION mode for lecture recordings: it draws the
 * interface the way a student's looks so instructor-only navigation stays out
 * of the video. It grants and removes nothing — the instructor keeps every bit
 * of access they had.
 *
 * Two things would break it silently, so they are pinned here:
 *
 *   1. The split. Auth.user is what the interface is DRAWN from (role reads
 *      'student' in this mode); Auth.realUser is what the server said and is
 *      what ACCESS decisions read. Collapse them and either the mode stops
 *      hiding anything, or an instructor gets locked out of their own pages
 *      mid-recording.
 *   2. isRealAdmin()/isRealInstructor() must stay TRUE while previewing. Those
 *      are what the page gates use.
 *
 * app.js has no build step and no browser in CI, and the DOM surface it touches
 * is small, so it is shimmed rather than pulling in jsdom — same policy as
 * topology-render.test.js, which this follows.
 *
 * Run: node front-end/test/view-mode-client.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

/** Minimal Storage shim — app.js only uses get/set/removeItem. */
function makeStorage(seed) {
  const m = new Map(seed ? Object.entries(seed) : []);
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
    _map: m,
  };
}

function makeWindow({ storage = null } = {}) {
  const sandbox = { console, setTimeout, clearTimeout, setInterval, clearInterval, JSON };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;

  const reloads = [];
  sandbox.location = { protocol: 'https:', pathname: '/hub', href: '/hub', reload: () => reloads.push(1) };
  sandbox._reloads = reloads;

  const listeners = new Map();
  sandbox.addEventListener = (ev, fn) => {
    if (!listeners.has(ev)) listeners.set(ev, []);
    listeners.get(ev).push(fn);
  };
  sandbox.removeEventListener = () => {};
  sandbox.dispatchEvent = (e) => { (listeners.get(e.type) || []).forEach((fn) => fn(e)); };
  sandbox.Event = class { constructor(type) { this.type = type; } };
  sandbox._listeners = listeners;

  sandbox.document = {
    addEventListener() {}, removeEventListener() {},
    createElement: () => ({ style: {}, appendChild() {}, setAttribute() {}, textContent: '', innerHTML: '' }),
    querySelector: () => null,
    getElementById: () => null,
    head: { appendChild() {} },
    body: { appendChild() {} },
    documentElement: { getAttribute: () => null, setAttribute() {}, removeAttribute() {} },
  };

  sandbox.localStorage = makeStorage(storage);
  sandbox.sessionStorage = makeStorage();
  sandbox.navigator = { userAgent: 'node' };
  sandbox.fetch = () => Promise.reject(new Error('fetch not stubbed for this test'));

  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'js', 'app.js'), 'utf8'), sandbox, { filename: 'app.js' });

  // app.js declares its globals with `const`, which at script top level lands in
  // the context's lexical scope rather than on the global object — reachable
  // from code inside the vm, but not as sandbox properties. Evaluate them out.
  for (const name of ['API', 'APIError', 'Auth', 'ViewMode', 'Utils']) {
    sandbox[name] = vm.runInContext(name, sandbox);
  }
  return sandbox;
}

/** Point the sandbox's fetch at a fixed /auth/me payload. */
function stubMe(sb, user) {
  sb.fetch = () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ user }) });
}

const ON = { 'cc-student-view': '1' };

// ---------------------------------------------------------------------------
// The flag itself
// ---------------------------------------------------------------------------

test('inactive by default', () => {
  assert.strictEqual(makeWindow().ViewMode.isActive(), false);
});

test('enter() sets the flag and reloads', () => {
  const sb = makeWindow();
  sb.ViewMode.enter();

  assert.strictEqual(sb.ViewMode.isActive(), true);
  assert.strictEqual(sb.localStorage.getItem('cc-student-view'), '1');
  // Required: pages read the role once at DOMContentLoaded and never re-render.
  assert.strictEqual(sb._reloads.length, 1);
});

test('exit() clears the flag and reloads', () => {
  const sb = makeWindow({ storage: ON });
  assert.strictEqual(sb.ViewMode.isActive(), true);

  sb.ViewMode.exit();

  assert.strictEqual(sb.ViewMode.isActive(), false);
  assert.strictEqual(sb.localStorage.getItem('cc-student-view'), null);
  assert.strictEqual(sb._reloads.length, 1);
});

test('clear() is silent — no reload', () => {
  // Used by logout and by the self-heal, where reloading would loop.
  const sb = makeWindow({ storage: ON });
  sb.ViewMode.clear();

  assert.strictEqual(sb.ViewMode.isActive(), false);
  assert.strictEqual(sb._reloads.length, 0);
});

test('the flag survives a page load', () => {
  // Every navigation is a full reload, so this is what makes the mode last for
  // a whole recording rather than one page.
  const sb = makeWindow({ storage: ON });
  assert.strictEqual(sb.ViewMode.isActive(), true);
});

test('a second tab follows along', () => {
  const sb = makeWindow({ storage: ON });
  sb.dispatchEvent({ type: 'storage', key: 'cc-student-view' });
  assert.strictEqual(sb._reloads.length, 1);

  sb.dispatchEvent({ type: 'storage', key: 'ciab-theme' });
  assert.strictEqual(sb._reloads.length, 1, 'an unrelated key must not reload the page');
});

test('only staff are offered the mode', () => {
  const sb = makeWindow();
  assert.strictEqual(sb.ViewMode.canPreview({ role: 'admin' }), true);
  assert.strictEqual(sb.ViewMode.canPreview({ role: 'instructor' }), true);
  assert.strictEqual(sb.ViewMode.canPreview({ role: 'student' }), false);
  assert.strictEqual(sb.ViewMode.canPreview({ role: 'user' }), false);
  assert.strictEqual(sb.ViewMode.canPreview(null), false);
});

// ---------------------------------------------------------------------------
// The real/effective split
// ---------------------------------------------------------------------------

test('with the mode off, Auth is untouched', async () => {
  const sb = makeWindow();
  stubMe(sb, { id: 'u1', email: 'a@b.c', role: 'admin' });

  assert.strictEqual(await sb.Auth.check(), true);
  assert.strictEqual(sb.Auth.user.role, 'admin');
  assert.strictEqual(sb.Auth.isAdmin(), true);
  assert.strictEqual(sb.Auth.isViewingAsStudent(), false);
});

for (const role of ['admin', 'instructor']) {
  test(`a ${role} is DRAWN as a student but still IS a ${role}`, async () => {
    const sb = makeWindow({ storage: ON });
    stubMe(sb, { id: 'u1', email: 'prof@clinic.local', role, firstName: 'Pat' });

    await sb.Auth.check();

    // Drawn — this is what every chrome check in the app reads.
    assert.strictEqual(sb.Auth.user.role, 'student');
    assert.strictEqual(sb.Auth.user.viewingAsStudent, true);
    assert.strictEqual(sb.Auth.isAdmin(), false);
    assert.strictEqual(sb.Auth.isInstructor(), false);

    // Actual — this is what the page access gates read. If these ever went
    // false, the instructor would be bounced off their own pages mid-recording.
    assert.strictEqual(sb.Auth.realUser.role, role);
    assert.strictEqual(sb.Auth.isRealInstructor(), true);
    assert.strictEqual(sb.Auth.isRealAdmin(), role === 'admin');
    assert.strictEqual(sb.Auth.isViewingAsStudent(), true);

    // Identity is untouched: same person, same account, different drawing.
    assert.strictEqual(sb.Auth.user.email, sb.Auth.realUser.email);
    assert.strictEqual(sb.Auth.user.id, sb.Auth.realUser.id);
    assert.strictEqual(sb.Auth.user.firstName, 'Pat');
  });
}

test('the drawn role is re-derived on every page load', async () => {
  const sb = makeWindow({ storage: ON });
  stubMe(sb, { id: 'u1', email: 'a@b.c', role: 'admin' });

  await sb.Auth.check();
  assert.strictEqual(sb.Auth.user.role, 'student');
  await sb.Auth.check();
  assert.strictEqual(sb.Auth.user.role, 'student');
  assert.strictEqual(sb.Auth.realUser.role, 'admin');
});

for (const role of ['student', 'user']) {
  test(`a stray flag on a ${role} account is cleared`, async () => {
    // Nothing to hide on such an account, so the flag is dead weight. Clearing
    // it keeps the mode from being something a student can end up "in".
    const sb = makeWindow({ storage: ON });
    stubMe(sb, { id: 'u2', email: 'stu@clinic.local', role });

    await sb.Auth.check();

    assert.strictEqual(sb.Auth.user.role, role);
    assert.strictEqual(sb.Auth.isViewingAsStudent(), false);
    assert.strictEqual(sb.ViewMode.isActive(), false);
    assert.strictEqual(sb._reloads.length, 0, 'the self-heal must not loop');
  });
}

test('logout drops the mode with the session', async () => {
  const sb = makeWindow({ storage: ON });
  stubMe(sb, { id: 'u1', email: 'a@b.c', role: 'admin' });
  await sb.Auth.check();

  await sb.Auth.logout();

  assert.strictEqual(sb.ViewMode.isActive(), false);
  assert.strictEqual(sb.Auth.user, null);
  assert.strictEqual(sb.Auth.realUser, null);
});

// ---------------------------------------------------------------------------
// Nothing is blocked
// ---------------------------------------------------------------------------

test('requests are not altered by the mode', async () => {
  // The server knows nothing about Student View. If a request ever started
  // carrying it, the mode would stop being presentation-only.
  const seen = [];
  const sb = makeWindow({ storage: ON });
  sb.fetch = (url, cfg) => {
    seen.push({ url, cfg });
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) });
  };

  await sb.API.request('/admin/settings');

  assert.strictEqual(seen.length, 1);
  assert.strictEqual(seen[0].url, '/api/admin/settings', 'no extra query parameter');
  const headerNames = Object.keys(seen[0].cfg.headers).map((h) => h.toLowerCase());
  assert.ok(!headerNames.some((h) => h.includes('view') || h.includes('student')),
    'no Student View header may be sent');
});
