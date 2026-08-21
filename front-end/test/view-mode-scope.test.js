/**
 * view-mode-scope.test.js — the lists, in Student View.
 *
 * This covers the one thing about Student View that is easy to get wrong and
 * embarrassing to get wrong on camera.
 *
 * Both workspace endpoints treat a privileged caller as CLUSTER-WIDE by default
 * and only narrow when the client asks:
 *
 *     showAll = isPrivileged && req.query.scope !== 'mine'
 *         — src/routes/guac-sessions.js, src/routes/workstations.js
 *
 * Student View changes nothing on the server, so during a recording the caller
 * is still an instructor there. Hiding the "All users | Me only" toggle is
 * therefore NOT enough: with the toggle gone the client stops sending
 * ?scope=mine, and the list comes back holding every student's VM — with their
 * email address in the owner column — in the middle of the lecture.
 *
 * So the client has to ask for ?scope=mine EXPLICITLY. These tests assert the
 * URL that actually goes out.
 *
 * Run: node front-end/test/view-mode-scope.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

function makeStorage(seed) {
  const m = new Map(seed ? Object.entries(seed) : []);
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
}

/** A DOM stub that hands back a usable element for anything asked of it. */
function fakeEl() {
  const el = {
    style: {}, dataset: {}, textContent: '', innerHTML: '',
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    appendChild() {}, removeChild() {}, remove() {}, insertAdjacentHTML() {},
    setAttribute() {}, removeAttribute() {}, getAttribute: () => null,
    addEventListener() {}, removeEventListener() {},
    scrollIntoView() {}, closest: () => null,
    querySelector: () => fakeEl(), querySelectorAll: () => [],
  };
  return el;
}

function makeWindow({ storage = null, scripts = [] } = {}) {
  // No-op timers. workstations.js schedules a 30s auto-refresh after every
  // load (line ~238); with real timers that keeps the event loop alive and
  // `node --test` never exits.
  let _timerId = 0;
  const sandbox = {
    console, JSON,
    setTimeout: () => ++_timerId,
    clearTimeout: () => {},
    setInterval: () => ++_timerId,
    clearInterval: () => {},
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;

  sandbox.location = { protocol: 'https:', pathname: '/hub', href: '/hub', reload() {} };
  sandbox.addEventListener = () => {};
  sandbox.removeEventListener = () => {};
  sandbox.dispatchEvent = () => {};
  sandbox.Event = class { constructor(type) { this.type = type; } };

  sandbox.document = {
    getElementById: () => fakeEl(),
    querySelector: () => fakeEl(),
    querySelectorAll: () => [],
    createElement: () => fakeEl(),
    addEventListener() {}, removeEventListener() {},
    head: { appendChild() {} },
    body: { appendChild() {} },
    documentElement: { getAttribute: () => null, setAttribute() {}, removeAttribute() {} },
  };

  sandbox.localStorage = makeStorage(storage);
  sandbox.sessionStorage = makeStorage();
  sandbox.navigator = { userAgent: 'node' };

  const calls = [];
  sandbox._calls = calls;
  sandbox.fetch = (url) => {
    calls.push(String(url));
    return Promise.resolve({
      ok: true, status: 200,
      json: () => Promise.resolve({ vms: [], workstations: [], templates: [] }),
    });
  };

  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'js', 'app.js'), 'utf8'), sandbox, { filename: 'app.js' });
  for (const f of scripts) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  for (const name of ['Auth', 'ViewMode', 'API', 'Utils', 'VmWorkspaces', 'Workstations', 'HubCourses']) {
    try { sandbox[name] = vm.runInContext(name, sandbox); } catch (_) { /* not loaded */ }
  }
  return sandbox;
}

/** Put the sandbox in the state Auth.check() would leave it in. */
function signIn(sb, { role, previewing = false }) {
  const server = { id: 'u1', email: 'pat@clinic.local', role };
  sb.Auth.realUser = server;
  sb.Auth.user = previewing
    ? { ...server, role: 'student', realRole: role, viewingAsStudent: true }
    : server;
}

const ON = { 'cc-student-view': '1' };

// ---------------------------------------------------------------------------
// Lane VMs  →  GET /api/dashboard/vms
// ---------------------------------------------------------------------------

const VMS = { scripts: ['js/vm-console.js'] };
const vmsUrl = (sb) => sb._calls.find((u) => u.includes('/dashboard/vms'));

for (const role of ['admin', 'instructor']) {
  test(`Lane VMs: a ${role} normally gets the cluster-wide list`, async () => {
    const sb = makeWindow(VMS);
    signIn(sb, { role });

    await sb.VmWorkspaces.render(fakeEl(), 'someConsole');

    assert.ok(!vmsUrl(sb).includes('scope=mine'),
      'without the mode, staff keep their default cluster-wide view');
  });

  test(`Lane VMs: a ${role} in Student View asks for scope=mine`, async () => {
    const sb = makeWindow({ ...VMS, storage: ON });
    signIn(sb, { role, previewing: true });

    await sb.VmWorkspaces.render(fakeEl(), 'someConsole');

    assert.ok(vmsUrl(sb).includes('scope=mine'),
      'the request MUST narrow explicitly — the server still sees a privileged caller, ' +
      'so omitting this puts every student VM and email on screen');
  });
}

test('Lane VMs: a real student is unaffected', async () => {
  const sb = makeWindow(VMS);
  signIn(sb, { role: 'student' });

  await sb.VmWorkspaces.render(fakeEl(), 'someConsole');

  // The server scopes students by allocation regardless of the parameter, so
  // this only pins that we did not change their behaviour.
  assert.ok(vmsUrl(sb).startsWith('/api/dashboard/vms'));
});

// ---------------------------------------------------------------------------
// Workstations  →  GET /api/workstations/mine
// ---------------------------------------------------------------------------

const WKS = { scripts: ['js/workstations.js'] };
const wksUrl = (sb) => sb._calls.find((u) => u.includes('/workstations/mine'));

test('Workstations: an admin normally gets scope=all', async () => {
  const sb = makeWindow(WKS);
  signIn(sb, { role: 'admin' });

  await sb.Workstations.loadMyWorkstations(true);

  assert.ok(wksUrl(sb).includes('scope=all'));
});

test('Workstations: an admin in Student View asks for scope=mine', async () => {
  const sb = makeWindow({ ...WKS, storage: ON });
  signIn(sb, { role: 'admin', previewing: true });

  await sb.Workstations.loadMyWorkstations(true);

  const url = wksUrl(sb);
  assert.ok(url.includes('scope=mine'),
    'sending nothing would leave the server on its privileged default');
  assert.ok(!url.includes('scope=all'));
});

test('Workstations: an instructor in Student View asks for scope=mine', async () => {
  // The workstations endpoint only widens for admins, so an instructor was
  // already scoped — but the request must still be explicit, so the mode does
  // not depend on which endpoint happens to be lenient.
  const sb = makeWindow({ ...WKS, storage: ON });
  signIn(sb, { role: 'instructor', previewing: true });

  await sb.Workstations.loadMyWorkstations(true);

  assert.ok(wksUrl(sb).includes('scope=mine'));
});

// ---------------------------------------------------------------------------
// Home page courses  ->  GET /api/cle/my/overview
// ---------------------------------------------------------------------------
//
// Same trap as the lists above, one layer up. The endpoint decides whether to
// send taught-course cards and the admin summary from req.user.role, which is
// always the caller's REAL role. So the client has to ask for the student
// framing, or a professor's home page keeps its staff cards on camera.

const HUB = { scripts: ['js/hub-courses.js'] };
const hubUrl = (sb) => sb._calls.find((u) => u.includes('/cle/my/overview'));

test('Home page: an instructor normally gets the full overview', async () => {
  const sb = makeWindow(HUB);
  signIn(sb, { role: 'instructor' });

  await sb.HubCourses.load(true);

  assert.ok(!hubUrl(sb).includes('as=student'));
});

test('Home page: an instructor in Student View asks for as=student', async () => {
  const sb = makeWindow({ ...HUB, storage: ON });
  signIn(sb, { role: 'instructor', previewing: true });

  await sb.HubCourses.load(true);

  assert.ok(hubUrl(sb).includes('as=student'),
    'without this the taught-course cards and admin summary stay on the home page');
});

test('Home page: a real student asks for nothing extra', async () => {
  const sb = makeWindow(HUB);
  signIn(sb, { role: 'student' });

  await sb.HubCourses.load(true);

  assert.ok(!hubUrl(sb).includes('as=student'),
    'the parameter is for staff previewing; a student already sees a student page');
});
