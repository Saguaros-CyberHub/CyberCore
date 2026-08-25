/**
 * ciab-module-visibility.test.js — whether Clinic-in-a-Box appears in the menu.
 *
 * GET /api/modules had NO authentication and returned every active module plus
 * every subnav to anyone who asked. That was fine while every module was for
 * everyone; it stopped being fine when CIAB became enrollment-only, because a
 * student on no roster would still be offered a module they cannot open.
 *
 * Filtering happens SERVER-SIDE through a gate the plugin registers with the
 * module loader. The alternative — a client-side probe — could only remove the
 * entry after it had already painted, which is exactly the flicker the
 * fail-closed comment in layout.js isEntryVisible() exists to prevent.
 *
 * The assertions that carry weight:
 *   1. a gate that THROWS hides its module (fail closed). A menu entry that
 *      leads to a 403 is worse than no entry.
 *   2. the SUBNAV goes with it. A hidden module whose submenu still shipped
 *      would hand its URLs to precisely the people it was hidden from.
 *   3. ungated modules are untouched, so this cannot regress the rest of the app.
 *
 * Run: node --test "test/*.test.js"
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'ciab-module-visibility-secret';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// Shaped like the rows cybercore_module actually returns.
const MODULE_ROWS = [
  { key: 'cle',      name: 'Cyber Learning Environment', entry_url: '/cle/dashboard',   category: 'plugin', display_order: 1 },
  { key: 'crucible', name: 'The Crucible',               entry_url: '/crucible/dashboard', category: 'module', display_order: 2 },
  { key: 'ciab',     name: 'Clinic-in-a-Box',            entry_url: '/ciab/dashboard',  category: 'plugin', display_order: 3 },
];

stub(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), {
  cybercoreQuery: async () => ({ rows: MODULE_ROWS }),
});

// A stand-in for the real loader: the registry contract is what matters here,
// not the filesystem walk that populates it.
const gates = new Map();
stub(path.join(ROOT, 'src', 'module-loader.js'), {
  getAccessGates: () => gates,
  getAllSubnavs: () => ({
    cle: { items: [{ label: 'Courses', url: '/cle/courses' }] },
    crucible: { items: [{ label: 'Weekly', url: '/crucible/dashboard' }] },
    ciab: { items: [{ label: 'Dashboard', url: '/ciab/dashboard' }] },
  }),
});

const modulesRouter = require(path.join(ROOT, 'src', 'routes', 'modules.js'));

let ciabGate = async () => true;
gates.set('ciab', (req) => ciabGate(req));

let server, port;

before(async () => {
  const app = express();
  app.use(cookieParser());
  app.use('/api/modules', modulesRouter);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());
beforeEach(() => { ciabGate = async () => true; });

const tokenFor = (role) => jwt.sign({ sub: 'u1', email: 'a@b.c', role }, process.env.JWT_SECRET, { expiresIn: '1h' });

function get(query = '', { bearer = null, cookie = null } = {}) {
  const headers = {};
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (cookie) headers.Cookie = `token=${cookie}`;
  return new Promise((resolve, reject) => {
    const req = http.get({ port, path: `/api/modules${query}`, headers }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(raw) }));
    });
    req.on('error', reject);
  });
}

const keysOf = (body) => [...body.modules, ...body.plugins].map((m) => m.key);

test('a gated module is hidden when its gate says no', async () => {
  ciabGate = async () => false;
  const { body } = await get('', { bearer: tokenFor('student') });
  assert.ok(!keysOf(body).includes('ciab'), 'CIAB should not be listed');
  assert.ok(!('ciab' in body.subnavs), 'and neither should its submenu');
});

test('the same request shows it when the gate says yes', async () => {
  const { body } = await get('', { bearer: tokenFor('student') });
  assert.ok(keysOf(body).includes('ciab'));
  assert.ok('ciab' in body.subnavs);
});

test('a gate that THROWS hides its module — fail closed', async () => {
  // A menu entry that leads to a 403 is worse than no menu entry, and a gate
  // that cannot answer has not said yes.
  ciabGate = async () => { throw new Error('clinic_db unreachable'); };
  const { body } = await get('', { bearer: tokenFor('student') });
  assert.ok(!keysOf(body).includes('ciab'));
  assert.ok(!('ciab' in body.subnavs));
});

test('one failing gate does not take the rest of the menu down', async () => {
  ciabGate = async () => { throw new Error('boom'); };
  const { status, body } = await get('', { bearer: tokenFor('student') });
  assert.strictEqual(status, 200);
  assert.deepStrictEqual(keysOf(body).sort(), ['cle', 'crucible']);
});

test('ungated modules are never filtered', async () => {
  ciabGate = async () => false;
  const { body } = await get('', { bearer: tokenFor('student') });
  assert.ok(keysOf(body).includes('crucible'));
  assert.ok(keysOf(body).includes('cle'));
  assert.ok('crucible' in body.subnavs);
  assert.ok('cle' in body.subnavs);
});

test('the endpoint still answers an anonymous request', async () => {
  // optionalAuth, not authenticateToken: the payload is module names and menu
  // labels, and requiring a token would break the pre-login shell. The gate
  // simply sees no user and says no.
  ciabGate = async (req) => !!req.user;
  const { status, body } = await get();
  assert.strictEqual(status, 200);
  assert.ok(!keysOf(body).includes('ciab'));
  assert.ok(keysOf(body).includes('crucible'), 'ungated modules still list');
});

test('the gate receives the request, so it can read the user and the query', async () => {
  let seen = null;
  ciabGate = async (req) => { seen = { role: req.user && req.user.role, view: req.query.view }; return true; };
  await get('?view=student', { bearer: tokenFor('instructor') });
  assert.deepStrictEqual(seen, { role: 'instructor', view: 'student' });
});

test('the session cookie authenticates as well as the header', async () => {
  // Page navigations only carry the cookie, so a header-only implementation
  // would make every gated module vanish on a plain navigation.
  let sawUser = false;
  ciabGate = async (req) => { sawUser = !!req.user; return true; };
  await get('', { cookie: tokenFor('student') });
  assert.strictEqual(sawUser, true);
});

test('categories stay separated after filtering', async () => {
  const { body } = await get('', { bearer: tokenFor('admin') });
  assert.deepStrictEqual(body.modules.map((m) => m.key), ['crucible']);
  assert.deepStrictEqual(body.plugins.map((m) => m.key).sort(), ['ciab', 'cle']);
});
