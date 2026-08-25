/**
 * ciab-gate-scope.test.js — the CIAB enrollment gate must gate CIAB, and
 * nothing else.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * ciab/routes/api.js is mounted at '/' by the plugin loader (manifest.json:
 * mountPath '/'), so a `router.use('/api', ...)` inside it matches EVERY
 * /api/* request in the entire application — not merely CIAB's own.
 *
 * That was harmless while the chain was authenticateToken + checkSchedule +
 * clinicApiRoutes, because all three call next() for a normal signed-in user
 * and the request fell through to whoever actually owned the path. Adding
 * requireCiabAccess to that mount changed it into a chain that TERMINATES with
 * a 403, and a student on no CIAB roster was locked out of:
 *
 *     GET /api/cle/my/overview      the hub's "My Courses" panel
 *     GET /api/cle/courses/...      every CLE course route
 *     ...and any other plugin loaded after ciab
 *
 * Plugin load order is readdir order, so `ciab` sorts before `cle` and wins.
 * Core routes escaped only because server.js registers them before
 * moduleLoader.loadAll(). The student saw "Could not load your courses:
 * Clinic-in-a-Box is only available to students an instructor has enrolled."
 *
 * The gate now sits on CIAB-OWNED PREFIXES, and clinic-api.js — which is
 * mounted at the bare /api and owns five paths — carries it per route.
 *
 * Run: node --test "test/*.test.js"
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'ciab-gate-scope-secret';
process.env.CIAB_ENROLLMENT_CACHE_MS = '0';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const express = require('express');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

let enrolled = false;

// A COMPLETE db stub, not just query(). Some CIAB handlers reach for `pool`
// directly, and a handler that throws prints a stack trace — which, run under
// `node --test` with the rest of the suite, corrupts the runner's IPC channel
// and fails the whole FILE rather than an assertion.
// Path-aware: the enrollment probe gets the yes/no this test is steering, and
// every other statement gets a benign row so the handler behind the gate can
// render instead of throwing. A staff request bypasses the gate and DOES reach
// those handlers.
const fakeQuery = async (sql) => {
  if (/ciab_enrollment/.test(String(sql))) {
    return enrolled ? { rows: [{ x: 1 }], rowCount: 1 } : { rows: [], rowCount: 0 };
  }
  return { rows: [{ count: '0' }], rowCount: 1 };
};
const fakePool = { query: fakeQuery, connect: async () => ({ query: fakeQuery, release() {} }) };
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: fakeQuery,
  getPool: () => fakePool,
  setPool: () => {},
  pool: fakePool,
});

// Routing is what is under test. The schedule window is a separate gate with
// its own reasons to refuse, and letting the real one run against stub data
// just adds noise.
stub(path.join(CIAB, 'middleware', 'schedule.js'), {
  checkSchedule: (req, res, next) => next(),
});
stub(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: async () => ({ rows: [] }) });

// Only the shape matters here; the real generators are irrelevant to routing.
stub(path.join(CIAB, 'ai', 'profile'), { generateProfile: async () => ({}) });
stub(path.join(ROOT, 'src', 'utils', 'llm-client.js'), {
  isConfigured: () => false, cachedSystem: (s) => s, generate: async () => ({ text: '' }),
});

// WHAT IS UNDER TEST is the MOUNT BLOCK in routes/api.js -- which prefixes
// carry requireCiabAccess and which do not. The leaf routers are stubbed with
// trivial ones that answer 200, for two reasons:
//
//   1. Requiring the real ones drags in the profile generator, PDFKit, the
//      Anthropic SDK and the batch deployer. Under the full suite's concurrency
//      that was heavy enough to take the child process down mid-message, which
//      surfaces as "Unable to deserialize cloned data" -- a whole-FILE failure
//      with no assertion attached to it.
//   2. A leaf that throws on stub data produces noise that has nothing to do
//      with routing, and can mask the thing being asserted.
//
// The chain each prefix is mounted with is real, which is the whole point.
const leaf = (name) => {
  const r = express.Router({ mergeParams: true });
  r.all(/.*/, (req, res) => res.json({ ok: true, router: name }));
  return r;
};
for (const name of [
  'profiles', 'progress', 'interview', 'instructor', 'intake-form',
  'real-client-intake', 'intakes', 'clinic-risk-assessment', 'cis-ram',
  'profile-deploy', 'sections', 'section-roster',
]) {
  stub(path.join(CIAB, 'routes', `${name}.js`), leaf(name));
}

// clinic-api.js stays REAL: it is the file mounted at the bare /api, so its
// per-route gating is exactly what the regression is about.
stub(path.join(ROOT, 'src', 'utils', 'llm-client.js'), {
  isConfigured: () => false, cachedSystem: (x) => x, generate: async () => ({ text: '' }),
});
stub(path.join(CIAB, 'ai', 'profile'), { generateProfile: async () => ({}) });

const ciabApiRouter = require(path.join(CIAB, 'routes', 'api.js'));

let server, port;

before(async () => {
  const app = express();
  app.use(express.json());

  // EXACTLY the real mount: manifest.json puts this router at '/'.
  app.use('/', ciabApiRouter);

  // A stand-in for every plugin loaded AFTER ciab. In production this is the
  // CLE plugin, whose routes serve the hub's My Courses panel.
  app.get('/api/cle/my/overview', (req, res) => res.json({ courses: ['CYBR 480'] }));
  app.get('/api/cle/courses', (req, res) => res.json({ courses: [] }));
  app.get('/api/some-other-plugin/thing', (req, res) => res.json({ ok: true }));

  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());
beforeEach(() => { enrolled = false; });

const tokenFor = (role) => jwt.sign({ sub: 'u1', email: 'a@b.c', role }, process.env.JWT_SECRET, { expiresIn: '1h' });

function get(pathname, role = 'student') {
  return new Promise((resolve, reject) => {
    const req = http.get({
      port, path: pathname, headers: { Authorization: `Bearer ${tokenFor(role)}` },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(raw); } catch (_) { /* not JSON */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
  });
}

test('a student on no CIAB roster can still load their CLE courses', async () => {
  // The exact failure a student reported: the hub's My Courses panel showing
  // "Could not load your courses: Clinic-in-a-Box is only available to
  // students an instructor has enrolled."
  const res = await get('/api/cle/my/overview');
  assert.strictEqual(res.status, 200,
    'CIAB must not answer for a path it does not own');
  assert.deepStrictEqual(res.json, { courses: ['CYBR 480'] });
});

test('no CIAB error text ever reaches a non-CIAB route', async () => {
  for (const p of ['/api/cle/courses', '/api/some-other-plugin/thing']) {
    const res = await get(p);
    assert.strictEqual(res.status, 200, `${p} should be untouched`);
    assert.ok(!res.json.code, `${p} answered with a CIAB error: ${JSON.stringify(res.json)}`);
  }
});

test('an unknown /api path 404s rather than 403ing', async () => {
  // A path nobody owns must fall through to Express's own 404. Answering 403
  // would tell an unauthenticated scanner that CIAB exists, and would break
  // any route added later by a plugin that loads after this one.
  const res = await get('/api/nothing-here-at-all');
  assert.strictEqual(res.status, 404);
});

test('CIAB\'s own routes ARE still gated', async () => {
  // The regression fix must not have simply removed the gate.
  const gated = ['/api/profiles', '/api/progress', '/api/interview', '/api/intake-form'];
  for (const p of gated) {
    const res = await get(p);
    assert.strictEqual(res.status, 403, `${p} should refuse a non-enrolled student`);
    assert.strictEqual(res.json.code, 'CIAB_NOT_ENROLLED', `${p} should say why`);
  }
});

test('an enrolled student reaches CIAB\'s own routes', async () => {
  enrolled = true;
  const res = await get('/api/profiles');
  assert.notStrictEqual(res.status, 403, 'an enrolled student must get past the gate');
});

test('instructors and admins are never blocked anywhere', async () => {
  for (const role of ['instructor', 'admin']) {
    assert.strictEqual((await get('/api/cle/my/overview', role)).status, 200);
    assert.notStrictEqual((await get('/api/profiles', role)).status, 403);
  }
});

test('the catch-all\'s own expensive route is still gated', async () => {
  // /api/generate mints a profile through the LLM. It lives in clinic-api.js,
  // which shares the bare /api mount with the rest of the application — so it
  // carries the gate PER ROUTE. If that ever regresses to a router.use(), the
  // three tests above go red with it.
  const post = (role) => new Promise((resolve, reject) => {
    const body = JSON.stringify({});
    const req = http.request({
      port, path: '/api/generate', method: 'POST',
      headers: {
        Authorization: `Bearer ${tokenFor(role)}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => { let j = null; try { j = JSON.parse(raw); } catch (_) {} resolve({ status: res.statusCode, json: j }); });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });

  const student = await post('student');
  assert.strictEqual(student.status, 403);
  assert.strictEqual(student.json.code, 'CIAB_NOT_ENROLLED');

  enrolled = true;
  assert.notStrictEqual((await post('student')).status, 403);
});

test('the open endpoints stay open to any signed-in user', async () => {
  // /my-sections answering [] is more useful than a 403 to somebody asking
  // which sections they are on; /config and /health disclose nothing.
  for (const p of ['/api/my-sections', '/api/config']) {
    const res = await get(p);
    assert.notStrictEqual(res.status, 403, `${p} should not be enrollment-gated`);
  }
});
