/**
 * site-config-route.test.js — GET /api/site-config answers at the path the
 * whole product actually calls.
 *
 * The handler was defined inside routes/admin/settings.js, which server.js
 * mounts at '/api/admin'. Its real address was therefore /api/admin/site-config
 * while login.html, register.html, activate.html, hub.html,
 * module-placeholder.html and Layout.loadSiteBranding() all fetched
 * /api/site-config. Every one of them 404'd.
 *
 * Nothing reported it. Each caller guards on `response.ok` and falls back to a
 * hard-coded default, so a configured site name, logo and description simply
 * never appeared -- and an admin who had loaded the console once stayed pinned
 * to the cached "<name> Administration" on every page, because the fetch that
 * would have corrected it returned no body.
 *
 * The mount is the assertion. A test that reached into the router directly
 * would have passed happily throughout the entire bug.
 *
 * Run: node --test front-end/test/site-config-route.test.js   (or npm test)
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const express = require('express');

const ROOT = path.join(__dirname, '..');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// The router destructures cybercoreQuery at require time, so the stub has to
// be a stable function that delegates -- swapping the export afterwards would
// be invisible to it, and the swap would silently do nothing.
let ROWS = [];
let QUERY = async () => ({ rows: ROWS, rowCount: ROWS.length });
stub(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), {
  cybercoreQuery: (...args) => QUERY(...args)
});

const siteConfigRoutes = require(path.join(ROOT, 'src', 'routes', 'site-config.js'));

let server, port;

before(async () => {
  const app = express();
  // Mounted exactly as server.js mounts it. Any drift here and the test stops
  // proving the thing that broke.
  app.use('/api', siteConfigRoutes);
  server = http.createServer(app);
  await new Promise(r => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());

const get = async p => {
  const res = await fetch(`http://127.0.0.1:${port}${p}`);
  return { status: res.status, body: res.status === 200 ? await res.json() : null };
};

test('THE BUG: /api/site-config responds, unauthenticated', async () => {
  ROWS = [];
  const { status, body } = await get('/api/site-config');
  assert.strictEqual(status, 200, 'no Authorization header is sent by login.html');
  assert.strictEqual(body.site_name, 'CyberHub');
});

test('configured branding is returned, not the defaults', async () => {
  ROWS = [
    { key: 'site_name', value: 'CyberHub AZ' },
    { key: 'site_logo_url', value: '/img/site-logo.svg' },
    { key: 'site_favicon_url', value: '/img/site-logo.png' },
    { key: 'site_description', value: 'University of Arizona Cyber Training Platform' }
  ];
  const { body } = await get('/api/site-config');
  assert.strictEqual(body.site_name, 'CyberHub AZ');
  assert.strictEqual(body.site_logo_url, '/img/site-logo.svg');
  assert.strictEqual(body.site_favicon_url, '/img/site-logo.png');
  assert.strictEqual(body.site_description, 'University of Arizona Cyber Training Platform');
});

test('a database that is down yields defaults, not a 500', async () => {
  // Branding is cosmetic; the sign-in page must still render if the DB is out.
  const good = QUERY;
  QUERY = async () => { throw new Error('ECONNREFUSED'); };
  try {
    const { status, body } = await get('/api/site-config');
    assert.strictEqual(status, 200);
    assert.strictEqual(body.site_name, 'CyberHub');
    assert.strictEqual(body.site_logo_url, null);
  } finally {
    QUERY = good;
  }
});

test('self_registration_enabled reflects the env flag, never a settings row', async () => {
  // It gates a route. A route's availability must not depend on a row anyone
  // with the admin console can edit.
  ROWS = [{ key: 'self_registration_enabled', value: 'true' }];
  const original = process.env.ALLOW_SELF_REGISTRATION;
  try {
    delete process.env.ALLOW_SELF_REGISTRATION;
    assert.strictEqual((await get('/api/site-config')).body.self_registration_enabled, false);
    process.env.ALLOW_SELF_REGISTRATION = 'true';
    assert.strictEqual((await get('/api/site-config')).body.self_registration_enabled, true);
  } finally {
    if (original === undefined) delete process.env.ALLOW_SELF_REGISTRATION;
    else process.env.ALLOW_SELF_REGISTRATION = original;
  }
});

// ── The mount itself, which is what actually broke ──────────────────────────

test('server.js mounts the router at /api', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'server.js'), 'utf8');
  assert.match(src, /app\.use\('\/api',\s*siteConfigRoutes\)/,
    "the handler is only reachable at /api/site-config if it is mounted at '/api'");
});

test('it is registered before the plugin loader, or the CIAB catch-all eats it', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'server.js'), 'utf8');
  const mount = src.indexOf("app.use('/api', siteConfigRoutes)");
  const loadAll = src.search(/moduleLoader\.loadAll|loadAll\(/);
  assert.ok(mount > -1, 'mount present');
  if (loadAll > -1) {
    assert.ok(mount < loadAll,
      'CIAB mounts at / with an /api catch-all; core routes survive only by being registered first');
  }
});

test('every client fetch of the config points at a path the server serves', () => {
  // The regression in one line: the clients said /api/site-config and the
  // server said /api/admin/site-config, and nothing compared the two.
  const pub = path.join(ROOT, 'public');
  const files = [
    path.join(pub, 'login.html'), path.join(pub, 'register.html'),
    path.join(pub, 'activate.html'), path.join(pub, 'hub.html'),
    path.join(pub, 'module-placeholder.html'), path.join(pub, 'js', 'layout.js')
  ];
  const wanted = new Set();
  for (const f of files) {
    for (const m of fs.readFileSync(f, 'utf8').matchAll(/fetch\(\s*'(\/api\/[^']*site-config)'/g)) {
      wanted.add(m[1]);
    }
  }
  assert.ok(wanted.size > 0, 'the client code still fetches the config somewhere');
  assert.deepStrictEqual([...wanted], ['/api/site-config'],
    'every caller must use the one path server.js mounts');
});
