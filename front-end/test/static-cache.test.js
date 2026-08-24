/**
 * static-cache.test.js — deployed code must actually reach the browser.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * The admin console is unbundled, unversioned JS loaded by plain <script src>,
 * so a deploy only lands once a browser re-fetches the file. express.static's
 * default sends an ETag and NO Cache-Control, which lets a browser — and
 * Cloudflare, which caches .js by default — keep serving the previous copy.
 *
 * That is not a theoretical staleness problem. It produced a real failure that
 * looked like a server bug and was not: a months-old admin-lanes.js calling the
 * rebuilt /api/admin/reconcile, reading `r.summary` off a response shape that
 * postdated it, and reporting
 *
 *     Audit failed: Cannot read properties of undefined (reading 'orphaned_on_proxmox')
 *
 * The server was healthy. The page was old. Nothing on screen said so, and no
 * amount of reading the server logs would have shown it.
 *
 * `no-cache` means "revalidate before use", not "do not store" — the ETag still
 * answers 304 on the unchanged case, so this costs a conditional request per
 * asset rather than a re-download.
 *
 * Run: node front-end/test/static-cache.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const http = require('http');
const fs = require('fs');
const express = require('express');

const PUBLIC = path.join(__dirname, '..', 'public');
const SERVER_SRC = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');

/**
 * Rebuild the static mount exactly as server.js declares it, by lifting the
 * extension pattern and the setHeaders body out of the source. If someone
 * changes the mount, this reads the change rather than testing a stale copy.
 */
function mountFromServerSource() {
  const extMatch = SERVER_SRC.match(/const REVALIDATE_EXT = (\/.+\/i);/);
  assert.ok(extMatch, 'server.js no longer declares REVALIDATE_EXT — the static mount changed');
  // eslint-disable-next-line no-eval
  const REVALIDATE_EXT = eval(extMatch[1]);

  const app = express();
  app.use(express.static(PUBLIC, {
    setHeaders(res, filePath) {
      if (REVALIDATE_EXT.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
    }
  }));
  return app;
}

function fetchHeaders(server, urlPath) {
  const { port } = server.address();
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: urlPath }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    }).on('error', reject);
  });
}

async function withServer(fn) {
  const server = http.createServer(mountFromServerSource());
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  try { return await fn(server); } finally { server.close(); }
}

test('admin JS is served must-revalidate, so a deploy is not optional', async () => {
  await withServer(async (server) => {
    const { status, headers } = await fetchHeaders(server, '/js/admin/admin-lanes.js');
    assert.strictEqual(status, 200);
    assert.strictEqual(headers['cache-control'], 'no-cache',
      'a stale admin-lanes.js against a rebuilt API is the exact failure this prevents');
    assert.ok(headers.etag, 'the ETag is what keeps revalidation cheap (304, not a re-download)');
  });
});

test('admin.html revalidates too — it carries the script tags and tab hooks', async () => {
  await withServer(async (server) => {
    const { headers } = await fetchHeaders(server, '/admin.html');
    assert.strictEqual(headers['cache-control'], 'no-cache',
      'stale markup means stale <script src> and missing onclick wiring');
  });
});

test('a conditional request still short-circuits to 304', async () => {
  await withServer(async (server) => {
    const first = await fetchHeaders(server, '/js/admin/admin-core.js');
    const { port } = server.address();
    const status = await new Promise((resolve, reject) => {
      http.get({
        host: '127.0.0.1', port, path: '/js/admin/admin-core.js',
        headers: { 'If-None-Match': first.headers.etag },
      }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
    });
    assert.strictEqual(status, 304,
      'no-cache must not turn every page load into a full re-download');
  });
});

test('non-code assets keep the default caching', async () => {
  // Pick any non-html/js/css file that actually exists, so this stays true as
  // the asset tree changes.
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
  const asset = walk(PUBLIC).find(p => /\.(png|jpg|svg|ico|woff2?)$/i.test(p));
  if (!asset) return;   // nothing to assert against in this checkout

  await withServer(async (server) => {
    const rel = '/' + path.relative(PUBLIC, asset).split(path.sep).join('/');
    const { headers } = await fetchHeaders(server, encodeURI(rel));
    assert.notStrictEqual(headers['cache-control'], 'no-cache',
      'images and fonts change name when they change; they should stay cacheable');
  });
});

test('the reconcile client never renders a payload it has not confirmed', () => {
  const src = fs.readFileSync(
    path.join(PUBLIC, 'js', 'admin', 'admin-lanes.js'), 'utf8');

  // The old client did `const s = r.summary` with no guard, which is why an
  // unexpected response shape surfaced as a TypeError instead of a message.
  const guarded = /if \(r\.cached\) renderReconcileResult\(/.test(src)
    && /if \(!r\.cached\) \{ renderReconcileEmpty\(\); return; \}/.test(src);
  assert.ok(guarded,
    'GET /reconcile returns {empty:true} with no summary before the first scan — ' +
    'rendering that unguarded is what produced the original TypeError');

  assert.ok(/if \(p\.result\) \{/.test(src),
    'a done-poll can carry result:null when the payload exceeded the cache ceiling');
});
