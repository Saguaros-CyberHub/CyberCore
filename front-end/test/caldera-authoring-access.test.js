/**
 * caldera-authoring-access.test.js — who may reach the Caldera AUTHORING
 * console, and the proof that the console is not published without a gate.
 *
 * ############################################################################
 * # NO CALDERA SERVER HAS EVER BEEN RUN AGAINST THIS CODE. Nothing here      #
 * # proves the authoring VM works; the liveness probe is driven by an        #
 * # injected transport. What IS proved is everything on this side of the     #
 * # seam: who gets a 2xx, who gets a 401/403, what the deny response         #
 * # contains, and that the Caddyfile in this repo actually asks.             #
 * ############################################################################
 *
 * WHY THIS FILE IS HALF SOURCE-TEXT GATE
 * ----------------------------------------------------------------------------
 * The authorization decision lives in TWO places that cannot see each other:
 *
 *   - config/caddy/Caddyfile, which must ASK the app before proxying anything
 *     to the authoring VM; and
 *   - front-end/src/routes/caldera-authoring.js, which must ANSWER correctly.
 *
 * A behavioural test can only exercise the second. And the failure mode that
 * actually matters is entirely in the first: somebody adds `reverse_proxy` for
 * /caldera* while debugging, drops the forward_auth block, and the result is an
 * adversary authoring console published on the public internet behind nothing
 * but Caldera's own shared, baked, static password — with every test in this
 * repository still green, because the app is answering exactly as designed and
 * nobody is asking it.
 *
 * So §3 parses the Caddyfile into its site blocks and asserts, per block, that
 * the caldera route exists AND carries forward_auth AND that its `uri` is the
 * very path front-end/src/server.js mounts. That last one is not pedantry: a
 * forward_auth pointed at a path that answers 200 unauthenticated — a static
 * file, a health check, /api/site-config — allows EVERY request with no error
 * anywhere, which is the quietest possible way to lose this control.
 *
 * Run: node --test front-end/test/caldera-authoring-access.test.js  (or npm test)
 */

'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');
const CADDYFILE = path.join(REPO, 'config', 'caddy', 'Caddyfile');

// The gate audits its 403s through utils/audit, which opens a pg Pool at
// require time. Stubbed before the router is required so this suite touches no
// database and leaves no handle open. `calls` doubles as the assertion that a
// denied student is actually recorded.
const auditCalls = [];
(function stubAudit() {
  const p = require.resolve(path.join(ROOT, 'src', 'utils', 'audit.js'));
  require.cache[p] = {
    id: p,
    filename: p,
    loaded: true,
    exports: { log: (entry) => { auditCalls.push(entry); return Promise.resolve(); } },
  };
})();

// authenticate() reads process.env.JWT_SECRET at CALL time, so setting it here
// is enough and no require-cache game is needed for it.
process.env.JWT_SECRET = 'caldera-authoring-test-secret';

// REQUIRED, not decoration. The gate now mints a signed SSO token before it is
// allowed to write any 2xx (see the GHSA-7r4p-vjf4-gxv4 note in
// src/routes/caldera-authoring.js), and minting FAILS CLOSED when
// CALDERA_SSO_SECRET is missing or under 32 bytes — an allow becomes a 503.
// Without this line every "an instructor is allowed" assertion below would fail
// for a reason that has nothing to do with what it is testing. The token
// itself, and the fail-closed behaviour when this is absent, are the subject of
// test/caldera-sso.test.js.
process.env.CALDERA_SSO_SECRET = 'caldera-authoring-access-test-sso-secret-0123456789';

const calderaAuthoring = require(path.join(ROOT, 'src', 'routes', 'caldera-authoring.js'));

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/** What the injected transport does on the next /status probe. */
let PROBE = async () => ({ status: 200 });

let server;
let port;

before(async () => {
  const app = express();
  // cookieParser BEFORE the router, exactly as src/server.js orders it — a
  // browser navigation carries the session in a cookie and nothing else, so
  // without this the whole point of the endpoint is untested.
  app.use(cookieParser());
  app.use(
    calderaAuthoring.MOUNT_PATH,
    calderaAuthoring.createCalderaAuthoringRouter({ fetch: (...args) => PROBE(...args) })
  );
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

after(() => server && server.close());

function token(claims) {
  return jwt.sign(claims, process.env.JWT_SECRET, { expiresIn: '1h' });
}

const STUDENT = { sub: 'dddddddd-dddd-dddd-dddd-dddddddddddd', email: 's@x.edu', role: 'student' };
const INSTRUCTOR = { sub: 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', email: 'i@x.edu', role: 'instructor' };
const ADMIN = { sub: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', email: 'a@x.edu', role: 'admin' };

/** A page navigation: the session travels as a cookie, never as a header. */
async function asBrowser(p, claims) {
  const headers = claims ? { cookie: `token=${token(claims)}` } : {};
  const res = await fetch(`http://127.0.0.1:${port}${p}`, { headers, redirect: 'manual' });
  return { status: res.status, text: await res.text(), headers: res.headers };
}

/** An API call: Authorization: Bearer, the way the rest of the app is driven. */
async function asApi(p, claims) {
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    headers: { authorization: `Bearer ${token(claims)}` },
    redirect: 'manual',
  });
  return { status: res.status, text: await res.text(), headers: res.headers };
}

const AUTHORIZE = `${calderaAuthoring.MOUNT_PATH}/authorize`;
const STATUS = `${calderaAuthoring.MOUNT_PATH}/status`;

// ---------------------------------------------------------------------------
// §1 The gate — the decision Caddy's forward_auth reads
// ---------------------------------------------------------------------------

test('anonymous is DENIED — no cookie, no header, no session', async () => {
  const { status } = await asBrowser(AUTHORIZE, null);
  assert.strictEqual(status, 401);
  assert.ok(status < 200 || status > 299,
    'forward_auth forwards to Caldera on ANY 2xx — a deny must never land in that range');
});

test('a student is DENIED even though they hold a perfectly valid session', async () => {
  const { status } = await asBrowser(AUTHORIZE, STUDENT);
  assert.strictEqual(status, 403);
});

test('an INSTRUCTOR is allowed, from a cookie alone (the browser navigation case)', async () => {
  const { status, headers } = await asBrowser(AUTHORIZE, INSTRUCTOR);
  assert.strictEqual(status, 204);
  assert.ok(status >= 200 && status < 300, 'forward_auth only proxies on a 2xx');
  // A 2xx with no identity header is the whole of GHSA-7r4p-vjf4-gxv4: Caddy
  // copies nothing and the CLIENT's X-CyberCore-Auth rides through to Caldera.
  // Asserted properly in test/caldera-sso.test.js; asserted here too so the
  // pairing cannot be broken by an edit to this file alone.
  assert.ok(headers.get('x-cybercore-auth'), 'the ALLOW carried no signed token');
});

test('an ADMIN is allowed', async () => {
  const { status } = await asBrowser(AUTHORIZE, ADMIN);
  assert.strictEqual(status, 204);
});

test('a bearer header works too — the gate is not cookie-only', async () => {
  assert.strictEqual((await asApi(AUTHORIZE, INSTRUCTOR)).status, 204);
  assert.strictEqual((await asApi(AUTHORIZE, STUDENT)).status, 403);
});

test('a HALF-FINISHED sign-in is not a session', async () => {
  // A stage token is signed with the same secret and carries the account's real
  // role, so a hand-rolled token check would accept it and let somebody who
  // knows an instructor's password — but not their second factor — into the
  // authoring console. Reusing authenticate() is what makes this free.
  const staged = jwt.sign({ ...INSTRUCTOR, stage: 'mfa' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const res = await fetch(`http://127.0.0.1:${port}${AUTHORIZE}`, {
    headers: { cookie: `token=${staged}` },
  });
  assert.strictEqual(res.status, 401);
  assert.strictEqual(await res.text(), '');
});

test('a forged or expired token is denied, not 500', async () => {
  for (const bad of ['garbage', jwt.sign(INSTRUCTOR, 'the-wrong-secret')]) {
    const res = await fetch(`http://127.0.0.1:${port}${AUTHORIZE}`, {
      headers: { cookie: `token=${bad}` },
    });
    assert.strictEqual(res.status, 401);
    assert.strictEqual(await res.text(), '');
  }
});

test('THE LEAK: a deny carries NO body at all', async () => {
  // forward_auth hands the deny response back to the client verbatim, and the
  // stock requireRole body names the platform's role vocabulary and confirms
  // the prober holds a valid session:
  //   {"error":"Access denied...","requiredRoles":["instructor","admin"],"userRole":"student"}
  // On the internal :80 listener this endpoint is reachable from the lab
  // subnets, so that is a free structure hint for anyone with a lane shell.
  for (const who of [null, STUDENT]) {
    const { text, headers } = await asBrowser(AUTHORIZE, who);
    assert.strictEqual(text, '', 'the deny response must have an empty body');
    assert.strictEqual(headers.get('content-type'), null, 'and must not even declare a type');
    for (const leak of ['requiredRoles', 'instructor', 'admin', 'student', 'error', 'TOKEN']) {
      assert.ok(!text.includes(leak), `deny body leaked ${leak}`);
    }
  }
});

test('the ALLOW is not cacheable — a proxy must not hand it to the next person', async () => {
  const { headers } = await asBrowser(AUTHORIZE, INSTRUCTOR);
  assert.match(String(headers.get('cache-control') || ''), /no-store/);
});

test('a denied student is audited (silencing the body did not silence the record)', async () => {
  auditCalls.length = 0;
  // A DIFFERENT student id: auditDenial() dedupes per (user, route) for a
  // minute, and the earlier deny tests already burned STUDENT's slot. That
  // dedupe is deliberate — it is what stops a client retrying in a loop from
  // flooding the table — so the test works with it rather than around it.
  await asBrowser(AUTHORIZE, { ...STUDENT, sub: 'cccccccc-cccc-cccc-cccc-cccccccccccc' });
  const denial = auditCalls.find((c) => c && c.action === 'access.denied');
  assert.ok(denial, 'requireRole must still write its access.denied row');
  assert.strictEqual(denial.status, 'denied');
});

// ---------------------------------------------------------------------------
// §2 /status — "authoring is not set up" instead of a dead link
// ---------------------------------------------------------------------------

function withUpstream(value, fn) {
  const prevUrl = process.env.CALDERA_AUTHORING_URL;
  const prevUp = process.env.CALDERA_AUTHORING_UPSTREAM;
  delete process.env.CALDERA_AUTHORING_URL;
  if (value == null) delete process.env.CALDERA_AUTHORING_UPSTREAM;
  else process.env.CALDERA_AUTHORING_UPSTREAM = value;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (prevUrl === undefined) delete process.env.CALDERA_AUTHORING_URL;
      else process.env.CALDERA_AUTHORING_URL = prevUrl;
      if (prevUp === undefined) delete process.env.CALDERA_AUTHORING_UPSTREAM;
      else process.env.CALDERA_AUTHORING_UPSTREAM = prevUp;
    });
}

test('/status is instructor-gated like the console itself', async () => {
  assert.strictEqual((await asBrowser(STATUS, null)).status, 401);
  assert.strictEqual((await asBrowser(STATUS, STUDENT)).status, 403);
});

test('unconfigured reports configured:false and does NOT probe a placeholder host', async () => {
  await withUpstream(null, async () => {
    let probed = false;
    PROBE = async () => { probed = true; return { status: 200 }; };
    const { status, text } = await asBrowser(STATUS, INSTRUCTOR);
    assert.strictEqual(status, 200);
    const body = JSON.parse(text);
    assert.strictEqual(body.configured, false);
    assert.strictEqual(body.reachable, null,
      'null, not false — "nobody set this up" is a different fix from "the box is down"');
    assert.strictEqual(body.detail, 'not_configured');
    assert.strictEqual(body.path, '/caldera', 'the UI must not hard-code the Caddy path');
    assert.strictEqual(probed, false, 'a placeholder hostname must never be dialled');
  });
});

test('configured and answering → reachable:true, whatever status Caldera returns', async () => {
  await withUpstream('caldera-authoring.lab.test:8888', async () => {
    let asked = null;
    // 401 is the realistic answer: the probe carries no credential by design,
    // and Caldera's own login form sits there.
    PROBE = async (url) => { asked = url; return { status: 401 }; };
    const body = JSON.parse((await asBrowser(STATUS, INSTRUCTOR)).text);
    assert.strictEqual(body.configured, true);
    assert.strictEqual(body.reachable, true);
    assert.strictEqual(body.http_status, 401);
    assert.strictEqual(body.upstream, 'caldera-authoring.lab.test:8888');
    assert.strictEqual(asked, 'http://caldera-authoring.lab.test:8888/',
      'a bare host:port is the documented form and must be given a scheme here');
  });
});

test('configured and dead → reachable:false, with a CODE and not an error string', async () => {
  await withUpstream('caldera-authoring.lab.test:8888', async () => {
    const err = new Error('connect ECONNREFUSED 100.100.10.60:8888');
    PROBE = async () => { throw err; };
    const body = JSON.parse((await asBrowser(STATUS, INSTRUCTOR)).text);
    assert.strictEqual(body.reachable, false);
    assert.strictEqual(body.detail, 'unreachable');
    const raw = JSON.stringify(body);
    assert.ok(!raw.includes('ECONNREFUSED') && !raw.includes('stack'),
      'undici error text carries the resolved address and the failing syscall; this body '
      + 'renders in a browser');
  });
});

test('a malformed upstream is a configuration report, not a 500', async () => {
  await withUpstream('http://:::nonsense', async () => {
    PROBE = async () => { throw new Error('should not be called'); };
    const { status, text } = await asBrowser(STATUS, INSTRUCTOR);
    assert.strictEqual(status, 200);
    const body = JSON.parse(text);
    assert.strictEqual(body.configured, false);
    assert.strictEqual(body.detail, 'malformed_upstream');
  });
});

// ---------------------------------------------------------------------------
// §3 The Caddyfile gate — the half no behavioural test can see
// ---------------------------------------------------------------------------

/**
 * Split the Caddyfile into its top-level site blocks.
 *
 * Two things make a naive brace scan wrong here, and both are in this file:
 *   - `{$CYBERHUB_HOST}` is an environment placeholder, not a block. Its braces
 *     are replaced with «» first, or every site header opens a phantom block.
 *   - `#` comments contain braces and the words this test greps for, so they go
 *     before the scan. That also means a caldera proxy that is merely DESCRIBED
 *     in a comment cannot satisfy the assertions below.
 */
function siteBlocks(raw) {
  const src = raw
    .replace(/\{\$([^}]*)\}/g, (_m, name) => `«${name}»`)
    .split(/\r?\n/)
    .map((line) => line.replace(/(^|\s)#.*$/, '$1'))
    .join('\n');

  const blocks = [];
  let depth = 0;
  let open = -1;
  let headerFrom = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '{') {
      if (depth === 0) open = i;
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0) {
        blocks.push({ header: src.slice(headerFrom, open).trim(), body: src.slice(open + 1, i) });
        headerFrom = i + 1;
      }
    }
  }
  // The global options block has an empty header and is not a site.
  return blocks.filter((b) => b.header.length > 0);
}

/**
 * The body of the first directive block matching `re`, brace-balanced.
 *
 * A lazy /\{([\s\S]*?)\}/ is wrong here and fails in exactly the way that
 * matters: it stops at the closing brace of the NESTED forward_auth block, so
 * the reverse_proxy line that follows falls outside the match and the handle
 * looks like it proxies nothing.
 */
function directiveBlock(body, re) {
  const at = body.search(re);
  if (at < 0) return null;
  const open = body.indexOf('{', at);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < body.length; i++) {
    if (body[i] === '{') depth++;
    else if (body[i] === '}') {
      depth--;
      if (depth === 0) return body.slice(open + 1, i);
    }
  }
  return null;
}

test('THE POINT OF THIS FILE: /caldera is proxied in BOTH site blocks, and NEITHER is ungated', () => {
  const blocks = siteBlocks(fs.readFileSync(CADDYFILE, 'utf8'));

  const findOne = (needle) => {
    const hits = blocks.filter((b) => b.header.includes(needle));
    assert.strictEqual(hits.length, 1, `expected exactly one site block for ${needle}`);
    return hits[0];
  };
  const publicSite = findOne('CYBERHUB_HOST');   // «CYBERHUB_HOST» after substitution
  const internalSite = findOne('http://:80');

  // Guacamole's own proxy must survive any edit to this file.
  for (const [name, block] of [['public site', publicSite], ['internal :80 listener', internalSite]]) {
    assert.match(block.body, /handle\s+\/guacamole\*/, `${name}: the guacamole handle went missing`);
  }

  // THE CONSOLE IS ON ITS OWN HOSTNAME, NOT A PATH. magma is an SPA that
  // bootstraps from GET /api/v2/config/main at the ORIGIN ROOT, so it uses the
  // default base for the one call that would have told it a different base — a
  // subpath mount was tried and the SPA 404'd its own API, rendering a login
  // form that looked like an auth failure and was not.
  const serving = blocks.filter((b) => /\bimport\s+caldera_gate\b/.test(b.body));
  assert.ok(serving.length >= 2,
    `expected >= 2 site blocks serving the console, found ${serving.length}. Two are needed because a `
    + 'Cloudflare tunnel may deliver either http:// or https:// to this container.');
  for (const b of serving) {
    assert.match(b.header, /«CALDERA_HOST»/,
      `site block \`${b.header}\` imports the gate but is not the console's own hostname`);
  }

  // THE GATE ITSELF, defined once and imported. This is the assertion the file
  // exists for: without forward_auth the public site would publish an adversary
  // authoring console behind nothing but Caldera's own login form.
  const snippet = blocks.find((b) => /^\(caldera_gate\)$/.test(b.header.trim()));
  assert.ok(snippet, 'no `(caldera_gate)` snippet — the gate must be defined once and imported');
  assert.match(snippet.body, /forward_auth\s+\S+\s*\{[^}]*\}/, 'the gate snippet has no forward_auth');
  assert.match(snippet.body, /reverse_proxy/, 'the gate snippet proxies nothing');
  assert.match(snippet.body, /reverse_proxy\s+«CALDERA_AUTHORING_UPSTREAM:[^»]+»/,
    'the upstream must come from CALDERA_AUTHORING_UPSTREAM, never a literal');
  assert.ok(!/reverse_proxy\s+\d+\.\d+\.\d+\.\d+/.test(snippet.body),
    'a hard-coded IP for the authoring console');

  // And NOTHING may reach the upstream without going through it.
  for (const b of blocks) {
    if (/^\(caldera_gate\)$/.test(b.header.trim())) continue;
    assert.ok(!/reverse_proxy\s+«CALDERA_AUTHORING_UPSTREAM/.test(b.body),
      `site block \`${b.header}\` proxies to Caldera directly instead of importing the gate, so it `
      + 'never runs forward_auth');
  }
});

test('forward_auth points at the path server.js actually mounts', () => {
  // A forward_auth whose `uri` names a path that answers 200 unauthenticated
  // allows EVERY request, silently. So the two ends are compared directly.
  const caddy = fs.readFileSync(CADDYFILE, 'utf8');
  const uris = [...caddy.matchAll(/forward_auth[^{]*\{[^}]*?uri\s+(\S+)/g)].map((m) => m[1]);
  // ONE now, not two: the gate is defined once in the `(caldera_gate)` snippet
  // and imported by each serving site block, so there is a single forward_auth
  // to keep in step with the app. That every serving block imports it is
  // asserted in the test above.
  assert.ok(uris.length >= 1, 'the gate must name the authorize endpoint');
  for (const uri of uris) {
    assert.strictEqual(uri, calderaAuthoring.AUTHORIZE_PATH,
      'the Caddyfile asks a different path than the app answers on');
  }

  const serverSrc = fs.readFileSync(path.join(ROOT, 'src', 'server.js'), 'utf8');
  assert.ok(serverSrc.includes(`app.use('${calderaAuthoring.MOUNT_PATH}', calderaAuthoringRoutes)`),
    'server.js must mount the router on the prefix the Caddyfile asks for');
  assert.ok(calderaAuthoring.AUTHORIZE_PATH.startsWith(calderaAuthoring.MOUNT_PATH),
    'the authorize path must live under the mount');

  // Caddy hits this endpoint once per SUBREQUEST of a single-page app. A 429 is
  // non-2xx, which forward_auth reads as DENY — the console would appear to log
  // the instructor out mid-session.
  assert.ok(serverSrc.includes(`'${calderaAuthoring.AUTHORIZE_PATH}',`),
    'the forward_auth probe must be in RATE_LIMIT_SKIP_PATHS in server.js');
});

test('the console is an AUTHORING surface — the app never registers it as an engine', () => {
  // The E8 cluster gate has not passed. Authoring ships now because it touches
  // nothing in any lane; EXECUTION stays unreachable.
  const engines = require(path.join(ROOT, 'src', 'incident', 'engines'));
  assert.deepStrictEqual(engines.registeredEngines(), ['synthetic']);
  assert.throws(() => engines.engineFor('caldera'));

  const routeSrc = fs.readFileSync(
    path.join(ROOT, 'src', 'routes', 'caldera-authoring.js'), 'utf8'
  );
  const code = routeSrc.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  for (const forbidden of [/registerEngine/, /engineFor/, /dispatchRun/, /agentShellExec/, /resolveScopeTargets/]) {
    assert.ok(!forbidden.test(code),
      `the authoring route must not reach into dispatch (${forbidden})`);
  }
});
