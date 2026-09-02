/**
 * caldera-sso.test.js — the SIGNED SSO TOKEN, both ends of it.
 *
 * ############################################################################
 * # WHAT THIS FILE PROVES, AND WHAT IT CANNOT.                               #
 * #                                                                          #
 * # PROVED: the token format, the MAC, expiry, the role rule, the path rule, #
 * # single use, the fail-closed behaviour of a missing or short key, and     #
 * # that infrastructure/caldera/login_handler.py agrees with                 #
 * # src/utils/caldera-sso.js on every one of them — the Python verifier is   #
 * # actually EXECUTED here (§5) against tokens this repo minted.             #
 * #                                                                          #
 * # NOT PROVED: that Caldera itself calls the login handler, or that Caddy   #
 * # copies the header. No Caldera has ever run against this code and the     #
 * # Caddyfile is asserted by test/caldera-authoring-access.test.js, not here.#
 * ############################################################################
 *
 * WHY THIS FILE IS MOSTLY BYPASS ATTEMPTS
 * ----------------------------------------------------------------------------
 * Caddy advisory GHSA-7r4p-vjf4-gxv4: forward_auth's `copy_headers` does not
 * strip a CLIENT-supplied copy of a copied header. If the authorize endpoint
 * answers 2xx without setting X-CyberCore-Auth, the browser's own value rides
 * through to the authoring console — the caller names their own identity. Every
 * stable Caddy from v2.10.0 is affected and docker-compose.yml pins the
 * floating `caddy:2-alpine` tag, so this is a live condition, not a historical
 * one.
 *
 * Two properties close it, and each has a test here that fails loudly:
 *
 *   1. THE GATE CANNOT ANSWER 2xx WITHOUT A FRESHLY MINTED TOKEN. §3 sweeps a
 *      matrix of requests — allowed, denied, misconfigured — and asserts that
 *      EVERY 2xx in the whole matrix carries a token that verifies, and that no
 *      two of them are the same token.
 *   2. A FORGED HEADER IS WORTHLESS. §1 and §2 are the reason: without
 *      CALDERA_SSO_SECRET, no attacker-chosen bytes verify.
 *
 * And the bypass this platform is uniquely exposed to gets its own section:
 * CyberCore has a Student View, the DRAWN role is genuinely rewritten to
 * 'student' (public/js/app.js keeps `user` apart from `realUser`, which is why
 * Auth.isRealInstructor() exists), and the preview is carried to the server as
 * `?view=student` — where server code DOES honour it
 * (ciab/utils/enrollment.js canSeeCiab). A query parameter that can change an
 * access decision is exactly the bypass this design exists to prevent, so §3
 * asserts both behaviourally and structurally that this endpoint never looks.
 *
 * Run: node --test front-end/test/caldera-sso.test.js   (or npm test)
 */

'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');
const LOGIN_HANDLER = path.join(REPO, 'infrastructure', 'caldera', 'login_handler.py');
const VECTORS_FILE = path.join(__dirname, 'fixtures', 'caldera-sso-vectors.json');
const PY_RUNNER = path.join(__dirname, 'fixtures', 'caldera-sso-python-runner.py');

// requireRole audits its 403s through utils/audit, which opens a pg Pool at
// require time. Stubbed before the router is required so this suite touches no
// database and leaves no handle open.
(function stubAudit() {
  const p = require.resolve(path.join(ROOT, 'src', 'utils', 'audit.js'));
  require.cache[p] = {
    id: p, filename: p, loaded: true,
    exports: { log: () => Promise.resolve() },
  };
})();

process.env.JWT_SECRET = 'caldera-sso-test-jwt-secret';

// A real 48-byte key. Long enough that the >= 32 floor is not accidentally the
// thing under test in every case; §1 varies it deliberately.
const SECRET = 'caldera-sso-test-secret-0123456789abcdefghij';
process.env.CALDERA_SSO_SECRET = SECRET;

const sso = require(path.join(ROOT, 'src', 'utils', 'caldera-sso.js'));
const calderaAuthoring = require(path.join(ROOT, 'src', 'routes', 'caldera-authoring.js'));

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/**
 * The handful of Redis commands the burn uses, with TTL bookkeeping so expiry
 * is simulated rather than waited for. Shaped exactly like the fake in
 * test/reconcile-job.test.js — same reasoning: an injected object cannot leak
 * into another suite the way a monkey-patched module can.
 */
function fakeRedis({ ready = true } = {}) {
  const store = new Map();
  const alive = (e) => e && (e.expiresAt === null || e.expiresAt > Date.now());
  const get = (k) => (alive(store.get(k)) ? store.get(k).value : (store.delete(k), null));
  return {
    isReady: ready,
    _store: store,
    _calls: [],
    _expire: (k) => { const e = store.get(k); if (e) e.expiresAt = Date.now() - 1; },
    async set(k, v, opts = {}) {
      this._calls.push({ key: k, opts });
      if (opts.NX && get(k) !== null) return null;
      const ttl = opts.PX ? opts.PX : (opts.EX ? opts.EX * 1000 : null);
      store.set(k, { value: v, expiresAt: ttl ? Date.now() + ttl : null });
      return 'OK';
    },
  };
}

let server;
let port;
let redis;

before(async () => {
  redis = fakeRedis();
  const app = express();
  // cookieParser BEFORE the routers, exactly as src/server.js orders it — a
  // browser navigation carries the session in a cookie and nothing else.
  app.use(cookieParser());
  app.use(
    calderaAuthoring.MOUNT_PATH,
    calderaAuthoring.createCalderaAuthoringRouter({ fetch: async () => ({ status: 401 }) })
  );
  app.use(
    calderaAuthoring.REDEEM_MOUNT_PATH,
    calderaAuthoring.createCalderaRedeemRouter({ redis })
  );
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

after(() => server && server.close());

const STUDENT = { sub: 'dddddddd-dddd-dddd-dddd-dddddddddddd', email: 's@x.edu', role: 'student' };
const INSTRUCTOR = { sub: 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', email: 'i@x.edu', role: 'instructor' };
const ADMIN = { sub: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', email: 'a@x.edu', role: 'admin' };

const session = (claims) => jwt.sign(claims, process.env.JWT_SECRET, { expiresIn: '1h' });

const AUTHORIZE = `${calderaAuthoring.MOUNT_PATH}/authorize`;

/** GET the gate the way Caddy's forward_auth subrequest does. */
async function authorize(p, claims, extraHeaders) {
  const headers = Object.assign({}, extraHeaders || {});
  if (claims) headers.cookie = `token=${session(claims)}`;
  const res = await fetch(`http://127.0.0.1:${port}${p}`, { headers, redirect: 'manual' });
  return { status: res.status, token: res.headers.get(sso.SSO_HEADER), text: await res.text() };
}

/** POST the burn the way the Caldera container does. */
async function redeem(bodyObj, tokenHeader) {
  const headers = { 'content-type': 'application/json' };
  if (tokenHeader !== undefined && tokenHeader !== null) headers[sso.SSO_HEADER] = tokenHeader;
  const res = await fetch(`http://127.0.0.1:${port}${calderaAuthoring.REDEEM_PATH}`, {
    method: 'POST', headers, body: JSON.stringify(bodyObj),
  });
  return { status: res.status, text: await res.text() };
}

/** Run fn with CALDERA_SSO_SECRET set to `value` (undefined = unset). */
async function withSecret(value, fn) {
  const prev = process.env.CALDERA_SSO_SECRET;
  if (value === undefined) delete process.env.CALDERA_SSO_SECRET;
  else process.env.CALDERA_SSO_SECRET = value;
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.CALDERA_SSO_SECRET;
    else process.env.CALDERA_SSO_SECRET = prev;
  }
}

/** Sign an arbitrary payload with the live key — the forger's best case. */
function handSign(payloadObj, secret = SECRET) {
  const p = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const si = `v1.${p}`;
  const mac = crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(si, 'ascii').digest();
  return `${si}.${mac.toString('base64url')}`;
}

// ===========================================================================
// §1 THE KEY — fail closed, in both directions
// ===========================================================================

test('mint THROWS when CALDERA_SSO_SECRET is unset — there is no default key', async () => {
  await withSecret(undefined, () => {
    assert.throws(
      () => sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }),
      (err) => err.code === 'SECRET_MISSING'
    );
  });
});

test('mint THROWS when the key is under 32 bytes, at exactly the boundary', async () => {
  await withSecret('x'.repeat(31), () => {
    assert.throws(
      () => sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }),
      (err) => err.code === 'SECRET_TOO_SHORT'
    );
  });
  await withSecret('x'.repeat(32), () => {
    assert.ok(sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }),
      '32 bytes is the floor, not one above it');
  });
});

test('a thrown key error never carries the key or its length', async () => {
  // These messages reach console.error in the route. "your key is 12 bytes" is
  // a free search-space hint.
  await withSecret('shhh-this-is-the-actual-key', () => {
    try {
      sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(!err.message.includes('shhh'), 'the message quoted the key');
      assert.ok(!/\b27\b/.test(err.message), 'the message quoted the key length');
    }
  });
});

test('VERIFY fails closed too — a missing key rejects rather than skipping the MAC', async () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  await withSecret(undefined, () => {
    assert.deepStrictEqual(sso.verifyToken(token, { path: '/caldera' }),
      { ok: false, reason: 'secret_missing' });
  });
  await withSecret('x'.repeat(20), () => {
    assert.deepStrictEqual(sso.verifyToken(token, { path: '/caldera' }),
      { ok: false, reason: 'secret_too_short' });
  });
});

test('the key is trimmed of exactly the four ASCII whitespace bytes, and no more', async () => {
  // A key delivered as CALDERA_SSO_SECRET=$(cat /etc/...) carries a newline;
  // Python's .strip() and JS's .trim() disagree on U+FEFF, so both sides trim a
  // fixed four-character set. If that drifts, tokens fail with 'bad_signature'
  // and nothing points at the cause.
  const base = 'k'.repeat(40);
  const a = await withSecret(base, () => sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera', }, { now: 1000, jti: 'a'.repeat(32) }));
  const b = await withSecret(` \t\r\n${base}\n\t `, () => sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }, { now: 1000, jti: 'a'.repeat(32) }));
  assert.strictEqual(a, b, 'surrounding ASCII whitespace must not change the key');

  const c = await withSecret(` ${base}`, () => sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }, { now: 1000, jti: 'a'.repeat(32) }));
  assert.notStrictEqual(a, c, 'a non-breaking space is KEY MATERIAL, not whitespace');
});

// ===========================================================================
// §2 THE TOKEN — every way to break one
// ===========================================================================

test('a valid token verifies, and carries exactly the five contract claims', () => {
  const token = sso.mintToken({ sub: INSTRUCTOR.sub, role: 'instructor', path: '/caldera' });
  const out = sso.verifyToken(token, { path: '/caldera/js/app.js' });
  assert.strictEqual(out.ok, true);
  assert.deepStrictEqual(Object.keys(out.payload).sort(), ['exp', 'jti', 'path', 'role', 'sub']);
  assert.strictEqual(out.payload.sub, INSTRUCTOR.sub);
  assert.strictEqual(out.payload.role, 'instructor');
  assert.strictEqual(out.payload.path, '/caldera');
  assert.match(out.payload.jti, /^[0-9a-f]{32}$/, 'the jti is 128 bits of hex');
  assert.strictEqual(token.split('.').length, 3);
  assert.strictEqual(token.split('.')[0], 'v1');
  assert.ok(!/[=+/]/.test(token), 'base64url, unpadded — no =, + or / anywhere');
});

test('exp is mint time + 60 seconds, not longer', () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }, { now: 1_700_000_000 });
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  assert.strictEqual(payload.exp, 1_700_000_060);
  assert.strictEqual(sso.TOKEN_TTL_SECONDS, 60);
});

test('every mint is FRESH — no two tokens share a jti', () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const t = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
    const jti = JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8')).jti;
    assert.ok(!seen.has(jti), 'a repeated jti would make the single-use burn reject a real login');
    seen.add(jti);
  }
});

test('a TAMPERED PAYLOAD fails — the escalation attempt, in full', () => {
  // The attack: take an instructor's token, rewrite role to admin, keep the MAC.
  const token = sso.mintToken({ sub: 'u', role: 'instructor', path: '/caldera' });
  const [, payloadB64, mac] = token.split('.');
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  payload.role = 'admin';
  const forged = `v1.${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}.${mac}`;
  assert.deepStrictEqual(sso.verifyToken(forged, { path: '/caldera' }),
    { ok: false, reason: 'bad_signature' });
});

test('a TAMPERED MAC fails, including a one-bit flip', () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const [v, p, mac] = token.split('.');
  const bytes = Buffer.from(mac, 'base64url');
  bytes[0] ^= 0x01;
  assert.deepStrictEqual(
    sso.verifyToken(`${v}.${p}.${bytes.toString('base64url')}`, { path: '/caldera' }),
    { ok: false, reason: 'bad_signature' }
  );
  // A SHORT MAC must be a rejection, not a crash: timingSafeEqual throws on a
  // length mismatch, and an escaped 500 is itself a (coarse) oracle. Two
  // distinct shapes, and they are rejected at different steps on purpose:
  //   - 16 canonical bytes decodes fine and dies at the length check
  //   - an arbitrary truncation is not canonical base64url and dies earlier
  const short = Buffer.from(mac, 'base64url').subarray(0, 16).toString('base64url');
  assert.deepStrictEqual(
    sso.verifyToken(`${v}.${p}.${short}`, { path: '/caldera' }),
    { ok: false, reason: 'bad_signature' }
  );
  assert.deepStrictEqual(
    sso.verifyToken(`${v}.${p}.${mac.slice(0, 10)}`, { path: '/caldera' }),
    { ok: false, reason: 'malformed' }
  );
});

test('a TRUNCATED or malformed token fails, and never throws', () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const shapes = [
    token.split('.').slice(0, 2).join('.'),   // no MAC
    token.split('.')[1],                      // payload alone
    '',
    '...',
    'v1..',
    `${token}.extra`,
    `v1.${token.split('.')[1]}=.${token.split('.')[2]}`, // padded, non-canonical
    `v1.${token.split('.')[1]}!.${token.split('.')[2]}`, // outside the alphabet
    null,
    undefined,
    12345,
  ];
  for (const bad of shapes) {
    const out = sso.verifyToken(bad, { path: '/caldera' });
    assert.strictEqual(out.ok, false, `accepted ${String(bad)}`);
  }
});

test('an EXPIRED token fails, and exp is exclusive', () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }, { now: 1000 });
  assert.strictEqual(sso.verifyToken(token, { path: '/caldera', now: 1059 }).ok, true);
  assert.deepStrictEqual(sso.verifyToken(token, { path: '/caldera', now: 1060 }),
    { ok: false, reason: 'expired' }, 'exactly at exp is already gone');
  assert.deepStrictEqual(sso.verifyToken(token, { path: '/caldera', now: 1061 }),
    { ok: false, reason: 'expired' });
});

test('role "student" fails EVEN WITH A PERFECT SIGNATURE', () => {
  // The far-side role check is not redundant with the gate. If the minting
  // route ever regressed, this is what still keeps a student out.
  const forged = handSign({ sub: 'u', role: 'student', path: '/caldera', exp: 4_000_000_000, jti: 'a'.repeat(32) });
  assert.deepStrictEqual(sso.verifyToken(forged, { path: '/caldera' }),
    { ok: false, reason: 'bad_role' });
  // …and it cannot be minted in the first place.
  assert.throws(() => sso.mintToken({ sub: 'u', role: 'student', path: '/caldera' }),
    (err) => err.code === 'BAD_ROLE');
});

test('a MISSING role fails — absent is not "default to something"', () => {
  const forged = handSign({ sub: 'u', path: '/caldera', exp: 4_000_000_000, jti: 'a'.repeat(32) });
  assert.deepStrictEqual(sso.verifyToken(forged, { path: '/caldera' }),
    { ok: false, reason: 'missing_claim' });
  for (const missing of ['sub', 'path', 'exp', 'jti']) {
    const claims = { sub: 'u', role: 'admin', path: '/caldera', exp: 4_000_000_000, jti: 'a'.repeat(32) };
    delete claims[missing];
    assert.strictEqual(sso.verifyToken(handSign(claims), { path: '/caldera' }).ok, false,
      `a token with no ${missing} was accepted`);
  }
});

test('a PATH MISMATCH fails, and a sibling prefix is not a match', () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  assert.strictEqual(sso.verifyToken(token, { path: '/caldera' }).ok, true);
  assert.strictEqual(sso.verifyToken(token, { path: '/caldera/' }).ok, true);
  assert.strictEqual(sso.verifyToken(token, { path: '/caldera/api/v2/agents' }).ok, true);
  for (const wrong of ['/guacamole/x', '/', '/calderaX', '/caldera-admin/steal', '/api/caldera']) {
    assert.deepStrictEqual(sso.verifyToken(token, { path: wrong }),
      { ok: false, reason: 'path_mismatch' }, `${wrong} was accepted`);
  }
});

test('pathMatches refuses to treat a string prefix as a path prefix', () => {
  assert.strictEqual(sso.pathMatches('/caldera', '/caldera-admin'), false);
  assert.strictEqual(sso.pathMatches('/caldera', '/caldera'), true);
  assert.strictEqual(sso.pathMatches('/caldera/', '/caldera/x'), true);
  assert.strictEqual(sso.pathMatches('/caldera', '/caldera?a=1'), true);
  assert.strictEqual(sso.pathMatches('caldera', '/caldera'), false, 'relative claims are not claims');
});

// ===========================================================================
// §3 THE GATE — the advisory's failure mode, closed by construction
// ===========================================================================

test('an instructor is allowed AND handed a token that verifies', async () => {
  const { status, token } = await authorize(AUTHORIZE, INSTRUCTOR);
  assert.strictEqual(status, 204);
  assert.ok(token, 'the ALLOW carried no X-CyberCore-Auth header');
  const out = sso.verifyToken(token, { path: '/caldera/' });
  assert.strictEqual(out.ok, true);
  assert.strictEqual(out.payload.sub, INSTRUCTOR.sub, 'the token names the SESSION user');
  assert.strictEqual(out.payload.role, 'instructor');
  assert.strictEqual(out.payload.path, calderaAuthoring.PUBLIC_PATH);
});

test('an admin token says admin — the role is copied from the session, not assumed', async () => {
  const { status, token } = await authorize(AUTHORIZE, ADMIN);
  assert.strictEqual(status, 204);
  assert.strictEqual(sso.verifyToken(token, { path: '/caldera' }).payload.role, 'admin');
});

test('a DENY carries no token at all', async () => {
  for (const who of [null, STUDENT]) {
    const { status, token, text } = await authorize(AUTHORIZE, who);
    assert.ok(status < 200 || status > 299, 'a deny must be non-2xx for forward_auth');
    assert.strictEqual(token, null, 'a denied request was handed a signed token');
    assert.strictEqual(text, '', 'and the body stays empty');
  }
});

test('THE ADVISORY: the gate NEVER answers 2xx without a freshly minted token', async () => {
  // GHSA-7r4p-vjf4-gxv4 bites exactly here. copy_headers does not strip the
  // client's own X-CyberCore-Auth, so a 2xx with no header set means the
  // BROWSER's header reaches Caldera. This sweeps every shape of request the
  // endpoint can see — including the misconfigured-key paths, which are the
  // ones a hand-written `if` would get wrong — and holds the invariant over all
  // of them at once.
  const attempts = [
    () => authorize(AUTHORIZE, INSTRUCTOR),
    () => authorize(AUTHORIZE, ADMIN),
    () => authorize(AUTHORIZE, STUDENT),
    () => authorize(AUTHORIZE, null),
    () => authorize(`${AUTHORIZE}?view=student`, INSTRUCTOR),
    () => authorize(`${AUTHORIZE}?view=student&role=admin`, STUDENT),
    () => authorize(AUTHORIZE, INSTRUCTOR, { [sso.SSO_HEADER]: 'v1.forged.forged' }),
    () => authorize(AUTHORIZE, INSTRUCTOR, { 'X-CyberCore-User': ADMIN.sub, 'X-CyberCore-Role': 'admin' }),
    () => authorize(AUTHORIZE, { ...INSTRUCTOR, stage: 'mfa' }),
    () => withSecret(undefined, () => authorize(AUTHORIZE, INSTRUCTOR)),
    () => withSecret('too-short', () => authorize(AUTHORIZE, ADMIN)),
  ];

  const issued = new Set();
  for (const attempt of attempts) {
    const { status, token } = await attempt();
    if (status < 200 || status > 299) {
      assert.strictEqual(token, null, `a ${status} still set the identity header`);
      continue;
    }
    assert.ok(token, `HTTP ${status} with NO token — this is the advisory, exactly`);
    assert.strictEqual(sso.verifyToken(token, { path: '/caldera' }).ok, true,
      `HTTP ${status} carried a token that does not verify`);
    assert.ok(!issued.has(token), 'the same token was issued twice — it is single use');
    issued.add(token);
  }
  assert.ok(issued.size >= 2, 'the sweep must actually have produced some allows');
});

test('a MISSING key takes the console offline rather than opening it', async () => {
  for (const bad of [undefined, '', 'short', 'x'.repeat(31)]) {
    const { status, token } = await withSecret(bad, () => authorize(AUTHORIZE, ADMIN));
    assert.strictEqual(status, 503, 'a misconfigured key must be a non-2xx, so forward_auth denies');
    assert.strictEqual(token, null);
  }
});

test('THE STUDENT VIEW BYPASS: ?view=student cannot change the decision', async () => {
  // CyberCore rewrites the DRAWN role to 'student' in Student View, and server
  // code elsewhere honours ?view=student on purpose (ciab canSeeCiab, so the
  // sidebar preview is faithful). Honouring it HERE would be an access decision
  // steered by a query parameter — and forward_auth copies the original query
  // string onto the subrequest, so the client controls it end to end.
  for (const q of ['?view=student', '?view=student&x=1', '?role=student', '?view=STUDENT']) {
    const { status, token } = await authorize(`${AUTHORIZE}${q}`, INSTRUCTOR);
    assert.strictEqual(status, 204, `${q} locked a real instructor out mid-lecture`);
    assert.strictEqual(sso.verifyToken(token, { path: '/caldera' }).payload.role, 'instructor',
      `${q} rewrote the role INSIDE the signed token`);
  }
  // …and the bypass does not run the other way either.
  for (const q of ['?view=instructor', '?view=admin', '?role=admin']) {
    const { status, token } = await authorize(`${AUTHORIZE}${q}`, STUDENT);
    assert.strictEqual(status, 403, `${q} upgraded a student`);
    assert.strictEqual(token, null);
  }
});

test('no header can name its own identity either', async () => {
  const headers = {
    'X-CyberCore-User': ADMIN.sub,
    'X-CyberCore-Role': 'admin',
    'Remote-User': ADMIN.sub,
    'Remote-Groups': 'admin',
    [sso.SSO_HEADER]: handSign({ sub: ADMIN.sub, role: 'admin', path: '/caldera', exp: 4_000_000_000, jti: 'a'.repeat(32) }),
  };
  // A student sending a perfectly-signed admin token they somehow obtained is
  // still a student: the gate reads the SESSION, never the inbound header.
  const denied = await authorize(AUTHORIZE, STUDENT, headers);
  assert.strictEqual(denied.status, 403);
  assert.strictEqual(denied.token, null);

  const allowed = await authorize(AUTHORIZE, INSTRUCTOR, headers);
  assert.strictEqual(allowed.status, 204);
  const out = sso.verifyToken(allowed.token, { path: '/caldera' });
  assert.strictEqual(out.payload.sub, INSTRUCTOR.sub, 'the inbound header steered the identity');
  assert.strictEqual(out.payload.role, 'instructor');
});

test('STRUCTURALLY: the route never reads a query parameter at all', () => {
  // Behavioural tests prove the cases someone thought of. This proves there is
  // no code path to think of: the file cannot honour ?view=anything because it
  // never looks at req.query.
  const src = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'caldera-authoring.js'), 'utf8');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  assert.ok(!/req\.query/.test(code), 'the authoring route reads req.query — that is the bypass');
  assert.ok(!/viewingAsStudent|realRole|view\s*===/.test(code),
    'the authoring route reasons about the Student View — it must read server truth only');
  // The gate must also never mint from anything but the authenticated session.
  assert.match(code, /mintToken\(\{\s*sub:\s*req\.user\.userId/,
    'the token must be minted from req.user, which authenticate() built from the signed JWT');
});

test('the ALLOW is not cacheable — a proxy must not replay a single-use token', async () => {
  const res = await fetch(`http://127.0.0.1:${port}${AUTHORIZE}`, {
    headers: { cookie: `token=${session(ADMIN)}` },
  });
  assert.match(String(res.headers.get('cache-control') || ''), /no-store/);
});

// ===========================================================================
// §4 THE BURN — single use, and who may drive it
// ===========================================================================

test('REPLAY DEFEATED: the first redeem is 200 and every one after is 409', async () => {
  const token = sso.mintToken({ sub: INSTRUCTOR.sub, role: 'instructor', path: '/caldera' });
  const jti = sso.verifyToken(token, { path: '/caldera' }).payload.jti;

  assert.strictEqual((await redeem({ jti }, token)).status, 200);
  // The token is still perfectly valid, unexpired and correctly signed. It is
  // simply spent — which is the entire point: a token captured off the wire is
  // dead the instant the real login used it.
  assert.strictEqual(sso.verifyToken(token, { path: '/caldera' }).ok, true);
  assert.strictEqual((await redeem({ jti }, token)).status, 409);
  assert.strictEqual((await redeem({ jti }, token)).status, 409);
});

test('the burn is ATOMIC — SET NX with a TTL longer than the token', async () => {
  redis._calls.length = 0;
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const jti = sso.verifyToken(token, { path: '/caldera' }).payload.jti;
  await redeem({ jti }, token);
  const call = redis._calls.find((c) => c.key.endsWith(jti));
  assert.ok(call, 'the jti never reached Redis');
  assert.strictEqual(call.opts.NX, true,
    'a GET-then-SET would let two simultaneous replays both be told 200');
  assert.ok(call.opts.PX > sso.TOKEN_TTL_SECONDS * 1000,
    'the nonce must outlive the token, or clock skew reopens the replay window');
  assert.ok(!call.key.includes('u'.repeat(2)) && call.key.startsWith('caldera:sso:jti:'),
    'the key is namespaced and carries no identity');
});

test('concurrent redeems of the same jti: exactly one 200', async () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const jti = sso.verifyToken(token, { path: '/caldera' }).payload.jti;
  const results = await Promise.all([0, 1, 2, 3, 4].map(() => redeem({ jti }, token)));
  const ok = results.filter((r) => r.status === 200);
  const conflict = results.filter((r) => r.status === 409);
  assert.strictEqual(ok.length, 1, 'more than one caller was told the nonce was theirs');
  assert.strictEqual(conflict.length, 4);
});

test('THE GUARD: redeem needs the TOKEN, not merely a jti', async () => {
  // The Caddyfile's catch-all publishes every app path, so this endpoint is
  // reachable from the internet. Requiring the token turns "anyone may burn any
  // nonce" into "only the holder of this token may burn this token's nonce".
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const jti = sso.verifyToken(token, { path: '/caldera' }).payload.jti;

  assert.strictEqual((await redeem({ jti }, undefined)).status, 401, 'no header');
  assert.strictEqual((await redeem({ jti }, 'v1.aaaa.bbbb')).status, 401, 'garbage header');
  assert.strictEqual((await redeem({ jti }, `${token}x`)).status, 401, 'a tampered token');

  const expired = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' }, { now: 1000 });
  assert.strictEqual((await redeem({ jti }, expired)).status, 401, 'an expired token');

  const student = handSign({ sub: 'u', role: 'student', path: '/caldera', exp: 4_000_000_000, jti });
  assert.strictEqual((await redeem({ jti }, student)).status, 401, 'a signed student token');

  // …and the nonce survived every one of those attempts.
  assert.strictEqual((await redeem({ jti }, token)).status, 200,
    'a rejected caller pre-burned the nonce — that is a denial of service');
});

test('the body must name the TOKEN\'S OWN jti — no burning someone else\'s', async () => {
  const mine = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const theirs = sso.mintToken({ sub: 'v', role: 'admin', path: '/caldera' });
  const theirJti = sso.verifyToken(theirs, { path: '/caldera' }).payload.jti;

  assert.strictEqual((await redeem({ jti: theirJti }, mine)).status, 400);
  assert.strictEqual((await redeem({ jti: theirJti }, theirs)).status, 200,
    'the real holder can still use it');
});

test('a malformed jti is a 400 and never reaches Redis', async () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  redis._calls.length = 0;
  for (const jti of [undefined, null, '', 'nope', 'A'.repeat(32), '0'.repeat(31), '0'.repeat(33), { a: 1 }, 42]) {
    assert.strictEqual((await redeem({ jti }, token)).status, 400, `accepted jti ${String(jti)}`);
  }
  assert.strictEqual((await redeem({}, token)).status, 400, 'no jti at all');
  assert.strictEqual(redis._calls.length, 0, 'an attacker-chosen key reached Redis');
});

test('NO REDIS, NO 200 — an unconfirmed burn is not a burn', async () => {
  const down = express();
  down.use(calderaAuthoring.REDEEM_MOUNT_PATH,
    calderaAuthoring.createCalderaRedeemRouter({ redis: fakeRedis({ ready: false }) }));
  const srv = http.createServer(down);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
    const jti = sso.verifyToken(token, { path: '/caldera' }).payload.jti;
    const res = await fetch(`http://127.0.0.1:${srv.address().port}${calderaAuthoring.REDEEM_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', [sso.SSO_HEADER]: token },
      body: JSON.stringify({ jti }),
    });
    assert.strictEqual(res.status, 503,
      'a Redis outage must take the console offline, never quietly restore replayability');
  } finally {
    srv.close();
  }
});

test('every redeem answer is a bare status — no reason, no oracle', async () => {
  const token = sso.mintToken({ sub: 'u', role: 'admin', path: '/caldera' });
  const jti = sso.verifyToken(token, { path: '/caldera' }).payload.jti;
  for (const [body, hdr] of [[{ jti }, undefined], [{ jti: 'x' }, token], [{ jti }, token], [{ jti }, token]]) {
    const { text } = await redeem(body, hdr);
    assert.strictEqual(text, '', 'the burn told the caller WHY it failed');
  }
});

// ===========================================================================
// §5 CROSS-LANGUAGE AGREEMENT — the Python verifier, actually executed
// ===========================================================================

const vectors = JSON.parse(fs.readFileSync(VECTORS_FILE, 'utf8'));

test('the committed vectors are what the Node verifier actually answers', () => {
  // The fixture is the contract written down. If this fails, the Node side
  // changed and the Python side has not been told.
  assert.ok(vectors.cases.length >= 12, 'the vector set has been gutted');
  assert.strictEqual(vectors.header, sso.SSO_HEADER);
  assert.strictEqual(vectors.version, sso.TOKEN_VERSION);
  const env = { CALDERA_SSO_SECRET: vectors.secret };
  for (const c of vectors.cases) {
    const out = sso.verifyToken(c.token, { env, path: c.request_path, now: c.verify_at });
    const got = out.ok ? 'ok' : out.reason;
    assert.strictEqual(got, c.expect, `Node disagrees with the fixture on: ${c.name}`);
    if (c.expect === 'ok') assert.deepStrictEqual(out.payload, c.payload);
  }
});

/** python3, then python. Returns null when neither runs — CI may have neither. */
function findPython() {
  for (const exe of ['python3', 'python']) {
    const probe = spawnSync(exe, ['-c', 'import sys; sys.stdout.write("ok")'], { encoding: 'utf8' });
    if (!probe.error && probe.status === 0 && probe.stdout.trim() === 'ok') return exe;
  }
  return null;
}

test('THE OTHER HALF: python3 verifies tokens this repo minted, case for case', (t) => {
  const python = findPython();
  if (!python) {
    // Loud, not silent. The vector assertions above still ran, so the contract
    // is pinned either way — but "we could not run the verifier" must not read
    // as "the verifier passed".
    t.skip('no python3 on PATH — the Node/fixture half ran, the Python half did NOT');
    return;
  }

  const run = spawnSync(python, [PY_RUNNER, LOGIN_HANDLER, VECTORS_FILE], {
    encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
  });
  assert.strictEqual(run.status, 0,
    `the Python verifier did not run cleanly:\n${run.stderr || run.error}`);

  const out = JSON.parse(run.stdout);

  // 1. Every vector, same answer, same reason.
  assert.strictEqual(out.results.length, vectors.cases.length);
  for (let i = 0; i < vectors.cases.length; i++) {
    const expected = vectors.cases[i];
    const actual = out.results[i];
    assert.strictEqual(actual.name, expected.name, 'the runner drifted out of order');
    assert.strictEqual(actual.got, expected.expect,
      `PYTHON DISAGREES on "${expected.name}": expected ${expected.expect}, got ${actual.got}`);
    if (expected.expect === 'ok') {
      assert.deepStrictEqual(actual.payload, expected.payload,
        'the two sides parsed the same signed bytes into different claims');
    }
  }

  // 2. The key rule, on both sides. A Python that accepted a short key while
  //    Node refused would mean Caldera trusting a token Node would never mint.
  assert.deepStrictEqual(out.secret_checks, {
    missing: 'secret_missing',
    short: 'secret_too_short',
    whitespace_padded_ok: 'ok',
    ok: 'ok',
  });

  // 3. Path reconstruction. Caddy's handle_path STRIPS /caldera before the
  //    upstream sees the request, so a step-5 check against the raw path would
  //    fail every single login. This is the arithmetic that fixes it, and the
  //    last case is the one that matters: X-Forwarded-Uri is a client-supplied
  //    header and must never be able to point the check somewhere else.
  assert.deepStrictEqual(out.paths, {
    stripped_root: '/caldera/',
    stripped_asset: '/caldera/js/app.js',
    already_prefixed: '/caldera/js/app.js',
    forwarded_uri_used: '/caldera/js/app.js',
    forwarded_uri_ignored_when_foreign: '/caldera/js/app.js',
  });

  // 4. The environment contract with the compose service and the Dockerfile,
  //    both written by another author. A rename on that side that is not
  //    mirrored here rejects every login with 'path_mismatch', and a missing
  //    factory symbol stops the container booting at all.
  assert.deepStrictEqual(out.config, {
    path_prefix_var: '/authoring',
    path_var_synonym: '/authoring',
    path_default: '/caldera',
    user_default: 'cybercore',
    user_from_env: 'cybercore',
    admin_falls_back_to_one_account: 'cybercore',
    exports_load_login_handler: true,
    exports_load_alias: true,
    importable_without_caldera: true,
  });
  assert.strictEqual(out.config.path_default, calderaAuthoring.PUBLIC_PATH,
    'the Python default path and the path the Node side MINTS must be the same string');
});

test('a token minted RIGHT NOW is accepted by the Python verifier', (t) => {
  // The vectors are frozen; this is the live wire. It catches the failure the
  // fixture cannot: a change to mintToken that keeps the old vectors passing
  // (they are literal strings) while producing tokens Python rejects.
  const python = findPython();
  if (!python) {
    t.skip('no python3 on PATH — the live cross-language check did NOT run');
    return;
  }
  const token = sso.mintToken({ sub: INSTRUCTOR.sub, role: 'instructor', path: '/caldera' });
  const program = [
    'import importlib.util, json, os, sys',
    'spec = importlib.util.spec_from_file_location("h", sys.argv[1])',
    'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
    'p = m.verify_token(os.environ["CC_TOKEN"], m.load_secret(), request_path="/caldera/js/app.js")',
    'json.dump(p, sys.stdout)',
  ].join('\n');
  const run = spawnSync(python, ['-c', program, LOGIN_HANDLER], {
    encoding: 'utf8',
    env: { ...process.env, CC_TOKEN: token, CALDERA_SSO_SECRET: SECRET },
  });
  assert.strictEqual(run.status, 0, `python rejected a freshly minted token:\n${run.stderr}`);
  const payload = JSON.parse(run.stdout);
  assert.strictEqual(payload.sub, INSTRUCTOR.sub);
  assert.strictEqual(payload.role, 'instructor');
  assert.strictEqual(payload.path, '/caldera');
});

test('the Python verifier uses compare_digest, never ==', () => {
  // A timing oracle on a MAC is a real, published attack: Python's bytes __eq__
  // short-circuits on the first differing byte, so an attacker recovers a valid
  // signature one byte at a time. This is cheap to assert and expensive to
  // rediscover.
  const py = fs.readFileSync(LOGIN_HANDLER, 'utf8');
  assert.match(py, /hmac\.compare_digest\(/, 'the MAC comparison is not constant time');
  assert.ok(!/if\s+mac\s*==\s*expected/.test(py), 'a plain == crept back into the MAC check');
  assert.ok(!/CALDERA_SSO_SECRET["']?\s*,\s*["'][^"']+["']\)/.test(py),
    'os.environ.get with a DEFAULT secret — the key must fail closed');
  // The pure logic must stay importable without Caldera, or this file's only
  // automated proof stops running.
  assert.match(py, /except ImportError/, 'the Caldera import is not guarded');
});
