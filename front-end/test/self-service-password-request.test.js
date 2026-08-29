/**
 * self-service-password-request.test.js — POST /api/auth/password/request
 *
 * The only unauthenticated way to obtain a link, and the reason instructors no
 * longer have to be in the loop: a student who missed the invitation window
 * re-sends themselves one instead of asking someone with a roster to do it.
 *
 * Being unauthenticated is what makes every property below load-bearing.
 *
 *   1. ENUMERATION. Anyone on the internet can post an address here. The moment
 *      the answer varies — a different body, a different status, or merely a
 *      different amount of time — this becomes a way to ask "does this person
 *      have an account on the cyber range", which is exactly the question not to
 *      answer.
 *
 *   2. ORDERING. issueActivationToken REVOKES the account's outstanding
 *      invitation before minting a replacement. So if deliverability were checked
 *      after that call rather than before it, an unauthenticated request naming
 *      any student's address would destroy their live link and queue nothing to
 *      replace it. With MAIL_ENABLED=false — the current state of this
 *      deployment — that is every request.
 *
 *   3. PURPOSE. 'activate' tokens are what pendingActivationFor counts, so
 *      minting one has a visible side effect on an instructor's roster. Choosing
 *      it from activated_at alone would mark established users as "invited".
 *
 * Run: node --test front-end/test/self-service-password-request.test.js
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

/** LF regardless of checkout — core.autocrlf=true otherwise breaks every slice. */
function readSrc(...parts) {
  return fs.readFileSync(path.join(...parts), 'utf8').replace(/\r\n/g, '\n');
}

const AUTH_SRC = readSrc(ROOT, 'src', 'routes', 'auth.js');
const SERVER_SRC = readSrc(ROOT, 'src', 'server.js');
const LOGIN_SRC = readSrc(ROOT, 'public', 'login.html');

/**
 * Comments stripped. Several assertions below are ORDERING checks, and the
 * comments in this code necessarily name the very identifiers being ordered
 * ("check deliverability before issueActivationToken") — so prose would otherwise
 * satisfy or defeat them regardless of what the code does.
 */
function withoutComments(src) {
  return src.split('\n').map(l => l.replace(/\/\/.*$/, '')).join('\n');
}

/** The route handler itself — the part that talks to the caller. */
function handler() {
  const start = AUTH_SRC.indexOf("router.post('/password/request'");
  assert.notStrictEqual(start, -1, 'the request route was renamed or removed');
  const next = AUTH_SRC.indexOf('\nrouter.', start + 10);
  return withoutComments(AUTH_SRC.slice(start, next === -1 ? AUTH_SRC.length : next));
}

/** Everything that runs after the caller has been answered. */
function deliverBody() {
  const start = AUTH_SRC.indexOf('async function deliverRecoveryLink');
  assert.notStrictEqual(start, -1, 'deliverRecoveryLink was renamed or removed');
  const src = AUTH_SRC.slice(start);
  return withoutComments(src.slice(0, src.indexOf('\n}\n') + 3));
}

// ── one answer, on every path ────────────────────────────────────────────────

test('every response is the same frozen object', () => {
  const body = handler();
  const responses = body.match(/res\.(json|send|status)\([^)]*/g) || [];

  assert.ok(responses.length > 0, 'the handler never responds');
  for (const r of responses) {
    assert.match(r, /RECOVERY_ACK/,
      `"${r}" is a response this endpoint can give that differs from the others — `
      + 'any difference is an account-existence oracle');
  }
});

test('the handler cannot report failure, not even a 500', () => {
  const body = handler();
  assert.doesNotMatch(body, /status\(4\d\d\)/, 'a 4xx on one path identifies that path');
  assert.doesNotMatch(body, /status\(5\d\d\)/,
    'a thrown error must not become the one response shape that differs');
});

test('nothing about the account leaks into the response', () => {
  const body = handler();
  assert.doesNotMatch(body, /user_id/);
  assert.doesNotMatch(body, /expires_at/);
  assert.doesNotMatch(body, /\bsent\b\s*:/);
  assert.doesNotMatch(body, /\btoken\b/, 'the token must never reach the caller');
});

test('the caller is answered BEFORE any lookup happens', () => {
  // A miss is one SELECT; a hit is a SELECT plus a revoke, a token INSERT and an
  // outbox INSERT carrying a pgp_sym_encrypt. That difference is measurable, and
  // a measurable difference is a usable oracle even when the body is identical.
  const body = handler();
  const responded = body.indexOf('res.json(RECOVERY_ACK)');
  const worked = body.indexOf('deliverRecoveryLink');

  assert.notStrictEqual(responded, -1);
  assert.notStrictEqual(worked, -1);
  assert.ok(responded < worked,
    'the response must be sent before the work starts, or the timing difference '
    + 'between a hit and a miss answers the question the body refuses to');
});

test('delivery failures cannot escape into the request', () => {
  const body = handler();
  assert.match(body, /setImmediate/);
  assert.match(body, /\.catch\(/, 'an unhandled rejection here would crash the process');
});

// ── the ordering that must not be reversed ───────────────────────────────────

test('deliverability is checked BEFORE a token is minted', () => {
  const body = deliverBody();
  const checked = body.indexOf('canSendTo');
  const minted = body.indexOf('issueActivationToken');

  assert.notStrictEqual(checked, -1, 'the deliverability guard is gone');
  assert.notStrictEqual(minted, -1);
  assert.ok(checked < minted,
    'issueActivationToken revokes the outstanding invitation before minting a '
    + 'replacement. Checking deliverability afterwards turns this endpoint into an '
    + 'unauthenticated way to destroy any student\'s live invitation link.');
});

test('federated and disabled accounts are skipped silently', () => {
  const body = deliverBody();
  assert.match(body, /auth_provider/, 'a federated account has no local password to set');
  assert.match(body, /user\.active/);
  assert.match(body, /status !== 'active'/);

  // Skips must return, never respond — the caller was answered long ago.
  assert.doesNotMatch(body, /res\./, 'this function must not touch the response');
});

// ── which link gets sent ─────────────────────────────────────────────────────

test('choosePurpose needs all three signals, not activated_at alone', () => {
  const start = AUTH_SRC.indexOf('function choosePurpose');
  assert.notStrictEqual(start, -1, 'choosePurpose was renamed or removed');
  const src = AUTH_SRC.slice(start);
  const fn = src.slice(0, src.indexOf('\n}\n') + 3);

  assert.match(fn, /activated_at/);
  assert.match(fn, /last_auth_at/,
    'activated_at is NULL forever for cohort and self-registered accounts, which '
    + 'have working passwords — last_auth_at is what says they have used it');
  assert.match(fn, /provisioned_via/,
    "'activate' is only right for an account somebody else created");
  assert.match(fn, /'reset'/);
});

test('the recovery lookup returns the columns choosePurpose reads', () => {
  // findUserByEmail returns the GUARD column set, which omits last_auth_at.
  // Reusing it would make choosePurpose read undefined and silently pick
  // 'activate' for established accounts.
  const start = AUTH_SRC.indexOf('async function findUserForRecovery');
  assert.notStrictEqual(start, -1);
  const src = AUTH_SRC.slice(start);
  const fn = src.slice(0, src.indexOf('\n}\n') + 3);

  for (const col of ['last_auth_at', 'activated_at', 'provisioned_via', 'auth_provider', 'active', 'status']) {
    assert.match(fn, new RegExp(col), `${col} is needed by a guard or by choosePurpose`);
  }
});

test('a reset link carries mode=reset and an activation link does not', () => {
  const body = deliverBody();
  assert.match(body, /activationUrl\([^)]*'reset'\)/,
    "without mode=reset, /activate greets a password reset with \"Welcome! Finish "
    + 'setting up your account"');
  assert.match(body, /templateKey: firstTime \? 'activation' : 'passwordReset'/);
});

// ── rate limiting ────────────────────────────────────────────────────────────

test('the endpoint is rate limited, keyed on the address not the IP', () => {
  assert.match(SERVER_SRC, /passwordRequestLimiter/);

  const start = SERVER_SRC.indexOf('const passwordRequestLimiter');
  const block = SERVER_SRC.slice(start, SERVER_SRC.indexOf('});', start));
  assert.match(block, /req\.body\?\.email/,
    'keyed on the IP alone, one campus NAT address is a single bucket for a whole '
    + 'class — the hazard authLimiter already documents');
});

test('the body is parsed before the limiter, or the email key never fills', () => {
  const mount = SERVER_SRC.slice(SERVER_SRC.indexOf("app.use('/api/auth/password/request'"));
  const line = mount.slice(0, mount.indexOf('\n'));
  const bodyParser = line.indexOf('authBodyParser');
  const limiter = line.indexOf('passwordRequestLimiter');

  assert.notStrictEqual(bodyParser, -1, 'without authBodyParser req.body is undefined here');
  assert.ok(bodyParser < limiter, 'the parser must run first');
});

// ── the sign-in page ─────────────────────────────────────────────────────────

test('the login page offers the link and never branches on the answer', () => {
  assert.match(LOGIN_SRC, /forgotStep/);
  assert.match(LOGIN_SRC, /requestPasswordLink/);
  assert.match(LOGIN_SRC, /forgotStep'\]|'forgotStep'/,
    'forgotStep must be registered with showStep or it never hides');

  const start = LOGIN_SRC.indexOf("getElementById('forgotForm').addEventListener");
  const fn = LOGIN_SRC.slice(start, LOGIN_SRC.indexOf('\n      });', start));
  assert.match(fn, /result\.message/, "render the server's answer verbatim");
  assert.doesNotMatch(fn, /no such account|not found|doesn't exist/i,
    'a "no such account" branch here reintroduces the oracle the endpoint refuses '
    + 'to be');
});

// ── self-registration is closed ──────────────────────────────────────────────

test('registration is off unless explicitly enabled', () => {
  assert.match(AUTH_SRC, /ALLOW_SELF_REGISTRATION === 'true'/,
    'anything looser than an exact "true" defaults an open /register');

  const start = AUTH_SRC.indexOf("router.post('/register'");
  const body = AUTH_SRC.slice(start, AUTH_SRC.indexOf('\nrouter.', start + 10));
  assert.match(body, /SELF_REGISTRATION_ENABLED/, 'the route does not consult the flag');
  assert.match(body, /403/);
});

test('closing registration still leaves invited students a way back in', () => {
  // The whole point: turning /register off must not strand anyone who already
  // has an account. The refusal names the route that still works.
  const start = AUTH_SRC.indexOf("router.post('/register'");
  const body = AUTH_SRC.slice(start, AUTH_SRC.indexOf('\nrouter.', start + 10));
  assert.match(body, /forgot your password|sign-in page/i,
    'the 403 must point at self-service recovery, not dead-end the reader');
});

test('the sign-in page hides the register prompt unless the server enables it', () => {
  // Fails closed: if the config fetch fails the prompt stays hidden, which is the
  // harmless way to be wrong about a route that would 403 anyway.
  assert.match(LOGIN_SRC, /id="registerPrompt" style="display: none;"/,
    'the prompt must start hidden and be revealed, not the reverse');
  assert.match(LOGIN_SRC, /config\.self_registration_enabled/);
});
