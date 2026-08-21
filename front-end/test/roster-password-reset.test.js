/**
 * roster-password-reset.test.js — "New password" sends a link, not a password.
 *
 * What changed, and why it needs pinning:
 *
 * The instructor's "New password" button used to mint a temporary password,
 * display it once, AND email the plaintext. That is the failure mode
 * activation.js was written against — a working credential sitting in a mailbox,
 * readable by anyone who later reaches that mailbox, still valid until somebody
 * remembers to sign in. It now issues a single-use, expiring link instead.
 *
 * Three things can silently undo that, and each is a test below:
 *
 *   1. A password creeping back into the response or the email body. Either one
 *      restores the exact exposure, and neither shows up as a failure anywhere.
 *   2. The reset token being issued with the DEFAULT purpose. issueActivationToken
 *      revokes per purpose, so a 'reset' minted as 'activate' would cancel an
 *      outstanding invitation as a side effect — taking the roster's "invited"
 *      badge with it, since pendingActivationFor counts live 'activate' tokens.
 *   3. /activate consuming one token and leaving the other purpose live, which
 *      is a second undisclosed way into an account whose password just changed.
 *
 * Run: node --test front-end/test/roster-password-reset.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');

const templates = require(path.join(UTILS, 'email-templates'));

const ROUTE_SRC = fs.readFileSync(
  path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'routes', 'course-roster.js'), 'utf8');
const AUTH_SRC = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'auth.js'), 'utf8');
const CLIENT_SRC = fs.readFileSync(
  path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'public', 'js', 'roster-import.js'), 'utf8');

/** The whole `router.post('/students/:studentId/password', ...)` handler. */
function passwordRouteBody() {
  const start = ROUTE_SRC.indexOf("router.post('/students/:studentId/password'");
  assert.notStrictEqual(start, -1, 'the password route has been renamed or removed');
  const next = ROUTE_SRC.indexOf('router.', start + 10);
  return ROUTE_SRC.slice(start, next === -1 ? ROUTE_SRC.length : next);
}

// ── the email carries a link and nothing else ────────────────────────────────

test('passwordReset never renders a password, even when handed one', () => {
  // Stronger than grepping for the WORD: the prose legitimately says "choose a
  // new password". What must never appear is a VALUE. Passing one in proves the
  // template has no path that would render it if a future caller — or a
  // copy-paste from credentialsIssued — started supplying one.
  const SECRET = 'Tr0ub4dor-NEVER-SEND-ME';
  const body = templates.passwordReset({
    siteName: 'CyberHub',
    firstName: 'Ada',
    username: 'ada',
    password: SECRET,
    resetUrl: 'https://example.org/activate?token=abc123&mode=reset',
    courseCode: 'CYBR-480',
    expiresAt: new Date('2026-01-02T03:04:05Z'),
  });
  for (const part of ['subject', 'text', 'html']) {
    assert.ok(body[part] && body[part].trim(), `${part} is empty`);
    assert.ok(!body[part].includes(SECRET), `${part} carries a credential`);
  }
  assert.ok(body.text.includes('https://example.org/activate?token=abc123&mode=reset'),
    'the link is the only credential this message has — it must be in the text part');
});

test('passwordReset says the current password still works', () => {
  // A recipient who did not expect this mail otherwise cannot tell whether they
  // have already been locked out.
  const body = templates.passwordReset({ siteName: 'CyberHub', resetUrl: 'https://x/a' });
  assert.match(body.text, /current password keeps working/i);
});

test('passwordReset survives being called with no arguments', () => {
  // A template that throws on a missing optional field turns a cosmetic gap into
  // a failed send.
  const body = templates.passwordReset();
  assert.strictEqual(typeof body.subject, 'string');
  assert.ok(body.subject.trim().length > 0);
});

test('passwordReset escapes interpolated values', () => {
  const body = templates.passwordReset({
    siteName: 'CyberHub', firstName: '<script>alert(1)</script>', resetUrl: 'https://x/a',
  });
  assert.ok(!body.html.includes('<script>alert(1)</script>'), 'raw markup reached the html part');
});

// ── activationUrl carries the cosmetic mode ─────────────────────────────────

test('activationUrl adds mode only when asked, and encodes it', () => {
  // Required so /activate can tell a reset from a first-time activation: the
  // token is deliberately never inspected before the submit, so the URL is the
  // only signal available. It authorizes nothing.
  const activation = require(path.join(UTILS, 'activation'));
  assert.strictEqual(activation.activationUrl('t0k', 'https://h/'), 'https://h/activate?token=t0k');
  assert.strictEqual(activation.activationUrl('t0k', 'https://h', 'reset'),
    'https://h/activate?token=t0k&mode=reset');
  assert.ok(activation.activationUrl('t0k', 'https://h', 'a b').endsWith('&mode=a%20b'));
});

test("'reset' is a purpose the token table actually accepts", () => {
  const src = fs.readFileSync(path.join(UTILS, 'activation.js'), 'utf8');
  assert.match(src, /VALID_PURPOSES\s*=\s*\[[^\]]*'reset'/,
    "issueActivationToken would reject 'reset' with a 400");
  assert.match(src, /CHECK \(purpose IN \('activate','reset'\)\)/,
    'the boot DDL would reject the INSERT');
});

// ── the route hands out a link, not a credential ─────────────────────────────

test('the password route issues a reset token, not an activation one', () => {
  const src = ROUTE_SRC.slice(ROUTE_SRC.indexOf('async function sendPasswordResetLink'));
  const helper = src.slice(0, src.indexOf('\n}\n') + 3);
  assert.match(helper, /purpose:\s*'reset'/,
    "a reset minted with the default purpose would revoke the student's invitation");
  assert.match(helper, /templateKey:\s*'passwordReset'/);
  assert.match(helper, /activationUrl\([^)]*'reset'\)/,
    'the link must carry mode=reset or /activate greets a reset as a new account');
});

test('the password route no longer sets, generates or returns a password', () => {
  const body = passwordRouteBody();
  assert.doesNotMatch(body, /setPassword/, 'the route still writes a password to the account');
  assert.doesNotMatch(body, /generatePassword/);
  assert.doesNotMatch(body, /notifyCredentials/, 'the route still emails a plaintext credential');
  // `password,` as a returned property. The word appears in prose and in
  // `password-reset link`, so match the JS shape rather than the word.
  assert.doesNotMatch(body, /^\s*password[,:]\s*$/m, 'a password is still in the response body');
  assert.doesNotMatch(body, /expires_at:\s*expiresAt/);
});

test('the password route refuses rather than half-succeeding when mail cannot reach', () => {
  const body = passwordRouteBody();
  assert.match(body, /mailer\.mailEnabled\(\)/);
  assert.match(body, /mailer\.checkRecipient/);
  // Link-only means no delivery is no credential. The 409 has to name the one
  // path that still works — cohort accounts (@cohort.invalid) land here by
  // construction and the instructor cannot guess the alternative.
  const four09s = body.match(/status\(409\)[\s\S]{0,400}?\}\);/g) || [];
  assert.strictEqual(four09s.length, 2, 'expected a 409 for mail-disabled and for a blocked recipient');
  for (const block of four09s) {
    assert.match(block, /Admin/, 'the 409 does not tell the instructor what to do instead');
  }
});

test('the route still gates on course provenance, not just enrollment', () => {
  // loadManageableStudent -> assertCourseProvisionedStudent is what stops an
  // instructor resetting an account their course did not create.
  assert.match(passwordRouteBody(), /loadManageableStudent/);
});

test('notifyCredentials and the session warning are gone, not merely unused', () => {
  assert.doesNotMatch(ROUTE_SRC, /async function notifyCredentials/);
  assert.doesNotMatch(ROUTE_SRC, /SESSION_SURVIVAL_WARNING/);
});

// ── redeeming a link closes the other door ───────────────────────────────────

test('/activate revokes BOTH token purposes after a successful set', () => {
  const start = AUTH_SRC.indexOf("router.post('/activate'");
  assert.notStrictEqual(start, -1);
  const body = AUTH_SRC.slice(start, AUTH_SRC.indexOf('\n});', start));
  assert.match(body, /revokeActivationTokens/,
    'the other purpose stays live — a second undisclosed way into the account');
  assert.match(body, /\['activate',\s*'reset'\]/);
});

// ── the client stops rendering a password ────────────────────────────────────

test('the roster client no longer has a password-display modal', () => {
  assert.doesNotMatch(CLIENT_SRC, /function showPasswordResult/);
  assert.doesNotMatch(CLIENT_SRC, /result\.password/);
});

test('the roster client surfaces the server message verbatim on failure', () => {
  // The 409 names the admin path; swallowing it for a generic string would
  // leave the instructor with a dead button and no explanation.
  const src = CLIENT_SRC.slice(CLIENT_SRC.indexOf('async function regenerateStudentPassword'));
  const fn = src.slice(0, src.indexOf('\n  }\n') + 5);
  assert.match(fn, /err\.message/);
  assert.match(fn, /result\.note/);
});
