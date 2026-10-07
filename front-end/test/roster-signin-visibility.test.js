/**
 * roster-signin-visibility.test.js — instructors can see who has not signed in.
 *
 * WHAT WENT WRONG, AND WHY IT NEEDS PINNING
 *
 * The course roster derived one boolean, `activation_pending`, from
 * pendingActivationFor() — which counts only tokens with `expires_at > NOW()`.
 * The Students tab then gated BOTH the "invited" badge and the "Resend invite"
 * button on that single boolean.
 *
 * So the moment an invitation timed out, the badge and the button disappeared
 * together, and a student who had never signed in became visually identical to
 * one who had been working for weeks. Exactly the students who needed a new link
 * were the ones an instructor could neither see nor help — which is why
 * instructors ended up emailing an administrator to re-send invitations by hand.
 *
 * Four things can silently restore that, and each is a test below:
 *
 *   1. Re-gating the Resend button on token liveness instead of `can_resend`.
 *   2. Dropping `last_auth_at` from the roster query, which empties the column.
 *   3. Losing either branch of invitationStateFor's FILTER pair — with only the
 *      live branch it is pendingActivationFor again, under a new name.
 *   4. Deriving "has used this account" from activated_at alone. That column is
 *      written only by completePasswordChange, which a cohort student handed a
 *      printed password never reaches, so an entire section that signs in daily
 *      would report as "invite expired".
 *
 * Run: node --test front-end/test/roster-signin-visibility.test.js  (or npm test)
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

const activation = require(path.join(ROOT, 'src', 'utils', 'activation'));

const ACTIVATION_SRC = readSrc(ROOT, 'src', 'utils', 'activation.js');
const STUDENTS_SRC = readSrc(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'routes', 'course-students.js');
const ROSTER_SRC = readSrc(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'routes', 'course-roster.js');
const PAGE_SRC = readSrc(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'public', 'pages', 'courses.html');
const CLIENT_SRC = readSrc(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'public', 'js', 'roster-import.js');

/** Source with // line comments removed, so prose cannot satisfy an assertion. */
function withoutComments(src) {
  return src.split('\n').map(l => l.replace(/\/\/.*$/, '')).join('\n');
}

// ── the state machine ────────────────────────────────────────────────────────

test('deriveInviteStatus separates the three states an instructor acts on', () => {
  const d = activation.deriveInviteStatus;

  assert.strictEqual(
    d({ activatedAt: new Date(), lastAuthAt: null, invite: null }), 'active');
  assert.strictEqual(
    d({ activatedAt: null, lastAuthAt: null, invite: { liveExpiresAt: new Date() } }), 'invited');
  assert.strictEqual(
    d({ activatedAt: null, lastAuthAt: null, invite: { expiredAt: new Date() } }), 'expired');
  assert.strictEqual(
    d({ activatedAt: null, lastAuthAt: null, invite: null }), 'never_invited');
});

test('THE BUG: an expired invitation is a state of its own, not "active"', () => {
  // This is the regression. Before, an expired token made activation_pending
  // false, and false was indistinguishable from "they signed in weeks ago".
  const status = activation.deriveInviteStatus({
    activatedAt: null, lastAuthAt: null, invite: { expiredAt: new Date(Date.now() - 1000) },
  });
  assert.strictEqual(status, 'expired');
  assert.notStrictEqual(status, 'active');
});

test('a cohort student who signed in is active, even with activated_at NULL', () => {
  // provisionAccount never writes activated_at, and a cohort account is created
  // with must_change_password false — so it never reaches completePasswordChange,
  // the only writer. Keying on activated_at alone reports a whole section that
  // logs in daily as never having been invited.
  assert.strictEqual(
    activation.deriveInviteStatus({ activatedAt: null, lastAuthAt: new Date(), invite: null }),
    'active');
});

test('"never invited" is not reported as "expired"', () => {
  // The badge says "invite expired". For an account no invitation was ever sent
  // to, that is simply untrue, and it sends the instructor looking for a lapse
  // that never happened.
  assert.strictEqual(
    activation.deriveInviteStatus({ activatedAt: null, lastAuthAt: null, invite: null }),
    'never_invited');
});

test('invitationStateFor asks for BOTH the live and the lapsed branch', () => {
  const src = ACTIVATION_SRC.slice(ACTIVATION_SRC.indexOf('async function invitationStateFor'));
  const fn = src.slice(0, src.indexOf('\n}\n') + 3);

  assert.match(fn, /FILTER \(WHERE expires_at\s*>\s*NOW\(\)\)/,
    'without the live branch there is no "invited" state');
  assert.match(fn, /FILTER \(WHERE expires_at\s*<=\s*NOW\(\)\)/,
    'without the lapsed branch this is pendingActivationFor again, renamed — and '
    + 'expired invitations become invisible exactly as before');
  assert.match(fn, /purpose = 'activate'/);
  assert.match(fn, /consumed_at IS NULL/,
    'consumed rows are outside the partial index this query relies on');
});

// ── the roster API ───────────────────────────────────────────────────────────

test('the roster query selects last_auth_at', () => {
  // Dropping it does not fail anything — the column simply renders empty for
  // every student, which reads as "nobody has ever signed in".
  const src = STUDENTS_SRC.slice(STUDENTS_SRC.indexOf('const usersResult'));
  const q = src.slice(0, src.indexOf('`, [userIds]'));
  assert.match(q, /last_auth_at/, 'the Last sign-in column has nothing to render');
});

test('the roster computes invite_state and can_resend server-side', () => {
  assert.match(STUDENTS_SRC, /invite_state:\s*status/);
  assert.match(STUDENTS_SRC, /can_resend:/);
  assert.match(STUDENTS_SRC, /deriveInviteStatus\(/,
    'the route must share the one definition, not re-derive its own');
});

test('can_resend mirrors what the resend endpoint will actually accept', () => {
  // A button the API refuses is worse than no button: the instructor clicks it,
  // gets a 409, and concludes the feature is broken.
  const src = STUDENTS_SRC.slice(STUDENTS_SRC.indexOf('can_resend:'));
  const expr = src.slice(0, src.indexOf('\n'));
  assert.match(expr, /canRegen/, 'must keep the provenance gate');
  assert.match(expr, /status !== 'active'/, 'must not offer to re-invite an active account');
  assert.match(expr, /emailable/, 'must not offer to mail an address nothing can reach');
});

test('staff rows are never offered a resend', () => {
  const src = STUDENTS_SRC.slice(STUDENTS_SRC.indexOf('students.unshift('));
  const block = src.slice(0, src.indexOf('\n    }'));
  assert.match(block, /invite_state:\s*'staff'/);
  assert.match(block, /can_resend:\s*false/);
});

test('the roster reports whether email is configured at all', () => {
  // Deliverability is folded into can_resend, so with mail off every resend
  // button vanishes at once. Without this flag nothing on screen says why.
  assert.match(STUDENTS_SRC, /email_enabled:/);
});

// ── the Students tab ─────────────────────────────────────────────────────────

test('THE REGRESSION: Resend is gated on can_resend, never on token liveness', () => {
  const code = withoutComments(PAGE_SRC);
  const ls = code.slice(code.indexOf('async function loadStudents('));
  const body = ls.slice(0, ls.indexOf('\n    }'));

  assert.match(body, /s\.can_resend \?/,
    'the Resend button must be gated on the server-computed can_resend');
  assert.doesNotMatch(body, /activation_pending/,
    'gating on activation_pending is the original bug: it goes false the moment a '
    + 'link expires, so the button vanishes from exactly the rows that need it');
});

test('the table renders a Last sign-in column', () => {
  assert.match(PAGE_SRC, /<th>Last sign-in<\/th>/);
});

test('header and body cell counts match', () => {
  // The hidden cred-col makes this a genuine off-by-one trap: inserting a <td>
  // without its <th> shifts every column right of it, silently.
  const ls = PAGE_SRC.slice(PAGE_SRC.indexOf('async function loadStudents('));
  const body = ls.slice(0, ls.indexOf('\n    }'));

  const thead = body.slice(body.indexOf('<thead>'), body.indexOf('</thead>'));
  // <th[\s>] and not <th, or the enclosing <thead> counts as a cell.
  const headCells = (thead.match(/<th[\s>]/g) || []).length;

  const row = body.slice(body.indexOf('html += `<tr>'), body.indexOf('</tr>`'));
  const bodyCells = (row.match(/<td[\s>]/g) || []).length;

  assert.strictEqual(headCells, bodyCells,
    `${headCells} header cells vs ${bodyCells} body cells — the columns are offset`);
});

test('the summary counts signed-in from last_auth_at, not from activated', () => {
  const ls = PAGE_SRC.slice(PAGE_SRC.indexOf('async function loadStudents('));
  const body = ls.slice(0, ls.indexOf('\n    }'));

  assert.match(body, /const signedIn = roll\.filter\(s => s\.last_auth_at\)/,
    'counting activations would report a cohort section that signs in daily as 0 of N');
});

test('the summary excludes staff rows from the class count', () => {
  const ls = PAGE_SRC.slice(PAGE_SRC.indexOf('async function loadStudents('));
  const body = ls.slice(0, ls.indexOf('\n    }'));
  assert.match(body, /is_self/);
  assert.match(body, /is_course_instructor/);
});

// ── the client ───────────────────────────────────────────────────────────────

test('a successful resend refreshes the roster', () => {
  // Without it the row keeps showing "invite expired" beside a link that is now
  // live again, which reads as the button having failed.
  const src = CLIENT_SRC.slice(CLIENT_SRC.indexOf('async function resendStudentActivation'));
  const fn = src.slice(0, src.indexOf('\n  }\n') + 5);
  assert.match(fn, /loadStudents/);
  assert.match(fn, /err\.message/, 'the 409 names the remaining path and must not be swallowed');
});

test('the resend button is disabled in flight', () => {
  // issueActivationToken revokes before it mints, so a double click kills the
  // link the first click just sent.
  const src = CLIENT_SRC.slice(CLIENT_SRC.indexOf('async function resendStudentActivation'));
  const fn = src.slice(0, src.indexOf('\n  }\n') + 5);
  assert.match(fn, /btn\.disabled = true/);
});

// ── bulk resend ──────────────────────────────────────────────────────────────

test('bulk resend skips anyone who has ever signed in', () => {
  const src = ROSTER_SRC.slice(ROSTER_SRC.indexOf("router.post('/students/activation/resend-all'"));
  const body = src.slice(0, src.indexOf('\nrouter.'));

  assert.match(body, /!u\.activated_at && !u\.last_auth_at/,
    'filtering on activated_at alone would mail a fresh "finish setting up" '
    + 'invitation to an entire cohort section that had been working all week');
  assert.match(body, /canManageAccount/, 'provenance is still enforced per row');
  assert.match(body, /canSendTo/, 'synthetic cohort addresses must never be mailed');
  // `password` as a returned property — the words "New password" appear in the
  // 409 that names the remaining path, and that is prose, not a credential.
  assert.doesNotMatch(body, /password\s*[,:)]/i,
    'a bulk run must never hand back a credential');
});

test('bulk resend reports its cap instead of silently truncating', () => {
  const src = ROSTER_SRC.slice(ROSTER_SRC.indexOf("router.post('/students/activation/resend-all'"));
  const body = src.slice(0, src.indexOf('\nrouter.'));
  assert.match(body, /capped/);
  assert.match(body, /skipped/,
    'a bare success over a partial run is what sends an instructor back to email');
});

test('the bulk route has its own rate limit, mounted before the shared one', () => {
  // Ordering is the whole protection here and is invisible in review. One call
  // can queue a section's worth of mail, so it must not sit only inside the
  // general 20-per-15-minutes roster bucket.
  const server = readSrc(ROOT, 'src', 'server.js');
  const bulk = server.indexOf('bulkResendLimiter);');
  const general = server.indexOf('rosterImportLimiter);');

  assert.notStrictEqual(bulk, -1, 'the bulk limiter is not mounted');
  assert.ok(bulk < general,
    'the tighter bucket must be mounted first or it can be bypassed by ordering');
});

// ── the single resend route ──────────────────────────────────────────────────

test('both plugins refuse to re-invite an already-activated account', () => {
  // Unguarded, this is an instructor-initiated password reset wearing an
  // invitation's clothes: the redeemed link calls completePasswordChange and
  // overwrites a working password, and the account re-appears as "invited".
  const ciab = readSrc(ROOT, 'modules', 'crucible', 'plugins', 'ciab', 'routes', 'section-roster.js');

  for (const [name, src, marker] of [
    ['CLE', ROSTER_SRC, "router.post('/students/:studentId/activation/resend'"],
    ['CIAB', ciab, "router.post('/students/:userId/activation/resend'"],
  ]) {
    const start = src.indexOf(marker);
    assert.notStrictEqual(start, -1, `${name}: the resend route was renamed or removed`);
    const body = src.slice(start, src.indexOf('\nrouter.', start + 10));
    assert.match(body, /activated_at/, `${name}: missing the already-activated guard`);
    assert.match(body, /409/, `${name}: the guard must be a 409, not a silent send`);
  }
});

test('CLE resend requires an encryption key, not just MAIL_ENABLED', () => {
  // Without mailKey, enqueue accepts the row and then suppresses it for having
  // no key to encrypt the body with — after the student's previous link was
  // already revoked.
  const start = ROSTER_SRC.indexOf("router.post('/students/:studentId/activation/resend'");
  const body = ROSTER_SRC.slice(start, ROSTER_SRC.indexOf('\nrouter.', start + 10));
  assert.match(body, /canInvite/,
    'canInvite composes mailEnabled + mailKey + checkRecipient');
});
