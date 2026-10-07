/**
 * broadcast-audience.test.js — who a broadcast actually reaches.
 *
 * The admin Broadcast tab promises an exact recipient count before anything is
 * queued. Everything that promise rests on is a pure function in
 * broadcast-audience.js, and this file pins the ones that would be expensive to
 * get wrong:
 *
 *   - normalizeSpec — whitelists roles, rejects malformed ids BEFORE Postgres
 *     sees them, and is deterministic, because the preview/send fingerprint
 *     hashes its output
 *   - dedupeRecipients — one message per mailbox, and the source carrying a
 *     name wins, so nobody the platform knows gets greeted as a stranger
 *   - splitByPolicy — the specific reason beats the general one
 *   - fingerprint — changes when the audience or the message changes, and only
 *     then
 *
 * Pure reads and pure transforms, so like mailer-policy.test.js this needs no
 * database and no relay.
 *
 * Run: node front-end/test/broadcast-audience.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const audience = require(path.join(__dirname, '..', 'src', 'utils', 'broadcast-audience'));

const UUID_A = '7f1c9e3a-0b2d-4c5e-8a9f-1234567890ab';
const UUID_B = '1a2b3c4d-5e6f-4a8b-9c0d-abcdef123456';

/** A stand-in for mailer.checkRecipient, so these tests never read env. */
const allowAll = () => ({ ok: true });
const blockDomain = (domain) => (addr) =>
  addr.endsWith(domain) ? { ok: false, reason: `reserved domain that cannot receive mail` } : { ok: true };

function user(email, extra = {}) {
  return {
    user_id: extra.user_id || UUID_A,
    email,
    first_name: extra.first_name ?? 'Ada',
    last_name: extra.last_name ?? 'Lovelace',
    role: extra.role ?? 'student',
    organization: extra.organization ?? 'Pima CC',
    active: extra.active ?? true,
    status: extra.status ?? 'active',
  };
}

// ── address parsing ──────────────────────────────────────────────────────────

test('parseAddressList: splits on commas, semicolons and any whitespace', () => {
  const { addresses } = audience.parseAddressList('a@x.edu, b@x.edu;c@x.edu\nd@x.edu\te@x.edu');
  assert.deepStrictEqual(addresses, ['a@x.edu', 'b@x.edu', 'c@x.edu', 'd@x.edu', 'e@x.edu']);
});

test('parseAddressList: lowercases, trims and de-duplicates', () => {
  const { addresses } = audience.parseAddressList('  Ada@Example.EDU , ada@example.edu ');
  assert.deepStrictEqual(addresses, ['ada@example.edu']);
});

test('parseAddressList: reports unusable tokens instead of dropping them', () => {
  // A silently discarded address is how someone finds out a month later that a
  // student never got the announcement.
  const { addresses, invalid } = audience.parseAddressList('good@x.edu, notanaddress, @x.edu');
  assert.deepStrictEqual(addresses, ['good@x.edu']);
  assert.deepStrictEqual(invalid, ['@x.edu', 'notanaddress']);
});

test('parseAddressList: accepts an array as readily as a blob', () => {
  const { addresses } = audience.parseAddressList(['a@x.edu', 'b@x.edu']);
  assert.deepStrictEqual(addresses, ['a@x.edu', 'b@x.edu']);
});

test('parseAddressList: survives null, undefined and empty input', () => {
  for (const input of [null, undefined, '', '   ', []]) {
    assert.deepStrictEqual(audience.parseAddressList(input), { addresses: [], invalid: [] });
  }
});

// ── spec normalization ───────────────────────────────────────────────────────

test('normalizeSpec: keeps only real roles and discards the rest', () => {
  const spec = audience.normalizeSpec({ roles: ['student', 'ADMIN', 'superuser', ''] });
  assert.deepStrictEqual(spec.roles, ['admin', 'student']);
});

test('normalizeSpec: only the two known activity states survive', () => {
  assert.strictEqual(audience.normalizeSpec({ activity: 'active' }).activity, 'active');
  assert.strictEqual(audience.normalizeSpec({ activity: 'inactive' }).activity, 'inactive');
  for (const bogus of ['deleted', 'banned', 'ACTIVE', true, null]) {
    assert.strictEqual(audience.normalizeSpec({ activity: bogus }).activity, null,
      `"${bogus}" was accepted as an activity filter`);
  }
});

test('normalizeSpec: rejects malformed user ids rather than passing them to Postgres', () => {
  // `= ANY($1::uuid[])` raises 22P02 on a bad id, turning one typo into a 500.
  const spec = audience.normalizeSpec({ userIds: [UUID_A, 'nope', '', '123'] });
  assert.deepStrictEqual(spec.userIds, [UUID_A]);
  assert.deepStrictEqual(spec.rejected.userIds, ['123', 'nope']);
});

test('normalizeSpec: is deterministic, because the fingerprint hashes it', () => {
  const a = audience.normalizeSpec({ roles: ['student', 'admin'], userIds: [UUID_B, UUID_A], addresses: 'b@x.edu, a@x.edu' });
  const b = audience.normalizeSpec({ roles: ['admin', 'student'], userIds: [UUID_A, UUID_B], addresses: 'a@x.edu\nb@x.edu' });
  assert.deepStrictEqual(a, b, 'two spellings of one audience must normalize identically');
});

test('normalizeSpec: survives garbage where arrays were expected', () => {
  const spec = audience.normalizeSpec({ roles: 'student', organizations: 42, userIds: null });
  assert.deepStrictEqual(spec.roles, []);
  assert.deepStrictEqual(spec.organizations, []);
  assert.deepStrictEqual(spec.userIds, []);
});

test('normalizeSpec: excludeSelf is opt-in and strictly boolean', () => {
  assert.strictEqual(audience.normalizeSpec({}).excludeSelf, false);
  assert.strictEqual(audience.normalizeSpec({ excludeSelf: 'yes' }).excludeSelf, false);
  assert.strictEqual(audience.normalizeSpec({ excludeSelf: true }).excludeSelf, true);
});

test('isEmptySpec: an audience naming nobody is empty, and one naming anybody is not', () => {
  assert.strictEqual(audience.isEmptySpec(audience.normalizeSpec({})), true);
  // Nothing usable survived normalization, so this is still "nobody".
  assert.strictEqual(audience.isEmptySpec(audience.normalizeSpec({ roles: ['nope'] })), true);
  for (const named of [{ roles: ['student'] }, { activity: 'active' }, { organizations: ['x'] },
    { userIds: [UUID_A] }, { addresses: 'a@x.edu' }]) {
    assert.strictEqual(audience.isEmptySpec(audience.normalizeSpec(named)), false,
      `${JSON.stringify(named)} names someone`);
  }
});

// ── query building ───────────────────────────────────────────────────────────

test('buildFilterQuery: returns null when no filter field was set', () => {
  assert.strictEqual(audience.buildFilterQuery(audience.normalizeSpec({ userIds: [UUID_A] })), null);
});

test('buildFilterQuery: an unset facet becomes a NULL parameter, not a literal', () => {
  const q = audience.buildFilterQuery(audience.normalizeSpec({ roles: ['student'] }));
  assert.deepStrictEqual(q.params, [['student'], null, null]);
  assert.ok(!/\$\d[^:]*'/.test(q.text.replace(/'active'|'inactive'|'deleted', 'banned'/g, '')),
    'values must be bound, never interpolated');
});

test('buildFilterQuery: deleted and banned accounts are excluded unconditionally', () => {
  // Not a filter the admin can relax: that mailbox may belong to someone who
  // has left the institution.
  for (const spec of [{ roles: ['student'] }, { activity: 'inactive' }, { organizations: ['x'] }]) {
    const q = audience.buildFilterQuery(audience.normalizeSpec(spec));
    assert.match(q.text, /status NOT IN \('deleted', 'banned'\)/);
  }
});

test('buildFilterQuery: "active" demands both columns agree', () => {
  const q = audience.buildFilterQuery(audience.normalizeSpec({ activity: 'active' }));
  assert.match(q.text, /active = TRUE AND status = 'active'/);
});

test('buildPickedQuery: keeps the hard block but applies no role or status filter', () => {
  // Picking someone by name means picking them.
  const q = audience.buildPickedQuery(audience.normalizeSpec({ userIds: [UUID_A], roles: ['instructor'] }));
  assert.deepStrictEqual(q.params, [[UUID_A]]);
  assert.match(q.text, /status NOT IN \('deleted', 'banned'\)/);
  assert.ok(!/role = ANY/.test(q.text));
});

test('buildPickedQuery: returns null when nobody was picked', () => {
  assert.strictEqual(audience.buildPickedQuery(audience.normalizeSpec({ roles: ['student'] })), null);
});

// ── deduplication ────────────────────────────────────────────────────────────

test('dedupeRecipients: one message per mailbox, however many sources named it', () => {
  const { recipients, duplicatesRemoved } = audience.dedupeRecipients([
    { source: 'filter', rows: [audience.toRecipient(user('ada@x.edu'))] },
    { source: 'picked', rows: [audience.toRecipient(user('ada@x.edu'))] },
    { source: 'pasted', rows: [audience.anonymousRecipient('ada@x.edu')] },
  ]);
  assert.strictEqual(recipients.length, 1);
  assert.strictEqual(duplicatesRemoved, 2);
});

test('dedupeRecipients: the source that knows the person wins', () => {
  // Otherwise someone the platform has a first name for is greeted "Hi,".
  const { recipients } = audience.dedupeRecipients([
    { source: 'filter', rows: [audience.toRecipient(user('ada@x.edu', { first_name: 'Ada' }))] },
    { source: 'pasted', rows: [audience.anonymousRecipient('ada@x.edu')] },
  ]);
  assert.strictEqual(recipients[0].first_name, 'Ada');
  assert.strictEqual(recipients[0].source, 'filter');
});

test('dedupeRecipients: matching is case-insensitive', () => {
  const { recipients } = audience.dedupeRecipients([
    { source: 'filter', rows: [audience.toRecipient(user('Ada@X.edu'))] },
    { source: 'pasted', rows: [audience.anonymousRecipient('ada@x.edu')] },
  ]);
  assert.strictEqual(recipients.length, 1);
  assert.strictEqual(recipients[0].email, 'ada@x.edu', 'the stored address must be canonicalised');
});

test('dedupeRecipients: counts what each source contributed', () => {
  const { sources } = audience.dedupeRecipients([
    { source: 'filter', rows: [audience.toRecipient(user('a@x.edu')), audience.toRecipient(user('b@x.edu'))] },
    { source: 'picked', rows: [] },
    { source: 'pasted', rows: [audience.anonymousRecipient('c@x.edu')] },
  ]);
  assert.deepStrictEqual(sources, { filter: 2, picked: 0, pasted: 1 });
});

test('dedupeRecipients: a row with no usable address is skipped, not counted', () => {
  const { recipients, sources } = audience.dedupeRecipients([
    { source: 'filter', rows: [{ email: '   ' }, audience.toRecipient(user('a@x.edu'))] },
  ]);
  assert.strictEqual(recipients.length, 1);
  assert.strictEqual(sources.filter, 1);
});

// ── policy split ─────────────────────────────────────────────────────────────

test('splitByPolicy: separates deliverable from suppressed, carrying the reason', () => {
  const recipients = [
    audience.anonymousRecipient('ada@example.edu'),
    audience.anonymousRecipient('student1@clinic.local'),
  ];
  const { deliverable, suppressed } = audience.splitByPolicy(recipients, blockDomain('.local'));
  assert.deepStrictEqual(deliverable.map(r => r.email), ['ada@example.edu']);
  assert.strictEqual(suppressed.length, 1);
  assert.match(suppressed[0].reason, /reserved domain/);
});

test('splitByPolicy: a server-wide block suppresses absolutely everyone', () => {
  // The trap this closes: sendTest() does not check MAIL_ENCRYPT_KEY but
  // enqueue() does, so a successful test send is NOT proof a broadcast will go.
  const recipients = [audience.anonymousRecipient('ada@example.edu')];
  const { deliverable, suppressed } = audience.splitByPolicy(recipients, allowAll, 'email is not configured on this server');
  assert.strictEqual(deliverable.length, 0);
  assert.strictEqual(suppressed[0].reason, 'email is not configured on this server');
});

test('splitByPolicy: the specific reason beats the server-wide one', () => {
  // Matches the order inside enqueue(): "reserved domain" tells the admin more
  // than "email is not configured".
  const { suppressed } = audience.splitByPolicy(
    [audience.anonymousRecipient('bot@clinic.local')],
    blockDomain('.local'),
    'email is not configured on this server'
  );
  assert.match(suppressed[0].reason, /reserved domain/);
});

test('groupSuppressionReasons: collapses to counts, biggest first, with examples', () => {
  const suppressed = [
    { email: 'a@clinic.local', reason: 'reserved' },
    { email: 'b@clinic.local', reason: 'reserved' },
    { email: 'c@cohort.invalid', reason: 'synthetic' },
  ];
  const groups = audience.groupSuppressionReasons(suppressed);
  assert.deepStrictEqual(groups.map(g => [g.reason, g.count]), [['reserved', 2], ['synthetic', 1]]);
  assert.deepStrictEqual(groups[0].examples, ['a@clinic.local', 'b@clinic.local']);
});

test('groupSuppressionReasons: caps examples so a 400-row report stays readable', () => {
  const many = Array.from({ length: 40 }, (_, i) => ({ email: `u${i}@clinic.local`, reason: 'reserved' }));
  const [group] = audience.groupSuppressionReasons(many, 5);
  assert.strictEqual(group.count, 40);
  assert.strictEqual(group.examples.length, 5);
});

// ── active/status divergence ─────────────────────────────────────────────────

test('divergenceCount: counts rows whose two active flags disagree', () => {
  assert.strictEqual(audience.divergenceCount([
    { active: true, status: 'active' },      // agrees
    { active: false, status: 'inactive' },   // agrees
    { active: true, status: 'suspended' },   // disagrees
    { active: false, status: 'active' },     // disagrees
  ]), 2);
});

test('divergenceCount: an anonymous recipient has no flags to disagree about', () => {
  assert.strictEqual(audience.divergenceCount([audience.anonymousRecipient('a@x.edu')]), 0);
});

// ── fingerprint ──────────────────────────────────────────────────────────────

const MSG = { subject: 'Lab 3', bodyText: 'Opens Monday.', buttonLabel: '', buttonUrl: '', includeGreeting: true };

test('fingerprint: identical inputs hash identically, whatever the ordering', () => {
  const spec = audience.normalizeSpec({ roles: ['student'] });
  assert.strictEqual(
    audience.fingerprint(spec, ['b@x.edu', 'a@x.edu'], MSG),
    audience.fingerprint(spec, ['a@x.edu', 'b@x.edu'], MSG)
  );
});

test('fingerprint: changes when the audience changes at constant size', () => {
  // The reason a recipient COUNT is not enough: one account added and one
  // removed between preview and confirm leaves the count identical.
  const spec = audience.normalizeSpec({ roles: ['student'] });
  assert.notStrictEqual(
    audience.fingerprint(spec, ['a@x.edu', 'b@x.edu'], MSG),
    audience.fingerprint(spec, ['a@x.edu', 'c@x.edu'], MSG)
  );
});

test('fingerprint: changes when the message changes', () => {
  // Closes the other half of the window: preview, edit the subject, confirm.
  const spec = audience.normalizeSpec({ roles: ['student'] });
  const emails = ['a@x.edu'];
  const base = audience.fingerprint(spec, emails, MSG);
  for (const edit of [{ subject: 'Lab 4' }, { bodyText: 'Opens Tuesday.' },
    { buttonUrl: 'https://example.org' }, { includeGreeting: false }]) {
    assert.notStrictEqual(audience.fingerprint(spec, emails, { ...MSG, ...edit }), base,
      `editing ${Object.keys(edit)[0]} did not change the fingerprint`);
  }
});

test('fingerprint: changes when the spec changes even if the result set does not', () => {
  const emails = ['a@x.edu'];
  assert.notStrictEqual(
    audience.fingerprint(audience.normalizeSpec({ roles: ['student'] }), emails, MSG),
    audience.fingerprint(audience.normalizeSpec({ roles: ['instructor'] }), emails, MSG)
  );
});
