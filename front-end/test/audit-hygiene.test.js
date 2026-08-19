/**
 * audit-hygiene.test.js — properties of the audit trail that hold across the
 * whole tree, not inside any one function.
 *
 * The invariants here are all of the kind that only ever break by accident:
 *
 *   1. APPEND-ONLY. Nothing updates or deletes a row in cybercore_audit_log.
 *      This is enforced by construction — src/utils/audit.js exposes only
 *      inserts — rather than by a trigger, because a trigger would also block
 *      legitimate backfill fixups and schema evolution. A grep is what keeps
 *      the construction honest.
 *
 *   2. NO CREDENTIALS IN METADATA. redact() in the writer is a backstop, but
 *      the actual guarantee is that call sites never pass one. The audit table
 *      is plaintext and adminer is published on 0.0.0.0:8181, which is the
 *      same reasoning that made 029_email_outbox.sql encrypt mail bodies:
 *      activation links are working credentials until redeemed.
 *
 *   3. NO BARE jsonb ? OPERATOR, and a legacy-id predicate that is identical
 *      in all three places it appears. Both learned the hard way — see the
 *      individual tests.
 *
 * Run: node front-end/test/audit-hygiene.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ROOTS = [path.join(ROOT, 'src'), path.join(ROOT, 'modules')];

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.name.endsWith('.js')) out.push(full);
  }
  return out;
}

const JS_FILES = ROOTS.flatMap(r => walk(r));

/** Source with comments stripped, for checks that must not match prose. */
function codeOnly(file) {
  return fs.readFileSync(file, 'utf8')
    .replace(/--.*$/gm, '')
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
}

test('the source tree contains no UPDATE or DELETE against the audit table', () => {
  const offenders = [];
  for (const file of JS_FILES) {
    const src = fs.readFileSync(file, 'utf8');
    if (/UPDATE\s+cybercore_audit_log/i.test(src) || /DELETE\s+FROM\s+cybercore_audit_log/i.test(src)) {
      offenders.push(path.relative(ROOT, file));
    }
  }
  assert.deepStrictEqual(offenders, [], 'the audit log must stay append-only');
});

test('the migration declares no trigger or purge machinery', () => {
  const sql = fs.readFileSync(path.join(ROOT, 'migrations', '032_audit_log.sql'), 'utf8');
  assert.ok(!/CREATE\s+TRIGGER/i.test(sql), 'no triggers on the audit table');
  // Retention is "keep everything", by decision. If that ever changes it
  // should be a deliberate migration, not something that drifts in.
  assert.ok(!/DELETE\s+FROM\s+cybercore_audit_log/i.test(sql));
});

const SQL_BEARING_FILES = [
  path.join(ROOT, 'migrations', '032_audit_log.sql'),
  path.join(ROOT, 'src', 'utils', 'audit.js'),
  path.join(ROOT, 'scripts', 'backfill-audit-log.js'),
  path.join(ROOT, 'src', 'routes', 'admin', 'audit.js'),
];

test('no SQL uses the bare jsonb ? operator', () => {
  // Adminer — and several other clients — treat a bare ? as a bind placeholder
  // and rewrite it to $1 before the server ever sees it, so
  // `WHERE metadata ? 'legacy_id'` arrives as `WHERE metadata $1 'legacy_id'`
  // and the import dies with a syntax error. The arrow form means the same
  // thing for every value this code writes.
  for (const file of SQL_BEARING_FILES) {
    assert.ok(
      !/\b(metadata|context|config|changes)\s+\?\s+'/.test(codeOnly(file)),
      `${path.relative(ROOT, file)} uses the jsonb ? operator, which some clients eat`
    );
  }
});

test('the legacy-id index predicate is identical everywhere it appears', () => {
  // A partial unique index can only be inferred by ON CONFLICT when the
  // predicate matches the index exactly. If these three drift apart the
  // backfill stops being re-runnable — it starts erroring on a duplicate key
  // instead of skipping, which is the failure this index exists to prevent.
  const PREDICATE = "WHERE (metadata->>'legacy_id') IS NOT NULL";

  const sites = {
    'migrations/032_audit_log.sql':   path.join(ROOT, 'migrations', '032_audit_log.sql'),
    'src/utils/audit.js':             path.join(ROOT, 'src', 'utils', 'audit.js'),
    'scripts/backfill-audit-log.js':  path.join(ROOT, 'scripts', 'backfill-audit-log.js'),
  };
  for (const [label, file] of Object.entries(sites)) {
    assert.ok(fs.readFileSync(file, 'utf8').includes(PREDICATE), `${label} must use the shared predicate`);
  }
});

test('ensureAuditLog mirrors every index the migration declares', () => {
  // The migration is applied by hand; ensureAuditLog() is what an existing
  // deployment actually gets on restart. An index in one and not the other is
  // a query that is fast in testing and slow in production.
  const sql = fs.readFileSync(path.join(ROOT, 'migrations', '032_audit_log.sql'), 'utf8');
  const ensure = fs.readFileSync(path.join(ROOT, 'src', 'utils', 'audit.js'), 'utf8');

  const names = [...sql.matchAll(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)/gi)].map(m => m[1]);
  assert.ok(names.length >= 8, 'the migration declares its index set');
  for (const name of names) {
    assert.ok(ensure.includes(name), `ensureAuditLog() is missing index ${name}`);
  }
});

test('nothing follows the last semicolon in the migration', () => {
  // Adminer splits a script on ';' and sends each piece as its own statement.
  // A trailing comment block therefore becomes a final comment-only query,
  // which Postgres answers with an empty result and Adminer surfaces as
  // "Error in query: Unknown error." — after every real statement has already
  // succeeded. It reads like a failed migration and is not one.
  // (migrations/009_multi_vm_support.sql has the same latent papercut.)
  const code = fs.readFileSync(path.join(ROOT, 'migrations', '032_audit_log.sql'), 'utf8')
    .replace(/--.*$/gm, '');
  assert.strictEqual(code.split(';').pop().trim(), '', 'no content after the final statement');
});

test('the migration and ensureAuditLog agree on the statement set', () => {
  const code = fs.readFileSync(path.join(ROOT, 'migrations', '032_audit_log.sql'), 'utf8')
    .replace(/--.*$/gm, '');
  const statements = code.split(';').map(s => s.trim()).filter(Boolean);
  // 1 table + 9 indexes + pg_trgm + the trigram index. If this count moves,
  // ensureAuditLog() needs the same change or an existing deployment silently
  // ends up with a different schema from a hand-applied one.
  assert.strictEqual(statements.length, 12);
});

// Keys that must never appear in an audit call's metadata literal. `password`
// covers temp_password / guac_password / password_hash; the rest are the live
// credentials this platform actually hands out.
const FORBIDDEN = [
  'temp_password', 'password_hash', 'guac_password', 'plaintext',
  'mfa_secret', 'recovery_code', 'activation_token', 'activation_url',
  'access_token', 'jwt', 'authToken',
];

/**
 * Pull the argument text of every audit call, by paren-matching from the
 * opening paren. Crude on purpose: it needs to be cheap and dependency-free,
 * and a false positive here is a prompt to look, not a broken build.
 */
function auditCallArgs(src) {
  const out = [];
  const re = /\b(?:audit\.(?:log|logMany|batch)|logActivity|auditAuth|auditProvision)\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    let depth = 0;
    let i = m.index + m[0].length - 1;
    const start = i;
    for (; i < src.length; i++) {
      if (src[i] === '(') depth++;
      else if (src[i] === ')') { depth--; if (depth === 0) break; }
    }
    out.push(src.slice(start, i + 1));
  }
  return out;
}

test('no audit call site passes a credential in its metadata', () => {
  const offenders = [];
  for (const file of JS_FILES) {
    // The writer itself names these keys in its redaction regex.
    if (/utils[\\/]audit\.js$/.test(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    for (const call of auditCallArgs(src)) {
      for (const key of FORBIDDEN) {
        // `password_supplied: !!x` is a boolean about a password, not one.
        const re = new RegExp(`\\b${key}\\b(?!_supplied)\\s*:`, 'i');
        if (re.test(call)) offenders.push(`${path.relative(ROOT, file)} → ${key}`);
      }
    }
  }
  assert.deepStrictEqual(offenders, [], 'credentials must never reach the audit table');
});

test('the auth instrumentation records the typed email but never the password', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'auth.js'), 'utf8');

  // A failed login must be attributable to the address that was tried —
  // otherwise the trail cannot answer "who is being guessed at".
  assert.ok(
    /auditAuth\(req, 'auth\.login', \{ email, status: 'failure', reason: 'unknown_user' \}\)/.test(src),
    'an unknown-user login failure records the typed address'
  );

  for (const call of auditCallArgs(src)) {
    assert.ok(!/\bpassword\b\s*[,:)]/.test(call), `password leaked into an audit call: ${call.slice(0, 120)}`);
    assert.ok(!/newPassword/.test(call), 'a chosen password must never be logged');
    assert.ok(!/\btoken\b\s*:/.test(call), 'an activation or session token must never be logged');
  }
});

test('the four coverage areas the operator asked for are all instrumented', () => {
  const all = JS_FILES.map(f => fs.readFileSync(f, 'utf8')).join('\n');

  const required = {
    'auth (incl. failed logins)': /'auth\.login'/,
    'students being added':       /'enrollment\.student_added'/,
    'roster imports':             /'enrollment\.roster_imported'/,
    'VM/lane deploys':            /'lane\.deployed'|'vm\.provisioned'/,
    'VM/lane teardown':           /'lane\.destroyed'|'vm\.destroyed'/,
    'remote script execution':    /'vm\.script_executed'/,
    'bulk account deletion':      /'user\.deleted'/,
    'privilege denial':           /'access\.denied'/,
    'admin config changes':       /'config\.modules_updated'/,
  };

  for (const [what, re] of Object.entries(required)) {
    assert.ok(re.test(all), `${what} has no audit call site`);
  }
});
