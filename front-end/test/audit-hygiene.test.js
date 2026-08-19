/**
 * audit-hygiene.test.js — properties of the audit trail that hold across the
 * whole tree, not inside any one function.
 *
 * Two invariants, both of the kind that only ever break by accident:
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

test('the migration declares no ON UPDATE or purge machinery', () => {
  const sql = fs.readFileSync(path.join(ROOT, 'migrations', '032_audit_log.sql'), 'utf8');
  assert.ok(!/CREATE\s+TRIGGER/i.test(sql), 'no triggers on the audit table');
  // Retention is "keep everything", by decision. If that ever changes it
  // should be a deliberate migration, not something that drifts in.
  assert.ok(!/DELETE\s+FROM\s+cybercore_audit_log/i.test(sql));
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
 * Pull the argument text of every audit.log / audit.batch / logActivity call,
 * by brace-matching from the opening paren. Crude on purpose: it needs to be
 * cheap and to have no dependencies, and a false positive here is a prompt to
 * look, not a broken build.
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
    // The writer itself names these keys in its redaction regex, and the
    // hygiene test names them in this list.
    if (/utils[\\/]audit\.js$/.test(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    for (const call of auditCallArgs(src)) {
      for (const key of FORBIDDEN) {
        // `password_supplied: !!x` is a boolean about a password, not one.
        const re = new RegExp(`\\b${key}\\b(?!_supplied)\\s*:`, 'i');
        if (re.test(call)) {
          offenders.push(`${path.relative(ROOT, file)} → ${key}`);
        }
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
