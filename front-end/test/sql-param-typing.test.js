/**
 * sql-param-typing.test.js — the parameter-typing mistake that takes a whole
 * feature down at parse time, everywhere, silently.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * mailer.js once wrote:
 *
 *     CASE WHEN $5::boolean AND $8 IS NOT NULL THEN pgp_sym_encrypt($8, $7) END
 *
 * PostgreSQL fixes a parameter's type at its FIRST reference. `$8 IS NOT NULL`
 * is a NullTest, which supplies no type, so $8 stayed `unknown` and the whole
 * INSERT failed to parse:
 *
 *     could not determine data type of parameter $8
 *
 * Deterministic, value-independent, and fatal to every enqueue() call in every
 * deployment — activation invites, course notices, password notices and admin
 * broadcasts all landed in the same catch block, which logs and returns
 * "suppressed" rather than throwing. So the platform reported that it had
 * handled the mail while queueing none of it.
 *
 * $6 on the same line was fine only by luck: it happened to appear first inside
 * pgp_sym_encrypt(), which does type its argument.
 *
 * A pure source scan — no database, and it catches the pattern anywhere in the
 * tree rather than only in the statement that got it wrong first.
 *
 * Run: node front-end/test/sql-param-typing.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
// Plugins write raw SQL too -- the CLE attack console and CIAB both do -- and
// scanning only src/ let every one of them opt out of this check by accident.
// Same roots audit-hygiene.test.js walks, for the same reason.
const ROOTS = [SRC, path.join(ROOT, 'modules')];

function jsFiles(dir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    // vendor bundles are minified third-party code, and node_modules is not ours
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'vendor') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...jsFiles(full));
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/**
 * A parameter placed straight into a NULL test with no cast. `$8::text IS NOT
 * NULL` is fine; `$8 IS NOT NULL` is the bug.
 */
const UNCAST_NULLTEST = /\$\d+\s+IS\s+(?:NOT\s+)?NULL/gi;

test('no query puts an uncast parameter in a NULL test', () => {
  const offenders = [];

  for (const file of ROOTS.flatMap((r) => jsFiles(r))) {
    const source = fs.readFileSync(file, 'utf8');
    // split on /\r?\n/, not '\n'. With core.autocrlf=true a Windows checkout
    // leaves a trailing \r on every line, and \r is a line terminator to a JS
    // regex — so `.` cannot cross it, /\/\/.*$/ fails to match, and the comment
    // stripper below silently stops stripping. That turns the explanatory comment
    // in mailer.js, which quotes the broken form on purpose, into a false
    // positive: the test fails on Windows and passes in CI.
    source.split(/\r?\n/).forEach((line, i) => {
      // The explanatory comment in mailer.js quotes the broken form on purpose.
      const code = line.replace(/--.*$/, '').replace(/\/\/.*$/, '');
      for (const match of code.match(UNCAST_NULLTEST) || []) {
        offenders.push(`${path.relative(ROOT, file)}:${i + 1}  ${match.trim()}`);
      }
    });
  }

  assert.deepStrictEqual(offenders, [],
    'Cast the parameter on its first reference (e.g. $8::text IS NOT NULL), or ' +
    'Postgres cannot determine its type and the statement fails to parse:\n  ' +
    offenders.join('\n  '));
});

test('the enqueue INSERT casts every parameter it encrypts', () => {
  // The specific statement that failed in production, pinned directly.
  const source = fs.readFileSync(path.join(SRC, 'utils', 'mailer.js'), 'utf8');
  const insert = source.slice(
    source.indexOf('INSERT INTO cybercore_email_outbox'),
    source.indexOf('RETURNING email_id, status')
  );

  assert.ok(insert.length > 0, 'could not find the enqueue INSERT');
  for (const bare of insert.match(/pgp_sym_encrypt\(\s*\$\d+\s*,/g) || []) {
    assert.fail(`pgp_sym_encrypt receives an uncast parameter: ${bare}`);
  }
  assert.match(insert, /\$8::text IS NOT NULL/,
    '$8 must be cast where it is first referenced, not only inside pgp_sym_encrypt()');
});
