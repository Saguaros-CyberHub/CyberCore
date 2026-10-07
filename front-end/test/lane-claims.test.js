/**
 * lane-claims.test.js — one definition of "this lane still owns its VXLAN".
 *
 * WHY THIS FILE EXISTS
 * The predicate deciding whether a lane still holds its vxlan_id and gateway WAN
 * address was spelled six different ways across the codebase, and two of the
 * spellings were wrong in opposite directions. That was not a tidiness problem:
 * the allocator's version excluded 'error', handing a failed lane's VXLAN
 * straight back to the next deploy, while the audit counted that same lane's
 * VMIDs as accounted-for. A lane's machines were therefore invisible to the
 * audit at the exact moment its id was being reissued — and once a new lane took
 * it, the contested-VXLAN guard in teardownLanes correctly refused to let the old
 * row destroy anything, ever. Those machines could not be found or removed by
 * any code path.
 *
 * So the constants below are load-bearing, and the grep at the bottom is what
 * stops a seventh spelling appearing.
 *
 * Run: node front-end/test/lane-claims.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const C = require(path.join(__dirname, '..', 'src', 'utils', 'lane-claims.js'));

// ── vocabulary ──────────────────────────────────────────────────────────────

test('claiming and released statuses partition the enum exactly', () => {
  // The full set is the cybercore_lane_status enum in
  // config/postgres/001_init_db.sql. A value in neither list would be silently
  // treated as claim-less by holdsInfra and as claiming by the SQL predicate —
  // the exact disagreement this module exists to prevent.
  const enumValues = ['pending', 'deploying', 'active', 'suspended', 'error', 'deleted'];
  assert.deepStrictEqual([...C.ALL_STATUSES].sort(), [...enumValues].sort());

  const overlap = C.CLAIMING_STATUSES.filter(s => C.RELEASED_STATUSES.includes(s));
  assert.deepStrictEqual(overlap, [], 'a status cannot both hold and release');
});

test('holdsInfra agrees with the SQL predicate for every status', () => {
  // The JS and SQL forms are used on the same rows by the audit and the
  // allocator respectively. If they ever disagree, one of them is handing out an
  // id the other thinks is taken.
  for (const status of C.ALL_STATUSES) {
    const sqlSaysClaims = !C.RELEASED_STATUSES.includes(status);
    assert.strictEqual(C.holdsInfra({ status }), sqlSaysClaims,
      `holdsInfra disagrees with "${C.CLAIMS_SQL}" for status '${status}'`);
  }
});

test('holdsInfra is false for junk rather than throwing', () => {
  assert.strictEqual(C.holdsInfra(null), false);
  assert.strictEqual(C.holdsInfra(undefined), false);
  assert.strictEqual(C.holdsInfra({}), false);
  assert.strictEqual(C.holdsInfra({ status: 'not-a-status' }), false);
});

test('claimsSql qualifies with an alias, and refuses an injectable one', () => {
  assert.strictEqual(C.claimsSql(), "status NOT IN ('error', 'deleted')");
  assert.strictEqual(C.claimsSql('l'), "l.status NOT IN ('error', 'deleted')");
  assert.strictEqual(C.claimsSql(undefined), C.CLAIMS_SQL);
  // The alias is interpolated into SQL, so it is validated rather than trusted.
  assert.throws(() => C.claimsSql('l; DROP TABLE cybercore_lane --'), /refusing to build SQL/);
  assert.throws(() => C.claimsSql('a b'), /refusing to build SQL/);
});

// ── the guard that stops a seventh spelling ─────────────────────────────────

const ROOT = path.join(__dirname, '..');

/** Every .js file under src/ and modules/, skipping node_modules. */
function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

test('no file spells the claim predicate by hand any more', () => {
  const files = [
    ...walk(path.join(ROOT, 'src')),
    ...walk(path.join(ROOT, 'modules')),
  ].filter(f => !f.endsWith(path.join('utils', 'lane-claims.js')));

  // Only the CLAIM predicate — a status list naming both 'error' and 'deleted'.
  //
  // Deliberately narrow. Plenty of other queries filter cybercore_lane on status
  // to answer a DIFFERENT question ("which of this user's lanes are usable" uses
  // IN ('active','suspended')), and enrolment rows carry their own unrelated
  // status vocabulary. Flagging those would train people to ignore this test.
  // The {error, deleted} pair is unambiguous: that set exists only to express
  // "has this lane given its resources back".
  const CLAIM_PAIR = /\bstatus\s+NOT\s+IN\s*\(\s*'(error|deleted)'\s*,\s*'(error|deleted)'\s*\)/i;
  const offenders = [];
  for (const file of files) {
    const src = fs.readFileSync(file, 'utf8');
    if (!src.includes('cybercore_lane')) continue;
    src.split(/\r?\n/).forEach((line, i) => {
      const trimmed = line.trim();
      // Skip prose: SQL comments and JS comments quoting the old form on purpose.
      if (trimmed.startsWith('--') || trimmed.startsWith('*') || trimmed.startsWith('//')) return;
      if (!CLAIM_PAIR.test(line)) return;
      offenders.push(`${path.relative(ROOT, file)}:${i + 1}  ${trimmed}`);
    });
  }

  assert.deepStrictEqual(offenders, [],
    'These lines spell the lane claim predicate inline. Use claimsSql() from '
    + 'utils/lane-claims.js instead — divergent copies of this predicate are what '
    + "let a failed lane's VXLAN be reissued while its machines were still "
    + 'running, with the audit simultaneously counting them as accounted-for:\n'
    + offenders.join('\n'));
});

test('the allocator and the WAN allocator both go through claimsSql', () => {
  // These two decide what the next deploy is handed. If either drifts back to a
  // literal, the audit and the allocator can disagree again without any test
  // failing on behaviour.
  for (const rel of ['src/utils/lane-deployer.js', 'src/utils/lane-wan-allocator.js']) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    assert.match(src, /require\(['"]\.\/lane-claims['"]\)/, `${rel} must import lane-claims`);
    assert.match(src, /\$\{claimsSql\(/, `${rel} must interpolate claimsSql()`);
  }
});
