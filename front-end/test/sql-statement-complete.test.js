/**
 * sql-statement-complete.test.js -- SQL that never finished being written.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * challenge-lane-deployer.rebuildLaneChallengeVms shipped with all four of its
 * statements gutted down to their first line:
 *
 *     SELECT lane_id, user_id, module_key, name, status, vxlan_id,   <- trailing comma
 *     SELECT spec FROM crucible_challenge                            <- no WHERE
 *     UPDATE cybercore_lane                                          <- no SET, no WHERE
 *     UPDATE cybercore_lane l                                        <- same
 *
 * Each still looked like SQL, so nothing in review or at require time noticed.
 * The first one reached Postgres as `syntax error at end of input` the moment an
 * instructor pressed Redeploy on a single machine -- and the two UPDATEs, had
 * parsing got that far, were a missing-WHERE away from rewriting every lane in
 * the table.
 *
 * A sibling in cle/routes/vms.js had the same shape (`SELECT id FROM
 * cybercore_template_catalog` with a params array and no $1), which fails at
 * PARSE time and so takes out the workstation redeploy for a reason that names
 * neither templates nor SQL.
 *
 * Cheap to catch statically, and value-independent: a statement that binds
 * parameters must reference them, and one that ends on a clause keyword or a
 * dangling comma was never finished. A pure source scan -- no database.
 *
 * Run: node front-end/test/sql-statement-complete.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

/** Every tracked .js in the app, excluding tests and vendored code. */
function sourceFiles() {
  const out = execFileSync('git', ['ls-files', '*.js'], { cwd: ROOT, encoding: 'utf8' });
  return out.split('\n')
    .map((f) => f.trim())
    .filter(Boolean)
    .filter((f) => !f.startsWith('test/'))
    .filter((f) => !f.includes('node_modules') && !f.includes('/vendor/'));
}

/**
 * Query call sites with a template-literal statement.
 *
 * Deliberately only matches a literal with no `${}` in it. An interpolated
 * statement builds its WHERE clause and its $N numbering at runtime (the audit
 * and cluster log endpoints do exactly that, with `$${idx}`), so a static read
 * of one says nothing true -- and a check that reports those as broken would be
 * turned off within a week.
 */
function staticQueries(src) {
  const out = [];
  // Tempered: reject a literal containing ${...} INTERPOLATION, but keep one
  // containing $1 PARAMETERS -- which is nearly every statement worth checking.
  // [^`$]* excluded both, and every assertion below then passed on an empty set.
  const re = /\b(?:cybercoreQuery|clinicQuery|query|client\.query)\s*\(\s*`((?:[^`$]|\$(?!\{))*)`\s*(,\s*\[)?/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const sql = m[1];
    if (!/\b(SELECT|INSERT|UPDATE|DELETE)\b/i.test(sql)) continue;
    out.push({
      sql,
      hasParams: !!m[2],
      line: src.slice(0, m.index).split('\n').length,
    });
  }
  return out;
}

const FILES = sourceFiles().map((f) => ({
  file: f,
  queries: staticQueries(fs.readFileSync(path.join(ROOT, f), 'utf8')),
}));

test('the scan actually reaches the deployers it exists for', () => {
  // A scan that silently matches nothing passes forever. Pin the floor.
  const seen = FILES.filter((f) => f.queries.length > 0);
  assert.ok(seen.length > 5, `only ${seen.length} files had static SQL — the matcher is broken`);
  for (const f of ['src/utils/challenge-lane-deployer.js', 'src/utils/lane-deployer.js']) {
    const hit = FILES.find((x) => x.file === f);
    assert.ok(hit && hit.queries.length > 0, `no static SQL found in ${f}`);
  }
});

test('no statement ends on a clause keyword or a dangling comma', () => {
  const bad = [];
  for (const { file, queries } of FILES) {
    for (const q of queries) {
      const flat = q.sql.replace(/--[^\n]*/g, ' ').replace(/\s+/g, ' ').trim();
      if (/,$/.test(flat)) bad.push(`${file}:${q.line} ends on a comma: ${flat.slice(-70)}`);
      else if (/\b(WHERE|AND|OR|SET|FROM|VALUES|INTO|JOIN|ON|ANY|IN)$/i.test(flat)) {
        bad.push(`${file}:${q.line} ends on a clause keyword: ${flat.slice(-70)}`);
      }
    }
  }
  assert.deepStrictEqual(bad, [], 'truncated SQL statement(s):\n' + bad.join('\n'));
});

test('a statement that binds parameters references them', () => {
  // `UPDATE cybercore_lane` with a params array is not a typo you can see; it is
  // a statement whose body went missing.
  const bad = [];
  for (const { file, queries } of FILES) {
    for (const q of queries) {
      if (!q.hasParams) continue;
      if (!/\$\d/.test(q.sql)) {
        bad.push(`${file}:${q.line} binds parameters but has no $N: ${q.sql.replace(/\s+/g, ' ').trim().slice(0, 90)}`);
      }
    }
  }
  assert.deepStrictEqual(bad, [], 'statement(s) with unused parameters:\n' + bad.join('\n'));
});

test('every UPDATE and DELETE is scoped by a WHERE', () => {
  // The two gutted UPDATEs in rebuildLaneChallengeVms were one successful parse
  // away from rewriting every row in cybercore_lane.
  const bad = [];
  for (const { file, queries } of FILES) {
    for (const q of queries) {
      const flat = q.sql.replace(/--[^\n]*/g, ' ').replace(/\s+/g, ' ').trim();
      if (!/^\s*(UPDATE|DELETE)\b/i.test(flat)) continue;
      if (!/\bWHERE\b/i.test(flat)) {
        bad.push(`${file}:${q.line} has no WHERE: ${flat.slice(0, 90)}`);
      }
    }
  }
  assert.deepStrictEqual(bad, [], 'unscoped write(s):\n' + bad.join('\n'));
});

test('the four statements that were gutted are whole again', () => {
  // Named explicitly, because the generic rules above would also pass on a
  // statement that is syntactically complete but semantically the wrong one.
  const src = fs.readFileSync(
    path.join(ROOT, 'src/utils/challenge-lane-deployer.js'), 'utf8'
  ).split(String.fromCharCode(13, 10)).join('\n');
  const fn = src.slice(src.indexOf('async function rebuildLaneChallengeVms'));

  assert.ok(/FROM cybercore_lane\s+WHERE lane_id = \$1/.test(fn),
    'the lane load must be scoped to the one lane');
  assert.ok(/host\(gateway_wan_ip\)/.test(fn),
    'gateway_wan_ip is read back, never re-derived — resolveLaneNetworking needs it');
  assert.ok(/_challenge\s+WHERE challenge_key = \$1\s+AND status = 'active'/.test(fn),
    "the spec load must match the error message's claim that it checks 'active'");
  assert.ok(/SET config = COALESCE\(config, '\{\}'::jsonb\) \|\| \$2::jsonb/.test(fn),
    'the in-flight marker must MERGE config, never replace it');
  assert.ok(/jsonb_set\(\s*COALESCE\(l\.config, '\{\}'::jsonb\),\s*'\{vms\}'/.test(fn),
    'the write-back must splice config.vms server-side');
  assert.ok(/NOT \(\(e->>'name'\) = ANY\(\$3::text\[\]\)\)/.test(fn),
    'untouched machines are kept by NAME — losing one orphans a running VM');
});

/*
 * NOT CHECKED HERE: a missing ::type[] on `col = ANY($1)`.
 *
 * It looks like the same family as sql-param-typing.test.js and it is not.
 * Postgres resolves that parameter's type from the LEFT operand, so
 * `WHERE id = ANY($1)` with a JS array binds correctly as uuid[] — and 14 live
 * call sites across students.js, sessions.js, groups.js and lanes.js have been
 * doing exactly that in production. An assertion demanding the cast fails all
 * fourteen while nothing is broken, which is how a check gets switched off.
 *
 * The cast is still worth writing for a reader. It is a convention, not a
 * correctness rule, so it does not belong in a test.
 *
 * The typing bug that IS fatal — a parameter whose first reference supplies no
 * type at all, such as `$8 IS NOT NULL` — is covered by sql-param-typing.test.js.
 */
