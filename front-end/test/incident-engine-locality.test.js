/**
 * incident-engine-locality.test.js — the incident engine lives in ONE place.
 *
 * WHY THIS FILE EXISTS
 * The engine that drives CYBR 400 was born inside the CLE plugin, welded to
 * cle_db and to a run table with a NOT NULL foreign key to cle_course. That weld
 * is the entire reason CiAB could never use it, and E0/E1 unpick it by moving
 * the engine into shared core (src/incident/) where both plugins can reach it.
 *
 * The failure this file defends against is not a regression in behaviour. It is
 * the second copy. This repo has already lived through it once at a larger
 * scale — see ciab-deploy-parity.test.js, whose header counts THREE generations
 * of the same lane-deploy sequence, the third of which "drifted and lost the
 * non-obvious details that actually make a lane reachable". The same pressure
 * applies here and it applies for reasonable-sounding reasons: someone needs a
 * slightly different dispatch command for a CiAB scenario, the shared runner
 * looks intimidating, and copying eighty lines into the plugin is ten minutes.
 *
 * A copy of THIS engine drifts in a particularly bad way, because every
 * difference is silent:
 *
 *   - a stale buildDispatchCommand loses the `setsid` that puts the wrapper in
 *     its own process group, so `kill -TERM -$P` misses and an aborted attack
 *     keeps generating for another forty minutes
 *   - a stale resolveLoggenTarget guesses when the ladder should have returned
 *     null, and fires log-generator at the student's SIEM instead of the sensor
 *   - a stale dueTargets loses the scheduled-start join, and a five-minute run
 *     shows as 'scheduled' from start to finish
 *   - a stale base64 stager writes cc-attack.sh in place rather than through a
 *     .tmp + mv, so a lane can execute a half-written wrapper
 *
 * None of those produce an error anyone sees. They produce a lane that looks
 * fine and teaches nothing, which is why this is a source-text gate and not a
 * behavioural test: no runtime assertion can catch "somebody inlined it over
 * there" without a live Proxmox cluster.
 *
 * WHAT IS DELIBERATELY ALLOWED
 * One-line re-export shims at the old cle/utils/ paths. E1 left them so the
 * strangler did not have to land in one commit; E2 re-pointed the CLE routes and
 * DELETED them, which is the destination state the shim test below now records
 * rather than enforces. A shim contains none of the forbidden tokens, so it
 * passed this gate for free — and if one ever comes back carrying an
 * implementation, that is precisely the case this file is here to fail.
 *
 * Run: node --test front-end/test/incident-engine-locality.test.js  (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CLE = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle');
const INCIDENT = path.join(ROOT, 'src', 'incident');

/**
 * Every .js/.sh file in the CLE plugin, with its repo-relative path.
 *
 * node_modules is skipped defensively — a plugin is allowed to have its own, and
 * a vendored dependency that happens to contain one of these identifiers would
 * be a false failure nobody could act on.
 */
function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (/\.(js|sh)$/.test(entry.name)) {
      out.push({ rel: path.relative(ROOT, full).split(path.sep).join('/'), full });
    }
  }
  return out;
}

/**
 * Strip comments before asserting a token is ABSENT.
 *
 * Borrowed wholesale from ciab-deploy-parity.test.js, and load-bearing for the
 * same reason: this codebase documents its traps at length, and the traps are
 * named after exactly the identifiers forbidden below. cle/routes/attacks.js is
 * expected to carry a comment saying "the dispatch command is built in
 * src/incident/runner.js, do not rebuild it here" — without this, the comment
 * that exists to prevent the copy would itself fail the test.
 */
function codeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('#');
    })
    .join('\n');
}

const CLE_FILES = walk(CLE).map((f) => ({ ...f, code: codeOnly(fs.readFileSync(f.full, 'utf8')) }));

/**
 * A DEFINITION of `name`, not a call to it.
 *
 * The distinction is the whole test. `runner.buildDispatchCommand(...)` in a CLE
 * route is correct and expected — that IS delegation. `function
 * buildDispatchCommand(` or `const buildDispatchCommand = (` in the same file is
 * the second copy. Matching the bare identifier would forbid the right thing
 * along with the wrong one and the gate would be deleted within a month.
 */
function definitionRe(name) {
  return new RegExp(
    String.raw`(?:^|\s)(?:async\s+)?function\s+${name}\s*\(`
    + String.raw`|(?:const|let|var)\s+${name}\s*=\s*(?:async\s*)?(?:function|\()`
    + String.raw`|^\s*(?:async\s+)?${name}\s*\([^)]*\)\s*\{`,
    'm'
  );
}

const HINT = 'It belongs in src/incident/. See this file\'s header, and the plan\'s E1.';

for (const fn of ['buildDispatchCommand', 'resolveLoggenTarget', 'dueTargets']) {
  test(`the CLE plugin defines no second copy of ${fn}()`, () => {
    const re = definitionRe(fn);
    const offenders = CLE_FILES.filter((f) => re.test(f.code)).map((f) => f.rel);
    assert.deepStrictEqual(offenders, [],
      `${fn}() is defined inside the CLE plugin. ${HINT}\n  ${offenders.join('\n  ')}`);
  });

  test(`src/incident/ is where ${fn}() actually lives`, () => {
    // The mirror assertion. Without it, deleting the engine outright would make
    // every test above pass — "no second copy" is satisfied trivially by no copy
    // at all, and this gate would go green on a broken tree.
    const re = definitionRe(fn);
    const found = walk(INCIDENT)
      .filter((f) => re.test(codeOnly(fs.readFileSync(f.full, 'utf8'))))
      .map((f) => f.rel);
    assert.ok(found.length >= 1, `${fn}() is not defined anywhere under src/incident/`);
  });
}

test('the CLE plugin does not restage the attack wrapper itself', () => {
  // The base64 stager is the sequence that writes cc-attack.sh into a guest:
  // `base64 -d > <path>.tmp` then `mv -f <path>.tmp <path>`. attack-command.test.js
  // already pins that it goes through the .tmp, because writing the live path
  // directly lets a lane execute a half-written wrapper — a shell script is read
  // incrementally by the interpreter, so a truncated one runs its first half.
  //
  // A copy of this in the plugin is the same defect wearing a different name.
  const offenders = CLE_FILES
    .filter((f) => /base64\s+-d\s*>/.test(f.code) || /CC_ATTACK_B64|WRAPPER_B64/.test(f.code))
    .map((f) => f.rel);
  assert.deepStrictEqual(offenders, [],
    `the CLE plugin stages the attack wrapper itself. ${HINT}\n  ${offenders.join('\n  ')}`);
});

test('the wrapper, the emitter and the playbooks moved with the engine', () => {
  // Leaving any of these behind would make src/incident/ require UPWARD into a
  // plugin — core depending on a module that can be disabled. That inversion is
  // the kind that gets copied once it exists, so it is pinned here rather than
  // left to review.
  for (const rel of ['cc-attack.sh', 'cc-emit.js', path.join('playbooks', 'host-baseline.json')]) {
    assert.ok(fs.existsSync(path.join(INCIDENT, rel)), `src/incident/${rel} is missing`);
  }
  for (const rel of ['utils/cc-attack.sh', 'utils/cc-emit.js', 'playbooks']) {
    assert.ok(!fs.existsSync(path.join(CLE, rel)),
      `cle/${rel} still exists; src/incident/ would require upward into the plugin`);
  }
});

test('the shims left in cle/utils/ are shims, not implementations', () => {
  // E1 leaves four one-line re-exports so the strangler does not have to land in
  // a single commit. E2 deletes them. Until then, "one line" is the property
  // worth pinning: a shim that grows a body is a second copy that this file's
  // other assertions would only catch once it re-declared a named function.
  for (const name of ['attack-runner', 'attack-target', 'attack-worker', 'loggen-catalog']) {
    const p = path.join(CLE, 'utils', `${name}.js`);
    if (!fs.existsSync(p)) continue;   // E2 deleted it — the destination state.
    const code = codeOnly(fs.readFileSync(p, 'utf8')).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    assert.deepStrictEqual(code.length, 1,
      `cle/utils/${name}.js is no longer a one-line shim (${code.length} code lines). ${HINT}`);
    assert.match(code[0], /^module\.exports = require\(['"][^'"]*src\/incident\/[^'"]+['"]\);$/,
      `cle/utils/${name}.js must re-export from src/incident/, not reimplement. ${HINT}`);
  }
});

test('the engine adapter registry answers for synthetic and refuses the unknown', () => {
  // The contract from E0. Two properties, and the second is the one with teeth:
  // engineFor() must THROW a named error rather than fall back, because a run
  // row written by a newer build (engine='caldera') read by an older one would
  // otherwise be dispatched with the synthetic engine's semantics — the worker
  // would poll a guest state file no Caldera operation writes, decide the target
  // never started, and mark a live intrusion 'failed'.
  const engines = require('../src/incident/engines');
  assert.ok(engines.registeredEngines().includes('synthetic'),
    'the synthetic engine must be registered');
  assert.ok(!engines.registeredEngines().includes('caldera'),
    'caldera is legal in the DB CHECK but must not register until E9 ships an adapter');

  assert.throws(() => engines.engineFor('caldera'), (err) => {
    assert.strictEqual(err.name, 'UnknownIncidentEngineError');
    assert.strictEqual(err.code, 'UNKNOWN_INCIDENT_ENGINE');
    assert.strictEqual(err.engineKey, 'caldera');
    return true;
  });

  for (const m of engines.ENGINE_METHODS) {
    assert.strictEqual(typeof engines.engineFor('synthetic')[m], 'function',
      `the synthetic adapter must implement ${m}()`);
  }
});

test('the incident tables carry no cross-database foreign key, and the mutex is the PAIR', () => {
  // Three invariants from E0's DDL that a later edit could quietly undo:
  //
  //  1. No FK on the scope. There is none to be had — course_id lives in cle_db
  //     and engagement_id in clinic_db — so an added REFERENCES would simply
  //     fail to create, leaving a server that boots with no incident engine and
  //     a warning nobody reads.
  //  2. 'caldera' present in the engine CHECK from day one. These are CREATE
  //     TABLE IF NOT EXISTS statements re-run on every boot; widening a CHECK
  //     afterwards needs an ALTER that has to be correct against both shapes
  //     forever, which is the one genuinely unsafe operation available here.
  //  3. The dispatch mutex keyed on (scope_type, scope_id), never scope_id
  //     alone. A course id and an engagement id are both UUIDs from the same
  //     space; a bare-value index would eventually refuse an engagement's
  //     dispatch because an unrelated course was mid-dispatch under a colliding
  //     id — a bug nobody could ever diagnose from the symptom.
  const schema = require('../src/incident/schema');
  const run = schema.RUN_TABLE_SQL;
  const target = schema.TARGET_TABLE_SQL;

  assert.ok(!/scope_id[^,]*REFERENCES/i.test(run), 'scope_id must have no foreign key');
  assert.ok(!/lane_id[^,]*REFERENCES/i.test(target), 'lane_id must have no foreign key');
  assert.ok(!/user_id[^,]*REFERENCES/i.test(target), 'user_id must have no foreign key');

  assert.match(run, /scope_type IN \('course','engagement'\)/);
  assert.match(run, /engine IN \('synthetic','caldera'\)/);
  assert.match(run, /mode IN \('technique','tactic','chain','scenario'\)/);
  for (const c of ['chain', 'duration', 'technique', 'tactic', 'scenario']) {
    assert.ok(run.includes(`cc_incident_run_${c}_matches_mode`), `missing correlated CHECK for ${c}`);
  }

  const mutex = schema.INCIDENT_INDEX_SQL.find((s) => s.includes('ux_cc_incident_run_dispatching'));
  assert.ok(mutex, 'the per-scope dispatch mutex is missing');
  assert.match(mutex, /\(scope_type,\s*scope_id\)/,
    'the dispatch mutex MUST be keyed on the PAIR, never scope_id alone');
  assert.match(mutex, /WHERE status IN \('scheduling','dispatching'\)/);

  for (const sql of schema.INCIDENT_INDEX_SQL) {
    assert.match(sql, /IF NOT EXISTS/,
      'every boot-hook statement must be natively re-runnable');
  }
});

test('src/incident/ never requires upward into a plugin — no exceptions left', () => {
  // Core must not depend on a module that can be disabled. E1 held ONE exception
  // open and named it: runner.js and worker.js took the CLE pool, because the
  // run tables were still cle_attack_run / cle_attack_target in cle_db and a
  // pure relocation had to keep talking to the same database.
  //
  // E2 closed it. Both files now write cybercore_incident_run / _target through
  // cybercoreQuery, and the allowance is GONE rather than narrowed — which is
  // the state worth pinning, because a re-introduced require would arrive
  // looking exactly like the one that used to be legitimate.
  //
  // The pre-cutover rows still need a sweep and it still needs the CLE pool.
  // That sweep lives in the PLUGIN (cle/routes/attacks.js
  // recoverLegacyAttackRuns) and src/server.js calls it — a plugin requiring
  // core, plus a boot sequence that already reaches into CiAB and CLE the same
  // way. Neither direction is this file's concern; what it forbids is
  // src/incident/ reaching upward.
  const offenders = walk(INCIDENT)
    .filter((f) => /require\(['"][^'"]*modules\/crucible\/plugins\//
      .test(codeOnly(fs.readFileSync(f.full, 'utf8'))))
    .map((f) => f.rel);
  assert.deepStrictEqual(offenders, [],
    'core must not require into a plugin:\n  ' + offenders.join('\n  '));
});

test('the shared incident tables are the only run tables src/incident/ writes', () => {
  // The rename half of E2, pinned as source text because there is no database in
  // this suite to observe it against.
  //
  // A LEFTOVER cle_attack_* statement in core is the worst possible outcome of a
  // partial re-point: cybercoreQuery would run it against cybercore_db, where
  // those tables do not exist, so the statement throws — and every throw on this
  // path is already swallowed (dispatch catches per lane, the sweeper catches
  // per target, boot recovery catches the lot). The result is an attack that
  // dispatches and is never reconciled, with one warning line to show for it.
  const offenders = [];
  for (const f of walk(INCIDENT)) {
    if (!/\.js$/.test(f.rel)) continue;
    const code = codeOnly(fs.readFileSync(f.full, 'utf8'));
    if (/\bcle_attack_(run|target)\b/.test(code)) offenders.push(f.rel);
  }
  assert.deepStrictEqual(offenders, [],
    'src/incident/ must not name the legacy CLE tables:\n  ' + offenders.join('\n  '));

  for (const name of ['runner.js', 'worker.js']) {
    const src = fs.readFileSync(path.join(INCIDENT, name), 'utf8');
    assert.match(src, /cybercore_incident_target/, `${name} must write the shared target table`);
    assert.match(src, /cybercore_incident_run/, `${name} must write the shared run table`);
  }
});
