/**
 * incident-scope.test.js — one engine, two owners, and the seam between them.
 *
 * WHAT THIS FILE IS DEFENDING
 * ----------------------------------------------------------------------------
 * E2 replaced findCourseLanes(courseId) with findScopeLanes({scopeType, scopeId})
 * so that a CiAB engagement and a CLE course can drive the same incident engine.
 * Every part of that generalization is behaviour-preserving EXCEPT one: the
 * WHERE arm that decides which lanes belong to the caller.
 *
 * A mistake there does not throw, does not log and does not fail a deploy. It
 * dispatches a live intrusion into somebody else's student's lane — or, in the
 * mirror-image failure, silently targets nobody and reports a clean run. Both
 * are invisible from the console: the first shows N targets where the instructor
 * expected N, and the second shows a completed run with zero events, which looks
 * exactly like "the technique didn't match much this time".
 *
 * So the two arms are pinned as SOURCE TEXT. There is no database in this suite
 * and no way to observe the predicate at runtime; scopeLanesSql() is pure
 * precisely so that it can be read here.
 *
 * THE OTHER HALF is the dispatch mutex. cybercore_incident_run holds at most one
 * in-flight run per scope, and the index that enforces it MUST be keyed on the
 * PAIR (scope_type, scope_id). A course id and an engagement id are both UUIDs
 * drawn from the same space; an index on the bare value would eventually — once,
 * unreproducibly, in March — refuse an engagement's dispatch because an
 * unrelated course happened to be mid-dispatch under a colliding id. Nobody
 * would ever diagnose that from the symptom, which is why it is asserted rather
 * than trusted.
 *
 * Run: node --test front-end/test/incident-scope.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const runner = require(path.join(ROOT, 'src', 'incident', 'runner.js'));
const schema = require(path.join(ROOT, 'src', 'incident', 'schema.js'));

/** Collapse whitespace so an assertion is about the SQL, not about indentation. */
const flat = (s) => String(s).replace(/\s+/g, ' ').trim();

// ════════════════════════════════════════════════════════════════════════════
// §1 — THE TWO WHERE ARMS
// ════════════════════════════════════════════════════════════════════════════

test('the scope vocabulary is exactly the two the run table declares', () => {
  // SCOPE_TYPES and cybercore_incident_run's CHECK are written out separately
  // and must not drift: a scope the code can build a query for but the table
  // refuses is a 400 at INSERT time, after the lanes have already been resolved
  // and the instructor has been shown a target list.
  assert.deepStrictEqual([...runner.SCOPE_TYPES], ['course', 'engagement']);
  assert.match(schema.RUN_TABLE_SQL, /scope_type IN \('course','engagement'\)/);
});

test('the two arms never produce the same SQL', () => {
  // THE CENTRAL ASSERTION. If these ever collapse — a copy-paste, a refactor
  // that "simplifies" the switch, a default arm added for a third scope — then
  // one owner's instructor dispatches into the other owner's lanes, and nothing
  // anywhere reports it.
  const course = flat(runner.scopeLanesSql('course'));
  const engagement = flat(runner.scopeLanesSql('engagement'));
  assert.notStrictEqual(course, engagement,
    'the course and engagement arms resolved to identical SQL');
});

test('the course arm matches on course_id and nothing else', () => {
  const sql = flat(runner.scopeLanePredicate('course'));
  assert.strictEqual(sql, `l.config->>'course_id' = $1`);
  assert.ok(!/engagement_id/.test(sql), 'the course arm must not read engagement_id');
  assert.ok(!/'ciab'/.test(sql), 'the course arm must not require the CiAB marker');
});

test("the engagement arm requires the CiAB marker as well as the id", () => {
  // `ciab: true` is not belt-and-braces. `engagement_id` is a generic-sounding
  // key in a free-form JSONB column that more than one deployer writes;
  // config->>'ciab' = 'true' is the marker lane-provision.js stamps on a CiAB
  // profile lane and nothing else does.
  //
  // Without it, any future feature that recorded an engagement_id on a lane
  // would be swept into a CiAB instructor's dispatch. That is not a crash — it
  // is an extra student receiving an attack, reported as a successful run.
  const sql = flat(runner.scopeLanePredicate('engagement'));
  assert.match(sql, /l\.config->>'engagement_id' = \$1/);
  assert.match(sql, /l\.config->>'ciab' = 'true'/);
  assert.match(sql, /AND/, 'both conditions, conjoined — either alone is wrong');
});

test('the scope IDENTIFIER is always bound, never interpolated', () => {
  // The predicate is interpolated because a WHERE fragment cannot be a
  // parameter. That is safe only while the fragment is one of two literals
  // chosen by a switch — which is what the tests above pin — AND while the
  // caller-supplied value stays a bound parameter. $1 in both arms, nothing else.
  for (const scope of runner.SCOPE_TYPES) {
    const sql = runner.scopeLanesSql(scope);
    assert.match(sql, /\$1/, `${scope}: the scope id must be bound`);
    assert.ok(!/\$\{/.test(sql), `${scope}: no template interpolation may reach the SQL`);
    assert.ok(!/\$2/.test(sql), `${scope}: the statement takes exactly one parameter`);
  }
});

test('an unknown scope type throws rather than falling through', () => {
  // The one behaviour that keeps the interpolation safe. A permissive default —
  // returning TRUE, or an empty string, or falling back to the course arm —
  // turns a typo into "every active lane in the estate is a target".
  for (const bad of ['section', 'COURSE', '', null, undefined, 0,
                     `course' OR '1'='1`]) {
    assert.throws(() => runner.scopeLanePredicate(bad),
      `expected scope type ${JSON.stringify(bad)} to be refused`);
    assert.throws(() => runner.scopeLanesSql(bad));
  }
});

test('everything except the WHERE arm is identical across scopes', () => {
  // The generalization is supposed to be ONE fragment wide. Downstream —
  // resolveScopeTargets, the per-user collapse, the resolver ladder, the target
  // rows — reads the same columns in the same order whichever caller asked, and
  // a column that appeared on only one arm would produce a target list missing
  // student_email for exactly one of the two products.
  const strip = (scope) =>
    flat(runner.scopeLanesSql(scope)).replace(flat(runner.scopeLanePredicate(scope)), '<PREDICATE>');
  assert.strictEqual(strip('course'), strip('engagement'));

  const sql = strip('course');
  for (const col of ['l.lane_id', 'l.user_id', 'l.name', 'l.status', 'l.module_key', 'l.config',
                     'u.email AS student_email', 'u.first_name', 'u.last_name']) {
    assert.ok(sql.includes(col), `the shared SELECT lost ${col}`);
  }
  assert.match(sql, /JOIN cybercore_user u ON u\.user_id = l\.user_id/);
  assert.match(sql, /ORDER BY u\.email, l\.created_at DESC/);
});

test("only 'active' lanes are discovered by default, on both arms", () => {
  // A lane in 'deploying' has no guest agent to dispatch to and a lane in
  // 'error' or 'deleted' may have had its VMs destroyed under it. Both would
  // resolve to a vmid — the config still names one — and be dispatched at,
  // burning the synchronized-start window on agentShellExec's retry ladder for
  // a machine that is never going to answer.
  for (const scope of runner.SCOPE_TYPES) {
    assert.match(flat(runner.scopeLanesSql(scope)), /AND l\.status = 'active'/,
      `${scope}: the status filter is missing`);
  }
});

test('suspended discovery requires an explicit opt-in and retains the scope boundary', () => {
  for (const scope of runner.SCOPE_TYPES) {
    const active = flat(runner.scopeLanesSql(scope));
    const suspended = flat(runner.scopeLanesSql(scope, { includeSuspended: true }));
    assert.strictEqual(suspended, active.replace("l.status = 'active'", "l.status IN ('active', 'suspended')"));
    assert.ok(suspended.includes(flat(runner.scopeLanePredicate(scope))));
    for (const includeSuspended of [false, undefined, null, 'true', 1]) {
      assert.strictEqual(flat(runner.scopeLanesSql(scope, { includeSuspended })), active);
    }
  }
  assert.throws(() => runner.scopeLanesSql('unknown', { includeSuspended: true }));
});

test('the material_id filter is deliberately absent', () => {
  // vuln-lab-provision.findCourseLanes() filters `config->>'material_id' IS
  // NULL` to separate a student's workstation lane from their vulnerable-lab
  // lane. This resolver must NOT: CYBR 400's sensor pair can legitimately arrive
  // by either route depending on how the instructor deployed it, so resolving
  // both and skipping the one without a sensor is honest where guessing the
  // route silently targets nothing.
  //
  // Pinned rather than left to comment, because "why does this query not have
  // the filter the neighbouring one has" is exactly the question a later reader
  // answers by adding it.
  for (const scope of runner.SCOPE_TYPES) {
    assert.ok(!/material_id/.test(runner.scopeLanesSql(scope)),
      `${scope}: a material_id filter would drop the lane holding the sensor`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §2 — THE DISPATCH MUTEX
// ════════════════════════════════════════════════════════════════════════════

test('the dispatch mutex is keyed on the PAIR, and is partial', () => {
  const mutex = schema.INCIDENT_INDEX_SQL.find((s) => s.includes('ux_cc_incident_run_dispatching'));
  assert.ok(mutex, 'the per-scope dispatch mutex is missing');

  // Both column names, in order. Named individually so a failure says WHICH
  // half went missing — the scope_type half is the one a "simplification" drops.
  assert.match(mutex, /\(\s*scope_type\s*,\s*scope_id\s*\)/,
    'the mutex MUST be keyed on (scope_type, scope_id), never scope_id alone');

  // Partial on the two pre-run states only. Widening it to include 'running'
  // would forbid the legitimate case of layering a technique over a chain;
  // narrowing it to 'dispatching' alone would let two launches both reach
  // 'scheduling' and then fight for the same guest-exec channels, blowing each
  // other's synchronized-start window.
  assert.match(mutex, /WHERE status IN \('scheduling','dispatching'\)/);
  assert.match(mutex, /IF NOT EXISTS/, 'the boot hook re-runs on every start');
});

test('the scope index the console reads is keyed on the pair too', () => {
  // Same collision, lower stakes: a history list keyed on the bare scope_id
  // would still be CORRECT (the query carries scope_type), it would just scan.
  // Keyed on the pair it does not, and the two indexes agree on what a scope is.
  const idx = schema.INCIDENT_INDEX_SQL.find((s) => s.includes('idx_cc_incident_run_scope'));
  assert.ok(idx, 'the scope history index is missing');
  assert.match(idx, /\(\s*scope_type\s*,\s*scope_id\s*,\s*created_at DESC\s*\)/);
});

// ════════════════════════════════════════════════════════════════════════════
// §3 — THE CLE CALLER IS SCOPED, AND ONLY TO ITSELF
// ════════════════════════════════════════════════════════════════════════════

const ATTACKS = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'routes', 'attacks.js');
const attacksSrc = fs.readFileSync(ATTACKS, 'utf8');

/** Comment-stripped, so a comment naming a forbidden shape is not a failure. */
const attacksCode = attacksSrc
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .split(/\r?\n/)
  .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*'))
  .join('\n');

test('every :runId handler re-checks the scope, not just the run id', () => {
  // A run id is a bearer token if nothing else is checked: an instructor who
  // learns another course's run id could abort or retry it. The plugin's own
  // header calls this "a repeated bug class in this plugin, not a hypothetical",
  // and E2 widened the check — matching scope_id alone would now also let a CLE
  // instructor drive a CiAB ENGAGEMENT's run under a colliding UUID.
  assert.match(attacksCode, /scope_type = 'course'\s+AND scope_id = \$2/,
    "getRunForCourse must match BOTH scope_type='course' and scope_id");
});

test('the CLE routes pass a course scope and never an engagement one', () => {
  // The CLE plugin is one of two callers and must only ever ask for its own
  // half. An 'engagement' string reaching this file would mean a route that can
  // enumerate, or dispatch into, a CiAB client's lanes.
  assert.match(attacksCode, /scopeType: 'course'/);
  assert.ok(!/'engagement'/.test(attacksCode),
    'the CLE routes must never construct an engagement scope');
});

test('the CLE routes write the shared tables and only READ the legacy ones', () => {
  // cle_attack_run / cle_attack_target are frozen. They are read once, by GET /,
  // so pre-cutover history stays visible, and written once by the one-shot boot
  // sweep that terminalizes rows stranded across the cutover. Any OTHER write
  // would be a run whose targets the shared sweeper never reconciles: it
  // dispatches, generates for its full duration, and never reaches a terminal
  // state anywhere the console can see.
  const legacyWrites = attacksCode
    .split(/\r?\n/)
    .filter((l) => /\b(INSERT INTO|UPDATE)\s+cle_attack_(run|target)\b/.test(l));
  assert.strictEqual(legacyWrites.length, 2,
    'exactly two legacy writes are allowed, both inside recoverLegacyAttackRuns:\n  '
    + legacyWrites.join('\n  '));
  assert.match(attacksCode, /function recoverLegacyAttackRuns/,
    'the one-shot cutover sweep must exist, or a run in flight across the cutover '
    + 'sits at \'dispatching\' forever');

  for (const t of ['cybercore_incident_run', 'cybercore_incident_target']) {
    assert.ok(attacksCode.includes(t), `the routes must reach ${t}`);
  }
});

test('the recent-runs list is a JS union, because it spans two databases', () => {
  // cybercore_incident_run is in cybercore_db and cle_attack_run is in cle_db.
  // Postgres has no cross-database query, so a SQL UNION here is not merely
  // discouraged — it cannot be expressed, and an attempt would fail at runtime
  // inside a try/catch that turns it into an empty history list.
  assert.ok(!/\bUNION\b/i.test(attacksCode),
    'a SQL UNION cannot span cle_db and cybercore_db');
  assert.match(attacksCode, /legacy: true/,
    'legacy rows must be tagged so a caller can tell a frozen run from a live one');
  assert.ok(!/legacy: false/.test(attacksCode),
    'live rows must keep the shape the console has always been served — only the '
    + 'legacy rows carry the flag');
  assert.match(attacksCode, /\.sort\(/,
    'the two sources must be merged into one created_at DESC list, not concatenated');
});

test('the run list never ships the answer key or the compiled playbook', () => {
  // cybercore_incident_run is WIDER than cle_attack_run was. `SELECT r.*` would
  // now put `playbook` and `answer_key` — the attack verbatim and its grading
  // key, both marked STAFF ONLY in src/incident/schema.js — into a response
  // whose shape is this phase's acceptance bar. Nobody would notice until it
  // was on a screen a student could see.
  //
  // `SELECT r.*` over the LEGACY table is fine and stays — cle_attack_run never
  // had those columns. It is the shared query that must name its columns, so the
  // assertion is scoped to the statement reading cybercore_incident_run rather
  // than to the whole file.
  // Walked back from the FROM to its own SELECT rather than matched forward: a
  // lazy forward match starts at the file's first SELECT and swallows the legacy
  // statement on the way, which is how this assertion passes while asserting
  // nothing.
  const from = attacksCode.indexOf('FROM cybercore_incident_run r');
  assert.ok(from > 0, 'the shared run list query is missing');
  const projection = attacksCode.slice(attacksCode.lastIndexOf('SELECT', from), from);
  assert.ok(!/\br\.\*/.test(projection),
    'select the columns explicitly; r.* leaks playbook and answer_key');
  for (const secret of ['playbook', 'answer_key']) {
    assert.ok(!new RegExp(`\\b${secret}\\b`).test(projection),
      `${secret} must never be selected by a route`);
  }
  // The rename that keeps the emitted shape byte-compatible with what
  // cle_attack_run produced, so attack-console.js needed no edit.
  assert.match(attacksCode, /r\.scope_id AS course_id/);
});

test('the CLE plugin no longer carries the E1 re-export shims', () => {
  // E1 left four one-line shims at cle/utils/ so the strangler did not have to
  // land in one commit. E2 deletes them and re-points every require at
  // src/incident/. A shim that comes back is a second import path for a module
  // with process-level state (the worker's interval and its `running` guard),
  // and two copies of that means two sweepers racing each other's claims.
  const utils = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle', 'utils');
  for (const name of ['attack-runner.js', 'attack-target.js', 'attack-worker.js',
                      'loggen-catalog.js']) {
    assert.ok(!fs.existsSync(path.join(utils, name)),
      `cle/utils/${name} still exists; E2 deletes the shims`);
  }
  assert.match(attacksSrc, /require\('\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/src\/incident\/runner'\)/);
  assert.match(attacksSrc, /require\('\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/src\/incident\/catalog'\)/);
});

// ════════════════════════════════════════════════════════════════════════════
// §4 — BOOT WIRING
// ════════════════════════════════════════════════════════════════════════════

test('both boot sweeps run, and the legacy one runs from the plugin', () => {
  // The shared sweep lives in core and reaches cybercore_db. The legacy sweep
  // CANNOT: cle_attack_target is in cle_db, reachable only through the plugin's
  // injected pool, and core requiring into a module that can be disabled is the
  // inversion E2 exists to remove. So there are two calls, and src/server.js
  // makes both — after moduleLoader.loadAll(), because the CLE pool is injected
  // there and a sweep against a null pool swallows its own failure.
  const server = fs.readFileSync(path.join(ROOT, 'src', 'server.js'), 'utf8');
  const shared = server.indexOf('recoverAttackRuns()');
  const legacy = server.indexOf('recoverLegacyAttackRuns()');
  const start = server.indexOf('startAttackWorker()');
  const loadAll = server.indexOf('moduleLoader.loadAll');

  assert.ok(shared > 0, 'src/server.js must call the shared boot recovery');
  assert.ok(legacy > 0, 'src/server.js must call the one-shot legacy cutover sweep');
  assert.ok(loadAll > 0 && loadAll < legacy,
    'the legacy sweep needs the CLE pool, which loadAll() injects');
  assert.ok(shared < start && legacy < start,
    'both sweeps must finish before the worker starts claiming targets');

  // And core must not be the thing that knows about cle_db.
  const worker = fs.readFileSync(path.join(ROOT, 'src', 'incident', 'worker.js'), 'utf8');
  assert.ok(!/require\([^)]*modules\/crucible\/plugins/.test(worker),
    'the worker must not require into a plugin for the legacy pool');
});
