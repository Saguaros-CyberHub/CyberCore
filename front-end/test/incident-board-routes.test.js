/**
 * incident-board-routes.test.js — Track E, phase E5: the two thin routers.
 *
 * SOURCE SCANS ABOVE, EXECUTED BEHAVIOUR BELOW, AND BOTH ARE NEEDED.
 *
 * A scan pins a property over a WHOLE FILE at once — "no instructor sub-route
 * anywhere forgets its role gate", "the CiAB router is never mounted on the
 * bare /api prefix" — including code a handler added later contains that no
 * existing test calls. It cannot see a wrong status code, an unvalidated body
 * or a response shape. So §3 and §4 replace the module graph in require.cache
 * and drive the REAL routers, through the REAL board, asserting on statuses and
 * bodies. `node --test "test/*.test.js"` gives every file its own process, so
 * that cache write cannot reach another test file.
 *
 * THE PROPERTIES, AND WHY EACH ONE EARNS A TEST
 *
 *   1. THE CIAB MOUNT IS A CIAB-OWNED PREFIX. routes/api.js is mounted at '/',
 *      so `router.use('/api', ...)` there matches every /api/* request in the
 *      whole application. Putting an enrollment gate on that mount once cost
 *      every student on no CIAB roster their CLE routes as well. A board
 *      registered on bare /api would repeat it exactly.
 *
 *   2. 404 FOR BOTH "no such run" AND "not your run", with the SAME body. A 403
 *      confirms the run exists, and across a department that is an enumerable
 *      oracle for how many exercises are running and when.
 *
 *   3. A STUDENT WRITE CANNOT SET auto_* OR override_*. The whole grade is in
 *      those columns. This is the finding the input whitelist exists for, and
 *      it is checked against what was actually STORED, not against what the
 *      handler returned.
 *
 *   4. THE STUDENT BOARD IS THE WHITELIST, over the wire. Not the projection
 *      unit-tested in isolation (that is incident-answer-key-leak.test.js) —
 *      the object a real request actually receives.
 *
 *   5. EVERY INSTRUCTOR SUB-ROUTE CARRIES ITS OWN ROLE GATE. Neither mount
 *      applies one: CLE's is authenticateToken only, and CiAB's is
 *      requireCiabAccess, which answers "you are not enrolled" to somebody
 *      whose actual problem is that they are not staff. A handler that forgets
 *      is open to every enrolled student.
 *
 * Run: node --test test/incident-board-routes.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CLE = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const read = (p) => fs.readFileSync(p, 'utf8');

/**
 * Strip comments before counting mounts.
 *
 * Borrowed from ciab-deploy-parity.test.js, and load-bearing for the same
 * reason: routes/api.js's header explains the bare-/api trap by QUOTING
 * `router.use('/api', ...)`, so an uncommented scan counts the warning as a
 * second offence.
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

// ---------------------------------------------------------------------------
// Fixture ids. Real uuids: board.js refuses anything else before it reaches SQL.
// ---------------------------------------------------------------------------
const COURSE_1 = '11111111-1111-1111-1111-111111111111';
const COURSE_2 = '22222222-2222-2222-2222-222222222222';
const ENGAGEMENT = '33333333-3333-3333-3333-333333333333';
const RUN_C1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const RUN_C2 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const RUN_E1 = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const STUDENT = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
const OUTSIDER = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const STAFF = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const TARGET = '99999999-9999-9999-9999-999999999999';

// ---------------------------------------------------------------------------
// §1 + §2 Source scans
// ---------------------------------------------------------------------------

test('E5-R1: the CiAB board is on a CIAB-OWNED prefix, never on bare /api', () => {
  const api = codeOnly(read(path.join(CIAB, 'routes', 'api.js')));
  assert.match(api, /router\.use\(\s*'\/api\/engagements\/:engagementId\/incidents'/,
    'the board must be registered on /api/engagements/...');
  // The catch-all is `router.use('/api', authenticateToken, clinicApiRoutes)`
  // and must remain the ONLY bare-/api mount. Anything else there applies to
  // core's routes and to every other plugin's.
  const bareApiMounts = api.match(/router\.use\(\s*'\/api'\s*,/g) || [];
  assert.strictEqual(bareApiMounts.length, 1,
    'exactly one bare /api mount (the documented catch-all) may exist');
  assert.ok(api.includes('incidentRoutes'), 'the router has to actually be mounted');
  // The full chain, at the mount, which is only safe because the prefix is ours.
  const mount = api.slice(api.indexOf("'/api/engagements/:engagementId/incidents'"));
  const block = mount.slice(0, mount.indexOf(');'));
  for (const mw of ['authenticateToken', 'requireCiabAccess', 'checkSchedule']) {
    assert.ok(block.includes(mw), `the CiAB mount is missing ${mw}`);
  }
});

test('E5-R2: the CLE board is mounted beside /attacks, with the courseId shim', () => {
  const api = codeOnly(read(path.join(CLE, 'routes', 'api.js')));
  assert.match(api, /router\.use\('\/api\/cle\/courses\/:courseId\/incidents'/);
  assert.ok(api.includes("const incidentRoutes = require('./incidents');"));
  const mount = api.slice(api.indexOf("'/api/cle/courses/:courseId/incidents'"));
  const block = mount.slice(0, mount.indexOf('incidentRoutes'));
  assert.ok(block.includes('authenticateToken'), 'the CLE mount is missing authenticateToken');
  assert.ok(block.includes('res.locals.courseId'), 'the nested-router shim is missing');
});

test('E5-R3: every instructor sub-route carries its own role gate', () => {
  // Neither mount applies one. CiAB's is requireCiabAccess, which is an
  // ENROLLMENT gate and answers the wrong question for a student who is simply
  // not staff; CLE's is authenticateToken alone.
  const ciab = read(path.join(CIAB, 'routes', 'incidents.js'));
  const staffRoutes = [
    "router.patch('/:runId/findings/:findingId'",
    "router.post('/:runId/score'",
    "router.post('/:runId/release'",
  ];
  for (const decl of staffRoutes) {
    const i = ciab.indexOf(decl);
    assert.ok(i >= 0, `${decl} is missing from the CiAB router`);
    const line = ciab.slice(i, ciab.indexOf('\n', i));
    assert.ok(line.includes('instructorOnly'), `${decl} has no role gate`);
  }
  assert.match(ciab, /const instructorOnly = requireRole\('instructor', 'admin'\)/);

  // CLE reaches the same place differently: its tier is resolved per request
  // against the course, so an instructor of ANOTHER course is not staff here.
  const cle = read(path.join(CLE, 'routes', 'incidents.js'));
  for (const decl of staffRoutes) {
    const i = cle.indexOf(decl);
    assert.ok(i >= 0, `${decl} is missing from the CLE router`);
    const body = cle.slice(i, i + 400);
    assert.ok(body.includes('staffOnly: true'), `${decl} does not resolve staff-only`);
  }
});

test('E5-R4: the feature gate is on writes only, and it is not the staff middleware', () => {
  const cle = read(path.join(CLE, 'routes', 'incidents.js'));
  // requireCourseFeature resolves through getManagedCourse, which returns null
  // for anyone who does not MANAGE the course — so mounting it here would 404
  // every student write on a perfectly enabled board.
  assert.ok(!/requireCourseFeature\(/.test(cle),
    'the staff-only feature middleware must not gate a student write path');
  assert.ok(cle.includes("isFeatureEnabled(course, 'blue_team')"));
  // Reads stay open. The three read handlers resolve without `write: true`.
  for (const decl of ["router.get('/:runId',", "router.get('/:runId/status',"]) {
    const i = cle.indexOf(decl);
    assert.ok(i >= 0, `${decl} missing`);
    const body = cle.slice(i, i + 300);
    assert.ok(!body.includes('write: true'),
      `${decl} gates a READ on the feature — a disabled tab would hide graded work`);
  }
});

test('E5-R4b: the board borrows the engine lane predicate rather than restating it', () => {
  // The two arms are NOT symmetric -- the engagement arm also requires
  // config->>'ciab' = 'true', because an engagement id alone does not
  // distinguish a CiAB lane from anything else that might one day carry that
  // key. A second copy of the predicate in board.js would be correct on the day
  // it was written and wrong the first time either arm changed, and the symptom
  // would be a student who owns a lane being told their run does not exist.
  // loadRouters() FIRST: it is what puts the fake database into require.cache,
  // and requiring board.js before that would bind it to the real pool for the
  // rest of the process -- every executed test below then tries to open a
  // Postgres connection that is not there.
  loadRouters();
  const board = require('../src/incident/board');
  const runner = require('../src/incident/runner');
  for (const scope of ['course', 'engagement']) {
    assert.strictEqual(board.scopeLanePredicate(scope), runner.scopeLanePredicate(scope),
      `${scope}: the board's lane predicate has drifted from the engine's`);
  }
  assert.match(runner.scopeLanePredicate('engagement'), /'ciab'/,
    'the engagement arm must still require the CiAB marker');
  assert.throws(() => board.scopeLanePredicate('nonsense'), /unknown incident scope type/);
});

// ---------------------------------------------------------------------------
// §3 The module graph, replaced
// ---------------------------------------------------------------------------

/** Rows the fake database holds. Reset per test that mutates them. */
const state = {
  runs: [],
  lanes: [],
  targets: [],
  findings: [],
  scores: [],
  sql: [],
};

function resetState() {
  state.runs = [
    fullRun(RUN_C1, 'course', COURSE_1),
    fullRun(RUN_C2, 'course', COURSE_2),
    fullRun(RUN_E1, 'engagement', ENGAGEMENT),
  ];
  state.lanes = [{ user_id: STUDENT, engagement_id: ENGAGEMENT, course_id: COURSE_1, ciab: 'true', status: 'active' }];
  state.targets = [{ target_id: TARGET, run_id: RUN_C1, user_id: STUDENT, created_at: '2026-03-01T09:00:00Z' }];
  state.findings = [];
  state.scores = [];
  state.sql = [];
}

/** A run row with every private column populated — the whole point of §4. */
function fullRun(runId, scopeType, scopeId) {
  return {
    run_id: runId, scope_type: scopeType, scope_id: scopeId, scope_label: 'CYBR400-01',
    engine: 'synthetic', launched_by: STAFF,
    mode: 'chain', technique_id: 'T1110.001', tactic_id: 'TA0006',
    chain_key: 'ransomware-ryuk', scenario_id: 'sc-1',
    scenario_ref: { name: 'Ransomware at Acme' },
    playbook: { steps: [{ message: 'THE-WHOLE-ATTACK' }] },
    answer_key: { techniques: [{ id: 'T1486' }] },
    duration_seconds: null, speed: '1.00', catalog_version: 'loggen-2026.02',
    lead_seconds: 60, scheduled_start_at: '2026-03-01T10:00:00.000Z',
    status: 'completed', event_group_id: null, error: null,
    created_at: '2026-03-01T09:00:00.000Z', finished_at: '2026-03-01T10:30:00.000Z',
  };
}

/** Project a row through a SQL column list, so a star select would be visible. */
function pick(list, row) {
  const out = {};
  for (const raw of list.split(',')) {
    const col = raw.trim().replace(/^[a-z_]+\./i, '');
    if (col) out[col] = row[col] === undefined ? null : row[col];
  }
  return out;
}
const selectList = (sql) => /SELECT\s+([\s\S]*?)\s+FROM\s/i.exec(sql)[1];
const returningList = (sql) => /RETURNING\s+([\s\S]*)$/i.exec(sql)[1];

let counter = 0;
const newId = () => `0000000${(counter += 1)}-0000-0000-0000-000000000000`.slice(-36);

/**
 * The fake cybercoreQuery.
 *
 * It interprets the handful of statements board.js issues rather than returning
 * canned rows, so the COLUMN LISTS are exercised: a star select would show up
 * as private columns appearing in a student response, which is exactly what §4
 * asserts against. Anything unrecognised THROWS, so a new query added later
 * fails loudly here instead of silently returning zero rows.
 */
async function fakeQuery(sql, params) {
  state.sql.push(sql);
  const p = params || [];

  if (/FROM cybercore_incident_run r\s+WHERE r\.run_id/.test(sql)) {
    const row = state.runs.find((r) => r.run_id === p[0] && r.scope_type === p[1] && r.scope_id === p[2]);
    return { rows: row ? [pick(selectList(sql), row)] : [] };
  }
  if (/FROM cybercore_incident_run r\s+WHERE r\.scope_type/.test(sql)) {
    const rows = state.runs.filter((r) => r.scope_type === p[0] && r.scope_id === p[1]);
    return { rows: rows.map((r) => pick(selectList(sql), r)) };
  }
  if (/FROM cybercore_lane l/.test(sql)) {
    // The predicate comes from runner.scopeLanePredicate, which binds the scope
    // id as $1 -- so p = [scopeId, userId]. The engagement arm also requires the
    // ciab marker, which the fixture lanes carry.
    const keys = (sql.match(/config->>'(\w+)'/g) || []).map((m) => /'(\w+)'/.exec(m)[1]);
    const scopeKey = keys[0];
    const needsCiab = keys.includes('ciab');
    const rows = state.lanes.filter((l) => l.user_id === p[1]
      && l[scopeKey] === p[0]
      && (!needsCiab || l.ciab === 'true')
      && l.status === 'active');
    return { rows: rows.map(() => ({ '?column?': 1 })) };
  }
  if (/SELECT target_id FROM cybercore_incident_target/.test(sql)) {
    const rows = state.targets.filter((t) => t.run_id === p[0] && t.user_id === p[1]);
    return { rows: rows.map((t) => ({ target_id: t.target_id })) };
  }
  if (/FROM cybercore_incident_finding f/.test(sql)) {
    const rows = state.findings
      .filter((f) => f.run_id === p[0] && (p.length < 2 || f.user_id === p[1]));
    return { rows: rows.map((f) => pick(selectList(sql), f)) };
  }
  if (/FROM cybercore_incident_score s/.test(sql)) {
    const rows = state.scores.filter((s) => s.run_id === p[0] && (p.length < 2 || s.user_id === p[1]));
    return { rows: rows.map((s) => pick(selectList(sql), s)) };
  }
  if (/^\s*INSERT INTO cybercore_incident_finding/.test(sql)) {
    const cols = /\(([^)]*)\)\s*VALUES/i.exec(sql)[1].split(',').map((c) => c.trim());
    const row = { finding_id: newId(), submitted_at: '2026-03-01T10:05:00.000Z', withdrawn_at: null };
    cols.forEach((c, i) => { row[c] = p[i]; });
    if (typeof row.evidence === 'string') row.evidence = JSON.parse(row.evidence);
    state.findings.push(row);
    return { rows: [pick(returningList(sql), row)] };
  }
  if (/UPDATE cybercore_incident_finding\s+SET withdrawn_at/.test(sql)) {
    const row = state.findings.find((f) => f.finding_id === p[0] && f.run_id === p[1]
      && f.user_id === p[2] && !f.withdrawn_at);
    if (!row) return { rows: [] };
    row.withdrawn_at = '2026-03-01T10:20:00.000Z';
    return { rows: [pick(returningList(sql), row)] };
  }
  if (/UPDATE cybercore_incident_finding\s+SET override_verdict/.test(sql)) {
    // p = [verdict, points, note, staffUserId, cleared, findingId, runId]
    const row = state.findings.find((f) => f.finding_id === p[5] && f.run_id === p[6]);
    if (!row) return { rows: [] };
    row.override_verdict = p[0];
    row.override_points = p[1];
    row.override_note = p[2];
    row.override_by = p[4] ? null : p[3];
    row.override_at = p[4] ? null : '2026-03-01T11:05:00.000Z';
    return { rows: [pick(returningList(sql), row)] };
  }
  throw new Error(`fakeQuery: unhandled SQL\n${sql}`);
}

function put(modPath, exports) {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
}

let ROUTERS = null;
function loadRouters() {
  if (ROUTERS) return ROUTERS;

  put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: fakeQuery });
  put(path.join(ROOT, 'src', 'utils', 'audit.js'), { log: async () => {} });
  put(path.join(ROOT, 'src', 'middleware', 'auth.js'), {
    authenticateToken: (req, res, next) => next(),
    requireRole: (...roles) => (req, res, next) => (
      req.user && roles.includes(req.user.role)
        ? next()
        : res.status(403).json({ error: 'forbidden' })
    ),
  });

  // CLE's own database: only the enrollment probe reaches it from this router.
  put(path.join(CLE, 'utils', 'db.js'), {
    query: async (sql, p) => {
      if (/FROM cle_course_enrollment/.test(sql)) {
        const enrolled = String(p[0]) === COURSE_1 && String(p[1]) === STUDENT;
        return {
          rows: enrolled
            ? [{ course_id: COURSE_1, code: 'CYBR400-01', course_name: 'Blue Team', features: null }]
            : [],
        };
      }
      throw new Error(`cle db: unhandled SQL\n${sql}`);
    },
  });
  put(path.join(CLE, 'utils', 'course-access.js'), {
    // Staff manage COURSE_1 only, so an instructor is NOT staff on COURSE_2 —
    // which is what makes the cross-scope 404 below a real test.
    getManagedCourse: async (courseId, user) => (
      (user && (user.role === 'admin' || user.role === 'instructor') && String(courseId) === COURSE_1)
        ? { course_id: COURSE_1, code: 'CYBR400-01', course_name: 'Blue Team', features: null }
        : null
    ),
    canManageCourse: async () => false,
  });

  ROUTERS = {
    cle: require(path.join(CLE, 'routes', 'incidents.js')),
    ciab: require(path.join(CIAB, 'routes', 'incidents.js')),
  };
  return ROUTERS;
}

/** One request through a router, with no socket and no port. */
function call(which, method, url, opts) {
  const o = opts || {};
  const router = loadRouters()[which];
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: o.query || {}, headers: {},
      params: {},
      user: o.user === null ? undefined : (o.user || { role: 'student', userId: STUDENT }),
    };
    const res = {
      statusCode: 200,
      locals: o.locals || {},
      headers: {},
      status(code) { this.statusCode = code; return this; },
      set(k, v) { this.headers[k] = v; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      getHeader(k) { return this.headers[k]; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); return this; },
      send(payload) { resolve({ status: this.statusCode, body: payload }); return this; },
      end() { resolve({ status: this.statusCode, body: null }); return this; },
    };
    router(req, res, (err) => (err ? reject(err) : resolve({ status: 404, body: null })));
  });
}

const asCourse1 = (extra) => Object.assign({ locals: { courseId: COURSE_1 } }, extra || {});
const asEngagement = (extra) => Object.assign({ locals: { engagementId: ENGAGEMENT } }, extra || {});

// ---------------------------------------------------------------------------
// §4 Executed behaviour
// ---------------------------------------------------------------------------

test('E5-R5: another scope\'s run and a run that does not exist are the SAME 404', async () => {
  resetState();
  const missing = await call('cle', 'GET', `/${'0'.repeat(8)}-0000-0000-0000-000000000000`, asCourse1());
  const foreign = await call('cle', 'GET', `/${RUN_C2}`, asCourse1());

  assert.strictEqual(missing.status, 404);
  assert.strictEqual(foreign.status, 404, 'a run in another course must not be a 403');
  assert.deepStrictEqual(missing.body, foreign.body,
    'the two answers must be indistinguishable, or the board is an enumeration oracle');

  // And that holds for staff too: an instructor who manages COURSE_1 cannot
  // drive COURSE_2's run by putting its id in the path.
  const staffForeign = await call('cle', 'GET', `/${RUN_C2}`,
    asCourse1({ user: { role: 'instructor', userId: STAFF } }));
  assert.strictEqual(staffForeign.status, 404);

  // Somebody in neither the roster nor the staff list gets the same answer as a
  // run that is not there.
  const outsider = await call('cle', 'GET', `/${RUN_C1}`,
    asCourse1({ user: { role: 'student', userId: OUTSIDER } }));
  assert.strictEqual(outsider.status, 404);
  assert.deepStrictEqual(outsider.body, missing.body);
});

test('E5-R6: a CiAB student with no lane in the engagement gets a 404, not a 403', async () => {
  resetState();
  const ok = await call('ciab', 'GET', `/${RUN_E1}`, asEngagement());
  assert.strictEqual(ok.status, 200, 'the student who HOLDS a lane can read the board');
  assert.strictEqual(ok.body.tier, 'student');

  const none = await call('ciab', 'GET', `/${RUN_E1}`,
    asEngagement({ user: { role: 'student', userId: OUTSIDER } }));
  assert.strictEqual(none.status, 404);

  // A lane that has been torn down is not a lane.
  state.lanes[0].status = 'destroyed';
  const stale = await call('ciab', 'GET', `/${RUN_E1}`, asEngagement());
  assert.strictEqual(stale.status, 404);
});

test('E5-R7: the student board carries the whitelist and nothing else, over the wire', async () => {
  resetState();
  const projection = require('../src/incident/projection');
  const res = await call('ciab', 'GET', `/${RUN_E1}`, asEngagement());
  assert.strictEqual(res.status, 200);

  assert.deepStrictEqual(
    Object.keys(res.body.run).sort(),
    projection.STUDENT_RUN_KEYS.slice().sort()
  );
  const wire = JSON.stringify(res.body);
  for (const secret of ['THE-WHOLE-ATTACK', 'T1110.001', 'TA0006', 'ransomware-ryuk',
    'loggen-2026.02', 'answer_key', 'playbook', 'T1486', 'catalog_version']) {
    assert.ok(!wire.includes(secret), `${secret} reached a student response`);
  }

  // Pre-release: submissions only, and NO technique count.
  assert.strictEqual(res.body.score.released, false);
  assert.ok(!Object.prototype.hasOwnProperty.call(res.body.score, 'techniques_total'));

  // The SQL that ran never asked for the private columns in the first place —
  // layer 2. A projection bug must be a missing field, not a disclosure.
  const runSelects = state.sql.filter((s) => /FROM cybercore_incident_run/.test(s));
  assert.ok(runSelects.length > 0);
  for (const sql of runSelects) {
    assert.ok(!/answer_key|r\.playbook|technique_id|catalog_version/.test(sql),
      `a student read asked Postgres for a private column:\n${sql}`);
  }
});

test('E5-R8: a student write cannot set auto_* or override_*', async () => {
  resetState();
  const res = await call('ciab', 'POST', `/${RUN_E1}/findings`, asEngagement({
    body: {
      kind: 'finding',
      technique_id: 'T1486',
      title: 'ransomware',
      // Everything below is an attempt to grade oneself.
      auto_verdict: 'hit',
      auto_points: 99,
      auto_matched_key: 'T1486',
      auto_note: 'nice',
      scored_at: '2026-03-01T10:00:00.000Z',
      override_verdict: 'hit',
      override_points: 99,
      override_note: 'PRIVATE',
      override_by: STUDENT,
      user_id: STAFF,
      run_id: RUN_C2,
    },
  }));
  assert.strictEqual(res.status, 201);

  // What was STORED, not what came back. The insert names its columns, so the
  // only way any of these could be set is if the whitelist grew.
  assert.strictEqual(state.findings.length, 1);
  const stored = state.findings[0];
  for (const col of ['auto_verdict', 'auto_points', 'auto_matched_key', 'auto_note', 'scored_at',
    'override_verdict', 'override_points', 'override_note', 'override_by', 'override_at']) {
    assert.strictEqual(stored[col], undefined, `a student write set ${col}`);
  }
  // The row is attributed to the CALLER and to the run in the URL, never to
  // whatever the body claimed.
  assert.strictEqual(stored.user_id, STUDENT);
  assert.strictEqual(stored.run_id, RUN_E1);
  // The student's lane is recorded from the target table, not from the body.
  assert.strictEqual(stored.target_id, null, 'no target row exists for this run in the fixture');

  // And the response is the student projection: no verdict yet, no note.
  assert.strictEqual(res.body.finding.verdict, null);
  assert.ok(!Object.prototype.hasOwnProperty.call(res.body.finding, 'override_note'));
  assert.ok(!JSON.stringify(res.body).includes('PRIVATE'));
});

test('E5-R9: the body is validated, and a bad claim is a 400 with a code', async () => {
  resetState();
  const badKind = await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'grade_me' } }));
  assert.strictEqual(badKind.status, 400);
  assert.strictEqual(badKind.body.code, 'BAD_KIND');

  const badTech = await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'finding', technique_id: 'DROP TABLE' } }));
  assert.strictEqual(badTech.status, 400);
  assert.strictEqual(badTech.body.code, 'BAD_TECHNIQUE');

  const iocNoValue = await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'ioc', ioc_type: 'ip' } }));
  assert.strictEqual(iocNoValue.status, 400);
  assert.strictEqual(iocNoValue.body.code, 'BAD_IOC_VALUE');

  const timelineNoTech = await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'timeline' } }));
  assert.strictEqual(timelineNoTech.status, 400);
  assert.strictEqual(timelineNoTech.body.code, 'BAD_TIMELINE');

  assert.strictEqual(state.findings.length, 0, 'and none of them stored anything');
});

test('E5-R10: a student cannot drive the instructor sub-routes', async () => {
  resetState();
  await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'finding', technique_id: 'T1486' } }));
  const findingId = state.findings[0].finding_id;

  for (const [method, url] of [
    ['PATCH', `/${RUN_E1}/findings/${findingId}`],
    ['POST', `/${RUN_E1}/score`],
    ['POST', `/${RUN_E1}/release`],
  ]) {
    const res = await call('ciab', method, url, asEngagement({ body: { override_verdict: 'hit' } }));
    assert.strictEqual(res.status, 403, `${method} ${url} was not refused`);
  }
  assert.strictEqual(state.findings[0].override_verdict, undefined,
    'nothing was written on the way to the refusal');

  // The same refusal on the CLE side comes from the per-request tier rather
  // than a role gate — an instructor of another course is not staff here.
  const cle = await call('cle', 'POST', `/${RUN_C1}/release`, asCourse1());
  assert.strictEqual(cle.status, 403);
});

test('E5-R11: an instructor CAN adjudicate, and the note stays staff-side', async () => {
  resetState();
  await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'finding', technique_id: 'T1486' } }));
  const findingId = state.findings[0].finding_id;

  const res = await call('ciab', 'PATCH', `/${RUN_E1}/findings/${findingId}`, asEngagement({
    user: { role: 'instructor', userId: STAFF },
    body: { override_verdict: 'hit', override_points: 0.75, override_note: 'seen in office hours' },
  }));
  assert.strictEqual(res.status, 200);
  assert.strictEqual(state.findings[0].override_verdict, 'hit');
  assert.strictEqual(state.findings[0].override_points, 0.75);
  assert.strictEqual(state.findings[0].override_by, STAFF);

  // The scorer's own columns were NOT touched, which is what makes a re-score
  // safe to run at any time.
  assert.strictEqual(state.findings[0].auto_verdict, undefined);

  // A verdict outside the CHECK is a 400, not a constraint violation at 500.
  const bogus = await call('ciab', 'PATCH', `/${RUN_E1}/findings/${findingId}`, asEngagement({
    user: { role: 'instructor', userId: STAFF },
    body: { override_verdict: 'full_marks' },
  }));
  assert.strictEqual(bogus.status, 400);
  assert.strictEqual(bogus.body.code, 'BAD_VERDICT');

  // And the student still cannot read the note that was written about them.
  const student = await call('ciab', 'GET', `/${RUN_E1}`, asEngagement());
  assert.ok(!JSON.stringify(student.body).includes('office hours'));
});

test('E5-R12: after release the board closes to new submissions', async () => {
  resetState();
  state.scores.push({
    run_id: RUN_E1, user_id: STUDENT, techniques_total: 3, techniques_found: 1,
    techniques_missed: 2, iocs_total: 2, iocs_found: 0, false_positives: 0,
    timeline_score: null, first_detection_at: null, ttd_seconds: null,
    auto_points: '1.00', override_points: null, final_points: '1.00',
    released: true, released_at: '2026-03-01T12:00:00.000Z', released_by: STAFF,
    scored_at: '2026-03-01T11:00:00.000Z',
  });

  const late = await call('ciab', 'POST', `/${RUN_E1}/findings`,
    asEngagement({ body: { kind: 'finding', technique_id: 'T1486' } }));
  assert.strictEqual(late.status, 409, 'a submission after the answers are visible is a transcription');
  assert.strictEqual(late.body.code, 'BOARD_RELEASED');
  assert.strictEqual(state.findings.length, 0);

  // And now the counts ARE visible — that is what release means.
  const board = await call('ciab', 'GET', `/${RUN_E1}`, asEngagement());
  assert.strictEqual(board.body.score.released, true);
  assert.strictEqual(board.body.score.techniques_total, 3);
  assert.strictEqual(board.body.score.points, 1);
});

test('E5-R13: /status answers without any of the board, for the 2s poll', async () => {
  resetState();
  const res = await call('ciab', 'GET', `/${RUN_E1}/status`, asEngagement());
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(Object.keys(res.body).sort(),
    ['finished_at', 'released', 'run_id', 'status', 'submitted']);
  assert.strictEqual(res.body.released, false);
  assert.strictEqual(res.body.submitted, 0);
});

test('E5-R14: the run LIST is projected too, at the student tier', async () => {
  resetState();
  const projection = require('../src/incident/projection');
  const student = await call('ciab', 'GET', '/', asEngagement());
  assert.strictEqual(student.status, 200);
  assert.strictEqual(student.body.tier, 'student');
  assert.strictEqual(student.body.runs.length, 1);
  assert.deepStrictEqual(Object.keys(student.body.runs[0]).sort(),
    projection.STUDENT_RUN_KEYS.slice().sort());
  assert.ok(!JSON.stringify(student.body).includes('ransomware-ryuk'));

  const staff = await call('ciab', 'GET', '/',
    asEngagement({ user: { role: 'instructor', userId: STAFF } }));
  assert.strictEqual(staff.body.tier, 'staff');
  assert.strictEqual(staff.body.runs[0].chain_key, 'ransomware-ryuk',
    'an instructor DOES see what they launched');
});
