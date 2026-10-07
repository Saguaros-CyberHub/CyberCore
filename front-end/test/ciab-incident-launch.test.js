/**
 * ciab-incident-launch.test.js — Track E, phase E6: the CiAB incident launcher.
 *
 * The endpoints an instructor drives a clinic's incident from, addressed by
 * ENGAGEMENT: GET /catalog, GET /targets, POST /, POST /:runId/abort,
 * POST /:runId/retry. They live in
 * modules/crucible/plugins/ciab/routes/incident-launch.js and are MOUNTED
 * INSIDE routes/incidents.js, so every request below is driven through the
 * board router — which is the only way the mount ORDER gets tested at all.
 *
 * SOURCE SCANS AND EXECUTED BEHAVIOUR, and both are needed for the same reason
 * incident-board-routes.test.js gives: a scan pins a property over a whole file
 * including handlers no test calls, and it cannot see a status code or a body.
 *
 * THE PROPERTIES, AND WHY EACH ONE EARNS A TEST
 *
 *   1. MODE 'scenario' IS ACCEPTED, AND ONLY WITH A REAL SCENARIO. E7 landed
 *      the compiler, so the blanket refusal this file used to pin is gone —
 *      engines/synthetic.js now answers supportsMode('scenario') true. What
 *      replaced it is narrower and stricter: a scenario id that names nothing
 *      on this Client is a NAMED 400 raised before any row exists. The failure
 *      being guarded against never changed — a run that dispatches an EMPTY
 *      playbook reports 'completed' having generated nothing, which looks
 *      exactly like a working exercise. front-end/test/ciab-scenario-e2e.test.js
 *      is where the accepting half is exercised end to end.
 *
 *   2. A BAD SELECTION IS REJECTED, NOT INTERPOLATED. technique_id reaches a
 *      root shell inside a student's VM. resolveSelection refuses anything the
 *      catalog does not offer, and it must refuse BEFORE a run row exists —
 *      the dispatch mutex is partial on 'scheduling', so an abandoned row would
 *      hold the whole engagement.
 *
 *   3. THE MUTEX IS A 409, NOT A 500. ux_cc_incident_run_dispatching is a
 *      UNIQUE index, so a second Launch arrives as constraint violation 23505.
 *      Unmapped, an instructor sees a 500 naming a Postgres index.
 *
 *   4. A STUDENT CANNOT LAUNCH, ABORT OR RETRY. Neither mount applies a role
 *      gate: /api/engagements/... carries requireCiabAccess, which is an
 *      ENROLLMENT gate and answers the wrong question for someone whose actual
 *      problem is that they are not staff.
 *
 *   5. ANOTHER SCOPE'S RUN IS A 404, and scope_type is in the predicate. A
 *      course id and an engagement id are both UUIDs from the same space.
 *
 *   6. THE CATALOG NEVER REACHES A STUDENT. catalog_version names the exact
 *      log-generator build; a student who can read it can diff two runs, which
 *      is why projection.js keeps it off every student payload.
 *
 *   7. THE ANSWER KEY IS COMPILED INTO THE INSERT, SEEDED BY THE RUN ID, and
 *      never returned. engines/synthetic.js: compiling it afterwards leaves a
 *      window in which a completed run has no key and the board grades every
 *      correct answer as a false positive.
 *
 * Run: node --test test/ciab-incident-launch.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const LAUNCH_FILE = path.join(CIAB, 'routes', 'incident-launch.js');
const BOARD_FILE = path.join(CIAB, 'routes', 'incidents.js');
const read = (p) => fs.readFileSync(p, 'utf8');

/** Borrowed from incident-board-routes.test.js. See its header for why. */
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
// Fixture ids. Real uuids: every reader refuses anything else before SQL.
// ---------------------------------------------------------------------------
const ENGAGEMENT = '33333333-3333-3333-3333-333333333333';
const ENGAGEMENT_B = '44444444-4444-4444-4444-444444444444';
const COURSE = '11111111-1111-1111-1111-111111111111';
const PROFILE = '55555555-5555-5555-5555-555555555555';
const SECTION_MINE = '66666666-6666-6666-6666-666666666666';
const SECTION_THEIRS = '77777777-7777-7777-7777-777777777777';
const RUN_E = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const RUN_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const RUN_COURSE = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const STAFF = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const STUDENT = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
const LANE_1 = '00000001-0000-0000-0000-000000000000';
const LANE_2 = '00000002-0000-0000-0000-000000000000';

// ---------------------------------------------------------------------------
// §1 Source scans
// ---------------------------------------------------------------------------

test('E6-L1: the launcher is mounted ABOVE the board\'s /:runId, or /catalog 404s', () => {
  const board = codeOnly(read(BOARD_FILE));
  const mount = board.indexOf("router.use(require('./incident-launch'))");
  assert.ok(mount >= 0, 'routes/incidents.js must mount the launcher');
  const runIdRoute = board.indexOf("router.get('/:runId'");
  assert.ok(runIdRoute >= 0, "the board still has to own GET /:runId");
  // Express matches in REGISTRATION ORDER. Below /:runId, both /catalog and
  // /targets would be read as run ids, and board.readRunForStaff rejects a
  // non-uuid before SQL — so the symptom is a flat 404 with no explanation.
  assert.ok(mount < runIdRoute,
    'the launcher must be mounted before GET /:runId or /catalog and /targets are swallowed');
});

test('E6-L2: launch, abort and retry each carry their own role gate', () => {
  const src = read(LAUNCH_FILE);
  for (const decl of ["router.post('/'", "router.post('/:runId/abort'",
    "router.post('/:runId/retry'", "router.get('/catalog'", "router.get('/targets'"]) {
    const i = src.indexOf(decl);
    assert.ok(i >= 0, `${decl} is missing from the launcher`);
    const line = src.slice(i, src.indexOf('\n', i));
    assert.ok(line.includes('instructorOnly'), `${decl} has no role gate`);
  }
  assert.match(src, /const instructorOnly = requireRole\('instructor', 'admin'\)/);
});

test('E6-L3: the launcher reads no star select, and returns no key', () => {
  const code = codeOnly(read(LAUNCH_FILE));
  // It WRITES answer_key — that is the whole point of the INSERT — but it must
  // never read the column back, and RETURNING is a narrow list for the same
  // reason board.js's column lists are: a star select puts the graded truth in
  // the same object a handler might spread into a response.
  assert.ok(!code.includes('SELECT *'), 'the launcher contains a star select');
  assert.ok(!code.includes('RETURNING *'), 'the launcher returns the whole run row');
  assert.ok(!/SELECT[^;]*answer_key/i.test(code), 'the launcher reads the answer key back');
  assert.ok(!/RETURNING[^`]*answer_key/i.test(code), 'the launcher returns the answer key');
});

test('E6-L4: the launcher lives outside the student-facing board file', () => {
  // routes/incidents.js is student-facing: students read boards and bank
  // findings through it, and incident-answer-key-leak.test.js forbids the
  // string 'answer_key' anywhere in it. The writer therefore lives next door,
  // which is also the split CLE already has (board vs attacks.js).
  const board = codeOnly(read(BOARD_FILE));
  assert.ok(!board.includes('answer_key'),
    'the student-facing board file must not name the answer key');
  assert.ok(codeOnly(read(LAUNCH_FILE)).includes('answer_key'),
    'the launcher is where the key is written; if that moved, move this test');
});

test('E6-L5: mode scenario is implemented, and the blanket refusal is gone', () => {
  const code = codeOnly(read(LAUNCH_FILE));

  // THIS ASSERTION IS INVERTED FROM WHAT E6 SHIPPED, ON PURPOSE. Its previous
  // form pinned supportsMode('scenario') === false and said in as many words
  // "if this flips, E4 landed and the refusal below needs revisiting". E4
  // landed src/incident/scenario-compiler.js and E7 wired it, so it flipped and
  // the refusal was lifted. The failing test WAS the signal, not a regression.
  const engine = require('../src/incident/engines').engineFor('synthetic');
  assert.strictEqual(engine.supportsMode('scenario'), true,
    'E7 wired the compiler; the engine must claim the mode it can now run');

  // The launcher WRITES the scenario columns — that is what makes the run
  // reproducible and the answer key gradable — so their presence is now
  // required rather than forbidden.
  assert.ok(/scenario_id/.test(code), 'the launcher must record which scenario ran');
  assert.ok(/scenario_ref/.test(code),
    'and a snapshot of it, so a regenerated profile cannot rename a graded incident');

  // What must NOT come back is the old blanket refusal. A route that still
  // carried it would refuse a mode the picker now offers.
  assert.ok(!/SCENARIO_MODE_UNAVAILABLE/.test(code),
    'the compiler shipped; a blanket scenario refusal is now a bug');
  // Source text, NOT require(). Requiring the launcher here would load it
  // before loadRouter() has put the stubs in the module cache, and the whole of
  // §3 would then be bound to the real pools — the trap resetState() documents.
  assert.ok(!/SCENARIO_REFUSAL/.test(code), 'the refusal constant is gone with the refusal');
});

// ---------------------------------------------------------------------------
// §2 The module graph, replaced
// ---------------------------------------------------------------------------

const state = {
  runs: [],
  inserts: [],       // every INSERT the launcher issued, as { sql, params }
  targetRows: [],
  updates: [],
  insertError: null, // set to make the next run INSERT fail (the mutex test)
  modules: [],       // ciab_module rows binding a section to (profile, type)
  managedSections: new Set([SECTION_MINE]),
  dispatched: [],
  aborted: [],
  retried: [],
  targets: [],
  // E7. Rows the `profiles` table would return for scenario-source.js. Empty
  // means "this client has no readable profile", which is what makes every
  // scenario id name nothing here.
  profiles: [],
};

function resetState() {
  // FIRST, ALWAYS. put() only helps a module that has not been required yet:
  // incident-launch.js destructures `cybercoreQuery` and `query` at load time,
  // so anything that requires it before the stubs are in the cache binds it to
  // the real pools for the rest of the process — and the symptom is a test
  // suite that spends a minute timing out against a Postgres that is not there.
  loadRouter();
  state.runs = [
    { run_id: RUN_E, scope_type: 'engagement', scope_id: ENGAGEMENT, engine: 'synthetic',
      status: 'completed', mode: 'technique', technique_id: 'T1110.001', tactic_id: null,
      chain_key: null, duration_seconds: 600, speed: null, scope_label: 'Defensive Monitoring',
      catalog_version: '2.0.0', created_at: null, finished_at: null },
    { run_id: RUN_B, scope_type: 'engagement', scope_id: ENGAGEMENT_B, engine: 'synthetic',
      status: 'completed', mode: 'technique', technique_id: 'T1110.001', tactic_id: null,
      chain_key: null, duration_seconds: 600, speed: null, scope_label: 'Someone else',
      catalog_version: '2.0.0', created_at: null, finished_at: null },
    // Same shape, different SCOPE TYPE. This is what makes the scope_type half
    // of the predicate testable rather than assumed.
    { run_id: RUN_COURSE, scope_type: 'course', scope_id: ENGAGEMENT, engine: 'synthetic',
      status: 'completed', mode: 'technique', technique_id: 'T1110.001', tactic_id: null,
      chain_key: null, duration_seconds: 600, speed: null, scope_label: 'CYBR400-01',
      catalog_version: '2.0.0', created_at: null, finished_at: null },
  ];
  state.inserts = [];
  state.targetRows = [];
  state.updates = [];
  state.insertError = null;
  state.modules = [];
  state.managedSections = new Set([SECTION_MINE]);
  state.dispatched = [];
  state.aborted = [];
  state.retried = [];
  state.profiles = [];
  state.targets = [
    { lane_id: LANE_1, user_id: STUDENT, student_email: 'a@clinic.local', node: 'pve1',
      vmid: 1101, vm_name: 'sensor-1', resolved_by: 'template', resolvable: true, skip_reason: null },
    { lane_id: LANE_2, user_id: STAFF, student_email: 'b@clinic.local', node: 'pve1',
      vmid: null, vm_name: null, resolved_by: null, resolvable: false,
      skip_reason: 'no log-generator VM' },
  ];
}

const selectList = (sql) => /SELECT\s+([\s\S]*?)\s+FROM\s/i.exec(sql)[1];

function pick(list, row) {
  const out = {};
  for (const raw of list.split(',')) {
    const col = raw.trim().replace(/^[a-z_]+\./i, '');
    if (col) out[col] = row[col] === undefined ? null : row[col];
  }
  return out;
}

/**
 * The fake cybercoreQuery. It INTERPRETS the statements rather than returning
 * canned rows, so the column lists are exercised and an unrecognised statement
 * throws loudly instead of silently returning zero rows.
 */
async function fakeCybercoreQuery(sql, params) {
  const p = params || [];

  if (/^\s*SELECT[\s\S]*FROM cybercore_incident_run\s+WHERE run_id/i.test(sql)) {
    // The literal 'engagement' is in the SQL text, so scope_type is filtered
    // here rather than bound — which is exactly the property under test.
    const row = state.runs.find((r) => r.run_id === p[0]
      && r.scope_type === 'engagement' && r.scope_id === p[1]);
    return { rows: row ? [pick(selectList(sql), row)] : [] };
  }
  if (/^\s*INSERT INTO cybercore_incident_run/i.test(sql)) {
    state.inserts.push({ sql, params: p });
    if (state.insertError) {
      const err = new Error('duplicate key value violates unique constraint');
      err.code = state.insertError;
      throw err;
    }
    // Positional, and it MUST stay in step with the INSERT's own column list —
    // that is the point of interpreting the statement rather than canning a
    // row. E7 widened it with the three scenario columns.
    const row = { run_id: p[0], scope_type: 'engagement', scope_id: p[1], scope_label: p[2],
      engine: p[3], launched_by: p[4], mode: p[5], technique_id: p[6], tactic_id: p[7],
      chain_key: p[8], scenario_id: p[9], scenario_ref: p[10], playbook: p[11],
      duration_seconds: p[12], speed: p[13], catalog_version: p[14],
      answer_key: p[15], status: 'scheduling', created_at: '2026-09-01T10:00:00.000Z' };
    state.runs.push(row);
    return { rows: [{ run_id: row.run_id, status: row.status, created_at: row.created_at }] };
  }
  if (/^\s*INSERT INTO cybercore_incident_target/i.test(sql)) {
    state.targetRows.push(p);
    return { rows: [] };
  }
  if (/^\s*UPDATE cybercore_incident_run/i.test(sql)) {
    state.updates.push({ sql, params: p });
    return { rows: [] };
  }
  throw new Error(`fakeCybercoreQuery: unhandled SQL\n${sql}`);
}

/** The CiAB plugin pool. Only the section-binding lookup reaches it. */
async function fakeCiabQuery(sql, params) {
  if (/FROM ciab_module/i.test(sql)) {
    const rows = state.modules
      .filter((m) => m.profile_id === params[0] && m.engagement_type === params[1])
      .map((m) => ({ section_id: m.section_id }));
    return { rows };
  }
  // E7. utils/scenario-source.js reads the engagement's telemetry plan and then
  // the client's profile row. Answered here with a REAL engagement and NO
  // profile JSON, which is the shape E6-R1 needs: the compile refuses with a
  // named 400 rather than a 404 about an engagement that plainly exists.
  if (/FROM ciab_engagement/i.test(sql)) {
    return {
      rows: String(params[0]) === ENGAGEMENT
        ? [{ engagement_id: ENGAGEMENT, profile_id: PROFILE,
            engagement_type: 'defensive_monitoring', telemetry_plan: {} }]
        : [],
    };
  }
  if (/FROM profiles/i.test(sql)) return { rows: state.profiles };
  throw new Error(`fakeCiabQuery: unhandled SQL\n${sql}`);
}

function put(modPath, exports) {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
}

let ROUTER = null;
function loadRouter() {
  if (ROUTER) return ROUTER;

  put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: fakeCybercoreQuery });
  put(path.join(ROOT, 'src', 'utils', 'audit.js'), {
    log: async () => {},
    batch: async () => 'aaaaaaaa-0000-0000-0000-00000000ffff',
  });
  put(path.join(ROOT, 'src', 'middleware', 'auth.js'), {
    authenticateToken: (req, res, next) => next(),
    requireRole: (...roles) => (req, res, next) => (
      req.user && roles.includes(req.user.role)
        ? next()
        : res.status(403).json({ error: 'forbidden' })
    ),
  });
  put(path.join(CIAB, 'utils', 'db.js'), { query: fakeCiabQuery });
  put(path.join(CIAB, 'utils', 'enrollment.js'), {
    canManageSection: async (sectionId, user) => (
      !!user && (user.role === 'admin' || state.managedSections.has(String(sectionId)))
    ),
  });
  // The launcher requires this LAZILY (it drags config/site.json in at module
  // scope through batch-deployer), so the stub has to be in the cache before
  // the first REQUEST rather than before the require.
  put(path.join(CIAB, 'utils', 'engagement-provision.js'), {
    getEngagementById: async (id) => (
      String(id) === ENGAGEMENT
        ? { engagement_id: ENGAGEMENT, profile_id: PROFILE, engagement_type: 'defensive_monitoring',
            display_name: 'Defensive Monitoring', retired_at: null }
        : null
    ),
  });

  // The REAL runner and the REAL engine adapter: resolveSelection and
  // compileAnswerKey are the two things under test and stubbing them would test
  // the stub. Only the four functions that reach Proxmox are replaced, on the
  // module's own exports object — which is what the route holds.
  const runner = require('../src/incident/runner');
  runner.resolveScopeTargets = async () => state.targets.slice();
  runner.makeGuestProbe = () => null;
  runner.dispatchRun = async (args) => { state.dispatched.push(args); };
  runner.abortRun = async (runId) => { state.aborted.push(runId); return { aborted: 1 }; };
  runner.retryTargets = async (args) => { state.retried.push(args); return { retried: 1 }; };

  ROUTER = require(path.join(CIAB, 'routes', 'incidents.js'));
  return ROUTER;
}

/** One request through the BOARD router, so the launcher's mount is exercised. */
function call(method, url, opts) {
  const o = opts || {};
  const router = loadRouter();
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: {}, headers: {}, params: {},
      user: o.user === null ? undefined : (o.user || { role: 'student', userId: STUDENT }),
    };
    let done = false;
    const finish = (payload, res) => {
      if (done) return;
      done = true;
      resolve({ status: res.statusCode, body: payload, headers: res.headers });
    };
    const res = {
      statusCode: 200,
      headersSent: false,
      locals: Object.assign({ engagementId: ENGAGEMENT }, o.locals || {}),
      headers: {},
      status(code) { this.statusCode = code; return this; },
      set(k, v) { this.headers[k] = v; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      getHeader(k) { return this.headers[k]; },
      json(payload) { this.headersSent = true; finish(payload, this); return this; },
      send(payload) { this.headersSent = true; finish(payload, this); return this; },
      end() { this.headersSent = true; finish(null, this); return this; },
    };
    router(req, res, (err) => (err ? reject(err) : resolve({ status: 404, body: null })));
  });
}

/** Let the detached launchInBackground() finish before asserting on its rows. */
const settle = () => new Promise((r) => setImmediate(() => setImmediate(r)));

const staff = { role: 'instructor', userId: STAFF };
const admin = { role: 'admin', userId: STAFF };
const student = { role: 'student', userId: STUDENT };

// ---------------------------------------------------------------------------
// §3 Executed behaviour
// ---------------------------------------------------------------------------

test('E6-R1: a scenario id that names nothing is refused, and writes nothing', async () => {
  resetState();
  // This fixture's stubbed engagement resolves to a profile with no readable
  // JSON, so `scenarios` is empty and every id names nothing — which is the
  // shape under test here. ciab-scenario-e2e.test.js drives the accepting half
  // against a real compiled profile.
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'scenario', scenario_id: 'sc-1', duration_seconds: 600 },
  });

  assert.strictEqual(res.status, 400, 'an unknown scenario is a client error, not a 500');
  assert.ok(['UNKNOWN_SCENARIO', 'NO_SCENARIOS'].includes(res.body.code),
    `a NAMED refusal, got ${JSON.stringify(res.body.code)}`);
  // It has to say what to do instead, or an instructor reads it as a bug in a
  // picker that offered them the option.
  assert.match(res.body.error, /scenario/i);

  // And crucially: no run row. A row at 'scheduling' holds the dispatch mutex
  // for the whole engagement until something sweeps it — and a scenario run
  // with no playbook would dispatch nothing while reporting success.
  assert.strictEqual(state.inserts.length, 0, 'a refused scenario must not reach the run table');
});

test('E6-R2: an invalid technique id is rejected, never interpolated', async () => {
  resetState();
  // T9999 matches TECHNIQUE_RE but is not in the catalog — the exact case the
  // regex alone would let through into a root shell.
  const bogus = await call('POST', '/', {
    user: staff, body: { mode: 'technique', technique_id: 'T9999', duration_seconds: 600 },
  });
  assert.strictEqual(bogus.status, 400);
  assert.strictEqual(bogus.body.code, 'INVALID_SELECTION');
  assert.match(bogus.body.error, /catalog/i);
  assert.strictEqual(state.inserts.length, 0);

  // A shell metacharacter is refused by shape, before the catalog lookup.
  const injected = await call('POST', '/', {
    user: staff,
    body: { mode: 'technique', technique_id: "T1110.001'; rm -rf /", duration_seconds: 600 },
  });
  assert.strictEqual(injected.status, 400);
  assert.strictEqual(state.inserts.length, 0, 'nothing may be written for an unvalidated selection');

  // An unknown chain, and a mode nothing offers.
  const chain = await call('POST', '/', {
    user: staff, body: { mode: 'chain', chain_key: 'not-a-chain' },
  });
  assert.strictEqual(chain.status, 400);
  const nonsense = await call('POST', '/', { user: staff, body: { mode: 'wat' } });
  assert.strictEqual(nonsense.status, 400);
  assert.strictEqual(nonsense.body.code, 'UNSUPPORTED_MODE');

  // A chain with a duration is a correlated CHECK violation in the DB and a
  // 400 here, because a constraint violation explains nothing.
  const chainDuration = await call('POST', '/', {
    user: staff, body: { mode: 'chain', chain_key: 'ransomware-ryuk', duration_seconds: 600 },
  });
  assert.strictEqual(chainDuration.status, 400);
  assert.match(chainDuration.body.error, /scripted length/i);
  assert.strictEqual(state.inserts.length, 0);
});

test('E6-R3: the dispatch mutex surfaces as 409, not 500', async () => {
  resetState();
  state.insertError = '23505';   // ux_cc_incident_run_dispatching
  const res = await call('POST', '/', {
    user: staff, body: { mode: 'technique', technique_id: 'T1110.001', duration_seconds: 600 },
  });

  assert.strictEqual(res.status, 409, 'a concurrent launch is a conflict, not a server error');
  assert.strictEqual(res.body.code, 'INCIDENT_IN_FLIGHT');
  // The index survives a restart, so the message must say how to clear it
  // rather than implying it expires on its own.
  assert.match(res.body.error, /abort/i);
  // CiAB vocabulary: Engagement, never course or cohort.
  assert.match(res.body.error, /engagement/i);
  assert.ok(!/course|cohort|lane/i.test(res.body.error), 'CLE vocabulary in a CiAB message');
  assert.strictEqual(state.inserts.length, 1, 'the INSERT is what raised it');
});

test('E6-R4: a student cannot launch, abort or retry', async () => {
  resetState();
  const attempts = [
    ['POST', '/', { mode: 'technique', technique_id: 'T1110.001', duration_seconds: 600 }],
    ['POST', `/${RUN_E}/abort`, {}],
    ['POST', `/${RUN_E}/retry`, {}],
  ];
  for (const [method, url, body] of attempts) {
    const res = await call(method, url, { user: student, body });
    assert.strictEqual(res.status, 403, `${method} ${url} is open to a student`);
  }
  // Reads too: the catalog and the picker are staff surfaces.
  for (const url of ['/catalog', '/targets']) {
    const res = await call('GET', url, { user: student });
    assert.strictEqual(res.status, 403, `GET ${url} is open to a student`);
  }
  assert.strictEqual(state.inserts.length, 0);
  assert.strictEqual(state.aborted.length, 0);
  assert.strictEqual(state.retried.length, 0);
});

test('E6-R5: a run from another engagement — or another scope type — is a 404', async () => {
  resetState();
  const cases = [
    `/${RUN_B}/abort`,                                        // another engagement
    `/${RUN_B}/retry`,
    `/${RUN_COURSE}/abort`,                                   // a course run, colliding scope_id
    `/${RUN_COURSE}/retry`,
    '/00000000-0000-0000-0000-000000000000/abort',            // no such run
    '/not-a-uuid/abort',                                      // not even an id
  ];
  const bodies = [];
  for (const url of cases) {
    const res = await call('POST', url, { user: staff });
    assert.strictEqual(res.status, 404, `${url} must be a 404`);
    bodies.push(JSON.stringify(res.body));
  }
  assert.strictEqual(new Set(bodies).size, 1,
    'every refusal must be byte-identical, or the launcher is an enumeration oracle');
  assert.strictEqual(state.aborted.length, 0, 'nothing may be signalled for a foreign run');
  assert.strictEqual(state.retried.length, 0);

  // The engagement itself, when it is not yours: the module binding names a
  // section this instructor does not manage.
  state.modules = [{ profile_id: PROFILE, engagement_type: 'defensive_monitoring',
    section_id: SECTION_THEIRS }];
  const theirs = await call('POST', `/${RUN_E}/abort`, { user: staff });
  assert.strictEqual(theirs.status, 404, "somebody else's clinic must not be distinguishable");
  assert.strictEqual(JSON.parse(bodies[0]).error, theirs.body.error);

  // An admin is never locked out of a block they reserved.
  const asAdmin = await call('POST', `/${RUN_E}/abort`, { user: admin });
  assert.strictEqual(asAdmin.status, 202);
  await settle();
  assert.deepStrictEqual(state.aborted, [RUN_E]);
});

test('E6-R6: the catalog is staff-only, private, and never reaches a student', async () => {
  resetState();
  const denied = await call('GET', '/catalog', { user: student });
  assert.strictEqual(denied.status, 403);
  assert.ok(!JSON.stringify(denied.body).includes('catalog_version'),
    'catalog_version names the exact log-generator build; a student who reads it can diff two runs');

  const ok = await call('GET', '/catalog', { user: staff });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(ok.body.catalog_version, require('../src/incident/catalog').CATALOG_VERSION);
  assert.ok(Array.isArray(ok.body.techniques) && ok.body.techniques.length);
  // PRIVATE, never public: a shared cache would hand the build string to
  // whatever proxy sits in front of this.
  assert.match(String(ok.headers['Cache-Control']), /private/);
  assert.ok(!/public/.test(String(ok.headers['Cache-Control'])));

  // And the mount order holds: /catalog is not read as a run id.
  assert.ok(!('run' in ok.body), 'GET /catalog was answered by the board, not the launcher');
});

test('E6-R7: /targets lists environments without paying for the guest probe', async () => {
  resetState();
  let probeUsed = null;
  const runner = require('../src/incident/runner');
  const real = runner.resolveScopeTargets;
  runner.resolveScopeTargets = async (scope, opts) => {
    probeUsed = opts && opts.probe ? 'yes' : 'no';
    assert.deepStrictEqual(scope, { scopeType: 'engagement', scopeId: ENGAGEMENT });
    return state.targets.slice();
  };
  try {
    const res = await call('GET', '/targets', { user: staff });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.total, 2);
    assert.strictEqual(res.body.resolvable, 1);
    // Rung 4 costs a guest exec per candidate VM. This is a READ that runs on
    // every tab open; the probe belongs at launch and nowhere else.
    assert.strictEqual(probeUsed, 'no', '/targets must not run the guest probe');
  } finally {
    runner.resolveScopeTargets = real;
  }
});

test('E6-R8: a launch compiles the answer key INTO the insert, seeded by the run id', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff, body: { mode: 'technique', technique_id: 'T1110.001', duration_seconds: 600 },
  });

  assert.strictEqual(res.status, 202);
  assert.strictEqual(res.body.status, 'scheduling');
  assert.strictEqual(res.body.status_url,
    `/api/engagements/${ENGAGEMENT}/incidents/${res.body.run_id}/status`);
  // The /status suffix is what src/server.js exempts from the global rate
  // limiter; the console polls it at 2s.
  assert.match(res.body.status_url, /\/status$/);

  assert.strictEqual(state.inserts.length, 1);
  const { sql, params } = state.inserts[0];
  assert.ok(!/RETURNING\s+\*/i.test(sql), 'the insert must not return the whole row');
  assert.strictEqual(params[0], res.body.run_id, 'the run id is minted before the statement');
  assert.strictEqual(params[1], ENGAGEMENT);
  assert.strictEqual(params[3], 'synthetic');
  assert.strictEqual(params[5], 'technique');
  assert.strictEqual(params[6], 'T1110.001');
  assert.strictEqual(params[7], null);
  assert.strictEqual(params[8], null);
  assert.strictEqual(params[9], null, 'a technique run names no scenario');
  assert.strictEqual(params[10], null, 'and carries no scenario snapshot');
  assert.strictEqual(params[11], null, 'and no compiled playbook — its playbook is on disk');
  assert.strictEqual(params[12], 600);

  // THE SEED IS THE RUN ID. Compiled in the same statement, so there is no
  // window in which a finished run has no key and every correct answer scores
  // as a false positive.
  const key = JSON.parse(params[15]);
  assert.strictEqual(key.run_id, res.body.run_id);
  assert.strictEqual(key.engine, 'synthetic');
  assert.ok(key.techniques.length > 0 && key.totals.events > 0);
  // PLAYBOOKS holds the staged JSON as TEXT — it is what gets base64'd to the
  // guest — so the parse here mirrors engines/synthetic.js exactly.
  const raw = require('../src/incident/runner').playbookFor({ mode: 'technique', arg: 'T1110.001' });
  const direct = require('../src/incident/answer-key').compileAnswerKey({
    runId: res.body.run_id,
    playbook: typeof raw === 'string' ? JSON.parse(raw) : raw,
    requestedSeconds: 600,
  });
  assert.deepStrictEqual(key, direct, 'the stored key must be the one the guest will produce');

  // Never in the response.
  const wire = JSON.stringify(res.body);
  for (const secret of ['answer_key', 'techniques', 'iocs', 'timeline']) {
    assert.ok(!wire.includes(secret), `${secret} came back from a launch`);
  }

  // The detached half: target rows, then dispatch. Opt-OUT, so the unresolvable
  // environment is still recorded — as 'skipped', with its reason.
  await settle();
  assert.strictEqual(state.targetRows.length, 2);
  assert.strictEqual(state.targetRows[0][8], 'pending');
  assert.strictEqual(state.targetRows[1][8], 'skipped');
  assert.strictEqual(state.dispatched.length, 1);
  assert.strictEqual(state.dispatched[0].runId, res.body.run_id);
});

test('E6-R9: exclude_lane_ids is honoured, and a tactic stores an empty key', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'tactic', tactic_id: 'TA0006', duration_seconds: 600,
      exclude_lane_ids: [LANE_2] },
  });
  assert.strictEqual(res.status, 202);
  await settle();

  assert.strictEqual(state.targetRows.length, 1, 'the excluded environment must not be recorded');
  assert.strictEqual(state.targetRows[0][1], LANE_1);

  // {} is the HONEST key for a tactic: a dozen unrelated behaviours with no
  // single story to script. scoring.js reads it as "not auto-graded" and marks
  // every claim 'unscored', where a guessed key would mis-grade silently.
  assert.deepStrictEqual(JSON.parse(state.inserts[0].params[15]), {});
  assert.strictEqual(state.inserts[0].params[5], 'tactic');
  assert.strictEqual(state.inserts[0].params[7], 'TA0006');
});

test('E6-R10: retry rebuilds the selection from the stored run, and takes lane_ids', async () => {
  resetState();
  const res = await call('POST', `/${RUN_E}/retry`, {
    user: staff, body: { lane_ids: [LANE_1, 'nonsense'] },
  });
  assert.strictEqual(res.status, 202);
  assert.strictEqual(res.body.status, 'retrying');
  await settle();

  assert.strictEqual(state.retried.length, 1);
  const call0 = state.retried[0];
  assert.strictEqual(call0.runId, RUN_E);
  // Filtered, not trusted: this reaches `lane_id = ANY($2::uuid[])` and one bad
  // element fails the whole statement with a 22P02 nobody can act on.
  assert.deepStrictEqual(call0.laneIds, [LANE_1]);
  // Rebuilt from the ROW, so a retry means what the original launch meant.
  assert.strictEqual(call0.selection.mode, 'technique');
  assert.strictEqual(call0.selection.arg, 'T1110.001');

  // A run the catalog can no longer reproduce is a 409, not a silent re-fire.
  state.runs[0].technique_id = 'T9999';
  const gone = await call('POST', `/${RUN_E}/retry`, { user: staff });
  assert.strictEqual(gone.status, 409);
  assert.strictEqual(gone.body.code, 'RUN_NOT_REPRODUCIBLE');
  assert.strictEqual(state.retried.length, 1, 'nothing may be re-fired for an unreproducible run');
});

test('E6-R11: an unbound engagement is drivable; a bound one is its section\'s', async () => {
  resetState();
  // Bound to a section this instructor DOES manage.
  state.modules = [{ profile_id: PROFILE, engagement_type: 'defensive_monitoring',
    section_id: SECTION_MINE }];
  const mine = await call('GET', '/targets', { user: staff });
  assert.strictEqual(mine.status, 200);

  // Bound to somebody else's, plus one of mine: any single claim is enough.
  state.modules.push({ profile_id: PROFILE, engagement_type: 'defensive_monitoring',
    section_id: SECTION_THEIRS });
  assert.strictEqual((await call('GET', '/targets', { user: staff })).status, 200);

  // Bound ONLY to somebody else's.
  state.modules = [{ profile_id: PROFILE, engagement_type: 'defensive_monitoring',
    section_id: SECTION_THEIRS }];
  assert.strictEqual((await call('GET', '/targets', { user: staff })).status, 404);

  // Bound to nothing at all — the common case for an engagement created from
  // the admin reservation panel. Nothing claims it, so there is nobody to
  // exclude and refusing would make the launcher unusable.
  state.modules = [];
  assert.strictEqual((await call('GET', '/targets', { user: staff })).status, 200);

  // An engagement that does not exist is the same 404 as one that is not yours.
  const missing = await call('GET', '/targets', {
    user: staff, locals: { engagementId: ENGAGEMENT_B },
  });
  assert.strictEqual(missing.status, 404);
});
