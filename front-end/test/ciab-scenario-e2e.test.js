/**
 * ciab-scenario-e2e.test.js — Track E, phase E7: a scenario, end to end.
 * ============================================================================
 * E4 built the compiler (src/incident/scenario-compiler.js) and E7 wired it to
 * the button. This file drives THE WHOLE CHAIN with the module graph replaced
 * at the edges only:
 *
 *   instructor picks a scenario
 *     -> GET  /scenarios                          the picker's source
 *     -> POST /                                   compile + INSERT
 *          engines/synthetic.resolveSelection      validates the compiled half
 *          engines/synthetic.compileAnswerKey      reads the compiler's key
 *     -> runner.dispatchRun({ playbookJson })      what reaches the guest
 *     -> ciab_engagement.telemetry_plan            the choice, written down
 *
 * The REAL compiler, the REAL engine adapter and the REAL answer-key builder
 * run. Only the four functions that reach Proxmox, the two database handles and
 * the auth middleware are replaced — stubbing the compiler would test the stub,
 * and the properties below are all properties OF the compiler's output.
 *
 * ── THE PROPERTIES, AND WHY EACH ONE EARNS A TEST ──────────────────────────
 *
 *  1. A SCENARIO LAUNCH WRITES BOTH HALVES. mode 'scenario', a non-empty
 *     playbook AND a non-empty answer_key, in ONE statement. Either alone is a
 *     broken run: a playbook with no key is an ungradable incident, and a key
 *     with no playbook is a run that dispatches nothing while reporting
 *     success — the failure the mode was withheld for through E6.
 *
 *  2. AN UNKNOWN SCENARIO ID IS A NAMED 400, BEFORE ANY ROW EXISTS. The
 *     dispatch mutex is a partial UNIQUE index on (scope_type, scope_id) WHERE
 *     status IN ('scheduling','dispatching'), so a run row written and then
 *     abandoned holds the entire engagement until something sweeps it.
 *
 *  3. THE KEY'S TECHNIQUE SET IS THE ATTACK'S. The key is what the board grades
 *     against; if it names a technique the playbook never emits, every student
 *     is marked down for missing an event that did not happen.
 *
 *  4. totals.events IS THE PLANNED COUNT. It is the number an instructor
 *     quotes, and the E8 cluster gate compares it against Kibana's own hit
 *     count. It has to be the emitter's own planner, run against the same seed.
 *
 *  5. A STUDENT CANNOT LAUNCH ONE. Neither mount applies a role gate:
 *     /api/engagements/... carries requireCiabAccess, an ENROLLMENT gate, which
 *     answers the wrong question for someone whose problem is not being staff.
 *
 *  6. THE FLOOR AND THE ATTACK COME FROM ONE COMPILATION. The attack's pools
 *     are the floor's, which is what makes the vocabulary contract hold by
 *     construction. Two compilations of the same scenario must agree, or the
 *     deploy-time floor and the launch-time attack describe different estates.
 *
 * Run: node --test test/ciab-scenario-e2e.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

// ---------------------------------------------------------------------------
// Fixture ids. Real uuids: every reader refuses anything else before SQL.
// ---------------------------------------------------------------------------
const ENGAGEMENT = '33333333-3333-3333-3333-333333333333';
const PROFILE = '55555555-5555-5555-5555-555555555555';
const STAFF = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const STUDENT = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
const LANE_1 = '00000001-0000-0000-0000-000000000000';

/**
 * A client profile, in the CANONICAL layout the AI generator produces
 * (student_view.raw.threats.{network,threat_profile}). Written to a real file,
 * because scenario-source.js reads json_file_path off disk exactly as
 * routes/profile-deploy.js loadProfileForDeploy() does — stubbing `fs` would
 * skip the one part of that reader that has ever been wrong.
 *
 * Windows-dominant with two Linux servers, which is the shape a small clinic
 * really produces and the shape the compiler's bucketing was written against.
 */
const PROFILE_JSON = {
  id: PROFILE,
  company_name: 'Saguaro Family Dental',
  student_view: {
    stakeholders: [
      { name: 'Dana Okafor', email: 'dokafor@example.org' },
      { name: 'Miguel Torres' },
      { name: 'Priya Raman' },
    ],
    raw: {
      threats: {
        organization: { company_name: 'Saguaro Family Dental', industry: 'Healthcare' },
        network: {
          assets: [
            { hostname: 'DC01', ip: '10.50.10.10', role: 'server', os: 'Windows Server 2019', function: 'Domain controller and DNS', critical: true, services: ['389/LDAP', '445/SMB'] },
            { hostname: 'FILE01', ip: '10.50.10.11', role: 'server', os: 'Windows Server 2019', function: 'File share for finance and HR', critical: true, services: ['445/SMB'] },
            { hostname: 'SQL01', ip: '10.50.10.12', role: 'server', os: 'Windows Server 2022', function: 'Practice management database', services: ['1433/MSSQL'] },
            { hostname: 'WEB01', ip: '10.50.10.13', role: 'server', os: 'Ubuntu Server 22.04', function: 'Public website', services: ['80/HTTP', '443/HTTPS'] },
            { hostname: 'MAIL-RELAY', ip: '10.50.10.14', role: 'server', os: 'Debian 12', function: 'Outbound smtp relay', services: ['25/SMTP'] },
            { hostname: 'FW-EDGE', ip: '10.50.10.1', role: 'network', os: 'Embedded', function: 'Perimeter firewall' },
            { hostname: 'BILLING-WS', ip: '10.50.20.23', role: 'workstation', os: 'Windows 11 23H2', function: 'Billing and claims' },
            { hostname: 'RECEPTION-WS', ip: '10.50.20.21', role: 'workstation', os: 'Windows 11 23H2', function: 'Front desk check-in' },
            { hostname: 'LAB-LINUX', ip: '10.50.20.25', role: 'workstation', os: 'Ubuntu 22.04', function: 'Lab analysis workstation' },
          ],
        },
        threat_profile: {
          scenarios: [
            {
              scenario_id: 'TS-001',
              name: 'Ransomware via phished billing credentials',
              type: 'ransomware',
              threat_actor: 'Opportunistic ransomware affiliate',
              initial_vector: 'Invoice-themed phishing email',
              attack_path: [
                { step: 1, action: 'Send an invoice-themed lure to billing staff', target: 'MAIL-RELAY', technique: 'T1566.001', detection_opportunity: 'Mail gateway records a lookalike display name' },
                { step: 2, action: 'The macro launches a downloader', target: 'BILLING-WS', technique: 'T1059.001', detection_opportunity: 'An office application spawning a scripting host' },
                { step: 3, action: 'Dump cached domain credentials', target: 'BILLING-WS', technique: 'T1003.001', detection_opportunity: 'LSASS memory access from a non-administrative process' },
                { step: 4, action: 'Enumerate shares and domain administrators', target: 'DC01', technique: 'T1018', detection_opportunity: 'Broad SMB enumeration from one workstation' },
                { step: 5, action: 'Move laterally onto the file server', target: 'FILE01', technique: 'T1021.002', detection_opportunity: 'A service account holding an interactive logon at 03:00' },
                { step: 6, action: 'Encrypt the finance share', target: 'FILE01', technique: 'T1486', detection_opportunity: 'Mass file rename followed by vssadmin delete shadows' },
              ],
              impacted_assets: ['FILE01', 'SQL01'],
            },
            {
              scenario_id: 'TS-002',
              name: 'Credential stuffing against the public site',
              type: 'credential_stuffing',
              threat_actor: 'Commodity credential-stuffing operator',
              initial_vector: 'Reused passwords from an unrelated breach',
              attack_path: [
                { step: 1, action: 'Replay a breach wordlist', target: 'WEB01', technique: 'T1110.003', detection_opportunity: 'Many accounts failing from one source in a short window' },
              ],
              impacted_assets: ['WEB01'],
            },
          ],
        },
      },
    },
  },
};

/**
 * The profile JSON goes to a REAL file, and its path is stored the way the
 * `profiles` table stores one: repo-relative with a leading slash, resolved
 * against process.cwd(). That is the exact join loadProfileJson() does, copied
 * from routes/profile-deploy.js loadProfileForDeploy() — and it is the one part
 * of that reader that has ever been wrong, so stubbing `fs` would test nothing.
 *
 * Derived from __dirname rather than written as a literal, so the suite passes
 * from the repo root as well as from front-end/.
 */
const ABS_JSON_PATH = path.join(__dirname, '.tmp', `ciab-scenario-e2e-${process.pid}.json`);
const REL_JSON_PATH = path.relative(process.cwd(), ABS_JSON_PATH).replace(/\\/g, '/');

fs.mkdirSync(path.dirname(ABS_JSON_PATH), { recursive: true });
fs.writeFileSync(ABS_JSON_PATH, JSON.stringify(PROFILE_JSON), 'utf-8');
process.on('exit', () => { try { fs.unlinkSync(ABS_JSON_PATH); } catch (e) { /* gone */ } });

// ---------------------------------------------------------------------------
// §1 The module graph, replaced at the edges
// ---------------------------------------------------------------------------

const state = {
  inserts: [],          // every INSERT the launcher issued, as { sql, params }
  runs: [],
  targetRows: [],
  updates: [],
  dispatched: [],
  telemetryPlan: { stack: 'elastic', sensor: true },
  planWrites: [],
  targets: [],
  profileRows: [],
};

function resetState() {
  loadRouter();          // FIRST, ALWAYS — see the comment inside loadRouter()
  state.inserts = [];
  state.runs = [];
  state.targetRows = [];
  state.updates = [];
  state.dispatched = [];
  state.telemetryPlan = { stack: 'elastic', sensor: true };
  state.planWrites = [];
  state.profileRows = [{
    id: PROFILE, company_name: 'Saguaro Family Dental', json_file_path: `/${REL_JSON_PATH}`,
  }];
  state.targets = [
    { lane_id: LANE_1, user_id: STUDENT, student_email: 'a@clinic.local', node: 'pve1',
      vmid: 1101, vm_name: 'sensor-1', resolved_by: 'postdeploy', resolvable: true, skip_reason: null },
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

/** cybercore_db. Interprets statements rather than returning canned rows. */
async function fakeCybercoreQuery(sql, params) {
  const p = params || [];
  if (/^\s*SELECT[\s\S]*FROM cybercore_incident_run\s+WHERE run_id/i.test(sql)) {
    const row = state.runs.find((r) => r.run_id === p[0]
      && r.scope_type === 'engagement' && r.scope_id === p[1]);
    return { rows: row ? [pick(selectList(sql), row)] : [] };
  }
  if (/^\s*INSERT INTO cybercore_incident_run/i.test(sql)) {
    state.inserts.push({ sql, params: p });
    const row = {
      run_id: p[0], scope_type: 'engagement', scope_id: p[1], scope_label: p[2],
      engine: p[3], launched_by: p[4], mode: p[5],
      technique_id: p[6], tactic_id: p[7], chain_key: p[8],
      scenario_id: p[9], scenario_ref: p[10], playbook: p[11],
      duration_seconds: p[12], speed: p[13], catalog_version: p[14], answer_key: p[15],
      status: 'scheduling', created_at: '2026-09-01T10:00:00.000Z',
    };
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

/** The CiAB plugin pool: the section binding, the engagement, the profile. */
async function fakeCiabQuery(sql, params) {
  const p = params || [];
  if (/FROM ciab_module/i.test(sql)) return { rows: [] };
  if (/FROM ciab_engagement/i.test(sql)) {
    return {
      rows: String(p[0]) === ENGAGEMENT
        ? [{ engagement_id: ENGAGEMENT, profile_id: PROFILE,
            engagement_type: 'defensive_monitoring', telemetry_plan: state.telemetryPlan }]
        : [],
    };
  }
  if (/FROM profiles/i.test(sql)) {
    return { rows: state.profileRows.filter((r) => String(r.id) === String(p[0])) };
  }
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

  // put() only helps a module that has not been required yet: incident-launch.js
  // destructures `cybercoreQuery` and `query` at load time, so anything that
  // requires it before the stubs are in the cache binds it to the real pools for
  // the rest of the process — and the symptom is a suite that spends a minute
  // timing out against a Postgres that is not there.
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
  put(path.join(CIAB, 'utils', 'enrollment.js'), { canManageSection: async () => true });
  // Lazily required by the launcher (it drags config/site.json in through
  // batch-deployer), so the stub has to be in the cache before the first
  // REQUEST rather than before the require.
  put(path.join(CIAB, 'utils', 'engagement-provision.js'), {
    getEngagementById: async (id) => (
      String(id) === ENGAGEMENT
        ? { engagement_id: ENGAGEMENT, profile_id: PROFILE,
            engagement_type: 'defensive_monitoring', display_name: 'Defensive Monitoring',
            retired_at: null, telemetry_plan: state.telemetryPlan }
        : null
    ),
    // The real one merges and re-validates; here we only need to observe THAT
    // the launcher records the choice, and with which id.
    recordTelemetryScenario: async (engagementId, scenarioId) => {
      state.planWrites.push({ engagementId, scenarioId });
      state.telemetryPlan = { ...state.telemetryPlan, scenario_id: scenarioId };
      return { written: true };
    },
  });

  // The REAL runner, the REAL adapter and the REAL compiler. Only the four
  // functions that reach Proxmox are replaced, on the module's own exports
  // object — which is what the route holds.
  const runner = require('../src/incident/runner');
  runner.resolveScopeTargets = async () => state.targets.slice();
  runner.makeGuestProbe = () => null;
  runner.dispatchRun = async (args) => { state.dispatched.push(args); };
  runner.abortRun = async () => ({ aborted: 1 });
  runner.retryTargets = async (args) => { state.dispatched.push(args); return { retried: 1 }; };

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
const settle = () => new Promise((r) => setImmediate(() => setImmediate(() => setImmediate(r))));

const staff = { role: 'instructor', userId: STAFF };
const student = { role: 'student', userId: STUDENT };

const DURATION = 1800;

/** The insert's params, by the INSERT's own column list. */
const P = {
  runId: 0, scopeId: 1, engine: 3, mode: 5,
  techniqueId: 6, tacticId: 7, chainKey: 8,
  scenarioId: 9, scenarioRef: 10, playbook: 11,
  duration: 12, catalogVersion: 14, answerKey: 15,
};

// ---------------------------------------------------------------------------
// §2 The picker
// ---------------------------------------------------------------------------

test('E7-1: GET /scenarios projects the client\'s scenarios, and not the key', async () => {
  resetState();
  const res = await call('GET', '/scenarios', { user: staff });

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.scenarios.length, 2);
  const one = res.body.scenarios.find((s) => s.scenario_id === 'TS-001');
  assert.strictEqual(one.name, 'Ransomware via phished billing credentials');
  assert.strictEqual(one.type, 'ransomware');
  assert.strictEqual(one.technique_count, 6, 'six distinct techniques across six phases');
  assert.strictEqual(one.step_count, 6);

  // THE PER-STEP PROSE IS THE ANSWER KEY. scenario-compiler.js refuses to let
  // `action` or `detection_opportunity` onto a playbook for exactly that
  // reason; the picker's projection must not put them on the wire either.
  const wire = JSON.stringify(res.body);
  for (const secret of ['detection_opportunity', 'attack_path',
    'Mail gateway records', 'vssadmin']) {
    assert.ok(!wire.includes(secret), `${secret} came back from the scenario picker`);
  }

  // PRIVATE, never public: this names one client's threat model, and a shared
  // cache would hand it to whatever proxy sits in front of this.
  assert.match(String(res.headers['Cache-Control']), /private/);
  assert.ok(!/public/.test(String(res.headers['Cache-Control'])));
});

test('E7-2: the scenario surface is staff-only', async () => {
  resetState();
  const denied = await call('GET', '/scenarios', { user: student });
  assert.strictEqual(denied.status, 403,
    'a student who can read the picker knows how many techniques to look for');
});

// ---------------------------------------------------------------------------
// §3 The launch
// ---------------------------------------------------------------------------

test('E7-3: a scenario launch writes mode, a playbook AND an answer key', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'scenario', scenario_id: 'TS-001', duration_seconds: DURATION },
  });

  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  assert.strictEqual(res.body.status, 'scheduling');
  assert.match(res.body.status_url, /\/status$/);

  assert.strictEqual(state.inserts.length, 1);
  const { sql, params } = state.inserts[0];
  assert.ok(!/RETURNING\s+\*/i.test(sql), 'the insert must not return the whole row');

  assert.strictEqual(params[P.runId], res.body.run_id, 'the run id is minted before the statement');
  assert.strictEqual(params[P.mode], 'scenario');
  assert.strictEqual(params[P.engine], 'synthetic');
  assert.strictEqual(params[P.scenarioId], 'TS-001');
  assert.strictEqual(params[P.duration], DURATION);
  // The correlated CHECKs: exactly one mode column is populated.
  assert.strictEqual(params[P.techniqueId], null);
  assert.strictEqual(params[P.tacticId], null);
  assert.strictEqual(params[P.chainKey], null);

  // ── BOTH HALVES, IN ONE STATEMENT ────────────────────────────────────────
  const playbook = JSON.parse(params[P.playbook]);
  assert.ok(Array.isArray(playbook.steps) && playbook.steps.length > 0,
    'a scenario run with an empty playbook reports completed having generated nothing');
  const key = JSON.parse(params[P.answerKey]);
  assert.ok(key.techniques.length > 0, 'and an empty key grades every correct answer as a miss');
  assert.strictEqual(key.run_id, res.body.run_id, 'THE SEED IS THE RUN ID');
  assert.strictEqual(key.engine, 'synthetic');

  // The snapshot, so a regenerated profile cannot rename a graded incident.
  const ref = JSON.parse(params[P.scenarioRef]);
  assert.strictEqual(ref.scenario_id, 'TS-001');
  assert.strictEqual(ref.name, 'Ransomware via phished billing credentials');
  assert.strictEqual(ref.engagement_id, ENGAGEMENT);

  // Never in the response.
  const wire = JSON.stringify(res.body);
  for (const secret of ['answer_key', 'techniques', 'iocs', 'timeline', 'steps']) {
    assert.ok(!wire.includes(secret), `${secret} came back from a launch`);
  }

  // ── And the compiled playbook is what reaches the guest ──────────────────
  await settle();
  assert.strictEqual(state.dispatched.length, 1);
  const dispatched = state.dispatched[0];
  assert.strictEqual(dispatched.selection.mode, 'scenario');
  assert.strictEqual(dispatched.selection.arg, 'TS-001');
  // playbookFor() must return the COMPILED playbook, not a disk lookup: there
  // is no file named TS-001 and there never will be.
  const staged = require('../src/incident/runner').playbookFor(dispatched.selection);
  assert.ok(staged, 'the dispatcher would stage no playbook at all');
  assert.deepStrictEqual(JSON.parse(staged), playbook,
    'the guest must run the same playbook the answer key was compiled from');

  // The environments are recorded before the dispatch, opt-OUT.
  assert.strictEqual(state.targetRows.length, 1);
  assert.strictEqual(state.targetRows[0][8], 'pending');
});

test('E7-4: an unknown scenario id is a NAMED 400 and writes nothing', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'scenario', scenario_id: 'TS-999', duration_seconds: DURATION },
  });

  assert.strictEqual(res.status, 400, 'not a 500, and not a run that dispatches nothing');
  assert.strictEqual(res.body.code, 'UNKNOWN_SCENARIO');
  // It names what DOES exist, or an instructor cannot act on it.
  assert.match(res.body.error, /TS-001/);
  assert.match(res.body.error, /TS-002/);

  // A row at 'scheduling' holds the per-engagement dispatch mutex until
  // something sweeps it, so "refused" has to mean nothing was written.
  assert.strictEqual(state.inserts.length, 0);
  assert.strictEqual(state.dispatched.length, 0);

  // A missing id, and a shell metacharacter, are the same refusal.
  for (const bad of [undefined, '', "TS-001'; rm -rf /", 'TS-001\nTS-002']) {
    const r = await call('POST', '/', {
      user: staff, body: { mode: 'scenario', scenario_id: bad, duration_seconds: DURATION },
    });
    assert.strictEqual(r.status, 400, `${JSON.stringify(bad)} was not refused`);
    assert.strictEqual(state.inserts.length, 0, 'nothing may be written for an unvalidated scenario');
  }
});

test('E7-5: the key\'s technique set is exactly the compiled attack\'s', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'scenario', scenario_id: 'TS-001', duration_seconds: DURATION },
  });
  assert.strictEqual(res.status, 202);

  const params = state.inserts[0].params;
  const playbook = JSON.parse(params[P.playbook]);
  const key = JSON.parse(params[P.answerKey]);

  // The playbook's own tagged techniques — what the emitter will stamp on every
  // event it produces.
  const tagged = new Set();
  for (const step of playbook.steps) if (step.technique) tagged.add(String(step.technique));

  const keyed = new Set(key.techniques.map((t) => t.id));
  assert.ok(tagged.size > 0, 'a compiled attack with no tagged technique is not gradable');
  assert.deepStrictEqual([...keyed].sort(), [...tagged].sort(),
    'the key is what the board grades against: a technique in one and not the other '
    + 'either marks every student down for an event that never fired, or lets a real '
    + 'phase go unscored');
});

test('E7-6: totals.events is the planner\'s own count, at the run\'s seed', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'scenario', scenario_id: 'TS-001', duration_seconds: DURATION },
  });
  assert.strictEqual(res.status, 202);

  const params = state.inserts[0].params;
  const playbook = JSON.parse(params[P.playbook]);
  const key = JSON.parse(params[P.answerKey]);

  // Re-run cc-emit's OWN planner, the way the guest will, against the same
  // seed. This is the number an instructor quotes and the number the E8 gate
  // compares against Kibana's hit count.
  const emit = require('../src/incident/cc-emit');
  const plan = emit.planTimeline(playbook, {
    rng: emit.makeRng(emit.seedFrom(res.body.run_id)),
    requested: DURATION,
  });
  assert.ok(plan.events.length > 0);
  assert.strictEqual(key.totals.events, plan.events.length,
    'totals.events must be the emitter\'s planned count, not an estimate');
  assert.strictEqual(key.totals.techniques, key.techniques.length);

  // And the per-technique counts add up to it, so a partial grade is arithmetic
  // rather than a guess.
  const summed = key.techniques.reduce((n, t) => n + t.event_count, 0);
  assert.ok(summed <= key.totals.events,
    'a technique cannot account for more events than the run plans');
});

test('E7-7: a student cannot launch a scenario', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: student,
    body: { mode: 'scenario', scenario_id: 'TS-001', duration_seconds: DURATION },
  });
  assert.strictEqual(res.status, 403,
    'neither mount carries a role gate; requireCiabAccess is an ENROLLMENT gate '
    + 'and answers the wrong question here');
  assert.strictEqual(state.inserts.length, 0);
  assert.strictEqual(state.dispatched.length, 0);
});

// ---------------------------------------------------------------------------
// §4 One compilation, two halves
// ---------------------------------------------------------------------------

test('E7-8: the launch records the scenario on the engagement\'s telemetry plan', async () => {
  resetState();
  const res = await call('POST', '/', {
    user: staff,
    body: { mode: 'scenario', scenario_id: 'TS-002', duration_seconds: DURATION },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await settle();

  // WHY IT MATTERS. The benign floor on every sensor here is compiled from a
  // scenario at DEPLOY time and the intrusion from one at LAUNCH time. The
  // attack's pools are a clone of the floor's by construction — that is what
  // makes "no closed-vocabulary field separates the incident from ordinary
  // traffic" true. If the two name different scenarios the estate's vocabulary
  // forks and one terms aggregation on loggen.source.host ends the hunt.
  assert.deepStrictEqual(state.planWrites,
    [{ engagementId: ENGAGEMENT, scenarioId: 'TS-002' }]);

  // AFTER the 202, never before it: the write is bookkeeping for the next
  // deploy and must not be able to fail a launch that has already gone out.
  assert.strictEqual(state.dispatched.length, 1, 'and the incident still dispatched');
});

test('E7-9: the floor and the attack come from ONE compilation', () => {
  // Compiled twice, at DIFFERENT seeds, exactly as the two halves are in
  // production: the deploy-time floor is compiled under the engagement id and
  // the launch-time attack under the run id.
  const { compileScenario } = require('../src/incident/scenario-compiler');
  const scenario = PROFILE_JSON.student_view.raw.threats.threat_profile.scenarios[0];
  const assets = PROFILE_JSON.student_view.raw.threats.network.assets;
  const stakeholders = PROFILE_JSON.student_view.stakeholders;

  const atDeploy = compileScenario({
    scenario, assets, options: { runId: ENGAGEMENT, stakeholders },
  });
  const atLaunch = compileScenario({
    scenario, assets, options: { runId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', stakeholders, requestedSeconds: DURATION },
  });

  // The FLOOR is seed-independent — buildFloor() takes no rng at all — which is
  // what makes it honest for utils/scenario-source.js to compile the deploy-time
  // floor under the engagement id rather than inventing a uuid per deploy.
  assert.deepStrictEqual(atDeploy.floor, atLaunch.floor,
    'a floor that varied with the seed would mean every redeploy changed the estate');

  // And the contract that makes the whole exercise work: every pool the ATTACK
  // can draw from is one the floor also declares. A host, account or address
  // the attack can produce and the floor cannot is an oracle.
  for (const [name, values] of Object.entries(atLaunch.attack.pools)) {
    assert.deepStrictEqual(values, atDeploy.floor.pools[name],
      `pool ${name} differs between the attack and the floor students will see`);
  }
});

test('E7-10: a scenario run rebuilds from its stored row, playbook and all', () => {
  // The retry path. A scenario has no catalog entry to look the incident up
  // from, so the STORED playbook is the only thing that can reproduce it —
  // recompiling would seed differently and grade against the wrong key.
  const engine = require('../src/incident/engines').engineFor('synthetic');
  const stored = {
    mode: 'scenario',
    scenario_id: 'TS-001',
    duration_seconds: DURATION,
    playbook: JSON.stringify({ name: 'scenario TS-001', steps: [{ technique: 'T1486' }] }),
  };
  const selection = engine.resolveSelection(stored);
  assert.strictEqual(selection.mode, 'scenario');
  assert.strictEqual(selection.arg, 'TS-001');
  assert.strictEqual(selection.durationSeconds, DURATION);
  assert.ok(selection.capSeconds > DURATION, 'the cap is a backstop above the duration');
  assert.deepStrictEqual(selection.playbook.steps, [{ technique: 'T1486' }],
    'a jsonb column may come back as text; both shapes must resolve identically');

  // A row that LOST its playbook must be refused, not degraded: without one the
  // wrapper falls through to the keyword generator with an argument that means
  // nothing to it and reports success having produced no incident.
  assert.throws(
    () => engine.resolveSelection({ ...stored, playbook: null }),
    /no compiled playbook/i
  );
  assert.throws(
    () => engine.resolveSelection({ ...stored, scenario_id: "TS-1'; id" }),
    /invalid scenario id/i
  );
});

// ---------------------------------------------------------------------------
// §5 The floor swap actually runs
// ---------------------------------------------------------------------------

test('E7-11: floorForEngagement compiles the client floor, or nothing at all', async () => {
  resetState();
  // Required AFTER loadRouter(), so it binds the stubbed `query` rather than
  // the real pool — the same module-cache rule the router itself follows.
  const src = require(path.join(CIAB, 'utils', 'scenario-source.js'));

  // No scenario recorded yet: an engagement that has not chosen one is an
  // ORDINARY state, so this must be null rather than a throw. Returning null
  // composes to no hook at all and leaves the lane on the baked floor.
  state.telemetryPlan = { stack: 'elastic', sensor: true };
  assert.strictEqual(await src.floorForEngagement(ENGAGEMENT), null);

  // And once the launcher has recorded one:
  state.telemetryPlan = { stack: 'elastic', sensor: true, scenario_id: 'TS-001' };
  const got = await src.floorForEngagement(ENGAGEMENT);
  assert.ok(got, 'a chosen scenario must yield a floor to publish');
  assert.strictEqual(got.scenarioId, 'TS-001');
  assert.ok(Array.isArray(got.floor.steps) && got.floor.steps.length > 0);

  // THIS IS THE E8 GATE'S SECOND CHECK, made testable without a cluster: a
  // terms aggregation on loggen.source.host must show ONLY the client's own
  // hostnames. If the generic baked pools survived, one aggregation in Discover
  // separates the incident from ordinary traffic and the exercise is over.
  const hosts = new Set(got.floor.pools.hosts.map((h) => String(h).toLowerCase()));
  for (const own of ['dc01', 'file01', 'billing-ws']) {
    assert.ok(hosts.has(own), `the floor must draw the client machine ${own}`);
  }
  for (const generic of ['web-01', 'db-01', 'ws-042', 'app-01']) {
    assert.ok(!hosts.has(generic), `the baked generic host ${generic} survived the swap`);
  }

  // An engagement that does not exist is null, not a throw: this runs inside a
  // deploy and must never be able to fail a lane whose machines are all up.
  assert.strictEqual(await src.floorForEngagement('00000000-0000-0000-0000-000000000000'), null);
});

test('E7-12: both deploy paths publish that floor onto the sensor', () => {
  // A SOURCE SCAN, because the alternative is standing up the whole
  // challenge-lane deployer to observe one composition. What it pins is the
  // thing that was missing before E7: makeFloorSwapPostDeploy had no caller at
  // all, so a compiled floor never left the server.
  const raw = fs.readFileSync(path.join(CIAB, 'utils', 'lane-provision.js'), 'utf8');
  const code = raw
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n');

  // BOTH paths. A retried environment is a fresh clone of the same golden
  // image, so it comes back on the generic floor; one environment on a
  // different vocabulary from the rest of its engagement is one student who can
  // end the hunt with a single aggregation.
  const swaps = code.match(/makeFloorSwapPostDeploy\(/g) || [];
  assert.strictEqual(swaps.length, 2,
    'provisionProfileLanes AND retryProfileLane must both publish the client floor');
  const floors = code.match(/floorForEngagement\(/g) || [];
  assert.strictEqual(floors.length, 2, 'and both must compile it from the recorded scenario');

  // Composed into the hook the deployer actually calls, not built and dropped.
  const chains = code.split('chainPostDeploy(').slice(1);
  assert.strictEqual(chains.length, 2, 'exactly two postDeploy chains, one per path');
  for (const chain of chains) {
    // Up to the chain's OWN closing paren, which is the one alone on a line at
    // four-space indent. Stopping at the first ')' would stop inside
    // makeProfilePostDeploy's argument list, and the assertion below would then
    // pass or fail for a reason that has nothing to do with the floor swap.
    const body = chain.split(/^ {4}\),$/m)[0];
    assert.ok(/floorSwap/.test(body), `a postDeploy chain omits the floor swap:\n${body}`);
    // Ordering: the stamp is one cheap statement that makes the environment
    // findable at all; the swap is a 30KB guest exec. chainPostDeploy runs each
    // hook in its own try, so this is about latency rather than correctness —
    // but a reader should not have to rediscover which is which.
    assert.ok(body.indexOf('sensorStamp') < body.indexOf('floorSwap'),
      'the sensor stamp lands before the floor swap');
  }

  // And the hook itself still refuses to publish a floor with no steps — an
  // empty floor is worse than a generic one, because source.type:host would
  // then occur ONLY during the attack.
  const { buildFloorSwapScript } = require(path.join(CIAB, 'utils', 'blueteam-postdeploy.js'));
  assert.throws(() => buildFloorSwapScript({ steps: [] }), /steps is required/i);
});
