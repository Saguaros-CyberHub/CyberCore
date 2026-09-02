/**
 * caldera-authoring-ui.test.js — "pick a class, then author for it", and the
 * two properties that make it safe.
 *
 * ############################################################################
 * # NO CALDERA SERVER HAS EVER BEEN RUN AGAINST THIS CODE. Every request in  #
 * # this file is answered by a fake object defined here. Nothing below       #
 * # proves the authoring VM works, and nothing below can.                    #
 * #                                                                          #
 * # What IS proved is everything on this side of the seam, which is where    #
 * # both of this phase's real risks live: the ORDER two things happen in,    #
 * # and the fact that EXECUTION is still unreachable.                        #
 * ############################################################################
 *
 * WHAT THE FEATURE IS
 * ----------------------------------------------------------------------------
 * ONE standalone Caldera "authoring" instance, on a VM outside every lane, with
 * no agents and no implants. An instructor picks their class in the console they
 * already use, presses "Author attacks", and CyberCore refreshes that class's
 * fact source on the authoring instance from the DEPLOYED SPEC before handing
 * over a link to it. Back in the console, an adversary picker lists what the
 * instance holds.
 *
 * THE TWO PROPERTIES THIS FILE EXISTS FOR
 * ----------------------------------------------------------------------------
 * 1. THE SYNC HAPPENS BEFORE THE LINK IS OFFERED.
 *
 *    A link followed before the fact source is refreshed is a class authoring
 *    against the PREVIOUS environment's hosts, and every symptom of that is
 *    silence: the adversary is built, the operation runs, no link is created for
 *    a machine that is not there, and the run is reported as a success. So §1
 *    pins the ordering at the unit level (the sync call is made before the
 *    result is returned) and §2/§3 pin the consequence at the route level (a
 *    sync that FAILS produces an answer carrying no link at all). The second
 *    half is what gives the first any teeth: an ordering assertion nobody can
 *    fail is decoration.
 *
 * 2. SELECTING AN ADVERSARY CANNOT DISPATCH ONE.
 *
 *    src/incident/engines/index.js does not register the caldera adapter and
 *    engineFor('caldera') throws, so EXECUTION is unreachable until the E8
 *    cluster gate passes. This phase ships AUTHORING only, which is safe because
 *    it touches nothing in any lane. §6 is the source-text gate that keeps it
 *    that way, and §4 proves the console renders a picked adversary as
 *    prepared-but-gated rather than issuing a request.
 *
 * ABOUT §6, AND HOW IT WAS NARROWED — READ THIS BEFORE EDITING IT
 * ----------------------------------------------------------------------------
 * The brief for this phase described an existing source-text gate asserting that
 * 'caldera' was absent from the route and public directories, which the
 * authoring surface would legitimately break. THAT GATE DOES NOT EXIST IN THIS
 * TREE — verified, not assumed: no test under front-end/test/ or under either
 * plugin's test directory scans those directories for the token, and before this
 * phase the word appeared in no file under either of them. What existed was the
 * narrower pair that still stands untouched: caldera-engine.test.js's "caldera is
 * implemented and still NOT registered" and incident-engine-locality.test.js's
 * mirror of it.
 *
 * So §6 WRITES that gate rather than editing one, in the form the phase needs:
 * it stops proving "the word is absent" — which authoring makes false and which
 * was never the property worth having — and proves instead the three things that
 * actually keep execution shut:
 *
 *   G1  no browser or route file reaches the ENGINE ADAPTER
 *       (engines/caldera, calderaEngineUnregistered, registerEngine)
 *   G2  no browser or route file contains the bare quoted ENGINE KEY, which is
 *       what `engine: 'caldera'`, `engineFor('caldera')` and
 *       `<option value="caldera">` all look like. The word inside a longer
 *       string — a sentence explaining the gate to an instructor — is allowed,
 *       and that is the entire narrowing.
 *   G3  no browser or route file names a Caldera OPERATION verb. The authoring
 *       surface uses listSources/getSource/createSource/updateSource and
 *       listAdversaries; createOperation, getOperation, listLinks, listAgents,
 *       finishOperation and abortOperation are the ones that execute, they live
 *       in src/incident/engines/caldera.js alone, and nothing above may name
 *       them.
 *
 * plus a MIRROR half (G4-G7), because every one of G1-G3 is satisfied by
 * deleting the feature: the authoring endpoints must exist, the launcher must
 * refuse a body naming an adversary, and the engine registry must still refuse
 * the engine.
 *
 * Run: node --test front-end/test/caldera-authoring-ui.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const CLE = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle');

// The environment decides whether authoring is configured AT ALL, and this suite
// asserts both answers. Cleared here so a developer with a live .env cannot make
// the not_configured branch silently untestable.
for (const k of ['CALDERA_AUTHORING_URL', 'CALDERA_AUTHORING_UPSTREAM',
  'CALDERA_AUTHORING_API_KEY', 'CALDERA_AUTHORING_API_KEY_FILE']) {
  delete process.env[k];
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ENGAGEMENT = '33333333-3333-3333-3333-333333333333';
const COURSE = '11111111-1111-1111-1111-111111111111';
const PROFILE = '55555555-5555-5555-5555-555555555555';
const STAFF = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const STUDENT = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
const LANE = '00000001-0000-0000-0000-000000000000';

/**
 * A deployed spec: three Windows, one Linux, and one sensor.
 *
 * The sensor is what makes the platform count a real assertion rather than a
 * count of rows — fact-source.js excludes the evidence plane from the targetable
 * set, so a correct summary says "3 Windows, 1 Linux" and a naive one says four
 * and two.
 */
const SPEC = Object.freeze({
  dns: { ad_domain: 'clinic.example' },
  vms: [
    { name: 'DC01', hostname: 'dc01', os_family: 'windows_server', role: 'dc' },
    { name: 'WS01', hostname: 'ws01', os_family: 'windows_client', role: 'workstation' },
    { name: 'WS02', hostname: 'ws02', os_family: 'windows_client', role: 'workstation' },
    { name: 'APP01', hostname: 'app01', os_family: 'ubuntu', role: 'web' },
    { name: 'SENSOR', hostname: 'sensor', os_family: 'rocky', role: 'loggen' },
  ],
});

const ADVERSARY_ROWS = [
  {
    adversary_id: 'adv-zeta',
    name: 'Zeta invoice fraud',
    description: 'phish then move',
    atomic_ordering: ['ab-1', 'ab-2', 'ab-3'],
  },
  {
    adversary_id: 'adv-alpha',
    name: 'Alpha credential theft',
    atomic_ordering: ['ab-4'],
    // Deliberately present: an adversary object can carry per-ability command
    // text, and the projection must not pass it on to a picker.
    atomic_ordering_details: [{ command: 'powershell -enc AAAA' }],
  },
];

// ---------------------------------------------------------------------------
// §1 The core module — the ordering, and every way it can refuse
// ---------------------------------------------------------------------------

const authoring = require(path.join(ROOT, 'src', 'incident', 'caldera', 'authoring.js'));
const { CalderaError } = require(path.join(ROOT, 'src', 'incident', 'caldera', 'client.js'));

/** A fact-source-capable client that records the order it was called in. */
function fakeClient(over) {
  const seq = [];
  const client = {
    seq,
    listSources: async () => { seq.push('listSources'); return []; },
    createSource: async (body) => { seq.push('createSource'); return { id: body.id }; },
    updateSource: async (id) => { seq.push('updateSource'); return { id }; },
    listAdversaries: async () => { seq.push('listAdversaries'); return ADVERSARY_ROWS.slice(); },
    ...(over || {}),
  };
  return client;
}

const transportDown = () => new CalderaError('nothing answered', { code: 'CALDERA_UNREACHABLE' });

test('E9-A1: THE ORDERING — the fact source is synced BEFORE anything is returned', async () => {
  const client = fakeClient();
  const seq = client.seq;

  const out = await authoring.prepareAuthoring({
    client, scopeLabel: 'Northwind — Defensive Monitoring', scopeKey: ENGAGEMENT, spec: SPEC,
  });
  seq.push('returned');

  // The sync is not merely called: it has RESOLVED before prepareAuthoring's own
  // promise does. That is the property the whole feature rests on — a caller
  // awaiting this and then rendering a link cannot render it early.
  assert.deepStrictEqual(seq, ['listSources', 'createSource', 'returned']);
  assert.strictEqual(out.ready, true);
  assert.strictEqual(out.fact_source.action, 'created');
  assert.ok(out.fact_source.name.startsWith('CyberCore: Northwind'),
    'the name is the only handle an instructor has inside a store with no ownership');
});

test('E9-A2: the platform summary counts TARGETS, not rows', () => {
  // Asserted through the prepare path's own output rather than by calling
  // summarizePlatforms directly, because the console renders THIS object.
  const client = fakeClient();
  return authoring.prepareAuthoring({ client, scopeLabel: 'X', scopeKey: 'k', spec: SPEC })
    .then((out) => {
      assert.deepStrictEqual(out.platforms, { windows: 3, linux: 1, other: 0 });
      // The sensor is the evidence plane. An ability that lands on it corrupts
      // the store the student is graded on reading, so it is not a target and
      // must not be counted as one.
      assert.deepStrictEqual(out.excluded, ['sensor']);
      assert.deepStrictEqual(
        out.hosts.map((h) => h.fqdn),
        ['dc01.clinic.example', 'ws01.clinic.example', 'ws02.clinic.example', 'app01.clinic.example']
      );
    });
});

test('E9-A3: a re-prepare UPDATES one row rather than creating a second', async () => {
  // The class's id is a uuidv5 over the scope key, so the same class addresses
  // the same row forever. A server with thirty rows called "CyberCore: Section A"
  // is a server where an instructor picks the wrong one, and picking wrong is
  // unobservable: the operation runs, against another class's hosts.
  const first = await authoring.prepareAuthoring({
    client: fakeClient(), scopeLabel: 'X', scopeKey: ENGAGEMENT, spec: SPEC,
  });
  const client = fakeClient({
    listSources: async () => [{ id: first.fact_source.id, name: first.fact_source.name }],
  });
  const second = await authoring.prepareAuthoring({
    client, scopeLabel: 'X', scopeKey: ENGAGEMENT, spec: SPEC,
  });
  assert.strictEqual(second.fact_source.action, 'updated');
  assert.strictEqual(second.fact_source.id, first.fact_source.id);
  assert.ok(client.seq.includes('updateSource'));
  assert.ok(!client.seq.includes('createSource'));
});

test('E9-A4: every failure is a REASON, never a throw and never a link', async () => {
  const cases = [
    ['no client at all', { client: null }, 'not_configured'],
    ['a caller-known refusal', { client: fakeClient(), unavailable: 'no_api_key' }, 'no_api_key'],
    ['nothing deployed', { client: fakeClient(), spec: null }, 'no_spec'],
    ['the box is down', {
      client: fakeClient({ listSources: async () => { throw transportDown(); } }),
    }, 'unreachable'],
    ['the key is wrong', {
      client: fakeClient({
        listSources: async () => { throw new CalderaError('401', { code: 'CALDERA_UNAUTHORIZED' }); },
      }),
    }, 'unauthorized'],
    ['it refused the source', {
      client: fakeClient({ createSource: async () => { throw new CalderaError('500', { code: 'CALDERA_HTTP' }); } }),
    }, 'error'],
    ['a client with no source API', { client: { listAdversaries: async () => [] } }, 'sync_failed'],
  ];

  for (const [what, over, reason] of cases) {
    const out = await authoring.prepareAuthoring({
      scopeLabel: 'X', scopeKey: ENGAGEMENT, spec: SPEC, ...over,
    });
    assert.strictEqual(out.ready, false, `${what}: must not report ready`);
    assert.strictEqual(out.reason, reason, what);
    // THE CONSEQUENCE, asserted on every branch: nothing that could become a
    // link, and nothing that could become a platform summary.
    assert.strictEqual(out.fact_source, undefined, `${what}: leaked a fact source`);
    assert.strictEqual(out.platforms, undefined, `${what}: leaked a platform summary`);
  }
});

test('E9-A5: the adversary projection drops the command text', async () => {
  const out = await authoring.listAdversaryProfiles(fakeClient());
  assert.strictEqual(out.ready, true);
  // Sorted by name: the store's own order is insertion order on a shared box,
  // which is not where a human looks for the thing they just made.
  assert.deepStrictEqual(out.adversaries.map((a) => a.name),
    ['Alpha credential theft', 'Zeta invoice fraud']);
  assert.deepStrictEqual(out.adversaries[0], {
    adversary_id: 'adv-alpha',
    name: 'Alpha credential theft',
    description: null,
    ability_count: 1,
  });
  const serialized = JSON.stringify(out);
  assert.ok(!/powershell/i.test(serialized),
    'an adversary carries per-ability command text; a picker must not.');
  // EXECUTION travels with the list, so a console renders the gate from the
  // server's word rather than a constant of its own that can drift open.
  assert.deepStrictEqual(out.execution, { enabled: false, reason: 'cluster_gate' });
});

test('E9-A6: the API key is read from a FILE first, and never leaves', () => {
  const reads = [];
  const readFile = (p) => { reads.push(p); if (p === '/run/secrets/ok') return 'red-key\n'; throw new Error('ENOENT'); };

  assert.deepStrictEqual(
    authoring.resolveApiKey({ CALDERA_AUTHORING_API_KEY_FILE: '/run/secrets/ok' }, readFile),
    { apiKey: 'red-key', present: true, source: 'file', detail: null }
  );
  // The trailing newline `echo` leaves behind is stripped: a key ending in one
  // fails authentication with a 401 that looks exactly like a wrong key.
  assert.deepStrictEqual(reads, ['/run/secrets/ok']);

  // A file that is named and missing is REPORTED, not thrown: it is precisely
  // the condition the setup message exists to describe.
  const missing = authoring.resolveApiKey({ CALDERA_AUTHORING_API_KEY_FILE: '/nope' }, readFile);
  assert.strictEqual(missing.present, false);
  assert.strictEqual(missing.detail, 'unreadable_file');
  // And it does NOT silently fall back to the inline variable — a deployment
  // that named a file meant that file, and quietly using a stale env value is
  // how a rotated credential goes on working until it does not.
  const bothSet = authoring.resolveApiKey(
    { CALDERA_AUTHORING_API_KEY_FILE: '/nope', CALDERA_AUTHORING_API_KEY: 'inline' }, readFile
  );
  assert.strictEqual(bothSet.present, false);

  assert.deepStrictEqual(authoring.resolveApiKey({ CALDERA_AUTHORING_API_KEY: 'inline' }, readFile),
    { apiKey: 'inline', present: true, source: 'env', detail: null });
  assert.strictEqual(authoring.resolveApiKey({}, readFile).present, false);
});

test('E9-A7: resolveTarget refuses to build a client it cannot authenticate', () => {
  const noKey = () => { throw new Error('ENOENT'); };
  assert.deepStrictEqual(
    authoring.resolveTarget({ configured: false, malformed: false }),
    { client: null, unavailable: 'not_configured', upstream: null }
  );
  assert.strictEqual(
    authoring.resolveTarget({ configured: false, malformed: true }).unavailable, 'error');
  const t = authoring.resolveTarget(
    { configured: true, baseUrl: 'http://authoring.lab.test:8888', upstream: 'authoring.lab.test:8888' },
    { env: {}, readFile: noKey }
  );
  // createCalderaClient() THROWS on an empty key, so a missing credential must
  // be caught here — otherwise a configuration state becomes a 500 on the one
  // screen that could have explained it.
  assert.strictEqual(t.client, null);
  assert.strictEqual(t.unavailable, 'no_api_key');
  assert.strictEqual(t.upstream, 'authoring.lab.test:8888');
});

// ---------------------------------------------------------------------------
// §2 The module graph, replaced — shared by the CiAB and CLE route sections
// ---------------------------------------------------------------------------

const state = {
  lanes: [],
  specs: {},
  managed: true,          // does this staff member manage the CLE course?
  enrolled: false,
  audits: [],
};

function put(modPath, exports) {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
}

/**
 * ONE tolerant fake for the shared pool, because both routers reach it.
 *
 * Unhandled statements THROW rather than returning zero rows: a silent empty
 * result would make "the spec is not there" and "the query was wrong" the same
 * observation, which is the failure this suite is about.
 */
async function fakeCybercoreQuery(sql, params) {
  if (/FROM\s+\S*challenge\s+WHERE challenge_key/i.test(sql)) {
    const spec = state.specs[String(params[0])];
    return { rows: spec ? [{ spec }] : [] };
  }
  if (/FROM cybercore_incident_run/i.test(sql)) return { rows: [] };
  if (/^\s*(INSERT|UPDATE)/i.test(sql)) return { rows: [] };
  throw new Error(`fakeCybercoreQuery: unhandled SQL\n${sql}`);
}

async function fakeCiabQuery(sql, params) {
  if (/FROM ciab_module/i.test(sql)) return { rows: [] };
  if (/FROM ciab_engagement/i.test(sql)) {
    return {
      rows: String(params[0]) === ENGAGEMENT
        ? [{ engagement_id: ENGAGEMENT, profile_id: PROFILE,
             engagement_type: 'defensive_monitoring', telemetry_plan: {} }]
        : [],
    };
  }
  if (/FROM profiles/i.test(sql)) return { rows: [] };
  throw new Error(`fakeCiabQuery: unhandled SQL\n${sql}`);
}

async function fakeCleQuery(sql) {
  if (/cle_course_enrollment/i.test(sql)) {
    return {
      rows: state.enrolled
        ? [{ course_id: COURSE, code: 'CYBR400', course_name: 'Blue Team', features: {} }]
        : [],
    };
  }
  throw new Error(`fakeCleQuery: unhandled SQL\n${sql}`);
}

let ROUTERS = null;
function loadRouters() {
  if (ROUTERS) return ROUTERS;

  put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: fakeCybercoreQuery });
  put(path.join(ROOT, 'src', 'utils', 'audit.js'), {
    log: async (entry) => { state.audits.push(entry); },
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
  put(path.join(CIAB, 'utils', 'engagement-provision.js'), {
    getEngagementById: async (id) => (
      String(id) === ENGAGEMENT
        ? { engagement_id: ENGAGEMENT, profile_id: PROFILE,
            engagement_type: 'defensive_monitoring', display_name: 'Defensive Monitoring',
            retired_at: null }
        : null
    ),
  });

  put(path.join(CLE, 'utils', 'db.js'), { query: fakeCleQuery });
  put(path.join(CLE, 'utils', 'course-access.js'), {
    getManagedCourse: async (courseId, user) => (
      state.managed && user && (user.role === 'instructor' || user.role === 'admin')
        ? { course_id: COURSE, code: 'CYBR400', course_name: 'Blue Team', features: {} }
        : null
    ),
  });
  put(path.join(CLE, 'utils', 'course-features.js'), { isFeatureEnabled: () => true });
  put(path.join(ROOT, 'src', 'incident', 'board.js'), {
    listRunsForScope: async () => [],
    readRunForStaff: async () => null,
    readRunForStudent: async () => null,
  });

  // The REAL runner, with only the function that would reach Postgres replaced —
  // src/incident/caldera/authoring.js requires it lazily and calls exactly one
  // method, so patching the module's own exports object is enough and nothing
  // that dispatches is stubbed into existence.
  const runner = require(path.join(ROOT, 'src', 'incident', 'runner.js'));
  runner.findScopeLanes = async () => state.lanes.slice();
  runner.resolveScopeTargets = async () => [];

  ROUTERS = {
    ciab: require(path.join(CIAB, 'routes', 'incidents.js')),
    cle: require(path.join(CLE, 'routes', 'incidents.js')),
  };
  return ROUTERS;
}

function resetState() {
  loadRouters();
  state.lanes = [{
    lane_id: LANE, user_id: STUDENT, name: 'lane-1', status: 'active',
    module_key: 'ciab', config: { challenge_key: 'northwind-v3', ciab: 'true' },
  }];
  state.specs = { 'northwind-v3': SPEC };
  state.managed = true;
  state.enrolled = false;
  state.audits = [];
  delete process.env.CALDERA_AUTHORING_UPSTREAM;
  delete process.env.CALDERA_AUTHORING_API_KEY;
  authoring.resolveTarget = REAL_RESOLVE_TARGET;
}

const REAL_RESOLVE_TARGET = authoring.resolveTarget;

/** One request through a router, with the moment the answer arrived recorded. */
function call(router, method, url, opts) {
  const o = opts || {};
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: {}, headers: {}, params: {},
      user: o.user === null ? undefined : (o.user || { role: 'instructor', userId: STAFF }),
    };
    let done = false;
    const finish = (payload, res) => {
      if (done) return;
      done = true;
      if (o.seq) o.seq.push('response');
      resolve({ status: res.statusCode, body: payload, headers: res.headers });
    };
    const res = {
      statusCode: 200,
      headersSent: false,
      locals: { engagementId: ENGAGEMENT, courseId: COURSE },
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

/** Point the routes at a fake authoring instance for the duration of one test. */
function withInstance(client, fn) {
  authoring.resolveTarget = () => ({ client, unavailable: null, upstream: 'authoring.lab.test:8888' });
  return Promise.resolve(fn()).finally(() => { authoring.resolveTarget = REAL_RESOLVE_TARGET; });
}

// ---------------------------------------------------------------------------
// §3 The CiAB console's endpoints
// ---------------------------------------------------------------------------

const student = { role: 'student', userId: STUDENT };

test('E9-R1: THE ORDERING AT THE ROUTE — the link comes back only after the sync', async () => {
  resetState();
  const { ciab } = loadRouters();
  const client = fakeClient();
  const seq = client.seq;

  const res = await withInstance(client, () => call(ciab, 'POST',
    '/authoring/fact-source', { seq }));

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.ready, true);
  // The response was produced AFTER the write to the authoring instance, and
  // this is the assertion the console's whole design rests on.
  assert.deepStrictEqual(seq, ['listSources', 'createSource', 'response']);
  assert.strictEqual(res.body.console_path, '/caldera/');
  assert.deepStrictEqual(res.body.platforms, { windows: 3, linux: 1, other: 0 });
  assert.ok(res.body.fact_source.name.includes('Defensive Monitoring'));
  assert.strictEqual(res.body.environments, 1);
  assert.deepStrictEqual(res.body.execution, { enabled: false, reason: 'cluster_gate' });

  const row = state.audits.find((a) => a.action === 'incident.authoring_prepared');
  assert.ok(row, 'preparing a shared server is a staff action and is audited');
  assert.strictEqual(row.metadata.windows, 3);
  assert.ok(!('hosts' in row.metadata), 'the host list describes an estate; keep it out of audit');
});

test('E9-R2: A SYNC THAT FAILS OFFERS NO LINK — this is what gives E9-R1 teeth', async () => {
  resetState();
  const { ciab } = loadRouters();
  const down = fakeClient({ listSources: async () => { throw transportDown(); } });

  const res = await withInstance(down, () => call(ciab, 'POST', '/authoring/fact-source'));

  assert.strictEqual(res.status, 200, 'a 4xx here becomes an unreadable toast; see the route');
  assert.strictEqual(res.body.ready, false);
  assert.strictEqual(res.body.reason, 'unreachable');
  assert.strictEqual(res.body.console_path, null,
    'an unreachable instance must never be linked to: the instructor would author against '
    + 'whatever it happens to hold');
  assert.strictEqual(res.body.platforms, undefined);
  assert.strictEqual(state.audits.filter((a) => a.action === 'incident.authoring_prepared').length, 0,
    'nothing was prepared, so nothing is recorded as prepared');
});

test('E9-R3: an unconfigured platform says so, with no network call at all', async () => {
  resetState();
  const { ciab } = loadRouters();
  // No stub: the REAL resolveTarget, against an environment with nothing set.
  const res = await call(ciab, 'POST', '/authoring/fact-source');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.ready, false);
  assert.strictEqual(res.body.reason, 'not_configured');
  assert.strictEqual(res.body.console_path, null);
  assert.strictEqual(res.body.upstream, null,
    'the placeholder host is not disclosed as if it were a real one');
});

test('E9-R4: an Engagement with nothing deployed is explained, not synced', async () => {
  resetState();
  state.lanes = [];
  const { ciab } = loadRouters();
  const client = fakeClient();
  const res = await withInstance(client, () => call(ciab, 'POST', '/authoring/fact-source'));
  assert.strictEqual(res.body.ready, false);
  assert.strictEqual(res.body.reason, 'no_spec');
  assert.strictEqual(res.body.console_path, null);
  assert.deepStrictEqual(client.seq, [],
    'an empty fact source published to a shared server is worse than none');
});

test('E9-R5: the adversary list is instructor-only and carries the execution gate', async () => {
  resetState();
  const { ciab } = loadRouters();
  const res = await withInstance(fakeClient(), () => call(ciab, 'GET', '/authoring/adversaries'));
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.ready, true);
  assert.strictEqual(res.body.adversaries.length, 2);
  assert.deepStrictEqual(res.body.execution, { enabled: false, reason: 'cluster_gate' });
  assert.strictEqual(res.headers['Cache-Control'], 'no-store');
});

test('E9-R6: A STUDENT SEES NO AUTHORING SURFACE — both endpoints refuse them', async () => {
  resetState();
  const { ciab } = loadRouters();
  await withInstance(fakeClient(), async () => {
    for (const [method, url] of [['POST', '/authoring/fact-source'], ['GET', '/authoring/adversaries']]) {
      const res = await call(ciab, method, url, { user: student });
      assert.strictEqual(res.status, 403, `${method} ${url} let a student in`);
      const body = JSON.stringify(res.body || {});
      assert.ok(!/caldera/i.test(body), 'a refusal must not disclose the console path');
      assert.ok(!/fact_source|platforms/.test(body));
    }
  });
});

test('E9-R7: THE LAUNCHER REFUSES A BODY NAMING AN AUTHORED ADVERSARY', async () => {
  resetState();
  const { ciab } = loadRouters();
  // An ignored field would be far worse than a refusal: the instructor believes
  // they launched the intrusion they authored while the class hunts another one.
  const res = await call(ciab, 'POST', '/', {
    body: { mode: 'technique', technique_id: 'T1110.001', adversary_id: 'adv-zeta' },
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.body.code, 'AUTHORED_ADVERSARY_NOT_DISPATCHABLE');
  assert.match(res.body.error, /cannot be launched yet/);
});

test('E9-R8: engineFor still refuses caldera — nothing above could have dispatched it', () => {
  const engines = require(path.join(ROOT, 'src', 'incident', 'engines'));
  assert.deepStrictEqual(engines.registeredEngines(), ['synthetic']);
  assert.throws(() => engines.engineFor('caldera'), (err) => {
    assert.strictEqual(err.code, 'UNKNOWN_INCIDENT_ENGINE');
    return true;
  });
  const launcher = require(path.join(CIAB, 'routes', 'incident-launch.js'));
  assert.strictEqual(launcher.INCIDENT_ENGINE, 'synthetic');
});

// ---------------------------------------------------------------------------
// §4 The CLE twin
// ---------------------------------------------------------------------------

test('E9-C1: the CLE twin syncs before it links, and labels the scope by course', async () => {
  resetState();
  const { cle } = loadRouters();
  const client = fakeClient();
  const seq = client.seq;
  const res = await withInstance(client, () => call(cle, 'POST', '/authoring/fact-source', { seq }));

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.ready, true);
  assert.deepStrictEqual(seq, ['listSources', 'createSource', 'response']);
  assert.strictEqual(res.body.console_path, '/caldera/');
  assert.deepStrictEqual(res.body.platforms, { windows: 3, linux: 1, other: 0 });
  assert.ok(res.body.fact_source.name.includes('CYBR400'));
});

test('E9-C2: the two products get DIFFERENT fact sources for the same machines', async () => {
  // The scope KEY is the course id on one side and the engagement id on the
  // other, so two classes running an identical spec never share a row. A name
  // built from the label alone would merge them, and one instructor's edits
  // would land in the other's exercise.
  resetState();
  const { ciab, cle } = loadRouters();
  const a = await withInstance(fakeClient(), () => call(ciab, 'POST', '/authoring/fact-source'));
  const b = await withInstance(fakeClient(), () => call(cle, 'POST', '/authoring/fact-source'));
  assert.notStrictEqual(a.body.fact_source.id, b.body.fact_source.id);
  assert.notStrictEqual(a.body.fact_source.name, b.body.fact_source.name);
});

test('E9-C3: A STUDENT ON THE COURSE SEES NO AUTHORING SURFACE', async () => {
  resetState();
  state.managed = false;
  state.enrolled = true;               // genuinely on the course, and still not staff
  const { cle } = loadRouters();
  await withInstance(fakeClient(), async () => {
    for (const [method, url] of [['POST', '/authoring/fact-source'], ['GET', '/authoring/adversaries']]) {
      const res = await call(cle, method, url, { user: student });
      assert.strictEqual(res.status, 403, `${method} ${url} let an enrolled student in`);
      assert.ok(!/caldera/i.test(JSON.stringify(res.body || {})));
    }
  });
});

test('E9-C4: someone on neither side of the course gets the same 404 as a bad id', async () => {
  resetState();
  state.managed = false;
  state.enrolled = false;
  const { cle } = loadRouters();
  const res = await withInstance(fakeClient(),
    () => call(cle, 'POST', '/authoring/fact-source', { user: student }));
  assert.strictEqual(res.status, 404);
  assert.deepStrictEqual(res.body, { error: 'Not found' });
});

test('E9-C5: the authoring routes are declared ABOVE anything taking :runId', () => {
  // Express matches in registration order. Below GET /:runId/status,
  // '/authoring/adversaries' resolves to run_id 'authoring' and 404s in a way
  // that looks exactly like "this course has no incidents".
  const src = fs.readFileSync(path.join(CLE, 'routes', 'incidents.js'), 'utf8');
  assert.ok(src.indexOf("router.post('/authoring/fact-source'") < src.indexOf("router.get('/:runId'"));
  assert.ok(src.indexOf("router.get('/authoring/adversaries'") < src.indexOf("router.get('/:runId'"));

  const launch = fs.readFileSync(path.join(CIAB, 'routes', 'incident-launch.js'), 'utf8');
  assert.ok(launch.indexOf("router.post('/authoring/fact-source'") < launch.indexOf("router.post('/:runId/abort'"));
});

// ---------------------------------------------------------------------------
// §5 The consoles themselves, driven in a sandbox
// ---------------------------------------------------------------------------

/**
 * A DOM small enough to render into and read back.
 *
 * Elements are property bags; innerHTML is a string. Enough to exercise the
 * render path with no jsdom, which is not a dependency of this repo — the same
 * approach test/audit-ui.test.js takes.
 */
function makeDom() {
  const elements = new Map();
  const el = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, value: '', innerHTML: '', textContent: '', checked: false, style: {},
        handlers: {},
        classList: { add() {}, remove() {}, contains: () => true },
        addEventListener(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); },
        setSelectionRange() {}, focus() {},
        getAttribute() { return null; },
      });
    }
    return elements.get(id);
  };
  return {
    elements,
    document: {
      getElementById: el,
      querySelectorAll: () => [],
      querySelector: () => null,
      createElement: () => el('scratch'),
    },
  };
}

const READY_PAYLOAD = {
  ready: true,
  reason: null,
  fact_source: { name: 'CyberCore: Northwind [abc123]', id: 'fs-1', action: 'created' },
  platforms: { windows: 3, linux: 1, other: 0 },
  hosts: [
    { name: 'DC01', fqdn: 'dc01.clinic.example', platform: 'windows' },
    { name: 'APP01', fqdn: 'app01.clinic.example', platform: 'linux' },
  ],
  excluded: ['SENSOR'],
  domains: ['clinic.example'],
  warnings: [],
  console_path: '/caldera/',
  upstream: 'authoring.lab.test:8888',
  environments: 4,
  execution: { enabled: false, reason: 'cluster_gate' },
};

const ADVERSARY_PAYLOAD = {
  ready: true,
  reason: null,
  adversaries: [
    { adversary_id: 'adv-alpha', name: 'Alpha credential theft', description: null, ability_count: 1 },
    { adversary_id: 'adv-zeta', name: 'Zeta invoice fraud', description: 'phish then move', ability_count: 3 },
  ],
  execution: { enabled: false, reason: 'cluster_gate' },
  upstream: 'authoring.lab.test:8888',
};

/** Load the CiAB console into a sandbox wired to a scripted API. */
function mountCiabConsole(answers) {
  const dom = makeDom();
  const calls = [];
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const context = {
    window: {},
    document: dom.document,
    console: { warn() {}, error() {}, log() {} },
    setTimeout, clearTimeout, setInterval, clearInterval, Promise, JSON, Math, Date, Number, String,
    Array, Object, Set, Map, encodeURIComponent, isFinite, parseInt,
    esc,
    escJs: (s) => String(s == null ? '' : s).replace(/['\\]/g, '\\$&'),
    timeAgo: () => 'just now',
    switchTab: () => {},
    Toast: { success() {}, error() {}, info() {} },
    Confirm: { show: async () => true },
    Utils: { setBtnLoading() {} },
    API: {
      request: async (p, opts) => {
        calls.push({ path: p, method: (opts && opts.method) || 'GET', body: opts && opts.body });
        for (const [re, value] of answers) {
          if (re.test(p)) return typeof value === 'function' ? value() : value;
        }
        throw new Error(`unscripted API call ${p}`);
      },
    },
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(
    fs.readFileSync(path.join(CIAB, 'public', 'js', 'instructor-incidents.js'), 'utf8'),
    context,
    { filename: 'instructor-incidents.js' }
  );
  return { context, dom, calls, Incidents: context.window.Incidents };
}

const CIAB_BASE_ANSWERS = () => [
  [/\/catalog$/, { techniques: [{ id: 'T1110.001', name: 'Password Guessing', tactic: 'credential-access', tactic_name: 'Credential Access', description: 'x', keywords: [], expected_volume: 'medium', fidelity: 'low' }], tactics: [], chains: [] }],
  [/\/scenarios$/, { scenarios: [], chosen: null }],
  [/\/targets$/, { targets: [], resolvable: 0, total: 0 }],
];

async function openEngagement(harness) {
  harness.dom.document.getElementById('incidentEngagementSelect').value = ENGAGEMENT;
  await harness.Incidents.onEngagementChange();
}

test('E9-U1: the CiAB console shows the platform summary AND the link, together', async () => {
  const h = mountCiabConsole([
    ...CIAB_BASE_ANSWERS(),
    [/\/authoring\/fact-source$/, READY_PAYLOAD],
    [/\/authoring\/adversaries$/, ADVERSARY_PAYLOAD],
    [/incidents$/, { runs: [] }],
  ]);
  await openEngagement(h);

  // Before the click there is a button and NO link — the instructor cannot get
  // to the authoring UI without going through the refresh.
  let html = h.dom.document.getElementById('incidentAuthoring').innerHTML;
  assert.match(html, /Author attacks/);
  assert.ok(!/\/caldera/.test(html), 'the link exists only after the refresh');

  await h.Incidents.authorAttacks(null);
  html = h.dom.document.getElementById('incidentAuthoring').innerHTML;

  // THE PLATFORM SUMMARY REACHES THE UI, as a sentence rather than a JSON blob:
  // an instructor about to leave for a UI CyberCore cannot help them inside
  // needs to know what they are authoring against.
  assert.match(html, /3 Windows machines and 1 Linux machine/);
  assert.match(html, /CyberCore: Northwind \[abc123\]/);
  assert.match(html, /href="\/caldera\/"/);
  assert.match(html, /rel="noopener noreferrer"/);
  assert.match(html, /dc01\.clinic\.example/);

  // The refresh really did precede the read of the adversary list.
  assert.deepStrictEqual(
    h.calls.filter((c) => /authoring/.test(c.path)).map((c) => `${c.method} ${c.path.split('/incidents')[1]}`),
    ['POST /authoring/fact-source', 'GET /authoring/adversaries']
  );
});

test('E9-U2: an unreachable instance renders the SETUP MESSAGE and never a link', async () => {
  const h = mountCiabConsole([
    ...CIAB_BASE_ANSWERS(),
    [/\/authoring\/fact-source$/, { ready: false, reason: 'unreachable', console_path: null, upstream: 'authoring.lab.test:8888' }],
    [/incidents$/, { runs: [] }],
  ]);
  await openEngagement(h);
  await h.Incidents.authorAttacks(null);

  const html = h.dom.document.getElementById('incidentAuthoring').innerHTML;
  assert.match(html, /Attack authoring is not set up/);
  assert.match(html, /did not answer/);
  assert.match(html, /authoring\.lab\.test:8888/);
  assert.ok(!/href="\/caldera/.test(html), 'a dead link is worse than none: see the file header');
  // And it must never be a raw error either.
  assert.ok(!/\[object|undefined|Error:/.test(html));

  // The adversary list is not even attempted: there is nothing to author for.
  assert.deepStrictEqual(h.calls.filter((c) => /adversaries/.test(c.path)), []);
});

test('E9-U3: every refusal code produces an ACTION, not just an apology', async () => {
  for (const reason of ['not_configured', 'no_api_key', 'unreachable', 'unauthorized',
    'no_spec', 'sync_failed', 'error']) {
    const h = mountCiabConsole([
      ...CIAB_BASE_ANSWERS(),
      [/\/authoring\/fact-source$/, { ready: false, reason, console_path: null, upstream: null }],
      [/incidents$/, { runs: [] }],
    ]);
    // eslint-disable-next-line no-await-in-loop
    await openEngagement(h);
    // eslint-disable-next-line no-await-in-loop
    await h.Incidents.authorAttacks(null);
    const html = h.dom.document.getElementById('incidentAuthoring').innerHTML;
    assert.ok(!/\/caldera/.test(html), `${reason}: offered a link`);
    assert.ok(/administrator|Deploy the Environments/.test(html),
      `${reason}: says what is wrong but not what to do about it`);
  }
});

test('E9-U4: SELECTING AN ADVERSARY CANNOT PRODUCE A DISPATCH', async () => {
  const h = mountCiabConsole([
    ...CIAB_BASE_ANSWERS(),
    [/\/authoring\/fact-source$/, READY_PAYLOAD],
    [/\/authoring\/adversaries$/, ADVERSARY_PAYLOAD],
    [/incidents$/, { runs: [] }],
  ]);
  await openEngagement(h);
  await h.Incidents.authorAttacks(null);

  const beforeCalls = h.calls.length;
  h.Incidents.selectAdversary('adv-zeta');
  const html = h.dom.document.getElementById('incidentAuthoring').innerHTML;

  // Rendered as PREPARED-BUT-GATED, in a sentence. A greyed-out button with no
  // explanation reads as a broken platform, and this one is not broken.
  assert.match(html, /Zeta invoice fraud is prepared, not scheduled/);
  assert.match(html, /cannot be fired into your Environments yet/);
  assert.match(html, /signed off/);

  // NOT ONE REQUEST. Picking sets a value on the page and nothing else.
  assert.strictEqual(h.calls.length, beforeCalls,
    'selecting an adversary issued a request; there is no endpoint that would accept it');

  // And nothing anywhere in this console has ever sent an adversary id.
  for (const c of h.calls) {
    assert.ok(!/adversary/i.test(JSON.stringify(c.body || {})),
      `a request body carried an adversary: ${c.method} ${c.path}`);
  }
});

/** Load the CLE mount into a sandbox wired to a scripted tier and fetch. */
function mountCleConsole({ tier, fetchAnswers }) {
  const dom = makeDom();
  const fetches = [];
  const context = {
    window: {
      BlueTeamApi: { create: () => ({ listRuns: async () => ({ tier, runs: [] }) }) },
      BlueTeamBoard: { mount: () => ({ destroy() {} }) },
      console: { warn() {} },
    },
    document: dom.document,
    console: { warn() {}, error() {}, log() {} },
    escHtml: (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    currentCourseId: COURSE,
    localStorage: { getItem: () => 'token-value' },
    Promise, JSON, Date, Array, Object, String, Number, encodeURIComponent, isFinite,
    setTimeout, clearTimeout,
    fetch: async (url, opts) => {
      fetches.push({ url, method: (opts && opts.method) || 'GET' });
      for (const [re, value] of (fetchAnswers || [])) {
        if (re.test(url)) return { ok: true, status: 200, json: async () => value };
      }
      throw new Error(`unscripted fetch ${url}`);
    },
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(
    fs.readFileSync(path.join(CLE, 'public', 'js', 'blue-team.js'), 'utf8'),
    context,
    { filename: 'blue-team.js' }
  );
  return { context, dom, fetches, CleBlueTeam: context.window.CleBlueTeam };
}

test('E9-U5: A STUDENT IS RENDERED NO PART OF THE AUTHORING PANEL', async () => {
  const h = mountCleConsole({ tier: 'student' });
  await h.CleBlueTeam.load();
  const html = h.dom.document.getElementById('blueTeamContent').innerHTML;

  assert.match(html, /Your instructor will start one/, 'the student board still rendered');
  for (const forbidden of [/Author attacks/, /caldera/i, /authoring/i, /adversar/i]) {
    assert.ok(!forbidden.test(html), `a student was shown ${forbidden}`);
  }
  // The panel builder itself, asked directly, also answers with nothing: the
  // tier is the SERVER's word and this file must not second-guess it.
  assert.strictEqual(h.CleBlueTeam.authoringHtml(), '');
  // And no authoring request was ever attempted on their behalf.
  assert.deepStrictEqual(h.fetches.filter((f) => /authoring/.test(f.url)), []);
});

test('E9-U6: the CLE twin renders the summary and the link, in that one answer', async () => {
  const h = mountCleConsole({
    tier: 'staff',
    fetchAnswers: [
      [/\/authoring\/fact-source$/, READY_PAYLOAD],
      [/\/authoring\/adversaries$/, ADVERSARY_PAYLOAD],
    ],
  });
  await h.CleBlueTeam.load();

  let html = h.dom.document.getElementById('blueTeamContent').innerHTML;
  assert.match(html, /Author attacks/);
  assert.ok(!/\/caldera/.test(html), 'no link before the refresh');

  // Press the button the mount wired, rather than calling an internal: that is
  // the path a person actually takes.
  const btn = h.dom.document.getElementById('blueTeamAuthorBtn');
  assert.ok(btn.handlers.click && btn.handlers.click.length, 'the button was never wired');
  await btn.handlers.click[0]();

  html = h.dom.document.getElementById('blueTeamContent').innerHTML;
  assert.match(html, /3 Windows machines and 1 Linux machine/);
  assert.match(html, /href="\/caldera\/"/);
  // Filtered to the course's own incidents collection. The mount ALSO probes
  // /api/caldera-authoring/status on load — a platform question, answered by a
  // different router, and unscripted in this harness on purpose — and what this
  // assertion is about is the ORDER OF THE TWO CALLS THAT TOUCH THE CONSOLE'S
  // FACT SOURCE. Widening it to every fetch would make it fail for a reason it
  // was never written to catch.
  assert.deepStrictEqual(
    h.fetches
      .filter((f) => /\/incidents\//.test(f.url))
      .map((f) => `${f.method} ${f.url.split('/incidents')[1]}`),
    ['POST /authoring/fact-source', 'GET /authoring/adversaries']
  );
});

test('E9-U7: the CLE twin refuses the link when the refresh did not land', async () => {
  const h = mountCleConsole({
    tier: 'staff',
    fetchAnswers: [[/\/authoring\/fact-source$/, { ready: false, reason: 'not_configured' }]],
  });
  await h.CleBlueTeam.load();
  await h.dom.document.getElementById('blueTeamAuthorBtn').handlers.click[0]();

  const html = h.dom.document.getElementById('blueTeamContent').innerHTML;
  assert.match(html, /Attack authoring is not set up/);
  assert.match(html, /CALDERA_AUTHORING_UPSTREAM/);
  assert.ok(!/href="\/caldera/.test(html));
  assert.deepStrictEqual(h.fetches.filter((f) => /adversaries/.test(f.url)), []);
});

// ---------------------------------------------------------------------------
// §6 The narrowed source-text gate. Read the header before touching it.
// ---------------------------------------------------------------------------

const GATED_DIRS = [
  'modules/crucible/plugins/ciab/routes',
  'modules/crucible/plugins/ciab/public',
  'modules/crucible/plugins/cle/routes',
  'modules/crucible/plugins/cle/public',
  'public',
  'src/routes',
];

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (/\.(js|html)$/.test(entry.name)) {
      out.push({ rel: path.relative(ROOT, full).split(path.sep).join('/'), full });
    }
  }
  return out;
}

/**
 * Source with its comments removed.
 *
 * Load-bearing, and for the reason ciab-deploy-parity.test.js gives: this
 * codebase documents its traps at length and the traps are named after exactly
 * the identifiers forbidden below. src/incident/caldera/authoring.js's header
 * lists the operation verbs in order to say that it never calls them, and the
 * consoles explain the execution gate to an instructor in prose. A gate that
 * cannot tell the explanation from the offence would forbid the comment written
 * to prevent the offence.
 */
function codeOnly(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('#') && !t.startsWith('<!--');
    })
    .join('\n');
}

const GATED_FILES = GATED_DIRS
  .flatMap((d) => walk(path.join(ROOT, d)))
  .map((f) => ({ ...f, code: codeOnly(fs.readFileSync(f.full, 'utf8')) }));

test('E9-G1: no browser or route file reaches the caldera ENGINE ADAPTER', () => {
  assert.ok(GATED_FILES.length > 50, 'the scan found almost nothing; the directory list is wrong');
  const re = /engines\/caldera|calderaEngineUnregistered|registerEngine/;
  const offenders = GATED_FILES.filter((f) => re.test(f.code)).map((f) => f.rel);
  assert.deepStrictEqual(offenders, [],
    'the adapter is unregistered until the E8 cluster gate passes, and nothing a browser can '
    + `reach may import or register it:\n  ${offenders.join('\n  ')}`);
});

test('E9-G2: no browser or route file contains the bare ENGINE KEY', () => {
  // THE NARROWING. The old rule would have been "the word caldera is absent",
  // which the authoring surface makes false — and which was never the property
  // worth having, because an authoring link and a dispatch look nothing alike.
  // What an EXECUTION path always looks like is the exact quoted key:
  // engine: 'caldera', engineFor('caldera'), <option value="caldera">. That is
  // forbidden; the word inside a longer string is not.
  const re = /(['"])caldera\1/;
  const offenders = GATED_FILES.filter((f) => re.test(f.code)).map((f) => f.rel);
  assert.deepStrictEqual(offenders, [],
    'a bare quoted engine key is what selecting caldera as an execution engine looks like. '
    + 'The word inside a sentence is fine; this is not:\n  ' + offenders.join('\n  '));
});

test('E9-G3: no browser or route file names a Caldera OPERATION verb', () => {
  // The authoring surface calls listSources / getSource / createSource /
  // updateSource / listAdversaries. These six are the ones that execute, they
  // belong to src/incident/engines/caldera.js alone, and their appearance above
  // would mean a dispatch path had grown where none may exist.
  const re = /\b(createOperation|getOperation|listLinks|listAgents|finishOperation|abortOperation)\b/;
  const offenders = GATED_FILES.filter((f) => re.test(f.code)).map((f) => f.rel);
  assert.deepStrictEqual(offenders, [],
    `a Caldera operation verb reached a route or a browser file:\n  ${offenders.join('\n  ')}`);
});

test('E9-G4: no console builds a request body naming an adversary', () => {
  // `it.adversary_id` is a property READ off a list row and is expected. An
  // object KEY spelled adversary_id is what a launch body would look like, and
  // there is no endpoint that would accept one.
  for (const rel of ['modules/crucible/plugins/ciab/public/js/instructor-incidents.js',
    'modules/crucible/plugins/cle/public/js/blue-team.js']) {
    const code = codeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    assert.ok(!/adversary_id\s*:/.test(code),
      `${rel} builds an object keyed by adversary_id — the only use for one is a launch`);
  }
});

test('E9-G5: THE MIRROR — the authoring surface actually exists', () => {
  // Every assertion above is satisfied by deleting the feature. This is the half
  // that makes them mean something.
  const expect = [
    ['modules/crucible/plugins/ciab/routes/incident-launch.js',
      [/router\.post\('\/authoring\/fact-source'/, /router\.get\('\/authoring\/adversaries'/,
        /syncFactSource|prepareAuthoring/, /AUTHORED_ADVERSARY_NOT_DISPATCHABLE/]],
    ['modules/crucible/plugins/cle/routes/incidents.js',
      [/router\.post\('\/authoring\/fact-source'/, /router\.get\('\/authoring\/adversaries'/,
        /prepareAuthoring/]],
    ['modules/crucible/plugins/ciab/public/js/instructor-incidents.js',
      [/authorAttacks/, /Author attacks/, /console_path/]],
    ['modules/crucible/plugins/cle/public/js/blue-team.js',
      [/authoringHtml/, /Author attacks/, /console_path/]],
  ];
  for (const [rel, patterns] of expect) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    for (const re of patterns) {
      assert.match(src, re, `${rel} no longer carries ${re}`);
    }
  }
});

test('E9-G6: THE MIRROR — the sync is what produces the link, in both consoles', () => {
  // Pinned as source text because it is a two-line ordering that no runtime
  // assertion in another suite would notice being reversed: console_path must be
  // conditional on `result.ready`, which prepareAuthoring only sets after the
  // sync resolves.
  for (const rel of ['modules/crucible/plugins/ciab/routes/incident-launch.js',
    'modules/crucible/plugins/cle/routes/incidents.js']) {
    const code = codeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    assert.match(code, /console_path:\s*result\.ready\s*\?/,
      `${rel} must gate the link on the sync's own result, not on anything else`);
  }
});

test('E9-G7: THE MIRROR — the honesty banner is on every file this phase added', () => {
  // Not decoration. No Caldera server exists, and a banner that can be deleted
  // without a test noticing will be.
  for (const rel of ['src/incident/caldera/authoring.js', 'test/caldera-authoring-ui.test.js']) {
    const head = fs.readFileSync(path.join(ROOT, rel), 'utf8').slice(0, 4000);
    assert.ok(/NEVER (BEEN RUN|TALKED TO|EXECUTED)|NO CALDERA SERVER|HAS EVER RUN AGAINST/i.test(head),
      `${rel} must say at the top that it has never met a real Caldera server`);
  }
});
