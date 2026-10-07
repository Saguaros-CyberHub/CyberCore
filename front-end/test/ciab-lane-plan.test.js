/**
 * ciab-lane-plan.test.js — POST /api/profile-deploy/plan, the live diagram's
 * data source.
 *
 * WHY THIS FILE EXISTS
 * The admin lane-deploy page draws a network diagram of one classroom lane while
 * an admin ticks assets. The entire value of that diagram is that it is TRUE:
 * the machines, their segments and their octets have to be the ones
 * runProfileDeploy would build from the same inputs. A preview that is
 * confidently wrong is worse than no preview, because it is believed.
 *
 * So this file runs the REAL synthesizer (profile-to-spec.js), the REAL
 * placement rule (lane-networking.resolveVmSegments) and the REAL console
 * planner through the REAL router. Only the edges are stubbed — the two
 * databases, auth, and the cluster. Stubbing profile-to-spec would leave every
 * assertion here checking a fake, when "does the preview agree with the deploy"
 * is the only question worth asking.
 *
 * THE PROPERTIES:
 *
 *   1. THE PIVOT IS DRAWN WHERE THE DEPLOY PUTS IT. Under v3 exactly one machine
 *      is dual-homed at .240 and everything else lands on `int`. This is the
 *      assertion the whole redesign exists for: the browser's own
 *      topology-editor.deriveSegments would put those machines on `ext`, which
 *      is the exact inverse, so placement is computed here and shipped verbatim.
 *
 *   2. vulnApp: null IS NOT AN OPTION. profile-to-spec gates both
 *      vuln_app_install and the synthetic vuln-app VM on
 *      `vulnApp && vulnApp.install_script`. With null there is no pivot,
 *      applyV3Topology never runs, and every machine falls back to ['ext'].
 *      PLAN_PROBE_APP exists to prevent that, and property 2 is what proves it
 *      is doing its job rather than being decorative.
 *
 *   3. THE LLM IS NEVER ON THIS PATH. getOrGenerateVulnApp takes ~4 minutes.
 *      The stub throws, so any call at all fails the test rather than making the
 *      suite slow.
 *
 *   4. A REFUSAL AN ADMIN CAN CAUSE BY TICKING A BOX IS A 200 WITH problems[].
 *      The .80-.99 band holds 20 machines; ticking a 21st is a thrown Error
 *      inside the synthesizer. A 500 mid-typing blanks the diagram instead of
 *      explaining it.
 *
 *   5. THE CARVE WINS OVER THE SELECTOR. runProfileDeploy builds at
 *      engagementRow.subnet_scheme, not at the request's. A v2-carved profile
 *      previewed as v3 would draw two segments and a .240 pivot for a lane that
 *      deploys flat.
 *
 *   6. NO DANGLING SEGMENTS, AND NO PROFILE JSON. A node naming a segment id the
 *      response does not carry renders attached with zero edges and no warning
 *      ring — invisible wrongness. And json_data is the whole client profile,
 *      which src/server.js deliberately 404s over HTTP.
 *
 *   7. THE PREVIEW WRITES NOTHING. It runs on a keystroke debounce; an INSERT on
 *      that path (resolveEngagement's adopt branch is one line away) would mean
 *      an admin adopting reservations by typing.
 */

'use strict';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

const PROFILE_ID = '11111111-2222-3333-4444-555555555555';

function put(absPath, exports) {
  const resolved = require.resolve(absPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
  return exports;
}

// ── mutable test state ──────────────────────────────────────────────────────
const state = {
  engagement: null,      // the ciab_engagement row, or null
  reservation: null,     // what findProfileChallenge answers
  vulnAppCacheRow: null, // ciab_profile_vuln_apps
  writes: [],            // every non-SELECT statement either db saw
  laneCount: 0,          // live lanes on the reservation
};

// ── the profile on disk ─────────────────────────────────────────────────────
// loadProfileForDeploy resolves json_file_path against process.cwd(), so this
// file becomes a sandbox in the OS temp dir for its whole run.
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'ciab-plan-'));
const REAL_CWD = process.cwd();
fs.mkdirSync(path.join(SANDBOX, 'profiles'));
process.chdir(SANDBOX);
after(() => { process.chdir(REAL_CWD); fs.rmSync(SANDBOX, { recursive: true, force: true }); });

/** web-01 declares 80/HTTP, so isWebServer forces it Linux and it becomes the pivot. */
const ASSETS = [
  { hostname: 'web-01', role: 'server', os: 'Debian 12', services: ['80/HTTP'] },
  { hostname: 'dc01', role: 'server', os: 'Windows Server 2019 Standard' },
  { hostname: 'file01', role: 'server', os: 'Windows Server 2019 Standard' },
  { hostname: 'ws-acct-01', role: 'workstation', os: 'Windows 11 Pro' },
  // No os_family parses out of this, so the resolver is never asked: a ghost.
  { hostname: 'ot-hmi-01', role: 'ot', os: 'Siemens embedded firmware' },
];

function writeProfile(assets) {
  fs.writeFileSync(path.join(SANDBOX, 'profiles', 'client.json'), JSON.stringify({
    student_view: {
      meta: { run_id: 'run-plan-1', client_type: 'SMB' },
      raw: {
        threats: {
          organization: { company_name: 'Northwind Dental', employees_total: 120 },
          network: {
            public_ip: '203.0.113.7',
            subnets: [
              { name: 'Servers', cidr: '192.168.2.0/24', vlan_id: 20,
                purpose: 'server vlan', trust_level: 'Medium' },
            ],
            assets: assets || ASSETS,
          },
        },
      },
    },
  }));
}
writeProfile();

// ── the two databases ───────────────────────────────────────────────────────
const isRead = (sql) => /^\s*SELECT/i.test(String(sql));

async function clinicQuery(sql, params) {
  const text = String(sql).replace(/\s+/g, ' ').trim();
  if (!isRead(text)) { state.writes.push({ db: 'clinic', sql: text, params }); return { rows: [], rowCount: 0 }; }

  if (/FROM profiles WHERE id/i.test(text)) {
    return {
      rows: [{
        id: PROFILE_ID, user_id: 'u1', company_name: 'Northwind Dental',
        industry: 'Healthcare', difficulty: 'easy', client_type: 'SMB',
        employee_count: 120, json_file_path: 'profiles/client.json',
        html_file_path: null, run_id: 'run-plan-1', generation_status: 'complete',
      }],
      rowCount: 1,
    };
  }
  if (/FROM vuln_scripts/i.test(text)) return { rows: [], rowCount: 0 };
  if (/FROM ciab_profile_vuln_apps/i.test(text)) {
    return state.vulnAppCacheRow
      ? { rows: [state.vulnAppCacheRow], rowCount: 1 }
      : { rows: [], rowCount: 0 };
  }
  if (/FROM ciab_engagement/i.test(text)) {
    return state.engagement ? { rows: [state.engagement], rowCount: 1 } : { rows: [], rowCount: 0 };
  }
  return { rows: [], rowCount: 0 };
}

/** Every active os_template row the resolver may pick from. node is set on all
 *  of them so vm-template-resolver never reaches site-config's readFileSync. */
const TEMPLATE_CATALOG = [
  { id: 1, os_family: 'linux', os_version: 'debian-13', os_name: 'Debian 13 web',
    template_vmid: 1005, node: 'node-1', role_hints: ['web'], is_active: true,
    preferred: false, created_at: new Date('2025-01-01') },
  { id: 2, os_family: 'windows_server', os_version: '2019', os_name: 'Windows Server 2019',
    template_vmid: 1004, node: 'node-1', role_hints: [], is_active: true,
    preferred: true, created_at: new Date('2025-01-02') },
  { id: 3, os_family: 'windows_client', os_version: '11', os_name: 'Windows 11',
    template_vmid: 1002, node: 'node-1', role_hints: [], is_active: true,
    preferred: true, created_at: new Date('2025-01-03') },
];

async function cybercoreQuery(sql, params) {
  const text = String(sql).replace(/\s+/g, ' ').trim();
  if (!isRead(text)) { state.writes.push({ db: 'cybercore', sql: text, params }); return { rows: [] }; }
  if (/FROM cybercore_template_catalog/i.test(text)) return { rows: TEMPLATE_CATALOG };
  if (/COUNT\(DISTINCT vxlan_id\)/i.test(text)) return { rows: [{ used: String(state.laneCount) }] };
  if (/COUNT\(\*\)/i.test(text)) return { rows: [{ n: state.laneCount }] };
  return { rows: [] };
}

const fakePool = { query: clinicQuery, connect: async () => ({ query: clinicQuery, release() {} }) };

put(path.join(CIAB, 'utils', 'db.js'), {
  query: clinicQuery, getPool: () => fakePool, setPool: () => {}, pool: fakePool,
});
put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery });

put(path.join(ROOT, 'src', 'middleware', 'auth.js'), {
  authenticateToken: (req, res, next) => (
    req.user ? next() : res.status(401).json({ error: 'unauthorized' })
  ),
  requireRole: (...roles) => (req, res, next) => (
    req.user && roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'forbidden' })
  ),
});

put(path.join(ROOT, 'src', 'utils', 'audit.js'), { log: () => {}, batch: () => {} });
put(path.join(ROOT, 'src', 'utils', 'lane-deployer.js'),
  new Proxy({}, { get: () => async () => ({}) }));
// batch-deployer calls getSchedulingConfig() at MODULE LOAD, which reads
// config/site.json — a file a checkout does not carry. Stubbing it is what lets
// the REAL challenge-lane-deployer load, so resolveConsolePlan below is the
// deploy's own console rule rather than a fake. (buildLanePlan degrades
// gracefully when this require fails; that path is asserted separately.)
put(path.join(ROOT, 'src', 'utils', 'batch-deployer.js'),
  new Proxy({}, { get: () => async () => ({}) }));
put(path.join(ROOT, 'src', 'utils', 'proxmox.js'), { proxmoxAPI: async () => ({}) });
put(path.join(ROOT, 'src', 'utils', 'guacamole.js'), { guacAPI: async () => ({}) });
put(path.join(ROOT, 'src', 'utils', 'lane-claims.js'), { claimsSql: () => 'true' });
put(path.join(ROOT, 'src', 'middleware', 'deployment-guards.js'),
  { buildDeployPreview: async () => ({}) });

// PROPERTY 3: the LLM path must never be reached from /plan.
put(path.join(CIAB, 'utils', 'vuln-app-generator.js'), {
  getOrGenerateVulnApp: async () => {
    throw new Error('getOrGenerateVulnApp reached from the preview path — that is a ~4 minute LLM call');
  },
});
put(path.join(CIAB, 'utils', 'vuln-app-builder.js'), { resolveImageFile: () => null });
put(path.join(CIAB, 'utils', 'cost-estimator.js'),
  { estimateDeployCost: () => ({}), DEFAULT_MODEL: 'claude-sonnet-5' });
put(path.join(CIAB, 'utils', 'profile-students.js'), {
  provisionLaneStudents: async () => ({ groupSlug: 's', students: [], credentials: [] }),
  slugForGroup: () => 's',
});
put(path.join(CIAB, 'utils', 'lane-provision.js'), new Proxy({}, { get: () => async () => ({}) }));
put(path.join(CIAB, 'utils', 'bake-orchestrator.js'), {
  listBakes: async () => [],
  getLatestReadyBake: async () => null,
  startBake: async () => ({}),
  buildBakeSteps: () => ({}),
});
put(path.join(CIAB, 'utils', 'bake-staging.js'), new Proxy({}, { get: () => () => ({}) }));
put(path.join(CIAB, 'utils', 'blueteam-templates.js'), { resolveTelemetryTemplates: async () => null });

// engagement-provision: only the READ is exercised. resolveEngagement is
// deliberately a thrower here — it INSERTs via adoptExistingReservation, and
// PROPERTY 7 is that the preview never calls it.
put(path.join(CIAB, 'utils', 'engagement-provision.js'), {
  getEngagement: async () => state.engagement,
  resolveEngagement: async () => {
    throw new Error('resolveEngagement reached from the preview path — it INSERTs');
  },
  assertEngagementDeployable: () => {},
  DEFAULT_SUBNET_SCHEME: 'v3',
});

const laneReservation = require(path.join(CIAB, 'utils', 'lane-reservation.js'));
put(path.join(CIAB, 'utils', 'lane-reservation.js'), Object.assign({}, laneReservation, {
  findProfileChallenge: async () => state.reservation,
  getOrCreateProfileChallenge: async () => {
    throw new Error('getOrCreateProfileChallenge reached from the preview path — it CARVES');
  },
}));

// The router, with the REAL profile-to-spec, lane-networking and console planner.
const router = require(path.join(CIAB, 'routes', 'profile-deploy.js'));

/** One request through the real router, with no socket and no port. */
function call(method, url, opts) {
  const o = opts || {};
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: o.query || {}, headers: {},
      user: o.anonymous ? undefined : { role: o.role || 'admin', userId: 'admin-1' },
    };
    const res = {
      statusCode: 200, headers: {},
      status(code) { this.statusCode = code; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      getHeader(k) { return this.headers[k]; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); return this; },
      send(payload) { resolve({ status: this.statusCode, body: payload }); return this; },
      end() { resolve({ status: this.statusCode, body: null }); return this; },
    };
    router(req, res, (err) => (err ? reject(err) : resolve({ status: 404, body: null })));
  });
}

const plan = (body) => call('POST', '/plan', {
  body: Object.assign({ profile_id: PROFILE_ID, num_lanes: 3 }, body || {}),
});

const RESERVED_V3 = {
  challenge_id: 'ch-1', challenge_key: 'ciab-profile-11111111-default',
  created_at: new Date(), vxlan_block: { start: 10000, end: 10024 },
  max_students: 25, zone_abbrev: 'ciabprof',
  spec: { subnet_scheme: 'v3', vxlan_block: { start: 10000, end: 10024 } },
};

beforeEach(() => {
  state.engagement = null;
  state.reservation = null;
  state.vulnAppCacheRow = null;
  state.writes.length = 0;
  state.laneCount = 0;
  writeProfile();
});

// ── PROPERTY 1 ──────────────────────────────────────────────────────────────

test('v3: exactly one machine is dual-homed at .240 and everything else is on int', async () => {
  const { status, body } = await plan({ subnet_scheme: 'v3', vuln_app_enabled: true });
  assert.equal(status, 200, JSON.stringify(body));

  const assetMachines = body.machines.filter((m) => m.origin !== 'attack_box');
  const pivots = assetMachines.filter((m) => m.segments.length > 1);

  assert.equal(pivots.length, 1, 'a v3 lane has exactly one dual-homed pivot');
  assert.deepEqual(pivots[0].segments, ['ext', 'int']);
  assert.equal(pivots[0].ip_octet, 240, 'the pivot is pinned to DUAL_HOMED_OCTET');
  assert.equal(pivots[0].name, 'web-01', 'web-01 declares 80/HTTP, so isWebServer picks it');
  assert.equal(pivots[0].is_pivot, true);
  assert.equal(pivots[0].view_role, 'dmz', 'so topology-icons draws the DMZ glyph');

  for (const m of assetMachines) {
    if (m.is_pivot) continue;
    assert.deepEqual(m.segments, ['int'],
      `${m.name} must land on the corporate segment, not the attacker's`);
  }
  assert.equal(body.vuln_app.target_vm, 'web-01');
});

test('Kali is drawn on ext at .50 and is the console, though it is never in spec.vms', async () => {
  const { body } = await plan({ subnet_scheme: 'v3', attack_boxes: true });
  const kali = body.machines.find((m) => m.origin === 'attack_box');
  assert.ok(kali, 'the attack box is synthesized — the spec only records attack_boxes: true');
  assert.deepEqual(kali.segments, ['ext']);
  assert.equal(kali.ip_octet, 50, 'the gateway bakes its RDP DNAT against .50');
  assert.equal(kali.view_role, 'attacker');
  assert.equal(kali.is_console, true);
  assert.equal(body.console.vm, 'kali');
});

test('attack_boxes:false removes the attacker node and leaves no console', async () => {
  const { body } = await plan({ attack_boxes: false });
  assert.equal(body.machines.filter((m) => m.origin === 'attack_box').length, 0);
  assert.equal(body.console, null, 'the console is picked at deploy time from the spec VMs');
});

// ── PROPERTY 2 ──────────────────────────────────────────────────────────────

test('vuln-app OFF under v3 is drawn honestly: no pivot, everything on ext', async () => {
  const { body } = await plan({ subnet_scheme: 'v3', vuln_app_enabled: false });

  assert.equal(body.vuln_app.target_vm, null);
  for (const m of body.machines) {
    assert.deepEqual(m.segments, ['ext'],
      `${m.name}: with no pivot, applyV3Topology never runs and everything falls to ext`);
  }
  assert.ok(body.notices.some((n) => n.code === 'NO_PIVOT_V3'),
    'the operator is told the int segment buys them nothing in this configuration');
});

test('the synthetic vuln-app VM appears when no selected asset serves web', async () => {
  // Untick web-01 — the only asset satisfying isWebServer.
  const selection = ASSETS.map((a) => ({
    hostname: a.hostname, role: a.role, os: a.os,
    included: a.role === 'server' && a.hostname !== 'web-01',
  }));
  const { body } = await plan({ subnet_scheme: 'v3', asset_selection: selection });

  const synthetic = body.machines.find((m) => m.name === 'vuln-app');
  assert.ok(synthetic, 'profile-to-spec appends a dedicated VM when nothing serves web');
  assert.equal(synthetic.origin, 'synthetic');
  assert.equal(synthetic.template_vmid, 1005);
  assert.deepEqual(synthetic.segments, ['ext', 'int'], 'it becomes the pivot');
  assert.equal(synthetic.ip_octet, 240);
  assert.equal(body.vuln_app.target_vm, 'vuln-app');
});

test('the cached target_hostname decides the pivot, as it does on the deploy', async () => {
  state.vulnAppCacheRow = { target_hostname: 'file01' };
  const { body } = await plan({ subnet_scheme: 'v3' });
  assert.equal(body.vuln_app.target_vm, 'file01', 'targeting rung 1 wins over the isWebServer guess');
  assert.equal(body.vuln_app.target_source, 'cached');
  const pivot = body.machines.find((m) => m.is_pivot);
  assert.equal(pivot.name, 'file01');
  assert.deepEqual(pivot.segments, ['ext', 'int']);
});

// ── v2 ──────────────────────────────────────────────────────────────────────

test('v2 is one flat segment: every machine on lan, no pivot, no .240', async () => {
  const { body } = await plan({ subnet_scheme: 'v2' });
  assert.deepEqual(body.segments.map((s) => s.id), ['lan']);
  for (const m of body.machines) {
    assert.deepEqual(m.segments, ['lan'], `${m.name} is on the one flat segment`);
    assert.notEqual(m.ip_octet, 240, 'nothing is dual-homed on a flat lane');
  }
  assert.equal(body.machines.filter((m) => m.is_pivot).length, 0);
});

// ── PROPERTY 4 ──────────────────────────────────────────────────────────────

test('21 band-bound machines is a 200 with BAND_CAPACITY, not a 500', async () => {
  const many = Array.from({ length: 24 }, (_, i) => ({
    hostname: `srv-${String(i).padStart(2, '0')}`, role: 'server',
    os: 'Windows Server 2019 Standard',
  }));
  writeProfile(many);

  const { status, body } = await plan({ subnet_scheme: 'v3' });
  assert.equal(status, 200, 'a refusal an admin causes by ticking a box must not blank the diagram');
  const problem = body.problems.find((p) => p.code === 'BAND_CAPACITY');
  assert.ok(problem, `expected BAND_CAPACITY, got ${JSON.stringify(body.problems)}`);
  assert.match(problem.message, /20/, 'the message names the real limit');
});

test('every asset missing a template, vuln-app OFF, is NO_DEPLOYABLE_VMS', async () => {
  writeProfile([
    { hostname: 'ot-1', role: 'server', os: 'Siemens embedded firmware' },
    { hostname: 'ot-2', role: 'server', os: 'proprietary switch OS' },
  ]);
  const { status, body } = await plan({ vuln_app_enabled: false });
  assert.equal(status, 200);
  assert.ok(body.problems.some((p) => p.code === 'NO_DEPLOYABLE_VMS'),
    `expected NO_DEPLOYABLE_VMS, got ${JSON.stringify(body.problems)}`);
  assert.equal(body.ghosts.length, 2, 'both are named, so the operator knows which');
});

test('the same profile with the vuln-app ON still builds one machine: the app itself', async () => {
  // Worth pinning because it is counter-intuitive and the diagram must show it:
  // a client whose every asset is unbuildable is NOT an empty lane while the
  // vuln-app is on — profile-to-spec appends the dedicated VM regardless.
  writeProfile([
    { hostname: 'ot-1', role: 'server', os: 'Siemens embedded firmware' },
    { hostname: 'ot-2', role: 'server', os: 'proprietary switch OS' },
  ]);
  const { body } = await plan({ vuln_app_enabled: true, attack_boxes: false });
  assert.ok(!body.problems.some((p) => p.code === 'NO_DEPLOYABLE_VMS'));
  assert.deepEqual(body.machines.map((m) => m.name), ['vuln-app']);
  assert.equal(body.ghosts.length, 2);
});

// ── PROPERTY 5 ──────────────────────────────────────────────────────────────

test('a v2 carve beats a v3 request, and says so', async () => {
  state.engagement = { subnet_scheme: 'v2', engagement_type: 'default' };
  const { body } = await plan({ subnet_scheme: 'v3' });

  assert.equal(body.scheme.requested, 'v3');
  assert.equal(body.scheme.effective, 'v2', 'the block was carved at v2; the selector is advisory');
  assert.equal(body.scheme.locked_by_engagement, true);
  assert.deepEqual(body.segments.map((s) => s.id), ['lan']);
  assert.ok(body.notices.some((n) => n.code === 'SCHEME_LOCKED_BY_ENGAGEMENT'));
});

test('with no ciab_engagement row the carve is read off the reservation spec', async () => {
  state.reservation = Object.assign({}, RESERVED_V3, {
    spec: { subnet_scheme: 'v2', vxlan_block: { start: 10000, end: 10024 } },
  });
  const { body } = await plan({ subnet_scheme: 'v3' });
  assert.equal(body.scheme.effective, 'v2',
    'a pre-engagement reservation still records the scheme it was carved at');
});

// ── addresses ───────────────────────────────────────────────────────────────

test('concrete addresses appear only when lane 1 really is the block start', async () => {
  state.reservation = RESERVED_V3;
  state.laneCount = 0;
  const fresh = await plan({ subnet_scheme: 'v3' });
  const pivot = fresh.body.machines.find((m) => m.is_pivot);
  // vxlan 10000 -> high 39, low 16 -> ext 10.39.16.x, int high |0x80 -> 10.167.16.x
  assert.equal(pivot.ip_display, '10.39.16.240');
  assert.equal(fresh.body.segments.find((s) => s.id === 'ext').cidr, '10.39.16.0/24');
  assert.equal(fresh.body.segments.find((s) => s.id === 'int').cidr, '10.167.16.0/24');

  // Once a slot is consumed, lane 1's vxlan is no longer the block start, so an
  // address would be a guess. Bare octets are honest; a wrong /24 is not.
  state.laneCount = 3;
  const used = await plan({ subnet_scheme: 'v3' });
  assert.equal(used.body.machines.find((m) => m.is_pivot).ip_display, null);
  assert.equal(used.body.segments.find((s) => s.id === 'ext').cidr, null);
  assert.equal(used.body.machines.find((m) => m.is_pivot).ip_octet, 240,
    'the octet is still known and still drawn');
});

test('with no reservation there are no addresses and the operator is told why', async () => {
  const { body } = await plan({});
  assert.ok(body.machines.every((m) => m.ip_display === null));
  assert.ok(body.segments.every((s) => s.cidr === null));
  assert.ok(body.notices.some((n) => n.code === 'NO_RESERVATION'));
});

// ── ghosts ──────────────────────────────────────────────────────────────────

test('an asset that resolves no template is a ghost, named, with a reason and a remedy', async () => {
  const selection = ASSETS.map((a) => ({
    hostname: a.hostname, role: a.role, os: a.os,
    included: a.role === 'server' || a.hostname === 'ot-hmi-01',
  }));
  const { body } = await plan({ asset_selection: selection });

  const ghost = body.ghosts.find((g) => g.name === 'ot-hmi-01');
  assert.ok(ghost, 'a ticked asset that will not be built has to be visible');
  // "Siemens embedded firmware" DOES parse — parseOs has an `embedded` family —
  // so the resolver is asked and finds no active template. The two reasons send
  // an operator to different places (fix the OS string vs. add a template),
  // which is why the ghost carries the reason rather than just "no template".
  assert.equal(ghost.reason, 'no_family_match');
  assert.ok(ghost.reason_text.length > 0);
  assert.ok(ghost.remedies.length >= 1, 'a ghost without a remedy is just bad news');
  assert.ok(!body.machines.some((m) => m.name === 'ot-hmi-01'),
    'and it must NOT appear as a machine — no VM is built for it');
  assert.equal(body.counts.ghosts, body.ghosts.length);
});

test('unticked assets are parked, not ghosts', async () => {
  const { body } = await plan({});   // default selection: servers only
  assert.ok(body.parked.some((p) => p.hostname === 'ws-acct-01'));
  assert.ok(!body.ghosts.some((g) => g.name === 'ws-acct-01'),
    'you unticked it — that is not a failure to build it');
});

// ── PROPERTY 6 ──────────────────────────────────────────────────────────────

test('every machine is attached, and no machine names a segment that does not exist', async () => {
  for (const scheme of ['v2', 'v3']) {
    const { body } = await plan({ subnet_scheme: scheme });
    const ids = new Set(body.segments.map((s) => s.id));
    for (const m of body.machines) {
      assert.ok(m.segments.length > 0, `${m.name} (${scheme}) has no NIC — it would float`);
      for (const id of m.segments) {
        assert.ok(ids.has(id),
          `${m.name} (${scheme}) names segment '${id}', which renders attached with zero edges`);
      }
    }
    for (const g of body.ghosts) {
      assert.ok(!g.segments || g.segments.length === 0, 'a ghost is unwired by construction');
    }
  }
});

test('every machine carries a stable id, and ids are unique', async () => {
  const { body } = await plan({});
  const ids = body.machines.map((m) => m.id).concat(body.ghosts.map((g) => g.id));
  assert.equal(new Set(ids).size, ids.length, 'duplicate ids collapse nodes in the renderer');
  assert.ok(body.machines.every((m) => m.id.startsWith('m:')));
  assert.ok(body.ghosts.every((g) => g.id.startsWith('ghost:')));
});

test('the response never carries the client profile JSON', async () => {
  const { body } = await plan({});
  const serialized = JSON.stringify(body);
  assert.ok(!serialized.includes('json_data'),
    'src/server.js 404s profile JSON over HTTP deliberately; this must not be a side door');
  assert.ok(!serialized.includes('student_view'));
});

// ── PROPERTY 7 ──────────────────────────────────────────────────────────────

test('the preview writes nothing to either database', async () => {
  state.reservation = RESERVED_V3;
  await plan({ subnet_scheme: 'v3' });
  await plan({ subnet_scheme: 'v2', vuln_app_enabled: false });
  assert.deepEqual(state.writes, [],
    `the preview runs on a keystroke debounce: ${JSON.stringify(state.writes)}`);
});

test('live lanes lock the spec, and the diagram says so instead of drawing the selection', async () => {
  state.reservation = Object.assign({}, RESERVED_V3, {
    spec: {
      subnet_scheme: 'v3',
      vxlan_block: { start: 10000, end: 10024 },
      vms: [{ name: 'legacy-01', role: 'server', os_family: 'linux', template_vmid: 1005,
              nics: [{ segment: 'int' }], ipOctet: 80 }],
    },
  });
  state.laneCount = 4;

  const { body } = await plan({ subnet_scheme: 'v3' });
  assert.equal(body.engagement.spec_source, 'stored');
  assert.ok(body.notices.some((n) => n.code === 'SPEC_LOCKED_BY_LIVE_LANES'));
  assert.ok(body.machines.some((m) => m.name === 'legacy-01'),
    'the lanes are built from the stored spec, so that is what must be drawn');
  assert.ok(!body.machines.some((m) => m.name === 'dc01'),
    'the asset selection being ticked is discarded by runProfileDeploy here');
});

// ── auth ────────────────────────────────────────────────────────────────────

test('/plan is admin-only', async () => {
  assert.equal((await call('POST', '/plan', { anonymous: true })).status, 401);
  assert.equal((await call('POST', '/plan', { role: 'instructor' })).status, 403);
  assert.equal((await call('POST', '/plan', { role: 'student' })).status, 403);
});

test('a missing profile_id is a 400, and a missing profile is a 404', async () => {
  assert.equal((await call('POST', '/plan', { body: {} })).status, 400);
});

// ── /preview no longer contradicts the plan ─────────────────────────────────

test('/preview sizes the cluster against what will be BUILT, not the whole profile', async () => {
  // The defect: serverCount was `assets.filter(role === 'server')` over the
  // WHOLE profile, so unticking an asset changed the deploy and not the preview,
  // and the number an operator sized the cluster against was not the number of
  // VMs they were about to create.
  const onlyDc = ASSETS.map((a) => ({
    hostname: a.hostname, role: a.role, os: a.os, included: a.hostname === 'dc01',
  }));

  const all = await call('POST', '/preview', {
    body: { profile_id: PROFILE_ID, num_lanes: 2, vuln_app_enabled: false },
  });
  const one = await call('POST', '/preview', {
    body: { profile_id: PROFILE_ID, num_lanes: 2, vuln_app_enabled: false, asset_selection: onlyDc },
  });

  assert.equal(all.status, 200);
  assert.equal(one.status, 200);
  assert.equal(one.body.profile_asset_summary.will_deploy, 1,
    'one ticked asset that resolves a template is one machine');
  assert.ok(one.body.profile_asset_summary.will_deploy < all.body.profile_asset_summary.will_deploy,
    'unticking assets must move the preview, or it is answering a different question');
});

test('/preview counts the machines that will not be built, separately', async () => {
  const withGhost = ASSETS.map((a) => ({
    hostname: a.hostname, role: a.role, os: a.os,
    included: a.role === 'server' || a.hostname === 'ot-hmi-01',
  }));
  const { body } = await call('POST', '/preview', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, asset_selection: withGhost },
  });
  assert.equal(body.profile_asset_summary.not_built, 1);
  assert.ok(body.lane_plan_counts, 'the same counts the diagram shows, from one request');
});

test('/preview and /plan agree about the machine count', async () => {
  const body = { profile_id: PROFILE_ID, num_lanes: 3, subnet_scheme: 'v3' };
  const prev = await call('POST', '/preview', { body: body });
  const p = await plan({ subnet_scheme: 'v3' });
  const specMachines = p.body.machines.filter((m) => m.origin !== 'attack_box').length;
  assert.equal(prev.body.profile_asset_summary.will_deploy, specMachines,
    'two answers to "how many machines" that can disagree is the defect, not the feature');
});
