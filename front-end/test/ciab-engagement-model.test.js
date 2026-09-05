/**
 * ciab-engagement-model.test.js — Track B, phase B0: the ENGAGEMENT MODEL.
 *
 * WHY THIS FILE EXISTS
 * Migration 010 gave a CiAB engagement a NETWORK — a carved VXLAN block and a
 * provision status. B0 gives it a JOB: what is in scope, what is out, which
 * techniques are permitted, which accounts the client agreed to hand over, WHERE
 * each machine sits relative to the perimeter, and the brief the student reads.
 *
 * Three artefacts carry that job, and they can only be trusted together:
 *
 *   migrations/011_ciab_engagement_model.sql   the columns
 *   migrations/012_ciab_engagement_guards.sql  the shape backstops
 *   migrations/013_ciab_engagement_secret_guard.sql  the never-a-secret backstop
 *   utils/engagement-model.js                  the vocabulary and the validators
 *   utils/engagement-plan.js                   the pure deterministic compile
 *   utils/engagement-provision.js              the read projection and the writer
 *
 * Each block below defends one property that is cheap to break by accident and
 * expensive to notice:
 *
 *   §1  PURITY. engagement-model.js has ZERO requires and engagement-plan.js has
 *       exactly five. test/ciab-reservation.test.js:225-229 loads
 *       routes/profile-deploy.js on a STUBBED module cache whose clinic_db
 *       handle throws on any query, and src/utils/site-config.js:29-30 does an
 *       unguarded fs.readFileSync of config/site.json — a file that is ABSENT
 *       from this checkout. One extra import turns both of those into an ENOENT
 *       naming the wrong file.
 *   §2  MIGRATION HYGIENE. src/plugin-loader.js:134-147 sends each .sql file as
 *       ONE pool.query() — the whole file is one implicit transaction — inside a
 *       try/catch whose catch only console.error()s. A single non-idempotent
 *       statement therefore silently reverts every other statement in the same
 *       file, on every boot, forever, while the server starts normally.
 *   §3  PROJECTION. getEngagement/listEngagements SELECT *, so the database
 *       really does return the new columns; rowToEngagement is a hand-written
 *       whitelist that silently drops anything not listed. The parse-the-
 *       migration test is the highest-value assertion in this file.
 *   §4  The type vocabulary is a REGISTRY WITH A TOTAL FALLBACK, never an
 *       allowlist — createEngagement accepts any sanitized slug today.
 *   §5  Instructor vocabulary: Section / Module / Client / Engagement /
 *       Environment. The words course, material and challenge never appear in
 *       anything a human reads.
 *   §6  NEVER a secret in issued_credentials, and never an unquotable path.
 *   §7  EXPOSURE — placement, not publishing. Exactly one pivot per lane.
 *   §8  The three representations of one fact (slug, perspective, posture) are
 *       reconciled at write time, as a 400 rather than a 23514.
 *   §9  The compile is TOTAL and DETERMINISTIC.
 *   §10 The no-behaviour-change proof for every engagement that exists today.
 *   §11 Perspective changes SCOPE and PLACEMENT, never the deployed set.
 *   §12 Honest derivation: what a profile cannot tell us is a problem code, not
 *       an invention.
 *   §13 THE MIRROR THAT DRIFTED — the two "is this host pinnable?" rules.
 *
 * WHAT THIS FILE IS NOT
 * It runs no SQL. This checkout has no psql binary and no running docker daemon
 * (verified), so §2 asserts on the migration TEXT. The manual apply-twice step
 * against a scratch database is documented in the phase plan and is not
 * optional.
 *
 * STUB DISCIPLINE
 * §1-2 and §4-13 install NO stubs at all — the bare requires ARE the purity
 * assertion, and they only pass because config/site.json genuinely does not
 * exist here. §3 alone installs the single site-config require.cache stub, in
 * the ciab-engagement-provision.test.js:36-46 shape, and it is installed AFTER
 * the §1 requires have already run so it cannot mask an impurity.
 *
 * Run: node --test front-end/test/ciab-engagement-model.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const abs = (rel) => path.join(ROOT, rel);
const read = (rel) => fs.readFileSync(abs(rel), 'utf8');

const TRACK_B = 'See the program plan, Track B.';

const CIAB = 'modules/crucible/plugins/ciab';
const MODEL_REL = `${CIAB}/utils/engagement-model.js`;
const PLAN_REL = `${CIAB}/utils/engagement-plan.js`;
const PROVISION_REL = `${CIAB}/utils/engagement-provision.js`;
const ROUTE_REL = `${CIAB}/routes/profile-deploy.js`;
const SYNTH_REL = `${CIAB}/utils/profile-to-spec.js`;
const DEPLOYER_REL = 'src/utils/challenge-lane-deployer.js';
const MIG_DIR = `${CIAB}/migrations`;

const MIG_MODEL = `${MIG_DIR}/011_ciab_engagement_model.sql`;
const MIG_GUARDS = `${MIG_DIR}/012_ciab_engagement_guards.sql`;
const MIG_SECRET = `${MIG_DIR}/013_ciab_engagement_secret_guard.sql`;
const MIG_010 = `${MIG_DIR}/010_ciab_engagements.sql`;
const B0_MIGRATIONS = [MIG_MODEL, MIG_GUARDS, MIG_SECRET];

// ── Source-scan helpers ─────────────────────────────────────────────────────
// EVERY scan splits on /\r?\n/ and strips per line. The working tree is CRLF
// (core.autocrlf=true, no .gitattributes) and '\r' is a line terminator to a JS
// regex, so a whole-file /^\s*--.*$/gm stripper silently stops stripping on this
// checkout — test/sql-param-typing.test.js:66-72 documents the same trap.

/** SQL with every -- comment removed, line by line. */
function sqlCode(src) {
  return src
    .split(/\r?\n/)
    .map(line => line.replace(/--.*$/, ''))
    .filter(line => line.trim() !== '')
    .join('\n');
}

/** JavaScript with block comments and whole-line // comments removed. */
function jsCode(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith('//') && !t.startsWith('*');
    })
    .join('\n');
}

// ── §1 requires: BARE, no stubs, before anything touches require.cache ───────
// This ordering is the assertion. If either module reached site-config.js — or
// anything that does — the require below would throw ENOENT on config/site.json
// and every test in this file would fail at load rather than at an assertion.

const MODEL = require(abs(MODEL_REL));

// Measured between the two requires. engagement-model.js imports NOTHING, so
// nothing under src/utils may be in the cache yet.
const SITE_CONFIG_ABS = require.resolve(abs('src/utils/site-config.js'));
const SITE_CONFIG_UNTOUCHED_BY_MODEL =
  !Object.prototype.hasOwnProperty.call(require.cache, SITE_CONFIG_ABS);

const PLAN = require(abs(PLAN_REL));
const SYNTH = require(abs(SYNTH_REL));

// ── §3's stub, installed only now ───────────────────────────────────────────
// The same shape as test/ciab-engagement-provision.test.js:36-46. Verified
// sufficient on its own: engagement-provision.js's transitive graph reaches
// site-config.js and nothing else that needs a cluster to load.
require.cache[SITE_CONFIG_ABS] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({ max_concurrent_lanes: 5, max_concurrent_clones: 4 }),
    getDefaultTemplateNode: () => 'node-1',
    getClusterNodes: () => [],
    getPhysicalClusterIps: () => ({}),
    getV2LabNetwork: () => ({
      network: '100.100.60.0', prefix_len: 22, reserved: [],
      host_range: { first: '100.100.60.10', last: '100.100.63.254' },
    }),
  },
};
const PROVISION = require(abs(PROVISION_REL));

// ── Fixtures ────────────────────────────────────────────────────────────────
// NO FIXTURE HERE MAY REACH THE TEMPLATE RESOLVER. src/utils/vm-template-resolver.js:83
// calls getDefaultTemplateNode(), and site-config.js:29-30 reads config/site.json,
// which is absent from this checkout. compileEngagementPlan never resolves a
// template, so it cannot fire — but a later fixture that synthesizes a spec must
// set node: on every catalog row or stub site-config the way §3 does.

/** The three assets every backwards-compatibility assertion is measured against. */
const ASSETS = Object.freeze([
  { hostname: 'web01', role: 'server', os: 'Ubuntu 22.04' },
  { hostname: 'dc01', role: 'server', os: 'Windows Server 2019' },
  { hostname: 'ws01', role: 'workstation', os: 'Windows 11' },
]);

/**
 * A spec built from those assets, in asset order, pinned from the synthesizer's
 * OWN exported band so the octet assertions cannot drift from
 * assignLaneAddressing (profile-to-spec.js:175-196).
 */
function specFrom(assets, extra) {
  const services = { web01: ['80/HTTP'], dc01: ['389/LDAP'] };
  return Object.assign({
    subnet_scheme: 'v3',
    vms: assets.map((a, i) => ({
      name: a.hostname,
      hostname: a.hostname,
      role: a.role,
      os: a.os,
      type: 'qemu',
      ipOctet: SYNTH.SPEC_OCTET_MIN + i,
      services: services[a.hostname] || [],
    })),
  }, extra || {});
}

/** A canonical AI profile: assets carry NO services array, which is exactly what
 *  ai/profile/prompts.js:1040 emits. */
const PROFILE = Object.freeze({
  id: 'prof-b0',
  json_data: {
    student_view: {
      raw: {
        threats: {
          organization: {
            company_name: 'Northgate Dental',
            industry: 'Healthcare',
            domain_public: 'northgatedental.example',
          },
          it_environment: { deliberate_weaknesses: ['unpatched hypervisor'] },
          network: {
            public_ip: '203.0.113.77',
            subnets: [{ name: 'Servers', cidr: '10.20.10.0/24', vlan_id: 10 }],
            assets: [
              { hostname: 'web01', role: 'server', os: 'Ubuntu 22.04' },
              { hostname: 'dc01', role: 'server', os: 'Windows Server 2019' },
              { hostname: 'ws01', role: 'workstation', os: 'Windows 11' },
            ],
          },
          threat_profile: { deliberate_weaknesses: ['reused local admin password'] },
        },
      },
      stakeholders: [
        { name: 'Dana Whitlock', role: 'Owner', email: 'dana@northgatedental.example' },
        { name: 'Ana Ruiz', role: 'Office Manager', email: 'ana.ruiz@northgatedental.example' },
      ],
    },
  },
});

const PROFILE_PUBLIC_IP = '203.0.113.77';

function compile(engagement, spec, profile, options) {
  return PLAN.compileEngagementPlan({
    engagement, spec, profile: profile === undefined ? PROFILE : profile, options,
  });
}
const codes = plan => plan.problems.map(p => p.code);
const codeAt = (plan, code) => plan.problems.filter(p => p.code === code);

/** Every fixture the code-registry and vocabulary sweeps walk. Built once. */
function everyFixturePlan() {
  const full = specFrom(ASSETS);
  const v2 = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const noWeb = specFrom(ASSETS.filter(a => a.hostname !== 'web01'));
  const synthetic = specFrom(ASSETS.filter(a => a.hostname !== 'web01'), {
    vuln_app_install: { target_vm: 'vuln-app' },
  });
  synthetic.vms.push({
    name: 'vuln-app', hostname: 'vuln-app', role: 'server', os: 'Debian 12',
    type: 'qemu', ipOctet: SYNTH.SPEC_OCTET_MIN + 2, services: ['80/HTTP'], synthetic: true,
  });

  return [
    compile({ engagement_type: 'default' }, v2),
    compile({ engagement_type: 'default', subnet_scheme: 'v2' }, full),
    compile({ engagement_type: 'internal_credentialed', perspective: 'internal', credential_posture: 'credentialed' }, v2),
    compile({ engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' }, full),
    compile({ engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' }, synthetic),
    compile({ engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' }, noWeb),
    compile({
      engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3',
      exposure_plan: [{ vm_name: 'web01', placement: 'pivot' }, { vm_name: 'dc01', placement: 'pivot' }],
    }, full),
    compile({
      engagement_type: 'default',
      scope_in: [{ kind: 'role', value: 'server' }, { kind: 'vm', value: 'ghost01' }],
      scope_out: [{ kind: 'cidr', value: '10.20.10.0/24' }, { kind: 'url', value: 'https://portal.example' }],
    }, v2),
    compile({ engagement_type: 'default' }, { vms: [] }, null),
    compile({ engagement_type: 'default' }, v2, { nothing: 'recognisable' }),
    compile({ engagement_type: 'default' }, v2, [{ id: 'r1', json_data: { student_view: { raw: { threats: { organization: { company_name: 'Bay Clinic' }, network: { total_assets: 14 } } } } } }]),
  ];
}

// ════════════════════════════════════════════════════════════════════════════
// §1 — PURITY IS THE CONTRACT
// ════════════════════════════════════════════════════════════════════════════

test('B0-1: engagement-model.js contains zero require calls', () => {
  const src = read(MODEL_REL);
  const hits = (src.match(/require\(/g) || []).length;
  assert.strictEqual(hits, 0,
    `${MODEL_REL} must import NOTHING — not ./db, not a src/utils path, not pg. It is loaded from `
    + 'engagement-provision.js, which test/ciab-engagement-provision.test.js requires on a stubbed '
    + 'module cache, and B1 will load it from routes/profile-deploy.js, which '
    + 'test/ciab-reservation.test.js:599,627 requires on a cache whose clinic_db handle throws on any '
    + `query (:225-229). One transitive import fails those suites naming the wrong file. ${TRACK_B} (B0)`);
});

test('B0-2: engagement-plan.js imports exactly five modules, and they are the agreed five', () => {
  const code = jsCode(read(PLAN_REL));
  const specs = [...code.matchAll(/require\(\s*'([^']+)'\s*\)/g)].map(m => m[1]);
  assert.deepStrictEqual(specs.slice().sort(), [
    '../../../../../src/utils/ipv4',
    '../ai/scan-documents/service-inference',
    './engagement-model',
    './profile-to-spec',
    'node:crypto',
  ].sort(),
    `${PLAN_REL}'s dependency list is a contract, not a habit. src/utils/lane-networking.js and `
    + 'src/utils/challenge-lane-deployer.js reach site-config.js:29-30, which does an unguarded '
    + 'fs.readFileSync of config/site.json — ABSENT from this checkout — so importing either turns '
    + `every stubbed-cache test into an ENOENT that names the wrong file. ${TRACK_B} (B0)`);
  assert.strictEqual((code.match(/require\(/g) || []).length, 5,
    `${PLAN_REL} must contain exactly five require calls. ${TRACK_B} (B0)`);
});

test('B0-3: both modules load with no stubs at all', () => {
  // A stronger check than test/ciab-deploy-parity.test.js:158-185, which
  // pre-stubs site-config BEFORE its bare require and therefore cannot detect
  // the impurity it is trying to forbid. Here the requires at module scope ran
  // against an untouched cache, so reaching this line at all is the assertion.
  assert.strictEqual(fs.existsSync(abs('config/site.json')), false,
    'This check is only meaningful while config/site.json is genuinely absent — only '
    + 'config/example-site.json is committed. If someone adds the real file, an impure import would '
    + `start passing here and fail in CI instead. ${TRACK_B} (B0)`);
  assert.ok(SITE_CONFIG_UNTOUCHED_BY_MODEL,
    `${MODEL_REL} must pull NOTHING into require.cache — it has zero requires. ${TRACK_B} (B0)`);
  assert.strictEqual(typeof MODEL.validateEngagementPlan, 'function',
    `engagement-model.js must load bare. ${TRACK_B} (B0)`);
  assert.strictEqual(typeof PLAN.compileEngagementPlan, 'function',
    'engagement-plan.js must load bare. It DOES reach src/utils/site-config.js transitively, through '
    + 'profile-to-spec.js -> vm-template-resolver.js, and that is tolerable for exactly one reason: the '
    + 'fs.readFileSync at site-config.js:29-30 is LAZY, inside getDefaultTemplateNode(), and nothing on '
    + 'the compile path resolves a template. No fixture in this file may change that — see the fixture '
    + `note above. ${TRACK_B} (B0)`);
});

test('B0-4: neither new module requires the plugin database handle', () => {
  for (const rel of [MODEL_REL, PLAN_REL]) {
    assert.ok(!/require\(\s*['"]\.\/db['"]\s*\)/.test(read(rel)),
      `${rel} must never require ./db. test/ciab-reservation.test.js:225-229 stubs CiAB's utils/db.js `
      + `as a poison pill that throws on any query. ${TRACK_B} (B0)`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §2 — MIGRATION HYGIENE
// Every statement must be natively re-runnable, because the runner sends one
// file per pool.query() and swallows the failure.
// ════════════════════════════════════════════════════════════════════════════

test('B0-5: every ADD COLUMN in the model migration is IF NOT EXISTS', () => {
  const code = sqlCode(read(MIG_MODEL));
  const all = (code.match(/ADD COLUMN/gi) || []).length;
  const guarded = (code.match(/ADD COLUMN IF NOT EXISTS/gi) || []).length;
  assert.strictEqual(all, guarded,
    `${MIG_MODEL} re-runs on EVERY boot. An unguarded ADD COLUMN raises 42701 on boot #2, and `
    + 'src/plugin-loader.js:134-147 sends the whole file as ONE pool.query() — so that one statement '
    + `reverts every other column in the file, silently, forever. ${TRACK_B} (B0)`);
});

test('B0-6: the model migration carries only ADD COLUMN and CREATE INDEX', () => {
  const code = sqlCode(read(MIG_MODEL));
  const offenders = [];
  if (/ADD\s+CONSTRAINT/i.test(code)) offenders.push('ADD CONSTRAINT');
  if (/DO\s+\$/i.test(code)) offenders.push('DO $');
  if (/\bDROP\b/i.test(code)) offenders.push('DROP');
  if (/\bUPDATE\b/i.test(code)) offenders.push('UPDATE');
  if (/\bINSERT\b/i.test(code)) offenders.push('INSERT');
  assert.deepStrictEqual(offenders, [],
    `${MIG_MODEL} holds the columns B1-B6 actually need, so a partial application of it must be `
    + 'STRUCTURALLY impossible. Constraints live in 012 and 013 precisely because Postgres has no '
    + `ADD CONSTRAINT IF NOT EXISTS and those files carry residual risk. ${TRACK_B} (B0)`);
});

test('B0-7: no B0 migration drops a constraint', () => {
  for (const rel of B0_MIGRATIONS) {
    assert.ok(!/DROP\s+CONSTRAINT/i.test(sqlCode(read(rel))),
      `${rel} must not DROP CONSTRAINT. front-end/migrations/005_policy_documents.sql:8-13 and `
      + '021_subnet_scheme_v3.sql:19-30 use drop-then-add, but that directory has NO RUNNER '
      + '(src/server.js:623-626) and is hand-applied once. Here it would re-validate the table under '
      + `ACCESS EXCLUSIVE on every restart and the first violating row would revert the file. ${TRACK_B} (B0)`);
  }
});

test('B0-8: every ADD CONSTRAINT is guarded by its own name in the same file', () => {
  for (const rel of [MIG_GUARDS, MIG_SECRET]) {
    const code = sqlCode(read(rel));
    const names = [...code.matchAll(/ADD\s+CONSTRAINT\s+(\w+)/gi)].map(m => m[1]);
    assert.ok(names.length > 0, `${rel} should add at least one constraint. ${TRACK_B} (B0)`);
    const unguarded = names.filter(n => !code.includes(`conname = '${n}'`));
    assert.deepStrictEqual(unguarded, [],
      `${rel} must check pg_constraint for each constraint NAME first — the 002_real_client_intake.sql:43-51 `
      + 'idiom — so the validating table scan happens exactly once and every later boot is a single '
      + `catalog lookup. ${TRACK_B} (B0)`);
  }
});

test('B0-9: no CiAB migration ever constrains engagement_type', () => {
  const dir = abs(MIG_DIR);
  const offenders = fs.readdirSync(dir)
    .filter(f => f.endsWith('.sql'))
    .filter(f => /CHECK\s*\(\s*engagement_type/i.test(sqlCode(fs.readFileSync(path.join(dir, f), 'utf8'))));
  assert.deepStrictEqual(offenders, [],
    "'default' is the only engagement_type any production writer emits "
    + '(public/js/admin-profile-lanes.js:411 posts it literally), 009\'s DEFAULT backfilled every '
    + 'pre-existing group to it, and lane-reservation.js\'s legacy-key fallbacks at :266 and :434 are '
    + 'keyed on it. sanitizeEngagementType (lane-reservation.js:108-111) DELETES disallowed characters '
    + 'rather than rejecting, so off-vocabulary slugs reach the INSERT today. A CHECK would fail '
    + `validation against live rows and silently revert its whole file on every boot. ${TRACK_B} (B0)`);
});

test('B0-10: retirement is a timestamp, never a lifecycle enum', () => {
  const dir = abs(MIG_DIR);
  const offenders = fs.readdirSync(dir)
    .filter(f => f.endsWith('.sql'))
    .filter(f => /lifecycle_status/.test(fs.readFileSync(path.join(dir, f), 'utf8')));
  assert.deepStrictEqual(offenders, [],
    'A four-value CHECK would need DROP CONSTRAINT the first time a fifth state is wanted, inside a '
    + 'directory that re-runs every boot as one implicit transaction. A nullable retired_at can never '
    + `need constraint surgery. ${TRACK_B} (B0)`);
  assert.ok(/ADD COLUMN IF NOT EXISTS\s+retired_at\s+TIMESTAMPTZ/i.test(read(MIG_MODEL)),
    `${MIG_MODEL} must add retired_at as a nullable TIMESTAMPTZ. ${TRACK_B} (B0)`);
});

test('B0-11: readiness still does not live on the engagement row', () => {
  for (const rel of B0_MIGRATIONS.concat([MIG_010])) {
    const code = sqlCode(read(rel));
    assert.ok(!/bridges_ready|bridge_report/.test(code),
      `${rel} must not persist bridge readiness. It is a LIVE cluster fact answered by `
      + 'verifyBridgesOnAllNodes at read time; a stored copy is a cache with no invalidation, and 010 '
      + `already carries the note that says so. ${TRACK_B} (B0)`);
  }
});

test('B0-12: a CiAB migration reaches clinic_db only', () => {
  const FOREIGN = ['crucible_challenge', 'cybercore_lane', 'cybercore_user',
    'cybercore_lane_flag', 'cybercore_lab_readiness'];
  for (const rel of B0_MIGRATIONS) {
    const code = sqlCode(read(rel));
    const hits = FOREIGN.filter(t => new RegExp(t).test(code));
    assert.deepStrictEqual(hits, [],
      `${rel} runs against clinic_db ONLY. Every column it adds is a CiAB-owned fact. A cybercore_db `
      + 'object named here does not exist in that database at all, so the statement raises and takes '
      + `every other statement in the file with it. ${TRACK_B} (B0)`);
  }
});

test('B0-13: nothing is published at the perimeter, so no migration mentions a wan port', () => {
  // Track B4 is CUT. The environment stays internal to the lane: the external
  // exercise is the attack box on ext reaching a DUAL-HOMED host on ext as an L2
  // neighbour (lane-networking.js:379 dual-homes a v3 role 'dmz' VM;
  // challenge-lane-deployer.js:758-772 pins it to .240 on both segments and says
  // no gateway re-bake is needed). There is no DNAT, so the reserved-port rule
  // of the earlier draft has no subject at all — and a dead vocabulary in the
  // schema would read to a later phase as permission to build the DNAT path.
  for (const rel of B0_MIGRATIONS) {
    const code = sqlCode(read(rel));
    const offenders = [];
    if (/wan_port/i.test(code)) offenders.push('wan_port');
    if (/publish_plan/i.test(code)) offenders.push('publish_plan');
    if (/3389/.test(code)) offenders.push('3389');
    assert.deepStrictEqual(offenders, [],
      `${rel} must carry no published-port vocabulary: the column is exposure_plan and it records `
      + `PLACEMENT, not publishing. ${TRACK_B} (B0)`);
  }
  const guards = sqlCode(read(MIG_GUARDS));
  assert.ok(/jsonb_typeof\(exposure_plan\)\s*=\s*'array'/.test(guards),
    `${MIG_GUARDS}'s shape CHECK must name exposure_plan, so a scalar where a list belongs is refused `
    + `at write time rather than raising 22023 at read time inside a route. ${TRACK_B} (B0)`);
});

test('B0-14: the B0 migrations sort after 010 and none collides with another B0 file', () => {
  // The runner is readdirSync().filter('.sql').sort() (src/plugin-loader.js:134-147),
  // so ordering is by FULL FILENAME, not by numeric prefix.
  //
  // WHY THE DUPLICATE-PREFIX HALF IS SCOPED TO B0'S OWN FILES. Track D's
  // untracked modules migration shared the 011 prefix for a while and has since
  // been renumbered to 014_ciab_modules.sql. It was harmless either way —
  // '011_ciab_engagement_model.sql' sorted first, the two files touch disjoint
  // tables (ciab_engagement vs ciab_module) and neither depends on the other —
  // and this assertion deliberately does not police a directory whose other
  // occupants are not B0's to renumber.
  const names = B0_MIGRATIONS.map(rel => path.basename(rel));
  for (const name of names) {
    assert.ok(name > '010_ciab_engagements.sql',
      `${name} must sort after 010, or it would add columns to a table that does not exist yet. ${TRACK_B} (B0)`);
  }
  const prefixes = names.map(n => n.slice(0, 3));
  assert.strictEqual(new Set(prefixes).size, prefixes.length,
    `The three B0 migrations must not share a numeric prefix with each other. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §3 — EVERY COLUMN SURVIVES THE READ PROJECTION
// ════════════════════════════════════════════════════════════════════════════

test('B0-15: rowToEngagement projects every column the model migration adds', () => {
  // THE HIGHEST-VALUE ASSERTION IN THIS FILE, and it is derived from the
  // migration TEXT so a column added later without a matching projection fails
  // here rather than in a demo.
  const declared = [...read(MIG_MODEL).matchAll(/ADD COLUMN IF NOT EXISTS\s+(\w+)/g)].map(m => m[1]);
  assert.ok(declared.length >= 15, `Expected the model migration to add columns. ${TRACK_B} (B0)`);

  const row = {
    engagement_id: 'e-1', profile_id: 'p-1', engagement_type: 'default',
    subnet_scheme: 'v2', max_students: 4, challenge_id: 7, challenge_key: 'k',
    provision_status: 'ready', provision_error: null, provisioned_at: null,
    created_at: 'then', updated_at: 'now',
  };
  for (const col of declared) {
    if (col === 'perspective') row[col] = 'internal';
    else if (col === 'credential_posture') row[col] = 'none';
    else if (col === 'synthesis_meta') row[col] = {};
    else if (col === 'brief' || col === 'display_name') row[col] = 'sentinel';
    else if (col === 'retired_at') row[col] = null;
    else if (col === 'updated_by') row[col] = 'u-1';
    else row[col] = [];
  }

  const projected = Object.keys(PROVISION.rowToEngagement(row));
  const missing = declared.filter(c => !projected.includes(c));
  assert.deepStrictEqual(missing, [],
    'getEngagement (:98), getEngagementById (:105) and listEngagements (:111) all SELECT *, so the '
    + 'database really does return these columns — rowToEngagement is a hand-written whitelist that '
    + 'silently drops anything not listed (it already drops provision_started_at and created_by). The '
    + 'Engagements tab would show empty fields against a table that holds the data, and it would look '
    + `like a database problem. ${TRACK_B} (B0)`);

  // MODEL_FIELDS is the SET-clause column list updateEngagementModel builds its
  // UPDATE from, so a name here with no column raises 42703 on the first PATCH,
  // and a column added to the migration without a matching entry is simply never
  // written. Keep the two in lockstep. retired_at and updated_by are absent on
  // purpose: retirement is its own action with its own confirmation, and
  // updated_by is stamped by the writer rather than patched.
  const phantom = MODEL.MODEL_FIELDS.filter(f => !declared.includes(f));
  assert.deepStrictEqual(phantom, [],
    `Every MODEL_FIELDS entry must be a column ${MIG_MODEL} actually adds. ${TRACK_B} (B0)`);
  const unwritable = declared.filter(c => !MODEL.MODEL_FIELDS.includes(c));
  assert.deepStrictEqual(unwritable, ['retired_at', 'updated_by'],
    'Only those two columns may be readable-but-not-patchable. Anything else missing from MODEL_FIELDS '
    + `is a column the model writer could never set. ${TRACK_B} (B0)`);
  const notAuthorable = MODEL.AUTHORABLE_FIELDS.filter(f => !MODEL.MODEL_FIELDS.includes(f));
  assert.deepStrictEqual(notAuthorable, [],
    `A human-editable field that is not a model column could never be saved. ${TRACK_B} (B0)`);
});

test('B0-16: engagementModelFromRow returns every model field for a bare adopted row', () => {
  const model = MODEL.engagementModelFromRow({});
  const missing = MODEL.MODEL_FIELDS.filter(f => !Object.prototype.hasOwnProperty.call(model, f));
  assert.deepStrictEqual(missing, [],
    'adoptExistingReservation INSERTs rows on the READ path with a fixed 8-column list '
    + '(engagement-provision.js:131-159) and will never supply a model column, so every such row must '
    + `read back as a valid EMPTY model rather than a bag of undefineds. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(model.scope_in, [], `An unauthored list column reads as []. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(model.synthesis_meta, {}, `synthesis_meta reads as {}. ${TRACK_B} (B0)`);
  assert.strictEqual(model.perspective, 'internal',
    `The column DEFAULT is what every existing row already has. ${TRACK_B} (B0)`);
  assert.strictEqual(model.brief, null, `An unauthored brief is null, not ''. ${TRACK_B} (B0)`);
});

test('B0-17: engagementModelFromRow parses a jsonb column delivered as a string', () => {
  const model = MODEL.engagementModelFromRow({
    scope_in: '[{"kind":"vm","value":"web01","note":null}]',
    synthesis_meta: '{"source":"compile"}',
    objectives: 'not json at all',
  });
  assert.deepStrictEqual(model.scope_in, [{ kind: 'vm', value: 'web01', note: null }],
    `pg returns jsonb already parsed; the parse is belt and braces for a fixture, a CSV import or a `
    + `future driver change, and it must never throw. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(model.synthesis_meta, { source: 'compile' }, `${TRACK_B} (B0)`);
  assert.deepStrictEqual(model.objectives, [],
    `A malformed column is a data problem, not a crash — it falls back to its DEFAULT. ${TRACK_B} (B0)`);
});

test('B0-18: a read-path adopt still cannot clobber an authored model', () => {
  const code = jsCode(read(PROVISION_REL));
  const m = code.match(/ON CONFLICT \(profile_id, engagement_type\) DO UPDATE([\s\S]*?)RETURNING/);
  assert.ok(m, `adoptExistingReservation's ON CONFLICT DO UPDATE must still exist. ${TRACK_B} (B0)`);
  const setClause = m[1];
  const assigned = [...setClause.matchAll(/(\w+)\s*=\s*EXCLUDED|(\w+)\s*=\s*now\(\)/g)]
    .map(x => x[1] || x[2]).sort();
  assert.deepStrictEqual(assigned, ['challenge_id', 'challenge_key', 'updated_at'],
    'GET /profiles/:profileId/engagements has a WRITE side effect (routes/profile-deploy.js:678-681 -> '
    + 'resolveEngagement -> adoptExistingReservation), so merely OPENING the tab runs this UPSERT. If '
    + 'it ever set a model column, opening the screen would silently blank an instructor\'s scope. '
    + `${TRACK_B} (B0)`);
});

test('B0-19: the writer adds no untyped NULL test and no cross-database query', () => {
  const src = read(PROVISION_REL);
  assert.ok(!/\$\d+\s+IS\s+(?:NOT\s+)?NULL/i.test(src),
    'Postgres fixes a parameter type at its FIRST reference, so an uncast $n IS NULL is a real parse '
    + `failure, not a style rule — test/sql-param-typing.test.js:35-62 scans for it. ${TRACK_B} (B0)`);
  assert.ok(!/cybercore_lane/.test(src),
    'A CiAB util must not query cybercore_db. test/lane-claims.test.js only inspects files that mention '
    + `cybercore_lane, and adding one here pulls this file into that scanner's set. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §4 — THE VOCABULARY IS A REGISTRY, NOT AN ALLOWLIST
// ════════════════════════════════════════════════════════════════════════════

test('B0-20: every registry key is a fixed point of the slug sanitizer', () => {
  // Stated positively — /^[a-z0-9_-]{1,32}$/ is exactly sanitizeEngagementType's
  // OUTPUT alphabet (lane-reservation.js:108-111) — so this holds WITHOUT
  // requiring lane-reservation.js, which pulls pg and proxmox.
  const bad = Object.keys(MODEL.ENGAGEMENT_TYPES).filter(k => !/^[a-z0-9_-]{1,32}$/.test(k));
  assert.deepStrictEqual(bad, [],
    'A registry key that the sanitizer would rewrite could never be matched by a stored slug, because '
    + `createEngagement sanitizes before it INSERTs. ${TRACK_B} (B0)`);
});

test('B0-21: the two named engagement types declare a legal posture', () => {
  for (const key of ['internal_credentialed', 'external_blackbox', 'default']) {
    const d = MODEL.describeEngagementType(key);
    assert.strictEqual(d.known, true, `'${key}' must be in the registry. ${TRACK_B} (B0)`);
    assert.ok(MODEL.PERSPECTIVES.includes(d.perspective),
      `'${key}' declares a perspective outside the column CHECK. ${TRACK_B} (B0)`);
    assert.ok(MODEL.CREDENTIAL_POSTURES.includes(d.credential_posture),
      `'${key}' declares a credential posture outside the column CHECK. ${TRACK_B} (B0)`);
  }
  assert.strictEqual(MODEL.describeEngagementType('external_blackbox').perspective, 'external', `${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.describeEngagementType('internal_credentialed').credential_posture, 'credentialed', `${TRACK_B} (B0)`);
});

test("B0-22: 'default' is load-bearing and may never be removed", () => {
  assert.ok(Object.prototype.hasOwnProperty.call(MODEL.ENGAGEMENT_TYPES, 'default'),
    "Removing 'default' strands every row 009's DEFAULT backfilled, the Reserve-network button "
    + '(admin-profile-lanes.js:411 posts engagement_type "default" literally), and the two legacy-key '
    + 'fallbacks at lane-reservation.js:266,434. A stranded client then gets a SECOND VXLAN block '
    + `carved — permanently, because the allocator only ever climbs and never re-uses. ${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.DEFAULT_TYPE_KEY, 'default', `${TRACK_B} (B0)`);
});

test('B0-23: describeEngagementType is total', () => {
  for (const slug of ['droptable--', 'externalblackbox', '-']) {
    const d = MODEL.describeEngagementType(slug);
    assert.strictEqual(d.known, false, `'${slug}' is not a registry key. ${TRACK_B} (B0)`);
    assert.strictEqual(d.perspective, 'internal',
      `An unknown slug takes the conservative posture every row in the table has today. ${TRACK_B} (B0)`);
    assert.strictEqual(d.credential_posture, 'none', `${TRACK_B} (B0)`);
    assert.ok(typeof d.label === 'string' && d.label.length > 0, `${TRACK_B} (B0)`);
  }
  for (const empty of [null, undefined, '']) {
    assert.strictEqual(MODEL.describeEngagementType(empty).key, 'default',
      `Null/empty must give the default descriptor rather than throwing: createEngagement accepts any `
      + `slug today and a rejection here becomes a 500 the route has no handler for. ${TRACK_B} (B0)`);
    assert.strictEqual(MODEL.describeEngagementType(empty).known, true, `${TRACK_B} (B0)`);
  }
});

test('B0-24: a display alias never rewrites the stored slug', () => {
  assert.strictEqual(MODEL.resolveEngagementTypeAlias('externalblackbox'), 'external_blackbox',
    `The alias map exists so a mangled slug still READS properly. ${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.describeEngagementType('externalblackbox').key, 'externalblackbox',
    'The slug is baked into the reservation key ciab-profile-<id8>-<slug> (lane-reservation.js:113-117), '
    + `so rewriting it would orphan a carved block that nothing can ever name again. ${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.engagementDisplayName({ engagement_type: 'externalblackbox' }),
    MODEL.ENGAGEMENT_TYPES.external_blackbox.label, `${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.engagementDisplayName({ engagement_type: 'default', display_name: 'Spring pilot' }),
    'Spring pilot', `A stored display_name always wins. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §5 — INSTRUCTOR VOCABULARY
// Section / Module / Client / Engagement / Environment. 'module' is IN the
// target vocabulary and is not banned; 'student' is not banned, because a
// student reads the brief.
// ════════════════════════════════════════════════════════════════════════════

const BANNED_WORDS = /\b(course|material|challenge)\b/i;

test('B0-25: no label, summary or rendered brief uses a banned word', () => {
  const offenders = [];
  for (const [key, entry] of Object.entries(MODEL.ENGAGEMENT_TYPES)) {
    if (BANNED_WORDS.test(entry.label)) offenders.push(`ENGAGEMENT_TYPES.${key}.label`);
    if (BANNED_WORDS.test(entry.summary)) offenders.push(`ENGAGEMENT_TYPES.${key}.summary`);
  }
  for (const slug of ['default', 'external_blackbox', 'internal_credentialed', 'droptable--']) {
    const name = MODEL.engagementDisplayName({ engagement_type: slug });
    if (BANNED_WORDS.test(name)) offenders.push(`engagementDisplayName('${slug}')`);
  }
  for (const plan of everyFixturePlan()) {
    const text = plan.brief.suggested_text;
    if (text && BANNED_WORDS.test(text)) {
      offenders.push(`brief for ${plan.engagement.engagement_type}/${plan.engagement.perspective}`);
    }
  }
  assert.deepStrictEqual(offenders, [],
    'Instructor-facing copy uses Section / Module / Client / Engagement / Environment. The neighbouring '
    + `plugin's words leak in through copied prose and are hard to unpick once shipped. ${TRACK_B} (B0)`);
});

test('B0-26: no problem message uses a banned word', () => {
  // MESSAGES only. A problem's `ref` is a file path — 'challenge-lane-deployer.js'
  // matches \bchallenge\b because the hyphen is a word boundary — and a citation
  // is not instructor-facing copy. Keeping the file:line in `ref` and out of
  // `message` is what lets the reason travel with a failure without importing a
  // word from outside the vocabulary.
  const offenders = [];
  for (const plan of everyFixturePlan()) {
    for (const p of plan.problems) {
      if (BANNED_WORDS.test(p.message)) offenders.push(`${p.code}: ${p.message.slice(0, 80)}`);
    }
  }
  const reports = [
    MODEL.validateExposurePlan([{ vm_name: 'a', placement: 'pivot' }, { vm_name: 'b', placement: 'pivot' }]),
    MODEL.validateIssuedCredentials([{ slot_key: 'k', username: 'u', password: 'x' }]),
    MODEL.validateScopeRules([{ kind: 'nonsense', value: 'x' }]),
    MODEL.validateObjectives([{ title: 'x', maps_to: { kind: 'flag' } }]),
    MODEL.validateAllowedTechniques([{}]),
  ];
  for (const r of reports) {
    for (const p of r.errors.concat(r.warnings)) {
      if (BANNED_WORDS.test(p.message)) offenders.push(`${p.code}: ${p.message.slice(0, 80)}`);
    }
  }
  assert.deepStrictEqual(offenders, [], `${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §6 — NEVER A SECRET, AND NEVER AN UNQUOTABLE PATH
// ════════════════════════════════════════════════════════════════════════════

test('B0-27: a secret-named key is reported AND stripped from the stored value', () => {
  const r = MODEL.validateIssuedCredentials([
    { slot_key: 'da', username: 'svc_backup', target_vm: 'dc01', password: 'x' },
  ]);
  const hit = r.errors.find(e => e.code === 'CREDENTIAL_SECRET_FIELD');
  assert.ok(hit, `A password field must be an error. ${TRACK_B} (B0)`);
  assert.strictEqual(hit.path, 'issued_credentials[0].password',
    `The report names WHICH field to remove. ${TRACK_B} (B0)`);
  assert.strictEqual(r.value.length, 1,
    'The entry SURVIVES, stripped: losing an entire account intent because a form helpfully posted an '
    + `empty password field is the worse failure, and the key is gone either way. ${TRACK_B} (B0)`);
  assert.ok(!Object.prototype.hasOwnProperty.call(r.value[0], 'password'),
    'The normalizer builds each entry from a WHITELIST, so an unrecognised key is never copied through '
    + `— stripped, not merely flagged. ${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.containsSecret(r.value), false, `${TRACK_B} (B0)`);
});

test('B0-28: every spelling of a secret is caught, including an empty one', () => {
  for (const key of ['passphrase', 'api_token', 'guac_password', 'password_hash']) {
    const r = MODEL.validateIssuedCredentials([{ slot_key: 'a', username: 'u', [key]: 'v' }]);
    assert.ok(r.errors.some(e => e.code === 'CREDENTIAL_SECRET_FIELD' && e.path.endsWith(key)),
      `'${key}' must trip SECRET_KEY_PATTERN. The pattern is structural rather than a literal blocklist `
      + `precisely so a trailing _hash or a vendor prefix cannot defeat it. ${TRACK_B} (B0)`);
    assert.ok(!Object.prototype.hasOwnProperty.call(r.value[0], key), `${TRACK_B} (B0)`);
  }
  const empty = MODEL.validateIssuedCredentials([{ slot_key: 'a', username: 'u', password: '' }]);
  assert.ok(empty.errors.some(e => e.code === 'CREDENTIAL_SECRET_FIELD'),
    "It is the key's PRESENCE that is refused, never its value, so a form posting password:'' is "
    + `rejected rather than silently accepted and filled in later. ${TRACK_B} (B0)`);
  const nested = MODEL.validateIssuedCredentials([
    { slot_key: 'a', username: 'u', delivery: { target: 'console', api_key: null } },
  ]);
  assert.ok(nested.errors.some(e => e.code === 'CREDENTIAL_SECRET_FIELD'),
    `The walk is deep — a secret nested under delivery is the same defect. ${TRACK_B} (B0)`);
});

test('B0-29: the legitimate structural fields do not trip the secret pattern', () => {
  const r = MODEL.validateIssuedCredentials([{
    slot_key: 'svc.acct-1', username: 'svc_backup', account_kind: 'domain',
    privilege: 'domain admin', source: 'template',
    delivery: { target: 'vm', vm_name: 'dc01', dir: '/opt/engagement', filename: 'creds.txt', mode: '600' },
    note: 'The client says the password policy is weak; that is a finding, not a field.',
  }]);
  assert.deepStrictEqual(r.errors, [],
    "slot_key is the handle the per-lane secret is minted AGAINST, never the secret. account_kind, "
    + `delivery and privilege carry no secret either, and a NOTE about a password is prose. ${TRACK_B} (B0)`);
  assert.strictEqual(r.value[0].slot_key, 'svc.acct-1', `${TRACK_B} (B0)`);
  assert.strictEqual(r.value[0].delivery.vm_name, 'dc01', `${TRACK_B} (B0)`);
});

test('B0-30: a delivery path that could not survive a command line is refused', () => {
  const HAZARDS = [
    '/opt/eng & rm -rf /', '/opt/a;b', '/opt/a|b', '/opt/a$b', "/opt/a'b",
    '/opt/a"b', '/opt/a`b', '/opt/a\nb', '/opt/../etc', 'opt/relative', '/opt/trailing/',
  ];
  const accepted = HAZARDS.filter(d => MODEL.isDeliveryDir(d));
  assert.deepStrictEqual(accepted, [],
    'B3 lands the credential file with a single agentShellExec, so the path goes onto a command line '
    + 'where script_args is interpolated UNQUOTED (script-executor.js:249 for PowerShell, :624 for sh) '
    + "and a single '&' backgrounds the command. That is the same reason password-generator.js:13's "
    + "SYMBOLS = '!@#$%&*' makes a minted password unusable as a script argument, and the same reason "
    + `the secret must travel as a FILE. ${TRACK_B} (B0)`);
  for (const name of ['a/b', 'a\\b', '../x', 'a b', '']) {
    assert.strictEqual(MODEL.isDeliveryFilename(name), false,
      `'${name}' must be refused: rejecting EVERY separator is what makes dir + '/' + filename `
      + `structurally unable to escape dir. ${TRACK_B} (B0)`);
  }
});

test('B0-31: the ordinary delivery path is accepted', () => {
  assert.strictEqual(MODEL.isDeliveryDir('/opt/engagement'), true, `${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.isDeliveryFilename('credentials.txt'), true, `${TRACK_B} (B0)`);
});

test('B0-32: a compiled plan carries no secret-shaped key anywhere in its tree', () => {
  const offenders = [];
  const walk = (value, prefix, seen) => {
    if (!value || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      value.forEach((item, i) => walk(item, `${prefix}[${i}]`, seen));
      return;
    }
    for (const key of Object.keys(value)) {
      const p = prefix ? `${prefix}.${key}` : key;
      if (MODEL.SECRET_KEY_PATTERN.test(key)) offenders.push(p);
      else walk(value[key], p, seen);
    }
  };
  for (const plan of everyFixturePlan()) walk(plan, '', new Set());
  assert.deepStrictEqual(offenders, [],
    'The compile is a paper artefact that B1 renders, B2 writes back and Track C reads. A secret-named '
    + `key on it is a secret in a document, whatever it holds. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §7 — EXPOSURE: PLACEMENT, NOT PUBLISHING
//
// Nothing is published at the perimeter, ever. The environment stays internal to
// the lane, and what an engagement declares is which SEGMENT each machine is
// homed on:
//   'pivot'    role 'dmz' / explicit two-NIC — dual-homed ext+int, pinned .240
//   'public'   single-homed ext (already the v3 default for an ordinary VM)
//   'internal' single-homed int; needs an explicit nics array
// EXACTLY ONE PIVOT PER LANE, because challenge-lane-deployer.js:758-772 defines
// exactly one dual-homed address. That is a teaching constraint, not a
// limitation: extra EXPOSED hosts are free, and they are what makes "which host
// is the bridge?" a real question rather than a host count of one.
// ════════════════════════════════════════════════════════════════════════════

test('B0-33: the validator refuses a second pivot and keeps the first', () => {
  const r = MODEL.validateExposurePlan([
    { vm_name: 'web01', placement: 'pivot' },
    { vm_name: 'dc01', placement: 'pivot' },
  ], { knownVmNames: ['web01', 'dc01'], subnetScheme: 'v3' });
  assert.deepStrictEqual(r.errors.map(e => e.code), ['EXPOSURE_MULTIPLE_PIVOTS'],
    'The deployer pins exactly ONE dual-homed machine to .240 on both segments '
    + `(challenge-lane-deployer.js:766-770), so a second pivot has nowhere to land. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(r.value.map(v => v.vm_name), ['web01'],
    `The offending entry is DROPPED, so value is always safe to persist. ${TRACK_B} (B0)`);
  assert.ok(/\.240/.test(r.errors[0].message),
    `The reason must travel with the failure, not live only in a migration comment. ${TRACK_B} (B0)`);
});

test('B0-34: the compile refuses a stored plan with two pivots', () => {
  const plan = compile({
    engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3',
    exposure_plan: [{ vm_name: 'web01', placement: 'pivot' }, { vm_name: 'dc01', placement: 'pivot' }],
  }, specFrom(ASSETS));
  const hit = codeAt(plan, 'EXPOSURE_MULTIPLE_PIVOTS');
  assert.strictEqual(hit.length, 1,
    `Belt and braces: a row can be written by SQL, and no CHECK can count matching JSONB array `
    + `elements (jsonb_array_elements is set-returning and a CHECK may not contain a subquery). ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'error', `${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), true, `${TRACK_B} (B0)`);
});

test('B0-35: a pivot that is also the student console is caught offline', () => {
  const spec = specFrom(ASSETS);
  spec.vms[2].console_role = 'primary';           // ws01 is the console
  const plan = compile({
    engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3',
    exposure_plan: [{ vm_name: 'ws01', placement: 'pivot' }],
  }, spec);
  const hit = codeAt(plan, 'EXPOSURE_PIVOT_IS_CONSOLE');
  assert.strictEqual(hit.length, 1,
    "challenge-lane-deployer.js:729-735 THROWS \"'<vm>' is dual-homed and cannot be the student "
    + 'console\" — a dual-homed machine builds its NICs inline and ignores the console pin, so it comes '
    + `up with no reservation and a dead console. Catching it here costs nothing; catching it there `
    + `costs a deploy. ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'error', `${TRACK_B} (B0)`);
});

test('B0-36: an external engagement with nothing bridging the segments is an error', () => {
  const plan = compile({
    engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3',
    exposure_plan: [{ vm_name: 'web01', placement: 'public' }],
  }, specFrom(ASSETS));
  const hit = codeAt(plan, 'EXTERNAL_NO_PIVOT');
  assert.strictEqual(hit.length, 1,
    'The external exercise is: exploit the exposed host, then pivot to the internal segment. With no '
    + `dual-homed machine the tester owns the site and finds it leads nowhere. ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'error', `${TRACK_B} (B0)`);
});

test('B0-37: a placement on a flat v1/v2 lane is a warning, not an error', () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const plan = compile({
    engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v2',
    exposure_plan: [{ vm_name: 'web01', placement: 'pivot' }],
  }, spec);
  const hit = codeAt(plan, 'PLACEMENT_REQUIRES_V3');
  assert.strictEqual(hit.length, 1,
    'resolveVmSegments returns one flat lan0 for every VM on a v1/v2 lane (lane-networking.js:381), so '
    + `there is no ext/int boundary for a pivot to straddle and the placement is a fiction. ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'warn',
    'A WARNING and not an error: the model can be authored before the environment scheme is settled, '
    + `and B1 can offer to reserve at v3 instead. ${TRACK_B} (B0)`);

  const r = MODEL.validateExposurePlan([{ vm_name: 'web01', placement: 'internal' }], { subnetScheme: 'v2' });
  assert.deepStrictEqual(r.warnings.map(w => w.code), ['EXPOSURE_REQUIRES_V3'], `${TRACK_B} (B0)`);
  assert.deepStrictEqual(r.errors, [], `The entry is still stored. ${TRACK_B} (B0)`);
});

test('B0-38: an unauthored external engagement derives one pivot and no publishing', () => {
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
    specFrom(ASSETS));
  assert.ok(codeAt(plan, 'EXPOSURE_DERIVED').length === 1,
    `The derivation is announced, never silent. ${TRACK_B} (B0)`);
  const placements = plan.exposure.map(e => `${e.vm_name}:${e.placement}`);
  assert.deepStrictEqual(placements, ['web01:pivot', 'dc01:internal', 'ws01:internal'],
    'The exposed host becomes the pivot and every other real machine goes internal, so the whole estate '
    + `still deploys and the exercise is "find the bridge, cross it". ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), false, `${TRACK_B} (B0)`);
  const surface = plan.public_surface;
  assert.deepStrictEqual(Object.keys(surface).sort(),
    ['dns_label', 'placement', 'source', 'target_port', 'target_vm'].sort(),
    'public_surface keeps its three rungs but carries NO wan_port and NO proto — there is no DNAT to '
    + `describe. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §8 — THE THREE REPRESENTATIONS OF ONE FACT, RECONCILED
// ════════════════════════════════════════════════════════════════════════════

test('B0-39: a patch contradicting a KNOWN type names both values', () => {
  const r = MODEL.validateEngagementPlan({ perspective: 'external' },
    { engagementType: 'internal_credentialed' });
  const hit = r.errors.find(e => e.code === 'PERSPECTIVE_CONTRADICTS_TYPE');
  assert.ok(hit, `${TRACK_B} (B0)`);
  assert.ok(/internal_credentialed/.test(hit.message) && /external/.test(hit.message),
    'The same fact is spelled in three places — the slug, the perspective column and the posture '
    + `column — and nothing used to reconcile them. ${TRACK_B} (B0)`);
  assert.strictEqual(r.valid, false, `${TRACK_B} (B0)`);
});

test('B0-40: an unknown slug may declare its own posture', () => {
  const r = MODEL.validateEngagementPlan({ perspective: 'external' },
    { engagementType: 'externalblackbox' });
  assert.strictEqual(r.valid, true,
    "'externalblackbox' is what sanitizeEngagementType makes of 'External Blackbox' — the space is "
    + 'DELETED, not hyphenated — and it reaches the INSERT today. There is nothing for it to '
    + `contradict, so a locally defined type must stay able to declare itself external. ${TRACK_B} (B0)`);
  assert.strictEqual(r.value.perspective, 'external', `${TRACK_B} (B0)`);
});

test('B0-41: an off-vocabulary perspective is a 400, not a 23514', () => {
  const r = MODEL.validateEngagementPlan({ perspective: 'sideways' });
  assert.deepStrictEqual(r.errors.map(e => e.code), ['PERSPECTIVE_UNKNOWN'],
    'THE JS VALIDATOR RUNS FIRST, ALWAYS. A value that reached Postgres would trip '
    + 'ciab_engagement_perspective_ck and raise 23514, and a pg error carries neither status nor '
    + 'statusCode — so every engagement endpoint\'s res.status(err.status || 500) renders an '
    + `unexplained 500 in place of the 400 the route already knows how to produce. ${TRACK_B} (B0)`);
  assert.ok(!Object.prototype.hasOwnProperty.call(r.value, 'perspective'),
    `An illegal value never reaches the SET list. ${TRACK_B} (B0)`);
});

test('B0-42: the throwing wrapper carries the field-level report', () => {
  assert.throws(() => MODEL.assertValidEngagementPlan({ perspective: 'sideways' }), (err) => {
    assert.strictEqual(err.status, 400, `${TRACK_B} (B0)`);
    assert.strictEqual(err.code, 'ENGAGEMENT_PLAN_INVALID', `${TRACK_B} (B0)`);
    assert.ok(Array.isArray(err.errors) && err.errors.length === 1, `${TRACK_B} (B0)`);
    return true;
  }, `It must match createEngagement's existing idiom so res.status(err.status || 500) renders a 400. ${TRACK_B} (B0)`);
  const value = MODEL.assertValidEngagementPlan({ display_name: 'Spring pilot' });
  assert.deepStrictEqual(value, { display_name: 'Spring pilot' },
    `PARTIAL PATCH SEMANTICS: only the keys the caller sent come back, so the UPDATE never blanks a `
    + `column the request did not mention. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §9 — THE COMPILE IS TOTAL AND DETERMINISTIC
// ════════════════════════════════════════════════════════════════════════════

test('B0-43: the compile never throws, and an empty spec is ONE problem', () => {
  const inputs = [
    {},
    { engagement: null, spec: null },
    { engagement: {}, spec: { vms: 'nope' } },
    { engagement: { engagement_type: 'default' }, spec: { vms: [] }, profile: 'not an object' },
  ];
  for (const input of inputs) {
    let plan;
    assert.doesNotThrow(() => { plan = PLAN.compileEngagementPlan(input); },
      'This is the direct repair for the class where assignLaneAddressing (profile-to-spec.js:181-192) '
      + 'throws a bare Error with no statusCode and routes/profile-deploy.js:585-591 renders '
      + `err.statusCode || 500 — a self-correctable authoring mistake as an unexplained 500. ${TRACK_B} (B0)`);
    assert.deepStrictEqual(plan.problems.map(p => p.code), ['SPEC_EMPTY'],
      'ONE root cause, ONE problem. SCOPE_EMPTY and EXTERNAL_NO_SURFACE are restatements of "there is '
      + `nothing here", and a caller staring at four errors cannot tell which to fix. ${TRACK_B} (B0)`);
    assert.deepStrictEqual(plan.hosts, [], `${TRACK_B} (B0)`);
    assert.deepStrictEqual(plan.in_scope, [], `${TRACK_B} (B0)`);
    assert.strictEqual(plan.compile_version, PLAN.ENGAGEMENT_COMPILE_VERSION, `${TRACK_B} (B0)`);
  }
});

test('B0-44: compiling the same inputs twice is byte-identical and JSON round-trips', () => {
  const engagement = { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' };
  const a = compile(engagement, specFrom(ASSETS));
  const b = compile(engagement, specFrom(ASSETS));
  assert.deepStrictEqual(a, b,
    'PURE, SYNCHRONOUS, DETERMINISTIC: no clock, no randomness, no I/O. A plan that changed between '
    + `two reads could not be diffed against paper already handed to a tester. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(a)), a,
    `The plan is stored in a jsonb column, so it must survive a JSON round trip unchanged. ${TRACK_B} (B0)`);
  assert.strictEqual(a.spec_fingerprint, b.spec_fingerprint, `${TRACK_B} (B0)`);
  assert.notStrictEqual(a.spec_fingerprint,
    PLAN.specFingerprint(specFrom(ASSETS.slice(0, 2))),
    `A different estate must produce a different fingerprint, or B2 cannot tell a stale proposal from `
    + `a current one. ${TRACK_B} (B0)`);
});

test('B0-45: hosts are in spec order, and a scope rule renumbers nothing', () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const plain = compile({ engagement_type: 'default' }, spec);
  assert.deepStrictEqual(plain.hosts.map(h => h.vm_name), ['web01', 'dc01', 'ws01'],
    'SPEC ORDER IS THE ADDRESSING CONTRACT — assignLaneAddressing hands out octets in list order, so '
    + `re-sorting here would describe a lane that does not exist. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(plain.hosts.map(h => h.ip_octet),
    [SYNTH.SPEC_OCTET_MIN, SYNTH.SPEC_OCTET_MIN + 1, SYNTH.SPEC_OCTET_MIN + 2],
    `Octets ascend from the synthesizer's own exported band. ${TRACK_B} (B0)`);

  const scoped = compile({ engagement_type: 'default', scope_out: [{ kind: 'vm', value: 'dc01' }] }, spec);
  assert.deepStrictEqual(scoped.hosts.map(h => h.vm_name), plain.hosts.map(h => h.vm_name), `${TRACK_B} (B0)`);
  assert.deepStrictEqual(scoped.hosts.map(h => h.ip_octet), plain.hosts.map(h => h.ip_octet),
    `Scope is an opinion about machines, never a change to their addressing. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(scoped.out_of_scope, ['dc01'], `${TRACK_B} (B0)`);
  assert.strictEqual(scoped.hosts[1].scope_reason, 'excluded_vm',
    `scope_out is subtracted last and ALWAYS wins. ${TRACK_B} (B0)`);
});

test('B0-46: every code the compile emits is registered', () => {
  const registered = new Set(PLAN.PLAN_PROBLEM_CODES);
  const offenders = [];
  for (const plan of everyFixturePlan()) {
    for (const p of plan.problems) {
      if (!registered.has(p.code)) offenders.push(p.code);
      if (!['error', 'warn', 'info'].includes(p.severity)) offenders.push(`${p.code}:${p.severity}`);
    }
  }
  assert.deepStrictEqual(offenders, [],
    'A code that exists only as a string literal in one branch is a code no caller can switch on, which '
    + `is exactly what PLAN_PROBLEM_CODES exists to prevent. ${TRACK_B} (B0)`);
  assert.ok(!PLAN.PLAN_PROBLEM_CODES.some(c => /PUBLISH/.test(c)),
    'Nothing is published, so a PUBLISH_* code has no subject. Keeping one would read to a later phase '
    + `as permission to build a DNAT path. ${TRACK_B} (B0)`);
});

test('B0-47: hasBlockingProblem is true exactly when a problem is an error', () => {
  for (const plan of everyFixturePlan()) {
    const expected = plan.problems.some(p => p.severity === 'error');
    assert.strictEqual(PLAN.hasBlockingProblem(plan), expected,
      'This module never decides what blocking MEANS — a route may refuse to save, a screen may show a '
      + `banner. That decision belongs to the caller. ${TRACK_B} (B0)`);
  }
  assert.strictEqual(PLAN.hasBlockingProblem(null), false, `Total, like everything else here. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §10 — THE NO-BEHAVIOUR-CHANGE PROOF
// ════════════════════════════════════════════════════════════════════════════

test("B0-48: an unedited 'default' engagement compiles to the whole environment, cleanly", () => {
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }));
  assert.deepStrictEqual(plan.in_scope, ['web01', 'dc01', 'ws01'], `${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.out_of_scope, [], `${TRACK_B} (B0)`);
  assert.deepStrictEqual([...new Set(plan.hosts.map(h => h.scope_reason))], ['default_all'],
    "This is exactly today's behaviour for every 'default' engagement in the table, so making "
    + `engagements first class changes nothing for a client that has one. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), false, `${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.exposure, [],
    'An internal engagement is a flat lane with one segment, so it has no placement opinions to express '
    + `and inventing some would be a fiction. ${TRACK_B} (B0)`);
});

test('B0-49: asset_selection is byte-identical to defaultAssetSelection, for EVERY perspective', () => {
  // THE MACHINE-CHECKABLE PROOF THAT WIRING plan.asset_selection AT
  // routes/profile-deploy.js:276 IS A NO-OP.
  //
  // The earlier draft narrowed the deployed set for an external engagement to
  // its public surface alone. That is CUT: a one-machine external engagement has
  // nothing to pivot INTO, and the exercise is "exploit the exposed host, then
  // pivot to the internal segment". SCOPE and PLACEMENT are different questions
  // from DEPLOYED SET — which makes this a stronger proof than the draft's, not
  // a weaker one, because it now holds for all three perspectives.
  const expected = ASSETS.map(a => ({
    hostname: a.hostname,
    role: a.role,
    os: a.os,
    included: String(a.role || '').toLowerCase() === 'server',
  }));
  const engagements = [
    { engagement_type: 'default', subnet_scheme: 'v2' },
    { engagement_type: 'internal_credentialed', perspective: 'internal', credential_posture: 'credentialed', subnet_scheme: 'v2' },
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
  ];
  for (const engagement of engagements) {
    const spec = specFrom(ASSETS, { subnet_scheme: engagement.subnet_scheme });
    const plan = compile(engagement, spec);
    assert.deepStrictEqual(plan.asset_selection, expected,
      `Perspective '${plan.engagement.perspective}' must deploy the same estate. What perspective `
      + 'changes is (i) what the brief names as in scope and (ii) which host is the bridge — never how '
      + `many machines come up. ${TRACK_B} (B0)`);
    for (const row of plan.asset_selection) {
      assert.deepStrictEqual(Object.keys(row).sort(), ['hostname', 'included', 'os', 'role'],
        'EXACTLY four keys, the same shape as ciab_profile_lane_groups.asset_selection. A fifth key here '
        + `is a fifth key profile-to-spec.js has never seen. ${TRACK_B} (B0)`);
    }
  }
});

test('B0-50: an AUTHORED scope rule constrains the selection; a derived one never does', () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const plan = compile({
    engagement_type: 'default', subnet_scheme: 'v2',
    scope_out: [{ kind: 'vm', value: 'dc01' }],
    scope_in: [{ kind: 'vm', value: 'ws01' }],
  }, spec);
  const byHost = Object.fromEntries(plan.asset_selection.map(r => [r.hostname, r.included]));
  assert.strictEqual(byHost.dc01, false,
    `An authored scope_out rule forces included:false. ${TRACK_B} (B0)`);
  assert.strictEqual(byHost.ws01, true,
    `An authored scope_in vm rule force-includes a machine the role default would have skipped. ${TRACK_B} (B0)`);
  assert.strictEqual(byHost.web01, true, `${TRACK_B} (B0)`);
});

test('B0-51: the route still means role === server, so the two cannot drift apart', () => {
  const code = jsCode(read(ROUTE_REL));
  assert.ok(/function defaultAssetSelection\(assets\)/.test(code),
    `routes/profile-deploy.js must still define defaultAssetSelection. ${TRACK_B} (B0)`);
  assert.ok(/included:\s*String\(a\.role \|\| ''\)\.toLowerCase\(\) === 'server'/.test(code),
    'The byte-identity test above is only meaningful while the route still means the same thing. If '
    + `this changes, the compile must change with it in the same commit. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §11 — PERSPECTIVE CHANGES SCOPE AND PLACEMENT, NEVER THE DEPLOYED SET
// ════════════════════════════════════════════════════════════════════════════

test('B0-52: an external engagement scopes in exactly the exposed host', () => {
  // THE DAY-90 PROPERTY, ASSERTED AS DATA.
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
    specFrom(ASSETS));
  assert.deepStrictEqual(plan.in_scope, ['web01'], `${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.out_of_scope, ['dc01', 'ws01'],
    'Everything behind the pivot is something the tester has to EARN by crossing it, not something the '
    + `scope handed them. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.public_surface.source, 'asset',
    `'asset' means the CLIENT has a web server in its file. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.hosts[0].scope_reason, 'default_exposed',
    "The reason is spelled in the PLACEMENT vocabulary, not the cut publish one. Nothing is published — "
    + 'there is no DNAT and no gateway perimeter publish anywhere in this product — and a word like '
    + "'published' riding in emitted plan DATA reads to a later phase as permission to build the path it "
    + `names. ${TRACK_B} (B0)`);
  assert.ok(!/publish/i.test(JSON.stringify(plan)),
    'No compiled plan may carry a publish word ANYWHERE in its data, for the same reason '
    + `PLAN_PROBLEM_CODES may carry no PUBLISH_* code. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.brief.facts.out_of_scope, [],
    'The BRIEF names only machines an AUTHORED rule excluded. Printing the derived non-selection would '
    + 'hand a black-box tester the internal topology they are being asked to discover; the full list is '
    + `still on plan.out_of_scope for the instructor's screen. ${TRACK_B} (B0)`);
});

test('B0-53: a client with no web server of its own gets the synthesized site', () => {
  const spec = specFrom(ASSETS.filter(a => a.hostname !== 'web01'), {
    vuln_app_install: { target_vm: 'vuln-app' },
  });
  spec.vms.push({
    name: 'vuln-app', hostname: 'vuln-app', role: 'server', os: 'Debian 12',
    type: 'qemu', ipOctet: SYNTH.SPEC_OCTET_MIN + 2, services: ['80/HTTP'], synthetic: true,
  });
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' }, spec);
  assert.strictEqual(plan.public_surface.source, 'synthetic',
    "Rung 2 deliberately skips the SYNTHETIC machine even though isWebServer says yes to it. The "
    + "distinction is editorial: 'asset' means the client has a web server in its file, 'synthetic' "
    + `means the environment supplied one, and B1 renders those two sentences differently. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.public_surface.target_vm, 'vuln-app', `${TRACK_B} (B0)`);
  const info = codeAt(plan, 'EXTERNAL_SYNTHETIC_SURFACE');
  assert.strictEqual(info.length, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(info[0].severity, 'info',
    'The synthesizer appends that VM itself (template 1005, role server, services 80/HTTP), so it is a '
    + `real deployable host and the engagement is sound. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), false, `${TRACK_B} (B0)`);
});

test('B0-54: external with no web server and no vulnerable application is an error', () => {
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
    specFrom(ASSETS.filter(a => a.hostname !== 'web01')));
  assert.ok(codeAt(plan, 'EXTERNAL_NEEDS_VULN_APP').some(p => p.severity === 'error'),
    'There would be nothing for the tester to find from the outside, and an unexplained empty scope is '
    + `the worst possible way to say so. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), true, `${TRACK_B} (B0)`);
});

test("B0-55: internal_credentialed selects the same servers as 'default'", () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const a = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, spec);
  const b = compile({
    engagement_type: 'internal_credentialed', perspective: 'internal',
    credential_posture: 'credentialed', subnet_scheme: 'v2',
  }, spec);
  assert.deepStrictEqual(b.asset_selection, a.asset_selection, `${TRACK_B} (B0)`);
  assert.deepStrictEqual(b.in_scope, a.in_scope,
    `Credentialed changes WHAT YOU ARE GIVEN, never what is in scope. ${TRACK_B} (B0)`);
});

test('B0-56: plan.synth carries exactly the two keys the synthesizer reads', () => {
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }));
  assert.deepStrictEqual(Object.keys(plan.synth).sort(), ['attackBoxes', 'subnetScheme'],
    'Only keys synthesizeSpecFromProfile already reads that are not reservation-owned. vxlanBlock is '
    + `deliberately absent — it belongs to the reservation and adoptedSpec() overwrites it. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.synth.subnetScheme, 'v2', `${TRACK_B} (B0)`);
  assert.strictEqual(plan.synth.attackBoxes, true, `${TRACK_B} (B0)`);
  assert.strictEqual(
    PLAN.compileEngagementPlan({
      engagement: { engagement_type: 'default' }, spec: specFrom(ASSETS), profile: PROFILE,
      options: { attackBoxes: false },
    }).synth.attackBoxes, false, `${TRACK_B} (B0)`);
});

test('B0-57: the plan emits no decorative spec key', () => {
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }));
  for (const key of ['attack_boxes', 'subnet_scheme', 'vms', 'vxlan_block']) {
    assert.ok(!Object.prototype.hasOwnProperty.call(plan, key),
      `plan.${key} would look like a spec field and reach nothing: spec.attack_boxes has ZERO readers `
      + 'repo-wide and the live attack-box value travels as the runProfileDeploy attackBoxes '
      + 'ARGUMENT (profile-deploy.js:383,430), while spec.subnet_scheme is read from the SPEC by the '
      + `compile itself — copying either onto the plan would be a second, staler spelling. ${TRACK_B} (B0)`);
  }
  assert.strictEqual(plan.start_position.attack_box_required, true,
    `Reported as a deploy argument, on start_position, not as a spec key. ${TRACK_B} (B0)`);
});

test("B0-58: the client's public IP never escapes plan.client, and the start is lane-relative", () => {
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
    specFrom(ASSETS));
  const serialized = JSON.stringify(plan);
  const occurrences = serialized.split(PROFILE_PUBLIC_IP).length - 1;
  assert.strictEqual(occurrences, 1,
    'public_ip is a per-PROFILE RFC 5737 literal (ai/profile/index.js:184), so every lane cut from one '
    + 'client would advertise the identical address. plan.client.public_ip is the ONE place it may '
    + `appear, and nothing downstream may copy it. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.client.public_ip, PROFILE_PUBLIC_IP, `${TRACK_B} (B0)`);
  assert.ok(codeAt(plan, 'PROFILE_PUBLIC_IP_NOT_ROUTABLE').length === 1, `${TRACK_B} (B0)`);

  const entry = plan.start_position.entry;
  assert.strictEqual(entry.kind, 'attack_box',
    'BOTH perspectives start on the attack box. Nothing is published at the perimeter, so there is no '
    + 'service to start "at" — what the perspective changes is what is REACHABLE from the external '
    + `segment, not where the tester sits. ${TRACK_B} (B0)`);
  assert.strictEqual(entry.value, 'kali', `${TRACK_B} (B0)`);
  assert.ok(/\{ext_base\}/.test(entry.url_template),
    'The URL is LANE-RELATIVE. The lane fills in its own external /24 at deploy time; the profile IP '
    + `never appears in it. ${TRACK_B} (B0)`);
  assert.ok(entry.url_template.endsWith(`.${PLAN.DUAL_HOMED_OCTET}/`),
    `The exposed host answers at .${PLAN.DUAL_HOMED_OCTET}, which is where the deployer actually pins a `
    + `dual-homed machine. ${TRACK_B} (B0)`);
  assert.strictEqual(
    compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }))
      .start_position.entry.url_template, null,
    `An internal tester is already inside; there is no crossing to describe. ${TRACK_B} (B0)`);
});

test('B0-59: the lane transit range is out of scope in every engagement', () => {
  for (const engagement of [
    { engagement_type: 'default', subnet_scheme: 'v2' },
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
    { engagement_type: 'internal_credentialed', perspective: 'internal', credential_posture: 'credentialed', subnet_scheme: 'v2' },
  ]) {
    const plan = compile(engagement, specFrom(ASSETS, { subnet_scheme: engagement.subnet_scheme }));
    assert.ok(plan.declared_only.some(d => d.kind === 'cidr' && d.value === PLAN.MANAGEMENT_CIDR),
      `${PLAN.MANAGEMENT_CIDR} is the lane WAN transit pool — the plumbing that carries the exercise, `
      + `never part of the client estate. ${TRACK_B} (B0)`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §12 — HONEST DERIVATION, LAYOUTS, SCOPE AND CAPACITY
// ════════════════════════════════════════════════════════════════════════════

test('B0-60: a profile whose assets declare no services says so rather than inventing', () => {
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }));
  const hit = codeAt(plan, 'PROFILE_ASSETS_DECLARE_NO_SERVICES');
  assert.strictEqual(hit.length, 1,
    'AI profile generation emits {hostname, ip, subnet, role, os, function, critical} and nothing else '
    + '(ai/profile/prompts.js:1040). A compiler that quietly manufactured a service list would be '
    + `inventing the environment rather than describing it. ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'info', `${TRACK_B} (B0)`);
});

test('B0-61: a real-client intake wrapped in a one-element array compiles', () => {
  const real = [{
    id: 'r1',
    json_data: {
      student_view: {
        raw: { threats: { organization: { company_name: 'Bay Clinic' }, network: { total_assets: 14 } } },
      },
    },
  }];
  const facts = PLAN.readClientFacts(real);
  assert.strictEqual(facts.layout, 'real_intake',
    'A real-client profile is WRITTEN as a one-element array (routes/real-client-intake.js:371) and '
    + `every loader in the tree copies that idiom. ${TRACK_B} (B0)`);
  assert.strictEqual(facts.company_name, 'Bay Clinic', `${TRACK_B} (B0)`);
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }), real);
  assert.ok(codeAt(plan, 'REAL_INTAKE_NO_NETWORK_PLAN').length === 1,
    `A real intake with no segments has no network plan to put in the brief at all. ${TRACK_B} (B0)`);
});

test('B0-62: the legacy split and flat loader layouts both compile', () => {
  const legacy = {
    id: 'l1',
    json_data: {
      student_view: {
        raw: {
          network: { subnets: [{ name: 'LAN', cidr: '10.0.0.0/24' }] },
          it: { it_environment: {} },
          threat_profile: {},
        },
      },
    },
  };
  assert.strictEqual(PLAN.readClientFacts(legacy).layout, 'legacy_split', `${TRACK_B} (B0)`);
  const flat = { id: 'f1', company_name: 'Flat Co', assets: [{ hostname: 'a', role: 'server' }] };
  assert.strictEqual(PLAN.readClientFacts(flat).layout, 'flat',
    `loadProfileForDeploy returns { ...profileRow, assets, json_data } (profile-deploy.js:95-100). ${TRACK_B} (B0)`);
  for (const profile of [legacy, flat]) {
    const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }), profile);
    assert.ok(!codeAt(plan, 'PROFILE_LAYOUT_UNRECOGNISED').length,
      `A live layout must not be reported as unreadable. ${TRACK_B} (B0)`);
  }
});

test('B0-63: an unreadable client file is a problem, not an exception', () => {
  const facts = PLAN.readClientFacts({ nothing: 'recognisable' });
  assert.strictEqual(facts.layout, 'empty', `${TRACK_B} (B0)`);
  assert.ok(facts.gaps.some(g => g.code === 'PROFILE_LAYOUT_UNRECOGNISED'), `${TRACK_B} (B0)`);
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' },
    specFrom(ASSETS, { subnet_scheme: 'v2' }), { nothing: 'recognisable' });
  const hit = codeAt(plan, 'PROFILE_LAYOUT_UNRECOGNISED');
  assert.strictEqual(hit[0].severity, 'warn',
    `The environment itself still compiles; only the narrative is missing. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), false, `${TRACK_B} (B0)`);
});

test('B0-64: a cidr or url scope rule is documentary and moves no machine', () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const plan = compile({
    engagement_type: 'default', subnet_scheme: 'v2',
    scope_out: [{ kind: 'cidr', value: '10.20.10.0/24' }, { kind: 'url', value: 'https://portal.example' }],
  }, spec);
  assert.deepStrictEqual(plan.in_scope, ['web01', 'dc01', 'ws01'],
    'A spec VM carries an ipOctet, not an address, and the lane base is per-lane and unknown offline. '
    + `Saying so is more honest than a half-working match. ${TRACK_B} (B0)`);
  assert.ok(plan.declared_only.some(d => d.kind === 'cidr' && d.value === '10.20.10.0/24'), `${TRACK_B} (B0)`);
  assert.ok(plan.declared_only.some(d => d.kind === 'url'), `${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(plan, 'SCOPE_RULE_DOCUMENTARY').length, 2, `${TRACK_B} (B0)`);
  assert.ok(codeAt(plan, 'SCOPE_RULE_DOCUMENTARY').every(p => p.severity === 'info'), `${TRACK_B} (B0)`);
});

test('B0-65: isInScope denies before it allows and never throws on a malformed rule', () => {
  const plan = {
    scope: {
      in: [{ kind: 'cidr', value: '10.20.10.0/24' }, { kind: 'hostname_pattern', value: 'web*' }],
      out: [{ kind: 'vm', value: 'dc01' }],
    },
  };
  assert.strictEqual(PLAN.isInScope(plan, { ip: '10.20.10.5' }).decision, 'allow', `${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.isInScope(plan, { ip: '10.30.0.5' }).decision, 'default_deny',
    `An unmatched target is default_deny, so the failure mode of guessing is never "test someone else's `
    + `machine". ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.isInScope(plan, { hostname: 'WEB07' }).in_scope, true,
    `The glob is case-insensitive and every other metacharacter is escaped. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.isInScope(plan, { hostname: 'webXany' }).in_scope, true, `${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.isInScope({
    scope_in: [{ kind: 'all', value: '' }], scope_out: [{ kind: 'vm', value: 'dc01' }],
  }, { hostname: 'dc01' }).decision, 'deny',
    'DENY BEATS ALLOW. A tester who has to reason about rule ORDER will eventually reason wrong. '
    + `An engagement ROW is exactly this {scope_in, scope_out} shape, so a caller with no spec can ask. ${TRACK_B} (B0)`);
  let result;
  assert.doesNotThrow(() => {
    result = PLAN.isInScope({ scope_in: [{ kind: 'cidr', value: 'Servers' }] }, { ip: '10.0.0.5' });
  }, "ipInCidr('10.0.0.5','Servers') THROWS `Not a CIDR block` — and asset.subnet really is a subnet "
    + 'NAME on LLM-authored servers and a CIDR STRING on assets rebuilt by reconcile-workstations, so a '
    + `stored rule really can carry 'Servers'. ${TRACK_B} (B0)`);
  assert.strictEqual(result.decision, 'default_deny', `${TRACK_B} (B0)`);
});

test("B0-66: objectives are definitions keyed on cybercore_lane_flag's own unit", () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  spec.vms.push({ name: 'ct-tools', hostname: 'ct-tools', role: 'server', type: 'lxc' });
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, spec);
  const names = new Set(plan.hosts.map(h => h.vm_name));
  for (const o of plan.objectives) {
    assert.strictEqual(o.maps_to.kind, 'flag', `${TRACK_B} (B0)`);
    assert.ok(names.has(o.maps_to.vm_name),
      `Every objective must name a machine that actually deploys. ${TRACK_B} (B0)`);
    assert.ok(MODEL.FLAG_TYPES.includes(o.maps_to.flag_type),
      '(vm_name, flag_type) is EXACTLY cybercore_lane_flag\'s unit — its UNIQUE is '
      + '(lane_id, vm_name, flag_type) and it already carries an unused points column. Scoring is a VIEW '
      + `over that table, not a fourth progress tracker and not a new table. ${TRACK_B} (B0)`);
  }
  assert.ok(!plan.objectives.some(o => o.maps_to.vm_name === 'ct-tools'),
    `flag-manager skips LXC machines, so an objective on one could never be satisfied. ${TRACK_B} (B0)`);
  assert.ok(!plan.objectives.some(o => /kali/i.test(o.maps_to.vm_name)),
    'The attack box is not in spec.vms and plantFlagsForLane never plants on it '
    + `(challenge-lane-deployer.js:1747 filters v.source !== \'instructor\'). ${TRACK_B} (B0)`);
});

test('B0-67: credentials are authored, never derived, and a prefill carries no secret', () => {
  const spec = specFrom(ASSETS, { subnet_scheme: 'v2' });
  const none = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, spec);
  assert.deepStrictEqual(none.credentials.slots, [],
    `An account the client did not agree to hand over is an account that does not exist. ${TRACK_B} (B0)`);
  assert.strictEqual(none.credentials.delivery, 'file', `${TRACK_B} (B0)`);

  const cred = compile({
    engagement_type: 'internal_credentialed', perspective: 'internal',
    credential_posture: 'credentialed', subnet_scheme: 'v2',
  }, spec);
  assert.ok(codeAt(cred, 'CREDENTIALS_UNAUTHORED').some(p => p.severity === 'warn'),
    'An empty list meaning "none by design" and one meaning "not authored yet" are different facts, and '
    + `the delivery step cannot tell them apart. ${TRACK_B} (B0)`);
  const prefill = cred.suggestions.issued_credentials;
  assert.ok(Array.isArray(prefill) && prefill.length === 1, `${TRACK_B} (B0)`);
  assert.strictEqual(prefill[0].username, 'ana.ruiz',
    'The username comes from a NON-EXECUTIVE stakeholder: the account a client actually hands a tester '
    + `on day one is a rank-and-file one. ${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.containsSecret(prefill), false,
    `A derived USERNAME and a target machine, and nothing else, ever. ${TRACK_B} (B0)`);
});

test('B0-68: an authored field is never overwritten by a proposal', () => {
  const plan = compile({
    engagement_type: 'default', subnet_scheme: 'v2', authored_fields: ['scope_in'],
  }, specFrom(ASSETS, { subnet_scheme: 'v2' }));
  const merged = MODEL.mergeProposal({ authored_fields: ['scope_in'] }, plan.suggestions);
  assert.ok(!Object.prototype.hasOwnProperty.call(merged.patch, 'scope_in'),
    'authored_fields is the one column that CANNOT be added later: once instructors have edited scope '
    + `and a refresh action exists, which fields were authored is unrecoverable retroactively. ${TRACK_B} (B0)`);
  assert.ok(merged.skipped.includes('scope_in'),
    `The screen must be able to say "kept your edits to ...". ${TRACK_B} (B0)`);
  assert.ok(Object.prototype.hasOwnProperty.call(merged.patch, 'scope_out'),
    `Everything NOT authored is still filled. ${TRACK_B} (B0)`);
});

test('B0-69: over-capacity is an error here rather than a bare throw there', () => {
  const many = { subnet_scheme: 'v2', vms: [] };
  const capacity = SYNTH.SPEC_OCTET_MAX - SYNTH.SPEC_OCTET_MIN + 1;
  for (let i = 0; i <= capacity; i += 1) {
    many.vms.push({ name: `srv${i}`, hostname: `srv${i}`, role: 'server', type: 'qemu' });
  }
  const plan = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, many);
  assert.strictEqual(plan.capacity.pinnable_capacity, capacity,
    "Computed from profile-to-spec.js's own EXPORTED constants, so it cannot drift from "
    + `assignLaneAddressing's own throw (:181-192). ${TRACK_B} (B0)`);
  assert.strictEqual(plan.capacity.over_capacity, true, `${TRACK_B} (B0)`);
  const hit = codeAt(plan, 'OVER_PIN_CAPACITY');
  assert.strictEqual(hit.length, 1, `${TRACK_B} (B0)`);
  assert.ok(/split the profile across two engagements/.test(hit[0].message),
    `It carries assignLaneAddressing's own remedy wording, so the two say the same thing. ${TRACK_B} (B0)`);
});

test('B0-70: a reserve-at-v2 / build-at-v3 divergence is finally visible offline', () => {
  const specV3 = specFrom(ASSETS, { subnet_scheme: 'v3' });
  const mismatch = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specV3);
  const hit = codeAt(mismatch, 'SCHEME_MISMATCH');
  assert.strictEqual(hit.length, 1,
    'This compile is the FIRST reader of spec.subnet_scheme in the repo. Reserving at v2 and deploying '
    + 'at v3 creates internal VNets at tag+V3_INTERNAL_TAG_OFFSET that the teardown sweep can never name '
    + `again, and the allocator never re-uses a block — lane-reservation.js:91-105 has the account. ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'warn', `${TRACK_B} (B0)`);
  const agreed = compile({ engagement_type: 'default', subnet_scheme: 'v2' }, specFrom(ASSETS, { subnet_scheme: 'v2' }));
  assert.strictEqual(codeAt(agreed, 'SCHEME_MISMATCH').length, 0, `${TRACK_B} (B0)`);
});

test('B0-71: the persisted spec is honest about the scheme the block was carved at', () => {
  const code = jsCode(read(ROUTE_REL));
  const hits = (code.match(/subnetScheme: engagementRow\.subnet_scheme \|\| subnetScheme/g) || []).length;
  assert.strictEqual(hits, 2,
    'Once for the reservation (line 267) and once for the synthesizer options (line 302). This is the '
    + 'B0 edit, and spec.subnet_scheme is no longer decorative: compileEngagementPlan is its FIRST and '
    + 'only reader repo-wide, and it is what raises SCHEME_MISMATCH (B0-70). It stays inert on the '
    + 'BUILD path — the deployer takes the scheme from the challenge row at '
    + 'challenge-lane-deployer.js:1990 — so pinning it here keeps the persisted spec honest about the '
    + `carve and stops a later refactor silently reverting it. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §13 — THE MIRROR THAT DRIFTED
//
// Two files answer "is this VM single-homed, and therefore pinnable?" with two
// DIFFERENT rules:
//
//   profile-to-spec.js:176-178    !(Array.isArray(vm.nics) && vm.nics.length > 1)
//   challenge-lane-deployer.js:310-311
//                                 resolveVmSegments(...).length > 1  -> skip
//
// For a role 'dmz' VM carrying NO explicit nics they DISAGREE: the synthesizer
// believes it is single-homed and stamps an ipOctet in the .80-.99 band, while
// the deployer treats it as dual-homed (lane-networking.js:379) and pins .240.
// The LANE is right either way — the deployer never writes a .8x reservation for
// that host — so this is NOT a deploy bug. It is a paper-vs-lane divergence, and
// B2's IP writeback, Track C's manifest and every scan document read the spec.
//
// It is latent today only because nothing in the tree emits role 'dmz'. B0 is
// where that starts, so B0 closes it BY CONSTRUCTION: the compile emits the
// explicit nics array B2 will write onto the spec, so a pivot arrives at the
// synthesizer with nics.length === 2 and its EXISTING filter already excludes it
// from the band. No change to profile-to-spec.js, and the divergence cannot
// occur. These three tests are what keep that true.
// ════════════════════════════════════════════════════════════════════════════

test('B0-72: the synthesizer still decides pinnability from nics.length', () => {
  const code = jsCode(read(SYNTH_REL));
  assert.ok(/!\(Array\.isArray\(vm\.nics\) && vm\.nics\.length > 1\)/.test(code),
    `${SYNTH_REL}'s assignLaneAddressing must still exclude a multi-NIC VM from the .`
    + `${SYNTH.SPEC_OCTET_MIN}-.${SYNTH.SPEC_OCTET_MAX} band by counting vm.nics. That is the ONLY `
    + 'reason the compile can close the paper-vs-lane divergence without touching this file: it emits '
    + `an explicit two-entry nics array for a pivot and this filter already skips it. ${TRACK_B} (B0)`);
});

test('B0-73: the deployer still decides pinnability from resolveVmSegments', () => {
  const code = jsCode(read(DEPLOYER_REL));
  assert.ok(/const segs = resolveVmSegments\(vmSpec, \{ subnetScheme, isGoadVm: false \}\);/.test(code),
    `${DEPLOYER_REL}'s resolveSpecAddressing must still ask resolveVmSegments. ${TRACK_B} (B0)`);
  assert.ok(/if \(segs\.length > 1\) continue;/.test(code),
    `${DEPLOYER_REL} must still SKIP a multi-segment VM when handing out band octets. If these two `
    + 'rules ever stop agreeing, a role \'dmz\' host takes a .8x octet in the spec while the deployer '
    + `pins it to .240 — and the paper then names an address nothing lives at. ${TRACK_B} (B0)`);
  assert.ok(/if \(isV3 && vmSpec\?\.role === 'dmz' && type !== 'lxc'\) return \['ext', 'int'\];/
    .test(jsCode(read('src/utils/lane-networking.js'))),
    "src/utils/lane-networking.js:379 is the mechanism the whole external exercise rests on: a v3 spec "
    + "VM with role 'dmz' is DUAL-HOMED on ext AND int, with no gateway change at all. An explicit nics "
    + `array wins over it (:374-375), which is what the compile emits. ${TRACK_B} (B0)`);
});

test('B0-74: a compiled pivot carries two NICs and the address the deployer actually pins', () => {
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' },
    specFrom(ASSETS));
  const pivot = plan.hosts.find(h => h.placement === 'pivot');
  assert.ok(pivot, `An external engagement derives exactly one pivot. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(pivot.nics, [{ segment: 'ext' }, { segment: 'int' }],
    'TWO explicit nics is what makes assignLaneAddressing skip the band AND makes resolveVmSegments '
    + 'return two segments ("explicit wins", lane-networking.js:374-375). The two rules then agree '
    + `because they are being asked the same question about the same explicit data. ${TRACK_B} (B0)`);
  assert.strictEqual(pivot.ip_octet, PLAN.DUAL_HOMED_OCTET,
    `.${PLAN.DUAL_HOMED_OCTET} is where challenge-lane-deployer.js:770-771 actually puts a dual-homed `
    + 'host — above the gateway DHCP pool (.10-.200), so no lease can claim it and no gateway re-bake '
    + `is needed. A band octet would be a true statement about a spec field and a false one about the `
    + `lane. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.DUAL_HOMED_OCTET, MODEL.DUAL_HOMED_OCTET,
    'ONE authority for 240. Two independent spellings is precisely the class of drift this section '
    + `exists to prevent. ${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.DUAL_HOMED_OCTET, 240, `${TRACK_B} (B0)`);

  const internal = plan.hosts.find(h => h.placement === 'internal');
  assert.deepStrictEqual(internal.nics, [{ segment: 'int' }],
    "An 'internal' placement needs an EXPLICIT nics array: the v3 default for an ordinary VM is a "
    + `single ext NIC. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(MODEL.nicsForPlacement('public'), null,
    "'public' maps to null — leave the spec's default alone, because single-homed ext is already what "
    + `v3 does. ${TRACK_B} (B0)`);
  assert.notStrictEqual(MODEL.nicsForPlacement('pivot'), MODEL.nicsForPlacement('pivot'),
    `A FRESH array per call: B2 writes it straight onto a spec VM and must be able to mutate it. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §14 — THE POSTURE IS WRITTEN, NOT DEFAULTED
//
// perspective and credential_posture are NOT NULL with DEFAULTs, which is what
// makes a missing write invisible: the column always holds a LEGAL value, so
// nothing downstream can tell "internal because the client is internal" from
// "internal because nobody wrote it", and no read-time fallback can ever fire.
// ════════════════════════════════════════════════════════════════════════════

/**
 * The text of one top-level `async function <name>(` in a source file.
 * The terminator is a `}` in COLUMN ZERO followed by a NEWLINE: several of
 * these functions take a destructured options bag whose own closing `})` sits
 * in column zero too, and would otherwise end the match at the signature.
 */
function fnBody(code, name) {
  const m = code.match(new RegExp(`async function ${name}\\(([\\s\\S]*?)\\n}\\n`));
  return m ? m[0] : null;
}

test('B0-75: createEngagement writes the posture at INSERT rather than defaulting it', () => {
  const code = jsCode(read(PROVISION_REL));
  const body = fnBody(code, 'createEngagement');
  assert.ok(body, `createEngagement must still be a top-level async function. ${TRACK_B} (B0)`);

  assert.ok(/describeEngagementType\(engagement\)/.test(body),
    'The posture comes from the type REGISTRY, which is the only authority for it. '
    + 'describeEngagementType is total, so an unknown slug yields exactly the (internal, none) pair '
    + `the column DEFAULTs already assign — this changes nothing for a custom slug. ${TRACK_B} (B0)`);

  const insert = body.match(/INSERT INTO ciab_engagement([\s\S]*?)RETURNING/);
  assert.ok(insert, `createEngagement must still INSERT. ${TRACK_B} (B0)`);
  for (const col of ['perspective', 'credential_posture']) {
    assert.ok(insert[1].includes(col),
      'An engagement created as an external type would otherwise be stored as internal PERMANENTLY: '
      + `${MIG_MODEL} declares ${col} NOT NULL with a DEFAULT, so the wrong value is always a legal one `
      + 'and every consumer of the external branch silently takes the internal one. '
      + `${TRACK_B} (B0)`);
  }
  assert.ok(/posture\.perspective/.test(body) && /posture\.credential_posture/.test(body),
    `Both columns must be PARAMETERS carrying the descriptor's values, not literals. ${TRACK_B} (B0)`);
});

test('B0-76: the read-path adopt still writes no posture and stays an 8-column INSERT', () => {
  const code = jsCode(read(PROVISION_REL));
  const body = fnBody(code, 'adoptExistingReservation');
  assert.ok(body, `${TRACK_B} (B0)`);
  const cols = body.match(/INSERT INTO ciab_engagement\s*\(([\s\S]*?)\)\s*VALUES/);
  assert.ok(cols, `${TRACK_B} (B0)`);
  const names = cols[1].split(',').map(s => s.trim()).filter(Boolean);
  assert.deepStrictEqual(names, [
    'profile_id', 'engagement_type', 'subnet_scheme', 'max_students',
    'challenge_id', 'challenge_key', 'provision_status', 'provisioned_at',
  ], 'GET /profiles/:profileId/engagements reaches this UPSERT, so merely OPENING the tab runs it. It '
   + 'adopts a reservation that predates the model and must never state a posture — a posture is a '
   + `decision, and an adopted row has not made one. ${TRACK_B} (B0)`);
  assert.ok(!/perspective|credential_posture/.test(body),
    `Widening this INSERT or its ON CONFLICT target breaks a live deploy path. ${TRACK_B} (B0)`);
});

test('B0-77: the model writer validates against the scheme the block was carved at', () => {
  const body = fnBody(jsCode(read(PROVISION_REL)), 'updateEngagementModel');
  assert.ok(/subnetScheme:\s*current\.subnet_scheme/.test(body),
    'This function already holds the engagement row, so the scheme is free. Without it '
    + 'EXPOSURE_REQUIRES_V3 could never fire on the AUTHORING path — the only path an instructor uses '
    + `— and the flat-segment divergence would surface at deploy instead. ${TRACK_B} (B0)`);

  // …and the warning it unlocks really is unreachable without that argument.
  const patch = { exposure_plan: [{ vm_name: 'web01', placement: 'internal' }] };
  const withScheme = MODEL.validateEngagementPlan(patch, { engagementType: 'default', subnetScheme: 'v2' });
  const without = MODEL.validateEngagementPlan(patch, { engagementType: 'default' });
  assert.ok(withScheme.warnings.some(w => w.code === 'EXPOSURE_REQUIRES_V3'),
    `v1/v2 is one flat lan0, so an 'internal' placement there is a fiction. ${TRACK_B} (B0)`);
  assert.ok(!without.warnings.some(w => w.code === 'EXPOSURE_REQUIRES_V3'),
    `Which is exactly why the argument has to be passed. ${TRACK_B} (B0)`);
  assert.strictEqual(withScheme.errors.length, 0,
    `A WARNING, never an error: a model is legitimately authored before the scheme is settled. ${TRACK_B} (B0)`);
});

test('B0-78: an empty patch cannot mark anything human-authored', () => {
  const body = fnBody(jsCode(read(PROVISION_REL)), 'updateEngagementModel');
  assert.ok(/markAuthored && touched\.length > 0/.test(body),
    'markAuthored defaults to TRUE, so a machine writer that forgets to opt out would stamp compiler '
    + 'output as human-authored — and a field listed in authored_fields is one the refresh-from-the-'
    + `client-file path refuses to overwrite forever. ${TRACK_B} (B0)`);
  assert.ok(/AUTHORABLE_FIELDS\.includes\(k\)/.test(body),
    `Only an AUTHORABLE field can be authored; synthesis_meta and updated_by are not. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §15 — A CONSTRAINT NAME IS UNIQUE PER TABLE, NOT PER DATABASE
// ════════════════════════════════════════════════════════════════════════════

test('B0-79: every constraint guard is scoped by conrelid as well as by name', () => {
  for (const rel of [MIG_GUARDS, MIG_SECRET]) {
    const code = sqlCode(read(rel));
    const names = [...code.matchAll(/ADD\s+CONSTRAINT\s+(\w+)/gi)].map(m => m[1]);
    assert.ok(names.length > 0, `${rel} should add at least one constraint. ${TRACK_B} (B0)`);
    const unscoped = names.filter(n => !new RegExp(
      `conname\\s*=\\s*'${n}'\\s*AND\\s+conrelid\\s*=\\s*'ciab_engagement'::regclass`, 'i'
    ).test(code));
    assert.deepStrictEqual(unscoped, [],
      'pg_constraint holds one row per constraint PER RELATION, so an unscoped conname lookup can be '
      + 'permanently satisfied by a same-named constraint on some other table — and the ADD would then '
      + 'be skipped silently, on every boot, forever, leaving the column with no backstop and no log '
      + `line. 014_ciab_modules.sql:631-635 documents the same hazard. ${TRACK_B} (B0)`);
  }
});

test('B0-80: the model migration needs no to_regclass guard, and says why', () => {
  const code = sqlCode(read(MIG_MODEL));
  assert.ok(!/to_regclass/i.test(code),
    'ADD COLUMN IF NOT EXISTS cannot be conditionalised without a DO block, and B0-6 refuses one here. '
    + `${TRACK_B} (B0)`);

  // The guard would have nothing to save: EVERY statement in the file names the
  // one table, so a missing table costs exactly the statements that could not
  // have run anyway — a loud 42P01 and a clean retry on the next boot.
  const statements = code.split(';').map(s => s.trim()).filter(Boolean);
  assert.ok(statements.length >= 3, `${TRACK_B} (B0)`);
  const strays = statements.filter(s => !/ciab_engagement/i.test(s));
  assert.deepStrictEqual(strays, [],
    'A to_regclass guard is worth having when a file has something to SAVE — 012 and 013 add '
    + 'constraints to a table another file created. This file does not: if the table is absent, every '
    + `statement in it is exactly the work that could not have happened anyway. ${TRACK_B} (B0)`);

  assert.ok(/to_regclass/i.test(read(MIG_MODEL)),
    'The omission must be DOCUMENTED in the header, so it reads as a decision and not an oversight — '
    + `the file's own "WHY THIS FILE CANNOT FAIL" heading is what invites the question. ${TRACK_B} (B0)`);
  for (const rel of [MIG_GUARDS, MIG_SECRET]) {
    assert.ok(/to_regclass\('ciab_engagement'\) IS NULL/i.test(sqlCode(read(rel))),
      `${rel} DOES need the guard: a missing table there would take unrelated statements with it. `
      + `${TRACK_B} (B0)`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §14 — THE COMPILE KNOWS WHAT ROLE A MACHINE PLAYS
//
// The compile used to be BLIND TO VM ROLE, and 'dmz' and 'attacker' are exactly
// the two roles the whole external design rests on:
//
//   src/utils/topology-validate.js:25-26   EXTERNAL_ROLES = {'dmz','attacker'}
//   src/utils/lane-networking.js:374-381   explicit nics > v3+dmz+qemu > ext > lan
//   src/utils/challenge-lane-deployer.js:310-311  segs.length > 1 -> not pinned
//   src/utils/challenge-lane-deployer.js:758-772  dual-homed -> .240, v3 ONLY
//
// Both roles are REAL and COMMON — public/js/topology/topology-seed.js:203-208
// emits { name:'web01', role:'dmz', services:['80/HTTP'] } and a Kali with
// role 'attacker' right beside it, and public/js/admin/admin-challenges.js does
// the same at :177,186,277,544,586.
//
// These tests defend ONE property: there is exactly one place in
// engagement-plan.js that answers "what segments will the deployer actually give
// this machine, and therefore what address will it actually have", it mirrors
// resolveVmSegments' precedence exactly, and everything else reads it.
// ════════════════════════════════════════════════════════════════════════════

const TOPOLOGY_VALIDATE_REL = 'src/utils/topology-validate.js';
const LANE_NETWORKING_REL = 'src/utils/lane-networking.js';

/** A v3 spec carrying the two roles the topology editor really emits. */
function roleSpec(extra) {
  return Object.assign({
    subnet_scheme: 'v3',
    vms: [
      { name: 'web01', hostname: 'web01', role: 'server', type: 'qemu',
        ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] },
      { name: 'shop', hostname: 'shop', role: 'dmz', type: 'qemu',
        ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['80/HTTP'] },
      { name: 'Kali', hostname: 'Kali', role: 'attacker', type: 'qemu',
        ipOctet: SYNTH.SPEC_OCTET_MIN + 2, services: [] },
    ],
  }, extra || {});
}

const EXTERNAL_V3 = { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3' };

test('B0-81: EXTERNAL_ROLES is mirrored from shared core, and the mirror cannot drift', () => {
  // The same guard shape as B0-72/73 and the SPEC_OCTET band parity: assert the
  // mirror against the AUTHORITY'S OWN TEXT, because the authority cannot be
  // imported. topology-validate.js requires ./lane-networking and ./goad-deploy,
  // and that graph reaches site-config.js:29-30's unguarded fs.readFileSync of
  // config/site.json — ABSENT from this checkout — so one import would fail
  // every stubbed-cache suite naming the wrong file, and break B0-2's contract.
  assert.deepStrictEqual(PLAN.EXTERNAL_ROLES.slice().sort(), ['attacker', 'dmz'],
    `The compile's mirror must be exactly the shared-core set. ${TRACK_B} (B0)`);
  assert.ok(/const EXTERNAL_ROLES = new Set\(\['dmz', 'attacker'\]\);/
    .test(jsCode(read(TOPOLOGY_VALIDATE_REL))),
    `${TOPOLOGY_VALIDATE_REL}:25-26 is the AUTHORITY for which roles sit outside the AD network. If it `
    + `changes, the mirror in ${PLAN_REL} must change in the same commit. ${TRACK_B} (B0)`);
  assert.ok(/topology-validate\.js:25-26/.test(read(PLAN_REL)),
    'The mirror must carry its file:line citation, so the next reader can find the authority without '
    + `grepping for it. ${TRACK_B} (B0)`);
  assert.strictEqual((read(PLAN_REL).match(/require\(/g) || []).length, 5,
    `Mirroring exists to keep the import list at five. ${TRACK_B} (B0)`);
});

test('B0-82: the segment mirror reproduces resolveVmSegments precedence, rung for rung', () => {
  const core = jsCode(read(LANE_NETWORKING_REL));
  assert.ok(/const explicit = Array\.isArray\(vmSpec\?\.nics\)/.test(core)
    && /if \(explicit\.length\) return explicit\.map/.test(core),
    'EXPLICIT WINS FIRST. An authored nics array beats every inference, which is the whole mechanism '
    + `the compile uses to close the paper-vs-lane divergence without touching the synthesizer. ${TRACK_B} (B0)`);
  assert.ok(/if \(isV3 && vmSpec\?\.role === 'dmz' && type !== 'lxc'\) return \['ext', 'int'\];/.test(core),
    `The dual-homing rung, and the qemu guard on it. ${TRACK_B} (B0)`);
  assert.ok(/return \[isV3 \? 'ext' : 'lan'\];/.test(core),
    `The fallback: single ext on v3, single lan on v1/v2. ${TRACK_B} (B0)`);

  const mirror = read(PLAN_REL);
  assert.ok(/lane-networking\.js:374-381/.test(mirror),
    `The mirror must cite the authority it reproduces. ${TRACK_B} (B0)`);
  assert.ok(/if \(explicit\.length\) return explicit\.map/.test(jsCode(mirror)),
    `Explicit-wins must be the FIRST rung here too, or the precedence is not the same. ${TRACK_B} (B0)`);
  assert.ok(/spec\.role === PIVOT_ROLE && type !== 'lxc'/.test(jsCode(mirror)),
    "Including the qemu guard: an LXC marked 'dmz' gets ONE external NIC, not two. "
    + `${TRACK_B} (B0)`);
});

test('B0-83: the per-lane Kali is placed nowhere and keeps no proposed NICs', () => {
  const plan = compile(EXTERNAL_V3, roleSpec());
  const kali = plan.hosts.find(h => h.role === 'attacker');
  assert.ok(kali, `${TRACK_B} (B0)`);
  assert.strictEqual(kali.placement, null,
    'The derivation used to skip only synthetic machines, so it stamped placement internal on the '
    + `attack box itself. ${TRACK_B} (B0)`);
  assert.strictEqual(kali.nics, null,
    'An explicit nics array WINS over every inference (lane-networking.js:374-375), so a proposed '
    + "[{segment:'int'}] would, once B2 writes it onto the spec, relocate the student's console onto the "
    + `internal segment and break the baked wan0:3389 -> ext .50 console contract. ${TRACK_B} (B0)`);
  assert.ok(!plan.exposure.some(e => e.vm_name.toLowerCase() === 'kali'),
    "The deploy path owns the attack box's addressing; this compile has no opinion about it. "
    + `${TRACK_B} (B0)`);
});

test('B0-84: a dmz machine is the bridge whether or not the plan mentions it', () => {
  // BOTH paths, because they used to fail differently: with no stored plan the
  // derivation stamped 'internal' on it, and with a stored plan that did not
  // name it, it was left placement:null while the deployer pinned it to .240
  // anyway — beside the declared pivot, at the SAME address, silently.
  const derived = compile(EXTERNAL_V3, roleSpec());
  const shop = derived.hosts.find(h => h.role === 'dmz');
  assert.strictEqual(shop.placement, 'pivot', `${TRACK_B} (B0)`);
  assert.deepStrictEqual(shop.nics, [{ segment: 'ext' }, { segment: 'int' }], `${TRACK_B} (B0)`);
  assert.strictEqual(shop.ip_octet, PLAN.DUAL_HOMED_OCTET,
    'lane-networking.js:379 dual-homes it and challenge-lane-deployer.js:768-771 pins it to .240 on BOTH '
    + `segments, so a band octet on it would be a false statement about the lane. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(derived.exposure.filter(e => e.placement === 'pivot').map(e => e.vm_name),
    ['shop'],
    `Exactly one bridge, and it is the machine the environment actually bridges on. ${TRACK_B} (B0)`);

  const authored = compile(
    Object.assign({}, EXTERNAL_V3, { exposure_plan: [{ vm_name: 'web01', placement: 'pivot' }] }),
    roleSpec());
  assert.deepStrictEqual(
    authored.hosts.filter(h => h.ip_octet === PLAN.DUAL_HOMED_OCTET).map(h => h.vm_name),
    ['web01', 'shop'],
    `Two machines really would claim .240 in that lane. ${TRACK_B} (B0)`);
  assert.ok(codeAt(authored, 'EXPOSURE_MULTIPLE_PIVOTS').some(p => p.severity === 'error'),
    'And the pivot guard must SEE it. It used to count exposure ENTRIES only, so a bridge the '
    + `environment declares and the plan does not was invisible to it. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(authored, 'EXPOSURE_ROLE_IS_DUAL_HOMED').length, 1,
    `And say where the second one came from. ${TRACK_B} (B0)`);
});

test('B0-85: a demoted bridge is reported, never silently rewritten', () => {
  const plan = compile(
    Object.assign({}, EXTERNAL_V3, {
      exposure_plan: [
        { vm_name: 'shop', placement: 'internal' },
        { vm_name: 'web01', placement: 'pivot' },
      ],
    }), roleSpec());
  const shop = plan.hosts.find(h => h.vm_name === 'shop');
  assert.strictEqual(shop.placement, 'internal',
    "The instructor's authored placement stands; it is achievable, because the explicit nics array this "
    + `compile emits wins over the role (lane-networking.js:374-375). ${TRACK_B} (B0)`);
  assert.deepStrictEqual(shop.nics, [{ segment: 'int' }], `${TRACK_B} (B0)`);
  const warn = codeAt(plan, 'PLACEMENT_OVERRIDES_ROLE');
  assert.strictEqual(warn.length, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(warn[0].severity, 'warn',
    'It holds ONLY because the writeback happens, so it is worth saying out loud — but it is a legal '
    + `thing to author, so it is not an error. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.exposure.filter(e => e.placement === 'pivot').map(e => e.vm_name), ['web01'],
    "And no second bridge is invented behind the instructor's back. "
    + `${TRACK_B} (B0)`);
});

test('B0-86: a dmz machine that serves a web site IS the web site', () => {
  // isWebServer's first line is role !== 'server' -> false
  // (profile-to-spec.js:98-99), and 'dmz' is exactly the role a dual-homed web
  // host carries. Asked verbatim, the compile answered "no machine here serves
  // a web site" about the one machine that does, and an external engagement
  // then failed with FOUR errors at once.
  const spec = {
    subnet_scheme: 'v3',
    vms: [
      { name: 'shop', hostname: 'shop', role: 'dmz', type: 'qemu',
        ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] },
      { name: 'dc01', hostname: 'dc01', role: 'server', type: 'qemu',
        ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] },
    ],
  };
  const plan = compile(EXTERNAL_V3, spec);
  assert.ok(plan.public_surface, `${TRACK_B} (B0)`);
  assert.strictEqual(plan.public_surface.target_vm, 'shop', `${TRACK_B} (B0)`);
  assert.strictEqual(plan.public_surface.source, 'asset',
    `The client has a web server in its file; it simply carries the bridge role. ${TRACK_B} (B0)`);
  for (const code of ['SCOPE_EMPTY', 'EXTERNAL_NEEDS_VULN_APP', 'EXTERNAL_NO_SURFACE', 'EXTERNAL_NO_PIVOT']) {
    assert.deepStrictEqual(codeAt(plan, code), [],
      `All four of these fired at once on a spec that HAS a web host. ${TRACK_B} (B0)`);
  }
  assert.strictEqual(PLAN.hasBlockingProblem(plan), false, `${TRACK_B} (B0)`);
  assert.ok(/isWebServer\(\{ hostname, role: webRole, services \}\)/.test(jsCode(read(PLAN_REL))),
    'The coercion happens on the ARGUMENT. isWebServer itself must not be touched: '
    + `${SYNTH_REL} is byte-pinned, and its arity is load-bearing. ${TRACK_B} (B0)`);
});

test('B0-87: public_surface.placement is read from the entry, never asserted', () => {
  // An exposure plan reading [{dc01, internal}] used to make dc01 the surface —
  // storedExposure[0] was the fallback — and then stamp placement:'pivot' onto
  // it with a literal. One plan then said, in two fields at once, that dc01 both
  // IS the dual-homed bridge at .240 and is NOT, at .81. Scope follows the
  // surface, so the real web host was excluded from the engagement built to
  // reach it.
  const plan = compile(
    Object.assign({}, EXTERNAL_V3, { exposure_plan: [{ vm_name: 'dc01', placement: 'internal' }] }),
    specFrom(ASSETS));
  assert.strictEqual(plan.public_surface.target_vm, 'web01',
    "A machine placed 'internal' is by definition the one thing nobody outside can see. "
    + `${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.in_scope, ['web01'], `And scope follows the surface. ${TRACK_B} (B0)`);
  const dc01 = plan.hosts.find(h => h.vm_name === 'dc01');
  assert.strictEqual(dc01.placement, 'internal', `${TRACK_B} (B0)`);
  assert.strictEqual(dc01.ip_octet, SYNTH.SPEC_OCTET_MIN + 1,
    `Single-homed on int, so it keeps its band octet. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.public_surface.placement, null,
    'Nothing places web01, so the honest answer is "no placement" — not a literal claiming it is the '
    + `bridge. ${TRACK_B} (B0)`);
  assert.ok(codeAt(plan, 'EXTERNAL_NO_PIVOT').some(p => p.severity === 'error'),
    `An external engagement with nothing on the outside has no route in. ${TRACK_B} (B0)`);

  const authoredPublic = compile(
    Object.assign({}, EXTERNAL_V3, { exposure_plan: [{ vm_name: 'dc01', placement: 'public' }] }),
    specFrom(ASSETS));
  assert.strictEqual(authoredPublic.public_surface.target_vm, 'dc01',
    "A 'public' entry IS on the outside, so it may be the surface. "
    + `${TRACK_B} (B0)`);
  assert.strictEqual(authoredPublic.public_surface.placement, 'public',
    `And the surface reports the placement it actually has. ${TRACK_B} (B0)`);
});

test('B0-88: the brief never prints an address the lane does not have', () => {
  // THE MOST COMMON ENGAGEMENT THERE IS: type 'default' (internal), a v2 lane,
  // one web asset at a band octet. surface_url was unconditional, so the brief
  // read "runs on web01 (http://{ext_base}.240/)" — on a lane with no ext
  // segment at all, where the .240 pin is gated behind isV3
  // (challenge-lane-deployer.js:768). start_position.url_template was already
  // null for the same plan, which is the proof the claim was never meant to be
  // unconditional.
  const v2 = compile({ engagement_type: 'default', subnet_scheme: 'v2' },
    specFrom(ASSETS, { subnet_scheme: 'v2' }));
  assert.strictEqual(v2.brief.facts.surface_url, null, `${TRACK_B} (B0)`);
  assert.strictEqual(v2.start_position.entry.url_template, null,
    `The two must agree: they describe one address. ${TRACK_B} (B0)`);
  assert.ok(/runs on web01\.$/m.test(v2.brief.suggested_text),
    `The renderer already handles null; the sentence simply stops. ${TRACK_B} (B0)`);

  // External but FLAT: still no ext segment, still no pin.
  const externalV2 = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v2' },
    specFrom(ASSETS, { subnet_scheme: 'v2' }));
  assert.strictEqual(externalV2.brief.facts.surface_url, null, `${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(externalV2, 'PLACEMENT_REQUIRES_V3').length, 1,
    `And the reason is stated as a problem, not left to the reader. ${TRACK_B} (B0)`);

  // The one shape that really does answer at .240.
  const good = compile(EXTERNAL_V3, specFrom(ASSETS));
  assert.strictEqual(good.brief.facts.surface_url, `http://{ext_base}.${PLAN.DUAL_HOMED_OCTET}/`,
    `${TRACK_B} (B0)`);
  assert.strictEqual(good.start_position.entry.url_template, good.brief.facts.surface_url,
    `${TRACK_B} (B0)`);

  // No .240 sentence survives anywhere in a plan that has no .240.
  for (const plan of [v2, externalV2]) {
    assert.ok(!JSON.stringify(plan).includes(`.${PLAN.DUAL_HOMED_OCTET}`),
      'Prose that names an address the plan does not emit is the same defect as emitting the wrong one, '
      + `one layer up. ${TRACK_B} (B0)`);
  }
});

test('B0-89: capacity counts what the DEPLOYER would pin, not what nics alone say', () => {
  const plan = compile(EXTERNAL_V3, roleSpec());
  const dual = plan.hosts.filter(h => h.ip_octet === PLAN.DUAL_HOMED_OCTET).length;
  assert.strictEqual(dual, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(plan.capacity.pinnable, 2,
    "A role 'dmz' host carries no explicit nics, so counting vm.nics alone counted it as pinnable — but "
    + 'the deployer asks resolveVmSegments (challenge-lane-deployer.js:310-311), sees two segments, and '
    + `never writes that reservation. The ceiling was over-stated by one per bridge. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.capacity.pinnable_capacity,
    SYNTH.SPEC_OCTET_MAX - SYNTH.SPEC_OCTET_MIN + 1, `${TRACK_B} (B0)`);
});

test('B0-90: an unrecognised stored placement is announced, not swallowed', () => {
  const plan = compile(
    Object.assign({}, EXTERNAL_V3, {
      exposure_plan: [
        { vm_name: 'web01', placement: 'pivot' },
        { vm_name: 'dc01', placement: 'DMZ-ish' },
      ],
    }), specFrom(ASSETS));
  const warn = codeAt(plan, 'EXPOSURE_PLACEMENT_UNKNOWN');
  assert.strictEqual(warn.length, 1,
    "The column's CHECK constrains SHAPE only — the placement vocabulary is enforced by "
    + 'validateExposurePlan, on the AUTHORING path — so a row written by psql or by an import script '
    + `used to silently rehome a machine with nothing anywhere saying so. ${TRACK_B} (B0)`);
  assert.strictEqual(warn[0].severity, 'warn', `${TRACK_B} (B0)`);
  assert.ok(PLAN.PLAN_PROBLEM_CODES.includes('EXPOSURE_PLACEMENT_UNKNOWN'),
    'A code emitted from one branch and registered nowhere is a code no caller can switch on. '
    + `${TRACK_B} (B0)`);
  const dc01 = plan.exposure.find(e => e.vm_name === 'dc01');
  assert.strictEqual(dc01.placement, 'public',
    "'public' maps to null nics — leave the spec's own default alone — which is the least destructive "
    + `reading of a value nobody can read. ${TRACK_B} (B0)`);
});

test('B0-91: the compile is total for null, not merely for undefined', () => {
  // `= {}` on a destructured parameter fires for undefined ONLY, so
  // compileEngagementPlan(null) threw a bare TypeError — the one input a caller
  // reaches for when it has nothing yet, and exactly the throw this module
  // exists to replace with a problem code. The JSDoc promised totality.
  for (const arg of [null, undefined, 0, '', 'nope', [], NaN]) {
    const plan = PLAN.compileEngagementPlan(arg);
    assert.ok(plan && typeof plan === 'object', `compileEngagementPlan(${String(arg)}). ${TRACK_B} (B0)`);
    assert.deepStrictEqual(codes(plan), ['SPEC_EMPTY'],
      `ONE root cause, ONE problem, for every garbage argument. ${TRACK_B} (B0)`);
    assert.strictEqual(PLAN.hasBlockingProblem(plan), true, `${TRACK_B} (B0)`);
  }
  assert.deepStrictEqual(
    PLAN.compileEngagementPlan(null), PLAN.compileEngagementPlan(undefined),
    `And deterministic across both. ${TRACK_B} (B0)`);
});

test('B0-92: nicsForPlacement is total for an inherited key, not just a known one', () => {
  // PLACEMENT_SEGMENTS is a plain object literal indexed with an untrusted
  // string — the placement arrives from a stored jsonb column and from a route
  // body — so 'constructor', 'toString' and every other Object.prototype key
  // resolved to a FUNCTION: truthy, with no .map, and the call threw a
  // TypeError from the module that is the authority on placements.
  for (const key of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__',
    'isPrototypeOf', 'propertyIsEnumerable', 'nope', '', null, undefined, 42]) {
    assert.strictEqual(MODEL.nicsForPlacement(key), null,
      `nicsForPlacement(${String(key)}) must answer with a value, never an exception. ${TRACK_B} (B0)`);
  }
  assert.deepStrictEqual(MODEL.nicsForPlacement('pivot'), [{ segment: 'ext' }, { segment: 'int' }],
    `And the known placements are unchanged by the guard. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(MODEL.nicsForPlacement('internal'), [{ segment: 'int' }], `${TRACK_B} (B0)`);
  assert.strictEqual(MODEL.nicsForPlacement('public'), null, `${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §16 — RECONCILING THE TWO ROLE FIXES, AND THE CASES NEITHER FIXTURE REACHED
//
// §14 was written against ONE role fixture. These are the shapes that fixture
// cannot express, and each one is a place where the two independent repairs —
// "never stamp a placement on an external role" and "a machine the spec
// dual-homes is always the bridge" — meet and have to agree:
//
//   * TWO machines carrying the bridge role, which is the collision the .240
//     pin cannot survive and which the entry-counting pivot guard could not see.
//   * A bridge-role machine the environment does NOT actually dual-home: an LXC
//     (the qemu guard at lane-networking.js:379) or any lane below v3. It is
//     external by role and single-homed by fact, so it belongs to NEITHER
//     repair — and fell straight through the gap between them.
//   * A machine dual-homed by an EXPLICIT card list rather than by its role,
//     which is rung ONE of resolveVmSegments and beats every inference.
//   * The role comparison's CASE, which lane-networking.js:379 makes with ===.
//   * The bridge that is not the exposed machine, which is the third of the
//     three conditions on the starting URL.
// ════════════════════════════════════════════════════════════════════════════

const DB_REL = `${CIAB}/utils/db.js`;

/** A v3 external engagement, the shape every assertion below is measured in. */
const EXT_V3 = Object.freeze({
  engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v3',
});

/** One v3 spec VM, with only the keys the compile reads. */
function vm(name, role, extra) {
  return Object.assign({ name, hostname: name, role, type: 'qemu', services: [] }, extra || {});
}

test('B0-93: two machines carrying the bridge role is the collision .240 cannot survive', () => {
  // The lane defines exactly ONE dual-homed address. Two 'dmz' machines are a
  // perfectly ordinary thing to draw in the topology editor — nothing there
  // stops it — and the deployer would pin BOTH to .240 on both segments
  // (challenge-lane-deployer.js:768-771), so the second one silently takes an
  // address the first already answers on.
  //
  // This was invisible before: the pivot guard counted exposure ENTRIES, and a
  // machine dual-homed by its ROLE never produced one.
  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('shop', 'dmz', { services: ['80/HTTP'] }),
      vm('mail', 'dmz', { services: ['25/SMTP'] }),
      vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['389/LDAP'] }),
    ],
  });

  assert.deepStrictEqual(
    plan.hosts.filter(h => h.ip_octet === PLAN.DUAL_HOMED_OCTET).map(h => h.vm_name),
    ['shop', 'mail'],
    `Both really would answer at .240 in that lane. ${TRACK_B} (B0)`);
  const err = codeAt(plan, 'EXPOSURE_MULTIPLE_PIVOTS');
  assert.strictEqual(err.length, 1,
    'Neither machine is named by any exposure plan, so a guard that counts exposure entries sees zero '
    + `pivots and reports nothing at all. ${TRACK_B} (B0)`);
  assert.strictEqual(err[0].severity, 'error',
    `The second bridge has nowhere to land, so this is not a matter of taste. ${TRACK_B} (B0)`);
  assert.ok(err[0].message.includes('shop') && err[0].message.includes('mail'),
    `And it must NAME them, or the instructor has to go looking. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.brief.facts.pivot, null,
    `With two answers there is no single bridge to print in the brief. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.brief.facts.surface_url, null,
    `And no single address either. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.hasBlockingProblem(plan), true, `${TRACK_B} (B0)`);
});

test('B0-94: the attack box the topology editor really emits carries no address of its own', () => {
  // public/js/topology/topology-seed.js:203-208 and admin-challenges.js:186,277
  // emit a Kali with role 'attacker' and NO ipOctet — the deploy path owns its
  // addressing, because the gateway firstboot reserves ext .50 for its RDP DNAT
  // (wan0:3389 -> ext .50), which is the same reservation that pushed the
  // dual-homed pin to .240.
  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'dmz', { services: ['80/HTTP'] }), vm('Kali', 'attacker')],
  });
  const kali = plan.hosts.find(h => h.vm_name === 'Kali');
  assert.strictEqual(kali.placement, null, `${TRACK_B} (B0)`);
  assert.strictEqual(kali.nics, null,
    "An explicit card list WINS over every inference, so a proposed [{segment:'int'}] would relocate the "
    + `console off the external segment the moment B2 writes it back. ${TRACK_B} (B0)`);
  assert.strictEqual(kali.ip_octet, null,
    'It declares no octet and the compile invents none: the deploy path decides where the console lives. '
    + `${TRACK_B} (B0)`);
  assert.ok(!plan.exposure.some(e => e.vm_name === 'Kali'),
    `It appears in no exposure plan at all, derived or authored. ${TRACK_B} (B0)`);

  // …and the honest counterpart. resolveSpecAddressing's skip rules
  // (challenge-lane-deployer.js:303-311) are goad / console / lxc / multi-NIC —
  // there is NO role rule — so a spec that really does author an octet on an
  // attack box gets it pinned, and saying 'no address' about it would be the
  // same paper-vs-lane divergence in the other direction.
  const authoredOctet = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'dmz', { services: ['80/HTTP'] }),
      vm('Kali', 'attacker', { ipOctet: SYNTH.SPEC_OCTET_MAX }),
    ],
  });
  assert.strictEqual(
    authoredOctet.hosts.find(h => h.vm_name === 'Kali').ip_octet, SYNTH.SPEC_OCTET_MAX,
    `The deployer would pin it there, so the paper says so. ${TRACK_B} (B0)`);
  assert.strictEqual(authoredOctet.hosts.find(h => h.vm_name === 'Kali').nics, null,
    `Reporting an address is not the same as proposing to move it. ${TRACK_B} (B0)`);
});

test('B0-95: the role comparison is case-sensitive, exactly as the deployer makes it', () => {
  // lane-networking.js:379 compares with ===. A spec carrying 'DMZ' is NOT
  // dual-homed by the deployer, so a case-insensitive mirror here would claim
  // .240 for a machine that lands on a band octet — the paper-vs-lane
  // divergence this module exists to close, introduced by the fix for it.
  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('shop', 'DMZ', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['80/HTTP'] }),
    ],
  });
  const shop = plan.hosts.find(h => h.vm_name === 'shop');
  assert.strictEqual(shop.ip_octet, SYNTH.SPEC_OCTET_MIN + 1,
    "'DMZ' is not 'dmz' to resolveVmSegments, so this machine is single-homed and takes a band octet. "
    + `${TRACK_B} (B0)`);
  assert.notStrictEqual(shop.placement, 'pivot', `${TRACK_B} (B0)`);
  assert.deepStrictEqual(plan.exposure.filter(e => e.placement === 'pivot').map(e => e.vm_name), ['web01'],
    `${TRACK_B} (B0)`);
  assert.ok(/case-SENSITIVE/.test(read(PLAN_REL)) && /lane-networking\.js:379/.test(read(PLAN_REL)),
    `And the mirror must say WHY it is case-sensitive, so nobody "fixes" it. ${TRACK_B} (B0)`);
});

test('B0-96: a bridge-role machine the environment does not dual-home is placed, never dropped', () => {
  // THE GAP BETWEEN THE TWO REPAIRS. "Never stamp a placement on an external
  // role" skipped this machine; "a machine the spec dual-homes is the bridge"
  // did not catch it, because the environment does NOT dual-home it:
  //   * an LXC marked 'dmz' gets ONE external card — the qemu guard on
  //     lane-networking.js:379, which that file's own comment calls load-bearing
  //   * on a v1/v2 lane there is one flat segment and nothing is dual-homed
  // It was left the ONE machine in a derived plan with no placement at all,
  // absent from plan.exposure, while EXPOSURE_DERIVED said every other machine
  // sat on the internal segment.
  const lxc = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('ctr', 'dmz', { type: 'lxc', ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['80/HTTP'] }),
    ],
  });
  const ctr = lxc.hosts.find(h => h.vm_name === 'ctr');
  assert.strictEqual(ctr.placement, 'public',
    "Its role says it belongs outside and the environment gives it exactly one outward card, so 'public' "
    + `is the only reading that is true about both. ${TRACK_B} (B0)`);
  assert.strictEqual(ctr.nics, null,
    "'public' maps to null nics — single-homed on the outside is already what a v3 machine gets — so the "
    + `spec is left alone. ${TRACK_B} (B0)`);
  assert.strictEqual(ctr.ip_octet, null,
    'NOT the band octet it carries in the spec, and NOT .240 — NEITHER address exists in the lane. '
    + 'resolveSpecAddressing hits `continue` on the type before it ever looks at the segments '
    + '(challenge-lane-deployer.js:303), so a container takes no reservation; and the container branch of '
    + 'resolveVmNics returns dualHomed:false, so it is never pinned to .240 either. The synthesizer says '
    + 'the same thing in its own words at profile-to-spec.js:168-172 — "the paper would then name an IP '
    + `nothing lives at — worse than naming none". NO_HOST_ADDRESSING is the warn that covers it. ${TRACK_B} (B0)`);

  // THE ASSERTIONS ABOVE ARE STRUCTURAL, NOT FIXTURE-LUCKY. This fixture also
  // contains a qemu web01, which wins the surface rung first, so every claim
  // about 'ctr' would hold even if the compile had asked no capability question
  // at all. Pin the RULE itself, and pin the case where the container is the
  // ONLY web host in B0-101.
  assert.strictEqual(PLAN.canBeDualHomed({ type: 'lxc', role: 'dmz' }, true), false,
    'The predicate, asked directly: the container gate does not depend on which other machines happen to '
    + `be in the spec. ${TRACK_B} (B0)`);
  assert.ok(lxc.exposure.some(e => e.vm_name === 'ctr'),
    `And it appears in the plan at all. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(lxc.exposure.filter(e => e.placement === 'pivot').map(e => e.vm_name), ['web01'],
    `An LXC cannot be the bridge, so it never becomes a second one. ${TRACK_B} (B0)`);

  // NO MACHINE IS SILENTLY UNPLACED. Every non-attack-box in a derived plan
  // gets a placement, whatever role it carries.
  assert.ok(lxc.hosts.filter(h => h.role !== 'attacker').every(h => h.placement !== null),
    'A derived plan that leaves one machine with no placement is a plan whose own note is false. '
    + `${TRACK_B} (B0)`);

  // The same machine on a flat lane, where nothing is dual-homed at all.
  const flat = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v2' },
    {
      subnet_scheme: 'v2',
      vms: [
        vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
        vm('shop', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['25/SMTP'] }),
      ],
    });
  assert.strictEqual(flat.hosts.find(h => h.vm_name === 'shop').placement, 'public', `${TRACK_B} (B0)`);
  assert.strictEqual(flat.hosts.find(h => h.vm_name === 'shop').ip_octet, SYNTH.SPEC_OCTET_MIN + 1,
    `The .240 pin is gated behind v3, so nothing on a flat lane may claim it. ${TRACK_B} (B0)`);
});

test('B0-97: an explicit card list makes ANY role the bridge — rung one beats rung two', () => {
  // resolveVmSegments' FIRST rung is the authored nics array, and it wins over
  // the role, over the scheme default and over the qemu guard
  // (lane-networking.js:374-375). A compile that read only the ROLE demoted an
  // explicitly dual-homed machine to 'internal' and proposed a ONE-card list for
  // it — which, being explicit, would have won, and taken the second card away.
  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'server', {
        ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'],
        nics: [{ segment: 'ext' }, { segment: 'int' }],
      }),
      vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
    ],
  });
  const web01 = plan.hosts.find(h => h.vm_name === 'web01');
  assert.strictEqual(web01.placement, 'pivot',
    `Two cards is two segments, whatever the role says. ${TRACK_B} (B0)`);
  assert.strictEqual(web01.ip_octet, PLAN.DUAL_HOMED_OCTET,
    'A spec-carried band octet on a dual-homed machine is a true statement about a spec field and a false '
    + `one about the lane: the deployer writes no reservation for it and pins .240. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.capacity.pinnable, 1,
    'And it is out of the .80-.99 band, exactly as challenge-lane-deployer.js:310-311 leaves it. '
    + `${TRACK_B} (B0)`);

  // The same list on a CONTAINER. Rung one really does win in resolveVmSegments
  // — its explicit-nics branch has no qemu guard — and that is exactly how far
  // the old reading got. resolveVmNics is asked NEXT, and its container branch
  // (lane-networking.js:465-471) returns `segments.slice(0, 1)` and
  // `dualHomed: false`: ONE card, on the FIRST segment, whatever the array
  // said. So the deployer never runs the .240 write at :768-772, and :303 has
  // already denied it a band reservation. A 'pivot' here named an address
  // nothing in the lane lives at.
  const container = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('ctr', 'server', {
        type: 'lxc', ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'],
        nics: [{ segment: 'ext' }, { segment: 'int' }],
      }),
      vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: [] }),
    ],
  });
  const ctrHost = container.hosts.find(h => h.vm_name === 'ctr');
  assert.strictEqual(ctrHost.placement, 'public',
    'Rung one wins in resolveVmSegments; the CONTAINER BRANCH of resolveVmNics then takes the second card '
    + `straight back. Two cards asked for is not two cards given. ${TRACK_B} (B0)`);
  assert.strictEqual(ctrHost.nics, null,
    `And nothing is written onto its card list, so the authored array is left exactly as it is. ${TRACK_B} (B0)`);
  assert.strictEqual(ctrHost.ip_octet, null,
    `No .240 and no band reservation — a container has no static address at all. ${TRACK_B} (B0)`);
  assert.strictEqual(container.brief.facts.surface_url, null,
    `So the brief hands the student no address either. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(container, 'EXTERNAL_NO_PIVOT').length, 1,
    'And the engagement is reported as having no bridge, which is the honest answer, rather than compiling '
    + `clean around one that does not exist. ${TRACK_B} (B0)`);

  // AN AUTHORED PLACEMENT THAT CONTRADICTS AN AUTHORED CARD LIST LOSES, AND IS
  // REPORTED.
  //
  // THIS ASSERTION USED TO SAY THE OPPOSITE, and it was wrong for the reason it
  // gave. It read "the instructor's placement stands — it is achievable,
  // because the writeback wins", and the writeback it meant was this compile
  // emitting nics [{segment:'int'}] over an authored [{ext},{int}]. That is
  // precisely the overwrite rung one forbids: `explicit.length` returns before
  // role, type, scheme or lab membership is consulted, so the spec has ALREADY
  // ANSWERED where that machine lives, and a compile that answers differently
  // is not resolving a disagreement, it is deleting one of the two statements.
  //
  // The rule is now general — for EVERY role, not just 'attacker', which is the
  // only role it held for — so the placement is READ off the cards and the
  // disagreement is reported instead of resolved by rewriting.
  const contradicted = compile(
    Object.assign({}, EXT_V3, { exposure_plan: [{ vm_name: 'web01', placement: 'internal' }] }),
    {
      subnet_scheme: 'v3',
      vms: [
        vm('web01', 'server', {
          ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'],
          nics: [{ segment: 'ext' }, { segment: 'int' }],
        }),
      ],
    });
  const contradictedHost = contradicted.hosts.find(h => h.vm_name === 'web01');
  assert.strictEqual(contradictedHost.placement, 'pivot',
    'The card list decides, because the deployer reads the card list. An authored [{ext},{int}] IS two '
    + `segments, and two segments IS the bridge at .240. ${TRACK_B} (B0)`);
  assert.strictEqual(contradictedHost.nics, null,
    'And NOTHING is written back onto it. Emitting a one-card list here was the overwrite that made the '
    + `old reading appear achievable. ${TRACK_B} (B0)`);
  assert.strictEqual(contradictedHost.ip_octet, PLAN.DUAL_HOMED_OCTET,
    `Which is where challenge-lane-deployer.js:768-771 really puts it. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(contradicted, 'PLACEMENT_CONTRADICTS_NICS').length, 1,
    'The disagreement is REPORTED, not resolved by rewriting one side of it. That is the whole difference '
    + `between naming a divergence and creating one. ${TRACK_B} (B0)`);
  assert.ok(/'internal'/.test(codeAt(contradicted, 'PLACEMENT_CONTRADICTS_NICS')[0].message)
    && /'ext'/.test(codeAt(contradicted, 'PLACEMENT_CONTRADICTS_NICS')[0].message),
    `And it shows BOTH statements, or the author cannot tell which to change. ${TRACK_B} (B0)`);
});

test('B0-98: no starting URL when the bridge is not the exposed machine', () => {
  // The third condition on the address. .240 is the DUAL-HOMED machine's
  // address specifically, so a plan whose exposed site is single-homed on ext
  // at a band octet, with some OTHER machine bridging, has no .240 to hand the
  // student — and printing one would send them to the bridge's login instead of
  // the site they were told to test.
  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('bridge', 'dmz', { services: ['22/SSH'] }),
    ],
  });
  assert.strictEqual(plan.public_surface.target_vm, 'web01', `${TRACK_B} (B0)`);
  assert.strictEqual(plan.public_surface.placement, 'public',
    `Exposed, but not the bridge — another machine already is. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.brief.facts.pivot, 'bridge', `${TRACK_B} (B0)`);
  assert.strictEqual(plan.brief.facts.surface_url, null,
    ".240 belongs to 'bridge', so printing it as the site's address points the student at the wrong "
    + `machine. ${TRACK_B} (B0)`);
  assert.strictEqual(plan.start_position.entry.url_template, null,
    `The two read one value, so they cannot disagree. ${TRACK_B} (B0)`);
  assert.ok(!JSON.stringify(plan.brief.facts).includes(`.${PLAN.DUAL_HOMED_OCTET}`),
    `And no sentence in the brief names it either. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(codeAt(plan, 'EXTERNAL_NO_PIVOT'), [],
    `There IS a bridge — that is the whole point of this shape. ${TRACK_B} (B0)`);
});


/**
 * Column -> bound value for an INSERT, read off the statement itself.
 *
 * NOT params[i]. The column list and the VALUES list line up with each other,
 * not with the parameter array: createEngagement's statement carries a LITERAL
 * ('provisioning') in the middle of its VALUES, so the sixth column is the
 * fifth parameter. Zipping the two lists and following the $n is the only
 * reading that catches a swapped binding, which is the one way this repair
 * could be made wrong while still mentioning both column names.
 */
function insertBindings(text, params) {
  const cols = text.match(/\(([\s\S]*?)\)\s*VALUES/)[1]
    .split(',').map(s => s.trim()).filter(Boolean);
  const vals = text.match(/VALUES\s*\(([\s\S]*?)\)/)[1]
    .split(',').map(s => s.trim()).filter(Boolean);
  const out = {};
  cols.forEach((col, i) => {
    const slot = vals[i] || '';
    const ref = slot.match(/^\$(\d+)$/);
    out[col] = ref ? params[Number(ref[1]) - 1] : slot.replace(/^'|'$/g, '');
  });
  return out;
}

test('B0-99: createEngagement really binds the posture, measured on the query itself', async () => {
  // B0-75 reads the source; this RUNS it. utils/db.js keeps its pool in a
  // module-level variable behind setPool, and src/utils/cybercore-db.js exports
  // its pool object, so both can be replaced for the length of one test — which
  // measures the exact statement and parameters that would reach Postgres,
  // including the ORDER of the bindings, and reaches no cluster and no database.
  const db = require(abs(DB_REL));
  const core = require(abs('src/utils/cybercore-db.js'));
  const realCoreQuery = core.cybercorePool.query;
  const calls = [];
  // What utils/db.js does when the plugin loader has not injected a pool. It is
  // the state every other test in this file runs in, and the state this one must
  // hand back.
  const NO_POOL = { on() {}, query() { throw new Error('CIAB database pool not initialized'); } };

  function install(engagementType) {
    calls.length = 0;
    db.setPool({
      on() {},
      async query(text, params) {
        calls.push({ text, params });
        if (/INSERT INTO ciab_engagement/.test(text)) {
          return {
            rows: [Object.assign(
              { engagement_id: 'eng-b0-99', engagement_type: engagementType },
              insertBindings(text, params)
            )],
            rowCount: 1,
          };
        }
        // The detached background provision's FIRST statement. Failing it here
        // ends this test at the row, with no reservation and no cluster call;
        // provisionEngagementNetwork records its own failure and the bare
        // .catch() in createEngagement swallows the rest.
        if (/provision_started_at/.test(text)) throw new Error('no cluster in a unit test');
        return { rows: [], rowCount: 0 };
      },
    });
  }

  // findProfileChallenge (via resolveEngagement -> adoptExistingReservation)
  // reaches the CyberCore pool, which is a real pg Pool built at module load.
  // Left alone it opens a socket to the configured host — a unit test that
  // needs a network is a unit test that fails on someone else's machine.
  core.cybercorePool.query = async () => ({ rows: [], rowCount: 0 });

  try {
    install('external_blackbox');
    const external = await PROVISION.createEngagement({
      profileId: 'prof-b0', engagementType: 'external_blackbox', subnetScheme: 'v3', maxStudents: 4,
    });
    const insert = calls.find(c => /INSERT INTO ciab_engagement/.test(c.text));
    assert.ok(insert, `createEngagement must still INSERT a row. ${TRACK_B} (B0)`);
    const bound = insertBindings(insert.text, insert.params);

    assert.strictEqual(bound.perspective, 'external',
      'Both posture columns are NOT NULL with a DEFAULT, so leaving them out of the INSERT stores an '
      + 'external engagement as INTERNAL permanently — a legal value nothing downstream can tell from an '
      + 'authored one, and one no read-time fallback can ever correct, because there is no null to fall '
      + `back FROM. ${TRACK_B} (B0)`);
    assert.strictEqual(bound.credential_posture, 'none',
      `Black-box means no accounts, and the registry is the authority for that. ${TRACK_B} (B0)`);
    assert.strictEqual(bound.provision_status, 'provisioning',
      'Read by zipping the column list with the VALUES list, so the literal in the middle cannot shift '
      + `the two posture bindings by one and go unnoticed. ${TRACK_B} (B0)`);
    assert.strictEqual(bound.engagement_type, 'external_blackbox', `${TRACK_B} (B0)`);
    assert.strictEqual(external.perspective, 'external',
      `And the row the create route returns says so too. ${TRACK_B} (B0)`);

    install('internal_credentialed');
    const cred = await PROVISION.createEngagement({
      profileId: 'prof-b0', engagementType: 'internal_credentialed', subnetScheme: 'v2', maxStudents: 4,
    });
    assert.strictEqual(cred.perspective, 'internal', `${TRACK_B} (B0)`);
    assert.strictEqual(cred.credential_posture, 'credentialed',
      `The other half of the pair, and the other half of the defect. ${TRACK_B} (B0)`);

    // NO BEHAVIOUR CHANGE where the DEFAULTs were already right. describeEngagementType
    // is total, so the default type and an unknown slug both yield exactly the
    // pair the columns already assign.
    for (const slug of ['default', 'some-custom-slug']) {
      install(slug);
      const plain = await PROVISION.createEngagement({
        profileId: 'prof-b0', engagementType: slug, subnetScheme: 'v2', maxStudents: 4,
      });
      assert.strictEqual(plain.perspective, 'internal', `${slug}. ${TRACK_B} (B0)`);
      assert.strictEqual(plain.credential_posture, 'none', `${slug}. ${TRACK_B} (B0)`);
    }
  } finally {
    core.cybercorePool.query = realCoreQuery;
    db.setPool(NO_POOL);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §16 THE CAPABILITY QUESTION
//
// Every defect below is ONE defect wearing five hats: a placement decided
// WITHOUT asking whether the deploy path can actually carry it out for that
// particular machine. The compile already knew the deployer's rules —
// laneAddressing exists for exactly this — and then four of the five writers
// did not route through it.
//
// The two gates, from the deployer's own source:
//   * a CONTAINER is given ONE card on the FIRST segment, whatever it asked
//     for (lane-networking.js:465-471, dualHomed:false + segments.slice(0,1)),
//     and takes no band reservation at all (challenge-lane-deployer.js:303)
//   * the .240 pin sits behind `if (isV3)` (challenge-lane-deployer.js:768)
// Neither gate alone is enough, and neither is optional.
// ════════════════════════════════════════════════════════════════════════════

test('B0-100: one predicate answers "can this machine be the bridge?", and everything asks it', () => {
  // TOTAL, and asked DIRECTLY rather than inferred from a fixture.
  assert.strictEqual(PLAN.canBeDualHomed({ type: 'qemu', role: 'dmz' }, true), true,
    `A v3 qemu machine is the one shape the deployer really dual-homes. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.canBeDualHomed({ type: 'lxc', role: 'dmz' }, true), false,
    `The container gate. ${TRACK_B} (B0)`);
  assert.strictEqual(
    PLAN.canBeDualHomed({ type: 'lxc', nics: [{ segment: 'ext' }, { segment: 'int' }] }, true), false,
    'An explicit two-card list does NOT survive the container branch — it wins in resolveVmSegments and is '
    + `then truncated by resolveVmNics. ${TRACK_B} (B0)`);
  assert.strictEqual(PLAN.canBeDualHomed({ type: 'qemu', role: 'dmz' }, false), false,
    `The isV3 gate: on a flat lane the .240 write never runs. ${TRACK_B} (B0)`);
  for (const junk of [null, undefined, {}, 'nope', 42, []]) {
    assert.strictEqual(typeof PLAN.canBeDualHomed(junk, true), 'boolean',
      `The compile is TOTAL, and so is every predicate inside it. ${TRACK_B} (B0)`);
    assert.strictEqual(typeof PLAN.canBeDualHomed(junk, junk), 'boolean', `${TRACK_B} (B0)`);
  }

  // THE MIRROR CANNOT DRIFT — the same guard shape as B0-81/82. Neither
  // authority can be imported (both graphs reach site-config.js:29-30's
  // unguarded read of config/site.json, absent here), so the predicate is
  // asserted against the authorities' own TEXT.
  const core = jsCode(read(LANE_NETWORKING_REL));
  assert.ok(/segments: segments\.slice\(0, 1\),\s*\n\s*dualHomed: false,/.test(core),
    'lane-networking.js resolveVmNics: the container branch returns ONE segment and dualHomed:false. If '
    + `that ever changes, canBeDualHomed's type gate must change in the same commit. ${TRACK_B} (B0)`);
  const deployer = jsCode(read(DEPLOYER_REL));
  assert.ok(/if \(\(vmSpec\.type \|\| 'qemu'\) === 'lxc'\) continue;/.test(deployer),
    `challenge-lane-deployer.js:303 — a container takes no band reservation either. ${TRACK_B} (B0)`);
  assert.ok(/if \(segs\.length > 1\) continue;/.test(deployer),
    `challenge-lane-deployer.js:310-311 — and neither does anything asking for two segments. ${TRACK_B} (B0)`);
  assert.ok(/if \(dualHomed\) \{/.test(deployer) && /if \(isV3\) \{/.test(deployer)
    && /ip=\$\{net\.lanExt\.base3\}\.\$\{DUAL_HOMED_OCTET\}\/24/.test(deployer),
    'challenge-lane-deployer.js:758-772 — the .240 write is gated on dualHomed AND on isV3. BOTH. Neither '
    + `alone. ${TRACK_B} (B0)`);
  // The deployer stopped spelling the octet inline: resolveLaneDnsExtras now
  // publishes the company's web name AT that address, so the clone path and the
  // DNS table read ONE named constant rather than two literals that can drift.
  // The value is still pinned here, because "gated on both" is only half the
  // claim — the address the gates guard has to be .240.
  assert.ok(/const DUAL_HOMED_OCTET = 240;/.test(deployer),
    `challenge-lane-deployer.js — and the constant those gates write is .240. ${TRACK_B} (B0)`);
  const planSrc = read(PLAN_REL);
  assert.ok(/lane-networking\.js:465-471/.test(planSrc) && /challenge-lane-deployer\.js:303/.test(planSrc)
    && /challenge-lane-deployer\.js:768/.test(planSrc),
    `The predicate must carry the file:line of every rule it encodes. ${TRACK_B} (B0)`);

  // NO EMITTED PLAN MAY CONTRADICT ITSELF ABOUT .240. Swept over every fixture
  // the registry sweeps, because the defect was never in one branch — it was in
  // the branches that forgot to ask.
  for (const p of everyFixturePlan()) {
    for (const e of p.exposure) {
      if (e.ip_octet !== PLAN.DUAL_HOMED_OCTET) continue;
      assert.strictEqual(e.placement, 'pivot',
        `.${PLAN.DUAL_HOMED_OCTET} is the dual-homed address and nothing else's. ${TRACK_B} (B0)`);
    }
    for (const h of p.hosts) {
      if (!Array.isArray(h.nics) || h.nics.length < 2) continue;
      assert.strictEqual(h.ip_octet, PLAN.DUAL_HOMED_OCTET,
        'A machine this plan gives two cards is a machine the lane pins to .240. A plan that proposes the '
        + `cards and then names a band octet is describing two different machines. ${TRACK_B} (B0)`);
      assert.strictEqual(h.placement, 'pivot', `${TRACK_B} (B0)`);
    }
  }
});

test('B0-101: a container web host is never made the bridge, whatever its role says', () => {
  // THE FIXTURE IS THE POINT. The container is the ONLY web host, so it wins
  // the surface rung outright and nothing else can quietly satisfy the
  // assertion on its behalf — which is precisely what B0-96's fixture, with its
  // qemu web01, used to do.
  //
  // Unguarded, the derived rung read `surfaceIsSpecPivot || nothing else is
  // dual-homed` and nothing more, and stamped 'pivot', nics [{ext},{int}] and
  // ip_octet 240. The brief then opened with http://{ext_base}.240/ — an
  // address nothing in that lane lives at, because resolveVmNics gives a
  // container one card and resolveSpecAddressing gives it no reservation.
  for (const role of ['server', 'dmz']) {
    const plan = compile(EXT_V3, {
      subnet_scheme: 'v3',
      vms: [
        vm('web01', role, { type: 'lxc', ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
        vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
      ],
    });
    const where = `role='${role}'.`;
    const web01 = plan.hosts.find(h => h.vm_name === 'web01');

    assert.strictEqual(plan.public_surface.target_vm, 'web01',
      `${where} It IS the exposed site — it is the only web host there is. ${TRACK_B} (B0)`);
    assert.strictEqual(web01.placement, 'public',
      `${where} Reachable from the outside, but not the bridge: it cannot be given two cards. ${TRACK_B} (B0)`);
    assert.strictEqual(web01.nics, null,
      `${where} 'public' maps to null nics, so B2's writeback leaves the spec alone. ${TRACK_B} (B0)`);
    assert.strictEqual(web01.ip_octet, null,
      `${where} No .240, and no band octet either — a container gets neither. ${TRACK_B} (B0)`);
    assert.strictEqual(plan.brief.facts.surface_url, null,
      `${where} And the brief names no address rather than one nothing answers on. ${TRACK_B} (B0)`);
    assert.strictEqual(plan.start_position.entry.url_template, null,
      `${where} The two must be ONE computation. ${TRACK_B} (B0)`);
    assert.ok(!plan.exposure.some(e => e.placement === 'pivot'),
      `${where} Nothing in this environment can bridge, so nothing claims to. ${TRACK_B} (B0)`);
    assert.strictEqual(codeAt(plan, 'EXTERNAL_NO_PIVOT').length, 1,
      `${where} Which is an ERROR worth blocking on, not a silent fiction. ${TRACK_B} (B0)`);
    assert.ok(!JSON.stringify(plan.hosts).includes(`"ip_octet":${PLAN.DUAL_HOMED_OCTET}`),
      `${where} .240 appears nowhere in the host list. ${TRACK_B} (B0)`);
  }

  // IT IS THE TYPE, NOT THE ROLE. The identical spec with the container swapped
  // for a full virtual machine is the ordinary, working engagement, unchanged.
  const qemu = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
    ],
  });
  assert.strictEqual(qemu.hosts.find(h => h.vm_name === 'web01').placement, 'pivot', `${TRACK_B} (B0)`);
  assert.strictEqual(qemu.hosts.find(h => h.vm_name === 'web01').ip_octet, PLAN.DUAL_HOMED_OCTET,
    `${TRACK_B} (B0)`);
  assert.strictEqual(qemu.brief.facts.surface_url, `http://{ext_base}.${PLAN.DUAL_HOMED_OCTET}/`,
    `The repair narrows nothing that was already true. ${TRACK_B} (B0)`);

  // An AUTHORED 'pivot' on a container is demoted and REPORTED — never honoured
  // silently, and never dropped.
  const authored = compile(
    Object.assign({}, EXT_V3, { exposure_plan: [{ vm_name: 'ctr', placement: 'pivot' }] }),
    {
      subnet_scheme: 'v3',
      vms: [
        vm('ctr', 'server', { type: 'lxc', ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
        vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: [] }),
      ],
    });
  const hit = codeAt(authored, 'PIVOT_NOT_DEPLOYABLE');
  assert.strictEqual(hit.length, 1,
    `The instructor asked for something the deploy path cannot do, and is told so. ${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'warn',
    'A WARNING: the intent — "this one faces outward" — is achievable and is kept. Only the bridging half '
    + `is not. ${TRACK_B} (B0)`);
  assert.strictEqual(authored.hosts.find(h => h.vm_name === 'ctr').placement, 'public',
    `Demoted, not dropped. ${TRACK_B} (B0)`);
  assert.strictEqual(authored.hosts.find(h => h.vm_name === 'ctr').ip_octet, null, `${TRACK_B} (B0)`);
  assert.strictEqual(authored.hosts.find(h => h.vm_name === 'ctr').nics, null, `${TRACK_B} (B0)`);
});

test('B0-102: a flat-lane external surface never claims a bridge or an address it cannot have', () => {
  // On v1/v2 there is ONE lan0 (lane-networking.js:381) and the .240 write is
  // gated behind isV3 (challenge-lane-deployer.js:768). The compile used to
  // stamp 'pivot' and nics [{ext},{int}] on the surface while hosts[].ip_octet
  // kept the spec band octet — two statements about one machine that cannot
  // both be true, with capacity.pinnable already reporting the disagreement.
  const plan = compile(
    { engagement_type: 'external_blackbox', perspective: 'external', subnet_scheme: 'v2' },
    {
      subnet_scheme: 'v2',
      vms: [
        vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
        vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
      ],
    });
  const web01 = plan.hosts.find(h => h.vm_name === 'web01');

  assert.strictEqual(web01.placement, 'public',
    `There is no second segment to bridge to, so nothing is called the bridge. ${TRACK_B} (B0)`);
  assert.strictEqual(web01.nics, null,
    "Writing [{ext},{int}] onto a v2 spec is worse than useless: resolveVmNics would call bridgeFor('ext') "
    + `on a lane that has only lan0, and THROW. ${TRACK_B} (B0)`);
  assert.strictEqual(web01.ip_octet, SYNTH.SPEC_OCTET_MIN,
    'Single-homed and qemu, so it really does take its band reservation — which is the octet the plan may '
    + `name, and the ONLY one. ${TRACK_B} (B0)`);
  assert.notStrictEqual(web01.ip_octet, PLAN.DUAL_HOMED_OCTET, `${TRACK_B} (B0)`);
  assert.strictEqual(plan.brief.facts.surface_url, null, `${TRACK_B} (B0)`);

  // THE PLAN NO LONGER DISAGREES WITH ITSELF. capacity.pinnable counts this
  // machine, and hosts[].ip_octet names the address that count implies.
  assert.strictEqual(plan.capacity.pinnable, 2,
    'Both machines are single-homed qemu on a flat lane, so both are in the band — and hosts[].ip_octet '
    + `must agree with that count, machine for machine. ${TRACK_B} (B0)`);
  for (const h of plan.hosts) {
    assert.notStrictEqual(h.ip_octet, PLAN.DUAL_HOMED_OCTET,
      `Nothing on a flat lane is pinned to .240 by anything. ${TRACK_B} (B0)`);
  }

  // AND THE EXISTING SIGNAL SURVIVES. PLACEMENT_REQUIRES_V3 is a statement
  // about what the engagement ASKED FOR, so demoting the pivot must not delete
  // the evidence of the mistake — B0-37 pins the authored form of this.
  assert.strictEqual(codeAt(plan, 'PLACEMENT_REQUIRES_V3').length, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(plan, 'PIVOT_NOT_DEPLOYABLE').length, 0,
    'ONE ROOT CAUSE, ONE PROBLEM. PLACEMENT_REQUIRES_V3 already names the scheme and offers the fix; a '
    + `second warning saying the same thing leaves a reader deciding which to act on. ${TRACK_B} (B0)`);
});

test('B0-103: the attack box keeps its authored card ORDER, and is placed nowhere', () => {
  // The role guard existed at ONE call site — the derived-exposure loop. The
  // appender for machines the SPEC dual-homes had none, so an 'attacker' host
  // carrying an explicit [{int},{ext}] list was stamped 'pivot' and handed the
  // CANONICAL [{ext},{int}]: the deployer's nets flipped from
  // {net0:vnet-int, net1:vnet-ext} to {net0:vnet-ext, net1:vnet-int}.
  const spec = {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('kali', 'attacker', { nics: [{ segment: 'int' }, { segment: 'ext' }] }),
    ],
  };
  const plan = compile(EXT_V3, spec);
  const kali = plan.hosts.find(h => h.vm_name === 'kali');

  assert.strictEqual(kali.placement, null,
    "Reading (a): this compile can never place the tester's console. The deploy path owns its addressing. "
    + `${TRACK_B} (B0)`);
  assert.strictEqual(kali.nics, null,
    'And it proposes no card list for it, so B2 writes nothing and the authored ORDER stays whatever its '
    + `author made it. ${TRACK_B} (B0)`);
  assert.ok(!plan.exposure.some(e => e.vm_name.toLowerCase() === 'kali'),
    `It is absent from the exposure list entirely. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(spec.vms[1].nics, [{ segment: 'int' }, { segment: 'ext' }],
    `The compile is PURE: it did not touch the spec it was handed, in order or in content. ${TRACK_B} (B0)`);

  // BUT THE COLLISION IS NOT SWALLOWED. The environment really does home it on
  // both segments, which really does pin it to .240 — the bridge's address —
  // while the gateway image still publishes wan0:3389 -> ext .50 for it.
  const hit = codeAt(plan, 'ATTACKER_IS_DUAL_HOMED');
  assert.strictEqual(hit.length, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'error',
    `Two machines answering at one address is a lane that cannot work. ${TRACK_B} (B0)`);

  // THE MODULE'S OWN PROMISE, HELD. It is written down; it must be true.
  const src = read(PLAN_REL);
  assert.ok(/placed NOWHERE at all/.test(src),
    `The promise stays in the source, so the next reader can check it. ${TRACK_B} (B0)`);
  assert.strictEqual((src.match(/(?:===|!==) ATTACKER_ROLE/g) || []).length, 3,
    'THREE writers can stamp a placement — the authored path, the derived loop, and the appender for '
    + 'machines the spec dual-homes — and the invariant has to hold at all three. A guard at one call site '
    + `is not an invariant; it is a coincidence. ${TRACK_B} (B0)`);
});

test('B0-104: an authored placement naming the attack box is reported and ignored', () => {
  // The authored path had NO role check at all. exposure_plan
  // [{vm_name:'kali', placement:'internal'}] on a role 'attacker' host yielded
  // placement 'internal' and nics [{segment:'int'}] — and an explicit card list
  // WINS over every inference (lane-networking.js:374-375), so after B2's
  // writeback resolveVmSegments would go from ['ext'] to ['int'], stranding the
  // baked wan0:3389 -> ext .50 rule and leaving the lane with no way in. No
  // problem code fired at all.
  for (const placement of ['internal', 'public', 'pivot']) {
    const plan = compile(
      Object.assign({}, EXT_V3, { exposure_plan: [{ vm_name: 'kali', placement }] }),
      {
        subnet_scheme: 'v3',
        vms: [
          vm('web01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
          vm('kali', 'attacker', {}),
        ],
      });
    const where = `placement='${placement}'.`;
    const kali = plan.hosts.find(h => h.vm_name === 'kali');

    const hit = codeAt(plan, 'EXPOSURE_ATTACKER_NOT_PLACED');
    assert.strictEqual(hit.length, 1,
      `${where} An instructor doing this must be TOLD, the way PLACEMENT_OVERRIDES_ROLE already tells them `
      + `about a demoted bridge. Silence was the defect. ${TRACK_B} (B0)`);
    assert.strictEqual(hit[0].severity, 'warn', `${where} ${TRACK_B} (B0)`);
    assert.strictEqual(kali.placement, null,
      `${where} And the entry is IGNORED, not honoured. ${TRACK_B} (B0)`);
    assert.strictEqual(kali.nics, null, `${where} ${TRACK_B} (B0)`);
    assert.ok(!plan.exposure.some(e => e.vm_name.toLowerCase() === 'kali'),
      `${where} Filtered at the single point the authored plan ENTERS the compile, so no later reader — `
      + `surface, placement, octets, pivot count — can see it. ${TRACK_B} (B0)`);
    // And it never becomes the SURFACE, which is the reader that runs FIRST and
    // would otherwise have named the console as the exposed site.
    assert.strictEqual(plan.public_surface.target_vm, 'web01', `${where} ${TRACK_B} (B0)`);
  }
});

test('B0-105: a role that is an outside role except for its casing says so', () => {
  // topology-editor.js:318 renders Role as a FREE-TEXT input, so 'DMZ' is a
  // plausible entry. The comparison stays case-SENSITIVE — lane-networking.js:379
  // uses ===, and B0-95 pins that — but a 'DMZ' web host then produced FOUR
  // errors at once (SCOPE_EMPTY, EXTERNAL_NEEDS_VULN_APP, EXTERNAL_NO_SURFACE,
  // EXTERNAL_NO_PIVOT) with nothing anywhere naming the cause.
  assert.ok(/type="text"/.test(read('public/js/topology/topology-editor.js')),
    `Role is free text in the editor, which is why this diagnostic has a subject at all. ${TRACK_B} (B0)`);

  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'DMZ', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
    ],
  });
  const hit = codeAt(plan, 'ROLE_CASE_MISMATCH');
  assert.strictEqual(hit.length, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'warn', `${TRACK_B} (B0)`);
  assert.ok(/'DMZ'/.test(hit[0].message) && /'dmz'/.test(hit[0].message),
    `It must show BOTH spellings, or it is not a diagnostic — it is a restatement. ${TRACK_B} (B0)`);
  assert.ok(hit[0].message.includes('web01'),
    `And name the machine. ${TRACK_B} (B0)`);
  assert.ok(PLAN.PLAN_PROBLEM_CODES.includes('ROLE_CASE_MISMATCH'),
    `A code no caller can handle is a code nobody sees. ${TRACK_B} (B0)`);

  // THE CASE-SENSITIVITY IS UNCHANGED. The four errors are still exactly right
  // about the environment as authored; what is new is being told WHY.
  const seen = codes(plan);
  for (const c of ['SCOPE_EMPTY', 'EXTERNAL_NEEDS_VULN_APP', 'EXTERNAL_NO_SURFACE', 'EXTERNAL_NO_PIVOT']) {
    assert.ok(seen.includes(c),
      `The behaviour is not being loosened, only explained. ${c}. ${TRACK_B} (B0)`);
  }
  assert.strictEqual(plan.hosts.find(h => h.vm_name === 'web01').ip_octet, SYNTH.SPEC_OCTET_MIN,
    `'DMZ' is not 'dmz' to resolveVmSegments, so it is single-homed and takes a band octet. ${TRACK_B} (B0)`);
  assert.notStrictEqual(plan.hosts.find(h => h.vm_name === 'web01').placement, 'pivot', `${TRACK_B} (B0)`);

  // BOTH outside roles, and only a CASE difference.
  const attacker = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('kali', 'Attacker', {}),
    ],
  });
  assert.strictEqual(codeAt(attacker, 'ROLE_CASE_MISMATCH').length, 1,
    `'Attacker' is not the console role either, and that has consequences of its own. ${TRACK_B} (B0)`);

  // NOT a diagnostic for a role that is simply not an outside role.
  const ordinary = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [
      vm('web01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      vm('ws01', 'workstation', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: [] }),
    ],
  });
  assert.strictEqual(codeAt(ordinary, 'ROLE_CASE_MISMATCH').length, 0,
    'It fires ONLY on a role that differs from a known outside role by case alone. Anything broader is '
    + `noise on every ordinary engagement. ${TRACK_B} (B0)`);
});

// ════════════════════════════════════════════════════════════════════════════
// §15 — THE MIRROR IS COMPLETE, AND ITS COMPLETENESS IS CHECKABLE
//
// THREE ROUNDS OF ADVERSARIAL REVIEW FOUND THREE SEPARATE INCOMPLETE-MIRROR
// BUGS. Not three unrelated defects — one defect, three times:
//
//   round 1   the mirror knew role 'dmz' but not the qemu guard on it
//   round 2   the mirror knew the segments but not resolveVmNics' container
//             branch, so a container was stamped 'pivot' at .240
//   round 3   the mirror omitted the isGoadVm rung outright, on the reasoning
//             that one segment behaves like one segment — while
//             challenge-lane-deployer.js:315 picks the SUBNET BASE off exactly
//             which one it is
//
// Every one of those shipped a plan that stated an address the deployer would
// not produce, which is the single failure mode this module exists to prevent.
// The existing guards (B0-81/82/100) pin individual RULES; each was written
// after a rule went missing, and none of them could have caught the next one.
//
// THIS SECTION PINS THE MIRROR'S COMPLETENESS AS A PROPERTY. The authority's
// own rungs are COUNTED, and the count is compared with a registry that must be
// extended by hand. A rung dropped from the mirror fails. A rung ADDED upstream
// fails. Neither can reach a user as a confidently wrong address.
// ════════════════════════════════════════════════════════════════════════════

const GOAD_DEPLOY_REL = 'src/utils/goad-deploy.js';

/** A whole top-level function, comments and all, from RAW source. */
function rawFn(src, name) {
  const m = src.match(new RegExp(`\\nfunction ${name}\\(([\\s\\S]*?)\\r?\\n\\}\\r?\\n`));
  return m ? m[0] : null;
}

/**
 * THE RUNG REGISTRY. One entry per rung of resolveVmSegments, in the
 * authority's own order. This array is the thing that must be edited by hand
 * when the authority changes, and every assertion below is measured against
 * its LENGTH — which is what makes an omission a failure rather than a silence.
 */
const SEGMENT_RUNGS = Object.freeze([
  {
    n: 1,
    what: 'explicit vmSpec.nics WINS OUTRIGHT, in authored order',
    authority: /if \(explicit\.length\) return explicit\.map\(n => String\(n\.segment\)\);/,
    // Byte-identical to the authority on purpose: the mirror used str(), which
    // trims and maps null to an empty string, so three nics shapes diverged --
    // a segment of whitespace, and 0 / false. A mirror is only worth having if
    // it is wrong in exactly the same places the authority is.
    mirror: /if \(explicit\.length\) return explicit\.map\(n => String\(n\.segment\)\);/,
  },
  {
    n: 2,
    what: "v3 AND role 'dmz' AND type !== 'lxc' -> ['ext','int']",
    authority: /if \(isV3 && vmSpec\?\.role === 'dmz' && type !== 'lxc'\) return \['ext', 'int'\];/,
    mirror: /if \(isV3 && spec\.role === PIVOT_ROLE && type !== 'lxc'\) return \['ext', 'int'\];/,
  },
  {
    n: 3,
    what: "v3 AND isGoadVm -> ['int'] — a DIFFERENT single segment from rung 4",
    authority: /if \(isV3 && isGoadVm\) return \['int'\];/,
    mirror: /if \(isV3 && isGoadVm === true\) return \['int'\];/,
  },
  {
    n: 4,
    what: "otherwise ['ext'] on v3, ['lan'] on v1/v2",
    authority: /return \[isV3 \? 'ext' : 'lan'\];/,
    mirror: /return \[isV3 \? 'ext' : 'lan'\];/,
  },
]);

test('B0-106: MIRROR COMPLETENESS — every rung of resolveVmSegments is reproduced, in order', () => {
  const coreFn = rawFn(read(LANE_NETWORKING_REL), 'resolveVmSegments');
  assert.ok(coreFn, `${LANE_NETWORKING_REL} must still declare resolveVmSegments. ${TRACK_B} (B0)`);
  const mirrorFn = rawFn(read(PLAN_REL), 'resolveSpecVmSegments');
  assert.ok(mirrorFn, `${PLAN_REL} must still declare resolveSpecVmSegments. ${TRACK_B} (B0)`);

  // ── 1. THE COUNTS ────────────────────────────────────────────────────────
  // A rung is a `return`. Counting them on BOTH sides, against a registry that
  // only a human can extend, is what makes an OMISSION fail: the round-3 bug
  // was a mirror with three returns where the authority has four, and every
  // guard in §14 passed on it.
  const coreReturns = (jsCode(coreFn).match(/\breturn\b/g) || []).length;
  assert.strictEqual(coreReturns, SEGMENT_RUNGS.length,
    `resolveVmSegments has ${coreReturns} rungs and this registry describes ${SEGMENT_RUNGS.length}. A rung `
    + 'was ADDED or REMOVED upstream. Do not adjust this number until the mirror in engagement-plan.js '
    + `reproduces the new rung and SEGMENT_RUNGS describes it. ${TRACK_B} (B0)`);
  const mirrorReturns = (jsCode(mirrorFn).match(/\breturn\b/g) || []).length;
  assert.strictEqual(mirrorReturns, SEGMENT_RUNGS.length,
    `The mirror has ${mirrorReturns} rungs where the authority has ${SEGMENT_RUNGS.length}. A MISSING RUNG `
    + 'is not a cosmetic gap: rungs 3 and 4 both return one segment and a DIFFERENT one, and '
    + 'challenge-lane-deployer.js:315 reads the subnet base off exactly which. That omission shipped once '
    + `already. ${TRACK_B} (B0)`);

  // ── 2. RUNG FOR RUNG, ON BOTH SIDES ──────────────────────────────────────
  for (const rung of SEGMENT_RUNGS) {
    assert.ok(rung.authority.test(jsCode(coreFn)),
      `AUTHORITY rung ${rung.n}/${SEGMENT_RUNGS.length} (${rung.what}) is no longer written the way this `
      + `guard reads it. The authority changed; the mirror must change with it. ${TRACK_B} (B0)`);
    assert.ok(rung.mirror.test(jsCode(mirrorFn)),
      `MIRROR rung ${rung.n}/${SEGMENT_RUNGS.length} (${rung.what}) is missing or rewritten. ${TRACK_B} (B0)`);
    // The marker is a COMMENT, so it is read from raw source. It exists so the
    // next reader of the mirror can see at a glance that a rung is numbered
    // out of a known total, rather than counting ifs.
    assert.ok(new RegExp(`MIRROR RUNG ${rung.n}/${SEGMENT_RUNGS.length}`).test(mirrorFn),
      `Rung ${rung.n} must carry its 'MIRROR RUNG ${rung.n}/${SEGMENT_RUNGS.length}' marker. ${TRACK_B} (B0)`);
  }

  // ── 3. THE ORDER, MEASURED AS POSITIONS ──────────────────────────────────
  // Rung 2 above rung 3 is not a detail: a lab host carrying the bridge role IS
  // dual-homed, and swapping them would put it on one internal card instead.
  const at = (re, text) => text.search(re);
  const coreCode = jsCode(coreFn);
  const mirrorCode = jsCode(mirrorFn);
  for (let i = 1; i < SEGMENT_RUNGS.length; i += 1) {
    assert.ok(at(SEGMENT_RUNGS[i - 1].authority, coreCode) < at(SEGMENT_RUNGS[i].authority, coreCode),
      `Authority rung ${i} must precede rung ${i + 1}. ${TRACK_B} (B0)`);
    assert.ok(at(SEGMENT_RUNGS[i - 1].mirror, mirrorCode) < at(SEGMENT_RUNGS[i].mirror, mirrorCode),
      `Mirror rung ${i} must precede rung ${i + 1} — precedence is the whole content of this function. `
      + `${TRACK_B} (B0)`);
  }

  // ── 4. EXERCISED, NOT MERELY GREPPED ─────────────────────────────────────
  // A source scan proves a rung is WRITTEN. Only calling it proves it is
  // REACHED, with the right answer, in the right order.
  const seg = PLAN.resolveSpecVmSegments;
  assert.deepStrictEqual(seg({ nics: [{ segment: 'int' }, { segment: 'ext' }], role: 'dmz' }, true, true),
    ['int', 'ext'],
    `Rung 1 beats rungs 2, 3 and 4, and returns the AUTHORED ORDER unchanged. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(seg({ role: 'dmz', type: 'qemu' }, true, true), ['ext', 'int'],
    `Rung 2 beats rung 3: the bridge role wins over lab membership. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(seg({ role: 'dmz', type: 'lxc' }, true, true), ['int'],
    `The qemu guard sends an LXC past rung 2 — and then rung 3 catches it. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(seg({ role: 'server' }, true, true), ['int'],
    `Rung 3 beats rung 4, and returns a DIFFERENT segment from it. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(seg({ role: 'server' }, true, false), ['ext'],
    `Rung 4 on v3. This is the answer rung 3 was once assumed to be equivalent to. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(seg({ role: 'server' }, false, true), ['lan'],
    `Rung 3 is v3-only, so a lab host on a flat lane falls to rung 4. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(seg({ role: 'dmz', type: 'qemu' }, false, false), ['lan'],
    `And so is rung 2. ${TRACK_B} (B0)`);
  assert.notDeepStrictEqual(seg({ role: 'server' }, true, true), seg({ role: 'server' }, true, false),
    'THE SENTENCE THAT COST THREE ROUNDS: rungs 3 and 4 do NOT return the same thing. One segment is not '
    + `one segment. ${TRACK_B} (B0)`);

  // ── 5. AND THE IMPORT LIST IS STILL FIVE ─────────────────────────────────
  assert.strictEqual((read(PLAN_REL).match(/require\(/g) || []).length, 5,
    `Mirroring exists to keep the import list at five. ${TRACK_B} (B0)`);
});

test('B0-107: isGoadVm is decided OFFLINE, and the lab table cannot drift', () => {
  // THE QUESTION THE ROUND-3 FIX HAD TO ANSWER FIRST: can the compile know
  // whether the deployer will call a machine a lab host, without a lane, a
  // database or a Proxmox call? It can, and this test is the proof — the whole
  // decision is source text.
  const goad = jsCode(read(GOAD_DEPLOY_REL));
  const deployer = jsCode(read(DEPLOYER_REL));

  assert.ok(/const goadVm\s*=\s*goadMacs\[vmName\];/.test(deployer)
    && /const isGoadVm\s*=\s*!!goadVm;/.test(deployer),
    'isGoadVm is nothing but "is this name a key of prepareGoadMacs output". If the deployer ever derives '
    + `it some other way, the mirror is guessing. ${TRACK_B} (B0)`);
  for (const [re, why] of [
    [/if \(!spec\?\.goad\?\.enabled\) return \{\};/, 'nothing is a lab host unless goad.enabled'],
    [/if \(!Array\.isArray\(spec\.vms\)\) return \{\};/, 'and unless spec.vms is an array'],
    [/const labName = canonicalGoadLabName\(spec\.goad\.version \|\| DEFAULT_LAB\);/, 'the lab is goad.version, canonicalized and defaulted'],
    [/const supplied = spec\.goad\.lab;/, 'a compiled lab supplies its own roster'],
    [/const lab = supplied \|\| GOAD_LABS\[labName\];/, 'the supplied roster precedes the built-in lab'],
    [/const labDef = lab \|\| GOAD_LABS\[DEFAULT_LAB\];/, 'an UNKNOWN version falls back, it does not fail'],
    [/const byName = Object\.fromEntries\(labDef\.vms\.map\(v => \[v\.name\.toLowerCase\(\), v\]\)\);/,
      'matching is on name.toLowerCase(), with no trim'],
    [/const labVm = byName\[vm\.name\.toLowerCase\(\)\];/, 'and it is the SPEC name that is looked up'],
    [/static_ip:\s*buildIp\(laneSubnetBase, labVm\.ipOctet\)/, 'the address is the lab octet'],
  ]) {
    assert.ok(re.test(goad),
      `prepareGoadMacs' decision must still be ${why} — the mirror reproduces exactly this. ${TRACK_B} (B0)`);
  }
  assert.ok(/const DEFAULT_LAB = 'GOAD-Light';/.test(goad)
    && PLAN.GOAD_DEFAULT_LAB === 'GOAD-Light',
    `The default lab is part of the decision, so it is part of the mirror. ${TRACK_B} (B0)`);

  // Nothing in that chain reads a lane, a vxlan id or a subnet base to decide
  // MEMBERSHIP — those only shape the MAC and the IP string.
  assert.ok(/function prepareGoadMacs\(spec, vxlanId, laneSubnetBase\)/.test(goad),
    `Membership is a function of the spec alone. ${TRACK_B} (B0)`);

  // ── THE TABLE ITSELF, PARSED OUT OF THE AUTHORITY ────────────────────────
  const block = read(GOAD_DEPLOY_REL).match(/const GOAD_LABS = \{[\s\S]*?\r?\n\};/);
  assert.ok(block, `${GOAD_DEPLOY_REL} must still declare GOAD_LABS. ${TRACK_B} (B0)`);
  const parsed = {};
  let currentLab = null;
  for (const line of block[0].split(/\r?\n/)) {
    const labHead = line.match(/^\s{2}'?([A-Za-z0-9_-]+)'?:\s*\{/);
    if (labHead) { currentLab = labHead[1]; parsed[currentLab] = {}; continue; }
    const vmLine = line.match(/\{\s*name:\s*'([^']+)'[\s\S]*?ipOctet:\s*(\d+)/);
    if (vmLine && currentLab) parsed[currentLab][vmLine[1].toLowerCase()] = Number(vmLine[2]);
  }
  assert.ok(Object.keys(parsed).length >= 6,
    `The parse must actually find the labs, or this guard proves nothing. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(PLAN.GOAD_LAB_VMS)), parsed,
    'The mirrored lab table must be the authority table, name for name and octet for octet. A lab added '
    + 'upstream — or a VM added to one — changes which spec machines the deployer addresses itself, and a '
    + `mirror that has not heard about it names the wrong address for them. ${TRACK_B} (B0)`);

  // ── AND THE MIRROR ANSWERS THE SAME QUESTION ─────────────────────────────
  const g = PLAN.goadLabOctet;
  assert.strictEqual(g({ goad: { enabled: true }, vms: [] }, 'DC01'), 10,
    `Default lab, matched by name, case-insensitively. ${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: true }, vms: [] }, 'dc01'), 10, `${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: true }, vms: [] }, ' DC01'), null,
    `prepareGoadMacs does NOT trim, so neither does the mirror. ${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: true }, vms: [] }, 'SRV01'), null,
    `SRV01 is not in GOAD-Light. ${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: true, version: 'NHA' }, vms: [] }, 'SRV01'), 21,
    `It is in NHA, at a different octet. ${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: true, version: 'nonesuch' }, vms: [] }, 'DC01'), 10,
    `An unknown version falls back to the default lab, exactly as prepareGoadMacs does. ${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: false }, vms: [] }, 'DC01'), null,
    `goad.enabled false means NOTHING is a lab host. ${TRACK_B} (B0)`);
  assert.strictEqual(g({ goad: { enabled: true } }, 'DC01'), null,
    `And prepareGoadMacs returns an empty map when spec.vms is not an array. ${TRACK_B} (B0)`);
  assert.strictEqual(g({}, 'DC01'), null, `${TRACK_B} (B0)`);
  assert.strictEqual(g(null, null), null, `Total, like everything else here. ${TRACK_B} (B0)`);

  // The two deployer facts the octet itself rests on.
  assert.ok(/if \(goadMacs\[name\]\) continue;/.test(deployer),
    'A lab host is SKIPPED before the band is consulted, so its spec ipOctet is inert and the paper must '
    + `not print it. ${TRACK_B} (B0)`);
  assert.ok(/subnetBase: \(isV3 && segs\[0\] === 'int'\) \? goadSubnetBase : laneSubnetBase,/.test(deployer),
    'AND THIS IS WHY RUNG 3 MATTERS: the subnet base is chosen by WHICH single segment, not by how many. '
    + `${TRACK_B} (B0)`);
  assert.ok(/const goadSubnetBase = isV3 \? net\.lanInt\.base3 : net\.lan\.base3;/.test(deployer),
    `Internal on v3, the one flat lane otherwise — which is what segment_for_address reports. ${TRACK_B} (B0)`);
});

test('B0-107b: engagement addresses follow the real resolver for aliases, compiled labs and WS01', () => {
  // Run the actual catalog/resolver source with only validation and logging
  // replaced. Every fixture is valid; this exercises membership without loading
  // the deployer's network dependencies into the pure engagement compiler.
  const source = read(GOAD_DEPLOY_REL);
  const declarations = ['GOAD_LABS', 'GOAD_EXTENSIONS'].map(name => {
    const match = source.match(new RegExp(`const ${name} = \\{[\\s\\S]*?\\r?\\n\\};`));
    assert.ok(match, `${name} must remain readable for the parity contract`);
    return match[0];
  });
  const canonical = rawFn(read('src/utils/goad-lab-rebrand.js'), 'canonicalGoadLabName');
  const functions = ['getLab', 'extensionsForLab', 'resolveGoadExtensions', 'resolveGoadLab'].map(name => {
    const fn = rawFn(source, name);
    assert.ok(fn, `${name} must remain readable for the parity contract`);
    return fn;
  });
  assert.ok(canonical);
  const authority = new Function(`
    const str = value => value == null ? '' : String(value);
    const DEFAULT_LAB = 'GOAD-Light';
    const assertValidLabDef = () => {};
    const console = { warn() {} };
    ${declarations.join('\n')}
    ${canonical}
    ${functions.join('\n')}
    return { resolve: resolveGoadLab, extensions: GOAD_EXTENSIONS };
  `)();
  const extensionMirror = Object.fromEntries(Object.values(authority.extensions)
    .filter(ext => ext.inLab)
    .map(ext => [ext.key, { name: ext.machine, ipOctet: ext.ipOctet, compatibility: ext.compatibility }]));
  assert.deepStrictEqual(JSON.parse(JSON.stringify(PLAN.GOAD_LAB_EXTENSIONS)), extensionMirror);

  const compiled = (vms, baseLab) => ({ forestRoot: 'cy400test.org', vms, ...(baseLab ? { baseLab } : {}) });
  const custom = { name: 'AUTH01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 60 };
  const selections = [[], ['ws01'], [' WS01 ', 'ws01', 'elk', 'lx01', 'unknown']];
  const versions = ['GOAD-Mini', 'mini', ' goad-mini ', 'light', 'GOAD-Light', 'GOAD', 'full', 'goad', 'NHA', 'SCCM', 'DRACARYS', 'unknown', undefined];
  const fixtures = versions.flatMap(version => selections.map(extensions => ({ enabled: true, version, extensions })));
  fixtures.push(
    { enabled: true, version: 'CC-MINI-CUSTOM', lab: compiled([custom], 'GOAD-Mini'), extensions: ['ws01', 'elk'] },
    { enabled: true, version: 'CIAB-custom', lab: compiled([custom]), extensions: ['ws01'] },
    { enabled: true, version: 'CC-MINI-CONFLICT', lab: compiled([{ ...custom, ipOctet: 31 }], 'GOAD-Mini'), extensions: ['ws01'] },
    { enabled: true, version: 'CC-MINI-WS', lab: compiled([{ ...custom, name: 'ws01', ipOctet: 61 }], 'GOAD-Mini'), extensions: ['ws01'] }
  );
  const candidates = ['DC01', 'DC02', 'DC03', 'SRV01', 'SRV02', 'SRV03', 'AUTH01', 'ws01', 'WS01', 'lx01', 'elk', ' DC01'];
  for (const options of fixtures) {
    const spec = { goad: options, vms: candidates.map(name => ({ name })) };
    const roster = authority.resolve(spec).labDef.vms;
    for (const name of candidates) {
      const vm = roster.find(host => host.name.toLowerCase() === name.toLowerCase());
      assert.strictEqual(PLAN.goadLabOctet(spec, name), vm?.ipOctet ?? null,
        `${JSON.stringify(options)} / ${name} must match the actual deployed roster`);
    }
  }
  assert.strictEqual(PLAN.goadLabOctet({ goad: { enabled: true, version: 'mini' }, vms: [] }, 'DC02'), null);
  assert.strictEqual(PLAN.goadLabOctet({ goad: { enabled: true, version: 'full' }, vms: [] }, 'DC03'), 12);
  const invalidGenerated = { goad: { enabled: true, version: 'CC-absent', generated_lab: {} }, vms: [{ name: 'DC01' }] };
  assert.throws(() => authority.resolve(invalidGenerated), /cannot fall back/);
  assert.strictEqual(PLAN.goadLabOctet(invalidGenerated, 'DC01'), null, 'refused identities must not acquire invented Light addresses');
  assert.strictEqual((read(PLAN_REL).match(/require\(/g) || []).length, 5);
});

/** A v3 external engagement whose spec is an AD lab. */
function goadSpec(vms, extra) {
  return Object.assign({
    subnet_scheme: 'v3',
    goad: { enabled: true, version: 'GOAD-Light' },
    vms,
  }, extra || {});
}

test('B0-108: an AD lab host is addressed by the lab, and is never made the bridge', () => {
  // FINDING N-A, THE THIRD INCOMPLETE-MIRROR BUG. The mirror had no isGoadVm
  // rung, on the reasoning that a rung returning ONE segment cannot behave
  // differently from the rung below it, which also returns one. The two return
  // a DIFFERENT segment, and challenge-lane-deployer.js:315 picks the subnet
  // base off exactly that — so an AD lab host with role 'server' was stamped
  // 'pivot', handed [{ext},{int}] and .240, and the brief opened with
  // http://{ext_base}.240/ for a machine the lab addresses on the INTERNAL
  // segment at its own octet, and which the band never touches at all.
  const plan = compile(EXT_V3, goadSpec([
    vm('SRV02', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
    vm('DC01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
  ]));
  const srv = plan.hosts.find(h => h.vm_name === 'SRV02');

  assert.deepStrictEqual(srv.segments, ['int'],
    `Rung 3: an AD lab host on v3 lands on the INTERNAL segment. ${TRACK_B} (B0)`);
  assert.notStrictEqual(srv.placement, 'pivot',
    'It cannot be the bridge. Proposing one writes [{ext},{int}] onto its spec, rung 1 would honour that, '
    + 'and the machine really would move to .240 — out from under the reservation the lab made for it and '
    + `out from under the playbook, which drives the lab at its own addresses. ${TRACK_B} (B0)`);
  assert.notStrictEqual(srv.ip_octet, PLAN.DUAL_HOMED_OCTET, `${TRACK_B} (B0)`);
  assert.strictEqual(srv.ip_octet, 22,
    'Its address is the LAB octet (goad-deploy.js prepareGoadMacs), not the ipOctet its spec carries: '
    + `challenge-lane-deployer.js:306 skips it before the band is reached. ${TRACK_B} (B0)`);
  assert.strictEqual(srv.segment_for_address, 'int',
    'AND THE SEGMENT IS PART OF THE ADDRESS. .22 on the internal base and .22 on the external base are '
    + `different machines; an octet printed without its segment is half a fact. ${TRACK_B} (B0)`);
  assert.strictEqual(srv.goad_lab_vm, true, `${TRACK_B} (B0)`);
  assert.strictEqual(plan.brief.facts.surface_url, null,
    `And the brief hands out no .240 URL, because nothing in this lane answers there. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(plan, 'EXTERNAL_NO_PIVOT').length, 1,
    'The honest answer for an all-lab estate with no bridge, rather than compiling clean around one that '
    + `does not exist. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(plan, 'GOAD_HOST_ADDRESSED_BY_LAB').length, 2,
    `Both lab hosts say where they really live, once each. ${TRACK_B} (B0)`);
  assert.ok(/\.22\b/.test(codeAt(plan, 'GOAD_HOST_ADDRESSED_BY_LAB')[0].message)
    && new RegExp(`\\.${SYNTH.SPEC_OCTET_MIN}\\b`).test(codeAt(plan, 'GOAD_HOST_ADDRESSED_BY_LAB')[0].message),
    'And it names BOTH the address it really gets and the one its spec asks for, or the author cannot see '
    + `which of the two the paper is talking about. ${TRACK_B} (B0)`);

  // THE OTHER LAB HOST, for the same reason, at its own octet.
  assert.strictEqual(plan.hosts.find(h => h.vm_name === 'DC01').ip_octet, 10, `${TRACK_B} (B0)`);

  // ── RUNG 2 STILL BEATS RUNG 3, because the authority says so ─────────────
  // A lab host carrying the bridge role really IS dual-homed and really IS
  // pinned to .240 — resolveVmSegments checks 'dmz' first. The compile must not
  // contradict that; what it must do is say the lane now addresses one machine
  // two ways.
  const bridged = compile(EXT_V3, goadSpec([
    vm('DC01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
  ]));
  const dc = bridged.hosts.find(h => h.vm_name === 'DC01');
  assert.strictEqual(dc.placement, 'pivot',
    `The bridge role is checked ABOVE lab membership, and the mirror keeps that order. ${TRACK_B} (B0)`);
  assert.strictEqual(dc.ip_octet, PLAN.DUAL_HOMED_OCTET, `${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(bridged, 'GOAD_HOST_IS_BRIDGE').length, 1,
    'Two mechanisms now address one machine — the .240 pin and the lab reservation — and neither knows '
    + `about the other. Saying so is the entire job. ${TRACK_B} (B0)`);

  // ── AND NONE OF THIS FIRES WITHOUT goad.enabled ─────────────────────────
  const notALab = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('SRV02', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] })],
  });
  const plainSrv = notALab.hosts.find(h => h.vm_name === 'SRV02');
  assert.deepStrictEqual(plainSrv.segments, ['ext'],
    `A machine merely NAMED SRV02 is rung 4, on ext. Membership needs goad.enabled. ${TRACK_B} (B0)`);
  assert.strictEqual(plainSrv.placement, 'pivot',
    `And it is an ordinary bridge candidate again. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(notALab, 'GOAD_HOST_ADDRESSED_BY_LAB').length, 0, `${TRACK_B} (B0)`);
});

test('B0-109: an authored card list is never overwritten — for EVERY role, not one', () => {
  // FINDING N-B. The 'never rewrite an authored card list' invariant held for
  // role 'attacker' ONLY (B0-103). Rung 1 of resolveVmSegments has no role in
  // it at all: `explicit.length` returns before role, type, scheme or lab
  // membership is consulted. A special case written for one role IS the defect.
  //
  // Executed before the fix: web01, role 'dmz', authored nics [{int}] — a
  // perfectly ordinary "put the web host behind the bridge" — came out as
  // placement 'pivot', nics [{ext},{int}], ip_octet 240 and a .240 starting
  // URL, with the only problem an info. The deployer gives it ONE internal card.
  const single = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'dmz', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'int' }],
    })],
  });
  const web = single.hosts.find(h => h.vm_name === 'web01');
  assert.deepStrictEqual(web.segments, ['int'],
    `Rung 1 beats rung 2: the card list wins over the bridge role. ${TRACK_B} (B0)`);
  assert.strictEqual(web.placement, 'internal',
    `So the placement is READ off the cards, not proposed over them. ${TRACK_B} (B0)`);
  assert.strictEqual(web.nics, null,
    `And nothing is written back. A one-card spec keeps its one card. ${TRACK_B} (B0)`);
  assert.strictEqual(web.ip_octet, SYNTH.SPEC_OCTET_MIN,
    `Single-homed means band-pinned, at the octet the spec asked for. ${TRACK_B} (B0)`);
  assert.strictEqual(single.brief.facts.surface_url, null,
    `And no .240 URL for a machine that does not answer there. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(single, 'PLACEMENT_FROM_AUTHORED_NICS').length, 1,
    `The compile says out loud that it read rather than proposed. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(single, 'EXTERNAL_NO_PIVOT').length, 1,
    `And an external engagement whose only web host is internal has no bridge. ${TRACK_B} (B0)`);

  // ── AUTHORED ORDER IS PRESERVED EXACTLY ─────────────────────────────────
  // [{int},{ext}] means net0 on int and net1 on ext. Normalizing it to
  // [{ext},{int}] with no code naming the rewrite reverses which card is which.
  const reversed = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'dmz', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'],
      nics: [{ segment: 'int' }, { segment: 'ext' }],
    })],
  });
  const rev = reversed.hosts.find(h => h.vm_name === 'web01');
  assert.deepStrictEqual(rev.segments, ['int', 'ext'],
    `The order the author wrote, not the canonical one. ${TRACK_B} (B0)`);
  assert.strictEqual(rev.nics, null,
    `And no [{ext},{int}] emitted over it — that IS the silent rewrite. ${TRACK_B} (B0)`);
  assert.strictEqual(rev.placement, 'pivot',
    `Two segments is still the bridge; only the ORDER was never anyone else's to change. ${TRACK_B} (B0)`);
  assert.strictEqual(rev.ip_octet, PLAN.DUAL_HOMED_OCTET, `${TRACK_B} (B0)`);

  // ── THE SAME RULE FOR AN ORDINARY ROLE, AND FOR A LAB HOST ──────────────
  for (const [role, spec] of [
    ['server', { subnet_scheme: 'v3', vms: [vm('web01', 'server', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'int' }] })] }],
    ['lab host', goadSpec([vm('SRV02', 'server', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'ext' }] })])],
  ]) {
    const p = compile(EXT_V3, spec);
    const h = p.hosts[0];
    assert.strictEqual(h.nics, null,
      `A ${role} with an authored card list keeps it too. The invariant is general or it is not one. `
      + `${TRACK_B} (B0)`);
  }
  // Rung 1 even overrides lab membership: an authored ext card really does put
  // a lab host on the external segment, and the mirror must say so.
  const labExt = compile(EXT_V3, goadSpec([vm('SRV02', 'server', {
    ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'ext' }] })]));
  assert.deepStrictEqual(labExt.hosts[0].segments, ['ext'],
    `Rung 1 beats rung 3 as well. ${TRACK_B} (B0)`);
});

test('B0-110: a card naming a segment the lane has no bridge for is named offline', () => {
  // FINDING N-C. resolveVmNics looks every segment up in resolveSegmentBridges'
  // table and THROWS on a miss, so a spec carrying nics [{segment:'dmz'}] does
  // not deploy at all — and the compile emitted a healthy-looking plan for it:
  // a placement, an octet, and one info problem. The one thing that machine
  // guaranteed was the one thing nothing said.
  const core = jsCode(read(LANE_NETWORKING_REL));
  assert.ok(/which this lane does not have/.test(core) && /Available: /.test(core),
    `The deploy-time throw is the authority for this problem existing. ${TRACK_B} (B0)`);
  assert.ok(/return \{ ext: vnetExtName, int: vnetIntName \};/.test(core),
    `v3 has exactly ext and int. ${TRACK_B} (B0)`);
  assert.ok(/return \{ lan: vnetExtName, ext: vnetExtName, int: vnetExtName \};/.test(core),
    'and v1/v2 maps lan, ext AND int onto its one VNet — deliberately, so a v3-authored spec does not '
    + `explode when its challenge is switched to v2. The mirror reproduces BOTH rows. ${TRACK_B} (B0)`);
  assert.deepStrictEqual(PLAN.laneSegmentIds(true), ['ext', 'int'], `${TRACK_B} (B0)`);
  assert.deepStrictEqual(PLAN.laneSegmentIds(false), ['lan', 'ext', 'int'], `${TRACK_B} (B0)`);

  const plan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'server', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'dmz' }],
    })],
  });
  const hit = codeAt(plan, 'NICS_UNKNOWN_SEGMENT');
  assert.strictEqual(hit.length, 1, `${TRACK_B} (B0)`);
  assert.strictEqual(hit[0].severity, 'error',
    `It is a HARD deploy throw: nothing in the environment comes up. ${TRACK_B} (B0)`);
  assert.ok(/'dmz'/.test(hit[0].message) && /'ext'/.test(hit[0].message) && /'int'/.test(hit[0].message),
    'It must name the segment asked for AND the ones the lane has, the way the deployer’s own message '
    + `does, so the eventual task log is recognisably this. ${TRACK_B} (B0)`);
  assert.ok(hit[0].message.includes('web01'), `And the machine. ${TRACK_B} (B0)`);
  assert.ok(PLAN.hasBlockingProblem(plan),
    `A lane that cannot come up must not compile clean. ${TRACK_B} (B0)`);

  // 'lan' IS a real bridge on v1/v2, and is NOT one on v3.
  const v2 = compile({ engagement_type: 'default', perspective: 'internal', subnet_scheme: 'v2' }, {
    subnet_scheme: 'v2',
    vms: [vm('web01', 'server', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'lan' }],
    })],
  });
  assert.strictEqual(codeAt(v2, 'NICS_UNKNOWN_SEGMENT').length, 0,
    `resolveSegmentBridges gives v1/v2 a 'lan' key, so this deploys. ${TRACK_B} (B0)`);
  const v3lan = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'server', {
      ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'], nics: [{ segment: 'lan' }],
    })],
  });
  assert.strictEqual(codeAt(v3lan, 'NICS_UNKNOWN_SEGMENT').length, 1,
    `And does NOT give v3 one, so the same spec on a v3 lane throws. ${TRACK_B} (B0)`);

  // THE CONTAINER EXCEPTION, and it is the authority's own: resolveVmNics' lxc
  // branch calls bridgeFor(segments[0]) and truncates the rest, so a second
  // card is never built and never validated.
  assert.ok(/segments: segments\.slice\(0, 1\),/.test(core),
    `The truncation is what makes the second card unvalidated. ${TRACK_B} (B0)`);
  const ctr = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('ctr', 'server', {
      type: 'lxc', services: ['80/HTTP'], nics: [{ segment: 'int' }, { segment: 'dmz' }],
    })],
  });
  assert.strictEqual(codeAt(ctr, 'NICS_UNKNOWN_SEGMENT').length, 0,
    'A card the deployer never builds is a card it never looks a bridge up for. Reporting one here would '
    + `be a second wrong statement, not a stricter one. ${TRACK_B} (B0)`);
  const ctrFirst = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('ctr', 'server', {
      type: 'lxc', services: ['80/HTTP'], nics: [{ segment: 'dmz' }, { segment: 'int' }],
    })],
  });
  assert.strictEqual(codeAt(ctrFirst, 'NICS_UNKNOWN_SEGMENT').length, 1,
    `The FIRST one is built, so the FIRST one throws. ${TRACK_B} (B0)`);
});

test('B0-111: two entries for one machine, and a surface that serves nothing, are both named', () => {
  // FINDING N-D. [{b,pivot},{b,internal}] used to collapse to one entry with
  // ZERO problems: two contradictory authored statements about one machine, and
  // nothing anywhere saying which reading survived.
  const dup = compile(
    Object.assign({}, EXT_V3, {
      exposure_plan: [
        { vm_name: 'b', placement: 'pivot' },
        { vm_name: 'b', placement: 'internal' },
      ],
    }),
    {
      subnet_scheme: 'v3',
      vms: [
        vm('b', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['22/SSH'] }),
        vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['80/HTTP'] }),
      ],
    });
  assert.strictEqual(dup.exposure.filter(e => e.vm_name === 'b').length, 1,
    `One machine still has one placement — the reading does not change. ${TRACK_B} (B0)`);
  const dupHit = codeAt(dup, 'EXPOSURE_DUPLICATE_VM');
  assert.strictEqual(dupHit.length, 1, `But it is now announced. ${TRACK_B} (B0)`);
  assert.ok(/'pivot'/.test(dupHit[0].message) && /'internal'/.test(dupHit[0].message),
    `Showing BOTH statements, or the author cannot tell which one they lost. ${TRACK_B} (B0)`);
  assert.strictEqual(dup.exposure.find(e => e.vm_name === 'b').placement, 'pivot',
    `First wins, so the reading cannot flip on a re-save. ${TRACK_B} (B0)`);

  // THE SAME RUN'S SECOND HALF. An authored pivot on a machine that serves
  // nothing becomes the public surface at port 80 — surfacePort's default, not
  // a service it was found to run — while the machine that DOES serve the web
  // site drops out of the exposure plan entirely.
  const notWeb = codeAt(dup, 'EXPOSURE_SURFACE_NOT_WEB');
  assert.strictEqual(notWeb.length, 1, `${TRACK_B} (B0)`);
  assert.ok(notWeb[0].message.includes('web01') && notWeb[0].message.includes("'b'"),
    `Naming the machine the brief will open on AND the one that actually serves. ${TRACK_B} (B0)`);
  assert.strictEqual(dup.public_surface.target_vm, 'b',
    'The authored plan is still not extended behind the author’s back — that is what keeps their list '
    + `theirs. It is reported instead. ${TRACK_B} (B0)`);

  // NOT noise on an ordinary authored plan whose surface really is the web host.
  const ordinary = compile(
    Object.assign({}, EXT_V3, { exposure_plan: [{ vm_name: 'web01', placement: 'pivot' }] }),
    {
      subnet_scheme: 'v3',
      vms: [vm('web01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] })],
    });
  assert.strictEqual(codeAt(ordinary, 'EXPOSURE_SURFACE_NOT_WEB').length, 0, `${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(ordinary, 'EXPOSURE_DUPLICATE_VM').length, 0, `${TRACK_B} (B0)`);
});

test('B0-112: the derived note never claims nothing was authored when everything was rejected', () => {
  // FINDING N-E. An exposure plan whose only entry named the attack box is
  // discarded at the filter, exposureEntries is then empty, the derived branch
  // runs — and the note said "No exposure plan was authored", two lines below
  // an EXPOSURE_ATTACKER_NOT_PLACED problem saying one was. A message that
  // contradicts the message beside it teaches a reader to trust neither.
  const rejected = compile(
    Object.assign({}, EXT_V3, { exposure_plan: [{ vm_name: 'kali', placement: 'internal' }] }),
    {
      subnet_scheme: 'v3',
      vms: [
        vm('kali', 'attacker', { ipOctet: SYNTH.SPEC_OCTET_MIN + 2 }),
        vm('web01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
      ],
    });
  const note = codeAt(rejected, 'EXPOSURE_DERIVED')[0];
  assert.ok(note, `${TRACK_B} (B0)`);
  assert.ok(!/No exposure plan was authored/.test(note.message),
    `One WAS authored. Saying otherwise is a false statement in a problem list. ${TRACK_B} (B0)`);
  assert.ok(/could not be used/.test(note.message),
    `The two facts are different and the message must distinguish them. ${TRACK_B} (B0)`);
  assert.strictEqual(codeAt(rejected, 'EXPOSURE_ATTACKER_NOT_PLACED').length, 1,
    `The problem that contradicted it is still there, and still right. ${TRACK_B} (B0)`);

  // AND THE OTHER HALF STILL READS CORRECTLY: nothing authored at all.
  const none = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] })],
  });
  assert.ok(/No exposure plan was authored/.test(codeAt(none, 'EXPOSURE_DERIVED')[0].message),
    `Which is true here, and is the only place it may be said. ${TRACK_B} (B0)`);
});

test('B0-113: a role that differs by WHITESPACE, not only by case, says so', () => {
  // FINDING N-F. The casing diagnostic closed only the casing case.
  // topology-editor.js:349-352 stores the role input VERBATIM — only `services`
  // and `default_scripts` are trimmed there — so 'dmz ' with a trailing space is
  // storable, invisible in the editor, and reproduces the identical four errors
  // with nothing naming the cause.
  const editor = read('public/js/topology/topology-editor.js');
  assert.ok(/role:\s*[^\n]*\.value\s*(?!\.trim)/.test(editor) || /role:/.test(editor),
    `The editor must still be the reason this diagnostic has a subject. ${TRACK_B} (B0)`);

  for (const spelling of ['dmz ', ' dmz', 'DMZ ', 'dmz\t']) {
    const plan = compile(EXT_V3, {
      subnet_scheme: 'v3',
      vms: [
        vm('web01', spelling, { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
        vm('dc01', 'server', { ipOctet: SYNTH.SPEC_OCTET_MIN + 1, services: ['389/LDAP'] }),
      ],
    });
    const hit = codeAt(plan, 'ROLE_CASE_MISMATCH');
    assert.strictEqual(hit.length, 1,
      `'${spelling}' matches a known outside role after trimming and lower-casing, so it is a spelling `
      + `mistake with consequences, not an unrelated role. ${TRACK_B} (B0)`);
    assert.ok(hit[0].message.includes('web01') && /'dmz'/.test(hit[0].message),
      `It names the machine and the spelling that works. ${TRACK_B} (B0)`);
    assert.ok(/whitespace/.test(hit[0].message) || /case/.test(hit[0].message),
      'AND it names the DIFFERENCE. A trailing space is invisible in a message that merely quotes both '
      + `spellings, which reads like a typo in the diagnostic itself. ${TRACK_B} (B0)`);
  }
  const trailing = compile(EXT_V3, {
    subnet_scheme: 'v3',
    vms: [vm('web01', 'dmz ', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] })],
  });
  assert.ok(/whitespace/.test(codeAt(trailing, 'ROLE_CASE_MISMATCH')[0].message),
    `'dmz ' differs by whitespace alone, and the message must say the word. ${TRACK_B} (B0)`);

  // THE COMPARISON ITSELF IS UNCHANGED, and B0-95 pins that: lane-networking
  // compares with ===, so 'dmz ' is NOT the dual-homing role and the four errors
  // are still exactly right about the environment as authored.
  for (const c of ['SCOPE_EMPTY', 'EXTERNAL_NEEDS_VULN_APP', 'EXTERNAL_NO_SURFACE', 'EXTERNAL_NO_PIVOT']) {
    assert.ok(codes(trailing).includes(c),
      `The behaviour is not being loosened, only explained. ${c}. ${TRACK_B} (B0)`);
  }
  assert.strictEqual(trailing.hosts[0].ip_octet, SYNTH.SPEC_OCTET_MIN,
    `Single-homed, band-pinned, exactly as before. ${TRACK_B} (B0)`);

  // AND STILL NOT NOISE on a role that is simply not an outside role, however
  // it is spelled.
  for (const role of ['workstation', ' server ', 'db']) {
    const p = compile(EXT_V3, {
      subnet_scheme: 'v3',
      vms: [
        vm('web01', 'dmz', { ipOctet: SYNTH.SPEC_OCTET_MIN, services: ['80/HTTP'] }),
        vm('x', role, { ipOctet: SYNTH.SPEC_OCTET_MIN + 1 }),
      ],
    });
    assert.strictEqual(codeAt(p, 'ROLE_CASE_MISMATCH').length, 0,
      `'${role}' is not a mis-spelling of an outside role, and widening past that would put a warning on `
      + `every ordinary engagement. ${TRACK_B} (B0)`);
  }
});

test('B0-114: the totality claim states the real contract rather than an absolute', () => {
  // A NITPICK WORTH FIXING IN THE DOC, NOT THE CODE. "Never throws, for any
  // input" is literally false for an object carrying a THROWING ACCESSOR, and a
  // guarantee that is false in one reachable case is a guarantee nobody can
  // rely on in the others. Defending against a hostile getter would mean
  // wrapping every property read in this file to buy nothing: every input this
  // module can actually receive is JSON, and JSON has no getters.
  const src = read(PLAN_REL);
  assert.ok(!/Never throws, for any input/.test(src),
    `The absolute is gone. ${TRACK_B} (B0)`);
  assert.ok(/JSON-DERIVED/i.test(src) && /THROWING ACCESSOR/.test(src),
    'The doc must name the real contract AND the exception it excludes, so the next reader does not '
    + `re-derive it from a crash. ${TRACK_B} (B0)`);

  // THE CONTRACT ITSELF, EXERCISED over the shapes JSON can actually produce.
  for (const bad of [
    null, undefined, {}, { engagement: null, spec: null },
    { spec: { vms: 'nope' } }, { spec: { vms: [null, 1, 'x', []] } },
    { spec: { vms: [{ name: 'a', nics: 'no' }] } },
    { spec: { vms: [{ name: 'a', nics: [null, {}, { segment: '' }] }] } },
    { spec: { goad: 'yes', vms: [{ name: 'DC01' }] } },
    { spec: { goad: { enabled: true, version: 42 }, vms: [{ name: 'DC01' }] } },
    { engagement: { exposure_plan: 'no' }, spec: { vms: [] } },
    { engagement: { exposure_plan: [{}, null, { vm_name: 'a' }, { vm_name: 'a' }] }, spec: { vms: [] } },
  ]) {
    const plan = PLAN.compileEngagementPlan(bad);
    assert.ok(plan && Array.isArray(plan.problems),
      `Total over every JSON shape, including the new rungs' inputs. ${TRACK_B} (B0)`);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(plan)), plan,
      `And the result still round-trips. ${TRACK_B} (B0)`);
  }

  // AND THE EXCLUDED CASE IS REAL, which is why the claim had to change.
  const hostile = { vms: [] };
  Object.defineProperty(hostile, 'vms', {
    get() { throw new Error('hostile accessor'); }, enumerable: true, configurable: true,
  });
  assert.throws(() => PLAN.compileEngagementPlan({ engagement: {}, spec: hostile }),
    /hostile accessor/,
    'A throwing accessor propagates, and the doc now says so instead of promising otherwise. This is not '
    + `reachable from JSON. ${TRACK_B} (B0)`);
});
