/**
 * ciab-blueteam.test.js — Track E, phase E3: the CiAB defensive engagement.
 *
 * WHAT E3 ADDS, AND WHY EACH PIECE NEEDS DEFENDING HERE
 *
 * A `defensive_monitoring` engagement deploys, into a client's environment,
 * three machines nobody selected: a synthetic-telemetry sensor and one or two
 * SIEMs. Almost every way that can go wrong produces a lane that DEPLOYS, comes
 * up green, opens a console, and is useless — which is the failure mode this
 * plugin's tests exist for.
 *
 *   §1  THE TYPE. A registry key, not a CHECK value, and a slug that is frozen
 *       the moment a VXLAN block is carved under its name.
 *   §2  v2, TWICE. A 400 while it is still free to fix, and a 409 at deploy
 *       when it is not — because a carved block cannot be re-carved.
 *   §3  telemetry_plan. `sensor` is DERIVED, never authored: the loggen sensor
 *       ships to Elasticsearch only, so `wazuh + sensor` is a machine that
 *       retries forever and produces nothing.
 *   §4  MIGRATION HYGIENE for 017. One statement, incapable of raising on boot
 *       two, and it must not widen the read-path adopt's 8-column INSERT.
 *   §5  ADDRESSING PARITY. .24 and .51 are mirrored, not imported, so a test
 *       has to hold the mirror against its authority.
 *   §6  THE POSTDEPLOY CHAIN. deployChallengeLanes takes ONE hook and CiAB
 *       already spends it; a throw in the vuln-app install must not skip the
 *       sensor stamp.
 *   §7  THE STAMP ITSELF. Matched by spec name (never proxmox_name), written
 *       with a single-statement jsonb_set, and RE-APPLIED after the deployer
 *       has written each lane's config whole.
 *   §8  LANE CONFIG. engagement_id + profile_id are how anything outside this
 *       plugin finds a CiAB lane at all.
 *   §9  attackBoxes. Left true, Kali wins the console and the student's Console
 *       button silently opens the attacker's machine instead of the SIEM.
 *   §10 THE NAMED 400. role_hints has no admin UI, so "untagged" is the normal
 *       first-time state and must never resolve to "deploy without a SIEM".
 *
 * WHAT THIS FILE IS NOT. It runs no SQL and touches no cluster. §4 asserts on
 * migration TEXT, and the apply-twice check against a scratch database is a
 * manual step the phase plan owns.
 *
 * STUB DISCIPLINE, AND THE ORDER IS LOAD-BEARING TWICE OVER.
 * engagement-model.js and profile-to-spec.js are required BARE first, with no
 * stubs at all, and what the module cache holds immediately afterwards IS §5's
 * assertion — E3 must not have given the synthesizer an edge to a pool or a
 * cluster client. THEN cybercore-db is stubbed, and only THEN are
 * blueteam-postdeploy.js and blueteam-templates.js required: both destructure
 * `cybercoreQuery` at module load, so a stub installed after them is held by
 * nobody, the real pg pool tries to reach a host that is not there, and the
 * assertions pass on swallowed errors instead of on behaviour.
 *
 * Run: node --test front-end/test/ciab-blueteam.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const abs = (rel) => path.join(ROOT, rel);
const read = (rel) => fs.readFileSync(abs(rel), 'utf8');

const TRACK_E = 'See the program plan, Track E (E3).';

const CIAB = 'modules/crucible/plugins/ciab';
const MODEL_REL = `${CIAB}/utils/engagement-model.js`;
const SYNTH_REL = `${CIAB}/utils/profile-to-spec.js`;
const PROVISION_REL = `${CIAB}/utils/engagement-provision.js`;
const LANEPROV_REL = `${CIAB}/utils/lane-provision.js`;
const ROUTE_REL = `${CIAB}/routes/profile-deploy.js`;
const TEMPLATES_REL = `${CIAB}/utils/blueteam-templates.js`;
const POSTDEPLOY_REL = `${CIAB}/utils/blueteam-postdeploy.js`;
const MIG_REL = `${CIAB}/migrations/017_ciab_telemetry_plan.sql`;

// Every line-wise scan splits on a CRLF-tolerant boundary: this checkout mixes
// conventions and '\r' is a line terminator to a JS regex, so a whole-file
// /^\s*\/\/.*$/gm stripper silently stops stripping. Same trap
// test/sql-param-typing.test.js:66-72 documents.
const NEWLINE = /\r?\n/;

/** Source with line comments and block comments removed, flattened to one line. */
function jsCode(src) {
  return src
    .split(NEWLINE)
    .map(l => l.replace(/^\s*\/\/.*$/, ''))
    .join('\n')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, ' ');
}

/** SQL with `--` comments removed, flattened to one line. */
function sqlCode(src) {
  return src.split(NEWLINE).map(l => l.replace(/--.*$/, '')).join('\n').replace(/\s+/g, ' ');
}

// ── BARE requires, before anything touches require.cache ────────────────────
// The ordering IS the assertion. profile-to-spec.js has to keep loading with no
// cluster, no database and no readable config/site.json — that property is what
// lets the whole plugin fixture suite require it, and it is one careless import
// away from ending. If E3 had made it require goad-deploy.js (for the octets)
// or blueteam-templates.js (for the catalog rows), one of those edges would put
// a pg Pool or a cluster client in the module cache, and §5 below would say so.
const MODEL = require(abs(MODEL_REL));
const SYNTH = require(abs(SYNTH_REL));

/**
 * Which heavyweight modules the two pure ones dragged in.
 *
 * Measured HERE, between the bare requires above and the stubs below, because
 * afterwards the cache is full of things this file put there. site-config is
 * deliberately not on the list: profile-to-spec has always reached it through
 * vm-template-resolver, and that is fine — site-config's getConfig() reads the
 * file LAZILY, on call. What must never appear is a database pool or a cluster
 * client, because those are constructed at require time.
 */
const HEAVY_AFTER_PURE = ['src/utils/proxmox.js', 'src/utils/db.js',
  'src/utils/cybercore-db.js', 'src/utils/goad-deploy.js']
  .filter(rel => Object.prototype.hasOwnProperty.call(require.cache, require.resolve(abs(rel))));

// ── Stubs, installed before anything that holds a DB handle ─────────────────
function put(modPath, exports) {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
}

/**
 * Every statement the stubbed cybercore_db pool was asked to run.
 *
 * This stub MUST be installed before blueteam-postdeploy.js and
 * blueteam-templates.js are required: both destructure `cybercoreQuery` at
 * module load, so a stub installed afterwards is held by nobody and the real pg
 * pool tries to reach a host that is not there — which does not fail the test,
 * it just makes it slow and then silently passes on a swallowed error.
 */
const SQL = [];
let NEXT_ROWS = [];
put(abs('src/utils/cybercore-db.js'), {
  cybercoreQuery: async (text, params) => {
    SQL.push({ text: String(text).replace(/\s+/g, ' ').trim(), params });
    const rows = NEXT_ROWS;
    NEXT_ROWS = [];
    return { rows, rowCount: rows.length };
  },
});

put(abs('src/utils/site-config.js'), {
  getSchedulingConfig: () => ({ max_concurrent_lanes: 5, max_concurrent_clones: 4 }),
  getDefaultTemplateNode: () => 'node-1',
  getClusterNodes: () => [],
  getPhysicalClusterIps: () => ({}),
  getNodeAddress: () => '10.0.0.1',
  getV2LabNetwork: () => ({
    network: '100.100.60.0', prefix_len: 22, reserved: [],
    host_range: { first: '100.100.60.10', last: '100.100.63.254' },
  }),
});

const POSTDEPLOY = require(abs(POSTDEPLOY_REL));
const TEMPLATES = require(abs(TEMPLATES_REL));

/**
 * Where the incident engine's target ladder lives TODAY.
 *
 * E1 moved it from the CLE plugin to src/incident/ and left a one-line
 * re-export shim behind, which E2 deletes. Both states are legitimate while the
 * strangler is in flight, so this resolves rather than picking one — a test
 * that hard-codes either path fails for a reason that has nothing to do with
 * what it is checking.
 */
const TARGET_REL = ['src/incident/target.js',
  'modules/crucible/plugins/cle/utils/attack-target.js']
  .find(rel => fs.existsSync(abs(rel)) && /LOGGEN_ROLES/.test(read(rel)));

// ════════════════════════════════════════════════════════════════════════════
// §1 — THE ENGAGEMENT TYPE
// ════════════════════════════════════════════════════════════════════════════

test("E3-1: 'defensive_monitoring' is a registry key with an internal, credentialed posture", () => {
  const d = MODEL.describeEngagementType('defensive_monitoring');
  assert.strictEqual(d.known, true,
    `An unregistered slug takes the conservative fallback descriptor and renders as an ordinary `
    + `locally defined engagement. ${TRACK_E}`);
  assert.strictEqual(d.key, 'defensive_monitoring', TRACK_E);
  assert.strictEqual(d.perspective, 'internal',
    `The team is placed inside the segment on day one — a defender who has to break in first is `
    + `not defending. ${TRACK_E}`);
  assert.strictEqual(d.credential_posture, 'credentialed', TRACK_E);
  assert.strictEqual(d.system, false,
    `It is an engagement an operator creates, unlike the bake's staging network. ${TRACK_E}`);
  assert.strictEqual(MODEL.BLUE_TEAM_TYPE_KEY, 'defensive_monitoring',
    `The slug has exactly one spelling; routes and lane-provision both branch on it. ${TRACK_E}`);
});

test('E3-2: no migration is needed for the slug, and none may constrain the column', () => {
  // The registry is a REGISTRY WITH A TOTAL FALLBACK, not an allowlist:
  // createEngagement sanitizes and never rejects, so a CHECK would fail
  // validation against live rows and silently revert its whole file on every
  // boot. This re-asserts B0-9 over the directory as it stands after E3.
  const dir = abs(`${CIAB}/migrations`);
  const offenders = fs.readdirSync(dir)
    .filter(f => f.endsWith('.sql'))
    .filter(f => /CHECK\s*\(\s*engagement_type/i.test(sqlCode(fs.readFileSync(path.join(dir, f), 'utf8'))));
  assert.deepStrictEqual(offenders, [], TRACK_E);

  const mig = sqlCode(read(MIG_REL));
  assert.ok(!/defensive_monitoring/.test(mig),
    `Migration 017 must not mention the slug at all. The type is a JS registry entry; a migration `
    + `that named it would imply a vocabulary the database does not have. ${TRACK_E}`);
});

test('E3-3: the slug is a fixed point of the sanitizer, so a stored row can match it', () => {
  // /^[a-z0-9_-]{1,32}$/ is sanitizeEngagementType's OUTPUT alphabet. A key the
  // sanitizer would rewrite could never be matched by a stored slug, because
  // createEngagement sanitizes before it INSERTs.
  assert.match(MODEL.BLUE_TEAM_TYPE_KEY, /^[a-z0-9_-]{1,32}$/, TRACK_E);
});

test('E3-4: the display aliases never rewrite a stored slug', () => {
  // The slug is baked into the reservation key ciab-profile-<id8>-<slug>, and
  // therefore into the name of a carved VXLAN block. Rewriting it orphans that
  // block permanently — the allocator only ever climbs and never re-uses.
  for (const mangled of ['defensivemonitoring', 'defensive-monitoring']) {
    assert.strictEqual(MODEL.resolveEngagementTypeAlias(mangled), 'defensive_monitoring',
      `'${mangled}' must READ as the defensive engagement. ${TRACK_E}`);
    assert.strictEqual(MODEL.describeEngagementType(mangled).key, mangled,
      `describeEngagementType must report the slug it was GIVEN, unknown and all — it is the `
      + `reservation key. ${TRACK_E}`);
    assert.strictEqual(
      MODEL.engagementDisplayName({ engagement_type: mangled }),
      MODEL.ENGAGEMENT_TYPES.defensive_monitoring.label,
      `Only the screen changes. ${TRACK_E}`);
  }
});

test('E3-5: the label and summary use CiAB vocabulary only', () => {
  // Section / Module / Client / Engagement / Environment. The neighbouring
  // plugin's words leak in through copied prose and are hard to unpick once
  // shipped.
  const BANNED = /\b(course|material|challenge|assignment|lesson)\b/i;
  const entry = MODEL.ENGAGEMENT_TYPES.defensive_monitoring;
  assert.ok(!BANNED.test(entry.label), `label: ${entry.label}. ${TRACK_E}`);
  assert.ok(!BANNED.test(entry.summary), `summary: ${entry.summary}. ${TRACK_E}`);
});

// ════════════════════════════════════════════════════════════════════════════
// §2 — v2, TWICE: A 400 WHILE IT IS FIXABLE AND A 409 WHEN IT IS NOT
// ════════════════════════════════════════════════════════════════════════════

test('E3-6: a defensive engagement on a non-v2 scheme is a field-level 400', () => {
  const r = MODEL.validateEngagementPlan(
    { display_name: 'Spring monitoring' },
    { engagementType: 'defensive_monitoring', subnetScheme: 'v3' });
  assert.strictEqual(r.valid, false, TRACK_E);
  const err = r.errors.find(e => e.code === 'DEFENSIVE_REQUIRES_V2');
  assert.ok(err, `Expected DEFENSIVE_REQUIRES_V2, got ${JSON.stringify(r.errors)}. ${TRACK_E}`);
  assert.strictEqual(err.path, 'subnet_scheme',
    `A field-level path is what the route turns into a usable 400 rather than a bare message. ${TRACK_E}`);
  assert.match(err.message, /v2/, TRACK_E);
});

test('E3-7: v2 passes, and every other engagement type is untouched by the rule', () => {
  const ok = MODEL.validateEngagementPlan(
    { display_name: 'Spring monitoring' },
    { engagementType: 'defensive_monitoring', subnetScheme: 'v2' });
  assert.deepStrictEqual(ok.errors, [], TRACK_E);

  for (const type of ['default', 'external_blackbox', 'internal_credentialed', 'droptable--']) {
    const r = MODEL.validateEngagementPlan({ display_name: 'x' },
      { engagementType: type, subnetScheme: 'v3' });
    assert.ok(!r.errors.some(e => e.code === 'DEFENSIVE_REQUIRES_V2'),
      `'${type}' must be free to be v3 — R1 made v3 the default for the offensive tracks precisely `
      + `so the network enforces the pivot. ${TRACK_E}`);
  }
});

test('E3-8: an unknown scheme is not invented when the caller passes none', () => {
  // subnetScheme is optional. With nothing to check the rule must stay silent
  // rather than guessing that the absence means v3 — a PATCH that touches only
  // the brief has said nothing about the network.
  const r = MODEL.validateEngagementPlan({ brief: 'hunt it' },
    { engagementType: 'defensive_monitoring' });
  assert.deepStrictEqual(r.errors, [], TRACK_E);
});

test('E3-9: assertEngagementDeployable refuses a carved-at-v3 defensive engagement with a 409', () => {
  const PROVISION = require(abs(PROVISION_REL));
  const engagement = {
    engagement_id: 'e-1', engagement_type: 'defensive_monitoring', subnet_scheme: 'v3',
    provision_status: 'ready', challenge_id: 7, max_students: 4,
  };
  assert.throws(
    () => PROVISION.assertEngagementDeployable(engagement, {
      profileId: 'p-1', engagementType: 'defensive_monitoring',
    }),
    (err) => {
      assert.strictEqual(err.status, 409,
        `409, not 400: by deploy time this is a conflict with a network that already exists, not a `
        + `bad request. ${TRACK_E}`);
      assert.strictEqual(err.code, 'ENGAGEMENT_SCHEME_NOT_V2', TRACK_E);
      assert.match(err.message, /cannot be re-carved/,
        `The message must say WHY the remedy is a new engagement: a v2 block holds one VNet per lane `
        + `and a v3 block holds two, so rewriting the row only makes it lie about the carve. ${TRACK_E}`);
      return true;
    });

  // The same engagement at v2 passes the gate untouched.
  assert.doesNotThrow(() => PROVISION.assertEngagementDeployable(
    { ...engagement, subnet_scheme: 'v2' },
    { profileId: 'p-1', engagementType: 'defensive_monitoring' }));

  // And an offensive engagement at v3 is still perfectly deployable.
  assert.doesNotThrow(() => PROVISION.assertEngagementDeployable(
    { ...engagement, engagement_type: 'default' },
    { profileId: 'p-1', engagementType: 'default' }));
});

// ════════════════════════════════════════════════════════════════════════════
// §3 — telemetry_plan: THE STACK IS AUTHORED, THE SENSOR IS DERIVED
// ════════════════════════════════════════════════════════════════════════════

test('E3-10: the stack vocabulary is exactly elastic | wazuh | both', () => {
  assert.deepStrictEqual([...MODEL.TELEMETRY_STACKS], ['elastic', 'wazuh', 'both'], TRACK_E);
  const r = MODEL.validateTelemetryPlan({ stack: 'splunk' });
  assert.ok(r.errors.some(e => e.code === 'TELEMETRY_STACK_UNKNOWN'), TRACK_E);
  assert.ok(!('stack' in r.value),
    `A rejected stack must not be stored — a value that reached Postgres and tripped a CHECK would `
    + `raise 23514 and render as an unhandled 500 instead of this 400. ${TRACK_E}`);
});

test('E3-11: sensor is DERIVED from the stack and cannot be authored true on wazuh', () => {
  // The sensor's agent ships to Elasticsearch and Beats cannot ship to Wazuh's
  // indexer at all (OpenSearch 2.x removed the compatibility override). So
  // wazuh + sensor is not a preference; it is a machine that boots, looks
  // healthy, retries forever and produces no events anywhere.
  assert.strictEqual(MODEL.validateTelemetryPlan({ stack: 'elastic' }).value.sensor, true, TRACK_E);
  assert.strictEqual(MODEL.validateTelemetryPlan({ stack: 'both' }).value.sensor, true, TRACK_E);

  const forced = MODEL.validateTelemetryPlan({ stack: 'wazuh', sensor: true });
  assert.strictEqual(forced.value.sensor, false,
    `An authored true must be overwritten, not honoured. ${TRACK_E}`);
  assert.deepStrictEqual(forced.errors, [],
    `It is a WARNING, not an error: the engagement is still perfectly deployable, it just has no `
    + `synthetic floor. ${TRACK_E}`);
  assert.ok(forced.warnings.some(w => w.code === 'TELEMETRY_SENSOR_NOT_AVAILABLE'), TRACK_E);
});

test('E3-12: a wazuh-only plan warns that there is no false-positive floor', () => {
  // Stated honestly rather than discovered in class: with no synthetic haystack
  // every event in the index belongs to the incident, so triage degenerates to
  // "find the only thing there".
  const r = MODEL.validateTelemetryPlan({ stack: 'wazuh' });
  assert.ok(r.warnings.some(w => w.code === 'TELEMETRY_NO_SYNTHETIC_FLOOR'), TRACK_E);
});

test('E3-13: an empty plan is legal and means no telemetry at all', () => {
  const r = MODEL.validateTelemetryPlan({});
  assert.deepStrictEqual(r.errors, [], TRACK_E);
  assert.deepStrictEqual(r.value, {},
    `{} is the column DEFAULT. An ordinary offensive engagement patching an unrelated field must `
    + `never be told about a SIEM. ${TRACK_E}`);
  const bad = MODEL.validateTelemetryPlan([1, 2]);
  assert.ok(bad.errors.some(e => e.code === 'TELEMETRY_PLAN_NOT_OBJECT'), TRACK_E);
});

test('E3-14: a non-empty plan must name a stack', () => {
  const r = MODEL.validateTelemetryPlan({ scenario_id: 'sc-1' });
  assert.ok(r.errors.some(e => e.code === 'TELEMETRY_STACK_REQUIRED'), TRACK_E);
});

test('E3-15: telemetryPlanFromRow is total and re-derives the sensor', () => {
  // A hand-edited row, a CSV import, or a database where 017 has not run must
  // all read back as something usable — never undefined, and never with a
  // sensor the stack cannot feed.
  assert.deepStrictEqual(MODEL.telemetryPlanFromRow({}), {}, TRACK_E);
  assert.deepStrictEqual(MODEL.telemetryPlanFromRow(null), {}, TRACK_E);
  assert.deepStrictEqual(MODEL.telemetryPlanFromRow({ telemetry_plan: 'not json' }), {}, TRACK_E);
  assert.deepStrictEqual(
    MODEL.telemetryPlanFromRow({ telemetry_plan: '{"stack":"elastic"}' }),
    { stack: 'elastic', sensor: true },
    `A jsonb column delivered as a string must still parse. ${TRACK_E}`);
  assert.strictEqual(
    MODEL.telemetryPlanFromRow({ telemetry_plan: { stack: 'wazuh', sensor: true } }).sensor, false,
    `The derivation is re-applied on the way OUT, so a hand-edited row cannot resurrect the `
    + `impossible combination the validator refuses. ${TRACK_E}`);
});

test('E3-16: telemetry_plan is NOT a MODEL_FIELD, and has its own writer', () => {
  // MODEL_FIELDS is the SET-clause list updateEngagementModel builds its UPDATE
  // from, and ciab-engagement-model.test.js B0-15 pins it to exactly the columns
  // migration 011 adds. Adding this column there fails that test. The deeper
  // reason is that `sensor` is derived: a generic PATCH that echoed a stored
  // plan back would be able to set it.
  assert.ok(!MODEL.MODEL_FIELDS.includes('telemetry_plan'), TRACK_E);
  assert.ok(!MODEL.AUTHORABLE_FIELDS.includes('telemetry_plan'), TRACK_E);
  const PROVISION = require(abs(PROVISION_REL));
  assert.strictEqual(typeof PROVISION.setEngagementTelemetryPlan, 'function',
    `Without a writer the column can only ever hold its default. ${TRACK_E}`);
  const code = jsCode(read(PROVISION_REL));
  assert.match(code, /telemetry_plan = \$2::jsonb/,
    `Cast on FIRST reference. Postgres fixes a parameter's type where it is first used. ${TRACK_E}`);
});

test('E3-17: the read projection carries telemetry_plan', () => {
  // getEngagement/listEngagements SELECT *, so the database really does return
  // the column — rowToEngagement is a hand-written whitelist that silently drops
  // anything not listed, and the tab would show an empty field against a table
  // that holds the data.
  const PROVISION = require(abs(PROVISION_REL));
  const projected = PROVISION.rowToEngagement({
    engagement_id: 'e-1', profile_id: 'p-1', engagement_type: 'defensive_monitoring',
    subnet_scheme: 'v2', telemetry_plan: { stack: 'both' },
  });
  assert.deepStrictEqual(projected.telemetry_plan, { stack: 'both', sensor: true }, TRACK_E);
  // A pre-017 row, which is every row adoptExistingReservation inserts.
  assert.deepStrictEqual(
    PROVISION.rowToEngagement({ engagement_id: 'e-2' }).telemetry_plan, {},
    `Widening the projection must be a no-op for every existing caller. ${TRACK_E}`);
});

/**
 * E7's writer on top of E3's column.
 *
 * The launcher calls it after a scenario launch so the NEXT deploy rebuilds the
 * benign floor from the scenario the incident was actually written for. Two
 * properties, and both are the same failure seen from different ends:
 *
 *   IT MERGES. telemetry_plan also holds `stack` and the resolved template
 *   keys, which are what a redeploy rebuilds the environment's images from.
 *   A writer that sent {scenario_id} alone would blank them and the next build
 *   would silently land on whatever the catalog tags today.
 *
 *   IT NEVER THROWS. The incident has already been dispatched by the time it
 *   runs. Failing the launch over a bookkeeping write would abort a live
 *   exercise to protect the next one.
 *
 * The CiAB pool is injected rather than stubbed through require.cache, because
 * utils/db.js is built for exactly that — setPool() is how the plugin loader
 * hands it the real one.
 */
test('E7-13: recordTelemetryScenario merges one key, and never throws', async () => {
  const PROVISION = require(abs(PROVISION_REL));
  const DB = require(abs(`${CIAB}/utils/db.js`));

  const seen = [];
  let stored = {
    engagement_id: 'e-1', profile_id: 'p-1', engagement_type: 'defensive_monitoring',
    subnet_scheme: 'v2',
    telemetry_plan: { stack: 'elastic', sensor: true, elk_template_key: 'elk-2026-03' },
  };
  DB.setPool({
    on() {},
    query: async (text, params) => {
      seen.push({ text: String(text).replace(/\s+/g, ' ').trim(), params });
      if (/UPDATE ciab_engagement/i.test(text)) {
        stored = { ...stored, telemetry_plan: JSON.parse(params[1]) };
        return { rows: [stored], rowCount: 1 };
      }
      return { rows: [stored], rowCount: 1 };
    },
  });

  const ok = await PROVISION.recordTelemetryScenario('e-1', 'TS-002');
  assert.strictEqual(ok.written, true, TRACK_E);
  assert.strictEqual(stored.telemetry_plan.scenario_id, 'TS-002', TRACK_E);
  assert.strictEqual(stored.telemetry_plan.stack, 'elastic',
    `The stack must survive: it is what decides which SIEM deploys. ${TRACK_E}`);
  assert.strictEqual(stored.telemetry_plan.elk_template_key, 'elk-2026-03',
    `The recorded image must survive, or the next redeploy lands on a different one. ${TRACK_E}`);
  // sensor is DERIVED on every write, so this path cannot introduce the
  // combination validateTelemetryPlan exists to make unauthorable.
  assert.strictEqual(stored.telemetry_plan.sensor, true, TRACK_E);

  // Writing the same id again is a no-op, not a second UPDATE.
  const again = await PROVISION.recordTelemetryScenario('e-1', 'TS-002');
  assert.deepStrictEqual(again, { written: false, reason: 'unchanged' }, TRACK_E);

  // An engagement that stands up NO telemetry: {} is the column default and a
  // legal value. Writing {scenario_id} there would fail validation with
  // TELEMETRY_STACK_REQUIRED, and inventing a stack would deploy a SIEM nobody
  // asked for on the next build.
  stored = { ...stored, telemetry_plan: {} };
  assert.deepStrictEqual(
    await PROVISION.recordTelemetryScenario('e-1', 'TS-002'),
    { written: false, reason: 'no-plan' }, TRACK_E);

  // And a database that is simply gone is a reason, not an exception.
  DB.setPool({ on() {}, query: async () => { throw new Error('pool is gone'); } });
  assert.deepStrictEqual(
    await PROVISION.recordTelemetryScenario('e-1', 'TS-002'),
    { written: false, reason: 'error' },
    `A launch that already went out must not be failed by its own bookkeeping. ${TRACK_E}`);
});

// ════════════════════════════════════════════════════════════════════════════
// §4 — MIGRATION 017 HYGIENE
// ════════════════════════════════════════════════════════════════════════════

test('E3-18: migration 017 is ONE natively re-runnable statement', () => {
  // src/plugin-loader.js sends every .sql file in this directory to pool.query()
  // on EVERY boot, as one implicit transaction per file, inside a try/catch
  // whose catch only console.error()s. One statement that can raise on boot 2
  // silently reverts its whole file, forever, while the server starts normally.
  const code = sqlCode(read(MIG_REL));
  const statements = code.split(';').map(s => s.trim()).filter(Boolean);
  assert.strictEqual(statements.length, 1,
    `017 must be exactly one statement, so a partial application is structurally impossible. `
    + `Got: ${JSON.stringify(statements)}. ${TRACK_E}`);
  assert.match(statements[0],
    /^ALTER TABLE ciab_engagement ADD COLUMN IF NOT EXISTS telemetry_plan JSONB NOT NULL DEFAULT '\{\}'::jsonb$/,
    TRACK_E);
});

test('E3-19: 017 adds no constraint and no index, and reaches clinic_db only', () => {
  const code = sqlCode(read(MIG_REL));
  assert.ok(!/ADD CONSTRAINT|CHECK\s*\(/i.test(code),
    `Adding a constraint to a column that already holds live rows is the one genuinely unsafe `
    + `operation available in a boot-rerun directory: it validates against existing rows and a `
    + `single row it dislikes reverts the file on every boot. ${TRACK_E}`);
  assert.ok(!/DROP\s+(COLUMN|CONSTRAINT|TABLE)/i.test(code), TRACK_E);
  for (const foreign of ['cybercore_lane', 'cybercore_template_catalog', 'cle_course', 'cybercore_user']) {
    assert.ok(!new RegExp(foreign, 'i').test(code),
      `A CiAB migration runs against clinic_db. '${foreign}' lives in another database and the `
      + `statement would raise 42P01 on every boot. ${TRACK_E}`);
  }
});

test('E3-20: 017 has a DEFAULT, so the read-path adopt keeps working', () => {
  // adoptExistingReservation's UPSERT runs on the READ path — merely opening the
  // Engagements tab executes it — with a FIXED 8-column list. A NOT NULL column
  // WITHOUT a default would break that on the first page load.
  const code = sqlCode(read(MIG_REL));
  assert.match(code, /NOT NULL DEFAULT '\{\}'::jsonb/, TRACK_E);

  const body = read(PROVISION_REL);
  const insert = body.slice(body.indexOf('async function adoptExistingReservation'));
  const cols = insert.match(/INSERT INTO ciab_engagement\s*\(([\s\S]*?)\)\s*VALUES/);
  assert.ok(cols, TRACK_E);
  assert.ok(!/telemetry_plan/.test(cols[1]),
    `E3 must not widen that INSERT. An adopted reservation has made no telemetry decision, and a `
    + `separate test pins the column list at eight. ${TRACK_E}`);
});

test('E3-21: 017 sorts last, after every migration whose table it depends on', () => {
  // The runner is readdirSync().filter('.sql').sort(), so ordering is by FULL
  // FILENAME. ciab_engagement is created by 010; anything that sorted before it
  // would ALTER a table that does not exist yet.
  const names = fs.readdirSync(abs(`${CIAB}/migrations`)).filter(f => f.endsWith('.sql')).sort();
  const me = path.basename(MIG_REL);
  assert.ok(names.includes(me), TRACK_E);
  assert.ok(me > '010_ciab_engagements.sql', TRACK_E);
  assert.strictEqual(names[names.length - 1], me,
    `017 is the newest CiAB migration. If a later one has landed, this assertion is the reminder `
    + `to check the ordering rather than assume it. ${TRACK_E}`);
  assert.strictEqual(names.filter(n => n.slice(0, 3) === '017').length, 1,
    `Two files sharing a numeric prefix is survivable but confusing; there is no reason to add one. `
    + `${TRACK_E}`);
});

// ════════════════════════════════════════════════════════════════════════════
// §5 — ADDRESSING PARITY: THE MIRROR AND ITS AUTHORITY
// ════════════════════════════════════════════════════════════════════════════

test('E3-22: the synthesizer still loads with no cluster and no database', () => {
  assert.deepStrictEqual(HEAVY_AFTER_PURE, [],
    `Requiring engagement-model.js and profile-to-spec.js pulled in ${HEAVY_AFTER_PURE.join(', ')}. `
    + `Each of those constructs a pool or a cluster client AT REQUIRE TIME, so the synthesizer `
    + `would stop being loadable from a plain unit test — and the failure would name the wrong `
    + `file. ${TRACK_E}`);
  const code = jsCode(read(SYNTH_REL));
  assert.ok(!/require\(.*goad-deploy/.test(code),
    `The SIEM octets are MIRRORED from goad-deploy.js, not imported: that module pulls `
    + `script-executor -> proxmox + db. The mirror is checked below instead. ${TRACK_E}`);
  assert.ok(!/require\(.*blueteam-templates/.test(code),
    `The synthesizer is handed resolved template ids; it never queries a catalog. ${TRACK_E}`);
});

test('E3-23: SIEM_OCTETS agrees with GOAD_EXTENSIONS, its authority', () => {
  // This is the one place that can afford to load both — same trade
  // ciab-deploy-parity.test.js makes for the .80-.99 band.
  const goad = require(abs('src/utils/goad-deploy.js'));
  assert.strictEqual(SYNTH.SIEM_OCTETS.elk, goad.GOAD_EXTENSIONS.elk.ipOctet,
    `A drifted octet is a dhcp-host line for an address something else owns, and dnsmasq refuses `
    + `to START on a duplicate — which takes DHCP down for the whole lane. ${TRACK_E}`);
  assert.strictEqual(SYNTH.SIEM_OCTETS.wazuh, goad.GOAD_EXTENSIONS.wazuh.ipOctet, TRACK_E);

  // Neither may ever equal a lane infrastructure octet. On v2 there is ONE flat
  // segment, so .50 (Kali) really is the same address as upstream's ELK pin.
  for (const [name, octet] of Object.entries(SYNTH.SIEM_OCTETS)) {
    for (const [infra, taken] of Object.entries(goad.INFRA_IP_OCTETS)) {
      assert.notStrictEqual(octet, taken,
        `${name} claims .${octet}, which is the lane ${infra}. ${TRACK_E}`);
    }
    assert.ok(octet < SYNTH.SPEC_OCTET_MIN || octet > SYNTH.SPEC_OCTET_MAX,
      `${name} must be OUTSIDE the .${SYNTH.SPEC_OCTET_MIN}-.${SYNTH.SPEC_OCTET_MAX} band, or it `
      + `would collide with a band octet the walk invents. ${TRACK_E}`);
    assert.ok(Number.isInteger(octet) && octet >= 2 && octet <= 254,
      `resolveSpecAddressing PASS 1 range-checks an explicit octet 2-254 and throws otherwise. `
      + `${TRACK_E}`);
  }
});

test('E3-24: the SIEMs stay OUT of GOAD_LABS, which is what gives them a host-record', () => {
  const goad = require(abs('src/utils/goad-deploy.js'));
  for (const key of ['elk', 'wazuh']) {
    assert.strictEqual(goad.GOAD_EXTENSIONS[key].inLab, false,
      `Being ABSENT from goadMacs is exactly what keeps a machine inside resolveSpecAddressing, and `
      + `that function is the ONLY source of the host-record that makes ${key}.cybercore.lan resolve. `
      + `In a lab roster it would get a MAC and a dhcp-host line and LOSE the host-record — after `
      + `which the sensor's baked ELK_HOST resolves to nothing, ships nowhere, and reports healthy. `
      + `${TRACK_E}`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §6 — THE POSTDEPLOY CHAIN
// ════════════════════════════════════════════════════════════════════════════

test('E3-25: chainPostDeploy runs EVERY hook, even after one throws', () => {
  // deployChallengeLanes takes ONE postDeploy and CiAB already spends it on the
  // vuln-app install. A Docker pull failing must not decide whether the incident
  // engine can find this lane's sensor.
  const ran = [];
  const boom = async () => { ran.push('boom'); throw new Error('docker pull failed'); };
  const ok = async () => { ran.push('ok'); };
  const hook = POSTDEPLOY.chainPostDeploy(boom, ok);
  return assert.rejects(() => hook({}), /docker pull failed/).then(() => {
    assert.deepStrictEqual(ran, ['boom', 'ok'],
      `The second hook was skipped, which is the whole failure this composer exists to prevent. `
      + `${TRACK_E}`);
  });
});

test('E3-26: exactly one failure rethrows that error unchanged', async () => {
  // The deployer records hookErr.message verbatim as config.post_deploy_error
  // and shows it to the instructor. Wrapping a single diagnostic message in a
  // summary would replace the diagnosis with a count.
  const original = Object.assign(new Error("vuln-app target 'x' is not among this lane's machines"),
    { code: 'VULN_APP_TARGET_MISSING' });
  const hook = POSTDEPLOY.chainPostDeploy(
    async () => { throw original; },
    async () => {});
  await assert.rejects(() => hook({}), (err) => {
    assert.strictEqual(err, original, `The identity, not merely the message. ${TRACK_E}`);
    return true;
  });
});

test('E3-27: two or more failures aggregate, and the message names every one', async () => {
  const hook = POSTDEPLOY.chainPostDeploy(
    async () => { throw new Error('first thing'); },
    async () => { throw new Error('second thing'); });
  await assert.rejects(() => hook({}), (err) => {
    assert.ok(err instanceof AggregateError, TRACK_E);
    assert.strictEqual(err.errors.length, 2, TRACK_E);
    assert.match(err.message, /first thing/, TRACK_E);
    assert.match(err.message, /second thing/,
      `config.post_deploy_error is the only place an instructor sees either of these. ${TRACK_E}`);
    return true;
  });
});

test('E3-28: chaining nothing is null, and chaining one is that one', () => {
  // deployChallengeLanes expects null for "no hook", and an offensive lane must
  // compose to EXACTLY the function it composed to before E3 — not to a wrapper
  // around it, which would change what post_deploy_error says.
  assert.strictEqual(POSTDEPLOY.chainPostDeploy(null, undefined), null, TRACK_E);
  const only = async () => {};
  assert.strictEqual(POSTDEPLOY.chainPostDeploy(only, null), only, TRACK_E);
});

// ════════════════════════════════════════════════════════════════════════════
// §7 — THE SENSOR STAMP
// ════════════════════════════════════════════════════════════════════════════

const SENSOR_SPEC = {
  vms: [
    { name: 'DC-01', role: 'server' },
    { name: 'sensor', role: 'sensor' },
    { name: 'elk', role: 'siem' },
  ],
};

test('E3-29: no sensor in the spec means no hook at all', () => {
  assert.strictEqual(
    POSTDEPLOY.makeSensorStampPostDeploy({ vms: [{ name: 'DC-01', role: 'server' }] }), null,
    `Same shape makeVulnAppPostDeploy uses for "there is no app": an offensive engagement composes `
    + `to what it always composed to. ${TRACK_E}`);
  assert.strictEqual(POSTDEPLOY.makeSensorStampPostDeploy({}), null, TRACK_E);
  assert.strictEqual(POSTDEPLOY.makeSensorStampPostDeploy(null), null, TRACK_E);
});

test('E3-30: the sensor is found by ROLE, matching the incident engine LOGGEN_ROLES', () => {
  const vm = POSTDEPLOY.findSensorSpecVm(SENSOR_SPEC);
  assert.strictEqual(vm.name, 'sensor', TRACK_E);
  assert.ok(TARGET_REL, `Could not find the incident target ladder. ${TRACK_E}`);
  const ladder = read(TARGET_REL);
  assert.match(ladder, /const LOGGEN_ROLES = new Set\(\[[^\]]*'sensor'/,
    `role 'sensor' must stay in the engine's LOGGEN_ROLES set, or rung 2 of the target ladder — the `
    + `recovery path when the stamp is lost — stops firing with no error anywhere. ${TRACK_E}`);
});

test('E3-31: the stamp matches the SPEC name, never proxmox_name', async () => {
  // proxmox_name carries the student suffix, so matching on it would work on
  // lane 1 and silently fail on every other lane in the class.
  SQL.length = 0;
  const records = new Map();
  const hook = POSTDEPLOY.makeSensorStampPostDeploy(SENSOR_SPEC, { records });
  await hook({
    laneId: 'lane-9',
    deployedVMs: [
      { name: 'DC-01', vm_id: 600001, node: 'n1', proxmox_name: 'dc-01-student3' },
      { name: 'sensor', vm_id: 620001, node: 'n2', proxmox_name: 'sensor-student3' },
    ],
  });
  const rec = records.get('lane-9');
  assert.ok(rec, TRACK_E);
  assert.strictEqual(rec.vmid, 620001, TRACK_E);
  assert.strictEqual(rec.node, 'n2', TRACK_E);
  assert.strictEqual(rec.vm_name, 'sensor', TRACK_E);
  assert.strictEqual(rec.resolved_by, 'postdeploy',
    `Rung 0's provenance — it is what GET /targets reports. ${TRACK_E}`);
});

test('E3-32: the stamp is a single-statement jsonb_set, never read-modify-write', async () => {
  // A dispatch resolves many lanes at once. A SELECT-mutate-UPDATE of a JSONB
  // column loses one of two concurrent edits; this mirrors cacheLoggenTarget's
  // statement exactly, COALESCE and create_missing included.
  SQL.length = 0;
  const hook = POSTDEPLOY.makeSensorStampPostDeploy(SENSOR_SPEC);
  await hook({ laneId: 'lane-1', deployedVMs: [{ name: 'sensor', vm_id: 1, node: 'n1' }] });
  assert.strictEqual(SQL.length, 1, `One statement, not a read then a write. ${TRACK_E}`);
  assert.match(SQL[0].text, /jsonb_set\(COALESCE\(config, '\{\}'::jsonb\), '\{loggen\}', \$2::jsonb, true\)/,
    `COALESCE + create_missing=true, so a lane whose config is NULL or lacks the key still gets one `
    + `— plain jsonb_set silently no-ops on both. ${TRACK_E}`);
  assert.ok(!/SELECT/i.test(SQL[0].text), TRACK_E);
});

test('E3-33: a spec that declares a sensor and a lane that has none is an error', async () => {
  // Not a silent skip. The environment would look complete, the SIEM would be
  // up, and every incident run against the lane would resolve nothing — and the
  // ladder's later rungs cannot save it, because there is no machine to find.
  const hook = POSTDEPLOY.makeSensorStampPostDeploy(SENSOR_SPEC);
  await assert.rejects(
    () => hook({ laneId: 'lane-2', deployedVMs: [{ name: 'DC-01', vm_id: 1, node: 'n1' }] }),
    /nothing to aim at/, TRACK_E);
});

test('E3-34: the stamp is RE-APPLIED after the deployer writes each config whole', () => {
  // challenge-lane-deployer builds the active config from the batch-wide
  // laneConfig and writes it WHOLE in its final step, which runs AFTER the
  // postDeploy hook. Anything the hook merged into config is gone by then —
  // exactly what applyReseedRecords already exists for.
  const deployer = jsCode(read('src/utils/challenge-lane-deployer.js'));
  assert.match(deployer, /UPDATE cybercore_lane SET status = 'active', config = \$2::jsonb/,
    `If this whole-config write ever becomes a merge, the re-apply below is redundant rather than `
    + `load-bearing — and someone should be told. ${TRACK_E}`);

  const prov = jsCode(read(LANEPROV_REL));
  assert.match(prov, /applySensorStamps\(sensorStampRecords\)/,
    `Without the drain the stamp never survives the deploy it was made during. ${TRACK_E}`);
  const provRaw = read(LANEPROV_REL);
  assert.ok(
    provRaw.indexOf('deployChallengeLanes(') < provRaw.indexOf('applySensorStamps('),
    `The re-apply must come AFTER the deploy returns, or it writes into a config the deployer is `
    + `about to overwrite. ${TRACK_E}`);
});

// ════════════════════════════════════════════════════════════════════════════
// §8 — LANE CONFIG: HOW ANYTHING OUTSIDE THIS PLUGIN FINDS A CiAB LANE
// ════════════════════════════════════════════════════════════════════════════

test('E3-35: every deploy path writes engagement_id and profile_id onto the lane', () => {
  // The incident engine discovers a scope's lanes from cybercore_lane.config:
  // a course lane is config->>'course_id', a CiAB lane is
  // config->>'engagement_id' AND config->>'ciab' = 'true'. Without these keys
  // the second arm matches nothing.
  const code = jsCode(read(LANEPROV_REL));
  const configs = [...code.matchAll(/laneConfig: \{([^}]*)\}/g)].map(m => m[1]);
  assert.ok(configs.length >= 2,
    `Both provisionProfileLanes and retryProfileLane build one. ${TRACK_E}`);
  for (const c of configs) {
    assert.match(c, /ciab: true/, TRACK_E);
    assert.match(c, /engagement_id:/,
      `A retried lane missing engagement_id is the one lane in a class the engine cannot find — and `
      + `it is the lane that was already having a bad day. ${TRACK_E}`);
    assert.match(c, /profile_id:/, TRACK_E);
  }
});

test('E3-36: no allowlist edit was needed, because the spec path spreads laneConfig verbatim', () => {
  // LANE_CONFIG_PASSTHROUGH_KEYS belongs to lane-deployer.js's WORKSTATION path.
  // It is easy to assume the new keys must be added to it; they must not, and
  // this records why.
  const deployer = jsCode(read('src/utils/challenge-lane-deployer.js'));
  assert.match(deployer, /const activeConfig = \{ \.\.\.laneConfig,/,
    `The challenge path spreads laneConfig VERBATIM. If that ever becomes a filtered copy, `
    + `engagement_id disappears from every CiAB lane with no error anywhere. ${TRACK_E}`);
});

test('E3-37: the routes thread the engagement id into all three deploy paths', () => {
  const code = jsCode(read(ROUTE_REL));
  const calls = [...code.matchAll(/(provisionProfileLanes|retryProfileLane)\(\{([\s\S]{0,900}?)\}\)/g)];
  assert.ok(calls.length >= 3,
    `Expected the first deploy, add-lanes and retry. Found ${calls.length}. ${TRACK_E}`);
  for (const [, fn, args] of calls) {
    // [,:] because both spellings are live: an explicit `engagementId: x` and
    // the ES6 shorthand `profileId,` where the local already has the name.
    assert.match(args, /engagementId[,:]/,
      `${fn} is called without an engagementId, so its lanes are invisible to the engine. ${TRACK_E}`);
    assert.match(args, /profileId[,:]/, `${fn} is called without a profileId. ${TRACK_E}`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §9 — attackBoxes: THE CONSOLE THE STUDENT ACTUALLY OPENS
// ════════════════════════════════════════════════════════════════════════════

test('E3-38: attack boxes default OFF for defensive_monitoring, ON for everything else', () => {
  const code = jsCode(read(ROUTE_REL));
  assert.match(code,
    /const attackBoxes = opts\.attackBoxes === undefined \? engagement !== BLUE_TEAM_TYPE_KEY : !!opts\.attackBoxes;/,
    `resolveConsolePlan picks the primary console as consoles.find(kind === 'kali') before it looks `
    + `at anything else, so on a lane where Kali exists Kali IS the Console button. Left true, the `
    + `student presses Console and lands on the attacker's machine instead of the SIEM — no error, `
    + `no warning. ${TRACK_E}`);
  assert.ok(!/attackBoxes = true,/.test(code),
    `A destructured default of true would win over the engagement-aware one. ${TRACK_E}`);
});

test('E3-39: an omitted attack_boxes reaches the default as undefined, not as true', () => {
  // `attack_boxes !== false` resolves an OMITTED field to true, which is how a
  // defensive lane would silently acquire a Kali box despite the default above.
  for (const rel of [ROUTE_REL, `${CIAB}/routes/profiles.js`]) {
    const code = jsCode(read(rel));
    const bad = /attackBoxes: attack_boxes !== false/.test(code);
    assert.ok(!bad,
      `${rel} still turns an omitted attack_boxes into true, so the engagement-aware default can `
      + `never fire. ${TRACK_E}`);
    if (/attackBoxes: attack_boxes/.test(code)) {
      assert.match(code, /attackBoxes: attack_boxes === undefined \? undefined : attack_boxes !== false/,
        `${rel} must pass undefined when the body omits the field. ${TRACK_E}`);
    }
  }
});

test('E3-40: the deploy reports which way the default went', () => {
  // The default is engagement-dependent now, so a caller that omitted the field
  // has no other way to learn what was built — and the audit record would
  // otherwise state a fact about the lane that is not true of it.
  const code = jsCode(read(ROUTE_REL));
  assert.match(code, /attack_boxes: attackBoxes,/, TRACK_E);
  assert.match(code, /attack_boxes: result\.attack_boxes,/, TRACK_E);
});

// ════════════════════════════════════════════════════════════════════════════
// §10 — THE NAMED 400: role_hints HAS NO ADMIN UI
// ════════════════════════════════════════════════════════════════════════════

test('E3-41: an engagement with no telemetry plan resolves to null and queries nothing', async () => {
  SQL.length = 0;
  assert.strictEqual(await TEMPLATES.resolveTelemetryTemplates({}), null, TRACK_E);
  assert.strictEqual(await TEMPLATES.resolveTelemetryTemplates(null), null, TRACK_E);
  assert.strictEqual(await TEMPLATES.resolveTelemetryTemplates({ stack: 'splunk' }), null, TRACK_E);
  assert.deepStrictEqual(SQL, [],
    `Every offensive deploy goes through this call. It must cost nothing. ${TRACK_E}`);
});

test('E3-42: a missing role_hints tag is a NAMED 400 carrying the SQL that fixes it', async () => {
  // "untagged" is the NORMAL first-time state: role_hints is a TEXT[] that
  // nothing in the admin UI writes. If this returned null instead, the lane
  // would deploy, come up green, and have nowhere to send anything.
  SQL.length = 0;
  NEXT_ROWS = [];
  await assert.rejects(
    () => TEMPLATES.resolveTelemetryTemplates({ stack: 'elastic', sensor: true }),
    (err) => {
      assert.strictEqual(err.status, 400, TRACK_E);
      assert.strictEqual(err.statusCode, 400,
        `routes/profile-deploy.js renders err.statusCode; without it this is a 500. ${TRACK_E}`);
      assert.strictEqual(err.code, 'TELEMETRY_TEMPLATE_MISSING_SENSOR', TRACK_E);
      assert.match(err.message, /UPDATE cybercore_template_catalog SET role_hints/,
        `The refusal must carry the remedy — there is no screen that can set role_hints. ${TRACK_E}`);
      assert.match(err.message, /'loggen'/, TRACK_E);
      return true;
    });
});

test('E3-43: each role refuses under its own name', () => {
  for (const [key, expected] of [
    ['sensor', 'TELEMETRY_TEMPLATE_MISSING_SENSOR'],
    ['elk', 'TELEMETRY_TEMPLATE_MISSING_ELK'],
    ['wazuh', 'TELEMETRY_TEMPLATE_MISSING_WAZUH'],
  ]) {
    const err = TEMPLATES.missingTemplateError(key, { envKeyWasSet: false });
    assert.strictEqual(err.code, expected,
      `A combined refusal would make the instructor guess which of three images is missing. `
      + `${TRACK_E}`);
    assert.match(err.message, new RegExp(`'${TEMPLATES.TELEMETRY_ROLES[key].hint}'`), TRACK_E);
  }
});

test('E3-44: the sensor query is loadLoggenTemplate\'s, and honours the SAME env override', () => {
  // Two different queries for one image would let CiAB and CYBR 400 deploy
  // DIFFERENT sensors out of one catalog, after which the incident engine's
  // ladder resolves one machine and probes the other.
  assert.strictEqual(TEMPLATES.TELEMETRY_ROLES.sensor.envKey, 'CYBR400_LOGGEN_TEMPLATE_KEY',
    `Not a new CIAB_-prefixed variable: a site that has already pinned its sensor must not have to `
    + `pin it twice, and two variables that disagree is a lane aimed at the wrong box. ${TRACK_E}`);
  const mine = jsCode(read(TEMPLATES_REL));
  assert.match(mine, /'\$\{role\.hint\}' = ANY\(role_hints\) AND is_active/, TRACK_E);
  const theirs = jsCode(read(TARGET_REL));
  assert.match(theirs, /'loggen' = ANY\(role_hints\) AND is_active/,
    `If the engine's own query changes shape, this mirror has to change with it. ${TRACK_E}`);
});

test('E3-45: the two SIEM queries refuse a draft row and a row with no VMID', () => {
  // These machines are cloned directly by this plugin, and status has its own
  // CHECK ('draft' | 'active' | 'retired') — a half-registered draft is a real
  // state a site passes through, and a row with no template_vmid clones nothing
  // hours into a batch.
  for (const key of ['elk', 'wazuh']) {
    const pred = TEMPLATES.TELEMETRY_ROLES[key].extraPredicate;
    assert.match(pred, /template_type = 'workstation'/, TRACK_E);
    assert.match(pred, /status = 'active'/, TRACK_E);
    assert.match(pred, /template_vmid IS NOT NULL/, TRACK_E);
  }
  assert.strictEqual(TEMPLATES.TELEMETRY_ROLES.elk.envKey, 'CIAB_ELK_TEMPLATE_KEY', TRACK_E);
  assert.strictEqual(TEMPLATES.TELEMETRY_ROLES.wazuh.envKey, 'CIAB_WAZUH_TEMPLATE_KEY', TRACK_E);
});

test('E3-46: a resolved plan carries exactly the machines the stack asks for', async () => {
  const row = (vmid) => [{ template_vmid: vmid, template_key: 'k', node: 'n1', os_name: 'Ubuntu' }];

  SQL.length = 0;
  NEXT_ROWS = row(1801);
  const wazuhOnly = await TEMPLATES.resolveTelemetryTemplates({ stack: 'wazuh', sensor: false });
  assert.strictEqual(wazuhOnly.sensor, null,
    `The loggen sensor ships to Elasticsearch only. ${TRACK_E}`);
  assert.strictEqual(wazuhOnly.elk, null,
    `A wazuh-only site must never be asked to tag an Elastic image it does not have. ${TRACK_E}`);
  assert.strictEqual(wazuhOnly.wazuh.template_vmid, 1801, TRACK_E);
  assert.strictEqual(SQL.length, 1, `One row asked for, one query run. ${TRACK_E}`);
});

test('E3-48: the telemetry plan has exactly one way in, and it replaces the plan whole', () => {
  // telemetry_plan is not one of the seven fields PATCH edits and is not a
  // MODEL_FIELD, so updateEngagementModel could never write it. Without this
  // route the column can only ever hold its default, and every part of E3
  // downstream of it is unreachable.
  const src = read(`${CIAB}/routes/engagements.js`);
  assert.match(src, /router\.put\('\/:engagementId\/telemetry', instructorOnly,/,
    `PUT, not PATCH: there is no partial telemetry plan — a stack carrying half its template `
    + `keys from a previous decision is a lane built from images nobody chose. instructorOnly, `
    + `because choosing a SIEM carves nothing and spends no VXLAN id. ${TRACK_E}`);
  assert.match(src, /setEngagementTelemetryPlan\(/,
    `It must go through the narrow writer, which re-derives sensor on every write. ${TRACK_E}`);

  const code = jsCode(src);
  assert.ok(!/updateEngagementModel\([^)]*telemetry/.test(code),
    `The general model writer must never be handed a telemetry plan: its patch semantics would let `
    + `a caller echo a stored plan back and set the derived field. ${TRACK_E}`);
  // Reading a SCALAR off the plan (`engagement.telemetry_plan.stack`) is fine
  // and is what the row should carry. What must never appear is the object
  // itself as a metadata value, or a spread of anything.
  assert.ok(!/metadata: \{[^}]*telemetry_plan:/.test(code),
    `Audit rows carry names and counts, never the object — audit.js caps serialized metadata at `
    + `16KB and DISCARDS it whole when it is bigger, taking profile_id with it. ${TRACK_E}`);
  assert.ok(!/metadata: \{[^}]*\.\.\./.test(code),
    `test/audit-hygiene.test.js is a source-literal check and CANNOT SEE A SPREAD, so a spread is `
    + `not caught — it is merely unnoticed. ${TRACK_E}`);
});

test('E3-49: /types tells a screen the stack vocabulary and the scheme it forces', () => {
  // One decision, one payload: choosing the defensive type is what makes a
  // stack picker relevant AND what forces the subnet scheme, so a create form
  // that had to call a second route could render the picker without the
  // constraint.
  const code = jsCode(read(`${CIAB}/routes/engagements.js`));
  assert.match(code, /telemetry_stacks: \[\.\.\.TELEMETRY_STACKS\]/, TRACK_E);
  assert.match(code, /telemetry_type: BLUE_TEAM_TYPE_KEY/, TRACK_E);
  assert.match(code, /telemetry_subnet_scheme: BLUE_TEAM_SUBNET_SCHEME/,
    `Read from the registry, never spelled on the screen — a form that hard-coded 'v2' and a `
    + `validator that changed its mind would disagree silently. ${TRACK_E}`);
});

test('E3-47: an engagement-recorded template_key beats the environment variable', async () => {
  // A lane redeployed months later must land on the image it was BUILT against,
  // not on whatever happens to be tagged that day.
  SQL.length = 0;
  NEXT_ROWS = [{ template_vmid: 1900, template_key: 'pinned', node: 'n1', os_name: 'Ubuntu' }];
  const r = await TEMPLATES.resolveTelemetryTemplates({
    stack: 'wazuh', sensor: false, wazuh_template_key: 'pinned',
  });
  assert.strictEqual(r.wazuh.template_vmid, 1900, TRACK_E);
  assert.deepStrictEqual(SQL[0].params, ['pinned'],
    `The key must reach the query as a PARAMETER, never interpolated. ${TRACK_E}`);
  assert.match(SQL[0].text, /WHERE template_key = \$1/, TRACK_E);
});
