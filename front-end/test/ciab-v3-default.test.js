/**
 * ciab-v3-default.test.js — Track R1: v3 is the DEFAULT, not just a constant.
 * ============================================================================
 * THE DEFECT THIS FILE EXISTS TO KEEP CLOSED.
 *
 * utils/profile-to-spec.js declared `DEFAULT_SUBNET_SCHEME = 'v3'` and exported
 * it, and test/ciab-spec-dns-topology.test.js:397 asserted the flip. All of it
 * was INERT: that constant only fires when a caller OMITS `options.subnetScheme`,
 * and not one live caller did. Every real path spelled the fallback itself —
 *
 *   routes/engagements.js         :316  subnetScheme: engagement.subnet_scheme || 'v2'
 *   routes/engagements.js         :549  subnetScheme: body.subnet_scheme      || 'v2'
 *   routes/profile-deploy.js      :209  subnetScheme = 'v2'   (runProfileDeploy)
 *   routes/profile-deploy.js      :626  subnetScheme: subnet_scheme || 'v2'
 *   routes/profile-deploy.js      :758  subnetScheme: subnet_scheme || 'v2'
 *   utils/engagement-provision.js :524  subnetScheme = 'v2'   (createEngagement)
 *   migrations/006, 010                 DEFAULT 'v2'
 *
 * — so every engagement was still carved AND built as v2, one flat lan0, and the
 * enforced-pivot DMZ topology never engaged for anybody. Six spellings of one
 * fact is what let the flip drift; the fix is ONE exported constant that every
 * site reads, which is what §1 pins.
 *
 * WHY IT MATTERS THAT THE TOPOLOGY ENGAGES. On v2 the attack box, the company
 * web host and the domain controller share a broadcast domain, so "pivot through
 * the web server to reach AD" is a CONVENTION a student can decline to follow.
 * On v3 the FORWARD drop between ext0 and int0 makes it a fact about the network.
 * §3 proves the default really produces that shape rather than merely a string.
 *
 * STUBS. §2 replaces utils/db.js, utils/lane-reservation.js and
 * src/utils/lab-network-provision.js in require.cache — the shape
 * test/ciab-engagement-routes.test.js:726-745 uses — so no cluster and no
 * database is touched. utils/profile-to-spec.js and utils/engagement-model.js
 * are the REAL modules: the constant under test is profile-to-spec's, and
 * stubbing it would make §1 assert its own fixture. site-config.js is NOT
 * stubbed and must not need to be — profile-to-spec's only edge to it is
 * vm-template-resolver.js:83 `row.node || getDefaultTemplateNode()`, so every
 * catalog fixture below carries a `node` and the lazy config read never happens.
 *
 * Run: node --test front-end/test/ciab-v3-default.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const UTILS = path.join(ROOT, 'src', 'utils');

const R1 = 'See the program plan, Track R1 (make v3 the actual default).';

const rel = (p) => path.relative(ROOT, p).replace(/\\/g, '/');
const read = (p) => fs.readFileSync(p, 'utf8');

const SYNTH_PATH     = path.join(CIAB, 'utils', 'profile-to-spec.js');
const PROVISION_PATH = path.join(CIAB, 'utils', 'engagement-provision.js');
const DEPLOY_PATH    = path.join(CIAB, 'routes', 'profile-deploy.js');
const ENGAGE_PATH    = path.join(CIAB, 'routes', 'engagements.js');
const MIG_016        = path.join(CIAB, 'migrations', '016_ciab_v3_default.sql');

// The three files R1 owns. profile-to-spec.js is deliberately absent: it owns
// the constant and was already correct.
const CALL_SITE_FILES = [ENGAGE_PATH, DEPLOY_PATH, PROVISION_PATH];

// ── Source-scan helpers ─────────────────────────────────────────────────────
// EVERY scan splits on /\r?\n/. The working tree is CRLF (core.autocrlf=true,
// no .gitattributes) and '\r' is a line terminator to a JS regex, so a
// whole-file /^\s*\/\/.*$/gm stripper silently stops stripping on this checkout
// — test/ciab-engagement-model.test.js:97-101 documents the same trap.

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

/** SQL with every -- comment removed, line by line. */
function sqlCode(src) {
  return src
    .split(/\r?\n/)
    .map((line) => line.replace(/--.*$/, ''))
    .filter((line) => line.trim() !== '')
    .join('\n');
}

// ════════════════════════════════════════════════════════════════════════════
// §1 — ONE CONSTANT, ONE OWNER, AND NO LITERAL LEFT BEHIND
// ════════════════════════════════════════════════════════════════════════════

const SYNTH = require(SYNTH_PATH);

test('R1-1: profile-to-spec.js owns the default and it is v3', () => {
  assert.strictEqual(SYNTH.DEFAULT_SUBNET_SCHEME, 'v3',
    'This is the one declaration. Every other file imports it; nothing re-declares it. '
    + `${R1}`);
});

test('R1-2: the three call-site files import the constant and declare none of their own', () => {
  for (const file of CALL_SITE_FILES) {
    const code = jsCode(read(file));

    assert.ok(/\bDEFAULT_SUBNET_SCHEME\b/.test(code),
      `${rel(file)} must READ the default rather than spell it. ${R1}`);

    // Imported from the owner, by any relative spelling of that one module.
    assert.ok(/require\(\s*'[^']*profile-to-spec'\s*\)/.test(code),
      `${rel(file)} must reach DEFAULT_SUBNET_SCHEME through utils/profile-to-spec.js, which is its `
      + `only declaration site. ${R1}`);

    assert.ok(!/const\s+DEFAULT_SUBNET_SCHEME\s*=/.test(code),
      `${rel(file)} declares its own DEFAULT_SUBNET_SCHEME. A second declaration is the six-spellings `
      + `bug wearing a different name — the flip drifts again the moment the two disagree. ${R1}`);
  }
});

test("R1-3: no call site carries a bare 'v2' fallback any more", () => {
  // Three spellings stay legal, and each is a DIFFERENT fact from "the default":
  //   ['v1', 'v2', 'v3']              the CHECK vocabulary — v2 stays selectable
  //   deploy_path: 'v2'               the shared-deployer pipeline, not a subnet
  //   ADOPTED_SUBNET_SCHEME = 'v2'    what an already-carved legacy block IS
  const ALLOWED = [
    /\['v1',\s*'v2',\s*'v3'\]/,
    /deploy_path:\s*'v2'/,
    /const ADOPTED_SUBNET_SCHEME = 'v2';/,
  ];

  for (const file of CALL_SITE_FILES) {
    jsCode(read(file)).split(/\r?\n/).forEach((line, i) => {
      if (!line.includes("'v2'")) return;
      assert.ok(ALLOWED.some((re) => re.test(line)),
        `${rel(file)}:${i + 1} still hardcodes 'v2'. That literal is what made the flip to v3 inert: `
        + `the exported default only ever fires for a caller that omits the option. — ${line.trim()} `
        + `${R1}`);
    });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §2 — CREATION AND RESERVATION, ON A STUBBED CACHE
// ════════════════════════════════════════════════════════════════════════════

const DB  = { inserts: [], updates: [], engagements: [] };
const RES = { calls: [] };
const NET = { verified: [] };

// Same stub value the real module exports; the real one is pinned by
// test/ciab-engagement-provision.test.js's expectedTagsFor case, so this cannot
// drift silently into agreeing with nothing.
const STUB_V3_OFFSET = 4000000;

function put(modPath, exports) {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
}

put(path.join(CIAB, 'utils', 'db.js'), {
  setPool: () => {},
  query: async (sql, params = []) => {
    if (/INSERT INTO ciab_engagement/i.test(sql)) {
      DB.inserts.push({ sql, params });
      const row = {
        engagement_id: `e${DB.inserts.length}`,
        profile_id: params[0],
        engagement_type: params[1],
        subnet_scheme: params[2],
        max_students: params[3],
        provision_status: 'provisioning',
      };
      DB.engagements.push(row);
      return { rows: [row] };
    }
    if (/UPDATE ciab_engagement/i.test(sql)) {
      DB.updates.push({ sql, params });
      return { rows: [] };
    }
    if (/SELECT \* FROM ciab_engagement/i.test(sql)) {
      if (/engagement_id = \$1/.test(sql)) {
        return { rows: DB.engagements.filter((e) => e.engagement_id === params[0]) };
      }
      // No pre-existing engagement for (profile, type) — createEngagement's
      // 409 guard has to fall through for the create to happen at all.
      return { rows: [] };
    }
    return { rows: [] };
  },
});

put(path.join(CIAB, 'utils', 'lane-reservation.js'), {
  DEFAULT_ENGAGEMENT_TYPE: 'default',
  sanitizeEngagementType: (t) => (t == null || t === '' ? 'default' : String(t).toLowerCase()),
  findProfileChallenge: async () => null,
  getOrCreateProfileChallenge: async (args) => {
    RES.calls.push(args);
    return {
      challenge_id: 'c1',
      challenge_key: 'ciab-profile-aaaaaaaa-default',
      engagement_type: args.engagementType,
      vxlan_block: { start: 10000, end: 10000 + (args.requestedMax - 1) },
      max_students: args.requestedMax,
      was_existing: false,
      spec: {},
    };
  },
});

put(path.join(UTILS, 'lab-network-provision.js'), {
  V3_INTERNAL_TAG_OFFSET: STUB_V3_OFFSET,
  getLabReadiness: async () => null,
  verifyBridgesOnAllNodes: async ({ tags }) => {
    NET.verified.push(tags);
    return { ready: true, nodesReady: ['n1'], nodesPending: [], nodesUnreachable: [] };
  },
});

const PROVISION = require(PROVISION_PATH);

function resetProvisionState() {
  DB.inserts.length = 0;
  DB.updates.length = 0;
  DB.engagements.length = 0;
  RES.calls.length = 0;
  NET.verified.length = 0;
}

/**
 * createEngagement starts its carve DETACHED — nothing awaits it — so the
 * reservation half of "end to end" only exists a few ticks later. Polling a
 * predicate rather than sleeping a fixed time keeps this deterministic.
 */
async function settle(pred, tries = 200) {
  for (let i = 0; i < tries; i += 1) {
    if (pred()) return true;
    await new Promise((r) => setImmediate(r));
  }
  return pred();
}

test('R1-4: an engagement created with no scheme is stored AND carved as v3', async () => {
  resetProvisionState();

  const row = await PROVISION.createEngagement({
    profileId: 'aaaaaaaa-1111-4000-8000-000000000000',
    maxStudents: 2,
    companyName: 'Acme Clinic',
  });

  // CREATION
  assert.strictEqual(row.subnet_scheme, 'v3', `${R1}`);
  assert.strictEqual(DB.inserts.length, 1, `${R1}`);
  assert.strictEqual(DB.inserts[0].params[2], 'v3',
    'The INSERT must state v3 rather than leaning on the column DEFAULT. A row that omits the column '
    + 'reads correctly only on a database where migration 016 has already run, and the writer is the '
    + `one place that always knows. ${R1}`);

  // RESERVATION — the detached carve, with the same scheme.
  await settle(() => RES.calls.length > 0);
  assert.strictEqual(RES.calls.length, 1, `the carve must have started. ${R1}`);
  assert.strictEqual(RES.calls[0].subnetScheme, 'v3',
    'getOrCreateProfileChallenge decides how many VNets exist. Carving at v2 and later building at v3 '
    + 'creates internal VNets the teardown sweep can never name again — lane-reservation.js:91-105. '
    + `${R1}`);

  // …and readiness is checked for BOTH segments of every lane.
  await settle(() => NET.verified.length > 0);
  assert.deepStrictEqual(NET.verified[0],
    [10000, 10000 + STUB_V3_OFFSET, 10001, 10001 + STUB_V3_OFFSET],
    'A v3 block is 2N VNets, not N. Verifying only the external half would call a half-built '
    + `segmented lane ready. ${R1}`);
});

test("R1-5: an explicit 'v2' still wins, end to end", async () => {
  resetProvisionState();

  const row = await PROVISION.createEngagement({
    profileId: 'bbbbbbbb-2222-4000-8000-000000000000',
    subnetScheme: 'v2',
    maxStudents: 2,
    companyName: 'Acme Clinic',
  });

  assert.strictEqual(row.subnet_scheme, 'v2', `${R1}`);
  assert.strictEqual(DB.inserts[0].params[2], 'v2',
    'v2 must stay FULLY selectable. A default that cannot be overridden is not a default, it is a '
    + `removal. ${R1}`);

  await settle(() => RES.calls.length > 0);
  assert.strictEqual(RES.calls[0].subnetScheme, 'v2', `${R1}`);

  await settle(() => NET.verified.length > 0);
  assert.deepStrictEqual(NET.verified[0], [10000, 10001],
    `a v2 block is one VNet per lane, and asking for an internal tag would fail a healthy block. ${R1}`);
});

test('R1-6: an ADOPTED pre-A8 reservation is recorded v2, and that is not a missed literal', () => {
  assert.strictEqual(PROVISION.ADOPTED_SUBNET_SCHEME, 'v2', `${R1}`);
  assert.notStrictEqual(PROVISION.ADOPTED_SUBNET_SCHEME, PROVISION.DEFAULT_SUBNET_SCHEME,
    'adoptExistingReservation writes a row for a block that was ALREADY CARVED, before this table '
    + 'existed, by the inline deploy path — one VNet per lane. Recording v3 there would not create the '
    + 'second VNet, it would only make the row LIE about what is in Proxmox, and the next deploy would '
    + 'cable its lanes onto int-segment bridges that exist on no node. This is the same rule migration '
    + `016 refuses to break with a backfill, applied on the read path. ${R1}`);

  const body = jsCode(read(PROVISION_PATH));
  assert.ok(/reservation\.subnet_scheme \|\| ADOPTED_SUBNET_SCHEME/.test(body),
    `the adopt path must keep reading the named constant rather than the default. ${R1}`);
});

test('R1-7: engagement-provision re-exports the owner\'s constant rather than a copy', () => {
  assert.strictEqual(PROVISION.DEFAULT_SUBNET_SCHEME, SYNTH.DEFAULT_SUBNET_SCHEME,
    'Same value from the same declaration. If these two ever have to be kept in step by hand, the '
    + `six-spellings bug is back. ${R1}`);
});

test('R1-8: expectedTagsFor is what makes the capacity note true', () => {
  // The migration's capacity warning is not rhetoric: a v3 engagement really
  // does spend two tags per lane, and this is the function that counts them.
  const v2 = PROVISION.expectedTagsFor({ start: 10000, end: 10009 }, 'v2');
  const v3 = PROVISION.expectedTagsFor({ start: 10000, end: 10009 }, 'v3');
  assert.strictEqual(v2.length, 10, `${R1}`);
  assert.strictEqual(v3.length, 20,
    'Defaulting to v3 DOUBLES VNet tag consumption per engagement. Migration 016 flags it; nothing '
    + `here tries to solve it. ${R1}`);
});

// ════════════════════════════════════════════════════════════════════════════
// §3 — THE DEPLOY OPTIONS, AND THE TOPOLOGY THEY ACTUALLY PRODUCE
// ════════════════════════════════════════════════════════════════════════════

const { DUAL_HOMED_OCTET } = require(path.join(CIAB, 'utils', 'engagement-model.js'));

// Every row carries `node`, so vm-template-resolver.js:83 never calls
// getDefaultTemplateNode() and site-config.js never reads config/site.json.
const CATALOG = [
  {
    id: 1, os_family: 'linux', os_version: 'debian-13', os_name: 'Debian 13 (web)',
    template_vmid: 1005, node: 'node-1', role_hints: ['web'], is_active: true,
    preferred: true, created_at: '2025-01-01T00:00:00Z',
  },
  {
    id: 2, os_family: 'windows_server', os_version: '2022', os_name: 'Windows Server 2022',
    template_vmid: 1010, node: 'node-1', role_hints: ['dc'], is_active: true,
    preferred: true, created_at: '2025-01-01T00:00:00Z',
  },
];

const PROFILE = {
  company_name: 'Acme Clinic',
  assets: [
    { hostname: 'web01', role: 'server', os: 'Ubuntu Server 22.04 LTS', services: ['80/HTTP'] },
    { hostname: 'dc01',  role: 'server', os: 'Windows Server 2022',     services: ['445/SMB'] },
  ],
};

const VULN_APP = { install_script: 'install.sh', delivery_mode: 'docker', target_hostname: 'web01' };

const synth = (options) => SYNTH.synthesizeSpecFromProfile({
  profile: PROFILE,
  assetSelection: null,
  vmTemplateCatalog: CATALOG,
  vulnScriptCatalog: [],
  vulnApp: VULN_APP,
  options,
}).spec;

test('R1-9: omitting subnetScheme produces a real v3 lane, not just the string', () => {
  const spec = synth({});
  assert.strictEqual(spec.subnet_scheme, 'v3', `${R1}`);

  const web = spec.vms.find((v) => v.name === 'web01');
  const dc  = spec.vms.find((v) => v.name === 'dc01');

  assert.deepStrictEqual(web.nics, [{ segment: 'ext' }, { segment: 'int' }],
    'The host serving the company site is the DUAL-HOMED bridge — the only way across the FORWARD '
    + `drop. Without it "pivot through the web server" is a worksheet instruction, not a network. ${R1}`);
  assert.strictEqual(web.ipOctet, DUAL_HOMED_OCTET,
    `.240 on both segments is where challenge-lane-deployer.js actually pins it. ${R1}`);

  assert.deepStrictEqual(dc.nics, [{ segment: 'int' }],
    'Everything that is not the bridge moves INTERNAL. Left on ext0 the domain controller would sit in '
    + `the attack box's own broadcast domain and the pivot could simply be skipped. ${R1}`);
});

test("R1-10: an explicit 'v2' still synthesizes the old flat lane, byte for byte", () => {
  const spec = synth({ subnetScheme: 'v2' });
  assert.strictEqual(spec.subnet_scheme, 'v2', `${R1}`);
  for (const vm of spec.vms) {
    assert.strictEqual(vm.nics, undefined,
      `v2 is one flat lan0 and the synthesizer must not place anything. ${R1}`);
    assert.notStrictEqual(vm.ipOctet, DUAL_HOMED_OCTET,
      `nothing is dual-homed on v2, so nothing may claim the dual-homed address. ${R1}`);
  }
});

test('R1-11: runProfileDeploy defaults its own parameter to the constant', () => {
  const code = jsCode(read(DEPLOY_PATH));
  assert.ok(/subnetScheme = DEFAULT_SUBNET_SCHEME/.test(code),
    'runProfileDeploy is reachable from generate-and-deploy as well as POST /deploy, so the default '
    + `has to live on the function and not only on the route that happens to be reading. ${R1}`);
  assert.ok(!/subnetScheme = 'v[123]'/.test(code), `${R1}`);
});

test('R1-12: every route hand-off spells the default with the constant', () => {
  // Named one by one rather than by a sweeping regex, because the OTHER
  // fallback in these files — `engagementRow.subnet_scheme || subnetScheme` —
  // is correct and must not be rewritten to the constant: it prefers the
  // scheme the block was carved at over the request, which is a different rule.
  const EXPECTED = [
    // routes/engagements.js: the create form, and the offline compile.
    [ENGAGE_PATH, /subnetScheme: body\.subnet_scheme \|\| DEFAULT_SUBNET_SCHEME/],
    [ENGAGE_PATH, /subnetScheme: engagement\.subnet_scheme \|\| DEFAULT_SUBNET_SCHEME/],
    // routes/profile-deploy.js: POST /deploy, and POST /engagements.
    [DEPLOY_PATH, /subnetScheme: subnet_scheme \|\| DEFAULT_SUBNET_SCHEME/],
  ];
  for (const [file, re] of EXPECTED) {
    assert.ok(re.test(jsCode(read(file))),
      `${rel(file)} must apply the default through the constant — expected ${re}. ${R1}`);
  }

  // POST /deploy and POST /engagements are two separate hand-offs in one file
  // and BOTH were `|| 'v2'`; one of them silently keeping the old literal is
  // exactly the shape of the bug R1 is closing.
  const deployHits =
    (jsCode(read(DEPLOY_PATH)).match(/subnetScheme: subnet_scheme \|\| DEFAULT_SUBNET_SCHEME/g) || []).length;
  assert.strictEqual(deployHits, 2,
    `routes/profile-deploy.js has two request-body hand-offs and both must read the constant. ${R1}`);
});

test('R1-13: the BUILD follows the carve, or v2 stops being selectable at all', () => {
  const code = jsCode(read(DEPLOY_PATH));

  assert.ok(/const carvedScheme = engagementRow\.subnet_scheme \|\| subnetScheme;/.test(code),
    'The scheme the block was ACTUALLY carved at has to be named once and reused. Before R1 the build '
    + `read the request instead, which was survivable only while the default was itself v2. ${R1}`);

  assert.ok(/subnet_scheme: carvedScheme,/.test(code),
    'deployChallengeLanes cables every lane from `challenge.subnet_scheme` '
    + '(challenge-lane-deployer.js:2247). Passing the request there means an engagement deliberately '
    + 'created as v2 — one VNet per lane — gets built as v3 by any deploy that omits subnet_scheme, and '
    + `every lane cables onto an int bridge that was never created. ${R1}`);

  assert.ok(/carvedScheme, attackBoxes,/.test(code),
    'ciab_profile_lane_groups.subnet_scheme must record the carve too: add-lanes and retry-lane rebuild '
    + 'their challenge object from group.subnet_scheme days later, on a path nobody is watching. '
    + `${R1}`);

  // …and B0's two pinned expressions survive R1's edit. B0-71 in
  // test/ciab-engagement-model.test.js counts them and expects exactly two.
  const b0 = (code.match(/subnetScheme: engagementRow\.subnet_scheme \|\| subnetScheme/g) || []).length;
  assert.strictEqual(b0, 2,
    'Once for the reservation and once for the synthesizer options. Folding these into carvedScheme '
    + `would read identically and break B0-71, which pins the literal text. ${R1}`);
});

// ════════════════════════════════════════════════════════════════════════════
// §4 — MIGRATION 016: DEFAULTS ONLY, FOREVER
// ════════════════════════════════════════════════════════════════════════════

const MIG_SRC  = read(MIG_016);
const MIG_CODE = sqlCode(MIG_SRC);

test('R1-14: 016 sets the DEFAULT on both subnet_scheme columns', () => {
  for (const table of ['ciab_engagement', 'ciab_profile_lane_groups']) {
    assert.ok(new RegExp(`'${table}'`).test(MIG_CODE),
      `${table} must be one of the tables 016 re-defaults — 010:46 and 006:31 both declared `
      + `DEFAULT 'v2'. ${R1}`);
  }
  assert.ok(/ALTER COLUMN subnet_scheme SET DEFAULT/.test(MIG_CODE), `${R1}`);
  assert.ok(/'v3'/.test(MIG_CODE), `${R1}`);
});

test('R1-15: 016 rewrites NO existing row — no backfill, not ever', () => {
  // THE CRITICAL PROPERTY. An engagement already RESERVED as v2 has a VXLAN
  // block carved for v2: ONE VNet per lane. v3 carves TWO — an external and an
  // internal — so rewriting a live reservation's scheme does not create the
  // second VNet, it only makes the row disagree with Proxmox, and the lane then
  // deploys onto bridges that do not exist.
  for (const verb of [/\bUPDATE\b/i, /\bINSERT\b/i, /\bDELETE\b/i, /\bMERGE\b/i, /\bTRUNCATE\b/i]) {
    assert.ok(!verb.test(MIG_CODE),
      `016 contains a row-level ${verb} outside its comments. Only the DEFAULT may change: a DEFAULT `
      + 'governs rows that do not exist yet, while subnet_scheme on an existing row is a DESCRIPTION of '
      + `a carve that has already happened. ${R1}`);
  }
  // The reasoning has to survive in the file, or the next agent "helpfully"
  // adds the backfill this test forbids and only learns why from a red suite.
  assert.ok(/backfill/i.test(MIG_SRC) && /carve/i.test(MIG_SRC),
    `016 must keep the written account of WHY there is no backfill. ${R1}`);
});

test('R1-16: 016 records the capacity cost it does not solve', () => {
  assert.ok(/two VNet tags|TWO VNet|doubles/i.test(MIG_SRC),
    'v3 consumes two VNet tags per lane instead of one, so defaulting to v3 doubles tag consumption '
    + 'per engagement, and the allocator never re-uses a released block. That has to be written down '
    + `here — flagged, not solved. ${R1}`);
});

test('R1-17: 016 is idempotent, because it re-runs on every single boot', () => {
  // src/plugin-loader.js:134-147 sends every .sql in this directory to
  // pool.query() at every boot, as one implicit transaction per file, and
  // catches failure with nothing but console.error.
  assert.ok(/to_regclass/.test(MIG_CODE),
    '008\'s corollary: never reference a table another migration created without a guard, or one '
    + `missing object rolls the whole file back. ${R1}`);
  assert.ok(/information_schema\.columns/.test(MIG_CODE),
    `the COLUMN is guarded separately from the table, exactly as 012 guards 011's columns. ${R1}`);
  assert.ok(/pg_attrdef/.test(MIG_CODE),
    'The catalog read is what makes every boot after the first take no lock at all. SET DEFAULT is '
    + 'idempotent on its own but still needs ACCESS EXCLUSIVE for the instant it runs, and taking that '
    + `on two live tables at every restart is a cost with no benefit. ${R1}`);

  // Nothing in the file may be a statement that fails the SECOND time.
  assert.ok(!/ADD CONSTRAINT/i.test(MIG_CODE),
    'Postgres has no ADD CONSTRAINT IF NOT EXISTS; 012\'s header has the account. 016 needs none — a '
    + `DEFAULT is not a constraint. ${R1}`);
  assert.ok(!/DROP\s+(TABLE|COLUMN|CONSTRAINT|DEFAULT)/i.test(MIG_CODE),
    `a DROP makes the second application a different operation from the first. ${R1}`);
  for (const m of MIG_CODE.match(/CREATE\s+(TABLE|INDEX|UNIQUE INDEX)[\s\S]{0,40}/gi) || []) {
    assert.ok(/IF NOT EXISTS/i.test(m), `${m.trim()} must be IF NOT EXISTS. ${R1}`);
  }
});

test('R1-18: 016 narrows no vocabulary and renumbers nothing', () => {
  assert.ok(!/CHECK\s*\(/i.test(MIG_CODE),
    "006 and 010 both declare CHECK (subnet_scheme IN ('v1','v2','v3')). v2 stays fully selectable, "
    + `and narrowing that would make every existing v1/v2 row illegal. ${R1}`);

  const dir = path.join(CIAB, 'migrations');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  assert.ok(files.includes('016_ciab_v3_default.sql'), `${R1}`);
  const sixteens = files.filter((f) => f.startsWith('016_'));
  assert.strictEqual(sixteens.length, 1,
    `two files at the same ordinal apply in an order nobody chose. ${R1}`);
  assert.ok(files.includes('015_ciab_profile_bake.sql'),
    `015 belongs to another track and 016 must sit after it, not on it. ${R1}`);
  assert.ok(!/ciab_profile_bake/.test(MIG_CODE),
    `016 touches only the two subnet_scheme columns. ${R1}`);
});

// ─── §5 the paths a HUMAN takes ─────────────────────────────────────────────
//
// §1-§4 above prove the server-side default is v3. That is necessary and it is
// not sufficient, because a default only fires when the caller OMITS the field
// — and the three surfaces a person actually clicks were all still SENDING an
// explicit 'v2', which beats any default by construction. An engagement created
// through the UI was therefore still v2 on a tree where every server-side
// assertion in this file already passed. These tests pin the other half.

const PROFILES_ROUTE = path.join(CIAB, 'routes', 'profiles.js');
const ADMIN_LANES_JS = path.join(CIAB, 'public', 'js', 'admin-profile-lanes.js');
const ADMIN_LANES_HTML = path.join(CIAB, 'public', 'pages', 'admin-profile-lanes.html');
const ENG_UI_JS = path.join(CIAB, 'public', 'js', 'instructor-engagements.js');

test('R1-19: POST /api/profiles/generate-and-deploy routes through the constant', () => {
  // The seventh call site. It hands its scheme straight to runProfileDeploy, so
  // a bare 'v2' here silently un-defaults the whole generate-and-deploy flow no
  // matter what profile-to-spec says.
  const src = read(PROFILES_ROUTE);
  assert.ok(/subnetScheme: subnet_scheme \|\| DEFAULT_SUBNET_SCHEME/.test(src),
    `${rel(PROFILES_ROUTE)} must fall back to the imported constant, not a literal. ${R1}`);
  assert.ok(/DEFAULT_SUBNET_SCHEME\s*\}\s*=\s*require\(['"]\.\.\/utils\/profile-to-spec['"]\)/.test(src),
    `${rel(PROFILES_ROUTE)} must IMPORT the constant rather than re-declare it. ${R1}`);
  assert.ok(!/const DEFAULT_SUBNET_SCHEME\s*=/.test(src),
    `a second declaration is the same drift wearing a different name. ${R1}`);
});

test('R1-20: no browser file sends an explicit v2 fallback', () => {
  // A browser file cannot require() the constant, so each names it ONCE at the
  // top; what is forbidden is spelling 'v2' inline at the <select> read.
  for (const p of [ADMIN_LANES_JS, ENG_UI_JS]) {
    const src = read(p);
    assert.ok(!/\|\|\s*'v2'/.test(src),
      `${rel(p)} still falls back to a literal 'v2'; an explicit value beats every server default. ${R1}`);
  }
  assert.ok(/const DEFAULT_SUBNET_SCHEME = 'v3';/.test(read(ADMIN_LANES_JS)), `${R1}`);
  assert.ok(/const ENG_DEFAULT_SUBNET_SCHEME = 'v3';/.test(read(ENG_UI_JS)), `${R1}`);
});

test('R1-21: every subnet-scheme <select> pre-selects v3, and v2 stays offered', () => {
  const html = read(ADMIN_LANES_HTML);
  const selects = html.match(/<select id="(?:gen|dep)-subnet-scheme">[\s\S]*?<\/select>/g) || [];
  assert.strictEqual(selects.length, 2,
    `expected the generate and the deploy selector. ${R1}`);
  for (const s of selects) {
    assert.ok(/<option value="v3" selected>/.test(s),
      `a v2-selected option is an explicit v2 on every submit. ${R1}\n${s}`);
    assert.ok(!/<option value="v2" selected>/.test(s), `${R1}\n${s}`);
    assert.ok(/value="v2"/.test(s),
      `v2 must stay selectable — an operator near the VXLAN ceiling needs it. ${R1}\n${s}`);
  }
  // The engagement modal builds its options from ENG_SUBNET_SCHEMES.
  const ui = read(ENG_UI_JS);
  assert.ok(/s === ENG_DEFAULT_SUBNET_SCHEME \? ' selected' : ''/.test(ui),
    `the engagement modal must mark the constant selected, not a literal. ${R1}`);
  assert.ok(/const ENG_SUBNET_SCHEMES = \['v1', 'v2', 'v3'\];/.test(ui),
    `all three stay offered. ${R1}`);
});
