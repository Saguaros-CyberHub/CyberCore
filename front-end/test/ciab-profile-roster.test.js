/**
 * ciab-profile-roster.test.js — the client's real roster reaches the website
 * generator, or the generated company is a generic one.
 *
 * WHY THIS FILE EXISTS
 * Every CIAB lane ships a vulnerable web app that is supposed to look like the
 * profiled company's own internal tool: its staff in the seed data, its
 * headcount in the design brief. The concept prompt asks for exactly that —
 * ai/vuln-app/prompts.js reads `profile.stakeholders` and
 * `profile.employee_count || profile.employees_total` and renders
 *
 *     - Size: ${employees} employees
 *     REAL STAKEHOLDERS (use a few real names in seed_data ...):
 *     ${stakeholders || '(no stakeholder data in profile — invent plausible names)'}
 *
 * and the profile object it reads is whatever routes/profile-deploy.js's
 * loadProfileForDeploy() returned. That function used to select ten columns and
 * lift only `assets` out of the JSON, so both fields were undefined on every
 * deploy: the brief said "Size: ? employees", the roster line said "invent
 * plausible names", and the real stakeholders sat unread in json_data.
 *
 * NOTHING FAILS WHEN THIS REGRESSES. The deploy succeeds, the lane comes up,
 * the app is themed and vulnerable — it is just about a company that does not
 * exist, and nobody reviewing a lane can tell the difference without the
 * profile open beside it. That is the whole reason this file executes the
 * function and then renders the actual prompt from its output, rather than
 * asserting the fields are present somewhere.
 *
 * THE TWO LAYOUTS ARE BOTH LIVE
 * An AI-generated profile puts the roster at student_view.stakeholders
 * (ai/profile/index.js combineProfile). A real-client intake puts it at
 * student_view.raw.threats.stakeholders and array-wraps the whole file
 * (utils/profile-filler.js buildStudentView, written by routes/real-client-intake.js).
 * A reader that knows only one of them is wrong for half the profiles in the
 * table, so both are exercised below.
 *
 * Run: node --test front-end/test/ciab-profile-roster.test.js   (or npm test)
 */

const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const ROUTE = 'modules/crucible/plugins/ciab/routes/profile-deploy.js';

const put = (modPath, exports) => {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
};

// profile-deploy pulls the batch lane deployer, which pulls site-config, which
// reads a gitignored config/site.json at module load. Same stub the slot,
// console-designation and lane-provision tests install.
put(path.join(UTILS, 'site-config.js'), {
  getSchedulingConfig: () => ({
    min_free_mem_gb: 8, min_free_disk_gb: 20,
    max_concurrent_lanes: 5, max_concurrent_clones: 4,
    node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
  }),
  getDefaultTemplateNode: () => 'node-1',
});

// The single `profiles` row loadProfileForDeploy reads, swapped per test.
// profile-deploy destructures { pool, query } once at module load, so the pool
// object has to be stable and the row has to arrive through this closure.
let PROFILE_ROW = null;
put(path.join(CIAB, 'utils', 'db.js'), {
  query: async () => ({ rows: [], rowCount: 0 }),
  pool: { query: async () => ({ rows: PROFILE_ROW ? [PROFILE_ROW] : [] }) },
});

const { loadProfileForDeploy } = require(path.join(CIAB, 'routes', 'profile-deploy.js'));
const { buildConceptUserPrompt } = require(path.join(CIAB, 'ai', 'vuln-app', 'prompts.js'));

// json_file_path is resolved against process.cwd(), so the fixture has to live
// under a directory this file can become. A sandbox in the OS temp dir keeps
// the repo clean and keeps two agents' runs from colliding on one filename.
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'ciab-roster-'));
fs.mkdirSync(path.join(SANDBOX, 'profiles'));
after(() => fs.rmSync(SANDBOX, { recursive: true, force: true }));

let fixtureSeq = 0;

/**
 * Write `json` where a real profile's JSON lives and run the real loader over
 * it. `row` overrides the profiles-table columns — chiefly employee_count,
 * which is populated for AI profiles and NULL for every real-client intake.
 */
async function load(json, row = {}) {
  const name = `client_profile_${++fixtureSeq}.json`;
  fs.writeFileSync(path.join(SANDBOX, 'profiles', name), JSON.stringify(json, null, 2), 'utf8');
  PROFILE_ROW = {
    id: 'p1', user_id: 'u1', company_name: 'Northwind Freight', industry: 'Logistics',
    difficulty: 'beginner', client_type: 'smb', employee_count: null,
    json_file_path: `profiles/${name}`, html_file_path: null,
    run_id: 'RUN_1', generation_status: 'complete',
    ...row,
  };
  const cwd = process.cwd();
  process.chdir(SANDBOX);
  try {
    return await loadProfileForDeploy('p1');
  } finally {
    process.chdir(cwd);
  }
}

const ASSETS = [{ hostname: 'WEB-01', role: 'server', os: 'ubuntu-22.04' }];

// An AI-generated profile: roster at student_view.stakeholders, headcount on
// the organization block AND on the profiles row.
const AI_PROFILE = {
  student_view: {
    quick: { company_name: 'Northwind Freight', industry: 'Logistics', employees_total: 240 },
    raw: {
      threats: {
        organization: { company_name: 'Northwind Freight', industry: 'Logistics', employees_total: 240 },
        network: { assets: ASSETS, subnets: [{ name: 'LAN', cidr: '10.10.0.0/24' }] },
      },
    },
    stakeholders: [
      { id: 'stake_1', name: 'Dana Whitfield', role: 'Owner', department: 'Executive' },
      { id: 'stake_2', name: 'Marcus Hayes', role: 'IT Manager', department: 'IT' },
      { id: 'stake_3', name: 'Elena Barrow', role: 'Controller', department: 'Finance' },
    ],
  },
};

// A real-client intake, exactly as real-client-intake.js writes it: the whole
// document array-wrapped, the roster one level deeper, employee_count NULL on
// the row, and a headcount BAND rather than a number.
const REAL_CLIENT_PROFILE = [{
  student_view: {
    quick: { company_name: 'Testing', industry: 'Healthcare', employees_total: null },
    raw: {
      threats: {
        organization: { company_name: 'Testing', industry: 'Healthcare', employees_band: '51-100' },
        network: { total_assets: 1, segments: [], assets: ASSETS },
        stakeholders: [{ name: 'Priya Raman', role: 'Practice Administrator' }],
      },
    },
  },
}];

// Neither field anywhere — the shape that must still deploy untouched.
const BARE_PROFILE = {
  student_view: { raw: { threats: { network: { assets: ASSETS } } } },
};

// ── 1. the fields actually arrive ───────────────────────────────────────────

test('an AI profile hands over its roster and its headcount', async () => {
  const { profile, assets } = await load(AI_PROFILE, { employee_count: 240 });

  assert.deepStrictEqual(profile.stakeholders.map(s => s.name),
    ['Dana Whitfield', 'Marcus Hayes', 'Elena Barrow'],
    'student_view.stakeholders is where combineProfile writes an AI roster');
  assert.strictEqual(profile.employee_count, 240,
    'the profiles column must be SELECTed — the prompt reads it first');
  assert.strictEqual(profile.employees_total, 240);

  // Regression guard on the pre-existing contract: threading the roster through
  // must not disturb what the deployer and the preview route already consume.
  assert.deepStrictEqual(assets, ASSETS);
  assert.deepStrictEqual(profile.assets, ASSETS);
  assert.ok(profile.json_data && profile.json_data.student_view);
});

test('a real-client intake finds its roster one level deeper, and a band for a size', async () => {
  // employee_count is NULL for every real-client profile (real-client-intake.js
  // inserts null), so this row is the case where the column alone tells you
  // nothing and the JSON has to answer.
  const { profile } = await load(REAL_CLIENT_PROFILE, { employee_count: null });

  assert.deepStrictEqual(profile.stakeholders.map(s => s.name), ['Priya Raman'],
    'a real-client roster lives at student_view.raw.threats.stakeholders');
  assert.strictEqual(profile.employee_count, null);
  assert.strictEqual(profile.employees_total, '51-100',
    'employees_band is the only headcount a real-client intake carries');
  assert.deepStrictEqual(profile.assets, ASSETS,
    'the array-wrapped document must still unwrap to one profile');
});

// ── 2. a profile with neither still deploys exactly as before ───────────────

test('a profile carrying neither field loads without throwing and stays usable', async () => {
  const { profile, assets } = await load(BARE_PROFILE);

  assert.deepStrictEqual(profile.stakeholders, [],
    'absent roster must be an empty array, not undefined — the prompt Array.isArray-guards it');
  assert.strictEqual(profile.employees_total, null);
  assert.deepStrictEqual(assets, ASSETS);
});

test('a roster stored as something other than an array degrades to empty', async () => {
  // Hand-written and legacy JSON both exist in the profiles directory, and a
  // stakeholders OBJECT reaching the prompt would be truthy but unmappable.
  const { profile } = await load({
    student_view: { raw: { threats: { network: { assets: ASSETS } } } },
    stakeholders: { ceo: 'Dana Whitfield' },
  });
  assert.deepStrictEqual(profile.stakeholders, []);
});

// ── 3. the payoff: the prompt the generator actually sends ──────────────────
//
// The assertions above would still pass if prompts.js renamed the fields it
// reads. These render the real prompt from the real loader's output, so the two
// halves cannot drift apart silently.

test('the concept prompt names the real staff and the real headcount', async () => {
  const { profile, assets } = await load(AI_PROFILE, { employee_count: 240 });
  const prompt = buildConceptUserPrompt({
    profile: { ...profile, assets },        // exactly what runProfileDeploy passes
    webServer: { hostname: 'WEB-01', services: ['HTTP'] },
    deliveryMode: 'docker',
    difficulty: 'easy',
  });

  assert.ok(prompt.includes('Dana Whitfield (Owner)'),
    'the roster must reach the prompt as "<name> (<role>)" seed-data material');
  assert.ok(prompt.includes('Marcus Hayes (IT Manager)'));
  assert.ok(prompt.includes('- Size: 240 employees'),
    'the brief must state the real headcount, not "?"');
  assert.ok(!prompt.includes('no stakeholder data in profile'),
    'the invent-plausible-names fallback fired even though the profile has a roster');
});

test('the concept prompt for a bare profile still renders its fallbacks', async () => {
  const { profile, assets } = await load(BARE_PROFILE);
  const prompt = buildConceptUserPrompt({
    profile: { ...profile, assets },
    webServer: null,
    deliveryMode: 'docker',
    difficulty: 'easy',
  });

  assert.ok(prompt.includes('- Size: ? employees'));
  assert.ok(prompt.includes('no stakeholder data in profile'),
    'with nothing to supply, the prompt must still ask the model to invent names');
});

// ── 4. contract guard: the column has to stay in the SELECT ─────────────────
//
// The stubbed pool returns its row whatever the SQL asks for, so no test above
// can notice employee_count being dropped from the query — and in production
// that single missing column is the difference between "Size: 240 employees"
// and "Size: ? employees" for every AI profile.

test('loadProfileForDeploy still selects employee_count', () => {
  const src = fs.readFileSync(path.join(ROOT, ROUTE), 'utf8');
  const select = src.match(/SELECT id, user_id[\s\S]*?FROM profiles/);
  assert.ok(select, `${ROUTE} no longer has the loadProfileForDeploy profile SELECT`);
  assert.ok(/employee_count/.test(select[0]),
    `${ROUTE} dropped employee_count from the profile SELECT. The vuln-app concept `
    + `prompt reads it first (ai/vuln-app/prompts.js), and without it every generated `
    + `company website is briefed with "Size: ? employees".`);
});
