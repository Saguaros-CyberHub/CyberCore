/**
 * ciab-bake-route.test.js — Track G5, phase F2: the bake orchestrator acquires
 * a caller — and (S1) the caller compiles an environment worth baking.
 *
 * WHY THIS FILE EXISTS
 * utils/bake-orchestrator.js shipped complete and tested — five sequenced
 * phases, a durable row, an in-process mutex, a boot sweep, a deploy gate — and
 * `startBake()` was called by NOTHING. buildBakeSteps(), the one place the five
 * phases are bound to the code that performs them, was called by nothing either.
 * A library with a green suite and no caller is indistinguishable from a working
 * feature until someone tries to bake a client and finds there is no way to,
 * which is the same silent-success shape the whole track exists to eliminate,
 * one level up. ciab-bake-wiring.test.js made exactly this argument about
 * goad-lab-push and the post-condition probe.
 *
 * So every assertion here is about a REQUEST — one that starts a bake, one that
 * is refused, one that reads status, one that is refused a deploy. Source text
 * proves none of that: it cannot see a wrong status code, a refusal rendered as
 * a 500, or a bake that never actually ran.
 *
 * THE SIX PROPERTIES:
 *
 *   1. THE ROUTE RETURNS BEFORE THE BAKE DOES. startBake detaches bakeProfile
 *      with a bare .catch and the row carries the outcome — the same contract
 *      createEngagement has. Proved by HOLDING the first phase write open and
 *      watching the 202 come back anyway, rather than by hoping a race lands
 *      the right way.
 *
 *   2. A SECOND CONCURRENT START FOR ONE CLIENT IS REFUSED, AND CREATES
 *      NOTHING. The orchestrator's own mutex is keyed on bake_id, which guards
 *      a double-click on one environment. It does not guard the case that costs
 *      a cluster: an edited profile compiles to a different hash, so a second
 *      press is a second ROW — a second staging lane and a second controller VM,
 *      with whichever loses unfindable forever. The route holds that guard.
 *
 *   3. A PHASE WITH NO IMPLEMENTATION IS ITS OWN STATE, NOT A 500 AND NOT A
 *      SILENT SUCCESS. Two of the five phases refuse by construction. The row
 *      can only say 'failed' — migration 015's CHECK constraint is the whole
 *      vocabulary — so the distinction between "this is not built yet" and
 *      "this ran and broke" is drawn on the way out, and it has to survive to
 *      the operator. The regex that draws it is pinned against what the REAL
 *      buildBakeSteps() throws, in both flavours, because matching prose that
 *      lives in another module is otherwise a coupling nobody would notice
 *      breaking.
 *
 *   4. THE STATUS ROUTE REPORTS phase_detail — the same column name, and the
 *      same job, as ciab_profile_lane_jobs.phase_detail, which the admin UI
 *      already polls. A ninety-minute bake with no progress channel is a row
 *      that reads the same whether it is working or hung.
 *
 *   5. A DEPLOY IS REFUSED WHEN THE BAKE IS NOT USABLE, BY NAME. Every refusal
 *      is a different button: not built, still building, failed, not
 *      implemented, unsigned, drifted. And the refusal reaches POST /deploy
 *      intact — assertBakeDeployable stamps `status` while that renderer reads
 *      `statusCode`, which is exactly why assertEngagementDeployable's 409
 *      renders as a bare 500 on this path today.
 *
 *   6. AUTH GATING MATCHES THE NEIGHBOURS. Every route in the file except the
 *      deliberately token-gated image pull carries authenticateToken and the
 *      admin role, asserted over the whole file and then executed on the four
 *      new ones. There is no requireCiabAccess on this mount, so a route that
 *      forgets its own gate is open to every signed-in user — and Bake burns
 *      ninety minutes of cluster time per press.
 *
 *   7. THE BAKE CARRIES AN ATTACK PATH, AND THE COMPILER'S REFUSALS ARE
 *      ANSWERS. This route used to call the chain-LESS `compileLab(profile)`,
 *      which lowers a chain it is handed and, handed none, emits `acls: {}` and
 *      an all-null `ir.chain`: a forest with a roster and no way through it. It
 *      passed assertLabCompiles (AD semantics) and assertGoadLabPreflight (the
 *      dereferences the playbooks perform) because neither has an opinion about
 *      whether an exercise is solvable, and it deployed green. Nothing called
 *      the per-lab content emitter either, so no bake ever shipped files/ or
 *      scripts/. Both are asserted here against the real modules.
 *
 *      The other half is that compileLabWithChain REFUSES, for three good
 *      reasons, and a refusal is not a crash: an operator has to be able to tell
 *      "this client cannot host an AD engagement" from "the bake fell over".
 *      Each refusal code gets its own state, its own 422 and its own remedy, and
 *      an UNRECOGNISED failure still renders as the 500 it is — because a
 *      classifier that names everything names nothing.
 *
 * OFFLINE. The plugin graph is replaced in require.cache before the router
 * loads: ciab/utils/db.js COMPLETELY (query, pool, getPool, setPool) because a
 * partial stub leaves the real module loaded for the omitted export and that
 * one builds a pg pool. bake-orchestrator, goad-lab-push and
 * goad-role-manifest are the REAL modules — they are what is under test — and
 * the database underneath them is a small in-memory ciab_profile_bake that
 * answers the statements the orchestrator actually issues.
 *
 * goad-lab-compile and goad-lab-content run BOTH WAYS, and the split is load
 * bearing. Most properties here need a compiled tree they can VARY — "the client
 * was edited" has to be a one-line change rather than a second AI fixture — so
 * `state.compile` and `state.content` stand in. But a stub cannot answer the
 * question S1 exists to ask: whether the route compiles a real chain and real
 * content at all. A stub that returns a chain proves only that the stub returns
 * a chain. So `state.real = true` puts the REAL compiler, the REAL attack-chain
 * designer and the REAL content emitter back on the path, against the profile
 * JSON in the sandbox, and the assertions about acls, ir.chain, files/ and
 * scripts/ are made against what they actually produce. It costs about thirty
 * milliseconds; the composer is pure CPU over the chassis on disk.
 *
 * `node --test "test/*.test.js"` gives every file its own process, so these
 * cache writes cannot reach another test file.
 *
 * Run: node --test front-end/test/ciab-bake-route.test.js  (or npm test)
 */

const { test, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const ROUTE_FILE = path.join(CIAB, 'routes', 'profile-deploy.js');

const PROFILE_ID = '11111111-2222-3333-4444-555555555555';
const TINY_PROFILE_ID = '99999999-8888-7777-6666-555555555555';
// A client with a REAL asset register — the shape B1 is about. 110 employees on
// one site puts org-sizing at two controllers plus a member (tier M), which is
// exactly the server list ai/profile's own roles[] gives a client this size,
// because the paper and the compiler read the same sizing module.
const REGISTER_PROFILE_ID = '44444444-3333-2222-1111-000000000000';
const TERMINAL = ['ready', 'failed', 'superseded'];

/**
 * The asset register that client's documents print.
 *
 * WEB-01 declares an HTTP service, so profile-to-spec forces it onto Linux and
 * makes it the lane's dual-homed DMZ pivot — which is what turns this fixture
 * into the DEFAULT v3 shape rather than a special case: applyV3Topology then
 * stamps nics[] on every OTHER machine too.
 */
const REGISTER_ASSETS = Object.freeze([
  { hostname: 'DC-01', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP', '445/SMB'] },
  { hostname: 'DC-02', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
  { hostname: 'FS-01', role: 'server', os: 'Windows Server 2016', services: ['445/SMB'] },
  { hostname: 'WEB-01', role: 'server', os: 'Debian 12', services: ['80/HTTP'] },
  { hostname: 'WS-014', role: 'workstation', os: 'Windows 11', services: [] },
]);

const REGISTER_JSON = Object.freeze({
  student_view: {
    meta: { run_id: 'run-register-1', client_type: 'SMB', difficulty: 'intermediate' },
    quick: { company_name: 'Harborview Dental Group', employees_total: 110 },
    raw: {
      threats: {
        organization: {
          company_name: 'Harborview Dental Group',
          domain_public: 'harborviewdental.com',
          employees_total: 110,
          hq_city: 'Tucson, AZ',
          industry: 'Healthcare',
          department_breakdown: { Operations: 40, Finance: 12, IT: 8, Administration: 10 },
        },
        it_environment: { delivery: 'Hybrid' },
        network: { assets: REGISTER_ASSETS },
      },
    },
    stakeholders: [
      { name: 'Dr. Jane Smith', role: 'Chief Executive Officer', department: 'Executive' },
      { name: 'Marcus Webb', role: 'IT Manager', department: 'IT' },
      { name: 'Rosa Delaney', role: 'Controller', department: 'Finance' },
      { name: 'Tom Ng', role: 'Operations Lead', department: 'Operations' },
    ],
  },
});

/** The rows `SELECT ... FROM profiles WHERE id = $1` answers with. */
const PROFILES = {
  [PROFILE_ID]: {
    id: PROFILE_ID, user_id: 'u1', company_name: 'Northwind Clinic',
    industry: 'Healthcare', difficulty: 'easy', client_type: 'SMB',
    employee_count: 120, json_file_path: 'profiles/client.json',
    html_file_path: null, run_id: 'run-bake-1', generation_status: 'complete',
  },
  // Six people, cloud-first: below org-sizing's first-domain floor, so the real
  // compiler refuses it outright.
  [TINY_PROFILE_ID]: {
    id: TINY_PROFILE_ID, user_id: 'u1', company_name: 'Larkspur Studio',
    industry: 'Professional Services', difficulty: 'easy', client_type: 'SMB',
    employee_count: 6, json_file_path: 'profiles/tiny.json',
    html_file_path: null, run_id: 'run-tiny', generation_status: 'complete',
  },
  [REGISTER_PROFILE_ID]: {
    id: REGISTER_PROFILE_ID, user_id: 'u1', company_name: 'Harborview Dental Group',
    industry: 'Healthcare', difficulty: 'intermediate', client_type: 'SMB',
    employee_count: 110, json_file_path: 'profiles/register.json',
    html_file_path: null, run_id: 'run-register-1', generation_status: 'complete',
  },
};


function put(absPath, exports) {
  const resolved = require.resolve(absPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
  return exports;
}

// ── the profile on disk ─────────────────────────────────────────────────────
//
// loadProfileForDeploy resolves json_file_path against process.cwd(), so this
// file becomes a sandbox in the OS temp directory for its whole run — the same
// arrangement ciab-profile-roster.test.js uses, and for the same two reasons: the
// repo stays clean, and two agents' runs cannot collide on one filename.
// `node --test` gives each file its own process, so the chdir reaches nothing else.

const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'ciab-bake-'));
const REAL_CWD = process.cwd();
fs.mkdirSync(path.join(SANDBOX, 'profiles'));
process.chdir(SANDBOX);
after(() => { process.chdir(REAL_CWD); fs.rmSync(SANDBOX, { recursive: true, force: true }); });

{
  fs.writeFileSync(path.join(SANDBOX, 'profiles', 'client.json'), JSON.stringify({
    student_view: {
      meta: { run_id: 'run-bake-1', client_type: 'SMB' },
      raw: {
        threats: {
          organization: { company_name: 'Northwind Clinic', employees_total: 120 },
          network: { assets: [{ hostname: 'web-01', role: 'server', os: 'Debian 12' }] },
        },
      },
    },
  }));
}

// The client with a real asset register, on disk exactly as the deploy path
// reads it — loadProfileForDeploy normalizes assets out of
// student_view.raw.threats.network.assets, and the compiler reads the same
// place, which is the whole point: one register, two consumers.
fs.writeFileSync(path.join(SANDBOX, 'profiles', 'register.json'), JSON.stringify(REGISTER_JSON));

// A SECOND client, and the only thing that matters about it is its size: six
// people, cloud-first. org-sizing puts the first domain out of reach for that
// org entirely, so the real compiler refuses it — which is the below-floor
// profile property 7 asserts, made of a real org rather than a thrown fixture.
{
  fs.writeFileSync(path.join(SANDBOX, 'profiles', 'tiny.json'), JSON.stringify({
    student_view: {
      meta: { run_id: 'run-tiny', client_type: 'SMB' },
      raw: {
        threats: {
          organization: { company_name: 'Larkspur Studio', employees_total: 6 },
          it_environment: { delivery: 'cloud' },
          network: { assets: [] },
        },
      },
    },
  }));
}

// ── the in-memory ciab_profile_bake ─────────────────────────────────────────
//
// Small on purpose: it answers the statements bake-orchestrator actually issues
// and nothing else. The alternative — stubbing the orchestrator — would leave
// every property in this file asserting a fake, when the whole question is
// whether the REAL sequencer, the REAL steps object and the REAL refusals reach
// an operator through a route.

const state = {
  audit: [],
  compile: null,          // what the stubbed compiler returns, or throws
  pause: null,            // held phase writes — see holdPhaseWrites()
  content: null,          // what the stubbed content emitter returns
  real: false,            // run the REAL compiler + content emitter on this path
  deploySpec: null,       // what synthesizeSpecFromProfile hands runProfileDeploy
  engagements: new Map(), // engagement_type → row, seeded by seedNetworks()
  reservations: new Map(),// engagement_type → reservation (its vxlan_block)
  createdEngagements: [], // every createEngagement() the routes made
  provisioned: [],        // every provisionProfileLanes() argument set
  cybercore: [],          // every cybercoreQuery the deploy path issued
};

const db = (() => {
  const rows = [];
  const log = [];
  let seq = 0;
  const norm = (s) => String(s).replace(/\s+/g, ' ').trim();
  const byId = (id) => rows.find((r) => r.bake_id === id);

  const query = async (text, params) => {
    const sql = norm(text);
    const p = params || [];
    log.push({ sql, params: p });

    if (/FROM profiles WHERE id = \$1/.test(sql)) {
      const row = PROFILES[p[0]];
      if (!row) return { rows: [], rowCount: 0 };
      return { rows: [{ ...row }], rowCount: 1 };
    }

    // The deploy path's own bookkeeping. Answered rather than ignored because
    // runProfileDeploy reads the id straight back out, and a deploy that 500s on
    // its group row never reaches the hand-off that C1b is about.
    if (/^INSERT INTO ciab_profile_lane_groups/.test(sql)) {
      return { rows: [{ id: 'grp-1' }], rowCount: 1 };
    }
    if (/^UPDATE ciab_profile_lane_groups/.test(sql)) return { rows: [], rowCount: 1 };

    if (/^INSERT INTO ciab_profile_bake/.test(sql)) {
      const [profile_id, lab_hash, lab_name, goad_ref, manifest_sha, spec, phase_detail, created_by] = p;
      // ON CONFLICT (profile_id, lab_hash) DO NOTHING — the constraint the whole
      // design rests on: identical content finds the existing row.
      if (rows.some((r) => r.profile_id === profile_id && r.lab_hash === lab_hash)) {
        return { rows: [], rowCount: 0 };
      }
      seq += 1;
      const row = {
        bake_id: `bake-${seq}`, profile_id, lab_hash, lab_name, goad_ref, manifest_sha,
        spec: JSON.parse(spec),
        staging_lane_id: null, staging_vxlan_id: null, controller_vmid: null,
        status: 'pending', phase_detail, error: null,
        verify_report: null, bh_report: null,
        gate_solvable: null, gate_paper: null, gate_no_unintended: null,
        gates_approved_by: null, gates_approved_at: null, golden_vmids: null,
        started_at: null, finished_at: null, created_by,
        created_at: seq, updated_at: seq,
      };
      rows.push(row);
      return { rows: [row], rowCount: 1 };
    }

    if (/^SELECT \* FROM ciab_profile_bake/.test(sql)) {
      if (/WHERE bake_id = \$1/.test(sql)) return { rows: [byId(p[0])].filter(Boolean), rowCount: 1 };
      if (/AND lab_hash = \$2/.test(sql)) {
        return { rows: rows.filter((r) => r.profile_id === p[0] && r.lab_hash === p[1]) };
      }
      if (/status = 'ready'/.test(sql)) {
        const ready = rows.filter((r) => r.profile_id === p[0] && r.status === 'ready')
          .sort((a, b) => b.created_at - a.created_at);
        return { rows: ready.slice(0, 1) };
      }
      // listBakes: newest first.
      return {
        rows: rows.filter((r) => r.profile_id === p[0]).sort((a, b) => b.created_at - a.created_at),
      };
    }

    if (/^UPDATE ciab_profile_bake/.test(sql)) {
      if (/status = 'superseded'/.test(sql)) {
        const hit = rows.filter((r) => r.profile_id === p[0] && r.bake_id !== p[1] && r.status === 'ready');
        for (const r of hit) {
          r.status = 'superseded';
          r.phase_detail = 'Superseded by a newer bake of this environment.';
        }
        return { rows: hit.map((r) => ({ bake_id: r.bake_id })), rowCount: hit.length };
      }

      const isPhaseWrite = /SET status = \$2, phase_detail = \$3/.test(sql);
      // The gate property 1 rests on: a held phase write keeps the bake provably
      // in flight while the route answers.
      if (isPhaseWrite && state.pause) await state.pause;

      const row = byId(p[0]);
      if (!row) return { rows: [], rowCount: 0 };

      if (isPhaseWrite) {
        row.status = p[1];
        row.phase_detail = p[2];
        row.started_at = row.started_at || 'started';
      } else if (/SET phase_detail = \$2/.test(sql)) {
        row.phase_detail = p[1];
      } else if (/SET status = 'failed'/.test(sql)) {
        row.status = 'failed'; row.error = p[1]; row.finished_at = 'finished';
      } else if (/SET status = 'ready'/.test(sql)) {
        row.status = 'ready'; row.phase_detail = p[1]; row.error = null; row.finished_at = 'finished';
      } else if (/SET status = 'pending'/.test(sql)) {
        Object.assign(row, {
          status: 'pending', phase_detail: 'Queued for a re-bake.', error: null,
          started_at: null, finished_at: null,
          gate_solvable: null, gate_paper: null, gate_no_unintended: null,
          gates_approved_by: null, gates_approved_at: null,
        });
      } else if (/SET gate_solvable = \$2/.test(sql)) {
        row.gate_solvable = p[1]; row.gate_paper = p[2]; row.gate_no_unintended = p[3];
        row.gates_approved_by = p[4] ? p[5] : null;
        row.gates_approved_at = p[4] ? 'approved' : null;
      } else if (/SET error = left/.test(sql)) {
        row.error = `${row.error || ''}${p[1]}`;
      } else if (/staging_lane_id = NULL/.test(sql)) {
        row.staging_lane_id = null; row.staging_vxlan_id = null; row.controller_vmid = null;
      } else {
        // recordBakeFields, and the heartbeat's bare updated_at. Only the SET
        // list is scanned: `bake_id = $1` lives in the WHERE clause.
        const setList = sql.slice(sql.indexOf('SET '), sql.indexOf(' WHERE '));
        const re = /(\w+) = \$(\d+)(::jsonb)?/g;
        let m;
        while ((m = re.exec(setList)) !== null) {
          if (m[1] === 'updated_at') continue;
          const raw = p[Number(m[2]) - 1];
          row[m[1]] = m[3] ? JSON.parse(raw) : raw;
        }
      }
      seq += 1;
      row.updated_at = seq;
      return { rows: [row], rowCount: 1 };
    }

    return { rows: [], rowCount: 0 };
  };

  return { rows, log, query, reset() { rows.length = 0; log.length = 0; } };
})();

const fakePool = { query: db.query, connect: async () => ({ query: db.query, release() {} }) };

// db FIRST, and completely: bake-orchestrator requires it at module load.
put(path.join(CIAB, 'utils', 'db.js'), {
  query: db.query, getPool: () => fakePool, setPool: () => {}, pool: fakePool,
});

put(path.join(ROOT, 'src', 'middleware', 'auth.js'), {
  authenticateToken: (req, res, next) => (
    req.user ? next() : res.status(401).json({ error: 'unauthorized' })
  ),
  requireRole: (...roles) => (req, res, next) => (
    req.user && roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'forbidden' })
  ),
});

put(path.join(ROOT, 'src', 'utils', 'audit.js'), {
  log: (e) => state.audit.push(e),
  batch: (e) => state.audit.push(e),
});

put(path.join(ROOT, 'src', 'utils', 'lane-deployer.js'), new Proxy({}, { get: () => async () => ({}) }));
put(path.join(ROOT, 'src', 'utils', 'proxmox.js'), { proxmoxAPI: async () => ({}) });
put(path.join(ROOT, 'src', 'utils', 'guacamole.js'), { guacAPI: async () => ({}) });
put(path.join(ROOT, 'src', 'utils', 'lane-claims.js'), { claimsSql: () => 'true' });
put(path.join(ROOT, 'src', 'middleware', 'deployment-guards.js'), { buildDeployPreview: async () => ({}) });
put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), {
  // Recorded, because the spec that reaches crucible_challenge is what add-lanes
  // and retry-lane read back days later — an overlay applied only in memory
  // would give the first deploy golden clones and every later lane the catalog.
  cybercoreQuery: async (sql, params) => {
    state.cybercore.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params: params || [] });
    return /COUNT/.test(String(sql)) ? { rows: [{ n: 0, used: '0' }] } : { rows: [] };
  },
});

put(path.join(CIAB, 'utils', 'vuln-app-generator.js'), { getOrGenerateVulnApp: async () => null });
put(path.join(CIAB, 'utils', 'vuln-app-builder.js'), { resolveImageFile: () => null });
put(path.join(CIAB, 'utils', 'cost-estimator.js'), { estimateDeployCost: () => ({}), DEFAULT_MODEL: 'm' });
put(path.join(CIAB, 'utils', 'profile-students.js'), {
  provisionLaneStudents: async () => ({ groupSlug: 's', students: [], credentials: [] }),
  slugForGroup: () => 's',
});
// A RECORDING stub, not a Proxy that swallows everything: the whole of C1b is
// about WHAT reaches the deployer, and a stub that returns {} for any call
// cannot tell a lane cloning golden templates from one cloning the catalog.
put(path.join(CIAB, 'utils', 'lane-provision.js'), {
  provisionProfileLanes: async (args) => { state.provisioned.push(args); return {}; },
  retryProfileLane: async () => ({}),
  teardownProfileLanes: async () => ({}),
  readGroupProgress: () => null,
  progressIdForGroup: (id) => `ciab-group-${id}`,
  progressIdForLane: (g, l) => `ciab-group-${g}-lane-${l}`,
  groupOperationsInFlight: () => [],
  assertNoConflictingProfileOperation: () => {},
});

// ── the engagements + reservations this client owns ─────────────────────────
//
// Keyed BY ENGAGEMENT TYPE, because that is the fact C1a turns on: the bake
// borrows a one-slot 'bake' block so it cannot eat a seat out of the class's
// block, and a stub that answered the same row for every type would make the
// two indistinguishable — which is exactly the bug.
const STAGING_VXLAN = 10200;                 // the single id the bake block holds
const STAGING_INT = '10.167.216';            // v3InternalSubnet(10200).base3
const STAGING_EXT = '10.39.216';             // v2LaneSubnet(10200).base3

function seedNetworks() {
  state.engagements = new Map([
    ['default', {
      engagement_id: 'e1', profile_id: PROFILE_ID, engagement_type: 'default',
      subnet_scheme: 'v3', max_students: 5, provision_status: 'ready',
      challenge_id: 'chal-0001-aaaa',
    }],
    ['bake', {
      engagement_id: 'e-bake', profile_id: PROFILE_ID, engagement_type: 'bake',
      subnet_scheme: 'v3', max_students: 1, provision_status: 'ready',
      challenge_id: 'chal-bake-aaaa',
    }],
  ]);
  state.reservations = new Map([
    ['default', {
      challenge_id: 'chal-0001-aaaa', challenge_key: 'ciab-profile-1111-default',
      vxlan_block: { start: 10000, end: 10004 }, max_students: 5, spec: {},
    }],
    ['bake', {
      challenge_id: 'chal-bake-aaaa', challenge_key: 'ciab-profile-1111-bake',
      vxlan_block: { start: STAGING_VXLAN, end: STAGING_VXLAN }, max_students: 1, spec: {},
    }],
  ]);
}

put(path.join(CIAB, 'utils', 'engagement-provision.js'), {
  listEngagements: async () => [...state.engagements.values()],
  resolveEngagement: async (_profileId, type) => state.engagements.get(type || 'default') || null,
  // The real one's refusals, in the shape the routes read them. Stubbing it to a
  // no-op would let a bake start against a block that is still being carved.
  assertEngagementDeployable: (engagement, { engagementType }) => {
    if (!engagement) {
      throw Object.assign(new Error(`No network reserved for this client's '${engagementType}' engagement yet.`),
        { status: 409, code: 'ENGAGEMENT_NOT_RESERVED' });
    }
    if (engagement.provision_status !== 'ready') {
      throw Object.assign(new Error("This engagement's network is still being reserved."),
        { status: 409, code: 'ENGAGEMENT_PROVISIONING' });
    }
    return engagement;
  },
  getEngagementById: async () => null,
  createEngagement: async ({ engagementType, subnetScheme, maxStudents }) => {
    const row = {
      engagement_id: `e-${engagementType}`, profile_id: PROFILE_ID,
      engagement_type: engagementType, subnet_scheme: subnetScheme,
      max_students: maxStudents, provision_status: 'provisioning', challenge_id: null,
    };
    state.engagements.set(engagementType, row);
    state.createdEngagements.push(row);
    return row;
  },
  reprovisionEngagement: async () => ({}),
});
put(path.join(CIAB, 'utils', 'lane-reservation.js'), {
  teardownLane: async () => ({}),
  getOrCreateProfileChallenge: async ({ engagementType }) => ({
    ...state.reservations.get(engagementType || 'default'),
    engagement_type: engagementType || 'default',
    was_existing: false,
  }),
  deleteProfileChallenge: async () => ({}),
  findProfileChallenge: async (_profileId, type) => state.reservations.get(type || 'default') || null,
  getProfileChallengeById: async () => null,
  listProfileChallenges: async () => [],
  DEFAULT_ENGAGEMENT_TYPE: 'default',
  sanitizeEngagementType: (v) => (v ? String(v) : 'default'),
  VXLAN_SEARCH_MIN: 10000,
  VXLAN_SEARCH_MAX: 19999,
});
// The synthesizer is stubbed so a deploy's spec is a one-line fixture — but
// buildSpecDns is the REAL one. Its AD branch is what C1b activates (its own
// comment says "a later wave stamps spec.goad"), and a stubbed version of the
// rule that decides whether the forwarder is published at all would be a second
// implementation of exactly the thing under test.
const realSpec = require(path.join(CIAB, 'utils', 'profile-to-spec.js'));
put(path.join(CIAB, 'utils', 'profile-to-spec.js'), {
  // TWO CALLERS, ONE FUNCTION, AND ONLY ONE OF THEM IS A FIXTURE.
  //
  // runProfileDeploy synthesizes the DEPLOY spec and always hands over the
  // asset selection it built — defaultAssetSelection returns an array on every
  // path — so that call is answered with the fixture, which is what keeps a
  // deploy's spec a one-liner in this file.
  //
  // The BAKE's web-host derivation (bakeWebMachine) calls the SAME function
  // with assetSelection: null and its own probe catalog, and that call goes
  // straight to the real module. It has to: the name that comes back is the
  // name capture keys this client's golden template on, the property under test
  // is that it equals the name a real deploy gives the same machine, and a stub
  // of it would be precisely the second spelling X1 exists to prevent.
  synthesizeSpecFromProfile: (args) => (Array.isArray(args && args.assetSelection)
    ? { spec: state.deploySpec || { vms: [{ name: 'web-01' }] }, service_gaps: [], template_misses: [] }
    : realSpec.synthesizeSpecFromProfile(args)),
  // REAL, for the reason isWebServer is: resolveDmzVm is the one function that
  // DECIDES which machine a lane puts in the DMZ, and the bake asks it instead
  // of deciding again.
  resolveDmzVm: (...args) => realSpec.resolveDmzVm(...args),
  buildSpecDns: (...args) => realSpec.buildSpecDns(...args),
  // REAL, for the same reason buildSpecDns is. isWebServer decides which asset
  // gets forced onto Linux and becomes the lane's dual-homed DMZ pivot, and the
  // compiler asks THIS function which assets can never be forest hosts. A stub
  // of it here would be a second implementation of the rule the correspondence
  // between the bake and the deploy rests on.
  isWebServer: (...args) => realSpec.isWebServer(...args),
  DEFAULT_SUBNET_SCHEME: 'v3',
});

// The REAL compiler and content emitter, captured BEFORE the stubs go into
// require.cache below. Neither touches the database — goad-lab-compile reads the
// chassis off disk and pulls the validator, the pre-flight and the attack-chain
// designer behind it — so holding a reference costs nothing and is the only way
// this file can assert what they actually produce rather than what a stub says
// they do.
const realCompile = require(path.join(CIAB, 'utils', 'goad-lab-compile.js'));
const realContent = require(path.join(CIAB, 'utils', 'goad-lab-content.js'));

// The compiler. Its output is the bake's IDENTITY, so varying `ir` here is what
// "the client was edited" means — and `state.real` hands the path back to the
// module that has to be right for any of it to matter.
put(path.join(CIAB, 'utils', 'goad-lab-compile.js'), {
  compileLab: (...args) => realCompile.compileLab(...args),
  compileLabWithChain: (...args) => {
    if (state.real) return realCompile.compileLabWithChain(...args);
    if (state.compile instanceof Error) throw state.compile;
    return state.compile;
  },
  LabCompileError: realCompile.LabCompileError,
  // goad-lab-content's assertSiteSound delegates the site→AD half of the seam
  // back to the compiler's own gate rather than re-implementing it, so the
  // website derivation reaches this module even when the compile itself is a
  // fixture. Passed straight through: it is a checker, and a stubbed checker
  // proves nothing.
  assertFootholdHonoured: (...args) => realCompile.assertFootholdHonoured(...args),
});

// The per-lab files/ and scripts/. Stubbed for the same reason the compiler is —
// the identity has to notice a content change, and that has to be a one-line
// edit — and real under `state.real` for the same reason too.
put(path.join(CIAB, 'utils', 'goad-lab-content.js'), {
  generateLabContent: (...args) => (
    state.real ? realContent.generateLabContent(...args) : state.content),
  // The fake merge records the same two facts the real one wires in, so the
  // emitted config.json still REFERENCES what the tree ships. A merge that
  // dropped them would leave a bake whose files/ is copied nowhere, which is the
  // silent no-op mergeLabContent exists to prevent.
  mergeLabContent: (lab, content) => (state.real
    ? realContent.mergeLabContent(lab, content)
    : { ...lab, ciab_content: { files_vars: content.files_vars, host_scripts: content.host_scripts } }),
  // THE WEBSITE HALF IS NEVER STUBBED, in either mode. The deploy overlay
  // re-derives site.reseed off the bake's compiled lab to find out WHERE the
  // website publishes the pivot credential, and that is not a fact this file has
  // any business inventing: a stubbed plant list would prove the overlay can
  // copy an object, while the defect it exists to prevent is a descriptor that
  // does not match the bytes cc_web really wrote. So the real emitter runs over
  // whatever `compiled()` describes, and a fixture it cannot author a site for
  // is a fixture that does not describe a client.
  generateSiteContent: (...args) => realContent.generateSiteContent(...args),
  SITE_WEB_PLANT_FORMATS: realContent.SITE_WEB_PLANT_FORMATS,
  SITE_PIVOT_FIELD: realContent.SITE_PIVOT_FIELD,
  SITE_RESEED_OPS: realContent.SITE_RESEED_OPS,
  SITE_DOCROOT: realContent.SITE_DOCROOT,
});

const orch = require(path.join(CIAB, 'utils', 'bake-orchestrator.js'));
const router = require(ROUTE_FILE);
const {
  bakeIdentityForProfile, notImplementedPhase, bakeStateOf, deployNeedsBake,
  assertProfileBakeDeployable, compileRefusalOf, COMPILE_REFUSALS,
} = router;

const ROUTE_SRC = fs.readFileSync(ROUTE_FILE, 'utf8');

// ── fixtures + drivers ──────────────────────────────────────────────────────

/**
 * A compiled tree the push phase will accept: named, data/-bearing, chained.
 *
 * `ir.chain` and `ir.acls` are POPULATED, because that is what
 * compileLabWithChain returns and what the route now refuses to ship without.
 * They are also separate from `ir.principals` on purpose: the roster and the
 * attack path are two independently editable facts, and the identity has to
 * notice a change to either one on its own.
 *
 * AND IT IS A LAB THE WEBSITE GENERATOR CAN AUTHOR A SITE FOR. The deploy
 * overlay now re-derives site.reseed off this IR — the descriptor that tells the
 * per-lane reseed WHERE the website publishes the pivot credential — so a
 * skeleton IR here would only ever prove the overlay handles a shape nothing
 * emits. The roster carries real users with real passwords, the domain is an
 * object with its NetBIOS name, and the entry is planted 'web_app_credential',
 * which is the case where goad-lab-content publishes the FOOTHOLD on the site
 * rather than an inert bind account. Everything the sweep further down needs to
 * vary — a different entry kind, a crackable password — it gets from the real
 * compiler over real run ids instead.
 */
const CLINIC_DN = 'DC=clinic,DC=local';
function clinicUser(sam, password, over) {
  return Object.assign({
    sam,
    firstname: sam.split('.')[0],
    surname: sam.split('.')[1] || 'staff',
    password,
    description: '',
    city: 'Tucson',
    path: `OU=Staff,${CLINIC_DN}`,
    domain: 'clinic.local',
    groups: [],
    spns: [],
  }, over || {});
}

function compiled(over = {}) {
  return {
    ir: {
      lab_name: 'CIAB-a1b2c3d4',
      tier: 'S',
      run_id: 'run-bake-1',
      domains: [{
        fqdn: 'clinic.local', netbios: 'CLINIC', dc_host_key: 'dc01',
        is_forest_root: true, parent_fqdn: null, trust_fqdn: null,
      }],
      version: 1,
      principals: {
        users: [
          clinicUser('svc.webapp', 'Cedar-Harbor12!'),
          clinicUser('marcus.webb', 'Rivet-Landing-41!'),
          clinicUser('rosa.delaney', 'Quartz-Meadow-18!'),
          clinicUser('tom.ng', 'Sable-Junction-77!'),
        ],
        groups: [{
          name: 'ITOps', scope: 'global', path: `OU=Groups,${CLINIC_DN}`,
          domain: 'clinic.local', managed_by: null, members: [],
        }],
        ous: [
          { name: 'Staff', path: CLINIC_DN, domain: 'clinic.local' },
          { name: 'Groups', path: CLINIC_DN, domain: 'clinic.local' },
        ],
        declared_admins: [{ sam: 'marcus.webb', domain: 'clinic.local', reason: 'roster_realism' }],
      },
      chain: {
        start: {
          kind: 'web_credential', principal: 'svc.webapp', host: 'srv02',
          how: 'the settings page prints the directory-integration password in the clear',
          plants: [],
        },
        objective: { kind: 'domain_admins', target: 'Domain Admins', domain: 'clinic.local' },
        edges: [{
          id: 'edge0', from: 'svc.webapp', to: 'marcus.webb', edge_type: 'acl',
          right: 'GenericAll', depth: 0, target_kind: 'user',
          created_by: { role: 'acl', host: 'dc01', item: 'edge-0', item_vars: {} },
        }],
        decoys: [],
        domain: 'clinic.local',
      },
      acls: { 'clinic.local': { 'edge-0': { for: 'svc.webapp', to: 'marcus.webb', right: 'GenericAll' } } },
      // The three facts the DEPLOY side of a bake reads out of the IR, and which
      // nothing else in this file exercises: which hosts are domain controllers
      // (deployPrebakedGoadLane heals a DC and a member differently), the octet
      // the emitted ansible inventory addresses each one at (which is what the
      // bake's own spec.vms are placed on — see the octets in the real chassis
      // providers/proxmox/inventory) and the credential the website hands out
      // (the account lane-reseed has to give every lane its OWN password for).
      hosts: [
        { key: 'dc01', hostname: 'NWC-DC01', type: 'dc', domain: 'clinic.local', path: CLINIC_DN, roles: [], ipOctet: 10 },
        { key: 'srv02', hostname: 'NWC-SRV02', type: 'server', domain: 'clinic.local', path: CLINIC_DN, roles: ['web'], ipOctet: 22 },
      ],
      foothold_credential: {
        sam: 'svc.webapp', domain: 'clinic.local',
        password: 'Cedar-Harbor12!', honoured_by: 'ad',
        // A WEB-SIDE PLANT (goad-lab-content.SITE_WEB_PLANT_FORMATS). This is
        // the branch where the site publishes the foothold itself, so the
        // account the reseed rotates and the account the chain starts at are the
        // same one — which is what makes this fixture the SIMPLE case, and the
        // real-compiler sweep the one that proves they usually are not.
        planted_at: { host_key: 'srv02', path: '/admin/integrations', format: 'web_app_credential' },
      },
      ...(over.ir || {}),
    },
    run_id: 'run-bake-1',
    files: {
      'data/config.json': '{"lab":{"domains":{},"hosts":{"dc01":{}}}}',
      'data/inventory': '[all:vars]\ndomain_name=CIAB-a1b2c3d4\n',
      'providers/proxmox/inventory': '[all]\ndc01\n',
    },
    chain: ['build.yml', 'ad-parent_domain.yml', 'ad-data.yml', 'ad-acl.yml', 'vulnerabilities.yml'],
    tier: 'S',
    warnings: [],
  };
}

/**
 * A generated content pack, in the shape goad-lab-content returns.
 *
 * `tree` is the half the identity hashes and the half that reaches the guest;
 * `files_vars` and `host_scripts` are the wiring without which the tree is
 * copied nowhere and the config.json never names it.
 */
function contentPack(over = {}) {
  return {
    seed: 'run-bake-1',
    lab_name: 'CIAB-a1b2c3d4',
    domain: 'clinic.local',
    tree: {
      'files/dc01/wwwroot/appsettings.Production.json': '{"Ldap":{"BindPassword":"Cedar-Harbor12!"}}\n',
      'scripts/asrep_marcus.webb.ps1': '# re-runnable: reads state before it writes it\n',
      ...(over.tree || {}),
    },
    files: [{ kind: 'web_app_config', item: 'web_app_config', host_key: 'dc01' }],
    scripts: [{ technique: 'asrep', host_key: 'dc01' }],
    files_vars: {
      dc01: {
        web_app_config: {
          src: 'dc01/wwwroot/appsettings.Production.json',
          dest: 'C:\\inetpub\\wwwroot\\appsettings.Production.json',
        },
      },
    },
    host_scripts: { dc01: ['asrep_marcus.webb.ps1'] },
    warnings: [],
  };
}

/** One request through the REAL router, with no socket and no port. */
function call(method, url, opts) {
  const o = opts || {};
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: o.query || {}, headers: {},
      // `undefined` means an anonymous caller — authenticateToken refuses it.
      user: o.anonymous ? undefined : { role: o.role || 'admin', userId: 'admin-1' },
    };
    const res = {
      statusCode: 200,
      headers: {},
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

/** Hold every phase transition until the returned function is called. */
function holdPhaseWrites() {
  let release;
  state.pause = new Promise((r) => { release = r; });
  return () => { state.pause = null; release(); };
}

/** Spin the microtask/macrotask queues until every bake row is terminal. */
async function settle() {
  for (let i = 0; i < 400; i += 1) {
    await new Promise((r) => setImmediate(r));
    if (db.rows.length > 0 && db.rows.every((r) => TERMINAL.includes(r.status))) return;
  }
  throw new Error(`bake never reached a terminal state: ${db.rows.map((r) => r.status).join(', ')}`);
}

function reset() {
  db.reset();
  state.audit.length = 0;
  state.compile = compiled();
  state.content = contentPack();
  state.real = false;
  state.pause = null;
  state.deploySpec = null;
  state.createdEngagements.length = 0;
  state.provisioned.length = 0;
  state.cybercore.length = 0;
  seedNetworks();
}

// ───────────────────────────────────────────────────────────────────────────
// 1. The route starts a bake and returns before it finishes
// ───────────────────────────────────────────────────────────────────────────

test('POST /profiles/:id/bake answers 202 while the bake is still running', async () => {
  reset();
  // Every phase transition is held, so the bake is PROVABLY mid-flight when the
  // response lands. Without this the assertion would be a race that usually
  // passes — which is the same thing as no assertion.
  const release = holdPhaseWrites();

  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);

  assert.strictEqual(res.status, 202,
    'the row exists, the environment does not — the same 202 the engagement route answers with');
  assert.strictEqual(res.body.success, true);
  assert.strictEqual(res.body.started, true);
  assert.strictEqual(db.rows.length, 1, 'exactly one bake row');
  assert.ok(!TERMINAL.includes(db.rows[0].status),
    'the response came back before the bake did — that is the whole contract of a detached worker');

  release();
  await settle();
  assert.strictEqual(db.rows[0].status, 'failed',
    'and the outcome landed on the ROW afterwards, which is the only place an operator can see it');
});

test('the bake is created with the identity the migration describes', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const row = db.rows[0];
  assert.match(row.lab_hash, /^[0-9a-f]{64}$/, 'lab_hash is a lowercase hex content digest');
  assert.strictEqual(row.lab_name, `CIAB-${row.lab_hash.slice(0, 8)}`,
    'lab_name is DERIVED by labNameForHash and stored, never authored');
  assert.match(row.goad_ref, /^[0-9a-f]{40}$/,
    'a full commit SHA — a branch name here would make the bake unreproducible');
  assert.ok(row.spec.goad && row.spec.goad.lab,
    'spec.goad.lab is validateBakeIdentity’s one hard requirement: without the compiled lab '
    + 'definition the lanes cloned from this bake resolve a DIFFERENT forest');
  assert.ok(row.spec.goad.generated_lab.files['data/config.json'],
    'and the tree the compile phase picks up travels with it');
});

test('editing the client produces a NEW bake, not a mutation of the old one', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();
  const first = db.rows[0].lab_hash;

  // One field of the compiled IR changes — which is what a profile edit is.
  state.compile = compiled({ ir: { version: 2 } });
  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  assert.strictEqual(res.status, 202);
  assert.strictEqual(db.rows.length, 2, 'UNIQUE (profile_id, lab_hash) is what makes bakes versioned');
  assert.notStrictEqual(db.rows[1].lab_hash, first);
});

test('re-baking IDENTICAL content is refused, never silently restarted', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const again = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(again.status, 409);
  assert.strictEqual(again.body.code, 'BAKE_ALREADY_EXISTS');
  assert.strictEqual(db.rows.length, 1,
    'an auto-restart on a repeated press would re-run ninety minutes because somebody double-clicked');
  assert.match(again.body.error, /Re-bake/, 'the refusal names the button that WOULD redo it');
});

// ───────────────────────────────────────────────────────────────────────────
// 2. A second concurrent start for one client is refused, and creates nothing
// ───────────────────────────────────────────────────────────────────────────

test('a second bake for the same client while one is in flight is refused', async () => {
  reset();
  const release = holdPhaseWrites();
  const first = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(first.status, 202);

  // DIFFERENT content, so the orchestrator's own bake_id mutex would NOT catch
  // it — this is precisely the case that allocates a second staging lane and a
  // second controller VM, with whichever loses unfindable forever.
  state.compile = compiled({ ir: { version: 99 } });
  const second = await call('POST', `/profiles/${PROFILE_ID}/bake`);

  assert.strictEqual(second.status, 409);
  assert.strictEqual(second.body.code, 'BAKE_IN_PROGRESS');
  assert.strictEqual(second.body.state, 'pending',
    'and the guard covers a QUEUED bake too, not only one that has entered a phase — a pending row is about to allocate, which is exactly when a second press does the damage');
  assert.strictEqual(db.rows.length, 1, 'AND NOTHING WAS CREATED — this is the finding');
  assert.match(second.body.error, /staging lane/,
    'the refusal says what a second bake would have built, not just that it was refused');

  release();
  await settle();
});

// ───────────────────────────────────────────────────────────────────────────
// 3. A phase with no implementation is its own state
// ───────────────────────────────────────────────────────────────────────────

/**
 * The message a phase with no implementation actually produces.
 *
 * Only the COMPILE phase can still raise it — provision and capture are wired to
 * bake-staging.js now (see test/ciab-bake-staging.test.js) and refuse on their
 * own terms instead. The classification machinery below is still live and still
 * has to work, so the tests that exercise it seed the row with the real wording
 * rather than a shape nothing produces.
 */
const UNBUILT_PHASE_ERROR =
  "The 'compile' phase has no implementation yet: nothing composes a chassis "
  + '(ciab/data/chassis/S|M|L) plus a client profile into an ad/<LAB> tree yet.';

test('a provision refusal reaches the row by name, not as a skip', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const row = db.rows[0];
  assert.strictEqual(row.status, 'failed',
    'migration 015’s CHECK constraint is the whole vocabulary — there is no sixth status to write');

  // THE GAP THIS USED TO PIN, now closed. bakeIdentityForProfile emitted no
  // spec.goad.fixed_subnet, so EVERY route-started bake stopped here — and the
  // capture flavour of the same refusal stopped it on the far side of the
  // ninety-minute chain. The identity carries the pin now, so the staging phase
  // gets past both guards and stops on the one thing this sandbox genuinely does
  // not have: a cluster user to own the lane.
  assert.doesNotMatch(row.error, /fixed_subnet|vxlan_block/,
    'a route-started bake must no longer die on a field the route itself is supposed to emit');
  assert.match(row.error, /no account on the cluster database/,
    'and it stops LOUDLY on the next real precondition rather than building something unusable');
  assert.strictEqual(bakeStateOf(row), 'failed',
    'a BUILT phase that refused is a failure an operator can act on, not a missing feature');

  // And the not-implemented classification still says no, which is what keeps it
  // from swallowing every refusal as a missing phase.
  assert.strictEqual(notImplementedPhase(row), null);
  assert.strictEqual(notImplementedPhase({ status: 'failed', error: UNBUILT_PHASE_ERROR }), 'compile');
});

test('GET /profiles/:id/bake reports it as its own state, with a 200 and not a 500', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const failed = await call('GET', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(failed.status, 200, 'a bake that refused is an ANSWER, not a server error');
  assert.strictEqual(failed.body.state, 'failed');
  assert.strictEqual(failed.body.deployable, false);
  assert.strictEqual(failed.body.blocked.code, 'BAKE_FAILED');

  // The other half: a phase that genuinely has no implementation is its own
  // state, with its own remedy. Seeded on the row, because the only phase that
  // can still raise it is compile and the route always hands compile a tree.
  db.rows[0].error = UNBUILT_PHASE_ERROR;
  const res = await call('GET', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 200, 'a feature that is not built yet is an ANSWER, not a server error');
  assert.strictEqual(res.body.state, 'not_implemented');
  assert.deepStrictEqual(res.body.not_implemented.step, 'compile');
  assert.match(res.body.not_implemented.detail, /chassis/,
    'and it names what is missing, so an operator can tell "not built yet" from "it failed"');
  assert.strictEqual(res.body.deployable, false);
  assert.strictEqual(res.body.blocked.code, 'BAKE_STEP_NOT_IMPLEMENTED',
    'not BAKE_FAILED — "press Re-bake" is advice that would never work here');
  assert.match(res.body.blocked.reason, /Re-bake will stop in the same place/);
});

test('the classifier is pinned to what the REAL steps object actually throws', async () => {
  // The one coupling in this design that source text cannot keep honest: the
  // distinction between "not built yet" and "failed" is drawn by matching a
  // message that lives in another module. If bake-orchestrator rewords it, this
  // fails HERE rather than degrading a route into reporting every unbuilt phase
  // as a generic failure.
  const steps = orch.buildBakeSteps();
  const args = {
    bake: { bake_id: 'b1', lab_name: 'CIAB-a1b2c3d4', spec: {} },
    setDetail: async () => {}, record: async () => true,
  };

  // COMPILE is the only phase left that refuses by construction: provision and
  // capture are bake-staging's now. Its refusal still has to classify, or the
  // route degrades into reporting an unbuilt phase as a generic failure and
  // telling an operator to press Re-bake forever.
  for (const step of ['compile']) {
    const err = await steps[step](args).then(() => null, (e) => e);
    assert.ok(err instanceof orch.BakeStepNotImplemented, `${step} must refuse by name`);
    assert.strictEqual(notImplementedPhase({ status: 'failed', error: err.message }), step,
      `the route classifier must recognise the '${step}' refusal that buildBakeSteps actually throws`);
  }

  // The OTHER flavour: bakeProfile's own guard, for a steps object missing a
  // key entirely. Its wording is different and both must classify.
  reset();
  // The two phases BEFORE capture need implementations, or the bake stops at the
  // first refusal and never reaches the guard being tested.
  const handRolled = orch.buildBakeSteps({
    compileLab: async () => compiled(),
    provisionStagingLane: async () => ({
      verify_report: {
        ran: true,
        passed: true,
        report: { passed: true, summary: { ok: 1, total: 1 }, checks: [], errors: [] },
      },
    }),
  });
  delete handRolled.capture;
  const result = await orch.bakeProfile(
    { bake_id: 'nope', profile_id: PROFILE_ID, lab_name: 'CIAB-a1b2c3d4', spec: { goad: {} } },
    { steps: handRolled, heartbeatMs: 0 });
  assert.strictEqual(result.status, 'failed');
  assert.strictEqual(notImplementedPhase({ status: 'failed', error: result.error }), 'capture');
});

test('a bake that is merely FAILED is not reported as unimplemented', () => {
  // The classification has to be able to say no, or it says nothing.
  assert.strictEqual(notImplementedPhase({ status: 'failed', error: 'GOAD playbook exit 2' }), null);
  assert.strictEqual(bakeStateOf({ status: 'failed', error: 'GOAD playbook exit 2' }), 'failed');
  assert.strictEqual(bakeStateOf({ status: 'provisioning' }), 'building');
  assert.strictEqual(bakeStateOf({ status: 'ready', gates_approved_at: null }), 'awaiting_signoff',
    "'ready' is not deployable on its own — the gates are the only evidence anyone looked");
  assert.strictEqual(bakeStateOf({ status: 'ready', gates_approved_at: 'x' }), 'ready');
  assert.strictEqual(bakeStateOf(null), 'not_built');
});

// ───────────────────────────────────────────────────────────────────────────
// 4. The status route reports phase_detail
// ───────────────────────────────────────────────────────────────────────────

test('the status route carries phase_detail, at the top of the body and on the row', async () => {
  reset();
  const release = holdPhaseWrites();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);

  const queued = await call('GET', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(queued.body.phase_detail, 'Queued.',
    'the same column name and the same job as ciab_profile_lane_jobs.phase_detail, which the admin '
    + 'UI already polls — a second status channel would be a second thing to keep true');

  release();
  await settle();

  const done = await call('GET', `/profiles/${PROFILE_ID}/bake`);
  assert.match(done.body.phase_detail, /ninety minutes|staging lane/,
    'phase_detail is deliberately LEFT ALONE by the failure write: it still holds the last thing the '
    + 'failing phase said, which is most of the diagnosis');
  assert.strictEqual(done.body.bake.phase_detail, done.body.phase_detail);
  assert.strictEqual(done.body.bake.status, 'failed', 'the raw status is reported too, never replaced');
  assert.strictEqual(done.body.bakes.length, 1);
});

test('the status route summarises the lab tree instead of shipping it every poll', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const res = await call('GET', `/profiles/${PROFILE_ID}/bake`);
  assert.deepStrictEqual(res.body.bake.lab.files, [
    'data/config.json', 'data/inventory', 'providers/proxmox/inventory',
    'files/dc01/wwwroot/appsettings.Production.json', 'scripts/asrep_marcus.webb.ps1',
  ], 'the file LIST is the useful part — including the planted artifacts and the technique '
    + 'scripts, because a panel showing three chassis files for a lab that ships fifteen members '
    + 'is describing a different environment; the contents are hundreds of kilobytes no panel renders');
  assert.deepStrictEqual(res.body.bake.lab.chain, compiled().chain,
    'the chain is kept: an operator who cannot see it cannot tell a four-playbook lab from a sixteen');
  assert.strictEqual(JSON.stringify(res.body).indexOf('domain_name='), -1,
    'no file CONTENT may reach a status poll that runs every few seconds');
});

// ───────────────────────────────────────────────────────────────────────────
// 5. A deploy is refused when the bake is not usable, by name
// ───────────────────────────────────────────────────────────────────────────

test('POST /deploy is refused when the client’s bake stopped on an unbuilt phase', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();
  // Seeded, because the only phase that still refuses by construction is compile
  // and the route always hands compile a tree. The property under test is the
  // RENDERING of that state on the deploy path, which is unchanged.
  db.rows[0].error = UNBUILT_PHASE_ERROR;

  // The plan says these lanes carry an AD lab, which is what makes the bake
  // load-bearing for this deploy.
  state.deploySpec = { vms: [{ name: 'web-01' }], goad: { enabled: true } };
  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });

  assert.strictEqual(res.status, 501,
    'and it reaches the client intact: assertBakeDeployable stamps `status` while this renderer '
    + 'reads `statusCode`, which is exactly why the engagement gate’s 409 renders as a bare 500 here');
  assert.strictEqual(res.body.code, 'BAKE_STEP_NOT_IMPLEMENTED');
  assert.strictEqual(res.body.state, 'not_implemented');
  assert.match(res.body.error, /'compile' phase/);
  assert.ok(!state.audit.some((e) => e.action === 'profile_lane.deployed'),
    'a refused deploy records no deployment — the audit row is written after runProfileDeploy returns, so a gate that threw after the group existed would leave both');
});

test('the gate names a different remedy for every reason a bake is unusable', async () => {
  reset();
  const profile = { id: PROFILE_ID, json_data: {} };
  const adSpec = { vms: [{ name: 'web-01' }], goad: { enabled: true } };
  const refusal = async (spec) => assertProfileBakeDeployable({ profileId: PROFILE_ID, profile, spec })
    .then(() => null, (e) => e);

  // Nothing baked, but the plan needs one.
  let err = await refusal(adSpec);
  assert.strictEqual(err.code, 'BAKE_NOT_BUILT');
  assert.strictEqual(err.statusCode, 409, 'both property names, or POST /deploy renders it as a 500');
  assert.match(err.message, /ninety minutes/, 'the refusal says why it is not done inline');

  // Still building.
  const release = holdPhaseWrites();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  err = await refusal(adSpec);
  assert.strictEqual(err.code, 'BAKE_IN_PROGRESS');
  release();
  await settle();

  // Built, but by a phase that does not exist. Seeded — see UNBUILT_PHASE_ERROR.
  db.rows[0].error = UNBUILT_PHASE_ERROR;
  err = await refusal(adSpec);
  assert.strictEqual(err.code, 'BAKE_STEP_NOT_IMPLEMENTED');
  assert.strictEqual(err.statusCode, 501);

  // Built and finished — but nobody signed it off.
  db.rows[0].status = 'ready';
  db.rows[0].error = null;
  err = await refusal(adSpec);
  assert.strictEqual(err.code, 'BAKE_GATES_NOT_APPROVED');
  assert.match(err.message, /report success whether or not they planted anything/);

  // Signed off — and then the client was edited.
  const gates = await call('POST', `/bakes/${db.rows[0].bake_id}/gates`, {
    body: { gate_solvable: true, gate_paper: true, gate_no_unintended: true },
  });
  assert.strictEqual(gates.status, 200);
  assert.strictEqual(gates.body.state, 'ready');
  assert.strictEqual(await refusal(adSpec), null, 'a signed-off, current bake deploys');

  state.compile = compiled({ ir: { version: 7 } });
  err = await refusal(adSpec);
  assert.strictEqual(err.code, 'BAKE_CONTENT_DRIFT');
  assert.match(err.message, /do not match their brief/);
});

test('a bake the gate cannot compile is a REFUSAL, never a pass', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();
  db.rows[0].status = 'ready';
  db.rows[0].error = null;
  db.rows[0].gates_approved_at = 'approved';

  // "I could not check" and "there is no drift" must never be the same answer —
  // the same doctrine gradeVerifyReport applies to a probe that never ran.
  state.compile = Object.assign(new Error('this client has no Active Directory to compile'), { status: 422 });
  const err = await assertProfileBakeDeployable({
    profileId: PROFILE_ID, profile: { id: PROFILE_ID }, spec: { goad: { enabled: true } },
  }).then(() => null, (e) => e);

  assert.strictEqual(err.code, 'BAKE_DRIFT_UNKNOWN');
  assert.match(err.message, /Refusing rather than assuming/);
});

test('a client that has never baked and needs no lab deploys exactly as before', async () => {
  // The backwards-compatibility half, and the reason the gate is not simply
  // "always". Every CIAB deploy shipping today has no spec.goad and no bake row.
  reset();
  assert.strictEqual(deployNeedsBake({ vms: [{ name: 'web-01' }] }, []), false);
  assert.strictEqual(
    await assertProfileBakeDeployable({
      profileId: PROFILE_ID, profile: { id: PROFILE_ID }, spec: { vms: [{ name: 'web-01' }] },
    }),
    null);

  // …but a client that HAS one is gated whether or not the spec says so, because
  // a baked environment the deploy ignored would hand students other machines.
  assert.strictEqual(deployNeedsBake({ vms: [] }, [{ bake_id: 'b1' }]), true);
  assert.strictEqual(deployNeedsBake({ goad: { enabled: true } }, []), true,
    'and the plan’s own statement is honoured now, so the rule is not inert the day '
    + 'profile-to-spec starts emitting spec.goad');
});

test('the gate is on the live deploy path, not merely defined', () => {
  // Executed above through POST /deploy; this pins WHERE, because a refactor
  // that moved the call out of runProfileDeploy would leave every behavioural
  // test above green — generate-and-deploy reaches the same function.
  const body = ROUTE_SRC.slice(ROUTE_SRC.indexOf('async function runProfileDeploy'));
  const gate = body.indexOf('await assertProfileBakeDeployable(');
  assert.notStrictEqual(gate, -1, 'runProfileDeploy must call the bake gate');
  assert.ok(gate < body.indexOf('provisionLaneStudents'),
    'and before a single student account is minted');
  assert.strictEqual(
    (ROUTE_SRC.match(/assertProfileBakeDeployable\(/g) || []).length, 2,
    'defined once and called ONCE — an inline fallback that quietly baked on the deploy path is '
    + 'the one thing this gate exists to prevent, and a second call site is where one would go');
});

// ───────────────────────────────────────────────────────────────────────────
// 6. Auth gating matches the neighbours
// ───────────────────────────────────────────────────────────────────────────

const NEW_ROUTES = [
  ['POST', `/profiles/${PROFILE_ID}/bake`],
  ['GET', `/profiles/${PROFILE_ID}/bake`],
  ['POST', '/bakes/bake-1/rebake'],
  ['POST', '/bakes/bake-1/gates'],
];

test('every bake route refuses an anonymous caller and a non-admin', async () => {
  reset();
  for (const [method, url] of NEW_ROUTES) {
    const anon = await call(method, url, { anonymous: true });
    assert.strictEqual(anon.status, 401, `${method} ${url} must authenticate first`);

    for (const role of ['student', 'instructor']) {
      const res = await call(method, url, { role });
      assert.strictEqual(res.status, 403,
        `${method} ${url} is open to a ${role} — there is no requireCiabAccess on this mount, so a `
        + 'route that forgets its own gate is open to every signed-in user, and Bake burns ninety '
        + 'minutes of cluster time per press');
    }
  }
});

test('no route in the file is registered without authenticateToken and the admin role', () => {
  // A whole-file property, including handlers no test above calls. The image
  // pull is the one deliberate exception: lane VMs have no JWT and it is gated
  // on a 24-byte token plus a lab-source check instead.
  const offenders = [];
  const re = /router\.(get|post|put|patch|delete)\(\s*'([^']+)'\s*,\s*([^\n]*)/g;
  let m;
  while ((m = re.exec(ROUTE_SRC)) !== null) {
    const [, verb, route, tail] = m;
    if (route === '/image/:token') continue;
    if (!/authenticateToken/.test(tail) || !/adminOnly/.test(tail)) {
      offenders.push(`${verb.toUpperCase()} ${route}`);
    }
  }
  assert.deepStrictEqual(offenders, []);
});

test('the route builds its steps with buildBakeSteps and never by hand', () => {
  // bakeProfile fails a bake whose phase is missing rather than skipping it,
  // but only calling buildBakeSteps() guarantees the set is the SHIPPED one —
  // a hand-assembled object is how a phase silently goes missing in the first
  // place.
  assert.ok(/steps: bakeOrchestrator\.buildBakeSteps\(\)/.test(ROUTE_SRC));
  assert.strictEqual((ROUTE_SRC.match(/bakeOrchestrator\.buildBakeSteps\(\)/g) || []).length, 2,
    'the start route and the re-bake route, and nothing else');
});

test('starting a bake writes an audit row that names the version and no digest key', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const entry = state.audit.find((e) => e.action === 'profile_bake.started');
  assert.ok(entry, 'a press that commits ninety minutes of cluster time is an auditable act');
  assert.strictEqual(entry.source, 'ciab');
  assert.strictEqual(entry.target.type, 'bake');
  assert.strictEqual(entry.metadata.profile_id, PROFILE_ID);
  assert.match(entry.metadata.lab_version, /^[0-9a-f]{12}$/);
  // audit.js's SECRET_KEY_RE matches the bare substring `hash`, so a metadata
  // key called lab_hash is stored as "[redacted]" — which reads as a scrubbed
  // credential rather than as the version identity it is.
  for (const key of Object.keys(entry.metadata)) {
    assert.ok(!/hash|secret|token|cred|pass/i.test(key), `metadata key '${key}' would be redacted`);
  }
});

test('a bake for a client with no profile JSON is a 4xx, not a 500', async () => {
  reset();
  const res = await call('POST', '/profiles/00000000-0000-0000-0000-000000000000/bake');
  assert.strictEqual(res.status, 404);
  assert.strictEqual(db.rows.length, 0);
});

// ───────────────────────────────────────────────────────────────────────────
// 7. S1 — the bake carries an attack path, and the refusals are answers
// ───────────────────────────────────────────────────────────────────────────

test('a bake compiles WITH a chain — acls are planted and ir.chain is populated', async () => {
  // THE DEFECT, stated as a test. bakeIdentityForProfile called
  // compiler.compileLab(profile), which LOWERS a chain it is handed; handed
  // none it emits acls:{} and an all-null ir.chain. assertLabCompiles has no
  // opinion about solvability and assertGoadLabPreflight only checks the
  // dereferences the playbooks perform, so a roster-only forest passed both,
  // pushed clean and deployed green — a silent success.
  //
  // Asserted against the REAL compiler and the REAL designer: a stubbed chain
  // would only prove that the stub returns a chain.
  reset();
  state.real = true;

  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 202);
  await settle();

  const ir = db.rows[0].spec.goad.lab;
  assert.ok(ir.chain.start && ir.chain.start.kind,
    'the chain has an ENTRY — how a student gets their first credential');
  assert.ok(ir.chain.objective && ir.chain.objective.target,
    'and an objective, which is the account taking it ends at');
  assert.ok(ir.chain.edges.length > 0,
    'and edges between them. An all-null chain is a lab whose only content is a roster');

  const aclCount = Object.values(ir.acls)
    .reduce((n, block) => n + Object.keys(block || {}).length, 0);
  assert.ok(aclCount > 0,
    'ad-acl.yml plants lab.domains[d].acls; an empty acls map means the play runs over nothing '
    + 'and reports success, which is exactly how a chain-less lab deploys green');

  assert.ok(db.rows[0].spec.goad.generated_lab.chain.includes('ad-acl.yml'),
    'and the PLAYBOOK chain runs the play that plants them — a designed ACL with no ad-acl.yml '
    + 'in the run is a design nothing ever applies');
});

test('the pushed tree ships files/ and scripts/, and config.json references them', async () => {
  // The other half of the same defect: goad-lab-content had no caller anywhere
  // in the tree, so every bake shipped three chassis-derived text files and
  // nothing else — no web-app config (the seam between the website and the
  // forest), no planted credential for the chain's entry technique, none of the
  // six technique scripts. GOAD's two escape hatches take no parameters, so this
  // content cannot be templated at deploy time; if the bake does not ship it,
  // nothing does.
  reset();
  state.real = true;
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const tree = db.rows[0].spec.goad.generated_lab.files;
  const members = Object.keys(tree);
  for (const required of ['data/config.json', 'data/inventory', 'providers/proxmox/inventory']) {
    assert.ok(members.includes(required), `the tree is missing ${required}`);
  }
  assert.ok(members.some((p) => p.startsWith('files/')),
    'the planted artifacts — vulns/files is a byte copy, so these ARE the per-client content');
  assert.ok(members.some((p) => p.startsWith('scripts/')),
    'and the technique scripts roles/ps runs');
  assert.ok(!members.includes('playbooks.yml'),
    'and NOT playbooks.yml: pushLabTree renders it from the chain and refuses a tree that ships '
    + 'its own, because two sources of truth for the chain is one too many');

  // Shipping the bytes is only half of it. An artifact nothing references is
  // copied nowhere: vulnerabilities.yml keys vulns_vars off the host dict, so
  // the merged config.json — not the composer's — has to be the one that ships.
  const lab = JSON.parse(tree['data/config.json']).lab;
  const wired = Object.values(lab.hosts).filter(
    (h) => h.vulns_vars && h.vulns_vars.files && Object.keys(h.vulns_vars.files).length > 0);
  assert.ok(wired.length > 0,
    'config.json must carry the vulns_vars.files entries mergeLabContent wired in, or the tree is '
    + 'delivered and nothing on the guest ever reads it');
  for (const host of wired) {
    assert.ok(host.vulns.includes('files'),
      'and `files` has to be in the host vulns array — it IS the execution order');
    for (const entry of Object.values(host.vulns_vars.files)) {
      assert.ok(Object.prototype.hasOwnProperty.call(tree, `files/${entry.src}`),
        `config.json copies from files/${entry.src}, which the tree does not carry — win_copy `
        + 'fails on a missing source, an hour into the bake');
    }
  }
  assert.ok(Object.values(lab.hosts).some((h) => (h.scripts || []).length > 0),
    'and hosts[].scripts names the .ps1 files roles/ps executes');
});

test('the bake identity covers the ATTACK PATH, even when the roster is untouched', async () => {
  // WHY THIS IS THE THIRD THING S1 ASKS FOR. lab_hash is what
  // assertBakeDeployable measures drift against and what ON CONFLICT
  // (profile_id, lab_hash) keys a row on. If the hash covered only the roster
  // and the hosts, editing a profile in a way that moved only the attack path
  // would find the OLD row: the deploy gate would report no drift, and lanes
  // would be cloned from golden templates whose AD carries different edges from
  // the answer key the instructor is holding. Silently.
  reset();
  const base = bakeIdentityForProfile({ id: PROFILE_ID });

  // One edge moves. Same company, same roster, same hosts.
  const moved = compiled();
  moved.ir.chain = {
    ...moved.ir.chain,
    edges: [{ from: 'svc.sql', to: 'helpdesk.svc', via: 'WriteDacl' }],
  };
  state.compile = moved;
  const afterChain = bakeIdentityForProfile({ id: PROFILE_ID });

  assert.deepStrictEqual(afterChain.spec.goad.lab.principals, base.spec.goad.lab.principals,
    'the roster really is identical — otherwise this test proves nothing about the chain');
  assert.notStrictEqual(afterChain.labHash, base.labHash,
    'and the environment is a different one, because the golden templates were built with the '
    + 'old edges planted in AD');

  // And the CONTENT, which the IR does not describe. A new artifact writer in
  // goad-lab-content rewrites the bytes on the guest while leaving the IR
  // byte-identical; a hash over the IR alone would call that the same
  // environment and deploy last week's templates against this week's plants.
  reset();
  const beforeContent = bakeIdentityForProfile({ id: PROFILE_ID });
  state.content = contentPack({
    tree: { 'files/dc01/wwwroot/appsettings.Production.json': '{"Ldap":{"BindPassword":"Slate-Beacon44#"}}\n' },
  });
  const afterContent = bakeIdentityForProfile({ id: PROFILE_ID });
  assert.notStrictEqual(afterContent.labHash, beforeContent.labHash,
    'the planted credential changed; the environment changed');

  // …and it is still STABLE under no change at all, or every poll of the status
  // route would report drift and no bake would ever be deployable.
  reset();
  assert.strictEqual(
    bakeIdentityForProfile({ id: PROFILE_ID }).labHash,
    bakeIdentityForProfile({ id: PROFILE_ID }).labHash,
    'identical content compiles to one identity — that is what makes re-baking a no-op');
});

test('each compiler refusal is its own named state with a remedy, never a 500', async () => {
  // These three are the compiler correctly declining to produce a broken
  // environment. An operator reading "500 Internal Server Error" goes to the
  // cluster; an operator reading "this client is below the domain floor" goes to
  // the intake. Rendering both the same way sends half of them to the wrong
  // place, and the one that costs a day is the first.
  const expected = {
    CIAB_NO_AD_TO_COMPILE: 'no_ad_to_compile',
    CHAIN_UNREPAIRABLE: 'chain_unrepairable',
    CIAB_ADMIN_NEGOTIATION_FAILED: 'admin_negotiation_failed',
  };
  for (const [code, wantState] of Object.entries(expected)) {
    reset();
    state.compile = Object.assign(new Error(`the compiler declined: ${code}`), { code, status: 422 });

    const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
    assert.strictEqual(res.status, 422,
      `${code} must be a 422 — the request is well-formed, the environment it describes is not`);
    assert.strictEqual(res.body.code, code);
    assert.strictEqual(res.body.state, wantState, `${code} needs a state of its OWN`);
    assert.strictEqual(res.body.compile_refusal.code, code);
    assert.ok(res.body.compile_refusal.remedy.length > 60,
      'and a remedy — a refusal an operator cannot act on is barely better than a crash');
    assert.strictEqual(res.body.compile_refusal.reason, res.body.error,
      'the reason is the compiler\'s own message, not a rewrite of it');
    assert.strictEqual(db.rows.length, 0,
      'and nothing was created: lab_hash IS the row identity and a refused compile has none');
  }

  // The classification has to be able to say NO, or it says nothing. An
  // unrecognised failure is an outage and must keep looking like one.
  reset();
  state.compile = Object.assign(new Error('EIO reading the chassis library'), { code: 'EIO' });
  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 500);
  assert.strictEqual(res.body.state, undefined);
  assert.strictEqual(res.body.compile_refusal, undefined);
  assert.strictEqual(compileRefusalOf({ code: 'EIO' }), null);
  assert.deepStrictEqual(Object.keys(COMPILE_REFUSALS).sort(), Object.keys(expected).sort(),
    'the vocabulary is exactly these three; a fourth needs a state and a remedy of its own');
});

test('a client below the domain floor is refused by name — the reason and the remedy', async () => {
  // The real org-sizing ladder, not a thrown fixture: six people, cloud-first,
  // has_domain false. There is no forest to build and no amount of re-baking
  // will produce one, so the refusal has to say so and say what to do instead.
  reset();
  state.real = true;

  const res = await call('POST', `/profiles/${TINY_PROFILE_ID}/bake`);

  assert.strictEqual(res.status, 422, 'a correct answer about this client, not a server error');
  assert.strictEqual(res.body.code, 'CIAB_NO_AD_TO_COMPILE');
  assert.strictEqual(res.body.state, 'no_ad_to_compile');
  assert.match(res.body.error, /org-sizing puts the first domain at/,
    'the refusal names the RULE it applied, not just the verdict');
  assert.match(res.body.error, /6-employee/, 'and the fact about this client that triggered it');
  assert.match(res.body.compile_refusal.remedy, /without a GOAD tier/,
    'and what to do instead — this client still deploys, it just has no AD lab');
  assert.strictEqual(db.rows.length, 0);
});

test('the status route reports a refused client as refused, not as "not built yet"', async () => {
  // 'not_built' means "press Bake". For a client that can never compile, Bake
  // refuses every time — so reporting 'not_built' is the same silent-success
  // shape one level up: a button that looks like it will work and never does.
  reset();
  state.real = true;

  const res = await call('GET', `/profiles/${TINY_PROFILE_ID}/bake`);

  assert.strictEqual(res.status, 200, 'a client that cannot host AD is an ANSWER, not a 500');
  assert.strictEqual(res.body.state, 'no_ad_to_compile');
  assert.strictEqual(res.body.compile_refusal.code, 'CIAB_NO_AD_TO_COMPILE');
  assert.match(res.body.compile_refusal.remedy, /without a GOAD tier/);
  assert.strictEqual(res.body.deployable, false);
  assert.strictEqual(res.body.blocked.code, 'BAKE_NOT_BUILT');

  // …and a client that CAN compile and simply has not been baked still reads
  // the old way, or this would have replaced one wrong answer with another.
  reset();
  const ok = await call('GET', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(ok.body.state, 'not_built');
  assert.strictEqual(ok.body.compile_refusal, null);
  assert.strictEqual(bakeStateOf(null, null), 'not_built');
  assert.strictEqual(bakeStateOf(null, { state: 'chain_unrepairable' }), 'chain_unrepairable');
  assert.strictEqual(bakeStateOf({ status: 'ready', gates_approved_at: 'x' }, { state: 'chain_unrepairable' }), 'ready',
    'a bake that EXISTS is still described by its own row — the refusal only fills a vacuum');
});

test('a deploy blocked by a refused compile says which refusal, not just "could not check"', async () => {
  // The gate's verdict is still BAKE_DRIFT_UNKNOWN — a bake that cannot be
  // compared cannot be deployed either way, and "I could not check" must never
  // become "there is no drift". But the REASON rides along, because
  // "this client is below the domain floor" and "the compiler crashed" send an
  // operator to two different places.
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();
  db.rows[0].status = 'ready';
  db.rows[0].error = null;
  db.rows[0].gates_approved_at = 'approved';

  state.compile = Object.assign(
    new Error('Larkspur Studio has no Active Directory to compile'),
    { code: 'CIAB_NO_AD_TO_COMPILE', status: 422 });

  const err = await assertProfileBakeDeployable({
    profileId: PROFILE_ID, profile: { id: PROFILE_ID }, spec: { goad: { enabled: true } },
  }).then(() => null, (e) => e);

  assert.strictEqual(err.code, 'BAKE_DRIFT_UNKNOWN');
  assert.strictEqual(err.compile_refusal.code, 'CIAB_NO_AD_TO_COMPILE');
  assert.strictEqual(err.compile_refusal.state, 'no_ad_to_compile');

  // And it reaches the client through POST /deploy, which is the only place an
  // operator sees it.
  state.deploySpec = { vms: [{ name: 'web-01' }], goad: { enabled: true } };
  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_DRIFT_UNKNOWN');
  assert.strictEqual(res.body.compile_refusal.code, 'CIAB_NO_AD_TO_COMPILE');
});

test('a compile that comes back without a chain is refused as a DEFECT, never baked', async () => {
  // The guard that makes the original defect impossible to reintroduce quietly.
  // It is a 500 on purpose: the three refusals above are the compiler correctly
  // declining, and this is the compiler breaking its own contract — which is a
  // bug in us, not a client that cannot host an engagement.
  reset();
  const chainless = compiled();
  chainless.ir.chain = { start: null, objective: null, edges: [], decoys: [], domain: null };
  chainless.ir.acls = { 'clinic.local': {} };
  state.compile = chainless;

  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 500,
    'not a 422 — nothing about this client is wrong, and no remedy an operator can apply exists');
  assert.strictEqual(res.body.code, 'CIAB_BAKE_CHAINLESS_COMPILE');
  assert.strictEqual(res.body.compile_refusal, undefined);
  assert.match(res.body.error, /roster and no attack path/);
  assert.strictEqual(db.rows.length, 0,
    'ninety minutes of cluster time is not spent on an environment with no exercise in it');
});

test('the identity is compiled WITH a chain and merged WITH its content', () => {
  // The one coupling behavioural tests cannot pin: WHICH compiler entry point
  // this function calls. Every assertion above would stay green against a
  // fixture that happened to carry a chain, and the live defect was precisely a
  // call to the entry point that does not design one.
  // Normalised first: the route file is CRLF on disk, so a slice keyed on a bare
  // '\n}\n' finds nothing and the assertions below would scan an empty string —
  // a source pin that passes because it read nothing is worse than no pin.
  const SRC = ROUTE_SRC.replace(/\r\n/g, '\n');
  const from = SRC.indexOf('function bakeIdentityForProfile');
  assert.notStrictEqual(from, -1);
  const body = SRC.slice(from);
  const stop = body.indexOf('\n}\n');
  assert.ok(stop > 0, 'the function body has to be findable, or this test asserts over nothing');
  const fn = body.slice(0, stop + 3);


  assert.ok(/compiler\.compileLabWithChain\(/.test(fn),
    'compileLabWithChain runs composer -> designer -> composer and refuses rather than emit an '
    + 'unproven chain');
  assert.ok(!/compiler\.compileLab\(/.test(fn),
    'compileLab LOWERS a chain it is handed; called bare it emits acls:{} and an all-null '
    + 'ir.chain, and both checkers pass it — this is the defect, spelled out');
  assert.ok(/generateLabContent\(/.test(fn) && /mergeLabContent\(/.test(fn),
    'and the per-lab files/ and scripts/ are generated AND wired in — a tree shipped without the '
    + 'vulns_vars.files entries is copied nowhere');
});

// ───────────────────────────────────────────────────────────────────────────
// 8. C1 — the bake-to-deploy loop actually closes
// ───────────────────────────────────────────────────────────────────────────
/*
 * THREE PRODUCERS THAT DID NOT EXIST, each for a consumer that did.
 *
 *   spec.vxlan_block + spec.goad.fixed_subnet   bake-staging.assertBakeableSpec
 *       and assertFixedSubnet require both, so EVERY bake started through this
 *       route failed in the provision phase — and the fixed_subnet flavour of
 *       the same refusal is also made by captureGolden, which runs AFTER the
 *       ninety-minute ansible chain. The worst place in the system to discover
 *       a missing field.
 *
 *   spec.goad.prebaked + the golden templates   the deploy gate validated a
 *       signed-off bake and then threw the row away. Every lane cloned the
 *       ORIGINAL catalog templates and stood up its own ansible controller, so
 *       the golden images were built, reviewed, and never once cloned — while
 *       every deploy reported success.
 *
 *   spec.reseed.pivot   resolveReseedPlan refuses to GUESS the pivot account
 *       (resetting an invented name fails on every lane at once; resetting the
 *       wrong real one breaks the forest), so with nothing naming it the
 *       credential phase is skipped and every student in a section holds the one
 *       password baked into the golden image.
 *
 * Every assertion below drives a REQUEST or the real pure producer, and reads
 * what actually reached the consumer — the bake row's spec, or the challenge
 * object handed to lane-provision. None of it is visible in source text.
 */

/** Let the setImmediate'd background deploy hand off to lane-provision. */
async function drain() {
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
}

/** The challenge object the deploy actually handed the lane deployer. */
function deployedChallenge() {
  assert.strictEqual(state.provisioned.length, 1,
    'exactly one hand-off to lane-provision — that object IS the deploy');
  return state.provisioned[0].challenge;
}

/** A client whose forest is two Windows boxes plus a dual-homed web host. */
function adDeploySpec() {
  return {
    subnet_scheme: 'v3',
    vms: [
      { name: 'NWC-DC01', type: 'qemu', role: 'server', os_family: 'windows',
        template_vmid: 9001, template_node: 'catalog-node', ipOctet: 80 },
      { name: 'NWC-SRV02', type: 'qemu', role: 'server', os_family: 'windows',
        template_vmid: 9002, template_node: 'catalog-node', ipOctet: 81 },
      // Dual-homed, so isGoadManagedVm exempts it from the AD roster — it still
      // clones its golden image, it just is not part of the forest.
      { name: 'web-01', type: 'qemu', role: 'dmz', os_family: 'linux',
        template_vmid: 9003, template_node: 'catalog-node', ipOctet: 240,
        nics: [{ segment: 'ext' }, { segment: 'int' }] },
    ],
  };
}

const GOLDEN = {
  'NWC-DC01': { name: 'NWC-DC01', vmid: 700001, node: 'node-3' },
  'NWC-SRV02': { name: 'NWC-SRV02', vmid: 700002, node: 'node-3' },
  'web-01': { name: 'web-01', vmid: 700003, node: 'node-3' },
};

/** Bake this client, then sign it off — the state a deploy is allowed to use. */
async function bakeAndSignOff(golden = GOLDEN) {
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();
  const row = db.rows[0];
  row.status = 'ready';
  row.error = null;
  row.gate_solvable = true;
  row.gate_paper = true;
  row.gate_no_unintended = true;
  row.gates_approved_at = 'approved';
  row.golden_vmids = golden;
  return row;
}

// ── (a) the staging network ─────────────────────────────────────────────────

test('a bake carries the block its staging lane draws from, and the bases it will bake in', async () => {
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const spec = db.rows[0].spec;
  assert.deepStrictEqual(spec.vxlan_block, { start: STAGING_VXLAN, end: STAGING_VXLAN },
    'the bake records WHERE its staging lane lives; without it bake-staging falls back to the '
    + 'client default reservation, which is the class block');
  assert.deepStrictEqual(spec.goad.fixed_subnet, { int: STAGING_INT, ext: STAGING_EXT },
    'and the two /24 bases every lane cloned from it is pinned to — a provisioned forest writes its '
    + 'own addresses into DNS, SYSVOL and every SPN, so this is the difference between a template '
    + 'set lanes can be built from and one that is fiction on every lane');

  // NOT THE CLASS'S BLOCK. The student engagement holds 10000-10004 and is sized
  // exactly to max_students; a staging lane is never torn down (its VMs ARE the
  // golden templates), so an id borrowed from there is a seat gone for the life
  // of the environment.
  const classBlock = state.reservations.get('default').vxlan_block;
  assert.ok(spec.vxlan_block.start < classBlock.start || spec.vxlan_block.start > classBlock.end,
    `the staging id ${spec.vxlan_block.start} sits inside the class ${classBlock.start}-${classBlock.end}`);
  assert.strictEqual(spec.vxlan_block.start, spec.vxlan_block.end,
    'and it is a block of ONE — with more ids nothing could say which one the staging lane would '
    + 'take, and fixed_subnet is derived from exactly that id');
});

test('the bases are the deployer own derivation, not a second copy of the arithmetic', () => {
  // lane-networking.js exists because the last copy of these four lines drifted
  // and minted addresses that collided with the shared allocator's. A base
  // derived one way at bake time and another way at deploy time is a forest that
  // names addresses no lane owns — and the lane still reports active.
  const laneNetworking = require(path.join(ROOT, 'src', 'utils', 'lane-networking.js'));
  const fixed = router.bakeFixedSubnetFor({ start: STAGING_VXLAN, end: STAGING_VXLAN });
  assert.strictEqual(fixed.int, laneNetworking.v3InternalSubnet(STAGING_VXLAN).base3);
  assert.strictEqual(fixed.ext, laneNetworking.v2LaneSubnet(STAGING_VXLAN).base3);
  assert.notStrictEqual(fixed.int, fixed.ext,
    'both segments, and different ones: int is where the baked AD lives, ext is where Kali, the '
    + 'DMZ pivot and every published console live');
});

test('bake-staging reads the block back off the spec, without touching the class reservation', async () => {
  // The REAL consumer, driven. resolveVxlanBlock prefers spec.vxlan_block and
  // falls back to findProfileChallenge(profile_id) — the DEFAULT engagement —
  // and that fallback is precisely what must never fire for a route-started bake.
  reset();
  await call('POST', `/profiles/${PROFILE_ID}/bake`);
  await settle();

  const bakeStaging = require(path.join(CIAB, 'utils', 'bake-staging.js'));
  const block = await bakeStaging.resolveVxlanBlock({
    bake: db.rows[0],
    spec: db.rows[0].spec,
    override: null,
    deps: {
      findProfileChallenge: async () => {
        throw new Error('resolveVxlanBlock fell back to the class reservation');
      },
    },
  });
  assert.deepStrictEqual(block, { start: STAGING_VXLAN, end: STAGING_VXLAN });
});

// ── (a) the pre-flight refuses EARLY ────────────────────────────────────────

test('a client with no staging network gets one carved and the bake is refused, not started', async () => {
  reset();
  state.engagements.delete('bake');
  state.reservations.delete('bake');

  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);

  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.body.code, 'BAKE_NETWORK_PROVISIONING');
  assert.strictEqual(db.rows.length, 0,
    'and NOTHING was started: a bake whose staging lane has no block to allocate from would fail in '
    + 'the provision phase after the row, the mutex and the audit entry already existed');
  assert.strictEqual(state.createdEngagements.length, 1);
  assert.strictEqual(state.createdEngagements[0].engagement_type, 'bake');
  assert.strictEqual(state.createdEngagements[0].max_students, 1,
    'ONE slot: a staging lane must not be sized like a class, and a one-id block is what makes the '
    + 'id — and therefore the baked subnet — knowable in advance');
  assert.match(res.body.error, /Press Bake again/,
    'carving is a background job (an SDN apply plus a wait for bridges on every node), so the '
    + 'refusal has to tell an operator what to do next rather than hang the request for a minute');
});

test('a staging network that is still carving refuses the bake by name', async () => {
  reset();
  state.engagements.get('bake').provision_status = 'provisioning';

  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.body.code, 'BAKE_NETWORK_NOT_READY');
  assert.match(res.body.error, /still being reserved/,
    'the wording is assertEngagementDeployable own — one vocabulary for one fact');
  assert.strictEqual(db.rows.length, 0);
  assert.strictEqual(state.createdEngagements.length, 0,
    'and it did not carve a SECOND block on top of the one already being carved');
});

test('a staging block bigger than one lane is refused, because the baked subnet would be a guess', async () => {
  reset();
  state.reservations.get('bake').vxlan_block = { start: 10200, end: 10204 };

  const res = await call('POST', `/profiles/${PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.body.code, 'BAKE_NETWORK_BLOCK_TOO_BIG');
  assert.match(res.body.error, /ninety minutes/,
    'the refusal has to say what it saves: with more than one id the capture phase compares the '
    + 'declared bases against whichever id the allocator happened to hand out, and refuses at the '
    + 'far end of the chain');
  assert.strictEqual(db.rows.length, 0);
});

test('the pre-flight is the REAL provision and capture guards, not a copy of them', () => {
  // A pre-flight assembled out of a second copy of the rules is a pre-flight that
  // can pass a spec the consumer then rejects — and this consumer rejects at the
  // end of a ninety-minute run. So the codes have to be bake-staging own.
  const bakeStaging = require(path.join(CIAB, 'utils', 'bake-staging.js'));
  const good = {
    subnet_scheme: 'v3',
    vxlan_block: { start: STAGING_VXLAN, end: STAGING_VXLAN },
    goad: { enabled: true, fixed_subnet: { int: STAGING_INT, ext: STAGING_EXT } },
  };
  assert.strictEqual(router.assertBakeSpecProvisionable(good), good);

  const codeOf = (spec) => {
    try { router.assertBakeSpecProvisionable(spec); return null; } catch (e) { return e.code; }
  };
  assert.strictEqual(codeOf({ ...good, goad: { enabled: false } }), 'BAKE_PROVISION_NOT_GOAD');
  assert.strictEqual(codeOf({ ...good, goad: { ...good.goad, prebaked: true } }),
    'BAKE_PROVISION_ALREADY_PREBAKED');
  assert.strictEqual(codeOf({ ...good, goad: { enabled: true } }), 'BAKE_CAPTURE_NO_FIXED_SUBNET');
  assert.strictEqual(codeOf({ ...good, goad: { enabled: true, fixed_subnet: { int: STAGING_INT } } }),
    'BAKE_CAPTURE_NO_FIXED_SUBNET');
  assert.strictEqual(codeOf({ ...good, vxlan_block: undefined }), 'BAKE_PROVISION_NO_VXLAN_BLOCK');

  // …and they really are the shipped functions, so a reworded refusal in
  // bake-staging cannot leave this route agreeing with a rule nobody enforces.
  assert.throws(() => bakeStaging.assertFixedSubnet({ goad: { enabled: true } }),
    (err) => err.code === 'BAKE_CAPTURE_NO_FIXED_SUBNET');
  assert.throws(() => bakeStaging.assertBakeableSpec({ goad: { enabled: false } }),
    (err) => err.code === 'BAKE_PROVISION_NOT_GOAD');
});

test('a client that cannot compile is refused BEFORE any staging network is carved', async () => {
  // Ordering, and it costs range: three kinds of client can never be baked, and
  // carving a VXLAN block plus its VNets for one of them leaves a reservation
  // nothing will ever use. The compile is pure CPU over files already on disk.
  reset();
  state.real = true;
  state.engagements.delete('bake');
  state.reservations.delete('bake');

  const res = await call('POST', `/profiles/${TINY_PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 422);
  assert.strictEqual(res.body.code, 'CIAB_NO_AD_TO_COMPILE');
  assert.strictEqual(state.createdEngagements.length, 0,
    'a client below the domain floor must not leave a staging reservation behind');
});

// ── (b) the deploy clones the golden templates ──────────────────────────────

test('a deploy against a signed-off bake clones the GOLDEN templates, not the catalog', async () => {
  reset();
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await drain();

  const spec = deployedChallenge().spec;
  const byName = Object.fromEntries(spec.vms.map((v) => [v.name, v]));

  assert.strictEqual(byName['NWC-DC01'].template_vmid, 700001,
    'THE WHOLE POINT OF A BAKE: the machine clones the template the ninety-minute chain produced. '
    + 'Left at 9001 it clones the stock catalog image and the forest is gone');
  assert.strictEqual(byName['NWC-SRV02'].template_vmid, 700002);
  assert.strictEqual(byName['web-01'].template_vmid, 700003,
    'a machine outside the AD roster still clones ITS golden image — it was on the staging lane and '
    + 'it was captured');
  assert.strictEqual(byName['NWC-DC01'].template_node, 'node-3',
    'and from the node the staging lane was placed on, not the catalog node the synthesizer wrote');
});

test('and it takes deployPrebakedGoadLane path instead of re-running the chain', async () => {
  reset();
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();
  await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  await drain();

  const goad = deployedChallenge().spec.goad;
  assert.strictEqual(goad.enabled, true);
  assert.strictEqual(goad.prebaked, true,
    'challenge-lane-deployer branches on exactly this key: without it a lane cloned from golden AD '
    + 'images ALSO stands up an ansible controller and re-provisions a forest that is already there '
    + '— ninety minutes per student, and it reports success');
  assert.deepStrictEqual(goad.fixed_subnet, { int: STAGING_INT, ext: STAGING_EXT },
    'pinned to the bases the images were baked on — applyPrebakedFixedSubnet refuses the lane '
    + 'without them, and lane-reseed refuses to reseed a lane that disagrees with them');
  assert.strictEqual(goad.generated_lab, undefined,
    'and the ansible tree does NOT travel: a pre-baked lane has no controller, and this spec is '
    + 'persisted and re-read on every add-lanes and every retry for the life of the engagement');
});

test('the lab definition it deploys against is the shape goad-deploy validates', async () => {
  // The bake stamps the COMPILER IR on spec.goad.lab — {hosts, principals,
  // chain, acls} — because that is what the answer key and the drift check need.
  // goad-deploy wants {forestRoot, vms:[{name, role, os, template_vmid,
  // ipOctet}]} and VALIDATES it before a single clone, inside prepareGoadMacs,
  // which is NOT covered by the deployer best-effort GOAD catch. Handing it the
  // IR does not degrade the lane; it kills the whole deploy.
  reset();
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();
  await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  await drain();

  const spec = deployedChallenge().spec;
  const goadDeploy = require(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'));

  // The real validator, and the real roster reconciliation — the two things that
  // would throw before the first clone.
  const { labDef } = goadDeploy.resolveGoadLab(spec);
  assert.strictEqual(labDef.forestRoot, 'clinic.local');
  assert.deepStrictEqual(labDef.vms.map((v) => [v.name, v.role, v.template_vmid, v.ipOctet]), [
    ['NWC-DC01', 'dc', 700001, 80],
    ['NWC-SRV02', 'member', 700002, 81],
  ], 'the controller is a dc and the member is a member — deployPrebakedGoadLane heals the two '
    + 'differently, and a role it does not recognise is a machine it silently skips');

  // prepareGoadMacs runs assertGoadRoster, which requires the lab roster and the
  // goad-managed spec VMs to be the same set in BOTH directions.
  const macs = goadDeploy.prepareGoadMacs(spec, 12345, STAGING_INT);
  assert.deepStrictEqual(Object.keys(macs).sort(), ['NWC-DC01', 'NWC-SRV02'],
    'the dual-homed web host is exempt (explicit nics), and everything in the forest is present — '
    + 'an unmatched host gets no MAC, no DHCP reservation, is skipped by the pre-baked heal, and '
    + 'the lane still reports active');
  assert.strictEqual(macs['NWC-DC01'].static_ip, `${STAGING_INT}.80`);
});

test('the golden overlay is PERSISTED, so add-lanes and retry clone it too', async () => {
  // add-lanes and retry-lane rebuild their challenge object from the stored
  // reservation spec, days later. An overlay applied only in memory would give
  // the first deploy golden clones and hand every later lane of the same
  // engagement the catalog templates and a ninety-minute chain.
  reset();
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();
  await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  await drain();

  const write = state.cybercore.filter((q) => /UPDATE crucible_challenge SET spec/.test(q.sql));
  assert.strictEqual(write.length, 1, 'one write, not one per concern');
  const stored = JSON.parse(write[0].params[0]);
  assert.strictEqual(stored.goad.prebaked, true);
  assert.strictEqual(stored.vms.find((v) => v.name === 'NWC-DC01').template_vmid, 700001);
  assert.strictEqual(stored.reseed.pivot.sam, 'svc.webapp');
  // The plant descriptors have to survive the round trip too: add-lanes and
  // retry-lane rebuild the challenge from THIS row, so a seam that lived only in
  // memory would give the first deploy a rewritten website and every later lane
  // of the same engagement the baked password.
  assert.ok(stored.reseed.pivot.site.plants.length >= 2,
    'the persisted spec carries nowhere for a later lane to rewrite the credential');
  assert.strictEqual(stored.reseed.pivot.rotate, true);
  assert.ok(Array.isArray(stored.reseed.fixed));
  assert.ok(stored.reseed.uniqueness.per_lane.length >= 3);
});

test('a signed-off bake that captured nothing is refused, never silently re-run', async () => {
  reset();
  await bakeAndSignOff({});
  state.deploySpec = adDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_NO_GOLDEN_TEMPLATES');
  assert.strictEqual(state.provisioned.length, 0,
    'falling through to the live path would hand students a forest nobody reviewed while the panel '
    + 'reads ready');
});

test('a golden template with no machine to clone onto is refused', async () => {
  reset();
  await bakeAndSignOff({
    ...GOLDEN,
    'NWC-SRV09': { name: 'NWC-SRV09', vmid: 700009, node: 'node-3' },
  });
  state.deploySpec = adDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_GOLDEN_UNMATCHED');
  assert.match(res.body.error, /NWC-SRV09/,
    'the forest still holds that host AD account, its SPNs and its DNS records, all pointing at a '
    + 'machine the lane does not have — and the lane would report active');
  assert.strictEqual(state.provisioned.length, 0);
});

test('a bake and a deploy that disagree about the subnet scheme are refused', async () => {
  reset();
  const row = await bakeAndSignOff();
  row.spec.subnet_scheme = 'v3';
  state.engagements.get('default').subnet_scheme = 'v2';
  state.deploySpec = adDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_SCHEME_MISMATCH');
  assert.strictEqual(state.provisioned.length, 0,
    'a v2 lane has ONE segment, so half the addresses a v3-baked forest names would be wrong — and '
    + 'the lane would still come up');
});

// ── (b) the no-bake path is untouched ───────────────────────────────────────

test('a deploy with no bake is byte-identical to today', async () => {
  // The backwards-compatibility half. Every CIAB deploy shipping today has no
  // spec.goad and no bake row, and none of them may acquire one.
  reset();
  const plain = { subnet_scheme: 'v3', vms: [{ name: 'web-01', template_vmid: 9003 }] };
  state.deploySpec = plain;

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await drain();

  const spec = deployedChallenge().spec;
  assert.deepStrictEqual(spec, router.adoptedSpec(plain, {
    vxlan_block: state.reservations.get('default').vxlan_block,
    spec: {},
  }), 'exactly what adoptedSpec produced and nothing else — no goad key, no reseed key, no '
    + 'rewritten template_vmid');
  assert.strictEqual(spec.goad, undefined);
  assert.strictEqual(spec.reseed, undefined);
  assert.strictEqual(spec.vms[0].template_vmid, 9003, 'still the catalog template');
});

test('the overlay returns its INPUT when nothing applies, so unchanged is provable', () => {
  // Identity-equal, not merely deep-equal: a reconstruction that happens to look
  // the same is not a proof that the no-bake path is untouched.
  const spec = { vms: [{ name: 'web-01' }] };
  assert.strictEqual(router.prebakedSpecFromBake(spec, null), spec);
  assert.strictEqual(router.prebakedSpecFromBake(spec, { status: 'failed' }), spec);
  assert.strictEqual(router.prebakedSpecFromBake(spec, { status: 'provisioning' }), spec);
});

// ── (c) the pivot credential ────────────────────────────────────────────────

test('the deploy spec NAMES the pivot account, so lane-reseed can rotate it', async () => {
  // resolveReseedPlan refuses to guess: a spec that names no account gets the
  // credential phase skipped and says so on the lane row, which means every lane
  // in the section keeps the ONE password baked into the golden image.
  reset();
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();
  await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  await drain();

  const spec = deployedChallenge().spec;
  const pivot = spec.reseed.pivot;
  assert.strictEqual(pivot.sam, 'svc.webapp',
    'the account the WEBSITE publishes — on this client that is also the chain\'s foothold, because '
    + 'its entry is planted web-side');
  assert.strictEqual(pivot.domain, 'clinic.local',
    "the account's DNS domain off labIR.principals.users, which is what Set-ADAccountPassword "
    + '-Server and ValidateCredentials take');
  assert.strictEqual(pivot.netbios, 'CLINIC',
    'the short name is CARRIED, because the settings page prints it beside the account — and it is '
    + 'carried in its own field, because it is not a domain either AD call accepts');
  assert.strictEqual(pivot.rotate, true);
  assert.strictEqual(pivot.fixed_reason, null);

  // ── the half that was missing entirely ──────────────────────────────────
  // Without this block lane-reseed rotates AD, writes an env file it created
  // itself, and leaves the company website publishing the BAKED password out of
  // its own config file and off its integration-settings page — with plan.warnings
  // empty and the lane green.
  assert.ok(pivot.site && Array.isArray(pivot.site.plants) && pivot.site.plants.length >= 2,
    `the deploy spec carries no site plants: ${JSON.stringify(pivot.site)}`);
  const kinds = pivot.site.plants.map((p) => p.kind);
  assert.ok(kinds.includes('app_config'), 'the config cc_web templates under the docroot is not a target');
  assert.ok(kinds.includes('published_page'), 'the page that prints the password is not a target');
  for (const plant of pivot.site.plants) {
    assert.ok(plant.path.startsWith(pivot.site.docroot),
      `${plant.path} is not under the docroot the bake installed`);
    assert.ok(realContent.SITE_RESEED_OPS.includes(plant.op),
      `${plant.path} names operation '${plant.op}', which lane-reseed does not implement`);
  }

  // The REAL consumer agrees it can act on it.
  const laneReseed = require(path.join(CIAB, 'utils', 'lane-reseed.js'));
  const plan = laneReseed.resolveReseedPlan({
    spec,
    deployedVMs: [
      { vm_id: 1, name: 'NWC-DC01', type: 'qemu', node: 'n1' },
      { vm_id: 2, name: 'web-01', type: 'qemu', node: 'n1' },
    ],
  });
  assert.ok(plan.pivot, 'resolveReseedPlan must be able to build a credential plan from it');
  assert.strictEqual(plan.pivot.sam, 'svc.webapp');
  assert.strictEqual(plan.pivot.domain, 'clinic.local');
  assert.strictEqual(plan.pivot.envKey, 'AD_SERVICE_PASSWORD');
  assert.ok(plan.dc, 'and it found the domain controller to reset it on');
  assert.strictEqual(plan.pivot.sitePlants.length, pivot.site.plants.length,
    'the consumer accepted every publisher the producer emitted — a descriptor it drops is a page '
    + 'that goes on serving the baked password');
  assert.ok(!plan.warnings.some((w) => /declares NO site plants/.test(w)),
    `the consumer still reports the seam as unwired: ${JSON.stringify(plan.warnings)}`);
});

// ── (c2) WHICH account, in WHICH domain, and which must never be rotated ────
//
// Driven by the REAL compiler over many run ids rather than by one fixture. The
// whole defect was that the overlay took the account off the CHAIN while the
// website publishes a different one on most clients, and no single fixture can
// show that: it is a property of the spread of chain entries the designer
// rotates through. Twenty-four clients cover all seven entry points several
// times over.

const SWEEP_RUN_IDS = Object.freeze(
  Array.from({ length: 24 }, (unused, i) => `RUN_RESEED_SWEEP_${i}`));

const sweepCache = new Map();
/**
 * One real client: compiled with a real chain, its real website authored, and a
 * bake row shaped exactly as the deploy gate hands one to the overlay.
 */
function sweepClient(i) {
  if (!sweepCache.has(i)) {
    const runId = SWEEP_RUN_IDS[i];
    const c = realCompile.compileLabWithChain({
      json_data: {
        student_view: {
          meta: { run_id: runId, client_type: 'SMB', difficulty: 'intermediate' },
          quick: { company_name: `Sweep Client ${i}`, employees_total: 40 + i * 7 },
          raw: {
            threats: {
              organization: {
                company_name: `Sweep Client ${i}`, domain_public: `sweep${i}.example`,
                employees_total: 40 + i * 7, hq_city: 'Tucson, AZ',
                industry: 'Professional Services',
                department_breakdown: { Operations: 20, Sales: 10, Finance: 6, IT: 4, Administration: 5 },
              },
              it_environment: { delivery: 'Hybrid' },
            },
          },
          stakeholders: [
            { name: 'Dr. Jane Smith', role: 'Chief Executive Officer', department: 'Executive' },
            { name: 'Marcus Webb', role: 'IT Manager', department: 'IT' },
          ],
        },
      },
    });
    const ir = c.ir;
    const site = realContent.generateSiteContent(ir, { runId: c.run_id });
    const bake = {
      bake_id: `sweep-${i}`, lab_name: ir.lab_name, status: 'ready',
      // The witness the overlay checks its own re-derivation against.
      verify_report: {
        cc_web: {
          applicable: true, passed: true,
          pivot_path: site.pivot.path,
          pivot_account: `${site.pivot.domain}\\${site.pivot.username}`,
        },
      },
      spec: { goad: { lab: { ...ir, forestRoot: ir.foothold_credential.domain } } },
    };
    sweepCache.set(i, { ir, site, bake, runId });
  }
  return sweepCache.get(i);
}

/** The reseed block the overlay would put on the deploy spec for that client. */
function sweepReseed(i) {
  const { ir, bake } = sweepClient(i);
  return router.reseedBlockForBake({
    spec: {}, bake, ir, foothold: ir.foothold_credential,
  });
}

test('over 24 real clients the rotated account is ALWAYS the one the website publishes', () => {
  // THE DEFECT, STATED AS A PROPERTY. The overlay used to take the account off
  // labIR.foothold_credential. goad-lab-content only publishes the foothold when
  // the chain plants it web-side; for an AS-REP, a null-session, an open-share or
  // a password-equals-username entry it deliberately publishes an INERT bind
  // account instead. So on most of these clients the reseed rotated one account
  // while every page on the box advertised another — silently, on both sides.
  const disagreements = [];
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir, site } = sweepClient(i);
    const pivot = sweepReseed(i).pivot;
    assert.strictEqual(pivot.sam, site.reseed.username,
      `client ${i} (entry '${ir.chain.start.kind}') rotates '${pivot.sam}' and its website `
      + `publishes '${site.reseed.username}'`);
    if (site.reseed.username !== ir.foothold_credential.sam) disagreements.push(i);
  }
  assert.ok(disagreements.length >= 8,
    `only ${disagreements.length} of ${SWEEP_RUN_IDS.length} clients publish an account other than `
    + 'the foothold — this sweep no longer covers the case the defect was, so it would pass either '
    + 'way. Widen the run ids until the entry rotation is represented again');
});

test('and the domain it carries is an FQDN that names a real principal, never a short name', () => {
  // site.reseed.domain is `bindNetbios` — CLINIC, not clinic.local — because
  // that is what the settings page prints. Set-ADAccountPassword -Server and
  // PrincipalContext('Domain', …) both want DNS, so a short name is a credential
  // nothing can set and nothing can validate, on every lane at once.
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir, site } = sweepClient(i);
    const pivot = sweepReseed(i).pivot;

    assert.ok(pivot.domain.includes('.'),
      `client ${i} carries '${pivot.domain}', which is a single label`);
    assert.notStrictEqual(pivot.domain, site.reseed.domain,
      `client ${i} took the NetBIOS short name '${site.reseed.domain}' as its DNS domain`);
    assert.strictEqual(pivot.netbios, site.reseed.domain,
      'the short name belongs in its own field, not thrown away');

    // The FQDN is a fact about the PRINCIPAL, so it has to be the domain the
    // roster creates that account in — which is not the forest root on a
    // multi-domain client.
    const roster = ir.principals.users.find((u) => u.sam === pivot.sam);
    assert.ok(roster, `client ${i}: '${pivot.sam}' is not on the compiled roster at all`);
    assert.strictEqual(pivot.domain, roster.domain,
      `client ${i}: '${pivot.sam}' is created in ${roster.domain} and the spec says ${pivot.domain}`);
    assert.ok(ir.domains.some((d) => d.fqdn === pivot.domain),
      `client ${i}: ${pivot.domain} is not a domain this forest builds`);
  }
});

test('every client carries the plants the bake really installed, or the deploy is refused', () => {
  // A descriptor that does not match the bytes cc_web wrote is a lane that fails
  // its credential phase on a path nobody can explain from the spec — or worse,
  // rewrites a file nothing reads and reports success.
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { site } = sweepClient(i);
    const pivot = sweepReseed(i).pivot;
    assert.deepStrictEqual(pivot.site.plants, site.reseed.plants,
      `client ${i}: the spec's plants are not the ones the site generator emitted`);
    assert.ok(pivot.site.plants.length >= 2, `client ${i} publishes in fewer than two places`);
  }
});

test('a pivot domain that is not one this forest builds is refused, not sent to a DC', () => {
  // The mechanical form of the short-name rule. A single label is accepted by
  // AD_DOMAIN_RE's character class and by every string check on the way down, so
  // it reaches Set-ADAccountPassword and fails there — on every lane in the
  // section at once, after the staged rewrites are already on the web box.
  // Driven on the AD-only shape, where the account to rotate is the foothold and
  // does not move when the roster is edited — so this test changes exactly one
  // thing and sees exactly one refusal.
  const { ir, bake } = sweepClient(2);
  const adOnly = { ...bake, verify_report: null, spec: { ...bake.spec, cc_web: { enabled: false } } };

  const shortName = JSON.parse(JSON.stringify(ir));
  shortName.principals.users.find((u) => u.sam === ir.foothold_credential.sam).domain = 'SWEEP';
  assert.throws(
    () => router.reseedBlockForBake({
      spec: {}, bake: adOnly, ir: shortName, foothold: shortName.foothold_credential,
    }),
    (err) => err.code === 'BAKE_PIVOT_DOMAIN_UNRESOLVED' && /DNS domain/.test(err.message));

  // …and an account the roster does not create at all is the same refusal, for
  // the same reason: nothing names a domain to reset it in.
  const orphan = JSON.parse(JSON.stringify(ir));
  orphan.principals.users = orphan.principals.users.filter(
    (u) => u.sam !== ir.foothold_credential.sam);
  assert.throws(
    () => router.reseedBlockForBake({
      spec: {}, bake: adOnly, ir: orphan, foothold: orphan.foothold_credential,
    }),
    (err) => err.code === 'BAKE_PIVOT_DOMAIN_UNRESOLVED' && /creates no such user/.test(err.message));
});

test('a bake whose website moved under the descriptor is refused, not shipped', () => {
  // The re-derivation is a SECOND derivation of one fact, so it is checked
  // against the only witness of the first: the staging lane's own web report.
  const { ir, bake } = sweepClient(0);
  const moved = {
    ...bake,
    verify_report: { cc_web: { ...bake.verify_report.cc_web, pivot_path: '/var/www/cc-web/config/somewhere-else.ini' } },
  };
  assert.throws(
    () => router.reseedBlockForBake({ spec: {}, bake: moved, ir, foothold: ir.foothold_credential }),
    (err) => err.code === 'BAKE_SITE_RESEED_DRIFT' && /Re-bake this client/.test(err.message),
    'a bake whose installed pivot path disagrees with the re-derived one was deployed anyway');

  const relabelled = {
    ...bake,
    verify_report: { cc_web: { ...bake.verify_report.cc_web, pivot_account: 'SWEEP\\somebody.else' } },
  };
  assert.throws(
    () => router.reseedBlockForBake({ spec: {}, bake: relabelled, ir, foothold: ir.foothold_credential }),
    (err) => err.code === 'BAKE_SITE_RESEED_DRIFT',
    'a bake that published a different account than the one re-derived was deployed anyway');
});

// ── (c3) the credentials a reseed must NEVER rotate ─────────────────────────

test('an exercise-bearing credential is named as FIXED, with the declaration that fixed it', () => {
  // THE SUBTLE HALF. Rotating a password is wrong when the password's weakness
  // IS the exercise: `Qwerty12345` on an AS-REP-roastable account is drawn from
  // CRACKABLE_PASSWORDS precisely so it falls to an offline crack, and a
  // password_equals_samaccountname entry is only an entry while password ==
  // username. Turning either into a 20-character CSPRNG value reports
  // `credential: ok` and leaves a chain nobody can walk.
  //
  // Read off the DESIGNER'S declarations (planted_at.format, edge_type), never
  // inferred from the string.
  const covered = new Set();
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir } = sweepClient(i);
    const block = sweepReseed(i);
    const entryKind = ir.chain.start.kind;
    const format = ir.foothold_credential.planted_at.format;
    const byName = new Map(block.fixed.map((f) => [f.sam, f]));

    if (Object.prototype.hasOwnProperty.call(router.FIXED_ENTRY_FORMATS, format)) {
      covered.add(entryKind);
      const entry = byName.get(ir.foothold_credential.sam);
      assert.ok(entry,
        `client ${i} (entry '${entryKind}', planted '${format}') does not name its own foothold as `
        + 'a credential that must stay fixed — an operator reading the reseed report cannot tell '
        + '"deliberately not rotated" from "forgotten"');
      assert.match(entry.technique, new RegExp(entryKind.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
        'the reason does not name the declaration it came from');
      assert.strictEqual(entry.domain, ir.principals.users.find((u) => u.sam === entry.sam).domain);
      // AND IT IS NOT THE ONE ROTATED. This is the assertion the old overlay
      // failed on 18 clients in 24.
      assert.notStrictEqual(block.pivot.sam, entry.sam,
        `client ${i} would rotate '${entry.sam}', whose password IS the exercise`);
    }

    // Every kerberoast edge's target too: its password is a wordlist value by
    // construction, and the student is meant to crack it.
    for (const edge of ir.chain.edges.concat(ir.chain.decoys || [])) {
      if (edge.edge_type !== 'kerberoast') continue;
      covered.add('kerberoast_edge');
      assert.ok(byName.has(edge.to),
        `client ${i}: the roasted account '${edge.to}' is not named as fixed`);
      assert.notStrictEqual(block.pivot.sam, edge.to);
    }
  }
  // The sweep has to have MET the cases it claims to defend.
  for (const kind of ['asrep', 'user_equals_password', 'open_share', 'anonymous_rpc']) {
    assert.ok(covered.has(kind),
      `no client in this sweep had a '${kind}' entry, so the rule was never exercised for it`);
  }
  assert.ok(covered.has('kerberoast_edge'), 'no client in this sweep carried a kerberoast edge');
});

test('the AS-REP password itself survives: the value that must crack is never rotated', () => {
  // Named against the wordlist the designer draws from, so a change that started
  // minting AS-REP passwords out of a CSPRNG would fail HERE rather than on a
  // student's `hashcat` run.
  const chainMod = require(path.join(CIAB, 'utils', 'goad-attack-chain.js'));
  let checked = 0;
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir } = sweepClient(i);
    if (ir.foothold_credential.planted_at.format !== 'asrep_roastable') continue;
    checked += 1;
    const cred = ir.foothold_credential;
    assert.ok(chainMod.CRACKABLE_PASSWORDS.includes(cred.password),
      `${cred.sam}'s AS-REP password is not from the wordlist the exercise depends on`);
    const block = sweepReseed(i);
    assert.notStrictEqual(block.pivot.sam, cred.sam);
    const entry = block.fixed.find((f) => f.sam === cred.sam);
    assert.match(entry.why, /crackable wordlist/);
    assert.ok(block.uniqueness.baked.some((b) => b.includes(cred.sam)),
      'the plan does not say, in words, that this credential is identical across the section');
  }
  assert.ok(checked >= 2, `only ${checked} AS-REP clients in the sweep`);
});

test('when the published account IS the exercise, the plan refuses to rotate and SAYS SO', () => {
  // The guard, driven on a real configuration: an AD-ONLY bake (spec.cc_web
  // .enabled false). There is no website, so the account the reseed would rotate
  // falls back to the chain's own foothold — and on an AS-REP or a
  // password-equals-username client that is exactly the credential whose value
  // carries the exercise.
  let checked = 0;
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir, bake } = sweepClient(i);
    const format = ir.foothold_credential.planted_at.format;
    if (format !== 'asrep_roastable' && format !== 'password_equals_samaccountname') continue;
    checked += 1;

    const adOnly = { ...bake, verify_report: null, spec: { ...bake.spec, cc_web: { enabled: false } } };
    const block = router.reseedBlockForBake({
      spec: {}, bake: adOnly, ir, foothold: ir.foothold_credential,
    });

    assert.strictEqual(block.pivot.sam, ir.foothold_credential.sam);
    assert.strictEqual(block.pivot.rotate, false,
      `client ${i} would rotate ${block.pivot.sam}, whose password IS the technique`);
    assert.ok(block.pivot.fixed_reason && block.pivot.fixed_reason.length > 40,
      'rotate:false with no reason is indistinguishable from a forgotten credential');
    assert.match(block.pivot.fixed_reason, /crackable wordlist|IS the sAMAccountName/);
    assert.strictEqual(block.pivot.site, undefined, 'an AD-only bake has no site to rewrite');

    // AND THE UNIQUENESS GUARANTEE IS NOT QUIETLY DROPPED.
    assert.ok(block.uniqueness.per_lane.some((v) => /flag/.test(v)));
    assert.ok(block.uniqueness.per_lane.some((v) => /seeded record identifiers/.test(v)));
    assert.ok(!block.uniqueness.per_lane.some((v) => /pivot credential/.test(v)),
      'the plan claims per-lane uniqueness for a credential it is not rotating');
    assert.ok(block.uniqueness.baked.some((v) => v.includes(block.pivot.sam)
      && /NOT rotated per lane/.test(v)),
    `the plan does not state where uniqueness is NOT provided: ${JSON.stringify(block.uniqueness.baked)}`);
  }
  assert.ok(checked >= 4, `only ${checked} clients in the sweep hit this shape`);
});

test('a plant format nobody has classified is treated as fixed, not rotated on a guess', () => {
  // The fail-safe. The two failure modes are not symmetric: not rotating loses
  // per-lane uniqueness LOUDLY (it is named in the plan and on the lane row),
  // while rotating a credential whose publishers we cannot enumerate breaks the
  // exercise silently.
  const { ir } = sweepClient(1);
  const future = JSON.parse(JSON.stringify(ir));
  future.foothold_credential.planted_at.format = 'browser_saved_password';

  const fixed = router.fixedCredentialsFromIr(future);
  const entry = fixed.find((f) => f.sam === future.foothold_credential.sam);
  assert.ok(entry, 'an unclassified plant format was rotated on a guess');
  assert.match(entry.why, /browser_saved_password/);
  assert.match(entry.why, /FIXED_ENTRY_FORMATS/,
    'the message does not say where to classify it, so the next reader guesses too');
});

test('nothing on the reseed block is a secret — the deploy spec is not the answer key', () => {
  // The spec is written to crucible_challenge.spec and re-read by add-lanes and
  // retry-lane for the life of the engagement. What C1c puts on it grew a lot —
  // an account name, a domain, a docroot, six plant descriptors with the prose
  // that surrounds a leaked password — so the rule that none of it is a
  // CREDENTIAL is checked against the compiler's own list of what counts, rather
  // than against a guess about which fields might carry one.
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir } = sweepClient(i);
    const serialised = JSON.stringify(sweepReseed(i));
    // ONE EXEMPTION, AND IT IS NOT A LOOPHOLE: a password_equals_samaccountname
    // credential's password IS an account name, and the spec has to be able to
    // name that account to say it must not be rotated. There is nothing to
    // withhold — the chain's own `how` for that entry is "the staff list the web
    // app publishes is the spray list".
    const isAccountName = new Set(ir.principals.users.map((u) => u.sam));
    for (const secret of realContent.declaredSecrets(ir)) {
      if (isAccountName.has(secret)) continue;
      assert.ok(!serialised.includes(secret),
        `client ${i}: the deploy spec carries the password ${JSON.stringify(secret)} in clear — a `
        + 'row an instructor, and every later add-lanes, reads');
    }
  }
});

test('a web-side plant IS rotated — the rule has a boundary and it is the right one', () => {
  // The other direction, and it matters as much: a credential whose every copy
  // is a file on the web box is exactly what lane-reseed rewrites, so treating
  // it as fixed would hand a whole cohort one password for no reason.
  let checked = 0;
  for (let i = 0; i < SWEEP_RUN_IDS.length; i += 1) {
    const { ir, site } = sweepClient(i);
    const format = ir.foothold_credential.planted_at.format;
    if (!realContent.SITE_WEB_PLANT_FORMATS.includes(format)) continue;
    checked += 1;
    const block = sweepReseed(i);
    assert.strictEqual(block.pivot.sam, ir.foothold_credential.sam,
      'the site publishes the foothold on a web-side plant, so that is the account to rotate');
    assert.strictEqual(block.pivot.rotate, true,
      `client ${i} refuses to rotate a credential that exists only in files on the web box`);
    assert.ok(!block.fixed.some((f) => f.sam === ir.foothold_credential.sam));
    assert.ok(block.uniqueness.per_lane.some((v) => v.includes(block.pivot.sam)));
    // The mirrored-description variant publishes in one MORE place than the
    // plain one, and the site plan says which copies it cannot reach.
    if (format === 'ad_description_mirrored_on_web') {
      assert.ok(site.reseed.unrotatable.length > 0,
        'the AD description keeps the baked value and nothing said so');
    }
  }
  assert.ok(checked >= 6, `only ${checked} web-plant clients in the sweep`);
});

test('a bake with no foothold credential is refused rather than shipped', async () => {
  // The catastrophic silent success: every student in the section holding one
  // password, one paste into the group chat, cohort finished.
  reset();
  const noFoothold = compiled();
  delete noFoothold.ir.foothold_credential;
  state.compile = noFoothold;
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_NO_PIVOT_CREDENTIAL');
  assert.strictEqual(state.provisioned.length, 0);
});

test('the lane resolver learns the forest — and an EXTERNAL engagement still does not', async () => {
  // buildSpecDns has carried an AD branch since it was written and it had never
  // once fired: it is keyed on spec.goad.domain, its own comment says "a later
  // wave stamps spec.goad", and nothing ever did. So every AD tool a student is
  // taught to invoke by NAME — `nxc smb dc01.clinic.local`, `bloodhound-python
  // -d clinic.local` — failed at resolution on a lane whose directory was
  // sitting right there.
  reset();
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();
  await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  await drain();

  assert.strictEqual(deployedChallenge().spec.dns.ad_domain, 'clinic.local',
    'the gateway publishes a conditional forwarder for the forest the bake built');

  // …and the rule that WITHHOLDS it is untouched, because enumerating AD through
  // the compromised pivot is the whole middle of an external engagement.
  reset();
  state.engagements.set('external_blackbox', {
    ...state.engagements.get('default'),
    engagement_type: 'external_blackbox',
  });
  state.reservations.set('external_blackbox', state.reservations.get('default'));
  await bakeAndSignOff();
  state.deploySpec = adDeploySpec();
  await call('POST', '/deploy', {
    body: {
      profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false },
      engagement_type: 'external_blackbox',
    },
  });
  await drain();

  const dns = deployedChallenge().spec.dns;
  assert.ok(!dns || dns.ad_domain === undefined,
    'publishing the forest lane-wide on an external engagement deletes the exercise');
});

test('a bake from before the pin existed is refused by name, not at the first clone', async () => {
  // Every bake row written before this route emitted spec.goad.fixed_subnet.
  // Stamping `prebaked` on one of those reaches applyPrebakedFixedSubnet, which
  // throws OUTSIDE the deployer's best-effort GOAD catch — so the whole lane
  // deploy dies with a message about a spec nobody hand-wrote. The refusal has
  // to name the bake, because re-baking is the only thing that fixes it.
  reset();
  const row = await bakeAndSignOff();
  delete row.spec.goad.fixed_subnet;
  state.deploySpec = adDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_NO_FIXED_SUBNET');
  assert.match(res.body.error, /Re-bake this client/);
  assert.strictEqual(state.provisioned.length, 0);

  // Half a pin is refused too: applyPrebakedFixedSubnet only checks `int`, so a
  // spec pinning that alone leaves the EXTERNAL segment per-lane — and on a v3
  // lane that is where Kali, the DMZ pivot and every published console live.
  reset();
  const half = await bakeAndSignOff();
  half.spec.goad.fixed_subnet = { int: STAGING_INT };
  state.deploySpec = adDeploySpec();
  const partial = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(partial.body.code, 'BAKE_NO_FIXED_SUBNET');
});

test('a forest machine the bake never captured is refused too — both directions', async () => {
  // BAKE_GOLDEN_UNMATCHED is golden → spec. This is spec → golden, and it is the
  // quieter of the two: the machine clones the stock catalog image, has no
  // account in the baked directory, and the pre-baked heal retries its secure
  // channel six times, warns, and gives up in a log nobody reads.
  reset();
  await bakeAndSignOff({
    'NWC-DC01': { name: 'NWC-DC01', vmid: 700001, node: 'node-3' },
    'web-01': { name: 'web-01', vmid: 700003, node: 'node-3' },
  });
  state.deploySpec = adDeploySpec();          // still selects NWC-SRV02

  const res = await call('POST', '/deploy', {
    body: { profile_id: PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_GOLDEN_MISSING');
  assert.match(res.body.error, /NWC-SRV02/);
  assert.strictEqual(state.provisioned.length, 0);
});

// ───────────────────────────────────────────────────────────────────────────
// 9. B1 — a bake is made of machines, and a deploy can find them
// ───────────────────────────────────────────────────────────────────────────
/*
 * TWO LINKED DEFECTS, DRIVEN END TO END ON THE SHAPE THE SITE ACTUALLY SHIPS.
 *
 *   the bake had no machines   The spec was { subnet_scheme, goad, vxlan_block }
 *       and nothing else. bake-staging.stagingChallenge hands that STRAIGHT to
 *       deployChallengeLanes, so the staging lane came up holding a gateway and
 *       a Kali, the chain ran against an empty inventory, and captureGolden had
 *       nothing to convert. The deployer would not even have got that far: it
 *       calls resolveGoadLab on spec.goad.lab before the first clone, and the
 *       bare compiler IR fails assertValidLabDef on `forestRoot`.
 *
 *   the deploy could not find them   deployLabDefFromBake asked isGoadManagedVm
 *       "is this machine in the forest", and that predicate exempts anything
 *       carrying an explicit nics[] segment — which profile-to-spec stamps on
 *       EVERY machine of a v3 lane with a dual-homed DMZ host, i.e. on every
 *       CIAB profile lane. Every deploy of a baked client refused with
 *       BAKE_LAB_NO_MEMBERS, naming an asset selection that was never wrong.
 *
 * The fixture below is the default shape and nothing else: DEFAULT_SUBNET_SCHEME
 * ('v3'), a web asset that becomes the dual-homed pivot, and the REAL compiler
 * and REAL synthesizer on the two ends of the loop.
 */

/** The template catalog the synthesizer resolves against. */
const REGISTER_CATALOG = [
  { id: 1, os_family: 'windows_server', os_version: '2019', os_name: 'WinSrv2019',
    template_vmid: 1004, node: 'catalog-node', role_hints: [], is_active: true, preferred: true },
  { id: 2, os_family: 'linux', os_version: '12', os_name: 'Debian13-web',
    template_vmid: 1005, node: 'catalog-node', role_hints: ['web'], is_active: true, preferred: true },
];

/** The profile object both producers read, in the layout production hands them. */
function registerProfile() {
  return {
    ...PROFILES[REGISTER_PROFILE_ID],
    assets: REGISTER_ASSETS.map((a) => ({ ...a })),
    json_data: REGISTER_JSON,
  };
}

/**
 * The deploy spec a real /deploy would synthesize for that client.
 *
 * The REAL synthesizer, at the REAL default scheme — this is what makes the
 * fixture the default topology rather than a hand-built approximation of one.
 * Its output reaches the router through the same seam every other test uses.
 */
function registerDeploySpec() {
  const { spec } = realSpec.synthesizeSpecFromProfile({
    profile: registerProfile(),
    assetSelection: null,
    vmTemplateCatalog: REGISTER_CATALOG,
    vulnScriptCatalog: [],
    vulnApp: { install_script: 'install.sh', delivery_mode: 'docker', target_hostname: 'WEB-01' },
    options: { subnetScheme: realSpec.DEFAULT_SUBNET_SCHEME },
  });
  return spec;
}

/** Bake this client for real, then record the templates capture would have made. */
async function bakeRegisterAndSignOff(overGolden) {
  state.real = true;
  await call('POST', `/profiles/${REGISTER_PROFILE_ID}/bake`);
  await settle();
  const row = db.rows.find((r) => r.profile_id === REGISTER_PROFILE_ID);
  assert.ok(row, 'the bake row has to exist for anything below to mean anything');
  // captureGolden keys golden_vmids by the STAGING LANE's machine names, and a
  // staging lane's machines are spec.vms — so the golden set is DERIVED from the
  // bake's own spec here rather than typed out, because that coupling is exactly
  // what the correspondence tests below are about.
  const golden = {};
  row.spec.vms.forEach((vm, i) => {
    golden[vm.name] = { name: vm.name, vmid: 700100 + i, node: 'node-7' };
  });
  row.status = 'ready';
  row.error = null;
  row.gate_solvable = true;
  row.gate_paper = true;
  row.gate_no_unintended = true;
  row.gates_approved_at = 'approved';
  row.golden_vmids = overGolden || golden;
  return row;
}

const goadDeployReal = require(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'));

/**
 * A bake's machines, split the way every consumer downstream splits them: the
 * FOREST is what spec.goad.lab names, and everything else on spec.vms is a
 * machine the staging lane stands up without the GOAD layer owning it — today
 * that is exactly one, the company web host (X1).
 */
function splitBakeVms(spec) {
  const forest = new Set((spec.goad.lab.hosts || []).map((h) => String(h.hostname).toLowerCase()));
  const inForest = (vm) => forest.has(String(vm.name).toLowerCase());
  return { forest: spec.vms.filter(inForest), other: spec.vms.filter((vm) => !inForest(vm)) };
}

// ── (a) the bake carries the machines its staging lane clones ───────────────

test('a bake spec carries vms, and they are the lab own forest hosts', async () => {
  reset();
  state.real = true;
  const res = await call('POST', `/profiles/${REGISTER_PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await settle();

  const spec = db.rows[0].spec;
  assert.ok(Array.isArray(spec.vms) && spec.vms.length > 0,
    'without spec.vms the staging lane deploys a gateway and a Kali, the chain runs against an '
    + 'empty inventory, and capture has nothing to convert into golden templates');

  // ONE MACHINE PER COMPILED HOST, with the same name and the same octet. The
  // octet is not a preference: providers/proxmox/inventory addresses each host
  // at exactly it, and the chain runs over that file.
  //
  // Asserted over the FOREST half of spec.vms, because the list also carries the
  // company web host now (X1, section (d) below) — a machine the compiled forest
  // deliberately never contained.
  const hosts = spec.goad.lab.hosts;
  const { forest } = splitBakeVms(spec);
  assert.deepStrictEqual(forest.map((v) => v.name), hosts.map((h) => h.hostname));
  assert.deepStrictEqual(forest.map((v) => v.ipOctet), hosts.map((h) => h.ipOctet));
  for (const vm of forest) {
    assert.strictEqual(vm.type, 'qemu');
    assert.ok(Number.isInteger(vm.template_vmid) && vm.template_vmid > 0,
      `${vm.name} has no template to clone from`);
    assert.strictEqual(vm.nics, undefined,
      'no explicit segment: the GOAD layer places a lab host on the internal segment itself, and '
      + 'an explicit one is read downstream as "placed by hand, not a lab host"');
  }
  assert.strictEqual(new Set(spec.vms.map((v) => v.vm_offset)).size, spec.vms.length,
    'two machines sharing a vm_offset clone to one VMID and the second deploy fails');

  // …and they are the CLIENT's machines, not names minted off the company.
  assert.deepStrictEqual(forest.map((v) => v.name), ['DC-01', 'DC-02', 'FS-01'],
    'the asset register the student reads names these three Windows servers; a forest called '
    + 'anything else corresponds to no document and to no deploy');
});

test('the staging lane own deployer accepts that spec — the gate a bake used to die at', async () => {
  // THE REAL ENTRY POINT. deployLaneVms calls prepareGoadMacs before a single
  // clone, and prepareGoadMacs runs resolveGoadLab -> assertValidLabDef and then
  // assertGoadRoster. The bare compiler IR fails the first on `forestRoot`, so
  // every bake started through this route died in its provision phase with a
  // message about a spec nobody hand-wrote.
  reset();
  state.real = true;
  await call('POST', `/profiles/${REGISTER_PROFILE_ID}/bake`);
  await settle();
  const spec = db.rows[0].spec;

  const { labDef, fromSpec } = goadDeployReal.resolveGoadLab(spec);
  assert.strictEqual(fromSpec, true, 'the bake own lab, not a built-in GOAD one');
  assert.ok(labDef.forestRoot && labDef.forestRoot.includes('.'), String(labDef.forestRoot));
  assert.deepStrictEqual(labDef.vms.map((v) => v.role), ['dc', 'dc', 'member'],
    'a controller and a member are provisioned and healed differently, and a role the deployer '
    + 'does not recognise is a machine it silently skips');

  const macs = goadDeployReal.prepareGoadMacs(spec, STAGING_VXLAN, STAGING_INT);
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC-01', 'DC-02', 'FS-01']);
  assert.strictEqual(macs['WEB-01'], undefined,
    'the company web host is on this same spec (X1) and is NOT a lab host: it carries an explicit '
    + 'two-segment nics[], which is what isGoadManagedVm reads as "placed by hand" — so it is '
    + 'exempt from the roster instead of failing it as a stray');
  assert.strictEqual(macs['DC-01'].static_ip, `${STAGING_INT}.${spec.vms[0].ipOctet}`,
    'the address the emitted ansible inventory reaches it at — a machine anywhere else is '
    + 'unreachable to every playbook in the chain');
  assert.strictEqual(macs['DC-01'].nic_model, 'e1000',
    'a stock Windows guest has no virtio driver, never DHCPs, and comes up unreachable');

  // And the object bake-staging really hands the deployer carries them: the
  // staging challenge is the bake's spec plus a key, a name and the block, so a
  // spec without machines is a lane without machines, full stop.
  const bakeStaging = require(path.join(CIAB, 'utils', 'bake-staging.js'));
  const challenge = bakeStaging.stagingChallenge(db.rows[0], spec,
    { start: STAGING_VXLAN, end: STAGING_VXLAN });
  assert.deepStrictEqual(challenge.spec.vms.map((v) => v.name),
    ['DC-01', 'DC-02', 'FS-01', 'WEB-01'],
    'the forest AND the company web host: the provision phase installs the site on the last one '
    + 'BEFORE the capture, so a staging lane without it has nowhere to put the website');
  assert.strictEqual(challenge.subnet_scheme, 'v3');

  // …and the capture phase would name its golden templates after exactly those
  // machines. This is the link the whole B1 correspondence hangs on: capture
  // reads the LANE's machine list, which is spec.vms, and keys golden_vmids by
  // name — so the names the bake emits here are the names a deploy has to match.
  const targets = bakeStaging.captureTargets({
    bake: db.rows[0],
    lane: {
      vxlan_id: STAGING_VXLAN,
      config: {
        node: 'node-7',
        gateway_vm_id: 900001,
        attack_box_vm_id: 900002,
        vms: challenge.spec.vms.map((vm, i) => ({
          name: vm.name, vm_id: 800100 + i, node: 'node-7', type: 'qemu',
        })).concat([{ name: 'Kali', vm_id: 900002, node: 'node-7', type: 'qemu' }]),
      },
    },
  });
  assert.deepStrictEqual(targets.map((t) => t.name), ['DC-01', 'DC-02', 'FS-01', 'WEB-01'],
    'the golden templates are named after the staging machines, and the attack box is excluded — '
    + 'the web host is IN, because the golden image is the only copy of the company website a '
    + 'student lane ever gets (the site is installed before capture, never after it)');
});

// ── (b) the deploy finds them on the DEFAULT topology ───────────────────────

test('a DEFAULT v3 deploy resolves every forest machine and leaves the web host out', async () => {
  reset();
  await bakeRegisterAndSignOff();
  const synthesized = registerDeploySpec();
  state.deploySpec = synthesized;

  // The fixture is only worth anything if it really is the shape that broke:
  // every machine carrying an explicit segment, the web host dual-homed.
  assert.ok(synthesized.vms.every((v) => Array.isArray(v.nics) && v.nics.length > 0),
    'applyV3Topology stamps a segment on EVERY machine once the lane has a dual-homed DMZ host — '
    + 'if that ever stops being true, the regression this test guards is no longer reachable');
  assert.strictEqual(synthesized.vms.find((v) => v.name === 'WEB-01').nics.length, 2);

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await drain();

  const spec = deployedChallenge().spec;
  assert.strictEqual(spec.goad.prebaked, true,
    'the whole point: clone the golden images instead of standing a controller and re-running the '
    + 'ninety-minute chain on every student lane');

  assert.deepStrictEqual(
    spec.goad.lab.vms.map((v) => [v.name, v.role]),
    [['DC-01', 'dc'], ['DC-02', 'dc'], ['FS-01', 'member']],
    'every Windows forest machine is IN even though v3 gave it a nics[] segment');
  assert.ok(!spec.goad.lab.vms.some((v) => v.name === 'WEB-01'),
    'and the Linux web host stays OUT — deployPrebakedGoadLane skips role linux, so a Linux member '
    + 'in this list would be a machine nothing heals');

  // The octet comes from the DEPLOY spec, because the scan report and the asset
  // register are written from it and a student nmaps what they say.
  const byName = Object.fromEntries(spec.vms.map((v) => [v.name, v]));
  for (const v of spec.goad.lab.vms) {
    assert.strictEqual(v.ipOctet, byName[v.name].ipOctet, `${v.name}: paper address vs lane address`);
    assert.strictEqual(v.template_vmid, byName[v.name].template_vmid, `${v.name}: golden template`);
    assert.ok(v.template_vmid >= 700100, `${v.name} still clones the catalog image`);
  }

  // The inferred placement is off the forest machines and untouched everywhere
  // else: the DMZ bridge is authored, and it is what the whole v3 layout is for.
  for (const name of ['DC-01', 'DC-02', 'FS-01']) {
    assert.strictEqual(byName[name].nics, undefined, `${name} kept an inferred nics[]`);
  }
  assert.strictEqual(byName['WEB-01'].nics.length, 2, 'the pivot is still dual-homed');
});

test('and the deployer agrees — prepareGoadMacs resolves all three, exempting the pivot', async () => {
  // Again the REAL gate, this time on the deploy side. assertGoadRoster requires
  // the lab roster and the goad-managed spec VMs to be the same set in BOTH
  // directions; before this change the roster was empty and the deploy never
  // reached here at all.
  reset();
  await bakeRegisterAndSignOff();
  state.deploySpec = registerDeploySpec();
  await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  await drain();

  const spec = deployedChallenge().spec;
  const macs = goadDeployReal.prepareGoadMacs(spec, 12345, STAGING_INT);
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC-01', 'DC-02', 'FS-01'],
    'every forest machine gets a deterministic MAC and a DHCP reservation; without one it takes a '
    + 'pool lease, the pre-baked cloud-init strip never runs, its baked hostname is overwritten and '
    + 'its secure channel breaks — all of it silently');
  assert.strictEqual(macs['WEB-01'], undefined, 'the dual-homed pivot is not a lab host');
  assert.strictEqual(macs['DC-01'].static_ip, `${STAGING_INT}.${spec.vms[0].ipOctet}`);
});

// ── (c) the two refusals: they fire, and they stay quiet ────────────────────

test('BAKE_LAB_NO_MEMBERS fires when the bake forest names nothing this deploy has', async () => {
  // The historical shape: a bake whose hostnames were minted off the company
  // name, deployed against a spec whose machines come from the asset register.
  // The golden set is left matching the deploy machines so that the ROSTER
  // refusal is the one under test — in the wild both fire, and the golden half
  // is two tests below.
  reset();
  const row = await bakeRegisterAndSignOff();
  const minted = ['HARBOR-DC01', 'HARBOR-DC02', 'HARBOR-SRV02'];
  row.spec.goad.lab.hosts = row.spec.goad.lab.hosts.map((h, i) => ({ ...h, hostname: minted[i] }));
  row.spec.goad.lab.vms = row.spec.goad.lab.vms.map((v, i) => ({ ...v, name: minted[i] }));
  state.deploySpec = registerDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_LAB_NO_MEMBERS');
  assert.match(res.body.error, /HARBOR-DC01/, 'the refusal prints the forest it was looking for');
  assert.match(res.body.error, /DC-01/, 'and the machines this deploy actually has');
  assert.strictEqual(state.provisioned.length, 0,
    'cloning golden templates onto a lane with no directory in it is an exercise with no forest');
});

test('BAKE_LAB_NO_MEMBERS does NOT fire on the default happy path', async () => {
  // The half that matters: this refusal had zero coverage, and EVERY deploy of a
  // baked client on the default topology reached it.
  reset();
  await bakeRegisterAndSignOff();
  state.deploySpec = registerDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await drain();
  assert.strictEqual(deployedChallenge().spec.goad.lab.vms.length, 3);
});

test('BAKE_GOLDEN_UNMATCHED fires for a template no machine can be cloned onto', async () => {
  // The other side of the same correspondence, and the one a hostname mismatch
  // reaches first: the bake captured HARBOR-DC01 and this deploy has DC-01, so
  // the forest holds an account, SPNs and DNS records for a machine the lane
  // will not have — and the lane would still report active.
  reset();
  await bakeRegisterAndSignOff({
    'HARBOR-DC01': { name: 'HARBOR-DC01', vmid: 700100, node: 'node-7' },
    'HARBOR-DC02': { name: 'HARBOR-DC02', vmid: 700101, node: 'node-7' },
    'HARBOR-SRV02': { name: 'HARBOR-SRV02', vmid: 700102, node: 'node-7' },
  });
  state.deploySpec = registerDeploySpec();

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_GOLDEN_UNMATCHED');
  assert.match(res.body.error, /HARBOR-DC01/);
  assert.strictEqual(state.provisioned.length, 0);
});

test('BAKE_GOLDEN_UNMATCHED does NOT fire when the bake and the register agree', async () => {
  // The correspondence as one assertion: the names capture keys the golden
  // templates on ARE the names the synthesizer gives the deploy machines.
  reset();
  const row = await bakeRegisterAndSignOff();
  const synthesized = registerDeploySpec();
  state.deploySpec = synthesized;

  const golden = Object.keys(row.golden_vmids).map((n) => n.toLowerCase()).sort();
  const deployed = synthesized.vms.map((v) => v.name.toLowerCase()).sort();
  assert.ok(golden.length > 0 && golden.every((g) => deployed.includes(g)),
    `every golden template must have a machine to clone onto: ${golden} vs ${deployed}`);

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  // Drained before the test ends: /deploy answers 202 and finishes the hand-off
  // on a later tick, and a deploy still in flight would push into the NEXT
  // test's state.provisioned after its reset() — which reads exactly like the
  // refusal below failing to refuse.
  await drain();
});

test('a forest machine placed somewhere the lab did not put it is refused, not rewritten', async () => {
  // Dropping the inferred nics[] deletes a claim about WHO decided the
  // placement; it does not change the placement. A machine whose authored
  // placement genuinely disagrees with the forest is a different fact: a
  // dual-homed lab host gets no pinned MAC at all (the deployer builds multi-NIC
  // configs inline), so it would come up on a pool lease while the baked forest
  // names a different address.
  reset();
  await bakeRegisterAndSignOff();
  const spec = registerDeploySpec();
  spec.vms.find((v) => v.name === 'FS-01').nics = [{ segment: 'ext' }];
  state.deploySpec = spec;

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.body.code, 'BAKE_LAB_VM_MISPLACED');
  assert.match(res.body.error, /FS-01/);
  assert.strictEqual(state.provisioned.length, 0);

  // Same refusal for a forest machine declared a container: an LXC takes net1
  // with its template owning net0, so it could never carry the pinned MAC the
  // baked forest was addressed on — and the old predicate simply SKIPPED it,
  // which left its golden template unmatched and the reason unprinted.
  reset();
  await bakeRegisterAndSignOff();
  const asContainer = registerDeploySpec();
  asContainer.vms.find((v) => v.name === 'DC-01').type = 'lxc';
  state.deploySpec = asContainer;

  const lxc = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(lxc.body.code, 'BAKE_LAB_VM_MISPLACED');
  assert.match(lxc.body.error, /DC-01/);
  assert.strictEqual(state.provisioned.length, 0);
});


// ── (d) X1: the company web host, and the name both sides have to agree on ──
/*
 * THE DEFECT, STATED ONCE. bake-staging's provision phase installs this
 * client's website on the staging lane's dual-homed DMZ host, and it does that
 * BEFORE the capture, because the golden image is the only copy of that site a
 * student lane will ever get. A bake spec holding nothing but the Windows
 * forest gave it nowhere to go: resolveDmzHost found no dual-homed machine on
 * the lane and refused with BAKE_PROVISION_NO_DMZ_HOST — before the chain even
 * started. Every real bake died there.
 *
 * THE CORRESPONDENCE IS WHY THE WORK WAS DEFERRED RATHER THAN DONE. The capture
 * names this client's golden template after the STAGING machine, and a deploy
 * refuses a golden template none of its own machines match
 * (BAKE_GOLDEN_UNMATCHED) — ninety minutes after Bake was pressed, on a client
 * that then cannot be deployed at all. So the two sides have to spell this one
 * machine's name identically, and every assertion below compares the bake's
 * answer with the REAL synthesizer's rather than with a literal.
 */

/** The machine the REAL synthesizer puts in this client's DMZ on a deploy. */
function deployWebMachine() {
  const spec = registerDeploySpec();
  const name = realSpec.resolveDmzVm({
    subnetScheme: realSpec.DEFAULT_SUBNET_SCHEME,
    vms: spec.vms,
    vulnAppInstall: spec.vuln_app_install,
  });
  return spec.vms.find((vm) => vm.name === name) || null;
}

/** This client, baked for real, through the route. */
async function bakeRegisterSpec() {
  reset();
  state.real = true;
  const res = await call('POST', `/profiles/${REGISTER_PROFILE_ID}/bake`);
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await settle();
  return db.rows[0].spec;
}

/** The one machine on a spec that is on both segments. */
function dualHomed(spec) {
  return spec.vms.filter((vm) => Array.isArray(vm.nics) && vm.nics.length > 1);
}

test('the bake spec carries the company web host, dual-homed at .240', async () => {
  const spec = await bakeRegisterSpec();
  const bakeStaging = require(path.join(CIAB, 'utils', 'bake-staging.js'));
  const engagementModel = require(path.join(CIAB, 'utils', 'engagement-model.js'));

  const dual = dualHomed(spec);
  assert.strictEqual(dual.length, 1,
    'EXACTLY one dual-homed machine. The deployer defines a single dual-homed address (.240 on '
    + 'both segments), so a second one would be handed the first one\'s IP and the lane would come '
    + `up with a conflict on its most important host. Got: ${dual.map((v) => v.name).join(', ')}`);
  const [web] = dual;

  assert.deepStrictEqual(web.nics.map((n) => n.segment), ['ext', 'int'],
    'ext AND int: the pivot is the only path from the attacker\'s segment to the forest, which is '
    + 'what makes "reach AD through the web host" a fact about the network');
  // The octet is asserted against BOTH owners rather than against 240, because
  // the failure this guards is a copy of the number drifting — bake-staging
  // goes looking for the web host at CC_WEB_DMZ_OCTET and the deployer pins a
  // dual-homed guest at DUAL_HOMED_OCTET, and a spec that agrees with only one
  // of them is a site installed on an address nothing answers at.
  assert.strictEqual(web.ipOctet, bakeStaging.CC_WEB_DMZ_OCTET,
    'the address bake-staging connects to when it installs the site');
  assert.strictEqual(web.ipOctet, engagementModel.DUAL_HOMED_OCTET,
    'and the address the deployer actually pins a dual-homed guest at (ipconfig0/ipconfig1)');

  assert.strictEqual(web.template_vmid, deployWebMachine().template_vmid,
    'the same image a deploy of this client clones for this machine');
  assert.strictEqual(web.template_vmid, 1005,
    'which is the baked web template (Debian + Docker + Apache). Spelled once, inside '
    + 'profile-to-spec, and read back out of it here — this line is the reminder that a change to '
    + 'that constant has to be a change to the template on the node, not to this file');

  assert.strictEqual(web.os_family, 'linux');
  assert.strictEqual(web.type, 'qemu',
    'a container gets ONE card whatever it asks for, so a dual-homed LXC is a claim the deploy '
    + 'cannot honour');
  assert.deepStrictEqual(web.post_clone_scripts, [],
    'no vulnerable-service installers on the machine a golden image is taken from');
  assert.strictEqual(spec.vuln_app_install, undefined,
    'and NO per-lane app install on the staging lane: the site the golden image carries is the one '
    + 'bake-staging\'s cc_web phase writes, from the compiled lab, before the capture');

  assert.strictEqual(spec.vms[spec.vms.length - 1], web, 'appended after the forest');
  assert.strictEqual(new Set(spec.vms.map((v) => v.vm_offset)).size, spec.vms.length,
    'its own vm_offset: two machines sharing one clone to a single VMID');
});

test('and its NAME is the one the real synthesizer gives a deploy of the same client', async () => {
  const spec = await bakeRegisterSpec();
  const [web] = dualHomed(spec);
  const deployed = deployWebMachine();

  assert.ok(deployed,
    'the fixture is only worth anything if a deploy of this client really does put a machine in '
    + 'the DMZ — if that ever stops being true this whole correspondence is unreachable');
  assert.strictEqual(web.name, deployed.name,
    'THE WHOLE REASON THIS WAS DEFERRED: the capture keys this client\'s golden template on the '
    + 'BAKE\'s name for the machine, and the deploy refuses a golden template no machine of its '
    + 'own matches (BAKE_GOLDEN_UNMATCHED) — ninety minutes after Bake was pressed. Both names are '
    + 'produced by profile-to-spec, which is the only arrangement in which they cannot drift');
  assert.strictEqual(web.name, 'WEB-01',
    'and it is the CLIENT\'s own web server off the asset register — the machine the scan report, '
    + 'the brief and the topology diagram all print — rather than a name minted for the bake');
  assert.strictEqual(web.hostname, deployed.hostname);
  assert.strictEqual(web.ipOctet, deployed.ipOctet);
  assert.deepStrictEqual(web.nics, deployed.nics);
});

test('bake-staging.resolveDmzHost accepts that spec — the gate every real bake died at', async () => {
  const spec = await bakeRegisterSpec();
  const bakeStaging = require(path.join(CIAB, 'utils', 'bake-staging.js'));

  // THE REAL LANE SHAPE. The staging challenge IS this spec, so the lane's
  // recorded machine list is spec.vms plus the console the deployer appends.
  const laneFor = (vms) => ({
    vxlan_id: STAGING_VXLAN,
    config: {
      node: 'node-7',
      gateway_vm_id: 900001,
      attack_box_vm_id: 900002,
      lane_subnet_base: STAGING_EXT,
      vms: vms
        .map((vm, i) => ({ name: vm.name, vm_id: 800100 + i, node: 'node-7', type: 'qemu' }))
        .concat([{ name: 'Kali', vm_id: 900002, node: 'node-7', type: 'qemu' }]),
    },
  });

  const host = bakeStaging.resolveDmzHost({ spec, lane: laneFor(spec.vms) });
  assert.strictEqual(host.name, deployWebMachine().name,
    'the phase that installs the website finds the same machine the deploy calls its pivot');
  assert.strictEqual(host.ip, `${STAGING_EXT}.${bakeStaging.CC_WEB_DMZ_OCTET}`,
    'and it is reached on the lane\'s EXTERNAL base at .240 — the address the deployer pinned it '
    + 'to at clone time, which is nowhere on the lane row to be read off');
  assert.ok(Number.isInteger(host.vm_id) && host.vm_id > 0, 'a VMID capture can convert');

  // AND THE DEFECT IS STILL REACHABLE, which is what makes the assertion above
  // mean something: the bake spec as it was — the forest and nothing else.
  const forestOnly = { ...spec, vms: spec.vms.filter((vm) => vm.name !== host.name) };
  assert.throws(
    () => bakeStaging.resolveDmzHost({ spec: forestOnly, lane: laneFor(forestOnly.vms) }),
    (err) => err.code === 'BAKE_PROVISION_NO_DMZ_HOST',
    'a bake spec with no web host on it refuses in the provision phase, which is where every real '
    + 'bake stopped before this machine existed');
});

test('and the web host is NOT in the forest the bake built', async () => {
  const spec = await bakeRegisterSpec();
  const { forest, other } = splitBakeVms(spec);

  assert.deepStrictEqual(other.map((vm) => vm.name), ['WEB-01'],
    'exactly one machine on the staging lane that the compiled forest does not name');
  assert.deepStrictEqual(forest.map((vm) => vm.name), ['DC-01', 'DC-02', 'FS-01']);
  assert.ok(!spec.goad.lab.vms.some((v) => v.name === 'WEB-01'),
    'deployPrebakedGoadLane skips role \'linux\', so a Linux member inside the lab definition is a '
    + 'machine nothing heals and nothing restarts — while the lane reports active');
  assert.ok(!spec.goad.lab.hosts.some((h) => h.hostname === 'WEB-01'),
    'and the compiled forest never contained it: the synthesizer forces every web asset onto Linux '
    + 'and the compiler skips them');

  // The deployer agrees, on this same spec: three forest machines get a
  // deterministic MAC and a DHCP reservation, and the pivot is exempt rather
  // than a stray that fails the roster.
  const macs = goadDeployReal.prepareGoadMacs(spec, STAGING_VXLAN, STAGING_INT);
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC-01', 'DC-02', 'FS-01']);
  assert.strictEqual(macs['WEB-01'], undefined);
});

test('the golden set includes the web host, and the deploy clones it without refusing', async () => {
  // THE FULL LOOP, and the one that would have cost ninety minutes to discover:
  // capture records a golden template for every staging machine, the deploy
  // matches each one to a machine of its own by NAME, and the web host now has
  // to match too.
  reset();
  const row = await bakeRegisterAndSignOff();
  state.deploySpec = registerDeploySpec();

  assert.ok(Object.prototype.hasOwnProperty.call(row.golden_vmids, 'WEB-01'),
    'the capture converts the machine the website was installed on — without it every lane clones '
    + 'a stock web image and the company site exists nowhere');

  const res = await call('POST', '/deploy', {
    body: { profile_id: REGISTER_PROFILE_ID, num_lanes: 1, vuln_app: { enabled: false } },
  });
  assert.strictEqual(res.status, 202, JSON.stringify(res.body));
  await drain();

  const spec = deployedChallenge().spec;
  const web = spec.vms.find((vm) => vm.name === 'WEB-01');
  assert.strictEqual(web.template_vmid, row.golden_vmids['WEB-01'].vmid,
    'the lane clones the GOLDEN web image — the one with this client\'s site baked into it — '
    + 'rather than the catalog\'s empty Debian');
  assert.strictEqual(web.nics.length, 2, 'and it is still the lane\'s dual-homed pivot');
  assert.ok(!spec.goad.lab.vms.some((v) => v.name === 'WEB-01'),
    'still outside the forest on the deploy side too');
});
