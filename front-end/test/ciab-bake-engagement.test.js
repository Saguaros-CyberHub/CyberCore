/**
 * ciab-bake-engagement.test.js — Track B, phase B3: the staging engagement a
 * bake borrows cannot be pulled out from under it by a routine operator action.
 *
 * WHAT WAS WRONG.
 * A bake builds one client environment on a STAGING lane and captures its VMs as
 * the golden templates every student lane afterwards clones. That lane needs a
 * VXLAN id, and routes/profile-deploy.js gives it a DEDICATED one-slot
 * engagement — type 'bake' — rather than a seat out of the client's student
 * block. Its header explains why at length, and the reasoning is right: it costs
 * no student slot, and a block holding exactly ONE id is the only shape that
 * makes the staging lane's id — and therefore the pair of /24 bases the golden
 * templates write into their own DNS zone, their SYSVOL referrals and every SPN
 * — knowable BEFORE the lane exists.
 *
 * The slug it spent was an undeclared string. Nothing in utils/engagement-model.js
 * named it, so describeEngagementType answered known:false and the row rendered
 * in the operator's engagement list as an ordinary, locally defined engagement
 * with a Retire button on it. One confirmed click ends the system's only record
 * of which block those templates were built against, and the bake reports
 * nothing at all — nothing in a ninety-minute ansible run reads this table.
 *
 * WHAT B3 ASSERTS, IN THREE PARTS:
 *
 *   §1 REGISTERED. 'bake' is a first-class registry entry, flagged as
 *      system-owned, with a legal posture and a key the slug sanitizer leaves
 *      alone — plus the migration half: the value is not passing merely because
 *      nothing enforces it, and if a vocabulary CHECK is ever added it has to
 *      name this type or every bake starts failing with a 23514 rendered as a
 *      500.
 *
 *   §2 VISIBLE, NOT RETIRABLE. It stays in the operator listing — it is real
 *      infrastructure holding a real block, and hiding it makes a stranded bake
 *      HARDER to diagnose — but it is marked system-owned, the Retire button is
 *      not offered for it, the create form is not offered it, and the create and
 *      retire routes refuse it even when called directly.
 *
 *   §3 REFUSED WHILE A BAKE IS LIVE. Retiring one whose bake row is not in a
 *      terminal state is a 409 with a SCREAMING_SNAKE code that names the bake,
 *      the state it is in and the remedy — assertEngagementDeployable's shape,
 *      with no inline fallback. The guard lives on retireEngagement, so it holds
 *      for every caller and not only for the handler that has it today.
 *
 * HOW IT IS DRIVEN. §2 and §3 mount the REAL router from routes/engagements.js
 * over the REAL engagement-provision, the REAL bake-orchestrator, the REAL
 * registry and the REAL slug sanitizer, and stub exactly one boundary: the
 * database handle. So a refusal here is the refusal an operator gets, produced
 * by the code that ships, rendered through the route's own error renderer —
 * this suite has shipped components that passed their own tests and could not
 * run from a real entry point, and a hand-rolled fake of the layer under test is
 * how that happens.
 *
 * `node --test "test/*.test.js"` gives every file its own process, so the
 * require.cache writes below cannot reach another test file.
 *
 * Run: node --test front-end/test/ciab-bake-engagement.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const MIG_DIR = path.join(CIAB, 'migrations');
const ROUTES_FILE = path.join(CIAB, 'routes', 'engagements.js');
const DEPLOY_ROUTE_FILE = path.join(CIAB, 'routes', 'profile-deploy.js');

const read = (p) => fs.readFileSync(p, 'utf8');

// ── The one stubbed boundary: the database ──────────────────────────────────

/**
 * Everything the stubbed pool holds, plus a log of every statement it was
 * asked for. The log is not decoration: "the refusal happened BEFORE the write"
 * is the property that matters, and it is only visible in what SQL ran.
 */
const DB = {
  engagements: [],
  bakes: [],
  profiles: [{ id: 'p1', company_name: 'Acme' }],
  statements: [],
  // 42P01 on the bake table, for the "a read that could not run is not an
  // absent bake" case. It lives in the stub rather than in a swapped export
  // because every consumer destructures `const { query } = require('./db')` at
  // load — the same reason a live pool cannot be swapped out under one either.
  bakeTableMissing: false,
};

function resetDb() {
  DB.engagements = [];
  DB.bakes = [];
  DB.statements = [];
  DB.bakeTableMissing = false;
}

/** Statements matching a pattern, as flattened one-line text. */
const ran = (re) => DB.statements.filter((s) => re.test(s));

function put(modPath, exports) {
  const resolved = require.resolve(modPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
}

put(path.join(ROOT, 'src', 'utils', 'proxmox.js'), { proxmoxAPI: async () => ({}) });
put(path.join(ROOT, 'src', 'utils', 'lab-network-provision.js'),
  new Proxy({}, { get: () => async () => ({}) }));
put(path.join(ROOT, 'src', 'utils', 'lane-deployer.js'),
  new Proxy({}, { get: () => async () => ({}) }));
put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: async () => ({ rows: [] }) });

const AUDIT = [];
put(path.join(ROOT, 'src', 'utils', 'audit.js'), { log: (e) => AUDIT.push(e) });
put(path.join(ROOT, 'src', 'middleware', 'auth.js'), {
  requireRole: (...roles) => (req, res, next) => (
    req.user && roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'forbidden' })
  ),
});

// The compile and the spec synthesizer are irrelevant here and expensive to
// load; profile-to-spec is stubbed rather than replaced with a literal because
// engagement-provision.js imports DEFAULT_SUBNET_SCHEME from it BY IDENTITY —
// re-declaring the default is the exact drift R1 removed.
put(path.join(CIAB, 'utils', 'engagement-plan.js'), { compileEngagementPlan: () => ({ problems: [] }) });
put(path.join(CIAB, 'utils', 'profile-to-spec.js'), {
  synthesizeSpecFromProfile: () => ({ spec: {} }),
  DEFAULT_SUBNET_SCHEME: 'v3',
});
put(path.join(CIAB, 'routes', 'profile-deploy.js'), {
  loadProfileForDeploy: async () => ({ profile: { id: 'p1' }, assets: [] }),
  defaultAssetSelection: () => [],
  BAKE_ENGAGEMENT_TYPE: 'bake',
});

put(path.join(CIAB, 'utils', 'db.js'), {
  query: async (text, params) => {
    const sql = String(text).replace(/\s+/g, ' ').trim();
    DB.statements.push(sql);
    const p = params || [];

    if (/^UPDATE ciab_engagement SET retired_at = now\(\)/.test(sql)) {
      // The real statement is conditional — `AND retired_at IS NULL` — so a
      // second retire is a zero-row UPDATE rather than a moved timestamp.
      const row = DB.engagements.find((e) => e.engagement_id === p[0] && !e.retired_at);
      if (!row) return { rows: [] };
      row.retired_at = '2026-09-01T00:00:00.000Z';
      row.updated_by = p[1];
      return { rows: [row] };
    }
    if (/FROM ciab_profile_bake/.test(sql)) {
      if (DB.bakeTableMissing) {
        throw Object.assign(new Error('relation "ciab_profile_bake" does not exist'), { code: '42P01' });
      }
      return { rows: DB.bakes.filter((b) => b.profile_id === p[0]) };
    }
    if (/FROM ciab_engagement WHERE engagement_id = \$1/.test(sql)) {
      return { rows: DB.engagements.filter((e) => e.engagement_id === p[0]) };
    }
    if (/FROM ciab_engagement WHERE profile_id = \$1 AND engagement_type = \$2/.test(sql)) {
      return { rows: DB.engagements.filter((e) => e.profile_id === p[0] && e.engagement_type === p[1]) };
    }
    if (/FROM ciab_engagement WHERE profile_id = \$1/.test(sql)) {
      return { rows: DB.engagements.filter((e) => e.profile_id === p[0]) };
    }
    if (/FROM profiles WHERE id = \$1/.test(sql)) {
      return { rows: DB.profiles.filter((x) => x.id === p[0]) };
    }
    return { rows: [] };
  },
});

// ── The real modules under test ─────────────────────────────────────────────

const MODEL = require(path.join(CIAB, 'utils', 'engagement-model.js'));
const ORCH = require(path.join(CIAB, 'utils', 'bake-orchestrator.js'));
const PROVISION = require(path.join(CIAB, 'utils', 'engagement-provision.js'));
const laneReservation = require(path.join(CIAB, 'utils', 'lane-reservation.js'));
// The unadopted-reservation probe on the list route talks to cybercore_db. It
// is not this file's subject, and a thrown probe would only make every list
// answer unadopted_probe:'unavailable'.
laneReservation.findProfileChallenge = async () => null;

const router = require(ROUTES_FILE);

/** One request through the REAL router, with no socket and no port. */
function call(method, url, opts) {
  const o = opts || {};
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: o.query || {}, headers: {},
      user: { role: o.role || 'admin', userId: 'u1' },
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

// ── Fixtures ────────────────────────────────────────────────────────────────

const BAKE_TYPE = MODEL.BAKE_TYPE_KEY;

function engagement(over) {
  return Object.assign({
    engagement_id: 'e-x', profile_id: 'p1', engagement_type: 'default',
    subnet_scheme: 'v3', max_students: 30, challenge_id: 'ch-1',
    challenge_key: 'ciab-profile-p1-default', provision_status: 'ready',
    perspective: 'internal', credential_posture: 'none', retired_at: null,
  }, over);
}

function bake(over) {
  return Object.assign({
    bake_id: 'b-1', profile_id: 'p1', lab_hash: 'a1b2c3d4', lab_name: 'CIAB-a1b2c3d4',
    status: 'capturing', phase_detail: 'Capturing the golden templates',
    spec: {}, staging_vxlan_id: 10042,
  }, over);
}

/** The staging engagement plus a bake in whatever state the case needs. */
function stageBake(status, extra) {
  resetDb();
  DB.engagements.push(engagement({ engagement_id: 'e-bake', engagement_type: BAKE_TYPE, max_students: 1 }));
  if (status) DB.bakes.push(bake(Object.assign({ status }, extra || {})));
}

// ════════════════════════════════════════════════════════════════════════════
// §1 — REGISTERED, NOT AN UNDECLARED STRING
// ════════════════════════════════════════════════════════════════════════════

test('B3-1: the staging type is a first-class registry entry, flagged system-owned', () => {
  const d = MODEL.describeEngagementType(BAKE_TYPE);
  assert.strictEqual(d.known, true,
    'An unregistered slug answers known:false, which is what rendered the staging engagement in the '
    + 'operator list as an ordinary locally defined one — with a Retire button on it.');
  assert.strictEqual(d.system, true, 'and the registry says the PLATFORM owns it');
  assert.ok(MODEL.SYSTEM_ENGAGEMENT_TYPES.includes(BAKE_TYPE));
  assert.strictEqual(MODEL.isSystemEngagementType(BAKE_TYPE), true);

  // TOTAL, exactly like describeEngagementType, because it is asked about
  // request bodies and about slugs stored before this registry existed.
  for (const other of ['default', 'external_blackbox', 'purple_team', '', null, undefined]) {
    assert.strictEqual(MODEL.isSystemEngagementType(other), false,
      `${JSON.stringify(other)} is not platform-owned, and asking must never throw`);
  }

  // The posture must be one the column CHECKs accept, or createEngagement's
  // INSERT — which writes the descriptor's values, not the DEFAULTs — raises
  // 23514, and a pg error carries no status: it renders as a bare 500.
  assert.ok(MODEL.PERSPECTIVES.includes(d.perspective));
  assert.ok(MODEL.CREDENTIAL_POSTURES.includes(d.credential_posture));

  // A key the sanitizer would rewrite could never be matched by a stored slug,
  // because every writer sanitizes before it INSERTs.
  assert.strictEqual(laneReservation.sanitizeEngagementType(BAKE_TYPE), BAKE_TYPE);
});

test('B3-2: the route that spends the slug and the registry that declares it agree', () => {
  // routes/profile-deploy.js owns the bake path and declares the slug it spends.
  // Two spellings of one identity is how a reservation key stops matching the
  // row that names it — read as TEXT, so this holds without loading that file's
  // graph (the batch deployer, the vuln-app generator, two pools).
  const src = read(DEPLOY_ROUTE_FILE);
  const m = src.match(/const\s+BAKE_ENGAGEMENT_TYPE\s*=\s*'([^']+)'/);
  assert.ok(m, 'routes/profile-deploy.js still declares BAKE_ENGAGEMENT_TYPE');
  assert.strictEqual(m[1], BAKE_TYPE,
    `profile-deploy spends '${m[1]}' while the registry declares '${BAKE_TYPE}'. The slug is baked `
    + 'into the reservation key, so a disagreement orphans a carved block that nothing can name.');
});

/**
 * Every `CHECK (...)` expression in one migration, read with balanced parens.
 *
 * A regex that stops at the first ')' reads half of `CHECK (status IN ('a','b'))`,
 * and one that runs to the next ';' swallows the columns after it — including
 * `UNIQUE (profile_id, engagement_type)`, which is an index and not a constraint
 * on the value. Both mis-readings answer the wrong question here.
 */
function checkExpressions(sql) {
  const out = [];
  const re = /\bCHECK\s*\(/gi;
  let m = re.exec(sql);
  while (m) {
    let depth = 0;
    let i = m.index + m[0].length - 1;
    for (; i < sql.length; i += 1) {
      if (sql[i] === '(') depth += 1;
      else if (sql[i] === ')') { depth -= 1; if (depth === 0) break; }
    }
    out.push(sql.slice(m.index, i + 1));
    m = re.exec(sql);
  }
  return out;
}

test('B3-3: nothing constrains engagement_type in the database — and if it ever does, bake is in it', () => {
  // THE POINT OF THIS TEST. 'bake' may have been passing only because nothing
  // enforces the column, which is its own latent failure: the day someone adds a
  // vocabulary CHECK omitting it, every bake fails with a 23514 that carries
  // neither `status` nor `statusCode` and renders as an unhandled 500.
  //
  // 011_ciab_engagement_model.sql's header says NO CHECK ON engagement_type,
  // HERE OR EVER, and gives the reason: the sanitizer coerces rather than
  // rejects, so a CHECK turns every off-vocabulary slug into a 500. This asserts
  // the state of the tree AND survives a future author disagreeing.
  const files = fs.readdirSync(MIG_DIR).filter((f) => f.endsWith('.sql'));
  assert.ok(files.length > 0, 'the migrations directory is readable');

  const constrained = [];
  for (const f of files) {
    // Comments are stripped LINE BY LINE. The working tree is CRLF and '\r' is
    // a line terminator to a JS regex, so a whole-file /^\s*--.*$/gm stripper
    // silently stops stripping here — the trap test/sql-param-typing.test.js
    // documents.
    const sql = read(path.join(MIG_DIR, f))
      .split(/\r?\n/).map((l) => l.replace(/--.*$/, '')).join('\n');
    for (const expr of checkExpressions(sql)) {
      if (/\bengagement_type\b/.test(expr)) constrained.push({ file: f, expr });
    }
  }

  for (const c of constrained) {
    assert.ok(
      new RegExp(`'${BAKE_TYPE}'`).test(c.expr),
      `${c.file} constrains engagement_type without naming '${BAKE_TYPE}': ${c.expr.trim()}. `
      + 'A bake creates its staging engagement with that exact slug, so the constraint would raise '
      + '23514 — which carries no status property and renders as a bare 500 — on every bake.'
    );
  }
  assert.deepStrictEqual(constrained.map((c) => c.file), [],
    'Today there is deliberately none: the slug sanitizer coerces rather than rejects, so a CHECK '
    + 'would turn every locally defined slug into an unhandled 500. See 011\'s header.');

  // The one constraint that IS on the column is its width, and the slug has to
  // fit it — a longer one would be silently truncated or rejected at INSERT.
  const create = read(path.join(MIG_DIR, '010_ciab_engagements.sql'));
  const width = create.match(/engagement_type\s+VARCHAR\((\d+)\)/i);
  assert.ok(width, 'ciab_engagement.engagement_type is still a VARCHAR(n)');
  assert.ok(BAKE_TYPE.length <= Number(width[1]),
    `'${BAKE_TYPE}' does not fit VARCHAR(${width[1]})`);
});

test('B3-4: the terminal states this refusal turns on are the bake table\'s own', () => {
  // The guard says "not terminal". If that list drifts from migration 015's
  // status vocabulary, the refusal either fires forever or never fires.
  const sql = read(path.join(MIG_DIR, '015_ciab_profile_bake.sql'));
  const check = sql.match(/status\s+VARCHAR\(\d+\)[\s\S]*?CHECK\s*\(status IN \(([^)]*)\)\)/);
  assert.ok(check, 'migration 015 still constrains ciab_profile_bake.status');
  const declared = (check[1].match(/'([a-z_]+)'/g) || []).map((s) => s.replace(/'/g, ''));

  for (const s of ORCH.TERMINAL_STATUSES) {
    assert.ok(declared.includes(s), `TERMINAL_STATUSES names '${s}', which the migration does not allow`);
  }
  // 'pending' is NOT terminal, and that is load-bearing: a queued bake has
  // allocated nothing yet but is about to start on exactly this block.
  assert.ok(declared.includes('pending'));
  assert.ok(!ORCH.TERMINAL_STATUSES.includes('pending'),
    'a queued bake is not finished — retiring underneath it strands it just as thoroughly');
});

// ════════════════════════════════════════════════════════════════════════════
// §2 — VISIBLE IN THE OPERATOR LISTING, AND NOT RETIRABLE FROM IT
// ════════════════════════════════════════════════════════════════════════════

test('B3-5: the staging engagement is LISTED, marked system-owned, and offers no Retire', async () => {
  resetDb();
  DB.engagements.push(engagement({ engagement_id: 'e-std' }));
  DB.engagements.push(engagement({
    engagement_id: 'e-bake', engagement_type: BAKE_TYPE, max_students: 1,
    challenge_key: 'ciab-profile-p1-bake',
  }));

  const list = await call('GET', '/', { role: 'admin', query: { profile_id: 'p1' } });
  assert.strictEqual(list.status, 200);
  assert.strictEqual(list.body.engagements.length, 2,
    'IT STAYS VISIBLE. It is real infrastructure holding a real block, and hiding it makes a '
    + 'stranded bake harder to diagnose, not easier.');

  const staging = list.body.engagements.find((e) => e.engagement_type === BAKE_TYPE);
  const ordinary = list.body.engagements.find((e) => e.engagement_type === 'default');

  assert.strictEqual(staging.system_owned, true, 'the screen is told who owns it');
  assert.strictEqual(staging.can.retire, false,
    'THE FINDING: an admin was offered Retire on the block a bake\'s golden templates were built '
    + 'against, and retiring it strands the bake with no cause anywhere');
  assert.strictEqual(staging.can.reprovision, true,
    'Re-provision stays open — "the staging reservation carries no block, re-provision it" is a '
    + 'remedy the bake path hands the operator by name');
  // It reads as itself now, not as a mystery slug: the registry's label and
  // summary reach the card because the descriptor is resolved server-side.
  assert.strictEqual(staging.type_descriptor.known, true);
  assert.strictEqual(staging.type_descriptor.system, true);
  assert.ok(/bake/i.test(staging.display_label), 'and it is named as a bake');

  // AND AN ORDINARY ENGAGEMENT IS COMPLETELY UNCHANGED.
  assert.strictEqual(ordinary.system_owned, false);
  assert.strictEqual(ordinary.can.retire, true);
  assert.strictEqual(ordinary.can.edit, true);
  assert.strictEqual(list.body.can.retire, true, 'the top-level advice is unchanged too');

  // An instructor is offered no destructive action on either row, exactly as
  // before — `can` is computed for the CALLER.
  const asInstructor = await call('GET', '/', { role: 'instructor', query: { profile_id: 'p1' } });
  for (const row of asInstructor.body.engagements) assert.strictEqual(row.can.retire, false);
});

test('B3-6: the create form is not offered a type the platform owns', async () => {
  // GET /types is the create form's vocabulary — instructor-engagements.js
  // renders one <option> per entry — so anything in it is something an operator
  // can ask for. A staging network created by hand at the form's default of
  // thirty slots is a block the bake path then refuses, after the range has
  // already been spent and with nothing able to hand it back.
  const types = await call('GET', '/types', { role: 'instructor' });
  assert.strictEqual(types.status, 200);
  const keys = types.body.types.map((t) => t.key);
  assert.ok(!keys.includes(BAKE_TYPE), `GET /types must not offer '${BAKE_TYPE}'`);
  assert.ok(keys.includes('default') && keys.includes('external_blackbox'),
    'and every operator-authored type is still offered');
  assert.deepStrictEqual(
    keys.slice().sort(),
    Object.keys(MODEL.ENGAGEMENT_TYPES).filter((k) => !MODEL.isSystemEngagementType(k)).sort(),
    'the list is exactly the non-system registry, derived rather than hand-filtered'
  );
});

test('B3-7: create refuses a system-owned type, and allow_custom_type does not launder it', async () => {
  resetDb();
  const refused = await call('POST', '/', {
    role: 'admin', body: { profile_id: 'p1', engagement_type: BAKE_TYPE, max_students: 30 },
  });
  assert.strictEqual(refused.status, 400);
  assert.strictEqual(refused.body.code, 'SYSTEM_ENGAGEMENT_TYPE');
  assert.ok(/Bake/.test(refused.body.error), 'the refusal names the action that owns it');
  assert.deepStrictEqual(ran(/INSERT INTO ciab_engagement/), [],
    'NOTHING WAS CARVED — a VXLAN block is never handed back');

  // The override licenses an UNKNOWN slug. A system slug is KNOWN, so the
  // unknown-type refusal would wave it straight through — which is why this
  // check sits above it and does not read the flag.
  const forced = await call('POST', '/', {
    role: 'admin',
    body: { profile_id: 'p1', engagement_type: BAKE_TYPE, max_students: 1, allow_custom_type: true },
  });
  assert.strictEqual(forced.status, 400);
  assert.strictEqual(forced.body.code, 'SYSTEM_ENGAGEMENT_TYPE');
  assert.deepStrictEqual(ran(/INSERT INTO ciab_engagement/), [], 'still nothing carved');

  // AND AN ORDINARY CREATE IS UNTOUCHED. createEngagement is swapped for the
  // duration: the real one detaches a provision that reaches the cluster, and
  // what is under test here is the refusal, not the carve.
  const realCreate = PROVISION.createEngagement;
  const created = [];
  PROVISION.createEngagement = async (opts) => {
    created.push(opts);
    return engagement({ engagement_id: 'e-new', engagement_type: opts.engagementType,
      provision_status: 'provisioning' });
  };
  try {
    const ok = await call('POST', '/', {
      role: 'admin', body: { profile_id: 'p1', engagement_type: 'external_blackbox', max_students: 25 },
    });
    assert.strictEqual(ok.status, 202, 'an operator-authored type still creates');
    assert.strictEqual(created.length, 1);
  } finally {
    PROVISION.createEngagement = realCreate;
  }
});

// ════════════════════════════════════════════════════════════════════════════
// §3 — TEARDOWN IS REFUSED WHILE THE BAKE IS LIVE
// ════════════════════════════════════════════════════════════════════════════

test('B3-8: retiring the staging engagement needs the intention stated, not just confirm', async () => {
  stageBake(null);
  const r = await call('POST', '/e-bake/retire', { role: 'admin', body: { confirm: true } });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.body.code, 'SYSTEM_ENGAGEMENT_CONFIRM_REQUIRED');
  assert.ok(/confirm_system_owned/.test(r.body.error), 'and the refusal names the way through');
  assert.deepStrictEqual(ran(/UPDATE ciab_engagement SET retired_at/), [],
    'nothing was retired');

  // The screen never sends it, because project() withholds the button — the
  // route checks anyway, because a hidden button is a screen decision and this
  // endpoint is reachable by anything holding an admin token.
  assert.strictEqual(DB.engagements[0].retired_at, null);
});

test('B3-9: a live bake refuses the teardown by NAME, with the state and the remedy', async () => {
  for (const status of ['pending', 'compiling', 'provisioning', 'verifying', 'capturing']) {
    stageBake(status);
    const r = await call('POST', '/e-bake/retire', {
      role: 'admin', body: { confirm: true, confirm_system_owned: true },
    });

    assert.strictEqual(r.status, 409, `a bake reading '${status}' must refuse with a 409`);
    assert.strictEqual(r.body.code, 'ENGAGEMENT_BAKE_IN_FLIGHT');
    assert.ok(/^[A-Z_]+$/.test(r.body.code), 'the code is machine-readable');
    // NAMES THE BAKE. "Something is using it" sends an operator hunting; the
    // lab name is what the bake panel shows and what the controller directory
    // is called.
    assert.ok(r.body.error.includes('CIAB-a1b2c3d4'), `the refusal names the bake: ${r.body.error}`);
    assert.ok(r.body.error.includes(status), 'and the state it is in');
    assert.ok(r.body.error.includes('Capturing the golden templates'),
      'and the progress line, which is the difference between minute 70 and a hang');
    // NAMES THE REMEDY, in assertEngagementDeployable's shape: what to do, not
    // just what went wrong.
    assert.ok(/Wait for it to finish/.test(r.body.error), 'the refusal says what to do instead');
    assert.ok(/restart the server/.test(r.body.error), 'including the way out of a stranded run');

    // AND THE STRUCTURED HALF REACHES THE CLIENT. assertBakeEngagementRetirable
    // attaches err.bake so a caller can link to the bake rather than parse the
    // prose; sendErr forwards only the keys it names, so a payload the producer
    // builds and the renderer drops is a payload that does not exist.
    assert.ok(r.body.bake, `the 409 carries error.bake (got keys: ${Object.keys(r.body).join(',')})`);
    assert.strictEqual(r.body.bake.lab_name, 'CIAB-a1b2c3d4');
    assert.strictEqual(r.body.bake.status, status);
    assert.ok(r.body.bake.bake_id, 'and the id, which is what a link needs');

    // NO INLINE FALLBACK: it refused instead of retiring anyway.
    assert.deepStrictEqual(ran(/UPDATE ciab_engagement SET retired_at/), [],
      `a bake reading '${status}' must not lose its network`);
    assert.strictEqual(DB.engagements[0].retired_at, null);
  }
});

test('B3-10: a finished bake does not block the documented remedy', async () => {
  // The refusal has to be about a bake that is RUNNING, not about the type.
  // 'Retire the staging engagement and let Bake re-create it at one slot' is a
  // remedy routes/profile-deploy.js hands the operator by name when a staging
  // block was carved at the wrong size, and a blanket refusal makes that
  // instruction impossible to follow.
  stageBake('ready');
  DB.bakes.push(bake({ bake_id: 'b-0', lab_name: 'CIAB-99999999', status: 'failed' }));
  DB.bakes.push(bake({ bake_id: 'b-2', lab_name: 'CIAB-88888888', status: 'superseded' }));
  AUDIT.length = 0;

  const r = await call('POST', '/e-bake/retire', {
    role: 'admin', body: { confirm: true, confirm_system_owned: true },
  });
  assert.strictEqual(r.status, 200, `expected the retire to go through: ${JSON.stringify(r.body)}`);
  assert.ok(r.body.engagement.retired_at, 'and the row is marked');
  assert.strictEqual(ran(/UPDATE ciab_engagement SET retired_at/).length, 1);

  const row = AUDIT.filter((a) => a.action === 'profile_engagement.retired').pop();
  assert.ok(row, 'and it is audited');
  assert.strictEqual(row.metadata.system_owned, true,
    'the audit row records that a platform-owned engagement was ended — this is how "why did that '
    + 'bake lose its network" gets answered afterwards');
  assert.strictEqual(row.metadata.capacity_released, false, 'and still that nothing was released');
});

test('B3-11: an ordinary engagement retires exactly as before, and never reads the bake table', async () => {
  resetDb();
  DB.engagements.push(engagement({ engagement_id: 'e-std' }));
  DB.bakes.push(bake({ status: 'capturing' }));   // a live bake on the SAME client
  AUDIT.length = 0;

  const bare = await call('POST', '/e-std/retire', { role: 'admin', body: {} });
  assert.strictEqual(bare.status, 400, 'confirm is still required');
  assert.strictEqual(bare.body.code, 'CONFIRM_REQUIRED');

  const done = await call('POST', '/e-std/retire', { role: 'admin', body: { confirm: true } });
  assert.strictEqual(done.status, 200, 'and a confirmed retire still succeeds');
  assert.ok(done.body.engagement.retired_at);
  const row = AUDIT.filter((a) => a.action === 'profile_engagement.retired').pop();
  assert.strictEqual(row.metadata.capacity_released, false);
  assert.strictEqual(row.metadata.system_owned, false);

  // THE GUARD COSTS AN ORDINARY ENGAGEMENT NOTHING. A live bake on the same
  // client has no bearing on a student engagement, and reading the bake table
  // for one would make every retire in the system depend on a table it has no
  // relationship with.
  assert.deepStrictEqual(ran(/ciab_profile_bake/), [],
    'retiring an ordinary engagement never touches the bake table');

  // A second retire is still a 409, not a moved timestamp — retirement is
  // evidence and a double click must not rewrite when it happened.
  const again = await call('POST', '/e-std/retire', { role: 'admin', body: { confirm: true } });
  assert.strictEqual(again.status, 409);
});

test('B3-12: the guard is on retireEngagement, so it holds for every caller', async () => {
  // Not on the handler. The whole finding is that a second caller of this
  // machinery appeared — the bake path — without anyone noticing, and a guard
  // written into one route is a guard the next caller does not get.
  stageBake('capturing');
  await assert.rejects(
    () => PROVISION.retireEngagement('e-bake', { actingUserId: 'u1' }),
    (err) => {
      assert.strictEqual(err.status, 409);
      assert.strictEqual(err.code, 'ENGAGEMENT_BAKE_IN_FLIGHT');
      assert.ok(err.bake && err.bake.lab_name === 'CIAB-a1b2c3d4',
        'the error carries the bake it refused for');
      return true;
    }
  );
  assert.deepStrictEqual(ran(/UPDATE ciab_engagement SET retired_at/), [],
    'the refusal happens BEFORE the write, not as a rollback afterwards');

  // And the same function retires an ordinary engagement without asking the
  // bake table anything.
  resetDb();
  DB.engagements.push(engagement({ engagement_id: 'e-std' }));
  const retired = await PROVISION.retireEngagement('e-std', { actingUserId: 'u1' });
  assert.ok(retired.retired_at);
  assert.deepStrictEqual(ran(/ciab_profile_bake/), []);
});

test('B3-13: a bake table that cannot be read refuses the teardown rather than allowing it', async () => {
  // A READ THAT CANNOT RUN IS NOT AN ABSENT BAKE. The plugin re-runs its own
  // migrations at every boot and only console.errors a failure, so a missing
  // ciab_profile_bake is a real state — and answering "no live bake" on the
  // evidence that nothing is known is exactly how the block gets pulled. The
  // route renders 42P01 as a 503 naming the remedy, and the retirement does not
  // happen.
  stageBake('capturing');
  DB.bakeTableMissing = true;

  const r = await call('POST', '/e-bake/retire', {
    role: 'admin', body: { confirm: true, confirm_system_owned: true },
  });
  assert.strictEqual(r.status, 503);
  assert.strictEqual(r.body.code, 'ENGAGEMENT_STORE_MISSING');
  assert.deepStrictEqual(ran(/UPDATE ciab_engagement SET retired_at/), [],
    'the block is not released on the strength of a read that never ran');
  assert.strictEqual(DB.engagements[0].retired_at, null);
});
