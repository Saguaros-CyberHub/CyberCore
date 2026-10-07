/**
 * ciab-bake-orchestrator.test.js — Track G5: the per-profile bake is durable,
 * restartable, and refuses rather than guesses.
 *
 * WHY THIS FILE EXISTS
 * A bake is ninety minutes of Ansible that cannot be trusted to report its own
 * health. The vendored role library has twenty sites where a task reports
 * SUCCESS and did nothing, three of them shipped vulnerabilities that are simply
 * absent afterwards; `changed_when` appears twice in the whole tree and
 * `error_action: stop` six times, so neither "changed" nor the exit code carries
 * information. Nothing in that chain can be asserted from here.
 *
 * What CAN be asserted from here is everything wrapped around it, and every one
 * of these properties is invisible to source text:
 *
 *   1. THE ROW MOVES. status walks compiling -> pushing -> provisioning ->
 *      verifying -> capturing -> ready, and phase_detail is written as work
 *      happens. Before this module the only durable write was one terminal row
 *      up to two hours later, which makes a working bake and a hung bake the
 *      same row.
 *
 *   2. THE DETACHED WORKER NEVER THROWS. bakeProfile is called with a bare
 *      .catch and nothing awaits it. A rejection out of its top level lands on
 *      an unhandled-rejection handler instead of in the row, where it is the
 *      only thing an operator can see. Tested including the case where the
 *      failure UPDATE itself throws.
 *
 *   3. THE MUTEX IS REAL. A staging lane is not idempotent in any sense: a
 *      second concurrent bake of one row allocates a second lane and a second
 *      controller VM, both write staging_lane_id over each other, and whichever
 *      loses is unfindable forever.
 *
 *   4. RECOVERY MARKS AND CLEANS, AND NEVER RETRIES. A stranded bake leaks a
 *      whole lane; an automatic retry at every boot is a loop that costs ninety
 *      minutes of cluster time per iteration.
 *
 *   5. THE GATE REFUSES WITH A DISTINCT CODE PER REASON, including the two
 *      drift cases — the profile was edited, or the GOAD pin moved — which are
 *      the ones that would otherwise deploy quietly and hand students machines
 *      that do not match their brief.
 *
 * ciab/utils/db.js is stubbed COMPLETELY — { query, getPool, setPool, pool } —
 * because a partial stub leaves the real module loaded for whichever export was
 * omitted, and that one builds a pg pool. Same stub shape as
 * ciab-module-admin.test.js. teardownLanes is INJECTED rather than stubbed
 * through require.cache: bake-orchestrator requires lane-deployer lazily and
 * only on the teardown path, so a test that passes its own never loads it.
 *
 * Run: node --test front-end/test/ciab-bake-orchestrator.test.js  (or npm test)
 */

const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

/** Every statement the module issued this test, flattened for matching. */
let dbLog = [];
/** (sql, params) => result | null. Null/undefined means "no rows". */
let dbRespond = null;

const flat = (sql) => String(sql).replace(/\s+/g, ' ').trim();

stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (text, params) => {
    const sql = flat(text);
    dbLog.push({ sql, params: params || [] });
    const res = dbRespond ? await dbRespond(sql, params || []) : null;
    return res || { rows: [], rowCount: 0 };
  },
  getPool: () => null,
  setPool: () => {},
  pool: null,
});

const orch = require(path.join(CIAB, 'utils', 'bake-orchestrator.js'));

const MIGRATION = fs.readFileSync(
  path.join(CIAB, 'migrations', '015_ciab_profile_bake.sql'), 'utf8').replace(/\r\n/g, '\n');

// ── fixtures ────────────────────────────────────────────────────────────────

const P1 = '11111111-1111-4111-8111-111111111111';
const P2 = '11111111-1111-4111-8111-111111111112';
const ACTOR = '99999999-9999-4999-8999-999999999999';
// A real 64-char lowercase hex digest, because labNameForHash slices it and the
// migration's CHECK constrains the alphabet.
const HASH = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const HASH2 = 'ffffffff0000111122223333444455556666777788889999aaaabbbbccccdddd';
// The pinned GOAD fork commit. A branch name here is the thing goad_ref exists
// to make impossible.
const GOAD_REF = '00e9b63eb1e82f16780943f5d237d5529fd4a1a9';
const GOAD_REF2 = '1234567890abcdef1234567890abcdef12345678';

const SPEC = {
  goad: { enabled: true, version: 'GOAD-Light', lab: { forestRoot: 'clinic.local', vms: [{ name: 'DC01' }] } },
  fixed_subnet: '10.39.16',
  subnet_scheme: 'v3',
};

function bakeRow(over = {}) {
  return {
    bake_id: '22222222-2222-4222-8222-222222222222',
    profile_id: P1,
    lab_hash: HASH,
    lab_name: 'CIAB-a1b2c3d4',
    goad_ref: GOAD_REF,
    manifest_sha: 'sha256:manifest',
    spec: SPEC,
    staging_lane_id: null,
    staging_vxlan_id: null,
    controller_vmid: null,
    status: 'pending',
    phase_detail: 'Queued.',
    error: null,
    verify_report: null,
    bh_report: null,
    gate_solvable: null,
    gate_paper: null,
    gate_no_unintended: null,
    gates_approved_by: null,
    gates_approved_at: null,
    golden_vmids: null,
    started_at: null,
    finished_at: null,
    created_by: ACTOR,
    created_at: null,
    updated_at: null,
    ...over,
  };
}

/** Five phases that do nothing, recording the order they were called in. */
function noopSteps(seen = []) {
  const steps = {};
  for (const phase of orch.PHASES) steps[phase.step] = async () => { seen.push(phase.step); };
  return steps;
}

/** Every status written against THIS bake row, in order. */
function statusSequence() {
  const out = [];
  for (const call of dbLog) {
    // The supersede statement is scoped by profile_id and targets OTHER rows;
    // counting it here would report a transition this bake never made.
    if (!/WHERE bake_id = \$1/.test(call.sql)) continue;
    const literal = call.sql.match(/SET status = '([a-z]+)'/);
    if (literal) { out.push(literal[1]); continue; }
    if (/SET status = \$2/.test(call.sql)) out.push(call.params[1]);
  }
  return out;
}

/** Every phase_detail-only write (the progress channel), in order. */
function detailWrites() {
  return dbLog
    .filter((c) => /^UPDATE ciab_profile_bake SET phase_detail = \$2/.test(c.sql))
    .map((c) => c.params[1]);
}

const indexOfSql = (re) => dbLog.findIndex((c) => re.test(c.sql));
const settle = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

beforeEach(() => { dbLog = []; dbRespond = null; });

// ---------------------------------------------------------------------------
// 1. The row moves, and it moves in one direction
// ---------------------------------------------------------------------------

test('a bake walks every phase in order and lands on ready', async () => {
  const seen = [];
  const result = await orch.bakeProfile(bakeRow(), { steps: noopSteps(seen), heartbeatMs: 0 });

  assert.deepStrictEqual(seen, ['compile', 'push', 'provision', 'verify', 'capture'],
    'the phases must run in the declared order — the push depends on the compile, and the '
    + 'capture depends on a lane the provision built');
  assert.deepStrictEqual(statusSequence(),
    ['compiling', 'pushing', 'provisioning', 'verifying', 'capturing', 'ready']);
  assert.deepStrictEqual(result, { bake_id: bakeRow().bake_id, status: 'ready', skipped: false, error: null });
});

test('every phase writes an opening phase_detail, so a poll is never blank', async () => {
  await orch.bakeProfile(bakeRow(), { steps: noopSteps(), heartbeatMs: 0 });
  const opening = dbLog.filter((c) => /SET status = \$2, phase_detail = \$3/.test(c.sql));
  assert.strictEqual(opening.length, orch.PHASES.length);
  for (const call of opening) {
    assert.ok(typeof call.params[2] === 'string' && call.params[2].length > 20,
      `phase '${call.params[1]}' opened with no usable detail: ${JSON.stringify(call.params[2])}`);
  }
});

test('a step streams progress inside its phase without changing the status', async () => {
  // The whole point: a ninety-minute provisioning phase that says nothing is
  // indistinguishable from a hang.
  const steps = noopSteps();
  steps.provision = async ({ setDetail }) => {
    await setDetail('WinRM up on 3/4 hosts');
    await setDetail('ansible-playbook 7/16: ad-parent_domain.yml');
  };
  await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });

  assert.deepStrictEqual(detailWrites(), ['WinRM up on 3/4 hosts', 'ansible-playbook 7/16: ad-parent_domain.yml']);
  assert.deepStrictEqual(statusSequence(),
    ['compiling', 'pushing', 'provisioning', 'verifying', 'capturing', 'ready'],
    'streaming progress must not add or reorder a status transition');
});

test('progress is best-effort and a dropped write never fails a bake', async () => {
  // Losing a line of text is cosmetic. Killing ninety minutes of work over it is
  // not, and that asymmetry has to be real rather than intended.
  dbRespond = (sql) => {
    if (/^UPDATE ciab_profile_bake SET phase_detail = \$2/.test(sql)) throw new Error('connection reset');
    return null;
  };
  const steps = noopSteps();
  steps.provision = async ({ setDetail }) => {
    assert.strictEqual(await setDetail('halfway'), false, 'a failed progress write must report itself');
  };
  const result = await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });
  assert.strictEqual(result.status, 'ready');
});

test('a phase records its ids the moment it has them, not when it finishes', async () => {
  // A crash one second after the lane exists must still leave something
  // findable. If staging_lane_id were written at the end of the phase, the
  // entire ninety-minute window would be unrecoverable.
  const steps = noopSteps();
  steps.provision = async ({ record }) => {
    await record({ staging_lane_id: 'lane-1', staging_vxlan_id: 10500, controller_vmid: 9001 });
    throw new Error('run.sh exited 2');
  };
  await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });

  const recordAt = indexOfSql(/SET staging_lane_id = \$2/);
  const failAt = indexOfSql(/SET status = 'failed'/);
  assert.ok(recordAt !== -1, 'the lane id was never persisted');
  assert.ok(recordAt < failAt, 'the lane id must be on the row BEFORE the failure is recorded');
  assert.deepStrictEqual(dbLog[recordAt].params.slice(1), ['lane-1', 10500, 9001]);
});

test('a later phase reads what an earlier one recorded', async () => {
  // Otherwise capture would have to re-SELECT the row to learn the lane id this
  // process just wrote — three round trips to re-learn a known fact.
  let sawLane = null;
  const steps = noopSteps();
  steps.provision = async ({ record }) => { await record({ staging_lane_id: 'lane-7' }); };
  steps.capture = async ({ bake }) => { sawLane = bake.staging_lane_id; };
  await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });
  assert.strictEqual(sawLane, 'lane-7');
});

test('the golden template ids are stored as jsonb, cast on first reference', async () => {
  // Postgres fixes a parameter's type at its first reference; an uncast jsonb
  // parameter is a parse failure, not a style preference.
  const steps = noopSteps();
  steps.capture = async () => ({ golden_vmids: { DC01: 9101, SRV02: 9102 } });
  await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });

  const write = dbLog.find((c) => /SET golden_vmids = /.test(c.sql));
  assert.ok(write, 'the capture phase result was never persisted');
  assert.match(write.sql, /golden_vmids = \$2::jsonb/);
  assert.strictEqual(write.params[1], JSON.stringify({ DC01: 9101, SRV02: 9102 }));
});

// ---------------------------------------------------------------------------
// 2. The detached worker never throws
// ---------------------------------------------------------------------------

test('a failing step is recorded in the row, and the bake does not reject', async () => {
  const seen = [];
  const steps = noopSteps(seen);
  steps.push = async () => { throw new Error('controller refused the lab directory'); };

  let result;
  await assert.doesNotReject(async () => { result = await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 }); });

  assert.strictEqual(result.status, 'failed');
  assert.deepStrictEqual(seen, ['compile'], 'no phase after the failure may run');
  const fail = dbLog.find((c) => /SET status = 'failed'/.test(c.sql));
  assert.ok(fail, 'the failure was never written to the row');
  assert.strictEqual(fail.params[1], 'controller refused the lab directory');
});

test('the failure write leaves phase_detail alone, so WHERE it died survives', async () => {
  // The status says failed and the error says why; phase_detail is the only
  // thing that still says which phase, and overwriting it loses the diagnosis.
  const steps = noopSteps();
  steps.verify = async () => { throw new Error('bloodhound collection empty'); };
  await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });
  const fail = dbLog.find((c) => /SET status = 'failed'/.test(c.sql));
  assert.ok(!/phase_detail/.test(fail.sql), 'the failure UPDATE must not touch phase_detail');
});

test('a missing phase implementation FAILS the bake — it is never skipped', async () => {
  // Skipping is the exact failure this whole track exists to eliminate: a run
  // that reports success and did nothing.
  const steps = noopSteps();
  delete steps.verify;
  const result = await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });

  assert.strictEqual(result.status, 'failed');
  assert.match(result.error, /'verify' phase has no implementation/);
  assert.ok(!statusSequence().includes('ready'), 'a bake with an unimplemented phase must never read ready');
});

test('a phase that returns an unknown column fails instead of losing the value', async () => {
  // Silently dropping it is indistinguishable from the phase not having produced
  // it, which is how a bake reaches ready with no staging lane recorded.
  const steps = noopSteps();
  steps.provision = async () => ({ staging_lane_id: 'lane-2', lane_ip: '10.39.16.5' });
  const result = await orch.bakeProfile(bakeRow(), { steps, heartbeatMs: 0 });

  assert.strictEqual(result.status, 'failed');
  assert.match(result.error, /unknown column\(s\): lane_ip/);
});

test('it does not throw even when EVERY database write fails', async () => {
  // The last line of defence: if the failure UPDATE itself throws and this
  // rejects, the reason lands on an unhandled-rejection handler and the row
  // still reads "provisioning" forever.
  dbRespond = () => { throw new Error('clinic_db is down'); };
  let result;
  await assert.doesNotReject(async () => { result = await orch.bakeProfile(bakeRow(), { steps: noopSteps(), heartbeatMs: 0 }); });
  assert.strictEqual(result.status, 'failed');
});

test('it does not throw when handed no row at all', async () => {
  await assert.doesNotReject(() => orch.bakeProfile(null, { steps: noopSteps() }));
  await assert.doesNotReject(() => orch.bakeProfile({}, { steps: noopSteps() }));
  assert.deepStrictEqual(dbLog, [], 'with no bake id there is no row to write to');
});

// ---------------------------------------------------------------------------
// 3. The in-process mutex
// ---------------------------------------------------------------------------

test('a second concurrent bake of the same id is refused and runs nothing', async () => {
  // The DB status alone cannot do this: two callers can both read a non-terminal
  // status before either writes, and the staging lane underneath is not
  // idempotent — the loser's lane and controller VM become unfindable.
  let release;
  const gate = new Promise((r) => { release = r; });
  const firstSteps = noopSteps();
  firstSteps.compile = () => gate;

  const secondSeen = [];
  const bake = bakeRow();

  const first = orch.bakeProfile(bake, { steps: firstSteps, heartbeatMs: 0 });
  await settle(2);

  const second = await orch.bakeProfile(bake, { steps: noopSteps(secondSeen), heartbeatMs: 0 });
  assert.strictEqual(second.skipped, true);
  assert.deepStrictEqual(secondSeen, [], 'the duplicate must not run a single phase');

  release();
  const done = await first;
  assert.strictEqual(done.status, 'ready');
});

test('the mutex is released whether the bake succeeds or fails', async () => {
  // Released in a finally. Without that, one failed bake locks the row out of
  // every future restart for the life of the process — and the only remedy
  // would be a server restart, which is what stranded it in the first place.
  const bake = bakeRow();
  const boom = noopSteps();
  boom.compile = async () => { throw new Error('nope'); };
  assert.strictEqual((await orch.bakeProfile(bake, { steps: boom, heartbeatMs: 0 })).status, 'failed');

  const seen = [];
  const again = await orch.bakeProfile(bake, { steps: noopSteps(seen), heartbeatMs: 0 });
  assert.strictEqual(again.status, 'ready');
  assert.strictEqual(seen.length, 5, 'a restart after a failure must run every phase');
});

test('two different bakes do not block each other', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const slow = noopSteps();
  slow.compile = () => gate;

  const a = orch.bakeProfile(bakeRow({ bake_id: 'aaaa-1' }), { steps: slow, heartbeatMs: 0 });
  await settle(2);
  const b = await orch.bakeProfile(bakeRow({ bake_id: 'bbbb-2' }), { steps: noopSteps(), heartbeatMs: 0 });
  assert.strictEqual(b.status, 'ready');
  release();
  await a;
});

// ---------------------------------------------------------------------------
// 4. A restart is a fresh lane, never a resume
// ---------------------------------------------------------------------------

test('a previous attempt\'s staging lane is destroyed before any new phase starts', async () => {
  // run.sh is not idempotent and a half-promoted forest is not a state any
  // playbook in the chain can start from, so there is no partial resume to
  // attempt — only a clean rebuild.
  const calls = [];
  const teardown = async (laneIds, opts) => { calls.push({ laneIds, opts }); return { errors: [] }; };

  await orch.bakeProfile(
    bakeRow({ status: 'failed', staging_lane_id: 'lane-old', controller_vmid: 9001, golden_vmids: [9101, 9102] }),
    { steps: noopSteps(), teardown, heartbeatMs: 0 });

  assert.strictEqual(calls.length, 1, 'the abandoned lane was never torn down');
  assert.deepStrictEqual(calls[0].laneIds, ['lane-old']);
  assert.deepStrictEqual(calls[0].opts.extraVmIds, [9001, 9101, 9102],
    'the controller and any half-captured templates live outside the lane config, so teardownLanes '
    + 'only finds them if they are passed as extras');

  const clearedAt = indexOfSql(/SET staging_lane_id = NULL/);
  const firstPhaseAt = indexOfSql(/SET status = \$2/);
  assert.ok(clearedAt !== -1 && clearedAt < firstPhaseAt,
    'the stale ids must be cleared before the rebuild starts, or a second failure tears down a lane that is gone');
});

test('a bake with no previous lane skips teardown entirely', async () => {
  let called = 0;
  await orch.bakeProfile(bakeRow(), {
    steps: noopSteps(), heartbeatMs: 0, teardown: async () => { called++; return { errors: [] }; },
  });
  assert.strictEqual(called, 0);
});

test('a completed bake supersedes the previous READY version, and only that', async () => {
  await orch.bakeProfile(bakeRow(), { steps: noopSteps(), heartbeatMs: 0 });
  const sup = dbLog.find((c) => /SET status = 'superseded'/.test(c.sql));
  assert.ok(sup, 'nothing retired the previous version');
  assert.match(sup.sql, /WHERE profile_id = \$1 AND bake_id <> \$2 AND status = 'ready'/,
    'only a READY sibling may be superseded — a failed one keeps its error as evidence, and an '
    + 'active one is a different content version a process is still writing');
  const readyAt = indexOfSql(/SET status = 'ready'/);
  const supAt = dbLog.indexOf(sup);
  assert.ok(readyAt < supAt,
    'the previous version is retired only once the replacement is proven — otherwise a failed bake '
    + 'leaves the client with no deployable environment at all');
});

// ---------------------------------------------------------------------------
// 5. Boot recovery
// ---------------------------------------------------------------------------

function strandedRows(active, pending = []) {
  return (sql) => {
    if (/status IN \('compiling','pushing','provisioning','verifying','capturing'\)/.test(sql)) {
      return { rows: active, rowCount: active.length };
    }
    if (/WHERE status = 'pending'/.test(sql)) return { rows: pending, rowCount: pending.length };
    return null;
  };
}

test('the sweep marks every non-terminal row failed — the active ones and the queued ones', async () => {
  dbRespond = strandedRows(
    [{ bake_id: 'b1', profile_id: P1, lab_name: 'CIAB-aaaa1111', staging_lane_id: 'lane-1', controller_vmid: 9001, golden_vmids: null }],
    [{ bake_id: 'b2', lab_name: 'CIAB-bbbb2222' }]
  );

  const result = await orch.recoverStrandedBakes({ teardown: async () => ({ errors: [] }) });
  assert.deepStrictEqual(
    { interrupted: result.interrupted, never_started: result.never_started },
    { interrupted: 1, never_started: 1 });

  const writes = dbLog.filter((c) => /^UPDATE ciab_profile_bake SET status =/.test(c.sql));
  assert.strictEqual(writes.length, 2, 'two statements: one for the rows that leak a lane, one for the rows that do not');
  for (const w of writes) {
    assert.match(w.sql, /SET status = 'failed'/,
      'the sweep may only move a row to a TERMINAL state — anything else is a row nothing will ever pick up');
  }
});

test('the sweep never retries a bake', async () => {
  // An operator pressing Re-bake is a decision; an automatic retry at every boot
  // is a loop, and this loop costs ninety minutes of cluster time per iteration.
  dbRespond = strandedRows([{ bake_id: 'b1', profile_id: P1, lab_name: 'CIAB-aaaa1111', staging_lane_id: 'lane-1', controller_vmid: null, golden_vmids: null }]);
  await orch.recoverStrandedBakes({ teardown: async () => ({ errors: [] }) });
  await settle();

  for (const call of dbLog) {
    for (const active of orch.ACTIVE_STATUSES) {
      assert.ok(!new RegExp(`SET status = '${active}'`).test(call.sql),
        `the sweep restarted a bake: ${call.sql.slice(0, 80)}`);
    }
    assert.ok(!/SET status = \$2/.test(call.sql), 'the sweep must not enter a phase');
  }
});

test('the sweep names the phase the bake died in, using the row\'s own old status', async () => {
  // Postgres evaluates the SET list against the row as it was, so `|| status ||`
  // reads the OLD value. Without it the sweep would need a second read per row
  // just to write "while provisioning" instead of "while something".
  dbRespond = strandedRows([]);
  await orch.recoverStrandedBakes({ cleanup: false });
  const active = dbLog.find((c) => /status IN \('compiling'/.test(c.sql));
  assert.match(active.sql, /error = 'Interrupted by a server restart while ' \|\| status \|\|/);
  const pending = dbLog.find((c) => /WHERE status = 'pending'/.test(c.sql));
  assert.match(pending.sql, /never started/, 'a queued row never started a build and must not claim it did');
});

test('the sweep schedules teardown for the lane a stranded bake leaked, and only for those', async () => {
  // This is what recoverStrandedEngagements does not have to do. A stranded
  // engagement leaks bookkeeping; a stranded bake leaks a lane, a controller VM
  // and possibly half a set of templates, and the row is the only thing that
  // knows their ids.
  const calls = [];
  dbRespond = strandedRows([
    { bake_id: 'b1', profile_id: P1, lab_name: 'CIAB-aaaa1111', staging_lane_id: 'lane-1', controller_vmid: 9001, golden_vmids: [9101] },
    { bake_id: 'b2', profile_id: P2, lab_name: 'CIAB-bbbb2222', staging_lane_id: null, controller_vmid: null, golden_vmids: null },
  ]);

  const result = await orch.recoverStrandedBakes({
    teardown: async (laneIds, opts) => { calls.push({ laneIds, opts }); return { errors: [] }; },
  });
  await settle();

  assert.strictEqual(result.teardowns_scheduled, 1, 'a row that allocated nothing has nothing to clean');
  assert.deepStrictEqual(calls[0].laneIds, ['lane-1']);
  assert.deepStrictEqual(calls[0].opts.extraVmIds, [9001, 9101]);
  assert.ok(dbLog.some((c) => /SET staging_lane_id = NULL/.test(c.sql) && c.params[0] === 'b1'),
    'once the lane is gone the row must stop pointing at it');
});

test('a teardown that cannot finish is written back onto the row, not swallowed', async () => {
  // A leaked VM nobody can see is exactly what this path exists to prevent, so
  // the failure has to reach the operator rather than a log line at boot.
  dbRespond = strandedRows([{ bake_id: 'b1', profile_id: P1, lab_name: 'CIAB-aaaa1111', staging_lane_id: 'lane-1', controller_vmid: 9001, golden_vmids: null }]);
  await orch.recoverStrandedBakes({ teardown: async () => ({ errors: ['VM 9001 is still on the cluster'] }) });
  await settle();

  const note = dbLog.find((c) => /SET error = left\(COALESCE\(error, ''\) \|\| \$2/.test(c.sql));
  assert.ok(note, 'the teardown failure never reached the row');
  assert.match(note.params[1], /VM 9001 is still on the cluster/);
});

test('the sweep survives the table not existing yet', async () => {
  // Plugin migrations run at boot but ordering across plugins is not guaranteed.
  dbRespond = () => { throw new Error('relation "ciab_profile_bake" does not exist'); };
  const result = await orch.recoverStrandedBakes();
  assert.deepStrictEqual(result, { interrupted: 0, never_started: 0, teardowns_scheduled: 0 });
});

test('VMIDs with no lane row are reported as an unrecoverable leak, not as cleaned', async () => {
  // teardownLanes returns immediately when laneIds is empty, so extraVmIds ALONE
  // are never destroyed — and a VMID with no lane row has no recorded node, so
  // nothing could place it anyway. Reporting success here would close the ticket
  // on a VM that is still running.
  const outcome = await orch.teardownStagingLane(
    { staging_lane_id: null, controller_vmid: 9001, golden_vmids: null },
    { teardown: async () => { throw new Error('must not be called'); } });
  assert.strictEqual(outcome.cleaned, false);
  assert.match(outcome.note, /9001/);
  assert.match(outcome.note, /by hand/);
});

// ---------------------------------------------------------------------------
// 6. The deploy gate
// ---------------------------------------------------------------------------

const CURRENT = { currentGoadRef: GOAD_REF, currentLabHash: HASH, profileId: P1 };

const readyBake = (over = {}) => bakeRow({
  status: 'ready',
  gate_solvable: true, gate_paper: true, gate_no_unintended: true,
  gates_approved_by: ACTOR, gates_approved_at: '2026-08-29T00:00:00Z',
  ...over,
});

const refusal = (code, re) => (err) =>
  err.status === 409 && err.code === code && (!re || re.test(err.message));

test('gate: nothing baked refuses and names the remedy', () => {
  assert.throws(() => orch.assertBakeDeployable(null, CURRENT),
    refusal('BAKE_NOT_BUILT', /Bake it first/));
});

test('gate: a bake still running refuses rather than waiting or half-deploying', () => {
  for (const status of ['pending', ...orch.ACTIVE_STATUSES]) {
    assert.throws(
      () => orch.assertBakeDeployable(bakeRow({ status, phase_detail: 'ansible 7/16' }), CURRENT),
      refusal('BAKE_IN_PROGRESS', /ansible 7\/16/),
      `status '${status}' must refuse`);
  }
});

test('gate: a failed bake quotes its reason and points at Re-bake', () => {
  assert.throws(
    () => orch.assertBakeDeployable(bakeRow({ status: 'failed', error: 'run.sh exited 2' }), CURRENT),
    refusal('BAKE_FAILED', /run\.sh exited 2/));
});

test('gate: a superseded bake refuses and points at the current one', () => {
  assert.throws(() => orch.assertBakeDeployable(bakeRow({ status: 'superseded' }), CURRENT),
    refusal('BAKE_SUPERSEDED', /CIAB-a1b2c3d4/));
});

test('gate: an unrecognised status is not a licence to deploy', () => {
  assert.throws(() => orch.assertBakeDeployable(bakeRow({ status: 'archived' }), CURRENT),
    refusal('BAKE_NOT_READY', /archived/));
});

test('gate: unapproved gates refuse and name the ones still outstanding', () => {
  // The playbooks report success whether or not they planted anything, so the
  // sign-off is the only evidence anyone checked.
  assert.throws(
    () => orch.assertBakeDeployable(
      bakeRow({ status: 'ready', gate_solvable: true, gate_paper: null, gate_no_unintended: false }), CURRENT),
    (err) => refusal('BAKE_GATES_NOT_APPROVED')(err)
      && /paper artefacts/.test(err.message)
      && /unintended/.test(err.message)
      && !/solve path/.test(err.message));
});

test('gate: three ticks with no approval stamp is still not approved', () => {
  // gates_approved_at is the single fact the gate reads, precisely so a row
  // cannot be approved by setting three booleans in a psql session.
  assert.throws(
    () => orch.assertBakeDeployable(readyBake({ gates_approved_at: null }), CURRENT),
    refusal('BAKE_GATES_NOT_APPROVED', /approval was never recorded/));
});

test('gate: a caller that cannot supply the current hashes is REFUSED, never waved through', () => {
  // "I could not check" and "there is no drift" must never be the same answer —
  // that is the whole difference between a gate and a decoration.
  assert.throws(() => orch.assertBakeDeployable(readyBake(), { currentGoadRef: GOAD_REF }),
    refusal('BAKE_DRIFT_UNKNOWN', /no compiled content hash/));
  assert.throws(() => orch.assertBakeDeployable(readyBake(), { currentLabHash: HASH }),
    refusal('BAKE_DRIFT_UNKNOWN', /no pinned GOAD ref/));
  assert.throws(() => orch.assertBakeDeployable(readyBake(), {}),
    refusal('BAKE_DRIFT_UNKNOWN'));
});

test('gate: a moved GOAD pin is toolchain drift and refuses', () => {
  assert.throws(
    () => orch.assertBakeDeployable(readyBake(), { ...CURRENT, currentGoadRef: GOAD_REF2 }),
    refusal('BAKE_TOOLCHAIN_DRIFT', /00e9b63e.*12345678/s));
});

test('gate: a profile edited since the bake is content drift and refuses', () => {
  // THE DRIFT DETECTION. Without it a deploy quietly hands students machines
  // that do not match the client they were briefed on, and nothing reports it.
  assert.throws(
    () => orch.assertBakeDeployable(readyBake(), { ...CURRENT, currentLabHash: HASH2 }),
    refusal('BAKE_CONTENT_DRIFT', /edited since/));
});

test('gate: every refusal carries a DISTINCT code', () => {
  // One code per remedy. Two refusals sharing a code means a UI cannot tell the
  // operator which button to press.
  const codes = [];
  const cases = [
    [null, CURRENT],
    [bakeRow({ status: 'provisioning' }), CURRENT],
    [bakeRow({ status: 'failed' }), CURRENT],
    [bakeRow({ status: 'superseded' }), CURRENT],
    [bakeRow({ status: 'archived' }), CURRENT],
    [bakeRow({ status: 'ready' }), CURRENT],
    [readyBake(), {}],
    [readyBake(), { ...CURRENT, currentGoadRef: GOAD_REF2 }],
    [readyBake(), { ...CURRENT, currentLabHash: HASH2 }],
  ];
  for (const [bake, ctx] of cases) {
    try { orch.assertBakeDeployable(bake, ctx); assert.fail('should have refused'); }
    catch (err) { assert.strictEqual(err.status, 409); codes.push(err.code); }
  }
  assert.strictEqual(new Set(codes).size, codes.length, `duplicate refusal code in ${codes.join(', ')}`);
});

test('gate: a ready, approved, current bake passes and is returned unchanged', () => {
  const bake = readyBake();
  assert.strictEqual(orch.assertBakeDeployable(bake, CURRENT), bake);
});

test('gate: a bake in flight in THIS process refuses even if the row says ready', async () => {
  // The row is written by the same process that is mid-capture; a caller reading
  // it between the ready write and the mutex release would otherwise deploy from
  // templates that are still being made.
  let release;
  const gate = new Promise((r) => { release = r; });
  const steps = noopSteps();
  const bake = readyBake({ bake_id: 'inflight-1' });
  steps.capture = () => gate;

  const running = orch.bakeProfile(bake, { steps, heartbeatMs: 0 });
  await settle(2);
  assert.throws(() => orch.assertBakeDeployable(bake, CURRENT), refusal('BAKE_IN_PROGRESS'));
  release();
  await running;
  assert.strictEqual(orch.assertBakeDeployable(bake, CURRENT), bake);
});

// ---------------------------------------------------------------------------
// 7. Creating: identical content is a no-op, an edit is a new row
// ---------------------------------------------------------------------------

test('an edited profile produces a NEW row and starts baking it', async () => {
  const inserted = bakeRow({ bake_id: 'new-1', lab_hash: HASH2, lab_name: 'CIAB-ffffffff' });
  dbRespond = (sql) => (/^INSERT INTO ciab_profile_bake/.test(sql) ? { rows: [inserted], rowCount: 1 } : null);

  const seen = [];
  const out = await orch.startBake({
    profileId: P1, labHash: HASH2, goadRef: GOAD_REF, manifestSha: 'sha256:m',
    spec: SPEC, actingUserId: ACTOR, steps: noopSteps(seen), heartbeatMs: 0,
  });
  await settle();

  assert.deepStrictEqual({ created: out.created, started: out.started }, { created: true, started: true });
  assert.strictEqual(out.bake.lab_hash, HASH2);
  assert.deepStrictEqual(seen, ['compile', 'push', 'provision', 'verify', 'capture']);
});

test('re-baking IDENTICAL content is a no-op that finds the existing row', async () => {
  // This is what UNIQUE (profile_id, lab_hash) buys, and it is what makes
  // "immutable versioned bakes" true rather than aspirational.
  const existing = bakeRow({ status: 'ready' });
  dbRespond = (sql) => {
    if (/^INSERT INTO ciab_profile_bake/.test(sql)) return { rows: [], rowCount: 0 };
    if (/^SELECT \* FROM ciab_profile_bake WHERE profile_id = \$1 AND lab_hash = \$2/.test(sql)) {
      return { rows: [existing], rowCount: 1 };
    }
    return null;
  };

  const seen = [];
  const out = await orch.startBake({
    profileId: P1, labHash: HASH, goadRef: GOAD_REF, manifestSha: 'sha256:m',
    spec: SPEC, steps: noopSteps(seen), heartbeatMs: 0,
  });
  await settle();

  assert.deepStrictEqual({ created: out.created, started: out.started }, { created: false, started: false });
  assert.strictEqual(out.bake.bake_id, existing.bake_id);
  assert.deepStrictEqual(seen, [], 'a repeated press must not re-run ninety minutes of work');
});

test('the insert resolves the collision in ONE statement', () => {
  // SELECT-then-INSERT would let two admins pressing Bake at the same instant
  // both read "no row", and the loser's INSERT raises 23505 — which carries no
  // `status`, so the route renders it as a 500.
  const src = fs.readFileSync(path.join(CIAB, 'utils', 'bake-orchestrator.js'), 'utf8');
  assert.match(src, /ON CONFLICT \(profile_id, lab_hash\) DO NOTHING/);
});

test('a failed bake is NOT auto-restarted by pressing Bake again', async () => {
  // Restarting is an operator's decision with its own confirmation. Auto-restart
  // on a repeated press re-runs ninety minutes because somebody double-clicked.
  dbRespond = (sql) => {
    if (/^INSERT INTO ciab_profile_bake/.test(sql)) return { rows: [], rowCount: 0 };
    if (/^SELECT \* FROM ciab_profile_bake WHERE profile_id = \$1 AND lab_hash = \$2/.test(sql)) {
      return { rows: [bakeRow({ status: 'failed', error: 'run.sh exited 2' })], rowCount: 1 };
    }
    return null;
  };
  const seen = [];
  const out = await orch.startBake({
    profileId: P1, labHash: HASH, goadRef: GOAD_REF, manifestSha: 'sha256:m',
    spec: SPEC, steps: noopSteps(seen), heartbeatMs: 0,
  });
  await settle();
  assert.strictEqual(out.started, false);
  assert.deepStrictEqual(seen, []);
});

test('identity is validated in JS first, with a distinct 400 code per problem', () => {
  // The CHECK constraints in the migration are backstops for a writer that is
  // not this module. A 23514 reaching a route renders as an unhandled 500
  // naming a constraint, in place of the 400 the route already knows how to make.
  const base = { profileId: P1, labHash: HASH, goadRef: GOAD_REF, manifestSha: 'sha256:m', spec: SPEC };
  const cases = [
    [{ profileId: null }, 'BAKE_PROFILE_REQUIRED'],
    [{ labHash: 'NOTHEX' }, 'BAKE_LAB_HASH_INVALID'],
    [{ labHash: 'abc' }, 'BAKE_LAB_HASH_INVALID'],
    [{ goadRef: 'main' }, 'BAKE_GOAD_REF_INVALID'],
    [{ goadRef: GOAD_REF.slice(0, 7) }, 'BAKE_GOAD_REF_INVALID'],
    [{ manifestSha: '' }, 'BAKE_MANIFEST_SHA_INVALID'],
    [{ spec: null }, 'BAKE_SPEC_INVALID'],
    [{ spec: [] }, 'BAKE_SPEC_INVALID'],
    [{ spec: { goad: { version: 'GOAD-Light' } } }, 'BAKE_SPEC_NO_LAB'],
    [{ spec: { ...SPEC, subnet_scheme: 'v9' } }, 'BAKE_SPEC_SCHEME_INVALID'],
    [{ spec: { ...SPEC, fixed_subnet: 42 } }, 'BAKE_SPEC_SUBNET_INVALID'],
  ];
  const codes = new Set();
  for (const [over, code] of cases) {
    assert.throws(() => orch.validateBakeIdentity({ ...base, ...over }),
      (err) => err.status === 400 && err.code === code,
      `${JSON.stringify(over)} should be ${code}`);
    codes.add(code);
  }
  // Eight distinct codes across eleven cases: the two hash rejections, the two
  // ref rejections and the two spec-shape rejections each share one remedy.
  assert.strictEqual(codes.size, 8);
  assert.doesNotThrow(() => orch.validateBakeIdentity(base));
});

// ---------------------------------------------------------------------------
// 8. Restarting
// ---------------------------------------------------------------------------

test('a restart is refused while one is running', async () => {
  dbRespond = (sql) => (/^SELECT \* FROM ciab_profile_bake WHERE bake_id = \$1/.test(sql)
    ? { rows: [bakeRow({ status: 'provisioning' })], rowCount: 1 } : null);
  await assert.rejects(() => orch.restartBake(bakeRow().bake_id, { steps: noopSteps() }),
    refusal('BAKE_IN_PROGRESS'));
});

test('a restart is refused for a healthy bake unless forced', async () => {
  // Re-baking identical content destroys golden templates lanes may be cloning
  // from, and produces the same content by definition — different content would
  // be a different row.
  dbRespond = (sql) => (/^SELECT \* FROM ciab_profile_bake WHERE bake_id = \$1/.test(sql)
    ? { rows: [bakeRow({ status: 'ready' })], rowCount: 1 } : null);
  await assert.rejects(() => orch.restartBake(bakeRow().bake_id, { steps: noopSteps() }),
    refusal('BAKE_ALREADY_READY'));
});

test('a restart clears the stamps AND the sign-off before rebuilding', async () => {
  // The gates approved a specific set of machines. A restart builds different
  // ones, and a sign-off that outlived the environment it signed off on is worse
  // than no sign-off at all.
  const failed = bakeRow({ status: 'failed', error: 'run.sh exited 2', gates_approved_at: '2026-08-01T00:00:00Z' });
  dbRespond = (sql) => {
    if (/^SELECT \* FROM ciab_profile_bake WHERE bake_id = \$1/.test(sql)) return { rows: [failed], rowCount: 1 };
    if (/SET status = 'pending'/.test(sql)) return { rows: [bakeRow({ status: 'pending' })], rowCount: 1 };
    return null;
  };
  await orch.restartBake(failed.bake_id, { steps: noopSteps(), heartbeatMs: 0 });
  await settle();

  const reset = dbLog.find((c) => /SET status = 'pending'/.test(c.sql));
  assert.ok(reset);
  for (const column of ['started_at', 'finished_at', 'gate_solvable', 'gate_paper', 'gate_no_unintended',
    'gates_approved_by', 'gates_approved_at']) {
    assert.match(reset.sql, new RegExp(`${column} = NULL`), `${column} must be cleared by a restart`);
  }
  assert.deepStrictEqual(statusSequence().slice(0, 2), ['pending', 'compiling'],
    'the restart must actually start the bake, not merely reset the row');
});

// ---------------------------------------------------------------------------
// 9. The gates writer
// ---------------------------------------------------------------------------

test('gates cannot be approved before the bake is ready', async () => {
  dbRespond = () => ({ rows: [bakeRow({ status: 'provisioning' })], rowCount: 1 });
  await assert.rejects(
    () => orch.approveBakeGates(bakeRow().bake_id, { gateSolvable: true, gatePaper: true, gateNoUnintended: true }),
    (err) => err.status === 409 && err.code === 'BAKE_NOT_READY');
});

test('the approval stamp is written only when all three gates pass', async () => {
  const ready = bakeRow({ status: 'ready' });
  dbRespond = (sql) => (/^SELECT/.test(sql) ? { rows: [ready], rowCount: 1 } : { rows: [ready], rowCount: 1 });

  await orch.approveBakeGates(ready.bake_id, { gateSolvable: true, gatePaper: true, gateNoUnintended: false, actingUserId: ACTOR });
  let write = dbLog.find((c) => /SET gate_solvable = \$2/.test(c.sql));
  assert.strictEqual(write.params[4], false, 'two of three must not stamp an approval');

  dbLog = [];
  await orch.approveBakeGates(ready.bake_id, { gateSolvable: true, gatePaper: true, gateNoUnintended: true, actingUserId: ACTOR });
  write = dbLog.find((c) => /SET gate_solvable = \$2/.test(c.sql));
  assert.strictEqual(write.params[4], true);
  assert.deepStrictEqual(write.params.slice(1, 4), [true, true, true]);
  // A partial review is still RECORDED — 'reviewed and rejected' (false) has to
  // stay distinguishable from 'never looked at' (null).
  assert.match(write.sql, /gate_solvable = \$2, gate_paper = \$3, gate_no_unintended = \$4/);
});

// ---------------------------------------------------------------------------
// 10. Pure helpers
// ---------------------------------------------------------------------------

test('the lab name is CIAB- plus eight hex, and refuses anything else', () => {
  // It becomes a directory name under ad/ on the controller and a key in
  // playbooks.yml. A digest carrying '/' or '+' would fail ninety minutes into
  // the bake as a path that does not exist.
  assert.strictEqual(orch.labNameForHash(HASH), 'CIAB-a1b2c3d4');
  assert.throws(() => orch.labNameForHash('A1B2C3D4'), /lowercase hex/);
  assert.throws(() => orch.labNameForHash('abc/def+'), /lowercase hex/);
  assert.throws(() => orch.labNameForHash(null), /lowercase hex/);
});

test('golden VMIDs are read from any of the three shapes a capture might report', () => {
  // Guessing one shape and failing quietly on the others is a silent storage
  // leak: teardown enumerates nothing and reports success.
  assert.deepStrictEqual(orch.vmidsFromGolden([9101, 9102]), [9101, 9102]);
  assert.deepStrictEqual(orch.vmidsFromGolden([{ vmid: 9101 }, { vm_id: 9102 }]), [9101, 9102]);
  assert.deepStrictEqual(orch.vmidsFromGolden({ DC01: 9101, SRV02: { vmid: 9102 } }), [9101, 9102]);
  assert.deepStrictEqual(orch.vmidsFromGolden(null), []);
  assert.deepStrictEqual(orch.vmidsFromGolden({ DC01: 'not-a-vmid', DC02: 0 }), []);
  // Deduped, and the controller leads because it is the one guaranteed to exist.
  assert.deepStrictEqual(
    orch.vmidsForTeardown({ controller_vmid: 9001, golden_vmids: [9101, 9101, 9001] }),
    [9001, 9101]);
});

test('a phase patch is checked against a whitelist, not a spread', () => {
  assert.strictEqual(orch.assertStepPatch(null, 'x'), null);
  assert.throws(() => orch.assertStepPatch('lane-1', 'the x phase'), /may only return an object/);
  assert.throws(() => orch.assertStepPatch([1], 'the x phase'), /an array/);
  assert.throws(() => orch.assertStepPatch({ nope: 1 }, 'the x phase'), /unknown column\(s\): nope/);
  for (const column of orch.STEP_PATCH_COLUMNS) {
    assert.doesNotThrow(() => orch.assertStepPatch({ [column]: null }, 'the x phase'));
  }
});

// ---------------------------------------------------------------------------
// 11. The migration and this module agree
// ---------------------------------------------------------------------------

/** The CREATE TABLE body, comments stripped. */
function createTableBody() {
  const start = MIGRATION.indexOf('CREATE TABLE IF NOT EXISTS ciab_profile_bake (');
  assert.ok(start !== -1, 'the migration must create ciab_profile_bake');
  const end = MIGRATION.indexOf('\n);', start);
  assert.ok(end !== -1, 'the CREATE TABLE never closed');
  return MIGRATION.slice(start, end);
}

/** Declared column names: two-space indent, lowercase identifier, a type after it. */
function declaredColumns() {
  return createTableBody().split('\n')
    .filter((l) => !l.trim().startsWith('--'))
    .map((l) => l.match(/^ {2}([a-z_][a-z0-9_]*)\s+[A-Za-z]/))
    .filter(Boolean)
    .map((m) => m[1]);
}

test('the migration is idempotent, because it re-runs on every single boot', () => {
  // src/plugin-loader.js sends each file as ONE pool.query per boot and catches
  // the failure with nothing but console.error.
  assert.match(MIGRATION, /CREATE TABLE IF NOT EXISTS ciab_profile_bake/);
  const creates = MIGRATION.match(/^CREATE (?:UNIQUE )?INDEX[^\n]*/gm) || [];
  assert.ok(creates.length >= 3, 'the indexes went missing');
  for (const line of creates) {
    assert.match(line, /IF NOT EXISTS/, `not idempotent: ${line}`);
  }
  assert.ok(!/\bDROP\b/.test(MIGRATION), 'a DROP in a file that re-runs every boot is a data loss waiting for a restart');
});

test('the status CHECK and BAKE_STATUSES are the same list', () => {
  // A status this module writes that the constraint rejects raises 23514, and a
  // pg error carries no `status`, so the route renders an unhandled 500 naming a
  // constraint instead of anything an operator can act on.
  const m = createTableBody().match(/CHECK \(status IN \(([^)]*)\)\)/s);
  assert.ok(m, 'status has no CHECK constraint');
  const declared = m[1].match(/'([a-z]+)'/g).map((s) => s.replace(/'/g, ''));
  assert.deepStrictEqual(declared.slice().sort(), orch.BAKE_STATUSES.slice().sort());
});

test('every phase status and every terminal status is in the vocabulary', () => {
  for (const phase of orch.PHASES) {
    assert.ok(orch.BAKE_STATUSES.includes(phase.status), `phase ${phase.step} writes an illegal status`);
    assert.ok(orch.ACTIVE_STATUSES.includes(phase.status), `phase ${phase.step} is not covered by the boot sweep`);
  }
  for (const s of orch.TERMINAL_STATUSES) assert.ok(orch.BAKE_STATUSES.includes(s));
  // Every legal status is accounted for exactly once: five phases, three
  // terminals, and 'pending'. A status belonging to neither group is one the
  // sweep would leave stranded forever.
  assert.deepStrictEqual(
    [...orch.ACTIVE_STATUSES, ...orch.TERMINAL_STATUSES, 'pending'].sort(),
    orch.BAKE_STATUSES.slice().sort());
});

test('the boot sweep index covers exactly the statuses the sweep looks for', () => {
  const m = MIGRATION.match(/idx_ciab_profile_bake_status[\s\S]*?WHERE status IN \(([^)]*)\)/);
  assert.ok(m, 'the partial index for the boot sweep is missing');
  const indexed = m[1].match(/'([a-z]+)'/g).map((s) => s.replace(/'/g, ''));
  assert.deepStrictEqual(indexed.slice().sort(), orch.ACTIVE_STATUSES.slice().sort());

  const src = fs.readFileSync(path.join(CIAB, 'utils', 'bake-orchestrator.js'), 'utf8');
  assert.ok(src.includes(`status IN ('compiling','pushing','provisioning','verifying','capturing')`),
    'the sweep statement must use the same list the partial index does, or it seq-scans');
});

test('UNIQUE (profile_id, lab_hash) is the version identity', () => {
  // Without it, re-baking identical content makes a second row, "immutable
  // versioned bakes" stops being true, and the ON CONFLICT in createBake has
  // nothing to conflict on — which makes the no-op an unhandled 23505 instead.
  assert.match(createTableBody(), /UNIQUE \(profile_id, lab_hash\)/);
});

test('rowToBake projects every column the migration declares', () => {
  // SELECT * hides the omission, because the database really does return the
  // column — the only place it disappears is here.
  const declared = declaredColumns();
  assert.ok(declared.length > 20, `the column parser found only ${declared.length} columns`);
  assert.deepStrictEqual(
    Object.keys(orch.rowToBake(Object.fromEntries(declared.map((c) => [c, null])))).sort(),
    declared.slice().sort());
});

test('every column a phase may write is a real column', () => {
  const declared = declaredColumns();
  for (const column of orch.STEP_PATCH_COLUMNS) {
    assert.ok(declared.includes(column), `${column} is not in ciab_profile_bake`);
  }
  for (const gate of orch.GATES) {
    assert.ok(declared.includes(gate.column), `${gate.column} is not in ciab_profile_bake`);
    assert.ok(gate.label.length > 15, `${gate.column} needs a label an operator can act on`);
  }
});

test('the gates are nullable, so "rejected" stays distinct from "never reviewed"', () => {
  for (const gate of orch.GATES) {
    const line = createTableBody().split('\n').find((l) => new RegExp(`^ {2}${gate.column}\\s`).test(l));
    assert.ok(line, `${gate.column} is not declared`);
    assert.ok(!/NOT NULL/.test(line) && !/DEFAULT/.test(line),
      `${gate.column} must stay nullable with no default: a NOT NULL DEFAULT FALSE collapses `
      + '"someone reviewed this and it failed" into "nobody has looked at it"');
  }
});
