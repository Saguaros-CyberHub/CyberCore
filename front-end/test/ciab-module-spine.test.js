/**
 * ciab-module-spine.test.js — Track D, phase D1: the properties of the module
 * spine that nothing else in this tree can catch.
 *
 * D1 ships three files and no routes, so there is no request to send and no
 * page to click. Everything worth pinning is therefore either a pure function's
 * behaviour or a fact about the TEXT of the files themselves, and each class of
 * assertion below exists because the alternative failure is silent:
 *
 *   THE VOCABULARY AGAINST THE CHECK CONSTRAINTS. Migration 014 is re-sent on
 *   every boot, and CREATE TABLE IF NOT EXISTS is a no-op on any deployment
 *   that has already run it. So a word added to module-states.js and forgotten
 *   in the constraint cannot be caught by a fresh-database test, a schema dump
 *   of a dev box, or code review of the migration — every one of those looks
 *   right. It surfaces as a 23514 the first time an instructor picks that word,
 *   in production, and nowhere else. The agreement is asserted in BOTH
 *   directions, from the comment-stripped migration text.
 *
 *   THE PROJECTION WHITELIST. A student's payload is built key by key rather
 *   than stripped, so the only way a column added by a later migration reaches
 *   a student is if somebody edits studentModuleView. Pinning
 *   Object.keys(...).sort() against the exported constant, with a fixture row
 *   that deliberately carries instructor_notes, release_state,
 *   cloned_from_module_id and a fabricated future column, turns that edit into
 *   a failing test instead of a leak nobody looks for.
 *
 *   THE GATE'S ORDER, AND ITS FAIL-CLOSED DIRECTION. evaluateGate is the
 *   smallest thing in the phase that can be wrong, and every one of its
 *   ambiguities is resolved toward "shut". The tests assert the direction, not
 *   just the value: an unrecognised release_state hides rather than opens, a
 *   dangling prerequisite locks rather than being dropped, and an instructor's
 *   unlock beats the window and the prerequisites but never a draft. A lock
 *   with no reason is separately impossible — asserted over every combination
 *   the fixture can produce, because an unactionable lock is a support ticket.
 *
 *   THE QUERY COUNTS. The two composed reads are the whole performance
 *   contract: fixed round trips, invariant under module count and roster size.
 *   An N+1 introduced later is invisible in review and shows up in production
 *   as "the instructor page is slow with a big class". Counted here, it is a
 *   number that changed.
 *
 *   THE MIGRATION'S SHAPE. The loader sends the whole file as ONE query — a
 *   single implicit transaction — console.warn()s any failure, and boots
 *   healthy anyway. One bare CREATE TABLE, one COMMIT, one CONCURRENTLY or one
 *   cross-database foreign key therefore leaves a server with NO D1 schema and
 *   nothing at all reporting it. These are text assertions because there is no
 *   runtime signal to assert on.
 *
 *   THE ZERO-BEHAVIOUR-CHANGE CLAIM. D1's exit criterion says the rest of the
 *   system is untouched, so the tests check that no route file and no boot hook
 *   has learned these modules' names, and that the wall clock is still read in
 *   exactly the two places the design says it is.
 *
 * No database and no cluster: ciab/utils/db.js is stubbed COMPLETELY through
 * require.cache before anything under test is required, the way
 * ciab-section-roster.test.js does it, and ./lane-reservation is stubbed the
 * same way so that even module-spine's deliberately lazy require costs nothing
 * and no test can reach Proxmox.
 *
 * Run: node --test "test/*.test.js"
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

// ── stubs, before anything under test is required ───────────────────────────

let dbCalls = [];
let dbHandler = () => ({ rows: [], rowCount: 0 });

// The WHOLE surface of ciab/utils/db.js. A partial stub leaves the real module
// loaded for whichever export was omitted, and that one pulls in a pool.
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (sql, params) => {
    dbCalls.push({ sql, params });
    return dbHandler(sql, params) || { rows: [], rowCount: 0 };
  },
  getPool: () => null,
  setPool: () => {},
  pool: null,
});

// ./lane-reservation requires the Proxmox client and the batch deployer at
// module scope. module-spine defers its require into one function for exactly
// that reason; stubbing it here means the deferral is also free under test, and
// lets the environment-key test prove the sanitizer was actually consulted.
let sanitizeCalls = [];
stub(path.join(CIAB, 'utils', 'lane-reservation.js'), {
  sanitizeEngagementType: (raw) => {
    sanitizeCalls.push(raw);
    const s = String(raw == null ? '' : raw).trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    return s ? s.slice(0, 32) : 'default';
  },
});

const spine = require(path.join(CIAB, 'utils', 'module-spine.js'));
const S = require(path.join(CIAB, 'utils', 'module-states.js'));
const { getPartName } = require(path.join(CIAB, 'utils', 'part-definitions.js'));

// ── file text, read once ────────────────────────────────────────────────────

const SPINE_FILE = path.join(CIAB, 'utils', 'module-spine.js');
const STATES_FILE = path.join(CIAB, 'utils', 'module-states.js');
const MIGRATION_FILE = path.join(CIAB, 'migrations', '014_ciab_modules.sql');

const read = (file) => fs.readFileSync(file, 'utf8');
const SPINE_SRC = read(SPINE_FILE);
const STATES_SRC = read(STATES_FILE);
const SQL_RAW = read(MIGRATION_FILE);

/** Line-oriented, and splitting on /\r?\n/ because this is a Windows checkout. */
const lines = (text) => text.split(/\r?\n/);

/**
 * The migration with every -- comment removed. Every structural assertion runs
 * against THIS, never the raw text: the header argues at length about the
 * neighbouring plugin, transactions and cascades, and a scan of the raw file
 * would be answered by the prose rather than by the DDL.
 */
const SQL_CODE = lines(SQL_RAW).map((line) => line.replace(/--.*$/, '')).join('\n');

/** JavaScript with block and line comments removed, for the same reason. */
function codeOnly(src) {
  return lines(src.replace(/\/\*[\s\S]*?\*\//g, ''))
    .map((line) => line.replace(/\/\/.*$/, ''))
    .join('\n');
}

/** One CREATE TABLE body, comment-free. `\b` stops ciab_module matching _prereq. */
function tableBody(name) {
  const at = SQL_CODE.search(new RegExp(`CREATE TABLE IF NOT EXISTS ${name}\\b`, 'i'));
  assert.ok(at >= 0, `migration 014 must declare ${name}`);
  const close = SQL_CODE.indexOf('\n);', at);
  assert.ok(close > at, `${name}'s declaration must be closed`);
  return SQL_CODE.slice(at, close);
}

/** The string literals inside one NAMED check constraint. */
function checkValues(constraintName) {
  const at = SQL_CODE.indexOf(constraintName);
  assert.ok(at >= 0, `migration 014 must name the constraint ${constraintName}`);
  const body = SQL_CODE.slice(at, SQL_CODE.indexOf('\n', SQL_CODE.indexOf(')', at)));
  return (body.match(/'([^']*)'/g) || []).map((q) => q.slice(1, -1));
}

// ── fixtures ────────────────────────────────────────────────────────────────

const SECTION_ID = '11111111-1111-4111-8111-111111111111';
const PROFILE_A = '22222222-2222-4222-8222-222222222222';
const PROFILE_B = '33333333-3333-4333-8333-333333333333';
const STUDENT = '44444444-4444-4444-8444-444444444444';
const STAFF = '55555555-5555-4555-8555-555555555555';

const NOW = Date.parse('2026-03-15T12:00:00.000Z');
const PAST = '2026-03-01T00:00:00.000Z';
const EARLIER = '2026-02-01T00:00:00.000Z';
const FUTURE = '2026-04-01T00:00:00.000Z';

const activeSection = () => ({
  section_id: SECTION_ID, name: 'Clinic', code: 'CYBR-480', term: 'SP26', status: 'active',
});

/** A ciab_module row with every column the loader selects. */
function mod(overrides) {
  return {
    module_id:             'm-1',
    section_id:            SECTION_ID,
    position:              1,
    title:                 'Scope the client',
    brief:                 'Read the engagement brief before you start.',
    instructor_notes:      'Swap the client next term.',
    profile_id:            null,
    engagement_type:       'default',
    assessment_part:       null,
    release_state:         'open',
    release_at:            null,
    close_at:              null,
    cloned_from_module_id: null,
    created_by:            STAFF,
    updated_by:            STAFF,
    created_at:            '2026-01-01T00:00:00.000Z',
    updated_at:            '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

/** A ciab_module_student row. */
function state(overrides) {
  return {
    module_id:        'm-1',
    user_id:          STUDENT,
    completion:       'auto',
    completed_at:     null,
    completed_by:     null,
    release_override: null,
    override_reason:  null,
    override_by:      null,
    override_at:      null,
    ...overrides,
  };
}

/** evaluateGate's argument, defaulted to the everything-is-fine case. */
function gateInput(overrides) {
  return {
    module: mod({}),
    phase: 'open',
    state: null,
    prereqs: [],
    cyclic: false,
    sectionActive: true,
    enrolled: true,
    ...overrides,
  };
}

const studentInput = (overrides) => ({
  section: activeSection(),
  enrolled: true,
  modules: [],
  edges: [],
  states: [],
  derivedCompleteIds: new Set(),
  now: NOW,
  ...overrides,
});

beforeEach(() => {
  dbCalls = [];
  sanitizeCalls = [];
  dbHandler = () => ({ rows: [], rowCount: 0 });
});

// ---------------------------------------------------------------------------
// The clock
// ---------------------------------------------------------------------------

test('D1: the resolver refuses to run without an injected clock', () => {
  for (const missing of [undefined, null, NaN, 'not a date', {}, []]) {
    assert.throws(
      () => spine.toMs(missing),
      (err) => err.status === 500 && /now is required/.test(err.message),
      `toMs(${JSON.stringify(missing)}) must refuse rather than default to now`
    );
  }
  assert.strictEqual(spine.toMs(new Date(NOW)), NOW);
  assert.strictEqual(spine.toMs(NOW), NOW);
  assert.strictEqual(spine.toMs('2026-03-15T12:00:00.000Z'), NOW);

  // And the refusal reaches the entry points, so no response can be built at
  // whatever instant each individual call happened to run at.
  assert.throws(() => spine.resolveForStudent(studentInput({ now: undefined })), /now is required/);
  assert.throws(
    () => spine.resolveForInstructor({ section: activeSection(), modules: [], edges: [], states: [], roster: [], derivedByUser: new Map() }),
    /now is required/
  );
});

test('D1: every module in one response is judged at the one injected instant', () => {
  const view = spine.resolveForStudent(studentInput({
    modules: [mod({ module_id: 'm-1' }), mod({ module_id: 'm-2', position: 2 })],
  }));
  assert.strictEqual(view.now, NOW);
});

test('D1: the wall clock is read in exactly two places, both composed reads', () => {
  const hits = lines(SPINE_SRC).filter((line) => /Date\.now\(\)/.test(line));
  assert.strictEqual(hits.length, 2,
    'a defaulting clock anywhere else silently un-pins every other test in this file');
  for (const line of hits) {
    assert.match(line, /\{\s*now\s*=\s*Date\.now\(\)\s*\}\s*=\s*\{\}/,
      'each must be the default of a composed read\'s options argument');
  }
  assert.ok(!/Date\.now\(\)/.test(STATES_SRC), 'the vocabulary file reads no clock at all');
});

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

test('D1: the module order is total, so "the next module" cannot flip between page loads', () => {
  const same = { position: 3, created_at: '2026-01-01T00:00:00.000Z' };
  const a = mod({ module_id: 'aaa', ...same });
  const b = mod({ module_id: 'bbb', ...same });

  assert.strictEqual(spine.compareModules(a, b), -1);
  assert.strictEqual(spine.compareModules(b, a), 1);
  assert.strictEqual(spine.compareModules(a, a), 0);
  assert.deepStrictEqual(spine.sortModules([b, a]).map((m) => m.module_id), ['aaa', 'bbb']);
  assert.deepStrictEqual(spine.sortModules([a, b]).map((m) => m.module_id), ['aaa', 'bbb']);

  // position first, then created_at, then id — and a non-finite position is 0.
  const ordered = spine.sortModules([
    mod({ module_id: 'z', position: 2, created_at: EARLIER }),
    mod({ module_id: 'y', position: 1, created_at: FUTURE }),
    mod({ module_id: 'x', position: null, created_at: PAST }),
    mod({ module_id: 'w', position: 2, created_at: PAST }),
    mod({ module_id: 'v', position: 2, created_at: 'not a date' }),
  ]).map((m) => m.module_id);
  assert.deepStrictEqual(ordered, ['x', 'y', 'z', 'w', 'v'],
    'an unparseable created_at sorts LAST rather than jumping to the front');
});

test('D1: sortModules returns a new array, and the SQL order names the same three keys', async () => {
  const input = [mod({ module_id: 'b', position: 2 }), mod({ module_id: 'a', position: 1 })];
  const snapshot = input.map((m) => m.module_id);
  const sorted = spine.sortModules(input);
  assert.notStrictEqual(sorted, input);
  assert.deepStrictEqual(input.map((m) => m.module_id), snapshot, 'the caller\'s array is untouched');

  await spine.loadModules(SECTION_ID);
  assert.match(dbCalls[0].sql, /ORDER BY position, created_at, module_id/,
    'the database path and the pure path must not be able to disagree');
});

// ---------------------------------------------------------------------------
// The prerequisite graph
// ---------------------------------------------------------------------------

test('D1: a cycle and everything downstream of it are both reported as cyclic', () => {
  const modules = ['a', 'b', 'c', 'd', 'e'].map((id, i) => mod({ module_id: id, position: i + 1 }));
  const edges = [
    { module_id: 'b', prereq_module_id: 'a' },
    { module_id: 'c', prereq_module_id: 'b' },
    { module_id: 'a', prereq_module_id: 'c' },  // closes A -> B -> C -> A
    { module_id: 'd', prereq_module_id: 'c' },  // merely downstream
  ];
  const graph = spine.buildGraph(modules, edges);
  assert.deepStrictEqual([...graph.cyclicIds].sort(), ['a', 'b', 'c', 'd'],
    'a module that can never unlock must not be reported as merely waiting');
  assert.ok(!graph.cyclicIds.has('e'));
  assert.deepStrictEqual(graph.requiresById.get('b'), ['a']);
  assert.deepStrictEqual(graph.dependentsById.get('c'), ['a', 'd']);

  // Deterministic regardless of the order the rows arrived in.
  const shuffled = spine.buildGraph([...modules].reverse(), [...edges].reverse());
  assert.deepStrictEqual([...shuffled.cyclicIds].sort(), [...graph.cyclicIds].sort());
});

test('D1: cycle detection is iterative, so a malformed graph cannot blow the stack', () => {
  const size = 20000;
  const modules = [];
  const edges = [];
  for (let i = 0; i < size; i += 1) {
    modules.push(mod({ module_id: `m-${i}`, position: i }));
    if (i > 0) edges.push({ module_id: `m-${i}`, prereq_module_id: `m-${i - 1}` });
  }
  const graph = spine.buildGraph(modules, edges);
  assert.strictEqual(graph.cyclicIds.size, 0);

  edges.push({ module_id: 'm-0', prereq_module_id: `m-${size - 1}` });
  const looped = spine.buildGraph(modules, edges);
  assert.strictEqual(looped.cyclicIds.size, size,
    'a RangeError out of a page-data builder is a 500 on a page a student is reading');
});

test('D1: a prerequisite naming a module outside the section is kept, never dropped', () => {
  const graph = spine.buildGraph(
    [mod({ module_id: 'a' }), mod({ module_id: 'b', position: 2 })],
    [{ module_id: 'b', prereq_module_id: 'ghost' }]
  );
  assert.deepStrictEqual(graph.dangling, [{ module_id: 'b', prereq_module_id: 'ghost' }]);
  assert.deepStrictEqual(graph.requiresById.get('b'), ['ghost'],
    'dropping the edge would silently OPEN the module it was gating');
  assert.strictEqual(graph.cyclicIds.size, 0, 'an unresolvable edge is not a cycle');
});

test('D1: duplicate positions are collected once, in position order', () => {
  const graph = spine.buildGraph([
    mod({ module_id: 'a', position: 2 }),
    mod({ module_id: 'b', position: 1 }),
    mod({ module_id: 'c', position: 2 }),
    mod({ module_id: 'd', position: 1 }),
  ], []);
  assert.deepStrictEqual(graph.duplicatePositions, [
    { position: 1, module_ids: ['b', 'd'] },
    { position: 2, module_ids: ['a', 'c'] },
  ]);
});

// ---------------------------------------------------------------------------
// Release phase
// ---------------------------------------------------------------------------

test('D1: every release ambiguity resolves toward closed', () => {
  // 'scheduled' with no release time never opens.
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'scheduled', release_at: null }), NOW), 'pending');
  // A word no build of this file knows hides the module rather than publishing it.
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'published' }), NOW), 'draft');
  assert.strictEqual(spine.releasePhase(mod({ release_state: null }), NOW), 'draft');
  assert.strictEqual(spine.releasePhase(mod({ release_state: undefined }), NOW), 'draft');
  // An inverted window resolves closed, not open.
  assert.strictEqual(
    spine.releasePhase(mod({ release_state: 'open', release_at: PAST, close_at: EARLIER }), NOW),
    'closed'
  );
  // And a close_at exactly at `now` is already closed.
  assert.strictEqual(
    spine.releasePhase(mod({ release_state: 'open', close_at: new Date(NOW).toISOString() }), NOW),
    'closed'
  );
  for (const phase of ['draft', 'archived', 'closed']) {
    assert.strictEqual(spine.releasePhase(mod({ release_state: phase, release_at: PAST }), NOW), phase);
  }
});

test('D1: a release time in the future is pending and one in the past is open', () => {
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'open', release_at: FUTURE }), NOW), 'pending');
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'open', release_at: PAST }), NOW), 'open');
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'open', release_at: null }), NOW), 'open');
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'scheduled', release_at: FUTURE }), NOW), 'pending');
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'scheduled', release_at: PAST }), NOW), 'open');
  for (const phase of S.RELEASE_PHASES) assert.ok(S.isReleasePhase(phase));
  assert.ok(!S.isReleasePhase('scheduled'), 'an intent can never be an answer');
});

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

test('D1: a module on a prerequisite cycle locks rather than opens', () => {
  const gate = spine.evaluateGate(gateInput({ cyclic: true }));
  assert.strictEqual(gate.access, 'locked');
  assert.deepStrictEqual(gate.reasons.map((r) => r.code), [S.REASON.PREREQ_CYCLE]);
  assert.strictEqual(gate.reasons[0].message, S.MESSAGE.PREREQ_CYCLE);
});

test('D1: an unresolvable prerequisite locks the module it was gating', () => {
  const gate = spine.evaluateGate(gateInput({
    prereqs: [{ module_id: 'ghost', title: null, position: null, satisfied: false, missing: true }],
  }));
  assert.strictEqual(gate.access, 'locked');
  assert.deepStrictEqual(gate.reasons.map((r) => r.code), [S.REASON.PREREQ_MISSING]);
});

test('D1: waived satisfies a prerequisite exactly as complete does, and incomplete does not', () => {
  assert.ok(S.satisfiesPrereq('complete'));
  assert.ok(S.satisfiesPrereq('waived'));
  assert.ok(!S.satisfiesPrereq('incomplete'));
  assert.ok(!S.satisfiesPrereq('auto'));
  assert.ok(!S.satisfiesPrereq(undefined));

  const modules = [mod({ module_id: 'first' }), mod({ module_id: 'second', position: 2 })];
  const edges = [{ module_id: 'second', prereq_module_id: 'first' }];
  const secondAccess = (completion) => spine.resolveForStudent(studentInput({
    modules, edges, states: [state({ module_id: 'first', completion })],
  })).modules.find((m) => m.module_id === 'second').access;

  assert.strictEqual(secondAccess('complete'), 'open');
  assert.strictEqual(secondAccess('waived'), 'open');
  assert.strictEqual(secondAccess('incomplete'), 'locked');
  assert.strictEqual(secondAccess('auto'), 'locked');
});

test('D1: an instructor unlock beats the window and the prerequisites, and says so', () => {
  const unlocked = { release_override: 'unlock' };
  for (const scenario of [
    { phase: 'pending' },
    { phase: 'closed' },
    { prereqs: [{ module_id: 'first', title: 'First', position: 1, satisfied: false, missing: false }] },
    { prereqs: [{ module_id: 'ghost', title: null, position: null, satisfied: false, missing: true }] },
    { cyclic: true },
  ]) {
    const gate = spine.evaluateGate(gateInput({ ...scenario, state: state(unlocked) }));
    assert.strictEqual(gate.access, 'open', `unlock must beat ${JSON.stringify(scenario)}`);
    assert.deepStrictEqual(gate.reasons, []);
    assert.deepStrictEqual(gate.advisories.map((a) => a.code), [S.ADVISORY.INSTRUCTOR_UNLOCKED]);
    assert.strictEqual(gate.advisories[0].message, S.MESSAGE.INSTRUCTOR_UNLOCKED);
  }
});

test('D1: an instructor lock beats an otherwise open module and shows its own reason', () => {
  const gate = spine.evaluateGate(gateInput({
    state: state({ release_override: 'lock', override_reason: 'Academic integrity hold.' }),
  }));
  assert.strictEqual(gate.access, 'locked');
  assert.deepStrictEqual(gate.reasons.map((r) => r.code), [S.REASON.INSTRUCTOR_LOCKED]);
  assert.strictEqual(gate.reasons[0].message, 'Academic integrity hold.');

  const noReason = spine.evaluateGate(gateInput({ state: state({ release_override: 'lock' }) }));
  assert.strictEqual(noReason.reasons[0].message, S.MESSAGE.INSTRUCTOR_LOCKED);
});

test('D1: no override can beat a draft, an archived module or an archived section', () => {
  for (const override of ['unlock', 'lock']) {
    const st = state({ release_override: override });
    assert.strictEqual(spine.evaluateGate(gateInput({ phase: 'draft', state: st })).access, 'hidden');
    assert.strictEqual(spine.evaluateGate(gateInput({ phase: 'archived', state: st })).access, 'hidden');

    const archivedSection = spine.evaluateGate(gateInput({ sectionActive: false, state: st }));
    assert.strictEqual(archivedSection.access, 'locked');
    assert.deepStrictEqual(archivedSection.reasons.map((r) => r.code), [S.REASON.SECTION_ARCHIVED]);

    const stranger = spine.evaluateGate(gateInput({ enrolled: false, state: st }));
    assert.strictEqual(stranger.access, 'locked');
    assert.deepStrictEqual(stranger.reasons.map((r) => r.code), [S.REASON.NOT_ENROLLED]);
  }
});

test('D1: archiving a section revokes, and only an active enrollment grants', async () => {
  const view = spine.resolveForStudent(studentInput({
    section: { ...activeSection(), status: 'archived' },
    modules: [mod({ module_id: 'a' }), mod({ module_id: 'b', position: 2 })],
  }));
  assert.deepStrictEqual(
    view.modules.map((m) => [m.access, m.reasons[0].code]),
    [['locked', S.REASON.SECTION_ARCHIVED], ['locked', S.REASON.SECTION_ARCHIVED]]
  );
  assert.strictEqual(spine.resolveForStudent(studentInput({ section: null, modules: [mod({})] }))
    .modules[0].reasons[0].code, S.REASON.SECTION_ARCHIVED);

  // The join is what makes 'archive' more than a label, and the enrollment
  // predicate names 'active' and nothing else — 'completed' must not grant.
  await spine.loadSectionForStudent(SECTION_ID, STUDENT);
  const sql = dbCalls[0].sql;
  assert.match(sql, /FROM ciab_section/);
  assert.match(sql, /e\.status\s*=\s*'active'/);
  assert.ok(!/completed/.test(sql), 'an end-of-term roster must not silently keep access');
  assert.ok(!/WHERE[\s\S]*s\.status/.test(sql),
    'the section status is RETURNED so archived stays distinguishable from missing');
  assert.match(sql, /e\.section_id\s*=\s*s\.section_id/,
    'the enrollment must be on THIS section — enrollment.isEnrolled(userId) answers "any active '
    + 'enrollment on ANY active section", which would let any enrolled student in the school read '
    + 'any other section\'s modules');
  assert.deepStrictEqual(dbCalls[0].params, [SECTION_ID, STUDENT]);
});

test('D1: a lock is never handed to a student without a reason', () => {
  const phases = S.RELEASE_PHASES;
  const overrides = [null, 'unlock', 'lock'];
  const prereqSets = [
    [],
    [{ module_id: 'p', title: 'P', position: 1, satisfied: true, missing: false }],
    [{ module_id: 'p', title: 'P', position: 1, satisfied: false, missing: false }],
    [{ module_id: 'ghost', title: null, position: null, satisfied: false, missing: true }],
  ];
  let combinations = 0;

  for (const sectionActive of [true, false]) {
    for (const enrolled of [true, false]) {
      for (const phase of phases) {
        for (const override of overrides) {
          for (const prereqs of prereqSets) {
            for (const cyclic of [true, false]) {
              combinations += 1;
              const gate = spine.evaluateGate(gateInput({
                phase, prereqs, cyclic, sectionActive, enrolled,
                state: override ? state({ release_override: override }) : null,
              }));
              assert.ok(S.isAccessState(gate.access), `invented access state ${gate.access}`);
              if (gate.access === 'open') {
                assert.deepStrictEqual(gate.reasons, [], 'an open module explains nothing');
              } else {
                assert.ok(gate.reasons.length > 0,
                  `a ${gate.access} with no reason is unactionable in a UI`);
                for (const reason of gate.reasons) {
                  assert.ok(S.REASON[reason.code], `unknown reason code ${reason.code}`);
                  assert.ok(typeof reason.message === 'string' && reason.message.length > 0);
                  assert.ok('detail' in reason);
                }
              }
              for (const advisory of gate.advisories) {
                assert.ok(S.ADVISORY[advisory.code], `unknown advisory code ${advisory.code}`);
              }
            }
          }
        }
      }
    }
  }
  assert.strictEqual(combinations, 480, 'the sweep must actually cover the cross product');
});

test('D1: the release window outranks an unmet prerequisite, and carries its date', () => {
  const blocking = [{ module_id: 'first', title: 'First', position: 1, satisfied: false, missing: false }];
  const closed = spine.evaluateGate(gateInput({
    module: mod({ close_at: PAST }), phase: 'closed', prereqs: blocking,
  }));
  assert.strictEqual(closed.access, 'closed');
  assert.deepStrictEqual(closed.reasons.map((r) => r.code), [S.REASON.MODULE_CLOSED]);
  assert.deepStrictEqual(closed.reasons[0].detail, { close_at: PAST });

  const pending = spine.evaluateGate(gateInput({
    module: mod({ release_at: FUTURE }), phase: 'pending', prereqs: blocking,
  }));
  assert.strictEqual(pending.access, 'locked');
  assert.deepStrictEqual(pending.reasons.map((r) => r.code), [S.REASON.NOT_YET_RELEASED]);
  assert.deepStrictEqual(pending.reasons[0].detail, { release_at: FUTURE });

  const gated = spine.evaluateGate(gateInput({ prereqs: blocking }));
  assert.deepStrictEqual(gated.reasons.map((r) => r.code), [S.REASON.PREREQ_INCOMPLETE]);
  assert.deepStrictEqual(gated.reasons[0].detail, {
    blocking: [{ module_id: 'first', title: 'First', position: 1 }],
  });
});

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------

test('D1: the stored decision outranks the derived signal in both directions', () => {
  assert.deepStrictEqual(spine.resolveCompletion(state({ completion: 'incomplete' }), true),
    { completion: 'incomplete', source: 'decision' });
  assert.deepStrictEqual(spine.resolveCompletion(state({ completion: 'complete' }), false),
    { completion: 'complete', source: 'decision' });
  assert.deepStrictEqual(spine.resolveCompletion(state({ completion: 'waived' }), false),
    { completion: 'waived', source: 'decision' });

  assert.deepStrictEqual(spine.resolveCompletion(state({}), true),
    { completion: 'complete', source: 'derived' });
  assert.deepStrictEqual(spine.resolveCompletion(state({}), false),
    { completion: 'incomplete', source: 'derived' });
  assert.deepStrictEqual(spine.resolveCompletion(state({}), null),
    { completion: 'incomplete', source: 'default' });
  assert.deepStrictEqual(spine.resolveCompletion(null, undefined),
    { completion: 'incomplete', source: 'default' });

  for (const source of ['decision', 'derived', 'default']) {
    assert.ok(S.COMPLETION_SOURCES.includes(source));
  }
  assert.ok(!S.isCompletion('auto'), '"auto" is an input, never an answer');
  assert.ok(S.isCompletionDecision('auto'), 'but clearing a decision is a legitimate write');
});

test('D1: a missing per-student row is exactly a row holding every default', () => {
  assert.deepStrictEqual(spine.rowToStudentState(null), { ...S.DEFAULT_STUDENT_STATE });
  assert.notStrictEqual(spine.rowToStudentState(null), S.DEFAULT_STUDENT_STATE,
    'the default is copied, so a caller cannot annotate a frozen singleton');

  const modules = [mod({ module_id: 'a' }), mod({ module_id: 'b', position: 2 })];
  const sparse = spine.resolveForStudent(studentInput({ modules }));
  const materialised = spine.resolveForStudent(studentInput({
    modules,
    states: [state({ module_id: 'a' }), state({ module_id: 'b' })],
  }));
  assert.deepStrictEqual(sparse, materialised,
    'pre-creating a row per student is the anti-pattern this table exists to avoid');
});

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

/** STUDENT_VIEW_KEYS, sorted, without mutating the frozen export. */
const sortedViewKeys = () => [...spine.STUDENT_VIEW_KEYS].sort();

test('D1: a student is handed exactly STUDENT_VIEW_KEYS and nothing a migration adds', () => {
  const row = {
    ...mod({ profile_id: PROFILE_A, assessment_part: 2, cloned_from_module_id: 'm-0' }),
    future_column_a_later_migration: 'a column nobody has written yet',
  };
  const view = spine.studentModuleView({
    module: row,
    gate: { access: 'open', reasons: [], advisories: [] },
    completion: 'incomplete',
    completionSource: 'default',
  });

  assert.ok(Object.isFrozen(spine.STUDENT_VIEW_KEYS));
  assert.deepStrictEqual([...spine.STUDENT_VIEW_KEYS], sortedViewKeys(),
    'the exported constant is itself sorted, so the comparison below cannot pass by luck');
  assert.deepStrictEqual(Object.keys(view).sort(), sortedViewKeys());
  for (const forbidden of [
    'instructor_notes', 'release_state', 'cloned_from_module_id', 'section_id',
    'created_by', 'updated_by', 'created_at', 'updated_at', 'future_column_a_later_migration',
  ]) {
    assert.ok(!(forbidden in view), `${forbidden} must never reach a student`);
  }

  // And the same holds through the whole entry point, where the row really comes
  // from the database.
  const resolved = spine.resolveForStudent(studentInput({ modules: [row] }));
  assert.deepStrictEqual(Object.keys(resolved.modules[0]).sort(), sortedViewKeys());
  assert.ok(!JSON.stringify(resolved).includes('nobody has written yet'));
  assert.ok(!JSON.stringify(resolved).includes('Swap the client next term'));
});

test('D1: the brief is gated on the server, not by the browser hiding it', () => {
  const module = mod({ brief: 'The client runs an unpatched file server.' });
  const briefFor = (access) => spine.studentModuleView({
    module,
    gate: { access, reasons: [], advisories: [] },
    completion: 'incomplete',
    completionSource: 'default',
  }).brief;

  assert.strictEqual(briefFor('open'), module.brief);
  assert.strictEqual(briefFor('closed'), module.brief);
  assert.strictEqual(briefFor('locked'), null);
  assert.strictEqual(briefFor('hidden'), null);

  const upcoming = spine.resolveForStudent(studentInput({
    modules: [mod({ release_state: 'scheduled', release_at: FUTURE })],
  })).modules[0];
  assert.strictEqual(upcoming.access, 'locked');
  assert.strictEqual(upcoming.brief, null, 'next week\'s brief must not be readable from the network tab');
  assert.strictEqual(upcoming.title, 'Scope the client', 'the title and the date still ship');
  assert.strictEqual(upcoming.release_at, FUTURE);
});

test('D1: a draft module\'s id never crosses the wire, for anybody', () => {
  const modules = [
    mod({ module_id: 'published-1' }),
    mod({ module_id: 'draft-secret', position: 2, release_state: 'draft', title: 'UNRELEASED Tabletop' }),
    mod({ module_id: 'archived-secret', position: 3, release_state: 'archived' }),
  ];

  const enrolled = spine.resolveForStudent(studentInput({ modules }));
  assert.deepStrictEqual(enrolled.modules.map((m) => m.module_id), ['published-1']);
  assert.strictEqual(enrolled.counts.total, 1);
  const payload = JSON.stringify(enrolled);
  assert.ok(!payload.includes('draft-secret') && !payload.includes('archived-secret'),
    'an id alone is enough to guess a URL');

  // Including for the student the caller is about to refuse, and for a student
  // on a section that has since been archived: both still receive a payload.
  for (const input of [
    studentInput({ modules, enrolled: false }),
    studentInput({ modules, section: { ...activeSection(), status: 'archived' } }),
  ]) {
    const refused = spine.resolveForStudent(input);
    const text = JSON.stringify(refused);
    assert.ok(!text.includes('draft-secret') && !text.includes('archived-secret'),
      'a refused reader must not learn which modules exist');
  }

  // AND THROUGH THE PREREQUISITE GRAPH, which is the door the three scenarios
  // above cannot see: an edge from a PUBLISHED module to a draft one is a legal
  // row, and resolving it by name puts the draft's id and title straight into
  // the gated module's PREREQ_INCOMPLETE detail — one field over from the drop
  // that is supposed to make a draft unknowable.
  for (const secret of ['draft-secret', 'archived-secret']) {
    const gated = spine.resolveForStudent(studentInput({
      modules, edges: [{ module_id: 'published-1', prereq_module_id: secret }],
    }));
    const text = JSON.stringify(gated);
    assert.ok(!text.includes(secret), `a prerequisite is not a back door to ${secret}`);
    assert.ok(!text.includes('UNRELEASED'), 'nor to its title');

    const blocked = gated.modules.find((m) => m.module_id === 'published-1');
    assert.strictEqual(blocked.access, 'locked', 'and it still fails closed');
    assert.deepStrictEqual(blocked.reasons.map((r) => r.code), [S.REASON.PREREQ_MISSING],
      'PREREQ_INCOMPLETE would tell them to finish a module absent from their own list, '
      + 'which can never clear');
    assert.strictEqual(blocked.reasons[0].detail, null, 'and it names nothing at all');
  }

  // The instructor, who can fix it, still gets the whole picture.
  const staffView = spine.resolveForInstructor({
    section: activeSection(),
    modules,
    edges: [{ module_id: 'published-1', prereq_module_id: 'draft-secret' }],
    states: [], roster: ['u-0'], derivedByUser: new Map(), now: NOW,
  });
  assert.deepStrictEqual(
    staffView.modules.find((m) => m.module_id === 'published-1').requires_module_ids,
    ['draft-secret']
  );
});

test('D1: eligibility is supplied by the caller and never inferred', () => {
  const modules = [mod({ module_id: 'a' }), mod({ module_id: 'b', position: 2 })];
  const stranger = spine.resolveForStudent(studentInput({ modules, enrolled: false }));

  assert.strictEqual(stranger.enrolled, false, 'echoed so a route can 403 without re-asking');
  assert.strictEqual(stranger.modules.length, 2);
  for (const view of stranger.modules) {
    assert.strictEqual(view.access, 'locked');
    assert.deepStrictEqual(view.reasons.map((r) => r.code), [S.REASON.NOT_ENROLLED]);
    assert.strictEqual(view.brief, null);
  }
  assert.strictEqual(stranger.next_module_id, null);

  // Omitting it is not "probably enrolled".
  const omitted = spine.resolveForStudent({
    section: activeSection(), modules, edges: [], states: [], derivedCompleteIds: new Set(), now: NOW,
  });
  assert.strictEqual(omitted.enrolled, false);
});

test('D1: next_module_id is the first open module that is not already done', () => {
  const modules = [
    mod({ module_id: 'a', position: 1 }),
    mod({ module_id: 'b', position: 2 }),
    mod({ module_id: 'c', position: 3 }),
  ];
  const view = spine.resolveForStudent(studentInput({
    modules,
    states: [state({ module_id: 'a', completion: 'complete' })],
  }));
  assert.strictEqual(view.next_module_id, 'b');
  assert.deepStrictEqual(view.counts, { total: 3, open: 3, locked: 0, closed: 0 });

  const done = spine.resolveForStudent(studentInput({
    modules,
    states: modules.map((m) => state({ module_id: m.module_id, completion: 'waived' })),
  }));
  assert.strictEqual(done.next_module_id, null);
});

test('D1: rowToModule whitelists its columns, so a later migration cannot leak through it', () => {
  assert.strictEqual(spine.rowToModule(null), null);
  assert.strictEqual(spine.rowToModule(undefined), null);

  const mapped = spine.rowToModule({ ...mod({}), score: 99, environment_policy: 'deploy' });
  assert.ok(!('score' in mapped) && !('environment_policy' in mapped));
  assert.deepStrictEqual(Object.keys(mapped), [
    'module_id', 'section_id', 'position', 'title', 'brief', 'instructor_notes',
    'profile_id', 'engagement_type', 'assessment_part',
    'release_state', 'release_at', 'close_at',
    'cloned_from_module_id', 'created_by', 'updated_by', 'created_at', 'updated_at',
  ]);

  const st = spine.rowToStudentState({ ...state({}), feedback: 'nice work' });
  assert.ok(!('feedback' in st));
});

// ---------------------------------------------------------------------------
// Environment and evidence
// ---------------------------------------------------------------------------

test('D1: two modules against one client and one engagement share a visible environment', () => {
  const modules = [
    mod({ module_id: 'scope', position: 1, profile_id: PROFILE_A, engagement_type: 'external' }),
    mod({ module_id: 'report', position: 2, profile_id: PROFILE_A, engagement_type: 'external' }),
    mod({ module_id: 'other', position: 3, profile_id: PROFILE_B, engagement_type: 'external' }),
  ];
  assert.strictEqual(spine.environmentKeyOf(modules[0]), spine.environmentKeyOf(modules[1]));
  assert.notStrictEqual(spine.environmentKeyOf(modules[0]), spine.environmentKeyOf(modules[2]));

  const groups = spine.groupByEnvironment(modules);
  assert.strictEqual(groups.size, 2);
  assert.deepStrictEqual(
    groups.get(`${PROFILE_A}:external`).map((m) => m.module_id), ['scope', 'report']
  );

  const view = spine.resolveForInstructor({
    section: activeSection(), modules, edges: [], states: [], roster: [], derivedByUser: new Map(), now: NOW,
  });
  const scope = view.modules.find((m) => m.module_id === 'scope');
  assert.deepStrictEqual(scope.shares_environment_with, ['report'],
    'D5 must be able to refcount before it tears anything down');
  assert.deepStrictEqual(
    view.modules.find((m) => m.module_id === 'other').shares_environment_with, []
  );

  const shared = view.issues.filter((i) => i.code === S.ISSUE.SHARED_ENVIRONMENT);
  assert.strictEqual(shared.length, 1);
  assert.strictEqual(shared[0].severity, 'info');
  assert.deepStrictEqual(shared[0].detail, {
    environment_key: `${PROFILE_A}:external`,
    module_ids: ['scope', 'report'],
  });
});

test('D1: an environment key is never invented, and never trusted as stored', () => {
  assert.strictEqual(spine.environmentKeyOf(mod({ profile_id: null })), null);
  assert.strictEqual(spine.environmentKeyOf(null), null);
  assert.strictEqual(spine.groupByEnvironment([mod({ profile_id: null })]).size, 0);

  // Not derived from the section, and not from any other column.
  const key = spine.environmentKeyOf(mod({ profile_id: PROFILE_A, engagement_type: '  External Test! ' }));
  assert.ok(!key.includes(SECTION_ID));
  assert.strictEqual(key, `${PROFILE_A}:externaltest`);
  assert.deepStrictEqual(sanitizeCalls, ['  External Test! '],
    'a hand-inserted row must not alias onto a key it does not name');

  assert.strictEqual(
    spine.environmentKeyOf(mod({ profile_id: PROFILE_A, engagement_type: null })),
    `${PROFILE_A}:default`
  );
});

test('D1: the evidence key needs both halves, and takes its name from the definitions', () => {
  assert.strictEqual(spine.evidenceKeyFor(mod({ profile_id: PROFILE_A, assessment_part: null })), null);
  assert.strictEqual(spine.evidenceKeyFor(mod({ profile_id: null, assessment_part: 2 })), null);
  assert.strictEqual(spine.evidenceKeyFor(null), null);

  assert.deepStrictEqual(spine.evidenceKeyFor(mod({ profile_id: PROFILE_A, assessment_part: 2 })), {
    profile_id: PROFILE_A,
    part_number: 2,
    part_name: getPartName(2),
  });

  // A stored label is never consulted — assessment_progress.part_name is
  // untrustworthy, which is why routes/progress.js re-derives it too.
  const withLabel = spine.evidenceKeyFor(
    mod({ profile_id: PROFILE_A, assessment_part: 2, part_name: 'Whatever The Row Says' })
  );
  assert.strictEqual(withLabel.part_name, getPartName(2));
  assert.notStrictEqual(withLabel.part_name, 'Whatever The Row Says');
});

// ---------------------------------------------------------------------------
// Section issues
// ---------------------------------------------------------------------------

test('D1: every configuration error a student cannot act on is raised, with its severity', () => {
  const modules = [
    mod({ module_id: 'a', position: 1, release_state: 'scheduled', release_at: null, profile_id: PROFILE_A, assessment_part: 1 }),
    mod({ module_id: 'b', position: 1, release_state: 'open', release_at: FUTURE, close_at: PAST, profile_id: PROFILE_A, assessment_part: 2 }),
    mod({ module_id: 'c', position: 3, release_state: 'open', profile_id: null }),
    mod({ module_id: 'd', position: 4, release_state: 'open', profile_id: null }),
  ];
  const edges = [
    { module_id: 'c', prereq_module_id: 'd' },
    { module_id: 'd', prereq_module_id: 'c' },
    { module_id: 'a', prereq_module_id: 'ghost' },
  ];
  const graph = spine.buildGraph(modules, edges);
  const issues = spine.sectionIssues({ section: activeSection(), modules, graph, nowMs: NOW });
  const codes = issues.map((i) => i.code);

  for (const code of [
    S.ISSUE.PREREQ_CYCLE, S.ISSUE.PREREQ_MISSING, S.ISSUE.SCHEDULED_WITHOUT_DATE,
    S.ISSUE.CLOSE_BEFORE_RELEASE, S.ISSUE.CLIENT_UNBOUND, S.ISSUE.DUPLICATE_POSITION,
    S.ISSUE.SHARED_ENVIRONMENT,
  ]) {
    assert.ok(codes.includes(code), `${code} must be reported`);
  }
  for (const issue of issues) {
    assert.strictEqual(issue.severity, S.ISSUE_SEVERITY[issue.code]);
    assert.strictEqual(issue.message, S.MESSAGE[issue.code]);
    assert.ok('module_id' in issue && 'detail' in issue);
  }
  assert.strictEqual(issues.filter((i) => i.code === S.ISSUE.PREREQ_CYCLE).length, 2);
  assert.strictEqual(issues.filter((i) => i.code === S.ISSUE.CLIENT_UNBOUND).length, 2);
  assert.deepStrictEqual(
    issues.find((i) => i.code === S.ISSUE.DUPLICATE_POSITION).detail,
    { position: 1, module_ids: ['a', 'b'] }
  );

  // Errors before warnings before info, so the list reads the same twice.
  const severities = issues.map((i) => i.severity);
  const rank = { error: 0, warning: 1, info: 2 };
  for (let i = 1; i < severities.length; i += 1) {
    assert.ok(rank[severities[i]] >= rank[severities[i - 1]], 'issues must be ordered by severity');
  }

  // A section of nothing but drafts is a warning of its own.
  const allDrafts = spine.sectionIssues({
    section: activeSection(),
    modules: [mod({ module_id: 'x', release_state: 'draft' })],
    graph: spine.buildGraph([mod({ module_id: 'x', release_state: 'draft' })], []),
    nowMs: NOW,
  });
  assert.ok(allDrafts.some((i) => i.code === S.ISSUE.NO_PUBLISHED_MODULES));
  assert.ok(!allDrafts.some((i) => i.code === S.ISSUE.CLIENT_UNBOUND),
    'an unbound DRAFT is normal — the instructor has not chosen the client yet');
  assert.deepStrictEqual(spine.sectionIssues({ section: activeSection(), modules: [], graph: spine.buildGraph([], []), nowMs: NOW }), []);
});

test('D1: no configuration issue is ever returned on a student path', () => {
  const modules = [
    mod({ module_id: 'a', position: 1, release_state: 'scheduled', release_at: null }),
    mod({ module_id: 'b', position: 1, release_state: 'open', profile_id: null }),
  ];
  const view = spine.resolveForStudent(studentInput({ modules }));
  assert.ok(!('issues' in view));
  const payload = JSON.stringify(view);
  for (const code of Object.keys(S.ISSUE)) {
    if (S.REASON[code]) continue; // PREREQ_CYCLE / PREREQ_MISSING are also reasons
    assert.ok(!payload.includes(code), `${code} names something a student cannot act on`);
  }
});

// ---------------------------------------------------------------------------
// The instructor view
// ---------------------------------------------------------------------------

test('D1: the instructor rollup is the same gate the student is looking at', () => {
  const modules = [
    mod({ module_id: 'first', position: 1 }),
    mod({ module_id: 'second', position: 2 }),
  ];
  const edges = [{ module_id: 'second', prereq_module_id: 'first' }];
  const roster = ['u-blocked', 'u-done', 'u-unlocked'];
  const states = [
    state({ module_id: 'first', user_id: 'u-done', completion: 'complete' }),
    state({ module_id: 'second', user_id: 'u-unlocked', release_override: 'unlock' }),
  ];

  const instructor = spine.resolveForInstructor({
    section: activeSection(), modules, edges, states, roster, derivedByUser: new Map(), now: NOW,
  });
  const second = instructor.modules.find((m) => m.module_id === 'second');

  assert.strictEqual(instructor.roster_size, 3);
  assert.strictEqual(second.students.enrolled, 3);
  assert.strictEqual(second.students.with_state, 1);
  assert.strictEqual(second.students.blocked_by_prereq, 1);
  assert.deepStrictEqual(second.students.access, { hidden: 0, locked: 1, open: 2, closed: 0 });
  assert.deepStrictEqual(second.students.overridden, { unlock: 1, lock: 0 });
  assert.deepStrictEqual(second.students.completion, { incomplete: 3, complete: 0, waived: 0 });
  assert.deepStrictEqual(second.requires_module_ids, ['first']);
  assert.deepStrictEqual(
    instructor.modules.find((m) => m.module_id === 'first').required_by_module_ids, ['second']
  );

  // The number in the grid resolves to the same word on the student's own page.
  for (const [userId, expected] of [['u-blocked', 'locked'], ['u-done', 'open'], ['u-unlocked', 'open']]) {
    const asStudent = spine.resolveForStudent(studentInput({
      modules, edges, states: states.filter((s) => s.user_id === userId),
    }));
    assert.strictEqual(
      asStudent.modules.find((m) => m.module_id === 'second').access, expected,
      `${userId} must be told the same thing the grid counts`
    );
  }

  // An EMPTY roster is a real answer, and a brand-new section must not render
  // as "the roster was not loaded" forever.
  const emptyRoster = spine.resolveForInstructor({
    section: activeSection(), modules, edges, states, roster: [], derivedByUser: new Map(), now: NOW,
  });
  assert.deepStrictEqual(emptyRoster.modules[0].students, {
    enrolled: 0,
    with_state: 0,
    completion: { incomplete: 0, complete: 0, waived: 0 },
    access: { hidden: 0, locked: 0, open: 0, closed: 0 },
    overridden: { unlock: 0, lock: 0 },
    blocked_by_prereq: 0,
  }, 'nobody is enrolled is a zeroed rollup, not an absence');

  const noRoster = spine.resolveForInstructor({
    section: activeSection(), modules, edges, states, derivedByUser: new Map(), now: NOW,
  });
  assert.strictEqual(noRoster.modules[0].students, null,
    '"nobody is enrolled" and "the roster was not loaded" must stay distinguishable');
});

test('D1: the instructor view counts phases and keeps the staff-only columns', () => {
  const modules = [
    mod({ module_id: 'a', position: 1, release_state: 'draft' }),
    mod({ module_id: 'b', position: 2, release_state: 'scheduled', release_at: FUTURE }),
    mod({ module_id: 'c', position: 3, release_state: 'open' }),
    mod({ module_id: 'd', position: 4, release_state: 'closed' }),
    mod({ module_id: 'e', position: 5, release_state: 'archived' }),
  ];
  const view = spine.resolveForInstructor({
    section: activeSection(), modules, edges: [], states: [], roster: [], derivedByUser: new Map(), now: NOW,
  });
  assert.deepStrictEqual(view.counts, { total: 5, draft: 1, pending: 1, open: 1, closed: 1, archived: 1 });
  assert.deepStrictEqual(view.modules.map((m) => m.release_phase), ['draft', 'pending', 'open', 'closed', 'archived']);
  assert.strictEqual(view.modules[0].instructor_notes, 'Swap the client next term.',
    'the staff view is the one place these belong');
  assert.deepStrictEqual(view.section, activeSection());
});

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

test('D1: the derived-completion query is skipped entirely when nothing is bound', async () => {
  const unbound = [mod({ module_id: 'a', profile_id: null, assessment_part: null })];
  assert.deepStrictEqual([...(await spine.loadPartCompletions(unbound, [STUDENT])).keys()], []);
  assert.strictEqual(dbCalls.length, 0, 'no module addresses a deliverable, so there is nothing to ask');

  const halfBound = [
    mod({ module_id: 'a', profile_id: PROFILE_A, assessment_part: null }),
    mod({ module_id: 'b', profile_id: null, assessment_part: 3 }),
  ];
  await spine.loadPartCompletions(halfBound, [STUDENT]);
  assert.strictEqual(dbCalls.length, 0, 'half a binding addresses nothing');

  const bound = [mod({ module_id: 'a', profile_id: PROFILE_A, assessment_part: 3 })];
  await spine.loadPartCompletions(bound, []);
  assert.strictEqual(dbCalls.length, 0, 'nobody to ask about');

  await spine.loadPartCompletions(bound, [STUDENT]);
  assert.strictEqual(dbCalls.length, 1, 'and exactly one query otherwise');
  assert.deepStrictEqual(dbCalls[0].params[0], S.COMPLETING_PART_STATUSES,
    'the completing statuses are a parameter, not a third spelling inside the SQL');
  assert.ok(!/'submitted'|'reviewed'/.test(dbCalls[0].sql));
  assert.match(dbCalls[0].sql, /FROM assessment_progress/);
});

test('D1: derived completion matches exact triples, so an answer key satisfies nothing', async () => {
  const modules = [
    mod({ module_id: 'a', profile_id: PROFILE_A, assessment_part: 3 }),
    mod({ module_id: 'b', position: 2, profile_id: PROFILE_B, assessment_part: 3 }),
  ];
  dbHandler = () => ({
    rows: [
      // The student really did submit part 3 for client A.
      { user_id: STUDENT, profile_id: PROFILE_A, part_number: 3 },
      // The instructor's answer key: same client, same part, status 'reviewed',
      // and told apart from a student submission only by its own user_id.
      { user_id: STAFF, profile_id: PROFILE_A, part_number: 3 },
      // A near miss the cross-product ANY() arrays let through.
      { user_id: STUDENT, profile_id: PROFILE_A, part_number: 4 },
    ],
  });

  const completions = await spine.loadPartCompletions(modules, [STUDENT]);
  assert.deepStrictEqual([...completions.keys()], [STUDENT], 'only the ids we asked about');
  assert.deepStrictEqual([...completions.get(STUDENT)], ['a'],
    'module b is a different client and must not be completed by client A\'s submission');

  assert.deepStrictEqual(dbCalls[0].params[1], [STUDENT], 'scoped by user id, and that is load-bearing');
  assert.deepStrictEqual(dbCalls[0].params[2].sort(), [PROFILE_A, PROFILE_B].sort());
  assert.deepStrictEqual(dbCalls[0].params[3], [3]);
});

test('D1: every loader asks for its columns by name and scopes by section', async () => {
  await spine.loadSectionForStaff(SECTION_ID);
  await spine.loadModules(SECTION_ID);
  await spine.loadPrereqEdges(SECTION_ID);
  await spine.loadStudentStates(SECTION_ID, STUDENT);
  await spine.loadSectionStates(SECTION_ID);
  await spine.loadActiveRoster(SECTION_ID);

  for (const call of dbCalls) {
    assert.ok(!/SELECT\s+\*/i.test(call.sql),
      'SELECT * is the other door a column added by a later migration could walk through');
  }
  assert.match(dbCalls[2].sql, /FROM ciab_module_prereq[\s\S]*WHERE section_id = \$1/);
  assert.match(dbCalls[3].sql, /WHERE m\.section_id = \$1 AND st\.user_id = \$2/);
  assert.match(dbCalls[4].sql, /WHERE m\.section_id = \$1/);
  assert.match(dbCalls[5].sql, /FROM ciab_enrollment[\s\S]*status = 'active'/);
  assert.match(dbCalls[5].sql, /enrollment_role\s*=\s*'student'/,
    'a TA or an observer would inflate every rollup denominator AND be handed to '
    + 'loadPartCompletions, whose scoping contract is that the answer key lives under a staff id');
});

// ---------------------------------------------------------------------------
// Composed reads — the query budget
// ---------------------------------------------------------------------------

/** Answers whichever loader is asking, from an in-memory section. */
function serve({ section, modules, edges, states, roster, progress }) {
  return (sql) => {
    if (/FROM ciab_section/.test(sql)) return { rows: section ? [section] : [] };
    if (/FROM ciab_module_prereq/.test(sql)) return { rows: edges };
    if (/FROM ciab_module_student/.test(sql)) return { rows: states };
    if (/FROM ciab_module\b/.test(sql)) return { rows: modules };
    if (/FROM ciab_enrollment/.test(sql)) return { rows: roster.map((user_id) => ({ user_id })) };
    if (/FROM assessment_progress/.test(sql)) return { rows: progress };
    throw new Error(`unexpected query: ${sql}`);
  };
}

/** A section of `count` part-bound modules and `students` enrolled students. */
function fixture(count, students) {
  const modules = [];
  for (let i = 0; i < count; i += 1) {
    modules.push(mod({
      module_id: `m-${i}`, position: i + 1, profile_id: PROFILE_A, assessment_part: (i % 8) + 1,
    }));
  }
  const roster = [];
  for (let i = 0; i < students; i += 1) roster.push(`u-${i}`);
  return {
    section: { ...activeSection(), enrolled: true },
    modules,
    edges: modules.slice(1).map((m, i) => ({ module_id: m.module_id, prereq_module_id: `m-${i}` })),
    states: [],
    roster,
    progress: [],
  };
}

test('D1: the student view is a fixed 5 queries however big the section gets', async () => {
  const small = fixture(2, 1);
  dbHandler = serve(small);
  const view = await spine.studentSectionView(SECTION_ID, STUDENT);
  const smallCount = dbCalls.length;
  assert.strictEqual(smallCount, 5, 'section, modules, edges, states, part completions');
  assert.strictEqual(view.modules.length, 2);
  assert.strictEqual(view.enrolled, true);

  dbCalls = [];
  dbHandler = serve(fixture(40, 300));
  await spine.studentSectionView(SECTION_ID, STUDENT);
  assert.strictEqual(dbCalls.length, smallCount,
    'an N+1 shows up here as a number, not as a slow page in production');

  // And a section with no deliverable bound anywhere spends one fewer.
  dbCalls = [];
  const unbound = fixture(6, 1);
  unbound.modules = unbound.modules.map((m) => ({ ...m, profile_id: null, assessment_part: null }));
  dbHandler = serve(unbound);
  await spine.studentSectionView(SECTION_ID, STUDENT);
  assert.strictEqual(dbCalls.length, 4);
});

test('D1: the instructor view is a fixed 6 queries however big the roster gets', async () => {
  dbHandler = serve(fixture(2, 1));
  const view = await spine.instructorSectionView(SECTION_ID);
  const smallCount = dbCalls.length;
  assert.strictEqual(smallCount, 6, 'section, modules, edges, states, roster, part completions');
  assert.strictEqual(view.roster_size, 1);

  dbCalls = [];
  dbHandler = serve(fixture(40, 300));
  const big = await spine.instructorSectionView(SECTION_ID);
  assert.strictEqual(dbCalls.length, smallCount,
    'the cross-product runs in memory: 40 modules x 300 students is still 6 round trips');
  assert.strictEqual(big.roster_size, 300);
  assert.strictEqual(big.modules[0].students.enrolled, 300);
});

test('D1: a section that does not exist costs one query and answers null', async () => {
  dbHandler = serve({ ...fixture(2, 1), section: null });
  assert.strictEqual(await spine.studentSectionView(SECTION_ID, STUDENT), null);
  assert.strictEqual(dbCalls.length, 1);

  dbCalls = [];
  assert.strictEqual(await spine.instructorSectionView(SECTION_ID), null);
  assert.strictEqual(dbCalls.length, 1);
});

test('D1: a student dropped from the class still gets the shape, with everything locked', async () => {
  const data = fixture(3, 1);
  data.section = { ...activeSection(), enrolled: false };
  dbHandler = serve(data);

  const view = await spine.studentSectionView(SECTION_ID, STUDENT);
  assert.strictEqual(view.enrolled, false, 'so the caller chooses between 403 and a sentence');
  assert.ok(view.modules.every((m) => m.access === 'locked'));
  assert.ok(view.modules.every((m) => m.reasons[0].code === S.REASON.NOT_ENROLLED));
});

// ---------------------------------------------------------------------------
// The two writes
// ---------------------------------------------------------------------------

test('D1: a completion outside the vocabulary is refused with a 400 before any query', async () => {
  for (const bad of ['submitted', 'graded', '', null, undefined, 'COMPLETE']) {
    await assert.rejects(
      () => spine.setCompletion('m-1', STUDENT, bad),
      (err) => err.status === 400 && /completion must be one of/.test(err.message),
      `${JSON.stringify(bad)} must be refused`
    );
  }
  for (const bad of ['open', 'unlocked', '']) {
    await assert.rejects(
      () => spine.setReleaseOverride('m-1', STUDENT, bad),
      (err) => err.status === 400 && /release override must be null or one of/.test(err.message)
    );
  }
  assert.strictEqual(dbCalls.length, 0, 'a refusal must not reach the database');
});

test('D1: both writers upsert on the primary key migration 014 actually creates', async () => {
  dbHandler = () => ({ rows: [state({})] });

  await spine.setCompletion('m-1', STUDENT, 'complete', { actorId: STAFF });
  await spine.setReleaseOverride('m-1', STUDENT, 'unlock', { reason: 'Extension', actorId: STAFF });
  await spine.setReleaseOverride('m-1', STUDENT, null);

  for (const call of dbCalls) {
    assert.match(call.sql, /INSERT INTO ciab_module_student/);
    assert.match(call.sql, /ON CONFLICT \(module_id, user_id\) DO UPDATE/);
    assert.match(call.sql, /updated_at\s+= now\(\)/);
    assert.ok(!/RETURNING \*/.test(call.sql));
  }
  assert.deepStrictEqual(dbCalls[1].params, ['m-1', STUDENT, 'unlock', 'Extension', STAFF]);
  assert.deepStrictEqual(dbCalls[2].params, ['m-1', STUDENT, null, null, null]);
});

test('D1: reversing a completion clears who marked it and when', async () => {
  dbHandler = () => ({ rows: [state({})] });

  for (const [decision, marking] of [['complete', true], ['waived', true], ['incomplete', false], ['auto', false]]) {
    dbCalls = [];
    await spine.setCompletion('m-1', STUDENT, decision, { actorId: STAFF });
    assert.strictEqual(dbCalls[0].params[3], marking,
      `${decision} must ${marking ? 'record' : 'clear'} the attribution`);
    assert.match(dbCalls[0].sql, /CASE WHEN \$4::boolean THEN now\(\) ELSE NULL END/,
      'completed_at follows the decision rather than being written unconditionally');
    assert.match(dbCalls[0].sql, /CASE WHEN \$4::boolean THEN \$5::uuid ELSE NULL END/,
      'a stale completed_by is worse than none: it names somebody as having marked work '
      + 'complete that the row now says is not');
    assert.match(dbCalls[0].sql, /\(module_id, user_id, completion, completed_at, completed_by\)/);
  }
});

// ---------------------------------------------------------------------------
// The three unknowns that used to fail open, and the one wire nothing crossed
// ---------------------------------------------------------------------------

test('D1: a phase no build of this file knows hides rather than opens', () => {
  // RELEASE_PHASES and RELEASE_STATES share four of their five words, so the
  // realistic caller error is passing module.release_state where
  // releasePhase(module, now) belongs — and 'scheduled' is the word that then
  // arrives here. Rule 12 is a fall-through to 'open', so without rule 0 every
  // scheduled module's brief would be published with no reason attached.
  for (const phase of ['scheduled', 'published', 'hidden', '', undefined, null]) {
    const gate = spine.evaluateGate(gateInput({ phase }));
    assert.strictEqual(gate.access, 'hidden', `${JSON.stringify(phase)} must not be open`);
    assert.strictEqual(gate.reasons.length, 1, 'and a refusal always carries its reason');
    assert.strictEqual(gate.reasons[0].code, S.REASON.MODULE_DRAFT);

    const view = spine.studentModuleView({
      module: mod({}), gate, completion: 'incomplete', completionSource: 'default',
    });
    assert.strictEqual(view.brief, null, 'and no brief ships behind it');
  }
  // Every word the function may actually be handed is still answered normally.
  for (const phase of S.RELEASE_PHASES) {
    assert.ok(S.isAccessState(spine.evaluateGate(gateInput({ phase })).access));
  }
  assert.strictEqual(spine.evaluateGate(gateInput({ phase: 'open' })).access, 'open');
});

test('D1: a release_state this build does not know is not rescued by a past close_at', () => {
  // 'closed' is MORE permissive than 'draft' on the student path: the student
  // view drops only draft and archived, and a closed module ships its brief. So
  // the unrecognised-state test has to sit ABOVE the window, not below it.
  assert.strictEqual(spine.releasePhase(mod({ release_state: 'published', close_at: PAST }), NOW), 'draft');
  assert.strictEqual(spine.releasePhase(mod({ release_state: null, close_at: PAST }), NOW), 'draft');
  assert.strictEqual(spine.releasePhase(mod({ release_state: '', close_at: EARLIER }), NOW), 'draft');

  const view = spine.resolveForStudent(studentInput({
    modules: [mod({ module_id: 'unknown-word', release_state: 'published', close_at: PAST })],
  }));
  assert.deepStrictEqual(view.modules, [], 'it is dropped, brief and id and all');

  // And the five real words are untouched by the new test.
  for (const [state, expected] of [
    ['draft', 'draft'], ['archived', 'archived'], ['closed', 'closed'],
    ['open', 'closed'], ['scheduled', 'closed'],
  ]) {
    assert.strictEqual(spine.releasePhase(mod({ release_state: state, close_at: PAST }), NOW), expected);
  }
});

test('D1: a state row belonging to another student is refused, never quietly used', async () => {
  const modules = [mod({ module_id: 'a' })];
  const someoneElse = state({
    module_id: 'a',
    user_id: STAFF,
    completion: 'complete',
    release_override: 'lock',
    override_reason: 'Locked pending an integrity review of the other student.',
  });

  // loadStudentStates and loadSectionStates return identical column shapes and
  // sit next to each other; only the first is user-scoped. Reaching for the
  // wrong one used to hand this student the instructor's private sentence about
  // somebody else, verbatim, with no way for the resolver to notice.
  assert.throws(
    () => spine.resolveForStudent(studentInput({ modules, states: [someoneElse], userId: STUDENT })),
    (err) => err.status === 500 && /another student/.test(err.message)
  );

  // Their own row is of course still indexed.
  const mine = spine.resolveForStudent(studentInput({
    modules, states: [state({ module_id: 'a', user_id: STUDENT, completion: 'complete' })], userId: STUDENT,
  }));
  assert.strictEqual(mine.modules[0].completion, 'complete');

  // And the shipped composed read passes the id, so the guard is armed there.
  const data = fixture(1, 1);
  data.states = [someoneElse];
  dbHandler = serve(data);
  await assert.rejects(() => spine.studentSectionView(SECTION_ID, STUDENT), (err) => err.status === 500);
});

test('D1: a published module gated on an unpublished one is an error, not a silent lockout', () => {
  for (const unpublished of ['draft', 'archived']) {
    const modules = [
      mod({ module_id: 'first', position: 1, release_state: unpublished, profile_id: PROFILE_A }),
      mod({ module_id: 'second', position: 2, release_state: 'open', profile_id: PROFILE_A }),
    ];
    const edges = [{ module_id: 'second', prereq_module_id: 'first' }];
    const view = spine.resolveForInstructor({
      section: activeSection(), modules, edges, states: [], roster: ['u-0', 'u-1'],
      derivedByUser: new Map(), now: NOW,
    });

    const issue = view.issues.find((i) => i.code === S.ISSUE.PREREQ_UNPUBLISHED);
    assert.ok(issue, `a ${unpublished} prerequisite locks the whole roster and nothing else says so`);
    assert.strictEqual(issue.severity, 'error', 'students are affected right now and cannot act');
    assert.strictEqual(issue.module_id, 'second');
    assert.deepStrictEqual(issue.detail, { prereq_module_id: 'first' });
    assert.strictEqual(issue.message, S.MESSAGE.PREREQ_UNPUBLISHED);

    // The number on its own is indistinguishable from a class that has not got
    // there yet, which is the whole reason the issue has to exist.
    const second = view.modules.find((m) => m.module_id === 'second');
    assert.strictEqual(second.students.blocked_by_prereq, 2);
    assert.strictEqual(second.students.access.open, 0);
  }

  // A published prerequisite raises nothing, and neither does a draft module
  // gated on another draft — the instructor is still writing both.
  const fine = spine.resolveForInstructor({
    section: activeSection(),
    modules: [
      mod({ module_id: 'first', position: 1, release_state: 'draft' }),
      mod({ module_id: 'second', position: 2, release_state: 'draft' }),
      mod({ module_id: 'third', position: 3, release_state: 'open', profile_id: PROFILE_A }),
      mod({ module_id: 'fourth', position: 4, release_state: 'open', profile_id: PROFILE_A }),
    ],
    edges: [
      { module_id: 'second', prereq_module_id: 'first' },
      { module_id: 'fourth', prereq_module_id: 'third' },
    ],
    states: [], roster: [], derivedByUser: new Map(), now: NOW,
  });
  assert.ok(!fine.issues.some((i) => i.code === S.ISSUE.PREREQ_UNPUBLISHED));
});

test('D1: a derived completion reaches both resolvers and unlocks what follows', () => {
  // derivedCompleteIds and derivedByUser are the ONE derived-completion signal
  // D1 ships, and every other test in this file passes them empty. Changing
  // derivedSignalFor to return null, or the map key on either side, would leave
  // every student who really did submit a part locked out for the whole term
  // with the suite still green.
  const modules = [
    mod({ module_id: 'm1', position: 1, profile_id: PROFILE_A, assessment_part: 2 }),
    mod({ module_id: 'm2', position: 2, profile_id: PROFILE_A, assessment_part: 3 }),
  ];
  const edges = [{ module_id: 'm2', prereq_module_id: 'm1' }];

  const student = spine.resolveForStudent(studentInput({
    modules, edges, derivedCompleteIds: new Set(['m1']),
  }));
  const first = student.modules.find((m) => m.module_id === 'm1');
  assert.strictEqual(first.completion, 'complete');
  assert.strictEqual(first.completion_source, 'derived',
    'and the instructor UI can tell "the tracker says so" from "I said so"');
  assert.strictEqual(student.modules.find((m) => m.module_id === 'm2').access, 'open');

  const instructor = spine.resolveForInstructor({
    section: activeSection(), modules, edges, states: [], roster: ['u-0', 'u-1'],
    derivedByUser: new Map([['u-0', new Set(['m1'])]]), now: NOW,
  });
  assert.deepStrictEqual(
    instructor.modules.find((m) => m.module_id === 'm1').students.completion,
    { incomplete: 1, complete: 1, waived: 0 }
  );
  const second = instructor.modules.find((m) => m.module_id === 'm2').students;
  assert.strictEqual(second.access.open, 1, 'exactly the one who submitted');
  assert.strictEqual(second.blocked_by_prereq, 1);
});

test('D1: a real assessment_progress row unlocks the next module, end to end', async () => {
  // The one assertion that covers the (user, client, part) key on BOTH sides of
  // loadPartCompletions, through the shipped composed read rather than around it.
  const data = fixture(2, 1);
  data.progress = [{ user_id: STUDENT, profile_id: PROFILE_A, part_number: 1 }];
  dbHandler = serve(data);

  const view = await spine.studentSectionView(SECTION_ID, STUDENT);
  assert.strictEqual(view.modules[0].completion, 'complete');
  assert.strictEqual(view.modules[0].completion_source, 'derived');
  assert.strictEqual(view.modules[1].access, 'open',
    'the module that follows is what the derivation is FOR');

  dbCalls = [];
  const staffData = fixture(2, 1);
  staffData.progress = [{ user_id: 'u-0', profile_id: PROFILE_A, part_number: 1 }];
  dbHandler = serve(staffData);
  const grid = await spine.instructorSectionView(SECTION_ID);
  assert.strictEqual(grid.modules[0].students.completion.complete, 1);
  assert.strictEqual(grid.modules[1].students.access.open, 1);
});

// ---------------------------------------------------------------------------
// The vocabulary against the CHECK constraints
// ---------------------------------------------------------------------------

test('D1: every stored vocabulary and its CHECK constraint agree in both directions', () => {
  const pairs = [
    ['ciab_module_release_state_chk', S.RELEASE_STATES],
    ['ciab_module_student_completion_chk', S.COMPLETION_DECISIONS],
    ['ciab_module_student_override_chk', S.RELEASE_OVERRIDES],
  ];
  for (const [constraint, vocabulary] of pairs) {
    const inSql = checkValues(constraint).sort();
    const inJs = [...vocabulary].sort();
    assert.deepStrictEqual(inSql, inJs,
      `${constraint} and its vocabulary must match exactly — CREATE TABLE IF NOT EXISTS is a `
      + 'no-op on a deployment that already ran this file, so a drift is a 23514 in production');
  }
  // The derived vocabularies deliberately have no constraint to agree with.
  assert.deepStrictEqual([...S.COMPLETIONS], ['incomplete', 'complete', 'waived']);
  assert.ok(!S.COMPLETIONS.includes('auto'));
  assert.ok(S.SATISFYING_COMPLETIONS.every((c) => S.COMPLETIONS.includes(c)));
  for (const code of [...Object.keys(S.REASON), ...Object.keys(S.ADVISORY), ...Object.keys(S.ISSUE)]) {
    assert.strictEqual(typeof S.MESSAGE[code], 'string', `${code} needs a sentence`);
    assert.strictEqual(S.messageFor(code), S.MESSAGE[code]);
  }
  for (const code of Object.keys(S.ISSUE)) {
    assert.ok(['error', 'warning', 'info'].includes(S.ISSUE_SEVERITY[code]));
  }
  assert.strictEqual(S.messageFor('constructor'), 'Unavailable.',
    'an inherited property name is not a sentence');
  assert.strictEqual(S.messageFor('NOPE'), 'Unavailable.');
});

test('D1: every label covers its whole family, so no badge can render empty', () => {
  for (const value of [...S.RELEASE_STATES, ...S.RELEASE_PHASES]) {
    assert.ok(S.RELEASE_LABELS[value], `${value} needs a label`);
  }
  for (const value of S.ACCESS_STATES) assert.ok(S.ACCESS_LABELS[value]);
  for (const value of [...S.COMPLETION_DECISIONS, ...S.COMPLETIONS]) {
    assert.ok(S.COMPLETION_LABELS[value]);
  }
  for (const frozen of [
    S.RELEASE_STATES, S.RELEASE_PHASES, S.ACCESS_STATES, S.COMPLETION_DECISIONS,
    S.COMPLETIONS, S.SATISFYING_COMPLETIONS, S.COMPLETION_SOURCES, S.RELEASE_OVERRIDES,
    S.COMPLETING_PART_STATUSES, S.DEFAULT_STUDENT_STATE, S.REASON, S.ADVISORY, S.ISSUE,
    S.ISSUE_SEVERITY, S.MESSAGE, S.RELEASE_LABELS, S.ACCESS_LABELS, S.COMPLETION_LABELS,
  ]) {
    assert.ok(Object.isFrozen(frozen), 'a vocabulary a caller can edit is not one vocabulary');
  }
});

// ---------------------------------------------------------------------------
// The migration's shape
// ---------------------------------------------------------------------------

test('D1 migration: every create carries IF NOT EXISTS, because the file re-runs on every boot', () => {
  const creates = [...SQL_CODE.matchAll(/CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX|EXTENSION)\s+(IF NOT EXISTS\s+)?(\S+)/gi)];
  assert.ok(creates.length >= 12, 'the three tables and their indexes must all be here');
  for (const [statement, guard, name] of creates) {
    assert.ok(guard, `bare statement: ${statement.replace(/\s+/g, ' ')} (${name}) — one failure rolls `
      + 'back the whole file, is only console.warn()ed, and the server still reports healthy');
  }
  for (const add of SQL_CODE.match(/ADD\s+COLUMN[^,;]*/gi) || []) {
    assert.match(add, /IF NOT EXISTS/i);
  }
  for (const table of ['ciab_module', 'ciab_module_prereq', 'ciab_module_student']) {
    assert.ok(tableBody(table).length > 0);
  }
});

test('D1 migration: nothing in the file can break the all-or-nothing send', () => {
  const forbidden = [
    [/\bBEGIN\s*;/i, 'BEGIN;'],
    [/\bCOMMIT\b/i, 'COMMIT'],
    [/\bROLLBACK\b/i, 'ROLLBACK'],
    [/\bSTART\s+TRANSACTION\b/i, 'START TRANSACTION'],
    [/\bCONCURRENTLY\b/i, 'CONCURRENTLY'],
    [/\bVACUUM\b/i, 'VACUUM'],
    [/\bREINDEX\b/i, 'REINDEX'],
    [/\bCREATE\s+DATABASE\b/i, 'CREATE DATABASE'],
    [/\bALTER\s+SYSTEM\b/i, 'ALTER SYSTEM'],
    [/\bCREATE\s+(?:OR REPLACE\s+)?TRIGGER\b/i, 'CREATE TRIGGER'],
    [/\bCREATE\s+(?:OR REPLACE\s+)?FUNCTION\b/i, 'CREATE FUNCTION'],
  ];
  for (const [pattern, name] of forbidden) {
    assert.ok(!pattern.test(SQL_CODE),
      `${name} either destroys the all-or-nothing property or cannot run inside a transaction block`);
  }
  // The only BEGIN/END in the file are the PL/pgSQL block's, which are not
  // transaction control.
  assert.strictEqual((SQL_CODE.match(/\bBEGIN\b/g) || []).length, 2);
});

test('D1 migration: no foreign key points at a table in the other database', () => {
  const CROSS_DB = [
    ['cybercore', 'user'].join('_'),
    ['cybercore', 'lane'].join('_'),
    ['crucible', 'challenge'].join('_'),
    ['cybercore', 'lane', 'flag'].join('_'),
    ['cybercore', 'template', 'catalog'].join('_'),
  ];
  for (const table of CROSS_DB) {
    assert.ok(!new RegExp(`REFERENCES\\s+${table}`, 'i').test(SQL_CODE),
      `a syntactically valid cross-database FK to ${table} fails at runtime and takes the file with it`);
    assert.ok(!new RegExp(`\\b${table}\\b`).test(SQL_CODE),
      `${table} does not live in this database`);
  }
  const declarations = SQL_CODE.split('\n');
  for (const column of ['user_id', 'created_by', 'updated_by', 'completed_by', 'override_by']) {
    const declared = declarations.filter((line) => new RegExp(`^\\s*${column}\\s+UUID`, 'i').test(line));
    assert.ok(declared.length > 0, `${column} must be declared`);
    for (const line of declared) {
      assert.ok(!/REFERENCES/i.test(line), `${column} must be a bare UUID: ${line.trim()}`);
    }
  }
});

test('D1 migration: the ciab_section key is attached by a guard that cannot itself fail the file', () => {
  const at = SQL_CODE.indexOf('DO $section_fk$');
  assert.ok(at > 0, 'a named dollar tag: a bare $$ is terminated early by any dollar-quoted string inside');
  const block = SQL_CODE.slice(at);
  assert.ok(block.includes('$section_fk$;'), 'and the block must be closed by the same tag');

  const guard = block.slice(0, block.indexOf('THEN'));
  assert.match(guard, /to_regclass\('public\.ciab_section'\)/,
    'a condition that SELECTed FROM ciab_section would raise 42P01 at parse time');
  assert.match(guard, /FROM pg_constraint/);
  assert.match(guard, /conrelid\s*=\s*'public\.ciab_module'::regclass/,
    'the constraint name must be scoped to this table');
  assert.ok(!/FROM ciab_section/i.test(guard));
  assert.ok(!/FROM ciab_module\b/i.test(guard),
    'no "would any row violate it" pre-check: an orphan can only exist because the FK is absent, '
    + 'so such a check would prevent the constraint from ever being added, on every boot, forever');

  const then = block.slice(block.indexOf('THEN'));
  assert.match(then, /ALTER TABLE ciab_module\s+ADD CONSTRAINT ciab_module_section_fk/);
  assert.match(then, /REFERENCES ciab_section\(section_id\)\s+ON DELETE CASCADE/,
    'RESTRICT would turn the delete route\'s deliberate 409 into an unhandled 23503');
  assert.match(then, /EXCEPTION WHEN lock_not_available OR deadlock_detected THEN/,
    'an unwrapped ALTER lets a lock timeout roll back all three tables');
  assert.ok(!/EXCEPTION WHEN OTHERS/i.test(block),
    'WHEN OTHERS would also swallow 23503 and 42501, which never clear by waiting: the ALTER '
    + 'would fail on every boot, forever, silently, leaving section_id with no referential '
    + 'integrity while the server reported healthy');
});

test('D1 migration: the client key is inline, and deleting a client keeps the module', () => {
  assert.match(tableBody('ciab_module'),
    /profile_id\s+UUID REFERENCES profiles\(id\) ON DELETE SET NULL/,
    'SET NULL: the profile delete route is owner-scoped and must not destroy someone else\'s graded module');
  assert.match(tableBody('ciab_module'),
    /cloned_from_module_id UUID REFERENCES ciab_module\(module_id\) ON DELETE SET NULL/);
  assert.match(tableBody('ciab_module_student'),
    /module_id UUID NOT NULL REFERENCES ciab_module\(module_id\) ON DELETE CASCADE/);
});

test('D1 migration: a cross-section prerequisite edge is impossible to insert', () => {
  assert.match(tableBody('ciab_module'),
    /CONSTRAINT ciab_module_section_module_key UNIQUE \(section_id, module_id\)/,
    'the composite FK target — do not remove it');

  const prereq = tableBody('ciab_module_prereq');
  for (const [name, columns] of [
    ['ciab_module_prereq_module_fk', '(section_id, module_id)'],
    ['ciab_module_prereq_requires_fk', '(section_id, prereq_module_id)'],
  ]) {
    const at = prereq.indexOf(name);
    assert.ok(at > 0, `${name} must exist`);
    const clause = prereq.slice(at, at + 260).replace(/\s+/g, ' ');
    assert.ok(clause.includes(`FOREIGN KEY ${columns}`), `${name} must be composite: ${clause}`);
    assert.ok(clause.includes('REFERENCES ciab_module (section_id, module_id)'));
    assert.ok(clause.includes('ON UPDATE CASCADE ON DELETE CASCADE'));
  }
  assert.match(prereq, /PRIMARY KEY \(module_id, prereq_module_id\)/);
  assert.match(prereq, /CHECK \(module_id <> prereq_module_id\)/, 'the only cycle SQL can catch');

  // Both cascade lookups must have an index of their own rather than falling
  // back to a section-prefix scan on every module delete.
  assert.match(SQL_CODE, /CREATE INDEX IF NOT EXISTS \w+\s+ON ciab_module_prereq\(section_id, module_id\)/);
  assert.match(SQL_CODE, /CREATE INDEX IF NOT EXISTS \w+\s+ON ciab_module_prereq\(section_id, prereq_module_id\)/);
});

test('D1 migration: nothing forbids two modules at one position or against one client', () => {
  const uniques = SQL_CODE.match(/\bUNIQUE\s*\([^)]*\)/gi) || [];
  assert.deepStrictEqual(uniques.map((u) => u.replace(/\s+/g, ' ').trim()), ['UNIQUE (section_id, module_id)'],
    'a unique (section_id, position) fails a swap-two-positions reorder mid-statement, and one '
    + 'mentioning profile_id would make the repetition this whole program exists for unrepresentable');
  assert.ok(!/CREATE\s+UNIQUE\s+INDEX/i.test(SQL_CODE));
  assert.ok(!/UNIQUE[^;]*position/i.test(SQL_CODE));
  assert.ok(!/UNIQUE[^;]*profile_id/i.test(SQL_CODE));
});

test('D1 migration: every CHECK constraint is named', () => {
  const total = (SQL_CODE.match(/\bCHECK\s*\(/gi) || []).length;
  const named = (SQL_CODE.match(/CONSTRAINT\s+\w+\s*\n?\s*CHECK\s*\(/gi) || []).length;
  assert.ok(total > 0);
  assert.strictEqual(named, total,
    'a future guarded DROP/ADD must not depend on PostgreSQL\'s auto-generated name');
});

test('D1 migration: ciab_module_student is not a fourth progress tracker', () => {
  const body = tableBody('ciab_module_student');
  for (const column of ['score', 'feedback', 'rubric', 'evidence', 'content', 'percentage', 'flag', 'points', 'submitted']) {
    assert.ok(!new RegExp(`\\b${column}`, 'i').test(body),
      `${column} belongs to assessment_progress, which already owns the deliverable`);
  }
  assert.match(body, /completion\s+VARCHAR\(16\) NOT NULL DEFAULT 'auto'/);
  assert.match(body, /PRIMARY KEY \(module_id, user_id\)/, 'the ON CONFLICT target both writers name');
});

test('D1 migration: the engagement is named by (profile_id, engagement_type) and nothing else', () => {
  const body = tableBody('ciab_module');
  for (const column of ['engagement_id', 'challenge_id', 'challenge_key', 'lane_id', 'lane_group_id', 'environment_policy']) {
    assert.ok(!new RegExp(`\\b${column}\\b`, 'i').test(body),
      `${column} would name an environment the module cannot be sure exists yet`);
  }
  assert.match(body, /engagement_type VARCHAR\(32\) NOT NULL DEFAULT 'default'/);
  assert.match(SQL_CODE, /CREATE INDEX IF NOT EXISTS \w+\s+ON ciab_module\(profile_id, engagement_type\)/);
});

test('D1 migration: it opens with the extension this database already uses', () => {
  const firstStatement = SQL_CODE.split(';')[0].trim();
  assert.match(firstStatement, /^CREATE EXTENSION IF NOT EXISTS "uuid-ossp"$/);
  assert.match(SQL_CODE, /uuid_generate_v4\(\)/);
  assert.ok(!/gen_random_uuid|pgcrypto/i.test(SQL_CODE),
    'the neighbouring migrations all use uuid-ossp; a second generator is a second dependency');

  // The loader runs migrations in plain lexicographic filename order, so the
  // three digits are the whole ordering. Two files sharing them both run, in an
  // order nothing promises, and every "migration NNN" comment in this tree
  // becomes ambiguous — which is how the D1 file came to be renumbered to 014.
  assert.match(path.basename(MIGRATION_FILE), /^\d{3}_/);
  const byPrefix = new Map();
  for (const file of fs.readdirSync(path.join(CIAB, 'migrations'))) {
    if (!file.endsWith('.sql')) continue;
    assert.match(file, /^\d{3}_/, `${file} must open with the digits the loader sorts on`);
    const prefix = file.slice(0, 3);
    assert.ok(!byPrefix.has(prefix),
      `${file} and ${byPrefix.get(prefix)} both claim ${prefix}`);
    byPrefix.set(prefix, file);
  }
  assert.ok(byPrefix.has(path.basename(MIGRATION_FILE).slice(0, 3)));
});

// ---------------------------------------------------------------------------
// Zero behaviour change, and the scanners that will see these files
// ---------------------------------------------------------------------------

test('D2: the resolver is reachable from exactly the four files D2 declares, and mounted exactly where D2 says', () => {
  const readRepo = (rel) => read(path.join(ROOT, rel));

  // KEPT FROM D1, AND STILL TRUE. api.js requires only './section-modules';
  // neither resolver file is named there or in the boot path.
  const untouched = [
    'modules/crucible/plugins/ciab/routes/api.js',
    'src/server.js',
  ];
  for (const rel of untouched) {
    const src = readRepo(rel);
    assert.ok(!/module-spine|module-states/.test(src), `${rel} must name neither resolver file`);
  }

  const api = readRepo('modules/crucible/plugins/ciab/routes/api.js');

  // KEPT FROM D1, AND IT IS WHY THE FILE IS CALLED section-modules.js:
  // routes/modules.js would collide with core's src/routes/modules.js, which
  // owns GET /api/modules — the sidebar endpoint this plugin's access gate
  // actually feeds.
  assert.ok(!/require\('\.\/modules?'\)/.test(api));

  // (1) The require D2 declares, by its exact basename. The basename must also
  // match the hardcoded leaf-stub string in ciab-gate-scope.test.js, because
  // stub() calls require.resolve() at module load: a name that array does not
  // carry loads the real router inside that test process and takes the whole
  // FILE down with 'Unable to deserialize cloned data'.
  assert.ok(api.includes("require('./section-modules')"),
    'api.js must require the D2 router by the basename the gate-scope stub array names');
  const gateScope = readRepo('test/ciab-gate-scope.test.js');
  assert.ok(/'section-modules'/.test(gateScope),
    "ciab-gate-scope.test.js's leaf-stub array must name 'section-modules', or that whole file crashes");

  // (2) REGISTRATION ORDER AS A NUMBER, not as a comment. Express matches
  // router.use() prefixes in registration order and this router is mounted at
  // '/', so every prefix here is global. The modules mount must sit BELOW the
  // roster mount (both are /api/instructor/sections/:sectionId/... children)
  // and ABOVE both the bare sections mount — of which it is a strict string
  // prefix — and the bare /api catch-all.
  // Anchored to the START of a line, so a prefix quoted inside this file's own
  // explanatory comment block cannot be mistaken for the mount it describes.
  const mountAt = (needle) => api.indexOf(`
${needle}`);
  const modulesMount = api.indexOf("  '/api/instructor/sections/:sectionId/modules',");
  const rosterMount = api.indexOf("  '/api/instructor/sections/:sectionId/roster',");
  const sectionsMount = mountAt("router.use('/api/instructor/sections'");
  const catchAll = mountAt("router.use('/api', ");
  assert.ok(modulesMount > 0, 'api.js must mount the modules router at its full path');
  assert.ok(rosterMount > 0 && sectionsMount > 0 && catchAll > 0);
  assert.ok(modulesMount > rosterMount, 'the modules mount belongs below the roster mount');
  assert.ok(modulesMount < sectionsMount,
    'sections.js owns the /:sectionId/... verbs this path sits under, so it must be mounted after');
  assert.ok(modulesMount < catchAll, 'every CIAB prefix with gated routes sits above the bare /api mount');

  // (3) THE MOUNT'S CHAIN, which nothing else in this tree guards. Without it a
  // later refactor that drops the gate, or copies checkSchedule in from the
  // /api/profiles mount two lines below, stays green while a student gets the
  // wrong refusal or an instructor is told access is only available Mon-Fri.
  // ANCHORED TO THE ROUTER ARGUMENT, not to the next `);`. `api.indexOf(');')`
  // finds the one inside `next();` on the res.locals middleware line, not the one
  // closing router.use( -- so the slice stopped BEFORE the router and everything
  // appended after that middleware was invisible. The exact refactor this
  // assertion names in its own comment (copying checkSchedule in from the
  // /api/profiles mount two lines below, written as `..., (req,res,next)=>{...},
  // checkSchedule, sectionModuleRoutes`) left it fully green while an instructor
  // opening the Modules tab outside a group's schedule window was refused by the
  // STUDENT time gate. Slicing to the router name covers every middleware
  // position, and a router swapped for another one fails the first assertion.
  const routerAt = api.indexOf('sectionModuleRoutes', modulesMount);
  assert.ok(routerAt > modulesMount,
    'the modules mount must hand off to sectionModuleRoutes; a swapped router is a silent reroute');
  const chain = api.slice(modulesMount, routerAt);
  assert.ok(chain.includes('authenticateToken'), 'the modules mount must authenticate');
  assert.ok(chain.includes('requireCiabAccess'), 'a CIAB-owned prefix carries the enrollment gate');
  assert.ok(!chain.includes('checkSchedule'),
    'a staff surface must not be behind the student schedule window');

  // (4) THE SAME TREE WALK D1 RAN, now compared against an EXACT allowlist.
  // Four entries, not one: module-admin.js holds the decisions so they are
  // testable with no HTTP server, and keeping it "unaware" would mean injecting
  // buildGraph and RELEASE_STATES as arguments — a precedent-free calling
  // convention. An exact four-entry allowlist is as mechanical an invariant as
  // an exact one-entry allowlist, and a FIFTH file still fails: wiring the
  // resolver from routes/instructor.js, a middleware file or a plugin index
  // does not become quietly acceptable.
  const walk = (dir, out = []) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, out);
      else if (e.name.endsWith('.js')) out.push(full);
    }
    return out;
  };
  const D1_FILES = new Set([SPINE_FILE, STATES_FILE]);
  const aware = [path.join(ROOT, 'src'), path.join(ROOT, 'modules')]
    .flatMap((dir) => walk(dir))
    .filter((file) => !D1_FILES.has(file) && /module-spine|module-states/.test(read(file)))
    .map((file) => path.relative(ROOT, file).split(path.sep).join('/'))
    .sort();
  assert.deepStrictEqual(aware, [
    'modules/crucible/plugins/ciab/routes/section-modules.js',
    'modules/crucible/plugins/ciab/utils/module-admin.js',
  ], 'exactly these files may name the resolver; module-spine.js and module-states.js are its other two');

  // (5) THE COMPANION INVARIANT. The modules mount stamps res.locals.sectionId
  // on every request under its prefix, and a request that matches no modules
  // route falls THROUGH to the sections mount with its url intact. sections.js
  // registers no two-segment /:sectionId/:param route today, and must not grow
  // one: such a route would be handed the section id the MODULES mount wrote,
  // authorize against it, and act on it while its own :sectionId param said
  // something else — a write against the wrong section, answering 200.
  const sections = readRepo('modules/crucible/plugins/ciab/routes/sections.js');
  assert.ok(!/router\.(get|post|patch|put|delete)\('\/:sectionId\/:/.test(sections),
    'a /:sectionId/:param route in sections.js would catch a modules path that fell through');
  // And the operand order that makes the fallthrough inert either way.
  assert.ok(sections.includes('const sectionIdOf = (req, res) => req.params.sectionId || res.locals.sectionId;'),
    'sections.js must prefer its OWN :sectionId param over a res.locals another mount wrote');
});

test('D1: the resolver requires ./lane-reservation lazily, inside the one function that needs it', () => {
  const topLevel = lines(SPINE_SRC).filter((line) => /^(const|let|var)\s.*require\(/.test(line));
  assert.deepStrictEqual(topLevel.map((l) => l.trim()), [
    "const { query } = require('./db');",
    "const S = require('./module-states');",
    "const { getPartName } = require('./part-definitions');",
  ], 'a top-level ./lane-reservation would pull the Proxmox client and the batch deployer into '
    + 'every node --test child process, where the weight is a whole-file crash with no assertion');

  const lazy = lines(SPINE_SRC).filter((line) => /require\(['"]\.\/lane-reservation['"]\)/.test(line));
  assert.strictEqual(lazy.length, 1);
  assert.match(lazy[0], /^\s{2,}/, 'it must be indented inside a function body');

  assert.ok(!/require\(/.test(codeOnly(STATES_SRC)),
    'the vocabulary file imports nothing, so a route validator can use it without a pool');
});

test('D1: neither new file trips the three scanners that walk this tree', () => {
  const AUDIT_TABLE = ['cybercore', 'audit', 'log'].join('_');
  const LANE_TABLE = ['cybercore', 'lane'].join('_');
  for (const [name, src] of [['module-spine.js', SPINE_SRC], ['module-states.js', STATES_SRC]]) {
    assert.ok(!new RegExp(`\\$\\d+\\s+IS\\s+(NOT\\s+)?NULL`, 'i').test(src),
      `${name}: an uncast parameter in a NULL test stays type "unknown" and the statement fails to parse`);
    assert.ok(!src.includes(AUDIT_TABLE), `${name} must not name the audit table`);
    assert.ok(!src.includes(LANE_TABLE), `${name} must not name the lane table`);
  }
  // The one NULL test in the file is cast at its first reference.
  assert.match(SPINE_SRC, /\$3::text IS DISTINCT FROM NULL/);
});

test('D1: no word from the other plugin\'s vocabulary reaches anything a person reads', () => {
  const CLE_WORDS = /\b(course|courses|material|materials|challenge|challenges|assignment|assignments|lesson|lessons)\b/i;
  for (const [name, text] of [
    ['migration 014', SQL_CODE],
    ['module-states.js', codeOnly(STATES_SRC)],
    ['module-spine.js', codeOnly(SPINE_SRC)],
  ]) {
    const hit = text.match(CLE_WORDS);
    assert.strictEqual(hit, null,
      `${name} names ${hit && hit[0]} — an instructor must never have to tell the two programs apart`);
  }
  for (const sentence of Object.values(S.MESSAGE)) {
    assert.ok(!CLE_WORDS.test(sentence), `a student reads this: ${sentence}`);
    assert.ok(/[.?]$/.test(sentence), 'each message is a whole sentence naming the remedy');
  }
  for (const key of spine.STUDENT_VIEW_KEYS) assert.ok(!CLE_WORDS.test(key));
});
