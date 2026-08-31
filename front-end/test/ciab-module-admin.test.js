/**
 * ciab-module-admin.test.js — Track D, phase D2: every decision the Modules
 * routes make, exercised with NO HTTP server and NO database.
 *
 * That is the whole reason utils/module-admin.js exists. Folded into
 * routes/section-modules.js these rules could only be inspected by standing up
 * express and a stubbed pool, and the failures they guard against are exactly
 * the kind that survive that: a wrong cast in a builder, an operand order in a
 * collision check, a clone that quietly drops a column a later migration added.
 *
 * WHAT EACH GROUP BELOW IS ACTUALLY DEFENDING:
 *
 *   THE CLONE PARTITION. CLONE_COPIES and CLONE_RESETS plus 'section_id' must
 *   equal MODULE_COLUMNS as a set. A column added by a later migration then
 *   fails a test rather than shipping as a copy that silently omits a field.
 *
 *   THE REORDER STATEMENT'S TEXT. It is migration 014's header statement plus
 *   exactly ONE addition, `updated_by`. It must NOT carry `position IS DISTINCT
 *   FROM v.pos`: under READ COMMITTED an unmatched row is never scanned, so it is
 *   never locked and EvalPlanQual never re-checks it — and that re-check is the
 *   whole mechanism that makes one UPDATE a correct last-write-wins. With the
 *   predicate, two co-instructors reordering one section inside a statement's
 *   window commit an interleaved order NEITHER asked for, reported as a 200.
 *   Asserting the SQL here is the only way to see that without a server.
 *
 *   THE CYCLE DIFF. buildGraph marks everything DOWNSTREAM of a cycle as cyclic
 *   too, so the bare `cyclicIds.size > 0` recipe would refuse every unrelated
 *   edge on an already-broken section and name the wrong module, the wrong edge
 *   and the wrong remedy. The before/after diff is asserted against exactly
 *   that case.
 *
 *   THE SLUG. engagement_type is the slug half of an engagement's identity, and
 *   it must go through sanitizeEngagementType on create, on patch and on clone
 *   — including when the value is INHERITED from the source row. A recording
 *   stub proves it was consulted rather than merely that the output looks
 *   right.
 *
 * ciab/utils/db.js is stubbed COMPLETELY — { query, getPool, setPool, pool } —
 * because a partial stub leaves the real module loaded for whichever export was
 * omitted, and that one builds a pg pool. ./lane-reservation is stubbed and
 * RECORDING, so module-admin's deliberately lazy require costs nothing and is
 * assertable.
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

// The WHOLE surface. A partial stub leaves the real module loaded for whatever
// was left out, and that one builds a pg pool at require time.
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async () => ({ rows: [], rowCount: 0 }),
  getPool: () => null,
  setPool: () => {},
  pool: null,
});

let slugCalls = [];
stub(path.join(CIAB, 'utils', 'lane-reservation.js'), {
  sanitizeEngagementType: (raw) => {
    slugCalls.push(raw);
    const s = String(raw == null ? '' : raw).trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    return s ? s.slice(0, 32) : 'default';
  },
});

const admin = require(path.join(CIAB, 'utils', 'module-admin.js'));
const S = require(path.join(CIAB, 'utils', 'module-states.js'));

const ADMIN_SRC = fs.readFileSync(path.join(CIAB, 'utils', 'module-admin.js'), 'utf8').replace(/\r\n/g, '\n');

const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const A = uuid(1);
const B = uuid(2);
const C = uuid(3);
// uuid(n) above is all digits and dashes, so .toUpperCase() on it is a NO-OP.
// Any test about id CASE has to use ids that actually carry hex letters.
const HEX_A = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee01';
const HEX_B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee02';
const P1 = uuid(11);
const P2 = uuid(12);
const SEC = uuid(90);
const ACTOR = uuid(91);

const mod = (over = {}) => ({
  module_id: A, section_id: SEC, position: 1, title: 'One', brief: null,
  instructor_notes: null, profile_id: null, engagement_type: 'default',
  assessment_part: null, release_state: 'draft', release_at: null, close_at: null,
  cloned_from_module_id: null, created_by: ACTOR, updated_by: ACTOR,
  created_at: null, updated_at: null, ...over,
});

beforeEach(() => { slugCalls = []; });

// ---------------------------------------------------------------------------
// The clone partition
// ---------------------------------------------------------------------------

test('CLONE_COPIES and CLONE_RESETS partition every column of ciab_module', () => {
  const columns = admin.MODULE_COLUMNS.split(',').map((c) => c.trim()).sort();
  const partition = [...admin.CLONE_COPIES, ...admin.CLONE_RESETS, 'section_id'].sort();
  assert.deepStrictEqual(partition, columns,
    'a column added by a later migration must fail here rather than be silently omitted from the clone');
  // No column may be in both lists, or the decision is ambiguous.
  const overlap = admin.CLONE_COPIES.filter((c) => admin.CLONE_RESETS.includes(c));
  assert.deepStrictEqual(overlap, []);
});

test('MODULE_COLUMNS is the same 17 columns spine.loadModules names', () => {
  const spineSrc = fs.readFileSync(path.join(CIAB, 'utils', 'module-spine.js'), 'utf8');
  const select = spineSrc.slice(spineSrc.indexOf('async function loadModules'));
  const columns = admin.MODULE_COLUMNS.split(',').map((c) => c.trim());
  assert.strictEqual(columns.length, 17);
  for (const col of columns) {
    assert.ok(new RegExp(`\\b${col}\\b`).test(select.slice(0, 800)),
      `loadModules must name ${col}, or a RETURNING row stops matching rowToModule's whitelist`);
  }
});

// ---------------------------------------------------------------------------
// normalizeModuleInput
// ---------------------------------------------------------------------------

test('create mode returns a COMPLETE record with the documented defaults', () => {
  const { values } = admin.normalizeModuleInput({ title: 'Scoping' }, { partial: false });
  const row = Object.fromEntries(values);
  assert.strictEqual(row.title, 'Scoping');
  assert.strictEqual(row.release_state, 'draft');
  assert.strictEqual(row.engagement_type, 'default');
  assert.strictEqual(row.brief, null);
  assert.strictEqual(row.instructor_notes, null);
  assert.strictEqual(row.profile_id, null);
  assert.strictEqual(row.assessment_part, null);
  assert.strictEqual(row.release_at, null);
  assert.strictEqual(row.close_at, null);
  // Positional: the INSERT's params follow this order.
  assert.strictEqual(values.length, 9);
});

test('patch mode returns ONLY supplied keys, and an explicit null clears', () => {
  const { values } = admin.normalizeModuleInput({ brief: null, title: 'Renamed' }, { partial: true });
  const keys = values.map(([k]) => k).sort();
  assert.deepStrictEqual(keys, ['brief', 'title']);
  assert.strictEqual(Object.fromEntries(values).brief, null, 'an explicit null clears the column');

  const untouched = admin.normalizeModuleInput({ title: 'Only this' }, { partial: true });
  assert.deepStrictEqual(untouched.values.map(([k]) => k), ['title'],
    'an absent key must not be written, or a PATCH silently blanks fields the caller never named');
});

test('a title is required, trimmed, and sliced to the column width', () => {
  assert.throws(() => admin.normalizeModuleInput({ title: '   ' }, { partial: false }),
    (e) => e.status === 400 && e.code === 'TITLE_REQUIRED' && e.message === 'A module title is required');
  const { values } = admin.normalizeModuleInput({ title: 'x'.repeat(300) }, { partial: false });
  assert.strictEqual(Object.fromEntries(values).title.length, admin.TITLE_MAX);
  assert.strictEqual(admin.TITLE_MAX, 255);
});

test('release_state is validated against S.RELEASE_STATES and the message is BUILT from it', () => {
  let thrown = null;
  try { admin.normalizeModuleInput({ title: 't', release_state: 'published' }, { partial: false }); }
  catch (e) { thrown = e; }
  assert.ok(thrown);
  assert.strictEqual(thrown.status, 400);
  assert.strictEqual(thrown.code, 'RELEASE_STATE_INVALID');
  assert.strictEqual(thrown.message, `release_state must be one of: ${S.RELEASE_STATES.join(', ')}`,
    'a hand-written list is a 23514 in production on a deployment where every fresh-database test passed');
  for (const state of S.RELEASE_STATES) {
    const { values } = admin.normalizeModuleInput({ title: 't', release_state: state }, { partial: false });
    assert.strictEqual(Object.fromEntries(values).release_state, state);
  }
});

test('an assessment_part must be a whole number of 1 or more', () => {
  for (const bad of [0, 1.5, -2]) {
    assert.throws(() => admin.normalizeModuleInput({ title: 't', assessment_part: bad }, { partial: false }),
      (e) => e.code === 'ASSESSMENT_PART_INVALID' && e.status === 400, `${bad} must be refused`);
  }
  assert.strictEqual(Object.fromEntries(admin.normalizeModuleInput({ title: 't', assessment_part: '' }, { partial: false }).values).assessment_part, null);
  assert.strictEqual(Object.fromEntries(admin.normalizeModuleInput({ title: 't', assessment_part: 3 }, { partial: false }).values).assessment_part, 3);
});

test('a bad date is refused per field, and a good one is stored as a Date', () => {
  assert.throws(() => admin.normalizeModuleInput({ title: 't', release_at: 'not a date' }, { partial: false }),
    (e) => e.code === 'RELEASE_AT_INVALID' && e.message === 'Opens at is not a valid date and time');
  assert.throws(() => admin.normalizeModuleInput({ title: 't', close_at: 'not a date' }, { partial: false }),
    (e) => e.code === 'CLOSE_AT_INVALID' && e.message === 'Closes at is not a valid date and time');
  const row = Object.fromEntries(admin.normalizeModuleInput({ title: 't', release_at: '2026-03-01T09:00:00Z' }, { partial: false }).values);
  assert.ok(row.release_at instanceof Date);
});

test('a profile_id must be a uuid, and blank means unbound', () => {
  assert.throws(() => admin.normalizeModuleInput({ title: 't', profile_id: 'nope' }, { partial: false }),
    (e) => e.code === 'PROFILE_ID_INVALID' && e.message === 'That is not a valid client id');
  assert.strictEqual(Object.fromEntries(admin.normalizeModuleInput({ title: 't', profile_id: '' }, { partial: false }).values).profile_id, null);
  assert.strictEqual(Object.fromEntries(admin.normalizeModuleInput({ title: 't', profile_id: P1 }, { partial: false }).values).profile_id, P1);
});

test("'scheduled' with no date, and an inverted window, are ACCEPTED and echoed in warnings", () => {
  // Refusing either would break correcting an inverted window in two PATCHes,
  // and make two of the resolver's nine issues unreachable for D2-created rows.
  const { values } = admin.normalizeModuleInput({ title: 't', release_state: 'scheduled' }, { partial: false });
  const notices = admin.writeNotices(values);
  assert.strictEqual(notices.length, 1);
  assert.strictEqual(notices[0].code, S.ISSUE.SCHEDULED_WITHOUT_DATE);
  assert.strictEqual(notices[0].severity, S.ISSUE_SEVERITY[S.ISSUE.SCHEDULED_WITHOUT_DATE]);
  assert.strictEqual(notices[0].message, S.messageFor(S.ISSUE.SCHEDULED_WITHOUT_DATE));

  const inverted = admin.normalizeModuleInput(
    { title: 't', release_at: '2026-03-05T09:00:00Z', close_at: '2026-03-01T09:00:00Z' },
    { partial: false }
  );
  const codes = admin.writeNotices(inverted.values).map((n) => n.code);
  assert.ok(codes.includes(S.ISSUE.CLOSE_BEFORE_RELEASE));

  // The healthy case says nothing.
  const fine = admin.normalizeModuleInput({ title: 't', release_state: 'open' }, { partial: false });
  assert.deepStrictEqual(admin.writeNotices(fine.values), []);
});

// ---------------------------------------------------------------------------
// The engagement slug
// ---------------------------------------------------------------------------

test('engagement_type is only ever produced by sanitizeEngagementType', () => {
  const created = admin.normalizeModuleInput({ title: 't', engagement_type: ' External ' }, { partial: false });
  assert.strictEqual(Object.fromEntries(created.values).engagement_type, 'external');
  assert.ok(slugCalls.includes(' External '), 'create must consult the slug function');

  slugCalls = [];
  const patched = admin.normalizeModuleInput({ engagement_type: 'Internal ' }, { partial: true });
  assert.strictEqual(Object.fromEntries(patched.values).engagement_type, 'internal');
  assert.strictEqual(slugCalls.length, 1, 'patch must consult it too');

  slugCalls = [];
  const plan = admin.planClone(mod({ engagement_type: ' External ' }), {}, { crossSection: false });
  assert.strictEqual(plan.engagement_type, 'external');
  assert.strictEqual(slugCalls.length, 1,
    'an INHERITED value must be sanitized too, or a hand-inserted row rides across a clone unslugged');
});

test('the ./lane-reservation require is lazy and indented inside a function body', () => {
  const lazy = ADMIN_SRC.split('\n').filter((l) => /require\(['"]\.\/lane-reservation['"]\)/.test(l));
  assert.strictEqual(lazy.length, 1, 'exactly one, and it must not be hoisted');
  assert.match(lazy[0], /^\s{2,}/,
    'a top-level require pulls the Proxmox client into every node --test child and crashes the whole FILE');
});

// ---------------------------------------------------------------------------
// conflictingPartBinding
// ---------------------------------------------------------------------------

test('a part collision needs BOTH a client and a part, on both sides', () => {
  const modules = [mod({ module_id: A, profile_id: P1, assessment_part: 2, title: 'Existing' })];

  assert.strictEqual(
    admin.conflictingPartBinding(modules, { module_id: null, profile_id: P1, assessment_part: 2 }).module_id, A,
    'same client and same part would complete each other: assessment_progress has no section column');

  // The repetition the programme exists for is all allowed.
  assert.strictEqual(admin.conflictingPartBinding(modules, { module_id: null, profile_id: P1, assessment_part: 3 }), null,
    'same client, different part');
  assert.strictEqual(admin.conflictingPartBinding(modules, { module_id: null, profile_id: P2, assessment_part: 2 }), null,
    'same part, different client');
  assert.strictEqual(admin.conflictingPartBinding(modules, { module_id: null, profile_id: P1, assessment_part: null }), null,
    'a null part on the candidate');
  assert.strictEqual(
    admin.conflictingPartBinding([mod({ profile_id: P1, assessment_part: null })], { module_id: null, profile_id: P1, assessment_part: 2 }),
    null, 'a null part on the stored row');
  assert.strictEqual(admin.conflictingPartBinding(modules, { module_id: null, profile_id: null, assessment_part: 2 }), null,
    'an unbound candidate');
});

test('a module never collides with ITSELF, whatever the id casing', () => {
  const modules = [mod({ module_id: A, profile_id: P1, assessment_part: 2 })];
  assert.strictEqual(admin.conflictingPartBinding(modules, { module_id: A, profile_id: P1, assessment_part: 2 }), null);
  assert.strictEqual(
    admin.conflictingPartBinding(modules, { module_id: A.toUpperCase(), profile_id: P1, assessment_part: 2 }), null,
    'PostgreSQL renders uuid lowercase; a case-sensitive compare would make every PATCH collide with itself');
});

// ---------------------------------------------------------------------------
// classifyPrereqCandidate
// ---------------------------------------------------------------------------

test('the four prerequisite verdicts', () => {
  const modules = [mod({ module_id: A }), mod({ module_id: B, position: 2 })];

  const self = admin.classifyPrereqCandidate({ modules, edges: [], moduleId: A, prereqModuleId: A });
  assert.strictEqual(self.status, 400);
  assert.strictEqual(self.code, 'PREREQ_SELF');

  const foreign = admin.classifyPrereqCandidate({ modules, edges: [], moduleId: A, prereqModuleId: C });
  assert.strictEqual(foreign.status, 404);
  assert.strictEqual(foreign.code, 'PREREQ_NOT_IN_SECTION');

  const missing = admin.classifyPrereqCandidate({ modules, edges: [], moduleId: C, prereqModuleId: A });
  assert.strictEqual(missing.status, 404);
  assert.strictEqual(missing.code, 'MODULE_NOT_IN_SECTION');

  // A requires B already; B requiring A closes the loop.
  const cycle = admin.classifyPrereqCandidate({
    modules,
    edges: [{ module_id: A, prereq_module_id: B }],
    moduleId: B,
    prereqModuleId: A,
  });
  assert.strictEqual(cycle.status, 409);
  assert.strictEqual(cycle.code, 'PREREQ_CYCLE');
  assert.deepStrictEqual(cycle.detail.cyclic_module_ids.sort(), [A, B].sort(),
    'only the NEWLY cyclic ids');

  assert.deepStrictEqual(admin.classifyPrereqCandidate({ modules, edges: [], moduleId: A, prereqModuleId: B }),
    { ok: true, moduleId: A, prereqModuleId: B },
    'an accepted verdict carries the NORMALIZED pair, so the route inserts what the cycle check judged');
});

test('an ALREADY-cyclic section does not have an unrelated edge blamed on it', () => {
  // A<->B is already a loop. C and D are nowhere near it, so C requiring D adds
  // no cycle at all — and must not be reported as "you created a cycle".
  // buildGraph marks everything DOWNSTREAM of a cycle as cyclic too, so the
  // bare `after.size > 0` recipe would refuse this edge and name the wrong
  // module, the wrong edge and the wrong remedy.
  const D = uuid(4);
  const modules = [
    mod({ module_id: A }), mod({ module_id: B, position: 2 }),
    mod({ module_id: C, position: 3 }), mod({ module_id: D, position: 4 }),
  ];
  const edges = [
    { module_id: A, prereq_module_id: B },
    { module_id: B, prereq_module_id: A },
  ];
  const verdict = admin.classifyPrereqCandidate({ modules, edges, moduleId: C, prereqModuleId: D });
  assert.strictEqual(verdict.status, 409);
  assert.strictEqual(verdict.code, 'PREREQ_SECTION_ALREADY_CYCLIC',
    'the honest refusal names the loop that already exists, not the edge just attempted');
  assert.strictEqual(verdict.error, 'This section already has a prerequisite loop. Fix that first, then add this one.');

  // And an edge that genuinely extends the damage still reports the cycle, with
  // ONLY the ids that were not already cyclic.
  const worse = admin.classifyPrereqCandidate({ modules, edges, moduleId: C, prereqModuleId: A });
  assert.strictEqual(worse.code, 'PREREQ_CYCLE');
  assert.deepStrictEqual(worse.detail.cyclic_module_ids, [C],
    'A and B were already stuck; only C is news');
});

test('an UPPER-CASED prerequisite request is judged, not waved through', () => {
  // THE MIRROR OF 'checkReorderShape lower-cases every id'. buildGraph keys byId
  // with the raw DB value — PostgreSQL's lowercase canonical uuid — and DROPS any
  // edge whose gated id is not in that map. Without folding here, the candidate
  // edge never entered the graph, after.size === before.size, the verdict was
  // { ok: true }, and the route then inserted the raw upper-cased ids: Postgres
  // parses an upper-case uuid literal happily, both composite FKs and
  // ciab_module_prereq_self_chk are value comparisons and pass, and ON CONFLICT
  // saw no duplicate — so the API committed the exact loop it promises to refuse
  // and D1's resolver then marked both modules and everything downstream cyclic.
  const modules = [mod({ module_id: HEX_A }), mod({ module_id: HEX_B, position: 2 })];
  const edges = [{ module_id: HEX_B, prereq_module_id: HEX_A }];

  const lower = admin.classifyPrereqCandidate({ modules, edges, moduleId: HEX_A, prereqModuleId: HEX_B });
  assert.strictEqual(lower.code, 'PREREQ_CYCLE');

  for (const [g, pq, label] of [
    [HEX_A.toUpperCase(), HEX_B.toUpperCase(), 'both upper'],
    [HEX_A.toUpperCase(), HEX_B, 'gated upper only'],
    [HEX_A, HEX_B.toUpperCase(), 'prereq upper only'],
  ]) {
    const v = admin.classifyPrereqCandidate({ modules, edges, moduleId: g, prereqModuleId: pq });
    assert.strictEqual(v.ok, false, label);
    assert.strictEqual(v.code, 'PREREQ_CYCLE', label);
    assert.deepStrictEqual(v.detail.cyclic_module_ids.slice().sort(), [HEX_A, HEX_B].slice().sort(), label);
  }

  // A self-edge in mixed case is still a self-edge.
  const self = admin.classifyPrereqCandidate({ modules, edges: [], moduleId: HEX_A, prereqModuleId: HEX_A.toUpperCase() });
  assert.strictEqual(self.code, 'PREREQ_SELF');
});

test('an accepted verdict returns the NORMALIZED pair the route must insert', () => {
  // The route writes verdict.moduleId / verdict.prereqModuleId, never
  // req.params.moduleId and never the raw body value: writing the raw values
  // would commit an edge in a case the cycle check did not judge.
  const modules = [mod({ module_id: HEX_A }), mod({ module_id: HEX_B, position: 2 })];
  const ok = admin.classifyPrereqCandidate({
    modules, edges: [], moduleId: HEX_B.toUpperCase(), prereqModuleId: ` ${HEX_A.toUpperCase()} `,
  });
  assert.strictEqual(ok.ok, true);
  assert.strictEqual(ok.moduleId, HEX_B);
  assert.strictEqual(ok.prereqModuleId, HEX_A);
});

// ---------------------------------------------------------------------------
// Reorder
// ---------------------------------------------------------------------------

test('checkReorderShape refuses all five hostile payloads with no database', () => {
  for (const bad of [undefined, null, 'abc', { }, 42]) {
    const r = admin.checkReorderShape(bad);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.code, 'ORDER_INVALID');
  }
  assert.strictEqual(admin.checkReorderShape([]).code, 'ORDER_INVALID');

  const tooMany = admin.checkReorderShape(Array.from({ length: admin.MAX_MODULES + 1 }, (_, i) => uuid(i)));
  assert.strictEqual(tooMany.code, 'ORDER_INVALID');
  assert.match(tooMany.error, new RegExp(String(admin.MAX_MODULES)));

  const notUuid = admin.checkReorderShape([A, 'nope']);
  assert.deepStrictEqual(notUuid.detail.invalid, ['nope'],
    'a non-uuid must never reach the ::uuid cast, where it raises 22P02 and surfaces as a 500');

  const nonString = admin.checkReorderShape([A, 7]);
  assert.strictEqual(nonString.code, 'ORDER_INVALID');

  const dup = admin.checkReorderShape([A, B, A]);
  assert.deepStrictEqual(dup.detail.duplicates, [A],
    'UPDATE ... FROM (VALUES ...) with two rows naming one module picks a source row arbitrarily and reports no error');
});

test('checkReorderShape lower-cases every id before anything compares them', () => {
  const r = admin.checkReorderShape([A.toUpperCase(), B.toUpperCase()]);
  assert.deepStrictEqual(r.ids, [A, B],
    'the owned set is built from database rows, which are lowercase canonical form');
});

test('checkReorderMembership is exact set algebra and echoes the canonical order', () => {
  assert.deepStrictEqual(admin.checkReorderMembership([A, B], [A, B]), { ok: true });

  const missing = admin.checkReorderMembership([A], [A, B]);
  assert.strictEqual(missing.ok, false);
  assert.strictEqual(missing.body.code, 'ORDER_STALE');
  assert.deepStrictEqual(missing.body.missing_from_order, [B]);
  assert.deepStrictEqual(missing.body.not_in_section, []);
  assert.deepStrictEqual(missing.body.order, [A, B], 'the client must be able to resync without a second GET');

  const foreign = admin.checkReorderMembership([A, C], [A, B]);
  assert.deepStrictEqual(foreign.body.not_in_section, [C]);
  assert.deepStrictEqual(foreign.body.missing_from_order, [B]);
});

test('reorderStatement produces the exact text, casts and params', () => {
  const one = admin.reorderStatement(SEC, ACTOR, [A]);
  assert.ok(one.text.includes('FROM (VALUES'));
  assert.ok(one.text.includes('($3::uuid, 1)'));
  assert.ok(one.text.includes('AND m.section_id = $1::uuid'), 'the section scope is what makes it safe');
  assert.ok(!one.text.includes('IS DISTINCT FROM'),
    'a qual that skips an already-correct row means that row is never scanned, never locked and never '
    + 'EvalPlanQual-re-checked — which is exactly how two concurrent reorders commit an interleaved '
    + 'order neither instructor asked for, as a 200. 014 ships no UNIQUE (section_id, position) to '
    + 'serialize them, so the single-statement lock IS the concurrency control');
  assert.ok(one.text.includes('updated_by = $2::uuid'),
    'attribution on a row migration 014 forbids a trigger from maintaining');
  assert.deepStrictEqual(one.params, [SEC, ACTOR, A]);

  const two = admin.reorderStatement(SEC, ACTOR, [A, B]);
  assert.ok(two.text.includes('($3::uuid, 1), ($4::uuid, 2)'));
  assert.deepStrictEqual(two.params, [SEC, ACTOR, A, B]);

  const forty = admin.reorderStatement(SEC, ACTOR, Array.from({ length: 40 }, (_, i) => uuid(i)));
  assert.strictEqual(forty.params.length, 42);
  assert.strictEqual(forty.params[0], SEC);
  assert.strictEqual(forty.params[1], ACTOR);
  assert.ok(forty.text.includes('($42::uuid, 40)'));
  // ONE statement. Nothing in this plugin calls pool.connect(), so a second
  // statement would have no rollback.
  assert.strictEqual((forty.text.match(/UPDATE ciab_module/g) || []).length, 1);
});

// ---------------------------------------------------------------------------
// planClone
// ---------------------------------------------------------------------------

test('a clone is always a draft with no window, whatever the source or the body', () => {
  const source = mod({ release_state: 'open', release_at: new Date(), close_at: new Date() });
  const plan = admin.planClone(source, { release_state: 'open', release_at: '2026-01-01T00:00:00Z' }, { crossSection: false });
  assert.strictEqual(plan.release_state, undefined, 'the release columns are SQL literals, not plan fields');
  assert.strictEqual(plan.release_at, undefined);
  assert.strictEqual(plan.close_at, undefined);
  assert.strictEqual(plan.title, 'One (copy)');
});

test('a clone re-points the client and the engagement, and inherits them otherwise', () => {
  const source = mod({ profile_id: P1, engagement_type: 'external', brief: 'b', instructor_notes: 'n', assessment_part: 2 });

  const repointed = admin.planClone(source, { profile_id: P2, engagement_type: 'internal' }, { crossSection: false });
  assert.strictEqual(repointed.profile_id, P2, 'cloning onto a different client is the point');
  assert.strictEqual(repointed.engagement_type, 'internal');

  const inherited = admin.planClone(source, {}, { crossSection: false });
  assert.strictEqual(inherited.profile_id, P1);
  assert.strictEqual(inherited.engagement_type, 'external');
  assert.strictEqual(inherited.brief, 'b');
  assert.strictEqual(inherited.instructor_notes, 'n');
  assert.strictEqual(inherited.assessment_part, 2);
});

test('a cross-section clone drops prerequisite copying unconditionally, and says so', () => {
  const plan = admin.planClone(mod(), { include_prereqs: true }, { crossSection: true });
  assert.strictEqual(plan.copy_prereqs, false,
    'both ends of an edge are a composite FK: the 23503 is PREVENTED, never caught');
  assert.ok(plan.notices.some((n) => n.code === 'PREREQ_NOT_COPIED'));

  const same = admin.planClone(mod(), {}, { crossSection: false });
  assert.strictEqual(same.copy_prereqs, true, 'in-section, copying is the default');
  assert.strictEqual(admin.planClone(mod(), { include_prereqs: false }, { crossSection: false }).copy_prereqs, false);
});

test('planClone carries EXACTLY CLONE_COPIES, by reading the list rather than a hand-written twin', () => {
  // The partition test above already forces a later author to CLASSIFY a column
  // added by a migration. This is what makes that classification do something:
  // planClone used to hardcode its six fields, so an author who correctly added
  // a name to CLONE_COPIES got a fully green suite and a clone that still
  // dropped the column.
  const source = mod({
    title: 'Scoping', brief: 'b', instructor_notes: 'n',
    profile_id: P1, engagement_type: 'external', assessment_part: 3,
  });
  const plan = admin.planClone(source, {}, { crossSection: false });

  const carried = Object.keys(plan).filter((k) => k !== 'copy_prereqs' && k !== 'notices').sort();
  assert.deepStrictEqual(carried, [...admin.CLONE_COPIES].sort(),
    'the plan column set IS CLONE_COPIES; a second hand-written list can disagree with it');

  // Every column except the three the request may re-point comes straight off
  // the source row.
  for (const col of admin.CLONE_COPIES) {
    if (col === 'title' || col === 'profile_id' || col === 'engagement_type') continue;
    assert.strictEqual(plan[col], source[col], `${col} must ride across a clone`);
  }
  // And no reset column leaks in.
  for (const col of admin.CLONE_RESETS) {
    assert.ok(!(col in plan), `${col} is a CLONE_RESET and must never appear in the plan`);
  }

  // A source missing a column entirely yields null, never undefined: an
  // undefined parameter is a null bind in node-postgres either way, but a plan
  // that reports undefined reads as "not decided" in review.
  const sparse = admin.planClone({ title: 'T' }, {}, { crossSection: false });
  for (const col of admin.CLONE_COPIES) {
    if (col === 'title' || col === 'engagement_type') continue;
    assert.strictEqual(sparse[col], null, `${col} must be an explicit null`);
  }
});

test('a 255-character source title is shortened rather than raising 22001', () => {
  const plan = admin.planClone(mod({ title: 'x'.repeat(255) }), {}, { crossSection: false });
  assert.strictEqual(plan.title.length, 255, '255 + " (copy)" is 262, and 22001 is a 500 for a clone that looks correct');
  assert.ok(plan.notices.some((n) => n.code === 'TITLE_TRUNCATED'));
});

test('an explicitly blank clone title is a refusal, not a silent fallback', () => {
  assert.throws(() => admin.planClone(mod(), { title: '   ' }, { crossSection: false }),
    (e) => e.status === 400 && e.code === 'TITLE_REQUIRED');
  assert.throws(() => admin.planClone(mod(), { profile_id: 'nope' }, { crossSection: false }),
    (e) => e.status === 400 && e.code === 'PROFILE_ID_INVALID');
});

// ---------------------------------------------------------------------------
// vocabulary()
// ---------------------------------------------------------------------------

test('vocabulary() ships the server-side maps the browser renders from', () => {
  const v = admin.vocabulary();
  assert.strictEqual(v.labels.release, S.RELEASE_LABELS);
  assert.strictEqual(v.labels.access, S.ACCESS_LABELS);
  assert.strictEqual(v.labels.completion, S.COMPLETION_LABELS);
  assert.strictEqual(v.release_states, S.RELEASE_STATES,
    'the select options ARE the CHECK constraint values, so the browser cannot offer one the database refuses');
  assert.ok(v.parts.length > 0);
  for (const p of v.parts) {
    assert.strictEqual(typeof p.number, 'number');
    assert.strictEqual(typeof p.name, 'string');
  }
  const numbers = v.parts.map((p) => p.number);
  assert.deepStrictEqual(numbers, [...numbers].sort((a, b) => a - b));
});

// ---------------------------------------------------------------------------
// Scanner compliance and vocabulary hygiene, for the file itself
// ---------------------------------------------------------------------------

test('module-admin.js trips none of the three scanners that walk this tree', () => {
  const AUDIT_TABLE = ['cybercore', 'audit', 'log'].join('_');
  const LANE_TABLE = ['cybercore', 'lane'].join('_');
  assert.ok(!/\$\d+\s+IS\s+(NOT\s+)?NULL/i.test(ADMIN_SRC),
    'an uncast parameter in a NULL test stays type "unknown" and the statement fails to parse');
  assert.ok(!ADMIN_SRC.includes(AUDIT_TABLE));
  assert.ok(!ADMIN_SRC.includes(LANE_TABLE));
});

test('no word from the other plugin\'s vocabulary reaches anything a person reads', () => {
  const code = ADMIN_SRC
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');
  const hit = code.match(/\b(course|courses|material|materials|challenge|challenges|assignment|assignments|lesson|lessons)\b/i);
  assert.strictEqual(hit, null,
    `module-admin.js names ${hit && hit[0]} — an instructor must never have to tell the two programs apart`);
});
