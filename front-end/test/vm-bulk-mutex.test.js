/**
 * Tests for the workstation-operation mutex and lane-scope query
 * (cle/utils/lane-provision.js)
 *
 * These cover the two pieces the bulk delete / bulk redeploy feature rests on,
 * both of which fail SILENTLY and destructively when they regress:
 *
 *   1. findCourseWorkstationLanes' `material_id IS NULL` predicate. Vulnerable-
 *      lab lanes carry config.material_id and are torn down through
 *      vuln-lab-provision, which knows about flag snapshots and module
 *      instances. One lab lane id reaching laneDeployer.teardownLanes destroys
 *      an assignment's machines through a path that has never heard of any of
 *      that. The predicate must live in the query that PRODUCES the ids — a
 *      second filtering pass is exactly what gets dropped in a refactor — so
 *      these assert on the emitted SQL text, the way sql-param-typing.test.js
 *      does.
 *
 *   2. The conflict matrix. The progress registry is the only mutex this app
 *      has (no job queue, one Node process). The cell most likely to be dropped
 *      in implementation is "an in-flight provision blocks a bulk delete":
 *      deployLanes inserts lane rows before its clones finish, so a bulk delete
 *      landing mid-provision enumerates lanes whose VMs are still being built
 *      and orphans them. The inverse cell — two different lanes must NOT block
 *      each other — is what keeps two instructors from queueing behind each
 *      other on the normal case.
 *
 * Nothing here touches a database or the cluster: cybercore-db is stubbed
 * through require.cache the way deploy-targets.test.js does it, and the mutex
 * tests drive global._batchDeployProgress by hand because listProgressIds and
 * readProgress read that global directly.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const SRC_UTILS = path.join(__dirname, '..', 'src', 'utils');
const CLE = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// site-config reads config/site.json, which is gitignored and absent in a plain
// checkout — and batch-deployer calls getSchedulingConfig() at MODULE level, so
// requiring lane-deployer would throw outside a deployed environment. Same stub
// provision-slots.test.js and lane-deployer-slots.test.js use.
stub(path.join(SRC_UTILS, 'site-config.js'), {
  getSchedulingConfig: () => ({
    min_free_mem_gb: 8, min_free_disk_gb: 20,
    max_concurrent_lanes: 5, max_concurrent_clones: 4,
    node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
  }),
});

let lastQuery = null;
let coreHandler = () => ({ rows: [] });
stub(path.join(SRC_UTILS, 'cybercore-db.js'), {
  cybercoreQuery: async (sql, params) => {
    lastQuery = { sql, params };
    return coreHandler(sql, params) || { rows: [] };
  },
});

const laneProvision = require(path.join(CLE, 'utils', 'lane-provision.js'));
const {
  progressIdForCourse,
  progressIdForCourseRebuild,
  progressIdForLane,
  courseOperationsInFlight,
  assertNoConflictingWorkstationOperation,
  findCourseWorkstationLanes,
} = laneProvision;

const COURSE = '11111111-1111-1111-1111-111111111111';
const OTHER_COURSE = '22222222-2222-2222-2222-222222222222';
const LANE_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const LANE_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

/** Replace the whole registry with the named in-flight entries. */
function given(entries) {
  global._batchDeployProgress = {};
  for (const [key, over] of Object.entries(entries)) {
    global._batchDeployProgress[key] = {
      group_name: 'x', total: 3, completed: 1, succeeded: 1, failed: 0,
      phase: 'cloning', phase_detail: 'Cloning', lanes: {},
      _laneTimes: [], _startedAtMs: Date.now(),
      ...over,
    };
  }
}

function conflictOf(args) {
  try {
    assertNoConflictingWorkstationOperation(args);
    return null;
  } catch (e) {
    return e;
  }
}

// ── key namespace ───────────────────────────────────────────────────────────

test('every key in the family shares the course prefix, so one listProgressIds finds them all', () => {
  const base = progressIdForCourse(COURSE);
  assert.ok(progressIdForCourseRebuild(COURSE).startsWith(base));
  assert.ok(progressIdForLane(COURSE, LANE_A).startsWith(base));
  // ...and the character after the prefix is always '-' or end-of-string, which
  // is what makes the prefix unambiguous for a fixed-length UUID course id.
  for (const k of [progressIdForCourseRebuild(COURSE), progressIdForLane(COURSE, LANE_A)]) {
    assert.strictEqual(k.slice(base.length).startsWith('-'), true);
  }
});

test('a sibling course\'s keys are never enumerated', () => {
  given({
    [progressIdForCourseRebuild(OTHER_COURSE)]: {},
    [progressIdForLane(OTHER_COURSE, LANE_A)]: {},
  });
  assert.deepStrictEqual(courseOperationsInFlight(COURSE), []);
});

test('scope and laneId are recovered by slicing the key', () => {
  given({
    [progressIdForCourse(COURSE)]: {},
    [progressIdForCourseRebuild(COURSE)]: {},
    [progressIdForLane(COURSE, LANE_A)]: {},
  });
  const byScope = Object.fromEntries(
    courseOperationsInFlight(COURSE).map(op => [op.scope, op])
  );
  assert.strictEqual(byScope.provision.laneId, null);
  assert.strictEqual(byScope.course.laneId, null);
  assert.strictEqual(byScope.lane.laneId, LANE_A);
});

// ── conflict matrix ─────────────────────────────────────────────────────────

test('an in-flight provision blocks a course-scope bulk operation', () => {
  // The cell most likely to be dropped. deployLanes inserts lane rows before
  // its clones finish, so a bulk delete here would enumerate lanes whose VMs
  // are still being built and orphan them.
  given({ [progressIdForCourse(COURSE)]: {} });
  const err = conflictOf({ courseId: COURSE });
  assert.ok(err, 'expected a conflict');
  assert.strictEqual(err.status, 409);
  assert.match(err.message, /deploy on this course/i);
});

test('an in-flight provision also blocks a single-lane rebuild', () => {
  // A provision is course-wide by construction — its key names no lanes — so
  // it can never be proven disjoint from one lane.
  given({ [progressIdForCourse(COURSE)]: {} });
  assert.strictEqual(conflictOf({ courseId: COURSE, laneId: LANE_A })?.status, 409);
});

test('a single-lane operation blocks a course-scope bulk operation', () => {
  given({ [progressIdForLane(COURSE, LANE_A)]: {} });
  assert.strictEqual(conflictOf({ courseId: COURSE })?.status, 409);
});

test('a single-lane operation does NOT block a different lane', () => {
  // Two instructors fixing two students is the normal case and must not queue.
  given({ [progressIdForLane(COURSE, LANE_A)]: {} });
  assert.strictEqual(conflictOf({ courseId: COURSE, laneId: LANE_B }), null);
});

test('a single-lane operation blocks the same lane', () => {
  given({ [progressIdForLane(COURSE, LANE_A)]: {} });
  assert.strictEqual(conflictOf({ courseId: COURSE, laneId: LANE_A })?.status, 409);
});

test('a course-scope bulk blocks another course-scope bulk', () => {
  // initProgress replaces the entry wholesale, so sharing the key would erase
  // the first operation's counters and report the second's to its poller.
  given({ [progressIdForCourseRebuild(COURSE)]: {} });
  assert.strictEqual(conflictOf({ courseId: COURSE })?.status, 409);
});

test('a completed entry conflicts with nothing', () => {
  // finishProgress leaves entries in place for an hour so a late poller can
  // still read the outcome. Without the exemption one finished bulk delete
  // would 409 every operation on the course for that hour.
  given({ [progressIdForCourseRebuild(COURSE)]: { phase: 'complete' } });
  assert.deepStrictEqual(courseOperationsInFlight(COURSE), []);
  assert.strictEqual(conflictOf({ courseId: COURSE }), null);
});

test('ignoreProgressId excludes the caller\'s own claim', () => {
  const mine = progressIdForCourseRebuild(COURSE);
  given({ [mine]: {} });
  assert.strictEqual(conflictOf({ courseId: COURSE, ignoreProgressId: mine }), null);
});

test('an empty registry conflicts with nothing', () => {
  delete global._batchDeployProgress;
  assert.deepStrictEqual(courseOperationsInFlight(COURSE), []);
  assert.strictEqual(conflictOf({ courseId: COURSE }), null);
});

// ── findCourseWorkstationLanes scoping ──────────────────────────────────────

test('the lane query filters lab lanes and foreign courses in ONE statement', async () => {
  coreHandler = () => ({ rows: [] });
  await findCourseWorkstationLanes(COURSE, [LANE_A]);

  const sql = lastQuery.sql;
  // The entire safety story of the bulk paths. If either of these moves out of
  // this query and into a second filtering pass, a lab lane id can reach
  // laneDeployer.teardownLanes and destroy an assignment's machines.
  assert.match(sql, /config->>'material_id'\s+IS NULL/,
    'material_id IS NULL must be in the query that produces the ids');
  assert.match(sql, /config->>'course_id'\s+=\s+\$1/,
    'course scoping must be in the same query');
  assert.match(sql, /status <> 'deleted'/);
  assert.deepStrictEqual(lastQuery.params, [COURSE, [LANE_A]]);
});

test('a null lane list means every workstation lane of the course', async () => {
  coreHandler = () => ({ rows: [] });
  await findCourseWorkstationLanes(COURSE);
  // The nullable-array form has to survive: passing null must not become
  // `= ANY(NULL)`, which matches nothing and would silently return an empty
  // course.
  assert.match(lastQuery.sql, /\$2::uuid\[\] IS NULL OR/);
  assert.deepStrictEqual(lastQuery.params, [COURSE, null]);
});

test('rows are returned verbatim, so callers hand the SERVER\'s ids downstream', async () => {
  // A caller must never pass its own request array to teardownLanes — only
  // what came back from here, which is already scope-checked.
  const row = {
    lane_id: LANE_A, user_id: 'u1', status: 'active', vxlan_id: 10003,
    config: { course_id: COURSE }, student_email: 'a@x.edu',
    first_name: 'A', last_name: 'B', created_at: new Date(0),
  };
  coreHandler = () => ({ rows: [row] });
  const rows = await findCourseWorkstationLanes(COURSE, [LANE_A, LANE_B]);
  assert.deepStrictEqual(rows.map(r => r.lane_id), [LANE_A],
    'a requested id the query rejected must not appear in the result');
});
