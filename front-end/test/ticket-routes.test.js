/**
 * ticket-routes.test.js — the parts of the ticket API that decide who sees what.
 *
 * Two classes of bug are pinned here, both silent in the obvious tests:
 *
 *   1. SCOPE. scopeClause() is the single predicate behind the staff list, the
 *      status counts and the detail read. If those three ever disagree, a
 *      ticket shows in a count and 404s when clicked — or, far worse, an
 *      instructor's list widens to somebody else's course. The clause is also
 *      spliced into queries that already have parameters, so its $n numbering
 *      has to survive being offset; a shift there does not error, it silently
 *      compares the scope against the wrong value.
 *
 *   2. ROUTE ORDER. Express matches router paths in registration order, so
 *      /mine, /stats and /form MUST be declared before /:id. Registered the
 *      other way round, GET /api/tickets/mine is answered as "ticket 'mine' not
 *      found" — a 404 that looks like an empty list rather than a routing bug.
 *
 * The router pulls in the connection pool and the lane deployer at require
 * time, so both are stubbed; nothing under test does I/O.
 *
 * Run: node front-end/test/ticket-routes.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const Module = require('module');

const SRC = path.join(__dirname, '..', 'src');
const DB_PATH = path.join(SRC, 'utils', 'cybercore-db.js');
const DEPLOYER_PATH = path.join(SRC, 'utils', 'lane-deployer.js');
const ROUTE_PATH = path.join(SRC, 'routes', 'tickets.js');

const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const resolved = (() => {
    try { return Module._resolveFilename(request, parent); } catch { return request; }
  })();
  if (resolved === DB_PATH) {
    return { cybercorePool: { connect: async () => ({}) }, cybercoreQuery: async () => ({ rows: [], rowCount: 0 }) };
  }
  // lane-deployer reads config/site.json at require time and drags in Proxmox,
  // Guacamole and SSH. Only one pure function is used from it.
  if (resolved === DEPLOYER_PATH) {
    return { laneWorkstationRecords: lane => (lane.config && lane.config.workstations) || [] };
  }
  return realLoad(request, parent, isMain);
};

const router = require(ROUTE_PATH);
const tickets = require(path.join(SRC, 'utils', 'tickets.js'));
Module._load = realLoad;

const ADMIN = { userId: 'u-admin', role: 'admin' };
const TEACH = { userId: 'u-teach', role: 'instructor' };
const STUDENT = { userId: 'u-stud', role: 'student' };

/** [method, path] for every route the router registered, in order. */
function routeTable() {
  return router.stack
    .filter(layer => layer.route)
    .map(layer => [Object.keys(layer.route.methods)[0], layer.route.path]);
}

// ── route order ─────────────────────────────────────────────────────────────

test('the literal GET paths are registered before /:id', () => {
  const table = routeTable();
  const idAt = table.findIndex(([m, p]) => m === 'get' && p === '/:id');
  assert.ok(idAt >= 0, '/:id is not registered');
  for (const literal of ['/form', '/mine', '/stats']) {
    const at = table.findIndex(([m, p]) => m === 'get' && p === literal);
    assert.ok(at >= 0, `${literal} is not registered`);
    assert.ok(at < idAt, `${literal} is registered after /:id and will never match`);
  }
});

test('every endpoint the UI calls exists', () => {
  const table = routeTable().map(([m, p]) => `${m} ${p}`);
  for (const route of [
    'get /form', 'post /', 'get /mine', 'get /', 'get /stats', 'get /:id',
    'patch /:id/status', 'post /:id/reply', 'post /:id/note', 'post /:id/comment',
  ]) {
    assert.ok(table.includes(route), `missing route: ${route}`);
  }
});

test('there are no unexpected extra routes', () => {
  // A stray route added without a scope check is exactly the kind of thing
  // that gets reviewed once and never again.
  assert.strictEqual(routeTable().length, 10);
});

// ── scope ───────────────────────────────────────────────────────────────────

test('an admin is unscoped', () => {
  const s = tickets.scopeClause(ADMIN, []);
  assert.strictEqual(s.text, 'TRUE');
  assert.deepStrictEqual(s.params, []);
});

test('a student sees only tickets they filed', () => {
  const s = tickets.scopeClause(STUDENT, ['c-1', 'c-2']);
  // Even handed a course list, a student must never be scoped by course.
  assert.strictEqual(s.text, 't.requester_user_id = $1');
  assert.deepStrictEqual(s.params, ['u-stud']);
  assert.ok(!s.text.includes('course_id'));
  assert.ok(!s.text.includes('instructor'));
});

test('an instructor is scoped by BOTH the snapshot and the live course list', () => {
  // Snapshot alone locks out a new instructor when a course changes hands;
  // live alone locks out the instructor who was actually Cc'd on the mail.
  const s = tickets.scopeClause(TEACH, ['c-1', 'c-2']);
  assert.match(s.text, /t\.instructor_user_id = \$1/);
  assert.match(s.text, /t\.course_id = ANY\(\$2::uuid\[\]\)/);
  assert.deepStrictEqual(s.params, ['u-teach', ['c-1', 'c-2']]);
});

test('an instructor with no resolvable courses still sees their snapshot tickets', () => {
  // The cle_db-is-down path: narrower, never empty, never an error.
  const s = tickets.scopeClause(TEACH, []);
  assert.deepStrictEqual(s.params, ['u-teach', []]);
  assert.match(s.text, /instructor_user_id = \$1/);
});

test('the instructor clause cannot match a ticket with no course', () => {
  // Postgres: NULL = ANY(...) is NULL, not true — but relying on that is how a
  // guard gets deleted as redundant. The explicit IS NOT NULL is the guard.
  const s = tickets.scopeClause(TEACH, ['c-1']);
  assert.match(s.text, /t\.course_id IS NOT NULL AND t\.course_id = ANY/);
});

test('an anonymous or role-less caller gets the requester scope, not everything', () => {
  // Fails CLOSED. A missing role must never fall through to the admin branch.
  for (const who of [{ userId: 'x' }, { userId: 'x', role: 'user' }, { userId: 'x', role: 'wizard' }]) {
    const s = tickets.scopeClause(who, ['c-1']);
    assert.strictEqual(s.text, 't.requester_user_id = $1', `${who.role} was over-scoped`);
  }
  const none = tickets.scopeClause(null, []);
  assert.strictEqual(none.text, 't.requester_user_id = $1');
  assert.deepStrictEqual(none.params, [null]);
});

// ── placeholder arithmetic ─────────────────────────────────────────────────

test('placeholders shift together when the clause is spliced into a bigger query', () => {
  // A shift here does not error. It silently compares the scope against the
  // wrong value, which in this module means showing one person another
  // person's tickets.
  assert.strictEqual(tickets.offsetPlaceholders('a = $1 AND b = $2', 3), 'a = $4 AND b = $5');
  assert.strictEqual(tickets.offsetPlaceholders('a = $1', 0), 'a = $1');
  assert.strictEqual(tickets.offsetPlaceholders('TRUE', 5), 'TRUE');
});

test('double-digit placeholders are not mangled', () => {
  // $1 inside $10 is the classic string-replace bug.
  assert.strictEqual(tickets.offsetPlaceholders('x = $9 AND y = $10', 1), 'x = $10 AND y = $11');
});

test('a cast on a placeholder survives the shift', () => {
  assert.strictEqual(
    tickets.offsetPlaceholders('t.course_id = ANY($2::uuid[])', 2),
    't.course_id = ANY($4::uuid[])'
  );
});

test('every scope clause numbers its placeholders from $1 with no gaps', () => {
  // listTickets() appends its own filters after the scope params, so the clause
  // must start at $1 and use every number up to its own count.
  for (const [who, taught] of [[ADMIN, []], [TEACH, ['c-1']], [STUDENT, []]]) {
    const s = tickets.scopeClause(who, taught);
    const used = [...s.text.matchAll(/\$(\d+)/g)].map(m => Number(m[1]));
    const expected = s.params.map((_, i) => i + 1);
    assert.deepStrictEqual([...new Set(used)].sort((a, b) => a - b), expected,
      `${who.role} clause placeholders do not match its params`);
  }
});
