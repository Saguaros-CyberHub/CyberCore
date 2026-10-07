/**
 * audit-api.test.js — the read side of the audit log.
 *
 * Two things are tested here because they are the two that break silently:
 *
 *   1. $n placeholder numbering as filters combine. Every admin route in this
 *      repo hand-rolls its WHERE clause with a manual `paramIdx++`
 *      (src/routes/admin/cluster.js:584-596 is the template), and an
 *      off-by-one there does not throw — it binds the wrong value to the
 *      wrong column and returns confidently wrong rows.
 *
 *   2. CSV escaping. An audit log is full of attacker-controlled strings: the
 *      email typed at a failed login, a user agent, a lane name. A quote or a
 *      newline breaks the file; a leading '=' makes Excel execute it.
 *
 * Run: node front-end/test/audit-api.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const Module = require('module');

const DB_PATH = path.join(__dirname, '..', 'src', 'utils', 'cybercore-db.js');
const ROUTE_PATH = path.join(__dirname, '..', 'src', 'routes', 'admin', 'audit.js');

// The router pulls in the pool at require time; stub it so no connection is
// attempted. Everything under test is pure.
const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const resolved = (() => {
    try { return Module._resolveFilename(request, parent); } catch { return request; }
  })();
  if (resolved === DB_PATH) {
    return { cybercorePool: {}, cybercoreQuery: async () => ({ rows: [], rowCount: 0 }) };
  }
  return realLoad(request, parent, isMain);
};

const { buildAuditWhere, csvCell } = require(ROUTE_PATH);
Module._load = realLoad;

/** Highest $n mentioned in a clause. */
function maxPlaceholder(clause) {
  const found = [...clause.matchAll(/\$(\d+)/g)].map(m => Number(m[1]));
  return found.length ? Math.max(...found) : 0;
}

test('no filters produces no WHERE clause and no params', () => {
  const r = buildAuditWhere({});
  assert.strictEqual(r.clause, '');
  assert.deepStrictEqual(r.params, []);
  assert.strictEqual(r.nextIdx, 1);
});

test('placeholders stay in step with params as filters combine', () => {
  const r = buildAuditWhere({
    action: 'lane.deployed',
    category: 'infra',
    status: 'failure',
    source: 'cle',
    actor_user_id: 'u-1',
    target_user_id: 's-1',
    target_type: 'lane',
    from: '2026-01-01',
    to: '2026-02-01',
    q: 'jane',
  });

  // The invariant that matters: every param has exactly one placeholder, and
  // nextIdx points at the first unused slot for LIMIT/OFFSET.
  assert.strictEqual(maxPlaceholder(r.clause), r.params.length);
  assert.strictEqual(r.nextIdx, r.params.length + 1);
});

test('a repeated filter collapses to = ANY, binding one array param', () => {
  const r = buildAuditWhere({ action: ['lane.deployed', 'lane.destroyed'] });
  assert.ok(r.clause.includes('= ANY($1)'));
  assert.deepStrictEqual(r.params, [['lane.deployed', 'lane.destroyed']]);
  assert.strictEqual(r.nextIdx, 2);
});

test('a single-valued repeatable filter uses plain equality', () => {
  const r = buildAuditWhere({ action: ['lane.deployed'] });
  assert.ok(r.clause.includes('a.action = $1'));
  assert.ok(!r.clause.includes('ANY'));
});

test('empty-string filters are ignored rather than matching empty rows', () => {
  const r = buildAuditWhere({ action: '', category: '', q: '' });
  assert.strictEqual(r.clause, '');
  assert.deepStrictEqual(r.params, []);
});

test('the free-text search reuses ONE placeholder across every column', () => {
  const r = buildAuditWhere({ q: 'jane' });
  // Five columns, one bound value — repeating the param would shift every
  // subsequent index.
  assert.strictEqual(r.params.length, 1);
  assert.strictEqual(r.params[0], '%jane%');
  assert.strictEqual((r.clause.match(/\$1/g) || []).length, 5);
  assert.strictEqual(r.nextIdx, 2);
});

test('startIdx reserves earlier placeholders for the export keyset cursor', () => {
  // The CSV export binds (occurred_at, audit_id) as $1/$2 before the filters.
  const r = buildAuditWhere({ status: 'denied' }, 3);
  assert.ok(r.clause.includes('$3'));
  assert.ok(!r.clause.includes('$1'));
  assert.strictEqual(r.nextIdx, 4);
});

test('target_id is bound as text, matching the column type', () => {
  const r = buildAuditWhere({ target_id: 10432 });
  assert.strictEqual(r.params[0], '10432');
});

test('CSV cells are quoted and embedded quotes doubled', () => {
  assert.strictEqual(csvCell('plain'), '"plain"');
  assert.strictEqual(csvCell('say "hi"'), '"say ""hi"""');
  assert.strictEqual(csvCell(null), '""');
  assert.strictEqual(csvCell(undefined), '""');
});

test('a newline inside a value cannot break the row', () => {
  const cell = csvCell('line one\r\nline two');
  assert.ok(cell.startsWith('"') && cell.endsWith('"'));
  // Quoted newlines are legal CSV; what matters is that the quoting survives.
  assert.strictEqual((cell.match(/"/g) || []).length, 2);
});

test('formula injection is neutralized', () => {
  // An audit log records what somebody typed at a login prompt. If that lands
  // in a spreadsheet unescaped, opening the export runs it.
  // A leading ' defuses the formula. Single quotes inside are data, not
  // delimiters, so only double quotes get doubled.
  assert.strictEqual(csvCell("=cmd|'/c calc'!A1"), `"'=cmd|'/c calc'!A1"`);
  assert.strictEqual(csvCell('=1+1 says "hi"'), `"'=1+1 says ""hi"""`);
  assert.ok(csvCell('+1+1').startsWith('"\'+'));
  assert.ok(csvCell('-2+3').startsWith('"\'-'));
  assert.ok(csvCell('@SUM(A1)').startsWith('"\'@'));
});

test('objects are serialized, so metadata and changes export as JSON', () => {
  assert.strictEqual(csvCell({ a: 1 }), '"{""a"":1}"');
});
