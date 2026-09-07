'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { EVENT_SCHEMA_SQL, ensureCrucibleEventSchema } = require('../src/utils/crucible-events-schema');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');
const fresh = fs.readFileSync(path.join(REPO, 'config/postgres/modules/crucible.sql'), 'utf8');
const base = fs.readFileSync(path.join(REPO, 'config/postgres/001_init_db.sql'), 'utf8');
const routeSource = fs.readFileSync(path.join(ROOT, 'modules/crucible/routes/events.js'), 'utf8');
const flat = text => text.replace(/\s+/g, ' ').trim();

function harness(query) {
  const handlers = new Map();
  const router = {};
  for (const method of ['get', 'post', 'patch', 'delete']) {
    router[method] = (route, ...callbacks) => handlers.set(`${method} ${route}`, callbacks.at(-1));
  }
  const noop = () => {};
  const mocks = {
    express: { Router: () => router },
    '../../../src/middleware/auth': { authenticateToken: noop, requireRole: () => noop },
    '../../../src/utils/cybercore-db': { cybercoreQuery: query },
  };
  new Function('require', 'module', 'console', routeSource)(id => {
    assert.ok(Object.hasOwn(mocks, id), `Unexpected dependency: ${id}`);
    return mocks[id];
  }, { exports: {} }, { error: noop });
  return async (method, { role = 'user', query = {}, body = {}, userId = 'actor-id' } = {}) => {
    const res = { statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; return this; } };
    await handlers.get(`${method} /api/crucible/events`)({ user: { role, userId }, query, body }, res);
    return res;
  };
}

test('runtime upgrades use the authoritative fresh event columns, indexes, and score table', () => {
  for (const pattern of [
    /ALTER TABLE cybercore_event[\s\S]*?;/,
    /CREATE TABLE IF NOT EXISTS crucible_score \([\s\S]*?\n\);/,
  ]) {
    const expected = fresh.match(pattern);
    const actual = EVENT_SCHEMA_SQL.match(pattern);
    assert.ok(expected && actual);
    assert.equal(flat(actual[0]), flat(expected[0]));
  }
  for (const expected of fresh.matchAll(/CREATE INDEX IF NOT EXISTS idx_cybercore_event_[^;]+;/g)) {
    assert.ok(flat(EVENT_SCHEMA_SQL).includes(flat(expected[0])));
  }
  assert.doesNotMatch(EVENT_SCHEMA_SQL, /(?:^|\n)\s*(DROP|TRUNCATE|UPDATE|DELETE|INSERT)\b/i);
});

test('the old core-only table is missing creator metadata and the upgrade adds every route event column', () => {
  const oldTable = base.match(/CREATE TABLE IF NOT EXISTS cybercore_event \(([\s\S]*?)\n\);/)[1];
  const oldColumns = new Set([...oldTable.matchAll(/^\s*(\w+)\s+/gm)].map(match => match[1]));
  assert.equal(oldColumns.has('created_by'), false, 'Keep the historical-volume regression meaningful');
  const additions = [...EVENT_SCHEMA_SQL.matchAll(/ADD COLUMN IF NOT EXISTS (\w+)/g)].map(match => match[1]);
  const upgradedColumns = new Set([...oldColumns, ...additions]);
  for (const match of routeSource.matchAll(/\be\.(\w+)/g)) {
    assert.ok(upgradedColumns.has(match[1]), `Event route column ${match[1]} is missing from the upgrade`);
  }
  assert.match(EVENT_SCHEMA_SQL, /created_by\s+UUID REFERENCES cybercore_user\(user_id\) ON DELETE SET NULL/);
});

test('the hand-run migration reuses the runtime SQL and startup awaits it before listening', () => {
  const migrationPath = path.join(ROOT, 'migrations/036_crucible_events.sql');
  const migration = fs.readFileSync(migrationPath, 'utf8');
  const include = migration.match(/^\\ir\s+(.+)$/m);
  assert.ok(include);
  assert.equal(fs.readFileSync(path.resolve(path.dirname(migrationPath), include[1].trim()), 'utf8'), EVENT_SCHEMA_SQL);
  const server = fs.readFileSync(path.join(ROOT, 'src/server.js'), 'utf8');
  const initialize = server.indexOf("await require('./utils/crucible-events-schema').ensureCrucibleEventSchema()");
  assert.ok(initialize > server.indexOf('async function start()'));
  assert.ok(initialize < server.indexOf('app.listen(', initialize));
  assert.match(server, /Event schema initialization failed; event requests remain unavailable/);
});

test('schema ensure sends the idempotent DDL unchanged and exposes migration failures', async () => {
  const calls = [];
  const query = async sql => calls.push(sql);
  await ensureCrucibleEventSchema({ query });
  await ensureCrucibleEventSchema({ query });
  assert.deepEqual(calls, [EVENT_SCHEMA_SQL, EVENT_SCHEMA_SQL]);
  const failure = new Error('permission denied for table cybercore_event');
  await assert.rejects(ensureCrucibleEventSchema({ query: async () => { throw failure; } }), error => error === failure);
});

test('student event lists filter event status explicitly despite the joined user status column', async () => {
  let observed;
  const events = [{ event_id: 'public-event', created_by_name: 'Lab Author', participant_count: '2' }];
  const call = harness(async (sql, params) => { observed = { sql, params }; return { rows: events }; });
  const response = await call('get', { query: { type: 'weekly' } });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.events, events);
  assert.deepEqual(observed.params, ['weekly']);
  assert.match(observed.sql, /WHERE e\.module_key = 'crucible' AND e\.event_type = \$1 AND e\.status = 'active' AND e\.is_public = true/);
  assert.match(observed.sql, /LEFT JOIN cybercore_user u ON e\.created_by = u\.user_id/);
  assert.match(observed.sql, /COUNT\(DISTINCT s\.user_id\) AS participant_count/);
});

test('admin event lists include drafts and private events while retaining module scope', async () => {
  let sql;
  const call = harness(async text => { sql = text; return { rows: [] }; });
  const response = await call('get', { role: 'admin' });
  assert.equal(response.statusCode, 200);
  assert.match(sql, /WHERE e\.module_key = 'crucible'/);
  assert.doesNotMatch(sql, /e\.status = 'active'|e\.is_public = true/);
});

test('event creation records the authenticated creator rather than a client-supplied identity', async () => {
  let observed;
  const created = { event_id: 'new-event', created_by: 'authenticated-admin', status: 'draft' };
  const call = harness(async (sql, params) => { observed = { sql, params }; return { rows: [created] }; });
  const response = await call('post', { role: 'admin', userId: 'authenticated-admin', body: {
    name: 'Course exercise', event_type: 'weekly', is_public: false, created_by: 'different-user',
  } });
  assert.equal(response.statusCode, 201);
  assert.deepEqual(response.body.event, created);
  assert.match(observed.sql, /is_public, created_by, module_key/);
  assert.equal(observed.params[6], false);
  assert.equal(observed.params[7], 'authenticated-admin');
});

test('database errors remain visible instead of being reported as an empty successful list', async () => {
  const call = harness(async () => { throw new Error('column e.created_by does not exist'); });
  const response = await call('get');
  assert.equal(response.statusCode, 500);
  assert.match(response.body.error, /created_by/);
});
