'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cleanup = require('../src/utils/wazuh-agent-cleanup');

const laneId = '11111111-1111-4111-8111-111111111111';
const jobId = '22222222-2222-4222-8222-222222222222';
const manager = '100.100.20.10';
const agentName = `cc-${laneId.replaceAll('-', '')}-610811-${jobId.replaceAll('-', '')}`;
const registration = { job_id: jobId, vm_id: 610811, manager, agent_id: '013', agent_name: agentName };
const copy = value => structuredClone(value);

// A shared atomic statement model exercises worker claims/acknowledgements,
// including distinct service instances and replacement snapshots. All HTTP is
// injected; these tests never reach real Wazuh or Proxmox infrastructure.
function environment() {
  let clock = Date.parse('2026-09-07T12:00:00Z');
  const rows = new Map(), liveLanes = new Set(), agents = new Map();
  const calls = [], statements = [];
  let settingsCalls = 0;
  function add(registrations = [registration], changes = {}) {
    const row = { lane_id: laneId, registrations: copy(registrations), created_at: new Date(clock).toISOString(),
      retain_until: new Date(clock + cleanup.GRACE_MS).toISOString(), next_attempt_at: new Date(clock).toISOString(),
      attempts: 0, last_error: null, lease_token: null, lease_until: null, ...changes };
    rows.set(row.lane_id, row); return row;
  }
  async function query(sql, args = []) {
    statements.push({ sql, args });
    if (sql.includes('CREATE TABLE IF NOT EXISTS')) return { rows: [] };
    if (sql.includes('WITH candidate AS')) {
      const row = [...rows.values()].find(item => Date.parse(item.next_attempt_at) <= Date.parse(args[0])
        && (!item.lease_until || Date.parse(item.lease_until) <= Date.parse(args[0])));
      if (!row) return { rows: [] };
      Object.assign(row, { lease_token: args[1], lease_until: args[2], attempts: row.attempts + 1 });
      return { rows: [copy(row)] };
    }
    if (sql.startsWith('SELECT lane_id FROM cybercore_lane')) return { rows: liveLanes.has(args[0]) ? [{ lane_id: args[0] }] : [] };
    const row = rows.get(args[0]);
    const owned = row && row.lease_token === args[1];
    if (sql.includes('SET lease_until =')) {
      if (owned) row.lease_until = args[2];
      return { rows: owned ? [{ lane_id: row.lane_id }] : [] };
    }
    if (sql.includes('DELETE FROM cybercore_wazuh_cleanup')) {
      if (owned) rows.delete(row.lane_id);
      return { rows: owned ? [{ lane_id: args[0] }] : [] };
    }
    if (sql.includes('SET next_attempt_at =')) {
      if (owned) Object.assign(row, { next_attempt_at: args[2], last_error: args[3], lease_token: null, lease_until: null });
      return { rows: [], rowCount: owned ? 1 : 0 };
    }
    throw new Error('Unexpected SQL');
  }
  const client = {
    listAgents: async () => { calls.push(['list']); return [...agents.values()].map(copy); },
    deleteAgent: async (id, name) => {
      calls.push(['delete', id, name]);
      const agent = agents.get(id);
      if (agent && agent.name !== name) throw new Error('Identity mismatch');
      agents.delete(id);
      return { id, name, already_absent: !agent };
    },
  };
  const settings = () => { settingsCalls++; return { manager, client }; };
  const factory = changes => cleanup.createService({ query, settings, now: () => clock, ...changes });
  return { rows, agents, liveLanes, calls, statements, client, query, add, factory,
    now: () => clock, advance: milliseconds => { clock += milliseconds; }, settingsCalls: () => settingsCalls };
}

test('cleanup removes only the exact managed registration and keeps a tombstone during grace', async () => {
  const e = environment(); const row = e.add();
  e.agents.set('013', { id: '013', name: agentName });
  e.agents.set('001', { id: '001', name: 'cyberhub-node-0' });
  e.agents.set('999', { id: '999', name: 'other-lane-vm-610811' });
  const result = await e.factory().processPending();
  assert.deepEqual(result, { processed: 1, completed: 0, deferred: 1, failed: 0, removed: 1 });
  assert.deepEqual([...e.agents.keys()], ['001', '999']);
  assert.deepEqual(e.calls, [['list'], ['delete', '013', agentName]]);
  assert.equal(e.rows.get(laneId), row);
  assert.equal(row.last_error, null); assert.equal(row.lease_token, null);
});

test('a registration created after an initial missing result is removed on a later grace-period check', async () => {
  const e = environment(); const missingId = { ...registration }; delete missingId.agent_id;
  e.add([missingId]);
  const service = e.factory();
  assert.equal((await service.processPending()).deferred, 1);
  assert.deepEqual(e.calls, [['list']]);
  e.agents.set('014', { id: '014', name: agentName });
  e.advance(cleanup.RECHECK_MS);
  assert.equal((await service.processPending()).removed, 1);
  assert.deepEqual(e.calls.at(-1), ['delete', '014', agentName]);
  e.advance(cleanup.GRACE_MS);
  assert.equal((await service.processPending()).completed, 1);
  assert.equal(e.rows.size, 0);
});

test('installation retries retain their original enrollment identity despite a new job UUID', async () => {
  const e = environment();
  e.add([{ ...registration, job_id: '33333333-3333-4333-8333-333333333333' }]);
  e.agents.set('013', { id: '013', name: agentName });
  assert.equal((await e.factory().processPending()).removed, 1);
  assert.deepEqual(e.calls, [['list'], ['delete', '013', agentName]]);
});

test('outages retain cleanup across restarts with bounded increasing backoff and no secret error text', async () => {
  const e = environment(); const row = e.add();
  e.agents.set('013', { id: '013', name: agentName });
  e.client.deleteAgent = async () => { throw new Error('password=DO_NOT_STORE_THIS'); };
  for (let attempt = 1; attempt <= 9; attempt++) {
    const result = await e.factory().processPending();
    assert.equal(result.failed, 1); assert.equal(e.rows.size, 1);
    const delay = Date.parse(row.next_attempt_at) - e.now();
    assert.ok(delay >= cleanup.RECHECK_MS && delay <= cleanup.MAX_BACKOFF_MS);
    assert.doesNotMatch(row.last_error, /DO_NOT_STORE_THIS|password=/);
    e.advance(delay);
  }
  e.client.deleteAgent = async (id, name) => ({ id, name, already_absent: true });
  assert.equal((await e.factory().processPending()).completed, 1);
  assert.equal(e.rows.size, 0);
});

test('manager changes and invalid ownership metadata remain pending indefinitely without API deletes', async () => {
  for (const invalid of [
    { manager: '100.100.20.11' }, { agent_name: 'cyberhub-node-0' }, { vm_id: 610812 },
    { agent_name: agentName.replace(laneId.replaceAll('-', ''), '9'.repeat(32)) },
    { agent_id: '000' }, { agent_id: '013,014' }, { job_id: 'bad' },
  ]) {
    const e = environment(); const row = e.add([{ ...registration, ...invalid }]);
    e.advance(cleanup.GRACE_MS + 1);
    assert.equal((await e.factory().processPending()).failed, 1);
    assert.equal(e.rows.size, 1); assert.ok(row.last_error);
    assert.equal(e.calls.length, 0);
  }
});

test('known IDs still require identity verification and ambiguous name lookups never delete', async () => {
  const e = environment(); e.add();
  e.agents.set('013', { id: '013', name: 'unrelated-infrastructure-server' });
  e.agents.set('014', { id: '014', name: agentName });
  assert.equal((await e.factory().processPending()).failed, 1);
  assert.equal(e.agents.get('013').name, 'unrelated-infrastructure-server');
  const byName = environment(); const item = { ...registration }; delete item.agent_id;
  byName.add([item]);
  byName.agents.set('013', { id: '013', name: agentName });
  byName.agents.set('014', { id: '014', name: agentName });
  assert.equal((await byName.factory().processPending()).failed, 1);
  assert.deepEqual(byName.calls, [['list']]);
});

test('a reused numeric ID is preserved once the original managed name is gone', async () => {
  const e = environment(); e.add(); e.agents.set('013', { id: '013', name: agentName });
  const service = e.factory();
  assert.equal((await service.processPending()).removed, 1);
  e.agents.set('013', { id: '013', name: 'new-unrelated-agent' });
  e.advance(cleanup.GRACE_MS + 1);
  assert.equal((await service.processPending()).completed, 1);
  assert.equal(e.agents.get('013').name, 'new-unrelated-agent');
  assert.equal(e.calls.filter(call => call[0] === 'delete').length, 1);
});

test('malformed inventory cannot falsely confirm that a registration disappeared', async () => {
  for (const inventory of [null, [{ id: '013' }], [{ id: 13, name: agentName }],
    [{ id: '013', name: 'one' }, { id: '013', name: 'two' }]]) {
    const e = environment(); e.add(); e.advance(cleanup.GRACE_MS + 1);
    e.client.listAgents = async () => inventory;
    assert.equal((await e.factory().processPending()).failed, 1);
    assert.equal(e.rows.size, 1); assert.equal(e.calls.length, 0);
  }
});

test('a lane that still exists cannot have its registration removed', async () => {
  const e = environment(); e.add(); e.liveLanes.add(laneId);
  assert.equal((await e.factory().processPending()).failed, 1);
  assert.equal(e.calls.length, 0); assert.equal(e.settingsCalls(), 0);
});

test('empty registration arrays need no configured Wazuh API and retire after grace', async () => {
  const e = environment(); e.add([]);
  const service = e.factory({ settings: () => { throw new Error('must not load API settings'); } });
  assert.equal((await service.processPending()).deferred, 1);
  e.advance(cleanup.GRACE_MS);
  assert.equal((await service.processPending()).completed, 1);
  assert.equal(e.calls.length, 0);
});

test('duplicate snapshots are deduplicated while conflicting saved IDs stay pending', async () => {
  const e = environment(); const withoutId = { ...registration }; delete withoutId.agent_id;
  e.add([withoutId, registration, { ...registration, password: 'never-used' }]);
  e.agents.set('013', { id: '013', name: agentName });
  await e.factory().processPending();
  assert.deepEqual(e.calls, [['list'], ['delete', '013', agentName]]);
  const normalized = cleanup.registrationsFor(laneId, [{ ...registration, password: 'not-persisted', agent_key: 'not-persisted' }]);
  assert.deepEqual(normalized, [registration]);
  const conflict = environment(); conflict.add([registration, { ...registration, agent_id: '014' }]);
  assert.equal((await conflict.factory().processPending()).failed, 1);
  assert.equal(conflict.calls.length, 0);
});

test('distinct workers cannot claim the same live lease; expired leases recover after restart', async () => {
  const e = environment(); e.add();
  e.agents.set('013', { id: '013', name: agentName });
  let release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  e.client.deleteAgent = async (id, name) => { entered(); await blocked; return { id, name, already_absent: true }; };
  const first = e.factory().processPending();
  await started;
  assert.equal((await e.factory().processPending()).processed, 0);
  release(); await first;
  const row = e.rows.get(laneId);
  row.lease_token = '44444444-4444-4444-8444-444444444444';
  row.lease_until = new Date(e.now() + cleanup.LEASE_MS).toISOString();
  e.advance(cleanup.LEASE_MS + 1);
  assert.equal((await e.factory().processPending()).processed, 1);
  assert.ok(e.statements.some(({ sql }) => /FOR UPDATE SKIP LOCKED/.test(sql)));
});

test('an old worker cannot acknowledge or delete a newly appended cleanup snapshot', async () => {
  const e = environment(); const row = e.add(); e.advance(cleanup.GRACE_MS + 1);
  e.agents.set('013', { id: '013', name: agentName });
  let release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  e.client.deleteAgent = async (id, name) => { entered(); await blocked; return { id, name, already_absent: true }; };
  const pending = e.factory().processPending({ limit: 1 }); await started;
  Object.assign(row, { lease_token: null, lease_until: null,
    retain_until: new Date(e.now() + cleanup.GRACE_MS).toISOString(), next_attempt_at: new Date(e.now()).toISOString() });
  release();
  assert.equal((await pending).completed, 0);
  assert.equal(e.rows.get(laneId), row);
  assert.equal(row.lease_token, null);
});

test('lease replacement while inventory is loading stops the old worker before deletion', async () => {
  const e = environment(); const row = e.add();
  let release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  e.client.listAgents = async () => { entered(); await blocked; return [{ id: '013', name: agentName }]; };
  const pending = e.factory().processPending({ limit: 1 }); await started;
  const replacement = '55555555-5555-4555-8555-555555555555';
  row.lease_token = replacement; release();
  assert.equal((await pending).failed, 1);
  assert.equal(e.calls.length, 0); assert.equal(row.lease_token, replacement);
});

test('background cleanup logs aggregate removals or pending failures without exposing API errors', async () => {
  for (const fail of [false, true]) {
    const e = environment(); const logs = []; e.add(); e.agents.set('013', { id: '013', name: agentName });
    if (fail) e.client.listAgents = async () => { throw new Error('SECRET API password'); };
    const service = e.factory({ log: text => logs.push(text), warn: text => logs.push(text) });
    service.kickWorker();
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(logs.length, 1);
    assert.match(logs[0], fail ? /Removed 0 registration\(s\); 1 lane\(s\) pending retry/ : /Removed 1 registration\(s\); 0 lane\(s\) pending retry/);
    assert.doesNotMatch(logs[0], /SECRET|password|013|610811/);
  }
});

test('cleanup API settings preserve TLS configuration without installer version or group requirements', () => {
  let passed;
  const result = cleanup.cleanupSettings({ WAZUH_MANAGER: manager, WAZUH_API_URL: 'https://100.100.20.10:55000',
    WAZUH_API_USERNAME: 'api-user', WAZUH_API_PASSWORD: 'test-only', WAZUH_API_CA_FILE: '/run/secrets/ca.pem',
    WAZUH_API_SERVER_NAME: 'localhost' }, { createClient: options => { passed = options; return 'client'; } });
  assert.equal(result.manager, manager); assert.equal(result.client, 'client');
  assert.equal(passed.caFile, '/run/secrets/ca.pem'); assert.equal(passed.serverName, 'localhost');
  assert.equal(passed.apiUrl, 'https://100.100.20.10:55000');
});

test('schema is retried after DDL failure and matches the operator migration without a cascading FK', async () => {
  const e = environment(); let failed = false;
  const service = e.factory({ query: async (...args) => {
    if (!failed) { failed = true; throw new Error('DDL denied'); } return e.query(...args);
  } });
  await assert.rejects(service.ensureSchema(), /DDL denied/);
  await service.ensureSchema();
  const migration = fs.readFileSync(path.join(__dirname, '../migrations/037_wazuh_agent_cleanup.sql'), 'utf8')
    .split(/\r?\n/).filter(line => !line.startsWith('--')).join('\n').trim();
  assert.equal(migration, cleanup.SCHEMA.trim());
  assert.doesNotMatch(cleanup.SCHEMA, /REFERENCES|ON DELETE CASCADE/);
});
