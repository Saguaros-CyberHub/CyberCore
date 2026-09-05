'use strict';

// Exercise the registered route callbacks with real spec/domain/compiler
// helpers. Every dependency capable of touching infrastructure is replaced.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');

const filename = path.join(__dirname, '../src/routes/lab-templates.js');
const sourceRequire = createRequire(filename);
const clone = value => JSON.parse(JSON.stringify(value));

function harness(stored = {}) {
  const handlers = new Map();
  const state = { reserved: null, updated: null };
  const router = {};
  for (const method of ['get', 'post', 'put', 'delete']) {
    router[method] = (route, ...callbacks) => handlers.set(`${method} ${route}`, callbacks.at(-1));
  }
  const query = async (sql, args) => {
    if (sql.includes('SELECT spec FROM crucible_challenge')) return { rows: [{ spec: clone(stored) }] };
    if (sql.includes('UPDATE crucible_challenge')) {
      state.updated = args[4] === null ? null : JSON.parse(args[4]);
      return { rows: [{ spec: state.updated }] };
    }
    throw new Error('Unexpected query in offline route test');
  };
  const noop = () => {};
  const mocks = {
    express: { Router: () => router },
    '../utils/db': { query },
    '../utils/cybercore-db': { cybercoreQuery: query },
    '../utils/proxmox': { proxmoxAPI: {} },
    '../utils/site-config': { getDefaultTemplateNode: () => 'offline-node' },
    '../middleware/auth': { authenticateToken: noop, requireRole: () => noop },
    '../utils/lab-network-provision': {
      sanitizeZoneAbbrev: () => 'fixture',
      reserveLabNetwork: async options => {
        state.reserved = clone(options.spec);
        return { challenge_id: 'offline' };
      },
      teardownLabNetwork: async () => { throw new Error('Unexpected teardown'); },
    },
  };
  const moduleObject = { exports: {} };
  new Function('require', 'module', 'exports', '__filename', '__dirname', 'console',
    fs.readFileSync(filename, 'utf8'))(
    id => Object.hasOwn(mocks, id) ? mocks[id] : sourceRequire(id),
    moduleObject, moduleObject.exports, filename, path.dirname(filename),
    { log: noop, warn: noop, error: noop },
  );
  return {
    state,
    async call(method, route, body) {
      const res = { statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(value) { this.body = value; return this; } };
      await handlers.get(`${method} ${route}`)({ body, params: { id: 'offline' } }, res);
      return res;
    },
  };
}

const mini = { enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org',
  child_subdomain: null, rename_forest: true };
const createBody = goad => ({ name: 'Offline fixture', challenge_key: 'offline',
  max_lanes: 1, template_vmid: 1004, goad });

test('POST preserves an explicit valid Mini opt-in before reserving the network', async () => {
  const h = harness();
  const res = await h.call('post', '/create-lab', createBody(mini));
  assert.equal(res.statusCode, 200, JSON.stringify(res.body));
  assert.equal(h.state.reserved.goad.rename_forest, true);
  assert.equal(h.state.reserved.goad.version, 'GOAD-Mini');
  assert.equal(h.state.reserved.goad.child_subdomain, null);
});

for (const changes of [
  { version: 'SCCM' }, { version: 'NO-SUCH-LAB' }, { version: '' },
  { domain: 'not-a-domain' }, { domain: 'demo.local' }, { domain: '' },
  { child_subdomain: 'unbuilt' }, { prebaked: true }, { enabled: 'true' },
  { extensions: ['not-an-extension'] }, { extensions: 'elk' },
  { generated_lab: { name: 'another-tree', files: { 'data/config.json': '{}' } } },
  { rename_plan: { baseLab: 'GOAD-Mini', domain: 'forged.org' } },
]) {
  test(`invalid rename POST is rejected before reservation: ${JSON.stringify(changes)}`, async () => {
    const h = harness();
    const res = await h.call('post', '/create-lab', createBody({ ...mini, ...changes }));
    assert.equal(res.statusCode, 400, JSON.stringify(res.body));
    assert.equal(h.state.reserved, null);
  });
}

test('legacy POST retains its defaults and never invents the opt-in', async () => {
  const h = harness();
  const res = await h.call('post', '/create-lab', createBody({ enabled: true, version: 'GOAD-Mini' }));
  assert.equal(res.statusCode, 200);
  assert.equal(h.state.reserved.goad.domain, 'cybersaguaros.local');
  assert.equal(h.state.reserved.goad.child_subdomain, 'tumamoc');
  assert.equal(Object.hasOwn(h.state.reserved.goad, 'rename_forest'), false);
});

test('PUT malformed opt-in fails before UPDATE and leaves the existing spec intact', async () => {
  const stored = { goad: mini, vms: [{ name: 'DC01' }] };
  const h = harness(stored);
  const res = await h.call('put', '/lab-templates/:id', {
    spec: { goad: { ...mini, domain: 'not-a-domain' } },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(h.state.updated, null);
  assert.equal(stored.goad.domain, 'cy400test.org');
});

function ciabSpec() {
  return { zone: { abbrev: 'owned' }, vxlan_block: { start: 400 },
    vms: [{ name: 'CUSTOMDC', role: 'dc', template_vmid: 91004 }],
    goad: { enabled: true, version: 'CIAB-fixture', domain: 'compiled.org',
      child_subdomain: null, include_kali: false, prebaked: true,
      fixed_subnet: { int: '10.167.161', ext: '10.39.161' },
      lab: { labName: 'CIAB-fixture', forestRoot: 'compiled.org',
        vms: [{ name: 'CUSTOMDC', role: 'dc', ipOctet: 10 }] } } };
}

test('CiAB prebaked edit preserves its server-owned custom roster when the card omits lab', async () => {
  const stored = ciabSpec();
  const input = clone(stored);
  delete input.goad.lab;
  const h = harness(stored);
  const res = await h.call('put', '/lab-templates/:id', { name: 'Updated title', spec: input });
  assert.equal(res.statusCode, 200, JSON.stringify(res.body));
  assert.deepEqual(h.state.updated, stored);
  assert.equal(Object.hasOwn(input.goad, 'lab'), false, 'the request is not mutated');
});

test('compiled lab and generated files survive unchanged full-spec roundtrip', async () => {
  const stored = ciabSpec();
  stored.goad.generated_lab = { name: 'CIAB-fixture', files: { 'data/config.json': '{}' },
    extension_configs: { ws01: { 'data/config.json': '{}' } } };
  const h = harness(stored);
  const res = await h.call('put', '/lab-templates/:id', { spec: clone(stored) });
  assert.equal(res.statusCode, 200, JSON.stringify(res.body));
  assert.deepEqual(h.state.updated, stored);
});

for (const change of [
  { lab: { forestRoot: 'injected.org' } },
  { generated_lab: { name: 'injected', files: { 'evil.yml': 'arbitrary' } } },
  { rename_plan: { baseLab: 'GOAD-Mini', domain: 'forged.org' } },
  { version: 'GOAD-Mini' }, { domain: 'different.org' },
]) {
  test(`compiled identity replacement fails before UPDATE: ${JSON.stringify(change)}`, async () => {
    const stored = ciabSpec();
    const h = harness(stored);
    const res = await h.call('put', '/lab-templates/:id', {
      spec: { goad: { ...stored.goad, ...change } },
    });
    assert.equal(res.statusCode, 400);
    assert.equal(h.state.updated, null);
  });
}

test('stock PUT cannot introduce a server-owned lab definition', async () => {
  const h = harness({ goad: mini });
  const res = await h.call('put', '/lab-templates/:id', {
    spec: { goad: { ...mini, lab: { forestRoot: 'injected.org' } } },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(h.state.updated, null);
});

test('explicitly disabling a compiled environment retains its definition', async () => {
  const stored = ciabSpec();
  const h = harness(stored);
  const res = await h.call('put', '/lab-templates/:id', {
    spec: { goad: { ...stored.goad, enabled: false } },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(h.state.updated.goad.enabled, false);
  assert.deepEqual(h.state.updated.goad.lab, stored.goad.lab);
});

test('null GOAD disables a compiled environment without deleting its server-owned definition', async () => {
  const stored = ciabSpec();
  const h = harness(stored);
  const res = await h.call('put', '/lab-templates/:id', { spec: { goad: null } });
  assert.equal(res.statusCode, 200);
  assert.equal(h.state.updated.goad.enabled, false);
  assert.deepEqual(h.state.updated.goad.lab, stored.goad.lab);
});

test('creating from an off-catalog compiled card refuses instead of dropping its definition', async () => {
  const h = harness();
  const res = await h.call('post', '/create-lab', createBody(ciabSpec().goad));
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /Edit the original compiled environment or regenerate/);
  assert.equal(h.state.reserved, null);
});

for (const version of ['GOAD-Light', 'GOAD', 'light', 'full']) {
  test(`${version} POST preserves effective authored child while keeping transformation on the controller`, async () => {
    const h = harness();
    const res = await h.call('post', '/create-lab', createBody({
      ...mini, version, child_subdomain: 'research', extensions: ['elk', 'ws01'],
    }));
    assert.equal(res.statusCode, 200, JSON.stringify(res.body));
    assert.equal(h.state.reserved.goad.child_subdomain, 'research');
    assert.equal(h.state.reserved.goad.rename_forest, true);
    assert.equal(Object.hasOwn(h.state.reserved.goad, 'generated_lab'), false);
  });
}

test('multi-domain PUT persists the same default child that the controller will build', async () => {
  const h = harness();
  const goad = { ...mini, version: 'GOAD-Light' };
  delete goad.child_subdomain;
  const res = await h.call('put', '/lab-templates/:id', { spec: { goad } });
  assert.equal(res.statusCode, 200, JSON.stringify(res.body));
  assert.equal(h.state.updated.goad.child_subdomain, 'corp');
});
