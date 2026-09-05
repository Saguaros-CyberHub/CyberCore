const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function fixture(routeName, faults = {}) {
  const calls = [];
  const routes = new Map();
  const noop = async () => {};
  const spec = { goad: { enabled: true, version: 'GOAD-Mini', rename_forest: true },
    vms: [{ name: 'DC01', template_vmid: 1004, vm_offset: 600000 }] };
  const metadata = { status: faults.goad ? 'failed' : 'provisioned', controller_vmid: 204242,
    forest_rename: { applied: true, forest_root: 'cy400test.org' },
    ...(faults.goad ? { error: 'domain join failed' } : {}) };
  let terminal;
  let writes = 0;
  const db = async (sql, args) => {
    calls.push({ kind: 'db', sql, args });
    if (/UPDATE cybercore_lane SET status = '(active|suspended)'/.test(sql)) {
      terminal = { status: sql.includes("'suspended'") ? 'suspended' : 'active', config: JSON.parse(args[1]) };
    }
    if (sql.includes('SELECT EXISTS')) return { rows: [{ is_installed: true }] };
    if (sql.includes('FROM cybercore_user')) return { rows: [{ user_id: 'u1', email: 'fixture@example.org' }] };
    if (sql.includes('FROM crucible_challenge')) return { rows: [{ id: 1, challenge_id: 1, challenge_key: 'fixture', name: 'Fixture', spec, subnet_scheme: 'v1' }] };
    if (sql.includes('WITH used')) return { rows: [{ vxlan_id: 4242 }] };
    if (sql.includes('INSERT INTO cybercore_lane')) return { rows: [{ lane_id: 'lane1', user_id: 'u1', vxlan_id: 4242 }] };
    if (sql.includes('INSERT INTO deployment_vuln_selections')) return { rows: [{ id: 1 }] };
    return { rows: [] };
  };
  const api = async (method, url) => {
    calls.push({ kind: 'api', method, url });
    if (url === '/api2/json/cluster/sdn/vnets') return [{ tag: 4242, vnet: 'vn4242', zone: 'z' }];
    return null;
  };
  const modules = {
    express: { Router: () => new Proxy({}, { get: (_, method) => (route, ...handlers) => routes.set(`${method}:${route}`, handlers.at(-1)) }) },
    '../../middleware/auth': { authenticateToken: noop, requireRole: () => noop },
    '../../utils/proxmox': { proxmoxAPI: api, waitForTask: noop, findTemplateNode: async id => id === 1701 ? 'gateway-source' : 'vm-source' },
    '../../utils/site-config': { getDefaultTemplateNode: () => 'template' },
    '../../utils/cybercore-db': { cybercoreQuery: db }, '../../utils/db': { query: db },
    '../../middleware/activity-logger': { logActivity: noop },
    '../../middleware/deployment-guards': { buildDeployPreview: async () => ({}) },
    '../../utils/script-executor': { waitForGuestAgent: async () => true, executeScriptsOnVM: noop, getVMIPs: async () => [] },
    '../../utils/flag-manager': { plantFlagsForLane: noop },
    '../../utils/node-selector': { selectBestNode: async () => ({ node: 'node1', score: 1 }) },
    '../../utils/goad-deploy': {
      CONTROLLER_TEMPLATE_VMID: 1700,
      prepareGoadDeploymentSpec: value => { calls.push({ kind: 'prepare' }); return value; },
      prepareGoadMacs: () => ({ DC01: { mac: '02:00:00:00:00:10', static_ip: '10.0.0.10' } }),
      buildLaneNet0: () => 'virtio,bridge=vn4242',
      deployGoadLane: async () => {
        calls.push({ kind: 'goad' });
        if (faults.goad) throw Object.assign(new Error('domain join failed'), { goadMeta: metadata });
        // No inner DB write: proves the route persists the returned metadata.
        return { controllerVmId: 204242, goadMeta: metadata };
      },
    },
    '../../utils/goad-agent-attach': { withGoadAgentVulnScripts: () => [] },
    '../../utils/challenge-lane-deployer': {
      resolveGoadExternalPins: () => ({}), resolveSpecAddressing: () => ({ pinnedHosts: [], dnsRecords: [] }),
      applyPrebakedFixedSubnet: () => {},
      validateGoadLaneAddressing: () => {
        calls.push({ kind: 'validate' });
        if (faults.preflight) throw Object.assign(new Error('external extension placement invalid'), { status: 400 });
      },
      writeLaneReservations: async () => {
        calls.push({ kind: 'reservations' });
        if (++writes === 2 && faults.dhcp) throw new Error('DHCP restoration failed');
      },
    },
    '../../utils/lane-networking': {
      resolveGatewayVmid: () => 1701, configureLaneTailscale: noop,
      resolveLaneNetworking: () => ({ wan: { ip: '10.0.0.2/24' }, lan: { base3: '10.0.0', gatewayIp: '10.0.0.1' } }),
      formatLaneGatewayNet0: () => '', resolveVmNics: () => ({ nets: { net0: 'virtio' }, dualHomed: false }),
      resolveSegmentBridges: () => ({}),
    },
    '../../utils/lane-claims': { claimsSql: () => "status NOT IN ('error','deleted')" },
  };
  const file = path.join(__dirname, '../src/routes/admin', `${routeName}.js`);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module: { exports: {} }, __dirname: path.dirname(file), Buffer,
    console: { log() {}, warn() {}, error() {} },
    setTimeout: callback => queueMicrotask(callback),
    require: name => modules[name] || (['crypto', 'fs', 'path'].includes(name) ? require(name) : {}),
  }, { filename: file });
  return {
    calls, metadata,
    async run() {
      const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
      const route = routeName === 'lanes' ? '/deploy-lane' : '/deploy-lab-network';
      await routes.get(`post:${route}`)({ body: { challenge_key: 'fixture', module: 'crucible', template_id: 1, confirm: true }, user: { userId: 'u1' } }, response);
      for (let i = 0; i < 30 && !terminal && response.statusCode === 200; i++) await new Promise(resolve => setImmediate(resolve));
      return { response, terminal };
    },
  };
}

for (const route of ['lanes', 'lab-networks']) {
  test(`${route}: addressing fails before allocation or any Proxmox calls`, async () => {
    const f = fixture(route, { preflight: true });
    const { response } = await f.run();
    assert.equal(response.statusCode, 400);
    assert.ok(!f.calls.some(call => call.kind === 'api' || (call.kind === 'db' && /WITH used|INSERT INTO cybercore_lane/.test(call.sql))));
  });
  test(`${route}: final success retains returned GOAD metadata without relying on inner persistence`, async () => {
    const f = fixture(route);
    const { terminal } = await f.run();
    assert.equal(terminal?.status, 'active');
    assert.deepEqual(terminal.config.goad, f.metadata);
    assert.equal(terminal.config.vms.length, 1);
    assert.ok(f.calls.some(call => call.url === '/api2/json/nodes/gateway-source/lxc/1701/clone'));
    assert.ok(f.calls.some(call => call.url === '/api2/json/nodes/vm-source/qemu/1004/clone'));
  });
  test(`${route}: DHCP restoration retains the original GOAD failure, metadata, and suspended claims`, async () => {
    const f = fixture(route, { goad: true, dhcp: true });
    const { terminal } = await f.run();
    assert.equal(terminal?.status, 'suspended');
    assert.equal(terminal.config.error, 'domain join failed');
    assert.equal(terminal.config.goad.controller_vmid, 204242);
    assert.equal(terminal.config.goad.dhcp_error, 'DHCP restoration failed');
    assert.equal(f.calls.filter(call => call.kind === 'reservations').length, 2);
  });
  test(`${route}: DHCP failure after GOAD success retains its controller and blocks readiness`, async () => {
    const f = fixture(route, { dhcp: true });
    const { terminal } = await f.run();
    assert.equal(terminal?.status, 'suspended');
    assert.equal(terminal.config.error, 'DHCP restoration failed');
    assert.equal(terminal.config.goad.status, 'failed');
    assert.equal(terminal.config.goad.controller_vmid, 204242);
  });
}
