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
    if (sql.includes('FROM crucible_challenge')) return { rows: [{ id: 1, challenge_id: 1, challenge_key: 'fixture', name: 'Fixture', spec, subnet_scheme: 'v2' }] };
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
    // The pooled WAN transit address. This fixture used to say subnet_scheme
    // 'v1' and never needed the stub: v1 was the one scheme that reached the
    // internet through its module's own transit /16, so both deploy routes
    // skipped allocation entirely. Migration 038 retired v1, the fixture row is
    // 'v2', and the allocation now runs on every deploy this file exercises.
    // Stubbed rather than omitted for the reason the gateway-lifecycle note
    // below gives: the fake require hands back {} for anything missing, so a gap
    // here answers 503 on every case and reads as a GOAD regression.
    '../../utils/lane-wan-allocator': {
      findWanIpConflicts: async () => [],
      allocateLaneWanIps: async (n) => {
        calls.push({ kind: 'wan-allocate', n });
        return Array.from({ length: n }, (_, i) => ({ address: `100.100.60.${100 + i}` }));
      },
      recordLaneWanLease: async () => { calls.push({ kind: 'wan-lease' }); },
      releaseLaneWanIps: async () => { calls.push({ kind: 'wan-release' }); },
    },
    // The gateway start gate. Both admin deploy routes used to fire
    // POST .../status/start and sleep 5s; they now confirm the container really
    // reached 'running' before configuring anything inside it, because a gateway
    // that lost the /dev/rbd-pve udev race on a backfilling node otherwise takes
    // the whole deploy down three minutes later inside GOAD's prep.sh. Stubbed
    // rather than omitted: the fake require hands back {} for anything missing,
    // so a gap here fails every deploy with "is not a function" and reads as a
    // GOAD regression. See utils/gateway-lifecycle.js.
    '../../utils/gateway-lifecycle': {
      ensureGatewayRunning: async () => {
        calls.push({ kind: 'gateway-running' });
        if (faults.gateway) {
          throw Object.assign(
            new Error("Lane gateway 101701 on node1 is 'stopped', not running, after 3 start attempts"),
            { gatewayNotRunning: true, node: 'node1', lastStatus: 'stopped' }
          );
        }
        return { running: true, statusReadable: true, lastStatus: 'running' };
      },
      waitForGatewayFirstboot: async () => { calls.push({ kind: 'gateway-firstboot' }); return true; },
    },
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
  test(`${route}: the gateway is proven running, and its firstboot awaited, BEFORE anything is written into it`, async () => {
    // Ordering, not merely presence. Reservations are pushed into the container
    // over `pct exec`, so they cannot precede it running; and firstboot REWRITES
    // /etc/dnsmasq.conf and the nat table from scratch, so a reservation written
    // ahead of it is silently erased and the lane comes up with dead consoles
    // while still reporting 'active'.
    const f = fixture(route);
    await f.run();
    const at = (kind) => f.calls.findIndex(call => call.kind === kind);
    assert.ok(at('gateway-running') >= 0, 'the deploy must confirm the gateway reached running');
    assert.ok(at('gateway-firstboot') > at('gateway-running'),
      'firstboot is waited for only once the container is actually up');
    assert.ok(at('reservations') > at('gateway-firstboot'),
      'DHCP reservations must be written on top of firstboot, never under it');
    assert.ok(at('goad') > at('gateway-running'), 'GOAD must never start against an unproven gateway');
  });
  test(`${route}: a gateway that never starts suspends the lane before GOAD is ever reached`, async () => {
    // The cyberhub-node-8 failure. Before the gate, a gateway that lost the
    // /dev/rbd-pve udev race was never noticed: the deploy wrote reservations
    // into a stopped container, swallowed that, cloned a GOAD controller, and
    // died three to five minutes later inside prep.sh with
    // "ssh: connect to host 10.42.129.1 port 22: No route to host" — an error
    // about the one machine that was never at fault. It must now fail in seconds,
    // naming the gateway, having cloned no controller.
    const f = fixture(route, { gateway: true });
    const { terminal } = await f.run();
    assert.equal(terminal?.status, 'suspended');
    assert.match(terminal.config.error, /not running, after 3 start attempts/);
    assert.ok(!f.calls.some(call => call.kind === 'goad'),
      'GOAD provisioning must not run behind a gateway that never started');
    assert.ok(!f.calls.some(call => call.kind === 'reservations'),
      'nothing should be written into a container that is not running');
  });
}
