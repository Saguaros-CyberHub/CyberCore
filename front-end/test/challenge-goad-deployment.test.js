'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const utils = path.join(__dirname, '..', 'src', 'utils');

// Importing the pure addressing helpers must not depend on a site's local file.
require.cache[require.resolve(path.join(utils, 'site-config'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({ max_concurrent_lanes: 2, max_concurrent_clones: 2 }),
    getDefaultTemplateNode: () => 'node-test',
  },
};
const deployer = require(path.join(utils, 'challenge-lane-deployer'));
const goad = require(path.join(utils, 'goad-deploy'));
const networking = require(path.join(utils, 'lane-networking'));
const source = fs.readFileSync(path.join(utils, 'challenge-lane-deployer.js'), 'utf8').replace(/\r\n/g, '\n');
function functionSource(name) {
  const start = source.indexOf(`async function ${name}(`);
  assert.ok(start >= 0);
  return source.slice(start, source.indexOf('\n}\n', start) + 3);
}
function fixture() {
  return {
    goad: { enabled: true, version: 'GOAD-Mini', rename_forest: true,
      domain: 'cy400test.org', child_subdomain: '', extensions: ['elk', 'ws01'] },
    vms: [
      { name: 'DC01', template_vmid: 1004, vm_offset: 600000 },
      { name: 'ws01', template_vmid: 1006, vm_offset: 610000 },
      { name: 'elk', role: 'siem', template_vmid: 1011, vm_offset: 620000, ipOctet: 24 },
    ],
  };
}

test('ELK gets its installer IP and DNS without whole-lane pinning, including v3', () => {
  const spec = fixture();
  const requiredIpOctets = deployer.resolveGoadExternalPins(spec);
  for (const subnetScheme of ['v2', 'v3']) {
    const out = deployer.resolveSpecAddressing({
      specVms: spec.vms, requiredIpOctets, subnetScheme,
      laneSubnetBase: '10.30.1', goadSubnetBase: '10.31.1', reserved: [1, 5, 50],
    });
    assert.deepEqual(out.pinnedHosts, [{ name: 'elk', octet: 24, subnetBase: '10.30.1' }]);
    assert.ok(out.dnsRecords.some(r => r.alias === 'elk' && r.ip === '10.30.1.24'));
    const mac = goad.macForOctet(24, 10001);
    const nic = networking.resolveVmNics(spec.vms[2], {
      subnetScheme, bridges: networking.resolveSegmentBridges(subnetScheme, 'external', 'internal'),
      pinnedMac: mac,
    });
    assert.ok(nic.nets.net0.includes(mac));
    assert.ok(nic.nets.net0.includes('bridge=external'));
  }
});

test('external extension absence, wrong IP and wrong v3 network are refused', () => {
  const absent = fixture(); absent.vms.pop();
  assert.throws(() => deployer.resolveGoadExternalPins(absent), /requires machine/);
  const moved = fixture(); moved.vms[2].ipOctet = 80;
  assert.throws(() => deployer.resolveGoadExternalPins(moved), /must use .24/);
  const internal = fixture(); internal.vms[2].nics = [{ segment: 'int' }];
  assert.throws(() => deployer.resolveSpecAddressing({
    specVms: internal.vms, requiredIpOctets: { elk: 24 }, subnetScheme: 'v3',
    laneSubnetBase: '10.30.1', goadSubnetBase: '10.31.1',
  }), /external lane network/);
});

async function runOuter(fail, restoreFails = false) {
  let state = { status: 'deploying', config: { existing_marker: 'preserve' } };
  const events = [], audits = [];
  const noop = async () => {};
  const spec = fixture();
  const meta = {
    status: fail ? 'failed' : 'provisioned', controller_vmid: 210000,
    forest_rename: { applied: true, forest_root: 'cy400test.org' },
    generated_lab: { extension_configs: { ws01: { sha256: 'fixture-digest' } } },
  };
  const context = {
    module: { exports: {} },
    console: { log() {}, warn() {}, error() {} },
    setTimeout: f => { f(); return 0; },
    GATEWAY_VMID_OFFSET: 100000, ATTACK_BOX_VMID_OFFSET: 700000,
    CONSOLE_OCTET_MIN: 60, CONSOLE_OCTET_MAX: 79,
    hostnameFor: s => s, getDefaultTemplateNode: () => 'node-test',
    resolveLaneNetworking: () => ({ lan: { base3: '10.39.16' } }),
    applyPrebakedFixedSubnet() {}, resolveSpecVms: s => s.vms,
    resolveGoadExternalPins: deployer.resolveGoadExternalPins,
    resolveConsolePlan: () => ({ consoles: [{ kind: 'kali', ref: 'kali', name: 'kali', primary: true }] }),
    resolveSpecAddressing: () => ({ pinnedHosts: [{ name: 'elk', octet: 24 }], dnsRecords: [] }),
    cloneChallengeVm: async ({ vmSpec }) => ({ name: vmSpec.name, vm_id: vmSpec.vm_offset + 10000,
      node: 'node-test', type: 'qemu' }),
    cloneAttackBox: noop, proxmoxAPI: noop, waitForTask: noop,
    writeLaneReservations: async () => {
      events.push('reservations');
      if (restoreFails && events.filter(e => e === 'reservations').length === 2) {
        throw new Error('gateway SSH unavailable');
      }
    },
    resolveGatewayTransitIp: async () => '100.100.60.12',
    discoverKaliIp: async () => '10.39.16.50',
    laneDeployer: { installConsoleDnat: noop }, createLaneConsole: async () => '42',
    plantFlagsForLane: noop, registerWorkspaceVms: noop,
    audit: { log: async e => audits.push(e) },
    goadDeploy: {
      CONTROLLER_TEMPLATE_VMID: 1700, INFRA_IP_OCTETS: { Kali: 50, gateway: 1, controller: 5 },
      prepareGoadMacs: () => ({ DC01: { static_ip: '10.39.16.10' }, ws01: { static_ip: '10.39.16.31' } }),
      deployGoadLane: async () => {
        events.push('GOAD');
        // Simulate an independent config write and a failed best-effort metadata
        // write in GOAD. The final caller must still carry the returned result.
        state.config.concurrent_marker = 'keep';
        if (fail) throw Object.assign(new Error('WS01 delivery failed'), { goadMeta: meta });
        return { goadMeta: meta };
      },
    },
    cybercoreQuery: async (sql, params) => {
      const patch = JSON.parse(params[1]);
      state.config = /\|\|/.test(sql) ? { ...state.config, ...patch } : patch;
      if (/status = \$3/.test(sql)) state.status = params[2];
      else if (/status = 'active'/.test(sql)) state.status = 'active';
      return { rows: [] };
    },
  };
  vm.runInNewContext(functionSource('deployLaneVms') + '\nmodule.exports = deployLaneVms;', context);
  const progress = { lanes: {} };
  let caught;
  try {
    await context.module.exports({ laneId: 'lane-test', user: { id: 1, email: 'student@example.invalid' },
      vxlanId: 10000, vnet: { vnet: 'network-test' }, targetNode: 'node-test',
      attackBoxCreds: { username: 'student', password: 'fixture' } }, {
      spec, subnetScheme: 'v2', moduleKey: 'crucible', challengeKey: 'cy400test', attackBoxes: true,
      laneConfig: {}, extraSpecs: [], templateNodeByVmid: {}, logTag: 'test', progress,
    });
  } catch (err) { caught = err; }
  return { state, events, audits, progress, caught };
}

test('successful outer deployment preserves returned GOAD metadata and other lane config', async () => {
  const { state, events, audits, caught } = await runOuter(false);
  assert.equal(caught, undefined);
  assert.equal(state.status, 'active');
  assert.equal(state.config.goad.forest_rename.forest_root, 'cy400test.org');
  assert.equal(state.config.goad.generated_lab.extension_configs.ws01.sha256, 'fixture-digest');
  assert.equal(state.config.existing_marker, 'preserve');
  assert.equal(state.config.concurrent_marker, 'keep');
  assert.deepEqual(events, ['reservations', 'GOAD', 'reservations']);
  assert.equal(audits[0].status, 'success');
});

test('delivery failure leaves suspended owned resources, visible error and failed batch result', async () => {
  const { state, events, audits, progress, caught } = await runOuter(true);
  assert.match(caught.message, /WS01 delivery failed/);
  assert.equal(state.status, 'suspended');
  assert.equal(state.config.vms.length, 3);
  assert.equal(state.config.gateway_vm_id, 110000);
  assert.equal(state.config.attack_box_vm_id, 710000);
  assert.equal(state.config.goad.controller_vmid, 210000);
  assert.match(state.config.provisioning_error, /WS01 delivery failed/);
  assert.equal(progress.lanes['lane-test'].status, 'error');
  assert.equal(audits[0].status, 'failure');
  assert.deepEqual(events, ['reservations', 'GOAD', 'reservations']);
});

test('a subsequent DHCP restoration failure preserves the original GOAD failure and metadata', async () => {
  const { state, caught } = await runOuter(true, true);
  assert.match(caught.message, /WS01 delivery failed/);
  assert.equal(state.status, 'suspended');
  assert.equal(state.config.goad.controller_vmid, 210000);
  assert.equal(state.config.goad.error, 'WS01 delivery failed');
  assert.equal(state.config.goad.reservation_error, 'gateway SSH unavailable');
});

test('the actual batch entry compiles before any allocation or clone dependency is reached', async () => {
  const calls = [];
  const context = { module: { exports: {} },
    parseSpec: s => s, attachGoadAgentScripts: s => s,
    goadDeploy: { prepareGoadDeploymentSpec: () => { calls.push('compile'); throw new Error('invalid rename'); } },
    loadExtraWorkstations: async () => { calls.push('external-read'); },
    laneDeployer: { allocateVxlanIds: async () => { calls.push('allocate'); } },
  };
  vm.runInNewContext(functionSource('deployChallengeLanesInner') + '\nmodule.exports = deployChallengeLanesInner;', context);
  await assert.rejects(context.module.exports({ users: [{ id: 1 }], challenge: { spec: fixture() } }), /invalid rename/);
  assert.deepEqual(calls, ['compile']);
});
