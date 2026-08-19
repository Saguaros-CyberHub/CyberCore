/**
 * lane-deployer-slots.test.js — multi-workstation lane deploys.
 *
 * Stubs Proxmox, Postgres and the gateway SSH channel so the whole deployLanes /
 * teardownLanes path runs in-process. Verifies:
 *   - a single-template deploy is byte-identical to the pre-slot behaviour
 *     (600000+vxlan VMID, .50, port 3389, flat config keys)
 *   - a two-template deploy lands on .50/.51 with distinct MACs, VMIDs and
 *     gateway ports
 *   - the gateway is configured ONCE from the full slot list — the regression
 *     that made a second workstation clobber the first's DHCP reservation and
 *     delete its DNAT
 *   - a gateway-config failure is survivable for one workstation and fatal for
 *     more than one
 *   - teardown finds the allocated slot-1+ VMIDs, which cannot be re-derived
 *
 * Run: node front-end/test/lane-deployer-slots.test.js
 */

const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stubModule(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// ── captured side effects ────────────────────────────────────────────────────
const calls = {
  clones: [],        // { vmid, sourceVmid, node }
  configs: [],       // { vmid, body }
  starts: [],        // vmid
  deletes: [],       // vmid
  dnsmasqFiles: [],  // { gatewayVmid, path, content }
  pctExecs: [],      // { gatewayVmid, script }
};
let gatewayAccessShouldFail = false;
let dnsmasqShouldBeDown = false;   // model a gateway whose dnsmasq refused to start
let cloudInitDriveOnClone = false; // model a template that actually ships a cloud-init drive
let agentIpOverride = null;   // force the guest-agent IP, to model a bad DHCP lease

/** Poll until `fn()` is true or the budget expires — the IP confirm is detached. */
async function waitFor(fn, ms = 2000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await new Promise(r => setTimeout(r, 10));
  }
  return false;
}

// ── Proxmox ──────────────────────────────────────────────────────────────────
// Guest-agent IPs are derived from the MAC the deployer set: macForOctet encodes
// the vxlan in bytes 4-5 and the lane octet in byte 6, and a v2 lane subnet is
// 10.<vxh>.<vxl> — so the stub can return exactly the address the reservation
// should have produced, which is what confirmWorkstationIp checks.
const macByVmid = new Map();
const vmMeta = new Map();   // vmid → { name, type } as the cluster would report it

function ipFromMac(mac) {
  const [, , , hi, lo, octet] = mac.split(':');
  return `10.${parseInt(hi, 16)}.${parseInt(lo, 16)}.${parseInt(octet, 16)}`;
}

stubModule('proxmox.js', {
  proxmoxAPI: async (method, url, body) => {
    if (url.includes('/cluster/sdn/vnets')) {
      return [10000, 10001, 10002].map(tag => ({ tag, vnet: `vnet${tag}` }));
    }
    if (url.includes('/cluster/resources')) {
      return [...vmMeta.entries()].map(([vmid, m]) => ({ vmid, node: 'node1', type: m.type, name: m.name }));
    }
    if (url.includes('/nodes') && !url.includes('/qemu/') && !url.includes('/lxc/')) {
      return [{ node: 'node1' }];
    }
    const vmid = Number((/\/(?:qemu|lxc)\/(\d+)/.exec(url) || [])[1]);
    if (method === 'POST' && url.endsWith('/clone')) {
      calls.clones.push({ vmid: body.newid, sourceVmid: vmid, node: body.target });
      macByVmid.set(body.newid, null);
      vmMeta.set(body.newid, { name: body.name || body.hostname || null, type: url.includes('/lxc/') ? 'lxc' : 'qemu' });
      return 'UPID:node1:clone';
    }
    if (method === 'POST' && url.endsWith('/status/start')) { calls.starts.push(vmid); return 'UPID:node1:start'; }
    if (method === 'DELETE') { calls.deletes.push(vmid); macByVmid.delete(vmid); vmMeta.delete(vmid); return null; }
    if (url.includes('/agent/network-get-interfaces')) {
      const mac = macByVmid.get(vmid);
      if (!mac && !agentIpOverride) throw new Error('no agent');
      const ip = agentIpOverride || ipFromMac(mac);
      return { result: [{ name: 'eth0', 'ip-addresses': [{ 'ip-address-type': 'ipv4', 'ip-address': ip }] }] };
    }
    if (method === 'PUT' && url.endsWith('/config')) {
      calls.configs.push({ vmid, body });
      const m = /macaddr=([0-9A-F:]+)/i.exec(body.net0 || '');
      if (m) macByVmid.set(vmid, m[1]);
      return null;
    }
    if (method === 'GET' && url.endsWith('/config')) {
      // Default: no cloud-init drive, no disks. Templates that carry one take
      // the credential-injection path instead, which is where citype matters.
      return cloudInitDriveOnClone ? { ide2: 'local-lvm:vm-1-cloudinit,media=cdrom' } : {};
    }
    if (url.includes('/tasks/')) return { status: 'stopped' };
    return null;
  },
  waitForTask: async () => ({ status: 'stopped' }),
  findTemplateNode: async () => 'node1',
});

// ── Postgres ─────────────────────────────────────────────────────────────────
const lanes = new Map(); // lane_id → { lane_id, vxlan_id, status, config }
let laneSeq = 0;

stubModule('cybercore-db.js', {
  cybercoreQuery: async (sql, args = []) => {
    if (/INSERT INTO cybercore_lane/.test(sql)) {
      const lane_id = `lane-${++laneSeq}`;
      lanes.set(lane_id, { lane_id, vxlan_id: args[3], status: 'deploying', config: JSON.parse(args[4]) });
      return { rows: [{ lane_id }] };
    }
    if (/UPDATE cybercore_lane/.test(sql) && /jsonb_set/.test(sql)) {
      const lane = lanes.get(args[0]);
      if (lane) {
        lane.config.ws_ip = { ...(lane.config.ws_ip || {}), [args[1]]: args[2] };
        lane.config.ws_ip_confirmed = { ...(lane.config.ws_ip_confirmed || {}), [args[1]]: args[3] };
      }
      return { rows: [] };
    }
    if (/UPDATE cybercore_lane/.test(sql)) {
      const ids = Array.isArray(args[0]) ? args[0] : [args[0]];
      for (const id of ids) {
        const lane = lanes.get(id);
        if (!lane) continue;
        if (/status='active'/.test(sql)) lane.status = 'active';
        if (/status='error'/.test(sql) || /status = 'error'/.test(sql)) lane.status = 'error';
        if (args[1]) Object.assign(lane.config, JSON.parse(args[1]));
      }
      return { rows: [] };
    }
    if (/SELECT lane_id, vxlan_id, status, config FROM cybercore_lane/.test(sql)) {
      return { rows: args[0].map(id => lanes.get(id)).filter(Boolean) };
    }
    if (/INSERT INTO cybercore_resource/.test(sql)) {
      return { rows: [{ resource_id: `res-${Math.random().toString(16).slice(2, 8)}` }] };
    }
    // Must precede the DISTINCT branch: allocateVxlanIds' CTE contains both.
    if (/generate_series/.test(sql)) {
      const out = [];
      for (let v = args[0]; v <= args[1] && out.length < args[2]; v++) out.push({ vxlan_id: v });
      return { rows: out };
    }
    if (/SELECT DISTINCT vxlan_id FROM cybercore_lane/.test(sql)) return { rows: [] };
    if (/DELETE FROM cybercore_lane/.test(sql)) {
      for (const id of args[0]) lanes.delete(id);
      return { rowCount: args[0].length, rows: [] };
    }
    return { rows: [] };
  },
});

// ── gateway shell, node picker, config, guac, tailscale ──────────────────────
stubModule('node-ssh.js', {
  // The message matters: node-ssh's own preflight reports an unusable channel as
  // "missing or unreadable", and the deployer stops probing the gateway the
  // moment it sees one of those rather than spending its whole budget on a
  // channel that is never going to answer.
  pctPushFromString: async (node, gatewayVmid, content, dest) => {
    if (gatewayAccessShouldFail) throw new Error(`SSH key '/no/such/key' is missing or unreadable`);
    calls.dnsmasqFiles.push({ gatewayVmid, path: dest, content });
  },
  // The real pctExec resolves { stdout, stderr, code }, and the deployer READS
  // stdout: once to decide the gateway's firstboot has stopped rewriting the
  // config it is about to write, and once to confirm dnsmasq actually came back
  // up. A stub that returns undefined makes both look like failures.
  pctExec: async (node, gatewayVmid, argv) => {
    if (gatewayAccessShouldFail) throw new Error(`SSH key '/no/such/key' is missing or unreadable`);
    const script = argv[argv.length - 1];
    calls.pctExecs.push({ gatewayVmid, script });
    let stdout = '';
    if (script.includes('firstboot-done')) {
      stdout = 'firstboot-done\n';
    } else if (script.includes('pgrep dnsmasq')) {
      stdout = dnsmasqShouldBeDown
        ? 'dnsmasq-down\ndnsmasq: duplicate dhcp-host IP address 10.39.16.50\n'
        : 'dnsmasq-up\n';
    }
    return { stdout, stderr: '', code: 0 };
  },
});
stubModule('node-selector.js', { selectBestNode: async () => ({ node: 'node1' }) });
stubModule('site-config.js', {
  getDefaultTemplateNode: () => 'node1',
  // max_concurrent_clones matters: batch-deployer builds its clone semaphore
  // from it at require time, and `new Semaphore(undefined)` never grants a
  // permit — the deploy hangs with no error at all.
  getSchedulingConfig: () => ({ max_concurrent_lanes: 4, max_concurrent_clones: 4 }),
  getClusterNodes: () => ['node1'],
  // Full shape, matching src/utils/site-config.getV2LabNetwork: the allocator
  // and wanConfigFromAddress read host_range/reserved/probe, and a stub that
  // stops at the legacy five keys fails on `host_range.first`.
  getV2LabNetwork: () => ({
    bridge: 'vmbr0', vlan_tag: 60,
    subnet: '100.100.60.0/24', network: '100.100.60.0', broadcast: '100.100.60.255',
    prefix_len: 24, cidr: '/24', subnet_base: '100.100.60', gateway: '100.100.60.1',
    host_range: { first: '100.100.60.10', last: '100.100.60.254' },
    reserved: ['100.100.60.1', '100.100.60.0', '100.100.60.255'],
    probe: { enabled: false, node: null, interface: 'vmbr0.60', timeout_ms: 2000 },
  }),
  getV1LanSubnet: () => ({ base3: '192.18.0', cidr: '192.18.0.0/24', gateway_ip: '192.18.0.1', netmask24: '255.255.255.0' }),
  getModuleNetwork: () => ({}),
  getModuleNetworks: () => ({}),
});
stubModule('guacamole.js', { guacAPI: async () => ({ identifier: `guac-${Math.random().toString(16).slice(2, 8)}` }) });
stubModule('guac-credentials.js', { ensureGuacUser: async () => true, getGuacCredentials: async () => null });
stubModule('tailscale.js', { deleteLaneDevices: async () => 0, isEnabled: () => false });

// lane-networking is mostly pure maths we want to exercise for real; only the
// Tailscale call reaches the network.
const laneNetworking = require(path.join(UTILS, 'lane-networking.js'));
laneNetworking.configureLaneTailscale = async () => null;

// The WAN allocator reaches Postgres and ssh, so it is stubbed — but it hands
// out 100.100.60.10, .11, … in order, which is what the pre-allocator
// derivation produced for vxlan 10000/10001/… That keeps every assertion below
// (console endpoints, gateway net0) asserting the same addresses it always did,
// so a change in those numbers means a real regression rather than a stub
// artefact. Addresses are NOT reused across calls: the whole point of the
// allocator is that two lanes never share one.
let _stubWanCursor = 10;
let _stubWanFail = null;      // set to a message to model an exhausted pool
stubModule('lane-wan-allocator.js', {
  allocateLaneWanIps: async (count) => (_stubWanFail
    ? Promise.reject(new Error(_stubWanFail))
    : Array.from({ length: count }, () => {
      const address = `100.100.60.${_stubWanCursor++}`;
      return { address, ip: `${address}/24`, cidr: '/24', bridge: 'vmbr0', vlanTag: 60, gw: '100.100.60.1' };
    })),
  releaseLaneWanIps: async () => {},
  recordLaneWanLease: async () => true,
  wanConfigFromAddress: (a) => ({
    bridge: 'vmbr0', vlanTag: 60, ip: `${a}/24`, gw: '100.100.60.1', address: a,
  }),
  findWanIpConflicts: async () => [],
});

process.env.GUAC_ENABLED = 'true';

const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));

// ── fixtures ─────────────────────────────────────────────────────────────────
const KALI = { id: 't-kali', template_key: 'kali', os_name: 'Kali', template_vmid: 1001, provider_type: 'qemu', os_family: 'linux', metadata: {} };
const WIN  = { id: 't-win',  template_key: 'win11', os_name: 'Windows 11', template_vmid: 1004, provider_type: 'qemu', os_family: 'windows', metadata: {} };
const BLOCK = { start: 10000, end: 10002 };
const USERS = [{ id: 'u1', email: 'student@example.edu' }];

function reset() {
  for (const k of Object.keys(calls)) calls[k] = [];
  lanes.clear();
  macByVmid.clear();
  vmMeta.clear();
  laneSeq = 0;
  gatewayAccessShouldFail = false;
  dnsmasqShouldBeDown = false;
  cloudInitDriveOnClone = false;
  agentIpOverride = null;
}

/** The cloud-init PUT for a workstation (the one carrying ciuser/cipassword). */
function cloudInitConfigFor(vmid) {
  return calls.configs.find(c => c.vmid === vmid && c.body.ciuser !== undefined) || null;
}

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// ── 1. single template: unchanged shape ──────────────────────────────────────
test('single template keeps the pre-slot lane shape', async () => {
  reset();
  const res = await laneDeployer.deployLanes({ users: USERS, template: KALI, vxlanBlock: BLOCK });
  assert.strictEqual(res.failed.length, 0, JSON.stringify(res.failed));
  assert.strictEqual(res.provisioned.length, 1);

  const lane = [...lanes.values()][0];
  assert.strictEqual(lane.status, 'active');
  assert.strictEqual(lane.config.workstation_vmid, 600000 + 10000, 'slot 0 keeps 600000+vxlanId');
  assert.strictEqual(lane.config.ip, '10.39.16.50');
  assert.strictEqual(lane.config.console_port, 3389);
  assert.strictEqual(lane.config.console_via, 'gateway');
  assert.ok(lane.config.guac_connection_id, 'flat guac_connection_id still written');
  assert.strictEqual(lane.config.workstations.length, 1);
  assert.strictEqual(lane.config.workstations[0].slot, 0);
});

// ── 2. two templates: distinct octets, ports, MACs, VMIDs ────────────────────
test('two templates land on .50/.51 with distinct ports, MACs and VMIDs', async () => {
  reset();
  const res = await laneDeployer.deployLanes({ users: USERS, templates: [KALI, WIN], vxlanBlock: BLOCK });
  assert.strictEqual(res.failed.length, 0, JSON.stringify(res.failed));

  const ws = [...lanes.values()][0].config.workstations;
  assert.strictEqual(ws.length, 2);
  assert.deepStrictEqual(ws.map(w => w.ip), ['10.39.16.50', '10.39.16.51']);
  assert.deepStrictEqual(ws.map(w => w.console_port), [3389, 3390]);
  assert.deepStrictEqual(ws.map(w => w.mac), ['02:00:CC:27:10:32', '02:00:CC:27:10:33']);
  assert.strictEqual(ws[0].vmid, 610000, 'slot 0 stays derived');
  assert.ok(ws[1].vmid >= 300000 && ws[1].vmid <= 399999, `slot 1 allocated from the band, got ${ws[1].vmid}`);
  assert.notStrictEqual(ws[0].vmid, ws[1].vmid);
  assert.notStrictEqual(ws[0].hostname, ws[1].hostname, 'dnsmasq needs distinct reservation hostnames');

  // Each slot got its own clone, its own NIC MAC and its own Guac connection.
  assert.strictEqual(calls.clones.filter(c => c.sourceVmid !== 1694).length, 2);
  const guacIds = ws.map(w => w.guac_connection_id);
  assert.ok(guacIds.every(Boolean) && new Set(guacIds).size === 2, 'one Guac connection per slot');
});

// ── 3. the regression: gateway rendered once, from every slot ────────────────
test('gateway is configured once with every slot in one file and one rule pass', async () => {
  reset();
  await laneDeployer.deployLanes({ users: USERS, templates: [KALI, WIN], vxlanBlock: BLOCK });

  assert.strictEqual(calls.dnsmasqFiles.length, 1, 'one dnsmasq write per lane, not one per workstation');
  const conf = calls.dnsmasqFiles[0].content;
  assert.ok(/dhcp-host=02:00:CC:27:10:32,10\.39\.16\.50,/.test(conf), `slot 0 reservation missing:\n${conf}`);
  assert.ok(/dhcp-host=02:00:CC:27:10:33,10\.39\.16\.51,/.test(conf), `slot 1 reservation missing:\n${conf}`);

  // One iptables pass holding BOTH DNATs. Previously each call flushed
  // LANE-CONSOLE and re-added a single rule, so slot 1 deleted slot 0's.
  const ruleScripts = calls.pctExecs.map(e => e.script).filter(s => s.includes('LANE-CONSOLE'));
  assert.strictEqual(ruleScripts.length, 1, 'iptables rebuilt once, not per workstation');
  const rules = ruleScripts[0];
  assert.ok(rules.includes('--dport 3389') && rules.includes('10.39.16.50:3389'), 'slot 0 DNAT missing');
  assert.ok(rules.includes('--dport 3390') && rules.includes('10.39.16.51:3389'), 'slot 1 DNAT missing');
  assert.strictEqual((rules.match(/iptables-save \| grep -v "LANE-CONSOLE"/g) || []).length, 1);
});

// ── 4. gateway failure: survivable at 1 slot, fatal past it ──────────────────
test('gateway failure falls back for one workstation', async () => {
  reset();
  gatewayAccessShouldFail = true;
  const res = await laneDeployer.deployLanes({ users: USERS, template: KALI, vxlanBlock: BLOCK });
  assert.strictEqual(res.failed.length, 0, 'a single RDP workstation rides the baked DNAT');
  assert.strictEqual([...lanes.values()][0].config.console_via, 'gateway-baked-dnat');
});

test('gateway failure fails the lane when it has more than one workstation', async () => {
  reset();
  gatewayAccessShouldFail = true;
  const res = await laneDeployer.deployLanes({ users: USERS, templates: [KALI, WIN], vxlanBlock: BLOCK });
  assert.strictEqual(res.provisioned.length, 0);
  assert.strictEqual(res.failed.length, 1);
  assert.ok(/baked DNAT cannot cover/.test(res.failed[0].reason), res.failed[0].reason);
  assert.strictEqual([...lanes.values()][0].status, 'error');
  assert.strictEqual(calls.clones.filter(c => c.sourceVmid !== 1694).length, 0,
    'no workstation is cloned once the lane is known to be unreachable');
});

// ── 3b. cloud-init drive format ──────────────────────────────────────────────
// A Windows clone MUST be told citype=configdrive2. Proxmox does not infer it
// from ostype (verified false on this cluster — see the Windows template's
// README), and the nocloud default produces a drive cloudbase-init finds, fails
// to parse, and reports success on: the account keeps its bake password while
// the lane advertises a generated one. There is no signal anywhere except a
// student failing to log in, so it is pinned here.
test('a Windows clone is pinned to configdrive2; Linux keeps the default', async () => {
  reset();
  cloudInitDriveOnClone = true;
  await laneDeployer.deployLanes({ users: USERS, template: WIN, vxlanBlock: BLOCK });

  const win = cloudInitConfigFor(610000);
  assert.ok(win, 'the Windows clone got a cloud-init config PUT');
  assert.strictEqual(win.body.citype, 'configdrive2', 'cloudbase-init reads the OpenStack layout only');
  assert.ok(win.body.cipassword, 'a password is injected alongside it');
  assert.strictEqual([...lanes.values()][0].config.credentials_source, 'cloudinit');

  reset();
  cloudInitDriveOnClone = true;
  await laneDeployer.deployLanes({ users: USERS, template: KALI, vxlanBlock: BLOCK });

  const kali = cloudInitConfigFor(610000);
  assert.ok(kali, 'the Linux clone got a cloud-init config PUT');
  assert.ok(!('citype' in kali.body), 'nocloud is already the default and what cloud-init reads');
});

// ── 4a. dnsmasq down is fatal even for one workstation ───────────────────────
// The gateway's baked wan0:3389 DNAT targets <base>.50, and the only thing that
// puts a guest there is a DHCP lease. A gateway whose dnsmasq refused to start
// (classically: its boot-time config re-added `dhcp-host=kali,<base>.50` on top
// of our reservation for the same address) serves no lease at all, so there is
// nothing for the fallback to reach and the lane must fail rather than report
// 'active' with a console that connects to nothing.
test('a gateway whose dnsmasq will not start fails the lane, fallback or not', async () => {
  reset();
  dnsmasqShouldBeDown = true;
  const res = await laneDeployer.deployLanes({ users: USERS, template: KALI, vxlanBlock: BLOCK });
  assert.strictEqual(res.provisioned.length, 0);
  assert.strictEqual(res.failed.length, 1);
  assert.ok(/dnsmasq is not running/.test(res.failed[0].reason), res.failed[0].reason);
  assert.strictEqual([...lanes.values()][0].status, 'error');
});

// ── 4b. a guest that took a pool lease downgrades the lane ───────────────────
// Reproduces the observed production failure: SSH to the node was unavailable,
// so no DHCP reservation was written, and the Windows guest took .199 instead of
// the reserved .50. The gateway's baked DNAT still targets .50, so the console
// is dead — the lane must not keep reporting a healthy console.
test('a workstation on a pool lease marks the console unreachable', async () => {
  reset();
  gatewayAccessShouldFail = true;
  agentIpOverride = '10.39.16.199';       // pool lease, same lane subnet
  await laneDeployer.deployLanes({ users: USERS, template: WIN, vxlanBlock: BLOCK });

  const lane = [...lanes.values()][0];
  await waitFor(() => lane.config.console_via === 'unreachable');
  assert.strictEqual(lane.config.console_via, 'unreachable');
  assert.ok(/pool lease/.test(lane.config.console_error || ''), lane.config.console_error);
  agentIpOverride = null;
});

// ── 4c. a second interface must NOT be mistaken for a bad lease ──────────────
test('an address outside the lane subnet does not downgrade the lane', async () => {
  reset();
  agentIpOverride = '172.17.0.5';          // some other interface entirely
  await laneDeployer.deployLanes({ users: USERS, template: WIN, vxlanBlock: BLOCK });

  const lane = [...lanes.values()][0];
  await new Promise(r => setTimeout(r, 50));
  assert.strictEqual(lane.config.console_via, 'gateway', 'a foreign subnet is not evidence of a bad lease');
  assert.ok(!lane.config.console_error);
  agentIpOverride = null;
});

// ── 5. port collision is caught before anything is built ─────────────────────
test('two slots pinned to the same WAN port are rejected up front', async () => {
  reset();
  const pinned = { ...WIN, metadata: { console_wan_port: 3389 } };
  await assert.rejects(
    () => laneDeployer.deployLanes({ users: USERS, templates: [KALI, pinned], vxlanBlock: BLOCK }),
    /both publish gateway port 3389/
  );
  assert.strictEqual(calls.clones.length, 0);
});

// ── 6. teardown finds the allocated slot VMIDs ───────────────────────────────
test('teardown destroys every slot, including allocated VMIDs', async () => {
  reset();
  await laneDeployer.deployLanes({ users: USERS, templates: [KALI, WIN], vxlanBlock: BLOCK });
  const lane = [...lanes.values()][0];
  const slotVmids = lane.config.workstations.map(w => w.vmid);

  calls.deletes = [];
  await laneDeployer.teardownLanes([lane.lane_id]);
  for (const vmid of slotVmids) {
    assert.ok(calls.deletes.includes(vmid), `slot VMID ${vmid} was never destroyed`);
  }
});

// ── 6b. a reallocated slot VMID is not destroyed out from under its new owner ─
// A deploy that recorded an allocated VMID and then failed before cloning leaves
// that id free; a later deploy hands it to a DIFFERENT lane. Tearing down the
// first lane must not destroy the second lane's running machine.
test('teardown skips a slot VMID that was reallocated to another lane', async () => {
  reset();
  await laneDeployer.deployLanes({ users: USERS, templates: [KALI, WIN], vxlanBlock: BLOCK });
  const victim = [...lanes.values()][0];
  const reusedVmid = victim.config.workstations[1].vmid;

  // A stale lane row that recorded the same id under its own (different) name,
  // exactly as a failed earlier deploy would have left it.
  lanes.set('lane-stale', {
    lane_id: 'lane-stale',
    vxlan_id: 10002,
    status: 'error',
    config: {
      gateway_vmid: 110002,
      workstations: [
        { slot: 0, vmid: 610002, ip: '10.39.18.50', hostname: 'lane-10002', provider_type: 'qemu' },
        { slot: 1, vmid: reusedVmid, ip: '10.39.18.51', hostname: 'lane-10002-ws1', provider_type: 'qemu' },
      ],
    },
  });

  // The stale lane's OWN machines do exist in the cluster, under its own names.
  vmMeta.set(110002, { name: 'lane-10002-gateway', type: 'lxc' });
  vmMeta.set(610002, { name: 'lane-10002', type: 'qemu' });

  calls.deletes = [];
  await laneDeployer.teardownLanes(['lane-stale']);
  assert.ok(!calls.deletes.includes(reusedVmid),
    `destroyed VMID ${reusedVmid}, which now belongs to a different, live lane`);
  // The guard must be per-VM, not per-lane: everything the stale lane really
  // owns still gets cleaned up.
  assert.ok(calls.deletes.includes(110002), "the stale lane's own gateway should still be destroyed");
  assert.ok(calls.deletes.includes(610002), "the stale lane's own slot-0 workstation should still be destroyed");
});

// ── 7. slot band is enforced ─────────────────────────────────────────────────
test('more workstations than the octet band is rejected', async () => {
  reset();
  const many = new Array(laneDeployer.WORKSTATION_MAX_SLOTS + 1).fill(KALI);
  await assert.rejects(
    () => laneDeployer.deployLanes({ users: USERS, templates: many, vxlanBlock: BLOCK }),
    /exceeds the 30-slot band/
  );
});

// ── 8. WAN address pool ──────────────────────────────────────────────────────
test('every lane in a batch gets its own WAN transit address', async () => {
  reset();
  await laneDeployer.deployLanes({
    users: [{ id: 'u1', email: 'a@x.edu' }, { id: 'u2', email: 'b@x.edu' }, { id: 'u3', email: 'c@x.edu' }],
    template: KALI, vxlanBlock: { start: 10000, end: 10005 },
  });
  // The gateway net0 carries it, and the Guac console host is the same address.
  const gwNet0 = calls.configs
    .filter(c => c.body && typeof c.body.net0 === 'string' && c.body.net0.includes('name=wan0'))
    .map(c => c.body.net0.match(/ip=([\d.]+)/)[1]);
  assert.strictEqual(gwNet0.length, 3, 'one gateway per lane');
  assert.strictEqual(new Set(gwNet0).size, 3,
    `two lanes shared a WAN address — the exact bug this replaced: ${gwNet0.join(', ')}`);
});

test('an exhausted WAN pool fails the deploy and closes out its progress', async () => {
  // The CLE route is fire-and-forget: it answers "provisioning started" and the
  // UI polls. A progress entry left open would spin forever on a deploy that
  // never began, so the failure has to land somewhere the poller reads.
  reset();
  _stubWanFail = 'Lane WAN pool exhausted: needed 2 address(es), found 0.';
  try {
    await assert.rejects(
      () => laneDeployer.deployLanes({
        users: [{ id: 'u1', email: 'a@x.edu' }, { id: 'u2', email: 'b@x.edu' }],
        template: KALI, vxlanBlock: BLOCK,
        progressId: 'cle-course-test', progressLabel: 'Test course',
      }),
      /pool exhausted/
    );
    const p = laneDeployer.readProgress('cle-course-test');
    assert.ok(p, 'progress entry should still be readable');
    assert.match(p.error || '', /pool exhausted/, 'the reason must reach the poller');
    assert.strictEqual(p.phase, 'complete', 'and it must not read as still running');
  } finally {
    _stubWanFail = null;
  }
});

test('no Proxmox work happens when the pool is exhausted', async () => {
  // Allocation is deliberately before the first clone, so an exhausted pool
  // fails the request rather than half a classroom.
  reset();
  _stubWanFail = 'Lane WAN pool exhausted: needed 2 address(es), found 0.';
  try {
    await laneDeployer.deployLanes({
      users: [{ id: 'u1', email: 'a@x.edu' }, { id: 'u2', email: 'b@x.edu' }],
      template: KALI, vxlanBlock: BLOCK, progressId: 'cle-course-test2',
    }).catch(() => {});
    assert.strictEqual(calls.clones.length, 0, 'nothing should have been cloned');
  } finally {
    _stubWanFail = null;
  }
});

(async () => {
  let failures = 0;
  for (const [name, fn] of tests) {
    try {
      await fn();
      console.log(`  ok  ${name}`);
    } catch (err) {
      failures++;
      console.error(`FAIL  ${name}\n      ${err.message}`);
    }
  }
  console.log(failures === 0 ? `\n${tests.length} passed` : `\n${failures}/${tests.length} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})();
