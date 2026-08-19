/**
 * workstation-credentials.test.js — which account a lane workstation is built with.
 *
 * The bug this pins: a Windows template that declared neither
 * metadata.default_rdp_user nor metadata.cloud_init_user fell through to a
 * username derived from the student's EMAIL. cloudbase-init is pinned at bake
 * time to one account and can only set THAT account's password, so the generated
 * password landed on the baked account while Guacamole authenticated as a user
 * that did not exist — a plain RDP login failure with nothing pointing at
 * cloud-init. Migrations 025 and 026 exist for the same failure but can only
 * rewrite a template that already had default_rdp_user set, so a newly
 * registered image walked straight into it.
 *
 * Linux is deliberately NOT changed: cloud-init genuinely creates whatever
 * account ciuser names there, so the per-student username is correct.
 *
 * Run: node --test front-end/test/workstation-credentials.test.js
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stubModule(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// The deployer pulls in Proxmox, Postgres, ssh and Guacamole at require time.
stubModule('cybercore-db.js', { cybercoreQuery: async () => ({ rows: [] }) });
stubModule('proxmox.js', { proxmoxAPI: async () => ({}), waitForTask: async () => {}, findTemplateNode: async () => 'node1', forceDestroyVM: async () => true });
stubModule('node-ssh.js', { nodeExec: async () => ({ stdout: '' }), pctExec: async () => ({ stdout: '' }), pctPushFromString: async () => {}, pctExecWithStdin: async () => ({ stdout: '' }) });
stubModule('guacamole.js', { guacAPI: async () => ({}) });
stubModule('guac-credentials.js', { ensureGuacUser: async () => true });
stubModule('tailscale.js', { deleteLaneDevices: async () => 0, isEnabled: () => false });
stubModule('node-selector.js', { selectBestNode: async () => ({ node: 'node1' }) });
stubModule('lane-wan-allocator.js', {
  allocateLaneWanIps: async () => [], releaseLaneWanIps: async () => {},
  recordLaneWanLease: async () => true, findWanIpConflicts: async () => [],
  wanConfigFromAddress: (a) => ({ address: a, ip: `${a}/22` }),
});
stubModule('site-config.js', {
  getDefaultTemplateNode: () => 'node1',
  getSchedulingConfig: () => ({ max_concurrent_lanes: 4, max_concurrent_clones: 4 }),
  getClusterNodes: () => ['node1'],
  getV2LabNetwork: () => ({
    bridge: 'vmbr0', vlan_tag: 60, subnet: '100.100.60.0/22', network: '100.100.60.0',
    broadcast: '100.100.63.255', prefix_len: 22, cidr: '/22', subnet_base: '100.100.60',
    gateway: '100.100.60.1', host_range: { first: '100.100.60.10', last: '100.100.63.254' },
    reserved: [], probe: { enabled: false, node: null, interface: 'vmbr0.60', timeout_ms: 2000 },
  }),
  getV1LanSubnet: () => ({ base3: '192.18.0', cidr: '192.18.0.0/24', gateway_ip: '192.18.0.1', netmask24: '255.255.255.0' }),
  getModuleNetwork: () => ({}), getModuleNetworks: () => ({}),
});

const { resolveWorkstationCredentials } = require(path.join(UTILS, 'lane-deployer.js'));

const USER = { id: 'u1', email: 'jpmickelson04@gmail.com' };
const tpl = (over) => ({ id: 't1', template_key: 'elk', os_name: 'CYBR 400 ELK Stack Template', metadata: {}, ...over });

test('a template that bakes account AND password is used verbatim, no injection', () => {
  const c = resolveWorkstationCredentials(
    tpl({ os_family: 'windows_client', metadata: { default_rdp_user: 'labuser', default_rdp_pass: 'hunter2' } }), USER);
  assert.deepStrictEqual(c, { username: 'labuser', password: 'hunter2', source: 'template' });
});

test('a pinned cloud-init account keeps its name and gets a fresh password', () => {
  const c = resolveWorkstationCredentials(
    tpl({ os_family: 'windows_client', metadata: { cloud_init_user: 'cactus-user' } }), USER);
  assert.strictEqual(c.username, 'cactus-user');
  assert.strictEqual(c.source, 'cloudinit');
  assert.ok(c.password && c.password.length >= 8, 'per-lane password');
});

test('an image baked with a different account is honoured, not overridden', () => {
  // bake-win-client-template.sh writes username=Admin, so the per-template
  // declaration has to beat the Windows default.
  const c = resolveWorkstationCredentials(
    tpl({ os_family: 'windows_client', metadata: { cloud_init_user: 'Admin' } }), USER);
  assert.strictEqual(c.username, 'Admin');
});

test('THE BUG: a Windows template declaring nothing no longer uses the email local part', () => {
  const c = resolveWorkstationCredentials(tpl({ os_family: 'windows_client' }), USER);
  assert.notStrictEqual(c.username, 'jpmickelson04');
  assert.strictEqual(c.username, 'cactus-user');
  assert.strictEqual(c.source, 'cloudinit');
  assert.ok(c.password, 'still a per-lane password');
});

test('the Windows fallback covers windows_server too, not just windows_client', () => {
  assert.strictEqual(resolveWorkstationCredentials(tpl({ os_family: 'windows_server' }), USER).username, 'cactus-user');
  assert.strictEqual(resolveWorkstationCredentials(tpl({ os_family: 'windows' }), USER).username, 'cactus-user');
});

test('the Windows fallback is overridable per site', () => {
  // The constant is read at module load, so the override is exercised by
  // re-loading the module with the variable set — which is exactly how a site
  // that sets it in the environment gets it.
  const prev = process.env.LANE_DEFAULT_WINDOWS_CI_USER;
  process.env.LANE_DEFAULT_WINDOWS_CI_USER = 'site-account';
  try {
    delete require.cache[require.resolve(path.join(UTILS, 'lane-deployer.js'))];
    const reloaded = require(path.join(UTILS, 'lane-deployer.js'));
    assert.strictEqual(
      reloaded.resolveWorkstationCredentials(tpl({ os_family: 'windows_client' }), USER).username,
      'site-account'
    );
  } finally {
    if (prev === undefined) delete process.env.LANE_DEFAULT_WINDOWS_CI_USER;
    else process.env.LANE_DEFAULT_WINDOWS_CI_USER = prev;
    delete require.cache[require.resolve(path.join(UTILS, 'lane-deployer.js'))];
    require(path.join(UTILS, 'lane-deployer.js'));
  }
});

test('Linux keeps the per-student account — cloud-init really does create it', () => {
  const c = resolveWorkstationCredentials(tpl({ os_family: 'linux' }), USER);
  assert.strictEqual(c.username, 'jpmickelson04');
  assert.strictEqual(c.source, 'cloudinit');
});

test('a Linux username is sanitized to something a guest will accept', () => {
  const c = resolveWorkstationCredentials(tpl({ os_family: 'linux' }), { id: 'u2', email: 'A.B+tag@x.edu' });
  assert.strictEqual(c.username, 'a-b-tag');
});

test('a user with no email at all still yields a usable account', () => {
  assert.strictEqual(resolveWorkstationCredentials(tpl({ os_family: 'linux' }), { id: 'u3' }).username, 'student');
});

test('every lane from one template gets a different password', () => {
  const t = tpl({ os_family: 'windows_client' });
  const a = resolveWorkstationCredentials(t, USER);
  const b = resolveWorkstationCredentials(t, { id: 'u4', email: 'other@x.edu' });
  assert.strictEqual(a.username, b.username, 'same pinned account');
  assert.notStrictEqual(a.password, b.password, 'but never the same secret');
});
