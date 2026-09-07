'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const access = require('../src/utils/wazuh-gateway-access');
const SHELL = process.platform === 'win32'
  ? ['C:/Program Files/Git/bin/sh.exe', 'C:/Program Files/Git/usr/bin/sh.exe'].find(fs.existsSync) || 'sh'
  : 'sh';
const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
const shellPath = value => value.split(path.sep).join('/').replace(/^([A-Za-z]):/, (_, drive) => '/' + drive.toLowerCase());
const lane = {
  lane_id: '12345678-1234-1234-1234-123456789abc', status: 'active', vxlan_id: 10811,
  config: { gateway_vmid: 110811, subnet_scheme: 'v2', vnet: 'aaaabha1',
    workstations: [{ vmid: 610811, name: 'Windows 11' }] },
};
const gateway = { vmid: 110811, type: 'lxc', status: 'running', node: 'node-3' };
const guest = { vmid: 610811, type: 'qemu', status: 'running', node: 'node-3' };
const gatewayConfig = {
  ostype: 'alpine', description: 'Lane gateway\nLane: ' + lane.lane_id,
  net0: 'name=wan0,bridge=vmbr0,ip=100.100.62.68/22',
  net1: 'name=lan0,bridge=aaaabha1,ip=10.42.59.1/24',
};
const guestConfig = { net0: 'virtio=AA:BB:CC:DD:EE:FF,bridge=aaaabha1' };
const manager = '100.100.20.10';
const clone = value => JSON.parse(JSON.stringify(value));
function scopeFor(input = lane, config = gatewayConfig) {
  return access.validateGateway(access.validateLane(input, 610811, manager), gateway, config, guest, guestConfig);
}

test('gateway ownership requires lane membership, saved identity, live description and connected bridges', () => {
  assert.equal(scopeFor().gatewayVmid, 110811);
  assert.deepEqual(scopeFor().segments, [{ iface: 'lan0', bridge: 'aaaabha1', cidr: '10.42.59.1/24', subnet: '10.42.59.0/24' }]);
  for (const change of [
    value => { value.status = 'destroyed'; },
    value => { value.config.workstations = []; },
    value => { value.config.gateway_vm_id = 110812; },
    value => { value.config.gateway_vmid = 110812; },
    value => { delete value.config.gateway_vmid; },
    value => { value.config.vnet = 'aaaabha1;touch /tmp/no'; },
    value => { value.config.subnet_scheme = 'unknown'; },
  ]) {
    const invalid = clone(lane); change(invalid);
    assert.throws(() => scopeFor(invalid), { safe: true });
  }
  for (const bad of [
    { description: 'Lane gateway\nLane: different' }, { description: 'Lane: ' + lane.lane_id + '-suffix' },
    { net1: 'name=lan0,bridge=other,ip=10.42.59.1/24' },
    { net1: 'name=ext0,bridge=aaaabha1,ip=10.42.59.1/24' },
    { net1: 'name=lan0,bridge=aaaabha1,ip=10.42.59.1/16' },
    { net2: 'name=extra,bridge=other,ip=10.1.1.1/24' },
    { net0: 'name=eth0,bridge=vmbr0' }, { ostype: 'debian' }, { template: 1 },
  ]) assert.throws(() => scopeFor(lane, { ...gatewayConfig, ...bad }), { safe: true });
  assert.throws(() => access.validateGateway(access.validateLane(lane, 610811, manager), gateway,
    gatewayConfig, guest, { net0: 'virtio=AA:BB:CC:DD:EE:FF,bridge=other' }), { safe: true });
});

test('malware and disabled internet lanes are refused before any infrastructure access', async () => {
  for (const config of [
    { internet_enabled: false }, { analysis_profile: 'malware' }, { analysis: { profile: 'malware', state: 'preparation' } },
    { workstations: [{ vmid: 610811, analysis_profile: 'malware' }] },
  ]) {
    let calls = 0;
    await assert.rejects(access.ensureWazuhGatewayAccess({ lane: { ...lane, config: { ...lane.config, ...config } }, vmId: 610811, manager },
      { proxmox: async () => { calls++; }, pctExec: async () => { calls++; } }), /isolated|malware/);
    assert.equal(calls, 0);
  }
});

test('invalid manager values cannot enter generated gateway commands', () => {
  for (const bad of ['100.100.20.10;echo bad', '100.100.20.10/24', '::1', '127.0.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255']) {
    assert.throws(() => access.validateLane(lane, 610811, bad), { safe: true });
  }
  assert.throws(() => access.renderApply({ manager, segments: [{ iface: 'wan0', cidr: '10.1.1.1/24', subnet: '10.1.1.0/24' }] }, true), /scope/);
});

test('v3 validates both distinct segments and discovers migrated gateways from live resources', async () => {
  const v3 = clone(lane); v3.config.subnet_scheme = 'v3'; v3.config.vnet_internal = 'internal1';
  const cfg = { ...gatewayConfig, net1: 'name=ext0,bridge=aaaabha1,ip=10.42.59.1/24', net2: 'name=int0,bridge=internal1,ip=10.43.59.1/24' };
  const calls = [];
  const result = await access.ensureWazuhGatewayAccess({ lane: v3, vmId: 610811, manager }, {
    proxmox: async (method, url) => {
      calls.push([method, url]);
      if (url.includes('/cluster/resources')) return [{ ...gateway, node: 'node-4' }, guest];
      if (url.includes('/lxc/')) return cfg;
      return guestConfig;
    },
    pctExec: async (node, vmid, argv) => {
      assert.equal(node, 'node-4'); assert.equal(vmid, 110811);
      assert.match(argv[2], /-i ext0 -o wan0/); assert.match(argv[2], /-i int0 -o wan0/);
      return { code: 0, stdout: access.SENTINEL + '\n' };
    },
  });
  assert.deepEqual(result.interfaces, ['ext0', 'int0']);
  assert.ok(calls.some(([, url]) => url === '/api2/json/nodes/node-4/lxc/110811/config'));
});

// Exercise the actual shell, its guards, awk audit, exact-rule mutation and
// persistence against a fabricated firewall. These functions never invoke the
// host's real iptables or change networking.
function fixture(t, scope = scopeFor()) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cc-wazuh-gateway-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const part of ['local.d', 'iptables', 'run']) fs.mkdirSync(path.join(dir, part));
  fs.writeFileSync(path.join(dir, 'forwarding'), '1\n');
  const base = '-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n'
    + '-A FORWARD -i lan0 -d 100.64.0.0/10 -j DROP\n'
    + '-A FORWARD -i wan0 -o lan0 -j DROP\n';
  fs.writeFileSync(path.join(dir, 'rules'), base);
  fs.writeFileSync(path.join(dir, 'extra'), '');
  const d = shellPath(dir);
  const prefix = `ccw_fixture=${quote(d)}
iptables-save() { printf '*filter\\n'; cat "$ccw_fixture/rules"; printf 'COMMIT\\n'; cat "$ccw_fixture/extra"; }
iptables() {
  [ "$1" = -w ] && shift 2
  ccw_verb=$1; ccw_chain=$2; shift 2
  if [ "$ccw_verb" = -I ]; then shift; fi
  ccw_rule="-A $ccw_chain $*"
  case "$ccw_verb" in
    -C) if [ -f "$ccw_fixture/check-error" ]; then return 2; fi; grep -Fqx -- "$ccw_rule" "$ccw_fixture/rules" ;;
    -D) grep -Fvx -- "$ccw_rule" "$ccw_fixture/rules" > "$ccw_fixture/next" || :; mv "$ccw_fixture/next" "$ccw_fixture/rules" ;;
    -I) printf '%s\\n' "$ccw_rule" > "$ccw_fixture/next"; cat "$ccw_fixture/rules" >> "$ccw_fixture/next"; mv "$ccw_fixture/next" "$ccw_fixture/rules" ;;
    *) return 90 ;;
  esac
}
ip() {
  if [ "$1" = link ]; then return 0; fi
  case "$6" in
${scope.segments.map(segment => `    ${segment.iface}) printf '3: ${segment.iface} inet ${segment.cidr} scope global ${segment.iface}\\n' ;;`).join('\n')}
    *) return 1 ;;
  esac
}
`;
  const rewrite = script => script.replaceAll('/etc/local.d', d + '/local.d').replaceAll('/etc/iptables', d + '/iptables')
    .replaceAll('/proc/sys/net/ipv4/ip_forward', d + '/forwarding').replaceAll('/run/cybercore-wazuh-gateway.lock', d + '/run/lock');
  return {
    dir, base, read: name => fs.readFileSync(path.join(dir, name), 'utf8'),
    write: (name, content) => fs.writeFileSync(path.join(dir, name), content),
    run: (install = true, chosen = scope) => spawnSync(SHELL, ['-s'], { input: prefix + rewrite(access.renderApply(chosen, install)), encoding: 'utf8' }),
  };
}

test('real shell only adds manager TCP1514, preserves unrelated rules and remains idempotent', t => {
  const f = fixture(t);
  const first = f.run(); assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, new RegExp(access.SENTINEL));
  const installed = f.read('rules');
  assert.ok(installed.endsWith(f.base));
  assert.equal(installed.split('\n').filter(line => line.includes(access.TAG)).length, 1);
  assert.match(installed.split('\n')[0], /-s 10\.42\.59\.0\/24 -d 100\.100\.20\.10\/32 -i lan0 -o wan0 -p tcp -m tcp --dport 1514 .* -j ACCEPT$/);
  assert.doesNotMatch(installed, /1515|55000|--dport 80 /);
  assert.ok(f.read('iptables/rules-save').includes(installed));
  assert.ok(f.read('local.d/98-cybercore-wazuh.start').includes(access.SENTINEL));
  const retry = f.run(); assert.equal(retry.status, 0, retry.stderr);
  assert.equal(f.read('rules'), installed);
});

test('reboot hook restores allow above newly inserted v3 perimeter drops without flushing', t => {
  const v3 = { ...scopeFor(), segments: [
    { iface: 'ext0', cidr: '10.42.59.1/24', subnet: '10.42.59.0/24' },
    { iface: 'int0', cidr: '10.43.59.1/24', subnet: '10.43.59.0/24' },
  ] };
  const f = fixture(t, v3);
  const install = f.run(); assert.equal(install.status, 0, install.stderr);
  const newDrop = '-A FORWARD -i int0 -o wan0 -d 100.100.0.0/16 -j DROP\n';
  f.write('rules', newDrop + f.read('rules'));
  const boot = f.run(false); assert.equal(boot.status, 0, boot.stderr);
  const rules = f.read('rules').split('\n');
  assert.ok(rules[0].includes(access.TAG)); assert.ok(rules[1].includes(access.TAG));
  assert.equal(rules.filter(line => line.includes(access.TAG)).length, 2);
  assert.ok(f.read('rules').includes(newDrop)); assert.ok(f.read('rules').endsWith(f.base));
});

test('live isolation markers and disabled forwarding stop before writing hooks or rules', t => {
  for (const [name, contents] of [
    ['extra', '*mangle\n:CCMA_LAN - [0:0]\n-A PREROUTING -i lan0 -j CCMA_LAN\nCOMMIT\n'],
    ['extra', '-A FORWARD -i lan0 -m comment --comment CYBERCORE-MALWARE -j DROP\n'],
    ['local.d/99-cybercore-malware.start', '# malware policy\n'], ['forwarding', '0\n'],
  ]) {
    const f = fixture(t); f.write(name, contents);
    const result = f.run(); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /CYBERCORE_WAZUH_GATEWAY_ERROR:containment-active/);
    assert.equal(f.read('rules'), f.base);
    assert.equal(fs.existsSync(path.join(f.dir, 'local.d/98-cybercore-wazuh.start')), false);
  }
});

test('changed manager and conflicting owned rules or hooks are never silently replaced', t => {
  const f = fixture(t); assert.equal(f.run().status, 0);
  const before = f.read('rules');
  const changed = f.run(true, { ...scopeFor(), manager: '100.100.20.11' });
  assert.notEqual(changed.status, 0); assert.match(changed.stderr, /existing-rule-conflict/);
  assert.equal(f.read('rules'), before);
  f.write('local.d/98-cybercore-wazuh.start', '# separately configured\n');
  const hook = f.run(); assert.notEqual(hook.status, 0); assert.match(hook.stderr, /existing-hook-conflict/);
  assert.equal(f.read('rules'), before);
});

test('iptables check errors cannot be mistaken for an absent rule', t => {
  const f = fixture(t); f.write('check-error', '1');
  const result = f.run(); assert.notEqual(result.status, 0); assert.match(result.stderr, /apply-rules/);
  assert.equal(f.read('rules'), f.base);
});

function happyDependencies(overrides = {}) {
  return {
    proxmox: async (_method, url) => url.includes('/cluster/') ? [gateway, guest]
      : url.includes('/lxc/') ? gatewayConfig : guestConfig,
    pctExec: async () => ({ code: 0, stdout: access.SENTINEL + '\n' }),
    ...overrides,
  };
}

test('DNS managers resolve to one validated IPv4 and never interpolate DNS text into firewall rules', async () => {
  let script;
  const result = await access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager: 'wazuh.example.edu' }, happyDependencies({
    resolve4: async host => { assert.equal(host, 'wazuh.example.edu'); return [manager]; },
    pctExec: async (_node, _id, argv) => { script = argv[2]; return { code: 0, stdout: access.SENTINEL + '\n' }; },
  }));
  assert.equal(result.manager, manager);
  assert.match(script, /-d 100\.100\.20\.10\/32/); assert.doesNotMatch(script, /wazuh\.example\.edu/);
  for (const answers of [[], [manager, '100.100.20.11'], ['127.0.0.1'], ['100.100.20.10;echo bad']]) {
    let executed = false;
    await assert.rejects(access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager: 'wazuh.example.edu' }, happyDependencies({
      resolve4: async () => answers, pctExec: async () => { executed = true; },
    })), /one unicast IPv4/);
    assert.equal(executed, false);
  }
});

test('same-gateway batch calls serialize and revalidate the lane after waiting', async () => {
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  let entered;
  const started = new Promise(resolve => { entered = resolve; });
  let simultaneous = 0, maximum = 0, reads = 0;
  const deps = happyDependencies({
    readLane: async () => { reads++; return reads <= 2 ? lane : { ...lane, config: { ...lane.config, internet_enabled: false } }; },
    pctExec: async () => {
      simultaneous++; maximum = Math.max(maximum, simultaneous); entered();
      await blocked; simultaneous--;
      return { code: 0, stdout: access.SENTINEL + '\n' };
    },
  });
  const first = access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager }, deps);
  await started;
  const second = access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager }, deps);
  assert.equal(reads, 2);
  const rejected = assert.rejects(second, /isolated/);
  release(); await first; await rejected;
  assert.equal(maximum, 1); assert.equal(reads, 3);
  // Failed queued jobs release the process lock for a later valid request.
  await access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager }, happyDependencies());
});

test('delayed Proxmox reads cannot open access after internet is disabled or a job is replaced', async () => {
  for (const change of ['internet-disabled', 'job-replaced', 'vm-detached', 'network-changed']) {
    let release, entered;
    const blocked = new Promise(resolve => { release = resolve; });
    const started = new Promise(resolve => { entered = resolve; });
    let changed = false, executed = false, reads = 0;
    const deps = happyDependencies({
      readLane: async () => {
        reads++;
        if (!changed) return lane;
        if (change === 'job-replaced') throw Object.assign(new Error('Installation job replaced'), { safe: true });
        const current = clone(lane);
        if (change === 'internet-disabled') current.config.internet_enabled = false;
        if (change === 'vm-detached') current.config.workstations = [];
        if (change === 'network-changed') current.config.vnet = 'newbridge';
        return current;
      },
      proxmox: async (_method, url) => {
        if (url.includes('/cluster/')) return [gateway, guest];
        if (url.includes('/lxc/')) { entered(); await blocked; return gatewayConfig; }
        return guestConfig;
      },
      pctExec: async () => { executed = true; return { code: 0, stdout: access.SENTINEL + '\n' }; },
    });
    const pending = access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager }, deps);
    await started; assert.equal(reads, 1);
    const rejected = assert.rejects(pending, /isolated|replaced|available lane|network changed/);
    changed = true; release(); await rejected;
    assert.equal(reads, 2, change); assert.equal(executed, false, change);
  }
});

test('upstream exceptions never expose SSH commands or credentials', async () => {
  const deps = {
    proxmox: async (_method, url) => url.includes('/cluster/') ? [gateway, guest]
      : url.includes('/lxc/') ? gatewayConfig : guestConfig,
    pctExec: async () => { throw Object.assign(new Error('SECRET command'), { stderr: 'SECRET password' }); },
  };
  await assert.rejects(access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager }, deps), error => error.safe
    && /TCP 1514/.test(error.message) && !/SECRET|password/.test(error.message));
  deps.pctExec = async () => { throw { stderr: 'CYBERCORE_WAZUH_GATEWAY_ERROR:containment-active\n' }; };
  await assert.rejects(access.ensureWazuhGatewayAccess({ lane, vmId: 610811, manager }, deps), /isolation/);
});
