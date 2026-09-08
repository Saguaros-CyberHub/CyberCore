'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { buildLinuxSuricataFunctions, SURICATA_WARNINGS } = require('../src/utils/wazuh-linux-suricata');

const python = ['python3', 'python'].find(command => spawnSync(command, ['--version'], { timeout: 5000 }).status === 0);
const source = buildLinuxSuricataFunctions();
const imports = 'import os, re, stat, shutil, subprocess, tempfile, time\nfrom pathlib import Path\nfrom xml.dom import minidom\n';
function execute(code) {
  const result = spawnSync(python, ['-'], { input: imports + source + '\n' + code, encoding: 'utf8', timeout: 20000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

const fixture = String.raw`
from unittest.mock import patch
RealPath = Path
temporary = tempfile.TemporaryDirectory(prefix='cybercore-suricata-test-')
root = RealPath(temporary.name)
SURICATA_CONFIG_DIR = root / 'etc/cybercore-suricata'
SURICATA_DATA_DIR = root / 'var/lib/cybercore-suricata'
SURICATA_LOG_DIR = root / 'var/log/cybercore-suricata'
SURICATA_UNIT_DIR = root / 'etc/systemd/system'
SURICATA_RUNTIME_DIR = root / 'run/systemd/system'
SURICATA_DISTRO_CONFIG = root / 'etc/suricata/suricata.yaml'
release_file = root / 'os-release'
release_file.write_text('ID=kali\n')
logrotate_file = root / 'logrotate'
for directory in (SURICATA_CONFIG_DIR.parent, SURICATA_DATA_DIR.parent,
                  SURICATA_LOG_DIR.parent, SURICATA_UNIT_DIR, SURICATA_RUNTIME_DIR):
    directory.mkdir(parents=True, exist_ok=True)
def Path(value):
    if str(value) == '/etc/os-release': return release_file
    if str(value) == '/usr/sbin/logrotate': return logrotate_file
    return RealPath(value)
# Model root-owned POSIX modes on Windows as well as unprivileged Linux runners.
original_stat = RealPath.stat
def fixture_stat(path, *args, **kwargs):
    value = original_stat(path, *args, **kwargs)
    fields = list(value)
    fields[0] &= ~0o022
    fields[4] = 0
    return os.stat_result(fields)
permissions = patch.object(RealPath, 'stat', fixture_stat)
permissions.start()
commands = {'apt-get': '/usr/bin/apt-get', 'ip': '/usr/sbin/ip'}
active = set()
calls = []
stage_failure = None
failure_count = 0
route_data = [{'dst': 'default', 'dev': 'ens18', 'metric': 100}]
address_data = [{'addr_info': [{'family': 'inet', 'scope': 'global', 'local': '10.60.1.15', 'prefixlen': 24}]}]
default_yaml = '''%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    HTTP_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
app-layer:
  protocols:
    http:
      enabled: yes
outputs:
  - pcap-log:
      enabled: yes
include: /custom/unsafe.yaml
plugins: [/custom/plugin.so]
'''
def installed():
    commands.update({'suricata': '/usr/bin/suricata', 'suricata-update': '/usr/bin/suricata-update',
                     'logrotate': '/usr/sbin/logrotate'})
    SURICATA_DISTRO_CONFIG.parent.mkdir(exist_ok=True)
    SURICATA_DISTRO_CONFIG.write_text(default_yaml)
    logrotate_file.write_text('fixture')
def run(args, timeout=60, env=None):
    global failure_count
    calls.append(list(args))
    command = args[0].split('/')[-1]
    if command == 'systemctl':
        operation = args[1]
        if operation == 'is-active':
            if args[-1] not in active: raise subprocess.CalledProcessError(3, args)
        elif operation == 'mask': (SURICATA_RUNTIME_DIR / 'suricata.service').write_text('mask')
        elif operation == 'unmask': (SURICATA_RUNTIME_DIR / 'suricata.service').unlink()
        elif operation in ('restart', 'start'):
            if stage_failure == 'start' and args[-1] == SURICATA_SERVICE and failure_count == 0:
                failure_count += 1
                raise subprocess.CalledProcessError(1, args)
            active.add(args[-1])
            if args[-1] == SURICATA_SERVICE: (SURICATA_LOG_DIR / 'eve.json').write_text('{}\n')
        elif operation == 'stop':
            active.difference_update(args[2:])
    elif command == 'apt-get':
        if stage_failure == 'packages': raise subprocess.CalledProcessError(1, args)
        if 'install' in args: installed()
    elif command == 'ip':
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(route_data if 'route' in args else address_data).encode())
    elif command == 'suricata-update':
        (SURICATA_DATA_DIR / 'rules/suricata.rules').write_text('alert tcp any any -> any any (msg:"fixture"; sid:1;)\n')
        if stage_failure == 'rules': raise subprocess.CalledProcessError(1, args, output=b'secret diagnostic must not escape')
    elif command == 'suricata':
        if '-V' in args: return subprocess.CompletedProcess(args, 0, stdout=b'This is Suricata version 7.0.15 RELEASE')
        if stage_failure == 'test': raise subprocess.CalledProcessError(1, args)
    return subprocess.CompletedProcess(args, 0, stdout=b'')
shutil.which = lambda command: commands.get(command)
time.sleep = lambda seconds: None
_suri_unmanaged_process = lambda owned: False
def owned_sensor():
    installed()
    for location in (SURICATA_CONFIG_DIR, SURICATA_DATA_DIR, SURICATA_LOG_DIR, SURICATA_DATA_DIR / 'rules'):
        location.mkdir(exist_ok=True)
    (SURICATA_CONFIG_DIR / 'managed').write_text(SURICATA_OWNER)
    (SURICATA_CONFIG_DIR / 'suricata.yaml').write_text(SURICATA_OWNER + 'previous: true\n')
    (SURICATA_DATA_DIR / 'rules/suricata.rules').write_text('previous rules\n')
    active.add(SURICATA_SERVICE)
`;

test('generated sensor functions parse as Python and all warning codes are explicitly mapped', { skip: !python }, () => {
  const result = execute('import ast\nast.parse(' + JSON.stringify(source) + ')\nprint(json.dumps(True))');
  assert.equal(result, true);
  const codes = [...source.matchAll(/['"](suricata-[a-z-]+)['"]/g)].map(match => match[1]);
  const nonWarnings = new Set(['suricata-update', 'suricata-main']);
  for (const code of new Set(codes.filter(value => !nonWarnings.has(value)))) assert.equal(typeof SURICATA_WARNINGS[code], 'string', code);
});

test('fresh sensor uses passive capture, connected subnet, bounded resources and metadata-only EVE', { skip: !python }, () => {
  const result = execute(fixture + String.raw`
import yaml
result = configure_suricata()
config = yaml.safe_load((SURICATA_CONFIG_DIR / 'suricata.yaml').read_text())
units = {location.name: content for location, content in _suri_units('/usr/bin/suricata').items()}
print(json.dumps({'result': result, 'config': config, 'calls': calls, 'units': units,
                  'distro_unchanged': SURICATA_DISTRO_CONFIG.read_text() == default_yaml,
                  'mask_removed': not (SURICATA_RUNTIME_DIR / 'suricata.service').exists()}))
`);
  assert.deepEqual(result.result, { complete: true, warnings: [] });
  assert.equal(result.distro_unchanged, true);
  assert.equal(result.mask_removed, true);
  assert.equal(result.config.vars['address-groups'].HOME_NET, '[10.60.1.0/24]');
  assert.equal(result.config.vars['address-groups'].EXTERNAL_NET, 'any');
  assert.equal(result.config['af-packet'][0].interface, 'ens18');
  assert.equal(result.config['af-packet'][0].threads, 2);
  assert.equal(result.config['af-packet'][0]['disable-promisc'], false);
  assert.equal(result.config['af-packet'][0]['copy-mode'], undefined);
  assert.equal(result.config.runmode, 'workers');
  assert.equal(result.config.include, undefined);
  assert.equal(result.config.plugins, undefined);
  assert.deepEqual(Object.keys(result.config.outputs[0]), ['eve-log']);
  const eve = result.config.outputs[0]['eve-log'];
  assert.deepEqual(eve.types.map(value => typeof value === 'string' ? value : Object.keys(value)[0]), ['alert', 'stats', 'dns', 'tls', 'flow']);
  for (const value of Object.values(eve.types[0].alert)) assert.equal(value, false);
  assert.match(result.units['cybercore-suricata.service'], /CPUQuota=150%\nMemoryHigh=512M\nMemoryMax=1G/);
  assert.match(result.units['logrotate.conf'], /daily\n    maxsize 50M\n    rotate 3/);
  assert.match(result.units['cybercore-suricata-logrotate.timer'], /OnUnitActiveSec=1min/);
  assert.ok(result.calls.some(args => args.includes('-T')));
  assert.ok(result.calls.some(args => args[0] === 'apt-get' && args.includes('APT::Get::AllowUnauthenticated=false')));
  assert.ok(result.calls.every(args => !args.some(arg => /iptables|nft|wazuh-agent|--no-check-certificate|--allow-unauthenticated/.test(arg))));
});

test('owned retry refreshes rules without reinstalling packages or replacing distro configuration', { skip: !python }, () => {
  const result = execute(fixture + String.raw`
owned_sensor()
result = configure_suricata()
print(json.dumps({'result': result, 'calls': calls, 'distro_unchanged': SURICATA_DISTRO_CONFIG.read_text() == default_yaml}))
`);
  assert.deepEqual(result.result, { complete: true, warnings: [] });
  assert.equal(result.distro_unchanged, true);
  assert.ok(result.calls.every(args => args[0] !== 'apt-get'));
});

for (const scenario of ['unmanaged-installed', 'unmanaged-running', 'unsupported', 'ambiguous', 'unsafe-interface']) {
  test(`${scenario} returns a specific warning before package or service changes`, { skip: !python }, () => {
    const setup = {
      'unmanaged-installed': 'installed()',
      'unmanaged-running': "active.add('suricata.service')",
      unsupported: "release_file.write_text('ID=rocky\\n')",
      ambiguous: "route_data.append({'dst': 'default', 'dev': 'ens19', 'metric': 100})",
      'unsafe-interface': "route_data[0]['dev'] = 'eth0;id'",
    }[scenario];
    const result = execute(fixture + '\n' + setup + String.raw`
result = configure_suricata()
print(json.dumps({'result': result, 'calls': calls, 'config_created': SURICATA_CONFIG_DIR.exists()}))
`);
    assert.equal(result.result.complete, false);
    const expected = {
      'unmanaged-installed': 'suricata-unmanaged-installation', 'unmanaged-running': 'suricata-unmanaged-installation',
      unsupported: 'suricata-unsupported-distribution', ambiguous: 'suricata-interface-ambiguous',
      'unsafe-interface': 'suricata-interface-unavailable',
    }[scenario];
    assert.deepEqual(result.result.warnings, [expected]);
    assert.equal(result.config_created, false);
    assert.ok(result.calls.every(args => args[0] === 'ip' || (args[0] === 'systemctl' && args[1] === 'is-active')));
  });
}

test('package failure removes its temporary service mask and retains a retryable ownership marker', { skip: !python }, () => {
  const result = execute(fixture + String.raw`
stage_failure = 'packages'
first = configure_suricata()
mask_removed = not (SURICATA_RUNTIME_DIR / 'suricata.service').exists()
stage_failure = None
second = configure_suricata()
print(json.dumps({'first': first, 'second': second, 'mask_removed': mask_removed}))
`);
  assert.deepEqual(result.first, { complete: false, warnings: ['suricata-package-install-failed'] });
  assert.deepEqual(result.second, { complete: true, warnings: [] });
  assert.equal(result.mask_removed, true);
});

for (const failure of ['rules', 'test', 'start']) {
  test(`${failure} failure restores owned configuration and rules without exposing command output`, { skip: !python }, () => {
    const result = execute(fixture + '\nowned_sensor()\nstage_failure = ' + JSON.stringify(failure) + String.raw`
result = configure_suricata()
print(json.dumps({'result': result, 'config': (SURICATA_CONFIG_DIR / 'suricata.yaml').read_text(),
                  'rules': (SURICATA_DATA_DIR / 'rules/suricata.rules').read_text(), 'active': sorted(active), 'calls': calls}))
`);
    const code = { rules: 'suricata-rule-update-failed', test: 'suricata-configuration-test-failed', start: 'suricata-service-start-failed' }[failure];
    assert.deepEqual(result.result, { complete: false, warnings: [code] });
    assert.equal(result.config, '# Managed by CyberCore Suricata v1\nprevious: true\n');
    assert.equal(result.rules, 'previous rules\n');
    assert.ok(result.active.includes('cybercore-suricata.service'));
    assert.ok(result.calls.every(args => !args.includes('wazuh-agent')));
    assert.doesNotMatch(JSON.stringify(result.result), /secret diagnostic/);
  });
}

test('collector addition preserves multiple XML roots and existing collectors and is idempotent', { skip: !python }, () => {
  const result = execute(String.raw`
from pathlib import PurePosixPath
SURICATA_LOG_DIR = PurePosixPath('/var/log/cybercore-suricata')
SURICATA_RESULT = {'complete': True, 'warnings': []}
document = minidom.parseString('<cybercore><ossec_config><client><server><address>manager</address></server></client><localfile><location>/var/log/auth.log</location><log_format>syslog</log_format></localfile></ossec_config><ossec_config><syscheck><directories>/etc</directories></syscheck></ossec_config></cybercore>')
first = add_suricata_collector(document)
second = add_suricata_collector(document)
print(json.dumps({'first': first, 'second': second, 'xml': document.toxml(), 'count': len(document.getElementsByTagName('localfile'))}))
`);
  assert.equal(result.first, true);
  assert.equal(result.second, true);
  assert.equal(result.count, 2);
  assert.match(result.xml, /<syscheck><directories>\/etc<\/directories><\/syscheck>/);
  assert.match(result.xml, /<log_format>json<\/log_format><location>\/var\/log\/cybercore-suricata\/eve.json<\/location>/);
  assert.match(result.xml, /<location>\/var\/log\/auth.log<\/location><log_format>syslog<\/log_format>/);
});

test('existing JSON wildcard collector avoids duplication; incompatible collector updates the shared result', { skip: !python }, () => {
  for (const format of ['json', 'syslog']) {
    const result = execute('format = ' + JSON.stringify(format) + String.raw`
from pathlib import PurePosixPath
SURICATA_LOG_DIR = PurePosixPath('/var/log/cybercore-suricata')
SURICATA_RESULT = {'complete': True, 'warnings': []}
shared = SURICATA_RESULT
document = minidom.parseString('<ossec_config><localfile><log_format>' + format + '</log_format><location>/var/log/*/eve.json</location></localfile></ossec_config>')
before = document.toxml()
success = add_suricata_collector(document)
print(json.dumps({'success': success, 'shared': shared, 'unchanged': before == document.toxml()}))
`);
    assert.equal(result.success, format === 'json');
    assert.equal(result.unchanged, true);
    assert.deepEqual(result.shared, { complete: format === 'json', warnings: format === 'json' ? [] : ['suricata-collector-conflict'] });
  }
});

test('incomplete sensor does not append a misleading Wazuh collector', { skip: !python }, () => {
  const result = execute(String.raw`
document = minidom.parseString('<ossec_config/>')
before = document.toxml()
print(json.dumps({'success': add_suricata_collector(document), 'unchanged': before == document.toxml()}))
`);
  assert.deepEqual(result, { success: false, unchanged: true });
});

test('unsafe path ownership, writable permissions and ancestor links are refused', { skip: !python }, () => {
  const result = execute(String.raw`
from types import SimpleNamespace
failures = []
class Item:
    def __init__(self, uid=0, mode=0o640, linked=False, parents=()):
        self.uid, self.mode, self.linked, self.parents = uid, mode, linked, parents
    def is_symlink(self): return self.linked
    def exists(self): return True
    def is_file(self): return True
    def is_dir(self): return True
    def stat(self): return SimpleNamespace(st_uid=self.uid, st_mode=self.mode)
Path = lambda item: item
for item in (Item(uid=1000), Item(mode=0o660), Item(linked=True), Item(parents=(Item(linked=True),))):
    try:
        _suri_safe(item)
        failures.append(None)
    except SuricataSetupError as error:
        failures.append(str(error))
print(json.dumps(failures))
`);
  assert.deepEqual(result, Array(4).fill('suricata-unsafe-path'));
});

test('failed fresh service startup leaves no enabled managed sensor and does not stop the distro service', { skip: !python }, () => {
  const result = execute(fixture + String.raw`
stage_failure = 'start'
result = configure_suricata()
print(json.dumps({'result': result, 'calls': calls, 'unit_exists': (SURICATA_UNIT_DIR / SURICATA_SERVICE).exists()}))
`);
  assert.deepEqual(result.result, { complete: false, warnings: ['suricata-service-start-failed'] });
  assert.equal(result.unit_exists, false);
  assert.ok(result.calls.some(args => args[0] === 'systemctl' && args[1] === 'disable' && args.includes('cybercore-suricata.service')));
  assert.ok(result.calls.every(args => !(args[0] === 'systemctl' && args[1] === 'stop' && args.includes('suricata.service'))));
});

test('unmanaged-process guard recognizes the real Suricata-Main thread name and checks service ownership', { skip: !python }, () => {
  const result = execute(String.raw`
from types import SimpleNamespace
class Process:
    def __init__(self, comm, cgroup): self.values = {'comm': comm, 'cgroup': cgroup}
    def joinpath(self, name): return SimpleNamespace(read_text=lambda: self.values[name])
processes = []
Path = lambda value: SimpleNamespace(glob=lambda pattern: processes)
results = []
for comm, cgroup, owned in [('Suricata-Main', '0::/system.slice/suricata.service', True),
                             ('Suricata-Main', '0::/system.slice/cybercore-suricata.service', False),
                             ('Suricata-Main', '0::/system.slice/cybercore-suricata.service', True),
                             ('suricata', '0::/user.slice/session.scope', True),
                             ('curl', '0::/user.slice/session.scope', False)]:
    processes = [Process(comm, cgroup)]
    results.append(_suri_unmanaged_process(owned))
print(json.dumps(results))
`);
  assert.deepEqual(result, [true, true, false, true, false]);
});
