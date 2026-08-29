/**
 * Standalone test runner for profile-to-spec synthesizer.
 * Run with: node front-end/modules/crucible/plugins/ciab/test/profile-to-spec.test.js
 *
 * Uses Node's built-in assert — no test framework required.
 */

const assert = require('assert');
const {
  synthesizeSpecFromProfile,
  parseOs,
  parseService,
  isWebServer,
  assignLaneAddressing,
  dnsLabel,
  SPEC_OCTET_MIN,
  SPEC_OCTET_MAX
} = require('../utils/profile-to-spec');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
    if (err.actual !== undefined) console.log(`    actual:   ${JSON.stringify(err.actual)}`);
    if (err.expected !== undefined) console.log(`    expected: ${JSON.stringify(err.expected)}`);
    failed++;
  }
}

// ─── Fixtures ───────────────────────────────────────────────────────────────

const VM_CATALOG = [
  { id: 'tpl-win2022', template_vmid: 1000, node: 'cyberhub-node-5',
    os_family: 'windows_server', os_version: '2022', os_name: 'Windows Server 2022',
    role_hints: ['dc', 'file', 'web'], is_active: true, preferred: true },
  { id: 'tpl-ubuntu2204', template_vmid: 1001, node: 'cyberhub-node-5',
    os_family: 'linux', os_version: 'ubuntu-22.04', os_name: 'Ubuntu Server 22.04',
    role_hints: ['web', 'db'], is_active: true, preferred: true },
  { id: 'tpl-win11', template_vmid: 1002, node: 'cyberhub-node-5',
    os_family: 'windows_client', os_version: '11', os_name: 'Windows 11',
    role_hints: [], is_active: true, preferred: true }
];

const VULN_SCRIPTS = [
  // os_target matches migrations/012_seed_vuln_scripts.sql — init-setup is
  // Windows-only PowerShell (init-setup.ps1).
  { id: 'sc-init',  slug: 'init-setup',      os_target: 'windows',
    services_exposed: [], category: 'initial setup', script_type: 'baseline', is_active: true },
  { id: 'sc-smb',   slug: 'win-smb-vuln',    os_target: 'windows',
    services_exposed: ['445/SMB'], category: 'lateral movement', script_type: 'vulnerable', is_active: true },
  { id: 'sc-rdp',   slug: 'win-rdp-bluekeep',os_target: 'windows',
    services_exposed: ['3389/RDP'], category: 'remote access', script_type: 'vulnerable', is_active: true },
  { id: 'sc-http',  slug: 'lin-apache-2449', os_target: 'linux',
    services_exposed: ['80/HTTP'], category: 'web', script_type: 'vulnerable', is_active: true }
];

function profileWith(assets) {
  return { id: 'profile-1', company_name: 'AcmeCo', assets };
}

// ─── parseOs ────────────────────────────────────────────────────────────────

console.log('\nparseOs');

test('parses Windows Server 2022', () => {
  assert.deepStrictEqual(parseOs('Windows Server 2022'), { os_family: 'windows_server', os_version: '2022' });
});

test('parses Windows Server 2019 R2', () => {
  assert.deepStrictEqual(parseOs('Windows Server 2019 R2'), { os_family: 'windows_server', os_version: '2019r2' });
});

test('parses Windows 11', () => {
  assert.deepStrictEqual(parseOs('Windows 11'), { os_family: 'windows_client', os_version: '11' });
});

test('parses Ubuntu Server 22.04 LTS', () => {
  assert.deepStrictEqual(parseOs('Ubuntu Server 22.04 LTS'), { os_family: 'linux', os_version: 'ubuntu-22.04' });
});

test('parses Debian 12', () => {
  assert.deepStrictEqual(parseOs('Debian 12'), { os_family: 'linux', os_version: 'debian-12' });
});

test('unparseable OS returns nulls', () => {
  assert.deepStrictEqual(parseOs('SomethingWeird OS'), { os_family: null, os_version: null });
});

test('empty string returns nulls', () => {
  assert.deepStrictEqual(parseOs(''), { os_family: null, os_version: null });
});

// ─── parseService ───────────────────────────────────────────────────────────

console.log('\nparseService');

test('parses 445/SMB', () => {
  assert.deepStrictEqual(parseService('445/SMB'), { port: 445, service: 'smb' });
});

test('parses 80/HTTP lowercased', () => {
  assert.deepStrictEqual(parseService('80/HTTP'), { port: 80, service: 'http' });
});

test('parses bare service (no port)', () => {
  assert.deepStrictEqual(parseService('ldap'), { port: null, service: 'ldap' });
});

test('handles empty token', () => {
  assert.strictEqual(parseService(''), null);
});

// ─── isWebServer ────────────────────────────────────────────────────────────

console.log('\nisWebServer');

test('server with port 80 is a web server', () => {
  assert.strictEqual(isWebServer({ role: 'server', services: ['80/HTTP', '22/SSH'] }), true);
});

test('server with port 443 is a web server', () => {
  assert.strictEqual(isWebServer({ role: 'server', services: ['443/HTTPS'] }), true);
});

test('workstation with port 80 is NOT a web server', () => {
  assert.strictEqual(isWebServer({ role: 'workstation', services: ['80/HTTP'] }), false);
});

test('server with only SMB is NOT a web server', () => {
  assert.strictEqual(isWebServer({ role: 'server', services: ['445/SMB'] }), false);
});

// ─── Synthesizer: server filter ─────────────────────────────────────────────

console.log('\nsynthesizeSpecFromProfile — server filter');

test('default selection: only servers become VMs', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB', '3389/RDP'] },
    { hostname: 'WS-01', role: 'workstation', os: 'Windows 11', services: [] },
    { hostname: 'FS-01', role: 'server', os: 'Ubuntu Server 22.04', services: ['22/SSH'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(result.spec.vms.length, 2);
  const names = result.spec.vms.map(v => v.name).sort();
  assert.deepStrictEqual(names, ['DC-01', 'FS-01']);
});

test('explicit selection overrides default', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: [] },
    { hostname: 'WS-01', role: 'workstation', os: 'Windows 11', services: [] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: [
      { hostname: 'DC-01', included: false },
      { hostname: 'WS-01', included: true }
    ],
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(result.spec.vms.length, 1);
  assert.strictEqual(result.spec.vms[0].name, 'WS-01');
});

// ─── Synthesizer: template + service resolution ─────────────────────────────

console.log('\nsynthesizeSpecFromProfile — template & service resolution');

test('matched assets get template_vmid + bootstrap + service scripts', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB', '3389/RDP'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(result.spec.vms.length, 1);
  const vm = result.spec.vms[0];
  assert.strictEqual(vm.template_vmid, 1000);
  assert.ok(vm.post_clone_scripts.includes('init-setup'));
  assert.ok(vm.post_clone_scripts.includes('win-smb-vuln'));
  assert.ok(vm.post_clone_scripts.includes('win-rdp-bluekeep'));
  assert.strictEqual(result.service_gaps.length, 0);
  assert.strictEqual(result.template_misses.length, 0);
});

test('unparseable OS lands in template_misses', () => {
  const profile = profileWith([
    { hostname: 'WEIRD-01', role: 'server', os: 'PlanetExpress OS 9000', services: [] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(result.spec.vms.length, 0);
  assert.strictEqual(result.template_misses.length, 1);
  assert.strictEqual(result.template_misses[0].reason, 'unparseable_os');
});

test('parseable OS with no catalog match lands in template_misses', () => {
  const profile = profileWith([
    { hostname: 'MAC-01', role: 'server', os: 'macOS 14', services: [] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(result.spec.vms.length, 0);
  assert.strictEqual(result.template_misses[0].reason, 'no_family_match');
});

test('declared service with no installer lands in service_gaps', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['12345/QuantumDB'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(result.spec.vms.length, 1);
  assert.strictEqual(result.service_gaps.length, 1);
  assert.strictEqual(result.service_gaps[0].service, 'quantumdb');
  assert.strictEqual(result.service_gaps[0].port, 12345);
  assert.strictEqual(result.service_gaps[0].reason, 'no_installer');
});

test('init-setup bootstrap appears exactly once even if duplicate services', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB', '445/SMB'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  const initCount = result.spec.vms[0].post_clone_scripts.filter(s => s === 'init-setup').length;
  assert.strictEqual(initCount, 1);
  const smbCount = result.spec.vms[0].post_clone_scripts.filter(s => s === 'win-smb-vuln').length;
  assert.strictEqual(smbCount, 1);
});

// os_family ('windows_server'/'windows_client'/'linux') and os_target
// ('windows'/'linux') are different namespaces. Comparing them raw excluded
// init-setup from every host, so it ran nowhere. These two lock in both
// directions of the intended behaviour.
test('init-setup lands on Windows hosts despite the os_family/os_target namespace gap', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: [] },
    { hostname: 'WS-01', role: 'server', os: 'Windows 11',          services: [] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  // windows_server and windows_client both normalise to os_target 'windows'.
  for (const vm of result.spec.vms) {
    assert.ok(
      vm.post_clone_scripts.includes('init-setup'),
      `${vm.name} should get the Windows bootstrap`
    );
  }
});

test('init-setup is skipped on Linux hosts (powershell does not exist there)', () => {
  const profile = profileWith([
    { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS
  });
  const vm = result.spec.vms[0];
  assert.ok(!vm.post_clone_scripts.includes('init-setup'), 'Linux VM must not get the PowerShell bootstrap');
  // The Linux service script still resolves — only the bootstrap is filtered.
  assert.ok(vm.post_clone_scripts.includes('lin-apache-2449'));
});

// ─── Synthesizer: vuln-app placement ────────────────────────────────────────

console.log('\nsynthesizeSpecFromProfile — vuln-app placement');

test('vuln-app targets web-server asset automatically', () => {
  const profile = profileWith([
    { hostname: 'DC-01',  role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] },
    { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS,
    vulnApp: {
      id: 'va-1', delivery_mode: 'docker', install_script: 'echo install', target_hostname: null
    }
  });
  assert.ok(result.spec.vuln_app_install);
  assert.strictEqual(result.spec.vuln_app_install.target_vm, 'WEB-01');
  assert.strictEqual(result.spec.vuln_app_install.mode, 'docker');
});

test('vuln-app standalone_vm adds an extra synthetic VM when no web server', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS,
    vulnApp: {
      id: 'va-2', delivery_mode: 'standalone_vm', install_script: 'echo standalone'
    }
  });
  assert.strictEqual(result.spec.vms.length, 2);
  const synthetic = result.spec.vms.find(v => v.synthetic);
  assert.ok(synthetic, 'expected a synthetic VM');
  assert.strictEqual(synthetic.name, 'vuln-app');
  assert.strictEqual(result.spec.vuln_app_install.target_vm, 'vuln-app');
});

test('vuln-app (docker mode) gets a dedicated standalone VM when no web server', () => {
  // The real delivery mode is always 'docker'. With most realistic profiles
  // now being serverless, "no web server" is the common case — the app must
  // still deploy onto its own VM cloned from the Linux web template (so Docker
  // is present), NOT be silently skipped.
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS,
    vulnApp: {
      id: 'va-3', delivery_mode: 'docker', install_script: 'echo docker'
    }
  });
  assert.ok(result.spec.vuln_app_install, 'vuln-app should still be placed');
  assert.strictEqual(result.spec.vuln_app_install.target_vm, 'vuln-app');
  assert.strictEqual(result.spec.vuln_app_install.mode, 'docker');
  const synthetic = result.spec.vms.find(v => v.synthetic);
  assert.ok(synthetic, 'expected a synthetic vuln-app VM');
  // Must clone template 1005 — the baked Docker-capable "web-01" template.
  assert.strictEqual(synthetic.template_vmid, 1005);
});

test('vuln-app fully serverless profile (no servers at all) still deploys standalone', () => {
  // A cloud-first org: only workstations, zero servers. The vuln-app must
  // still come up on its own VM.
  const profile = profileWith([
    { hostname: 'admin-ws-01', role: 'workstation', os: 'Windows 11', services: [] },
    { hostname: 'ops-ws-02',   role: 'workstation', os: 'Windows 11', services: [] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS,
    vulnApp: {
      id: 'va-4', delivery_mode: 'docker', install_script: 'echo docker'
    }
  });
  assert.ok(result.spec.vuln_app_install, 'vuln-app should be placed even with no servers');
  assert.strictEqual(result.spec.vuln_app_install.target_vm, 'vuln-app');
  const synthetic = result.spec.vms.find(v => v.synthetic);
  assert.ok(synthetic, 'expected a synthetic vuln-app VM');
});

// ─── Lane addressing (A4) ───────────────────────────────────────────────────
// ipOctet is the contract between a profile's generated paper and its lane's
// real addresses: the scan documents can only claim `10.x.y.83` for `web01` if
// the deploy actually puts it there. These pin the properties the paper depends
// on — stable order, no duplicate alias, nothing pinned that the deployer would
// ignore.

console.log('\nlane addressing');

test('every deployable VM gets a sequential ipOctet from the band base', () => {
  const result = synthesizeSpecFromProfile({
    profile: profileWith([
      { hostname: 'DC-01',  role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] },
      { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] }
    ]),
    assetSelection: null, vmTemplateCatalog: VM_CATALOG, vulnScriptCatalog: VULN_SCRIPTS
  });
  const octets = result.spec.vms.map(v => v.ipOctet);
  assert.deepStrictEqual(octets, [SPEC_OCTET_MIN, SPEC_OCTET_MIN + 1]);
});

test('the synthetic vuln-app VM is addressed like any other machine', () => {
  // It is appended after the loop, so it is the one most likely to be forgotten
  // — and it is the host the student's whole web exercise points at.
  const result = synthesizeSpecFromProfile({
    profile: profileWith([
      { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] }
    ]),
    assetSelection: null, vmTemplateCatalog: VM_CATALOG, vulnScriptCatalog: VULN_SCRIPTS,
    vulnApp: { install_script: 'echo hi', delivery_mode: 'docker' }
  });
  const synthetic = result.spec.vms.find(v => v.synthetic);
  assert.ok(synthetic, 'expected a synthetic vuln-app VM');
  assert.strictEqual(typeof synthetic.ipOctet, 'number');
  assert.deepStrictEqual(synthetic.dns_aliases, ['vuln-app']);
});

test('adding an asset does not move an existing octet', () => {
  // Order is the contract. Paper already handed to a student must keep naming
  // the address the lane actually uses.
  const first = { hostname: 'DC-01',  role: 'server', os: 'Windows Server 2022', services: [] };
  const added = { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', services: [] };
  const before = synthesizeSpecFromProfile({
    profile: profileWith([first]),
    assetSelection: null, vmTemplateCatalog: VM_CATALOG, vulnScriptCatalog: VULN_SCRIPTS
  });
  const after = synthesizeSpecFromProfile({
    profile: profileWith([first, added]),
    assetSelection: null, vmTemplateCatalog: VM_CATALOG, vulnScriptCatalog: VULN_SCRIPTS
  });
  assert.strictEqual(
    before.spec.vms.find(v => v.name === 'DC-01').ipOctet,
    after.spec.vms.find(v => v.name === 'DC-01').ipOctet
  );
});

test('a dotted hostname publishes only its first label', () => {
  // resolveDnsAliases validates a SINGLE DNS label and silently drops anything
  // with a dot, so `web01.corp.local` would publish no name at all.
  assert.strictEqual(dnsLabel('web01.corp.local'), 'web01');
  assert.strictEqual(dnsLabel('FILE_01'), 'file-01');
  assert.strictEqual(dnsLabel('   '), null);
  assert.strictEqual(dnsLabel('---'), null);
});

test('two hosts cannot claim one DNS alias', () => {
  // The deployer THROWS on a duplicate alias, which would fail the whole batch
  // over a convenience name. First claimant wins; the loser keeps its address.
  const vms = [
    { name: 'a', hostname: 'web_01', type: 'qemu' },
    { name: 'b', hostname: 'web-01', type: 'qemu' }
  ];
  assignLaneAddressing(vms);
  assert.deepStrictEqual(vms[0].dns_aliases, ['web-01']);
  assert.ok(!vms[1].dns_aliases, 'the second claimant must not publish the same alias');
  assert.strictEqual(vms[1].ipOctet, SPEC_OCTET_MIN + 1, 'but it still gets a fixed address');
});

test('LXC machines are not pinned — the deployer would ignore the address', () => {
  // Pinning one writes an address nothing honours, and the paper would then
  // name an IP no host answers on. Worse than naming none.
  const vms = [
    { name: 'ct', hostname: 'ct', type: 'lxc' },
    { name: 'vm', hostname: 'vm', type: 'qemu' }
  ];
  assignLaneAddressing(vms);
  assert.strictEqual(vms[0].ipOctet, undefined);
  assert.strictEqual(vms[1].ipOctet, SPEC_OCTET_MIN);
});

test('overflowing the band fails loudly rather than half-pinning the lane', () => {
  const capacity = SPEC_OCTET_MAX - SPEC_OCTET_MIN + 1;
  const vms = [];
  for (let i = 0; i <= capacity; i++) vms.push({ name: `h${i}`, hostname: `h${i}`, type: 'qemu' });
  assert.throws(() => assignLaneAddressing(vms), /can pin only/);
});

// ─── Done ───────────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
