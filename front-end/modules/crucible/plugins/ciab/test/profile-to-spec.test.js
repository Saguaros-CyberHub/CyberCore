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
  isWebServer
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
  { id: 'sc-init',  slug: 'init-setup',      os_target: 'linux',
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

test('vuln-app silently skipped when no web server and not standalone_vm', () => {
  const profile = profileWith([
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] }
  ]);
  const result = synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog: VM_CATALOG,
    vulnScriptCatalog: VULN_SCRIPTS,
    vulnApp: {
      id: 'va-3', delivery_mode: 'apache_vhost', install_script: 'echo vhost'
    }
  });
  assert.strictEqual(result.spec.vuln_app_install, null);
});

// ─── Done ───────────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
