/**
 * End-to-end integration simulation for the synthesize-challenge pipeline.
 *
 * Simulates the route handler in real-client-intake.js:synthesize-challenge
 * against the AZ Cyber Initiative fixture + hardcoded catalog rows matching
 * what migrations 013 (vm_template_catalog) and 012 (vuln_scripts) seed.
 *
 * Run with: node front-end/plugins/ciab/test/synthesize-integration.test.js
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { normalizeIntake } = require('../utils/intake-normalizer');
const { resolveTemplate } = require('../../../src/utils/vm-template-resolver');
const { resolveScriptsForVm } = require('../../../src/utils/vuln-script-resolver');

// Mirrors migration 013 seed rows (real cyberhub-node-5 inventory).
const templates = [
  { id: 't1', os_family: 'windows_server', os_name: 'Windows Server 2022', os_version: '2022', template_vmid: 1000, node: 'cyberhub-node-5', role_hints: ['dc','file','web','mail','backup','print'], preferred: true, is_active: true },
  { id: 't2', os_family: 'linux',          os_name: 'Rocky Linux',         os_version: null,    template_vmid: 1001, node: 'cyberhub-node-5', role_hints: ['web','file','db'], preferred: true, is_active: true },
  { id: 't3', os_family: 'windows_client', os_name: 'Windows 11',          os_version: '25H2',  template_vmid: 1002, node: 'cyberhub-node-5', role_hints: [], preferred: true, is_active: true },
  { id: 't4', os_family: 'linux',          os_name: 'Ubuntu',              os_version: null,    template_vmid: 1003, node: 'cyberhub-node-5', role_hints: ['web'], preferred: true, is_active: true },
  { id: 't5', os_family: 'linux',          os_name: 'Metasploitable 2',    os_version: null,    template_vmid: 1600, node: 'cyberhub-node-5', role_hints: [], preferred: false, is_active: true }
];

// Mirrors a subset of vuln_scripts rows (post-014 migration: script_type column present).
const scripts = [
  { id: 's1', slug: 'init-setup',     name: 'Bootstrap',               category: 'Initial Setup',    script_type: 'baseline',   os_target: 'windows', services_exposed: [],                     depends_on: [],             is_active: true },
  { id: 's2', slug: 'smb-baseline',   name: 'SMB (Standard-Secure)',   category: 'Network Services', script_type: 'baseline',   os_target: 'windows', services_exposed: ['445/SMB'],            depends_on: ['init-setup'], is_active: true },
  { id: 's3', slug: 'smb-config',     name: 'SMB (Null Session)',      category: 'Network Services', script_type: 'vulnerable', os_target: 'windows', services_exposed: ['445/SMB'],            depends_on: ['init-setup'], is_active: true },
  { id: 's4', slug: 'ssh-baseline',   name: 'OpenSSH (Standard)',      category: 'Network Services', script_type: 'baseline',   os_target: 'windows', services_exposed: ['22/SSH'],             depends_on: ['init-setup'], is_active: true },
  { id: 's5', slug: 'rdp-baseline',   name: 'RDP (Standard-Secure)',   category: 'Network Services', script_type: 'baseline',   os_target: 'windows', services_exposed: ['3389/RDP'],           depends_on: ['init-setup'], is_active: true },
  { id: 's6', slug: 'rdp-config',     name: 'RDP (NLA off)',           category: 'Network Services', script_type: 'vulnerable', os_target: 'windows', services_exposed: ['3389/RDP'],           depends_on: ['init-setup'], is_active: true },
  { id: 's7', slug: 'iis-config',     name: 'IIS Web Server',          category: 'Web Server',       script_type: 'vulnerable', os_target: 'windows', services_exposed: ['80/HTTP','443/HTTPS'], depends_on: ['init-setup'], is_active: true },
  { id: 's8', slug: 'life-artifacts', name: 'User Simulation',         category: 'User Simulation',  script_type: 'baseline',   os_target: 'windows', services_exposed: [],                     depends_on: ['init-setup'], is_active: true }
];

let passed = 0;
let failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); passed++; }
  catch (err) { console.log(`  ✗ ${name}`); console.log(`    ${err.message}`); failed++; }
}

console.log('\nsynthesize pipeline — AZ Cyber Initiative');

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'intake-az-cyber-initiative.json'), 'utf-8'));
const normalized = normalizeIntake(fixture);

// Resolve templates + scripts for each VM — mirrors the route handler.
const specVms = [];
const extraPhantoms = [];
const extraWarnings = [];
for (const vm of normalized.vms) {
  const match = resolveTemplate({ os_family: vm.os_family, os_version: vm.os_version, role: vm.role }, templates);
  if (!match) {
    extraPhantoms.push({ name: vm.name, os_family: vm.os_family });
    continue;
  }
  const { required, missing } = resolveScriptsForVm(vm, scripts);
  specVms.push({ name: vm.name, role: vm.role, os: match.os_name, template_vmid: match.template_vmid, template_match: match.match_type, services: vm.services, default_scripts: required, missing_scripts: missing });
  if (missing.length) extraWarnings.push({ code: 'script_missing', vm: vm.name, missing });
}

test('4 deployable Windows 11 VMs resolved with vmid 1002', () => {
  assert.strictEqual(specVms.length, 4);
  assert.ok(specVms.every(v => v.template_vmid === 1002), `all VMs should use Windows 11 (vmid 1002): ${JSON.stringify(specVms.map(v=>v.template_vmid))}`);
});

test('resolver picks smb-baseline over smb-config (baseline preferred)', () => {
  for (const v of specVms) {
    assert.ok(v.default_scripts.includes('smb-baseline'),
      `${v.name} should use smb-baseline, got: ${v.default_scripts.join(',')}`);
    assert.ok(!v.default_scripts.includes('smb-config'),
      `${v.name} should NOT use vulnerable smb-config; got: ${v.default_scripts.join(',')}`);
  }
});

test('2 macOS phantoms from normalizer remain as phantoms', () => {
  const mac = normalized.phantoms.filter(p => p.os_family === 'macos');
  assert.strictEqual(mac.length, 2);
});

test('no extra phantoms created by template resolver (windows_client has a template)', () => {
  assert.strictEqual(extraPhantoms.length, 0);
});

test('every deployable VM gets init-setup + smb-baseline', () => {
  for (const v of specVms) {
    assert.ok(v.default_scripts.includes('init-setup'),   `${v.name} missing init-setup`);
    assert.ok(v.default_scripts.includes('smb-baseline'), `${v.name} missing smb-baseline`);
  }
});

test('every workstation gets life-artifacts', () => {
  for (const v of specVms) {
    assert.ok(v.default_scripts.includes('life-artifacts'), `${v.name} missing life-artifacts`);
  }
});

test('no missing_scripts entries for AZ Cyber (SMB fully covered by catalog)', () => {
  for (const v of specVms) {
    assert.strictEqual(v.missing_scripts.length, 0, `${v.name} has missing scripts: ${JSON.stringify(v.missing_scripts)}`);
  }
});

test('caller opting into vulnerable type gets smb-config, not smb-baseline', () => {
  // Simulate an admin-driven "make this a challenge lab" call with prefer_type=vulnerable.
  const { resolveScriptsForVm } = require('../../../src/utils/vuln-script-resolver');
  const vm = { name: 'ws01', role: 'workstation', os_family: 'windows_client', os_version: null,
               services: ['SMB'], suggested_script_services: [{ service: 'SMB', version: null }] };
  const { required } = resolveScriptsForVm(vm, scripts, { prefer_type: 'vulnerable' });
  assert.ok(required.includes('smb-config'),   `should pick smb-config when admin prefers vulnerable; got: ${required.join(',')}`);
  assert.ok(!required.includes('smb-baseline'), `should NOT pick smb-baseline when admin prefers vulnerable`);
});

test('template_match = family_only (version not specified for workstations)', () => {
  for (const v of specVms) {
    assert.strictEqual(v.template_match, 'family_only', `${v.name} got match=${v.template_match}`);
  }
});

test('normalizer warnings still present for SaaS mail + web + DC unknown + VPN + OS gap', () => {
  const codes = normalized.warnings.map(w => w.code);
  assert.ok(codes.includes('role_saas'), 'expected role_saas');
  assert.ok(codes.includes('role_unknown'), 'expected role_unknown');
  assert.ok(codes.includes('vpn_edge'), 'expected vpn_edge');
  assert.ok(codes.includes('os_count_gap'), 'expected os_count_gap');
});

console.log('\nsynthesize pipeline — happy path with real server');

// Construct a richer fixture: small business with a DC
const richFixture = {
  schema_version: '1.0',
  cover_name: 'Acme Dental',
  sections: {
    company: { cover_name: 'Acme Dental', industry: 'Healthcare', frameworks: ['HIPAA'] },
    network: {
      workstation_count: '5', laptop_count: '0', server_count: '1',
      os_count_win_server: '1', os_count_win_client: '5',
      role_dc: 'yes', role_file: 'yes', role_mail: 'no', role_web: 'no',
      services: ['SMB', 'RDP', 'SSH'], domain_mode: 'AD'
    },
    wireless: {}, endpoint: {}, email_web: {}, access: {}, data: {}, vuln_audit: {}, ig1: {}, notes: {}
  }
};
const rich = normalizeIntake(richFixture);
const richSpec = [];
for (const vm of rich.vms) {
  const match = resolveTemplate({ os_family: vm.os_family, os_version: vm.os_version, role: vm.role }, templates);
  if (!match) continue;
  const { required } = resolveScriptsForVm(vm, scripts);
  richSpec.push({ name: vm.name, role: vm.role, os: match.os_name, template_vmid: match.template_vmid, default_scripts: required });
}

test('Acme Dental synthesizes 5 workstations + 1 DC server', () => {
  const workstations = richSpec.filter(v => v.role === 'workstation');
  const dc = richSpec.filter(v => v.role === 'dc');
  assert.strictEqual(workstations.length, 5, `expected 5 workstations, got ${workstations.length}`);
  assert.strictEqual(dc.length, 1, `expected 1 DC server, got ${dc.length}`);
});

test('Acme DC uses Windows Server 2022 (vmid 1000, role_hints includes dc)', () => {
  const dc = richSpec.find(v => v.role === 'dc');
  assert.ok(dc);
  assert.strictEqual(dc.template_vmid, 1000, `expected vmid 1000 for DC, got ${dc.template_vmid}`);
});

test('Acme DC gets init-setup + smb-baseline (baseline preferred, role-scoped services)', () => {
  // ROLE_SERVICE_HINTS['dc'] = ['SMB','LDAP','DNS'] so SSH/RDP (endpoint-class) don't land on the DC.
  const dc = richSpec.find(v => v.role === 'dc');
  assert.ok(dc.default_scripts.includes('init-setup'),   `DC missing init-setup; got: ${dc.default_scripts.join(',')}`);
  assert.ok(dc.default_scripts.includes('smb-baseline'), `DC missing smb-baseline; got: ${dc.default_scripts.join(',')}`);
  assert.ok(!dc.default_scripts.includes('smb-config'),  `DC should NOT pick vulnerable smb-config by default; got: ${dc.default_scripts.join(',')}`);
});

test('Acme workstations get init-setup + smb-baseline + life-artifacts (workstation-class services)', () => {
  // workstationServices is filtered to ['SMB','RDP'] in deriveVmList; RDP is also in suggestions,
  // so baseline-preferred resolver should pick rdp-baseline (not rdp-config).
  const ws = richSpec.filter(v => v.role === 'workstation');
  for (const w of ws) {
    assert.ok(w.default_scripts.includes('smb-baseline'), `${w.name} missing smb-baseline; got: ${w.default_scripts.join(',')}`);
    assert.ok(w.default_scripts.includes('rdp-baseline'), `${w.name} missing rdp-baseline; got: ${w.default_scripts.join(',')}`);
    assert.ok(w.default_scripts.includes('life-artifacts'), `${w.name} missing life-artifacts`);
  }
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
