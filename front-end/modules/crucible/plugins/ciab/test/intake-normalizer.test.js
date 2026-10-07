/**
 * Standalone test runner for intake-normalizer.
 * Run with: node front-end/plugins/ciab/test/intake-normalizer.test.js
 *
 * Uses Node's built-in assert module — no test framework required.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { normalizeIntake, reconcileOsCounts, resolveRoleOrSaaS } = require('../utils/intake-normalizer');

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

console.log('\nreconcileOsCounts');

test('no gap returns declared unchanged', () => {
  const r = reconcileOsCounts({ windows_client: 3, macos: 0, linux: 0, other: 0, windows_server: 0 }, 3, ['windows_client', 'linux'], 'windows_client');
  assert.strictEqual(r.gap, 0);
  assert.strictEqual(r.counts.windows_client, 3);
});

test('gap fills proportionally among fillable families', () => {
  const r = reconcileOsCounts(
    { windows_client: 1, macos: 2, linux: 0, other: 0, windows_server: 0 },
    6,
    ['windows_client', 'linux'],
    'windows_client'
  );
  // gap=3, only fillable declared is windows_client (1), so all 3 go to win_client. macos untouched.
  assert.strictEqual(r.gap, 3);
  assert.strictEqual(r.counts.windows_client, 4);
  assert.strictEqual(r.counts.macos, 2);
});

test('gap routes to defaultFillable if no fillable declared', () => {
  const r = reconcileOsCounts(
    { windows_client: 0, macos: 2, linux: 0, other: 0, windows_server: 0 },
    5,
    ['windows_client', 'linux'],
    'windows_client'
  );
  // gap=3, no fillable declared, default=windows_client
  assert.strictEqual(r.gap, 3);
  assert.strictEqual(r.counts.windows_client, 3);
  assert.strictEqual(r.counts.macos, 2);
});

console.log('\nresolveRoleOrSaaS');

test('mail=yes + 0 servers + google → saas', () => {
  const r = resolveRoleOrSaaS('mail', {
    sections: { network: { role_mail: 'yes', server_count: '0' }, email_web: { email_provider: 'Google Workspace' } }
  });
  assert.strictEqual(r.status, 'saas');
  assert.match(r.reason, /SaaS/i);
});

test('web=yes + 0 servers → saas by default', () => {
  const r = resolveRoleOrSaaS('web', {
    sections: { network: { role_web: 'yes', server_count: '0' }, email_web: {} }
  });
  assert.strictEqual(r.status, 'saas');
});

test('dc=yes + servers > 0 → deploy', () => {
  const r = resolveRoleOrSaaS('dc', {
    sections: { network: { role_dc: 'yes', server_count: '2' } }
  });
  assert.strictEqual(r.status, 'deploy');
});

test('role=unknown + 0 servers → skip (with reason)', () => {
  const r = resolveRoleOrSaaS('dc', {
    sections: { network: { role_dc: 'unknown', server_count: '0' } }
  });
  assert.strictEqual(r.status, 'skip');
  assert.ok(r.reason);
});

test('role=no → skip silently', () => {
  const r = resolveRoleOrSaaS('file', {
    sections: { network: { role_file: 'no', server_count: '0' } }
  });
  assert.strictEqual(r.status, 'skip');
  assert.strictEqual(r.reason, null);
});

console.log('\nnormalizeIntake — AZ Cyber Initiative fixture');

const fixturePath = path.join(__dirname, 'fixtures', 'intake-az-cyber-initiative.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
const out = normalizeIntake(fixture);

test('produces 4 deployable Windows workstation VMs', () => {
  const ws = out.vms.filter(v => v.os_family === 'windows_client');
  assert.strictEqual(ws.length, 4, `expected 4 Windows workstations, got ${ws.length}`);
});

test('produces 2 macOS phantom assets (no template)', () => {
  const macPhantoms = out.phantoms.filter(p => p.os_family === 'macos');
  assert.strictEqual(macPhantoms.length, 2, `expected 2 macOS phantoms, got ${macPhantoms.length}`);
});

test('produces 0 server VMs (server_count=0, all roles SaaS/skip)', () => {
  const servers = out.vms.filter(v => !['workstation', 'laptop'].includes(v.role));
  assert.strictEqual(servers.length, 0, `expected 0 server VMs, got ${servers.length}`);
});

test('windows workstations have SMB in services', () => {
  const ws = out.vms.filter(v => v.os_family === 'windows_client');
  assert.ok(ws.every(v => v.services.includes('SMB')), 'every Windows workstation should have SMB');
});

test('warning surfaced: mail resolved to SaaS', () => {
  assert.ok(out.warnings.some(w => w.code === 'role_saas' && /MAIL/.test(w.msg)), 'expected MAIL SaaS warning');
});

test('warning surfaced: web resolved to SaaS', () => {
  assert.ok(out.warnings.some(w => w.code === 'role_saas' && /WEB/.test(w.msg)), 'expected WEB SaaS warning');
});

test('warning surfaced: DC unknown (not deployed)', () => {
  assert.ok(out.warnings.some(w => w.code === 'role_unknown' && /DC/.test(w.msg)), 'expected DC unknown warning');
});

test('warning surfaced: VPN treated as edge appliance', () => {
  assert.ok(out.warnings.some(w => w.code === 'vpn_edge'), 'expected VPN edge warning');
});

test('warning surfaced: OS count gap reconciled', () => {
  assert.ok(out.warnings.some(w => w.code === 'os_count_gap'), 'expected OS count gap warning');
});

test('cover_name preserved', () => {
  assert.strictEqual(out.cover_name, 'AZ Cyber Initiative');
});

test('notes free text preserved', () => {
  assert.ok(out.notes.includes('Website Vulnerabilities'), 'notes should carry through');
});

console.log('\nnormalizeIntake — schema v1.1 (endpoint_count replaces ws/laptop)');

// Same client, corrected intake: 3 endpoints (1 Win + 2 mac), no double-count.
const v11Fixture = {
  schema_version: '1.1',
  cover_name: 'AZ Cyber Initiative (v1.1)',
  sections: {
    company: { cover_name: 'AZ Cyber Initiative', frameworks: ['NIST-CSF'] },
    network: {
      endpoint_count: '3',
      server_count: '0',
      os_count_win_server: '0', os_count_win_client: '1',
      os_count_linux: '0', os_count_macos: '2', os_count_other: '0',
      role_dc: 'unknown', role_file: 'no', role_mail: 'yes', role_web: 'yes',
      role_db: 'no', role_backup: 'unknown', role_print: 'no',
      services: ['SMB', 'HTTP', 'VPN']
    },
    wireless: {}, endpoint: {}, email_web: { email_provider: 'Google Workspace' },
    access: {}, data: {}, vuln_audit: {}, ig1: {}, notes: {}
  }
};
const v11 = normalizeIntake(v11Fixture);

test('v1.1: produces 1 deployable Windows workstation (not 4)', () => {
  const ws = v11.vms.filter(v => v.os_family === 'windows_client');
  assert.strictEqual(ws.length, 1, `expected 1 Windows workstation, got ${ws.length}`);
});

test('v1.1: produces 2 macOS phantoms', () => {
  const phantoms = v11.phantoms.filter(p => p.os_family === 'macos');
  assert.strictEqual(phantoms.length, 2);
});

test('v1.1: no os_count_gap warning (counts reconcile cleanly)', () => {
  assert.ok(!v11.warnings.some(w => w.code === 'os_count_gap'),
    `should not warn about gap: ${JSON.stringify(v11.warnings.filter(w=>w.code==='os_count_gap'))}`);
});

test('v1.1: SaaS warnings still fire for mail + web', () => {
  const codes = v11.warnings.map(w => w.code);
  assert.ok(codes.filter(c => c === 'role_saas').length >= 2, 'expected 2+ role_saas warnings');
});

test('legacy (v1.0) intake with endpoint_count=0 still falls back to ws+laptop', () => {
  // Sanity: the AZ Cyber fixture has no endpoint_count — original behavior preserved.
  assert.strictEqual(out.deviceTotal, 6, `legacy fixture should still compute deviceTotal=6, got ${out.deviceTotal}`);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
