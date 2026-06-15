/**
 * Standalone test runner for ai/scan-documents.
 * Run: node front-end/modules/crucible/plugins/ciab/test/scan-documents.test.js
 */

const assert = require('assert');
const {
  generateScanDocuments,
  generateNmap,
  generateNessus,
  generateZap,
  scannableAssets,
  buildHostPorts
} = require('../ai/scan-documents');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); passed++; }
  catch (err) { console.log(`  ✗ ${name}\n    ${err.message}`); failed++; }
}

// Fixture: a small profile with a mix of asset roles
const FIXTURE = {
  industry: 'healthcare',
  assets: [
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2022', ip: '10.10.5.10',
      services: ['445/SMB', '3389/RDP', '88/Kerberos', '389/LDAP'] },
    { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', ip: '10.10.5.20',
      services: ['80/HTTP', '443/HTTPS', '22/SSH'] },
    { hostname: 'WS-EMP-01', role: 'workstation', os: 'Windows 11', ip: '10.10.5.100',
      services: [] },
    { hostname: 'PRN-01', role: 'peripheral', os: 'Embedded', ip: '10.10.5.200',
      services: ['9100/IPP'] }
  ]
};

console.log('\nscannableAssets — filters to servers + network');
test('excludes workstations and peripherals', () => {
  const s = scannableAssets(FIXTURE);
  assert.strictEqual(s.length, 2);
  assert.deepStrictEqual(s.map(a => a.hostname).sort(), ['DC-01', 'WEB-01']);
});

console.log('\nbuildHostPorts — every port traces back to declared service');
test('DC-01 emits exactly the SMB/RDP/Kerberos/LDAP ports', () => {
  const ports = buildHostPorts(FIXTURE.assets[0]);
  const portNums = ports.map(p => p.port).sort((a, b) => a - b);
  assert.deepStrictEqual(portNums, [88, 389, 445, 3389]);
});
test('WEB-01 emits HTTP/HTTPS/SSH ports', () => {
  const ports = buildHostPorts(FIXTURE.assets[1]);
  const portNums = ports.map(p => p.port).sort((a, b) => a - b);
  assert.deepStrictEqual(portNums, [22, 80, 443]);
});
test('asset with no services emits no ports', () => {
  assert.strictEqual(buildHostPorts(FIXTURE.assets[2]).length, 0);
});

console.log('\ngenerateNmap');
test('produces a Markdown report with profile-declared ports only', () => {
  const md = generateNmap({ profileData: FIXTURE, companyName: 'TestCo', domain: 'test.local' });
  assert.match(md, /^# TestCo/);
  assert.match(md, /Nmap scan report/);
  // Declared ports show up in the port table
  assert.match(md, /^445\/tcp/m);
  assert.match(md, /^3389\/tcp/m);
  assert.match(md, /^80\/tcp/m);
  // Workstation/peripheral are EXCLUDED — no port 9100 etc.
  assert.ok(!md.includes('WS-EMP-01'), 'workstation should not appear in scan');
  assert.ok(!md.includes('9100/tcp'), 'peripheral printer port should not appear');
});
test('only includes ports the assets declared (no inventing 22 on DC-01)', () => {
  const md = generateNmap({ profileData: FIXTURE, companyName: 'TestCo', domain: 'test.local' });
  // DC-01 declared 445/3389/88/389. It did NOT declare port 22 — so no SSH on DC-01 in scan.
  const dcSection = md.slice(md.indexOf('DC-01'), md.indexOf('WEB-01'));
  assert.ok(!dcSection.includes('22/tcp'), 'DC-01 must not show SSH (not declared)');
});
test('vuln scripts trace back to declared services (MS17-010 on SMB host)', () => {
  const md = generateNmap({ profileData: FIXTURE, companyName: 'TestCo', domain: 'test.local' });
  assert.match(md, /smb-vuln-ms17-010/);
  assert.match(md, /VULNERABLE/);
});
test('hostname FQDN includes domain', () => {
  const md = generateNmap({ profileData: FIXTURE, companyName: 'TestCo', domain: 'test.local' });
  assert.match(md, /DC-01\.test\.local/);
});
test('declared IP is used', () => {
  const md = generateNmap({ profileData: FIXTURE, companyName: 'TestCo' });
  assert.match(md, /\(10\.10\.5\.10\)/);
});

console.log('\ngenerateNessus');
test('emits findings only for declared services', () => {
  const xml = generateNessus({ profileData: FIXTURE, companyName: 'TestCo' });
  // DC-01 has SMB declared → MS17-010 should appear
  assert.match(xml, /MS17-010/);
  // DC-01 has RDP declared → BlueKeep should appear
  assert.match(xml, /BlueKeep/);
});
test('emits service-detection info finding for every declared port', () => {
  const xml = generateNessus({ profileData: FIXTURE, companyName: 'TestCo' });
  // Should have several pluginID="22964" (Service Detection) findings — one per port
  const matches = xml.match(/pluginID="22964"/g);
  assert.ok(matches && matches.length >= 6, `expected ≥6 service-detection findings, got ${matches?.length || 0}`);
});
test('omits hosts with no declared services from findings', () => {
  const xml = generateNessus({ profileData: FIXTURE, companyName: 'TestCo' });
  assert.ok(!xml.includes('WS-EMP-01'), 'workstation should not appear in Nessus output');
});

console.log('\ngenerateZap');
test('emits findings only when web-server asset exists', () => {
  const html = generateZap({ profileData: FIXTURE, companyName: 'TestCo', domain: 'test.local' });
  assert.match(html, /SQL Injection/);
  assert.match(html, /WEB-01\.test\.local/);
});
test('emits empty report when no web hosts', () => {
  const noWebFixture = { assets: [FIXTURE.assets[0]] }; // DC-01 only, no port 80/443
  const html = generateZap({ profileData: noWebFixture, companyName: 'TestCo' });
  assert.match(html, /No web-server assets/);
  assert.ok(!html.includes('SQL Injection'), 'should not include alerts when no web hosts');
});

console.log('\ngenerateScanDocuments — bundle');
test('produces 3 documents by default', () => {
  const docs = generateScanDocuments({ profileData: FIXTURE, companyName: 'TestCo', domain: 'test.local' });
  assert.strictEqual(docs.length, 3);
  assert.deepStrictEqual(docs.map(d => d.type).sort(), ['nessus', 'nmap', 'zap']);
});
test('respects types filter', () => {
  const docs = generateScanDocuments({ profileData: FIXTURE, companyName: 'TestCo', types: ['nmap'] });
  assert.strictEqual(docs.length, 1);
  assert.strictEqual(docs[0].type, 'nmap');
});
test('filenames are slugified company name', () => {
  const docs = generateScanDocuments({ profileData: FIXTURE, companyName: 'Test Co. LLC!', types: ['nmap'] });
  assert.match(docs[0].filename, /^test_co__llc__nmap_scan\.md$/);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
