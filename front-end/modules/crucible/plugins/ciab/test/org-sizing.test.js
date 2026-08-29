/**
 * test/org-sizing.test.js — the band matrix + the plausibility validator.
 *
 * These are the assertions that make the stakeholder's two named cases
 * structurally impossible rather than merely unlikely:
 *   "a small non-profit wouldn't have a Domain Controller"
 *   "a small business wouldn't have multiple file servers and multiple DCs"
 */

const test = require('node:test');
const assert = require('node:assert');

const { computeOrgSizing, normalizeDelivery, bandOf, SECTOR_EMPLOYEE_BANDS } = require('../ai/profile/org-sizing');
const { buildServerRoster, pickEmployeeCount } = require('../ai/profile/prompts');
const { validateSizing } = require('../ai/profile/validators');

const SECTORS = ['SMB', 'NonProfit', 'Utility_IT_OT', 'K12', 'Library'];
const DELIVERIES = ['On-Premises', 'On-Prem', 'Hybrid', 'Cloud', 'Mostly Cloud'];
const SIZES = [8, 12, 22, 34, 55, 78, 120, 160, 260, 420];
const SEEDS = ['RUN_A1', 'RUN_B2', 'RUN_C3', 'RUN_D4', 'RUN_E5'];

const roster = (sector, emp, delivery, seed) =>
  buildServerRoster(seed, { clientType: sector, employeeCount: emp, delivery, maturity: 'Intermediate' });
const countDc = (r) => r.filter(s => /domain controller/i.test(s.role)).length;
const countFs = (r) => r.filter(s => /file server/i.test(s.role)).length;

// ─── determinism ──────────────────────────────────────────────────────────

test('same seed produces an identical headcount and roster', () => {
  for (const sector of SECTORS) {
    const seedObj = { run_id: 'RUN_STABLE', employees: { min: 10, max: 400 } };
    const a = pickEmployeeCount(seedObj, sector);
    const b = pickEmployeeCount(seedObj, sector);
    assert.strictEqual(a, b, `${sector} headcount must be reproducible`);

    const r1 = JSON.stringify(roster(sector, a, 'Hybrid', 'RUN_STABLE'));
    const r2 = JSON.stringify(roster(sector, a, 'Hybrid', 'RUN_STABLE'));
    assert.strictEqual(r1, r2, `${sector} roster must be reproducible`);
  }
});

test('no Math.random or Date in the sizing path', () => {
  const fs = require('fs');
  // Strip comments first — these files deliberately NAME the calls they
  // removed, and the prose explaining the fix must not fail the check.
  const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const f of ['org-sizing.js', 'hash.js']) {
    const src = stripComments(fs.readFileSync(require.resolve(`../ai/profile/${f}`), 'utf8'));
    assert.ok(!/Math\.random\(/.test(src), `${f} must not use Math.random`);
    assert.ok(!/Date\.now\(/.test(src), `${f} must not use Date.now`);
  }
});

test('headcount draw is log-skewed, so small orgs are common', () => {
  // Uniform over [25,200] puts the median at ~112 — a mid-market company.
  // Log-uniform must land it well below that.
  const draws = [];
  for (let i = 0; i < 600; i++) {
    draws.push(pickEmployeeCount({ run_id: 'RUN_DIST_' + i, employees: { min: 25, max: 200 } }, 'SMB'));
  }
  draws.sort((a, b) => a - b);
  const median = draws[draws.length >> 1];
  assert.ok(median < 95, `median headcount ${median} should be well below the band midpoint of 112`);
  assert.ok(draws.every(d => d >= 25 && d <= 200), 'every draw stays inside the band');
});

// ─── delivery normalization ───────────────────────────────────────────────

test('every delivery label the UI offers maps to exactly one class', () => {
  assert.strictEqual(normalizeDelivery('On-Premises'), 'onprem');
  assert.strictEqual(normalizeDelivery('On-Prem'), 'onprem');
  assert.strictEqual(normalizeDelivery('Hybrid'), 'hybrid');
  assert.strictEqual(normalizeDelivery('Cloud'), 'cloud');
  // The old startsWith('cloud') check failed on this one and silently
  // treated the org as Hybrid, handing it an on-prem domain.
  assert.strictEqual(normalizeDelivery('Mostly Cloud'), 'cloud');
  assert.strictEqual(normalizeDelivery(undefined), 'hybrid');
});

// ─── the stakeholder's two named cases ────────────────────────────────────

test('a small non-profit never gets a domain controller', () => {
  for (const delivery of DELIVERIES) {
    for (const emp of [6, 10, 14, 18, 24, 30]) {
      for (const seed of SEEDS) {
        const r = roster('NonProfit', emp, delivery, seed);
        assert.strictEqual(countDc(r), 0,
          `NonProfit/${emp}/${delivery}/${seed} produced ${countDc(r)} DC(s)`);
      }
    }
  }
});

test('no organization of any size or sector gets more than one file server', () => {
  for (const sector of SECTORS) {
    for (const delivery of DELIVERIES) {
      for (const emp of SIZES) {
        for (const seed of SEEDS) {
          const fs = countFs(roster(sector, emp, delivery, seed));
          assert.ok(fs <= 1, `${sector}/${emp}/${delivery}/${seed} produced ${fs} file servers`);
        }
      }
    }
  }
});

test('a small business never gets two domain controllers', () => {
  for (const delivery of DELIVERIES) {
    for (const emp of [12, 22, 34, 45]) {
      for (const seed of SEEDS) {
        const dc = countDc(roster('SMB', emp, delivery, seed));
        assert.ok(dc <= 1, `SMB/${emp}/${delivery}/${seed} produced ${dc} DCs`);
      }
    }
  }
});

test('a second domain controller never appears below 60 users, in any sector', () => {
  for (const sector of SECTORS) {
    for (const delivery of DELIVERIES) {
      for (const emp of [8, 12, 22, 34, 55]) {
        for (const seed of SEEDS) {
          const dc = countDc(roster(sector, emp, delivery, seed));
          assert.ok(dc <= 1, `${sector}/${emp}/${delivery}/${seed} produced ${dc} DCs below 60 users`);
        }
      }
    }
  }
});

// ─── delivery is honored in every branch, not just two ────────────────────

test('cloud-first orgs get no on-prem domain, in every sector', () => {
  for (const sector of SECTORS) {
    for (const emp of [12, 34, 55]) {
      for (const seed of SEEDS) {
        // Utility and K12 branches previously ignored delivery entirely:
        // measured 100% DC and 85% two-DCs even with delivery=Cloud.
        const dc = countDc(roster(sector, emp, 'Cloud', seed));
        assert.strictEqual(dc, 0, `${sector}/${emp}/Cloud/${seed} produced ${dc} DC(s)`);
      }
    }
  }
});

test('the on-prem override cannot defeat a sector AD floor', () => {
  // Previously On-Prem dropped the threshold to a flat 12 for every sector,
  // which is how 97% of on-prem non-profits ended up with Active Directory.
  for (const seed of SEEDS) {
    assert.strictEqual(countDc(roster('NonProfit', 14, 'On-Premises', seed)), 0);
    assert.strictEqual(countDc(roster('SMB', 12, 'On-Premises', seed)), 0);
  }
});

// ─── band matrix ──────────────────────────────────────────────────────────

test('band matrix: every profile stays inside its plausible envelope', () => {
  let checked = 0;
  for (const sector of SECTORS) {
    for (const delivery of DELIVERIES) {
      for (const emp of SIZES) {
        for (const seed of SEEDS) {
          const sizing = computeOrgSizing({ clientType: sector, employeeCount: emp, delivery, maturity: 'Intermediate', runId: seed });
          const r = roster(sector, emp, delivery, seed);

          assert.ok(countDc(r) <= sizing.identity.max_dcs,
            `${sector}/${emp}/${delivery}: ${countDc(r)} DCs > cap ${sizing.identity.max_dcs}`);
          assert.ok(r.filter(s => s.role_short !== 'nas').length <= sizing.servers.max_total,
            `${sector}/${emp}/${delivery}: ${r.length} servers > cap ${sizing.servers.max_total}`);

          // Endpoint ratio is the check that catches the old constant-128 bug.
          const ratio = sizing.endpoints.workstations / emp;
          assert.ok(ratio >= 0.5 && ratio <= 3.0,
            `${sector}/${emp}: endpoint ratio ${ratio.toFixed(2)} outside [0.5, 3.0]`);

          assert.ok([24, 23, 22].includes(sizing.network.subnet_mask));
          assert.ok(sizing.network.vlan_count >= 1 && sizing.network.vlan_count <= 14);
          assert.ok(sizing.stakeholder_count >= 3 && sizing.stakeholder_count <= 9);
          checked++;
        }
      }
    }
  }
  assert.ok(checked >= 1000, `expected a wide matrix, checked ${checked}`);
});

test('thresholds that should not fire early, do not', () => {
  for (const seed of SEEDS) {
    const small = computeOrgSizing({ clientType: 'SMB', employeeCount: 30, delivery: 'Hybrid', maturity: 'Intermediate', runId: seed });
    assert.strictEqual(small.network.l3_core, false, 'no L3 core at 30 employees');
    assert.strictEqual(small.security.siem, false, 'no in-house SIEM at 30 employees');
    assert.strictEqual(small.staffing.has_security, false, 'no security hire at 30 employees');
    assert.strictEqual(small.network.dmz, false, 'no DMZ at 30 employees');
    assert.ok(['micro', 'smb'].includes(small.security.firewall_tier));
  }
});

test('sector employee bands are sane and every sector has one', () => {
  for (const sector of SECTORS) {
    const band = SECTOR_EMPLOYEE_BANDS[sector];
    assert.ok(band, `${sector} needs an employee band`);
    assert.ok(band.min >= 1 && band.max > band.min);
  }
  assert.strictEqual(bandOf(10), 'A');
  assert.strictEqual(bandOf(30), 'B');
  assert.strictEqual(bandOf(80), 'C');
});

// ─── validateSizing ───────────────────────────────────────────────────────

function sizingFor(sector, emp, delivery = 'Hybrid') {
  return computeOrgSizing({ clientType: sector, employeeCount: emp, delivery, maturity: 'Intermediate', runId: 'RUN_V' });
}

test('validateSizing strips a domain controller from a serverless org', () => {
  const sizing = sizingFor('NonProfit', 12);
  const payload = {
    it_environment: { servers: [{ hostname: 'dc-01', role: 'Domain Controller' }, { hostname: 'nas-01', role: 'NAS' }] },
    network: {}
  };
  const out = validateSizing(payload, { sizing, employeeCount: 12 });
  assert.strictEqual(out.payload.it_environment.servers.length, 1);
  assert.ok(out.review.some(r => r.id === 'S-01'), 'S-01 must fire');
});

test('validateSizing trims extra domain controllers and file servers', () => {
  const sizing = sizingFor('SMB', 40);
  const payload = {
    it_environment: {
      servers: [
        { hostname: 'dc-01', role: 'Domain Controller' },
        { hostname: 'dc-02', role: 'Secondary Domain Controller' },
        { hostname: 'fs-01', role: 'File Server' },
        { hostname: 'fs-02', role: 'File Server' }
      ]
    },
    network: {}
  };
  const out = validateSizing(payload, { sizing, employeeCount: 40 });
  const servers = out.payload.it_environment.servers;
  assert.strictEqual(servers.filter(s => /domain controller/i.test(s.role)).length, sizing.identity.max_dcs);
  assert.strictEqual(servers.filter(s => /file server/i.test(s.role)).length, 1);
  assert.ok(out.review.some(r => r.id === 'S-02'));
  assert.ok(out.review.some(r => r.id === 'S-03'));
});

test('validateSizing flags an enterprise stack on a tiny org', () => {
  const sizing = sizingFor('NonProfit', 12);
  const payload = {
    it_environment: {
      servers: [],
      endpoint_protection: { product: 'CrowdStrike Falcon' },
      saas: [{ name: 'Splunk SIEM' }]
    },
    network: { firewall: { vendor: 'Palo Alto Networks', model: 'PA-820' } }
  };
  const out = validateSizing(payload, { sizing, employeeCount: 12 });
  assert.ok(out.review.some(r => r.id === 'P-01'), 'SIEM must be flagged');
  assert.ok(out.review.some(r => r.id === 'P-02'), 'enterprise EDR must be flagged');
  assert.ok(out.review.some(r => r.id === 'P-03'), 'oversized firewall must be flagged');
});

test('validateSizing catches an implausible endpoint ratio and duplicate IPs', () => {
  const sizing = sizingFor('SMB', 28);
  const payload = {
    it_environment: {
      servers: [],
      endpoints: { windows_laptops: 60, windows_desktops: 68, shared_kiosks: 0, macos: 0, mobile: 0 }
    },
    network: { assets: [{ hostname: 'a', ip: '10.0.0.5' }, { hostname: 'b', ip: '10.0.0.5' }] }
  };
  const out = validateSizing(payload, { sizing, employeeCount: 28 });
  assert.ok(out.review.some(r => r.id === 'E-01'), 'the old 128-endpoints-for-28-staff case must be flagged');
  assert.ok(out.review.some(r => r.id === 'N-01'), 'duplicate IPs must be flagged');
});

test('validateSizing catches AD language in a profile with no domain', () => {
  const sizing = sizingFor('NonProfit', 12);
  const payload = {
    it_environment: { servers: [], patch_management: { method: 'Group Policy software installation' } },
    network: {}
  };
  const out = validateSizing(payload, { sizing, employeeCount: 12 });
  assert.ok(out.review.some(r => r.id === 'C-01'));
});

test('validateSizing leaves a plausible profile completely alone', () => {
  const sizing = sizingFor('SMB', 85);
  const payload = {
    it_environment: {
      servers: [{ hostname: 'dc-01', role: 'Domain Controller' }, { hostname: 'fs-01', role: 'File Server' }],
      endpoints: { windows_laptops: 60, windows_desktops: 30, shared_kiosks: 0, macos: 0, mobile: 0 },
      endpoint_protection: { product: 'Sophos Intercept X' }
    },
    network: { firewall: { vendor: 'Fortinet', model: 'FortiGate 60F' }, assets: [] }
  };
  const out = validateSizing(payload, { sizing, employeeCount: 85 });
  assert.deepStrictEqual(out.review, [], `expected no findings, got ${JSON.stringify(out.review)}`);
});
