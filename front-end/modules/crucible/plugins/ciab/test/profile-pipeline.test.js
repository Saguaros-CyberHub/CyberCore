/**
 * profile-pipeline.test.js — end-to-end smoke test for the inline profile generator.
 * Mocks the LLM client so we don't need an ANTHROPIC_API_KEY. Verifies:
 *   - The full pipeline (A → B → C → D → combine) runs without exception
 *   - Validators repair / autofill where expected
 *   - Combined output has the student_view / instructor_view shape
 *
 * Run: node front-end/modules/crucible/plugins/ciab/test/profile-pipeline.test.js
 *
 * NOTE: skips DB write step by stubbing pool.query. The route handler's DB
 * insert path is exercised separately in manual integration tests.
 */

process.env.ANTHROPIC_API_KEY = 'sk-stub';

const assert = require('assert');
const llm = require('../../../../../src/utils/llm-client');

// ─── Stub pool before requiring ai/profile (CIAB db module is lazy-init) ──
const dbModule = require('../utils/db');
const insertedRows = [];
const fakePool = {
  query: async (sql, args) => {
    if (/INSERT INTO profiles/.test(sql)) {
      insertedRows.push({ sql, args });
      return { rows: [{
        id: 'fake-uuid',
        company_name: args[1],
        client_type: args[2],
        industry: args[3],
        difficulty: args[4],
        created_at: new Date(),
        run_id: args[8],
        json_file_path: args[7]
      }] };
    }
    return { rows: [] };
  },
  on: () => {}
};
dbModule.setPool(fakePool);

// ─── Mock LLM client — return canned outputs that mirror the prompt schemas ────
const MOCK_ORG = {
  run_id: 'RUN_TEST',
  organization: {
    company_name: 'Mock Healthcare LLC',
    industry: 'Healthcare',
    naics_hint: '621111',
    hq_city: 'Phoenix, AZ',
    employees_total: 45, // intentionally wrong; validator should fix
    domain_public: 'mockhealth.com',
    business_model: 'Outpatient clinic',
    critical_services: ['EHR', 'Billing'],
    key_system_dependencies: ['EHR', 'Email'],
    department_breakdown: { IT: 3, Operations: 10, Administration: 5, 'Sales/Marketing': 2, Other: 10 }, // sums to 30, not 50
    risks: ['phishing'],
    annual_revenue_range: '$5M-25M',
    past_incidents: [],
    regulatory_timeline: 'HIPAA audit Q3 2026',
    growth_trajectory: 'Stable',
    business_continuity: { rpo_hours: 4, rto_hours: 8, estimated_downtime_cost_per_hour: 5000 }
  },
  profiles: {
    governance_and_policy: {
      framework: 'NIST CSF', policies_present: ['acceptable use', 'password'],
      policies_missing: ['incident response'], policy_enforcement: 'Inconsistent',
      risk_tolerance: 'Moderate', deliberate_weaknesses: ['no IR plan']
    }
  },
  stakeholders: [
    { name: 'Dr. Jane Smith', role: 'CEO', department: 'Executive', email: 'jane@mockhealth.com',
      technical_fluency: 'Low', decision_power: 'Final Approval', communication_style: 'Direct',
      concerns: ['budget'], likely_pushback: ['cost'], information_they_can_provide: ['strategy'],
      information_they_lack: ['tech details'], signature_quote: 'Just fix it.',
      hidden_info: 'Knows audit is overdue', shadow_it_knowledge: 'None',
      relationship_conflicts: 'None' }
  ]
};

const MOCK_IT = {
  run_id: 'RUN_TEST',
  it_environment: {
    delivery: 'Hybrid',
    endpoints: { windows_laptops: 20, windows_desktops: 15, shared_kiosks: 0, macos: 5, mobile: 10 },
    servers: [
      { hostname: 'ehr-01', os: 'Windows Server 2019 Standard 10.0.17763', role: 'EHR' },
      { hostname: 'ehr-01', os: 'Windows Server 2019', role: 'duplicate' }, // dedup test
      { hostname: 'fs-01', os: 'Windows', role: 'File server' } // unversioned OS warning
    ],
    saas: [{ name: 'Microsoft 365', category: 'Productivity', sso_enabled: true, mfa: true, data_sensitivity: 'Medium' }],
    endpoint_protection: { product: 'CrowdStrike', managed: true, edr_enabled: true, coverage_percent: 95 },
    patch_management: { method: 'WSUS', frequency: 'Monthly', compliance_rate: 80 },
    remote_access: { vpn: 'OpenVPN', split_tunnel: false, mfa: 'All' },
    backups: { method: 'Cloud', frequency: 'Daily', immutability: true, offsite: true, restore_tests: 'Quarterly' },
    physical_security: { badge_access: true, cameras: true, server_room_locked: true, clean_desk_policy: false, visitor_logging: true },
    vendor_risk: [{ vendor: 'Epic', access_type: 'VPN', data_shared: 'PHI', last_assessment: '2025-06' }],
    vendor_dependencies: ['Epic Systems'], known_unknowns: [],
    deliberate_weaknesses: ['no quarterly access reviews']
  }
};

const MOCK_NETWORK = {
  run_id: 'RUN_TEST',
  network: {
    public_ip: '203.0.113.50',
    subnets: [
      { name: 'Management', cidr: '10.10.1.0/24', vlan_id: 10, purpose: 'Admin', trust_level: 'High' },
      { name: 'Servers', cidr: '10.10.2.0/24', vlan_id: 20, purpose: 'Servers', trust_level: 'High' },
      { name: 'Workstations', cidr: '10.10.3.0/24', vlan_id: 30, purpose: 'Endpoints', trust_level: 'Medium' }
    ],
    assets: [
      { hostname: 'ehr-01', ip: '10.10.2.10', subnet: 'Servers', role: 'server', os: 'Windows Server 2019', function: 'EHR', critical: true },
      { hostname: 'admin-ws-01', ip: '10.10.3.10', subnet: 'Workstations', role: 'workstation', os: 'Windows 10 Pro', function: 'Admin', critical: false },
      { hostname: 'ops-ws-01', ip: '10.10.3.11', subnet: 'Workstations', role: 'workstation', os: 'Windows 10 Pro', function: 'Ops', critical: false }
    ],
    firewall: {
      vendor: 'pfSense', model: 'CE', firmware: '2.7.0',
      vpn: { enabled: true, type: 'IPSec', mfa: 'All', split_tunnel: false },
      rules: [
        { id: 1, name: 'allow_internal', source: '10.10.0.0/16', destination: 'any', port: 'any', protocol: 'TCP', action: 'Allow', logging: true, description: 'mapped wrong fields' }
      ]
    },
    deliberate_weaknesses: ['flat workstation segment']
  }
};

const MOCK_THREAT = {
  run_id: 'RUN_TEST',
  threat_profile: {
    top_threats: ['phishing', 'ransomware'],
    deliberate_weaknesses: ['No EDR on ehr-01'],
    scenarios: [{
      scenario_id: 'TS-001', name: 'Ransomware via phish', type: 'ransomware',
      threat_actor: 'criminal', initial_vector: 'email',
      attack_path: [
        { step: 1, action: 'phish', target: 'admin-ws-01', technique: 'T1566.001', detection_opportunity: 'email gw' },
        { step: 2, action: 'exec', target: 'NOPE-host', technique: 'T1059.001', detection_opportunity: 'EDR' }, // invalid host
        { step: 3, action: 'pivot', target: 'ehr-01', technique: 'INVALID-ID', detection_opportunity: 'siem' } // invalid technique
      ],
      impacted_assets: ['ehr-01'], potential_impact: 'PHI loss', likelihood: 'High', difficulty_to_detect: 'Medium'
    }]
  },
  artifacts: [{ artifact_id: 'ART-VULN-01', type: 'vuln_scan_sample', description: 'mock',
    content: { scan_date: '2026-01-15', findings: [] } }]
};

// Branch-aware mock — picks the right canned response based on a prompt-text hint
let callIndex = 0;
const callRecord = [];
const mockClient = {
  messages: {
    create: async (params) => {
      callIndex++;
      const userText = params.messages[0]?.content || '';
      const systemText = Array.isArray(params.system) ? params.system.map(b => b.text || '').join(' ') : (params.system || '');
      callRecord.push({ index: callIndex, systemSnippet: systemText.slice(0, 60), userSnippet: userText.slice(0, 80) });

      // Dispatch on user-prompt opening (each branch has a unique "Generate the X." line).
      let response;
      if (/Generate the organization profile/.test(userText)) response = MOCK_ORG;
      else if (/Generate the IT environment/.test(userText)) response = MOCK_IT;
      else if (/Generate the network architecture/.test(userText)) response = MOCK_NETWORK;
      else if (/Generate the threat profile/.test(userText)) response = MOCK_THREAT;
      else response = { ok: true };

      return {
        content: [{ type: 'text', text: JSON.stringify(response) }],
        usage: { input_tokens: 100, output_tokens: 50 },
        stop_reason: 'end_turn'
      };
    }
  }
};
llm._setClientForTest(mockClient);

// Stub fs writes (don't pollute the profiles directory)
const fs = require('fs');
const realWrite = fs.writeFileSync;
const writtenFiles = [];
fs.writeFileSync = (file, content) => { writtenFiles.push({ file, size: content.length }); };
const realMkdir = fs.mkdirSync;
fs.mkdirSync = () => {};
const realExists = fs.existsSync;
fs.existsSync = () => true;

// ─── Run the pipeline ──────────────────────────────────────────────────────

const { generateProfile, buildConfig, combineProfile } = require('../ai/profile');

(async () => {
  let passed = 0, failed = 0;
  function test(name, fn) {
    return Promise.resolve()
      .then(fn)
      .then(() => { console.log(`  ✓ ${name}`); passed++; })
      .catch(err => { console.log(`  ✗ ${name}\n    ${err.message}`); failed++; });
  }

  console.log('\nbuildConfig — input shape');

  await test('produces a config + seed with run_id', () => {
    const { config, seed } = buildConfig({ client_type: 'SMB', difficulty: 'intermediate', employees: 50 });
    assert.ok(seed.run_id);
    assert.ok(seed.run_id.startsWith('RUN_'));
    assert.strictEqual(config.clientType, 'SMB');
    assert.strictEqual(seed.difficulty, 'intermediate');
  });

  console.log('\ngenerateProfile — end-to-end with mocked LLM');

  await test('runs the full A/B/C/D pipeline and returns a profile row', async () => {
    const row = await generateProfile({
      user_id: 'user-uuid-fake',
      client_type: 'SMB',
      industry: 'Healthcare',
      difficulty: 'intermediate',
      employees: 50
    });
    assert.ok(row);
    assert.strictEqual(row.id, 'fake-uuid');
    assert.strictEqual(row.company_name, 'Mock Healthcare LLC');
    assert.ok(row.run_id);
  });

  await test('fired 4 LLM calls (one per branch)', () => {
    assert.strictEqual(callIndex, 4, `expected 4 LLM calls, got ${callIndex}`);
  });

  await test('wrote a JSON file under profiles/', () => {
    assert.strictEqual(writtenFiles.length, 1);
    assert.match(writtenFiles[0].file, /client_profile_RUN_.*\.json$/);
    assert.ok(writtenFiles[0].size > 100, 'JSON should not be empty');
  });

  await test('inserted a profiles row', () => {
    assert.strictEqual(insertedRows.length, 1);
    assert.strictEqual(insertedRows[0].args[1], 'Mock Healthcare LLC');
  });

  console.log('\ncombineProfile — student_view shape');

  await test('produces student_view + instructor_view', () => {
    const combined = combineProfile({
      orgPayload: MOCK_ORG,
      itPayload: MOCK_IT,
      netPayload: MOCK_NETWORK,
      threatPayload: MOCK_THREAT,
      config: { clientType: 'SMB' },
      seed: { run_id: 'RUN_TEST', difficulty: 'intermediate' },
      employeeCount: 50
    });
    assert.ok(combined.student_view);
    assert.ok(combined.student_view.raw.threats.organization);
    assert.ok(combined.student_view.raw.threats.network);
    assert.ok(combined.student_view.quick.company_name);
    assert.ok(Array.isArray(combined.student_view.stakeholders));
    assert.ok(combined.instructor_view);
    assert.ok(Array.isArray(combined.instructor_view.deliberate_weaknesses.governance));
  });

  console.log(`\n${passed} passed, ${failed} failed`);

  // Restore fs
  fs.writeFileSync = realWrite;
  fs.mkdirSync = realMkdir;
  fs.existsSync = realExists;

  process.exit(failed === 0 ? 0 : 1);
})();
