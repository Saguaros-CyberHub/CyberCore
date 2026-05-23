/**
 * Profile pipeline prompts.
 * ============================================================================
 * Ported from front-end/N8N Workflow/UPGRADED_{A1,B1,C1,D1}_*.js — the four
 * parallel Claude branches that generate org / IT / network / threat profiles.
 *
 * Each builder is a pure function: takes a normalized config+seed and returns
 * a { systemPrompt, userPrompt } pair. The system prompts are LARGE and
 * IDENTICAL across calls of the same branch → marked for prompt caching in
 * the orchestrator (90% cost drop after the first call in a 5-min window).
 *
 * Output schemas mirror what the existing N8N validators (A3/B3/C3/D4) expect
 * downstream, so the rest of the pipeline (combine, store) doesn't change.
 */

// ─── Shared boilerplate ───────────────────────────────────────────────────

const SYS_HEADER = `You generate FICTIONAL training profiles for the Clinic-in-a-Box university course. Return ONLY strict JSON. No markdown. No extra text. No code fences.

Hard format rules:
- Output must be a single JSON object that parses with JSON.parse() on the first try.
- Quote ALL keys and strings with double quotes.
- Do NOT use comments, trailing commas, or unquoted property names.
- If you cannot comply with all hard constraints, output exactly: {"error":"cannot_comply","reason":"<short explanation>"}

Style:
- Realistic, internally consistent. Pick ONE plausible product per role — no laundry lists of alternatives.
- Reference the same hostnames / IPs / vendors consistently within the output.
- Difficulty calibrates depth: beginner = simpler/fewer items; intermediate = standard; advanced = more nuance, more weaknesses, more cross-cutting hidden info.
`;

// ─── Shared helpers ───────────────────────────────────────────────────────

function pickEmployeeCount(seed) {
  const e = seed.employees;
  if (typeof e === 'object' && e) {
    const min = e.min ?? 25, max = e.max ?? 200;
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  return e || 50;
}

// ─── A: Organization profile ──────────────────────────────────────────────

function buildOrgPrompt({ config, seed, employeeCount }) {
  const clientTypeName = config.clientTypeName || 'Small-Medium Business';
  const tmpl = seed.template || {};
  const industry = tmpl.industry || 'Professional Services';
  const naicsHint = tmpl.naics_hint || '541990';
  const risks = tmpl.risks || ['data breach', 'phishing', 'insider threats'];
  const compliance = tmpl.compliance || ['Industry Standards'];
  const criticalSystems = tmpl.criticalSystems || ['CRM', 'Email', 'ERP'];
  const stakeholderCount = seed.stakeholder_count
    || seed.difficulty_settings?.stakeholder_count?.min || 5;
  const overrides = seed.organization_overrides || config.organization_overrides || {};

  const companyNameRule = overrides.company_name
    ? `Company name MUST be exactly: "${overrides.company_name}"`
    : `Generate a realistic company name for a ${industry} firm`;
  const hqCityRule = overrides.hq_city
    ? `HQ city MUST be exactly: "${overrides.hq_city}"`
    : `HQ city: pick a realistic US city`;

  const systemPrompt = SYS_HEADER + `
You are generating ONLY the organization + stakeholders + governance portion of the profile. NO network, NO IT environment, NO threat scenarios — those are generated separately.

Required output schema (every field is required, every type is enforced):

{
  "run_id": "<echoed from input>",
  "organization": {
    "company_name": "string",
    "industry": "string",
    "naics_hint": "string",
    "hq_city": "string",
    "employees_total": int,
    "domain_public": "string",
    "business_model": "string (2–3 sentences)",
    "critical_services": ["string", ...],
    "key_system_dependencies": ["string", ...],
    "department_breakdown": { "IT": int, "Operations": int, "Administration": int, "Sales/Marketing": int, "Other": int },
    "risks": ["string", ...],
    "annual_revenue_range": "<$1M-5M|$5M-25M|$25M-100M|$100M+>",
    "past_incidents": [
      { "year": int, "type": "ransomware|phishing|data_breach|insider_threat|service_outage|vendor_compromise", "severity": "Low|Medium|High|Critical", "outcome": "string" }
    ],
    "regulatory_timeline": "string (upcoming compliance deadlines)",
    "growth_trajectory": "<Shrinking|Stable|Moderate Growth|Rapid Growth> - <context>",
    "business_continuity": { "rpo_hours": int, "rto_hours": int, "estimated_downtime_cost_per_hour": int }
  },
  "profiles": {
    "governance_and_policy": {
      "framework": "<NIST CSF|CIS Controls|ISO 27001|None|Partial>",
      "policies_present": ["string (3–6 policies)"],
      "policies_missing": ["string (2–4 missing/outdated policies)"],
      "policy_enforcement": "<Strict|Inconsistent|Minimal>",
      "risk_tolerance": "<Risk Averse|Moderate|Risk Accepting>",
      "deliberate_weaknesses": ["string (3–5 governance gaps for students to find)"]
    }
  },
  "stakeholders": [
    {
      "name": "string", "role": "string", "department": "string",
      "email": "firstname.lastname@<company-domain>",
      "technical_fluency": "Low|Medium|High",
      "decision_power": "Final Approval|Operational|Technical|Advisory|None",
      "communication_style": "string", "concerns": ["string"], "likely_pushback": ["string"],
      "information_they_can_provide": ["string"], "information_they_lack": ["string"],
      "signature_quote": "string",
      "hidden_info": "string (something they know but won't volunteer)",
      "shadow_it_knowledge": "string (unauthorized tools, or 'None known')",
      "relationship_conflicts": "string (tension with another stakeholder, or 'None')"
    }
  ]
}

Cross-field rules:
- department_breakdown values must SUM to employees_total.
- Stakeholders: include exactly the requested count. MUST include 1 executive leader (CEO / Owner / Principal / Superintendent etc. matching the org type) and 1 IT Manager.
- annual_revenue_range must be realistic for the headcount and industry.
- past_incidents: 0–1 for beginner, 1–2 for intermediate, 2–3 for advanced.
- business_continuity values must be realistic for the industry (a hospital needs lower RPO/RTO than a retail shop).
- hidden_info MUST be unique per stakeholder. At least 2 must have genuinely useful hidden information.
- At least 1 stakeholder should have a real shadow_it_knowledge entry.
- At least 2 stakeholders should reference relationship_conflicts with named other stakeholders.`;

  const userPrompt = `Generate the organization profile.

run_id: ${seed.run_id}
client_type: ${config.clientType || 'SMB'} (${clientTypeName})
industry: ${industry}
NAICS hint: ${naicsHint}
employees_total: EXACTLY ${employeeCount}
${companyNameRule}
${hqCityRule}
key risks: ${risks.join(', ')}
compliance requirements: ${compliance.join(', ')}
critical systems: ${criticalSystems.join(', ')}
IT maturity: ${seed.maturity || 'Intermediate'}
delivery mode: ${seed.delivery || 'Hybrid'}
difficulty: ${seed.difficulty || 'intermediate'}
stakeholder cooperation: ${seed.difficulty_settings?.stakeholder_cooperation || 'moderate'}
stakeholder_count: EXACTLY ${stakeholderCount}`;

  return { systemPrompt, userPrompt };
}

// ─── B: IT environment ────────────────────────────────────────────────────

function buildItPrompt({ config, seed, employeeCount }) {
  const tmpl = seed.template || {};
  const industry = tmpl.industry || 'Professional Services';
  const criticalSystems = tmpl.criticalSystems || ['CRM', 'Email', 'ERP'];
  const endpointMin = seed.endpoint_range?.min || seed.endpoint_count || 20;
  const endpointMax = seed.endpoint_range?.max || seed.endpoint_count || 90;
  const weaknessMin = seed.weakness_range?.min || seed.difficulty_settings?.deliberate_weaknesses?.min || 3;
  const weaknessMax = seed.weakness_range?.max || seed.difficulty_settings?.deliberate_weaknesses?.max || 8;

  const systemPrompt = SYS_HEADER + `
You are generating ONLY the IT environment / asset inventory. NO org bios, NO stakeholders, NO network diagrams.

Required output schema:

{
  "run_id": "<echoed>",
  "it_environment": {
    "delivery": "<Cloud|On-Prem|Hybrid>",
    "endpoints": { "windows_laptops": int, "windows_desktops": int, "shared_kiosks": int, "macos": int, "mobile": int },
    "servers": [ { "hostname": "string", "os": "fully versioned string e.g. Windows Server 2019 Standard 10.0.17763", "role": "string" } ],
    "saas": [ { "name": "string", "category": "string", "sso_enabled": bool, "mfa": bool, "data_sensitivity": "Low|Medium|High" } ],
    "endpoint_protection": { "product": "string", "managed": bool, "edr_enabled": bool, "coverage_percent": int },
    "patch_management": { "method": "<WSUS|Intune|Manual|Third-party>", "frequency": "<Daily|Weekly|Monthly|Ad-hoc>", "compliance_rate": int },
    "remote_access": { "vpn": "string-or-None", "split_tunnel": bool, "mfa": "All|ExecOnly|None" },
    "backups": { "method": "<Cloud|On-Prem|Hybrid|None>", "frequency": "<Daily|Weekly|Monthly>", "immutability": bool, "offsite": bool, "restore_tests": "string" },
    "physical_security": { "badge_access": bool, "cameras": bool, "server_room_locked": bool, "clean_desk_policy": bool, "visitor_logging": bool },
    "vendor_risk": [ { "vendor": "string", "access_type": "<VPN|API|On-site|Remote Desktop|Cloud Portal>", "data_shared": "string", "last_assessment": "date-or-Never" } ],
    "vendor_dependencies": ["string"],
    "known_unknowns": ["string"],
    "deliberate_weaknesses": ["string"]
  }
}

Hard rules:
- Pick ONE realistic product per function — no competing alternatives in the same list.
- Every server.os MUST be a fully versioned string (no bare "Windows Server" or "Linux").
- Server hostnames must be descriptive (e.g. dc-01, fs-01, app-erp-01), not "server1".
- Generate 3–5 SaaS apps realistic for the industry.
- physical_security values match the maturity level (lower maturity = fewer controls).
- vendor_risk: 2–4 entries. At Low/Intermediate maturity, at least one must have "Never" as last_assessment.`;

  const userPrompt = `Generate the IT environment.

run_id: ${seed.run_id}
employees_total: ${employeeCount}
industry: ${industry}
critical_systems: ${criticalSystems.join(', ')}
delivery: ${seed.delivery || 'Hybrid'}
maturity: ${seed.maturity || 'Intermediate'}
difficulty: ${seed.difficulty || 'intermediate'}
total_endpoints_range: ${endpointMin}–${endpointMax}
deliberate_weaknesses_count: ${weaknessMin}–${weaknessMax}`;

  return { systemPrompt, userPrompt };
}

// ─── C: Network ───────────────────────────────────────────────────────────

function buildNetworkPrompt({ config, seed }) {
  const tmpl = seed.template || {};
  const industry = tmpl.industry || 'Professional Services';
  const netConfig = config.network || {};
  const subnetList = (netConfig.requiredSubnets || ['Management', 'Servers', 'Workstations', 'Guest'])
    .map((s, i) => `${i + 1}) ${s}`).join('\n');
  const exampleWsCount = Math.min(10, Math.max(5, Math.floor((seed.endpoint_count || 50) / 10)));
  const fwRulesMax = Math.min(seed.firewall_rules_range?.max || 25, 25);
  const weaknessMin = seed.weakness_range?.min || 3;
  const weaknessMax = seed.weakness_range?.max || 8;

  // Challenge network mode — forces real VM IPs to be used as-is
  const cnData = config?.challenge_network;
  const isChallenge = cnData?.is_challenge === true;
  const realAssets = cnData?.real_assets || [];
  let challengeSection = '';
  let serversBlock = `- dc-01 (Domain Controller)
- file-server-01 (File Server)
- app-server-01 (Application Server)
- backup-server-01 (Backup Server)`;

  if (isChallenge && realAssets.length > 0) {
    const firstIp = realAssets[0].ip;
    const realSubnet = firstIp.split('.').slice(0, 3).join('.') + '.0/24';
    challengeSection = `
CHALLENGE NETWORK MODE:
- Servers subnet CIDR MUST be: ${realSubnet}
- The fixed-IP servers below MUST be included EXACTLY as written (do not rename, renumber, or omit):
${realAssets.map(a => `  - hostname: "${a.hostname}", ip: "${a.ip}"`).join('\n')}
- Other subnets must use different RFC1918 ranges (not ${firstIp.split('.').slice(0, 3).join('.')}.x).
- Do NOT create extra servers that duplicate these roles.`;
    serversBlock = realAssets.map(a => `- ${a.hostname} (FIXED ip ${a.ip})`).join('\n');
  }

  const otSection = config.clientType === 'Utility_IT_OT' ? `
OT assets (each must have hostname AND ip):
- scada-server (OT-Control subnet)
- hmi-01 (OT-Control subnet)
- historian-01 (OT-Control or DMZ)
- plc-001..plc-003 (OT-Field subnet)` : '';

  const systemPrompt = SYS_HEADER + `
You are generating ONLY the network architecture: subnets, asset inventory, firewall, VPN. NO org bios, NO stakeholders, NO threats, NO diagram_text field.

Required output schema:

{
  "run_id": "<echoed>",
  "network": {
    "public_ip": "string (must match input value)",
    "subnets": [ { "name": "string", "cidr": "x.x.x.x/xx", "vlan_id": int, "purpose": "string", "trust_level": "High|Medium|Low" } ],
    "assets": [ { "hostname": "department-based name", "ip": "x.x.x.x", "subnet": "subnet name", "role": "server|workstation|network|ot", "os": "string", "function": "string", "critical": bool } ],
    "firewall": {
      "vendor": "string", "model": "string", "firmware": "string",
      "vpn": { "enabled": bool, "type": "SSL-VPN|IPSec|Both", "mfa": "All|ExecOnly|None", "split_tunnel": bool },
      "rules": [ { "id": int, "name": "string", "src": "string", "dst": "string", "port": "string", "proto": "TCP|UDP|ANY", "action": "Allow|Deny", "logging": bool, "comment": "string" } ]
    },
    "deliberate_weaknesses": ["string"]
  }
}

Hard rules:
- Internal addressing is RFC1918 ONLY (10.x.x.x, 172.16-31.x.x, 192.168.x.x).
- Every asset MUST have a static IP that falls within its subnet's CIDR.
- Use a /24 subnet for Workstations.
- Firewall fields are EXACTLY: src, dst, port, proto, comment (not source/destination/protocol/description).
- Use ONE default-deny rule at the end of the rule list — do NOT emit a separate deny rule per subnet.
- Each rule must be UNIQUE.
- diagram_text field is FORBIDDEN — do not emit it.`;

  const userPrompt = `Generate the network architecture.

run_id: ${seed.run_id}
industry: ${industry}
client_type: ${config.clientTypeName || config.clientType || 'SMB'}
public_ip MUST be exactly: ${seed.public_ip}
maturity: ${seed.maturity}
difficulty: ${seed.difficulty}
total_endpoints: ${seed.endpoint_count} (only emit ${exampleWsCount} example workstations — system will autofill the rest from these examples)
${challengeSection}

REQUIRED SUBNETS (include all):
${subnetList}

CORE INFRASTRUCTURE (in Management subnet):
- firewall (e.g. fw-01)
- switch-core (e.g. sw-core-01)

SERVERS (in Servers subnet):
${serversBlock}
${otSection}

WORKSTATIONS (Workstations subnet):
Emit ${exampleWsCount} EXAMPLE workstations using DEPARTMENT-BASED naming
(admin-ws-01, ops-ws-02, acct-ws-01, front-desk-01, it-ws-01).
NOT sequential ws-001..ws-${String(exampleWsCount).padStart(3, '0')}.
Use abbreviations appropriate for ${industry}: admin, ops, sales, fin, hr, it, clinical, front-desk, warehouse, eng.

FIREWALL:
- EXACTLY ${fwRulesMax} rules (no more).
- 5–8 Allow rules for legitimate inter-subnet traffic.
- ONE default-deny rule at the end.
- ≥2 rules with INTENTIONAL WEAKNESSES.

DELIBERATE WEAKNESSES:
${weaknessMin}–${weaknessMax} intentional security issues total:
- ≥2 in firewall rules (overly permissive / disabled logging / any-any).
- ≥2 in network design (flat network / poor segmentation / management exposure).
- ≥1 related to VPN/remote access.`;

  return { systemPrompt, userPrompt };
}

// ─── D: Threat profile ────────────────────────────────────────────────────

function buildThreatPrompt({ config, seed, networkSummary }) {
  const tmpl = seed.template || {};
  const industry = tmpl.industry || 'Professional Services';
  const risks = tmpl.risks || ['data breach', 'phishing', 'insider threats'];
  const difficulty = seed.difficulty || 'intermediate';
  const scenarioRanges = {
    beginner: { min: 2, max: 3 },
    intermediate: { min: 3, max: 5 },
    advanced: { min: 4, max: 6 }
  };
  const range = scenarioRanges[difficulty] || scenarioRanges.intermediate;

  const systemPrompt = SYS_HEADER + `
You are generating ONLY the threat profile: top threats, deliberate weaknesses, attack-path scenarios, and one vuln-scan artifact. Reference actual hostnames/IPs from the provided network summary — do NOT invent new ones.

Required output schema:

{
  "run_id": "<echoed>",
  "threat_profile": {
    "top_threats": ["string"],
    "deliberate_weaknesses": ["string (each must reference a real host or service from network data)"],
    "scenarios": [
      {
        "scenario_id": "TS-001", "name": "string", "type": "ransomware|phishing|insider|credential_stuffing|...",
        "threat_actor": "string", "initial_vector": "string",
        "attack_path": [
          { "step": int, "action": "string", "target": "hostname from network data", "technique": "T#### or T####.### (valid MITRE ATT&CK ID)", "detection_opportunity": "string" }
        ],
        "impacted_assets": ["hostname from network data"],
        "potential_impact": "string", "likelihood": "Low|Medium|High", "difficulty_to_detect": "Low|Medium|High"
      }
    ]
  },
  "artifacts": [
    { "artifact_id": "ART-VULN-01", "type": "vuln_scan_sample", "description": "string",
      "content": { "scan_date": "YYYY-MM-DD",
                   "findings": [ { "host": "hostname", "ip": "x.x.x.x", "vuln": "string", "severity": "Low|Medium|High|Critical", "cvss": number } ] } }
  ]
}

Hard rules:
- Each scenario has 5–7 attack_path steps. Each step is a JSON object with step/action/target/technique/detection_opportunity.
- All technique IDs must be REAL MITRE ATT&CK IDs (e.g. T1566.001, T1078, T1021.001, T1059.001, T1486, T1003.001).
- Attack paths follow a realistic kill chain: initial access → execution → persistence → lateral movement → privilege escalation → collection/exfiltration → impact.
- deliberate_weaknesses: 5–8 specific exploitable weaknesses that tie into the scenarios, each referencing an actual host/service from network data.
- Use ONLY hostnames/IPs from the provided network summary.`;

  const userPrompt = `Generate the threat profile.

run_id: ${seed.run_id}
industry: ${industry}
risks_to_cover: ${risks.join(', ')}
maturity: ${seed.maturity || 'Intermediate'}
difficulty: ${difficulty}
scenarios_count: ${range.min}–${range.max}

NETWORK SUMMARY (only reference these hosts/IPs):
${networkSummary || '(no network data — synthesize generic hostnames like dc-01, file-server-01)'}`;

  return { systemPrompt, userPrompt };
}

// ─── Network summary builder for D branch ────────────────────────────────

function buildNetworkSummary(networkOutput) {
  if (!networkOutput || !networkOutput.network) return null;
  const net = networkOutput.network;
  const assets = (net.assets || []).slice(0, 30); // truncate for token budget
  const lines = [
    `public_ip: ${net.public_ip || 'unknown'}`,
    `subnets: ${(net.subnets || []).map(s => `${s.name} (${s.cidr})`).join(', ')}`,
    `assets (first ${assets.length}):`,
    ...assets.map(a => `  - ${a.hostname} [${a.ip}] role=${a.role} os=${a.os}`)
  ];
  return lines.join('\n');
}

module.exports = {
  pickEmployeeCount,
  buildOrgPrompt,
  buildItPrompt,
  buildNetworkPrompt,
  buildThreatPrompt,
  buildNetworkSummary,
  SYS_HEADER
};
