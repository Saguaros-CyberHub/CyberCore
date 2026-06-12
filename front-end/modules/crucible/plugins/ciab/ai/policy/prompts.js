/**
 * Policy generator prompts — the per-policy section/extra recipe tables.
 * Kept as a separate file so future tweaks don't touch the orchestrator.
 */

// Per-policy section recipe + context-injection notes. Lookup by case-insensitive
// substring against the policy name from profile.governance.policies_present.
const POLICY_PROMPTS = {
  'data handling': {
    sections: 'Purpose & Scope, Data Classification (table with levels: Confidential/Internal/Public, descriptions, examples, handling requirements), Data Handling Procedures (storage, transmission, disposal subsections), Roles & Responsibilities (table), Compliance & Enforcement, Exceptions',
    extra: (ctx) => `Reference the company's backup method (${ctx.backups.method || 'cloud'}) and SaaS applications (${ctx.saasList}) for approved storage. Include NIST SP 800-88 for disposal standards.`
  },
  'incident response': {
    sections: 'Purpose & Scope, Incident Classification (table with severity P1-P4, descriptions, examples, response times), Incident Response Phases (Preparation, Detection & Analysis, Containment with short-term and long-term, Eradication & Recovery, Post-Incident Activity), Roles & Responsibilities (Incident Commander, Security Analyst, IT Operations, Communications Lead, Legal), Communication Plan (table with audience/timing/method/content)',
    extra: (ctx) => `Reference the company's EDR (${ctx.endpoint_protection.product || 'EDR'}), firewall (${ctx.firewall.vendor || 'perimeter firewall'}), and backup solution. Include specific server names: ${ctx.serverList}.`
  },
  'password': {
    sections: 'Purpose & Scope, Password Requirements (table comparing Standard User/Administrator/Service Account for: min length, complexity, max age, history, lockout threshold, lockout duration), Multi-Factor Authentication (MFA) requirements, Prohibited Practices, Password Manager policy, Privileged Access Management, Compliance & Enforcement',
    extra: (ctx) => `Reference the VPN (${ctx.remote_access.vpn || 'VPN'}) and MFA status (${ctx.remote_access.mfa || 'enabled'}). Mention specific servers that need default password changes: ${ctx.serverList}.`
  },
  'acceptable use': {
    sections: 'Purpose & Scope, Acceptable Use (General Principles, Email & Communications, Internet & Cloud Services subsections), Prohibited Activities (comprehensive list), Software & Licensing, Monitoring & Privacy notice, Enforcement (escalation levels)',
    extra: (ctx) => `List specific approved SaaS: ${ctx.saasList}. Industry context: ${ctx.industry}.`
  },
  'access control': {
    sections: 'Purpose & Scope, Access Control Principles (Least Privilege, Need-to-Know, Separation of Duties, Default Deny), Account Management (Provisioning, Modification, Deprovisioning subsections), Authentication Requirements (table by system type), Access Reviews schedule, Remote Access requirements, Compliance',
    extra: (ctx) => `Reference VPN (${ctx.remote_access.vpn || 'VPN'}), endpoint counts, server names: ${ctx.serverList}. Include split tunnel status.`
  },
  'business continuity': {
    sections: 'Purpose & Scope, Recovery Objectives (table with RTO/RPO/cost), Critical Business Functions (prioritized table), Backup & Recovery Strategy, Disaster Scenarios (Ransomware, Facility Loss, Power Outage - each with numbered steps), Testing & Maintenance schedule',
    extra: (ctx) => `Use backup details: method=${ctx.backups.method || 'cloud'}, frequency=${ctx.backups.frequency || 'daily'}, immutable=${ctx.backups.immutability || false}, restore_tests=${ctx.backups.restore_tests || 'quarterly'}. ${ctx.business_continuity.rto_hours ? 'RTO: ' + ctx.business_continuity.rto_hours + 'h, RPO: ' + ctx.business_continuity.rpo_hours + 'h' : ''}`
  },
  'change management': {
    sections: 'Purpose & Scope, Change Categories (table: Standard/Normal/Emergency with description, approval needed, examples), Change Request Process (numbered steps), Change Windows (maintenance windows, blackout periods), Rollback Requirements, Documentation & Audit',
    extra: (ctx) => `Reference specific servers for change management: ${ctx.serverList}.`
  },
  'information security': {
    sections: 'Purpose & Scope, Information Security Objectives, Security Framework description, Security Domains (table mapping domain to key controls to subordinate policy), Roles & Responsibilities (table), Risk Assessment process, Policy Compliance & Review',
    extra: (ctx) => `Framework: ${ctx.framework}. Risk tolerance: ${ctx.risk_tolerance}. Reference all security controls: EDR (${ctx.endpoint_protection.product || 'EDR'}), firewall (${ctx.firewall.vendor || 'firewall'}), backups (${ctx.backups.frequency || 'daily'}).`
  },
  'network security': {
    sections: 'Purpose & Scope, Network Architecture (Segmentation requirements, Perimeter Security), Wireless Network Security, Remote Access, Network Monitoring & Logging, DNS/DHCP/Network Services, Compliance',
    extra: (ctx) => `Firewall: ${ctx.firewall.vendor || 'enterprise'}. VPN: ${ctx.remote_access.vpn || 'VPN'}. Subnets: ${(ctx.subnets || []).map(s => s.name || s.subnet || s).join(', ') || 'segmented'}. Servers: ${ctx.serverList}.`
  },
  'remote work': {
    sections: 'Purpose & Scope, Eligibility & Approval, Secure Connection Requirements, Device Security (Company-Issued subsection, BYOD subsection), Physical Security for Remote Work, Data Handling, Incident Reporting',
    extra: (ctx) => `VPN: ${ctx.remote_access.vpn || 'VPN'}, split_tunnel: ${ctx.remote_access.split_tunnel === false ? 'disabled' : 'enabled'}, MFA: ${ctx.remote_access.mfa || 'required'}. EDR: ${ctx.endpoint_protection.product || 'endpoint protection'}.`
  },
  'vendor': {
    sections: 'Purpose & Scope, Vendor Risk Assessment (Risk Tiering table: Critical/High/Medium/Low with criteria and review frequency), Assessment Process (numbered steps), Current Vendor Inventory if applicable, Contractual Requirements, Ongoing Monitoring, Vendor Offboarding',
    extra: (ctx) => `Vendor dependencies: ${(ctx.vendor_dependencies || []).map(v => typeof v === 'string' ? v : v.name || v.vendor).join(', ') || 'various'}. Compliance: ${ctx.complianceStr}.`
  },
  'third-party': {
    sections: 'Purpose & Scope, Third-Party Risk Assessment (Risk Tiering table), Assessment Process, Contractual Requirements, Ongoing Monitoring, Offboarding',
    extra: (ctx) => `Vendor dependencies: ${(ctx.vendor_dependencies || []).map(v => typeof v === 'string' ? v : v.name || v.vendor).join(', ') || 'various'}.`
  },
  'data retention': {
    sections: 'Purpose & Scope, Retention Schedule (table with data category, retention period, storage location, disposal method — include: financial records, HR, client contracts, client PII, email, security logs, backup media, CCTV), Legal Hold process, Data Disposal Procedures, Responsibilities, Compliance',
    extra: (ctx) => `Backup method: ${ctx.backups.method || 'standard'}. Compliance: ${ctx.complianceStr}.`
  },
  'training': {
    sections: 'Purpose & Scope, Training Requirements (table: Training Type/Audience/Frequency/Duration for orientation, annual refresher, phishing simulation, role-based, executive briefing, IR drill), Core Training Topics (All Employees subsection, Technical Staff subsection), Phishing Simulation Program, Training Delivery & Tracking, Metrics & Reporting',
    extra: (ctx) => `Employee count: ${ctx.employees_total}. Delivery model: ${ctx.delivery}.`
  },
  'cybersecurity training': {
    sections: 'Same as training above',
    extra: (ctx) => `Employee count: ${ctx.employees_total}. Delivery model: ${ctx.delivery}.`
  },
  'cloud security': {
    sections: 'Purpose & Scope, Cloud Service Approval process, Approved Cloud Services table, Security Requirements (Identity & Access, Data Protection, Configuration & Hardening subsections), Cloud Data Lifecycle, Incident Response in Cloud',
    extra: (ctx) => `Approved SaaS: ${ctx.saasList}. Delivery: ${ctx.delivery}. Backup: ${ctx.backups.method || 'standard'}.`
  },
  'physical security': {
    sections: 'Purpose & Scope, Facility Access Controls (table with zone types: Public/Controlled/Restricted/High Security), Server Room Security, Visitor Management, Clean Desk & Screen Lock, Surveillance, Equipment & Asset Protection, Emergency Procedures',
    extra: (ctx) => `Physical security details: ${JSON.stringify(ctx.physical_security) !== '{}' ? JSON.stringify(ctx.physical_security) : 'standard corporate facility'}. Location: ${ctx.hq_city || 'US'}.`
  }
};

const DEFAULT_SECTIONS = 'Purpose & Scope, Policy Statement, Roles & Responsibilities, Requirements, Compliance & Enforcement, Related Documents';

// Big static system prompt — cached via cache_control: ephemeral. Sets writing
// style + HTML formatting + length expectations across every policy in a batch.
const SYSTEM_PROMPT = `You are a corporate-policy author. Generate the BODY CONTENT of a realistic, enforceable internal policy document for a company that is going through a cybersecurity training exercise.

HARD RULES:
- Output BODY CONTENT ONLY. No <html>/<head>/<body> tags. No DOCTYPE. No markdown fences. Start directly with <h2>1. Purpose &amp; Scope</h2>.
- Use real HTML for structure: <h2> (major numbered sections), <h3> (subsections), <p>, <ul>/<li>, <ol>/<li>, <table>/<thead>/<tbody>/<tr>/<th>/<td>, <strong>.
- Reference the company by its real name. Do not use placeholders like [Company Name].
- Reference specific systems, tools, vendors, and configurations from the provided company profile — never invent generic ones if a specific one is given.
- Tables must have <th> headers and be well-formed.
- Include specific numbers: timeframes (hours/days/weeks), retention periods, review cycles, password lengths, etc.
- Length: approximately 800–1200 words total.
- Tone: professional, clear, actionable. Written as a real policy that an auditor would accept, not a template.

DEPTH (based on lab difficulty):
- beginner       → concise, straightforward, fewer sub-clauses
- intermediate   → moderately detailed, standard sub-sections
- advanced       → detailed with appendices, cross-references to other policies, more exception clauses

Do not include any commentary, markdown, or wrapping tags around the output. Just the HTML body content of the policy.`;

function buildCompanyContext(ctx) {
  return `COMPANY PROFILE:
- Name: ${ctx.company_name}
- Industry: ${ctx.industry}
- Size: ${ctx.employees_total} employees
- Location: ${ctx.hq_city || 'United States'}
- Security Framework: ${ctx.framework}
- Policy Enforcement: ${ctx.policy_enforcement}
- Risk Tolerance: ${ctx.risk_tolerance}
- Compliance Focus: ${ctx.complianceStr}
- IT Delivery Model: ${ctx.delivery}
- Endpoint Protection: ${ctx.endpoint_protection.product || 'managed EDR solution'}
- VPN: ${ctx.remote_access.vpn || 'corporate VPN'}${ctx.remote_access.split_tunnel === false ? ' (split tunneling disabled)' : ''}
- MFA: ${ctx.remote_access.mfa || 'enabled for remote access'}
- Backups: ${ctx.backups.method || 'standard'}, ${ctx.backups.frequency || 'daily'}${ctx.backups.immutability ? ', immutable' : ''}
- Firewall: ${ctx.firewall.vendor || 'enterprise firewall'}
- Key Servers: ${ctx.serverList}
- SaaS Applications: ${ctx.saasList}`;
}

function findPolicyConfig(policyName) {
  const lower = String(policyName || '').toLowerCase();
  for (const [key, cfg] of Object.entries(POLICY_PROMPTS)) {
    if (lower.includes(key)) return cfg;
  }
  return null;
}

/**
 * Build the user-message text for a single policy. Returns a string.
 * @param {string} policyName  e.g. "Data Handling Policy"
 * @param {object} ctx         normalized context (see buildContext in index.js)
 */
function buildUserPrompt(policyName, ctx) {
  const cfg = findPolicyConfig(policyName);
  const sections = cfg ? cfg.sections : DEFAULT_SECTIONS;
  const extra = cfg ? cfg.extra(ctx) : '';
  const depth = ctx.difficulty === 'advanced' ? 'detailed with appendices and cross-references'
              : ctx.difficulty === 'beginner' ? 'concise and straightforward'
              : 'moderately detailed';

  return `DOCUMENT: ${policyName}

${buildCompanyContext(ctx)}

REQUIRED SECTIONS:
${sections}

ADDITIONAL CONTEXT:
${extra}

STYLE REQUIREMENTS:
- Use the company name "${ctx.company_name}" throughout
- Policy depth: ${depth}
- Output: HTML body content only, starting directly with <h2>1. Purpose &amp; Scope</h2>`;
}

module.exports = {
  SYSTEM_PROMPT,
  buildUserPrompt,
  buildCompanyContext,
  findPolicyConfig,
  POLICY_PROMPTS,
  DEFAULT_SECTIONS
};
