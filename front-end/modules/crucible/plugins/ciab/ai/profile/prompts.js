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

// ─── Naming-seed pool ──────────────────────────────────────────────────────
// Random anchor words that get injected into the org prompt to break Claude's
// default-name convergence. Pulled from places, surnames, natural features,
// and trade vocabulary spread across many cultures + regions. The seed gets
// used as a thematic anchor — Claude builds a name that "feels" related
// without literally including the seed word, which gives wide variety.
const NAMING_SEEDS = [
  // US Western place names
  'Tumbleweed', 'Saguaro', 'Mesquite', 'Yavapai', 'Sonoran', 'Coyote', 'Catalina',
  'Verdigris', 'Walapai', 'Cochise', 'Mogollon', 'Buckeye', 'Tonto',
  // US Eastern / Midwestern
  'Schuylkill', 'Brandywine', 'Hocking', 'Allegheny', 'Ozark', 'Cumberland',
  'Susquehanna', 'Monongahela', 'Adirondack', 'Wabash', 'Kanawha',
  // US Southern / Gulf
  'Atchafalaya', 'Tallahatchie', 'Suwannee', 'Yazoo', 'Pearl River', 'Sabine',
  // US Pacific
  'Klamath', 'Methow', 'Skagit', 'Willapa', 'Sequim', 'Yamhill',
  // Surnames — diverse heritage
  'Okafor', 'Larsen', 'Tran', 'Hassan', 'Petrov', 'Cabrera', 'Voss', 'Kowalski',
  'Nakamura', 'Eze', 'Holloway', 'Ramachandran', 'Stojanov', 'Dwyer', 'Bekele',
  'Quintero', 'Adebayo', 'Kowalczyk', 'Nakashima', 'Cifuentes', 'Wojcik',
  // Natural / geographic
  'Buttermilk Springs', 'Three Rivers', 'Ironwood', 'Birchwood', 'Foxglove',
  'Indigo Bay', 'Hemlock Ridge', 'Crow Creek', 'Bramble Hollow', 'Slate Falls',
  // Trade / craft jargon
  'Foundry', 'Tannery', 'Mill', 'Cooperage', 'Joinery', 'Cannery', 'Drydock',
  'Brickworks', 'Toolworks', 'Granary', 'Smelter', 'Shipyard',
  // Astronomical / scientific
  'Polaris', 'Eridanus', 'Magellan', 'Halley', 'Vega', 'Procyon', 'Hyades',
  // Old / historical industry terms
  'Hansa', 'Guild', 'Compact', 'Chartered', 'Trust', 'Bureau'
];

function hashStr(s, salt = '') {
  const x = String(s || '') + '|' + salt;
  let h = 0;
  for (let i = 0; i < x.length; i++) h = ((h * 31) + x.charCodeAt(i)) >>> 0;
  return h;
}

function pickNamingSeed(runId) {
  return NAMING_SEEDS[hashStr(runId, 'seed') % NAMING_SEEDS.length];
}

// Per-client-type suffix pools. Combined with a seed word these produce
// plausible names entirely client-side — the model has no chance to converge
// on "Meridian Strategic Advisors".
const SUFFIX_POOLS = {
  SMB: [
    'Holdings', 'Trading Co', 'Industries', 'Group', '& Sons', 'Partners',
    '& Co', 'Brothers', 'Mercantile', 'Works', 'Supply Co', 'Logistics',
    'Outfitters', 'Provisioners', 'Manufacturing'
  ],
  NonProfit: [
    'Foundation', 'Trust', 'Society', 'Coalition', 'Initiative', 'Fund',
    'Center', 'Alliance', 'Project', 'Council', 'Collective'
  ],
  Utility_IT_OT: [
    'Utility', 'Water Authority', 'Energy', 'Cooperative', 'Public Service',
    'Power', 'Municipal Utilities', 'Water District', 'Light & Power'
  ],
  K12: [
    'School District', 'Public Schools', 'Academy', 'County Schools',
    'Unified School District', 'Charter Academy', 'Community Schools'
  ]
};

// Build a deterministic full company name from run_id + clientType.
// Same run_id → same name (good for reproducibility & retries).
function generateCompanyName(runId, clientType = 'SMB') {
  const seedWord = pickNamingSeed(runId);
  const pool = SUFFIX_POOLS[clientType] || SUFFIX_POOLS.SMB;
  const suffix = pool[hashStr(runId, 'suffix') % pool.length];
  return `${seedWord} ${suffix}`;
}

// ─── Per-branch flavor packets ────────────────────────────────────────────
// Without these, every IT/network/threat profile converges on the same
// trained-in defaults (CrowdStrike Falcon, Palo Alto firewall, Veeam backups,
// dc-01/fs-01/app-server-01 hostnames, Conti ransomware scenarios). Each
// branch gets a deterministic random anchor from a pool the model is told
// to lean on — same run_id → same flavor (reproducible) but each new
// run picks differently across all dimensions.

const VENDOR_FLAVORS = [
  'Microsoft-heavy (Azure AD / Entra, Defender, Intune, Edge, OneDrive, SharePoint)',
  'Google-heavy (Workspace, ChromeOS, Drive, Meet, Chrome Enterprise)',
  'Apple-heavy (mostly macOS endpoints, Jamf Pro, iCloud, Apple Business Manager)',
  'Mixed-cloud (AWS workloads + Microsoft 365 office productivity, some on-prem legacy)',
  'AWS-heavy (EC2/S3 backed apps, Okta SSO, Slack, Zoom, JumpCloud directory)',
  'On-prem traditionalist (Windows AD, file shares, minimal SaaS, RDP gateway for remote)',
  'Linux + open-source preferred (Ubuntu desktops, Nextcloud, Mattermost, Zimbra mail)',
  'Cisco shop (Cisco Meraki networking, Webex, AnyConnect VPN, IronPort email security)',
  'Fortinet stack (FortiGate firewall, FortiClient, FortiManager, FortiAnalyzer SIEM)',
  'SMB-budget vendors (BitDefender or ESET, Synology NAS backups, Bitwarden, ProtonMail)',
  'VMware + Dell shop (vSphere on Dell PowerEdge, Horizon VDI, Dell SonicWall)',
  'Cisco + Microsoft hybrid (Cisco ASA + Cisco Umbrella, Microsoft 365 E5, Intune)'
];

const EDR_PRODUCTS = [
  'CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'SentinelOne Singularity',
  'Sophos Intercept X', 'BitDefender GravityZone Business Security', 'ESET PROTECT Enterprise',
  'VMware Carbon Black Cloud', 'Trend Micro Apex One', 'Cisco Secure Endpoint',
  'Cybereason Defense Platform', 'Webroot Business Endpoint Protection',
  'Symantec Endpoint Protection 14', 'Kaspersky Endpoint Security for Business',
  'Malwarebytes for Business EDR', 'Huntress Managed EDR'
];

const FIREWALL_VENDORS = [
  { vendor: 'Palo Alto Networks', model: 'PA-440', firmware: 'PAN-OS 11.0.3' },
  { vendor: 'Palo Alto Networks', model: 'PA-820', firmware: 'PAN-OS 10.2.7' },
  { vendor: 'Fortinet', model: 'FortiGate 60F', firmware: 'FortiOS 7.4.1' },
  { vendor: 'Fortinet', model: 'FortiGate 100F', firmware: 'FortiOS 7.2.5' },
  { vendor: 'Cisco Meraki', model: 'MX67', firmware: 'MX 18.107.2' },
  { vendor: 'Cisco Meraki', model: 'MX85', firmware: 'MX 18.211.4' },
  { vendor: 'Cisco', model: 'ASA 5516-X', firmware: 'ASA 9.18(2)5' },
  { vendor: 'Netgate', model: 'pfSense Plus 23.05', firmware: 'FreeBSD 14.0 base' },
  { vendor: 'SonicWall', model: 'TZ470', firmware: 'SonicOS 7.0.1-5145' },
  { vendor: 'Check Point', model: '1570', firmware: 'R81.10' },
  { vendor: 'WatchGuard', model: 'Firebox T45', firmware: 'Fireware 12.10.1' },
  { vendor: 'Sophos', model: 'XGS 116', firmware: 'SFOS 19.5.3 MR-3' },
  { vendor: 'OPNsense', model: 'DEC2700 Appliance', firmware: 'OPNsense 23.7.10' },
  { vendor: 'Juniper Networks', model: 'SRX320', firmware: 'Junos 22.4R3' }
];

const BACKUP_PRODUCTS = [
  'Veeam Backup & Replication', 'Acronis Cyber Protect 15', 'Datto SIRIS',
  'Synology Active Backup for Business', 'Rubrik Security Cloud', 'Cohesity DataProtect',
  'Microsoft Azure Backup', 'AWS Backup', 'Carbonite Endpoint Backup',
  'Veritas Backup Exec 22', 'Unitrends Backup', 'NAKIVO Backup & Replication',
  'MSP360 Managed Backup', 'BackupAssist ER', 'iDrive Business'
];

const HOSTNAME_THEMES = [
  'numbered classic (dc-01, fs-01, app-erp-01, sql-01)',
  'department-prefixed (acct-srv-01, hr-app-01, ops-db-01, sales-fs-01)',
  'site-coded short-3 (sea-fs-01, dal-dc-01, nyc-app-01, hou-sql-01)',
  'project-codename (mercury-fs, apollo-dc, gemini-app, atlas-db)',
  'role + tier (web-tier-01, db-tier-01, app-tier-01, mid-tier-01)',
  'function-noun (billing-svr, ticket-svr, dms-svr, archive-svr)',
  'mythological (zeus-dc, hermes-mail, athena-app, hades-bak)',
  'planet/star (jupiter-dc, saturn-fs, vega-app, polaris-sql)'
];

const THREAT_ACTOR_FLAVORS = [
  'opportunistic ransomware affiliate (Akira-style or BlackBasta-style)',
  'business email compromise crew (mid-tier, targets finance/wire fraud)',
  'commodity malware delivery (Emotet/IcedID/Qakbot follow-on to Cobalt Strike)',
  'disgruntled-insider scenario (recently terminated IT contractor with retained credentials)',
  'cryptominer / unsophisticated automated (Mirai-derivative + cryptojacking)',
  'targeted supply-chain compromise (upstream managed-services provider got breached)',
  'industrial espionage (data-theft from R&D, formulas, or customer lists)',
  'nation-state-adjacent (long dwell time, low noise, exfil over DNS or HTTPS)',
  'hacktivist (defacement + data leak + brand damage motive)',
  'initial-access broker handoff (broker sells access, ransomware operator takes over)',
  'BYOD malware infection (employee personal device brought infection to network)',
  'lost / stolen laptop with cached credentials enabling lateral movement'
];

const FIRST_NAMES = [
  'Marcus', 'Aisha', 'Diego', 'Yuki', 'Priya', 'Liam', 'Esther', 'Tomás',
  'Mei', 'Kofi', 'Anastasia', 'Idris', 'Lila', 'Henrik', 'Sofia', 'Rohan',
  'Ngozi', 'Tariq', 'Inara', 'Otto', 'Wren', 'Joaquín', 'Hana', 'Saoirse',
  'Ezekiel', 'Reema', 'Mateo', 'Camille', 'Anders', 'Themba', 'Linnea',
  'Bao', 'Indira', 'Soren', 'Yejide', 'Lev', 'Calliope', 'Amara', 'Brennan',
  'Dilnoza', 'Magnus', 'Sade', 'Cyrus', 'Imelda', 'Jaxon', 'Nadia',
  'Quintessa', 'Ulises', 'Vivienne', 'Tobias', 'Beatrix', 'Halvor', 'Junie'
];

const LAST_NAMES_DIVERSE = [
  'Hayes', 'Okonkwo', 'Patel', 'Caldwell', 'Mendoza', 'Lindqvist', 'Bauer',
  'Ramos', 'Walsh', 'Bekele', 'Choi', 'Iniesta', 'Petersen', 'Sandoval',
  'Iqbal', 'Holt', 'Reyes', 'Volkov', 'Akinyemi', 'Berg', 'Sato', 'Pulaski',
  'Dimitriou', 'Salas', 'Erdogan', 'Yamamoto', 'Holloway', 'Quinn', 'Macharia',
  'Steiner', 'Vasquez', 'Khouri', 'Brady', 'Nwosu', 'Tan', 'Kowalczyk',
  'Brooks', 'Carmody', 'Pham', 'Eze', 'Sundberg', 'Hassani', 'Mathisen',
  'O\'Brien', 'Castellanos', 'Anand', 'Lefebvre', 'Halonen', 'Yousef',
  'Townsend', 'Mortensen', 'Adeoye', 'Schmidt', 'Lavigne'
];

function pickN(list, count, hashFn) {
  const out = [];
  const used = new Set();
  let attempt = 0;
  while (out.length < count && attempt < count * 8) {
    const idx = hashFn(attempt) % list.length;
    if (!used.has(idx)) { used.add(idx); out.push(list[idx]); }
    attempt++;
  }
  return out;
}

// ─── Server hardware pools (used by the deterministic roster) ──────────────
const SERVER_HARDWARE = [
  { make: 'HPE',     model: 'ProLiant DL360 Gen10 Plus' },
  { make: 'HPE',     model: 'ProLiant DL380 Gen11' },
  { make: 'Dell',    model: 'PowerEdge R650' },
  { make: 'Dell',    model: 'PowerEdge R750xs' },
  { make: 'Dell',    model: 'PowerEdge T550' },
  { make: 'Lenovo',  model: 'ThinkSystem SR650 V2' },
  { make: 'Lenovo',  model: 'ThinkSystem SR630 V3' },
  { make: 'Supermicro', model: 'SYS-1029U-TR4' },
  { make: 'Cisco',   model: 'UCS C220 M6' }
];

// Hostname-theme renderers — each takes a `prefix` (e.g. 'dc', 'fs', 'web')
// and an index, returns a themed hostname.
const HOSTNAME_RENDERERS = {
  'numbered classic (dc-01, fs-01, app-erp-01, sql-01)':
    (prefix, i) => `${prefix}-${String(i).padStart(2, '0')}`,
  'department-prefixed (acct-srv-01, hr-app-01, ops-db-01, sales-fs-01)':
    (prefix, i, ctx) => `${ctx.dept || 'corp'}-${prefix}-${String(i).padStart(2, '0')}`,
  'site-coded short-3 (sea-fs-01, dal-dc-01, nyc-app-01, hou-sql-01)':
    (prefix, i, ctx) => `${ctx.site || 'hq'}-${prefix}-${String(i).padStart(2, '0')}`,
  'project-codename (mercury-fs, apollo-dc, gemini-app, atlas-db)':
    (prefix, i, ctx) => `${ctx.codenames[(i - 1) % ctx.codenames.length]}-${prefix}-${String(i).padStart(2, '0')}`,
  'role + tier (web-tier-01, db-tier-01, app-tier-01, mid-tier-01)':
    (prefix, i) => `${prefix}-tier-${String(i).padStart(2, '0')}`,
  'function-noun (billing-svr, ticket-svr, dms-svr, archive-svr)':
    (prefix, i) => `${prefix}-svr-${String(i).padStart(2, '0')}`,
  'mythological (zeus-dc, hermes-mail, athena-app, hades-bak)':
    (prefix, i, ctx) => `${ctx.mythos[(i - 1) % ctx.mythos.length]}-${prefix}-${String(i).padStart(2, '0')}`,
  'planet/star (jupiter-dc, saturn-fs, vega-app, polaris-sql)':
    (prefix, i, ctx) => `${ctx.planets[(i - 1) % ctx.planets.length]}-${prefix}-${String(i).padStart(2, '0')}`
};
const CODENAME_POOLS = {
  codenames: ['mercury', 'apollo', 'gemini', 'atlas', 'orion', 'titan', 'pegasus', 'phoenix'],
  mythos:    ['zeus', 'hermes', 'athena', 'hades', 'apollo', 'odin', 'thor', 'freya'],
  planets:   ['jupiter', 'saturn', 'vega', 'polaris', 'sirius', 'rigel', 'altair', 'antares']
};

const SERVER_OS_POOL = [
  'Windows Server 2019 Standard 10.0.17763.5122',
  'Windows Server 2022 Standard 10.0.20348.2113',
  'Windows Server 2019 Datacenter 10.0.17763.5122',
  'Ubuntu Server 22.04.3 LTS',
  'Ubuntu Server 20.04.6 LTS',
  'Red Hat Enterprise Linux 8.8',
  'Debian 12.4 Bookworm'
];

// Build a deterministic server roster. ALWAYS includes web-01 so every
// company has a public-facing web server for the vuln-app pipeline.
// Other roles (dc, fs, sql, etc.) are picked based on client_type +
// employee_count so a 25-person firm doesn't get 12 servers.
function buildServerRoster(runId, opts = {}) {
  const { clientType = 'SMB', employeeCount = 50, hostnameTheme = 'numbered classic (dc-01, fs-01, app-erp-01, sql-01)' } = opts;
  const h = (salt) => hashStr(runId, salt);
  const renderer = HOSTNAME_RENDERERS[hostnameTheme] || HOSTNAME_RENDERERS['numbered classic (dc-01, fs-01, app-erp-01, sql-01)'];
  const ctx = { ...CODENAME_POOLS, site: ['sea','dal','nyc','hou','chi','phx','atl','den'][h('site') % 8], dept: 'corp' };

  // Decide which roles this company has based on size + type
  const roles = [];
  roles.push({ prefix: 'dc',    role_label: 'Domain Controller',          function: 'Primary Active Directory domain controller and DNS server',           windows: true });
  if (employeeCount >= 60) {
    roles.push({ prefix: 'dc',  role_label: 'Secondary Domain Controller', function: 'Secondary AD DC for failover and load balancing',                     windows: true });
  }
  roles.push({ prefix: 'fs',    role_label: 'File Server',                 function: 'Primary file share for all departments including project files',     windows: true });
  // Web is MANDATORY — every company gets one (the vuln-app pipeline deploys to it).
  roles.push({ prefix: 'web',   role_label: 'Web / App Server',            function: 'Internal web portal — used by staff for daily operations',           windows: false });
  if (clientType !== 'NonProfit') {
    roles.push({ prefix: 'sql', role_label: 'Database Server',             function: 'SQL Server backing the line-of-business application',                windows: true });
  }
  if (employeeCount >= 40) {
    roles.push({ prefix: 'app', role_label: 'Application Server',          function: 'Hosts the line-of-business / practice management application',       windows: true });
  }
  if (employeeCount >= 50) {
    roles.push({ prefix: 'rds', role_label: 'Remote Desktop Gateway',      function: 'RDS gateway for after-hours and remote staff access',                windows: true });
  }
  roles.push({ prefix: 'bak',   role_label: 'Backup Server',               function: 'Local backup target with offsite replication',                       windows: false });

  // Number duplicates per prefix
  const prefixCount = {};
  return roles.map(r => {
    prefixCount[r.prefix] = (prefixCount[r.prefix] || 0) + 1;
    const idx = prefixCount[r.prefix];
    const hostname = renderer(r.prefix, idx, ctx);
    const hw = SERVER_HARDWARE[h('hw' + hostname) % SERVER_HARDWARE.length];
    const osPool = r.windows
      ? SERVER_OS_POOL.filter(s => s.startsWith('Windows'))
      : SERVER_OS_POOL;
    const os = osPool[h('os' + hostname) % osPool.length];
    return {
      hostname,
      role: r.role_label,
      role_short: r.prefix,
      os,
      function: r.function,
      make: hw.make,
      model: hw.model,
      critical: r.prefix === 'dc' || r.prefix === 'fs' || r.prefix === 'sql' || r.prefix === 'app' || r.prefix === 'web'
    };
  });
}

/**
 * Build the per-run flavor packet. All anchors hashed from run_id with
 * different salts → independent random choice per dimension, but
 * deterministic given the run_id.
 */
function buildFlavorBundle(runId, stakeholderCount = 5) {
  const h = (salt) => hashStr(runId, salt);
  const firstNames = pickN(FIRST_NAMES, stakeholderCount, i => h('first' + i));
  const lastNames  = pickN(LAST_NAMES_DIVERSE, stakeholderCount, i => h('last' + i));
  const stakeholderNames = firstNames.map((f, i) => `${f} ${lastNames[i]}`);
  return {
    vendor_flavor:       VENDOR_FLAVORS[h('vendor') % VENDOR_FLAVORS.length],
    edr_product:         EDR_PRODUCTS[h('edr') % EDR_PRODUCTS.length],
    firewall_choice:     FIREWALL_VENDORS[h('fw') % FIREWALL_VENDORS.length],
    backup_product:      BACKUP_PRODUCTS[h('backup') % BACKUP_PRODUCTS.length],
    hostname_theme:      HOSTNAME_THEMES[h('hostnames') % HOSTNAME_THEMES.length],
    threat_actor_flavor: THREAT_ACTOR_FLAVORS[h('threat') % THREAT_ACTOR_FLAVORS.length],
    stakeholder_names:   stakeholderNames
  };
}

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

  // Deterministic company name: client-side, hashed from run_id. Bypasses the
  // model's convergence to "Meridian Strategic Advisors" entirely. Overrides
  // still win if explicitly supplied (e.g. real-client intake aliases).
  const effectiveCompanyName = overrides.company_name
    || generateCompanyName(seed.run_id, config.clientType);

  const companyNameRule = `Company name MUST be exactly: "${effectiveCompanyName}"`;
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
- At least 2 stakeholders should reference relationship_conflicts with named other stakeholders.

REALISM RULES (this is a training profile for student risk assessments — accuracy matters):
- annual_revenue_range MUST match headcount: <50 emp = mostly $1M-5M, 50-100 emp = $5M-25M, 100-250 emp = $25M-100M, 250+ = $100M+. Exceptions only for specific high-revenue-per-head industries (law/finance/tech consulting).
- Stakeholder roles must be PLAUSIBLE for the company size: a 25-person firm does NOT have a CISO, CIO, CTO, and Chief Data Officer — they have an "IT Manager" or "Office Manager doing IT". Add C-suite roles only at 100+ employees or specific industries (finance, healthcare).
- business_model: 2-3 sentences describing what the company actually DOES day-to-day, in plain language. NOT marketing-speak like "leveraging synergies to deliver value". Real example: "Wholesale distributor of plumbing supplies to contractors across Arizona and southern Nevada. Operates one warehouse with 12 trucks and an online portal for contractor accounts."
- past_incidents: REALISTIC and small-scale. An SMB does not have a "nation-state APT breach". They have things like "2023 — phishing (Medium): one employee clicked, MFA blocked the login, account locked for 20 min." or "2022 — service_outage (High): ransomware on accounting workstation, restored from backup in 6 hours, no data exfil confirmed".
- business_continuity: rpo_hours and rto_hours must match maturity. Low maturity: RPO 24h, RTO 48-72h. Intermediate: RPO 8-24h, RTO 24h. High: RPO 1-4h, RTO 4-8h. estimated_downtime_cost_per_hour ranges $500-2000/hr for SMB, $5000-25000/hr for mid-market.
- regulatory_timeline: include 1-2 SPECIFIC upcoming deadlines (e.g. "PCI-DSS quarterly scan due 2026-Q2", "annual HIPAA risk analysis due Sept 2026") — not vague "compliance review pending".
- department_breakdown should look HUMAN: a 30-person services firm has like {IT:1, Operations:18, Administration:4, Sales/Marketing:5, Other:2}, not perfectly-distributed 6/6/6/6/6.

STAKEHOLDER DETAIL (each must read like a real person):
- signature_quote: 1 sentence in their actual voice, with their concerns/personality. E.g. for IT Manager: "Honestly, half my day is just resetting passwords for the warehouse crew."
- concerns: 2-4 realistic worries from THEIR job perspective (not generic "cybersecurity is important"). CFO worries about wire fraud + finance audit; IT worries about ransomware + after-hours pages; HR worries about employee PII.
- hidden_info: must be SPECIFIC and useful for the student's investigation. NOT "knows things about the company" — instead "knows the old VPN account 'temp-admin' is still active from a 2019 consultant", or "remembers the warehouse manager shares one login across 4 forklift drivers".
- relationship_conflicts: name a specific other stakeholder and the friction. E.g. "Tension with Marcus Hayes (IT Mgr) — he keeps blocking my Dropbox install requests".
- shadow_it_knowledge: SPECIFIC tools — "Sales team uses a personal Trello board synced to a Dropbox shared with a former contractor's Gmail".

COMPANY NAMING — AVOID OVERUSED LLM-DEFAULT NAMES:
- DO NOT use these clichéd words in the company name: Meridian, Strategic, Advisors, Pinnacle, Summit, Apex, Horizon, Vertex, Capstone, Cornerstone, Synergy, Catalyst, Insight, Cipher, Sentinel, Nexus, Quantum, Acme, Acumen, Pivotal, Convergence, Paradigm.
- DO NOT use "Smith & Associates" or any "<surname> & Associates" pattern.
- DO pick from a wide vocabulary: real place names (towns, rivers, mountains, neighborhoods), unusual surnames, scientific or natural words (botanical, geological, astronomical), trade jargon for that industry, foreign-language words that fit the industry's cultural context.
- A good naming method: pick a real geographic feature within 500 miles of the HQ city + a plain industry noun (e.g. "Tumbleweed Manufacturing", "Coyote Creek Dental", "Buttermilk Springs Logistics", "Three Rivers Print Co"). Or pick a founder's likely surname (drawn from the regional ethnic mix) + a service noun ("Okafor Holdings", "Larsen Cabinetry", "Tran Family Pharmacy").
- The name should feel like a REAL company that's been around 5-30 years, not a startup pitch deck.`;

  const flavor = buildFlavorBundle(seed.run_id, stakeholderCount);
  const stakeholderNameBlock = flavor.stakeholder_names
    .map((n, i) => `  ${i + 1}. ${n}`)
    .join('\n');

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
stakeholder_count: EXACTLY ${stakeholderCount}

REQUIRED STAKEHOLDER NAMES — use these EXACT names (one per stakeholder, in this order):
${stakeholderNameBlock}
Assign roles, departments, and emails appropriately to each name — keep all other stakeholder content (concerns, hidden_info, conflicts) original and unique per person.`;

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
    "servers": [ { "hostname": "string", "os": "fully versioned string e.g. Windows Server 2019 Standard 10.0.17763", "role": "string", "make": "string e.g. HPE / Dell / Lenovo", "model": "string e.g. ProLiant DL360 Gen10 Plus", "function": "1 sentence describing what this server does day-to-day" } ],
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
- vendor_risk: 2–4 entries. At Low/Intermediate maturity, at least one must have "Never" as last_assessment.

REALISM RULES (this is a training profile for student risk assessments — accuracy matters more than perfection):
- Product TIER must match company size + budget. A 25-person professional-services firm does NOT run CrowdStrike Falcon Complete + Rubrik + Palo Alto Panorama. They run Microsoft 365 Business Premium + Defender, or Sophos Central, or Bitdefender GravityZone — and they backup to Synology/iDrive/Datto/Veeam Essentials.
- Patch compliance percent must be PLAUSIBLE for the maturity: Low ≤ 70%, Intermediate 70-90%, High 90-98%. Almost never 100%.
- Server COUNT scales with employee count: ~1 server per 10-20 employees for traditional shops, fewer for cloud-native. A 30-person firm should not have 12 on-prem servers.
- Endpoint OS mix should reflect real SMB patterns: most shops are 80-95% Windows; "all macOS" only for design/creative/dev studios under 30 people.
- vendor_risk entries should reference REAL vendor types (MSP, accountant, payroll provider, cloud backup, SaaS app, building access vendor) — not fictional placeholders.
- known_unknowns: include 2-4 genuine SMB gaps ("don't know how many shadow-IT apps employees are using", "unsure if all laptops have BitLocker", "no inventory of who has admin rights").
- BACKUP product MUST be realistic for the chosen ecosystem (do not pair Veeam Enterprise Edition with a 15-person dental office).
- saas[].sso_enabled is usually FALSE for SMB-tier shops unless they have an explicit SSO product like Okta/Entra/JumpCloud.
- saas[].mfa is realistically MIXED — not every SaaS app has MFA enforced; older line-of-business apps often don't.
- saas[].data_sensitivity should be realistic (CRM with customer data = High, internal wiki = Low).`;

  const flavor = buildFlavorBundle(seed.run_id);
  const roster = buildServerRoster(seed.run_id, {
    clientType: config.clientType, employeeCount, hostnameTheme: flavor.hostname_theme
  });
  const rosterBlock = roster.map(s =>
    `  - hostname: "${s.hostname}", role: "${s.role}", make: "${s.make}", model: "${s.model}", os: "${s.os}", function: "${s.function}"`
  ).join('\n');

  const userPrompt = `Generate the IT environment.

run_id: ${seed.run_id}
employees_total: ${employeeCount}
industry: ${industry}
critical_systems: ${criticalSystems.join(', ')}
delivery: ${seed.delivery || 'Hybrid'}
maturity: ${seed.maturity || 'Intermediate'}
difficulty: ${seed.difficulty || 'intermediate'}
total_endpoints_range: ${endpointMin}–${endpointMax}
deliberate_weaknesses_count: ${weaknessMin}–${weaknessMax}

VENDOR ECOSYSTEM (anchor for this company — bias your choices toward this stack):
  ${flavor.vendor_flavor}

REQUIRED PRODUCT ANCHORS — use these specific products (do NOT substitute):
  endpoint_protection.product: ${flavor.edr_product}
  backups.method-product: ${flavor.backup_product}

Other vendor/product choices (firewall, VPN, SaaS apps) should be CONSISTENT with the vendor ecosystem above — e.g. a Microsoft-heavy shop uses Microsoft 365 + OneDrive, an Apple-heavy shop uses Jamf + iCloud, a Cisco shop uses Webex + Cisco AnyConnect. AVOID always defaulting to the same SaaS lineup (Slack + Zoom + Google Drive). Pick a SaaS bundle that fits the anchored ecosystem.

REQUIRED SERVERS — your servers[] array MUST be EXACTLY this list, in this order, with these exact hostnames + make + model + os. You may write a more interesting function string per server but keep hostname/make/model/os/role verbatim:
${rosterBlock}
Do NOT add extra servers. Do NOT rename them. Do NOT omit any.`;

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
  const employeeCount = seed.employees?.max || seed.employees?.min || seed.endpoint_count || 50;

  // Build the SAME roster used by the IT branch so both branches produce
  // identical server lists. Without this they invent independent server
  // names and the IT/Assets/Network-Diagram tabs disagree.
  const _flavor = buildFlavorBundle(seed.run_id);
  const roster = buildServerRoster(seed.run_id, {
    clientType: config.clientType, employeeCount, hostnameTheme: _flavor.hostname_theme
  });

  // Challenge network mode — forces real VM IPs to be used as-is
  const cnData = config?.challenge_network;
  const isChallenge = cnData?.is_challenge === true;
  const realAssets = cnData?.real_assets || [];
  let challengeSection = '';
  let serversBlock = roster.map(s =>
    `- ${s.hostname} (${s.role}, ${s.make} ${s.model}, ${s.os})`
  ).join('\n');

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
- diagram_text field is FORBIDDEN — do not emit it.

REALISM RULES (this is a training profile for student risk assessments):
- Subnet count and VLAN sophistication must match maturity. Low-maturity shops often have a FLAT network (just LAN + Guest WiFi); high-maturity shops have proper segmentation.
- assets[].os should be REALISTIC versions actually still in production: Windows 10 22H2 (very common), Windows 11 23H2, Ubuntu 22.04 LTS, Windows Server 2019/2022, macOS 14 Sonoma. Avoid years-old patch levels unless the deliberate weakness is "running unpatched OS".
- Public IP from RFC 5737 (203.0.113.x — already provided). Do NOT use real-world public IPs.
- Firewall rules: real SMBs have UNTIDY rule lists with descriptive but inconsistent names. Some rules will have weakness baked in (port 3389 RDP open to ANY, SMB outbound allowed everywhere, MGMT access not restricted to MGMT subnet). At least 2 rules should look like "added by Bob in 2022 — purpose unclear".
- assets[].function field should be human-readable role descriptions, not technical jargon. E.g. "Primary file share for Accounting + HR" not just "SMB share".
- assets[].critical=true for ANY server hosting customer data, financial systems, or being the only DC/file share. Aim for ~30% critical assets.`;

  const flavor = buildFlavorBundle(seed.run_id);

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

SERVERS (in Servers subnet) — your assets[] entries with role="server" MUST be EXACTLY this list, in this order, with these exact hostnames + os. The function field can be expanded but hostnames/os are verbatim:
${serversBlock}
Do NOT add extra servers. Do NOT rename. Do NOT omit. Assign sequential IPs within the Servers subnet starting at .10.
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
- ≥1 related to VPN/remote access.

REQUIRED FIREWALL ANCHOR — use this EXACT firewall hardware (do NOT substitute):
  firewall.vendor:   ${flavor.firewall_choice.vendor}
  firewall.model:    ${flavor.firewall_choice.model}
  firewall.firmware: ${flavor.firewall_choice.firmware}

HOSTNAME THEME — use this naming convention for server + workstation hostnames:
  ${flavor.hostname_theme}
Apply consistently across ALL hostnames in this network (servers, workstations, network gear).`;

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

  const flavor = buildFlavorBundle(seed.run_id);

  const userPrompt = `Generate the threat profile.

run_id: ${seed.run_id}
industry: ${industry}
risks_to_cover: ${risks.join(', ')}
maturity: ${seed.maturity || 'Intermediate'}
difficulty: ${difficulty}
scenarios_count: ${range.min}–${range.max}

PRIMARY THREAT-ACTOR FLAVOR for this company (anchor at LEAST one scenario to this archetype):
  ${flavor.threat_actor_flavor}

Other scenarios should still vary across the kill chain but avoid defaulting to generic "ransomware affiliate" every time — vary actor motives, sophistication, and dwell times.

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
  generateCompanyName,
  pickNamingSeed,
  buildFlavorBundle,
  buildServerRoster,
  NAMING_SEEDS,
  SUFFIX_POOLS,
  VENDOR_FLAVORS,
  HOSTNAME_THEMES,
  FIREWALL_VENDORS,
  THREAT_ACTOR_FLAVORS,
  SYS_HEADER
};
