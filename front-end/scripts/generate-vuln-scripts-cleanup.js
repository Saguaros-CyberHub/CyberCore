#!/usr/bin/env node
/**
 * generate-vuln-scripts-cleanup.js
 *
 * Emits a single SQL file that:
 *   1. UPDATEs the 14 existing rows in vuln_scripts with cleaned metadata
 *      (name, description, category, difficulty, services_exposed, script_type,
 *       estimated_runtime_sec, script_args). script_content is NEVER touched.
 *   2. INSERTs the 13 new Phase-1 scripts with full content read from
 *      ../vuln-scripts/*.ps1. Uses ON CONFLICT (slug) DO UPDATE so re-running
 *      is idempotent.
 *
 * Run: cd front-end && node scripts/generate-vuln-scripts-cleanup.js
 * Output: front-end/vuln-scripts/vuln_scripts_cleaned.sql
 */

const path = require('path');
const fs = require('fs');

const VULN_DIR = path.join(__dirname, '..', 'vuln-scripts');
const OUT_PATH = path.join(VULN_DIR, 'vuln_scripts_cleaned.sql');

// --- Cleaned metadata for existing rows (matched by slug) -------------------
const EXISTING_UPDATES = [
  {
    slug: 'win-artifact',
    name: 'DunderCorp Artifacts (Users/Ops)',
    description: 'Seeds realistic user + ops artifacts under C:\\ProgramData\\DunderCorp\\Artifacts (Creds/Logs/Configs/Exports/Notes/Transcripts) plus USER2/ADMIN PSReadLine history and LabShare drops. Supports -Setup, -Verify, and -Reset.',
    category: 'User Simulation',
    difficulty: 'intermediate',
    services_exposed: [],
    script_type: 'baseline',
    estimated_runtime_sec: 60,
    script_args: '-Setup'
  },
  {
    slug: 'winrm',
    name: 'WinRM Insecure Exposure',
    description: 'Enables PSRemoting, sets WinRM to autostart, and adds a non-admin (default USER2) to Remote Management Users. Default path: HTTP listener on 5985. With -EnableHttps: self-signed cert + HTTPS listener on 5986 + firewall rule. Intended for vuln-lab use; not a hardened baseline.',
    category: 'Network Services',
    difficulty: 'intermediate',
    services_exposed: ['5985/WinRM', '5986/WinRM-HTTPS'],
    script_type: 'vulnerable',
    estimated_runtime_sec: 30,
    script_args: ''
  },
  {
    slug: 'win-smb-null-session',
    name: 'SMB (Null Session Enabled)',
    description: 'Provisions the Public/Users/Drop/Legacy SMB share layout and explicitly enables null-session access (RestrictNullSessAccess=0, RestrictAnonymous=0, NullSessionShares=Public) so unauthenticated enumeration of shares and pipes is possible. Seeds share content for discovery.',
    category: 'Network Services',
    difficulty: 'beginner',
    services_exposed: ['445/SMB'],
    script_type: 'vulnerable',
    estimated_runtime_sec: 30,
    script_args: ''
  },
  {
    slug: 'win-persistence',
    name: 'DunderCorp Persistence Trio',
    description: 'Creates three persistence artifacts: HKLM Run entry DunderOpsUpdate (wscript.exe opshelper.vbs), Startup-folder CMD DunderStartup.cmd, and SYSTEM scheduled task DunderUserEnvSync (userenv_sync.ps1 on-logon). Stages supporting files under C:\\ProgramData\\DunderCorp\\Persistence with read-only ACLs; supports -Verify and -Reset.',
    category: 'Persistence',
    difficulty: 'intermediate',
    services_exposed: [],
    script_type: 'vulnerable',
    estimated_runtime_sec: 45,
    script_args: ''
  },
  {
    slug: 'win-priv-esc',
    name: 'DunderCorp Privilege Escalation Lab',
    description: 'Two SYSTEM execution rails for privesc: scheduled task DunderCacheRefresh (refresh_cache.ps1 every minute as SYSTEM) and weak service DunderTelemetry (ImagePath executes telemetry_service.ps1 as LocalSystem). preflight.ps1, refresh_cache.ps1, and the DunderTelemetry service registry key are deliberately user-modifiable for classic hijack-and-wait privesc.',
    category: 'Privilege Escalation',
    difficulty: 'intermediate',
    services_exposed: [],
    script_type: 'vulnerable',
    estimated_runtime_sec: 45,
    script_args: ''
  },
  {
    slug: 'win-life-artifacts',
    name: 'User Simulation (USER2 + ADMIN)',
    description: 'Creates USER2 (standard) and ADMIN (local administrator) accounts, seeds realistic profile content (VPN notes, hostname lists, inventory CSVs, maintenance notes) plus shared C:\\LabShare and C:\\ProgramData\\Ops drops. Pure realism, no vuln injection.',
    category: 'User Simulation',
    difficulty: 'beginner',
    services_exposed: [],
    script_type: 'baseline',
    estimated_runtime_sec: 60,
    script_args: ''
  },
  {
    slug: 'win-owasp-setup',
    name: 'OWASP Apps Setup',
    description: 'Extracts Java 23 + Node.js, verifies WebGoat / Juice Shop / VulnServer downloads from C:\\LabApps\\installers, installs Node via MSI, opens firewall on 8080/3000/9999, and persists runtime config to C:\\LabApps\\state\\runtime.json. Requires owasp-download to have run first.',
    category: 'Web Server',
    difficulty: 'intermediate',
    services_exposed: ['8080/WebGoat', '3000/JuiceShop', '9091/WebWolf', '9999/VulnServer'],
    script_type: 'baseline',
    estimated_runtime_sec: 600,
    script_args: '-Setup'
  },
  {
    slug: 'win-install-480-services',
    name: 'MedAlliance T1 (Full Stack)',
    description: 'Tier-1 MedAlliance lab: IIS (80 corporate landing + 8080 Health Monitor dashboard), IIS FTP (21 anonymous read on /logs), SQL Server Express (SA=SQLAdmin2024!, xp_cmdshell enabled, hr_database with 20 employees + payroll + system_credentials), WinRM (5985), RDP (3389). Branches Server vs. Client SKUs; SQL section auto-skips if no MSSQL service present.',
    category: 'Composite Lab',
    difficulty: 'advanced',
    services_exposed: ['80/HTTP', '8080/HealthMonitor', '21/FTP', '1433/MSSQL', '5985/WinRM', '3389/RDP', '445/SMB'],
    script_type: 'vulnerable',
    estimated_runtime_sec: 600,
    script_args: ''
  },
  {
    slug: 'win-dundercorp-full-path-1',
    name: 'DunderCorp Attack Path (Part 1)',
    description: 'Combined orchestrator for the DunderCorp Part-1 challenge narrative. Stages users, shares, persistence, privesc, and credential artifacts in one run.',
    category: 'Composite Lab',
    difficulty: 'advanced',
    services_exposed: [],
    script_type: 'vulnerable',
    estimated_runtime_sec: 600,
    script_args: ''
  },
  {
    slug: 'win-480-artifacts',
    name: 'MedAlliance T1 Artifacts',
    description: 'Plants per-student unique proof files, breadcrumb docs, and loot content for the MedAlliance Tier-1 challenge. Depends on the shares + users scripts having run first.',
    category: 'User Simulation',
    difficulty: 'intermediate',
    services_exposed: [],
    script_type: 'vulnerable',
    estimated_runtime_sec: 120,
    script_args: ''
  },
  {
    slug: 'win-480-config-users',
    name: 'MedAlliance T1 Users',
    description: "Creates m.chen (standard, RDP + WinRM groups, password MedAlliance2024! matching the Linux loot), MedHealthSvc service account, sets a strong Administrator password only reachable via privesc, drops a cmdkey saved-credential artifact, and writes personal_notes.txt in m.chen's Documents with passwords jotted down (realistic sticky-note pattern).",
    category: 'User Simulation',
    difficulty: 'intermediate',
    services_exposed: [],
    script_type: 'vulnerable',
    estimated_runtime_sec: 45,
    script_args: ''
  },
  {
    slug: 'win-480-config-shares',
    name: 'MedAlliance T1 Shares',
    description: 'Creates SMB shares populated with realistic corporate documents (financial reports, HR records, IT runbooks) laced with planted credentials, internal hostnames, and sensitive data for the MedAlliance Tier-1 challenge.',
    category: 'Data Exfiltration',
    difficulty: 'intermediate',
    services_exposed: ['445/SMB'],
    script_type: 'vulnerable',
    estimated_runtime_sec: 60,
    script_args: ''
  },
  {
    slug: 'win-start-ssh',
    name: 'SSH (Start Service)',
    description: 'Enables the sshd service with automatic startup, ensures DefaultShell is PowerShell, and reports port-22 listen status. No vulnerabilities injected.',
    category: 'Network Services',
    difficulty: 'beginner',
    services_exposed: ['22/SSH'],
    script_type: 'baseline',
    estimated_runtime_sec: 15,
    script_args: ''
  },
  {
    slug: 'win-owasp-start',
    name: 'OWASP Apps Start',
    description: 'Starts WebGoat (8080), Juice Shop (3000), and VulnServer (9999) after owasp-setup has provisioned them. Uses launcher scripts under C:\\LabApps\\state and tails logs for readiness checks.',
    category: 'Web Server',
    difficulty: 'intermediate',
    services_exposed: ['8080/WebGoat', '3000/JuiceShop', '9091/WebWolf', '9999/VulnServer'],
    script_type: 'baseline',
    estimated_runtime_sec: 60,
    script_args: '-Start'
  }
];

// --- New Phase-1 scripts (content read from ../vuln-scripts/*.ps1) ---------
const NEW_SCRIPTS = [
  {
    slug: 'init-setup', file: 'init-setup.ps1',
    name: 'Lab Bootstrap',
    description: 'Execution policy, firewall basics, lab directory tree (C:\\Lab / LabApps / LabShare), ICMP allow, high-perf power plan, student + svcbackup accounts. Foundation for every other script.',
    category: 'Initial Setup', script_type: 'baseline', difficulty: 'beginner',
    services_exposed: [], depends_on: [], estimated_runtime_sec: 20, script_args: ''
  },
  {
    slug: 'smb-baseline', file: 'smb-baseline.ps1',
    name: 'SMB (Standard-Secure)',
    description: 'Public + Users shares with authenticated-only access, SMB signing required, SMB1 disabled, null sessions blocked. Clean baseline for real-client synthesis.',
    category: 'Network Services', script_type: 'baseline', difficulty: 'beginner',
    services_exposed: ['445/SMB'], depends_on: ['init-setup'], estimated_runtime_sec: 20, script_args: ''
  },
  {
    slug: 'rdp-baseline', file: 'rdp-baseline.ps1',
    name: 'RDP (Standard-Secure)',
    description: 'RDP on 3389 with NLA required, TLS security layer, high encryption. Only the student account granted access.',
    category: 'Network Services', script_type: 'baseline', difficulty: 'beginner',
    services_exposed: ['3389/RDP'], depends_on: ['init-setup'], estimated_runtime_sec: 10, script_args: ''
  },
  {
    slug: 'ssh-baseline', file: 'ssh-baseline.ps1',
    name: 'OpenSSH (Standard)',
    description: 'Installs OpenSSH Server Windows capability, starts sshd + ssh-agent with stock config, opens port 22. No seeded keys or relaxed auth.',
    category: 'Network Services', script_type: 'baseline', difficulty: 'beginner',
    services_exposed: ['22/SSH'], depends_on: ['init-setup'], estimated_runtime_sec: 90, script_args: ''
  },
  {
    slug: 'winrm-baseline', file: 'winrm-baseline.ps1',
    name: 'WinRM HTTPS (Hardened)',
    description: 'HTTPS listener on 5986 with self-signed cert, Kerberos + Negotiate auth only, Basic auth denied, unencrypted transport denied. Removes the default HTTP listener.',
    category: 'Network Services', script_type: 'baseline', difficulty: 'intermediate',
    services_exposed: ['5986/WinRM-HTTPS'], depends_on: ['init-setup'], estimated_runtime_sec: 30, script_args: ''
  },
  {
    slug: 'rdp-config', file: 'rdp-config.ps1',
    name: 'RDP (NLA Off)',
    description: 'Enables RDP on 3389, disables NLA, drops to RDP security layer with low encryption, grants student + svcbackup access. Classic brute-force / PtH target.',
    category: 'Network Services', script_type: 'vulnerable', difficulty: 'beginner',
    services_exposed: ['3389/RDP'], depends_on: ['init-setup'], estimated_runtime_sec: 15, script_args: ''
  },
  {
    slug: 'winrm-http', file: 'winrm-http.ps1',
    name: 'WinRM HTTP (Unencrypted + Basic)',
    description: 'Bootstraps PSRemoting with an unencrypted 5985 listener, enables Basic auth + TrustedHosts=*. Exposes WinRM to trivial credential-based RCE.',
    category: 'Network Services', script_type: 'vulnerable', difficulty: 'intermediate',
    services_exposed: ['5985/WinRM'], depends_on: ['init-setup'], estimated_runtime_sec: 20, script_args: ''
  },
  {
    slug: 'ftp-anonymous', file: 'ftp-anonymous.ps1',
    name: 'IIS FTP (Anonymous R/W)',
    description: 'Installs IIS FTP role, configures a public site on 21 with anonymous read + write, SSL disabled, seeds plaintext credential files under the FTP root.',
    category: 'Network Services', script_type: 'vulnerable', difficulty: 'intermediate',
    services_exposed: ['21/FTP'], depends_on: ['init-setup'], estimated_runtime_sec: 180, script_args: ''
  },
  {
    slug: 'vulnerable-registry', file: 'vulnerable-registry.ps1',
    name: 'Registry Privesc Playground',
    description: 'AlwaysInstallElevated=1 in both hives, plaintext AutoAdminLogon, Users-writable HKLM Run key ACL, silent UAC for admins, CachedLogonsCount=25 (more DCC2 hashes on disk).',
    category: 'Privilege Escalation', script_type: 'vulnerable', difficulty: 'intermediate',
    services_exposed: [], depends_on: ['init-setup'], estimated_runtime_sec: 15, script_args: ''
  },
  {
    slug: 'cached-credentials', file: 'cached-credentials.ps1',
    name: 'Plaintext Credentials Hunt',
    description: 'Seeds credential artifacts in six common places: unattend.xml (Panther), GPP Groups.xml cpassword, nightly-backup.bat net-use, WinSCP.ini, machine-level DB_PASSWORD env var, PSReadLine history with embedded creds.',
    category: 'Credential Access', script_type: 'vulnerable', difficulty: 'beginner',
    services_exposed: [], depends_on: ['init-setup'], estimated_runtime_sec: 10, script_args: ''
  },
  {
    slug: 'defender-weaken', file: 'defender-weaken.ps1',
    name: 'Defender Downgrade',
    description: 'Path / extension / process exclusions for lab folders, disables real-time + behavior + script + archive scanning, disables PUA + cloud sampling. Retains Defender presence so the box still looks protected on a cursory check.',
    category: 'Defense Evasion', script_type: 'vulnerable', difficulty: 'beginner',
    services_exposed: [], depends_on: ['init-setup'], estimated_runtime_sec: 15, script_args: ''
  },
  {
    slug: 'event-log-reduction', file: 'event-log-reduction.ps1',
    name: 'Log Retention Minimized',
    description: 'Shrinks Application / Security / System / Setup logs to 1MB each, disables PS script-block + module logging, disables 4688 cmdline auditing, clears existing logs, disables Sysmon if present.',
    category: 'Defense Evasion', script_type: 'vulnerable', difficulty: 'intermediate',
    services_exposed: [], depends_on: ['init-setup'], estimated_runtime_sec: 15, script_args: ''
  },
  {
    slug: 'scheduled-task-privesc', file: 'scheduled-task-privesc.ps1',
    name: 'Writable Scheduled Tasks',
    description: 'Two SYSTEM scheduled tasks (LabHealthCheck every 15m, LabDeploy at logon) backed by Users-writable script and .bat files for classic task-hijack privesc; grants Users read on the Tasks folder for enumeration.',
    category: 'Privilege Escalation', script_type: 'vulnerable', difficulty: 'intermediate',
    services_exposed: [], depends_on: ['init-setup'], estimated_runtime_sec: 15, script_args: ''
  }
];

// --- Helpers ---------------------------------------------------------------
function sqlString(s) {
  if (s === null || s === undefined) return 'NULL';
  return `'${String(s).replace(/'/g, "''")}'`;
}
function sqlArray(arr) {
  // pg text[] literal — wraps each element in double-quotes if needed
  if (!arr || arr.length === 0) return `'{}'`;
  const escaped = arr.map(s => `"${String(s).replace(/"/g, '\\"')}"`).join(',');
  return `'{${escaped}}'`;
}
function sqlJsonbArray(arr) {
  return `'${JSON.stringify(arr || []).replace(/'/g, "''")}'::jsonb`;
}
function dollarQuote(tag, content) {
  // Dollar-quote so backslashes / PowerShell $vars / quotes all pass through.
  // Caller is responsible for a unique tag that cannot appear in content.
  return `$${tag}$${content}$${tag}$`;
}

// --- Emit ------------------------------------------------------------------
let out = '';
out += '-- =========================================================================\n';
out += '-- vuln_scripts_cleaned.sql\n';
out += '-- Auto-generated by front-end/scripts/generate-vuln-scripts-cleanup.js\n';
out += `-- Generated ${new Date().toISOString()}\n`;
out += '-- Run this AFTER importing vuln_scripts (1).sql.\n';
out += '--\n';
out += '-- PART 1: UPDATE metadata on existing rows (script_content untouched).\n';
out += '-- PART 2: INSERT 13 new Phase-1 scripts (idempotent via ON CONFLICT).\n';
out += '-- =========================================================================\n';
out += 'BEGIN;\n\n';

// PART 1 — metadata updates
out += '-- ---------- PART 1: metadata cleanup on existing rows ----------\n\n';
for (const e of EXISTING_UPDATES) {
  out += `UPDATE vuln_scripts SET\n`;
  out += `  name                  = ${sqlString(e.name)},\n`;
  out += `  description           = ${sqlString(e.description)},\n`;
  out += `  category              = ${sqlString(e.category)},\n`;
  out += `  difficulty            = ${sqlString(e.difficulty)},\n`;
  out += `  services_exposed      = ${sqlJsonbArray(e.services_exposed)},\n`;
  out += `  script_type           = ${sqlString(e.script_type)},\n`;
  out += `  estimated_runtime_sec = ${e.estimated_runtime_sec},\n`;
  out += `  script_args           = ${sqlString(e.script_args)}\n`;
  out += `WHERE slug = ${sqlString(e.slug)};\n\n`;
}

// PART 2 — new scripts
out += '-- ---------- PART 2: new Phase-1 scripts ----------\n\n';
for (const s of NEW_SCRIPTS) {
  const filePath = path.join(VULN_DIR, s.file);
  if (!fs.existsSync(filePath)) {
    console.error(`[gen] missing ${s.file}`); process.exit(1);
  }
  const content = fs.readFileSync(filePath, 'utf-8');
  const tag = s.slug.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  if (content.includes(`$${tag}$`)) {
    console.error(`[gen] tag collision for ${s.slug} — content contains $${tag}$`); process.exit(1);
  }
  out += `INSERT INTO vuln_scripts (slug, name, description, category, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec, is_active, script_args, script_type) VALUES (\n`;
  out += `  ${sqlString(s.slug)},\n`;
  out += `  ${sqlString(s.name)},\n`;
  out += `  ${sqlString(s.description)},\n`;
  out += `  ${sqlString(s.category)},\n`;
  out += `  'windows',\n`;
  out += `  ${sqlString(s.difficulty)},\n`;
  out += `  ${dollarQuote(tag, content)},\n`;
  out += `  ${sqlJsonbArray(s.services_exposed)},\n`;
  out += `  ${sqlArray(s.depends_on)},\n`;
  out += `  ${s.estimated_runtime_sec},\n`;
  out += `  true,\n`;
  out += `  ${sqlString(s.script_args)},\n`;
  out += `  ${sqlString(s.script_type)}\n`;
  out += `)\n`;
  out += `ON CONFLICT (slug) DO UPDATE SET\n`;
  out += `  name                  = EXCLUDED.name,\n`;
  out += `  description           = EXCLUDED.description,\n`;
  out += `  category              = EXCLUDED.category,\n`;
  out += `  difficulty            = EXCLUDED.difficulty,\n`;
  out += `  script_content        = EXCLUDED.script_content,\n`;
  out += `  services_exposed      = EXCLUDED.services_exposed,\n`;
  out += `  depends_on            = EXCLUDED.depends_on,\n`;
  out += `  estimated_runtime_sec = EXCLUDED.estimated_runtime_sec,\n`;
  out += `  is_active             = true,\n`;
  out += `  script_args           = EXCLUDED.script_args,\n`;
  out += `  script_type           = EXCLUDED.script_type;\n\n`;
}

out += 'COMMIT;\n';

fs.writeFileSync(OUT_PATH, out, 'utf-8');
console.log(`[gen] wrote ${OUT_PATH}`);
console.log(`[gen] ${EXISTING_UPDATES.length} UPDATEs + ${NEW_SCRIPTS.length} INSERTs, total ${out.length} bytes`);
