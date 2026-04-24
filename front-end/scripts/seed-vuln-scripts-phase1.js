#!/usr/bin/env node
/**
 * seed-vuln-scripts-phase1.js
 *
 * One-shot loader that UPSERTs the Phase-1 vuln-script set into vuln_scripts
 * (clinic_db). Reads canonical .ps1 content from ../vuln-scripts/ so the
 * files on disk are the source of truth — re-running this script after you
 * edit a .ps1 will push the new content to the DB.
 *
 * Usage:
 *   cd front-end
 *   node scripts/seed-vuln-scripts-phase1.js           # UPSERT all
 *   node scripts/seed-vuln-scripts-phase1.js --dry-run # preview without writing
 *
 * Env:
 *   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD — same as the app
 */

const path = require('path');
const fs = require('fs');
const { pool } = require('../src/utils/db');

const SCRIPTS_DIR = path.join(__dirname, '..', 'vuln-scripts');
const DRY_RUN = process.argv.includes('--dry-run');

// slug -> metadata. script_content is read from `${slug}.ps1` on disk.
// script_type: 'baseline' = standard service config, no baked-in vulns;
//              'vulnerable' = deliberate weakness injection.
const CATALOG = [
  {
    slug: 'init-setup',
    file: 'init-setup.ps1',
    name: 'Lab Bootstrap',
    description: 'Execution policy, firewall basics, lab directory tree, ICMP enable, student accounts. Foundation for every other script.',
    category: 'Initial Setup',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: [],
    depends_on: [],
    estimated_runtime_sec: 20
  },
  // --- Baseline service configs (prefer for real-client intakes) ---
  {
    slug: 'smb-baseline',
    file: 'smb-baseline.ps1',
    name: 'SMB (Standard-Secure)',
    description: 'Public + Users shares with authenticated-only access. SMB1 disabled, signing required, null sessions blocked. No vulns.',
    category: 'Network Services',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: ['445/SMB'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 20
  },
  {
    slug: 'rdp-baseline',
    file: 'rdp-baseline.ps1',
    name: 'RDP (Standard-Secure)',
    description: 'RDP on 3389 with NLA required, TLS security layer, high encryption. Only the student account granted access.',
    category: 'Network Services',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: ['3389/RDP'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 10
  },
  {
    slug: 'ssh-baseline',
    file: 'ssh-baseline.ps1',
    name: 'OpenSSH (Standard)',
    description: 'Installs OpenSSH Server Windows capability, starts sshd with stock config, opens port 22. No seeded keys or relaxed auth.',
    category: 'Network Services',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: ['22/SSH'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 90
  },
  {
    slug: 'winrm-baseline',
    file: 'winrm-baseline.ps1',
    name: 'WinRM HTTPS (Hardened)',
    description: 'HTTPS listener on 5986 with self-signed cert, Kerberos/Negotiate only, Basic auth denied, unencrypted transport denied.',
    category: 'Network Services',
    script_type: 'baseline',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: ['5986/WinRM-HTTPS'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 30
  },
  // --- Vulnerable variants (deliberate weakness injection) ---
  {
    slug: 'rdp-config',
    file: 'rdp-config.ps1',
    name: 'RDP Insecure Listener',
    description: 'Enables RDP on 3389, disables NLA, drops to RDP security layer, grants student+svcbackup access. Classic brute-force / PtH target.',
    category: 'Network Services',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: ['3389/RDP'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 15
  },
  {
    slug: 'winrm-http',
    file: 'winrm-http.ps1',
    name: 'WinRM HTTP Listener',
    description: 'Bootstraps PSRemoting, creates unencrypted 5985 listener, enables Basic auth and TrustedHosts=*. Exposes remote code execution via auth.',
    category: 'Network Services',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: ['5985/WinRM'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 20
  },
  {
    slug: 'ftp-anonymous',
    file: 'ftp-anonymous.ps1',
    name: 'IIS FTP (Anonymous R/W)',
    description: 'Installs IIS FTP role, configures a public site on port 21 with anonymous read+write, seeds plaintext credential files. SSL disabled.',
    category: 'Network Services',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: ['21/FTP'],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 180
  },
  {
    slug: 'vulnerable-registry',
    file: 'vulnerable-registry.ps1',
    name: 'Registry Privesc Playground',
    description: 'AlwaysInstallElevated=1, plaintext AutoAdminLogon, writable Run key ACL, silent UAC for admins, CachedLogonsCount=25. Multiple privesc angles.',
    category: 'Privilege Escalation',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: [],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 15
  },
  {
    slug: 'cached-credentials',
    file: 'cached-credentials.ps1',
    name: 'Plaintext Credentials Hunt',
    description: 'Seeds credential artifacts in the 6 most common places: unattend.xml, GPP cpassword, nightly-backup.bat, WinSCP.ini, machine env var, PSReadLine history.',
    category: 'Credential Access',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: [],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 10
  },
  {
    slug: 'defender-weaken',
    file: 'defender-weaken.ps1',
    name: 'Defender Downgrade',
    description: 'Path/extension/process exclusions for lab folders, disables real-time + behavior + script scanning, disables PUA and cloud sampling.',
    category: 'Defense Evasion',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'beginner',
    services_exposed: [],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 15
  },
  {
    slug: 'event-log-reduction',
    file: 'event-log-reduction.ps1',
    name: 'Log Retention Minimized',
    description: 'Shrinks Application/Security/System logs to 1MB each, disables PS script-block + module logging, disables 4688 cmdline auditing, clears existing logs.',
    category: 'Defense Evasion',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: [],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 15
  },
  {
    slug: 'scheduled-task-privesc',
    file: 'scheduled-task-privesc.ps1',
    name: 'Writable Scheduled Tasks',
    description: 'Two SYSTEM scheduled tasks (LabHealthCheck every 15m, LabDeploy at-logon) backed by Users-writable script/batch files for classic task-hijack privesc.',
    category: 'Privilege Escalation',
    script_type: 'vulnerable',
    os_target: 'windows',
    difficulty: 'intermediate',
    services_exposed: [],
    depends_on: ['init-setup'],
    estimated_runtime_sec: 15
  }
];

async function main() {
  console.log(`\n[seed] Reading from ${SCRIPTS_DIR}${DRY_RUN ? ' (DRY RUN)' : ''}\n`);

  const results = [];
  for (const entry of CATALOG) {
    const filePath = path.join(SCRIPTS_DIR, entry.file);
    if (!fs.existsSync(filePath)) {
      console.error(`  ✗ ${entry.slug.padEnd(28)} — missing file ${entry.file}`);
      results.push({ slug: entry.slug, status: 'missing_file' });
      continue;
    }
    const content = fs.readFileSync(filePath, 'utf-8');

    if (DRY_RUN) {
      console.log(`  • ${entry.slug.padEnd(28)} ${content.length.toString().padStart(5)} bytes  [${entry.category}]`);
      results.push({ slug: entry.slug, status: 'dry_run', bytes: content.length });
      continue;
    }

    try {
      const r = await pool.query(
        `INSERT INTO vuln_scripts
           (slug, name, description, category, script_type, os_target, difficulty,
            script_content, services_exposed, depends_on, estimated_runtime_sec, is_active)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,true)
         ON CONFLICT (slug) DO UPDATE SET
           name                  = EXCLUDED.name,
           description           = EXCLUDED.description,
           category              = EXCLUDED.category,
           script_type           = EXCLUDED.script_type,
           os_target             = EXCLUDED.os_target,
           difficulty            = EXCLUDED.difficulty,
           script_content        = EXCLUDED.script_content,
           services_exposed      = EXCLUDED.services_exposed,
           depends_on            = EXCLUDED.depends_on,
           estimated_runtime_sec = EXCLUDED.estimated_runtime_sec,
           is_active             = true
         RETURNING (xmax = 0) AS inserted`,
        [
          entry.slug, entry.name, entry.description, entry.category,
          entry.script_type || 'vulnerable',
          entry.os_target, entry.difficulty, content,
          JSON.stringify(entry.services_exposed),
          entry.depends_on, entry.estimated_runtime_sec
        ]
      );
      const inserted = r.rows[0]?.inserted;
      console.log(`  ${inserted ? '+' : '~'} ${entry.slug.padEnd(28)} ${content.length.toString().padStart(5)} bytes  ${inserted ? 'inserted' : 'updated '}  [${entry.category}]`);
      results.push({ slug: entry.slug, status: inserted ? 'inserted' : 'updated', bytes: content.length });
    } catch (err) {
      console.error(`  ✗ ${entry.slug.padEnd(28)} — ${err.message}`);
      results.push({ slug: entry.slug, status: 'error', error: err.message });
    }
  }

  const ok = results.filter(r => r.status === 'inserted' || r.status === 'updated').length;
  const dry = results.filter(r => r.status === 'dry_run').length;
  const err = results.filter(r => r.status === 'error' || r.status === 'missing_file').length;
  console.log(`\n[seed] done. ${ok} written, ${dry} previewed, ${err} failed.`);

  await pool.end();
  process.exit(err === 0 ? 0 : 1);
}

main().catch(err => {
  console.error('[seed] fatal:', err);
  process.exit(2);
});
