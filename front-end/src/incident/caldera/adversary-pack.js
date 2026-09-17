'use strict';

/**
 * CyberCore profiles declare intent and resolve IDs against the live catalog.
 * Atomic hashes the entire test object, so upstream edits change its ability ID.
 * Exact technique + plugin + name selectors prevent a different test (possibly
 * requiring downloads, credentials, or destructive defaults) replacing intent.
 * Unresolved steps are reported; the seeding route refuses partial profiles.
 *
 * Names reviewed against Atomic Red Team 388942adbd9641f4dfdcf079d7efe9a75ec0ac43
 * (in infrastructure/caldera/Dockerfile) and Stockpile
 * 08f37d8c1c5325910176d9fbaf9a83efccafd96c (Caldera 5.3.0). Pinned metadata is
 * retained in test/fixtures/caldera-pack-catalog.json. No generated IDs are
 * embedded in selectors. This module never executes commands or accesses a lane.
 */
const { v5: uuidv5 } = require('uuid');
const { normalizeAbility } = require('./adversary');

// Never change the namespace or existing keys: these identify seeded profiles.
const PACK_NAMESPACE = 'f3c1b27e-58a4-4d6b-9e30-7a1c5d0b8f42';
const NAME_PREFIX = 'CyberCore: ';
const atomic = (technique, abilityName) => ({ technique, plugin: 'atomic', abilityName });
const stockpile = (technique, abilityName) => ({ technique, plugin: 'stockpile', abilityName });

const PACKS = Object.freeze([
  {
    key: 'foothold-survey',
    name: 'Foothold survey',
    description: 'An operator establishes user context, surveys the host and network, then enumerates domain accounts and computers using native Windows commands.',
    platform: 'windows',
    prerequisites: ['Domain-joined Windows agent with access to a domain controller; English domain group names.'],
    steps: [
      atomic('T1033', 'User Discovery - whoami'),
      atomic('T1082', 'Hostname Discovery (Windows)'),
      atomic('T1016', 'System Network Configuration Discovery on Windows'),
      atomic('T1057', 'Process Discovery - tasklist'),
      atomic('T1087.001', 'Enumerate all accounts on Windows (Local)'),
      atomic('T1087.002', 'Enumerate all accounts (Domain)'),
      atomic('T1069.002', 'Basic Permission Groups Discovery Windows (Domain)'),
      atomic('T1018', 'Remote System Discovery - net group Domain Computers'),
    ],
  },
  {
    key: 'credential-harvest',
    name: 'Credential harvest',
    description: 'After checking user context, search local files and registry values, enumerate the Windows credential vault, and attempt an LSASS dump with the native comsvcs DLL. Vault enumeration does not itself decrypt passwords.',
    platform: 'windows',
    prerequisites: [
      'Elevated Windows PowerShell agent; LSASS protection may block the dump.',
      'Use lane exercise credentials and files. Files are searched relative to the agent working directory; vault results depend on the agent identity.',
      'Run operation cleanup to remove the LSASS dump; verify protected data is removed afterwards.',
    ],
    steps: [
      atomic('T1033', 'User Discovery - whoami'),
      atomic('T1552.001', 'Extracting passwords with findstr'),
      stockpile('T1552.002', 'Credentials in Registry - HKCU'),
      atomic('T1555', 'Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Windows Credentials]'),
      atomic('T1003.001', 'Dump LSASS.exe Memory using comsvcs.dll'),
    ],
  },
  {
    key: 'lateral-move',
    name: 'SMB and WMI lateral move',
    description: 'Establish reachability, inspect local shares, mount a remote admin share, transfer Sandcat and start it over WMI. Stockpile parsers connect the transfer to execution; Atomic adds native share reconnaissance.',
    platform: 'windows',
    prerequisites: [
      'Lane host facts plus valid domain.user.name/domain.user.password and has_password/has_admin relationships must be learned or supplied by the instructor; lane seeding does not supply passwords.',
      'Remote administrative access, SMB, WMI and WMIC must be available. Remote Host Ping must learn isAccessibleFrom; do not seed that relationship.',
      'Check remote agent contact and group configuration before running; cleanup stops and removes the remote agent.',
    ],
    steps: [
      // Upstream tags Remote Host Ping T1016, NOT T1018. Its parser produces
      // isAccessibleFrom. An arbitrary discovery test cannot replace it.
      stockpile('T1016', 'Remote Host Ping'),
      atomic('T1135', 'View available share drives'),
      stockpile('T1021.002', 'Mount Share'),
      stockpile('T1021.002', 'Copy 54ndc47 (SMB)'),
      stockpile('T1047', 'Start 54ndc47 (WMI)'),
    ],
  },
  {
    key: 'tamper-and-persist',
    name: 'Defence tamper and persist',
    description: 'Discover security processes, attempt to disable Defender real-time monitoring, hide file extensions and establish startup-folder and scheduled-task persistence using benign executable surrogates.',
    platform: 'windows',
    prerequisites: [
      'Elevated Windows agent with Defender installed and a writable user Startup folder; tamper protection may block the defense change.',
      'The startup shortcut launches Calculator at logon. The local task named spawn is scheduled for 20:10; task creation is not proof of task execution.',
      'Run cleanup and restore the lane snapshot afterwards: upstream registry cleanup deletes HideFileExt rather than restoring its prior value.',
    ],
    steps: [
      atomic('T1518.001', 'Security Software Discovery - powershell'),
      stockpile('T1562.001', 'Disable Windows Defender Real-Time Protection'),
      atomic('T1112', 'Modify Registry of Current User Profile - cmd'),
      atomic('T1547.001', 'Add Executable Shortcut Link to User Startup Folder'),
      atomic('T1053.005', 'Scheduled task Local'),
    ],
  },
  {
    key: 'stage-and-exfil',
    name: 'Stage and exfiltrate',
    description: 'Survey files and local shares, locate exercise documents, create a staging directory, copy the discovered files, compress them and upload the archive to Caldera. Stockpile carries file and directory facts through each collection step.',
    platform: 'windows',
    prerequisites: [
      'Windows PowerShell 5+; seed file.sensitive.extension (for example txt) and place exercise documents under C:\\Users.',
      'A disposable agent working directory with no pre-existing staged directory. Cleanup removes that directory and its archive.',
      'Agent upload contact must be reachable. Only collect lane exercise documents.',
    ],
    steps: [
      atomic('T1083', 'File and Directory Discovery (PowerShell)'),
      atomic('T1135', 'View available share drives'),
      stockpile('T1005', 'Find files'),
      stockpile('T1074.001', 'Create staging directory'),
      stockpile('T1074.001', 'Stage sensitive files'),
      stockpile('T1560.001', 'Compress staged directory'),
      stockpile('T1041', 'Exfil staged directory'),
    ],
  },
  {
    key: 'linux-survey',
    name: 'Foothold survey (Linux)',
    description: 'The Linux counterpart to the Windows survey, for lanes whose estate is not all Windows. Stockpile discovery remains preferred for its fact parsers.',
    platform: 'linux',
    prerequisites: ['A Linux agent supporting the selected catalog executors.'],
    steps: [
      { technique: 'T1033' },
      { technique: 'T1082' },
      { technique: 'T1016' },
      { technique: 'T1057' },
      { technique: 'T1087.001' },
      { technique: 'T1083' },
    ],
  },
  {
    key: 'powershell-foothold',
    name: 'PowerShell foothold and reconnaissance',
    description: 'An encoded PowerShell execution surrogate precedes identity, process, local-account, connection and file reconnaissance. The encoded command prints a message; subsequent discovery operates on the real host.',
    platform: 'windows',
    prerequisites: [
      '64-bit Windows PowerShell 5.1 with the LocalAccounts and NetTCPIP modules; writable agent working directory.',
      'Enable PowerShell script-block and process-command-line logging to investigate the encoded execution and follow-on discovery.',
    ],
    steps: [
      atomic('T1059.001', 'PowerShell Command Execution'),
      atomic('T1033', 'GetCurrent User with PowerShell Script'),
      atomic('T1057', 'Process Discovery - Get-Process'),
      atomic('T1087.001', 'Enumerate all accounts via PowerShell (Local)'),
      atomic('T1049', 'System Network Connections Discovery with PowerShell'),
      atomic('T1083', 'File and Directory Discovery (PowerShell)'),
    ],
  },
  {
    key: 'domain-mapping',
    name: 'Domain and share reconnaissance',
    description: 'A domain user maps accounts, privileged groups, domain controllers, computers and locally published shares before choosing a lateral target. Discovery uses native tools without downloading reconnaissance frameworks.',
    platform: 'windows',
    prerequisites: [
      'Domain-joined Windows agent with a reachable domain controller, nltest and English domain group names.',
      'Share enumeration is local; this profile discovers targets but does not connect to them or request Kerberos service tickets.',
    ],
    steps: [
      atomic('T1033', 'User Discovery - whoami'),
      atomic('T1087.002', 'Enumerate all accounts (Domain)'),
      atomic('T1069.002', 'Basic Permission Groups Discovery Windows (Domain)'),
      atomic('T1018', 'Remote System Discovery - nltest'),
      atomic('T1018', 'Remote System Discovery - net group Domain Computers'),
      atomic('T1135', 'View available share drives'),
    ],
  },
  {
    key: 'scheduled-persistence',
    name: 'Logon persistence through native tools',
    description: 'An operator checks user and host context, inspects security processes, then installs a user Startup shortcut and a PowerShell-created scheduled task. Both persistence mechanisms use Calculator as the execution surrogate.',
    platform: 'windows',
    prerequisites: [
      'Elevated Windows PowerShell agent with ScheduledTasks and an existing, writable user Startup folder.',
      'Use a disposable user profile without an existing AtomicTask or calc_exe.lnk. The task principal is BUILTIN\\Administrators; localized systems may need a reviewed ability variant.',
      'Logon triggers are created but not forced. Run operation cleanup and verify task and shortcut removal.',
    ],
    steps: [
      atomic('T1033', 'User Discovery - whoami'),
      atomic('T1082', 'Hostname Discovery (Windows)'),
      atomic('T1518.001', 'Security Software Discovery - powershell'),
      atomic('T1547.001', 'Add Executable Shortcut Link to User Startup Folder'),
      atomic('T1053.005', 'Powershell Cmdlet Scheduled Task'),
    ],
  },
]);

const str = (value) => (value == null ? '' : String(value).trim());

/** Normalize once, retaining plugin provenance discarded by normalizeAbility. */
function catalog(abilities) {
  const out = [];
  for (const raw of Array.isArray(abilities) ? abilities : []) {
    const ability = normalizeAbility(raw);
    if (ability) out.push({ ...ability, plugin: str(raw && raw.plugin).toLowerCase() || null });
  }
  return out;
}

/** Exact selectors constrain candidates; legacy nameMatch only breaks ties. */
function pick(step, rows, platform) {
  const wanted = str(step.technique).toUpperCase();
  const requiredPlugin = str(step.plugin).toLowerCase();
  const requiredName = str(step.abilityName).toLowerCase();
  const match = str(step.nameMatch).toLowerCase();
  const candidates = rows.filter((row) => row.technique.toUpperCase() === wanted
    && (!platform || row.platforms.includes(platform))
    && (!requiredPlugin || row.plugin === requiredPlugin)
    && (!requiredName || row.name.toLowerCase() === requiredName));
  if (!candidates.length) return null;
  const scored = candidates.map((row) => ({
    row,
    named: match && row.name.toLowerCase().includes(match) ? 0 : 1,
    sourced: row.plugin === 'stockpile' ? 0 : 1,
  }));
  scored.sort((a, b) => a.named - b.named || a.sourced - b.sourced || a.row.id.localeCompare(b.row.id));
  return scored[0].row;
}

/** Resolve without executing; prerequisites are operator guidance, not checks. */
function resolvePack(pack, abilities) {
  const rows = catalog(abilities);
  const resolved = [];
  const unresolved = [];
  const seen = new Set();
  for (const [index, step] of pack.steps.entries()) {
    const row = pick(step, rows, pack.platform);
    const missing = {
      step: index + 1,
      technique: step.technique,
      ...(step.plugin ? { plugin: step.plugin } : {}),
      ...(step.abilityName ? { name: step.abilityName } : {}),
    };
    if (!row) {
      unresolved.push({ ...missing, reason: step.plugin || step.abilityName ? 'no_matching_ability' : 'no_ability_for_platform' });
      continue;
    }
    if (seen.has(row.id)) {
      unresolved.push({ ...missing, reason: 'duplicate_ability' });
      continue;
    }
    seen.add(row.id);
    resolved.push({ technique: step.technique, ability_id: row.id, name: row.name, tactic: row.tactic, plugin: row.plugin });
  }
  return {
    key: pack.key,
    adversary_id: uuidv5(pack.key, PACK_NAMESPACE),
    name: `${NAME_PREFIX}${pack.name}`,
    description: pack.description,
    platform: pack.platform,
    prerequisites: Array.isArray(pack.prerequisites) ? [...pack.prerequisites] : [],
    atomic_ordering: resolved.map((entry) => entry.ability_id),
    resolved,
    unresolved,
  };
}

function resolveAll(abilities, packs) {
  return (Array.isArray(packs) ? packs : PACKS).map((pack) => resolvePack(pack, abilities));
}

/** Caldera's accepted fields only; prerequisites also appear in its console. */
function toWire(resolvedPack) {
  const prerequisites = resolvedPack.prerequisites || [];
  return {
    adversary_id: resolvedPack.adversary_id,
    name: resolvedPack.name,
    description: resolvedPack.description + (prerequisites.length ? ` Prerequisites: ${prerequisites.join(' ')}` : ''),
    atomic_ordering: [...resolvedPack.atomic_ordering],
    // Caldera 5.3's optional String field rejects null. Omitting it lets the
    // server assign its default objective on both create and replace.
    tags: ['cybercore'],
  };
}

module.exports = { PACKS, PACK_NAMESPACE, NAME_PREFIX, resolvePack, resolveAll, toWire };
