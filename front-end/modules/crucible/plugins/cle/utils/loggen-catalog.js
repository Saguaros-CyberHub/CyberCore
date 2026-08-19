/**
 * CLE Plugin — log-generator attack catalog (CYBR 400)
 * ============================================================================
 * A TRANSCRIPTION of what summved/log-generator supports, pinned to the commit
 * baked into the Rocky sensor image.
 *
 * Why transcribed and not fetched. The MITRE catalog upstream is not data — it
 * is a hardcoded object literal in src/utils/mitreMapper.ts, and the only CLI
 * that exposes it (`npm run mitre-list`) has no --json flag, it pretty-prints.
 * Scraping that text over a guest-agent exec, per lane, to populate a picker
 * would be slower, flakier and no more truthful than this file. Attack CHAINS
 * do have `attack-chains:list --json`, but a half-live catalog is worse than a
 * consistently pinned one.
 *
 * What keeps it honest: LOGGEN_REF below is the exact commit the bake script
 * checks out, and the baked image records the same value in
 * /opt/cybercore/loggen-manifest.json. The dispatch wrapper reads that file
 * anyway, so a mismatch is detected for free and surfaced as a banner rather
 * than silently offering the class techniques the guest no longer recognises.
 * Re-baking at a new ref means re-transcribing this file and bumping both.
 *
 * ---------------------------------------------------------------------------
 * READ THIS BEFORE TRUSTING A TECHNIQUE
 *
 * `generate --mitre-technique T1110` does NOT execute an attack. It filters the
 * ordinary generated log stream down to entries whose MESSAGE TEXT matches that
 * technique's keyword patterns (mitreMapper.ts matchesPattern). So the event
 * yield is a property of the keywords, not of the technique's real-world
 * prevalence: T1562.004 matches "drop"/"block"/"deny"/"reject" and floods,
 * while T1071.001 needs "suspicious" AND "connection" in one line and barely
 * fires.
 *
 * `keywords` and `expected_volume` exist to make that visible in the UI.
 * expected_volume is an ESTIMATE read off the matcher source, not a
 * measurement — treat it as a hint about which techniques make a usable class
 * demo, and correct it once you have real numbers from cle_attack_target.event_count.
 * ============================================================================
 */

/**
 * Upstream commit the sensor image is baked from. Must equal `ref` in
 * /opt/cybercore/loggen-manifest.json on the guest.
 */
const LOGGEN_REF = '2db735a7a5c6fb56654187325bb36772d3c9c4d7';

/**
 * Bumped whenever the contents below change, independently of LOGGEN_REF — a
 * corrected description or volume hint is a catalog change but not an image
 * change. Stored on every run so an old row still explains what it offered.
 */
const CATALOG_VERSION = '1.0.0';

/**
 * mitreMapper.ts TACTICS, all 14. Listed in kill-chain order rather than the
 * numeric order upstream declares them in, because that is the order an
 * instructor scanning a filter dropdown expects. Ids are what matter.
 */
const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0040', name: 'Impact' },
];

/**
 * The 15 unique techniques reachable via `--mitre-technique`.
 *
 * mitreMapper.TECHNIQUE_PATTERNS has 16 entries but two of them (brute_force,
 * account_lockout) both map to T1110, so upstream's own `mitre-list` dedupes to
 * 15. `keywords` merges the match rules of every entry that contributes to a
 * technique, spelled the way matchesPattern actually tests them: a '+' joins
 * terms that must BOTH appear in one message.
 */
const TECHNIQUES = [
  {
    id: 'T1005', name: 'Data from Local System', tactic: 'TA0009',
    description: 'Adversaries may search local system sources to find files of interest.',
    keywords: ['data + access', 'data + read', 'data + export', 'data + download'],
    expected_volume: 'medium',
  },
  {
    id: 'T1018', name: 'Remote System Discovery', tactic: 'TA0007',
    description: 'Adversaries may attempt to get a listing of other systems on the network.',
    keywords: ['scan', 'probe', 'port', 'discovery'],
    expected_volume: 'high',
  },
  {
    id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'TA0010',
    description: 'Adversaries may steal data by exfiltrating it over an existing C2 channel.',
    keywords: ['outbound', 'external', 'connection + established'],
    expected_volume: 'medium',
  },
  {
    id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'TA0011',
    description: 'Adversaries may communicate using application layer protocols to blend in with existing traffic.',
    keywords: ['suspicious + connection', 'unusual traffic', 'anomalous'],
    expected_volume: 'low',
  },
  {
    id: 'T1078', name: 'Valid Accounts', tactic: 'TA0001',
    description: 'Login from an unusual geographic location using otherwise valid credentials.',
    keywords: ['unusual location', 'suspicious login', 'geographic', 'country'],
    expected_volume: 'low',
  },
  {
    id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'TA0004',
    description: 'Adversaries may obtain and abuse credentials of existing local accounts to escalate privilege.',
    keywords: ['privilege', 'escalation', 'unauthorized access', 'admin access'],
    expected_volume: 'medium',
  },
  {
    id: 'T1082', name: 'System Information Discovery', tactic: 'TA0007',
    description: 'Adversaries may attempt to get detailed information about the system.',
    keywords: ['system + info', 'system + discovery', 'system + enumeration', 'system + reconnaissance'],
    expected_volume: 'low',
  },
  {
    id: 'T1098', name: 'Account Manipulation', tactic: 'TA0003',
    description: 'Adversaries may manipulate accounts to maintain access to victim systems.',
    keywords: ['password changed', 'password reset', 'credentials updated'],
    expected_volume: 'low',
  },
  {
    id: 'T1110', name: 'Brute Force', tactic: 'TA0006',
    description: 'Repeated authentication attempts, password spraying, and the account lockouts they cause.',
    keywords: ['brute force', 'password spray', 'multiple + attempts', 'locked', 'lockout', 'account disabled'],
    expected_volume: 'medium',
  },
  {
    id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'TA0006',
    description: 'Adversaries may use password guessing to gain access to accounts.',
    keywords: ['failed login', 'login failed', 'authentication failed', 'invalid credentials'],
    expected_volume: 'medium',
  },
  {
    id: 'T1213', name: 'Data from Information Repositories', tactic: 'TA0009',
    description: 'Adversaries may leverage information repositories to mine valuable information.',
    keywords: ['query', 'select', 'database', 'sql'],
    expected_volume: 'high',
  },
  {
    id: 'T1496', name: 'Resource Hijacking', tactic: 'TA0040',
    description: 'Adversaries may leverage system resources, for example to mine cryptocurrency.',
    keywords: ['high + cpu', 'high + memory', 'high + disk', 'high + resource'],
    expected_volume: 'medium',
  },
  {
    id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'TA0040',
    description: 'Adversaries may perform endpoint denial of service attacks to degrade or block availability.',
    keywords: ['service + down', 'service + failed', 'service + unavailable', 'service + timeout'],
    expected_volume: 'medium',
  },
  {
    id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', tactic: 'TA0005',
    description: 'Adversaries may disable security tools to avoid detection.',
    keywords: ['intrusion', 'attack', 'malicious', 'threat'],
    expected_volume: 'medium',
  },
  {
    id: 'T1562.004', name: 'Impair Defenses: Disable or Modify System Firewall', tactic: 'TA0005',
    description: 'Adversaries may disable or modify system firewalls. Matches ordinary firewall deny logging, so this is the highest-volume option in the catalog.',
    keywords: ['drop', 'block', 'deny', 'reject'],
    expected_volume: 'high',
  },
];

/**
 * The three attack-chain templates in src/chains/templates/.
 *
 * Unlike techniques these are genuinely scripted multi-stage campaigns, so they
 * always produce a coherent narrative and never suffer the low-yield problem
 * above. They run their own length: the CLI takes --speed, not --duration, and
 * the product decision is that we do not derive one from the other. estimated_minutes
 * is the template's own metadata.estimated_duration.
 */
const CHAINS = [
  {
    key: 'insider-threat-data-theft',
    name: 'Malicious Insider Data Theft',
    category: 'insider_threat',
    difficulty: 'beginner',
    estimated_minutes: 25,
    description: 'A trusted insider with legitimate access enumerates file shares, collects sensitive data and exfiltrates it automatically, cleaning up behind itself. The gentlest starting point: no exploitation at all, so students must reason about behaviour rather than signatures.',
    tactics: ['TA0005', 'TA0007', 'TA0009', 'TA0010'],
    techniques: ['T1005', 'T1039', 'T1213', 'T1020', 'T1070.004', 'T1083'],
  },
  {
    key: 'ransomware-ryuk',
    name: 'Ryuk Ransomware Campaign',
    category: 'ransomware',
    difficulty: 'intermediate',
    estimated_minutes: 30,
    description: 'A complete Ryuk chain: spearphishing attachment, Windows Command Shell, run-key persistence, defence tampering, LSASS credential theft, RDP lateral movement, then mass encryption. Ends loudly, which makes it a good first exercise in working backwards from an obvious impact event.',
    tactics: ['TA0001', 'TA0002', 'TA0003', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0040'],
    techniques: [
      'T1566.001', 'T1059.003', 'T1547.001', 'T1562.001',
      'T1003.001', 'T1018', 'T1021.001', 'T1486',
    ],
  },
  {
    key: 'apt29-cozy-bear',
    name: 'APT29 Cozy Bear Campaign',
    category: 'apt',
    difficulty: 'advanced',
    estimated_minutes: 45,
    description: 'Ten techniques across the full kill chain, from a spearphishing attachment through PowerShell execution, registry persistence, process injection and LSASS credential theft to exfiltration over a C2 channel. The longest and quietest of the three.',
    tactics: [
      'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005',
      'TA0006', 'TA0007', 'TA0009', 'TA0010', 'TA0011',
    ],
    techniques: [
      'T1566.001', 'T1059.001', 'T1547.001', 'T1055', 'T1070.004',
      'T1003.001', 'T1082', 'T1005', 'T1041', 'T1071.001',
    ],
  },
];

// ---------------------------------------------------------------------------
// Validation + lookup
// ---------------------------------------------------------------------------

/**
 * Upstream's own validators, copied verbatim from mitreMapper.isValidTechnique
 * / isValidTactic. Anchored, digits only — no separator, no shell metacharacter
 * and no newline can survive them, which is what lets attack-runner.js treat a
 * matched id as safe to interpolate.
 *
 * These are anchored, and in JavaScript that genuinely excludes a trailing
 * newline as well -- unlike Python, where `$` would match before one.
 * attack-runner.js still rejects newlines explicitly, as defence in depth
 * rather than because these regexes need the help.
 */
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const TACTIC_RE = /^TA\d{4}$/;

const _techniqueById = new Map(TECHNIQUES.map((t) => [t.id, t]));
const _tacticById = new Map(TACTICS.map((t) => [t.id, t]));
const _chainByKey = new Map(CHAINS.map((c) => [c.key, c]));

/** @returns {object|null} the catalog entry, or null if we do not offer it. */
function findTechnique(id) {
  return _techniqueById.get(String(id || '')) || null;
}

/** @returns {object|null} */
function findTactic(id) {
  return _tacticById.get(String(id || '')) || null;
}

/** @returns {object|null} */
function findChain(key) {
  return _chainByKey.get(String(key || '')) || null;
}

/** Human tactic name for a technique row, for rendering. */
function tacticNameOf(technique) {
  return _tacticById.get(technique && technique.tactic)?.name || 'Unknown';
}

/**
 * Seconds -> the duration string `generate --duration` accepts.
 *
 * Upstream parseDuration is /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/ and rejects a
 * total of zero, so components MUST be emitted h-then-m-then-s and at least one
 * must survive. Zero components are omitted: '1h' not '1h0m0s'.
 *
 * @param {number} seconds
 * @returns {string}
 * @throws if the input is not a positive finite integer — a silently wrong
 *   duration here becomes a lane that never stops generating.
 */
function formatDuration(seconds) {
  const n = Number(seconds);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`formatDuration: expected a positive integer of seconds, got ${JSON.stringify(seconds)}`);
  }
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  const s = n % 60;
  return `${h ? `${h}h` : ''}${m ? `${m}m` : ''}${s ? `${s}s` : ''}`;
}

/**
 * The whole catalog, shaped for the picker. Static — the route may cache it.
 */
function catalog() {
  return {
    catalog_version: CATALOG_VERSION,
    loggen_ref: LOGGEN_REF,
    tactics: TACTICS,
    techniques: TECHNIQUES.map((t) => ({ ...t, tactic_name: tacticNameOf(t) })),
    chains: CHAINS,
  };
}

module.exports = {
  LOGGEN_REF,
  CATALOG_VERSION,
  TACTICS,
  TECHNIQUES,
  CHAINS,
  TECHNIQUE_RE,
  TACTIC_RE,
  findTechnique,
  findTactic,
  findChain,
  tacticNameOf,
  formatDuration,
  catalog,
};
