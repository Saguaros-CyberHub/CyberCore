/**
 * ig1-derivation.js — Deterministic CIS Controls v8 IG1 baseline derivation.
 * ============================================================================
 * Takes an AI-generated profile (org + IT + network + threats) and produces
 * a realistic per-safeguard answer set (yes / partial / no) plus evidence
 * notes. Students see this as the baseline state of the company's IG1
 * compliance and conduct their risk assessment against it.
 *
 * Rules each answer is grounded in:
 *   - Declared IT controls (EDR, patch cadence, MFA coverage, backups, etc.)
 *   - Maturity level (Low/Intermediate/High)
 *   - Vendor flavor (Microsoft-heavy shops likely have BitLocker + Intune)
 *   - Deliberate weaknesses (each weakness flips 1-2 specific safeguards to 'no')
 *   - run_id hash for stable tie-breaking on borderline cases
 *
 * The answers are NOT random — they reflect what's actually present in the
 * profile's IT environment. A student reading the profile should be able to
 * justify each answer from the declared facts.
 */

const path = require('path');
const fs = require('fs');

const IG1_PATH = path.join(__dirname, '..', 'data', 'frameworks', 'cis-ig1.json');
let _ig1Cache = null;
function loadIg1() {
  if (!_ig1Cache) _ig1Cache = JSON.parse(fs.readFileSync(IG1_PATH, 'utf8'));
  return _ig1Cache;
}

function hashStr(s, salt = '') {
  const x = String(s || '') + '|' + salt;
  let h = 0;
  for (let i = 0; i < x.length; i++) h = ((h * 31) + x.charCodeAt(i)) >>> 0;
  return h;
}

// ─── Per-profile compliance posture archetypes ────────────────────────────
// Two SMBs at the same maturity level rarely have identical compliance
// profiles. Real-world variance comes from "what we invested in" — one shop
// has great backups but no MFA, another has mature policy but weak endpoint
// security. Each AI-generated profile picks ONE archetype hashed from
// run_id, which shifts scores per control family. Result: meaningfully
// different IG1 distributions even at the same maturity baseline.

const POSTURE_ARCHETYPES = [
  {
    name: 'backup-mature',
    description: 'Invested heavily in data recovery after a past incident; less on identity.',
    shifts: { 11: +30, 3: +20, 10: +5,  5: -15, 6: -15, 14: -5,  17: -10 }
  },
  {
    name: 'identity-focused',
    description: 'Strong MFA + access management; backups and incident response lag.',
    shifts: { 5: +25, 6: +25, 14: +5,  11: -15, 17: -15, 8: -10 }
  },
  {
    name: 'endpoint-heavy',
    description: 'Big EDR + patching investment; weaker on policy and recovery.',
    shifts: { 10: +25, 4: +20, 7: +20, 2: +10, 14: -15, 17: -15, 11: -5 }
  },
  {
    name: 'compliance-mature',
    description: 'Audit-driven shop with policies and training but uneven tech controls.',
    shifts: { 14: +25, 15: +25, 17: +20, 1: +10, 5: +5,  10: -10, 13: -15 }
  },
  {
    name: 'tech-mature-policy-weak',
    description: 'Engineers built solid technical controls; nobody wrote the policy down.',
    shifts: { 1: +15, 2: +15, 4: +15, 10: +20, 11: +10, 14: -20, 15: -20, 17: -15 }
  },
  {
    name: 'policy-strong-tech-weak',
    description: 'Lots of binder policies + training; thin operational tooling.',
    shifts: { 14: +20, 15: +20, 17: +15, 8: +5,  10: -15, 13: -20, 1: -10, 4: -10 }
  },
  {
    name: 'uneven-chaotic',
    description: 'Inconsistent posture — strong in some unexpected places, weak in others.',
    // No fixed shifts — computed per-safeguard from run_id hash, ±25 swings.
    shifts: '__uneven__'
  },
  {
    name: 'balanced',
    description: 'Even posture across the board; no standout strengths or weaknesses.',
    shifts: {} // baseline-only
  }
];

function pickPostureArchetype(runId) {
  const idx = hashStr(runId, 'posture') % POSTURE_ARCHETYPES.length;
  return POSTURE_ARCHETYPES[idx];
}

// Return the per-control shift for an archetype. For 'uneven-chaotic', the
// shift is computed per-control from run_id hash so different controls get
// different swings within the same profile.
function archetypeShiftFor(archetype, controlNum, runId) {
  if (archetype.shifts === '__uneven__') {
    const h = hashStr(runId, 'unevenctrl' + controlNum) % 100;
    // Maps 0..99 → -25..+25
    return Math.round(((h / 99) * 50) - 25);
  }
  return archetype.shifts[String(controlNum)] || 0;
}

// Pick between three answers based on a numeric score (0-100).
// Wider partial band squeezed (was 25-75, now 35-65) so genuine yes/no
// answers happen more often than partial.
function scoreToAnswer(score, runId, safeguardNum) {
  if (score >= 70) return 'yes';
  if (score <= 30) return 'no';
  // 31-69 → mostly partial, but hash-driven pull toward yes/no for variety.
  // Higher pull-rate (was 35%, now 50%) so more answers escape the partial bucket.
  const tieBreak = hashStr(runId, 'ig1' + safeguardNum) % 100;
  if (score >= 55 && tieBreak < 50) return 'yes';
  if (score <= 45 && tieBreak < 50) return 'no';
  return 'partial';
}

// Maturity → base score
function maturityBaseline(maturity) {
  const m = String(maturity || '').toLowerCase();
  if (m.includes('high'))       return 70;
  if (m.includes('low'))        return 25;
  return 48; // intermediate / default — pushed slightly above the 'partial' floor
}

// Look up answer for a specific safeguard given profile state.
// Returns { answer, evidence } — evidence is a short note a student can read.
function deriveSafeguard(sg, ctx) {
  const { maturity, it, net, weaknessTexts, vendorFlavor, runId, archetype } = ctx;
  const base = maturityBaseline(maturity) + archetypeShiftFor(archetype, sg.control, runId);
  const num  = sg.num;

  // Helper: does any deliberate_weakness text mention this safeguard's
  // control area? If so, the safeguard is almost certainly 'no'.
  const weaknessKeyword = (kw) => weaknessTexts.some(w => w.toLowerCase().includes(kw));

  // Helper: pull declared values
  const edr      = it?.endpoint_protection || {};
  const patch    = it?.patch_management || {};
  const backups  = it?.backups || {};
  const remote   = it?.remote_access || {};
  const physical = it?.physical_security || {};
  const fw       = net?.firewall || {};

  // Default starting score = maturity baseline
  let score = base;
  let evidence = '';

  switch (num) {
    // ─── Control 1 — Asset inventory ─────────────────────────────────────
    case '1.1':
      score = (edr.coverage_percent >= 80 ? 75 : base);
      evidence = edr.coverage_percent ? `EDR covers ${edr.coverage_percent}% of endpoints — implies an inventory exists.` : 'No explicit asset inventory mentioned.';
      break;
    case '1.2':
      score = (patch.method && patch.method !== 'Manual' && patch.method !== 'Ad-hoc') ? 60 : 30;
      evidence = `Patch method: ${patch.method || 'unknown'}. Centralized methods usually flag unauthorized assets.`;
      break;

    // ─── Control 2 — Software inventory ─────────────────────────────────
    case '2.1':
      score = (patch.method === 'Intune' || patch.method === 'WSUS') ? 75 : base - 10;
      evidence = `Patch method ${patch.method || 'unknown'} ${patch.method === 'Intune' || patch.method === 'WSUS' ? 'maintains software inventory' : 'does not necessarily catalog software'}.`;
      break;
    case '2.2':
      score = (patch.compliance_rate >= 80) ? 70 : 35;
      evidence = `Patch compliance rate: ${patch.compliance_rate || 'unknown'}%.`;
      break;
    case '2.3':
      score = (edr.edr_enabled ? base + 15 : base - 15);
      evidence = edr.edr_enabled ? `EDR ${edr.product || ''} flags unauthorized software.` : 'No EDR; unauthorized software likely undetected.';
      break;

    // ─── Control 3 — Data protection ────────────────────────────────────
    case '3.1':
      score = base - 10;
      evidence = 'No formal data management process declared.';
      break;
    case '3.2':
      score = base - 15;
      evidence = 'No formal data inventory declared in profile.';
      break;
    case '3.3':
      score = base; evidence = 'Access controls per default Windows/Linux ACLs; no DLP layer.';
      break;
    case '3.4':
      score = base - 20; evidence = 'Retention policy not formally documented.';
      break;
    case '3.5':
      score = base - 10; evidence = 'Disposal process informal — no certificate-of-destruction workflow.';
      break;
    case '3.6':
      // Encrypt data on end-user devices — assumed yes for Microsoft-heavy shops (BitLocker default)
      // (Match Microsoft 365 / Intune / Microsoft Defender — NOT BitDefender.)
      const msShop = /Microsoft|Intune|\bMicrosoft Defender|Entra|Azure AD/i.test(vendorFlavor || '');
      score = msShop ? 80 : (base + 5);
      evidence = msShop ? 'Microsoft-heavy shop — BitLocker assumed enabled by Intune.' : 'Disk encryption likely opt-in / inconsistent.';
      break;

    // ─── Control 4 — Secure configuration ───────────────────────────────
    case '4.1':
      score = base - 5; evidence = 'No formal secure-config baseline declared.';
      break;
    case '4.2':
      score = base; evidence = `Firewall ${fw.vendor || ''} ${fw.model || ''} present; rule discipline varies.`;
      break;
    case '4.3':
      score = base + 10; evidence = 'Session locking typically enforced via Windows Group Policy / macOS defaults.';
      break;
    case '4.4':
      // Implement firewall on servers
      score = 70; evidence = `Perimeter firewall (${fw.vendor || 'unknown'}) implies server firewall mgmt; host firewalls vary.`;
      break;
    case '4.5':
      // Implement firewall on end-user devices
      score = (edr.edr_enabled || edr.product) ? 70 : 40;
      evidence = edr.product ? `${edr.product} typically manages host firewall.` : 'No EDR — host firewall coverage uncertain.';
      break;
    case '4.6':
      score = base; evidence = 'Asset management cadence consistent with stated maturity.';
      break;
    case '4.7':
      score = base + 5; evidence = 'Default admin accounts disabled per typical OS hardening guidelines.';
      break;

    // ─── Control 5 — Account management ─────────────────────────────────
    case '5.1':
      const dirImpl = remote.vpn && remote.mfa ? base + 15 : base;
      score = dirImpl; evidence = 'Account inventory via directory service (Active Directory / Entra).';
      break;
    case '5.2':
      score = base + 10; evidence = 'Password policy enforced via directory service — uniqueness not technically validated.';
      break;
    case '5.3':
      score = base - 10; evidence = 'Dormant account cleanup typically informal in this maturity range.';
      break;
    case '5.4':
      score = (remote.mfa === 'All') ? 75 : (remote.mfa === 'ExecOnly' ? 50 : 30);
      evidence = `Admin accounts: MFA coverage = ${remote.mfa || 'unknown'}.`;
      break;

    // ─── Control 6 — Access control management ──────────────────────────
    case '6.1': score = base + 5; evidence = 'Access grants typically tied to onboarding ticket workflow.'; break;
    case '6.2': score = base - 10; evidence = 'Offboarding access revocation often delayed (no automation).'; break;
    case '6.3':
      score = (remote.mfa === 'All') ? 85 : (remote.mfa === 'ExecOnly' ? 45 : 20);
      evidence = `MFA coverage: ${remote.mfa || 'unknown'}.`;
      break;
    case '6.4': score = base - 5; evidence = 'Role-based access typical; some over-provisioning expected.'; break;
    case '6.5':
      score = (remote.mfa === 'All') ? 80 : (remote.mfa === 'ExecOnly' ? 55 : 25);
      evidence = `Admin MFA tied to overall MFA coverage (${remote.mfa || 'unknown'}).`;
      break;

    // ─── Control 7 — Continuous vulnerability mgmt ──────────────────────
    case '7.1':
      score = (patch.frequency === 'Weekly' || patch.frequency === 'Daily') ? 65 : 30;
      evidence = `Patch frequency: ${patch.frequency || 'unknown'}.`;
      break;
    case '7.2':
      score = (patch.compliance_rate >= 80) ? 70 : 35;
      evidence = `${patch.compliance_rate || 'unknown'}% patch compliance.`;
      break;
    case '7.3':
      score = (patch.frequency === 'Monthly' || patch.frequency === 'Weekly') ? 70 : 30;
      evidence = `OS patching: ${patch.frequency || 'unknown'} cadence.`;
      break;
    case '7.4':
      score = (patch.frequency === 'Monthly' || patch.frequency === 'Weekly') ? 60 : 25;
      evidence = `Application patching tied to overall ${patch.frequency || 'unknown'} cadence — apps lag OS by ~2 weeks.`;
      break;

    // ─── Control 8 — Audit log management ───────────────────────────────
    case '8.1': score = base - 15; evidence = 'Audit log policy not formally documented.'; break;
    case '8.2':
      score = fw.rules?.some(r => r.logging) ? base + 10 : base - 20;
      evidence = fw.rules?.some(r => r.logging) ? 'Some firewall rules have logging enabled.' : 'Most firewall rules lack logging.';
      break;
    case '8.3': score = base - 25; evidence = 'No SIEM; logs stored locally with limited retention.'; break;

    // ─── Control 9 — Email & web browser protections ────────────────────
    case '9.1': score = base + 10; evidence = 'Browsers managed centrally via Group Policy / MDM.'; break;
    case '9.2': score = base; evidence = 'DNS filtering via ISP; no enterprise DNS security service.'; break;

    // ─── Control 10 — Malware defenses ──────────────────────────────────
    case '10.1':
      score = edr.edr_enabled ? 80 : (edr.product ? 60 : 25);
      evidence = edr.product ? `${edr.product} deployed${edr.edr_enabled ? ' with EDR features' : ''}.` : 'No managed AV declared.';
      break;
    case '10.2':
      score = (edr.managed ? base + 15 : base - 10);
      evidence = `EDR ${edr.managed ? 'centrally managed' : 'unmanaged / local'}; signature updates ${edr.managed ? 'automatic' : 'manual'}.`;
      break;
    case '10.3':
      score = base + 5; evidence = 'AutoRun disabled on managed endpoints by GPO/MDM default.';
      break;

    // ─── Control 11 — Data recovery ─────────────────────────────────────
    case '11.1':
      score = (backups.frequency === 'Daily' ? 80 : backups.frequency === 'Weekly' ? 60 : 30);
      evidence = `Backups run ${backups.frequency || 'unknown'}.`;
      break;
    case '11.2':
      score = backups.offsite ? 75 : 30;
      evidence = backups.offsite ? 'Offsite backups configured.' : 'No offsite backups.';
      break;
    case '11.3':
      score = backups.immutability ? 80 : 25;
      evidence = backups.immutability ? 'Backups are immutable (versioned / air-gapped).' : 'No immutability — backups vulnerable to ransomware.';
      break;
    case '11.4':
      // Restore tests
      const rt = String(backups.restore_tests || '').toLowerCase();
      score = (rt.includes('quarterly') || rt.includes('monthly')) ? 75 :
              (rt.includes('annual') ? 50 :
              (rt.includes('never') || !rt ? 20 : 40));
      evidence = `Restore tests: ${backups.restore_tests || 'not documented'}.`;
      break;
    case '11.5':
      score = backups.offsite && backups.immutability ? 70 : 30;
      evidence = `Isolation: offsite=${!!backups.offsite}, immutable=${!!backups.immutability}.`;
      break;

    // ─── Control 12 — Network infrastructure mgmt ───────────────────────
    case '12.1':
      score = base + 5; evidence = `Network gear: ${fw.vendor || 'unknown'} maintained on vendor-supported firmware (${fw.firmware || 'unknown'}).`;
      break;

    // ─── Control 13 — Network monitoring & defense ──────────────────────
    case '13.1':
      score = base - 5; evidence = 'No dedicated NIDS; perimeter firewall handles allow/deny only.';
      break;

    // ─── Control 14 — Security awareness training ───────────────────────
    case '14.1': score = base; evidence = 'Annual security awareness training program.'; break;
    case '14.2': score = base - 5; evidence = 'Recognition training included in annual program; no simulated phishing.'; break;
    case '14.3': score = base - 10; evidence = 'No formal authentication-best-practices training.'; break;
    case '14.4': score = base - 5; evidence = 'Data-handling training included in role-based onboarding.'; break;
    case '14.5': score = base - 10; evidence = 'Limited training on unintentional exposure (USB, cloud sharing).'; break;
    case '14.6': score = base - 15; evidence = 'No dedicated incident-reporting training; ad-hoc only.'; break;
    case '14.7': score = base - 15; evidence = 'No formal training on identifying outdated software.'; break;
    case '14.8': score = base - 20; evidence = 'No training on dangers of public Wi-Fi.'; break;

    // ─── Control 15 — Service provider management ──────────────────────
    case '15.1':
      const vrCount = (it?.vendor_risk || []).length;
      score = vrCount >= 3 ? base + 10 : (vrCount > 0 ? base - 5 : base - 25);
      evidence = `${vrCount} vendor(s) tracked in vendor risk inventory.`;
      break;

    // ─── Control 16 — Application software security ────────────────────
    case '16.1': score = base - 20; evidence = 'No formal AppSec program — apps are SaaS or commercial.'; break;

    // ─── Control 17 — Incident response ────────────────────────────────
    case '17.1':
      score = base - 10; evidence = 'Incident response plan exists at policy level but rarely exercised.';
      break;
    case '17.2': score = base - 15; evidence = 'No formal IR contact list — informal escalation.'; break;
    case '17.3': score = base - 25; evidence = 'No formal IR reporting workflow defined.'; break;

    default:
      score = base;
      evidence = 'Inferred from declared IT maturity.';
  }

  // Deliberate-weakness short-circuit — if a weakness clearly maps to this
  // safeguard's domain, force the answer down.
  const weaknessMap = {
    '5.4':  ['admin account', 'shared admin', 'no mfa'],
    '6.3':  ['no mfa', 'mfa not enforced', 'missing mfa'],
    '6.5':  ['shared admin', 'admin without mfa'],
    '8.2':  ['no logging', 'logs disabled', 'log gap'],
    '8.3':  ['no siem', 'no central log'],
    '10.1': ['no antivirus', 'unmanaged av', 'no edr'],
    '11.2': ['no offsite', 'backups on-prem only'],
    '11.3': ['no immutab', 'backups overwritten'],
    '11.4': ['no restore test', 'untested backup'],
    '14.1': ['no training', 'no awareness'],
    '17.1': ['no incident plan', 'no ir plan']
  };
  const triggers = weaknessMap[num];
  if (triggers && triggers.some(kw => weaknessKeyword(kw))) {
    return { answer: 'no', evidence: evidence + ' (weakness explicitly flagged this control.)' };
  }

  return { answer: scoreToAnswer(score, runId, num), evidence };
}

/**
 * Derive IG1 baseline for an entire profile.
 * Returns { answers: { ig1_1.1: 'yes', ... }, notes: { ig1_1.1: '...', ... }, coverage_pct }
 */
function deriveIg1Baseline(combinedPayloads, runId = '') {
  const ig1 = loadIg1();
  const it      = combinedPayloads?.it_environment || {};
  const net     = combinedPayloads?.network || {};
  const tp      = combinedPayloads?.threat_profile || null;
  const maturity = combinedPayloads?.maturity || combinedPayloads?.it_environment?.maturity || 'Intermediate';
  const vendorFlavor = combinedPayloads?.vendor_flavor || '';

  // Collect deliberate-weakness text from all branches
  const weaknessTexts = [
    ...(it.deliberate_weaknesses || []),
    ...(net.deliberate_weaknesses || []),
    ...(tp?.deliberate_weaknesses || []),
    ...(combinedPayloads?.profiles?.governance_and_policy?.deliberate_weaknesses || [])
  ].map(String);

  const archetype = pickPostureArchetype(runId);
  const ctx = { maturity, it, net, weaknessTexts, vendorFlavor, runId, archetype };
  const answers = {};
  const notes   = {};
  let yes = 0, partial = 0, no = 0;

  for (const sg of ig1.safeguards) {
    const { answer, evidence } = deriveSafeguard(sg, ctx);
    answers[`ig1_${sg.num}`] = answer;
    notes[`ig1_${sg.num}_note`] = evidence;
    if (answer === 'yes') yes++;
    else if (answer === 'partial') partial++;
    else no++;
  }

  const total = ig1.safeguards.length;
  const coveragePct = Math.round(((yes + (partial * 0.5)) / total) * 100);

  return {
    answers,
    notes,
    coverage_pct: coveragePct,
    totals: { yes, partial, no, total },
    posture: { name: archetype.name, description: archetype.description }
  };
}

module.exports = { deriveIg1Baseline, deriveSafeguard, loadIg1 };
