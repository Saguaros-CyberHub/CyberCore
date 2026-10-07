/**
 * answer-key-risk-assessment.js — Instructor-facing answer-key generator
 * for the Clinic Risk Assessment.
 * ============================================================================
 * Given an AI-generated profile + its pre-filled intake, deterministically
 * produces a COMPLETE risk assessment the instructor can compare against
 * student submissions:
 *
 *   1. Risk findings (~15–22 per profile)  → risk_findings
 *   2. CIS RAM safeguard scoring (all 56)   → cis_ram_safeguards + cis_ram_assessments
 *   3. Executive-summary narrative           → report_deliverables
 *   4. CSF maturity scores                   → report_deliverables.csf_scores
 *
 * The output is grounded in declared profile facts (stakeholder names, EDR
 * product, MFA coverage, deliberate weaknesses, threat scenarios) so each
 * answer key is genuinely tailored — not boilerplate.
 *
 * Findings vary across profiles because:
 *   - They reference declared products/stakeholders by name
 *   - The posture archetype changes which findings dominate
 *   - The deliberate_weaknesses + threat scenarios are profile-unique
 */

const { loadIg1, deriveIg1Baseline } = require('./ig1-derivation');
const frameworks = require('./frameworks');
const { buildAssetRegister } = require('./asset-register-generator');
const { deriveReadinessFromProfile, scoreReadiness } = require('./insurance-readiness');
const { fairMonteCarlo } = require('./quant-risk');

// ─── Finding builders ────────────────────────────────────────────────────

/**
 * Pull useful pieces out of the profile + intake.
 */
function unpackContext(profileData, intakePayload) {
  const sv = profileData?.student_view?.raw?.threats || {};
  const org = sv.organization || profileData?.organization || {};
  const it  = sv.it_environment || profileData?.it_environment || {};
  const net = sv.network || profileData?.network || {};
  const tp  = sv.threat_profile || profileData?.threat_profile || null;
  const stakeholders = profileData?.student_view?.stakeholders || sv.stakeholders || profileData?.stakeholders || [];
  const ig1Section = intakePayload?.sections?.ig1 || {};
  const posture = intakePayload?._meta?.posture || null;

  return { org, it, net, tp, stakeholders, ig1Section, posture };
}

function stakeholderByPattern(stakeholders, re, fallback = null) {
  return stakeholders.find(s => re.test(String(s.role || ''))) || fallback;
}

// ─── Realistic finding library ───────────────────────────────────────────
// Each builder takes the unpacked context and returns either `null` (the
// condition that warrants this finding isn't present) or a finding object
// (no finding_code yet — assigned later in order).

function f_mfa(ctx) {
  const mfa = ctx.it?.remote_access?.mfa;
  if (mfa === 'All') return null;
  const exec = stakeholderByPattern(ctx.stakeholders, /CEO|Owner|President|Principal|Director|Superintendent/i, { name: 'the principal' });
  const it = stakeholderByPattern(ctx.stakeholders, /IT|CIO|CISO|Technology|Tech|System|Network/i, { name: 'the IT lead' });
  const noMfa = mfa === 'None' || !mfa;
  return {
    title: noMfa
      ? 'No MFA enforced on any account — credential phishing risk'
      : `MFA limited to executives — ${it.name}'s admin account and rank-and-file staff unprotected`,
    description: noMfa
      ? `${ctx.org.company_name} has not deployed multi-factor authentication on any account, including domain administrator and finance roles. ${exec.name}'s account holds wire-transfer authority. A single phishing email harvesting credentials would yield immediate access. Industry baselines (CIS IG1, NIST CSF PR.AA-03) treat MFA as table-stakes for any business handling sensitive data.`
      : `Multi-factor authentication is enabled only for executive accounts. The IT helpdesk, finance staff, and vendor / contractor accounts continue to authenticate with passwords. ${it.name}'s account in particular holds domain-admin privileges yet has not been migrated. CIS IG1 6.3 and 6.5 require MFA on ALL accounts (not just admin) and on all administrative interfaces.`,
    category: 'people',
    likelihood: noMfa ? 5 : 4,
    impact: 5,
    status: 'open',
    recommendation: noMfa
      ? `Enable MFA for all users within 30 days. Recommended sequence: (1) enroll the ${ctx.it.endpoint_protection?.product?.includes('Microsoft') ? 'Microsoft 365' : 'identity provider'} MFA service; (2) issue hardware keys (Yubikey 5 NFC ≈ $50/user) to ${exec.name}, ${it.name}, and finance staff; (3) push Authenticator-app enrollment to all remaining users; (4) enforce conditional access blocking legacy auth.`
      : `Extend MFA from "ExecOnly" to "All" via existing conditional-access policies. Stage rollout: (1) IT + admin accounts week 1; (2) finance + payroll week 2; (3) all remaining staff week 3. Sunset legacy authentication protocols (POP3, IMAP basic auth) at week 4.`,
    control_refs: [
      { framework: 'CIS_IG1', id: '6.3' },
      { framework: 'CIS_IG1', id: '6.5' },
      { framework: 'NIST_CSF', id: 'PR.AA-03' }
    ]
  };
}

function f_backups_offsite(ctx) {
  const b = ctx.it?.backups || {};
  if (b.offsite === true) return null;
  return {
    title: 'Backups stored on-premises only — single-site failure destroys recovery path',
    description: `All backup media live at the primary site. A destructive ransomware incident, environmental event (fire, water, HVAC failure), or physical theft would destroy production AND backups simultaneously. Current cadence: ${b.frequency || 'unknown'}. Last documented restore test: ${b.restore_tests || 'never recorded'}. This is the single highest-impact recoverability gap in the engagement.`,
    category: 'technical',
    likelihood: 3,
    impact: 5,
    status: 'open',
    recommendation: 'Add an offsite tier within 60 days. For SMB budgets: cloud object storage with object lock (AWS S3 Glacier, Backblaze B2, Wasabi) running nightly via the existing backup product. Estimated cost: ~$30–80/TB/month with annual commitment. Verify with a quarterly restore drill.',
    control_refs: [
      { framework: 'CIS_IG1', id: '11.2' },
      { framework: 'CIS_IG1', id: '11.5' },
      { framework: 'NIST_CSF', id: 'RC.RP-01' }
    ]
  };
}

function f_backups_immutable(ctx) {
  const b = ctx.it?.backups || {};
  if (b.immutability === true) return null;
  return {
    title: 'Backups are not immutable — vulnerable to ransomware encryption',
    description: `Backups can be modified or deleted by anyone with backup-admin credentials. Modern ransomware actively targets and destroys backups (Conti, LockBit, Akira playbooks all include this step) so a destructive incident would render recovery impossible. Without immutability, the backup tier provides protection against accidental deletion only — not against malicious destruction.`,
    category: 'technical',
    likelihood: 3,
    impact: 5,
    status: 'open',
    recommendation: 'Enable object-lock / WORM (write-once-read-many) on the offsite backup tier with a 30-day minimum lock period. Most cloud backup products support this as a free toggle. Confirm with the backup vendor that "ransomware-proof" or "immutable" is enabled and document the lock period in the IR runbook.',
    control_refs: [
      { framework: 'CIS_IG1', id: '11.3' },
      { framework: 'NIST_CSF', id: 'PR.DS-11' }
    ]
  };
}

function f_no_restore_tests(ctx) {
  const b = ctx.it?.backups || {};
  const rt = String(b.restore_tests || '').toLowerCase();
  if (rt.includes('quarterly') || rt.includes('monthly')) return null;
  return {
    title: 'Backup restore tests are not performed on a regular cadence',
    description: `${ctx.org.company_name} has not documented a regular backup-restore test program. Without periodic restore drills, the organization has no evidence that backups are recoverable. Industry data shows that 1 in 5 organizations discovers backup failures only when they attempt their first restore during an actual incident — by which time it is too late.`,
    category: 'process',
    likelihood: 3,
    impact: 4,
    status: 'open',
    recommendation: 'Establish a quarterly restore drill: pick one non-critical workload, restore to an isolated VLAN, validate data integrity + application function, record results in an IR runbook. First drill within 30 days as a baseline measurement.',
    control_refs: [
      { framework: 'CIS_IG1', id: '11.4' }
    ]
  };
}

function f_no_siem(ctx) {
  const va = ctx.it?.vendor_risk || [];  // unused but illustrative
  const it = ctx.it || {};
  // No declared SIEM/logging program → finding
  // We can't read intake's vuln_audit here from the profile alone; instead
  // gate on patch_management + remote_access + endpoint_protection telemetry.
  const hasManagedEdr = it?.endpoint_protection?.managed === true || it?.endpoint_protection?.edr_enabled === true;
  if (hasManagedEdr) {
    // Less critical but still worth flagging
    return {
      title: 'EDR telemetry is collected but not centralized — no SIEM correlation',
      description: `${ctx.it?.endpoint_protection?.product || 'The EDR'} captures endpoint events but firewall, Active Directory, and SaaS-app logs are not aggregated to a single console. Detection requires manually pivoting across vendor portals — slow and error-prone. Cross-source correlation (e.g. "unusual VPN login + unfamiliar workstation + privilege escalation") cannot be performed.`,
      category: 'technical',
      likelihood: 3,
      impact: 4,
      status: 'open',
      recommendation: 'Stand up centralized log aggregation within 90 days. For SMB-friendly options: free tiers of Wazuh, Microsoft Sentinel (3 GB/day free), or Datadog (5 GB/day free). Prioritize ingesting: (1) Active Directory auth + admin events, (2) firewall block events, (3) EDR detections, (4) M365 / Workspace audit log.',
      control_refs: [
        { framework: 'CIS_IG1', id: '8.1' },
        { framework: 'CIS_IG1', id: '8.2' },
        { framework: 'CIS_IG1', id: '8.3' },
        { framework: 'NIST_CSF', id: 'DE.AE-03' }
      ]
    };
  }
  return {
    title: 'No managed endpoint detection or central logging — limited visibility',
    description: `${ctx.org.company_name} relies on traditional antivirus only — no EDR, no SIEM, no centralized log retention beyond what individual systems keep locally (typically 7–30 days). An attacker who lands a single foothold has high dwell-time potential and will likely complete an attack chain before any signal reaches a human.`,
    category: 'technical',
    likelihood: 4,
    impact: 4,
    status: 'open',
    recommendation: 'Two-phase: (1) within 30 days deploy managed EDR (CrowdStrike Falcon Go, Bitdefender GravityZone, Sophos Intercept X) at ~$30–60/endpoint/year; (2) within 90 days stand up SIEM aggregation (Wazuh free, Microsoft Sentinel free tier) ingesting AD + firewall + EDR.',
    control_refs: [
      { framework: 'CIS_IG1', id: '10.1' },
      { framework: 'CIS_IG1', id: '8.1' },
      { framework: 'NIST_CSF', id: 'DE.CM-01' }
    ]
  };
}

function f_patch_compliance(ctx) {
  const p = ctx.it?.patch_management || {};
  const rate = Number(p.compliance_rate || 0);
  if (rate >= 85) return null;
  const method = p.method || 'unknown';
  return {
    title: `Patch compliance at ${rate || 'unknown'}% — high-severity vulnerabilities persist beyond vendor SLAs`,
    description: `Current patching cadence is ${p.frequency || 'unknown'} via ${method}. ${rate}% compliance means roughly ${100 - rate}% of endpoints are running outdated software at any given time. Modern attack tooling exploits CVEs within 24–72 hours of disclosure — at this cadence, the organization is consistently behind the curve on critical patches.`,
    category: 'technical',
    likelihood: 4,
    impact: 4,
    status: 'open',
    recommendation: `Raise patch compliance to ≥90% within 60 days. Tactical steps: (1) inventory all endpoints (Intune / WSUS reports) to find the ~${100 - rate}% out-of-band machines; (2) institute a weekly patch window with explicit waiver process; (3) measure with a public dashboard the IT lead reviews weekly; (4) escalate exceptions to management at the 14-day mark.`,
    control_refs: [
      { framework: 'CIS_IG1', id: '7.1' },
      { framework: 'CIS_IG1', id: '7.2' },
      { framework: 'CIS_IG1', id: '7.3' },
      { framework: 'NIST_CSF', id: 'PR.PS-02' }
    ]
  };
}

function f_vendor_risk(ctx) {
  const vendors = ctx.it?.vendor_risk || [];
  const stale = vendors.filter(v => /never|none|2019|2020|2021/i.test(String(v.last_assessment || '')));
  if (stale.length === 0) return null;
  const v = stale[0];
  return {
    title: `Vendor "${v.vendor || 'unnamed'}" has ${v.last_assessment === 'Never' ? 'never been risk-assessed' : 'a stale risk assessment'}`,
    description: `Third-party vendor "${v.vendor || 'unnamed'}" has ${v.access_type || 'declared'} access to ${v.data_shared || 'company systems / data'}. Last documented risk assessment: ${v.last_assessment || 'never'}. Third-party / supply-chain compromise is the leading vector for breaches in the SMB segment per Verizon DBIR — this vendor is functionally an extension of the company's attack surface but is not being managed as one.`,
    category: 'process',
    likelihood: 3,
    impact: 4,
    status: 'open',
    recommendation: `Within 30 days: (1) obtain vendor's most recent SOC 2 Type II report or equivalent attestation; (2) review their MFA, encryption, and IR posture; (3) document acceptable / unacceptable findings and decide whether to renegotiate or replace. Add an annual review cadence to procurement workflow for ALL ${vendors.length} declared vendors.`,
    control_refs: [
      { framework: 'CIS_IG1', id: '15.1' },
      { framework: 'NIST_CSF', id: 'GV.SC-04' }
    ]
  };
}

function f_flat_network(ctx) {
  const subnets = ctx.net?.subnets || [];
  const weaknesses = (ctx.net?.deliberate_weaknesses || []).join(' ').toLowerCase();
  if (subnets.length >= 3 && !weaknesses.includes('flat')) return null;
  return {
    title: 'Network lacks segmentation between user, server, and guest traffic',
    description: `The current topology runs ${subnets.length || 'all'} subnet(s) without trust-zone separation. A compromised workstation has direct east-west access to file shares, the domain controller, and management interfaces. Standard ransomware playbooks complete in under 4 hours on flat networks — segmentation is the single most effective lateral-movement disruptor available to SMBs.`,
    category: 'technical',
    likelihood: 4,
    impact: 4,
    status: 'open',
    recommendation: 'Within 90 days establish minimum three trust zones: User (workstations + printers), Server (DC, file, app, sql, web), Guest (BYOD + visitor wifi). Implement at the existing firewall/L3 switch with default-deny between zones, opening only the specific ports each role needs. Document the firewall rules in the IR runbook.',
    control_refs: [
      { framework: 'CIS_IG1', id: '12.1' },
      { framework: 'CIS_IG1', id: '13.1' },
      { framework: 'NIST_CSF', id: 'PR.IR-01' }
    ]
  };
}

function f_no_dlp(ctx) {
  // Always include — almost no SMB has DLP and the regulatory exposure is real
  if (Number(ctx.it?.endpoint_protection?.coverage_percent || 0) < 50) return null;
  return {
    title: 'No data loss prevention (DLP) policy enforced on email or endpoints',
    description: `${ctx.org.company_name} has no DLP rules preventing sensitive data (customer PII, financial records, intellectual property) from being attached to outbound email, copied to removable media, or uploaded to unauthorized cloud services. Both intentional exfiltration (insider threat) and accidental disclosure (autocomplete-to-wrong-recipient) are possible with no visibility or block.`,
    category: 'technical',
    likelihood: 2,
    impact: 4,
    status: 'open',
    recommendation: 'Phase in DLP over 6 months. Phase 1: enable Microsoft Purview / Google DLP default templates in audit-only mode for 30 days to baseline normal traffic. Phase 2: convert top 3 violating rules from audit to block. Phase 3: extend to endpoint DLP (USB exfil blocking) via existing EDR.',
    control_refs: [
      { framework: 'CIS_IG1', id: '3.1' },
      { framework: 'CIS_IG1', id: '3.2' },
      { framework: 'NIST_CSF', id: 'PR.DS-05' }
    ]
  };
}

function f_no_awareness(ctx) {
  // Tied to maturity — low maturity profiles get this finding
  if (/high/i.test(String(ctx.it?.maturity || ''))) return null;
  return {
    title: 'No formal security-awareness training program for staff',
    description: `New hires receive no documented security training. Existing staff have no annual refresher, no simulated-phishing program, and no recorded acknowledgment of acceptable-use policies. Verizon DBIR data shows ~75% of SMB breaches start with social engineering — staff training is the cheapest, highest-leverage control available.`,
    category: 'people',
    likelihood: 4,
    impact: 3,
    status: 'open',
    recommendation: 'Within 60 days: (1) license a training platform (KnowBe4, Hoxhunt, Curricula) — typically $20–35 per user per year; (2) deliver a 30-minute onboarding module to all current staff; (3) launch monthly simulated-phishing campaign; (4) require annual recertification with completion tracked by HR.',
    control_refs: [
      { framework: 'CIS_IG1', id: '14.1' },
      { framework: 'CIS_IG1', id: '14.2' },
      { framework: 'NIST_CSF', id: 'PR.AT-01' }
    ]
  };
}

function f_no_ir_plan(ctx) {
  // Always-on finding for SMB profiles — almost none have a true IR plan
  return {
    title: 'No documented incident-response plan or contact list',
    description: `${ctx.org.company_name} has no written incident-response plan. There is no defined call tree, no documented decision authority for engaging law enforcement / cyber insurance / external IR firms, and no playbook for the most-likely scenarios (ransomware, BEC, data breach). During an actual incident, the first 4 hours — when most cost is incurred — will be spent reading other people's templates.`,
    category: 'process',
    likelihood: 5,  // certainty: a major incident WILL eventually occur
    impact: 4,
    status: 'open',
    recommendation: 'Within 90 days: (1) draft a 10-page IR plan covering the top 4 scenarios (ransomware, BEC, data theft, insider) — use SANS or NIST IR plan templates as a starting point; (2) populate the call tree with named individuals + backups; (3) pre-engage a retainer-based IR firm and cyber-insurance carrier; (4) run one tabletop exercise per quarter for the leadership team.',
    control_refs: [
      { framework: 'CIS_IG1', id: '17.1' },
      { framework: 'CIS_IG1', id: '17.2' },
      { framework: 'NIST_CSF', id: 'RS.MA-01' }
    ]
  };
}

function f_threat_scenario(scn, idx) {
  if (!scn) return null;
  const likelihoodMap = { Low: 2, Medium: 3, High: 4 };
  return {
    title: `Plausible attack chain: ${scn.name || `Scenario ${idx + 1}`}`,
    description: `Type: ${scn.type || 'unknown'}. Initial vector: ${scn.initial_vector || 'not specified'}. Threat actor profile: ${scn.threat_actor || 'unknown'}. Likely impact: ${scn.potential_impact || 'high-confidence service disruption + data exposure'}. This scenario was identified during the threat-modeling phase as plausible given the company's industry, exposure surface, and current control posture.`,
    category: 'technical',
    likelihood: likelihoodMap[scn.likelihood] || 3,
    impact: 4,
    status: 'open',
    recommendation: scn.attack_path?.[0]?.detection_opportunity
      ? `Disrupt the attack chain at step 1 (initial access): ${scn.attack_path[0].detection_opportunity}. Add complementary controls at lateral-movement step.`
      : 'Build layered detection: (1) email security at perimeter, (2) EDR on endpoint, (3) authentication anomaly alerts, (4) data-exfil DLP at egress.',
    control_refs: [
      { framework: 'CIS_IG1', id: '10.1' },
      { framework: 'NIST_CSF', id: 'DE.CM-01' }
    ]
  };
}

function f_deliberate_weakness(text, idx) {
  if (!text) return null;
  const lower = text.toLowerCase();
  // Map weakness keywords to categories + scoring + control refs
  let category = 'technical';
  let likelihood = 3, impact = 3;
  let controls = [{ framework: 'CIS_IG1', id: '4.1' }];
  if (/mfa|password|credential|account/.test(lower)) { category = 'people'; likelihood = 4; impact = 4; controls = [{framework:'CIS_IG1', id:'6.3'}]; }
  else if (/backup|recovery/.test(lower))             { category = 'technical'; likelihood = 3; impact = 5; controls = [{framework:'CIS_IG1', id:'11.2'}]; }
  else if (/log|siem|monitor|audit/.test(lower))      { category = 'technical'; likelihood = 3; impact = 3; controls = [{framework:'CIS_IG1', id:'8.2'}]; }
  else if (/policy|training|awareness/.test(lower))   { category = 'people';    likelihood = 3; impact = 3; controls = [{framework:'CIS_IG1', id:'14.1'}]; }
  else if (/firewall|segment|vlan|network/.test(lower)) { category = 'technical'; likelihood = 3; impact = 4; controls = [{framework:'CIS_IG1', id:'12.1'}]; }
  else if (/vendor|third.?party/.test(lower))         { category = 'process';   likelihood = 3; impact = 4; controls = [{framework:'CIS_IG1', id:'15.1'}]; }
  return {
    title: text.length > 100 ? text.slice(0, 97) + '...' : text,
    description: `${text}. Identified during the architectural / control review. This weakness is exploitable as documented and should be remediated as part of the engagement closeout.`,
    category,
    likelihood,
    impact,
    status: 'open',
    recommendation: 'Document a remediation plan with owner + target date during the closeout meeting. Escalate to leadership if remediation cost exceeds the assessor-recommended threshold.',
    control_refs: controls
  };
}

// Map a finding category + control refs to an owner role + threat source +
// realistic discovery method. Used to enrich the answer-key findings with
// Tier 1 fields (owner / due date / evidence / discovery / threat source).
function enrichFindingMeta(finding, ctx) {
  const refs = (finding.control_refs || []).map(r => String(r.id || ''));
  const cat = finding.category || '';
  const title = String(finding.title || '').toLowerCase();
  const stake = ctx.stakeholders || [];
  const exec  = stake.find(s => /CEO|Owner|President|Principal|Director/i.test(s.role || ''));
  const it    = stake.find(s => /IT|CIO|CISO|Technology|System|Network/i.test(s.role || ''));
  const cfo   = stake.find(s => /CFO|Finance|Accountant|Controller/i.test(s.role || ''));
  const hr    = stake.find(s => /HR|People|Talent/i.test(s.role || ''));

  // Owner role + name by category
  let owner_role = 'IT Manager';
  let owner_name = it?.name || null;
  if (/Identity|Account|MFA|Password|Privileg/i.test(title) || refs.some(r => /^5\.|^6\./.test(r))) {
    owner_role = 'IT Manager'; owner_name = it?.name || null;
  }
  if (/Backup|Recovery|Data|Privacy|DLP/i.test(title) || refs.some(r => /^3\.|^11\./.test(r))) {
    owner_role = 'IT Manager'; owner_name = it?.name || null;
  }
  if (/Training|Awareness|Policy|Governance/i.test(title) || refs.some(r => /^14\./.test(r))) {
    owner_role = 'HR Manager'; owner_name = hr?.name || it?.name || null;
  }
  if (/Vendor|Third-?party|Supply.?chain|SaaS/i.test(title) || refs.some(r => /^15\./.test(r))) {
    owner_role = 'CFO'; owner_name = cfo?.name || null;
  }
  if (/Incident.?Response|IR.?plan|Tabletop/i.test(title) || refs.some(r => /^17\./.test(r))) {
    owner_role = 'CEO'; owner_name = exec?.name || null;
  }

  // Threat source (NIST 800-30 taxonomy)
  let threat_source = 'adversarial';  // default
  if (/structural|no\s+(plan|test|policy|inventory|training)/i.test(title) || /^(11\.|14\.|17\.)/.test(refs.join(' '))) {
    threat_source = 'structural';
  }
  if (/misconfigur|accidental|exposure|expired/i.test(title)) threat_source = 'accidental';
  if (/disaster|weather|environmental|outage|power/i.test(title)) threat_source = 'environmental';

  // Discovery method
  let discovery_method = 'document_review';
  if (cat === 'people')   discovery_method = 'interview';
  if (cat === 'process')  discovery_method = 'document_review';
  if (cat === 'technical') discovery_method = 'technical_scan';
  if (cat === 'physical') discovery_method = 'observation';

  // Evidence observed — short specific note grounded in declared facts
  let evidence = '';
  if (/mfa/i.test(title)) {
    evidence = `Verified via interview with ${it?.name || 'IT lead'}: MFA enforcement set to "${ctx.it?.remote_access?.mfa || 'unknown'}" in the identity provider console.`;
  } else if (/patch/i.test(title)) {
    evidence = `Patch dashboard screenshot from ${ctx.it?.patch_management?.method || 'patch console'} shows ${ctx.it?.patch_management?.compliance_rate || '?'}% compliance.`;
  } else if (/backup/i.test(title)) {
    evidence = `Backup-tool config review (${ctx.it?.backups?.frequency || 'unknown'} schedule). Restore tests: ${ctx.it?.backups?.restore_tests || 'never documented'}.`;
  } else if (/vendor/i.test(title)) {
    evidence = `Vendor inventory review: ${(ctx.it?.vendor_risk || []).length} vendors documented, missing SOC 2 attestations for several.`;
  } else if (/incident|ir.?plan|tabletop/i.test(title)) {
    evidence = `Interview with ${exec?.name || 'leadership'}: no IR plan document exists, no documented tabletop exercise in past 12 months.`;
  } else if (/training|awareness/i.test(title)) {
    evidence = `HR interview: no formal security training program, no simulated-phishing campaign, no acknowledged AUP on file.`;
  } else if (/network|segment|firewall/i.test(title)) {
    evidence = `Network architecture review: firewall rule export + topology diagram analysis.`;
  } else if (/dlp/i.test(title)) {
    evidence = `Email + endpoint configuration review: no DLP rules enabled in either tier.`;
  } else if (/siem|logging/i.test(title)) {
    evidence = `Console walkthrough: ${ctx.it?.endpoint_protection?.product || 'EDR'} logs available only in vendor portal; no centralized SIEM detected.`;
  } else {
    evidence = `Documented during architectural review of declared IT environment + interview with ${it?.name || 'IT lead'}.`;
  }

  // Target completion date — based on severity
  const inherent = (finding.likelihood || 0) * (finding.impact || 0);
  const today = new Date();
  const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x.toISOString().slice(0, 10); };
  let target_completion_date;
  if (inherent >= 16)      target_completion_date = addDays(today, 30);   // critical: 30d
  else if (inherent >= 12) target_completion_date = addDays(today, 60);   // high: 60d
  else if (inherent >= 6)  target_completion_date = addDays(today, 90);   // medium: 90d
  else                     target_completion_date = addDays(today, 180);  // low: 6mo

  // Reviewer — same role as owner unless owner IS the IT lead, in which case CEO reviews
  let reviewer = exec?.name || 'CEO';
  if (owner_role === 'CEO' || owner_role === 'CFO') reviewer = exec?.name || 'CEO';
  else if (it?.name && owner_role !== 'IT Manager') reviewer = it.name;
  else reviewer = exec?.name || 'CEO';

  return {
    ...finding,
    owner_role,
    owner_name,
    reviewer,
    target_completion_date,
    evidence_observed: evidence,
    discovery_method,
    threat_source
  };
}

// Project a finding's residual (post-treatment) likelihood + impact.
//
// Industry rule of thumb (NIST SP 800-30, CIS RAM v2.1):
//   - Most controls reduce LIKELIHOOD (you prevent the bad thing from
//     happening); impact tends to stay the same (the bad thing, if it
//     happens, still hurts about the same).
//   - A few control categories reduce IMPACT too: backups + immutability
//     (you can recover), network segmentation (smaller blast radius), DLP
//     (less data exfiltrated), encryption at rest.
//
// We model this with two reductions:
//   residual_likelihood = max(1, likelihood - 2)   ← strong reduction
//   residual_impact     = max(1, impact - {1 or 0}) ← modest, varies by control category
function deriveResidualScores(finding) {
  const L = Number(finding.likelihood || 0);
  const I = Number(finding.impact || 0);
  if (!L || !I) return { residual_likelihood: null, residual_impact: null };

  // Categories whose treatments meaningfully reduce IMPACT (not just likelihood)
  const impactReducingRefs = (finding.control_refs || [])
    .map(r => String(r.id || ''))
    .some(id => /^11\./.test(id)   // Data Recovery
             || /^12\./.test(id)   // Network Infrastructure (segmentation)
             || /^13\./.test(id)   // Network monitoring & defense
             || /^3\./.test(id));  // Data Protection

  const residualLikelihood = Math.max(1, L - 2);
  const residualImpact     = impactReducingRefs ? Math.max(1, I - 1) : I;
  return { residual_likelihood: residualLikelihood, residual_impact: residualImpact };
}

/**
 * Build the full findings list for this profile.
 * Deterministic, ordered: critical findings first, then medium, then low.
 */
function buildFindings(ctx) {
  const candidates = [
    f_mfa(ctx),
    f_no_ir_plan(ctx),
    f_backups_offsite(ctx),
    f_backups_immutable(ctx),
    f_no_restore_tests(ctx),
    f_no_siem(ctx),
    f_patch_compliance(ctx),
    f_vendor_risk(ctx),
    f_flat_network(ctx),
    f_no_dlp(ctx),
    f_no_awareness(ctx)
  ].filter(Boolean);

  // Add up to 3 threat-scenario findings
  const scenarios = (ctx.tp?.scenarios || []).slice(0, 3);
  scenarios.forEach((scn, idx) => candidates.push(f_threat_scenario(scn, idx)));

  // Add up to 6 deliberate-weakness findings from IT / network / governance branches
  const weaknesses = [
    ...(ctx.it?.deliberate_weaknesses || []),
    ...(ctx.net?.deliberate_weaknesses || []),
    ...((ctx.org?.profiles?.governance_and_policy?.deliberate_weaknesses) || [])
  ].slice(0, 6);
  weaknesses.forEach((w, idx) => {
    const f = f_deliberate_weakness(w, idx);
    if (f) candidates.push(f);
  });

  // Filter nulls, dedupe by title, sort by inherent risk desc
  const seen = new Set();
  const out = [];
  candidates.filter(Boolean).forEach(c => {
    const key = c.title.toLowerCase().slice(0, 50);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(c);
  });
  out.sort((a, b) => (b.likelihood * b.impact) - (a.likelihood * a.impact));

  // Assign finding codes in priority order + project residual scores + enrich with owner/evidence/threat source
  return out.map((f, i) => {
    const enriched = enrichFindingMeta({
      ...f,
      finding_code: `F-${String(i + 1).padStart(3, '0')}`,
      ...deriveResidualScores(f)
    }, ctx);
    return enriched;
  });
}

// Link findings to relevant assets by keyword matching against asset names.
// Returns affected_asset_ids[] per finding (UUIDs assigned by DB INSERT —
// we use a 2-pass approach: insert assets first to get IDs, then link).
function linkFindingsToAssets(findings, assetsWithIds) {
  return findings.map(f => {
    const title = String(f.title || '').toLowerCase();
    const desc = String(f.description || '').toLowerCase();
    const text = title + ' ' + desc;
    const affected = [];

    // Heuristic linking
    if (/mfa|password|credential|account|admin/.test(text)) {
      // Identity-related — affects DC + all SaaS apps
      assetsWithIds.forEach(a => {
        if (/Domain Controller|Email|CRM|Accounting/i.test(a.name) || a.asset_type === 'saas')
          affected.push(a.id);
      });
    }
    if (/backup|recovery|ransomware/.test(text)) {
      assetsWithIds.forEach(a => {
        if (/Backup|File Server|Database/i.test(a.name)) affected.push(a.id);
      });
    }
    if (/network|segment|flat|firewall|vlan/.test(text)) {
      assetsWithIds.forEach(a => {
        if (/Firewall|Switch/i.test(a.name)) affected.push(a.id);
      });
    }
    if (/patch|vuln|outdated|cve/.test(text)) {
      assetsWithIds.forEach(a => {
        if (a.asset_type === 'server' || a.asset_type === 'workstation') affected.push(a.id);
      });
    }
    if (/web|application|app/.test(text)) {
      assetsWithIds.forEach(a => {
        if (/Web|Application/i.test(a.name)) affected.push(a.id);
      });
    }
    if (/vendor|third.?party|supply.?chain|saas/.test(text)) {
      assetsWithIds.forEach(a => {
        if (a.asset_type === 'saas') affected.push(a.id);
      });
    }
    if (/dlp|data\s+(loss|exposure|theft)|exfil|customer|pii|phi/.test(text)) {
      assetsWithIds.forEach(a => {
        if (/Customer Records|Employee Records|Data/i.test(a.name) || a.data_classification === 'Restricted')
          affected.push(a.id);
      });
    }
    if (/laptop|stolen|physical/.test(text)) {
      assetsWithIds.forEach(a => {
        if (a.asset_type === 'workstation' || a.asset_type === 'mobile') affected.push(a.id);
      });
    }
    if (/email|phishing|bec|wire/.test(text)) {
      assetsWithIds.forEach(a => {
        if (/Email|Executive/i.test(a.name)) affected.push(a.id);
      });
    }

    return { ...f, affected_asset_ids: [...new Set(affected)].slice(0, 6) };
  });
}

// ─── CIS RAM scoring ─────────────────────────────────────────────────────

function answerToLikelihood(answer) {
  if (answer === 'yes') return 1;       // control in place → low likelihood of related event
  if (answer === 'partial') return 2;
  return 3;                              // 'no' or missing → high likelihood
}

// Per-control inherent-impact heuristics (1=low, 2=medium, 3=high). The
// numbers express the BUSINESS impact if the control's purpose is breached
// — e.g. backup failure (control 11) is higher mission-impact than software
// inventory drift (control 2).
const CONTROL_MISSION_IMPACT = {
  1: 2, 2: 1, 3: 3, 4: 2, 5: 2, 6: 3, 7: 2, 8: 2, 9: 2,
  10: 3, 11: 3, 12: 2, 13: 2, 14: 2, 15: 2, 16: 2, 17: 3
};
const CONTROL_OBLIGATIONS_IMPACT = {
  1: 2, 2: 2, 3: 3, 4: 1, 5: 3, 6: 3, 7: 2, 8: 3, 9: 2,
  10: 2, 11: 3, 12: 1, 13: 2, 14: 3, 15: 3, 16: 2, 17: 3
};
const CONTROL_ASSET_CLASS = {
  1: 'Enterprise Assets', 2: 'Software', 3: 'Data',
  4: 'Enterprise Assets', 5: 'Accounts', 6: 'Accounts',
  7: 'Software', 8: 'Logs', 9: 'Email + Web',
  10: 'Enterprise Assets', 11: 'Data', 12: 'Network',
  13: 'Network', 14: 'People', 15: 'Service Providers',
  16: 'Application Software', 17: 'Incident Response'
};

// Treatment-cost rough buckets by control number.
const CONTROL_COST = {
  1: '$', 2: '$', 3: '$$', 4: '$', 5: '$', 6: '$', 7: '$', 8: '$$', 9: '$',
  10: '$$', 11: '$$', 12: '$', 13: '$$', 14: '$', 15: '$', 16: '$$$', 17: '$'
};

function buildCisRamRows(ctx, ig1Catalog) {
  const rows = [];
  for (const sg of ig1Catalog.safeguards) {
    const answer = ctx.ig1Section[`ig1_${sg.num}`] || 'unknown';
    const likelihood = answerToLikelihood(answer);
    const mImpact = CONTROL_MISSION_IMPACT[sg.control]      || 2;
    const oImpact = CONTROL_OBLIGATIONS_IMPACT[sg.control] || 2;
    const inherent = likelihood * Math.max(mImpact, oImpact);

    // Treatment plan — if not 'yes', describe what needs to happen
    let treatment_title, treatment_desc, tL = likelihood, tM = mImpact, tO = oImpact;
    if (answer === 'yes') {
      treatment_title = 'Maintain current control';
      treatment_desc = `${sg.name} is implemented. Verify annually that the control still operates as designed and that asset coverage matches inventory growth.`;
      tL = 1;
    } else if (answer === 'partial') {
      treatment_title = `Close coverage gaps in ${sg.name}`;
      treatment_desc = `Control is partially in place. Identify uncovered assets / accounts / processes and extend coverage to ≥95% within 90 days. Document the gap-closure plan with named owner.`;
      tL = 1;  // treatment brings likelihood down
    } else {
      treatment_title = `Implement ${sg.name}`;
      treatment_desc = `Control is not in place. Develop implementation plan within 30 days; deploy within 90 days; verify with control test by end of quarter.`;
      tL = 1;
    }

    rows.push({
      safeguard_num: sg.num,
      asset_class: CONTROL_ASSET_CLASS[sg.control] || 'Enterprise Assets',
      mission_impact: mImpact,
      obligations_impact: oImpact,
      likelihood,
      treatment_safeguard: sg.num,
      treatment_title,
      treatment_description: treatment_desc,
      treatment_mission_impact: mImpact,
      treatment_obligations_impact: oImpact,
      treatment_likelihood: tL,
      treatment_cost: CONTROL_COST[sg.control] || '$',
      implementation_year: new Date().getFullYear(),
      status: answer === 'yes' ? 'mitigated' : (answer === 'partial' ? 'open' : 'open'),
      notes: `Answer-key baseline derived from declared IT controls and CIS RAM heuristics. Inherent risk ${inherent}/9 → treatment target ≤ ${tL * Math.max(mImpact, oImpact)}/9.`
    });
  }
  return rows;
}

// ─── Executive summary builder ───────────────────────────────────────────

function buildExecSummary(ctx, findings, coverage, csfScores) {
  const critical = findings.filter(f => f.likelihood * f.impact >= 16);
  const high     = findings.filter(f => f.likelihood * f.impact >= 12 && f.likelihood * f.impact < 16);
  const medium   = findings.filter(f => f.likelihood * f.impact >= 6 && f.likelihood * f.impact < 12);
  const csfAvg = (['GV','ID','PR','DE','RS','RC'].reduce((s, k) => s + (csfScores[k] || 0), 0) / 6).toFixed(1);
  const weakestCsf = ['GV','ID','PR','DE','RS','RC']
    .map(k => ({ k, score: csfScores[k] || 0 })).sort((a,b)=>a.score-b.score)[0];
  const fnNames = { GV:'Govern', ID:'Identify', PR:'Protect', DE:'Detect', RS:'Respond', RC:'Recover' };
  const postureNote = ctx.posture
    ? ` Their compliance posture maps to the "${ctx.posture.name}" archetype: ${ctx.posture.description || 'distinct strengths and weaknesses across control families'}.`
    : '';
  const employeeBand = ctx.org?.employees_total ? `${ctx.org.employees_total}-employee ` : '';
  const industry = ctx.org?.industry || 'small-business';

  const topThree = findings.slice(0, 3).map((f, i) =>
    `(${i + 1}) ${f.title}`).join('; ');

  return [
    `${ctx.org?.company_name || 'The organization'} is a ${employeeBand}${industry} firm.${postureNote}`,
    '',
    `Overall cybersecurity posture is consistent with their declared maturity level. The assessment identified ${findings.length} findings across technical, process, people, and physical-control categories: ${critical.length} critical, ${high.length} high, ${medium.length} medium, and ${findings.length - critical.length - high.length - medium.length} low-severity.`,
    '',
    `The CIS Controls v8 IG1 baseline shows ${coverage.score}% coverage (${coverage.yes} of ${coverage.total} safeguards fully implemented, ${coverage.partial} partial, ${coverage.no} not met). The NIST CSF 2.0 maturity index is ${csfAvg} / 5, with the ${fnNames[weakestCsf.k]} function the weakest at ${weakestCsf.score.toFixed(1)}.`,
    '',
    `Top priority findings for the next 90 days: ${topThree}.`,
    '',
    `Recommended approach: address the three critical findings through quick-win remediations (MFA extension, backup immutability, IR-plan drafting) within the first 30 days, then run a 60-day IG1 uplift sprint targeting the top 10 unmet safeguards. Standing up centralized logging and a security-awareness program will produce the largest CSF function-score gains for the lowest capital outlay. Reassess in 6 months.`
  ].join('\n');
}

// Deloitte / CISO-board-report structure for the executive summary.
// Returns { current_posture, top_risks, progress, decisions_needed }
// — each a 1-2 paragraph string ready for the report.
function buildDeloitteExecSummary(ctx, findings, coverage, csfScores, readiness) {
  const critical = findings.filter(f => f.likelihood * f.impact >= 16);
  const high     = findings.filter(f => f.likelihood * f.impact >= 12 && f.likelihood * f.impact < 16);
  const csfAvg = (['GV','ID','PR','DE','RS','RC']
    .reduce((s, k) => s + (csfScores[k] || 0), 0) / 6).toFixed(1);
  const company = ctx.org?.company_name || 'The organization';
  const industry = ctx.org?.industry || 'small-business';
  const employeeBand = ctx.org?.employees_total ? `${ctx.org.employees_total}-employee ` : '';
  const postureName = ctx.posture?.name ? `"${ctx.posture.name}"` : 'mixed';

  const top3 = findings.slice(0, 3);

  const current_posture =
    `${company} is a ${employeeBand}${industry} firm with a ${postureName} compliance posture. ` +
    `Against the CIS Controls v8 Implementation Group 1 baseline, the organization has implemented ${coverage.yes} of ${coverage.total} safeguards (${coverage.score}% coverage). ` +
    `NIST CSF 2.0 maturity averages ${csfAvg} of 5 across the six functions, indicating ${csfAvg >= 3.5 ? 'a mature' : csfAvg >= 2 ? 'a developing' : 'an early-stage'} cybersecurity program. ` +
    `Cyber-insurance readiness scores ${readiness?.score ?? '—'}/100, placing the organization in the "${readiness?.tier ?? 'Unrated'}" tier with current underwriters.`;

  const top_risks =
    `Three risks demand board-level attention: ` +
    top3.map((f, i) => `(${i + 1}) ${f.title} — inherent risk ${f.likelihood}×${f.impact}=${f.likelihood * f.impact}, ${f.likelihood * f.impact >= 16 ? 'critical' : 'high'} severity, ${f.owner_role || 'IT'}-owned.`).join(' ') +
    ` Collectively these represent the largest reduction-of-exposure opportunities in the next two quarters. ` +
    `If implemented as specified in Section 06 (Recommendations), the projected aggregate risk reduction is approximately ${(() => {
      const inh = findings.reduce((s, f) => s + (f.likelihood * f.impact), 0);
      const res = findings.reduce((s, f) => s + ((f.residual_likelihood || f.likelihood) * (f.residual_impact || f.impact)), 0);
      return inh > 0 ? Math.round(((inh - res) / inh) * 100) + '%' : 'meaningful';
    })()}.`;

  const progress =
    findings.some(f => f.status === 'mitigated')
      ? `${findings.filter(f => f.status === 'mitigated').length} of ${findings.length} findings have already been mitigated since the prior engagement, demonstrating active remediation capability. ${findings.filter(f => f.status === 'open').length} findings remain open and require attention.`
      : `This is the first formal risk assessment of record; no prior baseline exists to measure progress against. We recommend establishing this assessment as the baseline and re-measuring in 6 months following implementation of the recommendations in Section 06.`;

  const decisions_needed =
    `The leadership team should make explicit decisions on: ` +
    `(1) BUDGET — approval of the cyber-insurance readiness uplift (estimated $${Math.round(15000 + (critical.length * 5000)).toLocaleString()} one-time + $${Math.round(8000 + (csfAvg < 2 ? 6000 : 0)).toLocaleString()}/year recurring) to move from ${readiness?.tier || 'current tier'} to Insurable; ` +
    `(2) POLICY — formal adoption of the documented Incident Response plan + assignment of named tabletop owners; ` +
    `(3) STAFFING — designation of a single accountable owner for cybersecurity (CISO function, even if part-time or fractional); ` +
    `(4) RISK ACCEPTANCE — written sign-off on any of the ${critical.length} critical findings the board elects to formally accept rather than remediate. ` +
    `These decisions should be documented at the next leadership meeting and revisited quarterly.`;

  return { current_posture, top_risks, progress, decisions_needed };
}

// ─── Top-level entry: persist the answer key into the DB ─────────────────

/**
 * Generate and persist a complete answer-key risk assessment for the
 * instructor. Idempotent — re-running deletes prior rows and rewrites.
 *
 * @param {object} opts
 * @param {string} opts.profileId
 * @param {string} opts.userId         — the instructor's user_id
 * @param {object} opts.profileData    — full profile JSON (student_view + meta)
 * @param {object} opts.intakePayload  — intake.payload (v1.1 shape, with sections.ig1 + _meta.posture)
 * @param {object} opts.pool           — pg Pool
 * @returns {Promise<{findings_inserted, cis_ram_rows_inserted, report_id, exec_summary, coverage, csf_scores}>}
 */
async function generateInstructorAnswerKeyRiskAssessment({ profileId, userId, profileData, intakePayload, pool }) {
  if (!profileId || !userId) throw new Error('profileId and userId required');
  if (!pool) throw new Error('pg pool required');

  const ctx = unpackContext(profileData, intakePayload);
  const ig1Catalog = loadIg1();

  // 1) Findings ------------------------------------------------------------
  const findings = buildFindings(ctx);

  // 2) CIS RAM scoring ----------------------------------------------------
  const cisRamRows = buildCisRamRows(ctx, ig1Catalog);

  // 3) Coverage + CSF -----------------------------------------------------
  const coverage = frameworks.ig1Coverage(ctx.ig1Section);
  const csfScores = frameworks.aggregateIg1ToCsf(ctx.ig1Section);

  // 4) Exec summary -------------------------------------------------------
  const execSummary = buildExecSummary(ctx, findings, coverage, csfScores);

  // 5) Asset register -----------------------------------------------------
  const assetRows = buildAssetRegister(ctx);

  // 6) Insurance readiness ------------------------------------------------
  const readinessAnswers = deriveReadinessFromProfile(ctx);
  // Posture-driven overrides: a mature posture has these in place too
  if (ctx.posture?.name === 'compliance-mature' || ctx.posture?.name === 'policy-strong-tech-weak') {
    readinessAnswers.ir_plan_written = 'yes';
    readinessAnswers.tabletop_12mo = 'partial';
    readinessAnswers.security_training = 'yes';
  }
  if (ctx.posture?.name === 'tech-mature-policy-weak' || ctx.posture?.name === 'endpoint-heavy') {
    readinessAnswers.vuln_scanning = 'yes';
    readinessAnswers.pam_in_place = 'partial';
  }
  const readinessScore = scoreReadiness(readinessAnswers);

  // 7) Persist ------------------------------------------------------------
  // Delete prior answer key for this profile (idempotent re-run).
  await pool.query(`DELETE FROM risk_findings WHERE profile_id = $1 AND user_id = $2 AND ai_generated = true`, [profileId, userId]);
  await pool.query(`DELETE FROM risk_assets WHERE profile_id = $1 AND user_id = $2 AND ai_generated = true`, [profileId, userId]);

  // 7a) Insert asset register first so we have IDs for finding linkage
  const insertedAssets = [];
  for (const a of assetRows) {
    const r = await pool.query(`
      INSERT INTO risk_assets
        (user_id, profile_id, name, asset_type, owner_role, custodian,
         confidentiality, integrity, availability, criticality_tier,
         data_classification, data_categories, hostname, description,
         containers, ai_generated)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15::jsonb, true)
      RETURNING id, name, asset_type, data_classification
    `, [
      userId, profileId, a.name, a.asset_type, a.owner_role, a.custodian,
      a.confidentiality, a.integrity, a.availability, a.criticality_tier,
      a.data_classification, JSON.stringify(a.data_categories || []),
      a.hostname || null, a.description || null,
      JSON.stringify(a.containers || [])
    ]);
    insertedAssets.push(r.rows[0]);
  }

  // 7b) Link findings to assets
  const linkedFindings = linkFindingsToAssets(findings, insertedAssets);

  let findingsInserted = 0;
  for (const f of linkedFindings) {
    await pool.query(`
      INSERT INTO risk_findings
        (user_id, profile_id, finding_code, title, description, category,
         likelihood, impact, residual_likelihood, residual_impact,
         status, recommendation, control_refs, ai_generated,
         owner_role, owner_name, reviewer, target_completion_date,
         evidence_observed, discovery_method, threat_source, affected_asset_ids,
         scenario_library_key)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, true,
              $14, $15, $16, $17, $18, $19, $20, $21::jsonb, $22)
      ON CONFLICT (profile_id, finding_code) DO UPDATE SET
        title = EXCLUDED.title, description = EXCLUDED.description,
        category = EXCLUDED.category, likelihood = EXCLUDED.likelihood,
        impact = EXCLUDED.impact,
        residual_likelihood = EXCLUDED.residual_likelihood,
        residual_impact = EXCLUDED.residual_impact,
        status = EXCLUDED.status,
        recommendation = EXCLUDED.recommendation, control_refs = EXCLUDED.control_refs,
        owner_role = EXCLUDED.owner_role, owner_name = EXCLUDED.owner_name,
        reviewer = EXCLUDED.reviewer, target_completion_date = EXCLUDED.target_completion_date,
        evidence_observed = EXCLUDED.evidence_observed,
        discovery_method = EXCLUDED.discovery_method,
        threat_source = EXCLUDED.threat_source,
        affected_asset_ids = EXCLUDED.affected_asset_ids,
        scenario_library_key = EXCLUDED.scenario_library_key,
        updated_at = NOW()
    `, [
      userId, profileId, f.finding_code, f.title, f.description, f.category,
      f.likelihood, f.impact, f.residual_likelihood, f.residual_impact,
      f.status, f.recommendation,
      JSON.stringify(f.control_refs || []),
      f.owner_role || null, f.owner_name || null, f.reviewer || null,
      f.target_completion_date || null,
      f.evidence_observed || null, f.discovery_method || null,
      f.threat_source || null,
      JSON.stringify(f.affected_asset_ids || []),
      f.scenario_library_key || null
    ]);
    findingsInserted++;
  }

  // 7c) Insurance readiness upsert
  await pool.query(`
    INSERT INTO insurance_readiness
      (user_id, profile_id, mfa_email, mfa_remote, mfa_privileged, mfa_cloud,
       edr_coverage_pct, immutable_backups, tested_restore_12mo,
       ir_plan_written, tabletop_12mo, pam_in_place, security_training, vuln_scanning,
       readiness_score, readiness_tier, ai_generated)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, true)
    ON CONFLICT (profile_id, user_id) DO UPDATE SET
      mfa_email = EXCLUDED.mfa_email, mfa_remote = EXCLUDED.mfa_remote,
      mfa_privileged = EXCLUDED.mfa_privileged, mfa_cloud = EXCLUDED.mfa_cloud,
      edr_coverage_pct = EXCLUDED.edr_coverage_pct,
      immutable_backups = EXCLUDED.immutable_backups,
      tested_restore_12mo = EXCLUDED.tested_restore_12mo,
      ir_plan_written = EXCLUDED.ir_plan_written,
      tabletop_12mo = EXCLUDED.tabletop_12mo,
      pam_in_place = EXCLUDED.pam_in_place,
      security_training = EXCLUDED.security_training,
      vuln_scanning = EXCLUDED.vuln_scanning,
      readiness_score = EXCLUDED.readiness_score,
      readiness_tier = EXCLUDED.readiness_tier,
      updated_at = NOW()
  `, [
    userId, profileId,
    readinessAnswers.mfa_email, readinessAnswers.mfa_remote,
    readinessAnswers.mfa_privileged, readinessAnswers.mfa_cloud,
    readinessAnswers.edr_coverage_pct, readinessAnswers.immutable_backups,
    readinessAnswers.tested_restore_12mo, readinessAnswers.ir_plan_written,
    readinessAnswers.tabletop_12mo, readinessAnswers.pam_in_place,
    readinessAnswers.security_training, readinessAnswers.vuln_scanning,
    readinessScore.score, readinessScore.tier
  ]);

  // CIS RAM assessment envelope (upsert)
  await pool.query(`
    INSERT INTO cis_ram_assessments (profile_id, user_id, acceptable_risk_score, impact_criteria, status, completed_at)
    VALUES ($1, $2, 6, $3::jsonb, 'complete', NOW())
    ON CONFLICT (profile_id) DO UPDATE SET
      acceptable_risk_score = EXCLUDED.acceptable_risk_score,
      impact_criteria = EXCLUDED.impact_criteria,
      status = 'complete', completed_at = NOW(), updated_at = NOW()
  `, [
    profileId, userId,
    JSON.stringify({
      mission_definition: 'Service availability, business operations continuity, customer-facing service uptime.',
      obligations_definition: 'Contractual, regulatory (PCI / HIPAA / state breach laws), and ethical obligations to clients and employees.',
      dollar_thresholds: { low: 5000, medium: 50000, high: 250000 },
      notes: 'Answer-key baseline scoring derived from declared IT controls and posture archetype. Instructor reference — students should arrive at similar but not identical scoring.'
    })
  ]);

  // CIS RAM rows (idempotent upsert by safeguard_num)
  let ramInserted = 0;
  for (const r of cisRamRows) {
    await pool.query(`
      INSERT INTO cis_ram_safeguards (
        profile_id, user_id, safeguard_num, asset_class,
        mission_impact, obligations_impact, likelihood,
        treatment_safeguard, treatment_title, treatment_description,
        treatment_mission_impact, treatment_obligations_impact, treatment_likelihood,
        treatment_cost, implementation_year, notes, status
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
      )
      ON CONFLICT (profile_id, safeguard_num) DO UPDATE SET
        asset_class = EXCLUDED.asset_class,
        mission_impact = EXCLUDED.mission_impact,
        obligations_impact = EXCLUDED.obligations_impact,
        likelihood = EXCLUDED.likelihood,
        treatment_safeguard = EXCLUDED.treatment_safeguard,
        treatment_title = EXCLUDED.treatment_title,
        treatment_description = EXCLUDED.treatment_description,
        treatment_mission_impact = EXCLUDED.treatment_mission_impact,
        treatment_obligations_impact = EXCLUDED.treatment_obligations_impact,
        treatment_likelihood = EXCLUDED.treatment_likelihood,
        treatment_cost = EXCLUDED.treatment_cost,
        implementation_year = EXCLUDED.implementation_year,
        notes = EXCLUDED.notes, status = EXCLUDED.status,
        updated_at = NOW()
    `, [
      profileId, userId, r.safeguard_num, r.asset_class,
      r.mission_impact, r.obligations_impact, r.likelihood,
      r.treatment_safeguard, r.treatment_title, r.treatment_description,
      r.treatment_mission_impact, r.treatment_obligations_impact, r.treatment_likelihood,
      r.treatment_cost, r.implementation_year, r.notes, r.status
    ]);
    ramInserted++;
  }

  // Deloitte-structured exec summary (4 sections)
  const deloitte = buildDeloitteExecSummary(ctx, findings, coverage, csfScores, readinessScore);

  // Report deliverable (latest version — upsert)
  const reportQ = await pool.query(`SELECT id FROM report_deliverables WHERE profile_id = $1 ORDER BY version DESC LIMIT 1`, [profileId]);
  let reportId;
  if (reportQ.rowCount > 0) {
    reportId = reportQ.rows[0].id;
    await pool.query(`
      UPDATE report_deliverables
         SET exec_summary = $1,
             exec_current_posture = $2,
             exec_top_risks = $3,
             exec_progress = $4,
             exec_decisions_needed = $5,
             csf_scores = $6::jsonb,
             status = 'draft',
             branding = COALESCE(branding, '{}'::jsonb) || $7::jsonb,
             updated_at = NOW()
       WHERE id = $8
    `, [
      execSummary,
      deloitte.current_posture, deloitte.top_risks,
      deloitte.progress, deloitte.decisions_needed,
      JSON.stringify(csfScores),
      JSON.stringify({ prepared_by: 'Instructor answer-key (auto-generated)' }),
      reportId
    ]);
  } else {
    const ins = await pool.query(`
      INSERT INTO report_deliverables
        (profile_id, version, status, exec_summary,
         exec_current_posture, exec_top_risks, exec_progress, exec_decisions_needed,
         branding, csf_scores, created_by)
      VALUES ($1, 1, 'draft', $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9)
      RETURNING id
    `, [
      profileId, execSummary,
      deloitte.current_posture, deloitte.top_risks,
      deloitte.progress, deloitte.decisions_needed,
      JSON.stringify({ prepared_by: 'Instructor answer-key (auto-generated)' }),
      JSON.stringify(csfScores), userId
    ]);
    reportId = ins.rows[0].id;
  }

  return {
    findings_inserted: findingsInserted,
    assets_inserted: insertedAssets.length,
    cis_ram_rows_inserted: ramInserted,
    insurance_readiness_score: readinessScore.score,
    insurance_readiness_tier: readinessScore.tier,
    report_id: reportId,
    exec_summary: execSummary,
    deloitte_exec: deloitte,
    coverage,
    csf_scores: csfScores,
    posture: ctx.posture
  };
}

module.exports = {
  generateInstructorAnswerKeyRiskAssessment,
  // Exported for tests
  buildFindings,
  buildCisRamRows,
  buildExecSummary,
  buildDeloitteExecSummary,
  unpackContext
};
