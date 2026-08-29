/**
 * ai/profile/org-sizing.js — the canonical organization sizing profile.
 * ============================================================================
 * ONE deterministic, pure derivation of "what does an org of this size, in
 * this sector, with this delivery posture actually run?" — computed once and
 * consumed by every branch, instead of five prompts each asserting their own
 * version of it.
 *
 * Why this exists (audit findings it closes):
 *   - buildServerRoster() was already size-aware but was fed constants, so
 *     100% of SMB profiles got a DC and 46% got two.
 *   - endpoint counts were derived from the MIDPOINT of the employee band
 *     while headcount was drawn at random from inside it, so a 28-person
 *     company was told to have 128 endpoints.
 *   - buildFlavorBundle() picked firewall/EDR/backup with no size input at
 *     all, so a 12-person food bank could draw a Palo Alto PA-820.
 *   - the Utility and K12 roster branches never consulted delivery, so a
 *     cloud-first district still got a full on-prem AD stack.
 *
 * Everything here is PURE and deterministic given (inputs + runId). No I/O,
 * no Math.random(), no Date. Same seed ⇒ same sizing, always.
 *
 * Thresholds are field-observed central tendencies for small/SLED orgs, not
 * best practice. The numbers that matter most:
 *   first AD ≈ 20-30 employees   ·  second DC ≈ 60-80 users
 *   L3 core ≈ 100-150 users      ·  in-house SIEM ≈ 400-600 employees
 *   first dedicated IT ≈ 40-75   ·  first security hire ≈ 500-1000
 *   a /24 saturates ≈ 90-100 employees (this is WHY a second subnet appears)
 */

const { hashInt, hashCoin, hashFloat } = require('./hash');

// ─── Input normalization ──────────────────────────────────────────────────

/**
 * Collapse every delivery label the UI, the admin console and the seed
 * defaults can produce into exactly one of three classes.
 *
 * The old code did `deliv.startsWith('cloud')`, which silently failed on
 * 'Mostly Cloud' and on 'On-Premises' vs 'On-Prem' inconsistencies — two of
 * the five labels the UI offers never matched, so those orgs were treated as
 * Hybrid and got an on-prem domain they should never have had.
 */
function normalizeDelivery(delivery) {
  const d = String(delivery || '').toLowerCase().trim();
  if (!d) return 'hybrid';
  if (/cloud|saas|entra[- ]?only|google[- ]?only/.test(d)) return 'cloud';
  if (/on[-\s_]?prem|onprem|traditional|legacy/.test(d)) return 'onprem';
  return 'hybrid';
}

function normalizeMaturity(maturity) {
  const m = String(maturity || '').toLowerCase().trim();
  if (/^(low|beginner|basic|poor|minimal)/.test(m)) return 'low';
  if (/^(high|advanced|mature|strong)/.test(m)) return 'high';
  return 'intermediate';
}

/** Size bands. Everything downstream keys off these. */
function bandOf(employees) {
  const e = Math.max(1, Number(employees) || 1);
  if (e <= 15)  return 'A';
  if (e <= 40)  return 'B';
  if (e <= 100) return 'C';
  if (e <= 250) return 'D';
  if (e <= 600) return 'E';
  return 'F';
}

// ─── Sector employee bands ────────────────────────────────────────────────
// Where a sector's headcount actually sits when nobody specifies one. These
// used to live ONLY in the browser (generator.html CLIENT_TYPES and
// admin-profile-lanes.js CLIENT_TYPE_DEFAULTS — two copies), and neither ever
// reached the server, so every profile fell back to a hardcoded 50.
const SECTOR_EMPLOYEE_BANDS = {
  SMB:           { min: 12, max: 200 },
  NonProfit:     { min: 6,  max: 90  },
  Utility_IT_OT: { min: 18, max: 320 },
  // Staff headcount, not enrollment. A district with 2,000 STAFF serves
  // ~25,000 students and is not a single-campus topology — the generator
  // models one site, so the top of this band is deliberately conservative.
  K12:           { min: 40, max: 500 },
  Library:       { min: 8,  max: 120 }
};

/** First-AD threshold by sector. Never below 10 in any sector. */
const DOMAIN_FLOOR = {
  SMB:           { cloud: Infinity, hybrid: 24, onprem: 16 },
  // NPOs run on donated/discounted M365 + Google. On-prem AD is genuinely
  // uncommon here — the floor must survive an On-Prem delivery pick, which
  // it previously did not (it dropped to 12).
  NonProfit:     { cloud: Infinity, hybrid: 45, onprem: 32 },
  // Utilities and districts do run AD early and for real, but they had NO
  // floor at all — an 8-person water utility got DC + FS + CIS + SQL + backup.
  Utility_IT_OT: { cloud: 60,       hybrid: 22, onprem: 18 },
  K12:           { cloud: 70,       hybrid: 25, onprem: 20 },
  Library:       { cloud: Infinity, hybrid: 30, onprem: 22 }
};

/** Sector endpoint ratio: workstation-class devices per employee. */
const ENDPOINT_RATIO = {
  SMB:           [1.00, 1.30],
  NonProfit:     [0.85, 1.15],
  // Field/shift-heavy: crews share ruggedized kit, they don't each have a desk.
  Utility_IT_OT: [0.60, 0.95],
  // STAFF machines only. The 1:1 student fleet is counted separately.
  K12:           [0.90, 1.20],
  // Public-access patron PCs outnumber staff machines.
  Library:       [1.60, 2.60]
};

// ─── The sizing profile ───────────────────────────────────────────────────

/**
 * @param {object} args
 * @param {string} args.clientType      SMB | NonProfit | Utility_IT_OT | K12 | Library
 * @param {string} [args.industry]
 * @param {number} args.employeeCount
 * @param {string} [args.delivery]      any label; normalized internally
 * @param {string} [args.maturity]
 * @param {string} args.runId           determinism anchor
 * @returns {object} sizing
 */
function computeOrgSizing({ clientType, industry, employeeCount, delivery, maturity, runId }) {
  const sector = SECTOR_EMPLOYEE_BANDS[clientType] ? clientType : 'SMB';
  const emp = Math.max(1, Math.round(Number(employeeCount) || 1));
  const band = bandOf(emp);
  const deliveryClass = normalizeDelivery(delivery);
  const maturityClass = normalizeMaturity(maturity);
  const rid = String(runId || 'RUN_DEFAULT');

  const cloudFirst = deliveryClass === 'cloud';
  const onPremHeavy = deliveryClass === 'onprem';

  // ── Identity ────────────────────────────────────────────────────────────
  const domainFloor = (DOMAIN_FLOOR[sector] || DOMAIN_FLOOR.SMB)[deliveryClass];
  const hasDomain = emp >= domainFloor;

  // Second DC. Baseline is 60-80 users — that is genuinely where redundancy
  // appears, and a single DC at 150 users is a finding rather than a
  // generation error.
  //
  // But the baseline is adjusted by how resourced the sector actually is.
  // Non-profits and libraries run lean and are the sectors this course is
  // built around; a 70-person food bank with two domain controllers is the
  // same class of error as a 20-person one with a PA-820. Districts and
  // utilities are genuinely multi-site and AD-heavy, so they get there sooner.
  const secondDcBase = hashInt(rid, 'seconddc', 60, 80);
  const secondDcAt =
      sector === 'NonProfit'     ? secondDcBase + 60   // effectively above their band
    : sector === 'Library'       ? secondDcBase + 30
    : sector === 'K12'           ? secondDcBase + 20
    : sector === 'Utility_IT_OT' ? secondDcBase + 20
    : secondDcBase;
  const maxDcs = !hasDomain ? 0 : (emp >= secondDcAt ? 2 : 1);

  let directory;
  if (!hasDomain) directory = cloudFirst ? (sector === 'K12' ? 'google' : 'entra') : (emp < 12 ? 'workgroup' : 'entra');
  else if (onPremHeavy) directory = 'ad';
  else directory = 'hybrid-ad';

  // ── Servers ─────────────────────────────────────────────────────────────
  // ~1 server per 10-20 employees for traditional shops, fewer cloud-native.
  const serverDivisor = cloudFirst ? 45 : onPremHeavy ? 12 : 20;
  const scaledServers = hasDomain
    ? Math.max(1, Math.min(12, Math.ceil(emp / serverDivisor) + 1))
    : (cloudFirst ? 0 : Math.min(2, Math.floor(emp / 40)));

  // Some sectors run a line-of-business system that exists regardless of how
  // cloud-forward the org is, because it IS the business. A utility's
  // CIS/billing (meter-to-cash) and a library's ILS do not disappear because
  // the org moved email to Google. Without this floor a cloud-first utility
  // came back with zero servers, which is as wrong as the DC stack it used
  // to get unconditionally.
  const sectorServerFloor =
      sector === 'Utility_IT_OT' ? (emp >= 25 ? 3 : emp >= 12 ? 1 : 0)
    : sector === 'Library'       ? (emp >= 12 ? 1 : 0)
    : sector === 'K12'           ? (hasDomain ? 3 : 0)
    : 0;

  const maxServers = Math.max(scaledServers, sectorServerFloor);

  const hypervisorHosts = maxServers === 0 ? 0
    : emp < 25 ? 1
    : emp < 75 ? hashInt(rid, 'hv', 1, 2)
    : emp < 150 ? hashInt(rid, 'hv', 2, 3)
    : emp < 300 ? hashInt(rid, 'hv', 3, 5)
    : hashInt(rid, 'hv', 4, 8);

  // ── Endpoints ───────────────────────────────────────────────────────────
  const [rLo, rHi] = ENDPOINT_RATIO[sector] || ENDPOINT_RATIO.SMB;
  const ratio = rLo + hashFloat(rid, 'epratio') * (rHi - rLo);
  const workstations = Math.max(2, Math.round(emp * ratio));

  // K12 1:1 fleet is ChromeOS, managed in Google Admin, NOT domain-joined and
  // NOT part of the Windows endpoint buckets. Tracked separately so the
  // prompts can state it without inflating windows_desktops.
  const studentDevices = sector === 'K12' ? Math.round(emp * hashInt(rid, 'k12ratio', 8, 13)) : 0;

  const laptopPct = onPremHeavy ? hashInt(rid, 'lap', 30, 50)
    : sector === 'Library' ? hashInt(rid, 'lap', 10, 25)
    : sector === 'Utility_IT_OT' ? hashInt(rid, 'lap', 25, 45)
    : hashInt(rid, 'lap', 55, 78);

  const printers = Math.max(1, Math.round(emp / hashInt(rid, 'mfp', 12, 25)));

  // ── Network ─────────────────────────────────────────────────────────────
  // A /24 gives ~254 usable. Real device load is ~2.5x employees once phones,
  // printers, APs and cameras are counted — so a /24 saturates near 90-100
  // employees. THAT is why a second subnet appears, not "best practice".
  const activeIps = Math.round(emp * 2.5);
  const subnetMask = activeIps > 900 ? 22 : activeIps > 450 ? 23 : 24;

  // 1-2 VLANs at 15 people, 4-6 at 100, 8-12 at 400.
  let vlanBase = Math.min(12, 1 + Math.floor(emp / 40));
  if (maturityClass === 'low') vlanBase = Math.max(1, vlanBase - 1);
  if (maturityClass === 'high') vlanBase = Math.min(14, vlanBase + 1);
  // Sectors with a mandatory segmentation story get a floor: utilities need
  // the Purdue split, districts need student/staff, libraries need public.
  const vlanFloor = sector === 'Utility_IT_OT' ? 4 : (sector === 'K12' || sector === 'Library') ? 3 : 1;
  const vlanCount = Math.max(vlanFloor, vlanBase);

  const switchCount = Math.max(1, Math.ceil((emp * 2.2) / 44));
  const apCount = sector === 'K12'
    ? Math.max(2, Math.round(emp / 3))               // ~1 per classroom
    : Math.max(1, Math.round(emp / hashInt(rid, 'apr', 8, 15)));

  // A core switch is a real budget line, not scenery. Below ~100 users the
  // firewall does inter-VLAN routing and there is exactly one flat switch
  // stack. The generator previously mandated a 'switch-core' on every
  // profile, including 10-person cloud-first non-profits.
  const l3Core = emp >= hashInt(rid, 'l3', 100, 150);

  // A DMZ is only real when something is actually self-hosted inbound. Most
  // orgs under 150 seats expose nothing but a VPN.
  const dmz = hasDomain && emp >= 120 && !cloudFirst && hashCoin(rid, 'dmz', 45);

  const sites = emp < 60 ? 1
    : emp < 150 ? (hashCoin(rid, 'secondsite', 30) ? 2 : 1)
    : Math.max(1, Math.min(6, Math.round(emp / hashInt(rid, 'sitesz', 90, 160))));

  // ── Security stack ──────────────────────────────────────────────────────
  const firewallTier = emp <= 15 ? 'micro'
    : emp <= 40 ? (maturityClass === 'high' ? 'smb' : hashCoin(rid, 'fwtier', 35) ? 'micro' : 'smb')
    : emp <= 100 ? 'smb'
    : emp <= 250 ? 'mid'
    : 'enterprise';

  const edrTier = emp <= 15 ? (maturityClass === 'high' ? 'smb' : 'av-only')
    : emp <= 40 ? (maturityClass === 'low' ? 'av-only' : 'smb')
    : emp <= 150 ? (maturityClass === 'high' ? 'mdr' : 'smb')
    : emp <= 400 ? 'mdr'
    : 'enterprise';

  const backupTier = emp <= 15 ? 'micro' : emp <= 60 ? 'smb' : emp <= 250 ? 'mid' : 'enterprise';

  // An in-house SIEM below ~400 staff with no security headcount is the
  // classic tell. Co-managed MDR is what actually shows up earlier.
  const siemThreshold = hashInt(rid, 'siem', 400, 600);
  const siem = emp >= siemThreshold && maturityClass !== 'low';
  const mdr = !siem && emp >= 40 && (maturityClass === 'high' || hashCoin(rid, 'mdr', 35));

  // ── Staffing ────────────────────────────────────────────────────────────
  const itDivisor = cloudFirst ? 120 : (sector === 'Utility_IT_OT' || sector === 'K12') ? 50 : 75;
  const itFteRaw = emp / itDivisor;
  const firstItHire = hashInt(rid, 'itjob', 40, 75);
  const hasDedicatedIt = emp >= firstItHire;
  const hasSysadmin = emp >= hashInt(rid, 'sysadmin', 100, 150);
  const hasSecurity = emp >= hashInt(rid, 'sec', 500, 1000);
  const itFte = hasDedicatedIt ? Math.max(1, Math.round(itFteRaw)) : 0;
  const supportModel = !hasDedicatedIt ? 'msp' : hasSysadmin ? 'inhouse' : 'hybrid';

  // ── Firewall rule count ─────────────────────────────────────────────────
  // Was pinned at exactly 25 for every profile because the admin-supplied
  // range never reached the generator.
  const fwRuleTarget = Math.max(6, Math.min(40,
    hashInt(rid, 'fwrules', 6 + Math.floor(emp / 25), 12 + Math.floor(emp / 12))));

  // ── Stakeholders ────────────────────────────────────────────────────────
  // Was pinned at 5 for a 10-person non-profit and a 2,000-staff district
  // alike. A 15-person org does not have a CISO, a CTO and a VP Infrastructure.
  const stakeholderCount = emp <= 20 ? hashInt(rid, 'stak', 3, 4)
    : emp <= 60 ? hashInt(rid, 'stak', 4, 6)
    : emp <= 200 ? hashInt(rid, 'stak', 5, 7)
    : hashInt(rid, 'stak', 6, 9);

  return {
    sector, band, employees: emp, industry: industry || null,
    delivery_class: deliveryClass, maturity_class: maturityClass, run_id: rid,

    identity: {
      has_domain: hasDomain, max_dcs: maxDcs, second_dc_at: secondDcAt,
      domain_floor: domainFloor, directory
    },
    servers: {
      max_total: maxServers,
      max_file_servers: 1,           // never more than one, at any size, in any sector
      allow_app_sql: hasDomain && emp >= 70 && !cloudFirst,
      allow_rds: hasDomain && emp >= 100 && !cloudFirst,
      hypervisor_hosts: hypervisorHosts,
      nas_likely: !hasDomain || emp < 30
    },
    endpoints: {
      workstations, ratio: Math.round(ratio * 100) / 100,
      laptop_pct: laptopPct, printers, student_devices: studentDevices,
      total: workstations
    },
    network: {
      vlan_count: vlanCount, subnet_mask: subnetMask, active_ips: activeIps,
      switch_count: switchCount, ap_count: apCount,
      l3_core: l3Core, dmz, sites
    },
    security: {
      firewall_tier: firewallTier, edr_tier: edrTier, backup_tier: backupTier,
      siem, mdr, siem_threshold: siemThreshold
    },
    staffing: {
      it_fte: itFte, has_dedicated_it: hasDedicatedIt,
      has_sysadmin: hasSysadmin, has_security: hasSecurity, model: supportModel
    },
    firewall_rule_target: fwRuleTarget,
    stakeholder_count: stakeholderCount
  };
}

module.exports = {
  computeOrgSizing,
  normalizeDelivery,
  normalizeMaturity,
  bandOf,
  SECTOR_EMPLOYEE_BANDS,
  DOMAIN_FLOOR,
  ENDPOINT_RATIO
};
