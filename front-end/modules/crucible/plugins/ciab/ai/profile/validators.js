/**
 * ai/profile/validators.js — Per-branch business validation + autofill.
 * ============================================================================
 * The generic JSON-repair (truncation, escaping, brackets) lives in
 * llm-client.js. These functions handle BUSINESS validation:
 *   - department_breakdown sums to employees_total (A)
 *   - server OS strings have versions, SaaS not duplicated (B)
 *   - workstation autofill from examples (C — the biggest delta-from-LLM)
 *   - MITRE technique IDs are well-formed (D)
 *
 * Validators are best-effort: they LOG warnings and patch obvious gaps,
 * but don't throw. The orchestrator decides what to do with the patched output.
 */

const { isDcRecord } = require('./dc-name');

// ─── A: organization ─────────────────────────────────────────────────────

function validateOrg(payload, ctx) {
  const warnings = [];
  if (!payload || !payload.organization) {
    warnings.push('org payload missing .organization');
    return { payload, warnings };
  }
  const o = payload.organization;
  const target = ctx.employeeCount;

  if (o.department_breakdown && target) {
    const dept = o.department_breakdown;
    const sum = Object.values(dept).reduce((a, v) => a + (Number(v) || 0), 0);
    if (sum !== target) {
      // Patch: scale "Other" to make it sum
      dept.Other = (dept.Other || 0) + (target - sum);
      warnings.push(`A: department_breakdown rebalanced (was ${sum}, target ${target})`);
    }
    o.employees_total = target;
  }
  return { payload, warnings };
}

// ─── B: IT environment ───────────────────────────────────────────────────

function validateIt(payload) {
  const warnings = [];
  if (!payload?.it_environment) {
    warnings.push('B: it_environment missing');
    return { payload, warnings };
  }
  const it = payload.it_environment;

  // Drop duplicate servers by hostname
  if (Array.isArray(it.servers)) {
    const seen = new Set();
    it.servers = it.servers.filter(s => {
      const k = String(s.hostname || '').toLowerCase();
      if (!k || seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  // Flag bare OS strings (warn only; don't fabricate)
  if (Array.isArray(it.servers)) {
    for (const s of it.servers) {
      if (s.os && !/\d/.test(s.os)) {
        warnings.push(`B: server "${s.hostname}" has unversioned os "${s.os}"`);
      }
    }
  }

  return { payload, warnings };
}

// ─── C: network — firewall sanity ────────────────────────────────────────
// Workstation reconciliation (matching the IT branch's endpoint counts,
// distributing across subnets) now happens once, later in the pipeline —
// see ai/profile/reconcile-workstations.js, called from index.js right
// before the profile JSON is written. It completely rebuilds the
// workstation list from the IT branch's totals, so autofilling one here
// first would just be discarded — no point doing that work twice.

function validateNetwork(payload) {
  const warnings = [];
  if (!payload?.network) {
    warnings.push('C: network missing');
    return { payload, warnings };
  }
  const net = payload.network;

  // Firewall: normalize field names; cap rules at 25
  if (net.firewall) {
    if (Array.isArray(net.firewall.rules)) {
      net.firewall.rules = net.firewall.rules.slice(0, 25).map(r => ({
        id: r.id,
        name: r.name,
        src: r.src ?? r.source ?? 'any',
        dst: r.dst ?? r.destination ?? 'any',
        port: r.port,
        proto: r.proto ?? r.protocol ?? 'ANY',
        action: r.action,
        logging: r.logging,
        comment: r.comment ?? r.description ?? ''
      }));
    }
  }

  // 3. Strip diagram_text if model emitted it anyway
  if (net.diagram_text) {
    delete net.diagram_text;
    warnings.push('C: removed diagram_text (forbidden field)');
  }

  return { payload, warnings };
}

// ─── D: threat profile ───────────────────────────────────────────────────

const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

function validateThreat(payload, ctx) {
  const warnings = [];
  if (!payload?.threat_profile) {
    warnings.push('D: threat_profile missing');
    return { payload, warnings };
  }
  const tp = payload.threat_profile;

  // Validate MITRE IDs
  if (Array.isArray(tp.scenarios)) {
    for (const sc of tp.scenarios) {
      if (Array.isArray(sc.attack_path)) {
        for (const step of sc.attack_path) {
          if (step.technique && !TECHNIQUE_RE.test(step.technique)) {
            warnings.push(`D: scenario ${sc.scenario_id || '?'} step ${step.step} has invalid technique "${step.technique}"`);
          }
        }
      }
    }
  }

  // Cross-check targets exist in network if we have it
  if (ctx.networkAssets) {
    const validHosts = new Set(ctx.networkAssets.map(a => String(a.hostname || '').toLowerCase()));
    if (Array.isArray(tp.scenarios)) {
      for (const sc of tp.scenarios) {
        const stepTargets = (sc.attack_path || []).map(s => String(s.target || '').toLowerCase());
        const invalid = stepTargets.filter(t => t && !validHosts.has(t));
        if (invalid.length > 0) {
          warnings.push(`D: scenario ${sc.scenario_id || '?'} references unknown hosts: ${invalid.slice(0, 3).join(', ')}`);
        }
      }
    }
  }

  return { payload, warnings };
}

// ─── E: plausibility (sizing) ────────────────────────────────────────────
/**
 * validateSizing — the check that did not exist.
 *
 * Everything above this point is STRUCTURAL: department sums, duplicate
 * hostnames, field renames, a MITRE regex. Nothing asked whether the
 * infrastructure the model returned is plausible for the organization it
 * belongs to, which is how "a 12-person non-profit with two domain
 * controllers and a Palo Alto PA-820" shipped without a single warning.
 *
 * Actions:
 *   clamp  — the payload is edited in place to the plausible value
 *   flag   — recorded in `review` so the profile is marked needs_review
 *
 * Deliberately never throws: a profile that took four LLM calls to build is
 * not discarded over a sizing disagreement. It is corrected, or it is
 * surfaced. Silence is the one option removed.
 *
 * @param {object} payload combined { organization, it_environment, network }
 * @param {object} ctx     { sizing, roster, employeeCount }
 */
function validateSizing(payload, ctx = {}) {
  const warnings = [];
  const review = [];
  const sizing = ctx.sizing;
  if (!sizing || !payload) return { payload, warnings, review };

  const it  = payload.it_environment || {};
  const net = payload.network || {};
  const emp = ctx.employeeCount || sizing.employees;
  const flag = (id, msg) => { warnings.push(`E/${id}: ${msg}`); review.push({ id, message: msg }); };

  // ── S: identity and servers ───────────────────────────────────────────
  const servers = Array.isArray(it.servers) ? it.servers : [];
  // The domain-controller predicate is IMPORTED, never re-spelled here: the
  // compiler adopts this same register's controllers into the forest by name
  // (utils/goad-lab-compile.js/paperForestNames), so a machine S-01 demotes
  // that the compiler still reads as a DC — or the reverse — is a profile whose
  // paper and lane disagree about which host runs the directory, and that is
  // only discovered ninety minutes into a bake. See ai/profile/dc-name.js.
  const isDc = isDcRecord;
  const isFs = (s) => /file server|\bfs\b/i.test(`${s.role || ''} ${s.hostname || ''}`);

  const dcs = servers.filter(isDc);
  if (!sizing.identity.has_domain && dcs.length > 0) {
    // S-01 — the stakeholder's first named case.
    it.servers = servers.filter(s => !isDc(s));
    flag('S-01', `${dcs.length} domain controller(s) on a ${emp}-employee ${sizing.sector} ` +
      `with delivery=${sizing.delivery_class} (AD floor is ${sizing.identity.domain_floor}) — removed`);
  } else if (dcs.length > sizing.identity.max_dcs) {
    // S-02 — the stakeholder's second named case.
    const keep = new Set(dcs.slice(0, sizing.identity.max_dcs));
    it.servers = servers.filter(s => !isDc(s) || keep.has(s));
    flag('S-02', `${dcs.length} domain controllers at ${emp} employees ` +
      `(second DC threshold is ${sizing.identity.second_dc_at}) — trimmed to ${sizing.identity.max_dcs}`);
  }

  const fileServers = (it.servers || []).filter(isFs);
  if (fileServers.length > sizing.servers.max_file_servers) {
    // S-03 — "a small business wouldn't have multiple file servers".
    const keep = new Set(fileServers.slice(0, sizing.servers.max_file_servers));
    it.servers = (it.servers || []).filter(s => !isFs(s) || keep.has(s));
    flag('S-03', `${fileServers.length} file servers — trimmed to ${sizing.servers.max_file_servers}`);
  }

  const totalServers = (it.servers || []).length;
  if (totalServers > sizing.servers.max_total) {
    flag('S-04', `${totalServers} servers for ${emp} employees exceeds the ` +
      `plausible ceiling of ${sizing.servers.max_total} for this size and delivery posture`);
  }

  // ── E: endpoint arithmetic ────────────────────────────────────────────
  const ep = it.endpoints || {};
  const epTotal = ['windows_laptops', 'windows_desktops', 'shared_kiosks', 'macos', 'mobile']
    .reduce((sum, k) => sum + (Number(ep[k]) || 0), 0);
  if (epTotal > 0 && emp > 0) {
    const ratio = epTotal / emp;
    // Library public-access fleets legitimately run high; everyone else does not.
    const ceiling = sizing.sector === 'Library' ? 3.5 : 2.0;
    if (ratio > ceiling) {
      flag('E-01', `${epTotal} endpoints for ${emp} employees (${ratio.toFixed(1)}x) ` +
        `exceeds ${ceiling}x for a ${sizing.sector}`);
    } else if (ratio < 0.4) {
      flag('E-02', `${epTotal} endpoints for ${emp} employees (${ratio.toFixed(1)}x) is implausibly low`);
    }
  }

  // ── P: security stack vs size and staffing ────────────────────────────
  const stackText = JSON.stringify(it.endpoint_protection || {}) + ' ' + JSON.stringify(it.saas || []);
  if (!sizing.security.siem && /\bSIEM\b|Splunk|QRadar|Sentinel|LogRhythm|Exabeam/i.test(stackText)) {
    flag('P-01', `a SIEM appears at ${emp} employees with ${sizing.staffing.it_fte} IT FTE ` +
      `(in-house SIEM threshold is ${sizing.security.siem_threshold}, and there is no security headcount)`);
  }
  if (sizing.security.edr_tier === 'av-only' &&
      /CrowdStrike|SentinelOne|Carbon Black|Cybereason|Cortex XDR/i.test(stackText)) {
    flag('P-02', `enterprise EDR on a ${emp}-employee ${sizing.sector} (tier is ${sizing.security.edr_tier})`);
  }

  const fw = net.firewall || {};
  if (sizing.security.firewall_tier === 'micro' &&
      /Palo Alto|PA-\d{3,}|Firepower|FortiGate 6\d{2}|Check Point 5\d{3}/i.test(`${fw.vendor || ''} ${fw.model || ''}`)) {
    flag('P-03', `${fw.vendor} ${fw.model} on a ${emp}-employee ${sizing.sector} ` +
      `(firewall tier is ${sizing.security.firewall_tier})`);
  }

  // ── C: internal contradiction ─────────────────────────────────────────
  // The highest-value check here: a profile with no DC that still talks about
  // domain membership and Group Policy. Students read both pages.
  if (!sizing.identity.has_domain) {
    const adText = JSON.stringify(it) + ' ' + JSON.stringify(net.assets || []);
    if (/group policy|\bGPO\b|domain-joined|domain joined/i.test(adText)) {
      flag('C-01', 'profile has no domain controller but still references domain membership or Group Policy');
    }
  }

  // ── N: addressing sanity the prompt declares but nothing enforced ─────
  const assets = Array.isArray(net.assets) ? net.assets : [];
  const seenIps = new Map();
  for (const a of assets) {
    if (!a || !a.ip) continue;
    if (seenIps.has(a.ip)) {
      flag('N-01', `duplicate IP ${a.ip} on ${seenIps.get(a.ip)} and ${a.hostname}`);
      break;
    }
    seenIps.set(a.ip, a.hostname);
  }

  return { payload, warnings, review };
}

module.exports = {
  validateOrg,
  validateIt,
  validateNetwork,
  validateThreat,
  validateSizing
};
