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

// ─── C: network — workstation autofill + firewall sanity ─────────────────

const DEPT_ABBREVS = ['admin', 'ops', 'sales', 'fin', 'hr', 'it', 'eng', 'mkt', 'cs', 'qa'];

function validateNetwork(payload, ctx) {
  const warnings = [];
  if (!payload?.network) {
    warnings.push('C: network missing');
    return { payload, warnings };
  }
  const net = payload.network;

  // 1. Workstation autofill — the biggest delta-from-LLM. The prompt asks
  //    for 5-10 examples; we fill the rest programmatically up to endpoint_count.
  const targetTotal = ctx.endpointCount || 50;
  if (Array.isArray(net.assets)) {
    const workstations = net.assets.filter(a => String(a.role || '').toLowerCase() === 'workstation');
    const others = net.assets.filter(a => String(a.role || '').toLowerCase() !== 'workstation');

    if (workstations.length > 0 && workstations.length < targetTotal) {
      const wsSubnet = workstations[0].subnet;
      const baseIp = String(workstations[0].ip || '').split('.').slice(0, 3).join('.');
      const startOctet = Math.max(...workstations.map(w => {
        const last = parseInt(String(w.ip || '').split('.')[3], 10);
        return Number.isFinite(last) ? last : 10;
      })) + 1;

      // Pick a department-naming pattern from existing examples (e.g. "admin", "ops")
      const exampleHostnames = workstations.map(w => String(w.hostname || '').toLowerCase());
      const detectedDepts = DEPT_ABBREVS.filter(d => exampleHostnames.some(h => h.startsWith(d + '-')));
      const depts = detectedDepts.length > 0 ? detectedDepts : ['admin', 'ops'];

      const needed = targetTotal - workstations.length;
      const generated = [];
      for (let i = 0; i < needed; i++) {
        const dept = depts[i % depts.length];
        const num = String(Math.floor(i / depts.length) + workstations.filter(w =>
          String(w.hostname || '').toLowerCase().startsWith(dept + '-')).length + 1).padStart(2, '0');
        const ipLast = startOctet + i;
        if (ipLast > 250) break; // /24 subnet ceiling
        generated.push({
          hostname: `${dept}-ws-${num}`,
          ip: `${baseIp}.${ipLast}`,
          subnet: wsSubnet,
          role: 'workstation',
          os: workstations[0].os || 'Windows 10 Pro',
          function: `${dept.toUpperCase()} workstation`,
          critical: false
        });
      }
      net.assets = [...others, ...workstations, ...generated];
      warnings.push(`C: autofilled ${generated.length} workstations from ${workstations.length} examples → ${workstations.length + generated.length} total`);
    }
  }

  // 2. Firewall: normalize field names; cap rules at 25
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

module.exports = {
  validateOrg,
  validateIt,
  validateNetwork,
  validateThreat
};
