/**
 * CIAB Plugin — Real-Client Intake Normalizer
 *
 * Pure-function module. Takes a raw intake payload (as stored in
 * real_client_intakes.payload) and emits a normalized structure that the
 * synthesize endpoint feeds to the template + script resolvers.
 *
 * No DB, no IO, no framework deps. Unit-testable with fixtures.
 */

const SAAS_EMAIL_PROVIDERS = new Set([
  'google workspace', 'google', 'gmail', 'g suite',
  'microsoft 365', 'microsoft365', 'office 365', 'office365', 'o365',
  'zoho', 'fastmail', 'proton', 'protonmail'
]);

// Roles → the services they typically imply on a self-hosted server.
const ROLE_SERVICE_HINTS = {
  dc:     ['SMB', 'LDAP', 'DNS'],
  file:   ['SMB'],
  mail:   ['SMTP'],
  web:    ['HTTP'],
  db:     ['SQL'],
  backup: ['SMB'],
  print:  ['SMB']
};

// Intake service tokens → canonical service name used by the script resolver.
const SERVICE_CANONICAL = {
  SMB: 'SMB', RDP: 'RDP', SSH: 'SSH',
  HTTP: 'HTTP', HTTPS: 'HTTP',
  SQL: 'SQL', MSSQL: 'SQL',
  FTP: 'FTP', DNS: 'DNS', LDAP: 'LDAP',
  VPN: 'VPN', SMTP: 'SMTP'
};

function num(v) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : 0;
}

function lc(v) {
  return String(v || '').trim().toLowerCase();
}

/**
 * Decide how to treat a yes/no/unknown role flag given the rest of the intake.
 * Returns one of: 'deploy' | 'saas' | 'skip' | 'edge'
 *   deploy — create a server VM for this role
 *   saas   — role provided by an external SaaS; no VM, emit warning
 *   skip   — role not present (either explicitly no, or unknown with no capacity)
 *   edge   — typically an appliance outside challenge scope (VPN concentrator)
 */
function resolveRoleOrSaaS(role, intake) {
  const net = intake?.sections?.network || {};
  const emailWeb = intake?.sections?.email_web || {};
  const value = lc(net[`role_${role}`]);
  const serverCount = num(net.server_count);

  if (value === 'yes') {
    if (serverCount > 0) return { status: 'deploy', reason: 'declared yes with servers' };
    // yes + no servers → probably SaaS. For mail, check provider; others default to saas.
    if (role === 'mail') {
      const provider = lc(emailWeb.email_provider);
      if (SAAS_EMAIL_PROVIDERS.has(provider)) {
        return { status: 'saas', reason: `email provider "${emailWeb.email_provider}" is SaaS` };
      }
      return { status: 'saas', reason: 'mail declared but no servers — assumed SaaS' };
    }
    if (role === 'web') return { status: 'saas', reason: 'web declared but no servers — assumed SaaS (e.g., Squarespace, Wix)' };
    return { status: 'saas', reason: `${role} declared but no servers — assumed external service` };
  }

  if (value === 'unknown') {
    if (serverCount === 0) {
      return { status: 'skip', reason: `${role} status unknown; no servers declared — treating as absent` };
    }
    // Unknown but servers exist — admin should decide. Skip with clear warning.
    return { status: 'skip', reason: `${role} status unknown — not deploying, admin should confirm` };
  }

  // 'no', '', or anything else → skip silently (no 'no' is the expected case)
  return { status: 'skip', reason: null };
}

/**
 * Distribute `gap` unaccounted devices across the family counts, using only
 * families that have templates (`fillable`). Preserves existing ratio among
 * fillable families; if none of the declared families are fillable, routes
 * the entire gap to the default fillable family.
 */
function reconcileOsCounts(declared, deviceTotal, fillableFamilies, defaultFillable) {
  const families = ['windows_server', 'windows_client', 'linux', 'macos', 'other'];
  const out = {};
  for (const f of families) out[f] = declared[f] || 0;
  const declaredSum = families.reduce((s, f) => s + out[f], 0);
  const gap = deviceTotal - declaredSum;
  if (gap <= 0) return { counts: out, gap: 0 };

  const fillableDeclared = fillableFamilies.filter(f => out[f] > 0);
  const baseTotal = fillableDeclared.reduce((s, f) => s + out[f], 0);

  if (baseTotal > 0) {
    // Weighted fill — allocate gap proportionally, floor then top up the largest.
    let assigned = 0;
    const shares = fillableDeclared.map(f => ({ f, n: Math.floor(gap * (out[f] / baseTotal)) }));
    shares.forEach(s => { out[s.f] += s.n; assigned += s.n; });
    const remainder = gap - assigned;
    if (remainder > 0) {
      // Push the leftover to the single largest fillable declared family.
      const biggest = shares.slice().sort((a, b) => b.n - a.n)[0]?.f || defaultFillable;
      out[biggest] += remainder;
    }
  } else {
    out[defaultFillable] = (out[defaultFillable] || 0) + gap;
  }

  return { counts: out, gap };
}

/**
 * Build the flat VM list from normalized counts + roles + services.
 * Returns { vms: [...], phantoms: [...] }
 *   vms[]:      { name, role, os_family, os_version, services[], suggested_script_services[] }
 *   phantoms[]: { name, role, os_family, os_version, reason }
 */
function deriveVmList(normalized) {
  const vms = [];
  const phantoms = [];

  // Family → hint for VM OS display + resolver input.
  const familyOsName = {
    windows_client: { os_family: 'windows_client', os_version: null,   role: 'workstation' },
    windows_server: { os_family: 'windows_server', os_version: null,   role: 'server' },
    linux:          { os_family: 'linux',          os_version: null,   role: 'server' },
    macos:          { os_family: 'macos',          os_version: null,   role: 'workstation' },
    other:          { os_family: 'other',          os_version: null,   role: 'workstation' }
  };

  const workstationServices = normalized.services.filter(s => ['SMB', 'RDP'].includes(s.canonical));
  let wsIdx = 1;

  // Workstations + laptops: map proportional OS counts to VMs.
  const endpointFamilies = ['windows_client', 'macos', 'linux', 'other'];
  for (const fam of endpointFamilies) {
    const n = normalized.endpointCounts[fam] || 0;
    for (let i = 0; i < n; i++) {
      const base = familyOsName[fam];
      const name = `ws${String(wsIdx++).padStart(2, '0')}`;
      if (fam === 'macos' || fam === 'other' || fam === 'linux') {
        phantoms.push({
          name,
          role: base.role,
          os_family: fam,
          os_version: base.os_version,
          reason: fam === 'macos' ? 'no macOS template available — rendered as phantom asset'
                : fam === 'linux' ? 'endpoint-class Linux treated as phantom (no standard desktop Linux template)'
                : 'unknown OS family — rendered as phantom asset'
        });
      } else {
        vms.push({
          name,
          role: base.role,
          os_family: fam,
          os_version: base.os_version,
          services: workstationServices.map(s => s.canonical),
          suggested_script_services: workstationServices.map(s => ({ service: s.canonical, version: s.version || null }))
        });
      }
    }
  }

  // Server VMs from resolved roles. Start numbering at 01 per role.
  const serverFamily = normalized.serverCounts.windows_server > 0 ? 'windows_server'
                     : normalized.serverCounts.linux > 0 ? 'linux'
                     : 'windows_server'; // fallback

  const rolesInOrder = ['dc', 'file', 'web', 'db', 'mail', 'backup', 'print'];
  for (const role of rolesInOrder) {
    const decision = normalized.resolvedRoles[role];
    if (!decision || decision.status !== 'deploy') continue;
    const base = familyOsName[serverFamily];
    const roleSvcHints = (ROLE_SERVICE_HINTS[role] || []).map(s => ({ service: s, version: null }));
    // Include any explicitly declared services that match role hints.
    const declaredForRole = normalized.services.filter(s => (ROLE_SERVICE_HINTS[role] || []).includes(s.canonical));
    const scriptSvcs = declaredForRole.length > 0
      ? declaredForRole.map(s => ({ service: s.canonical, version: s.version || null }))
      : roleSvcHints;
    vms.push({
      name: `${role}01`,
      role,
      os_family: serverFamily,
      os_version: base.os_version,
      services: (ROLE_SERVICE_HINTS[role] || []).slice(),
      suggested_script_services: scriptSvcs
    });
  }

  return { vms, phantoms };
}

function normalizeIntake(payload) {
  const sections = payload?.sections || {};
  const net = sections.network || {};
  const company = sections.company || {};

  const warnings = [];
  const addWarn = (code, msg) => warnings.push({ code, msg });

  // Schema v1.1+: single endpoint_count. Legacy (<=v1.0) split desktops/laptops
  // across workstation_count + laptop_count — often double-counted by clients.
  // Prefer endpoint_count when present (>0); fall back to ws+laptop otherwise.
  const endpointCountExplicit = num(net.endpoint_count);
  const deviceTotal = endpointCountExplicit > 0
    ? endpointCountExplicit
    : num(net.workstation_count) + num(net.laptop_count);
  const serverCount = num(net.server_count);

  // 1. Reconcile OS counts for endpoints.
  const declared = {
    windows_server: num(net.os_count_win_server),
    windows_client: num(net.os_count_win_client),
    linux:          num(net.os_count_linux),
    macos:          num(net.os_count_macos),
    other:          num(net.os_count_other)
  };
  // Endpoint OS = win_client + macos + linux + other. Win Server counts apply to servers.
  const endpointDeclared = {
    windows_server: 0,
    windows_client: declared.windows_client,
    linux:          declared.linux,
    macos:          declared.macos,
    other:          declared.other
  };
  const recon = reconcileOsCounts(
    endpointDeclared,
    deviceTotal,
    /* fillable = */ ['windows_client', 'linux'],   // macOS/other fall through to proportional if declared but never default-filled
    /* defaultFillable = */ 'windows_client'
  );
  if (recon.gap > 0) {
    addWarn('os_count_gap', `Intake reports ${deviceTotal} endpoint devices but only ${deviceTotal - recon.gap} OSes specified. Filled ${recon.gap} as ${Object.entries(recon.counts).filter(([k,v]) => v > (endpointDeclared[k]||0)).map(([k,v])=>`${v - (endpointDeclared[k]||0)} ${k}`).join(', ')}.`);
  }

  // 2. Server count distribution.
  const serverCounts = {
    windows_server: Math.min(declared.windows_server, serverCount),
    linux: 0
  };
  if (serverCount > 0 && declared.windows_server === 0) {
    // Intake says "we have servers" but didn't split by OS. Assume Windows.
    serverCounts.windows_server = serverCount;
    addWarn('server_os_unspecified', `${serverCount} servers declared without OS breakdown — assumed Windows Server.`);
  }

  // 3. Resolve each server role.
  const resolvedRoles = {};
  for (const role of ['dc', 'file', 'web', 'db', 'mail', 'backup', 'print']) {
    resolvedRoles[role] = resolveRoleOrSaaS(role, payload);
    const dec = resolvedRoles[role];
    if (dec.status === 'saas') addWarn('role_saas', `${role.toUpperCase()} resolved to SaaS — ${dec.reason}. No VM created.`);
    else if (dec.status === 'skip' && lc(net[`role_${role}`]) === 'unknown') {
      addWarn('role_unknown', `${role.toUpperCase()} ${dec.reason}.`);
    }
  }

  // 4. Service list — canonicalize + attach versions from svc_version_* fields.
  const rawServices = Array.isArray(net.services) ? net.services : [];
  const services = [];
  for (const tok of rawServices) {
    const canonical = SERVICE_CANONICAL[String(tok).toUpperCase()];
    if (!canonical) continue;
    const versionField = `svc_version_${canonical.toLowerCase()}`;
    const version = net[versionField] || null;
    services.push({ raw: tok, canonical, version });
  }
  // VPN flagged as edge appliance even if admin added a role later.
  if (services.some(s => s.canonical === 'VPN')) {
    addWarn('vpn_edge', 'VPN listed in services — typically an edge appliance, not deployed as a VM. Admin should confirm.');
  }

  // 5. Domain.
  const domainMode = lc(net.domain_mode);
  if (resolvedRoles.dc.status === 'skip' && ['ad', 'hybrid'].includes(domainMode)) {
    addWarn('domain_inconsistent', `Domain mode "${net.domain_mode}" declared but DC not deployed. Challenge will be workgroup-only.`);
  }

  const endpointCounts = {
    windows_client: recon.counts.windows_client,
    macos:          recon.counts.macos,
    linux:          recon.counts.linux,
    other:          recon.counts.other
  };

  const normalized = {
    cover_name:     payload?.cover_name || company.cover_name || 'Unknown Client',
    industry:       company.industry || null,
    frameworks:     Array.isArray(company.frameworks) ? company.frameworks : [],
    deviceTotal,
    serverCount,
    endpointCounts,
    serverCounts,
    resolvedRoles,
    services,
    domainMode,
    notes:          sections.notes?.free_text || '',
    warnings
  };

  const { vms, phantoms } = deriveVmList(normalized);

  return {
    ...normalized,
    vms,
    phantoms
  };
}

module.exports = {
  normalizeIntake,
  resolveRoleOrSaaS,
  reconcileOsCounts,
  deriveVmList,
  ROLE_SERVICE_HINTS,
  SERVICE_CANONICAL,
  SAAS_EMAIL_PROVIDERS
};
