/**
 * ai/profile/render.js -- Professional Client Profile HTML renderer (v4.1).
 *
 * Pure function: takes the profile object built by ai/profile/index.js
 * combineProfile() and returns a full standalone HTML document string.
 *
 * Handles both the split-branch shape and the merged shape we emit via
 * cascading || fallbacks -- no adapter needed.
 */

function renderProfileHtml(profile) {
/*
 * ============================================================================
 * PROFESSIONAL CLIENT PROFILE GENERATOR v4.1 - UPGRADED for Workflow v1.2
 * ============================================================================
 * UPGRADES from v4.0:
 * - Attack path rendering handles both string[] and structured object[] formats
 *   (structured: {step, action, target, technique, detection_opportunity})
 * - New org fields displayed: annual_revenue_range, past_incidents,
 *   regulatory_timeline, growth_trajectory, business_continuity (RPO/RTO)
 * - New IT fields displayed: physical_security, vendor_risk, data_sensitivity
 * - SaaS table shows data_sensitivity column when available
 * - Kill-chain CSS for structured attack paths
 * - Diagram section gracefully hidden when diagram_text is removed
 * ============================================================================
 * NOTE: This generator does NOT include instructor-only content (weaknesses,
 * answer keys, grading rubrics). Those are in the instructor_view.
 * ============================================================================
 */

// (profile passed as fn arg)

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

if (!profile || !profile.meta) {
  throw new Error('Missing profile data. Ensure S1 Build Student View is connected.');
}

const meta = profile.meta;
const sv = profile.student_view || {};
const config = profile.config || {};
const seed = profile.seed || {};
const learning = profile.learning_objectives || {};

// ═══════════════════════════════════════════════════════════════════════════
// DATA EXTRACTION - Handle multiple possible data locations
// ═══════════════════════════════════════════════════════════════════════════

const rawOrg = sv.raw?.org;
const rawIt = sv.raw?.it;
const rawNetwork = sv.raw?.network;
const rawThreats = sv.raw?.threats;

// Build organization data with fallbacks
const org = rawOrg?.organization || rawThreats?.organization || {};
const governance = rawOrg?.profiles?.governance_and_policy || rawThreats?.profiles?.governance_and_policy || {};
const riskTolerance = rawOrg?.profiles?.risk_tolerance || rawThreats?.profiles?.risk_tolerance || {};

// Build IT environment data with fallbacks
const itEnv = rawIt?.it_environment || rawThreats?.it_environment || {};

// Build network data with fallbacks
const network = rawNetwork || rawThreats?.network || {};

// Build threat profile with fallbacks
const threatProfile = rawThreats?.threat_profile || {};

// Build stakeholders with fallbacks
const stakeholders = rawOrg?.stakeholders || rawThreats?.stakeholders || sv.stakeholders || [];

// Build artifacts with fallbacks
const artifacts = rawThreats?.artifacts || [];

// ═══════════════════════════════════════════════════════════════════════════
// APPLY ORGANIZATION OVERRIDES
// ═══════════════════════════════════════════════════════════════════════════

const overrides = config.organization_overrides || seed.organization_overrides || {};

// ═══════════════════════════════════════════════════════════════════════════
// BUILD FINAL DATA OBJECT
// ═══════════════════════════════════════════════════════════════════════════

const data = {
  // Meta
  run_id: meta.run_id || 'UNKNOWN',
  generated_at: meta.generated_at || new Date().toISOString(),
  difficulty: meta.difficulty || seed.difficulty || 'intermediate',
  client_type: meta.client_type || config.clientType || 'Unknown',
  client_type_name: config.clientTypeName || meta.client_type || 'Unknown Organization',

  // Organization (with overrides)
  company_name: overrides.company_name || org.company_name || sv.quick?.company_name || 'Unknown Company',
  industry: overrides.industry || org.industry || sv.quick?.industry || seed.template?.industry || 'Unknown Industry',
  naics: org.naics_hint || seed.template?.naics_hint || 'N/A',
  hq_city: overrides.hq_city || org.hq_city || 'N/A',
  employees: org.employees_total || sv.quick?.employees_total || seed.employees?.max || 0,
  domain: overrides.domain || org.domain_public || sv.quick?.domain_public || 'N/A',
  business_model: org.business_model || 'N/A',
  critical_services: org.critical_services || seed.template?.criticalSystems || [],
  key_systems: org.key_system_dependencies || seed.template?.criticalSystems || [],
  departments: org.department_breakdown || {},
  risks: org.risks || seed.template?.risks || [],

  // ─── NEW: Org fields from upgraded A1 ───
  annual_revenue_range: org.annual_revenue_range || null,
  past_incidents: org.past_incidents || [],
  regulatory_timeline: org.regulatory_timeline || '',
  growth_trajectory: org.growth_trajectory || '',
  business_continuity: org.business_continuity || null,

  // Governance
  framework: overrides.framework || governance.framework || 'None',
  policies_present: governance.policies_present || [],
  policies_missing: governance.policies_missing || [],
  policy_enforcement: governance.policy_enforcement || 'N/A',
  risk_tolerance_overall: riskTolerance.overall || governance.risk_tolerance || 'N/A',

  // IT Environment
  delivery: itEnv.delivery || sv.quick?.delivery || seed.delivery || 'N/A',
  endpoints: itEnv.endpoints || {},
  servers: itEnv.servers || [],
  saas: itEnv.saas || sv.quick?.saas || [],
  endpoint_protection: itEnv.endpoint_protection || {},
  patch_management: itEnv.patch_management || {},
  remote_access: itEnv.remote_access || {},
  backups: itEnv.backups || {},
  vendor_dependencies: itEnv.vendor_dependencies || [],
  known_unknowns: itEnv.known_unknowns || [],

  // ─── NEW: IT fields from upgraded B1 ───
  physical_security: itEnv.physical_security || null,
  vendor_risk: itEnv.vendor_risk || [],

  // Network
  public_ip: network.public_ip || sv.quick?.public_ip || seed.public_ip || 'N/A',
  subnets: network.subnets || sv.quick?.subnets || [],
  assets: network.assets || sv.quick?.assets || [],
  firewall: network.firewall || {},
  diagram_text: network.diagram || network.diagram_text || '',

  // Threats
  top_threats: threatProfile.top_threats || sv.quick?.top_threats || seed.template?.risks || [],
  scenarios: threatProfile.scenarios || sv.quick?.scenarios || [],

  // Stakeholders
  stakeholders: stakeholders,

  // Artifacts
  artifacts: artifacts,

  // Learning Objectives
  work_roles: learning.work_roles || config.nice_alignment?.work_roles || [],
  learning_by_part: learning.by_part || {},

  // Config info for display
  estimated_hours: config.difficulty_settings?.suggested_hours || seed.difficulty_settings?.suggested_hours || 10,
  compliance_focus: seed.template?.compliance || []
};

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const formatDate = (d) => {
  try {
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  } catch {
    return 'N/A';
  }
};

const getDifficultyColor = (diff) => {
  switch(diff?.toLowerCase()) {
    case 'beginner': return '#38a169';
    case 'advanced': return '#e53e3e';
    default: return '#dd6b20';
  }
};

const getTrustLevelClass = (level) => {
  switch(level?.toLowerCase()) {
    case 'high': return 'trust-high';
    case 'low': return 'trust-low';
    default: return 'trust-medium';
  }
};

// Helper: render a single attack path step (handles both string and object)
const renderAttackStep = (step, index, total) => {
  if (typeof step === 'object' && step !== null) {
    // Structured format from upgraded D1 prompt
    return `
      <div class="kill-chain-step">
        <div class="kill-chain-num">${step.step || index + 1}</div>
        <div class="kill-chain-body">
          <div class="kill-chain-action">${esc(step.action || '')}</div>
          <div class="kill-chain-meta">
            ${step.target ? '<span class="tag tag-default"><code>' + esc(step.target) + '</code></span>' : ''}
            ${step.technique ? '<span class="tag tag-purple">' + esc(step.technique) + '</span>' : ''}
          </div>
          ${step.detection_opportunity ? '<div class="kill-chain-detection">Detection: ' + esc(step.detection_opportunity) + '</div>' : ''}
        </div>
      </div>
      ${index < total - 1 ? '<div class="kill-chain-connector">&#8595;</div>' : ''}`;
  }
  // String format (legacy)
  return `
    <span class="attack-path-step">${esc(step)}</span>
    ${index < total - 1 ? '<span class="attack-path-arrow">&#8594;</span>' : ''}`;
};

// Helper: generate professional SVG network diagram from profile data
const generateNetworkDiagram = (data) => {
  const subnets = data.subnets || [];
  const servers = data.servers || [];
  const fwVendor = data.firewall?.vendor || 'Firewall';
  const fwRules = data.firewall?.rules || [];
  const saas = data.saas || [];
  const remoteAccess = data.remote_access || {};
  const endpointProt = data.endpoint_protection || {};
  const backups = data.backups || {};

  if (subnets.length === 0 && servers.length === 0) return '';

  const W = 960;

  // ── SVG icon helpers ──
  const iconServer = (x, y, size = 16) =>
    `<g transform="translate(${x},${y})"><rect width="${size}" height="${size * 0.7}" rx="2" fill="#e2e8f0" stroke="#64748b" stroke-width="1"/><line x1="2" y1="${size*0.35}" x2="${size-2}" y2="${size*0.35}" stroke="#94a3b8" stroke-width="0.5"/><circle cx="${size-3}" cy="${size*0.55}" r="1.5" fill="#22c55e"/></g>`;
  const iconCloud = (x, y) =>
    `<g transform="translate(${x},${y})"><ellipse cx="10" cy="10" rx="10" ry="7" fill="#dbeafe" stroke="#3b82f6" stroke-width="1"/><ellipse cx="16" cy="8" rx="7" ry="5" fill="#dbeafe" stroke="#3b82f6" stroke-width="1"/><ellipse cx="13" cy="12" rx="9" ry="5" fill="#dbeafe" stroke="#3b82f6" stroke-width="1"/></g>`;
  const iconShield = (x, y) =>
    `<g transform="translate(${x},${y})"><path d="M8,1 L15,4 L15,9 C15,13 8,16 8,16 C8,16 1,13 1,9 L1,4 Z" fill="#fef2f2" stroke="#dc2626" stroke-width="1.2"/><path d="M5,8 L7,10 L11,6" fill="none" stroke="#dc2626" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></g>`;
  const iconSwitch = (x, y) =>
    `<g transform="translate(${x},${y})"><rect width="20" height="10" rx="2" fill="#f1f5f9" stroke="#475569" stroke-width="1"/><circle cx="4" cy="5" r="1.5" fill="#22c55e"/><circle cx="8" cy="5" r="1.5" fill="#22c55e"/><circle cx="12" cy="5" r="1.5" fill="#f59e0b"/><circle cx="16" cy="5" r="1.5" fill="#22c55e"/></g>`;
  const iconLock = (x, y) =>
    `<g transform="translate(${x},${y})"><rect x="2" y="7" width="10" height="8" rx="1.5" fill="#fbbf24" stroke="#92400e" stroke-width="1"/><path d="M4,7 L4,5 C4,2.5 10,2.5 10,5 L10,7" fill="none" stroke="#92400e" stroke-width="1.2"/></g>`;
  const iconWifi = (x, y) =>
    `<g transform="translate(${x},${y})"><path d="M7,12 A1,1 0 1,0 9,12 A1,1 0 1,0 7,12" fill="#6366f1"/><path d="M4,9 Q8,5 12,9" fill="none" stroke="#6366f1" stroke-width="1.2" stroke-linecap="round"/><path d="M1,6 Q8,0 15,6" fill="none" stroke="#6366f1" stroke-width="1.2" stroke-linecap="round"/></g>`;

  // ── Match servers to subnets by IP prefix (3 octets for /24, 2 for /16) ──
  const matchServerToSubnet = (serverIp, subnetRange) => {
    if (!serverIp || !subnetRange) return false;
    const cidr = subnetRange.replace(/\/\d+$/, '');
    const mask = parseInt((subnetRange.match(/\/(\d+)$/) || [, '24'])[1]);
    const octetsToMatch = mask >= 24 ? 3 : mask >= 16 ? 2 : 1;
    const subPrefix = cidr.split('.').slice(0, octetsToMatch).join('.');
    return serverIp.startsWith(subPrefix);
  };

  // ── Enrich servers with IPs from assets (servers often lack IPs) ──
  const allAssets = data.assets || [];
  const enrichedServers = servers.map(srv => {
    if (srv.ip) return srv;
    // Find matching asset by hostname
    const match = allAssets.find(a =>
      a.hostname && srv.hostname &&
      a.hostname.toLowerCase() === srv.hostname.toLowerCase() &&
      (a.role === 'server' || !a.role)
    );
    if (match && match.ip) {
      return { ...srv, ip: match.ip, subnet: match.subnet };
    }
    return srv;
  });

  // ── Identify infrastructure-only subnet names (no workstations should appear here) ──
  const infraSubnetNames = new Set();
  subnets.forEach(s => {
    const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
    if (/\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) &&
        !/\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n)) {
      // Store all possible range identifiers
      if (s.range) infraSubnetNames.add(s.range);
      if (s.cidr) infraSubnetNames.add(s.cidr);
      // Also store the 3-octet prefix for IP matching
      const r = s.range || s.cidr || '';
      if (r) infraSubnetNames.add(r.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.'));
    }
  });

  // ── Count workstation assets per subnet ──
  // skipWsSubnets is populated after subnet classification to know which have servers
  let skipWsSubnets = new Set(); // filled later
  const getWorkstationSummary = (subRange, forceSkip, sub) => {
    if (!subRange || forceSkip) return [];
    // Never show workstations in infrastructure subnets
    const prefix = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
    if (infraSubnetNames.has(subRange) || infraSubnetNames.has(prefix)) return [];
    if (skipWsSubnets.has(subRange)) return [];
    const wsInSubnet = allAssets.filter(a =>
      a.role === 'workstation' && a.ip && matchServerToSubnet(a.ip, subRange)
    );
    if (wsInSubnet.length === 0) return [];
    // A public-access / patron subnet (e.g. a library's public computer lab):
    // its "desktops" are patron-facing PUBLIC COMPUTERS, not staff desktops.
    const subName = ((sub && (sub.name || '')) + ' ' + (sub && (sub.purpose || ''))).toLowerCase();
    const isPublicAccess = /\b(public.?access|patron|public.?computer|public.?pc|public.?lab)\b/.test(subName);
    // Group by asset type
    const counts = {};
    wsInSubnet.forEach(ws => {
      const type = ws._asset_type || 'workstation';
      const os = ws.os || 'Unknown';
      const key = type === 'laptop' && os.includes('macOS') ? 'macOS' :
                  type === 'laptop' ? 'Laptop' :
                  type === 'desktop' ? (isPublicAccess ? 'Public Computer' : 'Desktop') :
                  type === 'kiosk' ? 'Kiosk' :
                  type === 'mobile' ? 'Mobile' : 'Workstation';
      counts[key] = (counts[key] || 0) + 1;
    });
    return Object.entries(counts).map(([type, count]) => ({ type, count }));
  };

  // Also count network devices per subnet
  const getNetworkDeviceSummary = (subRange) => {
    if (!subRange) return [];
    return allAssets.filter(a =>
      a.role === 'network' && a.ip && matchServerToSubnet(a.ip, subRange)
    );
  };

  // ── Classify subnets into trust zones ──
  const trustZones = { high: [], medium: [], low: [] };
  const subnetData = subnets.map(sub => {
    const trust = (sub.trust_level || 'medium').toLowerCase();
    const subRange = sub.range || sub.cidr || '';
    // Match servers by IP prefix OR by subnet name/purpose
    const matched = enrichedServers.filter(s => {
      if (s.ip && matchServerToSubnet(s.ip, subRange)) return true;
      // Fallback: match by subnet field on the server/asset
      if (s.subnet && s.subnet === subRange) return true;
      // Fallback: match by subnet name containing "server" and server role
      const subName = (sub.name || '').toLowerCase();
      const subPurpose = (sub.purpose || '').toLowerCase();
      if ((subName.includes('server') || subPurpose.includes('server')) &&
          !s.ip && !s._subnetMatched) {
        s._subnetMatched = true;
        return true;
      }
      return false;
    });
    // If this subnet has servers or network devices matched, don't show workstations here
    const hasInfraDevices = matched.length > 0;
    const wsSummary = getWorkstationSummary(subRange, hasInfraDevices, sub);
    const netDevices = getNetworkDeviceSummary(subRange);
    const totalHosts = matched.length + wsSummary.reduce((s, w) => s + w.count, 0) + netDevices.length;
    const entry = { ...sub, matchedServers: matched, wsSummary, netDevices, totalHosts, trust };
    (trustZones[trust] || trustZones.medium).push(entry);
    return entry;
  });

  const matchedHostnames = new Set(subnetData.flatMap(s => s.matchedServers.map(sv => sv.hostname)));
  const unmatchedServers = enrichedServers.filter(s => !matchedHostnames.has(s.hostname));

  // ── Role icon selector ──
  const getRoleIcon = (role) => {
    const r = (role || '').toLowerCase();
    if (r.includes('domain') || r.includes('dc') || r.includes('active dir')) return '🔐';
    if (r.includes('file') || r.includes('storage') || r.includes('nas')) return '📁';
    if (r.includes('mail') || r.includes('exchange')) return '📧';
    if (r.includes('web') || r.includes('iis') || r.includes('apache')) return '🌐';
    if (r.includes('database') || r.includes('sql') || r.includes('db')) return '🗄️';
    if (r.includes('app') || r.includes('erp') || r.includes('crm')) return '⚙️';
    if (r.includes('print')) return '🖨️';
    if (r.includes('backup')) return '💾';
    if (r.includes('monitor') || r.includes('siem')) return '📊';
    return '🖥️';
  };

  // ── Layout calculation ──
  const HEADER_H = 50;
  // Dynamic height: base 30 + 10px per SaaS item (up to 6) or VPN lines
  const saasCount = Math.min((saas || []).length, 6);
  const vpnLines = remoteAccess.vpn ? (remoteAccess.mfa && remoteAccess.mfa !== 'None' ? 2 : 1) : 0;
  const INTERNET_ZONE_H = Math.max(45, 24 + Math.max(saasCount, vpnLines) * 11 + 8);
  const DMZ_H = 60;
  const FW_ZONE_H = 80;
  const CORE_SWITCH_H = 50;
  const SUBNET_HEADER = 36;
  const SERVER_ROW_H = 32;
  const SERVER_PAD = 8;
  const ZONE_GAP = 20;
  const SIDE_PAD = 20;

  // Calculate content rows for a subnet (servers + ws summary + net devices)
  const calcSubnetRows = (sub) => {
    let rows = sub.matchedServers.length;
    if (sub.wsSummary && sub.wsSummary.length > 0) rows += sub.wsSummary.length;
    if (sub.netDevices && sub.netDevices.length > 0) rows += sub.netDevices.length;
    return Math.max(rows, 1); // at least 1 row for "no hosts"
  };

  // Calculate subnet zone heights
  const calcZoneH = (zoneSubs) => {
    if (zoneSubs.length === 0) return 0;
    const cols = Math.min(zoneSubs.length, 3);
    const rows = Math.ceil(zoneSubs.length / cols);
    const maxRowsPerGridRow = [];
    for (let r = 0; r < rows; r++) {
      let maxR = 0;
      for (let c = 0; c < cols; c++) {
        const idx = r * cols + c;
        if (idx < zoneSubs.length) maxR = Math.max(maxR, calcSubnetRows(zoneSubs[idx]));
      }
      maxRowsPerGridRow.push(maxR);
    }
    return maxRowsPerGridRow.reduce((sum, mr) => sum + SUBNET_HEADER + mr * SERVER_ROW_H + SERVER_PAD + ZONE_GAP, 0) + 40;
  };

  const highZoneH = calcZoneH(trustZones.high);
  const medZoneH = calcZoneH(trustZones.medium);
  const lowZoneH = calcZoneH(trustZones.low);
  const unmatchedH = unmatchedServers.length > 0 ? unmatchedServers.length * SERVER_ROW_H + 60 : 0;
  const saasH = saas.length > 0 ? 70 : 0;
  const legendH = 70;
  const totalH = HEADER_H + INTERNET_ZONE_H + FW_ZONE_H + CORE_SWITCH_H + highZoneH + medZoneH + lowZoneH + unmatchedH + saasH + legendH + 40;

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${totalH}" style="width:100%;max-width:960px;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;">`;

  // ── Defs: gradients, markers, filters ──
  svg += `<defs>
    <marker id="nd-arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#475569"/></marker>
    <marker id="nd-arrow-red" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#dc2626"/></marker>
    <linearGradient id="nd-header-bg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#0f172a"/><stop offset="100%" stop-color="#1e3a5f"/></linearGradient>
    <linearGradient id="nd-inet-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#eff6ff"/><stop offset="100%" stop-color="#dbeafe"/></linearGradient>
    <linearGradient id="nd-fw-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#fef2f2"/><stop offset="100%" stop-color="#fee2e2"/></linearGradient>
    <linearGradient id="nd-core-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#f8fafc"/><stop offset="100%" stop-color="#f1f5f9"/></linearGradient>
    <linearGradient id="nd-high-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#f0fdf4"/><stop offset="100%" stop-color="#dcfce7"/></linearGradient>
    <linearGradient id="nd-med-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#fffbeb"/><stop offset="100%" stop-color="#fef3c7"/></linearGradient>
    <linearGradient id="nd-low-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#fef2f2"/><stop offset="100%" stop-color="#fecaca"/></linearGradient>
    <filter id="nd-shadow"><feDropShadow dx="0" dy="1" stdDeviation="2" flood-opacity="0.1"/></filter>
    <filter id="nd-shadow-lg"><feDropShadow dx="0" dy="2" stdDeviation="4" flood-opacity="0.15"/></filter>
  </defs>`;

  let curY = 0;

  // ── Title bar ──
  svg += `<rect x="0" y="${curY}" width="${W}" height="${HEADER_H}" fill="url(#nd-header-bg)"/>`;
  svg += `<text x="${SIDE_PAD}" y="${curY + 30}" font-size="16" font-weight="700" fill="white">Network Architecture Diagram</text>`;
  svg += `<text x="${W - SIDE_PAD}" y="${curY + 20}" text-anchor="end" font-size="9" fill="#94a3b8">${esc(data.company_name || '')}</text>`;
  svg += `<text x="${W - SIDE_PAD}" y="${curY + 34}" text-anchor="end" font-size="9" fill="#94a3b8">Public IP: ${esc(data.public_ip || 'N/A')}</text>`;
  curY += HEADER_H;

  // ── Internet / WAN Zone ──
  svg += `<rect x="0" y="${curY}" width="${W}" height="${INTERNET_ZONE_H}" fill="url(#nd-inet-bg)" stroke="#bfdbfe" stroke-width="0.5"/>`;
  svg += `<text x="${SIDE_PAD}" y="${curY + 14}" font-size="8" font-weight="600" fill="#3b82f6" letter-spacing="1.5">EXTERNAL / WAN</text>`;
  svg += iconCloud(W/2 - 13, curY + 16);
  svg += `<text x="${W/2 + 18}" y="${curY + 30}" font-size="11" font-weight="600" fill="#1e40af">Internet</text>`;

  // SaaS apps on the right
  if (saas.length > 0) {
    const topSaas = saas.slice(0, 6).map(s => typeof s === 'string' ? s : s.name || '');
    svg += `<text x="${W - SIDE_PAD}" y="${curY + 18}" text-anchor="end" font-size="8" fill="#6b7280" font-weight="600">CLOUD SERVICES</text>`;
    topSaas.forEach((name, i) => {
      svg += `<text x="${W - SIDE_PAD}" y="${curY + 30 + i * 10}" text-anchor="end" font-size="8" fill="#6b7280">☁ ${esc(name)}</text>`;
    });
  }

  // VPN on the left
  if (remoteAccess.vpn) {
    svg += iconLock(SIDE_PAD + 5, curY + 18);
    svg += `<text x="${SIDE_PAD + 22}" y="${curY + 30}" font-size="9" fill="#6b7280">VPN: ${esc(remoteAccess.vpn)}</text>`;
    if (remoteAccess.mfa && remoteAccess.mfa !== 'None') {
      svg += `<text x="${SIDE_PAD + 22}" y="${curY + 40}" font-size="8" fill="#16a34a">MFA: ${esc(remoteAccess.mfa)}</text>`;
    }
  }

  curY += INTERNET_ZONE_H;

  // ── Firewall Zone ──
  svg += `<rect x="0" y="${curY}" width="${W}" height="${FW_ZONE_H}" fill="url(#nd-fw-bg)" stroke="#fca5a5" stroke-width="0.5"/>`;
  svg += `<text x="${SIDE_PAD}" y="${curY + 14}" font-size="8" font-weight="600" fill="#dc2626" letter-spacing="1.5">PERIMETER SECURITY</text>`;

  // Firewall box
  const fwX = W/2 - 100, fwBoxW = 200, fwBoxH = 48;
  svg += `<rect x="${fwX}" y="${curY + 20}" width="${fwBoxW}" height="${fwBoxH}" rx="6" fill="white" stroke="#dc2626" stroke-width="2" filter="url(#nd-shadow-lg)"/>`;
  svg += iconShield(fwX + 10, curY + 34);
  svg += `<text x="${fwX + 30}" y="${curY + 42}" font-size="12" font-weight="700" fill="#991b1b">${esc(fwVendor)}</text>`;
  svg += `<text x="${fwX + 30}" y="${curY + 56}" font-size="8" fill="#b91c1c">${fwRules.length > 0 ? fwRules.length + ' ACL rules + implicit deny' : 'Perimeter Firewall'}</text>`;

  // Connection line: Internet → Firewall
  svg += `<line x1="${W/2}" y1="${curY}" x2="${W/2}" y2="${curY + 20}" stroke="#dc2626" stroke-width="2" marker-end="url(#nd-arrow-red)"/>`;

  curY += FW_ZONE_H;

  // ── Core Switch / Distribution ──
  svg += `<rect x="0" y="${curY}" width="${W}" height="${CORE_SWITCH_H}" fill="url(#nd-core-bg)" stroke="#e2e8f0" stroke-width="0.5"/>`;
  svg += `<text x="${SIDE_PAD}" y="${curY + 14}" font-size="8" font-weight="600" fill="#475569" letter-spacing="1.5">CORE / DISTRIBUTION</text>`;

  const swX = W/2 - 70, swBoxW = 140;
  svg += `<rect x="${swX}" y="${curY + 20}" width="${swBoxW}" height="22" rx="4" fill="white" stroke="#475569" stroke-width="1.5" filter="url(#nd-shadow)"/>`;
  svg += iconSwitch(swX + 8, curY + 26);
  svg += `<text x="${swX + 34}" y="${curY + 35}" font-size="10" font-weight="600" fill="#334155">Core Switch</text>`;

  // Connection: Firewall → Core Switch
  svg += `<line x1="${W/2}" y1="${curY}" x2="${W/2}" y2="${curY + 20}" stroke="#475569" stroke-width="2" marker-end="url(#nd-arrow)"/>`;

  // Endpoint protection badge
  if (endpointProt.product) {
    svg += `<rect x="${W - SIDE_PAD - 160}" y="${curY + 22}" width="150" height="18" rx="9" fill="#eff6ff" stroke="#3b82f6" stroke-width="0.8"/>`;
    svg += `<text x="${W - SIDE_PAD - 85}" y="${curY + 34}" text-anchor="middle" font-size="8" fill="#1d4ed8">🛡️ ${esc(endpointProt.product)}${endpointProt.edr_enabled ? ' + EDR' : ''}</text>`;
  }

  // Backup badge
  if (backups.method) {
    svg += `<rect x="${SIDE_PAD + 10}" y="${curY + 22}" width="140" height="18" rx="9" fill="#f0fdf4" stroke="#16a34a" stroke-width="0.8"/>`;
    svg += `<text x="${SIDE_PAD + 80}" y="${curY + 34}" text-anchor="middle" font-size="8" fill="#166534">💾 ${esc(backups.method)} (${esc(backups.frequency || 'daily')})</text>`;
  }

  curY += CORE_SWITCH_H;

  // ── Render a zone of subnets ──
  const renderSubnetZone = (zoneName, zoneSubs, gradient, borderColor, labelColor, zoneLabel) => {
    if (zoneSubs.length === 0) return;
    const zH = calcZoneH(zoneSubs);

    svg += `<rect x="0" y="${curY}" width="${W}" height="${zH}" fill="url(#${gradient})" stroke="${borderColor}" stroke-width="0.5"/>`;
    svg += `<text x="${SIDE_PAD}" y="${curY + 14}" font-size="8" font-weight="600" fill="${labelColor}" letter-spacing="1.5">${zoneLabel}</text>`;

    const cols = Math.min(zoneSubs.length, 3);
    const colW = (W - SIDE_PAD * 2 - (cols - 1) * 12) / cols;
    let rowY = curY + 24;

    zoneSubs.forEach((sub, i) => {
      const col = i % cols;
      const colX = SIDE_PAD + col * (colW + 12);

      // Start new row
      if (i > 0 && col === 0) {
        const prevRowStart = i - cols;
        let maxH = 0;
        for (let p = prevRowStart; p < i && p < zoneSubs.length; p++) {
          const h = SUBNET_HEADER + calcSubnetRows(zoneSubs[p]) * SERVER_ROW_H + SERVER_PAD;
          maxH = Math.max(maxH, h);
        }
        rowY += maxH + ZONE_GAP;
      }

      const contentRows = calcSubnetRows(sub);
      const subH = SUBNET_HEADER + contentRows * SERVER_ROW_H + SERVER_PAD;
      const subRange = sub.range || sub.cidr || '';
      const gateway = sub.gateway || (subRange ? subRange.replace(/\.\d+\//, '.1/').replace(/\/\d+$/, '') : '');

      // Subnet card
      svg += `<rect x="${colX}" y="${rowY}" width="${colW}" height="${subH}" rx="8" fill="white" stroke="${borderColor}" stroke-width="1.5" filter="url(#nd-shadow)"/>`;

      // Subnet header bar
      svg += `<rect x="${colX}" y="${rowY}" width="${colW}" height="${SUBNET_HEADER}" rx="8" fill="${borderColor}" opacity="0.12"/>`;
      svg += `<rect x="${colX}" y="${rowY + SUBNET_HEADER - 4}" width="${colW}" height="4" fill="${borderColor}" opacity="0.12"/>`;
      svg += `<text x="${colX + 10}" y="${rowY + 15}" font-size="10" font-weight="700" fill="#1e293b">${esc(sub.name || 'Subnet')}</text>`;
      svg += `<text x="${colX + colW - 8}" y="${rowY + 15}" text-anchor="end" font-size="8" fill="#64748b" font-family="'Consolas','Monaco',monospace">${esc(subRange)}</text>`;
      if (gateway) {
        svg += `<text x="${colX + 10}" y="${rowY + 28}" font-size="7" fill="#94a3b8">GW: ${esc(gateway)}</text>`;
      }
      svg += `<text x="${colX + colW - 8}" y="${rowY + 28}" text-anchor="end" font-size="7" fill="#94a3b8">${sub.totalHosts} host${sub.totalHosts !== 1 ? 's' : ''}</text>`;

      // Connection line from core switch
      const lineX = colX + colW / 2;
      svg += `<line x1="${lineX}" y1="${curY}" x2="${lineX}" y2="${rowY}" stroke="${borderColor}" stroke-width="1" stroke-dasharray="3,3" opacity="0.6"/>`;

      // Render content rows
      let rowIdx = 0;

      // 1. Servers (individual entries)
      if (sub.matchedServers.length > 0) {
        sub.matchedServers.forEach((srv) => {
          const srvY = rowY + SUBNET_HEADER + rowIdx * SERVER_ROW_H + 4;
          const srvW = colW - 16;
          svg += `<rect x="${colX + 8}" y="${srvY}" width="${srvW}" height="${SERVER_ROW_H - 4}" rx="4" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1"/>`;
          svg += `<text x="${colX + 14}" y="${srvY + 12}" font-size="9" fill="#334155">${getRoleIcon(srv.role)} <tspan font-weight="600">${esc(srv.hostname || 'Server')}</tspan></text>`;
          svg += `<text x="${colX + 14}" y="${srvY + 23}" font-size="7.5" fill="#94a3b8">${esc(srv.os || '')}${srv.ip ? ' • ' + esc(srv.ip) : ''}</text>`;
          rowIdx++;
        });
      }

      // 2. Network devices (individual entries)
      if (sub.netDevices && sub.netDevices.length > 0) {
        sub.netDevices.forEach((dev) => {
          const devY = rowY + SUBNET_HEADER + rowIdx * SERVER_ROW_H + 4;
          const devW = colW - 16;
          svg += `<rect x="${colX + 8}" y="${devY}" width="${devW}" height="${SERVER_ROW_H - 4}" rx="4" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1"/>`;
          svg += `<text x="${colX + 14}" y="${devY + 12}" font-size="9" fill="#334155">🔌 <tspan font-weight="600">${esc(dev.hostname || 'Network Device')}</tspan></text>`;
          svg += `<text x="${colX + 14}" y="${devY + 23}" font-size="7.5" fill="#94a3b8">${esc(dev.function || dev.os || '')}${dev.ip ? ' • ' + esc(dev.ip) : ''}</text>`;
          rowIdx++;
        });
      }

      // 3. Workstation summaries (grouped counts)
      if (sub.wsSummary && sub.wsSummary.length > 0) {
        sub.wsSummary.forEach((ws) => {
          const wsY = rowY + SUBNET_HEADER + rowIdx * SERVER_ROW_H + 4;
          const wsW = colW - 16;
          const wsIcon = ws.type === 'Laptop' ? '💻' : ws.type === 'Desktop' ? '🖥️' : ws.type === 'macOS' ? '🍎' : ws.type === 'Kiosk' ? '📺' : ws.type === 'Mobile' ? '📱' : '💻';
          svg += `<rect x="${colX + 8}" y="${wsY}" width="${wsW}" height="${SERVER_ROW_H - 4}" rx="4" fill="#fefce8" stroke="#fde68a" stroke-width="1"/>`;
          svg += `<text x="${colX + 14}" y="${wsY + 12}" font-size="9" fill="#334155">${wsIcon} <tspan font-weight="600">${ws.count}× ${esc(ws.type)}</tspan></text>`;
          svg += `<text x="${colX + 14}" y="${wsY + 23}" font-size="7.5" fill="#94a3b8">Endpoints</text>`;
          rowIdx++;
        });
      }

      // 4. Empty state
      if (sub.totalHosts === 0) {
        svg += `<text x="${colX + colW/2}" y="${rowY + SUBNET_HEADER + 16}" text-anchor="middle" font-size="9" fill="#c0c0c0" font-style="italic">No hosts mapped</text>`;
      }
    });

    // Update curY based on rendered content
    curY += zH;
  };

  renderSubnetZone('high', trustZones.high, 'nd-high-bg', '#16a34a', '#15803d', 'HIGH TRUST ZONE — INTERNAL / SERVERS');
  renderSubnetZone('medium', trustZones.medium, 'nd-med-bg', '#d97706', '#b45309', 'MEDIUM TRUST ZONE — STANDARD ACCESS');
  renderSubnetZone('low', trustZones.low, 'nd-low-bg', '#dc2626', '#b91c1c', 'LOW TRUST ZONE — RESTRICTED / GUEST');

  // ── Unmatched servers (server room) ──
  if (unmatchedServers.length > 0) {
    const usZoneH = unmatchedServers.length * SERVER_ROW_H + 50;
    svg += `<rect x="0" y="${curY}" width="${W}" height="${usZoneH}" fill="#f8fafc" stroke="#e2e8f0" stroke-width="0.5"/>`;
    svg += `<text x="${SIDE_PAD}" y="${curY + 14}" font-size="8" font-weight="600" fill="#475569" letter-spacing="1.5">SERVER ROOM — UNALLOCATED / MANAGEMENT</text>`;

    const tblX = SIDE_PAD + 20, tblW = W - SIDE_PAD * 2 - 40;

    // Table header
    svg += `<rect x="${tblX}" y="${curY + 24}" width="${tblW}" height="20" rx="4" fill="#e2e8f0"/>`;
    svg += `<text x="${tblX + 10}" y="${curY + 38}" font-size="8" font-weight="700" fill="#475569">HOSTNAME</text>`;
    svg += `<text x="${tblX + tblW * 0.3}" y="${curY + 38}" font-size="8" font-weight="700" fill="#475569">OPERATING SYSTEM</text>`;
    svg += `<text x="${tblX + tblW * 0.65}" y="${curY + 38}" font-size="8" font-weight="700" fill="#475569">ROLE</text>`;
    svg += `<text x="${tblX + tblW - 10}" y="${curY + 38}" text-anchor="end" font-size="8" font-weight="700" fill="#475569">IP ADDRESS</text>`;

    unmatchedServers.forEach((srv, i) => {
      const rowY = curY + 46 + i * SERVER_ROW_H;
      const rowBg = i % 2 === 0 ? 'white' : '#f8fafc';
      svg += `<rect x="${tblX}" y="${rowY}" width="${tblW}" height="${SERVER_ROW_H}" fill="${rowBg}" ${i === unmatchedServers.length - 1 ? 'rx="0 0 4 4"' : ''}/>`;
      svg += `<line x1="${tblX}" y1="${rowY + SERVER_ROW_H}" x2="${tblX + tblW}" y2="${rowY + SERVER_ROW_H}" stroke="#f1f5f9" stroke-width="0.5"/>`;
      svg += `<text x="${tblX + 10}" y="${rowY + 20}" font-size="9" font-weight="600" fill="#334155">${getRoleIcon(srv.role)} ${esc(srv.hostname || 'Server')}</text>`;
      svg += `<text x="${tblX + tblW * 0.3}" y="${rowY + 20}" font-size="8.5" fill="#64748b">${esc(srv.os || 'Unknown')}</text>`;
      svg += `<text x="${tblX + tblW * 0.65}" y="${rowY + 20}" font-size="8.5" fill="#64748b">${esc(srv.role || 'General')}</text>`;
      svg += `<text x="${tblX + tblW - 10}" y="${rowY + 20}" text-anchor="end" font-size="8.5" fill="#94a3b8" font-family="'Consolas','Monaco',monospace">${esc(srv.ip || 'N/A')}</text>`;
    });

    curY += usZoneH;
  }

  // ── Legend ──
  svg += `<rect x="0" y="${curY}" width="${W}" height="${legendH}" fill="#f8fafc" stroke="#e2e8f0" stroke-width="0.5"/>`;
  svg += `<text x="${SIDE_PAD}" y="${curY + 16}" font-size="8" font-weight="600" fill="#475569" letter-spacing="1.5">LEGEND</text>`;

  // Trust zone legend
  const legY = curY + 28;
  svg += `<rect x="${SIDE_PAD}" y="${legY}" width="12" height="12" rx="3" fill="#dcfce7" stroke="#16a34a" stroke-width="1.5"/>`;
  svg += `<text x="${SIDE_PAD + 18}" y="${legY + 10}" font-size="9" fill="#475569">High Trust</text>`;
  svg += `<rect x="${SIDE_PAD + 90}" y="${legY}" width="12" height="12" rx="3" fill="#fef3c7" stroke="#d97706" stroke-width="1.5"/>`;
  svg += `<text x="${SIDE_PAD + 108}" y="${legY + 10}" font-size="9" fill="#475569">Medium Trust</text>`;
  svg += `<rect x="${SIDE_PAD + 200}" y="${legY}" width="12" height="12" rx="3" fill="#fecaca" stroke="#dc2626" stroke-width="1.5"/>`;
  svg += `<text x="${SIDE_PAD + 218}" y="${legY + 10}" font-size="9" fill="#475569">Low Trust / DMZ</text>`;

  // Device icons legend
  svg += `<text x="${SIDE_PAD + 340}" y="${legY + 10}" font-size="9" fill="#475569">🖥️ Server</text>`;
  svg += `<text x="${SIDE_PAD + 400}" y="${legY + 10}" font-size="9" fill="#475569">🔐 Domain Controller</text>`;
  svg += `<text x="${SIDE_PAD + 510}" y="${legY + 10}" font-size="9" fill="#475569">📁 File Server</text>`;
  svg += `<text x="${SIDE_PAD + 590}" y="${legY + 10}" font-size="9" fill="#475569">🗄️ Database</text>`;
  svg += `<text x="${SIDE_PAD + 660}" y="${legY + 10}" font-size="9" fill="#475569">🌐 Web Server</text>`;

  // Stats bar
  svg += `<text x="${SIDE_PAD}" y="${legY + 30}" font-size="8" fill="#94a3b8">${subnets.length} subnet${subnets.length !== 1 ? 's' : ''} · ${servers.length} server${servers.length !== 1 ? 's' : ''} · ${fwRules.length} firewall rule${fwRules.length !== 1 ? 's' : ''}</text>`;
  svg += `<text x="${W - SIDE_PAD}" y="${legY + 30}" text-anchor="end" font-size="8" fill="#94a3b8">Generated ${new Date().toISOString().split('T')[0]} · Clinic-in-a-Box</text>`;

  svg += `</svg>`;
  return svg;
};

// Helper: get severity CSS class
const getSeverityClass = (sev) => {
  switch((sev || '').toLowerCase()) {
    case 'critical': return 'tag-danger';
    case 'high': return 'tag-danger';
    case 'medium': return 'tag-warning';
    case 'low': return 'tag-success';
    default: return 'tag-default';
  }
};

// Helper: boolean display
const boolDisplay = (val) => val ? '<span style="color:#276749;font-weight:600;">Yes</span>' : '<span style="color:#c53030;font-weight:600;">No</span>';

// ═══════════════════════════════════════════════════════════════════════════
// Detect if attack paths use structured format (for CSS inclusion)
// ═══════════════════════════════════════════════════════════════════════════
const hasStructuredAttackPaths = data.scenarios.some(s =>
  s.attack_path && s.attack_path.length > 0 && typeof s.attack_path[0] === 'object'
);

// ═══════════════════════════════════════════════════════════════════════════
// Check if new fields exist (for conditional section rendering)
// ═══════════════════════════════════════════════════════════════════════════
const hasSaasDataSensitivity = data.saas.some(s => typeof s === 'object' && s.data_sensitivity);

// ═══════════════════════════════════════════════════════════════════════════
// ASSET ENRICHMENT: Make/Model/Serial + IT Environment Cross-Reference
// ═══════════════════════════════════════════════════════════════════════════

// Deterministic hash from string → stable int (for seeded generation)
function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// Pick from array using seeded index
function seededPick(arr, seed) { return arr[seed % arr.length]; }

// Generate a realistic-looking serial number seeded from hostname+company
function generateSerial(hostname, vendor, company) {
  const seed = hashStr(hostname + (company || ''));
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  const digits = '0123456789';
  const hex = '0123456789ABCDEF';

  const genChars = (n, pool) => {
    let out = '';
    let s = seed;
    for (let i = 0; i < n; i++) {
      s = ((s * 1103515245 + 12345) & 0x7fffffff);
      out += pool[s % pool.length];
    }
    return out;
  };

  const v = (vendor || '').toLowerCase();
  if (v.includes('dell'))         return genChars(7, chars);                         // Dell service tag: F3K7N2X
  if (v.includes('hp') || v.includes('hewlett'))  return 'CND' + genChars(7, digits);   // HP: CND3456789
  if (v.includes('lenovo'))       return 'PF-' + genChars(7, chars);                 // Lenovo: PF-3ABCD12
  if (v.includes('apple'))        return 'C02' + genChars(9, chars);                 // Apple: C02FP12QML7H
  if (v.includes('cisco'))        return 'FCW' + genChars(8, chars);                 // Cisco: FCW2345ABCD
  if (v.includes('palo'))         return genChars(12, digits);                       // PA: 012345678901
  if (v.includes('fortinet') || v.includes('forti')) return 'FG' + genChars(13, hex); // Fortinet: FG1234ABCDEF01
  if (v.includes('sonicwall'))    return genChars(12, hex);
  return genChars(10, chars);                                                        // Generic
}

// Make/Model lookup tables
const serverMakeModels = [
  { make: 'Dell', model: 'PowerEdge R750' },
  { make: 'Dell', model: 'PowerEdge R740' },
  { make: 'Dell', model: 'PowerEdge R640' },
  { make: 'HPE', model: 'ProLiant DL380 Gen10 Plus' },
  { make: 'HPE', model: 'ProLiant DL360 Gen10 Plus' },
  { make: 'Lenovo', model: 'ThinkSystem SR650 V2' },
  { make: 'Lenovo', model: 'ThinkSystem SR630 V2' }
];

const switchMakeModels = [
  { make: 'Cisco', model: 'Catalyst 9300-48P' },
  { make: 'Cisco', model: 'Catalyst 9200-24P' },
  { make: 'HPE', model: 'Aruba 6300M' },
  { make: 'Juniper', model: 'EX4400-48P' }
];

const laptopMakeModels = [
  { make: 'Dell', model: 'Latitude 5550' },
  { make: 'Dell', model: 'Latitude 5540' },
  { make: 'Lenovo', model: 'ThinkPad T14 Gen 4' },
  { make: 'Lenovo', model: 'ThinkPad T16 Gen 2' },
  { make: 'HP', model: 'EliteBook 840 G10' },
  { make: 'HP', model: 'EliteBook 860 G10' }
];

const desktopMakeModels = [
  { make: 'Dell', model: 'OptiPlex 7020' },
  { make: 'Dell', model: 'OptiPlex 7010' },
  { make: 'Lenovo', model: 'ThinkCentre M70q Gen 4' },
  { make: 'HP', model: 'ProDesk 400 G9' },
  { make: 'HP', model: 'EliteDesk 800 G9' }
];

const macMakeModels = [
  { make: 'Apple', model: 'MacBook Pro 14" M3' },
  { make: 'Apple', model: 'MacBook Air 13" M2' },
  { make: 'Apple', model: 'iMac 24" M3' }
];

const kioskMakeModels = [
  { make: 'Dell', model: 'OptiPlex 3000 Thin Client' },
  { make: 'HP', model: 'ProDesk 400 G9 Mini' },
  { make: 'Lenovo', model: 'ThinkCentre M70q Tiny' },
  { make: 'Dell', model: 'Wyse 5070' }
];

const mobileMakeModels = [
  { make: 'Apple', model: 'iPhone 15' },
  { make: 'Apple', model: 'iPhone 14' },
  { make: 'Apple', model: 'iPad 10th Gen' },
  { make: 'Samsung', model: 'Galaxy S24' },
  { make: 'Samsung', model: 'Galaxy Tab S9' }
];

// Assign make/model to an asset based on its role and OS
function assignMakeModel(asset) {
  const h = hashStr(asset.hostname || 'unknown');
  const os = (asset.os || '').toLowerCase();
  const fn = (asset.function || '').toLowerCase();
  const hostname = (asset.hostname || '').toLowerCase();

  if (asset.role === 'server') {
    return seededPick(serverMakeModels, h);
  }

  if (asset.role === 'network') {
    // Check if it's a firewall or switch
    if (hostname.includes('fw') || fn.includes('firewall')) {
      // Use the actual firewall vendor if available
      const fwVendor = data.firewall?.vendor || '';
      const fwModel = data.firewall?.model || '';
      if (fwVendor || fwModel) {
        return { make: fwVendor || 'Unknown', model: fwModel || 'Firewall' };
      }
      return { make: 'Palo Alto', model: 'PA-850' };
    }
    return seededPick(switchMakeModels, h);
  }

  if (asset.role === 'workstation') {
    if (asset._asset_type === 'mobile') {
      return seededPick(mobileMakeModels, h);
    }
    if (asset._asset_type === 'kiosk') {
      return seededPick(kioskMakeModels, h);
    }
    if (os.includes('macos') || os.includes('mac os') || os.includes('apple')) {
      return seededPick(macMakeModels, h);
    }
    // Determine laptop vs desktop based on enriched asset_type or hostname hints
    if (asset._asset_type === 'laptop' || hostname.includes('lap') || hostname.includes('lt-')) {
      return seededPick(laptopMakeModels, h);
    }
    if (asset._asset_type === 'desktop') {
      return seededPick(desktopMakeModels, h);
    }
    // Default: mix of laptops and desktops
    return h % 3 === 0 ? seededPick(desktopMakeModels, h) : seededPick(laptopMakeModels, h);
  }

  if (asset.role === 'ot') {
    return { make: 'Siemens', model: hostname.includes('plc') ? 'SIMATIC S7-1500' : 'SIMATIC HMI TP700' };
  }

  return { make: 'Unknown', model: 'Unknown' };
}

// ─── Cross-reference IT environment endpoints with network workstations ───
// Assign realistic OS and device type to workstations based on IT env counts
// ALSO reconcile workstation count to match endpoint total exactly

const ep = data.endpoints || {};
let wsAssets = data.assets.filter(a => a.role === 'workstation');
const nonWsAssets = data.assets.filter(a => a.role !== 'workstation');

// ── Industry-aware endpoint filtering ──
// Filter out device types that aren't realistic for this organization type.
// Mobile devices and kiosks are only included for industries that actually use them.
const industry = (data.industry || '').toLowerCase();
const clientType = (data.client_type_name || data.client_type || '').toLowerCase();
const orgContext = industry + ' ' + clientType;

// Determine which device types are realistic for this organization
const includeMobile = /\b(healthcare|hospital|clinic|medical|pharma|field.?service|logistics|construction|utilities|energy|emergency|law.?enforcement|government.?agency)\b/.test(orgContext);
const includeKiosk = /\b(retail|hospitality|hotel|restaurant|hospital|clinic|library|museum|airport|transit|warehouse|manufacturing|bank)\b/.test(orgContext);
const includeMacOS = /\b(creative|design|media|marketing.?agency|tech|software|startup|university|architecture|video|music|advertising)\b/.test(orgContext);

// Build assignment queue with industry-appropriate device types only
const assignmentQueue = [];
if (ep.windows_laptops > 0)   assignmentQueue.push({ os: 'Windows 11 Pro', type: 'laptop', count: ep.windows_laptops, fn: 'Employee Laptop' });
if (ep.windows_desktops > 0)  assignmentQueue.push({ os: 'Windows 11 Pro', type: 'desktop', count: ep.windows_desktops, fn: 'Employee Desktop' });
if (ep.shared_kiosks > 0 && includeKiosk)  assignmentQueue.push({ os: 'Windows 10 Enterprise LTSC', type: 'kiosk', count: ep.shared_kiosks, fn: 'Shared Kiosk Terminal' });
if (ep.macos > 0 && includeMacOS)          assignmentQueue.push({ os: 'macOS Sonoma 14', type: 'laptop', count: ep.macos, fn: 'Employee MacBook' });
if (ep.mobile > 0 && includeMobile)        assignmentQueue.push({ os: 'iOS 17 / Android 14', type: 'mobile', count: ep.mobile, fn: 'Mobile Device (MDM)' });

// If filtering removed devices, redistribute those counts to laptops/desktops
const filteredOut = (ep.shared_kiosks || 0) * (!includeKiosk ? 1 : 0) +
                    (ep.macos || 0) * (!includeMacOS ? 1 : 0) +
                    (ep.mobile || 0) * (!includeMobile ? 1 : 0);
if (filteredOut > 0) {
  // Add filtered counts back as desktops (most common fallback)
  const desktopEntry = assignmentQueue.find(q => q.type === 'desktop');
  if (desktopEntry) {
    desktopEntry.count += filteredOut;
  } else if (assignmentQueue.length > 0) {
    assignmentQueue[0].count += filteredOut; // add to whatever exists
  }
  // Update the endpoints display counts too
  if (!includeKiosk && ep.shared_kiosks) { data.endpoints.windows_desktops = (data.endpoints.windows_desktops || 0) + ep.shared_kiosks; delete data.endpoints.shared_kiosks; }
  if (!includeMacOS && ep.macos) { data.endpoints.windows_laptops = (data.endpoints.windows_laptops || 0) + ep.macos; delete data.endpoints.macos; }
  if (!includeMobile && ep.mobile) { data.endpoints.windows_desktops = (data.endpoints.windows_desktops || 0) + ep.mobile; delete data.endpoints.mobile; }
}

// Calculate the authoritative endpoint total from IT env
const endpointTotal = assignmentQueue.reduce((sum, b) => sum + b.count, 0);

// Reconcile workstation count to match endpoint total AND distribute across subnets
if (endpointTotal > 0) {
  // Identify workstation-eligible subnets (exclude server/infrastructure/management subnets)
  const wsSubnets = data.subnets.filter(s => {
    const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
    // Exclude subnets meant for servers, infrastructure, or network management
    const isInfraOnly = /\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) &&
                        !/\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n);
    return !isInfraOnly && (s.range || s.cidr);
  });

  // Assign distribution weights based on subnet purpose/name
  // Works across all company types: corporate, healthcare, education, manufacturing, retail, government, etc.
  const subnetWeights = wsSubnets.map(s => {
    const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
    // ── Very high density: a library's public-access computer lab is the
    //    densest part of the network — more machines than staff. Must be
    //    checked BEFORE the generic guest/public rule below (which is for
    //    corporate BYOD lobbies and is low-density). ──
    if (/\b(public.?access|patron|public.?computer|public.?pc|public.?lab)\b/.test(n)) return { subnet: s, weight: 55 };
    // ── High density (35-45): primary user subnets where most endpoints live ──
    if (/\b(staff|employee|corporate|office|workstation|user|desktop|internal)\b/.test(n)) return { subnet: s, weight: 40 };
    if (/\b(clinical|nursing|medical|patient.care|ward)\b/.test(n)) return { subnet: s, weight: 40 }; // healthcare
    if (/\b(production|shop.?floor|warehouse|manufacturing|plant)\b/.test(n)) return { subnet: s, weight: 35 }; // manufacturing
    if (/\b(trading|operations|call.?center)\b/.test(n)) return { subnet: s, weight: 40 }; // finance

    // ── Medium density (15-25): department/functional subnets ──
    if (/\b(admin|administration|executive|front.?desk|reception)\b/.test(n)) return { subnet: s, weight: 20 };
    if (/\b(student|classroom|lab|library|learning|academic|faculty|teacher)\b/.test(n)) return { subnet: s, weight: 25 }; // education
    if (/\b(engineering|development|r&d|research|design|dev)\b/.test(n)) return { subnet: s, weight: 20 };
    if (/\b(sales|marketing|retail|store|pos|point.of.sale)\b/.test(n)) return { subnet: s, weight: 20 };
    if (/\b(hr|human.resource|finance|accounting|legal|compliance)\b/.test(n)) return { subnet: s, weight: 15 };
    if (/\b(pharmacy|radiology|imaging|diagnostic)\b/.test(n)) return { subnet: s, weight: 15 }; // healthcare

    // ── Low density (3-10): restricted/special purpose subnets ──
    if (/\b(guest|visitor|public|lobby|waiting|open)\b/.test(n)) return { subnet: s, weight: 5 };
    if (/\b(wireless|wifi|byod|mobile)\b/.test(n)) return { subnet: s, weight: 8 };
    if (/\b(dmz|external|perimeter)\b/.test(n)) return { subnet: s, weight: 2 };
    if (/\b(iot|scada|ot|hvac|camera|security|building)\b/.test(n)) return { subnet: s, weight: 3 };
    if (/\b(voice|voip|phone|telephony)\b/.test(n)) return { subnet: s, weight: 3 };
    if (/\b(printer|print)\b/.test(n)) return { subnet: s, weight: 2 };
    if (/\b(backup|storage|san|nas)\b/.test(n)) return { subnet: s, weight: 1 };

    // ── Default: moderate allocation for unrecognized subnets ──
    return { subnet: s, weight: 15 };
  });

  const totalWeight = subnetWeights.reduce((s, w) => s + w.weight, 0) || 1;

  // ── Determine preferred device types per subnet based on purpose ──
  // Each subnet gets a preference order: which device types belong here?
  // The system pulls from the available endpoint pool accordingly.
  const getSubnetDevicePrefs = (subnetName) => {
    const n = subnetName.toLowerCase();
    // Library public-access lab: rows of public computers (desktops) plus a
    // few catalog/self-check kiosks. Checked before the generic guest/public
    // rule (which is BYOD/mobile-only).
    if (/\b(public.?access|patron|public.?computer|public.?pc|public.?lab)\b/.test(n))
      return ['desktop', 'kiosk'];
    // Education
    if (/\b(student|classroom|lab|library|learning|academic)\b/.test(n))
      return ['desktop', 'kiosk', 'laptop']; // shared desktops, kiosks, some laptops
    if (/\b(faculty|teacher|staff)\b/.test(n))
      return ['laptop', 'desktop']; // teacher laptops, some desktops
    // Healthcare
    if (/\b(clinical|nursing|patient|ward|medical)\b/.test(n))
      return ['desktop', 'mobile', 'laptop']; // workstations, tablets, carts
    if (/\b(pharmacy|radiology|imaging)\b/.test(n))
      return ['desktop', 'kiosk'];
    // Manufacturing / Retail
    if (/\b(production|shop.?floor|warehouse|plant)\b/.test(n))
      return ['kiosk', 'desktop', 'mobile'];
    if (/\b(pos|point.of.sale|store|retail|sales.?floor)\b/.test(n))
      return ['kiosk', 'desktop'];
    // Office / Corporate
    if (/\b(admin|administration|executive|front.?desk|reception|office)\b/.test(n))
      return ['laptop', 'desktop'];
    if (/\b(engineering|development|r&d|research|design|dev)\b/.test(n))
      return ['laptop', 'desktop'];
    if (/\b(hr|human.resource|finance|accounting|legal|compliance)\b/.test(n))
      return ['laptop', 'desktop'];
    if (/\b(trading|operations|call.?center)\b/.test(n))
      return ['desktop', 'laptop'];
    // General user subnets
    if (/\b(staff|employee|corporate|workstation|user|internal)\b/.test(n))
      return ['laptop', 'desktop', 'mobile'];
    // Restricted
    if (/\b(guest|visitor|public|lobby)\b/.test(n))
      return ['mobile']; // guest = BYOD/mobile only
    if (/\b(wireless|wifi|byod)\b/.test(n))
      return ['mobile', 'laptop'];
    // Default
    return ['laptop', 'desktop'];
  };

  // Build remaining pool of each device type
  const devicePool = {};
  for (const q of assignmentQueue) {
    devicePool[q.type] = (devicePool[q.type] || 0) + q.count;
  }
  // Map for lookup
  const deviceInfo = {};
  for (const q of assignmentQueue) {
    if (!deviceInfo[q.type]) deviceInfo[q.type] = { os: q.os, fn: q.fn };
  }

  // Generate workstations per subnet, pulling from the device pool by preference
  wsAssets = [];
  let globalIdx = 0;

  // Sort subnets by weight descending so high-priority subnets get first pick
  const sortedWeights = [...subnetWeights].sort((a, b) => b.weight - a.weight);

  for (const sw of sortedWeights) {
    const subRange = sw.subnet.range || sw.subnet.cidr || '';
    const subnetBase = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
    const subnetName = (sw.subnet.name || '') + ' ' + (sw.subnet.purpose || '');
    const targetCount = Math.round((sw.weight / totalWeight) * endpointTotal);
    const prefs = getSubnetDevicePrefs(subnetName);

    let subnetAssigned = 0;

    // Pull devices in preference order
    for (const prefType of prefs) {
      if (subnetAssigned >= targetCount) break;
      const available = devicePool[prefType] || 0;
      if (available <= 0) continue;

      // How many of this type to assign? Proportional to remaining need
      const remaining = targetCount - subnetAssigned;
      const toAssign = Math.min(available, remaining);

      for (let i = 0; i < toAssign; i++) {
        const ipHost = 50 + subnetAssigned + i;
        const info = deviceInfo[prefType] || { os: 'Windows 11 Pro', fn: 'Workstation' };
        wsAssets.push({
          hostname: `ws-${String(globalIdx + 1).padStart(3, '0')}`,
          ip: subnetBase ? `${subnetBase}.${Math.min(ipHost, 254)}` : '',
          subnet: subRange,
          role: 'workstation',
          function: info.fn,
          os: info.os,
          _asset_type: prefType,
          critical: false
        });
        globalIdx++;
      }
      devicePool[prefType] -= toAssign;
      subnetAssigned += toAssign;
    }

    // If still need more and pool has remaining devices of any type, fill
    if (subnetAssigned < targetCount) {
      for (const type of Object.keys(devicePool)) {
        if (subnetAssigned >= targetCount) break;
        const available = devicePool[type] || 0;
        if (available <= 0) continue;
        const toAssign = Math.min(available, targetCount - subnetAssigned);
        for (let i = 0; i < toAssign; i++) {
          const ipHost = 50 + subnetAssigned + i;
          const info = deviceInfo[type] || { os: 'Windows 11 Pro', fn: 'Workstation' };
          wsAssets.push({
            hostname: `ws-${String(globalIdx + 1).padStart(3, '0')}`,
            ip: subnetBase ? `${subnetBase}.${Math.min(ipHost, 254)}` : '',
            subnet: subRange,
            role: 'workstation',
            function: info.fn,
            os: info.os,
            _asset_type: type,
            critical: false
          });
          globalIdx++;
        }
        devicePool[type] -= toAssign;
        subnetAssigned += toAssign;
      }
    }
  }

  // Any remaining devices that didn't fit (rounding) go to the largest subnet
  const remainingTotal = Object.values(devicePool).reduce((s, v) => s + v, 0);
  if (remainingTotal > 0 && sortedWeights.length > 0) {
    const bigSub = sortedWeights[0].subnet;
    const subRange = bigSub.range || bigSub.cidr || '';
    const subnetBase = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
    for (const type of Object.keys(devicePool)) {
      while (devicePool[type] > 0) {
        const info = deviceInfo[type] || { os: 'Windows 11 Pro', fn: 'Workstation' };
        wsAssets.push({
          hostname: `ws-${String(globalIdx + 1).padStart(3, '0')}`,
          ip: subnetBase ? `${subnetBase}.${Math.min(200 + (globalIdx % 54), 254)}` : '',
          subnet: subRange,
          role: 'workstation',
          function: info.fn,
          os: info.os,
          _asset_type: type,
          critical: false
        });
        globalIdx++;
        devicePool[type]--;
      }
    }
  }

  // Rebuild data.assets with the reconciled workstation list
  data.assets = [...nonWsAssets, ...wsAssets];
}

// ── Always clean up: remove workstations from infrastructure subnets ──
// This catches LLM-generated workstations that were placed in server/management ranges
{
  const infraSubnets = data.subnets.filter(s => {
    const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
    return /\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) &&
           !/\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n);
  });
  if (infraSubnets.length > 0) {
    const infraPrefixes = infraSubnets.map(s => {
      const r = s.range || s.cidr || '';
      return r.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
    }).filter(Boolean);

    const beforeCount = data.assets.length;
    data.assets = data.assets.filter(a => {
      if (a.role !== 'workstation') return true; // keep non-workstations
      if (!a.ip) return true; // keep if no IP to check
      const assetPrefix = a.ip.split('.').slice(0, 3).join('.');
      return !infraPrefixes.includes(assetPrefix); // remove if IP is in infra subnet
    });
    const removed = beforeCount - data.assets.length;
    if (removed > 0) {
      // Redistribute removed workstations to the largest eligible subnet
      const eligibleSubnets = data.subnets.filter(s => {
        const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
        return !/\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) ||
               /\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n);
      });
      if (eligibleSubnets.length > 0) {
        // Pick the first eligible subnet (typically the largest user subnet)
        const targetSub = eligibleSubnets[0];
        const subRange = targetSub.range || targetSub.cidr || '';
        const subBase = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
        for (let i = 0; i < removed; i++) {
          data.assets.push({
            hostname: `ws-relocated-${String(i + 1).padStart(3, '0')}`,
            ip: subBase ? `${subBase}.${Math.min(200 + i, 254)}` : '',
            subnet: subRange,
            role: 'workstation',
            function: 'Employee Desktop',
            os: 'Windows 11 Pro',
            _asset_type: 'desktop',
            critical: false
          });
        }
      }
    }
  }
}

// Enrich ALL assets with make/model/serial
for (const asset of data.assets) {
  const mm = assignMakeModel(asset);
  asset._make = mm.make;
  asset._model = mm.model;
  asset._serial = generateSerial(asset.hostname, mm.make, data.company_name);
}

// ─── Filter endpoint categories: remove zero-count entries ───
const filteredEndpoints = {};
for (const [key, val] of Object.entries(data.endpoints)) {
  if (val && val > 0) {
    filteredEndpoints[key] = val;
  }
}
data.endpoints = filteredEndpoints;

// ═══════════════════════════════════════════════════════════════════════════
// BUILD HTML DOCUMENT
// ═══════════════════════════════════════════════════════════════════════════

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Client Profile: ${esc(data.company_name)}</title>
  <style>
    /* ═══════════════════════════════════════════════════════════════════════
       CSS RESET & BASE STYLES
       ═══════════════════════════════════════════════════════════════════════ */
    * { margin: 0; padding: 0; box-sizing: border-box; }

    :root {
      --primary: #1a365d;
      --primary-light: #2c5282;
      --primary-lighter: #3182ce;
      --accent: #ed8936;
      --accent-dark: #c05621;
      --success: #38a169;
      --warning: #d69e2e;
      --danger: #e53e3e;
      --gray-50: #f8fafc;
      --gray-100: #f1f5f9;
      --gray-200: #e2e8f0;
      --gray-300: #cbd5e0;
      --gray-400: #a0aec0;
      --gray-500: #718096;
      --gray-600: #4a5568;
      --gray-700: #2d3748;
      --gray-800: #1a202c;
      --radius: 8px;
      --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }

    body {
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif;
      line-height: 1.6;
      color: var(--gray-700);
      background: var(--gray-100);
    }

    /* ═══════════════════════════════════════════════════════════════════════
       COVER PAGE
       ═══════════════════════════════════════════════════════════════════════ */
    .cover-page {
      min-height: 100vh;
      display: flex; flex-direction: column; justify-content: center; align-items: center;
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 50%, var(--primary-lighter) 100%);
      color: white; text-align: center; padding: 60px 40px;
      position: relative; overflow: hidden;
    }
    .cover-page::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
      background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
      opacity: 0.3;
    }
    .cover-content { position: relative; z-index: 1; max-width: 800px; }
    .cover-badge { display: inline-block; padding: 8px 24px; background: rgba(255,255,255,0.15); border-radius: 30px; font-size: 0.9em; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 30px; backdrop-filter: blur(4px); }
    .cover-title { font-size: 1.5em; font-weight: 300; letter-spacing: 4px; text-transform: uppercase; margin-bottom: 15px; opacity: 0.9; }
    .cover-company { font-size: 3.5em; font-weight: 700; margin: 20px 0; text-shadow: 0 4px 20px rgba(0,0,0,0.3); }
    .cover-industry { font-size: 1.5em; font-weight: 300; opacity: 0.9; margin-bottom: 10px; }
    .cover-location { font-size: 1.2em; opacity: 0.7; margin-bottom: 40px; }
    .cover-difficulty { display: inline-block; padding: 12px 30px; background: var(--accent); border-radius: 30px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 50px; box-shadow: 0 4px 15px rgba(237, 137, 54, 0.4); }
    .cover-meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-top: 40px; padding-top: 40px; border-top: 1px solid rgba(255,255,255,0.2); }
    .cover-meta-item { text-align: center; }
    .cover-meta-label { font-size: 0.8em; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }
    .cover-meta-value { font-size: 1.1em; font-weight: 600; }

    /* ═══════════════════════════════════════════════════════════════════════
       NAVIGATION & TABS
       ═══════════════════════════════════════════════════════════════════════ */
    .nav-wrapper { position: sticky; top: 0; z-index: 100; background: white; box-shadow: var(--shadow); }
    .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; }
    .nav-tabs { display: flex; overflow-x: auto; scrollbar-width: none; -ms-overflow-style: none; }
    .nav-tabs::-webkit-scrollbar { display: none; }
    .nav-tab { flex-shrink: 0; padding: 16px 24px; font-size: 0.95em; font-weight: 500; color: var(--gray-500); background: none; border: none; border-bottom: 3px solid transparent; cursor: pointer; transition: all 0.2s; white-space: nowrap; }
    .nav-tab:hover { color: var(--primary); background: var(--gray-50); }
    .nav-tab.active { color: var(--primary); border-bottom-color: var(--primary); font-weight: 600; }

    /* ═══════════════════════════════════════════════════════════════════════
       MAIN CONTENT
       ═══════════════════════════════════════════════════════════════════════ */
    .main-container { max-width: 1400px; margin: 0 auto; padding: 30px 20px; }
    .tab-panel { display: none; animation: fadeIn 0.3s ease; }
    .tab-panel.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* ═══════════════════════════════════════════════════════════════════════
       CARDS & SECTIONS
       ═══════════════════════════════════════════════════════════════════════ */
    .section { margin-bottom: 30px; }
    .section-header { display: flex; align-items: center; gap: 12px; padding: 16px 24px; background: linear-gradient(90deg, var(--primary), var(--primary-light)); color: white; border-radius: var(--radius) var(--radius) 0 0; font-size: 1.2em; font-weight: 600; }
    .section-header-icon { font-size: 1.3em; }
    .section-content { background: white; border: 1px solid var(--gray-200); border-top: none; border-radius: 0 0 var(--radius) var(--radius); padding: 24px; }
    .card { background: white; border: 1px solid var(--gray-200); border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow); }
    .card-header { padding: 16px 20px; background: var(--gray-50); border-bottom: 1px solid var(--gray-200); font-weight: 600; color: var(--gray-700); }
    .card-body { padding: 20px; }

    /* ═══════════════════════════════════════════════════════════════════════
       INFO GRID
       ═══════════════════════════════════════════════════════════════════════ */
    .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
    .info-item.wide { grid-column: span 2; }
    .info-grid-4 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .info-item { background: var(--gray-50); padding: 16px 20px; border-radius: var(--radius); border-left: 4px solid var(--primary); }
    .info-item.accent { border-left-color: var(--accent); }
    .info-item.success { border-left-color: var(--success); }
    .info-item.danger { border-left-color: var(--danger); }
    .info-label { font-size: 0.8em; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
    .info-value { font-size: 1.1em; font-weight: 600; color: var(--primary); }
    .info-value.mono { font-family: 'Consolas', 'Monaco', 'Courier New', monospace; }

    /* ═══════════════════════════════════════════════════════════════════════
       TABLES
       ═══════════════════════════════════════════════════════════════════════ */
    .table-wrapper { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.95em; }
    th { background: var(--primary); color: white; padding: 14px 16px; text-align: left; font-weight: 600; white-space: nowrap; }
    td { padding: 12px 16px; border-bottom: 1px solid var(--gray-200); vertical-align: top; }
    tr:nth-child(even) td { background: var(--gray-50); }
    tr:hover td { background: #edf2f7; }
    .table-mono td:nth-child(2) { font-family: 'Consolas', 'Monaco', monospace; color: var(--primary-lighter); }

    /* ═══════════════════════════════════════════════════════════════════════
       TAGS & BADGES
       ═══════════════════════════════════════════════════════════════════════ */
    .tag { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 500; margin: 2px; }
    .tag-default { background: var(--gray-200); color: var(--gray-700); }
    .tag-primary { background: #dbeafe; color: var(--primary); }
    .tag-success { background: #d1fae5; color: #065f46; }
    .tag-warning { background: #fef3c7; color: #92400e; }
    .tag-danger { background: #fee2e2; color: #991b1b; }
    .tag-purple { background: #ede9fe; color: #5b21b6; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }
    .badge-trust-high { background: #d1fae5; color: #065f46; }
    .badge-trust-medium { background: #fef3c7; color: #92400e; }
    .badge-trust-low { background: #fee2e2; color: #991b1b; }
    .badge-allow { background: #d1fae5; color: #065f46; }
    .badge-deny { background: #fee2e2; color: #991b1b; }

    /* ═══════════════════════════════════════════════════════════════════════
       STAKEHOLDER CARDS
       ═══════════════════════════════════════════════════════════════════════ */
    .stakeholder-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px; }
    .stakeholder-card { background: white; border-radius: var(--radius); border: 1px solid var(--gray-200); overflow: hidden; box-shadow: var(--shadow); transition: box-shadow 0.2s, transform 0.2s; }
    .stakeholder-card:hover { box-shadow: var(--shadow-lg); transform: translateY(-2px); }
    .stakeholder-header { padding: 20px; background: linear-gradient(135deg, var(--primary), var(--primary-light)); color: white; }
    .stakeholder-name { font-size: 1.3em; font-weight: 700; margin-bottom: 4px; }
    .stakeholder-role { color: var(--accent); font-weight: 600; font-size: 0.95em; }
    .stakeholder-dept { opacity: 0.8; font-size: 0.85em; margin-top: 4px; }
    .stakeholder-body { padding: 20px; }
    .stakeholder-detail { margin-bottom: 16px; }
    .stakeholder-detail-label { font-size: 0.8em; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
    .stakeholder-quote { font-style: italic; color: var(--gray-600); padding: 12px 16px; background: var(--gray-50); border-left: 3px solid var(--accent); margin-top: 16px; border-radius: 0 var(--radius) var(--radius) 0; }
    .stakeholder-quote::before { content: '"'; font-size: 1.5em; color: var(--accent); margin-right: 4px; }

    /* ═══════════════════════════════════════════════════════════════════════
       THREAT & SCENARIO CARDS
       ═══════════════════════════════════════════════════════════════════════ */
    .threat-card { background: white; border-radius: var(--radius); border: 1px solid var(--gray-200); border-left: 4px solid var(--danger); padding: 20px; margin-bottom: 20px; box-shadow: var(--shadow); }
    .threat-card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
    .threat-id { display: inline-block; padding: 4px 12px; background: var(--danger); color: white; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
    .threat-type { font-weight: 600; color: var(--gray-700); text-transform: capitalize; }
    .threat-title { font-size: 1.15em; font-weight: 600; color: var(--gray-800); margin-bottom: 12px; }
    .threat-detail { margin-bottom: 12px; }
    .threat-detail strong { color: var(--gray-600); font-size: 0.9em; }

    /* Legacy string-based attack path (horizontal arrows) */
    .attack-path { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 6px; }
    .attack-path-step { padding: 4px 10px; background: var(--gray-100); border-radius: 4px; font-family: monospace; font-size: 0.85em; }
    .attack-path-arrow { color: var(--danger); font-weight: bold; }

    /* ─── NEW: Structured kill-chain attack path (vertical steps) ─── */
    .kill-chain { margin-top: 12px; }
    .kill-chain-step { display: flex; gap: 12px; margin-bottom: 4px; }
    .kill-chain-num { width: 28px; height: 28px; border-radius: 50%; background: var(--danger); color: white; display: flex; align-items: center; justify-content: center; font-size: 0.8em; font-weight: 700; flex-shrink: 0; margin-top: 2px; }
    .kill-chain-body { flex: 1; }
    .kill-chain-action { font-weight: 500; color: var(--gray-700); margin-bottom: 4px; }
    .kill-chain-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 2px; }
    .kill-chain-meta code { font-size: 0.85em; }
    .kill-chain-detection { font-size: 0.85em; color: var(--gray-500); font-style: italic; }
    .kill-chain-connector { text-align: center; color: var(--danger); font-size: 1.2em; margin: 2px 0 2px 8px; }

    /* ─── NEW: Incident cards ─── */
    .incident-card { background: var(--gray-50); padding: 14px 18px; border-left: 4px solid var(--accent); border-radius: 0 var(--radius) var(--radius) 0; margin-bottom: 10px; }
    .incident-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .incident-type { font-weight: 600; color: var(--gray-700); text-transform: capitalize; }

    /* ═══════════════════════════════════════════════════════════════════════
       ARTIFACT CARDS
       ═══════════════════════════════════════════════════════════════════════ */
    .artifact-card { background: var(--gray-800); border-radius: var(--radius); overflow: hidden; margin-bottom: 16px; }
    .artifact-header { padding: 12px 16px; background: var(--gray-700); display: flex; justify-content: space-between; align-items: center; }
    .artifact-id { color: var(--accent); font-weight: 600; font-size: 0.9em; }
    .artifact-type { color: var(--gray-400); font-size: 0.85em; }
    .artifact-desc { padding: 12px 16px; color: var(--gray-400); font-size: 0.9em; border-bottom: 1px solid var(--gray-700); }
    .artifact-data { padding: 16px; color: #68d391; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.9em; white-space: pre-wrap; word-break: break-all; }

    /* ═══════════════════════════════════════════════════════════════════════
       NETWORK DIAGRAM
       ═══════════════════════════════════════════════════════════════════════ */
    .diagram-box { background: var(--gray-800); color: #68d391; padding: 24px; border-radius: var(--radius); font-family: 'Consolas', 'Monaco', monospace; font-size: 0.9em; white-space: pre-wrap; overflow-x: auto; line-height: 1.4; }

    /* ═══════════════════════════════════════════════════════════════════════
       LEARNING OBJECTIVES
       ═══════════════════════════════════════════════════════════════════════ */
    .nice-tag { display: inline-block; padding: 4px 10px; background: #7c3aed; color: white; border-radius: 4px; font-size: 0.8em; font-weight: 600; margin: 2px; }
    .learning-part { background: var(--gray-50); border-radius: var(--radius); padding: 20px; margin-bottom: 16px; }
    .learning-part-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .learning-part-title { font-weight: 600; color: var(--primary); }
    .learning-part-badge { padding: 4px 12px; background: var(--primary); color: white; border-radius: 4px; font-size: 0.8em; font-weight: 600; }

    /* ═══════════════════════════════════════════════════════════════════════
       SUMMARY STATS
       ═══════════════════════════════════════════════════════════════════════ */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }
    .stat-card { background: white; border-radius: var(--radius); padding: 20px; text-align: center; border: 1px solid var(--gray-200); box-shadow: var(--shadow); }
    .stat-value { font-size: 2em; font-weight: 700; color: var(--primary); margin-bottom: 4px; }
    .stat-label { font-size: 0.85em; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.5px; }

    /* ─── Interactive filter cards ─── */
    .filter-card { cursor: pointer; transition: all 0.2s ease; user-select: none; position: relative; }
    .filter-card:hover { border-color: var(--primary-lighter); transform: translateY(-2px); box-shadow: var(--shadow-lg); }
    .filter-card.active { border-color: var(--primary); background: linear-gradient(135deg, #ebf4ff, #dbeafe); }
    .filter-card.active .stat-value { color: var(--primary); }
    .filter-card.active .stat-label { color: var(--primary-light); font-weight: 600; }
    .filter-card.active::after { content: ''; position: absolute; bottom: 0; left: 20%; right: 20%; height: 3px; background: var(--primary); border-radius: 3px 3px 0 0; }

    /* ─── Sortable table headers ─── */
    .sortable-th { cursor: pointer; user-select: none; transition: background 0.15s; white-space: nowrap; }
    .sortable-th:hover { background: var(--primary-light); }
    .sortable-th .sort-icon { display: inline-block; margin-left: 6px; font-size: 0.75em; opacity: 0.4; transition: opacity 0.15s; }
    .sortable-th.sort-asc .sort-icon, .sortable-th.sort-desc .sort-icon { opacity: 1; }
    .ws-row { transition: opacity 0.2s ease; }
    .ws-row.hidden { display: none; }

    /* ═══════════════════════════════════════════════════════════════════════
       FOOTER & MISC
       ═══════════════════════════════════════════════════════════════════════ */
    .footer { text-align: center; padding: 40px 20px; background: var(--gray-800); color: var(--gray-400); margin-top: 40px; }
    .footer-title { color: white; font-size: 1.2em; font-weight: 600; margin-bottom: 10px; }
    .footer p { margin: 8px 0; font-size: 0.9em; }
    .confidential-banner { background: var(--danger); color: white; text-align: center; padding: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 2px; font-size: 0.85em; }

    /* ═══════════════════════════════════════════════════════════════════════
       PRINT & RESPONSIVE
       ═══════════════════════════════════════════════════════════════════════ */
    @media print {
      .nav-wrapper { display: none; }
      .cover-page { min-height: auto; page-break-after: always; }
      .tab-panel { display: block !important; page-break-before: always; }
      .tab-panel:first-of-type { page-break-before: avoid; }
      .section { page-break-inside: avoid; }
      body { background: white; }
    }
    @media (max-width: 768px) {
      .cover-company { font-size: 2em; }
      .cover-meta { grid-template-columns: 1fr; gap: 20px; }
      .stakeholder-grid { grid-template-columns: 1fr; }
      .info-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="confidential-banner">
    CONFIDENTIAL - FOR EDUCATIONAL PURPOSES ONLY - SIMULATED CLIENT PROFILE
  </div>

  <!-- ═════════════════════════════════════════════════════════════════════
       COVER PAGE
       ═════════════════════════════════════════════════════════════════════ -->
  <div class="cover-page">
    <div class="cover-content">
      <div class="cover-badge">${esc(data.client_type_name)}</div>
      <div class="cover-title">Client Profile Packet</div>
      <div class="cover-company">${esc(data.company_name)}</div>
      <div class="cover-industry">${esc(data.industry)}</div>
      <div class="cover-location">${esc(data.hq_city)}</div>
      <div class="cover-difficulty" style="background: ${getDifficultyColor(data.difficulty)}">
        ${esc(data.difficulty)} Difficulty
      </div>
      <div class="cover-meta">
        <div class="cover-meta-item">
          <div class="cover-meta-label">Profile ID</div>
          <div class="cover-meta-value">${esc(data.run_id)}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Generated</div>
          <div class="cover-meta-value">${formatDate(data.generated_at)}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Est. Time</div>
          <div class="cover-meta-value">${data.estimated_hours} Hours</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═════════════════════════════════════════════════════════════════════
       NAVIGATION
       ═════════════════════════════════════════════════════════════════════ -->
  <div class="nav-wrapper">
    <div class="nav-container">
      <div class="nav-tabs">
        <button class="nav-tab active" data-tab="overview">Overview</button>
        <button class="nav-tab" data-tab="governance">Governance</button>
        ${data.policies_present.length > 0 ? '<button class="nav-tab" data-tab="policies">Policies</button>' : ''}
        <button class="nav-tab" data-tab="stakeholders">Stakeholders</button>
        <button class="nav-tab" data-tab="it">IT Environment</button>
        <button class="nav-tab" data-tab="network">Network</button>
        <button class="nav-tab" data-tab="assets">Assets</button>
        ${data.firewall.rules && data.firewall.rules.length > 0 ? '<button class="nav-tab" data-tab="firewall">Firewall</button>' : ''}
        <button class="nav-tab" data-tab="threats">Threats</button>
      </div>
    </div>
  </div>

  <div class="main-container">
    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: OVERVIEW
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel active" id="tab-overview">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128202;</span>
          Executive Summary
        </div>
        <div class="section-content">
          <div class="stats-grid" style="margin-bottom: 30px;">
            <div class="stat-card">
              <div class="stat-value">${data.employees}</div>
              <div class="stat-label">Employees</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.stakeholders.length}</div>
              <div class="stat-label">Stakeholders</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.assets.length}</div>
              <div class="stat-label">Network Assets</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.subnets.length}</div>
              <div class="stat-label">Subnets</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.scenarios.length}</div>
              <div class="stat-label">Threat Scenarios</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.estimated_hours}h</div>
              <div class="stat-label">Est. Time</div>
            </div>
          </div>

          <div class="info-grid" style="margin-bottom: 24px;">
            <div class="info-item">
              <div class="info-label">Company Name</div>
              <div class="info-value">${esc(data.company_name)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Industry</div>
              <div class="info-value">${esc(data.industry)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">NAICS Code</div>
              <div class="info-value">${esc(data.naics)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Headquarters</div>
              <div class="info-value">${esc(data.hq_city)}</div>
            </div>
            <div class="info-item wide">
              <div class="info-label">Public Domain</div>
              <div class="info-value mono">${esc(data.domain)}</div>
            </div>
            <div class="info-item accent">
              <div class="info-label">Public IP</div>
              <div class="info-value mono">${esc(data.public_ip)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">IT Delivery Model</div>
              <div class="info-value">${esc(data.delivery)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Security Framework</div>
              <div class="info-value">${esc(data.framework)}</div>
            </div>
            ${data.annual_revenue_range ? `
            <div class="info-item accent">
              <div class="info-label">Annual Revenue</div>
              <div class="info-value">${esc(data.annual_revenue_range)}</div>
            </div>` : ''}
            ${data.growth_trajectory ? `
            <div class="info-item">
              <div class="info-label">Growth Trajectory</div>
              <div class="info-value">${esc(data.growth_trajectory)}</div>
            </div>` : ''}
          </div>

          <h4 style="margin: 24px 0 12px; color: var(--primary);">Business Model</h4>
          <p style="color: var(--gray-600); line-height: 1.7;">${esc(data.business_model)}</p>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 24px;">
            <div>
              <h4 style="margin-bottom: 12px; color: var(--primary);">Critical Services</h4>
              <div>${data.critical_services.map(s => '<span class="tag tag-danger">' + esc(s) + '</span>').join('') || '<span class="tag tag-default">None specified</span>'}</div>
            </div>
            <div>
              <h4 style="margin-bottom: 12px; color: var(--primary);">Key System Dependencies</h4>
              <div>${data.key_systems.map(s => '<span class="tag tag-primary">' + esc(s) + '</span>').join('') || '<span class="tag tag-default">None specified</span>'}</div>
            </div>
          </div>

          ${data.business_continuity ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Business Continuity</h4>
          <div class="info-grid info-grid-4">
            <div class="info-item danger">
              <div class="info-label">Recovery Point Objective</div>
              <div class="info-value">${data.business_continuity.rpo_hours || 'N/A'} hours</div>
            </div>
            <div class="info-item danger">
              <div class="info-label">Recovery Time Objective</div>
              <div class="info-value">${data.business_continuity.rto_hours || 'N/A'} hours</div>
            </div>
            <div class="info-item accent">
              <div class="info-label">Est. Downtime Cost</div>
              <div class="info-value">$${(data.business_continuity.estimated_downtime_cost_per_hour || 0).toLocaleString()}/hr</div>
            </div>
          </div>` : ''}

          ${Object.keys(data.departments).length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Department Breakdown</h4>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr><th>Department</th><th>Headcount</th><th>% of Total</th></tr>
              </thead>
              <tbody>
                ${Object.entries(data.departments).map(([dept, count]) => `
                  <tr>
                    <td>${esc(dept.replace(/_/g, ' / '))}</td>
                    <td><strong>${count}</strong></td>
                    <td>${data.employees > 0 ? ((count / data.employees) * 100).toFixed(1) : 0}%</td>
                  </tr>
                `).join('')}
                <tr style="background: var(--gray-200); font-weight: 600;">
                  <td>Total</td>
                  <td>${Object.values(data.departments).reduce((a, b) => a + b, 0)}</td>
                  <td>100%</td>
                </tr>
              </tbody>
            </table>
          </div>` : ''}

          ${data.past_incidents.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--accent);">Past Security Incidents</h4>
          ${data.past_incidents.map(inc => `
            <div class="incident-card">
              <div class="incident-header">
                <span class="incident-type">${esc(inc.type || 'Unknown')} (${inc.year || '?'})</span>
                <span class="tag ${getSeverityClass(inc.severity)}">${esc(inc.severity || 'Unknown')}</span>
              </div>
              <p style="font-size: 0.9em; color: var(--gray-600);">${esc(inc.outcome || '')}</p>
            </div>
          `).join('')}` : ''}

          <h4 style="margin: 24px 0 12px; color: var(--primary);">Known Industry Risks</h4>
          <div>${data.risks.map(r => '<span class="tag tag-warning">' + esc(r) + '</span>').join('') || '<span class="tag tag-default">None specified</span>'}</div>
        </div>
      </div>
    </div>

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: GOVERNANCE
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel" id="tab-governance">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128220;</span>
          Governance &amp; Compliance
        </div>
        <div class="section-content">
          <div class="info-grid" style="margin-bottom: 24px;">
            <div class="info-item">
              <div class="info-label">Security Framework</div>
              <div class="info-value">${esc(data.framework)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Policy Enforcement</div>
              <div class="info-value">${esc(data.policy_enforcement)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Risk Tolerance</div>
              <div class="info-value">${esc(data.risk_tolerance_overall)}</div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
            <div class="card">
              <div class="card-header" style="background: #d1fae5; color: #065f46;">Policies Present</div>
              <div class="card-body">
                ${data.policies_present.length > 0
                  ? data.policies_present.map(p => '<div style="padding: 8px 0; border-bottom: 1px solid var(--gray-100);">' + esc(p) + '</div>').join('')
                  : '<p style="color: var(--gray-500);">No policies documented</p>'}
              </div>
            </div>
            <div class="card">
              <div class="card-header" style="background: #fee2e2; color: #991b1b;">Missing Policies</div>
              <div class="card-body">
                ${data.policies_missing.length > 0
                  ? data.policies_missing.map(p => '<div style="padding: 8px 0; border-bottom: 1px solid var(--gray-100);">' + esc(p) + '</div>').join('')
                  : '<p style="color: var(--gray-500);">None identified</p>'}
              </div>
            </div>
          </div>

          ${data.regulatory_timeline ? `
          <h4 style="margin: 24px 0 12px; color: var(--accent);">Regulatory Timeline</h4>
          <div class="info-item accent" style="margin-bottom: 16px;">
            <div class="info-label">Upcoming Compliance Deadlines</div>
            <div class="info-value" style="font-size: 1em; font-weight: 500;">${esc(data.regulatory_timeline)}</div>
          </div>` : ''}

          ${data.compliance_focus.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Compliance Focus Areas</h4>
          <div>${data.compliance_focus.map(c => '<span class="tag tag-purple">' + esc(c) + '</span>').join('')}</div>
          ` : ''}
        </div>
      </div>
    </div>

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: POLICY DOCUMENTS
         ═════════════════════════════════════════════════════════════════════ -->
    ${data.policies_present.length > 0 ? `
    <div class="tab-panel" id="tab-policies">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128220;</span>
          Policy Documents (${data.policies_present.length})
        </div>
        <div class="section-content">
          <p style="margin-bottom: 20px; color: var(--gray-600);">
            The following policy documents are currently in place at ${esc(data.company_name)}.
            Each policy can be viewed on the student dashboard via the "View Policies" button.
          </p>
          <div style="display: grid; gap: 12px;">
            ${data.policies_present.map((policyName, i) => {
              const vMajor = i % 3 === 0 ? 2 : 1;
              const vMinor = [0, 1, 2, 0, 1][i % 5];
              const daysAgo = [0, 90, 180, 270, 45, 135, 365][i % 7];
              const effectiveDate = new Date(Date.now() - daysAgo * 86400000).toISOString().split('T')[0];
              return `
              <div style="border: 1px solid var(--gray-200); border-radius: 10px; overflow: hidden;">
                <div style="padding: 14px 18px; background: var(--gray-50); display: flex; align-items: center; gap: 12px;">
                  <span style="font-size: 1.2em;">📋</span>
                  <div style="flex: 1;">
                    <div style="font-weight: 600; color: var(--primary-darker);">${esc(policyName)}</div>
                    <div style="font-size: 0.82em; color: var(--gray-500);">Version ${vMajor}.${vMinor} &middot; Effective: ${effectiveDate} &middot; Classification: Internal</div>
                  </div>
                  <span class="tag tag-blue">Active</span>
                </div>
              </div>`;
            }).join('')}
          </div>

          ${data.policies_missing.length > 0 ? `
          <h4 style="margin: 28px 0 12px; color: var(--danger);">Missing Policies</h4>
          <div style="display: grid; gap: 8px;">
            ${data.policies_missing.map(p => `
              <div style="padding: 10px 16px; background: #fff5f5; border: 1px solid #fed7d7; border-radius: 8px; display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--danger);">⚠️</span>
                <span style="color: #742a2a; font-weight: 500;">${esc(p)}</span>
                <span class="tag tag-red" style="margin-left: auto;">Not Found</span>
              </div>
            `).join('')}
          </div>
          ` : ''}
        </div>
      </div>
    </div>
    ` : ''}

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: STAKEHOLDERS
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel" id="tab-stakeholders">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128101;</span>
          Key Stakeholders (${data.stakeholders.length} contacts)
        </div>
        <div class="section-content">
          <p style="margin-bottom: 24px; color: var(--gray-600);">
            The following individuals may be available for interviews during the assessment.
            Understanding their roles, concerns, and communication styles will help you gather
            relevant information and build rapport.
          </p>

          ${data.stakeholders.length > 0 ? `
          <div class="stakeholder-grid">
            ${data.stakeholders.map(s => `
              <div class="stakeholder-card">
                <div class="stakeholder-header">
                  <div class="stakeholder-name">${esc(s.name)}</div>
                  <div class="stakeholder-role">${esc(s.role)}</div>
                  ${s.department ? `<div class="stakeholder-dept">${esc(s.department)} Department</div>` : ''}
                </div>
                <div class="stakeholder-body">
                  ${s.email ? `
                  <div class="stakeholder-detail">
                    <div class="stakeholder-detail-label">Email</div>
                    <div style="font-family: monospace; color: var(--primary-lighter);">${esc(s.email)}</div>
                  </div>` : ''}

                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                    ${s.technical_fluency ? `
                    <div class="stakeholder-detail">
                      <div class="stakeholder-detail-label">Technical Fluency</div>
                      <div><span class="tag tag-primary">${esc(s.technical_fluency)}</span></div>
                    </div>` : ''}
                    ${s.decision_power ? `
                    <div class="stakeholder-detail">
                      <div class="stakeholder-detail-label">Decision Power</div>
                      <div><span class="tag tag-default">${esc(s.decision_power)}</span></div>
                    </div>` : ''}
                  </div>

                  ${s.communication_style ? `
                  <div class="stakeholder-detail">
                    <div class="stakeholder-detail-label">Communication Style</div>
                    <div style="color: var(--gray-600); font-size: 0.95em;">${esc(s.communication_style)}</div>
                  </div>` : ''}

                  ${s.concerns && s.concerns.length > 0 ? `
                  <div class="stakeholder-detail">
                    <div class="stakeholder-detail-label">Key Concerns</div>
                    <div>${s.concerns.map(c => '<span class="tag tag-warning">' + esc(c) + '</span>').join('')}</div>
                  </div>` : ''}

                  ${s.likely_pushback && s.likely_pushback.length > 0 ? `
                  <div class="stakeholder-detail">
                    <div class="stakeholder-detail-label">Likely Pushback</div>
                    <div>${s.likely_pushback.map(p => '<span class="tag tag-danger">' + esc(p) + '</span>').join('')}</div>
                  </div>` : ''}

                  ${s.information_they_can_provide && s.information_they_can_provide.length > 0 ? `
                  <div class="stakeholder-detail">
                    <div class="stakeholder-detail-label">Information They Can Provide</div>
                    <div>${s.information_they_can_provide.map(i => '<span class="tag tag-success">' + esc(i) + '</span>').join('')}</div>
                  </div>` : ''}

                  ${s.information_they_lack && s.information_they_lack.length > 0 ? `
                  <div class="stakeholder-detail">
                    <div class="stakeholder-detail-label">Information They Lack</div>
                    <div>${s.information_they_lack.map(i => '<span class="tag tag-default">' + esc(i) + '</span>').join('')}</div>
                  </div>` : ''}

                  ${s.signature_quote ? `
                  <div class="stakeholder-quote">${esc(s.signature_quote)}</div>` : ''}
                </div>
              </div>
            `).join('')}
          </div>
          ` : '<p style="color: var(--gray-500);">No stakeholders defined for this profile.</p>'}
        </div>
      </div>
    </div>

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: IT ENVIRONMENT
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel" id="tab-it">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128187;</span>
          IT Environment
        </div>
        <div class="section-content">
          <div class="info-grid" style="margin-bottom: 24px;">
            <div class="info-item">
              <div class="info-label">Delivery Model</div>
              <div class="info-value">${esc(data.delivery)}</div>
            </div>
          </div>

          ${Object.keys(data.endpoints).length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Endpoint Inventory</h4>
          <div class="info-grid info-grid-4">
            ${Object.entries(data.endpoints).map(([type, count]) => `
              <div class="info-item">
                <div class="info-label">${esc(type.replace(/_/g, ' '))}</div>
                <div class="info-value">${count}</div>
              </div>
            `).join('')}
            <div class="info-item" style="border-left: 3px solid var(--primary);">
              <div class="info-label">Total Endpoints</div>
              <div class="info-value" style="font-weight:700;">${Object.values(data.endpoints).reduce((a, b) => a + b, 0)}</div>
            </div>
          </div>` : ''}

          ${data.servers.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Servers</h4>
          <div class="table-wrapper">
            <table>
              <thead><tr><th>Hostname</th><th>Make / Model</th><th>Operating System</th><th>Role</th></tr></thead>
              <tbody>
                ${data.servers.map(s => {
                  // Match server to enriched asset for make/model
                  const matched = data.assets.find(a => a.hostname === s.hostname && a.role === 'server');
                  const make = matched?._make || '';
                  const model = matched?._model || '';
                  return `
                  <tr>
                    <td><code style="background: var(--gray-100); padding: 2px 8px; border-radius: 4px;">${esc(s.hostname)}</code></td>
                    <td>${make && model ? esc(make + ' ' + model) : '<span style="color:var(--gray-400);">N/A</span>'}</td>
                    <td>${esc(s.os)}</td>
                    <td>${esc(s.role)}</td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>` : ''}

          ${data.saas.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">SaaS Applications</h4>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Application</th>
                  <th>Category</th>
                  <th>SSO</th>
                  <th>MFA</th>
                  ${hasSaasDataSensitivity ? '<th>Data Sensitivity</th>' : ''}
                </tr>
              </thead>
              <tbody>
                ${data.saas.map(s => {
                  const app = typeof s === 'string' ? { name: s } : s;
                  return `
                    <tr>
                      <td><strong>${esc(app.name)}</strong></td>
                      <td>${esc(app.category || 'N/A')}</td>
                      <td>${app.sso_enabled ? '<span class="tag tag-success">Yes</span>' : '<span class="tag tag-danger">No</span>'}</td>
                      <td>${app.mfa ? '<span class="tag tag-success">Yes</span>' : '<span class="tag tag-danger">No</span>'}</td>
                      ${hasSaasDataSensitivity ? '<td><span class="tag ' + getSeverityClass(app.data_sensitivity) + '">' + esc(app.data_sensitivity || 'N/A') + '</span></td>' : ''}
                    </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>` : ''}

          ${Object.keys(data.endpoint_protection).length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Endpoint Protection</h4>
          <div style="margin-bottom: 8px; font-size: 0.8em; color: var(--gray-500);">
            <span style="display: inline-block; width: 10px; height: 10px; background: var(--success); border-radius: 2px; margin-right: 4px; vertical-align: middle;"></span> Secure
            &nbsp;&nbsp;
            <span style="display: inline-block; width: 10px; height: 10px; background: var(--danger); border-radius: 2px; margin-right: 4px; vertical-align: middle;"></span> Needs attention
          </div>
          <div class="info-grid info-grid-4">
            <div class="info-item">
              <div class="info-label">Product</div>
              <div class="info-value">${esc(data.endpoint_protection.product || 'N/A')}</div>
            </div>
            <div class="info-item ${data.endpoint_protection.managed ? 'success' : 'danger'}">
              <div class="info-label">Managed</div>
              <div class="info-value">${boolDisplay(data.endpoint_protection.managed)}</div>
            </div>
            <div class="info-item ${data.endpoint_protection.edr_enabled ? 'success' : 'danger'}">
              <div class="info-label">EDR Enabled</div>
              <div class="info-value">${boolDisplay(data.endpoint_protection.edr_enabled)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Coverage</div>
              <div class="info-value">${data.endpoint_protection.coverage_percent || 'N/A'}%</div>
            </div>
          </div>` : ''}

          ${Object.keys(data.patch_management).length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Patch Management</h4>
          <div class="info-grid">
            <div class="info-item">
              <div class="info-label">Method</div>
              <div class="info-value">${esc(data.patch_management.method || 'N/A')}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Frequency</div>
              <div class="info-value">${esc(data.patch_management.frequency || 'N/A')}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Compliance Rate</div>
              <div class="info-value">${data.patch_management.compliance_rate || 'N/A'}%</div>
            </div>
          </div>` : ''}

          ${Object.keys(data.remote_access).length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Remote Access</h4>
          <div style="margin-bottom: 8px; font-size: 0.8em; color: var(--gray-500);">
            <span style="display: inline-block; width: 10px; height: 10px; background: var(--success); border-radius: 2px; margin-right: 4px; vertical-align: middle;"></span> Secure configuration
            &nbsp;&nbsp;
            <span style="display: inline-block; width: 10px; height: 10px; background: var(--danger); border-radius: 2px; margin-right: 4px; vertical-align: middle;"></span> Needs attention
          </div>
          <div class="info-grid">
            <div class="info-item">
              <div class="info-label">VPN Solution</div>
              <div class="info-value">${esc(data.remote_access.vpn || 'None')}</div>
            </div>
            <div class="info-item ${data.remote_access.mfa && data.remote_access.mfa !== 'None' ? 'success' : 'danger'}">
              <div class="info-label">MFA</div>
              <div class="info-value">${esc(data.remote_access.mfa || 'None')}</div>
            </div>
            <div class="info-item ${data.remote_access.split_tunnel ? 'danger' : 'success'}">
              <div class="info-label">Split Tunnel</div>
              <div class="info-value">${data.remote_access.split_tunnel ? 'Yes' : 'No'}</div>
            </div>
          </div>` : ''}

          ${Object.keys(data.backups).length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Backup Strategy</h4>
          <div class="info-grid info-grid-4">
            <div class="info-item">
              <div class="info-label">Method</div>
              <div class="info-value">${esc(data.backups.method || 'N/A')}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Frequency</div>
              <div class="info-value">${esc(data.backups.frequency || 'N/A')}</div>
            </div>
            <div class="info-item ${data.backups.immutability ? 'success' : 'danger'}">
              <div class="info-label">Immutable</div>
              <div class="info-value">${boolDisplay(data.backups.immutability)}</div>
            </div>
            <div class="info-item ${data.backups.offsite ? 'success' : 'danger'}">
              <div class="info-label">Offsite</div>
              <div class="info-value">${boolDisplay(data.backups.offsite)}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Restore Tests</div>
              <div class="info-value">${esc(data.backups.restore_tests || 'N/A')}</div>
            </div>
          </div>` : ''}

          ${data.physical_security ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Physical Security</h4>
          <div class="info-grid info-grid-4">
            <div class="info-item ${data.physical_security.badge_access ? 'success' : 'danger'}">
              <div class="info-label">Badge Access</div>
              <div class="info-value">${boolDisplay(data.physical_security.badge_access)}</div>
            </div>
            <div class="info-item ${data.physical_security.cameras ? 'success' : 'danger'}">
              <div class="info-label">Cameras</div>
              <div class="info-value">${boolDisplay(data.physical_security.cameras)}</div>
            </div>
            <div class="info-item ${data.physical_security.server_room_locked ? 'success' : 'danger'}">
              <div class="info-label">Server Room Locked</div>
              <div class="info-value">${boolDisplay(data.physical_security.server_room_locked)}</div>
            </div>
            <div class="info-item ${data.physical_security.clean_desk_policy ? 'success' : ''}">
              <div class="info-label">Clean Desk Policy</div>
              <div class="info-value">${boolDisplay(data.physical_security.clean_desk_policy)}</div>
            </div>
            <div class="info-item ${data.physical_security.visitor_logging ? 'success' : 'danger'}">
              <div class="info-label">Visitor Logging</div>
              <div class="info-value">${boolDisplay(data.physical_security.visitor_logging)}</div>
            </div>
          </div>` : ''}

          ${data.vendor_risk.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Third-Party Vendor Risk</h4>
          <div class="table-wrapper">
            <table>
              <thead><tr><th>Vendor</th><th>Access Type</th><th>Data Shared</th><th>Last Assessment</th></tr></thead>
              <tbody>
                ${data.vendor_risk.map(v => `
                  <tr>
                    <td><strong>${esc(v.vendor)}</strong></td>
                    <td>${esc(v.access_type)}</td>
                    <td>${esc(v.data_shared)}</td>
                    <td>${v.last_assessment === 'Never' ? '<span class="tag tag-danger">Never</span>' : esc(v.last_assessment)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>` : ''}

          ${data.vendor_dependencies.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Vendor Dependencies</h4>
          <div>${data.vendor_dependencies.map(v => '<span class="tag tag-default">' + esc(v) + '</span>').join('')}</div>` : ''}

          ${data.known_unknowns.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--accent);">Known Unknowns (Ask About These)</h4>
          <div style="background: #fffbeb; border-left: 4px solid var(--accent); padding: 16px; border-radius: 0 var(--radius) var(--radius) 0;">
            <ul style="margin: 0; padding-left: 20px;">
              ${data.known_unknowns.map(k => '<li style="margin-bottom: 8px;">' + esc(k) + '</li>').join('')}
            </ul>
          </div>` : ''}
        </div>
      </div>
    </div>

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: NETWORK
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel" id="tab-network">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#127760;</span>
          Network Architecture
        </div>
        <div class="section-content">
          <div class="info-grid" style="margin-bottom: 24px;">
            <div class="info-item accent">
              <div class="info-label">Public IP Address</div>
              <div class="info-value mono">${esc(data.public_ip)}</div>
            </div>
            ${data.firewall.vendor ? `
            <div class="info-item">
              <div class="info-label">Firewall Vendor</div>
              <div class="info-value">${esc(data.firewall.vendor)}</div>
            </div>` : ''}
            ${data.firewall.vpn ? `
            <div class="info-item ${data.firewall.vpn.enabled ? 'success' : 'danger'}">
              <div class="info-label">VPN Enabled</div>
              <div class="info-value">${boolDisplay(data.firewall.vpn.enabled)}</div>
            </div>
            <div class="info-item ${data.firewall.vpn.mfa && data.firewall.vpn.mfa !== 'None' ? 'success' : 'danger'}">
              <div class="info-label">VPN MFA</div>
              <div class="info-value">${esc(data.firewall.vpn.mfa || 'None')}</div>
            </div>` : ''}
          </div>

          ${data.subnets.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Network Subnets</h4>
          <div class="table-wrapper">
            <table>
              <thead><tr><th>Subnet Name</th><th>CIDR</th><th>VLAN ID</th><th>Purpose</th><th>Trust Level</th></tr></thead>
              <tbody>
                ${data.subnets.map(s => `
                  <tr>
                    <td><strong>${esc(s.name)}</strong></td>
                    <td><code style="background: var(--gray-100); padding: 2px 8px; border-radius: 4px;">${esc(s.cidr)}</code></td>
                    <td>${s.vlan_id || 'N/A'}</td>
                    <td>${esc(s.purpose || 'N/A')}</td>
                    <td><span class="badge badge-trust-${(s.trust_level || 'medium').toLowerCase()}">${esc(s.trust_level || 'Medium')}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>` : ''}

          <h4 style="margin: 24px 0 12px; color: var(--primary);">Network Diagram</h4>
          <div style="background: white; border: 1px solid var(--gray-200); border-radius: var(--radius); padding: 20px; overflow-x: auto;">
            ${generateNetworkDiagram(data) || '<p style="color: var(--gray-400); text-align: center; padding: 40px;">Insufficient network data to generate diagram</p>'}
          </div>
        </div>
      </div>
    </div>

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: ASSETS
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel" id="tab-assets">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128421;</span>
          Asset Inventory (${data.assets.length} assets)
        </div>
        <div class="section-content">
          ${data.assets.length > 0 ? `
          <div class="stats-grid" style="margin-bottom: 24px;">
            <div class="stat-card">
              <div class="stat-value">${data.assets.filter(a => a.role === 'server').length}</div>
              <div class="stat-label">Servers</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.assets.filter(a => a.role === 'network').length}</div>
              <div class="stat-label">Network Devices</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.assets.filter(a => a.role === 'workstation').length}</div>
              <div class="stat-label">Workstations</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">${data.assets.filter(a => a.critical).length}</div>
              <div class="stat-label">Critical Assets</div>
            </div>
          </div>

          <div class="table-wrapper">
            <table class="table-mono">
              <thead><tr><th>Hostname</th><th>IP Address</th><th>Subnet</th><th>Role</th><th>Make / Model</th><th>OS</th><th>Function</th><th>Serial</th><th>Critical</th></tr></thead>
              <tbody>
                ${data.assets.filter(a => a.role !== 'workstation').map(a => `
                  <tr>
                    <td><strong>${esc(a.hostname)}</strong></td>
                    <td><code style="font-size:0.85em;">${esc(a.ip || 'N/A')}</code></td>
                    <td>${esc(a.subnet || 'N/A')}</td>
                    <td><span class="tag tag-${a.role === 'server' ? 'primary' : a.role === 'network' ? 'purple' : a.role === 'ot' ? 'warning' : 'default'}">${esc(a.role)}</span></td>
                    <td>${esc((a._make || '') + ' ' + (a._model || '')).trim() || 'N/A'}</td>
                    <td>${esc(a.os || 'N/A')}</td>
                    <td>${esc(a.function || 'N/A')}</td>
                    <td><code style="font-size:0.8em;">${esc(a._serial || 'N/A')}</code></td>
                    <td>${a.critical ? '<span class="tag tag-danger">Yes</span>' : 'No'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>

          ${data.assets.filter(a => a.role === 'workstation').length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Workstations (<span id="ws-visible-count">${data.assets.filter(a => a.role === 'workstation').length}</span> devices)</h4>

          <div class="stats-grid" style="margin-bottom: 16px;">
            <div class="stat-card filter-card active" data-filter="all" onclick="filterWorkstations('all', this)">
              <div class="stat-value">${data.assets.filter(a => a.role === 'workstation').length}</div>
              <div class="stat-label">All</div>
            </div>
            ${Object.entries(data.endpoints).map(([type, count]) => `
              <div class="stat-card filter-card" data-filter="${esc(type)}" onclick="filterWorkstations('${esc(type)}', this)">
                <div class="stat-value">${count}</div>
                <div class="stat-label">${esc(type.replace(/_/g, ' '))}</div>
              </div>
            `).join('')}
          </div>

          <div class="table-wrapper">
            <table class="table-mono" id="ws-table">
              <thead><tr>
                <th class="sortable-th" data-col="0" onclick="sortWsTable(0)">Hostname <span class="sort-icon">&#8597;</span></th>
                <th class="sortable-th" data-col="1" onclick="sortWsTable(1)">IP Address <span class="sort-icon">&#8597;</span></th>
                <th class="sortable-th" data-col="2" onclick="sortWsTable(2)">Make / Model <span class="sort-icon">&#8597;</span></th>
                <th class="sortable-th" data-col="3" onclick="sortWsTable(3)">OS <span class="sort-icon">&#8597;</span></th>
                <th class="sortable-th" data-col="4" onclick="sortWsTable(4)">Type <span class="sort-icon">&#8597;</span></th>
                <th>Serial</th>
              </tr></thead>
              <tbody id="ws-tbody">
                ${data.assets.filter(a => a.role === 'workstation').map(a => {
                  const typeLabel = a._asset_type === 'laptop' ? 'Laptop' : a._asset_type === 'desktop' ? 'Desktop' : a._asset_type === 'kiosk' ? 'Kiosk' : a._asset_type === 'mobile' ? 'Mobile' : 'Workstation';
                  // Map asset_type back to endpoint key for filtering
                  const filterKey = a._asset_type === 'laptop' && (a.os || '').includes('macOS') ? 'macos'
                    : a._asset_type === 'laptop' ? 'windows_laptops'
                    : a._asset_type === 'desktop' ? 'windows_desktops'
                    : a._asset_type === 'kiosk' ? 'shared_kiosks'
                    : a._asset_type === 'mobile' ? 'mobile'
                    : 'other';
                  return `
                  <tr class="ws-row" data-ws-type="${esc(filterKey)}">
                    <td><strong>${esc(a.hostname)}</strong></td>
                    <td><code style="font-size:0.85em;">${esc(a.ip || 'N/A')}</code></td>
                    <td>${esc((a._make || '') + ' ' + (a._model || '')).trim() || 'N/A'}</td>
                    <td>${esc(a.os || 'N/A')}</td>
                    <td><span class="tag tag-${a._asset_type === 'laptop' ? 'primary' : a._asset_type === 'desktop' ? 'default' : a._asset_type === 'kiosk' ? 'warning' : a._asset_type === 'mobile' ? 'purple' : 'default'}">${esc(typeLabel)}</span></td>
                    <td><code style="font-size:0.8em;">${esc(a._serial || 'N/A')}</code></td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
          ` : ''}
          ` : '<p style="color: var(--gray-500);">No assets defined for this profile.</p>'}
        </div>
      </div>

    </div>

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: FIREWALL RULES
         ═════════════════════════════════════════════════════════════════════ -->
    ${data.firewall.rules && data.firewall.rules.length > 0 ? `
    <div class="tab-panel" id="tab-firewall">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#128293;</span>
          Firewall ACL Rules (${data.firewall.rules.length + 1} rules)
        </div>
        <div class="section-content">
          <div class="info-grid" style="margin-bottom: 24px;">
            ${data.firewall.vendor ? `
            <div class="info-item">
              <div class="info-label">Firewall Vendor</div>
              <div class="info-value">${esc(data.firewall.vendor)}</div>
            </div>` : ''}
            <div class="info-item accent">
              <div class="info-label">Total Rules</div>
              <div class="info-value">${data.firewall.rules.length + 1} (incl. implicit deny)</div>
            </div>
            <div class="info-item success">
              <div class="info-label">Allow Rules</div>
              <div class="info-value">${data.firewall.rules.filter(r => r.action === 'Allow').length}</div>
            </div>
            <div class="info-item danger">
              <div class="info-label">Deny Rules</div>
              <div class="info-value">${data.firewall.rules.filter(r => r.action !== 'Allow').length + 1}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Logging Enabled</div>
              <div class="info-value">${data.firewall.rules.filter(r => r.logging).length} / ${data.firewall.rules.length}</div>
            </div>
          </div>

          <div class="table-wrapper">
            <table>
              <thead><tr><th>ID</th><th>Name</th><th>Source</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Action</th><th>Logging</th></tr></thead>
              <tbody>
                ${data.firewall.rules.map(r => `
                  <tr>
                    <td>${r.id}</td>
                    <td>${esc(r.name || 'Unnamed')}</td>
                    <td><code style="background: var(--gray-100); padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">${esc(r.src)}</code></td>
                    <td><code style="background: var(--gray-100); padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">${esc(r.dst)}</code></td>
                    <td>${esc(r.port)}</td>
                    <td>${esc(r.proto)}</td>
                    <td><span class="badge badge-${r.action === 'Allow' ? 'allow' : 'deny'}">${esc(r.action)}</span></td>
                    <td>${r.logging ? '<span class="tag tag-success">Yes</span>' : '<span class="tag tag-danger">No</span>'}</td>
                  </tr>
                `).join('')}
                <tr style="background: #fee2e2;">
                  <td>${data.firewall.rules.length + 1}</td>
                  <td><strong>Implicit Deny All</strong></td>
                  <td><code style="background: var(--gray-100); padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">Any</code></td>
                  <td><code style="background: var(--gray-100); padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">Any</code></td>
                  <td>Any</td>
                  <td>Any</td>
                  <td><span class="badge badge-deny">Deny</span></td>
                  <td><span class="tag tag-success">Yes</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    ` : ''}

    <!-- ═════════════════════════════════════════════════════════════════════
         TAB: THREATS (with upgraded attack path rendering)
         ═════════════════════════════════════════════════════════════════════ -->
    <div class="tab-panel" id="tab-threats">
      <div class="section">
        <div class="section-header">
          <span class="section-header-icon">&#9888;</span>
          Threat Profile
        </div>
        <div class="section-content">
          <h4 style="margin-bottom: 12px; color: var(--danger);">Top Threats for This Sector</h4>
          <div style="margin-bottom: 24px;">
            ${data.top_threats.map(t => '<span class="tag tag-danger">' + esc(typeof t === 'object' ? t.name || t : t) + '</span>').join('')}
          </div>

          ${data.scenarios.length > 0 ? `
          <h4 style="margin: 24px 0 12px; color: var(--primary);">Attack Scenarios</h4>
          ${data.scenarios.map(s => {
            const pathIsStructured = s.attack_path && s.attack_path.length > 0 && typeof s.attack_path[0] === 'object';
            return `
            <div class="threat-card">
              <div class="threat-card-header">
                <span class="threat-id">${esc(s.scenario_id || 'N/A')}</span>
                <span class="threat-type">${esc(s.type || 'Unknown')}</span>
              </div>
              <div class="threat-title">${esc(s.name || s.title || 'Threat Scenario')}</div>

              <div class="threat-detail">
                <strong>Threat Actor:</strong> ${esc(s.threat_actor || s.actor || 'Unknown')}
              </div>

              <div class="threat-detail">
                <strong>Initial Vector:</strong> ${esc(s.initial_vector || s.vector || 'Unknown')}
              </div>

              ${s.attack_path && s.attack_path.length > 0 ? `
              <div class="threat-detail">
                <strong>Attack Path:</strong>
                ${pathIsStructured ? `
                <div class="kill-chain">
                  ${s.attack_path.map((step, i) => renderAttackStep(step, i, s.attack_path.length)).join('')}
                </div>
                ` : `
                <div class="attack-path">
                  ${s.attack_path.map((step, i) => renderAttackStep(step, i, s.attack_path.length)).join('')}
                </div>
                `}
              </div>` : ''}

              ${s.impacted_assets && s.impacted_assets.length > 0 ? `
              <div class="threat-detail">
                <strong>Impacted Assets:</strong>
                <div style="margin-top: 6px;">
                  ${s.impacted_assets.map(a => '<code style="background: var(--gray-100); padding: 2px 8px; border-radius: 4px; margin-right: 6px;">' + esc(a) + '</code>').join('')}
                </div>
              </div>` : ''}

              <div class="threat-detail">
                <strong>Potential Impact:</strong> ${esc(s.potential_impact || s.impact || s.expected_impact || 'Business disruption')}
              </div>

              <div style="display: flex; gap: 16px; margin-top: 12px;">
                ${s.likelihood ? '<span class="tag tag-' + (s.likelihood === 'High' ? 'danger' : s.likelihood === 'Low' ? 'success' : 'warning') + '">Likelihood: ' + esc(s.likelihood) + '</span>' : ''}
                ${s.difficulty_to_detect ? '<span class="tag tag-default">Detection: ' + esc(s.difficulty_to_detect) + '</span>' : ''}
              </div>
            </div>`;
          }).join('')}
          ` : '<p style="color: var(--gray-500);">No specific threat scenarios defined.</p>'}
        </div>
      </div>
    </div>

  </div>

  <!-- ═════════════════════════════════════════════════════════════════════
       FOOTER
       ═════════════════════════════════════════════════════════════════════ -->
  <div class="footer">
    <div class="footer-title">Clinic-in-a-Box</div>
    <p><strong>Profile ID:</strong> ${esc(data.run_id)}</p>
    <p><strong>Generated:</strong> ${formatDate(data.generated_at)}</p>
    <p style="margin-top: 20px; opacity: 0.7;">
      This is a simulated organization profile generated for educational purposes.<br/>
      Part of the Clinic-in-a-Box Cyber Risk Assessment Training Program.
    </p>
  </div>

  <!-- ═════════════════════════════════════════════════════════════════════
       JAVASCRIPT - TAB NAVIGATION
       ═════════════════════════════════════════════════════════════════════ -->
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // ─── Tab Navigation ───
      const tabs = document.querySelectorAll('.nav-tab');
      const panels = document.querySelectorAll('.tab-panel');

      tabs.forEach(tab => {
        tab.addEventListener('click', function() {
          tabs.forEach(t => t.classList.remove('active'));
          panels.forEach(p => p.classList.remove('active'));

          this.classList.add('active');
          const panelId = 'tab-' + this.dataset.tab;
          const panel = document.getElementById(panelId);
          if (panel) {
            panel.classList.add('active');
          }
        });
      });
    });

    // ─── Workstation Filter ───
    function filterWorkstations(type, el) {
      const cards = document.querySelectorAll('.filter-card');
      cards.forEach(c => c.classList.remove('active'));
      el.classList.add('active');

      const rows = document.querySelectorAll('.ws-row');
      let visible = 0;
      rows.forEach(row => {
        if (type === 'all' || row.dataset.wsType === type) {
          row.classList.remove('hidden');
          visible++;
        } else {
          row.classList.add('hidden');
        }
      });

      const counter = document.getElementById('ws-visible-count');
      if (counter) counter.textContent = visible;
    }

    // ─── Workstation Table Sort ───
    let currentSortCol = -1;
    let sortAsc = true;

    function sortWsTable(colIndex) {
      const tbody = document.getElementById('ws-tbody');
      if (!tbody) return;

      // Toggle direction if same column, otherwise default ascending
      if (currentSortCol === colIndex) {
        sortAsc = !sortAsc;
      } else {
        sortAsc = true;
        currentSortCol = colIndex;
      }

      // Update header icons
      document.querySelectorAll('.sortable-th').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        th.querySelector('.sort-icon').innerHTML = '&#8597;';
      });
      const activeHeader = document.querySelector('.sortable-th[data-col="' + colIndex + '"]');
      if (activeHeader) {
        activeHeader.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
        activeHeader.querySelector('.sort-icon').innerHTML = sortAsc ? '&#9650;' : '&#9660;';
      }

      // Sort rows
      const rows = Array.from(tbody.querySelectorAll('.ws-row'));
      rows.sort((a, b) => {
        const aText = (a.cells[colIndex]?.textContent || '').trim().toLowerCase();
        const bText = (b.cells[colIndex]?.textContent || '').trim().toLowerCase();

        // IP address sorting: compare octets numerically
        if (colIndex === 1) {
          const aParts = aText.split('.').map(Number);
          const bParts = bText.split('.').map(Number);
          for (let i = 0; i < 4; i++) {
            if ((aParts[i] || 0) !== (bParts[i] || 0)) {
              return sortAsc ? (aParts[i] || 0) - (bParts[i] || 0) : (bParts[i] || 0) - (aParts[i] || 0);
            }
          }
          return 0;
        }

        // Default: alphabetical
        if (aText < bText) return sortAsc ? -1 : 1;
        if (aText > bText) return sortAsc ? 1 : -1;
        return 0;
      });

      rows.forEach(row => tbody.appendChild(row));
    }
  </script>
</body>
</html>`;

// ═══════════════════════════════════════════════════════════════════════════

  return html;

}

module.exports = { renderProfileHtml };
