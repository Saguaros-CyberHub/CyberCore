/**
 * ai/profile/render.js — Render a generated profile to standalone HTML.
 * ============================================================================
 * Replaces the N8N "Professional Document Generator" node. Produces a
 * self-contained HTML page (inline CSS, no external assets) that the user
 * can open from `front-end/profiles/<filename>.html`. Renders the same data
 * the JSON file holds, but pretty.
 *
 * Sections rendered:
 *   - Cover (company name, industry, employees, run_id, generated_at)
 *   - Organization (description, breakdown, revenue, growth, BCP)
 *   - Governance & Policy (framework, policies present/missing, weaknesses)
 *   - Stakeholders (cards)
 *   - IT Environment (endpoints, servers, SaaS, backups, EDR, remote access)
 *   - Network (subnets table, asset inventory table, firewall summary)
 *   - Threat Profile (top threats, scenarios with attack paths)
 *
 * Pure function — no I/O. Caller writes the returned string to disk.
 */

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderProfileHtml(combined) {
  const sv = combined?.student_view || {};
  const threats = sv.raw?.threats || {};
  const org = threats.organization || {};
  const gov = threats.profiles?.governance_and_policy || {};
  const it = threats.it_environment || {};
  const network = threats.network || {};
  const tp = threats.threat_profile || {};
  const stakeholders = sv.stakeholders || [];
  const meta = sv.meta || {};

  const generatedAt = meta.generated_at
    ? new Date(meta.generated_at).toLocaleString()
    : new Date().toLocaleString();

  const title = `Client Profile: ${org.company_name || 'Generated Profile'}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
           line-height: 1.6; color: #2d3748; background: #f1f5f9; }
    .cover { min-height: 60vh; display: flex; flex-direction: column;
             justify-content: center; align-items: center; text-align: center;
             padding: 80px 40px; color: white;
             background: linear-gradient(135deg, #1a365d 0%, #2c5282 50%, #3182ce 100%); }
    .cover .badge { display: inline-block; padding: 6px 22px; background: rgba(255,255,255,0.15);
                    border-radius: 30px; font-size: 0.85em; letter-spacing: 2px;
                    text-transform: uppercase; margin-bottom: 24px; }
    .cover h1 { font-size: 2.6em; font-weight: 700; margin-bottom: 12px; }
    .cover .industry { font-size: 1.2em; opacity: 0.85; margin-bottom: 24px; }
    .cover .meta { display: flex; gap: 24px; flex-wrap: wrap; justify-content: center;
                   font-size: 0.9em; opacity: 0.85; }
    .cover .meta span { background: rgba(255,255,255,0.1); padding: 4px 12px; border-radius: 4px; }
    .container { max-width: 1000px; margin: -40px auto 0; padding: 0 24px 80px; }
    section.card { background: white; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                   padding: 32px; margin-bottom: 24px; }
    h2 { color: #1a365d; font-size: 1.5em; margin-bottom: 18px;
         border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
    h3 { color: #2c5282; font-size: 1.1em; margin: 20px 0 10px; }
    p { margin-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.92em; }
    th { background: #2c5282; color: white; padding: 10px 12px; text-align: left; font-weight: 600; }
    td { padding: 9px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) td { background: #f8fafc; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
    .stat { padding: 14px 18px; background: #f8fafc; border-left: 4px solid #3182ce; border-radius: 4px; }
    .stat .label { font-size: 0.78em; color: #718096; text-transform: uppercase; letter-spacing: 1px; }
    .stat .value { font-size: 1.4em; color: #1a365d; font-weight: 600; margin-top: 4px; }
    .pill { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.78em;
            background: #e2e8f0; color: #2d3748; margin: 2px 4px 2px 0; }
    .pill.warn { background: #fef3c7; color: #92400e; }
    .pill.danger { background: #fee2e2; color: #991b1b; }
    .stakeholder { padding: 14px 18px; background: #f8fafc; border-radius: 6px;
                   border-left: 3px solid #3182ce; margin-bottom: 12px; }
    .stakeholder .name { font-weight: 600; color: #1a365d; }
    .stakeholder .role { color: #718096; font-size: 0.9em; }
    .stakeholder .quote { font-style: italic; color: #4a5568; margin-top: 6px; font-size: 0.92em; }
    .scenario { padding: 14px 18px; background: #f8fafc; border-radius: 6px;
                border-left: 3px solid #d69e2e; margin-bottom: 14px; }
    .scenario .name { font-weight: 600; color: #1a365d; }
    .scenario .actor { color: #718096; font-size: 0.88em; margin-bottom: 6px; }
    .step { margin-left: 16px; padding: 4px 0; font-size: 0.9em; }
    .step .technique { display: inline-block; padding: 1px 6px; background: #1a365d; color: white;
                        font-size: 0.75em; border-radius: 3px; margin-right: 6px; font-family: monospace; }
    footer { text-align: center; padding: 30px; color: #718096; font-size: 0.85em; }
    .muted { color: #718096; }
  </style>
</head>
<body>
  <div class="cover">
    <div class="badge">CIAB Client Profile</div>
    <h1>${esc(org.company_name || 'Generated Profile')}</h1>
    <div class="industry">${esc(org.industry || 'Unknown Industry')}</div>
    <div class="meta">
      <span>${esc(org.employees_total || sv.quick?.employees_total || '?')} employees</span>
      <span>${esc(org.hq_city || 'Unknown location')}</span>
      <span>${esc(meta.client_type || 'SMB')}</span>
      <span>Difficulty: ${esc(meta.difficulty || 'intermediate')}</span>
    </div>
  </div>

  <div class="container">

    ${renderOrgSection(org)}
    ${renderGovernanceSection(gov)}
    ${renderStakeholdersSection(stakeholders)}
    ${renderItSection(it)}
    ${renderNetworkSection(network)}
    ${renderThreatSection(tp)}

  </div>

  <footer>
    Generated ${esc(generatedAt)} · run <code>${esc(meta.run_id || '?')}</code> · CIAB Profile Generator
  </footer>
</body>
</html>`;
}

function renderOrgSection(org) {
  if (!org || Object.keys(org).length === 0) return '';
  const bcp = org.business_continuity || {};
  return `<section class="card">
    <h2>Organization</h2>
    <p>${esc(org.business_model || '')}</p>
    <div class="grid" style="margin-top:14px">
      <div class="stat"><div class="label">Annual Revenue</div><div class="value">${esc(org.annual_revenue_range || '—')}</div></div>
      <div class="stat"><div class="label">Growth</div><div class="value">${esc((org.growth_trajectory || '—').split(' - ')[0])}</div></div>
      <div class="stat"><div class="label">RTO</div><div class="value">${esc(bcp.rto_hours || '—')}h</div></div>
      <div class="stat"><div class="label">RPO</div><div class="value">${esc(bcp.rpo_hours || '—')}h</div></div>
    </div>

    ${Array.isArray(org.critical_services) && org.critical_services.length ? `
    <h3>Critical Services</h3>
    <div>${org.critical_services.map(s => `<span class="pill">${esc(s)}</span>`).join('')}</div>` : ''}

    ${Array.isArray(org.past_incidents) && org.past_incidents.length ? `
    <h3>Past Incidents</h3>
    <table>
      <thead><tr><th>Year</th><th>Type</th><th>Severity</th><th>Outcome</th></tr></thead>
      <tbody>${org.past_incidents.map(i => `<tr>
        <td>${esc(i.year)}</td>
        <td>${esc(i.type)}</td>
        <td><span class="pill ${i.severity === 'Critical' ? 'danger' : i.severity === 'High' ? 'warn' : ''}">${esc(i.severity)}</span></td>
        <td>${esc(i.outcome)}</td>
      </tr>`).join('')}</tbody>
    </table>` : ''}

    ${org.regulatory_timeline ? `<h3>Regulatory Timeline</h3><p>${esc(org.regulatory_timeline)}</p>` : ''}
  </section>`;
}

function renderGovernanceSection(gov) {
  if (!gov || Object.keys(gov).length === 0) return '';
  return `<section class="card">
    <h2>Governance &amp; Policy</h2>
    <div class="grid">
      <div class="stat"><div class="label">Framework</div><div class="value" style="font-size:1.1em">${esc(gov.framework || '—')}</div></div>
      <div class="stat"><div class="label">Enforcement</div><div class="value" style="font-size:1.1em">${esc(gov.policy_enforcement || '—')}</div></div>
      <div class="stat"><div class="label">Risk Tolerance</div><div class="value" style="font-size:1.1em">${esc(gov.risk_tolerance || '—')}</div></div>
    </div>
    ${Array.isArray(gov.policies_present) ? `<h3>Policies Present (${gov.policies_present.length})</h3>
      <div>${gov.policies_present.map(p => `<span class="pill">${esc(p)}</span>`).join('')}</div>` : ''}
    ${Array.isArray(gov.policies_missing) && gov.policies_missing.length ? `<h3>Policies Missing</h3>
      <div>${gov.policies_missing.map(p => `<span class="pill warn">${esc(p)}</span>`).join('')}</div>` : ''}
  </section>`;
}

function renderStakeholdersSection(stakeholders) {
  if (!Array.isArray(stakeholders) || stakeholders.length === 0) return '';
  return `<section class="card">
    <h2>Stakeholders (${stakeholders.length})</h2>
    ${stakeholders.map(s => `<div class="stakeholder">
      <div class="name">${esc(s.name)} <span class="role">— ${esc(s.role)}${s.department ? ', ' + esc(s.department) : ''}</span></div>
      <div class="muted" style="font-size:0.88em">
        ${esc(s.email || '')} · Tech fluency: ${esc(s.technical_fluency)} · Decision power: ${esc(s.decision_power)}
      </div>
      ${s.persona?.signature_quote ? `<div class="quote">"${esc(s.persona.signature_quote)}"</div>` : ''}
    </div>`).join('')}
  </section>`;
}

function renderItSection(it) {
  if (!it || Object.keys(it).length === 0) return '';
  const ep = it.endpoints || {};
  const remote = it.remote_access || {};
  const backups = it.backups || {};
  const edr = it.endpoint_protection || {};
  return `<section class="card">
    <h2>IT Environment</h2>

    <h3>Endpoints (${(ep.windows_laptops||0)+(ep.windows_desktops||0)+(ep.macos||0)+(ep.mobile||0)+(ep.shared_kiosks||0)} total)</h3>
    <div class="grid">
      <div class="stat"><div class="label">Windows Laptops</div><div class="value">${esc(ep.windows_laptops || 0)}</div></div>
      <div class="stat"><div class="label">Windows Desktops</div><div class="value">${esc(ep.windows_desktops || 0)}</div></div>
      <div class="stat"><div class="label">macOS</div><div class="value">${esc(ep.macos || 0)}</div></div>
      <div class="stat"><div class="label">Mobile</div><div class="value">${esc(ep.mobile || 0)}</div></div>
    </div>

    ${Array.isArray(it.servers) && it.servers.length ? `<h3>Servers</h3>
    <table><thead><tr><th>Hostname</th><th>OS</th><th>Role</th></tr></thead>
      <tbody>${it.servers.map(s => `<tr><td><code>${esc(s.hostname)}</code></td><td>${esc(s.os)}</td><td>${esc(s.role)}</td></tr>`).join('')}</tbody>
    </table>` : ''}

    ${Array.isArray(it.saas) && it.saas.length ? `<h3>SaaS Applications</h3>
    <table><thead><tr><th>Name</th><th>Category</th><th>SSO</th><th>MFA</th><th>Data Sensitivity</th></tr></thead>
      <tbody>${it.saas.map(s => `<tr>
        <td>${esc(s.name)}</td><td>${esc(s.category)}</td>
        <td>${s.sso_enabled ? '✓' : '✗'}</td><td>${s.mfa ? '✓' : '✗'}</td>
        <td><span class="pill ${s.data_sensitivity === 'High' ? 'danger' : s.data_sensitivity === 'Medium' ? 'warn' : ''}">${esc(s.data_sensitivity)}</span></td>
      </tr>`).join('')}</tbody>
    </table>` : ''}

    <div class="grid" style="margin-top:14px">
      <div class="stat"><div class="label">Endpoint Protection</div><div class="value" style="font-size:1em">${esc(edr.product || '—')}</div></div>
      <div class="stat"><div class="label">VPN</div><div class="value" style="font-size:1em">${esc(remote.vpn || 'None')}</div></div>
      <div class="stat"><div class="label">MFA</div><div class="value" style="font-size:1em">${esc(remote.mfa || 'None')}</div></div>
      <div class="stat"><div class="label">Backups</div><div class="value" style="font-size:1em">${esc(backups.method || '—')} · ${esc(backups.frequency || '—')}</div></div>
    </div>
  </section>`;
}

function renderNetworkSection(net) {
  if (!net || Object.keys(net).length === 0) return '';
  const fw = net.firewall || {};
  return `<section class="card">
    <h2>Network</h2>
    <p><strong>Public IP:</strong> <code>${esc(net.public_ip || '—')}</code></p>

    ${Array.isArray(net.subnets) && net.subnets.length ? `<h3>Subnets</h3>
    <table><thead><tr><th>Name</th><th>CIDR</th><th>VLAN</th><th>Trust</th><th>Purpose</th></tr></thead>
      <tbody>${net.subnets.map(s => `<tr>
        <td>${esc(s.name)}</td><td><code>${esc(s.cidr)}</code></td>
        <td>${esc(s.vlan_id || '—')}</td><td>${esc(s.trust_level || '—')}</td>
        <td>${esc(s.purpose || '')}</td>
      </tr>`).join('')}</tbody>
    </table>` : ''}

    ${Array.isArray(net.assets) && net.assets.length ? `<h3>Asset Inventory (${net.assets.length})</h3>
    <table><thead><tr><th>Hostname</th><th>IP</th><th>Role</th><th>OS</th><th>Subnet</th></tr></thead>
      <tbody>${net.assets.slice(0, 50).map(a => `<tr>
        <td><code>${esc(a.hostname)}</code></td><td><code>${esc(a.ip)}</code></td>
        <td>${esc(a.role)}</td><td>${esc(a.os)}</td><td>${esc(a.subnet)}</td>
      </tr>`).join('')}</tbody>
    </table>
    ${net.assets.length > 50 ? `<p class="muted" style="font-size:0.85em">…and ${net.assets.length - 50} more (see JSON for full list)</p>` : ''}` : ''}

    ${fw.vendor ? `<h3>Firewall — ${esc(fw.vendor)} ${esc(fw.model || '')}</h3>
    <p class="muted">VPN: ${esc(fw.vpn?.type || 'Disabled')} · MFA: ${esc(fw.vpn?.mfa || 'None')} · Split tunnel: ${fw.vpn?.split_tunnel ? 'enabled' : 'disabled'} · Rules: ${(fw.rules || []).length}</p>` : ''}
  </section>`;
}

function renderThreatSection(tp) {
  if (!tp || Object.keys(tp).length === 0) return '';
  return `<section class="card">
    <h2>Threat Profile</h2>
    ${Array.isArray(tp.top_threats) && tp.top_threats.length ? `<h3>Top Threats</h3>
    <div>${tp.top_threats.map(t => `<span class="pill warn">${esc(t)}</span>`).join('')}</div>` : ''}

    ${Array.isArray(tp.scenarios) && tp.scenarios.length ? `<h3>Scenarios (${tp.scenarios.length})</h3>
    ${tp.scenarios.map(sc => `<div class="scenario">
      <div class="name">${esc(sc.name)} <span class="muted" style="font-weight:normal">(${esc(sc.scenario_id || '')})</span></div>
      <div class="actor">Actor: ${esc(sc.threat_actor || '—')} · Vector: ${esc(sc.initial_vector || '—')} · Likelihood: ${esc(sc.likelihood || '—')}</div>
      ${Array.isArray(sc.attack_path) ? sc.attack_path.map(step => `<div class="step">
        <strong>${esc(step.step)}.</strong>
        <span class="technique">${esc(step.technique)}</span>
        ${esc(step.action)} → <code>${esc(step.target)}</code>
      </div>`).join('') : ''}
      ${sc.potential_impact ? `<div class="muted" style="margin-top:8px;font-size:0.9em"><strong>Impact:</strong> ${esc(sc.potential_impact)}</div>` : ''}
    </div>`).join('')}` : ''}
  </section>`;
}

module.exports = { renderProfileHtml };
