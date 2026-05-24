/**
 * asset-register-generator.js
 *
 * Given an AI-generated profile, emits a realistic asset register the
 * instructor's answer-key can populate. Each row gets data classification,
 * CIA ratings, criticality tier, and owner — exactly what a senior assessor
 * would record in OCTAVE Allegro / NIST 800-30 asset characterization.
 *
 * Output → risk_assets table rows.
 */

// Asset templates by role/type with sensible CIA defaults
const ASSET_BLUEPRINTS = {
  // Server-side
  'Domain Controller':   { type: 'server', conf: 3, integ: 3, avail: 3, criticality: 1, dataClass: 'Restricted',  dataCats: ['Credentials', 'Identity'], containers: ['technical'] },
  'File Server':         { type: 'server', conf: 3, integ: 3, avail: 2, criticality: 1, dataClass: 'Confidential', dataCats: ['Operational'],          containers: ['technical'] },
  'Database Server':     { type: 'server', conf: 3, integ: 3, avail: 2, criticality: 1, dataClass: 'Confidential', dataCats: ['Customer Data'],        containers: ['technical'] },
  'Application Server':  { type: 'server', conf: 2, integ: 3, avail: 2, criticality: 2, dataClass: 'Confidential', dataCats: ['Operational'],          containers: ['technical'] },
  'Web / App Server':    { type: 'server', conf: 2, integ: 3, avail: 3, criticality: 2, dataClass: 'Confidential', dataCats: ['Customer Data'],        containers: ['technical'] },
  'Backup Server':       { type: 'server', conf: 3, integ: 3, avail: 2, criticality: 1, dataClass: 'Restricted',   dataCats: ['Backup Data'],          containers: ['technical', 'physical'] },
  'Remote Desktop Gateway': { type: 'server', conf: 2, integ: 2, avail: 2, criticality: 2, dataClass: 'Internal', dataCats: ['Authentication'],       containers: ['technical'] },
  'Secondary Domain Controller': { type: 'server', conf: 3, integ: 3, avail: 3, criticality: 1, dataClass: 'Restricted', dataCats: ['Credentials', 'Identity'], containers: ['technical'] },

  // Network gear
  'Perimeter Firewall':  { type: 'network_device', conf: 2, integ: 3, avail: 3, criticality: 1, dataClass: 'Internal', dataCats: ['Network Configuration'], containers: ['technical', 'physical'] },
  'Core Switch':         { type: 'network_device', conf: 1, integ: 2, avail: 3, criticality: 1, dataClass: 'Internal', dataCats: ['Network Configuration'], containers: ['technical', 'physical'] },
  'WiFi Access Point':   { type: 'network_device', conf: 1, integ: 2, avail: 2, criticality: 3, dataClass: 'Internal', dataCats: [],                       containers: ['technical', 'physical'] },

  // Endpoints (aggregate row, not per-device)
  'Workstation Fleet':   { type: 'workstation',    conf: 2, integ: 2, avail: 2, criticality: 2, dataClass: 'Confidential', dataCats: ['Email','Documents'], containers: ['technical', 'physical', 'people'] },
  'Laptop Fleet':        { type: 'workstation',    conf: 2, integ: 2, avail: 2, criticality: 2, dataClass: 'Confidential', dataCats: ['Email','Documents'], containers: ['technical', 'physical', 'people'] },
  'Mobile Device Fleet': { type: 'mobile',         conf: 2, integ: 1, avail: 1, criticality: 3, dataClass: 'Confidential', dataCats: ['Email'],            containers: ['physical', 'people'] }
};

// SaaS application templates (rows generated from declared SaaS apps)
const SAAS_BLUEPRINTS = {
  'CRM':         { conf: 3, integ: 3, avail: 2, criticality: 1, dataClass: 'Confidential', dataCats: ['Customer Data', 'PII'] },
  'Accounting':  { conf: 3, integ: 3, avail: 2, criticality: 1, dataClass: 'Restricted',   dataCats: ['Financial', 'PII'] },
  'Payroll':     { conf: 3, integ: 3, avail: 2, criticality: 1, dataClass: 'Restricted',   dataCats: ['PII', 'Financial'] },
  'Email':       { conf: 3, integ: 2, avail: 3, criticality: 1, dataClass: 'Confidential', dataCats: ['Communications'] },
  'File Storage':{ conf: 3, integ: 2, avail: 2, criticality: 2, dataClass: 'Confidential', dataCats: ['Documents'] },
  'Communications': { conf: 2, integ: 2, avail: 3, criticality: 2, dataClass: 'Internal',  dataCats: ['Communications'] },
  'HR':          { conf: 3, integ: 3, avail: 1, criticality: 2, dataClass: 'Restricted',   dataCats: ['PII'] },
  'default':     { conf: 2, integ: 2, avail: 1, criticality: 3, dataClass: 'Internal',     dataCats: [] }
};

// Map a server's role string to a known blueprint key (case-insensitive
// substring match).
function matchBlueprint(roleStr) {
  if (!roleStr) return null;
  const r = String(roleStr).toLowerCase();
  if (/(secondary).*(domain|dc)/.test(r) || /(dc-0[2-9])/i.test(roleStr)) return ASSET_BLUEPRINTS['Secondary Domain Controller'];
  if (/domain|active.?directory|ad.?server/.test(r)) return ASSET_BLUEPRINTS['Domain Controller'];
  if (/file.?server|fs[-_]|share/.test(r)) return ASSET_BLUEPRINTS['File Server'];
  if (/database|sql|db.?server/.test(r)) return ASSET_BLUEPRINTS['Database Server'];
  if (/web|http|app/.test(r) && !/^app/.test(r)) return ASSET_BLUEPRINTS['Web / App Server'];
  if (/application|app.?server/.test(r)) return ASSET_BLUEPRINTS['Application Server'];
  if (/backup|veeam|bak/.test(r)) return ASSET_BLUEPRINTS['Backup Server'];
  if (/rds|remote.?desktop|terminal/.test(r)) return ASSET_BLUEPRINTS['Remote Desktop Gateway'];
  return null;
}

/**
 * Generate the answer-key asset register for a profile.
 *
 * @param {object} ctx — unpacked profile context (org, it, network, stakeholders)
 * @returns {Array<object>} asset rows ready for INSERT
 */
function buildAssetRegister(ctx) {
  const org    = ctx.org   || {};
  const it     = ctx.it    || {};
  const net    = ctx.net   || {};
  const stake  = ctx.stakeholders || [];
  const assets = [];

  // Find the IT lead — they'll own most technical assets
  const itLead    = stake.find(s => /IT|CIO|CISO|Technology|System|Network/i.test(s.role || ''));
  const finance   = stake.find(s => /CFO|Finance|Accountant|Controller/i.test(s.role || ''));
  const exec      = stake.find(s => /CEO|Owner|President|Principal|Director/i.test(s.role || ''));
  const hr        = stake.find(s => /HR|People|Talent/i.test(s.role || ''));

  // 1. Servers from it.servers
  const servers = it.servers || [];
  for (const s of servers) {
    const tpl = matchBlueprint(s.role) || matchBlueprint(s.hostname) || ASSET_BLUEPRINTS['Application Server'];
    assets.push({
      name: s.hostname || s.role || 'unnamed-server',
      asset_type: tpl.type,
      owner_role: 'IT Manager',
      custodian: itLead?.name || 'IT Manager',
      confidentiality: tpl.conf,
      integrity: tpl.integ,
      availability: tpl.avail,
      criticality_tier: tpl.criticality,
      data_classification: tpl.dataClass,
      data_categories: tpl.dataCats || [],
      hostname: s.hostname || null,
      description: s.function || `${s.role || 'Server'} (${s.make || ''} ${s.model || ''}, ${s.os || ''}).`.trim(),
      containers: tpl.containers || ['technical']
    });
  }

  // 2. Perimeter firewall + core switch (always at least one of each)
  const fw = net.firewall || {};
  assets.push({
    name: 'Perimeter Firewall',
    asset_type: 'network_device',
    owner_role: 'IT Manager',
    custodian: itLead?.name || 'IT Manager',
    confidentiality: 2, integrity: 3, availability: 3,
    criticality_tier: 1,
    data_classification: 'Internal',
    data_categories: ['Network Configuration', 'Authentication Logs'],
    hostname: fw.model || 'fw-01',
    description: `${fw.vendor || 'Perimeter'} ${fw.model || 'firewall'} (${fw.firmware || 'firmware unknown'}). Single point of perimeter enforcement; loss = direct internet exposure of internal systems.`,
    containers: ['technical', 'physical']
  });
  assets.push({
    name: 'Core Switch',
    asset_type: 'network_device',
    owner_role: 'IT Manager',
    custodian: itLead?.name || 'IT Manager',
    confidentiality: 1, integrity: 2, availability: 3,
    criticality_tier: 1,
    data_classification: 'Internal',
    data_categories: ['Network Configuration'],
    hostname: 'sw-core-01',
    description: 'L2/L3 distribution switch. Loss of availability = LAN-wide outage.',
    containers: ['technical', 'physical']
  });

  // 3. Endpoint fleets (aggregate rows, not per-device)
  const ep = it.endpoints || {};
  const wsCount = (ep.windows_desktops || 0) + (ep.shared_kiosks || 0);
  const ltCount = (ep.windows_laptops || 0) + (ep.macos || 0);
  if (wsCount > 0) {
    const tpl = ASSET_BLUEPRINTS['Workstation Fleet'];
    assets.push({
      name: `Workstation Fleet (${wsCount} devices)`,
      asset_type: tpl.type, owner_role: 'IT Manager',
      custodian: itLead?.name || 'IT Manager',
      confidentiality: tpl.conf, integrity: tpl.integ, availability: tpl.avail,
      criticality_tier: tpl.criticality,
      data_classification: tpl.dataClass, data_categories: tpl.dataCats,
      description: `${wsCount} desktop workstations. Each holds local cached credentials and access to corporate systems via authenticated sessions.`,
      containers: tpl.containers
    });
  }
  if (ltCount > 0) {
    const tpl = ASSET_BLUEPRINTS['Laptop Fleet'];
    assets.push({
      name: `Laptop Fleet (${ltCount} devices)`,
      asset_type: tpl.type, owner_role: 'IT Manager',
      custodian: itLead?.name || 'IT Manager',
      confidentiality: tpl.conf, integrity: tpl.integ, availability: tpl.avail,
      criticality_tier: tpl.criticality,
      data_classification: tpl.dataClass, data_categories: tpl.dataCats,
      description: `${ltCount} laptops. Mobile devices that leave the perimeter — primary loss/theft risk.`,
      containers: tpl.containers
    });
  }
  if (ep.mobile > 0) {
    const tpl = ASSET_BLUEPRINTS['Mobile Device Fleet'];
    assets.push({
      name: `Mobile Device Fleet (${ep.mobile} devices)`,
      asset_type: tpl.type, owner_role: 'IT Manager',
      custodian: itLead?.name || 'IT Manager',
      confidentiality: tpl.conf, integrity: tpl.integ, availability: tpl.avail,
      criticality_tier: tpl.criticality,
      data_classification: tpl.dataClass, data_categories: tpl.dataCats,
      description: `${ep.mobile} corporate mobile devices. Hold email and SaaS app sessions.`,
      containers: tpl.containers
    });
  }

  // 4. SaaS applications
  const saas = it.saas || [];
  for (const app of saas) {
    const cat = (app.category || '').toLowerCase();
    let tpl = SAAS_BLUEPRINTS.default;
    for (const k of Object.keys(SAAS_BLUEPRINTS)) {
      if (cat.includes(k.toLowerCase())) { tpl = SAAS_BLUEPRINTS[k]; break; }
    }
    let owner = 'IT Manager';
    let custodian = itLead?.name || 'IT Manager';
    if (/account|payroll|financ/i.test(cat)) { owner = 'CFO'; custodian = finance?.name || 'CFO'; }
    else if (/hr|talent/i.test(cat)) { owner = 'HR Manager'; custodian = hr?.name || 'HR Manager'; }
    assets.push({
      name: app.name,
      asset_type: 'saas',
      owner_role: owner, custodian: custodian,
      confidentiality: tpl.conf, integrity: tpl.integ, availability: tpl.avail,
      criticality_tier: tpl.criticality,
      data_classification: tpl.dataClass, data_categories: tpl.dataCats,
      description: `${app.category || 'SaaS application'}. SSO=${app.sso_enabled ? 'Yes' : 'No'} · MFA=${app.mfa ? 'Yes' : 'No'} · Sensitivity=${app.data_sensitivity || 'Unknown'}.`,
      containers: ['technical']
    });
  }

  // 5. Information assets (people / process / data)
  if (exec) {
    assets.push({
      name: 'Executive Email + Approval Authority',
      asset_type: 'process',
      owner_role: 'CEO', custodian: exec.name,
      confidentiality: 3, integrity: 3, availability: 1,
      criticality_tier: 1,
      data_classification: 'Restricted',
      data_categories: ['Approval Authority', 'Strategic Communications'],
      description: `${exec.name}'s email + signing/approval authority. Primary target of business email compromise (BEC) attacks; loss of integrity = wire fraud potential.`,
      containers: ['technical', 'people']
    });
  }
  assets.push({
    name: 'Customer Records',
    asset_type: 'data_store',
    owner_role: 'CFO', custodian: finance?.name || exec?.name || 'CFO',
    confidentiality: 3, integrity: 3, availability: 2,
    criticality_tier: 1,
    data_classification: 'Restricted',
    data_categories: ['PII', 'Customer Data'],
    description: 'Customer records aggregated across CRM, finance, and operational systems. Subject to state breach-notification laws if disclosed.',
    containers: ['technical', 'people']
  });
  assets.push({
    name: 'Employee Records (PII)',
    asset_type: 'data_store',
    owner_role: 'HR Manager', custodian: hr?.name || 'HR Manager',
    confidentiality: 3, integrity: 2, availability: 1,
    criticality_tier: 2,
    data_classification: 'Restricted',
    data_categories: ['PII', 'Employment Records'],
    description: 'Employee personal information including SSN, payroll, benefits, performance reviews. Regulated under state PII statutes.',
    containers: ['technical', 'people']
  });

  return assets;
}

module.exports = { buildAssetRegister, ASSET_BLUEPRINTS, SAAS_BLUEPRINTS };
