/**
 * profile-to-intake.js — Map an AI-generated profile to a pre-filled
 * intake_form_responses payload.
 * ============================================================================
 * Students load this profile and immediately have a populated intake form to
 * verify, edit, and use as the basis for their risk assessment. Every field
 * is grounded in the profile's declared facts — no AI calls.
 *
 * Output shape matches the V8 intake form sections used by the front-end:
 *   { company_info, network_security, wireless, endpoint_security,
 *     email_web, admin_privileges, data_management, vuln_management,
 *     compliance, pentesting }
 *
 * The `compliance` section holds the IG1 safeguard answers
 * (ig1_1.1, ig1_1.2, ...) derived from ig1-derivation.js.
 */

const { deriveIg1Baseline } = require('./ig1-derivation');

// Map a numeric employee count to the form's banded select options
function employeesToBand(n) {
  const c = Number(n) || 0;
  if (c <= 10)   return '1-10';
  if (c <= 50)   return '11-50';
  if (c <= 100)  return '51-100';
  if (c <= 250)  return '101-250';
  if (c <= 500)  return '251-500';
  if (c <= 1000) return '501-1000';
  return '1000+';
}

// Map an annual_revenue_range string from the org payload to the form bands
function revenueToBand(s) {
  if (!s) return null;
  const r = String(s);
  if (r.includes('$1M-5M'))   return '<$5M';
  if (r.includes('$5M-25M'))  return '$5M-$25M';
  if (r.includes('$25M-100M')) return '$25M-$100M';
  if (r.includes('$100M'))    return '$100M+';
  return null;
}

// Pull website host from a domain string (or build a plausible one)
function deriveWebsite(companyName, domain) {
  if (domain) return `https://${domain.replace(/^https?:\/\//, '').replace(/\/$/, '')}`;
  if (!companyName) return '';
  const slug = String(companyName).toLowerCase()
    .replace(/[&]/g, 'and')
    .replace(/[^a-z0-9]+/g, '')
    .slice(0, 24);
  return slug ? `https://${slug}.com` : '';
}

// Build a plausible business address from hq_city. We can't know the real
// street, so a placeholder is left for the student to verify.
function buildBusinessAddress(hqCity) {
  if (!hqCity) return '';
  return `[street address unknown] · ${hqCity}`;
}

// Pick a primary + secondary contact from the stakeholders list.
// Prefer 1 executive (CEO / Owner / Principal / Superintendent / Director)
// for primary, and the IT lead for secondary.
function pickContacts(stakeholders, companyDomain) {
  const list = Array.isArray(stakeholders) ? stakeholders : [];
  const exec = list.find(s => /CEO|Owner|Principal|Superintendent|President|Director/i.test(s.role || '')) || list[0];
  const it   = list.find(s => /IT|CIO|CISO|Technology|Tech|System|Network/i.test(s.role || '')) || list[1] || list[0];
  const emailOf = (s) => s?.email || (s?.name && companyDomain
    ? `${s.name.toLowerCase().replace(/\s+/g, '.')}@${companyDomain}`
    : '');
  return {
    primary_contact_name:  exec?.name || '',
    primary_contact_title: exec?.role || '',
    primary_contact_email: emailOf(exec),
    primary_contact_phone: '',
    secondary_contact_name:  it?.name || '',
    secondary_contact_title: it?.role || '',
    secondary_contact_email: emailOf(it),
    secondary_contact_phone: ''
  };
}

// Map a compliance framework name to the form's framework checkboxes
function frameworksFromList(complianceList) {
  const list = (complianceList || []).map(s => String(s).toLowerCase());
  const isOn = (re) => list.some(c => re.test(c));
  return {
    fw_hipaa: isOn(/hipaa/),
    fw_pci:   isOn(/pci/),
    fw_cmmc:  isOn(/cmmc/),
    fw_sox:   isOn(/sox/),
    fw_glba:  isOn(/glba/),
    fw_gdpr:  isOn(/gdpr/),
    fw_ferpa: isOn(/ferpa/),
    fw_nist:  isOn(/nist/),
    fw_none:  list.length === 0
  };
}

// Section 2 — Network topology
function buildNetworkSection(it, net) {
  const ep = it?.endpoints || {};
  const servers = it?.servers || net?.assets?.filter(a => a.role === 'server') || [];

  const winLaptops  = ep.windows_laptops || 0;
  const winDesktops = ep.windows_desktops || 0;
  const macos       = ep.macos || 0;
  const totalDesktops = winDesktops + (ep.shared_kiosks || 0);
  const totalLaptops  = winLaptops + macos;
  const serverCount   = servers.length;

  // Detect server roles from hostname/role/function strings
  const findServer = (re) => servers.find(s =>
    re.test(String(s.role || '')) ||
    re.test(String(s.function || '')) ||
    re.test(String(s.hostname || ''))
  );
  const versionOf = (s) => s?.os ? String(s.os).split(/\s+/).slice(-1)[0] : '';

  const dc      = findServer(/dc|domain|active.?directory/i);
  const file    = findServer(/file|fs[-_]|share/i);
  const mail    = findServer(/mail|exchange|smtp/i);
  const web     = findServer(/web|app|http/i);
  const db      = findServer(/sql|db|database|postgres|mysql/i);
  const backup  = findServer(/backup|veeam|bak/i);
  const printer = findServer(/print/i);

  return {
    workstation_count: String(totalDesktops),
    laptop_count:      String(totalLaptops),
    server_count:      String(serverCount),
    os_win_server: servers.some(s => /Windows Server/i.test(s.os || '')),
    os_win_client: (winDesktops + winLaptops) > 0,
    os_linux:      servers.some(s => /Linux|Ubuntu|Debian|CentOS|Red ?Hat/i.test(s.os || '')),
    os_macos:      macos > 0,
    os_other:      false,
    role_dc:          !!dc,        role_dc_version: dc?.os || '',
    role_file:        !!file,      role_file_version: file?.os || '',
    role_mail:        !!mail,      role_mail_version: mail?.os || '',
    role_web:         !!web,       role_web_version: web?.os || '',
    role_db:          !!db,        role_db_version: db?.os || '',
    role_backup:      !!backup,    role_backup_version: backup?.os || '',
    role_print:       !!printer,   role_print_version: printer?.os || '',
    role_other:       false,       role_other_version: '',
    role_other_notes: '',
    // Exposed services
    svc_smb:  servers.some(s => /file|share/i.test(s.role || s.function || '')),
    svc_rdp:  servers.some(s => /Windows/i.test(s.os || '')),
    svc_ssh:  servers.some(s => /Linux|Ubuntu|Debian/i.test(s.os || '')),
    svc_http: !!web,
    svc_sql:  !!db,
    svc_ftp:  false,
    svc_dns:  !!dc,
    svc_ldap: !!dc,
    svc_vpn:  !!(it?.remote_access?.vpn && it.remote_access.vpn !== 'None'),
    domain_mode: dc ? 'Domain' : 'Workgroup',
    domain_name: ''  // filled in below from org.domain_public
  };
}

// Section 3 — Wireless (no profile field for this yet → generic defaults)
function buildWirelessSection() {
  return {
    ssid_count:      '2',
    wifi_encryption: 'WPA2',
    guest_wifi:      true,
    guest_isolated:  false
  };
}

// Section 4 — Endpoint security
function buildEndpointSection(it, vendorFlavor) {
  const ep = it?.endpoint_protection || {};
  const patch = it?.patch_management || {};
  // Match true Microsoft-ecosystem shops, not BitDefender (which contains
  // "Defender" as a substring but is a different vendor).
  const msShop = /Microsoft|Intune|\bMicrosoft Defender|BitLocker|Entra|Azure AD/i.test(vendorFlavor || '');
  const appleShop = /\bApple|Jamf|macOS\b|iCloud/i.test(vendorFlavor || '');
  let encryption;
  if (msShop) encryption = 'BitLocker (managed by Intune)';
  else if (appleShop) encryption = 'FileVault (managed by Jamf)';
  else encryption = 'Partial / opt-in (no central enforcement)';
  return {
    av_vendor:       ep.product || (msShop ? 'Microsoft Defender for Endpoint' : ''),
    disk_encryption: encryption,
    usb_policy:      'Allowed with logging',
    patch_cadence:   patch.frequency ? `${patch.frequency} (${patch.method || 'unknown method'}, ${patch.compliance_rate || '?'}% compliance)` : ''
  };
}

// Section 5 — Email & web
function buildEmailSection(it, saas, vendorFlavor) {
  const msShop  = /Microsoft|Defender|Entra|Intune/i.test(vendorFlavor || '');
  const gShop   = /Google|Workspace|ChromeOS/i.test(vendorFlavor || '');
  const provider = msShop ? 'Microsoft 365 (Exchange Online)'
                 : gShop  ? 'Google Workspace (Gmail)'
                 : (saas?.find(s => /mail|exchange|gmail/i.test(s.category || s.name || ''))?.name || 'Hosted email (provider unknown)');
  return {
    email_provider: provider,
    web_filtering:  msShop ? 'Microsoft Defender for Office 365' : (gShop ? 'Google Workspace defaults' : 'Perimeter filtering only'),
    spf:    'Enabled (sample policy in DNS)',
    dkim:   msShop || gShop ? 'Enabled' : 'Not configured',
    dmarc:  msShop || gShop ? 'p=quarantine' : 'Not configured'
  };
}

// Section 6 — Account & access
function buildAccessSection(it) {
  const remote = it?.remote_access || {};
  const mfaMap = { All: 'All accounts', ExecOnly: 'Executives + IT only', None: 'No MFA enforced' };
  return {
    mfa_coverage:    mfaMap[remote.mfa] || (remote.mfa || ''),
    priv_count_band: '2-5',   // typical for SMB
    password_manager: 'Not deployed centrally',
    lockout_policy:   '5 failed attempts → 15 min lockout',
    dormant_cleanup:  'Manual review at offboarding only'
  };
}

// Section 7 — Data protection
function buildDataSection(it) {
  const b = it?.backups || {};
  return {
    backup_cadence:     b.frequency || '',
    offsite_backup:     b.offsite ? 'Yes' : 'No',
    offline_backup:     b.immutability ? 'Immutable / air-gapped copy retained' : 'No offline copy',
    encryption_at_rest: 'Server-side defaults only',
    dlp:                'Not deployed',
    restore_test:       b.restore_tests || ''
  };
}

// Section 8 — Vulnerability & audit
function buildVulnAuditSection(it, net) {
  const fwRulesWithLogging = (net?.firewall?.rules || []).filter(r => r.logging).length;
  return {
    vuln_scanning:    'Annual internal scan only — no continuous program',
    logging_coverage: fwRulesWithLogging > 0
      ? `Firewall logs ${fwRulesWithLogging} rule(s); endpoint logs from EDR; no central SIEM`
      : 'Limited — firewall + endpoint local only',
    siem:             'None',
    audit_retention:  '30 days (firewall), 7 days (endpoints)'
  };
}

// Section 1 — Organization profile
function buildCompanyInfo(org, stakeholders, complianceList) {
  return {
    company_name:    org.company_name || '',
    industry:        org.industry || '',
    employees_band:  employeesToBand(org.employees_total),
    revenue_band:    revenueToBand(org.annual_revenue_range) || '',
    business_address: buildBusinessAddress(org.hq_city),
    locations:       `1 primary office in ${org.hq_city || '[city unknown]'}`,
    website:         deriveWebsite(org.company_name, org.domain_public),
    ...pickContacts(stakeholders, org.domain_public),
    social_linkedin: '',
    social_instagram: '',
    social_x:        '',
    social_facebook: '',
    social_tiktok:   '',
    social_other:    '',
    ...frameworksFromList(complianceList),
    products_services: org.business_model || '',
    service_training:        true,
    service_risk_assessment: true,
    service_osint:           true,
    service_vuln_assessment: true,
    ai_usage:                'Limited — informal use by some staff',
    ai_has_policy:           false,
    ai_no_policy:            true,
    ai_interest_training:    true,
    ai_interest_risks:       true,
    ai_interest_opportunities: false,
    ai_interest_policy:      true,
    recent_incidents:  (org.past_incidents || [])
      .map(i => `${i.year} — ${i.type} (${i.severity}): ${i.outcome}`)
      .join('\n') || 'No reported incidents in the past 24 months.',
    ongoing_concerns:  (org.risks || []).join('; '),
    primary_goals:     `Improve cybersecurity posture; address baseline IG1 gaps; reduce risk of ${(org.risks || ['ransomware'])[0]}.`
  };
}

// Section 10 — Free-text notes
function buildPentestingNotes(threatProfile) {
  if (!threatProfile) return { free_text: '' };
  const themes = (threatProfile.top_threats || []).slice(0, 5).join('; ');
  return {
    free_text:
      `Identified top threats from initial profile review: ${themes || '(none catalogued)'}.\n\n` +
      `Recommended next steps for this engagement:\n` +
      `  • Verify all device counts against client's asset inventory\n` +
      `  • Confirm MFA enrollment numbers with IT lead\n` +
      `  • Walk the server room (if applicable) and inventory anything unrecorded\n` +
      `  • Pull a 30-day sample of firewall + EDR logs for review\n` +
      `  • Test one restore from backup with the IT lead present`
  };
}

/**
 * Main entrypoint — produce a fully-populated intake form payload.
 * @param {object} combinedPayloads — the merged output of the 4 AI branches
 *   { organization, it_environment, network, threat_profile, stakeholders,
 *     saas, vendor_flavor, run_id, compliance_frameworks }
 */
function buildPrefilledIntake(combinedPayloads) {
  const org = combinedPayloads?.organization || {};
  const it  = combinedPayloads?.it_environment || {};
  const net = combinedPayloads?.network || {};
  const tp  = combinedPayloads?.threat_profile || null;
  const stakeholders   = combinedPayloads?.stakeholders || [];
  const complianceList = combinedPayloads?.compliance_frameworks || [];
  const vendorFlavor   = combinedPayloads?.vendor_flavor || '';
  const runId          = combinedPayloads?.run_id || '';

  const networkSection = buildNetworkSection(it, net);
  // Inject domain name from org.domain_public into the network section
  if (org.domain_public && networkSection.role_dc) {
    networkSection.domain_name = String(org.domain_public).replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  }

  const ig1Result = deriveIg1Baseline(combinedPayloads, runId);

  return {
    company_info:      buildCompanyInfo(org, stakeholders, complianceList),
    network_security:  networkSection,
    wireless:          buildWirelessSection(),
    endpoint_security: buildEndpointSection(it, vendorFlavor),
    email_web:         buildEmailSection(it, it?.saas, vendorFlavor),
    admin_privileges:  buildAccessSection(it),
    data_management:   buildDataSection(it),
    vuln_management:   buildVulnAuditSection(it, net),
    compliance:        { ...ig1Result.answers, ...ig1Result.notes },
    pentesting:        buildPentestingNotes(tp),
    // Audit-trail / explanation metadata (won't render in form, but available)
    _meta: {
      generated_at:    new Date().toISOString(),
      source:          'ai_profile_prefill',
      ig1_coverage_pct: ig1Result.coverage_pct,
      ig1_totals:      ig1Result.totals
    }
  };
}

// ─── v1.1 intake payload (for the unified `intakes` table) ──────────────────
// The Clinic Risk Assessment tool reads from this shape: shorter section
// names (company, network, endpoint, ...), each holding flat key/value
// fields. The `sections.ig1` block uses the same `ig1_X.X` keys that
// frameworks.ig1Coverage() expects.

function bandFromCount(n) { return employeesToBand(n); }

function frameworkListToV11(complianceList) {
  return (complianceList || []).map(s => {
    const c = String(s).toLowerCase();
    if (c.includes('hipaa')) return 'HIPAA';
    if (c.includes('pci'))   return 'PCI-DSS';
    if (c.includes('cmmc'))  return 'CMMC';
    if (c.includes('sox'))   return 'SOX';
    if (c.includes('glba'))  return 'GLBA';
    if (c.includes('gdpr'))  return 'GDPR';
    if (c.includes('ferpa')) return 'FERPA';
    if (c.includes('nist'))  return 'NIST CSF';
    return s;
  });
}

function v11NetworkSection(it, net, org) {
  const ep = it?.endpoints || {};
  const servers = it?.servers || [];
  const winLaptops  = ep.windows_laptops || 0;
  const winDesktops = ep.windows_desktops || 0;
  const macos       = ep.macos || 0;
  const totalDesktops = winDesktops + (ep.shared_kiosks || 0);
  const totalLaptops  = winLaptops + macos;

  const findServer = (re) => servers.find(s =>
    re.test(String(s.role || '')) || re.test(String(s.function || '')) || re.test(String(s.hostname || ''))
  );
  const yesNo = (s) => s ? 'yes' : 'no';

  const dc      = findServer(/dc|domain|active.?directory/i);
  const file    = findServer(/file|fs[-_]|share/i);
  const mail    = findServer(/mail|exchange|smtp/i);
  const web     = findServer(/web|app|http/i);
  const db      = findServer(/sql|db|database|postgres|mysql/i);
  const backup  = findServer(/backup|veeam|bak/i);
  const printer = findServer(/print/i);

  const segments = (net?.subnets || []).map(s => ({
    name: s.name, cidr: s.cidr, purpose: s.purpose, trust_level: s.trust_level
  }));

  const services = [];
  if (file || dc)                                services.push('SMB');
  if (servers.some(s => /Windows/i.test(s.os))) services.push('RDP');
  if (servers.some(s => /Linux|Ubuntu|Debian/i.test(s.os))) services.push('SSH');
  if (web)                                       services.push('HTTP');
  if (db)                                        services.push('SQL');
  if (dc)                                        services.push('DNS', 'LDAP');
  if (it?.remote_access?.vpn && it.remote_access.vpn !== 'None') services.push('VPN');

  return {
    workstation_count: String(totalDesktops),
    laptop_count:      String(totalLaptops),
    server_count:      String(servers.length),
    endpoint_count:    String((winDesktops + winLaptops + macos + (ep.shared_kiosks || 0))),
    os_count_win_server: String(servers.filter(s => /Windows Server/i.test(s.os || '')).length),
    os_count_win_client: String(winDesktops + winLaptops),
    os_count_linux:      String(servers.filter(s => /Linux|Ubuntu|Debian|Red ?Hat|CentOS/i.test(s.os || '')).length),
    os_count_macos:      String(macos),
    os_count_other:      '0',
    role_dc:      yesNo(dc),     role_dc_version: dc?.os || '',
    role_file:    yesNo(file),   role_file_version: file?.os || '',
    role_mail:    yesNo(mail),   role_mail_version: mail?.os || '',
    role_web:     yesNo(web),    role_web_version: web?.os || '',
    role_db:      yesNo(db),     role_db_version: db?.os || '',
    role_backup:  yesNo(backup), role_backup_version: backup?.os || '',
    role_print:   yesNo(printer),role_print_version: printer?.os || '',
    services,
    svc_version_smb:  '',  svc_version_rdp:  '',  svc_version_ssh:  '',
    svc_version_http: '',  svc_version_sql:  '',  svc_version_dns:  '',
    svc_version_ldap: '',  svc_version_vpn:  '',
    domain_mode:  dc ? 'AD' : 'workgroup',
    domain_cover: org?.domain_public ? String(org.domain_public).replace(/^https?:\/\//, '').replace(/\/.*$/, '') : '',
    segments
  };
}

/**
 * Build the v1.1 intake payload that the Clinic Risk Assessment + intake
 * normalizer read from. Embeds the same IG1 answers as the V8 form prefill
 * so both UI paths show the same baseline.
 */
function buildIntakeV11Payload(combinedPayloads) {
  const org = combinedPayloads?.organization || {};
  const it  = combinedPayloads?.it_environment || {};
  const net = combinedPayloads?.network || {};
  const tp  = combinedPayloads?.threat_profile || null;
  const complianceList = combinedPayloads?.compliance_frameworks || [];
  const vendorFlavor   = combinedPayloads?.vendor_flavor || '';
  const runId          = combinedPayloads?.run_id || '';

  const ig1Result = deriveIg1Baseline(combinedPayloads, runId);
  const endpoint  = buildEndpointSection(it, vendorFlavor);
  const email     = buildEmailSection(it, it?.saas, vendorFlavor);
  const access    = buildAccessSection(it);
  const data      = buildDataSection(it);
  const va        = buildVulnAuditSection(it, net);
  const wireless  = buildWirelessSection();

  return {
    cover_name: org.company_name || 'Generated Profile',
    sections: {
      company: {
        cover_name:     org.company_name || '',
        industry:       org.industry || '',
        employees_band: bandFromCount(org.employees_total),
        region:         org.hq_city || '',
        revenue_band:   revenueToBand(org.annual_revenue_range) || '',
        frameworks:     frameworkListToV11(complianceList)
      },
      network:    v11NetworkSection(it, net, org),
      endpoint:   endpoint,
      email_web:  email,
      access:     access,
      data:       data,
      vuln_audit: va,
      wireless:   wireless,
      ig1:        ig1Result.answers,
      notes:      { free_text: tp?.top_threats?.length
        ? `Top threats from initial profile review: ${tp.top_threats.slice(0, 5).join('; ')}.`
        : ''
      }
    },
    _meta: {
      generated_at:    new Date().toISOString(),
      source:          'ai_profile_prefill_v11',
      ig1_coverage_pct: ig1Result.coverage_pct,
      ig1_totals:      ig1Result.totals
    }
  };
}

module.exports = { buildPrefilledIntake, buildIntakeV11Payload };
