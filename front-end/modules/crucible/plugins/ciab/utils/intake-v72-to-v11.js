/**
 * V7.2 (intake_form_responses, 15 JSONB columns) → canonical v1.2 payload.
 *
 * v1.2 is v1.1 (real-client schema) extended with the structured
 * consultant-engagement metadata that V7.2 collects (primary/secondary
 * contacts, AI policy, services requested, recent incidents, role versions,
 * etc.) so neither side loses data when the schemas merge.
 *
 * Pure function. No DB, no IO, no framework deps. Unit-testable.
 */

const SCHEMA_VERSION = '1.2';

const COMPLIANCE_FRAMEWORK_FLAGS = [
  ['fw_hipaa', 'HIPAA'], ['fw_pci', 'PCI-DSS'], ['fw_cmmc', 'CMMC'],
  ['fw_sox',   'SOX'],   ['fw_glba','GLBA'],    ['fw_gdpr', 'GDPR'],
  ['fw_ferpa', 'FERPA'], ['fw_nist','NIST'],    ['fw_none', 'NONE'],
];

const SERVICES_REQUESTED_FLAGS = [
  ['service_training',         'training'],
  ['service_risk_assessment',  'risk_assessment'],
  ['service_osint',            'osint'],
  ['service_vuln_assessment',  'vuln_assessment'],
];

const AI_INTEREST_FLAGS = [
  ['ai_interest_training',      'training'],
  ['ai_interest_risks',         'risks'],
  ['ai_interest_opportunities', 'opportunities'],
  ['ai_interest_policy',        'policy'],
];

const SERVICE_FLAGS = [
  ['svc_smb',  'SMB'],  ['svc_rdp',  'RDP'],  ['svc_ssh',  'SSH'],
  ['svc_http', 'HTTP'], ['svc_sql',  'SQL'],  ['svc_ftp',  'FTP'],
  ['svc_dns',  'DNS'],  ['svc_ldap', 'LDAP'], ['svc_vpn',  'VPN'],
];

function flagsToArray(src, flagMap) {
  if (!src || typeof src !== 'object') return [];
  return flagMap.filter(([k]) => isTrue(src[k])).map(([, v]) => v);
}

function isTrue(v) {
  if (v === true || v === 1) return true;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    return s === 'true' || s === 'yes' || s === '1' || s === 'on';
  }
  return false;
}

function pickStr(...vals) {
  for (const v of vals) {
    if (v == null) continue;
    const s = String(v).trim();
    if (s !== '') return s;
  }
  return null;
}

function pickInt(...vals) {
  for (const v of vals) {
    if (v == null || v === '') continue;
    const n = parseInt(v, 10);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

/**
 * Convert one row from intake_form_responses (V7.2 shape) to a canonical
 * v1.2 payload object suitable for `intakes.payload`.
 *
 * @param {object} row — full row from intake_form_responses (camelCase or snake_case both fine)
 * @returns {{ schema_version, cover_name, sections: object, _audit: object }}
 */
function convertV72ToV12(row) {
  const r = row || {};
  const company_info     = r.company_info     || {};
  const network_security = r.network_security || {};
  const network_devices  = r.network_devices  || {};
  const network_ports    = r.network_ports    || {};
  const wireless_in      = r.wireless         || {};
  const endpoint_in      = r.endpoint_security|| {};
  const email_web_in     = r.email_web        || {};
  const access_in        = r.admin_privileges || {};
  const data_in          = r.data_management  || {};
  const vuln_in          = r.vuln_management  || {};
  const compliance_in    = r.compliance       || {};
  const security_policies = r.security_policies || {};
  const software_assets   = r.software_assets   || {};
  const secure_config     = r.secure_config     || {};
  const pentesting        = r.pentesting        || {};

  // === company (v1.1 baseline + V7.2 extras under namespaced groups) ===
  const cover_name =
    pickStr(company_info.company_name, r.cover_name) || 'Unknown Organization';

  const company = {
    cover_name,
    industry:        pickStr(company_info.industry),
    employees_band:  pickStr(company_info.employees_band),
    revenue_band:    pickStr(company_info.revenue_band),
    frameworks:      flagsToArray(company_info, COMPLIANCE_FRAMEWORK_FLAGS),
    region:          pickStr(company_info.region),  // v1.1 — not in V7.2
    // v1.2 extensions
    business_address: pickStr(company_info.business_address),
    locations:        pickStr(company_info.locations),
    website:          pickStr(company_info.website),
    primary_contact: {
      name:   pickStr(company_info.primary_contact_name),
      title:  pickStr(company_info.primary_contact_title),
      email:  pickStr(company_info.primary_contact_email),
      phone:  pickStr(company_info.primary_contact_phone),
    },
    secondary_contact: {
      name:   pickStr(company_info.secondary_contact_name),
      title:  pickStr(company_info.secondary_contact_title),
      email:  pickStr(company_info.secondary_contact_email),
      phone:  pickStr(company_info.secondary_contact_phone),
    },
    social: {
      linkedin:  pickStr(company_info.social_linkedin),
      instagram: pickStr(company_info.social_instagram),
      x:         pickStr(company_info.social_x),
      facebook:  pickStr(company_info.social_facebook),
      tiktok:    pickStr(company_info.social_tiktok),
      other:     pickStr(company_info.social_other),
    },
    services_requested: flagsToArray(company_info, SERVICES_REQUESTED_FLAGS),
    ai_usage:           pickStr(company_info.ai_usage),
    ai_has_policy:      isTrue(company_info.ai_has_policy),
    ai_interests:       flagsToArray(company_info, AI_INTEREST_FLAGS),
    products_services:  pickStr(company_info.products_services),
    recent_incidents:   pickStr(company_info.recent_incidents),
    ongoing_concerns:   pickStr(company_info.ongoing_concerns),
    primary_goals:      pickStr(company_info.primary_goals),
  };

  // === network (consolidate network_security + network_devices + network_ports) ===
  // V7.2 used split workstation_count + laptop_count; v1.1+ uses endpoint_count.
  const ws = pickInt(network_security.workstation_count) || 0;
  const lt = pickInt(network_security.laptop_count) || 0;
  const endpoint_count = (ws + lt) > 0
    ? (ws + lt)
    : pickInt(network_security.endpoint_count, network_devices.endpoint_count);

  // V7.2: os_win_server etc. v1.1: os_count_win_server etc. Renaming.
  const network = {
    endpoint_count,
    server_count: pickInt(network_security.server_count, network_devices.server_count),
    os_count_win_server: pickInt(network_security.os_win_server) || 0,
    os_count_win_client: pickInt(network_security.os_win_client) || 0,
    os_count_linux:      pickInt(network_security.os_linux) || 0,
    os_count_macos:      pickInt(network_security.os_macos) || 0,
    os_count_other:      pickInt(network_security.os_other) || 0,
    role_dc:     pickStr(network_security.role_dc),
    role_file:   pickStr(network_security.role_file),
    role_mail:   pickStr(network_security.role_mail),
    role_web:    pickStr(network_security.role_web),
    role_db:     pickStr(network_security.role_db),
    role_backup: pickStr(network_security.role_backup),
    role_print:  pickStr(network_security.role_print),
    role_other:  pickStr(network_security.role_other),
    // v1.2 extension: per-role version strings (V7.2 captures these).
    role_dc_version:     pickStr(network_security.role_dc_version),
    role_file_version:   pickStr(network_security.role_file_version),
    role_mail_version:   pickStr(network_security.role_mail_version),
    role_web_version:    pickStr(network_security.role_web_version),
    role_db_version:     pickStr(network_security.role_db_version),
    role_backup_version: pickStr(network_security.role_backup_version),
    role_print_version:  pickStr(network_security.role_print_version),
    role_other_version:  pickStr(network_security.role_other_version),
    role_other_notes:    pickStr(network_security.role_other_notes),
    services: flagsToArray(network_security, SERVICE_FLAGS),
    domain_mode: pickStr(network_security.domain_mode),
    domain_name: pickStr(network_security.domain_name),  // v1.2 extension
  };

  // === wireless (direct rename) ===
  const wireless = {
    ssid_count:      pickInt(wireless_in.ssid_count),
    wifi_encryption: pickStr(wireless_in.wifi_encryption),
    guest_wifi:      pickStr(wireless_in.guest_wifi),
    guest_isolated:  pickStr(wireless_in.guest_isolated),
  };

  // === endpoint (rename: endpoint_security → endpoint) ===
  const endpoint = {
    av_vendor:        pickStr(endpoint_in.av_vendor),
    disk_encryption:  pickStr(endpoint_in.disk_encryption),
    usb_policy:       pickStr(endpoint_in.usb_policy),
    patch_cadence:    pickStr(endpoint_in.patch_cadence),
  };

  // === email_web (direct) ===
  const email_web = {
    email_provider: pickStr(email_web_in.email_provider),
    web_filtering:  pickStr(email_web_in.web_filtering),
    spf:            pickStr(email_web_in.spf),
    dkim:           pickStr(email_web_in.dkim),
    dmarc:          pickStr(email_web_in.dmarc),
  };

  // === access (rename: admin_privileges → access) ===
  const access = {
    mfa_coverage:     pickStr(access_in.mfa_coverage),
    priv_count_band:  pickStr(access_in.priv_count_band),
    password_manager: pickStr(access_in.password_manager),
    lockout_policy:   pickStr(access_in.lockout_policy),
    dormant_cleanup:  pickStr(access_in.dormant_cleanup),
  };

  // === data (rename: data_management → data) ===
  const data = {
    backup_cadence:      pickStr(data_in.backup_cadence),
    offsite_backup:      pickStr(data_in.offsite_backup),
    offline_backup:      pickStr(data_in.offline_backup),
    encryption_at_rest:  pickStr(data_in.encryption_at_rest),
    dlp:                 pickStr(data_in.dlp),
    restore_test:        pickStr(data_in.restore_test),
  };

  // === vuln_audit (rename: vuln_management → vuln_audit) ===
  const vuln_audit = {
    vuln_scanning:    pickStr(vuln_in.vuln_scanning),
    logging_coverage: pickStr(vuln_in.logging_coverage),
    siem:             pickStr(vuln_in.siem),
    audit_retention:  pickStr(vuln_in.audit_retention),
  };

  // === ig1 (already structurally compatible — direct copy) ===
  const ig1 = compliance_in && Object.keys(compliance_in).length > 0
    ? compliance_in
    : {};

  // === notes (free text + structured fold-in of legacy V7.2 sections) ===
  const legacyParts = [];
  if (pentesting.free_text)  legacyParts.push(pentesting.free_text);
  if (Object.keys(security_policies).length > 0) {
    legacyParts.push('--- Security Policies (legacy) ---\n' + JSON.stringify(security_policies, null, 2));
  }
  if (Object.keys(software_assets).length > 0) {
    legacyParts.push('--- Software Assets (legacy) ---\n' + JSON.stringify(software_assets, null, 2));
  }
  if (Object.keys(secure_config).length > 0) {
    legacyParts.push('--- Secure Configuration (legacy) ---\n' + JSON.stringify(secure_config, null, 2));
  }
  if (Object.keys(network_ports).length > 0) {
    legacyParts.push('--- Network Ports (legacy) ---\n' + JSON.stringify(network_ports, null, 2));
  }
  if (Object.keys(network_devices).length > 0 && network_devices !== network_security) {
    legacyParts.push('--- Network Devices (legacy) ---\n' + JSON.stringify(network_devices, null, 2));
  }
  if (r.additional_notes) legacyParts.push(r.additional_notes);
  const notes = { free_text: legacyParts.join('\n\n').trim() };

  return {
    schema_version: SCHEMA_VERSION,
    cover_name,
    sections: { company, network, wireless, endpoint, email_web, access, data, vuln_audit, ig1, notes },
    _audit: {
      converted_from: 'intake_form_responses',
      converted_at:   new Date().toISOString(),
      original_status: r.status || null,
      original_completion: r.completion_percentage ?? null,
    },
  };
}

module.exports = {
  SCHEMA_VERSION,
  convertV72ToV12,
};
