// /src/routes/intake-form.js - V7.2 with 15 sections
const express = require('express');
const router = express.Router();
const { pool } = require('../utils/db');
const { authenticateToken } = require('../../../src/middleware/auth');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

// V7.2 Section names
const V72_SECTIONS = [
  'company_info', 'security_policies', 'data_management', 'network_security',
  'wireless', 'endpoint_security', 'compliance', 'software_assets',
  'vuln_management', 'admin_privileges', 'secure_config', 'email_web',
  'network_ports', 'network_devices', 'pentesting'
];

// Helper: Load profile JSON from file
function loadProfileFromFile(jsonFilePath) {
  if (!jsonFilePath) throw new Error('No JSON file path provided');
  
  const possiblePaths = [
    jsonFilePath,
    path.join(__dirname, '..', '..', jsonFilePath.replace(/^\//, '')),
    path.join(__dirname, '..', '..', 'profiles', path.basename(jsonFilePath)),
    path.join(process.cwd(), jsonFilePath.replace(/^\//, '')),
    path.join(process.cwd(), 'profiles', path.basename(jsonFilePath)),
  ];
  
  for (const filePath of possiblePaths) {
    if (fs.existsSync(filePath)) {
      const fileContent = fs.readFileSync(filePath, 'utf8');
      let jsonData = JSON.parse(fileContent);
      if (Array.isArray(jsonData) && jsonData.length > 0) jsonData = jsonData[0];
      let studentView = jsonData.student_view || jsonData;
      const stakeholdersRaw = studentView.raw?.threats?.stakeholders || studentView.stakeholders || [];
      return {
        ...studentView,
        quick: {
          ...studentView.quick,
          company_name: studentView.raw?.threats?.organization?.company_name || studentView.quick?.company_name,
          industry: studentView.raw?.threats?.organization?.industry || studentView.quick?.industry,
          employees_total: studentView.raw?.threats?.organization?.employees_total || studentView.quick?.employees_total,
          domain_public: studentView.raw?.threats?.organization?.domain_public || studentView.quick?.domain_public
        },
        stakeholders: stakeholdersRaw
      };
    }
  }
  throw new Error(`Profile JSON file not found: ${jsonFilePath}`);
}

// GET /api/intake-form/:profileId
router.get('/:profileId', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    
    let result = await pool.query(`SELECT * FROM intake_form_responses WHERE user_id = $1 AND profile_id = $2`, [userId, profileId]);
    
    if (result.rows.length === 0) {
      result = await pool.query(`INSERT INTO intake_form_responses (user_id, profile_id, status) VALUES ($1, $2, 'not_started') RETURNING *`, [userId, profileId]);
    }
    
    const profileResult = await pool.query(`
      SELECT id, company_name, industry, client_type, difficulty, json_filename, json_file_path,
             employee_count, stakeholder_count, compliance_frameworks, key_risks, critical_systems
      FROM profiles WHERE id = $1
    `, [profileId]);
    
    if (profileResult.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
    
    const profile = profileResult.rows[0];
    let studentData = null;
    
    try {
      const jsonPath = profile.json_file_path || profile.json_filename;
      if (jsonPath) studentData = loadProfileFromFile(jsonPath);
    } catch (fileErr) {
      console.warn('[Intake Form] Could not load JSON file:', fileErr.message);
    }
    
    if (!studentData) {
      studentData = {
        quick: {
          company_name: profile.company_name,
          industry: profile.industry,
          employees_total: profile.employee_count
        }
      };
    }
    
    // Build form_data from V7.2 columns
    const row = result.rows[0];
    const form_data = {};
    V72_SECTIONS.forEach(section => {
      form_data[section] = row[section] || {};
    });
    
    res.json({ success: true, form_data, profile_data: studentData, profile_basic: { id: profile.id, company_name: profile.company_name } });
    
  } catch (error) {
    console.error('[Intake Form] Error:', error);
    res.status(500).json({ error: 'Failed to fetch intake form', details: error.message });
  }
});

// PUT /api/intake-form/:profileId
router.put('/:profileId', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const body = req.body;
    
    // Calculate completion
    let totalFields = 0, completedFields = 0;
    V72_SECTIONS.forEach(section => {
      if (body[section] && typeof body[section] === 'object') {
        Object.values(body[section]).forEach(v => {
          totalFields++;
          if (v !== null && v !== undefined && v !== '' && v !== false) completedFields++;
        });
      }
    });
    const completion = totalFields > 0 ? Math.round((completedFields / totalFields) * 100) : 0;
    let status = completion === 0 ? 'not_started' : (completion < 100 ? 'in_progress' : 'complete');
    
    const result = await pool.query(`
      UPDATE intake_form_responses SET 
        company_info = $1, security_policies = $2, data_management = $3, network_security = $4,
        wireless = $5, endpoint_security = $6, compliance = $7, software_assets = $8,
        vuln_management = $9, admin_privileges = $10, secure_config = $11, email_web = $12,
        network_ports = $13, network_devices = $14, pentesting = $15,
        completion_percentage = $16, status = $17, last_saved_at = NOW(),
        started_at = COALESCE(started_at, NOW()), updated_at = NOW()
      WHERE user_id = $18 AND profile_id = $19 RETURNING *
    `, [
      JSON.stringify(body.company_info || {}), JSON.stringify(body.security_policies || {}),
      JSON.stringify(body.data_management || {}), JSON.stringify(body.network_security || {}),
      JSON.stringify(body.wireless || {}), JSON.stringify(body.endpoint_security || {}),
      JSON.stringify(body.compliance || {}), JSON.stringify(body.software_assets || {}),
      JSON.stringify(body.vuln_management || {}), JSON.stringify(body.admin_privileges || {}),
      JSON.stringify(body.secure_config || {}), JSON.stringify(body.email_web || {}),
      JSON.stringify(body.network_ports || {}), JSON.stringify(body.network_devices || {}),
      JSON.stringify(body.pentesting || {}),
      completion, status, userId, profileId
    ]);
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'Form not found' });
    
    res.json({ success: true, form_data: result.rows[0], completion, status });
    
  } catch (error) {
    console.error('[Intake Form] Error updating:', error);
    res.status(500).json({ error: 'Failed to update form', details: error.message });
  }
});

// GET /api/intake-form/:profileId/status
router.get('/:profileId/status', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const result = await pool.query(`SELECT status, completion_percentage, last_saved_at FROM intake_form_responses WHERE user_id = $1 AND profile_id = $2`, [userId, profileId]);
    if (result.rows.length === 0) return res.json({ success: true, status: 'not_started', completion_percentage: 0 });
    res.json({ success: true, ...result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch status' });
  }
});

// POST /api/intake-form/:profileId/complete
router.post('/:profileId/complete', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const result = await pool.query(`UPDATE intake_form_responses SET status = 'complete', completed_at = NOW(), completion_percentage = 100 WHERE user_id = $1 AND profile_id = $2 RETURNING *`, [userId, profileId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Form not found' });
    res.json({ success: true, message: 'Form marked as complete', form_data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete form' });
  }
});

// ============================================================================
// PDF EXPORT - Professional Intake Form
// ============================================================================

// Human-readable field labels
const FIELD_LABELS = {
  // Section 1
  company_name: 'Company Name', business_address: 'Business Address', industry_sector: 'Industry Sector',
  num_employees: 'Number of Employees', primary_contact_name: 'Name', primary_contact_title: 'Title',
  primary_contact_email: 'Email', primary_contact_phone: 'Phone', secondary_contact_name: 'Name',
  secondary_contact_title: 'Title', secondary_contact_email: 'Email', secondary_contact_phone: 'Phone',
  locations: 'Office / Operations Locations', website: 'Website',
  social_linkedin: 'LinkedIn', social_instagram: 'Instagram', social_x: 'X (Twitter)',
  social_facebook: 'Facebook', social_tiktok: 'TikTok', social_other: 'Other',
  products_services: 'Key Products or Services', recent_incidents: 'Recent Security Incidents or Data Breaches',
  ongoing_concerns: 'Ongoing Cybersecurity Concerns', primary_goals: 'Primary Cybersecurity Program Goals',
  ai_used: 'AI Usage', ai_has_policy: 'Has AI Policy', ai_no_policy: 'No AI Policy',
  ai_interest_training: 'AI Awareness Training', ai_interest_risks: 'AI Risk Understanding',
  ai_interest_opportunities: 'AI Opportunity Understanding', ai_interest_policy: 'AI Policy Development',
  // Services
  service_training: 'Cybersecurity Awareness Training', service_risk_assessment: 'Cybersecurity Risk Assessment',
  service_osint: 'OSINT Research', service_vuln_assessment: 'Website Vulnerability Assessment',
  // Section 2 - Policies
  policy_incident_response: 'Incident Response', policy_acceptable_use: 'Acceptable Use',
  policy_remote_access: 'Remote Access', policy_network_security: 'Network Security',
  policy_data_management: 'Data Management', policy_disaster_recovery: 'Disaster Recovery',
  policy_employee_awareness: 'Employee Awareness', policy_data_backup: 'Data Backup',
  policy_vendor_management: 'Vendor Management', policy_data_retention: 'Data Retention',
  policy_email: 'Email', policy_risk_management: 'Risk Management',
  policy_change_management: 'Change Management', policy_access_control: 'Access Control',
  policy_password: 'Password', policy_vendor_contractor: 'Vendor / Contractor',
  policy_byod: 'BYOD', policy_other: 'Other', policy_documents_notes: 'Policy Notes',
  // Training
  training_info_security: 'Information Security', training_mobile_security: 'Mobile Security',
  training_social_engineering: 'Social Engineering', training_phishing: 'Phishing',
  training_physical_security: 'Physical Security', training_wireless: 'Wireless',
  training_security_awareness: 'Security Awareness', training_safe_internet: 'Safe Internet',
  training_email_security: 'Email Security', training_other: 'Other Training',
  // Section 3 - Data
  data_biometric: 'Biometric', data_privacy: 'Privacy', data_health: 'Health',
  data_business: 'Business', data_financial: 'Financial', data_intellectual_property: 'Intellectual Property',
  data_credit_card: 'Credit Card', data_classified: 'Classified / Sensitive',
  data_bank_account: 'Bank Account', data_trade_secrets: 'Trade Secrets',
  data_email_addresses: 'Email Addresses', data_consumer: 'Consumer (Name/Address/Phone)',
  data_membership: 'Membership', data_other: 'Other',
  storage_onprem_physical: 'On-Premises (Physical)', storage_onprem_digital: 'On-Premises (Digital)',
  storage_cloud: 'Cloud', storage_3rd_party: '3rd Party Data Center', storage_other: 'Other',
  backup_onprem: 'On-Premises', backup_cloud: 'Cloud', backup_3rd_party: '3rd Party Data Center',
  backup_other: 'Other', backup_unknown: 'Unknown', backup_none: 'No Backup Solution',
  ac_role_based: 'Role-Based', ac_attribute_based: 'Attribute-Based', ac_mandatory: 'Mandatory',
  ac_discretionary: 'Discretionary', ac_rule_based: 'Rule-Based', ac_other: 'Other',
  backup_tests: 'Annual Backup Tests Completed', retention_followed: 'Data Retention Policy Followed',
  access_control: 'Using Access Control',
  // Section 4 - Network
  net_load_balancer: 'Load Balancer', net_nac: 'NAC', net_utm: 'UTM', net_ids_ips: 'IDS/IPS',
  net_vpn: 'VPN', net_siem: 'SIEM', net_web_filter: 'Web Filter', net_switch: 'Switch',
  net_router: 'Router', net_wifi_ap: 'WiFi Access Point', net_modem: 'Modem', net_other: 'Other',
  server_mail: 'Mail Server', server_dhcp: 'DHCP Server', server_web: 'Web Server',
  server_file: 'File Server', server_database: 'Database Server', server_dns: 'DNS Server',
  server_application: 'Application Server', server_virtual: 'Virtual Server',
  server_cloud: 'Cloud Server', server_other: 'Other',
  fw_stateful: 'Stateful', fw_stateless: 'Stateless', fw_ngfw: 'NGFW', fw_waf: 'WAF',
  fw_cloud: 'Cloud', fw_packet_filtering: 'Packet Filtering',
  ips_network: 'Network IPS', ips_host: 'Host IPS', ids_network: 'Network IDS', ids_host: 'Host IDS',
  siem_splunk: 'Splunk', siem_qradar: 'QRadar', siem_logrhythm: 'LogRhythm', siem_other: 'Other SIEM',
  net_edr: 'EDR', net_xdr: 'XDR', net_email_security: 'Email Security Solution',
  password_manager_name: 'Password Manager', security_assets_list: 'Security Assets Detail',
  // Section 5 - Wireless
  wifi_wep: 'WEP', wifi_wps: 'WPS', wifi_wpa_personal: 'WPA Personal', wifi_wpa_enterprise: 'WPA Enterprise',
  wifi_wpa2_personal: 'WPA2 Personal', wifi_wpa2_enterprise: 'WPA2 Enterprise',
  wifi_wpa3_personal: 'WPA3 Personal', wifi_wpa3_enterprise: 'WPA3 Enterprise', wifi_unknown: 'Unknown',
  // Section 6 - Endpoint
  av_norton: 'Norton', av_mcafee: 'McAfee', av_crowdstrike: 'CrowdStrike', av_avast: 'AVAST',
  av_bitdefender: 'Bitdefender', av_malwarebytes: 'Malwarebytes', av_sophos: 'Sophos', av_other: 'Other',
  app_blacklist: 'Block / Blacklisting', app_whitelist: 'Allow / Whitelisting', app_list_unknown: 'Unknown',
  // Section 7 - Compliance
  comp_gdpr: 'GDPR', comp_sox: 'SOX', comp_ferpa: 'FERPA', comp_pci_dss: 'PCI-DSS',
  comp_soc2: 'SOC 2', comp_glba: 'GLBA', comp_fisma: 'FISMA', comp_hipaa: 'HIPAA',
  comp_ccpa: 'CCPA', comp_cmmc: 'CMMC', comp_other: 'Other', comp_unknown: 'Unknown',
  vendor_compliance: 'Vendor Compliance Notes',
  // Sections 8-15 radio fields
  software_inventory: 'Up-to-Date Software Inventory', unauthorized_software: 'Unauthorized Software Detected & Resolved',
  software_review: 'Software Inventory Reviewed for Compliance',
  vuln_scanning: 'Regular Vulnerability Scanning', vuln_remediation: 'Timely Vulnerability Remediation',
  vuln_reports: 'Scan Reports Reviewed & Acted Upon',
  admin_roles: 'Admin Privileges Role-Based', admin_audit: 'Admin Privileges Tracked & Audited',
  admin_revoke: 'Process to Revoke Admin Privileges',
  secure_config_install: 'Secure Configs Applied on Install', secure_config_update: 'Configs Regularly Updated & Validated',
  secure_config_deviations: 'Config Deviations Detected & Corrected',
  email_filter: 'Malicious Email/Web Content Filtering', browser_settings: 'Email/Browser Security Settings Updated',
  email_training: 'Email/Web Security Training Provided',
  ports_disabled: 'Unnecessary Ports/Protocols Disabled', ports_review: 'Port Configs Regularly Reviewed',
  ports_monitor: 'Port Activities Monitored & Logged',
  scanner_nessus: 'Nessus', scanner_openvas: 'OpenVAS', scanner_other: 'Other Scanner',
  scanner_unknown: 'Unknown', scanner_report: 'Scanner Report Details',
  pentest_regular: 'Regular Penetration Tests', pentest_improve: 'Pentest Results Used for Improvements',
  redteam: 'Red Team Exercises Employed',
};

// Section layout config for grouped rendering
const SECTION_CONFIG = {
  company_info: {
    title: '1. Company Information',
    groups: [
      { label: 'Organization Details', fields: ['company_name', 'business_address', 'industry_sector', 'num_employees', 'locations', 'website'] },
      { label: 'Primary Contact', fields: ['primary_contact_name', 'primary_contact_title', 'primary_contact_email', 'primary_contact_phone'] },
      { label: 'Secondary Contact', fields: ['secondary_contact_name', 'secondary_contact_title', 'secondary_contact_email', 'secondary_contact_phone'] },
      { label: 'Social Media', type: 'inline', fields: ['social_linkedin', 'social_instagram', 'social_x', 'social_facebook', 'social_tiktok', 'social_other'] },
      { label: 'Services Requested', type: 'checklist', fields: ['service_training', 'service_risk_assessment', 'service_osint', 'service_vuln_assessment'] },
      { label: 'AI Usage', type: 'radio', fields: ['ai_used'] },
      { label: 'AI Policy', type: 'checklist', fields: ['ai_has_policy', 'ai_no_policy'] },
      { label: 'AI Interests', type: 'checklist', fields: ['ai_interest_training', 'ai_interest_risks', 'ai_interest_opportunities', 'ai_interest_policy'] },
      { label: null, type: 'textarea', fields: ['products_services', 'recent_incidents', 'ongoing_concerns', 'primary_goals'] },
    ]
  },
  security_policies: {
    title: '2. Security Policies and Procedures',
    groups: [
      { label: 'Policies in Place', type: 'checklist', fields: ['policy_incident_response', 'policy_acceptable_use', 'policy_remote_access', 'policy_network_security', 'policy_data_management', 'policy_disaster_recovery', 'policy_employee_awareness', 'policy_data_backup', 'policy_vendor_management', 'policy_data_retention', 'policy_email', 'policy_risk_management', 'policy_change_management', 'policy_access_control', 'policy_password', 'policy_vendor_contractor', 'policy_byod', 'policy_other'] },
      { label: null, type: 'textarea', fields: ['policy_documents_notes'] },
      { label: 'Security Training Scores (0-4)', type: 'scores', fields: ['training_info_security', 'training_mobile_security', 'training_social_engineering', 'training_phishing', 'training_physical_security', 'training_wireless', 'training_security_awareness', 'training_safe_internet', 'training_email_security', 'training_other'] },
    ]
  },
  data_management: {
    title: '3. Data and Information Management',
    groups: [
      { label: 'Data Types Managed', type: 'checklist', fields: ['data_biometric', 'data_privacy', 'data_health', 'data_business', 'data_financial', 'data_intellectual_property', 'data_credit_card', 'data_classified', 'data_bank_account', 'data_trade_secrets', 'data_email_addresses', 'data_consumer', 'data_membership', 'data_other'] },
      { label: 'Data Storage', type: 'checklist', fields: ['storage_onprem_physical', 'storage_onprem_digital', 'storage_cloud', 'storage_3rd_party', 'storage_other'] },
      { label: 'Backup Solutions', type: 'checklist', fields: ['backup_onprem', 'backup_cloud', 'backup_3rd_party', 'backup_other', 'backup_unknown', 'backup_none'] },
      { label: 'Backup & Retention', type: 'yesno', fields: ['backup_tests', 'retention_followed'] },
      { label: 'Access Control Methods', type: 'checklist', fields: ['ac_role_based', 'ac_attribute_based', 'ac_mandatory', 'ac_discretionary', 'ac_rule_based', 'ac_other'] },
      { label: null, type: 'yesno', fields: ['access_control'] },
    ]
  },
  network_security: {
    title: '4. Network Security and Access Control',
    groups: [
      { label: 'Network Equipment', fields: ['net_load_balancer', 'net_nac', 'net_utm', 'net_ids_ips', 'net_vpn', 'net_siem', 'net_web_filter', 'net_switch', 'net_router', 'net_wifi_ap', 'net_modem', 'net_other'] },
      { label: 'Servers', fields: ['server_mail', 'server_dhcp', 'server_web', 'server_file', 'server_database', 'server_dns', 'server_application', 'server_virtual', 'server_cloud', 'server_other'] },
      { label: 'Firewall Types', type: 'checklist', fields: ['fw_stateful', 'fw_stateless', 'fw_ngfw', 'fw_waf', 'fw_cloud', 'fw_packet_filtering'] },
      { label: 'IDS/IPS', type: 'checklist', fields: ['ips_network', 'ips_host', 'ids_network', 'ids_host'] },
      { label: 'SIEM', type: 'checklist', fields: ['siem_splunk', 'siem_qradar', 'siem_logrhythm', 'siem_other'] },
      { label: 'Additional Security Tools', fields: ['net_edr', 'net_xdr', 'net_email_security', 'password_manager_name'] },
      { label: null, type: 'textarea', fields: ['security_assets_list'] },
    ]
  },
  wireless: {
    title: '5. Wireless Security',
    groups: [
      { label: 'Wireless Protocols in Use', type: 'checklist', fields: ['wifi_wep', 'wifi_wps', 'wifi_wpa_personal', 'wifi_wpa_enterprise', 'wifi_wpa2_personal', 'wifi_wpa2_enterprise', 'wifi_wpa3_personal', 'wifi_wpa3_enterprise', 'wifi_unknown'] },
    ]
  },
  endpoint_security: {
    title: '6. Endpoint and Application Security',
    groups: [
      { label: 'Antivirus / Endpoint Protection', type: 'checklist', fields: ['av_norton', 'av_mcafee', 'av_crowdstrike', 'av_avast', 'av_bitdefender', 'av_malwarebytes', 'av_sophos', 'av_other'] },
      { label: 'Application Control', type: 'checklist', fields: ['app_blacklist', 'app_whitelist', 'app_list_unknown'] },
    ]
  },
  compliance: {
    title: '7. Compliance and Regulatory Requirements',
    groups: [
      { label: 'Applicable Frameworks', type: 'checklist', fields: ['comp_gdpr', 'comp_sox', 'comp_ferpa', 'comp_pci_dss', 'comp_soc2', 'comp_glba', 'comp_fisma', 'comp_hipaa', 'comp_ccpa', 'comp_cmmc', 'comp_other', 'comp_unknown'] },
      { label: null, type: 'textarea', fields: ['vendor_compliance'] },
    ]
  },
  software_assets: {
    title: '8. Inventory and Control of Software Assets',
    groups: [
      { label: null, type: 'yesno', fields: ['software_inventory', 'unauthorized_software', 'software_review'] },
    ]
  },
  vuln_management: {
    title: '9. Continuous Vulnerability Management',
    groups: [
      { label: null, type: 'yesno', fields: ['vuln_scanning', 'vuln_remediation', 'vuln_reports'] },
    ]
  },
  admin_privileges: {
    title: '10. Controlled Use of Administrative Privileges',
    groups: [
      { label: null, type: 'yesno', fields: ['admin_roles', 'admin_audit', 'admin_revoke'] },
    ]
  },
  secure_config: {
    title: '11. Secure Configuration for Hardware and Software',
    groups: [
      { label: null, type: 'yesno', fields: ['secure_config_install', 'secure_config_update', 'secure_config_deviations'] },
    ]
  },
  email_web: {
    title: '12. Email and Web Browser Protections',
    groups: [
      { label: null, type: 'yesno', fields: ['email_filter', 'browser_settings', 'email_training'] },
    ]
  },
  network_ports: {
    title: '13. Limitation and Control of Network Ports',
    groups: [
      { label: null, type: 'yesno', fields: ['ports_disabled', 'ports_review', 'ports_monitor'] },
    ]
  },
  network_devices: {
    title: '14. Secure Configuration for Network Devices',
    groups: [
      { label: 'Vulnerability Scanners', type: 'checklist', fields: ['scanner_nessus', 'scanner_openvas', 'scanner_other', 'scanner_unknown'] },
      { label: null, fields: ['scanner_report'] },
    ]
  },
  pentesting: {
    title: '15. Penetration Tests and Red Team Exercises',
    groups: [
      { label: null, type: 'yesno', fields: ['pentest_regular', 'pentest_improve', 'redteam'] },
    ]
  },
};

// Colors
const PDF_COLORS = {
  primary: '#1e40af',
  primaryLight: '#dbeafe',
  headerBg: '#1e3a5f',
  headerText: '#ffffff',
  sectionBg: '#f0f4f8',
  border: '#cbd5e1',
  text: '#1e293b',
  textLight: '#64748b',
  yes: '#16a34a',
  no: '#dc2626',
  unknown: '#d97706',
  checkOn: '#1e40af',
  checkOff: '#cbd5e1',
};

function renderIntakePdf(doc, formData, companyName) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;

  function ensureSpace(needed) {
    if (doc.y + needed > doc.page.height - 60) {
      doc.addPage();
    }
  }

  // ---- Compute real completion % from actual section data ----
  // Boolean false counts as filled (student deliberately unchecked a checkbox)
  // Only null, undefined, and '' count as unfilled
  let totalFields = 0, filledFields = 0;
  V72_SECTIONS.forEach(section => {
    const d = parseSection(formData[section]);
    Object.values(d).forEach(v => {
      totalFields++;
      if (v !== null && v !== undefined && v !== '') filledFields++;
    });
  });
  const completion = totalFields > 0 ? Math.round((filledFields / totalFields) * 100) : 0;

  // ---- COVER PAGE ----
  doc.moveDown(2);

  // Title accent bar
  doc.rect(leftMargin, doc.y, pageWidth, 3).fill(PDF_COLORS.primary);
  doc.y += 10;
  doc.fontSize(26).font('Helvetica-Bold').fillColor(PDF_COLORS.headerBg)
    .text('Client Intake Form', { align: 'center' });
  doc.moveDown(0.15);
  doc.fontSize(10).font('Helvetica').fillColor(PDF_COLORS.textLight)
    .text('Cybersecurity Risk Assessment', { align: 'center' });
  doc.moveDown(0.6);
  doc.rect(leftMargin + pageWidth * 0.3, doc.y, pageWidth * 0.4, 1).fill(PDF_COLORS.border);
  doc.moveDown(0.6);

  // Company name
  doc.fontSize(18).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
    .text(companyName, { align: 'center' });
  doc.moveDown(0.8);

  // Meta info
  const metaY = doc.y;
  const metaCol = pageWidth / 2;
  doc.fontSize(9).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
    .text('Date Generated:', leftMargin, metaY);
  doc.font('Helvetica').fillColor(PDF_COLORS.text)
    .text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), leftMargin + 90, metaY);
  doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
    .text('Status:', leftMargin + metaCol, metaY);
  doc.font('Helvetica').fillColor(PDF_COLORS.text)
    .text(`${completion}% Complete`, leftMargin + metaCol + 45, metaY);
  doc.y = metaY + 13;
  doc.fontSize(9).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
    .text('Prepared By:', leftMargin, doc.y);
  doc.font('Helvetica').fillColor(PDF_COLORS.text)
    .text('Clinic-in-a-Box Platform', leftMargin + 90, doc.y);
  doc.moveDown(1.2);

  // Sections summary
  doc.rect(leftMargin, doc.y, pageWidth, 1).fill(PDF_COLORS.border);
  doc.moveDown(0.4);
  doc.fontSize(10).font('Helvetica-Bold').fillColor(PDF_COLORS.headerBg).text('Sections');
  doc.moveDown(0.2);
  V72_SECTIONS.forEach(section => {
    const config = SECTION_CONFIG[section];
    if (!config) return;
    const sectionData = parseSection(formData[section]);
    const filled = Object.values(sectionData).filter(v => v !== null && v !== undefined && v !== '').length;
    const total = Object.keys(sectionData).length;
    const status = total === 0 ? 'Empty' : (filled === 0 ? 'Not Started' : (filled >= total ? 'Complete' : `${filled}/${total} fields`));
    const rowY = doc.y;
    doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(config.title, leftMargin + 8, rowY, { width: pageWidth - 100 });
    doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.textLight)
      .text(status, leftMargin + 8, rowY, { width: pageWidth - 16, align: 'right' });
    doc.y = rowY + 12; // lock row height, prevent doc.y drift
  });

  // ---- CONTENT SECTIONS (packed, no forced page breaks) ----
  V72_SECTIONS.forEach(section => {
    const config = SECTION_CONFIG[section];
    if (!config) return;
    const data = parseSection(formData[section]);
    if (Object.keys(data).length === 0) return;

    // Only add page if less than 70pt of space left for header + first group
    ensureSpace(70);

    // Section header bar
    const headerY = doc.y;
    doc.rect(leftMargin, headerY, pageWidth, 22).fill(PDF_COLORS.headerBg);
    doc.fontSize(11).font('Helvetica-Bold').fillColor(PDF_COLORS.headerText)
      .text(config.title, leftMargin + 10, headerY + 5, { width: pageWidth - 20 });
    doc.y = headerY + 26;

    config.groups.forEach(group => {
      if (group.label) {
        ensureSpace(24);
        doc.fontSize(9).font('Helvetica-Bold').fillColor(PDF_COLORS.primary)
          .text(group.label, leftMargin, doc.y);
        doc.moveDown(0.15);
      }

      const type = group.type || 'text';

      if (type === 'checklist') {
        renderChecklist(doc, data, group.fields, pageWidth, leftMargin);
      } else if (type === 'yesno') {
        renderYesNo(doc, data, group.fields, pageWidth, leftMargin);
      } else if (type === 'scores') {
        renderScores(doc, data, group.fields, pageWidth, leftMargin);
      } else if (type === 'textarea') {
        group.fields.forEach(f => {
          if (data[f]) {
            ensureSpace(30);
            doc.fontSize(8.5).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
              .text(FIELD_LABELS[f] || f, leftMargin);
            doc.moveDown(0.1);
            const textHeight = doc.heightOfString(String(data[f]), { width: pageWidth - 16, fontSize: 8.5 }) + 10;
            ensureSpace(textHeight + 4);
            const boxY = doc.y;
            doc.rect(leftMargin, boxY, pageWidth, textHeight).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
            doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.text)
              .text(String(data[f]), leftMargin + 6, boxY + 5, { width: pageWidth - 12 });
            doc.y = boxY + textHeight + 4;
          }
        });
      } else if (type === 'inline') {
        const colWidth = (pageWidth - 10) / 2;
        let col = 0;
        let rowY = doc.y;
        const ROW_H = 12;
        group.fields.forEach(f => {
          const val = data[f];
          if (!val) return;
          if (col === 0 && rowY + ROW_H > doc.page.height - 60) {
            doc.addPage();
            rowY = doc.y;
          }
          const x = leftMargin + col * (colWidth + 10);
          doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
            .text(FIELD_LABELS[f] || f, x, rowY, { width: 65 });
          doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.text)
            .text(String(val), x + 67, rowY, { width: colWidth - 67 });
          doc.y = rowY + ROW_H;
          col++;
          if (col >= 2) { col = 0; rowY += ROW_H; }
        });
        if (col > 0) rowY += ROW_H;
        doc.y = rowY;
      } else if (type === 'radio') {
        group.fields.forEach(f => {
          const val = data[f];
          if (val) {
            const display = val === 'yes' ? 'Yes' : val === 'no' ? 'No' : val === 'unknown' ? 'Unknown' : String(val);
            doc.fontSize(8.5).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
              .text(`${FIELD_LABELS[f] || f}: ${display}`, leftMargin, doc.y, { width: pageWidth });
          }
        });
        doc.moveDown(0.15);
      } else {
        // Default: labeled text fields in two columns
        const colWidth = (pageWidth - 10) / 2;
        let col = 0;
        let rowY = doc.y;
        const ROW_H = 24;
        group.fields.forEach(f => {
          const val = data[f];
          if (!val && val !== 0) return;
          // Page break check at start of each row
          if (col === 0 && rowY + ROW_H > doc.page.height - 60) {
            doc.addPage();
            rowY = doc.y;
          }
          const x = leftMargin + col * (colWidth + 10);
          doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
            .text(FIELD_LABELS[f] || f.replace(/_/g, ' '), x, rowY);
          doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.text)
            .text(String(val), x, rowY + 9, { width: colWidth });
          doc.y = rowY + ROW_H; // lock doc.y
          col++;
          if (col >= 2) { col = 0; rowY += ROW_H; }
        });
        if (col > 0) rowY += ROW_H;
        doc.y = rowY;
      }
      doc.moveDown(0.15);
    });
    doc.moveDown(0.3);
  });
}

function parseSection(data) {
  if (!data) return {};
  if (typeof data === 'string') { try { return JSON.parse(data); } catch(e) { return {}; } }
  return data;
}

function renderChecklist(doc, data, fields, pageWidth, leftMargin) {
  const colWidth = (pageWidth - 6) / 3;
  let col = 0;
  let rowY = doc.y;
  const ROW_H = 12;

  fields.forEach(f => {
    // Check for page break at start of each new row
    if (col === 0 && rowY + ROW_H > doc.page.height - 60) {
      doc.addPage();
      rowY = doc.y;
    }

    const isChecked = data[f] === true || data[f] === 'true';
    const x = leftMargin + col * colWidth;
    const label = FIELD_LABELS[f] || f;
    const color = isChecked ? PDF_COLORS.text : PDF_COLORS.textLight;

    // Draw checkbox square (rect doesn't move doc.y)
    if (isChecked) {
      doc.rect(x, rowY + 1, 7, 7).fill(PDF_COLORS.checkOn);
    } else {
      doc.rect(x, rowY + 1, 7, 7).lineWidth(0.5).strokeColor(PDF_COLORS.checkOff).stroke();
    }

    // Draw label text — then force doc.y back so it doesn't drift
    doc.fontSize(8).font('Helvetica').fillColor(color)
      .text(label, x + 10, rowY, { width: colWidth - 12 });
    doc.y = rowY + ROW_H; // prevent doc.y from drifting with text height

    col++;
    if (col >= 3) { col = 0; rowY += ROW_H; }
  });
  if (col > 0) rowY += ROW_H;
  doc.y = rowY;
}

function renderYesNo(doc, data, fields, pageWidth, leftMargin) {
  fields.forEach(f => {
    const val = data[f];
    if (!val) return;

    const label = FIELD_LABELS[f] || f.replace(/_/g, ' ');
    let display, color;
    if (val === 'yes') { display = 'YES'; color = PDF_COLORS.yes; }
    else if (val === 'no') { display = 'NO'; color = PDF_COLORS.no; }
    else { display = 'UNKNOWN'; color = PDF_COLORS.unknown; }

    if (doc.y + 15 > doc.page.height - 60) doc.addPage();

    const rowY = doc.y;
    doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(label, leftMargin, rowY, { width: pageWidth - 70 });

    const badgeX = leftMargin + pageWidth - 50;
    doc.roundedRect(badgeX, rowY - 1, 42, 12, 3).fill(color);
    doc.fontSize(7).font('Helvetica-Bold').fillColor('#ffffff')
      .text(display, badgeX, rowY + 1, { width: 42, align: 'center' });

    doc.y = rowY + 15;
  });
}

function renderScores(doc, data, fields, pageWidth, leftMargin) {
  const barMaxWidth = 80;
  const barX = leftMargin + pageWidth - barMaxWidth - 30;

  fields.forEach(f => {
    const val = parseInt(data[f]);
    if (isNaN(val)) return;
    const label = FIELD_LABELS[f] || f;

    if (doc.y + 14 > doc.page.height - 60) doc.addPage();

    const rowY = doc.y;
    doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(label, leftMargin, rowY, { width: pageWidth - barMaxWidth - 50 });

    doc.roundedRect(barX, rowY + 1, barMaxWidth, 7, 2).fill('#e2e8f0');
    const fillWidth = (val / 4) * barMaxWidth;
    if (fillWidth > 0) {
      const fillColor = val <= 1 ? PDF_COLORS.no : val <= 2 ? PDF_COLORS.unknown : PDF_COLORS.yes;
      doc.roundedRect(barX, rowY + 1, fillWidth, 7, 2).fill(fillColor);
    }
    doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
      .text(`${val}/4`, barX + barMaxWidth + 5, rowY, { width: 30 });

    doc.y = rowY + 14;
  });
}

// GET /api/intake-form/:profileId/export - Export as PDF
router.get('/:profileId/export', authenticateToken, async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const result = await pool.query(`SELECT ifr.*, p.company_name FROM intake_form_responses ifr JOIN profiles p ON ifr.profile_id = p.id WHERE ifr.user_id = $1 AND ifr.profile_id = $2`, [userId, profileId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Form not found' });

    const formData = result.rows[0];
    const companyName = formData.company_name || 'Unknown Organization';
    const doc = new PDFDocument({ margin: 50, size: 'letter', bufferPages: true });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="intake-form-${companyName.replace(/[^a-zA-Z0-9]/g, '-')}.pdf"`);
    doc.pipe(res);

    renderIntakePdf(doc, formData, companyName);

    doc.end();
  } catch (error) {
    console.error('[Intake Form] PDF export error:', error);
    if (!res.headersSent) res.status(500).json({ error: 'Failed to export PDF' });
  }
});

module.exports = router;
module.exports.renderIntakePdf = renderIntakePdf;
module.exports.V72_SECTIONS = V72_SECTIONS;
module.exports.SECTION_CONFIG = SECTION_CONFIG;
module.exports.FIELD_LABELS = FIELD_LABELS;
