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

// Human-readable field labels (V8 - 10 sections + IG1)
const FIELD_LABELS = {
  // Section 1 - Organization Profile
  company_name: 'Company Name', industry: 'Industry', employees_band: 'Employee Count',
  revenue_band: 'Revenue Band', business_address: 'Business Address', locations: 'Locations',
  website: 'Website',
  primary_contact_name: 'Primary Contact Name', primary_contact_title: 'Primary Contact Title',
  primary_contact_email: 'Primary Contact Email', primary_contact_phone: 'Primary Contact Phone',
  secondary_contact_name: 'Secondary Contact Name', secondary_contact_title: 'Secondary Contact Title',
  secondary_contact_email: 'Secondary Contact Email', secondary_contact_phone: 'Secondary Contact Phone',
  social_linkedin: 'LinkedIn', social_instagram: 'Instagram', social_x: 'X (Twitter)',
  social_facebook: 'Facebook', social_tiktok: 'TikTok', social_other: 'Other Social',
  fw_hipaa: 'HIPAA', fw_pci: 'PCI-DSS', fw_cmmc: 'CMMC', fw_sox: 'SOX',
  fw_glba: 'GLBA', fw_gdpr: 'GDPR', fw_ferpa: 'FERPA', fw_nist: 'NIST CSF', fw_none: 'None / Unknown',
  products_services: 'Key Products or Services',
  service_training: 'Cybersecurity Awareness Training', service_risk_assessment: 'Risk Assessment',
  service_osint: 'OSINT Research', service_vuln_assessment: 'Vulnerability Assessment',
  recent_incidents: 'Recent Security Incidents', ongoing_concerns: 'Ongoing Concerns',
  primary_goals: 'Primary Cybersecurity Goals',
  ai_has_policy: 'Has AI Policy', ai_no_policy: 'No AI Policy',
  ai_interest_training: 'AI Awareness Training', ai_interest_risks: 'AI Risk Understanding',
  ai_interest_opportunities: 'AI Opportunity Understanding', ai_interest_policy: 'AI Policy Development',
  // Section 2 - Network Topology
  workstation_count: 'Desktop Count', laptop_count: 'Laptop Count', server_count: 'Server Count',
  os_win_server: 'Windows Server', os_win_client: 'Windows Client', os_linux: 'Linux',
  os_macos: 'macOS', os_other: 'Other OS',
  role_dc: 'Domain Controller', role_dc_version: 'DC Version',
  role_file: 'File Server', role_file_version: 'File Server Version',
  role_mail: 'Mail Server', role_mail_version: 'Mail Server Version',
  role_web: 'Web/App Server', role_web_version: 'Web Server Version',
  role_db: 'Database Server', role_db_version: 'DB Server Version',
  role_backup: 'Backup Server', role_backup_version: 'Backup Server Version',
  role_print: 'Print Server', role_print_version: 'Print Server Version',
  role_other: 'Other Server', role_other_version: 'Other Server Details',
  role_other_notes: 'Server Notes',
  svc_smb: 'SMB', svc_smb_version: 'SMB Version',
  svc_rdp: 'RDP', svc_rdp_version: 'RDP Version',
  svc_ssh: 'SSH', svc_ssh_version: 'SSH Version',
  svc_http: 'HTTP/HTTPS', svc_http_version: 'HTTP Version',
  svc_sql: 'SQL/Database', svc_sql_version: 'SQL Version',
  svc_ftp: 'FTP', svc_ftp_version: 'FTP Version',
  svc_dns: 'DNS', svc_dns_version: 'DNS Version',
  svc_ldap: 'LDAP', svc_ldap_version: 'LDAP Version',
  svc_vpn: 'VPN', svc_vpn_version: 'VPN Type',
  domain_mode: 'Domain Mode', domain_name: 'Domain Name',
  // Section 3 - Wireless
  ssid_count: 'SSID Count', wifi_encryption: 'Wi-Fi Encryption',
  guest_wifi: 'Guest Network', guest_isolated: 'Guest Isolated',
  // Section 4 - Endpoint Security
  av_vendor: 'AV / EDR Vendor', disk_encryption: 'Disk Encryption',
  usb_policy: 'USB Policy', patch_cadence: 'Patch Cadence',
  // Section 5 - Email & Web
  email_provider: 'Email Provider', web_filtering: 'Web Filtering',
  spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC',
  // Section 6 - Account & Access
  mfa_coverage: 'MFA Coverage', priv_count_band: 'Privileged Account Count',
  password_manager: 'Password Manager', lockout_policy: 'Lockout Policy',
  dormant_cleanup: 'Dormant Account Cleanup',
  // Section 7 - Data Protection
  backup_cadence: 'Backup Cadence', offsite_backup: 'Offsite Backup',
  offline_backup: 'Offline Backup', encryption_at_rest: 'Encryption at Rest',
  dlp: 'DLP', restore_test: 'Backup Restore Test',
  // Section 8 - Vulnerability & Audit
  vuln_scanning: 'Vulnerability Scanning', logging_coverage: 'Logging Coverage',
  siem: 'SIEM', audit_retention: 'Audit Log Retention',
  // Section 10 - Notes
  free_text: 'Additional Notes',
};

// Section layout config for grouped PDF rendering (V8 - 10 sections + IG1)
const SECTION_CONFIG = {
  company_info: {
    title: '1. Organization Profile',
    groups: [
      { label: 'Organization Details', fields: ['company_name', 'industry', 'employees_band', 'revenue_band', 'business_address', 'locations', 'website'] },
      { label: 'Primary Contact', fields: ['primary_contact_name', 'primary_contact_title', 'primary_contact_email', 'primary_contact_phone'] },
      { label: 'Secondary Contact', fields: ['secondary_contact_name', 'secondary_contact_title', 'secondary_contact_email', 'secondary_contact_phone'] },
      { label: 'Social Media', type: 'inline', fields: ['social_linkedin', 'social_instagram', 'social_x', 'social_facebook', 'social_tiktok', 'social_other'] },
      { label: 'Regulatory Frameworks', type: 'checklist', fields: ['fw_hipaa', 'fw_pci', 'fw_cmmc', 'fw_sox', 'fw_glba', 'fw_gdpr', 'fw_ferpa', 'fw_nist', 'fw_none'] },
      { label: 'Services Requested', type: 'checklist', fields: ['service_training', 'service_risk_assessment', 'service_osint', 'service_vuln_assessment'] },
      { label: 'AI Usage', type: 'radio', fields: ['ai_usage'] },
      { label: 'AI Policy', type: 'checklist', fields: ['ai_has_policy', 'ai_no_policy'] },
      { label: 'AI Interests', type: 'checklist', fields: ['ai_interest_training', 'ai_interest_risks', 'ai_interest_opportunities', 'ai_interest_policy'] },
      { label: null, type: 'textarea', fields: ['products_services', 'recent_incidents', 'ongoing_concerns', 'primary_goals'] },
    ]
  },
  network_security: {
    title: '2. Network Topology',
    groups: [
      { label: 'Device Counts', fields: ['workstation_count', 'laptop_count', 'server_count'] },
      { label: 'Operating Systems', fields: ['os_win_server', 'os_win_client', 'os_linux', 'os_macos', 'os_other'] },
      { label: 'Server Roles', fields: ['role_dc', 'role_dc_version', 'role_file', 'role_file_version', 'role_mail', 'role_mail_version', 'role_web', 'role_web_version', 'role_db', 'role_db_version', 'role_backup', 'role_backup_version', 'role_print', 'role_print_version', 'role_other', 'role_other_version'] },
      { label: null, type: 'textarea', fields: ['role_other_notes'] },
      { label: 'Exposed Services', type: 'checklist', fields: ['svc_smb', 'svc_rdp', 'svc_ssh', 'svc_http', 'svc_sql', 'svc_ftp', 'svc_dns', 'svc_ldap', 'svc_vpn'] },
      { label: 'Domain & Network', fields: ['domain_mode', 'domain_name'] },
    ]
  },
  wireless: {
    title: '3. Wireless',
    groups: [
      { label: null, fields: ['ssid_count', 'wifi_encryption', 'guest_wifi', 'guest_isolated'] },
    ]
  },
  endpoint_security: {
    title: '4. Endpoint Security',
    groups: [
      { label: null, fields: ['av_vendor', 'disk_encryption', 'usb_policy', 'patch_cadence'] },
    ]
  },
  email_web: {
    title: '5. Email & Web',
    groups: [
      { label: null, fields: ['email_provider', 'web_filtering', 'spf', 'dkim', 'dmarc'] },
    ]
  },
  admin_privileges: {
    title: '6. Account & Access',
    groups: [
      { label: null, fields: ['mfa_coverage', 'priv_count_band', 'password_manager', 'lockout_policy', 'dormant_cleanup'] },
    ]
  },
  data_management: {
    title: '7. Data Protection',
    groups: [
      { label: null, fields: ['backup_cadence', 'offsite_backup', 'offline_backup', 'encryption_at_rest', 'dlp', 'restore_test'] },
    ]
  },
  vuln_management: {
    title: '8. Vulnerability & Audit',
    groups: [
      { label: null, fields: ['vuln_scanning', 'logging_coverage', 'siem', 'audit_retention'] },
    ]
  },
  compliance: {
    title: '9. CIS Controls IG1 Safeguards',
    groups: [
      { label: 'IG1 Safeguard Responses', type: 'ig1' },
    ]
  },
  // Legacy sections (may be empty in V8 forms)
  security_policies: { title: 'Security Policies (Legacy)', groups: [] },
  software_assets: { title: 'Software Assets (Legacy)', groups: [] },
  secure_config: { title: 'Secure Configuration (Legacy)', groups: [] },
  network_ports: { title: 'Network Ports (Legacy)', groups: [] },
  network_devices: { title: 'Network Devices (Legacy)', groups: [] },
  pentesting: {
    title: '10. Additional Notes',
    groups: [
      { label: null, type: 'textarea', fields: ['free_text'] },
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
      } else if (type === 'ig1') {
        renderIG1Pdf(doc, data, pageWidth, leftMargin, ensureSpace);
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

function renderIG1Pdf(doc, data, pageWidth, leftMargin, ensureSpace) {
  // IG1 data is stored as ig1_X.X = "yes"|"partial"|"no"|"unknown" and ig1_X.X_notes = "..."
  const ig1Keys = Object.keys(data).filter(k => /^ig1_\d+\.\d+$/.test(k)).sort((a, b) => {
    const na = parseFloat(a.replace('ig1_', '')), nb = parseFloat(b.replace('ig1_', ''));
    return na - nb;
  });

  if (ig1Keys.length === 0) {
    doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.textLight)
      .text('No IG1 safeguard responses recorded.', leftMargin, doc.y);
    doc.moveDown(0.3);
    return;
  }

  ig1Keys.forEach(key => {
    const num = key.replace('ig1_', '');
    const val = data[key];
    const notes = data[`${key}_notes`] || '';
    if (!val) return;

    ensureSpace(20);
    const rowY = doc.y;

    // Safeguard number
    doc.fontSize(8).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
      .text(num, leftMargin, rowY, { width: 30 });

    // Status badge
    let display, color;
    if (val === 'yes') { display = 'YES'; color = PDF_COLORS.yes; }
    else if (val === 'partial') { display = 'PARTIAL'; color = PDF_COLORS.unknown; }
    else if (val === 'no') { display = 'NO'; color = PDF_COLORS.no; }
    else { display = "DON'T KNOW"; color = PDF_COLORS.textLight; }

    const badgeX = leftMargin + pageWidth - 60;
    doc.roundedRect(badgeX, rowY - 1, 52, 12, 3).fill(color);
    doc.fontSize(6.5).font('Helvetica-Bold').fillColor('#ffffff')
      .text(display, badgeX, rowY + 1, { width: 52, align: 'center' });

    doc.y = rowY + 14;

    if (notes) {
      ensureSpace(16);
      doc.fontSize(7.5).font('Helvetica').fillColor(PDF_COLORS.textLight)
        .text(`Notes: ${notes}`, leftMargin + 30, doc.y, { width: pageWidth - 90 });
      doc.moveDown(0.1);
    }
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
