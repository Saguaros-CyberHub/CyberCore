/**
 * Policy Document Template Engine
 * Generates realistic, professional policy documents from profile data.
 * Each policy is a standalone HTML document with inline CSS.
 */

// ============================================================================
// SHARED HELPERS
// ============================================================================

function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '').replace(/^-+/, '');
}

function formatDate(d) {
  return d.toISOString().split('T')[0];
}

function nextReviewDate() {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return formatDate(d);
}

function today() {
  return formatDate(new Date());
}

/** Extract a context object from raw profile JSON for template use */
function buildContext(profileJson) {
  const raw = profileJson?.student_view?.raw || {};
  const threats = raw.threats || {};
  const org = threats.organization || {};
  const gov = threats.profiles?.governance_and_policy || {};
  const it = threats.it_environment || raw.it?.it_environment || {};
  const net = threats.network || raw.network || {};

  return {
    company_name: org.company_name || 'Organization',
    industry: org.industry || 'General',
    employees_total: org.employees_total || 50,
    hq_city: org.hq_city || '',
    business_model: org.business_model || '',
    framework: gov.framework || 'Ad-hoc',
    policy_enforcement: gov.policy_enforcement || 'Informal',
    policies_present: gov.policies_present || [],
    policies_missing: gov.policies_missing || [],
    risk_tolerance: gov.risk_tolerance || 'Moderate',
    deliberate_weaknesses: gov.deliberate_weaknesses || [],
    endpoint_protection: it.endpoint_protection || {},
    remote_access: it.remote_access || {},
    backups: it.backups || {},
    patch_management: it.patch_management || {},
    servers: it.servers || [],
    saas: it.saas || [],
    endpoints: it.endpoints || {},
    physical_security: it.physical_security || {},
    vendor_risk: it.vendor_risk || {},
    vendor_dependencies: it.vendor_dependencies || [],
    delivery: it.delivery || 'On-Premises',
    firewall: net.firewall || {},
    subnets: net.subnets || [],
    difficulty: profileJson?.difficulty || 'intermediate',
    compliance_focus: threats.profiles?.compliance_focus || [],
    past_incidents: org.past_incidents || [],
    business_continuity: org.business_continuity || {},
  };
}


// ============================================================================
// HTML WRAPPER
// ============================================================================

function buildPolicyHTML(title, ctx, bodyContent) {
  const effectiveDate = today();
  const reviewDate = nextReviewDate();

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — ${esc(ctx.company_name)}</title>
<style>
  @media print { body { padding: 20px; } .no-print { display: none; } }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; max-width: 850px; margin: 0 auto; padding: 40px 50px; color: #1a202c; line-height: 1.7; background: #fff; }
  .doc-header { border-bottom: 3px solid #1a365d; padding-bottom: 20px; margin-bottom: 30px; }
  .doc-header .org-name { color: #718096; font-size: 0.85em; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 4px; }
  .doc-header h1 { color: #1a365d; font-size: 1.7em; margin-bottom: 8px; font-weight: 700; }
  .doc-meta { display: flex; gap: 12px; flex-wrap: wrap; }
  .doc-meta span { background: #f7fafc; border: 1px solid #e2e8f0; padding: 3px 12px; border-radius: 4px; font-size: 0.8em; color: #4a5568; }
  h2 { color: #2c5282; margin-top: 32px; margin-bottom: 12px; font-size: 1.2em; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
  h3 { color: #2d3748; margin-top: 22px; margin-bottom: 8px; font-size: 1.05em; }
  p { margin-bottom: 12px; }
  ul, ol { margin: 8px 0 12px 24px; }
  li { margin-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 0.92em; }
  th { background: #1a365d; color: #fff; padding: 9px 12px; text-align: left; font-weight: 600; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  tr:nth-child(even) td { background: #f7fafc; }
  .callout { background: #ebf8ff; border-left: 4px solid #3182ce; padding: 12px 16px; margin: 14px 0; border-radius: 0 4px 4px 0; font-size: 0.92em; }
  .callout-warn { background: #fffbeb; border-left-color: #d69e2e; }
  .doc-footer { margin-top: 44px; padding-top: 20px; border-top: 2px solid #1a365d; color: #718096; font-size: 0.82em; }
  .doc-footer p { margin-bottom: 4px; }
  .sig-block { display: flex; gap: 40px; margin-top: 20px; }
  .sig-line { flex: 1; border-top: 1px solid #a0aec0; padding-top: 6px; font-size: 0.85em; color: #718096; }
</style>
</head>
<body>
<div class="doc-header">
  <div class="org-name">${esc(ctx.company_name)}</div>
  <h1>${esc(title)}</h1>
  <div class="doc-meta">
    <span>Version 1.0</span>
    <span>Effective: ${effectiveDate}</span>
    <span>Classification: Internal Use Only</span>
    <span>Review Cycle: Annual</span>
  </div>
</div>

${bodyContent}

<div class="doc-footer">
  <p><strong>Document Owner:</strong> Information Security Department</p>
  <p><strong>Approved By:</strong> Chief Information Security Officer / Executive Leadership</p>
  <p><strong>Next Review Date:</strong> ${reviewDate}</p>
  <div class="sig-block">
    <div class="sig-line">Prepared By — Information Security</div>
    <div class="sig-line">Approved By — Executive Sponsor</div>
  </div>
  <p style="margin-top: 18px; font-style: italic; color: #a0aec0;">Simulated policy document generated for Clinic-in-a-Box cybersecurity training exercise.</p>
</div>
</body>
</html>`;
}


// ============================================================================
// POLICY GENERATORS
// ============================================================================

function generateDataHandlingPolicy(policyName, ctx) {
  const saasNames = ctx.saas.map(s => s.name || s.app || s).filter(Boolean).slice(0, 5);
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Data Handling Policy establishes requirements for the classification, storage, transmission, and disposal of data at <strong>${esc(ctx.company_name)}</strong>. It applies to all employees, contractors, and third-party service providers who access, process, or store organizational data.</p>
<p>As a ${esc(ctx.industry)} organization with approximately ${ctx.employees_total} employees, ${esc(ctx.company_name)} handles sensitive client information, financial records, and proprietary business data that require appropriate safeguards.</p>

<h2>2. Data Classification</h2>
<table>
  <tr><th>Level</th><th>Description</th><th>Examples</th><th>Handling Requirements</th></tr>
  <tr><td><strong>Confidential</strong></td><td>Highly sensitive; unauthorized disclosure would cause significant harm</td><td>Client PII, financial records, authentication credentials, HR files</td><td>Encrypted at rest and in transit; access logged; need-to-know only</td></tr>
  <tr><td><strong>Internal</strong></td><td>Business-sensitive; not intended for public release</td><td>Internal reports, project plans, employee directories, network diagrams</td><td>Access restricted to employees; stored on approved systems only</td></tr>
  <tr><td><strong>Public</strong></td><td>Approved for external distribution</td><td>Marketing materials, published policies, public-facing content</td><td>No special handling; approved by management before release</td></tr>
</table>

<h2>3. Data Handling Procedures</h2>
<h3>3.1 Storage</h3>
<ul>
  <li>Confidential data must be stored on approved, encrypted systems only</li>
  <li>Removable media (USB drives, external hard drives) must not be used for Confidential data without written approval</li>
  <li>Cloud storage is permitted only on sanctioned platforms: ${saasNames.length ? saasNames.map(n => esc(n)).join(', ') : 'approved SaaS applications'}</li>
  <li>Backup frequency: ${esc(ctx.backups.frequency || 'Daily')} using ${esc(ctx.backups.method || 'approved backup solution')}</li>
</ul>

<h3>3.2 Transmission</h3>
<ul>
  <li>Confidential data must be encrypted when transmitted over any network (TLS 1.2+ minimum)</li>
  <li>Email containing Confidential data must use encryption or approved secure file-sharing platforms</li>
  <li>Fax transmission of Confidential data is prohibited unless no alternative exists and is pre-approved</li>
</ul>

<h3>3.3 Disposal</h3>
<ul>
  <li>Electronic media: Secure wipe using NIST SP 800-88 standards, or physical destruction</li>
  <li>Paper records: Cross-cut shredding (minimum P-4 security level)</li>
  <li>Disposal of IT assets must be logged and verified by IT department</li>
</ul>

<h2>4. Roles &amp; Responsibilities</h2>
<table>
  <tr><th>Role</th><th>Responsibility</th></tr>
  <tr><td>All Employees</td><td>Classify data appropriately; follow handling procedures; report suspected data breaches within 1 hour</td></tr>
  <tr><td>Department Managers</td><td>Ensure team compliance; approve access requests for Confidential data; conduct quarterly data reviews</td></tr>
  <tr><td>IT / Security Team</td><td>Implement technical controls; monitor data access logs; manage encryption and DLP tools</td></tr>
  <tr><td>Data Owner</td><td>Determine classification level; approve access; ensure retention compliance</td></tr>
</table>

<h2>5. Compliance &amp; Enforcement</h2>
<p>This policy aligns with ${esc(ctx.company_name)}'s ${esc(ctx.framework)} security framework${ctx.compliance_focus.length ? ' and addresses ' + ctx.compliance_focus.map(c => esc(c)).join(', ') + ' requirements' : ''}.</p>
<p>Enforcement: ${esc(ctx.policy_enforcement)}. Violations may result in disciplinary action up to and including termination. Intentional mishandling of Confidential data may result in legal action.</p>

<h2>6. Exceptions</h2>
<p>Exceptions to this policy require written approval from the Information Security Department and must be documented with a risk assessment, compensating controls, and an expiration date not exceeding 12 months.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateIncidentResponsePlan(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Incident Response Plan (IRP) provides a structured approach for ${esc(ctx.company_name)} to detect, respond to, contain, and recover from cybersecurity incidents. It applies to all information systems, networks, and data assets operated by or on behalf of the organization.</p>

<h2>2. Incident Classification</h2>
<table>
  <tr><th>Severity</th><th>Description</th><th>Examples</th><th>Response Time</th></tr>
  <tr><td><strong>Critical (P1)</strong></td><td>Active breach with data exfiltration or system destruction</td><td>Ransomware, confirmed data breach, APT activity</td><td>Immediate — within 15 minutes</td></tr>
  <tr><td><strong>High (P2)</strong></td><td>Active attack or compromise with potential for escalation</td><td>Malware on server, unauthorized admin access, DDoS attack</td><td>Within 1 hour</td></tr>
  <tr><td><strong>Medium (P3)</strong></td><td>Suspicious activity requiring investigation</td><td>Unusual login patterns, phishing attempt received, policy violation</td><td>Within 4 hours</td></tr>
  <tr><td><strong>Low (P4)</strong></td><td>Minor security event with limited impact</td><td>Failed login attempts, minor policy deviation, spam increase</td><td>Within 24 hours</td></tr>
</table>

<h2>3. Incident Response Phases</h2>

<h3>3.1 Preparation</h3>
<ul>
  <li>Maintain current asset inventory of all ${ctx.employees_total}+ endpoints and ${ctx.servers.length || 'critical'} servers</li>
  <li>Ensure endpoint protection (${esc(ctx.endpoint_protection.product || 'approved EDR solution')}) is deployed and current on all systems</li>
  <li>Conduct tabletop exercises quarterly; full simulation annually</li>
  <li>Maintain offline copies of this plan and critical contact information</li>
  <li>Pre-establish relationships with external forensics and legal counsel</li>
</ul>

<h3>3.2 Detection &amp; Analysis</h3>
<ul>
  <li>Monitor security alerts from EDR, firewall (${esc(ctx.firewall.vendor || 'perimeter firewall')}), and SIEM</li>
  <li>Employees report suspected incidents to IT immediately via phone or dedicated security channel</li>
  <li>On-call security analyst performs initial triage within response time SLA</li>
  <li>Document: time of detection, affected systems, indicators of compromise (IOCs), initial scope assessment</li>
</ul>

<h3>3.3 Containment</h3>
<div class="callout callout-warn">
  <strong>Critical Decision:</strong> Short-term containment (isolate affected system) vs. long-term containment (rebuild while maintaining evidence). The Incident Commander makes this call based on severity and business impact.
</div>
<ul>
  <li><strong>Short-term:</strong> Isolate affected hosts from network; disable compromised accounts; block malicious IPs at firewall</li>
  <li><strong>Long-term:</strong> Apply patches; change credentials; implement additional monitoring; prepare clean systems</li>
  <li>Preserve forensic evidence: create disk images before remediation; maintain chain of custody</li>
</ul>

<h3>3.4 Eradication &amp; Recovery</h3>
<ul>
  <li>Remove malware, unauthorized access, and root cause from all affected systems</li>
  <li>Restore from known-good backups (${esc(ctx.backups.method || 'approved backup')} — frequency: ${esc(ctx.backups.frequency || 'daily')})</li>
  <li>Verify system integrity before returning to production</li>
  <li>Monitor restored systems with enhanced logging for 30 days</li>
</ul>

<h3>3.5 Post-Incident Activity</h3>
<ul>
  <li>Conduct lessons-learned meeting within 5 business days of incident closure</li>
  <li>Update IRP based on findings; document gaps and remediation actions</li>
  <li>Prepare incident report for management and, if required, regulatory bodies</li>
</ul>

<h2>4. Roles &amp; Responsibilities</h2>
<table>
  <tr><th>Role</th><th>Responsibility</th></tr>
  <tr><td>Incident Commander</td><td>Overall authority during incident; makes containment and escalation decisions</td></tr>
  <tr><td>Security Analyst</td><td>Initial triage, technical investigation, evidence collection</td></tr>
  <tr><td>IT Operations</td><td>System isolation, backup restoration, infrastructure changes</td></tr>
  <tr><td>Communications Lead</td><td>Internal notifications, external communications, regulatory reporting</td></tr>
  <tr><td>Legal / Compliance</td><td>Regulatory notification requirements, legal guidance, evidence preservation</td></tr>
  <tr><td>Executive Management</td><td>Strategic decisions, resource allocation, public communications approval</td></tr>
</table>

<h2>5. Communication Plan</h2>
<table>
  <tr><th>Audience</th><th>When</th><th>Method</th><th>Content</th></tr>
  <tr><td>IR Team</td><td>Immediately upon detection</td><td>Phone / secure messaging</td><td>Full technical details</td></tr>
  <tr><td>Executive Leadership</td><td>Within 1 hour (P1/P2)</td><td>Phone call</td><td>Impact summary, estimated timeline</td></tr>
  <tr><td>Affected Employees</td><td>As determined by IC</td><td>Email / all-hands</td><td>Required actions, status updates</td></tr>
  <tr><td>Regulators / Clients</td><td>Per legal requirements</td><td>Formal written notice</td><td>Per regulatory template</td></tr>
</table>

${ctx.past_incidents.length ? `
<h2>6. Historical Incidents</h2>
<p>The following past incidents inform our current procedures:</p>
<ul>
${ctx.past_incidents.map(inc => `  <li><strong>${esc(inc.year || 'N/A')}:</strong> ${esc(inc.type || inc)} — Severity: ${esc(inc.severity || 'N/A')}. Outcome: ${esc(inc.outcome || 'Resolved')}</li>`).join('\n')}
</ul>` : ''}`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generatePasswordPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This policy defines password and authentication requirements for all systems, applications, and services used by ${esc(ctx.company_name)}. It applies to all employees, contractors, and service accounts.</p>

<h2>2. Password Requirements</h2>
<table>
  <tr><th>Parameter</th><th>Standard User</th><th>Administrator / Privileged</th><th>Service Account</th></tr>
  <tr><td>Minimum Length</td><td>12 characters</td><td>16 characters</td><td>24 characters (auto-generated)</td></tr>
  <tr><td>Complexity</td><td>3 of 4 character types (upper, lower, number, symbol)</td><td>All 4 character types</td><td>Full character set</td></tr>
  <tr><td>Maximum Age</td><td>90 days</td><td>60 days</td><td>365 days (with rotation)</td></tr>
  <tr><td>History</td><td>Last 12 passwords</td><td>Last 24 passwords</td><td>N/A (unique each rotation)</td></tr>
  <tr><td>Lockout Threshold</td><td>5 failed attempts</td><td>3 failed attempts</td><td>3 failed attempts</td></tr>
  <tr><td>Lockout Duration</td><td>15 minutes</td><td>30 minutes + alert</td><td>Manual unlock only</td></tr>
</table>

<h2>3. Multi-Factor Authentication (MFA)</h2>
<div class="callout">
  <strong>MFA is required</strong> for all remote access (${esc(ctx.remote_access.vpn || 'VPN')}), cloud applications, administrative consoles, and email access from non-corporate devices.
</div>
<ul>
  <li>Approved MFA methods: authenticator apps (TOTP), hardware security keys (FIDO2), push notifications</li>
  <li>SMS-based MFA is not approved for privileged accounts due to SIM-swap risks</li>
  <li>MFA enrollment must be completed within 48 hours of account creation</li>
  ${ctx.remote_access.mfa ? `<li>Current VPN MFA status: ${esc(ctx.remote_access.mfa)}</li>` : ''}
</ul>

<h2>4. Prohibited Practices</h2>
<ul>
  <li>Reusing passwords across systems (corporate and personal)</li>
  <li>Sharing passwords with other employees or writing them on physical media</li>
  <li>Storing passwords in plaintext (spreadsheets, text files, emails, sticky notes)</li>
  <li>Using dictionary words, personal information, or common patterns (e.g., "Company2024!")</li>
  <li>Using browser "remember password" on shared or public computers</li>
</ul>

<h2>5. Password Manager</h2>
<p>All employees are required to use the company-approved password manager for storing work-related credentials. The IT department will provide licenses and training during onboarding.</p>
<ul>
  <li>Master password must meet Privileged Account requirements (16+ characters)</li>
  <li>Password manager vault must be backed up by the vendor</li>
  <li>Shared vaults may be used for team-specific credentials with department manager approval</li>
</ul>

<h2>6. Privileged Access Management</h2>
<ul>
  <li>Administrative credentials must be stored in a dedicated PAM solution, separate from standard password manager</li>
  <li>Privileged sessions should be logged and subject to periodic review</li>
  <li>Default and vendor-supplied passwords on all systems (including ${ctx.servers.length ? ctx.servers.slice(0, 3).map(s => esc(s.hostname)).join(', ') : 'servers and network equipment'}) must be changed before deployment</li>
</ul>

<h2>7. Compliance &amp; Enforcement</h2>
<p>Password policies are enforced technically via Active Directory Group Policy and application-level controls. Compliance is audited quarterly. Non-compliance will be addressed through the ${esc(ctx.policy_enforcement || 'standard disciplinary')} process.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateAcceptableUsePolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Acceptable Use Policy (AUP) defines the acceptable and prohibited uses of ${esc(ctx.company_name)}'s information technology resources including computers, networks, email, internet access, and cloud services. This policy applies to all employees, contractors, temporary workers, and any third parties granted access to organizational IT resources.</p>

<h2>2. Acceptable Use</h2>
<h3>2.1 General Principles</h3>
<ul>
  <li>IT resources are provided primarily for business purposes to support ${esc(ctx.company_name)}'s ${esc(ctx.industry)} operations</li>
  <li>Limited personal use is permitted provided it does not interfere with work duties, consume excessive resources, or violate any provision of this policy</li>
  <li>All use of IT resources is subject to monitoring and logging in accordance with applicable law</li>
</ul>

<h3>2.2 Email &amp; Communications</h3>
<ul>
  <li>Corporate email is for business communications; incidental personal use is acceptable</li>
  <li>Emails containing Confidential data must follow the Data Handling Policy</li>
  <li>Auto-forwarding corporate email to personal accounts is prohibited</li>
</ul>

<h3>2.3 Internet &amp; Cloud Services</h3>
<ul>
  <li>Internet access is provided for business use; incidental personal browsing is acceptable during breaks</li>
  <li>Only approved cloud services may be used for business data: ${ctx.saas.length ? ctx.saas.slice(0, 4).map(s => esc(s.name || s.app || s)).join(', ') : 'see approved application list'}</li>
  <li>Use of unapproved cloud storage, file sharing, or AI tools for business data is prohibited</li>
</ul>

<h2>3. Prohibited Activities</h2>
<ul>
  <li>Accessing, downloading, or distributing illegal, offensive, or sexually explicit material</li>
  <li>Installing unauthorized software, browser extensions, or modifying system configurations</li>
  <li>Attempting to bypass security controls, access unauthorized systems, or probe network vulnerabilities</li>
  <li>Using company resources for personal commercial activities, cryptocurrency mining, or gambling</li>
  <li>Connecting personal devices to the corporate network without IT approval</li>
  <li>Sharing login credentials or using another employee's account</li>
  <li>Sending mass unsolicited emails (spam) from company systems</li>
  <li>Using company systems to harass, defame, or discriminate against any individual</li>
</ul>

<h2>4. Software &amp; Licensing</h2>
<ul>
  <li>Only IT-approved software may be installed on company devices</li>
  <li>Software requests must be submitted through the IT service desk</li>
  <li>Using pirated, cracked, or unlicensed software is strictly prohibited and may result in legal liability</li>
  <li>Open-source software must be approved by IT to verify license compatibility</li>
</ul>

<h2>5. Monitoring &amp; Privacy</h2>
<p>${esc(ctx.company_name)} reserves the right to monitor all use of its IT resources including but not limited to email, internet traffic, file access, and application usage. Employees should have no expectation of privacy when using company-owned systems or networks.</p>
<p>Monitoring data is reviewed by authorized IT security personnel only and is handled in accordance with applicable privacy regulations.</p>

<h2>6. Enforcement</h2>
<p>Violations of this policy may result in:</p>
<ol>
  <li>Verbal warning and documented counseling</li>
  <li>Written warning with mandatory security awareness retraining</li>
  <li>Temporary or permanent revocation of IT access privileges</li>
  <li>Termination of employment or contract</li>
  <li>Legal action, if warranted</li>
</ol>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateAccessControlPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Access Control Policy establishes requirements for granting, managing, reviewing, and revoking access to ${esc(ctx.company_name)}'s information systems and data. It applies to all systems, applications, network resources, and physical access controls.</p>

<h2>2. Access Control Principles</h2>
<ul>
  <li><strong>Least Privilege:</strong> Users receive only the minimum access necessary to perform their job functions</li>
  <li><strong>Need-to-Know:</strong> Access to sensitive data is restricted to individuals who require it for their specific role</li>
  <li><strong>Separation of Duties:</strong> Critical functions are divided among multiple individuals to prevent fraud and errors</li>
  <li><strong>Default Deny:</strong> Access is denied unless explicitly granted through the approval process</li>
</ul>

<h2>3. Account Management</h2>
<h3>3.1 Account Provisioning</h3>
<ul>
  <li>Access requests must be submitted by the employee's manager via the IT service desk</li>
  <li>Requests must specify systems, access level, and business justification</li>
  <li>Standard role-based access templates exist for common positions</li>
  <li>Privileged (admin) access requires additional approval from IT Security</li>
</ul>

<h3>3.2 Account Modification</h3>
<ul>
  <li>Role changes trigger an access review: previous role access is revoked, new role access is provisioned</li>
  <li>Temporary elevated access may be granted for up to 72 hours with documented approval</li>
</ul>

<h3>3.3 Account Deprovisioning</h3>
<ul>
  <li>Voluntary termination: access revoked on the employee's last day</li>
  <li>Involuntary termination: access revoked immediately upon notification from HR</li>
  <li>Contractor accounts: automatically expire on contract end date; renewal requires new approval</li>
  <li>Accounts inactive for 60 days are automatically disabled; 90 days triggers deletion review</li>
</ul>

<h2>4. Authentication Requirements</h2>
<table>
  <tr><th>System Type</th><th>Authentication Method</th><th>Session Timeout</th></tr>
  <tr><td>Workstations (${ctx.endpoints.windows_desktops ? ctx.endpoints.windows_desktops + ' desktops, ' + (ctx.endpoints.windows_laptops || 0) + ' laptops' : 'all endpoints'})</td><td>Domain credentials + MFA for remote</td><td>15 minutes idle lock</td></tr>
  <tr><td>Servers (${ctx.servers.length || 'production systems'})</td><td>Named admin account + MFA</td><td>10 minutes idle</td></tr>
  <tr><td>Cloud / SaaS Applications</td><td>SSO with MFA where supported</td><td>Per application (max 8 hours)</td></tr>
  <tr><td>VPN (${esc(ctx.remote_access.vpn || 'remote access')})</td><td>Certificate + MFA</td><td>8 hours max, re-auth required</td></tr>
  <tr><td>Network Equipment</td><td>Named admin account, console only from management VLAN</td><td>5 minutes idle</td></tr>
</table>

<h2>5. Access Reviews</h2>
<ul>
  <li>Standard user access: reviewed semi-annually by department managers</li>
  <li>Privileged access: reviewed quarterly by IT Security</li>
  <li>Service accounts: reviewed annually with documented business justification</li>
  <li>Third-party access: reviewed at each contract renewal or quarterly, whichever is sooner</li>
  <li>Review findings must be remediated within 10 business days</li>
</ul>

<h2>6. Remote Access</h2>
<p>Remote access to ${esc(ctx.company_name)}'s network is provided via ${esc(ctx.remote_access.vpn || 'approved VPN solution')}${ctx.remote_access.split_tunnel === false ? ' (full tunnel — split tunneling disabled)' : ''}. Remote access requires MFA and is limited to company-managed devices unless explicitly approved.</p>

<h2>7. Compliance</h2>
<p>This policy supports ${esc(ctx.company_name)}'s ${esc(ctx.framework)} framework alignment${ctx.compliance_focus.length ? ' and addresses requirements from ' + ctx.compliance_focus.map(c => esc(c)).join(', ') : ''}. Access control logs are retained for a minimum of 1 year.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateBusinessContinuityPlan(policyName, ctx) {
  const bc = ctx.business_continuity || {};
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Business Continuity Plan (BCP) ensures ${esc(ctx.company_name)} can maintain or rapidly resume critical business functions following a disruptive event. It covers natural disasters, cyberattacks, infrastructure failures, pandemics, and other scenarios that could interrupt operations.</p>
<p>This plan covers all ${ctx.employees_total} employees across ${esc(ctx.hq_city || 'primary')} operations and associated IT infrastructure.</p>

<h2>2. Recovery Objectives</h2>
<table>
  <tr><th>Metric</th><th>Target</th><th>Description</th></tr>
  <tr><td><strong>Recovery Time Objective (RTO)</strong></td><td>${bc.rto_hours ? bc.rto_hours + ' hours' : '4–8 hours'}</td><td>Maximum acceptable downtime before critical systems must be restored</td></tr>
  <tr><td><strong>Recovery Point Objective (RPO)</strong></td><td>${bc.rpo_hours ? bc.rpo_hours + ' hours' : '1–4 hours'}</td><td>Maximum acceptable data loss measured in time</td></tr>
  <tr><td><strong>Estimated Downtime Cost</strong></td><td>${bc.estimated_downtime_cost_per_hour ? '$' + bc.estimated_downtime_cost_per_hour.toLocaleString() + '/hour' : 'To be assessed'}</td><td>Financial impact per hour of complete outage</td></tr>
</table>

<h2>3. Critical Business Functions</h2>
<table>
  <tr><th>Priority</th><th>Function</th><th>Dependencies</th><th>Recovery Target</th></tr>
  <tr><td>P1</td><td>Core ${esc(ctx.industry)} operations</td><td>${ctx.servers.length ? ctx.servers.slice(0, 2).map(s => esc(s.hostname)).join(', ') : 'Primary servers'}, network connectivity</td><td>Within RTO</td></tr>
  <tr><td>P1</td><td>Email &amp; communications</td><td>Cloud services, internet connectivity</td><td>Within 2 hours</td></tr>
  <tr><td>P2</td><td>Financial systems</td><td>${ctx.saas.length ? esc(ctx.saas.find(s => (s.name || s.app || '').toLowerCase().includes('account'))?.name || ctx.saas[0]?.name || 'Financial SaaS') : 'Financial applications'}</td><td>Within 4 hours</td></tr>
  <tr><td>P2</td><td>Customer-facing services</td><td>Web servers, database, DNS</td><td>Within 4 hours</td></tr>
  <tr><td>P3</td><td>Internal tools &amp; reporting</td><td>Various SaaS, file shares</td><td>Within 24 hours</td></tr>
</table>

<h2>4. Backup &amp; Recovery Strategy</h2>
<ul>
  <li><strong>Backup method:</strong> ${esc(ctx.backups.method || 'Hybrid cloud/local')}</li>
  <li><strong>Backup frequency:</strong> ${esc(ctx.backups.frequency || 'Daily')}</li>
  <li><strong>Immutable backups:</strong> ${ctx.backups.immutability ? 'Yes — protected against ransomware encryption' : 'Not confirmed — recommend enabling'}</li>
  <li><strong>Offsite storage:</strong> ${ctx.backups.offsite ? 'Yes' : 'Not confirmed'}</li>
  <li><strong>Restore testing:</strong> ${esc(ctx.backups.restore_tests || 'Quarterly')}</li>
</ul>

<h2>5. Disaster Scenarios &amp; Response</h2>
<h3>5.1 Ransomware / Major Cyber Incident</h3>
<ol>
  <li>Activate Incident Response Plan; isolate affected systems</li>
  <li>Assess scope: determine which systems and data are affected</li>
  <li>Restore from immutable backups (do NOT pay ransom without executive and legal approval)</li>
  <li>Rebuild affected systems from known-good images</li>
  <li>Engage external forensics as needed</li>
</ol>

<h3>5.2 Facility Loss (Fire, Flood, Natural Disaster)</h3>
<ol>
  <li>Ensure employee safety; activate emergency communication tree</li>
  <li>Activate remote work procedures for all capable employees</li>
  <li>Redirect critical services to cloud / backup site</li>
  <li>Coordinate with facilities management on timeline for physical recovery</li>
</ol>

<h3>5.3 Extended Power / Internet Outage</h3>
<ol>
  <li>Verify UPS runtime for critical systems</li>
  <li>Contact utility provider for estimated restoration</li>
  <li>If outage exceeds 4 hours, activate alternate work arrangements</li>
  <li>Cloud-hosted services remain available via employee mobile / home connections</li>
</ol>

<h2>6. Testing &amp; Maintenance</h2>
<ul>
  <li>Tabletop exercise: semi-annually</li>
  <li>Full BCP simulation: annually</li>
  <li>Backup restore test: ${esc(ctx.backups.restore_tests || 'quarterly')}</li>
  <li>Contact list verification: quarterly</li>
  <li>Plan review and update: annually or after any significant organizational change</li>
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateChangeManagementPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Change Management Policy establishes a standardized process for requesting, evaluating, approving, implementing, and reviewing changes to ${esc(ctx.company_name)}'s IT infrastructure, applications, and configurations. The goal is to minimize disruption while enabling the organization to adapt and improve its technology environment.</p>

<h2>2. Change Categories</h2>
<table>
  <tr><th>Category</th><th>Description</th><th>Approval Required</th><th>Examples</th></tr>
  <tr><td><strong>Standard</strong></td><td>Pre-approved, low-risk, routine changes</td><td>None (pre-approved list)</td><td>Patch Tuesday updates, adding user accounts, printer setup</td></tr>
  <tr><td><strong>Normal</strong></td><td>Planned changes requiring evaluation</td><td>Change Advisory Board (CAB)</td><td>New server deployment, firewall rule changes, application upgrades</td></tr>
  <tr><td><strong>Emergency</strong></td><td>Urgent changes to resolve critical incidents</td><td>Emergency CAB (2 members)</td><td>Zero-day patch, active threat containment, critical service restoration</td></tr>
</table>

<h2>3. Change Request Process</h2>
<ol>
  <li><strong>Request:</strong> Requestor submits change request with description, business justification, affected systems, rollback plan, and proposed schedule</li>
  <li><strong>Review:</strong> IT Security reviews for security implications; IT Operations reviews for infrastructure impact</li>
  <li><strong>Approval:</strong> CAB reviews Normal changes weekly; Emergency changes via expedited process</li>
  <li><strong>Implementation:</strong> Scheduled during approved maintenance window; changes to production require a tested rollback plan</li>
  <li><strong>Verification:</strong> Implementor verifies change was successful; monitoring for unexpected impacts for 24 hours</li>
  <li><strong>Closure:</strong> Documentation updated; change request closed with actual outcomes</li>
</ol>

<h2>4. Change Windows</h2>
<ul>
  <li><strong>Standard maintenance window:</strong> Saturday 10:00 PM – Sunday 6:00 AM (local time)</li>
  <li><strong>Emergency changes:</strong> May be implemented outside maintenance windows with Emergency CAB approval</li>
  <li><strong>Blackout periods:</strong> No non-emergency changes during month-end close, fiscal year-end, or peak business periods</li>
</ul>

<h2>5. Rollback Requirements</h2>
<ul>
  <li>Every Normal and Emergency change must have a documented rollback plan</li>
  <li>Rollback must be tested (where feasible) before the change window</li>
  <li>If a change causes unexpected issues, rollback is initiated within 30 minutes unless the change owner can demonstrate a fix is imminent</li>
  <li>System backups must be verified before implementing changes to critical systems${ctx.servers.length ? ' (' + ctx.servers.slice(0, 3).map(s => esc(s.hostname)).join(', ') + ', etc.)' : ''}</li>
</ul>

<h2>6. Documentation &amp; Audit</h2>
<ul>
  <li>All changes are logged in the IT service management system with full audit trail</li>
  <li>Failed changes are documented with root cause analysis</li>
  <li>Change success rate is reported monthly to IT management</li>
  <li>Unauthorized changes are treated as security incidents and escalated per the Incident Response Plan</li>
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateInfoSecPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Information Security Policy establishes the overarching framework for protecting the confidentiality, integrity, and availability of information assets at ${esc(ctx.company_name)}. It serves as the foundation for all subordinate security policies, standards, and procedures.</p>
<p>This policy applies to all employees (${ctx.employees_total}), contractors, business partners, and any party with access to ${esc(ctx.company_name)}'s information assets.</p>

<h2>2. Information Security Objectives</h2>
<ul>
  <li>Protect sensitive business and client information from unauthorized access, disclosure, or modification</li>
  <li>Ensure compliance with applicable regulatory and contractual requirements${ctx.compliance_focus.length ? ' including ' + ctx.compliance_focus.map(c => esc(c)).join(', ') : ''}</li>
  <li>Maintain availability of critical business systems and data per defined recovery objectives</li>
  <li>Foster a security-aware culture through training, awareness, and accountability</li>
  <li>Continuously improve the security posture through regular assessment and risk management</li>
</ul>

<h2>3. Security Framework</h2>
<p>${esc(ctx.company_name)} has adopted the <strong>${esc(ctx.framework)}</strong> approach to information security. Security controls are selected and implemented based on risk assessment, business requirements, and regulatory obligations.</p>
<div class="callout">
  <strong>Risk Tolerance:</strong> ${esc(ctx.risk_tolerance)}. Security investments are prioritized based on risk impact and likelihood, focusing resources on protecting the most critical assets and addressing the highest-probability threats.
</div>

<h2>4. Security Domains</h2>
<table>
  <tr><th>Domain</th><th>Key Controls</th><th>Subordinate Policy</th></tr>
  <tr><td>Access Control</td><td>Least privilege, MFA, regular access reviews</td><td>Access Control Policy</td></tr>
  <tr><td>Data Protection</td><td>Classification, encryption, DLP, retention</td><td>Data Handling Policy</td></tr>
  <tr><td>Network Security</td><td>Firewall (${esc(ctx.firewall.vendor || 'perimeter')}), segmentation, monitoring</td><td>Network Security Policy</td></tr>
  <tr><td>Endpoint Security</td><td>${esc(ctx.endpoint_protection.product || 'EDR')}, patching (${esc(ctx.patch_management.method || 'managed')})</td><td>Endpoint Management Standard</td></tr>
  <tr><td>Incident Response</td><td>Detection, containment, recovery, lessons learned</td><td>Incident Response Plan</td></tr>
  <tr><td>Business Continuity</td><td>Backups (${esc(ctx.backups.frequency || 'regular')}), DR testing, alternate operations</td><td>Business Continuity Plan</td></tr>
  <tr><td>Security Awareness</td><td>Onboarding training, phishing simulations, annual refresher</td><td>Security Awareness Program</td></tr>
</table>

<h2>5. Roles &amp; Responsibilities</h2>
<table>
  <tr><th>Role</th><th>Responsibility</th></tr>
  <tr><td>Executive Leadership</td><td>Approve security strategy, allocate budget, set risk tolerance</td></tr>
  <tr><td>IT Security / CISO</td><td>Develop and enforce policies, conduct risk assessments, manage incidents, report to leadership</td></tr>
  <tr><td>IT Operations</td><td>Implement and maintain technical controls, patch management, system hardening</td></tr>
  <tr><td>Department Managers</td><td>Ensure team compliance, manage access requests, participate in risk assessments</td></tr>
  <tr><td>All Employees</td><td>Follow security policies, complete training, report incidents and suspicious activity</td></tr>
</table>

<h2>6. Risk Assessment</h2>
<ul>
  <li>Formal risk assessments are conducted annually or upon significant changes to the business or IT environment</li>
  <li>Vulnerability assessments and penetration testing are performed at least annually</li>
  <li>Identified risks are documented in a risk register with assigned owners, treatment plans, and target dates</li>
  <li>Risk acceptance requires documented approval from executive leadership for any risk rated High or Critical</li>
</ul>

<h2>7. Policy Compliance &amp; Review</h2>
<p>Compliance with this policy is mandatory. Enforcement: ${esc(ctx.policy_enforcement)}. This policy is reviewed annually, or upon significant changes to the threat landscape, regulatory environment, or organizational structure.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateNetworkSecurityPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Network Security Policy defines requirements for the design, implementation, and management of ${esc(ctx.company_name)}'s network infrastructure to protect against unauthorized access, data interception, and network-based attacks.</p>

<h2>2. Network Architecture</h2>
<h3>2.1 Segmentation</h3>
<ul>
  <li>The network must be segmented into distinct security zones based on data sensitivity and function</li>
  <li>Critical servers${ctx.servers.length ? ' (' + ctx.servers.filter(s => s.role && (s.role.includes('Domain') || s.role.includes('Database'))).slice(0, 2).map(s => esc(s.hostname)).join(', ') + ')' : ''} must reside on dedicated VLANs separate from user workstations</li>
  <li>Guest and IoT networks must be isolated from the corporate network with no direct access to internal resources</li>
  ${ctx.subnets.length ? `<li>Current subnet allocation: ${ctx.subnets.slice(0, 4).map(s => esc(s.name || s.subnet || s)).join(', ')}</li>` : ''}
</ul>

<h3>2.2 Perimeter Security</h3>
<ul>
  <li>All internet traffic must pass through the perimeter firewall (${esc(ctx.firewall.vendor || 'enterprise-grade')})</li>
  <li>Default-deny rule set: only explicitly permitted traffic is allowed inbound and outbound</li>
  <li>Firewall rules must be reviewed quarterly and unused rules removed</li>
  <li>Intrusion Detection/Prevention (IDS/IPS) must be active on the perimeter</li>
</ul>

<h2>3. Wireless Network Security</h2>
<ul>
  <li>Corporate wireless: WPA3-Enterprise with RADIUS authentication; fallback to WPA2-Enterprise where WPA3 is unsupported</li>
  <li>Guest wireless: isolated VLAN, internet-only access, captive portal with acceptable use agreement</li>
  <li>Rogue access point detection must be enabled</li>
  <li>Wi-Fi passwords (PSK) for any shared networks must be rotated quarterly</li>
</ul>

<h2>4. Remote Access</h2>
<ul>
  <li>Remote access is provided via ${esc(ctx.remote_access.vpn || 'approved VPN solution')}${ctx.remote_access.split_tunnel === false ? ' with full tunnel (split tunneling disabled)' : ''}</li>
  <li>All remote connections require multi-factor authentication</li>
  <li>Remote access logs are retained for a minimum of 90 days and reviewed monthly</li>
  <li>Personal devices may access corporate resources only through approved virtual desktop or web-based solutions</li>
</ul>

<h2>5. Network Monitoring &amp; Logging</h2>
<ul>
  <li>All firewall, switch, and router logs must be forwarded to a centralized logging solution</li>
  <li>Network traffic anomalies must be investigated within 4 hours of alert generation</li>
  <li>DNS queries should be logged and monitored for indicators of compromise</li>
  <li>NetFlow or equivalent traffic analysis should be enabled on core network segments</li>
</ul>

<h2>6. DNS, DHCP &amp; Network Services</h2>
<ul>
  <li>Internal DNS must be configured to resolve only approved domains; DNS filtering for malicious domains is required</li>
  <li>DHCP servers must be authorized in Active Directory; rogue DHCP detection must be enabled</li>
  <li>Network Time Protocol (NTP) must be synchronized to reliable time sources for accurate logging</li>
</ul>

<h2>7. Compliance</h2>
<p>Network security controls support ${esc(ctx.company_name)}'s ${esc(ctx.framework)} framework. Network penetration testing is conducted at least annually by qualified assessors. Findings are remediated per the following SLAs: Critical — 72 hours, High — 2 weeks, Medium — 30 days, Low — 90 days.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateRemoteWorkPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This policy establishes security requirements for employees of ${esc(ctx.company_name)} who work remotely, whether from home, travel locations, or other non-office environments. It also covers Bring Your Own Device (BYOD) requirements where applicable.</p>

<h2>2. Eligibility &amp; Approval</h2>
<ul>
  <li>Remote work eligibility is determined by department managers based on role requirements</li>
  <li>Employees must acknowledge this policy before being granted remote access</li>
  <li>Remote work arrangements must be reviewed annually</li>
</ul>

<h2>3. Secure Connection Requirements</h2>
<ul>
  <li>All remote work must use the company VPN (${esc(ctx.remote_access.vpn || 'approved solution')}) to access internal resources</li>
  ${ctx.remote_access.split_tunnel === false ? '<li>Split tunneling is disabled — all traffic routes through corporate network for security monitoring</li>' : '<li>Split tunneling may be enabled for approved cloud applications only</li>'}
  <li>Multi-factor authentication is required for all remote access sessions</li>
  <li>Public Wi-Fi must never be used to access company resources without VPN</li>
</ul>

<h2>4. Device Security</h2>
<h3>4.1 Company-Issued Devices</h3>
<ul>
  <li>Must have ${esc(ctx.endpoint_protection.product || 'approved endpoint protection')} installed and active</li>
  <li>Must have full-disk encryption enabled</li>
  <li>Must receive patches per the standard patch management cycle (${esc(ctx.patch_management.method || 'managed')})</li>
  <li>Must have automatic screen lock after 5 minutes of inactivity</li>
  <li>Must not be used by family members or unauthorized individuals</li>
</ul>

<h3>4.2 BYOD (Personal Devices)</h3>
<ul>
  <li>Personal devices may access company email and approved SaaS applications through web browser only</li>
  <li>Company data must not be downloaded or stored locally on personal devices</li>
  <li>Personal devices must have a screen lock and current OS version</li>
  <li>${esc(ctx.company_name)} reserves the right to remotely wipe company data from BYOD devices upon termination</li>
</ul>

<h2>5. Physical Security for Remote Work</h2>
<ul>
  <li>Work area must be private — screen not visible to unauthorized persons</li>
  <li>Confidential documents must not be printed at home unless necessary; if printed, must be securely destroyed</li>
  <li>Company equipment must be stored securely when not in use (locked room or drawer)</li>
  <li>Video calls involving sensitive information must be conducted in a private setting</li>
</ul>

<h2>6. Data Handling</h2>
<ul>
  <li>All data handling follows the Data Handling Policy regardless of work location</li>
  <li>Company data must remain on company-approved storage and cloud services</li>
  <li>Personal cloud storage (Google Drive personal, Dropbox personal, etc.) must not be used for company data</li>
  <li>USB drives and external storage must not be used without IT approval</li>
</ul>

<h2>7. Incident Reporting</h2>
<p>Remote workers must immediately report lost/stolen devices, suspected compromises, or security incidents to IT Security. A lost laptop or phone is a <strong>Priority 2</strong> security incident requiring immediate response.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateVendorRiskPolicy(policyName, ctx) {
  const vr = ctx.vendor_risk || {};
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This policy establishes requirements for assessing, managing, and monitoring the security risks associated with third-party vendors, service providers, and business partners who access, process, or store ${esc(ctx.company_name)}'s data or connect to its systems.</p>

<h2>2. Vendor Risk Assessment</h2>
<h3>2.1 Risk Tiering</h3>
<table>
  <tr><th>Tier</th><th>Criteria</th><th>Assessment Depth</th><th>Review Frequency</th></tr>
  <tr><td><strong>Critical</strong></td><td>Accesses confidential data; critical to operations; network connectivity</td><td>Full security assessment + SOC 2 / ISO 27001 review</td><td>Annually</td></tr>
  <tr><td><strong>High</strong></td><td>Accesses internal data; supports important functions</td><td>Security questionnaire + evidence review</td><td>Annually</td></tr>
  <tr><td><strong>Medium</strong></td><td>Limited data access; standard business services</td><td>Self-attestation questionnaire</td><td>Every 2 years</td></tr>
  <tr><td><strong>Low</strong></td><td>No data access; no system connectivity</td><td>Standard contract terms</td><td>At renewal</td></tr>
</table>

<h3>2.2 Assessment Process</h3>
<ol>
  <li>Business owner submits vendor engagement request with scope of services and data involved</li>
  <li>IT Security assigns risk tier based on data access and system connectivity</li>
  <li>Vendor completes appropriate assessment (questionnaire, SOC report, penetration test results)</li>
  <li>IT Security reviews and documents findings, identifies residual risks</li>
  <li>Approval or rejection communicated to business owner; approved vendors added to vendor register</li>
</ol>

${ctx.vendor_dependencies.length ? `
<h2>3. Current Vendor Inventory (Key Dependencies)</h2>
<table>
  <tr><th>Vendor / Service</th><th>Category</th><th>Data Access</th></tr>
${ctx.vendor_dependencies.slice(0, 8).map(v => {
  const name = typeof v === 'string' ? v : (v.name || v.vendor || 'Unknown');
  const cat = typeof v === 'string' ? 'Service Provider' : (v.category || v.type || 'Service Provider');
  const access = typeof v === 'string' ? 'Varies' : (v.data_access || v.access || 'Varies');
  return `  <tr><td>${esc(name)}</td><td>${esc(cat)}</td><td>${esc(access)}</td></tr>`;
}).join('\n')}
</table>` : `
<h2>3. Vendor Register</h2>
<p>All vendors with access to ${esc(ctx.company_name)} data or systems must be recorded in the vendor register maintained by IT Security. The register includes vendor name, services provided, data classification accessed, risk tier, assessment status, contract dates, and primary contacts.</p>`}

<h2>4. Contractual Requirements</h2>
<p>All vendor contracts must include the following security provisions:</p>
<ul>
  <li>Data protection and confidentiality obligations</li>
  <li>Right to audit (or SOC 2 / equivalent certification requirement)</li>
  <li>Incident notification within 24 hours of any breach affecting ${esc(ctx.company_name)} data</li>
  <li>Data return and secure destruction upon contract termination</li>
  <li>Compliance with applicable regulations${ctx.compliance_focus.length ? ' including ' + ctx.compliance_focus.map(c => esc(c)).join(', ') : ''}</li>
  <li>Limitation on subcontractor use without prior approval</li>
</ul>

<h2>5. Ongoing Monitoring</h2>
<ul>
  <li>Critical and High vendors are monitored for security incidents via threat intelligence feeds</li>
  <li>Vendor access is reviewed quarterly and revoked when no longer needed</li>
  <li>Changes to vendor services or data scope trigger reassessment</li>
  <li>Vendor security incidents are tracked and factored into renewal decisions</li>
</ul>

<h2>6. Vendor Offboarding</h2>
<ul>
  <li>All access credentials and VPN connections revoked on contract end date</li>
  <li>Vendor confirms data return or certified destruction within 30 days</li>
  <li>Post-engagement review documented in vendor register</li>
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateDataRetentionPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Data Retention Policy defines the retention periods and disposal requirements for ${esc(ctx.company_name)}'s business records and data. It ensures compliance with legal, regulatory, and operational requirements while minimizing risk from retaining data longer than necessary.</p>

<h2>2. Retention Schedule</h2>
<table>
  <tr><th>Data Category</th><th>Retention Period</th><th>Storage Location</th><th>Disposal Method</th></tr>
  <tr><td>Financial records (tax, audit)</td><td>7 years</td><td>Secure file server / cloud archive</td><td>Certified destruction</td></tr>
  <tr><td>Employee HR records</td><td>7 years post-separation</td><td>HRIS / secure storage</td><td>Secure wipe + shred</td></tr>
  <tr><td>Client contracts</td><td>Duration + 6 years</td><td>Document management system</td><td>Certified destruction</td></tr>
  <tr><td>Client PII / sensitive data</td><td>Duration of relationship + 3 years</td><td>Encrypted database</td><td>Secure wipe</td></tr>
  <tr><td>Email communications</td><td>3 years (5 years for management)</td><td>Email archive</td><td>Automated purge</td></tr>
  <tr><td>Security logs &amp; audit trails</td><td>1 year minimum (3 years recommended)</td><td>SIEM / log management</td><td>Automated rotation</td></tr>
  <tr><td>Backup media</td><td>Per backup schedule, max 1 year for archives</td><td>${esc(ctx.backups.method || 'Backup infrastructure')}</td><td>Secure wipe / degauss</td></tr>
  <tr><td>CCTV / physical security footage</td><td>90 days</td><td>Local NVR / cloud storage</td><td>Automated overwrite</td></tr>
</table>

<h2>3. Legal Hold</h2>
<p>When litigation, investigation, or audit is anticipated or in progress, a legal hold notice suspends normal retention schedules for relevant data. Legal holds are issued by Legal/Compliance and must be followed immediately. Destroying data subject to legal hold is a serious violation.</p>

<h2>4. Data Disposal Procedures</h2>
<ul>
  <li><strong>Electronic data:</strong> NIST SP 800-88 compliant secure erasure, or physical destruction of media</li>
  <li><strong>Paper records:</strong> Cross-cut shredding (DIN 66399 Level P-4 minimum)</li>
  <li><strong>Hardware:</strong> Degaussing + physical destruction for drives containing Confidential data; certificate of destruction retained</li>
  <li><strong>Cloud data:</strong> Verify deletion from all replicas; request vendor confirmation</li>
</ul>

<h2>5. Responsibilities</h2>
<ul>
  <li><strong>Data Owners:</strong> Ensure data within their scope follows the retention schedule</li>
  <li><strong>IT Department:</strong> Implement automated retention and disposal for electronic systems</li>
  <li><strong>Legal / Compliance:</strong> Issue legal holds; update retention schedule for regulatory changes</li>
  <li><strong>All Employees:</strong> Do not retain business data in personal storage; follow disposal procedures</li>
</ul>

<h2>6. Compliance</h2>
<p>This policy is reviewed annually to ensure alignment with current regulatory requirements${ctx.compliance_focus.length ? ' including ' + ctx.compliance_focus.map(c => esc(c)).join(', ') : ''}. Retention compliance is audited semi-annually.</p>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateTrainingPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This policy establishes the cybersecurity awareness and training program for ${esc(ctx.company_name)}. Security awareness is a critical control — human error is involved in the majority of security incidents. All ${ctx.employees_total} employees, contractors, and temporary workers must participate.</p>

<h2>2. Training Requirements</h2>
<table>
  <tr><th>Training Type</th><th>Audience</th><th>Frequency</th><th>Duration</th></tr>
  <tr><td>Security Awareness Orientation</td><td>New hires (within 30 days)</td><td>Upon onboarding</td><td>60 minutes</td></tr>
  <tr><td>Annual Security Refresher</td><td>All employees</td><td>Annually</td><td>45-60 minutes</td></tr>
  <tr><td>Phishing Simulation</td><td>All employees</td><td>Monthly</td><td>N/A (simulated attack)</td></tr>
  <tr><td>Role-Based Technical Training</td><td>IT staff, developers, admins</td><td>Annually + as needed</td><td>4-8 hours</td></tr>
  <tr><td>Executive Security Briefing</td><td>C-suite, board members</td><td>Quarterly</td><td>30 minutes</td></tr>
  <tr><td>Incident Response Drill</td><td>IR team + managers</td><td>Semi-annually</td><td>2-4 hours</td></tr>
</table>

<h2>3. Core Training Topics</h2>
<h3>3.1 All Employees</h3>
<ul>
  <li>Recognizing phishing, vishing, and social engineering attacks</li>
  <li>Password hygiene and multi-factor authentication</li>
  <li>Safe internet and email use</li>
  <li>Data classification and handling</li>
  <li>Physical security awareness (tailgating, clean desk, visitor management)</li>
  <li>Incident reporting procedures — when and how to report</li>
  <li>Remote work and mobile device security</li>
</ul>

<h3>3.2 Technical Staff (Additional)</h3>
<ul>
  <li>Secure coding practices and OWASP Top 10</li>
  <li>Cloud security configuration (for ${esc(ctx.delivery)} environments)</li>
  <li>Log analysis and threat hunting fundamentals</li>
  <li>Vulnerability management and patch prioritization</li>
</ul>

<h2>4. Phishing Simulation Program</h2>
<ul>
  <li>Monthly simulated phishing campaigns of increasing sophistication</li>
  <li>Employees who click are automatically enrolled in targeted remedial training</li>
  <li>Repeated failures (3+ in 6 months) escalated to department manager for counseling</li>
  <li>Click rates tracked and reported to management monthly; organizational goal: &lt;5% click rate</li>
  <li>Results are anonymized for organizational reporting; individual results shared only with direct manager</li>
</ul>

<h2>5. Training Delivery &amp; Tracking</h2>
<ul>
  <li>Training delivered via approved learning management system (LMS)</li>
  <li>Completion tracked automatically; reminders sent at 7, 3, and 1 days before deadline</li>
  <li>Employees who fail to complete required training within 30 days of deadline will have non-essential IT access restricted until training is completed</li>
  <li>Training records retained for 3 years for compliance auditing</li>
</ul>

<h2>6. Metrics &amp; Reporting</h2>
<ul>
  <li>Training completion rate (target: 100% within 30 days of due date)</li>
  <li>Phishing simulation click rate (target: &lt;5%)</li>
  <li>Report rate for phishing simulations (target: &gt;50%)</li>
  <li>Number of security incidents attributed to human error (track trend)</li>
  <li>Results reported to executive leadership quarterly</li>
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateCloudSecurityPolicy(policyName, ctx) {
  const cloudApps = ctx.saas.filter(s => s.name || s.app).slice(0, 6);
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Cloud Security Policy defines requirements for the secure adoption, configuration, and management of cloud services used by ${esc(ctx.company_name)}. It covers Infrastructure as a Service (IaaS), Platform as a Service (PaaS), and Software as a Service (SaaS) environments.</p>

<h2>2. Cloud Service Approval</h2>
<ul>
  <li>All cloud services must be evaluated and approved by IT Security before adoption</li>
  <li>Shadow IT (use of unapproved cloud services for business data) is prohibited</li>
  <li>Evaluation criteria: data handling practices, encryption capabilities, compliance certifications, incident response procedures, data residency</li>
</ul>

${cloudApps.length ? `
<h2>3. Approved Cloud Services</h2>
<table>
  <tr><th>Service</th><th>Category</th><th>MFA Status</th></tr>
${cloudApps.map(s => {
  const name = s.name || s.app || 'Unknown';
  const cat = s.category || s.type || 'SaaS';
  const mfa = s.mfa === false ? '<span style="color:#e53e3e">Not Enabled</span>' : (s.mfa || 'Enabled');
  return `  <tr><td>${esc(name)}</td><td>${esc(cat)}</td><td>${mfa}</td></tr>`;
}).join('\n')}
</table>
<div class="callout callout-warn">
  Any cloud services not on this list must go through the approval process before use. Using unapproved services for business data is a policy violation.
</div>` : `
<h2>3. Approved Services</h2>
<p>A current list of approved cloud services is maintained by IT Security and published on the internal portal. All employees must verify a service is on the approved list before using it for business data.</p>`}

<h2>4. Security Requirements for Cloud Services</h2>
<h3>4.1 Identity &amp; Access</h3>
<ul>
  <li>SSO (Single Sign-On) integration is required for all SaaS applications where supported</li>
  <li>MFA is mandatory for all cloud service accounts, especially administrator accounts</li>
  <li>Service accounts must use API keys or OAuth tokens (never shared passwords)</li>
  <li>Access reviews conducted per the Access Control Policy</li>
</ul>

<h3>4.2 Data Protection</h3>
<ul>
  <li>Data must be encrypted in transit (TLS 1.2+) and at rest</li>
  <li>Confidential data may only be stored in cloud services that meet encryption and residency requirements</li>
  <li>Data Loss Prevention (DLP) controls should be enabled where available</li>
  <li>Cloud storage sharing links must be set to "specific people" — never "anyone with the link" for internal data</li>
</ul>

<h3>4.3 Configuration &amp; Hardening</h3>
<ul>
  <li>Cloud environments must follow vendor security best practices and CIS benchmarks</li>
  <li>Default configurations must be reviewed and hardened before deployment</li>
  <li>Administrative access to cloud management consoles requires MFA and is limited to designated personnel</li>
  <li>Logging and monitoring must be enabled for all cloud environments</li>
</ul>

<h2>5. Cloud Data Lifecycle</h2>
<ul>
  <li>Data stored in cloud must follow the Data Retention Policy</li>
  <li>Before decommissioning a cloud service, all data must be exported or migrated</li>
  <li>Vendor must provide confirmation of data deletion upon service termination</li>
  <li>Backups of cloud-hosted data: ${esc(ctx.backups.method || 'per backup policy')}</li>
</ul>

<h2>6. Incident Response in Cloud</h2>
<ul>
  <li>Cloud security incidents follow the standard Incident Response Plan</li>
  <li>IT Security maintains API access to cloud services for investigation and containment</li>
  <li>Vendor SLA for security incident notification: 24 hours maximum</li>
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generatePhysicalSecurityPolicy(policyName, ctx) {
  const ps = ctx.physical_security || {};
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This Physical Security Policy establishes requirements for protecting ${esc(ctx.company_name)}'s facilities, equipment, and personnel from unauthorized physical access, theft, and environmental threats. It applies to all company facilities${ctx.hq_city ? ' including the ' + esc(ctx.hq_city) + ' headquarters' : ''} and any locations housing company IT assets.</p>

<h2>2. Facility Access Controls</h2>
<table>
  <tr><th>Zone</th><th>Description</th><th>Access Control</th><th>Monitoring</th></tr>
  <tr><td><strong>Public</strong></td><td>Reception, lobby, public areas</td><td>Open during business hours</td><td>CCTV, reception desk</td></tr>
  <tr><td><strong>Controlled</strong></td><td>Office areas, conference rooms</td><td>${esc(ps.badge_access || 'Badge/key card access')}</td><td>CCTV at entry points</td></tr>
  <tr><td><strong>Restricted</strong></td><td>Server room, network closets, executive offices</td><td>Badge + PIN or biometric; access logged</td><td>CCTV + motion sensors</td></tr>
  <tr><td><strong>High Security</strong></td><td>Data center (if applicable)</td><td>Multi-factor physical access; escort required for visitors</td><td>CCTV + 24/7 monitoring</td></tr>
</table>

<h2>3. Server Room / Network Closet Security</h2>
<ul>
  <li>Access limited to authorized IT personnel — access list reviewed quarterly</li>
  <li>${esc(ps.server_room_lock || 'Badge access with PIN or key lock')} required for entry</li>
  <li>Environmental controls: HVAC for temperature/humidity, fire suppression, water leak detection</li>
  <li>UPS and surge protection for all critical equipment</li>
  <li>No food, drink, or personal items in server rooms</li>
  <li>All entry/exit events logged and retained for 90 days</li>
</ul>

<h2>4. Visitor Management</h2>
<ul>
  <li>All visitors must sign in at reception and receive a visitor badge</li>
  <li>Visitors must be escorted by an employee at all times in Controlled and Restricted zones</li>
  <li>Visitor badges must be visually distinct from employee badges</li>
  <li>Visitor logs retained for 1 year</li>
  <li>Vendor/contractor regular visitors may receive temporary badges with pre-approved access, reviewed monthly</li>
</ul>

<h2>5. Clean Desk &amp; Screen Lock</h2>
<ul>
  <li>Employees must lock their workstations when leaving their desk (Windows + L / Ctrl + Command + Q)</li>
  <li>Confidential documents must not be left on desks overnight — lock in drawers or cabinets</li>
  <li>Whiteboards containing sensitive information must be erased after meetings</li>
  <li>Printers: confidential print jobs should use "secure print" requiring badge/PIN at the printer</li>
</ul>

<h2>6. Surveillance</h2>
<ul>
  <li>${esc(ps.cameras || 'CCTV cameras')} installed at all entry/exit points, server rooms, and parking areas</li>
  <li>Footage retained for a minimum of 90 days</li>
  <li>Camera system access restricted to Security and IT administration</li>
  <li>Camera placement respects employee privacy (no cameras in restrooms, break rooms, or private offices)</li>
</ul>

<h2>7. Equipment &amp; Asset Protection</h2>
<ul>
  <li>All company-issued devices are tracked in the asset management system</li>
  <li>Laptops must use cable locks when left unattended in open office areas</li>
  <li>Equipment removal from premises requires documented approval</li>
  <li>Lost or stolen equipment must be reported within 1 hour to IT Security</li>
  <li>Decommissioned equipment follows the Data Retention Policy disposal procedures</li>
</ul>

<h2>8. Emergency Procedures</h2>
<ul>
  <li>Emergency exits must be clearly marked and unobstructed</li>
  <li>Fire drills conducted semi-annually</li>
  <li>Emergency contact numbers posted in all common areas</li>
  <li>First aid kits and AED devices maintained per regulatory requirements</li>
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


function generateGenericPolicy(policyName, ctx) {
  const body = `
<h2>1. Purpose &amp; Scope</h2>
<p>This policy establishes the requirements and guidelines for ${esc(policyName.toLowerCase())} at ${esc(ctx.company_name)}. It applies to all employees, contractors, and third parties operating within or on behalf of the organization.</p>
<p>As a ${esc(ctx.industry)} organization with ${ctx.employees_total} employees, ${esc(ctx.company_name)} recognizes the importance of establishing clear policies that protect the organization, its clients, and its employees.</p>

<h2>2. Policy Statement</h2>
<p>${esc(ctx.company_name)} is committed to maintaining standards aligned with its ${esc(ctx.framework)} security framework. This policy supports organizational objectives by providing clear direction, establishing accountability, and ensuring consistent application of controls.</p>

<h2>3. Roles &amp; Responsibilities</h2>
<table>
  <tr><th>Role</th><th>Responsibility</th></tr>
  <tr><td>Executive Leadership</td><td>Approve policy; allocate resources for implementation; set organizational direction</td></tr>
  <tr><td>IT / Security Department</td><td>Implement technical controls; monitor compliance; report on effectiveness</td></tr>
  <tr><td>Department Managers</td><td>Ensure team awareness and compliance; report gaps and issues</td></tr>
  <tr><td>All Employees</td><td>Read, understand, and follow this policy; report violations or concerns</td></tr>
</table>

<h2>4. Requirements</h2>
<ul>
  <li>All applicable controls must be implemented within 90 days of policy approval</li>
  <li>Existing processes must be reviewed and updated to align with this policy</li>
  <li>Documentation of compliance must be maintained and available for audit</li>
  <li>Exceptions require written approval from the policy owner with documented risk acceptance</li>
</ul>

<h2>5. Compliance &amp; Enforcement</h2>
<p>Compliance with this policy is mandatory. Enforcement: ${esc(ctx.policy_enforcement)}. Violations may result in disciplinary action up to and including termination of employment or contract. This policy is reviewed annually or upon significant organizational or regulatory changes.</p>

<h2>6. Related Documents</h2>
<ul>
  ${ctx.policies_present.filter(p => p !== policyName).slice(0, 5).map(p => `<li>${esc(p)}</li>`).join('\n  ')}
  ${ctx.policies_present.length <= 1 ? '<li>Information Security Policy</li><li>Acceptable Use Policy</li>' : ''}
</ul>`;

  return { name: policyName, slug: slugify(policyName), html: buildPolicyHTML(policyName, ctx, body) };
}


// ============================================================================
// POLICY REGISTRY
// ============================================================================

const POLICY_REGISTRY = {
  'data handling':            generateDataHandlingPolicy,
  'data protection':          generateDataHandlingPolicy,
  'incident response':        generateIncidentResponsePlan,
  'password':                 generatePasswordPolicy,
  'authentication':           generatePasswordPolicy,
  'acceptable use':           generateAcceptableUsePolicy,
  'access control':           generateAccessControlPolicy,
  'business continuity':      generateBusinessContinuityPlan,
  'disaster recovery':        generateBusinessContinuityPlan,
  'change management':        generateChangeManagementPolicy,
  'information security':     generateInfoSecPolicy,
  'cybersecurity policy':     generateInfoSecPolicy,
  'network security':         generateNetworkSecurityPolicy,
  'remote work':              generateRemoteWorkPolicy,
  'byod':                     generateRemoteWorkPolicy,
  'work from home':           generateRemoteWorkPolicy,
  'vendor':                   generateVendorRiskPolicy,
  'third-party':              generateVendorRiskPolicy,
  'supplier':                 generateVendorRiskPolicy,
  'data retention':           generateDataRetentionPolicy,
  'record retention':         generateDataRetentionPolicy,
  'training':                 generateTrainingPolicy,
  'cybersecurity training':   generateTrainingPolicy,
  'security awareness':       generateTrainingPolicy,
  'cloud security':           generateCloudSecurityPolicy,
  'cloud standards':          generateCloudSecurityPolicy,
  'physical security':        generatePhysicalSecurityPolicy,
};

function findGenerator(policyName) {
  const lower = policyName.toLowerCase();
  for (const [key, gen] of Object.entries(POLICY_REGISTRY)) {
    if (lower.includes(key)) return gen;
  }
  return null;
}


// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Generate all policy documents for a profile.
 * @param {Object} profileJson - The full profile JSON (student_view.raw structure)
 * @returns {{ policies: Array<{name, slug, html}>, company_name: string, total_count: number }}
 */
function generatePolicies(profileJson) {
  const ctx = buildContext(profileJson);

  const policies = [];
  for (const policyName of ctx.policies_present) {
    const generator = findGenerator(policyName) || generateGenericPolicy;
    policies.push(generator(policyName, ctx));
  }

  return {
    policies,
    company_name: ctx.company_name,
    total_count: policies.length,
    generated_at: new Date().toISOString(),
  };
}

/**
 * Generate a single policy by name.
 * @param {string} policyName
 * @param {Object} profileJson
 * @returns {{ name, slug, html }}
 */
function generateSinglePolicy(policyName, profileJson) {
  const ctx = buildContext(profileJson);
  const generator = findGenerator(policyName) || generateGenericPolicy;
  return generator(policyName, ctx);
}

module.exports = { generatePolicies, generateSinglePolicy, buildContext, POLICY_REGISTRY };
