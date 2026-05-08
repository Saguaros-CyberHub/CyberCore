/**
 * CIAB — Unified Intake API
 *
 * Replaces the split between /api/intake-form (V7.2, 15-column) and
 * /api/real-client/intake (v1.x JSON blob). Single canonical schema (v1.2),
 * single table (`intakes`), single set of endpoints. Both AI-generated and
 * real-client intakes flow through here.
 *
 * Mount path (from manifest.json): /api/intakes
 */

const express = require('express');
const router = express.Router();
const PDFDocument = require('pdfkit');

const { pool } = require('../utils/db');
const { authenticateToken } = require('../../../../../src/middleware/auth');
const { convertV72ToV12, SCHEMA_VERSION } = require('./../utils/intake-v72-to-v11');
const pdfh = require('../utils/pdf-helpers');

const SUPPORTED_SCHEMA_VERSIONS = ['1.0', '1.1', '1.2'];
const MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;

router.use(authenticateToken);

// ============================================================================
// HELPERS
// ============================================================================

function isPrivileged(req) {
  return req.user?.role === 'admin' || req.user?.role === 'instructor';
}

/**
 * Validate a v1.x payload's basic shape. We're permissive on field-level
 * structure (autosave from in-progress edits is allowed) but strict on the
 * outer envelope.
 */
function validatePayload(payload) {
  if (!payload || typeof payload !== 'object')
    return { ok: false, error: 'Payload is not an object.' };
  if (!payload.schema_version)
    return { ok: false, error: 'Missing schema_version.' };
  if (!SUPPORTED_SCHEMA_VERSIONS.includes(payload.schema_version))
    return { ok: false, error: `Unsupported schema_version: ${payload.schema_version}` };
  if (!payload.sections || typeof payload.sections !== 'object')
    return { ok: false, error: 'Missing sections object.' };
  return { ok: true };
}

/**
 * Walk the canonical payload's sections and count populated leaf fields.
 * Booleans count as filled in either state (a deliberately-unchecked box is a
 * recorded answer). null/undefined/'' and empty objects/arrays count as unfilled.
 */
function computeCompletion(payload) {
  const sections = payload?.sections;
  if (!sections || typeof sections !== 'object') return 0;
  let total = 0, filled = 0;
  function walk(v) {
    if (v === undefined) return;
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      for (const k of Object.keys(v)) walk(v[k]);
      return;
    }
    total++;
    if (v === false) { filled++; return; }
    if (v == null) return;
    if (typeof v === 'string' && v.trim() === '') return;
    if (Array.isArray(v) && v.length === 0) return;
    filled++;
  }
  for (const sec of Object.values(sections)) walk(sec);
  return total > 0 ? Math.round((filled / total) * 100) : 0;
}

/**
 * Summary view used by list endpoints — small object that renders quickly
 * without unmarshaling the full payload on every list row.
 */
function summarize(payload) {
  if (!payload?.sections) return null;
  const net = payload.sections.network || {};
  const ig1 = payload.sections.ig1 || {};
  const endpointCount = Number(net.endpoint_count) > 0
    ? Number(net.endpoint_count)
    : (Number(net.workstation_count) || 0) + (Number(net.laptop_count) || 0);
  const ig1Keys = Object.keys(ig1).filter(k => /^ig1_\d+\.\d+$/.test(k));
  const ig1Answered = ig1Keys.filter(k => ig1[k]).length;
  return {
    asset_total:      endpointCount + (Number(net.server_count) || 0),
    ig1_answered:     ig1Answered,
    ig1_total:        56,
    ig1_coverage_pct: Math.round((ig1Answered / 56) * 100),
  };
}

/**
 * Look up the intake row for a profile, lazily creating one for AI-simulated
 * profiles that don't have an intake yet (typical first-visit case).
 */
async function getOrCreateIntakeForProfile(userId, profileId) {
  const existing = await pool.query(
    `SELECT * FROM intakes WHERE profile_id = $1`, [profileId]
  );
  if (existing.rowCount > 0) return existing.rows[0];

  // Lazy-create an empty v1.2 intake. This handles profiles that pre-date
  // unification and never ran through the n8n profile-gen path that emits
  // a pre-filled payload.
  const profile = await pool.query(
    `SELECT id, company_name, profile_source FROM profiles WHERE id = $1`,
    [profileId]
  );
  if (profile.rowCount === 0) return null;

  const coverName = profile.rows[0].company_name || 'Unknown Organization';
  const source = profile.rows[0].profile_source === 'real_intake' ? 'real_client' : 'ai_simulated';
  const emptyPayload = {
    schema_version: SCHEMA_VERSION,
    cover_name: coverName,
    sections: {
      company: { cover_name: coverName },
      network: {}, wireless: {}, endpoint: {}, email_web: {},
      access: {}, data: {}, vuln_audit: {}, ig1: {}, notes: {},
    },
  };

  const inserted = await pool.query(
    `INSERT INTO intakes (user_id, profile_id, source, schema_version, cover_name, payload, status)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'in_progress')
     RETURNING *`,
    [userId, profileId, source, SCHEMA_VERSION, coverName, JSON.stringify(emptyPayload)]
  );
  return inserted.rows[0];
}

// ============================================================================
// ROUTES
// ============================================================================

// GET /api/intakes — list intakes visible to the caller
router.get('/', async (req, res) => {
  try {
    const userId = req.user.userId;
    const sql = isPrivileged(req)
      ? `SELECT id, user_id, profile_id, source, schema_version, cover_name,
                completion_percentage, status, created_at, updated_at
         FROM intakes
         ORDER BY updated_at DESC`
      : `SELECT id, user_id, profile_id, source, schema_version, cover_name,
                completion_percentage, status, created_at, updated_at
         FROM intakes
         WHERE user_id = $1
         ORDER BY updated_at DESC`;
    const params = isPrivileged(req) ? [] : [userId];
    const r = await pool.query(sql, params);
    res.json({ intakes: r.rows, can_see_all: isPrivileged(req) });
  } catch (err) {
    console.error('[intakes list]', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/intakes/by-id/:intakeId — fetch an unattached intake (real-client upload before linking)
router.get('/by-id/:intakeId', async (req, res) => {
  try {
    const { intakeId } = req.params;
    const r = await pool.query(`SELECT * FROM intakes WHERE id = $1`, [intakeId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Intake not found' });
    const row = r.rows[0];
    if (!isPrivileged(req) && row.user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    res.json({ intake: row, summary: summarize(row.payload) });
  } catch (err) {
    console.error('[intakes get-by-id]', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/intakes/:profileId — fetch (or lazily create) the intake for a profile
router.get('/:profileId', async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const row = await getOrCreateIntakeForProfile(userId, profileId);
    if (!row) return res.status(404).json({ error: 'Profile not found' });
    if (!isPrivileged(req) && row.user_id !== userId) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    res.json({ intake: row, summary: summarize(row.payload) });
  } catch (err) {
    console.error('[intakes get]', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/intakes/:profileId — auto-save the payload for a profile-bound intake
router.put('/:profileId', express.json({ limit: MAX_PAYLOAD_BYTES }), async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const payload = req.body;

    const v = validatePayload(payload);
    if (!v.ok) return res.status(400).json({ error: v.error });

    const completion = computeCompletion(payload);
    const status = completion >= 100 ? 'complete' : 'in_progress';
    const coverName = payload.cover_name || payload.sections?.company?.cover_name || null;

    // Ensure a row exists. If the profile itself doesn't exist, surface that
    // explicitly — it's the most common cause of a save failure.
    const ensured = await getOrCreateIntakeForProfile(userId, profileId);
    if (!ensured) {
      return res.status(404).json({
        error: `Profile ${profileId} does not exist. Open the form from a profile card or generator, not a stale URL.`,
      });
    }

    const r = await pool.query(
      `UPDATE intakes SET
         payload = $1::jsonb,
         schema_version = $2,
         cover_name = COALESCE($3, cover_name),
         completion_percentage = $4,
         status = $5,
         updated_at = NOW(),
         completed_at = CASE WHEN $5 = 'complete' AND completed_at IS NULL THEN NOW() ELSE completed_at END
       WHERE profile_id = $6
       RETURNING *`,
      [JSON.stringify(payload), payload.schema_version, coverName, completion, status, profileId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Intake row missing after lazy-create — please reload.' });
    res.json({ intake: r.rows[0], completion, status });
  } catch (err) {
    console.error('[intakes put]', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/intakes/:profileId/complete — mark the intake complete
router.post('/:profileId/complete', async (req, res) => {
  try {
    const { profileId } = req.params;
    const r = await pool.query(
      `UPDATE intakes SET status = 'complete', completion_percentage = 100,
         completed_at = NOW(), updated_at = NOW()
       WHERE profile_id = $1 RETURNING id, status, completion_percentage`,
      [profileId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Intake not found' });
    res.json({ ...r.rows[0], success: true });
  } catch (err) {
    console.error('[intakes complete]', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/intakes/upload — standalone real-client upload (no profile attached yet)
router.post('/upload', express.json({ limit: MAX_PAYLOAD_BYTES }), async (req, res) => {
  try {
    const userId = req.user.userId;
    const role = req.user.role || 'student';
    const payload = req.body;

    const v = validatePayload(payload);
    if (!v.ok) return res.status(400).json({ error: v.error });
    if (!payload.cover_name || !String(payload.cover_name).trim()) {
      return res.status(400).json({ error: 'cover_name is required for upload.' });
    }

    const rawPreview = JSON.stringify(payload).slice(0, 4096);
    const completion = computeCompletion(payload);

    const r = await pool.query(
      `INSERT INTO intakes
         (user_id, profile_id, source, schema_version, cover_name, payload,
          completion_percentage, status, raw_format, raw_preview)
       VALUES ($1, NULL, 'real_client', $2, $3, $4::jsonb, $5, 'complete', 'json', $6)
       RETURNING id, user_id, source, cover_name, created_at`,
      [userId, payload.schema_version, payload.cover_name.trim(),
       JSON.stringify(payload), completion, rawPreview]
    );
    res.json({ intake: r.rows[0], summary: summarize(payload) });
  } catch (err) {
    console.error('[intakes upload]', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/intakes/by-id/:intakeId/attach — attach an unattached intake to a profile
router.put('/by-id/:intakeId/attach', express.json(), async (req, res) => {
  try {
    if (!isPrivileged(req)) return res.status(403).json({ error: 'Admin/instructor only' });
    const { intakeId } = req.params;
    const { profile_id } = req.body || {};
    if (!profile_id) return res.status(400).json({ error: 'profile_id required' });

    // Don't double-attach a profile that already has an intake.
    const collision = await pool.query(
      `SELECT id FROM intakes WHERE profile_id = $1 AND id <> $2`,
      [profile_id, intakeId]
    );
    if (collision.rowCount > 0) {
      return res.status(409).json({ error: 'Profile already has an intake attached' });
    }

    const r = await pool.query(
      `UPDATE intakes SET profile_id = $1, updated_at = NOW()
       WHERE id = $2 RETURNING id, profile_id, source`,
      [profile_id, intakeId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Intake not found' });
    res.json({ intake: r.rows[0] });
  } catch (err) {
    console.error('[intakes attach]', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/intakes/by-id/:intakeId — soft-archive (admins only). Profile FK cascade handles attached intakes elsewhere.
router.delete('/by-id/:intakeId', async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const r = await pool.query(
      `UPDATE intakes SET status = 'in_progress', updated_at = NOW()
       WHERE id = $1 AND profile_id IS NULL
       RETURNING id`,
      [req.params.intakeId]
    );
    if (r.rowCount === 0) {
      return res.status(404).json({ error: 'Intake not found or attached to a profile' });
    }
    res.json({ archived: r.rows[0].id });
  } catch (err) {
    console.error('[intakes delete]', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// PDF EXPORT
// ============================================================================

// Field labels for v1.2 payload sections. Keys match the canonical shape.
const FIELD_LABELS = {
  // company
  cover_name: 'Organization Name', industry: 'Industry',
  employees_band: 'Employee Count', revenue_band: 'Revenue Band',
  business_address: 'Business Address', locations: 'Locations', website: 'Website',
  region: 'Region',
  // network
  endpoint_count: 'Endpoint Count', server_count: 'Server Count',
  os_count_win_server: 'Windows Server', os_count_win_client: 'Windows Client',
  os_count_linux: 'Linux', os_count_macos: 'macOS', os_count_other: 'Other OS',
  role_dc: 'Domain Controller', role_file: 'File Server', role_mail: 'Mail Server',
  role_web: 'Web Server', role_db: 'Database Server', role_backup: 'Backup Server',
  role_print: 'Print Server', role_other: 'Other Role',
  domain_mode: 'Domain Mode', domain_name: 'Domain Name',
  // wireless
  ssid_count: 'SSID Count', wifi_encryption: 'Wi-Fi Encryption',
  guest_wifi: 'Guest Wi-Fi', guest_isolated: 'Guest Isolated',
  // endpoint
  av_vendor: 'AV / EDR Vendor', disk_encryption: 'Disk Encryption',
  usb_policy: 'USB Policy', patch_cadence: 'Patch Cadence',
  // email_web
  email_provider: 'Email Provider', web_filtering: 'Web Filtering',
  spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC',
  // access
  mfa_coverage: 'MFA Coverage', priv_count_band: 'Privileged Accounts',
  password_manager: 'Password Manager', lockout_policy: 'Lockout Policy',
  dormant_cleanup: 'Dormant Account Cleanup',
  // data
  backup_cadence: 'Backup Cadence', offsite_backup: 'Offsite Backup',
  offline_backup: 'Offline Backup', encryption_at_rest: 'Encryption at Rest',
  dlp: 'DLP', restore_test: 'Restore Test',
  // vuln_audit
  vuln_scanning: 'Vulnerability Scanning', logging_coverage: 'Logging Coverage',
  siem: 'SIEM', audit_retention: 'Audit Retention',
};

function renderTextFields(doc, data, fields) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;
  const colWidth = (pageWidth - 10) / 2;
  const ROW_H = 24;
  let col = 0, rowY = doc.y;

  fields.forEach(f => {
    const val = data[f];
    if (val == null || val === '' || (Array.isArray(val) && val.length === 0)) return;
    if (col === 0 && rowY + ROW_H > doc.page.height - 60) { doc.addPage(); rowY = doc.y; }
    const x = leftMargin + col * (colWidth + 10);
    doc.fontSize(7.5).font('Helvetica-Bold').fillColor(pdfh.PDF_COLORS.textLight)
      .text(FIELD_LABELS[f] || f.replace(/_/g, ' '), x, rowY);
    const display = Array.isArray(val) ? val.join(', ') : String(val);
    doc.fontSize(8.5).font('Helvetica').fillColor(pdfh.PDF_COLORS.text)
      .text(display, x, rowY + 9, { width: colWidth });
    doc.y = rowY + ROW_H;
    col++;
    if (col >= 2) { col = 0; rowY += ROW_H; }
  });
  if (col > 0) rowY += ROW_H;
  doc.y = rowY;
}

function renderUnifiedIntakePdf(doc, payload, opts = {}) {
  const sections = payload.sections || {};
  const company = sections.company || {};
  const coverName = payload.cover_name || company.cover_name || 'Unknown Organization';

  pdfh.renderCoverPage(doc, {
    title: 'Client Intake Form',
    subtitle: 'Cybersecurity Risk Assessment',
    companyName: coverName,
    watermark: opts.watermark,
    meta: [
      ['Date Generated', new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })],
      ['Status',         `${opts.completion ?? 0}% Complete`],
      ['Prepared By',    'Clinic-in-a-Box Platform'],
      ['Source',         opts.source === 'real_client' ? 'Real-Client Engagement' : 'Training Sample'],
    ],
  });

  // 1. Organization
  pdfh.renderSectionHeader(doc, '1. Organization Profile');
  renderTextFields(doc, company, [
    'industry', 'employees_band', 'revenue_band', 'region',
    'business_address', 'locations', 'website',
  ]);
  if (company.frameworks?.length) {
    pdfh.renderTextarea(doc, 'Regulatory Frameworks', company.frameworks.join(', '));
  }
  if (company.primary_contact?.name || company.primary_contact?.email) {
    pdfh.renderTextarea(doc, 'Primary Contact',
      [company.primary_contact.name, company.primary_contact.title, company.primary_contact.email, company.primary_contact.phone]
        .filter(Boolean).join(' · '));
  }
  if (company.secondary_contact?.name || company.secondary_contact?.email) {
    pdfh.renderTextarea(doc, 'Secondary Contact',
      [company.secondary_contact.name, company.secondary_contact.title, company.secondary_contact.email, company.secondary_contact.phone]
        .filter(Boolean).join(' · '));
  }
  ['products_services', 'recent_incidents', 'ongoing_concerns', 'primary_goals'].forEach(f => {
    if (company[f]) pdfh.renderTextarea(doc, FIELD_LABELS[f] || f, company[f]);
  });

  // 2. Network
  pdfh.renderSectionHeader(doc, '2. Network Topology');
  renderTextFields(doc, sections.network || {}, [
    'endpoint_count', 'server_count',
    'os_count_win_server', 'os_count_win_client', 'os_count_linux', 'os_count_macos', 'os_count_other',
    'role_dc', 'role_file', 'role_mail', 'role_web', 'role_db', 'role_backup', 'role_print',
    'domain_mode', 'domain_name',
  ]);
  if (sections.network?.services?.length) {
    pdfh.renderTextarea(doc, 'Exposed Services', sections.network.services.join(', '));
  }

  // 3. Wireless / 4. Endpoint / 5. Email & Web / 6. Access / 7. Data / 8. Vuln & Audit
  const simple = [
    ['3. Wireless',           sections.wireless,   ['ssid_count', 'wifi_encryption', 'guest_wifi', 'guest_isolated']],
    ['4. Endpoint Security',  sections.endpoint,   ['av_vendor', 'disk_encryption', 'usb_policy', 'patch_cadence']],
    ['5. Email & Web',        sections.email_web,  ['email_provider', 'web_filtering', 'spf', 'dkim', 'dmarc']],
    ['6. Account & Access',   sections.access,     ['mfa_coverage', 'priv_count_band', 'password_manager', 'lockout_policy', 'dormant_cleanup']],
    ['7. Data Protection',    sections.data,       ['backup_cadence', 'offsite_backup', 'offline_backup', 'encryption_at_rest', 'dlp', 'restore_test']],
    ['8. Vulnerability & Audit', sections.vuln_audit, ['vuln_scanning', 'logging_coverage', 'siem', 'audit_retention']],
  ];
  for (const [title, sec, fields] of simple) {
    if (!sec) continue;
    pdfh.renderSectionHeader(doc, title);
    renderTextFields(doc, sec, fields);
  }

  // 9. CIS IG1
  pdfh.renderSectionHeader(doc, '9. CIS Controls IG1 Safeguards');
  pdfh.renderIG1(doc, sections.ig1 || {});

  // 10. Notes
  if (sections.notes?.free_text) {
    pdfh.renderSectionHeader(doc, '10. Additional Notes');
    pdfh.renderTextarea(doc, '', sections.notes.free_text);
  }
}

// GET /api/intakes/:profileId/export — PDF export
router.get('/:profileId/export', async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    const r = await pool.query(`SELECT * FROM intakes WHERE profile_id = $1`, [profileId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Intake not found' });
    const intake = r.rows[0];
    if (!isPrivileged(req) && intake.user_id !== userId) {
      return res.status(403).json({ error: 'Not permitted' });
    }

    const coverName = intake.cover_name || 'Unknown Organization';
    const safeName = coverName.replace(/[^a-zA-Z0-9]/g, '-');
    const watermark = intake.source === 'ai_simulated' ? 'TRAINING SAMPLE — NOT FOR CLIENT USE' : null;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="intake-${safeName}.pdf"`);

    const doc = new PDFDocument({ margin: 50, size: 'letter', bufferPages: true });
    doc.pipe(res);
    renderUnifiedIntakePdf(doc, intake.payload, {
      completion: intake.completion_percentage,
      source: intake.source,
      watermark,
    });
    doc.end();
  } catch (err) {
    console.error('[intakes export]', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.renderUnifiedIntakePdf = renderUnifiedIntakePdf;
module.exports.computeCompletion = computeCompletion;
module.exports.summarize = summarize;
