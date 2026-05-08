/**
 * CIAB — Clinic Risk Assessment API (Phase 1)
 *
 * The deliverable surface: risk register, CSF maturity, IG1 coverage,
 * and PDF report export. Reads intake from the unified `intakes` table
 * (Phase 0). Reuses utils/frameworks.js for CIS↔CSF crosswalk and
 * utils/pdf-helpers.js for PDF rendering primitives.
 *
 * Mount path: /api/clinic-risk-assessment
 */

const express = require('express');
const router = express.Router();
const PDFDocument = require('pdfkit');

const { pool } = require('../utils/db');
const { authenticateToken } = require('../../../../../src/middleware/auth');
const frameworks = require('../utils/frameworks');
const pdfh = require('../utils/pdf-helpers');

const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024; // chart PNGs can be heavy

router.use(authenticateToken);

// ============================================================================
// HELPERS
// ============================================================================

function isPrivileged(req) {
  return req.user?.role === 'admin' || req.user?.role === 'instructor';
}

async function userCanReadProfile(userId, profileId, role) {
  if (role === 'admin' || role === 'instructor') return true;
  const r = await pool.query(`SELECT 1 FROM profiles WHERE id = $1 AND user_id = $2`, [profileId, userId]);
  return r.rowCount > 0;
}

async function loadIntakeForProfile(profileId) {
  const r = await pool.query(
    `SELECT id, source, schema_version, cover_name, payload, completion_percentage, status
     FROM intakes WHERE profile_id = $1`,
    [profileId]
  );
  return r.rows[0] || null;
}

async function loadOrInitReport(profileId, userId) {
  const r = await pool.query(`SELECT * FROM report_deliverables WHERE profile_id = $1 ORDER BY version DESC LIMIT 1`, [profileId]);
  if (r.rowCount > 0) return r.rows[0];
  const ins = await pool.query(
    `INSERT INTO report_deliverables (profile_id, created_by) VALUES ($1, $2) RETURNING *`,
    [profileId, userId]
  );
  return ins.rows[0];
}

function ensureFindingFields(body) {
  // Title required; everything else is optional but typed.
  if (!body || typeof body !== 'object') return { ok: false, error: 'Body must be an object' };
  if (!body.title || !String(body.title).trim()) return { ok: false, error: 'title is required' };
  return { ok: true };
}

// ============================================================================
// READ
// ============================================================================

// GET /api/clinic-risk-assessment/frameworks — return catalogs once (cached client-side).
router.get('/frameworks', (req, res) => {
  res.json({
    cis_ig1: frameworks.getCisIg1(),
    nist_csf_2_0: frameworks.getNistCsf(),
  });
});

// GET /api/clinic-risk-assessment/:profileId — full dashboard bundle for one profile.
router.get('/:profileId', async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }

    const profileQ = await pool.query(
      `SELECT id, company_name, industry, profile_source, difficulty
       FROM profiles WHERE id = $1`,
      [profileId]
    );
    if (profileQ.rowCount === 0) return res.status(404).json({ error: 'Profile not found' });

    const profile = profileQ.rows[0];
    const intake = await loadIntakeForProfile(profileId);
    const report = await loadOrInitReport(profileId, userId);

    const findingsQ = await pool.query(
      `SELECT * FROM risk_findings WHERE profile_id = $1 ORDER BY inherent_risk DESC, finding_code ASC`,
      [profileId]
    );

    // IG1 coverage + auto-derived CSF scores from intake.
    const ig1Section = intake?.payload?.sections?.ig1 || {};
    const cisCoverage = frameworks.ig1Coverage(ig1Section);
    const csfFromIg1 = frameworks.aggregateIg1ToCsf(ig1Section);

    // If the assessor manually set CSF scores, prefer those over the auto-derived.
    const csfManual = report.csf_scores || {};
    const csfScores = { ...csfFromIg1, ...csfManual };

    res.json({
      profile: {
        id: profile.id,
        company_name: profile.company_name,
        industry: profile.industry,
        profile_source: profile.profile_source,
        difficulty: profile.difficulty,
      },
      intake: intake
        ? {
            id: intake.id,
            source: intake.source,
            cover_name: intake.cover_name,
            completion_percentage: intake.completion_percentage,
            status: intake.status,
          }
        : null,
      report: {
        id: report.id,
        version: report.version,
        status: report.status,
        exec_summary: report.exec_summary,
        branding: report.branding,
        csf_scores_manual: csfManual,
        finalized_at: report.finalized_at,
      },
      findings: findingsQ.rows,
      cis_coverage: cisCoverage,
      csf_scores: csfScores,
      csf_scores_auto: csfFromIg1,
    });
  } catch (err) {
    console.error('[CRA get]', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// FINDINGS CRUD
// ============================================================================

router.post('/:profileId/findings', express.json(), async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    const v = ensureFindingFields(req.body);
    if (!v.ok) return res.status(400).json({ error: v.error });

    const b = req.body;
    // Auto-assign finding_code (F-001 etc.) if not given.
    let finding_code = b.finding_code;
    if (!finding_code) {
      const c = await pool.query(`SELECT count(*) FROM risk_findings WHERE profile_id = $1`, [profileId]);
      const n = parseInt(c.rows[0].count, 10) + 1;
      finding_code = `F-${String(n).padStart(3, '0')}`;
    }

    const r = await pool.query(
      `INSERT INTO risk_findings
         (user_id, profile_id, finding_code, title, description, category,
          likelihood, impact, residual_likelihood, residual_impact,
          status, recommendation, control_refs, evidence_refs, ai_generated)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15)
       RETURNING *`,
      [
        userId, profileId, finding_code,
        String(b.title).trim(), b.description || null, b.category || null,
        b.likelihood || null, b.impact || null,
        b.residual_likelihood || null, b.residual_impact || null,
        b.status || 'open', b.recommendation || null,
        JSON.stringify(b.control_refs || []), JSON.stringify(b.evidence_refs || []),
        !!b.ai_generated,
      ]
    );
    res.json({ finding: r.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'finding_code already exists for this profile' });
    }
    console.error('[CRA finding create]', err);
    res.status(500).json({ error: err.message });
  }
});

router.put('/:profileId/findings/:findingId', express.json(), async (req, res) => {
  try {
    const { profileId, findingId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    const b = req.body || {};
    // Whitelist of updatable fields. control_refs / evidence_refs go through JSON.stringify.
    const fields = [];
    const params = [];
    let i = 1;
    const set = (col, val, isJson) => {
      if (val === undefined) return;
      fields.push(`${col} = $${i++}${isJson ? '::jsonb' : ''}`);
      params.push(isJson ? JSON.stringify(val) : val);
    };
    set('title',          b.title);
    set('description',    b.description);
    set('category',       b.category);
    set('likelihood',     b.likelihood);
    set('impact',         b.impact);
    set('residual_likelihood', b.residual_likelihood);
    set('residual_impact',     b.residual_impact);
    set('status',         b.status);
    set('recommendation', b.recommendation);
    if (b.control_refs !== undefined)  set('control_refs',  b.control_refs,  true);
    if (b.evidence_refs !== undefined) set('evidence_refs', b.evidence_refs, true);
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push(`updated_at = NOW()`);
    params.push(findingId, profileId);
    const r = await pool.query(
      `UPDATE risk_findings SET ${fields.join(', ')}
       WHERE id = $${i++} AND profile_id = $${i}
       RETURNING *`,
      params
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Finding not found' });
    res.json({ finding: r.rows[0] });
  } catch (err) {
    console.error('[CRA finding update]', err);
    res.status(500).json({ error: err.message });
  }
});

router.delete('/:profileId/findings/:findingId', async (req, res) => {
  try {
    const { profileId, findingId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    const r = await pool.query(
      `DELETE FROM risk_findings WHERE id = $1 AND profile_id = $2 RETURNING id`,
      [findingId, profileId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Finding not found' });
    res.json({ deleted: r.rows[0].id });
  } catch (err) {
    console.error('[CRA finding delete]', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// REPORT FIELDS (exec summary, manual CSF scores, branding)
// ============================================================================

router.put('/:profileId/report', express.json(), async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    await loadOrInitReport(profileId, userId);
    const b = req.body || {};
    const fields = [];
    const params = [];
    let i = 1;
    if (b.exec_summary !== undefined) { fields.push(`exec_summary = $${i++}`); params.push(b.exec_summary); }
    if (b.csf_scores   !== undefined) { fields.push(`csf_scores   = $${i++}::jsonb`); params.push(JSON.stringify(b.csf_scores)); }
    if (b.branding     !== undefined) { fields.push(`branding     = $${i++}::jsonb`); params.push(JSON.stringify(b.branding)); }
    if (b.status       !== undefined) {
      if (!['draft','final'].includes(b.status)) return res.status(400).json({ error: "status must be 'draft' or 'final'" });
      fields.push(`status = $${i++}`); params.push(b.status);
      if (b.status === 'final') fields.push(`finalized_at = NOW()`);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push(`updated_at = NOW()`);
    params.push(profileId);
    const r = await pool.query(
      `UPDATE report_deliverables SET ${fields.join(', ')}
       WHERE profile_id = $${i} AND version = (SELECT MAX(version) FROM report_deliverables WHERE profile_id = $${i})
       RETURNING *`,
      params
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Report not found' });
    res.json({ report: r.rows[0] });
  } catch (err) {
    console.error('[CRA report update]', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// PDF EXPORT
// ============================================================================

function renderHeatmapTable(doc, findings) {
  // Simple text table fallback if no chart PNG was provided. Lists the
  // 5×5 grid with finding counts in each cell.
  const grid = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => 0));
  for (const f of findings) {
    if (f.likelihood && f.impact) grid[f.likelihood - 1][f.impact - 1]++;
  }
  pdfh.renderTextarea(doc, 'Heat-Map (textual fallback)',
    'Rows = likelihood (1 low → 5 high); cols = impact (1 → 5).\n' +
    grid.map((r, i) => `L${i+1}  ` + r.map(n => String(n).padStart(3)).join(' ')).join('\n')
  );
}

function renderFindingsTable(doc, findings) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;
  pdfh.ensureSpace(doc, 24);

  // Header row
  const headerY = doc.y;
  doc.rect(leftMargin, headerY, pageWidth, 16).fill(pdfh.PD_COLORS_HEADER || '#1e3a5f');
  doc.fontSize(8).font('Helvetica-Bold').fillColor('#ffffff')
    .text('Code', leftMargin + 6, headerY + 4, { width: 40 })
    .text('Title', leftMargin + 50, headerY + 4, { width: pageWidth - 250 })
    .text('Cat.', leftMargin + pageWidth - 200, headerY + 4, { width: 40 })
    .text('L', leftMargin + pageWidth - 160, headerY + 4, { width: 18 })
    .text('I', leftMargin + pageWidth - 142, headerY + 4, { width: 18 })
    .text('Risk', leftMargin + pageWidth - 124, headerY + 4, { width: 32 })
    .text('Status', leftMargin + pageWidth - 90, headerY + 4, { width: 84 });
  doc.y = headerY + 18;

  const ROW_H = 14;
  if (findings.length === 0) {
    doc.fontSize(9).font('Helvetica').fillColor('#64748b')
      .text('No findings recorded.', leftMargin + 6, doc.y + 4);
    doc.y += 20;
    return;
  }

  findings.forEach((f, idx) => {
    pdfh.ensureSpace(doc, ROW_H);
    const rowY = doc.y;
    if (idx % 2 === 1) doc.rect(leftMargin, rowY, pageWidth, ROW_H).fill('#f8fafc');
    doc.fontSize(8).font('Helvetica').fillColor('#1e293b')
      .text(f.finding_code || '', leftMargin + 6, rowY + 3, { width: 40 })
      .text(f.title || '', leftMargin + 50, rowY + 3, { width: pageWidth - 250, ellipsis: true, lineBreak: false })
      .text(f.category || '—', leftMargin + pageWidth - 200, rowY + 3, { width: 40 })
      .text(f.likelihood ?? '—', leftMargin + pageWidth - 160, rowY + 3, { width: 18 })
      .text(f.impact ?? '—', leftMargin + pageWidth - 142, rowY + 3, { width: 18 })
      .text(f.inherent_risk ?? '—', leftMargin + pageWidth - 124, rowY + 3, { width: 32 })
      .text(f.status || 'open', leftMargin + pageWidth - 90, rowY + 3, { width: 84 });
    doc.y = rowY + ROW_H;
  });
}

function renderClinicRiskAssessmentPdf(doc, data) {
  const { profile, intake, report, findings, cis_coverage, csf_scores, charts = {} } = data;
  const coverName = profile.company_name || intake?.cover_name || 'Unknown Organization';
  const watermark = (intake?.source === 'ai_simulated' || profile.profile_source !== 'real_intake')
    ? 'TRAINING SAMPLE — NOT FOR CLIENT USE'
    : null;

  // --- Cover page ---
  pdfh.renderCoverPage(doc, {
    title: 'Clinic Risk Assessment',
    subtitle: 'Cybersecurity Risk Posture & Recommendations',
    companyName: coverName,
    watermark,
    meta: [
      ['Date',         new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })],
      ['Findings',     String(findings.length)],
      ['IG1 Coverage', `${cis_coverage.score}%`],
      ['Report State', (report.status || 'draft').toUpperCase()],
      ['Prepared By',  (report.branding?.prepared_by) || 'Clinic-in-a-Box Platform'],
      ['Source',       intake?.source === 'real_client' ? 'Real-Client Engagement' : 'Training Sample'],
    ],
  });

  // --- Executive Summary ---
  pdfh.renderSectionHeader(doc, 'Executive Summary');
  if (report.exec_summary && report.exec_summary.trim()) {
    pdfh.renderTextarea(doc, '', report.exec_summary);
  } else {
    doc.fontSize(9).font('Helvetica').fillColor('#64748b')
      .text('No executive summary recorded yet — assessor should complete the Report tab before finalizing.', { width: doc.page.width - doc.page.margins.left - doc.page.margins.right });
    doc.moveDown(0.5);
  }

  // --- Engagement Scope (from intake) ---
  pdfh.renderSectionHeader(doc, 'Engagement Scope');
  const company = intake?.payload?.sections?.company || {};
  const network = intake?.payload?.sections?.network || {};
  const lines = [
    ['Industry',         company.industry || '—'],
    ['Employee band',    company.employees_band || '—'],
    ['Endpoints',        network.endpoint_count ?? '—'],
    ['Servers',          network.server_count ?? '—'],
    ['Frameworks',       Array.isArray(company.frameworks) && company.frameworks.length ? company.frameworks.join(', ') : '—'],
  ];
  lines.forEach(([k, v]) => {
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#64748b').text(k + ':', { continued: true });
    doc.font('Helvetica').fillColor('#1e293b').text(' ' + v);
  });
  doc.moveDown(0.5);

  // --- Heat Map page ---
  doc.addPage();
  pdfh.renderSectionHeader(doc, 'Risk Heat Map (Inherent Risk)');
  if (charts.heatmap_png) {
    embedChart(doc, charts.heatmap_png, 460);
  } else {
    renderHeatmapTable(doc, findings);
  }

  // --- Findings table ---
  pdfh.renderSectionHeader(doc, 'Findings — Sorted by Inherent Risk');
  renderFindingsTable(doc, findings);

  // --- CSF Maturity Radar page ---
  doc.addPage();
  pdfh.renderSectionHeader(doc, 'NIST CSF 2.0 Maturity');
  if (charts.radar_png) {
    embedChart(doc, charts.radar_png, 380);
  } else {
    const fnNames = { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' };
    Object.entries(fnNames).forEach(([id, name]) => {
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#1e293b')
        .text(`${name}: ${(csf_scores[id] ?? 0).toFixed(1)} / 5`);
    });
  }

  // --- Compliance Coverage page ---
  doc.addPage();
  pdfh.renderSectionHeader(doc, 'Compliance Coverage');
  if (charts.cis_png) {
    embedChart(doc, charts.cis_png, 240);
  } else {
    doc.fontSize(10).font('Helvetica').fillColor('#1e293b')
      .text(`CIS IG1: ${cis_coverage.score}% (${cis_coverage.yes} yes, ${cis_coverage.partial} partial, ${cis_coverage.no} no, ${cis_coverage.unknown} unanswered of ${cis_coverage.total})`);
  }
  doc.moveDown(0.5);
  if (charts.csf_png) {
    embedChart(doc, charts.csf_png, 240);
  }

  // --- Detailed findings ---
  if (findings.length > 0) {
    doc.addPage();
    pdfh.renderSectionHeader(doc, 'Detailed Findings');
    findings.forEach(f => {
      pdfh.ensureSpace(doc, 60);
      doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f')
        .text(`${f.finding_code || ''} — ${f.title}`);
      doc.fontSize(9).font('Helvetica').fillColor('#64748b')
        .text(`Category: ${f.category || '—'}  |  Likelihood ${f.likelihood ?? '—'} × Impact ${f.impact ?? '—'} = Risk ${f.inherent_risk ?? '—'}  |  Status: ${f.status}`);
      doc.moveDown(0.2);
      if (f.description) pdfh.renderTextarea(doc, 'Description', f.description);
      if (f.recommendation) pdfh.renderTextarea(doc, 'Recommendation', f.recommendation);
      const refs = Array.isArray(f.control_refs) ? f.control_refs : [];
      if (refs.length > 0) {
        const refStr = refs.map(r => `${r.framework || '?'}:${r.id || '?'}`).join(', ');
        doc.fontSize(8).font('Helvetica-Oblique').fillColor('#64748b').text('Control refs: ' + refStr);
      }
      doc.moveDown(0.4);
    });
  }
}

function embedChart(doc, base64png, height) {
  try {
    // Strip data URL prefix if present.
    const m = base64png.match(/^data:image\/png;base64,(.*)$/);
    const buf = Buffer.from(m ? m[1] : base64png, 'base64');
    const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
    pdfh.ensureSpace(doc, height + 10);
    doc.image(buf, doc.page.margins.left, doc.y, { fit: [pageWidth, height], align: 'center' });
    doc.y += height + 10;
  } catch (e) {
    doc.fontSize(9).font('Helvetica').fillColor('#dc2626')
      .text('Chart failed to embed: ' + e.message);
    doc.moveDown(0.3);
  }
}

// POST /api/clinic-risk-assessment/:profileId/export — accepts {charts:{heatmap_png,radar_png,...}} from client
router.post('/:profileId/export', express.json({ limit: MAX_PAYLOAD_BYTES }), async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }

    const profileQ = await pool.query(
      `SELECT id, company_name, industry, profile_source, difficulty FROM profiles WHERE id = $1`,
      [profileId]
    );
    if (profileQ.rowCount === 0) return res.status(404).json({ error: 'Profile not found' });

    const profile = profileQ.rows[0];
    const intake = await loadIntakeForProfile(profileId);
    const report = await loadOrInitReport(profileId, userId);
    const findingsQ = await pool.query(
      `SELECT * FROM risk_findings WHERE profile_id = $1 ORDER BY inherent_risk DESC, finding_code ASC`,
      [profileId]
    );

    const ig1Section = intake?.payload?.sections?.ig1 || {};
    const cis_coverage = frameworks.ig1Coverage(ig1Section);
    const csf_scores = { ...frameworks.aggregateIg1ToCsf(ig1Section), ...(report.csf_scores || {}) };

    const charts = req.body?.charts || {};
    // Cache chart PNGs on the report so a re-export without client charts still has them.
    if (charts && Object.keys(charts).length > 0) {
      await pool.query(
        `UPDATE report_deliverables SET charts_cache = $1::jsonb, updated_at = NOW()
         WHERE id = $2`,
        [JSON.stringify(charts), report.id]
      );
    } else if (report.charts_cache && Object.keys(report.charts_cache).length > 0) {
      // Fall back to cached charts.
      Object.assign(charts, report.charts_cache);
    }

    const safeName = (profile.company_name || 'report').replace(/[^a-zA-Z0-9]/g, '-');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="clinic-risk-assessment-${safeName}.pdf"`);

    const doc = new PDFDocument({ margin: 50, size: 'letter', bufferPages: true });
    doc.pipe(res);
    renderClinicRiskAssessmentPdf(doc, {
      profile, intake, report, findings: findingsQ.rows,
      cis_coverage, csf_scores, charts,
    });
    doc.end();
  } catch (err) {
    console.error('[CRA export]', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.renderClinicRiskAssessmentPdf = renderClinicRiskAssessmentPdf;
