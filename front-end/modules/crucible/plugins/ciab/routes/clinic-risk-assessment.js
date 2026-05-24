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

// GET /api/clinic-risk-assessment/pickable — landing-page picker data.
// Returns AI profiles (for the user, or all if privileged) AND real-client
// intakes from the unified table. Intakes already attached to a profile
// surface that profile_id directly so the picker can deep-link.
router.get('/pickable', async (req, res) => {
  try {
    const userId = req.user.userId;
    const privileged = isPrivileged(req);

    const profileSql = privileged
      ? `SELECT id, company_name, industry, difficulty, profile_source,
                created_at, generation_status
         FROM profiles
         WHERE generation_status = 'complete'
         ORDER BY created_at DESC
         LIMIT 200`
      : `SELECT id, company_name, industry, difficulty, profile_source,
                created_at, generation_status
         FROM profiles
         WHERE user_id = $1 AND generation_status = 'complete'
         ORDER BY created_at DESC
         LIMIT 200`;
    const profileQ = privileged
      ? await pool.query(profileSql)
      : await pool.query(profileSql, [userId]);

    // Real-client intakes from unified table. For each, surface whether it's
    // already attached to a profile.
    const intakeSql = privileged
      ? `SELECT i.id, i.cover_name, i.profile_id, i.completion_percentage,
                i.created_at, i.user_id
         FROM intakes i
         WHERE i.source = 'real_client'
         ORDER BY i.created_at DESC
         LIMIT 200`
      : `SELECT i.id, i.cover_name, i.profile_id, i.completion_percentage,
                i.created_at, i.user_id
         FROM intakes i
         WHERE i.source = 'real_client' AND i.user_id = $1
         ORDER BY i.created_at DESC
         LIMIT 200`;
    const intakeQ = privileged
      ? await pool.query(intakeSql)
      : await pool.query(intakeSql, [userId]);

    res.json({
      ai_profiles: profileQ.rows.filter(p => p.profile_source !== 'real_intake'),
      real_client_intakes: intakeQ.rows,
      can_see_all: privileged,
    });
  } catch (err) {
    console.error('[CRA pickable]', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/clinic-risk-assessment/from-intake/:intakeId
// Lazy-creates a thin profile from a real-client intake so the user can run
// a risk assessment against it. The intake gets attached to the new profile
// (its profile_id is set). Returns { profile_id } so the client can redirect.
router.post('/from-intake/:intakeId', express.json(), async (req, res) => {
  try {
    const { intakeId } = req.params;
    const userId = req.user.userId;

    // Load the intake (must be real_client and not already attached).
    const ir = await pool.query(
      `SELECT id, user_id, cover_name, payload, profile_id, source
       FROM intakes WHERE id = $1`,
      [intakeId]
    );
    if (ir.rowCount === 0) return res.status(404).json({ error: 'Intake not found' });
    const intake = ir.rows[0];

    // Permission: owner or admin/instructor.
    if (intake.user_id !== userId && !isPrivileged(req)) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    if (intake.source !== 'real_client') {
      return res.status(400).json({ error: 'Only real-client intakes can be promoted via this endpoint.' });
    }

    // If already attached, return the existing profile_id (idempotent).
    if (intake.profile_id) {
      return res.json({ profile_id: intake.profile_id, reused: true });
    }

    // Pull a couple of fields from the intake to seed the profile.
    const company = intake.payload?.sections?.company || {};
    const network = intake.payload?.sections?.network || {};
    const coverName = intake.cover_name || company.cover_name || 'Untitled Engagement';
    const industry = company.industry || null;
    const endpointCount = Number(network.endpoint_count) || null;
    const frameworks = Array.isArray(company.frameworks) ? company.frameworks : [];

    // profiles.source_intake_id has a FK to real_client_intakes(id), not to
    // the unified intakes table. If this intakes row was migrated from (or
    // dual-written with) a real_client_intakes row, use that legacy id;
    // otherwise leave it null. The intake.profile_id back-link is enough
    // for the CRA dashboard.
    const fullIntake = await pool.query(
      `SELECT legacy_source_table, legacy_source_id FROM intakes WHERE id = $1`,
      [intakeId]
    );
    let sourceIntakeIdForFk = null;
    const fi = fullIntake.rows[0];
    if (fi?.legacy_source_table === 'real_client_intakes' && fi.legacy_source_id) {
      const rciCheck = await pool.query(`SELECT id FROM real_client_intakes WHERE id = $1`, [fi.legacy_source_id]);
      if (rciCheck.rowCount > 0) sourceIntakeIdForFk = fi.legacy_source_id;
    }

    // Use a deterministic-ish run_id so re-creates can be traced.
    const runId = `RC_${Date.now()}_${intakeId.slice(0, 8)}`;

    const pr = await pool.query(
      `INSERT INTO profiles
         (user_id, run_id, client_type, company_name, industry, difficulty,
          endpoint_count, compliance_frameworks,
          generation_status, profile_source, source_intake_id, filler_assets)
       VALUES
         ($1, $2, 'real_client', $3, $4, NULL,
          $5, $6::jsonb,
          'complete', 'real_intake', $7, '{}'::jsonb)
       RETURNING id`,
      [userId, runId, coverName, industry, endpointCount,
       JSON.stringify(frameworks), sourceIntakeIdForFk]
    );
    const profileId = pr.rows[0].id;

    // Attach the unified intake to the new profile (forward link).
    await pool.query(
      `UPDATE intakes SET profile_id = $1, updated_at = NOW()
       WHERE id = $2`,
      [profileId, intakeId]
    );

    // Mirror the link onto the legacy real_client_intakes row too, so the
    // existing detail/synthesize pages keep working.
    if (sourceIntakeIdForFk) {
      await pool.query(
        `UPDATE real_client_intakes
           SET linked_profile_id = $1, status = 'linked', updated_at = NOW()
         WHERE id = $2 AND linked_profile_id IS NULL`,
        [profileId, sourceIntakeIdForFk]
      );
    }

    res.json({ profile_id: profileId, reused: false });
  } catch (err) {
    console.error('[CRA from-intake]', err);
    res.status(500).json({ error: err.message });
  }
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

// GET /:profileId/report-data
// Returns the FULL bundle needed by the standalone HTML report page
// (different shape than /:profileId — includes intake.payload, CIS RAM
// workbook, top-unmet safeguards, computed recommendations). The HTML
// report uses this single request to render everything.
router.get('/:profileId/report-data', async (req, res) => {
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

    const ig1Section = intake?.payload?.sections?.ig1 || {};
    const cisCoverage = frameworks.ig1Coverage(ig1Section);
    const csfFromIg1 = frameworks.aggregateIg1ToCsf(ig1Section);
    const csfManual = report.csf_scores || {};
    const csfScores = { ...csfFromIg1, ...csfManual };

    // Top unmet IG1 safeguards (top 8 'no' answers)
    const ig1Cat = frameworks.getCisIg1();
    const sgIndex = Object.fromEntries((ig1Cat.safeguards || []).map(s => [s.num, s]));
    const topUnmet = Object.entries(ig1Section)
      .filter(([k, v]) => /^ig1_\d+\.\d+$/.test(k) && v === 'no')
      .map(([k]) => sgIndex[k.replace('ig1_', '')])
      .filter(Boolean)
      .slice(0, 8);

    // Pre-compute recommendations (same logic as PDF render).
    const posture = intake?.payload?._meta?.posture || null;
    const recommendations = buildRecommendations({
      findings: findingsQ.rows, cis_coverage: cisCoverage,
      csf_scores: csfScores, posture, intake
    });

    // CIS RAM workbook (best-effort — table may be empty).
    let cisRam = null;
    try {
      cisRam = await loadCisRamForPdf(profileId);
    } catch (_) { cisRam = null; }

    res.json({
      profile,
      intake,                       // full payload, not summary
      report,                       // full record
      findings: findingsQ.rows,
      cis_coverage: cisCoverage,
      csf_scores: csfScores,
      top_unmet_safeguards: topUnmet,
      recommendations,
      cis_ram: cisRam,
      posture
    });
  } catch (err) {
    console.error('[CRA report-data]', err);
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
  const pageWidth  = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;
  pdfh.ensureSpace(doc, 24);

  // Column geometry — push severity badge into its own column for visual scan
  const colCode    = 0;
  const colTitle   = 60;
  const colCat     = pageWidth - 240;
  const colL       = pageWidth - 175;
  const colI       = pageWidth - 152;
  const colRisk    = pageWidth - 129;
  const colSev     = pageWidth - 96;
  const colStatus  = pageWidth - 32;

  // Header row
  const headerY = doc.y;
  doc.rect(leftMargin, headerY, pageWidth, 18).fill('#1e3a5f');
  doc.fontSize(7.5).font('Helvetica-Bold').fillColor('#ffffff')
    .text('CODE',  leftMargin + 6 + colCode,   headerY + 5, { width: 50, characterSpacing: 1 })
    .text('FINDING', leftMargin + 6 + colTitle, headerY + 5, { width: colCat - colTitle - 8, characterSpacing: 1 })
    .text('CAT.',  leftMargin + 6 + colCat,    headerY + 5, { width: 56, characterSpacing: 1 })
    .text('L',     leftMargin + 6 + colL,      headerY + 5, { width: 18 })
    .text('I',     leftMargin + 6 + colI,      headerY + 5, { width: 18 })
    .text('RISK',  leftMargin + 6 + colRisk,   headerY + 5, { width: 28 })
    .text('SEVERITY', leftMargin + 6 + colSev, headerY + 5, { width: 58, characterSpacing: 1 })
    .text('STATUS',leftMargin + 6 + colStatus, headerY + 5, { width: 32, characterSpacing: 1 });
  doc.y = headerY + 18;

  const ROW_H = 18;
  if (findings.length === 0) {
    doc.fontSize(9).font('Helvetica-Oblique').fillColor('#64748b')
      .text('No findings recorded yet for this engagement.', leftMargin + 6, doc.y + 6);
    doc.y += 24;
    return;
  }

  findings.forEach((f, idx) => {
    pdfh.ensureSpace(doc, ROW_H);
    const rowY = doc.y;
    if (idx % 2 === 1) doc.rect(leftMargin, rowY, pageWidth, ROW_H).fill('#f8fafc');
    // Left accent stripe colored by severity
    doc.rect(leftMargin, rowY, 3, ROW_H).fill(pdfh.severityColorFor(f.inherent_risk));

    doc.fontSize(8).font('Helvetica-Bold').fillColor('#1e293b')
      .text(f.finding_code || '—', leftMargin + 6 + colCode, rowY + 5, { width: 50 });
    doc.fontSize(8).font('Helvetica').fillColor('#1e293b')
      .text(f.title || '', leftMargin + 6 + colTitle, rowY + 5,
        { width: colCat - colTitle - 8, ellipsis: true, lineBreak: false });
    doc.fontSize(7.5).font('Helvetica').fillColor('#64748b')
      .text(f.category || '—', leftMargin + 6 + colCat, rowY + 5, { width: 56, ellipsis: true, lineBreak: false });
    doc.fontSize(8).font('Helvetica').fillColor('#1e293b')
      .text(String(f.likelihood ?? '—'), leftMargin + 6 + colL, rowY + 5, { width: 18 })
      .text(String(f.impact ?? '—'),     leftMargin + 6 + colI, rowY + 5, { width: 18 })
      .text(String(f.inherent_risk ?? '—'), leftMargin + 6 + colRisk, rowY + 5, { width: 28 });
    // Severity badge
    pdfh.renderSeverityBadge(doc, leftMargin + 6 + colSev, rowY + 3, f.inherent_risk, 56);
    doc.fontSize(7.5).font('Helvetica').fillColor('#1e293b')
      .text((f.status || 'open').toUpperCase(), leftMargin + 6 + colStatus, rowY + 5, { width: 32 });
    doc.y = rowY + ROW_H;
  });

  // Severity legend
  doc.moveDown(0.4);
  const legY = doc.y;
  const legends = [
    { label: 'CRITICAL', color: '#dc2626' },
    { label: 'HIGH',     color: '#ea580c' },
    { label: 'MEDIUM',   color: '#d97706' },
    { label: 'LOW',      color: '#0891b2' }
  ];
  let lx = leftMargin;
  doc.fontSize(7).font('Helvetica-Bold').fillColor('#64748b')
    .text('SEVERITY:', lx, legY + 2, { width: 50 });
  lx += 50;
  legends.forEach(l => {
    doc.roundedRect(lx, legY + 1, 8, 8, 2).fill(l.color);
    doc.fontSize(7).font('Helvetica').fillColor('#64748b')
      .text(l.label, lx + 11, legY + 2, { width: 60 });
    lx += 70;
  });
  doc.y = legY + 14;
}

/**
 * Top-N critical findings as visually distinct cards under the heat map.
 */
function renderTopCriticalFindings(doc, findings, n = 3) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const left = doc.page.margins.left;
  const top = [...findings]
    .filter(f => Number(f.inherent_risk || 0) >= 5)
    .sort((a, b) => Number(b.inherent_risk || 0) - Number(a.inherent_risk || 0))
    .slice(0, n);
  if (top.length === 0) return;

  doc.fontSize(9).font('Helvetica-Bold').fillColor('#1e293b')
    .text(`Top ${top.length} risk${top.length > 1 ? 's' : ''} demanding attention:`,
      left, doc.y, { width: pageWidth });
  doc.moveDown(0.3);
  top.forEach((f) => {
    pdfh.ensureSpace(doc, 44);
    const rowY = doc.y;
    const cardW = pageWidth;
    const sev = pdfh.severityColorFor(f.inherent_risk);
    doc.rect(left, rowY, cardW, 38).fillOpacity(0.04).fill(sev).fillOpacity(1);
    doc.rect(left, rowY, 4, 38).fill(sev);
    doc.fontSize(7).font('Helvetica-Bold').fillColor(sev)
      .text(pdfh.severityLabelFor(f.inherent_risk) + ' · RISK ' + (f.inherent_risk ?? '—'),
        left + 14, rowY + 6, { characterSpacing: 1 });
    doc.fontSize(10).font('Helvetica-Bold').fillColor('#1e293b')
      .text(`${f.finding_code || ''} — ${f.title || ''}`,
        left + 14, rowY + 18, { width: cardW - 28, lineBreak: false, ellipsis: true });
    doc.fontSize(7.5).font('Helvetica').fillColor('#64748b')
      .text(`L${f.likelihood ?? '?'} × I${f.impact ?? '?'} · ${f.category || 'uncategorized'}`,
        left + 14, rowY + 30, { width: cardW - 28 });
    doc.y = rowY + 42;
  });
}

/**
 * Pull the CIS RAM workbook bundle for this profile, in the same shape the
 * frontend uses (controls grouped, rows decorated with is_reasonable). Reuses
 * the same helpers as routes/cis-ram.js so the PDF is consistent with the UI.
 */
async function loadCisRamForPdf(profileId) {
  const cisRamRoute = require('./cis-ram');
  const a = await pool.query(`SELECT * FROM cis_ram_assessments WHERE profile_id = $1`, [profileId]);
  if (a.rowCount === 0) return null;
  const rowsQ = await pool.query(
    `SELECT * FROM cis_ram_safeguards WHERE profile_id = $1 ORDER BY safeguard_num`,
    [profileId]
  );
  if (rowsQ.rowCount === 0) return null;
  const acceptable = a.rows[0].acceptable_risk_score;
  const decorated = rowsQ.rows.map(r => cisRamRoute.decorateRow(r, acceptable));
  return {
    assessment: a.rows[0],
    controls: cisRamRoute.groupByControl(decorated),
    rows: decorated,
  };
}

function renderCisRamRegister(doc, cisRam) {
  if (!cisRam || !cisRam.controls || cisRam.controls.length === 0) return;
  const ig1 = frameworks.getCisIg1();
  const safeguardName = Object.fromEntries((ig1.safeguards || []).map(sg => [sg.num, sg.name]));

  doc.addPage();
  pdfh.renderSectionHeader(doc, 'CIS RAM v2.1 Methodology');
  doc.fontSize(9).font('Helvetica').fillColor('#1e293b').text(
    `This assessment uses CIS RAM v2.1 — the published Risk Assessment Method aligned with CIS Controls IG1. ` +
    `Each safeguard is scored on Mission Impact × Obligations Impact × Likelihood (1–3 scale each). ` +
    `Inherent risk is the product of likelihood and the higher of the two impact dimensions. ` +
    `Treatments are "reasonable" when their residual risk score is at or below the engagement's ` +
    `acceptable risk threshold (currently ${cisRam.assessment.acceptable_risk_score}).`,
    { width: doc.page.width - doc.page.margins.left - doc.page.margins.right, lineGap: 2 }
  );
  doc.moveDown(0.6);

  pdfh.renderSectionHeader(doc, 'CIS RAM Risk Register');
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;

  for (const ctrl of cisRam.controls) {
    pdfh.ensureSpace(doc, 26);
    // Control band
    doc.rect(leftMargin, doc.y, pageWidth, 16).fill('#e2e8f0');
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#1e293b')
      .text(`Control ${ctrl.control} — ${ctrl.control_name}    (${ctrl.scored}/${ctrl.total} scored)`,
            leftMargin + 8, doc.y - 13, { width: pageWidth - 16 });
    doc.y += 4;

    // Header row
    pdfh.ensureSpace(doc, 14);
    const hY = doc.y;
    doc.fontSize(7).font('Helvetica-Bold').fillColor('#64748b')
      .text('#',          leftMargin + 8,        hY, { width: 28 })
      .text('Safeguard',  leftMargin + 38,       hY, { width: pageWidth - 270 })
      .text('Asset',      leftMargin + pageWidth - 230, hY, { width: 70 })
      .text('Inh',        leftMargin + pageWidth - 158, hY, { width: 22 })
      .text('Res',        leftMargin + pageWidth - 132, hY, { width: 22 })
      .text('Reas',       leftMargin + pageWidth - 106, hY, { width: 26 })
      .text('Yr',         leftMargin + pageWidth - 76,  hY, { width: 22 })
      .text('Status',     leftMargin + pageWidth - 50,  hY, { width: 50 });
    doc.y = hY + 10;

    // Rows
    ctrl.rows.forEach((r, idx) => {
      pdfh.ensureSpace(doc, 13);
      const rowY = doc.y;
      if (idx % 2 === 1) doc.rect(leftMargin, rowY, pageWidth, 12).fill('#f8fafc');
      doc.fontSize(7).font('Helvetica').fillColor('#1e293b')
        .text(r.safeguard_num,                     leftMargin + 8,        rowY + 1, { width: 28 })
        .text(safeguardName[r.safeguard_num] || '',leftMargin + 38,       rowY + 1, { width: pageWidth - 270, ellipsis: true, lineBreak: false })
        .text(r.asset_class || '—',                leftMargin + pageWidth - 230, rowY + 1, { width: 70, ellipsis: true, lineBreak: false })
        .text(r.inherent_risk_score ?? '—',        leftMargin + pageWidth - 158, rowY + 1, { width: 22 })
        .text(r.residual_risk_score ?? '—',        leftMargin + pageWidth - 132, rowY + 1, { width: 22 })
        .text(r.is_reasonable === true ? '✓' : (r.is_reasonable === false ? '✗' : '—'),
                                                    leftMargin + pageWidth - 106, rowY + 1, { width: 26 })
        .text(r.implementation_year || '—',        leftMargin + pageWidth - 76,  rowY + 1, { width: 22 })
        .text(r.status || 'open',                  leftMargin + pageWidth - 50,  rowY + 1, { width: 50 });
      doc.y = rowY + 12;
    });
    doc.moveDown(0.4);
  }
}

function renderCisRamTreatmentPlan(doc, cisRam) {
  if (!cisRam || !cisRam.rows) return;
  const acceptable = cisRam.assessment.acceptable_risk_score;
  // Treatment plan = rows that aren't yet "reasonable" (residual > acceptable)
  // OR rows with inherent above acceptable that haven't been treated, excluding accepted.
  const items = cisRam.rows.filter(r => {
    if (r.status === 'accepted' || r.status === 'not_applicable') return false;
    if (r.inherent_risk_score == null) return false;
    if (r.inherent_risk_score <= acceptable) return false;
    return true;
  }).sort((a, b) => (b.inherent_risk_score || 0) - (a.inherent_risk_score || 0));

  if (items.length === 0) {
    doc.addPage();
    pdfh.renderSectionHeader(doc, 'CIS RAM Treatment Plan');
    doc.fontSize(10).font('Helvetica').fillColor('#64748b')
      .text('No items above the acceptable risk threshold — no treatment plan required.');
    return;
  }

  const ig1 = frameworks.getCisIg1();
  const safeguardName = Object.fromEntries((ig1.safeguards || []).map(sg => [sg.num, sg.name]));

  doc.addPage();
  pdfh.renderSectionHeader(doc, 'CIS RAM Treatment Plan');
  doc.fontSize(9).font('Helvetica').fillColor('#1e293b').text(
    `${items.length} item${items.length === 1 ? '' : 's'} require attention — sorted by descending inherent risk. ` +
    `"Reasonable" treatments bring residual risk to ${acceptable} or below.`
  );
  doc.moveDown(0.5);

  for (const r of items) {
    pdfh.ensureSpace(doc, 60);
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f')
      .text(`${r.safeguard_num} — ${safeguardName[r.safeguard_num] || ''}`);
    doc.fontSize(8).font('Helvetica').fillColor('#64748b')
      .text(`Asset: ${r.asset_class || '—'}  |  Inherent ${r.inherent_risk_score ?? '—'}  →  Residual ${r.residual_risk_score ?? '—'}  ` +
            `|  ${r.is_reasonable === true ? 'Reasonable ✓' : (r.is_reasonable === false ? 'NOT reasonable ✗' : 'No treatment scored')}` +
            (r.implementation_year ? `  |  Target ${r.implementation_year}` : '') +
            (r.treatment_cost ? `  |  Cost ${r.treatment_cost}` : ''));
    doc.moveDown(0.2);
    if (r.treatment_title || r.treatment_description) {
      pdfh.renderTextarea(doc, 'Treatment',
        (r.treatment_title ? r.treatment_title + '\n\n' : '') + (r.treatment_description || ''));
    }
    if (r.notes) pdfh.renderTextarea(doc, 'Notes', r.notes);
    doc.moveDown(0.3);
  }
}

function renderClinicRiskAssessmentPdf(doc, data) {
  const { profile, intake, report, findings, cis_coverage, csf_scores, charts = {}, cisRam = null } = data;
  const coverName = profile.company_name || intake?.cover_name || 'Unknown Organization';
  const isTraining = intake?.source === 'ai_simulated' || profile.profile_source !== 'real_intake';
  const reportId = (report.id || '').slice(0, 8) || 'draft';
  const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  const csfFnNames = { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' };
  const csfAvg = (() => {
    const vals = Object.keys(csfFnNames).map(k => Number(csf_scores[k] || 0));
    return vals.reduce((s, v) => s + v, 0) / vals.length;
  })();

  const criticalCount = findings.filter(f => Number(f.inherent_risk || 0) >= 7).length;
  const highCount     = findings.filter(f => Number(f.inherent_risk || 0) >= 5 && Number(f.inherent_risk) < 7).length;
  const posture = intake?.payload?._meta?.posture || null;

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 1 — HERO COVER
  // ═══════════════════════════════════════════════════════════════════════
  pdfh.renderHeroCover(doc, {
    eyebrow: 'Cybersecurity Risk Assessment',
    title:   'Risk Assessment Report',
    companyName: coverName,
    subtitle: `Prepared ${date}`,
    watermark: isTraining ? 'Training Sample' : null,
    meta: [
      ['Report ID',       reportId.toUpperCase()],
      ['Engagement Type', isTraining ? 'Training engagement' : 'Real-client engagement'],
      ['Findings',        `${findings.length} (${criticalCount} critical · ${highCount} high)`],
      ['IG1 Coverage',    `${cis_coverage.score}%`],
      ['CSF Maturity',    `${csfAvg.toFixed(1)} / 5`],
      ['Prepared By',     (report.branding?.prepared_by) || 'Clinic-in-a-Box Platform']
    ],
    footerRight: `Report ${reportId.toUpperCase()} · ${date}`
  });

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 2 — EXECUTIVE DASHBOARD
  // ═══════════════════════════════════════════════════════════════════════
  pdfh.renderSectionHeaderModern(doc, 'Executive Dashboard', 'Section 01');

  const tiles = [
    { label: 'Total findings',  value: String(findings.length),
      sub: criticalCount > 0 ? `${criticalCount} critical` : 'none critical',
      color: criticalCount > 0 ? '#dc2626' : '#0891b2' },
    { label: 'Critical risks',  value: String(criticalCount),
      sub: criticalCount === 0 ? 'all under control' : 'immediate attention',
      color: criticalCount > 0 ? '#dc2626' : '#16a34a' },
    { label: 'IG1 coverage',    value: `${cis_coverage.score}%`,
      sub: `${cis_coverage.yes} of ${cis_coverage.total} met · ${cis_coverage.partial} partial`,
      color: cis_coverage.score >= 70 ? '#16a34a' : cis_coverage.score >= 40 ? '#d97706' : '#dc2626' },
    { label: 'CSF maturity',    value: csfAvg.toFixed(1),
      sub: 'avg of 6 functions, scale 0–5',
      color: csfAvg >= 3.5 ? '#16a34a' : csfAvg >= 2 ? '#d97706' : '#dc2626' }
  ];
  pdfh.renderKpiTiles(doc, tiles);

  // Posture archetype callout
  if (posture && posture.name) {
    pdfh.renderCallout(doc, {
      title: `Compliance Posture: ${prettyArchetype(posture.name)}`,
      body:  posture.description || '',
      color: '#1e40af'
    });
  }

  // Executive summary text
  if (report.exec_summary && report.exec_summary.trim()) {
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f').text('Executive Summary');
    doc.moveDown(0.2);
    doc.fontSize(9.5).font('Helvetica').fillColor('#1e293b')
      .text(report.exec_summary, { width: doc.page.width - doc.page.margins.left - doc.page.margins.right, align: 'justify' });
    doc.moveDown(0.5);
  } else {
    pdfh.renderCallout(doc, {
      title: 'Executive summary pending',
      body:  'The assessor has not yet drafted an executive summary on the Report tab. The narrative section will populate here once authored — the data sections below already reflect the current intake + scoring state.',
      color: '#d97706'
    });
  }

  // Engagement scope grid
  doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f').text('Engagement Scope');
  doc.moveDown(0.25);
  const company = intake?.payload?.sections?.company || {};
  const network = intake?.payload?.sections?.network || {};
  const ep = intake?.payload?.sections?.endpoint || {};
  const access = intake?.payload?.sections?.access || {};
  const dp = intake?.payload?.sections?.data || {};

  const scopeLines = [
    ['Industry',           company.industry || '—'],
    ['Employee band',      company.employees_band || '—'],
    ['Revenue band',       company.revenue_band || '—'],
    ['HQ region',          company.region || '—'],
    ['Endpoints',          String(network.endpoint_count ?? '—')],
    ['Servers',            String(network.server_count ?? '—')],
    ['Domain mode',        (network.domain_mode || '—').toUpperCase()],
    ['Compliance scope',   Array.isArray(company.frameworks) && company.frameworks.length ? company.frameworks.join(', ') : 'None declared'],
    ['Primary EDR',        ep.av_vendor || '—'],
    ['MFA coverage',       access.mfa_coverage || '—'],
    ['Backups',            dp.backup_cadence ? `${dp.backup_cadence} · offsite=${dp.offsite_backup || 'n/a'}` : '—']
  ];
  renderTwoColTable(doc, scopeLines);

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 3 — RISK HEAT MAP
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  pdfh.renderSectionHeaderModern(doc, 'Risk Heat Map', 'Section 02 · Inherent Risk');
  if (charts.heatmap_png) {
    embedChart(doc, charts.heatmap_png, 360);
  } else {
    renderHeatmapTable(doc, findings);
  }
  // Top 3 critical
  renderTopCriticalFindings(doc, findings, 3);

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 4 — FINDINGS TABLE
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  pdfh.renderSectionHeaderModern(doc, 'Findings — Sorted by Inherent Risk', 'Section 03');
  renderFindingsTable(doc, findings);

  // CIS RAM Register + Treatment Plan if present
  renderCisRamRegister(doc, cisRam);
  renderCisRamTreatmentPlan(doc, cisRam);

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 5 — CIS IG1 COMPLIANCE
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  pdfh.renderSectionHeaderModern(doc, 'CIS Controls IG1 Compliance', 'Section 04 · CIS v8 Implementation Group 1');

  // Coverage stat-block (3 columns)
  pdfh.renderKpiTiles(doc, [
    { label: 'Coverage score', value: `${cis_coverage.score}%`, sub: `of ${cis_coverage.total} safeguards`, color: '#1e40af' },
    { label: 'Met (yes)',      value: String(cis_coverage.yes),     sub: 'fully implemented',          color: '#16a34a' },
    { label: 'Partial',        value: String(cis_coverage.partial), sub: 'in progress',                color: '#d97706' },
    { label: 'Not met',        value: String(cis_coverage.no),      sub: 'remediation required',      color: '#dc2626' }
  ], { height: 70 });

  if (charts.cis_png) embedChart(doc, charts.cis_png, 200);

  // Posture callout (repeat — it's relevant context for IG1 results)
  if (posture && posture.name) {
    pdfh.renderCallout(doc, {
      title: `Why this distribution? Posture: ${prettyArchetype(posture.name)}`,
      body:  posture.description ||
        'This organization shows an uneven baseline — strong in some control families and weaker in others. The pattern matches their stated maturity and business priorities.',
      color: '#1e40af'
    });
  }

  // Top unmet IG1 safeguards (top 5 'no' answers)
  const ig1Notes = intake?.payload?.sections?.ig1 || {};
  const ig1Cat   = require('../utils/frameworks').getCisIg1();
  const sgIndex  = Object.fromEntries((ig1Cat.safeguards || []).map(s => [s.num, s]));
  const unmet = Object.entries(ig1Notes)
    .filter(([k, v]) => /^ig1_\d+\.\d+$/.test(k) && v === 'no')
    .map(([k]) => k.replace('ig1_', ''))
    .map(num => sgIndex[num])
    .filter(Boolean)
    .slice(0, 5);
  if (unmet.length) {
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f').text('Top unmet safeguards');
    doc.moveDown(0.2);
    pdfh.renderBulletList(doc, unmet.map(sg => `${sg.num} — ${sg.name} (${sg.control_name})`),
      { bulletColor: '#dc2626' });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 6 — NIST CSF 2.0 MATURITY
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  pdfh.renderSectionHeaderModern(doc, 'NIST CSF 2.0 Maturity', 'Section 05 · Functional Posture');

  if (charts.radar_png) embedChart(doc, charts.radar_png, 320);
  if (charts.csf_png)   embedChart(doc, charts.csf_png, 220);

  // Function-by-function table
  doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f').text('Function scores');
  doc.moveDown(0.25);
  const fnLines = Object.entries(csfFnNames).map(([id, name]) =>
    [name, `${(csf_scores[id] ?? 0).toFixed(1)} / 5`]);
  renderTwoColTable(doc, fnLines);

  // Weakest function callout
  const ranked = Object.entries(csfFnNames)
    .map(([id, name]) => ({ id, name, score: Number(csf_scores[id] || 0) }))
    .sort((a, b) => a.score - b.score);
  if (ranked.length && ranked[0].score < 3) {
    pdfh.renderCallout(doc, {
      title: `Weakest function: ${ranked[0].name} (${ranked[0].score.toFixed(1)} / 5)`,
      body:  `Prioritize controls aligned to NIST CSF "${ranked[0].name}" first — this is where the organization is most exposed today.`,
      color: '#dc2626'
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PAGE 7 — RECOMMENDATIONS
  // ═══════════════════════════════════════════════════════════════════════
  const recs = buildRecommendations({ findings, cis_coverage, csf_scores, posture, intake });
  if (recs.quickWins.length || recs.strategic.length) {
    doc.addPage();
    pdfh.renderSectionHeaderModern(doc, 'Recommendations', 'Section 06 · Prioritized Action Plan');

    if (recs.quickWins.length) {
      pdfh.renderCallout(doc, {
        title: 'Quick wins — implement within 30 days',
        body:  'High-impact controls that require minimal capital outlay or vendor procurement. The IT lead can typically own these within their existing licensing.',
        color: '#16a34a'
      });
      pdfh.renderBulletList(doc, recs.quickWins, { bulletColor: '#16a34a' });
      doc.moveDown(0.4);
    }
    if (recs.strategic.length) {
      pdfh.renderCallout(doc, {
        title: 'Strategic initiatives — 90 days to 6 months',
        body:  'Larger lifts that require budget approval, vendor selection, or cross-team coordination. Stage these into the next quarterly planning cycle.',
        color: '#1e40af'
      });
      pdfh.renderBulletList(doc, recs.strategic, { bulletColor: '#1e40af' });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // FINAL — DETAILED FINDINGS APPENDIX
  // ═══════════════════════════════════════════════════════════════════════
  if (findings.length > 0) {
    doc.addPage();
    pdfh.renderSectionHeaderModern(doc, 'Detailed Findings', 'Appendix A');
    findings.forEach(f => {
      pdfh.ensureSpace(doc, 70);
      const top = doc.y;
      const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
      const left = doc.page.margins.left;
      const sev = pdfh.severityColorFor(f.inherent_risk);

      // Title row with severity stripe
      doc.rect(left, top, 4, 20).fill(sev);
      doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f')
        .text(`${f.finding_code || ''} — ${f.title || ''}`, left + 12, top + 3, { width: pageWidth - 80 });
      pdfh.renderSeverityBadge(doc, left + pageWidth - 60, top + 4, f.inherent_risk, 60);
      doc.y = top + 24;
      doc.fontSize(8).font('Helvetica').fillColor('#64748b')
        .text(`Category: ${f.category || '—'}   ·   Likelihood ${f.likelihood ?? '?'} × Impact ${f.impact ?? '?'} = Risk ${f.inherent_risk ?? '?'}   ·   Status: ${(f.status || 'open').toUpperCase()}`,
          left + 12, doc.y, { width: pageWidth - 12 });
      doc.moveDown(0.3);
      if (f.description)   pdfh.renderTextarea(doc, 'Description',    f.description);
      if (f.recommendation) pdfh.renderTextarea(doc, 'Recommendation', f.recommendation);
      const refs = Array.isArray(f.control_refs) ? f.control_refs : [];
      if (refs.length > 0) {
        const refStr = refs.map(r => `${r.framework || '?'}:${r.id || '?'}`).join(', ');
        doc.fontSize(8).font('Helvetica-Oblique').fillColor('#64748b')
          .text('Control refs: ' + refStr, left, doc.y, { width: pageWidth });
      }
      doc.moveDown(0.5);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // METHODOLOGY APPENDIX
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  pdfh.renderSectionHeaderModern(doc, 'Methodology', 'Appendix B · How this report was built');
  doc.fontSize(9.5).font('Helvetica').fillColor('#1e293b').text(
    'This assessment combines (1) an intake questionnaire completed by the assessor — covering organizational profile, network topology, endpoint security, account management, and data protection — and (2) a baseline against the CIS Controls v8 Implementation Group 1 (IG1) and NIST Cybersecurity Framework 2.0. Findings are scored on a 1–5 likelihood × 1–5 impact scale (CIS RAM v2.1 style) producing a 1–25 inherent-risk score normalized to a 0–9 severity band.',
    { width: doc.page.width - doc.page.margins.left - doc.page.margins.right, align: 'justify' }
  );
  doc.moveDown(0.4);
  doc.fontSize(9.5).font('Helvetica').fillColor('#1e293b').text(
    'CSF maturity scores are computed by mapping each IG1 safeguard\'s response (yes / partial / no) to one or more CSF functions via the IG1↔CSF crosswalk, then averaging per function and normalizing to a 0–5 maturity scale. The Compliance Posture archetype is derived from the response pattern and indicates where the organization has invested compared to similar peers.',
    { width: doc.page.width - doc.page.margins.left - doc.page.margins.right, align: 'justify' }
  );
  doc.moveDown(0.4);
  pdfh.renderBulletList(doc, [
    'CIS Controls v8 (IG1) — Center for Internet Security, www.cisecurity.org/controls/v8',
    'NIST Cybersecurity Framework 2.0 — National Institute of Standards and Technology',
    'CIS Risk Assessment Method (RAM) v2.1 — methodology for likelihood × impact risk scoring'
  ]);

  // ═══════════════════════════════════════════════════════════════════════
  // FOOTERS (after all content is drawn)
  // ═══════════════════════════════════════════════════════════════════════
  pdfh.renderPageFooters(doc, {
    left:  `Clinic-in-a-Box · ${coverName} · Risk Assessment Report`,
    right: `Report ${reportId.toUpperCase()}`
  });
}

// Small helper — two-column key/value table
function renderTwoColTable(doc, rows) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const left = doc.page.margins.left;
  const colW = Math.floor(pageWidth / 2);
  rows.forEach((row, i) => {
    pdfh.ensureSpace(doc, 16);
    const top = doc.y;
    if (i % 2 === 1) doc.rect(left, top, pageWidth, 16).fill('#f8fafc');
    doc.fontSize(8.5).font('Helvetica-Bold').fillColor('#64748b')
      .text(row[0], left + 6, top + 4, { width: colW - 10 });
    doc.fontSize(8.5).font('Helvetica').fillColor('#1e293b')
      .text(String(row[1] ?? '—'), left + colW + 6, top + 4, { width: colW - 12 });
    doc.y = top + 16;
  });
}

// Pretty-print an archetype slug — "tech-mature-policy-weak" → "Tech-mature, policy-weak"
function prettyArchetype(name) {
  return String(name || '')
    .split('-').map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(' ')
    .replace(/Mature /g, 'mature, ').replace(/Weak /g, 'weak, ').replace(/,\s*$/, '');
}

// Build prioritized recommendations from coverage gaps + findings + posture.
function buildRecommendations({ findings, cis_coverage, csf_scores, posture, intake }) {
  const quickWins = [];
  const strategic = [];
  const access = intake?.payload?.sections?.access || {};
  const dp = intake?.payload?.sections?.data || {};
  const ep = intake?.payload?.sections?.endpoint || {};
  const va = intake?.payload?.sections?.vuln_audit || {};

  // Quick wins driven by intake gaps
  if (access.mfa_coverage && access.mfa_coverage.toLowerCase().includes('exec')) {
    quickWins.push('Extend MFA enforcement from executives to ALL accounts (CIS 6.3, 6.5) — typically a setting change in the existing identity provider.');
  }
  if (dp.restore_test && /never|not|none/i.test(dp.restore_test)) {
    quickWins.push('Schedule a quarterly backup restore test (CIS 11.4) — pick a non-critical workload and document the steps.');
  }
  if (dp.offsite_backup && /no/i.test(dp.offsite_backup)) {
    quickWins.push('Add an offsite backup tier (CIS 11.2) — cloud archive at the existing backup product is usually a single licensing add-on.');
  }
  if (ep.usb_policy && /allow/i.test(ep.usb_policy)) {
    quickWins.push('Restrict removable-media usage on endpoints (CIS 10.3) via existing EDR / GPO; allow-list specific business uses.');
  }
  if (va.siem && /none/i.test(va.siem)) {
    quickWins.push('Enable centralized log forwarding to a free-tier SIEM (Wazuh, Elastic Cloud trial) for at least firewall + EDR + auth events (CIS 8.1–8.3).');
  }

  // Strategic from coverage thresholds
  if (cis_coverage.score < 50) {
    strategic.push('Run a 90-day IG1 uplift sprint: target the top 10 unmet safeguards (Appendix A) with named owners and weekly status review.');
  }
  if ((csf_scores.RS || 0) < 2.5) {
    strategic.push('Stand up a documented incident response plan + run one tabletop exercise per quarter (CSF Respond function below threshold).');
  }
  if ((csf_scores.RC || 0) < 2.5 || (csf_scores.DE || 0) < 2.5) {
    strategic.push('Consider managed detection & response (MDR) service to lift Detect + Recover function maturity without hiring a SOC team.');
  }
  if (posture && posture.name === 'policy-strong-tech-weak') {
    strategic.push('Translate existing policy documents into enforced technical controls (Intune/Jamf baselines, GPO, conditional-access policies).');
  }
  if (posture && posture.name === 'tech-mature-policy-weak') {
    strategic.push('Document current technical controls into formal policy with assigned ownership (board-level approval; annual review cadence).');
  }
  // Per-critical-finding rec
  const crits = findings.filter(f => Number(f.inherent_risk || 0) >= 7);
  if (crits.length > 0) {
    strategic.push(`Treat the ${crits.length} critical-risk finding${crits.length > 1 ? 's' : ''} (Appendix A) as the top board-reported KPIs for the next two quarters.`);
  }

  return { quickWins, strategic };
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

    // CIS RAM bundle for the deliverable (Phase 2). Best-effort: if the
    // tables/rows aren't there yet, the renderer skips the CIS RAM section.
    const cisRam = await loadCisRamForPdf(profileId).catch(err => {
      console.warn('[CRA export] CIS RAM not available:', err.message);
      return null;
    });

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
      cis_coverage, csf_scores, charts, cisRam,
    });
    doc.end();
  } catch (err) {
    console.error('[CRA export]', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.renderClinicRiskAssessmentPdf = renderClinicRiskAssessmentPdf;
