/**
 * CIAB — CIS RAM v2.1 IG1 Workbook (Phase 2)
 *
 * Mirrors the published CIS RAM workbook — one assessment envelope per profile,
 * 56 safeguard rows lazily pre-populated from data/frameworks/cis-ig1.json on
 * first read. Drives the new "CIS RAM Workbook" tab and feeds the unified
 * Clinic Risk Assessment deliverable.
 *
 * Mount path: /api/cis-ram
 */

const express = require('express');
const router = express.Router();

const { pool } = require('../utils/db');
const { authenticateToken } = require('../../../../../src/middleware/auth');
const frameworks = require('../utils/frameworks');

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

/**
 * Ensure a cis_ram_assessments envelope exists for this profile, lazily
 * inserted with workbook defaults on first call.
 */
async function ensureAssessment(userId, profileId) {
  const existing = await pool.query(
    `SELECT * FROM cis_ram_assessments WHERE profile_id = $1`, [profileId]
  );
  if (existing.rowCount > 0) return existing.rows[0];

  const inserted = await pool.query(
    `INSERT INTO cis_ram_assessments (profile_id, user_id) VALUES ($1, $2) RETURNING *`,
    [profileId, userId]
  );
  return inserted.rows[0];
}

/**
 * Ensure all 56 IG1 safeguard rows exist for this profile. Uses a single
 * INSERT … SELECT with NOT EXISTS so re-runs are no-ops and we don't pay 56
 * round-trips on first open.
 */
async function ensureSafeguardRows(userId, profileId) {
  const ig1 = frameworks.getCisIg1();
  const rows = ig1.safeguards || [];
  if (rows.length === 0) return;

  // Build a VALUES list parameterized for one INSERT.
  // Skip rows that already exist — UNIQUE(profile_id, safeguard_num) makes
  // ON CONFLICT DO NOTHING the safest path here.
  const values = [];
  const params = [];
  rows.forEach((sg, i) => {
    values.push(`($${i * 4 + 1}, $${i * 4 + 2}, $${i * 4 + 3}, $${i * 4 + 4})`);
    params.push(userId, profileId, sg.num, sg.num); // treatment_safeguard defaults to self
  });

  await pool.query(
    `INSERT INTO cis_ram_safeguards (user_id, profile_id, safeguard_num, treatment_safeguard)
       VALUES ${values.join(',')}
     ON CONFLICT (profile_id, safeguard_num) DO NOTHING`,
    params
  );
}

/**
 * Compute "is_reasonable" per safeguard row given the engagement-level
 * acceptable_risk_score. Returns the row with that field added.
 */
function decorateRow(row, acceptable) {
  const residual = row.residual_risk_score;
  // Reasonable iff a treatment is scored AND its residual is at or below acceptable.
  const hasTreatment = residual != null;
  return {
    ...row,
    is_reasonable: hasTreatment ? residual <= acceptable : null,
  };
}

/**
 * Group rows by their CIS Control number ("1.1" → control 1) for the UI's
 * collapsible-section layout. Preserves IG1 catalog order so safeguard_num
 * sorts numerically ("9.1" before "10.1").
 */
function groupByControl(rows) {
  const ig1 = frameworks.getCisIg1();
  const safeguardOrder = new Map();
  (ig1.safeguards || []).forEach((sg, i) => safeguardOrder.set(sg.num, i));

  const sorted = rows.slice().sort((a, b) =>
    (safeguardOrder.get(a.safeguard_num) ?? 999) - (safeguardOrder.get(b.safeguard_num) ?? 999)
  );

  const byControl = new Map();
  for (const row of sorted) {
    const ctrl = parseInt(row.safeguard_num.split('.')[0], 10);
    if (!byControl.has(ctrl)) byControl.set(ctrl, []);
    byControl.get(ctrl).push(row);
  }

  // Annotate each control with its name from the catalog.
  const out = [];
  for (const [controlNum, controlRows] of byControl) {
    const first = (ig1.safeguards || []).find(sg => sg.control === controlNum);
    out.push({
      control: controlNum,
      control_name: first?.control_name || `Control ${controlNum}`,
      rows: controlRows,
      // Per-control completion: count rows that have inherent_risk_score set.
      scored: controlRows.filter(r => r.inherent_risk_score != null).length,
      total: controlRows.length,
    });
  }
  return out;
}

// ============================================================================
// ROUTES
// ============================================================================

// GET /api/cis-ram/:profileId — full workbook bundle for one profile
router.get('/:profileId', async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }

    const profileQ = await pool.query(`SELECT id, company_name FROM profiles WHERE id = $1`, [profileId]);
    if (profileQ.rowCount === 0) return res.status(404).json({ error: 'Profile not found' });

    const assessment = await ensureAssessment(userId, profileId);
    await ensureSafeguardRows(userId, profileId);

    const rows = await pool.query(
      `SELECT * FROM cis_ram_safeguards WHERE profile_id = $1 ORDER BY safeguard_num`,
      [profileId]
    );

    const acceptable = assessment.acceptable_risk_score;
    const decorated = rows.rows.map(r => decorateRow(r, acceptable));
    const ig1 = frameworks.getCisIg1();
    const safeguardCatalog = Object.fromEntries(
      (ig1.safeguards || []).map(sg => [sg.num, { name: sg.name, control: sg.control, control_name: sg.control_name }])
    );

    // Totals for the header bar.
    const scored = decorated.filter(r => r.inherent_risk_score != null).length;
    const reasonable = decorated.filter(r => r.is_reasonable === true).length;
    const aboveAcceptable = decorated.filter(r => r.inherent_risk_score != null && r.inherent_risk_score > acceptable).length;

    res.json({
      profile: profileQ.rows[0],
      assessment,
      safeguard_catalog: safeguardCatalog,
      controls: groupByControl(decorated),
      totals: {
        total: decorated.length,
        scored,
        reasonable,
        above_acceptable: aboveAcceptable,
      },
    });
  } catch (err) {
    console.error('[CIS RAM get]', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/cis-ram/:profileId — update the engagement envelope
router.put('/:profileId', express.json(), async (req, res) => {
  try {
    const { profileId } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }
    await ensureAssessment(userId, profileId);

    const b = req.body || {};
    const fields = [];
    const params = [];
    let i = 1;
    if (b.acceptable_risk_score !== undefined) {
      const n = parseInt(b.acceptable_risk_score, 10);
      if (!Number.isFinite(n) || n < 1 || n > 9) {
        return res.status(400).json({ error: 'acceptable_risk_score must be 1–9' });
      }
      fields.push(`acceptable_risk_score = $${i++}`); params.push(n);
    }
    if (b.impact_criteria !== undefined) {
      fields.push(`impact_criteria = $${i++}::jsonb`);
      params.push(JSON.stringify(b.impact_criteria || {}));
    }
    if (b.status !== undefined) {
      if (!['in_progress', 'complete'].includes(b.status)) {
        return res.status(400).json({ error: "status must be 'in_progress' or 'complete'" });
      }
      fields.push(`status = $${i++}`); params.push(b.status);
      if (b.status === 'complete') fields.push(`completed_at = NOW()`);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push(`updated_at = NOW()`);
    params.push(profileId);

    const r = await pool.query(
      `UPDATE cis_ram_assessments SET ${fields.join(', ')} WHERE profile_id = $${i} RETURNING *`,
      params
    );
    res.json({ assessment: r.rows[0] });
  } catch (err) {
    console.error('[CIS RAM put assessment]', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/cis-ram/:profileId/safeguards/:safeguardNum — update one safeguard row
router.put('/:profileId/safeguards/:safeguardNum', express.json(), async (req, res) => {
  try {
    const { profileId, safeguardNum } = req.params;
    const userId = req.user.userId;
    if (!(await userCanReadProfile(userId, profileId, req.user.role))) {
      return res.status(403).json({ error: 'Not permitted' });
    }

    const b = req.body || {};
    const editable = [
      'asset_class',
      'mission_impact', 'obligations_impact', 'likelihood',
      'treatment_safeguard', 'treatment_title', 'treatment_description',
      'treatment_mission_impact', 'treatment_obligations_impact', 'treatment_likelihood',
      'treatment_cost', 'implementation_year', 'last_completed_date',
      'notes', 'status',
    ];
    const fields = [];
    const params = [];
    let i = 1;
    for (const col of editable) {
      if (b[col] === undefined) continue;
      // Empty-string from inputs becomes NULL so users can clear a field.
      const val = b[col] === '' ? null : b[col];
      fields.push(`${col} = $${i++}`); params.push(val);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push(`updated_at = NOW()`);
    params.push(profileId, safeguardNum);

    const r = await pool.query(
      `UPDATE cis_ram_safeguards SET ${fields.join(', ')}
       WHERE profile_id = $${i++} AND safeguard_num = $${i}
       RETURNING *`,
      params
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Safeguard row not found — open the workbook tab once to pre-populate.' });

    // Decorate with reasonableness for the response.
    const a = await pool.query(`SELECT acceptable_risk_score FROM cis_ram_assessments WHERE profile_id = $1`, [profileId]);
    const acceptable = a.rows[0]?.acceptable_risk_score ?? 6;
    res.json({ row: decorateRow(r.rows[0], acceptable) });
  } catch (err) {
    console.error('[CIS RAM put safeguard]', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.decorateRow = decorateRow;
module.exports.groupByControl = groupByControl;
module.exports.ensureSafeguardRows = ensureSafeguardRows;
