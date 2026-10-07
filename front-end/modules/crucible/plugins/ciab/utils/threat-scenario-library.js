/**
 * threat-scenario-library.js — Seeder + accessor for the canonical
 * threat scenario library.
 *
 * On first call, upserts every scenario from
 *   data/threat-scenario-library.json
 * into the threat_scenario_library table. Subsequent calls are no-ops
 * once the catalog version matches. The list endpoint reads from DB
 * (so admins can edit individual entries via SQL without redeploying).
 */

const fs = require('fs');
const path = require('path');

const LIBRARY_JSON = path.join(__dirname, '..', 'data', 'threat-scenario-library.json');
let _seeded = false;

async function seedScenarioLibrary(pool) {
  if (_seeded) return { skipped: true };
  if (!fs.existsSync(LIBRARY_JSON)) {
    console.warn('[scenario-library] data file missing:', LIBRARY_JSON);
    return { error: 'data file missing' };
  }
  const catalog = JSON.parse(fs.readFileSync(LIBRARY_JSON, 'utf8'));
  const scenarios = catalog.scenarios || [];

  let inserted = 0;
  let updated = 0;
  for (const s of scenarios) {
    const r = await pool.query(`
      INSERT INTO threat_scenario_library
        (key, title, category, threat_source, description, recommendation_template,
         default_likelihood, default_impact,
         default_residual_likelihood, default_residual_impact,
         control_refs, applicable_industries, applicable_sizes, tags)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb)
      ON CONFLICT (key) DO UPDATE SET
        title = EXCLUDED.title, category = EXCLUDED.category,
        threat_source = EXCLUDED.threat_source,
        description = EXCLUDED.description,
        recommendation_template = EXCLUDED.recommendation_template,
        default_likelihood = EXCLUDED.default_likelihood,
        default_impact = EXCLUDED.default_impact,
        default_residual_likelihood = EXCLUDED.default_residual_likelihood,
        default_residual_impact = EXCLUDED.default_residual_impact,
        control_refs = EXCLUDED.control_refs,
        applicable_industries = EXCLUDED.applicable_industries,
        applicable_sizes = EXCLUDED.applicable_sizes,
        tags = EXCLUDED.tags,
        updated_at = NOW()
      RETURNING (xmax = 0) AS was_inserted
    `, [
      s.key, s.title, s.category, s.threat_source, s.description, s.recommendation_template,
      s.default_likelihood, s.default_impact,
      s.default_residual_likelihood, s.default_residual_impact,
      JSON.stringify(s.control_refs || []),
      JSON.stringify(s.applicable_industries || ['all']),
      JSON.stringify(s.applicable_sizes || ['SMB', 'MidMarket', 'Enterprise']),
      JSON.stringify(s.tags || [])
    ]);
    if (r.rows[0].was_inserted) inserted++;
    else updated++;
  }
  _seeded = true;
  console.log(`[scenario-library] seeded ${inserted} new, ${updated} updated (${scenarios.length} total)`);
  return { inserted, updated, total: scenarios.length };
}

async function listScenarios(pool, { industry, size, category } = {}) {
  const where = [];
  const params = [];
  if (industry) {
    params.push(industry);
    where.push(`(applicable_industries @> $${params.length}::jsonb OR applicable_industries @> '["all"]'::jsonb)`);
    params[params.length - 1] = JSON.stringify([industry]);
  }
  if (size) {
    params.push(JSON.stringify([size]));
    where.push(`applicable_sizes @> $${params.length}::jsonb`);
  }
  if (category) {
    params.push(category);
    where.push(`category = $${params.length}`);
  }
  const sql = `SELECT * FROM threat_scenario_library ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY category, key`;
  const r = await pool.query(sql, params);
  return r.rows;
}

async function getScenarioByKey(pool, key) {
  const r = await pool.query(`SELECT * FROM threat_scenario_library WHERE key = $1`, [key]);
  return r.rows[0] || null;
}

// Instantiate a library scenario as a finding for a profile.
// Returns the finding object ready for INSERT.
function scenarioToFinding(scenario, opts = {}) {
  const { findingCode = 'F-001', ownerRole = null, targetDate = null } = opts;
  return {
    finding_code: findingCode,
    title: scenario.title,
    description: scenario.description,
    category: scenario.category,
    threat_source: scenario.threat_source,
    likelihood: scenario.default_likelihood,
    impact: scenario.default_impact,
    residual_likelihood: scenario.default_residual_likelihood,
    residual_impact: scenario.default_residual_impact,
    status: 'open',
    recommendation: scenario.recommendation_template,
    control_refs: scenario.control_refs || [],
    scenario_library_key: scenario.key,
    owner_role: ownerRole,
    target_completion_date: targetDate
  };
}

module.exports = {
  seedScenarioLibrary,
  listScenarios,
  getScenarioByKey,
  scenarioToFinding
};
