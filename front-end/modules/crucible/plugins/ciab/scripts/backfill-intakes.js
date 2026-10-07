#!/usr/bin/env node
/**
 * One-shot backfill: convert intake_form_responses (V7.2 shape) rows into
 * the unified `intakes` table using utils/intake-v72-to-v11.js.
 *
 * Idempotent — checks legacy_source_table + legacy_source_id before insert.
 * Run after migration 003_unify_intakes.sql is applied:
 *
 *   node front-end/modules/crucible/plugins/ciab/scripts/backfill-intakes.js
 *
 * Reads DB config from the same env vars the plugin loader uses.
 */

require('dotenv').config({ path: require('path').join(__dirname, '../../../../../.env') });

const { Pool } = require('pg');
const { convertV72ToV12 } = require('../utils/intake-v72-to-v11');

const pool = new Pool({
  host:     process.env.DB_HOST     || process.env.CYBERCORE_DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || process.env.CYBERCORE_DB_PORT) || 5432,
  user:     process.env.DB_USER     || process.env.CYBERCORE_DB_USER     || process.env.CORE_DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || process.env.CYBERCORE_DB_PASSWORD || process.env.CORE_DB_PASSWORD || '',
  database: 'clinic_db',
});

function computeCompletion(payload) {
  // Mirror logic from V7.2 PDF export: count populated fields across sections.
  let total = 0, filled = 0;
  for (const sec of Object.values(payload.sections || {})) {
    for (const v of Object.values(sec || {})) {
      total++;
      if (v === false) { filled++; continue; }
      if (v == null) continue;
      if (typeof v === 'object' && Object.keys(v).length === 0) continue;
      if (typeof v === 'string' && v.trim() === '') continue;
      if (Array.isArray(v) && v.length === 0) continue;
      filled++;
    }
  }
  return total > 0 ? Math.round((filled / total) * 100) : 0;
}

async function main() {
  console.log('[backfill] Reading intake_form_responses…');
  const { rows } = await pool.query(`
    SELECT ifr.*, p.company_name AS profile_company_name
    FROM intake_form_responses ifr
    LEFT JOIN profiles p ON p.id = ifr.profile_id
  `);
  console.log(`[backfill] Found ${rows.length} V7.2 rows.`);

  let migrated = 0, skipped = 0, errored = 0;

  for (const row of rows) {
    try {
      const exists = await pool.query(
        `SELECT 1 FROM intakes
         WHERE legacy_source_table = 'intake_form_responses' AND legacy_source_id = $1`,
        [row.id]
      );
      if (exists.rowCount > 0) { skipped++; continue; }

      const payload = convertV72ToV12(row);
      // Profile company name takes precedence over field-level cover_name when present.
      const coverName = row.profile_company_name || payload.cover_name;
      payload.cover_name = coverName;
      payload.sections.company.cover_name = coverName;

      const completion = row.completion_percentage ?? computeCompletion(payload);
      const status = row.status === 'complete' ? 'complete' : 'in_progress';

      await pool.query(
        `INSERT INTO intakes
           (user_id, profile_id, source, schema_version, cover_name, payload,
            completion_percentage, status,
            legacy_source_table, legacy_source_id,
            created_at, updated_at, completed_at)
         VALUES ($1,$2,'ai_simulated',$3,$4,$5,$6,$7,'intake_form_responses',$8,$9,$10,$11)`,
        [
          row.user_id, row.profile_id,
          payload.schema_version, coverName, JSON.stringify(payload),
          completion, status,
          row.id,
          row.created_at, row.updated_at,
          row.completed_at,
        ]
      );
      migrated++;
    } catch (err) {
      errored++;
      console.error(`[backfill] FAILED row ${row.id}: ${err.message}`);
    }
  }

  console.log(`[backfill] Done. migrated=${migrated} skipped=${skipped} errored=${errored}`);
  await pool.end();
  process.exit(errored > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('[backfill] Fatal:', err);
  process.exit(1);
});
