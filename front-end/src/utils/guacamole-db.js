/**
 * ============================================================================
 * GUACAMOLE DATABASE CONNECTION (read-only)
 * Direct PostgreSQL connection to Guacamole's database for session audit.
 * ============================================================================
 */

const { Pool } = require('pg');

const guacDbPool = new Pool({
  host: process.env.GUAC_DB_HOST || '100.100.70.10',
  port: parseInt(process.env.GUAC_DB_PORT) || 5432,
  database: process.env.GUAC_DB_NAME || 'guacamole_db',
  user: process.env.GUAC_DB_USER || 'guacamole_user',
  password: process.env.GUAC_DB_PASSWORD || '',
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

guacDbPool.on('error', (err) => {
  console.error('[GuacDB] Pool error:', err.message);
});

async function guacDbQuery(text, params) {
  try {
    return await guacDbPool.query(text, params);
  } catch (error) {
    console.error('[GuacDB] Query error:', error.message);
    throw error;
  }
}

module.exports = { guacDbPool, guacDbQuery };
