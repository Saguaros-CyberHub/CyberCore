/**
 * ============================================================================
 * CYBERCORE DATABASE CONNECTION POOL
 * ============================================================================
 * Separate pool for the CyberCore/Crucible PostgreSQL database
 * (lane management, modules, challenges).
 */

const { Pool } = require('pg');

const cybercorePool = new Pool({
  host: process.env.CYBERCORE_DB_HOST || '100.100.20.50',
  port: parseInt(process.env.CYBERCORE_DB_PORT) || 5432,
  database: process.env.CYBERCORE_DB_NAME || 'cybercore_db',
  user: process.env.CYBERCORE_DB_USER || 'cactus-admin',
  password: process.env.CYBERCORE_DB_PASSWORD,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

cybercorePool.on('connect', () => {
  console.log('Connected to CyberCore PostgreSQL database');
});

cybercorePool.on('error', (err) => {
  console.error('CyberCore database error:', err.message);
});

async function cybercoreQuery(text, params) {
  const start = Date.now();
  try {
    const result = await cybercorePool.query(text, params);
    const duration = Date.now() - start;
    if (process.env.NODE_ENV === 'development') {
      console.log('CyberCore query:', { text: text.substring(0, 50), duration: `${duration}ms`, rows: result.rowCount });
    }
    return result;
  } catch (error) {
    console.error('CyberCore query error:', error.message);
    throw error;
  }
}

module.exports = {
  cybercorePool,
  cybercoreQuery
};
