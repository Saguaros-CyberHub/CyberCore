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
  // --- Bound how long a checked-out client may be held ----------------------
  // connectionTimeoutMillis limits ACQUISITION only. Once pg-pool hands a client
  // out, nothing here used to break a query that blocks server-side, so a single
  // stuck statement removed a pool slot permanently and the pool bled out one
  // request at a time — the site going unresponsive while the process looked
  // perfectly healthy. keepAlive covers the other half: a silently blackholed
  // TCP connection (as opposed to a cleanly closed one, which the pool's
  // 'error' handler already deals with) would otherwise park a client forever
  // on a reply that is never coming.
  statement_timeout: 30000,
  query_timeout: 35000,
  lock_timeout: 10000,
  idle_in_transaction_session_timeout: 60000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
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
