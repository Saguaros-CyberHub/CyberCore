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
  // --- Bound how long a checked-out client may be held ----------------------
  // connectionTimeoutMillis limits ACQUISITION only. Once pg-pool hands a client
  // out, nothing here used to break a query that blocks server-side, so a single
  // stuck statement removed a pool slot permanently and the pool bled out one
  // request at a time — the site going unresponsive while the process looked
  // perfectly healthy. keepAlive covers the other half: a silently blackholed
  // TCP connection (as opposed to a cleanly closed one, which the 'error'
  // handler already deals with) would otherwise park a client forever on a
  // reply that is never coming.
  statement_timeout: 30000,
  query_timeout: 35000,
  lock_timeout: 10000,
  idle_in_transaction_session_timeout: 60000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
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
