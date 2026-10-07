/**
 * ============================================================================
 * DATABASE CONNECTION POOL
 * ============================================================================
 */

const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'clinic_db',
  user: process.env.DB_USER || 'clinic_admin',
  password: process.env.DB_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
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

// Test connection on startup
pool.on('connect', () => {
  console.log('📦 Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected database error:', err);
});

/**
 * Execute a query with parameters
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    if (process.env.NODE_ENV === 'development') {
      console.log('📝 Query executed:', { text: text.substring(0, 50), duration: `${duration}ms`, rows: result.rowCount });
    }
    return result;
  } catch (error) {
    console.error('❌ Database query error:', error.message);
    throw error;
  }
}

/**
 * Get a client from the pool for transactions
 */
async function getClient() {
  const client = await pool.connect();
  const originalQuery = client.query.bind(client);
  const originalRelease = client.release.bind(client);

  // Override release to log
  client.release = () => {
    client.release = originalRelease;
    return originalRelease();
  };

  return client;
}

module.exports = {
  pool,
  query,
  getClient
};
