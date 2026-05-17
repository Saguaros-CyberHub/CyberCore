/**
 * CLE Plugin Database Connection
 * Pool is injected by the plugin loader after DB provisioning.
 */

let pool = null;

function setPool(p) {
  pool = p;
  pool.on('error', (err) => {
    console.error('[CLE] Database pool error:', err.message);
  });
}

function getPool() {
  return pool;
}

async function query(text, params) {
  if (!pool) throw new Error('CLE database pool not initialized');
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    if (process.env.NODE_ENV === 'development') {
      console.log('[CLE] query:', { text: text.substring(0, 50), duration: `${duration}ms`, rows: result.rowCount });
    }
    return result;
  } catch (error) {
    console.error('[CLE] query error:', error.message);
    throw error;
  }
}

// Export pool as a property so `const { pool } = require('./db')` works
module.exports = {
  setPool,
  getPool,
  query,
  get pool() { return pool; }
};
