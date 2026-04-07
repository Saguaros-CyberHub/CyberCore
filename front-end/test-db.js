require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'clinic_db',
  user: process.env.DB_USER || 'clinic_admin',
  password: process.env.DB_PASSWORD,
});

async function test() {
  console.log('Testing connection to:', process.env.DB_HOST);
  console.log('Database:', process.env.DB_NAME);
  console.log('User:', process.env.DB_USER);
  console.log('Password:', process.env.DB_PASSWORD ? '****' : 'NOT SET');
  
  try {
    const result = await pool.query('SELECT NOW()');
    console.log('✅ Connected! Server time:', result.rows[0].now);
    
    // Test users table
    const tables = await pool.query(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    console.log('📋 Tables:', tables.rows.map(r => r.table_name).join(', '));
    
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
  } finally {
    await pool.end();
  }
}

test();