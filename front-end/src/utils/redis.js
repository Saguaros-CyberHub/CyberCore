/**
 * Redis Connection
 * Shared Redis client for session storage and caching
 * Uses redis v3 API for compatibility
 */

const redis = require('redis');

// Create Redis client with v3 API
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'redis',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  db: parseInt(process.env.REDIS_DB) || 0,
  retry_strategy: (options) => {
    if (options.error && options.error.code === 'ECONNREFUSED') {
      return Math.min(options.attempt * 100, 3000);
    }
    if (options.total_retry_time > 1000 * 60 * 60) {
      return new Error('Redis retry time exhausted');
    }
    if (options.attempt > 10) {
      return undefined;
    }
    return Math.min(options.attempt * 100, 3000);
  }
});

redisClient.on('ready', () => {
  console.log('✓ Connected to Redis');
});

redisClient.on('error', (err) => {
  // Suppress verbose error logs during connection retries
});

redisClient.on('reconnecting', () => {
  // Silently retry
});

module.exports = redisClient;
