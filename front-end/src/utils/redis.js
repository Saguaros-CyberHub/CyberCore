/**
 * Redis Connection
 * Shared Redis client for session storage and caching
 * Uses the redis v4+ API (node-redis), which connect-redis v9 expects.
 */

const redis = require('redis');

// Total time to keep retrying a dead Redis before giving up, matching the
// one-hour budget the previous v3 retry_strategy enforced.
const RETRY_BUDGET_MS = 1000 * 60 * 60;
const connectingSince = Date.now();

const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || 'redis',
    port: parseInt(process.env.REDIS_PORT) || 6379,
    // v4 replaces retry_strategy with reconnectStrategy: return a delay in ms,
    // or an Error to stop reconnecting. Back off to a 3s ceiling so a Redis
    // that comes up after the app (the usual docker-compose ordering) is picked
    // up promptly without hammering it.
    reconnectStrategy: (retries) => {
      if (Date.now() - connectingSince > RETRY_BUDGET_MS) {
        return new Error('Redis retry time exhausted');
      }
      return Math.min((retries + 1) * 100, 3000);
    },
  },
  database: parseInt(process.env.REDIS_DB) || 0,
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

// v4+ requires an explicit connect(). It is deliberately not awaited: callers
// import this module synchronously, and the client's offline queue holds any
// commands issued before the handshake completes. The catch is required — once
// reconnectStrategy returns an Error this promise rejects, and an unhandled
// rejection would take the process down.
redisClient.connect().catch(() => {
  // Connection errors are already surfaced via the 'error' handler above.
});

module.exports = redisClient;
