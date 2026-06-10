'use strict';

/**
 * Express middleware that logs every HTTP request on response finish.
 * Status >= 500 → error, 400-499 → warn, everything else → http.
 */

const createLogger = require('../utils/logger');
const log = createLogger('http');

module.exports = function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const ms      = Date.now() - start;
    const status  = res.statusCode;
    const method  = req.method;
    const url     = req.originalUrl || req.url;
    // 404 is "not found", not a problem — vuln-range orchestrators get
    // walked by .env/secrets scanners constantly, and logging every miss at
    // warn floods stderr (and docker logs). Map 404 to http so it's hidden at
    // the default info level but still recoverable with LOG_LEVEL=http/debug.
    const level   = status >= 500 ? 'error'
                  : status === 404 ? 'http'
                  : status >= 400 ? 'warn'
                  : 'http';
    const userId  = req.user?.userId;

    const meta = { status, ms, ip: req.ip };
    if (userId) meta.user = userId;

    log[level](`${method} ${url}`, meta);
  });

  next();
};
