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
    const level   = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'http';
    const userId  = req.user?.userId;

    const meta = { status, ms, ip: req.ip };
    if (userId) meta.user = userId;

    log[level](`${method} ${url}`, meta);
  });

  next();
};
