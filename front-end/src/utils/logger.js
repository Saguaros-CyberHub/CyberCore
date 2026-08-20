'use strict';

/**
 * ============================================================================
 * LOGGER
 * Structured, leveled logging to stdout/stderr and rotating daily log files.
 *
 * Usage:
 *   const logger = require('./utils/logger');
 *   const log = logger('workstations');
 *   log.info('VM deployed', { vmId, node });
 *   log.warn('Proxmox unreachable', { error: err.message });
 *   log.error('Deploy failed', err);          // Error objects → stack trace
 *   log.debug('Clone params', { newid, name });
 *   log.http('POST /api/workstations 201 42ms');
 *
 * Environment:
 *   LOG_LEVEL   — error | warn | info | http | debug  (default: info)
 *   LOG_DIR     — path to log directory               (default: <cwd>/logs)
 *   NO_COLOR    — set any value to disable ANSI color
 * ============================================================================
 */

const fs   = require('fs');
const path = require('path');
const util = require('util');

// ── Levels (lower = more critical) ───────────────────────────────────────────
const LEVELS = { error: 0, warn: 1, info: 2, http: 3, debug: 4 };

// ── ANSI colours ──────────────────────────────────────────────────────────────
const C = {
  reset:  '\x1b[0m',
  dim:    '\x1b[2m',
  bold:   '\x1b[1m',
  error:  '\x1b[31m',   // red
  warn:   '\x1b[33m',   // yellow
  info:   '\x1b[36m',   // cyan
  http:   '\x1b[35m',   // magenta
  debug:  '\x1b[90m',   // bright-black (grey)
};

// ── Config ────────────────────────────────────────────────────────────────────
const LOG_LEVEL_NAME = (process.env.LOG_LEVEL || 'info').toLowerCase();
const ACTIVE_LEVEL   = LEVELS[LOG_LEVEL_NAME] ?? LEVELS.info;
const LOG_DIR        = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
const COLORIZE       = !process.env.NO_COLOR;

// ── Ensure log directory exists (fail silently — never crash for logging) ────
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {}

// ── Formatting helpers ────────────────────────────────────────────────────────
function ts() {
  return new Date().toISOString();
}

function padLevel(lvl) {
  return lvl.toUpperCase().padEnd(5);
}

function serializeMeta(meta) {
  if (meta == null)           return '';
  if (meta instanceof Error)  return '\n' + (meta.stack || meta.message);
  if (typeof meta === 'object') {
    try { return ' ' + util.inspect(meta, { depth: 4, colors: false, breakLength: 120 }); }
    catch (_) { return ' [unserializable]'; }
  }
  return ' ' + String(meta);
}

function consoleLine(level, tag, msg, meta) {
  const stamp = ts();
  const m     = serializeMeta(meta);
  if (COLORIZE) {
    const col = C[level] || C.reset;
    return `${C.dim}${stamp}${C.reset} ${col}${padLevel(level)}${C.reset} ${C.bold}[${tag}]${C.reset} ${msg}${m}`;
  }
  return `${stamp} ${padLevel(level)} [${tag}] ${msg}${m}`;
}

function fileLine(level, tag, msg, meta) {
  return `${ts()} ${padLevel(level)} [${tag}] ${msg}${serializeMeta(meta)}\n`;
}

// ── Rotating file streams ─────────────────────────────────────────────────────
const _streams = { app: null, error: null, date: '' };

function dateStr() {
  return new Date().toISOString().slice(0, 10);
}

function openStream(name, date) {
  try {
    const stream = fs.createWriteStream(
      path.join(LOG_DIR, `${name}-${date}.log`),
      { flags: 'a', encoding: 'utf8' }
    );
    // A WriteStream with no 'error' listener turns an async ENOSPC or EROFS
    // into an uncaught exception — the process dies with no usable stack,
    // because the failure happened inside the logger itself. Drop the stream
    // instead and keep serving; console output is unaffected.
    stream.on('error', (e) => {
      process.stderr.write(`[logger] ${name} log write failed, file logging disabled: ${e.message}
`);
      if (_streams[name] === stream) _streams[name] = null;
      _paused[name] = false;
    });
    return stream;
  } catch (e) {
    process.stderr.write(`[logger] Could not open ${name} log: ${e.message}\n`);
    return null;
  }
}

function getStreams() {
  const d = dateStr();
  if (d !== _streams.date) {
    // Date rolled — close old streams, open new ones
    try { _streams.app?.end();   } catch (_) {}
    try { _streams.error?.end(); } catch (_) {}
    _streams.app   = openStream('app',   d);
    _streams.error = openStream('error', d);
    _streams.date  = d;
  }
  return _streams;
}

// Set while a stream's internal buffer is above its high-water mark. Lines
// logged during that window are dropped rather than queued: losing log lines
// under disk pressure is strictly better than growing an unbounded buffer in a
// process that has no memory limit.
const _paused = { app: false, error: false };

function writeTo(streams, name, line) {
  const stream = streams[name];
  if (!stream || _paused[name]) return;
  try {
    if (stream.write(line) === false) {
      _paused[name] = true;
      stream.once('drain', () => { _paused[name] = false; });
    }
  } catch (_) {}
}

function writeFile(level, line) {
  const s = getStreams();
  writeTo(s, 'app', line);
  if (level === 'error' || level === 'warn') {
    writeTo(s, 'error', line);
  }
}

// ── Core emit ─────────────────────────────────────────────────────────────────
function emit(level, tag, msg, meta) {
  if ((LEVELS[level] ?? 99) > ACTIVE_LEVEL) return;

  const cl = consoleLine(level, tag, msg, meta);
  const fl = fileLine(level, tag, msg, meta);

  // errors and warnings → stderr; everything else → stdout
  if (level === 'error' || level === 'warn') {
    process.stderr.write(cl + '\n');
  } else {
    process.stdout.write(cl + '\n');
  }

  writeFile(level, fl);
}

// ── Logger factory ────────────────────────────────────────────────────────────
// Cache instances so `require('./logger')('workstations')` is idempotent.
const _cache = Object.create(null);

function createLogger(tag) {
  if (_cache[tag]) return _cache[tag];
  const log = {
    error: (msg, meta) => emit('error', tag, String(msg), meta),
    warn:  (msg, meta) => emit('warn',  tag, String(msg), meta),
    info:  (msg, meta) => emit('info',  tag, String(msg), meta),
    http:  (msg, meta) => emit('http',  tag, String(msg), meta),
    debug: (msg, meta) => emit('debug', tag, String(msg), meta),
  };
  _cache[tag] = log;
  return log;
}

module.exports = createLogger;
