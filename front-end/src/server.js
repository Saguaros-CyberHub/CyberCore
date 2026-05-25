/**
 * ============================================================================
 * CYBERHUB - MAIN SERVER
 * ============================================================================
 */

require('dotenv').config();

// ── Logging: must come before everything else so module-load logs are captured ─
const createLogger = require('./utils/logger');
const util = require('util');

// Cache loggers keyed by tag (extracted from [TAG] prefix pattern most modules use)
const _loggers = Object.create(null);
function _getLogger(tag) {
  return _loggers[tag] || (_loggers[tag] = createLogger(tag));
}

// Format variadic console args to a single string
function _fmt(args) {
  return args.map(a => (typeof a === 'string' ? a : util.inspect(a, { depth: 3 }))).join(' ');
}

// Extract [TAG] prefix from message for scoped log lines; falls back to 'app'
function _tag(args) {
  const first = String(args[0] ?? '');
  const m = first.match(/^\[([^\]]{1,40})\]/);
  return m ? m[1] : 'app';
}

// Strip the [TAG] prefix so it doesn't duplicate in the formatted output
function _msg(args) {
  const s = _fmt(args);
  return s.replace(/^\[[^\]]{1,40}\]\s*/, '');
}

// Override console.* — logger writes directly to process.stdout/stderr (no recursion)
console.log   = (...a) => _getLogger(_tag(a)).info (_msg(a));
console.info  = (...a) => _getLogger(_tag(a)).info (_msg(a));
console.warn  = (...a) => _getLogger(_tag(a)).warn (_msg(a));
console.error = (...a) => _getLogger(_tag(a)).error(_msg(a));
console.debug = (...a) => _getLogger(_tag(a)).debug(_msg(a));

const log = createLogger('server');
// ──────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redisClient = require('./utils/redis');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const path = require('path');

/**
 * Soft-decode the JWT from Authorization header or cookie. Returns the payload
 * if valid, null otherwise. Used by the rate-limiter's skip function to
 * recognize authenticated admin/user roles before authenticateToken runs
 * per-route. Never throws, never rejects — enforcement stays on route-level
 * authenticateToken.
 */
function peekJwt(req) {
  try {
    const authHeader = req.headers.authorization;
    const token = (authHeader && authHeader.startsWith('Bearer '))
      ? authHeader.substring(7)
      : (req.cookies && req.cookies.token);
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

// ============================================================================
// SECURITY: Require critical secrets or generate random per-boot fallbacks
// ============================================================================
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('JWT_SECRET not set — generated random secret (tokens will invalidate on restart)');
}
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('SESSION_SECRET not set — generated random secret');
}

// Import core routes
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const labTemplateRoutes = require('./routes/lab-templates');
const moduleRoutes = require('./routes/modules');
const laneBootstrapRoutes = require('./routes/lane-bootstrap');
const guacSessionRoutes = require('./routes/guac-sessions');
const workstationRoutes = require('./routes/workstations');

// Import loaders
const moduleLoader = require('./module-loader');

// Import middleware
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Build frame-src to allow Guacamole embedding. Same-origin proxy paths
// (e.g. "/guac") are already covered by 'self'. Only add an explicit origin
// when GUAC_PUBLIC_BASE_URL is a full cross-origin URL.
const guacPublicBase = (process.env.GUAC_PUBLIC_BASE_URL || '').trim();
const frameSrcDirective = ["'self'"];
if (guacPublicBase.startsWith('http')) {
  try {
    frameSrcDirective.push(new URL(guacPublicBase).origin);
  } catch {
    // Malformed URL — ignore; 'self' remains
  }
}

// HTTP request logging (before all routes)
const requestLogger = require('./middleware/request-logger');
app.use(requestLogger);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "http://localhost:5678", "ws://localhost:5678"],
      frameSrc: frameSrcDirective,
      upgradeInsecureRequests: null
    }
  },
  crossOriginOpenerPolicy: false
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? process.env.ALLOWED_ORIGINS?.split(',')
    : true,
  credentials: true
}));

// Trust reverse-proxy headers so req.ip reflects the real client, not the
// proxy. Without this, every client shares one rate-limit bucket keyed by
// the proxy's IP. Set TRUST_PROXY=false to disable if app is exposed directly.
if (process.env.TRUST_PROXY !== 'false') {
  app.set('trust proxy', process.env.TRUST_PROXY || 'loopback, linklocal, uniquelocal');
}

// cookieParser runs before the rate limiter so peekJwt can read the token
// cookie. Body parsing is kept below — the limiter doesn't need it.
app.use(cookieParser());

// Rate limiting. Admins are skipped entirely (they're already trusted with
// destructive ops, and per-admin session activity trivially blows through any
// reasonable cap). Authenticated non-admins + unauthenticated traffic share
// the configured cap, keyed by user ID when logged in (so proxy-collapse
// doesn't merge everyone's buckets) and by IP otherwise. Login brute-force
// protection is handled separately by `authLimiter` below, which stays tight.
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 2000,
  message:  { error: 'Too many requests, please try again later.' },
  skip: (req) => peekJwt(req)?.role === 'admin',
  keyGenerator: (req) => {
    const payload = peekJwt(req);
    return payload?.sub ? `user:${payload.sub}` : `ip:${req.ip}`;
  },
  handler: (req, res, next, opts) => {
    const payload = peekJwt(req);
    const who = payload?.sub ? `user:${payload.sub} (${payload.email || 'no-email'})` : `ip:${req.ip}`;
    console.warn(`[RATE LIMIT] ${req.method} ${req.originalUrl} from ${who} — bucket exhausted`);
    res.status(opts.statusCode).json(opts.message);
  }
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, please try again later.' }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many webhook calls.' }
});
app.use('/api/webhook', webhookLimiter);

// ============================================================================
// BODY PARSING & COOKIES
// ============================================================================

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
// cookieParser already applied earlier (before rate limiter)

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.COOKIE_SECURE === 'true',
    httpOnly: true,
    maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// ============================================================================
// STATIC FILES
// ============================================================================

app.use(express.static(path.join(__dirname, '../public')));
app.use('/profiles', express.static(path.join(__dirname, '../profiles')));
// /vuln-assets is gated by short-lived HMAC-signed URLs minted by the orchestrator
// (see src/utils/signed-url.js). Lab VMs carry ?token=…&exp=… on every request.
const { verifySignedUrl } = require('./utils/signed-url');
app.use('/vuln-assets', (req, res, next) => {
  const filename = decodeURIComponent(req.path.replace(/^\/+/, ''));
  if (!filename) return res.status(404).send('Not found');
  const v = verifySignedUrl(filename, req.query.exp, req.query.token);
  if (!v.ok) return res.status(403).send(`Forbidden: ${v.reason}`);
  next();
}, express.static(path.join(__dirname, '../vuln-assets')));

// ============================================================================
// CORE API ROUTES
// ============================================================================

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin', labTemplateRoutes);
app.use('/api/modules', moduleRoutes);
app.use('/api/dashboard', guacSessionRoutes);
app.use('/api/workstations', workstationRoutes);

// Unauthenticated, source-IP-gated. Called by lane gateway LXCs on first boot
// to fetch one-shot bootstrap payload (Tailscale auth key etc). See route
// file for security model.
app.use('/api/lane-bootstrap', laneBootstrapRoutes);

// ============================================================================
// CORE PAGE ROUTES
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/hub', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/hub.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/register.html'));
});

// Placeholder pages for modules without content
const placeholderModules = ['crucible', 'cyberlabs', 'forge', 'university', 'archive', 'wiki', 'library', 'cyberprobe'];
placeholderModules.forEach(mod => {
  app.get(`/${mod}`, (req, res) => {
    res.sendFile(path.join(__dirname, '../public/module-placeholder.html'));
  });
});

const { authenticateToken, requireRole } = require('./middleware/auth');

// Core admin page (role-gated)
app.get('/admin', authenticateToken, requireRole('admin'), (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'));
});

// Debug endpoint (admin-only)
app.get('/api/auth/debug', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  res.json({
    env: { JWT_SECRET: 'Set', CYBERCORE_DB: process.env.CYBERCORE_DB_NAME ? '***' : 'NOT SET' },
    headers: { authorization: req.headers.authorization ? 'Present' : 'Missing' },
    user: { email: req.user.email, role: req.user.role }
  });
});

app.get('/api/auth/test', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Auth working!', user: req.user });
});

// ============================================================================
// STARTUP — Load modules and plugins, then start listening
// ============================================================================

/**
 * Initialize the settings table in clinic_db if it doesn't exist
 */
async function initializeSettingsTable() {
  try {
    const { query } = require('./utils/db');
    
    // Create table if it doesn't exist
    await query(`
      CREATE TABLE IF NOT EXISTS settings (
        key VARCHAR(255) PRIMARY KEY,
        value TEXT,
        description TEXT,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Insert default settings if they don't exist
    await query(`
      INSERT INTO settings (key, value, description) VALUES 
        ('site_name', 'CyberHub', 'The display name of the CyberHub instance')
      ON CONFLICT (key) DO NOTHING
    `);

    console.log('✅ Settings table initialized');
  } catch (err) {
    console.warn('⚠️  Could not initialize settings table:', err.message);
  }
}

async function syncVmTemplateNodes() {
  try {
    const { cybercoreQuery } = require('./utils/cybercore-db');
    const { proxmoxAPI } = require('./utils/proxmox');

    const [catalogResult, resources] = await Promise.all([
      cybercoreQuery(`SELECT id, template_vmid, node FROM cybercore_template_catalog`),
      proxmoxAPI('GET', '/api2/json/cluster/resources')
    ]);

    const vmMap = {};
    for (const r of resources) {
      if (r.type === 'qemu' || r.type === 'lxc') vmMap[Number(r.vmid)] = r.node;
    }

    let updatedCount = 0;
    for (const row of catalogResult.rows) {
      const liveNode = vmMap[Number(row.template_vmid)];
      if (liveNode && liveNode !== row.node) {
        await cybercoreQuery(`UPDATE cybercore_template_catalog SET node = $1 WHERE id = $2`, [liveNode, row.id]);
        console.log(`[TemplateSync] VMID ${row.template_vmid}: ${row.node ?? 'null'} → ${liveNode}`);
        updatedCount++;
      }
    }
    console.log(`✅ VM template node sync complete (${updatedCount} updated, ${catalogResult.rows.length} total)`);
  } catch (err) {
    console.warn('⚠️  VM template node sync failed (non-fatal):', err.message);
  }
}

async function start() {
  try {
    // Load modules first — plugins create their databases (e.g. clinic_db)
    await moduleLoader.loadAll(app);

    // Initialize settings table after plugins have created their databases
    await initializeSettingsTable();

    // Sync template node locations from live Proxmox cluster
    await syncVmTemplateNodes();
  } catch (err) {
    console.error('Module loading error (non-fatal):', err.message);
  }



  // 404 handler (must come after all routes)
  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Global error handler
  app.use(errorHandler);

  app.listen(PORT, () => {
    log.info('CyberHub server started', {
      port:        PORT,
      env:         process.env.NODE_ENV || 'development',
      logLevel:    process.env.LOG_LEVEL || 'info',
      logDir:      process.env.LOG_DIR   || 'logs/',
    });
  });
}

start();

module.exports = app;
