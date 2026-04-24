/**
 * ============================================================================
 * CYBERHUB - MAIN SERVER
 * ============================================================================
 */

require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
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
const challengeTemplateRoutes = require('./routes/challenge-templates');
const moduleRoutes = require('./routes/modules');

// Import plugin loader
const pluginLoader = require('./plugin-loader');

// Import middleware
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

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
app.use('/api/admin', challengeTemplateRoutes);
app.use('/api/modules', moduleRoutes);

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
// STARTUP — Load plugins, then start listening
// ============================================================================

async function start() {
  try {
    // Load plugins from plugins/ directory
    await pluginLoader.loadAll(app);
  } catch (err) {
    console.error('Plugin loading error (non-fatal):', err.message);
  }

  // 404 handler (must come after plugin routes)
  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Global error handler
  app.use(errorHandler);

  app.listen(PORT, () => {
    console.log(`
+---------------------------------------------------------------+
|               CYBERHUB SERVER STARTED                         |
+---------------------------------------------------------------+
|  Server:     http://localhost:${PORT}                             |
|  Hub:        http://localhost:${PORT}/hub                         |
|  Login:      http://localhost:${PORT}/login                       |
|  Environment: ${process.env.NODE_ENV || 'development'}                                |
+---------------------------------------------------------------+
    `);
  });
}

start();

module.exports = app;
