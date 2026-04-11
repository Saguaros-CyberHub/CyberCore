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
const path = require('path');

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

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: { error: 'Too many requests, please try again later.' }
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
app.use(cookieParser());

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
app.use('/vuln-assets', express.static(path.join(__dirname, '../vuln-assets')));

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

const { authenticateToken } = require('./middleware/auth');

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
