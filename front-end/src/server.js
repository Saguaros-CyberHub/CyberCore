/**
 * ============================================================================
 * CLINIC-IN-A-BOX - MAIN SERVER
 * ============================================================================
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Import routes
const authRoutes = require('./routes/auth');
const profileRoutes = require('./routes/profiles');
const apiRoutes = require('./routes/api');
const progressRoutes = require('./routes/progress');
const interviewRoutes = require('./routes/interview');
const instructorRoutes = require('./routes/instructor');
const intakeFormRoutes = require('./routes/intake-form');
const adminRoutes = require('./routes/admin');
const challengeTemplateRoutes = require('./routes/challenge-templates');


// Import middleware
const { errorHandler } = require('./middleware/errorHandler');
const { checkSchedule } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;



// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Helmet for security headers
// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "http://localhost:5678", "ws://localhost:5678"]
    }
  }
}));

// CORS configuration
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

// Stricter rate limit for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: { error: 'Too many login attempts, please try again later.' }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ============================================================================
// BODY PARSING & COOKIES
// ============================================================================

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
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

//app.use('/profiles', express.static('F:/Projects/mounts/ftp'));

// ============================================================================
// API ROUTES
// ============================================================================

app.use('/api/auth', authRoutes);
// Student-facing routes get schedule check (blocks outside class hours)
app.use('/api/profiles', checkSchedule, profileRoutes);
app.use('/api', checkSchedule, apiRoutes);
app.use('/api/progress', checkSchedule, progressRoutes);
app.use('/api/interview', checkSchedule, interviewRoutes);
app.use('/api/instructor', instructorRoutes);
app.use('/api/intake-form', checkSchedule, intakeFormRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin', challengeTemplateRoutes);

// ============================================================================
// PAGE ROUTES
// ============================================================================

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/workspace', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/workspace.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/register.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

app.get('/generator', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/generator.html'));
});

app.get('/my-profiles', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/profiles.html'));
});

app.get('/interview', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/interview.html'));
});

app.get('/progress', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/progress.html'));
});

app.get('/instructor', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/instructor.html'));
});

app.get('/intake-form', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/intake-form.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'));
});

app.get('/guide', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/guide.html'));
});

const { authenticateToken } = require('./middleware/auth');

// Debug endpoint
app.get('/api/auth/debug', (req, res) => {
  res.json({
    env: {
      JWT_SECRET: !!process.env.JWT_SECRET ? 'Set ✅' : 'NOT SET ❌',
      DB_NAME: process.env.DB_NAME
    },
    headers: {
      authorization: req.headers.authorization ? 'Present ✅' : 'Missing ❌'
    },
    cookies: {
      token: req.cookies?.token ? 'Present ✅' : 'Missing ❌'
    }
  });
});

// Test protected route
app.get('/api/auth/test', authenticateToken, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Auth working!', 
    user: req.user 
  });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use(errorHandler);

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║           CLINIC-IN-A-BOX SERVER STARTED                      ║
╠═══════════════════════════════════════════════════════════════╣
║  🌐 Server:     http://localhost:${PORT}                         ║
║  📊 Dashboard:  http://localhost:${PORT}/dashboard               ║
║  🔐 Login:      http://localhost:${PORT}/login                   ║
║  📝 Register:   http://localhost:${PORT}/register                ║
╠═══════════════════════════════════════════════════════════════╣
║  Environment:   ${process.env.NODE_ENV || 'development'}                              ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
