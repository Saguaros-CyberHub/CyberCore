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

// Catch unhandled rejections and uncaught exceptions so the process doesn't
// silently crash. In Node 18+ an unhandled rejection exits with code 1 if
// no listener is registered — this surfaces the cause before exit.
process.on('unhandledRejection', (reason, promise) => {
  log.error('Unhandled promise rejection', { reason: reason?.stack || reason, promise: String(promise) });
});
process.on('uncaughtException', (err) => {
  log.error('Uncaught exception — process will exit', err);
  process.exit(1);
});
// ──────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
// connect-redis v9 exports RedisStore as a named export; the v7 default export
// is gone, and reading `.default` would silently yield undefined.
const { RedisStore } = require('connect-redis');
const redisClient = require('./utils/redis');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
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
const flagRoutes = require('./routes/flags');
const chatStatusRoutes = require('./routes/chat-status');
const ticketRoutes = require('./routes/tickets');

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
      // https: rather than a host allowlist. The site logo and favicon are
      // admin-set URLs that can point anywhere, so a fixed list would silently
      // block every branding change with nothing but a console violation to
      // show for it -- which is exactly how the Logo URL field came to look
      // like it did nothing. Images are passive content; the only exposure is
      // that the chosen host sees viewers' IPs. Drop the file in public/img
      // and use a relative path if you want branding to stay 'self'-only.
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'"],
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
// High-frequency, low-cost read endpoints that a single active user hits many
// times per session — the per-page auth-status check and short-interval status
// polls. Counting these toward the abuse bucket is what let normal users trip
// the limiter within minutes of logging in, so they're skipped here. Login
// brute-force protection stays enforced separately by `authLimiter`.
const RATE_LIMIT_SKIP_PATHS = [
  '/api/auth/me',
];
const RATE_LIMIT_SKIP_PATTERNS = [
  /\/status$/,   // e.g. workstation/lab status polls: /api/.../:id/status
];
// Never key a bucket on a raw IPv6 address. A single client is typically handed
// a whole IPv6 prefix, so one attacker could mint an unlimited number of
// distinct buckets and walk straight past the login cap. ipKeyGenerator
// collapses IPv6 to its subnet and passes IPv4 through untouched.
function ipKey(req) {
  return req.ip ? ipKeyGenerator(req.ip) : 'unknown';
}

function isHighFrequencyRead(req) {
  if (req.method !== 'GET') return false;
  const path = req.originalUrl.split('?')[0];
  return RATE_LIMIT_SKIP_PATHS.includes(path)
    || RATE_LIMIT_SKIP_PATTERNS.some((re) => re.test(path));
}

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 5000,
  message:  { error: 'Too many requests, please try again later.' },
  // A stage token carries the account's real role but represents a sign-in that
  // is only half finished, so it must not buy the admin exemption — otherwise
  // knowing an admin's password (without their second factor) is enough to
  // shed rate limiting. Bucketing by its `sub` below is still correct; that
  // identifies the account rather than granting it anything.
  skip: (req) => {
    const payload = peekJwt(req);
    return (!payload?.stage && payload?.role === 'admin') || isHighFrequencyRead(req);
  },
  keyGenerator: (req) => {
    const payload = peekJwt(req);
    return payload?.sub ? `user:${payload.sub}` : `ip:${ipKey(req)}`;
  },
  handler: (req, res, next, opts) => {
    const payload = peekJwt(req);
    const who = payload?.sub ? `user:${payload.sub} (${payload.email || 'no-email'})` : `ip:${req.ip}`;
    console.warn(`[RATE LIMIT] ${req.method} ${req.originalUrl} from ${who} — bucket exhausted`);
    res.status(opts.statusCode).json(opts.message);
  }
});
app.use('/api/', limiter);

// Parse body early for auth routes so the key generator can read the email.
// Without this, all users on a shared NAT IP (e.g. a university network)
// share one bucket and one person's failed attempts locks everyone out.
const authBodyParser = express.json({ limit: '10kb' });

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => {
    const email = (req.body?.email || '').toLowerCase().trim();
    return email ? `login:email:${email}` : `login:ip:${ipKey(req)}`;
  },
  message: { error: 'Too many login attempts, please try again later.' }
});
app.use('/api/auth/login', authBodyParser, authLimiter);
app.use('/api/auth/register', authBodyParser, authLimiter);

// Setting a first password gets its own buckets. Both endpoints write a
// password, so without a limit either one is an unthrottled oracle for anyone
// holding a stage token or guessing at activation links.
//
// Keyed on the token subject rather than the IP: a whole class arriving from
// one campus NAT address would otherwise share a bucket, and one student
// fumbling their new password would lock out everyone else.
const initialPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => {
    const payload = peekJwt(req);
    return payload?.sub ? `pwinit:user:${payload.sub}` : `pwinit:ip:${ipKey(req)}`;
  },
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' }
});
app.use('/api/auth/password/initial', initialPasswordLimiter);

// Asking for a link is unauthenticated and sends mail, which makes it the one
// endpoint an outsider can aim at a stranger's inbox. Keyed on the email first,
// exactly like authLimiter above and for the same reason — a whole class behind
// one campus NAT address must not share a bucket — with the IP as the fallback
// when no address was supplied.
//
// Tighter than login's five: a person needing a link clicks once, maybe twice.
// The endpoint answers identically whether or not the account exists, so the
// limit is about not being usable as a mailer, not about guessing.
const passwordRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => {
    const email = (req.body?.email || '').toLowerCase().trim();
    return email ? `pwreq:email:${email}` : `pwreq:ip:${ipKey(req)}`;
  },
  message: { error: 'Too many requests. Please wait a few minutes and try again.' }
});
app.use('/api/auth/password/request', authBodyParser, passwordRequestLimiter);

// Activation carries no identity until the token is redeemed, so this one can
// only be keyed on the client. It is the brute-force surface for a 32-byte
// random token — practically unguessable, but an open write endpoint should
// never be unbounded.
const activationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => `activate:ip:${ipKey(req)}`,
  message: { error: 'Too many activation attempts. Please wait a few minutes and try again.' }
});
app.use('/api/auth/activate', activationLimiter);

// Roster imports create accounts and send mail on an instructor's behalf, which
// makes them the one instructor-facing surface that can be turned outward. The
// cap is generous for real teaching (a class is one or two runs) and tight
// enough that the platform cannot be driven as a bulk sender. Preview and
// confirm share the bucket deliberately — preview is an account-existence
// oracle, so it should not be cheaper than the thing it previews.
const rosterImportLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => {
    const payload = peekJwt(req);
    return payload?.sub ? `roster:user:${payload.sub}` : `roster:ip:${ipKey(req)}`;
  },
  message: { error: 'Too many roster operations. Please wait a few minutes and try again.' }
});
// Mounted BEFORE the general roster bucket so the tighter cap cannot be bypassed
// by ordering. Both apply, which is intended: that one bounds CALLS, this one
// bounds RUNS. One call here can queue a whole section's invitations, so twenty
// of them inside the shared bucket would be thousands of messages from a single
// instructor — precisely the "driven as a bulk sender" outcome that bucket exists
// to prevent. Three runs an hour clears any real class and nothing more.
const bulkResendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  keyGenerator: (req) => {
    const payload = peekJwt(req);
    return payload?.sub ? `bulkinvite:user:${payload.sub}` : `bulkinvite:ip:${ipKey(req)}`;
  },
  message: {
    error: 'Too many bulk invitations. Please wait an hour, or resend to individual students.'
  }
});
app.use(/^\/api\/cle\/courses\/[^/]+\/roster\/students\/activation\//, bulkResendLimiter);

app.use(/^\/api\/cle\/courses\/[^/]+\/roster\//, rosterImportLimiter);

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many webhook calls.' }
});
app.use('/api/webhook', webhookLimiter);

// Flag submission is the one endpoint where brute force is the actual threat
// model, so it gets its own bucket. Deliberately NOT the global `limiter`:
// that one skips admins entirely and allows 5000/15min. Keyed on the JWT
// subject so one student cannot exhaust another's budget.
const flagSubmitLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => {
    const payload = peekJwt(req);
    return payload?.sub ? `flag:user:${payload.sub}` : `flag:ip:${ipKey(req)}`;
  },
  message: { error: 'Too many flag submissions, slow down.' }
});
app.use('/api/flags/submit', flagSubmitLimiter);

// ============================================================================
// BODY PARSING & COOKIES
// ============================================================================

// 10mb is needed by API routes that carry generated profiles and asset
// payloads, but it was previously applied to EVERY path — including
// unauthenticated non-/api routes, which no rate limiter covers (the
// limiter is mounted on '/api/' below). A large body on those paths is a
// free multi-megabyte synchronous JSON.parse on the only event loop.
// /api/ keeps the original 10mb limit, so no existing route changes.
const _jsonApi   = express.json({ limit: '10mb' });
const _jsonOther = express.json({ limit: '256kb' });
app.use((req, res, next) => (
  req.path.startsWith('/api/') ? _jsonApi : _jsonOther
)(req, res, next));
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

// The admin console is unbundled, unversioned JS loaded by plain <script src>,
// so a deploy only reaches a browser that re-fetches the file. Nothing forced
// that: express.static's default is an ETag with no Cache-Control, which lets a
// browser — and Cloudflare, which caches .js by default — serve the previous
// copy for as long as it likes.
//
// That produced a genuinely confusing failure once: a stale admin-lanes.js
// talking to an already-updated /api/admin/reconcile, reporting a TypeError
// from a response shape it predated. The server was fine, the page was months
// old, and nothing on screen said so.
//
// no-cache does NOT mean "do not store" — it means "revalidate before use". The
// ETag still answers 304 on the overwhelmingly common unchanged case, so this
// costs a conditional request per asset, not a re-download.
//
// Only markup and code are pinned this way. Images and fonts are content-
// addressed by their own filenames and keep the default.
const REVALIDATE_EXT = /\.(html|js|css)$/i;
app.use(express.static(path.join(__dirname, '../public'), {
  setHeaders(res, filePath) {
    if (REVALIDATE_EXT.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
  }
}));
// Profile HTML files are pre-generated with CSS baked in. This middleware
// intercepts HTML requests and injects an updated print stylesheet so print
// fixes apply to existing profiles without regenerating them.
const PROFILES_DIR = path.join(__dirname, '../profiles');
const PRINT_CSS_INJECTION = `
<style id="print-override">
@media print {
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { background: white; margin: 0; }
  .nav-wrapper, select, input { display: none !important; }
  .print-btn { display: none !important; }
  .confidential-banner { position: static; }
  .cover-page { min-height: auto; height: auto; page-break-after: always; padding: 40px; }
  .tab-panel {
    display: block !important;
    height: auto !important;
    min-height: 0 !important;
    overflow: visible !important;
    animation: none !important;
    opacity: 1 !important;
    visibility: visible !important;
  }
  .card, .section, .stakeholder-card { page-break-inside: avoid; }
  svg { max-width: 100% !important; height: auto !important; }
  .ws-row.hidden { display: none !important; }
  .footer { page-break-inside: avoid; }
}
</style>`;

app.use('/profiles', (req, res, next) => {
  if (!req.path.endsWith('.html')) return next();
  const filePath = path.join(PROFILES_DIR, req.path);
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return next();
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html.replace('</head>', PRINT_CSS_INJECTION + '\n</head>'));
  });
});
// Profile JSON holds the full simulated-company data set and must never be
// fetchable directly by URL. Every legitimate reader (scan-doc/policy/
// interview/deploy generation) already reads it server-side off disk, not
// over HTTP — nothing legitimate depends on this path being open.
app.use('/profiles', (req, res, next) => {
  if (req.path.endsWith('.json')) return res.status(404).send('Not found');
  next();
});
app.use('/profiles', express.static(PROFILES_DIR));
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
app.use('/api/flags', flagRoutes);
// Support tickets. MUST be registered here, in the core block, and not later:
// the CIAB plugin mounts at '/' with an /api catch-all that matches every
// /api/* request in the application (ciab/routes/api.js, test/ciab-gate-scope.test.js),
// and core routes survive only by being registered before moduleLoader.loadAll().
app.use('/api/tickets', ticketRoutes);

// Reports whether an LLM is configured, so the global chat widget can hide its
// launcher instead of offering a button that always fails. Must stay in core:
// POST /api/chat itself is implemented by the CIAB plugin, which mounts later.
app.use('/api/chat', chatStatusRoutes);

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

// Landing page for the activation links the CLE roster import emails. The token
// stays in the query string and is only ever POSTed to /api/auth/activate — the
// page itself is static and unauthenticated, because its recipient has no
// account credential yet by definition.
app.get('/activate', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/activate.html'));
});

// Placeholder pages for modules without content
const placeholderModules = ['crucible', 'cyberlabs', 'forge', 'university', 'archive', 'cyberwiki', 'wiki', 'library', 'cyberprobe'];
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

/**
 * Ensure the MFA columns exist on cybercore_user. The config/postgres init
 * scripts only run on a fresh database, so existing deployments need these
 * added idempotently at startup (mirrors the lazy table-init pattern above).
 */
async function ensureMfaColumns() {
  try {
    const { cybercoreQuery } = require('./utils/cybercore-db');
    await cybercoreQuery(`
      ALTER TABLE cybercore_user
        ADD COLUMN IF NOT EXISTS mfa_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS mfa_secret         BYTEA,
        ADD COLUMN IF NOT EXISTS mfa_recovery_codes JSONB,
        ADD COLUMN IF NOT EXISTS mfa_enrolled_at    TIMESTAMPTZ
    `);
    console.log('✅ MFA columns ensured on cybercore_user');
  } catch (err) {
    console.warn('⚠️  Could not ensure MFA columns:', err.message);
  }
}

/**
 * Ensure the lane WAN address columns exist.
 *
 * Belt and braces for migrations/033_lane_wan_ip.sql, which is a HAND-RUN psql
 * file (front-end/migrations/ has no runner — module-loader only walks
 * manifest.database.migrations inside modules and plugins). Without the columns
 * every insertLane fails, so the column must never be able to lag the code.
 *
 * Deliberately ONLY the two ADD COLUMNs. The backfill, the partial unique index
 * and the lease-table seed stay in 033: they are one-time, they need operator
 * eyes on the collision WARNINGs, and quietly creating a uniqueness constraint
 * at boot on a table that currently violates it is not something a startup hook
 * should be doing.
 */
async function ensureLaneWanColumns() {
  try {
    const { cybercoreQuery } = require('./utils/cybercore-db');
    await cybercoreQuery(`
      ALTER TABLE cybercore_lane
        ADD COLUMN IF NOT EXISTS gateway_wan_ip       INET,
        ADD COLUMN IF NOT EXISTS wan_ip_grandfathered BOOLEAN NOT NULL DEFAULT FALSE
    `);
    await cybercoreQuery(`
      CREATE TABLE IF NOT EXISTS cybercore_lane_wan_lease (
        lease_id     BIGSERIAL PRIMARY KEY,
        wan_ip       INET NOT NULL,
        lane_id      UUID,
        vxlan_id     INTEGER,
        allocated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_lane_wan_lease_ip
        ON cybercore_lane_wan_lease(wan_ip, allocated_at DESC)
    `);
    console.log('✅ Lane WAN address columns ensured on cybercore_lane');
  } catch (err) {
    console.warn('⚠️  Could not ensure lane WAN columns:', err.message);
  }
}

/**
 * Report — never repair — live lanes sharing a gateway WAN transit address.
 *
 * Both lanes in a colliding pair have running VMs and a student attached to
 * each, so which one moves is an operator decision, not a boot-time one. The
 * address is also the Guacamole console host, so a collision means two students'
 * consoles resolve to the same host:port and whichever gateway answers ARP first
 * wins.
 *
 * Expected to print something the first time it runs on an existing cluster:
 * the pre-allocator derivation (base + 10 + vxlan % 240) had 240 buckets against
 * VXLAN ids that only ever climb.
 */
async function warnWanIpConflicts() {
  try {
    const { findWanIpConflicts } = require('./utils/lane-wan-allocator');
    const conflicts = await findWanIpConflicts();
    if (conflicts.length === 0) return;

    const lanes = conflicts.reduce((n, c) => n + c.lane_count, 0);
    console.warn(
      `⚠️  ${conflicts.length} lane WAN transit address(es) are shared by more than one live lane ` +
      `(${lanes} lanes affected):`
    );
    for (const c of conflicts) {
      console.warn(`    ${c.wan_ip}  ×${c.lane_count}`);
      for (const l of (c.lanes || [])) {
        console.warn(`        vxlan ${l.vxlan_id}  ${l.owner || '(no owner)'}  ${l.node || '(no node)'}  ${l.name || ''}`);
      }
    }
    console.warn(
      '    Both owners\' Guacamole consoles resolve to the same host:port, and both gateways\n' +
      '    answer ARP for the same address on the lab VLAN.\n' +
      '    GET /api/admin/wan-conflicts for detail. Redeploy or tear down the newer lane of\n' +
      '    each pair; nothing is repaired automatically.'
    );
  } catch (err) {
    console.warn('⚠️  Could not audit lane WAN addresses:', err.message);
  }
}

/**
 * Release lanes left stranded in 'deploying' by a previous process.
 *
 * Deploys are fire-and-forget async work inside THIS process, with their
 * progress held in an in-memory global — a restart kills them mid-clone and
 * there is no resume. So any lane still marked 'deploying' when the server boots
 * is, by definition, abandoned: nothing is working on it and nothing ever will.
 *
 * Left alone it holds its VXLAN out of the pool forever, because allocateVxlanIds
 * skips only 'error' and 'deleted'. Marking it 'error' releases the id and makes
 * the row visible to teardown, so the operator can clean up whatever was built.
 *
 * "Not running at startup" is the whole test, and it is exact — which is why
 * this lives here rather than in the deploy path. The failure handler in
 * challenge-lane-deployer.js used to approximate it with "same challenge_key,
 * created in the last hour", which was both too wide (it condemned other
 * courses' in-flight lanes) and too narrow (a GOAD bake runs ~90 minutes, so a
 * perfectly healthy lane could outlive the window and be marked 'error' while
 * still building).
 */
async function recoverStrandedLanes() {
  try {
    const { cybercoreQuery } = require('./utils/cybercore-db');

    // An IN-PLACE lane rebuild also parks the row at 'deploying', but its
    // gateway, VXLAN and WAN address are all still legitimately held — the
    // gateway LXC is running, answering ARP, with untouched student machines
    // live behind it. Sweeping those to 'error' like an interrupted deploy
    // would drop them out of ux_cybercore_lane_vxlan_active and
    // allocateVxlanIds, and the next deployLanes could clone a gateway on top
    // of the running one. So they go back to 'active' with an explanation,
    // and this MUST run before the blanket sweep below.
    const rebuilt = await cybercoreQuery(`
      UPDATE cybercore_lane
         SET status = 'active',
             config = (config - 'rebuild') || jsonb_build_object(
                        'error',
                        'An in-place rebuild was interrupted by a server restart \u2014 some '
                     || 'machines may be missing. Rebuild them from the VM Management tab.',
                        'rebuild_interrupted_at', to_jsonb(NOW())),
             updated_at = NOW()
       WHERE status = 'deploying'
         AND config->'rebuild' IS NOT NULL
       RETURNING lane_id, vxlan_id
    `);
    if (rebuilt.rowCount > 0) {
      console.warn(
        `\u26a0\ufe0f  ${rebuilt.rowCount} lane(s) were mid-rebuild when the previous run stopped (vxlan ${rebuilt.rows.map(r => r.vxlan_id).join(', ')}). Their gateways are intact, so they are back to 'active' — re-run the rebuild to replace whatever is missing.`);
    }

    const result = await cybercoreQuery(`
      UPDATE cybercore_lane
         SET status = 'error',
             config = config || '{"error":"Deployment was interrupted by a server restart"}'::jsonb,
             updated_at = NOW()
       WHERE status = 'deploying'
       RETURNING lane_id, vxlan_id
    `);
    if (result.rowCount > 0) {
      console.warn(
        `⚠️  Released ${result.rowCount} lane(s) stranded mid-deploy by a previous run ` +
        `(vxlan ${result.rows.map(r => r.vxlan_id).join(', ')}). They are marked 'error' — ` +
        `tear them down to remove whatever was already built.`
      );
    }
  } catch (err) {
    console.warn('⚠️  Could not recover stranded lanes:', err.message);
  }
}

/**
 * Power back on any machine a resize took down and never got to restart.
 *
 * A resize is stop -> reconfigure -> start, and the start lives in this
 * process. A restart in the middle leaves a student's machine powered off with
 * nothing anywhere that knows to turn it back on — the single worst outcome
 * this feature can produce, and the reason vm-resize.js writes its intent to
 * the lane row BEFORE it stops anything.
 *
 * KEYED ON config, NOT ON STATUS, and that is deliberate. A resize must never
 * park the lane at 'deploying': the lane genuinely is active (its gateway is
 * up, its other machines untouched), and recoverStrandedLanes above sweeps
 * every 'deploying' row without a config.rebuild key straight to 'error' —
 * so borrowing that marker would condemn a perfectly healthy lane on every
 * restart. In-flight state is held by the progress-registry mutex instead.
 *
 * Only machines whose marker says was_running are started. One that was already
 * stopped when the resize began stays stopped, exactly as it would have.
 */
async function recoverInterruptedResizes() {
  try {
    const { cybercoreQuery } = require('./utils/cybercore-db');
    const { proxmoxAPI, getPowerState } = require('./utils/proxmox');
    const { vmApiBase } = require('./utils/vm-paths');

    const stranded = await cybercoreQuery(`
      SELECT lane_id, name, config->'resize'->'in_flight' AS marker
        FROM cybercore_lane
       WHERE config->'resize'->'in_flight' IS NOT NULL
         AND status <> 'deleted'
    `);
    if (stranded.rowCount === 0) return;

    // Two ways a marker survives: the process died mid-resize, or the resize
    // finished but could not switch the machine back on. Both want the same
    // remedy, so neither is singled out in the message.
    console.warn(`⚠️  ${stranded.rowCount} lane(s) have a machine left down by a resize — restoring power.`);

    for (const row of stranded.rows) {
      const m = row.marker || {};
      const started = [];
      try {
        if (m.was_running && m.node && m.vmid) {
          const state = await getPowerState(m.node, m.vmid, m.provider_type).catch(() => 'unknown');
          if (state !== 'running') {
            await proxmoxAPI('POST', `${vmApiBase(m.node, m.vmid, m.provider_type)}/status/start`);
            started.push(m.vmid);
          }
        }
        // The marker is cleared either way. Leaving it would make every
        // subsequent boot retry a start that already happened.
        await cybercoreQuery(`
          UPDATE cybercore_lane
             SET config = jsonb_set(
                            config,
                            '{resize}',
                            (COALESCE(config->'resize', '{}'::jsonb) - 'in_flight')
                              || jsonb_build_object(
                                   'status', 'interrupted',
                                   'error', 'A resize did not finish cleanly and the machine was left '
                                         || 'switched off. It has been powered back on; its size may '
                                         || 'not have changed.',
                                   'at', to_jsonb(NOW()))),
                 updated_at = NOW()
           WHERE lane_id = $1
        `, [row.lane_id]);
        if (started.length) {
          console.warn(`    ${row.name || row.lane_id}: started vmid ${started.join(', ')}`);
        }
      } catch (e) {
        console.warn(`    ${row.name || row.lane_id}: could not restore power — ${e.message}`);
      }
    }
  } catch (err) {
    console.warn('⚠️  Could not recover interrupted resizes:', err.message);
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

    // Ensure MFA columns exist on cybercore_user (idempotent)
    await ensureMfaColumns();

    // Lane WAN address columns. Must be before anything can deploy a lane, and
    // idempotent, because migrations/033 is hand-run and could lag the code.
    await ensureLaneWanColumns();

    // Same story as the MFA columns: the config/postgres scripts only run on a
    // fresh volume, so the password-policy and provenance columns — and the
    // activation-token table the roster import issues invitations from — have
    // to be added idempotently here for existing deployments.
    await require('./utils/account-provisioning').ensureProvisioningColumns();
    await require('./utils/activation').ensureActivationTokens();
    await require('./utils/mailer').ensureEmailOutbox();

    // The unified audit trail (migrations/032_audit_log.sql). Non-fatal: a DDL
    // permission problem must degrade to "no audit log", not "no server".
    await require('./utils/audit').ensureAuditLog();

    // Support tickets (migrations/034_support_tickets.sql). AFTER the mailer,
    // because ensureEmailOutbox() adds the cc_address/reply_to columns a ticket
    // notification needs to copy the course instructor. Non-fatal on the same
    // terms as the audit log: no ticket system beats no server.
    await require('./utils/tickets').ensureTicketTables();

    // Drains queued mail in the background. No-ops when mail isn't configured,
    // so an offline deployment doesn't spin a pointless timer.
    require('./utils/email-worker').startEmailWorker();

    // Nothing can be deploying yet — anything that says it is was abandoned by
    // a previous process and is holding a VXLAN it will never use.
    await recoverStrandedLanes();
    // After the lane sweep: that one decides lane STATUS, this one only
    // restores VM POWER, and a lane it just marked 'error' can still be
    // holding a machine this needs to switch back on.
    await recoverInterruptedResizes();

    // Shared lab-network readiness, in cybercore_db because it is a fact about
    // the RESERVATION (a crucible_challenge row) rather than about either
    // plugin. One writer — reserveLabNetwork — and two readers, CIAB and CLE.
    // A boot hook rather than a migration, because plugin migrations only run
    // against that plugin's own database (same reason ensureLaneWanColumns and
    // ensureAuditLog live here).
    try {
      await require('./utils/lab-network-provision').ensureLabReadinessTable();
      console.log('✅ Lab network readiness table ensured');
    } catch (e) {
      console.warn(`⚠️  Could not ensure lab readiness table: ${e.message}`);
    }

    // Read-only: says which lanes are double-booked on one gateway address.
    // Runs after recoverStrandedLanes so lanes it just released to 'error' are
    // already excluded rather than reported as conflicts.
    await warnWanIpConflicts();

    // Same doctrine as recoverStrandedLanes, applied to CIAB's VXLAN
    // reservations: carving a block is fire-and-forget async work inside THIS
    // process with no resume, so any engagement still 'provisioning' at boot was
    // abandoned by a previous one. Without this it spins "Initializing" forever
    // and blocks every deploy for that client — which is exactly the state CLE
    // courses can still get stuck in, because CLE never added this sweep.
    //
    // Lazy require: the CIAB plugin owns its own pool, and requiring it at module
    // scope would pull clinic_db into the boot path of a deployment that has the
    // plugin disabled.
    try {
      await require('../modules/crucible/plugins/ciab/utils/engagement-provision')
        .recoverStrandedEngagements();
    } catch (e) {
      console.warn(`[Boot] CIAB engagement sweep skipped: ${e.message}`);
    }

    // The same doctrine for CLE course labs, which reserve through the same
    // shared provisioner and had no sweep at all — a restart mid-provision left
    // a course spinning "Initializing" forever with deletion as the only exit.
    try {
      await require('../modules/crucible/plugins/cle/routes/courses')
        .recoverStrandedCourseLabs();
    } catch (e) {
      console.warn(`[Boot] CLE course-lab sweep skipped: ${e.message}`);
    }

    // CYBR 400 attack console. The INVERSE of recoverStrandedLanes above: an
    // attack runs detached on the guest, so a restart here is invisible to it
    // and 'running' targets must be left alone. Only lanes caught mid-dispatch
    // are ambiguous. See the header of cle/utils/attack-worker.js.
    //
    // Required from src/ because the plugin owns cle_db and its pool is only
    // injected during moduleLoader.loadAll() above — so this must stay after
    // it. Precedent for reaching into a plugin from src/: admin/lab-networks.js.
    const attackWorker = require('../modules/crucible/plugins/cle/utils/attack-worker');
    await attackWorker.recoverAttackRuns();
    attackWorker.startAttackWorker();

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
