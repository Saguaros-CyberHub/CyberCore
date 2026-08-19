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

    // Drains queued mail in the background. No-ops when mail isn't configured,
    // so an offline deployment doesn't spin a pointless timer.
    require('./utils/email-worker').startEmailWorker();

    // Nothing can be deploying yet — anything that says it is was abandoned by
    // a previous process and is holding a VXLAN it will never use.
    await recoverStrandedLanes();

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
