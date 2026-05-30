/**
 * vuln-app-base-css.js — Professional base stylesheet auto-injected into
 * every LLM-generated vuln-app, themed from the concept's color_palette.
 * ============================================================================
 * Why:
 *   Stage 2 generates each file independently — server.js, routes/auth.js,
 *   views/login.ejs, public/styles.css all written in parallel by separate
 *   LLM calls. Nothing enforces that the HTML's classes match what the CSS
 *   defines. Result: weird narrow sidebars, broken grids, wrong backgrounds.
 *
 *   By baking a known-good base into every app — with theming via CSS custom
 *   properties — we GUARANTEE consistent visual quality regardless of what
 *   the LLM produces. The LLM's own CSS still loads AFTER this one, so it
 *   can layer custom touches (logos, badges, custom hover states) on top
 *   without breaking the underlying layout.
 *
 *   This is a college course — the bar is "looks like a real internal tool",
 *   not "wins a design award". Consistency matters more than uniqueness.
 *
 * Theming model:
 *   The LLM produces concept.color_palette = { primary, accent, bg }. We
 *   substitute these into CSS custom properties at injection time, so each
 *   lab still feels like its own company.
 */

function buildBaseCss({ primary, accent, bg } = {}) {
  // Sane defaults if the LLM omitted any color (concept.color_palette is
  // free-form and sometimes incomplete).
  const PRIMARY = primary || '#2c5f2d';
  const ACCENT = accent || '#d4a574';
  const BG = bg || '#f4f1ea';

  return `/* === CIAB BASE STYLES (auto-injected by orchestrator) ===
 * Layout + components for a professional internal-tool look. Themed via the
 * concept's color_palette. The LLM's app-specific CSS loads AFTER this file,
 * so it can override anything that's not marked !important.
 * The !important rules below guard against the common LLM mistakes:
 *   - narrow vertical sidebars on login pages
 *   - inline grid templates that collapse columns
 *   - body backgrounds that don't fill the viewport
 */

:root {
  --ciab-primary: ${PRIMARY};
  --ciab-primary-dark: color-mix(in srgb, ${PRIMARY} 80%, black);
  --ciab-accent: ${ACCENT};
  --ciab-bg: ${BG};
  --ciab-card-bg: #ffffff;
  --ciab-text: #1a1a1a;
  --ciab-text-muted: #666666;
  --ciab-border: #d0c9b8;
  --ciab-success: #4a7c4e;
  --ciab-warning: #c87137;
  --ciab-error: #a83232;
  --ciab-shadow: 0 2px 12px rgba(0,0,0,0.08);
  --ciab-radius: 6px;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 16px;
  line-height: 1.5;
  color: var(--ciab-text);
  background: var(--ciab-bg);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

a { color: var(--ciab-primary); text-decoration: none; }
a:hover { text-decoration: underline; }

h1, h2, h3, h4 { color: var(--ciab-primary); margin: 0 0 0.5rem 0; }
h1 { font-size: 1.875rem; }
h2 { font-size: 1.5rem; }
h3 { font-size: 1.25rem; }
p { margin: 0 0 1rem 0; }

/* === Header (top brand bar) =============================================== */
header, .header, .site-header, .navbar {
  background: var(--ciab-primary);
  color: #fff;
  padding: 1rem 2rem;
  box-shadow: var(--ciab-shadow);
}
header a, .header a, .site-header a, .navbar a { color: #fff; }
header .logo, .header .logo {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 600;
  font-size: 1.25rem;
}
header nav ul, .navbar ul {
  list-style: none;
  display: flex;
  gap: 1.5rem;
  margin: 0;
  padding: 0;
}

/* === Main content ========================================================= */
main, .main, .content, .page-content {
  flex: 1;
  width: 100%;
  max-width: 1200px;
  margin: 2rem auto;
  padding: 0 2rem;
}

/* === Cards ================================================================ */
.card, .panel, .box {
  background: var(--ciab-card-bg);
  border-radius: var(--ciab-radius);
  padding: 2rem;
  box-shadow: var(--ciab-shadow);
  margin-bottom: 1.5rem;
}

/* === Forms ================================================================ */
form { display: block; }
label { display: block; font-weight: 500; margin-bottom: 0.375rem; }
input[type="text"], input[type="email"], input[type="password"],
input[type="number"], input[type="search"], input[type="url"],
input[type="tel"], input[type="date"], select, textarea {
  width: 100%;
  padding: 0.625rem 0.75rem;
  font-size: 1rem;
  font-family: inherit;
  border: 1px solid var(--ciab-border);
  border-radius: var(--ciab-radius);
  background: #fff;
  margin-bottom: 1rem;
}
input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: var(--ciab-primary);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--ciab-primary) 20%, transparent);
}
textarea { resize: vertical; min-height: 100px; }

/* === Buttons ============================================================== */
button, .btn, input[type="submit"], input[type="button"] {
  display: inline-block;
  padding: 0.625rem 1.25rem;
  font-size: 1rem;
  font-weight: 500;
  font-family: inherit;
  background: var(--ciab-primary);
  color: #fff;
  border: none;
  border-radius: var(--ciab-radius);
  cursor: pointer;
  text-decoration: none;
  transition: background 0.15s;
}
button:hover, .btn:hover, input[type="submit"]:hover { background: var(--ciab-primary-dark); }
.btn-secondary { background: var(--ciab-accent); color: #fff; }
.btn-outline { background: transparent; color: var(--ciab-primary); border: 2px solid var(--ciab-primary); }
.btn-outline:hover { background: var(--ciab-primary); color: #fff; }
.btn-danger { background: var(--ciab-error); }

/* === Tables =============================================================== */
table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
thead { background: var(--ciab-primary); color: #fff; }
th { padding: 0.75rem 1rem; text-align: left; font-weight: 600; }
td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--ciab-border); }
tbody tr:hover { background: color-mix(in srgb, var(--ciab-bg) 50%, transparent); }

/* === Alerts =============================================================== */
.alert, .message, .notice, .flash {
  padding: 0.75rem 1rem;
  border-radius: var(--ciab-radius);
  margin-bottom: 1rem;
  border-left: 4px solid var(--ciab-primary);
  background: color-mix(in srgb, var(--ciab-primary) 10%, white);
}
.alert-error, .alert-danger, .error { border-left-color: var(--ciab-error); background: #fdecec; color: #6a1d1d; }
.alert-success, .success { border-left-color: var(--ciab-success); background: #e8f5e9; color: #1d4a20; }
.alert-warning, .warning { border-left-color: var(--ciab-warning); background: #fff4e5; color: #6b3a18; }

/* === Footer =============================================================== */
footer, .footer, .site-footer {
  background: var(--ciab-primary);
  color: #fff;
  padding: 1.5rem 2rem;
  text-align: center;
  font-size: 0.875rem;
  margin-top: auto;
}
footer a, .footer a { color: #fff; opacity: 0.9; }

/* === Login page (this is where most LLM apps fall apart) ================== */
/* Anything that looks like a login wrapper gets centered single-column. The
   !important here is the key guarantee against LLM-generated 3-column or
   sidebar-heavy layouts that broke past deploys. */
.login-container, .login-wrapper, .login-page, .auth-container, .signin-container,
[class*="login-container"], [class*="auth-page"], [id*="login-page"] {
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  flex-direction: column !important;
  min-height: calc(100vh - 100px);
  padding: 2rem 1rem;
}
.login-card, .login-form, .login-box, .auth-card, .signin-card,
[class*="login-card"], [class*="login-form"], [class*="auth-card"] {
  width: 100% !important;
  max-width: 450px !important;
  background: var(--ciab-card-bg) !important;
  padding: 2.5rem !important;
  border-radius: var(--ciab-radius) !important;
  box-shadow: var(--ciab-shadow) !important;
  display: block !important;
  grid-template-columns: none !important;
}
/* Login pages should never have side-by-side sidebars — they look terrible
   in the lab and never have meaningful content to put in them. */
.login-container > aside, .login-container > .sidebar,
[class*="login-side"], [class*="login-info-side"] {
  display: none !important;
}

/* === Dashboard grid ======================================================= */
.dashboard, .dashboard-grid, .stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}
.stat-card, .stat-box, .metric-card {
  background: var(--ciab-card-bg);
  padding: 1.5rem;
  border-radius: var(--ciab-radius);
  border-left: 4px solid var(--ciab-primary);
  box-shadow: var(--ciab-shadow);
}
.stat-value, .metric-value { font-size: 2rem; font-weight: 700; color: var(--ciab-primary); }
.stat-label, .metric-label { color: var(--ciab-text-muted); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; }

/* === Status badges ======================================================== */
.badge, .status, .status-badge {
  display: inline-block;
  padding: 0.25rem 0.625rem;
  border-radius: 999px;
  font-size: 0.8125rem;
  font-weight: 500;
  background: var(--ciab-border);
  color: var(--ciab-text);
}
.badge-pending, .status-pending { background: #fff3cd; color: #856404; }
.badge-approved, .status-approved, .badge-success { background: #d4edda; color: #1d4a20; }
.badge-rejected, .status-rejected, .badge-danger { background: #f8d7da; color: #721c24; }
.badge-active, .status-active { background: #d1ecf1; color: #0c5460; }

/* === Responsive defaults ================================================== */
@media (max-width: 768px) {
  header, .header { padding: 0.75rem 1rem; }
  main, .main { padding: 0 1rem; margin: 1rem auto; }
  .card { padding: 1.25rem; }
  .dashboard, .dashboard-grid { grid-template-columns: 1fr; }
  header nav ul, .navbar ul { gap: 0.75rem; flex-wrap: wrap; }
}

/* === Anti-pattern guards ================================================== */
/* The LLM occasionally inlines style="display:grid;grid-template-columns:30px 1fr 30px"
   on outer wrappers, producing narrow vertical-text columns. Force any inline
   grid on the body or top-level wrappers back to block. */
body[style*="grid"], body > div[style*="grid-template-columns"] {
  display: block !important;
  grid-template-columns: none !important;
}
`;
}

module.exports = { buildBaseCss };
