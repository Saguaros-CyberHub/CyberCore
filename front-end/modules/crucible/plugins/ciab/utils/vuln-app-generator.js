/**
 * vuln-app-generator.js
 * ============================================================================
 * Generate a vulnerable web app per CIAB profile. The generated app deploys
 * onto the profile's web-server asset (or a dedicated VM if none).
 *
 * Two paths:
 *   1. Inline Claude via /src/utils/llm-client (default — N8N path removed).
 *   2. Hardcoded vulnerable-PHP template fallback — used when ANTHROPIC_API_KEY
 *      is missing or the LLM call fails. Lets the deploy path still work end-to-end
 *      without an API key (handy for local dev).
 *
 * Results are persisted to ciab_profile_vuln_apps and reused on subsequent
 * deploys of the same profile.
 */

const { pool, query } = require('./db');
const { isWebServer } = require('./profile-to-spec');
const llm = require('../../../../../src/utils/llm-client');
const { generateVulnApp: generateVulnAppMultistage } = require('../ai/vuln-app');

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Get-or-create the vuln app for a profile. Idempotent — if a row already
 * exists, returns it without regenerating.
 *
 * @param {object} args
 * @param {object} args.profile          profiles row + loaded JSON. profile.assets is the asset array.
 * @param {string} [args.llmModel]       model alias or full ID (resolved by llm-client)
 * @param {'docker'|'apache_vhost'|'standalone_vm'} [args.preferMode='docker']
 * @returns {Promise<object>}            ciab_profile_vuln_apps row
 */
async function getOrGenerateVulnApp({ profile, llmModel, preferMode = 'docker' }) {
  const existing = await query(
    `SELECT * FROM ciab_profile_vuln_apps WHERE profile_id = $1 ORDER BY generated_at DESC LIMIT 1`,
    [profile.id]
  );
  if (existing.rows.length > 0) {
    return existing.rows[0];
  }

  const assets = Array.isArray(profile.assets) ? profile.assets : [];
  const webServer = assets.find(isWebServer);
  const targetHostname = webServer ? webServer.hostname : null;
  const effectiveMode = webServer ? preferMode : 'standalone_vm';

  // Try the multi-stage pipeline first (concept → per-file fan-out → install).
  // Falls back to the hardcoded template if Claude is unreachable or the
  // pipeline blows up (caught broadly because we don't want a vuln-app
  // failure to take down the whole lane deploy — the lane is still useful
  // without the app).
  let generated = null;
  let source = 'fallback';
  if (process.env.ANTHROPIC_API_KEY) {
    try {
      generated = await generateVulnAppMultistage({
        profile, webServer, deliveryMode: effectiveMode, llmModel
      });
      source = 'claude_multistage';
    } catch (err) {
      console.warn(`[CIAB VulnApp] Multi-stage generation failed for profile ${profile.id}: ${err.message} — falling back to hardcoded template`);
    }
  } else {
    console.warn(`[CIAB VulnApp] ANTHROPIC_API_KEY not set — using hardcoded template`);
  }

  if (!generated || !generated.install_script) {
    generated = buildFallbackVulnApp({ profile, targetHostname, deliveryMode: effectiveMode });
    source = 'fallback';
  }

  const insert = await query(
    `INSERT INTO ciab_profile_vuln_apps
       (profile_id, target_hostname, delivery_mode, dockerfile, source_tree,
        install_script, llm_model, generation_meta)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8::jsonb)
     RETURNING *`,
    [
      profile.id, targetHostname, effectiveMode,
      generated.dockerfile || null,
      JSON.stringify(generated.source_tree || {}),
      generated.install_script,
      source.startsWith('claude') ? (llmModel || llm.DEFAULT_MODEL) : null,
      JSON.stringify({ ...(generated.generation_meta || {}), source })
    ]
  );
  return insert.rows[0];
}

// ─── Claude path ───────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a cybersecurity lab content author. Generate a small, deliberately-vulnerable web application for a hands-on student lab.

REQUIREMENTS — every app you generate MUST:
1. Be small (3–6 source files, ≤ 600 lines total) — pedagogical, not production.
2. Contain exactly 3–5 distinct OWASP Top-10 vulnerabilities. Each one must be triggerable through the public HTTP interface with simple input (a query param, a form field, a cookie). No multi-step exploit chains.
3. Be self-contained — SQLite for any data, no external services, no auth provider, no email.
4. Listen on port 80 (HTTP, no TLS — labs use HTTP for simplicity).
5. Be themed around the target company's industry so the lab feels realistic (e.g. healthcare → patient portal, retail → product search).
6. NEVER include real malware, reverse shells, ransomware, or anything that could harm the lab host beyond what the student is exploiting. Vulnerabilities = teaching XSS/SQLi/IDOR/SSRF/file-include/etc., not destructive payloads.

OUTPUT FORMAT — respond with raw JSON ONLY (no markdown fences, no prose):
{
  "vulns_picked": ["xss_reflected", "sqli_search", "idor_user_lookup"],  // 3-5 string labels
  "source_tree": {
    "index.php":   "<full file content>",
    "search.php":  "<full file content>",
    "setup.sh":    "<bash script that initializes the SQLite DB>",
    ...
  },
  "dockerfile":     "<full Dockerfile content if delivery_mode=docker, else empty string>",
  "install_script": "<single bash one-liner that installs and starts the app on a fresh Ubuntu/Debian VM>",
  "notes": "<2-3 sentences for the instructor: what's vulnerable, how to demo each finding>"
}

INSTALL_SCRIPT contract:
- For delivery_mode='docker': install Docker if missing, then \`docker build -t vuln-app .\` and \`docker run -d --restart=always --name vuln-app -p 80:80 vuln-app\`. The orchestrator unpacks source_tree + dockerfile into the CWD before running install_script.
- For delivery_mode='apache_vhost' or 'standalone_vm': install apache2 + php + php-sqlite3, source_tree files have already been written into /var/www/html/ by the orchestrator, then run any setup.sh and restart apache.

SECURITY CONSTRAINTS — even though the app is intentionally vulnerable:
- No \`rm -rf /\`, no fork bombs, no outbound network connections to the public internet beyond apt-get/docker.
- No backdoor accounts with hardcoded credentials matching real services (use admin/admin or similar obviously-fake creds).
- No code that exfiltrates env vars or files outside the app directory.
`;

function buildUserPrompt({ profile, webServer, targetHostname, deliveryMode }) {
  const company = profile.company_name || 'AcmeCo';
  const industry = profile.industry || 'general business';
  const difficulty = profile.difficulty || 'intermediate';
  const declaredServices = (webServer && Array.isArray(webServer.services))
    ? webServer.services.join(', ')
    : 'none declared';

  return `Generate a vulnerable web app for this lab:

- Company: ${company}
- Industry: ${industry}
- Difficulty: ${difficulty}  (easy=very obvious vulns; intermediate=mixed obvious + subtle; advanced=mostly subtle, requires reading code)
- Target host: ${targetHostname || 'a dedicated Ubuntu VM (no specific host)'}
- Declared services on target: ${declaredServices}
- Delivery mode: ${deliveryMode}

Pick vulnerabilities that fit ${industry} (e.g. a patient ID parameter for IDOR if healthcare, a coupon code for SQLi if retail). Theme the UI copy, table names, and seed data around ${company}. Make it feel like a real internal app, not a generic DVWA clone.

Respond with raw JSON matching the format in the system prompt. No markdown fences.`;
}

async function generateVulnAppWithClaude({ profile, webServer, targetHostname, deliveryMode, llmModel }) {
  const { value, usage } = await llm.generateJson({
    model: llmModel,
    system: llm.cachedSystem(SYSTEM_PROMPT),
    messages: [{
      role: 'user',
      content: buildUserPrompt({ profile, webServer, targetHostname, deliveryMode })
    }],
    max_tokens: 8192,
    temperature: 0.7,
    label: `vuln-app:${profile.id?.slice(0, 8)}`
  });

  if (!value.source_tree || typeof value.source_tree !== 'object') {
    throw new Error('Claude response missing source_tree object');
  }
  if (!value.install_script || typeof value.install_script !== 'string') {
    throw new Error('Claude response missing install_script');
  }

  return {
    source_tree: value.source_tree,
    dockerfile: value.dockerfile || null,
    install_script: value.install_script,
    generation_meta: {
      vulns: value.vulns_picked || [],
      notes: value.notes || '',
      usage,
      company: profile.company_name,
      industry: profile.industry
    }
  };
}

// ─── Fallback: hardcoded vulnerable PHP app ─────────────────────────────────
// Intentional weaknesses: reflected XSS, SQLi in /search, IDOR on /user,
// exposed phpinfo.php. Used only when ANTHROPIC_API_KEY is unset or Claude fails.
function buildFallbackVulnApp({ profile, targetHostname, deliveryMode }) {
  const companyName = (profile.company_name || 'AcmeCo').replace(/[^A-Za-z0-9 ]/g, '');
  const industry = profile.industry || 'general';

  const indexPhp = `<?php
// ${companyName} — internal portal (vulnerable demo)
$q = isset($_GET['q']) ? $_GET['q'] : '';
?>
<!doctype html><html><head><title>${companyName} Portal</title></head>
<body>
  <h1>${companyName} (${industry}) — Internal Portal</h1>
  <p>Welcome back. <a href="/search.php?q=test">Search</a> | <a href="/user.php?id=1">My Profile</a></p>
  <!-- Reflected XSS sink: -->
  <div>Last query: <?= $q ?></div>
</body></html>
`;

  const searchPhp = `<?php
// SQL injection sink — concatenates query into SQL.
$db = new SQLite3('/tmp/portal.db');
$q = $_GET['q'] ?? '';
$sql = "SELECT id, name FROM products WHERE name LIKE '%$q%'";
$rows = $db->query($sql);
echo "<h2>Search results for $q</h2><ul>";
while ($r = $rows->fetchArray(SQLITE3_ASSOC)) {
  echo "<li>" . $r['name'] . "</li>";
}
echo "</ul>";
`;

  const userPhp = `<?php
// IDOR — no auth check, any id is returned.
$id = (int)($_GET['id'] ?? 0);
$db = new SQLite3('/tmp/portal.db');
$row = $db->querySingle("SELECT * FROM users WHERE id=$id", true);
echo "<pre>" . htmlspecialchars(json_encode($row)) . "</pre>";
`;

  const phpinfo = `<?php phpinfo(); ?>`;

  const setupSh = `#!/bin/bash
set -e
mkdir -p /var/www/html
cat > /tmp/seed.sql <<'SQL'
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
INSERT OR IGNORE INTO users VALUES (1,'admin','admin@${companyName.toLowerCase()}.local','000-00-0001');
INSERT OR IGNORE INTO users VALUES (2,'alice','alice@${companyName.toLowerCase()}.local','000-00-0002');
INSERT OR IGNORE INTO products VALUES (1,'Widget',9.99),(2,'Gadget',19.99);
SQL
sqlite3 /tmp/portal.db < /tmp/seed.sql
chmod 666 /tmp/portal.db
`;

  const sourceTree = {
    'index.php':   indexPhp,
    'search.php':  searchPhp,
    'user.php':    userPhp,
    'phpinfo.php': phpinfo,
    'setup.sh':    setupSh
  };

  let installScript;
  let dockerfile = null;

  if (deliveryMode === 'docker') {
    dockerfile = `FROM php:8.2-apache
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev \\
 && docker-php-ext-install pdo_sqlite \\
 && rm -rf /var/lib/apt/lists/*
COPY *.php /var/www/html/
COPY setup.sh /tmp/setup.sh
RUN bash /tmp/setup.sh
EXPOSE 80
`;
    installScript = [
      'set -e',
      'mkdir -p /opt/vuln-app && cd /opt/vuln-app',
      'command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh',
      'docker build -t vuln-app .',
      'docker rm -f vuln-app 2>/dev/null || true',
      'docker run -d --restart=always --name vuln-app -p 80:80 vuln-app'
    ].join(' && ');
  } else {
    // apache_vhost or standalone_vm — same recipe
    installScript = [
      'set -e',
      'apt-get update',
      'DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 php libapache2-mod-php php-sqlite3 sqlite3',
      'rm -f /var/www/html/index.html',
      'bash /var/www/html/setup.sh',
      'chown -R www-data:www-data /var/www/html',
      'systemctl enable apache2 && systemctl restart apache2'
    ].join(' && ');
  }

  return {
    dockerfile,
    source_tree: sourceTree,
    install_script: installScript,
    generation_meta: {
      company: companyName,
      industry,
      vulns: ['reflected_xss', 'sqli', 'idor', 'exposed_phpinfo']
    }
  };
}

module.exports = {
  getOrGenerateVulnApp,
  buildFallbackVulnApp,
  generateVulnAppWithClaude,   // exported for testing
  SYSTEM_PROMPT                 // exported for testing / cost estimation
};
