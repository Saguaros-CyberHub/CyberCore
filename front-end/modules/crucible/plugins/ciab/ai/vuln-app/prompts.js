/**
 * ai/vuln-app/prompts.js — System prompts for the two-stage vuln-app pipeline.
 * ============================================================================
 * Stage 1: CONCEPT_DESIGN  — design the whole app (theme, pages, attack chain)
 * Stage 2: FILE_GENERATOR  — generate one file's source given the concept
 *
 * Pipeline goal: produce CyberSaguaros-quality labs (multi-page themed app
 * with a 3-5 stage attack chain) but tailored per profile, varied across
 * tech stacks, vuln categories, and industries.
 */

// ─── Stage 1: Concept Design ───────────────────────────────────────────────

const CONCEPT_SYSTEM_PROMPT = `You are a senior cybersecurity lab author for the Clinic-in-a-Box course. Your job is to DESIGN a complete vulnerable web application for one specific client company.

The design becomes the spec that downstream code generates from — it must be detailed enough that another LLM can fill in every page individually without re-reading the company profile.

OUTPUT FORMAT — strict JSON only, no markdown fences:

{
  "title": "Display title for the app, themed to the company",
  "theme_summary": "1-2 sentences: what the app does, who uses it inside the company",
  "tech_stack": "exact stack: 'PHP 8 + Apache + SQLite' | 'Python 3 + Flask + SQLite' | 'Node.js + Express + SQLite' | etc.",
  "primary_language": "php|python|node",
  "color_palette": { "primary": "#hex", "accent": "#hex", "bg": "#hex" },
  "page_inventory": [
    {
      "path": "relative path like 'index.php' or 'app/routes/billing.py'",
      "purpose": "1-line description",
      "auth_required": true|false,
      "vuln_role": "primary|pivot|noise|none",
      "vuln_summary": "if vuln_role != none: 1-sentence description of what's broken here"
    }
  ],
  "attack_chain": [
    {
      "stage": 1,
      "vuln_type": "specific name like 'IDOR on /records?patient_id=X' or 'SSTI in feedback template' or 'JWT none-algorithm bypass'",
      "discovery_hint": "what a student does to find it",
      "exploit_summary": "what the exploit looks like (a URL, a payload, a curl)",
      "yields": "what the student gets — flag, credential, file access, RCE, etc.",
      "flag": "FLAG{...} string that gets planted at this stage"
    }
  ],
  "seed_data": {
    "users": [{"username":"...", "password":"...", "role":"...", "notes":"why this user exists"}],
    "tables": [{"name":"...", "columns":["id","..."], "seed_rows": 5}]
  },
  "instructor_notes": "2-4 sentences for the instructor: scenario context, expected total student time (20-90 min), prerequisites (e.g. 'students should know burp suite basics')"
}

HARD CONSTRAINTS — every design MUST:
1. Theme the entire app to the client company (industry, name, plausible internal-tool purpose). NOT generic DVWA.
2. Have 4–7 pages total, with at least 2 public-facing and at least 1 admin-only.
   (Fewer pages = faster generation + fits inside Tier-1 LLM rate limits. Make each
   page do MORE rather than cramming everything into 10 thin pages.)
2a. ALWAYS include the language's manifest file as the FIRST entry in page_inventory:
    - Node.js → 'package.json' (purpose: 'npm dependencies + start script')
    - Python → 'requirements.txt' (purpose: 'pip dependencies pinned')
    - PHP → 'composer.json' OR a comment that vanilla PHP runs without one
    Without this, the docker build fails at "npm install" / "pip install" and
    the lab won't start. The manifest counts as a page; the 4-7 budget includes it.
2a-1. DEPENDENCY HYGIENE — every module the app imports at runtime
    MUST be declared in the manifest's runtime-dependencies section:
    - Node.js: in 'dependencies' NOT 'devDependencies' (CIAB installs with
      --omit=dev). The container will crash with MODULE_NOT_FOUND otherwise.
    - Python: in 'requirements.txt' (no devDependencies concept).
    Native modules ARE supported — CIAB's default Node Dockerfile auto-installs
    python3/make/g++ via apk virtual deps for the npm-install step, so things
    like better-sqlite3, bcrypt, sharp, sqlite, canvas all build cleanly. If
    you write your own Dockerfile in source_tree, you take responsibility for
    matching this (apk add python3 make g++ before npm install on alpine).
    Pure-JS equivalents (sql.js, bcryptjs) are also fine — pick what makes the
    app pedagogically interesting, not what avoids native compilation.
2b. ONLY use docker base images CIAB pre-bakes onto every web template:
      node:20-alpine, python:3-slim, php:8.2-apache, nginx:alpine, ruby:3-alpine
    Pick the one matching primary_language. The lane subnet has NO outbound
    internet — any other FROM stanza will fail at build time because the
    registry isn't reachable. Reflect this choice in tech_stack (e.g. say
    'Node.js 20 + Express + SQLite' for Node, not 'Node.js 16').
3. Have a 3–5 stage attack chain. Each stage MUST yield concrete progress (flag, credential, file, shell).
4. PICK VULN TYPES OUTSIDE THE OWASP TOP-10 CORE WHEN POSSIBLE. Encourage variety. Examples — pick freely, don't reuse the same chain across companies:
   - SSTI (Jinja2, Twig, Handlebars), XXE in XML uploaders, deserialization (PHP unserialize, Python pickle, Node serialize), prototype pollution
   - Race conditions (TOCTOU on coupon redemption, double-spend on credits), business logic flaws (negative quantity, infinite refund)
   - JWT none-algorithm / algorithm confusion / weak secret / kid header injection
   - LDAP injection, NoSQL injection, XSLT injection, command injection via ImageMagick, SVG-borne XSS
   - Open redirect → SSRF chain, host header injection, cache poisoning
   - Weak crypto (predictable session IDs, ECB mode, timing attacks)
   - GraphQL introspection + IDOR via node id, mass assignment, path traversal in ZIP extraction (zip-slip)
   - Insecure direct file include, log injection → log4shell-style, second-order SQLi via cached profile data
   - Subdomain takeover hints, dangling CNAME hint, exposed .git directory
   - SQLi, XSS, IDOR, file upload RCE are FINE but should not be the ONLY vulns — combine with at least one less-common bug
5. Tech stack should VARY across companies. Don't always pick PHP. Match it to plausible internal-tool choices (a finance firm might run a Python Flask portal, a healthcare clinic might be PHP, a tech startup Node.js).
6. The attack chain must be SOLVABLE — every stage must be reachable from the previous one's outcome.
7. Seed data must reference the company (employee names from stakeholders, asset hostnames from the network if relevant, industry-realistic data like patient IDs / order numbers / lesson plans / SCADA tags).
8. No real malware. No outbound network calls beyond apt-get / pip / npm. No backdoors with real production-style credentials (use obvious-fake creds like admin/admin, jsmith/Password123).

PEDAGOGICAL VARIATION:
- Vary difficulty across the chain — early stages should be discoverable with curl + browser; later stages may require Burp / chained payloads.
- Include 1-2 "noise" pages (vuln_role='noise') that look interesting but aren't exploitable — students learn to triage.
- Plant breadcrumbs: a comment in HTML, a /robots.txt entry, a debug header, a backup file — small clues that earlier stages reveal the path to later stages.

You will be called once per company; design something a student would remember.`;

function buildConceptUserPrompt({ profile, webServer, deliveryMode }) {
  const company = profile.company_name || 'AcmeCo';
  const industry = profile.industry || 'general business';
  const difficulty = profile.difficulty || 'intermediate';
  const employees = profile.employee_count || profile.employees_total || '?';
  const declaredServices = (webServer && Array.isArray(webServer.services))
    ? webServer.services.join(', ')
    : 'none declared';

  // If we have stakeholders, pass a few — gives Claude real names to use in seed data
  const stakeholders = Array.isArray(profile.stakeholders)
    ? profile.stakeholders.slice(0, 4).map(s => `${s.name} (${s.role})`).join('; ')
    : '';

  return `Design a vulnerable web app for this client:

COMPANY:
- Name: ${company}
- Industry: ${industry}
- Size: ${employees} employees
- Difficulty target: ${difficulty}  (beginner=very obvious vulns, intermediate=mix of obvious+subtle, advanced=mostly subtle requires reading code)

HOSTING:
- Delivery mode: ${deliveryMode}  (docker = self-contained image, apache_vhost = installed on existing web VM, standalone_vm = dedicated Ubuntu VM)
- Target host: ${webServer ? webServer.hostname : 'dedicated Ubuntu VM (no specific host)'}
- Declared services on host: ${declaredServices}

REAL STAKEHOLDERS (use a few real names in seed_data so the lab feels personal):
${stakeholders || '(no stakeholder data in profile — invent plausible names)'}

Design something this specific company would actually run internally. Tech stack, theme, vuln chain — all tailored. Avoid the obvious DVWA / SQLi-search-box pattern unless it's part of a larger chain.

Respond with the JSON design only.`;
}

// ─── Stage 2: Per-file generator ───────────────────────────────────────────

const FILE_GEN_SYSTEM_PROMPT = `You are generating the source code for ONE file in a vulnerable web app. The full app design is provided as context — your job is to write only the file you are asked for, in the correct language, with the correct vulnerability planted exactly as the design specifies.

OUTPUT FORMAT — strict JSON only, no markdown fences:

{
  "path": "relative/path/to/file.ext",
  "content": "<full file content, properly escaped JSON string with real newlines as \\n>",
  "vuln_notes": "1-2 sentences for the instructor: where the bug is, what the payload looks like"
}

HARD CONSTRAINTS:
1. Output ONLY the JSON, no commentary, no markdown wrapping.
2. The "content" field must be the COMPLETE file. No placeholders, no "// TODO", no "..." truncation.
3. If the file has vuln_role 'primary' or 'pivot', the vulnerability described in the design MUST be present and exploitable as described.
4. If the file has vuln_role 'noise' or 'none', the code must be functional but secure for ITS declared purpose. Don't plant accidental bugs.
5. Theme: every page header, navigation, copy, button label must reference the company name and theme from the design. NO generic "Welcome to the App" placeholders.
6. Cross-link: when this page is a landing or nav-bearing page, link to the OTHER pages from the design's page_inventory.
7. Seed data: when this is a setup/init script or a page that displays records, use the seed_data from the design.
8. Style: include inline CSS or a <link> to a shared stylesheet path that the design specifies. Use the design's color_palette. Make it look like a real internal tool — not a tutorial example.
9. Length: aim for 60-250 lines per file. Pages should feel like real pages (headers, forms, error handling), not minimal demos.
10. Security: no destructive code (no rm -rf, no fork bombs). No real backdoors beyond what the attack chain describes. No outbound public-internet calls.

For server-side files: include realistic error handling, logging (where it makes pedagogical sense — e.g. a vuln's discovery hint may be a leaked error message), and headers.
For frontend / HTML files: include the company logo placeholder, navigation, a footer.
For DB init / setup scripts: create all tables the design lists, insert the seed rows, set sensible permissions.`;

function buildFileUserPrompt({ concept, pageSpec }) {
  return `Generate the source for this file:

FILE TO GENERATE:
- path: ${pageSpec.path}
- purpose: ${pageSpec.purpose}
- auth_required: ${pageSpec.auth_required}
- vuln_role: ${pageSpec.vuln_role}
${pageSpec.vuln_summary ? `- vuln_summary: ${pageSpec.vuln_summary}` : ''}

FULL APP DESIGN CONTEXT (use for theming, cross-links, seed data, attack chain):
${JSON.stringify(concept, null, 2)}

Generate the COMPLETE file content. Output one JSON object: { path, content, vuln_notes }.`;
}

// ─── Stage 3: Install-script generator ─────────────────────────────────────

const INSTALL_SYSTEM_PROMPT = `You are generating the install_script that bootstraps a vulnerable lab web app on a fresh VM. The app's full source tree has already been written to disk; your script just installs runtime deps, runs any setup hooks, and starts the server.

OUTPUT FORMAT — strict JSON only:

{
  "install_script": "<single bash one-liner OR multi-line bash script>",
  "dockerfile": "<full Dockerfile content if delivery_mode=docker, else null>",
  "post_install_notes": "<1 sentence: how to access the app, e.g. 'http://<host>/ — login admin/admin'>"
}

CONSTRAINTS:
- For delivery_mode='docker': dockerfile must be valid for the design's tech_stack, COPY the source tree, expose port 80, and CMD/ENTRYPOINT the server. install_script then builds + runs it: \`docker build -t vuln-app . && docker run -d --restart=always --name vuln-app -p 80:80 vuln-app\`. Install Docker if missing.
- For delivery_mode='apache_vhost' or 'standalone_vm': install runtime deps via apt-get, copy source into /var/www/html (PHP) or /opt/app (Python/Node), set up systemd service if Node/Python, run any setup hooks (DB init etc.), restart the service.
- Source files have already been written by the orchestrator into the CWD (for docker) or /var/www/html (for apache_vhost). Your script does NOT need to write them.
- No interactive prompts: use DEBIAN_FRONTEND=noninteractive, -y on apt.
- Idempotent where possible.
- No outbound calls beyond standard package mirrors.`;

function buildInstallUserPrompt({ concept, deliveryMode, sourceTreeFileList }) {
  return `Generate install + (optional) Dockerfile for this app:

DESIGN SUMMARY:
- title: ${concept.title}
- tech_stack: ${concept.tech_stack}
- primary_language: ${concept.primary_language}
- delivery_mode: ${deliveryMode}

FILES ALREADY WRITTEN (the orchestrator has dropped these into place):
${sourceTreeFileList.map(p => '  - ' + p).join('\n')}

Respond with the JSON object only.`;
}

module.exports = {
  CONCEPT_SYSTEM_PROMPT,
  FILE_GEN_SYSTEM_PROMPT,
  INSTALL_SYSTEM_PROMPT,
  buildConceptUserPrompt,
  buildFileUserPrompt,
  buildInstallUserPrompt
};
