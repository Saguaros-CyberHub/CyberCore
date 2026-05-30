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
2a-0. THE APP MUST LISTEN ON PORT 80 INSIDE THE CONTAINER.
    CIAB ships the container with: -e PORT=80 -p 80:80
    The app code MUST read this env var and bind to it. Examples:
      Node/Express:    app.listen(process.env.PORT || 80, '0.0.0.0')
      Python/Flask:    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 80)))
      Python/FastAPI:  uvicorn.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 80)))
    DO NOT hardcode 3000/5000/8080 with no env-var fallback — CIAB's smoke
    test will reject the build because the container will be running but
    not reachable on :80. Also bind to 0.0.0.0 (not localhost / 127.0.0.1)
    so docker's port forwarding can reach the listener.
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
2b. BASE IMAGE — pick from the proven-working set below. CIAB builds the image
    on the orchestrator (which has internet), then ships the tarball to the
    isolated lane VM. The image must START cleanly: CIAB runs a 2-second
    smoke-test "docker run" after build, and a startup crash there kills the
    deploy. Pick:
      node:20-alpine             Node apps. MUST use better-sqlite3 (not
                                 sqlite3 — its v5 prebuilt requires GLIBC 2.38
                                 which alpine/musl doesnt have, crashes on
                                 startup).
      python:3-slim              Python apps (Flask, FastAPI). SQLite via
                                 stdlib sqlite3 module works out of the box.
      php:8.2-apache             PHP apps. php-sqlite3 extension is pre-enabled.
      nginx:alpine               Static + reverse-proxy patterns.
      ruby:3-alpine              Ruby/Sinatra apps.
    Pick the one matching primary_language. Reflect it in tech_stack (e.g.
    'Node.js 20 + Express + better-sqlite3', NOT 'Node.js 16').

    Native-binding gotchas you MUST avoid:
    - Node + sqlite3 (the npm package): broken on alpine and on Debian
      Bookworm. Use better-sqlite3 instead — same SQL, better prebuilt coverage.
    - Node + bcrypt: same family of issues; use bcryptjs (pure JS).
    - Node + canvas/sharp: needs glibc + build deps; only use if app genuinely
      needs image processing, and pin to a Debian-slim base + install build-essential.
3. Have a 3–5 stage attack chain. Each stage MUST yield concrete progress (flag, credential, file, shell).
4. PICK BEGINNER-FRIENDLY VULNERABILITIES. This is a college course; most
   students are NEW to web exploitation. Default to OWASP-style classics that
   are discoverable in a browser + curl, with payloads they can copy from any
   intro tutorial. NO Burp Suite required for stages 1–2 of the chain.

   PREFERRED — pick at least 3 of these for every chain (vary across companies
   so different labs feature different bugs):
   - **SQL injection** (basic): a login form or search box where ' OR '1'='1
     or UNION SELECT works. Plant the bug in a SINGLE query — no second-order
     SQLi, no blind, no time-based. Error messages should leak useful info.
   - **Reflected XSS**: a URL parameter or search field that echoes input
     unescaped — the payload <script>alert(1)</script> should fire.
   - **Stored XSS**: a comment / message / profile-bio field that renders
     unescaped on a page another user (e.g. admin) views.
   - **IDOR (Insecure Direct Object Reference)**: /profile/123 → /profile/124
     reveals someone else's data. /invoice/5.pdf → /invoice/6.pdf works. The
     ID should be in the URL, NOT a hashed token — easy to spot in DevTools.
   - **Missing authorization**: an /admin or /reports page that's linked
     ONLY from the nav-for-admins, but accessible to any logged-in user (or
     no login at all) if they know the URL. Discovery via robots.txt, a
     leaked comment in HTML, or just guessing /admin.
   - **Default credentials**: admin/admin, admin/password123, or per the
     company's seed_data. Often combined with another bug to land an admin
     session, then pivot.
   - **Exposed sensitive files**: /.env, /backup.sql, /config.bak, /admin.bak
     served by the web server because they're in the static directory.
     Discoverable via robots.txt hints, a comment in HTML, or directory guessing.
   - **Information disclosure**: error pages that leak the DB schema, stack
     traces with file paths, debug headers, .git/HEAD exposed.
   - **Path traversal** (file download / read endpoint): ?file=../../etc/passwd
     or ?path=../app.js — keep it to ONE simple traversal, not deep encoded.
   - **File upload RCE** (advanced — only for stage 3+ of the chain): upload
     a .php or .jsp shell to a "profile picture" or "vendor document" endpoint
     that doesn't validate file type. Yields a shell.
   - **Predictable cookies / hidden form fields**: a cookie like
     role=user that can be edited to role=admin; or a hidden form field
     <input type="hidden" name="price" value="99.99"> that the server trusts.

   AVOID for now — too advanced for first-time web-exploit students:
   - SSTI / template injection (requires knowing the template engine first)
   - XXE, deserialization (PHP unserialize, Python pickle, Node serialize)
   - Prototype pollution, race conditions / TOCTOU
   - JWT algorithm confusion, kid header injection
   - LDAP / NoSQL / XSLT injection
   - SSRF, cache poisoning, host header injection
   - Predictable session IDs / ECB / timing-based crypto attacks
   - Zip-slip, log4shell-style log injection, dangling CNAME
   - GraphQL introspection (most students don't know what GraphQL is yet)

   These can return in an "advanced" version of the curriculum later. For now,
   variety comes from how the OWASP classics are themed (a SQLi in a Cochise
   procurement portal feels different from the same SQLi in a Meridian patient
   portal), not from exotic vuln types.

4a. **Discoverability budget per stage** — student of average experience must
    be able to find each stage in:
      Stage 1: under 5 minutes — visible in DevTools, robots.txt, view-source,
               a single URL guess, or an obvious form input.
      Stage 2: under 15 minutes — pivots off stage 1's flag/cred. Should be a
               single payload from a tutorial.
      Stage 3: under 30 minutes — chains stages 1 & 2's outputs. May require
               trying 2-3 variations of a known payload.
      Stages 4–5 (if used): under 45 minutes each — the harder pivot, e.g.
               file upload RCE landed via stage 3's admin creds.
5. Tech stack should VARY across companies. Don't always pick PHP. Match it to plausible internal-tool choices (a finance firm might run a Python Flask portal, a healthcare clinic might be PHP, a tech startup Node.js).
6. The attack chain must be SOLVABLE — every stage must be reachable from the previous one's outcome.
7. Seed data must reference the company (employee names from stakeholders, asset hostnames from the network if relevant, industry-realistic data like patient IDs / order numbers / lesson plans / SCADA tags).
8. No real malware. No outbound network calls beyond apt-get / pip / npm. No backdoors with real production-style credentials (use obvious-fake creds like admin/admin, jsmith/Password123).

PEDAGOGICAL VARIATION:
- Vary difficulty across the chain — see rule 4a's time budget. Early stages
  use copy-paste payloads from intro tutorials; later stages chain previous
  stages' yields. Never require Burp Suite or proxy chaining at this level.
- Include 1-2 "noise" pages (vuln_role='noise') that look interesting but
  aren't exploitable — students learn to triage. Keep noise pages obviously
  secure (proper escaping, parameterized queries) so the red herring is
  educational, not frustrating.
- Plant breadcrumbs: a comment in HTML pointing at /admin, a /robots.txt
  entry disallowing /backup, a debug header echoing the DB version, a link
  to a .bak file — small clues that earlier stages reveal the path to later
  stages. STUDENTS SHOULD ALWAYS BE LOOKING AT view-source AND DEVTOOLS;
  reward that habit by hiding clues there.
- Stage 1's discovery_hint MUST name the exact place the student should
  look (e.g., "Try the login form with SQL injection payloads" or "Check
  /robots.txt and look at the disallowed paths"). Don't make stage 1 a
  mystery — it's the entry point to the whole chain.

You will be called once per company; design something a student would remember.`;

function buildConceptUserPrompt({ profile, webServer, deliveryMode, difficulty }) {
  const company = profile.company_name || 'AcmeCo';
  const industry = profile.industry || 'general business';
  // Per-deploy difficulty (easy|medium|hard) chosen by admin. Falls back to
  // profile.difficulty (an older field used at profile-creation time, with
  // values like 'beginner'/'intermediate'/'advanced'). Normalize to one of
  // easy/medium/hard so the prompt rules can branch cleanly.
  const NORMALIZE = { easy: 'easy', medium: 'medium', hard: 'hard',
    beginner: 'easy', intermediate: 'medium', advanced: 'hard' };
  const diffNorm = NORMALIZE[(difficulty || profile.difficulty || 'easy').toLowerCase()] || 'easy';
  const employees = profile.employee_count || profile.employees_total || '?';
  const declaredServices = (webServer && Array.isArray(webServer.services))
    ? webServer.services.join(', ')
    : 'none declared';

  // If we have stakeholders, pass a few — gives Claude real names to use in seed data
  const stakeholders = Array.isArray(profile.stakeholders)
    ? profile.stakeholders.slice(0, 4).map(s => `${s.name} (${s.role})`).join('; ')
    : '';

  // Per-difficulty vuln-pool guidance — appended to the system prompt's rule 4
  // (which describes the master list). Each level has a sharply different
  // expected output: easy = OWASP basics + 3-stage chain, medium = +1
  // intermediate vuln + 4-stage chain, hard = mostly advanced + 4-5 stages.
  const DIFFICULTY_DIRECTIVES = {
    easy: `DIFFICULTY: EASY (selected by instructor for this deploy).
- Chain length: 3 stages only.
- Vuln pool: USE ONLY from rule 4's PREFERRED list (SQLi, reflected XSS, stored XSS, IDOR, missing authorization, default credentials, exposed sensitive files, information disclosure, simple path traversal, predictable cookies/hidden fields).
- NO file-upload RCE in this chain (save for medium+).
- All payloads must be copy-pasteable from any intro web-security tutorial.
- DevTools + curl + view-source are sufficient — Burp NOT required.
- Discovery hints must literally name the file/URL/field to look at.`,
    medium: `DIFFICULTY: MEDIUM (selected by instructor for this deploy).
- Chain length: 4 stages.
- Vuln pool: AT LEAST 2 from rule 4's PREFERRED list (SQLi/XSS/IDOR/missing auth/etc.), PLUS exactly ONE of the following intermediate vulns:
    * File upload RCE — a profile-picture / document upload endpoint that doesn't validate file type, lets students drop a .php/.jsp/.js shell.
    * JWT with weak secret — token signed with HS256 and a weak password like 'secret' or 'company123'. Students brute-force with jwt-cracker or hashcat and forge admin role.
    * Stored XSS that fires in admin context — comment / message / ticket field renders unescaped on the admin dashboard, leading to session theft or admin action.
    * Simple SSRF — a "fetch URL" or "image preview" endpoint that fetches user-supplied URLs server-side (great for accessing internal /admin or metadata).
    * CSRF on a state-changing admin endpoint — no token, GET-based, exploitable via a crafted link from a low-priv user.
- Burp Suite (Repeater + Intruder basics) helpful but not strictly required.
- Students should need to chain stage-1's yield to find stage-2's input.`,
    hard: `DIFFICULTY: HARD (selected by instructor for this deploy).
- Chain length: 4-5 stages.
- Vuln pool: AT LEAST 2 ADVANCED vulnerabilities from this list:
    * SSTI (Jinja2 / Twig / Handlebars / EJS) in a search / template / report-render endpoint.
    * Deserialization (PHP unserialize / Python pickle / Node node-serialize) on a cookie or POST body.
    * Prototype pollution leading to auth bypass (Node apps).
    * Race condition / TOCTOU on a balance / coupon / approval endpoint.
    * NoSQL injection (MongoDB $where, operator injection) — only if the app legitimately uses NoSQL.
    * JWT algorithm confusion / kid header injection (more sophisticated than weak-secret).
    * Zip-slip in an archive-upload endpoint.
    * Second-order SQLi via cached / stored input.
    * Server-side template injection chained with sandbox escape.
  Plus 1-2 OWASP basics as warm-up stages 1-2.
- Burp Suite required (Repeater, Intruder, Decoder, sometimes a custom Python script).
- Students must read source where exposed (.git, /static/server.js.bak, exposed admin source-view feature).
- Custom payloads expected — no copy-paste off a single tutorial.`
  };
  const difficultyDirective = DIFFICULTY_DIRECTIVES[diffNorm];

  return `Design a vulnerable web app for this client:

COMPANY:
- Name: ${company}
- Industry: ${industry}
- Size: ${employees} employees
- Difficulty: ${diffNorm.toUpperCase()}  (per-deploy admin choice — see DIFFICULTY block below for the exact vuln pool to use)

${difficultyDirective}

HOSTING:
- Delivery mode: ${deliveryMode}  (docker = self-contained image, apache_vhost = installed on existing web VM, standalone_vm = dedicated Ubuntu VM)
- Target host: ${webServer ? webServer.hostname : 'dedicated Ubuntu VM (no specific host)'}
- Declared services on host: ${declaredServices}

REAL STAKEHOLDERS (use a few real names in seed_data so the lab feels personal):
${stakeholders || '(no stakeholder data in profile — invent plausible names)'}

Design something this specific company would actually run internally. Tech stack, theme, vuln chain — all tailored. The DIFFICULTY block above OVERRIDES the system prompt's default vuln-pool guidance — pick vulns from that block's allowed list.

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
8. Style: CIAB auto-injects a professional base stylesheet at /ciab-base.css
   into every HTML file's <head> at build time. It provides themed layout
   for: header/navbar, main content area (max-width 1200px), cards (.card),
   forms (label + input/textarea/select inherit clean styling automatically),
   buttons (button + .btn + .btn-secondary + .btn-outline + .btn-danger),
   tables (clean rows with hover), alerts (.alert + .alert-error/success/warning),
   footer, login pages (.login-container > .login-card, single-column centered,
   max-width 450px), dashboard grids (.dashboard-grid > .stat-card with
   .stat-value/.stat-label), status badges (.badge-pending/approved/rejected/active).
   It's themed automatically from the design's color_palette.

   YOUR JOB: write semantic HTML that USES these classes — don't reinvent
   layout, don't add 3-column login wrappers, don't write inline grid CSS.
   If you write your own stylesheet, ONLY add page-specific touches (custom
   accent on a unique component) — not full layout or color theming. The
   base.css already handles those, and overriding the layout has produced
   broken visual rendering in past deploys.
   Standard structure for every HTML page:
     <body>
       <header class="navbar">…company logo + nav…</header>
       <main>…page content using .card .alert .btn etc…</main>
       <footer>…copyright…</footer>
     </body>
   For login pages specifically:
     <main>
       <div class="login-container">
         <div class="login-card">…title, form, button…</div>
       </div>
     </main>
   DO NOT add aside elements or sidebar divs to login pages — base.css hides
   them with display:none because they always end up as broken narrow columns.
9. Length: aim for 60-250 lines per file. Pages should feel like real pages (headers, forms, error handling), not minimal demos.
10. Security: no destructive code (no rm -rf, no fork bombs). No real backdoors beyond what the attack chain describes. No outbound public-internet calls.
11. MODULE EXPORTS — every file the main app imports MUST export the thing
    the app expects to receive. The CIAB builder smoke-tests the image by
    starting it for 2 seconds; a startup TypeError ("Router.use() requires a
    middleware function but got a Object", "require() returned undefined",
    Python ImportError) kills the deploy. Concretely:
    - Node.js route files: end with "module.exports = router;" — never plain
      "module.exports = {};" or "module.exports = { router };" because then
      "app.use(require('./routes/foo'))" gets an object literal, not a router.
    - Node.js middleware files: end with "module.exports = functionName;" so
      "app.use(require('./mw/auth'))" gets a function.
    - Python Flask blueprints: end with "bp = Blueprint(...)" at module scope
      and the main file imports it as "from routes.foo import bp; app.register_blueprint(bp)".
    - PHP: requires are include-based; no module export, but the included file
      MUST not output anything (no leading whitespace, no echo before headers).
12. APP MAIN-FILE WIRING — the entrypoint (server.js / app.py / index.php)
    must import + mount every other file it references in the design's
    page_inventory. If page_inventory lists routes/foo.js but server.js
    doesn't require it, that route is dead. Cross-check before emitting.

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
