/**
 * ai/vuln-app/index.js — Multi-stage AI vulnerable-app pipeline.
 * ============================================================================
 * Replaces the prior single-shot vuln-app generator. Produces CyberSaguaros-
 * caliber labs: 5-10 themed pages, 3-5 stage attack chain, varied vuln
 * categories (not just OWASP Top-10), tech stack matched to the company.
 *
 *   Stage 1: CONCEPT_DESIGN — one Claude call, returns the full app spec
 *   Stage 2: FILE_GENERATOR — fan-out in parallel, one Claude call per page
 *   Stage 3: INSTALL_GEN    — one Claude call, returns Dockerfile + install_script
 *
 * The final output matches the legacy shape so the downstream lane-deploy
 * orchestrator (which writes source_tree files via guest agent then runs
 * install_script) doesn't change.
 */

const llm = require('../../../../../../src/utils/llm-client');
const {
  CONCEPT_SYSTEM_PROMPT,
  FILE_GEN_SYSTEM_PROMPT,
  INSTALL_SYSTEM_PROMPT,
  buildConceptUserPrompt,
  buildFileUserPrompt,
  buildInstallUserPrompt
} = require('./prompts');
const { detectMissingRelativeImports } = require('../../utils/vuln-app-builder');

// Override the global concurrency cap for the file-gen fan-out specifically.
// Each file call emits up to ~4K output tokens; with the global cap at 6 and
// Tier-1 Sonnet at 8K out/min, an 8-file fan-out blows through the budget in
// the first ~15 seconds and the rest get 429'd. Default 2 keeps us within
// Tier-1 limits; admins on higher tiers can bump this via env var.
const VULN_APP_FILE_CONCURRENCY = parseInt(process.env.CIAB_VULN_APP_FILE_CONCURRENCY, 10) || 2;
// 4096 was truncating files mid-line. 8192 is Sonnet's default ceiling and
// fits even the larger pages (auth + dashboard with inline CSS). Override
// via env if you start hitting it again.
const VULN_APP_FILE_MAX_TOKENS  = parseInt(process.env.CIAB_VULN_APP_FILE_MAX_TOKENS,  10) || 8192;
// Retries are serial (no fan-out budget pressure), so give a flagged-truncated
// page a bigger ceiling — re-running at the same 8192 cap just truncates again
// and the page gets dropped. Sonnet 4.5 allows far more output than this.
const VULN_APP_FILE_RETRY_MAX_TOKENS = parseInt(process.env.CIAB_VULN_APP_FILE_RETRY_MAX_TOKENS, 10) || 16384;

// ─── Stage 1: design the app ───────────────────────────────────────────────

async function designConcept({ profile, webServer, deliveryMode, llmModel, difficulty = 'easy' }) {
  const { value, usage, latencyMs } = await llm.generateJson({
    model: llmModel,
    system: llm.cachedSystem(CONCEPT_SYSTEM_PROMPT),
    messages: [{ role: 'user', content: buildConceptUserPrompt({ profile, webServer, deliveryMode, difficulty }) }],
    max_tokens: 8192,
    temperature: 0.8,           // higher to encourage variety across companies
    label: `vuln-app:concept:${profile.id?.slice(0,8) || 'na'}:${difficulty}`
  });

  // Basic shape validation — caller can decide what to do if anything is missing
  if (!value || !Array.isArray(value.page_inventory) || value.page_inventory.length === 0) {
    throw new Error('Concept design returned no page_inventory');
  }
  if (!Array.isArray(value.attack_chain) || value.attack_chain.length === 0) {
    throw new Error('Concept design returned no attack_chain');
  }
  return { concept: value, usage, latencyMs };
}

// ─── Stage 2.5 helper: turn a missing-import diagnostic into a page spec ────
// The file generator runs off a `pageSpec` (path/purpose/auth_required/...).
// For self-healing we don't have an explicit pageSpec — we have a file path
// that something else `require()`s. Synthesize a sensible spec by:
//   1. resolving the consumer's import to a canonical file path
//   2. listing every consumer that references it (so the LLM understands
//      the shape needed: schema, query helpers, exported functions, etc.)
//   3. excerpting a few lines around the import so the LLM sees the call
//      sites and can match function signatures
// The richer the `purpose` field, the more likely the regenerated file
// fits its consumers without further iteration.
function synthesizeRepairPage(missingItem, sourceTree, concept) {
  // missingItem = { from, spec, expected }
  const path = require('path').posix;
  const fileName = path.basename(missingItem.expected) || missingItem.expected;
  // The expected target — append .js if there's no extension so the LLM
  // generates a JS module (matches what node would resolve to).
  const targetPath = /\.[a-z]+$/i.test(missingItem.expected)
    ? missingItem.expected
    : `${missingItem.expected}.js`;

  // Find every file that imports this same module — there may be more than one.
  // The signal "imported by N files" tells the LLM this is shared infrastructure.
  const consumers = [];
  const importRe = new RegExp(
    `\\b(require|import)\\s*[\\(\\s][^'"\\n]*?['"]([^'"\\n]+)['"]`, 'g'
  );
  for (const [filePath, content] of Object.entries(sourceTree)) {
    if (!/\.(m?[jt]s|cjs)$/i.test(filePath)) continue;
    const src = String(content || '');
    for (const m of src.matchAll(importRe)) {
      const spec = m[2];
      if (!spec.startsWith('.') && !spec.startsWith('/')) continue;
      // Resolve the consumer's spec relative to ITS path; compare to our target.
      const resolved = path.normalize(path.join(path.dirname(filePath), spec));
      if (resolved === missingItem.expected ||
          resolved === missingItem.expected.replace(/\.[a-z]+$/i, '') ||
          missingItem.expected.startsWith(`${resolved}.`) ||
          missingItem.expected.startsWith(`${resolved}/`)) {
        // Grab a few lines of context around the import to show call sites.
        const lines = src.split('\n');
        const lineIdx = lines.findIndex(l => l.includes(spec));
        const excerpt = lineIdx >= 0
          ? lines.slice(Math.max(0, lineIdx - 1), Math.min(lines.length, lineIdx + 4)).join('\n')
          : '';
        consumers.push({ from: filePath, excerpt });
      }
    }
  }

  // Build a rich purpose string the file generator can act on.
  const stack = concept.tech_stack || '';
  const consumerSummary = consumers.length
    ? `Imported by ${consumers.length} file(s): ${consumers.map(c => c.from).join(', ')}`
    : `Referenced by ${missingItem.from} as '${missingItem.spec}'`;
  const callSites = consumers
    .filter(c => c.excerpt)
    .slice(0, 3)
    .map(c => `// in ${c.from}:\n${c.excerpt}`)
    .join('\n\n');

  return {
    path: targetPath,
    purpose: [
      `Shared module ${fileName} that was referenced but never generated in this app's source_tree.`,
      consumerSummary + '.',
      callSites ? `Generate it to match these existing call sites:\n${callSites}` : '',
      `Match the app's stack: ${stack}.`,
      `Export whatever the consumers expect (db connection, helper functions, schemas, etc.) — infer from the call sites.`
    ].filter(Boolean).join('\n'),
    auth_required: false,
    vuln_role: 'none',
    vuln_summary: null
  };
}

// ─── Stage 2: generate every page in parallel ─────────────────────────────

async function generateAllFiles({ concept, llmModel, profileIdShort }) {
  const pages = concept.page_inventory.filter(p => p && p.path);
  if (pages.length === 0) return { files: [], totalUsage: {}, fileErrors: [] };

  const buildOpts = (pageSpec, attemptLabel = '', maxTokens = VULN_APP_FILE_MAX_TOKENS) => ({
    model: llmModel,
    // Cache the file-gen system prompt across all N calls — big input savings
    // since each call also includes the same `concept` JSON in the user prompt.
    system: llm.cachedSystem(FILE_GEN_SYSTEM_PROMPT),
    messages: [{ role: 'user', content: buildFileUserPrompt({ concept, pageSpec }) }],
    max_tokens: maxTokens,
    temperature: 0.6,
    label: `vuln-app:file:${pageSpec.path.replace(/[^a-z0-9]/gi, '_').slice(0, 20)}:${profileIdShort}${attemptLabel}`
  });

  // Per-result interpreter — translates an LLM result + page into either a
  // successful file entry or an error reason. Shared by the initial pass + retries.
  const interpretResult = (r, page) => {
    if (!r.ok) return { ok: false, error: r.error.message };
    const fileSpec = r.value.value;
    if (!fileSpec || !fileSpec.content || typeof fileSpec.content !== 'string') {
      return { ok: false, error: 'no content field in file-gen response' };
    }
    // Detect truncation. The ONLY definitive signal from the API is
    // stop_reason='max_tokens'. We also flag if the file ends mid-token
    // (last non-whitespace char is :, =, (, [, { — these almost never
    // terminate valid code). Don't try to count braces or look for ; / ,
    // — both are valid file terminators in JS/PHP/Python and produced
    // false positives that wasted LLM budget on healthy files.
    // stop_reason lives on the raw Anthropic response (generateJson returns
    // { value, raw, usage, latencyMs }). Reading r.value.stop_reason or
    // r.value.value.stop_reason always yielded undefined, so 'max_tokens' was
    // never detected and truncated files ending on a "safe" char slipped through.
    const stopReason = r.value.raw && r.value.raw.stop_reason;
    const c = fileSpec.content;
    const lastLine = c.split('\n').pop().trim();
    const trimmed = c.replace(/\s+$/, '');
    const lastChar = trimmed.slice(-1);
    const looksTruncated =
      stopReason === 'max_tokens' ||
      /[:=([{]/.test(lastChar);
    if (looksTruncated) {
      return { ok: false, error: `file looks truncated (stop=${stopReason}, lastChar="${lastChar}", lastLine="${lastLine.slice(0,60)}")` };
    }
    return {
      ok: true,
      file: {
        path: fileSpec.path || page.path,
        content: c,
        vuln_notes: fileSpec.vuln_notes || null,
        vuln_role: page.vuln_role || 'none'
      },
      usage: r.value.usage || {}
    };
  };

  // ── Initial parallel pass ──────────────────────────────────────────────
  const optsList = pages.map(p => buildOpts(p));
  const results = await llm.generateParallel(optsList, {
    json: true,
    maxConcurrent: VULN_APP_FILE_CONCURRENCY
  });

  const files = [];
  const pendingRetry = [];   // pages that still need a successful file
  let totalIn = 0, totalOut = 0, totalCacheRead = 0;

  for (let i = 0; i < results.length; i++) {
    const interp = interpretResult(results[i], pages[i]);
    if (interp.ok) {
      files.push(interp.file);
      const u = interp.usage;
      totalIn       += u.input_tokens             || 0;
      totalOut      += u.output_tokens            || 0;
      totalCacheRead+= u.cache_read_input_tokens  || 0;
    } else {
      pendingRetry.push({ page: pages[i], lastError: interp.error });
    }
  }

  // ── Retry failed files individually, up to 2 extra attempts each ──────
  // Done sequentially (not parallel) to dodge rate limits — the failures are
  // usually rate-limit / partial-JSON parse errors, and serial gives the
  // budget time to recover.
  const MAX_RETRIES = 2;
  for (let attempt = 1; attempt <= MAX_RETRIES && pendingRetry.length > 0; attempt++) {
    console.warn(`   ↻ Retrying ${pendingRetry.length} failed file(s), attempt ${attempt}/${MAX_RETRIES}`);
    const stillPending = [];
    for (const item of pendingRetry) {
      try {
        const single = await llm.generateParallel(
          [buildOpts(item.page, `:retry${attempt}`, VULN_APP_FILE_RETRY_MAX_TOKENS)],
          { json: true, maxConcurrent: 1 }
        );
        const interp = interpretResult(single[0], item.page);
        if (interp.ok) {
          files.push(interp.file);
          const u = interp.usage;
          totalIn       += u.input_tokens             || 0;
          totalOut      += u.output_tokens            || 0;
          totalCacheRead+= u.cache_read_input_tokens  || 0;
          console.log(`   ✓ Retry succeeded for ${item.page.path}`);
        } else {
          stillPending.push({ page: item.page, lastError: interp.error });
        }
      } catch (err) {
        stillPending.push({ page: item.page, lastError: err.message });
      }
    }
    pendingRetry.length = 0;
    pendingRetry.push(...stillPending);
  }

  const fileErrors = pendingRetry.map(p => ({ path: p.page.path, error: p.lastError }));

  return {
    files,
    fileErrors,
    totalUsage: { input_tokens: totalIn, output_tokens: totalOut, cache_read_input_tokens: totalCacheRead }
  };
}

// ─── Stage 3 fallback: deterministic install_script + Dockerfile ──────────
// Used when the LLM stage-3 call fails (typically rate-limit on lower tiers).
// Pattern-matches the concept's primary_language and tech_stack hints to pick
// the right runtime install recipe.
function buildFallbackInstall({ concept, deliveryMode }) {
  const lang = String(concept.primary_language || '').toLowerCase();
  const stack = String(concept.tech_stack || '').toLowerCase();

  // PHP / Apache
  if (lang === 'php' || stack.includes('php') || stack.includes('apache')) {
    if (deliveryMode === 'docker') {
      return {
        install_script: [
          'set -e',
          'mkdir -p /opt/vuln-app && cd /opt/vuln-app',
          'command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh',
          'docker build -t vuln-app .',
          'docker rm -f vuln-app 2>/dev/null || true',
          'docker run -d --restart=always --name vuln-app -p 80:80 vuln-app'
        ].join(' && '),
        dockerfile: `FROM php:8.2-apache
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev \\
 && docker-php-ext-install pdo_sqlite \\
 && rm -rf /var/lib/apt/lists/*
COPY . /var/www/html/
RUN find /var/www/html -name "*.sh" -exec bash {} \\; 2>/dev/null || true
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
`,
        post_install_notes: 'PHP+Apache via Docker on port 80'
      };
    }
    return {
      install_script: [
        'set -e',
        'apt-get update',
        'DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 php libapache2-mod-php php-sqlite3 sqlite3',
        'rm -f /var/www/html/index.html',
        'find /var/www/html -name "*.sh" -exec bash {} \\; 2>/dev/null || true',
        'chown -R www-data:www-data /var/www/html',
        'systemctl enable apache2 && systemctl restart apache2'
      ].join(' && '),
      dockerfile: null,
      post_install_notes: 'PHP+Apache via apt — app installed in /var/www/html/'
    };
  }

  // Python / Flask
  if (lang === 'python' || stack.includes('python') || stack.includes('flask')) {
    if (deliveryMode === 'docker') {
      return {
        install_script: [
          'set -e',
          'mkdir -p /opt/vuln-app && cd /opt/vuln-app',
          'command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh',
          'docker build -t vuln-app .',
          'docker rm -f vuln-app 2>/dev/null || true',
          'docker run -d --restart=always --name vuln-app -p 80:80 vuln-app'
        ].join(' && '),
        dockerfile: `FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir flask flask-sqlalchemy
EXPOSE 80
CMD ["python", "app.py"]
`,
        post_install_notes: 'Flask via Docker on port 80'
      };
    }
    return {
      install_script: [
        'set -e',
        'apt-get update',
        'DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv',
        'cd /opt/vuln-app',
        'python3 -m venv venv && ./venv/bin/pip install flask flask-sqlalchemy',
        'find /opt/vuln-app -name "*.sh" -exec bash {} \\; 2>/dev/null || true',
        'cat > /etc/systemd/system/vuln-app.service <<\'EOF\'\n[Unit]\nDescription=CIAB vuln-app\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/vuln-app\nExecStart=/opt/vuln-app/venv/bin/python /opt/vuln-app/app.py\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF',
        'systemctl daemon-reload && systemctl enable --now vuln-app'
      ].join(' && '),
      dockerfile: null,
      post_install_notes: 'Flask via venv + systemd on port 80'
    };
  }

  // Node.js
  if (lang === 'node' || stack.includes('node') || stack.includes('express')) {
    if (deliveryMode === 'docker') {
      return {
        install_script: [
          'set -e',
          'mkdir -p /opt/vuln-app && cd /opt/vuln-app',
          'command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh',
          'docker build -t vuln-app .',
          'docker rm -f vuln-app 2>/dev/null || true',
          'docker run -d --restart=always --name vuln-app -p 80:80 vuln-app'
        ].join(' && '),
        dockerfile: `FROM node:20-alpine
WORKDIR /app
COPY . .
# Build tools for native modules (better-sqlite3, bcrypt, sharp, etc.).
# Installed as a virtual package so we can drop them after npm install
# and the final image stays at the runtime size, not the toolchain size.
RUN apk add --no-cache --virtual .build-deps python3 make g++ \\
 && npm install --omit=dev \\
 && apk del .build-deps
EXPOSE 80
CMD ["node", "server.js"]
`,
        post_install_notes: 'Node.js via Docker on port 80'
      };
    }
    return {
      install_script: [
        'set -e',
        'curl -fsSL https://deb.nodesource.com/setup_20.x | bash -',
        'apt-get install -y nodejs',
        'cd /opt/vuln-app && npm install --omit=dev',
        'cat > /etc/systemd/system/vuln-app.service <<\'EOF\'\n[Unit]\nDescription=CIAB vuln-app\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/vuln-app\nExecStart=/usr/bin/node /opt/vuln-app/server.js\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF',
        'systemctl daemon-reload && systemctl enable --now vuln-app'
      ].join(' && '),
      dockerfile: null,
      post_install_notes: 'Node.js via systemd on port 80'
    };
  }

  // Unknown stack — best-effort: install Apache + try running any setup.sh
  return {
    install_script: [
      'set -e',
      'apt-get update',
      'DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 php sqlite3',
      'find /var/www/html /opt/vuln-app -name "setup.sh" -exec bash {} \\; 2>/dev/null || true',
      'systemctl restart apache2 || true'
    ].join(' && '),
    dockerfile: null,
    post_install_notes: `Unknown tech_stack '${concept.tech_stack}' — using generic Apache fallback`
  };
}

// ─── Stage 3: install script + Dockerfile ─────────────────────────────────

async function generateInstall({ concept, deliveryMode, sourceTreeFileList, llmModel, profileIdShort }) {
  const { value, usage } = await llm.generateJson({
    model: llmModel,
    system: llm.cachedSystem(INSTALL_SYSTEM_PROMPT),
    messages: [{
      role: 'user',
      content: buildInstallUserPrompt({ concept, deliveryMode, sourceTreeFileList })
    }],
    max_tokens: 4096,
    temperature: 0.5,
    label: `vuln-app:install:${profileIdShort}`
  });
  if (!value || !value.install_script) {
    throw new Error('Install generator returned no install_script');
  }
  return {
    install_script: value.install_script,
    dockerfile: value.dockerfile || null,
    post_install_notes: value.post_install_notes || null,
    usage
  };
}

// ─── Public: orchestrate all three stages ─────────────────────────────────

/**
 * Generate a complete vulnerable web app via the multi-stage pipeline.
 *
 * @param {object} args
 * @param {object} args.profile        profiles row + .assets[] + .stakeholders[]
 * @param {object} [args.webServer]    web-server asset from the profile (or null → standalone_vm)
 * @param {'docker'|'apache_vhost'|'standalone_vm'} args.deliveryMode
 * @param {string} [args.llmModel]
 * @returns {Promise<{source_tree, dockerfile, install_script, generation_meta}>}
 */
async function generateVulnApp({ profile, webServer, deliveryMode, llmModel, difficulty = 'easy' }) {
  const profileIdShort = profile.id?.slice(0, 8) || 'na';
  const startedAt = Date.now();

  console.log(`🎯 [vuln-app] Stage 1: design concept for profile ${profileIdShort} (${profile.company_name}) at difficulty=${difficulty}`);
  const { concept, usage: stage1Usage } = await designConcept({ profile, webServer, deliveryMode, llmModel, difficulty });
  console.log(`   → ${concept.page_inventory.length} pages, ${concept.attack_chain.length}-stage chain, stack: ${concept.tech_stack}`);

  console.log(`🎯 [vuln-app] Stage 2: generate ${concept.page_inventory.length} files in parallel`);
  const { files, fileErrors, totalUsage: stage2Usage } = await generateAllFiles({
    concept, llmModel, profileIdShort
  });
  if (files.length === 0) {
    throw new Error(`All ${concept.page_inventory.length} file generations failed: ${fileErrors.map(e => e.path).join(', ')}`);
  }
  if (fileErrors.length > 0) {
    console.warn(`   ⚠ ${fileErrors.length}/${concept.page_inventory.length} files failed to generate (continuing with rest)`);
  }

  // Build source_tree (path → content map). Per-file vuln_notes get collected
  // into a separate map so they survive into generation_meta — source_tree
  // itself stays content-only (it's what gets written to disk in the lane VM).
  const source_tree = {};
  const file_annotations = {};
  for (const f of files) {
    source_tree[f.path] = f.content;
    if (f.vuln_notes || (f.vuln_role && f.vuln_role !== 'none')) {
      file_annotations[f.path] = {
        vuln_role: f.vuln_role || 'none',
        vuln_notes: f.vuln_notes || null
      };
    }
  }

  // ── Stage 2.5: self-healing pass for missing relative imports ───────────
  // Stage 2's per-file generators don't see each other's output, so it's
  // common for one file to `require('../db')` while no generator ever
  // produced db.js. Detect that statically and re-invoke the file generator
  // for ONLY the missing paths, with a purpose field that tells the LLM
  // what shape the file needs to satisfy its consumers. One pass — the
  // smoke test in vuln-app-builder.js catches anything still broken.
  const missing = detectMissingRelativeImports(source_tree, '[vuln-app:self-heal]');
  if (missing.length > 0) {
    console.warn(`🩹 [vuln-app] Self-healing ${missing.length} missing file(s) before Stage 3`);
    const repairPages = missing.map(m => synthesizeRepairPage(m, source_tree, concept));
    const repairConcept = { ...concept, page_inventory: repairPages };
    const { files: repairFiles, fileErrors: repairErrors } = await generateAllFiles({
      concept: repairConcept, llmModel, profileIdShort: `${profileIdShort}:heal`
    });
    for (const f of repairFiles) source_tree[f.path] = f.content;
    if (repairFiles.length > 0) {
      console.log(`🩹 [vuln-app] Self-heal added ${repairFiles.length}/${missing.length} files: ${repairFiles.map(f => f.path).join(', ')}`);
    }
    if (repairErrors.length > 0) {
      console.warn(`🩹 [vuln-app] Self-heal could not generate ${repairErrors.length} file(s): ${repairErrors.map(e => e.path).join(', ')} — smoke test will catch if still broken`);
    }
  }

  console.log(`🎯 [vuln-app] Stage 3: generate install script + Dockerfile`);
  let install_script, dockerfile, post_install_notes, stage3Usage;
  try {
    const r = await generateInstall({
      concept, deliveryMode, sourceTreeFileList: Object.keys(source_tree), llmModel, profileIdShort
    });
    install_script = r.install_script;
    dockerfile = r.dockerfile;
    post_install_notes = r.post_install_notes;
    stage3Usage = r.usage;
  } catch (err) {
    // Most common cause: rate-limited on Tier-1 after the file fan-out burned
    // the budget. Synthesize a deterministic install script from the concept
    // tech_stack so we don't waste the Stage 1+2 work.
    console.warn(`[vuln-app] Stage 3 failed (${err.message}) — synthesizing install_script from tech_stack`);
    const fallback = buildFallbackInstall({ concept, deliveryMode });
    install_script = fallback.install_script;
    dockerfile = fallback.dockerfile;
    post_install_notes = `${fallback.post_install_notes} (install script auto-generated — Stage 3 LLM call failed: ${err.message.slice(0, 80)})`;
    stage3Usage = { fallback: true };
  }

  const elapsedMs = Date.now() - startedAt;
  console.log(`✅ [vuln-app] Generated app for ${profile.company_name} in ${(elapsedMs/1000).toFixed(1)}s — ${files.length} files, ${concept.attack_chain.length} attack stages`);

  return {
    source_tree,
    dockerfile,
    install_script,
    // Surface the palette to the orchestrator's CSS injector so the auto-
    // injected base.css gets themed to this company's brand.
    color_palette: concept.color_palette || null,
    // The LLM-authored, app-specific stylesheet. The orchestrator inlines this
    // into every page's <head> at build time (see injectBaseStyles). Falls back
    // to the themed buildBaseCss() if the LLM omitted it.
    app_stylesheet: concept.app_stylesheet || null,
    generation_meta: {
      source: 'claude_multistage',
      pipeline_version: 2,
      // Persisted so vuln-app-generator's cache lookup can find rows by
      // (profile_id, difficulty), and the answer-key UI can show which
      // level was generated.
      difficulty,
      // Stashed in generation_meta because there's no dedicated DB column —
      // profile-to-spec.js reads it back to thread into vulnAppInstall so
      // the CSS injector can theme base.css to the company's brand.
      color_palette: concept.color_palette || null,
      // Same round-trip rationale as color_palette: persisted here so a cached
      // deploy re-inlines the LLM-authored stylesheet instead of falling back.
      app_stylesheet: concept.app_stylesheet || null,
      title: concept.title,
      theme_summary: concept.theme_summary,
      tech_stack: concept.tech_stack,
      primary_language: concept.primary_language,
      attack_chain: concept.attack_chain,
      page_count: files.length,
      page_errors: fileErrors,
      post_install_notes,
      instructor_notes: concept.instructor_notes,
      // Surfaced to the instructor cheat sheet so they have login creds +
      // seed data on hand without grep'ing the source tree.
      seed_data: concept.seed_data || null,
      // Per-file vuln annotations — vuln_role + vuln_notes (which stages
      // each page plays in the attack chain) from Stage 2 output.
      file_annotations,
      elapsed_ms: elapsedMs,
      usage: {
        stage1: stage1Usage,
        stage2: stage2Usage,
        stage3: stage3Usage
      }
    }
  };
}

module.exports = {
  generateVulnApp,
  designConcept,
  generateAllFiles,
  generateInstall
};
