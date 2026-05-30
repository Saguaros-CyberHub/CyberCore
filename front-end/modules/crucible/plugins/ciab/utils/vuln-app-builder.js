/**
 * vuln-app-builder.js — Build the vuln-app Docker image ON THE ORCHESTRATOR,
 * package it as a gzip'd image tarball, and serve it over HTTP so the isolated
 * lane web VM can `docker load` it (no build, no registry pulls on the lane).
 * ============================================================================
 * Why: lane subnets have no reliable outbound internet (no UDP 53, no registry
 * egress), so `docker build` on the lane VM is fragile — base-image pulls and
 * RUN-step package installs fail. The orchestrator HAS internet, so we build
 * there and ship a ready-to-run image. The lane only needs the Docker runtime
 * (pre-baked into the web template) to `docker load` + `docker run`.
 *
 * Transport: the lane PULLS over HTTP via the lane→orchestrator NAT path that
 * lane-bootstrap already uses (gateway MASQUERADEs the lane subnet out wan0).
 * The big image blob goes over one HTTP stream; the QEMU guest agent only
 * carries a tiny wget+load+run command (no slow base64 file transfer).
 *
 * Build engine: DooD — `docker build` + `docker save` against the
 * orchestrator VM's daemon via the /var/run/docker.sock mount declared in
 * docker-compose.yml.
 *
 * Why not kaniko? It was tried as a daemonless alternative but extracts each
 * build's base image into /, which clobbers the running app container
 * (overwrites curl, apk, /etc/os-release with Debian/glibc files) and makes
 * deploys deterministically break. Kaniko's documented runtime is a
 * disposable container per build, which would require either DooD (defeats
 * the point) or a separate sidecar service. See builder revert in this file.
 *
 * Security note: anything with code-execution inside the app container can
 * reach orchestrator-VM root via `docker run -v /:/host`. Mitigations:
 * dep hygiene (npm audit), no shell:true on spawns, OPNsense in front of the
 * orchestrator, admin-only gating on build features.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { buildBaseCss } = require('./vuln-app-base-css');

// Where built image tarballs land. Bind-mounted in docker-compose for
// persistence + easy cleanup; falls back to a tmp dir if unset.
const BUILD_DIR = process.env.CIAB_VULN_BUILD_DIR || '/app/vuln-builds';
// How long a built image stays servable before the sweeper deletes it.
const IMAGE_TTL_MS = parseInt(process.env.CIAB_VULN_IMAGE_TTL_MS, 10) || 2 * 60 * 60 * 1000;
// URL the LANE uses to reach the orchestrator. Internal HTTP (no TLS) so the
// web template's busybox wget works without ca-certificates. Lane egress
// SNATs to the gateway WAN IP — the same source lane-bootstrap uses.
const LANE_ORCH_URL = (process.env.CYBERCORE_INTERNAL_URL || 'http://100.100.20.50:80').replace(/\/+$/, '');
const BUILD_TIMEOUT_MS = parseInt(process.env.CIAB_VULN_BUILD_TIMEOUT_MS, 10) || 12 * 60 * 1000;

// token → { filePath, imageTag, hash, expiresAt }
const _registry = new Map();
// hash → token   (dedupe identical bundles within TTL so a group builds once
// and per-lane retries reuse the same image instead of rebuilding)
const _byHash = new Map();

let _dockerAvailable = null;   // cached probe result

// ─── Shell helper ───────────────────────────────────────────────────────────
// Captures both stdout and stderr. On non-zero exit, attaches a generous
// error tail so deprecation banners at the END of the output don't push the
// REAL error off the truncation cliff (which is exactly what bit us with
// `docker build` — Docker's new deprecation warning at the end took up the
// last 600 chars and hid the actual layer-build failure).
function runShell(script, { timeoutMs = BUILD_TIMEOUT_MS, label = 'sh' } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('/bin/sh', ['-c', script], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('error', err => { clearTimeout(timer); reject(err); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0) return resolve({ stdout, stderr });
      // Big tail (3KB) so multi-step builds with banners + the real error
      // both fit. If the output is short enough to fit in the tail, the
      // entire output is shown.
      const TAIL = 3000;
      const out = stderr || stdout;
      const tail = out.length > TAIL ? `... [truncated, last ${TAIL} chars] ...\n${out.slice(-TAIL)}` : out;
      const err = new Error(`${label} exited ${code}:\n${tail}`);
      err.exitCode = code;
      err.stdout = stdout;
      err.stderr = stderr;
      reject(err);
    });
  });
}

async function dockerAvailable() {
  if (_dockerAvailable !== null) return _dockerAvailable;
  try {
    await runShell(`docker version --format '{{.Server.Version}}'`, { timeoutMs: 15000, label: 'docker version' });
    _dockerAvailable = true;
  } catch (err) {
    console.warn(`[CIAB VulnBuild] Docker not available on orchestrator (${err.message.slice(0, 120)}) — lane-side build fallback will be used`);
    _dockerAvailable = false;
  }
  return _dockerAvailable;
}

// ─── Registry housekeeping ───────────────────────────────────────────────────
function sweep() {
  const now = Date.now();
  for (const [token, entry] of _registry) {
    if (entry.expiresAt <= now) {
      try { fs.rmSync(entry.filePath, { force: true }); } catch (_) {}
      _registry.delete(token);
      if (_byHash.get(entry.hash) === token) _byHash.delete(entry.hash);
    }
  }
}
setInterval(sweep, 10 * 60 * 1000).unref();

function hashBundle(sourceTree, dockerfile) {
  const h = crypto.createHash('sha256');
  const tree = sourceTree || {};
  for (const key of Object.keys(tree).sort()) {
    h.update(key).update('\0').update(String(tree[key])).update('\0');
  }
  h.update('DOCKERFILE\0').update(String(dockerfile || ''));
  return h.digest('hex');
}

// ─── Core build + package ────────────────────────────────────────────────────
async function buildAndPackage({ sourceTree, dockerfile, logTag = '[CIAB VulnBuild]' }) {
  const hash = hashBundle(sourceTree, dockerfile);

  // Reuse an in-flight/cached build of the identical bundle within its TTL.
  const existingToken = _byHash.get(hash);
  if (existingToken) {
    const entry = _registry.get(existingToken);
    if (entry && entry.expiresAt > Date.now() && fs.existsSync(entry.filePath)) {
      console.log(`${logTag} Reusing cached image ${entry.imageTag} (token ${existingToken.slice(0, 8)}…)`);
      return { token: existingToken, imageTag: entry.imageTag, url: imageUrl(existingToken), filePath: entry.filePath };
    }
  }

  const shortHash = hash.slice(0, 12);
  const imageTag = `ciab-vuln:${shortHash}`;
  const token = crypto.randomBytes(24).toString('hex');

  fs.mkdirSync(BUILD_DIR, { recursive: true });
  const ctxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ciab-vulnbuild-'));
  const outFile = path.join(BUILD_DIR, `${token}.tar.gz`);

  try {
    // Materialize the build context: source files + Dockerfile.
    const tree = sourceTree || {};
    for (const [relPath, content] of Object.entries(tree)) {
      const safe = String(relPath).replace(/\.\.(\/|\\)/g, '').replace(/^[/\\]+/, '');
      if (!safe) continue;
      const full = path.join(ctxDir, safe);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content == null ? '' : String(content));
    }
    if (dockerfile) {
      fs.writeFileSync(path.join(ctxDir, 'Dockerfile'), String(dockerfile));
    }
    if (!fs.existsSync(path.join(ctxDir, 'Dockerfile'))) {
      throw new Error('no Dockerfile in bundle — cannot build image');
    }

    // Build on the orchestrator's daemon (DooD via the mounted socket). The
    // build runs in a sandboxed Docker build container — RUN steps don't
    // share the app container's filesystem the way kaniko did, so this no
    // longer clobbers /usr/bin/curl etc. on the orchestrator.
    //
    // DOCKER_BUILDKIT=1 opts into BuildKit (the modern Docker builder).
    // The legacy builder is being removed in Docker 27+; without this var
    // newer Docker prints a deprecation banner that polluted our error
    // tails, and recent versions outright fail when buildx isn't installed.
    // BuildKit is included by default in any reasonably-current Docker
    // Engine — if the host doesn't have it, the build fails fast with a
    // clear "buildx not available" error instead of the truncated banner.
    console.log(`${logTag} Building image ${imageTag} (context ${ctxDir})`);
    await runShell(`DOCKER_BUILDKIT=1 docker build -t ${imageTag} ${shellQuote(ctxDir)}`, { label: `docker build ${imageTag}` });

    // Smoke-test: run the image briefly and confirm it doesn't crash on
    // startup. Catches the "image builds clean, app crashes on require()"
    // class of LLM-generated-app defects — missing deps (better-sqlite3),
    // syntax errors, port collisions inside the image, etc. Failures here
    // throw VULN_APP_SMOKE_FAILED so the deploy fails fast with the actual
    // container logs, rather than letting a broken image ship to lanes.
    await smokeTestImage(imageTag, { logTag });

    // Save → gzip to the served file. `docker save` keeps the repo:tag so the
    // lane's `docker load` restores the exact tag we tell it to run.
    console.log(`${logTag} Saving image ${imageTag} → ${outFile}`);
    await runShell(`docker save ${imageTag} | gzip -c > ${shellQuote(outFile)}`, { label: `docker save ${imageTag}` });

    const sizeBytes = fs.statSync(outFile).size;
    const entry = { filePath: outFile, imageTag, hash, expiresAt: Date.now() + IMAGE_TTL_MS };
    _registry.set(token, entry);
    _byHash.set(hash, token);
    console.log(`${logTag} ✓ Image ready: ${imageTag} (${(sizeBytes / 1048576).toFixed(1)} MB), token ${token.slice(0, 8)}…`);
    return { token, imageTag, url: imageUrl(token), filePath: outFile, sizeBytes };
  } finally {
    try { fs.rmSync(ctxDir, { recursive: true, force: true }); } catch (_) {}
  }
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function imageUrl(token) {
  return `${LANE_ORCH_URL}/api/profile-deploy/image/${token}`;
}

// ─── package.json auto-repair ────────────────────────────────────────────────
// The LLM regularly generates apps that `require('bcrypt')` or
// `require('better-sqlite3')` without adding the package to package.json's
// `dependencies` (often in `devDependencies`, or omitted entirely). The
// docker build's `npm install --omit=dev` then silently skips them, the
// container crashes on startup with MODULE_NOT_FOUND. Rather than rejecting
// these apps — which were designed correctly otherwise — we statically scan
// the source for runtime imports and ADD anything missing to `dependencies`
// with a version of "*" (latest). The orchestrator has internet for the
// build, so npm install pulls them. If a package name was hallucinated,
// npm install fails noisily, which is still a clearer failure than
// MODULE_NOT_FOUND at startup.
//
// Mutates sourceTree in place. Returns the list of added/moved deps for
// logging.
const NODE_BUILTINS = new Set([
  'assert','async_hooks','buffer','child_process','cluster','console','constants',
  'crypto','dgram','dns','domain','events','fs','fs/promises','http','http2','https',
  'module','net','os','path','perf_hooks','process','punycode','querystring',
  'readline','repl','stream','stream/promises','string_decoder','sys','timers',
  'timers/promises','tls','trace_events','tty','url','util','util/types','v8',
  'vm','wasi','worker_threads','zlib','inspector','test'
]);

function isNodeBuiltin(name) {
  const bare = name.replace(/^node:/, '');
  return NODE_BUILTINS.has(bare);
}

function topLevelPkgName(spec) {
  // 'lodash/fp' → 'lodash'   '@scope/pkg/sub' → '@scope/pkg'
  if (spec.startsWith('@')) return spec.split('/').slice(0, 2).join('/');
  return spec.split('/')[0];
}

function repairNodeSourceTree(sourceTree, logTag) {
  if (!sourceTree || typeof sourceTree !== 'object') return [];
  const pkgKey = Object.keys(sourceTree).find(
    k => k === 'package.json' || k.endsWith('/package.json')
  );
  if (!pkgKey) return []; // not a node project

  let pkg;
  try {
    pkg = JSON.parse(String(sourceTree[pkgKey]));
  } catch (err) {
    console.warn(`${logTag} package.json is not valid JSON — skipping dep repair (${err.message.slice(0, 80)})`);
    return [];
  }
  pkg.dependencies = pkg.dependencies || {};
  pkg.devDependencies = pkg.devDependencies || {};
  const declared = new Set(Object.keys(pkg.dependencies));

  // Scan all .js/.mjs/.cjs/.ts files for require()/import statements.
  const detected = new Set();
  const requireRe = /\brequire\(\s*['"]([^'"\n]+)['"]\s*\)/g;
  const importRe = /\bimport\s+(?:[^'"\n;]*?\s+from\s+)?['"]([^'"\n]+)['"]/g;
  for (const [key, value] of Object.entries(sourceTree)) {
    if (!/\.(m?[jt]s|cjs)$/i.test(key)) continue;
    const src = String(value || '');
    for (const m of src.matchAll(requireRe)) detected.add(m[1]);
    for (const m of src.matchAll(importRe)) detected.add(m[1]);
  }

  const added = [];
  for (const spec of detected) {
    if (spec.startsWith('.') || spec.startsWith('/')) continue; // relative
    if (isNodeBuiltin(spec)) continue;
    const name = topLevelPkgName(spec);
    if (declared.has(name)) continue;
    if (pkg.devDependencies[name]) {
      pkg.dependencies[name] = pkg.devDependencies[name];
      delete pkg.devDependencies[name];
      added.push(`${name} (moved from devDependencies)`);
    } else {
      pkg.dependencies[name] = '*';
      added.push(name);
    }
    declared.add(name);
  }

  if (added.length === 0) return [];

  // Clean up empty devDependencies object if we moved everything out
  if (Object.keys(pkg.devDependencies).length === 0) delete pkg.devDependencies;
  sourceTree[pkgKey] = JSON.stringify(pkg, null, 2) + '\n';
  console.log(`${logTag} Auto-repaired ${pkgKey} — added ${added.length} missing runtime dep(s): ${added.join(', ')}`);
  return added;
}

// ─── Static source-tree validation ───────────────────────────────────────────
// Catch the "LLM forgot to generate a file it requires" class of bugs BEFORE
// docker build. Stage 2 of the generation pipeline generates files in
// parallel from a planned page_inventory, but each generator only sees its
// own file's brief — nothing enforces that routes/auth.js's `require('../db')`
// actually corresponds to a file the index-generator produced. Today's case:
// auth.js requires `../db` but db.js was never generated, so the smoke test
// catches it 25-30 seconds into the build pipeline.
//
// This is faster (~5ms) and the error is precise enough to feed back to the
// LLM for a self-healing retry pass later. Returns a list of issues; empty
// means the tree is consistent.
function detectMissingRelativeImports(sourceTree, logTag) {
  if (!sourceTree || typeof sourceTree !== 'object') return [];
  const path = require('path').posix;
  const fileSet = new Set(Object.keys(sourceTree));

  // Given a file 'routes/auth.js' importing '../db', resolve to a candidate
  // path. Try common node-module conventions.
  function resolveToTreePath(fromFile, spec) {
    const fromDir = path.dirname(fromFile);
    const base = path.normalize(path.join(fromDir, spec));
    const tryPaths = [
      base,
      `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}.json`, `${base}.ts`,
      `${base}/index.js`, `${base}/index.mjs`, `${base}/index.cjs`, `${base}/index.ts`
    ];
    return tryPaths.find(p => fileSet.has(p));
  }

  const requireRe = /\brequire\(\s*['"]([^'"\n]+)['"]\s*\)/g;
  const importRe = /\bimport\s+(?:[^'"\n;]*?\s+from\s+)?['"]([^'"\n]+)['"]/g;
  const issues = [];
  for (const [key, value] of Object.entries(sourceTree)) {
    if (!/\.(m?[jt]s|cjs)$/i.test(key)) continue;
    const src = String(value || '');
    const refs = new Set();
    for (const m of src.matchAll(requireRe)) refs.add(m[1]);
    for (const m of src.matchAll(importRe)) refs.add(m[1]);
    for (const spec of refs) {
      if (!spec.startsWith('.') && !spec.startsWith('/')) continue; // bare module name — handled by repair
      const found = resolveToTreePath(key, spec);
      if (!found) {
        issues.push({ from: key, spec, expected: path.normalize(path.join(path.dirname(key), spec)) });
      }
    }
  }
  if (issues.length > 0) {
    console.warn(`${logTag} Source tree missing ${issues.length} file(s) referenced by relative imports:`);
    for (const it of issues) {
      console.warn(`${logTag}   ${it.from} requires '${it.spec}' → no '${it.expected}{,.js,/index.js,...}' in source_tree`);
    }
  }
  return issues;
}

// ─── Professional base styles auto-injection ─────────────────────────────────
// Inject a known-good CSS file into the source_tree and add a <link> tag to
// every HTML/EJS file's <head> so the base styles ALWAYS load — regardless of
// whether the LLM remembered to link its own stylesheet, or what weird inline
// styles it added. The base.css is themed from concept.color_palette via CSS
// custom properties, so each lab still feels like its own company while the
// LAYOUT stays consistent and professional.
//
// Loading order is base FIRST, then any LLM-generated stylesheets. The LLM's
// CSS can override variables and most rules; the !important guards in base
// catch the worst patterns (narrow login sidebars, broken grids, etc.).
function injectBaseStyles(sourceTree, palette, logTag) {
  if (!sourceTree || typeof sourceTree !== 'object') return;

  palette = palette || {};
  const baseCss = buildBaseCss({
    primary: palette.primary,
    accent: palette.accent,
    bg: palette.bg
  });

  // Decide where to drop the file. Conventions in the LLM-generated apps we've
  // seen: public/*.css (Express + static), static/*.css (Flask), assets/*.css.
  // Try to match the LLM's chosen layout; default to public/.
  const cssDirs = ['public', 'static', 'assets'];
  const detectedDir = cssDirs.find(d =>
    Object.keys(sourceTree).some(k => k.startsWith(`${d}/`) && k.endsWith('.css'))
  ) || 'public';
  const baseCssKey = `${detectedDir}/ciab-base.css`;
  sourceTree[baseCssKey] = baseCss;

  // The href the HTML <link> tag will use. Express/Flask/etc serve `public/`
  // (or `static/`) at the URL root, so 'public/foo.css' is served at '/foo.css'.
  const baseHref = `/ciab-base.css`;

  // Inject into every HTML/EJS/Handlebars/PHP/Python-template file. Place the
  // link FIRST in <head> so the LLM's app-specific stylesheet loads after and
  // can override. Templating placeholders (<%= %>, {{}}, <?php ?>) are left
  // alone — we only touch the <head> tag opening.
  // PHP is the big one — PHP+Apache labs embed HTML inside .php files, and
  // the regex previously missed them entirely. Same for Python templates
  // (.j2, .jinja2) and Ruby's .erb. ASP-flavored extensions included for
  // completeness even though they're rare in CIAB labs.
  const htmlExts = /\.(html?|ejs|hbs|handlebars|jsx|tsx|tmpl|tpl|php|phtml|j2|jinja2?|erb|aspx|cshtml|razor|vue|svelte)$/i;
  const linkTag = `<link rel="stylesheet" href="${baseHref}">`;
  let injectedCount = 0;
  const alreadyHas = new RegExp(`href=["']${baseHref}["']`);

  for (const [key, value] of Object.entries(sourceTree)) {
    if (!htmlExts.test(key)) continue;
    let content = String(value || '');
    if (alreadyHas.test(content)) continue;

    if (/<head[^>]*>/i.test(content)) {
      content = content.replace(/(<head[^>]*>)/i, `$1\n  ${linkTag}`);
    } else if (/<html[^>]*>/i.test(content)) {
      // No <head> — add a minimal one right after <html>
      content = content.replace(/(<html[^>]*>)/i, `$1\n<head>\n  ${linkTag}\n</head>`);
    } else {
      // No <html> either — likely a partial / fragment. Prepend the link;
      // it'll still apply once the partial is included.
      content = `${linkTag}\n${content}`;
    }
    sourceTree[key] = content;
    injectedCount++;
  }

  console.log(
    `${logTag} Injected base CSS at ${baseCssKey} (${(baseCss.length/1024).toFixed(1)}KB) ` +
    `themed primary=${palette.primary || 'default'} accent=${palette.accent || 'default'} ` +
    `bg=${palette.bg || 'default'}; linked into ${injectedCount} HTML file(s)`
  );
}

// ─── Build-time smoke test ───────────────────────────────────────────────────
// Run the freshly-built image with no port bindings or volumes and confirm it
// stays running for SMOKE_DURATION_MS. If the container exits within the
// window — MODULE_NOT_FOUND, syntax error, EACCES on bind, anything — grab
// the last ~40 log lines and throw a VULN_APP_SMOKE_FAILED error so the deploy
// surfaces the real reason. Without this check, a broken image still
// `docker save`s clean, ships to the lane, and only fails at the very end
// when the lane's `docker run` enters a crash loop (which we discover when a
// student opens their browser).
//
// We intentionally DO NOT bind ports during the smoke test — the goal is to
// catch crash-on-startup, not to verify the app accepts HTTP requests. Apps
// that bind :80 internally don't conflict with anything because the smoke
// container is its own network namespace.
const SMOKE_DURATION_MS = parseInt(process.env.CIAB_VULN_SMOKE_DURATION_MS, 10) || 25000;
const SMOKE_POLL_MS = 2000;

async function smokeTestImage(imageTag, { logTag = '[CIAB VulnBuild]' } = {}) {
  const containerName = `ciab-smoke-${crypto.randomBytes(4).toString('hex')}`;
  // Random high host port to avoid colliding with orchestrator services
  // (Caddy on 80/443, app on 3000, n8n on 5678, postgres on 5432, etc.).
  const smokeHostPort = 30000 + crypto.randomBytes(2).readUInt16BE() % 30000;
  // We also pass PORT=80 in case the app reads it — same as the install_script
  // we ship to lanes. The container's :80 maps to ${smokeHostPort} on the
  // orchestrator host so we can curl it. If the app binds to a different port
  // (3000, 8080, etc.) the curl-localhost probe will fail and surface that.
  console.log(`${logTag} Smoke-testing ${imageTag} (container ${containerName}, host :${smokeHostPort} → container :80, ${SMOKE_DURATION_MS/1000}s)`);
  try {
    await runShell(
      `docker run -d --name ${shellQuote(containerName)} -e PORT=80 -p 127.0.0.1:${smokeHostPort}:80 ${shellQuote(imageTag)}`,
      { label: 'docker run smoke', timeoutMs: 30000 }
    );

    const startedAt = Date.now();
    let httpOk = false;
    let lastCurlErr = '';

    while (Date.now() - startedAt < SMOKE_DURATION_MS) {
      await new Promise(r => setTimeout(r, SMOKE_POLL_MS));

      // First: is the container even still running? Quick crash detection.
      let running = null, exitCode = null;
      try {
        const { stdout } = await runShell(
          `docker inspect -f '{{.State.Running}} {{.State.ExitCode}}' ${shellQuote(containerName)}`,
          { label: 'docker inspect smoke', timeoutMs: 5000 }
        );
        [running, exitCode] = stdout.trim().split(/\s+/);
      } catch (_) {
        continue;
      }
      if (running !== 'true') {
        let logs = '(logs unavailable)';
        try {
          const r = await runShell(
            `docker logs ${shellQuote(containerName)} 2>&1 | tail -40`,
            { label: 'docker logs smoke', timeoutMs: 5000 }
          );
          logs = r.stdout.trim();
        } catch (_) {}
        const elapsedS = Math.round((Date.now() - startedAt) / 1000);
        const err = new Error(
          `vuln-app smoke test failed — container exited (code=${exitCode}) within ${elapsedS}s. ` +
          `Last 40 log lines:\n${logs}`
        );
        err.code = 'VULN_APP_SMOKE_FAILED';
        throw err;
      }

      // Second: does it answer HTTP on :80 (mapped to ${smokeHostPort})? Any
      // HTTP status is acceptable — even 500 means the app is bound and
      // responding. We only want to catch port-mismatch ("app on 3000 not 80")
      // and "app crashed on first request" defects.
      // -s silent, -o /dev/null discard body, -w write only the HTTP code,
      // --max-time prevents hanging on slow-start apps. -f makes 4xx/5xx
      // non-zero, so we use --write-out + grep for any 3-digit HTTP code.
      if (!httpOk) {
        try {
          const r = await runShell(
            `curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:${smokeHostPort}/`,
            { label: 'curl smoke', timeoutMs: 5000 }
          );
          const code = r.stdout.trim();
          if (/^[1-5]\d\d$/.test(code)) {
            httpOk = true;
            console.log(`${logTag} ✓ HTTP probe got ${code} from container :80 after ${Math.round((Date.now() - startedAt)/1000)}s`);
          } else {
            lastCurlErr = `unexpected response code "${code}"`;
          }
        } catch (err) {
          lastCurlErr = err.message.slice(0, 120);
        }
      }
    }

    if (!httpOk) {
      // Container ran the full window but never responded on :80. Almost
      // always means the app is bound to a different port (Express default
      // 3000, Flask default 5000, etc.). Grab logs so the user can see where
      // the app says it's listening.
      let logs = '(logs unavailable)';
      try {
        const r = await runShell(
          `docker logs ${shellQuote(containerName)} 2>&1 | tail -40`,
          { label: 'docker logs smoke', timeoutMs: 5000 }
        );
        logs = r.stdout.trim();
      } catch (_) {}
      const err = new Error(
        `vuln-app smoke test failed — container stayed running ${SMOKE_DURATION_MS/1000}s but never served HTTP on :80 (last curl: ${lastCurlErr || 'no response'}). ` +
        `Most likely the app is bound to a different port — install_script passes PORT=80 env, so the app should read process.env.PORT (Node) or os.environ['PORT'] (Python). ` +
        `Last 40 log lines:\n${logs}`
      );
      err.code = 'VULN_APP_SMOKE_FAILED';
      throw err;
    }

    console.log(`${logTag} ✓ Smoke test passed — container stayed running ${SMOKE_DURATION_MS/1000}s and served HTTP on :80`);
  } finally {
    try {
      await runShell(`docker rm -f ${shellQuote(containerName)} 2>/dev/null`, {
        label: 'docker rm smoke', timeoutMs: 10000
      });
    } catch (_) {}
  }
}

// ─── Public: ensure a docker-mode vuln-app has a prebuilt, servable image ────
/**
 * Build the image on the orchestrator if possible and attach a `prebuilt`
 * descriptor to the vulnAppInstall. On any failure (no Docker, build error)
 * returns the input unchanged so the deploy falls back to the legacy on-VM
 * build path. Only docker-mode installs are built here.
 *
 * @param {object} vulnAppInstall   spec.vuln_app_install ({ mode, source_tree, dockerfile, ... })
 * @param {object} [opts]
 * @param {string} [opts.logTag]
 * @returns {Promise<object>} the same object, possibly with .prebuilt = { token, imageTag, url }
 */
async function ensureVulnImage(vulnAppInstall, { logTag = '[CIAB VulnBuild]' } = {}) {
  if (!vulnAppInstall || vulnAppInstall.mode !== 'docker') return vulnAppInstall;
  // Don't retry a build we already know will fail with the same source. Set
  // by the prebuild path's catch (lane-deploy.js:1556) when smoke fails, so
  // the per-lane retry safety net at lane-deploy.js:1179 skips a second
  // doomed build attempt.
  if (vulnAppInstall._smokeFailed) {
    console.warn(`${logTag} skipping rebuild — earlier smoke test failed (source unchanged)`);
    return vulnAppInstall;
  }
  if (vulnAppInstall.prebuilt && vulnAppInstall.prebuilt.token) {
    // Already built — confirm the file still exists (TTL/restart safety).
    const entry = _registry.get(vulnAppInstall.prebuilt.token);
    if (entry && fs.existsSync(entry.filePath)) return vulnAppInstall;
  }
  if (!vulnAppInstall.dockerfile) {
    console.warn(`${logTag} docker-mode vuln app has no Dockerfile — cannot pre-build on orchestrator, using on-VM path`);
    return vulnAppInstall;
  }
  if (!(await dockerAvailable())) return vulnAppInstall;

  // Auto-repair package.json BEFORE building — adds runtime modules the LLM
  // forgot to declare in `dependencies`. Mutates vulnAppInstall.source_tree
  // in place, so both this build path AND any subsequent on-VM fallback see
  // the repaired manifest.
  repairNodeSourceTree(vulnAppInstall.source_tree, logTag);

  // Inject professional base CSS + <link> tags into every HTML/EJS file.
  // Themed from the concept's color_palette so each company gets its own
  // brand identity while the LAYOUT stays consistent and professional.
  // The LLM's own styles still load AFTER and can layer custom touches.
  injectBaseStyles(vulnAppInstall.source_tree, vulnAppInstall.color_palette, logTag);

  // Static check: every relative require/import must point to a file the LLM
  // actually generated. Catches Stage-2-parallel-generation skew where one
  // file references another that was never produced. Faster than waiting for
  // the smoke test and gives a more actionable error.
  const missing = detectMissingRelativeImports(vulnAppInstall.source_tree, logTag);
  if (missing.length > 0) {
    const summary = missing.map(m => `${m.from} → '${m.spec}'`).join('; ');
    const err = new Error(
      `vuln-app source incomplete — ${missing.length} relative import(s) point to ungenerated files: ${summary}`
    );
    err.code = 'VULN_APP_SMOKE_FAILED';
    err.missingFiles = missing;
    vulnAppInstall._smokeFailed = true;
    throw err;
  }

  try {
    const built = await buildAndPackage({
      sourceTree: vulnAppInstall.source_tree,
      dockerfile: vulnAppInstall.dockerfile,
      logTag
    });
    return {
      ...vulnAppInstall,
      prebuilt: { token: built.token, imageTag: built.imageTag, url: built.url }
    };
  } catch (err) {
    if (err.code === 'VULN_APP_SMOKE_FAILED') {
      // Image built but the app crashes on startup. Manifest auto-repair
      // already ran, so if it still fails, the bug is in the app source
      // itself (syntax error, bad CMD, etc.) — re-running with identical
      // input gets the same result. Mark so per-lane retry skips.
      console.warn(`${logTag} ${err.message.split('\n')[0]}`);
      console.warn(`${logTag} Smoke logs:\n${err.message.split('\n').slice(1).join('\n')}`);
      vulnAppInstall._smokeFailed = true;
      throw err;
    }
    console.warn(`${logTag} Orchestrator image build failed (${err.message.slice(0, 160)}) — falling back to on-VM build`);
    return vulnAppInstall;
  }
}

// ─── Public: route resolver ──────────────────────────────────────────────────
/**
 * Look up a servable image by token. Returns { filePath, imageTag } or null.
 * Touches the entry's TTL on a hit so an in-progress group keeps its image
 * alive even past the original window.
 */
function resolveImageFile(token) {
  sweep();
  const entry = _registry.get(token);
  if (!entry) return null;
  if (!fs.existsSync(entry.filePath)) { _registry.delete(token); return null; }
  entry.expiresAt = Date.now() + IMAGE_TTL_MS;   // keep alive while in use
  return { filePath: entry.filePath, imageTag: entry.imageTag };
}

/** Delete a built image (best-effort) — call on group teardown. */
function releaseImage(token) {
  const entry = _registry.get(token);
  if (!entry) return;
  try { fs.rmSync(entry.filePath, { force: true }); } catch (_) {}
  _registry.delete(token);
  if (_byHash.get(entry.hash) === token) _byHash.delete(entry.hash);
}

module.exports = {
  ensureVulnImage,
  resolveImageFile,
  releaseImage,
  // exported for reuse by the AI pipeline's self-healing retry pass and for testing
  detectMissingRelativeImports,
  repairNodeSourceTree,
  buildAndPackage,
  dockerAvailable,
  hashBundle,
  LANE_ORCH_URL
};
