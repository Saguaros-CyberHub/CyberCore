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
 * Build engine: the `kaniko` executor binary (baked into the app image via
 * multi-stage COPY — see ../Dockerfile). Daemonless: no `docker` CLI, no
 * `/var/run/docker.sock` mount, no host-VM escape path from a malicious
 * Dockerfile RUN step. RUN steps still execute with this container's
 * privileges, so this is not a hard sandbox — but it removes the worst
 * pivot. If kaniko isn't available, ensureVulnImage() falls back silently
 * and the deploy uses the legacy on-VM build path.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

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
// Path to the kaniko executor. Baked in by the Dockerfile multi-stage copy.
const KANIKO_EXECUTOR = process.env.KANIKO_EXECUTOR || '/kaniko/executor';

// token → { filePath, imageTag, hash, expiresAt }
const _registry = new Map();
// hash → token   (dedupe identical bundles within TTL so a group builds once
// and per-lane retries reuse the same image instead of rebuilding)
const _byHash = new Map();

let _builderAvailable = null;   // cached probe result

// ─── Shell helper ───────────────────────────────────────────────────────────
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
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${label} exited ${code}: ${(stderr || stdout).slice(-600)}`));
    });
  });
}

async function builderAvailable() {
  if (_builderAvailable !== null) return _builderAvailable;
  try {
    // kaniko doesn't expose a clean --version on every release; existence +
    // executable bit is enough to decide whether to use it. Falls back to the
    // on-VM build path when missing (local dev without the kaniko-bearing image).
    await runShell(`test -x ${shellQuote(KANIKO_EXECUTOR)}`, { timeoutMs: 5000, label: 'kaniko probe' });
    _builderAvailable = true;
  } catch (err) {
    console.warn(`[CIAB VulnBuild] Kaniko not available at ${KANIKO_EXECUTOR} (${err.message.slice(0, 120)}) — lane-side build fallback will be used`);
    _builderAvailable = false;
  }
  return _builderAvailable;
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

    // Build with kaniko: daemonless, no /var/run/docker.sock. Writes a
    // Docker-loadable tarball via --tar-path. --no-push skips registry I/O
    // entirely (we serve the tar over HTTP — no registry in the loop).
    // --cache=false because kaniko's layer cache wants a registry to back it;
    // we dedupe at the builder level via content hash instead.
    // --destination names the image inside the tar so the lane's
    // `docker load && docker run <tag>` finds it.
    const tarFile = path.join(BUILD_DIR, `${token}.tar`);
    console.log(`${logTag} Building image ${imageTag} via kaniko (context ${ctxDir})`);
    await runShell(
      `${shellQuote(KANIKO_EXECUTOR)} ` +
      `--dockerfile=${shellQuote(path.join(ctxDir, 'Dockerfile'))} ` +
      `--context=${shellQuote('dir://' + ctxDir)} ` +
      `--destination=${shellQuote(imageTag)} ` +
      `--tar-path=${shellQuote(tarFile)} ` +
      `--no-push --cache=false --verbosity=warn`,
      { label: `kaniko build ${imageTag}` }
    );

    // gzip the tar in place. `docker load` on the lane VM accepts the gzipped
    // form transparently. The intermediate uncompressed tar is discarded.
    console.log(`${logTag} Compressing ${tarFile} → ${outFile}`);
    await runShell(
      `gzip -c ${shellQuote(tarFile)} > ${shellQuote(outFile)} && rm -f ${shellQuote(tarFile)}`,
      { label: 'gzip image' }
    );

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
  if (vulnAppInstall.prebuilt && vulnAppInstall.prebuilt.token) {
    // Already built — confirm the file still exists (TTL/restart safety).
    const entry = _registry.get(vulnAppInstall.prebuilt.token);
    if (entry && fs.existsSync(entry.filePath)) return vulnAppInstall;
  }
  if (!vulnAppInstall.dockerfile) {
    console.warn(`${logTag} docker-mode vuln app has no Dockerfile — cannot pre-build on orchestrator, using on-VM path`);
    return vulnAppInstall;
  }
  if (!(await builderAvailable())) return vulnAppInstall;

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
  // exported for testing
  buildAndPackage,
  builderAvailable,
  hashBundle,
  LANE_ORCH_URL
};
