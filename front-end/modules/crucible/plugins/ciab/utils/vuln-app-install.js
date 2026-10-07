/**
 * ============================================================================
 * CIAB VULN-APP INSTALLER  (quarantine)
 * ----------------------------------------------------------------------------
 * The one part of CIAB's private deploy sequence that is genuinely CIAB-only:
 * pushing a generated vulnerable web app into a lane VM and starting it.
 *
 * Lifted out of ciab/utils/lane-deploy.js unchanged so that file can be deleted
 * (Track A7) without taking this with it. Everything else in lane-deploy.js was
 * a drifted re-implementation of src/utils/challenge-lane-deployer.js; this was
 * not, because nothing else on the platform installs an LLM-generated app.
 *
 * WHY THIS IS QUARANTINED RATHER THAN BLESSED
 * -------------------------------------------
 * `writeFileViaShellExec` base64-encodes a file and ships it through
 * `agentShellExec` in 48KB chunks instead of just calling
 * script-executor.guestFileWrite. That is a WORKAROUND, not a design:
 * guestFileWrite goes through proxmoxAPI's form-urlencoded serialization, which
 * returns HTTP 596 (pveproxy's 3-second backend timeout) on PVE 9.1.9. The same
 * request via curl returns 200 in ~200ms. Root-causing that is a separate
 * investigation and is deliberately NOT part of Track A; when it is fixed, this
 * whole file collapses to a guestFileWrite loop.
 *
 * Do not copy this pattern into new code. If you need to put a file in a guest,
 * call guestFileWrite and let it fail loudly, so the real bug keeps a reason to
 * get fixed.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT CARRY
 * ------------------------------------------
 * lane-deploy.js also held private copies of `proxmoxFormPOST`,
 * `agentShellExec` and `waitForAgentExecReady`. Those are NOT CIAB-only — the
 * identical implementations already live in src/utils/script-executor.js and
 * are what cle/utils/attack-runner.js and src/utils/flag-manager.js call. They
 * are imported below rather than moved, so this extraction removes a duplicate
 * instead of relocating one. (The shared `waitForAgentExecReady` differs only
 * in taking a default logTag argument and omitting one checkmark in a log line.)
 *
 * KNOWN DIVERGENCE, PRESERVED ON PURPOSE
 * --------------------------------------
 * `writeFileViaShellExec` does NOT poll each chunk to completion, while the
 * shared `executeShellViaFile` does (its runShell awaits pollExecStatus after
 * every call). So a large file's appends are fired without confirming the
 * previous one landed. That is how it has always run here and is left exactly
 * as it was — this phase is a move, not a fix — but it belongs to the same
 * investigation as the 596 above.
 * ============================================================================
 */

const {
  agentShellExec,
  pollExecStatus,
} = require('../../../../../src/utils/script-executor');

// ─── SSH-based vuln-app installer ──────────────────────────────────────────
// Sidesteps the chronically-flaky Proxmox /agent/exec endpoint (596 spam on
// any command after the first probe) by running the install via SSH instead.
// Requires the orchestrator to have IP reachability to the lane VM — works
// if the orchestrator host is on Tailscale (which has subnet routing for the
// lane via the gateway), or has a static route to 10.40.x.x.
//
// Uses sshpass for the bake-template's default 'web/bake-debug' credentials.
// (sshpass must be installed in the orchestrator container — add to Dockerfile.)
async function installVulnAppViaSSH({ node, vmId, vmName, vmIp, vulnAppInstall, logTag }) {
  if (!vulnAppInstall) return { success: true, skipped: true };
  if (!vmIp) return { success: false, error: 'no VM IP — cannot SSH' };
  const { mode, install_script, source_tree, dockerfile } = vulnAppInstall;
  const targetDir = mode === 'docker' ? '/opt/vuln-app' : '/var/www/html';
  console.log(`${logTag} Installing vuln app via SSH on ${vmName} (${vmIp}, mode=${mode}, dir=${targetDir})`);

  const fs = require('fs');
  const path = require('path');
  const { spawn } = require('child_process');

  const tmpDir = fs.mkdtempSync(`/tmp/ciab-vuln-${vmId}-`);
  try {
    // Materialize the bundle on disk so we can scp it
    fs.mkdirSync(path.join(tmpDir, 'files'), { recursive: true });
    if (source_tree && typeof source_tree === 'object') {
      for (const [relPath, content] of Object.entries(source_tree)) {
        const safe = relPath.replace(/\.\./g, '_').replace(/^\/+/, '');
        const full = path.join(tmpDir, 'files', safe);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content);
      }
    }
    if (dockerfile && mode === 'docker') {
      fs.writeFileSync(path.join(tmpDir, 'files', 'Dockerfile'), dockerfile);
    }
    fs.writeFileSync(path.join(tmpDir, 'install.sh'), install_script || '');

    // Tar the bundle so a single scp gets everything
    await runCommand('tar', ['czf', path.join(tmpDir, 'bundle.tar.gz'), '-C', tmpDir, 'install.sh', 'files']);

    const sshOpts = ['-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=10','-o','LogLevel=ERROR'];
    const sshpass = ['-p','bake-debug'];

    // 1. scp bundle to the VM
    await runCommand('sshpass', [...sshpass, 'scp', ...sshOpts,
      path.join(tmpDir, 'bundle.tar.gz'), `web@${vmIp}:/tmp/ciab-bundle.tar.gz`]);

    // 2. SSH in and install
    const remoteCmd = `set -e
sudo mkdir -p ${targetDir}
cd /tmp && rm -rf ciab-extract && mkdir ciab-extract && tar xzf ciab-bundle.tar.gz -C ciab-extract
sudo cp -rT ciab-extract/files/ ${targetDir}/
sudo chmod +x /tmp/ciab-extract/install.sh
sudo bash /tmp/ciab-extract/install.sh
echo "[ciab] install complete"
`;
    await runCommand('sshpass', [...sshpass, 'ssh', ...sshOpts, `web@${vmIp}`, remoteCmd]);

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
  }
}

function runCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    const child = require('child_process').spawn(cmd, args, { stdio: ['ignore','pipe','pipe'] });
    let stderr = '';
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} exited ${code}: ${stderr.slice(0, 500)}`));
    });
  });
}

// ─── File write via curl-based agent exec (bypasses broken guestFileWrite) ─
// The shared script-executor.js guestFileWrite uses proxmoxAPI's form-urlencoded
// serialization, which 596s on PVE 9.1.9. We bypass it entirely by base64-
// encoding the content and shipping it through a single `agentShellExec` call
// that does `base64 -d > file`. For >50KB files we chunk via append (>>) to
// avoid agent argv / Proxmox API body size limits.
async function writeFileViaShellExec({ node, vmId, fullPath, content, logTag }) {
  const buf = Buffer.from(content, 'utf8');
  const b64 = buf.toString('base64');
  const CHUNK = 48 * 1024;   // 48KB of base64 per agent call (~36KB binary)

  // Ensure parent dir exists, then truncate the file
  const dir = fullPath.replace(/\/[^/]+$/, '') || '/';
  await agentShellExec(node, vmId, `mkdir -p '${dir}' && : > '${fullPath}'`);

  if (b64.length <= CHUNK) {
    // Single-shot: echo base64 → decode → file
    await agentShellExec(node, vmId, `echo '${b64}' | base64 -d > '${fullPath}'`);
  } else {
    // Chunked: append each piece, decode at end into a different file, then mv
    const tmpPath = `${fullPath}.b64`;
    await agentShellExec(node, vmId, `: > '${tmpPath}'`);
    for (let i = 0; i < b64.length; i += CHUNK) {
      const piece = b64.slice(i, i + CHUNK);
      await agentShellExec(node, vmId, `printf %s '${piece}' >> '${tmpPath}'`);
    }
    await agentShellExec(node, vmId, `base64 -d < '${tmpPath}' > '${fullPath}' && rm -f '${tmpPath}'`);
  }
}

// ─── Vuln-app installer execution ──────────────────────────────────────────
// Writes source_tree files via QEMU guest agent, then runs install_script.
// Rewrite Dockerfile FROM lines to use a base image we've pre-baked into
// the web template. The LLM is told to only use these in the prompt, but
// regularly ignores it (emits node:16-slim, node:20-slim, etc.). Lane has
// no UDP-53 egress and unreliable DNS for pulls, so non-cached bases break.
const CACHED_BASES = {
  // Map "language hint" → cached image. First match wins.
  node:    'node:20-alpine',
  python:  'python:3-slim',
  php:     'php:8.2-apache',
  nginx:   'nginx:alpine',
  ruby:    'ruby:3-alpine'
};
function rewriteDockerfileBases(dockerfile, logTag) {
  if (!dockerfile) return dockerfile;
  const allowed = new Set(Object.values(CACHED_BASES));
  return dockerfile.replace(/^(FROM\s+)(\S+)(.*)$/gim, (line, prefix, image, suffix) => {
    if (allowed.has(image)) return line;   // already OK
    // Detect language from the image name
    for (const [lang, cached] of Object.entries(CACHED_BASES)) {
      if (image.toLowerCase().startsWith(lang)) {
        console.log(`${logTag} Rewriting Dockerfile FROM ${image} → ${cached} (LLM picked non-cached base)`);
        return `${prefix}${cached}${suffix}`;
      }
    }
    // Unknown image — default to node:20-alpine since most LLM-generated apps are Node
    console.log(`${logTag} Rewriting Dockerfile FROM ${image} → node:20-alpine (unknown base, defaulting to node)`);
    return `${prefix}node:20-alpine${suffix}`;
  });
}

// Build the small install script the lane runs when the image was prebuilt on
// the orchestrator: pull the gzip'd image over HTTP, docker load, run it. No
// build, no registry pulls, no base64 source transfer — the heavy blob comes
// down one HTTP stream the guest agent never touches.
function buildPrebuiltInstallScript({ url, imageTag }) {
  return [
    'set -e',
    `echo "[ciab] pulling prebuilt image from ${url}"`,
    // Web template may ship curl OR wget, not necessarily both — try each.
    'if command -v curl >/dev/null 2>&1; then',
    `  curl -fsSL "${url}" -o /tmp/vuln-app.tar.gz || { echo "[ciab] image pull failed (curl)"; exit 11; }`,
    'elif command -v wget >/dev/null 2>&1; then',
    `  wget -q -O /tmp/vuln-app.tar.gz "${url}" || { echo "[ciab] image pull failed (wget)"; exit 11; }`,
    'else',
    '  echo "[ciab] no curl or wget on host"; exit 12',
    'fi',
    'echo "[ciab] loading image"',
    'docker load -i /tmp/vuln-app.tar.gz',
    'docker rm -f vuln-app 2>/dev/null || true',
    // Debian web template ships apache2 enabled+running on :80; on some images
    // nginx is similarly active. Either binds the host port and makes the
    // subsequent `docker run -p 80:80` fail with exit 125 "address already in
    // use". Stop+disable both before launching the container so reboots stick.
    'for svc in apache2 nginx; do',
    '  systemctl stop "$svc" 2>/dev/null || service "$svc" stop 2>/dev/null || true',
    '  systemctl disable "$svc" 2>/dev/null || true',
    'done',
    // Start with PORT=80 env var so well-behaved apps bind to 80.
    // Then detect the actual listening port inside the container and remap
    // the host binding to 80:<actual_port> so Kali can always reach it on :80.
    `docker run -d --restart=always --name vuln-app -e PORT=80 -p 80:80 ${shellQuoteArg(imageTag)}`,
    'sleep 3',
    // Detect what port the app actually bound to inside the container.
    // ss/netstat shows LISTEN sockets; pick the lowest non-22 TCP port.
    'ACTUAL_PORT=$(docker exec vuln-app sh -c \'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null\' | awk \'/LISTEN/{print $4}\' | grep -oE \'[0-9]+$\' | grep -v \'^22$\' | sort -n | head -1)',
    // If app is NOT on 80, recreate the container with the correct mapping.
    'if [ -n "$ACTUAL_PORT" ] && [ "$ACTUAL_PORT" != "80" ]; then',
    '  echo "[ciab] vuln-app bound to port $ACTUAL_PORT, remapping 80->$ACTUAL_PORT"',
    `  docker rm -f vuln-app`,
    `  docker run -d --restart=always --name vuln-app -e PORT=80 -p 80:$ACTUAL_PORT ${shellQuoteArg(imageTag)}`,
    'fi',
    'rm -f /tmp/vuln-app.tar.gz',
    'echo "[ciab] vuln-app running"'
  ].join('\n');
}

function shellQuoteArg(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

async function installVulnAppOnVM({ node, vmId, vmName, vulnAppInstall, logTag }) {
  if (!vulnAppInstall) return { success: true, skipped: true };
  const { mode } = vulnAppInstall;
  const prebuilt = vulnAppInstall.prebuilt;

  // Hard skip: the orchestrator-side smoke test already proved this app
  // crashes (or can't bind :80, or has missing files). On-VM build runs the
  // SAME source against the SAME Dockerfile from a less-capable environment
  // (no internet through lane perimeter for some package mirrors, brittle
  // apt-get inside the lane web VM). It has never worked in this session
  // and produces noisy install_script exit-100 failures that confuse the
  // operator. Skip it — admin needs to regenerate the vuln-app instead.
  if (vulnAppInstall._smokeFailed) {
    console.warn(`${logTag} Vuln-app skipped on ${vmName}: orchestrator smoke test failed earlier in this deploy. ` +
      `On-VM build is intentionally not attempted (it would hit the same crash). ` +
      `Redeploy this lane to trigger a fresh LLM generation, or pick a different difficulty.`);
    return { success: false, skipped: true, error: 'vuln-app smoke test failed; on-VM fallback disabled' };
  }

  let source_tree, dockerfile, install_script;
  if (prebuilt && prebuilt.token) {
    // Orchestrator already built + saved the image. Nothing to write to the VM
    // — just pull/load/run. Skip source_tree + Dockerfile materialization.
    source_tree = null;
    dockerfile = null;
    install_script = buildPrebuiltInstallScript(prebuilt);
    console.log(`${logTag} Using prebuilt image ${prebuilt.imageTag} (pull from ${prebuilt.url}) — skipping on-VM build`);
  } else if (!prebuilt) {
    // No prebuilt image AND smoke didn't explicitly fail — usually means
    // Docker was unreachable on the orchestrator or the LLM didn't produce
    // a Dockerfile. Same reasoning applies: the on-VM build path is known
    // unreliable; better to fail loud than fail late in install_script.
    console.warn(`${logTag} Vuln-app skipped on ${vmName}: no prebuilt image and on-VM fallback is disabled. ` +
      `Check the earlier "Orchestrator image build failed" log line for the root cause.`);
    return { success: false, skipped: true, error: 'no prebuilt image; on-VM fallback disabled' };
  } else {
    // Legacy on-VM build path. Rewrite Dockerfile base to a cached image
    // BEFORE writing it, and force `docker build` to use --network=host so RUN
    // steps (apk/apt) can resolve DNS via the host's resolver. Lane subnet
    // blocks outbound UDP 53 for containers, but host DNS via lane gateway →
    // OPNsense works on TCP.
    source_tree = vulnAppInstall.source_tree;
    dockerfile = rewriteDockerfileBases(vulnAppInstall.dockerfile, logTag);
    install_script = vulnAppInstall.install_script || '';
    if (install_script.includes('docker build') && !install_script.includes('--network=host')) {
      install_script = install_script.replace(/docker\s+build\b/g, 'docker build --network=host');
      console.log(`${logTag} Patched install_script: added --network=host to docker build (lane has no container DNS)`);
    }
  }

  const targetDir = mode === 'docker' ? '/opt/vuln-app' : '/var/www/html';
  console.log(`${logTag} Installing vuln app on ${vmName} (mode=${mode}, dir=${targetDir})`);

  try {
    console.log(`${logTag} [install:step1] mkdir ${targetDir}`);
    await agentShellExec(node, vmId, `mkdir -p ${targetDir}`);
    console.log(`${logTag} [install:step1] ✓ mkdir done`);

    if (source_tree && typeof source_tree === 'object') {
      const fileCount = Object.keys(source_tree).length;
      console.log(`${logTag} [install:step2] writing ${fileCount} source_tree file(s) via curl-based shell writes`);
      let i = 0;
      for (const [relPath, content] of Object.entries(source_tree)) {
        i++;
        const safePath = relPath.replace(/\.\./g, '').replace(/^\/+/, '');
        const fullPath = `${targetDir}/${safePath}`;
        // BYPASS the shared script-executor.js guestFileWrite — it uses the
        // broken proxmoxAPI (form-urlencoded) which 596s. Use base64+exec via
        // our working curl-based agentShellExec instead. Handles arbitrary
        // binary safely. Files >100KB get chunked at 64KB to stay under any
        // command-line / agent argv size limits.
        console.log(`${logTag} [install:step2] ${i}/${fileCount} ${fullPath} (${content.length} bytes)`);
        await writeFileViaShellExec({ node, vmId, fullPath, content, logTag });
      }
      console.log(`${logTag} [install:step2] ✓ source_tree written`);
    }
    if (dockerfile && mode === 'docker') {
      console.log(`${logTag} [install:step3] writing Dockerfile (${dockerfile.length} bytes)`);
      await writeFileViaShellExec({ node, vmId, fullPath: `${targetDir}/Dockerfile`, content: dockerfile, logTag });
      console.log(`${logTag} [install:step3] ✓ Dockerfile written`);
    }

    // Run install_script inline via sh on stdin → poll until exit
    console.log(`${logTag} [install:step4] running install_script (${(install_script||'').length} bytes)`);
    const exec = await agentShellExec(node, vmId, install_script);
    const pid = exec && (exec.pid || (exec.result && exec.result.pid));
    if (pid) {
      console.log(`${logTag} [install:step4] install_script pid=${pid}, polling for completion...`);
      const result = await pollExecStatus(node, vmId, pid, 15 * 60 * 1000);
      // PVE 9.x returns `exitcode` (no hyphen); older versions / docs used
      // `exit-code`. Accept both. Same for err-data / err vs stderr.
      const exitCode = result?.exitcode ?? result?.['exit-code'];
      const stderr = result?.['err-data'] ?? result?.err ?? null;
      const stdout = result?.['out-data'] ?? result?.out ?? null;
      if (exitCode !== 0 && exitCode !== undefined) {
        console.warn(`${logTag} [install:step4] ✗ install_script exited ${exitCode}`);
        // Surface the script's actual stderr + last lines of stdout to the
        // orchestrator log. Without this we can see "exited 100" but not
        // WHY (apt failure, docker daemon down, etc.) — which means the
        // user has to ssh into the lane VM to diagnose. Most install_script
        // outputs are short (<10KB); we cap at 4KB to bound log size.
        const tailStderr = stderr ? String(stderr).slice(-4000) : null;
        const tailStdout = stdout ? String(stdout).slice(-1500) : null;
        if (tailStderr) console.warn(`${logTag} [install:step4] stderr:\n${tailStderr}`);
        if (tailStdout) console.warn(`${logTag} [install:step4] stdout (tail):\n${tailStdout}`);
        return { success: false, error: `install_script exited ${exitCode}`, stderr };
      }
      if (exitCode === undefined) {
        // pollExecStatus returned but no exit code field — likely timed out
        // before the agent flushed final status. Log loudly but don't fail
        // the deploy; if the script actually ran (it usually did), the app
        // is up.
        console.warn(`${logTag} [install:step4] ⚠ install_script status had no exit-code field — assuming success. Raw status: ${JSON.stringify(result || {}).slice(0, 200)}`);
      } else {
        console.log(`${logTag} [install:step4] ✓ install_script completed (exit ${exitCode})`);
      }
    }
    return { success: true };
  } catch (err) {
    console.warn(`${logTag} [install:CAUGHT] ${err.message}`);
    return { success: false, error: err.message };
  }
}

module.exports = {
  // The entry point lane-deploy.js calls per web VM.
  installVulnAppOnVM,
  // Currently unreferenced. Kept because it is the only non-guest-agent route
  // into a lane VM we have, and the obvious fallback if the 596 above ever
  // turns out to be unfixable. Needs sshpass in the orchestrator image and IP
  // reachability into the lane.
  installVulnAppViaSSH,
  // Pure, so they are testable without a cluster.
  rewriteDockerfileBases,
  buildPrebuiltInstallScript,
  shellQuoteArg,
  // Exported for the eventual guestFileWrite migration: whatever replaces this
  // has to be swapped in at one call site, not many.
  writeFileViaShellExec,
};
