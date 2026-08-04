/**
 * ============================================================================
 * Proxmox node SSH helpers — for operations that have no HTTPS API equivalent
 * ============================================================================
 *
 * The Proxmox HTTPS API covers VM/LXC lifecycle, storage, SDN, networks,
 * cluster ops, and (for QEMU only) guest-agent exec. For LXC containers
 * there is no `/exec` API endpoint — to run commands inside an LXC you must
 * SSH into the Proxmox node and use `pct exec`. Same for `pct push`.
 *
 * This module wraps that pattern using the `ssh` and `scp` CLIs (no npm
 * dependency). The host running this Node app needs:
 *
 *   1. The `ssh` and `scp` clients on PATH (standard openssh-client).
 *   2. A passwordless SSH key set up to the Proxmox nodes as a user with
 *      privileges to run `pct exec` (typically root).
 *
 * Configure via env:
 *
 *   PROXMOX_SSH_USER  — SSH user on Proxmox nodes (default: root)
 *   PROXMOX_SSH_KEY   — path to the private key (default: ~/.ssh/id_ed25519)
 *
 * Usage:
 *
 *   const { pctExec, pctPush } = require('./node-ssh');
 *   const out = await pctExec('cyberhub-node-3', 110120, ['ls', '/etc']);
 *   await pctPush('cyberhub-node-3', 110120, '/local/file', '/inside/lxc/file');
 *
 * Errors throw with stderr included so callers can log usefully.
 * ============================================================================
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const { getNodeAddress } = require('./site-config');

const SSH_USER = process.env.PROXMOX_SSH_USER || 'root';
const SSH_KEY  = process.env.PROXMOX_SSH_KEY  || path.join(os.homedir(), '.ssh', 'id_ed25519');

/**
 * The address to actually open a socket to for a Proxmox node.
 *
 * Proxmox names its nodes ('cyberhub-node-2') and every caller here passes that
 * name straight through from the API. In the container those names do not
 * resolve — its resolvers are 1.1.1.1 and the lab DNS, and neither serves the
 * cluster's node records, so ssh fails with "Could not resolve hostname" before
 * it ever reaches the key. site.json already carries the name → IP map, so use
 * it and fall back to the bare name for anything not declared there (a
 * single-node dev box where the name IS resolvable).
 */
function nodeAddress(node) {
  try {
    return getNodeAddress(node) || node;
  } catch (_) {
    return node;    // site.json unreadable — let ssh try the name and report it
  }
}

/**
 * One-line preflight so a misconfigured SSH channel reports the actual cause.
 * Without it the failure surfaces as ssh's own "Identity file ... not
 * accessible" warning buried in stderr, alongside a non-zero exit that reads
 * like a remote problem.
 */
function assertKeyReadable() {
  try {
    fs.accessSync(SSH_KEY, fs.constants.R_OK);
  } catch (_) {
    throw new Error(
      `SSH key '${SSH_KEY}' is missing or unreadable — the orchestrator cannot run ` +
      `commands on cluster nodes. Set PROXMOX_SSH_KEY to a key mounted into the ` +
      `container, and PROXMOX_SSH_USER if it is not '${SSH_USER}'.`
    );
  }
}

const SSH_FLAGS = [
  '-i', SSH_KEY,
  '-o', 'StrictHostKeyChecking=no',
  '-o', 'UserKnownHostsFile=/dev/null',
  '-o', 'BatchMode=yes',
  '-o', 'ConnectTimeout=10',
  '-o', 'ServerAliveInterval=30'
];

/**
 * Run a command via ssh on a Proxmox node. Returns { stdout, stderr, code }.
 * Throws on non-zero exit (so callers can use try/catch). Pass timeoutMs to
 * abort runaway commands; default 5 minutes.
 */
function nodeExec(node, args, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000;
  return new Promise((resolve, reject) => {
    try { assertKeyReadable(); } catch (e) { return reject(e); }
    const cmd = ['ssh', ...SSH_FLAGS, `${SSH_USER}@${nodeAddress(node)}`, '--', ...args];
    const child = spawn(cmd[0], cmd.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let killed = false;
    const t = setTimeout(() => { killed = true; child.kill('SIGKILL'); }, timeoutMs);

    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });
    child.on('error', err => { clearTimeout(t); reject(err); });
    child.on('close', code => {
      clearTimeout(t);
      if (killed) return reject(new Error(`nodeExec timed out after ${timeoutMs}ms on ${node}: ${args.join(' ')}`));
      if (code !== 0) {
        const e = new Error(`nodeExec exit ${code} on ${node}: ${args.join(' ')}\nstderr: ${stderr.trim()}\nstdout: ${stdout.trim()}`);
        e.code = code; e.stdout = stdout; e.stderr = stderr;
        return reject(e);
      }
      resolve({ stdout, stderr, code });
    });
  });
}

/**
 * Run a command inside an LXC via `pct exec`.
 *   pctExec('cyberhub-node-3', 110120, ['/bin/sh', '-c', 'echo hi'])
 * The LXC must be running. Stdin is closed; for stdin-fed commands use
 * pctExecWithStdin().
 */
function pctExec(node, vmid, args, opts = {}) {
  return nodeExec(node, ['pct', 'exec', String(vmid), '--', ...args], opts);
}

/**
 * Run a command inside an LXC with a stdin payload. Used for writing files
 * via heredoc-style: pctExecWithStdin(node, vmid, ['tee', '/etc/foo.conf'], 'file contents').
 */
function pctExecWithStdin(node, vmid, args, stdinData, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000;
  return new Promise((resolve, reject) => {
    try { assertKeyReadable(); } catch (e) { return reject(e); }
    const cmd = ['ssh', ...SSH_FLAGS, `${SSH_USER}@${nodeAddress(node)}`, '--',
                 'pct', 'exec', String(vmid), '--', ...args];
    const child = spawn(cmd[0], cmd.slice(1), { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let killed = false;
    const t = setTimeout(() => { killed = true; child.kill('SIGKILL'); }, timeoutMs);

    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });
    child.on('error', err => { clearTimeout(t); reject(err); });
    child.on('close', code => {
      clearTimeout(t);
      if (killed) return reject(new Error(`pctExecWithStdin timed out after ${timeoutMs}ms on ${node}/${vmid}`));
      if (code !== 0) {
        const e = new Error(`pctExecWithStdin exit ${code} on ${node}/${vmid}: ${args.join(' ')}\nstderr: ${stderr.trim()}`);
        e.code = code; e.stdout = stdout; e.stderr = stderr;
        return reject(e);
      }
      resolve({ stdout, stderr, code });
    });

    if (stdinData != null) child.stdin.write(stdinData);
    child.stdin.end();
  });
}

/**
 * Push a local file into an LXC's filesystem via `pct push`. The local file
 * must be on the same Proxmox node where the LXC runs. For files originating
 * on the orchestrator host (this Node app), this is two-step:
 *   1. scp from app host to node:/tmp/...
 *   2. pct push from node:/tmp/... to LXC:/...
 *
 * pctPushFromString writes the inline content directly via pctExecWithStdin
 * (no host-side temp file). Use that for small (<1MB) text payloads.
 */
async function pctPushFromString(node, vmid, content, destPath, opts = {}) {
  // Ensure destination directory exists, then tee the content in.
  const dir = destPath.substring(0, destPath.lastIndexOf('/')) || '/';
  await pctExec(node, vmid, ['/bin/sh', '-c', `mkdir -p ${dir}`], opts);
  await pctExecWithStdin(node, vmid,
    ['/bin/sh', '-c', `cat > ${destPath}`],
    content,
    opts);
}

module.exports = {
  nodeExec,
  pctExec,
  pctExecWithStdin,
  pctPushFromString,
  SSH_USER,
  SSH_KEY
};
