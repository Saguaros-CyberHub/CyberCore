/**
 * ============================================================================
 * PROXMOX API HELPER
 * Shared utility for communicating with the Proxmox VE API
 * ============================================================================
 */

const { getClusterNodes } = require('./site-config');
// Pure path builder, deliberately in its own module — see vm-paths.js for why.
const { vmApiBase } = require('./vm-paths');

const PROXMOX_URL = process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006';
const PROXMOX_TOKEN_ID = process.env.PROXMOX_TOKEN_ID || 'root@pam!clinic-app-token';
const PROXMOX_TOKEN_SECRET = process.env.PROXMOX_TOKEN_SECRET || '';

/**
 * Default socket-inactivity deadline for one Proxmox call.
 *
 * NOTE this is an INACTIVITY timeout, not a wall-clock deadline: a response
 * that trickles bytes resets it indefinitely. Callers that need a hard ceiling
 * (the reconcile scan does — Cloudflare kills the request at 100s) must pass an
 * AbortSignal as well, not instead.
 */
const DEFAULT_TIMEOUT_MS = Number(process.env.PROXMOX_HTTP_TIMEOUT_MS) || 30000;

function proxmoxTimeoutError(method, pathname, ms) {
  const err = new Error(`Proxmox ${method} ${pathname} timed out after ${Math.round(ms / 1000)}s`);
  // Tagged so a retrying caller can skip it. A call that ran out its deadline
  // will run out the same deadline again; a refused one usually will not.
  err.code = 'PROXMOX_TIMEOUT';
  return err;
}

function proxmoxAbortError(method, pathname) {
  const err = new Error(`Proxmox ${method} ${pathname} aborted (deadline reached)`);
  err.code = 'PROXMOX_ABORTED';
  return err;
}

/**
 * @param {string} method
 * @param {string} path
 * @param {object|string|null} body
 * @param {{timeoutMs?: number, signal?: AbortSignal}} [opts]
 *
 * `opts` is a fourth, optional parameter so the ~32 existing two- and
 * three-argument call sites are untouched.
 */
async function proxmoxAPI(method, path, body = null, opts = {}) {
  const https = require('https');
  const url = new URL(`${PROXMOX_URL}${path}`);

  const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : DEFAULT_TIMEOUT_MS;
  const signal = opts.signal || null;

  let bodyStr = null;
  if (body) {
    if (typeof body === 'string') {
      bodyStr = body;
    } else {
      bodyStr = Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    }
  }

  if (signal && signal.aborted) return Promise.reject(proxmoxAbortError(method, url.pathname));

  return new Promise((resolve, reject) => {
    const reqOpts = {
      hostname: url.hostname,
      port: url.port || 8006,
      path: url.pathname + url.search,
      method,
      headers: {
        'Authorization': `PVEAPIToken=${PROXMOX_TOKEN_ID}=${PROXMOX_TOKEN_SECRET}`,
        ...(bodyStr && { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(bodyStr) })
      },
      rejectUnauthorized: false  // Proxmox uses self-signed certs
    };

    let onAbort = null;
    let settled = false;
    // One shared deadline signal can be handed to every call in a fan-out. The
    // listener MUST come off on settle or the signal accumulates one per call
    // and trips MaxListenersExceededWarning partway through a scan.
    const cleanup = () => {
      if (settled) return;
      settled = true;
      if (signal && onAbort) signal.removeEventListener('abort', onAbort);
    };
    const done = (fn) => (arg) => { cleanup(); fn(arg); };
    const ok = done(resolve);
    const fail = done(reject);

    const req = https.request(reqOpts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          return fail(new Error(`Proxmox ${method} ${url.pathname} failed (${res.statusCode}): ${data}`));
        }
        try {
          const json = JSON.parse(data);
          ok(json.data !== undefined ? json.data : json);
        } catch {
          ok(data);
        }
      });
    });

    if (signal) {
      onAbort = () => req.destroy(proxmoxAbortError(method, url.pathname));
      signal.addEventListener('abort', onAbort, { once: true });
    }

    // Socket timeout prevents hanging if Proxmox stops responding mid-request.
    req.setTimeout(timeoutMs, () => {
      req.destroy(proxmoxTimeoutError(method, url.pathname, timeoutMs));
    });

    req.on('error', fail);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// Helper: wait for a Proxmox task to complete
async function waitForTask(node, upid, timeoutMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await proxmoxAPI('GET', `/api2/json/nodes/${node}/tasks/${encodeURIComponent(upid)}/status`);
    if (status.status === 'stopped') {
      if (status.exitstatus === 'OK') return status;
      throw new Error(`Proxmox task failed: ${status.exitstatus}`);
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error('Proxmox task timed out');
}

/**
 * Forcefully destroy a Proxmox VM or LXC: removes protection, unlocks,
 * stops, then deletes with purge. Tries `knownNode` first; if not provided,
 * iterates all cluster nodes (handles ghost configs from failed clones).
 *
 * Returns true on successful destroy, false if the VMID couldn't be
 * destroyed on any node (typically because it's already gone).
 */
async function forceDestroyVM(vmid, type, knownNode) {
  const nodes = knownNode ? [knownNode] : [];
  if (nodes.length === 0) {
    try {
      const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
      for (const n of nodeList) nodes.push(n.node);
    } catch (e) {
      getClusterNodes().forEach(n => nodes.push(n)); // fallback to site.json node list
    }
  }

  for (const node of nodes) {
    try {
      try {
        await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { protection: 0 });
        console.log(`[Teardown] Removed protection from ${type} ${vmid} on ${node}`);
      } catch (_) {}

      try {
        await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { lock: '' });
      } catch (_) {}

      try {
        const stopBody = type === 'qemu' ? { timeout: 0 } : {};
        await proxmoxAPI('POST', `/api2/json/nodes/${node}/${type}/${vmid}/status/stop`, stopBody);
        await new Promise(r => setTimeout(r, 4000));
      } catch (_) {}

      // QEMU accepts purge+skiplock; LXC accepts purge+force (rejects skiplock on newer versions)
      const primaryUrl = type === 'lxc'
        ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
        : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1&skiplock=1`;
      try {
        await proxmoxAPI('DELETE', primaryUrl);
      } catch (deleteErr) {
        console.log(`[Teardown] Retry destroy ${type} ${vmid} with minimal params...`);
        const fallback = type === 'lxc'
          ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
          : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1`;
        await proxmoxAPI('DELETE', fallback);
      }

      console.log(`[Teardown] Destroyed ${type} ${vmid} on ${node}`);
      return true;
    } catch (e) {
      if (/unable to find configuration file/i.test(e.message)) {
        console.log(`[Teardown] ${type} ${vmid} not on ${node} (no config file) — checking next node`);
        continue;
      }
      console.log(`[Teardown] ${type} ${vmid} not destroyable on ${node}: ${e.message}`);
      continue;
    }
  }
  return false;
}

/**
 * Verify which cluster node a template VMID actually lives on.
 * Queries live cluster resources and returns the real node, correcting
 * declaredNode if the template has been migrated. Falls back to
 * declaredNode if the cluster query fails or the VMID isn't visible
 * (e.g. on an offline node), letting the clone call surface the real error.
 */
async function findTemplateNode(vmid, declaredNode) {
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
    const match = resources.find(r =>
      (r.type === 'qemu' || r.type === 'lxc') && Number(r.vmid) === Number(vmid)
    );
    if (match) {
      if (match.node !== declaredNode) {
        console.log(`[TemplateResolver] VMID ${vmid} found on ${match.node} — correcting declared node ${declaredNode}`);
      }
      return match.node;
    }
    console.warn(`[TemplateResolver] VMID ${vmid} not found in cluster resources — using declared node ${declaredNode}`);
  } catch (e) {
    console.warn(`[TemplateResolver] Could not verify template ${vmid} location: ${e.message}`);
  }
  return declaredNode;
}

/**
 * Poll the cluster until these VMIDs are gone.
 *
 * Proxmox DELETE is ASYNCHRONOUS — it returns a UPID and destroys in the
 * background — and nothing in this codebase waits on that task. Anything that
 * re-uses a VMID it just destroyed (an in-place lane rebuild, an attach-mode
 * lab redeploy) therefore clones into an id still being purged, and gets
 * either "VM already exists" or, worse, a destroy task that lands AFTER the
 * clone and eats the new disk.
 *
 * Doubles as the survivor check. A caller's own error list is unreliable in
 * both directions — forceDestroyVM reports failure for a VM that merely moved
 * node, and teardown paths drop instance records even when VMs survive. The
 * cluster is the only authority.
 *
 * Lives here rather than in a plugin because src/utils must never require one:
 * lane-deployer needs this for the same reason vuln-lab-provision does.
 *
 * @returns {Promise<{surviving:number[]}>}
 */
async function waitForVmidsGone(vmids, { timeoutMs = 120000, intervalMs = 5000 } = {}) {
  const want = new Set((vmids || []).filter(v => v != null).map(v => String(v)));
  if (want.size === 0) return { surviving: [] };

  const deadline = Date.now() + timeoutMs;
  let surviving = [...want];

  while (Date.now() < deadline) {
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      const live = new Set((resources || []).map(r => String(r.vmid)));
      surviving = [...want].filter(v => live.has(v));
      if (surviving.length === 0) return { surviving: [] };
    } catch (e) {
      // A cluster read failure must not be reported as "they're gone" — keep
      // the last known survivor list and try again until the deadline.
      console.warn(`[Proxmox] Could not read cluster resources while waiting for destroy: ${e.message}`);
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }

  return { surviving: surviving.map(v => Number(v)) };
}
/**
 * Current power state of one VM, normalized to 'running' | 'stopped' | <raw>.
 *
 * Reads the VM's own status endpoint rather than /cluster/resources: a caller
 * polling one machine through a power transition needs the authoritative
 * per-VM view, and the cluster summary can lag a stop by a poll interval.
 */
async function getPowerState(node, vmid, providerType) {
  const st = await proxmoxAPI('GET', `${vmApiBase(node, vmid, providerType)}/status/current`);
  return (st && st.status) || 'unknown';
}

/**
 * Block until a VM reaches `want`, or throw.
 *
 * The app had no such waiter before this: waitForTask follows a UPID,
 * waitForVmidsGone follows a VMID's absence, and waitForTemplateUnlock follows
 * a lock field, but nothing followed power. Every existing power call either
 * fires and forgets (routes/workstations.js:799 writes the DB state
 * optimistically and never awaits the UPID) or sleeps a fixed 4s. Neither is
 * good enough for stop -> reconfigure -> start, where applying the config
 * before the guest has actually stopped writes into Proxmox's [PENDING]
 * section instead of the live config and the resize silently does nothing.
 *
 * A TRANSPORT ERROR IS NOT A FAILURE. A node under load, a pveproxy restart or
 * a brief 596 during a shutdown all surface here as a rejected request, and
 * treating those as "the guest is stuck" would abort a resize that was going
 * perfectly. Errors are swallowed and the poll continues until the deadline —
 * the same discipline waitForVmidsGone applies for the same reason.
 *
 * @param {string} want  'running' | 'stopped'
 * @throws {Error & {code:'POWER_STATE_TIMEOUT', lastState:string}}
 */
async function waitForPowerState(node, vmid, providerType, want, opts = {}) {
  const { timeoutMs = 180000, intervalMs = 3000, signal = null } = opts;
  const deadline = Date.now() + timeoutMs;
  let last = 'unknown';

  while (Date.now() < deadline) {
    if (signal && signal.aborted) {
      throw Object.assign(new Error(`Aborted while waiting for VM ${vmid} to be ${want}`),
        { code: 'PROXMOX_ABORTED' });
    }
    try {
      last = await getPowerState(node, vmid, providerType);
      if (last === want) return last;
    } catch (e) {
      // Deliberately swallowed — see the docblock. Not logged either: a 3s
      // poll over a 180s window would produce 60 lines per unreachable VM, and
      // the reason survives anyway in the timeout error's `lastState`.
      last = `unreadable (${e.message})`;
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }

  const err = new Error(
    `VM ${vmid} did not reach '${want}' within ${Math.round(timeoutMs / 1000)}s (last seen: ${last})`);
  err.code = 'POWER_STATE_TIMEOUT';
  err.lastState = last;
  throw err;
}

module.exports = {
  proxmoxAPI, waitForTask, forceDestroyVM, findTemplateNode, waitForVmidsGone, PROXMOX_URL,
  vmApiBase, getPowerState, waitForPowerState,
};
