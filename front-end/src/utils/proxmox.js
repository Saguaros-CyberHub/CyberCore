/**
 * ============================================================================
 * PROXMOX API HELPER
 * Shared utility for communicating with the Proxmox VE API
 * ============================================================================
 */

const { getClusterNodes } = require('./site-config');

const PROXMOX_URL = process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006';
const PROXMOX_TOKEN_ID = process.env.PROXMOX_TOKEN_ID || 'root@pam!clinic-app-token';
const PROXMOX_TOKEN_SECRET = process.env.PROXMOX_TOKEN_SECRET || '';

async function proxmoxAPI(method, path, body = null) {
  const https = require('https');
  const url = new URL(`${PROXMOX_URL}${path}`);

  let bodyStr = null;
  if (body) {
    if (typeof body === 'string') {
      bodyStr = body;
    } else {
      bodyStr = Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    }
  }

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

    const req = https.request(reqOpts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          return reject(new Error(`Proxmox ${method} ${url.pathname} failed (${res.statusCode}): ${data}`));
        }
        try {
          const json = JSON.parse(data);
          resolve(json.data !== undefined ? json.data : json);
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
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

module.exports = { proxmoxAPI, waitForTask, forceDestroyVM, findTemplateNode, PROXMOX_URL };
