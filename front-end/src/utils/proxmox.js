/**
 * ============================================================================
 * PROXMOX API HELPER
 * Shared utility for communicating with the Proxmox VE API
 * ============================================================================
 */

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

module.exports = { proxmoxAPI, waitForTask, PROXMOX_URL };
