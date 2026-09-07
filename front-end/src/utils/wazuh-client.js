'use strict';

const https = require('node:https');
const fs = require('node:fs');
const net = require('node:net');

const REQUEST_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const PAGE_SIZE = 500;
function failure(status, message) { return Object.assign(new Error(message), { status, safe: true }); }

function httpsUrl(value, originOnly = true) {
  let url;
  try { url = new URL(value); } catch (_) { throw failure(503, 'Configure a valid HTTPS Wazuh API URL and dashboard URL.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || (originOnly && url.pathname !== '/')) {
    throw failure(503, 'Wazuh URLs must use HTTPS without credentials; the API URL must be an origin.');
  }
  return url;
}

function managerHostname(value) {
  const manager = String(value || '').trim();
  if (!manager || manager.length > 253 || (!net.isIP(manager)
    && !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(manager))) {
    throw failure(503, 'Configure WAZUH_MANAGER as the manager hostname or IP address reachable by lane VMs.');
  }
  return manager;
}

function apiServerName(value) {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || value.length > 253 || net.isIP(value)
    || !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(value)) {
    throw failure(503, 'Set WAZUH_API_SERVER_NAME to a DNS hostname without a scheme, port, or path.');
  }
  return value;
}

function agentGroup(value, required = false) {
  if (!required && (value === undefined || value === '')) return null;
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(value) || value === '.' || value === '..') {
    throw failure(503, 'Set WAZUH_AGENT_GROUP to one existing Wazuh group name using letters, numbers, dots, underscores or hyphens.');
  }
  return value;
}

function createClient(options, deps = {}) {
  const base = httpsUrl(options.apiUrl);
  const serverName = apiServerName(options.serverName);
  if (typeof options.username !== 'string' || !options.username || options.username.includes(':')
    || typeof options.password !== 'string' || !options.password) {
    throw failure(503, 'Configure WAZUH_API_USERNAME and WAZUH_API_PASSWORD.');
  }
  let ca;
  if (options.caFile) {
    try { ca = (deps.readFileSync || fs.readFileSync)(options.caFile); }
    catch (_) { throw failure(503, 'Could not read WAZUH_API_CA_FILE.'); }
  }
  const transport = deps.request || https.request;
  const now = deps.now || Date.now;
  let token = null, tokenExpires = 0, authenticating = null;

  function request(method, path, authorization, body) {
    return new Promise((resolve, reject) => {
      let req, timer, settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(value);
      };
      const payload = body === undefined ? null : JSON.stringify(body);
      try {
        req = transport(new URL(path, base), { method, rejectUnauthorized: true,
          ...(ca ? { ca } : {}), ...(serverName ? { servername: serverName } : {}),
          headers: { Accept: 'application/json', Authorization: authorization,
            ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) } }, res => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            res.resume();
            finish(failure(res.statusCode === 401 ? 401 : 502, 'The Wazuh API rejected the request. Check API access and permissions.'));
            return;
          }
          const chunks = [];
          let size = 0;
          res.on('data', chunk => {
            size += Buffer.byteLength(chunk);
            if (size > MAX_RESPONSE_BYTES) {
              finish(failure(502, 'The Wazuh API response exceeded the supported size.'));
              res.destroy();
            } else chunks.push(Buffer.from(chunk));
          });
          res.on('error', () => finish(failure(502, 'Could not read the Wazuh API response.')));
          res.on('aborted', () => finish(failure(502, 'The Wazuh API response was interrupted.')));
          res.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
        });
        req.on('error', () => finish(failure(503, 'Could not connect securely to the Wazuh API. Check connectivity and its TLS certificate.')));
        timer = setTimeout(() => {
          finish(failure(504, 'The Wazuh API request timed out.'));
          req.destroy();
        }, deps.timeoutMs || REQUEST_TIMEOUT_MS);
        req.end(payload || undefined);
      } catch (_) {
        finish(failure(503, 'Could not connect securely to the Wazuh API.'));
      }
    });
  }

  async function authenticate() {
    if (token && now() < tokenExpires) return token;
    if (!authenticating) {
      authenticating = (async () => {
        const raw = (await request('POST', '/security/user/authenticate?raw=true',
          `Basic ${Buffer.from(`${options.username}:${options.password}`).toString('base64')}`)).trim();
        if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw)) {
          throw failure(502, 'The Wazuh API returned an invalid authentication response.');
        }
        token = raw;
        // Refresh well before the normal JWT expiration; also honor shorter tokens.
        let expires = now() + 4 * 60 * 1000;
        try {
          const exp = JSON.parse(Buffer.from(raw.split('.')[1], 'base64url').toString('utf8')).exp;
          if (Number.isFinite(exp)) expires = Math.min(expires, exp * 1000 - 30000);
        } catch (_) { /* The API remains the authority for validating its token. */ }
        tokenExpires = expires;
        return token;
      })().finally(() => { authenticating = null; });
    }
    return authenticating;
  }

  async function api(method, path, body) {
    let raw;
    for (let attempt = 0; attempt < 2; attempt++) {
      const credential = await authenticate();
      try { raw = await request(method, path, `Bearer ${credential}`, body); break; }
      catch (error) {
        if (error.status !== 401 || attempt) throw error;
        if (token === credential) { token = null; tokenExpires = 0; }
      }
    }
    let result;
    try { result = JSON.parse(raw); }
    catch (_) { throw failure(502, 'The Wazuh API returned an invalid response.'); }
    if (result?.error || !result?.data || result.data.total_failed_items > 0) {
      throw failure(502, 'The Wazuh API could not complete the request. Check API permissions and agent state.');
    }
    return result.data;
  }

  async function listAgents() {
    const agents = [];
    for (let offset = 0; offset < 100000; offset += PAGE_SIZE) {
      const data = await api('GET', `/agents?offset=${offset}&limit=${PAGE_SIZE}&select=id,name,status,lastKeepAlive&sort=%2Bid`);
      if (!Array.isArray(data.affected_items) || !Number.isSafeInteger(data.total_affected_items) || data.total_affected_items < 0) {
        throw failure(502, 'The Wazuh API returned an invalid agent list.');
      }
      agents.push(...data.affected_items);
      if (agents.length >= data.total_affected_items) return agents;
      if (!data.affected_items.length) throw failure(502, 'The Wazuh API returned an incomplete agent list.');
    }
    throw failure(502, 'The Wazuh agent inventory exceeds the supported size.');
  }

  async function getAgentKey(id) {
    if (!/^[0-9]{1,8}$/.test(String(id)) || Number(id) === 0) throw failure(502, 'Invalid Wazuh agent registration ID.');
    const data = await api('GET', `/agents/${id}/key`);
    const item = data.affected_items?.[0];
    const key = item?.key;
    if (String(item?.id) !== String(id) || typeof key !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(key)) {
      throw failure(502, 'The Wazuh API returned an invalid enrollment key.');
    }
    return key;
  }

  async function createAgent(name) {
    if (!/^cc-[A-Za-z0-9][A-Za-z0-9._-]{0,124}$/.test(name)) throw failure(400, 'Invalid managed Wazuh agent name.');
    const data = await api('POST', '/agents', { name, ip: 'any' });
    const item = data;
    if (!item || !/^[0-9]{1,8}$/.test(String(item.id)) || Number(item.id) === 0) {
      throw failure(502, 'The Wazuh API returned an invalid agent registration.');
    }
    return { id: String(item.id), key: typeof item.key === 'string' ? item.key : null };
  }

  async function assertGroupExists(value) {
    const group = agentGroup(value, true);
    try {
      const data = await api('GET', `/groups?groups_list=${encodeURIComponent(group)}&select=name`);
      if (data.total_affected_items !== 1 || data.affected_items?.length !== 1 || data.affected_items[0]?.name !== group) {
        throw failure(502, 'Invalid group response.');
      }
    } catch (_) {
      throw failure(503, 'Could not verify WAZUH_AGENT_GROUP. Create that exact group in Wazuh and grant the API account permission to read it.');
    }
  }

  async function ensureAgentGroup(id, value) {
    if (!/^[0-9]{1,8}$/.test(String(id)) || Number(id) === 0) throw failure(502, 'Invalid Wazuh agent registration ID.');
    const group = agentGroup(value, true);
    const assigned = async () => {
      const data = await api('GET', `/agents?agents_list=${id}&select=id,group`);
      const item = data.affected_items?.[0];
      // Wazuh omits `group` for registrations that have never connected and
      // have no group yet. Absence cannot confirm membership, but is valid.
      const groups = item?.group === undefined ? [] : item.group;
      if (data.total_affected_items !== 1 || data.affected_items?.length !== 1 || String(item?.id) !== String(id)
        || !Array.isArray(groups) || groups.some(name => typeof name !== 'string')) {
        throw failure(502, 'The Wazuh API returned invalid agent group membership.');
      }
      return groups.includes(group);
    };
    try {
      if (await assigned()) return;
      // Wazuh returns error 1751 for an existing membership. A concurrent retry
      // or a lost response is successful only if a fresh read confirms it.
      let assignmentError;
      try {
        const data = await api('PUT', `/agents/${id}/group/${encodeURIComponent(group)}?force_single_group=false`);
        if (data.total_affected_items !== 1 || data.affected_items?.length !== 1 || String(data.affected_items[0]) !== String(id)) {
          throw failure(502, 'The Wazuh API returned an invalid group assignment.');
        }
      } catch (error) { assignmentError = error; }
      if (!await assigned()) throw assignmentError || failure(502, 'Wazuh did not confirm group assignment.');
    } catch (_) {
      throw failure(502, 'Could not assign the agent to WAZUH_AGENT_GROUP. Check that the group exists and the API account can read agents and modify group assignments, then retry.');
    }
  }
  return { listAgents, createAgent, getAgentKey, assertGroupExists, ensureAgentGroup };
}

function defaultSettings(env = process.env) {
  const manager = managerHostname(env.WAZUH_MANAGER);
  const version = String(env.WAZUH_AGENT_VERSION || '').trim();
  if (!/^4\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d{0,2})-[1-9]\d{0,2}$/.test(version)) {
    throw failure(503, 'Set WAZUH_AGENT_VERSION to an explicit manager-compatible package version, such as 4.14.0-1.');
  }
  const client = createClient({ apiUrl: env.WAZUH_API_URL, username: env.WAZUH_API_USERNAME,
    password: env.WAZUH_API_PASSWORD, caFile: env.WAZUH_API_CA_FILE, serverName: env.WAZUH_API_SERVER_NAME });
  const consoleUrl = env.WAZUH_DASHBOARD_URL ? httpsUrl(env.WAZUH_DASHBOARD_URL, false).href : null;
  return { manager, version, consoleUrl, client, agentGroup: agentGroup(env.WAZUH_AGENT_GROUP) };
}

module.exports = { createClient, defaultSettings, managerHostname, REQUEST_TIMEOUT_MS };
