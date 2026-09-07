'use strict';

const crypto = require('node:crypto');
const { createClient, managerHostname } = require('./wazuh-client');

const POLL_MS = 30000;
const RECHECK_MS = 60000;
const GRACE_MS = 15 * 60000;
const LEASE_MS = 5 * 60000;
const MAX_BACKOFF_MS = 60 * 60000;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

// Runtime schema is required: migrations/ is an operator artifact, excluded
// from the app image and not run automatically. Keep 037 in sync with this.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS cybercore_wazuh_cleanup (
  lane_id UUID PRIMARY KEY,
  registrations JSONB NOT NULL CHECK (jsonb_typeof(registrations) = 'array'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retain_until TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes'),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  lease_token UUID,
  lease_until TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_wazuh_cleanup_due ON cybercore_wazuh_cleanup(next_attempt_at);
`;

function cleanupError(message) { return Object.assign(new Error(message), { cleanupSafe: true }); }

// Cleanup needs the existing API trust/credentials, independent of installer
// package versions or optional agent groups.
function cleanupSettings(env = process.env, dependencies = {}) {
  return {
    manager: managerHostname(env.WAZUH_MANAGER),
    client: (dependencies.createClient || createClient)({
      apiUrl: env.WAZUH_API_URL, username: env.WAZUH_API_USERNAME, password: env.WAZUH_API_PASSWORD,
      caFile: env.WAZUH_API_CA_FILE || undefined, serverName: env.WAZUH_API_SERVER_NAME || undefined,
    }),
  };
}

function registrationsFor(laneId, values) {
  if (!UUID.test(laneId || '') || !Array.isArray(values)) {
    throw cleanupError('Saved Wazuh cleanup metadata could not be verified.');
  }
  const byName = new Map();
  for (const raw of values) {
    const vmId = Number(raw?.vm_id);
    if (!raw || !UUID.test(raw.job_id || '') || !Number.isSafeInteger(vmId) || vmId <= 0
        || typeof raw.manager !== 'string' || !raw.manager || raw.manager !== managerHostname(raw.manager)) {
      throw cleanupError('Saved Wazuh registration ownership could not be verified.');
    }
    // Installation retries get a new job_id while retaining the original
    // registration name. Its UUID suffix belongs to that original enrollment.
    const prefix = `cc-${laneId.toLowerCase().replaceAll('-', '')}-${vmId}-`;
    const expected = raw.agent_name;
    if (typeof expected !== 'string' || !expected.startsWith(prefix) || !/^[a-f0-9]{32}$/.test(expected.slice(prefix.length)) || (raw.agent_id != null
      && (typeof raw.agent_id !== 'string' || !/^[0-9]{3,8}$/.test(raw.agent_id) || Number(raw.agent_id) === 0))) {
      throw cleanupError('Saved Wazuh registration ownership could not be verified.');
    }
    const item = { job_id: raw.job_id, vm_id: vmId, manager: raw.manager,
      agent_name: expected, ...(raw.agent_id != null ? { agent_id: raw.agent_id } : {}) };
    const old = byName.get(expected);
    if (old && (old.manager !== item.manager || (old.agent_id && item.agent_id && old.agent_id !== item.agent_id))) {
      throw cleanupError('Saved Wazuh cleanup registrations conflict. Review their ownership.');
    }
    byName.set(expected, old?.agent_id ? old : item);
  }
  return [...byName.values()];
}

function createService(dependencies = {}) {
  const query = dependencies.query || ((...args) => require('./cybercore-db').cybercoreQuery(...args));
  const settings = dependencies.settings || cleanupSettings;
  const now = dependencies.now || Date.now;
  let schemaPromise, timer, running = null;

  function ensureSchema() {
    if (!schemaPromise) schemaPromise = query(SCHEMA).catch(error => { schemaPromise = null; throw error; });
    return schemaPromise;
  }

  async function claim() {
    const result = await query(`WITH candidate AS (
      SELECT lane_id FROM cybercore_wazuh_cleanup
      WHERE next_attempt_at <= $1::timestamptz AND (lease_until IS NULL OR lease_until <= $1::timestamptz)
      ORDER BY next_attempt_at, lane_id LIMIT 1 FOR UPDATE SKIP LOCKED
    ) UPDATE cybercore_wazuh_cleanup AS cleanup
      SET lease_token = $2::uuid, lease_until = $3::timestamptz, attempts = attempts + 1
      FROM candidate WHERE cleanup.lane_id = candidate.lane_id RETURNING cleanup.*`,
    [new Date(now()).toISOString(), crypto.randomUUID(), new Date(now() + LEASE_MS).toISOString()]);
    return result.rows[0] || null;
  }

  async function renew(row) {
    const result = await query(`UPDATE cybercore_wazuh_cleanup SET lease_until = $3::timestamptz
      WHERE lane_id = $1 AND lease_token = $2::uuid RETURNING lane_id`,
    [row.lane_id, row.lease_token, new Date(now() + LEASE_MS).toISOString()]);
    if (!result.rows.length) throw cleanupError('Wazuh cleanup ownership changed; the current request will be retried.');
  }

  async function finish(row, error, removed) {
    const retainUntil = new Date(row.retain_until).getTime();
    if (!error && Number.isFinite(retainUntil) && now() >= retainUntil) {
      const result = await query(`DELETE FROM cybercore_wazuh_cleanup
        WHERE lane_id = $1 AND lease_token = $2::uuid RETURNING lane_id`, [row.lane_id, row.lease_token]);
      return { completed: result.rows.length ? 1 : 0, deferred: 0, failed: 0, removed };
    }
    const delay = error ? Math.min(MAX_BACKOFF_MS, RECHECK_MS * 2 ** Math.min(6, Math.max(0, Number(row.attempts || 1) - 1))) : RECHECK_MS;
    const message = error ? (error.cleanupSafe ? error.message
      : 'Wazuh cleanup could not confirm removal. Check API connectivity, credentials, TLS trust and permissions.') : null;
    await query(`UPDATE cybercore_wazuh_cleanup
      SET next_attempt_at = $3::timestamptz, last_error = $4, lease_token = NULL, lease_until = NULL
      WHERE lane_id = $1 AND lease_token = $2::uuid`,
    [row.lane_id, row.lease_token, new Date(now() + delay).toISOString(), message]);
    return { completed: 0, deferred: error ? 0 : 1, failed: error ? 1 : 0, removed };
  }

  async function processRow(row) {
    let removed = 0, error = null;
    // Renew the short claim while a large registration inventory is paginated.
    // The token guard stops an old worker from acknowledging a newer snapshot.
    let leaseError = null, renewing = false;
    const heartbeat = setInterval(() => {
      if (renewing) return;
      renewing = true;
      renew(row).catch(cause => { leaseError = cause; }).finally(() => { renewing = false; });
    }, 30000);
    heartbeat.unref?.();
    try {
      const registrations = registrationsFor(row.lane_id, row.registrations);
      if (!Number.isFinite(new Date(row.retain_until).getTime())) {
        throw cleanupError('Saved Wazuh cleanup retention time could not be verified.');
      }
      const lane = await query('SELECT lane_id FROM cybercore_lane WHERE lane_id = $1', [row.lane_id]);
      if (lane.rows.length) throw cleanupError('Wazuh cleanup is waiting for the lane to be removed.');
      if (registrations.length) {
        const config = settings();
        if (registrations.some(item => item.manager !== config.manager)) {
          throw cleanupError('Wazuh cleanup is waiting for configuration of the original manager.');
        }
        const inventory = await config.client.listAgents();
        const ids = new Set();
        if (!Array.isArray(inventory)) throw new Error('Invalid inventory');
        for (const agent of inventory) {
          if (!agent || typeof agent.id !== 'string' || !/^[0-9]{3,8}$/.test(agent.id)
              || typeof agent.name !== 'string' || !agent.name || ids.has(agent.id)) throw new Error('Invalid inventory');
          ids.add(agent.id);
        }
        for (const registration of registrations) {
          if (leaseError) throw leaseError;
          await renew(row);
          const matching = inventory.filter(agent => agent.name === registration.agent_name);
          if (matching.length > 1) throw cleanupError('The Wazuh API returned conflicting registrations for a saved managed name.');
          // A deleted registration ID can be reused by Wazuh during the grace
          // period. Absence of our exact name confirms it is gone; another name
          // at the old numeric ID must never become our deletion target.
          if (!matching.length) continue;
          const id = matching[0].id;
          if (Number(id) === 0) throw new Error('Invalid registration');
          if (registration.agent_id && registration.agent_id !== id) {
            throw cleanupError('The saved Wazuh managed name belongs to a different registration ID. Review its ownership.');
          }
          if (leaseError) throw leaseError;
          // deleteAgent performs another exact ID/name verification at the API
          // and confirms disappearance. Never use group or status-wide deletes.
          const result = await config.client.deleteAgent(id, registration.agent_name);
          if (!result || result.id !== id || result.name !== registration.agent_name
              || typeof result.already_absent !== 'boolean') throw new Error('Unconfirmed removal');
          if (!result.already_absent) removed++;
        }
      }
      if (leaseError) throw leaseError;
    } catch (cause) { error = cause; }
    finally { clearInterval(heartbeat); }
    return finish(row, error, removed);
  }

  function processPending({ limit = 10 } = {}) {
    if (running) return running;
    const maximum = Math.max(1, Math.min(100, Number.isSafeInteger(limit) ? limit : 10));
    running = (async () => {
      await ensureSchema();
      const summary = { processed: 0, completed: 0, deferred: 0, failed: 0, removed: 0 };
      for (let i = 0; i < maximum; i++) {
        const row = await claim();
        if (!row) break;
        const result = await processRow(row);
        summary.processed++;
        for (const key of ['completed', 'deferred', 'failed', 'removed']) summary[key] += result[key];
      }
      return summary;
    })().finally(() => { running = null; });
    return running;
  }

  function kickWorker() {
    // Detached: Wazuh availability cannot delay an already completed teardown.
    setImmediate(() => { processPending().then(summary => {
      if (summary.removed || summary.failed) {
        (dependencies.log || console.log)(`[Wazuh cleanup] Removed ${summary.removed} registration(s); ${summary.failed} lane(s) pending retry.`);
      }
    }).catch(() => {
      (dependencies.warn || console.warn)('[Wazuh cleanup] Pending registrations will be retried; the cleanup worker could not finish this pass.');
    }); });
  }
  function startWorker() {
    if (timer) return;
    timer = setInterval(kickWorker, POLL_MS);
    timer.unref?.();
    kickWorker();
  }
  function stopWorker() { if (timer) clearInterval(timer); timer = null; }
  return { ensureSchema, processPending, startWorker, stopWorker, kickWorker };
}

const service = createService();
module.exports = { ...service, createService, cleanupSettings, registrationsFor, SCHEMA,
  POLL_MS, GRACE_MS, RECHECK_MS, LEASE_MS, MAX_BACKOFF_MS };
