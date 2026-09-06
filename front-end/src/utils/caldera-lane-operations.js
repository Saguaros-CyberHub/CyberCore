'use strict';

// Classroom operations use the central server and one existing group per lane.
// This service is separate from the lane-local incident/grading engine.
const crypto = require('node:crypto');
const { v5: uuidv5 } = require('uuid');
const { targetsFor, pawFor, groupFor, seenAt, laneEligible, eligibleLaneSql } = require('./caldera-lane-agents');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const MAX_LANES = 100;
const TERMINAL = new Set(['finished', 'out_of_time', 'cleanup', 'stopped', 'failed']);
const cfg = lane => typeof lane?.config === 'string' ? JSON.parse(lane.config) : lane?.config || {};
const fail = (status, message) => Object.assign(new Error(message), { status });
const operationId = (batch, lane) => uuidv5(`operation:${lane}`, batch);
const sourceId = (batch, lane) => uuidv5(`source:${lane}`, batch);
const records = lane => Object.values(cfg(lane).caldera_operations || {});

async function parallel(items, limit, fn) {
  let index = 0;
  const result = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) { const i = index++; result[i] = await fn(items[i], i); }
  }));
  return result;
}

function defaultClient() {
  const { resolveTarget } = require('../incident/caldera/authoring');
  const { authoringConfig } = require('../routes/caldera-authoring');
  const target = resolveTarget(authoringConfig());
  if (!target.client) throw fail(503, 'Configure the central Caldera server and API key before launching an attack.');
  return target.client;
}

function createService(deps = {}) {
  const query = deps.query || ((...args) => require('./cybercore-db').cybercoreQuery(...args));
  const clientFor = deps.client || defaultClient;
  const now = deps.now || Date.now;
  const proxmox = (...args) => (deps.proxmox || require('./proxmox').proxmoxAPI)(...args);
  const schedule = deps.schedule || (task => setImmediate(task));
  const stamp = () => new Date(now()).toISOString();

  function select(lanes, input, courseId) {
    if (!UUID.test(courseId) || !Array.isArray(input.lane_ids) || !input.lane_ids.length || input.lane_ids.length > MAX_LANES
      || new Set(input.lane_ids).size !== input.lane_ids.length || input.lane_ids.some(id => typeof id !== 'string' || !UUID.test(id))) {
      throw fail(400, `Select between 1 and ${MAX_LANES} distinct lanes.`);
    }
    const selected = input.lane_ids.map(id => lanes.find(lane => lane.lane_id === id && cfg(lane).course_id === courseId));
    if (selected.some(lane => !lane)) throw fail(404, 'A selected lane was not found in this course.');
    return selected;
  }

  async function roster(lanes, client) {
    const [allAgents, resources] = await Promise.all([
      client.listAgents(), proxmox('GET', '/api2/json/cluster/resources?type=vm'),
    ]);
    if (!Array.isArray(allAgents) || !Array.isArray(resources)) throw fail(503, 'Could not verify Caldera agents and VM power.');
    const live = new Set(resources.filter(vm => vm.type === 'qemu' && !vm.template && vm.status === 'running').map(vm => Number(vm.vmid)));
    return new Map(lanes.map(lane => {
      const group = groupFor(lane.lane_id);
      const targets = targetsFor(lane);
      const agents = allAgents.filter(agent => agent.group === group && agent.trusted === true
        && seenAt(agent.last_seen) >= now() - 120000 && seenAt(agent.last_seen) <= now() + 30000)
        .flatMap(agent => {
          const target = targets.find(vm => pawFor(lane.lane_id, vm.vm_id) === agent.paw && live.has(vm.vm_id));
          return target ? [{ paw: agent.paw, host: agent.host, platform: agent.platform, last_seen: agent.last_seen,
            vm_id: target.vm_id, name: target.name }] : [];
        });
      return [lane.lane_id, { lane_id: lane.lane_id, name: lane.name, group,
        runnable: laneEligible(lane) && cfg(lane).internet_enabled !== false && agents.length > 0, agents }];
    }));
  }

  function publicRecord(record, remote) {
    let status = record.status;
    let error = record.error;
    if (remote) {
      if (remote.group !== record.group) { status = 'unknown'; error = 'The Caldera operation group changed. Review it in Caldera.'; }
      else if (record.status !== 'failed') status = remote.state || 'unknown';
    } else if (['running', 'paused', 'stopping'].includes(record.status)) {
      status = 'unknown'; error = 'This operation is unavailable in Caldera. Refresh status or inspect the console.';
    } else if (record.status === 'preparing' && now() - Date.parse(record.created_at) > 10 * 60 * 1000) {
      status = 'unknown'; error = 'Preparation was interrupted. Stop this batch before starting another.';
    }
    return { batch_id: record.batch_id, operation_id: record.operation_id, name: record.name,
      adversary_name: record.adversary_name, status, started_at: record.started_at || record.created_at,
      error: error || null, stop_requested: !!record.stop_requested };
  }

  function visibleRecords(lane, remote = new Map()) {
    let history = 0;
    return records(lane).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
      .map(record => publicRecord(record, remote.get(record.operation_id)))
      // Keep every active/uncertain operation: the UI uses these rows to stop
      // all lanes in a batch. Only terminal history may be truncated.
      .filter(record => !TERMINAL.has(record.status) || history++ < 20);
  }

  async function status(lanes, { courseId } = {}) {
    const scoped = lanes.filter(lane => cfg(lane).course_id === courseId);
    const response = { adversaries: [], lanes: scoped.map(lane => ({ lane_id: lane.lane_id, name: lane.name,
      group: groupFor(lane.lane_id), runnable: false, agents: [], operations: visibleRecords(lane) })) };
    let client;
    try { client = clientFor(); } catch (error) { return { ...response, configuration_error: error.message }; }
    const [inventory, adversaries, operations] = await Promise.allSettled([roster(scoped, client), client.listAdversaries(), client.listOperations()]);
    if (inventory.status === 'rejected') response.agents_error = 'Could not verify online agents and VM power. Refresh status.';
    if (adversaries.status === 'fulfilled' && Array.isArray(adversaries.value)) {
      response.adversaries = adversaries.value.filter(adv => typeof adv.adversary_id === 'string' && Array.isArray(adv.atomic_ordering) && adv.atomic_ordering.length)
        .map(adv => ({ adversary_id: adv.adversary_id, name: adv.name || adv.adversary_id,
          description: adv.description || '', ability_count: adv.atomic_ordering.length })).sort((a, b) => a.name.localeCompare(b.name));
    } else response.configuration_error = 'Could not read Caldera adversary profiles.';
    const remote = new Map(operations.status === 'fulfilled' && Array.isArray(operations.value) ? operations.value.map(op => [op.id, op]) : []);
    if (operations.status === 'rejected') response.operations_error = 'Could not refresh Caldera operation status.';
    response.lanes = scoped.map(lane => ({ ...(inventory.status === 'fulfilled' ? inventory.value.get(lane.lane_id) : response.lanes.find(row => row.lane_id === lane.lane_id)),
      operations: visibleRecords(lane, remote) }));
    return response;
  }

  async function loadLane(laneId, courseId) {
    const result = await query('SELECT lane_id, name, status, config FROM cybercore_lane WHERE lane_id = $1 AND config->>\'course_id\' = $2', [laneId, courseId]);
    return result.rows[0];
  }

  async function save(laneId, courseId, record) {
    await query(`UPDATE cybercore_lane SET config = jsonb_set(config, ARRAY['caldera_operations', $3::text],
      $4::jsonb || jsonb_build_object('stop_requested', COALESCE(config->'caldera_operations'->$3::text->'stop_requested', 'false'::jsonb))), updated_at = NOW()
      WHERE lane_id = $1 AND config->>'course_id' = $2 AND config->'caldera_operations'->$3::text->>'operation_id' = $5`,
    [laneId, courseId, record.batch_id, JSON.stringify(record), record.operation_id]);
  }

  async function stoppedOrChanged(laneId, courseId, record) {
    const current = await loadLane(laneId, courseId);
    return !current || !laneEligible(current) || cfg(current).caldera_operations?.[record.batch_id]?.operation_id !== record.operation_id
      || cfg(current).caldera_operations[record.batch_id].stop_requested === true;
  }

  async function stopRemote(client, record) {
    const remote = await client.getOperation(record.operation_id);
    if (remote?.tolerated && remote.status === 404) return;
    if (remote?.id !== record.operation_id || remote.group !== record.group) throw fail(409, 'The operation group could not be verified.');
    if (TERMINAL.has(remote.state)) return;
    try {
      const response = await client.abortOperation(record.operation_id);
      if (response?.tolerated && response.status === 404) return;
      if (response?.id === record.operation_id && response.group === record.group && TERMINAL.has(response.state)) return;
    } catch (_) { /* Re-read: the operation may have finished concurrently. */ }
    const confirmed = await client.getOperation(record.operation_id);
    if (confirmed?.tolerated && confirmed.status === 404) return;
    if (confirmed?.id !== record.operation_id || confirmed.group !== record.group || !TERMINAL.has(confirmed.state)) {
      throw fail(502, 'Caldera did not confirm that the operation stopped.');
    }
  }

  async function runBatch(selected, courseId, entries, client, adversary) {
    const prepared = [];
    let prepareFailed = false;
    const batchId = entries[selected[0].lane_id].batch_id;
    const snapshot = { adversary_id: uuidv5('adversary', batchId), name: `Classroom ${batchId.slice(0, 8)}: ${adversary.name || adversary.adversary_id}`,
      description: 'Snapshot for a CyberCore classroom exercise.', atomic_ordering: [...adversary.atomic_ordering] };
    await client.createAdversary(snapshot);
    await parallel(selected, 4, async lane => {
      const record = entries[lane.lane_id];
      try {
        if (await stoppedOrChanged(lane.lane_id, courseId, record)) throw fail(409, 'Lane changed or batch stopped before preparation.');
        // A fresh, empty source prevents facts from another class/lane leaking into this operation.
        const source = { id: sourceId(record.batch_id, lane.lane_id), name: record.name, facts: [], relationships: [], rules: [], adjustments: [] };
        await client.createSource(source);
        const created = await client.createOperation({ id: record.operation_id, name: record.name, group: record.group,
          adversary: { adversary_id: snapshot.adversary_id }, source: { id: source.id },
          state: 'paused', autonomous: 1, auto_close: true, obfuscator: 'plain-text', jitter: '2/8' });
        if (created?.id !== record.operation_id || created?.group !== record.group || created?.state !== 'paused'
          || created?.adversary?.adversary_id !== snapshot.adversary_id || created?.source?.id !== source.id) {
          throw fail(502, 'Caldera did not confirm the requested paused operation, group, adversary and fact source.');
        }
        record.status = 'paused'; await save(lane.lane_id, courseId, record); prepared.push(lane);
      } catch (error) {
        prepareFailed = true; record.status = 'failed'; record.error = error.status === 409 ? error.message : 'Could not prepare this lane in Caldera. The batch was not released.';
        await save(lane.lane_id, courseId, record);
      }
    });
    // All lanes must prepare before any begins. Release requests are concurrent;
    // execution follows each agent's polling interval, not a synchronized clock.
    if (!prepareFailed) {
      const fresh = await Promise.all(selected.map(lane => loadLane(lane.lane_id, courseId)));
      if (fresh.some(lane => !lane || !laneEligible(lane))) prepareFailed = true;
      else {
        const live = await roster(fresh, client);
        if (fresh.some(lane => !live.get(lane.lane_id)?.runnable || cfg(lane).caldera_operations?.[entries[lane.lane_id].batch_id]?.stop_requested)) prepareFailed = true;
      }
    }
    if (prepareFailed) {
      await parallel(selected, 4, async lane => {
        const record = entries[lane.lane_id];
        try {
          await stopRemote(client, record);
          record.status = 'failed'; record.error ||= 'The batch was stopped because at least one lane could not be prepared.';
        } catch (_) { record.status = 'unknown'; record.error = 'Could not confirm this prepared operation was stopped. Inspect Caldera before retrying.'; }
        await save(lane.lane_id, courseId, record);
      });
      return;
    }
    const releasedAt = stamp();
    await Promise.all(prepared.map(async lane => {
      const record = entries[lane.lane_id];
      try {
        if (await stoppedOrChanged(lane.lane_id, courseId, record)) throw fail(409, 'Lane changed or batch stopped before launch.');
        const remote = await client.startOperation(record.operation_id);
        if (remote?.group !== record.group || remote?.id !== record.operation_id) throw fail(502, 'Caldera did not confirm the requested operation.');
        record.status = remote.state || 'running'; record.started_at = releasedAt;
        if (await stoppedOrChanged(lane.lane_id, courseId, record)) {
          await stopRemote(client, record); record.status = 'stopped';
        }
      } catch (_) { record.status = 'unknown'; record.error = 'Launch could not be confirmed. Refresh status before retrying; the operation may have started.'; }
      await save(lane.lane_id, courseId, record);
    }));
  }

  async function launch(lanes, input = {}, { courseId, label = 'Classroom' } = {}) {
    const selected = select(lanes, input, courseId);
    if (!UUID.test(input.request_id) || typeof input.adversary_id !== 'string' || !input.adversary_id.trim() || input.adversary_id.length > 200) {
      throw fail(400, 'Choose an adversary and provide a unique request ID.');
    }
    const batch = input.request_id.toLowerCase();
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify([input.adversary_id, [...input.lane_ids].sort()])).digest('hex');
    const existing = selected.map(lane => cfg(lane).caldera_operations?.[batch]);
    if (existing.some(Boolean)) {
      if (!existing.every(record => record?.fingerprint === fingerprint)) throw fail(409, 'This request ID was already used with different selections.');
      return { batch_id: batch, results: selected.map((lane, i) => ({ lane_id: lane.lane_id, ...publicRecord(existing[i]) })) };
    }
    const client = clientFor();
    const [available, catalog] = await Promise.all([roster(selected, client), client.listAdversaries()]);
    if (selected.some(lane => !available.get(lane.lane_id)?.runnable)) throw fail(409, 'Every selected lane needs a running VM with a trusted agent seen in the last two minutes. Refresh status.');
    const adversary = Array.isArray(catalog) && catalog.find(item => item.adversary_id === input.adversary_id);
    if (!adversary || !Array.isArray(adversary.atomic_ordering) || !adversary.atomic_ordering.length) throw fail(400, 'This adversary is unavailable or has no abilities.');
    const entries = Object.fromEntries(selected.map(lane => [lane.lane_id, {
      batch_id: batch, fingerprint, operation_id: operationId(batch, lane.lane_id), group: groupFor(lane.lane_id),
      name: `${String(label).slice(0, 80)} / ${String(lane.name || lane.lane_id).slice(0, 80)} / ${batch.slice(0, 8)}`,
      adversary_id: adversary.adversary_id, adversary_name: adversary.name || adversary.adversary_id,
      status: 'preparing', created_at: stamp(), stop_requested: false,
    }]));
    // One atomic statement reserves every selected lane, or none. Locks serialize retries.
    const claimed = await query(`WITH locked AS MATERIALIZED (
      SELECT l.lane_id, l.config, l.status FROM cybercore_lane l
      WHERE l.lane_id = ANY($1::uuid[]) AND l.config->>'course_id' = $2 ORDER BY l.lane_id FOR UPDATE
    ), allowed AS (
      SELECT COUNT(*) = cardinality($1::uuid[]) AND bool_and(${eligibleLaneSql()} AND NOT (COALESCE(config->'caldera_operations', '{}'::jsonb) ? $3::text)) AS ok FROM locked
    ) UPDATE cybercore_lane l SET config = jsonb_set(l.config, '{caldera_operations}',
      COALESCE(l.config->'caldera_operations', '{}'::jsonb) || jsonb_build_object($3::text, $4::jsonb->l.lane_id::text)), updated_at = NOW()
      FROM locked WHERE l.lane_id = locked.lane_id AND (SELECT ok FROM allowed) RETURNING l.lane_id`,
    [selected.map(lane => lane.lane_id), courseId, batch, JSON.stringify(entries)]);
    if (claimed.rows.length !== selected.length) {
      const refreshed = await Promise.all(selected.map(lane => loadLane(lane.lane_id, courseId)));
      const prior = refreshed.map(lane => cfg(lane).caldera_operations?.[batch]);
      if (prior.every(record => record?.fingerprint === fingerprint)) return { batch_id: batch,
        results: selected.map((lane, i) => ({ lane_id: lane.lane_id, ...publicRecord(prior[i]) })) };
      throw fail(409, 'A selected lane changed or this request is already being processed. Refresh status.');
    }
    schedule(() => runBatch(selected, courseId, entries, client, adversary).catch(async () => {
      // Never release after an interrupted preparation. Saved operation IDs make
      // uncertain outcomes visible and stoppable after a worker/server failure.
      await Promise.allSettled(selected.map(async lane => {
        const record = entries[lane.lane_id]; record.status = 'unknown'; record.error = 'Batch processing was interrupted. Refresh status and stop the batch before retrying.';
        await save(lane.lane_id, courseId, record);
      }));
    }));
    return { batch_id: batch, results: selected.map(lane => ({ lane_id: lane.lane_id, ...publicRecord(entries[lane.lane_id]) })) };
  }

  async function stop(lanes, input = {}, { courseId } = {}) {
    const selected = select(lanes, input, courseId);
    if (!UUID.test(input.batch_id)) throw fail(400, 'Choose the batch to stop.');
    const batch = input.batch_id.toLowerCase();
    if (selected.some(lane => !cfg(lane).caldera_operations?.[batch])) throw fail(404, 'Batch not found in a selected lane.');
    const client = clientFor();
    // Persist cancellation before touching Caldera so a preparing worker cannot release it.
    await query(`UPDATE cybercore_lane SET config = jsonb_set(config,
      ARRAY['caldera_operations', $3::text, 'stop_requested'], 'true'::jsonb), updated_at = NOW()
      WHERE lane_id = ANY($1::uuid[]) AND config->>'course_id' = $2 AND config->'caldera_operations' ? $3::text`,
    [selected.map(lane => lane.lane_id), courseId, batch]);
    const results = await parallel(selected, 8, async lane => {
      const record = { ...cfg(lane).caldera_operations[batch], stop_requested: true };
      try {
        await stopRemote(client, record);
        record.status = 'stopped';
        delete record.error;
      } catch (_) { record.status = 'unknown'; record.error = 'Could not confirm the operation stopped. Retry Stop or inspect Caldera.'; }
      await save(lane.lane_id, courseId, record);
      return { lane_id: lane.lane_id, ...publicRecord(record) };
    });
    return { batch_id: batch, results };
  }

  return { status, launch, stop };
}

module.exports = { createService, operationId, sourceId, MAX_LANES };
