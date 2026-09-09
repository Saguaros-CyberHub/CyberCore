/**
 * ============================================================================
 * CLE — RESTART MACHINES
 *
 * Power-cycle the machines on a set of lanes: stop each guest cleanly, then
 * start it again. Nothing is destroyed, nothing is re-cloned, no configuration
 * changes — the disk is not touched at all.
 *
 * Shared by BOTH entry points rather than written twice:
 *   VM Management tab  -> routes/vms.js   POST /restart
 *   Environments tab   -> routes/labs.js  POST /:labId/restart
 *
 * Those two select differently (lanes vs (environment, student) pairs) and
 * claim different mutex keys, but everything after "which lanes" is identical.
 * The half that is easy to get wrong — excluding the gateway, resolving the
 * live node, bounding concurrency, and never leaving a machine off — lives here
 * once.
 *
 * NOT A RESET. The guest is shut down through ACPI and its qemu process goes
 * away before it is started again. That is what makes it useful for what people
 * actually reach for it for: a wedged service, a leaked mount, a guest that has
 * drifted since Monday. A reset leaves every one of those in place, and a
 * redeploy fixes them by destroying the student's work.
 * ============================================================================
 */

const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { laneMachines, laneGatewayVmid } = require('../../../../../src/utils/lane-machines');
const { restartOneVm, POWER_CONCURRENCY } = require('../../../../../src/utils/vm-power');
const { runBatch } = require('../../../../../src/utils/batch-deployer');
const laneDeployer = require('../../../../../src/utils/lane-deployer');

const LOG = '[CLE Restart]';

/**
 * A restart is far cheaper than a teardown, so it gets a higher ceiling than
 * MAX_BULK_LANES (50) — that number exists because 50 lanes is ~150 VMs handed
 * to teardownLanes at once. Still a hard 400 and never a silent truncation: an
 * instructor who selected a whole course and saw two thirds of it restart has
 * no way to know which third was skipped.
 */
const MAX_RESTART_TARGETS = 300;

/**
 * Which machines a restart will actually touch.
 *
 * Pure, so the gateway-exclusion rule can be tested without a cluster. Every
 * lane's machines come from laneMachines(), which is the single place that
 * knows all three config shapes AND drops the gateway.
 *
 * A lane that is not 'active' is SKIPPED rather than failing the batch. The
 * table polls every 8s, so one lane a co-instructor started rebuilding three
 * seconds ago must not fail the other forty-one.
 *
 * @param {Array}  lanes  server-resolved lane rows — never client-supplied ids
 * @param {object} [opts] { machines?: [{lane_id, slot|vmid}] } to narrow further
 * @returns {{targets: Array, skipped: Array}}
 */
function resolveRestartTargets(lanes, opts = {}) {
  const skipped = [];
  const targets = [];

  let wantVmids = null;
  if (opts.machines != null) {
    if (!Array.isArray(opts.machines) || opts.machines.length === 0) {
      const e = new Error('machines must be a non-empty array'); e.status = 400; throw e;
    }
    wantVmids = new Set(opts.machines.map(m => Number(m && (m.vmid ?? m.vm_id))).filter(Number.isInteger));
    if (!wantVmids.size) {
      const e = new Error('machines must name at least one vmid'); e.status = 400; throw e;
    }
  }

  for (const lane of (lanes || [])) {
    if (lane.status === 'deploying') {
      skipped.push({
        lane_id: lane.lane_id,
        reason: 'a deploy, rebuild or resize is already running on this lane',
      });
      continue;
    }
    // Unlike a redeploy, an 'error' lane is NOT refused. A rebuild has to clone
    // into a working gateway and cannot; a restart only powers guests that
    // already exist, and a half-built lane whose machines are up is exactly the
    // case an instructor is trying to clear.
    let machines = laneMachines(lane);
    // The Environments tab restarts ONE environment. An attached lane carries
    // the student's own workstations and possibly another lab's boxes in the
    // same config, so without this filter "restart this environment" would
    // power-cycle the student's Windows box as well.
    if (opts.materialId) machines = machines.filter(m => m.material_id === opts.materialId);
    if (wantVmids) machines = machines.filter(m => wantVmids.has(m.vmid));
    if (!machines.length) {
      skipped.push({
        lane_id: lane.lane_id,
        reason: wantVmids ? 'no machine on this lane was selected'
              : opts.materialId ? 'this lane holds no machines for that environment'
                                : 'lane records no machines other than its gateway',
      });
      continue;
    }
    for (const m of machines) {
      targets.push({
        lane_id: lane.lane_id,
        lane_name: lane.name,
        student_email: lane.student_email || null,
        user_id: lane.user_id || null,
        vxlan_id: lane.vxlan_id,
        gateway_vmid: laneGatewayVmid(lane),
        ...m,
      });
    }
  }

  if (targets.length > MAX_RESTART_TARGETS) {
    const e = new Error(
      `select at most ${MAX_RESTART_TARGETS} machines at a time (got ${targets.length})`);
    e.status = 400; throw e;
  }
  return { targets, skipped };
}

/**
 * Attach each target's LIVE node and power state from one cluster read.
 *
 * The node recorded on a lane is advisory: a migrated VM's is stale, and every
 * power call against the wrong host fails. Reading it once for the whole batch
 * also gives the "N of these are running" count the confirm dialog shows,
 * without a per-machine status call.
 *
 * A target the cluster does not know about is dropped into `skipped` — it has
 * been destroyed out from under the lane row, and a power call would 500.
 */
async function attachLiveState(targets) {
  const byVmid = {};
  const cluster = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
  for (const r of (cluster || [])) byVmid[String(r.vmid)] = r;

  const live = [];
  const skipped = [];
  for (const t of targets) {
    const l = byVmid[String(t.vmid)];
    if (!l) {
      skipped.push({ lane_id: t.lane_id, reason: `vmid ${t.vmid} is not in the cluster` });
      continue;
    }
    live.push({ ...t, node: l.node, running: l.status === 'running' });
  }
  return { live, skipped };
}

/**
 * The durable "this machine is down for a restart" marker.
 *
 * Written BEFORE the guest is stopped. If the process dies between the stop and
 * the start, recoverInterruptedResizes() in server.js finds this at boot and
 * powers the machine back on — the marker is the only thing that knows a
 * running machine was deliberately taken down.
 *
 * Deliberately does NOT set lane status to 'deploying'. The lane is genuinely
 * active, and recoverStrandedLanes() sweeps every 'deploying' row without a
 * config.rebuild key to 'error' on boot, which would condemn a healthy lane on
 * every restart of the app.
 */
async function markRestartInFlight(t, wasRunning) {
  await cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = jsonb_set(
                       COALESCE(config, '{}'::jsonb), '{restart}',
                       COALESCE(config->'restart', '{}'::jsonb) || $2::jsonb),
            updated_at = NOW()
      WHERE lane_id = $1`,
    [t.lane_id, JSON.stringify({
      status: 'running',
      at: new Date().toISOString(),
      in_flight: {
        vmid: t.vmid, node: t.node, provider_type: t.provider_type,
        was_running: !!wasRunning,
      },
    })]
  ).catch(e => console.warn(`${LOG} marker write failed for ${t.lane_id}: ${e.message}`));
}

async function clearRestartInFlight(laneId) {
  await cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = jsonb_set(
                       COALESCE(config, '{}'::jsonb), '{restart}',
                       COALESCE(config->'restart', '{}'::jsonb) - 'in_flight'),
            updated_at = NOW()
      WHERE lane_id = $1`,
    [laneId]
  ).catch(() => {});
}

/** Record the outcome per lane, so the table can badge a failed restart. */
async function recordLaneRestart(laneId, entries) {
  const failed = entries.filter(e => e.result.status === 'failed');
  const patch = {
    restart: {
      at: new Date().toISOString(),
      status: failed.length === 0 ? 'ok' : (failed.length < entries.length ? 'partial' : 'failed'),
      error: failed.length ? failed[0].result.error : null,
      machines: entries.map(({ target, result }) => ({
        vmid: target.vmid,
        name: target.name,
        status: result.status,
        forced: result.forced,
        power_restored: result.power_restored,
        ...(result.error ? { message: String(result.error).slice(0, 500) } : {}),
      })),
    },
  };
  await cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = COALESCE(config, '{}'::jsonb) || $2::jsonb, updated_at = NOW()
      WHERE lane_id = $1`,
    [laneId, JSON.stringify(patch)]
  ).catch(e => console.warn(`${LOG} could not record the restart on ${laneId}: ${e.message}`));
}

/**
 * Run the restart across a resolved batch.
 *
 * Bounded concurrency rather than a sequential loop: a restart is almost
 * entirely spent waiting for guests to shut down and boot, and 84 machines
 * serially at ~90s each is over two hours. Bounded rather than unbounded
 * because 84 simultaneous Windows boots is an outage, not a restart.
 *
 * @param {object} ctx { live, startStopped, progress }
 */
async function runRestartBatch(ctx) {
  const { live, startStopped, progress } = ctx;
  laneDeployer.setPhase(progress, 'restarting', `Restarting machines: 0/${live.length} complete`);

  const byLane = new Map();
  let done = 0;

  await runBatch(
    live,
    async (t) => {
      const key = `${t.lane_id}:${t.vmid}`;
      const setStatus = (st, err) => {
        if (progress.lanes[key]) {
          progress.lanes[key].status = st;
          if (err !== undefined) progress.lanes[key].error = err;
        }
      };
      setStatus('running');

      const result = await restartOneVm({
        node: t.node,
        vmid: t.vmid,
        providerType: t.provider_type,
        label: `${t.name || t.lane_name || t.lane_id} (${t.vmid})`,
        startIfStopped: startStopped,
        onPhase: (phase) => setStatus(phase),
        onIntent: async ({ was_running }) => { await markRestartInFlight(t, was_running); },
        // Cleared only when the machine ended in the power state it should be
        // in. Left in place otherwise, so the boot sweep tries the start again.
        onSettled: async ({ settled }) => {
          if (settled) await clearRestartInFlight(t.lane_id);
        },
      });

      if (!byLane.has(t.lane_id)) byLane.set(t.lane_id, []);
      byLane.get(t.lane_id).push({ target: t, result });

      if (result.status === 'failed') { progress.failed++; setStatus('error', result.error); }
      else { progress.succeeded++; setStatus('done', null); }
      return result;
    },
    {
      concurrency: POWER_CONCURRENCY,
      onProgress: () => {
        progress.completed = ++done;
        laneDeployer.setPhase(progress, 'restarting',
          `Restarting machines: ${done}/${live.length} complete`);
      },
    }
  );

  for (const [laneId, entries] of byLane) {
    await recordLaneRestart(laneId, entries);
  }
}

module.exports = {
  resolveRestartTargets,
  attachLiveState,
  runRestartBatch,
  MAX_RESTART_TARGETS,
};
