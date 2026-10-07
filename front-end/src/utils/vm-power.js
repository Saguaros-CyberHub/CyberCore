/**
 * ============================================================================
 * VM POWER CONTROL
 *
 * Bringing a guest down and back up, correctly. Shared by the resize engine
 * (which needs the guest stopped so a config write lands on the live config
 * rather than in Proxmox's [PENDING] section) and by the restart feature
 * (which just wants the power cycle).
 *
 * WHY NOT POST /status/reboot. Proxmox has one, and it does a clean shutdown
 * followed by a start — so on the happy path it is equivalent and shorter. It
 * is not used here because it is a single opaque call: there is no point at
 * which a guest that ignores the ACPI request can be escalated to a hard stop,
 * no way to report "shutting down" separately from "starting", and no way to
 * guarantee the machine is powered on at the end when the reboot itself fails
 * partway. Every one of those matters when the operation is running unattended
 * across a class of forty machines.
 * ============================================================================
 */

const { proxmoxAPI, getPowerState, waitForPowerState } = require('./proxmox');
const { vmApiBase } = require('./vm-paths');

const LOG = '[VM Power]';

/**
 * How long a guest gets to shut down cleanly before we pull the power.
 *
 * Generous on purpose. A Windows guest mid-update, or one showing a "you have
 * unsaved work" dialog, can sit at the ACPI request for minutes, and hard-
 * stopping it is exactly the case this timeout exists to postpone: the disk
 * survives a power-pull, but whatever was only in memory does not.
 */
const SHUTDOWN_TIMEOUT_MS = Number(process.env.VM_SHUTDOWN_TIMEOUT_MS)
  || Number(process.env.VM_RESIZE_SHUTDOWN_TIMEOUT_MS) || 180000;
/** After escalating to a hard stop, qemu should be gone in seconds. */
const HARD_STOP_TIMEOUT_MS = 60000;
/** Long enough for a Windows boot; the VM is usable before this elapses. */
const START_TIMEOUT_MS = Number(process.env.VM_START_TIMEOUT_MS)
  || Number(process.env.VM_RESIZE_START_TIMEOUT_MS) || 120000;

/**
 * How many machines to power-cycle at once inside one batch.
 *
 * NOT the clone semaphore. max_concurrent_clones bounds disk throughput during
 * a deploy, and a power cycle does no disk I/O at all — borrowing that budget
 * would throttle this against the wrong resource. But it cannot be unbounded
 * either: a 42-lane class is 84 simultaneous Windows boots, which is a
 * thundering herd on the nodes' CPU and turns a restart into an outage.
 */
const POWER_CONCURRENCY = Number(process.env.VM_POWER_CONCURRENCY) || 4;

/**
 * Bring a guest to a stop, gracefully first.
 *
 * ACPI/guest-agent shutdown is what lets open files flush and what makes
 * "the student's work is safe" true for work that was only in memory. It is
 * also the request a guest is allowed to ignore, so it cannot be the only
 * attempt — hence the escalation. Leading with `stop` would be simpler and
 * would silently discard unsaved work on every single call.
 *
 * @returns {Promise<{escalated: boolean}>}
 * @throws if the guest is still running after the hard stop
 */
async function stopGuest(node, vmid, providerType, onPhase) {
  const base = vmApiBase(node, vmid, providerType);

  if (onPhase) onPhase('shutting-down');
  await proxmoxAPI('POST', `${base}/status/shutdown`);
  try {
    await waitForPowerState(node, vmid, providerType, 'stopped', { timeoutMs: SHUTDOWN_TIMEOUT_MS });
    return { escalated: false };
  } catch (e) {
    if (e.code !== 'POWER_STATE_TIMEOUT') throw e;
  }

  // The guest ignored the request. Pull the power — the disk is consistent
  // either way, but anything unsaved in an open application is gone, which is
  // why the confirm dialog says so before any of this runs.
  console.warn(`${LOG} VM ${vmid} ignored the shutdown request after ` +
    `${Math.round(SHUTDOWN_TIMEOUT_MS / 1000)}s — escalating to a hard stop`);
  if (onPhase) onPhase('force-stopping');
  await proxmoxAPI('POST', `${base}/status/stop`);
  await waitForPowerState(node, vmid, providerType, 'stopped', { timeoutMs: HARD_STOP_TIMEOUT_MS });
  return { escalated: true };
}

/** Start a guest and wait for it, reporting rather than throwing on a slow boot. */
async function startGuest(node, vmid, providerType, onPhase) {
  if (onPhase) onPhase('starting');
  await proxmoxAPI('POST', `${vmApiBase(node, vmid, providerType)}/status/start`);
  try {
    await waitForPowerState(node, vmid, providerType, 'running', { timeoutMs: START_TIMEOUT_MS });
    return { confirmed: true };
  } catch (e) {
    // The start command was accepted; the guest is just slow, or it did not
    // come up. Either way the machine is no longer ours to hold open, but the
    // instructor has to be told rather than shown a green tick.
    return { confirmed: false };
  }
}

/**
 * Power-cycle ONE machine: stop it, then start it again.
 *
 * NOT a reset. The guest is shut down cleanly and its qemu process goes away
 * before it is started again, which is what makes this useful for the thing
 * people actually reach for it for — a wedged service, a leaked mount, a guest
 * that has drifted since Monday. A `reset` would leave every one of those in
 * place.
 *
 * Never throws: a batch restarting a class must report per-machine outcomes,
 * not die on the first guest that is wedged.
 *
 * `startIfStopped` decides what happens to a machine that was ALREADY off.
 * There is no universally right answer, which is why it is a parameter rather
 * than a rule: "restart everything before class" wants them on, and a targeted
 * restart of two wedged machines should not quietly boot the six a student
 * deliberately shut down.
 *
 * `onIntent` is awaited BEFORE the guest is stopped and is how the durable
 * marker is written; `onSettled` receives the outcome so the caller can decide
 * whether to clear it. It MUST NOT be cleared unconditionally — if the machine
 * was running and could not be started again, that marker is the only remaining
 * record that something owes it a power-on.
 *
 * @returns {Promise<{status, was_running, power_restored, forced, warnings, error}>}
 */
async function restartOneVm({
  node, vmid, providerType, label, startIfStopped = true,
  onPhase, onIntent, onSettled,
}) {
  const tag = label || `vm ${vmid}`;
  const out = {
    status: 'failed',
    was_running: null,
    power_restored: 'n/a',
    forced: false,
    warnings: [],
    error: null,
  };

  let wasRunning = null;
  try {
    const state = await getPowerState(node, vmid, providerType);
    wasRunning = state === 'running';
    out.was_running = wasRunning;

    if (!wasRunning && !startIfStopped) {
      out.status = 'skipped';
      out.power_restored = 'left_stopped';
      return out;
    }

    // Durable intent BEFORE the machine goes down. Everything after this point
    // can be interrupted by a process restart, and a machine left off with
    // nothing that knows to turn it back on is the worst outcome available.
    if (onIntent) await onIntent({ was_running: wasRunning });

    if (wasRunning) {
      const { escalated } = await stopGuest(node, vmid, providerType, onPhase);
      out.forced = escalated;
      if (escalated) {
        out.warnings.push(
          'the guest ignored the shutdown request and was powered off — unsaved work in open applications was lost');
      }
    }

    const { confirmed } = await startGuest(node, vmid, providerType, onPhase);
    out.status = 'restarted';
    out.power_restored = confirmed ? 'yes' : 'unconfirmed';
    if (!confirmed) {
      out.warnings.push('the machine was told to start but was not running after '
        + `${Math.round(START_TIMEOUT_MS / 1000)}s — check it before class`);
    }
    console.log(`${LOG} ${tag}: restarted${out.forced ? ' (forced)' : ''}`);
  } catch (e) {
    out.error = e.message;
    console.error(`${LOG} ${tag}: ${e.message}`);
  } finally {
    // A machine that was taken down must not be left down, whatever went wrong
    // on the way. This runs on the failure path too, and an extra start against
    // an already-running guest is a no-op to Proxmox — the asymmetry is
    // deliberate, because the two mistakes are not equally bad.
    try {
      if (wasRunning !== null && out.status !== 'skipped') {
        const endState = await getPowerState(node, vmid, providerType).catch(() => 'unknown');
        if (endState !== 'running') {
          await proxmoxAPI('POST', `${vmApiBase(node, vmid, providerType)}/status/start`);
          out.power_restored = out.error ? 'recovered' : out.power_restored;
        }
      }
    } catch (e) {
      out.power_restored = 'failed';
      out.warnings.push(`could not power the machine back on: ${e.message}`);
      console.error(`${LOG} ${tag}: power restore FAILED: ${e.message}`);
    }
    if (onSettled) {
      await Promise.resolve(onSettled({
        power_restored: out.power_restored,
        settled: out.power_restored !== 'failed' && out.power_restored !== 'unconfirmed',
      })).catch(() => {});
    }
  }

  return out;
}

module.exports = {
  stopGuest,
  startGuest,
  restartOneVm,
  POWER_CONCURRENCY,
  SHUTDOWN_TIMEOUT_MS,
  START_TIMEOUT_MS,
};
