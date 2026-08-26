/**
 * ============================================================================
 * VM RESIZE ENGINE
 *
 * Change a DEPLOYED machine's CPU and RAM without destroying what is on it.
 *
 * Before this existed, the only way to re-size a student's workstation was
 * rebuildLaneWorkstations() or POST /vms/redeploy — both of which destroy the
 * VM and clone a new one from the template. Their own confirm copy says it:
 * "Anything saved inside the machines is lost." Mid-semester that is not a
 * usable answer, so an under-sized cohort stayed under-sized.
 *
 * Nothing about `cores` and `memory` requires that. They are entries in the
 * Proxmox VM config; the disk image is never touched. What was missing was the
 * orchestration, and it is all here.
 *
 * WHY A REBOOT AND NOT HOTPLUG. Proxmox can change CPU and memory on a running
 * guest, but only when the VM carries `numa=1` and a `hotplug=` flag AND the
 * guest OS supports it. Neither string appears in any template this repo bakes
 * (bake-win-client-template.sh creates its VM with --machine q35 --bios ovmf
 * --cpu host --cores --memory and no --hotplug, no --numa, no --maxmem), and
 * the workstation fleet is Windows 11 — a CLIENT edition, which does not
 * support CPU or memory hotplug at all, and cannot hot-UNPLUG memory in any
 * edition. A stop/start is therefore the only mechanism that works on the
 * machines this feature exists for, and it costs 1-3 minutes with the disk
 * untouched throughout.
 *
 * DISK IS OUT OF SCOPE, deliberately. Growing a live disk is half a feature:
 * PUT /resize grows the block device and nothing grows the guest filesystem.
 * The whole existing strategy is "resize before first boot and let cloud-init's
 * growpart see it" (applyResources' docblock in lane-deployer.js), and a
 * repo-wide search for growpart|resize2fs|xfs_growfs|diskpart|Resize-Partition
 * finds only comments. A student handed a bigger block device and an unchanged
 * filesystem sees a feature that silently did nothing. Shrinking is impossible
 * outright. So callers must reject disk_gb before they get here; resizeOneVm
 * refuses it as a belt.
 * ============================================================================
 */

const {
  proxmoxAPI, getPowerState, waitForPowerState,
} = require('./proxmox');
const { vmApiBase } = require('./vm-paths');
const { applyResources } = require('./lane-deployer');

const LOG = '[VM Resize]';

/**
 * How long a guest gets to shut down cleanly before we pull the power.
 *
 * Generous on purpose. A Windows guest mid-update, or one showing a "you have
 * unsaved work" dialog, can sit at the ACPI request for minutes, and hard-
 * stopping it is exactly the case this timeout exists to postpone: the disk
 * survives a power-pull, but whatever was only in memory does not.
 */
const SHUTDOWN_TIMEOUT_MS = Number(process.env.VM_RESIZE_SHUTDOWN_TIMEOUT_MS) || 180000;
/** After escalating to a hard stop, qemu should be gone in seconds. */
const HARD_STOP_TIMEOUT_MS = 60000;
/** Long enough for a Windows boot; the VM is usable before this elapses. */
const START_TIMEOUT_MS = Number(process.env.VM_RESIZE_START_TIMEOUT_MS) || 120000;

/**
 * How many machines to resize at once inside one batch.
 *
 * NOT the clone semaphore. max_concurrent_clones bounds disk throughput during
 * a deploy, and a resize does no disk I/O at all — borrowing that budget would
 * throttle this against the wrong resource. But it cannot be unbounded either:
 * a 30-machine class at ~90s each is 45 minutes serially, and 30 simultaneous
 * Windows boots is a thundering herd on the nodes' CPU.
 */
const RESIZE_CONCURRENCY = Number(process.env.VM_RESIZE_CONCURRENCY) || 4;

/** The sizing fields this engine will touch. Disk is deliberately absent. */
const RESIZABLE_FIELDS = ['cores', 'memory_mb'];

/**
 * Read the sizing a VM currently has, straight from its Proxmox config.
 *
 * `balloon` rides along because it constrains what memory may be set to:
 * Proxmox rejects a config whose balloon floor exceeds `memory`, which is what
 * applyResources' balloon-lowering rule exists to handle.
 */
async function readVmSizing(node, vmid, providerType) {
  const cfg = await proxmoxAPI('GET', `${vmApiBase(node, vmid, providerType)}/config`) || {};
  return {
    cores: Number(cfg.cores) || null,
    memory_mb: Number(cfg.memory) || null,
    balloon: Number(cfg.balloon) || 0,
  };
}

/**
 * Is this request a no-op against what the machine already has?
 *
 * Pure, and load-bearing rather than an optimization. A bulk resize aimed at a
 * whole course will routinely include machines that are already the right
 * size — a re-run after a partial failure, or a class where some lanes were
 * deployed later with the newer sizing. Rebooting those would take a student's
 * machine away for no reason and for no change.
 */
function isNoOp(before, target) {
  return RESIZABLE_FIELDS.every(f => target[f] == null || Number(before[f]) === Number(target[f]));
}

/**
 * What to do about power, given how the run went.
 *
 * Extracted as a pure function so the one guarantee that really matters here —
 * A STUDENT'S MACHINE IS NEVER LEFT POWERED OFF — is testable without a
 * cluster. The rules:
 *
 *   - It was running and it is not running now: start it. Unconditionally, and
 *     including when the resize FAILED. A failed resize that leaves the machine
 *     off is far worse than a failed resize, because the student cannot work at
 *     all and nothing in the UI explains why.
 *   - It was already stopped: leave it stopped. A resize must not switch a
 *     machine on as a side effect — it was off for a reason, and an instructor
 *     resizing 30 lanes has not asked to boot the three that were deliberately
 *     shut down.
 *   - It is already running: nothing to do.
 */
function decidePowerPlan({ wasRunning, endState }) {
  if (!wasRunning) return { action: 'none', restored: 'left_stopped' };
  if (endState === 'running') return { action: 'none', restored: 'yes' };
  return { action: 'start', restored: 'pending' };
}

/**
 * Why a read-back did not match, in words an instructor can act on.
 *
 * applyResources' own warning is the most useful thing available when it has
 * one — it carries Proxmox's refusal verbatim. The bare mismatch message is the
 * fallback for the silent case, which is what a [PENDING] write looks like.
 */
function describeMismatch(after, target, warnings) {
  const first = (warnings || [])[0];
  if (first) return first;
  const bits = RESIZABLE_FIELDS
    .filter(f => target[f] != null && Number(after[f]) !== Number(target[f]))
    .map(f => `${f} is ${after[f]}, expected ${target[f]}`);
  return `Proxmox accepted the change but the machine did not take it (${bits.join('; ')})`;
}

/**
 * Bring a guest to a stop, gracefully first.
 *
 * ACPI/guest-agent shutdown is what lets open files flush and what makes
 * "the student's work is safe" true for work that was only in memory. It is
 * also the request a guest is allowed to ignore, so it cannot be the only
 * attempt — hence the escalation. Leading with `stop` would be simpler and
 * would silently discard unsaved work on every single resize.
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

/**
 * Resize ONE machine's CPU and RAM in place.
 *
 * Never throws: a batch resizing a class must report per-machine outcomes, not
 * die on the first machine whose guest is wedged. The caller decides what a
 * failure means.
 *
 * `onIntent` is awaited BEFORE the guest is stopped and is how the durable
 * "this machine was running when I took it down" marker gets written. Without
 * it, a process restart between the stop and the start leaves a student's
 * machine off with nothing anywhere that knows to turn it back on.
 *
 * `onSettled` receives the outcome so the caller can decide whether to clear
 * that marker. It MUST NOT be cleared unconditionally: if the machine was
 * running and could not be started again, the marker is the only remaining
 * record that something owes it a power-on, and dropping it converts a
 * recoverable failure into a machine that stays off until somebody notices.
 *
 * @param {object}   a
 * @param {string}   a.node          live node, resolved from /cluster/resources
 *                                   rather than lane config — a migrated VM's
 *                                   recorded node is stale, and every call here
 *                                   would fail against the wrong host.
 * @param {number}   a.vmid
 * @param {string}   [a.providerType] 'lxc' | 'qemu'
 * @param {object}   a.resources     { cores?, memory_mb? } — already normalized
 * @param {string}   [a.label]       for logs
 * @param {Function} [a.onPhase]     (phase) => void
 * @param {Function} [a.onIntent]    async ({ was_running }) => void
 * @param {Function} [a.onSettled]   async () => void
 * @returns {Promise<object>}
 */
async function resizeOneVm({
  node, vmid, providerType, resources, label, onPhase, onIntent, onSettled,
}) {
  const tag = label || `vm ${vmid}`;
  const out = {
    status: 'failed',
    before: null,
    after: null,
    applied: {},
    was_running: null,
    power_restored: 'n/a',
    forced: false,
    warnings: [],
    error: null,
  };

  // Belt for the caller's braces. Disk is refused here as well as in the route
  // so no future caller can reach the grow path by accident.
  if (resources && resources.disk_gb != null) {
    out.error = 'disk resizing is not supported on a deployed machine';
    return out;
  }
  if (!resources || RESIZABLE_FIELDS.every(f => resources[f] == null)) {
    out.error = 'nothing to change — supply cores and/or memory_mb';
    return out;
  }

  let wasRunning = null;
  try {
    out.before = await readVmSizing(node, vmid, providerType);

    if (isNoOp(out.before, resources)) {
      out.status = 'unchanged';
      out.after = out.before;
      const state = await getPowerState(node, vmid, providerType).catch(() => 'unknown');
      out.was_running = state === 'running';
      return out;
    }

    const state = await getPowerState(node, vmid, providerType);
    wasRunning = state === 'running';
    out.was_running = wasRunning;

    // LXC takes cores and memory live. The lane gateway is an LXC, and there is
    // no reason to interrupt it to change a number it will accept while running.
    if (providerType === 'lxc') {
      if (onPhase) onPhase('applying');
      const r = await applyResources({ node, vmid, providerType, resources, laneName: tag });
      out.warnings.push(...(r.warnings || []));
      out.after = await readVmSizing(node, vmid, providerType);
      if (isNoOp(out.after, resources)) {
        out.status = 'resized';
        out.applied = r.applied || {};
      } else {
        out.error = describeMismatch(out.after, resources, r.warnings);
      }
      return out;
    }

    // Durable intent BEFORE the machine goes down. Everything after this point
    // can be interrupted by a process restart.
    if (onIntent) await onIntent({ was_running: wasRunning });

    if (wasRunning) {
      const { escalated } = await stopGuest(node, vmid, providerType, onPhase);
      out.forced = escalated;
      if (escalated) {
        out.warnings.push(
          'the guest ignored the shutdown request and was powered off — unsaved work in open applications was lost');
      }
    }

    if (onPhase) onPhase('applying');
    const r = await applyResources({ node, vmid, providerType, resources, laneName: tag });
    out.warnings.push(...(r.warnings || []));

    // VERIFY BY READ-BACK, do not trust the PUT. applyResources never throws —
    // it folds every failure into `warnings`, which is right for a bulk deploy
    // where an under-sized workstation still beats a failed class, and wrong
    // here where the whole point is to know whether it took. A read-back also
    // catches the case a status code cannot: a config write that landed in
    // Proxmox's [PENDING] section rather than the live config, which reports
    // success and changes nothing until the next power cycle.
    out.after = await readVmSizing(node, vmid, providerType);
    if (isNoOp(out.after, resources)) {
      out.status = 'resized';
      out.applied = r.applied || {};
      console.log(`${LOG} ${tag}: ${out.before.cores}c/${out.before.memory_mb}MiB -> ` +
        `${out.after.cores}c/${out.after.memory_mb}MiB`);
    } else {
      out.error = describeMismatch(out.after, resources, r.warnings);
    }
  } catch (e) {
    out.error = e.message;
    console.error(`${LOG} ${tag}: ${e.message}`);
  } finally {
    // Power restoration runs on BOTH paths. See decidePowerPlan.
    try {
      if (wasRunning !== null && providerType !== 'lxc') {
        const endState = await getPowerState(node, vmid, providerType).catch(() => 'unknown');
        const plan = decidePowerPlan({ wasRunning, endState });
        if (plan.action === 'start') {
          if (onPhase) onPhase('starting');
          await proxmoxAPI('POST', `${vmApiBase(node, vmid, providerType)}/status/start`);
          try {
            await waitForPowerState(node, vmid, providerType, 'running', { timeoutMs: START_TIMEOUT_MS });
            out.power_restored = 'yes';
          } catch (e) {
            // The start command was accepted; the guest is just slow, or it did
            // not come up. Either way the machine is no longer ours to hold
            // open, but the instructor has to be told.
            out.power_restored = 'unconfirmed';
            out.warnings.push('the machine was told to start but was not running after ' +
              `${Math.round(START_TIMEOUT_MS / 1000)}s — check it before class`);
          }
        } else {
          out.power_restored = plan.restored;
        }
      }
    } catch (e) {
      out.power_restored = 'failed';
      out.warnings.push(`could not power the machine back on: ${e.message}`);
      console.error(`${LOG} ${tag}: power restore FAILED: ${e.message}`);
    }
    // The outcome decides whether the durable marker may be dropped — see the
    // docblock. 'failed' and 'unconfirmed' both mean a machine that was running
    // may not be running now.
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
  resizeOneVm,
  readVmSizing,
  // Pure, and exported for the tests that pin the two rules this feature
  // cannot get wrong: never reboot a machine that is already the right size,
  // and never leave a student's machine powered off.
  isNoOp,
  decidePowerPlan,
  describeMismatch,
  RESIZABLE_FIELDS,
  RESIZE_CONCURRENCY,
  SHUTDOWN_TIMEOUT_MS,
  START_TIMEOUT_MS,
};
