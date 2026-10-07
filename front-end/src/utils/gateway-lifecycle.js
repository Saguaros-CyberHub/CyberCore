/**
 * ============================================================================
 * LANE GATEWAY LIFECYCLE — start it, prove it started, wait out its firstboot
 *
 * WHY THIS IS ITS OWN MODULE
 * Challenge-lane deploys placed on cyberhub-node-8 failed for days behind an
 * error that named nothing real. node-8 had just joined the cluster and was
 * still doing Ceph backfill, so `pct start` on the freshly cloned gateway LXC
 * lost the race for the udev-created /dev/rbd-pve/<fsid>/<pool>/<image> symlink
 * and died in lxc.hook.pre-start with status 32. Nothing noticed: the deployer
 * fired the start, slept 5s, tried to write DHCP reservations into a stopped
 * container, swallowed THAT failure behind a misleading
 * "Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER", started every lane VM anyway,
 * cloned a GOAD controller, and finally died three to five minutes later when
 * the controller's prep.sh could not reach the gateway:
 *
 *     ssh: connect to host 10.42.129.1 port 22: No route to host
 *
 * The await/confirm/retry gate that fixes this already existed — but only in
 * lane-deployer.js, on the workstation/profile path. challenge-lane-deployer.js
 * never got it. Two deployers cloning the same gateway template onto the same
 * nodes must not hold two different opinions about whether it came up, so the
 * gate lives here and both call it.
 *
 * WHY THE REQUIRE LIST IS THIS SHORT, AND MUST STAY THIS SHORT
 * lane-deployer-slots.test.js replaces proxmox.js wholesale through
 * require.cache with a fake exporting exactly
 * { proxmoxAPI, waitForTask, findTemplateNode }. Destructuring anything else
 * off proxmox.js here — forceDestroyVM, waitForVmidsGone — would be undefined
 * at load in a test suite that has nothing to do with gateways, and the whole
 * file would fail to require.
 * ============================================================================
 */

const { proxmoxAPI, waitForTask } = require('./proxmox');
const { vmApiBase } = require('./vm-paths');
const nodeSsh = require('./node-ssh');

// A gateway start can fail on a rootfs mount that succeeds moments later --
// the same udev/RBD race GATEWAY_CLONE_RETRY_MS exists for. Only a FAILED
// start ever waits, so a healthy deploy is unchanged.
const GATEWAY_START_ATTEMPTS = 3;
const GATEWAY_START_RETRY_MS = 6000;

/**
 * One read of a container's status. Returns the status string, or null when the
 * answer could not be read at all.
 *
 * null means UNREADABLE, and unreadable is NOT evidence of anything. The node
 * may still be settling the clone, or — far more often — the caller is a test
 * whose proxmoxAPI stub returns {} or null for every URL it does not recognise.
 * Every decision built on this must treat null as "no information", never as
 * "not running": doing otherwise turns a mocked endpoint into a failed deploy.
 */
async function readGatewayStatus(node, gatewayVmid) {
  let st = null;
  try {
    st = await proxmoxAPI('GET', `${vmApiBase(node, gatewayVmid, 'lxc')}/status/current`);
  } catch (_) { /* the node may still be settling the clone; the caller keeps polling */ }
  return st && typeof st.status === 'string' ? st.status : null;
}

/**
 * Poll until the container reports 'running', or until a definite non-running
 * status has held for the whole window.
 *
 * @returns {Promise<{running: boolean, statusReadable: boolean, lastStatus: string|null}>}
 *   statusReadable false means the poll stopped because the answer was
 *   unreadable — the caller learned nothing and must not act as if it had.
 */
async function confirmGatewayRunning({ node, gatewayVmid, polls = 15, pollMs = 2000 } = {}) {
  let lastStatus = null;
  for (let i = 0; i < polls; i++) {
    const cur = await readGatewayStatus(node, gatewayVmid);
    if (cur === 'running') return { running: true, statusReadable: true, lastStatus: 'running' };
    if (cur === null) return { running: false, statusReadable: false, lastStatus };
    lastStatus = cur;
    await new Promise(r => setTimeout(r, pollMs));
  }
  return { running: false, statusReadable: true, lastStatus };
}

/**
 * START IT, AND RETRY. Two separate failures are handled here.
 *
 * (1) The start task is AWAITED. The POST returns a UPID and the start runs
 * asynchronously, so without this the code races its own container: probing
 * begins while the LXC is still booting, `pct exec` answers
 * "container not running", and waitForGatewayFirstboot spends its 5-error
 * budget in ~15s on a gateway that was always going to come up.
 *
 * (2) The start is RETRIED, because it can fail transiently. Observed on a
 * lane that failed five deploys in a row:
 *
 *     run_buffer: 569 Script exited with status 32
 *     lxc_init: 1037 Failed to run lxc.hook.pre-start for container "110891"
 *
 * 32 is mount(8)'s exit code. pre-start is where LXC activates and mounts the
 * rootfs, and this is the SAME mount failure the clone path hits -- `pct
 * clone` uses /dev/rbd-pve/<fsid>/<pool>/<image> the instant it maps it, and
 * that path is a udev-created symlink, not a kernel one. See
 * GATEWAY_CLONE_RETRY_MS and gateway-clone-recovery.test.js.
 *
 * That it is transient, not a broken container, was established directly: on
 * the failing VMID `lxc-start -F --logpriority=DEBUG` booted all the way to a
 * login prompt, and `fsck.ext4 -n -f` on its rootfs came back clean. Nothing
 * was wrong with it. The start simply happened seconds after the clone, while
 * the volume was still settling -- this cluster has been seen holding an image
 * with `rbd: error: image still has watchers` well after last use.
 *
 * For most courses a failed start only costs a warning. For a MALWARE profile
 * it is fatal by design -- the caller refuses to start workstations behind a
 * gateway whose isolation config was never verified -- so the whole lane died
 * for a container that started by hand minutes later.
 *
 * retryMs and pollMs are injectable so the behavioural test can run the whole
 * ladder in milliseconds; production passes neither.
 *
 * @returns {Promise<{running: boolean, statusReadable: boolean, lastStatus: string|null}>}
 * @throws  an Error tagged `gatewayNotRunning = true` (plus node, lastStatus,
 *          startErr) when the status is READABLE and definitely not running --
 *          challenge-lane-deployer branches on that tag to tell a gateway that
 *          never came up from any other failure on the clone path.
 */
async function startGatewayAndConfirm({
  node, gatewayVmid, logTag = '[Gateway]',
  attempts = GATEWAY_START_ATTEMPTS, retryMs = GATEWAY_START_RETRY_MS,
  pollMs = 2000, taskTimeoutMs = 120000,
} = {}) {
  let gwRunning = false;
  let lastStatus = null;
  let statusReadable = true;
  let startErr = null;

  for (let attempt = 1; attempt <= attempts && !gwRunning; attempt++) {
    if (attempt > 1) {
      console.warn(
        `${logTag} Gateway ${gatewayVmid} on ${node} did not start` +
        (startErr ? ` (${startErr})` : ` (status '${lastStatus}')`) +
        `; retrying ${attempt}/${attempts} in ${retryMs}ms`
      );
      await new Promise(r => setTimeout(r, retryMs));
    }

    startErr = null;
    try {
      const startUpid = await proxmoxAPI('POST', `${vmApiBase(node, gatewayVmid, 'lxc')}/status/start`);
      if (startUpid) await waitForTask(node, startUpid, taskTimeoutMs);
    } catch (e) {
      // Not decisive on its own -- the status poll below is the authority on
      // whether it came up, and a task that reports oddly is not proof that it
      // did not. Kept only to name the cause if every attempt fails.
      startErr = e.message;
      console.warn(`${logTag} Gateway ${gatewayVmid} start task on ${node}: ${e.message}`);
    }

    // Confirm it actually RUNS -- GET .../status/current -- before waiting on
    // anything inside it.
    //
    // Without this a gateway that fails to boot costs three minutes and then
    // reports something else entirely: waitForGatewayFirstboot probes over
    // `pct exec`, every probe fails because the container is stopped, it gives
    // up at its 180s timeout WITHOUT throwing (deliberately -- a slow firstboot
    // is survivable), and the failure finally surfaces from
    // applyGatewayWorkstationAccess as
    //
    //     nodeExec exit 255 ... pct exec <id> -- /bin/sh -c mkdir -p /etc/dnsmasq.d
    //     container '<id>' not running!
    //
    // which reads as an SSH or dnsmasq fault rather than a gateway that never
    // started. Fail here instead, in seconds, naming the actual thing.
    //
    // Fail on EVIDENCE, never on its absence. Proxmox reports {status:'stopped'}
    // for a container that did not start, so a definite non-running status is
    // grounds to retry and then to stop; a response we cannot read is not, and
    // blocking on one would make every caller that mocks this endpoint wait out
    // the whole budget.
    const seen = await confirmGatewayRunning({ node, gatewayVmid, pollMs });
    gwRunning = seen.running;
    statusReadable = seen.statusReadable;
    if (seen.lastStatus && seen.lastStatus !== 'running') lastStatus = seen.lastStatus;
    // Retrying on a status we cannot read would prove nothing and cost the delay.
    if (!statusReadable) break;
  }

  if (!gwRunning && statusReadable) {
    const err = new Error(
      `Lane gateway ${gatewayVmid} on ${node} is '${lastStatus}', not running, after ` +
      `${attempts} start attempts` + (startErr ? ` (${startErr})` : '') + `. ` +
      `Nothing inside it can be configured, so the lane would come up with no DHCP and no ` +
      `console. Its start task log names the reason — look for vzstart:${gatewayVmid} under ` +
      `/var/log/pve/tasks on ${node}; "Failed to run lxc.hook.pre-start" with status 32 ` +
      `is a rootfs mount that did not come up in time, not a damaged container.`
    );
    // Tagged, not just thrown. The challenge deployer catches this one case
    // specially: a gateway that never started is the failure where carrying on
    // (lane VMs, GOAD controller clone, prep.sh) buys three to five minutes and
    // then surfaces as an unrelated-looking "No route to host" from inside the
    // controller.
    err.gatewayNotRunning = true;
    err.node = node;
    err.lastStatus = lastStatus;
    err.startErr = startErr;
    throw err;
  }
  if (!statusReadable) {
    console.warn(
      `${logTag} Could not read gateway ${gatewayVmid} status on ${node} — continuing; ` +
      `waitForGatewayFirstboot will report if it is not actually up.`
    );
    return { running: false, statusReadable: false, lastStatus };
  }

  // 'running' rather than the local lastStatus, which only ever holds the
  // NON-running statuses seen along the way and is null on a clean first-try
  // start. Reporting it here would make this disagree with ensureGatewayRunning's
  // short-circuit for the identical outcome.
  return { running: true, statusReadable: true, lastStatus: 'running' };
}

/**
 * startGatewayAndConfirm, but safe to call on a gateway that may already be up.
 *
 * A deploy that started the gateway in an earlier phase — or a rebuild that
 * reuses a lane's existing one — must not POST /status/start at a running
 * container: Proxmox answers "CT <id> already running", the catch above records
 * it as startErr, and the ladder then spends its whole budget arguing with a
 * healthy lane. So read the status FIRST and short-circuit on 'running': zero
 * start POSTs, no sleeps.
 */
async function ensureGatewayRunning(opts = {}) {
  const { node, gatewayVmid } = opts;
  const cur = await readGatewayStatus(node, gatewayVmid);
  if (cur === 'running') return { running: true, statusReadable: true, lastStatus: 'running' };
  return startGatewayAndConfirm(opts);
}

/**
 * Block until the gateway's own firstboot hook has finished rendering its
 * config, so applyGatewayWorkstationAccess writes on top of it instead of under
 * it.
 *
 * /etc/local.d/00-cybercore-firstboot.start (see
 * infrastructure/proxmox-templates/sdn-templates/v2_gateway/) REWRITES
 * /etc/dnsmasq.conf from scratch on every boot and re-adds its baked
 * `dhcp-host=kali,<base>.50` line, then rewrites the nat table. Both of those
 * undo what applyGatewayWorkstationAccess just did, and the second one is not
 * merely lost work: the baked kali line plus our own MAC reservation are two
 * dhcp-host entries claiming the SAME address, and dnsmasq then refuses to
 * start at all. No DHCP means no workstation lands on its reserved octet, and
 * every console on the lane — including slot 0 on the baked wan0:3389 DNAT —
 * points at an address nothing answers on.
 *
 * This used to be a flat 5-second sleep, which held only while the node was
 * idle enough to boot an Alpine LXC in under 5s. Deploying a class breaks that
 * assumption on every lane after the first: the node is busy cloning and
 * booting the previous student's workstation, firstboot lands after our writes
 * instead of before them, and the whole cohort comes up with dead consoles
 * while the lanes still report 'active'. Hence a marker, not a timer.
 *
 * The marker is the persisted rules-save, written at the END of firstboot's
 * config phase — after the dnsmasq render and after every iptables rule. What
 * follows it is the Tailscale bootstrap, which retries for up to 10 minutes and
 * touches none of this, so waiting for that too would stall every deploy.
 *
 * Never throws: a gateway we cannot reach over SSH is exactly what
 * applyGatewayWorkstationAccess reports (and deployLaneWorkstations decides on)
 * moments later, with a better message than this could give.
 *
 * @returns {Promise<boolean>} whether firstboot was observed to finish.
 */
async function waitForGatewayFirstboot(
  node, gatewayVmid,
  // probeMs is injectable for the same reason retryMs and pollMs are: proving
  // that "container not running" does NOT consume the 5-error give-up budget
  // takes more than five probes, and at the production 3s interval that is a
  // 15-second test. Production passes neither.
  //
  // subnetScheme is VESTIGIAL — accepted and ignored. It used to gate a v1
  // early-return: template 1692 never received 00-cybercore-firstboot.start, so
  // the marker this loop greps for could never appear on a v1 lane and every one
  // of them burned the full 180s deadline. v1 is retired and both surviving
  // gateway generations (1694, 1695) write the marker, so THE WAIT IS NO LONGER
  // SKIPPED FOR ANYTHING. The option stays in the signature because five call
  // sites still pass it and they live in files this change does not own.
  { timeoutMs = 180000, logTag = '[Gateway]', probeMs = 3000, subnetScheme = null } = {}
) {
  const deadline = Date.now() + timeoutMs;
  const probe = [
    '/bin/sh', '-c',
    // The interface line differs by gateway generation, and BOTH are correct.
    // v2 renders one flat `interface=lan0`; the v3 segmented gateway renders
    // `interface=ext0` and `interface=int0` instead (the dnsmasq.conf heredoc
    // in bake-lane-gateway-v3.sh, around line 160). A probe that only knew
    // lan0 was never satisfied on a v3 lane: it sat out the full 180s, logged
    // "firstboot did not finish", and returned false every single time — which
    // on a malware profile is a hard deploy failure for a gateway that had
    // already finished booting. The rules-save marker below is written at v3
    // line ~415, still ahead of the tailscale bootstrap loop at ~445, so it is
    // reached in time on both generations.
    // `|| true` on the whole chain: pctExec rejects on a non-zero exit, and
    // "not ready yet" is the expected answer for most of this loop.
    `grep -qE '^interface=(lan0|ext0)' /etc/dnsmasq.conf && ` +
    `grep -q 'CYBERCORE-KALI-RDP' /etc/iptables/rules-save && echo firstboot-done || true`,
  ];

  let lastErr = null;
  let attempt = 0;
  let consecutiveErrors = 0;
  while (Date.now() < deadline) {
    if (attempt++ > 0) await new Promise(r => setTimeout(r, probeMs));
    try {
      const res = await nodeSsh.pctExec(node, gatewayVmid, probe, { timeoutMs: 30000 });
      consecutiveErrors = 0;
      if (String(res?.stdout || '').includes('firstboot-done')) return true;
    } catch (e) {
      // The container may not be far enough into its boot to run `pct exec` yet,
      // so an error is not automatically the end. But the whole budget must not
      // be spent on a channel that is never going to work: a lane deploy that
      // cannot SSH the node is a supported (degraded) outcome, and burning the
      // full timeout per lane before reaching it would turn one misconfigured
      // key into a class-wide stall. Anything that names a broken channel stops
      // immediately; everything else gets a few retries.
      lastErr = e;
      // "container not running" is the DEFINITION of not-ready-yet, not a broken
      // channel. Counting it toward the give-up budget is what made a slow boot
      // look like an unreachable node: five of these inside 15s and the probe
      // abandoned a gateway that was still starting.
      if (/not running/i.test(e.message)) continue;
      consecutiveErrors++;
      const fatal = /missing or unreadable|permission denied|could not resolve|connection refused|no route to host/i
        .test(e.message);
      if (fatal || consecutiveErrors >= 5) {
        console.warn(
          `${logTag} Gateway ${gatewayVmid} on ${node}: cannot probe firstboot over SSH ` +
          `(${e.message.split('\n')[0]}) — continuing without waiting for it`
        );
        return false;
      }
    }
  }
  console.warn(
    `${logTag} Gateway ${gatewayVmid} on ${node}: firstboot did not finish within ` +
    `${Math.round(timeoutMs / 1000)}s — continuing, but its boot-time config may overwrite ` +
    `the lane's DHCP reservations and console DNATs` +
    (lastErr ? ` (last probe error: ${lastErr.message.split('\n')[0]})` : '')
  );
  return false;
}

module.exports = {
  startGatewayAndConfirm,
  ensureGatewayRunning,
  confirmGatewayRunning,
  readGatewayStatus,
  waitForGatewayFirstboot,
  GATEWAY_START_ATTEMPTS,
  GATEWAY_START_RETRY_MS,
};
