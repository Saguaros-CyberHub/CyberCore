/**
 * ============================================================================
 * NODE HEALTH — short-lived, in-process quarantine for a Proxmox node that
 * just failed a deploy for a reason that was not the lane's fault
 * ============================================================================
 * THE INCIDENT
 * cyberhub-node-8 was added to the cluster and immediately started a Ceph
 * backfill. Every challenge lane the scheduler placed on it died the same way:
 * the gateway LXC (VMID 100000+vxlan, e.g. 110881) cloned fine, then `pct start`
 * failed with
 *
 *     lxc-start: ... Failed to run lxc.hook.pre-start for container "110881"
 *     ... exited with status 32
 *
 * because the pre-start hook lost the race for the udev-created symlink
 * /dev/rbd-pve/<fsid>/<pool>/<image>. udev on a backfilling node is late; the
 * hook does not wait. Nothing about the lane, the template, or the request was
 * wrong — the NODE was wrong, for the next several minutes.
 *
 * WHY A MODULE AND NOT JUST A RETRY
 * Retrying the start on the same node is the right first move and lives in the
 * deployers. This file solves the second-order problem: the very next lane in
 * the batch got scheduled onto node-8 as well, and the one after that, because
 * utils/node-selector.js scores on idle CPU and free RAM, and a node that is
 * busy doing nothing but Ceph backfill looks like the emptiest, most attractive
 * node in the cluster. The scheduler was actively steering the whole batch into
 * the one node that could not start a container. Before this module there was
 * no memory anywhere in the orchestrator of "that node just failed" — every
 * lane re-derived its placement from scratch and made the identical bad choice.
 *
 * WHY 15 MINUTES
 * Long enough to outlast a backfill burst and, more importantly, the rest of a
 * batch of lanes that is already in flight — the failure this exists to stop is
 * twenty lanes marching into the same hole inside ten minutes. Short enough
 * that a node which recovers on its own (backfill settles, udev catches up)
 * rejoins the pool without anyone being paged, and short enough that a stale
 * quarantine cannot quietly shrink the cluster for a whole shift. Override with
 * NODE_QUARANTINE_MS when debugging.
 *
 * THIS IS A STOPGAP. SAYING SO OUT LOUD IS PART OF THE FILE.
 * State here is per-process and dies with the process — a restart, a second app
 * container, or a deploy driven from a worker all begin with an empty Map. The
 * durable controls for a genuinely bad node are, and remain:
 *
 *   1. cluster.scheduling.excluded_nodes in config/site.json — survives
 *      restarts, applies to every process, and is visible to an operator
 *      reading the config rather than reading logs
 *   2. Proxmox HA maintenance mode on the node itself
 *
 * If a node is bad for longer than a coffee break it belongs in one of those
 * two. This module must NEVER be the only thing keeping a bad node out of the
 * scheduler. A node that keeps reappearing here — `count` climbing across
 * quarantines — is an operator alarm, not a solved problem.
 *
 * QUARANTINE IS SOFT
 * A caller that honours every quarantine and is then left with zero schedulable
 * nodes MUST ignore quarantine and place the lane anyway. Refusing to deploy
 * because the whole cluster is quarantined would turn a transient, self-healing
 * node fault into a total outage — strictly worse than trying a suspect node
 * and losing one lane. That policy is enforced in utils/node-selector.js, not
 * here, and it is exactly why quarantinedNodes() is a QUERY that hands back the
 * list rather than a filter that removes nodes on the caller's behalf. This
 * module reports; the scheduler decides.
 *
 * NO REQUIRES, DELIBERATELY. utils/node-selector.js requires this file and
 * utils/batch-deployer.js requires node-selector, so keeping this module
 * dependency-free is what guarantees there is no cycle to trip over.
 * ============================================================================
 */

'use strict';

/** How long one fault keeps a node out of the scheduler's preferred set. */
const NODE_QUARANTINE_MS = Number(process.env.NODE_QUARANTINE_MS) || 15 * 60 * 1000;

/** Longest reason kept. Room for a full lxc-start line, short enough to log. */
const MAX_REASON_LEN = 200;

/**
 * node name -> { reason, until, count }
 *
 * Module-level, and therefore per-process: see the STOPGAP note above. `count`
 * is cumulative across re-marks and is deliberately NOT reset when an entry
 * expires and the node is marked again, so a node that fails, recovers, then
 * fails again logs as "fault 3" instead of as three unrelated first-time blips.
 * That is the escalation signal the header calls an operator alarm, and it only
 * works if the row OUTLIVES its own quarantine window.
 *
 * So an expired entry is never deleted — it is simply no longer live, which
 * every reader decides with isLive() rather than by mutating the Map. Only
 * clearNodeFault() and _resetForTests() remove anything, and clearNodeFault
 * resetting the count is correct: an operator saying "this node is fine now" is
 * exactly the statement that the history no longer applies.
 *
 * The Map is therefore keyed by node name and bounded by the size of the
 * cluster (about a dozen rows), not by the number of faults, so retaining
 * expired rows costs nothing worth reclaiming.
 */
const faults = new Map();

/**
 * Reasons come straight off a caught error. Keep the first line only: the
 * pct/lxc-start failures that motivated this module arrive as a multi-line
 * blob with a stack trace attached, and the useful sentence is always line one.
 */
function normalizeReason(reason) {
  const text = (reason === null || reason === undefined) ? '' : String(reason);
  const firstLine = text.split('\n')[0].trim();
  if (!firstLine) return 'unspecified fault';
  return firstLine.length > MAX_REASON_LEN
    ? `${firstLine.slice(0, MAX_REASON_LEN - 3)}...`
    : firstLine;
}

/**
 * Node names come from whatever Proxmox handed the caller, on a path that is
 * already handling a failure. A bad name returns null rather than throwing —
 * blowing up inside the error handler would hide the fault we are recording.
 */
function normalizeNode(node) {
  if (typeof node !== 'string') return null;
  const trimmed = node.trim();
  return trimmed || null;
}

/**
 * Is this entry's window still open? An expired entry is KEPT, not deleted —
 * see the note on `count` above. Expiry is a property of `until`, never of
 * whether the row exists.
 *
 * This used to be a pruning sweep that deleted expired rows, which quietly broke
 * the cumulative `count` contract: markNodeFault reads the previous entry to
 * increment, and every reader (isNodeQuarantined, called for every candidate on
 * every placement) deleted the row on its way past. So a node that failed,
 * recovered, and failed again logged "fault 1" instead of "fault 2", and the
 * escalation signal this module documents as its operator alarm never climbed.
 */
function isLive(entry, now) {
  return !!entry && entry.until > now;
}

/** "15 min" / "45 s" / "5 ms" — readable at every scale a caller passes. */
function formatDuration(ms) {
  if (ms >= 60000) return `${Math.round(ms / 60000)} min`;
  if (ms >= 1000) return `${Math.round(ms / 1000)} s`;
  return `${ms} ms`;
}

/**
 * Record that a node failed for a reason we believe belongs to the node rather
 * than to the lane. Extends an existing quarantine instead of replacing it: a
 * node that fails twice in a row gets a fresh full window measured from the
 * SECOND failure, not whatever was left of the first.
 *
 * @param {string} node    Proxmox node name, e.g. 'cyberhub-node-8'
 * @param {string} reason  what actually failed; only the first line is kept
 * @param {{ttlMs?: number}} [opts]  ttlMs overrides NODE_QUARANTINE_MS
 * @returns {{node: string, reason: string, until: number, count: number}|null}
 *          null when `node` is not a usable name
 */
function markNodeFault(node, reason, { ttlMs } = {}) {
  const name = normalizeNode(node);
  if (!name) return null;

  const now = Date.now();
  const ttl = (Number.isFinite(ttlMs) && ttlMs > 0) ? ttlMs : NODE_QUARANTINE_MS;
  const text = normalizeReason(reason);

  const existing = faults.get(name);
  const entry = {
    reason: text,
    until: now + ttl,
    count: (existing ? existing.count : 0) + 1,
  };
  faults.set(name, entry);

  console.warn(`[NodeHealth] ${name} quarantined for ${formatDuration(ttl)} (fault ${entry.count}): ${text}`);

  return { node: name, ...entry };
}

/**
 * Is this node currently quarantined? An expired entry is pruned on the way
 * past and answers false, so a node whose window closed is immediately
 * schedulable again with no sweep, timer, or operator action.
 *
 * @param {string} node
 * @returns {boolean}
 */
function isNodeQuarantined(node) {
  const name = normalizeNode(node);
  if (!name) return false;

  return isLive(faults.get(name), Date.now());
}

/**
 * Everything currently quarantined — for the scheduler to weigh, and for admin
 * diagnostics to tell an operator WHY a node is being passed over instead of
 * leaving them to guess from placement behaviour.
 *
 * A query, not a filter: see QUARANTINE IS SOFT in the header.
 *
 * @returns {Array<{node: string, reason: string, until: string, remaining_s: number, count: number}>}
 */
function quarantinedNodes() {
  const now = Date.now();

  return [...faults.entries()].filter(([, entry]) => isLive(entry, now)).map(([node, entry]) => ({
    node,
    reason: entry.reason,
    until: new Date(entry.until).toISOString(),
    remaining_s: Math.ceil((entry.until - now) / 1000),
    count: entry.count,
  }));
}

/**
 * Lift a quarantine early. An operator who has confirmed the node is healthy —
 * backfill finished, a hand-run `pct start` worked — should not have to wait
 * out the TTL or restart the app to get the node back in rotation.
 *
 * @param {string} node
 * @returns {boolean} true only if a quarantine was actually removed
 */
function clearNodeFault(node) {
  const name = normalizeNode(node);
  if (!name) return false;
  return faults.delete(name);
}

/**
 * Wipe all state. Test-only, hence the underscore: quarantine is deliberately
 * per-process, and there is no legitimate application reason to forget every
 * recorded fault at once. Use clearNodeFault(node) for the one node you have
 * actually verified.
 */
function _resetForTests() {
  faults.clear();
}

module.exports = {
  NODE_QUARANTINE_MS,
  markNodeFault,
  isNodeQuarantined,
  quarantinedNodes,
  clearNodeFault,
  _resetForTests,
};
