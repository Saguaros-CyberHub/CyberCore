/**
 * ============================================================================
 * NODE BRIDGES
 * "Does this node actually have this SDN VNet bridge yet?"
 *
 * WHY THIS EXISTS
 * Creating an environment carves a VXLAN block -- a zone plus one VNet per lane
 * (two on v3) -- and commits it with a single cluster-wide `PUT /cluster/sdn`.
 * That commit does NOT create bridges. It makes every node queue its own
 * "SRV Networking" reload (`ifreload -a`), and those run independently and at
 * wildly different speeds: the shared ciabprof zone carries hundreds of VNets,
 * so one node can be finished in a minute while another is still working an
 * hour later. Until a node's reload lands, the VNet bridge does not exist in
 * that node's kernel and anything cabled to it dies at start with
 *
 *     bridge 'aaaabgdc' does not exist
 *
 * Placement used to be blind to this, so a deploy started minutes after an
 * environment was created sprayed lanes across every online node and the ones
 * on still-reloading nodes all failed. The fix is to ask each node what it
 * actually has before placing anything there; this module is that question, and
 * nothing more.
 *
 * DEPENDENCIES ARE DELIBERATELY ONE FILE.
 * node-selector.js needs this at placement time, and node-selector is loaded by
 * every deploy test in the suite. lab-network-provision.js -- where the same
 * probe already lived, inside verifyBridgesOnAllNodes -- pulls in cybercore-db,
 * reconcile-audit, lane-claims and site-config, which is far too much to drag
 * into the scheduler. So the probe moved HERE and verifyBridgesOnAllNodes calls
 * it, which also means the readiness badge and the placement filter can never
 * disagree about what "the bridge is up" means.
 * ============================================================================
 */

const { proxmoxAPI } = require('./proxmox');

/** Per-node probe timeout. A node mid-ifreload can simply stop answering. */
const BRIDGE_PROBE_MS = 10000;

/**
 * THE ONE PREDICATE. Everything that asks "is this bridge up on this node"
 * answers through this function.
 *
 * GET /nodes/<node>/network is built from the node's interface CONFIG -- which
 * includes /etc/network/interfaces.d/sdn, and that file is written at the START
 * of the srvreload task, before `ifreload -a` has brought anything up. Proxmox
 * then decorates each row with `exists: 1` (the interface is in /proc/net/dev)
 * and `active: 1` (ifupdown2 reports it up), and it sets those keys ONLY when
 * they are true -- a configured-but-not-yet-created VNet comes back as a row
 * with neither key rather than with active: 0.
 *
 * So a lenient "is it listed" check reports a bridge as present for the entire
 * window this module exists for. Require the kernel-level evidence instead.
 * Either key is that evidence (`exists` is not set for every interface type on
 * every PVE version), hence the OR.
 */
function bridgeIsUp(row) {
  if (!row || typeof row.iface !== 'string' || row.iface === '') return false;
  return Number(row.active) === 1 || Number(row.exists) === 1;
}

/**
 * The interface names that are actually up on one node.
 * Throws on a transport failure -- the caller decides what an unanswered node
 * means, and for placement it means "not this node", not "fail the deploy".
 *
 * @returns {Promise<Set<string>>}
 */
async function readNodeBridges(node, { perCallMs = BRIDGE_PROBE_MS } = {}) {
  const rows = await proxmoxAPI(
    'GET', `/api2/json/nodes/${node}/network`, null, { timeoutMs: perCallMs }
  );
  const up = new Set();
  for (const r of (Array.isArray(rows) ? rows : [])) {
    if (bridgeIsUp(r)) up.add(r.iface);
  }
  return up;
}

/**
 * Normalize whatever a caller has to hand into a list of VNet names.
 * Accepts bare strings and the vnet objects from GET /cluster/sdn/vnets
 * ({ vnet, zone, tag }), skips null/undefined/'' (so `[vnet, vnetInt]` works
 * unguarded on v2, where vnetInt is null), and de-duplicates while keeping
 * order -- a batch's union is built by flattening every lane's pair.
 *
 * @param {Array<string|{vnet:string}|null|undefined>} items
 * @returns {string[]}
 */
function bridgeNames(items) {
  const out = [];
  const seen = new Set();
  for (const it of (Array.isArray(items) ? items : [])) {
    if (!it) continue;
    const name = typeof it === 'string' ? it : it.vnet;
    if (typeof name !== 'string' || name === '') continue;
    if (seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  return out;
}

/**
 * Ask every node, at once, whether it has every one of `names`.
 *
 * NEVER THROWS. A node that cannot be reached is reported as unreachable, which
 * for every caller means the same thing as missing -- do not put a lane there --
 * but reads completely differently in a log line at 2am.
 *
 * CONCURRENTLY, with a per-call timeout, because serially sweeping nine nodes
 * on proxmoxAPI's 30s default would let two wedged nodes eat the whole budget
 * before a single healthy one was asked.
 *
 * @param {string[]} nodes
 * @param {string[]} names   bridge names that must ALL be present
 * @returns {Promise<{
 *   ready: string[],                        // has every name, in INPUT order
 *   missingByNode: {[node:string]: string[]},  // answered, short these names
 *   unreachable:   {[node:string]: string},    // did not answer, why
 *   presentByNode: {[node:string]: string[]},  // of `names`, what it does have
 * }>}
 */
async function probeNodesForBridges(nodes, names, { perCallMs = BRIDGE_PROBE_MS } = {}) {
  const nodeList = (Array.isArray(nodes) ? nodes : []).map(String);
  const want = bridgeNames(names);
  const result = { ready: [], missingByNode: {}, unreachable: {}, presentByNode: {} };

  // Nothing to require, or nobody to ask: answer without touching Proxmox. This
  // is what keeps every existing placement path -- which passes no bridges at
  // all -- exactly as cheap as it was before this module existed.
  if (nodeList.length === 0) return result;
  if (want.length === 0) {
    result.ready = [...nodeList];
    for (const n of nodeList) result.presentByNode[n] = [];
    return result;
  }

  const seen = await Promise.all(nodeList.map(async (node) => {
    try {
      const up = await readNodeBridges(node, { perCallMs });
      return { node, up };
    } catch (e) {
      return { node, error: e.message || String(e) };
    }
  }));

  // Rebuilt in INPUT order rather than settle order: the placement log names
  // these nodes, and a list that reshuffles itself between two identical
  // deploys is a list nobody can diff.
  for (const s of seen) {
    if (s.error !== undefined) {
      result.unreachable[s.node] = s.error;
      continue;
    }
    const present = want.filter(n => s.up.has(n));
    const missing = want.filter(n => !s.up.has(n));
    result.presentByNode[s.node] = present;
    if (missing.length === 0) result.ready.push(s.node);
    else result.missingByNode[s.node] = missing;
  }

  return result;
}

module.exports = {
  BRIDGE_PROBE_MS,
  bridgeIsUp,
  readNodeBridges,
  bridgeNames,
  probeNodesForBridges,
};
