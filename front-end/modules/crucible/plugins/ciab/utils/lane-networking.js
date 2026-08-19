/**
 * Lane Networking Helpers (CIAB-local)
 * ============================================================================
 * RE-EXPORT of src/utils/lane-networking.js. This file used to be a hand-mirrored
 * copy of the same primitives.
 *
 * The "self-contained so CIAB survives a refactor" rationale had been false since
 * this file started requiring cybercore-db, proxmox and tailscale across the same
 * boundary. What the duplication actually bought was a SECOND, hardcoded
 * 100.100.60.0/24 that ignored config/site.json and re-derived lane gateway WAN
 * addresses from `10 + vxlanId % 240` — into the very same VLAN the shared
 * allocator hands addresses out of. Widening the pool in site.json would have
 * fixed the shared module and left this one minting collisions against it,
 * cross-module and invisible.
 *
 * So: one implementation, one pool, one allocator. Only the CIAB-flavoured
 * Tailscale log tag and forceDestroyVM stay local.
 *
 * WAN addresses are ALLOCATED, not derived — see src/utils/lane-wan-allocator.js.
 * resolveLaneNetworking now requires the lane's address in opts.wanIp for v2/v3.
 */

const shared = require('../../../../../src/utils/lane-networking');
const { proxmoxAPI, waitForTask } = require('../../../../../src/utils/proxmox');

// ─── Forced VM destroy (for teardown + retry-cleanup) ───────────────────────

async function forceDestroyVM(vmid, type, knownNode) {
  const nodes = knownNode ? [knownNode] : [];
  if (nodes.length === 0) {
    try {
      const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
      for (const n of nodeList) nodes.push(n.node);
    } catch (_) {
      nodes.push('cyberhub-node-5');
    }
  }

  for (const node of nodes) {
    try {
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { protection: 0 }); } catch (_) {}
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { lock: '' });        } catch (_) {}
      try {
        const stopBody = type === 'qemu' ? { timeout: 0 } : {};
        await proxmoxAPI('POST', `/api2/json/nodes/${node}/${type}/${vmid}/status/stop`, stopBody);
        await new Promise(r => setTimeout(r, 3000));
      } catch (_) {}
      const upid = await proxmoxAPI('DELETE', `/api2/json/nodes/${node}/${type}/${vmid}?purge=1&force=1`);
      if (upid) { try { await waitForTask(node, upid, 600000); } catch (_) {} }
      console.log(`[CIAB Teardown] Destroyed ${type} ${vmid} on ${node}`);
      return true;
    } catch (e) {
      if (/unable to find configuration file/i.test(e.message)) continue;
      continue;
    }
  }
  return false;
}

// Descriptor copy, NOT `{ ...shared }`. The shared module exports
// TRANSIT_BY_MODULE and V2_LAB_NETWORK as lazy getters so config/site.json is
// read on first access rather than at import. A spread INVOKES those getters at
// require time — which both defeats the laziness and makes this module throw at
// import on any host where site.json is not readable yet.
module.exports = Object.defineProperties({}, {
  ...Object.getOwnPropertyDescriptors(shared),
  // CIAB's deploy logs are read on their own; keep the tag it has always used.
  configureLaneTailscale: {
    value: (opts) => shared.configureLaneTailscale({ logTag: '[CIAB Deploy]', ...opts }),
    enumerable: true,
  },
  forceDestroyVM: { value: forceDestroyVM, enumerable: true },
});
