/**
 * ============================================================================
 * PROXMOX PATH BUILDERS
 *
 * Pure string helpers for addressing a VM or container. No I/O, no state.
 *
 * WHY THIS IS NOT IN proxmox.js. It belongs there by topic, and it started
 * there — but proxmox.js is the network module, and six test files replace it
 * wholesale through require.cache to fake the cluster. Every pure helper living
 * inside it has to be re-supplied by each of those fakes, so adding one turns
 * into six unrelated test edits and a stub that quietly returns undefined the
 * day someone forgets. A module nobody needs to stub cannot have that problem.
 *
 * It also started as two byte-identical private copies, in lane-deployer.js and
 * routes/workstations.js, and the resize engine would have made a third. One
 * definition means the qemu/lxc decision cannot drift between them.
 * ============================================================================
 */

/**
 * The Proxmox API base path for one VM or container.
 *
 * provider_type 'lxc' -> /api2/json/nodes/{node}/lxc/{vmid}
 * anything else, including null/undefined -> .../qemu/{vmid}
 *
 * Defaulting to qemu rather than throwing on an unknown provider_type is
 * deliberate: lanes deployed before the column existed carry no provider_type
 * at all, and every one of them is a QEMU VM.
 */
function vmApiBase(node, vmid, providerType) {
  const kind = providerType === 'lxc' ? 'lxc' : 'qemu';
  return `/api2/json/nodes/${node}/${kind}/${vmid}`;
}

module.exports = { vmApiBase };
