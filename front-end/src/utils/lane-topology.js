/**
 * lane-topology.js — the live shape of a deployed lane.
 *
 * Returns the same { segments, gateway, nodes } payload the authoring canvas
 * consumes, so one renderer draws both a spec and a running lane.
 *
 * ── Placement comes from PROXMOX, not from the challenge spec ────────────────
 * Each VM's config is read and its netN `bridge=` matched against the lane's
 * VNets. That is the entire point of a live view: it shows what is actually
 * wired, so drift between the spec and reality is visible rather than assumed
 * away. A machine whose bridge is not one of this lane's VNets comes back with an
 * empty `segments` array — worth seeing as unattached rather than silently pinned
 * to a segment it may not be on.
 *
 * IPs are taken from the stored deployment record rather than the guest agent. A
 * guest-agent sweep would be per-VM, slow, and hangs on stopped machines; this
 * has to answer fast enough to sit behind a button.
 *
 * ── Why it lives in utils/ ──────────────────────────────────────────────────
 * Two callers need it and neither may have its own copy: the admin route
 * (GET /api/admin/lanes/:laneId/topology, adminOnly, any lane) and the CLE
 * instructor route (GET /api/cle/courses/:courseId/vms/:laneId/topology,
 * instructorOnly, scoped to lanes in a course the caller manages). The auth and
 * scoping differ; the diagram must not.
 */

const { proxmoxAPI } = require('./proxmox');
const { cybercoreQuery } = require('./cybercore-db');
const { query } = require('./db');
const { resolveSegments } = require('./lane-networking');

/**
 * buildLaneTopology(laneId) → { lane, segments, gateway, nodes }
 *
 * Throws an Error tagged `.status = 404` when the lane does not exist, so both
 * callers can map it straight onto a response code. Callers are responsible for
 * authorization — this function will describe any lane it is handed.
 */
async function buildLaneTopology(laneId) {
  const laneRow = await cybercoreQuery(
    `SELECT lane_id, vxlan_id, name, status, config, module_key FROM cybercore_lane WHERE lane_id = $1`,
    [laneId]
  );
  if (laneRow.rows.length === 0) {
    const err = new Error('Lane not found');
    err.status = 404;
    throw err;
  }

  const lane = laneRow.rows[0];
  const config = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

  // subnet_scheme is recorded on the lane; older rows predate it, so fall back
  // to the presence of an internal VNet rather than assuming v1.
  const subnetScheme = config.subnet_scheme || (config.vnet_internal ? 'v3' : 'v1');

  const cidr = (base) => (base ? `${base}.0/24` : null);
  const segments = resolveSegments(subnetScheme).map(seg => ({
    ...seg,
    cidr: seg.id === 'int' ? cidr(config.lane_subnet_internal) : cidr(config.lane_subnet_base),
    vnet: seg.id === 'int' ? config.vnet_internal : config.vnet,
  }));

  // bridge name → segment id, for reading a VM's real attachments back.
  const segForBridge = {};
  segments.forEach(s => { if (s.vnet) segForBridge[s.vnet] = s.id; });

  // Stored per-VM IPs, when a vuln-script deployment recorded them.
  const ipByName = {};
  try {
    const dep = await query(
      `SELECT deployed_network FROM deployment_vuln_selections
        WHERE lane_id = $1 ORDER BY created_at DESC LIMIT 1`, [laneId]
    );
    const net = dep.rows[0]?.deployed_network;
    const parsed = typeof net === 'string' ? JSON.parse(net || '{}') : (net || {});
    (parsed.vms || []).forEach(v => { if (v.name && v.ip) ipByName[v.name] = v.ip; });
  } catch (e) {
    // clinic_db is a separate database and may be unavailable; IPs are a
    // nicety here, not the point of the view.
    console.warn(`[LaneTopology] No stored IPs for lane ${laneId}: ${e.message}`);
  }

  const nodes = [];
  for (const vm of (config.vms || [])) {
    const type = vm.type === 'lxc' ? 'lxc' : 'qemu';
    let attached = [];
    let powerState = null;

    try {
      const cfg = await proxmoxAPI('GET', `/api2/json/nodes/${vm.node}/${type}/${vm.vm_id}/config`);
      // netN order IS nic order, so sort numerically before mapping.
      Object.keys(cfg || {})
        .filter(k => /^net\d+$/.test(k))
        .sort((a, b) => Number(a.slice(3)) - Number(b.slice(3)))
        .forEach(k => {
          const m = String(cfg[k]).match(/bridge=([^,]+)/);
          const segId = m && segForBridge[m[1]];
          if (segId && attached.indexOf(segId) === -1) attached.push(segId);
        });
      const status = await proxmoxAPI('GET', `/api2/json/nodes/${vm.node}/${type}/${vm.vm_id}/status/current`);
      powerState = status?.status || null;
    } catch (e) {
      // A destroyed or migrated VM must not blank the whole diagram.
      console.warn(`[LaneTopology] Could not read ${type}/${vm.vm_id} on ${vm.node}: ${e.message}`);
    }

    nodes.push({
      id: String(vm.vm_id),
      name: vm.name,
      role: vm.role || '',
      os: vm.os || vm.templateName || '',
      type,
      vmid: vm.vm_id,
      node: vm.node,
      ip: ipByName[vm.name] || null,
      power_state: powerState,
      // Empty means Proxmox reported a bridge that is not one of this lane's
      // VNets (or the read failed) — worth seeing as an unattached machine
      // rather than silently pinning it to a segment it may not be on.
      segments: attached,
    });
  }

  return {
    lane: {
      lane_id: lane.lane_id, name: lane.name, status: lane.status,
      vxlan_id: lane.vxlan_id, module: lane.module_key,
      challenge_key: config.challenge_key || null, subnet_scheme: subnetScheme,
    },
    segments,
    gateway: config.gateway_vm_id
      ? { label: `Lane gateway\n${config.gateway_vm_id}` }
      : { label: 'Lane gateway' },
    nodes,
  };
}

module.exports = { buildLaneTopology };
