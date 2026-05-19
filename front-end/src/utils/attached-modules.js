/**
 * ============================================================================
 * Attached-module orchestration helpers
 * ============================================================================
 * An "attached module" is a small set of VMs (typically 1-3) grafted onto an
 * already-running lane at runtime. Used for week-of-course content delivery —
 * e.g., the instructor attaches a DVWA box to every student lane in week 3,
 * then detaches it in week 4. The base lane (GOAD + gateway + Kali) stays up
 * across attach/detach cycles.
 *
 * Attached VMs sit on the same VXLAN as the base lane so the student's Kali
 * can reach them at <lane_subnet>.<ip_octet>. DHCP reservations are written
 * to a per-instance file inside the lane gateway so detach is a clean
 * one-file delete + dnsmasq reload.
 *
 * VMID encoding (cluster-unique, deterministic per (slot, vxlanId)):
 *
 *   vmid = 800000 + (slot * 10000) + vxlan_id
 *
 *   slot   range          example (vxlan 10000)
 *   ----   --------       --------------------
 *   0      800000-809999  → 810000
 *   1      810000-819999  → 820000
 *   ...
 *   9      890000-899999  → 900000   (LAST SLOT)
 *
 * 10 attached-VM slots per lane. Each attached MODULE consumes one slot per
 * VM it contains, so a 2-VM module takes slots [N, N+1]. With vxlan span <
 * 10000 the encoding is collision-free.
 *
 * IP octets are allocated from .100+ to stay clear of GOAD's .10-.49 ranges
 * and the .1/.5/.20 infra reservations.
 *
 * MAC addresses are deterministic so dnsmasq can hand out the reserved IP
 * the moment the VM boots:  02:80:00:<slot>:<vxh>:<vxl>
 * (locally-administered, unicast — 0x02 in the first octet)
 * ============================================================================
 */

const { v4: uuidv4 } = require('uuid');
const nodeSsh = require('./node-ssh');

const ATTACHED_VMID_BASE   = 800000;
const ATTACHED_VMID_STEP   = 10000;
const ATTACHED_MAX_SLOTS   = 10;   // slots 0..9

const ATTACHED_IP_OCTET_MIN = 100;
const ATTACHED_IP_OCTET_MAX = 239; // .240+ reserved for future use

/**
 * Compute a deterministic MAC for an attached VM.
 * Format: 02:80:00:<slot_byte>:<vxh>:<vxl>
 *   - 0x02 in byte 0 marks the MAC as locally-administered (unicast).
 *   - 0x80:00 acts as the "attached-module" OUI-style prefix so these MACs
 *     are visually distinct from the GOAD MACs (which use a different prefix).
 *   - slot + vxlan bytes make the MAC unique within the cluster.
 */
function macForSlot(slot, vxlanId) {
  if (slot < 0 || slot >= ATTACHED_MAX_SLOTS) {
    throw new Error(`attached-module slot ${slot} out of range [0, ${ATTACHED_MAX_SLOTS})`);
  }
  const slotByte = (slot & 0xFF).toString(16).padStart(2, '0');
  const vxh = ((vxlanId >> 8) & 0xFF).toString(16).padStart(2, '0');
  const vxl = (vxlanId & 0xFF).toString(16).padStart(2, '0');
  return `02:80:00:${slotByte}:${vxh}:${vxl}`;
}

/**
 * Build VMID from slot + vxlan_id. Encoding is documented at the top.
 */
function vmidForSlot(slot, vxlanId) {
  if (slot < 0 || slot >= ATTACHED_MAX_SLOTS) {
    throw new Error(`attached-module slot ${slot} out of range [0, ${ATTACHED_MAX_SLOTS})`);
  }
  return ATTACHED_VMID_BASE + (slot * ATTACHED_VMID_STEP) + vxlanId;
}

/**
 * Find `count` free slots in a lane, respecting slots already consumed by
 * existing attached modules. Returns an array of slot integers ascending.
 * Throws if not enough slots are free.
 */
function findFreeSlots(attachedModules, count) {
  const used = new Set();
  for (const m of attachedModules || []) {
    for (const vm of m.vms || []) {
      if (typeof vm.slot === 'number') used.add(vm.slot);
    }
  }
  const free = [];
  for (let s = 0; s < ATTACHED_MAX_SLOTS && free.length < count; s++) {
    if (!used.has(s)) free.push(s);
  }
  if (free.length < count) {
    throw new Error(
      `Lane has only ${free.length} free attached-module slots, ` +
      `but the module requires ${count}. ` +
      `Detach an existing module first (${used.size}/${ATTACHED_MAX_SLOTS} used).`
    );
  }
  return free;
}

/**
 * Allocate IP octets for the attached VMs. Honors `vm.ipOctet` in the spec
 * if present; otherwise picks the next free octet from .100 upward, skipping
 * any already-claimed octets across the lane.
 *
 * Returns: array of integer octets, same length as spec.vms.
 */
function allocateIpOctets(attachedModules, specVms) {
  const used = new Set();
  for (const m of attachedModules || []) {
    for (const vm of m.vms || []) {
      if (typeof vm.ip_octet === 'number') used.add(vm.ip_octet);
    }
  }

  const out = [];
  let cursor = ATTACHED_IP_OCTET_MIN;
  for (const vm of specVms) {
    let octet;
    if (typeof vm.ipOctet === 'number') {
      if (used.has(vm.ipOctet)) {
        throw new Error(
          `Attached VM '${vm.name}' requested IP octet .${vm.ipOctet}, ` +
          `but it's already claimed on this lane.`
        );
      }
      octet = vm.ipOctet;
    } else {
      while (used.has(cursor) && cursor <= ATTACHED_IP_OCTET_MAX) cursor++;
      if (cursor > ATTACHED_IP_OCTET_MAX) {
        throw new Error(`Out of attached-module IP octets in range [${ATTACHED_IP_OCTET_MIN}, ${ATTACHED_IP_OCTET_MAX}]`);
      }
      octet = cursor++;
    }
    used.add(octet);
    out.push(octet);
  }
  return out;
}

/**
 * Render a per-module dnsmasq reservations snippet. One file per attached
 * module instance so detach is a clean unlink.
 */
function renderDhcpFile(moduleInstanceId, challengeKey, attachedVms) {
  const lines = [
    `# Attached module ${challengeKey} (instance ${moduleInstanceId})`,
    `# Generated by attached-modules.js — do not hand-edit`
  ];
  for (const vm of attachedVms) {
    lines.push(`dhcp-host=${vm.mac},${vm.ip},${vm.name}`);
  }
  return lines.join('\n') + '\n';
}

function dhcpFilePathFor(moduleInstanceId) {
  return `/etc/dnsmasq.d/attached-${moduleInstanceId}.conf`;
}

/**
 * Push the per-module DHCP file into the lane gateway LXC and reload dnsmasq.
 * Mirrors goad-deploy.writeDhcpReservations but writes a fresh file per
 * module instead of rewriting the whole reservations table.
 */
async function writeDhcpForModule({ bestNode, gatewayVmId, moduleInstanceId, challengeKey, attachedVms }) {
  const conf = renderDhcpFile(moduleInstanceId, challengeKey, attachedVms);
  await nodeSsh.pctPushFromString(bestNode, gatewayVmId, conf, dhcpFilePathFor(moduleInstanceId));
  await reloadDnsmasq(bestNode, gatewayVmId);
}

/**
 * Delete the per-module DHCP file and reload dnsmasq. Safe to call on a lane
 * gateway that has no such file — `rm -f` swallows missing-file errors.
 */
async function removeDhcpForModule({ bestNode, gatewayVmId, moduleInstanceId }) {
  await nodeSsh.pctExec(bestNode, gatewayVmId, [
    '/bin/sh', '-c', `rm -f ${dhcpFilePathFor(moduleInstanceId)}`
  ]);
  await reloadDnsmasq(bestNode, gatewayVmId);
}

async function reloadDnsmasq(bestNode, gatewayVmId) {
  await nodeSsh.pctExec(bestNode, gatewayVmId, [
    '/bin/sh', '-c',
    'rc-service dnsmasq restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true'
  ]);
}

/**
 * Build a net0/net1 string for an attached VM clone. Mirrors goad-deploy.buildLaneNet0
 * but always specifies a hwaddr (DHCP reservation depends on it) and defaults
 * to virtio for QEMU (these are Linux VMs — no Windows AD-join NIC concerns).
 */
function buildAttachedNet0(vmSpec, vnetName, mac) {
  const type = vmSpec.type || 'qemu';
  if (type === 'lxc') {
    return `name=lan0,bridge=${vnetName},hwaddr=${mac}`;
  }
  const model = vmSpec.nic_model || 'virtio';
  return `${model},bridge=${vnetName},macaddr=${mac}`;
}

/**
 * Attach a challenge's VMs to an already-running lane.
 *
 * Caller provides:
 *   - lane:         row from cybercore_lane (must be 'active')
 *   - laneConfig:   parsed JSONB config from the lane row
 *   - challenge:    row from cybercore_challenge (spec already parsed)
 *   - spec:         parsed challenge spec (must have spec.attachable === true)
 *   - laneSubnetBase: e.g., '10.39.17' for v2, '192.18.0' for v1
 *   - vnetName, bestNode, templateNode, gatewayVmId: from the lane
 *   - proxmoxAPI, waitForTask: orchestration helpers from admin.js
 *
 * Returns:
 *   { module_instance_id, vms: [{ vm_id, name, type, slot, ip_octet, ip, mac, node }] }
 *
 * The caller is responsible for persisting the returned record into
 * cybercore_lane.config.attached_modules.
 */
async function attachModuleToLane({
  lane, laneConfig, challenge, spec, module,
  laneSubnetBase, vnetName, bestNode, templateNode, gatewayVmId,
  proxmoxAPI, waitForTask
}) {
  if (!spec || spec.attachable !== true) {
    throw new Error(`Challenge '${challenge.challenge_key}' is not marked attachable (spec.attachable must be true)`);
  }
  const specVms = Array.isArray(spec.vms) ? spec.vms : [];
  if (specVms.length === 0) {
    throw new Error(`Challenge '${challenge.challenge_key}' has no vms[] in spec`);
  }

  const vxlanId = lane.vxlan_id;
  const attachedModules = Array.isArray(laneConfig.attached_modules) ? laneConfig.attached_modules : [];

  // Slot + IP allocation — fail fast before touching Proxmox if either runs out.
  const slots = findFreeSlots(attachedModules, specVms.length);
  const ipOctets = allocateIpOctets(attachedModules, specVms);

  const moduleInstanceId = uuidv4();
  const laneName = lane.name;

  const attachedVms = [];

  for (let i = 0; i < specVms.length; i++) {
    const vmSpec = specVms[i];
    const slot = slots[i];
    const ipOctet = ipOctets[i];
    const vmId = vmidForSlot(slot, vxlanId);
    const mac = macForSlot(slot, vxlanId);
    const ip = `${laneSubnetBase}.${ipOctet}`;
    const vmType = vmSpec.type || 'qemu';
    const vmTemplate = vmSpec.template_vmid;
    const vmName = vmSpec.name || `${challenge.challenge_key}-${i}`;
    const hostname = `${laneName}-${vmName}`
      .replace(/[^a-z0-9-]/gi, '-')
      .substring(0, 63)
      .toLowerCase();

    if (!vmTemplate) {
      throw new Error(`Attached VM spec '${vmName}' missing template_vmid`);
    }

    console.log(`[Attach] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName}) on ${bestNode} for lane ${lane.lane_id}`);

    const clonePath = vmType === 'lxc'
      ? `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`
      : `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`;
    const cloneBody = {
      newid: vmId,
      [vmType === 'lxc' ? 'hostname' : 'name']: hostname,
      full: 1,
      target: bestNode,
      description: `Attached module: ${challenge.challenge_key}\nInstance: ${moduleInstanceId}\nVM: ${vmName}\nLane: ${lane.lane_id}\nSlot: ${slot}`,
      pool: `${module}-pool`
    };

    const cloneResult = await proxmoxAPI('POST', clonePath, cloneBody);
    if (cloneResult) await waitForTask(templateNode, cloneResult);

    // Configure NIC on the lane VNet with the deterministic MAC. LXC uses net1
    // (eth0 stays on the host bridge from the template), QEMU uses net0.
    const netCfg = buildAttachedNet0(vmSpec, vnetName, mac);
    const configPath = vmType === 'lxc'
      ? `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`
      : `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`;
    const configBody = vmType === 'lxc'
      ? { net1: netCfg }
      : { net0: netCfg };
    // QEMU clones use POST for config (matches admin.js deploy path); LXC uses PUT.
    const configMethod = vmType === 'lxc' ? 'PUT' : 'POST';
    await proxmoxAPI(configMethod, configPath, configBody);

    attachedVms.push({
      vm_id: vmId,
      name: vmName,
      type: vmType,
      slot,
      ip_octet: ipOctet,
      ip,
      mac,
      node: bestNode
    });
  }

  // Write DHCP reservations BEFORE starting the VMs, so the first DHCP request
  // they make already has its reservation in dnsmasq.
  await writeDhcpForModule({
    bestNode, gatewayVmId,
    moduleInstanceId,
    challengeKey: challenge.challenge_key,
    attachedVms
  });

  // Start the VMs.
  for (const vm of attachedVms) {
    const startPath = vm.type === 'lxc'
      ? `/api2/json/nodes/${vm.node}/lxc/${vm.vm_id}/status/start`
      : `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/status/start`;
    await proxmoxAPI('POST', startPath);
  }

  return {
    module_instance_id: moduleInstanceId,
    challenge_key: challenge.challenge_key,
    challenge_id: challenge.challenge_id,
    attached_at: new Date().toISOString(),
    vms: attachedVms
  };
}

/**
 * Detach a previously-attached module: stop + destroy its VMs, delete its
 * DHCP file, and reload dnsmasq on the lane gateway. Mirrors the forceful
 * teardown helpers in admin.js's DELETE /lanes/:id but scoped to one module.
 *
 * Returns: { destroyed: [vmid...], errors: [string...] }
 */
async function detachModuleFromLane({
  moduleInstance, bestNode, gatewayVmId,
  proxmoxAPI, forceDestroyVM
}) {
  const errors = [];

  // 1. Remove the DHCP file FIRST so dnsmasq doesn't try to hand out IPs to
  //    hosts that no longer exist. Failure here is non-fatal — destroying the
  //    VMs is the load-bearing step.
  try {
    await removeDhcpForModule({
      bestNode,
      gatewayVmId,
      moduleInstanceId: moduleInstance.module_instance_id
    });
  } catch (e) {
    errors.push(`DHCP cleanup failed: ${e.message}`);
  }

  // 2. Destroy each VM. forceDestroyVM is passed in from admin.js so we reuse
  //    its protection-removal + retry logic exactly.
  const destroyed = [];
  for (const vm of moduleInstance.vms || []) {
    try {
      const ok = await forceDestroyVM(vm.vm_id, vm.type, vm.node);
      if (ok) destroyed.push(vm.vm_id);
      else errors.push(`${vm.name} (${vm.type} ${vm.vm_id}): not destroyed`);
    } catch (e) {
      errors.push(`${vm.name} (${vm.type} ${vm.vm_id}): ${e.message}`);
    }
  }

  return { destroyed, errors };
}

module.exports = {
  // Constants — exported so admin.js can extend CYBERHUB_RANGES with the
  // matching VMID range for the reconcile audit.
  ATTACHED_VMID_BASE,
  ATTACHED_VMID_STEP,
  ATTACHED_MAX_SLOTS,
  ATTACHED_IP_OCTET_MIN,
  ATTACHED_IP_OCTET_MAX,

  // Helpers (exported mainly for tests + reconcile)
  macForSlot,
  vmidForSlot,
  findFreeSlots,
  allocateIpOctets,
  renderDhcpFile,
  dhcpFilePathFor,
  writeDhcpForModule,
  removeDhcpForModule,

  // Main orchestration
  attachModuleToLane,
  detachModuleFromLane,
};
