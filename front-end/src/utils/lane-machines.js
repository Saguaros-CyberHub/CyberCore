/**
 * ============================================================================
 * LANE MACHINE ENUMERATION
 *
 * Every machine on a lane EXCEPT the gateway, from all three places a lane
 * config records them. Pure: no I/O, no DB, no Proxmox.
 *
 * A lane's machines are not in one list, and every feature that has needed
 * "all of them" has had to know all three shapes:
 *
 *   config.workstations[]          the student's own machines (VM Management)
 *   config.attached_modules[].vms[]  vulnerable-lab boxes attached to the lane
 *   config.vms[]                   a challenge/dedicated environment lane
 *
 * src/incident/target.js:199 already normalises the same three for attack
 * dispatch, and this is deliberately its sibling rather than a rewrite. Two
 * differences, both load-bearing:
 *
 *   - IT DROPS LXC, THIS DOES NOT. That one needs guest-agent exec, which is
 *     QEMU-only, so an LXC is not a candidate at all. Power control works on
 *     both, so excluding containers here would silently skip machines.
 *
 *   - IT DROPS THE ATTACK BOX, THIS DOES NOT. Kali is never a log source, but
 *     it is very much a machine an instructor means by "restart everything" —
 *     on a v3 GOAD lane it is the student's own console.
 *
 * THE GATEWAY IS THE ONE EXCLUSION, and it is not a preference. The gateway LXC
 * carries the lane's VXLAN endpoint, its dnsmasq reservations and every console
 * DNAT rule. Power-cycling it drops every student's RDP/SSH session, takes DHCP
 * away from machines that reboot alongside it, and leaves the lane unreachable
 * for as long as it takes to come back — while fixing nothing, because the
 * problem an instructor is restarting to clear is inside the guests.
 * ============================================================================
 */

// gateway LXC = 100000 + vxlanId. Duplicated from lane-deployer's
// GATEWAY_VMID_OFFSET rather than imported: that module pulls in the DB, the
// Proxmox client and Guacamole at require time, and this one must stay pure so
// it can be unit-tested and required from anywhere.
const GATEWAY_VMID_OFFSET = 100000;

/**
 * The lane's gateway VMID.
 *
 * Recorded under two different key names by two different deploy paths, and
 * derivable from the VXLAN id when neither is present — which is the case for
 * lanes built before the key existed. All three are checked because getting
 * this wrong does not fail loudly: it just means the gateway is not recognised
 * as the gateway, and the next "restart everything" takes the whole lane down.
 */
function laneGatewayVmid(lane) {
  const cfg = (lane && lane.config) || {};
  const explicit = cfg.gateway_vmid ?? cfg.gateway_vm_id;
  if (explicit != null && Number.isFinite(Number(explicit))) return Number(explicit);
  const vxlan = lane && lane.vxlan_id;
  return vxlan != null && Number.isFinite(Number(vxlan))
    ? GATEWAY_VMID_OFFSET + Number(vxlan)
    : null;
}

/**
 * Every non-gateway machine on one lane, de-duplicated by VMID.
 *
 * De-duplication matters: a machine can legitimately appear in more than one
 * list (an attached module's VM that was also recorded as a workstation slot),
 * and a duplicate here means powering the same guest off twice — the second
 * shutdown lands on a machine that is already down and the start races it.
 *
 * @param {object} lane  a cybercore_lane row ({ lane_id, vxlan_id, config, name })
 * @returns {Array<{vmid, provider_type, slot, kind, name, template_id, template_name, node}>}
 */
function laneMachines(lane) {
  const cfg = (lane && lane.config) || {};
  const gatewayVmid = laneGatewayVmid(lane);
  const seen = new Set();
  const out = [];

  const push = (raw, extra) => {
    const vmid = Number(raw);
    if (!Number.isInteger(vmid) || vmid <= 0) return;
    if (gatewayVmid != null && vmid === gatewayVmid) return;   // the one exclusion
    if (seen.has(vmid)) return;
    seen.add(vmid);
    out.push({
      vmid,
      provider_type: extra.provider_type || null,
      slot: extra.slot ?? null,
      kind: extra.kind,
      name: extra.name || null,
      template_id: extra.template_id || null,
      template_name: extra.template_name || null,
      // Which vulnerable-lab material this machine belongs to, when it belongs
      // to one. The Environments tab restarts ONE environment's machines, and
      // an attached lane usually carries the student's own workstations
      // alongside another lab's boxes — without this the tab would restart all
      // of them.
      material_id: extra.material_id || null,
      // Advisory only. Every caller re-resolves the live node from
      // /cluster/resources, because a migrated VM's recorded node is stale and
      // a power call against the wrong host just fails.
      node: extra.node || cfg.node || null,
    });
  };

  // ── the student's own machines ───────────────────────────────────────────
  const ws = Array.isArray(cfg.workstations) ? cfg.workstations : [];
  if (ws.length) {
    for (const w of ws) {
      if (!w) continue;
      push(w.vmid, {
        provider_type: w.provider_type, slot: w.slot, kind: 'workstation',
        name: w.hostname || w.name, template_id: w.template_id,
        template_name: w.template_name, node: w.node,
      });
    }
  } else if (cfg.workstation_vmid) {
    // A lane deployed before config.workstations[] existed carries only the
    // flat slot-0 keys. Without this branch every such lane reports no machines
    // and a restart silently does nothing to it.
    push(cfg.workstation_vmid, {
      provider_type: cfg.provider_type, slot: 0, kind: 'workstation',
      name: (lane && lane.name) || null, template_id: cfg.template_id,
      template_name: cfg.template_name,
    });
  }

  // ── a challenge / dedicated environment lane's own machines ──────────────
  for (const vm of (Array.isArray(cfg.vms) ? cfg.vms : [])) {
    if (!vm) continue;
    push(vm.vm_id ?? vm.vmid, {
      provider_type: vm.type || vm.providerType || vm.provider_type,
      kind: 'environment',
      name: vm.name || vm.proxmox_name,
      template_id: vm.template_id, node: vm.node,
      // A dedicated lab lane's machines all belong to the lane's own material.
      material_id: cfg.material_id,
    });
  }

  // ── vulnerable-lab machines attached to this lane ────────────────────────
  for (const mod of (Array.isArray(cfg.attached_modules) ? cfg.attached_modules : [])) {
    for (const vm of (Array.isArray(mod && mod.vms) ? mod.vms : [])) {
      if (!vm) continue;
      push(vm.vm_id ?? vm.vmid, {
        provider_type: vm.type || vm.providerType || vm.provider_type,
        kind: 'environment',
        name: vm.name || vm.proxmox_name,
        template_id: vm.template_id, node: vm.node,
        // From the INSTANCE, not the VM: attachLabToLane stamps material_id on
        // the instance it appends to attached_modules[].
        material_id: mod.material_id,
      });
    }
  }

  return out;
}

module.exports = { laneMachines, laneGatewayVmid, GATEWAY_VMID_OFFSET };
