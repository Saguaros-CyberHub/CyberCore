/**
 * ============================================================================
 * TOPOLOGY VALIDATION
 * Pure checks over a challenge spec's machines and their network attachments.
 * ============================================================================
 *
 * Two of these (findGoadHostMismatch, findVmOffsetCollision) moved here from
 * challenge-lane-deployer.js, which still re-exports them so every deploy-time
 * caller is unchanged. The rest are new, and exist so the topology canvas can
 * show an author what is wrong BEFORE a lane is built rather than after.
 *
 * Everything here is pure — no DB, no Proxmox, no I/O. Callers that want the
 * catalog check pass `catalogVmids` in; callers that don't, don't.
 *
 * Severity contract:
 *   error   — this spec cannot deploy correctly. Block or refuse.
 *   warning — this spec deploys, but almost certainly not as intended.
 */

const goadDeploy = require('./goad-deploy');
const { DEFAULT_VM_OFFSET, resolveSegments, resolveVmSegments } = require('./lane-networking');

// Roles that are meant to sit outside the AD network, so a non-lab name on them
// is intentional rather than a typo. 'dmz' is the dual-homed pivot host;
// 'attacker' is the per-lane Kali the template editor adds by default.
const EXTERNAL_ROLES = new Set(['dmz', 'attacker']);

// ── the two legacy single-string checks, moved verbatim ──────────────────────

/**
 * On a GOAD lane, a spec VM only becomes an AD host if its NAME matches one in
 * the chosen GOAD lab definition (goad-deploy.GOAD_LABS). prepareGoadMacs keys
 * on that name, and everything downstream follows from it:
 *
 *   matched   → internal VNet, deterministic MAC, reserved IP, healed by the
 *               pre-baked GOAD pass
 *   unmatched → EXTERNAL VNet, random MAC, a pool lease, and skipped by the heal
 *
 * So a spec that says `SRV01` when the lab defines `SRV02` deploys a Windows box
 * that is on the wrong network segment, at an unpredictable address, never
 * joined to the domain — and nothing anywhere says so. This returns a
 * description of that mismatch so the deploy can log it and the CLE picker can
 * show it before an instructor commits a cohort.
 *
 * `role: 'dmz'` VMs are deliberately external (the dual-homed vuln website), so
 * they are expected not to match and are never reported.
 */
function findGoadHostMismatch(spec, specVms) {
  if (!spec?.goad?.enabled) return null;
  const labName = spec.goad.version || goadDeploy.DEFAULT_LAB;
  const labDef = goadDeploy.GOAD_LABS[labName] || goadDeploy.GOAD_LABS[goadDeploy.DEFAULT_LAB];
  if (!labDef) return null;

  const known = new Set(labDef.vms.map(v => v.name.toLowerCase()));
  const unmatched = specVms
    .filter(v => v.name && v.role !== 'dmz' && !known.has(String(v.name).toLowerCase()))
    .map(v => v.name);
  if (unmatched.length === 0) return null;

  return `${unmatched.join(', ')} ${unmatched.length === 1 ? 'is' : 'are'} not part of the `
       + `'${labName in goadDeploy.GOAD_LABS ? labName : goadDeploy.DEFAULT_LAB}' GOAD lab, which defines `
       + `${labDef.vms.map(v => v.name).join(', ')}. Unmatched hosts deploy to the EXTERNAL segment with `
       + `no reserved IP and are not domain-healed. Rename them to match the lab, or mark them "role": "dmz" `
       + `if they are meant to sit outside the AD network.`;
}

/**
 * Every challenge VM's id is `vm_offset + vxlanId`, so two VMs in one spec that
 * share an offset land on the SAME VMID. Proxmox then rejects the second clone
 * with "VM <id> already exists" partway through the lane, after the first VM and
 * the gateway already exist.
 *
 * Returns a human-readable problem string, or null when the spec is sound. This
 * is checked before anything is created, and surfaced by the CLE picker so an
 * instructor never selects a challenge that cannot deploy.
 */
function findVmOffsetCollision(specVms) {
  const byOffset = new Map();
  for (const vm of specVms) {
    const offset = vm.vm_offset || DEFAULT_VM_OFFSET;
    const name = vm.name || '(unnamed)';
    if (byOffset.has(offset)) {
      return `VMs '${byOffset.get(offset)}' and '${name}' share vm_offset ${offset}, so both would `
           + `clone to the same VMID. Give each VM in the spec a distinct vm_offset `
           + `(e.g. 600000, 610000, 620000).`;
    }
    byOffset.set(offset, name);
  }
  return null;
}

// ── per-VM findings, for the canvas ──────────────────────────────────────────

/** Which GOAD lab hosts this spec's lab definition declares, lowercased. */
function goadHostNames(spec) {
  if (!spec?.goad?.enabled) return null;
  const labName = spec.goad.version || goadDeploy.DEFAULT_LAB;
  const labDef = goadDeploy.GOAD_LABS[labName] || goadDeploy.GOAD_LABS[goadDeploy.DEFAULT_LAB];
  if (!labDef) return null;
  return new Set(labDef.vms.map(v => v.name.toLowerCase()));
}

/**
 * Validate a whole spec, returning findings keyed to individual VMs so the
 * canvas can paint a badge on the offending node.
 *
 * Findings carry `{ vm, code, severity, message }`; `vm` is null for problems
 * that belong to the topology as a whole rather than one machine.
 *
 * `catalogVmids` (optional) is the set of template_vmids known to
 * cybercore_template_catalog. Absent → the catalog check is skipped rather
 * than reported as failing, because an incomplete catalog is not a spec bug.
 */
function validateTopology({ spec = {}, subnetScheme = 'v1', specVms = [], catalogVmids = null } = {}) {
  const findings = [];
  const add = (severity, code, message, vm = null) => findings.push({ vm, code, severity, message });

  const segmentIds = new Set(resolveSegments(subnetScheme).map(s => s.id));
  const goadHosts = goadHostNames(spec);

  if (!specVms.length) {
    add('error', 'no-vms', 'This challenge declares no machines. Add at least one.');
  }

  // ── per-VM ────────────────────────────────────────────────────────────────
  const seenNames = new Map();
  const seenOffsets = new Map();

  for (const vm of specVms) {
    const name = vm.name || '(unnamed)';

    if (!vm.name) {
      add('error', 'missing-name', 'This machine has no name. Names key GOAD matching, DHCP reservations and flag planting.', name);
    } else if (seenNames.has(vm.name.toLowerCase())) {
      add('error', 'duplicate-name', `Two machines are both named '${vm.name}'. Names must be unique within a challenge.`, name);
    } else {
      seenNames.set(vm.name.toLowerCase(), true);
    }

    if (!vm.template_vmid && !spec.template_vmid) {
      add('error', 'missing-template', `'${name}' has no template VMID, so there is nothing to clone.`, name);
    } else if (catalogVmids && vm.template_vmid && !catalogVmids.has(Number(vm.template_vmid))) {
      add('warning', 'template-not-in-catalog',
        `Template ${vm.template_vmid} for '${name}' is not in the template catalog. It may still exist in Proxmox, but nothing verifies it.`, name);
    }

    const offset = vm.vm_offset || DEFAULT_VM_OFFSET;
    if (seenOffsets.has(offset)) {
      add('error', 'offset-collision',
        `'${name}' and '${seenOffsets.get(offset)}' share vm_offset ${offset}, so both clone to the same VMID and the second deploy fails.`, name);
    } else {
      seenOffsets.set(offset, name);
    }

    // Network attachment. Explicit nics[] are validated against the scheme;
    // derived attachments cannot be wrong by construction.
    const explicit = Array.isArray(vm.nics) ? vm.nics.filter(n => n && n.segment) : [];
    if (Array.isArray(vm.nics) && vm.nics.length && !explicit.length) {
      add('error', 'malformed-nics', `'${name}' has a nics list with no usable segment on any entry.`, name);
    }
    for (const nic of explicit) {
      if (!segmentIds.has(String(nic.segment))) {
        add('error', 'unknown-segment',
          `'${name}' attaches to segment '${nic.segment}', which a ${subnetScheme} lane does not have (${[...segmentIds].join(', ')}).`, name);
      }
    }

    // GOAD name matching — the failure mode findGoadHostMismatch describes,
    // reported per-machine so the canvas can mark the specific node.
    //
    // A WARNING, not an error, matching the deploy path: challenge-lane-deployer
    // only console.warns this, because "a challenge author may genuinely want an
    // extra box on the external segment".
    //
    // EXTERNAL_ROLES are exempt. The legacy string check exempts only 'dmz', so
    // it warns about the Kali row that the template editor adds to every GOAD
    // challenge by default — harmless in a log, but this one is shown to a human
    // on the canvas, where a permanent false positive trains people to ignore it.
    if (goadHosts && vm.name && !EXTERNAL_ROLES.has(vm.role) &&
        !goadHosts.has(vm.name.toLowerCase()) && !explicit.length) {
      add('warning', 'goad-name-mismatch',
        `'${vm.name}' is not a host in this GOAD lab, so it lands on the EXTERNAL segment with no reserved IP and is never domain-joined. Rename it to match the lab, or attach it to a segment explicitly.`, name);
    }
  }

  // ── whole-topology ────────────────────────────────────────────────────────
  if (subnetScheme === 'v3' && specVms.length) {
    const placement = specVms.map(vm => resolveVmSegments(vm, {
      subnetScheme,
      isGoadVm: !!(goadHosts && vm.name && goadHosts.has(vm.name.toLowerCase())),
    }));

    if (!placement.some(segs => segs.includes('int'))) {
      add('warning', 'empty-internal-segment',
        'Nothing is attached to the internal segment. A v3 lane exists to separate internal from external — as authored, this behaves like a v2 lane with extra moving parts.');
    }
    if (!placement.some(segs => segs.length > 1)) {
      add('warning', 'no-pivot-host',
        'No machine is dual-homed. The gateway DROPs traffic between the two segments, so with nothing bridging them the internal segment is unreachable and the intended pivot path does not exist.');
    }
  }

  return {
    errors: findings.filter(f => f.severity === 'error'),
    warnings: findings.filter(f => f.severity === 'warning'),
    findings,
  };
}

module.exports = {
  findGoadHostMismatch,
  findVmOffsetCollision,
  goadHostNames,
  validateTopology,
};
