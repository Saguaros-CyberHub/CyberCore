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
    // ZERO SEGMENTS. This is the loud half of the empty-nics contract documented
    // at challenge-spec.normaliseNics and lane-networking.resolveVmSegments: an
    // authored `nics: []` is INDISTINGUISHABLE from an absent key everywhere
    // downstream, so the deploy path re-derives a placement and the machine comes
    // up ATTACHED while the canvas shows it floating. Nothing else in the stack
    // can tell the two apart, which is precisely why it has to be caught here.
    //
    // An ERROR, not a warning: the spec as written cannot deploy as drawn, and
    // the failure is invisible at deploy time. The fix is to attach the machine
    // (a VM with no network has no DHCP lease, no Guacamole target and no vuln
    // scripts) — not to keep the empty array.
    //
    // Note the deliberate overlap with malformed-nics above: `nics: [{}, null]`
    // is both a junk list AND a machine that resolves to nothing. Two findings,
    // two different statements, both true.
    if (Array.isArray(vm.nics) && !explicit.length) {
      add('error', 'no-nic',
        `'${name}' is attached to no network segment. An empty nics list is read everywhere downstream as `
        + `"not authored", so this machine would silently deploy attached to `
        + `${[...segmentIds][0] || 'the lane network'} anyway. Attach it to a segment — a machine with no `
        + `network gets no DHCP lease, no console connection and no post-clone scripts.`, name);
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

  // ── SIEM placement ────────────────────────────────────────────────────────
  //
  // Both of these describe blue-team environments that LOOK correct on the
  // canvas and are useless (or undeployable) in the lane. They are cheap to run
  // on every spec because a topology with no `siem` machine matches neither.
  const named = (n) => specVms.some(v => String(v.name || '').toLowerCase() === n);
  const hasElkSiem = specVms.some(v =>
    v.role === 'siem' && String(v.name || '').toLowerCase() === 'elk');

  // GOAD's elk extension instruments `[elk_log:children] domain` — the WINDOWS
  // domain group — and nothing else. Its inventory never touches
  // `[linux_domain]`, so a Linux machine on an ELK-only lane ships no telemetry
  // at all: no Sysmon equivalent, no winlogbeat, no agent. The student is asked
  // to hunt across the environment and one host is simply not in the index.
  //
  // A WARNING rather than an error: the lane deploys and the rest of the hunt
  // works. GOAD's wazuh extension DOES cover Linux
  // (`[wazuh_agents_linux:children] linux_domain`), so adding a wazuh machine is
  // the fix — which is why the check clears the moment one is present.
  if (hasElkSiem && !named('wazuh')) {
    for (const vm of specVms) {
      if (vm.role !== 'linux') continue;
      const name = vm.name || '(unnamed)';
      add('warning', 'siem-blind-host',
        `'${name}' is a Linux host on a lane whose only SIEM is ELK. GOAD's elk extension instruments the `
        + `[domain] group only — never [linux_domain] — so this machine ships no telemetry and is a DARK BOX `
        + `in the middle of a hunting exercise. Add a 'wazuh' machine (its extension does cover Linux), or `
        + `drop this host.`, name);
    }
  }

  // .50 is Kali (goad-deploy INFRA_IP_OCTETS.Kali), and the gateway bakes its
  // RDP DNAT against exactly that value. On v3 Kali sits on the external segment
  // while a SIEM would sit internally, so the two never meet; on v1/v2 there is
  // ONE flat lan0 and they are the same address on the same subnet. dnsmasq
  // refuses to start when two dhcp-host lines claim one address — which takes
  // DHCP down for the WHOLE lane, not just these two machines.
  //
  // `include_kali !== false` reproduces the deploy path's own default-true test
  // (goad-deploy.js:582, :758, :1440): a GOAD spec that never mentions Kali
  // still gets one.
  const kaliPresent = !!(spec?.goad?.enabled) && spec.goad.include_kali !== false;
  if (kaliPresent && subnetScheme !== 'v3') {
    for (const vm of specVms) {
      if (Number(vm.ipOctet) !== goadDeploy.INFRA_IP_OCTETS.Kali) continue;
      const name = vm.name || '(unnamed)';
      add('error', 'siem-octet-collision',
        `'${name}' pins IP octet .${goadDeploy.INFRA_IP_OCTETS.Kali}, which is the Kali attack box on this `
        + `lane. A ${subnetScheme} lane has one flat subnet, so both machines claim the same address and `
        + `dnsmasq refuses to start — taking DHCP down for every machine in the lane. Move it to a free `
        + `octet (.24 is the conventional ELK slot), or turn Kali off.`, name);
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
