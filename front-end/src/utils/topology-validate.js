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

  // EXTENSION-AWARE, via goadHostNames -> resolveGoadLab. This function used to
  // index GOAD_LABS[version] directly, which knows nothing about
  // spec.goad.extensions, so it reported ws01 and elk as strays on any
  // environment with extensions ticked — in the CLE deploy picker, right where
  // an instructor is deciding whether to commit a cohort. Its advice ("rename
  // them to match the lab") would have BROKEN a correctly authored spec.
  //
  // This is the SECOND reader that had the bug; validateTopology's was fixed
  // first and this one was missed. Both now go through one resolver, which is
  // the point: a validator that disagrees with the deployer is worse than no
  // validator.
  const goadHosts = goadHostNames(spec);
  if (!goadHosts) return null;

  const labName = spec.goad.version || goadDeploy.DEFAULT_LAB;
  const resolvedName = labName in goadDeploy.GOAD_LABS ? labName : goadDeploy.DEFAULT_LAB;

  const unmatched = specVms
    .filter(v => v.name
      && v.role !== 'dmz'
      && !goadHosts.roster.has(String(v.name).toLowerCase())
      // An `external` extension (elk, wazuh, lx01) is not a GOAD host and is not
      // meant to be one: it is an ordinary pinnable spec VM whose absence from
      // goadMacs is exactly what earns it a reservation and a host-record.
      && !goadHosts.external.has(String(v.name).toLowerCase()))
    .map(v => v.name);
  if (unmatched.length === 0) return null;

  return `${unmatched.join(', ')} ${unmatched.length === 1 ? 'is' : 'are'} not part of the `
       + `'${resolvedName}' GOAD lab, which defines `
       + `${goadHosts.rosterNames.join(', ')}. Unmatched hosts deploy to the EXTERNAL segment with `
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

/**
 * The machine names this spec's GOAD layer accounts for, split the same way the
 * deploy path splits them.
 *
 * ROUTED THROUGH resolveGoadLab, NOT GOAD_LABS[version]. That is the whole
 * point: `spec.goad.extensions` changes the roster, and reading the raw lab
 * table gets an answer the deploy path does not agree with. The symptom was two
 * permanent false positives on any environment with extensions ticked — ws01
 * and elk both reported as strays that "land on the EXTERNAL segment with no
 * reserved IP", while resolveGoadLab was composing ws01 into the roster and
 * marking elk external by design. A validator that disagrees with the deployer
 * is worse than no validator: it trains an author to ignore the findings panel.
 *
 * Two sets, because the two placements fail differently and only one of them is
 * a GOAD host:
 *   roster    in the AD forest. Gets the deterministic MAC, the DHCP
 *             reservation, the WinRM wait and the secure-channel heal. This is
 *             the set `isGoadVm` means.
 *   external  an ordinary pinnable spec VM (elk, wazuh, lx01). Deliberately
 *             ABSENT from goadMacs so resolveSpecAddressing still sees it —
 *             which is the only source of its host-record. Not a stray, so it
 *             must not draw the name-mismatch warning, but not a GOAD VM
 *             either, so it must not claim internal placement on v3.
 *
 * @returns {{roster: Set<string>, external: Set<string>, extMachines: Map,
 *            selected: string[]}|null} null when the spec has no GOAD layer,
 *          which is what disables every GOAD check. `selected` is the resolved
 *          extension KEYS (not machine names) — the prebaked check reports keys,
 *          because "untick elk" is the action and `elk` is what the author
 *          ticked.
 */
function goadHostNames(spec) {
  if (!spec?.goad?.enabled) return null;
  let resolved;
  // resolveGoadLab throws on a malformed spec-supplied goad.lab (assertValidLabDef).
  // That is correct for a deploy and wrong here: the author is mid-edit and the
  // canvas must still render its other findings. Degrade to "no GOAD roster",
  // which suppresses the GOAD-specific checks rather than blanking the panel.
  try { resolved = goadDeploy.resolveGoadLab(spec); } catch (e) { return null; }
  const labDef = resolved?.labDef;
  if (!labDef) return null;
  // Machine name → catalog entry, for the extensions this spec actually
  // selected. Keyed on the MACHINE rather than the extension key because the
  // findings loop only ever has a vm.name in hand; they happen to be equal for
  // everything shipped today, and relying on that would break silently the
  // first time an extension contributes a differently-named box.
  const extMachines = new Map();
  for (const key of (resolved.extensions?.selected || [])) {
    const ext = goadDeploy.getExtension(key);
    if (ext) extMachines.set(String(ext.machine).toLowerCase(), ext);
  }
  return {
    roster: new Set((labDef.vms || []).map(v => String(v.name).toLowerCase())),
    // The same names in the case the lab actually declares them. `roster` is
    // lowercased because it exists to be MATCHED against; these exist to be
    // SHOWN to a human, and telling an author their lab defines 'dc01' when
    // every other surface calls it DC01 is a small, avoidable confusion.
    rosterNames: (labDef.vms || []).map(v => String(v.name)),
    external: resolved.extensions?.external || new Set(),
    extMachines,
    selected: resolved.extensions?.selected || [],
  };
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
      // An extension machine gets a message of its own, because the generic one
      // ("nothing to clone") reads as a bug in the extension and sends the author
      // looking in the wrong place. It names the VMID the catalog already knows,
      // and says what that image is and is not — a PLAIN base image, with the
      // stack installed in-lane by GOAD's own extension Ansible at deploy time.
      //
      // This used to say the opposite: that the image was a per-site golden ELK
      // and that ticking an extension "never installs anything". That described
      // the prebaked-SIEM design, which has been replaced — elk and wazuh now
      // clone a generic Ubuntu base and run.sh installs the stack on the lane.
      const ext = goadHosts?.extMachines?.get(String(vm.name || '').toLowerCase());
      if (ext && ext.template_vmid) {
        add('error', 'missing-template',
          `'${name}' comes from the ${ext.key} extension, whose image is template ${ext.template_vmid} — a plain `
          + `${ext.os || 'base image'} with none of the stack on it. Set it as this machine's template. The `
          + `${ext.key} stack itself is installed IN THE LANE at deploy time by GOAD's own `
          + `extensions/${ext.key}/ansible, exactly the way upstream's 'install_extension ${ext.key}' does — so `
          + `the image does not need to carry it, and the lane needs the internet egress it has.`, name);
      } else if (ext) {
        add('error', 'missing-template',
          `'${name}' comes from the ${ext.key} extension, which ships no template VMID of its own — so you have `
          + `to pick one. Any plain ${ext.os || 'base image'} will do: GOAD's extensions/${ext.key}/ansible `
          + `installs the stack in the lane at deploy time, so nothing has to be baked into the image.`, name);
      } else {
        add('error', 'missing-template', `'${name}' has no template VMID, so there is nothing to clone.`, name);
      }
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
    // Extension machines are exempt in BOTH directions, and for two different
    // reasons. An `inLab` extension (ws01) is already in `roster` above, because
    // resolveGoadLab composed it in — so it never reaches here. An `external`
    // one (elk, wazuh, lx01) genuinely is not a GOAD host, but it is not a
    // stray either: it carries an explicit ipOctet and dns_aliases, and
    // resolveSpecAddressing pins it precisely BECAUSE goadMacs does not name it.
    // Warning about it would be advising the author to undo the design.
    if (goadHosts && vm.name && !EXTERNAL_ROLES.has(vm.role) &&
        !goadHosts.roster.has(vm.name.toLowerCase()) &&
        !goadHosts.external.has(vm.name.toLowerCase()) && !explicit.length) {
      add('warning', 'goad-name-mismatch',
        `'${vm.name}' is not a host in this GOAD lab, so it lands on the EXTERNAL segment with no reserved IP and is never domain-joined. Rename it to match the lab, or attach it to a segment explicitly.`, name);
    }
  }

  // ── extensions on a PRE-BAKED lane ────────────────────────────────────────
  //
  // THE ONE COMBINATION THAT DEPLOYS GREEN AND DOES NOTHING. There are two GOAD
  // modes and only the live one runs Ansible: a live lane stands a controller and
  // runs /opt/goad-light/run.sh, which is the only thing anywhere that executes
  // an extension's install.yml. A pre-baked lane (spec.goad.prebaked) clones
  // golden images and heals their secure channels — no controller, no run.sh.
  //
  // So on a pre-baked lane every ticked extension does all the VISIBLE work and
  // none of the real work: the machine is cloned, addressed, given a DNS record
  // and a console, and nothing is installed on it. The author sees elk on the
  // canvas, the deploy reports active, and a student opens an empty Kibana. That
  // is the exact silent-success failure this codebase keeps documenting, so it is
  // an ERROR — the spec as authored cannot do what it says.
  //
  // Stated ONE machine at a time so the canvas can badge the offending node, and
  // anchored to the machine only when it is actually on the canvas: an extension
  // can be ticked before its row exists, and a finding pinned to a node that is
  // not there renders nowhere.
  //
  // goad-deploy.assertGoadExtensionsRunnable is the same rule at deploy time, for
  // the specs that never pass through this canvas (the CiAB compiler writes them
  // directly). Author-time here, deploy-time there; neither is redundant.
  if (goadHosts && spec?.goad?.prebaked && goadHosts.selected.length) {
    for (const key of goadHosts.selected) {
      const ext = goadDeploy.getExtension(key);
      const machine = String(ext ? ext.machine : key).toLowerCase();
      const row = specVms.find(v => String(v.name || '').toLowerCase() === machine);
      // Pre-baked + extensions is the INTENDED steady state once the images are
      // sealed, so the flag alone is not the problem. Exactly one shape is: a
      // machine still cloning the generic Ubuntu base, which carries no stack and
      // has no Ansible coming to install one. See goad-deploy's twin for the full
      // reasoning; this is the author-time half of the same rule.
      const vmid = Number(row?.template_vmid || ext?.template_vmid || spec.template_vmid || 0);
      if (vmid && vmid !== goadDeploy.PLAIN_BASE_TEMPLATE_VMID) continue;
      add('error', 'prebaked-extension',
        `The '${key}' extension is ticked on a pre-baked environment (spec.goad.prebaked), but `
        + `'${ext ? ext.machine : key}' ${vmid ? `still clones template ${vmid}, the generic Ubuntu base` : 'has no template'} `
        + `— an image with no ${key} on it. A pre-baked lane clones golden images and runs NO Ansible: no `
        + `controller is deployed, so run.sh — the only thing that ever installs an extension — never `
        + `executes, and nothing would install it. The machine would be cloned, addressed and given a console with `
        + `nothing on it, and the lane would still report active. Point it at a sealed template that already `
        + `carries the stack, or clear the pre-baked flag so the lab is provisioned live and the extension `
        + `installs in-lane.`,
        row ? (row.name || '(unnamed)') : null);
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
      // `roster` only. An external extension is placed as an ordinary spec VM,
      // which is exactly what isGoadVm: false means to resolveVmSegments.
      isGoadVm: !!(goadHosts && vm.name && goadHosts.roster.has(vm.name.toLowerCase())),
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
