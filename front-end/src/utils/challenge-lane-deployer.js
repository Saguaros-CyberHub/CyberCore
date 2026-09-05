/**
 * ============================================================================
 * CHALLENGE LANE DEPLOYER
 * ----------------------------------------------------------------------------
 * Deploy one isolated lane per user for a CHALLENGE: gateway LXC + the
 * challenge's own VMs + (optionally) a Kali attack box, with GOAD provisioning,
 * vuln scripts, capture flags, Guacamole consoles and workspace registration.
 *
 * This is the sequence that used to live inline inside
 * routes/admin/groups.js's POST /deploy-group handler. It was moved here — not
 * copied — so the CLE plugin's "Deploy Vulnerable Machine" path and the admin
 * Group Deploy run the SAME code. A second copy is how the CLE workstation path
 * broke the first time; see the header of lane-deployer.js.
 *
 * Division of labour between the two deployers:
 *
 *   lane-deployer.js           one CATALOG workstation per lane. The user's own
 *                              machine. Console pinned at <lane>.50 by MAC.
 *   challenge-lane-deployer.js the challenge's spec.vms[] per lane, plus Kali as
 *                              the attack box. The targets the user attacks.
 *
 * Callers supply users that ALREADY EXIST (`[{ id, email, password? }]`). This
 * module never creates accounts — that stays with the caller, because the admin
 * group deploy mints throwaway accounts while CLE deploys to a real roster.
 *
 * Load-bearing details, every one of which has broken a deploy before:
 *
 *   - Kali reaches <lane-ext>.50 through a DHCP RESERVATION keyed on a
 *     deterministic MAC, NOT a static cloud-init pin. The Kali cloud image's
 *     cloud-ifupdown helper races a static ipconfig0 and wins, leaving Kali on a
 *     random lease with an empty /etc/resolv.conf.
 *   - The gateway LXC hostname carries a `-b<16hex>` claim secret that firstboot
 *     greps back out for the lane-bootstrap request. Source-IP gating does not
 *     survive the orchestrator's Docker bridge.
 *   - Guacamole always targets the gateway's wan0 transit IP, never the
 *     lane-local address: guacd has no route into the lane subnet.
 *   - v3 DMZ hosts sit at .240 on both segments. .50 is reserved for Kali's RDP
 *     DNAT, and .240 is above the gateway's DHCP pool (.10-.200).
 *   - Pre-baked GOAD members get their cloud-init drive stripped, or
 *     cloudbase-init renames the host and breaks its AD secure channel.
 *   - Flags are planted LAST, after vuln scripts and GOAD, so nothing clobbers
 *     the files. The `postDeploy` hook therefore runs BEFORE them, not after.
 *   - `pinAllVms` addressing is recorded on the lane config and REPLAYED on
 *     rebuild, never re-derived: the reservations file is rendered whole-lane,
 *     so a rebuild that recomputed it would move machines off the addresses the
 *     lane's own generated paper names.
 * ============================================================================
 */

const crypto = require('crypto');

const {
  proxmoxAPI, waitForTask, findTemplateNode, forceDestroyVM, waitForVmidsGone,
} = require('./proxmox');
const { cybercoreQuery } = require('./cybercore-db');
const { query } = require('./db');
const { guacAPI } = require('./guacamole');
const guacCreds = require('./guac-credentials');
const { getDefaultTemplateNode, getSchedulingConfig } = require('./site-config');
const { selectBestNode } = require('./node-selector');
const { runBatch, distributeAcrossNodes, createCloneSemaphore } = require('./batch-deployer');
const { generatePassword } = require('./password-generator');
const { waitForGuestAgent, executeScriptsOnVM } = require('./script-executor');
const { plantFlagsForLane, seedLaneFlags } = require('./flag-manager');
const goadDeploy = require('./goad-deploy');
const audit = require('./audit');
const laneDeployer = require('./lane-deployer');
const laneWan = require('./lane-wan-allocator');
const nodeSsh = require('./node-ssh');
// The AGENT half of a ticked elk/wazuh extension. Derived here rather than
// stored on the spec, and this file is where it is derived because this is the
// ONE deploy every caller shares — see goad-agent-attach.js for the full
// argument and for why a template bake was the wrong answer.
const {
  attachGoadAgentScripts, withGoadAgentVulnScripts,
} = require('./goad-agent-attach');
const {
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  resolveGatewayVmid,
  resolveLaneNetworking,
  applyFixedSubnet,
  configureLaneTailscale,
  formatLaneGatewayNet0,
  resolveVmNics,
  resolveVmSegments,
  resolveSegmentBridges,
  DEFAULT_VM_OFFSET,
} = require('./lane-networking');
const { findGoadHostMismatch, findVmOffsetCollision } = require('./topology-validate');

const GATEWAY_VMID_OFFSET = 100000;   // gateway LXC = 100000 + vxlanId
const TEMP_GW_TEMPLATE_BASE = 169200; // per-node temp gateway template copies
// DEFAULT_VM_OFFSET moved to lane-networking so topology-validate can use it
// without importing a deployer. Re-exported below; still 600000.

const LOG = '[ChallengeLane]';

// ── spec helpers ─────────────────────────────────────────────────────────────

/** crucible_challenge.spec is JSONB; pg may hand it back as text. */
function parseSpec(spec) {
  if (!spec) return {};
  return typeof spec === 'string' ? JSON.parse(spec) : spec;
}

/**
 * The VMs a challenge deploys. Older single-VM specs carry a bare
 * template_vmid with no vms[] array (metasploitable2-basic), so synthesize one
 * entry for them rather than deploying nothing.
 */
function resolveSpecVms(spec, challengeKey) {
  if (Array.isArray(spec.vms) && spec.vms.length > 0) return spec.vms;
  if (!spec.template_vmid) return [];
  return [{
    name: challengeKey,
    template_vmid: spec.template_vmid,
    type: 'qemu',
    vm_offset: DEFAULT_VM_OFFSET,
  }];
}

// findGoadHostMismatch and findVmOffsetCollision now live in topology-validate.js
// alongside the rest of the spec checks, so the topology canvas can run them
// without importing a deploy path. They are still re-exported from this module
// (see module.exports) because cle/utils/vuln-lab-provision.js calls them here.

// Lane octets that a console-designated machine draws from. Deliberately a
// SUBSET of lane-deployer's .50-.79 workstation band, starting at .60:
//   .50      is Kali's, and the value the gateway template bakes its wan0:3389
//            DNAT against — never hand it to anything else.
//   .10-.23  are GOAD's lab hosts + controller.
//   .240     is the v3 dual-homed DMZ pivot.
//   .100+    is attached-modules' band.
// So .60-.79 is the one stretch inside the reserved workstation range that no
// other actor on a challenge lane touches, and it sits above the .10-.200 DHCP
// pool's live leases.
const CONSOLE_OCTET_MIN = 60;
const CONSOLE_OCTET_MAX = 79;

// Ordinary (non-console) spec machines under `pinAllVms`, from the next stretch
// up. Deliberately disjoint from the console band so a machine's address does
// not move when it is later designated the console — .60-.79 stays "machines the
// student opens", .80-.99 stays "machines the student attacks", and .100+ is
// still attached-modules'. 20 addresses is the hard ceiling one lane can pin;
// past that the caller gets a named error rather than a silent random lease.
const SPEC_OCTET_MIN = 80;
const SPEC_OCTET_MAX = 99;

// The v3 dual-homed DMZ pivot's host octet, on BOTH of its segments. It used to
// be .50, but the gateway firstboot reserves ext .50 for Kali's RDP DNAT
// (wan0:3389 -> ext.50), so the two collided and student RDP landed on the web
// host rather than the attack box. .240 is above the gateway's DHCP pool
// (.10-.200), so no lease can claim it and no gateway re-bake is needed. It is
// deliberately outside both bands above, because a dual-homed machine is never
// handed one: resolveVmNics builds its NICs inline and ignores the pinned MAC,
// so a band reservation would be one nothing ever requests.
//
// NAMED, because two readers in this file have to agree on it and a second
// literal 240 is exactly how they drift: cloneChallengeVm writes the static
// ipconfig, and resolveLaneDnsExtras publishes the company's web name AT that
// address. Exported for the same reason the CiAB paper already spells it
// (plugins/ciab/utils/engagement-model.js DUAL_HOMED_OCTET, whose comment names
// this file as the authority) - one place to read, none to re-spell.
const DUAL_HOMED_OCTET = 240;

/**
 * Pin a pre-baked ("GOAD-Like") lane onto the subnet its golden images were
 * baked on — and REFUSE to build one that never declared it.
 *
 * The refusal is the point. A golden AD image bakes its addresses into itself:
 * the AD-integrated DNS zone, the SYSVOL/DFS referral paths and every SPN all
 * name the IP the image was provisioned on. Clone it onto a per-lane subnet and each
 * of those records points at an address that does not exist on the lane —
 * while nothing fails: the clones boot, DHCP hands them the lane's own
 * addresses, the lane reports `active`, and the first `nxc`, domain join or
 * Kerberos ticket request is where a student discovers the forest is fiction.
 *
 * All three call sites used to spell this as
 * `if (prebaked && fixed_subnet) applyFixedSubnet(...)` with no else, so a spec
 * missing the field took exactly that silent path three times over.
 *
 * Empty counts as missing. applyFixedSubnet ignores a falsy base, so
 * `fixed_subnet: { int: '' }` — which is precisely what the topology canvas
 * seeds a new pre-baked challenge with (topology-seed.fromGoadLab) — is the
 * same silent per-lane subnet, with a field present to make it look answered.
 * The canvas's own validateCreateState already refuses that at authoring time;
 * this is the deploy-time backstop for a spec that arrived some other way.
 *
 * `ext` is passed through as-is rather than defaulted to `int`: a spec that
 * pins only the internal base leaves the EXTERNAL segment per-lane today, and
 * on v3 defaulting it would put both segments on one base. Only the internal
 * base is load-bearing — that is the segment the baked AD lives on.
 *
 * @returns {object} the same `net`, mutated by applyFixedSubnet
 * @throws when spec.goad.prebaked is set without a usable fixed_subnet.int
 */
function applyPrebakedFixedSubnet(net, isV3, spec) {
  if (!spec?.goad?.prebaked) return net;
  const fixed = spec.goad.fixed_subnet || {};
  // Trimmed because these are hand-typed into the create form: ' 10.39.16'
  // survives the truthiness check and then builds ' 10.39.16.1' as the gateway
  // address, which Proxmox accepts as a net config and no guest can reach.
  const int = String(fixed.int == null ? '' : fixed.int).trim();
  const ext = String(fixed.ext == null ? '' : fixed.ext).trim();
  if (!int) {
    throw new Error(
      'This challenge is marked pre-baked GOAD (spec.goad.prebaked) but its spec declares no ' +
      'goad.fixed_subnet.int, so every lane would be built on a per-lane subnet while the golden ' +
      'images still answer on the base they were baked on — their DNS, SYSVOL and SPN records would ' +
      'all name an address the lane does not have, and the lane would still report active. ' +
      'Set spec.goad.fixed_subnet = { int: "<base the images were baked on>", ext: "<external base>" }, ' +
      'or clear spec.goad.prebaked to provision the lab live instead.'
    );
  }
  return applyFixedSubnet(net, isV3, int, ext);
}

/**
 * Decide which machines on a lane get a Guacamole console, and which one the
 * student's console button opens (the "primary").
 *
 * Pure over its inputs, so the back-compat rule below is unit-testable without a
 * deploy. That rule is the whole point of the function:
 *
 *   precedence for the PRIMARY console:
 *     1. an explicit per-deploy `override` (the modal's console_vm)
 *     2. a spec VM carrying console_role === 'primary'
 *     3. the Kali attack box, when attackBoxes is on   <-- today's behaviour
 *     4. the first instructor-added workstation
 *     5. none
 *
 *   membership of the console list (each gets its own connection):
 *     - Kali, when attackBoxes is on
 *     - a spec VM whose console_role is 'primary' or 'secondary'
 *     - every instructor-added workstation (a machine you add is one to work from)
 *
 * "5. none" is deliberate and is what keeps every existing challenge
 * byte-identical: before this function existed, the ONLY console a challenge
 * lane ever created was Kali's. A spec that declares no console_role and deploys
 * with attackBoxes:false must therefore still create none — promoting
 * spec.vms[0] would hand every legacy challenge a brand-new DNAT, Guac
 * connection and cloud-init pass on its next redeploy, which nobody asked for.
 *
 * @param {object} a
 * @param {Array}   a.specVms            resolveSpecVms(spec, key) output
 * @param {boolean} a.attackBoxes
 * @param {Array}   [a.extraWorkstations] [{ name/hostname, ... }] instructor add-ons, slot order
 * @param {string}  [a.override]         a machine name, 'kali', or 'ws:<index>'
 * @returns {{ primary: object|null, consoles: Array }}
 *   each console: { ref, kind:'kali'|'spec'|'extra', name, primary, vm?, extra?, index? }
 * @throws when two spec VMs both claim 'primary', or override names nothing
 */
function resolveConsolePlan({ specVms = [], attackBoxes = false, extraWorkstations = [], override = null }) {
  const candidates = [];
  if (attackBoxes) {
    candidates.push({ ref: 'kali', kind: 'kali', name: 'kali', consoleRole: 'primary' });
  }
  specVms.forEach((vm) => {
    candidates.push({
      ref: 'spec:' + (vm.name || ''), kind: 'spec', name: vm.name || '', vm,
      consoleRole: vm.console_role || null,
    });
  });
  extraWorkstations.forEach((w, i) => {
    candidates.push({
      ref: 'ws:' + i, kind: 'extra', name: w.hostname || w.name || ('ws' + i),
      extra: w, index: i, consoleRole: w.console || null,
    });
  });

  // At most one SPEC VM may declare itself primary — a lane cannot open two
  // "the machine the student works from" consoles at once. (Kali and extras are
  // never the source of this ambiguity: Kali's role is implicit, and an extra's
  // primary flag is set by the same picker that sets `override`.)
  const specPrimaries = candidates.filter((c) => c.kind === 'spec' && c.consoleRole === 'primary');
  if (specPrimaries.length > 1) {
    throw new Error(
      `Two machines both declare console_role 'primary' (` +
      specPrimaries.map((c) => c.name).join(', ') +
      `); exactly one machine can be the student console`
    );
  }

  // Which machines get a console connection at all.
  const consoles = candidates.filter((c) =>
    c.kind === 'kali' ||
    c.kind === 'extra' ||
    (c.kind === 'spec' && (c.consoleRole === 'primary' || c.consoleRole === 'secondary'))
  );

  // Pick the primary.
  let primary = null;
  if (override) {
    primary = consoles.find((c) => c.ref === override || c.name === override) || null;
    if (!primary) {
      // The instructor named a machine the SPEC never designated. That is the
      // point of the override — "which machine do students open?" has to be
      // answerable with any machine on the lane, not only the ones the author
      // thought of — so promote it into the console list rather than refusing.
      // Only a name that matches nothing at all is an error.
      const promoted = candidates.find((c) => c.ref === override || c.name === override);
      if (!promoted) {
        throw new Error(`console override '${override}' names no machine on this lane`);
      }
      promoted.consoleRole = 'primary';
      consoles.push(promoted);
      primary = promoted;
    }
  } else if (specPrimaries.length === 1) {
    primary = specPrimaries[0];
  } else if (attackBoxes) {
    primary = consoles.find((c) => c.kind === 'kali') || null;
  } else {
    primary = consoles.find((c) => c.kind === 'extra') || null;
  }

  consoles.forEach((c) => { c.primary = (c === primary); });
  return { primary, consoles };
}

/** Catalog addresses required by the selected external GOAD installers. */
function resolveGoadExternalPins(spec) {
  if (!spec?.goad?.enabled) return {};
  const { extensions } = goadDeploy.resolveGoadLab(spec);
  const pins = {};
  for (const key of extensions.selected) {
    const ext = goadDeploy.getExtension(key);
    if (ext.inLab) continue;
    const vm = (spec.vms || []).find(v => String(v.name).toLowerCase() === ext.machine.toLowerCase());
    if (!vm) throw new Error(`Selected GOAD extension '${key}' requires machine '${ext.machine}'.`);
    if (vm.ipOctet != null && Number(vm.ipOctet) !== ext.ipOctet) {
      throw new Error(`GOAD extension '${key}' must use .${ext.ipOctet}; its installer uses that address.`);
    }
    pins[vm.name] = ext.ipOctet;
  }
  return pins;
}

/** Reject incompatible extension placement before allocating lane resources. */
function validateGoadLaneAddressing(spec, subnetScheme) {
  if (!spec?.goad?.enabled) return;
  try {
    const goadMacs = goadDeploy.prepareGoadMacs(spec, 1, '10.0.1');
    resolveSpecAddressing({
      specVms: spec.vms || [], goadMacs, requiredIpOctets: resolveGoadExternalPins(spec),
      subnetScheme, laneSubnetBase: '10.0.0', goadSubnetBase: '10.0.1',
      reserved: [1, 5, 50, ...Object.values(goadMacs).map(v => Number(v.static_ip.split('.').pop()))],
    });
  } catch (err) {
    err.status = 400;
    throw err;
  }
}

/**
 * Fixed lane addresses (and stable DNS names) for the machines the student
 * ATTACKS, not just the ones they open a console onto.
 *
 * General pinning is off unless the caller passes `pinAllVms`; selected GOAD
 * extensions always keep the addresses their installers require. A CLE challenge does
 * not need this — its author already knows the lab's shape. A PROFILE-DERIVED
 * lane does: the generated paper (scan report, asset register, network diagram)
 * names an address, and a machine on an ordinary DHCP pool lease lands
 * somewhere else. That divergence is invisible until a student runs nmap and
 * the exercise stops making sense.
 *
 * Pure over its inputs, like resolveConsolePlan, so the band arithmetic and the
 * skip rules below are testable without standing up a deploy.
 *
 * Three classes are deliberately NOT pinned:
 *   GOAD hosts   prepareGoadMacs already gave them a static IP and a MAC, and
 *                their reservation is written from goadMacs.
 *   consoles     already allocated by the caller; re-pinning double-claims the
 *                address, and dnsmasq refuses to start when two dhcp-host lines
 *                claim one — which takes DHCP down for the WHOLE lane.
 *   dual-homed   resolveVmNics builds those NICs inline and ignores the MAC
 *                entirely, so a pin would write a reservation nothing ever
 *                requests. v3 pins them to .DUAL_HOMED_OCTET by design, and
 *                resolveLaneDnsExtras reads that pin back out — a machine
 *                missing from pinnedHosts is NOT a machine with no address.
 *
 * DNS records are emitted for pinned AND console machines (an alias has to
 * resolve to an address, and only those have one that is knowable at deploy
 * time), and are independent of `pinAllVms` — a spec that declares
 * `dns_aliases` on its console machine gets them either way.
 *
 * ── Two sources of aliases, not one ─────────────────────────────────────────
 * An earlier version of this comment claimed `dns_aliases` exists only on
 * catalog TEMPLATE rows and so this pass was inert for every challenge. Both
 * halves are now wrong:
 *
 *   spec.vms[].dns_aliases    CiAB's synthesizer writes them
 *                             (ciab/utils/profile-to-spec.js), and the topology
 *                             canvas persists whatever the spec carries.
 *   extra.template.metadata   an instructor-added workstation (extraWorkstations)
 *     .dns_aliases            is a CATALOG ROW, so its aliases live where the
 *                             workstation path has always read them.
 *
 * The extras half is why `extraConsoles` exists. Extras used to get a dhcp-host
 * line from writeLaneReservations and NO host-record at all, so an alias on an
 * added machine was silently dropped. That is not cosmetic: the CYBR 400 sensor
 * image bakes `ELK_HOST=elk.cybercore.lan` into its elastic-agent.yml, and the
 * ELK box MUST ride the extras path because cloneChallengeVm never sets
 * ciuser/cipassword — only cloneExtraWorkstation does. Without the record the
 * agent resolves nothing, reports healthy, and ships zero events.
 *
 * Extras are emitted at their CONSOLE octet on the EXTERNAL base, matching
 * writeLaneReservations' own console loop — the two must agree or the record
 * points at an address nothing holds.
 *
 * @param {object} a
 * @param {Array}  a.specVms             resolveSpecVms output
 * @param {object} [a.goadMacs]          prepareGoadMacs output, keyed by VM name
 * @param {object} [a.consoleOctetForVm] spec-VM name -> already-allocated console octet
 * @param {Array}  [a.extraConsoles]     [{ hostname, template, octet }] instructor-added
 *   machines with their already-allocated console octet. DNS only — extras are
 *   never pinned (the console allocator owns their address) and never appear in
 *   pinnedHosts.
 * @param {Array}  [a.reserved]          octets already claimed on this lane
 * @param {boolean}[a.pinAllVms]
 * @param {object} [a.requiredIpOctets] selected extension VM names to installer octets
 * @returns {{ pinnedHosts: Array<{name,octet,subnetBase}>, dnsRecords: Array<{alias,ip}> }}
 * @throws when an explicit ipOctet collides, the band is full, or two machines
 *   claim one alias — each of which produces a lane that looks deployed and is
 *   silently wrong.
 */
function resolveSpecAddressing({
  specVms = [], goadMacs = {}, consoleOctetForVm = {}, extraConsoles = [], reserved = [],
  subnetScheme, laneSubnetBase, goadSubnetBase, pinAllVms = false, requiredIpOctets = {},
}) {
  const isV3 = subnetScheme === 'v3';
  const taken = new Set(reserved);
  const pinnedHosts = [];

  if (pinAllVms || Object.keys(requiredIpOctets).length) {
    // Everything that survives the skip rules, in spec order. Order is part of
    // the output contract: the auto-assigned octets must not move because an
    // unrelated machine was added earlier in the list.
    const eligible = [];
    for (const vmSpec of specVms) {
      const name = vmSpec.name;
      if (!name) continue;
      if (!pinAllVms && requiredIpOctets[name] == null) continue;
      if (goadMacs[name]) continue;
      if (consoleOctetForVm[name] != null) {
        if (requiredIpOctets[name] != null && consoleOctetForVm[name] !== requiredIpOctets[name]) {
          throw new Error(`GOAD extension '${name}' must keep its installer address .${requiredIpOctets[name]}.`);
        }
        continue;
      }
      if (requiredIpOctets[name] != null && (vmSpec.type || 'qemu') !== 'qemu') {
        throw new Error(`GOAD extension '${name}' requires a QEMU VM with a pinned network interface.`);
      }
      if ((vmSpec.type || 'qemu') === 'lxc') continue;   // net1; the template owns net0

      const segs = resolveVmSegments(vmSpec, { subnetScheme, isGoadVm: false });
      if (requiredIpOctets[name] != null && (segs.length !== 1 || (isV3 && segs[0] !== 'ext'))) {
        throw new Error(`GOAD extension '${name}' must have one interface on the external lane network.`);
      }
      if (segs.length > 1) continue;

      eligible.push({
        name, vmSpec,
        subnetBase: (isV3 && segs[0] === 'int') ? goadSubnetBase : laneSubnetBase,
      });
    }

    // PASS 1 — claim every EXPLICIT ipOctet before handing out a single
    // automatic one.
    //
    // One pass with a single moving cursor is not enough, and the bug it causes
    // is nasty: with seven machines where only the last declares ipOctet: 85,
    // the first six would take .80-.85 and the seventh would then be told its
    // own requested address "is already taken on this lane" — naming a conflict
    // the author cannot see anywhere in their spec, and which they could only
    // work around by reordering the array. An explicit octet is the author's
    // contract with the generated paper, so it wins outright over an address
    // this function invented.
    const explicitOctet = new Map();
    for (const e of eligible) {
      const requested = requiredIpOctets[e.name] ?? e.vmSpec.ipOctet;
      if (requested === undefined || requested === null) continue;
      const wanted = Number(requested);
      // Range-checked, not merely finite. Number() maps null->0, '' ->0 and
      // true->1, and Number.isFinite accepts 0, negatives, 300 and 80.5 — every
      // one of which reaches macForOctet(octet & 0xFF) and produces a
      // reservation for an address that is not the one requested, or claims the
      // gateway's own .1.
      if (!Number.isInteger(wanted) || wanted < 2 || wanted > 254) {
        throw new Error(
          `Machine '${e.name}' requested IP octet .${e.vmSpec.ipOctet}, which is not a usable ` +
          `host address — it must be a whole number between 2 and 254 (.1 is the lane gateway).`
        );
      }
      if (taken.has(wanted)) {
        throw new Error(
          `Machine '${e.name}' requested IP octet .${wanted}, which is already taken on this lane`
        );
      }
      taken.add(wanted);
      explicitOctet.set(e.name, wanted);
    }

    // PASS 2 — fill the rest from the band, skipping everything now claimed.
    let next = SPEC_OCTET_MIN;
    for (const e of eligible) {
      let octet = explicitOctet.get(e.name);
      if (octet === undefined) {
        while (taken.has(next)) next += 1;
        if (next > SPEC_OCTET_MAX) {
          throw new Error(
            `Too many pinned machines on one lane — the .${SPEC_OCTET_MIN}-.${SPEC_OCTET_MAX} band is ` +
            `full (${SPEC_OCTET_MAX - SPEC_OCTET_MIN + 1} maximum). Reduce the environment's asset count.`
          );
        }
        octet = next;
        taken.add(octet);
      }
      pinnedHosts.push({ name: e.name, octet, subnetBase: e.subnetBase });
    }
  }

  // Validation goes through lane-deployer.resolveDnsAliases rather than a second
  // regex here: one malformed label stops dnsmasq starting, which takes DHCP
  // down for every machine in the lane. That function already drops invalid
  // entries with a warning, and reusing it is what keeps the two deploy paths
  // from disagreeing about what a valid alias is.
  const ipFor = {};
  for (const h of pinnedHosts) ipFor[h.name] = `${h.subnetBase}.${h.octet}`;
  // Consoles always draw the external base, matching writeLaneReservations'
  // console loop — the two must agree or the record points off-subnet.
  for (const [name, octet] of Object.entries(consoleOctetForVm)) {
    ipFor[name] = `${laneSubnetBase}.${octet}`;
  }

  const dnsRecords = [];
  const claimedBy = {};
  // ONE claim table across spec VMs and extras, not two. A spec machine named
  // 'elk' and an added ELK workstation both claiming the alias is exactly the
  // shape a blue-team lane produces by accident, and dnsmasq would answer with
  // whichever host-record it happened to read first — so name both rather than
  // publishing a coin flip.
  const claimAlias = (alias, machineName, ip) => {
    if (claimedBy[alias]) {
      throw new Error(
        `dns_alias '${alias}' is claimed by two machines on this lane ` +
        `('${claimedBy[alias]}' and '${machineName}')`
      );
    }
    claimedBy[alias] = machineName;
    dnsRecords.push({ alias, ip });
  };

  for (const vmSpec of specVms) {
    const ip = ipFor[vmSpec.name];
    if (!ip) continue;
    // Validation goes through lane-deployer.resolveDnsAliases (see above); the
    // spec's per-VM key is wrapped in the template shape that function reads.
    const aliases = laneDeployer.resolveDnsAliases({
      metadata: { dns_aliases: vmSpec.dns_aliases ||
        (requiredIpOctets[vmSpec.name] != null ? [vmSpec.name.toLowerCase()] : undefined) },
      template_key: vmSpec.name,
    });
    for (const alias of aliases) claimAlias(alias, vmSpec.name, ip);
  }

  // Extras SECOND, so a spec VM's record keeps the address it has always had and
  // the duplicate-alias error names the added machine as the newcomer. An extra
  // with no aliases contributes nothing, which is what keeps every existing
  // caller byte-identical — every one of them passes no extraConsoles at all.
  for (const extra of extraConsoles) {
    if (!extra || extra.octet == null) continue;
    const name = extra.hostname || extra.name;
    if (!name) continue;
    // The catalog row, unwrapped — an extra's aliases live on the TEMPLATE's
    // metadata, which is where the workstation path has always read them.
    const aliases = laneDeployer.resolveDnsAliases({
      metadata: (extra.template || {}).metadata,
      template_key: name,
    });
    if (!aliases.length) continue;
    const ip = `${laneSubnetBase}.${extra.octet}`;
    for (const alias of aliases) claimAlias(alias, name, ip);
  }

  return { pinnedHosts, dnsRecords };
}

function resolveAttackBoxCredentials(user) {
  const username = String(user.email || 'student').split('@')[0]
    .replace(/[^a-z0-9_-]/gi, '-')
    .toLowerCase() || 'student';
  // A caller that just minted the account (admin group deploy) passes the
  // plaintext so Kali and the portal share one password. CLE cannot — portal
  // passwords are bcrypt and unrecoverable — so it gets a fresh per-lane one,
  // which is persisted onto the lane and surfaced in the UI.
  return { username, password: user.password || generatePassword() };
}

/** Proxmox VM name / LXC hostname: lowercase, hostname-safe, <= 63 chars. */
function hostnameFor(base) {
  return String(base).replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase();
}

// ── VNet resolution ──────────────────────────────────────────────────────────

/**
 * Map each allocated VXLAN id to its pre-created SDN VNet. v3 additionally needs
 * the internal VNet at (tag + V3_INTERNAL_TAG_OFFSET); a lane missing either is
 * dropped with a reason rather than deployed onto the wrong bridge.
 */
async function resolveVnets(vxlanIds, subnetScheme) {
  let vnets = [];
  try {
    vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  } catch (e) {
    throw new Error(`Could not read SDN VNets from Proxmox: ${e.message}`);
  }
  const byTag = {};
  for (const v of (vnets || [])) byTag[String(v.tag)] = v;

  const resolved = {};
  const missing = [];
  for (const vxlanId of vxlanIds) {
    const vnet = byTag[String(vxlanId)];
    if (!vnet) {
      missing.push({ vxlanId, reason: `No VNet with tag ${vxlanId} (lab network not fully provisioned)` });
      continue;
    }
    let vnetInt = null;
    if (subnetScheme === 'v3') {
      vnetInt = byTag[String(vxlanId + V3_INTERNAL_TAG_OFFSET)];
      if (!vnetInt) {
        missing.push({ vxlanId, reason: `No internal VNet with tag ${vxlanId + V3_INTERNAL_TAG_OFFSET} (v3 lab network incomplete)` });
        continue;
      }
    }
    resolved[vxlanId] = { vnet, vnetInt };
  }
  return { resolved, missing };
}

/**
 * Where each template actually lives, resolved once for the whole deploy rather
 * than per lane. spec.template_node is only a hint — findTemplateNode corrects it
 * when an image has been migrated, which is why a stale node in a challenge spec
 * doesn't break the deploy.
 *
 * Keyed by VMID because a multi-VM challenge can have its images spread across
 * nodes; assuming one node for all of them fails the clone outright.
 */
async function resolveTemplateNodes(specVms, spec, includeKali) {
  const hint = spec.template_node || getDefaultTemplateNode();
  const vmids = new Set();
  for (const vm of specVms) {
    const id = vm.template_vmid || spec.template_vmid;
    if (id) vmids.add(Number(id));
  }
  if (includeKali) vmids.add(KALI_TEMPLATE_VMID);
  // A live GOAD bake clones the ansible controller too.
  if (spec.goad?.enabled && !spec.goad?.prebaked) vmids.add(goadDeploy.CONTROLLER_TEMPLATE_VMID);

  const out = {};
  await Promise.all([...vmids].map(async (vmid) => {
    try {
      out[vmid] = await findTemplateNode(vmid, hint);
    } catch (e) {
      console.warn(`${LOG} Could not locate template ${vmid} (${e.message}) — falling back to ${hint}`);
      out[vmid] = hint;
    }
  }));
  return out;
}

// ── phase 1: gateways ────────────────────────────────────────────────────────

/**
 * Resolve the instructor's added machines to catalog rows.
 *
 * Filtered on the SAME predicate the picker and the workstation provision
 * endpoint use, so a template that is offered can always be deployed, and one
 * that cannot is refused here rather than half-way through building a lane.
 *
 * @param {Array} extras [{ template_id, resources }] in slot order
 * @returns {Promise<Array>} [{ template, hostname, resources }]
 */
async function loadExtraWorkstations(extras, logTag) {
  if (!Array.isArray(extras) || extras.length === 0) return [];

  const ids = extras.map(e => e.template_id).filter(Boolean);
  if (ids.length !== extras.length) throw new Error('Every added machine needs a template_id');
  // Two slots sharing one catalog row would give the lane two machines wanting
  // the same reservation hostname, and dnsmasq keys DNS off that name.
  if (new Set(ids.map(String)).size !== ids.length) {
    throw new Error('Each added machine must use a different workstation template');
  }

  const result = await cybercoreQuery(`
    SELECT id AS template_id, os_name AS name, template_key, os_family, os_version,
           provider_type, template_vmid, node, metadata
      FROM cybercore_template_catalog
     WHERE id = ANY($1::uuid[])
       AND template_type = 'workstation'
       AND is_active     = TRUE
       AND status        = 'active'
       AND template_vmid IS NOT NULL
  `, [ids]);

  const byId = {};
  for (const row of result.rows) byId[String(row.template_id)] = row;

  return extras.map((e, i) => {
    const template = byId[String(e.template_id)];
    if (!template) {
      throw new Error(
        `Added machine ${i + 1} is not a deployable workstation template — it may be inactive, ` +
        `still a draft, or missing its VMID. Check Admin -> Workstation Templates.`
      );
    }
    const slug = String(template.template_key || template.name || `ws${i}`)
      .toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    return { template, hostname: `${slug || 'ws'}-${i}`, resources: e.resources || null };
  });
}

/**
 * Replicate the gateway LXC template onto every target node, so the per-lane
 * clones are node-local. A cross-node LXC clone storm is the slowest part of a
 * class-sized deploy. Returns { byNode, tempIds } — tempIds are cleaned up by
 * cleanupTempGatewayTemplates once every gateway is cloned.
 */
async function replicateGatewayTemplate(targetNodes, templateNode, gatewayVmid, logTag) {
  const byNode = {};

  // Pick ids that are actually free rather than always starting at the base.
  // Two deploys running at once would otherwise both claim 169200, and a
  // cleanup that failed leaves an id occupied that nothing else sweeps — either
  // way the second clone fails with "VM already exists".
  const taken = new Set();
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    for (const r of (resources || [])) {
      const id = Number(r.vmid);
      if (id >= TEMP_GW_TEMPLATE_BASE && id < TEMP_GW_TEMPLATE_BASE + 100) taken.add(id);
    }
  } catch (e) {
    console.warn(`${logTag} Could not list cluster VMIDs to pick temp template ids: ${e.message}`);
  }
  let cursor = TEMP_GW_TEMPLATE_BASE;
  const nextTempId = () => {
    while (taken.has(cursor) && cursor < TEMP_GW_TEMPLATE_BASE + 100) cursor++;
    taken.add(cursor);
    return cursor++;
  };

  for (const node of targetNodes) {
    if (node === templateNode) {
      byNode[node] = gatewayVmid;
      continue;
    }
    const tempId = nextTempId();
    try {
      const upid = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
        newid: tempId,
        hostname: `gw-template-temp-${node}`,
        full: 1,
        target: node,
        description: `Temp gateway template for batch deploy`,
      });
      if (upid) await waitForTask(templateNode, upid);
      byNode[node] = tempId;
      console.log(`${logTag} Gateway template replicated to ${node} as ${tempId}`);
    } catch (err) {
      // Fall back to cross-node cloning from the origin — slower, still correct.
      console.error(`${logTag} Failed to replicate gateway template to ${node}: ${err.message}`);
      byNode[node] = gatewayVmid;
    }
  }
  return byNode;
}

async function cleanupTempGatewayTemplates(byNode, gatewayVmid, logTag) {
  const temps = Object.entries(byNode).filter(([, id]) => id !== gatewayVmid);
  if (temps.length === 0) return;
  await Promise.all(temps.map(async ([node, id]) => {
    try {
      await proxmoxAPI('DELETE', `/api2/json/nodes/${node}/lxc/${id}?purge=1&force=1`);
      console.log(`${logTag} Deleted temp gateway template ${id} on ${node}`);
    } catch (e) {
      console.warn(`${logTag} Could not delete temp gateway template ${id} on ${node}: ${e.message}`);
    }
  }));
}

/**
 * Clone + configure one lane gateway. Grouped by node and run serially within a
 * node by the caller: Proxmox holds a disk lock on an LXC template, so two
 * concurrent clones of the same container template fail with "CT is locked".
 */
async function cloneGateway(job, sourceNode, sourceVmid, ctx) {
  const { laneId, user, vxlanId, vnet, vnetInt, laneName, targetNode, wanIp } = job;
  const { subnetScheme, moduleKey, spec, description, logTag } = ctx;
  const gatewayVmId = GATEWAY_VMID_OFFSET + vxlanId;

  // Per-lane bootstrap secret embedded as a `-b<16hex>` suffix on the LXC
  // hostname. firstboot greps it back out (`hostname | grep -oE 'b[a-f0-9]{16}$'`)
  // and includes it as ?secret=… on the /api/lane-bootstrap request. Replaces
  // source-IP gating, which breaks behind the orchestrator's Docker bridge.
  // Hostname budget: 63 chars; reserve 18 for `-b<16hex>`.
  const claimSecret = crypto.randomBytes(8).toString('hex');
  const baseHost = hostnameFor(`${laneName}-gateway`.substring(0, 63 - 18)).replace(/-+$/g, '');
  const hostname = `${baseHost}-b${claimSecret}`;

  const upid = await proxmoxAPI('POST', `/api2/json/nodes/${sourceNode}/lxc/${sourceVmid}/clone`, {
    newid: gatewayVmId,
    hostname,
    full: 1,
    target: targetNode,
    description: `Lane gateway\nUser: ${user.email}\nLane: ${laneId}${description ? `\n${description}` : ''}`,
    pool: `${moduleKey}-pool`,
  });
  if (upid) await waitForTask(sourceNode, upid, 600000);

  const net = resolveLaneNetworking(subnetScheme, moduleKey, vxlanId, { wanIp });
  // Pre-baked ("GOAD-Like") lanes pin a fixed subnet so the gateway's ext0/int0
  // land on the same base the golden-image AD was baked on. Throws when the spec
  // is pre-baked and never said which base that is — see applyPrebakedFixedSubnet.
  applyPrebakedFixedSubnet(net, subnetScheme === 'v3', spec);

  if (subnetScheme === 'v3') {
    await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/config`, {
      net0: formatLaneGatewayNet0(net.wan),
      net1: `name=ext0,bridge=${vnet.vnet},ip=${net.lanExt.gatewayIp}/24,type=veth`,
      net2: `name=int0,bridge=${vnetInt.vnet},ip=${net.lanInt.gatewayIp}/24,type=veth`,
    });
  } else {
    await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/config`, {
      net0: formatLaneGatewayNet0(net.wan),
      net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`,
    });
  }

  await configureLaneTailscale({
    subnetScheme, vxlanId, wanIp: net.wan.ip.split('/')[0], laneName, claimSecret, logTag,
  });
}

// ── phase 2: per-lane VMs ────────────────────────────────────────────────────

/**
 * Clone one challenge VM onto the lane. Honours the spec's role/nic_model/GOAD
 * MAC, the v3 dual-homed DMZ layout, and the pre-baked cloud-init strip.
 */
async function cloneChallengeVm({ vmSpec, vxlanId, targetNode, laneId, user, ctx, net, goadMacs, vnetExtName, vnetIntName }) {
  const { moduleKey, spec, subnetScheme, challengeKey, description, logTag, cloneSem, templateNodeByVmid } = ctx;
  const isV3 = subnetScheme === 'v3';

  const vmId       = (vmSpec.vm_offset || DEFAULT_VM_OFFSET) + vxlanId;
  const vmTemplate = vmSpec.template_vmid || spec.template_vmid;
  const vmName     = vmSpec.name || challengeKey;
  const vmType     = vmSpec.type || 'qemu';

  if (!vmTemplate) throw new Error(`Challenge VM '${vmName}' has no template_vmid in spec`);

  // Each template can live on a different node. Resolved once per VMID up front
  // (see resolveTemplateNodes) — cloning every VM from one node, as the inline
  // version did, fails outright for a multi-VM spec whose images aren't
  // co-located.
  const templateNode = templateNodeByVmid[vmTemplate] || getDefaultTemplateNode();

  const goadVm    = goadMacs[vmName];
  const isGoadVm  = !!goadVm;
  const cloneName = hostnameFor(`${vmName}-${String(user.email).split('@')[0]}`);

  // Single owner for "which VNet does this VM attach to": the spec's explicit
  // nics[] when the topology canvas authored them, the historical name/role
  // derivation otherwise. See lane-networking.resolveVmNics.
  // A console-designated machine gets a deterministic MAC so the lane's DHCP
  // reservation can pin it to a fixed address. Without that it takes an ordinary
  // pool lease and the gateway's DNAT points at nothing — which is exactly why
  // the console used to be Kali-only. Same macForOctet() cloneAttackBox uses, so
  // the reservation and the NIC cannot disagree.
  const consoleOctet = (ctx._consoleOctetForVm || {})[vmName];
  // A pinned NON-console machine takes the identical treatment: same
  // macForOctet(), so its reservation and its NIC cannot disagree. Only one of
  // the two maps ever holds a given name — resolveSpecAddressing skips anything
  // already designated a console.
  const pinnedOctet = consoleOctet != null
    ? consoleOctet
    : (ctx._pinnedOctetForVm || {})[vmName];
  const { nets, dualHomed } = resolveVmNics(vmSpec, {
    subnetScheme,
    bridges: resolveSegmentBridges(subnetScheme, vnetExtName, vnetIntName),
    goadMac: goadVm?.mac,
    pinnedMac: goadVm?.mac
      || (pinnedOctet != null ? goadDeploy.macForOctet(pinnedOctet, vxlanId) : null),
    goadVm,
    isGoadVm,
  });

  // A dual-homed machine builds its NICs inline and ignores the pin entirely, so
  // it would come up with no reservation and a dead console. v3 pins those to
  // .240 by design; say so rather than deploying something that cannot work.
  if (dualHomed && consoleOctet != null) {
    throw new Error(
      `'${vmName}' is dual-homed and cannot be the student console: it is pinned to .240 on both ` +
      `segments by the v3 layout, which the console reservation cannot override. ` +
      `Point the console at a single-homed machine.`
    );
  }

  await cloneSem.run(async () => {
    console.log(`${logTag} Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName}) for ${user.email}`);

    if (vmType === 'lxc') {
      const upid = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
        newid: vmId, hostname: cloneName, full: 1, target: targetNode,
        description: `VM: ${vmName}\nUser: ${user.email}\nLane: ${laneId}${description ? `\n${description}` : ''}`,
        pool: `${moduleKey}-pool`,
      });
      if (upid) await waitForTask(templateNode, upid, 600000);
      await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/lxc/${vmId}/config`, nets);
      return;
    }

    const upid = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
      newid: vmId, name: cloneName, full: 1, target: targetNode,
      description: `VM: ${vmName}\nUser: ${user.email}\nLane: ${laneId}${description ? `\n${description}` : ''}`,
      pool: `${moduleKey}-pool`,
    });
    if (upid) await waitForTask(templateNode, upid, 600000);

    if (dualHomed) {
      await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${vmId}/config`, nets);
      // Dual-homed DMZ host sits at .240 on both segments. It used to be pinned
      // to .50, but the gateway firstboot reserves ext .50 for Kali's RDP DNAT
      // (wan0:3389 → ext.50) — so the two collided and student RDP landed on the
      // web host, not Kali. .240 is above the gateway's DHCP pool (.10–.200), so
      // no lease can claim it and no gateway re-bake is needed.
      //
      // Only v3 carries the two subnets this pins into. A multi-NIC spec on a
      // v1/v2 lane still gets both NICs above, just no static pinning.
      if (isV3) {
        await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${vmId}/config`, {
          ipconfig0:  `ip=${net.lanExt.base3}.${DUAL_HOMED_OCTET}/24,gw=${net.lanExt.gatewayIp}`,
          ipconfig1:  `ip=${net.lanInt.base3}.${DUAL_HOMED_OCTET}/24`,
          nameserver: net.lanExt.gatewayIp,
          citype:     'nocloud',
        });
        await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/qemu/${vmId}/cloudinit`).catch(() => {});
      }
      return;
    }

    const vmConfig = { ...nets };
    if (goadVm?.memory)  vmConfig.memory  = goadVm.memory;
    if (goadVm?.balloon) vmConfig.balloon = goadVm.balloon;
    if (goadVm?.cores)   vmConfig.cores   = goadVm.cores;
    await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${vmId}/config`, vmConfig);

    // Pre-baked golden images are already fully provisioned + domain-joined.
    // Proxmox regenerates a cloud-init ISO on every clone, and cloudbase-init
    // then applies the clone's VM name as the Windows hostname — which silently
    // breaks a member's domain secure channel, because its baked AD account
    // (e.g. TUC-SRV02$) no longer matches its renamed host. Domain controllers
    // are immune (Windows refuses to rename a DC), which is exactly why only
    // members broke in testing. Strip the cloud-init drive so the baked hostname
    // + whole identity survive the clone untouched; the reserved IP still
    // arrives via the deterministic MAC on net0.
    if (spec.goad?.prebaked && isGoadVm) {
      try {
        const cfg = await proxmoxAPI('GET', `/api2/json/nodes/${targetNode}/qemu/${vmId}/config`);
        const ciKey = cfg && Object.keys(cfg).find(k =>
          /^(ide|sata|scsi|virtio)\d+$/.test(k) &&
          typeof cfg[k] === 'string' && /cloudinit/i.test(cfg[k]));
        if (ciKey) {
          await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/qemu/${vmId}/config`, { delete: ciKey });
          console.log(`${logTag} Pre-baked ${vmName}: stripped cloud-init drive ${ciKey} (preserve baked hostname)`);
        } else {
          console.log(`${logTag} Pre-baked ${vmName}: no cloud-init drive found to strip`);
        }
      } catch (err) {
        console.warn(`${logTag} Pre-baked ${vmName}: cloud-init strip failed (member secure channel may break): ${err.message}`);
      }
    }
  });

  // proxmox_name is the clone name; `name` stays the spec name every other
  // caller (vuln scripts, flags, lane config) already matches on.
  return { vm_id: vmId, name: vmName, proxmox_name: cloneName, type: vmType, node: targetNode };
}

/**
 * Clone one CATALOG workstation the instructor added at deploy time.
 *
 * Everything template-shaped goes through lane-deployer's own resolvers rather
 * than a second copy here: each of them encodes a failure that has already
 * happened once on this cluster —
 *   - resolveNicModel: a stock Windows image has no virtio-net driver and never
 *     DHCPs, so it must get e1000;
 *   - resolveCitype: an unset citype means `nocloud`, which cloudbase-init finds,
 *     cannot parse, and REPORTS SUCCESS on — the account keeps its bake-time
 *     password while the lane advertises a generated one;
 *   - findCloudInitDrive: a template with no drive must fall back to its baked
 *     accounts, because publishing a credential Guacamole can only fail to
 *     authenticate with is worse than prompting.
 *
 * Addressing is DHCP against the MAC-keyed reservation, never a static
 * ipconfig0 — a static pin races the guest's own DHCP client and loses. That is
 * the same bug the Kali clone above carries its own note about.
 *
 * @returns a deployedVMs-shaped record, so it lands in config.vms[] with
 *   everything else. That placement is load-bearing: teardownLanes reads
 *   config.workstations ONLY when config.vms is empty, which on a challenge lane
 *   it never is — so a machine recorded anywhere else would never be destroyed.
 */
async function cloneExtraWorkstation({
  extra, vmid, octet, vxlanId, targetNode, laneId, user, ctx, net, vnet, laneSubnetBase,
}) {
  const { moduleKey, description, logTag, cloneSem, subnetScheme } = ctx;
  const template = extra.template;
  const providerType = template.provider_type === 'lxc' ? 'lxc' : 'qemu';
  const cloneName = hostnameFor(`${extra.hostname}-${String(user.email).split('@')[0]}`);
  const mac = goadDeploy.macForOctet(octet, vxlanId);
  const templateNode = ctx.templateNodeByVmid[template.template_vmid] || getDefaultTemplateNode();
  const gatewayIp = subnetScheme === 'v3' ? net.lanExt.gatewayIp : net.lan.gatewayIp;

  let creds = laneDeployer.resolveWorkstationCredentials(template, user);

  await cloneSem.run(async () => {
    console.log(`${logTag} Cloning added workstation ${template.template_vmid} → ${vmid} (${extra.hostname}) for ${user.email}`);
    const upid = await proxmoxAPI('POST',
      `/api2/json/nodes/${templateNode}/${providerType}/${template.template_vmid}/clone`, {
        newid: vmid, full: 1, target: targetNode,
        ...(providerType === 'lxc' ? { hostname: cloneName } : { name: cloneName }),
        description: `Added workstation: ${extra.hostname}
User: ${user.email}
Lane: ${laneId}${description ? `
${description}` : ''}`,
        pool: `${moduleKey}-pool`,
      });
    if (upid) await waitForTask(templateNode, upid, 600000);

    const base = `/api2/json/nodes/${targetNode}/${providerType}/${vmid}`;
    const nicVal = providerType === 'lxc'
      ? `name=eth0,bridge=${vnet.vnet},hwaddr=${mac},firewall=0,ip=dhcp`
      : `${laneDeployer.resolveNicModel(template)},bridge=${vnet.vnet},macaddr=${mac},firewall=0`;
    await proxmoxAPI('PUT', `${base}/config`, { net0: nicVal });

    // Sizing before the first boot, so cloud-init's growpart sees the resized disk.
    await laneDeployer.applyResources({
      node: targetNode, vmid, providerType,
      resources: extra.resources || null, laneName: cloneName,
    }).catch((e) => console.warn(`${logTag} Could not size ${cloneName}: ${e.message}`));

    if (providerType === 'qemu' && creds.source === 'cloudinit' && template.metadata?.cloud_init !== false) {
      let ciDrive = null;
      try { ciDrive = await laneDeployer.findCloudInitDrive(targetNode, vmid); }
      catch (e) { console.warn(`${logTag} cloud-init probe failed for ${cloneName}: ${e.message}`); }

      if (ciDrive) {
        const citype = laneDeployer.resolveCitype(template);
        await proxmoxAPI('PUT', `${base}/config`, {
          ...(citype ? { citype } : {}),
          ciuser: creds.username,
          cipassword: creds.password,
          ipconfig0: 'ip=dhcp',
          nameserver: gatewayIp,
        });
        await proxmoxAPI('PUT', `${base}/cloudinit`).catch(() => {});
      } else {
        console.log(`${logTag} ${cloneName}: no cloud-init drive — using the template's own accounts`);
        creds = { username: null, password: null, source: 'baked' };
      }
    } else if (providerType === 'lxc' && creds.source === 'cloudinit') {
      creds = { username: null, password: null, source: 'baked' };
    }
  });

  return {
    vm_id: vmid,
    name: extra.hostname,
    proxmox_name: cloneName,
    type: providerType,
    node: targetNode,
    // Marks it as an instructor addition rather than part of the environment's
    // own definition — flag planting keys on the spec, not on this list.
    source: 'instructor',
    octet,
    ip: `${laneSubnetBase}.${octet}`,
    template_id: template.template_id || template.id || null,
    template_name: template.name || template.os_name || null,
    _creds: creds,
  };
}

/**
 * Clone + configure the Kali attack box. Addressing is DHCP with a deterministic
 * MAC; the gateway's dnsmasq (fed by goadDeploy's hostMap, which reserves
 * <ext>.50 for that MAC) hands it .50 — matching the gateway's baked
 * wan0:3389 → ext.50 DNAT.
 *
 * Why DHCP and not the old `ipconfig0: ip=<ext>.50/24` static pin: the Kali cloud
 * image's hotplug-DHCP helper (cloud-ifupdown) raced the static config and won,
 * leaving Kali on a random lease; and the static path never populated
 * /etc/resolv.conf (no resolvconf), so DNS broke. DHCP fixes both.
 */
async function cloneAttackBox({ attackBoxVmId, vxlanId, targetNode, laneId, user, creds, ctx, vnet, laneSubnetBase }) {
  const { moduleKey, description, logTag, cloneSem, templateNodeByVmid } = ctx;
  const templateNode = templateNodeByVmid[KALI_TEMPLATE_VMID] || getDefaultTemplateNode();

  await cloneSem.run(async () => {
    console.log(`${logTag} Cloning Kali attack box → ${attackBoxVmId} for ${user.email}`);
    const upid = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${KALI_TEMPLATE_VMID}/clone`, {
      newid: attackBoxVmId,
      name: hostnameFor(`kali-${creds.username}`),
      full: 1,
      target: targetNode,
      description: `Attack Box (Kali)\nUser: ${user.email}\nLane: ${laneId}${description ? `\n${description}` : ''}`,
      pool: `${moduleKey}-pool`,
    });
    if (upid) await waitForTask(templateNode, upid, 600000);
  });

  console.log(`${logTag} Configuring cloud-init for ${attackBoxVmId} (user: ${creds.username})`);
  await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/config`, {
    net0: `virtio=${goadDeploy.macForOctet(goadDeploy.INFRA_IP_OCTETS.Kali, vxlanId)},bridge=${vnet.vnet}`,
    ipconfig0: 'ip=dhcp',
    ciuser: creds.username,
    cipassword: creds.password,
    nameserver: `${laneSubnetBase}.1`,
  });
  await proxmoxAPI('PUT', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/cloudinit`);
}

// A DNS NAME, not the single LABEL lane-deployer.resolveDnsAliases validates.
// Both lines resolveLaneDnsExtras writes carry a dotted name — `sevenkingdoms.local`
// for the forwarder, `www.acme-clinic.com` for the company site — and DNS_LABEL_RE
// would reject them both, so this is the one place that needs its own pattern.
// Per-label rules are the same (letters/digits/inner hyphens, 63 octets).
const DNS_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

// Range-checked rather than /\d+(\.\d+){3}/: `10.39.999.10` is four numbers and
// not an address, and dnsmasq refuses to start on the line rather than ignoring
// it — which takes DHCP down for every machine on the lane (installLaneReservations).
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** A spec-supplied DNS name, normalised — or '' when it is not one. */
function dnsNameOrEmpty(value) {
  // The trailing dot of a root-form FQDN is stripped rather than rejected: it is
  // a normal way to type one, and dnsmasq wants the name without it.
  const name = String(value == null ? '' : value).trim().toLowerCase().replace(/\.$/, '');
  if (!name || name.length > 253 || !DNS_NAME_RE.test(name)) return '';
  return name;
}

/**
 * The company's own DNS answers for a lane: a conditional forwarder for its AD
 * forest, and a name for its public web site.
 *
 * WHY THIS EXISTS. Nothing on a lane resolves the company's domain. The gateway
 * serves `cybercore.lan` and forwards everything else upstream, so Kali's
 * resolver knows the lane's short names and nothing about the forest. Every AD
 * tool invoked the way a student is taught to invoke it — `nxc smb dc01.corp.local`,
 * `bloodhound-python -d corp.local`, `GetUserSPNs.py corp.local/user` without
 * `-dc-ip` — fails at name resolution, before it has touched the target once.
 * `server=/<domain>/<dc>` fixes all of them at once: dnsmasq matches the domain
 * AND every subdomain, so the `_msdcs`/`_tcp` SRV records Kerberos and the
 * DC-locator actually look up are covered by the single line.
 *
 * OPT-IN. Reads `spec.dns` and nothing else, and no challenge in the tree carries
 * one, so every existing lane's reservations file is byte-identical:
 *
 *   spec.dns = {
 *     ad_domain: 'corp.acme-clinic.local',  // forest to forward (defaults to spec.goad.domain)
 *     ad_dc:     'DC01',                    // SPEC name of the DC that answers it
 *     web_name:  'www.acme-clinic.com',     // the company's public web name
 *     web_vm:    'web01',                   // SPEC name of the machine serving it
 *   }
 *
 * The DC and the web server are named as MACHINES, never as addresses: the lane
 * subnet is allocated per lane (`10.<vxh>.<vxl>`), so an IP literal in a spec is
 * right for at most one student and silently wrong for the rest.
 *
 * Pure over its inputs, like resolveSpecAddressing, and it validates before it
 * emits: these lines land in the SAME file as the lane's DHCP reservations, and
 * dnsmasq refuses to start on one malformed directive — which would take DHCP
 * down for the whole lane. So anything unusable is skipped with a warning
 * naming what was there, never written through.
 *
 * @param {string} [a.subnetScheme] the lane's scheme; only v3 statically pins its
 *   dual-homed DMZ host, so only v3 can publish that host's address
 * @returns {string[]} dnsmasq lines, empty when the spec declares no `dns` block
 */
function resolveLaneDnsExtras({
  spec = {}, goadMacs = {}, consoleOctets = {}, pinnedHosts = [],
  extSubnetBase, subnetScheme, logTag = LOG,
}) {
  const dns = spec && spec.dns;
  if (!dns || typeof dns !== 'object') return [];

  // Every address on this lane that is knowable at deploy time, keyed by the
  // SPEC name — the name an author writes in ad_dc / web_vm, not the Proxmox
  // clone name (which carries the student's username appended).
  const ipFor = {};
  for (const [name, info] of Object.entries(goadMacs || {})) {
    if (info && info.static_ip) ipFor[name] = info.static_ip;
  }
  for (const h of (pinnedHosts || [])) {
    if (h && h.name && h.subnetBase && h.octet != null) ipFor[h.name] = `${h.subnetBase}.${h.octet}`;
  }
  // Consoles draw the EXTERNAL base, matching writeLaneReservations' own console
  // loop — the two must agree or the record points at an off-subnet address.
  for (const [name, octet] of Object.entries(consoleOctets || {})) {
    if (extSubnetBase && octet != null) ipFor[name] = `${extSubnetBase}.${octet}`;
  }
  // The v3 dual-homed DMZ host. It is in NONE of the three sources above, and
  // that is deliberate in every one of them: resolveSpecAddressing skips a
  // multi-segment VM before it can reach pinnedHosts (resolveVmNics builds those
  // NICs inline and ignores the pinned MAC, so a reservation would be one
  // nothing ever requests), the pivot is not a GOAD lab host, and cloneChallengeVm
  // throws outright if it is named the console. So the company's own website —
  // on exactly the topology profile-to-spec now defaults to — resolved to
  // nothing: an empty record list plus a warning that web_vm could not be found.
  //
  // Its address IS knowable, and from the same constant the clone path writes:
  // cloneChallengeVm gives a dual-homed guest a STATIC .DUAL_HOMED_OCTET on both
  // segments (ipconfig0/ipconfig1), which is why no reservation is needed for it
  // in the first place.
  //
  // THE EXTERNAL ADDRESS, not the internal one. The host answers on both, and
  // ext is the segment Kali sits on: the site is meant to be reachable from the
  // attack box directly, and an int-side answer would route the student THROUGH
  // the machine they are attacking. It is also the address ipconfig0 carries, so
  // the record and the guest's primary interface cannot disagree.
  //
  // v3 ONLY. A multi-NIC spec on a v1/v2 lane still gets both NICs, but no
  // static pinning — there is no .240 there, and publishing one anyway would
  // point the company's name at an address nothing holds. No scheme, no entry.
  if (subnetScheme === 'v3' && extSubnetBase) {
    for (const vmSpec of (Array.isArray(spec.vms) ? spec.vms : [])) {
      const name = vmSpec && vmSpec.name;
      // Already resolved above means a real dhcp-host line exists for it; that
      // address is the one the lane hands out, so it wins over this inference.
      if (!name || ipFor[name]) continue;
      // An LXC gets net1 and one segment whatever its spec says (resolveVmNics),
      // so it never reaches the .240 ipconfig pass either.
      if ((vmSpec.type || 'qemu') === 'lxc') continue;
      // resolveVmSegments is the same predicate resolveVmNics derives dualHomed
      // from — asked here rather than re-spelled, so "which machines are pinned
      // to .240" has one answer for the clone path and the DNS table both.
      const segs = resolveVmSegments(vmSpec, { subnetScheme, isGoadVm: !!(goadMacs || {})[name] });
      if (segs.length < 2) continue;
      ipFor[name] = `${extSubnetBase}.${DUAL_HOMED_OCTET}`;
    }
  }
  const machines = () => Object.keys(ipFor).join(', ') || '(none)';

  const lines = [];

  // ── conditional forwarder for the AD forest ────────────────────────────────
  // An author who names the DC but not the domain means the one the GOAD half of
  // the spec already declares; making them write it twice is how the two drift.
  const declaredAdDomain = String(dns.ad_domain == null ? '' : dns.ad_domain).trim();
  const declaredAdDc = String(dns.ad_dc == null ? '' : dns.ad_dc).trim();
  const rawAdDomain = declaredAdDomain
    || (declaredAdDc ? String((spec.goad || {}).domain || '').trim() : '');
  if (declaredAdDc && !rawAdDomain) {
    // Named the machine, named no forest, and the spec has no GOAD domain to
    // borrow. Silence here would read as "the author didn't want a forwarder".
    console.warn(
      `${logTag} spec.dns.ad_dc '${declaredAdDc}' names a domain controller but no domain to ` +
      `forward to it — set dns.ad_domain (or spec.goad.domain), or nothing on this lane resolves ` +
      `the forest.`);
  } else if (rawAdDomain) {
    const adDomain = dnsNameOrEmpty(rawAdDomain);
    let dcName = declaredAdDc;
    // A named machine wins. Otherwise the lab's own DC, whose address
    // prepareGoadMacs has already resolved onto this lane's internal segment.
    // A profile-derived lane has no GOAD lab at all — its DC is an ordinary
    // pinned machine — so `ad_dc` is the only way to name it there.
    //
    // The FIRST DC, not every DC: a second `server=/<forest>/` line would send
    // part of the lane's forest traffic to DC02, which in the stock labs holds a
    // DIFFERENT domain and is not guaranteed authoritative for the root. Name
    // `ad_dc` explicitly when the first DC is not the one that should answer.
    let dcIp = dcName ? (ipFor[dcName] || null) : null;
    if (!dcName) {
      const dc = Object.entries(goadMacs || {})
        .find(([, info]) => info && info.role === 'dc' && info.static_ip);
      if (dc) { dcName = dc[0]; dcIp = dc[1].static_ip; }
    }
    if (!adDomain) {
      console.warn(
        `${logTag} spec.dns.ad_domain ${JSON.stringify(rawAdDomain)} is not a usable DNS name — ` +
        `skipping the AD forwarder. Nothing on this lane will resolve the forest.`);
    } else if (!dcIp) {
      console.warn(
        `${logTag} spec.dns: no address on this lane for the '${adDomain}' domain controller` +
        `${dcName ? ` '${dcName}'` : ' (no dns.ad_dc, and no GOAD host with role dc)'} — ` +
        `skipping the forwarder. Lane machines: ${machines()}`);
    } else if (!IPV4_RE.test(dcIp)) {
      console.warn(
        `${logTag} spec.dns: domain controller '${dcName}' resolved to ${JSON.stringify(dcIp)}, ` +
        `which is not an IPv4 address — skipping the '${adDomain}' forwarder.`);
    } else {
      lines.push(`server=/${adDomain}/${dcIp}`);
    }
  }

  // ── the company's public web name ─────────────────────────────────────────
  const declaredWebName = String(dns.web_name == null ? '' : dns.web_name).trim();
  if (declaredWebName) {
    const webName = dnsNameOrEmpty(declaredWebName);
    const webVm = String(dns.web_vm == null ? '' : dns.web_vm).trim();
    const webIp = webVm ? (ipFor[webVm] || null) : null;
    if (!webName) {
      console.warn(
        `${logTag} spec.dns.web_name ${JSON.stringify(declaredWebName)} is not a usable DNS name — skipping it.`);
    } else if (!webVm) {
      console.warn(
        `${logTag} spec.dns.web_name '${webName}' names no machine (set dns.web_vm to a spec VM) — skipping it.`);
    } else if (!webIp) {
      console.warn(
        `${logTag} spec.dns.web_vm '${webVm}' has no address on this lane, so '${webName}' would ` +
        `resolve to nothing — skipping it. A machine only has a knowable address if it is a GOAD ` +
        `host, a console, pinned, or the v3 dual-homed DMZ host. Lane machines: ${machines()}`);
    } else if (!IPV4_RE.test(webIp)) {
      console.warn(
        `${logTag} spec.dns.web_vm '${webVm}' resolved to ${JSON.stringify(webIp)}, which is not an ` +
        `IPv4 address — skipping '${webName}'.`);
    } else if (webName.includes('.')) {
      // A public name is already fully qualified, so it CANNOT go through
      // hostRecordLine: that helper appends the lane's own search domain and
      // would publish `www.acme-clinic.com.cybercore.lan` while leaving the name
      // the student was actually given unresolvable. Two-field host-record is
      // the same directive, minus the suffix.
      lines.push(`host-record=${webName},${webIp}`);
    } else {
      // A bare label goes through the shared helper, so it is published exactly
      // like every other in-lane alias (short AND `.cybercore.lan` forms).
      lines.push(laneDeployer.hostRecordLine(webName, webIp));
    }
  }

  return lines;
}

/**
 * Write the lane's MAC-keyed DHCP reservations into the gateway's dnsmasq.
 *
 * Why this exists at all. The gateway template bakes reservations keyed on the
 * DHCP CLIENT HOSTNAME:
 *
 *     dhcp-host=kali,<ext>.50
 *     dhcp-host=TUC-DC01,<int>.10
 *
 * which only match if the guest announces itself as exactly that name. The Kali
 * clone is named `kali-<user>` and Proxmox's cloud-init takes the guest hostname
 * from the VM name, so the baked `kali` entry never matches and the attack box
 * takes an ordinary pool lease. The gateway's `wan0:3389 -> <ext>.50` DNAT then
 * points at nothing, and the student's Guacamole console connects to a dead
 * address — with no error anywhere that explains why.
 *
 * MAC is the only identifier we actually control: every clone gets
 * macForOctet(<octet>, vxlanId) on net0, so a MAC-keyed reservation cannot miss.
 *
 * goad-deploy.js has a writeDhcpReservations() that does this for GOAD lanes,
 * but nothing has ever called it, and it is GOAD-only — a plain challenge lane
 * with an attack box needs the same reservation. One file covering both keeps a
 * duplicate `dhcp-host` for the same MAC out of dnsmasq, which it treats as
 * fatal.
 *
 * It also carries the lane's DNS, for the same reason: dnsmasq reads every
 * *.conf in /etc/dnsmasq.d and refuses to start when two files disagree, so the
 * per-machine host-records and the company's own names (resolveLaneDnsExtras)
 * go in THIS file rather than a second one.
 *
 * Best-effort by design: it needs a shell inside the gateway LXC over SSH
 * (Proxmox has no LXC exec API). If that isn't configured the lane still comes
 * up, so this logs loudly rather than failing the deploy.
 */
async function writeLaneReservations({
  gatewayVmId, node, vxlanId, goadMacs, attackBoxOctet, consoleOctets,
  pinnedHosts = [], dnsRecords = [], spec = {}, subnetScheme,
  extSubnetBase, intSubnetBase, liveGoadController, laneId, logTag,
}) {
  const lines = [
    '# Lane DHCP reservations — generated by challenge-lane-deployer.js',
    '# Keyed on MAC, not client hostname: the clone names do not match the',
    '# hostname-keyed entries baked into the gateway template.',
  ];

  if (attackBoxOctet != null) {
    // Kali always lives on the EXTERNAL segment, which is where the RDP DNAT is.
    lines.push(`dhcp-host=${goadDeploy.macForOctet(attackBoxOctet, vxlanId)},` +
               `${extSubnetBase}.${attackBoxOctet},kali`);
  }
  // Console-designated machines. Same MAC cloneChallengeVm pinned on net0, so
  // the guest's very first DHCPREQUEST already lands on the address the DNAT
  // installed below points at. Goes in THIS file, not a second one: dnsmasq reads
  // every *.conf in the directory and refuses to start when two claim one
  // address, and installLaneReservations is what neutralises the gateway's own
  // baked `dhcp-host=kali,<ext>.50` before writing.
  for (const [name, octet] of Object.entries(consoleOctets || {})) {
    const label = String(name).toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '');
    if (!label) continue;
    lines.push(`dhcp-host=${goadDeploy.macForOctet(octet, vxlanId)},${extSubnetBase}.${octet},${label}`);
  }
  if (liveGoadController) {
    const octet = goadDeploy.INFRA_IP_OCTETS.controller;
    lines.push(`dhcp-host=${goadDeploy.macForOctet(octet, vxlanId)},${intSubnetBase}.${octet},goad-controller`);
  }
  // GOAD lab hosts (DC01/DC02/SRV01/…). prepareGoadMacs already resolved each
  // one's deterministic MAC and its static IP on the internal segment.
  for (const [vmName, info] of Object.entries(goadMacs || {})) {
    lines.push(`dhcp-host=${info.mac},${info.static_ip},${vmName}`);
  }

  // Ordinary spec machines, when the caller asked for the whole lane to be
  // pinned (`pinAllVms`). Empty for every pre-existing caller, so this loop adds
  // nothing to a CLE or admin-group deploy's file.
  //
  // Each entry brings its OWN subnetBase rather than reusing extSubnetBase like
  // the console loop above: on a v3 lane a spec VM may sit on the internal
  // segment, and a reservation written against the external base would hand it
  // an address on a subnet its NIC is not attached to — dnsmasq would offer a
  // lease the guest cannot use, which looks exactly like "DHCP is broken".
  for (const h of pinnedHosts) {
    const label = String(h.name || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '');
    if (!label) continue;
    lines.push(`dhcp-host=${goadDeploy.macForOctet(h.octet, vxlanId)},${h.subnetBase}.${h.octet},${label}`);
  }

  // Stable in-lane DNS names. Same host-record form the workstation path emits
  // (lane-deployer.hostRecordLine is the one owner of it), landing in THIS
  // file because dnsmasq reads every *.conf in the directory and a second file
  // claiming one address stops it starting.
  //
  // reservationIp() only parses `dhcp-host=` lines, so these are correctly
  // excluded from collision-neutralisation — a host-record cannot collide with
  // a reservation the way two dhcp-host lines can.
  if (dnsRecords.length) {
    lines.push('# Stable per-role names (spec.vms[].dns_aliases).');
    for (const r of dnsRecords) lines.push(laneDeployer.hostRecordLine(r.alias, r.ip));
  }

  // The COMPANY's names — the AD forest's conditional forwarder and its public
  // web name — as opposed to the lane-local ones above. Empty for every spec
  // that does not declare `spec.dns`, which is all of them today.
  // subnetScheme, because only a v3 lane statically pins its dual-homed host —
  // without it the resolver cannot tell "the DMZ host is at .240" from "this
  // lane has no .240 at all", and one of those two answers is a DNS record
  // pointing at an address nothing holds.
  const dnsExtras = resolveLaneDnsExtras({
    spec, goadMacs, consoleOctets, pinnedHosts, extSubnetBase, subnetScheme, logTag,
  });
  if (dnsExtras.length) {
    lines.push('# The company being attacked: AD forwarder + public web name (spec.dns).');
    lines.push(...dnsExtras);
  }

  if (lines.length === 3) return;  // header only — nothing to reserve

  // installLaneReservations, NOT a bare push+restart. Our Kali line claims the
  // same address as the `dhcp-host=kali,<ext>.50` the gateway template bakes into
  // /etc/dnsmasq.conf, and dnsmasq refuses to start when two dhcp-host lines
  // claim one IP. Writing ours without commenting theirs out took dnsmasq down
  // for the whole lane: the GOAD hosts never got .10/.11/.22 and Kali got no
  // address at all, while the lane still reported active. The shared helper
  // neutralizes the baked line, verifies dnsmasq actually came back, and reverts
  // if it did not.
  try {
    await laneDeployer.installLaneReservations({
      node, gatewayVmId, gatewayVmid: gatewayVmId,
      path: '/etc/dnsmasq.d/lane-reservations.conf',
      lines, logTag,
    });
    const nReservations = lines.filter(l => l.startsWith('dhcp-host=')).length;
    console.log(
      `${logTag} Lane ${laneId}: ${nReservations} DHCP reservation(s) written` +
      (dnsRecords.length ? ` + ${dnsRecords.length} DNS host-record(s)` : '') +
      (dnsExtras.length ? ` + ${dnsExtras.length} company DNS line(s): ${dnsExtras.join(' ')}` : '')
    );
  } catch (err) {
    // A dead DHCP server is not survivable — every guest on this lane would sit
    // without an address. Anything else (no SSH channel, for instance) leaves the
    // gateway's baked reservation in place, so the lane is degraded but usable.
    if (err.noFallback || spec.goad?.rename_forest === true) throw err;
    console.error(
      `${logTag} Lane ${laneId}: could not write DHCP reservations (${err.message}). ` +
      (attackBoxOctet != null
        ? `Kali falls back to the gateway's baked hostname reservation for ${extSubnetBase}.${attackBoxOctet}, ` +
          `which only matches a guest announcing itself as exactly "kali". `
        : '') +
      'Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER.'
    );
  }
}

/** First non-loopback IPv4 the Kali guest agent reports, or null. */
async function discoverKaliIp(targetNode, attackBoxVmId, logTag) {
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const data = await proxmoxAPI('GET', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/agent/network-get-interfaces`);
      const ifaces = data?.result || (Array.isArray(data) ? data : []);
      for (const iface of ifaces) {
        if (iface.name === 'lo') continue;
        for (const addr of (iface['ip-addresses'] || [])) {
          const ip = addr['ip-address'];
          if (addr['ip-address-type'] === 'ipv4' && ip && !ip.startsWith('127.')) {
            console.log(`${logTag} Kali IP via guest agent: ${ip} (${iface.name})`);
            return ip;
          }
        }
      }
    } catch (agentErr) {
      console.log(`${logTag} Kali guest agent attempt ${attempt + 1}/10: ${agentErr.message}`);
    }
    if (attempt < 9) await new Promise(r => setTimeout(r, 5000));
  }
  return null;
}

/**
 * The gateway's wan0 transit IP — the ONLY address Guacamole can reach, since
 * guacd runs on the orchestrator's Docker bridge with no route into the lane
 * subnet. Read from the LXC config first (authoritative, no boot dependency),
 * falling back to the live interface list.
 */
async function resolveGatewayTransitIp(targetNode, gatewayVmId) {
  try {
    const cfg = await proxmoxAPI('GET', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/config`);
    const m = String(cfg?.net0 || '').match(/ip=([\d.]+)/);
    if (m) return m[1];
  } catch (_) { /* fall through */ }
  try {
    const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/interfaces`);
    for (const iface of (ifaces || [])) {
      if (iface.name === 'wan0' && iface.inet) return iface.inet.split('/')[0];
    }
  } catch (_) { /* fall through */ }
  return null;
}

/**
 * Create ONE Guacamole connection for a lane machine and grant it to the owner
 * plus any instructors.
 *
 * Generalised from createAttackBoxConsole, which hardcoded rdp/3389 — the only
 * console a challenge lane could have. Protocol and port are now the caller's.
 *
 * The owner's Guacamole account is ensured first. The admin group deploy creates
 * accounts for the users it mints, but the CLE path deploys to a real roster
 * whose members may never have had one — and a PATCH /users/<unknown>/permissions
 * fails, leaving the student with a connection they cannot see.
 *
 * ensureGuacUser, not getGuacCredential: this must never ROTATE an existing
 * account's password. The group deploy prints each student their credential
 * seconds earlier, and a rotation here would invalidate every one of them.
 */
async function createLaneConsole({
  connName, hostname, port = 3389, protocol = 'rdp', creds,
  template = {}, user, guacParent, instructorEmails, logTag,
}) {
  await guacCreds.ensureGuacUser(user.id, user.email).catch((e) =>
    console.warn(`${logTag} Could not ensure a Guacamole account for ${user.email}: ${e.message}`));

  // Parameters come from the SAME builder the workstation path uses, so an SSH
  // console gets a colour scheme rather than an RDP negotiation, and a Windows
  // target gets security:'any' forced — guacd fails the handshake outright
  // against a pinned 'tls', which reads as a broken lane, not a config error.
  const params = laneDeployer.buildGuacParameters({
    protocol, hostname, port, creds, template: template || {},
  });
  if (protocol === 'rdp') {
    // Kept from the Kali-only version: without server-layout the Guac UI shows
    // "Keyboard layout" as unset and keystrokes never reach xrdp.
    params['server-layout'] = params['server-layout'] || 'en-us-qwerty';
    params['ignore-cert'] = 'true';
    params['enable-wallpaper'] = 'true';
    params['enable-theming'] = 'true';
    params['enable-font-smoothing'] = 'true';
    params['enable-full-window-drag'] = 'true';
    params['color-depth'] = '24';
    params['resize-method'] = 'display-update';
  }

  const connBody = {
    name: connName,
    protocol,
    parentIdentifier: guacParent || 'ROOT',
    parameters: params,
    attributes: {
      'max-connections': '2',
      'max-connections-per-user': '1',
    },
  };

  // Refresh an existing connection instead of blindly POSTing. Guacamole's
  // schema carries UNIQUE (connection_name, parent_id), so re-provisioning a
  // lane whose connection name is unchanged makes the POST fail — leaving the
  // OLD connection live with the OLD password while the lane record and the
  // guest both move on. It surfaces only as a credential that silently no
  // longer works. Same idiom as lane-deployer.createGuacConnection and the
  // CIAB deploy path; GET /connections returns an object keyed by identifier.
  let connId = null;
  const existing = await guacAPI('GET', '/connections').catch(() => null);
  if (existing && typeof existing === 'object') {
    for (const [id, c] of Object.entries(existing)) {
      if (c && c.name === connName) { connId = id; break; }
    }
  }

  if (connId) {
    // PUT replaces the whole body, so a refreshed hostname and password both
    // overwrite what the previous deploy left behind.
    await guacAPI('PUT', `/connections/${encodeURIComponent(connId)}`, connBody);
    console.log(`${logTag} Guac connection refreshed: ${connName} (id=${connId})`);
  } else {
    const conn = await guacAPI('POST', '/connections', connBody);
    connId = conn?.identifier || null;
  }
  if (!connId) return null;

  const grantees = [user.email, ...(instructorEmails || [])].filter(Boolean);
  for (const email of grantees) {
    try {
      await guacAPI('PATCH', `/users/${encodeURIComponent(email)}/permissions`, [
        { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' },
      ]);
    } catch (permErr) {
      console.warn(`${logTag} Guac permission grant failed for ${email}: ${permErr.message}`);
    }
  }
  console.log(`${logTag} Guac connection ${connId} → ${user.email}`);
  return connId;
}

/** Run the caller's selected vuln scripts against the lane's QEMU targets. */
async function runVulnScripts({ laneId, deployedVMs, vulnScripts, logTag }) {
  const scriptEntries = vulnScripts.map(s => ({
    script_slug: s.script_slug,
    vm_name: s.vm_name || deployedVMs[0]?.name || 'default',
    status: 'pending',
    error: null,
  }));

  const dvs = await query(
    `INSERT INTO deployment_vuln_selections (lane_id, selected_scripts, status)
     VALUES ($1, $2, 'running_scripts') RETURNING id`,
    [laneId, JSON.stringify(scriptEntries)]
  );
  const deploymentId = dvs.rows[0].id;

  for (const vm of deployedVMs) {
    if (vm.type !== 'qemu') continue;
    const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
    if (!agentReady) {
      console.error(`${logTag} Guest agent not responding on ${vm.name} — skipping its scripts`);
      continue;
    }
    const slugs = vulnScripts
      .filter(s => (s.vm_name || deployedVMs[0]?.name) === vm.name)
      .map(s => s.script_slug);
    if (slugs.length === 0) continue;

    const rows = await query(
      `SELECT slug, script_content, os_target, depends_on, script_args
         FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`,
      [slugs]
    );
    if (rows.rows.length > 0) {
      await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, rows.rows, deploymentId);
    }
  }

  await query(
    `UPDATE deployment_vuln_selections SET status = 'complete', updated_at = NOW() WHERE id = $1`,
    [deploymentId]
  );
}

/**
 * Register every lane VM (challenge VMs + Kali, NOT the gateway — that's
 * plumbing, not a workspace) in cybercore_resource / cybercore_vm_instance /
 * cybercore_allocation, so the OWNER sees them on their "My Workspaces" page.
 *
 * Resource names are (module_key, name) UNIQUE — a single challenge deployed to
 * N lanes would collide on the base VM name (e.g. "ws01"). Suffix with the
 * Proxmox VMID (cluster-unique) to guarantee uniqueness while keeping the name
 * human-readable.
 */
async function registerWorkspaceVms({ laneId, user, vxlanId, moduleKey, challengeKey, laneConfig, rows, logTag }) {
  const slug = String(user.email || user.id).split('@')[0].replace(/[^a-z0-9-]/gi, '-').toLowerCase();

  for (const v of rows) {
    try {
      const resourceRes = await cybercoreQuery(
        `INSERT INTO cybercore_resource (type, module_key, name, status, metadata)
         VALUES ('vm', $1, $2, 'allocated', $3::jsonb)
         RETURNING resource_id`,
        [moduleKey, `${v.name}-${slug}-${v.vmid}`.substring(0, 80), JSON.stringify({
          vm_category:   'lane_vm',
          provider_type: v.providerType,
          template_name: v.templateName,
          lane_id:       laneId,
          vxlan_id:      vxlanId,
          challenge_key: challengeKey,
          ...laneConfig,
        })]
      );
      const resourceId = resourceRes.rows[0].resource_id;

      await cybercoreQuery(
        `INSERT INTO cybercore_vm_instance
           (resource_id, provider, provider_node, provider_vmid, power_state, metadata)
         VALUES ($1, 'proxmox', $2, $3, 'running', $4::jsonb)`,
        [resourceId, v.node, String(v.vmid), JSON.stringify({
          provider_type: v.providerType,
          // The guest name as Proxmox shows it. The resource `name` above is a
          // uniqueness key (spec name + owner slug + VMID), not a label.
          ...(v.proxmoxName ? { proxmox_name: v.proxmoxName } : {}),
          ...(v.guacConnId ? { guac_connection_id: v.guacConnId, guac_user: user.email } : {}),
        })]
      );

      await cybercoreQuery(
        `INSERT INTO cybercore_allocation (resource_id, user_id, purpose)
         VALUES ($1, $2, 'lane_vm')`,
        [resourceId, user.id]
      );
    } catch (regErr) {
      // Non-fatal: the lane still goes active, the VM just won't surface in
      // My Workspaces.
      console.warn(`${logTag} Workspace registration failed for ${v.name} (${user.email}): ${regErr.message}`);
    }
  }
}

/**
 * Everything that happens to ONE lane after its gateway exists: clone the
 * challenge VMs and Kali, boot them, provision GOAD, wire the console, run vuln
 * scripts, plant flags, register workspaces, and mark the lane active.
 */
async function deployLaneVms(job, ctx) {
  const {
    laneId, user, vxlanId, vnet, vnetInt, targetNode, attackBoxCreds, wanIp,
    extraVmids = [],
  } = job;
  const {
    spec, subnetScheme, moduleKey, challengeKey, attackBoxes, vulnScripts,
    laneConfig, guacParent, instructorEmails, progress, logTag,
    consoleVm, extraWorkstations, extraSpecs = [],
  } = ctx;

  const isV3 = subnetScheme === 'v3';
  const gatewayVmId = GATEWAY_VMID_OFFSET + vxlanId;

  const net = resolveLaneNetworking(subnetScheme, moduleKey, vxlanId, { wanIp });
  // Same pin the gateway took in cloneGateway, and the same refusal: the two
  // must agree on the lane's bases or the machines land on a subnet their own
  // gateway does not route.
  applyPrebakedFixedSubnet(net, isV3, spec);
  const vnetExtName    = vnet.vnet;
  const vnetIntName    = isV3 ? vnetInt.vnet : vnet.vnet;
  const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
  const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;

  const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId, goadSubnetBase);
  const specVms  = resolveSpecVms(spec, challengeKey);

  // Which machines get a console, and which one the student opens. Resolved
  // BEFORE any clone, because a spec VM chosen as the console needs a
  // deterministic MAC set on net0 at clone time — a machine that takes an
  // ordinary pool lease has no fixed address for a DNAT to point at, which is
  // the whole reason the console used to be Kali-only.
  const consolePlan = resolveConsolePlan({
    specVms, attackBoxes, extraWorkstations: extraSpecs, override: consoleVm,
  });

  // Address assignment for every machine that needs a fixed one. Kali keeps .50 (the
  // gateway bakes its DNAT against that value); everything else draws from
  // .60-.79, which is the one stretch of the reserved workstation band no other
  // actor on a challenge lane touches. An explicit spec.vms[].ipOctet wins — the
  // same key attached-modules and the GOAD lab definitions already honour.
  const consoleOctets = {};
  // Hoisted so resolveSpecAddressing below draws from the SAME claimed set. Two
  // independent allocators would happily hand one address to a console and to a
  // pinned machine, and dnsmasq refuses to start when two dhcp-host lines claim
  // one — which takes DHCP down for the whole lane.
  const taken = new Set([goadDeploy.INFRA_IP_OCTETS.Kali]);
  {
    Object.values(goadMacs || {}).forEach((g) => {
      const last = Number(String(g.static_ip || '').split('.').pop());
      if (Number.isFinite(last)) taken.add(last);
    });
    let next = CONSOLE_OCTET_MIN;
    for (const c of consolePlan.consoles) {
      if (c.kind === 'kali') { consoleOctets[c.ref] = goadDeploy.INFRA_IP_OCTETS.Kali; continue; }
      const wanted = Number(c.vm && c.vm.ipOctet);   // spec machines only; extras never pin
      if (Number.isFinite(wanted)) {
        if (taken.has(wanted)) {
          throw new Error(
            `Machine '${c.name}' requested IP octet .${wanted}, which is already taken on this lane`
          );
        }
        taken.add(wanted);
        consoleOctets[c.ref] = wanted;
        continue;
      }
      while (taken.has(next)) next += 1;
      if (next > CONSOLE_OCTET_MAX) {
        throw new Error(
          `Too many console machines on one lane — the .${CONSOLE_OCTET_MIN}-.${CONSOLE_OCTET_MAX} band is full`
        );
      }
      taken.add(next);
      consoleOctets[c.ref] = next;
    }
  }
  // Handed to cloneChallengeVm so a designated machine gets a pinned MAC.
  // Keyed by NAME, because cloneChallengeVm looks itself up by spec name. Extras
  // are keyed by the hostname they clone as, so writeLaneReservations emits one
  // dhcp-host line per machine with a label distinct within the lane.
  ctx._consoleOctetForVm = {};
  const reservationOctets = {};
  for (const c of consolePlan.consoles) {
    if (c.kind === 'spec') {
      ctx._consoleOctetForVm[c.name] = consoleOctets[c.ref];
      reservationOctets[c.name] = consoleOctets[c.ref];
    } else if (c.kind === 'extra') {
      reservationOctets[c.name] = consoleOctets[c.ref];
    }
  }

  // Instructor-added machines, with the console octet they were just handed.
  // DNS only: they are already reserved by the console allocator above, so they
  // must not reach the pinning pass — but their catalog row may carry
  // `metadata.dns_aliases`, and without this they would get a dhcp-host line and
  // no host-record. See resolveSpecAddressing's header for why that silently
  // breaks a baked agent that resolves `elk.cybercore.lan`.
  const extraConsoles = consolePlan.consoles
    .filter((c) => c.kind === 'extra')
    .map((c) => ({
      hostname: c.name,
      template: c.extra && c.extra.template,
      octet: consoleOctets[c.ref],
    }));

  // Fixed addresses + stable DNS names for the rest of the environment's
  // machines. No-ops unless the caller asked for them (see resolveSpecAddressing).
  const { pinnedHosts, dnsRecords } = resolveSpecAddressing({
    specVms, goadMacs, consoleOctetForVm: ctx._consoleOctetForVm, extraConsoles,
    // `taken` already carries every console octet — the loop above adds each as
    // it assigns it — plus Kali's and every GOAD static.
    //
    // The two infrastructure octets are added HERE rather than being in `taken`,
    // because the console allocator above predates them and changing what it
    // sees would alter existing lanes. Both are addresses writeLaneReservations
    // can actually emit or the gateway already owns:
    //   .1  the lane gateway itself — never leasable to a guest
    //   .5  the GOAD controller, whose dhcp-host line is written from
    //       liveGoadController and so is NOT in goadMacs. On a v1/v2 lane
    //       intSubnetBase === extSubnetBase, so a spec VM pinned to .5 would
    //       emit a second dhcp-host for the same address and dnsmasq would
    //       refuse to start — taking DHCP down for the whole lane.
    reserved: [
      ...taken,
      goadDeploy.INFRA_IP_OCTETS.gateway,
      goadDeploy.INFRA_IP_OCTETS.controller,
    ],
    subnetScheme, laneSubnetBase, goadSubnetBase, pinAllVms: !!ctx.pinAllVms,
    requiredIpOctets: resolveGoadExternalPins(spec),
  });
  // Read by cloneChallengeVm for the pinned MAC. Kept SEPARATE from
  // _consoleOctetForVm so the dual-homed console guard there keeps its exact
  // meaning — a pinned machine that happens to be dual-homed is skipped above,
  // not rejected.
  ctx._pinnedOctetForVm = {};
  for (const h of pinnedHosts) ctx._pinnedOctetForVm[h.name] = h.octet;

  if (progress) {
    progress.lanes[laneId] = {
      user: user.email, student: user.email, vxlan: vxlanId, node: targetNode,
      status: 'cloning', _startedAt: Date.now(),
    };
  }
  const setStatus = (s) => { if (progress?.lanes[laneId]) progress.lanes[laneId].status = s; };

  // 1. Clone the challenge VMs and Kali concurrently.
  const attackBoxVmId = attackBoxes ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null;

  const clonePromises = specVms.map(vmSpec => cloneChallengeVm({
    vmSpec, vxlanId, targetNode, laneId, user, ctx, net, goadMacs,
    vnetExtName, vnetIntName,
  }));

  const kaliPromise = attackBoxVmId
    ? cloneAttackBox({
        attackBoxVmId, vxlanId, targetNode, laneId, user,
        creds: attackBoxCreds, ctx, vnet, laneSubnetBase,
      })
    : Promise.resolve();

  // Added machines clone in the same concurrent phase as the environment's own,
  // through the same semaphore, so a lane with extras is not serialised behind
  // one that has none.
  const extraPromises = extraSpecs.map((extra, i) => cloneExtraWorkstation({
    extra,
    vmid: extraVmids[i],
    octet: consoleOctets['ws:' + i],
    vxlanId, targetNode, laneId, user, ctx, net, vnet, laneSubnetBase,
  }));

  const [deployedVMs, deployedExtras] = await Promise.all([
    Promise.all(clonePromises), Promise.all(extraPromises), kaliPromise,
  ]);

  // Appended to the SAME list the environment's own machines are in. This is
  // what makes teardown find them: teardownLanes reads config.workstations only
  // when config.vms is empty, and on a challenge lane it never is.
  deployedVMs.push(...deployedExtras.map(({ _creds, ...rest }) => rest));

  // Keep cleanup inventory durable before booting or provisioning any guest.
  await cybercoreQuery(
    `UPDATE cybercore_lane SET config = COALESCE(config, '{}'::jsonb) || $2::jsonb,
       updated_at = NOW() WHERE lane_id = $1`,
    [laneId, JSON.stringify({ vms: deployedVMs, node: targetNode,
      gateway_vm_id: gatewayVmId, attack_box_vm_id: attackBoxVmId })]
  );

  // 2. Boot the gateway first so dnsmasq is answering before anything DHCPs.
  setStatus('starting');
  await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/status/start`);
  await new Promise(r => setTimeout(r, 5000));

  // 2b. Write the lane's DHCP reservations BEFORE any guest boots, so the very
  //     first DHCPREQUEST already has a reservation waiting.
  //
  //     ONE renderer, called TWICE — here, and again after the GOAD block (3b),
  //     because the GOAD controller's prep.sh used to overwrite this same file.
  //     A closure rather than two argument lists: the second write has to
  //     reserve exactly what the first did — Kali's octet above all, since the
  //     gateway's baked wan0:3389 DNAT is aimed at it — and a second argument
  //     list at the second call site is precisely how the two would drift.
  const writeReservations = async () => {
    await writeLaneReservations({
      gatewayVmId, node: targetNode, vxlanId, goadMacs,
      attackBoxOctet: attackBoxVmId ? goadDeploy.INFRA_IP_OCTETS.Kali : null,
      consoleOctets: reservationOctets, pinnedHosts, dnsRecords, spec, subnetScheme,
      extSubnetBase: laneSubnetBase, intSubnetBase: goadSubnetBase,
      liveGoadController: !!(spec.goad?.enabled && !spec.goad?.prebaked),
      laneId, logTag,
    });
  };
  await writeReservations();

  // Every machine on the lane, added ones included — they are in deployedVMs now.
  for (const dvm of deployedVMs) {
    await proxmoxAPI('POST',
      `/api2/json/nodes/${dvm.node}/${dvm.type === 'lxc' ? 'lxc' : 'qemu'}/${dvm.vm_id}/status/start`);
  }

  // 3. GOAD provisioning, if the challenge declares it.
  let goadMeta = null;
  let goadError = null;
  if (spec.goad?.enabled) {
    setStatus('provisioning_goad');
    try {
      if (spec.goad?.prebaked) {
        // Golden-image lane: clones are already GOAD-provisioned, so just write
        // reservations + bounce onto the baked IPs. No controller, no ansible,
        // no ~90-min bake.
        const result = await goadDeploy.deployPrebakedGoadLane({
          lane: { lane_id: laneId },
          spec, vxlanId, gatewayVmId, bestNode: targetNode,
          laneSubnetBase: goadSubnetBase, extSubnetBase: laneSubnetBase,
          deployedVMs, proxmoxAPI,
        });
        goadMeta = result?.goadMeta || { status: 'provisioned', prebaked: true };
      } else {
        const result = await goadDeploy.deployGoadLane({
          lane: { lane_id: laneId },
          spec, module: moduleKey, vnet: isV3 ? vnetInt : vnet, vxlanId, gatewayVmId,
          bestNode: targetNode,
          // Where the GOAD CONTROLLER template lives — deployGoadLane clones
          // CONTROLLER_TEMPLATE_VMID from it, not the challenge VMs.
          templateNode: ctx.templateNodeByVmid[goadDeploy.CONTROLLER_TEMPLATE_VMID] || getDefaultTemplateNode(),
          laneSubnetBase: goadSubnetBase,
          extSubnetBase: laneSubnetBase, deployedVMs,
          proxmoxAPI, waitForTask, query: cybercoreQuery,
        });
        goadMeta = result.goadMeta;
      }
    } catch (goadErr) {
      // Finish recording the lane before reporting failure. 'suspended' retains
      // its network claims and permits teardown without advertising readiness.
      goadError = goadErr.message;
      goadMeta = { ...goadErr.goadMeta, status: 'failed', error: goadError };
      console.error(`${logTag} GOAD provisioning failed for ${user.email}: ${goadErr.message}`);
    }
    job.goadMeta = goadMeta;
    await audit.log({
      action: 'lane.goad_provisioned', status: goadError ? 'failure' : 'success',
      target: { type: 'lane', id: laneId }, targetUser: { id: user.id },
      metadata: {
        provisioning_status: goadMeta?.status,
        forest_rename: goadMeta?.forest_rename || null,
        controller_vmid: goadMeta?.controller_vmid || null,
      },
    });
    if (progress?.lanes[laneId]) {
      progress.lanes[laneId].goad = goadMeta;
      if (goadError) progress.lanes[laneId].error = goadError;
    }

    // 3b. Put the lane's reservations back. The GOAD controller writes DHCP
    //     reservations too — prep.sh, over SSH into the gateway — and every
    //     controller baked before prep.sh was pointed at its own
    //     goad-lane-reservations.conf wrote them by TRUNCATING this lane's file.
    //     What survived was prep.sh's HOST_MAP and nothing else: the GOAD
    //     roster, the controller, and Kali only when spec.goad.include_kali is
    //     not false — which is a DIFFERENT switch from the attack box this
    //     deploy clones. Everything the controller has never heard of was
    //     deleted: an extension host such as elk (it reaches us as a pinnedHost,
    //     not in goadMacs), the console reservations, and every host-record and
    //     company DNS line, which live in this same file. Found on a live lane
    //     with Kali on a pool lease at .53 while the gateway's baked wan0:3389
    //     DNAT still pointed at .50 — a student console connected to nothing —
    //     and elk holding .24 only until its next renewal, with winlogbeat on
    //     every Windows host aimed at a hardcoded <subnet>.24:9200.
    //
    //     Kali is not started until step 4 and deployGoadLane bounces the
    //     Windows VMs after prep.sh, so re-rendering here puts every line back
    //     before any guest that needs one asks for an address. Against a
    //     controller baked WITH the split it rewrites the file it already holds,
    //     byte for byte — which is why it is unconditional rather than sniffing
    //     the controller's age. It runs after the catch as well as after a
    //     success, because prep.sh runs early and a GOAD failure LATER in the
    //     deploy still leaves the truncated file behind. Live path only: a
    //     pre-baked lane has no controller and no prep.sh, so nothing to undo.
    if (!spec.goad?.prebaked) {
      try {
        await writeReservations();
      } catch (reservationError) {
        goadError = goadError || `DHCP restoration failed: ${reservationError.message}`;
        goadMeta = { ...goadMeta, status: 'failed', error: goadError,
          reservation_error: reservationError.message };
        job.goadMeta = goadMeta;
        if (progress?.lanes[laneId]) {
          progress.lanes[laneId].goad = goadMeta;
          progress.lanes[laneId].error = goadError;
        }
      }
    }
  }

  // 4. Consoles: boot what needs booting, publish each on the gateway's WAN IP,
  //    and create one Guacamole connection per console.
  //
  //    Guacamole ALWAYS targets the gateway's wan0 transit address, never a
  //    lane-local one: guacd runs on the orchestrator's Docker bridge with no
  //    route into the lane subnet.
  const gatewayTransitIp = consolePlan.consoles.length
    ? await resolveGatewayTransitIp(targetNode, gatewayVmId)
    : null;

  if (attackBoxVmId) {
    setStatus('configuring_kali');
    await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/status/start`);
    console.log(`${logTag} Kali attack box ${attackBoxVmId} started for ${user.email}`);
    await new Promise(r => setTimeout(r, 30000)); // guest agent needs a head start
    const found = await discoverKaliIp(targetNode, attackBoxVmId, logTag);
    if (!found) {
      // Kali's DHCP reservation targets .50, so that is the correct fallback when
      // the guest agent is slow — and it matches the gateway's baked wan0:3389.
      console.warn(`${logTag} Could not get Kali IP via guest agent — assuming the reserved .50`);
    }
  }

  // Publish every console port in ONE pass. installConsoleDnat strips its own
  // LANE-CONSOLE tag before re-adding, so a per-machine call would delete the
  // previous machine's rule — the same regression the workstation path already
  // carries a test for.
  const consoleTargets = consolePlan.consoles.map((c) => {
    const octet = consoleOctets[c.ref];
    let proto;
    let template = {};
    if (c.kind === 'kali') {
      proto = { protocol: 'rdp', guestPort: 3389, wanPort: 3389 };
    } else if (c.kind === 'extra') {
      // An added machine is a catalog workstation, so its console comes from the
      // same metadata the workstation path reads — an SSH-only image published
      // on 3389 is a console that connects to nothing.
      template = c.extra.template;
      proto = laneDeployer.resolveConsole(template);
    } else {
      proto = laneDeployer.resolveConsole({
        metadata: {
          console_protocol: (c.vm && c.vm.console_protocol) || 'rdp',
          console_port: c.vm && c.vm.console_port,
        },
      });
    }
    return { ...c, octet, template, ip: `${laneSubnetBase}.${octet}`, console: proto };
  });

  // Distinct gateway ports. The primary keeps its protocol's base port, which is
  // the one the v2 gateway already bakes an RDP rule for — so even a failed DNAT
  // install leaves the machine students actually open reachable.
  {
    const used = new Set();
    const ordered = [...consoleTargets].sort((a, b) => (b.primary === true) - (a.primary === true));
    for (const t of ordered) {
      let port = t.console.wanPort || t.console.guestPort;
      while (used.has(port)) port += 1;
      used.add(port);
      t.console = { ...t.console, wanPort: port };
    }
  }

  let consoleDnatOk = consoleTargets.length === 0;
  if (consoleTargets.length) {
    try {
      await laneDeployer.installConsoleDnat({
        node: targetNode, gatewayVmid: gatewayVmId, targets: consoleTargets,
        // A v3 gateway has ext0/int0 and no lan0 at all, so the FORWARD ACCEPT
        // has to name the interface this lane actually has.
        lanIface: isV3 ? 'ext0' : 'lan0',
        logTag,
      });
      consoleDnatOk = true;
    } catch (dnatErr) {
      // Recorded, not just logged. The gateway's baked wan0:3389 -> <ext>.50 rule
      // still covers ONE case — Kali, on the base RDP port — and covers nothing
      // else: a spec machine at .60 on 3389 would have the student land on Kali
      // instead, and a second console has no baked rule at all. console_via is
      // what the CLE VM list renders, so this reaches the instructor rather than
      // presenting as "the console just doesn't work".
      console.error(`${logTag} Console DNAT install failed for ${user.email}: ${dnatErr.message}`);
    }
  }

  for (const t of consoleTargets) {
    const creds = t.kind === 'kali'
      ? attackBoxCreds
      : (t.kind === 'extra'
          // Resolved at clone time: cloneExtraWorkstation downgrades to
          // {source:'baked'} when the image has no cloud-init drive, so this is
          // the credential that is actually in force on the guest.
          ? ((deployedExtras[t.index] || {})._creds || { username: null, password: null })
          : { username: null, password: null });
    const connName = t.kind === 'kali'
      // Unchanged for Kali, so an existing lane's connection is FOUND and
      // updated rather than duplicated — Guacamole's schema carries
      // UNIQUE(connection_name, parent_id) and a blind POST would fail, leaving
      // the old connection live with the old password.
      ? `${laneConfig.group_name || laneConfig.course_name || challengeKey} - ${attackBoxCreds.username} - Kali`
      : `${laneConfig.course_name || challengeKey} - ${user.email.split('@')[0]} - ${t.name}`;
    try {
      t.guacConnId = await createLaneConsole({
        connName,
        hostname: gatewayTransitIp || `${laneSubnetBase}.${t.octet}`,
        port: t.console.wanPort,
        protocol: t.console.protocol,
        creds,
        template: t.template || {},
        user, guacParent, instructorEmails, logTag,
      });
    } catch (guacErr) {
      console.warn(`${logTag} Could not create Guac connection for ${user.email} (${t.name}): ${guacErr.message}`);
    }
  }

  const primaryConsole = consoleTargets.find((t) => t.primary) || null;
  const primaryCreds = !primaryConsole
    ? { username: null, password: null, source: 'baked' }
    : primaryConsole.kind === 'kali'
      ? { username: attackBoxCreds.username, password: attackBoxCreds.password, source: 'cloudinit' }
      : primaryConsole.kind === 'extra'
        ? ((deployedExtras[primaryConsole.index] || {})._creds
            || { username: null, password: null, source: 'baked' })
        : { username: null, password: null, source: 'baked' };
  const kaliGuacConnId = (consoleTargets.find((t) => t.kind === 'kali') || {}).guacConnId || null;

  // 5. Vuln scripts.
  if (!goadError && vulnScripts && vulnScripts.length > 0) {
    setStatus('running_scripts');
    console.log(`${logTag} Running ${vulnScripts.length} vuln script(s) for ${user.email}`);
    try {
      await runVulnScripts({ laneId, deployedVMs, vulnScripts, logTag });
      console.log(`${logTag} Vuln scripts completed for ${user.email}`);
    } catch (scriptErr) {
      console.error(`${logTag} Vuln scripts failed for ${user.email}: ${scriptErr.message}`);
    }
  }

  // 5b. Caller-supplied provisioning, for work this module has no business
  //     knowing about — CiAB's generated vuln-app install and its per-lane fact
  //     file are the first two. The alternative to a hook here is a fifth copy
  //     of the deploy sequence, which is the exact failure this file's header
  //     documents.
  //
  //     Placed after vuln scripts and BEFORE flags, so the invariant in step 6
  //     still holds: flags are planted LAST and nothing can clobber the files. A
  //     hook that ran after them would be free to recreate a user profile on top
  //     of a planted user.txt.
  //
  //     Best-effort, like vuln scripts and GOAD above: the lane's machines exist
  //     and are reachable even when the hook fails, and failing the deploy here
  //     would destroy work already done. The error is RECORDED on the lane
  //     config rather than only logged, so it reaches the instructor instead of
  //     presenting as "the exercise content just isn't there".
  let postDeployError = null;
  if (!goadError && typeof ctx.postDeploy === 'function') {
    setStatus('post_deploy');
    try {
      await ctx.postDeploy({
        laneId, user, vxlanId, spec, subnetScheme,
        node: targetNode, gatewayVmId, gatewayTransitIp,
        deployedVMs, net, laneSubnetBase, goadSubnetBase,
        // Where each pinned machine actually lives, so a hook can seed a guest
        // with the same addresses the lane's DNS and DHCP publish.
        pinnedHosts, dnsRecords,
        logTag,
      });
    } catch (hookErr) {
      postDeployError = hookErr.message;
      console.error(`${logTag} postDeploy hook failed for ${user.email}: ${hookErr.message}`);
    }
  }

  // 6. Plant HTB-style user/root capture flags. Runs LAST, after vuln scripts and
  //    after GOAD provisioning, so a script that recreates a user profile or a
  //    GOAD heal that reboots a DC can't clobber the files. Because deployedVMs
  //    includes the GOAD hosts, this covers DC01/DC02/SRV02 with no change to
  //    goad-deploy.js.
  //
  //    Best-effort: flag failures are recorded per-flag as plant_status='failed'
  //    and surfaced on the instructor dashboard. They must never fail a deploy.
  try {
    setStatus('planting_flags');
    await plantFlagsForLane({
      laneId,
      userId: user.id,
      // Only the environment's OWN machines. An instructor's added workstation is
      // where the student works FROM; planting user.txt/root.txt on it would hand
      // them a flag for owning their own box.
      vms: deployedVMs.filter(v => v.source !== 'instructor'),
      specVms,
      api: proxmoxAPI,
      logTag: `${logTag}[Flags]`,
    });
  } catch (flagErr) {
    console.error(`${logTag} Flag planting failed for ${user.email}: ${flagErr.message}`);
  }

  // 7. Surface everything on the owner's dashboard.
  await registerWorkspaceVms({
    laneId, user, vxlanId, moduleKey, challengeKey, laneConfig, logTag,
    rows: [
      ...deployedVMs.map(v => ({
        name: v.name,
        proxmoxName: v.proxmox_name || null,
        vmid: v.vm_id,
        node: v.node,
        providerType: v.type === 'lxc' ? 'lxc' : 'qemu',
        // A machine with a console now HAS a connection — a designated spec
        // machine or one the instructor added — so the student's workspace card
        // opens it instead of showing a dead tile.
        guacConnId: (consoleTargets.find(t => t.kind !== 'kali' && t.name === v.name) || {}).guacConnId || null,
        templateName: v.name,
      })),
      ...(attackBoxVmId ? [{
        name: 'kali',
        // Mirrors cloneAttackBox's clone name — keep the two in step.
        proxmoxName: hostnameFor(`kali-${attackBoxCreds.username}`),
        vmid: attackBoxVmId,
        node: targetNode,
        providerType: 'qemu',
        guacConnId: kaliGuacConnId,
        templateName: 'Kali (Attack Box)',
      }] : []),
    ],
  });

  // 8. Persist the complete outcome before reporting readiness or failure.
  const activeConfig = {
    ...laneConfig,
    ...(goadMeta ? { goad: goadMeta } : {}),
    ...(goadError ? { error: goadError, provisioning_error: goadError } : {}),
    challenge_key:    challengeKey,
    module:           moduleKey,
    challenge_vm_id:  deployedVMs[0]?.vm_id,
    gateway_vm_id:    gatewayVmId,
    attack_box_vm_id: attackBoxVmId || null,
    node:             targetNode,
    vms:              deployedVMs,
    subnet_scheme:    subnetScheme,
    lane_subnet_base: laneSubnetBase,
    vnet:             vnetExtName,
    ...(isV3 ? { vnet_internal: vnetIntName, lane_subnet_internal: goadSubnetBase } : {}),
    ...(primaryConsole ? {
      // The same FLAT keys lane-deployer.js writes for a catalog workstation.
      // cle/routes/vms.js and labs.js read them directly, and the Console button
      // plus the My Workspaces card both resolve from them — drop one and both
      // go blank at once, with no error anywhere.
      //
      // Driven by the console PLAN now, not by `attackBoxVmId`, so they describe
      // whichever machine actually won. On a lane where Kali is still the console
      // — every environment that predates console_role — these are byte-identical
      // to what this block wrote before.
      // Whatever credential is actually in force on the machine the student
      // opens: Kali's generated pair, an added workstation's cloud-init pair, or
      // nothing at all for a spec machine that keeps its baked accounts.
      workstation_user:   primaryCreds.username,
      workstation_pass:   primaryCreds.password,
      credentials_source: primaryCreds.source,
      guac_connection_id: primaryConsole.guacConnId || null,
      guac_user:          user.email,
      console_protocol:   primaryConsole.console.protocol,
      console_port:       primaryConsole.console.wanPort,
      console_host:       gatewayTransitIp || null,
      console_via:        consoleDnatOk
        ? 'gateway'
        : (primaryConsole.kind === 'kali' && primaryConsole.console.wanPort === 3389
            ? 'gateway-baked-dnat'
            : 'unreachable'),
      // WHICH machine the console points at. attack_box_vm_id keeps meaning
      // Kali's vmid (labs.js reads it for the attack-box column), so it must not
      // be repurposed for this.
      console_vm_name:    primaryConsole.name,
    } : {}),
    // The lane's fixed addressing, so a REBUILD can replay it verbatim instead
    // of re-deriving it. Re-running the allocator would be wrong, not merely
    // wasteful: if the spec changed between deploy and rebuild, a machine would
    // silently move to a different address than the one the student's generated
    // paper names. Absent entirely on a lane that pinned nothing, which is every
    // lane that predates pinAllVms.
    ...(postDeployError ? { post_deploy_error: postDeployError } : {}),
    ...(pinnedHosts.length ? { pinned_hosts: pinnedHosts } : {}),
    ...(dnsRecords.length  ? { dns_records: dnsRecords }   : {}),
    // Every console on the lane, primary first. teardownLanes reads Guacamole
    // ids from here — without it each secondary console leaks one connection per
    // student on every teardown.
    ...(consoleTargets.length ? {
      consoles: consoleTargets.map((t) => ({
        ref: t.ref, name: t.name, kind: t.kind, primary: !!t.primary,
        ip: t.ip, protocol: t.console.protocol,
        wan_port: t.console.wanPort, guest_port: t.console.guestPort,
        guac_connection_id: t.guacConnId || null,
      })),
    } : {}),
  };
  await cybercoreQuery(
    `UPDATE cybercore_lane SET status = $3, config = COALESCE(config, '{}'::jsonb) || $2::jsonb,
       updated_at = NOW() WHERE lane_id = $1`,
    [laneId, JSON.stringify(activeConfig), goadError ? 'suspended' : 'active']
  );

  if (goadError) {
    setStatus('error');
    throw new Error(`GOAD provisioning failed; lane retained for inspection and cleanup: ${goadError}`);
  }
  setStatus('active');
  console.log(
    `${logTag} Lane ${laneId} active (vxlan ${vxlanId}, node ${targetNode}, ` +
    `${deployedVMs.length} challenge VM(s)${attackBoxVmId ? ' + Kali' : ''}) for ${user.email}`
  );

  return {
    lane_id: laneId,
    user_id: user.id,
    user_email: user.email,
    vxlan_id: vxlanId,
    node: targetNode,
    vms: deployedVMs,
    attack_box_vm_id: attackBoxVmId,
    guac_connection_id: kaliGuacConnId,
    ...(attackBoxVmId ? { attack_box_user: attackBoxCreds.username, attack_box_password: attackBoxCreds.password } : {}),
  };
}

// ── entry point ──────────────────────────────────────────────────────────────

/**
 * Deploy one challenge lane per user.
 *
 * @param {object}   a
 * @param {Array}    a.users             [{ id, email, password? }] — must already exist.
 *   `password` is optional; when absent a fresh per-lane Kali password is minted
 *   and returned on the corresponding `provisioned` entry.
 * @param {object}   a.challenge         { challenge_id, challenge_key, name, spec, subnet_scheme }
 * @param {string}   [a.moduleKey]       defaults to challenge.module_key or 'crucible'
 * @param {boolean}  [a.attackBoxes]     deploy a Kali attack box per lane
 * @param {boolean}  [a.pinAllVms]       give every non-console, non-GOAD, single-homed
 *   spec VM a fixed lane address via a MAC-keyed DHCP reservation, so the lane
 *   matches whatever paper describes it. Off by default — see resolveSpecAddressing.
 * @param {Function} [a.postDeploy]      async hook run per lane after vuln scripts
 *   and before flag planting. Receives { laneId, user, vxlanId, spec, subnetScheme,
 *   node, gatewayVmId, gatewayTransitIp, deployedVMs, net, laneSubnetBase,
 *   goadSubnetBase, pinnedHosts, dnsRecords, logTag }. Best-effort: a throw is
 *   recorded as config.post_deploy_error and does not fail the lane.
 * @param {Array}    [a.vulnScripts]     [{ vm_name, script_slug }]
 * @param {object}   [a.laneConfig]      merged into every lane's config JSONB
 * @param {string}   [a.namePrefix]      lane name = `${namePrefix}-${vxlanId}`; when
 *   omitted the lane's SDN zone is used, which is what the admin group deploy
 *   has always produced (e.g. `crucible-10003`).
 * @param {string}   [a.guacParent]      Guacamole connection-group identifier
 * @param {Array}    [a.instructorEmails] extra Guac READ grants
 * @param {string}   [a.description]     appended to every Proxmox description
 * @param {string}   [a.progressId]      key for readProgress()
 * @param {string}   [a.progressLabel]
 * @param {object}   [a.flagSeeds]       { [userId]: [rows from flagManager.snapshotLaneFlags] }.
 *   Replays a previous lane's flag values (and captures) onto the new lane before
 *   planting, so rebuilding a student's lane doesn't reset their progress. See
 *   flag-manager.seedLaneFlags for why it has to happen at insert time.
 * @returns {Promise<{provisioned: Array, failed: Array, progressId: string}>}
 */
async function deployChallengeLanes(args) {
  // Everything after initProgress runs inside deployChallengeLanesInner. A throw
  // there would otherwise leave the progress entry pinned in
  // global._batchDeployProgress forever (only finishProgress schedules its
  // eviction), and any lane row already inserted stuck at 'deploying' — which
  // also holds its VXLAN out of the pool permanently, since allocateVxlanIds
  // only skips 'error' and 'deleted'.
  //
  // insertedLaneIds is filled by the inner function as it creates rows, so the
  // recovery sweep below can name exactly the lanes THIS call made.
  const insertedLaneIds = [];
  try {
    return await deployChallengeLanesInner({ ...args, _insertedLaneIds: insertedLaneIds });
  } catch (err) {
    if (args.progressId) {
      const p = laneDeployer.readProgress(args.progressId);
      if (p) {
        const live = (global._batchDeployProgress || {})[args.progressId];
        if (live) {
          live.phase_detail = `Deployment failed: ${err.message}`;
          live.error = err.message;
        }
        laneDeployer.finishProgress(args.progressId);
      }
    }
    // A failed job may already own live guests. Suspend it so the operator can
    // inspect/tear it down while its VXLAN and WAN address remain claimed.
    //
    // Scoped to the ids this call inserted. It used to sweep by challenge_key +
    // "created in the last hour", which is not scoped to the call, the course, or
    // even the caller: one failed single-student redeploy would mark every
    // in-flight lane of the same challenge across every course as 'error',
    // releasing their VXLANs into the allocator while their VMs were still being
    // built. Concurrent deploys of one challenge are routine now that a single
    // student can be redeployed on their own, so that blast radius had to go.
    if (insertedLaneIds.length > 0) {
      await cybercoreQuery(
        `UPDATE cybercore_lane
            SET status = 'suspended', config = config || $2::jsonb, updated_at = NOW()
          WHERE lane_id = ANY($1::uuid[])
            AND status = 'deploying'`,
        [insertedLaneIds, JSON.stringify({ error: err.message })]
      ).catch(() => {});
    }
    throw err;
  }
}

async function deployChallengeLanesInner({
  users,
  challenge,
  moduleKey,
  attackBoxes = false,
  // Which machine the student's console opens, and any machines the instructor
  // added at deploy time. Both default to the pre-existing behaviour: no
  // override (so Kali wins when it is present) and no extras.
  consoleVm = null,
  extraWorkstations = [],
  // Additive capabilities, both off by default so every existing caller deploys
  // byte-identically. See resolveSpecAddressing and the step-5b hook.
  pinAllVms = false,
  postDeploy = null,
  vulnScripts = null,
  laneConfig = {},
  namePrefix = null,
  guacParent = null,
  instructorEmails = [],
  description = '',
  progressId = null,
  progressLabel = '',
  flagSeeds = null,
  _insertedLaneIds = [],
}) {
  if (!Array.isArray(users) || users.length === 0) {
    return { provisioned: [], failed: [], progressId };
  }
  if (!challenge) throw new Error('deployChallengeLanes: challenge is required');

  // SIEM agents are attached to the IN-MEMORY spec, never written back to the
  // challenge row. A stored spec's `extensions` is edited after the fact, and a
  // slug persisted from a deploy that ticked elk would keep installing
  // winlogbeat long after the elk box stopped being part of the environment.
  // Returns the SAME object when no SIEM extension is selected, so every
  // non-blue-team deploy is byte-identical to what it was before.
  // Prepare the identity plan before allocating a lane or cloning its gateway.
  // The authored challenge keeps its catalog version and explicit opt-in.
  const spec = goadDeploy.prepareGoadDeploymentSpec(attachGoadAgentScripts(parseSpec(challenge.spec)));
  const subnetScheme = challenge.subnet_scheme || 'v1';
  const resolvedModule = moduleKey || challenge.module_key || 'crucible';
  const challengeKey = challenge.challenge_key;
  const logTag = `${LOG}[${challengeKey}]`;

  // Machines the instructor added at deploy time. Resolved to catalog rows ONCE
  // for the whole batch — every lane clones the same images, so a per-lane
  // lookup would be one query per student for an identical answer.
  const extraSpecs = await loadExtraWorkstations(extraWorkstations, logTag);

  const specVms = resolveSpecVms(spec, challengeKey);
  if (specVms.length === 0) {
    throw new Error(`Challenge '${challengeKey}' declares no VMs (spec.vms[] is empty and there is no template_vmid)`);
  }
  for (const vm of specVms) {
    if (!vm.template_vmid && !spec.template_vmid) {
      throw new Error(`Challenge '${challengeKey}' VM '${vm.name || '?'}' has no template_vmid`);
    }
  }
  const collision = findVmOffsetCollision(specVms);
  if (collision) throw new Error(`Challenge '${challengeKey}' cannot deploy: ${collision}`);
  // External extension addresses are part of the installer contract even when
  // the caller did not request whole-lane pinning. Validate before allocation.
  validateGoadLaneAddressing(spec, subnetScheme);

  // Not fatal — a challenge author may genuinely want an extra box on the
  // external segment — but it is almost always a naming mistake, and it is
  // invisible at runtime otherwise.
  const goadMismatch = findGoadHostMismatch(spec, specVms);
  if (goadMismatch) console.warn(`${logTag} GOAD host mismatch: ${goadMismatch}`);

  const vxlanBlock = spec.vxlan_block;
  if (!vxlanBlock?.start || !vxlanBlock?.end) {
    throw new Error(
      `Challenge '${challengeKey}' has no reserved VXLAN block — recreate it through ` +
      `Admin → Create Lab so its SDN zone and VNets exist.`
    );
  }

  const progress = laneDeployer.initProgress(progressId, progressLabel || challenge.name || challengeKey, users.length);
  const failed = [];

  // 1. Allocate VXLAN ids from the challenge's own reserved block, then map each
  //    to its pre-created VNet(s).
  const vxlans = await laneDeployer.allocateVxlanIds(vxlanBlock, users.length);
  if (vxlans.length < users.length) {
    // Give back whatever WAS free before bailing. Without this a deploy that
    // asks for more lanes than the block holds parks the remainder for the
    // reservation TTL, so a retry with a smaller selection sees zero free.
    laneDeployer.releaseVxlanReservations(vxlans);
    laneDeployer.finishProgress(progressId);
    throw new Error(
      `Not enough VXLAN capacity for '${challengeKey}': ${vxlans.length} free id(s) for ` +
      `${users.length} user(s) (range ${vxlanBlock.start}-${vxlanBlock.end}).`
    );
  }
  // The two calls between the VXLAN allocation and the lane INSERTs that can
  // throw: a missing VNet and an exhausted WAN pool, both of which happen in
  // practice. Neither has created anything yet, so the ids are still free — but
  // without this they would sit reserved until the TTL expires, and the operator
  // retrying immediately would be told the block is full.
  let vnetsByVxlan;
  let missing;
  let wanIps;
  try {
    ({ resolved: vnetsByVxlan, missing } = await resolveVnets(vxlans, subnetScheme));

    // WAN transit addresses for the batch, before any Proxmox work. Same pool the
    // workstation lanes draw from — one shared VLAN, one allocator — so an
    // exhausted pool fails here rather than producing lanes that silently share a
    // gateway address and a Guacamole console host.
    wanIps = (subnetScheme === 'v2' || subnetScheme === 'v3')
      ? await laneWan.allocateLaneWanIps(users.length, { logTag })
      : null;
  } catch (err) {
    laneDeployer.releaseVxlanReservations(vxlans);
    laneDeployer.finishProgress(progressId);
    throw err;
  }
  const unusedWan = [];

  // 2. Spread the lanes across the cluster.
  let nodeAssignments;
  try {
    nodeAssignments = await distributeAcrossNodes(proxmoxAPI, users.length);
  } catch (e) {
    console.warn(`${logTag} Batch node distribution failed, falling back to a single node: ${e.message}`);
    const best = await selectBestNode();
    nodeAssignments = new Array(users.length).fill(best.node);
  }

  const gatewayVmid  = resolveGatewayVmid(resolvedModule, subnetScheme, spec);
  const gwSourceNode = await findTemplateNode(gatewayVmid, spec.template_node || getDefaultTemplateNode());
  const templateNodeByVmid = await resolveTemplateNodes(
    // Added machines clone from their own catalog images, which may live on a
    // different node than the environment's — resolving only the spec's would
    // send every added clone to the wrong source.
    [...specVms, ...extraSpecs.map(e => ({ template_vmid: e.template.template_vmid }))],
    spec, attackBoxes
  );
  console.log(
    `${logTag} Deploying ${users.length} lane(s): scheme=${subnetScheme}, gateway template=${gatewayVmid}@${gwSourceNode}, ` +
    `${specVms.length} challenge VM(s)${attackBoxes ? ` + Kali ${KALI_TEMPLATE_VMID}` : ''}; ` +
    `template nodes: ${Object.entries(templateNodeByVmid).map(([v, n]) => `${v}@${n}`).join(', ')}`
  );

  // 3. Create the lane rows up front so the caller can report them immediately.
  const jobs = [];
  const created = [];
  for (let i = 0; i < users.length; i++) {
    const user = users[i];
    const vxlanId = vxlans[i];
    const nets = vnetsByVxlan[vxlanId];
    if (!nets) {
      const reason = missing.find(m => m.vxlanId === vxlanId)?.reason || `No VNet for VXLAN ${vxlanId}`;
      failed.push({ user_id: user.id, user_email: user.email, reason });
      if (wanIps) unusedWan.push(wanIps[i].address);
      continue;
    }
    const wanIp = wanIps ? wanIps[i].address : null;

    // Falling back to the VNet's SDN zone keeps the admin group deploy's
    // historical lane names (`<zone>-<vxlan>`) byte-identical.
    const laneName = `${namePrefix || nets.vnet.zone || 'lane'}-${vxlanId}`;
    const expectedVms = specVms.map(vs => ({
      vm_id: (vs.vm_offset || DEFAULT_VM_OFFSET) + vxlanId,
      name: vs.name || challengeKey,
      type: vs.type || 'qemu',
    }));

    try {
      const ins = await cybercoreQuery(
        `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, gateway_wan_ip, created_at, updated_at)
         VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, $6::inet, NOW(), NOW())
         RETURNING lane_id`,
        [user.id, vxlanId, laneName, JSON.stringify({
          ...laneConfig,
          challenge_key: challengeKey,
          challenge_id:  challenge.challenge_id || null,
          module:        resolvedModule,
          subnet_scheme: subnetScheme,
          gateway_vm_id: GATEWAY_VMID_OFFSET + vxlanId,
          attack_box_vm_id: attackBoxes ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null,
          node:          nodeAssignments[i],
          user_email:    user.email,
          // This path never used to record the address at all, which is why the
          // 033 backfill has to re-derive it for most existing lanes.
          gateway_wan_ip: wanIp,
          vms:           expectedVms,
        }), resolvedModule, wanIp]
      );
      const laneId = ins.rows[0].lane_id;
      _insertedLaneIds.push(laneId);
      if (wanIp) await laneWan.recordLaneWanLease({ address: wanIp, laneId, vxlanId });

      // Carry a previous lane's flag values and captures onto this one, when the
      // caller is rebuilding a lane rather than creating a fresh one. MUST happen
      // here — after the row exists, long before step 6 plants — because
      // ensureLaneFlags only preserves a value that is already in the table.
      // Best-effort: a student re-earning a flag is a far better outcome than a
      // redeploy that dies and leaves them with no machines at all.
      const seeds = flagSeeds ? (flagSeeds[user.id] || flagSeeds[String(user.id)]) : null;
      if (seeds && seeds.length > 0) {
        const { seeded, skipped } = await seedLaneFlags({ laneId, userId: user.id, seeds })
          .catch((e) => {
            console.warn(`${logTag} Flag carry-over failed for ${user.email}: ${e.message}`);
            return { seeded: 0, skipped: seeds.length };
          });
        console.log(
          `${logTag} Carried ${seeded}/${seeds.length} flag(s) onto lane ${laneId} for ${user.email}` +
          (skipped > 0 ? ` (${skipped} will be re-minted)` : '')
        );
      }

      created.push({ lane_id: laneId, user_id: user.id, user_email: user.email, vxlan_id: vxlanId });
      jobs.push({
        laneId, user, vxlanId, wanIp,
        vnet: nets.vnet, vnetInt: nets.vnetInt,
        laneName, targetNode: nodeAssignments[i],
        attackBoxCreds: resolveAttackBoxCredentials(user),
      });
    } catch (err) {
      console.error(`${logTag} Failed to create lane record for ${user.email}: ${err.message}`);
      failed.push({ user_id: user.id, user_email: user.email, reason: err.message });
      if (wanIp) unusedWan.push(wanIp);
    }
  }
  if (unusedWan.length) await laneWan.releaseLaneWanIps(unusedWan);

  // Hand every id in this batch back to allocateVxlanIds' in-process reservation
  // set. The rows that inserted are now visible to its committed-rows query, and
  // the ones that failed were never taken — so holding either would only shrink
  // the pool. Unconditional and outside the loop so a throw above cannot park a
  // whole block for the reservation TTL.
  laneDeployer.releaseVxlanReservations(vxlans);

  // VMIDs for the added machines: one scan for the whole batch, before any
  // clone. They CANNOT be derived from vxlan_id the way spec machines are —
  // vm_offset is the environment author's namespace and findVmOffsetCollision
  // guards it, so an id invented per deploy would collide with it. These come
  // from lane-deployer's scanned 300000-399999 band instead, and are recorded on
  // the lane because a scanned id cannot be re-derived at teardown.
  if (extraSpecs.length && jobs.length) {
    const ids = await laneDeployer.reserveWorkstationVmids(extraSpecs.length * jobs.length);
    let cursor = 0;
    for (const job of jobs) job.extraVmids = ids.slice(cursor, cursor += extraSpecs.length);
  }

  if (jobs.length === 0) {
    if (progress) { progress.failed = failed.length; progress.completed = failed.length; }
    laneDeployer.finishProgress(progressId);
    return { provisioned: [], failed, progressId, lanes: created };
  }

  const concurrency = getSchedulingConfig().max_concurrent_lanes;
  const cloneSem = createCloneSemaphore();

  // runVulnScripts reads THIS list and never looks at spec.vms[].post_clone_scripts,
  // so the spec attach above is what downstream readers of ctx.spec see and this
  // is what actually installs anything. De-duplicated on (vm_name, script_slug):
  // CiAB's vulnScriptsFromSpec may already have produced the same entries from an
  // attached spec, and one host must not install the same agent twice. Null stays
  // null when there is nothing to add — deployLaneVms branches on length, and an
  // empty array would start writing a deployment_vuln_selections row for every
  // scriptless lane.
  const laneVulnScripts = withGoadAgentVulnScripts(vulnScripts, spec);

  const ctx = {
    spec, subnetScheme, moduleKey: resolvedModule, challengeKey,
    attackBoxes, consoleVm, extraWorkstations, extraSpecs,
    pinAllVms, postDeploy,
    vulnScripts: laneVulnScripts, laneConfig, guacParent, instructorEmails,
    description, progress, logTag, cloneSem, templateNodeByVmid,
  };

  // 4. Phase 1: gateway templates → per-node clones → temp cleanup.
  laneDeployer.setPhase(progress, 'gateway_replication', 'Replicating gateway templates');
  const uniqueNodes = [...new Set(jobs.map(j => j.targetNode))];
  const gwTemplateByNode = await replicateGatewayTemplate(uniqueNodes, gwSourceNode, gatewayVmid, logTag);

  laneDeployer.setPhase(progress, 'gateway_cloning', `Cloning ${jobs.length} gateway(s)`);
  const gatewayResults = {};
  const jobsByNode = {};
  for (const job of jobs) (jobsByNode[job.targetNode] ||= []).push(job);

  await Promise.all(Object.entries(jobsByNode).map(async ([node, nodeJobs]) => {
    const localTemplateId = gwTemplateByNode[node];
    // When replication fell back to the origin template, clone across nodes from
    // where it actually lives; otherwise the node-local copy is the source.
    const sourceNode = localTemplateId === gatewayVmid ? gwSourceNode : node;
    for (const job of nodeJobs) {
      try {
        await cloneGateway(job, sourceNode, localTemplateId, ctx);
        gatewayResults[job.laneId] = { success: true };
        console.log(`${logTag} Gateway ${GATEWAY_VMID_OFFSET + job.vxlanId} cloned on ${node}`);
      } catch (err) {
        console.error(`${logTag} Gateway clone failed for ${job.user.email}: ${err.message}`);
        gatewayResults[job.laneId] = { success: false, error: err.message };
      }
    }
  }));

  await cleanupTempGatewayTemplates(gwTemplateByNode, gatewayVmid, logTag);

  const gwOk = Object.values(gatewayResults).filter(r => r.success).length;
  console.log(`${logTag} Gateways: ${gwOk}/${jobs.length} cloned`);

  // 5. Phase 2: everything else, N lanes at a time.
  laneDeployer.setPhase(progress, 'deploying',
    `Deploying lanes (${concurrency} at a time, max ${cloneSem.max} concurrent clones)`);

  const provisioned = [];
  const { errors } = await runBatch(jobs, async (job) => {
    if (!gatewayResults[job.laneId]?.success) {
      throw new Error(`Skipped: gateway clone failed — ${gatewayResults[job.laneId]?.error}`);
    }
    const result = await deployLaneVms(job, ctx);
    provisioned.push(result);
    return result;
  }, {
    concurrency,
    onProgress: (completed, total, job, result) => {
      if (!progress) return;
      progress.completed = completed;
      if (result.success) progress.succeeded++; else progress.failed++;
      const laneProgress = progress.lanes[job.laneId];
      if (laneProgress?._startedAt) progress._laneTimes.push(Date.now() - laneProgress._startedAt);
      laneDeployer.recordLaneDone(progress, concurrency);
      progress.phase_detail = `Deploying lanes: ${completed}/${total} complete`;
      if (!result.success) {
        console.error(`${logTag} Lane ${job.laneId} (${job.user?.email || '?'}) FAILED: ${result.error}`);
      }
    },
  });

  // 6. Mark failures on the lane rows so the UI can explain them.
  for (const err of errors) {
    const job = jobs[err.index];
    if (!job) continue;
    const message = err.error?.message || String(err.error);
    failed.push({ user_id: job.user.id, user_email: job.user.email, lane_id: job.laneId, reason: message });
    if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'error';
    await cybercoreQuery(
      `UPDATE cybercore_lane SET status = 'suspended', config = config || $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
      [job.laneId, JSON.stringify({ error: message, ...(job.goadMeta ? { goad: job.goadMeta } : {}) })]
    ).catch(() => {});
  }

  laneDeployer.finishProgress(progressId);
  console.log(`${logTag} Complete: ${provisioned.length} provisioned, ${failed.length} failed`);

  return { provisioned, failed, progressId, lanes: created };
}

// ── in-place per-VM rebuild ──────────────────────────────────────────────────
//
// Destroy and re-clone SPECIFIC machines inside an existing challenge lane. The
// lane row, vxlan_id, gateway, WAN address, DHCP reservations, consoles and
// Guacamole connections all survive, and so do the machines not named — so a
// student whose web01 is broken keeps the domain they have already worked on.
//
// The workstation equivalent is lane-deployer.rebuildLaneWorkstations, and the
// same three properties make it safe here:
//   - VMIDs are DERIVED (vm_offset + vxlanId), so a rebuilt VM reclaims exactly
//     the id it had and teardown still finds it.
//   - the console targets the GATEWAY's wan0 ip:port, never the VM, so a
//     rebuilt machine keeps its existing Guacamole connection untouched.
//   - cybercore_lane_flag CASCADEs off the LANE row, which is not deleted here,
//     so a student's captured values and capture state survive; ensureLaneFlags
//     re-plants with ON CONFLICT DO UPDATE SET flag_value = <existing>, which is
//     what makes the carry-over automatic rather than a snapshot/replay dance.

/** A failure that happened BEFORE anything was destroyed. */
function challengePreflightError(msg) {
  const e = new Error(msg);
  e.phase = 'preflight';
  e.destroyed = false;
  return e;
}

/**
 * Rebuild named machines in place on a challenge lane.
 *
 * @param {string}        a.laneId
 * @param {string[]|null} a.vmNames  null = every spec machine on the lane
 * @returns {Promise<{lane_id, vms:Array, untouched:string[], errors:string[]}>}
 */
async function rebuildLaneChallengeVms({
  laneId, vmNames = null, progress = null, cloneSem = null, logTag = LOG,
}) {
  const laneRes = await cybercoreQuery(
    // host() on the INET column: gateway_wan_ip is read back, never re-derived —
    // resolveLaneNetworking below is handed this value, and the old derivation
    // was not unique per lane.
    `SELECT lane_id, user_id, module_key, name, status, vxlan_id, config,
            host(gateway_wan_ip) AS gateway_wan_ip
       FROM cybercore_lane
      WHERE lane_id = $1`,
    [laneId]
  );
  if (!laneRes.rows.length) throw challengePreflightError('Lane not found');
  const lane = laneRes.rows[0];
  const cfg = lane.config || {};

  // ── pre-flight ───────────────────────────────────────────────────────────
  if (lane.status !== 'active') {
    throw challengePreflightError(
      `This lane is ${lane.status}, not active. Rebuilding individual machines keeps the existing lane and gateway, which only makes sense for a working one \u2014 rebuild the whole environment instead.`);
  }
  if (lane.vxlan_id == null) throw challengePreflightError('Lane has no VXLAN id');
  const recorded = Array.isArray(cfg.vms) ? cfg.vms : [];
  if (!recorded.length) {
    throw challengePreflightError(
      `This lane records no machines. Attached environments share the student's workstation lane and are rebuilt as a unit \u2014 use the whole-environment rebuild.`);
  }
  if (!cfg.challenge_key) {
    throw challengePreflightError('This lane does not record which environment built it.');
  }

  const moduleKey = lane.module_key || 'crucible';
  const chal = await cybercoreQuery(
    // The table name is interpolated because it is derived from module_key, which
    // a bound parameter cannot supply — hence the character strip, which is the
    // only thing standing between this and an injection. Everything else binds.
    `SELECT spec FROM ${String(moduleKey).replace(/[^a-z0-9_]/gi, '')}_challenge
      WHERE challenge_key = $1
        AND status = 'active'`,
    [cfg.challenge_key]
  );
  if (!chal.rows.length) {
    throw challengePreflightError(
      `The environment '${cfg.challenge_key}' is no longer active, so its machines cannot be rebuilt. Re-activate it first.`);
  }
  const spec = parseSpec(chal.rows[0].spec);

  // LIVE GOAD provisions the domain with ansible from a controller against
  // every machine at once. Re-cloning one DC without re-running that leaves it
  // out of the domain — running, reachable, and quietly useless. A prebaked
  // lane has no such step (deployPrebakedGoadLane only writes reservations and
  // bounces onto the baked IPs), so per-machine is safe there.
  if (spec.goad?.enabled && !spec.goad?.prebaked) {
    throw challengePreflightError(
      `'${cfg.challenge_key}' provisions its domain across every machine at once, so a single machine cannot be rebuilt on its own without leaving it outside the domain. Rebuild the whole environment instead.`);
  }

  const specVms = resolveSpecVms(spec, cfg.challenge_key);
  const bySpecName = new Map(specVms.map(v => [v.name || cfg.challenge_key, v]));
  // Machines the INSTRUCTOR added at deploy time clone through a different path
  // (cloneExtraWorkstation, with catalog-template resolvers), so they are not
  // rebuildable here yet. They are marked on the lane record.
  const extras = new Set(recorded.filter(v => v.source === 'instructor').map(v => v.name));

  const wanted = vmNames == null
    ? specVms.map(v => v.name || cfg.challenge_key)
    : [...new Set(vmNames)];
  for (const n of wanted) {
    if (extras.has(n)) {
      throw challengePreflightError(
        `'${n}' was added to this environment at deploy time and cannot be rebuilt on its own yet \u2014 rebuild the whole environment.`);
    }
    if (!bySpecName.has(n)) {
      throw challengePreflightError(`This environment has no machine named '${n}'`);
    }
  }
  if (!wanted.length) throw challengePreflightError('No machines selected');

  const userRes = await cybercoreQuery(
    `SELECT user_id AS id, email FROM cybercore_user WHERE user_id = $1`, [lane.user_id]);
  const user = userRes.rows[0] || { id: lane.user_id, email: cfg.user_email || null };

  const targetNode = cfg.node;
  if (!targetNode) throw challengePreflightError('Lane does not record which node it was built on');

  // ── cluster snapshot ─────────────────────────────────────────────────────
  const gatewayVmId = GATEWAY_VMID_OFFSET + lane.vxlan_id;
  let live = [];
  try {
    live = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm') || [];
  } catch (e) {
    throw challengePreflightError(`Could not read cluster state: ${e.message}`);
  }
  const liveByVmid = {};
  for (const r of live) liveByVmid[String(r.vmid)] = r;
  const gw = liveByVmid[String(gatewayVmId)];
  if (!gw) {
    throw challengePreflightError(
      `This lane's gateway (LXC ${gatewayVmId}) is not on the cluster, so there is nothing to rebuild the machines behind. Rebuild the whole environment instead.`);
  }
  const gatewayNode = gw.node || targetNode;

  // ── networking + ctx, rebuilt the way deployLaneVms builds them ──────────
  const subnetScheme = cfg.subnet_scheme || 'v2';
  const isV3 = subnetScheme === 'v3';
  const net = resolveLaneNetworking(subnetScheme, moduleKey, lane.vxlan_id,
    lane.gateway_wan_ip ? { wanIp: lane.gateway_wan_ip } : {});
  // Re-wrapped as a pre-flight failure: this runs before anything on the lane is
  // touched, and the rest of this function's refusals promise the caller that
  // nothing was destroyed. Rebuilding a pre-baked machine onto a per-lane subnet
  // is the same silent breakage as deploying one — see applyPrebakedFixedSubnet.
  try {
    applyPrebakedFixedSubnet(net, isV3, spec);
  } catch (fixedErr) {
    throw challengePreflightError(fixedErr.message);
  }
  const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
  const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;
  const goadMacs = goadDeploy.prepareGoadMacs(spec, lane.vxlan_id, goadSubnetBase);

  // resolveVnets returns { resolved, missing } -- the VNets live under .resolved,
  // keyed by vxlan id, and each entry is { vnet, vnetInt } where each of THOSE is
  // the Proxmox VNet object whose .vnet property is the name. Indexing the
  // wrapper directly was always undefined, so this threw 'cabled to nothing' on
  // every rebuild no matter how healthy the lane was. Destructured the way
  // deployChallengeLanesInner already does it.
  const { resolved: vnetsByVxlan, missing: vnetsMissing } = await resolveVnets(
    [lane.vxlan_id], subnetScheme);
  const vnetPair = vnetsByVxlan[lane.vxlan_id] || vnetsByVxlan[String(lane.vxlan_id)];
  if (!vnetPair) {
    // Report WHY: resolveVnets already tells 'no VNet at all' apart from 'v3 lane
    // missing only its internal VNet', and those need different fixes.
    const reason = (vnetsMissing.find(m => String(m.vxlanId) === String(lane.vxlan_id)) || {}).reason
      || `No VNet with tag ${lane.vxlan_id}`;
    throw challengePreflightError(
      `${reason} \u2014 a rebuilt machine would be cabled to nothing.`);
  }
  const vnetExtName = vnetPair.vnet.vnet;
  const vnetIntName = isV3 ? vnetPair.vnetInt.vnet : vnetExtName;

  const templateNodeByVmid = await resolveTemplateNodes(specVms, spec, false);
  const ctx = {
    spec, subnetScheme, moduleKey, challengeKey: cfg.challenge_key,
    description: `Rebuild on lane ${laneId}`, logTag,
    cloneSem: cloneSem || laneDeployer.createCloneSemaphore(),
    templateNodeByVmid,
    _consoleOctetForVm: {},
  };

  // Console addressing is REPLAYED from the lane's own config, not re-derived.
  // Same rule the pinned_hosts block below already follows, and for a sharper
  // reason: writeLaneReservations renders the file WHOLE-LANE and
  // installLaneReservations overwrites it, so any machine missing from this map
  // has its dhcp-host line DELETED -- including machines this rebuild was never
  // asked to touch. They keep running on a stale lease until the next renew or
  // reboot, then drop to a pool address while the gateway DNAT and their
  // Guacamole connection still point at the old one. Nothing logs it.
  //
  // Re-deriving got this wrong twice over:
  //   - `override: cfg.console_vm` reads a key NOTHING writes. The deploy
  //     persists console_vm_name (and consoles[]), so the override was always
  //     null -- and an override-PROMOTED console (a spec VM carrying no
  //     console_role, which is exactly what promotion exists for) vanished from
  //     the plan, losing both its pinned MAC and its reservation.
  //   - `extraWorkstations: []` meant every instructor-added machine was absent
  //     too, so rebuilding one spec VM silently unaddressed all of them.
  const reservationOctets = {};
  const recordedConsoles = Array.isArray(cfg.consoles) ? cfg.consoles : [];
  for (const c of recordedConsoles) {
    // Kali is carried separately, by attackBoxOctet.
    if (c.kind === 'kali') continue;
    const octet = Number(String(c.ip || '').split('.').pop());
    if (!Number.isFinite(octet)) continue;
    reservationOctets[c.name] = octet;
    // Only a SPEC machine is re-cloned here, and only it needs its MAC pinned at
    // clone time; an added workstation is left running and just needs its
    // reservation line preserved.
    if (c.kind === 'spec') ctx._consoleOctetForVm[c.name] = octet;
  }

  // Lanes that predate config.consoles[] have nothing to replay, so fall back to
  // deriving the plan. Narrow on purpose: it cannot reproduce an override-
  // promoted console (the override was never persisted on those lanes either),
  // and it is only reached for a lane deployed before consoles[] existed.
  if (!recordedConsoles.length) {
    const consolePlan = resolveConsolePlan({
      specVms, attackBoxes: !!cfg.attack_box_vm_id, extraWorkstations: [],
      override: cfg.console_vm_name || null,
    });
    const taken = new Set([goadDeploy.INFRA_IP_OCTETS.Kali]);
    Object.values(goadMacs || {}).forEach((g) => {
      const last = Number(String(g.static_ip || '').split('.').pop());
      if (Number.isFinite(last)) taken.add(last);
    });
    let next = CONSOLE_OCTET_MIN;
    for (const c of consolePlan.consoles) {
      if (c.kind === 'kali') continue;
      const pinned = Number(c.vm && c.vm.ipOctet);
      const octet = Number.isFinite(pinned) ? pinned : (() => {
        while (taken.has(next)) next += 1;
        return next;
      })();
      taken.add(octet);
      if (c.kind === 'spec') ctx._consoleOctetForVm[c.name] = octet;
      reservationOctets[c.name] = octet;
    }
  }

  // Replayed from the lane's own config, NOT re-derived. Two reasons, and both
  // produce a lane that looks fine and is wrong:
  //   - the reservations file is rendered WHOLE-LANE below, so omitting these
  //     would delete every pinned machine's reservation and every host-record —
  //     the rest of the lane would fall to pool leases on its next reboot and
  //     `elk` would stop resolving, with nothing logged.
  //   - a rebuilt machine must keep the address the student's generated paper
  //     already names. Re-running the allocator against a since-edited spec
  //     could hand it a different one.
  const pinnedHosts = Array.isArray(cfg.pinned_hosts) ? cfg.pinned_hosts : [];
  const dnsRecords  = Array.isArray(cfg.dns_records)  ? cfg.dns_records  : [];
  // Without this the re-cloned VM gets a random MAC, never matches the
  // reservation being rewritten above, and lands on a pool lease.
  ctx._pinnedOctetForVm = {};
  for (const h of pinnedHosts) ctx._pinnedOctetForVm[h.name] = h.octet;

  // ── gateway FIRST, from the FULL machine list ────────────────────────────
  // Same inversion rebuildLaneWorkstations makes: the reservations already
  // exist and are unchanged, so writing them first is a no-op on the wire — and
  // a gateway that refuses fails the operation while every machine still runs.
  await writeLaneReservations({
    gatewayVmId, node: gatewayNode, vxlanId: lane.vxlan_id, goadMacs,
    attackBoxOctet: cfg.attack_box_vm_id ? goadDeploy.INFRA_IP_OCTETS.Kali : null,
    // `spec` is the lane's own stored challenge spec (parsed above), so a rebuild
    // re-emits the company DNS lines the deploy wrote. The file is rendered
    // WHOLE-LANE and overwritten, so omitting them here would silently delete the
    // forwarder from a lane nobody asked to change.
    consoleOctets: reservationOctets, pinnedHosts, dnsRecords, spec, subnetScheme,
    extSubnetBase: laneSubnetBase, intSubnetBase: goadSubnetBase,
    liveGoadController: false,
    laneId, logTag,
  });

  await cybercoreQuery(
    // Merged, not replaced: this runs while the lane is live and every other key
    // in config (vms, console_*, gateway ids) must survive it untouched.
    `UPDATE cybercore_lane
        SET config = COALESCE(config, '{}'::jsonb) || $2::jsonb,
            updated_at = NOW()
      WHERE lane_id = $1`,
    [laneId, JSON.stringify({
      rebuild: {
        at: new Date().toISOString(),
        mode: 'in_place_vms', vms_requested: wanted, status: 'running',
      },
    })]
  );

  // ── rebuild, one machine at a time ───────────────────────────────────────
  const rebuilt = [];
  const results = [];
  const errors = [];
  for (const name of wanted) {
    const vmSpec = bySpecName.get(name);
    const vmId = (vmSpec.vm_offset || DEFAULT_VM_OFFSET) + lane.vxlan_id;
    const vmType = vmSpec.type || 'qemu';
    const liveVm = liveByVmid[String(vmId)];

    try {
      if (liveVm) {
        await forceDestroyVM(vmId, vmType === 'lxc' ? 'lxc' : 'qemu', liveVm.node);
        // Proxmox DELETE is asynchronous. Cloning into an id it is still purging
        // either fails outright or lets the destroy land after the clone.
        const { surviving } = await waitForVmidsGone([vmId], { timeoutMs: 120000 });
        if (surviving.length) {
          throw new Error(`VM ${vmId} is still on the cluster after being destroyed`);
        }
      }

      const dvm = await cloneChallengeVm({
        vmSpec, vxlanId: lane.vxlan_id, targetNode, laneId, user, ctx, net, goadMacs,
        vnetExtName, vnetIntName,
      });
      await proxmoxAPI('POST',
        `/api2/json/nodes/${dvm.node}/${dvm.type === 'lxc' ? 'lxc' : 'qemu'}/${dvm.vm_id}/status/start`);
      rebuilt.push(dvm);
      results.push({ name, vm_id: vmId, status: 'rebuilt' });
    } catch (e) {
      results.push({ name, vm_id: vmId, status: 'failed', error: e.message });
      errors.push(`${name}: ${e.message}`);
    }
  }

  // ── flags ────────────────────────────────────────────────────────────────
  // Scoped to the machines actually rebuilt. The lane row survived, so their
  // cybercore_lane_flag rows did too — ensureLaneFlags re-plants with
  // ON CONFLICT DO UPDATE SET flag_value = <existing>, so a student's captured
  // values and capture state carry over with no snapshot needed.
  if (rebuilt.length) {
    try {
      await plantFlagsForLane({
        laneId, userId: lane.user_id, vms: rebuilt, specVms, logTag,
      });
    } catch (e) {
      console.warn(`${logTag} Flag re-plant after rebuild failed on lane ${laneId}: ${e.message}`);
    }

    // Vulnerability scripts are per-machine, and a fresh clone has none of them.
    // The SIEM agents are in exactly that class: a rebuilt DC comes back with no
    // Sysmon, no winlogbeat and no wazuh-agent, and it would go dark in a console
    // the rest of the lane is still reporting to — one host missing from a SIEM
    // is far harder to notice than an empty one. Re-derived from the spec rather
    // than replayed from cfg.vuln_scripts, for the same reason it is derived at
    // deploy: config written by an older deploy would reinstate a stack this
    // environment may no longer have.
    const scripts = withGoadAgentVulnScripts(cfg.vuln_scripts || [], spec).filter(
      sc => rebuilt.some(v => v.name === sc.vm_name));
    if (scripts.length) {
      try {
        await runVulnScripts({ laneId, deployedVMs: rebuilt, vulnScripts: scripts, logTag });
      } catch (e) {
        console.warn(`${logTag} Vuln scripts after rebuild failed: ${e.message}`);
      }
    }
  }

  // ── write back ───────────────────────────────────────────────────────────
  // Splice server-side so the machines that were NOT rebuilt keep their records
  // verbatim. status returns to ACTIVE even on partial failure: the gateway is
  // running with untouched machines behind it, and marking the lane 'error'
  // would release its VXLAN and WAN address while both are still in use.
  const ok = errors.length === 0;
  await cybercoreQuery(
    // Spliced server-side, keyed on NAME — the challenge equivalent of
    // lane-deployer.spliceLaneWorkstations, which does the same on slot.
    //
    // Read-modify-write in JS would lose whatever another operation wrote to
    // this row while the clones were running, and the untouched machines' records
    // must come through verbatim: they are still running, and their vm_id is the
    // only handle teardown has on them.
    //
    // $3 carries the names ACTUALLY rebuilt rather than the names requested, so a
    // machine whose clone failed keeps its old record instead of vanishing from
    // config.vms and becoming an orphan nothing can destroy.
    `UPDATE cybercore_lane l
        SET config = jsonb_set(
                       COALESCE(l.config, '{}'::jsonb),
                       '{vms}',
                       COALESCE((
                         SELECT jsonb_agg(vm)
                           FROM (
                             SELECT p AS vm FROM jsonb_array_elements($2::jsonb) AS p
                             UNION ALL
                             SELECT e AS vm
                               FROM jsonb_array_elements(
                                      COALESCE(l.config->'vms', '[]'::jsonb)) AS e
                              WHERE (e->>'name') IS NULL
                                 OR NOT ((e->>'name') = ANY($3::text[]))
                           ) u
                       ), '[]'::jsonb)
                     ) || $4::jsonb,
            -- Back to ACTIVE even on partial failure: the gateway is up with the
            -- untouched machines behind it, and 'error' would release this lane's
            -- VXLAN and WAN address while both are still in use.
            status = 'active',
            updated_at = NOW()
      WHERE lane_id = $1`,
    [
      laneId,
      JSON.stringify(rebuilt),
      results.filter(r => r.status === 'rebuilt').map(r => r.name),
      JSON.stringify({
        rebuild: {
          at: new Date().toISOString(),
          mode: 'in_place_vms', vms_requested: wanted,
          status: ok ? 'ok' : (rebuilt.length ? 'partial' : 'failed'),
          error: ok ? null : errors[0],
        },
      }),
    ]
  );

  if (progress?.lanes[laneId]) {
    progress.lanes[laneId].status = ok ? 'active' : 'error';
    progress.lanes[laneId].error = ok ? null : errors[0];
  }
  console.log(
    `${logTag} Lane ${laneId} rebuilt ${rebuilt.length}/${wanted.length} machine(s): ${wanted.join(', ')}`);

  return {
    lane_id: laneId,
    vms: results,
    untouched: recorded.map(v => v.name).filter(n => !wanted.includes(n)),
    errors,
  };
}

module.exports = {
  rebuildLaneChallengeVms,
  GATEWAY_VMID_OFFSET,
  DEFAULT_VM_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  parseSpec,
  resolveSpecVms,
  resolveConsolePlan,
  resolveSpecAddressing,
  resolveGoadExternalPins,
  validateGoadLaneAddressing,
  // Pure, and exported for the same reason resolveSpecAddressing is: both encode
  // a rule whose failure mode is a lane that deploys, reports active, and is
  // silently wrong — which no test can reach through the deploy path itself.
  resolveLaneDnsExtras,
  // Exported for ONE reason: the reservations file is rendered whole-lane and
  // overwritten, so "this change did not alter what an existing lane writes" is
  // a claim about the WHOLE file — not about the resolver that contributes two
  // of its lines. A test can only make that claim by rendering the file, and the
  // deploy path around this function needs Proxmox, SSH and a DB. Stub
  // laneDeployer.installLaneReservations and the `lines` array is the artifact.
  writeLaneReservations,
  applyPrebakedFixedSubnet,
  DUAL_HOMED_OCTET,
  CONSOLE_OCTET_MIN,
  CONSOLE_OCTET_MAX,
  SPEC_OCTET_MIN,
  SPEC_OCTET_MAX,
  findVmOffsetCollision,
  findGoadHostMismatch,
  resolveAttackBoxCredentials,
  deployChallengeLanes,
  // Same registry lane-deployer.js drives, re-exported so a caller only needs
  // one import to deploy and to poll.
  readProgress: laneDeployer.readProgress,
};
