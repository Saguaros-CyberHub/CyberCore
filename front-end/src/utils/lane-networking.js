/**
 * ============================================================================
 * LANE NETWORKING HELPERS
 * Subnet scheme logic, VMID constants, and gateway config for v2/v3 lanes.
 * ============================================================================
 */

const tailscale = require('./tailscale');
// buildLaneNet0 is the one net-string formatter; resolveVmNics wraps it rather
// than growing a second. goad-deploy does not require this module back, so the
// top-level require is cycle-free.
const goadDeploy = require('./goad-deploy');
const { cybercoreQuery } = require('./cybercore-db');
const { getV2LabNetwork } = require('./site-config');

// ── VMID constants ────────────────────────────────────────────────────────────
const V2_LANE_GATEWAY_VMID = 1694;
const V3_LANE_GATEWAY_VMID = 1695;
// Internal VNet tag offset for v3 segmented lanes (external + internal VNets).
// Keeps internal tags (~4.01M) clear of the 10000-range challenge blocks and
// well inside the 24-bit VXLAN id space.
const V3_INTERNAL_TAG_OFFSET = 4000000;

const ATTACK_BOX_VMID_OFFSET = 700000;
const KALI_TEMPLATE_VMID = 1699;
// Challenge VM id = (spec vm_offset || this) + vxlanId. Lives here rather than
// in a deployer so topology-validate can check offset collisions without
// pulling in a deploy path.
const DEFAULT_VM_OFFSET = 600000;

// ── v2 lab network ────────────────────────────────────────────────────────────
// Topology is declared in config/site.json under cluster.networking.
// Use getV2LabNetwork() from site-config.
//
// The per-module v1 transit map that used to live here (crucible 100.102.0.0/16
// and friends, read from cluster.networking.module_networks) went out with the
// v1 scheme itself. A v1 lane's wan0 hung off its MODULE's transit /16 and never
// drew an address from the pooled lab VLAN — which is exactly why every v1 row
// in cybercore_lane carries gateway_wan_ip NULL. With v1 undeployable there is
// nothing left for that map to answer, and a repo-wide audit found nothing else
// that ever asked it.

// Backward-compat export — resolved lazily from site.json at first access.
let _V2_LAB_NETWORK = null;

function _v2LabNetwork() {
  if (!_V2_LAB_NETWORK) {
    const n = getV2LabNetwork();
    _V2_LAB_NETWORK = { bridge: n.bridge, vlanTag: n.vlan_tag, subnetBase: n.subnet_base, gateway: n.gateway, cidr: n.cidr };
  }
  return _V2_LAB_NETWORK;
}

/**
 * The PRE-ALLOCATOR address derivation: base + 10 + (vxlanId % 240).
 *
 * NOT UNIQUE, and never was. 240 buckets against VXLAN ids that climb
 * monotonically forever (lab-network-provision.allocateVxlanBlock never reuses a
 * freed block) means any two live lanes 240 apart got the identical address on
 * the shared lab VLAN — and, because that address is also the Guacamole console
 * host, the identical console endpoint. That is the bug this was replaced for;
 * see utils/lane-wan-allocator.js.
 *
 * Retained for exactly two callers:
 *   - migration 033's backfill, which must reproduce what the already-running
 *     gateways were actually configured with
 *   - the conflict audit's drift check
 * Never call it to assign an address to a new lane.
 */
function legacyV2WanIp(vxlanId) {
  const net = _v2LabNetwork();
  return `${net.subnetBase}.${10 + (vxlanId % 240)}`;
}

/** legacyV2WanIp in the shape resolveLaneNetworking returns. Same warning. */
function legacyV2WanConfig(vxlanId) {
  const net = _v2LabNetwork();
  const address = legacyV2WanIp(vxlanId);
  return { bridge: net.bridge, vlanTag: net.vlanTag, ip: `${address}${net.cidr}`, gw: net.gateway, address };
}

/**
 * Canonical hostname for a lane gateway's Tailscale device identity.
 * ACLs match on this name — centralizing it makes future naming changes a
 * one-function change.
 */
function formatLaneHostname({ vxlanId, laneName } = {}) {
  const raw = laneName ? `lane-${vxlanId}-${laneName}` : `lane-${vxlanId}`;
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 63);
}

/**
 * Render a lane gateway's net0 string from the wan config object.
 *
 * The tag is always rendered now. v2 and v3 both land wan0 on the shared lab
 * VLAN and getV2LabNetwork() always resolves a vlan_tag (defaulting to 60), so
 * the null arm below no longer has a real caller — it used to be the v1 case,
 * whose per-module transit bridge was untagged. It stays as a formatting guard
 * only: a caller assembling a wan object by hand should get a valid net0 string
 * rather than a literal `tag=undefined` that Proxmox rejects at clone time.
 */
function formatLaneGatewayNet0(wan) {
  const parts = [
    'name=wan0',
    `bridge=${wan.bridge}`,
    wan.vlanTag != null ? `tag=${wan.vlanTag}` : null,
    `ip=${wan.ip}`,
    `gw=${wan.gw}`,
    'firewall=0',
    'type=veth'
  ].filter(Boolean);
  return parts.join(',');
}

/**
 * Compute v2 lane LAN subnet from vxlan_id.
 * Maps uint16 vxlan_id into 10.<high>.<low>.0/24.
 */
function v2LaneSubnet(vxlanId) {
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  const base3 = `10.${high}.${low}`;
  return {
    base3,
    cidr:      `${base3}.0/24`,
    gatewayIp: `${base3}.1`,
    netmask24: '255.255.255.0'
  };
}

/**
 * Compute a v3 lane's INTERNAL LAN subnet from the EXTERNAL vxlan_id.
 * Sets the high bit of the second octet so it can never collide with any
 * external subnet (which always has high < 128 for these vxlan ids).
 * vxlanId must be <= 32767.
 */
function v3InternalSubnet(vxlanId) {
  if (vxlanId > 32767) {
    throw new Error(
      `v3InternalSubnet: vxlanId ${vxlanId} exceeds 32767 — ` +
      `the internal-subnet high-bit scheme would overflow the second octet`
    );
  }
  const high = ((vxlanId >> 8) & 0xFF) | 0x80;
  const low  = vxlanId & 0xFF;
  const base3 = `10.${high}.${low}`;
  return {
    base3,
    cidr:      `${base3}.0/24`,
    gatewayIp: `${base3}.1`,
    netmask24: '255.255.255.0'
  };
}

/**
 * Resolve the gateway LXC template VMID for a deploy.
 *
 *   v3 → 1695, the segmented ext0/int0 gateway.
 *   v2 → 1694, the single-LAN gateway. There is nothing else left.
 *
 * WHY spec.gateway_vmid IS NOT HONOURED, EVEN THOUGH THE FIELD EXISTS.
 * The old body consulted a per-module v1 map (cyberlabs 1691 / crucible 1692 /
 * forge 1693) and only fell through to `spec.gateway_vmid || 1692` for a module
 * outside that map. Every real module was in the map, so the override was
 * unreachable in practice. Deleting the map with the rest of v1 would hand it
 * reach for the first time — and that is a regression, not the fix it looks
 * like.
 *
 * There is exactly ONE spec.gateway_vmid in the entire repository: the seeded
 * metasploitable2-basic challenge (migrations/007_cybercore_tables.sql:65)
 * carries 1699, which was the ORIGINAL shared gateway template. That VMID has
 * since been recycled — 1699 is KALI_TEMPLATE_VMID above, a QEMU image. Honour
 * the override and deploying that challenge issues a clone of 1699 as an LXC
 * gateway, i.e. tries to build a lane gateway out of the Kali template. Every
 * other gateway_vmid in the codebase is a LANE INSTANCE id
 * (GATEWAY_VMID_OFFSET + vxlanId), not a template, so nothing else would benefit
 * from switching it on either.
 *
 * So the field stays inert, exactly as it has always behaved at runtime. If a
 * challenge ever genuinely needs a bespoke gateway image, give it a scheme of
 * its own rather than resurrecting a stale spec key whose one stored value now
 * points at the wrong kind of machine.
 *
 * `module` is RETAINED FOR SIGNATURE ONLY. It no longer affects the answer, but
 * five call sites pass it positionally, so dropping the parameter here would
 * slide subnetScheme into its place.
 */
function resolveGatewayVmid(module, subnetScheme, spec) {   // eslint-disable-line no-unused-vars
  return subnetScheme === 'v3' ? V3_LANE_GATEWAY_VMID : V2_LANE_GATEWAY_VMID;
}

/**
 * Resolve the per-lane networking config based on subnet scheme.
 *   v2: { wan, lan }            — single LAN subnet
 *   v3: { wan, lanExt, lanInt } — segmented; `lan` deliberately omitted
 *
 * Both REQUIRE the lane's allocated WAN transit address to be passed in. It is
 * no longer derivable: the derivation had 240 buckets and handed two live lanes
 * the same address (see legacyV2WanIp). Re-deriving it for a lane that already
 * exists is the exact failure this signature change eliminates, so there is no
 * silent default — a caller that supplies nothing throws rather than guessing.
 *
 * AN UNRECOGNISED SCHEME IS REJECTED FIRST, ahead of the wanIp check, and that
 * ordering is the whole point of the branch. Letting anything non-v3 fall into
 * the v2 arm would be one less line and the wrong answer: a v1 lane never had a
 * pooled WAN address to pass, so it would fail with "needs its allocated WAN
 * address passed as opts.wanIp" — a true sentence and completely the wrong
 * diagnosis. The lane is not missing an address; its scheme no longer exists,
 * and the fix is a redeploy as v2, not a lookup.
 *
 * `module` is retained for signature compatibility only. It was read by the v1
 * uplink derivation and by nothing else; callers pass it positionally.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.wanIp] the lane's allocated wan0 address, with or
 *   without a prefix. DEPLOY paths get it from
 *   laneWanAllocator.allocateLaneWanIps(); READ-BACK paths read
 *   cybercore_lane.gateway_wan_ip.
 * @param {boolean} [opts.allowLegacyDerivation=false] opt-in escape hatch for
 *   migration 033's backfill and the conflict audit's drift check only.
 */
function resolveLaneNetworking(subnetScheme, module, vxlanId, opts = {}) {
  if (subnetScheme !== 'v2' && subnetScheme !== 'v3') {
    throw new Error(
      `resolveLaneNetworking: lane ${vxlanId} declares subnet scheme '${subnetScheme}', which ` +
      `this orchestrator no longer builds. The v1 scheme — one flat shared 192.18.0.0/24 behind ` +
      `a per-module transit gateway — was retired, so a lane on it has to be REDEPLOYED as v2 ` +
      `(single LAN, the same topology shape v1 drew) or v3 (segmented ext/int). It cannot be ` +
      `resolved in place.`
    );
  }
  let wan;
  if (opts.wanIp) {
    const net = _v2LabNetwork();
    const address = String(opts.wanIp).split('/')[0];
    wan = { bridge: net.bridge, vlanTag: net.vlanTag, ip: `${address}${net.cidr}`, gw: net.gateway, address };
  } else if (opts.allowLegacyDerivation) {
    wan = legacyV2WanConfig(vxlanId);
  } else {
    throw new Error(
      `resolveLaneNetworking: lane ${vxlanId} (${subnetScheme}) needs its allocated WAN ` +
      `address passed as opts.wanIp. Deploy paths get it from ` +
      `laneWanAllocator.allocateLaneWanIps(); read-back paths read ` +
      `cybercore_lane.gateway_wan_ip. Re-deriving it from the vxlan id hands two lanes ` +
      `the same address and the same Guacamole console host.`
    );
  }
  return subnetScheme === 'v3'
    ? { wan, lanExt: v2LaneSubnet(vxlanId), lanInt: v3InternalSubnet(vxlanId) }
    : { wan, lan: v2LaneSubnet(vxlanId) };
}

/**
 * For v2/v3 lanes: mint a one-shot Tailscale auth key and stage it in
 * lane_bootstrap_tokens for the gateway to fetch on first boot.
 * No-op if Tailscale env vars are not configured.
 * Failure does NOT fail the deploy — logged as a warning.
 */
async function configureLaneTailscale({ subnetScheme, vxlanId, wanIp, laneName, claimSecret, logTag = '[Deploy]' }) {
  if (subnetScheme !== 'v2' && subnetScheme !== 'v3') return false;
  if (!tailscale.isEnabled()) {
    console.log(`${logTag} Tailscale env not configured — skipping BYOAB key mint for lane ${vxlanId}`);
    return false;
  }
  if (!wanIp) {
    console.warn(`${logTag} Tailscale config skipped for lane ${vxlanId}: no wanIp passed`);
    return false;
  }
  try {
    const { key, tags } = await tailscale.mintLaneAuthKey({ vxlanId });
    const hostname = formatLaneHostname({ vxlanId, laneName });
    // _claim_secret is the per-lane one-shot the gateway echoes back as
    // ?secret=… on /api/lane-bootstrap. Replaces source-IP matching, which
    // breaks when the orchestrator's Docker bridge / proxy chain rewrites
    // the source IP. Mirrors the CIAB-side configureLaneTailscale.
    await tailscale.storeLaneBootstrap({
      cybercoreQuery,
      vxlanId,
      wanIp,
      payload: {
        tailscale_authkey:  key,
        tailscale_tags:     tags.join(','),
        tailscale_hostname: hostname,
        _claim_secret:      claimSecret || null
      }
    });
    console.log(`${logTag} Tailscale bootstrap staged for lane ${vxlanId} (wan=${wanIp}, tags=${tags.join(',')}${claimSecret ? ', secret-gated' : ', IP-gated'})`);
    return true;
  } catch (err) {
    const cause = err.cause ? ` (cause: ${err.cause.code || err.cause.message || err.cause})` : '';
    console.warn(`${logTag} Tailscale config failed for lane ${vxlanId} (deploy continues): ${err.message}${cause}`);
    if (err.cause && err.cause.stack) {
      console.warn(`${logTag} Tailscale cause stack: ${err.cause.stack.split('\n').slice(0, 3).join(' | ')}`);
    }
    return false;
  }
}

/**
 * Override a lane's IP addressing with a FIXED subnet base, leaving the per-lane
 * VNet/VXLAN (the isolation boundary) untouched. Used by pre-baked "GOAD-Like"
 * challenges: a golden-image AD has full IPs (<base>.10, DNS A/SRV records,
 * DC-locator data) hardwired to the subnet it was provisioned on, so every lane
 * MUST reuse that exact base. Safe because v3 lanes are VXLAN-isolated —
 * identical subnets behind separate gateways never collide. Mutates + returns net.
 */
function applyFixedSubnet(net, isV3, fixedInt, fixedExt) {
  const mk = (base) => ({ base3: base, cidr: `${base}.0/24`, gatewayIp: `${base}.1` });
  if (isV3) {
    if (fixedInt && net.lanInt) net.lanInt = { ...net.lanInt, ...mk(fixedInt) };
    if (fixedExt && net.lanExt) net.lanExt = { ...net.lanExt, ...mk(fixedExt) };
  } else if (fixedInt && net.lan) {
    net.lan = { ...net.lan, ...mk(fixedInt) };
  }
  return net;
}

// ── Segment model + VM NIC resolution ────────────────────────────────────────
//
// Until now, "which VNet does this VM attach to" was derived at deploy time
// from a VM's NAME (matching a GOAD lab host) and its `role` string, and that
// derivation was copy-pasted across five deploy paths. Nothing in the challenge
// spec ever recorded the answer, so nothing could show it to an author before
// the lane was built.
//
// resolveVmNics is now the single owner of that decision. A spec VM may declare
// its attachments explicitly via `nics: [{ segment }]` (what the topology canvas
// emits); when it does not, the historical derivation runs unchanged, so every
// pre-existing challenge deploys byte-for-byte as before.

/**
 * The network segments a lane has, given its subnet scheme. The v2 lane gateway
 * (1694) carries one LAN NIC; the v3 gateway (1695) carries two — ext0/int0.
 *
 * Returned as a LIST rather than fixed keys so an N-segment gateway later is an
 * extra array entry, not a schema change. Ids are the stable identifiers that
 * `spec.vms[].nics[].segment` and `spec.network.segments[].id` reference.
 */
function resolveSegments(subnetScheme) {
  if (subnetScheme === 'v3') {
    return [
      { id: 'ext', role: 'external', label: 'External / Attacker' },
      { id: 'int', role: 'internal', label: 'Internal / Corp' },
    ];
  }
  return [{ id: 'lan', role: 'lan', label: 'Lane Network' }];
}

/**
 * Map segment id → Proxmox bridge (SDN VNet) name.
 *
 * A v2 lane has exactly one VNet, so every id resolves to it — that keeps a
 * spec authored as v3 from exploding if its challenge is later switched to v2,
 * and matches the existing callers, which already pass the same vnet as both
 * ext and int on non-v3 lanes.
 */
function resolveSegmentBridges(subnetScheme, vnetExtName, vnetIntName) {
  if (subnetScheme === 'v3') {
    return { ext: vnetExtName, int: vnetIntName };
  }
  return { lan: vnetExtName, ext: vnetExtName, int: vnetExtName };
}

/**
 * Which segments a VM attaches to, in NIC order.
 *
 * Explicit wins: `vmSpec.nics` is honoured as authored. Otherwise reproduce the
 * pre-canvas derivation exactly —
 *   v3 + role 'dmz' + qemu → ext then int  (the dual-homed pivot host)
 *   v3 + GOAD-matched name → int
 *   everything else         → ext (v3) / lan (v2)
 *
 * The qemu guard on the dmz rule is not cosmetic: the old code returned from the
 * LXC branch before ever reaching the dual-homing block, so an LXC marked 'dmz'
 * got a single external NIC. Dropping the guard would silently change that.
 *
 * ── THE EMPTY-NICS CONTRACT (read this with challenge-spec.normaliseNics) ────
 * `nics: []` and an absent `nics` key mean the SAME THING here: nothing was
 * authored, so DERIVE. `explicit.length` being 0 falls through to the derivation
 * on purpose — that is what keeps every pre-canvas spec deploying byte-for-byte
 * as before, and it is deliberately NOT changed.
 *
 * The trap that follows: a canvas detach makes `segments: []`, syncFromCanvas
 * writes `nics: []`, buildSpecVm drops the key, and this function then re-attaches
 * the machine to 'lan'. The canvas shows it floating and the lane deploys it
 * connected. So this function is NOT where an author-intended detach can be
 * expressed — an empty array cannot be made to mean both "derive" and "isolate".
 *
 * A machine must always have at least one NIC (no network = no DHCP lease, no
 * Guacamole target, no vuln scripts), so the detach is refused at the editor,
 * and a spec that nonetheless arrives with zero segments is caught loudly by
 * topology-validate's `no-nic` error rather than silently re-attached here. A
 * genuinely isolated host would need its own flag, not an overloaded `[]`.
 */
function resolveVmSegments(vmSpec, { subnetScheme, isGoadVm = false } = {}) {
  const explicit = Array.isArray(vmSpec?.nics) ? vmSpec.nics.filter(n => n && n.segment) : [];
  if (explicit.length) return explicit.map(n => String(n.segment));

  const isV3 = subnetScheme === 'v3';
  const type = vmSpec?.type || 'qemu';
  if (isV3 && vmSpec?.role === 'dmz' && type !== 'lxc') return ['ext', 'int'];
  if (isV3 && isGoadVm) return ['int'];
  return [isV3 ? 'ext' : 'lan'];
}

/**
 * NIC model for a spec VM, when the spec did not name one.
 *
 * Windows guests get e1000: a stock Windows image has no virtio-net driver, so a
 * virtio NIC comes up dead and the guest never DHCPs — the single most common
 * way a "deployed" Windows box ends up unreachable, and the reason the GOAD lab
 * definitions hardcode e1000 on every AD host.
 *
 * This is the spec-shaped twin of lane-deployer.resolveNicModel, which answers
 * the same question for a CATALOG TEMPLATE ROW (`metadata.nic_model`,
 * `os_family`). Two shapes, so two readers; the rule they encode is one rule and
 * must stay identical in both.
 *
 * Returns null rather than 'virtio' when nothing applies, so buildLaneNet0's
 * existing `nicModel || vmSpec.nic_model || 'virtio'` chain is untouched for any
 * spec that carries neither os_family nor nic_model.
 *
 * THIS IS NOT INERT FOR EXISTING CHALLENGES. An earlier version of this comment
 * claimed no stored spec carries os_family; that was wrong, and the test that
 * "proved" it only checked challenge-spec.buildSpecVm, which is the CREATE path.
 * The EDIT path persists it:
 *
 *   topology-editor.js:271   a palette drop stamps os_family from the catalog row
 *   topology-editor.js:441   stripInternal() removes only __topoId
 *   admin-challenges.js:940  saveTemplate posts vm_specs, then spec.vms = vm_specs
 *   lab-templates.js:389     PUT does `nextSpec.vms = vm_specs` VERBATIM
 *
 * So a canvas-authored challenge with a Windows machine already has
 * os_family:'windows_server' in crucible_challenge.spec.vms[], and its net0
 * changes from virtio to e1000 the next time it deploys.
 *
 * That flip is deliberate and is a FIX — it is the same rule lane-deployer's
 * resolveNicModel has always applied to catalog templates, and a stock Windows
 * guest on virtio has no driver, never DHCPs, and comes up unreachable. But it
 * IS a behaviour change to already-authored labs, not a dormant capability, and
 * it must be described as one. See test/challenge-lane-addressing.test.js, which
 * now pins the reachable path rather than the create path.
 */
function resolveSpecNicModel(vmSpec) {
  if (vmSpec?.nic_model) return vmSpec.nic_model;
  return String(vmSpec?.os_family || '').startsWith('windows') ? 'e1000' : null;
}

/**
 * The Proxmox config keys and values for a lane VM's NICs.
 *
 * Returns { nets, segments, dualHomed }:
 *   nets      — merge straight into a qemu/lxc config POST/PUT
 *   segments  — ordered segment ids, for the topology canvas and live lane view
 *   dualHomed — caller uses this to decide whether the .240 ipconfig pass runs
 *
 * ctx: { subnetScheme, bridges, goadMac, goadVm, isGoadVm }
 *
 * Three renderings, matching the three shapes the deploy paths used inline:
 *   lxc          → net1 only (net0 belongs to the template), name=lan0 form
 *   multi-NIC    → plain `virtio,bridge=…` on each, no MAC, no model override
 *   single qemu  → buildLaneNet0, carrying the GOAD MAC and NIC model
 */
function resolveVmNics(vmSpec, ctx = {}) {
  // `pinnedMac` is the generic form of what `goadMac` always was: "put this
  // exact MAC on net0". GOAD was simply the only caller that needed it. A
  // console-designated machine needs the same thing, because a MAC-keyed DHCP
  // reservation is the only way to give it a fixed address the gateway's DNAT
  // can point at. `goadMac` is still accepted so existing callers are untouched.
  const { bridges = {}, goadMac, pinnedMac, goadVm, isGoadVm = !!goadVm } = ctx;
  const mac = pinnedMac || goadMac;
  const segments = resolveVmSegments(vmSpec, { ...ctx, isGoadVm });
  const type = vmSpec?.type || 'qemu';

  const bridgeFor = (segId) => {
    const bridge = bridges[segId];
    if (!bridge) {
      throw new Error(
        `VM '${vmSpec?.name || '(unnamed)'}' attaches to segment '${segId}', which this lane does not have. ` +
        `Available: ${Object.keys(bridges).join(', ') || '(none)'}.`
      );
    }
    return bridge;
  };

  // LXC challenge VMs take net1 — the template already owns net0.
  if (type === 'lxc') {
    return {
      nets: { net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, bridgeFor(segments[0]), mac) },
      segments: segments.slice(0, 1),
      dualHomed: false,
    };
  }

  // Resolved once for both renderings below. A dual-homed Windows pivot host is
  // as dead on virtio as a single-homed one, and the branch that used to
  // hardcode `virtio` here is the same defect in a second place.
  //
  // Note this widens the multi-NIC branch twice over: besides os_family, it now
  // honours an explicit vmSpec.nic_model that the hardcoded 'virtio' used to
  // ignore outright. A dual-homed spec VM carrying nic_model therefore changes
  // behaviour even with no os_family in play.
  const nicModel = goadVm?.nic_model || resolveSpecNicModel(vmSpec) || 'virtio';

  if (segments.length > 1) {
    const nets = {};
    segments.forEach((segId, i) => { nets[`net${i}`] = `${nicModel},bridge=${bridgeFor(segId)}`; });
    return { nets, segments, dualHomed: true };
  }

  return {
    nets: { net0: goadDeploy.buildLaneNet0(vmSpec, bridgeFor(segments[0]), mac, nicModel) },
    segments,
    dualHomed: false,
  };
}

module.exports = {
  V2_LANE_GATEWAY_VMID,
  V3_LANE_GATEWAY_VMID,
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  DEFAULT_VM_OFFSET,
  get V2_LAB_NETWORK()    { return _v2LabNetwork(); },
  // v2WanConfig is gone: it derived a non-unique address. Assign through
  // utils/lane-wan-allocator.js; these two exist only for the 033 backfill and
  // the conflict audit's drift check.
  legacyV2WanIp,
  legacyV2WanConfig,
  formatLaneHostname,
  formatLaneGatewayNet0,
  v2LaneSubnet,
  v3InternalSubnet,
  resolveGatewayVmid,
  resolveLaneNetworking,
  applyFixedSubnet,
  configureLaneTailscale,
  resolveSegments,
  resolveSegmentBridges,
  resolveVmSegments,
  resolveSpecNicModel,
  resolveVmNics,
};
