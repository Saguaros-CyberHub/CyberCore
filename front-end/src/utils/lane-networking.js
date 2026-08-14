/**
 * ============================================================================
 * LANE NETWORKING HELPERS
 * Subnet scheme logic, VMID constants, and gateway config for v1/v2/v3 lanes.
 * ============================================================================
 */

const tailscale = require('./tailscale');
// buildLaneNet0 is the one net-string formatter; resolveVmNics wraps it rather
// than growing a second. goad-deploy does not require this module back, so the
// top-level require is cycle-free.
const goadDeploy = require('./goad-deploy');
const { cybercoreQuery } = require('./cybercore-db');
const { getModuleNetwork, getModuleNetworks, getV2LabNetwork, getV1LanSubnet } = require('./site-config');

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

// ── v1 transit gateway map and v2 lab network ─────────────────────────────────
// Topology is declared in config/site.json under cluster.networking.
// Use getModuleNetwork(name) / getV2LabNetwork() / getV1LanSubnet() from site-config.

// Backward-compat exports — resolved lazily from site.json at first access.
let _TRANSIT_BY_MODULE = null;
let _V2_LAB_NETWORK    = null;

function _transitByModule() {
  if (!_TRANSIT_BY_MODULE) {
    const nets = getModuleNetworks();
    _TRANSIT_BY_MODULE = {};
    for (const [mod, n] of Object.entries(nets)) {
      if (n.gateway) {
        _TRANSIT_BY_MODULE[mod] = { bridge: n.bridge, gateway: n.gateway, subnetBase: n.subnet_base, cidr: n.cidr };
      }
    }
  }
  return _TRANSIT_BY_MODULE;
}

function _v2LabNetwork() {
  if (!_V2_LAB_NETWORK) {
    const n = getV2LabNetwork();
    _V2_LAB_NETWORK = { bridge: n.bridge, vlanTag: n.vlan_tag, subnetBase: n.subnet_base, gateway: n.gateway, cidr: n.cidr };
  }
  return _V2_LAB_NETWORK;
}

/**
 * Compute the lane gateway LXC's wan0 config from the module + vxlan_id (v1).
 * Maps vxlan_id (uint16) deterministically into the module's /16.
 */
function laneUplinkConfig(module, vxlanId) {
  const map = _transitByModule();
  const t = map[module];
  if (!t) {
    throw new Error(
      `No transit gateway configured for module '${module}'. ` +
      `Configured modules: ${Object.keys(map).join(', ')}. ` +
      `Add the module under cluster.networking.module_networks in config/site.json once the transit LXC is up.`
    );
  }
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  return {
    bridge: t.bridge,
    ip:     `${t.subnetBase}.${high}.${low}${t.cidr}`,
    gw:     t.gateway
  };
}

/**
 * Compute v2 lane gateway WAN config from vxlan_id.
 * Allocates from 100.100.60.10..249 (240 simultaneous lanes).
 */
function v2WanConfig(vxlanId) {
  const net = _v2LabNetwork();
  const offset = 10 + (vxlanId % 240);
  return {
    bridge:  net.bridge,
    vlanTag: net.vlanTag,
    ip:      `${net.subnetBase}.${offset}${net.cidr}`,
    gw:      net.gateway
  };
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
 * v2 includes a VLAN tag (lab network is tagged); v1 omits it.
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
 * Resolve the gateway VMID for a deploy based on subnet scheme.
 *   v1: 1691/1692/1693 by module.
 *   v2: always 1694 (subnet-agnostic).
 *   v3: always 1695 (3-NIC segmented gateway).
 */
function resolveGatewayVmid(module, subnetScheme, spec) {
  if (subnetScheme === 'v3') return V3_LANE_GATEWAY_VMID;
  if (subnetScheme === 'v2') return V2_LANE_GATEWAY_VMID;
  const v1Map = { cyberlabs: 1691, crucible: 1692, forge: 1693 };
  return v1Map[module] || (spec && spec.gateway_vmid) || 1692;
}

/**
 * Resolve the per-lane networking config based on subnet scheme.
 *   v1/v2: { wan, lan }            — single LAN subnet
 *   v3:    { wan, lanExt, lanInt } — segmented; `lan` deliberately omitted
 */
function resolveLaneNetworking(subnetScheme, module, vxlanId) {
  if (subnetScheme === 'v3') {
    return {
      wan:    v2WanConfig(vxlanId),
      lanExt: v2LaneSubnet(vxlanId),
      lanInt: v3InternalSubnet(vxlanId)
    };
  }
  if (subnetScheme === 'v2') {
    return {
      wan: v2WanConfig(vxlanId),
      lan: v2LaneSubnet(vxlanId)
    };
  }
  const v1Lan = getV1LanSubnet();
  return {
    wan: laneUplinkConfig(module, vxlanId),
    lan: {
      base3:     v1Lan.base3,
      cidr:      v1Lan.cidr,
      gatewayIp: v1Lan.gateway_ip,
      netmask24: v1Lan.netmask24
    }
  };
}

/**
 * For v2/v3 lanes: mint a one-shot Tailscale auth key and stage it in
 * lane_bootstrap_tokens for the gateway to fetch on first boot.
 * No-op if subnet_scheme is v1 or Tailscale env vars are not configured.
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
 * The network segments a lane has, given its subnet scheme. v1/v2 lane gateways
 * (1692/1694) carry one LAN NIC; the v3 gateway (1695) carries two — ext0/int0.
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
 * v1/v2 lanes have exactly one VNet, so every id resolves to it — that keeps a
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
 *   everything else         → ext (v3) / lan (v1,v2)
 *
 * The qemu guard on the dmz rule is not cosmetic: the old code returned from the
 * LXC branch before ever reaching the dual-homing block, so an LXC marked 'dmz'
 * got a single external NIC. Dropping the guard would silently change that.
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
  const { bridges = {}, goadMac, goadVm, isGoadVm = !!goadVm } = ctx;
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
      nets: { net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, bridgeFor(segments[0]), goadMac) },
      segments: segments.slice(0, 1),
      dualHomed: false,
    };
  }

  if (segments.length > 1) {
    const nets = {};
    segments.forEach((segId, i) => { nets[`net${i}`] = `virtio,bridge=${bridgeFor(segId)}`; });
    return { nets, segments, dualHomed: true };
  }

  return {
    nets: { net0: goadDeploy.buildLaneNet0(vmSpec, bridgeFor(segments[0]), goadMac, goadVm?.nic_model) },
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
  get TRANSIT_BY_MODULE() { return _transitByModule(); },
  get V2_LAB_NETWORK()    { return _v2LabNetwork(); },
  laneUplinkConfig,
  v2WanConfig,
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
  resolveVmNics,
};
