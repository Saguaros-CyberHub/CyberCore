/**
 * ============================================================================
 * LANE NETWORKING HELPERS
 * Subnet scheme logic, VMID constants, and gateway config for v1/v2/v3 lanes.
 * ============================================================================
 */

const tailscale = require('./tailscale');
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
async function configureLaneTailscale({ subnetScheme, vxlanId, wanIp, laneName, logTag = '[Deploy]' }) {
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
    await tailscale.storeLaneBootstrap({
      cybercoreQuery,
      vxlanId,
      wanIp,
      payload: {
        tailscale_authkey:  key,
        tailscale_tags:     tags.join(','),
        tailscale_hostname: hostname
      }
    });
    console.log(`${logTag} Tailscale bootstrap staged for lane ${vxlanId} (wan=${wanIp}, tags=${tags.join(',')})`);
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

module.exports = {
  V2_LANE_GATEWAY_VMID,
  V3_LANE_GATEWAY_VMID,
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
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
  configureLaneTailscale,
};
