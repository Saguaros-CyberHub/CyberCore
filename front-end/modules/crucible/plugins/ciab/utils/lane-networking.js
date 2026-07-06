/**
 * Lane Networking Helpers (CIAB-local)
 * ============================================================================
 * Same algorithms as front-end/src/utils/lane-networking.js, duplicated here
 * (instead of imported) so the CIAB plugin stays self-contained even if a
 * future refactor moves/removes the shared copy. Both files now read the
 * actual networking topology from config/site.json via site-config.js, so
 * there's a single source of truth for values — only the subnet-math
 * functions themselves are duplicated, not the config.
 *
 * If you change the algorithms here, update src/utils/lane-networking.js too
 * (or the other way).
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI, waitForTask } = require('../../../../../src/utils/proxmox');
const tailscale = require('../../../../../src/utils/tailscale');
const { getModuleNetworks, getV2LabNetwork, getV1LanSubnet } = require('../../../../../src/utils/site-config');

// ─── Constants (mirror src/utils/lane-networking.js) ────────────────────────
const V2_LANE_GATEWAY_VMID = 1694;
const V3_LANE_GATEWAY_VMID = 1695;
const V3_INTERNAL_TAG_OFFSET = 4000000;
const ATTACK_BOX_VMID_OFFSET = 700000;
const KALI_TEMPLATE_VMID = 1699;

// Topology is declared in config/site.json under cluster.networking — resolved
// lazily (not at module load) so a missing/late-written site.json doesn't
// crash require() at boot, only whichever call actually needs a value.
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

// ─── Subnet math ────────────────────────────────────────────────────────────

function laneUplinkConfig(module, vxlanId) {
  const map = _transitByModule();
  const t = map[module];
  if (!t) {
    throw new Error(`No transit gateway configured for module '${module}'. ` +
      `Configured modules: ${Object.keys(map).join(', ')}. ` +
      `Add the module under cluster.networking.module_networks in config/site.json once the transit LXC is up.`);
  }
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  return { bridge: t.bridge, ip: `${t.subnetBase}.${high}.${low}${t.cidr}`, gw: t.gateway };
}

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

function v2LaneSubnet(vxlanId) {
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  const base3 = `10.${high}.${low}`;
  return { base3, cidr: `${base3}.0/24`, gatewayIp: `${base3}.1`, netmask24: '255.255.255.0' };
}

function v3InternalSubnet(vxlanId) {
  if (vxlanId > 32767) {
    throw new Error(`v3InternalSubnet: vxlanId ${vxlanId} exceeds 32767 — ` +
      `internal-subnet high-bit scheme would overflow the second octet`);
  }
  const high = ((vxlanId >> 8) & 0xFF) | 0x80;
  const low  = vxlanId & 0xFF;
  const base3 = `10.${high}.${low}`;
  return { base3, cidr: `${base3}.0/24`, gatewayIp: `${base3}.1`, netmask24: '255.255.255.0' };
}

// ─── Resolution helpers ─────────────────────────────────────────────────────

function resolveGatewayVmid(module, subnetScheme, spec) {
  if (subnetScheme === 'v3') return V3_LANE_GATEWAY_VMID;
  if (subnetScheme === 'v2') return V2_LANE_GATEWAY_VMID;
  const v1Map = { cyberlabs: 1691, crucible: 1692, forge: 1693 };
  return v1Map[module] || (spec && spec.gateway_vmid) || 1692;
}

function resolveLaneNetworking(subnetScheme, module, vxlanId) {
  if (subnetScheme === 'v3') {
    return {
      wan:    v2WanConfig(vxlanId),
      lanExt: v2LaneSubnet(vxlanId),
      lanInt: v3InternalSubnet(vxlanId)
    };
  }
  if (subnetScheme === 'v2') {
    return { wan: v2WanConfig(vxlanId), lan: v2LaneSubnet(vxlanId) };
  }
  const v1Lan = getV1LanSubnet();
  return {
    wan: laneUplinkConfig(module, vxlanId),
    lan: { base3: v1Lan.base3, cidr: v1Lan.cidr, gatewayIp: v1Lan.gateway_ip, netmask24: v1Lan.netmask24 }
  };
}

// ─── String formatting ──────────────────────────────────────────────────────

function formatLaneHostname({ vxlanId, laneName } = {}) {
  const raw = laneName ? `lane-${vxlanId}-${laneName}` : `lane-${vxlanId}`;
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 63);
}

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

// ─── Tailscale staging (v2/v3 only) ─────────────────────────────────────────

async function configureLaneTailscale({ subnetScheme, vxlanId, wanIp, laneName, claimSecret, logTag = '[CIAB Deploy]' }) {
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
    // `_claim_secret` is the per-lane one-shot the gateway echoes back as
    // ?secret=… on /api/lane-bootstrap. It replaces source-IP matching, which
    // breaks when the orchestrator's docker bridge rewrites the source IP
    // (see lane-bootstrap.js + the gateway bake scripts). Leading underscore
    // marks it as internal-to-the-claim-flow, not part of the gateway payload.
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
    console.log(`${logTag} Tailscale bootstrap staged for lane ${vxlanId} (wan=${wanIp}${claimSecret ? ', secret-gated' : ', IP-gated'})`);
    return true;
  } catch (err) {
    console.warn(`${logTag} Tailscale config failed for lane ${vxlanId} (deploy continues): ${err.message}`);
    return false;
  }
}

// ─── Forced VM destroy (for teardown + retry-cleanup) ───────────────────────

async function forceDestroyVM(vmid, type, knownNode) {
  const nodes = knownNode ? [knownNode] : [];
  if (nodes.length === 0) {
    try {
      const nodeList = await proxmoxAPI('GET', '/api2/json/nodes');
      for (const n of nodeList) nodes.push(n.node);
    } catch (_) {
      nodes.push('cyberhub-node-5');
    }
  }

  for (const node of nodes) {
    try {
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { protection: 0 }); } catch (_) {}
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${type}/${vmid}/config`, { lock: '' });        } catch (_) {}
      try {
        const stopBody = type === 'qemu' ? { timeout: 0 } : {};
        const stopUpid = await proxmoxAPI('POST', `/api2/json/nodes/${node}/${type}/${vmid}/status/stop`, stopBody);
        if (stopUpid) {
          try { await waitForTask(node, stopUpid, 30000); } catch (_) {}
        }
      } catch (_) {}

      const primaryUrl = type === 'lxc'
        ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
        : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1&skiplock=1`;
      let destroyUpid;
      try {
        destroyUpid = await proxmoxAPI('DELETE', primaryUrl);
      } catch (_) {
        const fallback = type === 'lxc'
          ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
          : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1`;
        destroyUpid = await proxmoxAPI('DELETE', fallback);
      }
      // Wait for the destroy task to actually finish — otherwise the file lock
      // /var/lock/qemu-server/lock-<vmid>.conf may still be held when the
      // immediately-following clone tries to acquire it.
      if (destroyUpid) {
        try { await waitForTask(node, destroyUpid, 60000); } catch (_) {}
      }

      console.log(`[CIAB Teardown] Destroyed ${type} ${vmid} on ${node}`);
      return true;
    } catch (e) {
      if (/unable to find configuration file/i.test(e.message)) continue;
      continue;
    }
  }
  return false;
}

module.exports = {
  V2_LANE_GATEWAY_VMID,
  V3_LANE_GATEWAY_VMID,
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  laneUplinkConfig,
  v2WanConfig,
  v2LaneSubnet,
  v3InternalSubnet,
  resolveGatewayVmid,
  resolveLaneNetworking,
  formatLaneHostname,
  formatLaneGatewayNet0,
  configureLaneTailscale,
  forceDestroyVM
};
