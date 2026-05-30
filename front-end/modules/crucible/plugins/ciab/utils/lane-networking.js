/**
 * Lane Networking Helpers (CIAB-local)
 * ============================================================================
 * Mirrored from front-end/src/routes/admin.js — kept in sync manually.
 *
 * These are the small, stable per-deploy networking primitives used by the
 * CIAB profile-deploy orchestrator. We duplicate them here (instead of
 * importing from admin.js) so the CIAB plugin remains self-contained: if a
 * future refactor removes them from admin.js, CIAB still works. Long-term,
 * these should move to /src/utils/lane-networking.js and both call sites
 * should import the shared copy.
 *
 * If you change the algorithms here, update admin.js too (or the other way).
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI, waitForTask } = require('../../../../../src/utils/proxmox');
const tailscale = require('../../../../../src/utils/tailscale');

// ─── Constants (mirror admin.js) ────────────────────────────────────────────
const V2_LANE_GATEWAY_VMID = 1694;
const V3_LANE_GATEWAY_VMID = 1695;
const V3_INTERNAL_TAG_OFFSET = 4000000;
const ATTACK_BOX_VMID_OFFSET = 700000;
const KALI_TEMPLATE_VMID = 1699;

const V2_LAB_NETWORK = {
  bridge: 'vmbr0',
  vlanTag: 60,
  subnetBase: '100.100.60',
  gateway: '100.100.60.1',
  cidr: '/24'
};

// v1 per-module transit gateways. Only crucible is live today.
const TRANSIT_BY_MODULE = {
  crucible: { bridge: 'crucible', gateway: '100.102.0.1', subnetBase: '100.102', cidr: '/16' }
};

// ─── Subnet math ────────────────────────────────────────────────────────────

function laneUplinkConfig(module, vxlanId) {
  const t = TRANSIT_BY_MODULE[module];
  if (!t) {
    throw new Error(`No transit gateway configured for module '${module}'. ` +
      `Configured modules: ${Object.keys(TRANSIT_BY_MODULE).join(', ')}`);
  }
  const high = (vxlanId >> 8) & 0xFF;
  const low  = vxlanId & 0xFF;
  return { bridge: t.bridge, ip: `${t.subnetBase}.${high}.${low}${t.cidr}`, gw: t.gateway };
}

function v2WanConfig(vxlanId) {
  const offset = 10 + (vxlanId % 240);
  return {
    bridge:  V2_LAB_NETWORK.bridge,
    vlanTag: V2_LAB_NETWORK.vlanTag,
    ip:      `${V2_LAB_NETWORK.subnetBase}.${offset}${V2_LAB_NETWORK.cidr}`,
    gw:      V2_LAB_NETWORK.gateway
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
  return {
    wan: laneUplinkConfig(module, vxlanId),
    lan: { base3: '192.18.0', cidr: '192.18.0.0/24', gatewayIp: '192.18.0.1', netmask24: '255.255.255.0' }
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
