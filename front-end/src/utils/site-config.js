/**
 * ============================================================================
 * SITE CONFIG LOADER
 * Single reader for config/site.json. All code that needs cluster node names,
 * scheduling thresholds, or networking topology should import from here rather
 * than hardcoding values.
 * ============================================================================
 */

const path = require('path');
const fs   = require('fs');
const { ipToInt, intToIp, parseCidr, ipInCidr } = require('./ipv4');

// Resolves in both layouts. In the container the app lives at /app, so this
// clamps at the filesystem root and lands on /config/site.json — where
// docker-compose mounts ./config/site.json. In a host checkout it lands on
// <repo>/config/site.json. (One more `../` also works in the container, for the
// same clamping reason, but walks above the repo root on a host checkout.)
const CONFIG_PATH = path.resolve(__dirname, '../../../config/site.json');

let _cache = null;
// mtime of the file at the moment _cache was populated. The cache is never
// invalidated (deliberately - nothing reading config mid-deploy should shift
// underneath itself), so an operator who edits site.json and does not restart
// gets no feedback at all. Recording this lets the audit SAY so.
let _cacheMtimeMs = null;

function getConfig() {
  if (!_cache) {
    _cache = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    try { _cacheMtimeMs = fs.statSync(CONFIG_PATH).mtimeMs; } catch (_) { _cacheMtimeMs = null; }
  }
  return _cache;
}

/**
 * The raw name -> management IP map. getClusterNodes() returns only the keys,
 * but node-drift reporting needs the addresses to tell a node that is missing
 * from one that is merely mis-addressed.
 */
function getPhysicalClusterIps() {
  return getConfig().cluster?.physical_cluster_ips || {};
}

/**
 * Whether the site.json on disk has moved on from the copy this process parsed.
 *
 * Two ways this reads stale, with different fixes:
 *   - mtime advanced: the app needs a restart to see the edit.
 *   - mtime unchanged after an edit: the editor wrote-and-renamed, replacing the
 *     inode, and the single-file :ro bind mount is still serving the OLD file to
 *     the container. A restart will not help - it has to be edited IN PLACE.
 */
function getConfigFreshness() {
  getConfig();
  let diskMtimeMs = null;
  try { diskMtimeMs = fs.statSync(CONFIG_PATH).mtimeMs; } catch (_) {}
  return {
    config_path: CONFIG_PATH,
    config_mtime: diskMtimeMs ? new Date(diskMtimeMs).toISOString() : null,
    config_loaded_mtime: _cacheMtimeMs ? new Date(_cacheMtimeMs).toISOString() : null,
    config_stale_in_memory: !!(diskMtimeMs && _cacheMtimeMs && diskMtimeMs > _cacheMtimeMs),
  };
}

/** All node names declared in physical_cluster_ips, in definition order. */
function getClusterNodes() {
  return Object.keys(getConfig().cluster?.physical_cluster_ips || {});
}

/**
 * The management IP for a cluster node, from physical_cluster_ips, or null
 * when the node isn't declared there.
 *
 * Exists because Proxmox identifies nodes by NAME ('cyberhub-node-2') while the
 * orchestrator runs in a container whose resolvers are 1.1.1.1 and the lab DNS —
 * neither of which resolves those names. Anything opening a socket to a node
 * (node-ssh) must translate through this map rather than trust DNS.
 */
function getNodeAddress(node) {
  const details = getConfig().cluster?.physical_cluster_ips || {};
  const addr = details[node];
  return (typeof addr === 'string' && addr.trim()) ? addr.trim() : null;
}

/**
 * Last-resort fallback node for template resolution.
 * Used only when cybercore_template_catalog.node is null AND Proxmox is unreachable.
 * Real source of truth is cybercore_template_catalog, populated by syncVmTemplateNodes().
 */
function getDefaultTemplateNode() {
  const nodes = getClusterNodes();
  return nodes[nodes.length - 1] || 'cyberhub-node-0';
}

/**
 * Cluster scheduling thresholds and concurrency limits.
 * Returns the cluster.scheduling block with safe defaults if any key is absent.
 */
function getSchedulingConfig() {
  const s = getConfig().cluster?.scheduling || {};
  return {
    min_free_mem_gb:      s.min_free_mem_gb      ?? 8,
    min_free_disk_gb:     s.min_free_disk_gb     ?? 20,
    max_concurrent_lanes: s.max_concurrent_lanes ?? 5,
    max_concurrent_clones:s.max_concurrent_clones?? 4,
    node_score_weights:   s.node_score_weights   ?? { cpu: 0.35, mem: 0.55, disk: 0.10 }
  };
}

/**
 * All module network configs keyed by module name (e.g. 'crucible').
 * Each entry: { bridge, gateway, subnet_base, cidr }
 * Entries with null gateway are declared but not yet wired.
 */
function getModuleNetworks() {
  return getConfig().cluster?.networking?.module_networks || {};
}

/**
 * Network config for a single module's v1 transit gateway.
 * Returns null if the module has no entry or its gateway is not yet configured.
 */
function getModuleNetwork(moduleName) {
  const net = getModuleNetworks()[moduleName];
  if (!net || !net.gateway) return null;
  return net;
}

/**
 * v2 lab (transit) network — the shared VLAN every v2/v3 lane gateway's wan0
 * lands on. One address per LIVE lane, so the prefix is the hard ceiling on
 * concurrent lanes.
 *
 * The block is declared under `subnet` as a real CIDR. `cidr` is NOT that key:
 * it has always meant the prefix SUFFIX that gets string-concatenated onto an
 * address (`${subnet_base}.${octet}${cidr}` — lane-networking.js), and putting a
 * block in it renders `ip=100.100.60.32100.100.60.0/22` on a gateway's net0.
 * It stays, derived, with its old meaning.
 *
 * The legacy shape { subnet_base, cidr } is still accepted and synthesizes
 * `subnet`, so a config/site.json that predates this function needs no edit.
 */
function getV2LabNetwork() {
  const n = getConfig().cluster?.networking?.v2_lab_network || {};

  const legacyBase   = n.subnet_base || '100.100.60';
  const legacySuffix = n.cidr        || '/24';
  const subnet       = n.subnet      || `${legacyBase}.0${legacySuffix}`;

  const { network, prefixLen, broadcast, lastHost } = parseCidr(subnet);
  if (prefixLen > 30) {
    throw new Error(
      `cluster.networking.v2_lab_network.subnet '${subnet}' is a /${prefixLen} — ` +
      `too small to hold any lane. Use /30 or wider.`
    );
  }

  const gateway = n.gateway || intToIp(ipToInt(network) + 1);
  if (!ipInCidr(gateway, subnet)) {
    throw new Error(
      `cluster.networking.v2_lab_network.gateway ${gateway} is outside subnet ${subnet}. ` +
      `Every lane gateway is configured with gw=${gateway}; a gateway off-subnet makes ` +
      `every lane unreachable.`
    );
  }

  // Historical floor: the pre-allocator derivation started at <base>.10 and every
  // lane deployed to date sits at or above it. Defaulting here means widening the
  // prefix never moves an address that is already on the wire.
  const first = n.host_range?.first || intToIp(ipToInt(network) + 10);
  const last  = n.host_range?.last  || lastHost;
  if (ipToInt(first) > ipToInt(last) || !ipInCidr(first, subnet) || !ipInCidr(last, subnet)) {
    throw new Error(
      `cluster.networking.v2_lab_network.host_range ${first}–${last} is empty or falls ` +
      `outside ${subnet}.`
    );
  }

  const vlanTag = n.vlan_tag ?? 60;

  return {
    bridge:   n.bridge || 'vmbr0',
    vlan_tag: vlanTag,

    subnet,                                                // '100.100.60.0/22'
    network,                                               // '100.100.60.0'
    broadcast,                                             // '100.100.63.255'
    prefix_len: prefixLen,                                 // 22
    cidr:       `/${prefixLen}`,                           // '/22' — net0 suffix, legacy meaning
    subnet_base: network.split('.').slice(0, 3).join('.'), // legacy, derived; allocation no longer uses it
    gateway,

    host_range: { first, last },
    // Never handed out. Network and broadcast are ordinary host addresses inside
    // a /22, but plenty of gear dislikes them, so they are excluded by default.
    reserved: [...new Set([
      gateway, network, broadcast,
      ...(Array.isArray(n.reserved) ? n.reserved : []),
    ])],

    probe: {
      enabled:    n.probe?.enabled !== false,
      node:       n.probe?.node      || null,   // null = auto-pick from getClusterNodes()
      interface:  n.probe?.interface || `vmbr0.${vlanTag}`,
      timeout_ms: n.probe?.timeout_ms ?? 2000,
    },
  };
}

/**
 * v1 shared lane LAN subnet (the same /24 is used inside every v1 lane,
 * isolated by the lane gateway LXC).
 */
function getV1LanSubnet() {
  const s = getConfig().cluster?.networking?.v1_lane_subnet || {};
  return {
    base3:      s.base3      || '192.18.0',
    cidr:       s.cidr       || '192.18.0.0/24',
    gateway_ip: s.gateway_ip || '192.18.0.1',
    netmask24:  s.netmask24  || '255.255.255.0'
  };
}

module.exports = {
  getConfig,
  getClusterNodes,
  getPhysicalClusterIps,
  getConfigFreshness,
  getNodeAddress,
  getDefaultTemplateNode,
  getSchedulingConfig,
  getModuleNetworks,
  getModuleNetwork,
  getV2LabNetwork,
  getV1LanSubnet
};
