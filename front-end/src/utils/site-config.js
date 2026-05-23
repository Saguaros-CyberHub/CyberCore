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

const CONFIG_PATH = path.resolve(__dirname, '../../../../config/site.json');

let _cache = null;

function getConfig() {
  if (!_cache) {
    _cache = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  }
  return _cache;
}

/** All node names declared in physical_cluster_details, in definition order. */
function getClusterNodes() {
  return Object.keys(getConfig().cluster?.physical_cluster_details || {});
}

/**
 * Last-resort fallback node for template resolution.
 * Used only when vm_template_catalog.node is null AND Proxmox is unreachable.
 * Real source of truth is vm_template_catalog, populated by syncVmTemplateNodes().
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
 * v2 lab network config (bridge, vlan_tag, subnet_base, gateway, cidr).
 */
function getV2LabNetwork() {
  const n = getConfig().cluster?.networking?.v2_lab_network || {};
  return {
    bridge:      n.bridge      || 'vmbr0',
    vlan_tag:    n.vlan_tag    ?? 60,
    subnet_base: n.subnet_base || '100.100.60',
    gateway:     n.gateway     || '100.100.60.1',
    cidr:        n.cidr        || '/24'
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
  getDefaultTemplateNode,
  getSchedulingConfig,
  getModuleNetworks,
  getModuleNetwork,
  getV2LabNetwork,
  getV1LanSubnet
};
