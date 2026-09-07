'use strict';

const net = require('node:net');
const { laneEligible, targetsFor } = require('./caldera-lane-agents');
const { isMalwareLane } = require('./malware-analysis-state');
const { managerHostname } = require('./wazuh-client');

const TAG = 'CYBERCORE-WAZUH';
const HOOK = '/etc/local.d/98-cybercore-wazuh.start';
const SENTINEL = 'CYBERCORE_WAZUH_GATEWAY_READY';
const ERROR = 'CYBERCORE_WAZUH_GATEWAY_ERROR:';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const NAME = /^[a-zA-Z0-9_.-]+$/;
const object = value => typeof value === 'string' ? JSON.parse(value) : (value || {});
const pendingGateways = new Map();
function failure(message) { return Object.assign(new Error(message), { status: 409, safe: true }); }
function ipv4(value) {
  return typeof value === 'string' && net.isIP(value) === 4
    && !/^(0|127|22[4-9]|23\d|24\d|25[0-5])\./.test(value)
    && value !== '255.255.255.255';
}
function fields(value) {
  return Object.fromEntries(String(value || '').split(',').map(part => {
    const i = part.indexOf('='); return [part.slice(0, i), part.slice(i + 1)];
  }));
}

// Authoritative lane membership plus the gateway's deployment description and
// actual NIC bridges must agree. Never infer gateway ownership from a VMID alone.
function validateLane(lane, vmId, manager) {
  const cfg = object(lane?.config);
  if (!UUID.test(lane?.lane_id || '') || !laneEligible(lane)
      || !targetsFor(lane).some(vm => vm.vm_id === vmId)) {
    throw failure('The VM is no longer in an available lane. Refresh and retry.');
  }
  if (isMalwareLane(cfg) || cfg.internet_enabled === false) {
    throw failure('Wazuh gateway access cannot change an isolated or malware analysis lane.');
  }
  if (typeof manager !== 'string' || managerHostname(manager) !== manager
      || (net.isIP(manager) && !ipv4(manager))) {
    throw failure('Automatic Wazuh gateway access requires a unicast IPv4 manager or its DNS hostname.');
  }
  const ids = [cfg.gateway_vm_id, cfg.gateway_vmid].filter(id => id != null).map(Number);
  if (!ids.length || ids.some(id => !Number.isSafeInteger(id) || id < 100 || id !== ids[0])
      || (lane.vxlan_id != null && ids[0] !== 100000 + Number(lane.vxlan_id))) {
    throw failure('The lane gateway identity could not be verified. Review its saved gateway configuration.');
  }
  const scheme = cfg.subnet_scheme;
  if (!['v1', 'v2', 'v3'].includes(scheme) || typeof cfg.vnet !== 'string' || !NAME.test(cfg.vnet)
      || (scheme === 'v3' && (typeof cfg.vnet_internal !== 'string'
        || !NAME.test(cfg.vnet_internal) || cfg.vnet_internal === cfg.vnet))) {
    throw failure('The lane gateway network layout could not be verified.');
  }
  return { lane, cfg, vmId, manager, gatewayVmid: ids[0], scheme };
}

function validateGateway(request, gateway, gatewayConfig, guest, guestConfig) {
  if (!gateway || gateway.type !== 'lxc' || gateway.template || gateway.status !== 'running'
      || typeof gateway.node !== 'string' || !NAME.test(gateway.node)
      || !guest || guest.type !== 'qemu' || guest.template || guest.status !== 'running') {
    throw failure('The selected VM and its verified lane gateway must both be running.');
  }
  const description = String(gatewayConfig.description || '').split(/\r?\n/);
  if (!description.includes(`Lane: ${request.lane.lane_id}`) || gatewayConfig.ostype !== 'alpine'
      || gatewayConfig.template || fields(gatewayConfig.net0).name !== 'wan0') {
    throw failure('The live gateway does not match this lane deployment. No gateway access was changed.');
  }
  const expected = request.scheme === 'v3'
    ? [['net1', 'ext0', request.cfg.vnet], ['net2', 'int0', request.cfg.vnet_internal]]
    : [['net1', 'lan0', request.cfg.vnet]];
  const segments = expected.map(([key, iface, bridge]) => {
    const nic = fields(gatewayConfig[key]);
    const [ip, prefix] = String(nic.ip || '').split('/');
    if (nic.name !== iface || nic.bridge !== bridge || !ipv4(ip) || prefix !== '24') {
      throw failure('The live gateway interfaces do not match the saved lane network. No gateway access was changed.');
    }
    return { iface, bridge, cidr: `${ip}/24`, subnet: `${ip.split('.').slice(0, 3).join('.')}.0/24` };
  });
  if (Object.keys(gatewayConfig).some(key => /^net\d+$/.test(key) && !['net0', ...expected.map(x => x[0])].includes(key))) {
    throw failure('The lane gateway has an unexpected network interface. Review its network layout before deploying Wazuh.');
  }
  const guestBridges = Object.entries(guestConfig).filter(([key]) => /^net\d+$/.test(key)).map(([, value]) => fields(value).bridge);
  if (!guestBridges.some(bridge => segments.some(segment => segment.bridge === bridge))) {
    throw failure('The VM is not connected to its saved lane gateway network.');
  }
  return { manager: request.manager, gatewayVmid: request.gatewayVmid, node: gateway.node, segments };
}

function validateScope(scope) {
  if (!scope || !ipv4(scope.manager) || !Array.isArray(scope.segments)
      || ![['lan0'], ['ext0', 'int0']].some(names => names.join(',') === scope.segments.map(x => x.iface).join(','))) {
    throw failure('Invalid Wazuh gateway rule scope.');
  }
  for (const segment of scope.segments) {
    const [ip, prefix] = String(segment.cidr).split('/');
    if (!ipv4(ip) || prefix !== '24' || segment.subnet !== `${ip.split('.').slice(0, 3).join('.')}.0/24`) {
      throw failure('Invalid Wazuh gateway subnet.');
    }
  }
  return scope;
}

function ruleFor(scope, segment) {
  return `-s ${segment.subnet} -d ${scope.manager}/32 -i ${segment.iface} -o wan0 -p tcp -m tcp --dport 1514 -m comment --comment ${TAG} -j ACCEPT`;
}

// iptables-save can reorder match arguments. Compare their complete allowed
// meaning, rejecting unknown/duplicate switches, rather than assuming order.
const OWNED_RULE_AUDIT = `function rule(s, n,t,i,k,v,a) {
  gsub(/"/, "", s); n=split(s,t," ");
  for(i=1;i<=n;i+=2) {
    k=t[i]; v=t[i+1];
    if(k=="-m" && (v=="tcp" || v=="comment")) continue;
    if(k!~/^(-A|-s|-d|-i|-o|-p|--dport|--comment|-j)$/ || (k in a) || v=="") return "INVALID";
    a[k]=v;
  }
  return a["-A"] "|" a["-s"] "|" a["-d"] "|" a["-i"] "|" a["-o"] "|" a["-p"] "|" a["--dport"] "|" a["--comment"] "|" a["-j"];
}
NR==FNR { expected[rule($0)]=1; next }
/${TAG}/ { if (!expected[rule($0)]) exit 1 }`;

function renderApply(scope, install) {
  validateScope(scope);
  const rules = scope.segments.map(segment => ruleFor(scope, segment));
  const hook = install ? renderApply(scope, false) : null;
  return '#!/bin/sh\n# Wazuh agent transport only; preserve all other gateway policy.\n'
    + 'set -eu\numask 077\nccw_stage=preflight\nccw_tmp=\nccw_locked=0\n'
    + `trap 'ccw_exit=$?; if [ "$ccw_exit" -ne 0 ]; then printf "${ERROR}%s\\n" "$ccw_stage" >&2; fi; [ -z "$ccw_tmp" ] || rm -rf "$ccw_tmp"; [ "$ccw_locked" -eq 0 ] || rmdir /run/cybercore-wazuh-gateway.lock; exit "$ccw_exit"' EXIT\n`
    + 'ccw_stage=gateway-busy\nmkdir /run/cybercore-wazuh-gateway.lock\nccw_locked=1\n'
    + 'ccw_stage=preflight\nccw_tmp=$(mktemp -d)\n'
    + 'test ! -L /etc/local.d\ntest ! -L /etc/iptables\n'
    + `test ! -L ${HOOK}\ntest ! -L /etc/iptables/rules-save\n`
    + 'ccw_stage=containment-active\n'
    + 'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1\n'
    + 'test ! -e /etc/local.d/99-cybercore-malware.start\n'
    + 'iptables-save > "$ccw_tmp/before"\n'
    + `if grep -Eq 'CYBERCORE-MALWARE|CCMA_LAN' "$ccw_tmp/before"; then exit 1; fi\n`
    + 'ccw_stage=interface-changed\n'
    + scope.segments.map(segment => `ip -4 -o addr show dev ${segment.iface} > "$ccw_tmp/addresses"\n`
      + `awk '$4 == "${segment.cidr}" { found=1 } END { exit !found }' "$ccw_tmp/addresses"\n`).join('')
    + 'ip link show dev wan0 >/dev/null\n'
    + 'ccw_stage=existing-rule-conflict\n'
    + `cat > "$ccw_tmp/expected" <<'CCW_EXPECTED'\n${rules.map(rule => '-A FORWARD ' + rule).join('\n')}\nCCW_EXPECTED\n`
    + `awk '${OWNED_RULE_AUDIT}' "$ccw_tmp/expected" "$ccw_tmp/before"\n`
    + (install ? 'ccw_stage=existing-hook-conflict\n'
      + `cat > "$ccw_tmp/hook" <<'CCW_HOOK'\n${hook}CCW_HOOK\n`
      + `if [ -e ${HOOK} ]; then cmp -s "$ccw_tmp/hook" ${HOOK}; fi\n`
      + 'ccw_stage=persist-hook\nmkdir -p /etc/local.d\nchmod 750 "$ccw_tmp/hook"\n'
      + `cp "$ccw_tmp/hook" /etc/local.d/.cybercore-wazuh.start\nmv /etc/local.d/.cybercore-wazuh.start ${HOOK}\n` : '')
    + 'ccw_stage=apply-rules\n'
    // Moving only our exact rule ensures it precedes v3's boot-time perimeter
    // rules. Never flush a chain or replace the entire running ruleset.
    + rules.map(rule => `while :; do\n  if iptables -w 5 -C FORWARD ${rule} 2>/dev/null; then\n    iptables -w 5 -D FORWARD ${rule}\n`
      + '  else\n    ccw_check=$?\n    [ "$ccw_check" -eq 1 ] || exit "$ccw_check"\n    break\n  fi\ndone\n'
      + `iptables -w 5 -I FORWARD 1 ${rule}\niptables -w 5 -C FORWARD ${rule}\n`).join('')
    + 'ccw_stage=persist-rules\nmkdir -p /etc/iptables\niptables-save > "$ccw_tmp/after"\n'
    + 'cp "$ccw_tmp/after" /etc/iptables/.cybercore-wazuh-rules-save\n'
    + 'mv /etc/iptables/.cybercore-wazuh-rules-save /etc/iptables/rules-save\n'
    + `echo ${SENTINEL}\n`;
}

// Call only with a freshly authorized lane/job. The caller revalidates its job
// again after this operation and before guest execution. No credentials enter
// this script; API enrollment means agents do not need manager TCP 1515.
async function resolveManager(manager, dependencies) {
  if (ipv4(manager)) return manager;
  let timer;
  try {
    const resolve4 = dependencies.resolve4 || require('node:dns').promises.resolve4;
    const addresses = await Promise.race([
      resolve4(manager), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), 5000); }),
    ]);
    const unique = [...new Set(addresses)];
    if (unique.length !== 1 || !ipv4(unique[0])) throw new Error('ambiguous');
    return unique[0];
  } catch (_) {
    throw failure('WAZUH_MANAGER must resolve to one unicast IPv4 address for the lane gateway rule. Check its DNS record or configure the manager IPv4 address.');
  } finally { clearTimeout(timer); }
}

async function serialized(gatewayVmid, run) {
  const previous = pendingGateways.get(gatewayVmid) || Promise.resolve();
  const next = previous.catch(() => {}).then(run);
  pendingGateways.set(gatewayVmid, next);
  try { return await next; }
  finally { if (pendingGateways.get(gatewayVmid) === next) pendingGateways.delete(gatewayVmid); }
}

async function ensureWazuhGatewayAccess({ lane, vmId, manager }, dependencies = {}) {
  const initial = validateLane(lane, vmId, manager);
  return serialized(initial.gatewayVmid, async () => {
    // Batch jobs for one gateway serialize. Reload job/lane ownership after
    // waiting; callers supply their own authorized read/assert callback.
    const currentLane = dependencies.readLane ? await dependencies.readLane() : lane;
    const request = validateLane(currentLane, vmId, manager);
    if (request.gatewayVmid !== initial.gatewayVmid) throw failure('The lane gateway changed while waiting. Refresh and retry.');
    request.manager = await resolveManager(manager, dependencies);
    return applyVerified(request, dependencies, manager);
  });
}

async function applyVerified(request, dependencies, configuredManager) {
  const { vmId } = request;
  const proxmox = dependencies.proxmox || require('./proxmox').proxmoxAPI;
  const pctExec = dependencies.pctExec || require('./node-ssh').pctExec;
  const resources = await proxmox('GET', '/api2/json/cluster/resources?type=vm');
  const gateway = resources?.find(vm => Number(vm.vmid) === request.gatewayVmid);
  const guest = resources?.find(vm => Number(vm.vmid) === vmId);
  if (!gateway || !guest || !NAME.test(gateway.node || '') || !NAME.test(guest.node || '')) {
    throw failure('The selected VM or its lane gateway could not be found in Proxmox.');
  }
  const [gatewayConfig, guestConfig] = await Promise.all([
    proxmox('GET', `/api2/json/nodes/${gateway.node}/lxc/${request.gatewayVmid}/config`),
    proxmox('GET', `/api2/json/nodes/${guest.node}/qemu/${vmId}/config`),
  ]);
  const scope = validateGateway(request, gateway, gatewayConfig, guest, guestConfig);
  const script = renderApply(scope, true);
  if (dependencies.readLane) {
    // DNS and Proxmox reads can take time after the queue guard. The caller's
    // callback must verify job ownership once more immediately before mutation.
    const refreshed = validateLane(await dependencies.readLane(), vmId, configuredManager);
    if (refreshed.lane.lane_id !== request.lane.lane_id || refreshed.gatewayVmid !== request.gatewayVmid
        || refreshed.scheme !== request.scheme || refreshed.cfg.vnet !== request.cfg.vnet
        || refreshed.cfg.vnet_internal !== request.cfg.vnet_internal) {
      throw failure('The lane gateway network changed during verification. Refresh and retry.');
    }
  }
  let result;
  try {
    result = await pctExec(scope.node, scope.gatewayVmid, ['/bin/sh', '-c', script], { timeoutMs: 30000 });
  } catch (error) {
    const marker = String(error.stderr || '').match(/CYBERCORE_WAZUH_GATEWAY_ERROR:([a-z-]+)/)?.[1];
    if (marker === 'containment-active') throw failure('The gateway has active isolation or forwarding is disabled. Wazuh access was not opened.');
    if (marker === 'existing-rule-conflict' || marker === 'existing-hook-conflict') {
      throw failure('The gateway already has different Wazuh access settings. Review them before retrying.');
    }
    throw failure('Could not prepare Wazuh TCP 1514 access on the lane gateway. Check gateway SSH access and firewall configuration.');
  }
  if (result?.code !== 0 || !String(result.stdout || '').split(/\r?\n/).includes(SENTINEL)) {
    throw failure('The lane gateway did not confirm Wazuh TCP 1514 access. Review its firewall configuration.');
  }
  return { gatewayVmid: scope.gatewayVmid, node: scope.node, manager: scope.manager, interfaces: scope.segments.map(x => x.iface) };
}

module.exports = { ensureWazuhGatewayAccess, validateLane, validateGateway, renderApply, TAG, HOOK, SENTINEL };
