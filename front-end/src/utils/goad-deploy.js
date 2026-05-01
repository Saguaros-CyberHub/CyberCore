/**
 * ============================================================================
 * GOAD-Light per-lane orchestration helpers
 * ============================================================================
 * When a challenge spec has `spec.goad.enabled === true`, the standard deploy
 * flow keeps doing what it always does (clone gateway + clone the 3 Windows
 * VMs from spec.vms). This module adds the GOAD-specific layers ON TOP:
 *
 *   1. prepareGoadSpec()         — decorates spec.vms with deterministic MACs
 *                                   so the gateway's DHCP server can hand out
 *                                   reserved IPs (DC01=.10, DC02=.11, etc.)
 *   2. buildLaneNet0()           — builds the net0 string for a lane VM with
 *                                   optional macaddr (used by both qemu/lxc
 *                                   clone paths in admin.js)
 *   3. writeDhcpReservations()   — pushes a per-lane reservations file into
 *                                   the gateway's dnsmasq and reloads it
 *   4. deployController()        — clones LXC template 1700 onto the lane
 *   5. waitForWinRM()            — polls 5985 on each Windows VM from inside
 *                                   the controller until they all answer
 *   6. runGoadPlaybook()          — pct exec /opt/goad-light/run.sh
 *   7. stopController()          — final shutdown so the box isn't reachable
 *                                   while students are attacking the lane
 *
 * Normal (non-GOAD) lanes are completely unaffected — none of this runs unless
 * `spec.goad?.enabled` is true.
 * ============================================================================
 */

// Template VMID for the GOAD ansible controller (Debian 13 LXC, baked from
// scripts/bake-goad-controller.sh — git-clones upstream GOAD inside it)
const CONTROLLER_TEMPLATE_VMID = 1700;

// Lane subnet — every GOAD lane uses 192.18.0.0/24 with gateway at .1.
// Last octets per role are anchored to upstream GOAD's Proxmox provider
// inventories so upstream playbooks work unmodified.
const LANE_SUBNET = '192.18.0';
const ip = (octet) => `${LANE_SUBNET}.${octet}`;

// Per-lab topology. Each entry maps the lab name (matches upstream's
// ad/<name>/ directory + playbooks.yml key) to its VM list. `ipOctet`
// values mirror upstream's providers/proxmox/inventory exactly.
//
// Adding a new lab: copy the relevant ad/<name>/providers/proxmox/inventory
// values and create an entry here. The bake script (run.sh) reads the
// playbook chain from upstream's playbooks.yml at deploy time, so we don't
// need to track that here.
const GOAD_LABS = {
  'GOAD-Light': {
    displayName:  'GOAD-Light (3 Win VMs, 2 domains)',
    description:  'Lighter GOAD without Essos forest. Recommended starter.',
    forestRoot:   'sevenkingdoms.local',
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'DC02',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' }
    ]
  },
  'GOAD': {
    displayName:  'GOAD — full (5 Win VMs, 3 domains, 2 forests)',
    description:  'Full GOAD lab with cross-forest scenarios (Essos). Heaviest variant.',
    forestRoot:   'sevenkingdoms.local',
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'DC02',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'DC03',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 12, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' },
      { name: 'SRV03', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 23, nic_model: 'e1000' }
    ]
  },
  'GOAD-Mini': {
    displayName:  'GOAD-Mini (1 Win VM, single domain)',
    description:  'Minimal AD lab — just DC01. Fastest to deploy (~10 min).',
    forestRoot:   'sevenkingdoms.local',
    vms: [
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' }
    ]
  },
  'NHA': {
    displayName:  'NHA — No Hope Alpha (5 Win VMs, 2 domains)',
    description:  'Multi-server cross-domain lab without child domain (uses trusts).',
    forestRoot:   'north.sevenkingdoms.local',
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'DC02',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'SRV01', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 21, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' },
      { name: 'SRV03', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 23, nic_model: 'e1000' }
    ]
  },
  'SCCM': {
    displayName:  'SCCM Lab (3 Win servers + 1 workstation)',
    description:  'SCCM/MECM lab with PXE, client deployment. Long runtime (~60 min).',
    forestRoot:   'sccm.lab',
    vms: [
      { name: 'DC01',  role: 'dc',          os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 40, nic_model: 'e1000' },
      { name: 'SRV01', role: 'member',      os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 41, nic_model: 'e1000' },
      { name: 'SRV02', role: 'member',      os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 42, nic_model: 'e1000' },
      { name: 'WS01',  role: 'workstation', os: 'Windows 11',          template_vmid: 1002, ipOctet: 43, nic_model: 'e1000' }
    ]
  },
  'DRACARYS': {
    displayName:  'DRACARYS (2 Win + 1 Linux VM)',
    description:  'Mixed Win+Linux lab. LX01 uses Ubuntu template (VMID 1003).',
    forestRoot:   'dracarys.lab',
    vms: [
      { name: 'DC01',  role: 'dc',     os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
      { name: 'SRV01', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
      { name: 'LX01',  role: 'linux',  os: 'Ubuntu',              template_vmid: 1003, ipOctet: 12, nic_model: 'virtio' }
    ]
  }
};

// Reserved infrastructure IPs (apply to every lab; never collide with lab VMs).
const INFRA_IP_OCTETS = {
  gateway:    1,
  controller: 5,
  Kali:       20
};

/**
 * Return the lab definition or throw if unknown.
 */
function getLab(labName) {
  const lab = GOAD_LABS[labName];
  if (!lab) {
    throw new Error(`Unknown GOAD lab '${labName}'. Known: ${Object.keys(GOAD_LABS).join(', ')}`);
  }
  return lab;
}

/**
 * Default lab when spec.goad.version is missing (back-compat with earlier
 * specs that only had goad.enabled=true).
 */
const DEFAULT_LAB = 'GOAD-Light';

/**
 * Build a deterministic locally-administered MAC from an IP last octet.
 * Format: 02:00:CC:HH:LL:RR
 *   02      — locally-administered (and unicast)
 *   00:CC   — fixed marker for "this is a CyberHub-managed MAC"
 *   HH:LL   — vxlanId high/low bytes (uniqueness across lanes)
 *   RR      — IP last octet (matches the static IP for trivial reservation lookup)
 */
function macForOctet(ipOctet, vxlanId) {
  const hi = (vxlanId >> 8) & 0xFF;
  const lo = vxlanId & 0xFF;
  const hex = (n) => n.toString(16).padStart(2, '0').toUpperCase();
  return `02:00:CC:${hex(hi)}:${hex(lo)}:${hex(ipOctet & 0xFF)}`;
}

/**
 * Back-compat shim: old call sites used macFor('controller'|'DC01'|...).
 * Resolves the role via INFRA_IP_OCTETS first, then falls back to
 * GOAD-Light's VM list (the original default).
 */
function macFor(role, vxlanId) {
  if (INFRA_IP_OCTETS[role] !== undefined) return macForOctet(INFRA_IP_OCTETS[role], vxlanId);
  const lab = GOAD_LABS[DEFAULT_LAB];
  const vm = lab.vms.find(v => v.name === role);
  if (!vm) throw new Error(`Unknown GOAD role for MAC derivation: ${role}`);
  return macForOctet(vm.ipOctet, vxlanId);
}

/**
 * Build a per-lane MAC/IP/role lookup table for the GOAD VMs in spec.vms.
 * Pure function: never mutates `spec`. Caller invokes once per lane (passing
 * that lane's vxlanId) and uses the returned map when building net0 strings
 * and DHCP reservations.
 *
 * Returns: { '<vmName>': { mac, static_ip, role, nic_model }, ... }
 *
 * Lab is selected by spec.goad.version (defaults to GOAD-Light). VMs whose
 * name doesn't match a known role in that lab fall through to dynamic DHCP.
 */
function prepareGoadMacs(spec, vxlanId) {
  if (!spec?.goad?.enabled) return {};
  if (!Array.isArray(spec.vms)) return {};

  const labName = spec.goad.version || DEFAULT_LAB;
  const lab = GOAD_LABS[labName];
  if (!lab) {
    console.warn(`[GOAD] Unknown lab version '${labName}' — falling back to ${DEFAULT_LAB}`);
  }
  const labDef = lab || GOAD_LABS[DEFAULT_LAB];

  const byName = Object.fromEntries(labDef.vms.map(v => [v.name.toLowerCase(), v]));

  const out = {};
  for (const vm of spec.vms) {
    if (!vm?.name) continue;
    const labVm = byName[vm.name.toLowerCase()];
    if (!labVm) continue;
    out[vm.name] = {
      mac:        macForOctet(labVm.ipOctet, vxlanId),
      static_ip:  ip(labVm.ipOctet),
      role:       labVm.role,
      nic_model:  labVm.nic_model || 'e1000'
    };
  }
  return out;
}

/**
 * Build the net0 string for a lane VM clone. Centralizes the optional macaddr
 * suffix so admin.js's three deploy paths can share one helper.
 *
 * The 4th arg `nicModel` (when provided by prepareGoadMacs) overrides the
 * default. Upstream GOAD documents that AD-joining Windows VMs MUST use
 * e1000; virtio breaks the domain join. Linux VMs (DRACARYS LX01) work on
 * virtio. Non-GOAD lanes default to virtio as before.
 */
function buildLaneNet0(vmSpec, vnetName, mac, nicModel) {
  const macStr = mac || vmSpec?.mac;
  if ((vmSpec?.type || 'qemu') === 'lxc') {
    return `name=lan0,bridge=${vnetName}` + (macStr ? `,hwaddr=${macStr}` : '');
  }
  const model = nicModel || vmSpec?.nic_model || 'virtio';
  return `${model},bridge=${vnetName}` + (macStr ? `,macaddr=${macStr}` : '');
}

/**
 * Write the per-lane DHCP reservations file inside the lane gateway and
 * reload dnsmasq. Called AFTER the gateway is started.
 *
 * Reads spec.vms (decorated by prepareGoadSpec) plus the controller's static
 * IP, emits a single dnsmasq config snippet at /etc/dnsmasq.d/lane-reservations.conf
 * inside the gateway LXC.
 */
async function writeDhcpReservations({ gatewayVmId, bestNode, spec, vxlanId, proxmoxAPI }) {
  if (!spec?.goad?.enabled) return;

  const labName = spec.goad.version || DEFAULT_LAB;
  const lines = [`# GOAD-${labName} lane DHCP reservations — generated by goad-deploy.js`];

  // Controller — always (every lab uses one)
  lines.push(`dhcp-host=${macForOctet(INFRA_IP_OCTETS.controller, vxlanId)},${ip(INFRA_IP_OCTETS.controller)},goad-controller`);

  // Optional Kali (always pinned to .20 across all labs)
  if (spec.goad.include_kali !== false) {
    lines.push(`dhcp-host=${macForOctet(INFRA_IP_OCTETS.Kali, vxlanId)},${ip(INFRA_IP_OCTETS.Kali)},kali`);
  }

  // Lab VMs
  const macs = prepareGoadMacs(spec, vxlanId);
  for (const [vmName, info] of Object.entries(macs)) {
    lines.push(`dhcp-host=${info.mac},${info.static_ip},${vmName}`);
  }

  const conf = lines.join('\n') + '\n';

  // pct exec writes the file inside the gateway and HUPs dnsmasq.
  // We use a one-shot here-doc piped into `tee` so the content is delivered
  // as stdin — no shell-quoting hazards.
  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/exec`, {
    command: ['/bin/sh', '-c',
      `cat > /etc/dnsmasq.d/lane-reservations.conf <<'EOF'\n${conf}EOF\n` +
      `rc-service dnsmasq restart || /etc/init.d/dnsmasq restart || true`
    ]
  });
}

/**
 * Clone GOAD controller template (1700) onto the lane VNet.
 * Sets net0 with the controller's deterministic MAC so DHCP gives it .5.
 *
 * Returns the deployed controller VMID.
 */
async function deployController({
  vxlanId, vnetName, bestNode, templateNode, lane, module, proxmoxAPI, waitForTask
}) {
  // Controller VMID range: 200000+vxlanId (lane VMs are at 600000+, gateway at 100000+;
  // 200000 keeps controller IDs unambiguous).
  const controllerVmId = 200000 + vxlanId;
  const mac = macFor('controller', vxlanId);
  const hostname = `goad-ctrl-${vxlanId}`;

  const cloneResult = await proxmoxAPI(
    'POST',
    `/api2/json/nodes/${templateNode}/lxc/${CONTROLLER_TEMPLATE_VMID}/clone`,
    {
      newid: controllerVmId,
      hostname,
      full: 1,
      target: bestNode,
      description: `GOAD controller for lane ${lane.lane_id}\nModule: ${module}\nVXLAN: ${vxlanId}`,
      pool: `${module}-pool`
    }
  );
  if (cloneResult) await waitForTask(templateNode, cloneResult);

  await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${controllerVmId}/config`, {
    net0: `name=eth0,bridge=${vnetName},hwaddr=${mac},type=veth`
  });

  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${controllerVmId}/status/start`);
  return controllerVmId;
}

/**
 * Sleep helper.
 */
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * From inside the controller, TCP-poll port 5985 on each Windows VM until
 * they all answer (WinRM is up). Returns the IPs that responded; throws if
 * timeoutMs elapses before all are ready.
 */
async function waitForWinRM({ controllerVmId, bestNode, vmIPs, proxmoxAPI, timeoutMs = 600000 }) {
  const deadline = Date.now() + timeoutMs;
  const pending = new Set(vmIPs);
  const ready = [];

  while (pending.size > 0 && Date.now() < deadline) {
    for (const ip of [...pending]) {
      try {
        // bash one-liner: "exec 3<>/dev/tcp/IP/5985" succeeds iff port open
        const exec = await proxmoxAPI(
          'POST',
          `/api2/json/nodes/${bestNode}/lxc/${controllerVmId}/exec`,
          {
            command: ['/bin/bash', '-c', `timeout 3 bash -c 'exec 3<>/dev/tcp/${ip}/5985' 2>/dev/null && echo OK`]
          }
        );
        if (exec && (exec.output || exec).toString().includes('OK')) {
          pending.delete(ip);
          ready.push(ip);
          console.log(`[GOAD] WinRM ready on ${ip}`);
        }
      } catch {
        // ignore — will retry
      }
    }
    if (pending.size > 0) await sleep(10000);
  }

  if (pending.size > 0) {
    throw new Error(`WinRM did not come up on: ${[...pending].join(', ')} within ${timeoutMs}ms`);
  }
  return ready;
}

/**
 * Run /opt/goad-light/run.sh inside the controller. Blocks until the playbook
 * finishes (or fails). Returns the captured stdout/stderr.
 *
 * The wrapper inside the controller takes the lab name as the first arg and
 * a comma-separated list of "vmName:ip" pairs as the second. This keeps the
 * shell script simple and supports any lab topology without per-lab args.
 */
async function runGoadPlaybook({ controllerVmId, bestNode, spec, vxlanId, proxmoxAPI }) {
  const goad = spec.goad || {};
  const labName = goad.version || DEFAULT_LAB;
  const adminUser = goad.admin_user || 'Administrator';
  const adminPass = goad.admin_password;
  if (!adminPass) {
    throw new Error('spec.goad.admin_password is required');
  }

  const macs = prepareGoadMacs(spec, vxlanId);
  // host_map = "DC01:192.18.0.10,DC02:192.18.0.11,..."
  const hostMap = Object.entries(macs)
    .map(([name, info]) => `${name}:${info.static_ip}`)
    .join(',');

  // Long-running — give it 90 minutes max. SCCM in particular is slow.
  const result = await proxmoxAPI(
    'POST',
    `/api2/json/nodes/${bestNode}/lxc/${controllerVmId}/exec`,
    {
      command: ['/opt/goad-light/run.sh', labName, hostMap, adminUser, adminPass],
      'timeout': 5400
    }
  );
  return result;
}

/**
 * Stop the controller after the playbook finishes (or fails). Keeps the
 * provisioning credentials off any running box during student session.
 */
async function stopController({ controllerVmId, bestNode, proxmoxAPI }) {
  try {
    await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${controllerVmId}/status/stop`);
  } catch (err) {
    console.warn(`[GOAD] stopController: ${err.message}`);
  }
}

/**
 * Top-level orchestrator. Call AFTER the gateway and the 3 Windows VMs
 * (and optional Kali) have been cloned + started by the normal deploy path.
 *
 * Sequence:
 *   1. writeDhcpReservations  — gateway hands out reserved IPs from now on
 *   2. deployController       — clone 1700, attach to lane, start
 *   3. waitForWinRM           — poll until all 3 Windows VMs respond on 5985
 *   4. runGoadPlaybook        — actual AD provisioning over WinRM
 *   5. stopController         — shut down the controller
 *
 * Throws on any unrecoverable failure. Caller is responsible for catching
 * and updating lane status accordingly.
 */
async function deployGoadLane({
  lane, spec, module, vnet, vxlanId, gatewayVmId, bestNode, templateNode,
  proxmoxAPI, waitForTask, query
}) {
  if (!spec?.goad?.enabled) return null;

  console.log(`[GOAD] Starting GOAD-Light provisioning for lane ${lane.lane_id} (vxlan ${vxlanId})`);

  // 1. DHCP reservations on the gateway
  await writeDhcpReservations({ gatewayVmId, bestNode, spec, vxlanId, proxmoxAPI });
  console.log(`[GOAD] DHCP reservations written to gateway ${gatewayVmId}`);

  // 2. Deploy controller
  const controllerVmId = await deployController({
    vxlanId, vnetName: vnet.vnet, bestNode, templateNode, lane, module, proxmoxAPI, waitForTask
  });
  console.log(`[GOAD] Controller deployed: VMID ${controllerVmId}`);

  // Give controller + Windows VMs time to boot. Windows is slow (60-180s typical)
  // and WinRM service starts after first boot. We poll, so an over-sleep here
  // just shifts when polling starts — pick something modest.
  await sleep(60000);

  // 3. Wait for WinRM on every Windows VM in this lab (skip Linux)
  const macs = prepareGoadMacs(spec, vxlanId);
  const labName = spec.goad.version || DEFAULT_LAB;
  const labDef = GOAD_LABS[labName] || GOAD_LABS[DEFAULT_LAB];
  const winrmIPs = labDef.vms
    .filter(v => v.role !== 'linux')                  // Linux VMs don't run WinRM
    .map(v => macs[v.name]?.static_ip)
    .filter(Boolean);
  if (winrmIPs.length > 0) {
    await waitForWinRM({ controllerVmId, bestNode, vmIPs: winrmIPs, proxmoxAPI });
    console.log(`[GOAD] WinRM up on ${winrmIPs.length} Windows VM(s)`);
  }

  // 4. Run the playbook
  let playbookResult;
  let provisioningError = null;
  try {
    playbookResult = await runGoadPlaybook({ controllerVmId, bestNode, spec, vxlanId, proxmoxAPI });
    console.log(`[GOAD] Playbook completed for lane ${lane.lane_id}`);
  } catch (err) {
    provisioningError = err.message;
    console.error(`[GOAD] Playbook failed for lane ${lane.lane_id}: ${err.message}`);
  }

  // 5. Stop the controller (success or failure — credentials stay off the wire)
  await stopController({ controllerVmId, bestNode, proxmoxAPI });
  console.log(`[GOAD] Controller stopped: VMID ${controllerVmId}`);

  // Persist GOAD provisioning result on the lane record (clinic_db)
  if (query) {
    try {
      await query(
        `UPDATE cybercore_lane
         SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb,
             updated_at = NOW()
         WHERE lane_id = $2`,
        [
          JSON.stringify({
            goad: {
              controller_vmid: controllerVmId,
              status: provisioningError ? 'failed' : 'provisioned',
              error: provisioningError,
              provisioned_at: new Date().toISOString()
            }
          }),
          lane.lane_id
        ]
      );
    } catch (dbErr) {
      console.warn(`[GOAD] Failed to persist metadata: ${dbErr.message}`);
    }
  }

  if (provisioningError) {
    throw new Error(`GOAD provisioning failed: ${provisioningError}`);
  }
  return { controllerVmId, playbookResult };
}

module.exports = {
  // High-level
  deployGoadLane,
  // Per-lane MAC/IP lookup table (called from admin.js once per lane)
  prepareGoadMacs,
  // Net0 string builder (called from admin.js inside the VM clone loop)
  buildLaneNet0,
  // Lower-level pieces (exposed for testability and partial flows)
  writeDhcpReservations,
  deployController,
  waitForWinRM,
  runGoadPlaybook,
  stopController,
  macFor,
  macForOctet,
  // Lab catalog (also surfaced via API endpoint for the admin UI)
  GOAD_LABS,
  DEFAULT_LAB,
  INFRA_IP_OCTETS,
  LANE_SUBNET,
  getLab,
  CONTROLLER_TEMPLATE_VMID
};
