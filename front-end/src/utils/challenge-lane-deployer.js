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
 *     the files.
 * ============================================================================
 */

const crypto = require('crypto');

const { proxmoxAPI, waitForTask, findTemplateNode } = require('./proxmox');
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
const laneDeployer = require('./lane-deployer');
const nodeSsh = require('./node-ssh');
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

/** The Kali login for a user: their email local-part, plus a password. */
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
  const { laneId, user, vxlanId, vnet, vnetInt, laneName, targetNode } = job;
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

  const net = resolveLaneNetworking(subnetScheme, moduleKey, vxlanId);
  // Pre-baked ("GOAD-Like") lanes pin a fixed subnet so the gateway's ext0/int0
  // land on the same base the golden-image AD was baked on.
  if (spec.goad?.prebaked && spec.goad?.fixed_subnet) {
    applyFixedSubnet(net, subnetScheme === 'v3', spec.goad.fixed_subnet.int, spec.goad.fixed_subnet.ext);
  }

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
  const { nets, dualHomed } = resolveVmNics(vmSpec, {
    subnetScheme,
    bridges: resolveSegmentBridges(subnetScheme, vnetExtName, vnetIntName),
    goadMac: goadVm?.mac,
    goadVm,
    isGoadVm,
  });

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
          ipconfig0:  `ip=${net.lanExt.base3}.240/24,gw=${net.lanExt.gatewayIp}`,
          ipconfig1:  `ip=${net.lanInt.base3}.240/24`,
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
 * Best-effort by design: it needs a shell inside the gateway LXC over SSH
 * (Proxmox has no LXC exec API). If that isn't configured the lane still comes
 * up, so this logs loudly rather than failing the deploy.
 */
async function writeLaneReservations({
  gatewayVmId, node, vxlanId, goadMacs, attackBoxOctet,
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
  if (liveGoadController) {
    const octet = goadDeploy.INFRA_IP_OCTETS.controller;
    lines.push(`dhcp-host=${goadDeploy.macForOctet(octet, vxlanId)},${intSubnetBase}.${octet},goad-controller`);
  }
  // GOAD lab hosts (DC01/DC02/SRV01/…). prepareGoadMacs already resolved each
  // one's deterministic MAC and its static IP on the internal segment.
  for (const [vmName, info] of Object.entries(goadMacs || {})) {
    lines.push(`dhcp-host=${info.mac},${info.static_ip},${vmName}`);
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
    console.log(`${logTag} Lane ${laneId}: ${lines.length - 3} DHCP reservation(s) written`);
  } catch (err) {
    // A dead DHCP server is not survivable — every guest on this lane would sit
    // without an address. Anything else (no SSH channel, for instance) leaves the
    // gateway's baked reservation in place, so the lane is degraded but usable.
    if (err.noFallback) throw err;
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
 * Create the Kali RDP connection and grant it to the owner + any instructors.
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
async function createAttackBoxConsole({ connName, hostname, creds, user, guacParent, instructorEmails, logTag }) {
  await guacCreds.ensureGuacUser(user.id, user.email).catch((e) =>
    console.warn(`${logTag} Could not ensure a Guacamole account for ${user.email}: ${e.message}`));

  const connBody = {
    name: connName,
    protocol: 'rdp',
    parentIdentifier: guacParent || 'ROOT',
    parameters: {
      hostname,
      port: '3389',
      username: creds.username,
      password: creds.password,
      security: 'any',
      'ignore-cert': 'true',
      // Without server-layout the Guac UI shows "Keyboard layout" as unset and
      // keystrokes never reach xrdp. en-us-qwerty matches the default xrdp
      // keymap on Kali.
      'server-layout': 'en-us-qwerty',
      'enable-wallpaper': 'true',
      'enable-theming': 'true',
      'enable-font-smoothing': 'true',
      'enable-full-window-drag': 'true',
      'color-depth': '24',
      'resize-method': 'display-update',
    },
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
    laneId, user, vxlanId, vnet, vnetInt, targetNode, attackBoxCreds,
  } = job;
  const {
    spec, subnetScheme, moduleKey, challengeKey, attackBoxes, vulnScripts,
    laneConfig, guacParent, instructorEmails, progress, logTag,
  } = ctx;

  const isV3 = subnetScheme === 'v3';
  const gatewayVmId = GATEWAY_VMID_OFFSET + vxlanId;

  const net = resolveLaneNetworking(subnetScheme, moduleKey, vxlanId);
  if (spec.goad?.prebaked && spec.goad?.fixed_subnet) {
    applyFixedSubnet(net, isV3, spec.goad.fixed_subnet.int, spec.goad.fixed_subnet.ext);
  }
  const vnetExtName    = vnet.vnet;
  const vnetIntName    = isV3 ? vnetInt.vnet : vnet.vnet;
  const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
  const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;

  const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId, goadSubnetBase);
  const specVms  = resolveSpecVms(spec, challengeKey);

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

  const [deployedVMs] = await Promise.all([Promise.all(clonePromises), kaliPromise]);

  // 2. Boot the gateway first so dnsmasq is answering before anything DHCPs.
  setStatus('starting');
  await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/lxc/${gatewayVmId}/status/start`);
  await new Promise(r => setTimeout(r, 5000));

  // 2b. Write the lane's DHCP reservations BEFORE any guest boots, so the very
  //     first DHCPREQUEST already has a reservation waiting.
  await writeLaneReservations({
    gatewayVmId, node: targetNode, vxlanId, goadMacs,
    attackBoxOctet: attackBoxVmId ? goadDeploy.INFRA_IP_OCTETS.Kali : null,
    extSubnetBase: laneSubnetBase, intSubnetBase: goadSubnetBase,
    liveGoadController: !!(spec.goad?.enabled && !spec.goad?.prebaked),
    laneId, logTag,
  });

  for (const dvm of deployedVMs) {
    await proxmoxAPI('POST',
      `/api2/json/nodes/${dvm.node}/${dvm.type === 'lxc' ? 'lxc' : 'qemu'}/${dvm.vm_id}/status/start`);
  }

  // 3. GOAD provisioning, if the challenge declares it.
  if (spec.goad?.enabled) {
    setStatus('provisioning_goad');
    try {
      if (spec.goad?.prebaked) {
        // Golden-image lane: clones are already GOAD-provisioned, so just write
        // reservations + bounce onto the baked IPs. No controller, no ansible,
        // no ~90-min bake.
        await goadDeploy.deployPrebakedGoadLane({
          lane: { lane_id: laneId },
          spec, vxlanId, gatewayVmId, bestNode: targetNode,
          laneSubnetBase: goadSubnetBase, extSubnetBase: laneSubnetBase,
          deployedVMs, proxmoxAPI,
        });
      } else {
        await goadDeploy.deployGoadLane({
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
      }
    } catch (goadErr) {
      // Best-effort: the lane's VMs exist and are reachable even if AD didn't
      // finish provisioning. Failing the lane here would destroy work already done.
      console.error(`${logTag} GOAD provisioning failed for ${user.email}: ${goadErr.message}`);
    }
  }

  // 4. Kali: boot, find it, and publish a console on the gateway's WAN IP.
  let kaliGuacConnId = null;
  if (attackBoxVmId) {
    setStatus('configuring_kali');
    await proxmoxAPI('POST', `/api2/json/nodes/${targetNode}/qemu/${attackBoxVmId}/status/start`);
    console.log(`${logTag} Kali attack box ${attackBoxVmId} started for ${user.email}`);

    await new Promise(r => setTimeout(r, 30000)); // guest agent needs a head start
    let kaliIp = await discoverKaliIp(targetNode, attackBoxVmId, logTag);
    if (!kaliIp) {
      // Kali's DHCP reservation targets .50, so that's the correct fallback when
      // the guest agent is slow — and it matches the gateway's wan0:3389 DNAT.
      console.warn(`${logTag} Could not get Kali IP via guest agent — assuming the reserved .50`);
      kaliIp = `${laneSubnetBase}.50`;
    }

    const gatewayTransitIp = await resolveGatewayTransitIp(targetNode, gatewayVmId);
    const guacTargetIp = gatewayTransitIp || kaliIp;
    console.log(`${logTag} Guac RDP target: ${guacTargetIp} (${gatewayTransitIp ? 'via gateway DNAT' : 'direct to Kali'})`);

    try {
      kaliGuacConnId = await createAttackBoxConsole({
        connName: `${laneConfig.group_name || laneConfig.course_name || challengeKey} - ${attackBoxCreds.username} - Kali`,
        hostname: guacTargetIp,
        creds: attackBoxCreds,
        user, guacParent, instructorEmails, logTag,
      });
    } catch (guacErr) {
      console.warn(`${logTag} Could not create Guac connection for ${user.email}: ${guacErr.message}`);
    }
  }

  // 5. Vuln scripts.
  if (vulnScripts && vulnScripts.length > 0) {
    setStatus('running_scripts');
    console.log(`${logTag} Running ${vulnScripts.length} vuln script(s) for ${user.email}`);
    try {
      await runVulnScripts({ laneId, deployedVMs, vulnScripts, logTag });
      console.log(`${logTag} Vuln scripts completed for ${user.email}`);
    } catch (scriptErr) {
      console.error(`${logTag} Vuln scripts failed for ${user.email}: ${scriptErr.message}`);
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
      vms: deployedVMs,
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
        guacConnId: null,
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

  // 8. Lane is live.
  const activeConfig = {
    ...laneConfig,
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
    ...(attackBoxVmId ? {
      // Same keys lane-deployer.js writes for a catalog workstation, so the CLE
      // VM list and any other console/credential reader works unchanged.
      workstation_user:   attackBoxCreds.username,
      workstation_pass:   attackBoxCreds.password,
      credentials_source: 'cloudinit',
      guac_connection_id: kaliGuacConnId,
      guac_user:          user.email,
      console_protocol:   'rdp',
      console_port:       3389,
    } : {}),
  };
  await cybercoreQuery(
    `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
    [laneId, JSON.stringify(activeConfig)]
  );

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
    // Any lane row we managed to insert before failing must not sit in
    // 'deploying' — that status is invisible to teardown AND to the allocator.
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
            SET status = 'error', config = config || $2::jsonb, updated_at = NOW()
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

  const spec = parseSpec(challenge.spec);
  const subnetScheme = challenge.subnet_scheme || 'v1';
  const resolvedModule = moduleKey || challenge.module_key || 'crucible';
  const challengeKey = challenge.challenge_key;
  const logTag = `${LOG}[${challengeKey}]`;

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
    laneDeployer.finishProgress(progressId);
    throw new Error(
      `Not enough VXLAN capacity for '${challengeKey}': ${vxlans.length} free id(s) for ` +
      `${users.length} user(s) (range ${vxlanBlock.start}-${vxlanBlock.end}).`
    );
  }
  const { resolved: vnetsByVxlan, missing } = await resolveVnets(vxlans, subnetScheme);

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
  const templateNodeByVmid = await resolveTemplateNodes(specVms, spec, attackBoxes);
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
      continue;
    }

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
        `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
         VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
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
          vms:           expectedVms,
        }), resolvedModule]
      );
      const laneId = ins.rows[0].lane_id;
      _insertedLaneIds.push(laneId);

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
        laneId, user, vxlanId,
        vnet: nets.vnet, vnetInt: nets.vnetInt,
        laneName, targetNode: nodeAssignments[i],
        attackBoxCreds: resolveAttackBoxCredentials(user),
      });
    } catch (err) {
      console.error(`${logTag} Failed to create lane record for ${user.email}: ${err.message}`);
      failed.push({ user_id: user.id, user_email: user.email, reason: err.message });
    }
  }

  if (jobs.length === 0) {
    if (progress) { progress.failed = failed.length; progress.completed = failed.length; }
    laneDeployer.finishProgress(progressId);
    return { provisioned: [], failed, progressId, lanes: created };
  }

  const concurrency = getSchedulingConfig().max_concurrent_lanes;
  const cloneSem = createCloneSemaphore();

  const ctx = {
    spec, subnetScheme, moduleKey: resolvedModule, challengeKey,
    attackBoxes, vulnScripts, laneConfig, guacParent, instructorEmails,
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
      `UPDATE cybercore_lane SET status = 'error', config = config || $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
      [job.laneId, JSON.stringify({ error: message })]
    ).catch(() => {});
  }

  laneDeployer.finishProgress(progressId);
  console.log(`${logTag} Complete: ${provisioned.length} provisioned, ${failed.length} failed`);

  return { provisioned, failed, progressId, lanes: created };
}

module.exports = {
  GATEWAY_VMID_OFFSET,
  DEFAULT_VM_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  parseSpec,
  resolveSpecVms,
  findVmOffsetCollision,
  findGoadHostMismatch,
  resolveAttackBoxCredentials,
  deployChallengeLanes,
  // Same registry lane-deployer.js drives, re-exported so a caller only needs
  // one import to deploy and to poll.
  readProgress: laneDeployer.readProgress,
};
