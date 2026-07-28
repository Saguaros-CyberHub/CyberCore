/**
 * ============================================================================
 * LANE DEPLOYER
 * ----------------------------------------------------------------------------
 * Deploys workstation lanes (gateway LXC + one VM) for users that ALREADY
 * EXIST, out of a caller-supplied VXLAN block. This is the sequence that
 * routes/admin/groups.js runs for its Kali attack box, lifted out of that
 * route's group/challenge/user-creation coupling so any caller can reuse it.
 *
 * Why this module exists: groups.js, routes/admin/lanes.js, and the CLE plugin
 * each inlined the same clone-and-wire sequence. There was no "deploy one lane
 * for an existing user" primitive to call, so the third copy drifted and lost
 * the non-obvious details that actually make a lane reachable. Those details
 * are the whole point of this file:
 *
 *   1. The VM is pinned to <lane-base>.50 by a deterministic MAC plus a dnsmasq
 *      reservation written into the gateway. The gateway template ships
 *      `dhcp-host=kali,<base>.50` — a HOSTNAME match, so Kali lands on .50 for
 *      free and nothing else does. A Windows template announces its own name
 *      and takes a random lease, which is why reserving by MAC is required for
 *      "any template" to work.
 *   2. The console target is the gateway's WAN transit IP, never the lane-local
 *      IP. guacd runs on the orchestrator's Docker bridge and has no route into
 *      10.<vxh>.<vxl>.0/24; the gateway's wan0 DNAT is the only way in.
 *   3. The gateway carries a per-lane bootstrap claim secret in its hostname so
 *      /api/lane-bootstrap can identify it by secret rather than source IP
 *      (which the Docker bridge rewrites). Without it Tailscale never comes up.
 *   4. Windows guests get an e1000 NIC. Stock Windows images have no virtio-net
 *      driver, so a virtio NIC comes up dead and the VM never DHCPs.
 *   5. Each VM is registered in cybercore_resource / vm_instance / allocation as
 *      vm_category='lane_vm', which is what puts it on the OWNER's dashboard.
 *
 * groups.js and lanes.js still run their own copies — this module is additive
 * and does not change them. They are candidates to migrate onto it later.
 *
 * Scale strategy (mirrors groups.js):
 *   ≤3 lanes → sequential, gateway cloned from its origin node
 *   >3 lanes → distributeAcrossNodes, then
 *       phase 1: replicate the gateway LXC template to each target node
 *       phase 2: clone gateways grouped by node (serial within a node so
 *                concurrent LXC clones don't hit "CT is locked (disk)")
 *       phase 3: clone the VMs in parallel via runBatch + clone semaphore
 * ============================================================================
 */

const crypto = require('crypto');

const { cybercoreQuery } = require('./cybercore-db');
const { proxmoxAPI, waitForTask, findTemplateNode } = require('./proxmox');
const { selectBestNode } = require('./node-selector');
const { runBatch, distributeAcrossNodes, createCloneSemaphore } = require('./batch-deployer');
const {
  resolveGatewayVmid, resolveLaneNetworking, formatLaneGatewayNet0, configureLaneTailscale,
} = require('./lane-networking');
const { getDefaultTemplateNode, getSchedulingConfig, getClusterNodes } = require('./site-config');
const { guacAPI, ensureGuacAccount } = require('./guacamole');
const { generatePassword } = require('./password-generator');
const { macForOctet, INFRA_IP_OCTETS } = require('./goad-deploy');
const nodeSsh = require('./node-ssh');
const tailscale = require('./tailscale');

const GATEWAY_VMID_OFFSET = 100000;     // gateway LXC = 100000 + vxlanId (matches groups.js)
const WORKSTATION_VMID_OFFSET = 600000; // workstation = 600000 + vxlanId
const TEMP_GW_TEMPLATE_BASE = 169300;   // per-node temp gateway template copies (clear of groups.js' 169200)

// The lane octet the workstation lands on. Same value the gateway template bakes
// its wan0:3389 DNAT against (KALI_OCTET=50 in bake-lane-gateway-v2.sh) and the
// same one groups.js pins its attack box to — so a plain RDP template still
// works even if our own DNAT install fails.
const WORKSTATION_OCTET = INFRA_IP_OCTETS.Kali;

// Console protocols a template may expose, and the port the gateway publishes
// them on. SSH is remapped because the gateway's own sshd owns wan0:22 —
// DNATing that would black-hole access to the gateway itself.
const CONSOLE_PROTOCOLS = {
  rdp: { guestPort: 3389, wanPort: 3389 },
  vnc: { guestPort: 5900, wanPort: 5900 },
  ssh: { guestPort: 22,   wanPort: 2222 },
};

const DNSMASQ_RESERVATION_PATH = '/etc/dnsmasq.d/lane-workstation.conf';
const LOG = '[LaneDeployer]';

// ── generic helpers ──────────────────────────────────────────────────────────

function vmApiBase(node, vmid, providerType) {
  return `/api2/json/nodes/${node}/${providerType === 'lxc' ? 'lxc' : 'qemu'}/${vmid}`;
}

/** First non-loopback IPv4 from the guest agent (qemu) or interfaces API (lxc). */
async function getVmIp(node, vmid, providerType, retries = 12, delayMs = 10000) {
  for (let i = 0; i < retries; i++) {
    try {
      if (providerType === 'lxc') {
        const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${node}/lxc/${vmid}/interfaces`);
        for (const iface of (Array.isArray(ifaces) ? ifaces : [])) {
          if (iface.name === 'lo') continue;
          const ip = (iface.inet || '').split('/')[0];
          if (ip && !ip.startsWith('127.') && !ip.startsWith('169.254.')) return ip;
        }
      } else {
        const data = await proxmoxAPI('GET', `/api2/json/nodes/${node}/qemu/${vmid}/agent/network-get-interfaces`);
        const ifaces = data?.result || (Array.isArray(data) ? data : []);
        for (const iface of ifaces) {
          if (iface.name === 'lo') continue;
          for (const addr of (iface['ip-addresses'] || [])) {
            const ip = addr['ip-address'];
            if (addr['ip-address-type'] === 'ipv4' && ip && !ip.startsWith('127.') && !ip.startsWith('169.254.')) return ip;
          }
        }
      }
    } catch (_) {}
    if (i < retries - 1) await new Promise(r => setTimeout(r, delayMs));
  }
  return null;
}

/**
 * Allocate up to `count` free VXLAN ids within a reserved block. Dedupes against
 * every live cybercore_lane so retries and partial deploys don't collide.
 */
async function allocateVxlanIds(block, count) {
  const res = await cybercoreQuery(
    `WITH used AS (
       SELECT DISTINCT vxlan_id FROM cybercore_lane
        WHERE vxlan_id IS NOT NULL
          AND vxlan_id BETWEEN $1 AND $2
          AND status NOT IN ('error', 'deleted')
     )
     SELECT gs AS vxlan_id
       FROM generate_series($1::int, $2::int) gs
       LEFT JOIN used u ON u.vxlan_id = gs
      WHERE u.vxlan_id IS NULL
      ORDER BY gs LIMIT $3`,
    [block.start, block.end, count]
  );
  return res.rows.map(r => r.vxlan_id);
}

/** Map vnets (from /cluster/sdn/vnets) by tag, for vxlan → vnet lookup. */
async function loadVnetsByTag() {
  const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const byTag = {};
  for (const v of (Array.isArray(vnets) ? vnets : [])) byTag[String(v.tag)] = v;
  return byTag;
}

async function markLaneError(laneId, msg) {
  await cybercoreQuery(
    `UPDATE cybercore_lane SET status='error', config = config || $2::jsonb, updated_at=NOW() WHERE lane_id=$1`,
    [laneId, JSON.stringify({ error: msg })]
  ).catch(() => {});
}

/** Merge a patch into a lane's config without clobbering concurrent writes. */
async function patchLaneConfig(laneId, patch) {
  await cybercoreQuery(
    `UPDATE cybercore_lane SET config = config || $2::jsonb, updated_at=NOW() WHERE lane_id=$1`,
    [laneId, JSON.stringify(patch)]
  ).catch((e) => console.warn(`${LOG} Lane ${laneId} config patch failed: ${e.message}`));
}

// ── template shape ───────────────────────────────────────────────────────────

/**
 * Which protocol/ports this template's console speaks. Defaults to RDP, which is
 * what every workstation template in the catalog ships today (Windows RDP, Kali
 * xrdp). Override per template with metadata:
 *   { "console_protocol": "ssh" | "rdp" | "vnc", "console_port": 3390 }
 */
function resolveConsole(template) {
  const meta = template.metadata || {};
  const requested = String(meta.console_protocol || 'rdp').toLowerCase();
  const protocol = CONSOLE_PROTOCOLS[requested] ? requested : 'rdp';
  const base = CONSOLE_PROTOCOLS[protocol];
  const guestPort = Number(meta.console_port) || base.guestPort;
  const wanPort = Number(meta.console_wan_port) || (guestPort === 22 ? base.wanPort : guestPort);
  return { protocol, guestPort, wanPort };
}

/**
 * NIC model for a QEMU workstation. Windows guests get e1000 by default: stock
 * Windows images have no virtio-net driver, so a virtio NIC comes up dead and
 * the VM never DHCPs — the single most common way a "deployed" Windows box ends
 * up unreachable. Same reason GOAD forces e1000 on its AD hosts.
 */
function resolveNicModel(template) {
  const meta = template.metadata || {};
  if (meta.nic_model) return meta.nic_model;
  return String(template.os_family || '').startsWith('windows') ? 'e1000' : 'virtio';
}

/**
 * Credentials the user will present to the workstation itself.
 *   - A template that bakes its own account declares it as
 *     metadata.default_rdp_user / default_rdp_pass; we use that verbatim.
 *   - Otherwise mint a per-user account and hand it to the guest through
 *     cloud-init (ciuser/cipassword), exactly like groups.js does for Kali.
 */
function resolveWorkstationCredentials(template, user) {
  const meta = template.metadata || {};
  if (meta.default_rdp_user) {
    return { username: meta.default_rdp_user, password: meta.default_rdp_pass || null, source: 'template' };
  }
  const local = String(user.email || 'student').split('@')[0].replace(/[^a-z0-9_-]/gi, '-').toLowerCase();
  return { username: local || 'student', password: generatePassword(), source: 'cloudinit' };
}

/** The cloud-init drive key on a QEMU clone (ide2, sata3, …), or null. */
async function findCloudInitDrive(node, vmid) {
  const cfg = await proxmoxAPI('GET', `${vmApiBase(node, vmid, 'qemu')}/config`);
  if (!cfg) return null;
  return Object.keys(cfg).find(k =>
    /^(ide|sata|scsi|virtio)\d+$/.test(k) &&
    typeof cfg[k] === 'string' && /cloudinit/i.test(cfg[k])
  ) || null;
}

// ── gateway plumbing ─────────────────────────────────────────────────────────

/**
 * Pin the workstation to <lane-base>.50 and publish its console port on the
 * gateway's WAN IP. Must run BEFORE the workstation first boots so its very
 * first DHCPREQUEST already has a reservation waiting.
 *
 * Both halves need a shell inside the gateway LXC, and Proxmox has no LXC exec
 * API — so this goes over `pct` via SSH to the node, the same channel
 * goad-deploy.writeDhcpReservations and attached-modules.writeDhcpForModule use.
 * Throws if that isn't wired up; the caller degrades to a direct-to-lane-IP
 * console rather than failing the whole deploy.
 */
async function configureGatewayAccess({ node, gatewayVmid, laneBase, mac, hostname, console: con }) {
  const target = `${laneBase}.${WORKSTATION_OCTET}`;

  const reservation =
    `# Lane workstation reservation — generated by lane-deployer.js\n` +
    `# Pins the user's machine to ${target} so the gateway's console DNAT has a\n` +
    `# fixed destination regardless of which OS the template runs.\n` +
    `dhcp-host=${mac},${target},${hostname}\n`;
  await nodeSsh.pctPushFromString(node, gatewayVmid, reservation, DNSMASQ_RESERVATION_PATH);
  await nodeSsh.pctExec(node, gatewayVmid, ['/bin/sh', '-c',
    'rc-service dnsmasq restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true',
  ]);

  // wan0:<wanPort> → <base>.50:<guestPort>. The v2 gateway template already bakes
  // this for 3389, but only for 3389 — re-adding it is harmless (same
  // destination) and it's the only path for a non-RDP template. Strip our own tag
  // first so a re-provision doesn't stack duplicates, then persist so the rule
  // survives a gateway reboot (Alpine reloads /etc/iptables/rules-save at boot,
  // before firstboot re-adds its own rules).
  const rules = [
    'iptables-save | grep -v "LANE-CONSOLE" | iptables-restore || true',
    `iptables -t nat -A PREROUTING -i wan0 -p tcp --dport ${con.wanPort} ` +
      `-m comment --comment "LANE-CONSOLE" -j DNAT --to-destination ${target}:${con.guestPort}`,
    // Position 2 keeps this above the base template's perimeter DROP block
    // (position 1 is the global RELATED,ESTABLISHED ACCEPT). Fall back to a
    // plain insert if the chain is shorter than that — iptables rejects an
    // index past the end of the chain, and `;` separators would hide it.
    `iptables -I FORWARD 2 -i wan0 -o lan0 -p tcp -d ${target} --dport ${con.guestPort} ` +
      `-m comment --comment "LANE-CONSOLE" -j ACCEPT ` +
      `|| iptables -I FORWARD -i wan0 -o lan0 -p tcp -d ${target} --dport ${con.guestPort} ` +
      `-m comment --comment "LANE-CONSOLE" -j ACCEPT`,
    'mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules-save',
  ].join('; ');
  await nodeSsh.pctExec(node, gatewayVmid, ['/bin/sh', '-c', rules]);
}

// ── Guacamole ────────────────────────────────────────────────────────────────

/**
 * Resolve the user's Guacamole password, creating the account on first use.
 * Mirrors routes/workstations.js: prefer the stored (encrypted) credential so we
 * don't reset a password their other consoles already authenticate with, and
 * persist a newly minted one so the next deploy reuses it.
 */
async function resolveGuacPassword(userId, email) {
  if (!email) return null;
  const key = process.env.GUAC_ENCRYPT_KEY;
  let password = null;

  if (key) {
    const r = await cybercoreQuery(
      `SELECT CASE WHEN guac_password IS NOT NULL
                   THEN pgp_sym_decrypt(guac_password, $2)::text END AS pw
         FROM cybercore_user WHERE user_id = $1`,
      [userId, key]
    ).catch(() => ({ rows: [] }));
    password = r.rows[0]?.pw || null;
  }

  if (!password) {
    password = await ensureGuacAccount(email).catch(() => null);
    if (password && key) {
      await cybercoreQuery(
        `UPDATE cybercore_user SET guac_password = pgp_sym_encrypt($1, $2) WHERE user_id = $3`,
        [password, key, userId]
      ).catch(() => {});
    }
  }
  return password;
}

/** Guacamole connection parameters for the resolved protocol. */
function buildGuacParameters({ protocol, hostname, port, creds, template }) {
  const meta = template.metadata || {};
  const auth = {
    ...(creds?.username ? { username: creds.username } : {}),
    ...(creds?.password ? { password: creds.password } : {}),
  };

  if (protocol === 'ssh') {
    return { hostname, port: String(port), ...auth, 'color-scheme': 'gray-black', 'font-size': '12' };
  }
  if (protocol === 'vnc') {
    return { hostname, port: String(port), ...(creds?.password ? { password: creds.password } : {}) };
  }
  return {
    hostname,
    port: String(port),
    ...auth,
    ...(meta.rdp_domain ? { domain: meta.rdp_domain } : {}),
    // 'any' lets guacd negotiate whatever the guest offers — NLA/TLS on Windows,
    // plain RDP on xrdp. Pinning 'tls' fails outright against xrdp and against
    // NLA-only Windows, which is what the CLE copy of this code did.
    security: meta.rdp_security || 'any',
    'ignore-cert': 'true',
    // Without server-layout the Guac UI leaves "Keyboard layout" unset and
    // keystrokes never reach xrdp.
    'server-layout': meta.rdp_keyboard || 'en-us-qwerty',
    width: '1920',
    height: '1080',
    dpi: '96',
    'enable-wallpaper': 'true',
    'enable-theming': 'true',
    'enable-font-smoothing': 'true',
    'enable-full-window-drag': 'true',
    'color-depth': '24',
    'resize-method': 'display-update',
  };
}

/**
 * Create the user's Guacamole connection and grant them READ on it. Returns the
 * connection identifier, or null if Guacamole is off/unreachable — a lane
 * without a console is still a usable lane, and losing the whole deploy over a
 * Guac hiccup is worse than an instructor re-creating one connection.
 */
async function createGuacConnection({ connName, user, hostname, port, protocol, creds, template, parentIdentifier }) {
  if (process.env.GUAC_ENABLED !== 'true') return null;
  try {
    const conn = await guacAPI('POST', '/connections', {
      name: connName,
      protocol,
      parentIdentifier: parentIdentifier || 'ROOT',
      parameters: buildGuacParameters({ protocol, hostname, port, creds, template }),
      attributes: { 'max-connections': '5', 'max-connections-per-user': '2' },
    });
    const connId = conn?.identifier || null;
    if (connId && user.email) {
      await resolveGuacPassword(user.id, user.email);
      await guacAPI('PATCH', `/users/${encodeURIComponent(user.email)}/permissions`, [
        { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' },
      ]).catch((e) => console.warn(`${LOG} Guac permission grant failed for ${user.email}: ${e.message}`));
    }
    return connId;
  } catch (err) {
    console.warn(`${LOG} Guac setup failed for ${connName}: ${err.message}`);
    return null;
  }
}

// ── owner-facing workspace registration ──────────────────────────────────────

/**
 * Register the workstation in cybercore_resource / vm_instance / allocation so it
 * shows up on the OWNER's own dashboard (/api/dashboard/vms and My Workspaces)
 * with a working Console button. Without this the machine is only reachable
 * through an admin/instructor page, which is not the same as the user having
 * access to it.
 *
 * vm_category is 'lane_vm' so guac-sessions.js skips its IP refresh (that
 * refresh would overwrite our gateway WAN hostname with the unroutable
 * lane-local IP) and so its ghost-card filter ties the row to the lane.
 * Non-fatal: the lane still goes active if this fails.
 */
async function registerWorkspaceVm({ job, workstationVmid, providerType, guacConnId }) {
  const { laneId, user, template, vxlanId, targetNode, moduleKey, laneConfig } = job;
  const slug = String(user.email || user.id).split('@')[0].replace(/[^a-z0-9-]/gi, '-').toLowerCase();
  const displayName = template.os_name || template.template_key || 'workstation';
  // (module_key, name) is UNIQUE — suffix with the cluster-unique VMID so the
  // same template deployed to N lanes can't collide on the base name.
  const name = `${template.template_key || 'workstation'}-${slug}-${workstationVmid}`.substring(0, 80);

  try {
    const resourceRes = await cybercoreQuery(
      `INSERT INTO cybercore_resource (type, module_key, name, status, metadata)
       VALUES ('vm', $1, $2, 'allocated', $3::jsonb)
       RETURNING resource_id`,
      [moduleKey, name, JSON.stringify({
        vm_category: 'lane_vm',
        provider_type: providerType,
        template_name: displayName,
        catalog_template_id: template.id || null,
        lane_id: laneId,
        vxlan_id: vxlanId,
        ...laneConfig,
      })]
    );
    const resourceId = resourceRes.rows[0].resource_id;

    await cybercoreQuery(
      `INSERT INTO cybercore_vm_instance
         (resource_id, provider, provider_node, provider_vmid, power_state, metadata)
       VALUES ($1, 'proxmox', $2, $3, 'running', $4::jsonb)`,
      [resourceId, targetNode, String(workstationVmid), JSON.stringify({
        provider_type: providerType,
        ...(guacConnId ? { guac_connection_id: guacConnId, guac_user: user.email } : {}),
      })]
    );

    await cybercoreQuery(
      `INSERT INTO cybercore_allocation (resource_id, user_id, purpose)
       VALUES ($1, $2, 'lane_vm')`,
      [resourceId, user.id]
    );
    return resourceId;
  } catch (err) {
    console.warn(`${LOG} Workspace registration failed for ${user.email}: ${err.message}`);
    return null;
  }
}

// ── progress tracking ────────────────────────────────────────────────────────

/**
 * Same global._batchDeployProgress shape admin-lanes.js already polls, so a
 * caller can expose a progress endpoint without inventing a new contract.
 */
function initProgress(progressId, label, total) {
  if (!progressId) return null;
  if (!global._batchDeployProgress) global._batchDeployProgress = {};
  global._batchDeployProgress[progressId] = {
    group_name: label,
    total,
    completed: 0,
    succeeded: 0,
    failed: 0,
    started_at: new Date().toISOString(),
    phase: 'preparing',
    phase_detail: 'Allocating lanes',
    elapsed_s: 0,
    avg_lane_s: null,
    eta_s: null,
    eta_at: null,
    lanes: {},
    _laneTimes: [],
    _startedAtMs: Date.now(),
  };
  return global._batchDeployProgress[progressId];
}

function setPhase(progress, phase, detail) {
  if (!progress) return;
  progress.phase = phase;
  if (detail) progress.phase_detail = detail;
  progress.elapsed_s = Math.round((Date.now() - progress._startedAtMs) / 1000);
}

function recordLaneDone(progress, concurrency) {
  if (!progress) return;
  const now = Date.now();
  progress.elapsed_s = Math.round((now - progress._startedAtMs) / 1000);
  if (progress._laneTimes.length > 0) {
    const avgMs = progress._laneTimes.reduce((a, b) => a + b, 0) / progress._laneTimes.length;
    progress.avg_lane_s = Math.round(avgMs / 1000);
    const remaining = progress.total - progress.completed;
    const etaMs = (remaining / Math.max(1, concurrency)) * avgMs;
    progress.eta_s = Math.round(etaMs / 1000);
    progress.eta_at = new Date(now + etaMs).toISOString();
  }
}

function finishProgress(progressId) {
  const progress = (global._batchDeployProgress || {})[progressId];
  if (!progress) return;
  progress.phase = 'complete';
  progress.phase_detail = `${progress.succeeded} succeeded, ${progress.failed} failed`;
  progress.finished_at = new Date().toISOString();
  progress.eta_s = 0;
  progress.eta_at = null;
  progress.elapsed_s = Math.round((Date.now() - progress._startedAtMs) / 1000);
  setTimeout(() => { delete global._batchDeployProgress[progressId]; }, 3600000);
}

/** Strip internal bookkeeping so a route can return progress verbatim. */
function readProgress(progressId) {
  const progress = (global._batchDeployProgress || {})[progressId];
  if (!progress) return null;
  const { _laneTimes, _startedAtMs, ...clean } = progress;
  const lanes = {};
  for (const [id, lane] of Object.entries(clean.lanes || {})) {
    const { _startedAt, ...laneClean } = lane;
    lanes[id] = laneClean;
  }
  return { ...clean, lanes };
}

// ── per-lane steps ───────────────────────────────────────────────────────────

/** Create the lane row (status 'deploying') with the seed config. Sets job.laneId. */
async function insertLane(job) {
  const {
    user, template, vxlanId, vnet, targetNode, net, console: con,
    moduleKey, subnetScheme, laneName, laneConfig,
  } = job;
  const providerType = template.provider_type || 'qemu';
  const ins = await cybercoreQuery(
    `INSERT INTO cybercore_lane (user_id, module_key, name, status, vxlan_id, config, created_at, updated_at)
     VALUES ($1, $2, $3, 'deploying', $4, $5::jsonb, NOW(), NOW())
     RETURNING lane_id`,
    [user.id, moduleKey, laneName, vxlanId, JSON.stringify({
      ...laneConfig,
      template_id: template.id || null,
      template_name: template.os_name || template.template_key,
      provider_type: providerType,
      subnet_scheme: subnetScheme,
      vnet: vnet.vnet,
      gateway_vmid: GATEWAY_VMID_OFFSET + vxlanId,
      workstation_vmid: WORKSTATION_VMID_OFFSET + vxlanId,
      node: targetNode,
      user_email: user.email,
      lane_subnet_base: net.lan.base3,
      gateway_wan_ip: net.wan.ip.split('/')[0],
      workstation_ip: `${net.lan.base3}.${WORKSTATION_OCTET}`,
      console_protocol: con.protocol,
      console_port: con.wanPort,
    })]
  );
  job.laneId = ins.rows[0].lane_id;
  return job.laneId;
}

/**
 * Clone + configure + start the lane gateway LXC. Throws on failure and does not
 * touch lane status — the caller records errors. Clones from
 * job.gwSourceNode/Vmid (origin for sequential, node-local temp for batch).
 */
async function cloneGateway(job) {
  const {
    user, vxlanId, vnet, targetNode, gwSourceNode, gwSourceVmid,
    net, subnetScheme, laneName, description,
  } = job;
  const gatewayVmid = GATEWAY_VMID_OFFSET + vxlanId;

  // Per-lane bootstrap secret embedded as a `-b<16hex>` suffix on the LXC
  // hostname. firstboot greps it back out and passes it as ?secret=… on the
  // /api/lane-bootstrap request; without it the endpoint falls back to source-IP
  // matching, which never matches once the orchestrator's Docker bridge rewrites
  // the source — so Tailscale silently never comes up.
  // Hostname budget: 63 chars; reserve 18 for `-b<16hex>`.
  const claimSecret = crypto.randomBytes(8).toString('hex');
  const baseHost = `${laneName}-gateway`.substring(0, 63 - 18).toLowerCase()
    .replace(/[^a-z0-9-]/g, '-').replace(/-+$/g, '');
  job.claimSecret = claimSecret;

  const upid = await proxmoxAPI('POST', `${vmApiBase(gwSourceNode, gwSourceVmid, 'lxc')}/clone`, {
    newid: gatewayVmid,
    hostname: `${baseHost}-b${claimSecret}`,
    full: 1,
    target: targetNode,
    description: `Lane gateway\nUser: ${user.email}\nLane: ${job.laneId}${description ? `\n${description}` : ''}`,
  });
  if (upid) await waitForTask(gwSourceNode, upid, 600000);

  await proxmoxAPI('PUT', `${vmApiBase(targetNode, gatewayVmid, 'lxc')}/config`, {
    net0: formatLaneGatewayNet0(net.wan),
    net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`,
  });
  await configureLaneTailscale({
    subnetScheme, vxlanId, wanIp: net.wan.ip.split('/')[0], laneName, claimSecret, logTag: LOG,
  });
  await proxmoxAPI('POST', `${vmApiBase(targetNode, gatewayVmid, 'lxc')}/status/start`);
  await new Promise(r => setTimeout(r, 5000)); // let dnsmasq come up before the workstation DHCPs
}

/**
 * Proxmox holds a lock on an LXC template for the disk-copy phase of a clone, so
 * two lanes cloning the same container template at once fail with "CT is locked
 * (disk)". QEMU templates clone concurrently fine, so only LXC clones are
 * chained — keyed per template, so different templates still overlap.
 */
const _lxcCloneChain = new Map(); // `${node}:${vmid}` → promise

function serializeLxcClone(node, vmid, fn) {
  const key = `${node}:${vmid}`;
  const prev = _lxcCloneChain.get(key) || Promise.resolve();
  const next = prev.then(fn, fn);            // run regardless of the previous outcome
  _lxcCloneChain.set(key, next.catch(() => {}));
  return next;
}

/**
 * Clone + configure + start the workstation, wire up remote access, register it
 * for the owner, and mark the lane 'active'. Marks the lane 'error' and rethrows
 * on failure so runBatch records it.
 */
async function deployWorkstation(job) {
  const {
    user, template, vxlanId, vnet, targetNode, wsSourceNode, cloneSem,
    net, console: con, laneName, description, progress, guacParent,
  } = job;
  const workstationVmid = WORKSTATION_VMID_OFFSET + vxlanId;
  const gatewayVmid = GATEWAY_VMID_OFFSET + vxlanId;
  const providerType = template.provider_type || 'qemu';
  const laneBase = net.lan.base3;
  const gatewayWanIp = net.wan.ip.split('/')[0];
  const mac = macForOctet(WORKSTATION_OCTET, vxlanId);

  if (progress) {
    progress.lanes[job.laneId] = {
      user: user.email, vxlan: vxlanId, node: targetNode, status: 'cloning', _startedAt: Date.now(),
    };
  }

  try {
    // 1. Reserve <base>.50 for our MAC and publish the console port on the
    //    gateway WAN — before the workstation exists, so its first DHCP lease is
    //    already the reserved one.
    let viaGateway = false;
    try {
      await configureGatewayAccess({
        node: targetNode, gatewayVmid, laneBase, mac, hostname: laneName, console: con,
      });
      viaGateway = true;
    } catch (gwErr) {
      console.warn(
        `${LOG} Gateway access setup failed for ${laneName} (${gwErr.message}) — ` +
        `falling back to a direct lane-IP console. Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER.`
      );
    }

    // 2. Clone the template.
    const cloneBody = {
      newid: workstationVmid,
      ...(providerType === 'lxc' ? { hostname: laneName } : { name: laneName }),
      full: 1,
      target: targetNode,
      description: `Lane workstation\nUser: ${user.email}\nLane: ${job.laneId}${description ? `\n${description}` : ''}`,
    };
    const clonePath = `${vmApiBase(wsSourceNode, template.template_vmid, providerType)}/clone`;
    const runClone = async () => {
      const upid = await proxmoxAPI('POST', clonePath, cloneBody);
      if (upid) await waitForTask(wsSourceNode, upid, 600000);
    };
    await cloneSem.run(() => (providerType === 'lxc'
      ? serializeLxcClone(wsSourceNode, template.template_vmid, runClone)
      : runClone()));

    // 3. Put it on the lane VNet with the reserved MAC.
    const nicVal = providerType === 'lxc'
      ? `name=eth0,bridge=${vnet.vnet},hwaddr=${mac},firewall=0,ip=dhcp`
      : `${resolveNicModel(template)},bridge=${vnet.vnet},macaddr=${mac},firewall=0`;
    await proxmoxAPI('PUT', `${vmApiBase(targetNode, workstationVmid, providerType)}/config`, { net0: nicVal });

    // 4. Hand the user their login through cloud-init when the template carries a
    //    cloud-init drive (Linux cloud images, Windows + cloudbase-init).
    //    Addressing stays on DHCP so the reservation decides the IP — a static
    //    ipconfig0 races the guest's own DHCP client and loses (the exact bug
    //    groups.js hit pinning Kali statically).
    let creds = resolveWorkstationCredentials(template, user);
    if (providerType === 'qemu' && creds.source === 'cloudinit' && template.metadata?.cloud_init !== false) {
      let ciDrive = null;
      try { ciDrive = await findCloudInitDrive(targetNode, workstationVmid); }
      catch (e) { console.warn(`${LOG} cloud-init probe failed for ${laneName}: ${e.message}`); }

      if (ciDrive) {
        // citype is deliberately NOT set: Proxmox derives it from the template's
        // ostype — nocloud for Linux, configdrive2 for Windows. cloudbase-init
        // reads configdrive2, so forcing 'nocloud' here (as the Linux-only call
        // sites in groups.js/lanes.js do) silently breaks credential injection on
        // every Windows template. If a Windows template lands without creds,
        // check `qm config <vmid> | grep ostype` first — it must be win10/win11.
        await proxmoxAPI('PUT', `${vmApiBase(targetNode, workstationVmid, 'qemu')}/config`, {
          ciuser: creds.username,
          cipassword: creds.password,
          ipconfig0: 'ip=dhcp',
          nameserver: net.lan.gatewayIp,
        });
        await proxmoxAPI('PUT', `${vmApiBase(targetNode, workstationVmid, 'qemu')}/cloudinit`).catch(() => {});
      } else {
        // No cloud-init drive: the guest keeps whatever accounts the template
        // baked in. Publishing generated credentials Guacamole can only fail to
        // authenticate with is worse than prompting the user.
        console.log(`${LOG} ${laneName}: template has no cloud-init drive — using the template's own accounts`);
        creds = { username: null, password: null, source: 'baked' };
      }
    } else if (providerType === 'lxc' && creds.source === 'cloudinit') {
      creds = { username: null, password: null, source: 'baked' };
    }

    // 5. Boot it.
    if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'starting';
    await proxmoxAPI('POST', `${vmApiBase(targetNode, workstationVmid, providerType)}/status/start`);

    // 6. Console. The target is the gateway's WAN transit IP, which DNATs to the
    //    workstation — guacd sits on the orchestrator's Docker bridge and has no
    //    route into the lane subnet. Only if the gateway plumbing failed do we
    //    point straight at the lane IP (routable only where the lane subnet is
    //    carried, e.g. a Tailscale-connected orchestrator).
    const consoleHost = viaGateway ? gatewayWanIp : `${laneBase}.${WORKSTATION_OCTET}`;
    const consolePort = viaGateway ? con.wanPort : con.guestPort;
    const guacConnId = await createGuacConnection({
      connName: `${laneName}-${workstationVmid}`,
      user, template, creds, parentIdentifier: guacParent,
      hostname: consoleHost, port: consolePort, protocol: con.protocol,
    });

    // 7. Surface it on the owner's own dashboard.
    const resourceId = await registerWorkspaceVm({ job, workstationVmid, providerType, guacConnId });

    // 8. Lane is live. Deliberately NOT gated on discovering the guest's IP: a
    //    stock Windows template has no qemu-guest-agent, and the console doesn't
    //    need the IP anyway.
    await cybercoreQuery(
      `UPDATE cybercore_lane
          SET status='active', config = config || $2::jsonb, updated_at=NOW()
        WHERE lane_id=$1`,
      [job.laneId, JSON.stringify({
        ip: `${laneBase}.${WORKSTATION_OCTET}`,
        ip_confirmed: false,
        workstation_mac: mac,
        console_via: viaGateway ? 'gateway' : 'direct',
        console_host: consoleHost,
        console_port: consolePort,
        guac_connection_id: guacConnId,
        guac_user: user.email,
        workspace_resource_id: resourceId,
        ...(creds.username ? { workstation_user: creds.username } : {}),
        ...(creds.password ? { workstation_pass: creds.password } : {}),
        credentials_source: creds.source,
      })]
    );
    if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'active';
    console.log(
      `${LOG} Lane ${job.laneId} active (vxlan ${vxlanId}, node ${targetNode}, ws ${workstationVmid}, ` +
      `${con.protocol} via ${consoleHost}:${consolePort}) for ${user.email}`
    );

    // 9. Confirm the guest actually took the reserved lease, in the background.
    //    Purely diagnostic — never blocks the deploy or the console.
    confirmWorkstationIp(job, workstationVmid, providerType, `${laneBase}.${WORKSTATION_OCTET}`);

    return { laneId: job.laneId, user: user.email, vxlanId, status: 'active' };
  } catch (err) {
    await markLaneError(job.laneId, `workstation: ${err.message}`);
    if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'error';
    console.error(`${LOG} Lane ${job.laneId} workstation failed for ${user.email}: ${err.message}`);
    throw err;
  }
}

/**
 * Detached check that the workstation landed on the reserved address. Records
 * what it found on the lane so a mismatch (bad reservation, guest ignoring DHCP)
 * is visible in the UI instead of surfacing as a mysteriously dead console.
 */
function confirmWorkstationIp(job, workstationVmid, providerType, expectedIp) {
  getVmIp(job.targetNode, workstationVmid, providerType, 12, 10000)
    .then(async (ip) => {
      if (!ip) {
        console.log(`${LOG} Lane ${job.laneId}: no guest-agent IP (expected for templates without the agent)`);
        return;
      }
      if (ip !== expectedIp) {
        console.warn(`${LOG} Lane ${job.laneId}: workstation is on ${ip}, not the reserved ${expectedIp} — console may not connect`);
      }
      await patchLaneConfig(job.laneId, { ip, ip_confirmed: ip === expectedIp });
    })
    .catch((e) => console.warn(`${LOG} Lane ${job.laneId} IP check failed: ${e.message}`));
}

// ── batch template replication ───────────────────────────────────────────────

/**
 * Pick `count` temp VMIDs that are free cluster-wide. A fixed base + counter
 * collides when two batches run at once, and the loser's clone fails.
 */
async function reserveTempVmids(count) {
  if (count <= 0) return [];
  let taken = new Set();
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    taken = new Set((resources || []).map(r => Number(r.vmid)));
  } catch (e) {
    console.warn(`${LOG} Could not list cluster VMIDs for temp templates: ${e.message}`);
  }
  const ids = [];
  for (let id = TEMP_GW_TEMPLATE_BASE; ids.length < count && id < TEMP_GW_TEMPLATE_BASE + 1000; id++) {
    if (!taken.has(id)) ids.push(id);
  }
  return ids;
}

/** Replicate the gateway LXC template to each unique target node; returns node → vmid. */
async function replicateGatewayTemplate(uniqueNodes, originNode, originVmid) {
  const byNode = {};
  const needsCopy = uniqueNodes.filter(n => n !== originNode);
  const tempIds = await reserveTempVmids(needsCopy.length);

  for (const node of uniqueNodes) {
    if (node === originNode) { byNode[node] = originVmid; continue; }
    const tempId = tempIds.shift();
    if (!tempId) { byNode[node] = originVmid; continue; }
    try {
      const upid = await proxmoxAPI('POST', `${vmApiBase(originNode, originVmid, 'lxc')}/clone`, {
        newid: tempId, hostname: `lane-gw-temp-${node}`, full: 1, target: node,
        description: 'Temp lane gateway template for batch deploy',
      });
      if (upid) await waitForTask(originNode, upid, 600000);
      byNode[node] = tempId;
      console.log(`${LOG} Replicated gateway template → ${tempId} on ${node}`);
    } catch (err) {
      console.error(`${LOG} Gateway template replication to ${node} failed: ${err.message} — using origin`);
      byNode[node] = originVmid; // fall back to cross-node clone from origin
    }
  }
  return byNode;
}

async function cleanupTempGatewayTemplates(byNode, originVmid) {
  await Promise.all(Object.entries(byNode)
    .filter(([, id]) => id !== originVmid)
    .map(async ([node, id]) => {
      try { await proxmoxAPI('DELETE', `${vmApiBase(node, id, 'lxc')}?purge=1&force=1`); }
      catch (e) { console.warn(`${LOG} Could not delete temp gateway template ${id} on ${node}: ${e.message}`); }
    }));
}

// ── entry point ──────────────────────────────────────────────────────────────

/**
 * Deploy one workstation lane per user out of a reserved VXLAN block.
 *
 * @param {object}   a
 * @param {Array}    a.users          [{ id, email }] — must already exist in cybercore_user
 * @param {object}   a.template       cybercore_template_catalog row (needs template_vmid)
 * @param {object}   a.vxlanBlock     { start, end } — pre-reserved, VNets already created
 * @param {string}   [a.moduleKey='crucible']
 * @param {string}   [a.subnetScheme='v2']
 * @param {string}   [a.namePrefix='lane']  lane name = `${namePrefix}-${vxlanId}`
 * @param {object}   [a.laneConfig={}]      extra keys merged into cybercore_lane.config
 * @param {string}   [a.description='']     extra lines on the Proxmox object descriptions
 * @param {string}   [a.guacParent]         Guacamole connection-group identifier
 * @param {string}   [a.progressId]         key into global._batchDeployProgress
 * @param {string}   [a.progressLabel='']
 * @returns {Promise<{provisioned:Array, failed:Array, progressId:?string}>}
 */
async function deployLanes({
  users, template, vxlanBlock,
  moduleKey = 'crucible', subnetScheme = 'v2', namePrefix = 'lane',
  laneConfig = {}, description = '', guacParent = null,
  progressId = null, progressLabel = '',
}) {
  if (!Array.isArray(users) || users.length === 0) return { provisioned: [], failed: [], progressId };
  if (!vxlanBlock?.start || !vxlanBlock?.end) throw new Error('deployLanes: vxlanBlock {start,end} is required');
  if (!template?.template_vmid) {
    throw new Error(`deployLanes: template '${template?.template_key || '?'}' has no Proxmox VMID configured`);
  }

  const progress = initProgress(progressId, progressLabel, users.length);

  // Allocate VXLAN ids from the reserved block; map each to its pre-created VNet.
  const vxlans = await allocateVxlanIds(vxlanBlock, users.length);
  if (vxlans.length < users.length) {
    throw new Error(
      `VXLAN block exhausted: ${vxlans.length} free ids for ${users.length} users ` +
      `(range ${vxlanBlock.start}-${vxlanBlock.end}).`
    );
  }
  const vnetsByTag = await loadVnetsByTag();

  // Resolve template source nodes once.
  const gwOriginVmid = resolveGatewayVmid(moduleKey, subnetScheme);
  const gwOriginNode = await findTemplateNode(gwOriginVmid, getDefaultTemplateNode());
  const wsSourceNode = await findTemplateNode(template.template_vmid, template.node || getDefaultTemplateNode());
  const con = resolveConsole(template);
  console.log(
    `${LOG} Deploying ${users.length} lane(s) from ${template.os_name || template.template_key} ` +
    `(${template.provider_type || 'qemu'} ${template.template_vmid} @ ${wsSourceNode}, ` +
    `${con.protocol}, nic ${resolveNicModel(template)})`
  );

  // Build a job per user, skipping any whose VNet is missing.
  const jobs = [];
  const failed = [];
  for (let i = 0; i < users.length; i++) {
    const vxlanId = vxlans[i];
    const vnet = vnetsByTag[String(vxlanId)];
    if (!vnet) {
      failed.push({ user_id: users[i].id, reason: `No VNet for VXLAN ${vxlanId} (lab network not fully provisioned)` });
      continue;
    }
    jobs.push({
      user: users[i], template, vxlanId, vnet, wsSourceNode, console: con,
      moduleKey, subnetScheme, laneConfig, description, guacParent, progress,
      laneName: `${namePrefix}-${vxlanId}`,
      net: resolveLaneNetworking(subnetScheme, moduleKey, vxlanId),
    });
  }
  if (!jobs.length) {
    if (progress) { progress.failed = failed.length; progress.completed = failed.length; }
    finishProgress(progressId);
    return { provisioned: [], failed, progressId };
  }

  const cloneSem = createCloneSemaphore();
  jobs.forEach(j => { j.cloneSem = cloneSem; });

  const result = jobs.length > 3
    ? await batchDeploy(jobs, failed, { gwOriginNode, gwOriginVmid, cloneSem, progress })
    : await sequentialDeploy(jobs, failed, { gwOriginNode, gwOriginVmid, progress });

  finishProgress(progressId);
  return { ...result, progressId };
}

/** ≤3: one lane at a time, gateway cloned from its origin node. */
async function sequentialDeploy(jobs, failed, { gwOriginNode, gwOriginVmid, progress }) {
  const provisioned = [];
  setPhase(progress, 'deploying', `Deploying ${jobs.length} lane(s)`);
  for (const job of jobs) {
    job.targetNode = (await selectBestNode()).node;
    job.gwSourceNode = gwOriginNode;
    job.gwSourceVmid = gwOriginVmid;
    try {
      await insertLane(job);
      await cloneGateway(job);
      await deployWorkstation(job);
      provisioned.push({ user_id: job.user.id, lane_id: job.laneId, vxlan_id: job.vxlanId });
      if (progress) { progress.succeeded++; progress.completed++; recordLaneDone(progress, 1); }
    } catch (err) {
      if (job.laneId) await markLaneError(job.laneId, err.message);
      failed.push({ user_id: job.user.id, reason: err.message });
      if (progress) { progress.failed++; progress.completed++; }
    }
  }
  return { provisioned, failed };
}

/**
 * >3: distribute across nodes, replicate the gateway template, clone gateways
 * per-node (serial within a node), then clone workstations in parallel.
 */
async function batchDeploy(jobs, failed, { gwOriginNode, gwOriginVmid, cloneSem, progress }) {
  // Node assignment.
  let nodes;
  try {
    nodes = await distributeAcrossNodes(proxmoxAPI, jobs.length);
  } catch (e) {
    console.warn(`${LOG} distributeAcrossNodes failed (${e.message}); using best node for all`);
    const best = await selectBestNode();
    nodes = new Array(jobs.length).fill(best.node);
  }
  jobs.forEach((job, i) => { job.targetNode = nodes[i]; });

  // Lane rows up front so the UI shows every user as "deploying".
  for (const job of jobs) await insertLane(job);

  // Phase 1: replicate the gateway template to each target node.
  const uniqueNodes = [...new Set(jobs.map(j => j.targetNode))];
  setPhase(progress, 'gateway_replication', `Replicating gateway template to ${uniqueNodes.length} node(s)`);
  const gwTemplateByNode = await replicateGatewayTemplate(uniqueNodes, gwOriginNode, gwOriginVmid);

  // Phase 2: clone gateways grouped by node — sequential within a node so
  // concurrent LXC clones don't fight the same template lock; nodes in parallel.
  setPhase(progress, 'gateway_cloning', `Cloning ${jobs.length} gateway(s)`);
  const lanesByNode = {};
  for (const job of jobs) {
    job.gwSourceNode = job.targetNode;
    job.gwSourceVmid = gwTemplateByNode[job.targetNode];
    (lanesByNode[job.targetNode] = lanesByNode[job.targetNode] || []).push(job);
  }
  await Promise.all(Object.values(lanesByNode).map(async (nodeJobs) => {
    for (const job of nodeJobs) {
      try { await cloneGateway(job); job._gwOk = true; }
      catch (e) {
        job._gwOk = false;
        await markLaneError(job.laneId, `gateway: ${e.message}`);
        failed.push({ user_id: job.user.id, reason: `gateway: ${e.message}` });
        if (progress) { progress.failed++; progress.completed++; }
        console.error(`${LOG} Gateway clone failed for ${job.user.email}: ${e.message}`);
      }
    }
  }));

  // Phase 3: clone workstations in parallel (bounded by lane concurrency + the
  // shared clone semaphore) for lanes whose gateway came up.
  const wsJobs = jobs.filter(j => j._gwOk);
  const provisioned = [];
  const concurrency = getSchedulingConfig().max_concurrent_lanes;
  if (wsJobs.length) {
    setPhase(progress, 'deploying', `Deploying lanes (${concurrency} at a time)`);
    console.log(`${LOG} Batch: ${wsJobs.length} workstations (lane concurrency ${concurrency}, clones ${cloneSem.max})`);
    const { results } = await runBatch(wsJobs, deployWorkstation, {
      concurrency,
      onProgress: (completed, total, job, result) => {
        if (!progress) return;
        progress.completed++;
        if (result.success) progress.succeeded++; else progress.failed++;
        const lane = progress.lanes[job.laneId];
        if (lane?._startedAt) progress._laneTimes.push(Date.now() - lane._startedAt);
        recordLaneDone(progress, concurrency);
        progress.phase_detail = `Deploying lanes: ${completed}/${total} complete`;
      },
    });
    results.forEach((r, i) => {
      if (r && !r.error) provisioned.push({ user_id: wsJobs[i].user.id, lane_id: wsJobs[i].laneId, vxlan_id: wsJobs[i].vxlanId });
      else failed.push({ user_id: wsJobs[i].user.id, reason: r?.error || 'workstation deploy failed' });
    });
  }

  // Phase 4: drop the temp gateway templates.
  setPhase(progress, 'cleanup', 'Removing temp gateway templates');
  await cleanupTempGatewayTemplates(gwTemplateByNode, gwOriginVmid);

  return { provisioned, failed };
}

// ── teardown ─────────────────────────────────────────────────────────────────

/**
 * Tear down a set of lanes. Ported from the hardened group teardown in
 * routes/admin/groups.js: parallel unprotect + stop, parallel delete, orphan
 * retry rounds, then an orphaned-disk sweep. The naive per-lane sequential
 * version this replaces took minutes for a full class and left disks behind.
 *
 * Removes the lane VMs, their Guacamole connections, their workspace records
 * (cybercore_resource → vm_instance + allocation cascade), their Tailscale
 * devices, and finally the cybercore_lane rows.
 *
 * @param {Array<string>} laneIds
 * @param {object} [opts]
 * @param {number} [opts.concurrency=15]
 * @returns {Promise<{lanes_deleted:number, vms_destroyed:number, orphan_disks_swept:number, errors:Array<string>}>}
 */
async function teardownLanes(laneIds, { concurrency = 15 } = {}) {
  const errors = [];
  if (!Array.isArray(laneIds) || laneIds.length === 0) {
    return { lanes_deleted: 0, vms_destroyed: 0, orphan_disks_swept: 0, errors };
  }

  const laneRows = await cybercoreQuery(
    `SELECT lane_id, vxlan_id, config FROM cybercore_lane WHERE lane_id = ANY($1::uuid[])`,
    [laneIds]
  );
  if (laneRows.rows.length === 0) {
    return { lanes_deleted: 0, vms_destroyed: 0, orphan_disks_swept: 0, errors };
  }

  // Phase 1: enumerate targets.
  const vmsToDestroy = [];
  const vxlanIds = [];
  const guacConnIds = new Set();

  for (const lane of laneRows.rows) {
    const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    if (lane.vxlan_id) vxlanIds.push(lane.vxlan_id);
    if (cfg.guac_connection_id) guacConnIds.add(cfg.guac_connection_id);

    if (Array.isArray(cfg.vms) && cfg.vms.length > 0) {
      for (const vm of cfg.vms) {
        vmsToDestroy.push({ vmid: vm.vm_id, type: vm.type || 'qemu', label: vm.name || `vm-${vm.vm_id}` });
      }
    } else {
      const wsVmid = cfg.workstation_vmid || (lane.vxlan_id ? WORKSTATION_VMID_OFFSET + lane.vxlan_id : null);
      if (wsVmid) vmsToDestroy.push({ vmid: wsVmid, type: cfg.provider_type || 'qemu', label: 'workstation' });
    }
    const gwVmid = cfg.gateway_vmid || cfg.gateway_vm_id || (lane.vxlan_id ? GATEWAY_VMID_OFFSET + lane.vxlan_id : null);
    if (gwVmid) vmsToDestroy.push({ vmid: gwVmid, type: 'lxc', label: 'gateway' });
  }

  // Guac connections registered on the workspace rows, for lanes whose config
  // predates guac_connection_id. Compared as TEXT, not cast to uuid: Postgres
  // does not guarantee AND-evaluation order, so casting metadata->>'lane_id'
  // errors out if ANY resource row in the table holds a non-uuid there.
  const laneIdStrings = laneIds.map(String);
  try {
    const rows = await cybercoreQuery(
      `SELECT vi.metadata->>'guac_connection_id' AS cid
         FROM cybercore_vm_instance vi
         JOIN cybercore_resource r ON r.resource_id = vi.resource_id
        WHERE r.metadata->>'vm_category' = 'lane_vm'
          AND r.metadata->>'lane_id' = ANY($1::text[])`,
      [laneIdStrings]
    );
    for (const r of rows.rows) if (r.cid) guacConnIds.add(r.cid);
  } catch (e) {
    errors.push(`Workspace console lookup: ${e.message}`);
  }

  const [clusterResources, nodeList] = await Promise.all([
    proxmoxAPI('GET', '/api2/json/cluster/resources').catch(() => []),
    proxmoxAPI('GET', '/api2/json/nodes').catch(() => []),
  ]);
  const allNodeNames = (nodeList || []).map(n => n.node);
  if (allNodeNames.length === 0) allNodeNames.push(...getClusterNodes());

  const vmNodeMap = {};
  for (const r of (clusterResources || [])) {
    if (r.type === 'qemu' || r.type === 'lxc') vmNodeMap[r.vmid] = r.node;
  }

  const existingVms = vmsToDestroy.filter(vm => vmNodeMap[vm.vmid]);
  const missing = vmsToDestroy.length - existingVms.length;
  console.log(`${LOG} Teardown: ${vmsToDestroy.length} VMs across ${laneRows.rows.length} lanes (${missing} already gone)`);

  // Phase 2: unprotect + force-stop in parallel, then wait for the stop tasks.
  await Promise.all(existingVms.map(async (vm) => {
    const node = vmNodeMap[vm.vmid];
    try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/config`, { protection: 0 }); } catch (_) {}
    try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/config`, { lock: '' }); } catch (_) {}
  }));

  const stopTasks = [];
  await Promise.all(existingVms.map(async (vm) => {
    const node = vmNodeMap[vm.vmid];
    try {
      const upid = await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/stop`,
        vm.type === 'qemu' ? { timeout: 0 } : {});
      if (upid) stopTasks.push({ node, upid });
    } catch (e) {
      console.warn(`${LOG} Stop failed for ${vm.type} ${vm.vmid} on ${node}: ${e.message}`);
    }
  }));

  const stopDeadline = Date.now() + 30000;
  let pendingStops = [...stopTasks];
  while (pendingStops.length > 0 && Date.now() < stopDeadline) {
    await new Promise(r => setTimeout(r, 3000));
    const stillPending = [];
    for (const task of pendingStops) {
      try {
        const status = await proxmoxAPI('GET', `/api2/json/nodes/${task.node}/tasks/${encodeURIComponent(task.upid)}/status`);
        if (status.status !== 'stopped') stillPending.push(task);
      } catch (_) {}
    }
    pendingStops = stillPending;
  }

  // Phase 3: delete in parallel, trying other nodes if the known one is wrong.
  const buildDeleteUrl = (node, type, vmid) => type === 'lxc'
    ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
    : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1&skiplock=1`;

  const { errors: destroyErrors } = await runBatch(existingVms, async (vm) => {
    const knownNode = vmNodeMap[vm.vmid];
    const nodesToTry = knownNode ? [knownNode, ...allNodeNames.filter(n => n !== knownNode)] : allNodeNames;
    for (const node of nodesToTry) {
      try {
        try {
          await proxmoxAPI('DELETE', buildDeleteUrl(node, vm.type, vm.vmid));
        } catch (_) {
          const fallback = vm.type === 'lxc'
            ? `/api2/json/nodes/${node}/lxc/${vm.vmid}?purge=1&force=1`
            : `/api2/json/nodes/${node}/qemu/${vm.vmid}?purge=1`;
          await proxmoxAPI('DELETE', fallback);
        }
        return;
      } catch (e) {
        if (/unable to find configuration file/i.test(e.message) || /does not exist/i.test(e.message)) return;
        if (node === nodesToTry[nodesToTry.length - 1]) {
          throw new Error(`${vm.type} ${vm.vmid} (${vm.label}): failed on all nodes — ${e.message}`);
        }
      }
    }
  }, { concurrency });
  for (const err of destroyErrors) errors.push(err.error);

  // Phase 4: verify and retry orphans.
  const allTargetVmIds = vmsToDestroy.map(v => v.vmid);
  for (let round = 1; round <= 3; round++) {
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
      const stillAlive = (resources || []).filter(r =>
        (r.type === 'qemu' || r.type === 'lxc') && allTargetVmIds.includes(r.vmid));
      if (stillAlive.length === 0) break;

      console.warn(`${LOG} Teardown round ${round}: ${stillAlive.length} VMs still exist — retrying`);
      await Promise.all(stillAlive.map(async (vm) => {
        try { await proxmoxAPI('PUT', `/api2/json/nodes/${vm.node}/${vm.type}/${vm.vmid}/config`, { protection: 0 }); } catch (_) {}
        try {
          await proxmoxAPI('POST', `/api2/json/nodes/${vm.node}/${vm.type}/${vm.vmid}/status/stop`,
            vm.type === 'qemu' ? { timeout: 0 } : {});
        } catch (_) {}
      }));
      await new Promise(r => setTimeout(r, 8000));
      await Promise.all(stillAlive.map(async (vm) => {
        try {
          try {
            await proxmoxAPI('DELETE', buildDeleteUrl(vm.node, vm.type, vm.vmid));
          } catch (_) {
            const fallback = vm.type === 'lxc'
              ? `/api2/json/nodes/${vm.node}/lxc/${vm.vmid}?purge=1&force=1`
              : `/api2/json/nodes/${vm.node}/qemu/${vm.vmid}?purge=1`;
            await proxmoxAPI('DELETE', fallback);
          }
        } catch (e) {
          if (/unable to find configuration file/i.test(e.message)) return;
          if (round === 3) errors.push(`Orphaned VM ${vm.vmid} on ${vm.node}: ${e.message}`);
        }
      }));
    } catch (e) {
      console.error(`${LOG} Teardown verify round ${round} failed: ${e.message}`);
      break;
    }
  }

  // Phase 5: DB + Guacamole + Tailscale cleanup.
  await Promise.all([
    cybercoreQuery(
      `DELETE FROM cybercore_resource
        WHERE metadata->>'vm_category' = 'lane_vm'
          AND metadata->>'lane_id' = ANY($1::text[])`,
      [laneIdStrings]
    ).catch(e => errors.push(`Workspace resource cleanup: ${e.message}`)),

    ...(process.env.GUAC_ENABLED === 'true'
      ? [...guacConnIds].map(cid =>
          guacAPI('DELETE', `/connections/${encodeURIComponent(cid)}`)
            .catch(e => errors.push(`Guac connection ${cid}: ${e.message}`)))
      : []),

    ...vxlanIds.map(vxlanId => tailscale.deleteLaneDevices({ vxlanId }).catch(() => {})),
  ]);

  // Phase 6: sweep orphaned disks the delete left behind.
  const destroyedVmIdSet = new Set(allTargetVmIds);
  let orphanDisksSwept = 0;
  const sweptVolids = new Set();
  try {
    const discoveries = await Promise.all(allNodeNames.map(async (node) => {
      const found = [];
      let nodeStorages;
      try { nodeStorages = await proxmoxAPI('GET', `/api2/json/nodes/${node}/storage`); }
      catch (_) { return found; }

      for (const s of nodeStorages || []) {
        if (s.content && !s.content.includes('images')) continue;
        let contents;
        try {
          contents = await proxmoxAPI('GET', `/api2/json/nodes/${node}/storage/${s.storage}/content?content=images`);
        } catch (_) { continue; }
        for (const item of contents || []) {
          const match = item.volid?.match(/vm-(\d+)-(disk|cloudinit)/);
          if (!match) continue;
          if (!destroyedVmIdSet.has(parseInt(match[1], 10))) continue;
          found.push({ node, storage: s.storage, volid: item.volid, kind: match[2] });
        }
      }
      return found;
    }));

    for (const d of discoveries.flat()) {
      if (sweptVolids.has(d.volid)) continue;
      sweptVolids.add(d.volid);
      let deleted = false;
      let lastErr = null;
      for (let attempt = 1; attempt <= 3 && !deleted; attempt++) {
        try {
          await proxmoxAPI('DELETE',
            `/api2/json/nodes/${d.node}/storage/${d.storage}/content/${encodeURIComponent(d.volid)}`);
          orphanDisksSwept++;
          deleted = true;
        } catch (e) {
          lastErr = e;
          if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
        }
      }
      if (!deleted && lastErr) errors.push(`Disk sweep ${d.volid}: ${lastErr.message}`);
    }
  } catch (e) {
    errors.push(`Disk sweep: ${e.message}`);
  }

  // Finally, the lane rows themselves.
  const del = await cybercoreQuery(
    `DELETE FROM cybercore_lane WHERE lane_id = ANY($1::uuid[])`,
    [laneIds]
  );

  console.log(
    `${LOG} Teardown complete: ${del.rowCount} lanes, ${existingVms.length} VMs, ` +
    `${orphanDisksSwept} orphan disks, ${errors.length} errors`
  );
  return {
    lanes_deleted: del.rowCount,
    vms_destroyed: existingVms.length,
    orphan_disks_swept: orphanDisksSwept,
    errors,
  };
}

module.exports = {
  GATEWAY_VMID_OFFSET,
  WORKSTATION_VMID_OFFSET,
  WORKSTATION_OCTET,
  CONSOLE_PROTOCOLS,
  allocateVxlanIds,
  resolveConsole,
  resolveNicModel,
  deployLanes,
  teardownLanes,
  readProgress,
};
