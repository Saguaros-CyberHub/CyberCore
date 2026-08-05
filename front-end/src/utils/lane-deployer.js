/**
 * ============================================================================
 * LANE DEPLOYER
 * ----------------------------------------------------------------------------
 * Deploys workstation lanes (gateway LXC + one or more VMs) for users that
 * ALREADY EXIST, out of a caller-supplied VXLAN block. This is the sequence that
 * routes/admin/groups.js runs for its Kali attack box, lifted out of that
 * route's group/challenge/user-creation coupling so any caller can reuse it.
 *
 * Why this module exists: groups.js, routes/admin/lanes.js, and the CLE plugin
 * each inlined the same clone-and-wire sequence. There was no "deploy one lane
 * for an existing user" primitive to call, so the third copy drifted and lost
 * the non-obvious details that actually make a lane reachable. Those details
 * are the whole point of this file:
 *
 *   1. Each VM is pinned to <lane-base>.<50 + slot> by a deterministic MAC plus a
 *      dnsmasq reservation written into the gateway. The gateway template ships
 *      `dhcp-host=kali,<base>.50` — a HOSTNAME match, so Kali lands on .50 for
 *      free and nothing else does. A Windows template announces its own name
 *      and takes a random lease, which is why reserving by MAC is required for
 *      "any template" to work — and the only thing that works at all for slots
 *      past the one the template bakes.
 *   2. The console target is the gateway's WAN transit IP, never the lane-local
 *      IP. guacd runs on the orchestrator's Docker bridge and has no route into
 *      10.<vxh>.<vxl>.0/24; the gateway's wan0 DNAT is the only way in. Slot N is
 *      published on <protocol base port> + N.
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
const { guacAPI } = require('./guacamole');
const guacCreds = require('./guac-credentials');
const { generatePassword } = require('./password-generator');
const { macForOctet, INFRA_IP_OCTETS } = require('./goad-deploy');
const nodeSsh = require('./node-ssh');
const tailscale = require('./tailscale');

const GATEWAY_VMID_OFFSET = 100000;     // gateway LXC = 100000 + vxlanId (matches groups.js)
const WORKSTATION_VMID_OFFSET = 600000; // slot-0 workstation = 600000 + vxlanId
const TEMP_GW_TEMPLATE_BASE = 169300;   // per-node temp gateway template copies (clear of groups.js' 169200)
// GOAD controller = 200000 + vxlanId. Mirrors goad-deploy.js deployController();
// teardown needs it because the controller is never recorded on the lane.
const GOAD_CONTROLLER_VMID_OFFSET = 200000;

// VMIDs for workstations in slots 1+. Deliberately NOT `base + slot*step + vxlanId`
// like attached-modules.js: VXLAN blocks start at 10000 and grow without bound
// (lab-network-provision.allocateVxlanBlock), so any slot*step encoding collides
// as soon as ids exceed the step — slot 0/vxlan 20000 and slot 1/vxlan 10000 both
// land on the same number. These are scanned for free ids and RECORDED on the
// lane instead, which teardown already prefers over derived values.
const EXTRA_WS_VMID_BASE = 300000;
const EXTRA_WS_VMID_MAX  = 399999;

// The lane octets workstations land on: slot 0 → .50, slot 1 → .51, …
//
// Slot 0 is INFRA_IP_OCTETS.Kali on purpose. It is the value the gateway template
// bakes its wan0:3389 DNAT against (KALI_OCTET=50 in bake-lane-gateway-v2.sh) and
// the one groups.js pins its attack box to, so a plain RDP template in slot 0
// still works even if our own DNAT install fails. Slots 1+ have no baked
// equivalent — see applyGatewayWorkstationAccess.
//
// The band ends before .100, where attached-modules.js starts allocating
// (ATTACHED_IP_OCTET_MIN), and starts above GOAD's lab hosts (.10–.12) and the
// .1 gateway / .5 controller reservations.
const WORKSTATION_OCTET_BASE = INFRA_IP_OCTETS.Kali;
const WORKSTATION_MAX_SLOTS  = 30;                  // .50 – .79
const WORKSTATION_OCTET = WORKSTATION_OCTET_BASE;   // back-compat alias: slot 0

// Console protocols a template may expose, and the port the gateway publishes
// slot 0 on. SSH is remapped because the gateway's own sshd owns wan0:22 —
// DNATing that would black-hole access to the gateway itself. Slot N is published
// on wanPort + N (see consoleForSlot), which keeps each protocol's slots inside
// its own band: rdp 3389–3418, vnc 5900–5929, ssh 2222–2251.
const CONSOLE_PROTOCOLS = {
  rdp: { guestPort: 3389, wanPort: 3389 },
  vnc: { guestPort: 5900, wanPort: 5900 },
  ssh: { guestPort: 22,   wanPort: 2222 },
};

// One file for the whole lane, rewritten as a unit. It must NOT be split per
// workstation: dnsmasq reads every *.conf in the directory, so partial files
// would leave a stale reservation behind whenever a lane is re-provisioned with
// fewer machines.
const DNSMASQ_RESERVATION_PATH = '/etc/dnsmasq.d/lane-workstation.conf';
const LOG = '[LaneDeployer]';

// ── generic helpers ──────────────────────────────────────────────────────────

function vmApiBase(node, vmid, providerType) {
  return `/api2/json/nodes/${node}/${providerType === 'lxc' ? 'lxc' : 'qemu'}/${vmid}`;
}

// ── workstation slots ────────────────────────────────────────────────────────

/** Lane octet for a workstation slot. Throws rather than silently overrunning
 *  into the attached-module band at .100. */
function octetForSlot(slot) {
  if (!Number.isInteger(slot) || slot < 0 || slot >= WORKSTATION_MAX_SLOTS) {
    throw new Error(
      `workstation slot ${slot} out of range [0, ${WORKSTATION_MAX_SLOTS}) — ` +
      `the octet band is .${WORKSTATION_OCTET_BASE}–.${WORKSTATION_OCTET_BASE + WORKSTATION_MAX_SLOTS - 1}`
    );
  }
  return WORKSTATION_OCTET_BASE + slot;
}

/**
 * Where the gateway publishes this slot's console. Slot 0 keeps the template's
 * own wanPort so the baked wan0:3389 DNAT still describes it; every later slot
 * shifts up by its slot number — unless the template pinned an explicit
 * console_wan_port, which is honoured verbatim (see resolveConsole).
 */
function consoleForSlot(con, slot) {
  if (con.wanPortPinned) return { ...con };
  return { ...con, wanPort: con.wanPort + slot };
}

/**
 * VMIDs handed out to slots 1+ but not yet visible in the cluster, so two
 * overlapping deploys can't pick the same id in the window between the scan and
 * the clone that claims it.
 *
 * Entries expire: once the clone exists the cluster scan sees it anyway, and a
 * clone that has not appeared within the TTL has failed. Without the expiry this
 * map would only ever grow, and a long-lived process would eventually report the
 * band exhausted while the cluster had plenty of free ids.
 */
const _reservedWsVmids = new Map(); // vmid → Date.now() when handed out
const RESERVED_VMID_TTL_MS = 15 * 60 * 1000;

/**
 * Pick `count` VMIDs that are free cluster-wide for slot-1+ workstations.
 *
 * Slot 0 does NOT come through here — it stays at WORKSTATION_VMID_OFFSET +
 * vxlanId so every lane deployed before this file grew slots keeps the exact
 * VMID it already has recorded, and operators keep the 600000+vxlan shorthand.
 */
async function reserveWorkstationVmids(count) {
  if (count <= 0) return [];
  let taken = new Set();
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    taken = new Set((resources || []).map(r => Number(r.vmid)));
  } catch (e) {
    // Fail loudly: guessing here means a clone lands on a VMID that already
    // belongs to somebody else's machine.
    throw new Error(`Could not list cluster VMIDs to allocate workstation slots: ${e.message}`);
  }
  const now = Date.now();
  for (const [id, at] of _reservedWsVmids) {
    if (now - at > RESERVED_VMID_TTL_MS) _reservedWsVmids.delete(id);
  }

  const ids = [];
  for (let id = EXTRA_WS_VMID_BASE; ids.length < count && id <= EXTRA_WS_VMID_MAX; id++) {
    if (taken.has(id) || _reservedWsVmids.has(id)) continue;
    _reservedWsVmids.set(id, now);
    ids.push(id);
  }
  if (ids.length < count) {
    throw new Error(
      `Out of workstation VMIDs in [${EXTRA_WS_VMID_BASE}, ${EXTRA_WS_VMID_MAX}] — ` +
      `needed ${count}, found ${ids.length}`
    );
  }
  return ids;
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
  const pinnedWanPort = Number(meta.console_wan_port) || null;
  const wanPort = pinnedWanPort || (guestPort === 22 ? base.wanPort : guestPort);
  // A pinned port means "publish this image on exactly this gateway port", so
  // consoleForSlot leaves it alone instead of shifting it by slot. Two slots that
  // then want the same port are a real conflict, and deployLanes rejects them
  // rather than letting the second DNAT shadow the first.
  return { protocol, guestPort, wanPort, wanPortPinned: pinnedWanPort !== null };
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

// ── hardware sizing ──────────────────────────────────────────────────────────

/**
 * Bounds for caller-supplied workstation sizing. These are sanity rails, not a
 * quota: a value outside them is almost always a mistyped form (4 MiB of RAM,
 * 512 cores), and Proxmox would accept it and hand the student a machine that
 * cannot boot. Cluster headroom is a separate concern — deployment-guards.js
 * still gates the deploy on node capacity.
 */
const RESOURCE_LIMITS = {
  cores:     { min: 1,    max: 32     },  // vCPUs
  memory_mb: { min: 1024, max: 131072 },  // MiB, as Proxmox counts it
  disk_gb:   { min: 8,    max: 2048   },  // GiB, boot disk only
};

/**
 * Validate a { cores, memory_mb, disk_gb } override.
 *
 * Every field is optional, and an omitted one means "leave the template's own
 * sizing alone" — which is why unset fields are dropped rather than defaulted.
 * Returns { resources, errors }; a route turns a non-empty `errors` into a 400
 * instead of discovering the bad value partway through a class-wide deploy.
 */
function normalizeResourceSpec(input) {
  const errors = [];
  if (input == null) return { resources: null, errors };
  if (typeof input !== 'object' || Array.isArray(input)) {
    return { resources: null, errors: ['resources must be an object'] };
  }

  const resources = {};
  for (const [field, { min, max }] of Object.entries(RESOURCE_LIMITS)) {
    const raw = input[field];
    if (raw === undefined || raw === null || raw === '') continue;
    const n = Number(raw);
    if (!Number.isInteger(n)) { errors.push(`${field} must be a whole number`); continue; }
    if (n < min || n > max) { errors.push(`${field} must be between ${min} and ${max}`); continue; }
    resources[field] = n;
  }
  return { resources: Object.keys(resources).length ? resources : null, errors };
}

const DISK_KEY_RE = /^(scsi|virtio|sata|ide)(\d+)$/;
const SIZE_UNIT_GB = { K: 1 / 1048576, M: 1 / 1024, G: 1, T: 1024 };

// Controller preference when a template declares no boot order — the same
// order Proxmox itself defaults to, so scsi0 wins over sata0 rather than
// whatever sorts first alphabetically.
const DISK_BUS_ORDER = ['scsi', 'virtio', 'sata', 'ide'];

/** Size in GiB from a Proxmox volume string's `size=` field, or null. */
function diskSizeGb(volume) {
  const m = /(?:^|,)size=(\d+(?:\.\d+)?)([KMGT])?/.exec(String(volume || ''));
  if (!m) return null;
  return Number(m[1]) * (SIZE_UNIT_GB[m[2] || 'G'] || 1);
}

/**
 * The volume to grow: the guest's root/boot disk. QEMU templates name it
 * whatever the image was built with (scsi0, virtio0, sata0…), so trust the
 * config's own `bootdisk`, then its boot order, then the first disk by
 * controller preference. Never the cloud-init drive or a CD-ROM — those are a
 * few MiB of ISO and the resize call on them just fails. LXC has exactly one:
 * rootfs.
 */
function pickBootDisk(cfg, providerType) {
  if (providerType === 'lxc') {
    return cfg.rootfs ? { key: 'rootfs', currentGb: diskSizeGb(cfg.rootfs) } : null;
  }
  const isDisk = (k) => DISK_KEY_RE.test(k) && typeof cfg[k] === 'string'
    && !/cloudinit/i.test(cfg[k]) && !/media=cdrom/i.test(cfg[k]);

  let key = null;
  if (cfg.bootdisk && isDisk(cfg.bootdisk)) key = cfg.bootdisk;
  if (!key && typeof cfg.boot === 'string') {
    key = (/order=([^,]+)/.exec(cfg.boot)?.[1] || '').split(';').find(isDisk) || null;
  }
  if (!key) {
    const rank = (k) => {
      const [, bus, idx] = DISK_KEY_RE.exec(k);
      return DISK_BUS_ORDER.indexOf(bus) * 1000 + Number(idx);
    };
    key = Object.keys(cfg).filter(isDisk).sort((a, b) => rank(a) - rank(b))[0] || null;
  }
  return key ? { key, currentGb: diskSizeGb(cfg[key]) } : null;
}

/**
 * Apply the caller's CPU / RAM / disk sizing to a freshly cloned workstation.
 *
 * MUST run before the guest's first boot. cloud-init's growpart extends the root
 * filesystem only on the boot where it first sees the larger disk; resize a
 * running guest and the block device grows while the filesystem stays put.
 *
 * Returns { applied, warnings }. Never throws: an under-sized workstation is
 * still a workstation the student can connect to, and failing a whole class
 * deploy over one config PUT is the worse outcome. The warnings ride back on
 * cybercore_lane.config so the instructor sees what didn't take instead of
 * silently getting the template's defaults.
 */
async function applyResources({ node, vmid, providerType, resources, laneName }) {
  const applied = {};
  const warnings = [];
  if (!resources) return { applied, warnings };

  let cfg = {};
  try {
    cfg = await proxmoxAPI('GET', `${vmApiBase(node, vmid, providerType)}/config`) || {};
  } catch (err) {
    warnings.push(`could not read VM config for sizing: ${err.message}`);
    return { applied, warnings };
  }

  // CPU + RAM in one PUT.
  const patch = {};
  if (resources.cores) patch.cores = resources.cores;
  if (resources.memory_mb) {
    patch.memory = resources.memory_mb;
    // Proxmox rejects a config whose balloon floor exceeds `memory`, so a
    // template that ships ballooning (the Windows images here do) would fail the
    // whole PUT when RAM is sized below that floor. Pull the floor down with it
    // rather than setting balloon=0, which would disable ballooning outright and
    // hand the host back none of the guest's idle RAM.
    const balloon = Number(cfg.balloon);
    if (Number.isFinite(balloon) && balloon > 0 && balloon > resources.memory_mb) {
      patch.balloon = resources.memory_mb;
    }
  }
  if (Object.keys(patch).length) {
    try {
      await proxmoxAPI('PUT', `${vmApiBase(node, vmid, providerType)}/config`, patch);
      if (patch.cores) applied.cores = patch.cores;
      if (patch.memory) applied.memory_mb = patch.memory;
    } catch (err) {
      warnings.push(`CPU/RAM sizing failed (${err.message}) — using the template's defaults`);
      console.warn(`${LOG} ${laneName}: CPU/RAM sizing failed: ${err.message}`);
    }
  }

  // Disk is a separate resize endpoint, and grow-only: Proxmox cannot shrink a
  // volume, so a target at or below the image's own size is a no-op rather than
  // an error — "smaller than the template" can only mean the template's size.
  if (resources.disk_gb) {
    const disk = pickBootDisk(cfg, providerType);
    if (!disk) {
      warnings.push('could not identify a boot disk to resize');
    } else if (disk.currentGb != null && resources.disk_gb <= disk.currentGb) {
      applied.disk_gb = disk.currentGb;
      if (resources.disk_gb < disk.currentGb) {
        warnings.push(
          `disk stays at the template's ${disk.currentGb}G — ${resources.disk_gb}G would shrink it, which Proxmox cannot do`
        );
      }
    } else {
      try {
        const upid = await proxmoxAPI('PUT', `${vmApiBase(node, vmid, providerType)}/resize`, {
          disk: disk.key,
          size: `${resources.disk_gb}G`,
        });
        if (typeof upid === 'string' && upid.startsWith('UPID')) await waitForTask(node, upid, 300000);
        applied.disk_gb = resources.disk_gb;
      } catch (err) {
        warnings.push(`disk resize to ${resources.disk_gb}G failed (${err.message}) — using the template's disk`);
        console.warn(`${LOG} ${laneName}: disk resize failed: ${err.message}`);
      }
    }
  }

  if (Object.keys(applied).length) {
    console.log(
      `${LOG} ${laneName}: sized to ` +
      `${applied.cores ?? 'template'} core(s), ${applied.memory_mb ?? 'template'} MiB, ` +
      `${applied.disk_gb ?? 'template'} GiB disk`
    );
  }
  return { applied, warnings };
}

/**
 * Credentials the user will present to the workstation itself.
 *   - A template that bakes its own account AND its own password declares both
 *     as metadata.default_rdp_user / default_rdp_pass; we use them verbatim and
 *     inject nothing.
 *   - A template whose cloud-init agent is pinned to one account declares it as
 *     metadata.cloud_init_user: that account's name, with a fresh password per
 *     lane.
 *   - Otherwise mint a per-user account and hand it to the guest through
 *     cloud-init (ciuser/cipassword), exactly like groups.js does for Kali.
 */
function resolveWorkstationCredentials(template, user) {
  const meta = template.metadata || {};
  if (meta.default_rdp_user) {
    return { username: meta.default_rdp_user, password: meta.default_rdp_pass || null, source: 'template' };
  }
  // Some images pin their cloud-init agent to a single account at BAKE time —
  // cloudbase-init resolves the account from CONF.username, fixed when the image
  // was built. Such an agent can only set that account's PASSWORD on first boot;
  // it cannot create or rename one after templating. Name anyone else in ciuser
  // and the generated password still lands on the baked account while Guacamole
  // authenticates as a user that does not exist — which surfaces as a plain RDP
  // login failure, not as anything that points at cloud-init.
  //
  // So: keep the image's account name, vary only the password. Per-lane isolation
  // is unaffected — one VM, one account, one secret that only its owner is given.
  if (meta.cloud_init_user) {
    return { username: meta.cloud_init_user, password: generatePassword(), source: 'cloudinit' };
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
 * Pin every workstation in the lane to its slot's address and publish each one's
 * console port on the gateway's WAN IP. Must run BEFORE any workstation first
 * boots, so their very first DHCPREQUEST already has a reservation waiting.
 *
 * Renders the gateway's state from the FULL workstation list rather than
 * patching it per machine, because both halves are whole-file/whole-chain
 * operations:
 *   - dnsmasq reservations live in one file at a fixed path, so a per-workstation
 *     write would overwrite the previous machine's reservation;
 *   - the iptables step strips every LANE-CONSOLE rule before re-adding, so a
 *     per-workstation call would delete the previous machine's DNAT.
 * Both were invisible while a lane held exactly one machine.
 *
 * Needs a shell inside the gateway LXC, and Proxmox has no LXC exec API — so
 * this goes over `pct` via SSH to the node, the same channel
 * goad-deploy.writeDhcpReservations and attached-modules.writeDhcpForModule use.
 * Throws if that isn't wired up; the caller decides whether that is survivable
 * (it is for slot 0 alone — see deployLaneWorkstations).
 *
 * @param {Array} workstations [{ slot, mac, ip, hostname, console:{guestPort,wanPort} }]
 */
async function applyGatewayWorkstationAccess({ node, gatewayVmid, workstations }) {
  // The gateway's main config (rewritten fresh every boot by the firstboot
  // script — see bake-lane-gateway-v2.sh) bakes in a hostname-matched
  // reservation for this SAME address: `dhcp-host=kali,<base>.50`, so a Kali
  // guest lands on .50 with no per-deploy setup. Our own MAC-based reservations
  // below cover every workstation on this lane — Kali included, and more
  // precisely — but dnsmasq refuses to start at all when two dhcp-host lines
  // claim the same IP, regardless of whether they're matched by hostname or MAC.
  // This gateway is dedicated to this one lane and never needs the baked-in
  // fallback, so neutralize it before writing ours. Comment rather than delete:
  // idempotent on re-provision, and legible if anyone inspects the file by hand.
  await nodeSsh.pctExec(node, gatewayVmid, ['/bin/sh', '-c',
    `sed -i 's/^dhcp-host=kali,/#dhcp-host=kali,/' /etc/dnsmasq.conf`,
  ]);

  const lines = [
    '# Lane workstation reservations — generated by lane-deployer.js',
    '# Pins each machine to its slot address so the gateway console DNAT has a',
    '# fixed destination regardless of which OS the template runs.',
  ];
  for (const ws of workstations) {
    lines.push(`dhcp-host=${ws.mac},${ws.ip},${ws.hostname}`);
  }
  await nodeSsh.pctPushFromString(node, gatewayVmid, lines.join('\n') + '\n', DNSMASQ_RESERVATION_PATH);
  await nodeSsh.pctExec(node, gatewayVmid, ['/bin/sh', '-c',
    'rc-service dnsmasq restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true',
  ]);

  // wan0:<wanPort> → <slot ip>:<guestPort>, one pair per workstation. The v2
  // gateway template already bakes this for 3389 → .50, but only for that one
  // port and address — re-adding it is harmless (same destination) and it is the
  // only path for a non-RDP template or any slot past 0. Strip our own tag first
  // so a re-provision doesn't stack duplicates, then persist so the rules survive
  // a gateway reboot (Alpine reloads /etc/iptables/rules-save at boot, before
  // firstboot re-adds its own rules).
  const rules = ['iptables-save | grep -v "LANE-CONSOLE" | iptables-restore || true'];
  for (const ws of workstations) {
    const { guestPort, wanPort } = ws.console;
    rules.push(
      `iptables -t nat -A PREROUTING -i wan0 -p tcp --dport ${wanPort} ` +
        `-m comment --comment "LANE-CONSOLE" -j DNAT --to-destination ${ws.ip}:${guestPort}`
    );
    // Position 2 keeps this above the base template's perimeter DROP block
    // (position 1 is the global RELATED,ESTABLISHED ACCEPT). Fall back to a
    // plain insert if the chain is shorter than that — iptables rejects an
    // index past the end of the chain, and `;` separators would hide it.
    rules.push(
      `iptables -I FORWARD 2 -i wan0 -o lan0 -p tcp -d ${ws.ip} --dport ${guestPort} ` +
        `-m comment --comment "LANE-CONSOLE" -j ACCEPT ` +
        `|| iptables -I FORWARD -i wan0 -o lan0 -p tcp -d ${ws.ip} --dport ${guestPort} ` +
        `-m comment --comment "LANE-CONSOLE" -j ACCEPT`
    );
  }
  rules.push('mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules-save');
  await nodeSsh.pctExec(node, gatewayVmid, ['/bin/sh', '-c', rules.join('; ')]);
}

// ── Guacamole ────────────────────────────────────────────────────────────────

/**
 * Make sure the user has a Guacamole account before we grant it permissions.
 *
 * Deliberately does NOT read or rotate the password: the caller only needs the
 * account to exist, and rotating it here would invalidate the credential the
 * user is already holding. Creating one when it's missing still records the
 * password, so staff can hand it back later.
 */
async function ensureGuacUser(userId, email) {
  if (!email) return false;
  return guacCreds.ensureGuacUser(userId, email).catch((e) => {
    console.warn(`${LOG} Could not ensure a Guacamole account for ${email}: ${e.message}`);
    return false;
  });
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
      await ensureGuacUser(user.id, user.email);
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
async function registerWorkspaceVm({ job, template, workstationVmid, providerType, guacConnId }) {
  const { laneId, user, vxlanId, targetNode, moduleKey, laneConfig } = job;
  const slug = String(user.email || user.id).split('@')[0].replace(/[^a-z0-9-]/gi, '-').toLowerCase();
  const displayName = template.os_name || template.template_key || 'workstation';
  // (module_key, name) is UNIQUE — suffix with the cluster-unique VMID so the
  // same template deployed to N lanes, or to two slots of ONE lane, can't
  // collide on the base name.
  //
  // The VMID is appended AFTER truncating the prefix, not truncated along with
  // it. Trimming the whole string instead drops the discriminator once
  // template_key + slug reaches 80 chars, and the two rows collide, hit the
  // UNIQUE constraint, and lose their workspace registration — leaving a running
  // machine that never appears on the owner's dashboard, with only a warning in
  // the log to explain it.
  const vmidSuffix = `-${workstationVmid}`;
  const name = `${template.template_key || 'workstation'}-${slug}`
    .substring(0, 80 - vmidSuffix.length) + vmidSuffix;

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

/** Serializable projection of a workstation plan, for cybercore_lane.config. */
function workstationConfigEntry(ws) {
  return {
    slot: ws.slot,
    vmid: ws.vmid,
    octet: ws.octet,
    ip: ws.ip,
    mac: ws.mac,
    hostname: ws.hostname,
    provider_type: ws.providerType,
    template_id: ws.template.id || null,
    template_name: ws.template.os_name || ws.template.template_key,
    console_protocol: ws.console.protocol,
    console_port: ws.console.wanPort,
  };
}

/**
 * Create the lane row (status 'deploying') with the seed config. Sets job.laneId.
 *
 * Writes the PLANNED workstation list — VMIDs included — before anything is
 * cloned. Teardown reads it, so a deploy that dies partway through still leaves
 * every id it might have created on the record; deriving them afterwards is
 * impossible for slots 1+, whose VMIDs are allocated rather than computed.
 *
 * Slot 0 also lands on the flat `workstation_*` / `console_*` keys it has always
 * used. The CLE read paths (plugins/cle/routes/vms.js, labs.js) and the group
 * teardown still read those, and a lane with one machine should look exactly the
 * way it did before this file grew slots.
 */
async function insertLane(job) {
  const {
    user, vxlanId, vnet, targetNode, net, workstations,
    moduleKey, subnetScheme, laneName, laneConfig, resources,
  } = job;
  const primary = workstations[0];
  const ins = await cybercoreQuery(
    `INSERT INTO cybercore_lane (user_id, module_key, name, status, vxlan_id, config, created_at, updated_at)
     VALUES ($1, $2, $3, 'deploying', $4, $5::jsonb, NOW(), NOW())
     RETURNING lane_id`,
    [user.id, moduleKey, laneName, vxlanId, JSON.stringify({
      ...laneConfig,
      template_id: primary.template.id || null,
      template_name: primary.template.os_name || primary.template.template_key,
      provider_type: primary.providerType,
      subnet_scheme: subnetScheme,
      vnet: vnet.vnet,
      gateway_vmid: GATEWAY_VMID_OFFSET + vxlanId,
      workstation_vmid: primary.vmid,
      node: targetNode,
      user_email: user.email,
      lane_subnet_base: net.lan.base3,
      gateway_wan_ip: net.wan.ip.split('/')[0],
      workstation_ip: primary.ip,
      console_protocol: primary.console.protocol,
      console_port: primary.console.wanPort,
      workstations: workstations.map(workstationConfigEntry),
      // Per-slot lease confirmation, seeded so confirmWorkstationIp's jsonb_set
      // has a parent object to write into. Kept as flat maps rather than fields
      // on workstations[] so N concurrent confirmations can't clobber each other.
      ws_ip: {},
      ws_ip_confirmed: {},
      // What was asked for. `resources` (what was achieved) lands at the end of
      // deployLaneWorkstations; keeping both makes a partial apply legible.
      ...(resources ? { requested_resources: resources } : {}),
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
 * Clone + configure + start ONE workstation and wire up its console. Returns the
 * record the lane config keeps for that slot; throws on failure, leaving the
 * lane bookkeeping to deployLaneWorkstations.
 *
 * The gateway's DHCP reservation and console DNAT are NOT set up here — they are
 * a whole-lane operation that must already have run (see
 * applyGatewayWorkstationAccess), because they are rendered from every slot at
 * once.
 */
async function deployOneWorkstation(job, ws) {
  const {
    user, vxlanId, vnet, targetNode, cloneSem, net, laneName, description, progress, guacParent,
  } = job;
  const {
    slot, template, providerType, vmid: workstationVmid, mac, ip: workstationIp,
    hostname, console: con, sourceNode: wsSourceNode, resources,
  } = ws;
  const gatewayVmid = GATEWAY_VMID_OFFSET + vxlanId;
  const laneBase = net.lan.base3;
  const gatewayWanIp = net.wan.ip.split('/')[0];
  const label = job.workstations.length > 1 ? `${laneName} slot ${slot}` : laneName;

  // 2. Clone the template. (1 is the lane-wide gateway wiring, already done.)
  const cloneBody = {
    newid: workstationVmid,
    ...(providerType === 'lxc' ? { hostname } : { name: hostname }),
    full: 1,
    target: targetNode,
    description: `Lane workstation (slot ${slot})\nUser: ${user.email}\nLane: ${job.laneId}${description ? `\n${description}` : ''}`,
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

  // 3b. Apply the caller's CPU / RAM / disk sizing, before the guest's first
  //     boot so cloud-init's growpart sees the resized disk (see applyResources).
  const sizing = await applyResources({
    node: targetNode, vmid: workstationVmid, providerType, resources, laneName: label,
  });

  // 4. Hand the user their login through cloud-init when the template carries a
  //    cloud-init drive (Linux cloud images, Windows + cloudbase-init).
  //    Addressing stays on DHCP so the reservation decides the IP — a static
  //    ipconfig0 races the guest's own DHCP client and loses (the exact bug
  //    groups.js hit pinning Kali statically).
  let creds = resolveWorkstationCredentials(template, user);
  if (providerType === 'qemu' && creds.source === 'cloudinit' && template.metadata?.cloud_init !== false) {
    let ciDrive = null;
    try { ciDrive = await findCloudInitDrive(targetNode, workstationVmid); }
    catch (e) { console.warn(`${LOG} cloud-init probe failed for ${label}: ${e.message}`); }

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
      console.log(`${LOG} ${label}: template has no cloud-init drive — using the template's own accounts`);
      creds = { username: null, password: null, source: 'baked' };
    }
  } else if (providerType === 'lxc' && creds.source === 'cloudinit') {
    creds = { username: null, password: null, source: 'baked' };
  }

  // 5. Boot it.
  if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'starting';
  await proxmoxAPI('POST', `${vmApiBase(targetNode, workstationVmid, providerType)}/status/start`);

  // 6. Console. ALWAYS the gateway's WAN transit IP (e.g. 100.100.60.136) —
  //    never the lane-local address. guacd runs on the orchestrator's Docker
  //    bridge with no route into 10.<vxh>.<vxl>.0/24, so the gateway's wan0
  //    DNAT is the only way in. This is how every working lane on this cluster
  //    connects; a console pointed at the lane IP is dead on arrival.
  //
  //    That holds even when our own DNAT install failed, but ONLY for slot 0 on
  //    the template's own port: the v2 gateway bakes wan0:3389 -> <base>.50 and
  //    nothing else. deployLaneWorkstations refuses to get this far with a
  //    failed gateway and more than one slot, so the fallback below is always
  //    describing a single-machine lane.
  const consoleHost = gatewayWanIp;
  const consolePort = con.wanPort;
  let consoleVia = job._gatewayAccessOk ? 'gateway' : 'gateway-baked-dnat';
  if (!job._gatewayAccessOk) {
    if (con.protocol === 'rdp' && consolePort === CONSOLE_PROTOCOLS.rdp.wanPort) {
      // Do NOT read this as "degraded but fine". The baked DNAT's destination is
      // fixed at <base>.50, and the only thing that puts a guest there is the
      // DHCP reservation we just failed to write. The gateway template also
      // ships `dhcp-host=kali,<base>.50`, but that matches on the DHCP CLIENT
      // HOSTNAME, and Proxmox takes the guest hostname from the VM name — which
      // here is the lane name, never "kali" (the same trap documented in
      // challenge-lane-deployer.writeLaneReservations). So this path works only
      // for an image that keeps a baked hostname of exactly "kali" AND has no
      // cloud-init drive to rename it. Anything else takes a pool lease and the
      // console connects to nothing; confirmWorkstationIp catches that ~45s
      // later and downgrades the lane to 'unreachable'.
      console.warn(
        `${LOG} ${label}: gateway config failed — falling back to the template's baked ` +
        `wan0:3389 DNAT, which only reaches ${laneBase}.${WORKSTATION_OCTET_BASE}. Unless this ` +
        `image announces itself to DHCP as "kali", it will take a pool lease and the console ` +
        `will NOT connect. Fix PROXMOX_SSH_KEY / PROXMOX_SSH_USER and re-provision.`
      );
    } else {
      consoleVia = 'unreachable';
      console.error(
        `${LOG} ${label}: gateway config failed and ${con.protocol}:${consolePort} has no baked ` +
        `DNAT — this console will NOT connect until a rule for port ${consolePort} ` +
        `is added on gateway ${gatewayVmid}. Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER.`
      );
    }
  }
  const guacConnId = await createGuacConnection({
    connName: `${laneName}-${workstationVmid}`,
    user, template, creds, parentIdentifier: guacParent,
    hostname: consoleHost, port: consolePort, protocol: con.protocol,
  });

  // 7. Surface it on the owner's own dashboard.
  const resourceId = await registerWorkspaceVm({
    job, template, workstationVmid, providerType, guacConnId,
  });

  // 8. Confirm the guest actually took the reserved lease, in the background.
  //    Purely diagnostic — never blocks the deploy or the console.
  confirmWorkstationIp(job, slot, workstationVmid, providerType, workstationIp);

  console.log(
    `${LOG} Lane ${job.laneId} slot ${slot} up (vxlan ${vxlanId}, node ${targetNode}, ` +
    `ws ${workstationVmid} @ ${workstationIp}, ${con.protocol} via ${consoleHost}:${consolePort})`
  );

  return {
    ...workstationConfigEntry(ws),
    console_via: consoleVia,
    console_host: consoleHost,
    guac_connection_id: guacConnId,
    workspace_resource_id: resourceId,
    ...(Object.keys(sizing.applied).length ? { resources: sizing.applied } : {}),
    ...(sizing.warnings.length ? { resource_warnings: sizing.warnings } : {}),
    ...(creds.username ? { workstation_user: creds.username } : {}),
    ...(creds.password ? { workstation_pass: creds.password } : {}),
    credentials_source: creds.source,
  };
}

/**
 * Wire the gateway for every slot, deploy each workstation, then mark the lane
 * 'active'. This is the unit runBatch schedules — one job is one LANE, so the
 * concurrency limits and progress accounting keep meaning what they did when a
 * lane held exactly one machine.
 *
 * Workstations within a lane run in sequence: they share a gateway, a node and
 * (usually) a template, and the win from overlapping them is small next to the
 * cross-lane parallelism that already exists. It also means one config write at
 * the end rather than N racing merges into the same JSONB column.
 */
async function deployLaneWorkstations(job) {
  const { user, vxlanId, targetNode, laneName, progress, workstations, net } = job;
  const gatewayVmid = GATEWAY_VMID_OFFSET + vxlanId;

  if (progress) {
    progress.lanes[job.laneId] = {
      user: user.email, vxlan: vxlanId, node: targetNode, status: 'cloning',
      workstations: workstations.length, _startedAt: Date.now(),
    };
  }

  try {
    // 1. Reserve every slot's address and publish every slot's console port,
    //    before any workstation exists — so each guest's first DHCP lease is
    //    already the reserved one.
    job._gatewayAccessOk = false;
    try {
      await applyGatewayWorkstationAccess({ node: targetNode, gatewayVmid, workstations });
      job._gatewayAccessOk = true;
    } catch (gwErr) {
      // One machine on the template's own RDP port can still ride the gateway's
      // baked wan0:3389 -> .50 rule. Nothing else can: slots 1+ have no baked
      // reservation (so they would take pool leases and land nowhere the DNAT
      // points) and no baked DNAT (so their ports are not forwarded at all).
      // Continuing would produce a lane that reports 'active' with consoles that
      // cannot connect, which is strictly worse than failing here.
      if (workstations.length > 1) {
        throw new Error(
          `gateway access setup failed and this lane has ${workstations.length} workstations, ` +
          `which the gateway's baked DNAT cannot cover: ${gwErr.message}. ` +
          `Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER.`
        );
      }
      console.warn(
        `${LOG} Gateway access setup failed for ${laneName} (${gwErr.message}) — ` +
        `falling back to the gateway's baked DNAT. Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER.`
      );
    }

    // 2. Deploy each slot.
    const deployed = [];
    for (const ws of workstations) {
      deployed.push(await deployOneWorkstation(job, ws));
    }

    // 3. Lane is live. Deliberately NOT gated on discovering the guests' IPs: a
    //    stock Windows template has no qemu-guest-agent, and the console doesn't
    //    need the IP anyway.
    //
    //    Slot 0's record is ALSO flattened onto the keys it has always occupied.
    //    plugins/cle/routes/vms.js and labs.js read `ip`, `console_via`,
    //    `console_port`, `guac_connection_id`, `workstation_user/pass` directly,
    //    and a one-machine lane must keep looking exactly as it did.
    const primary = deployed[0];
    await cybercoreQuery(
      `UPDATE cybercore_lane
          SET status='active', config = config || $2::jsonb, updated_at=NOW()
        WHERE lane_id=$1`,
      [job.laneId, JSON.stringify({
        workstations: deployed,
        ip: primary.ip,
        ip_confirmed: false,
        workstation_mac: primary.mac,
        console_via: primary.console_via,
        console_host: primary.console_host,
        console_port: primary.console_port,
        guac_connection_id: primary.guac_connection_id,
        guac_user: user.email,
        workspace_resource_id: primary.workspace_resource_id,
        // What the machine was ACTUALLY sized to, plus anything the caller asked
        // for that Proxmox refused — an instructor who requested 16 GiB needs to
        // see that it landed at the template's 8, not find out from a student.
        ...(primary.resources ? { resources: primary.resources } : {}),
        ...(primary.resource_warnings ? { resource_warnings: primary.resource_warnings } : {}),
        ...(primary.workstation_user ? { workstation_user: primary.workstation_user } : {}),
        ...(primary.workstation_pass ? { workstation_pass: primary.workstation_pass } : {}),
        credentials_source: primary.credentials_source,
      })]
    );
    if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'active';
    console.log(
      `${LOG} Lane ${job.laneId} active (vxlan ${vxlanId}, node ${targetNode}, ` +
      `${deployed.length} workstation(s), subnet ${net.lan.base3}.0/24) for ${user.email}`
    );

    return { laneId: job.laneId, user: user.email, vxlanId, status: 'active', workstations: deployed.length };
  } catch (err) {
    await markLaneError(job.laneId, `workstation: ${err.message}`);
    if (progress?.lanes[job.laneId]) progress.lanes[job.laneId].status = 'error';
    console.error(`${LOG} Lane ${job.laneId} workstation failed for ${user.email}: ${err.message}`);
    throw err;
  }
}

/**
 * Detached check that a workstation landed on its reserved address. Records what
 * it found on the lane so a mismatch (bad reservation, guest ignoring DHCP) is
 * visible in the UI instead of surfacing as a mysteriously dead console.
 *
 * Writes through jsonb_set into the per-slot `ws_ip` / `ws_ip_confirmed` maps
 * rather than merging an object with `||`: these run detached, one per slot, and
 * `config || '{"ws_ip":{...}}'` replaces the whole nested object — so two slots
 * confirming at once would erase each other's result. jsonb_set touches one leaf,
 * and the row lock serializes the statements.
 *
 * Slot 0 additionally keeps the flat `ip` / `ip_confirmed` keys it has always
 * written, which the CLE VM list reads.
 */
function confirmWorkstationIp(job, slot, workstationVmid, providerType, expectedIp) {
  getVmIp(job.targetNode, workstationVmid, providerType, 12, 10000)
    .then(async (ip) => {
      if (!ip) {
        console.log(`${LOG} Lane ${job.laneId} slot ${slot}: no guest-agent IP (expected for templates without the agent)`);
        return;
      }
      const confirmed = ip === expectedIp;
      // The console ALWAYS targets the reserved address — our own LANE-CONSOLE
      // DNAT and the gateway's baked wan0:3389 rule both point there. So a guest
      // sitting anywhere else in the lane subnet is not merely suspicious: it
      // took an ordinary pool lease, and its console cannot connect at all.
      //
      // Restricted to the same /24 on purpose. getVmIp returns the FIRST
      // non-loopback IPv4 the agent reports, so a guest that happens to surface
      // some other interface first would otherwise be branded unreachable while
      // working fine. A different host in the LANE's own subnet is unambiguous.
      const sameSubnet = ip.split('.').slice(0, 3).join('.') === expectedIp.split('.').slice(0, 3).join('.');
      if (!confirmed && sameSubnet) {
        const detail =
          `workstation is on ${ip}, not the reserved ${expectedIp} — it took a DHCP pool ` +
          `lease, so the console DNAT points at an address nothing answers on. The lane's ` +
          `DHCP reservation did not apply; check PROXMOX_SSH_KEY / PROXMOX_SSH_USER and ` +
          `re-provision.`;
        console.error(`${LOG} Lane ${job.laneId} slot ${slot}: ${detail}`);
        // Downgrade the lane so it stops reading as healthy. An instructor
        // handing this to a student otherwise sees 'active' with a Console
        // button that silently fails.
        await patchLaneConfig(job.laneId, {
          console_via: 'unreachable',
          console_error: `slot ${slot}: ${detail}`,
        }).catch(() => {});
      } else if (!confirmed) {
        console.warn(
          `${LOG} Lane ${job.laneId} slot ${slot}: workstation reports ${ip}, not the reserved ` +
          `${expectedIp} — different subnet, so this is probably a second interface, not a bad lease`
        );
      }
      // Merged with `||` into the existing map rather than written through a
      // two-element jsonb_set path: jsonb_set can only create the LAST element
      // of a path, so if `ws_ip` were ever missing from config the write would
      // silently do nothing. This form creates the parent when absent and still
      // touches only one key, so concurrent per-slot confirmations don't clobber
      // each other (the row lock serializes the statements).
      await cybercoreQuery(
        `UPDATE cybercore_lane
            SET config = jsonb_set(
                  jsonb_set(
                    COALESCE(config, '{}'::jsonb), '{ws_ip}',
                    COALESCE(config->'ws_ip', '{}'::jsonb) || jsonb_build_object($2::text, to_jsonb($3::text))
                  ),
                  '{ws_ip_confirmed}',
                  COALESCE(config->'ws_ip_confirmed', '{}'::jsonb) || jsonb_build_object($2::text, to_jsonb($4::boolean))
                ),
                updated_at = NOW()
          WHERE lane_id = $1`,
        [job.laneId, String(slot), ip, confirmed]
      );
      if (slot === 0) await patchLaneConfig(job.laneId, { ip, ip_confirmed: confirmed });
    })
    .catch((e) => console.warn(`${LOG} Lane ${job.laneId} slot ${slot} IP check failed: ${e.message}`));
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
 * @param {object}   [a.template]     cybercore_template_catalog row (needs template_vmid).
 *   Shorthand for a one-workstation lane; ignored when `templates` is given.
 * @param {Array}    [a.templates]    one catalog row per workstation, in slot order.
 *   Every lane gets the same set: templates[0] → slot 0 → <base>.50, templates[1]
 *   → slot 1 → <base>.51, and so on, capped at WORKSTATION_MAX_SLOTS.
 * @param {object}   a.vxlanBlock     { start, end } — pre-reserved, VNets already created
 * @param {string}   [a.moduleKey='crucible']
 * @param {string}   [a.subnetScheme='v2']
 * @param {string}   [a.namePrefix='lane']  lane name = `${namePrefix}-${vxlanId}`
 * @param {object}   [a.laneConfig={}]      extra keys merged into cybercore_lane.config
 * @param {object|Array} [a.resources=null] { cores, memory_mb, disk_gb } applied to each
 *   CLONE before its first boot — the catalog template itself is never modified.
 *   Omitted fields keep the template's own sizing. Pass an array to size each slot
 *   separately (index-matched to `templates`, holes keep that template's own
 *   sizing). Validate with normalizeResourceSpec() first; out-of-range values are
 *   not re-checked here.
 * @param {string}   [a.description='']     extra lines on the Proxmox object descriptions
 * @param {string}   [a.guacParent]         Guacamole connection-group identifier
 * @param {string}   [a.progressId]         key into global._batchDeployProgress
 * @param {string}   [a.progressLabel='']
 * @returns {Promise<{provisioned:Array, failed:Array, progressId:?string}>}
 */
async function deployLanes({
  users, template, templates, vxlanBlock,
  moduleKey = 'crucible', subnetScheme = 'v2', namePrefix = 'lane',
  laneConfig = {}, resources = null, description = '', guacParent = null,
  progressId = null, progressLabel = '',
}) {
  if (!Array.isArray(users) || users.length === 0) return { provisioned: [], failed: [], progressId };
  if (!vxlanBlock?.start || !vxlanBlock?.end) throw new Error('deployLanes: vxlanBlock {start,end} is required');

  // This module builds single-LAN lanes: it reads net.lan throughout (subnet
  // base, gateway IP, the lan0 veth on the gateway). resolveLaneNetworking's v3
  // scheme returns lanExt/lanInt and NO lan, so a v3 caller would get
  // "Cannot read properties of undefined (reading 'base3')" partway through the
  // deploy, after the lane rows already exist. Segmented lanes go through
  // challenge-lane-deployer.js instead.
  if (subnetScheme !== 'v1' && subnetScheme !== 'v2') {
    throw new Error(
      `deployLanes: subnetScheme '${subnetScheme}' is not supported — this path builds ` +
      `single-LAN (v1/v2) lanes. Use challenge-lane-deployer for segmented v3 lanes.`
    );
  }

  const tmpls = (Array.isArray(templates) && templates.length) ? templates : (template ? [template] : []);
  if (!tmpls.length) throw new Error('deployLanes: one of template / templates is required');
  if (tmpls.length > WORKSTATION_MAX_SLOTS) {
    throw new Error(
      `deployLanes: ${tmpls.length} workstations per lane exceeds the ${WORKSTATION_MAX_SLOTS}-slot band ` +
      `(.${WORKSTATION_OCTET_BASE}–.${WORKSTATION_OCTET_BASE + WORKSTATION_MAX_SLOTS - 1})`
    );
  }
  for (const t of tmpls) {
    if (!t?.template_vmid) {
      throw new Error(`deployLanes: template '${t?.template_key || '?'}' has no Proxmox VMID configured`);
    }
  }
  const resourcesFor = (slot) => (Array.isArray(resources) ? (resources[slot] || null) : resources);

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

  // Resolve each template's source node and console once, not per lane.
  const gwOriginVmid = resolveGatewayVmid(moduleKey, subnetScheme);
  const gwOriginNode = await findTemplateNode(gwOriginVmid, getDefaultTemplateNode());
  const slotSpecs = await Promise.all(tmpls.map(async (t, slot) => ({
    slot,
    template: t,
    providerType: t.provider_type || 'qemu',
    octet: octetForSlot(slot),
    console: consoleForSlot(resolveConsole(t), slot),
    resources: resourcesFor(slot),
    sourceNode: await findTemplateNode(t.template_vmid, t.node || getDefaultTemplateNode()),
  })));

  // Two slots publishing the same WAN port would mean the second DNAT silently
  // shadows the first. Slot-shifted defaults can't collide, but a template can
  // pin metadata.console_wan_port, so check rather than assume.
  {
    const byPort = new Map();
    for (const s of slotSpecs) {
      const clash = byPort.get(s.console.wanPort);
      if (clash !== undefined) {
        throw new Error(
          `deployLanes: slots ${clash} and ${s.slot} both publish gateway port ${s.console.wanPort} — ` +
          `check metadata.console_wan_port on '${tmpls[clash].template_key}' / '${s.template.template_key}'`
        );
      }
      byPort.set(s.console.wanPort, s.slot);
    }
  }

  // VMIDs for slots 1+, allocated for the whole deploy in one cluster scan.
  const extraVmids = await reserveWorkstationVmids(users.length * (slotSpecs.length - 1));

  console.log(
    `${LOG} Deploying ${users.length} lane(s) × ${slotSpecs.length} workstation(s): ` +
    slotSpecs.map(s =>
      `slot ${s.slot}=${s.template.os_name || s.template.template_key} ` +
      `(${s.providerType} ${s.template.template_vmid} @ ${s.sourceNode}, .${s.octet}, ` +
      `${s.console.protocol}:${s.console.wanPort}, nic ${resolveNicModel(s.template)}` +
      (s.resources ? `, sized ${JSON.stringify(s.resources)}` : '') + ')'
    ).join('; ')
  );

  // Build a job per user, skipping any whose VNet is missing.
  const jobs = [];
  const failed = [];
  let extraCursor = 0;
  for (let i = 0; i < users.length; i++) {
    const vxlanId = vxlans[i];
    const vnet = vnetsByTag[String(vxlanId)];
    if (!vnet) {
      failed.push({ user_id: users[i].id, reason: `No VNet for VXLAN ${vxlanId} (lab network not fully provisioned)` });
      continue;
    }
    const laneName = `${namePrefix}-${vxlanId}`;
    const net = resolveLaneNetworking(subnetScheme, moduleKey, vxlanId);
    const workstations = slotSpecs.map(s => ({
      ...s,
      // Slot 0 keeps the historic 600000+vxlanId so lanes deployed before this
      // file grew slots are byte-identical; later slots come from the scan.
      vmid: s.slot === 0 ? WORKSTATION_VMID_OFFSET + vxlanId : extraVmids[extraCursor++],
      mac: macForOctet(s.octet, vxlanId),
      ip: `${net.lan.base3}.${s.octet}`,
      // dnsmasq keys DNS off the reservation hostname, so these must be distinct
      // within a lane. Slot 0 keeps the bare lane name it has always used.
      hostname: s.slot === 0 ? laneName : `${laneName}-ws${s.slot}`,
    }));
    jobs.push({
      user: users[i], vxlanId, vnet, workstations,
      moduleKey, subnetScheme, laneConfig, resources, description, guacParent, progress,
      laneName, net,
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
      await deployLaneWorkstations(job);
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
    const { results } = await runBatch(wsJobs, deployLaneWorkstations, {
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
    `SELECT lane_id, vxlan_id, status, config FROM cybercore_lane WHERE lane_id = ANY($1::uuid[])`,
    [laneIds]
  );
  if (laneRows.rows.length === 0) {
    return { lanes_deleted: 0, vms_destroyed: 0, orphan_disks_swept: 0, errors };
  }

  // A VXLAN id is only free-for-reuse while no LIVE lane holds it — an 'error'
  // or 'deleted' lane releases it (allocateVxlanIds and the
  // ux_cybercore_lane_vxlan_active partial index both say so). So two rows can
  // legitimately carry the same vxlan_id: a dead one and the healthy lane that
  // recycled it.
  //
  // Most VMIDs in this teardown are derived from vxlan_id (gateway 100000+,
  // slot-0 workstation 600000+, GOAD controller 200000+). Deriving them for a
  // dead lane whose id has been recycled would force-stop and purge the LIVE
  // lane's machines. So: find the ids that another, surviving lane owns, and
  // skip the VMIDs for those rows.
  //
  // Slot-1+ workstations are allocated from a free-id scan rather than derived,
  // so a recycled VXLAN could not have handed the live lane the same ids — they
  // would be safe to destroy. They are skipped anyway: leaving a VM behind is
  // recoverable, and one rule ("contested row destroys nothing") is far easier
  // to reason about than a per-VMID exemption.
  const contested = new Set();
  {
    const vxlans = laneRows.rows.map(r => r.vxlan_id).filter(v => v != null);
    if (vxlans.length > 0) {
      const others = await cybercoreQuery(
        `SELECT DISTINCT vxlan_id FROM cybercore_lane
          WHERE vxlan_id = ANY($1::int[])
            AND NOT (lane_id = ANY($2::uuid[]))
            AND status NOT IN ('error', 'deleted')`,
        [vxlans, laneIds]
      ).catch((e) => {
        errors.push(`VXLAN ownership check: ${e.message}`);
        // Fail SAFE: if we cannot tell, assume every id is contested and destroy
        // only what a lane explicitly recorded. Leaving a VM behind is
        // recoverable; destroying someone else's running lane is not.
        return { rows: vxlans.map(v => ({ vxlan_id: v })) };
      });
      for (const r of others.rows) contested.add(r.vxlan_id);
    }
  }
  if (contested.size > 0) {
    console.warn(
      `${LOG} VXLAN(s) ${[...contested].join(', ')} are held by a live lane that is not being torn down — ` +
      `skipping derived VMIDs for the dead row(s) so the live lane is not destroyed.`
    );
  }

  // Phase 1: enumerate targets.
  const vmsToDestroy = [];
  const vxlanIds = [];
  const guacConnIds = new Set();

  for (const lane of laneRows.rows) {
    const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    if (cfg.guac_connection_id) guacConnIds.add(cfg.guac_connection_id);
    // Slots 1+ each own a connection. The workspace-row lookup below finds them
    // too (it keys on lane_id, not slot), but only for lanes whose registration
    // succeeded — this covers the rest.
    for (const ws of (Array.isArray(cfg.workstations) ? cfg.workstations : [])) {
      if (ws?.guac_connection_id) guacConnIds.add(ws.guac_connection_id);
    }

    // A live lane has recycled this row's VXLAN. Nearly every VMID here —
    // including the ones recorded in cfg.vms and cfg.attack_box_vm_id — was
    // computed from that id at insert time, so it now names the live lane's
    // machines. Destroy nothing; the row and its DB bookkeeping still go. Same
    // for the Tailscale devices, which the live lane re-registered under that id.
    // (See the note above on why the allocated slot-1+ VMIDs go too.)
    if (lane.vxlan_id != null && contested.has(lane.vxlan_id)) {
      console.warn(
        `${LOG} Lane ${lane.lane_id} (status ${lane.status}) shares VXLAN ${lane.vxlan_id} with a live lane — ` +
        `removing the record only, destroying no VMs.`
      );
      continue;
    }
    if (lane.vxlan_id) vxlanIds.push(lane.vxlan_id);

    if (Array.isArray(cfg.vms) && cfg.vms.length > 0) {
      for (const vm of cfg.vms) {
        vmsToDestroy.push({ vmid: vm.vm_id, type: vm.type || 'qemu', label: vm.name || `vm-${vm.vm_id}` });
      }
    } else if (Array.isArray(cfg.workstations) && cfg.workstations.length > 0) {
      // Slot list, written by insertLane BEFORE anything is cloned — so a deploy
      // that died partway through still records every id it might have created.
      // Slots 1+ have allocated VMIDs that cannot be re-derived from vxlan_id, so
      // this is the ONLY way to find them.
      for (const ws of cfg.workstations) {
        if (!ws?.vmid) continue;
        vmsToDestroy.push({
          vmid: ws.vmid,
          type: ws.provider_type || cfg.provider_type || 'qemu',
          label: `workstation slot ${ws.slot ?? '?'}`,
          // Slot-1+ VMIDs are ALLOCATED, not derived, so they can legitimately be
          // reused: a deploy that recorded one and then failed before cloning
          // leaves it free, and a later deploy will hand the same id to a
          // different lane. Tearing down the first lane would then destroy the
          // second lane's running machine. The recorded hostname is what the
          // clone was named, so it identifies the owner — see the check by
          // vmNameMap below.
          expectName: ws.hostname || null,
        });
      }
    } else {
      const wsVmid = cfg.workstation_vmid || (lane.vxlan_id ? WORKSTATION_VMID_OFFSET + lane.vxlan_id : null);
      if (wsVmid) vmsToDestroy.push({ vmid: wsVmid, type: cfg.provider_type || 'qemu', label: 'workstation' });
    }

    // Kali. Challenge lanes store the attack box OUTSIDE cfg.vms (it isn't part
    // of the challenge spec), so enumerating cfg.vms alone leaves one running VM
    // per lane behind on every teardown.
    const abVmid = cfg.attack_box_vm_id || cfg.attack_box_vmid || null;
    if (abVmid) vmsToDestroy.push({ vmid: abVmid, type: 'qemu', label: 'attack-box' });

    // Attached modules (POST /lanes/:id/modules, and the CLE "attach" deploy
    // mode). Each instance owns its own VMs at 800000 + slot*10000 + vxlan.
    for (const mod of (Array.isArray(cfg.attached_modules) ? cfg.attached_modules : [])) {
      for (const vm of (mod.vms || [])) {
        vmsToDestroy.push({
          vmid: vm.vm_id,
          type: vm.type || 'qemu',
          label: `attached:${mod.challenge_key || '?'}/${vm.name || vm.vm_id}`,
        });
      }
    }

    // GOAD controller. deployGoadLane stops it but never destroys it, so a live
    // (non-pre-baked) bake leaves it running. Its VMID is deterministic and not
    // recorded on the lane, so derive it — the same way the admin group teardown
    // does. A lane that never ran GOAD simply has no VM there, and the
    // vmNodeMap filter below drops it.
    if (lane.vxlan_id) {
      vmsToDestroy.push({
        vmid: GOAD_CONTROLLER_VMID_OFFSET + lane.vxlan_id, type: 'qemu', label: 'goad-controller',
      });
    }

    const gwVmid = cfg.gateway_vmid || cfg.gateway_vm_id || (lane.vxlan_id ? GATEWAY_VMID_OFFSET + lane.vxlan_id : null);
    if (gwVmid) vmsToDestroy.push({ vmid: gwVmid, type: 'lxc', label: 'gateway' });
  }

  // A lane can list the same VMID twice (e.g. a config rewritten mid-deploy).
  // Destroying it twice turns the second attempt into a spurious error.
  {
    const seen = new Set();
    for (let i = vmsToDestroy.length - 1; i >= 0; i--) {
      const key = String(vmsToDestroy[i].vmid);
      if (seen.has(key)) vmsToDestroy.splice(i, 1);
      else seen.add(key);
    }
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
  const vmNameMap = {};
  for (const r of (clusterResources || [])) {
    if (r.type === 'qemu' || r.type === 'lxc') {
      vmNodeMap[r.vmid] = r.node;
      if (r.name) vmNameMap[r.vmid] = r.name;
    }
  }

  // VMIDs this teardown deliberately refuses to touch because they now belong to
  // someone else. Tracked separately from "not found": the orphan sweep in phase
  // 4 retries anything it still sees, and must not resurrect these.
  const ownershipSkipped = new Set();

  const existingVms = vmsToDestroy.filter((vm) => {
    if (!vmNodeMap[vm.vmid]) return false;
    // Ownership check for reusable (allocated) VMIDs. Only applied when BOTH the
    // expected and actual names are known, so a lane recorded before hostnames
    // were stored, or a VM the cluster reports without a name, still tears down.
    const actual = vmNameMap[vm.vmid];
    if (vm.expectName && actual && actual !== vm.expectName) {
      console.warn(
        `${LOG} Skipping ${vm.type} ${vm.vmid} (${vm.label}): it is named '${actual}', not the ` +
        `'${vm.expectName}' this lane recorded — the id was reallocated to another lane, ` +
        `and destroying it would take out a machine that is still in use.`
      );
      ownershipSkipped.add(vm.vmid);
      return false;
    }
    return true;
  });
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
  //
  // Built from vmsToDestroy rather than existingVms on purpose — a VM that was
  // mid-creation during the first scan is exactly what this sweep is for. But
  // the ones skipped for failing the ownership check are excluded: they are
  // alive, they will still be alive next round, and force-stopping them would
  // destroy the lane that legitimately owns that id.
  const allTargetVmIds = vmsToDestroy
    .map(v => v.vmid)
    .filter(id => !ownershipSkipped.has(id));
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

  // Finally, the lane rows — but ONLY when everything they own is actually gone.
  //
  // A lane row is the only handle on its VMs: their ids are derived from
  // vxlan_id, and the cybercore_resource rows were removed in phase 5. Deleting
  // the row while a VM survived orphans that VM permanently, AND frees its
  // vxlan_id for the next deploy, whose gateway clone then collides with the
  // container still running at 100000+<id>.
  //
  // So on failure the rows are marked 'error' instead: they keep pointing at the
  // survivors, they stay out of allocateVxlanIds (which skips 'error'), and a
  // retry of the same teardown can find them again.
  let deleted = 0;
  if (errors.length === 0) {
    const del = await cybercoreQuery(
      `DELETE FROM cybercore_lane WHERE lane_id = ANY($1::uuid[])`,
      [laneIds]
    );
    deleted = del.rowCount;
  } else {
    await cybercoreQuery(
      `UPDATE cybercore_lane
          SET status = 'error',
              config = config || $2::jsonb,
              updated_at = NOW()
        WHERE lane_id = ANY($1::uuid[])`,
      [laneIds, JSON.stringify({ teardown_errors: errors.slice(0, 20) })]
    ).catch(e => errors.push(`Could not mark lanes for retry: ${e.message}`));
    console.warn(
      `${LOG} Teardown left ${errors.length} error(s) — keeping ${laneIds.length} lane row(s) ` +
      `as 'error' so the surviving VMs stay reachable for a retry.`
    );
  }

  console.log(
    `${LOG} Teardown complete: ${deleted} lanes deleted, ${existingVms.length} VMs, ` +
    `${orphanDisksSwept} orphan disks, ${errors.length} errors`
  );
  return {
    lanes_deleted: deleted,
    lanes_kept_for_retry: errors.length > 0 ? laneIds.length : 0,
    vms_destroyed: existingVms.length,
    orphan_disks_swept: orphanDisksSwept,
    errors,
  };
}

module.exports = {
  GATEWAY_VMID_OFFSET,
  WORKSTATION_VMID_OFFSET,
  WORKSTATION_OCTET,
  WORKSTATION_OCTET_BASE,
  WORKSTATION_MAX_SLOTS,
  CONSOLE_PROTOCOLS,
  RESOURCE_LIMITS,
  allocateVxlanIds,
  octetForSlot,
  consoleForSlot,
  resolveConsole,
  resolveNicModel,
  resolveWorkstationCredentials,
  normalizeResourceSpec,
  deployLanes,
  teardownLanes,
  // Progress registry. Exported so challenge-lane-deployer.js drives the SAME
  // global._batchDeployProgress shape instead of inventing a second contract —
  // admin-lanes.js and the CLE pollers both already speak it.
  initProgress,
  setPhase,
  recordLaneDone,
  finishProgress,
  readProgress,
};
