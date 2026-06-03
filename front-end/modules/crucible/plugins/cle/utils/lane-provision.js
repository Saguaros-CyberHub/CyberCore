/**
 * ============================================================================
 * CLE Lane Provisioning
 * ----------------------------------------------------------------------------
 * Deploys per-student workstation lanes (gateway LXC + workstation VM) drawn
 * from a course's reserved VXLAN block. cybercore_lane is the source of truth —
 * no cybercore_resource / vm_instance / allocation rows are created.
 *
 * Reuses only CORE src/utils (the same machinery admin groups.js uses); imports
 * nothing from the CIAB plugin.
 *
 *   ≤3 students → sequential per-lane deploy (selectBestNode per lane)
 *   >3 students → distributeAcrossNodes, then:
 *       phase 1: replicate the gateway LXC template to each target node
 *       phase 2: clone gateways grouped by node (sequential within a node so
 *                concurrent clones don't hit "CT is locked (disk)")
 *       phase 3: clone workstations in parallel via runBatch + clone semaphore
 *     mirroring the groups.js batch flow.
 * ============================================================================
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI, waitForTask, findTemplateNode, forceDestroyVM } = require('../../../../../src/utils/proxmox');
const { selectBestNode } = require('../../../../../src/utils/node-selector');
const { runBatch, distributeAcrossNodes, createCloneSemaphore } = require('../../../../../src/utils/batch-deployer');
const {
  resolveGatewayVmid, resolveLaneNetworking, formatLaneGatewayNet0, configureLaneTailscale,
} = require('../../../../../src/utils/lane-networking');
const { getDefaultTemplateNode, getSchedulingConfig } = require('../../../../../src/utils/site-config');
const { guacAPI, ensureGuacAccount } = require('../../../../../src/utils/guacamole');

const MODULE_KEY = 'crucible';
const SUBNET_SCHEME = 'v2';
const GATEWAY_VMID_OFFSET = 100000;     // gateway LXC  = 100000 + vxlanId  (matches groups.js)
const WORKSTATION_VMID_OFFSET = 600000; // workstation  = 600000 + vxlanId
const TEMP_GW_TEMPLATE_BASE = 169300;   // per-node temp gateway template copies (clear of CIAB's 169200)

const LOG = '[CLE Lane]';

// ── helpers ──────────────────────────────────────────────────────────────────

function vmApiBase(node, vmid, providerType) {
  return `/api2/json/nodes/${node}/${providerType === 'lxc' ? 'lxc' : 'qemu'}/${vmid}`;
}

/** First non-loopback IPv4 from the guest agent (qemu) or interfaces API (lxc). */
async function getVmIp(node, vmid, providerType, retries = 18, delayMs = 10000) {
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
 * Allocate up to `count` free VXLAN ids WITHIN the course's reserved block.
 * Dedupes against every live cybercore_lane so retries / partial deploys don't
 * collide.
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

// ── per-lane steps ───────────────────────────────────────────────────────────

/** Create the lane row (status 'deploying') with the seed config. Sets job.laneId. */
async function insertLane(job) {
  const { student, courseId, challengeKey, template, vxlanId, vnet, targetNode } = job;
  const ins = await cybercoreQuery(
    `INSERT INTO cybercore_lane (user_id, module_key, name, status, vxlan_id, config, created_at, updated_at)
     VALUES ($1, $2, $3, 'deploying', $4, $5::jsonb, NOW(), NOW())
     RETURNING lane_id`,
    [student.id, MODULE_KEY, `cle-${vxlanId}`, vxlanId, JSON.stringify({
      cle: true,
      course_id: courseId,
      challenge_key: challengeKey,
      template_id: template.id,
      template_name: template.os_name || template.template_key,
      provider_type: template.provider_type || 'qemu',
      subnet_scheme: SUBNET_SCHEME,
      vnet: vnet.vnet,
      gateway_vmid: GATEWAY_VMID_OFFSET + vxlanId,
      workstation_vmid: WORKSTATION_VMID_OFFSET + vxlanId,
      node: targetNode,
      student_email: student.email,
    })]
  );
  job.laneId = ins.rows[0].lane_id;
  return job.laneId;
}

/**
 * Clone + configure + start the lane gateway LXC. Pure (throws on failure;
 * does not touch lane status — the caller records errors). Clones from
 * job.gwSourceNode/Vmid (origin for sequential, node-local temp for batch).
 */
async function cloneGateway(job) {
  const { student, courseId, vxlanId, vnet, targetNode, gwSourceNode, gwSourceVmid } = job;
  const gatewayVmid = GATEWAY_VMID_OFFSET + vxlanId;
  const net = resolveLaneNetworking(SUBNET_SCHEME, MODULE_KEY, vxlanId);
  const laneName = `cle-${vxlanId}`;

  const upid = await proxmoxAPI('POST', `${vmApiBase(gwSourceNode, gwSourceVmid, 'lxc')}/clone`, {
    newid: gatewayVmid,
    hostname: `${laneName}-gateway`,
    full: 1,
    target: targetNode,
    description: `CLE lane gateway\nCourse: ${courseId}\nStudent: ${student.email}\nLane: ${job.laneId}`,
  });
  if (upid) await waitForTask(gwSourceNode, upid, 600000);

  await proxmoxAPI('PUT', `${vmApiBase(targetNode, gatewayVmid, 'lxc')}/config`, {
    net0: formatLaneGatewayNet0(net.wan),
    net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`,
  });
  await configureLaneTailscale({
    subnetScheme: SUBNET_SCHEME, vxlanId, wanIp: net.wan.ip.split('/')[0], laneName, logTag: LOG,
  });
  await proxmoxAPI('POST', `${vmApiBase(targetNode, gatewayVmid, 'lxc')}/status/start`);
  await new Promise(r => setTimeout(r, 5000)); // let dnsmasq come up before the workstation DHCPs
}

/**
 * Clone + configure + start the workstation, resolve its IP from the guest
 * agent, create the Guac RDP connection, and mark the lane 'active'. Marks the
 * lane 'error' and rethrows on failure (so runBatch records it).
 */
async function deployWorkstation(job) {
  const { student, courseId, template, vxlanId, vnet, targetNode, wsSourceNode, cloneSem } = job;
  const workstationVmid = WORKSTATION_VMID_OFFSET + vxlanId;
  const providerType = template.provider_type || 'qemu';
  const laneName = `cle-${vxlanId}`;

  try {
    await cloneSem.run(async () => {
      const upid = await proxmoxAPI('POST', `${vmApiBase(wsSourceNode, template.template_vmid, providerType)}/clone`, {
        newid: workstationVmid,
        ...(providerType === 'lxc' ? { hostname: laneName } : { name: laneName }),
        full: 1,
        target: targetNode,
        description: `CLE workstation\nCourse: ${courseId}\nStudent: ${student.email}\nLane: ${job.laneId}`,
      });
      if (upid) await waitForTask(wsSourceNode, upid, 600000);
    });

    const nicVal = providerType === 'lxc'
      ? `name=eth0,bridge=${vnet.vnet},firewall=0,ip=dhcp`
      : `virtio,bridge=${vnet.vnet},firewall=0`;
    await proxmoxAPI('PUT', `${vmApiBase(targetNode, workstationVmid, providerType)}/config`, { net0: nicVal });
    await proxmoxAPI('POST', `${vmApiBase(targetNode, workstationVmid, providerType)}/status/start`);

    // IP from the QEMU guest agent (or LXC interfaces).
    const ip = await getVmIp(targetNode, workstationVmid, providerType);

    // Guacamole RDP connection (best-effort).
    let guacConnId = null;
    if (process.env.GUAC_ENABLED === 'true' && ip) {
      try {
        const rdpUser = template.metadata?.default_rdp_user || null;
        const rdpPass = template.metadata?.default_rdp_pass || null;
        const conn = await guacAPI('POST', '/connections', {
          name: `${laneName}-${workstationVmid}`,
          protocol: 'rdp',
          parentIdentifier: 'ROOT',
          parameters: {
            hostname: ip,
            port: '3389',
            ...(rdpUser ? { username: rdpUser } : {}),
            ...(rdpPass ? { password: rdpPass } : {}),
            security: template.metadata?.rdp_security || 'tls',
            'ignore-cert': 'true',
            width: '1920', height: '1080', dpi: '96',
            'enable-wallpaper': 'true', 'enable-theming': 'true',
            'enable-font-smoothing': 'true', 'color-depth': '24',
            'resize-method': 'display-update',
          },
          attributes: { 'max-connections': '5', 'max-connections-per-user': '2' },
        });
        guacConnId = conn?.identifier || null;
        if (guacConnId && student.email) {
          await ensureGuacAccount(student.email).catch(() => null);
          await guacAPI('PATCH', `/users/${encodeURIComponent(student.email)}/permissions`, [
            { op: 'add', path: `/connectionPermissions/${guacConnId}`, value: 'READ' },
          ]).catch((e) => console.warn(`${LOG} Guac permission grant failed for ${student.email}: ${e.message}`));
        }
      } catch (guacErr) {
        console.warn(`${LOG} Guac setup failed for ${laneName}: ${guacErr.message}`);
      }
    }

    await cybercoreQuery(
      `UPDATE cybercore_lane
          SET status='active', config = config || $2::jsonb, updated_at=NOW()
        WHERE lane_id=$1`,
      [job.laneId, JSON.stringify({ ip: ip || null, guac_connection_id: guacConnId, guac_user: student.email })]
    );
    console.log(`${LOG} Lane ${job.laneId} active (vxlan ${vxlanId}, node ${targetNode}, ws ${workstationVmid}) for ${student.email}`);
    return { laneId: job.laneId, student: student.email, status: 'active' };
  } catch (err) {
    await markLaneError(job.laneId, `workstation: ${err.message}`);
    console.error(`${LOG} Lane ${job.laneId} workstation failed for ${student.email}: ${err.message}`);
    throw err;
  }
}

// ── batch template replication ───────────────────────────────────────────────

/** Replicate the gateway LXC template to each unique target node; returns node → vmid. */
async function replicateGatewayTemplate(uniqueNodes, originNode, originVmid) {
  const byNode = {};
  let counter = 0;
  for (const node of uniqueNodes) {
    if (node === originNode) { byNode[node] = originVmid; continue; }
    const tempId = TEMP_GW_TEMPLATE_BASE + counter++;
    try {
      const upid = await proxmoxAPI('POST', `${vmApiBase(originNode, originVmid, 'lxc')}/clone`, {
        newid: tempId, hostname: `cle-gw-temp-${node}`, full: 1, target: node,
        description: 'Temp CLE gateway template for batch deploy',
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
 * Provision workstation lanes for a list of students out of a course's reserved
 * VXLAN block. Returns { provisioned: [...], failed: [...] }.
 *
 * @param {object} args
 * @param {string} args.courseId
 * @param {object} args.challenge   { challenge_key, vxlan_block:{start,end} }
 * @param {object} args.template    cybercore_template_catalog row (workstation)
 * @param {Array}  args.students    [{ id, email }]
 */
async function provisionLanes({ courseId, challenge, template, students }) {
  if (!students.length) return { provisioned: [], failed: [] };

  const block = challenge.vxlan_block || challenge.spec?.vxlan_block;
  if (!block?.start || !block?.end) throw new Error('Course has no reserved VXLAN block');

  // Allocate VXLAN ids from the reserved block; map each to its pre-created VNet.
  const vxlans = await allocateVxlanIds(block, students.length);
  if (vxlans.length < students.length) {
    throw new Error(`Course block exhausted: ${vxlans.length} free VXLANs for ${students.length} students. Increase max_students.`);
  }
  const vnetsByTag = await loadVnetsByTag();

  // Resolve template source nodes once.
  const gwOriginVmid = resolveGatewayVmid(MODULE_KEY, SUBNET_SCHEME);
  const gwOriginNode = await findTemplateNode(gwOriginVmid, getDefaultTemplateNode());
  const wsSourceNode = await findTemplateNode(template.template_vmid, template.node || getDefaultTemplateNode());

  // Build a job per student, skipping any whose VNet is missing.
  const jobs = [];
  const failed = [];
  for (let i = 0; i < students.length; i++) {
    const vxlanId = vxlans[i];
    const vnet = vnetsByTag[String(vxlanId)];
    if (!vnet) {
      failed.push({ student_id: students[i].id, reason: `No VNet for VXLAN ${vxlanId} (course lab not fully provisioned)` });
      continue;
    }
    jobs.push({ student: students[i], courseId, challengeKey: challenge.challenge_key, template, vxlanId, vnet, wsSourceNode });
  }
  if (!jobs.length) return { provisioned: [], failed };

  const cloneSem = createCloneSemaphore();
  jobs.forEach(j => { j.cloneSem = cloneSem; });

  if (jobs.length > 3) return batchDeploy(jobs, failed, { gwOriginNode, gwOriginVmid, cloneSem });
  return sequentialDeploy(jobs, failed, { gwOriginNode, gwOriginVmid });
}

/** ≤3: one lane at a time, gateway cloned from its origin node. */
async function sequentialDeploy(jobs, failed, { gwOriginNode, gwOriginVmid }) {
  const provisioned = [];
  for (const job of jobs) {
    job.targetNode = (await selectBestNode()).node;
    job.gwSourceNode = gwOriginNode;
    job.gwSourceVmid = gwOriginVmid;
    try {
      await insertLane(job);
      await cloneGateway(job);
      await deployWorkstation(job);
      provisioned.push({ student_id: job.student.id, lane_id: job.laneId, status: 'deploying' });
    } catch (err) {
      if (job.laneId) await markLaneError(job.laneId, err.message);
      failed.push({ student_id: job.student.id, reason: err.message });
    }
  }
  return { provisioned, failed };
}

/** >3: distribute across nodes, replicate gateway template, clone gateways
 *  per-node (serial within a node), then clone workstations in parallel. */
async function batchDeploy(jobs, failed, { gwOriginNode, gwOriginVmid, cloneSem }) {
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

  // Lane rows up front so the UI shows every student as "deploying".
  for (const job of jobs) await insertLane(job);

  // Phase 1: replicate the gateway template to each target node.
  const uniqueNodes = [...new Set(jobs.map(j => j.targetNode))];
  const gwTemplateByNode = await replicateGatewayTemplate(uniqueNodes, gwOriginNode, gwOriginVmid);

  // Phase 2: clone gateways grouped by node — sequential within a node so
  // concurrent LXC clones don't fight the same template lock; nodes in parallel.
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
        failed.push({ student_id: job.student.id, reason: `gateway: ${e.message}` });
        console.error(`${LOG} Gateway clone failed for ${job.student.email}: ${e.message}`);
      }
    }
  }));

  // Phase 3: clone workstations in parallel (bounded by lane concurrency + the
  // shared clone semaphore) for lanes whose gateway came up.
  const wsJobs = jobs.filter(j => j._gwOk);
  const provisioned = [];
  if (wsJobs.length) {
    const concurrency = getSchedulingConfig().max_concurrent_lanes;
    console.log(`${LOG} Batch: ${wsJobs.length} workstations (lane concurrency ${concurrency}, clones ${cloneSem.max})`);
    const { results } = await runBatch(wsJobs, deployWorkstation, { concurrency });
    results.forEach((r, i) => {
      if (r && !r.error) provisioned.push({ student_id: wsJobs[i].student.id, lane_id: wsJobs[i].laneId, status: 'deploying' });
      else failed.push({ student_id: wsJobs[i].student.id, reason: r?.error || 'workstation deploy failed' });
    });
  }

  // Phase 4: drop the temp gateway templates.
  await cleanupTempGatewayTemplates(gwTemplateByNode, gwOriginVmid);

  return { provisioned, failed };
}

/**
 * Tear down a student's lane: destroy the workstation + gateway, remove the
 * Guacamole connection, and delete the lane row.
 */
async function teardownLane(laneId) {
  const res = await cybercoreQuery(`SELECT config FROM cybercore_lane WHERE lane_id = $1`, [laneId]);
  if (res.rows.length === 0) return { success: true, alreadyGone: true };
  const cfg = res.rows[0].config || {};
  const providerType = cfg.provider_type || 'qemu';

  if (cfg.workstation_vmid) {
    await forceDestroyVM(cfg.workstation_vmid, providerType, cfg.node).catch(
      (e) => console.warn(`${LOG} workstation ${cfg.workstation_vmid} destroy: ${e.message}`));
  }
  if (cfg.gateway_vmid) {
    await forceDestroyVM(cfg.gateway_vmid, 'lxc', cfg.node).catch(
      (e) => console.warn(`${LOG} gateway ${cfg.gateway_vmid} destroy: ${e.message}`));
  }
  if (cfg.guac_connection_id && process.env.GUAC_ENABLED === 'true') {
    await guacAPI('DELETE', `/connections/${encodeURIComponent(cfg.guac_connection_id)}`).catch(
      (e) => console.warn(`${LOG} Guac connection ${cfg.guac_connection_id} delete: ${e.message}`));
  }

  await cybercoreQuery(`DELETE FROM cybercore_lane WHERE lane_id = $1`, [laneId]);
  console.log(`${LOG} Lane ${laneId} torn down`);
  return { success: true };
}

module.exports = {
  MODULE_KEY,
  allocateVxlanIds,
  provisionLanes,
  teardownLane,
};
