/**
 * ============================================================================
 * Group Admin Routes
 * Batch deploy groups of students, group teardown, account schedules,
 * and active/inactive toggles.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { proxmoxAPI, waitForTask, findTemplateNode } = require('../../utils/proxmox');
const { getDefaultTemplateNode, getClusterNodes, getSchedulingConfig } = require('../../utils/site-config');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { guacAPI, getGuacToken, GUAC_URL, GUAC_DS } = require('../../utils/guacamole');
const { buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const { generatePassword } = require('../../utils/password-generator');
const { waitForGuestAgent, executeScriptsOnVM } = require('../../utils/script-executor');
const { selectBestNode } = require('../../utils/node-selector');
const { runBatch, distributeAcrossNodes, createCloneSemaphore } = require('../../utils/batch-deployer');
const goadDeploy = require('../../utils/goad-deploy');
const tailscale = require('../../utils/tailscale');
const {
  V3_INTERNAL_TAG_OFFSET,
  ATTACK_BOX_VMID_OFFSET,
  KALI_TEMPLATE_VMID,
  resolveGatewayVmid,
  resolveLaneNetworking,
  configureLaneTailscale,
  formatLaneGatewayNet0,
} = require('../../utils/lane-networking');

const adminOnly = requireRole('admin');

const N8N_DEPLOY_WEBHOOK = process.env.N8N_DEPLOY_LANE_WEBHOOK || 'http://100.100.20.50:5678/webhook-test/6bcb6b80-01d9-41a4-86e5-c0747fef50db';

// Legacy fallback password when generatePassword() is unavailable
const GROUP_PASSWORD_FALLBACK = 'ClinicP@ssw0rd123!!';


// ============================================================================
// GROUP DEPLOYMENT
// ============================================================================

router.post('/deploy-group', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { group_name, num_instructors, num_students, attack_boxes, challenge_key, module, deploy_lanes, use_webhook, confirm, vuln_scripts: groupVulnScripts } = req.body;
    if (!group_name || !num_students) {
      return res.status(400).json({ error: 'group_name and num_students required' });
    }

    const numInst = parseInt(num_instructors) || 0;
    const numStud = parseInt(num_students) || 1;
    const shouldDeployLanes = !!deploy_lanes && !!challenge_key && !!module;

    if (!confirm && shouldDeployLanes) {
      try {
        let preflightVmCount = 1;
        try {
          const pfResult = await cybercoreQuery(
            `SELECT spec FROM ${module}_challenge WHERE challenge_key = $1 AND status = 'active'`, [challenge_key]
          );
          if (pfResult.rows.length > 0) {
            const pfSpec = typeof pfResult.rows[0].spec === 'string' ? JSON.parse(pfResult.rows[0].spec) : pfResult.rows[0].spec;
            preflightVmCount = (pfSpec.vms || []).length || 1;
          }
        } catch (_) {}

        const preview = await buildDeployPreview({
          numLanes: numStud,
          attackBoxes: !!attack_boxes,
          challengeVmCount: preflightVmCount,
          proxmoxAPI,
          cybercoreQuery
        });
        return res.json({ preview: true, ...preview });
      } catch (err) {
        console.error('[Group Deploy] Pre-flight check failed:', err.message);
      }
    }

    let spec = null;
    let vxlanBlock = null;
    let availableVxlans = [];
    let subnetScheme = 'v1';
    if (shouldDeployLanes) {
      const modResult = await cybercoreQuery(
        `SELECT EXISTS (SELECT 1 FROM cybercore_module WHERE key = $1) AS is_installed`,
        [module]
      );
      if (!modResult.rows[0].is_installed) {
        return res.status(400).json({ error: `Module '${module}' is not installed` });
      }

      const challengeResult = await cybercoreQuery(
        `SELECT challenge_id, challenge_key, name, spec, subnet_scheme
         FROM ${module}_challenge
         WHERE challenge_key = $1 AND status = 'active'`,
        [challenge_key]
      );
      if (challengeResult.rows.length === 0) {
        return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
      }
      spec = typeof challengeResult.rows[0].spec === 'string'
        ? JSON.parse(challengeResult.rows[0].spec) : challengeResult.rows[0].spec;
      subnetScheme = challengeResult.rows[0].subnet_scheme || 'v1';

      vxlanBlock = {
        start: spec.vxlan_block?.start ?? 10000,
        end: spec.vxlan_block?.end ?? 10009
      };
      const vxlanResult = await cybercoreQuery(
        `WITH used AS (
          SELECT DISTINCT vxlan_id FROM cybercore_lane
          WHERE vxlan_id IS NOT NULL
            AND vxlan_id BETWEEN $1 AND $2
            AND status NOT IN ('error')
        )
        SELECT gs AS vxlan_id
        FROM generate_series($1::int, $2::int) AS gs
        LEFT JOIN used u ON u.vxlan_id = gs
        WHERE u.vxlan_id IS NULL
        ORDER BY gs`,
        [vxlanBlock.start, vxlanBlock.end]
      );
      availableVxlans = vxlanResult.rows.map(r => r.vxlan_id);

      if (availableVxlans.length < numStud) {
        return res.status(400).json({
          error: `Not enough VXLAN capacity. Need ${numStud} lanes but only ${availableVxlans.length} available (range ${vxlanBlock.start}-${vxlanBlock.end}).`
        });
      }
    }

    const groupId = uuidv4();
    const created = { instructors: [], students: [], guac_group: null, guac_users: [], guac_connections: [], lanes: [], credentials: [] };

    try {
      const guacGroup = await guacAPI('POST', '/connectionGroups', {
        name: group_name,
        type: 'ORGANIZATIONAL',
        parentIdentifier: 'ROOT',
        attributes: {}
      });
      created.guac_group = guacGroup;
    } catch (e) {
      created.guac_group_error = e.message;
    }

    for (let i = 1; i <= numInst; i++) {
      const userId = uuidv4();
      const email = `${group_name.toLowerCase().replace(/[^a-z0-9]/g, '')}-instructor${i}@clinic.local`;
      const password = generatePassword();
      const passwordHash = await bcrypt.hash(password, 12);

      await cybercoreQuery(
        `INSERT INTO cybercore_user (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
         VALUES ($1, $2, $3, $4, 'bcrypt', $5, $6, $7, $8, true, NOW())
         RETURNING user_id, email, first_name, last_name, role`,
        [userId, email, email, passwordHash, 'Instructor', `${i}`, group_name, 'instructor']
      );
      created.instructors.push({ id: userId, email, name: `Instructor ${i}` });
      created.credentials.push({ email, password, role: 'instructor' });

      try {
        await guacAPI('POST', '/users', {
          username: email,
          password,
          attributes: { disabled: null, timezone: 'America/Phoenix' }
        });
        created.guac_users.push(email);
      } catch (e) { /* skip if Guac unreachable */ }
    }

    for (let i = 1; i <= numStud; i++) {
      const userId = uuidv4();
      const email = `${group_name.toLowerCase().replace(/[^a-z0-9]/g, '')}-student${i}@clinic.local`;
      const password = generatePassword();
      const passwordHash = await bcrypt.hash(password, 12);

      await cybercoreQuery(
        `INSERT INTO cybercore_user (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
         VALUES ($1, $2, $3, $4, 'bcrypt', $5, $6, $7, $8, true, NOW())
         RETURNING user_id, email, first_name, last_name, role`,
        [userId, email, email, passwordHash, 'Student', `${i}`, group_name, 'student']
      );
      created.students.push({ id: userId, email, name: `Student ${i}` });
      created.credentials.push({ email, password, role: 'student' });

      try {
        await guacAPI('POST', '/users', {
          username: email,
          password,
          attributes: { disabled: null, timezone: 'America/Phoenix' }
        });
        created.guac_users.push(email);
      } catch (e) { /* skip if Guac unreachable */ }
    }

    if (created.guac_group?.identifier) {
      const groupId_guac = created.guac_group.identifier;
      for (const guacUser of created.guac_users) {
        try {
          await guacAPI('PATCH', `/users/${encodeURIComponent(guacUser)}/permissions`, [
            { op: 'add', path: `/connectionGroupPermissions/${groupId_guac}`, value: 'READ' }
          ]);
        } catch (_) {}
      }
      console.log(`[Group ${group_name}] Granted ${created.guac_users.length} users access to Guac group ${groupId_guac}`);
    }

    await query(
      `INSERT INTO deployed_groups (id, group_name, config, created_by, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [groupId, group_name, JSON.stringify({
        instructors: created.instructors,
        students: created.students,
        credentials: created.credentials,
        guac_group: created.guac_group,
        guac_users: created.guac_users,
        attack_boxes: !!attack_boxes,
        challenge_key: challenge_key || null,
        module: module || null,
        deploy_lanes: shouldDeployLanes
      }), req.user.userId]
    );

    if (shouldDeployLanes) {
      const templateVmid = spec.template_vmid || 1600;
      const gatewayVmid = resolveGatewayVmid(module, subnetScheme, spec);
      const templateNode = await findTemplateNode(templateVmid, spec.template_node || getDefaultTemplateNode());
      console.log(`[Group Deploy] subnet_scheme=${subnetScheme} → gateway template=${gatewayVmid}`);

      let nodeAssignments;
      try {
        nodeAssignments = await distributeAcrossNodes(proxmoxAPI, numStud);
      } catch (e) {
        console.warn(`[Group Deploy] Batch node distribution failed, falling back to single node: ${e.message}`);
        const bestNodeInfo = await selectBestNode();
        nodeAssignments = new Array(numStud).fill(bestNodeInfo.node);
      }

      let vnets = [];
      try {
        vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      } catch (e) {
        console.error('Could not fetch VNets for group deploy:', e.message);
      }

      const laneJobs = [];
      for (let i = 0; i < created.students.length; i++) {
        const student = created.students[i];
        const vxlanId = availableVxlans[i];
        const vnet = vnets.find(v => v.tag === vxlanId);

        if (!vnet) {
          console.warn(`No VNet for VXLAN ${vxlanId}, skipping lane for ${student.email}`);
          continue;
        }
        const vnetInt = subnetScheme === 'v3'
          ? vnets.find(v => v.tag === vxlanId + V3_INTERNAL_TAG_OFFSET)
          : null;
        if (subnetScheme === 'v3' && !vnetInt) {
          console.warn(`No internal VNet for VXLAN ${vxlanId} (v3), skipping lane for ${student.email}`);
          continue;
        }

        try {
          const studentCred = created.credentials.find(c => c.email === student.email);
          const studentPwHash = studentCred ? await bcrypt.hash(studentCred.password, 12) : null;
          await cybercoreQuery(
            `INSERT INTO cybercore_user (user_id, username, email, first_name, last_name, role, auth_provider, organization, password_hash, password_alg)
             VALUES ($1, $2, $3, $4, $5, 'student', 'local', $6, $7, 'bcrypt')
             ON CONFLICT (username) DO UPDATE SET user_id = $1, email = $3, organization = $6, password_hash = $7, password_alg = 'bcrypt'`,
            [student.id, student.email, student.email, `Student`, `${i + 1}`, group_name, studentPwHash]
          );

          const laneName = `${vnet.zone}-${vxlanId}`;
          const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: spec.template_vmid || 1600, type: 'qemu', vm_offset: 600000 }];
          const expectedVms = vmSpecs.map(vs => ({
            vm_id: (vs.vm_offset || 600000) + vxlanId,
            name: vs.name || challenge_key,
            type: vs.type || 'qemu'
          }));
          const laneConfig = JSON.stringify({
            challenge_key,
            module,
            group_id: groupId,
            group_name,
            gateway_vm_id: 100000 + vxlanId,
            attack_box_vm_id: attack_boxes ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null,
            vms: expectedVms
          });
          const laneInsert = await cybercoreQuery(
            `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
             VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW())
             RETURNING lane_id`,
            [student.id, vxlanId, laneName, laneConfig, module]
          );
          const laneId = laneInsert.rows[0].lane_id;
          created.lanes.push({ lane_id: laneId, student_email: student.email, vxlan_id: vxlanId });
          laneJobs.push({ laneId, student, vxlanId, vnet, vnetInt, laneName, targetNode: nodeAssignments[i] });
        } catch (err) {
          console.error(`Failed to create lane record for ${student.email}:`, err.message);
        }
      }

      (async () => {
        const concurrency = getSchedulingConfig().max_concurrent_lanes;
        const cloneSem = createCloneSemaphore();
        console.log(`[Group ${group_name}] Starting parallel deployment of ${laneJobs.length} lanes (lane concurrency: ${concurrency}, max concurrent clones: ${cloneSem.max})...`);

        const batchId = groupId;
        if (!global._batchDeployProgress) global._batchDeployProgress = {};
        global._batchDeployProgress[batchId] = {
          group_name,
          total: laneJobs.length,
          completed: 0,
          succeeded: 0,
          failed: 0,
          started_at: new Date().toISOString(),
          phase: 'preparing',
          phase_detail: 'Replicating gateway templates',
          elapsed_s: 0,
          avg_lane_s: null,
          eta_s: null,
          eta_at: null,
          lanes: {},
          _laneTimes: []
        };
        const progress = global._batchDeployProgress[batchId];
        const deployStartTime = Date.now();

        function updateProgressTiming() {
          const now = Date.now();
          progress.elapsed_s = Math.round((now - deployStartTime) / 1000);
          if (progress._laneTimes.length > 0) {
            const avgMs = progress._laneTimes.reduce((a, b) => a + b, 0) / progress._laneTimes.length;
            progress.avg_lane_s = Math.round(avgMs / 1000);
            const remaining = progress.total - progress.completed;
            const etaMs = (remaining / concurrency) * avgMs;
            progress.eta_s = Math.round(etaMs / 1000);
            progress.eta_at = new Date(now + etaMs).toISOString();
          }
        }

        // Phase 1a: Replicate gateway template to each target node
        const uniqueTargetNodes = [...new Set(laneJobs.map(j => j.targetNode))];
        const tempTemplateIds = {};
        const TEMP_GW_TEMPLATE_BASE = 169200;
        let tempIdCounter = 0;

        progress.phase = 'gateway_replication';
        progress.phase_detail = `Replicating gateway template to ${uniqueTargetNodes.length} nodes`;
        console.log(`[Group ${group_name}] Phase 1a: Replicating gateway template ${gatewayVmid} to ${uniqueTargetNodes.length} nodes...`);

        for (const node of uniqueTargetNodes) {
          if (node === templateNode) {
            tempTemplateIds[node] = gatewayVmid;
            console.log(`[Group ${group_name}] Node ${node} is template home — using original ${gatewayVmid}`);
            continue;
          }
          const tempId = TEMP_GW_TEMPLATE_BASE + tempIdCounter++;
          try {
            console.log(`[Group ${group_name}] Replicating gateway template → ${tempId} on ${node}...`);
            const cloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
              newid: tempId,
              hostname: `gw-template-temp-${node}`,
              full: 1,
              target: node,
              description: `Temp gateway template for batch deploy (group: ${group_name})`
            });
            if (cloneResult) await waitForTask(templateNode, cloneResult);
            tempTemplateIds[node] = tempId;
            console.log(`[Group ${group_name}] Gateway template replicated to ${node} as ${tempId}`);
          } catch (err) {
            console.error(`[Group ${group_name}] Failed to replicate template to ${node}: ${err.message}`);
            tempTemplateIds[node] = gatewayVmid;
          }
        }

        // Phase 1b: Clone all gateways in parallel from node-local templates
        progress.phase = 'gateway_cloning';
        progress.phase_detail = `Cloning ${laneJobs.length} gateways in parallel`;
        updateProgressTiming();
        console.log(`[Group ${group_name}] Phase 1b: Cloning ${laneJobs.length} gateways in parallel from node-local templates...`);
        const gatewayResults = {};

        const lanesByNode = {};
        for (const job of laneJobs) {
          if (!lanesByNode[job.targetNode]) lanesByNode[job.targetNode] = [];
          lanesByNode[job.targetNode].push(job);
        }

        await Promise.all(Object.entries(lanesByNode).map(async ([node, jobs]) => {
          const localTemplateId = tempTemplateIds[node];
          const sourceNode = node === templateNode ? templateNode : node;

          for (const job of jobs) {
            const { laneId, student, vxlanId, vnet, vnetInt } = job;
            const gatewayVmId = 100000 + vxlanId;
            try {
              console.log(`[Group ${group_name}] Cloning gateway LXC ${localTemplateId}@${sourceNode} → ${gatewayVmId} for ${student.email}`);
              const gwCloneResult = await proxmoxAPI('POST', `/api2/json/nodes/${sourceNode}/lxc/${localTemplateId}/clone`, {
                newid: gatewayVmId,
                hostname: `${job.laneName}-gateway`,
                full: 1,
                target: node,
                description: `Group: ${group_name}\nStudent: ${student.email}\nLane: ${laneId}`,
                pool: `${module}-pool`
              });
              if (gwCloneResult) await waitForTask(sourceNode, gwCloneResult);
              const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
              if (subnetScheme === 'v3') {
                await proxmoxAPI('PUT', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/config`, {
                  net0: formatLaneGatewayNet0(net.wan),
                  net1: `name=ext0,bridge=${vnet.vnet},ip=${net.lanExt.gatewayIp}/24,type=veth`,
                  net2: `name=int0,bridge=${vnetInt.vnet},ip=${net.lanInt.gatewayIp}/24,type=veth`
                });
              } else {
                await proxmoxAPI('PUT', `/api2/json/nodes/${node}/lxc/${gatewayVmId}/config`, {
                  net0: formatLaneGatewayNet0(net.wan),
                  net1: `name=lan0,bridge=${vnet.vnet},ip=${net.lan.gatewayIp}/24,type=veth`
                });
              }
              await configureLaneTailscale({
                subnetScheme,
                vxlanId,
                wanIp: net.wan.ip.split('/')[0],
                laneName: job.laneName,
                logTag: `[Group ${group_name}]`
              });
              gatewayResults[laneId] = { success: true };
              console.log(`[Group ${group_name}] Gateway ${gatewayVmId} cloned on ${node}`);
            } catch (err) {
              console.error(`[Group ${group_name}] Gateway clone failed for ${student.email}: ${err.message}`);
              gatewayResults[laneId] = { success: false, error: err.message };
            }
          }
        }));

        const gwSuccessCount = Object.values(gatewayResults).filter(r => r.success).length;
        console.log(`[Group ${group_name}] Phase 1b complete: ${gwSuccessCount}/${laneJobs.length} gateways cloned`);

        // Phase 1c: Delete temporary template copies
        const tempIdsToDelete = Object.entries(tempTemplateIds)
          .filter(([_, id]) => id !== gatewayVmid)
          .map(([node, id]) => ({ node, id }));

        if (tempIdsToDelete.length > 0) {
          progress.phase_detail = 'Cleaning up temp gateway templates';
          console.log(`[Group ${group_name}] Phase 1c: Cleaning up ${tempIdsToDelete.length} temp gateway templates...`);
          await Promise.all(tempIdsToDelete.map(async ({ node, id }) => {
            try {
              await proxmoxAPI('DELETE', `/api2/json/nodes/${node}/lxc/${id}?purge=1&force=1`);
              console.log(`[Group ${group_name}] Deleted temp template ${id} on ${node}`);
            } catch (e) {
              console.warn(`[Group ${group_name}] Could not delete temp template ${id} on ${node}: ${e.message}`);
            }
          }));
        }

        // Phase 2: Clone QEMU VMs + Kali in parallel
        progress.phase = 'deploying';
        progress.phase_detail = `Deploying lanes (${concurrency} at a time, max ${cloneSem.max} concurrent clones)`;
        updateProgressTiming();
        console.log(`[Group ${group_name}] Phase 2: Cloning challenge VMs and Kali in parallel (concurrency: ${concurrency})...`);

        const { results, errors } = await runBatch(laneJobs, async (job) => {
          const { laneId, student, vxlanId, vnet, vnetInt, targetNode } = job;
          const bestNode = targetNode;

          if (!gatewayResults[laneId]?.success) {
            throw new Error(`Skipped: gateway clone failed — ${gatewayResults[laneId]?.error}`);
          }

          progress.lanes[laneId] = { student: student.email, vxlan: vxlanId, node: bestNode, status: 'cloning', _startedAt: Date.now() };
          console.log(`[Group ${group_name}] Deploying lane ${laneId} for ${student.email} on ${bestNode} (VXLAN ${vxlanId})${use_webhook ? ' via webhook' : ''}...`);

          if (use_webhook) {
            const webhookRes = await fetch(N8N_DEPLOY_WEBHOOK, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ user_id: student.id, challenge_key, module, event_id: null })
            });
            if (!webhookRes.ok) {
              const errText = await webhookRes.text();
              throw new Error(`N8N webhook failed (${webhookRes.status}): ${errText}`);
            }
            const webhookData = await webhookRes.json();
            if (webhookData.lane_id || webhookData.laneId) {
              console.log(`[Group ${group_name}] Webhook deployed lane for ${student.email}:`, webhookData);
            }
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', updated_at = NOW() WHERE lane_id = $1`,
              [laneId]
            );
          } else {
            const gatewayVmId = 100000 + vxlanId;
            const deployedVMs = [];
            // Captured during Guac connection creation, persisted into the
            // Kali vm_instance metadata so My Workspaces shows a Console button.
            let kaliGuacConnId = null;
            const net = resolveLaneNetworking(subnetScheme, module, vxlanId);
            const isV3 = subnetScheme === 'v3';
            const vnetExtName = vnet.vnet;
            const vnetIntName = isV3 ? vnetInt.vnet : vnet.vnet;
            const laneSubnetBase = isV3 ? net.lanExt.base3 : net.lan.base3;
            const goadSubnetBase = isV3 ? net.lanInt.base3 : net.lan.base3;

            const goadMacs = goadDeploy.prepareGoadMacs(spec, vxlanId, goadSubnetBase);

            const vmSpecs = spec.vms || [{ name: challenge_key, template_vmid: templateVmid, type: 'qemu', vm_offset: 600000 }];
            const clonePromises = vmSpecs.map(async (vmSpec) => {
              const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
              const vmTemplate = vmSpec.template_vmid || templateVmid;
              const vmName = vmSpec.name || challenge_key;
              const vmType = vmSpec.type || 'qemu';
              const goadMac = goadMacs[vmName]?.mac;
              const isGoadVm = !!goadMacs[vmName];
              const isDmz = vmSpec.role === 'dmz';
              const vmVnet = (isV3 && isGoadVm) ? vnetIntName : vnetExtName;

              await cloneSem.run(async () => {
                console.log(`[Group ${group_name}] Cloning ${vmType} template ${vmTemplate} → ${vmId} (${vmName}) for ${student.email}`);

                if (vmType === 'lxc') {
                  const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
                    newid: vmId, hostname: `${vmName}-${student.email.split('@')[0]}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
                    description: `Group: ${group_name}\nVM: ${vmName}\nStudent: ${student.email}\nLane: ${laneId}`,
                    pool: `${module}-pool`
                  });
                  if (result) await waitForTask(templateNode, result);
                  await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, {
                    net1: goadDeploy.buildLaneNet0({ type: 'lxc' }, vmVnet, goadMac)
                  });
                } else {
                  const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
                    newid: vmId, name: `${vmName}-${student.email.split('@')[0]}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(), full: 1, target: bestNode,
                    description: `Group: ${group_name}\nVM: ${vmName}\nStudent: ${student.email}\nLane: ${laneId}`,
                    pool: `${module}-pool`
                  });
                  if (result) await waitForTask(templateNode, result);
                  if (isV3 && isDmz) {
                    await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
                      net0: `virtio,bridge=${vnetExtName}`,
                      net1: `virtio,bridge=${vnetIntName}`
                    });
                    await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, {
                      ipconfig0:  `ip=${net.lanExt.base3}.50/24,gw=${net.lanExt.gatewayIp}`,
                      ipconfig1:  `ip=${net.lanInt.base3}.50/24`,
                      nameserver: net.lanExt.gatewayIp,
                      citype:     'nocloud'
                    });
                    await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${vmId}/cloudinit`).catch(() => {});
                  } else {
                    const goadVm = goadMacs[vmName];
                    const vmConfig = {
                      net0: goadDeploy.buildLaneNet0(vmSpec, vmVnet, goadMac, goadVm?.nic_model)
                    };
                    if (goadVm?.memory)  vmConfig.memory  = goadVm.memory;
                    if (goadVm?.balloon) vmConfig.balloon = goadVm.balloon;
                    if (goadVm?.cores)   vmConfig.cores   = goadVm.cores;
                    await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, vmConfig);
                  }
                }
              });

              return { vm_id: vmId, name: vmName, type: vmType, node: bestNode };
            });

            const shouldDeployAttackBox = !!attack_boxes;
            let attackBoxVmId = shouldDeployAttackBox ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null;
            const studentUsername = student.email.split('@')[0].replace(/[^a-z0-9_-]/gi, '-');
            const studentCred = created.credentials.find(c => c.email === student.email);
            const studentPassword = studentCred ? studentCred.password : GROUP_PASSWORD_FALLBACK;

            const kaliClonePromise = shouldDeployAttackBox ? (async () => {
              await cloneSem.run(async () => {
                console.log(`[Group ${group_name}] Cloning Kali attack box → ${attackBoxVmId} for ${student.email}...`);
                const kaliClone = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${KALI_TEMPLATE_VMID}/clone`, {
                  newid: attackBoxVmId,
                  name: `kali-${studentUsername}`,
                  full: 1,
                  target: bestNode,
                  description: `Attack Box (Kali)\nGroup: ${group_name}\nStudent: ${student.email}\nLane: ${laneId}`,
                  pool: `${module}-pool`
                });
                if (kaliClone) await waitForTask(templateNode, kaliClone);
              });

              console.log(`[Group ${group_name}] Configuring cloud-init for ${attackBoxVmId} (user: ${studentUsername})...`);
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/config`, {
                net0: `virtio,bridge=${vnet.vnet}`,
                ciuser: studentUsername,
                cipassword: studentPassword,
                nameserver: `${laneSubnetBase}.1`
              });
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/cloudinit`);
            })() : Promise.resolve();

            progress.lanes[laneId].status = 'cloning';
            const [clonedVMs] = await Promise.all([
              Promise.all(clonePromises),
              kaliClonePromise
            ]);
            deployedVMs.push(...clonedVMs);

            progress.lanes[laneId].status = 'starting';
            await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
            await new Promise(r => setTimeout(r, 5000));
            for (const dvm of deployedVMs) {
              const startPath = dvm.type === 'lxc'
                ? `/api2/json/nodes/${dvm.node}/lxc/${dvm.vm_id}/status/start`
                : `/api2/json/nodes/${dvm.node}/qemu/${dvm.vm_id}/status/start`;
              await proxmoxAPI('POST', startPath);
            }

            if (spec.goad?.enabled) {
              progress.lanes[laneId].status = 'provisioning_goad';
              try {
                await goadDeploy.deployGoadLane({
                  lane: { lane_id: laneId },
                  spec, module, vnet: isV3 ? vnetInt : vnet, vxlanId, gatewayVmId,
                  bestNode, templateNode, laneSubnetBase: goadSubnetBase, deployedVMs,
                  proxmoxAPI, waitForTask, query: cybercoreQuery
                });
              } catch (goadErr) {
                console.error(`[Group ${group_name}] GOAD provisioning failed for ${student.email}: ${goadErr.message}`);
              }
            }

            if (attackBoxVmId) {
              progress.lanes[laneId].status = 'configuring_kali';
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/status/start`);
              console.log(`[Group ${group_name}] Kali attack box ${attackBoxVmId} started for ${student.email}`);

              console.log(`[Group ${group_name}] Waiting for Kali guest agent...`);
              await new Promise(r => setTimeout(r, 30000));

              let kaliIp = null;
              for (let attempt = 0; attempt < 10 && !kaliIp; attempt++) {
                try {
                  const agentData = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/agent/network-get-interfaces`);
                  const interfaces = agentData.result || agentData || [];
                  for (const iface of interfaces) {
                    if (iface.name === 'lo') continue;
                    const ipAddrs = iface['ip-addresses'] || [];
                    for (const addr of ipAddrs) {
                      if (addr['ip-address-type'] === 'ipv4' && !addr['ip-address'].startsWith('127.')) {
                        kaliIp = addr['ip-address'];
                        console.log(`[Group ${group_name}] Kali IP via guest agent: ${kaliIp} (${iface.name})`);
                        break;
                      }
                    }
                    if (kaliIp) break;
                  }
                } catch (agentErr) {
                  console.log(`[Group ${group_name}] Guest agent attempt ${attempt + 1}/10: ${agentErr.message}`);
                }
                if (!kaliIp && attempt < 9) {
                  await new Promise(r => setTimeout(r, 5000));
                }
              }

              if (!kaliIp) {
                console.warn(`[Group ${group_name}] Could not get Kali IP via guest agent — using fallback`);
                kaliIp = `${laneSubnetBase}.100`;
              }
              console.log(`[Group ${group_name}] Kali IP: ${kaliIp}`);

              let gatewayTransitIp = null;
              try {
                const gwConfig = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`);
                const net0 = gwConfig.net0 || '';
                const ipMatch = net0.match(/ip=([\d.]+)/);
                if (ipMatch) gatewayTransitIp = ipMatch[1];
              } catch (_) {}

              if (!gatewayTransitIp) {
                try {
                  await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/exec`, {
                    command: JSON.stringify(['sh', '-c', "ip -4 addr show wan0 | grep inet | awk '{print $2}' | cut -d/ -f1"])
                  });
                } catch (_) {}
              }

              if (!gatewayTransitIp) {
                try {
                  const gwInterfaces = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/interfaces`);
                  for (const iface of (gwInterfaces || [])) {
                    if (iface.name === 'wan0' && iface.inet) {
                      gatewayTransitIp = iface.inet.split('/')[0];
                      break;
                    }
                  }
                } catch (_) {}
              }

              const guacTargetIp = gatewayTransitIp || kaliIp;
              console.log(`[Group ${group_name}] Guac RDP target: ${guacTargetIp} (${gatewayTransitIp ? 'via gateway DNAT' : 'direct to Kali'})`);

              // DNAT install is no longer a deploy-time concern — the gateway
              // template bakes wan0:3389 → <lane-base>.50:3389 into firstboot,
              // and Kali is pinned to .50 via cloud-init ipconfig0 above.

              try {
                const guacParent = created.guac_group?.identifier || 'ROOT';
                const kaliConn = await guacAPI('POST', '/connections', {
                  name: `${group_name} - ${student.email.split('@')[0]} - Kali`,
                  protocol: 'rdp',
                  parentIdentifier: guacParent,
                  parameters: {
                    hostname: guacTargetIp,
                    port: '3389',
                    username: studentUsername,
                    password: studentPassword,
                    security: 'any',
                    'ignore-cert': 'true',
                    // Without server-layout the Guac UI shows "Keyboard layout"
                    // as unset and keystrokes never reach xrdp. en-us-qwerty
                    // matches the default xrdp keymap on Kali; override per
                    // template later if a different physical keyboard is used.
                    'server-layout': 'en-us-qwerty',
                    'enable-wallpaper': 'true',
                    'enable-theming': 'true',
                    'enable-font-smoothing': 'true',
                    'enable-full-window-drag': 'true',
                    'color-depth': '24',
                    'resize-method': 'display-update'
                  },
                  attributes: {
                    'max-connections': '2',
                    'max-connections-per-user': '1'
                  }
                });

                if (kaliConn?.identifier) {
                  const connId = kaliConn.identifier;
                  kaliGuacConnId = connId;
                  created.guac_connections.push({
                    id: connId,
                    name: `${group_name} - ${student.email.split('@')[0]} - Kali`,
                    student_email: student.email
                  });
                  try {
                    await guacAPI('PATCH', `/users/${encodeURIComponent(student.email)}/permissions`, [
                      { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' }
                    ]);
                    console.log(`[Group ${group_name}] Guac connection ${connId} → ${student.email}`);
                  } catch (permErr) {
                    console.warn(`[Group ${group_name}] Student perm failed for ${student.email}: ${permErr.message}`);
                  }

                  for (const inst of created.instructors) {
                    try {
                      await guacAPI('PATCH', `/users/${encodeURIComponent(inst.email)}/permissions`, [
                        { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' }
                      ]);
                    } catch (_) {}
                  }
                }
              } catch (guacErr) {
                console.warn(`[Group ${group_name}] Could not create Guac connection for ${student.email}: ${guacErr.message}`);
              }
            }

            if (groupVulnScripts && groupVulnScripts.length > 0) {
              progress.lanes[laneId].status = 'running_scripts';
              console.log(`[Group ${group_name}] Running ${groupVulnScripts.length} vuln scripts for ${student.email}...`);
              const scriptEntries = groupVulnScripts.map(s => ({
                script_slug: s.script_slug,
                vm_name: s.vm_name || deployedVMs[0]?.name || 'default',
                status: 'pending', error: null
              }));

              const dvsResult = await query(
                `INSERT INTO deployment_vuln_selections (lane_id, selected_scripts, status)
                 VALUES ($1, $2, 'running_scripts') RETURNING id`,
                [laneId, JSON.stringify(scriptEntries)]
              );
              const deploymentId = dvsResult.rows[0].id;

              for (const vm of deployedVMs) {
                if (vm.type !== 'qemu') continue;
                const agentReady = await waitForGuestAgent(vm.node, vm.vm_id, 180000);
                if (!agentReady) { console.error(`[Group ${group_name}] Guest agent not responding on ${vm.name}`); continue; }
                const vmScriptSlugs = groupVulnScripts.filter(s => (s.vm_name || deployedVMs[0]?.name) === vm.name).map(s => s.script_slug);
                if (vmScriptSlugs.length > 0) {
                  const scriptRows = await query(`SELECT slug, script_content, os_target, depends_on, script_args FROM vuln_scripts WHERE slug = ANY($1) AND is_active = true`, [vmScriptSlugs]);
                  if (scriptRows.rows.length > 0) {
                    await executeScriptsOnVM(vm.node, vm.vm_id, vm.name, scriptRows.rows, deploymentId);
                  }
                }
              }
              await query(`UPDATE deployment_vuln_selections SET status = 'complete', updated_at = NOW() WHERE id = $1`, [deploymentId]);
              console.log(`[Group ${group_name}] Vuln scripts completed for ${student.email}`);
            }

            // Register each lane VM (challenge VMs + Kali, NOT the gateway —
            // gateway is plumbing, not a workspace) in cybercore_resource +
            // cybercore_vm_instance + cybercore_allocation so the student's
            // "My Workspaces" page sees them. Only Kali gets a guac_connection_id
            // since that's the only VM with a Guac connection in the group flow.
            //
            // Resource names are (module_key, name) UNIQUE — a single challenge
            // deployed to N lanes would collide on the base VM name (e.g. "ws01").
            // Suffix with the Proxmox VMID (cluster-unique) to guarantee uniqueness
            // while keeping the name human-readable.
            const studentSlug = student.email.split('@')[0].replace(/[^a-z0-9-]/gi, '-').toLowerCase();
            try {
              const vmInstanceRows = [
                ...deployedVMs.map(v => ({
                  name: `${v.name}-${studentSlug}-${v.vm_id}`.substring(0, 80),
                  displayName: v.name,
                  vmid: v.vm_id,
                  node: v.node,
                  providerType: v.type === 'lxc' ? 'lxc' : 'qemu',
                  guacConnId: null,
                  templateName: v.name
                })),
                ...(attackBoxVmId ? [{
                  name: `kali-${studentSlug}-${attackBoxVmId}`.substring(0, 80),
                  displayName: `kali-${studentSlug}`,
                  vmid: attackBoxVmId,
                  node: bestNode,
                  providerType: 'qemu',
                  guacConnId: kaliGuacConnId,
                  templateName: 'Kali (Attack Box)'
                }] : [])
              ];

              for (const v of vmInstanceRows) {
                const resourceRes = await cybercoreQuery(`
                  INSERT INTO cybercore_resource (type, module_key, name, status, metadata)
                  VALUES ('vm', $1, $2, 'allocated', $3::jsonb)
                  RETURNING resource_id
                `, [
                  module,
                  v.name,
                  JSON.stringify({
                    vm_category:    'lane_vm',
                    provider_type:  v.providerType,
                    template_name:  v.templateName,
                    lane_id:        laneId,
                    group_id:       groupId,
                    group_name,
                    challenge_key,
                    vxlan_id:       vxlanId
                  })
                ]);
                const resourceId = resourceRes.rows[0].resource_id;

                await cybercoreQuery(`
                  INSERT INTO cybercore_vm_instance
                    (resource_id, provider, provider_node, provider_vmid, power_state, metadata)
                  VALUES ($1, 'proxmox', $2, $3, 'running', $4::jsonb)
                `, [
                  resourceId,
                  v.node,
                  String(v.vmid),
                  JSON.stringify({
                    provider_type: v.providerType,
                    ...(v.guacConnId ? { guac_connection_id: v.guacConnId, guac_user: student.email } : {})
                  })
                ]);

                await cybercoreQuery(`
                  INSERT INTO cybercore_allocation (resource_id, user_id, purpose)
                  VALUES ($1, $2, 'lane_vm')
                `, [resourceId, student.id]);
              }
            } catch (regErr) {
              // Non-fatal: lane still goes active, but VMs won't surface in My Workspaces.
              console.warn(`[Group ${group_name}] Lane VM registration failed for ${student.email}: ${regErr.message}`);
            }

            const activeConfig = {
              challenge_vm_id: deployedVMs[0]?.vm_id,
              gateway_vm_id: gatewayVmId,
              attack_box_vm_id: attackBoxVmId || null,
              node: bestNode,
              challenge_key,
              module,
              group_id: groupId,
              group_name,
              vms: deployedVMs,
              subnet_scheme: subnetScheme,
              lane_subnet_base: laneSubnetBase,
              vnet: vnetExtName,
              ...(isV3 ? {
                vnet_internal: vnetIntName,
                lane_subnet_internal: goadSubnetBase
              } : {})
            };
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
              [laneId, JSON.stringify(activeConfig)]
            );
          }

          progress.lanes[laneId].status = 'active';
          console.log(`[Group ${group_name}] Lane ${laneId} deployed (VXLAN ${vxlanId}, node ${bestNode}, student ${student.email}${attack_boxes ? ' + Kali' : ''})`);
          return { laneId, student: student.email, vxlanId };
        }, {
          concurrency,
          onProgress: (completed, total, job, result) => {
            progress.completed = completed;
            if (result.success) progress.succeeded++;
            else progress.failed++;
            const laneProgress = progress.lanes[job.laneId];
            if (laneProgress && laneProgress._startedAt) {
              progress._laneTimes.push(Date.now() - laneProgress._startedAt);
            }
            updateProgressTiming();
            progress.phase_detail = `Deploying lanes: ${completed}/${total} complete`;
            const etaStr = progress.eta_s != null ? ` — ETA ${Math.ceil(progress.eta_s / 60)}min` : '';
            console.log(`[Group ${group_name}] Progress: ${completed}/${total} (${progress.succeeded} ok, ${progress.failed} failed)${etaStr}`);
            if (!result.success) {
              const errMsg = result.error?.message || result.error || 'unknown error';
              console.error(`[Group ${group_name}] Lane ${job.laneId} (${job.student?.email || '?'}) FAILED: ${errMsg}`);
              if (result.error?.stack) {
                console.error(`[Group ${group_name}] Lane ${job.laneId} stack:\n${result.error.stack}`);
              }
            }
          }
        });

        for (const err of errors) {
          const job = laneJobs[err.index];
          if (job) {
            console.error(`[Group ${group_name}] Lane ${job.laneId} error (post-batch): ${err.error?.message || err.error}`);
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'error', config = config || $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
              [job.laneId, JSON.stringify({ error: err.error?.message || String(err.error) })]
            ).catch(() => {});
          }
        }

        progress.phase = 'complete';
        progress.phase_detail = `${progress.succeeded} succeeded, ${progress.failed} failed`;
        progress.finished_at = new Date().toISOString();
        progress.eta_s = 0;
        progress.eta_at = null;
        updateProgressTiming();
        console.log(`[Group ${group_name}] All ${laneJobs.length} lane deployments complete (${progress.succeeded} succeeded, ${progress.failed} failed) in ${progress.elapsed_s}s.`);

        try {
          await query(
            `UPDATE deployed_groups
             SET config = jsonb_set(config::jsonb, '{guac_connections}', $1::jsonb, true)
             WHERE id = $2`,
            [JSON.stringify(created.guac_connections || []), groupId]
          );
          console.log(`[Group ${group_name}] Persisted ${created.guac_connections.length} Guac connection IDs to group config`);
        } catch (e) {
          console.warn(`[Group ${group_name}] Failed to persist guac_connections: ${e.message}`);
        }

        setTimeout(() => { delete global._batchDeployProgress[batchId]; }, 3600000);
      })();
    }

    logActivity(req, 'deploy_group', 'group', groupId, {
      group_name, instructors: created.instructors.length, students: created.students.length,
      lanes: created.lanes.length, deploy_lanes: shouldDeployLanes
    });

    res.json({
      success: true,
      group_id: groupId,
      group_name,
      instructors_created: created.instructors.length,
      students_created: created.students.length,
      guac_users_created: created.guac_users.length,
      guac_group: created.guac_group ? 'created' : 'failed',
      lanes_deploying: created.lanes.length,
      lanes: created.lanes,
      credentials: created.credentials
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/deploy-group/:groupId/progress', authenticateToken, adminOnly, (req, res) => {
  const progress = (global._batchDeployProgress || {})[req.params.groupId];
  if (!progress) {
    return res.status(404).json({ error: 'No active batch deployment found for this group' });
  }
  const { _laneTimes, ...clean } = progress;
  const cleanLanes = {};
  for (const [id, lane] of Object.entries(clean.lanes || {})) {
    const { _startedAt, ...laneClean } = lane;
    cleanLanes[id] = laneClean;
  }
  res.json({ ...clean, lanes: cleanLanes });
});


// ============================================================================
// GROUP MANAGEMENT
// ============================================================================

router.get('/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, group_name, config, created_by, created_at FROM deployed_groups ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/groups/:id', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(`SELECT * FROM deployed_groups WHERE id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const group = result.rows[0];
    const config = typeof group.config === 'string' ? JSON.parse(group.config) : group.config;
    const allUsers = [...(config.instructors || []), ...(config.students || [])];
    const errors = [];
    const students = config.students || [];

    const allVmsToDestroy = [];
    const laneIds = [];
    const vmNodeMap = {};

    const [clusterResources, nodeList] = await Promise.all([
      proxmoxAPI('GET', '/api2/json/cluster/resources').catch(() => []),
      proxmoxAPI('GET', '/api2/json/nodes').catch(() => [])
    ]);
    const allNodeNames = nodeList.map(n => n.node);
    if (allNodeNames.length === 0) allNodeNames.push(...getClusterNodes());

    for (const r of clusterResources) {
      if (r.type === 'qemu' || r.type === 'lxc') {
        vmNodeMap[r.vmid] = r.node;
      }
    }

    const studentLaneResults = await Promise.all(
      students.map(student =>
        cybercoreQuery(
          `SELECT lane_id, vxlan_id, status, config FROM cybercore_lane WHERE user_id = $1`,
          [student.id]
        ).then(r => r.rows).catch(() => [])
      )
    );

    let groupChallengeSpec = null;
    const groupChallengeKey = config.challenge_key;
    const groupModule = config.module;
    if (groupChallengeKey && groupModule) {
      try {
        const specResult = await cybercoreQuery(
          `SELECT spec FROM ${groupModule}_challenge WHERE challenge_key = $1 AND status = 'active'`,
          [groupChallengeKey]
        );
        if (specResult.rows.length > 0) {
          groupChallengeSpec = typeof specResult.rows[0].spec === 'string'
            ? JSON.parse(specResult.rows[0].spec) : specResult.rows[0].spec;
        }
      } catch (_) {}
    }

    for (const lanes of studentLaneResults) {
      for (const lane of lanes) {
        laneIds.push(lane.lane_id);
        const vxlanId = lane.vxlan_id;
        if (!vxlanId || lane.status === 'deleted') continue;

        const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});

        if (Array.isArray(laneConfig.vms) && laneConfig.vms.length > 0) {
          for (const vm of laneConfig.vms) {
            allVmsToDestroy.push({ vmid: vm.vm_id, type: vm.type || 'qemu', label: vm.name || `VM-${vm.vm_id}`, laneId: lane.lane_id });
          }
        } else if (groupChallengeSpec && Array.isArray(groupChallengeSpec.vms) && groupChallengeSpec.vms.length > 0) {
          for (const vmSpec of groupChallengeSpec.vms) {
            const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
            allVmsToDestroy.push({ vmid: vmId, type: vmSpec.type || 'qemu', label: vmSpec.name || `VM-${vmId}`, laneId: lane.lane_id });
          }
        } else {
          const challengeVmId = laneConfig.challenge_vm_id || (600000 + vxlanId);
          allVmsToDestroy.push({ vmid: challengeVmId, type: 'qemu', label: 'challenge', laneId: lane.lane_id });
        }

        const gatewayVmId = laneConfig.gateway_vm_id || (100000 + vxlanId);
        allVmsToDestroy.push({ vmid: gatewayVmId, type: 'lxc', label: 'gateway', laneId: lane.lane_id });

        const attackBoxVmId = laneConfig.attack_box_vm_id || (ATTACK_BOX_VMID_OFFSET + vxlanId);
        allVmsToDestroy.push({ vmid: attackBoxVmId, type: 'qemu', label: 'attack-box', laneId: lane.lane_id });

        const goadControllerVmId = 200000 + vxlanId;
        allVmsToDestroy.push({ vmid: goadControllerVmId, type: 'qemu', label: 'goad-controller', laneId: lane.lane_id });
      }
    }

    console.log(`[Group Teardown] ${group.group_name}: ${allVmsToDestroy.length} VMs to destroy across ${laneIds.length} lanes`);

    const existingVms = allVmsToDestroy.filter(vm => vmNodeMap[vm.vmid]);
    const missingVms = allVmsToDestroy.length - existingVms.length;
    if (missingVms > 0) {
      console.log(`[Group Teardown] ${missingVms} VMs not found in cluster (already deleted or never created)`);
    }

    // Phase 2: Unprotect + force-stop all VMs in parallel
    console.log(`[Group Teardown] Phase 2: Unprotecting and force-stopping ${existingVms.length} VMs...`);
    await Promise.all(existingVms.map(async (vm) => {
      const node = vmNodeMap[vm.vmid];
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/config`, { protection: 0 }); } catch (_) {}
      try { await proxmoxAPI('PUT', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/config`, { lock: '' }); } catch (_) {}
    }));

    const stopTasks = [];
    await Promise.all(existingVms.map(async (vm) => {
      const node = vmNodeMap[vm.vmid];
      try {
        const stopBody = vm.type === 'qemu' ? { timeout: 0 } : {};
        const upid = await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/stop`, stopBody);
        if (upid) stopTasks.push({ node, upid, type: vm.type, vmid: vm.vmid });
      } catch (e) {
        console.warn(`[Group Teardown] Stop failed for ${vm.type} ${vm.vmid} on ${node}: ${e.message}`);
      }
    }));

    console.log(`[Group Teardown] Waiting for ${stopTasks.length} stop tasks to complete...`);
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
    if (pendingStops.length > 0) {
      console.warn(`[Group Teardown] ${pendingStops.length} stop tasks still pending after 30s, proceeding with delete...`);
    }

    // Phase 3: Delete all VMs in parallel
    const buildDeleteUrl = (node, type, vmid) => type === 'lxc'
      ? `/api2/json/nodes/${node}/lxc/${vmid}?purge=1&force=1`
      : `/api2/json/nodes/${node}/qemu/${vmid}?purge=1&skiplock=1`;

    console.log(`[Group Teardown] Phase 3: Deleting ${existingVms.length} VMs...`);
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
          console.log(`[Group Teardown] Destroyed ${vm.type} ${vm.vmid} (${vm.label}) on ${node}`);
          return;
        } catch (e) {
          if (/unable to find configuration file/i.test(e.message) || /does not exist/i.test(e.message)) {
            console.log(`[Group Teardown] ${vm.type} ${vm.vmid} already gone on ${node}`);
            return;
          }
          if (node === nodesToTry[nodesToTry.length - 1]) {
            throw new Error(`${vm.type} ${vm.vmid} (${vm.label}): failed on all nodes — ${e.message}`);
          }
        }
      }
    }, { concurrency: 15 });

    for (const err of destroyErrors) {
      errors.push(err.error);
    }

    // Phase 4: Verify and retry orphans
    let orphanedCount = 0;
    const allTargetVmIds = allVmsToDestroy.map(v => v.vmid);

    for (let round = 1; round <= 3; round++) {
      try {
        const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');
        const stillAlive = resources.filter(r => (r.type === 'qemu' || r.type === 'lxc') && allTargetVmIds.includes(r.vmid));
        if (stillAlive.length === 0) {
          console.log(`[Group Teardown] All VMs confirmed destroyed${round > 1 ? ` (after ${round - 1} retry rounds)` : ''}`);
          break;
        }

        orphanedCount = stillAlive.length;
        console.warn(`[Group Teardown] Round ${round}: ${stillAlive.length} VMs still exist — retrying...`);

        await Promise.all(stillAlive.map(async (vm) => {
          try {
            try { await proxmoxAPI('PUT', `/api2/json/nodes/${vm.node}/${vm.type}/${vm.vmid}/config`, { protection: 0 }); } catch (_) {}
            const stopBody = vm.type === 'qemu' ? { timeout: 0 } : {};
            try { await proxmoxAPI('POST', `/api2/json/nodes/${vm.node}/${vm.type}/${vm.vmid}/status/stop`, stopBody); } catch (_) {}
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
            console.log(`[Group Teardown] Retry round ${round}: destroyed ${vm.type} ${vm.vmid} on ${vm.node}`);
          } catch (e) {
            if (/unable to find configuration file/i.test(e.message)) {
              console.log(`[Group Teardown] Retry round ${round}: ${vm.type} ${vm.vmid} already gone`);
              return;
            }
            if (round === 3) errors.push(`Orphaned VM ${vm.vmid} on ${vm.node}: ${e.message}`);
          }
        }));
      } catch (e) {
        console.error(`[Group Teardown] Verify round ${round} failed: ${e.message}`);
        break;
      }
    }

    // Phase 5: Cleanup DB and Guac in parallel
    const allUserIds = allUsers.map(u => u.id);
    const allUserEmails = allUsers.map(u => u.email);

    const torndownVxlanIds = [];
    for (const lanes of studentLaneResults) {
      for (const ln of lanes) {
        if (ln.vxlan_id && ln.status !== 'deleted') torndownVxlanIds.push(ln.vxlan_id);
      }
    }

    // cybercore_allocation has CHECK (user_id IS NOT NULL OR group_key IS NOT NULL)
    // and cybercore_user FK is ON DELETE SET NULL — so deleting a user would
    // try to NULL out user_id on any of their allocations not tied to a
    // group_key, which violates the check and rolls back the user delete.
    // Purge each user's allocations FIRST (before the user delete in the
    // Promise.all below) so the user delete has nothing left to SET NULL on.
    if (allUserIds.length > 0) {
      try {
        const ar = await cybercoreQuery(
          `DELETE FROM cybercore_allocation WHERE user_id = ANY($1::uuid[])`,
          [allUserIds]
        );
        console.log(`[Group Teardown] cybercore_allocation DELETE: ${ar.rowCount} rows removed (pre-user-delete)`);
      } catch (e) {
        console.error(`[Group Teardown] Allocation cleanup FAILED: ${e.message}`);
        errors.push(`Allocation cleanup: ${e.message}`);
      }
    }

    await Promise.all([
      laneIds.length > 0
        ? cybercoreQuery(`DELETE FROM cybercore_lane WHERE lane_id = ANY($1)`, [laneIds]).catch(e => errors.push(`Lane cleanup: ${e.message}`))
        : Promise.resolve(),

      // Drop the cybercore_resource rows we created for each lane VM during
      // deploy (see "Lane VM registration" in deploy path). The vm_instance
      // and allocation rows cascade. Skip if no lane IDs to delete.
      laneIds.length > 0
        ? cybercoreQuery(
            `DELETE FROM cybercore_resource WHERE (metadata->>'lane_id')::uuid = ANY($1::uuid[])`,
            [laneIds]
          ).catch(e => errors.push(`Lane VM resource cleanup: ${e.message}`))
        : Promise.resolve(),

      allUserIds.length > 0
        ? cybercoreQuery(
            `DELETE FROM cybercore_user WHERE user_id = ANY($1::uuid[]) OR username = ANY($2)`,
            [allUserIds, allUserEmails]
          )
          .then(r => {
            console.log(`[Group Teardown] cybercore_user DELETE: ${r.rowCount}/${allUserIds.length} rows removed`);
            if (r.rowCount < allUserIds.length) {
              const msg = `Only ${r.rowCount}/${allUserIds.length} cybercore_user rows deleted — check for FK constraints (badges awarded, schedules overridden, etc.)`;
              console.warn(`[Group Teardown] ${msg}`);
              errors.push(msg);
            }
          })
          .catch(e => {
            console.error(`[Group Teardown] User cleanup FAILED: ${e.message}`);
            errors.push(`User cleanup: ${e.message}`);
          })
        : Promise.resolve(),

      ...((config.guac_users || []).map(username =>
        guacAPI('DELETE', `/users/${encodeURIComponent(username)}`).catch(e => {
          console.warn(`[Group Teardown] Guac user delete failed for ${username}: ${e.message}`);
          errors.push(`Guac delete ${username}: ${e.message}`);
        })
      )),

      ...((config.guac_connections || []).map(conn =>
        guacAPI('DELETE', `/connections/${encodeURIComponent(conn.id)}`).catch(e => errors.push(`Guac connection ${conn.id} (${conn.name || '?'}): ${e.message}`))
      )),

      config.guac_group?.identifier
        ? guacAPI('DELETE', `/connectionGroups/${config.guac_group.identifier}`).catch(e => errors.push(`Guac group delete: ${e.message}`))
        : Promise.resolve(),

      ...torndownVxlanIds.map(vxId =>
        tailscale.deleteLaneDevices({ vxlanId: vxId }).catch(() => {})
      )
    ]);

    // Phase 6: Sweep orphaned disks
    const destroyedVmIdSet = new Set(allVmsToDestroy.map(v => v.vmid));
    let orphanDisksSwept = 0;
    const orphanDiskErrors = [];
    const sweptVolids = new Set();

    try {
      const orphanDisks = [];
      const discoveries = await Promise.all(allNodeNames.map(async (node) => {
        const found = [];
        let nodeStorages;
        try {
          nodeStorages = await proxmoxAPI('GET', `/api2/json/nodes/${node}/storage`);
        } catch (_) { return found; }

        for (const s of nodeStorages || []) {
          if (s.content && !s.content.includes('images')) continue;
          let contents;
          try {
            contents = await proxmoxAPI('GET',
              `/api2/json/nodes/${node}/storage/${s.storage}/content?content=images`);
          } catch (_) { continue; }

          for (const item of contents || []) {
            const match = item.volid?.match(/vm-(\d+)-(disk|cloudinit)/);
            if (!match) continue;
            const vmid = parseInt(match[1]);
            if (!destroyedVmIdSet.has(vmid)) continue;
            found.push({ node, storage: s.storage, volid: item.volid, kind: match[2] });
          }
        }
        return found;
      }));
      for (const arr of discoveries) orphanDisks.push(...arr);

      for (const d of orphanDisks) {
        if (sweptVolids.has(d.volid)) continue;
        sweptVolids.add(d.volid);

        let deleted = false;
        let lastErr = null;
        for (let attempt = 1; attempt <= 3 && !deleted; attempt++) {
          try {
            await proxmoxAPI('DELETE',
              `/api2/json/nodes/${d.node}/storage/${d.storage}/content/${encodeURIComponent(d.volid)}`);
            console.log(`[Group Teardown] Swept orphaned ${d.kind || 'disk'}: ${d.volid} on ${d.node}/${d.storage}`);
            orphanDisksSwept++;
            deleted = true;
          } catch (e) {
            lastErr = e;
            if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
          }
        }
        if (!deleted && lastErr) {
          orphanDiskErrors.push(`${d.volid}: ${lastErr.message}`);
        }
      }
    } catch (e) {
      console.error(`[Group Teardown] Orphan disk sweep failed: ${e.message}`);
      orphanDiskErrors.push(`Sweep error: ${e.message}`);
    }

    if (orphanDisksSwept > 0) console.log(`[Group Teardown] Swept ${orphanDisksSwept} orphaned disk images`);
    if (orphanDiskErrors.length > 0) errors.push(...orphanDiskErrors.map(e => `Disk sweep: ${e}`));

    await query(`DELETE FROM deployed_groups WHERE id = $1`, [req.params.id]);

    logActivity(req, 'delete_group', 'group', req.params.id, {
      group_name: group.group_name, users_deleted: allUsers.length, lanes_deleted: laneIds.length,
      vms_destroyed: allVmsToDestroy.length, orphaned_vms_found: orphanedCount,
      orphan_disks_swept: orphanDisksSwept, errors: errors.length
    });

    res.json({
      success: true,
      users_deleted: allUsers.length,
      lanes_deleted: laneIds.length,
      vms_destroyed: allVmsToDestroy.length,
      orphaned_vms_retried: orphanedCount,
      orphan_disks_swept: orphanDisksSwept,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/groups/:id/toggle-active', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { active } = req.body;
    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'active (boolean) required' });
    }

    const result = await query(`SELECT * FROM deployed_groups WHERE id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const config = typeof result.rows[0].config === 'string'
      ? JSON.parse(result.rows[0].config) : result.rows[0].config;
    const students = config.students || [];

    if (students.length === 0) {
      return res.status(400).json({ error: 'No students in this group' });
    }

    const studentIds = students.map(s => s.id);
    const updated = await cybercoreQuery(
      `UPDATE cybercore_user SET active = $1, status = CASE WHEN $1 THEN 'active' ELSE 'inactive' END, updated_at = NOW()
       WHERE user_id = ANY($2) AND role = 'student'
       RETURNING user_id, email, active`,
      [active, studentIds]
    );

    let lanesToggled = 0;
    const vmErrors = [];

    for (const student of students) {
      try {
        const lanesResult = await cybercoreQuery(
          `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane
           WHERE user_id = $1 AND status IN ('active', 'suspended')`,
          [student.id]
        );

        for (const lane of lanesResult.rows) {
          const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
          const node = laneConfig.node;
          if (!node) continue;

          const vmsToToggle = [];
          if (Array.isArray(laneConfig.vms)) {
            for (const vm of laneConfig.vms) {
              vmsToToggle.push({ vmid: vm.vm_id, type: vm.type || 'qemu' });
            }
          } else if (laneConfig.challenge_vm_id) {
            vmsToToggle.push({ vmid: laneConfig.challenge_vm_id, type: 'qemu' });
          }
          const gatewayVmId = laneConfig.gateway_vm_id || laneConfig.lane_gateway_vm_id;
          if (gatewayVmId) vmsToToggle.push({ vmid: gatewayVmId, type: 'lxc' });
          if (laneConfig.attack_box_vm_id) vmsToToggle.push({ vmid: laneConfig.attack_box_vm_id, type: 'qemu' });

          if (!active) {
            for (const vm of vmsToToggle) {
              try {
                await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/stop`);
                console.log(`[Toggle] Stopped ${vm.type} ${vm.vmid} on ${node}`);
              } catch (e) {
                vmErrors.push(`Stop ${vm.type} ${vm.vmid}: ${e.message}`);
              }
            }
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'suspended', updated_at = NOW() WHERE lane_id = $1`,
              [lane.lane_id]
            );
          } else {
            const gateway = vmsToToggle.find(v => v.type === 'lxc');
            const others = vmsToToggle.filter(v => v !== gateway);

            if (gateway) {
              try {
                await proxmoxAPI('POST', `/api2/json/nodes/${node}/${gateway.type}/${gateway.vmid}/status/start`);
                console.log(`[Toggle] Started gateway ${gateway.vmid} on ${node}`);
              } catch (e) { vmErrors.push(`Start gateway ${gateway.vmid}: ${e.message}`); }
              await new Promise(r => setTimeout(r, 3000));
            }

            for (const vm of others) {
              try {
                await proxmoxAPI('POST', `/api2/json/nodes/${node}/${vm.type}/${vm.vmid}/status/start`);
                console.log(`[Toggle] Started ${vm.type} ${vm.vmid} on ${node}`);
              } catch (e) { vmErrors.push(`Start ${vm.type} ${vm.vmid}: ${e.message}`); }
            }

            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', updated_at = NOW() WHERE lane_id = $1`,
              [lane.lane_id]
            );
          }
          lanesToggled++;
        }
      } catch (e) {
        vmErrors.push(`Lane lookup for ${student.email}: ${e.message}`);
      }
    }

    if (!active) {
      try {
        const activeSessions = await guacAPI('GET', '/activeConnections');
        const studentEmails = students.map(s => s.email);
        const toKill = Object.entries(activeSessions || {})
          .filter(([, session]) => studentEmails.includes(session.username))
          .map(([connId]) => ({ op: 'remove', path: `/${connId}` }));

        if (toKill.length > 0) {
          const token = await getGuacToken();
          await fetch(`${GUAC_URL}/api/session/data/${GUAC_DS}/activeConnections?token=${token}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(toKill)
          });
          console.log(`[Toggle] Killed ${toKill.length} Guacamole sessions`);
        }
      } catch (e) {
        console.error('[Toggle] Failed to kill Guac sessions:', e.message);
      }
    }

    logActivity(req, 'toggle_accounts', 'group', req.params.id, {
      group_name: result.rows[0].group_name, active, students_updated: updated.rows.length
    });

    res.json({
      success: true,
      group_name: result.rows[0].group_name,
      active,
      students_updated: updated.rows.length,
      lanes_toggled: lanesToggled,
      vm_errors: vmErrors.length > 0 ? vmErrors : undefined
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACCOUNT SCHEDULES
// ============================================================================

router.get('/groups/:id/schedule', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM account_schedules WHERE group_id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.json({ group_id: req.params.id, schedule: null });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/groups/:id/schedule', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { active_days, active_start, active_end, timezone } = req.body;

    if (!Array.isArray(active_days) || active_days.some(d => d < 0 || d > 6)) {
      return res.status(400).json({ error: 'active_days must be array of 0-6 (Sun-Sat)' });
    }
    if (!active_start || !active_end) {
      return res.status(400).json({ error: 'active_start and active_end required (HH:MM format)' });
    }

    const groupResult = await query(`SELECT id FROM deployed_groups WHERE id = $1`, [req.params.id]);
    if (groupResult.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const result = await query(
      `INSERT INTO account_schedules (group_id, active_days, active_start, active_end, timezone)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (group_id) DO UPDATE SET
         active_days = EXCLUDED.active_days,
         active_start = EXCLUDED.active_start,
         active_end = EXCLUDED.active_end,
         timezone = COALESCE(EXCLUDED.timezone, account_schedules.timezone),
         updated_at = NOW()
       RETURNING *`,
      [req.params.id, active_days, active_start, active_end, timezone || 'America/Chicago']
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/groups/:id/schedule/override', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { override_active } = req.body;

    if (override_active !== true && override_active !== false && override_active !== null) {
      return res.status(400).json({ error: 'override_active must be true, false, or null' });
    }

    const result = await query(
      `UPDATE account_schedules
       SET override_active = $1,
           override_by = $2,
           override_at = NOW(),
           updated_at = NOW()
       WHERE group_id = $3
       RETURNING *`,
      [override_active, req.user.userId, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No schedule found for this group. Create one first.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
