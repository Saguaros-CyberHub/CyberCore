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
const { proxmoxAPI } = require('../../utils/proxmox');
const { getClusterNodes } = require('../../utils/site-config');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { guacAPI, getGuacToken, GUAC_URL, GUAC_DS } = require('../../utils/guacamole');
const { buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const { generatePassword } = require('../../utils/password-generator');
const { runBatch } = require('../../utils/batch-deployer');
const { allocateVxlanIds } = require('../../utils/lane-deployer');
const { deployChallengeLanes, parseSpec, readProgress } = require('../../utils/challenge-lane-deployer');
const tailscale = require('../../utils/tailscale');
const { ATTACK_BOX_VMID_OFFSET } = require('../../utils/lane-networking');

const adminOnly = requireRole('admin');


// ============================================================================
// GROUP DEPLOYMENT
//
// This route owns ACCOUNTS: it mints the throwaway instructor/student users,
// their Guacamole accounts, the organizational connection group, and the
// deployed_groups bookkeeping row. The VM side — gateway, challenge VMs, Kali,
// GOAD, vuln scripts, flags, workspace registration — lives in
// utils/challenge-lane-deployer.js, which the CLE plugin calls too.
// ============================================================================

router.post('/deploy-group', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { group_name, num_instructors, num_students, attack_boxes, challenge_key, module, deploy_lanes, confirm, vuln_scripts: groupVulnScripts } = req.body;
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
            `SELECT spec FROM ${module.replace(/[^a-z0-9_]/gi, '')}_challenge WHERE challenge_key = $1 AND status = 'active'`, [challenge_key]
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

    // Resolve the challenge and prove there is VXLAN room BEFORE any account is
    // created. A capacity failure discovered after the users exist leaves a
    // half-built group behind, which is exactly what this pre-check avoids.
    let challengeRow = null;
    if (shouldDeployLanes) {
      const modResult = await cybercoreQuery(
        `SELECT EXISTS (SELECT 1 FROM cybercore_module WHERE key = $1) AS is_installed`,
        [module]
      );
      if (!modResult.rows[0].is_installed) {
        return res.status(400).json({ error: `Module '${module}' is not installed` });
      }

      const challengeResult = await cybercoreQuery(
        `SELECT challenge_id, challenge_key, name, spec, subnet_scheme, module_key
         FROM ${module.replace(/[^a-z0-9_]/gi, '')}_challenge
         WHERE challenge_key = $1 AND status = 'active'`,
        [challenge_key]
      );
      if (challengeResult.rows.length === 0) {
        return res.status(404).json({ error: `Challenge '${challenge_key}' not found or not active` });
      }
      challengeRow = challengeResult.rows[0];

      const spec = parseSpec(challengeRow.spec);
      const vxlanBlock = {
        start: spec.vxlan_block?.start ?? 10000,
        end: spec.vxlan_block?.end ?? 10009,
      };
      // Same allocator the deploy itself uses, so the check and the deploy can't
      // disagree about what "free" means (it excludes error AND deleted lanes,
      // matching the ux_cybercore_lane_vxlan_active partial unique index).
      const free = await allocateVxlanIds(vxlanBlock, numStud);
      if (free.length < numStud) {
        return res.status(400).json({
          error: `Not enough VXLAN capacity. Need ${numStud} lanes but only ${free.length} available (range ${vxlanBlock.start}-${vxlanBlock.end}).`,
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
      // Deploy detached: the response returns as soon as the accounts and Guac
      // objects exist, so a class-sized deploy doesn't hold the HTTP request open
      // for the ten-plus minutes the clones take. Progress is polled from
      // GET /deploy-group/:groupId/progress, keyed on the group id.
      //
      // Everything below this point used to be ~800 lines inline here. It now
      // lives in utils/challenge-lane-deployer.js so the CLE plugin's "Deploy
      // Vulnerable Machine" path runs the identical sequence instead of a third
      // drifting copy of it.
      (async () => {
        try {
          const result = await deployChallengeLanes({
            users: created.students.map(s => ({
              id: s.id,
              email: s.email,
              // The account password minted above, so a student's portal login
              // and their Kali login stay the same secret.
              password: created.credentials.find(c => c.email === s.email)?.password || null,
            })),
            challenge: challengeRow,
            moduleKey: module,
            attackBoxes: !!attack_boxes,
            vulnScripts: (groupVulnScripts && groupVulnScripts.length) ? groupVulnScripts : null,
            laneConfig: { group_id: groupId, group_name },
            guacParent: created.guac_group?.identifier || 'ROOT',
            instructorEmails: created.instructors.map(i => i.email),
            description: `Group: ${group_name}`,
            progressId: groupId,
            progressLabel: group_name,
          });

          const guacConnections = result.provisioned
            .filter(p => p.guac_connection_id)
            .map(p => ({
              id: p.guac_connection_id,
              name: `${group_name} - ${p.attack_box_user} - Kali`,
              student_email: p.user_email,
            }));

          // Persist what the deploy actually produced. Written as one merge so a
          // concurrent config update can't drop either key.
          await query(
            `UPDATE deployed_groups
                SET config = config::jsonb || jsonb_build_object(
                      'guac_connections', $1::jsonb,
                      'lanes',            $2::jsonb)
              WHERE id = $3`,
            [JSON.stringify(guacConnections), JSON.stringify(result.lanes || []), groupId]
          );

          console.log(
            `[Group ${group_name}] Deploy finished: ${result.provisioned.length} lane(s) active, ` +
            `${result.failed.length} failed`
          );
        } catch (err) {
          console.error(`[Group ${group_name}] Lane deployment failed: ${err.message}`);
        }
      })();
    }

    // One lane per student is queued. The lane rows themselves are created by the
    // detached deploy above, so the ids arrive via the progress endpoint (and are
    // persisted onto deployed_groups.config when it finishes) rather than here.
    const lanesQueued = shouldDeployLanes ? created.students.length : 0;

    logActivity(req, 'deploy_group', 'group', groupId, {
      group_name, instructors: created.instructors.length, students: created.students.length,
      lanes: lanesQueued, deploy_lanes: shouldDeployLanes
    });

    res.json({
      success: true,
      group_id: groupId,
      group_name,
      instructors_created: created.instructors.length,
      students_created: created.students.length,
      guac_users_created: created.guac_users.length,
      guac_group: created.guac_group ? 'created' : 'failed',
      lanes_deploying: lanesQueued,
      lanes: created.lanes,
      credentials: created.credentials
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/deploy-group/:groupId/progress', authenticateToken, adminOnly, (req, res) => {
  const progress = readProgress(req.params.groupId);
  if (!progress) {
    return res.status(404).json({ error: 'No active batch deployment found for this group' });
  }
  res.json(progress);
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
          `SELECT spec FROM ${String(groupModule).replace(/[^a-z0-9_]/gi, '')}_challenge WHERE challenge_key = $1 AND status = 'active'`,
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
