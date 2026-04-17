/**
 * CLE Plugin — Student Management API
 * Add, remove, modify students within deployed groups.
 * Lane deployment/teardown mirrors admin.js group-deploy logic exactly.
 * All endpoints require instructor or admin role (applied by api.js).
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const { query } = require('../../../src/utils/db');
const { cybercoreQuery } = require('../../../src/utils/cybercore-db');
const { guacAPI } = require('../../../src/utils/guacamole');
const { proxmoxAPI, waitForTask } = require('../../../src/utils/proxmox');
const { generatePassword } = require('../../../src/utils/password-generator');
const { selectBestNode } = require('../../../src/utils/node-selector');

const ATTACK_BOX_VMID_OFFSET = 700000;
const KALI_TEMPLATE_VMID = 1699;

// ============================================================================
// HELPERS
// ============================================================================

async function getInstructorGroups(userId, userRole) {
  const result = await query(`SELECT id, group_name, config, created_at FROM deployed_groups ORDER BY created_at DESC`);
  if (userRole === 'admin') return result.rows;
  return result.rows.filter(g => {
    const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
    return (cfg.instructors || []).some(i => i.id === userId);
  });
}

function parseCfg(row) {
  return typeof row.config === 'string' ? JSON.parse(row.config) : (row.config || {});
}

async function getGroupDeploymentContext(cfg) {
  const challengeKey = cfg.challenge_key;
  const module = cfg.module;
  if (!challengeKey || !module) return null;

  try {
    const challengeResult = await cybercoreQuery(
      `SELECT challenge_key, spec FROM ${module}_challenge WHERE challenge_key = $1 AND status = 'active'`,
      [challengeKey]
    );
    if (challengeResult.rows.length === 0) return null;
    const spec = typeof challengeResult.rows[0].spec === 'string'
      ? JSON.parse(challengeResult.rows[0].spec) : challengeResult.rows[0].spec;
    return { challengeKey, module, spec };
  } catch (e) {
    console.error(`[CLE] Failed to load challenge spec: ${e.message}`);
    return null;
  }
}

async function allocateVxlan(spec) {
  const vxlanBlock = {
    start: spec.vxlan_block?.start ?? 10000,
    end: spec.vxlan_block?.end ?? 10009
  };
  const result = await cybercoreQuery(
    `WITH used AS (
      SELECT DISTINCT vxlan_id FROM cybercore_lane
      WHERE vxlan_id IS NOT NULL AND vxlan_id BETWEEN $1 AND $2 AND status NOT IN ('error')
    )
    SELECT gs AS vxlan_id
    FROM generate_series($1::int, $2::int) AS gs
    LEFT JOIN used u ON u.vxlan_id = gs
    WHERE u.vxlan_id IS NULL
    ORDER BY gs LIMIT 1`,
    [vxlanBlock.start, vxlanBlock.end]
  );
  if (result.rows.length === 0) return null;
  return result.rows[0].vxlan_id;
}

// ============================================================================
// LIST STUDENTS
// ============================================================================

router.get('/', async (req, res) => {
  try {
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    if (groups.length === 0) return res.json({ groups: [], students: [] });

    const allStudents = [];
    for (const group of groups) {
      const cfg = parseCfg(group);
      for (const student of (cfg.students || [])) {
        allStudents.push({
          ...student,
          group_id: group.id,
          group_name: group.group_name,
          challenge_key: cfg.challenge_key || null
        });
      }
    }

    if (allStudents.length === 0) return res.json({ groups, students: [] });

    const studentIds = allStudents.map(s => s.id);
    const placeholders = studentIds.map((_, i) => `$${i + 1}`).join(',');

    const lanesResult = await cybercoreQuery(
      `SELECT lane_id, user_id, vxlan_id, name, status, config, created_at
       FROM cybercore_lane
       WHERE user_id::text IN (${placeholders}) AND status != 'deleted'
       ORDER BY created_at DESC`,
      studentIds
    );
    const laneMap = {};
    lanesResult.rows.forEach(l => { laneMap[l.user_id] = l; });

    const usersResult = await cybercoreQuery(
      `SELECT user_id, email, first_name, last_name FROM cybercore_user WHERE user_id::text IN (${placeholders})`,
      studentIds
    );
    const userMap = {};
    usersResult.rows.forEach(u => { userMap[u.user_id] = u; });

    const enriched = allStudents.map(s => ({
      id: s.id,
      email: userMap[s.id]?.email || s.email || 'unknown',
      first_name: userMap[s.id]?.first_name || 'Student',
      last_name: userMap[s.id]?.last_name || '',
      group_id: s.group_id,
      group_name: s.group_name,
      challenge_key: s.challenge_key,
      lane: laneMap[s.id] ? {
        lane_id: laneMap[s.id].lane_id,
        vxlan_id: laneMap[s.id].vxlan_id,
        status: laneMap[s.id].status,
        name: laneMap[s.id].name
      } : null
    }));

    res.json({ groups, students: enriched });
  } catch (error) {
    console.error('[CLE] List students error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// ADD STUDENT (with full lane deployment)
// ============================================================================

router.post('/', async (req, res) => {
  const { group_id, first_name, last_name, email } = req.body;
  if (!group_id) return res.status(400).json({ error: 'group_id required' });

  try {
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    const group = groups.find(g => g.id === group_id);
    if (!group) return res.status(403).json({ error: 'You are not an instructor for this group' });

    const cfg = parseCfg(group);
    const groupSlug = group.group_name.toLowerCase().replace(/[^a-z0-9]/g, '');
    const nextNum = (cfg.students || []).length + 1;

    const userId = uuidv4();
    const studentEmail = email || `${groupSlug}-student${nextNum}@clinic.local`;
    const studentFirstName = first_name || 'Student';
    const studentLastName = last_name || `${nextNum}`;
    const password = generatePassword();
    const passwordHash = await bcrypt.hash(password, 12);

    // 1. Create cybercore_user
    await cybercoreQuery(
      `INSERT INTO cybercore_user (user_id, username, email, password_hash, password_alg, first_name, last_name, organization, role, email_verified, created_at)
       VALUES ($1, $2, $3, $4, 'bcrypt', $5, $6, $7, 'student', true, NOW())`,
      [userId, studentEmail, studentEmail, passwordHash, studentFirstName, studentLastName, group.group_name]
    );

    // 2. Create Guacamole user + grant group permission
    let guacCreated = false;
    try {
      await guacAPI('POST', '/users', {
        username: studentEmail,
        password: password,
        attributes: { disabled: null, timezone: 'America/Phoenix' }
      });
      guacCreated = true;
      if (cfg.guac_group?.identifier) {
        await guacAPI('PATCH', `/users/${encodeURIComponent(studentEmail)}/permissions`, [
          { op: 'add', path: `/connectionGroupPermissions/${cfg.guac_group.identifier}`, value: 'READ' }
        ]);
      }
    } catch (e) {
      console.warn(`[CLE] Guac user creation failed for ${studentEmail}: ${e.message}`);
    }

    // 3. Update deployed_groups config
    const newStudent = { id: userId, email: studentEmail, name: `${studentFirstName} ${studentLastName}` };
    cfg.students = cfg.students || [];
    cfg.students.push(newStudent);
    cfg.credentials = cfg.credentials || [];
    cfg.credentials.push({ email: studentEmail, password, role: 'student' });
    await query(`UPDATE deployed_groups SET config = $1 WHERE id = $2`, [JSON.stringify(cfg), group_id]);

    // 4. Deploy lane (matching group's existing deployment)
    let laneResult = null;
    const deployCtx = await getGroupDeploymentContext(cfg);
    if (deployCtx && cfg.deploy_lanes !== false) {
      const { challengeKey, module, spec } = deployCtx;
      const vxlanId = await allocateVxlan(spec);

      if (vxlanId) {
        // Respond immediately with credentials, deploy lane in background
        const responsePayload = {
          student: newStudent,
          credentials: { email: studentEmail, password },
          guac_created: guacCreated,
          lane_deploying: true,
          vxlan_id: vxlanId,
          message: `Student added. Lane deploying in background (VXLAN ${vxlanId}).`
        };
        res.json(responsePayload);

        // Background deployment
        (async () => {
          try {
            const templateVmid = spec.template_vmid || 1600;
            const gatewayVmidByModule = { cyberlabs: 1691, crucible: 1692, forge: 1693 };
            const gatewayVmid = gatewayVmidByModule[module] || spec.gateway_vmid || 1692;
            const templateNode = spec.template_node || 'cyberhub-node-5';
            const bestNodeInfo = await selectBestNode();
            const bestNode = bestNodeInfo.node;

            const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
            const vnet = (Array.isArray(vnets) ? vnets : []).find(v => v.tag === vxlanId);
            if (!vnet) throw new Error(`No VNet for VXLAN ${vxlanId}`);

            const laneName = `${vnet.zone}-${vxlanId}`;
            const laneConfig = JSON.stringify({ challenge_key: challengeKey, module, group_id: group_id, group_name: group.group_name });
            const laneInsert = await cybercoreQuery(
              `INSERT INTO cybercore_lane (user_id, vxlan_id, name, status, config, module_key, created_at, updated_at)
               VALUES ($1, $2, $3, 'deploying', $4::jsonb, $5, NOW(), NOW()) RETURNING lane_id`,
              [userId, vxlanId, laneName, laneConfig, module]
            );
            const laneId = laneInsert.rows[0].lane_id;
            const deployedVMs = [];

            // Clone challenge VMs
            const vmSpecs = spec.vms || [{ name: challengeKey, template_vmid: templateVmid, type: 'qemu', vm_offset: 600000 }];
            for (const vmSpec of vmSpecs) {
              const vmId = (vmSpec.vm_offset || 600000) + vxlanId;
              const vmTemplate = vmSpec.template_vmid || templateVmid;
              const vmName = vmSpec.name || challengeKey;
              const vmType = vmSpec.type || 'qemu';

              console.log(`[CLE] Cloning ${vmType} template ${vmTemplate} -> ${vmId} (${vmName}) for ${studentEmail}`);
              if (vmType === 'lxc') {
                const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${vmTemplate}/clone`, {
                  newid: vmId, hostname: `${vmName}-${studentEmail.split('@')[0]}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(),
                  full: 1, target: bestNode, pool: `${module}-pool`
                });
                if (result) await waitForTask(templateNode, result);
                await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${vmId}/config`, { net1: `name=lan0,bridge=${vnet.vnet}` });
              } else {
                const result = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${vmTemplate}/clone`, {
                  newid: vmId, name: `${vmName}-${studentEmail.split('@')[0]}`.replace(/[^a-z0-9-]/gi, '-').substring(0, 63).toLowerCase(),
                  full: 1, target: bestNode, pool: `${module}-pool`
                });
                if (result) await waitForTask(templateNode, result);
                await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${vmId}/config`, { net0: `virtio,bridge=${vnet.vnet}` });
              }
              deployedVMs.push({ vm_id: vmId, name: vmName, type: vmType, node: bestNode });
            }

            // Clone gateway
            const gatewayVmId = 100000 + vxlanId;
            const gwResult = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/lxc/${gatewayVmid}/clone`, {
              newid: gatewayVmId, hostname: `${laneName}-gateway`, full: 1, target: bestNode, pool: `${module}-pool`
            });
            if (gwResult) await waitForTask(templateNode, gwResult);
            await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`, {
              net1: `name=lan0,bridge=${vnet.vnet},ip=192.18.0.1/24,gw=192.18.0.1`
            });

            // Clone attack box if group has them
            const hasAttackBoxes = !!cfg.attack_boxes;
            let attackBoxVmId = hasAttackBoxes ? (ATTACK_BOX_VMID_OFFSET + vxlanId) : null;
            const studentUsername = studentEmail.split('@')[0].replace(/[^a-z0-9_-]/gi, '-');

            if (hasAttackBoxes) {
              console.log(`[CLE] Cloning Kali attack box -> ${attackBoxVmId} for ${studentEmail}`);
              const kaliClone = await proxmoxAPI('POST', `/api2/json/nodes/${templateNode}/qemu/${KALI_TEMPLATE_VMID}/clone`, {
                newid: attackBoxVmId, name: `kali-${studentUsername}`, full: 1, target: bestNode, pool: `${module}-pool`
              });
              if (kaliClone) await waitForTask(templateNode, kaliClone);
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/config`, {
                net0: `virtio,bridge=${vnet.vnet}`, ciuser: studentUsername, cipassword: password
              });
              await proxmoxAPI('PUT', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/cloudinit`);
            }

            // Start VMs: gateway first, then challenge, then attack box
            await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/status/start`);
            await new Promise(r => setTimeout(r, 5000));
            for (const dvm of deployedVMs) {
              const startPath = dvm.type === 'lxc'
                ? `/api2/json/nodes/${dvm.node}/lxc/${dvm.vm_id}/status/start`
                : `/api2/json/nodes/${dvm.node}/qemu/${dvm.vm_id}/status/start`;
              await proxmoxAPI('POST', startPath);
            }

            if (attackBoxVmId) {
              await proxmoxAPI('POST', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/status/start`);
              await new Promise(r => setTimeout(r, 30000));

              // Get Kali IP via guest agent
              let kaliIp = null;
              for (let attempt = 0; attempt < 10 && !kaliIp; attempt++) {
                try {
                  const agentData = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/qemu/${attackBoxVmId}/agent/network-get-interfaces`);
                  for (const iface of (agentData.result || agentData || [])) {
                    if (iface.name === 'lo') continue;
                    for (const addr of (iface['ip-addresses'] || [])) {
                      if (addr['ip-address-type'] === 'ipv4' && !addr['ip-address'].startsWith('127.')) {
                        kaliIp = addr['ip-address']; break;
                      }
                    }
                    if (kaliIp) break;
                  }
                } catch (_) {}
                if (!kaliIp && attempt < 9) await new Promise(r => setTimeout(r, 5000));
              }
              if (!kaliIp) kaliIp = '192.18.0.100';

              // Get gateway transit IP
              let gatewayTransitIp = null;
              try {
                const gwConfig = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/config`);
                const ipMatch = (gwConfig.net0 || '').match(/ip=([\d.]+)/);
                if (ipMatch) gatewayTransitIp = ipMatch[1];
              } catch (_) {}
              if (!gatewayTransitIp) {
                try {
                  const gwInterfaces = await proxmoxAPI('GET', `/api2/json/nodes/${bestNode}/lxc/${gatewayVmId}/interfaces`);
                  for (const iface of (gwInterfaces || [])) {
                    if (iface.name === 'wan0' && iface.inet) { gatewayTransitIp = iface.inet.split('/')[0]; break; }
                  }
                } catch (_) {}
              }

              const guacTargetIp = gatewayTransitIp || kaliIp;

              // Create Guacamole RDP connection
              try {
                const guacParent = cfg.guac_group?.identifier || 'ROOT';
                const kaliConn = await guacAPI('POST', '/connections', {
                  name: `${group.group_name} - ${studentEmail.split('@')[0]} - Kali`,
                  protocol: 'rdp',
                  parentIdentifier: guacParent,
                  parameters: {
                    hostname: guacTargetIp, port: '3389',
                    username: studentUsername, password: password,
                    security: 'any', 'ignore-cert': 'true',
                    'enable-wallpaper': 'true', 'enable-theming': 'true',
                    'enable-font-smoothing': 'true', 'enable-full-window-drag': 'true',
                    'color-depth': '24', 'resize-method': 'display-update'
                  },
                  attributes: { 'max-connections': '2', 'max-connections-per-user': '1' }
                });

                if (kaliConn?.identifier) {
                  const connId = kaliConn.identifier;
                  // Grant student
                  await guacAPI('PATCH', `/users/${encodeURIComponent(studentEmail)}/permissions`, [
                    { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' }
                  ]).catch(() => {});
                  // Grant all group instructors
                  for (const inst of (cfg.instructors || [])) {
                    await guacAPI('PATCH', `/users/${encodeURIComponent(inst.email)}/permissions`, [
                      { op: 'add', path: `/connectionPermissions/${connId}`, value: 'READ' }
                    ]).catch(() => {});
                  }
                }
              } catch (guacErr) {
                console.warn(`[CLE] Guac connection failed for ${studentEmail}: ${guacErr.message}`);
              }
            }

            // Mark lane active
            const activeConfig = {
              challenge_vm_id: deployedVMs[0]?.vm_id,
              gateway_vm_id: gatewayVmId,
              attack_box_vm_id: attackBoxVmId || null,
              node: bestNode,
              challenge_key: challengeKey, module,
              group_id: group_id, group_name: group.group_name,
              vms: deployedVMs
            };
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'active', config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
              [laneId, JSON.stringify(activeConfig)]
            );
            console.log(`[CLE] Lane ${laneId} deployed for ${studentEmail} (VXLAN ${vxlanId})`);

          } catch (err) {
            console.error(`[CLE] Lane deployment failed for ${studentEmail}: ${err.message}`);
            // Mark lane as error
            await cybercoreQuery(
              `UPDATE cybercore_lane SET status = 'error', config = config || $2::jsonb, updated_at = NOW()
               WHERE user_id = $1 AND status = 'deploying'`,
              [userId, JSON.stringify({ error: err.message })]
            ).catch(() => {});
          }
        })();

        return; // Response already sent above
      } else {
        console.warn(`[CLE] No VXLAN available for ${studentEmail} — student added without lane`);
      }
    }

    // Fallback: no deployment context or no VXLANs — just add the student
    res.json({
      student: newStudent,
      credentials: { email: studentEmail, password },
      guac_created: guacCreated,
      lane_deploying: false,
      message: `Student added to ${group.group_name}. No lane deployed (group has no challenge configured or no VXLAN capacity).`
    });
  } catch (error) {
    console.error('[CLE] Add student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// REMOVE STUDENT (with full lane teardown)
// ============================================================================

router.delete('/:id', async (req, res) => {
  const studentId = req.params.id;

  try {
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    let targetGroup = null;
    let targetCfg = null;

    for (const g of groups) {
      const cfg = parseCfg(g);
      if ((cfg.students || []).some(s => s.id === studentId)) {
        targetGroup = g;
        targetCfg = cfg;
        break;
      }
    }
    if (!targetGroup) return res.status(403).json({ error: 'Student not found in your groups' });

    const student = targetCfg.students.find(s => s.id === studentId);
    const studentEmail = student?.email;

    // 1. Tear down all student lanes
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane WHERE user_id::text = $1 AND status != 'deleted'`,
      [studentId]
    );

    for (const lane of laneResult.rows) {
      const laneCfg = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
      const node = laneCfg.node;
      const vxlan = lane.vxlan_id;

      if (node && vxlan) {
        const vmIds = [];
        if (Array.isArray(laneCfg.vms)) {
          laneCfg.vms.forEach(vm => { if (vm.vm_id) vmIds.push({ id: vm.vm_id, type: vm.type || 'qemu' }); });
        } else if (laneCfg.challenge_vm_id) {
          vmIds.push({ id: laneCfg.challenge_vm_id, type: 'qemu' });
        } else {
          vmIds.push({ id: 600000 + vxlan, type: 'qemu' });
        }
        vmIds.push({ id: laneCfg.gateway_vm_id || (100000 + vxlan), type: 'lxc' });
        if (laneCfg.attack_box_vm_id) vmIds.push({ id: laneCfg.attack_box_vm_id, type: 'qemu' });

        for (const vm of vmIds) {
          try {
            const stopPath = vm.type === 'lxc'
              ? `/api2/json/nodes/${node}/lxc/${vm.id}/status/stop`
              : `/api2/json/nodes/${node}/qemu/${vm.id}/status/stop`;
            await proxmoxAPI('POST', stopPath);
          } catch (_) {}
          try {
            await new Promise(r => setTimeout(r, 2000));
            const delPath = vm.type === 'lxc'
              ? `/api2/json/nodes/${node}/lxc/${vm.id}?purge=1&force=1`
              : `/api2/json/nodes/${node}/qemu/${vm.id}?purge=1&skiplock=1&force=1`;
            await proxmoxAPI('DELETE', delPath);
          } catch (_) {}
        }
      }

      await cybercoreQuery(
        `UPDATE cybercore_lane SET status = 'deleted', updated_at = NOW() WHERE lane_id = $1`,
        [lane.lane_id]
      );
    }

    // 2. Delete Guacamole user + all their connections
    if (studentEmail) {
      try { await guacAPI('DELETE', `/users/${encodeURIComponent(studentEmail)}`); } catch (_) {}
    }

    // 3. Remove from group config
    targetCfg.students = targetCfg.students.filter(s => s.id !== studentId);
    targetCfg.credentials = (targetCfg.credentials || []).filter(c => c.email !== studentEmail);
    if (targetCfg.guac_users) {
      targetCfg.guac_users = targetCfg.guac_users.filter(u => u !== studentEmail);
    }
    await query(`UPDATE deployed_groups SET config = $1 WHERE id = $2`, [JSON.stringify(targetCfg), targetGroup.id]);

    // 4. Deactivate cybercore_user
    await cybercoreQuery(
      `UPDATE cybercore_user SET role = 'user', updated_at = NOW() WHERE user_id = $1`,
      [studentId]
    );

    console.log(`[CLE] Removed student ${studentEmail} from ${targetGroup.group_name} — ${laneResult.rows.length} lane(s) torn down (by ${req.user.email})`);

    res.json({
      ok: true,
      message: `Student ${studentEmail} removed. ${laneResult.rows.length} lane(s) and all VMs destroyed.`,
      lanes_deleted: laneResult.rows.length
    });
  } catch (error) {
    console.error('[CLE] Remove student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// MODIFY STUDENT
// ============================================================================

router.patch('/:id', async (req, res) => {
  const studentId = req.params.id;
  const { first_name, last_name, reset_password } = req.body;

  try {
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    let authorized = false;
    for (const g of groups) {
      const cfg = parseCfg(g);
      if ((cfg.students || []).some(s => s.id === studentId)) { authorized = true; break; }
    }
    if (!authorized) return res.status(403).json({ error: 'Student not found in your groups' });

    const updates = [];
    const params = [];
    let paramIdx = 1;

    if (first_name) { updates.push(`first_name = $${paramIdx++}`); params.push(first_name); }
    if (last_name) { updates.push(`last_name = $${paramIdx++}`); params.push(last_name); }

    let newPassword = null;
    if (reset_password) {
      newPassword = generatePassword();
      const hash = await bcrypt.hash(newPassword, 12);
      updates.push(`password_hash = $${paramIdx++}`);
      params.push(hash);

      const userResult = await cybercoreQuery(`SELECT email FROM cybercore_user WHERE user_id = $1`, [studentId]);
      if (userResult.rows.length > 0) {
        try {
          await guacAPI('PUT', `/users/${encodeURIComponent(userResult.rows[0].email)}/password`, {
            oldPassword: null, newPassword: newPassword
          });
        } catch (_) {}
      }
    }

    if (updates.length > 0) {
      updates.push(`updated_at = NOW()`);
      params.push(studentId);
      await cybercoreQuery(
        `UPDATE cybercore_user SET ${updates.join(', ')} WHERE user_id = $${paramIdx}`,
        params
      );
    }

    res.json({ ok: true, ...(newPassword ? { new_password: newPassword } : {}) });
  } catch (error) {
    console.error('[CLE] Modify student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
