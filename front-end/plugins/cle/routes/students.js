/**
 * CLE Plugin — Student Management API
 * Add, remove, modify students within deployed groups.
 * All endpoints require instructor or admin role (applied by api.js).
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const { query } = require('../../../src/utils/db');
const { cybercoreQuery } = require('../../../src/utils/cybercore-db');
const { guacAPI, GUAC_URL } = require('../../../src/utils/guacamole');
const { proxmoxAPI } = require('../../../src/utils/proxmox');
const { generatePassword } = require('../../../src/utils/password-generator');

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

async function getGroupStudents(groupId) {
  const result = await query(`SELECT config FROM deployed_groups WHERE id = $1`, [groupId]);
  if (result.rows.length === 0) return [];
  const cfg = typeof result.rows[0].config === 'string' ? JSON.parse(result.rows[0].config) : result.rows[0].config;
  return cfg.students || [];
}

// ============================================================================
// LIST STUDENTS
// ============================================================================

// GET / — list students in instructor's groups with lane + session info
router.get('/', async (req, res) => {
  try {
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    if (groups.length === 0) return res.json({ groups: [], students: [] });

    const allStudents = [];
    for (const group of groups) {
      const cfg = typeof group.config === 'string' ? JSON.parse(group.config) : group.config;
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

    // Enrich with lane status
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

    // Enrich with user details from cybercore_user
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
// ADD STUDENT
// ============================================================================

// POST / — add a student to an existing group
router.post('/', async (req, res) => {
  const { group_id, first_name, last_name, email } = req.body;
  if (!group_id) return res.status(400).json({ error: 'group_id required' });

  try {
    // Verify instructor belongs to this group
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    const group = groups.find(g => g.id === group_id);
    if (!group) return res.status(403).json({ error: 'You are not an instructor for this group' });

    const cfg = typeof group.config === 'string' ? JSON.parse(group.config) : group.config;
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

    // 2. Create Guacamole user
    let guacCreated = false;
    try {
      await guacAPI('POST', '/users', {
        username: studentEmail,
        password: password,
        attributes: { disabled: null, timezone: 'America/Phoenix' }
      });
      guacCreated = true;

      // Grant group permission if guac_group exists
      if (cfg.guac_group?.identifier) {
        await guacAPI('PATCH', `/users/${encodeURIComponent(studentEmail)}/permissions`, [
          { op: 'add', path: `/connectionGroupPermissions/${cfg.guac_group.identifier}`, value: 'READ' }
        ]);
      }
    } catch (e) {
      console.warn(`[CLE] Guac user creation failed for ${studentEmail}: ${e.message}`);
    }

    // 3. Update deployed_groups config to include new student
    const newStudent = { id: userId, email: studentEmail, name: `${studentFirstName} ${studentLastName}` };
    cfg.students = cfg.students || [];
    cfg.students.push(newStudent);
    cfg.credentials = cfg.credentials || [];
    cfg.credentials.push({ email: studentEmail, password, role: 'student' });

    await query(
      `UPDATE deployed_groups SET config = $1 WHERE id = $2`,
      [JSON.stringify(cfg), group_id]
    );

    console.log(`[CLE] Added student ${studentEmail} to group ${group.group_name} (by ${req.user.email})`);

    res.json({
      student: newStudent,
      credentials: { email: studentEmail, password },
      guac_created: guacCreated,
      message: `Student added to ${group.group_name}. Lane can be deployed separately from the Admin dashboard.`
    });
  } catch (error) {
    console.error('[CLE] Add student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// REMOVE STUDENT
// ============================================================================

// DELETE /:id — remove a student from their group, tear down lane
router.delete('/:id', async (req, res) => {
  const studentId = req.params.id;

  try {
    // Verify instructor has authority over this student
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    let targetGroup = null;
    let targetCfg = null;

    for (const g of groups) {
      const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
      if ((cfg.students || []).some(s => s.id === studentId)) {
        targetGroup = g;
        targetCfg = cfg;
        break;
      }
    }

    if (!targetGroup) return res.status(403).json({ error: 'Student not found in your groups' });

    const student = targetCfg.students.find(s => s.id === studentId);
    const studentEmail = student?.email;

    // 1. Tear down student's lane (if exists)
    const laneResult = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, config, status FROM cybercore_lane WHERE user_id::text = $1 AND status != 'deleted'`,
      [studentId]
    );

    for (const lane of laneResult.rows) {
      const laneCfg = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});
      const node = laneCfg.node;
      const vxlan = lane.vxlan_id;

      if (node && vxlan) {
        // Destroy VMs
        const vmIds = [];
        if (Array.isArray(laneCfg.vms)) {
          laneCfg.vms.forEach(vm => { if (vm.vm_id) vmIds.push({ id: vm.vm_id, type: vm.type || 'qemu' }); });
        } else {
          vmIds.push({ id: laneCfg.challenge_vm_id || (600000 + vxlan), type: 'qemu' });
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

    // 2. Delete Guacamole user + connections
    if (studentEmail) {
      try { await guacAPI('DELETE', `/users/${encodeURIComponent(studentEmail)}`); } catch (_) {}
    }

    // 3. Remove from group config
    targetCfg.students = targetCfg.students.filter(s => s.id !== studentId);
    targetCfg.credentials = (targetCfg.credentials || []).filter(c => c.email !== studentEmail);
    if (targetCfg.guac_users) {
      targetCfg.guac_users = targetCfg.guac_users.filter(u => u !== studentEmail);
    }

    await query(
      `UPDATE deployed_groups SET config = $1 WHERE id = $2`,
      [JSON.stringify(targetCfg), targetGroup.id]
    );

    // 4. Deactivate cybercore_user
    await cybercoreQuery(
      `UPDATE cybercore_user SET role = 'user', updated_at = NOW() WHERE user_id = $1`,
      [studentId]
    );

    console.log(`[CLE] Removed student ${studentEmail} from group ${targetGroup.group_name} (by ${req.user.email})`);

    res.json({
      ok: true,
      message: `Student ${studentEmail} removed and lane torn down.`,
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

// PATCH /:id — update student details or reset password
router.patch('/:id', async (req, res) => {
  const studentId = req.params.id;
  const { first_name, last_name, reset_password } = req.body;

  try {
    // Verify instructor has authority
    const groups = await getInstructorGroups(req.user.userId, req.user.role);
    let authorized = false;
    for (const g of groups) {
      const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
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

      // Also update Guac password
      const userResult = await cybercoreQuery(
        `SELECT email FROM cybercore_user WHERE user_id = $1`, [studentId]
      );
      if (userResult.rows.length > 0) {
        try {
          await guacAPI('PUT', `/users/${encodeURIComponent(userResult.rows[0].email)}/password`, {
            oldPassword: null,
            newPassword: newPassword
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

    res.json({
      ok: true,
      ...(newPassword ? { new_password: newPassword } : {})
    });
  } catch (error) {
    console.error('[CLE] Modify student error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
