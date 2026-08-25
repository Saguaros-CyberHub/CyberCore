/**
 * ============================================================================
 * Group Admin Routes
 * Batch deploy groups of students, group teardown, account schedules,
 * and active/inactive toggles.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { proxmoxAPI } = require('../../utils/proxmox');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { guacAPI, getGuacToken, GUAC_URL, GUAC_DS } = require('../../utils/guacamole');
const { buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const audit = require('../../utils/audit');
const accountProvisioning = require('../../utils/account-provisioning');
const { runBatch } = require('../../utils/batch-deployer');
const { allocateVxlanIds } = require('../../utils/lane-deployer');
// teardownLanes is reached through the namespace rather than destructured with
// allocateVxlanIds above so the delegation is obvious at every call site.
const laneDeployer = require('../../utils/lane-deployer');
const { deployChallengeLanes, parseSpec, readProgress } = require('../../utils/challenge-lane-deployer');
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
      // No default block here. deployChallengeLanes REQUIRES spec.vxlan_block —
      // a challenge without one has no SDN zone or VNets either, so falling back
      // to 10000-10009 would pass this check and then fail in the background,
      // after the HTTP 200 and after the accounts were created.
      const vxlanBlock = spec.vxlan_block;
      if (!vxlanBlock?.start || !vxlanBlock?.end) {
        return res.status(409).json({
          error: `Challenge '${challenge_key}' has no reserved VXLAN block — recreate it through `
               + `Admin → Create Lab so its SDN zone and VNets exist.`,
        });
      }
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

    // Account minting goes through the shared util (utils/account-provisioning),
    // which is now the only place in the platform that writes a cybercore_user
    // row. It lowercases the address on write, uses one bcrypt cost everywhere,
    // and stamps provenance — so a group-deployed account is distinguishable
    // from one an instructor's course created, which is what the CLE credential
    // guards key on.
    //
    // The generated addresses are unchanged (`<slug>-student1@clinic.local`) so
    // existing groups, their Guacamole accounts, and the credential CSVs that
    // were handed out all keep working. .local is a reserved domain, so the
    // mailer refuses to send to these — deliberately: nobody ever reads them.
    const slug = group_name.toLowerCase().replace(/[^a-z0-9]/g, '');
    const takenUsernames = new Set();

    const mintAccount = async (role, i) => {
      const email = `${slug}-${role}${i}@clinic.local`;
      const outcome = await accountProvisioning.provisionAccount({
        email,
        username: email,          // username has always equalled the address here
        firstName: role === 'instructor' ? 'Instructor' : 'Student',
        lastName: String(i),
        organization: group_name,
        role,
        emailVerified: true,      // synthetic address; nothing to verify
        // Unchanged behaviour: these credentials are handed out on a CSV, and
        // forcing a rotation would strand the copy the instructor printed.
        mustChangePassword: false,
        provenance: { by: req.user.userId, via: 'group_deploy', ref: String(groupId) },
        takenUsernames,
      });

      if (!outcome.created) {
        throw new Error(`An account already exists for ${email}. Choose a different group name.`);
      }

      const bucket = role === 'instructor' ? created.instructors : created.students;
      bucket.push({ id: outcome.user.user_id, email, name: `${role === 'instructor' ? 'Instructor' : 'Student'} ${i}` });
      created.credentials.push({ email, password: outcome.password, role });

      try {
        await guacAPI('POST', '/users', {
          username: email,
          password: outcome.password,
          attributes: { disabled: null, timezone: 'America/Phoenix' }
        });
        created.guac_users.push(email);
      } catch (e) { /* skip if Guac unreachable */ }
    };

    for (let i = 1; i <= numInst; i++) await mintAccount('instructor', i);
    for (let i = 1; i <= numStud; i++) await mintAccount('student', i);

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
    // Populated by the cybercore_user DELETE below, which is the only place the
    // deleted accounts' emails still exist.
    let deletedUsers = [];
    const students = config.students || [];

    // Every lane owned by a student in this group.
    //
    // This route used to carry a near-verbatim copy of teardownLanes' phases 2-6
    // wrapped around its own, weaker enumeration: it never read
    // cfg.workstations[], so every allocated slot-1+ machine leaked; it had no
    // contested-VXLAN check and no ownership check, so it could destroy a live
    // lane's machines; and it deleted the lane rows from inside a Promise.all with
    // no gate at all, which orphaned any VM that refused to die AND released its
    // vxlan_id for the next deploy to collide with.
    const studentLaneResults = await Promise.all(
      students.map(student =>
        cybercoreQuery(
          `SELECT lane_id FROM cybercore_lane WHERE user_id = $1`,
          [student.id]
        ).then(r => r.rows).catch(e => {
          // A lookup that fails silently is a lane this teardown will not touch,
          // so say so rather than under-reporting a clean run.
          errors.push(`Lane lookup for ${student.email || student.id}: ${e.message}`);
          return [];
        })
      )
    );
    const laneIds = [...new Set(studentLaneResults.flat().map(l => l.lane_id))];

    console.log(`[Group Teardown] ${group.group_name}: tearing down ${laneIds.length} lane(s)`);

    // The ONE canonical teardown: enumerate (including cfg.workstations[]),
    // contested-VXLAN skip, ownership check, unprotect/stop/purge, three orphan
    // retry rounds, disk sweep, workspace rows, Guacamole connections, Tailscale
    // devices, bootstrap tokens — and the lane rows deleted ONLY when nothing
    // survived.
    const EMPTY_TEARDOWN = {
      lanes_deleted: 0, lanes_kept_for_retry: 0, vms_destroyed: 0, orphan_disks_swept: 0,
      errors: [], warnings: [], survivors: [], ownership_skipped: [], contested: [],
    };
    const teardown = laneIds.length > 0
      ? await laneDeployer.teardownLanes(laneIds, { purgeJanitors: true })
      : EMPTY_TEARDOWN;
    errors.push(...teardown.errors);

    // Phase 5: Cleanup DB and Guac in parallel
    const allUserIds = allUsers.map(u => u.id);
    const allUserEmails = allUsers.map(u => u.email);

    // Deleting a user CASCADES to cybercore_lane (001_init_db.sql:201), which would
    // erase exactly the rows teardownLanes just kept on purpose — with zero Proxmox
    // interaction, orphaning every survivor permanently and releasing its vxlan_id.
    // So the accounts only go once the machines are verifiably gone.
    //
    // KEYS ON lanes_kept_for_retry, never errors.length: teardownLanes returns
    // errors: [...errors, ...warnings], so a Guacamole 403 — which leaves nothing
    // running anywhere — would otherwise strand a whole class's accounts.
    const canDeleteUsers = (teardown.lanes_kept_for_retry || 0) === 0;
    if (!canDeleteUsers) {
      const msg =
        `${teardown.lanes_kept_for_retry} lane record(s) were kept because machines survived ` +
        `the teardown — the student accounts were NOT deleted, because removing them would ` +
        `cascade those rows away and orphan the survivors. Re-run this teardown once the ` +
        `cause is cleared.`;
      console.warn(`[Group Teardown] ${msg}`);
      errors.push(msg);
    }

    // cybercore_allocation has CHECK (user_id IS NOT NULL OR group_key IS NOT NULL)
    // and cybercore_user FK is ON DELETE SET NULL — so deleting a user would
    // try to NULL out user_id on any of their allocations not tied to a
    // group_key, which violates the check and rolls back the user delete.
    // Purge each user's allocations FIRST (before the user delete in the
    // Promise.all below) so the user delete has nothing left to SET NULL on.
    if (canDeleteUsers && allUserIds.length > 0) {
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

    // The cybercore_lane rows and their cybercore_resource rows are gone already
    // if teardownLanes was satisfied, and deliberately still there if it was not.
    // This route must not delete either: the row is the only handle on a survivor's
    // derived VMIDs, and removing it frees the vxlan_id for a colliding redeploy.
    //
    // The (metadata->>'lane_id')::uuid cast that used to live here was a latent
    // bug too — Postgres does not guarantee AND-evaluation order, so it threw for
    // every lane as soon as ANY resource row in the table held a non-uuid there.
    // teardownLanes compares as TEXT.
    await Promise.all([
      canDeleteUsers && allUserIds.length > 0
        ? cybercoreQuery(
            `DELETE FROM cybercore_user WHERE user_id = ANY($1::uuid[]) OR username = ANY($2)
             RETURNING user_id, email, role`,
            [allUserIds, allUserEmails]
          )
          .then(r => {
            // One row per account, not just a count. "Which students were
            // deleted, and by whom" is unanswerable from a number, and this is
            // the last point at which the identities exist.
            deletedUsers = r.rows || [];
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
    ]);

    // The orphaned-disk sweep that used to live here was a second copy of
    // teardownLanes' phase 6, walking every node's storage over again. It runs
    // inside the teardown now, scoped to the VMIDs that teardown actually owned.

    await query(`DELETE FROM deployed_groups WHERE id = $1`, [req.params.id]);

    audit.batch({
      req,
      action: 'user.bulk_deleted',
      targetAction: 'user.deleted',
      target: { type: 'group', id: req.params.id, label: group.group_name },
      metadata: { group_name: group.group_name, reason: 'group_teardown' },
      targets: deletedUsers.map(u => ({
        id: u.user_id, label: u.email,
        metadata: { role: u.role, group_name: group.group_name },
      })),
    });

    const kept = teardown.lanes_kept_for_retry || 0;

    logActivity(req, 'delete_group', 'group', req.params.id, {
      group_name: group.group_name,
      users_deleted: deletedUsers.length,
      lanes_deleted: teardown.lanes_deleted,
      lanes_kept_for_retry: kept,
      vms_destroyed: teardown.vms_destroyed,
      orphan_disks_swept: teardown.orphan_disks_swept,
      errors: errors.length,
    });

    // 207, not 200, when machines survived. The old handler answered
    // success: true unconditionally — including the case where it had just
    // deleted every lane row out from under a VM it could not destroy.
    res.status(kept === 0 ? 200 : 207).json({
      success: kept === 0,
      users_deleted: deletedUsers.length,
      lanes_deleted: teardown.lanes_deleted,
      lanes_kept_for_retry: kept,
      vms_destroyed: teardown.vms_destroyed,
      orphan_disks_swept: teardown.orphan_disks_swept,
      survivors: teardown.survivors,
      ownership_skipped: teardown.ownership_skipped,
      contested: teardown.contested,
      errors: errors.length > 0 ? errors : undefined,
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
