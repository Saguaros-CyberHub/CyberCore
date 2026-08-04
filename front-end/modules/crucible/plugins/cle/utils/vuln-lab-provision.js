/**
 * ============================================================================
 * CLE Vulnerable-Lab Provisioning
 * ----------------------------------------------------------------------------
 * Deploys the vulnerable application an instructor assigns to students, in one
 * of two modes:
 *
 *   'lane'   — a full lab lane per student: gateway + the challenge's VMs + a
 *              Kali attack box, on a VXLAN drawn from THE CHALLENGE'S OWN
 *              reserved block. This is byte-for-byte the admin Group Deploy
 *              sequence (utils/challenge-lane-deployer.js), which is the only
 *              path that works for a v3/GOAD challenge — the internal VNets at
 *              (tag + 4000000) exist only in the challenge's own reservation,
 *              never in the course's v2 workstation block.
 *
 *   'attach' — graft the challenge's VMs onto the lane the student already has
 *              in this course, via utils/attached-modules.js. Cheap (no extra
 *              VXLAN, no second Kali) but only legal for a single-VNet,
 *              non-GOAD challenge that declares spec.attachable.
 *
 * Like lane-provision.js, this file is COURSE CONTEXT ONLY. The deploy logic
 * lives in the shared utils; if something here starts looking like Proxmox
 * orchestration, it belongs there instead.
 * ============================================================================
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI, waitForTask, forceDestroyVM } = require('../../../../../src/utils/proxmox');
const { getDefaultTemplateNode } = require('../../../../../src/utils/site-config');
const { resolveLaneNetworking } = require('../../../../../src/utils/lane-networking');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const challengeLaneDeployer = require('../../../../../src/utils/challenge-lane-deployer');
const attachedModules = require('../../../../../src/utils/attached-modules');
const laneProvision = require('./lane-provision');

const LOG = '[CLE VulnLab]';

const MODES = ['lane', 'attach'];

/** Progress key for one lab deploy, so the UI can poll a stable id. */
function progressIdForLab(materialId) {
  return `cle-lab-${materialId}`;
}

/** Live progress for a lab deploy, or null once it has aged out. */
function getLabProgress(materialId) {
  return laneDeployer.readProgress(progressIdForLab(materialId));
}

/**
 * Load a deployable vulnerable challenge by id. Rejects the per-course network
 * reservations (spec.cle = true) — those exist only to own a VXLAN block and
 * have no VMs.
 */
async function loadChallenge(challengeId) {
  const r = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, name, description, difficulty,
            spec, subnet_scheme, module_key, status
       FROM crucible_challenge
      WHERE challenge_id = $1
        AND status = 'active'
        AND spec->>'cle' IS DISTINCT FROM 'true'`,
    [challengeId]
  );
  if (r.rows.length === 0) {
    const err = new Error('Challenge template not found, not active, or not deployable');
    err.status = 404;
    throw err;
  }
  const row = r.rows[0];
  row.spec = challengeLaneDeployer.parseSpec(row.spec);
  return row;
}

/**
 * Describe what a challenge can and cannot do, so the picker and the deploy
 * endpoint agree instead of the instructor finding out after clicking Deploy.
 */
function describeChallenge(challenge) {
  const spec = challenge.spec || {};
  const vms = challengeLaneDeployer.resolveSpecVms(spec, challenge.challenge_key);
  const subnetScheme = challenge.subnet_scheme || 'v1';
  const goadEnabled = !!spec.goad?.enabled;

  const attachBlockers = [];
  if (spec.attachable !== true) attachBlockers.push('the challenge does not declare spec.attachable');
  if (subnetScheme === 'v3') attachBlockers.push('v3 challenges need their own segmented gateway (ext0/int0)');
  if (goadEnabled) attachBlockers.push('GOAD challenges provision Active Directory across the whole lane');

  const laneBlockers = [];
  if (vms.length === 0) laneBlockers.push('the challenge declares no VMs');
  if (!spec.vxlan_block?.start || !spec.vxlan_block?.end) {
    laneBlockers.push('the challenge has no reserved VXLAN block — recreate it via Admin → Create Lab');
  }
  // Two VMs sharing a vm_offset clone to the same VMID; catching it here means
  // the picker greys the challenge out instead of the deploy dying mid-lane.
  const collision = challengeLaneDeployer.findVmOffsetCollision(vms);
  if (collision) laneBlockers.push(collision);

  // Not a blocker — the lane still deploys — but a GOAD host whose name doesn't
  // match the lab definition lands on the wrong network segment with no reserved
  // IP and no domain join, which the instructor would otherwise only discover
  // when a student says the box is unreachable.
  const goadMismatch = challengeLaneDeployer.findGoadHostMismatch(spec, vms);

  return {
    challenge_id:   challenge.challenge_id,
    challenge_key:  challenge.challenge_key,
    name:           challenge.name,
    subnet_scheme:  subnetScheme,
    vm_count:       vms.length,
    vxlan_block:    spec.vxlan_block || null,
    goad_enabled:   goadEnabled,
    goad_prebaked:  !!spec.goad?.prebaked,
    attachable:     spec.attachable === true,
    can_deploy_lane:   laneBlockers.length === 0,
    can_attach:        attachBlockers.length === 0,
    lane_blockers:     laneBlockers,
    attach_blockers:   attachBlockers,
    // Deployable, but something about it will not behave as intended.
    warnings:          goadMismatch ? [goadMismatch] : [],
  };
}

/**
 * How many more lanes a reserved VXLAN block can still hold. Asks the same
 * allocator the deploy uses, so the number the picker shows and the number the
 * deploy gets cannot disagree.
 *
 * @param {{start:number,end:number}|null} block  spec.vxlan_block
 */
async function countFreeLanes(block) {
  if (!block?.start || !block?.end) return 0;
  const size = block.end - block.start + 1;
  const free = await laneDeployer.allocateVxlanIds(block, size);
  return free.length;
}

/** Every active lane a student holds in this course, newest first. */
async function findCourseLanes(userIds, courseId) {
  if (!userIds.length) return {};
  const r = await cybercoreQuery(
    `SELECT lane_id, user_id, vxlan_id, name, status, config, module_key
       FROM cybercore_lane
      WHERE user_id = ANY($1::uuid[])
        AND config->>'course_id' = $2
        AND status = 'active'
      ORDER BY created_at DESC`,
    [userIds, courseId]
  );
  const byUser = {};
  for (const row of r.rows) {
    if (!byUser[row.user_id]) byUser[row.user_id] = row;
  }
  return byUser;
}

// ── mode: lane ───────────────────────────────────────────────────────────────

/**
 * Deploy a dedicated lab lane per student on the challenge's own VXLAN block.
 * Returns whatever deployChallengeLanes returns.
 */
async function deployLabLanes({ course, challenge, students, materialId, instructorEmails }) {
  return challengeLaneDeployer.deployChallengeLanes({
    users: students.map(s => ({ id: s.id, email: s.email })),
    challenge,
    moduleKey: challenge.module_key || laneProvision.MODULE_KEY,
    attackBoxes: true,
    // config.course_id is how EVERY CLE read path finds these lanes again —
    // the VM list, the flag board, teardown. material_id ties them to the
    // specific lab assignment so one course can run several at once.
    laneConfig: {
      cle: true,
      course_id: course.course_id,
      course_name: course.course_name,
      material_id: materialId,
    },
    // Lanes come out as `cle-<course-code>-<vxlanId>`, matching the workstation
    // path's naming so both kinds of lane read the same way in Proxmox.
    namePrefix: laneProvision.laneNamePrefix(course.code),
    guacParent: 'ROOT',
    instructorEmails,
    description: `CLE course: ${course.course_name || course.course_id}`,
    progressId: progressIdForLab(materialId),
    progressLabel: `${challenge.name} — ${course.course_name || course.code || 'course'}`,
  });
}

// ── mode: attach ─────────────────────────────────────────────────────────────

/**
 * Graft the challenge onto one student's existing course lane. Mirrors
 * POST /api/admin/lanes/:laneId/modules, including the FOR UPDATE transaction
 * that appends to config.attached_modules — a plain read-modify-write loses
 * instances when two attaches land on the same lane at once.
 */
async function attachLabToLane({ lane, challenge, materialId, moduleKey }) {
  const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
  const laneSubnetScheme = laneConfig.subnet_scheme
    || (laneConfig.lane_subnet_base?.startsWith('10.') ? 'v2' : 'v1');
  const laneModule = lane.module_key || laneConfig.module || moduleKey;

  const net = resolveLaneNetworking(laneSubnetScheme, laneModule, lane.vxlan_id);
  const laneSubnetBase = (net.lanExt || net.lan).base3;

  const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const vnet = (vnets || []).find(v => v.tag === lane.vxlan_id);
  if (!vnet) {
    throw new Error(`No VNet found with tag ${lane.vxlan_id} in Proxmox SDN`);
  }

  const bestNode = laneConfig.node;
  if (!bestNode) throw new Error('Lane config is missing `node` — cannot place attached VMs');

  const instance = await attachedModules.attachModuleToLane({
    lane,
    laneConfig,
    challenge,
    spec: challenge.spec,
    module: laneModule,
    laneSubnetBase,
    vnetName: vnet.vnet,
    bestNode,
    templateNode: challenge.spec.template_node || getDefaultTemplateNode(),
    gatewayVmId: laneConfig.gateway_vm_id || laneConfig.gateway_vmid || (100000 + lane.vxlan_id),
    proxmoxAPI,
    waitForTask,
  });
  instance.material_id = materialId;

  await cybercoreQuery('BEGIN');
  try {
    const cur = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
      [lane.lane_id]
    );
    const curCfg = typeof cur.rows[0].config === 'string'
      ? JSON.parse(cur.rows[0].config || '{}')
      : (cur.rows[0].config || {});
    curCfg.attached_modules = [...(Array.isArray(curCfg.attached_modules) ? curCfg.attached_modules : []), instance];
    await cybercoreQuery(
      `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
      [lane.lane_id, JSON.stringify(curCfg)]
    );
    await cybercoreQuery('COMMIT');
  } catch (txErr) {
    await cybercoreQuery('ROLLBACK').catch(() => {});
    throw txErr;
  }

  return instance;
}

/**
 * Attach the challenge to every named student's existing lane, one at a time so
 * two attaches never race for the same slot on the same lane.
 */
async function attachLabToStudents({ course, challenge, students, materialId }) {
  const progressId = progressIdForLab(materialId);
  const progress = laneDeployer.initProgress(
    progressId,
    `${challenge.name} — ${course.course_name || course.code || 'course'}`,
    students.length
  );
  laneDeployer.setPhase(progress, 'deploying', `Attaching ${challenge.name} to ${students.length} lane(s)`);

  const lanesByUser = await findCourseLanes(students.map(s => s.id), course.course_id);
  const provisioned = [];
  const failed = [];

  for (const student of students) {
    const lane = lanesByUser[student.id];
    if (!lane) {
      failed.push({
        user_id: student.id, user_email: student.email,
        reason: 'Student has no active workstation lane in this course — provision one first, or deploy in "lane" mode',
      });
      continue;
    }
    if (progress) {
      progress.lanes[lane.lane_id] = {
        user: student.email, student: student.email, vxlan: lane.vxlan_id,
        node: null, status: 'attaching', _startedAt: Date.now(),
      };
    }
    try {
      const instance = await attachLabToLane({
        lane, challenge, materialId, moduleKey: challenge.module_key || laneProvision.MODULE_KEY,
      });
      provisioned.push({
        lane_id: lane.lane_id,
        user_id: student.id,
        user_email: student.email,
        vxlan_id: lane.vxlan_id,
        module_instance_id: instance.module_instance_id,
        vms: instance.vms,
      });
      if (progress) {
        progress.lanes[lane.lane_id].status = 'active';
        progress.succeeded++;
      }
      console.log(`${LOG} Attached ${challenge.challenge_key} to lane ${lane.lane_id} for ${student.email}`);
    } catch (err) {
      failed.push({ user_id: student.id, user_email: student.email, lane_id: lane.lane_id, reason: err.message });
      if (progress) {
        progress.lanes[lane.lane_id].status = 'error';
        progress.failed++;
      }
      console.error(`${LOG} Attach failed for ${student.email}: ${err.message}`);
    }
    if (progress) {
      progress.completed++;
      laneDeployer.recordLaneDone(progress, 1);
      progress.phase_detail = `Attaching: ${progress.completed}/${students.length} complete`;
    }
  }

  laneDeployer.finishProgress(progressId);
  return { provisioned, failed, progressId };
}

// ── entry point ──────────────────────────────────────────────────────────────

/**
 * Deploy a vulnerable lab to a set of students.
 *
 * @param {object} a
 * @param {object} a.course     cle_course row (course_id, course_name, code)
 * @param {object} a.challenge  row from loadChallenge()
 * @param {Array}  a.students   [{ id, email }] — already validated as enrolled
 * @param {string} a.materialId cle_course_material.material_id for this lab
 * @param {string} a.mode       'lane' | 'attach'
 * @param {Array}  [a.instructorEmails] extra Guacamole READ grants
 */
async function deployVulnLab({ course, challenge, students, materialId, mode, instructorEmails = [] }) {
  if (!MODES.includes(mode)) throw new Error(`Unknown deploy mode '${mode}'`);
  if (!students.length) return { provisioned: [], failed: [], progressId: null };

  const caps = describeChallenge(challenge);
  if (mode === 'lane' && !caps.can_deploy_lane) {
    const err = new Error(`Cannot deploy '${challenge.name}' as a lab lane: ${caps.lane_blockers.join('; ')}`);
    err.status = 409;
    throw err;
  }
  if (mode === 'attach' && !caps.can_attach) {
    const err = new Error(`Cannot attach '${challenge.name}' to an existing lane: ${caps.attach_blockers.join('; ')}`);
    err.status = 409;
    throw err;
  }

  console.log(
    `${LOG} Deploying '${challenge.challenge_key}' (${mode}) to ${students.length} student(s) ` +
    `in course ${course.course_id}`
  );

  return mode === 'attach'
    ? attachLabToStudents({ course, challenge, students, materialId })
    : deployLabLanes({ course, challenge, students, materialId, instructorEmails });
}

// ── teardown ─────────────────────────────────────────────────────────────────

/**
 * Detach one attached-module instance from its lane: destroy its VMs, remove its
 * dnsmasq file, and drop it from config.attached_modules.
 */
async function detachInstance(lane, laneConfig, instance) {
  const { destroyed, errors } = await attachedModules.detachModuleFromLane({
    moduleInstance: instance,
    bestNode: laneConfig.node,
    gatewayVmId: laneConfig.gateway_vm_id || laneConfig.gateway_vmid || (100000 + lane.vxlan_id),
    proxmoxAPI,
    forceDestroyVM,
  });

  await cybercoreQuery('BEGIN');
  try {
    const cur = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
      [lane.lane_id]
    );
    const curCfg = typeof cur.rows[0].config === 'string'
      ? JSON.parse(cur.rows[0].config || '{}')
      : (cur.rows[0].config || {});
    curCfg.attached_modules = (curCfg.attached_modules || [])
      .filter(m => m.module_instance_id !== instance.module_instance_id);
    await cybercoreQuery(
      `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
      [lane.lane_id, JSON.stringify(curCfg)]
    );
    await cybercoreQuery('COMMIT');
  } catch (txErr) {
    await cybercoreQuery('ROLLBACK').catch(() => {});
    throw txErr;
  }

  return { destroyed, errors };
}

/**
 * Tear down everything a lab assignment deployed: whole lanes for 'lane' mode,
 * attached-module instances for 'attach' mode. Safe to call for a lab that
 * deployed nothing.
 *
 * Both are matched on material_id, which both modes stamp — lanes on
 * config.material_id, attached instances on the instance record — so a course
 * running several labs at once tears down only the one asked for.
 */
async function teardownLab(materialId) {
  const result = { lanes_deleted: 0, vms_destroyed: 0, instances_detached: 0, errors: [] };

  // 1. Dedicated lab lanes.
  const lanes = await cybercoreQuery(
    `SELECT lane_id FROM cybercore_lane
      WHERE config->>'material_id' = $1 AND status <> 'deleted'`,
    [materialId]
  );
  const laneIds = lanes.rows.map(r => r.lane_id);
  if (laneIds.length > 0) {
    console.log(`${LOG} Tearing down ${laneIds.length} lab lane(s) for material ${materialId}`);
    const t = await laneDeployer.teardownLanes(laneIds);
    result.lanes_deleted = t.lanes_deleted || 0;
    result.vms_destroyed += t.vms_destroyed || 0;
    result.errors.push(...(t.errors || []));
  }

  // 2. Attached instances on lanes this lab did NOT own.
  //    jsonb_path_exists rather than a JS scan: a course can have dozens of
  //    lanes and only a couple carrying this lab.
  const attachedLanes = await cybercoreQuery(
    `SELECT lane_id, vxlan_id, config FROM cybercore_lane
      WHERE status <> 'deleted'
        AND jsonb_typeof(config->'attached_modules') = 'array'
        AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(config->'attached_modules') AS m
           WHERE m->>'material_id' = $1
        )`,
    [materialId]
  );

  for (const lane of attachedLanes.rows) {
    const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    const instances = (cfg.attached_modules || []).filter(m => m.material_id === materialId);
    for (const instance of instances) {
      try {
        const r = await detachInstance(lane, cfg, instance);
        result.instances_detached++;
        result.vms_destroyed += (r.destroyed || []).length;
        result.errors.push(...(r.errors || []));
      } catch (err) {
        result.errors.push(`Detach ${instance.module_instance_id} from lane ${lane.lane_id}: ${err.message}`);
      }
    }
  }

  return result;
}

module.exports = {
  MODES,
  progressIdForLab,
  getLabProgress,
  loadChallenge,
  describeChallenge,
  countFreeLanes,
  findCourseLanes,
  deployVulnLab,
  teardownLab,
};
