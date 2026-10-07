'use strict';

const { randomUUID } = require('node:crypto');

const TEMPLATE_COLS = 'id, template_key, os_name, os_family, os_version, template_vmid, node, provider_type, metadata';

function dependencies(overrides = {}) {
  return {
    query: overrides.query || require('./cybercore-db').cybercoreQuery,
    courseQuery: overrides.courseQuery || require('../../modules/crucible/plugins/cle/utils/db').query,
    laneDeployer: overrides.laneDeployer || require('./lane-deployer'),
    laneProvision: overrides.laneProvision || require('../../modules/crucible/plugins/cle/utils/lane-provision'),
    randomUUID: overrides.randomUUID || randomUUID,
  };
}

function invalid(message) { return Object.assign(new Error(message), { status: 409 }); }

function recordedWorkstations(lane) {
  const cfg = lane.config || {};
  const records = Array.isArray(cfg.workstations) ? cfg.workstations.filter(Boolean) : [];
  if (!records.length) return [{ slot: 0, template_id: cfg.template_id, resources: cfg.resources || null }];
  return records.slice().sort((a, b) => a.slot - b.slot);
}

async function loadTemplates(templateIds, query) {
  const templates = [];
  for (const id of templateIds) {
    if (typeof id !== 'string' || !id) throw invalid('The lane is missing a recorded workstation template.');
    const result = await query(`SELECT ${TEMPLATE_COLS} FROM cybercore_template_catalog
      WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'`, [id]);
    const template = result.rows[0];
    if (!template) throw invalid('A recorded workstation template is no longer active. Re-activate it before redeploying.');
    if (!template.template_vmid) throw invalid(`Template '${template.os_name}' has no Proxmox VMID configured.`);
    templates.push(template);
  }
  return templates;
}

/** Snapshot rebuild inputs before teardown. Safe to persist: template secrets are not copied. */
async function prepareWholeLaneRedeploy({ lane, course = null, challenge = null }, overrides = {}) {
  const deps = dependencies(overrides);
  const cfg = lane?.config || {};
  if (!lane?.lane_id || !lane.user_id || !cfg.course_id || cfg.material_id) {
    throw invalid('Whole-lane workstation redeploy requires a course workstation lane.');
  }
  if (!course) {
    course = (await deps.courseQuery(`SELECT course_id, course_name, code, challenge_id
      FROM cle_course WHERE course_id = $1`, [cfg.course_id])).rows[0];
  }
  if (!course || course.course_id !== cfg.course_id) throw invalid('The workstation course could not be resolved.');
  if (!challenge) {
    if (!course.challenge_id) throw invalid('Course has no reserved lab network.');
    const lab = await deps.laneProvision.resolveCourseLab(course.challenge_id);
    if (!lab) throw invalid('The reserved lab challenge is missing for this course.');
    challenge = { challenge_key: lab.challengeKey, vxlan_block: lab.vxlanBlock };
  }
  const block = challenge.vxlan_block || challenge.spec?.vxlan_block;
  if (!block?.start || !block?.end) throw invalid('Course has no reserved VXLAN block.');
  const records = recordedWorkstations(lane);
  const templateIds = records.map(record => record.template_id);
  await loadTemplates(templateIds, deps.query);
  const user = (await deps.query('SELECT user_id AS id, email FROM cybercore_user WHERE user_id = $1', [lane.user_id])).rows[0];
  if (!user?.email) throw invalid('The owner of this lane has no email address for its Guacamole connection.');
  return JSON.parse(JSON.stringify({
    version: 1, redeployId: deps.randomUUID(), oldLaneId: lane.lane_id,
    userId: lane.user_id, courseId: cfg.course_id,
    courseName: course.course_name, courseCode: course.code,
    challenge: { challenge_key: challenge.challenge_key, vxlan_block: block },
    templateIds, resources: records.map(record => record.resources || null),
  }));
}

/** A replacement is identified by the persisted rebuild marker, never by recycled IPs or VMIDs. */
async function findReplacementLane(plan, overrides = {}) {
  const deps = dependencies(overrides);
  const result = await deps.query(`SELECT lane_id, user_id, module_key, name, status, vxlan_id,
      host(gateway_wan_ip) AS gateway_wan_ip, config
    FROM cybercore_lane
    WHERE config->'workstation_redeploy'->>'id' = $1
      AND user_id = $2 AND config->>'course_id' = $3
    ORDER BY created_at DESC LIMIT 2`, [plan.redeployId, plan.userId, plan.courseId]);
  if (result.rows.length > 1) throw invalid('Multiple replacement lanes exist for this redeploy; resolve them before retrying.');
  return result.rows[0] || null;
}

/**
 * Shared business operation for Courses > Redeploy > whole lane and Reset Lab.
 * Caller owns authorization, the operation lock, and durable progress. A trusted
 * recovery caller may skip an already completed original teardown; any partial
 * replacement with this plan's marker is still torn down before another deploy.
 */
async function redeployWholeLane({
  plan, progressId, laneConfig = {}, onBeforeTeardown = null, onTeardown = null,
  skipTeardown = false, teardownStartedLaneId = null,
}, overrides = {}) {
  const deps = dependencies(overrides);
  let teardownComplete = skipTeardown === true;
  let replacementLaneId = null;
  let teardownWarnings = [];
  try {
    if (plan?.version !== 1 || !plan.redeployId || !plan.oldLaneId || !plan.userId || !plan.courseId
        || !Array.isArray(plan.templateIds) || !plan.templateIds.length) throw invalid('Invalid whole-lane redeploy plan.');
    // Revalidate before destructive work, including when replaying a saved plan.
    const templates = await loadTemplates(plan.templateIds, deps.query);
    const user = (await deps.query('SELECT user_id AS id, email FROM cybercore_user WHERE user_id = $1', [plan.userId])).rows[0];
    if (!user?.email) throw invalid('The lane owner no longer has an email address for its Guacamole connection.');
    const partial = await findReplacementLane(plan, deps);
    replacementLaneId = partial?.lane_id || null;
    if (partial && !skipTeardown) throw invalid('A replacement lane already exists for this redeploy. Recover the saved operation before retrying.');
    const sourceId = partial?.lane_id || (!skipTeardown ? plan.oldLaneId : null);
    if (sourceId) {
      const source = (await deps.query('SELECT lane_id, user_id, config FROM cybercore_lane WHERE lane_id = $1', [sourceId])).rows[0];
      // A server-persisted pre-teardown checkpoint closes the crash gap between
      // teardownLanes deleting the row and onTeardown recording completion.
      // Shared teardown hard-deletes this UUID only after its targets are gone.
      // Ordinary course calls and uncheckpointed missing rows cannot use this.
      const recoveredDeletion = !source && sourceId === plan.oldLaneId && teardownStartedLaneId === sourceId;
      if (!recoveredDeletion && (!source || source.user_id !== plan.userId || source.config?.course_id !== plan.courseId || source.config?.material_id)) {
        throw invalid('The lane owner or course changed before redeploy; nothing was destroyed.');
      }
      const analysis = source?.config?.analysis || {};
      if (source?.config?.analysis != null && (typeof analysis !== 'object' || Array.isArray(analysis)
          || !['preparation', 'isolating', 'analysis', 'resetting', 'error'].includes(analysis.state))) {
        throw invalid('The lane analysis state is invalid and needs administrator recovery.');
      }
      if (['isolating', 'resetting'].includes(analysis.state)
          && (!laneConfig.analysis?.operation_id || laneConfig.analysis.operation_id !== analysis.operation_id)) {
        throw invalid('Another analysis operation is still running on this lane.');
      }
      if (!recoveredDeletion && onBeforeTeardown) {
        await onBeforeTeardown({ laneId: sourceId });
        teardownStartedLaneId = sourceId;
      }
      const teardown = recoveredDeletion ? { warnings: [] } : await deps.laneDeployer.teardownLanes([sourceId]);
      if (teardown.lanes_kept_for_retry > 0 || (teardown.survivors || []).length) {
        throw invalid(`Could not fully tear the lane down (${(teardown.errors || [])[0] || 'machines survived'}), so it was not rebuilt.`);
      }
      // The shared teardown removes rows only after all machines and disks are
      // gone. Confirm that boundary before a fresh gateway can provide Internet.
      const remaining = await deps.query('SELECT lane_id FROM cybercore_lane WHERE lane_id = $1', [sourceId]);
      if (remaining.rows.length) throw invalid('The old lane still exists after teardown; the replacement was not deployed.');
      teardownWarnings = teardown.warnings || [];
      replacementLaneId = null;
    }
    teardownComplete = true;
    if (onTeardown) await onTeardown({ oldLaneId: plan.oldLaneId, teardownWarnings });
    const result = await deps.laneProvision.provisionLanes({
      courseId: plan.courseId, challenge: plan.challenge, templates, resources: plan.resources,
      students: [{ id: plan.userId, email: user.email }],
      courseName: plan.courseName, courseCode: plan.courseCode,
      progressId, progressLabel: `Rebuild \u2014 ${plan.courseName || plan.courseId}`,
      laneConfig: {
        ...laneConfig,
        workstation_redeploy: { id: plan.redeployId, source_lane_id: plan.oldLaneId },
      },
    });
    const replacement = (result.provisioned || []).find(lane => lane.user_id === plan.userId);
    replacementLaneId = replacement?.lane_id || (await findReplacementLane(plan, deps))?.lane_id || null;
    if ((result.failed || []).length || !replacement?.lane_id) {
      throw new Error(`Replacement lane deployment failed: ${(result.failed || []).map(item => item.reason).filter(Boolean).join('; ') || 'no workstation lane was provisioned'}`);
    }
    return { status: 'active', replacementLaneId, vxlanId: replacement.vxlan_id, teardownComplete, teardownWarnings };
  } catch (error) {
    if (teardownComplete && !replacementLaneId) {
      try { replacementLaneId = (await findReplacementLane(plan, deps))?.lane_id || null; } catch (_) { /* Preserve the original failure. */ }
    }
    error.teardownComplete = teardownComplete;
    error.teardownStartedLaneId = teardownStartedLaneId;
    error.replacementLaneId = replacementLaneId;
    throw error;
  }
}

module.exports = { prepareWholeLaneRedeploy, redeployWholeLane, findReplacementLane };
