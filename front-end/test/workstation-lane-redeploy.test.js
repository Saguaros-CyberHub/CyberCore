const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { prepareWholeLaneRedeploy, redeployWholeLane, findReplacementLane } = require('../src/utils/workstation-lane-redeploy');

function environment(options = {}) {
  const events = [];
  const lane = {
    lane_id: 'old-lane', user_id: 'student', config: {
      course_id: 'course', subnet_scheme: 'v2',
      workstations: [
        { slot: 1, template_id: 'second', resources: { cores: 2, memory_mb: 4096 } },
        { slot: 0, template_id: 'first', resources: { cores: 4, memory_mb: 8192, disk_gb: 128 } },
      ],
    },
  };
  const course = { course_id: 'course', course_name: 'Malware analysis', code: 'MA101', challenge_id: 'challenge' };
  const challenge = { challenge_key: 'course-network', vxlan_block: { start: 10000, end: 10099 } };
  const lanes = new Map([[lane.lane_id, lane]]);
  const templates = ['first', 'second'].map((id, slot) => ({
    id, template_vmid: 9000 + slot, metadata: { analysis_profile: 'malware', default_password: 'do-not-copy' },
  }));
  const deps = {
    randomUUID: () => 'redeploy-one',
    courseQuery: async () => ({ rows: [course] }),
    query: async (sql, params) => {
      if (sql.includes('FROM cybercore_template_catalog')) {
        events.push(`template:${params[0]}`);
        return { rows: templates.filter(t => t.id === params[0] && t.id !== options.missingTemplate) };
      }
      if (sql.includes('FROM cybercore_user')) return { rows: [{ id: 'student', email: 'current@example.test' }] };
      if (sql.includes("config->'workstation_redeploy'")) {
        return { rows: [...lanes.values()].filter(l => l.config.workstation_redeploy?.id === params[0]
          && l.user_id === params[1] && l.config.course_id === params[2]) };
      }
      if (sql.includes('FROM cybercore_lane WHERE lane_id = $1')) {
        return { rows: lanes.has(params[0]) ? [lanes.get(params[0])] : [] };
      }
      throw new Error(`Unexpected query: ${sql}`);
    },
    laneDeployer: {
      teardownLanes: async ids => {
        events.push(`teardown:${ids[0]}`);
        if (options.survivors) return { lanes_kept_for_retry: 1, survivors: [123], errors: ['guest survived'] };
        events.push('old-guests-and-gateway:deleted');
        events.push('old-disks-and-consoles:deleted');
        if (!options.keepRow) lanes.delete(ids[0]);
        return { lanes_deleted: 1, lanes_kept_for_retry: 0, warnings: [] };
      },
    },
    laneProvision: {
      resolveCourseLab: async () => ({ challengeKey: challenge.challenge_key, vxlanBlock: challenge.vxlan_block }),
      provisionLanes: async args => {
        events.push('deploy');
        deps.provisionedWith = args;
        const replacement = {
          lane_id: 'new-lane', user_id: args.students[0].id, vxlan_id: 10001,
          config: { ...args.laneConfig, course_id: args.courseId }, status: options.failedClone ? 'error' : 'active',
        };
        lanes.set(replacement.lane_id, replacement);
        if (options.throwDuringClone) throw new Error('Clone transport failed');
        return options.failedClone
          ? { provisioned: [], failed: [{ user_id: 'student', reason: 'Clone failed' }] }
          : { provisioned: [replacement], failed: [] };
      },
    },
  };
  return { events, lane, course, challenge, lanes, templates, deps };
}

test('the durable plan preserves slot templates/sizing without copying template credentials', async () => {
  const env = environment();
  const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
  assert.deepEqual(plan.templateIds, ['first', 'second']);
  assert.deepEqual(plan.resources, [{ cores: 4, memory_mb: 8192, disk_gb: 128 }, { cores: 2, memory_mb: 4096 }]);
  assert.equal(plan.userId, 'student');
  assert.equal(plan.courseId, 'course');
  assert.equal(plan.oldLaneId, 'old-lane');
  assert.equal(JSON.stringify(plan).includes('do-not-copy'), false);
  env.lanes.delete('old-lane');
  assert.deepEqual(await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps), plan,
    'recovery can validate the retained snapshot after the source row was deleted');
});

test('whole-lane redeploy deletes the old lab before provisioning its replacement with identical course settings', async () => {
  const env = environment();
  const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
  const result = await redeployWholeLane({
    plan, progressId: 'claimed-progress', laneConfig: { analysis: { state: 'resetting', operation_id: 'operation' } },
    onTeardown: async () => { env.events.push('durable-teardown-confirmed'); },
  }, env.deps);
  assert.equal(result.replacementLaneId, 'new-lane');
  assert.equal(result.status, 'active');
  assert.equal(env.lanes.has('old-lane'), false);
  assert.ok(env.events.indexOf('old-disks-and-consoles:deleted') < env.events.indexOf('durable-teardown-confirmed'));
  assert.ok(env.events.indexOf('durable-teardown-confirmed') < env.events.indexOf('deploy'));
  const args = env.deps.provisionedWith;
  assert.deepEqual(args.students, [{ id: 'student', email: 'current@example.test' }]);
  assert.deepEqual(args.templates.map(t => t.id), ['first', 'second']);
  assert.deepEqual(args.resources, plan.resources);
  assert.deepEqual(args.challenge, plan.challenge);
  assert.equal(args.courseCode, 'MA101');
  assert.equal(args.progressId, 'claimed-progress');
  assert.equal(args.laneConfig.analysis.operation_id, 'operation');
  assert.deepEqual(args.laneConfig.workstation_redeploy, { id: 'redeploy-one', source_lane_id: 'old-lane' });
  assert.equal((await findReplacementLane(plan, env.deps)).lane_id, 'new-lane');
});

test('survivors, undeleted source rows, ownership changes and missing templates prevent fresh Internet deployment', async () => {
  for (const options of [{ survivors: true }, { keepRow: true }, { changedOwner: true }, { missingTemplate: 'second' }]) {
    const env = environment({ ...options, missingTemplate: undefined });
    const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
    if (options.changedOwner) env.lane.user_id = 'somebody-else';
    if (options.missingTemplate) env.templates.pop();
    await assert.rejects(redeployWholeLane({ plan }, env.deps));
    assert.equal(env.events.includes('deploy'), false);
  }
});

test('a persisted teardown-start checkpoint recovers a crash after row deletion without a completion checkpoint', async () => {
  const env = environment();
  const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
  let savedStartedId = null;
  const teardown = env.deps.laneDeployer.teardownLanes;
  env.deps.laneDeployer.teardownLanes = async ids => {
    await teardown(ids);
    throw new Error('connection lost after successful teardown');
  };
  await assert.rejects(redeployWholeLane({ plan, onBeforeTeardown: async ({ laneId }) => { savedStartedId = laneId; } }, env.deps), error => {
    assert.equal(error.teardownComplete, false);
    assert.equal(error.teardownStartedLaneId, 'old-lane');
    return true;
  });
  assert.equal(env.lanes.has('old-lane'), false);
  await assert.rejects(redeployWholeLane({ plan }, env.deps), /owner or course changed/,
    'missing source without a durable checkpoint is not accepted');
  const result = await redeployWholeLane({ plan, teardownStartedLaneId: savedStartedId }, env.deps);
  assert.equal(result.replacementLaneId, 'new-lane');
  assert.equal(env.events.filter(event => event === 'teardown:old-lane').length, 1);
});

test('partial deploy failures expose the replacement ID for durable recovery instead of reporting success', async () => {
  for (const options of [{ failedClone: true }, { throwDuringClone: true }]) {
    const env = environment(options);
    const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
    await assert.rejects(redeployWholeLane({ plan }, env.deps), error => {
      assert.equal(error.teardownComplete, true);
      assert.equal(error.replacementLaneId, 'new-lane');
      return true;
    });
  }
});

test('recovery skips only the completed original teardown and destroys any marked partial replacement first', async () => {
  for (const withPartial of [false, true]) {
    const env = environment();
    const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
    env.lanes.delete('old-lane');
    if (withPartial) env.lanes.set('partial-lane', {
      lane_id: 'partial-lane', user_id: 'student',
      config: { course_id: 'course', workstation_redeploy: { id: plan.redeployId }, analysis: { state: 'resetting', operation_id: 'operation' } },
    });
    await redeployWholeLane({ plan, skipTeardown: true, laneConfig: { analysis: { operation_id: 'operation' } } }, env.deps);
    assert.equal(env.events.includes('teardown:old-lane'), false);
    assert.equal(env.events.includes('teardown:partial-lane'), withPartial);
    assert.equal(env.lanes.has('partial-lane'), false);
  }
});

test('a course redeploy cannot bypass another analysis operation or malformed analysis state', async () => {
  for (const analysis of [{ state: 'isolating', operation_id: 'other' }, { state: 'resetting', operation_id: 'other' }, 'invalid']) {
    const env = environment();
    env.lane.config.analysis = analysis;
    const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
    await assert.rejects(redeployWholeLane({ plan }, env.deps), /analysis/);
    assert.equal(env.events.some(event => event.startsWith('teardown:')), false);
  }
  const env = environment();
  env.lane.config.analysis = { state: 'resetting', operation_id: 'operation' };
  const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
  await redeployWholeLane({ plan, laneConfig: { analysis: { operation_id: 'operation' } } }, env.deps);
  assert.equal(env.events.includes('deploy'), true);
});

test('failure to persist completed teardown prevents a fresh deployment and reports that the old lab is gone', async () => {
  const env = environment();
  const plan = await prepareWholeLaneRedeploy({ lane: env.lane }, env.deps);
  await assert.rejects(redeployWholeLane({ plan, onTeardown: async () => { throw new Error('database unavailable'); } }, env.deps), error => {
    assert.equal(error.teardownComplete, true);
    assert.match(error.message, /database unavailable/);
    return true;
  });
  assert.equal(env.events.includes('deploy'), false);
});

test('the existing Courses whole-lane action executes the same shared redeploy operation', async () => {
  const env = environment();
  const source = fs.readFileSync(path.resolve(__dirname, '../modules/crucible/plugins/cle/routes/vms.js'), 'utf8');
  const start = source.indexOf('async function runFullLaneRebuild(');
  const end = source.indexOf('\n/**', start);
  const shared = {
    prepareWholeLaneRedeploy: args => prepareWholeLaneRedeploy(args, env.deps),
    redeployWholeLane: args => redeployWholeLane(args, env.deps),
  };
  const run = new Function('workstationRedeploy', 'laneDeployer', `${source.slice(start, end)}; return runFullLaneRebuild;`)(shared, { setPhase() {} });
  const progress = { succeeded: 0, failed: 0, lanes: { 'old-lane': {} } };
  await run({ courseId: 'course', course: env.course, lanes: [env.lane], challenge: env.challenge,
    progress, courseName: env.course.course_name, courseCode: env.course.code }, 'claimed-progress');
  assert.equal(progress.succeeded, 1);
  assert.equal(progress.failed, 0);
  assert.equal(env.events.includes('teardown:old-lane'), true);
  assert.equal(env.events.includes('deploy'), true);
});
