const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const goad = require('../src/utils/goad-deploy');

function authored(overrides = {}) {
  const options = { enabled: true, version: 'GOAD-Mini', rename_forest: true,
    domain: 'cy400test.org', extensions: ['elk', 'ws01'], probe: false, ...overrides };
  const names = goad.getLab(options.version).vms.map(vm => vm.name);
  for (const key of options.extensions || []) {
    const extension = goad.getExtension(key);
    if (extension && !names.includes(extension.machine)) names.push(extension.machine);
  }
  return { goad: options, vms: names.map(name => ({ name })) };
}

/** Actual orchestrator and controller helpers; all I/O is explicitly injected. */
function harness(spec = authored(), fault = {}) {
  const calls = [];
  const executions = new Map();
  let playbookFinished = false;
  const inventory = spec.vms.map((vm, i) => ({ name: vm.name, type: 'qemu', node: 'node-1', vm_id: 610010 + i }));
  const args = {
    lane: { lane_id: 77 }, spec, module: 'test', vnet: { vnet: 'vn4242' }, vxlanId: 4242,
    gatewayVmId: 104242, bestNode: 'node-1', templateNode: 'template-1',
    laneSubnetBase: '10.9.9', extSubnetBase: '10.9.8', deployedVMs: inventory,
    proxmoxAPI: async (method, url, body) => {
      calls.push({ action: 'api', method, url, body });
      if (url.endsWith('/clone')) return 'UPID:clone';
      if (url.endsWith('/time')) return { time: Math.floor(Date.now() / 1000), localtime: 0 };
      if (method === 'GET' && /\/config(?:\?current=1)?$/.test(url)) return { localtime: 0 };
      if (url.endsWith('/status/current')) return { status: fault.windowsStop ? 'running' : 'stopped' };
      if (url.endsWith('/204242/status/stop')) {
        if (fault.stop) throw new Error('stop rejected');
        return 'UPID:stop';
      }
      if (method === 'POST' && url.endsWith('/status/stop') && fault.windowsStopRejected) {
        throw new Error('already stopped');
      }
      if (url.endsWith('/agent/exec')) {
        const argv = new URLSearchParams(body).getAll('command');
        const pid = executions.size + 1;
        executions.set(pid, { argv, vmId: Number(url.match(/qemu\/(\d+)/)[1]) });
        return { pid };
      }
      return null;
    },
    waitForTask: async (node, task) => {
      calls.push({ action: 'task', node, task });
      if (fault.clone && task === 'UPID:clone') throw new Error('clone task timed out');
    },
    query: async (sql, parameters) => {
      calls.push({ action: 'persist', meta: JSON.parse(parameters[0]).goad });
      if (fault.persist) throw new Error('database unavailable');
    },
    deps: {
      waitForGuestAgent: async () => !fault.agent,
      waitForWinRM: async options => calls.push({ action: 'winrm', ips: options.vmIPs }),
      sleep: async () => {},
      pollExecStatus: async (node, vmId, pid) => {
        const execution = executions.get(pid);
        if (execution.argv.join(' ').includes('cybercore-clock-read')) {
          calls.push({ action: 'clock_read', afterPlaybook: playbookFinished });
          return { exited: true, exitcode: 0, stdout: JSON.stringify({
            utc_milliseconds: Date.now() - (fault.clockBefore || (playbookFinished && fault.clockAfter) ? 9 * 3600000 : 0),
            timezone: 'UTC',
          }) };
        }
        if (execution.argv.join(' ').includes('cybercore-clock-seed')) calls.push({ action: 'clock_seed' });
        if (execution.argv.join(' ').includes('cybercore-rebrand.py')) {
          const plan = JSON.parse(Buffer.from(execution.argv[3], 'base64').toString('utf8'));
          calls.push({ action: 'tree', lab: plan.lab_name, plan });
          if (fault.tree) return { exited: true, exitcode: 1, stderr: 'tree compilation interrupted' };
          const report = { lab: plan.lab_name, treeSha256: 'a'.repeat(64), chainMode: 'per-lab+shared', chain: ['build.yml'],
            identities: plan.expected_identities, extensionConfigs: {} };
          calls.push({ action: 'extension', key: 'ws01' });
          if (fault.extension) return { exited: true, exitcode: 1, stdout: JSON.stringify({ ok: false,
            error: 'ws01 stock config absent', delivery: { ...report, failedStep: 'extension:ws01' } }) };
          report.extensionConfigs.ws01 = { sha256: 'b'.repeat(64), dest: '/opt/goad/extensions/ws01/data/config.json' };
          if (plan.selected_extensions.includes('lx01')) report.extensionConfigs.lx01 = { sha256: 'c'.repeat(64) };
          if (fault.chain) report.chain = ['../default.yml'];
          if (fault.reportIdentity) report.identities = report.identities.filter(host => host.name !== fault.reportIdentity);
          return { exited: true, exitcode: 0, stdout: JSON.stringify(report) };
        }
        if (execution.argv[0].endsWith('/prep.sh')) {
          calls.push({ action: 'prep', hostMap: execution.argv[1] });
          if (fault.prep) return { exited: true, exitcode: 1, stderr: 'fixture prep failed' };
        }
        if (execution.argv.join(' ').includes('Get-CimInstance')) {
          const name = inventory.find(vm => vm.vm_id === vmId).name;
          const expected = goad.goadIdentityExpectations(goad.prepareGoadDeploymentSpec(spec)).find(vm => vm.name === name);
          calls.push({ action: 'identity', name });
          return { exited: true, exitcode: 0, 'out-data': JSON.stringify({ hostname: name,
            domain: fault.identity === name ? 'old.example.org' : expected.domain, joined: true,
            domain_role: /^DC\d+$/i.test(name) ? 5 : 1,
            secure_channel: /^DC\d+$/i.test(name) ? null : fault.trust !== name }) };
        }
        return { exited: true, exitcode: 0, stdout: 'ok' };
      },
      pushLabTree: async options => {
        throw new Error('Rename must not upload a generated lab tree');
      },
      pushExtensionConfig: async options => {
        throw new Error('Rename must not upload compiled extension content');
      },
      runPlaybook: async options => {
        calls.push({ action: 'playbook', lab: options.spec.goad.version });
        if (fault.playbook) throw fault.playbook instanceof Error ? fault.playbook : new Error('ansible domain join failed');
        playbookFinished = true;
        return { exited: true, exitcode: 0 };
      },
    },
  };
  return { args, calls, inventory };
}

test('preparation compiles once and preserves a shallow copy carrying the same compiled goad object', () => {
  const spec = authored();
  const prepared = goad.prepareGoadDeploymentSpec(spec);
  assert.notEqual(prepared, spec);
  assert.equal(goad.prepareGoadDeploymentSpec(prepared), prepared);
  const copy = { ...prepared };
  assert.equal(goad.prepareGoadDeploymentSpec(copy), copy);
  assert.equal(spec.goad.version, 'GOAD-Mini');
  assert.equal(spec.goad.generated_lab, undefined);
  assert.equal(prepared.goad.generated_lab, undefined);
  assert.ok(prepared.goad.rename_plan);
  assert.deepEqual(goad.resolveGoadLab(prepared).extensions.selected, ['elk', 'ws01']);
});

test('legacy alias resolves canonical runtime name and no-opt-in preparation preserves identity', () => {
  const spec = authored({ version: 'light', rename_forest: false, extensions: [] });
  assert.equal(goad.prepareGoadDeploymentSpec(spec), spec);
  assert.equal(goad.resolveGoadLab(spec).labName, 'GOAD-Light');
});

test('clock drift prevents domain promotion and preserves the failed host and cleanup inventory', async () => {
  const fixture = harness(authored(), { clockBefore: true });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error.goadMeta.stage, 'windows_clock');
    assert.equal(error.goadMeta.clock.passed, false);
    assert.equal(error.goadMeta.clock.phase, 'before_promotion');
    assert.equal(error.goadMeta.clock.checks[0].name, 'DC01');
    assert.equal(error.goadMeta.controller_stop.stopped, true);
    return true;
  });
  assert.ok(!fixture.calls.some(call => call.action === 'playbook'));
});

test('clock reset during GOAD reboots prevents readiness without silently reseeding', async () => {
  const fixture = harness(authored(), { clockAfter: true });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error.goadMeta.stage, 'windows_clock_verification');
    assert.equal(error.goadMeta.clock.phase, 'after_provisioning');
    assert.equal(error.goadMeta.clock.passed, false);
    assert.equal(error.goadMeta.controller_stop.stopped, true);
    return true;
  });
  const play = fixture.calls.findIndex(call => call.action === 'playbook');
  assert.ok(play > 0);
  assert.ok(!fixture.calls.slice(play).some(call => call.action === 'clock_seed'));
  assert.ok(!fixture.calls.some(call => call.action === 'identity'));
});

test('a Windows VM that did not stop cannot proceed with a pending UTC RTC change', async () => {
  const fixture = harness(authored(), { windowsStop: true });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error.goadMeta.stage, 'windows_clock');
    assert.match(error.message, /did not stop for UTC RTC activation/);
    assert.equal(error.goadMeta.controller_stop.stopped, true);
    return true;
  });
  assert.ok(!fixture.calls.some(call => call.action === 'playbook'));
});

test('an already stopped Windows VM is accepted only after confirming its stopped state', async () => {
  const fixture = harness(authored(), { windowsStopRejected: true });
  const result = await goad.deployGoadLane(fixture.args);
  assert.equal(result.goadMeta.clock.passed, true);
  assert.equal(result.goadMeta.clock.phase, 'after_provisioning');
  assert.equal(result.goadMeta.status, 'provisioned');
});

test('strict validation is an HTTP 400 before the actual controller clone function can execute', async () => {
  for (const changes of [{ domain: 'invalid.local' }, { domain: '' }, { prebaked: true }]) {
    const fixture = harness(authored(changes));
    await assert.rejects(goad.deployGoadLane(fixture.args), error => error.status === 400);
    assert.equal(fixture.calls.length, 0);
  }
});

for (const [fault, stage] of [['clone', 'controller_clone'], ['agent', 'controller_agent'],
  ['tree', 'delivery'], ['extension', 'delivery'], ['prep', 'dhcp'], ['playbook', 'playbook']]) {
  test(`${fault} failure stops the controller and carries durable cleanup ownership and metadata`, async () => {
    const fixture = harness(authored(), { [fault]: true });
    let failure;
    await assert.rejects(goad.deployGoadLane(fixture.args), error => {
      failure = error;
      assert.equal(error.controllerVmId, 204242);
      assert.equal(error.goadMeta.controller_vmid, 204242);
      assert.equal(error.goadMeta.controller_node, 'node-1');
      assert.equal(error.goadMeta.controller_clone_attempted, true);
      assert.equal(error.goadMeta.status, 'failed');
      assert.equal(error.goadMeta.forest_rename.requested, true);
      assert.equal(error.goadMeta.forest_rename.applied, false);
      assert.equal(error.goadMeta.forest_rename.compiled, ['prep', 'playbook'].includes(fault));
      assert.equal(error.goadMeta.stage, stage);
      assert.equal(error.goadMeta.controller_stop.stopped, true);
      if (fault === 'prep') assert.match(error.message, /fixture prep failed/);
      if (fault === 'playbook') assert.match(error.message, /ansible domain join failed/);
      return true;
    });
    assert.ok(fixture.calls.some(call => call.action === 'task' && call.task === 'UPID:stop'));
    assert.deepEqual(fixture.calls.find(call => call.action === 'persist').meta, JSON.parse(JSON.stringify(failure.goadMeta)));
    if (fault === 'extension') {
      assert.equal(failure.goadMeta.generated_lab.tree_sha256, 'a'.repeat(64));
      assert.equal(failure.goadMeta.generated_lab.failed_step, 'extension:ws01');
      assert.ok(!fixture.calls.some(call => call.action === 'playbook'));
    }
    if (fault === 'tree') assert.equal(failure.goadMeta.generated_lab.failed_step, 'controller_rename');
  });
}

test('a second cleanup error retains the original failure and the unconfirmed controller inventory', async () => {
  const fixture = harness(authored(), { extension: true, stop: true, persist: true });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error.message, 'ws01 stock config absent');
    assert.equal(error.goadMeta.controller_stop.stopped, false);
    assert.equal(error.goadMeta.controller_stop.error, 'stop rejected');
    return true;
  });
});

test('playbook timeout diagnostics survive controller cleanup and the persisted lane outcome', async () => {
  const timeout = new Error('GOAD playbook did not finish within 2h');
  timeout.goadPlaybook = {
    status: 'timed_out', timeout_ms: 7200000, elapsed_ms: 7200000, exitcode: null,
    last_task: 'mssql_ssms : Install SSMS on srv02', log_path: '/var/log/goad-run-4242.log',
    completion_path: '/var/log/goad-done-4242.txt',
  };
  const fixture = harness(authored(), { playbook: timeout });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error, timeout);
    assert.deepEqual(error.goadMeta.playbook, timeout.goadPlaybook);
    assert.equal(error.goadMeta.status, 'failed');
    assert.equal(error.goadMeta.controller_stop.stopped, true);
    return true;
  });
  assert.deepEqual(fixture.calls.find(call => call.action === 'persist').meta.playbook, timeout.goadPlaybook);
  assert.ok(fixture.calls.some(call => call.action === 'task' && call.task === 'UPID:stop'));
});

test('success returns the same durable metadata and verifies ws01 domain membership before cleanup', async () => {
  const fixture = harness();
  const result = await goad.deployGoadLane(fixture.args);
  assert.equal(result.goadMeta.status, 'provisioned');
  assert.equal(result.goadMeta.forest_rename.compiled, true);
  assert.equal(result.goadMeta.forest_rename.applied, true);
  assert.equal(result.goadMeta.identities.passed, true);
  assert.deepEqual(result.goadMeta.identities.checks.map(check => check.name), ['DC01', 'ws01']);
  assert.equal(result.goadMeta.identities.checks[1].observed.domain, 'cy400test.org');
  assert.deepEqual(fixture.calls.filter(call => ['tree', 'extension', 'playbook', 'identity'].includes(call.action)).map(call => call.action),
    ['tree', 'extension', 'playbook', 'identity', 'identity']);
  assert.match(fixture.calls.find(call => call.action === 'prep').hostMap, /kali\|10\.9\.8\.50\|/);
  assert.match(fixture.calls.find(call => call.action === 'prep').hostMap, /elk\|10\.9\.8\.24\|/);
  assert.deepEqual(fixture.calls.find(call => call.action === 'winrm').ips, ['10.9.9.10', '10.9.9.31']);
  const plan = fixture.calls.find(call => call.action === 'tree').plan;
  assert.equal(plan.files, undefined);
  assert.equal(plan.manifest, undefined);
  assert.equal(plan.extension_configs, undefined);
  assert.ok(JSON.stringify(plan).length < 5000, 'only a small identity plan is sent to the controller');
});

test('the actual controller invocation reports missing fork helper with refresh guidance', async () => {
  const spec = goad.prepareGoadDeploymentSpec(authored());
  let execution;
  await assert.rejects(goad.deliverControllerRename({ controllerVmId: 1, bestNode: 'offline', spec,
    proxmoxAPI: async (method, url, body) => {
      const argv = new URLSearchParams(body).getAll('command');
      const bootstrap = argv[2].replace('/opt/goad/scripts/cybercore-rebrand.py', '/__cybercore_test_missing__/cybercore-rebrand.py');
      execution = spawnSync('python', ['-c', bootstrap, argv[3]], { encoding: 'utf8' });
      return { pid: 1 };
    },
    deps: { pollExecStatus: async () => ({ exited: true, exitcode: execution.status,
      stdout: execution.stdout, stderr: execution.stderr }) },
  }), /Refresh or re-bake template 1700/);
});

test('a renamed ws01 joined to the wrong domain prevents readiness and preserves observed identity', async () => {
  const fixture = harness(authored(), { identity: 'ws01' });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error.goadMeta.stage, 'identity_verification');
    assert.equal(error.goadMeta.identities.passed, false);
    assert.equal(error.goadMeta.identities.checks[1].observed.domain, 'old.example.org');
    assert.equal(error.goadMeta.controller_stop.stopped, true);
    return true;
  });
});

test('matching WS01 name and domain with a broken secure channel prevents lane readiness', async () => {
  const fixture = harness(authored(), { trust: 'ws01' });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => {
    assert.equal(error.goadMeta.stage, 'identity_verification');
    assert.equal(error.goadMeta.status, 'failed');
    assert.equal(error.goadMeta.forest_rename.applied, false);
    assert.equal(error.goadMeta.controller_stop.stopped, true);
    const check = error.goadMeta.identities.checks.find(host => host.name === 'ws01');
    assert.equal(check.observed.hostname, check.expected.hostname);
    assert.equal(check.observed.domain, check.expected.domain);
    assert.equal(check.observed.joined, true);
    assert.equal(check.observed.secure_channel, false);
    assert.equal(check.ok, false);
    assert.match(check.error, /secure channel is broken/);
    return true;
  });
  assert.equal(fixture.calls.filter(call => call.action === 'identity' && call.name === 'ws01').length, 3);
});

test('controller report must confirm a valid playbook chain before provisioning Windows', async () => {
  const fixture = harness(authored(), { chain: true });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => error.goadMeta.generated_lab.failed_step === 'rename_chain');
  assert.ok(!fixture.calls.some(call => call.action === 'playbook'));
});

test('controller report must include the selected Linux extension identity', async () => {
  const fixture = harness(authored({ extensions: ['elk', 'ws01', 'lx01'] }), { reportIdentity: 'lx01' });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => error.goadMeta.generated_lab.failed_step === 'rename_identity');
  assert.ok(!fixture.calls.some(call => call.action === 'playbook'));
});

test('a successful playbook with failed controller stop does not report provisioned', async () => {
  const fixture = harness(authored(), { stop: true });
  await assert.rejects(goad.deployGoadLane(fixture.args), error => error.goadMeta.stage === 'controller_cleanup'
    && error.goadMeta.status === 'failed');
});

test('GOAD-Light and GOAD identity expectations include each child/trust/member target and ws01', () => {
  for (const version of ['GOAD-Light', 'GOAD']) {
    const prepared = goad.prepareGoadDeploymentSpec(authored({ version }));
    const expected = goad.goadIdentityExpectations(prepared);
    assert.equal(expected.length, goad.getLab(version).vms.length + 1);
    assert.ok(expected.some(vm => vm.domain === 'corp.cy400test.org'));
    assert.equal(expected.find(vm => vm.name === 'ws01').domain, 'cy400test.org');
    if (version === 'GOAD') assert.ok(expected.some(vm => vm.domain === 'cy400test-partner.org'));
  }
});
