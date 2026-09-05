const { test } = require('node:test');
const assert = require('node:assert/strict');
const { waitForGoadPlaybook } = require('../src/utils/goad-deploy');

function harness({ sentinels = ['__MISSING__'], tail = '', tailError = false } = {}) {
  const commands = [];
  let clock = 0;
  let reads = 0;
  const args = {
    controllerVmId: 210881, bestNode: 'pve1',
    logPath: '/var/log/goad-run-10881.log', donePath: '/var/log/goad-done-10881.txt',
    proxmoxAPI: async (method, url, body) => {
      assert.equal(method, 'POST');
      assert.match(url, /qemu\/210881\/agent\/exec$/);
      const argv = new URLSearchParams(body).getAll('command');
      assert.deepEqual(argv.slice(0, 2), ['/bin/sh', '-c']);
      commands.push(argv[2]);
      return { pid: commands.length };
    },
  };
  const deps = {
    now: () => clock,
    sleep: async ms => { clock += ms; },
    pollExecStatus: async (node, vmId, pid, timeoutMs) => {
      assert.equal(node, 'pve1');
      assert.equal(vmId, 210881);
      assert.equal(timeoutMs, 10000);
      if (commands[pid - 1].startsWith('tail ')) {
        if (tailError) throw new Error('guest agent unavailable during log read: password=diagnostic-secret');
        return { exited: true, exitcode: 0, stdout: tail };
      }
      const result = sentinels[Math.min(reads++, sentinels.length - 1)];
      if (result instanceof Error) throw result;
      if (typeof result === 'object') return result;
      return { exited: true, exitcode: 0, stdout: result };
    },
  };
  return { args, deps, commands, run: () => waitForGoadPlaybook(args, deps) };
}

test('a two-hour timeout captures the last active task without copying raw logs before cleanup', async () => {
  const fixture = harness({ tail: 'older output\n'.repeat(300)
    + 'TASK [mssql : Restart service MSSQL] ********\nchanged: [srv02]\n'
    + ' [started TASK: mssql_ssms : Install SSMS on srv02]\n' });
  await assert.rejects(fixture.run(), error => {
    assert.match(error.message, /did not finish within 2h/);
    assert.match(error.message, /Last task: mssql_ssms : Install SSMS on srv02/);
    const report = error.goadPlaybook;
    assert.equal(report.status, 'timed_out');
    assert.equal(report.timeout_ms, 7200000);
    assert.equal(report.elapsed_ms, 7200000);
    assert.equal(report.exitcode, null);
    assert.equal(report.last_task, 'mssql_ssms : Install SSMS on srv02');
    assert.equal(report.log_path, fixture.args.logPath);
    assert.equal(report.completion_path, fixture.args.donePath);
    assert.equal(report.log_tail, undefined);
    assert.ok(!error.message.includes('older output'));
    return true;
  });
  assert.match(fixture.commands.at(-1), /^tail -n 100 -- '/);
});

test('an Ansible failure includes its last task and retains raw failure output on the controller', async () => {
  const fixture = harness({ sentinels: ['2'], tail: '\x1b[31mTASK [mssql_ssms : Install SSMS] ********\x1b[0m\nfatal: [srv02]: FAILED!' });
  await assert.rejects(fixture.run(), error => {
    assert.match(error.message, /GOAD playbook exit 2/);
    assert.equal(error.goadPlaybook.status, 'failed');
    assert.equal(error.goadPlaybook.last_task, 'mssql_ssms : Install SSMS');
    assert.equal(error.goadPlaybook.log_tail, undefined);
    assert.ok(!error.message.includes('fatal: [srv02]'));
    assert.ok(!error.message.includes('\x1b'));
    return true;
  });
  assert.equal(fixture.commands.length, 2);
  assert.ok(fixture.commands.every(command => !command.includes('__tail__')));
});

test('diagnostic read failure retains the original two-hour timeout', async () => {
  const fixture = harness({ tailError: true });
  await assert.rejects(fixture.run(), error => {
    assert.match(error.message, /did not finish within 2h/);
    assert.equal(error.goadPlaybook.status, 'timed_out');
    assert.equal(error.goadPlaybook.log_error, 'Last task could not be read from the controller log');
    assert.ok(!JSON.stringify(error.goadPlaybook).includes('diagnostic-secret'));
    assert.ok(!error.message.includes('diagnostic-secret'));
    return true;
  });
});

test('transient sentinel reads and a partially written empty file do not interrupt the run', async () => {
  const fixture = harness({ sentinels: [new Error('guest agent reconnecting'), '', '__MISSING__', '0\n'] });
  const result = await fixture.run();
  assert.equal(result.exitcode, 0);
  assert.equal(result.goadPlaybook.status, 'succeeded');
  assert.equal(result.goadPlaybook.elapsed_ms, 60000);
  assert.equal(result.goadPlaybook.poll_error, undefined);
  assert.equal(fixture.commands.length, 4);
});

test('an unsuccessfully executed read cannot masquerade as playbook success', async () => {
  const fixture = harness({ sentinels: [{ exited: true, exitcode: 1, stdout: '0', stderr: 'read failed: password=poll-secret' }] });
  await assert.rejects(fixture.run(), error => {
    assert.equal(error.goadPlaybook.status, 'timed_out');
    assert.equal(error.goadPlaybook.poll_error, 'Completion status could not be read from the controller');
    assert.ok(!JSON.stringify(error.goadPlaybook).includes('poll-secret'));
    assert.ok(!error.message.includes('poll-secret'));
    return true;
  });
});

for (const completion of ['__MISSING__', '2']) {
  test(`Ansible user-loop passwords are absent from app diagnostics on ${completion === '2' ? 'failure' : 'timeout'}`, async () => {
    const tail = 'TASK [ad : Set users SPN lists] ********\n'
      + "changed: [dc01] => (item={'key': 'lab.user', 'value': {'password': 'student-domain-secret'}})\n"
      + 'fatal: [dc01]: FAILED! => {"msg": "password=second-secret", "detail": "[started TASK: embedded-secret]"}\n';
    const fixture = harness({ sentinels: [completion], tail });
    await assert.rejects(fixture.run(), error => {
      assert.equal(error.goadPlaybook.last_task, 'ad : Set users SPN lists');
      assert.equal(error.goadPlaybook.log_tail, undefined);
      const exposed = error.message + JSON.stringify(error.goadPlaybook);
      for (const secret of ['student-domain-secret', 'second-secret', 'embedded-secret']) {
        assert.ok(!exposed.includes(secret), `${secret} must remain in the controller log`);
      }
      return true;
    });
  });
}

test('task summaries are bounded even when a task heading is unusually long', async () => {
  const fixture = harness({ sentinels: ['2'], tail: `[started TASK: ${'x'.repeat(1000)}]\n` });
  await assert.rejects(fixture.run(), error => {
    assert.equal(error.goadPlaybook.last_task.length, 300);
    assert.ok(error.message.length < 500);
    return true;
  });
});

for (const sentinel of ['0garbage', '0\n1', '-1', '256', 'Infinity']) {
  test(`invalid completion ${JSON.stringify(sentinel)} cannot report success`, async () => {
    const fixture = harness({ sentinels: [sentinel] });
    await assert.rejects(fixture.run(), error => {
      assert.match(error.message, /invalid completion status/);
      assert.equal(error.goadPlaybook.status, 'invalid_completion');
      assert.equal(error.goadPlaybook.elapsed_ms, 15000);
      assert.equal(error.goadPlaybook.exitcode, null);
      return true;
    });
  });
}
