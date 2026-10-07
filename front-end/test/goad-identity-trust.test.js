const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const goad = require('../src/utils/goad-deploy');

function harness({ memberAnswers = [true], memberRole = 1, hostname = 'WS01' } = {}) {
  const spec = goad.prepareGoadDeploymentSpec({
    goad: { enabled: true, version: 'GOAD-Mini', rename_forest: true, domain: 'cy400test.org', extensions: ['ws01'] },
    vms: [{ name: 'DC01' }, { name: 'ws01' }],
  });
  const commands = new Map();
  const pauses = [];
  let memberReads = 0;
  const args = {
    spec,
    deployedVMs: [{ name: 'DC01', type: 'qemu', node: 'offline', vm_id: 101 },
      { name: 'ws01', type: 'qemu', node: 'offline', vm_id: 102 }],
    proxmoxAPI: async (method, url, body) => {
      assert.equal(method, 'POST');
      assert.match(url, /\/agent\/exec$/);
      const argv = new URLSearchParams(body).getAll('command');
      commands.set(commands.size + 1, argv.at(-1));
      return { pid: commands.size };
    },
    deps: {
      sleep: async ms => pauses.push(ms),
      pollExecStatus: async (node, vmid) => {
        let observed = { hostname: 'DC01', domain: 'cy400test.org', joined: true, domain_role: 5, secure_channel: null };
        if (vmid === 102) {
          const answer = memberAnswers[Math.min(memberReads++, memberAnswers.length - 1)];
          if (answer instanceof Error) throw answer;
          observed = { hostname, domain: 'cy400test.org', joined: true, domain_role: memberRole, secure_channel: answer };
        }
        return { exited: true, exitcode: 0, stdout: JSON.stringify(observed) };
      },
    },
  };
  return { run: () => goad.verifyGoadIdentities(args), commands, pauses };
}

test('DCs report trust as not applicable and member trust is positively confirmed', async () => {
  const report = await harness().run();
  assert.equal(report.passed, true);
  assert.equal(report.checks[0].observed.domain_role, 5);
  assert.equal(report.checks[0].observed.secure_channel, null);
  assert.equal(report.checks[1].observed.secure_channel, true);
});

test('temporary trust-query failure retries and a later success clears the stale error', async () => {
  const fixture = harness({ memberAnswers: [new Error('private transport response password=do-not-log'), null, true] });
  const report = await fixture.run();
  assert.equal(report.passed, true);
  assert.equal(report.checks[1].error, undefined);
  assert.deepEqual(fixture.pauses, [5000, 5000]);
  assert.ok(!JSON.stringify(report).includes('do-not-log'));
});

test('a member whose trust cannot be queried remains failed without exposing private errors', async () => {
  const fixture = harness({ memberAnswers: [new Error('private transport response password=do-not-log')] });
  await assert.rejects(fixture.run(), error => {
    assert.equal(error.goadIdentityVerification.passed, false);
    const exposed = error.message + JSON.stringify(error.goadIdentityVerification);
    assert.ok(!exposed.includes('do-not-log'));
    assert.equal(error.goadIdentityVerification.checks[1].error, 'Could not read Windows identity through the guest agent');
    return true;
  });
  assert.deepEqual(fixture.pauses, [5000, 5000]);
});

test('an unreported secure-channel result is not accepted as a healthy member', async () => {
  await assert.rejects(harness({ memberAnswers: [null] }).run(), error => {
    assert.equal(error.goadIdentityVerification.checks[1].observed.secure_channel, null);
    assert.equal(error.goadIdentityVerification.checks[1].error, 'Could not verify Windows member secure channel');
    return true;
  });
});

test('standalone or absent domain roles cannot bypass member trust validation', async () => {
  for (const role of [0, 2, null]) {
    await assert.rejects(harness({ memberRole: role }).run(), error => {
      assert.equal(error.goadIdentityVerification.checks[1].ok, false);
      assert.match(error.goadIdentityVerification.checks[1].error, /valid joined domain role/);
      return true;
    });
  }
});

test('a valid secure channel does not excuse an unexpected hostname suffix', async () => {
  await assert.rejects(harness({ hostname: 'WS01-JOSHUAMPAY' }).run(), error => {
    assert.equal(error.goadIdentityVerification.checks[1].observed.secure_channel, true);
    assert.match(error.goadIdentityVerification.checks[1].error, /does not match/);
    return true;
  });
});

const powershell = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
const hasPowerShell = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', 'exit 0']).status === 0;
test('the actual PowerShell queries secure channels only for member roles and suppresses trust errors', { skip: !hasPowerShell }, async () => {
  const fixture = harness();
  await fixture.run();
  const command = fixture.commands.get(1);
  for (const role of [1, 3, 4, 5]) {
    const expectedCalls = role === 1 || role === 3 ? 1 : 0;
    const script = `$script:trustCalls=0; function Get-CimInstance { [pscustomobject]@{Name='fixture';Domain='cy400test.org';PartOfDomain=$true;DomainRole=${role}} }; `
      + "function Test-ComputerSecureChannel { [CmdletBinding()] param(); $script:trustCalls++; throw 'private-trust-error' }; "
      + command + `; if ($script:trustCalls -ne ${expectedCalls}) { throw 'wrong secure-channel invocation count' }`;
    const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.domain_role, role);
    assert.equal(report.secure_channel, null);
    assert.ok(!result.stdout.includes('private-trust-error'));
    assert.ok(!result.stderr.includes('private-trust-error'));
  }
});
