const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const clock = require('../src/utils/goad-clock');

const UTC = Date.parse('2026-09-05T19:04:55Z');
const vms = [
  { name: 'DC01', type: 'qemu', node: 'pve1', vm_id: 601 },
  { name: 'ws01', type: 'qemu', node: 'pve2', vm_id: 602 },
];

function fixture(fault = {}) {
  const calls = [];
  const report = { passed: false, source: 'proxmox_node_utc', checks: [] };
  const executions = new Map();
  const args = {
    vms, report,
    proxmoxAPI: async (method, path, body) => {
      calls.push({ method, path, body });
      if (path.endsWith('/time')) {
        if (fault.invalidTime) return { localtime: UTC / 1000 - 7 * 3600 };
        return { time: UTC / 1000, localtime: UTC / 1000 - 7 * 3600, timezone: 'America/Phoenix' };
      }
      if (method === 'PUT') {
        if (fault.config) throw new Error('RTC update denied');
        return null;
      }
      if (path.endsWith('/config?current=1')) return { localtime: fault.pendingRtc ? 1 : 0 };
      if (path.endsWith('/config')) return { localtime: fault.rtcReadback ? 1 : 0 };
      throw new Error('Unexpected API call ' + path);
    },
    agentExecArgv: async (node, vmid, argv) => {
      calls.push({ action: 'exec', node, vmid, argv });
      const pid = executions.size + 1;
      executions.set(pid, argv[4]);
      return { pid };
    },
    pollExecStatus: async (node, vmid, pid) => {
      const command = executions.get(pid);
      if (fault.exec) return { exited: true, exitcode: 1, stdout: 'arbitrary guest output' };
      if (command.includes('cybercore-clock-read')) {
        return { exited: true, exitcode: 0, stdout: fault.invalidReport ? 'not JSON' : JSON.stringify({
          utc_milliseconds: UTC + (fault.skew || 0), timezone: fault.timezone || 'UTC',
        }) };
      }
      return { exited: true, exitcode: 0, stdout: 'seeded' };
    },
    waitForGuestAgent: async () => !fault.agent,
  };
  return { args, calls, report };
}

test('clock roster contains only managed Windows, including WS01, and refuses missing or duplicate entries', () => {
  const lab = { vms: [{ name: 'DC01', role: 'dc' }, { name: 'WS01', role: 'workstation' },
    { name: 'lx01', role: 'linux' }] };
  const all = [...vms, { name: 'lx01', type: 'qemu', vm_id: 700 },
    { name: 'kali', type: 'qemu', vm_id: 701 }, { name: 'elk', type: 'qemu', vm_id: 702 }];
  assert.deepEqual(clock.goadWindowsVms(lab, all), vms);
  assert.throws(() => clock.goadWindowsVms(lab, [vms[0]]), /one deployed Windows VM for WS01/);
  assert.throws(() => clock.goadWindowsVms(lab, [...all, vms[0]]), /one deployed Windows VM for DC01/);
});

test('RTC writes precede UTC seeding and each guest uses UTC time, never the node localtime', async () => {
  const f = fixture();
  await clock.configureGoadWindowsRtc(f.args);
  await clock.seedGoadWindowsClocks(f.args);
  assert.equal(f.report.passed, true);
  assert.deepEqual(f.report.checks.map(check => [check.name, check.rtc_utc, check.timezone, check.skew_seconds]),
    [['DC01', true, 'UTC', 0], ['ws01', true, 'UTC', 0]]);
  assert.equal(f.calls.filter(call => call.method === 'PUT').length, 2);
  const seeds = f.calls.filter(call => call.action === 'exec' && call.argv[4].includes('cybercore-clock-seed'));
  assert.equal(seeds.length, 2);
  for (const call of seeds) assert.ok(call.argv[4].includes(`FromUnixTimeMilliseconds(${UTC})`));
  assert.ok(f.calls.findIndex(call => call.action === 'exec') > f.calls.findIndex(call => call.method === 'PUT'));
  assert.equal(f.calls.filter(call => call.path?.endsWith('/time')).length, 6);
});

for (const [fault, pattern] of [
  [{ config: true }, /UTC RTC update failed/],
  [{ rtcReadback: true }, /did not retain the UTC RTC/],
  [{ pendingRtc: true }, /not active after restart/],
  [{ invalidTime: true }, /valid UTC time/],
  [{ agent: true }, /guest agent is unavailable/],
  [{ exec: true }, /clock command failed/],
  [{ invalidReport: true }, /invalid clock report/],
  [{ timezone: 'Romance Standard Time' }, /valid UTC clock/],
  [{ skew: -9 * 3600000 }, /60-second UTC tolerance/],
  [{ skew: 2 * 3600000 }, /60-second UTC tolerance/],
]) {
  test(`clock failure blocks provisioning: ${JSON.stringify(fault)}`, async () => {
    const f = fixture(fault);
    await assert.rejects(async () => {
      await clock.configureGoadWindowsRtc(f.args);
      await clock.seedGoadWindowsClocks(f.args);
    }, error => {
      assert.match(error.message, pattern);
      assert.equal(error.goadClock, f.report);
      assert.equal(f.report.passed, false);
      assert.equal(f.report.checks[0].passed, false);
      assert.ok(f.report.checks[0].error);
      assert.ok(!JSON.stringify(f.report).includes('arbitrary guest output'));
      return true;
    });
  });
}

test('slow node time response is refused instead of setting a stale clock', async () => {
  const ticks = [0, 11000];
  await assert.rejects(clock.nodeUtc('pve1', async () => ({ time: UTC / 1000 }), () => ticks.shift()),
    /took too long to trust/);
});

test('post-provisioning verification reads clocks without reseeding or changing RTC', async () => {
  const fault = {};
  const f = fixture(fault);
  await clock.configureGoadWindowsRtc(f.args);
  await clock.seedGoadWindowsClocks(f.args);
  const completed = f.calls.length;
  fault.skew = -9 * 3600000;
  await assert.rejects(clock.verifyGoadWindowsClocks(f.args), /60-second UTC tolerance/);
  assert.equal(f.report.phase, 'after_provisioning');
  assert.equal(f.report.passed, false);
  const validationCalls = f.calls.slice(completed);
  assert.ok(validationCalls.every(call => !call.method || call.method === 'GET'));
  assert.ok(validationCalls.filter(call => call.action === 'exec')
    .every(call => call.argv[4] === clock.CLOCK_READ_COMMAND));
});

test('external errors cannot put raw guest output or commands in persisted clock metadata', async () => {
  for (const operation of ['proxmoxAPI', 'agentExecArgv', 'pollExecStatus', 'waitForGuestAgent']) {
    const f = fixture();
    await clock.configureGoadWindowsRtc(f.args);
    f.args[operation] = async () => { throw new Error('PRIVATE-ERROR-COMMAND-AND-OUTPUT'); };
    await assert.rejects(clock.seedGoadWindowsClocks(f.args), error => {
      assert.equal(error.goadClock, f.report);
      assert.ok(!error.message.includes('PRIVATE-ERROR'));
      assert.ok(!JSON.stringify(f.report).includes('PRIVATE-ERROR'));
      return true;
    });
  }
});

test('numeric but out-of-range guest dates fail as invalid clock reports', async () => {
  const f = fixture({ skew: Number.MAX_SAFE_INTEGER - UTC });
  await clock.configureGoadWindowsRtc(f.args);
  await assert.rejects(clock.seedGoadWindowsClocks(f.args), /valid UTC clock/);
});

test('PowerShell sets UTC before applying the supplied UTC instant without changing the test machine', {
  skip: process.platform !== 'win32',
}, () => {
  // Shadow both mutating cmdlets with local functions. The real generated script
  // then runs against those functions; no host clock or timezone is modified.
  const script = [
    "$script:order=@(); $script:clock=$null",
    'function Set-TimeZone { param($Id) $script:order+=\"timezone:$Id\" }',
    'function Set-Date { param($Date) $script:order+=\"date\"; $script:clock=$Date.ToUniversalTime().ToString(\"o\") }',
    clock.clockSeedCommand(UTC),
    '@{ order=$script:order; utc=$script:clock } | ConvertTo-Json -Compress',
  ].join('\n');
  const out = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8' });
  assert.equal(out.status, 0, out.stderr);
  const result = JSON.parse(out.stdout.trim().split(/\r?\n/).at(-1));
  assert.deepEqual(result.order, ['timezone:UTC', 'date']);
  assert.equal(Date.parse(result.utc), UTC);
});
