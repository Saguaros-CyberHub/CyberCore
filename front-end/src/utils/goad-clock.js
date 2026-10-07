/** Keep GOAD Windows clocks in UTC before AD promotion and domain joins. */
const { performance } = require('node:perf_hooks');

const MAX_SKEW_MS = 60000;
const MAX_TIME_QUERY_MS = 10000;
const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

function clockError(message) {
  const error = new Error(message);
  error.code = 'GOAD_CLOCK';
  return error;
}

async function callSafely(message, operation) {
  try { return await operation(); }
  catch (_) { throw clockError(message); }
}

function goadWindowsVms(labDef, deployedVMs) {
  return labDef.vms.filter(vm => vm.role !== 'linux').map(expected => {
    const matches = (deployedVMs || []).filter(vm =>
      String(vm.name).toLowerCase() === expected.name.toLowerCase());
    const vm = matches[0];
    if (matches.length !== 1 || vm.type !== 'qemu' || !vm.node
      || !Number.isSafeInteger(Number(vm.vm_id)) || Number(vm.vm_id) <= 0) {
      throw clockError(`GOAD clock preparation requires one deployed Windows VM for ${expected.name}`);
    }
    return vm;
  });
}

function clockSeedCommand(utcMilliseconds) {
  if (!Number.isSafeInteger(utcMilliseconds) || utcMilliseconds < 946684800000
    || utcMilliseconds > 253402300799000) {
    throw clockError('Invalid Proxmox UTC time for GOAD clock preparation');
  }
  return [
    '# cybercore-clock-seed',
    "$ErrorActionPreference='Stop'",
    "Set-TimeZone -Id 'UTC'",
    `$target=[DateTimeOffset]::FromUnixTimeMilliseconds(${utcMilliseconds}).UtcDateTime`,
    'Set-Date -Date $target | Out-Null',
    "'Clock seeded from the Proxmox node'",
  ].join('\n');
}

const CLOCK_READ_COMMAND = [
  '# cybercore-clock-read',
  "$ErrorActionPreference='Stop'",
  "@{ utc_milliseconds=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); timezone=(Get-TimeZone).Id } | ConvertTo-Json -Compress",
].join('\n');

async function nodeUtc(node, proxmoxAPI, monotonic = () => performance.now()) {
  const start = monotonic();
  // Proxmox returns both time (UTC epoch seconds) and localtime (shifted by the
  // node timezone). Only time is suitable for setting another system's clock.
  const result = await callSafely(`Proxmox node ${node} UTC time could not be read`,
    () => proxmoxAPI('GET', `/api2/json/nodes/${encodeURIComponent(node)}/time`));
  const elapsed = monotonic() - start;
  if (elapsed < 0 || elapsed > MAX_TIME_QUERY_MS) {
    throw clockError(`Proxmox node ${node} UTC sample took too long to trust`);
  }
  if (typeof result?.time !== 'number' || !Number.isSafeInteger(result.time)
    || result.time < 946684800 || result.time > 253402300799) {
    throw clockError(`Proxmox node ${node} did not return a valid UTC time`);
  }
  return result.time * 1000;
}

function failed(error, report, check) {
  if (error?.code !== 'GOAD_CLOCK') {
    error = clockError(`GOAD VM ${check?.name || 'unknown'} clock preparation could not be completed`);
  }
  if (check) check.error = error.message;
  report.passed = false;
  error.goadClock = report;
  return error;
}

async function configureGoadWindowsRtc({ vms, proxmoxAPI, report }) {
  for (const vm of vms) {
    const check = { name: vm.name, vmid: Number(vm.vm_id), node: vm.node,
      rtc_utc: false, passed: false };
    report.checks.push(check);
    try {
      const url = `/api2/json/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vm_id}/config`;
      await callSafely(`GOAD VM ${vm.name} UTC RTC update failed`,
        () => proxmoxAPI('PUT', url, { localtime: 0 }));
      const config = await callSafely(`GOAD VM ${vm.name} UTC RTC setting could not be read`,
        () => proxmoxAPI('GET', url));
      if (![0, '0', false].includes(config?.localtime)) {
        throw clockError(`GOAD VM ${vm.name} did not retain the UTC RTC setting`);
      }
      check.rtc_configured = true;
    } catch (error) {
      throw failed(error, report, check);
    }
  }
}

async function runGoadWindowsClocks({ vms, proxmoxAPI, agentExecArgv,
  waitForGuestAgent, pollExecStatus, report, monotonic, seedClocks, phase }) {
  report.phase = phase;
  report.passed = false;
  for (const check of report.checks) check.passed = false;
  const execute = async (vm, script) => {
    const { pid } = await callSafely(`GOAD VM ${vm.name} clock command could not be started`,
      () => agentExecArgv(vm.node, vm.vm_id,
        [POWERSHELL, '-NoProfile', '-NonInteractive', '-Command', script], proxmoxAPI));
    const result = await callSafely(`GOAD VM ${vm.name} clock command status could not be read`,
      () => pollExecStatus(vm.node, vm.vm_id, pid, 60000));
    if (!result?.exited || result.exitcode !== 0) {
      // Persist a bounded status, never arbitrary guest output or command text.
      throw clockError(`GOAD VM ${vm.name} clock command ${result?.exited ? 'failed' : 'did not finish'}`);
    }
    return String(result['out-data'] ?? result.stdout ?? result.outData ?? '').trim();
  };
  for (const vm of vms) {
    const check = report.checks.find(item => item.vmid === Number(vm.vm_id) && item.node === vm.node);
    try {
      if (!check?.rtc_configured) throw clockError(`GOAD VM ${vm.name} UTC RTC was not configured`);
      // After the cold restart, check the running configuration, not merely
      // a pending value accepted while the old QEMU process was still running.
      const config = await callSafely(`GOAD VM ${vm.name} running RTC setting could not be read`,
        () => proxmoxAPI('GET', `/api2/json/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vm_id}/config?current=1`));
      if (![0, '0', false].includes(config?.localtime)) {
        throw clockError(`GOAD VM ${vm.name} UTC RTC setting is not active after restart`);
      }
      check.rtc_utc = true;
      const ready = await callSafely(`GOAD VM ${vm.name} guest agent is unavailable for clock preparation`,
        () => waitForGuestAgent(vm.node, vm.vm_id, 180000));
      if (!ready) {
        throw clockError(`GOAD VM ${vm.name} guest agent is unavailable for clock preparation`);
      }
      if (seedClocks) {
        const seed = await nodeUtc(vm.node, proxmoxAPI, monotonic);
        await execute(vm, clockSeedCommand(seed));
        check.seeded_utc = new Date(seed).toISOString();
      }
      // Independent readback, bracketed by fresh node samples, tolerates normal
      // guest-agent polling latency without accepting a timezone-sized offset.
      const before = await nodeUtc(vm.node, proxmoxAPI, monotonic);
      let observed;
      try { observed = JSON.parse(await execute(vm, CLOCK_READ_COMMAND)); }
      catch (error) {
        if (error instanceof SyntaxError) throw clockError(`GOAD VM ${vm.name} returned an invalid clock report`);
        throw error;
      }
      const after = await nodeUtc(vm.node, proxmoxAPI, monotonic);
      if (after < before || after - before > 90000) {
        throw clockError(`Proxmox node ${vm.node} UTC changed unexpectedly during verification`);
      }
      if (observed?.timezone !== 'UTC' || !Number.isSafeInteger(observed?.utc_milliseconds)
        || !Number.isFinite(new Date(observed.utc_milliseconds).getTime())) {
        throw clockError(`GOAD VM ${vm.name} did not report a valid UTC clock`);
      }
      check.timezone = 'UTC';
      check.observed_utc = new Date(observed.utc_milliseconds).toISOString();
      check.node_utc = new Date(after).toISOString();
      check.skew_seconds = Math.round((observed.utc_milliseconds - after) / 1000);
      if (observed.utc_milliseconds < before - MAX_SKEW_MS
        || observed.utc_milliseconds > after + MAX_SKEW_MS) {
        throw clockError(`GOAD VM ${vm.name} clock remains outside the 60-second UTC tolerance`);
      }
      check.passed = true;
    } catch (error) {
      throw failed(error, report, check);
    }
  }
  report.passed = report.checks.every(check => check.passed);
  return report;
}

function seedGoadWindowsClocks(options) {
  return runGoadWindowsClocks({ ...options, seedClocks: true, phase: 'before_promotion' });
}

function verifyGoadWindowsClocks(options) {
  // Read only after GOAD's reboots: reseeding here would hide a clock reset.
  return runGoadWindowsClocks({ ...options, seedClocks: false, phase: 'after_provisioning' });
}

module.exports = { goadWindowsVms, clockSeedCommand, CLOCK_READ_COMMAND,
  nodeUtc, configureGoadWindowsRtc, seedGoadWindowsClocks, verifyGoadWindowsClocks, MAX_SKEW_MS };
