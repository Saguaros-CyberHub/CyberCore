/**
 * ============================================================================
 * SCRIPT EXECUTOR
 * Runs vulnerability scripts on deployed VMs via Proxmox Guest Agent
 *
 * Key Proxmox API details:
 * - agent/exec: `command` = executable path only, `arg0`..`argN` = separate args
 * - agent/file-write: `content` = base64 string, `encode` = 1 to tell Proxmox to decode it
 * - agent/exec-status: `out-data`/`err-data` are returned as plain text (Proxmox decodes)
 * ============================================================================
 */

const { proxmoxAPI } = require('./proxmox');
const { query } = require('./db');

/**
 * Wait for the QEMU guest agent to become responsive
 */
async function waitForGuestAgent(node, vmId, timeoutMs = 180000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await proxmoxAPI('POST', `/api2/json/nodes/${node}/qemu/${vmId}/agent/ping`);
      return true;
    } catch (e) {
      await new Promise(r => setTimeout(r, 5000));
    }
  }
  return false;
}

/**
 * Write a file to the VM via guest agent
 * Content is base64-encoded, with encode=1 so Proxmox decodes it before sending to QGA
 * This avoids the Perl "Wide character" error
 */
async function guestFileWrite(node, vmId, filePath, content) {
  const cleaned = content
    .replace(/^\uFEFF/, '')
    .replace(/\r?\n/g, '\r\n')
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'");

  const b64 = Buffer.from(cleaned, 'utf-8').toString('base64');

  await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/file-write`, {
      file: filePath,
      content: b64,
      encode: 1  // Tell Proxmox: content is base64, please decode before writing
    }
  );
}

/**
 * Execute a command via guest agent
 * Proxmox only accepts { command: "full command string" }
 * Works reliably for short commands (~350 chars proven)
 */
async function agentExec(node, vmId, command) {
  console.log(`[AgentExec] ${command.substring(0, 120)}... (${command.length} chars)`);

  const result = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    { command: command }
  );

  const pid = result?.pid;
  if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);
  return { pid };
}

/**
 * Poll guest-exec-status until command completes
 */
async function pollExecStatus(node, vmId, pid, timeoutMs = 1800000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const status = await proxmoxAPI('GET',
        `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec-status?pid=${pid}`
      );

      if (status?.exited) {
        // Proxmox returns out-data/err-data as plain text (already decoded from QGA base64)
        return {
          exited: true,
          exitcode: status.exitcode ?? 0,
          stdout: status['out-data'] || '',
          stderr: status['err-data'] || ''
        };
      }
    } catch (e) {
      // May error while process is still running
    }

    await new Promise(r => setTimeout(r, 3000));
  }

  return { exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' };
}

/**
 * Execute a PowerShell script on a Windows VM
 * Strategy: write script to file via file-write, then execute with short exec command
 */
async function executePowerShellViaFile(node, vmId, scriptContent, scriptArgs = '') {
  // Normalize content: strip BOM, smart quotes, and ALL non-ASCII characters
  // (Proxmox's Perl backend crashes with "Wide character" on any non-ASCII in input-data)
  const cleaned = scriptContent
    .replace(/^\uFEFF/, '')
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u2014]/g, '--')
    .replace(/[^\x00-\x7F]/g, '');

  // Pipe the entire script directly into PowerShell via stdin (input-data)
  // Add script args handling: if scriptArgs provided, wrap in a param-forwarding block
  let stdinContent;
  if (scriptArgs) {
    // For scripts with param() blocks, save to file first then run with args
    // Use PowerShell to decode from base64 and save, then invoke
    const b64 = Buffer.from(cleaned, 'utf-8').toString('base64');
    const ts = Date.now();
    const ps1Path = `C:\\Windows\\Temp\\vuln_${ts}.ps1`;
    stdinContent = [
      `$bytes = [Convert]::FromBase64String('${b64}')`,
      `[IO.File]::WriteAllBytes('${ps1Path}', $bytes)`,
      `& '${ps1Path}' ${scriptArgs}`,
      `$ec = $LASTEXITCODE`,
      `Remove-Item '${ps1Path}' -Force -ErrorAction SilentlyContinue`,
      `[Environment]::Exit($ec)`
    ].join('\n') + '\n';
  } else {
    // No args — pipe script directly as stdin
    // Use [Environment]::Exit() to force-kill the process cleanly
    stdinContent = cleaned + '\n[Environment]::Exit($LASTEXITCODE)\n';
  }

  console.log(`[ScriptExec] Piping ${stdinContent.length} chars via stdin to powershell.exe on VM ${vmId}`);

  const result = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`, {
      command: 'powershell.exe',
      'input-data': stdinContent
    }
  );

  const pid = result?.pid;
  if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);

  return await pollExecStatus(node, vmId, pid);
}

/**
 * Get IP addresses from a VM via guest agent
 */
async function getVMIPs(node, vmId) {
  try {
    const agentData = await proxmoxAPI('GET',
      `/api2/json/nodes/${node}/qemu/${vmId}/agent/network-get-interfaces`
    );
    const ips = [];
    if (agentData?.result) {
      for (const iface of agentData.result) {
        if (iface.name === 'lo' || iface.name === 'Loopback Pseudo-Interface 1') continue;
        for (const addr of (iface['ip-addresses'] || [])) {
          if (addr['ip-address-type'] === 'ipv4' && !addr['ip-address'].startsWith('127.')) {
            ips.push(addr['ip-address']);
          }
        }
      }
    }
    return ips;
  } catch (e) {
    return [];
  }
}

/**
 * Sort scripts by dependency order (topological sort)
 */
function sortByDependencies(scripts) {
  const slugMap = {};
  scripts.forEach(s => { slugMap[s.slug] = s; });
  const visited = new Set();
  const sorted = [];

  function visit(slug) {
    if (visited.has(slug)) return;
    visited.add(slug);
    const script = slugMap[slug];
    if (!script) return;
    for (const dep of (script.depends_on || [])) {
      if (slugMap[dep]) visit(dep);
    }
    sorted.push(script);
  }

  scripts.forEach(s => visit(s.slug));
  return sorted;
}

/**
 * Execute all selected scripts on a VM in dependency order
 */
async function executeScriptsOnVM(node, vmId, vmName, scripts, deploymentId) {
  const sorted = sortByDependencies(scripts);

  for (const script of sorted) {
    const scriptKey = `${vmName}:${script.slug}`;
    console.log(`[ScriptExec] Running ${scriptKey} on VM ${vmId} (node ${node})`);

    await updateScriptStatus(deploymentId, vmName, script.slug, 'running');

    try {
      const result = await executePowerShellViaFile(node, vmId, script.script_content, script.script_args || '');

      if (result.exited) {
        const output = (result.stdout || '') + (result.stderr ? `\nSTDERR:\n${result.stderr}` : '');
        if (result.exitcode === 0) {
          console.log(`[ScriptExec] ${scriptKey} completed (exit: 0)`);
          await updateScriptStatus(deploymentId, vmName, script.slug, 'completed', null, output);
        } else {
          console.error(`[ScriptExec] ${scriptKey} failed (exit: ${result.exitcode})\nOUTPUT: ${output.substring(0, 2000)}`);
          await updateScriptStatus(deploymentId, vmName, script.slug, 'failed', `Exit code: ${result.exitcode}`, output);
        }
      } else {
        console.error(`[ScriptExec] ${scriptKey} timed out`);
        await updateScriptStatus(deploymentId, vmName, script.slug, 'failed', 'Script timed out');
      }
    } catch (e) {
      console.error(`[ScriptExec] ${scriptKey} error: ${e.message}`);
      await updateScriptStatus(deploymentId, vmName, script.slug, 'failed', e.message);
    }
  }
}

/**
 * Update script status in deployment_vuln_selections (clinic_db)
 */
async function updateScriptStatus(deploymentId, vmName, scriptSlug, status, error = null, output = null) {
  if (!deploymentId) return;
  try {
    const result = await query(
      `SELECT selected_scripts FROM deployment_vuln_selections WHERE id = $1`,
      [deploymentId]
    );
    if (result.rows.length === 0) return;

    const scripts = result.rows[0].selected_scripts || [];
    const entry = scripts.find(s => s.vm_name === vmName && s.script_slug === scriptSlug);
    if (entry) {
      entry.status = status;
      if (error) entry.error = error;
      if (output) entry.output = output;
      entry.updated_at = new Date().toISOString();
    }

    await query(
      `UPDATE deployment_vuln_selections SET selected_scripts = $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(scripts), deploymentId]
    );
  } catch (e) {
    console.error(`[ScriptExec] Failed to update script status: ${e.message}`);
  }
}

module.exports = {
  waitForGuestAgent,
  guestFileWrite,
  agentExec,
  pollExecStatus,
  executePowerShellViaFile,
  getVMIPs,
  sortByDependencies,
  executeScriptsOnVM,
  updateScriptStatus
};
