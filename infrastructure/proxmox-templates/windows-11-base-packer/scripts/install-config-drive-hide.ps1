# =============================================================================
# TEMPORARY -- delete this script, files/config-drive/, and the two provisioners
# that reference them in windows-11.pkr.hcl to back the whole thing out.
#
# Registers a scheduled task that drops the drive letter from the Proxmox
# cloud-init config drive on every boot. See the header of
# files/config-drive/Hide-ConfigDrive.ps1 for what this does and does not buy.
# =============================================================================

$ErrorActionPreference = "Stop"

$ScriptSource = "C:\Windows\Temp\config-drive\Hide-ConfigDrive.ps1"

# C:\Windows\Setup\Scripts, not C:\Windows\Temp: cleanup.ps1 empties Temp
# immediately before Sysprep, and this has to survive into the template.
$ScriptTarget = "C:\Windows\Setup\Scripts\Hide-ConfigDrive.ps1"

$TaskName = "CyberCore-HideConfigDrive"

if (-not (Test-Path $ScriptSource)) {
    throw "Missing $ScriptSource. It should have been uploaded from files/config-drive/."
}

Write-Host "Staging Hide-ConfigDrive.ps1"

Copy-Item -Path $ScriptSource -Destination $ScriptTarget -Force

Write-Host "Registering the $TaskName scheduled task"

# Two triggers rather than one. AtStartup is the one that matters -- it closes
# the window before the logon screen appears, and the script itself waits for
# Cloudbase-Init to finish so it cannot race the password being applied. AtLogOn
# is a backstop for the case where the startup run failed or timed out.
#
# Note this deliberately does NOT hang off Cloudbase-Init's LocalScriptsPlugin,
# which would be the obvious hook: local scripts are recorded as complete in
# HKLM\SOFTWARE\Cloudbase Solutions\Cloudbase-Init\<instance-id>\Plugins and are
# then skipped on subsequent boots with an unchanged instance ID -- that is,
# skipped on exactly the boots this needs to run on.
$Triggers = @(
    New-ScheduledTaskTrigger -AtStartup
    New-ScheduledTaskTrigger -AtLogOn
)

$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptTarget`""

# SYSTEM, because removing a mount point needs more than the student's token
# even though that account is a local Administrator -- an unelevated interactive
# session would hit UAC with no prompt to answer.
$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# IgnoreNew so the AtLogOn backstop cannot run concurrently with a still-waiting
# AtStartup instance. StartWhenAvailable keeps the task honest if the VM is
# suspended through its trigger, which lab VMs routinely are.
$Settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

# Sysprep /generalize preserves scheduled tasks, so registering here carries the
# task into the template and every clone made from it.
Register-ScheduledTask `
    -TaskName $TaskName `
    -Trigger $Triggers `
    -Action $Action `
    -Principal $Principal `
    -Settings $Settings `
    -Description "TEMPORARY: removes the drive letter from the cloud-init config drive on boot. See the CyberCore Windows 11 Packer README." `
    -Force | Out-Null

if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    throw "Register-ScheduledTask reported success but $TaskName does not exist"
}

Write-Host "$TaskName registered"
