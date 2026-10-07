# Opens the WinRM listener Packer connects to. Invoked by bootstrap.ps1 from the
# PACKERDATA CD during first logon -- it never runs over WinRM itself, because
# WinRM does not exist yet at that point.
#
# This deliberately configures an unauthenticated-transport, Basic-auth listener.
# That is only acceptable because the VM lives on an isolated build VLAN for the
# duration of the build and is generalized away afterwards. Do not copy this
# configuration into anything that survives.

$ErrorActionPreference = "Stop"

Write-Host "Setting network connection profiles to Private"

# WinRM's default firewall rules refuse to apply on a Public profile, and a
# freshly installed VM starts out Public.
Get-NetConnectionProfile |
    ForEach-Object {
        Set-NetConnectionProfile `
            -InterfaceIndex $_.InterfaceIndex `
            -NetworkCategory Private `
            -ErrorAction SilentlyContinue
    }

Write-Host "Enabling PowerShell remoting"

Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null

Write-Host "Configuring WinRM service"

winrm.cmd quickconfig -quiet -force

winrm.cmd set winrm/config/service '@{AllowUnencrypted="true"}'
winrm.cmd set winrm/config/service/auth '@{Basic="true"}'
winrm.cmd set winrm/config/client/auth '@{Basic="true"}'

# Packer uploads scripts as encoded blobs; the 150 MB default shell memory cap
# and short idle timeouts cause spurious failures on larger provisioners.
winrm.cmd set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
winrm.cmd set winrm/config/winrs '@{MaxShellsPerUser="30"}'
winrm.cmd set winrm/config '@{MaxTimeoutms="7200000"}'

Write-Host "Granting local administrators a full token over the network"

# Without this, a WinRM logon for a local admin gets a filtered token and DISM,
# AppX provisioning and Sysprep all fail with access denied.
New-Item `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Force | Out-Null

Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name LocalAccountTokenFilterPolicy `
    -Type DWord `
    -Value 1

Write-Host "Opening the firewall for WinRM"

Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -ErrorAction SilentlyContinue
Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -ErrorAction SilentlyContinue

if (-not (Get-NetFirewallRule -DisplayName "Packer WinRM" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName "Packer WinRM" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5985 `
        -Profile Any | Out-Null
}

Write-Host "Starting WinRM"

Set-Service -Name WinRM -StartupType Automatic
Restart-Service -Name WinRM

Write-Host "WinRM is listening"
