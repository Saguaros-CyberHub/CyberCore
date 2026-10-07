$ErrorActionPreference = "Stop"

Write-Host "Configuring power settings"

# Select High Performance. The plan is hidden on some Win11 SKUs, so fall back to
# Balanced rather than leaving the VM on a plan that sleeps.
$HighPerformanceGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

powercfg.exe /setactive $HighPerformanceGuid

if ($LASTEXITCODE -ne 0) {
    Write-Host "High Performance plan unavailable, keeping the current plan"
}

# Never turn off display on AC power.
powercfg.exe /change monitor-timeout-ac 0

# Never sleep on AC power.
powercfg.exe /change standby-timeout-ac 0

# Never hibernate. Also reclaims hiberfil.sys from the template image.
powercfg.exe /hibernate off

Write-Host "Disabling Fast Startup"

New-Item `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" `
    -Force | Out-Null

Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" `
    -Name HiberbootEnabled `
    -Type DWord `
    -Value 0

Write-Host "Enabling Remote Desktop"

Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name fDenyTSConnections `
    -Type DWord `
    -Value 0

# Set the firewall rules for Remote Desktop, ICMP echo requests (ping), and inbound OpenSSH connections to allow
#
# -Profile Any -RemoteAddress Any is the whole point of this call, not decoration.
# Merely enabling the group leaves Windows' shipped scoping in place, and the
# Public-profile Remote Desktop rule is restricted to LocalSubnet. A clone of this
# template boots onto a fresh lane VNet with a new MAC, so Windows classifies it as
# an unidentified network -- Public -- and the lane gateway DNATs RDP in from
# guacd's address, which is never in the guest's subnet. Result: RDP that answers
# fine from a neighbour on the same subnet and is silently dropped for Guacamole.
# Pinning the profile also means we do not have to chase the network category on
# every clone; the Private category set in configure-winrm.ps1 applies to the build
# VLAN's connection and does not survive Sysprep + redeployment.
#
# Deliberately NOT -ErrorAction SilentlyContinue: this group always exists on
# Windows 11, and remote access is the entire purpose of the template. Failing the
# build beats shipping an image whose RDP is unreachable from where it is used.
Set-NetFirewallRule `
    -DisplayGroup "Remote Desktop" `
    -Enabled True `
    -Profile Any `
    -RemoteAddress Any `
    -LocalAddress Any

Set-NetFirewallRule `
    -Name "CoreNet-Diag-ICMP4-EchoRequest-In" `
    -Enabled True `
    -Profile Any `
    -RemoteAddress Any `
    -LocalAddress Any `
    -ErrorAction SilentlyContinue

# install-software.ps1 treats OpenSSH as best-effort, so the rule is absent on a
# build VLAN that could not reach Windows Update. Do not fail the build over it.
Set-NetFirewallRule `
    -Name "OpenSSH-Server-In-TCP" `
    -Enabled True `
    -Profile Any `
    -ErrorAction SilentlyContinue

Write-Host "Verifying the QEMU guest agent"

# Installed by bootstrap.ps1 at first logon. If it is missing here the build has
# only got this far by luck, so say so loudly rather than silently shipping a
# template Proxmox cannot report an IP for.
$GuestAgent = Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue

if ($GuestAgent) {
    Set-Service -Name "QEMU-GA" -StartupType Automatic

    if ($GuestAgent.Status -ne "Running") {
        Start-Service -Name "QEMU-GA"
    }

    Write-Host "QEMU guest agent is configured"
}
else {
    Write-Host "WARNING: QEMU-GA service not found -- virtio-win-guest-tools did not install correctly. Check C:\Windows\Temp\bootstrap.log."
}
