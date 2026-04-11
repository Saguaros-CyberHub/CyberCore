Write-Host "==> Checking OpenSSH Server capability"
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

if (-not $cap) {
    Write-Host "OpenSSH.Server capability not found. Trying DISM..."
    dism /online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /Source:C:\Windows\WinSxS /LimitAccess
} elseif ($cap.State -ne "Installed") {
    Write-Host "==> Installing OpenSSH Server (offline from WinSxS)..."
    try {
        Add-WindowsCapability -Online -Name $cap.Name -Source "C:\Windows\WinSxS" -LimitAccess
    } catch {
        Write-Host "Add-WindowsCapability failed, trying DISM..."
        dism /online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /Source:C:\Windows\WinSxS /LimitAccess
    }
} else {
    Write-Host "OpenSSH Server already installed"
}

Write-Host "==> Configuring sshd"
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service sshd -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

Start-Sleep -Seconds 3

Write-Host "==> Status:"
$svc = Get-Service sshd -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Service: $($svc.Status) ($($svc.StartType))"
} else {
    Write-Host "Service: NOT FOUND (install may have failed)"
}
$listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 22 }
Write-Host "Port 22: $(if ($listener) { 'LISTENING' } else { 'NOT LISTENING' })"
