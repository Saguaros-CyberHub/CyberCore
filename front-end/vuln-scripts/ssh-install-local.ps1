$msiPath = "C:\LabApps\installers\openssh.msi"

if (-not (Test-Path $msiPath)) {
    Write-Host "ERROR: OpenSSH MSI not found at $msiPath"
    Write-Host "Expected the template to have this file pre-staged."
    [Environment]::Exit(1)
}

Write-Host "==> Installing OpenSSH from pre-staged MSI"
Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet /norestart" -Wait

Start-Sleep -Seconds 5

Write-Host "==> Configuring sshd"
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service sshd -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

Start-Sleep -Seconds 3

$svc = Get-Service sshd -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Service: $($svc.Status) ($($svc.StartType))"
} else {
    Write-Host "Service: NOT FOUND"
}
$listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 22 }
Write-Host "Port 22: $(if ($listener) { 'LISTENING' } else { 'NOT LISTENING' })"

Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
