Write-Host "==> Configuring SSH"
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service sshd -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
Write-Host "==> SSH Status:"
Get-Service sshd | Select-Object Status, StartType | Format-Table -AutoSize
$listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 22 }
Write-Host "Port 22: $(if ($listener) { 'LISTENING' } else { 'NOT LISTENING' })"
