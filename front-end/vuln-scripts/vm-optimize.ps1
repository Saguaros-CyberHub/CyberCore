Write-Host "==> Optimizing Windows VM for lab performance"

# Disable Defender real-time (massive disk I/O improvement)
Write-Host "  Disabling Defender real-time monitoring..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
} catch { Write-Host "  (Defender settings may require tamper protection disabled)" }

# Disable Windows Search indexing
Write-Host "  Disabling Windows Search..."
Stop-Service WSearch -Force -ErrorAction SilentlyContinue
Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue

# Disable SysMain/Superfetch
Write-Host "  Disabling SysMain..."
Stop-Service SysMain -Force -ErrorAction SilentlyContinue
Set-Service SysMain -StartupType Disabled -ErrorAction SilentlyContinue

# Disable Windows Update
Write-Host "  Disabling Windows Update..."
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

# Disable tips, suggestions, telemetry
Write-Host "  Disabling tips and telemetry..."
Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue

# Disable visual effects
Write-Host "  Disabling visual effects..."
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

# Disable hibernation (frees disk space)
Write-Host "  Disabling hibernation..."
powercfg /hibernate off 2>$null

# Set power plan to high performance
Write-Host "  Setting high performance power plan..."
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null

# Clear temp files
Write-Host "  Clearing temp files..."
Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== VM Optimization Complete ==="
Write-Host "Disabled: Defender, Search, SysMain, Updates, Telemetry, Visual Effects"
Write-Host "Enabled: High Performance power plan"
