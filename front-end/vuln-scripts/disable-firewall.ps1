Write-Host "==> Disabling Windows Firewall (all profiles)"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-Host "==> Enabling ICMP (ping)"
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow >$null 2>&1
Write-Host ""
Write-Host "=== Firewall Disabled ==="
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize
