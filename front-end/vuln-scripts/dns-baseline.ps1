$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline DNS: install DNS Server role, configure it to forward upstream,
# open TCP+UDP 53. Intended for a standalone Windows Server (DCs already
# bundle DNS via Install-ADDSForest; this baseline is for a plain DNS host).
# Works on Windows Server only -- DNS Server role is not available on client SKUs.

$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
if (-not $isServer) {
    Write-Host "DNS Server role is Server-only -- this VM is a client SKU. Skipping."
    Write-Host "If you need DNS on a client, use a forwarder (hosts file / Unbound) instead."
    [Environment]::Exit(0)
}

Write-Step "Installing DNS Server role"
Install-WindowsFeature -Name DNS -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null

Write-Step "Configuring upstream forwarders (1.1.1.1, 8.8.8.8)"
try {
    Set-DnsServerForwarder -IPAddress "1.1.1.1","8.8.8.8" -UseRootHint $true -ErrorAction SilentlyContinue
} catch { Write-Host "Forwarder config failed: $($_.Exception.Message)" }

Write-Step "Opening TCP+UDP 53 in firewall"
New-NetFirewallRule -DisplayName "Lab-DNS-53-TCP-Allow" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Lab-DNS-53-UDP-Allow" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Set-Service -Name DNS -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name DNS -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== dns-baseline complete ==="
Write-Host "Role       : DNS Server"
Write-Host "Forwarders : 1.1.1.1, 8.8.8.8 (+ root hints)"
Write-Host "Ports      : 53/TCP + 53/UDP"
