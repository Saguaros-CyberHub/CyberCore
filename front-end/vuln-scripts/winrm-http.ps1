$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- Enable WinRM service + create HTTP listener ---
Write-Step "Bootstrapping WinRM (Enable-PSRemoting -SkipNetworkProfileCheck)"
Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue | Out-Null

Write-Step "Ensuring HTTP listener exists on 5985"
$listeners = & winrm enumerate winrm/config/Listener 2>$null
if ($LASTEXITCODE -ne 0 -or -not ($listeners -match "Transport = HTTP")) {
    & winrm create winrm/config/Listener?Address=*+Transport=HTTP 2>$null | Out-Null
}

# --- Weaken: allow unencrypted + basic auth (makes CrackMapExec-style auth trivially demonstrable) ---
Write-Step "Enabling unencrypted transport + basic auth (lab weakness)"
& winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>$null | Out-Null
& winrm set winrm/config/service/auth '@{Basic="true"}'        2>$null | Out-Null
& winrm set winrm/config/client/auth  '@{Basic="true"}'        2>$null | Out-Null
& winrm set winrm/config/client '@{AllowUnencrypted="true"}'   2>$null | Out-Null
& winrm set winrm/config/client '@{TrustedHosts="*"}'          2>$null | Out-Null

# --- Firewall rules ---
Write-Step "Opening 5985/TCP (WinRM HTTP) in firewall"
New-NetFirewallRule -DisplayName "Lab-WinRM-5985-Allow" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# --- Make sure WinRM service is automatic + started ---
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name WinRM -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== winrm-http complete ==="
Write-Host "HTTP listener : 5985/TCP"
Write-Host "Basic auth    : ON"
Write-Host "Unencrypted   : ON"
Write-Host "TrustedHosts  : *"
