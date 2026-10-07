$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline HTTP: install IIS, serve a plain corporate landing page on port 80.
# No vulnerable apps (WebGoat / Juice Shop / VulnServer), no FTP, no anonymous
# shares. Counterpart to iis-config (vulnerable) and win-install-480-services
# (composite vulnerable lab).

Write-Step "Installing IIS web server role"
$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
if ($isServer) {
    Install-WindowsFeature -Name Web-Server,Web-Common-Http,Web-Default-Doc,Web-Static-Content,Web-Http-Logging,Web-Filtering -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
} else {
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-CommonHttpFeatures,IIS-DefaultDocument,IIS-StaticContent,IIS-HttpLogging -NoRestart -All -ErrorAction SilentlyContinue | Out-Null
}

Write-Step "Creating placeholder corporate landing page"
$wwwroot = "C:\inetpub\wwwroot"
if (-not (Test-Path $wwwroot)) { New-Item -Path $wwwroot -ItemType Directory -Force | Out-Null }

# Clear the stock IIS welcome page
Remove-Item "$wwwroot\iisstart.htm" -Force -ErrorAction SilentlyContinue
Remove-Item "$wwwroot\iisstart.png" -Force -ErrorAction SilentlyContinue

$landingPage = @"
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Internal Portal</title>
<style>
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f2f5; color: #333; margin: 0; }
.nav { background: #0a2540; color: #fff; padding: 16px 32px; }
.nav h1 { font-size: 18px; font-weight: 600; margin: 0; }
.wrap { max-width: 780px; margin: 40px auto; padding: 0 20px; }
.card { background: #fff; border-radius: 12px; padding: 28px; margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,.08); border: 1px solid #e8e8e8; }
.card h2 { font-size: 15px; color: #0a2540; margin: 0 0 12px; padding-bottom: 10px; border-bottom: 1px solid #eee; }
.card p { line-height: 1.65; color: #555; margin: 0 0 10px; font-size: 14px; }
.footer { text-align: center; color: #aaa; font-size: 12px; padding: 30px 0; }
</style>
</head><body>
<div class="nav"><h1>Internal Portal</h1></div>
<div class="wrap">
  <div class="card">
    <h2>Staff Resources</h2>
    <p>For access to internal systems, contact IT at ext. 4200 or support@internal.lab.</p>
    <p>Password resets, software requests, and hardware issues should be submitted via the ticketing portal.</p>
  </div>
  <div class="card">
    <h2>Service Status</h2>
    <p>All services are operating normally. Scheduled maintenance windows are posted in the IT calendar.</p>
  </div>
</div>
<div class="footer">Internal IT Portal &copy; 2024 | IIS/10.0</div>
</body></html>
"@
Set-Content -Path "$wwwroot\index.html" -Value $landingPage -Encoding UTF8

Write-Step "Opening TCP/80 in firewall"
Enable-NetFirewallRule -DisplayGroup "World Wide Web Services (HTTP)" -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Lab-HTTP-80-Allow" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Write-Step "Starting W3SVC"
Set-Service -Name W3SVC -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name W3SVC -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== http-baseline complete ==="
Write-Host "Site     : http://$env:COMPUTERNAME/"
Write-Host "Port     : 80/TCP"
Write-Host "Content  : corporate landing page (no vulnerable apps)"
