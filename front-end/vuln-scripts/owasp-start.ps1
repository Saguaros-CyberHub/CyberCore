$ErrorActionPreference = "Stop"

$LabRoot    = "C:\LabApps"
$StateDir   = Join-Path $LabRoot "state"
$LogsDir    = Join-Path $LabRoot "logs"
$VulnDir    = Join-Path $LabRoot "targets\VulnServer"
$ConfigPath = Join-Path $StateDir "runtime.json"

$ProgressLog = "C:\LabApps\progress.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
    Add-Content -Path $ProgressLog -Value "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ErrorAction SilentlyContinue
}

# Load config
if (-not (Test-Path $ConfigPath)) { throw "No config found. Run owasp-setup first." }
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if (-not (Test-Path $config.JavaExe)) { throw "Java not found at $($config.JavaExe)" }
$nodeExe = $config.NodeExe
if (-not (Test-Path $nodeExe)) {
    # Try system PATH (installed via MSI)
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCmd) { $nodeExe = $nodeCmd.Source } else {
        if (Test-Path "C:\Program Files\nodejs\node.exe") { $nodeExe = "C:\Program Files\nodejs\node.exe" }
    }
}
if (-not (Test-Path $nodeExe)) { throw "Node not found" }
$config | Add-Member -NotePropertyName NodeExe -NotePropertyValue $nodeExe -Force -ErrorAction SilentlyContinue
if (-not (Test-Path $config.WebGoatJar)) { throw "WebGoat not found at $($config.WebGoatJar)" }
if (-not (Test-Path $config.VulnServerExe)) { throw "VulnServer not found at $($config.VulnServerExe)" }

if (-not (Test-Path $LogsDir)) { New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null }

# Stop any existing processes
Write-Step "Stopping existing services"
foreach ($port in @(8080, 9091, 3000, 9999)) {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $port } |
        ForEach-Object {
            if ($_.OwningProcess -gt 4) {
                try { Stop-Process -Id $_.OwningProcess -Force } catch {}
            }
        }
}

# Create launchers
$wgLauncher = Join-Path $StateDir "start_webgoat.ps1"
Set-Content $wgLauncher @"
`$ErrorActionPreference = 'Stop'
& '$($config.JavaExe)' -jar '$($config.WebGoatJar)' --webgoat.port=8080 --webwolf.port=9091 *>> '$LogsDir\webgoat.log'
"@ -Encoding UTF8

$jsLauncher = Join-Path $StateDir "start_juiceshop.ps1"
Set-Content $jsLauncher @"
`$ErrorActionPreference = 'Stop'
Set-Location '$($config.JuiceRoot)'
& '$($config.NodeExe)' build/app *>> '$LogsDir\juiceshop.log'
"@ -Encoding UTF8

$vsLauncher = Join-Path $StateDir "start_vulnserver.ps1"
Set-Content $vsLauncher @"
`$ErrorActionPreference = 'Stop'
Set-Location '$VulnDir'
& '$($config.VulnServerExe)' 9999 *>> '$LogsDir\vulnserver.log'
"@ -Encoding UTF8

# Start services
Write-Step "Starting WebGoat (port 8080)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$wgLauncher -WindowStyle Hidden

Write-Step "Starting Juice Shop (port 3000)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$jsLauncher -WindowStyle Hidden

Write-Step "Starting VulnServer (port 9999)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$vsLauncher -WindowStyle Hidden

Write-Step "Waiting for services..."
Start-Sleep -Seconds 10

# Check
$wg = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 8080 }
$js = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 3000 }
$vs = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 9999 }

Write-Host ""
Write-Host "=== Services Status ==="
Write-Host "WebGoat 8080:    $(if ($wg) { 'LISTENING' } else { 'STARTING (Java is slow, wait 30-60s)' })"
Write-Host "Juice Shop 3000: $(if ($js) { 'LISTENING' } else { 'STARTING (wait 15s)' })"
Write-Host "VulnServer 9999: $(if ($vs) { 'LISTENING' } else { 'STARTING' })"
