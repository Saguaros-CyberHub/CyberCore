param(
    [switch]$Setup,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Restart
)

$ErrorActionPreference = "Stop"

# ═══════════════════════════════════════════════════════════════
# CONFIG — Change this to your clinic-app server IP
# ═══════════════════════════════════════════════════════════════
$AssetServer = "http://localhost:3000/vuln-assets"

$LabRoot       = "C:\LabApps"
$InstallersDir = Join-Path $LabRoot "installers"
$ToolsDir      = Join-Path $LabRoot "tools"
$JavaToolsDir  = Join-Path $ToolsDir "java23"
$NodeToolsDir  = Join-Path $ToolsDir "node20"
$WebGoatDir    = Join-Path $LabRoot "WebGoat"
$JuiceDir      = Join-Path $LabRoot "JuiceShop"
$TargetsDir    = Join-Path $LabRoot "targets"
$VulnDir       = Join-Path $TargetsDir "VulnServer"
$LogsDir       = Join-Path $LabRoot "logs"
$StateDir      = Join-Path $LabRoot "state"
$ConfigPath    = Join-Path $StateDir "runtime.json"

$WebGoatPort = 8080
$JuicePort   = 3000
$VulnPort    = 9999

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-Directories {
    New-Item -ItemType Directory -Force -Path `
        $LabRoot, $InstallersDir, $ToolsDir, $JavaToolsDir, $NodeToolsDir,
        $WebGoatDir, $JuiceDir, $TargetsDir, $VulnDir, $LogsDir, $StateDir | Out-Null
}

function Save-Config {
    param($Object)
    $Object | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
}

function Load-Config {
    if (-not (Test-Path $ConfigPath)) { throw "No runtime config found. Run -Setup first." }
    Get-Content $ConfigPath -Raw | ConvertFrom-Json
}

function Get-OnlyChildDirectory {
    param([string]$Path)
    $dirs = Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue
    if ($dirs.Count -eq 1) { return $dirs[0].FullName }
    if ($dirs.Count -gt 1) {
        $match = $dirs | Where-Object {
            Test-Path (Join-Path $_.FullName "bin\java.exe") -or
            Test-Path (Join-Path $_.FullName "node.exe") -or
            Test-Path (Join-Path $_.FullName "package.json")
        } | Select-Object -First 1
        if ($match) { return $match.FullName }
    }
    return $null
}

function Stop-All {
    foreach ($port in @(8080, 9091, 3000, 9999)) {
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $port } |
            ForEach-Object {
                if ($_.OwningProcess -and $_.OwningProcess -ne 0 -and $_.OwningProcess -ne 4) {
                    try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction Stop } catch {}
                }
            }
    }
}

function Add-FwRule {
    param([string]$Name, [int]$Port)
    if (-not (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
    }
}

# ═══════════════════════════════════════════════════════════════
# SETUP — Download from local asset server, extract, configure
# ═══════════════════════════════════════════════════════════════
function Setup-Lab {
    Ensure-Directories

    $javaZip = Join-Path $InstallersDir "temurin23.zip"
    $nodeZip = Join-Path $InstallersDir "node20.zip"
    $webGoatJar = Join-Path $WebGoatDir "webgoat.jar"
    $juiceZip = Join-Path $InstallersDir "juiceshop.zip"
    $vulnExe = Join-Path $VulnDir "vulnserver.exe"
    $vulnDll = Join-Path $VulnDir "essfunc.dll"

    # Download from local asset server (fast, no internet needed)
    Write-Step "Downloading assets from $AssetServer"

    if (-not (Test-Path $javaZip)) {
        Write-Step "Downloading Java 23..."
        Invoke-WebRequest -Uri "$AssetServer/temurin23.zip" -OutFile $javaZip -TimeoutSec 120
    }
    if (-not (Test-Path $nodeZip)) {
        Write-Step "Downloading Node.js 20..."
        Invoke-WebRequest -Uri "$AssetServer/node20.zip" -OutFile $nodeZip -TimeoutSec 60
    }
    if (-not (Test-Path $webGoatJar)) {
        Write-Step "Downloading WebGoat..."
        Invoke-WebRequest -Uri "$AssetServer/webgoat.jar" -OutFile $webGoatJar -TimeoutSec 120
    }
    if (-not (Test-Path $juiceZip)) {
        Write-Step "Downloading Juice Shop..."
        Invoke-WebRequest -Uri "$AssetServer/juiceshop.zip" -OutFile $juiceZip -TimeoutSec 120
    }
    if (-not (Test-Path $vulnExe)) {
        Write-Step "Downloading VulnServer..."
        Invoke-WebRequest -Uri "$AssetServer/vulnserver.exe" -OutFile $vulnExe -TimeoutSec 30
        Invoke-WebRequest -Uri "$AssetServer/essfunc.dll" -OutFile $vulnDll -TimeoutSec 30
    }

    # Extract Java
    $javaExe = Join-Path $JavaToolsDir "bin\java.exe"
    if (-not (Test-Path $javaExe)) {
        Write-Step "Extracting Java 23..."
        if (Test-Path $JavaToolsDir) { Remove-Item $JavaToolsDir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $JavaToolsDir | Out-Null
        Expand-Archive -Path $javaZip -DestinationPath $JavaToolsDir -Force
        $javaRoot = Get-OnlyChildDirectory -Path $JavaToolsDir
        if ($javaRoot) { $javaExe = Join-Path $javaRoot "bin\java.exe" }
        if (-not (Test-Path $javaExe)) { throw "Java not found after extraction" }
    }

    # Extract Node
    $nodeExe = Join-Path $NodeToolsDir "node.exe"
    if (-not (Test-Path $nodeExe)) {
        Write-Step "Extracting Node.js 20..."
        if (Test-Path $NodeToolsDir) { Remove-Item $NodeToolsDir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $NodeToolsDir | Out-Null
        Expand-Archive -Path $nodeZip -DestinationPath $NodeToolsDir -Force
        $nodeRoot = Get-OnlyChildDirectory -Path $NodeToolsDir
        if ($nodeRoot) {
            Get-ChildItem $nodeRoot -Force | ForEach-Object { Move-Item -Path $_.FullName -Destination $NodeToolsDir -Force }
            Remove-Item $nodeRoot -Recurse -Force
        }
        $nodeExe = Join-Path $NodeToolsDir "node.exe"
        if (-not (Test-Path $nodeExe)) { throw "Node not found after extraction" }
    }

    # Extract Juice Shop
    $juiceRoot = $null
    $juiceDirs = Get-ChildItem $JuiceDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "package.json") }
    if ($juiceDirs) {
        $juiceRoot = $juiceDirs[0].FullName
    } else {
        Write-Step "Extracting Juice Shop..."
        Expand-Archive -Path $juiceZip -DestinationPath $JuiceDir -Force
        $juiceDirs = Get-ChildItem $JuiceDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "package.json") }
        if ($juiceDirs) { $juiceRoot = $juiceDirs[0].FullName }
        if (-not $juiceRoot) { throw "Juice Shop not found after extraction" }
    }

    # Firewall rules
    Add-FwRule -Name "WebGoat 8080" -Port $WebGoatPort
    Add-FwRule -Name "Juice Shop 3000" -Port $JuicePort
    Add-FwRule -Name "VulnServer 9999" -Port $VulnPort

    # Save config
    $config = [pscustomobject]@{
        JavaExe       = $javaExe
        NodeExe       = $nodeExe
        WebGoatJar    = $webGoatJar
        JuiceRoot     = $juiceRoot
        VulnServerExe = $vulnExe
    }
    Save-Config $config

    Write-Step "Setup complete"
    Write-Host "Java:       $($config.JavaExe)"
    Write-Host "Node:       $($config.NodeExe)"
    Write-Host "WebGoat:    $($config.WebGoatJar)"
    Write-Host "JuiceShop:  $($config.JuiceRoot)"
    Write-Host "VulnServer: $($config.VulnServerExe)"
}

# ═══════════════════════════════════════════════════════════════
# START — Launch all services
# ═══════════════════════════════════════════════════════════════
function Start-Lab {
    Ensure-Directories
    $config = Load-Config

    if (-not (Test-Path $config.JavaExe)) { throw "Java not found. Run -Setup first." }
    if (-not (Test-Path $config.NodeExe)) { throw "Node not found. Run -Setup first." }
    if (-not (Test-Path $config.WebGoatJar)) { throw "WebGoat not found. Run -Setup first." }
    if (-not (Test-Path $config.VulnServerExe)) { throw "VulnServer not found. Run -Setup first." }

    Stop-All

    # WebGoat launcher
    $wgLauncher = Join-Path $StateDir "start_webgoat.ps1"
    Set-Content $wgLauncher @"
`$ErrorActionPreference = 'Stop'
& '$($config.JavaExe)' -jar '$($config.WebGoatJar)' --webgoat.port=$WebGoatPort --webwolf.port=9091 *>> '$LogsDir\webgoat.log'
"@ -Encoding UTF8

    # Juice Shop launcher
    $jsLauncher = Join-Path $StateDir "start_juiceshop.ps1"
    Set-Content $jsLauncher @"
`$ErrorActionPreference = 'Stop'
Set-Location '$($config.JuiceRoot)'
& '$($config.NodeExe)' build/app *>> '$LogsDir\juiceshop.log'
"@ -Encoding UTF8

    # VulnServer launcher
    $vsLauncher = Join-Path $StateDir "start_vulnserver.ps1"
    Set-Content $vsLauncher @"
`$ErrorActionPreference = 'Stop'
Set-Location '$VulnDir'
& '$($config.VulnServerExe)' $VulnPort *>> '$LogsDir\vulnserver.log'
"@ -Encoding UTF8

    Write-Step "Starting WebGoat on port $WebGoatPort"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$wgLauncher -WindowStyle Hidden

    Write-Step "Starting Juice Shop on port $JuicePort"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$jsLauncher -WindowStyle Hidden

    Write-Step "Starting VulnServer on port $VulnPort"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$vsLauncher -WindowStyle Hidden

    Write-Step "Waiting for services to start..."
    Start-Sleep -Seconds 15

    # Check ports
    $wg = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $WebGoatPort }
    $js = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $JuicePort }
    $vs = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $VulnPort }

    Write-Host ""
    Write-Host "=== OWASP Lab Services ==="
    Write-Host "WebGoat 8080:    $(if ($wg) { 'LISTENING' } else { 'NOT YET (Java startup is slow, wait 30s)' })"
    Write-Host "Juice Shop 3000: $(if ($js) { 'LISTENING' } else { 'NOT YET (wait 15s)' })"
    Write-Host "VulnServer 9999: $(if ($vs) { 'LISTENING' } else { 'NOT YET' })"
}

# ═══════════════════════════════════════════════════════════════
# STOP
# ═══════════════════════════════════════════════════════════════
function Stop-Lab {
    Write-Step "Stopping all lab services"
    Stop-All
    Write-Host "Services stopped."
}

# ═══════════════════════════════════════════════════════════════
# ENTRY
# ═══════════════════════════════════════════════════════════════
$flagCount = @($Setup, $Start, $Stop, $Restart | Where-Object { $_ }).Count

if ($flagCount -eq 0) {
    Write-Host "Usage: -Setup, -Start, -Stop, -Restart"
    Write-Host "Services: WebGoat (8080), Juice Shop (3000), VulnServer (9999)"
    [Environment]::Exit(1)
}

if ($Setup) { Setup-Lab }
if ($Start -or $Restart) {
    if ($Restart) { Stop-All }
    Start-Lab
}
if ($Stop) { Stop-Lab }

[Environment]::Exit(0)
