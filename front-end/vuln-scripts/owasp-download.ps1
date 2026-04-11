$ErrorActionPreference = "Stop"

$LabRoot       = "C:\LabApps"
$InstallersDir = Join-Path $LabRoot "installers"
$ToolsDir      = Join-Path $LabRoot "tools"
$JavaToolsDir  = Join-Path $ToolsDir "java23"
$NodeToolsDir  = Join-Path $ToolsDir "node20"
$WebGoatDir    = Join-Path $LabRoot "WebGoat"
$JuiceDir      = Join-Path $LabRoot "JuiceShop"
$TargetsDir    = Join-Path $LabRoot "targets"
$VulnDir       = Join-Path $TargetsDir "VulnServer"

$ProgressLog = "C:\LabApps\progress.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
    # Also write to progress log so external polling can track
    Add-Content -Path $ProgressLog -Value "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ErrorAction SilentlyContinue
}

# Clear progress log
if (Test-Path $ProgressLog) { Remove-Item $ProgressLog -Force }
Write-Step "Starting OWASP download script"

# Create all directories
foreach ($d in @($LabRoot, $InstallersDir, $ToolsDir, $JavaToolsDir, $NodeToolsDir, $WebGoatDir, $JuiceDir, $TargetsDir, $VulnDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$javaZip = Join-Path $InstallersDir "temurin23.zip"
$nodeZip = Join-Path $InstallersDir "node20.zip"

# Download Java 23
if (-not (Test-Path $javaZip)) {
    Write-Step "Downloading Temurin JDK 23 (~200MB)..."
    Invoke-WebRequest -Uri "https://api.adoptium.net/v3/binary/latest/23/ga/windows/x64/jdk/hotspot/normal/eclipse" -OutFile $javaZip -UseBasicParsing
    Write-Host "  Downloaded: $([math]::Round((Get-Item $javaZip).Length / 1MB, 1)) MB"
} else {
    Write-Host "==> Java 23 already downloaded"
}

# Download Node.js 20
if (-not (Test-Path $nodeZip)) {
    Write-Step "Downloading Node.js 20 (~30MB)..."
    Invoke-WebRequest -Uri "https://nodejs.org/dist/v20.19.2/node-v20.19.2-win-x64.zip" -OutFile $nodeZip -UseBasicParsing
    Write-Host "  Downloaded: $([math]::Round((Get-Item $nodeZip).Length / 1MB, 1)) MB"
} else {
    Write-Host "==> Node.js 20 already downloaded"
}

# Download WebGoat
$webGoatJar = Join-Path $WebGoatDir "webgoat.jar"
if (-not (Test-Path $webGoatJar)) {
    Write-Step "Resolving latest WebGoat release..."
    $wgRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/WebGoat/WebGoat/releases/latest"
    $wgAsset = $wgRelease.assets | Where-Object { $_.name -match '^webgoat-.*\.jar$' } | Select-Object -First 1
    if (-not $wgAsset) { throw "Could not find WebGoat JAR in latest release" }
    Write-Step "Downloading WebGoat ($($wgAsset.name), ~100MB)..."
    Invoke-WebRequest -Uri $wgAsset.browser_download_url -OutFile $webGoatJar -UseBasicParsing
    Write-Host "  Downloaded: $([math]::Round((Get-Item $webGoatJar).Length / 1MB, 1)) MB"
} else {
    Write-Host "==> WebGoat already downloaded"
}

# Download Juice Shop
$juiceZip = Join-Path $InstallersDir "juiceshop.zip"
if (-not (Test-Path $juiceZip)) {
    Write-Step "Resolving latest Juice Shop release..."
    $jsRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/juice-shop/juice-shop/releases/latest"
    $jsAsset = $jsRelease.assets | Where-Object { $_.name -match 'node20_win32_x64\.zip$' } | Select-Object -First 1
    if (-not $jsAsset) { throw "Could not find Juice Shop Windows build in latest release" }
    Write-Step "Downloading Juice Shop ($($jsAsset.name), ~150MB)..."
    Invoke-WebRequest -Uri $jsAsset.browser_download_url -OutFile $juiceZip -UseBasicParsing
    Write-Host "  Downloaded: $([math]::Round((Get-Item $juiceZip).Length / 1MB, 1)) MB"
} else {
    Write-Host "==> Juice Shop already downloaded"
}

# Download VulnServer
$vulnExe = Join-Path $VulnDir "vulnserver.exe"
$vulnDll = Join-Path $VulnDir "essfunc.dll"
if (-not (Test-Path $vulnExe)) {
    Write-Step "Downloading VulnServer..."
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stephenbradshaw/vulnserver/master/vulnserver.exe" -OutFile $vulnExe -UseBasicParsing
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stephenbradshaw/vulnserver/master/essfunc.dll" -OutFile $vulnDll -UseBasicParsing
} else {
    Write-Host "==> VulnServer already downloaded"
}

Write-Host ""
Write-Host "=== All Downloads Complete ==="
Write-Host "Files:"
Get-ChildItem $InstallersDir -File -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.Name) ($([math]::Round($_.Length / 1MB, 1)) MB)" }
Get-ChildItem $WebGoatDir -File -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.Name) ($([math]::Round($_.Length / 1MB, 1)) MB)" }
Get-ChildItem $VulnDir -File -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.Name) ($([math]::Round($_.Length / 1MB, 1)) MB)" }
Write-Host ""
Write-Host "Next: Run the 'owasp-setup' script to extract and configure services."
