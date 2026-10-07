$ErrorActionPreference = "Stop"

$LabRoot       = "C:\LabApps"
$InstallersDir = Join-Path $LabRoot "installers"
$ToolsDir      = Join-Path $LabRoot "tools"
$JavaToolsDir  = Join-Path $ToolsDir "java23"
$NodeToolsDir  = Join-Path $ToolsDir "node20"
$WebGoatDir    = Join-Path $LabRoot "WebGoat"
$JuiceDir      = Join-Path $LabRoot "JuiceShop"
$VulnDir       = Join-Path $LabRoot "targets\VulnServer"
$LogsDir       = Join-Path $LabRoot "logs"
$StateDir      = Join-Path $LabRoot "state"
$ConfigPath    = Join-Path $StateDir "runtime.json"

$ProgressLog = "C:\LabApps\progress.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
    Add-Content -Path $ProgressLog -Value "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ErrorAction SilentlyContinue
}

function Get-OnlyChildDir {
    param([string]$Path)
    $dirs = Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue
    if ($dirs.Count -eq 1) { return $dirs[0].FullName }
    $match = $dirs | Where-Object { Test-Path (Join-Path $_.FullName "bin\java.exe") -or Test-Path (Join-Path $_.FullName "node.exe") -or Test-Path (Join-Path $_.FullName "package.json") } | Select-Object -First 1
    if ($match) { return $match.FullName }
    return $null
}

# Create dirs
foreach ($d in @($LogsDir, $StateDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Verify downloads exist
$javaZip = Join-Path $InstallersDir "temurin23.zip"
$nodeMsi = Join-Path $InstallersDir "node.msi"
$webGoatJar = Join-Path $WebGoatDir "webgoat.jar"
$juiceZip = Join-Path $InstallersDir "juiceshop.zip"
$vulnExe = Join-Path $VulnDir "vulnserver.exe"

$missing = @()
if (-not (Test-Path $javaZip)) { $missing += "temurin23.zip" }
if (-not (Test-Path $nodeMsi)) { $missing += "node.msi" }
if (-not (Test-Path $webGoatJar)) { $missing += "webgoat.jar" }
if (-not (Test-Path $juiceZip)) { $missing += "juiceshop.zip" }
if (-not (Test-Path $vulnExe)) { $missing += "vulnserver.exe" }

if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing files - run owasp-download first:"
    $missing | ForEach-Object { Write-Host "  - $_" }
    [Environment]::Exit(1)
}

# Extract Java
$javaExe = $null
Write-Step "Extracting Java 23..."
if (-not (Test-Path "$JavaToolsDir\*")) {
    Expand-Archive -Path $javaZip -DestinationPath $JavaToolsDir -Force
}
$javaRoot = Get-OnlyChildDir -Path $JavaToolsDir
if ($javaRoot) { $javaExe = Join-Path $javaRoot "bin\java.exe" }
if (-not $javaExe -or -not (Test-Path $javaExe)) { throw "Java not found after extraction" }
Write-Host "  Java: $javaExe"

# Install Node via MSI
$nodeExe = $null
Write-Step "Installing Node.js..."
$nodeCheck = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCheck) {
    Start-Process msiexec.exe -ArgumentList "/i `"$nodeMsi`" /quiet /norestart" -Wait
    Start-Sleep -Seconds 3
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}
$nodeCheck = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCheck) {
    $nodeExe = $nodeCheck.Source
} else {
    # Check common install locations
    $candidates = @("C:\Program Files\nodejs\node.exe", "C:\Program Files (x86)\nodejs\node.exe")
    foreach ($c in $candidates) { if (Test-Path $c) { $nodeExe = $c; break } }
}
if (-not $nodeExe -or -not (Test-Path $nodeExe)) { throw "Node not found after install" }
Write-Host "  Node: $nodeExe"

# Extract Juice Shop
$juiceRoot = $null
Write-Step "Extracting Juice Shop..."
$juiceDirs = Get-ChildItem $JuiceDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "package.json") }
if (-not $juiceDirs -or $juiceDirs.Count -eq 0) {
    Expand-Archive -Path $juiceZip -DestinationPath $JuiceDir -Force
    $juiceDirs = Get-ChildItem $JuiceDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "package.json") }
}
if ($juiceDirs) { $juiceRoot = $juiceDirs[0].FullName }
if (-not $juiceRoot) { throw "Juice Shop not found after extraction" }
Write-Host "  Juice Shop: $juiceRoot"

# Firewall rules
Write-Step "Adding firewall rules"
foreach ($rule in @(@{Name="WebGoat 8080";Port=8080}, @{Name="Juice Shop 3000";Port=3000}, @{Name="VulnServer 9999";Port=9999})) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rule.Port | Out-Null
    }
}

# Save config
$config = [pscustomobject]@{
    JavaExe       = $javaExe
    NodeExe       = $nodeExe
    WebGoatJar    = $webGoatJar
    JuiceRoot     = $juiceRoot
    VulnServerExe = $vulnExe
}
$config | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8

Write-Host ""
Write-Host "=== Setup Complete ==="
Write-Host "Java:       $javaExe"
Write-Host "Node:       $nodeExe"
Write-Host "WebGoat:    $webGoatJar"
Write-Host "JuiceShop:  $juiceRoot"
Write-Host "VulnServer: $vulnExe"
Write-Host ""
Write-Host "Next: Run the 'owasp-start' script to launch all services."
