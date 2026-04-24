$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- Add broad path exclusions so lab artifacts + common tool drop paths don't get quarantined ---
Write-Step "Adding Defender path exclusions for lab folders"
$excludePaths = @(
    "C:\Lab",
    "C:\LabApps",
    "C:\LabShare",
    "C:\Tools",
    "C:\Scripts",
    "C:\Users\Public\Downloads",
    "C:\Users\student\Downloads"
)
foreach ($p in $excludePaths) {
    Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
}

# --- Exclude common extension patterns used in CTF exercises ---
Write-Step "Adding file-extension exclusions"
foreach ($ext in @(".ps1",".hta",".bat",".cmd",".py",".exe")) {
    Add-MpPreference -ExclusionExtension $ext -ErrorAction SilentlyContinue
}

# --- Exclude processes commonly invoked in post-exploitation ---
Write-Step "Adding process exclusions"
foreach ($proc in @("powershell.exe","cmd.exe","cscript.exe","wscript.exe","mshta.exe","rundll32.exe")) {
    Add-MpPreference -ExclusionProcess $proc -ErrorAction SilentlyContinue
}

# --- Lower the bar: disable cloud-delivered protection + sample submission ---
Write-Step "Disabling cloud protection + auto sample submission"
Set-MpPreference -MAPSReporting Disabled                 -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent NeverSend         -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $true        -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true            -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true        -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true            -ErrorAction SilentlyContinue
Set-MpPreference -DisableArchiveScanning $true           -ErrorAction SilentlyContinue

# --- Shrink the reputation service's effect: Pua disabled (so would-be PUAs run) ---
Set-MpPreference -PUAProtection Disabled -ErrorAction SilentlyContinue

# --- AMSI off via registry (blue-team can still detect; this is deliberate) ---
Write-Step "Disabling AMSI provider via registry"
$amsi = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (-not (Test-Path $amsi)) { New-Item -Path $amsi -Force | Out-Null }
New-ItemProperty -Path $amsi -Name "TamperProtection" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host ""
Write-Host "=== defender-weaken complete ==="
Write-Host "Paths excluded      : $($excludePaths -join ', ')"
Write-Host "Real-time           : disabled"
Write-Host "Behavior monitor    : disabled"
Write-Host "Script scan         : disabled"
Write-Host "Cloud + sampling    : disabled"
