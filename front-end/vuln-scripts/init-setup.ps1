$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- Execution policy (so dependent scripts run without prompts) ---
Write-Step "Setting execution policy to Bypass for CurrentUser and LocalMachine"
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
Set-ExecutionPolicy -Scope CurrentUser  -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue

# --- Lab directory tree used by other scripts ---
Write-Step "Creating C:\Lab working directories"
foreach ($dir in @("C:\Lab","C:\Lab\logs","C:\Lab\artifacts","C:\Lab\tools","C:\Lab\loot","C:\LabApps","C:\LabShare")) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# --- Set network profile to Private (lets SMB/WinRM/RDP firewall rules apply) ---
Write-Step "Setting all network profiles to Private"
Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.NetworkCategory -ne "Private") {
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue
    }
}

# --- Allow ICMP echo (ping) so students can enumerate ---
Write-Step "Enabling ICMPv4 echo-request in firewall"
Get-NetFirewallRule -Name "FPS-ICMP4-ERQ-In" -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Lab-ICMP-Allow-In" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# --- High-performance power plan (keeps VMs responsive for live demos) ---
Write-Step "Switching to High Performance power plan"
try { powercfg -setactive SCHEME_MIN 2>$null } catch {}

# --- Stamp a lab marker so students can find the environment build info ---
Write-Step "Writing C:\Lab\lab-info.txt"
$info = @"
Lab Environment
---------------
Built       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Hostname    : $env:COMPUTERNAME
OS Version  : $((Get-CimInstance Win32_OperatingSystem).Caption)
Arch        : $env:PROCESSOR_ARCHITECTURE
Admin User  : Administrator
Contact     : support@internal.lab
"@
Set-Content "C:\Lab\lab-info.txt" $info -Encoding UTF8

# --- Create a dedicated non-privileged student account used across lab scripts ---
Write-Step "Ensuring student accounts exist"
$pw = ConvertTo-SecureString "LabStudent!" -AsPlainText -Force
$accounts = @(
    @{ Name = "student";  FullName = "Lab Student";     Group = "Users" },
    @{ Name = "svcbackup"; FullName = "Backup Service"; Group = "Backup Operators" }
)
foreach ($acct in $accounts) {
    $existing = Get-LocalUser -Name $acct.Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-LocalUser -Name $acct.Name -Password $pw -FullName $acct.FullName -Description "Lab account" -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction SilentlyContinue | Out-Null
        Add-LocalGroupMember -Group $acct.Group -Member $acct.Name -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "=== init-setup complete ==="
Write-Host "Lab tree : C:\Lab, C:\LabApps, C:\LabShare"
Write-Host "Accounts : student / svcbackup (password LabStudent!)"
Write-Host "ICMP     : allowed"
