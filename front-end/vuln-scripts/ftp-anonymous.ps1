$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- Install IIS + FTP role features ---
Write-Step "Installing IIS FTP server features"
$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1  # 1 = workstation
if ($isServer) {
    Install-WindowsFeature -Name Web-Server,Web-Ftp-Server,Web-Ftp-Service -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
} else {
    # Client-class OS (Win10/11): use DISM
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-FTPServer,IIS-FTPSvc -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

# --- Create FTP root with some seed content ---
$ftpRoot = "C:\FTP\Public"
Write-Step "Creating FTP root at $ftpRoot"
if (-not (Test-Path $ftpRoot)) { New-Item -ItemType Directory -Path $ftpRoot -Force | Out-Null }

Set-Content "$ftpRoot\README.txt" @"
This is a legacy file drop share.
If you need to transfer files between systems, use the anonymous login.
Do NOT upload production data here - anyone on the network can read it.
"@ -Encoding ASCII

Set-Content "$ftpRoot\backup-schedule.txt" @"
Nightly backup schedule:
- FILE-01 -> /nightly/fs/
- MAIL-01 -> /nightly/mx/
- Credentials for backup agent: backupsvc / Winter2024!
"@ -Encoding ASCII

# --- Configure FTP site via IIS PowerShell module (available after feature install) ---
Import-Module WebAdministration -ErrorAction SilentlyContinue

$siteName = "LabFTP"
Write-Step "Configuring FTP site '$siteName' on port 21"
try {
    if (Get-WebSite -Name $siteName -ErrorAction SilentlyContinue) { Remove-WebSite -Name $siteName -ErrorAction SilentlyContinue }
    New-WebFtpSite -Name $siteName -Port 21 -PhysicalPath $ftpRoot -Force -ErrorAction SilentlyContinue | Out-Null

    # Allow anonymous
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled     -Value $true
    # No SSL required (deliberate weakness)
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.ssl.dataChannelPolicy    -Value 0

    # Grant anonymous Read + Write (full "legacy drop" experience)
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";users="*";permissions=3} -PSPath IIS: -Location $siteName
} catch {
    Write-Host "IIS FTP configuration failed: $($_.Exception.Message)"
}

# --- Firewall ---
Write-Step "Opening TCP/21 + passive range 40000-40100"
New-NetFirewallRule -DisplayName "Lab-FTP-21-Allow"      -Direction Inbound -Protocol TCP -LocalPort 21           -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Lab-FTP-Passive-Allow" -Direction Inbound -Protocol TCP -LocalPort 40000-40100  -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Start-Service "FTPSVC" -ErrorAction SilentlyContinue
Set-Service   "FTPSVC" -StartupType Automatic -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== ftp-anonymous complete ==="
Write-Host "FTP root  : $ftpRoot"
Write-Host "Port      : 21/TCP (anonymous read+write)"
Write-Host "SSL       : disabled"
