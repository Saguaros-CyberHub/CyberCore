$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline FTP: IIS FTP on port 21 with authentication required (NO anonymous),
# SSL policy set to require SSL for both control + data channels. Counterpart
# to ftp-anonymous (vulnerable).

Write-Step "Installing IIS + FTP features"
$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
if ($isServer) {
    Install-WindowsFeature -Name Web-Server,Web-Ftp-Server,Web-Ftp-Service -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
} else {
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-FTPServer,IIS-FTPSvc -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

$ftpRoot = "C:\FTP\Shared"
Write-Step "Creating FTP root at $ftpRoot"
if (-not (Test-Path $ftpRoot)) { New-Item -Path $ftpRoot -ItemType Directory -Force | Out-Null }

Set-Content "$ftpRoot\README.txt" @"
Authenticated FTP share.
Contact IT for credentials. Anonymous access is not permitted.
"@ -Encoding ASCII

# Self-signed cert for FTPS
Write-Step "Creating self-signed cert for FTPS"
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=$env:COMPUTERNAME-ftp" } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -DnsName "$env:COMPUTERNAME-ftp" -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -ErrorAction SilentlyContinue
}

Import-Module WebAdministration -ErrorAction SilentlyContinue

$siteName = "LabFTP"
Write-Step "Configuring FTP site '$siteName' on port 21 (authenticated, SSL required)"
try {
    if (Get-WebSite -Name $siteName -ErrorAction SilentlyContinue) { Remove-WebSite -Name $siteName -ErrorAction SilentlyContinue }
    New-WebFtpSite -Name $siteName -Port 21 -PhysicalPath $ftpRoot -Force -ErrorAction SilentlyContinue | Out-Null

    # Authenticated only -- anonymous DISABLED
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled     -Value $true

    # Require SSL for both channels (policy=1 == SslRequire)
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value 1
    Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.ssl.dataChannelPolicy    -Value 1
    if ($cert) {
        Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.ssl.serverCertHash -Value $cert.Thumbprint
    }

    # Authorize domain users / local Users group for read; admins full
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="Users";permissions=1} -PSPath IIS: -Location $siteName -ErrorAction SilentlyContinue
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="Administrators";permissions=3} -PSPath IIS: -Location $siteName -ErrorAction SilentlyContinue
} catch {
    Write-Host "IIS FTP configuration failed: $($_.Exception.Message)"
}

Write-Step "Opening TCP/21 + passive range 40000-40100"
New-NetFirewallRule -DisplayName "Lab-FTP-21-Allow"      -Direction Inbound -Protocol TCP -LocalPort 21          -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Lab-FTP-Passive-Allow" -Direction Inbound -Protocol TCP -LocalPort 40000-40100 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Start-Service "FTPSVC" -ErrorAction SilentlyContinue
Set-Service   "FTPSVC" -StartupType Automatic -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== ftp-baseline complete ==="
Write-Host "Anonymous  : disabled"
Write-Host "Basic auth : required"
Write-Host "SSL        : required (self-signed cert)"
Write-Host "Port       : 21/TCP"
