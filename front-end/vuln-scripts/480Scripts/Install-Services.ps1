<#
.SYNOPSIS
    Installs and configures IIS (80 + 8080), FTP (21), MSSQL (1433),
    WinRM (5985), and RDP (3389) on the MedAlliance-WIN Tier 1 target.

.NOTES
    Originally assumed Windows Server 2019 with SQL Express pre-installed.
    Now also runs on Windows 11 client SKUs (25H2) for instructor testing.

    SQL configuration is OPTIONAL — if no MSSQL* service is detected, the
    SQL section is skipped but all other artifacts (IT_Docs breadcrumb that
    references the SA password, planted creds, etc.) remain intact, so
    students still have a consistent lab story.
#>

param(
    [Parameter(Mandatory=$true)][string]$WinIP,
    [switch]$SkipSQL
)

$ErrorActionPreference = "Continue"
$script:SectionFailures = @()

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][Services] $Msg"
}

# ═══════════════════════════════════════════════════════════════
#  0. SKU DETECTION + DEPLOY-CONTEXT MARKER
# ═══════════════════════════════════════════════════════════════
$script:OSInfo   = Get-CimInstance Win32_OperatingSystem
$script:IsServer = $script:OSInfo.ProductType -ne 1  # 1=workstation, 2=DC, 3=member server
$script:OSCaption = $script:OSInfo.Caption
Write-Host "[Prereq] Detected: $script:OSCaption (IsServer=$script:IsServer)"

# Persist a small marker file so the sibling scripts don't have to re-detect.
$ctxDir = "C:\ProgramData\MedAlliance"
if (-not (Test-Path $ctxDir)) { New-Item -Path $ctxDir -ItemType Directory -Force | Out-Null }
$ctxPath = Join-Path $ctxDir "deploy-context.json"
$ctx = @{
    OSCaption = $script:OSCaption
    IsServer  = $script:IsServer
    WinIP     = $WinIP
    Timestamp = (Get-Date).ToString("s")
}
$ctx | ConvertTo-Json | Set-Content -Path $ctxPath -Encoding UTF8
Write-Phase "Wrote deploy context marker: $ctxPath"

# ═══════════════════════════════════════════════════════════════
#  Helper: Install-MedFeature — branches Server vs Client feature API
# ═══════════════════════════════════════════════════════════════
# On Server SKUs: Install-WindowsFeature <ServerName> -IncludeManagementTools
# On Client SKUs: Enable-WindowsOptionalFeature -Online -FeatureName <ClientName> -NoRestart
function Install-MedFeature {
    param(
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$ClientName
    )
    try {
        if ($script:IsServer) {
            if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
                Install-WindowsFeature -Name $ServerName -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
                Write-Phase "  [Feature:Server] $ServerName enabled."
            } else {
                Write-Warning "  [Feature:Server] Install-WindowsFeature unavailable for $ServerName"
            }
        } else {
            if (Get-Command Enable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
                $state = (Get-WindowsOptionalFeature -Online -FeatureName $ClientName -ErrorAction SilentlyContinue).State
                if ($state -ne 'Enabled') {
                    Enable-WindowsOptionalFeature -Online -FeatureName $ClientName -NoRestart -All -ErrorAction SilentlyContinue | Out-Null
                    Write-Phase "  [Feature:Client] $ClientName enabled."
                } else {
                    Write-Phase "  [Feature:Client] $ClientName already enabled."
                }
            } else {
                Write-Warning "  [Feature:Client] Enable-WindowsOptionalFeature unavailable for $ClientName"
            }
        }
    } catch {
        Write-Warning "  [Feature] Could not enable $ServerName/$ClientName : $_"
    }
}

# ═══════════════════════════════════════════════════════════════
#  1. IIS + FTP FEATURE INSTALLATION
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting IIS/FTP feature install..."

    # Core IIS
    Install-MedFeature -ServerName 'Web-Server'         -ClientName 'IIS-WebServer'
    Install-MedFeature -ServerName 'Web-Common-Http'    -ClientName 'IIS-CommonHttpFeatures'
    Install-MedFeature -ServerName 'Web-Default-Doc'    -ClientName 'IIS-DefaultDocument'
    Install-MedFeature -ServerName 'Web-Dir-Browsing'   -ClientName 'IIS-DirectoryBrowsing'
    Install-MedFeature -ServerName 'Web-Http-Errors'    -ClientName 'IIS-HttpErrors'
    Install-MedFeature -ServerName 'Web-Static-Content' -ClientName 'IIS-StaticContent'
    Install-MedFeature -ServerName 'Web-Http-Logging'   -ClientName 'IIS-HttpLogging'
    Install-MedFeature -ServerName 'Web-Stat-Compression' -ClientName 'IIS-HttpCompressionStatic'
    Install-MedFeature -ServerName 'Web-Filtering'      -ClientName 'IIS-RequestFiltering'
    Install-MedFeature -ServerName 'Web-Asp-Net45'      -ClientName 'IIS-ASPNET45'
    Install-MedFeature -ServerName 'Web-Net-Ext45'      -ClientName 'IIS-NetFxExtensibility45'
    Install-MedFeature -ServerName 'Web-ISAPI-Ext'      -ClientName 'IIS-ISAPIExtensions'
    Install-MedFeature -ServerName 'Web-ISAPI-Filter'   -ClientName 'IIS-ISAPIFilter'
    Install-MedFeature -ServerName 'Web-Mgmt-Console'   -ClientName 'IIS-ManagementConsole'

    # FTP
    Install-MedFeature -ServerName 'Web-Ftp-Server'     -ClientName 'IIS-FTPServer'
    Install-MedFeature -ServerName 'Web-Ftp-Service'    -ClientName 'IIS-FTPSvc'
    Install-MedFeature -ServerName 'Web-Ftp-Ext'        -ClientName 'IIS-FTPExtensibility'

    Write-Phase "[Section] IIS/FTP features completed."
} catch {
    Write-Warning "[Section] IIS/FTP feature install failed: $_"
    $script:SectionFailures += 'IIS-Features'
}

# ═══════════════════════════════════════════════════════════════
#  2. IIS SITE CONFIGURATION (default + HealthMonitor on 8080)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting IIS site configuration..."

    if (-not (Get-Module -ListAvailable WebAdministration)) {
        Write-Warning "[IIS] WebAdministration module not available — IIS site config skipped."
        $script:SectionFailures += 'IIS-Sites'
    } else {
        Import-Module WebAdministration -ErrorAction Stop

        # ── Default site on port 80: corporate landing page ──
        $wwwroot = "C:\inetpub\wwwroot"
        if (-not (Test-Path $wwwroot)) {
            New-Item -Path $wwwroot -ItemType Directory -Force | Out-Null
        }

        # Remove default IIS pages (only if present)
        Remove-Item "$wwwroot\iisstart.htm" -Force -ErrorAction SilentlyContinue
        Remove-Item "$wwwroot\iisstart.png" -Force -ErrorAction SilentlyContinue

        $landingPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MedAlliance Health Partners</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#333}
.nav{background:#0a2540;color:#fff;padding:16px 32px;display:flex;align-items:center;gap:16px}
.nav h1{font-size:18px;font-weight:600}
.nav .tag{background:#e94560;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600}
.wrap{max-width:900px;margin:40px auto;padding:0 20px}
.card{background:#fff;border-radius:12px;padding:32px;margin-bottom:24px;
      box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e8e8e8}
.card h2{font-size:16px;color:#0a2540;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #eee}
.card p{line-height:1.7;color:#555;margin-bottom:12px}
.services{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-top:16px}
.svc{background:#f8f9fb;border:1px solid #eee;border-radius:8px;padding:16px}
.svc h3{font-size:14px;color:#0a2540;margin-bottom:4px}
.svc p{font-size:13px;color:#888;margin:0}
.svc .port{display:inline-block;background:#e8f4fd;color:#0066cc;padding:1px 8px;
           border-radius:4px;font-size:12px;font-family:monospace;margin-top:8px}
.footer{text-align:center;color:#aaa;font-size:12px;padding:40px 0}
</style>
</head>
<body>
<div class="nav">
  <h1>MedAlliance Health Partners</h1>
  <span class="tag">INTERNAL</span>
</div>
<div class="wrap">
  <div class="card">
    <h2>Internal Systems Portal</h2>
    <p>Welcome to the MedAlliance Health Partners internal network. This server provides
       centralized IT services for staff. For access issues, contact IT at ext 4200 or
       <strong>it-support@medalliance.local</strong>.</p>
  </div>
  <div class="card">
    <h2>Available Services</h2>
    <div class="services">
      <div class="svc">
        <h3>Health Monitor</h3>
        <p>System status dashboard</p>
        <span class="port">:8080</span>
      </div>
      <div class="svc">
        <h3>File Shares</h3>
        <p>Company documents (SMB)</p>
        <span class="port">:445</span>
      </div>
      <div class="svc">
        <h3>HR Database</h3>
        <p>Employee records (SQL)</p>
        <span class="port">:1433</span>
      </div>
      <div class="svc">
        <h3>FTP Logs</h3>
        <p>System log archive</p>
        <span class="port">:21</span>
      </div>
      <div class="svc">
        <h3>Remote Desktop</h3>
        <p>RDP access for staff</p>
        <span class="port">:3389</span>
      </div>
      <div class="svc">
        <h3>Remote Mgmt</h3>
        <p>WinRM for IT admins</p>
        <span class="port">:5985</span>
      </div>
    </div>
  </div>
  <div class="card">
    <h2>IT Notices</h2>
    <p><strong>2024-11-10:</strong> Scheduled maintenance completed. SQL Server backups verified.
       Please report any service interruptions to IT.</p>
    <p><strong>2024-09-15:</strong> Windows Defender real-time protection has been temporarily
       disabled due to compatibility issues with the Health Monitor agent. A fix is pending
       from the vendor. <em>— M. Chen, Network Admin</em></p>
    <p><strong>2024-08-13:</strong> Automatic Windows Updates have been paused until Q1 2025
       to prevent disruption to clinical workflows during the EMR migration.</p>
  </div>
</div>
<div class="footer">
  MedAlliance Health Partners &copy; 2024 | MEDALLIANCE-WIN | IIS/10.0
</div>
</body>
</html>
"@
        Set-Content -Path "$wwwroot\index.html" -Value $landingPage -Encoding UTF8
        Write-Phase "Default site (port 80) configured."

        # ── Health Monitor dashboard on port 8080 ──
        $monitorPath = "C:\inetpub\healthmonitor"
        if (-not (Test-Path $monitorPath)) {
            New-Item -Path $monitorPath -ItemType Directory -Force | Out-Null
        }

        $loginPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>Health Monitor — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;
     display:flex;justify-content:center;align-items:center;min-height:100vh}
.login{background:#1e293b;border-radius:12px;padding:40px;width:380px;
       box-shadow:0 4px 24px rgba(0,0,0,.4);border:1px solid #334155}
.login h2{font-size:18px;margin-bottom:8px}
.login .sub{color:#64748b;font-size:13px;margin-bottom:28px}
label{display:block;font-size:13px;color:#94a3b8;margin-bottom:4px;margin-top:16px}
input{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;
      color:#e2e8f0;border-radius:6px;font-size:14px}
input:focus{outline:none;border-color:#3b82f6}
button{width:100%;padding:12px;background:#dc2626;color:#fff;border:none;
       border-radius:6px;font-size:14px;cursor:pointer;margin-top:24px;font-weight:600}
button:hover{background:#b91c1c}
.hint{color:#475569;font-size:11px;margin-top:20px;text-align:center;line-height:1.6}
</style>
</head>
<body>
<div class="login">
  <h2>Health Monitor v3.1</h2>
  <div class="sub">MEDALLIANCE-WIN &mdash; System Dashboard</div>
  <form action="dashboard.html" method="GET">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" placeholder="admin" autocomplete="off">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;">
    <button type="submit">Sign In</button>
  </form>
  <div class="hint">
    Default credentials are documented in the IT_Docs share.<br>
    Contact IT (ext 4200) if your account is locked.
  </div>
</div>
<!-- MedAlliance Health Monitor v3.1.2 | build 2024.11.02 | ASP.NET 4.8.1 | IIS/10.0 -->
</body>
</html>
"@
        Set-Content -Path "$monitorPath\index.html" -Value $loginPage -Encoding UTF8

        $subnetRef = $WinIP -replace '\.\d+$', ''  # e.g., 192.168.10
        $dashboardPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>Health Monitor — Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0}
.topbar{background:#1e293b;padding:14px 24px;display:flex;justify-content:space-between;
        align-items:center;border-bottom:2px solid #dc2626}
.topbar h1{font-size:16px;font-weight:600}
.topbar .user{color:#64748b;font-size:13px}
.topbar .user strong{color:#e2e8f0}
.content{padding:24px;max-width:1100px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:24px}
.card{background:#1e293b;border-radius:8px;padding:20px;border:1px solid #334155}
.card .label{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:8px}
.card .value{font-size:28px;font-weight:700}
.card .detail{font-size:12px;color:#475569;margin-top:6px}
.ok{color:#22c55e}.warn{color:#eab308}.crit{color:#ef4444}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;color:#64748b;font-weight:500;
   border-bottom:1px solid #334155;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td{padding:10px 12px;border-bottom:1px solid #1e293b}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot.g{background:#22c55e}.dot.r{background:#ef4444}.dot.y{background:#eab308}
.section{margin-bottom:24px}
.section h3{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:#dc2626;
            margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #334155}
</style>
</head>
<body>
<div class="topbar">
  <h1>MedAlliance Health Monitor</h1>
  <div class="user">Signed in as <strong>admin</strong> (System Administrator)
    &nbsp;|&nbsp; <a href="index.html" style="color:#dc2626;text-decoration:none">Logout</a></div>
</div>
<div class="content">

<div class="grid">
  <div class="card"><div class="label">Uptime</div>
    <div class="value ok">47d 13h</div>
    <div class="detail">Last reboot: 2024-10-01 03:00 (scheduled)</div></div>
  <div class="card"><div class="label">CPU</div>
    <div class="value ok">23%</div>
    <div class="detail">4 vCPU | Peak: 67% at 09:15</div></div>
  <div class="card"><div class="label">Memory</div>
    <div class="value warn">78%</div>
    <div class="detail">3.1 / 4.0 GB — MSSQL: 1.8 GB</div></div>
  <div class="card"><div class="label">Disk C:</div>
    <div class="value ok">45%</div>
    <div class="detail">18 GB / 40 GB used</div></div>
</div>

<div class="card section">
<h3>Services</h3>
<table>
<tr><th>Service</th><th>Port</th><th>Status</th><th>Configuration Notes</th></tr>
<tr><td>IIS Web Server</td><td>80, 8080</td>
    <td><span class="dot g"></span>Running</td><td>Default site + Health Monitor</td></tr>
<tr><td>SQL Server 2019 Express</td><td>1433</td>
    <td><span class="dot g"></span>Running</td>
    <td>Instance: SQLEXPRESS | SA: <strong>enabled</strong> | xp_cmdshell: enabled</td></tr>
<tr><td>FTP (IIS)</td><td>21</td>
    <td><span class="dot g"></span>Running</td>
    <td>Anonymous read enabled for /logs directory</td></tr>
<tr><td>SMB File Shares</td><td>445</td>
    <td><span class="dot g"></span>Running</td>
    <td>Company_Docs, IT_Docs (guest read) | HR_Files (auth required)</td></tr>
<tr><td>Remote Desktop</td><td>3389</td>
    <td><span class="dot g"></span>Running</td>
    <td>NLA enabled | m.chen, admin in Remote Desktop Users</td></tr>
<tr><td>WinRM</td><td>5985</td>
    <td><span class="dot g"></span>Running</td>
    <td>HTTP transport | m.chen in Remote Management Users</td></tr>
<tr><td>Windows Defender</td><td>&mdash;</td>
    <td><span class="dot r"></span>Disabled</td>
    <td style="color:#ef4444">Real-time protection OFF since 2024-09-15 (vendor compatibility)</td></tr>
<tr><td>Windows Update</td><td>&mdash;</td>
    <td><span class="dot r"></span>Paused</td>
    <td style="color:#ef4444">Last patch: KB5031361 (2024-08-13) — paused until Q1 2025</td></tr>
</table>
</div>

<div class="card section">
<h3>Recent Authentications</h3>
<table>
<tr><th>User</th><th>Source IP</th><th>Protocol</th><th>Timestamp</th><th>Result</th></tr>
<tr><td>m.chen</td><td>${subnetRef}.20</td><td>RDP</td><td>2024-11-15 08:32</td><td class="ok">Success</td></tr>
<tr><td>admin</td><td>${subnetRef}.20</td><td>WinRM</td><td>2024-11-14 16:45</td><td class="ok">Success</td></tr>
<tr><td>sa</td><td>${subnetRef}.20</td><td>MSSQL</td><td>2024-11-14 11:20</td><td class="ok">Success</td></tr>
<tr><td>ANONYMOUS</td><td>${subnetRef}.10</td><td>FTP</td><td>2024-11-13 14:10</td><td class="ok">Success</td></tr>
<tr><td>guest</td><td>${subnetRef}.10</td><td>SMB</td><td>2024-11-13 09:02</td><td class="ok">Success</td></tr>
<tr><td>j.rodriguez</td><td>${subnetRef}.20</td><td>RDP</td><td>2024-11-12 07:55</td><td class="crit">Failed (3x)</td></tr>
</table>
</div>

<div class="card section">
<h3>Databases</h3>
<table>
<tr><th>Name</th><th>Size</th><th>Tables</th><th>Last Backup</th><th>Notes</th></tr>
<tr><td>hr_database</td><td>24 MB</td><td>4</td><td>2024-11-10</td>
    <td>Employee records, payroll, reviews — <strong>contains PII</strong></td></tr>
<tr><td>app_config</td><td>2 MB</td><td>2</td><td>2024-11-10</td>
    <td>Application settings, system_users table</td></tr>
</table>
<div style="color:#475569;font-size:11px;margin-top:12px">
SQL Server 2019 Express 15.0.4385.2 | SA authentication: enabled<br>
Connection: <code>${WinIP},1433</code> | Credentials in IT_Docs share (server_setup_notes.txt)
</div>
</div>

<div class="card section">
<h3>Scheduled Tasks</h3>
<table>
<tr><th>Task</th><th>Schedule</th><th>Run As</th><th>Script Path</th><th>Last Run</th></tr>
<tr><td>Daily Report Generator</td><td>Every 15 min</td><td>NT AUTHORITY\SYSTEM</td>
    <td><code>C:\Scripts\daily_report.bat</code></td><td>2024-11-15 11:45</td></tr>
<tr><td>Health Check</td><td>Hourly</td><td>MedHealthSvc</td>
    <td><code>C:\Program Files\MedAlliance\Health Monitor\agent.exe</code></td><td>2024-11-15 11:00</td></tr>
<tr><td>Backup Job</td><td>Daily 02:00</td><td>NT AUTHORITY\SYSTEM</td>
    <td><code>C:\Scripts\backup_databases.bat</code></td><td>2024-11-15 02:00</td></tr>
</table>
</div>

</div>
</body>
</html>
"@
        Set-Content -Path "$monitorPath\dashboard.html" -Value $dashboardPage -Encoding UTF8

        # Create/refresh the IIS site on port 8080 (guarded)
        if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
            if (Get-Website -Name "HealthMonitor" -ErrorAction SilentlyContinue) {
                Remove-Website -Name "HealthMonitor" -ErrorAction SilentlyContinue
            }
            New-Website -Name "HealthMonitor" -Port 8080 -PhysicalPath $monitorPath -Force | Out-Null
            Start-Website -Name "HealthMonitor" -ErrorAction SilentlyContinue
            Write-Phase "Health Monitor site (port 8080) created."
        } else {
            Write-Warning "[IIS] Get-Website unavailable — skipping HealthMonitor site creation."
        }

        Write-Phase "[Section] IIS site configuration completed."
    }
} catch {
    Write-Warning "[Section] IIS site configuration failed: $_"
    $script:SectionFailures += 'IIS-Sites'
}

# ═══════════════════════════════════════════════════════════════
#  3. FTP SERVICE (IIS FTP)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting FTP configuration..."

    $ftpRoot = "C:\inetpub\ftproot"
    $ftpLogs = "$ftpRoot\logs"
    if (-not (Test-Path $ftpLogs)) {
        New-Item -Path $ftpLogs -ItemType Directory -Force | Out-Null
    }

    $subnetRef = $WinIP -replace '\.\d+$', ''

    # Fake log files with info leakage
    @"
#Software: MedAlliance Health Monitor v3.1
#Date: 2024-11-15
#Fields: date time s-ip cs-username s-computername s-port cs-method result

2024-11-15 08:32:14 ${WinIP} m.chen MEDALLIANCE-WIN 3389 RDP_CONNECT SUCCESS
2024-11-15 08:45:01 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 TASK_EXEC C:\Scripts\daily_report.bat
2024-11-14 16:45:22 ${subnetRef}.20 admin MEDALLIANCE-WIN 5985 WINRM_CONNECT SUCCESS
2024-11-14 11:20:33 ${subnetRef}.20 sa MEDALLIANCE-WIN 1433 SQL_AUTH SUCCESS
2024-11-13 14:10:05 ${subnetRef}.10 anonymous MEDALLIANCE-WIN 21 FTP_AUTH SUCCESS
2024-11-12 09:00:00 ${subnetRef}.20 m.chen MEDALLIANCE-WIN 445 SMB_CONNECT Company_Docs
2024-11-11 23:59:59 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 BACKUP_SQL hr_database
2024-11-10 15:30:00 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 SERVICE_RESTART MedHealthSvc
2024-11-10 03:00:00 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 SCHTASK daily_report.bat
2024-11-09 14:22:11 ${subnetRef}.20 j.thompson MEDALLIANCE-WIN 445 SMB_CONNECT IT_Docs
"@ | Set-Content -Path "$ftpLogs\monitor_2024-11.log" -Encoding UTF8

    @"
#Software: Microsoft Internet Information Services 10.0
#Date: 2024-11-01
#Fields: date time s-ip cs-method cs-uri-stem s-port cs-username c-ip sc-status

2024-11-15 08:30:22 ${WinIP} GET / 80 - ${subnetRef}.10 200
2024-11-15 08:30:45 ${WinIP} GET /healthmonitor/ 8080 - ${subnetRef}.10 200
2024-11-14 16:00:01 ${WinIP} POST /healthmonitor/login.aspx 8080 admin ${subnetRef}.20 302
2024-11-14 11:15:33 ${WinIP} GET /healthmonitor/dashboard.html 8080 admin ${subnetRef}.20 200
2024-11-13 09:00:00 ${WinIP} GET / 80 - ${subnetRef}.20 200
"@ | Set-Content -Path "$ftpLogs\iis_access_2024-11.log" -Encoding UTF8

    @"
MedAlliance Health Partners — FTP Service
==========================================
Read-only access to system and application logs.
For authenticated file share access, use SMB (\\MEDALLIANCE-WIN).
Contact IT (ext 4200) for access requests.
"@ | Set-Content -Path "$ftpRoot\README.txt" -Encoding UTF8

    # Create FTP site with anonymous access (guarded — FTP cmdlets require WebAdministration + FTP role)
    if (-not (Get-Module -ListAvailable WebAdministration)) {
        Write-Warning "[FTP] WebAdministration module not available — FTP site creation skipped."
        $script:SectionFailures += 'FTP'
    } elseif (-not (Get-Command New-WebFtpSite -ErrorAction SilentlyContinue)) {
        Write-Warning "[FTP] New-WebFtpSite unavailable (FTP feature likely not installed) — FTP site skipped."
        $script:SectionFailures += 'FTP'
    } else {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        if (Get-Website -Name "MedAlliance-FTP" -ErrorAction SilentlyContinue) {
            Remove-WebSite -Name "MedAlliance-FTP" -ErrorAction SilentlyContinue
        }
        New-WebFtpSite -Name "MedAlliance-FTP" -Port 21 -PhysicalPath $ftpRoot -Force | Out-Null

        Set-ItemProperty "IIS:\Sites\MedAlliance-FTP" `
            -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true -ErrorAction SilentlyContinue
        Set-ItemProperty "IIS:\Sites\MedAlliance-FTP" `
            -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $false -ErrorAction SilentlyContinue

        Add-WebConfiguration "/system.ftpServer/security/authorization" `
            -PSPath "IIS:" -Location "MedAlliance-FTP" `
            -Value @{accessType="Allow"; roles=""; permissions="Read"; users="*"} -ErrorAction SilentlyContinue

        Start-Website -Name "MedAlliance-FTP" -ErrorAction SilentlyContinue
        Write-Phase "FTP configured (anonymous read on /logs)."
    }

    Write-Phase "[Section] FTP configuration completed."
} catch {
    Write-Warning "[Section] FTP configuration failed: $_"
    $script:SectionFailures += 'FTP'
}

# ═══════════════════════════════════════════════════════════════
#  4. SQL SERVER CONFIGURATION (optional — auto-detect instance)
# ═══════════════════════════════════════════════════════════════
$sqlService = Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like 'MSSQL$*' -or $_.Name -eq 'MSSQLSERVER' } |
              Select-Object -First 1

if ($SkipSQL -or -not $sqlService) {
    Write-Warning "[SQL] Skipping — no MSSQL service present (or -SkipSQL set). IT_Docs breadcrumb still planted."
    $script:SectionFailures += 'SQL-Skipped'
} else {
    try {
        Write-Phase "[Section] Starting SQL Server configuration (service: $($sqlService.Name))..."

        # Start SQL services
        Start-Service -Name $sqlService.Name -ErrorAction SilentlyContinue
        Set-Service   -Name $sqlService.Name -StartupType Automatic -ErrorAction SilentlyContinue

        if (Get-Service -Name 'SQLBrowser' -ErrorAction SilentlyContinue) {
            Start-Service -Name 'SQLBrowser' -ErrorAction SilentlyContinue
            Set-Service   -Name 'SQLBrowser' -StartupType Automatic -ErrorAction SilentlyContinue
        }

        # Derive instance short name (e.g. "MSSQL$SQLEXPRESS" → "SQLEXPRESS", "MSSQLSERVER" → "MSSQLSERVER")
        $instanceName = if ($sqlService.Name -like 'MSSQL$*') {
            $sqlService.Name.Substring(6)
        } else {
            'MSSQLSERVER'
        }
        $sqlServerArg = if ($instanceName -eq 'MSSQLSERVER') { '.' } else { ".\$instanceName" }

        # Enable TCP/IP on port 1433 via WMI (more reliable than registry)
        try {
            $sqlWmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer
            $tcp = $sqlWmi.ServerInstances[$instanceName].ServerProtocols['Tcp']
            $tcp.IsEnabled = $true
            $tcp.Alter()
            $ipAll = $tcp.IPAddresses | Where-Object { $_.Name -eq 'IPAll' }
            $ipAll.IPAddressProperties['TcpPort'].Value = '1433'
            $ipAll.IPAddressProperties['TcpDynamicPorts'].Value = ''
            $tcp.Alter()
            Write-Phase "SQL TCP/IP enabled on port 1433 via WMI."
        } catch {
            Write-Phase "WMI method failed, falling back to registry..."
            $regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
            $instances = Get-ChildItem "$regBase" -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -match "MSSQL\d+\.$instanceName" }

            foreach ($inst in $instances) {
                $tcpPath = "$($inst.PSPath)\MSSQLServer\SuperSocketNetLib\Tcp"
                if (Test-Path $tcpPath) {
                    Set-ItemProperty -Path $tcpPath -Name "Enabled" -Value 1 -Force
                    $ipAllPath = "$tcpPath\IPAll"
                    if (Test-Path $ipAllPath) {
                        Set-ItemProperty -Path $ipAllPath -Name "TcpPort" -Value "1433" -Force
                        Set-ItemProperty -Path $ipAllPath -Name "TcpDynamicPorts" -Value "" -Force
                    }
                }
            }
            Write-Phase "SQL TCP/IP configured via registry."
        }

        # Enable mixed-mode auth via registry
        $regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
        $instances = Get-ChildItem $regBase -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match "MSSQL\d+\.$instanceName" }
        foreach ($inst in $instances) {
            $serverPath = "$($inst.PSPath)\MSSQLServer"
            if (Test-Path $serverPath) {
                Set-ItemProperty -Path $serverPath -Name "LoginMode" -Value 2 -Force
            }
        }

        # Restart SQL to apply changes
        Restart-Service -Name $sqlService.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 8

        # Find sqlcmd
        $sqlcmd = $null
        $searchPaths = @(
            "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE",
            "C:\Program Files\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE",
            "C:\Program Files\Microsoft SQL Server\*\SQLCMD.EXE"
        )
        foreach ($pattern in $searchPaths) {
            $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { $sqlcmd = $found.FullName; break }
        }

        if (-not $sqlcmd) {
            Write-Warning "[SQL] sqlcmd not found — SQL data seeding skipped."
            $script:SectionFailures += 'SQL-Seed'
        } else {
            Write-Phase "Found sqlcmd at: $sqlcmd"

            # Change SA password and enable account
            & $sqlcmd -S $sqlServerArg -E -Q "ALTER LOGIN [sa] WITH PASSWORD = N'SQLAdmin2024!'; ALTER LOGIN [sa] ENABLE;" 2>&1 | Out-Null

            # Enable xp_cmdshell (the main exploitation vector)
            & $sqlcmd -S $sqlServerArg -E -Q @"
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
"@ 2>&1 | Out-Null

            # Create HR database
            & $sqlcmd -S $sqlServerArg -E -Q "IF DB_ID('hr_database') IS NULL CREATE DATABASE hr_database;" 2>&1 | Out-Null

            # Create tables
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
IF OBJECT_ID('employees','U') IS NULL
CREATE TABLE employees (
    id INT PRIMARY KEY IDENTITY(1,1),
    first_name NVARCHAR(50), last_name NVARCHAR(50),
    email NVARCHAR(100), ssn CHAR(11),
    department NVARCHAR(50), title NVARCHAR(100),
    salary DECIMAL(10,2), hire_date DATE, manager_id INT NULL
);

IF OBJECT_ID('payroll','U') IS NULL
CREATE TABLE payroll (
    id INT PRIMARY KEY IDENTITY(1,1),
    employee_id INT, pay_period DATE,
    gross_pay DECIMAL(10,2), tax_withheld DECIMAL(10,2),
    net_pay DECIMAL(10,2), account_last4 CHAR(4)
);

IF OBJECT_ID('performance_reviews','U') IS NULL
CREATE TABLE performance_reviews (
    id INT PRIMARY KEY IDENTITY(1,1),
    employee_id INT, review_date DATE,
    rating INT, comments NVARCHAR(500), reviewer NVARCHAR(100)
);

IF OBJECT_ID('system_credentials','U') IS NULL
CREATE TABLE system_credentials (
    id INT PRIMARY KEY IDENTITY(1,1),
    system_name NVARCHAR(100), username NVARCHAR(50),
    credential NVARCHAR(100), notes NVARCHAR(200),
    last_rotated DATE
);
"@ 2>&1 | Out-Null

            # Populate employee data (realistic fake PII)
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
DELETE FROM employees;

INSERT INTO employees (first_name,last_name,email,ssn,department,title,salary,hire_date,manager_id) VALUES
('Marcus','Chen','m.chen@medalliance.local','458-71-4521','IT','Network Administrator',78500.00,'2019-03-15',NULL),
('Jennifer','Thompson','j.thompson@medalliance.local','312-55-8834','IT','Senior Systems Engineer',92000.00,'2017-06-01',1),
('David','Park','d.park@medalliance.local','629-43-1187','Finance','Financial Analyst',67000.00,'2020-01-20',6),
('Sarah','Mitchell','s.mitchell@medalliance.local','771-28-5593','HR','HR Director',95000.00,'2016-09-12',NULL),
('Robert','Garcia','r.garcia@medalliance.local','184-66-7742','Clinical','Clinical Systems Manager',88000.00,'2018-04-01',NULL),
('Amanda','Foster','a.foster@medalliance.local','533-19-6628','Finance','CFO',142000.00,'2015-02-28',NULL),
('James','Wilson','j.wilson@medalliance.local','847-32-9915','IT','Help Desk Technician',52000.00,'2022-08-15',1),
('Maria','Rodriguez','m.rodriguez@medalliance.local','265-77-3341','Clinical','Data Entry Specialist',44000.00,'2023-01-10',5),
('Kevin','Brown','k.brown@medalliance.local','918-54-2267','Operations','Office Manager',61000.00,'2019-11-01',NULL),
('Lisa','Anderson','l.anderson@medalliance.local','156-88-4479','HR','Recruiter',58000.00,'2021-05-20',4),
('Thomas','Martinez','t.martinez@medalliance.local','742-31-6653','IT','Junior Network Tech',48000.00,'2023-06-01',1),
('Rachel','Kim','r.kim@medalliance.local','389-62-1198','Clinical','Clinical Informatics Analyst',72000.00,'2020-09-15',5),
('Michael','Davis','m.davis@medalliance.local','601-45-8827','Finance','Accounts Payable',51000.00,'2021-03-01',6),
('Emily','Taylor','e.taylor@medalliance.local','234-17-5544','Operations','Receptionist',38000.00,'2022-11-15',9),
('Daniel','Lee','d.lee@medalliance.local','876-93-2210','IT','Security Analyst',85000.00,'2020-07-01',1),
('Jessica','Clark','j.clark@medalliance.local','445-68-9933','Clinical','EHR Support Specialist',56000.00,'2021-08-01',5),
('Andrew','Wright','a.wright@medalliance.local','567-24-1176','Finance','Senior Accountant',74000.00,'2018-12-01',6),
('Nicole','Harris','n.harris@medalliance.local','198-53-7782','HR','Benefits Coordinator',54000.00,'2022-02-14',4),
('Christopher','Moore','c.moore@medalliance.local','713-46-3358','Operations','Facilities Manager',63000.00,'2019-05-20',9),
('Stephanie','White','s.white@medalliance.local','832-71-4495','Clinical','Compliance Officer',91000.00,'2017-10-01',NULL);
"@ 2>&1 | Out-Null

            # Populate payroll data
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
DELETE FROM payroll;

INSERT INTO payroll (employee_id,pay_period,gross_pay,tax_withheld,net_pay,account_last4) VALUES
(1,'2024-11-01',3269.23,817.31,2451.92,'4521'),
(2,'2024-11-01',3833.33,958.33,2875.00,'8834'),
(3,'2024-11-01',2791.67,697.92,2093.75,'1187'),
(4,'2024-11-01',3958.33,989.58,2968.75,'5593'),
(5,'2024-11-01',3666.67,916.67,2750.00,'7742'),
(6,'2024-11-01',5916.67,1479.17,4437.50,'6628'),
(7,'2024-11-01',2166.67,541.67,1625.00,'9915'),
(8,'2024-11-01',1833.33,458.33,1375.00,'3341'),
(9,'2024-11-01',2541.67,635.42,1906.25,'2267'),
(10,'2024-11-01',2416.67,604.17,1812.50,'4479');
"@ 2>&1 | Out-Null

            # System credentials table — breadcrumb for students
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
DELETE FROM system_credentials;

INSERT INTO system_credentials (system_name,username,credential,notes,last_rotated) VALUES
('MEDALLIANCE-WIN (local)','admin','admin','Health Monitor dashboard — default, never changed','2023-01-15'),
('MEDALLIANCE-WIN (local)','m.chen','MedAlliance2024!','Network admin account — AD synced','2024-09-01'),
('SQL Server (SQLEXPRESS)','sa','SQLAdmin2024!','SA account — used by Health Monitor','2024-03-15'),
('Linux Server (medalliance-lnx)','j.thompson','Fall2024Med!','SSH access to Linux file server','2024-10-01'),
('FTP Service','anonymous','(no password)','Read-only log access','2023-06-01'),
('Backup Service','svc_backup','Backup#2024Secure','Nightly SQL backup job','2024-01-15');
"@ 2>&1 | Out-Null

            # Create app_config database
            & $sqlcmd -S $sqlServerArg -E -Q "IF DB_ID('app_config') IS NULL CREATE DATABASE app_config;" 2>&1 | Out-Null

            & $sqlcmd -S $sqlServerArg -E -d "app_config" -Q @"
IF OBJECT_ID('settings','U') IS NULL
CREATE TABLE settings (
    key_name NVARCHAR(100) PRIMARY KEY,
    value NVARCHAR(500),
    updated DATETIME DEFAULT GETDATE()
);

IF OBJECT_ID('app_users','U') IS NULL
CREATE TABLE app_users (
    id INT PRIMARY KEY IDENTITY(1,1),
    username NVARCHAR(50), password_hash NVARCHAR(128),
    role NVARCHAR(20), active BIT DEFAULT 1
);

DELETE FROM settings;
INSERT INTO settings (key_name,value) VALUES
('app.name','MedAlliance Health Monitor'),
('app.version','3.1.2'),
('db.connection','Server=localhost\SQLEXPRESS;Database=hr_database;User=sa;Password=SQLAdmin2024!'),
('backup.path','C:\Backups'),
('backup.schedule','0 2 * * *'),
('smtp.server','medalliance-lnx'),
('smtp.port','25');

DELETE FROM app_users;
INSERT INTO app_users (username,password_hash,role) VALUES
('admin','5f4dcc3b5aa765d61d8327deb882cf99','administrator'),
('m.chen','e10adc3949ba59abbe56e057f20f883e','viewer'),
('j.thompson','827ccb0eea8a706c4c34a16891f84e7b','viewer');
"@ 2>&1 | Out-Null

            Write-Phase "SQL Server configured: SA enabled, xp_cmdshell on, databases populated."
        }

        Write-Phase "[Section] SQL Server configuration completed."
    } catch {
        Write-Warning "[Section] SQL Server configuration failed: $_"
        $script:SectionFailures += 'SQL'
    }
}

# ═══════════════════════════════════════════════════════════════
#  5. WINRM
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting WinRM configuration..."

    # On Win11 client, any adapter on a "Public" profile will cause WinRM Enable-PSRemoting
    # to refuse. Force Public → Private before touching WSMan.
    Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.NetworkCategory -eq 'Public' } |
        Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue

    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force -ErrorAction SilentlyContinue
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force -ErrorAction SilentlyContinue
    winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>&1 | Out-Null
    winrm set winrm/config/service/auth '@{Basic="true"}'       2>&1 | Out-Null

    # Ensure WinRM listener exists on HTTP
    $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue
    if (-not ($listeners | Where-Object { $_.Keys -contains "Transport=HTTP" })) {
        New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force -ErrorAction SilentlyContinue | Out-Null
    }

    Restart-Service WinRM -ErrorAction SilentlyContinue
    Write-Phase "WinRM configured (port 5985, HTTP, basic auth)."
    Write-Phase "[Section] WinRM configuration completed."
} catch {
    Write-Warning "[Section] WinRM configuration failed: $_"
    $script:SectionFailures += 'WinRM'
}

# ═══════════════════════════════════════════════════════════════
#  6. RDP
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting RDP configuration..."

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Force -ErrorAction SilentlyContinue

    $nlaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $nlaPath) {
        Set-ItemProperty -Path $nlaPath -Name "UserAuthentication" -Value 1 -Force -ErrorAction SilentlyContinue
    }

    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

    Write-Phase "RDP enabled (port 3389, NLA on)."
    Write-Phase "[Section] RDP configuration completed."
} catch {
    Write-Warning "[Section] RDP configuration failed: $_"
    $script:SectionFailures += 'RDP'
}

# ═══════════════════════════════════════════════════════════════
#  7. SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
if ($script:SectionFailures.Count -eq 0) {
    Write-Phase "All services configured successfully."
    exit 0
} else {
    Write-Warning "Completed with failures/skips in sections: $($script:SectionFailures -join ', ')"
    exit 1
}
