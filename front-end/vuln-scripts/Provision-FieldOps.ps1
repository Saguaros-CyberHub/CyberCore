<#
.SYNOPSIS
    Builds the Copper Ridge FieldOps target (TUC-WEB01): IIS + ASP.NET, the
    deliberately vulnerable FieldOps portal, and four working local privilege
    escalation routes off the IIS application pool identity.

.DESCRIPTION
    This is the single source of truth for the challenge. The OS underneath is
    built by hand (clone of template 1004 -- see
    challenges/copperridge-fieldops/BUILD.md), but everything that *defines*
    the challenge lives here so it can be reviewed, diffed and re-run.

    Run elevated, on the scratch build VM, before sealing the template.
    Re-running is safe: every step is idempotent.

    Intended chain:
      /backup/web.config.bak leaks the portal password  (directory browsing +
        .bak is not in requestFiltering's denied extensions, unlike .config)
      -> portal login -> Attachments.aspx upload filter bypass
      -> webshell as 'IIS APPPOOL\FieldOpsAppPool'
      -> SYSTEM via any of routes A-E below.

.PARAMETER AppSource
    Directory holding the FieldOps app files -- the contents of
    challenges/copperridge-fieldops/app/ staged onto the box. See BUILD.md.

.PARAMETER SkipVerify
    Skip the closing verification pass. Do not use when building a template.

.NOTES
    WHY THE PRIVESC ROUTES ARE PLANTED THE WAY THEY ARE
    ---------------------------------------------------
    The pre-existing weak-services.ps1 advertises an unquoted service path and
    a writable service binary but neither is exploitable, for three reasons
    this script deliberately avoids:

      1. It registers a .bat as a service image. SCM calls CreateProcess on the
         image path, which fails ERROR_BAD_EXE_FORMAT for a batch file -- so
         overwriting the writable .bat executes nothing. Route D below compiles
         a real .exe.

      2. It grants write on the *leaf* directory of the service path. The
         unquoted-path insertion points for "C:\Program Files\Lab Update
         Service\updater.bat" are C:\Program.exe and "C:\Program Files\Lab.exe"
         -- and Users can create folders but not files at C:\, while
         C:\Program Files is read-execute. So no insertion point is writable.
         Route D grants write on the *parent*, making "C:\FieldOps
         Services\Sync.exe" a genuine insertion point.

      3. Its second service is start=demand with no SERVICE_START right granted,
         so exploiting it needs a reboot an unprivileged user cannot cause.
         Routes B and D both grant RP (SERVICE_START) explicitly.

    Everything is granted to BOTH IIS_IUSRS and the app pool virtual account.
    An ApplicationPoolIdentity token should carry IIS_IUSRS, but that is not
    worth betting the challenge on.
#>

param(
    [string]$AppSource = "C:\CyberCore\fieldops-app",
    [switch]$SkipVerify
)

$ErrorActionPreference = "Continue"
$script:Failures = @()

# ---- Challenge constants -------------------------------------------------
$SiteName      = "FieldOps"
$AppPoolName   = "FieldOpsAppPool"
$SiteRoot      = "C:\inetpub\FieldOps"
$AppPoolPrincipal = "IIS APPPOOL\$AppPoolName"
$IisUsers      = "IIS_IUSRS"

$SyncSvcName   = "CRFieldSync"          # route D -- unquoted path
$SyncSvcParent = "C:\FieldOps Services" # the writable insertion point lives here
$SyncSvcDir    = "$SyncSvcParent\Sync Agent"
$SyncSvcExe    = "$SyncSvcDir\CRFieldSync.exe"

$TelemetrySvc  = "CRTelemetry"          # route B -- weak service DACL

$TaskName      = "CRShiftExport"        # route C -- writable SYSTEM task
$TaskDir       = "C:\ProgramData\CopperRidge"
$TaskScript    = "$TaskDir\shift-export.ps1"

$BackupUser    = "svc_backup"           # route E -- stored creds, real account
$BackupPass    = 'Cu2019!RidgeBak'
$ScriptsDir    = "C:\Scripts"

$MarkerFile    = "C:\CyberCore\fieldops-bake.env"

function Write-Phase { param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][FieldOps] $Msg"
}
function Add-Failure { param([string]$Section)
    $script:Failures += $Section
}

Write-Host "=============================================================="
Write-Host " Copper Ridge FieldOps target provisioner"
Write-Host "=============================================================="

$osInfo   = Get-CimInstance Win32_OperatingSystem
$isServer = $osInfo.ProductType -ne 1
Write-Phase "Detected: $($osInfo.Caption) (IsServer=$isServer)"

# ==========================================================================
#  Helpers
# ==========================================================================

# Branches the Server vs Client feature API. Same shape as Install-MedFeature
# in 480Scripts/Install-Services.ps1 -- kept so this runs on a Win11 client
# SKU for instructor testing as well as on Server.
function Install-CRFeature {
    param(
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$ClientName
    )
    try {
        if ($isServer) {
            Install-WindowsFeature -Name $ServerName -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
        } else {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName $ClientName -ErrorAction SilentlyContinue).State
            if ($state -ne 'Enabled') {
                Enable-WindowsOptionalFeature -Online -FeatureName $ClientName -NoRestart -All -ErrorAction SilentlyContinue | Out-Null
            }
        }
    } catch {
        Write-Warning "  Could not enable $ServerName/$ClientName : $_"
    }
}

# Grant a filesystem right to both IIS_IUSRS and the app pool virtual account.
# icacls is used rather than Set-Acl because the app pool virtual account has
# no resolvable SID until the pool exists, and icacls handles it by name.
function Grant-FsAccess {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Rights   # e.g. '(OI)(CI)(M)' or '(F)'
    )
    foreach ($principal in @($IisUsers, $AppPoolPrincipal)) {
        & icacls $Path /grant "${principal}:$Rights" 2>&1 | Out-Null
    }
}

# Append an allow-ACE to a service's DACL without clobbering the existing one.
# sc sdshow returns "D:(...)(...)S:(...)"; the new ACE must be inserted at the
# end of the D: section, before any S: (SACL) section.
function Grant-ServiceAccess {
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [Parameter(Mandatory=$true)][string]$Sddl      # e.g. '(A;;CCDCLCSWRPWPDTLOCRRC;;;S-1-5-32-568)'
    )
    $current = (& sc.exe sdshow $ServiceName 2>&1 | Where-Object { $_ -match '^D:' }) -join ''
    if (-not $current) {
        Write-Warning "  Could not read SDDL for $ServiceName"
        return $false
    }
    if ($current -like "*$Sddl*") {
        Write-Phase "  $ServiceName already carries the ACE"
        return $true
    }

    if ($current -match '^(?<dacl>D:.*?)(?<sacl>S:.*)$') {
        $new = $Matches['dacl'] + $Sddl + $Matches['sacl']
    } else {
        $new = $current + $Sddl
    }

    $result = & sc.exe sdset $ServiceName $new 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  sdset failed for $ServiceName : $result"
        return $false
    }
    return $true
}

# BUILTIN\IIS_IUSRS. There is no two-letter SDDL alias for it, so use the SID.
$SddlIisUsers = 'S-1-5-32-568'

# ==========================================================================
#  1. IIS + ASP.NET
# ==========================================================================
try {
    Write-Phase "[1/8] Installing IIS and ASP.NET 4.x features..."

    Install-CRFeature -ServerName 'Web-Server'           -ClientName 'IIS-WebServer'
    Install-CRFeature -ServerName 'Web-Common-Http'      -ClientName 'IIS-CommonHttpFeatures'
    Install-CRFeature -ServerName 'Web-Default-Doc'      -ClientName 'IIS-DefaultDocument'
    Install-CRFeature -ServerName 'Web-Dir-Browsing'     -ClientName 'IIS-DirectoryBrowsing'
    Install-CRFeature -ServerName 'Web-Http-Errors'      -ClientName 'IIS-HttpErrors'
    Install-CRFeature -ServerName 'Web-Static-Content'   -ClientName 'IIS-StaticContent'
    Install-CRFeature -ServerName 'Web-Http-Logging'     -ClientName 'IIS-HttpLogging'
    Install-CRFeature -ServerName 'Web-Filtering'        -ClientName 'IIS-RequestFiltering'
    Install-CRFeature -ServerName 'Web-Asp-Net45'        -ClientName 'IIS-ASPNET45'
    Install-CRFeature -ServerName 'Web-Net-Ext45'        -ClientName 'IIS-NetFxExtensibility45'
    Install-CRFeature -ServerName 'Web-ISAPI-Ext'        -ClientName 'IIS-ISAPIExtensions'
    Install-CRFeature -ServerName 'Web-ISAPI-Filter'     -ClientName 'IIS-ISAPIFilter'
    Install-CRFeature -ServerName 'Web-Mgmt-Console'     -ClientName 'IIS-ManagementConsole'

    Import-Module WebAdministration -ErrorAction Stop
    Write-Phase "  IIS features installed, WebAdministration loaded."
} catch {
    Write-Warning "[1/8] IIS feature install failed: $_"
    Add-Failure 'IIS-Features'
}

# ==========================================================================
#  2. Application pool + site
# ==========================================================================
try {
    Write-Phase "[2/8] Creating application pool and site..."

    # Free port 80. The stock Default Web Site would otherwise win the binding.
    if (Test-Path "IIS:\Sites\Default Web Site") {
        Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
        Write-Phase "  Removed Default Web Site (frees :80)."
    }

    if (-not (Test-Path "IIS:\AppPools\$AppPoolName")) {
        New-WebAppPool -Name $AppPoolName | Out-Null
    }
    # identityType 4 = ApplicationPoolIdentity. This is what gives the webshell
    # 'IIS APPPOOL\FieldOpsAppPool' -- and with it SeImpersonatePrivilege,
    # which is privesc route A. Do not change to a named account.
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value 4
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion     -Value "v4.0"
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedPipelineMode       -Value 0   # Integrated
    # Keep the worker alive so a student's shell does not die on idle timeout.
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.idleTimeout  -Value "00:00:00"
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name recycling.periodicRestart.time -Value "00:00:00"

    if (-not (Test-Path $SiteRoot)) { New-Item -ItemType Directory -Path $SiteRoot -Force | Out-Null }

    if (-not (Test-Path "IIS:\Sites\$SiteName")) {
        New-Website -Name $SiteName -Port 80 -PhysicalPath $SiteRoot -ApplicationPool $AppPoolName | Out-Null
    } else {
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath     -Value $SiteRoot
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool  -Value $AppPoolName
    }

    Write-Phase "  Site '$SiteName' -> $SiteRoot on pool '$AppPoolName'."
} catch {
    Write-Warning "[2/8] Site/app-pool creation failed: $_"
    Add-Failure 'IIS-Site'
}

# ==========================================================================
#  3. Deploy the FieldOps application
# ==========================================================================
try {
    Write-Phase "[3/8] Deploying FieldOps application from $AppSource ..."

    if (-not (Test-Path $AppSource)) {
        throw "AppSource '$AppSource' not found. Stage challenges/copperridge-fieldops/app/ there first (see BUILD.md)."
    }

    Copy-Item -Path (Join-Path $AppSource '*') -Destination $SiteRoot -Recurse -Force
    foreach ($d in @("$SiteRoot\Uploads", "$SiteRoot\backup")) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # The upload directory must be writable by the worker process -- this is
    # what turns the filter bypass into a file on disk.
    Grant-FsAccess -Path "$SiteRoot\Uploads" -Rights '(OI)(CI)(M)'

    # Everything else stays read-only to the pool, so a student cannot simply
    # overwrite Attachments.aspx to remove the check.
    & icacls $SiteRoot /grant "${IisUsers}:(OI)(CI)(RX)" 2>&1 | Out-Null

    Write-Phase "  Deployed. Uploads/ is writable by the pool identity."
} catch {
    Write-Warning "[3/8] App deploy failed: $_"
    Add-Failure 'App-Deploy'
}

# ==========================================================================
#  4. Route B -- weak service DACL (binary-free escalation)
# ==========================================================================
# A LocalSystem service the web identity may reconfigure AND start. No file
# write and no reboot needed:
#   sc config CRTelemetry binPath= "cmd /c net localgroup administrators ..."
#   sc start  CRTelemetry
try {
    Write-Phase "[4/8] Route B: planting weak service DACL on $TelemetrySvc ..."

    if (-not (Get-Service -Name $TelemetrySvc -ErrorAction SilentlyContinue)) {
        & sc.exe create $TelemetrySvc `
            binPath= "C:\Windows\System32\cmd.exe /c timeout /t 86400" `
            start= demand `
            DisplayName= "Copper Ridge Telemetry Relay" | Out-Null
    }
    & sc.exe description $TelemetrySvc "Relays haul fleet telemetry to the dispatch aggregator." | Out-Null

    # CC=QueryConfig DC=ChangeConfig LC=QueryStatus SW=EnumDeps RP=Start
    # WP=Stop DT=PauseContinue LO=Interrogate CR=UserDefined RC=ReadControl
    $ok = Grant-ServiceAccess -ServiceName $TelemetrySvc `
                              -Sddl "(A;;CCDCLCSWRPWPDTLOCRRC;;;$SddlIisUsers)"
    if (-not $ok) { Add-Failure 'Route-B' }

    Write-Phase "  $TelemetrySvc reconfigurable and startable by $IisUsers."
} catch {
    Write-Warning "[4/8] Route B failed: $_"
    Add-Failure 'Route-B'
}

# ==========================================================================
#  5. Route C -- writable script behind a SYSTEM scheduled task (binary-free)
# ==========================================================================
# 5-minute repetition, not the 3AM-daily trigger weak-services.ps1 uses -- a
# trigger that never fires inside a class session teaches nothing.
try {
    Write-Phase "[5/8] Route C: planting writable SYSTEM scheduled task $TaskName ..."

    if (-not (Test-Path $TaskDir)) { New-Item -ItemType Directory -Path $TaskDir -Force | Out-Null }

    $exportScript = @'
# Copper Ridge -- shift downtime export
# Rolls the FieldOps downtime log into the dispatch share for the morning
# production meeting. Runs as SYSTEM every 5 minutes during shift.
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$out   = "C:\ProgramData\CopperRidge\shift-export.log"
Add-Content -Path $out -Value "[$stamp] shift export completed" -ErrorAction SilentlyContinue
'@
    Set-Content -Path $TaskScript -Value $exportScript -Encoding UTF8

    # The weakness: the web identity may rewrite the script SYSTEM executes.
    Grant-FsAccess -Path $TaskScript -Rights '(F)'
    Grant-FsAccess -Path $TaskDir    -Rights '(OI)(CI)(M)'

    $action    = New-ScheduledTaskAction -Execute "powershell.exe" `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$TaskScript`""
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
                    -RepetitionInterval (New-TimeSpan -Minutes 5) `
                    -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description "Exports the shift downtime log to the dispatch share." -Force | Out-Null

    # So enumeration (schtasks /query, winPEAS) actually surfaces it.
    & icacls "C:\Windows\System32\Tasks\$TaskName" /grant "${IisUsers}:(R)" 2>&1 | Out-Null

    Write-Phase "  $TaskName runs as SYSTEM every 5 min; its script is pool-writable."
} catch {
    Write-Warning "[5/8] Route C failed: $_"
    Add-Failure 'Route-C'
}

# ==========================================================================
#  6. Route D -- unquoted service path with a REAL writable insertion point
# ==========================================================================
# binPath is unquoted and contains spaces:
#     C:\FieldOps Services\Sync Agent\CRFieldSync.exe
# SCM will therefore try, in order:
#     C:\FieldOps.exe                     <- C:\ denies file-create to non-admins
#     C:\FieldOps Services\Sync.exe       <- THIS one; parent is pool-writable
#     C:\FieldOps Services\Sync Agent\CRFieldSync.exe
try {
    Write-Phase "[6/8] Route D: planting unquoted service path for $SyncSvcName ..."

    foreach ($d in @($SyncSvcParent, $SyncSvcDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # A real PE, not a .bat -- SCM cannot CreateProcess a batch file, which is
    # exactly why the equivalent primitive in weak-services.ps1 never fires.
    if (-not (Test-Path $SyncSvcExe)) {
        $csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
        if (-not (Test-Path $csc)) { $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
        if (Test-Path $csc) {
            $src = Join-Path $env:TEMP "crfieldsync.cs"
            Set-Content -Path $src -Encoding ASCII -Value @'
using System;
using System.Threading;
class CRFieldSync {
    static void Main() {
        // Placeholder sync agent. The real export moved to the scheduled
        // task in FY22 (CR-3301); this stub is retained for the service entry.
        Thread.Sleep(Timeout.Infinite);
    }
}
'@
            & $csc /nologo /target:exe /out:"$SyncSvcExe" "$src" 2>&1 | Out-Null
            Remove-Item $src -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path $SyncSvcExe)) {
            throw "Could not compile $SyncSvcExe (csc.exe not found). Route D would be a dead end."
        }
    }

    if (-not (Get-Service -Name $SyncSvcName -ErrorAction SilentlyContinue)) {
        # NOTE: binPath deliberately unquoted.
        & sc.exe create $SyncSvcName binPath= "$SyncSvcExe" start= demand `
            DisplayName= "Copper Ridge FieldSync Agent" | Out-Null
    }
    & sc.exe description $SyncSvcName "Synchronises FieldOps downtime entries with the dispatch aggregator." | Out-Null

    # The writable insertion point.
    Grant-FsAccess -Path $SyncSvcParent -Rights '(OI)(CI)(M)'

    # Startable without a reboot, or the route needs privileges the student
    # does not have yet.
    $ok = Grant-ServiceAccess -ServiceName $SyncSvcName `
                              -Sddl "(A;;CCLCSWRPWPLORC;;;$SddlIisUsers)"
    if (-not $ok) { Add-Failure 'Route-D' }

    Write-Phase "  $SyncSvcName has an unquoted path; '$SyncSvcParent' is pool-writable."
} catch {
    Write-Warning "[6/8] Route D failed: $_"
    Add-Failure 'Route-D'
}

# ==========================================================================
#  7. Route E -- stored credentials for an account that actually exists
# ==========================================================================
# cached-credentials.ps1 plants passwords matching no real account, so its
# creds->RunAs route dead-ends. Here the account is created for real.
try {
    Write-Phase "[7/8] Route E: creating $BackupUser and planting its credential ..."

    $securePass = ConvertTo-SecureString $BackupPass -AsPlainText -Force
    if (-not (Get-LocalUser -Name $BackupUser -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $BackupUser -Password $securePass `
            -FullName "Copper Ridge Backup Service" `
            -Description "Nightly configuration backup job (CR-3318)" `
            -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
    } else {
        Set-LocalUser -Name $BackupUser -Password $securePass -PasswordNeverExpires $true
    }
    if (-not (Get-LocalGroupMember -Group "Administrators" -Member $BackupUser -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group "Administrators" -Member $BackupUser -ErrorAction SilentlyContinue
    }

    # Artifact 1 -- the backup batch file that references the credential.
    if (-not (Test-Path $ScriptsDir)) { New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null }
    $batch = @"
@echo off
REM ============================================================
REM  Copper Ridge nightly configuration backup  (CR-3318)
REM  Scheduled 02:15. Dumps the FieldOps web.config to /backup
REM  so Dispatch can review it after a change window.
REM ============================================================
net use Z: \\TUC-SRV02\configdrop /user:TUC-WEB01\$BackupUser $BackupPass
copy /Y "$SiteRoot\web.config" "$SiteRoot\backup\web.config.bak"
copy /Y "$SiteRoot\backup\web.config.bak" Z:\TUC-WEB01\
net use Z: /delete /y
"@
    Set-Content -Path "$ScriptsDir\nightly-config-backup.bat" -Value $batch -Encoding ASCII
    & icacls $ScriptsDir /grant "${IisUsers}:(OI)(CI)(RX)" 2>&1 | Out-Null

    # Artifact 2 -- the classic leftover answer file.
    $pantherDir = "C:\Windows\Panther"
    if (-not (Test-Path $pantherDir)) { New-Item -ItemType Directory -Path $pantherDir -Force | Out-Null }
    $unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <Name>$BackupUser</Name>
            <Group>Administrators</Group>
            <Password>
              <Value>$BackupPass</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>false</Enabled>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"@
    Set-Content -Path "$pantherDir\Unattend.xml" -Value $unattend -Encoding UTF8
    & icacls "$pantherDir\Unattend.xml" /grant "${IisUsers}:(R)" 2>&1 | Out-Null

    Write-Phase "  $BackupUser is a real local administrator; credential planted in 2 places."
} catch {
    Write-Warning "[7/8] Route E failed: $_"
    Add-Failure 'Route-E'
}

# ==========================================================================
#  8. Firewall, service start, marker
# ==========================================================================
try {
    Write-Phase "[8/8] Opening TCP/80 and starting W3SVC ..."

    Enable-NetFirewallRule -DisplayGroup "World Wide Web Services (HTTP)" -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-NetFirewallRule -DisplayName "FieldOps-HTTP-80" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "FieldOps-HTTP-80" -Direction Inbound -Protocol TCP `
            -LocalPort 80 -Action Allow -Profile Any | Out-Null
    }

    Set-Service -Name W3SVC -StartupType Automatic -ErrorAction SilentlyContinue
    Restart-Service -Name W3SVC -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    if (-not (Test-Path (Split-Path $MarkerFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $MarkerFile -Parent) -Force | Out-Null
    }
    @"
# Copper Ridge FieldOps target -- planted artifacts
# Written by Provision-FieldOps.ps1 at $(Get-Date -Format 's')
CHALLENGE_KEY=copperridge-fieldops
SITE_NAME=$SiteName
SITE_ROOT=$SiteRoot
APP_POOL=$AppPoolName
FOOTHOLD_IDENTITY=IIS APPPOOL\$AppPoolName
PORTAL_USER=d.mercer
PORTAL_PASS=CopperRidge#2019
ROUTE_A=SeImpersonatePrivilege (inherent to ApplicationPoolIdentity)
ROUTE_B=$TelemetrySvc weak service DACL (binary-free)
ROUTE_C=$TaskName SYSTEM task, writable script (binary-free)
ROUTE_D=$SyncSvcName unquoted path, writable insertion point $SyncSvcParent\Sync.exe
ROUTE_E=$BackupUser local admin, credential in C:\Scripts\nightly-config-backup.bat and C:\Windows\Panther\Unattend.xml
"@ | Set-Content -Path $MarkerFile -Encoding UTF8

    Write-Phase "  Marker written to $MarkerFile"
} catch {
    Write-Warning "[8/8] Firewall/start failed: $_"
    Add-Failure 'Startup'
}

# ==========================================================================
#  Verification
# ==========================================================================
function Invoke-FieldOpsVerify {
    Write-Host ""
    Write-Host "=============================================================="
    Write-Host " VERIFY -- each planted artifact must be present"
    Write-Host "=============================================================="

    function Check { param([string]$Name, [scriptblock]$Test)
        $pass = $false
        try { $pass = [bool](& $Test) } catch { $pass = $false }
        $script:results += [pscustomobject]@{ Check = $Name; Pass = $pass }
        $tag = if ($pass) { "PASS" } else { "FAIL" }
        Write-Host ("  [{0}] {1}" -f $tag, $Name)
        return $pass
    }
    $script:results = @()

    Check "IIS site '$SiteName' exists and is started" {
        (Get-Website -Name $SiteName -ErrorAction SilentlyContinue).State -eq 'Started'
    } | Out-Null

    Check "App pool '$AppPoolName' uses ApplicationPoolIdentity (route A)" {
        (Get-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType).Value -eq 4
    } | Out-Null

    Check "Portal responds 200 on http://localhost/" {
        (Invoke-WebRequest -Uri "http://localhost/" -UseBasicParsing -TimeoutSec 15).StatusCode -eq 200
    } | Out-Null

    Check "web.config.bak is reachable at /backup/web.config.bak" {
        $r = Invoke-WebRequest -Uri "http://localhost/backup/web.config.bak" -UseBasicParsing -TimeoutSec 15
        $r.StatusCode -eq 200 -and $r.Content -match 'FieldOpsPassword'
    } | Out-Null

    Check "Uploads/ is writable by $IisUsers" {
        (& icacls "$SiteRoot\Uploads" | Out-String) -match 'IIS_IUSRS'
    } | Out-Null

    # Inspect the IIS_IUSRS ACE specifically -- the stock BA ace also carries
    # DC/RP, so a substring match against the whole SDDL would pass regardless.
    Check "Route B: $TelemetrySvc grants IIS_IUSRS change-config + start" {
        $sd = (& sc.exe sdshow $TelemetrySvc | Out-String)
        if ($sd -match "\(A;;(?<rights>[A-Z]+);;;$SddlIisUsers\)") {
            $r = $Matches['rights']
            $r -match 'DC' -and $r -match 'RP'
        } else { $false }
    } | Out-Null

    Check "Route C: $TaskName registered as SYSTEM" {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        $t -and $t.Principal.UserId -match 'SYSTEM'
    } | Out-Null

    Check "Route C: task script is writable by $IisUsers" {
        (& icacls $TaskScript | Out-String) -match 'IIS_IUSRS'
    } | Out-Null

    Check "Route D: $SyncSvcName binPath is unquoted and contains a space" {
        $bp = ((& sc.exe qc $SyncSvcName | Select-String 'BINARY_PATH_NAME') -split ':\s',2)[1]
        $bp -and $bp.Trim() -notmatch '^"' -and $bp -match ' '
    } | Out-Null

    Check "Route D: service image is a real PE, not a batch file" {
        (Test-Path $SyncSvcExe) -and ([System.IO.File]::ReadAllBytes($SyncSvcExe)[0..1] -join ',') -eq '77,90'
    } | Out-Null

    Check "Route D: insertion point '$SyncSvcParent\Sync.exe' is writable" {
        (& icacls $SyncSvcParent | Out-String) -match 'IIS_IUSRS'
    } | Out-Null

    Check "Route E: $BackupUser exists and is a local administrator" {
        (Get-LocalUser -Name $BackupUser -ErrorAction SilentlyContinue) -and
        (Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "\\$BackupUser$" })
    } | Out-Null

    Check "Route E: planted credential matches the real account password" {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine')
        $ctx.ValidateCredentials($BackupUser, $BackupPass)
    } | Out-Null

    Check "Route E: credential artifacts readable" {
        (Test-Path "$ScriptsDir\nightly-config-backup.bat") -and (Test-Path "C:\Windows\Panther\Unattend.xml")
    } | Out-Null

    $failed = @($script:results | Where-Object { -not $_.Pass })
    Write-Host ""
    Write-Host ("  {0}/{1} checks passed." -f ($script:results.Count - $failed.Count), $script:results.Count)
    return $failed.Count
}

$verifyFailures = 0
if (-not $SkipVerify) { $verifyFailures = Invoke-FieldOpsVerify }

Write-Host ""
Write-Host "=============================================================="
if ($script:Failures.Count -gt 0) {
    Write-Host " SECTION FAILURES: $($script:Failures -join ', ')"
}
if ($verifyFailures -gt 0 -or $script:Failures.Count -gt 0) {
    Write-Host " RESULT: NOT READY -- do not seal this template."
    Write-Host "=============================================================="
    exit 1
}
Write-Host " RESULT: FieldOps target ready. Safe to seal as a template."
Write-Host " Portal: http://<ip>/   d.mercer / CopperRidge#2019"
Write-Host "=============================================================="
exit 0
