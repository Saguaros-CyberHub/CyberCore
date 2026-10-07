<#
================================================================================
 goad-wazuh-agent  --  Wazuh agent 4.8.2 for ONE Windows lane host
================================================================================

 WHAT THIS IS
   The Windows agent half of GOAD's `wazuh` extension, ported from
   GOAD-main/extensions/wazuh/ansible/roles/wazuh_agent:
       defaults/main.yml  -> the MSI URL and staging directory below
       tasks/main.yml     -> the service guard, download, msiexec and start
   It installs the Wazuh agent MSI with the manager address baked in as MSI
   properties, and starts WazuhSvc. The agent then enrols itself with the
   manager on first start.

 WHY THIS RUNS PER LANE INSTEAD OF BEING BAKED INTO A TEMPLATE
   This is the case where baking is not merely risky but actively wrong. A
   Wazuh agent that is snapshotted AFTER it has registered carries the manager's
   client.keys entry -- ONE agent identity -- into every clone made from that
   image. The manager then sees a single agent ID connecting from every lane at
   once, and the symptom is agents flapping between connected and disconnected
   across the whole fleet. (seal-goad-wazuh-template.sh clears exactly this
   state out of the MANAGER for the same reason.) Installing at post-clone time
   sidesteps it entirely: there is no baked client.keys to clear, and each host
   enrols once, as itself. The shared Windows templates are also never touched,
   so nothing outside a blue-team lane can be broken by a change here.

 IT TARGETS A NAME, NOT AN IP.
   WAZUH_MANAGER and WAZUH_REGISTRATION_SERVER are set to wazuh.cybercore.lan,
   which the lane gateway publishes as a dnsmasq host-record for the lane's own
   `wazuh` machine. Upstream fills these from hostvars['wazuh'].ansible_host, a
   fixed lab IP; CyberCore addresses the SIEM differently, and a name means the
   two never have to agree.

 NO AGENT NAME IS PASSED, ON PURPOSE.
   Upstream does not set WAZUH_AGENT_NAME either, so the agent registers under
   its own hostname. Lane hostnames are unique, which is exactly what makes the
   per-lane install produce distinct agent identities.

 NO ARGUMENTS, NO SECRETS.
   script_args is interpolated UNQUOTED onto the command line by
   script-executor.js, so nothing may ever be passed through it. Enrolment here
   needs no password: it uses Wazuh's default registration service, the same as
   upstream.

 EXIT CODE CONTRACT
   Exits 0 when the agent is installed, EVEN IF THE MANAGER IS NOT ANSWERING.
   Post-clone scripts routinely run before the lane's Wazuh VM has finished
   booting. The agent re-attempts enrolment and reconnects on its own, so
   "cannot register yet" is a normal transient state and not a failed lane. It
   is logged and moved past. Exits 1 only when the agent could not be INSTALLED
   at all -- a real, actionable failure that executeScriptsOnVM records
   per-script without aborting the deploy.

 NO REBOOT. msiexec may return 3010 (success, reboot required); the Wazuh
   service runs fine without it and rebooting a lane VM mid-deploy is how a
   deploy loses machines.
================================================================================
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# --- Everything the upstream role's defaults/main.yml pins -------------------
$WazuhVersion   = '4.8.2-1'
$WazuhMsiUrl    = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
$WazuhManager   = 'wazuh.cybercore.lan'
$StagingDir     = 'C:\tmp'
# Upstream downloads to "c:\tmp/wazuh-agent" with no extension. Kept as a real
# .msi filename here: msiexec is documented to require the extension to
# recognise the package, and nothing about the install depends on the name.
$MsiPath        = Join-Path $StagingDir "wazuh-agent-$WazuhVersion.msi"
$MsiLogPath     = 'C:\Windows\Temp\wazuh-agent-install.log'
$AgentDir       = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$WazuhAgentPort = 1514   # the agent -> manager event channel
$WazuhEnrolPort = 1515   # the registration service

$script:Failures = @()

function Write-Step { param([string]$Message) Write-Host ''; Write-Host "==> $Message" }
function Write-Info { param([string]$Message) Write-Host "    $Message" }
function Write-Note { param([string]$Message) Write-Host "    NOTE: $Message" }
function Add-Failure {
    param([string]$Message)
    $script:Failures += $Message
    Write-Host "    ERROR: $Message"
}

function Get-RemoteFile {
    param([string]$Url, [string]$OutFile, [int]$Retries = 3)
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            Write-Info "GET $Url  (attempt $i of $Retries)"
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 600
            $len = (Get-Item $OutFile -ErrorAction SilentlyContinue).Length
            Write-Info "downloaded $len bytes -> $OutFile"
            return $true
        } catch {
            Write-Note "download failed: $($_.Exception.Message)"
            Start-Sleep -Seconds 5
        }
    }
    return $false
}

# A short, bounded TCP probe. Test-NetConnection can sit for 20+ seconds
# against a host that is still booting, and this is only ever informational.
function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 5000)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        $done = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($done -and $client.Connected) { $client.EndConnect($iar); return $true }
        return $false
    } catch {
        return $false
    } finally {
        if ($client) { $client.Close() }
    }
}

Write-Host '=========================================================='
Write-Host ' goad-wazuh-agent : Wazuh agent (per-lane install)'
Write-Host '=========================================================='
Write-Info "Host        : $env:COMPUTERNAME"
Write-Info "OS          : $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)"
Write-Info "Agent       : $WazuhVersion"
Write-Info "Manager     : $WazuhManager"
Write-Info "Started     : $(Get-Date -Format 'u')"

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { Write-Note "could not raise TLS version: $($_.Exception.Message)" }

# ============================================================================
# 1. ALREADY INSTALLED?
# ============================================================================
# Upstream registers `win_service: name=WazuhSvc` and gates the download, the
# msiexec call AND the service start on `not wazuh_agent_service.exists`.
# Mirrored, which is what makes a retried or redeployed lane a no-op here.
Write-Step 'Checking for an existing Wazuh agent'
$svc = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
if ($svc) {
    Write-Info "WazuhSvc already present (status: $($svc.Status)) -- skipping install"

    # Report the manager the existing install actually points at. Purely
    # informational, and the one fact worth having when a lane's agent shows up
    # under the wrong manager.
    $confPath = Join-Path $AgentDir 'ossec.conf'
    if (Test-Path $confPath) {
        try {
            $conf = Get-Content $confPath -Raw -ErrorAction Stop
            $m = [regex]::Match($conf, '(?is)<client>.*?<address>\s*(.*?)\s*</address>')
            if ($m.Success) { Write-Info "configured manager: $($m.Groups[1].Value)" }
        } catch {
            Write-Note "could not read ossec.conf: $($_.Exception.Message)"
        }
    }

    if ($svc.Status -ne 'Running') {
        try {
            Set-Service -Name 'WazuhSvc' -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name 'WazuhSvc' -ErrorAction Stop
            Write-Info 'started WazuhSvc'
        } catch {
            Add-Failure "could not start the existing WazuhSvc: $($_.Exception.Message)"
        }
    }
} else {
    # ========================================================================
    # 2. DOWNLOAD + INSTALL
    # ========================================================================
    Write-Step "Installing the Wazuh agent $WazuhVersion"
    if (-not (Test-Path $StagingDir)) {
        New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
    }

    if (-not (Get-RemoteFile -Url $WazuhMsiUrl -OutFile $MsiPath)) {
        Add-Failure "could not download the Wazuh agent MSI from $WazuhMsiUrl"
    } else {
        # Exactly upstream's command line, with a verbose MSI log added so a
        # failure leaves something to read in the deployment transcript.
        #
        # NOTHING SENSITIVE GOES ON THIS COMMAND LINE. The only properties are
        # the manager hostname, which is public inside the lane.
        $msiArgs = @(
            '/i', "`"$MsiPath`"",
            '/q',
            "WAZUH_MANAGER=$WazuhManager",
            "WAZUH_REGISTRATION_SERVER=$WazuhManager",
            '/L*V', "`"$MsiLogPath`""
        )
        Write-Info "running: msiexec.exe $($msiArgs -join ' ')"
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
        $rc = $proc.ExitCode

        # 0 = installed. 3010 = installed, reboot requested -- accepted and NOT
        # acted on; see the header.
        if ($rc -eq 0) {
            Write-Info 'msiexec reported success (exit 0)'
        } elseif ($rc -eq 3010) {
            Write-Info 'msiexec reported success with a reboot request (exit 3010) -- not rebooting, the service does not need it'
        } else {
            Add-Failure "msiexec exited $rc"
            if (Test-Path $MsiLogPath) {
                Write-Info "--- last 40 lines of $MsiLogPath ---"
                Get-Content $MsiLogPath -Tail 40 -ErrorAction SilentlyContinue |
                    ForEach-Object { Write-Info $_ }
                Write-Info '--- end of MSI log ---'
            }
        }

        # ====================================================================
        # 3. START THE SERVICE
        # ====================================================================
        # Starting the service is what triggers enrolment: the agent contacts
        # the registration server on 1515, is issued a key, and connects on
        # 1514. That first-run enrolment is the whole reason this is installed
        # per lane rather than baked -- a fresh install enrols as itself.
        Write-Step 'Starting the Wazuh agent service'
        Start-Sleep -Seconds 3
        $svc = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Failure 'WazuhSvc does not exist after the MSI install'
        } else {
            try { Set-Service -Name 'WazuhSvc' -StartupType Automatic -ErrorAction Stop } catch {
                Write-Note "could not set WazuhSvc to automatic start: $($_.Exception.Message)"
            }
            try {
                if ($svc.Status -ne 'Running') {
                    Start-Service -Name 'WazuhSvc' -ErrorAction Stop
                    Write-Info 'WazuhSvc started'
                } else {
                    Write-Info 'WazuhSvc already running'
                }
            } catch {
                # A start failure while the MANAGER is down is still an install
                # that will come good: the agent retries. Recorded as a note,
                # not a failure, unless the service itself is missing (above).
                Write-Note "WazuhSvc did not start on the first attempt: $($_.Exception.Message)"
            }
        }
    }
}

# ============================================================================
# 4. REACHABILITY -- REPORTED, NEVER ENFORCED
# ============================================================================
# This probe exists so the deployment transcript says whether the manager was
# up at install time, and NOTHING ELSE DEPENDS ON IT. Post-clone scripts
# routinely run before the lane's Wazuh VM has finished booting; the agent
# re-attempts enrolment on its own, so an unreachable manager now is a healthy,
# enrolled agent in ten minutes. Failing here would mark a perfectly good lane
# as failed.
Write-Step 'Checking Wazuh manager reachability (informational only)'
try {
    $addrs = [System.Net.Dns]::GetHostAddresses($WazuhManager) | ForEach-Object { $_.IPAddressToString }
    Write-Info "$WazuhManager resolves to: $($addrs -join ', ')"
} catch {
    Write-Info "$WazuhManager does not resolve yet -- the lane gateway publishes this host-record; the agent will keep retrying"
}
foreach ($p in @($WazuhEnrolPort, $WazuhAgentPort)) {
    $label = if ($p -eq $WazuhEnrolPort) { 'registration' } else { 'events' }
    if (Test-TcpPort -HostName $WazuhManager -Port $p) {
        Write-Info "TCP ${WazuhManager}:${p} ($label) is open"
    } else {
        Write-Info "TCP ${WazuhManager}:${p} ($label) is not answering yet. This is EXPECTED while the SIEM VM boots."
    }
}
Write-Info 'The agent re-attempts enrolment on its own; no action is required and this is not a failure.'

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ''
Write-Host '=== goad-wazuh-agent complete ==='
$svc = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
Write-Info ("WazuhSvc    : " + $(if ($svc) { $svc.Status } else { 'NOT INSTALLED' }))
Write-Info "Agent dir   : $AgentDir"
Write-Info "Manager     : $WazuhManager (registration + events)"
Write-Info "MSI log     : $MsiLogPath"
Write-Info "Finished    : $(Get-Date -Format 'u')"

if ($script:Failures.Count -gt 0) {
    Write-Host ''
    Write-Host "FAILED: $($script:Failures.Count) installation step(s) did not complete:"
    foreach ($f in $script:Failures) { Write-Host "  - $f" }
    # Non-zero ONLY for installation failures. executeScriptsOnVM marks this one
    # script failed and carries on with the rest of the deploy, so this buys
    # visibility without costing the lane.
    exit 1
}

exit 0
