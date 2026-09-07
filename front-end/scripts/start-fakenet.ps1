# CyberCore calls this through the QEMU guest agent only after external isolation.
# No infrastructure credentials or network connectivity checks belong here.
# Config keys and startup markers follow the installed FakeNet-NG interface:
# https://github.com/mandiant/flare-fakenet-ng/blob/master/fakenet/configs/default.ini
# https://github.com/mandiant/flare-fakenet-ng/blob/master/fakenet/fakenet.py

param(
    [ValidatePattern('^$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$AttemptId = ''
)

function Get-FakeNetIniValue {
    param([string]$Text, [string]$Section, [string]$Key)
    $current = ''
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') { $current = $Matches[1]; continue }
        if ($current -ieq $Section -and $line -match ('^\s*' + [regex]::Escape($Key) + '\s*[:=]\s*(.*)$')) {
            return $Matches[1].Trim()
        }
    }
    return $null
}

function Set-FakeNetIniValue {
    param([string]$Text, [string]$Section, [string]$Key, [string]$Value)
    $lines = [System.Collections.Generic.List[string]]::new()
    $current = ''
    $written = $false
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            if ($current -ieq $Section -and -not $written) {
                $lines.Add("${Key}: $Value"); $written = $true
            }
            $current = $Matches[1]
        }
        if ($current -ieq $Section -and $line -match ('^\s*' + [regex]::Escape($Key) + '\s*[:=]')) {
            if (-not $written) { $lines.Add("${Key}: $Value"); $written = $true }
        } else { $lines.Add($line) }
    }
    if (-not $written) {
        if ($current -ine $Section) { $lines.Add(''); $lines.Add("[$Section]") }
        $lines.Add("${Key}: $Value")
    }
    return $lines -join "`r`n"
}

function New-CyberCoreFakeNetConfig {
    param([string]$SourceText, [string]$GatewayIp, [string]$CaptureDirectory = 'C:\Analysis')
    if ([string]::IsNullOrWhiteSpace($SourceText)) {
        # Complete built-in profile when the binary package exposes no default.ini.
        # Bundled listener assets (certificates/defaultFiles) remain in FakeNet.
        $SourceText = @'
[FakeNet]
DivertTraffic: Yes
[Diverter]
NetworkMode: SingleHost
DebugLevel: Off
DumpPackets: Yes
DumpPacketsFilePrefix: packets
FixGateway: No
FixDNS: Yes
ModifyLocalDNS: Yes
StopDNSService: Yes
RedirectAllTraffic: Yes
DefaultTCPListener: RawTCPListener
DefaultUDPListener: RawUDPListener
BlackListPortsTCP: 139, 3389
BlackListPortsUDP: 67, 68, 137, 138, 3389
[RawTCPListener]
Enabled: True
Port: 1337
Protocol: TCP
Listener: RawListener
UseSSL: No
Timeout: 10
Hidden: False
[RawUDPListener]
Enabled: True
Port: 1337
Protocol: UDP
Listener: RawListener
UseSSL: No
Timeout: 10
Hidden: False
[DNS Server]
Enabled: True
Port: 53
Protocol: UDP
Listener: DNSListener
ResponseA: 192.0.2.123
ResponseMX: mail.analysis.invalid
ResponseTXT: FAKENET
NXDomains: 0
Hidden: False
[HTTPListener80]
Enabled: True
Port: 80
Protocol: TCP
Listener: HTTPListener
UseSSL: No
Webroot: defaultFiles/
Timeout: 10
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: http
Hidden: False
[HTTPListener443]
Enabled: True
Port: 443
Protocol: TCP
Listener: HTTPListener
UseSSL: Yes
Webroot: defaultFiles/
Timeout: 10
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: http
Hidden: False
'@
    }
    if ($SourceText -notmatch '(?m)^\s*\[FakeNet\]\s*$' -or $SourceText -notmatch '(?m)^\s*\[Diverter\]\s*$') {
        throw 'FakeNet configuration must contain [FakeNet] and [Diverter] sections.'
    }
    $placeholder = '(?:@@LANE_GATEWAY@@|\{\{GATEWAY_IP\}\}|__GATEWAY_IP__|__LANE_GATEWAY__)'
    if ($SourceText -match $placeholder) {
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($GatewayIp, [ref]$address) -or $address.AddressFamily -ne 'InterNetwork') {
            throw 'FakeNet configuration needs the workstation IPv4 default gateway.'
        }
        $SourceText = [regex]::Replace($SourceText, $placeholder, $GatewayIp)
    }
    $text = Set-FakeNetIniValue $SourceText 'FakeNet' 'DivertTraffic' 'Yes'
    $text = Set-FakeNetIniValue $text 'Diverter' 'NetworkMode' 'SingleHost'
    $text = Set-FakeNetIniValue $text 'Diverter' 'RedirectAllTraffic' 'Yes'
    $text = Set-FakeNetIniValue $text 'Diverter' 'FixGateway' 'No'
    $text = Set-FakeNetIniValue $text 'Diverter' 'DumpPackets' 'Yes'
    $text = Set-FakeNetIniValue $text 'Diverter' 'DumpPacketsFilePrefix' (Join-Path $CaptureDirectory 'packets')
    foreach ($protocol in @('TCP', 'UDP')) {
        $key = "BlackListPorts$protocol"
        $ports = @(Get-FakeNetIniValue $text 'Diverter' $key) -join ''
        $entries = @($ports -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if (@($entries | Where-Object { $_ -notmatch '^\d+(?:-\d+)?$' }).Count) { throw "Invalid FakeNet $key list." }
        if ($entries -notcontains '3389') { $entries += '3389' }
        $text = Set-FakeNetIniValue $text 'Diverter' $key ($entries -join ', ')
    }
    foreach ($section in [regex]::Matches($text, '(?m)^\s*\[([^\]]+)\]\s*$')) {
        foreach ($key in @('DumpHTTPPostsFilePrefix', 'TFTPFilePrefix')) {
            if (Get-FakeNetIniValue $text $section.Groups[1].Value $key) {
                $text = Set-FakeNetIniValue $text $section.Groups[1].Value $key (Join-Path $CaptureDirectory $key)
            }
        }
    }
    # Keep installed service/custom-response settings. Never add a blanket
    # svchost.exe exemption: only the RDP port needs to bypass diversion.
    return $text
}

function Test-FakeNetStartup {
    param([string]$LogText, [bool]$ProcessAlive, [double]$AgeSeconds)
    # -v emits these callbacks after listeners and the diverter have started.
    # A banner/config-load line alone occurs before driver/listener failures.
    return $ProcessAlive -and $AgeSeconds -ge 5 -and
        $LogText -match 'accept(?:Listeners|Diverter)\(\) not implemented by Listener' -and
        $LogText -notmatch '(?im)Traceback \(most recent call last\)|\bERROR:|Error starting .* listener|\[\s*FakeNet\]\s+Stopping'
}

function Write-CyberCoreFakeNetResult {
    param([string]$StartupAttemptId, [hashtable]$Result, [string]$CaptureDirectory = 'C:\Analysis')
    if ($StartupAttemptId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw 'Invalid FakeNet startup attempt ID.'
    }
    $Result.attemptId = $StartupAttemptId
    $resultPath = Join-Path $CaptureDirectory "cybercore-fakenet-start-$StartupAttemptId.json"
    $tempPath = $resultPath + '.tmp'
    [IO.File]::WriteAllText($tempPath, ($Result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    # Readers see either the prior status or this complete JSON document.
    if (Test-Path -LiteralPath $resultPath) { [IO.File]::Replace($tempPath, $resultPath, [NullString]::Value) }
    else { [IO.File]::Move($tempPath, $resultPath) }
}

function Open-CyberCoreFakeNetStatusReader {
    param([string]$ResultPath)
    # Get-Content omits FileShare.Delete on Windows. Its brief read can then
    # prevent the worker's atomic File.Replace and strand status at 'starting'.
    # Sharing deletion keeps an overlapping reader on the old complete document
    # while subsequent readers open the newly published one.
    $stream = [IO.FileStream]::new($ResultPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { return [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8) }
    catch { $stream.Dispose(); throw }
}

function Read-CyberCoreFakeNetResult {
    param([string]$StartupAttemptId, [string]$CaptureDirectory = 'C:\Analysis')
    if ($StartupAttemptId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw 'Invalid FakeNet startup attempt ID.'
    }
    $resultPath = Join-Path $CaptureDirectory "cybercore-fakenet-start-$StartupAttemptId.json"
    $reader = Open-CyberCoreFakeNetStatusReader $resultPath
    try { $result = $reader.ReadToEnd() | ConvertFrom-Json }
    finally { $reader.Dispose() }
    if ($result.attemptId -ne $StartupAttemptId) { throw 'FakeNet status belongs to a different startup attempt.' }
    if ($result.complete -eq $true -and $result.ready -eq $true) {
        $configPath = 'C:\Tools\FakeNet\configs\cybercore-analysis.ini'
        if ($result.pid -notmatch '^\d+$' -or [long]$result.pid -lt 1) { throw 'FakeNet returned an invalid process ID.' }
        $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($result.pid)"
        if (-not $current -or $current.ExecutablePath -ine 'C:\Tools\FakeNet\fakenet.exe' -or
            $current.CommandLine -notlike "*$configPath*" -or
            $current.CreationDate.ToUniversalTime().ToString('o') -ne $result.processCreatedUtc -or
            (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne $result.configHash) {
            throw 'FakeNet stopped or its running configuration changed during startup. Check C:\Analysis.'
        }
        $logText = Get-Content -LiteralPath $result.logPath -Raw
        if (-not (Test-FakeNetStartup $logText $true ((Get-Date) - $current.CreationDate).TotalSeconds)) {
            throw "FakeNet is no longer reporting successful initialization. Check $($result.logPath)."
        }
    }
    return $result
}

function Start-CyberCoreFakeNet {
    $ErrorActionPreference = 'Stop'
    if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        throw 'Start Analysis requires the QEMU guest agent running as LocalSystem.'
    }
    $executable = 'C:\Tools\FakeNet\fakenet.exe'
    $captureDir = 'C:\Analysis'
    $configDir = 'C:\Tools\FakeNet\configs'
    $configPath = Join-Path $configDir 'cybercore-analysis.ini'
    $statePath = Join-Path $captureDir 'cybercore-fakenet.json'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw 'FakeNet is missing. Install the complete package at C:\Tools\FakeNet\fakenet.exe in the clean template.'
    }
    New-Item -ItemType Directory -Path $captureDir -Force | Out-Null
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    $existing = @(Get-CimInstance Win32_Process -Filter "Name = 'fakenet.exe'" |
        Where-Object { $_.ExecutablePath -ieq $executable })
    if ($existing.Count) {
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            throw 'FakeNet is already running outside Start Analysis. Close that instance and try again, or Reset Lab.'
        }
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $matching = @($existing | Where-Object { $_.ProcessId -eq $state.pid -and $_.CommandLine -like "*$configPath*" })
        if (-not $matching.Count -or -not (Test-Path -LiteralPath $configPath -PathType Leaf) -or
            (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne $state.configHash -or
            ($state.processCreatedUtc -and $matching[0].CreationDate.ToUniversalTime().ToString('o') -ne $state.processCreatedUtc)) {
            throw 'The running FakeNet configuration has changed. Reset Lab before continuing.'
        }
        $logText = Get-Content -LiteralPath $state.logPath -Raw
        $age = ((Get-Date) - $matching[0].CreationDate).TotalSeconds
        if (-not (Test-FakeNetStartup $logText $true $age)) { throw 'The existing FakeNet instance is not ready. Check C:\Analysis or Reset Lab.' }
        return @{ ready = $true; pid = [int]$state.pid; captureDirectory = $captureDir; logPath = $state.logPath; reused = $true;
            configHash = $state.configHash; processCreatedUtc = $matching[0].CreationDate.ToUniversalTime().ToString('o') }
    }
    $sourceText = ''
    foreach ($candidate in @((Join-Path $configDir 'cybercore.ini.template'), (Join-Path $configDir 'default.ini'))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $sourceText = Get-Content -LiteralPath $candidate -Raw; break }
    }
    $gateway = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop
    $config = New-CyberCoreFakeNetConfig $sourceText $gateway $captureDir
    [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
    $tag = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $logPath = Join-Path $captureDir "fakenet-$tag.log"
    $stdoutPath = Join-Path $captureDir "fakenet-$tag.stdout.log"
    $stderrPath = Join-Path $captureDir "fakenet-$tag.stderr.log"
    $stdinPath = Join-Path $captureDir 'fakenet-stdin.txt'
    [IO.File]::WriteAllText($stdinPath, '')
    # No scheduled auto-restart: Reset Lab is the way back to a clean state.
    # Redirect stdin to EOF so older FakeNet releases cannot hang at an exit prompt.
    $process = Start-Process -FilePath $executable -ArgumentList @('-v', '-c', $configPath, '-l', $logPath) `
        -WorkingDirectory $captureDir -WindowStyle Hidden -PassThru `
        -RedirectStandardInput $stdinPath -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $startedAt = Get-Date
    while (((Get-Date) - $startedAt).TotalSeconds -lt 45) {
        Start-Sleep -Seconds 1
        $process.Refresh()
        $logText = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { '' }
        $stderrText = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        if ($process.HasExited -or ($logText + $stderrText) -match '(?im)Traceback \(most recent call last\)|\bERROR:|Error starting .* listener') {
            throw "FakeNet could not initialize. Check $logPath and $stderrPath."
        }
        $age = ((Get-Date) - $startedAt).TotalSeconds
        if (Test-FakeNetStartup $logText (-not $process.HasExited) $age) {
            $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($process.Id)"
            if (-not $current) { throw "FakeNet exited during startup. Check $logPath." }
            $state = @{ pid = $process.Id; configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash; logPath = $logPath;
                processCreatedUtc = $current.CreationDate.ToUniversalTime().ToString('o') }
            [IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
            return @{ ready = $true; pid = $process.Id; captureDirectory = $captureDir; logPath = $logPath; reused = $false;
                configHash = $state.configHash; processCreatedUtc = $state.processCreatedUtc }
        }
    }
    throw "FakeNet startup was not confirmed within 45 seconds. Check $logPath."
}

if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 0
    try {
        if ($AttemptId) {
            Write-CyberCoreFakeNetResult $AttemptId @{ complete = $false; phase = 'starting' }
        }
        $result = Start-CyberCoreFakeNet
    } catch {
        $result = @{ ready = $false; error = $_.Exception.Message; diagnostic = $_.ToString() }
        $exitCode = 1
    }
    $result.complete = $true
    if ($AttemptId) {
        # Publish before process exit; a long-lived descendant can retain handles.
        Write-CyberCoreFakeNetResult $AttemptId $result
        # Removing registration leaves the running application alone. Never call
        # Stop-ScheduledTask: that would stop FakeNet and its captures.
        Unregister-ScheduledTask -TaskName "CyberCore-FakeNet-$AttemptId" -Confirm:$false -ErrorAction SilentlyContinue
    }
    $result | ConvertTo-Json -Compress
    exit $exitCode
}
