<#
.SYNOPSIS
    Installs the CYBR 400 log mappings, retention policy and Kibana dashboard.

.DESCRIPTION
    Runs on the lane's Windows ELK box, from Start-ElkStack.ps1 at boot. Three
    things, in this order, because each depends on the previous one:

      1. An ILM policy + a `logs@custom` component template. The mappings are
         NOT optional decoration -- without them the loggen.* fields arrive
         under dynamic mapping, string fields can land as `text`, and every
         terms panel on the dashboard ("Log sources", "Top source hosts",
         "Log levels") silently renders empty because text fields are not
         aggregatable. The dashboard would import perfectly and show nothing.

         loggen.mitre.* is mapped too even though no panel displays it. The
         data is there for the instructor to query and for a later "map what
         you found to ATT&CK" exercise; it is simply not surfaced, because raw
         logs in a real environment carry no technique labels.

      2. A rollover, because a component template only affects indices created
         AFTER it is applied. Without this the mappings take effect at the next
         natural rollover, which on a lab-sized data stream could be days.

      3. The saved objects (data view + 7 Lens panels + dashboard).

    Written for Windows PowerShell 5.1, which is what ships on the Server image:
    no -Form on Invoke-RestMethod, no && chaining, no ternary. The saved-objects
    import is a multipart upload, so it goes through curl.exe (present in
    System32 on Server 2019+) rather than being hand-rolled.

    Idempotent. Imports once and drops a marker, so a professor who rearranges
    the dashboard does not lose it on the next reboot. -Force re-imports.

.PARAMETER Force
    Re-import even if the marker says it has already been done.
#>
[CmdletBinding()]
param(
    [string] $KibanaUrl    = 'http://localhost:5601',
    [string] $ElasticUrl   = 'http://localhost:9200',
    [string] $NdjsonPath   = 'C:\CyberCore\cybr400-loggen-dashboard.ndjson',
    [string] $MarkerPath   = 'C:\CyberCore\.dashboard-imported',
    [int]    $TimeoutMin   = 15,
    [switch] $Force
)

$ErrorActionPreference = 'Continue'
$log = 'C:\CyberCore\dashboard-import.log'

function Log($m) {
    $line = "$(Get-Date -Format s)  $m"
    $line | Out-File $log -Append -Encoding utf8
    Write-Verbose $line
}

if ((Test-Path $MarkerPath) -and (-not $Force)) {
    Log 'already imported (marker present) - nothing to do'
    return
}

if (-not (Test-Path $NdjsonPath)) {
    Log "ERROR: saved objects file not found: $NdjsonPath"
    return
}

# ---------------------------------------------------------------------------
# Wait for BOTH services. Elasticsearch first: Kibana can be listening on 5601
# and still refuse a saved-objects write while its own indices are unavailable.
# ---------------------------------------------------------------------------
function Wait-Http([string]$url, [string]$label, [datetime]$deadline) {
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) {
                Log "$label is up (HTTP $($r.StatusCode))"
                return $true
            }
        } catch {
            # Kibana answers 503 with a body while it is still starting, and
            # Invoke-WebRequest treats that as terminating. Both mean "not yet".
        }
        Start-Sleep -Seconds 10
    }
    Log "TIMEOUT waiting for $label at $url"
    return $false
}

$deadline = (Get-Date).AddMinutes($TimeoutMin)
if (-not (Wait-Http "$ElasticUrl/_cluster/health" 'elasticsearch' $deadline)) { return }
if (-not (Wait-Http "$KibanaUrl/api/status"      'kibana'        $deadline)) { return }

# ---------------------------------------------------------------------------
# 1. Retention + mappings
# ---------------------------------------------------------------------------
$ilm = @'
{
  "policy": {
    "phases": {
      "hot":    { "actions": { "rollover": { "max_primary_shard_size": "1gb", "max_age": "1d" } } },
      "delete": { "min_age": "14d", "actions": { "delete": {} } }
    }
  }
}
'@

# loggen.metadata is `flattened` on purpose. log-generator emits a different
# metadata shape per generator, and at the pinned commit it does not substitute
# the placeholders, so values like "{clientIP}" appear verbatim. Mapping those
# keys individually invites both a field explosion and a type conflict -- and a
# type conflict on a data stream does not warn, it REJECTS the document.
$componentTemplate = @'
{
  "template": {
    "settings": { "index.lifecycle.name": "cybr400-loggen" },
    "mappings": {
      "properties": {
        "loggen": {
          "properties": {
            "timestamp": { "type": "date" },
            "level":     { "type": "keyword" },
            "message":   { "type": "text" },
            "metadata":  { "type": "flattened" },
            "source": {
              "properties": {
                "type": { "type": "keyword" },
                "name": { "type": "keyword" },
                "host": { "type": "keyword" }
              }
            },
            "mitre": {
              "properties": {
                "technique":    { "type": "keyword" },
                "tactic":       { "type": "keyword" },
                "subtechnique": { "type": "keyword" },
                "description":  { "type": "text" }
              }
            }
          }
        }
      }
    }
  }
}
'@

function Put-Json([string]$url, [string]$body, [string]$label) {
    try {
        Invoke-RestMethod -Method Put -Uri $url -Body $body `
            -ContentType 'application/json' -TimeoutSec 60 -ErrorAction Stop | Out-Null
        Log "applied $label"
        return $true
    } catch {
        Log "ERROR applying ${label}: $($_.Exception.Message)"
        return $false
    }
}

Put-Json "$ElasticUrl/_ilm/policy/cybr400-loggen"       $ilm               'ILM policy'         | Out-Null
Put-Json "$ElasticUrl/_component_template/logs@custom"  $componentTemplate 'component template' | Out-Null

# ---------------------------------------------------------------------------
# 2. Roll the data streams so the new mappings apply to a fresh backing index.
#    A 404 here is the normal case on a lane where no events have shipped yet:
#    the data stream is created on first write and will pick the mappings up
#    from the template anyway. Not an error.
# ---------------------------------------------------------------------------
foreach ($ds in @('logs-loggen.events-default')) {
    try {
        Invoke-RestMethod -Method Post -Uri "$ElasticUrl/$ds/_rollover" `
            -TimeoutSec 60 -ErrorAction Stop | Out-Null
        Log "rolled over $ds"
    } catch {
        Log "rollover skipped for ${ds}: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 3. Saved objects
# ---------------------------------------------------------------------------
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not (Test-Path $curl)) {
    Log 'ERROR: curl.exe not found in System32 - cannot do a multipart upload on PS 5.1'
    return
}

$out = & $curl -s -S --max-time 120 `
    -X POST "$KibanaUrl/api/saved_objects/_import?overwrite=true" `
    -H 'kbn-xsrf: true' `
    -F "file=@$NdjsonPath" 2>&1

Log "import response: $out"

$ok = $false
try {
    $parsed = $out | ConvertFrom-Json
    # `success` false with successCount > 0 means some objects landed and some
    # did not; log the errors rather than silently marking the box done.
    if ($parsed.success) {
        $ok = $true
        Log "imported $($parsed.successCount) object(s)"
    } else {
        Log "import reported failures: $($parsed.errors | ConvertTo-Json -Compress -Depth 6)"
    }
} catch {
    Log 'could not parse the import response as JSON - treating as failure'
}

if ($ok) {
    "imported $(Get-Date -Format s)" | Out-File $MarkerPath -Encoding utf8
    Log "marker written to $MarkerPath"
    Log "dashboard: $KibanaUrl/app/dashboards#/view/cybr400-dashboard"
} else {
    Log 'NOT writing the marker - the next boot will retry'
}
