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

      3. The saved objects: a data view, 14 Lens panels and TWO dashboards.

         "Log Activity" answers "is data arriving and what does this estate
         look like". "Hunting Workbench" is the analytic surface a student
         builds toward -- rate, ratio and rarity, three moves that work on any
         log estate. Neither references a technique, a dataset or a file path,
         so neither can point at the instructor's attack.

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
    # Credentials for a secured stack. Leave empty for the security-disabled
    # build; the script behaves exactly as before when they are not supplied.
    [string] $EsUser       = '',
    [string] $EsPassword   = '',
    [switch] $Force
)

$ErrorActionPreference = 'Continue'
$log = 'C:\CyberCore\dashboard-import.log'

# An EXPLICIT Authorization header, not -Credential. PowerShell 5.1 does not send
# credentials preemptively -- it waits for a WWW-Authenticate challenge, and while
# Elasticsearch does challenge, relying on the retry turns every call into two and
# breaks outright on the endpoints that answer 401 with no challenge header.
#
# Empty credentials produce an empty header set, so the security-disabled build
# takes exactly the same code path it always did.
# Set by Put-Json when a call fails for a reason nothing downstream can
# survive. Declared here, before the first thing that can set it.
$hardFail    = $false
$AuthHeaders = @{}
$CurlAuth    = @()
if ($EsUser -ne '') {
    $pair = "{0}:{1}" -f $EsUser, $EsPassword
    $b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $AuthHeaders = @{ Authorization = "Basic $b64" }
    $CurlAuth    = @('-u', $pair)
}

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
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 `
                    -Headers $AuthHeaders -ErrorAction Stop
            if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) {
                Log "$label is up (HTTP $($r.StatusCode))"
                return $true
            }
        } catch {
            # Kibana answers 503 with a body while it is still starting, and
            # Invoke-WebRequest treats that as terminating. Both mean "not yet".
            #
            # A 401 does NOT mean "not yet" and must never be retried for fifteen
            # minutes. On a secured stack with no or wrong credentials this was the
            # first call in the script, so the whole import died here with nothing
            # in the log but a timeout -- and the lane came up with no mappings and
            # no dashboards, looking healthy.
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 401 -or $code -eq 403) {
                if ($EsUser -eq '') {
                    Log "FATAL: $label returned HTTP $code - the stack has security ENABLED but no credentials were supplied."
                    Log "       Re-run with:  -EsUser elastic -EsPassword '<password>'"
                } else {
                    Log "FATAL: $label rejected the supplied credentials for user '$EsUser' (HTTP $code)."
                }
                return $false
            }
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
  # 14 days, set deliberately and against the industry norm. A production SOC
  # keeps a month hot (NIST suggests 90; PCI wants a quarter immediately
  # available), but this is a teaching lane and the exercises never look further
  # back than the previous week, so the extra retention would buy nothing.
  #
  # It also helps in a way a longer window would not: every attack the instructor
  # has ever fired stays in the index until it ages out, and over a long window a
  # student hunting this week's attack is picking it out of a crowd of previous
  # weeks' attackers. Fourteen days keeps that crowd to one other class at most.
  #
  # At ~2M events/day this is ~28M documents and ~10 GB per lane, flat, however
  # long the course runs. Raise it only if an exercise needs month-over-month
  # comparison; the cost is roughly 0.7 GB per lane per extra day.
  "policy": {
    "phases": {
      "hot":    { "actions": { "rollover": { "max_primary_shard_size": "1gb", "max_age": "1d" } } },
      "delete": { "min_age": "14d", "actions": { "delete": {} } }
    }
  }
}
'@

# loggen.metadata was `flattened` while log-generator drove the baseline: it
# emitted a different metadata shape per generator and never substituted its
# placeholders, so mapping those keys invited a field explosion and a type
# conflict -- and a type conflict on a data stream does not warn, it REJECTS the
# document.
#
# Now that cc-emit.js produces both halves the key set is ours and bounded, so
# the fourteen below are mapped explicitly as keyword. That is what makes them
# AGGREGATABLE: a flattened subfield can be queried in KQL but does not appear
# in field caps, so Lens cannot build a terms panel on it -- and user and src_ip
# are the two fields a hunt pivots on more than any other.
#
# dynamic: false rather than true, so an unexpected key is still stored in
# _source but cannot create a mapping conflict that silently rejects documents.
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
            "metadata": {
              "dynamic": false,
              "properties": {
                "event_action": { "type": "keyword" },
                "user":         { "type": "keyword" },
                "target_user":  { "type": "keyword" },
                "src_ip":       { "type": "keyword" },
                "dst_ip":       { "type": "keyword" },
                "protocol":     { "type": "keyword" },
                "service":      { "type": "keyword" },
                "outcome":      { "type": "keyword" },
                "status":       { "type": "keyword" },
                "path":         { "type": "keyword" },
                "table":        { "type": "keyword" },
                "metric":       { "type": "keyword" },
                "shell":        { "type": "keyword" },
                "user_agent":   { "type": "keyword" }
              }
            },
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
        Invoke-RestMethod -Method Put -Uri $url -Body $body -Headers $AuthHeaders `
            -ContentType 'application/json' -TimeoutSec 60 -ErrorAction Stop | Out-Null
        Log "applied $label"
        return $true
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -eq 401 -or $code -eq 403) {
            # The header of this script says the mappings are NOT optional: without
            # them every terms panel renders empty. Logging and carrying on here
            # produced a lane that imported "successfully" and was silently useless.
            Log "FATAL applying ${label}: HTTP $code. The account lacks manage_ilm / manage_index_templates,"
            Log "      or no credentials were supplied to a secured stack. Nothing below this point can work."
            $script:hardFail = $true
        } else {
            Log "ERROR applying ${label}: $($_.Exception.Message)"
        }
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
        Invoke-RestMethod -Method Post -Uri "$ElasticUrl/$ds/_rollover" -Headers $AuthHeaders `
            -TimeoutSec 60 -ErrorAction Stop | Out-Null
        Log "rolled over $ds"
    } catch {
        Log "rollover skipped for ${ds}: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 3. Saved objects
# ---------------------------------------------------------------------------
if ($hardFail) {
    # Importing dashboards onto a cluster that rejected the mappings produces the
    # worst outcome available: an import that reports success, panels that render
    # empty, and nothing in the log that points at the cause.
    Log 'ABORTING before the dashboard import - the retention/mapping step failed above.'
    Log 'Fix the credentials or privileges and re-run; the dashboards are useless without it.'
    return
}

$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not (Test-Path $curl)) {
    Log 'ERROR: curl.exe not found in System32 - cannot do a multipart upload on PS 5.1'
    return
}

# @CurlAuth splats to nothing when no credentials were supplied, so the
# security-disabled build runs the identical command line it always did.
$out = & $curl -s -S --max-time 120 @CurlAuth `
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
