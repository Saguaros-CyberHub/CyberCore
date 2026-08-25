# CYBR 400 — Windows ELK box: reconfigure and re-template

Manual runbook for the Windows machine running Elasticsearch + Kibana. Unlike the sensor
(`bake-cybr400-loggen-template.sh`) this image is hand-built, so there is no script — these are the
steps, in order, with the reasoning that matters.

Run everything in an **elevated PowerShell** on the live VM.

**Outcome:** Elasticsearch and Kibana both come up unattended on every clone and every reboot, the box
accepts data from its lane's sensor with no credentials, and the image is re-templated for the CLE
two-machine deploy.

---

## 0. What the diagnosis found — read this first

The Kibana log showed it running healthily for 22 minutes and ending on
`SIGINT received - initiating shutdown`: a clean, deliberate stop. **Kibana is not crashing, and its
configuration is not the problem.** Three separate things are:

**1. The Kibana service runs as a local user account whose password is rotated on every deploy.**

```
PathName  : C:\Users\cactus-user\Downloads\nssm\nssm-2.24\win64\nssm.exe
StartName : .\cactus-user
```

`cactus-user` is the *cloud-init account*. `lane-deployer.js resolveWorkstationCredentials` generates a
fresh password for it per lane, and cloudbase-init's `SetUserPasswordPlugin` applies it at first boot.
Windows stores the service's credential in LSA secrets at install time, so the moment that password
changes the service can no longer log on: **Automatic, but Stopped**, with no application-level error
because Kibana never runs. Elasticsearch is unaffected because `elasticsearch-service-x64` installs as
LocalSystem.

> This is why it works on the machine you built it on and dies on every clone.

**2. `elasticsearch-service-x64` is `StartType: Manual`.** It is only running now because something
started it by hand. On a clone's first boot it does not start at all — so even a fixed Kibana would
have nothing to connect to.

**3. NSSM lives in `C:\Users\cactus-user\Downloads\`.** A user-profile path for a system service.

**And a fourth finding that changes the design.** Fleet is live on this box:

```
Fleet Usage: agents: {total_enrolled: 2, healthy: 0, offline: 2},
             fleet_server: {total_enrolled: 1, offline: 1}
```

A Fleet Server plus two enrolled agents — this Windows box and the Rocky sensor — both already
offline. **Fleet requires x-pack security**, so it cannot coexist with the plan to disable it. It is
also fundamentally incompatible with templating: an enrolled agent's identity is baked into the image,
so every clone reports as the *same* agent and Fleet sees one host flapping between thirty machines.
The two agents showing `offline` is that failure already beginning.

**Fleet is being removed.** Standalone agents write directly into Elasticsearch — the data path
(sensor → ES → Discover and dashboards in Kibana) is identical. What Fleet adds is central policy
management and an agent-health page, and the sensor's config is two fixed filestream inputs that never
change. It buys nothing here and costs per-clone enrollment, tokens and certificates.

### Record the stack version before you start

Read it **off disk**, not from the API. Right now security is still on, so 9200 is an HTTPS listener:
a plaintext request to it returns

```
Invoke-RestMethod : The underlying connection was closed: The connection was closed unexpectedly.
```

which is the signature of speaking HTTP to a TLS port, not of Elasticsearch being down. (Windows
PowerShell 5.1 has no `-SkipCertificateCheck`, so querying it properly would mean credentials and a
certificate-policy workaround — not worth it for a version string.)

Any of these work, in order of preference:

```powershell
# 1. The Elastic Agent already on this box — matched to the stack by definition.
& 'C:\Program Files\Elastic\Agent\elastic-agent.exe' version

# 2. Kibana's own package manifest.
(Get-Content 'C:\path\to\kibana\package.json' | ConvertFrom-Json).version

# 3. The Elasticsearch jar filename, e.g. elasticsearch-8.15.3.jar
Get-ChildItem 'C:\path\to\elasticsearch\lib\elasticsearch-*.jar' | Select-Object -ExpandProperty Name
```

If you would rather hit the live API, `curl.exe` ships with Windows and can ignore the cert:

```powershell
curl.exe -sk -u elastic https://localhost:9200
```

**This stack is 9.5.0** (`elastic-agent version` → `Binary: 9.5.0`, build 2026-07-29). Bake the sensor
with:

```bash
ELASTIC_VERSION=9.5.0 ./bake-cybr400-loggen-template.sh
```

The script refuses to run without it, because a mismatched agent installs cleanly and then fails to
ship — which reads as a network or DNS problem. The 9.5.0 Linux artifact is confirmed present
(423 MB), and the download path is unchanged from 8.x.

Re-read the version if this box is ever upgraded; the sensor image has to be re-baked to match.

> After step 2 disables security, `Invoke-RestMethod http://localhost:9200` starts working — and that
> transition is itself the proof the step landed.

---

## 1. Remove Fleet from this box

Record the stack version first (step 0) — uninstalling the agent removes the easiest way to read it.

```powershell
# The enrolled agent on this machine, and the Fleet Server it ran.
& 'C:\Program Files\Elastic\Agent\elastic-agent.exe' uninstall --force --skip-fleet-audit
```

### `--skip-fleet-audit` is not optional once security is off

The uninstaller's first act is to notify Fleet Server that the agent is unenrolling. If Fleet Server
is already dead — which it is the moment step 2 disables security, because Fleet cannot run without
it — that call fails and **retries with backoff for minutes**:

```
notify Fleet: network error: fail to notify audit/unenroll on fleet-server: all hosts failed:
  ... Post "https://localhost:8221/api/fleet/agents/<id>/audit/unenroll?":
  dial tcp 127.0.0.1:8221: connectex: No connection could be made ... (retry in 2.4s)
```

`--skip-fleet-audit` is supposed to skip that call. **It does not help when the agent being removed
IS the Fleet Server**, which is the case here — Elastic have an open issue for it ("elastic-agent
installed as Fleet server remains stuck in uninstalling with retry errors for over 4-5 minutes").
The retries are bounded, so it completes on its own, just slowly.

If you run this step **before** step 2, Fleet Server is still alive, the notification succeeds, and a
plain `--force` uninstall finishes immediately. That is the reason for the ordering.

**Force removal is acceptable here.** This box is about to become a template and Fleet is being
abandoned, so a graceful uninstall buys only a tidy record in a UI that is being turned off:

```powershell
Get-Process elastic-agent,fleet-server,filebeat,metricbeat -ErrorAction SilentlyContinue |
  Stop-Process -Force
Stop-Service 'Elastic Agent' -Force -ErrorAction SilentlyContinue
sc.exe delete "Elastic Agent"
Remove-Item 'C:\Program Files\Elastic\Agent' -Recurse -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Get-Service 'Elastic Agent' -ErrorAction SilentlyContinue    # expect: nothing
Test-Path 'C:\Program Files\Elastic\Agent'                   # expect: False
```

Unenrolling in the Kibana Fleet UI is unnecessary — the agents disappear with the Fleet Server, and
step 3 turns the page off entirely.

---

## 2. Elasticsearch — security off, and set it to start on boot

Edit `config\elasticsearch.yml`:

```yaml
cluster.name: cybr400
node.name: elk

network.host: 0.0.0.0
http.port: 9200

# Required. Without it, binding a non-loopback address promotes Elasticsearch to
# "production" mode and it refuses to start on the bootstrap checks.
discovery.type: single-node

# All four. `xpack.security.enabled: false` alone is NOT enough: the TLS layers
# are separate settings, so leaving http.ssl enabled keeps 9200 an HTTPS
# listener and every plaintext client keeps getting "the connection was closed
# unexpectedly" — the exact error that showed security was still on.
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
```

Then **delete the auto-configuration leftovers** the installer wrote:

```yaml
# DELETE THESE
cluster.initial_master_nodes: ["PACKERC-JB8JOMK"]   # see below — this one matters
http.host: 0.0.0.0                                  # redundant with network.host

# KEEP the `enabled` lines, delete only the cert paths beneath them.
# Removing `enabled` entirely makes Elasticsearch refuse to boot — see below.
xpack.security.http.ssl.enabled: false
#   keystore.path: certs/http.p12                   <- delete
xpack.security.transport.ssl.enabled: false
#   verification_mode: certificate                  <- delete
#   keystore.path: certs/transport.p12              <- delete
#   truststore.path: certs/transport.p12            <- delete
```

### The two edits are a PAIR — one without the other breaks startup

Deleting `cluster.initial_master_nodes` and adding `discovery.type: single-node` have to happen
together. Do only the delete and Elasticsearch fails its discovery bootstrap check:

```
the default discovery settings are unsuitable for production use; at least one of
[discovery.seed_hosts, discovery.seed_providers, cluster.initial_master_nodes] must be configured
```

`network.host: 0.0.0.0` is what makes Elasticsearch consider this a production deployment and enforce
those checks at all. `discovery.type: single-node` both self-bootstraps the node and bypasses them —
which is why it is not optional here, and why setting *both* it and `initial_master_nodes` is refused.

Your final active settings should be exactly:

```yaml
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false

cluster.name: cybr400
node.name: elk

network.host: 0.0.0.0
http.port: 9200

discovery.type: single-node
```

### Keep the two `ssl.enabled: false` lines — deleting the blocks is NOT equivalent

The obvious tidy-up is to delete the `xpack.security.http.ssl` / `transport.ssl` stanzas entirely and
rely on the defaults. **That does not work**, and the failure is a boot-time crash:

```
fatal exception while booting Elasticsearch
org.elasticsearch.ElasticsearchSecurityException: invalid configuration for xpack.security.transport.ssl
 - [xpack.security.transport.ssl.enabled] is not set, but the following settings have been configured
   in elasticsearch.yml : [xpack.security.transport.ssl.keystore.secure_password,
                           xpack.security.transport.ssl.truststore.secure_password]
```

The `secure_password` entries live in the **Elasticsearch keystore** (`config\elasticsearch.keystore`),
not in `elasticsearch.yml` — despite what the message says — so removing the YAML leaves them behind.
Elasticsearch then sees TLS settings configured with no explicit `enabled`, calls that invalid, and
exits 1.

So: set both to `false` explicitly. Deleting only the `keystore.path` / `truststore.path` /
`verification_mode` lines is fine; deleting the `enabled` line is not.

Optionally, once it boots, drop the dead keystore entries so the template stops carrying TLS material
it will never use:

```powershell
.\bin\elasticsearch-keystore.bat list
.\bin\elasticsearch-keystore.bat remove xpack.security.transport.ssl.keystore.secure_password
.\bin\elasticsearch-keystore.bat remove xpack.security.transport.ssl.truststore.secure_password
.\bin\elasticsearch-keystore.bat remove xpack.security.http.ssl.keystore.secure_password
```

### `cluster.initial_master_nodes` is the trap

The installer writes it with **the hostname of the machine Elasticsearch was installed on** — here
`PACKERC-JB8JOMK`, the Packer build box — while `node.name` is now `elk`. It names a node that does
not exist.

It survives unnoticed because the setting only applies at the *very first* bootstrap: once a cluster
has formed, later starts ignore it. But wipe the data directory, or bring up a clone that
re-initialises, and Elasticsearch starts, listens on 9200, and answers every request with
`master_not_discovered_exception` — which presents as a hung Elasticsearch rather than a
configuration error.

It is also **mutually exclusive with `discovery.type: single-node`**: set both and Elasticsearch
refuses to start. So removing it is not optional once you add the line above.

### `cluster.name` — confirmed safe to change

This was flagged as a risk and then tested: renaming an existing single-node cluster from
`elasticsearch` to `cybr400` against its existing data directory is accepted. The boot log shows
`node name [elk], node ID [...], cluster name [cybr400]` and carries on. The name check that bites is
the inter-node handshake, and there are no other nodes.

Note the log FILENAME follows it — the live log is now `logs\cybr400.log`.

> Verified against the current Elasticsearch reference for 9.x: `xpack.security.enabled` still exists,
> still defaults to `true`, and is still settable to `false` — no deprecation or removal notice. It is
> only marked "not recommended", which is a production caution, not a restriction.

> Why security off: TLS certificates are issued to the hostname at install time and service tokens are
> bound to cluster state. Cloning a machine and letting cloudbase-init rename it invalidates both.
> Disabling security deletes that entire class of failure instead of re-issuing per clone, and reduces
> the sensor's agent config to a URL. These lanes are isolated and not internet-reachable.

**Fix the start type — this is finding #2:**

```powershell
Set-Service elasticsearch-service-x64 -StartupType Automatic
```

**Pin the heap** so it stops depending on the clone's RAM. Create `config\jvm.options.d\heap.options`:

```
-Xms2g
-Xmx2g
```

The installer sizes the heap from physical RAM *at install time*, and the VirtIO balloon service
reclaims guest memory afterwards, so a clone given less RAM than the build machine can leave the JVM
unable to start. Keep `-Xmx` under half of what the box actually has
(`Get-CimInstance Win32_PhysicalMemory`) and under 31 GB.

Restart and prove it answers with no credentials:

```powershell
Restart-Service elasticsearch-service-x64
Invoke-RestMethod http://localhost:9200        # cluster banner, no auth
Invoke-RestMethod http://localhost:9200/_cluster/health | Format-List status, number_of_nodes
```

**If either fails, run Elasticsearch in the foreground** — it prints the reason to the console instead
of making you find it, and it is the fastest thing you can do here:

```powershell
Stop-Service elasticsearch-service-x64        # frees the port and the node lock
cd 'C:\path\to\elasticsearch'
.\bin\elasticsearch.bat
```

> The Windows service reports **started** as soon as the JVM wrapper launches, *not* when the node is
> ready — so `Get-Service` showing `Running` proves nothing. Repeated "Waiting for service to start"
> warnings usually mean it is dying and being retried.

> **The log filename tracks `cluster.name`.** After renaming the cluster to `cybr400` the live log is
> `logs\cybr400.log`; any `logs\elasticsearch.log` is stale history from before the rename and will
> point you at an error you already fixed.

Read the failures rather than retrying:

| Symptom | Cause |
|---|---|
| `status: yellow` or `green`, `number_of_nodes: 1` | correct. **yellow is expected** on a single node: replica shards cannot be assigned with nowhere to put them, so any index created with `number_of_replicas: 1` stays yellow forever. Kibana starts fine against it. Only a cluster with every index at 0 replicas goes green |
| "connection was closed unexpectedly" | still TLS — an `http.ssl` block still says `enabled: true` |
| "Unable to connect to the remote server" | different failure: nothing is listening. TLS is off, but the node is not up — go to the foreground start above |
| Service will not start; log says *"default discovery settings are unsuitable for production use"* | `discovery.type: single-node` is missing — you deleted `initial_master_nodes` without adding it |
| Service will not start; log names both `discovery.type` and `cluster.initial_master_nodes` | both are set; remove `initial_master_nodes` |
| `master_not_discovered_exception`, or `_cluster/health` hangs | `cluster.initial_master_nodes` still names a node that does not exist |
| Boots and dies: *"invalid configuration for xpack.security.transport.ssl — [enabled] is not set, but the following settings have been configured"* | you deleted the whole `ssl` block; the `secure_password` entries remain in the keystore. Restore `xpack.security.{http,transport}.ssl.enabled: false` |
| Service will not start, none of the above | suspect the `cluster.name` change against an existing data directory — put the old name back |

---

## 3. Kibana

Edit `config\kibana.yml`:

```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]

# Fleet's agent UI and API. Turning this off stops Kibana logging a stream of
# Fleet errors now that there is no Fleet Server and no security.
#
# Do NOT use `xpack.fleet.enabled: false`. It is incompatible from 8.x onward and
# takes the Security Solution plugin down with it through a transitive
# dependency; it is not in the 9.x settings reference at all. The line below is
# the documented switch ("Set to true (default) to enable Fleet").
xpack.fleet.agents.enabled: false

# Closed lab: nothing here can reach the internet, and both of these try to.
# Kibana's own APM agent posts to kibana-cloud-apm.apm.us-east-1.aws.found.io
# and telemetry to telemetry.elastic.co; in an isolated lane those attempts sit
# waiting for a timeout on every start. Turning them off removes the stall and
# the log noise, and stops a teaching lab phoning home about itself.
telemetry.optIn: false
telemetry.allowChangingOptInStatus: false
```

To silence Kibana's bundled APM agent as well, add an environment variable to the
service (it is not a `kibana.yml` setting):

```powershell
& 'C:\CyberCore\nssm.exe' set Kibana AppEnvironmentExtra ELASTIC_APM_ACTIVE=false
Restart-Service Kibana
```

**Delete** these if present — they are bound to the old secured cluster and are meaningless now:

- `elasticsearch.serviceAccountToken` / `elasticsearch.username` / `elasticsearch.password`
- `elasticsearch.ssl.*` (including `certificateAuthorities`)
- `xpack.fleet.outputs` and any other `xpack.fleet.*` enrolment leftovers

### `elasticsearch.hosts` must be `localhost` — the setup wizard hardcodes an IP

Kibana's generated block points at the machine's address **at setup time**:

```yaml
elasticsearch.hosts: [https://100.100.10.142:9200]     # WRONG on every clone
```

Two faults. `https` no longer matches an unsecured cluster — but the IP is the one that survives every
other check and then breaks all thirty lanes at once. `100.100.10.142` is this box's address on the
*build* network; a deployed lane machine comes up on `10.<a>.<b>.50`, so the hardcoded address points
at nothing. Kibana starts, retries, and shows "Kibana server is not ready yet" forever.

Kibana and Elasticsearch are on the same machine, so the address that is correct in every lane is:

```yaml
elasticsearch.hosts: ["http://localhost:9200"]
```

The same trap applies to `xpack.fleet.outputs`, which embeds the same IP plus a
`ca_trusted_fingerprint` for a CA that no longer exists. Delete it outright.

Set the three encryption keys to fixed 32+ character strings so saved objects survive a restart rather
than being re-keyed every boot:

```yaml
xpack.encryptedSavedObjects.encryptionKey: "<32+ chars>"
xpack.reporting.encryptionKey: "<32+ chars>"
xpack.security.encryptionKey: "<32+ chars>"
```

### Re-register the service — this is the actual fix

Two changes matter, and both are the difference between working on one machine and working on thirty:
move NSSM somewhere stable, and run the service as **LocalSystem** so no rotating password can lock it
out.

```powershell
$svc  = 'Kibana'
$root = 'C:\path\to\kibana'          # the real Kibana directory on this box
$nssm = 'C:\CyberCore\nssm.exe'

New-Item -ItemType Directory 'C:\CyberCore' -Force | Out-Null
Copy-Item 'C:\Users\cactus-user\Downloads\nssm\nssm-2.24\win64\nssm.exe' $nssm -Force

# Remove the old definition rather than editing it — the stored credential for
# .\cactus-user lives in LSA secrets and does not go away on its own.
& $nssm stop   $svc
& $nssm remove $svc confirm

& $nssm install $svc "$root\bin\kibana.bat"
& $nssm set $svc AppDirectory      $root
& $nssm set $svc DisplayName       "Kibana"
& $nssm set $svc Start             SERVICE_DELAYED_AUTO_START
& $nssm set $svc DependOnService   elasticsearch-service-x64

# THE FIX. LocalSystem has no password to rotate, so cloudbase-init resetting
# cactus-user on every deploy can no longer stop this service from starting.
& $nssm set $svc ObjectName        LocalSystem

# kibana.bat spawns node; without this NSSM stops the wrapper and orphans the child.
& $nssm set $svc AppKillProcessTree 1

# Elasticsearch reports "started" well before :9200 accepts connections, so Kibana
# may exit once on a cold boot. These turn that into a retry rather than a service
# that gives up and stays stopped.
& $nssm set $svc AppThrottle       60000
& $nssm set $svc AppExit Default   Restart
& $nssm set $svc AppRestartDelay   20000

& $nssm set $svc AppStdout "C:\CyberCore\kibana-service.out.log"
& $nssm set $svc AppStderr "C:\CyberCore\kibana-service.err.log"

Start-Service $svc
Get-CimInstance Win32_Service -Filter "Name='Kibana'" | Format-List Name, PathName, StartName, State
```

`StartName` must now read `LocalSystem`. If it still shows `.\cactus-user`, the remove/install did not
take — that is the whole point of this step.

---

## 4. Self-healing boot task

`DependOnService` waits for the Elasticsearch *service* to report started, not for port 9200 to accept
connections, which takes another 30–90 seconds. NSSM's restart policy covers most of that; this covers
the rest, and recovers the box if Kibana dies hours into a class.

Scheduled tasks survive cloning — the repo already relies on that for `CyberCore-HideConfigDrive`.

Save as `C:\CyberCore\Start-ElkStack.ps1`:

```powershell
$ErrorActionPreference = 'Continue'
$log = 'C:\CyberCore\elk-boot.log'
function Log($m) { "$(Get-Date -Format s)  $m" | Out-File $log -Append -Encoding utf8 }

# Elasticsearch is Automatic, but belt-and-braces: a clone that came up oddly
# should not need a human.
$es = Get-Service elasticsearch-service-x64 -ErrorAction SilentlyContinue
if ($es -and $es.Status -ne 'Running') { Log 'starting elasticsearch'; Start-Service $es.Name }

# Wait for it to actually ACCEPT connections, not merely to be "started".
$deadline = (Get-Date).AddMinutes(10)
$up = $false
while ((Get-Date) -lt $deadline) {
    $up = Test-NetConnection 127.0.0.1 -Port 9200 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($up) { break }
    Start-Sleep -Seconds 10
}
Log "elasticsearch listening on 9200: $up"

$k = Get-Service Kibana -ErrorAction SilentlyContinue
if ($k -and $k.Status -ne 'Running') {
    Log "kibana was $($k.Status) — starting"
    Start-Service Kibana -ErrorAction SilentlyContinue
}
Log "kibana status: $((Get-Service Kibana -ErrorAction SilentlyContinue).Status)"

# Mappings, retention and the professor's dashboard. Safe to call every boot --
# it waits for Kibana itself, imports once, and drops a marker. See section 4b.
if (Test-Path 'C:\CyberCore\Import-CybrDashboard.ps1') {
    Log 'running dashboard import'
    & 'C:\CyberCore\Import-CybrDashboard.ps1'
}
```

Register it:

```powershell
$a = New-ScheduledTaskAction -Execute 'powershell.exe' `
     -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\CyberCore\Start-ElkStack.ps1"'
$t = New-ScheduledTaskTrigger -AtStartup
$t.Delay = 'PT60S'
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'CyberCore-ELK-Boot' -Action $a -Trigger $t -Principal $p -Settings $s -Force
```

---

## 4b. The professor's dashboard

Kibana ships dashboards for the *System* integration (Windows event logs, syslog, SSH). None of them
know anything about `logs-loggen.*`, so out of the box a professor opening Kibana sees a dashboard
list with nothing relevant in it.

Two files from the repo go on the box, both into `C:\CyberCore\`:

| File | Purpose |
|---|---|
| `cybr400-kibana/cybr400-loggen-dashboard.ndjson` | Data view + 7 Lens panels + the dashboard |
| `cybr400-kibana/Import-CybrDashboard.ps1` | Applies mappings and retention, then imports the above |

```powershell
# From wherever you have the repo checked out, or copy them over RDP.
Copy-Item .\cybr400-kibana\cybr400-loggen-dashboard.ndjson C:\CyberCore\
Copy-Item .\cybr400-kibana\Import-CybrDashboard.ps1        C:\CyberCore\

# Run it once by hand to confirm before templating.
# NOTE: this is a PowerShell prompt. From cmd.exe, typing a .ps1 path does not
# run it -- cmd hands the file to its association and you get Notepad.
& 'C:\CyberCore\Import-CybrDashboard.ps1' -Force -Verbose
Get-Content C:\CyberCore\dashboard-import.log -Tail 20
```

From `cmd.exe`, or anywhere the execution policy is unset, invoke the interpreter explicitly:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\CyberCore\Import-CybrDashboard.ps1" -Force -Verbose
```

Then open `http://localhost:5601/app/dashboards#/view/cybr400-dashboard`.

**The mappings are the load-bearing part, not the panels.** The script applies a `logs@custom`
component template that types `loggen.source.type`, `loggen.level` and `loggen.mitre.technique` as
`keyword`. Without it those fields arrive under dynamic mapping, can land as `text`, and every
terms-based panel renders *empty* — the dashboard imports cleanly and simply shows nothing, which is
a miserable thing to debug in front of a class. `loggen.metadata` is mapped `flattened` because
log-generator emits a different metadata shape per generator and does not substitute its placeholders
at the pinned commit; mapping those keys individually invites a type conflict, and a type conflict on
a data stream does not warn, it rejects the document.

A component template only affects indices created after it lands, so the script also rolls the data
stream. A 404 on the rollover is normal on a box where no events have shipped yet.

### Where the attack telemetry now comes from

Attack runs no longer use log-generator. `--mitre-technique` is a filter, not a simulator: it runs
every generator at its configured rate and tags the lines whose text happens to match a keyword.
Measured on a deployed lane, one `T1005` run wrote 37,004 lines of which **76** carried the technique,
30,571 of them API-gateway records. T1005 is "read files off a local host", and log-generator has no
process, file or registry source at all.

So the attack half is generated by `cc-emit.js` from per-technique **playbooks** — all 15 techniques
and all 3 chains. The benign baseline stays on log-generator, which is good at generic enterprise
noise. A technique without a playbook still falls back to the old filter path.

**`cc-hostbase` now produces the entire benign baseline**, and `loggen-baseline` is disabled by
default (`LOGGEN_BASELINE_ENABLED=0`). log-generator stays installed, and setting that knob to `1`
puts it back.

| | writes | state |
|---|---|---|
| `cc-hostbase` | `logs/current/host.json` | **enabled** — ~125k events/day across 25 source/name pairs |
| `loggen-baseline` | `logs/current/logs.json` | **disabled**, retained as a fallback |

It was retired for four reasons, in order of cost:

1. **It never substitutes its metadata placeholders.** Every event it emits ships literal
   `"clientIP":"{clientIP}"`, `"method":"{method}"` into Kibana. Obviously synthetic to anyone who
   opens an event — and a *discriminator*, since emitter events have clean metadata. The same class of
   leak as a dataset name, sitting in the benign half where it is hardest to notice.
2. **It is flat 24/7** and cannot be made otherwise without retuning and restarting it hourly, and a
   restart that does not first rename `logs.json` risks filestream re-reading from offset 0.
3. **Every workaround in the bake exists to manage it** — the `frequency <= 20` batch cliff, 54,609
   `.jsonl` files stalling guest-exec, `rotation: false`, the rename-and-restart dance.
4. **One engine now drives both halves**, so benign and hostile traffic are identical in shape by
   construction rather than by hand-maintained parity. That parity had already drifted twice.

The benign stream runs a working week: about 0.27 events/sec at 03:00 against 2.89/sec at the morning
peak, with a lunch dip and weekends at ~22% of a weekday. That shape is not decoration — "unusual
hour" is a signal an analyst uses constantly, and it only exists if the ordinary hours look ordinary.

**`cc-hostbase` is not optional.** log-generator has no `host` source type, so without it every host
event in the index belongs to an instructor's attack and one terms click ends the exercise. It also
supplies the benign floor for every `(source.type, source.name)` pair the playbooks use — `sshd`,
`iptables`, `firewalld`, `postgres-primary` and the rest. A pair that only ever appears during an
attack is a better answer key than a dataset name would have been. `loggen-playbooks.test.js` enforces
this mechanically, because no code review catches it.

Four pre-seal checks refuse to seal an image that would break this: `CC_EMIT`, `CC_EMIT_PARSES`,
`HOST_PB`, `HOSTBASE_SERVICE`.

---

### Nothing here tells a student which events are the attack

That is deliberate, and it took closing three separate leaks — the dashboard was only the visible one:

| Leak | Fix |
|---|---|
| Panels split on `data_stream.dataset` | Timeline now splits on `loggen.source.type`; the "Attack events" metric became "Warnings & errors" |
| Discover offers `loggen.attack` / `loggen.baseline` as a one-click field | Both agent inputs ship to a single `loggen.events` dataset |
| Only attack events carried `loggen.mitre.*`, so `mitre.technique : *` was a perfect answer key | `BASELINE_STRIP_MITRE` now defaults to `0`, leaving MITRE labels on ~15% of benign traffic |
| A "MITRE techniques observed" panel read the labels straight off raw events | Panel removed entirely — replaced by "Authentication warnings & errors" and "Top source hosts" |

That last one is a realism fix as much as an answer-key fix. **Raw logs in a real environment carry no
ATT&CK labels.** A firewall log, an nginx access line, a Windows 4625 — none of them know what a
technique is. Attribution is produced by *detection rules* and lands on an alert, as ECS
`threat.technique.id`, never on the event. Elastic Security's own "MITRE ATT&CK coverage" view shows
which techniques your **rules** cover, not which appear in your logs. Aggregating
`loggen.mitre.technique` off raw documents is an artifact of synthetic data, so the panel is gone and
the dashboard reads like a real raw-log overview: volume by source, severity rate, failed auth, top
talkers.

The genuinely realistic version of that second tier — actual detection rules producing alerts — is
**not available on this stack**. The Elastic detection engine requires `xpack.security.enabled: true`,
and section 2 turns security off on purpose to fix the certificate and cloning failures. Building an
alerting layer means reversing that decision first.

Fixing only the dashboard would have been cosmetic: the dataset dropdown sits in Discover's field list
whatever the dashboard does, and the MITRE oracle is the first thing a curious student clicking
through fields would trip over.

**Attack events carry no MITRE label.** The agent's `drop_event` uses
`loggen.mitre.technique` to decide what ships, and a `drop_fields` immediately after it removes the
field before the event leaves the box. Order is the mechanism — reverse those two processors and every
attack event is discarded, because the field the filter tests no longer exists.

This does not create the reverse oracle. Roughly 88% of benign traffic is already untagged
(log-generator labels ~15% of its output, the host baseline ~10%), so `NOT loggen.mitre.technique : *`
returns overwhelmingly ordinary events with the attack a small fraction inside — which is the shape a
hunt should have.

**There is deliberately no in-index discriminator any more.** `log.file.path` used to serve as one,
on the reasoning that it was less discoverable than a dataset name. That reasoning does not survive
contact with Discover: the field appears in the field list like any other, with exactly two values —
`/opt/log-generator/...` and `/opt/log-generator-attack/...` — so one click on the second enumerated
the instructor's entire run. It was a *direct match*, which makes it easier than the oracles it sat
alongside, and clicking through the field list is precisely what a beginner does. It is now dropped
from **both** inputs; dropping it from only the attack tree would have left its absence as the same
oracle inverted.

**Verify a run through the Attack Console instead.** The console reports the emitter's own event
count per lane on the run's state line, read back over guest-exec. That path is admin-only and cannot
leak into the student's index. On the sensor itself:

```sh
# the per-run file still exists on disk, it is just no longer labelled in Kibana
ls -la /opt/log-generator-attack/logs/current/attack-*.json
grep -c '"technique":"' /opt/log-generator-attack/logs/current/attack-<RUN_ID>.json
```

If you need the field back temporarily to debug an ingest problem on one lane, remove
`log.file.path` from the `drop_fields` list in `/opt/Elastic/Agent/elastic-agent.yml` on that lane
only and restart the agent — then put it back before the next class.

For a genuinely hard assignment, pick a technique that the baseline *also* emits — `T1078`, `T1098`,
`T1110`, `T1110.001`, `T1496`, `T1499`, `T1562.001`, `T1562.004` or `T1059.003`. Those nine are in
both `loggen-catalog.js` and the stock baseline templates, so the technique label alone cannot
separate the attack from the noise and the student has to work from timing, volume and source.

**This depends on the sensor re-bake.** The panels read `loggen.*` fields, which only exist once the
Elastic Agent config carries the `ndjson` parser (`parsers: - ndjson: target: loggen`). Against a
sensor baked before that change, the whole log line sits in `message` as one opaque string: the two
metric panels still work, because they only count documents, but every terms panel will be empty.
Re-bake the sensor first, or expect exactly that.

The import is idempotent and marker-guarded, so a professor who rearranges the dashboard keeps their
layout across reboots. `-Force` re-imports and overwrites.

---

## 5. Firewall

```powershell
New-NetFirewallRule -DisplayName 'CYBR400 Elasticsearch 9200' -Direction Inbound `
  -Protocol TCP -LocalPort 9200 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'CYBR400 Kibana 5601' -Direction Inbound `
  -Protocol TCP -LocalPort 5601 -Action Allow -Profile Any
```

A workgroup Windows box treats the lane as an "unidentified network" and blocks inbound by default.
The sensor failing this way looks **exactly** like a DNS problem. 9200 is the one that matters;
students reach Kibana over RDP at `localhost:5601`, and 5601 is open so you can also browse it from the
sensor while debugging.

---

## 6. Leave cloudbase-init alone

```powershell
Get-Service cloudbase-init | Format-Table Name, Status, StartType   # expect Automatic
```

Tempting to disable it while fighting Kibana. Don't. The CLE workstation path sets
`citype=configdrive2` for Windows and relies on cloudbase-init to inject the RDP account — disable it
and every student gets a login failure with nothing explaining why. `ExtendVolumesPlugin` also stops
growing the disk.

It **will** rename the clone and rotate `cactus-user`'s password. Both are now harmless: nothing
depends on the Windows computer name (step 9), and no service runs as that account any more (step 3).

---

## 7. The sensor side

### How the two machines actually connect

Worth being explicit, because the direction is easy to get backwards: **Kibana never talks to the
agent.** Removing Fleet removed the only thing that ever did.

```
Rocky sensor (Linux)                          Windows ELK box
────────────────────                          ───────────────
log-generator writes
  logs/current/*.json
        |
        v
  Elastic Agent  ---- PUSHES over the lane --->  Elasticsearch :9200
  (standalone)        http://elk.cybercore.lan         |
                                                       v
                                                    Kibana :5601
                                                    READS localhost:9200
```

The sensor initiates the only cross-machine link. So what makes this work is Elasticsearch being
reachable across the lane — `network.host: 0.0.0.0` (step 2), the 9200 firewall rule (step 5), and the
`elk` DNS alias (step 9) — not anything in `kibana.yml`.

**Consequence to expect:** with no Fleet there is no agent listed anywhere in Kibana — no Agents page,
no health indicator. The only evidence the sensor is working is documents arriving in Discover. That is
the trade for removing per-clone enrollment, and it is why step 10 checks Kibana for documents rather
than checking a status page.


The Rocky machine's agent is currently **enrolled into Fleet**, which cannot survive templating. Two
paths:

- **Re-bake (preferred)** — `bake-cybr400-loggen-template.sh` installs a standalone agent from scratch
  with the correct config. Pass `ELASTIC_VERSION=<the version from step 0>`.
- **Reuse the existing machine** — un-enroll before re-templating, or every clone ships the same agent
  identity:
  ```bash
  sudo elastic-agent uninstall --force
  # then reinstall standalone with /etc/elastic-agent/elastic-agent.yml in place
  ```

The standalone config the bake writes needs no credentials and no TLS now:

```yaml
outputs:
  default:
    type: elasticsearch
    hosts: ["http://elk.cybercore.lan:9200"]
```

---

## 8. Clean up and re-template

### Moving Kibana or Elasticsearch? Re-register the service

NSSM stores the **absolute path** to `kibana.bat` at registration time, so relocating the folder
(e.g. out of `Downloads` to `C:\kibana`) silently breaks the service — it will have started fine
before the move and fail after it. Re-run the whole install block from step 3 with the new `$root`;
do not try to patch it, since the LSA-stored credential from the old definition needs clearing anyway.

The same applies to Elasticsearch: its Windows service was registered by `elasticsearch-service.bat`
against a fixed path. Relocating it means `elasticsearch-service.bat remove` then `install` again.

### Pre-template checklist

Run this before `qm template`. Several of these fail silently on a clone rather than on this machine,
which is exactly the class of problem worth catching once instead of thirty times.

```powershell
$fail = 0
function Chk($name, $cond, $fix) {
  if ($cond) { Write-Host ("  OK    " + $name) -ForegroundColor Green }
  else { Write-Host ("  FAIL  " + $name + "  ->  " + $fix) -ForegroundColor Red; $script:fail++ }
}
function Reachable($url) { try { $null = Invoke-RestMethod $url -TimeoutSec 5; $true } catch { $false } }

# Both config paths are derived from the REGISTERED SERVICES, so there is no
# placeholder to substitute and nothing to forget after relocating a folder.
# A file that cannot be read is reported as unreadable rather than silently
# rendering every setting inside it as "FAIL" -- which is exactly the false
# alarm a hardcoded path produced the first time this ran.
# NSSM stores the wrapped application in its service registry key. Read it there
# rather than shelling out to `nssm get`, which emits UTF-16 and does not survive
# capture reliably -- it returns an empty string that then throws on Split-Path.
$kibApp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kibana\Parameters' -Name Application -EA SilentlyContinue).Application
$kyml   = if ($kibApp) { Join-Path (Split-Path (Split-Path $kibApp -Parent) -Parent) 'config\kibana.yml' } else { $null }
$esPath = (Get-CimInstance Win32_Service -Filter "Name='elasticsearch-service-x64'").PathName
$esExe  = if ($esPath -match '"([^"]+)"') { $Matches[1] } else { ($esPath -split ' ')[0] }
$eyml   = Join-Path (Split-Path (Split-Path $esExe -Parent) -Parent) 'config\elasticsearch.yml'
Write-Host "kibana.yml        : $kyml"
Write-Host "elasticsearch.yml : $eyml`n"

$kib = Get-CimInstance Win32_Service -Filter "Name='Kibana'" -EA SilentlyContinue
Chk "Kibana runs as LocalSystem"  ($kib.StartName -eq 'LocalSystem') "nssm set Kibana ObjectName LocalSystem"
Chk "Kibana app path exists"      ($kibApp -and (Test-Path $kibApp)) "re-run step 3 after moving the folder"
Chk "Elasticsearch is Automatic"  ((Get-Service elasticsearch-service-x64 -EA SilentlyContinue).StartType -eq 'Automatic') "Set-Service ... -StartupType Automatic"
Chk "Fleet agent removed"         ($null -eq (Get-Service 'Elastic Agent' -EA SilentlyContinue)) "elastic-agent.exe uninstall --force"
Chk "cloudbase-init is Automatic" ((Get-Service cloudbase-init -EA SilentlyContinue).StartType -eq 'Automatic') "must stay Automatic or RDP creds break"
Chk "boot task registered"        ($null -ne (Get-ScheduledTask -TaskName 'CyberCore-ELK-Boot' -EA SilentlyContinue)) "step 4"
Chk "boot script present"         (Test-Path 'C:\CyberCore\Start-ElkStack.ps1') "step 4 - the task cannot run without it"
Chk "dashboard ndjson present"    (Test-Path 'C:\CyberCore\cybr400-loggen-dashboard.ndjson') "step 4b"
Chk "dashboard importer present"  (Test-Path 'C:\CyberCore\Import-CybrDashboard.ps1') "step 4b"
Chk "loggen component template"   ((Invoke-RestMethod "http://localhost:9200/_component_template/logs@custom" -EA SilentlyContinue) -ne $null) "step 4b - without it every terms panel renders empty"
Chk "firewall 9200 open"          ($null -ne (Get-NetFirewallRule -DisplayName '*Elasticsearch 9200*' -EA SilentlyContinue)) "step 5 - the sensor cannot ship without it"

if (-not $kyml -or -not (Test-Path $kyml)) { Chk "kibana.yml readable" $false "could not locate it from the Kibana service" }
else {
  $k = Get-Content $kyml -Raw
  Chk "no serviceAccountToken"    ($k -notmatch '(?m)^\s*elasticsearch\.serviceAccountToken') "delete the line"
  Chk "no certificateAuthorities" ($k -notmatch '(?m)^\s*elasticsearch\.ssl\.certificateAuthorities') "delete the line"
  Chk "no xpack.fleet.outputs"    ($k -notmatch '(?m)^\s*xpack\.fleet\.outputs') "delete the line"
  Chk "no hardcoded IP for ES"    (($k -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -notmatch '\d+\.\d+\.\d+\.\d+:9200') "use http://localhost:9200"
}

if (-not (Test-Path $eyml)) { Chk "elasticsearch.yml readable" $false "not found at $eyml" }
else {
  $e = Get-Content $eyml -Raw
  Chk "security disabled"           ($e -match '(?m)^\s*xpack\.security\.enabled:\s*false') "step 2"
  Chk "http.ssl.enabled false"      ($e -match '(?m)^\s*xpack\.security\.http\.ssl\.enabled:\s*false') "absent means boot failure"
  Chk "transport.ssl.enabled false" ($e -match '(?m)^\s*xpack\.security\.transport\.ssl\.enabled:\s*false') "absent means boot failure"
  Chk "discovery.type single-node"  ($e -match '(?m)^\s*discovery\.type:\s*single-node') "step 2"
  Chk "no initial_master_nodes"     ($e -notmatch '(?m)^\s*cluster\.initial_master_nodes') "delete it"
}

Chk "ES answers plaintext on 9200" (Reachable 'http://localhost:9200') "start ES"
Chk "Kibana answers on 5601"       (Test-NetConnection 127.0.0.1 -Port 5601 -InformationLevel Quiet -WarningAction SilentlyContinue) "start Kibana"

if ($fail -eq 0) { Write-Host "`nREADY TO TEMPLATE`n" -ForegroundColor Green }
else { Write-Host "`n$fail check(s) failed - do NOT template yet`n" -ForegroundColor Red }
```

Give students an empty stack rather than your test data:

```powershell
Invoke-RestMethod -Method Delete 'http://localhost:9200/logs-loggen*' -ErrorAction SilentlyContinue
```

Then stop cleanly and convert. **No sysprep** — `/generalize` resets the SID, renames the machine and
can disturb service registrations, and buys nothing here: the lane is isolated, the box is not
domain-joined, and the DNS name comes from the gateway. Duplicate SIDs across isolated lanes are
harmless.

```powershell
Stop-Service Kibana
Stop-Service elasticsearch-service-x64
Stop-Computer -Force
```

On the Proxmox node, once it is off:

```bash
qm template <vmid>
```

---

## 9. Register the template

In **Admin → Workstation Templates**, on this image's catalog row:

- `template_type` = `workstation`
- `metadata.dns_aliases` = `["elk"]`
- `metadata.cloud_init_user` = `cactus-user` — and make sure `default_rdp_user` /
  `default_rdp_pass` are **empty**
- `os_family` = `windows_server` (or `windows_client`)

### Use `cloud_init_user`, NOT `default_rdp_user`

These are not interchangeable, and picking the wrong one fails quietly.
`resolveWorkstationCredentials` (src/utils/lane-deployer.js) takes the
`default_rdp_user` branch first, and that branch **skips cloud-init credential
injection entirely** and returns `metadata.default_rdp_pass || null`. With no
password set, every lane shows a blank credential and nothing ever sets a
password on the guest:

```
WARN [LaneDeployer] Template '...' pins default_rdp_user='cactus-user': cloud-init
credential injection is SKIPPED and every lane will show the same static password.
```

`cloud_init_user` is the right branch for this image: cloudbase-init is pinned at
bake time to one account (`conf\cloudbase-init.conf`, `username=`), so it can only
set THAT account's password. Naming it here keeps the account fixed and gives each
lane a freshly generated password. Same reasoning as migrations 025/026.

Confirm the account name on the guest rather than assuming:

```powershell
Get-Content 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf' |
  Select-String 'username'
```

`os_family` matters too: `resolveCitype` only forces `citype=configdrive2` for
`windows*`. Get it wrong and cloudbase-init finds a `nocloud` drive, reads nothing
useful, and reports success having changed nothing.

Changing this metadata does not repair lanes already deployed — redeploy them.

`dns_aliases` is what links the pair. `lane-deployer.js` writes a dnsmasq `host-record` per lane, so
`elk.cybercore.lan` resolves **inside every lane to that lane's own ELK box** — which is what lets the
sensor ship one baked `elastic-agent.yml` with no per-lane templating.

> Do **not** try to achieve this by naming the Windows machine `elk`. cloudbase-init's
> `SetHostNamePlugin` renames every clone to the Proxmox VM name, truncates it to the 15-character
> NetBIOS limit, and with `allow_reboot=false` applies it only at the *next* reboot — so the name it
> advertises is the baked one on first boot and the lane name afterwards. Anything keyed on it works
> until the first reboot and then stops.

---

## 10. Verify on a real lane

Deploy one student: in **Provision Workstation VM**, pick this ELK image as the **first** machine and
the sensor as the **second**. First machine takes `.50` and the gateway's RDP console.

1. Gateway — `cat /etc/dnsmasq.d/lane-workstation.conf`: two `dhcp-host=` lines plus
   `host-record=elk,elk.cybercore.lan,<lan>.50`. Confirm `pgrep dnsmasq` is alive; a malformed line
   there takes DHCP down for the whole lane.
2. On the deployed ELK box, **before touching anything**:
   ```powershell
   Get-CimInstance Win32_Service -Filter "Name='Kibana'" | Format-List StartName, State
   Get-Service elasticsearch-service-x64 | Format-Table Name, Status, StartType
   ```
   `StartName` = `LocalSystem`, both `Running`, Elasticsearch `Automatic`. This is the whole fix,
   observed on a clone rather than on the machine you built.
3. RDP in through the existing console and browse `http://localhost:5601`.
4. On the sensor (SSH via the gateway on port 2223):
   ```bash
   getent hosts elk.cybercore.lan
   curl http://elk.cybercore.lan:9200      # hangs => Windows Firewall, not DNS
   systemctl is-active elastic-agent loggen-baseline
   ```
5. **In Kibana**, confirm `loggen.events` documents are arriving — the `CYBR 400 log-generator` data
   view from step 4b covers it. Events on disk are *not* success; that is the exact failure this
   runbook exists to rule out.
6. **Reboot the ELK box**, wait two minutes, re-check 2, 3 and 5. This is when cloudbase-init's rename
   and password rotation take effect — the conditions that were killing the service. If Kibana is down
   here, read `C:\CyberCore\elk-boot.log`: it will say whether 9200 ever came up.
7. Attack Console → fire `T1082` for 60 s and confirm the attack's documents land. Both the baseline
   and the attack ship to the single `loggen.events` dataset on purpose (see step 4b), and
   `log.file.path` is dropped from both inputs so it cannot be used as a filter either. Verify on the
   sensor rather than in Kibana:

   ```sh
   grep -c '"technique":"' /opt/log-generator-attack/logs/current/*.json
   ```

   then confirm the same count appears in Kibana for the run window without needing a discriminator:
   the count is the check.
