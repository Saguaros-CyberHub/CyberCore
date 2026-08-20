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
| `status: green`, `number_of_nodes: 1` | correct — this is the target |
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
5. **In Kibana**, confirm `loggen.baseline` documents are arriving — create a data view for `logs-*` if
   there isn't one. Events on disk are *not* success; that is the exact failure this runbook exists to
   rule out.
6. **Reboot the ELK box**, wait two minutes, re-check 2, 3 and 5. This is when cloudbase-init's rename
   and password rotation take effect — the conditions that were killing the service. If Kibana is down
   here, read `C:\CyberCore\elk-boot.log`: it will say whether 9200 ever came up.
7. Attack Console → fire `T1082` for 60 s and confirm `loggen.attack` documents land.
