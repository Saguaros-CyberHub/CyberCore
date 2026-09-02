# Track E — Cluster gate (E8)

**Status:** owner-run. Nothing in this document can be executed from a checkout — it needs a live
Proxmox cluster, a real deploy and a browser. Follow it top to bottom in one sitting.

**What the gate proves.** That one `defensive_monitoring` engagement, deployed at v2 for two students,
produces an environment in which a student can actually hunt: the client's own estate appears in
Kibana as ordinary traffic, an instructor-launched intrusion hides inside it with no field that
separates the two, the board grades what was actually emitted, and the answer key never reaches a
student.

**What it does not prove.** Anything about Caldera (E9 ships nothing until this passes), and anything
about backdated history (the emitter writes `loggen.timestamp`, the data view keys on `@timestamp` =
ingest time, and there is no timestamp processor in the agent config — do not design around
pre-seeded history).

**Automation.** `scripts/verify-track-e-lane.sh` runs every assertion below that a machine can run.
Section 6 says how. It does not replace this document: five items genuinely need a browser and it
prints `MANUAL:` for each rather than pretending otherwise.

---

## 0. Read this before you book cluster time

Three things in the current code will stop the gate if you do not decide them first. All three were
verified against the working tree, and where the plan and the code disagree, the code is what will
run.

### 0.1 A `defensive_monitoring` lane has NO student console unless you ask for one

`resolveConsolePlan` picks the primary console in this order: an explicit per-deploy override → a
spec VM carrying `console_role: 'primary'` → the Kali attack box when `attackBoxes` is on → the first
instructor-added workstation → **none**.

On a `defensive_monitoring` lane today:

* `attackBoxes` defaults to **false** for this engagement type (`routes/profile-deploy.js`, the
  `engagement !== BLUE_TEAM_TYPE_KEY` default) — so no Kali;
* the sensor deliberately carries **no** `console_role` (`profile-to-spec.js`: a console there hands
  the student a shell on the machine holding the answer);
* the SIEM machines are appended as ordinary **spec VMs** with `role: 'siem'` and an explicit
  `ipOctet` (elk `.24`, wazuh `.51`) and no `console_role` either;
* CiAB passes no `extraWorkstations` at all.

So `resolveConsolePlan` returns `primary: null, consoles: []`, and the deployer treats that as
success — `consoleDnatOk = consoleTargets.length === 0`. The lane deploys, reports **active**, and the
student has no way to open Kibana. Nothing errors.

**Decide one of these before you deploy.** Both are correct; they are different lane shapes.

| Option | What you do | Consequence |
|---|---|---|
| **A — Kali is the console** (matches E3b, zero code) | Send `attack_boxes: true` on the deploy call | Kali lands at `.50`, becomes the primary console, and the student browses `http://elk.cybercore.lan:5601` from it. This is the shape E3b designed for a headless Linux ELK. Confirm your Kali template actually has a browser. |
| **B — the SIEM is the console** (matches E3, needs a code change) | Give the ELK spec VM `console_role: 'primary'` | Only workable if the tagged ELK template is the **Windows** box (RDP). And note `cloneChallengeVm` never sets `ciuser`/`cipassword` — only `cloneExtraWorkstation` does — so a spec-VM console gets `{username: null, password: null}` in Guacamole: a lane that looks deployed and cannot be logged into. This is risk 3 in the plan, and it is real. |

**Recommendation for the gate: option A.** It needs no code, it is the shape the prebaked Linux ELK
was designed around, and it keeps the gate about telemetry rather than about console plumbing. Record
in the gate notes that a blue-team lane currently ships a Kali box, and that closing that gap is a
follow-up.

### 0.2 The plan's assertion 4 cannot be read from Kibana, and must not be

The plan says: *"Post-run it returns exactly `answer_key.techniques`."* It cannot. The sensor's baked
`elastic-agent.yml` drops `loggen.mitre` **and** `log.file.path` from every attack event before it
leaves the box (bake markers `ATTACK_STRIP_TAG` / `ATTACK_DROP_UNTAGGED`, pinned by
`front-end/test/bake-payloads.test.js`). An attack event arriving stamped with its technique would put
the entire run one filter away from full enumeration — which is exactly what the bake is preventing.

So the assertion splits in two, and both halves are checked in §4:

* **A4a (Elasticsearch):** the queryable technique set must **not** contain the attack's techniques.
  That is proof the strip worked.
* **A4b (sensor + database):** the raw attack file on the sensor still carries the tags, and that set
  must equal `answer_key.techniques`; and `cybercore_incident_target.event_count` must equal
  `answer_key.totals.events`. That is proof the run emitted what the board graded.

Do not "fix" this by removing the `drop_fields`. It would require a re-bake of template 1007 and a
redeploy of every existing lane, and it would delete the exercise.

### 0.3 Kibana mappings are applied by a PowerShell script that only runs on the Windows ELK box

`loggen.source.host`, `loggen.source.type`, `loggen.level`, the fourteen `loggen.metadata.*` fields
and `loggen.mitre.*` are aggregatable **only** because
`infrastructure/proxmox-templates/vm-templates/cybr400-kibana/Import-CybrDashboard.ps1` installs the
`logs@custom` component template, rolls `logs-loggen.events-default`, and imports the data view and
both dashboards. On the Windows ELK box that runs at boot from `Start-ElkStack.ps1`.

**On a prebaked Linux GOAD ELK it does not run at all.** Without it the `loggen.*` fields land under
dynamic mapping, string fields can type as `text`, and *every* terms aggregation in §4 — plus every
terms panel on both dashboards — silently returns empty. The dashboard imports perfectly and shows
nothing.

If your `elk`-tagged template is the Linux one, port those three steps into the bake before you start.
The component template body is in that PS1 file and is the authority.

---

## 1. Preconditions

Everything in this section is one-time setup. Do it before you book the cluster window, and verify
each one — a missing `role_hints` tag is a named 400 at deploy time, but a missing DNS alias is a
healthy agent shipping nothing.

Set these once in the shell you will use for the rest of the runbook:

```sh
export CC="https://cybercore.example.com"        # your app's base URL
export ADMIN_EMAIL="you@example.com"
export ADMIN_PASS="..."
export PGHOST="100.100.20.50"                     # CYBERCORE_DB_HOST
export PGUSER="cactus-admin"
export PGDATABASE="cybercore_db"
export PGPASSWORD="..."                           # CYBERCORE_DB_PASSWORD
```

Get an admin token (every `curl` below uses it):

```sh
export TOKEN=$(curl -sS -X POST "$CC/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "${TOKEN:0:24}..."
```

**Expected:** a JWT prefix, not empty. An empty value means MFA is enrolled on this account — log in
through the browser and copy the token out of local storage instead.

### P1 — The Track E code is deployed

```sh
cd front-end && npm test
```

**Expected:** `pass 3398`, `fail 0` (the count grows as phases land; `fail 0` is the criterion).

```sh
node -e "console.log(require('./src/incident/engines/synthetic').supportsMode('scenario'))"
```

**Expected:** `true`. If it prints `false`, E4 has not landed and `mode: 'scenario'` will be refused
with `UNSUPPORTED_MODE` — there is nothing to gate yet.

### P2 — The sensor template is baked and registered

The sensor image is baked by
`infrastructure/proxmox-templates/vm-templates/bake-cybr400-loggen-template.sh`, and
`ELASTIC_VERSION` **must** match the Elasticsearch it will ship to. Read the stack version off the ELK
box first:

```sh
curl -s http://<elk-box>:9200 | sed -n 's/.*"number" : "\([^"]*\)".*/\1/p'
```

**Expected:** an `x.y.z` version. Elastic does not support ingest two majors apart; **8.19 is the
common floor compatible with all 9.x**. A 7.x Elasticsearch cannot receive from a 9.x agent in either
direction.

Then register the template through Admin → Workstation Templates with **exactly** these values:

```
os_family      linux
os_name        Rocky Linux (CYBR 400 sensor)
template_vmid  1007
template_key   cybr400-loggen-template
template_type  workstation
metadata       {"console_protocol": "ssh"}
```

`template_type` must be `workstation` and `console_protocol` must be `ssh`: `resolveConsole()`
defaults to RDP, so leaving it unset publishes a gateway DNAT to port 3389 on a Linux box that is not
listening there.

### P3 — `role_hints` tags on the catalog rows

`role_hints` is a `TEXT[]` with **no admin UI**. On a fresh site it is empty on every row and stays
empty until you run these. `blueteam-templates.js` refuses the deploy with a named 400 carrying this
same SQL if you skip it — which is the correct behaviour, but you would rather find out now.

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "UPDATE cybercore_template_catalog SET role_hints = '{loggen}' WHERE template_key = 'cybr400-loggen-template';"
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "UPDATE cybercore_template_catalog SET role_hints = '{elk}' WHERE template_key = '<your-elk-template-key>';"
```

Only if you are deploying `stack='wazuh'` or `stack='both'`:

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "UPDATE cybercore_template_catalog SET role_hints = '{wazuh}' WHERE template_key = '<your-wazuh-template-key>';"
```

Verify all three at once:

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT template_key, template_vmid, node, template_type, status, role_hints
     FROM cybercore_template_catalog
    WHERE role_hints && '{loggen,elk,wazuh}' ORDER BY template_key;"
```

**Expected:** one row per role. Each SIEM row must have `template_type = workstation`,
`status = active`, and a non-null `template_vmid` and `node` — those are the resolver's own
predicates, and a half-registered `draft` row is a real state a site passes through that the resolver
deliberately will not pick up. The `loggen` row is matched on `role_hints` and `is_active` only.

### P4 — `node` is filled in on every catalog row

```sh
curl -sS -X POST "$CC/api/admin/vm-templates/sync-nodes" -H "Authorization: Bearer $TOKEN"
```

**Expected:** a JSON summary naming how many rows were updated. A row with a null `node` clones from
nowhere, hours into a batch.

### P5 — DNS aliases resolve inside a lane

Nothing to configure for the SIEM or the sensor: both are spec VMs, and `profile-to-spec.js` claims
`dns_aliases: ['elk']` / `['sensor']` from the hostname in PASS 1, **before** any client asset can
claim the name. The sensor's baked agent hard-codes `ELK_HOST=elk.cybercore.lan` and that is the only
name it will ever use.

What you must confirm is that the profile does not contain an asset whose hostname is literally `elk`
or `sensor`. The synthesizer refuses that collision outright, but finding out at deploy time costs a
cluster window:

```sh
psql -h "$PGHOST" -U "$PGUSER" -d clinic_db -c \
  "SELECT company_name FROM profiles WHERE id = '<profile-id>';"
```

Then open the profile in the UI and read the asset list.

**Expected:** no asset named `elk`, `sensor`, `wazuh` or `kali`.

### P6 — `pinAllVms` is true

CiAB sets it on both deploy paths (`lane-provision.js`, two call sites). Nothing to do — but if you
ever deploy this shape from the **CLE** side, note that a CLE GOAD lane defaults `pinAllVms` to
`false`, and without it the SIEM floats with no MAC reservation, no DHCP reservation and no
`host-record`. Three things lost in one move, and the only symptom is "the agents ship nowhere".

### P7 — Subnet scheme is v2, and the block is not already carved

`defensive_monitoring` is refused at anything but v2 (`validateEngagementPlan` → 400) and refused at
deploy if an already-carved block is the wrong scheme (`assertEngagementDeployable` → 409). A block
**cannot be re-carved** — the allocator only ever climbs and never re-uses.

```sh
psql -h "$PGHOST" -U "$PGUSER" -d clinic_db -c \
  "SELECT engagement_id, engagement_type, subnet_scheme, provision_status, max_students
     FROM ciab_engagement WHERE profile_id = '<profile-id>';"
```

**Expected:** either no row for `defensive_monitoring`, or one with `subnet_scheme = v2`. A v3 row
means you must use a different profile or a different engagement type slug — you cannot fix it in
place.

### P8 — The profile has ≥8 assets and ≥1 threat scenario

The compiler needs assets to bucket into the floor's pools and a scenario to compile the intrusion
from. A profile with no scenarios produces a named refusal (`NO_SCENARIOS`) at launch, not a bad run.

Cap: `defensive_monitoring` is capped at **19** selected assets (18 once the synthetic vuln-app VM is
counted), because the sensor and the SIEM are pinned into the same `.80–.99` band. The error message
says which of the over-budget machines the environment added for you.

### P9 — GOAD prebake (only for a GOAD-backed lane; skip for a profile-only lane)

If this gate is being run against a GOAD-backed lane, all of the following must be true of the golden
images **before** they were snapshotted. Each one is a re-bake if it is wrong.

1. `elasticsearch_version: '8.x'` and `winlogbeat 8.19.x` in `roles/elk/defaults/main.yml`, matching
   the sensor's `ELASTIC_VERSION`. GOAD's own `7.x` / `7.17.6` pins are self-consistent and cannot
   coexist with the sensor's agent.
2. ELK moved off `{{ip_range}}.50` — that is Kali's octet on v2, and on v2 they are the same address
   on the same subnet. CyberCore places it at `.24` (`SIEM_OCTETS`).
3. The ELK golden image uses **DHCP, not a static address**, so the lane's MAC-pinned reservation
   decides its IP. Otherwise the image and the reservation disagree and the only symptom is "the
   agents ship nowhere".
4. Logstash deleted from `roles/elk/tasks/main.yml` — it is installed, started and never configured,
   so otherwise it is a JVM in every golden image for nothing.
5. `winlogbeat.yml.j2` points at the **name** `elk.cybercore.lan`, not `hostvars['elk'].ansible_host`.
   Two lines, and the octet then stops mattering.
6. **`xpack.encryptedSavedObjects.encryptionKey` explicitly set in `kibana.yml`, 32+ chars.** This is
   the highest-consequence line in the whole change: if Kibana auto-generates it, it is regenerated on
   restart and every previously-encrypted saved object — including the detection rules' own API keys —
   becomes undecryptable. In a golden image that means rules that worked at bake time silently stop
   working in every clone.
7. If security is on: `xpack.security.http.ssl.enabled: false` **and**
   `xpack.security.authc.api_key.enabled: true`. Detection rules run as background tasks that mint API
   keys; without the second setting every rule fails to enable.
8. Prebuilt detection rules installed **and enabled during the bake**, while the staging lab still has
   internet. A deployed lane has no internet and Elastic downloads the `security_detection_engine`
   package from EPR on first use.
9. **Do NOT add ELK to `GOAD_LABS`.** `resolveSpecAddressing` skips a machine when `goadMacs[name]`
   exists, and `goadMacs` comes from `GOAD_LABS` — so adding it there loses the MAC pin, the
   reservation and the `host-record` in one move. As a plain spec VM it gets all three, and
   `deployPrebakedGoadLane` ignores it anyway (it heals only `dc` and `member`).
10. If you added `ws01`: widen `deployPrebakedGoadLane`'s heal filter to include `workstation`, or you
    get a domain-joined clone that boots, looks healthy, and cannot authenticate.

### P10 — Clocks

`cc-attack.sh`'s own header documents that these guests' clocks are not trustworthy: Proxmox only
syncs guest RTC on resume, and whether the Alpine gateway forwards NTP egress is deployment-dependent.
Live emission is correct regardless (the emitter sleeps to each offset against a monotonic base), but
**a clone whose clock is hours off makes every detection rule find nothing and look broken**, because
rules run on a schedule with a lookback window.

Confirm NTP works through the lane gateway before you blame the rules. §4's database block checks
`clock_skew_s` on every target for exactly this reason.

### P11 — Capacity

`ROLE_RESOURCES` already sizes GOAD-Light at **peak 48 GiB / idle 26 GiB per lane** before any SIEM.
Adding ELK (~5 GiB) + sensor (~2 GiB) + Wazuh all-in-one (8 GiB, 4 CPU):

| stack | idle per lane | × 20 students |
|---|---|---|
| `elastic` | ~33 GiB | ~660 GiB |
| `wazuh` | ~34 GiB | ~680 GiB |
| **`both`** | **~41 GiB** | **~820 GiB** |

**`both` is a real ~25 % on top of an already-heavy lane.** It is a legitimate choice — comparing two
consoles against one incident is a real skill — but it is an explicit opt-in with the number shown,
never a default. For the gate, deploy `elastic`: two students at ~33 GiB idle is ~66 GiB, which any
node can hold.

Two things worth knowing while you are sizing: GOAD-Light's `member` role is sized at 24 GiB peak for
SCCM/MSSQL-shaped work that a blue-team student mostly pivots through (`GOAD_LABS` supports per-VM
`memory`/`cores` overrides); and a **Wazuh-only** lane has no synthetic haystack at all, because the
loggen sensor ships to Elasticsearch only — so triage there is "find the only thing in the index".

### P12 — The engagement type is available

```sh
curl -sS "$CC/api/instructor/engagements/types" -H "Authorization: Bearer $TOKEN"
```

**Expected:** the response contains `defensive_monitoring`. The slug is **frozen** — it is baked into
the reservation key `ciab-profile-<id8>-<slug>` and therefore into the name of a carved VXLAN block.
Renaming it later orphans that block permanently.

---

## 2. Deploy

### D1 — Create the engagement

```sh
curl -sS -X POST "$CC/api/profile-deploy/engagements" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"profile_id":"<profile-id>","engagement_type":"defensive_monitoring","subnet_scheme":"v2","max_students":2}'
```

**Expected:** HTTP **202** and a body containing `"engagement_id"`. 202 is correct: the row exists, the
network does not yet.

```sh
export ENG="<engagement_id from above>"
```

### D2 — Wait for the block to be carved

```sh
curl -sS "$CC/api/instructor/engagements/$ENG" -H "Authorization: Bearer $TOKEN"
```

**Expected:** `"provision_status":"ready"` and a `subnet_scheme` of `v2`. Poll every 15 s; it takes
under a minute. A `failed` status has a message on the row — read it before retrying, because
`POST /:engagementId/reprovision` on a **healthy** engagement carves a *second* block.

### D3 — Choose the scenario

```sh
curl -sS "$CC/api/engagements/$ENG/incidents/scenarios" -H "Authorization: Bearer $TOKEN"
```

**Expected:** a list of the client's own threat scenarios with `scenario_id` and `name`. An empty list
means the profile has no `threat_profile.scenarios[]` and P8 was not met.

```sh
export SCENARIO="<scenario_id>"
```

### D4 — Set the telemetry plan

This is the load-bearing step and it is easy to skip. **The floor and the attack must be compiled from
the same scenario**, and the only thing that makes that true is this persisted choice: the deployer
reads `telemetry_plan.scenario_id` to compile the floor, and the launcher reads it again to compile
the attack. Compile them from different scenarios and the estate's vocabulary forks silently — the
attack names machines the floor's pools never mention, one terms aggregation on `loggen.source.host`
ends the hunt, and every part of it reviews as working.

```sh
curl -sS -X PUT "$CC/api/instructor/engagements/$ENG/telemetry" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"stack\":\"elastic\",\"scenario_id\":\"$SCENARIO\"}"
```

**Expected:** `200`, with `telemetry_plan.stack = "elastic"` and `telemetry_plan.sensor = true` in the
response. `sensor` is **derived**, never accepted from you: under `stack: "wazuh"` it comes back
`false` with a `TELEMETRY_NO_SYNTHETIC_FLOOR` warning, because the sensor ships to Elasticsearch only.

### D5 — Deploy two lanes

Note `attack_boxes: true` — that is decision 0.1, option A. Without it this lane has no console.

```sh
curl -sS -X POST "$CC/api/profile-deploy/deploy" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"profile_id":"<profile-id>",
       "num_lanes":2,
       "max_students":2,
       "group_name":"track-e-gate",
       "engagement_type":"defensive_monitoring",
       "subnet_scheme":"v2",
       "attack_boxes":true}'
```

**Expected:** HTTP **202** with a `group_id`. Any 4xx here carries a `code` you can act on —
`template_misses` names an untagged catalog row (go back to P3), `service_gaps` names an asset with no
matching image.

### D6 — Watch the deploy

```sh
curl -sS "$CC/api/profile-deploy/groups/<group_id>" -H "Authorization: Bearer $TOKEN"
```

**Expected, per lane:** `status: active`, and **no `post_deploy_error`**. A `post_deploy_error`
mentioning the floor swap is the one failure you must not ship past — see §5, symptom "generic
hostnames in Kibana".

### D7 — Confirm the lane shape on the cluster

Find the node and the vmids:

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT lane_id, user_id, vxlan_id, status,
          config->>'node' AS node,
          config->'loggen'->>'vmid' AS sensor_vmid,
          config->'loggen'->>'resolved_by' AS resolved_by
     FROM cybercore_lane
    WHERE config->>'engagement_id' = '$ENG' AND config->>'ciab' = 'true'
    ORDER BY created_at;"
```

**Expected:** two rows, `status = active`, a non-null `sensor_vmid`, and
`resolved_by = postdeploy`. `postdeploy` is rung 0 of the target ladder — the stamp
`blueteam-postdeploy.js` writes the moment the sensor VM is created — and its presence means the
incident engine will not have to probe for the sensor at dispatch time.

Record for §6:

```sh
export LANE1="<lane_id row 1>"; export LANE2="<lane_id row 2>"
export NODE="<node>"; export SENSOR1="<sensor_vmid row 1>"; export SENSOR2="<sensor_vmid row 2>"
export GW1=$((100000 + <vxlan_id row 1>))    # gateway LXC = 100000 + vxlan_id
```

### D8 — Confirm the environment appears to the students

Log in as each of the two student accounts and open **My Workspaces**.

**Expected:** one environment each, with a working Console button. Press it: it must open the machine
you chose in 0.1 (Kali under option A). If the button opens nothing, the console DNAT was never
installed — §6 covers it.

### D9 — Confirm the SIEM is reachable from the console

From the console machine (Kali under option A), in a terminal:

```sh
getent hosts elk.cybercore.lan
curl -s http://elk.cybercore.lan:9200
```

**Expected:** the name resolves to `<lane-base>.24`, and the second command returns the Elasticsearch
banner containing `"You Know, for Search"`. Then open `http://elk.cybercore.lan:5601` in the browser
on that machine and confirm Kibana loads.

---

## 3. Run the incident

### R1 — Confirm the engine has a resolvable target on both lanes

```sh
curl -sS "$CC/api/engagements/$ENG/incidents/targets" -H "Authorization: Bearer $TOKEN"
```

**Expected:** one entry per lane, each with a vmid and `resolved_by: "postdeploy"` (or `"cache"`,
which is the same stamp read back). A target reported **skipped** means `resolveLoggenTarget` could
not identify the sensor and deliberately refused to guess rather than fire an attack at the student's
SIEM — read the reason on the row.

### R2 — Let the floor run for at least 30 minutes before you launch

Assertion A3 measures the benign MITRE-tagged share of the index, and assertion A5 needs a pre-run
window that contains every source pair the attack will use. Both need volume. Thirty minutes at the
floor's rate is comfortable; ten is marginal.

Use the time to record the pre-run numbers you will compare against in §4 (the queries are there).

### R3 — Launch

```sh
curl -sS -X POST "$CC/api/engagements/$ENG/incidents" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"mode\":\"scenario\",\"scenario_id\":\"$SCENARIO\",\"duration_seconds\":1800}"
```

**Expected:** a run row with `mode: "scenario"`, `engine: "synthetic"`, and a `run_id`. Record it:

```sh
export RUN="<run_id>"
```

Refusals you may see, all of them 400s with a sentence in them:
`UNSUPPORTED_MODE` (E4 has not landed), `SCENARIO_NOT_CHOSEN` (D4 was skipped),
`UNKNOWN_SCENARIO` / `NO_SCENARIOS` (P8), `SCENARIO_UNCOMPILABLE` (the compiler refused this client —
the message names why), `INVALID_SELECTION` (the compiled playbook had no steps).

### R4 — Watch it to a terminal state

```sh
curl -sS "$CC/api/engagements/$ENG/incidents/$RUN/status" -H "Authorization: Bearer $TOKEN"
```

Poll every few seconds — the `/status` suffix is what exempts this route from the global rate limiter.

**Expected:** `status` moves `scheduling → dispatching → running → completed` and both targets reach
`completed`. A run stuck in `scheduling` or `dispatching` **holds the engagement's dispatch mutex**
(the unique index is partial on exactly those two statuses), so nothing else can be launched until it
is swept.

### R5 — Students submit, instructor scores and releases

As each student, on `/ciab/workspace`, submit **three findings, two IOCs and one timeline**. Then as
the instructor: override one verdict, then release.

```sh
curl -sS -X POST "$CC/api/engagements/$ENG/incidents/$RUN/score"   -H "Authorization: Bearer $TOKEN"
curl -sS -X POST "$CC/api/engagements/$ENG/incidents/$RUN/release" -H "Authorization: Bearer $TOKEN"
```

---

## 4. The assertions

Run every Elasticsearch query **from the sensor or from the console machine**, not from the
orchestrator: Elasticsearch lives inside the lane's VXLAN and has no route from anywhere else on the
cluster. A query that succeeds from the node and fails from the sensor is precisely the failure this
gate exists to catch.

From the Proxmox node, the sensor is reachable like this (substitute your own command for `<CMD>`):

```sh
qm guest exec $SENSOR1 --timeout 60 -- /bin/sh -c '<CMD>'
```

### A1 — Documents arrive within 10 minutes, all under one dataset

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_search' -d '
{"size":0,"track_total_hits":true,
 "aggs":{"ds":{"terms":{"field":"data_stream.dataset","size":20}}}}'
```

**Pass:** `hits.total.value > 0`, and the `ds` aggregation has **exactly one** bucket whose key is
`loggen.events`.

**Why one bucket is the whole point:** Discover shows `data_stream.dataset` as a one-click field. Two
datasets — a `loggen.baseline` and a `loggen.attack` — and a student "hunting" for the instructor's
attack just picks it from a dropdown. The bake ships both filestream inputs under one dataset
deliberately; if this has drifted, the exercise is a filter.

### A2 — `loggen.source.host` is the client's estate and nothing else

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_search' -d '
{"size":0,"aggs":{"h":{"terms":{"field":"loggen.source.host","size":200}}}}'
```

**Pass:** every bucket key is one of the client's own hostnames. **No** bucket may be
`web-01`, `ws-042`, `srv-prod-01`, `db-01`, `firewall-01`, `auth-01`, `app-server-01`, `fileserv-01`
or any other name from the baked generic pools.

**This is what proves the floor swap landed**, and it is the single most important assertion in the
gate. The baked floor draws hosts from generic pools; a CiAB profile's assets are the client's own
machine names. Ship only an attack playbook and `loggen.source.host: DC01` ends the exercise in one
click — and it would review as working.

Cross-check the source at the same time:

```sh
qm guest exec $SENSOR1 --timeout 60 -- /bin/sh -c \
  "node -e \"var p=require('/opt/cybercore/host-baseline.json'); console.log(p.pools.hosts.join(','))\""
```

**Pass:** the client's hostnames. If it prints `srv-prod-01,app-server-01,...` the swap never ran.

### A3 — Pre-run, 4–20 % of documents carry a technique, and they are the floor's

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_count' -d '{"query":{"match_all":{}}}'

curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_count' \
  -d '{"query":{"exists":{"field":"loggen.mitre.technique"}}}'
```

**Pass:** the second count divided by the first is between **0.04 and 0.20**.

**Both bounds matter.** Too low and "has a technique" is effectively an attack selector. Too high and
hunting by technique returns noise forever. And the scorer depends on this band: a student claim that
matches the floor's tagged set is graded a **defensible miss** — `partial`, 0 points, noted "that
label also occurs in ordinary traffic" — rather than a false positive. With no tagged floor that mercy
rule never fires and the scorer punishes students for finding what the floor deliberately planted.

Record the technique set as the pre-run baseline:

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_search' -d '
{"size":0,"aggs":{"t":{"terms":{"field":"loggen.mitre.technique","size":100}}}}'
```

### A4a — Post-run, the attack's techniques are still NOT queryable

Re-run the technique aggregation above.

**Pass:** the set is **unchanged** from A3 — it equals `answer_key.floor_techniques` and contains
**none** of `answer_key.techniques`.

**If an attack technique appears**, the agent's `drop_fields` on `loggen.mitre` is not running for the
attack tree and the whole run is one filter away from being fully enumerated. Note the order
dependency the bake documents: `drop_event` must come **before** `drop_fields`, or every attack event
is discarded instead of shipped. (A technique the floor also plants is not a leak — compare against
`answer_key.floor_techniques` before you re-bake anything.)

### A4b — The run emitted exactly what the board graded

The tags survive on the sensor's disk; only the shipped copy is stripped.

```sh
qm guest exec $SENSOR1 --timeout 60 -- /bin/sh -c \
  "sed -n 's/.*\"technique\":\"\\([^\"]*\\)\".*/\\1/p' /opt/log-generator-attack/logs/current/attack-$RUN.json | sort -u"

qm guest exec $SENSOR1 --timeout 60 -- /bin/sh -c "cat /opt/cybercore/runs/$RUN/count"
```

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT answer_key->'totals'->>'events' AS key_events,
          (SELECT string_agg(DISTINCT e->>'technique_id', ' ' ORDER BY e->>'technique_id')
             FROM jsonb_array_elements(answer_key->'techniques') e) AS key_techniques
     FROM cybercore_incident_run WHERE run_id = '$RUN';"
```

**Pass:** the technique set from the sensor equals `key_techniques`, and the count file equals
`key_events`.

**Why this is checkable at all:** the answer key is compiled server-side by re-running
`planTimeline(playbook, {rng: makeRng(seedFrom(runId))})` — `cc-emit` is deterministic on the run id,
so the server reproduces the exact event list every lane wrote, with zero Elasticsearch queries and
zero guest round-trips. A mismatch means the guest ran a *different* playbook: a stale staged file, a
truncated transfer, or a run that hit the timeout cap. Every score on that run is then measured
against events that were never written, and nothing in the UI reveals it.

### A5 — Every attack source pair also appears in the pre-run window

The attack playbook is staged on the sensor at `/opt/cybercore/runs/$RUN/playbook.json` and the floor
is at `/opt/cybercore/host-baseline.json`, so both can be expanded with the sensor's own baked
emitter. `scripts/verify-track-e-lane.sh` does this for you (section R); by hand:

```sh
qm guest exec $SENSOR1 --timeout 120 -- /bin/sh -c "node -e \"
var E=require('/opt/cybercore/cc-emit.js'), fs=require('fs');
var floor=JSON.parse(fs.readFileSync('/opt/cybercore/host-baseline.json','utf8'));
var atk=JSON.parse(fs.readFileSync('/opt/cybercore/runs/$RUN/playbook.json','utf8'));
function plan(p){return E.planTimeline(p,{rng:E.makeRng(E.seedFrom('$RUN')),requested:p.nominal_seconds||300});}
var f={},bad=[];
plan(floor).events.forEach(function(e){f[e.source.type+'/'+e.source.name]=1;});
plan(atk).events.forEach(function(e){var k=e.source.type+'/'+e.source.name; if(!f[k]&&bad.indexOf(k)<0)bad.push(k);});
console.log(bad.length? 'LEAK '+bad.join(',') : 'OK');\""
```

**Pass:** `OK`. Any pair listed is one terms aggregation away from selecting the attack.

Confirm it in the index too — every pair the attack used must already be visible in the pre-run
window:

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_search' -d '
{"size":0,"aggs":{"t":{"terms":{"field":"loggen.source.type","size":50},
 "aggs":{"n":{"terms":{"field":"loggen.source.name","size":50}}}}}}'
```

### A6 — No closed-vocabulary metadata field separates attack from benign

Fourteen `loggen.metadata.*` fields are mapped as explicit keywords, so each sits in Discover's field
list with a top-values popover. **One value that only the attack uses is 100 % precision and 100 %
recall, all semester.** This is the oracle that actually got through once: the floor shipped
`event_action: "routine"` on all 28 of its steps while the playbooks used 33 other values and never
"routine", so `NOT loggen.metadata.event_action: "routine"` returned every attack event and no benign
one.

By hand, per field:

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_search' -d '
{"size":0,"aggs":{"v":{"terms":{"field":"loggen.metadata.event_action","size":100}}}}'
```

**Pass:** for each of `event_action`, `user`, `target_user`, `protocol`, `service`, `outcome`,
`status`, `shell`, `user_agent`, `table`, `metric`, the value set present during the run window is a
subset of the value set present before it. `scripts/verify-track-e-lane.sh` does the whole set in one
pass (check `A6`).

### A7 — `NOT loggen.metadata.src_ip:10.*` does not return only attack events

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_count' -d '
{"query":{"bool":{"must_not":[{"prefix":{"loggen.metadata.src_ip":"10."}}]}}}'
```

**Pass:** a non-trivial count that includes documents from **before** the run. The assertion is on the
address *space*, not the values: whatever `/8` an attack can come from, ordinary traffic must come
from it too.

**Why the habit matters more than the filter.** A student who learns "the intruder is the unfamiliar
address" has learned something that fails on every intrusion that matters, because by the time you see
an adversary they are usually inside your address space using an account you issued them.

### A8 — Both dashboards render, and no panel points at the attack

Open Kibana on the console machine → **Dashboards**.

**Pass:** two dashboards present and rendering data — **CYBR 400 — Log Activity** and
**CYBR 400 - Hunting Workbench**. Then read every panel: none may aggregate `loggen.mitre.*`, split on
`data_stream.dataset`, or filter `log.file.path`. The workbench must look identical on a day with no
attack at all.

Empty terms panels are the tell for §0.3 — the `logs@custom` component template was never applied, so
those fields are `text` and not aggregatable. The dashboard imports perfectly and shows nothing.

`front-end/test/bake-payloads.test.js` pins this in the shipped ndjson; this check catches a dashboard
edited on the box.

> **Note for CiAB.** Both dashboard titles carry the string "CYBR 400" into a CiAB student's screen.
> That is a CLE course code in a clinic, which the CiAB vocabulary rule forbids everywhere else.
> It is cosmetic and out of scope for this gate, but record it — the fix is a retitle in
> `cybr400-loggen-dashboard.ndjson` plus a re-import.

### A9–A12 — only once E3b/E3c have landed

**A9 — `_exists_: winlog.event_id` must return BOTH benign and attack documents.** Run it in Discover
over a window spanning the pre-run hour and the run.
**Pass:** documents from both periods.
**Fail:** only run-window documents — which means the synthetic floor is still claiming
`source.type: 'host'` on Windows hostnames, and `_exists_: winlog.event_id` separates real from
synthetic in one click. The compiler must cede host telemetry to Sysmon when `hostTelemetry` is set,
keeping only the sources it can represent honestly: firewall, webserver, database, email, application,
network appliance.

**A10 — a terms aggregation on `host.name` shows every Windows asset in the lane**, each with pre-run
benign volume. A machine missing from that list is a dark box in the middle of a hunting exercise —
worse than not having it at all.

**A11 — the Alerts page has prebuilt rules enabled**, at least one fires on the run, and at least one
benign false positive exists in the same window. Two caveats to set expectations against: a large
share of Elastic's prebuilt rules target **Elastic Defend** (`event.dataset: endpoint.events.*`), not
Sysmon-via-winlogbeat, so you get a real alert queue and not full ATT&CK coverage — verify the enabled
rules' index patterns actually match where winlogbeat writes. And an empty Alerts page with rules
"enabled" is almost always **clock skew** (P10), not a rule problem.

**A12 — the sensor's synthetic stream still arrives after security was enabled.**

```sh
curl -s -H 'Content-Type: application/json' -X POST \
  'http://elk.cybercore.lan:9200/logs-loggen.*-*/_count' \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}'
```

**Pass:** a non-zero count. **Fail** means risk 5d exactly: the standalone agent still posts
unauthenticated to `http://elk:9200`, so turning on `xpack.security` leaves it **401ing while staying
HEALTHY** — no error the console can see, no events. If security is on, the sensor must be re-baked
with credentials in the same change. Fold the `timestamp` processor (`loggen.timestamp → @timestamp`)
in at the same time and close the backdating gap for free.

### DB — the run, the targets and the scores

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT run_id, engine, mode, status,
          jsonb_array_length(answer_key->'techniques') AS key_techniques,
          answer_key->'totals'->>'events' AS key_events
     FROM cybercore_incident_run WHERE run_id = '$RUN';"
```

**Pass:** one row, `engine = synthetic`, `mode = scenario`, `status = completed`.

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT lane_id, status, event_count, exit_code, clock_skew_s, late, resolved_by
     FROM cybercore_incident_target WHERE run_id = '$RUN' ORDER BY created_at;"
```

**Pass:** two rows, both `completed`, both with the **same** `event_count`, and that count equal to
`key_events` above. Same run id ⇒ same seed ⇒ same attack on every lane; that determinism is what lets
one answer key grade every student. Different counts mean one lane ran a different playbook, ran
short, or hit the timeout cap — and the two students are being graded against different realities.

`abs(clock_skew_s)` should be under 120 on both. See P10.

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT user_id, techniques_total, techniques_found, iocs_total, iocs_found,
          false_positives, timeline_score, ttd_seconds,
          auto_points, override_points, final_points, released
     FROM cybercore_incident_score WHERE run_id = '$RUN';"
```

**Pass:** two rows; `techniques_total` equals `key_techniques`; `released = true` after R5; and — for
the row you overrode — `final_points` differs from `auto_points` while `auto_points` is unchanged from
before the override. Re-running the scorer must be non-destructive: it writes only `auto_*`.

### UI — the release gate and the leak gate

**Pre-release**, as a student on `/ciab/workspace`: their own submissions only. No verdicts, no
points, and **no technique count anywhere on the page**. Knowing "there are six" tells a student when
to stop hunting, which is most of the exercise — that is why the gate is a database column rather than
a UI state.

**Post-release**, as the same student: verdicts and misses appear.

**The leak check**, with a *student* token:

```sh
curl -sS "$CC/api/engagements/$ENG/incidents/$RUN" -H "Authorization: Bearer $STUDENT_TOKEN" \
  | grep -Ei 'answer_key|technique_id|playbook|scenario_ref|catalog_version|override_note'
```

**Pass:** no output. `src/incident/projection.js` builds a new object from an 8-key whitelist
(`run_id, scope_type, scope_id, status, mode, scheduled_start_at, finished_at, engine`) — never
`delete row.answer_key`. A hit here means a route bypassed it.

Also confirm both "no such run" and "not your run" return **404**, never 403: a distinguishable
refusal turns the board into an enumeration oracle for how many clinics are running.

### Gateway

```sh
pct exec $GW1 -- cat /etc/dnsmasq.d/lane-reservations.conf
```

**Pass:** a `dhcp-host=` line **and** a `host-record=` line for both `elk` and `sensor`, e.g.

```
dhcp-host=<mac>,10.x.y.24,elk
host-record=elk,elk.cybercore.lan,10.x.y.24
dhcp-host=<mac>,10.x.y.8N,sensor
host-record=sensor,sensor.cybercore.lan,10.x.y.8N
```

A `dhcp-host` with no `host-record` is the silent failure this whole track keeps documenting: the
agent points at an unresolvable `elk.cybercore.lan` and ships nothing, with a healthy agent and no
error anywhere.

```sh
pct exec $GW1 -- iptables-save -t nat | grep LANE-CONSOLE
```

**Pass:** exactly **one** tag's worth of rules carrying the complete target list.
`installConsoleDnat` is one call per gateway per tag with the whole list — it strips its own tag first
and re-adds everything, so a second call would silently delete the first call's rules. Zero rules
means §0.1 bit you.

### Capacity

Tear the environment down, then:

```sh
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c \
  "SELECT * FROM cybercore_lane_wan_lease WHERE lane_id IN ('$LANE1','$LANE2');"
```

**Pass:** no live holder, and the `100.100.60.0/22` address the lanes held is available again. The
allocator only ever climbs and never re-uses, so a lease that is not released is capacity gone for
good.

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Deploy 400s with "no template in the catalog is tagged" | `role_hints` was never set — it has no admin UI, so empty is the normal first-time state | Run the exact `UPDATE` the error body carries. See P3. |
| Lane deploys, everything green, **Kibana index is empty** | `elk.cybercore.lan` does not resolve inside the lane. The sensor's agent hard-codes it at bake time, so a missing `host-record` leaves a **HEALTHY** agent shipping nothing, with no error | Check the gateway's `lane-reservations.conf` for the `host-record=elk,...` line (§4 Gateway). If it is missing, the DNS pass dropped the alias. |
| Index empty, `host-record` present, name resolves | Elasticsearch is refusing the sensor. Most often: security was turned on (E3c) and the sensor still posts unauthenticated — it **401s while staying HEALTHY** | Re-bake the sensor with credentials in the same change as the security switch (risk 5d). |
| `curl http://elk.cybercore.lan:9200` hangs from the sensor but works on the ELK box | The ELK golden image holds a **static IP** that disagrees with the lane's MAC-pinned reservation | The image must use DHCP so the reservation decides the address (risk 5f). Re-bake. |
| Every terms aggregation returns no buckets; both dashboards render empty | The `logs@custom` component template was not applied before the first write, so `loggen.*` string fields typed as `text` and are not aggregatable | Apply the component template from `Import-CybrDashboard.ps1`, then `POST /logs-loggen.events-default/_rollover` so a fresh backing index picks the mappings up. §0.3. |
| **Generic hostnames (`web-01`, `ws-042`) in `loggen.source.host`** | The floor swap did not land: `makeFloorSwapPostDeploy` never ran or threw | Read `cybercore_lane.config->>'post_deploy_error'`. Confirm `/opt/cybercore/host-baseline.json` on the sensor holds the client's hostnames. This is risk 5 and it **reviews as working** — do not ship past it. |
| A handful of generic-host documents, then client hostnames | Honest residual: `cc-hostbase` starts at guest boot, minutes before the postDeploy hook runs | Usually harmless (ES on a freshly cloned SIEM is often not accepting yet), but not guaranteed. A best-effort `_delete_by_query` for `@timestamp < <swap time>` is the documented cleanup. |
| Sensor ships nothing after a floor swap, and never recovers | The swap **truncated** the live `host.json` instead of `rm`-ing it. Zeroing the same inode strands filestream's registry offset past EOF | The swap script must be `stop → rm → staged write → mv -f → start`, never `truncate` and never `>` onto the live file. Restart the sensor to recover this lane. |
| Student presses **Console** and nothing opens | No console was ever published: `attackBoxes:false` + no `console_role` + no extras ⇒ `resolveConsolePlan` returns none, and the deployer treats an empty target list as success | §0.1. Re-deploy with `attack_boxes: true`, or give the SIEM a `console_role`. |
| Student presses **Console** and lands on Kali when you wanted the SIEM | `attackBoxes: true` makes Kali the primary — `resolveConsolePlan` prefers it over everything but an explicit override | Expected under option A. Under option B, send `attack_boxes: false` and set `console_role: 'primary'` on the SIEM. |
| Console opens but cannot log in — blank username/password in Guacamole | `cloneChallengeVm` never sets `ciuser`/`cipassword`; only `cloneExtraWorkstation` does. A spec-VM console gets `{username: null, password: null}` | Risk 3. Use option A, or move the SIEM onto the extras path. |
| Launch refused `SCENARIO_MODE_UNAVAILABLE` or `UNSUPPORTED_MODE` | E4 has not landed on this deployment | Nothing to gate yet. `supportsMode('scenario')` must be true (P1). |
| Launch refused `SCENARIO_NOT_CHOSEN` | D4 was skipped, so `telemetry_plan.scenario_id` is null | Set the telemetry plan. Both halves of the compile read the scenario from there so that floor and attack come from **one** compilation. |
| A target row is `skipped` | `resolveLoggenTarget` could not identify the sensor and refused to guess | Read `skip_reason`. Confirm the `loggen` tag (P3) and the postDeploy stamp (`config->'loggen'`). Guessing would fire an attack at the student's SIEM. |
| Run stuck in `scheduling`/`dispatching`; nothing else can launch | That is the dispatch mutex — a partial unique index on `(scope_type, scope_id) WHERE status IN ('scheduling','dispatching')` | Abort the run, or let the sweeper reach it. Confirm the worker is running: the sweep index covers `dispatching`, `scheduled` and `running`. |
| Two lanes report different `event_count` | One lane ran a different playbook, ran short, or hit the timeout cap | Compare `/opt/cybercore/runs/$RUN/playbook.json` on each sensor. The students are being graded against different realities. |
| Every claim scores as a false positive | The answer key on the run row does not describe the run that happened | A4b. Check the emitted technique set against `answer_key.techniques` before touching the scorer. |
| Students punished for finding floor-planted techniques | The benign MITRE floor is outside 4–20 % (A3), so the defensible-miss rule never fires | Recompile the floor. The scorer's `partial` verdict depends on `answer_key.floor_techniques` being populated. |
| Kibana Alerts page empty with rules "enabled" | Clock skew, or a rules/index-pattern mismatch | Check `clock_skew_s` on the target rows first (P10). Then verify the enabled rules' index patterns match where winlogbeat writes. |
| Detection rules worked at bake time, dead in every clone | `xpack.encryptedSavedObjects.encryptionKey` was auto-generated, so it regenerates on restart and every encrypted saved object — including the rules' API keys — becomes undecryptable | P9 item 6. Re-bake with the key pinned. This is the highest-consequence line in the GOAD prebake. |
| Rules all fail to enable, TLS off | `xpack.security.authc.api_key.enabled` was not set explicitly | P9 item 7. Rules run as background tasks that mint API keys. |
| `_exists_: winlog.event_id` returns only run-window documents | The synthetic floor is still claiming `source.type:'host'` on Windows hostnames while the attack lands in Sysmon | Risk 5b. The compiler must cede host telemetry when `hostTelemetry` is set. |
| A `ws01` clone boots, looks healthy, cannot authenticate | `deployPrebakedGoadLane` heals only `dc` and `member` roles | P9 item 10. Widen the heal filter to include `workstation`. |
| Second engagement on the same profile carved a new block | `POST /reprovision` on a healthy engagement carves a *second* block; the allocator only climbs | Check `provision_status` before reprovisioning. A carved block cannot be re-carved or re-used. |
| Node runs out of RAM at 20 students | `both` was selected | P11. `both` is ~25 % more per lane. Use one stack, or trim GOAD-Light's `member` role via the `GOAD_LABS` per-VM `memory` override. |

---

## 6. Running the automated checker

`scripts/verify-track-e-lane.sh` automates every assertion above that a machine can run, and prints
`MANUAL:` for the five that need a browser. Copy it to the node hosting the lane — `pct exec` and
`qm guest exec` are node-local, and the script refuses to run anywhere else.

```sh
scp scripts/verify-track-e-lane.sh root@<node>:/root/
ssh root@<node>
```

Then, on the node:

```sh
export CYBERCORE_DB_PASSWORD='...'      # enables the database checks
sh /root/verify-track-e-lane.sh \
  --lane <lane_id> \
  --node <node> \
  --sensor-vmid <sensor vmid> \
  --gateway-vmid <100000 + vxlan_id> \
  --run <run_id> \
  --stack elastic
```

`--gateway-vmid` and `--run` are derived from the database when it is reachable, so with
`CYBERCORE_DB_PASSWORD` set you can usually omit both. Add `--host-telemetry` once E3b/E3c have
landed to enable A9–A12.

**Expected output:** a `PASS`/`FAIL` line per check with the consequence attached to every failure, a
`MANUAL` block listing what still needs a browser, and a final tally. Exit code **0** only if nothing
failed.

Run it against **both** lanes. A gate passed on one lane says nothing about the other — and "the two
lanes disagree" is one of the failure modes it is looking for.

A `SKIP` line is **not** a pass. It means an argument or a credential was missing; supply it and run
again.

---

## 7. Sign-off

The gate is passed when, on **both** lanes:

- [ ] `verify-track-e-lane.sh` exits 0
- [ ] A1 — documents within 10 minutes, one dataset
- [ ] A2 — no baked generic hostname anywhere in `loggen.source.host`
- [ ] A3 — 4–20 % MITRE-tagged pre-run
- [ ] A4a — the attack's techniques are not queryable after the run
- [ ] A4b — emitted technique set and event count equal the answer key's
- [ ] A5/A6/A7 — no source pair, metadata value or address space is attack-only
- [ ] A8 — both dashboards render and no panel points at the attack
- [ ] DB — one run row, two completed targets with equal counts, score rows released
- [ ] UI — no technique count pre-release; verdicts post-release; override moved `final_points` only
- [ ] UI — the student endpoint leaks no key field
- [ ] Gateway — `dhcp-host` **and** `host-record` for `elk` and `sensor`; one `LANE-CONSOLE` tag
- [ ] Capacity — teardown released the lease

Only then may E9 (Caldera) ship. Groundwork for it already exists in the tree
(`src/incident/engines/caldera.js`, `bake-caldera-server.sh`), and the engine contract from E0 is what
keeps it additive — one adapter file, an `engine` value already in the run table's CHECK, and a bake,
with no board table, no route and no UI change. But nothing Caldera-shaped is allowed into a student's
lane until this page is fully ticked: an agent that can reach a controller outside its own lane is the
whole problem, and a synthetic engine that has not passed its own gate cannot tell you whether a
Caldera regression is Caldera's.
