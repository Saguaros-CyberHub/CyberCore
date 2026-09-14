# Caldera agents from the Blue Team Board

Open **CLE > Course > Blue Team Board > Caldera Agent** as a course instructor
or administrator. Select a running lane, its Windows or Linux QEMU VM, and click
**Install Agent**. The job continues if you close the dialog. Reopen it to see
progress and the agent's last check-in.

The picker checks live VM power in Proxmox. A lane retained as `suspended`
after a provisioning error can still provide a running VM for Caldera; its
saved deployment status is shown separately. Installing an agent does not mark
the deployment healthy or clear its error. Ordinary suspended lanes and
stopped, paused or unverified VMs remain unavailable. A Proxmox connection
failure is shown as an unavailable power check, rather than as no deployed lanes.

Click **Open Caldera console**, then select the displayed `lane-<lane UUID>`
group when creating a Caldera operation. A completed installation means the
server received a fresh check-in from that specific agent. Existing running
operations that accept its group may also select a newly connected agent.

The install uses the VM's QEMU guest agent with its existing elevated guest
execution context. It downloads Sandcat directly over HTTPS and starts a named
background process with local logs beside the binary. On Windows that process is
started hidden, so there is NO console window to look for on the VM's desktop:
confirm an agent from the Agent column in the dialog, or from the running
`mitre-sandcat.exe`, never from something visible on screen. Hunting for a window
that was never drawn is how a working agent gets reinstalled. Repeating the
install restarts only that managed agent. It does not install a startup service; after reboot, use **Install Agent**
again. Supported guest architectures are amd64 and arm64.

## Deploy agents across a class

Under **Blue Team Board**, choose **Group install agents**. The dialog works in
three steps — lanes, then machines, then the target list — and nothing is sent
until you press **Install**.

### Step 1: pick the lanes

Lanes are grouped by **Environment** by default; **Group by** also offers
**Student** and **None**. Grouping keys on the environment id the server sends,
never on its label. A label resolves one poll later, or not at all, so grouping
on it would file one environment under two headings and reshuffle every
collapsed header while you were reading it.

Each group header collapses, and carries a count line — lanes, VMs, agents, how
many lanes are selected, how many are unavailable — and a select-all checkbox
covering every available lane in that group. That checkbox shows a partial state
when some but not all of the group is selected, so a half-selected group can
never read as an empty one.

Use the lane search box to filter on student name and email, lane name and lane
number, environment, machine name, VM id and operating system. A search forces
every matching group open and disables **Expand all** / **Collapse all** while it
is active: a hit hidden behind a closed header is indistinguishable from no hit
at all. Clearing the box restores the arrangement you had before you typed.

The status pills filter the list and count the **whole course**, not the filtered
subset, so a "Failed 4" does not drop to zero because you searched for one
student. In install mode they are **All**, **Needs agent**, **Installing**,
**Failed**, **All installed** and **Unavailable**. "Needs agent" deliberately
excludes infrastructure machines and machines whose agent has already checked
in — it is the same test the **Only missing agents** button selects by, so the
pill cannot report work that the button then refuses to do.

**Run Caldera attack has the same lane picker.** The search box, the Group by
control, Expand/Collapse all and the status pills are built for both dialogs, so
a 45-lane course is searchable there too. Only the pills differ, because only the
questions differ: in attack mode they are **All**, **Ready**, **No agent** and
**Unavailable**. Scrolling a wall of identical chips hunting the two lanes that
have agents is the thing this replaces — type a student's name, or press
**Ready**.

Each lane is a two-line chip. Line one is the student's name, which is the only
label an instructor recognises; line two carries the lane number, the
environment, the VM and agent counts, and — when the lane cannot be used — a
badge naming the reason. One line cannot carry that: forty-five lanes named
`cle-cybr400-inperson-10880` all ellipsise to the same string.

**All available** is additive and scoped to what the filter is showing, so you
can search two students in turn and select both. **Clear** is global: clearing a
filtered list clears all of it, because lanes left selected out of view would
still be queued on submit.

### Step 2: pick the machines

Machines are listed under environment headings, one row per machine across every
selected lane. **Matching is on a machine key the server supplies, and that key
is scoped to the environment** — not on the bare VM name the way it used to be.
(Against a server too old to send that key the dialog falls back to the
environment plus the lowercased VM name, which is the same grouping scoped one
level tighter, so an older deployment degrades rather than breaking.)
Two challenges that each ship a `DC01` are
therefore two separate rows rather than one checkbox that would silently install
on both; and 44 student workstation lanes whose hostnames are all different
(`cle-cybr400-inperson-10880-ws1`) collapse onto a single **Workstation 1** row
instead of listing 44 single-lane machines. The environment heading carries that
scoping and is not decoration, because machine names are unique only within an
environment. It is drawn whenever the step spans more than one environment; a
course whose single environment resolved no label from its challenge spec shows
the rows without a heading, since there is nothing to tell them apart from.

A row's label can come from the challenge spec rather than from the VM name the
deployer recorded, so a machine authored as `DC01` reads as `DC01` even where the
lane config holds the lowercased Proxmox hostname. A workstation row is named by
its slot and template.

Ticking a machine selects it in every selected lane of that environment, and an
OS chosen against the machine applies to all of them. A row in **Targets** can
still override either.

**Role, OS and platform are resolved from the challenge spec and, for a GOAD
lane, from the GOAD lab roster**, so hand-picking an OS is now the exception
rather than the rule. A GOAD deployer writes `{vm_id, name, proxmox_name, type,
node}` with no OS at all, so before this every DC01, SRV02, ws01 and elk in the
class had to be marked Windows or Linux by hand, on every lane, every time. The
lab roster wins over the spec rows because it is what was actually built, and it
carries the roles and OS strings the spec rows lack. GOAD's Windows machines
therefore arrive already answered, and the machine's OS control reads
**Windows · from template**. In the target table a row whose OS came from the
server renders as plain text rather than as another bordered dropdown — still a
real control, so an override is one click away.

**Choose OS…** is decided by one field, the row's `platform` — `windows`,
`linux`, or nothing — and it appears only when *both* sources of that field came
up empty. The spec and the lab roster are the first source. The second is the
machine's own config row: `targetsFor` runs a single regex over
`[os, template_name, templateName, platform, name]`, and `enrichTargets` keeps
that inference as the fallback beneath the spec's answer. So the 44 `*-ws1`
desktops still resolve from the template name the deployer recorded, a challenge
row named `kali` or `ubuntu-22` still resolves, and the synthesised attack box is
answered by its own hardcoded `os: 'linux'` even in a lane with no spec at all.

What the regex cannot answer is exactly the GOAD case this section opened with:
`{vm_id, name, proxmox_name, type, node}` carries no OS word anywhere, so `DC01`,
`SRV02`, `ws01` and `elk` are answered by the spec and the lab roster or not at
all. **Do not read a challenge-table outage as "hand-pick an OS for all ~100
VMs".** It returns the GOAD machines, and any other machine whose config row
names no operating system, to a manual choice; every machine whose name or
template names an OS keeps its answer. That degradation is deliberately silent:
environment titles and machine rosters are cosmetic, and a challenge-table outage
must never turn an inventory poll into an error.

At machine level the same control says which of three things is true across the
lanes you selected: **Windows · from template** when every lane agrees, **Use
each VM's own OS** when they disagree, and **Choose OS…** when none of them
resolved.

The spec's literal `Unknown` default is treated as **no answer rather than as an
answer** — but in the OS *string*, not in that control. `specMachines` defaults an
undescribed spec row's `os` to the word `Unknown`, and `knownOs` drops it so it
falls through to the template name and then to null. That string is what the lane
and target search boxes match on, and dropping `Unknown` is what stops a search
for "unknown" from returning precisely the set of machines nobody has described —
the set that search can help with least. **It is not what the dropdown reads.**
Editing the spec's `os` default, or `knownOs`, can never change whether a row
shows **Choose OS…**, because that placeholder is computed from `platform`. The
two genuinely come apart in both directions: a VM whose only OS text is a
template named `server-2019-base` still asks you to pick, because that string
contains no word the platform regex recognises, while a challenge VM simply named
`kali` resolves to **Linux** with no OS text beside it at all.

Infrastructure machines — the SIEM (ELK, Wazuh) and the student's own attack
box — are listed with a **not a target** flag naming the role. Nothing ticks them
for you and **Only missing agents** never selects them, because Sandcat on the box
the class watches the attack from, or on the box Caldera already lives on, is
noise at best. They are still listed and you can still tick them by hand: an
instructor who genuinely wants an agent on the SIEM may have one, and a machine
that silently refused to appear would read as a deployment failure.

### Step 3: review the targets

The target table lists every selected machine in every selected lane. Its columns
are **Lane**, **Machine**, **Operating system**, **Agent** and **Status**; Lane,
Machine, Operating system and Status sort, ascending then descending. Agent does
not, because sorting on it would sort on exactly the facts Status already sorts
on. The default order reproduces the payload order exactly, so a poll that
changed nothing leaves the table — and your caret, your scroll position and any
open dropdown — untouched.

The target search box filters on student, lane, machine name, VM id, operating
system and status word. It never deselects, so the batch can hold rows you cannot
currently see; the footer says so before you install.

The **Agent** column is what says whether a machine is actually done: **checked
in** with an age, **stale**, **installing** or **install queued** while a job
runs, **install failed**, or **none**.

Four quick actions act on the rows the search is currently showing:

- **Select all shown** ticks every shown row that can be installed on right now.
  It skips a row whose lane is unavailable, whose VM is not running, and one that
  already has an install queued or running. It does **not** skip infrastructure —
  this is the button that means "all of it".
- **Only missing agents** ticks the shown rows that still need work and unticks
  everything else. It skips infrastructure, and it skips any machine whose agent
  has already checked in. It deselects as well as selects, and that is the point:
  a purely additive version would leave the SIEM and the attack box ticked from an
  earlier machine-level selection and quietly queue an install onto both. What it
  removes is also excluded, so the machine tick in step 2 does not put it straight
  back.
- **Retry failed** clears the selection, then ticks the shown rows whose last job
  failed or whose lane reported an error on the last submit. **It skips a VM whose
  agent is now present.** That combination — a recorded failure and a beaconing
  agent — is the case described under *Install script did not report completion*
  below; re-installing those machines is pure churn, and it would make Retry
  failed the button that undoes a working class.
- **Clear** drops the whole selection, at machine level and row level alike.

The selection preview shows exactly which VMs will receive agents. A request
accepts up to 200 VMs. Four installations run concurrently per app process;
the rest queue. Each VM has an independent persisted job and credential, so two
installs in one lane do not overwrite each other's progress. Busy or unavailable
VMs are reported individually. Closing the dialog does not cancel accepted jobs.

Jobs waiting in the queue expire after four hours; running jobs expire after
five minutes. An app restart interrupts in-memory
dispatch, and interrupted jobs become retryable after their respective timeout.
Finish an installation batch before updating the app.

## Structure and launch an exercise

An **ability** is one step with a platform-specific command. An **adversary
profile** is the ordered list of abilities for an exercise. An **operation**
runs that profile against one lane's `lane-<UUID>` agent group.

For a first exercise, create a Windows discovery profile in the Caldera console
using abilities for current-user discovery, system information and process
discovery. Choose abilities that run locally on the agent, without extra target
facts. Order them as the sequence students should investigate. Save the profile,
then return to **Blue Team Board > Run Caldera attack** and refresh the list.

Filter the profile list with the search box. The **Profiles** and **Past
launches** pills separate profiles somebody built from the snapshots every
classroom launch writes back to Caldera under a generated name, so a term's worth
of generated rows does not bury the profile you want.

### The profile card

Selecting a profile describes it in place, so choosing one no longer means
leaving this dialog to read the same list in the console.

- **A summary sentence** assembled from the server's own rollup: the number of
  steps, the tactics they fall into with a count each (largest first, at most four,
  then "and N more"), and the platforms the profile runs on with up to three
  executor names for each — "13 steps across 4 tactics: Discovery (5), …; runs on
  Windows (psh, cmd) and Linux (sh)." **The step count never comes from adding up
  the tactic counts.** Those counts skip every ability whose tactic is null, which
  is common for custom and plugin-authored rows, so adding them up would report a
  thirteen-step profile as a nine-step one. Abilities the catalog holds no entry
  for are **counted** in the same sentence rather than quietly dropped — "3
  abilities could not be described: not in the ability catalog." That clause
  carries the number and nothing else. **Which** ones they are is in the numbered
  step list below, where an unmatched step prints its bare ability id, because an
  id sitting where a name belongs reads as a step nobody bothered to describe
  rather than as one this server could not find.
- **A length warning above the verdict, past 40 steps**, saying to expect a long
  run and a lot of SIEM noise in every selected lane. It is advice, not a gate:
  nothing about it blocks the launch, and a long profile is a legitimate choice
  for an exercise students will hunt across a whole session.
- **A fit verdict against the agents actually checked in on the lanes you have
  selected** — not against the profile in the abstract. With no lanes selected it
  says to select lanes first. Otherwise it is one of: every step has an executor
  for the agents checked in; N of M steps will be skipped because no Windows (or
  Linux) agent is checked in, naming up to five of them; or no step in this
  profile can run on the agents checked in, naming the platforms it does target.
  Abilities the catalog could not describe, and rows that list no platforms at
  all, are **held out of the verdict and counted** — never assumed to work,
  because an assumed-green step is exactly the claim this dialog exists to stop
  making. The two share one trailing count: "*N abilities could not be checked:
  the catalog does not say what they run on.*" That number is kept apart from the
  skipped-step count, which is the separation that matters, but the two reasons
  are not told apart from each other and neither one is named. Only the skipped
  steps are named, up to five of them.
  Changing the lane selection rewrites the card, and closes any step description
  you had open: a verdict left standing while the selection moved underneath it
  would be a green answer about lanes nobody is launching on.
- **The ordered ability list**, one numbered row per step in the order Caldera
  will run them, carrying the ability name, its tactic, its MITRE technique id and
  technique name, and the platforms it runs on. A step the verdict excluded is
  badged **skipped**. Where the catalog carries a description, **What this step
  does** expands it.

**Full step detail ships for the selected profile only, and selecting a profile
costs an extra request.** The status poll appends `?adversary_id=<selected>`, and
the endpoint answers with the ability rows that one profile references; every
other profile in the list carries its summary rollup and nothing more. That is
deliberate — projecting every profile's steps put 160 KB of catalog into a
`no-store` payload polled every five seconds, a payload that grew with each
profile an instructor authored and of which the dialog never rendered more than a
thirteenth.

The visible consequence is a beat. Clicking a profile redraws immediately from
the payload already in hand, which knows its step count but not its steps, so for
a 250 ms debounce plus one round trip the card reads *"13 steps. This server does
not report tactics or platforms for profiles."* and lists nothing. **That is the
previous payload answering, not a broken catalog** — wait for the refresh before
concluding the stockpile is unreadable. The dialog asks for detail only when the
payload names an ordering it cannot describe, and the debounce collapses a walk
down a 28-row picker into one request rather than 28.

**A failed catalog read is remembered for 30 seconds.** Inside that window every
poll is rejected without contacting Caldera at all, and that rejection is
deliberately indistinguishable from the outage that caused it: the
`abilities_error` line stays up and the card stays degraded. So after restarting
Caldera the profile card can take up to half a minute to recover, and pressing
**Refresh status** during it cannot shorten the wait. The suppression is what
stops a stockpile that is already struggling from taking twelve requests a minute
from every open dialog; a successful read is cached for 60 seconds for the same
reason, which is also why a plugin installed just now may not appear in the card
immediately.

**When the ability catalog cannot be read, the card falls back to the step count
and says the detail is unavailable.** It never shows a zero. The sentence becomes
"13 steps. This server does not report tactics or platforms for profiles."; the
verdict states the agent mix and tells you to confirm in the Caldera console that
the profile's abilities have executors for those platforms; and each step reads
*The ability catalog could not be read* rather than *Not in the ability catalog*,
because those are different claims — conflating them asserts that thirteen named
abilities were deleted from the stockpile when the stockpile simply did not
answer. The error line under the dialog carries the outage itself. A server that
has answered before keeps serving its last good catalog: a stockpile only changes
when a plugin is installed, so a slightly stale description is right far more
often than an empty card that reads as "this profile does nothing". A Caldera
build with no abilities endpoint at all is a capability gap rather than a
failure — it degrades to the step count with no error banner.

### Lane badges say which of three things is wrong

The lane chips now distinguish **no agent checked in** from **lane not running**
and **internet off**. The launch preflight folds all three into a single
`runnable: false`, and the old dialog reported that one boolean as "lane not
running" — so a lane that was powered on and perfectly healthy but had nothing
checked in sent instructors off to restart a lane that was already running, and
the "no agent checked in" case was unreachable for precisely the lanes it
describes. The dialog now reads the lane's lifecycle status, its internet flag and
its agent roster as three separate facts, in that order, and badges whichever one
is actually true. Install mode adds **no running VMs** for an eligible lane with
nothing powered on.

### Launching

Select the profile and student lanes, then launch. Each selected lane needs a
running VM with a trusted managed agent seen within the last two minutes.
CyberCore snapshots the profile's ability ordering, creates a separate paused
operation for each lane, then sends the start requests together. If preparation
fails for a lane, the prepared batch is stopped before release. After release,
network failures can produce an uncertain result on individual lanes; refresh
status before retrying. Request IDs prevent an ambiguous retry from duplicating
the same operations.

Each operation targets all agents in its lane group. Install agents only on the
machines that should participate, and use platform-specific abilities where
Windows and Linux agents share a group. Start requests are concurrent, but actual
execution follows agent polling and planner timing; it is not synchronized to
the millisecond. The existing ELK agents forward the resulting host telemetry to
each student's SIEM.

Each operation receives a new empty fact source so learned facts and supplied
targets are not shared across student lanes. Host-local profiles work without
additional seeding. Run profiles that require credentials or remote-target facts
through Caldera with a lane-specific source; the classroom launcher currently
does not seed those facts or copy the shared authoring source. A profile can
finish with skipped steps if platform, executor or fact requirements are unmet.

The dialog shows per-lane operation IDs, status and errors, and identifies each
lane the way the lane picker does — student name, then `#<lane number>` and the
environment — rather than by the raw lane name. **Stop batch** stops
operation scheduling on the selected batch, including a batch still preparing.
Commands already executing in a guest can finish. Use Caldera's operation view
for individual ability results and compare the operation time window in ELK.
These classroom operations do not create automatic grading incidents.

## Windows installation settings

On Windows, installation uses `Set-MpPreference` to request turning off Microsoft Defender
real-time monitoring, behavior monitoring, downloaded-file scanning, script
scanning, block-at-first-seen and potentially unwanted application blocking on
the selected lab VM. It also uses `Add-MpPreference` to exclude only the managed
agent folder while preserving existing exclusions. It reads back the preferences,
effective real-time protection state and folder exclusion before downloading.
When some protections remain enabled but the exact agent folder exclusion is
present, installation continues with a notice listing the remaining settings and
Tamper Protection state. It still requires the agent to download, start and check
in to Caldera before reporting success. Applied changes remain after installation,
including a failed download; the dialog
states this behavior before installation. Already configured settings are left
alone. If Defender management commands are absent, the installer continues with
the download. Command errors, an unverifiable real-time state or an unverified
agent folder exclusion stop installation with an explanatory error. Other security products and application-control
policies require their own management controls.

To re-enable these Defender protections afterward, run elevated PowerShell on
the VM and remove the exact agent folder exclusion shown in the install output:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableBlockAtFirstSeen $false -PUAProtection Enabled
Remove-MpPreference -ExclusionPath '<agent folder shown in the install output>'
```

Windows or managed policy may re-enable protection independently, which can block
the agent again. See Microsoft's
[Defender PowerShell reference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference).

## Deployment

Set the existing environment values on the deployment:

```dotenv
CALDERA_HOST=caldera.saguaroscyberhub.org
CALDERA_AUTHORING_UPSTREAM=caldera:8888
COOKIE_DOMAIN=.saguaroscyberhub.org
```

Keep the existing `CALDERA_SSO_SECRET` and `CALDERA_API_KEY_RED` configured.
The red API key remains between server containers; guests and browsers never
receive it. The central image now includes Sandcat and Go and needs a rebuild:

```sh
docker compose build app caldera
docker compose up -d --force-recreate app caldera caddy
```

Recreation ensures Caddy reads the updated agent routes and remounts its
configuration file after a Git update. An app-only restart, or `up -d` with
an unchanged Caddy service, can leave the previous console-only gate running.

Route the hostname through the existing Caddy service. A tunnel or upstream
authentication proxy must let `/agent/*` reach Caddy without a browser login or
challenge. Caddy authorizes those requests using a per-VM capability and only
for beacon, payload download and upload. Console and API requests retain the
CyberCore instructor/admin login gate. No Caldera host port is published.

Guest DNS must resolve the hostname to a reachable HTTPS endpoint with a trusted
certificate. The lane gateway must permit outbound HTTPS. An explicit lane
**Internet: Off** disables forwarding and must be enabled before installing.
The V3 gateway blocks most management subnet traffic, so pointing the hostname
at a management address can still fail even with Internet enabled. Missing
`internet_enabled` on an older lane is treated as unknown; the connection is
tested through installation and check-in.

## Status and troubleshooting

- **Download returns 401:** the request may still be reaching the console login
  gate. With the updated repository on the server, refresh just Caddy:

  ```sh
  docker compose up -d --no-deps --force-recreate caddy
  ```

  Then retry **Install Agent**. To check the public routing without an agent
  credential, use this deliberately invalid path:

  ```sh
  curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://caldera.saguaroscyberhub.org/agent/not-a-token/file/download
  ```

  The updated Caddy route returns **404** for that malformed path. If it still
  returns **401**, check that the hostname's tunnel reaches this Caddy service
  and that an upstream login policy is not intercepting `/agent/*`.
- **Install Agent download returns 404:** if the agent route is working, an older
  Caldera image may still be running without Sandcat. Updating only the app or
  Caddy does not rebuild Caldera. From the updated repository on the server:

  ```sh
  docker compose build caldera
  docker compose up -d --no-deps --force-recreate caldera
  ```

  Wait for Caldera to report **All systems ready**, then retry **Install Agent**.
  If the download still fails, inspect `docker compose logs --since 5m caldera`
  immediately after the attempt. Caldera also returns 404 when payload compilation
  fails; recent download/build errors are more useful than old startup warnings.
- **Guest agent unavailable:** start/install the QEMU guest agent in the VM.
- **Download failed:** check DNS, HTTPS routing, certificate trust and proxy access.
- **Could not turn off Microsoft Defender protections:** check the
  target VM's Tamper Protection and managed policy. The installer verifies the
  effective real-time state, scanning preferences and exact folder exclusion,
  and names any settings that could not be verified. It proceeds with an
  installation notice when the exact agent folder exclusion is present and the
  real-time state is known, even if Tamper Protection keeps other protections on.
  A configured folder exclusion can allow the agent through antivirus scanning;
  other endpoint controls can still block it. See Microsoft's
  [exclusion scope documentation](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure).
- **Windows security software blocked Sandcat:** Windows errors 225/226 (including
  an `OpenRead` error saying the file contains a virus or potentially unwanted
  software) indicate an endpoint security block. On the target VM, review
  **Windows Security > Virus & threat protection > Protection history**, or the
  installed security product's console. Match the detection to the attempted
  Sandcat download under `%ProgramData%\CyberCore\Caldera\<group>\<agent ID>\`.
  Allow the intended agent under the lab's approved endpoint policy, then retry
  **Install Agent** to download it again. For Defender, see Microsoft's
  [Protection History guidance](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app).
- **Install script did not report completion:** **read the Agent column before you
  do anything else.** The QEMU guest agent reports a guest execution as exited only
  once *both* captured output channels close, not when the process ends. The
  Windows installer starts Sandcat through `Start-Process` with standard output
  and standard error redirected to log files, so the detached agent inherits those
  pipes and holds them open for its whole life — and the execution never reports
  exited. The 120-second guest-execution deadline therefore passes routinely on a
  completely successful install. **That deadline passing is no longer treated as a
  failure.** The job records the warning

  > The install script did not report completion within 120 seconds. On Windows a
  > detached agent holds the guest execution output open, so this is expected even
  > when the install succeeded. Waiting for the Caldera check-in instead.

  and then completes on the Caldera check-in instead. Before this, four agents that
  were already beaconing were reported as "Agent installation failed. Timed out",
  and instructors were sent to repair machines that were working. Two real failures
  can still follow, and they read differently:
  - *…and no Caldera agent checked in.* Nothing reached Caldera at all. The message
    tells you to check the Agent column before retrying, because Sandcat may still
    be starting; if it stays empty, check lane DNS, outbound HTTPS, the Caldera
    proxy and the guest agent. The guest execution status is appended, so a wedged
    QEMU guest agent identifies itself instead of reporting a bare deadline.
  - *…and the only Caldera agent on this machine cannot be told apart from the one
    an earlier install left running, so this installation is unconfirmed.* The paw
    is a hash of (lane, VM) and is identical across every reinstall, the group is
    per lane, and nothing ever deletes an agent row — so a Sandcat left running by a
    previous install keeps beaconing under exactly the paw this install is waiting
    for. With no completion report from the script, and no movement in the agent's
    pid, creation time or executable name, there is no evidence that the new
    install is what is beaconing. This is reported as a **failure even though an
    agent is present**, because the machine has to be checked — for a stalled
    download or a Defender prompt — rather than ticked off.
- **Started but no check-in:** the script *did* report completion with its startup
  marker and no fresh check-in followed: "Sandcat started, but no fresh Caldera
  check-in was received." Check lane DNS, outbound HTTPS, the Caldera proxy and
  guest agent logs. A script's successful exit alone is not reported as a connected
  agent.
- **A job says failed but the agent is checked in:** the progress card shows that
  job as **agent checked in** and keeps the server's error text below it as
  secondary detail, and the note above the job cards says how many recorded
  failures the agents have since reconciled. Do not look for that count in the
  footer summary line, which only ever reports the current selection, nor in the
  progress chips — those deliberately keep counting the server's own recorded
  statuses, so a reconciled job still shows in the "failed" chip.
  The reporting problem is real and worth seeing; the
  machine is not broken. The target table agrees — "checked in" outranks "install
  failed" in its status column — and **Retry failed** skips those VMs.
- **Interrupted install:** a running job can be retried after five minutes; a
  queued job after four hours. The installer stops waiting for a first check-in
  thirty seconds before that five-minute mark, so a job that is still working is
  never rewritten as "interrupted or timed out" and a retry can never claim the VM
  out from under an installer that is still running. Agent jobs
  and token hashes are stored in the existing lane JSON configuration; no SQL
  migration is required.

Linux files are under `/opt/CyberCore/Caldera/<group>/<agent ID>/`.
Windows files are under `%ProgramData%\CyberCore\Caldera\<group>\<agent ID>\`.
The executable is named `mitre-sandcat` or `mitre-sandcat.exe`; logs are beside it.
Other endpoint security controls may still prevent the executable from starting
after Defender real-time protection is turned off.

Each VM receives a random capability; CyberCore stores its hash. Reinstalling
that VM rotates its capability without changing other VMs' credentials. Active
lanes and retained provisioning failures use the same scoped agent gate. A
retained suspended lane must still have the agent's VM running to authenticate;
stopping that VM revokes its access. Other inactive lane states cannot authenticate. Destroying
a lane removes its running processes, although historical agent records may
remain visible in Caldera.

Manual Caldera operations are separate from CyberCore's incident engine and
automatic grading. The incident engine's existing Caldera launch gate is unchanged.

For the bulk-install and classroom-launch changes, rebuild only the app from the
updated repository, then refresh the Board:

```sh
docker compose up -d --no-deps --build app
```

## Outstanding work

**The unconfirmed-install case above is a symptom, not the disease.** The cause is
the redirected-handle launch in the Windows install script: `Start-Process` with
`-RedirectStandardOutput` and `-RedirectStandardError` creates Sandcat with handle
inheritance, so the guest execution can never report exited while the agent lives.
Fixing it properly means launching the agent so that it holds no inherited handle —
a scheduled task, or a process created without handle inheritance — and that has
to be verified on a real Windows VM before it ships. Two traps are already recorded
in the code review and will catch whoever implements it:

- **A WMI process create returns the wrapper's process id, not the agent's.** The
  script writes the launched process id to a PID file and, on the next install,
  refuses to stop that PID unless its `Win32_Process.ExecutablePath` matches the
  agent binary. Handed a wrapper's id, that guard either refuses a legitimate
  restart or fails to stop the old agent — which is exactly the stale-agent
  condition that makes an installation unconfirmable.
- **A refused create returns a status code instead of throwing.** The
  antivirus-block detection is a `catch` block that walks the exception chain for
  the wrapped HRESULTs of Windows errors 225 and 226 — `0x800700E1` and
  `0x800700E2`, ERROR_VIRUS_INFECTED and ERROR_VIRUS_DELETED — and for a
  `Win32Exception` whose `NativeErrorCode` is 225 or 226. A creation API that
  reports refusal through a return value never enters that block, so a Defender
  block would silently degrade into a generic failure and the "Windows security
  software blocked Sandcat" guidance above would become unreachable.

## Validation

Run the focused `caldera-agent*`, `caldera-lane-agents`, `caldera-lane-operations`,
`caldera-adversary`, `lane-environment`, `incident-scope`, `caldera-classroom-ui`,
container, authoring-access and Blue Team Board tests from `front-end/test`.
Name `lane-environment`, `incident-scope` and `caldera-adversary` explicitly:
the first two are their own files, and the `caldera-agent*` glob does **not**
match `caldera-adversary`, so all three are silently skipped by the old
command. Set `CADDY_BIN` to a Caddy 2.10.2
binary to exercise the actual reverse proxy against local mock services.
A production image build, a real lane check-in and a classroom operation launch
must still be verified on the deployment; local tests do not establish cluster
connectivity or guest execution.
