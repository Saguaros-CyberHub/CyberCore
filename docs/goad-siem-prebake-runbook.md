# Prebaking the GOAD SIEM extensions (elk / wazuh)

Owner-run. Produces four golden templates so that ticking **elk** or **wazuh** in the
Topology Designer clones a machine that already has the stack on it, instead of
installing it per lane.

**Why prebake at all.** A live `install_extension` works — lanes have internet, and
`run.sh` supports it — but it costs ~25–40 min and ~2 GB *per lane*, and the expensive
part is per-host: `roles/logs_windows` reboots every Windows host and runs
`winlogbeat setup -e` once per host for identical global work. Prebaking pays that once.

**The trade you are accepting.** Stack versions freeze at seal time. Refreshing means
redoing this runbook. That is the same trade every other template here makes.

---

## What you end up with

| VMID | What | Made by |
|---|---|---|
| 1011 | plain Ubuntu 22.04 base, no SIEM | `bake-ubuntu-lab-template.sh` |
| 1012 | ELK golden (ES + Kibana + winlogbeat setup already loaded) | `seal-goad-elk-template.sh` |
| 1013 | Wazuh golden (manager + indexer + dashboard) | `seal-goad-wazuh-template.sh` |
| 1004 / 1006 | Windows server / Win11, **with agents installed but not registered** | staging pass, below |

---

## Phase 0 — prerequisites

### 0.1 Re-bake the GOAD controller (REQUIRED, and freeze a rollback first)

`run.sh` only learned about extensions in this change. Template 1700 must be re-baked
or the extensions argument is silently ignored — the forest builds, the deploy reports
success, and there is no SIEM.

CyberCore now refuses that case rather than deploying green, so a missed re-bake is a
clear error and not a mystery. But you still have to do it.

```bash
# Freeze the CURRENT working controller first — this is your only way back.
qm clone 1700 1701 --name goad-controller-template-frozen --full --storage vmpool
qm template 1701

qm destroy 1700 --purge
bash bake-goad-controller-vm.sh

# Confirm the capability marker landed:
qm clone 1700 9994 --name ctrl-test --full --storage vmpool && qm start 9994
qm guest exec 9994 -- /bin/sh -c 'cat /opt/goad-light/.cc-extension-install'
qm stop 9994 && qm destroy 9994 --purge
```

Rollback if the bake is bad: set `CONTROLLER_TEMPLATE_VMID = 1701` in
`front-end/src/utils/goad-deploy.js`.

### 0.2 Bake the plain Ubuntu base (1011)

`GOAD_CONTROLLER_PUBKEY` is required and has no default — it is how the controller
SSHes into the elk/wazuh box to run Ansible. Get it from the controller you just baked.

```bash
GOAD_CONTROLLER_PUBKEY="$(cat /root/.ssh/goad-controller-deploy.key.pub)" \
  bash bake-ubuntu-lab-template.sh
```

---

### 0.3 Pre-flight: can the controller actually reach the SIEM box?

**The most likely single failure in this whole runbook, and it fails late.** If
`GOAD_CONTROLLER_PUBKEY` did not land in 1011's `authorized_keys`, Ansible cannot reach
the elk/wazuh box — and you find out *after* waiting for the entire AD forest to build.
Thirty seconds to rule out:

```bash
qm clone 1011 9995 --name ubuntu-test --full --storage vmpool
qm start 9995
qm guest exec 9995 -- /bin/sh -c 'ip -4 addr show | grep inet'   # note the address
# then, from the controller you baked in 0.1:
ssh -i /root/.ssh/goad-controller-deploy.key -o StrictHostKeyChecking=no \
    ubuntu@<that-address> 'echo reachable'
qm stop 9995 && qm destroy 9995 --purge
```

---

## Phase 1 — the staging install (once)

Deploy **one** lane, live (not prebaked), GOAD-Light, with **`elk` and `ws01` ticked —
not `wazuh` yet**. Install one stack at a time: `install_extension` is additive, so the
forest gets built once and you debug a single stack instead of two. Wazuh comes back in
step 1.3.

Expect 25–40 minutes for this half. Watch it:

```bash
qm guest exec <controller-vmid> -- /bin/sh -c 'tail -f /var/log/goad-run-<vxlan>.log'
```

### 1.1 Confirm the ELK agents actually shipped

**Do this before sealing anything.** Sealing an ELK box whose agents never reached it
produces a golden image that makes *every* future lane look broken — and it looks fine
at seal time.

```bash
# from the staging lane's Kali box: every Windows host should appear
curl -s 'http://elk.cybercore.lan:9200/winlogbeat-*/_search?size=0' \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"h":{"terms":{"field":"host.name"}}}}'
```

You want a bucket per Windows host — DC01, DC02, SRV02 and ws01 for GOAD-Light + ws01.
`seal-goad-elk-template.sh` re-checks this and refuses if it finds nothing, but finding
out here is cheaper than finding out mid-seal.

**Now seal ELK** — jump to Phase 2, run the elk seal only, then come back for wazuh.

### 1.2 Add wazuh to the SAME lane

`install_extension` is additive, so the forest you already built is reused. Tick
`wazuh` on the same environment and redeploy; expect another 20–30 minutes.

### 1.3 Install the SOCFortress rules BY HAND

**Upstream's role never runs them.** `roles/wazuh_manager/tasks/main.yml` gates both
SOCFortress tasks on `when: not ossec_folder.stat.exists`, where `ossec_folder` stats
`/var/ossec` — which the Wazuh installer created earlier in the same role. The
condition is therefore always false and the pack is skipped on every GOAD install
anywhere. This is an upstream bug, not something specific to us; verified on disk.

Stock Wazuh rules (~3000) ship with the product and are present. SOCFortress is an
additional pack on top of those.

```bash
# on the staging lane's wazuh box
sudo bash /opt/wazuh/wazuh_socfortress_rules.sh    # if the role copied it
# if it did not, take it from the vendored copy:
#   GOAD-main/extensions/wazuh/ansible/roles/wazuh_manager/files/wazuh_socfortress_rules.sh
sudo systemctl restart wazuh-manager
```

`seal-goad-wazuh-template.sh` refuses by default when the pack is missing
(`REQUIRE_SOCFORTRESS=1`). That default is deliberate — it catches you skipping this
step. Set `REQUIRE_SOCFORTRESS=0` only if you decide stock rules are enough.

### 1.4 Confirm the wazuh agents enrolled

```bash
# on the staging lane's wazuh box
/var/ossec/bin/agent_control -l
```

Every Windows host should be listed and Active. Then seal wazuh in Phase 2.

---

## Phase 2 — seal the two SIEM boxes

Run from the Proxmox node holding the staging lane. Both clone to a **new** VMID rather
than converting in place, so a failed seal is retryable and the golden template is not
tied to the lane's lifecycle.

```bash
SRC_VMID=<staging elk vmid>   bash seal-goad-elk-template.sh     # -> 1012
SRC_VMID=<staging wazuh vmid> bash seal-goad-wazuh-template.sh   # -> 1013
```

Each prints a FROZEN VERSION box — record what you froze.

**What the elk seal is doing that matters.** The staging lab's logs and the dashboards
you want to keep live in the same Elasticsearch. It deletes data indices by exact name
(never a wildcard in a DELETE URL), keeps `.kibana*` and the index templates, then
restarts Elasticsearch and *re-asserts* that the winlogbeat template survived. That
last check is the difference between a correct seal and a destructive one.

**What the wazuh seal is doing that matters.** It empties
`/var/ossec/etc/client.keys` and the agent state. Seal with those populated and every
cloned manager boots already knowing the staging lab's hosts, so real lane agents
collide with ghosts and show as disconnected — in every lane at once, with nothing in
any log explaining it. It stops the manager *before* truncating, because `wazuh-authd`
and `wazuh-db` hold the registry in memory and rewrite it on shutdown.

Wazuh's generated admin password lands in `/opt/cybercore/wazuh-credentials` (0600) and
is printed once. **It is identical in every clone** — acceptable on isolated per-student
lanes, matching the `bake-debug` convention, but write it down.

---

## Phase 3 — the Windows agents: NOTHING TO DO

**There is no Windows re-bake. Templates 1004 and 1006 are never touched.**

An earlier revision of this runbook had you re-bake both Windows templates with Sysmon,
winlogbeat and wazuh-agent pre-installed. That is gone, and it is worth knowing why,
because re-baking looks like the obvious move:

- **Blast radius.** 1004 and 1006 are shared with *every* GOAD lab. A bad bake breaks
  CYBR 480 and everything else, to serve blue-team lanes.
- **The agent-identity trap.** A wazuh-agent snapshotted after it registers bakes ONE
  agent identity into every clone, so the manager sees a single agent flapping across
  every lane at once — with nothing in any log explaining it. Avoiding that needed a
  careful clear-`client.keys`-before-sysprep step that you had to get right by hand,
  every time.
- **Frozen versions.** Bumping an agent meant redoing the bake.

Instead the agents install **per lane, at deploy time**, through the post-clone script
mechanism this platform already uses to plant vuln apps. Ticking `elk` or `wazuh` in the
Designer attaches the matching slug to every Windows host in the AD roster
automatically:

| slug | installs | file |
|---|---|---|
| `goad-elk-agent` | Sysmon (SwiftOnSecurity config, embedded) + winlogbeat 7.17.6 | `front-end/vuln-scripts/goad-elk-agent.ps1` |
| `goad-wazuh-agent` | wazuh-agent 4.8.2 | `front-end/vuln-scripts/goad-wazuh-agent.ps1` |

Both are seeded into `vuln_scripts` (clinic_db) by an idempotent boot hook,
`front-end/src/utils/goad-agent-scripts.js`, called from `src/server.js`. Attachment
lives in `front-end/src/utils/goad-agent-attach.js`. Both scripts are **no-ops on a
re-run**, so retries and redeploys are safe.

Two things they deliberately do NOT do, each of which looks like an omission:

- **No `winlogbeat setup`.** GOAD's role runs it once per host — with no `run_once`, so
  3–4 times per lane for identical global work — to push index templates, ILM policies
  and dashboards into Kibana. Template 1012 was sealed *from a staging lab* and already
  carries all of it. This is the single biggest reason sealing the ELK box is worth
  doing.
- **No reboot.** The role reboots each host before `setup`. No setup, no reboot.

They also exit 0 when the SIEM is not reachable yet. Post-clone scripts can run before
the SIEM VM has finished booting; both agents retry on their own, so *installing*
succeeds even when *connecting* cannot. A script that failed here would mark a perfectly
good lane as failed.

**Cost:** ~55 MB per Windows host per lane (winlogbeat zip + wazuh MSI). The Sysmon
config is embedded, so it is not downloaded. Compare the ~2 GB per lane that sealing the
ELK box removed — this is the small half.

### If you ever DO want them in the image

Serve the two payloads from the orchestrator instead of the internet. The
`CYBERCORE-IMAGE-PULL` firewall rule already permits lane → orchestrator:80 for the
vuln-app image pull, so the same path works here and makes the install LAN-speed. That
is an optimisation, not a prerequisite — and it is a much smaller change than re-baking
a shared Windows template.

---

## Phase 3.5 — the staged rollout (recommended: do this before Phase 4)

You do not have to go straight to fully-prebaked lanes, and I would not. There is a
middle setting that gets most of the speedup at a fraction of the risk:

**Leave the lane LIVE, but point its `elk` row at the sealed template 1012.**

The elk role then finds Elasticsearch, Kibana and Java already installed and is close to
a no-op, so the ~2 GB per-lane download — the actual bandwidth problem — disappears.
The agents still install per lane through Phase 3's scripts, exactly as they would
anyway. Nothing about the deploy path changes and nothing new can fail.

Run a term like that. Move to fully-prebaked (Phase 4) once you have seen the sealed
images work in anger, and when the remaining minutes per lane start to matter.

---

## Phase 4 — flip the specs to prebaked

Point the extension machines at the sealed templates and set `spec.goad.prebaked`.

CyberCore enforces this pairing in two places — `topology-validate` at authoring time
and `assertGoadExtensionsRunnable` at deploy time. Prebaked **plus a sealed template**
is fully supported and is the intended steady state. Prebaked plus **1011** is refused,
because that image has no stack and a prebaked lane runs no Ansible to add one.

A prebaked GOAD lane also requires `spec.goad.fixed_subnet`.

---

## Phase 5 — verify one clone

Deploy a single prebaked lane and check, in order:

- `getent hosts elk.cybercore.lan` resolves to `.24`, **not** `.50` (`.50` is Kali; on a
  flat v1/v2 subnet those are the same address, and two `dhcp-host` lines claiming one
  address make dnsmasq refuse to start — DHCP down for the whole lane)
- Kibana loads at `http://elk.cybercore.lan:5601` with the dashboards present and
  **zero documents** from the staging lab
- the Wazuh dashboard loads with **zero agents** listed, then agents appear as the
  Windows hosts enroll
- run `powershell.exe -enc <b64>` by hand on a domain host; it appears in Kibana within
  60 s as ECS with `process.command_line`, `process.parent.name`, `winlog.event_id: 1`
- a terms agg on `host.name` shows every Windows machine in the lane

---

## Known gaps

- **`lx01` still points at template 1003**, unverified. 1011 is exactly the generic
  Ubuntu box it wants, so these may want to collapse — confirm what 1003 actually is
  first.
- **`bake-win-client-template.sh` still defaults `FINAL_VMID=1002`** while this cluster
  has Windows 11 at 1006. The catalog follows the cluster; the bake script default has
  drifted and was deliberately left alone.
- **None of these scripts has ever been executed.** Each says so in its header and
  lists what is unverified. Treat the first run as the experiment.
