# A node that fails every lane because Ceph is still backfilling

Operator-run, at a Proxmox node console. Diagnoses and clears the failure mode where one
cluster node — most recently `cyberhub-node-8`, freshly joined and still doing Ceph
backfill — fails **every** challenge-lane deploy scheduled onto it while ten other nodes
are healthy.

**The one-line version.** The lane gateway LXC clones onto the node fine but never
reaches `running`, because `pct start`'s `lxc.hook.pre-start` loses a race for the
udev-created `/dev/rbd-pve/<fsid>/<pool>/<image>` symlink. Everything the deploy reports
after that point is a consequence, not a cause.

**Why it keeps happening to the same node.** See the last section — a backfilling node
looks *idle* to the scheduler and is therefore chosen *first*.

---

## The VMIDs, before anything else

Every command below wants a VMID, and they are derived from the lane's VXLAN id:

| What | VMID | vxlan 10881 |
|---|---|---|
| lane gateway LXC | `100000 + vxlan` | **110881** |
| GOAD controller VM | `200000 + vxlan` | **210881** |

The rest of this runbook uses 110881 / 210881 as the worked example. Substitute your own.

---

## Phase 1 — recognise it

The orchestrator log for a lane that hit this reads, in order:

```
[ChallengeLane] Lane <id>: could not write DHCP reservations (nodeExec exit 255 on cyberhub-node-8: pct exec 110881 -- /bin/sh -c mkdir -p /etc/dnsmasq.d ... container '110881' not running!)
[GOAD] Lane <id> failed during dhcp: prep.sh failed (exit 255): ssh: connect to host 10.42.129.1 port 22: No route to host
```

**Read it as one fault, not two.** The gateway LXC was cloned and then never started.
Nothing inside a stopped container can be configured, so:

- the DHCP reservation write fails with `container '110881' not running!`
- the lane VMs are started anyway, onto a LAN with no DHCP server
- the GOAD controller is cloned, and its `prep.sh` cannot SSH to the gateway at
  `10.42.129.1`, because there is nothing at that address to answer

That last error arrives **3–5 minutes** after the real failure, which is why this used to
get misdiagnosed as a GOAD problem, an SSH-key problem or a networking problem. The
`Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER` hint that used to accompany the first line was
simply wrong: the SSH to the node worked perfectly, and it was `pct exec` on the far side
that refused.

**What the orchestrator does now.** The challenge-lane path confirms the gateway actually
reaches `running` before it configures anything inside it, and fails fast — in seconds —
with a message that names the start task instead of the symptom:

```
Lane gateway 110881 on cyberhub-node-8 is 'stopped', not running, after N start
attempts. ... look for vzstart:110881 under /var/log/pve/tasks on cyberhub-node-8
```

`vzstart:<vmid>` in the failure text is the marker that you are in this runbook and not
some other one. The deployer will also **re-place the lane onto a different node once**
before giving up, so a single bad node no longer kills a batch outright — it makes it
slow. It does not make the bad node go away, which is what the rest of this is for.

---

## Phase 2 — confirm the failure mode on the node

As **root, on the node that failed** (`cyberhub-node-8` here).

### 2.1 Read the start task log

```bash
ls -t /var/log/pve/tasks/*/UPID:cyberhub-node-8:*:vzstart:110881:* | head -1 | xargs cat
```

You are looking for exactly this pair:

```
Failed to run lxc.hook.pre-start for container 110881
run_buffer: 569 Script exited with status 32
```

**32 is `mount(8)`'s exit code.** The pre-start hook mounts the container rootfs from
`/dev/rbd-pve/<fsid>/vmpool/vm-110881-disk-0`; the mount could not resolve that path. It
is a missing symlink — not a corrupt filesystem, not a bad container config.

If the task log says something else — out of memory, a missing bridge, an AppArmor denial
— you are not in this runbook. Stop here.

### 2.2 Prove the container itself is healthy

**Do not skip this.** This is the step that stops people rebuilding a perfectly good
container, or blaming the gateway template.

```bash
lxc-start -n 110881 -F --logpriority=DEBUG
```

Runs it in the foreground with full debug. **Ctrl-C once you see a login prompt.** Then:

```bash
pct start 110881 ; pct status 110881
```

Expect `status: running`.

If it boots by hand, the container was never damaged — **it lost a race.** The symlink
that was missing at deploy time is there now, because udev finished creating it a moment
after `pct start` looked. That is the whole bug.

Leave it running or stop it; Phase 6 tears the lane down either way.

---

## Phase 3 — check Ceph

```bash
ceph -s
ceph osd pool stats vmpool
```

You are looking for any of `backfilling`, `recovering`, `degraded` or `misplaced` in the
PG states, plus a **non-trivial recovery rate** on the `recovery:` line.

The node that produced this runbook was measured moving **282 MiB/s of backfill** while
failing every clone scheduled onto it. That is the load level that loses the udev race. A
node at a few MiB/s of trickle recovery may well be fine — Phase 4 decides that, not this
phase. This phase only tells you *why* Phase 4 is about to fail.

Note the shape of it: a backfilling node is busy in the *storage* path and idle everywhere
the scheduler looks. `ceph -s` is the only place that load is visible at all.

---

## Phase 4 — the readiness probe

### 4.1 Why this probe, and why it must not settle

`pct clone` and `pct start` both reach for `/dev/rbd-pve/<fsid>/<pool>/<image>`. That path
is a **symlink**, created by udev through `50-rbd-pve.rules` →
`/usr/libexec/ceph-rbdnamer-pve`. It is not created by the kernel and it is not created by
`rbd map`.

So there is a window between `rbd map` returning and the symlink existing. Most nodes
close it in low single-digit milliseconds and nothing ever notices. A node under heavy
Ceph recovery does not, and every clone and every start scheduled there dies inside that
window with `mount ... exit code 32`.

**The probe must pass WITHOUT `udevadm settle`.** This is the part that matters. A settle
*waits* for the very event whose lateness is the bug, so a probe with a settle in it goes
green on a node that will still fail every real clone. If you find yourself adding one to
make the probe pass, you have made the probe useless.

### 4.2 Run it

```bash
FSID=$(ceph fsid); NAME=t-$(hostname -s)-$RANDOM
rbd -p vmpool create --size 1G "$NAME" && DEV=$(rbd -p vmpool map "$NAME")
test -L "/dev/rbd-pve/$FSID/vmpool/$NAME" && echo READY || echo NOT-READY
rbd -p vmpool unmap "$DEV"; rbd -p vmpool rm "$NAME"
```

Expect `READY`, then `Removing image: 100% complete...done.`

**Run the whole block five times.** The race is a race: one pass proves nothing.

- **Five READY** — the node is fit to take lanes.
- **Any single NOT-READY** — keep the node out. One in five is one lane in five failing,
  and each of those costs a 3–5 minute deploy and a manual teardown.

Re-run after `ceph -s` reports `HEALTH_OK` with no recovery in flight. On the node that
produced this runbook the probe went from intermittent to five-for-five once backfill
completed, with no other change made to the node.

---

## Phase 5 — keep the node out

There are **two** controls and you want both. They stop different things:

- `ha-manager` node-maintenance stops **Proxmox** placing HA-managed guests there, and
  migrates off what is already running.
- `excluded_nodes` stops **CyberCore's own scheduler** choosing it for a new lane. Node
  selection is done by `node-selector.js` against the live cluster resource list; it has
  never asked Proxmox whether a node is in maintenance.

Neither one implies the other. Skipping the second is the common mistake, and the symptom
is that lanes keep landing on a node you believe you took out.

### 5.1 Proxmox side

```bash
ha-manager crm-command node-maintenance enable cyberhub-node-8
ha-manager status | grep -i maintenance
```

### 5.2 CyberCore side

Add the node to `cluster.scheduling.excluded_nodes` in `config/site.json` on the
orchestrator host:

```json
"scheduling": {
  "min_free_mem_gb": 8,
  "min_free_disk_gb": 20,
  "excluded_nodes": ["cyberhub-node-8"]
}
```

**EDIT IT IN PLACE.** `config/site.json` is mounted into the app container as a
*single-file* bind mount:

```
- ./config/site.json:/config/site.json:ro
```

A single-file bind mount is pinned to an **inode**. Any editor that writes a temp file and
renames it over the original — `vim` with its default `backupcopy=auto`, `sed -i`,
`sponge`, most scripted "read JSON, write it back out" helpers — creates a *new* inode,
and the container goes on serving the OLD file forever. **A restart does not help.** It is
not a caching problem; the container is bind-mounted to a file that no longer has a name.

Safe in-place options:

```bash
# vim, forced to truncate-and-write the existing inode
vim -c 'set backupcopy=yes' /path/to/CyberCore/config/site.json

# or edit a copy and stream it back over the original
cp config/site.json /tmp/site.json && vim /tmp/site.json
cat /tmp/site.json > config/site.json      # '>' truncates in place; the inode survives
```

Then restart the app so it re-parses the file. `site-config.js` caches the parse for the
life of the process and deliberately never invalidates it, so that nothing reading config
mid-deploy can shift underneath itself — which also means an edit without a restart has no
effect and produces no error:

```bash
docker compose restart app
docker logs --tail 50 cybercore-app
```

### 5.3 Confirm the app is actually serving the new file

Run the reconcile audit (**Admin → Cluster → Reconcile**, or `GET /api/admin/reconcile`)
and read the `cluster_nodes` block, which carries `getConfigFreshness()`:

| field | meaning |
|---|---|
| `config_mtime` | mtime of the file on disk right now |
| `config_loaded_mtime` | mtime at the moment the running process parsed it |
| `config_stale_in_memory` | disk has moved on — **restart the app** |

`config_stale_in_memory: true` after a restart, or a `config_mtime` that did not advance
after you saved, both mean the same thing: you wrote a new inode and the container is
still holding the old one. Go back and edit in place.

### 5.4 The automatic quarantine is not this

The orchestrator quarantines a node for **15 minutes** (`NODE_QUARANTINE_MS`) after a
gateway clone or start fails there, so the *rest of the batch* stops piling onto it.

That is a stopgap and nothing more, and it fails open by design:

- It **expires on its own**, so a node whose Ceph is still backfilling an hour later is
  schedulable again the moment it lapses.
- It is **per-process**. A restart, a second app container or a deploy driven from a
  worker all start with an empty quarantine map.
- It is **soft**. If honouring every quarantine would leave the scheduler with zero
  nodes, it places the lane anyway — refusing to deploy because the whole cluster is
  quarantined would turn a transient node fault into a total outage. On a small or
  already-degraded cluster that can put the lane straight back onto the bad node.

**It is not a substitute for `excluded_nodes`.** If you walk away after seeing the
quarantine kick in, the next batch fails exactly like the last one. A node whose
quarantine `count` keeps climbing across separate quarantines is an operator alarm, not a
problem the orchestrator has solved. (`NODE_QUARANTINE_MS` is env-overridable if you need
a shorter window while testing this runbook — leave it alone in production.)

### 5.5 SDN bridge readiness is a third thing again

There is a **fifth placement filter**, and it is neither a drain nor a quarantine. Before
placing a lane, the scheduler asks every candidate node whether the lane's SDN VNet bridge
is actually up there, and skips the ones where it is not.

**Why it exists.** Creating an environment carves a VXLAN block and commits it with a single
cluster-wide `PUT /cluster/sdn`. That commit creates **no bridges**. It makes every node
queue its own *SRV Networking* reload (`ifreload -a`), and those run independently — with
hundreds of VNets in the shared `ciabprof` zone, one node finishes in a minute and another is
still working an hour later. A lane placed on the second one clones perfectly and then dies:

```
bridge 'aaaabgdc' does not exist
```

Before the filter, the only safe move was to wait for the **slowest** node before deploying
anything. Now one finished node is enough.

**How it differs from the other two.** It is per-placement, derived from the live cluster,
and never written down:

| | `excluded_nodes` | quarantine | bridge readiness |
|---|---|---|---|
| set by | an operator, in `site.json` | a failed clone/start | the live node |
| lives | until edited | 15 min, per process | the length of one placement |
| means | never send lanes here | probably avoid this node | this node cannot cable *this* lane yet |

A node without the bridge is **not** marked faulty. It has done nothing wrong — it is
mid-reload — and quarantining it would keep it out of the *next* deploy too, by which time it
is very likely the healthiest node in the cluster.

**What you see.** In the app log, per deploy:

```
[NodeSelector] Bridge(s) aaaabgdc up on cyberhub-node-5, cyberhub-node-6; skipping
  cyberhub-node-8 (missing aaaabgdc) — their SDN reload has not landed yet
```

If **no** node has them yet, the deploy waits `cluster.scheduling.bridge_wait_s` (default
300s; the two synchronous admin routes use a fixed 15s) and then fails with
`BRIDGES_NOT_ON_ANY_NODE`, naming the bridges and each node's state. That error means "come
back in a few minutes", not "something is broken".

**Checking it by hand.** Which nodes have a given VNet:

```bash
V=$(pvesh get /cluster/sdn/vnets --output-format json | jq -r '.[]|select(.zone=="<zone>")|.vnet' | head -1)
for n in $(pvesh get /nodes --output-format json | jq -r '.[].node'); do
  printf '%s: ' "$n"
  pvesh get /nodes/$n/network --output-format json | jq -r --arg v "$V" '[.[]|select(.iface==$v and (.active==1 or .exists==1))]|length'
done
```

`0` means that node is still reloading. Note the `active`/`exists` test: Proxmox lists a VNet
from the node's generated `interfaces.d/sdn`, which is written at the **start** of the reload
task, so merely appearing in that output does not mean the bridge exists.

Which nodes are still reloading:

```bash
pvesh get /cluster/tasks --output-format json | jq '.[]|select(.type=="srvreload")|{node,starttime,endtime,status}'
```

**Known gap.** The quarantine is applied before this filter, so if the *only* bridge-ready
node is also quarantined while another node is not, the placement fails rather than using it.
The quarantine lapses in 15 minutes, so a retry clears it.

---

## Phase 6 — clean up the failed lanes

**Failed lanes are deliberately not destroyed.** A deploy that fails marks its lane rows
`suspended` rather than deleting them: the row keeps its VXLAN id and its WAN address
claimed, so nothing can be built on top of the wreckage, and the guests stay up for
inspection. That is a feature, and it means the guests are still sitting on the bad node
right now:

```bash
pvesh get /cluster/resources --type vm | grep -E '110881|210881'
```

Expect the gateway LXC `110881` (stopped, or running if you started it by hand in Phase
2.2) and — if the deploy got as far as GOAD — the controller VM `210881`, stopped.

**Tear them down through the app, not with `pct destroy`.** The admin teardown is the one
hardened path: it enumerates `cfg.workstations[]` (hand-destroying the gateway leaks every
slot-1-and-up machine), checks ownership, retries orphans, sweeps leftover disks, and only
deletes the lane row once nothing survived — so a VM that refuses to die keeps its VXLAN
reserved instead of releasing it for the next deploy to collide with.

- **Admin → Lanes → the failed lane → Delete** — `DELETE /api/admin/lanes/:id`
- For a lane the reconcile audit reports as drifted (released-but-alive, half torn down, a
  tombstone with live machines), use **Purge** — `POST /api/admin/lanes/:id/purge`. It
  asks you to type the VXLAN id back as confirmation and requires a fresh audit.
- A whole failed batch: **Admin → Groups → the group → Delete**.

A `207` response means some machines survived and the lane row was kept on purpose. Re-run
the teardown; do not delete the row by hand.

Only then redeploy. With Phase 5 in place the lanes will be built somewhere else.

---

## Phase 7 — re-enable the node

In this order. Re-enabling in the wrong order buys you one more round of failed lanes.

### 7.1 Lift both blocks

```bash
ha-manager crm-command node-maintenance disable cyberhub-node-8
```

Then remove the node from `cluster.scheduling.excluded_nodes` — **in place**, per Phase
5.2 — and restart the app:

```bash
docker compose restart app
```

### 7.2 Re-run the probe once more

Phase 4.2, on the node, five times. `ceph -s` reporting `HEALTH_OK` is necessary and not
sufficient: the probe is the thing that decides.

### 7.3 Check the audit for the two adjacent failures

Run the reconcile audit again. Two of its findings look like this bug and are not.

**SDN zone peer drift** (`zone_peer_drift` in the audit). A node that joined the cluster
**after** a VXLAN zone was created is not in that zone's peer list. Lanes then build on it
perfectly — the gateway clones, starts, boots, hands out DHCP — and have **no VXLAN
peering**, so the lane has no network. Same "the lane is dead" complaint from the student,
completely different cause, and Phase 2's task log is clean. Repair it from
**Admin → Cluster → Fix peers** on the affected zone; the server recomputes the peer set
from a live `/cluster/status` and refuses to write a zone with fewer than two resolved
peers.

**Node drift** (`nodes_undeclared` in the audit). Confirm the node is declared in
`cluster.physical_cluster_ips` in `site.json`:

```json
"physical_cluster_ips": {
  "cyberhub-node-8": "100.100.10.18"
}
```

This matters more than it looks. Node **selection** reads the LIVE Proxmox cluster, so a
newly joined node becomes schedulable the moment it joins — but everything that opens a
socket to a node translates the node NAME through `physical_cluster_ips`, because the app
runs in a container whose resolvers are `1.1.1.1` and the lab DNS, and neither of those
resolves `cyberhub-node-8`. A node that is schedulable but undeclared therefore gets lanes
assigned to it and then fails every `pct exec` with:

```
ssh: Could not resolve hostname cyberhub-node-8
```

`nodes_undeclared` catches exactly this. Fix it before the node takes work, not after.

---

## Why this keeps picking the bad node

Worth understanding, because it is the reason an explicit exclusion has to exist at all.

`node-selector.js` scores every online node on **used** CPU, memory and disk fraction and
takes the lowest score — weights `cpu 0.35`, `mem 0.55`, `disk 0.10`, lower is better.

A node doing heavy Ceph backfill has:

- **idle CPU** — recovery is I/O, not compute
- **free RAM** — it has no guests on it yet, which is precisely why it is backfilling
- **free disk** — same reason

So it scores **best**, every time, and wins every placement decision. *The one node least
able to build a lane is the one most likely to be chosen*, and it stays that way until it
has enough guests on it to look loaded — which it can never get, because every lane placed
there fails.

Nothing in the scheduler's inputs (`/cluster/resources`) exposes Ceph recovery state, so
the scheduler cannot learn this on its own. Hence the three separate mitigations:
`NODE_QUARANTINE_MS` for the rest of a batch, the clone/start retry ladder for the races
that are survivable, and `excluded_nodes` for the operator's judgement — the only one of
the three that holds until you say otherwise.

---

## Known gaps

- **`excluded_nodes` has no UI.** It is a `site.json` edit and an app restart, with the
  bind-mount inode trap of Phase 5.2 sitting in front of it.
- **The probe is manual and node-local.** Nothing runs it when a node joins the cluster
  and nothing runs it on a schedule, so a node that starts backfilling again — another
  node added, an OSD replaced — re-acquires this failure silently.
- **The 15-minute quarantine is per-orchestrator-process.** It lapses whether or not the
  underlying node got better.
- **Re-placement is one retry, onto one other node.** A cluster where several nodes are
  backfilling at once — which is what adding two nodes on the same day looks like — can
  still exhaust it.
