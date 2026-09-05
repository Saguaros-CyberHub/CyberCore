# GOAD domain and machine renaming

GOAD remains in its separate fork and on each lane's GOAD controller. CyberCore
does not need a GOAD checkout, source cache, Docker volume, or lab binaries on
the webserver. The ignored `GOAD-main/` developer folder is not a runtime
dependency.

CyberCore validates the requested names and sends a small identity plan to the
controller. The rename helper maintained in the GOAD fork validates and copies
the controller's existing lab content locally, creates the renamed lab, and
rewrites selected extension configurations. The existing controller runner
then provisions the lane. CyberCore records the resulting identity and delivery
metadata and verifies Windows hostname/domain membership after provisioning.

## Controller prerequisite

The fork's rename helper must be present in the controller image. It is published
as commit `0fb45a48e1865fa65054dda22f5e924eea56369c` on the fork's
`cybercore-elk-fixes` branch, preserving the existing ELK fixes. The local bake
script and CiAB metadata now pin that commit. Rebuild the controller template:

```sh
# On the existing controller build host, retain your normal build arguments:
GOAD_REPO=https://github.com/joshmp087/GOAD.git \
GOAD_REF=0fb45a48e1865fa65054dda22f5e924eea56369c \
  ./infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh
```

Existing controller templates still need rebuilding; changing the pin does not
update an already baked VM. An older controller missing the helper reports a
capability error; it must not silently build the stock domain. There is no
webserver Compose override or GOAD source mount to install. CyberCore's local
changes remain uncommitted.

Deploy the updated CyberCore application files through your normal workflow
and restart its existing `app` service so Node loads the new planner and
deployment code (`docker compose restart app` with this repository's source
mounts). Reload the admin page to use the updated authoring controls. This is
the existing web application service; GOAD still runs on the lane controller.

## Authoring

Enable **Rename forest** on a fresh, live GOAD-Mini, GOAD-Light, or GOAD lab.
Prebaked environments preserve their golden-image identities and cannot use this
option. Disabling rename keeps the existing stock deployment path.

For root `cy400test.org` and child label `corp`:

| Base | Resulting domains |
| --- | --- |
| GOAD-Mini | `cy400test.org` |
| GOAD-Light | `cy400test.org`, `corp.cy400test.org` |
| GOAD | `cy400test.org`, `corp.cy400test.org`, `cy400test-partner.org` |

The independent trust forest uses the sibling `-partner` domain. NetBIOS names
must remain distinct and within Windows limits. The child label defaults to
`corp` when absent. Computer names follow the neutral catalog roster, including
DC01, DC02, SRV02, and ws01; inventory keys stay stable. The base lab's users,
groups, OUs, passwords, and attack relationships retain their exercise semantics.

ELK and WS01 can be selected together. Selected external extensions retain their
installer addresses, including ELK `.24`; Kali retains `.50`. Renamed Windows
identities, including WS01, are checked before the lane is reported ready.

## Failure handling and acceptance

Offline verification on 2026-09-04 passed all 3,953 CyberCore tests and all 11
controller-helper tests. The controller and JavaScript test reference agreed
for all three bases with two-, three-, and four-label roots, including extension
joins and script/binary hashes. A separate run with an unavailable GOAD checkout
passed 66 webserver checks; one optional source comparison was skipped.
No live Proxmox lane or ELK event flow was tested in this work.

A failed build with allocated resources remains `suspended`, retaining its VM
inventory, controller identity, error, and network claims for inspection and
teardown. It is not advertised as a ready student lane.

Verify fresh control and renamed lanes on the refreshed controller before a
classroom rollout: actual AD domains and hostnames, child promotion and GOAD
trust direction, WS01 secure channel and DNS, Kali/ELK addresses after renewal
or reboot, and fresh events from every Windows host in the correct lane's ELK.
Also inject a failure and verify visible failure plus complete teardown.

Caldera rollout remains separate. Use lane-specific agent identifiers because
computer names repeat across lanes; trace a benign simulation through fresh
Windows events to the intended lane's ELK before enabling attack scenarios.
