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

The fork's rename helper must be present in the controller image. The current
pin is `48b62c77b2d0bce82f6eb595ba5e1afd9526d50c` on `cybercore-elk-fixes`.
It includes forest renaming and a fixed SSMS installer that avoids the old
download alias redirecting to an incompatible SSMS 22 bootstrapper. The ELK
Windows role uses the rendered configuration in the Elastic installation and
recovers a missing service after interrupted extraction. The local bake script
and CiAB metadata pin that commit. The controller also enables the fork's
`cybercore_manage_hostname` guard: after bootstrap, GOAD retires Cloudbase-Init
on managed Windows guests so later reboots preserve the configured hostname.
Rebuild the controller template:

```sh
# On the existing controller build host, retain your normal build arguments:
GOAD_REPO=https://github.com/joshmp087/GOAD.git \
GOAD_REF=48b62c77b2d0bce82f6eb595ba5e1afd9526d50c \
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

Offline verification on 2026-09-05 passed all 3,996 CyberCore tests and all 36
GOAD fork tests. The controller and JavaScript test reference agreed
for all three bases with two-, three-, and four-label roots, including extension
joins and script/binary hashes. A separate run with an unavailable GOAD checkout
passed 66 webserver checks; one optional source comparison was skipped.
On 2026-09-05, an existing GOAD-Light lane stalled at SSMS after the unpinned
download returned a 22.9.2 bootstrapper. The operator applied the SSMS role fix
to its controller and ran the tagged repair against the existing forest. The
repair verified the installed executable and ended with zero failed or
unreachable hosts. The remaining server, security, and vulnerability tasks then
completed successfully on all three core hosts. WS01 and ELK then completed
with zero failed or unreachable hosts, including Sysmon and Winlogbeat setup
on DC01, DC02, SRV02, and WS01. The subsequent check matched DC01 to
`cybersaguaros.org` and DC02/SRV02 to `tumamoc.cybersaguaros.org`. The workstation
reported `WS01-JOSHUAMPAY`, while its AD computer account remained `WS01` and its
domain secure channel returned false. The chosen recovery name is `WS01`.
All four Sysmon/Winlogbeat services were running. An all-time Elasticsearch query
confirmed ingestion from all four collectors; a nine-hour Windows/controller
UTC discrepancy hid those events from the recent-time filter. At 20:35 UTC on
2026-09-05, a live clock correction brought all four Windows guests within three
seconds of the synchronized Proxmox node. SRV02's secure channel passed; WS01's
still failed. That recovery preserved guest timezones and did not change RTC
boot settings, hostnames, or membership. WS01 membership recovery, fresh-event
visibility, clock stability across boots, and a fresh uninterrupted deployment
still require acceptance.

The deployer sets GOAD Windows guests to UTC RTC mode before their cold restart,
then sets the Windows timezone and clock from a fresh Proxmox node UTC sample
before domain promotion. It verifies clocks again after provisioning without
silently correcting a later reset. Member machines must also pass a domain
secure-channel check; domain controllers are excluded from that member-only test.

A failed build with allocated resources remains `suspended`, retaining its VM
inventory, controller identity, error, and network claims for inspection and
teardown. It is not advertised as a ready student lane.

Playbook failures retain the last task, log and completion-file paths, elapsed
time, and outcome before controller cleanup. Raw Ansible output stays in the
controller log because task results can contain lab passwords. The overall
playbook deadline remains two hours.

Manual Ansible recovery does not resume the completed CyberCore job or run its
remaining hooks and identity checks. Existing retry actions recreate lanes;
toggling a lane active only changes power/status. Preserve generated lab and
extension identity files during repair, and verify the recovered lane before
reconciling its application status.

The fork includes `scripts/cybercore/repair-ws01.yml` for explicit manual recovery
of an already configured workstation. Its README documents the saved-inventory
invocation. Correct the lane clocks first. The playbook verifies the generated
configuration, prevents Cloudbase-Init from restoring the display name, and
checks canonical hostname and domain trust after rejoining. It does not run
automatically or mark the CyberCore lane ready.

Verify fresh control and renamed lanes on the refreshed controller before a
classroom rollout: actual AD domains and hostnames, child promotion and GOAD
trust direction, WS01 secure channel and DNS, Kali/ELK addresses after renewal
or reboot, and fresh events from every Windows host in the correct lane's ELK.
Also inject a failure and verify visible failure plus complete teardown.

Caldera rollout remains separate. Use lane-specific agent identifiers because
computer names repeat across lanes; trace a benign simulation through fresh
Windows events to the intended lane's ELK before enabling attack scenarios.
