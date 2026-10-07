# Installing endpoint and network telemetry with Wazuh

The Admin Dashboard's **Deploy Wazuh agents** dialog now offers two independent
monitoring options. Both apply to the selected VMs and can be used when retrying
an already connected, CyberCore-managed agent. Registration IDs and keys are
reused; installing monitoring does not create a duplicate agent.

| Option | Applies to | Default | Installs or configures |
| --- | --- | --- | --- |
| Include Windows security telemetry | Windows targets | Selected in the UI | Sysmon, PowerShell script block logging, available Defender event collection |
| Include Suricata on Linux sensors | Debian, Ubuntu and Kali QEMU VMs | Off | Passive Suricata, ET Open rules, EVE JSON collection and log rotation |

API clients must explicitly request `windows_telemetry: true` or
`linux_suricata: true` on each matching target. Omitting the fields retains the
existing agent-only behavior. Turning an option off on a later deployment does
not uninstall a sensor or remove monitoring already configured.

## Windows profile

- Prefer Windows' Sysmon optional feature when it is available. Otherwise
  download Sysmon from Microsoft, extract only the executable for the machine's
  architecture, and require a valid Microsoft Authenticode signature.
- New Sysmon installations record process creation, network connections and DNS
  queries, with SHA-256 hashes. Expensive image-load/process-access collection,
  deleted-file archives and clipboard collection are not enabled by this profile.
- Preserve existing Sysmon services and configurations. An existing stopped or
  incomplete installation reports a setup issue instead of being replaced.
- Enable PowerShell script block logging for Windows PowerShell and PowerShell
  Core policies. Collect the PowerShell 7 channel when present. Do not install
  PowerShell 7 or enable module logging or transcription.
- Collect the available Defender Operational channel. Preserve its protection
  mode, exclusions and existing security policy; collecting an event channel
  does not activate an absent or disabled antivirus engine.
- Add missing Wazuh event-channel collectors without replacing existing queries.
  Report a warning when an existing query could restrict the expected coverage.
- Increase local event-log capacity to at least 128 MiB for Sysmon and 64 MiB
  for the other channels, preserving larger limits and existing retention modes.

The installer does not reboot the VM. A pending Windows feature restart is
reported for review. Missing PowerShell 7 or Defender is reported as an optional
source gap; required Sysmon/Windows PowerShell setup failures make the monitoring
job incomplete. The base Wazuh service is started before extended setup and
restarted after collection changes, including when a monitoring step fails.

## Linux Suricata profile

The sensor observes the **selected VM's default-route interface**. It can inspect
Windows traffic only if that traffic is routed through or explicitly mirrored to
that interface. Merely installing Suricata on a Kali VM does not give it every
other VM's traffic. This option does not create mirrors, modify lane gateways,
enable IPS, or change firewall rules. See [Windows network monitoring options](wazuh-windows-network-options.md)
for placement choices and the range's NAT attribution limits.

Packages come from the guest's configured distribution repositories with package
authentication enabled. Unsupported distributions and unmanaged Suricata
installations are preserved and report an actionable setup issue. The dedicated
configuration detects the interface's connected IPv4 networks for `HOME_NET`.
`EXTERNAL_NET` is `any` so rules can also detect attacks between machines inside
the same lane; this deliberately accepts more noise for classroom exercises.
Promiscuous capture accepts mirrored frames delivered to the selected interface.
The 6.x–8.x version gate describes installer configuration compatibility, not
upstream maintenance status; use distribution packages receiving security fixes.

| Item | Location or setting |
| --- | --- |
| Sensor service | `cybercore-suricata.service` |
| Configuration | `/etc/cybercore-suricata/suricata.yaml` |
| Detection rules | `/var/lib/cybercore-suricata/rules/suricata.rules` |
| Wazuh JSON source | `/var/log/cybercore-suricata/eve.json` |
| Rotation timer | `cybercore-suricata-logrotate.timer` |
| Resource budget | Two capture workers, 150% CPU quota, 512 MiB memory high watermark, 1 GiB maximum |
| EVE output | Alerts, statistics, DNS, TLS and flow metadata; no packet/body/file capture |
| Local rotation | Check each minute; rotate daily or above 50 MiB, keep three rotations |

The rotation threshold can be exceeded between checks. Size the VM and Wazuh
storage for actual class traffic. Rules are refreshed during setup/retry; this
version does not schedule daily rule updates. Maintain rule freshness explicitly
for long-lived sensors. Configuration/rules are tested with `suricata -T` before
the managed service starts; failed updates restore previous managed files when
possible. Existing unrelated Suricata configuration is not adopted automatically.

A local isolated Suricata 7.0.3 configuration test with 52,302 enabled ET Open
rules passed with approximately 482 MiB peak resident memory. Live flows and
future rules can consume more. Pilot the busiest expected lane before deploying
widely, and watch memory pressure, service restarts and EVE capture-drop counters;
the 1 GiB service limit can terminate an overloaded sensor.

For a manually maintained sensor, the following uses its dedicated update
configuration, keeps the updater's rule test enabled, and restarts the sensor
only after the test passes. The lock coordinates with CyberCore deployment.
Restarting creates a brief capture gap and avoids loading two detection engines
at once under the memory limit. Verify service health afterward; an updater's
exit code alone does not prove its restart command succeeded.

```bash
sudo flock -n /run/cybercore-wazuh-install.lock suricata-update \
  --config /etc/cybercore-suricata/update.yaml \
  --data-dir /var/lib/cybercore-suricata \
  --suricata /usr/bin/suricata \
  --suricata-conf /etc/cybercore-suricata/suricata.yaml \
  --output /var/lib/cybercore-suricata/rules \
  --reload-command='systemctl restart cybercore-suricata.service'
sudo systemctl is-active cybercore-suricata.service
```

The upstream updater backs up rules and restores them when its configuration
test fails. This is not a transaction across unexpected interruption and service
restart: a future scheduled updater needs staged publication, rollback and
health verification before enabling unattended refresh. See the
[official updater options](https://suricata-update.readthedocs.io/en/latest/update.html)
and [rule-test failure handling](https://github.com/OISF/suricata-update/blob/master/suricata/update/main.py).

## Enrollment and verification

Enrollment records now travel through guest-agent stdin. Executable installer
source and process arguments contain no enrollment key. Larger source files are
staged separately, checked against a SHA-256 digest in memory, and removed before
execution. Interrupted staging can leave nonsecret source fragments in the
guest's temporary directory. Linux's HTTP helper also supplies its authorization
header and request body through curl stdin, rather than command arguments.

After deploying this CyberCore version, select a small set of VMs and the desired
options. Connected VMs remain selectable in the individual target table; the
**Select missing agents** shortcut intentionally skips them. Completion requires
both monitoring configuration confirmation and a fresh Wazuh agent check-in.
Warnings appear with each installation job. No notifications or new Wazuh
manager detection rules are installed by these options.

Confirm newly generated events reach the intended Wazuh agent. Wazuh's default
alert index contains events that trigger indexed alerts, so enabling a collector
does not guarantee every process, DNS lookup or flow appears in an alert-based
dashboard. Use the source's local logs and manager collection configuration to
distinguish capture, forwarding and indexing. The [monitoring plan](wazuh-monitoring-plan.md)
covers priorities, retention, alert tuning and coverage checks.

For operational diagnosis, use the Windows event logs and Sysmon service status,
or on a Linux sensor inspect `journalctl -u cybercore-suricata.service` and its
EVE file. Investigate setup warnings before declaring monitoring coverage; a
running Wazuh agent alone does not establish working IDS capture.

## Validation on September 7, 2026

- All 245 Wazuh tests passed, including route validation, UI selection, ownership,
  teardown cleanup, generated installers and secret-free dispatch. The 29 Linux
  sensor and enhanced integration tests passed again after the final network
  scope adjustment.
- Windows VM 610811 completed an enhanced installation and an idempotent retry
  using its existing agent registration, ID 017. Sysmon and Wazuh were running;
  Sysmon, Windows PowerShell and Defender collectors were present and enabled.
  PowerShell 7 was absent and correctly reported as an optional source gap.
- Local events confirmed process creation, network connections, DNS queries and
  PowerShell script blocks. Wazuh's alert index contained new Sysmon and
  PowerShell events for this agent. A bounded scan of 588 Sysmon and 271
  PowerShell events since the pilot began found no enrollment key in encoded,
  decoded-record or raw-key form. This checks the observed pilot, not every
  possible logging product or policy.
- An isolated real Suricata engine accepted the generated Linux configuration
  and downloaded ET Open rules. No live Linux sensor or traffic mirror was
  deployed during this validation; a network capture pilot is still required
  before broad sensor deployment.
