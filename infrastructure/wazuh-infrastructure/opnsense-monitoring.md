# OPNsense monitoring and lab boundary

Deployment: `saguaros-opnsense-1`, OPNsense 26.7.3_8, 2026-09-07 local time.
This records the configuration of the existing firewall. No sensor VM, traffic
mirror, Windows packet capture, or inline IPS was added.

## Log delivery

Two native **System → Settings → Logging → Targets** entries send RFC3164 logs
to `100.100.20.10:514`, transport **TCP(4)**:

| Description | Applications | Facilities |
| --- | --- | --- |
| CyberCore Wazuh firewall and IDS logs | `filterlog,configd.py,firewall,suricata` | unrestricted |
| CyberCore Wazuh authentication logs | unrestricted | `auth,authpriv` |

Leave severity filters empty, enable both targets, and leave RFC5424 disabled.
OPNsense's audit logger uses the `auth` facility, so it is covered together with
SSH authentication. Unbound query logging is not forwarded by these targets.
The sender selects `100.100.20.1` on `vlan0.20`; Wazuh's TCP receiver binds to
`100.100.20.10:514` and accepts only `100.100.20.1`. This is internal TCP syslog,
without TLS or agent enrollment. Received firewall events are identified by
their trusted receiver location; they do not create an endpoint registration.

The existing OPNsense Wazuh plugin was stopped and retained registration ID
`015`, which no longer existed on the manager. Its installed agent version,
4.14.7, is newer than the 4.14.1 manager. The plugin is disabled while syslog is
used; its old key and log evidence were retained. Disabling its native template
also stops the unused duplicate writer to
`/var/ossec/logs/opnsense_syslog.log` (approximately 11.9 GB at audit time).
Manager upgrades or router package changes require a separate change.

## IDS

Native **Services → Intrusion Detection → Administration** settings:

| Setting | Value |
| --- | --- |
| Enabled | yes |
| Capture mode | PCAP live mode (IDS) |
| Interface | `opt7`: `vlan060_lab`, device `vlan0.60` |
| Promiscuous mode | disabled; routed traffic already reaches this interface |
| Home networks | `100.100.0.0/16,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12` |
| EVE syslog output | enabled |
| Fast syslog alerts | disabled |
| Log payload | disabled |
| HTTP/TLS extended event logging | remains disabled |
| Local alert rotation | daily, seven saved logs |

Enable these ET Open files in the native Download tab:

```text
botcc.rules
botcc.portgrouped.rules
compromised.rules
emerging-attack_response.rules
emerging-coinminer.rules
emerging-current_events.rules
emerging-dns.rules
emerging-exploit.rules
emerging-exploit_kit.rules
emerging-malware.rules
emerging-phishing.rules
emerging-scan.rules
emerging-shellcode.rules
emerging-web_server.rules
emerging-worm.rules
```

The initial download produced 28,112 active rules in 16 generated files,
approximately 26.8 MB. The installed Suricata 8.0.6 configuration passed a real
`suricata -T`. The existing rule policy retains alert actions. This deployment
does not install automatic blocking or active responses.

The existing native `ids update` cron entry is enabled at 00:00 every day in
the firewall's local timezone. Its UUID is
`b8d16807-81d2-478d-bb99-e3b946a44c01`; the rendered entry was verified in
`/var/cron/tabs/nobody` after successful download, configuration testing, and
service startup.
Native rule updates use OPNsense's updater and reload mechanism, rather than a
second external scheduler. Check the IDS log after scheduled updates; a
download setting alone does not prove that fresh rules loaded.

This interface observes traffic crossing the lab perimeter. Lane gateways NAT
guests to addresses such as `100.100.62.68`; correlate those addresses with
CyberCore's lane history. Same-lane traffic stays inside its bridge and is not
visible here. Traffic that never crosses the lab interface is outside this IDS
capture scope. Endpoint agents remain the source of host activity.

## Lab management rules

These native **Firewall → Rules [new]** entries apply only **inbound** on `opt7`,
use IPv4, quick evaluation, and log matches. Rules precede the existing broad
lab web and firewall-self allowances. Source is `any` unless stated otherwise.
Each TCP port below is a separate named rule.

| Sequence | Action | Destination / protocol | Description |
| --- | --- | --- | --- |
| 50–52 | block | This Firewall `(self)`, TCP 22 / 80 / 443 | CyberCore deny lab firewall management TCP PORT |
| 55 | pass | This Firewall, TCP/UDP 53 | CyberCore preserve firewall DNS |
| 56 | pass | This Firewall, UDP 123 | CyberCore preserve firewall NTP |
| 60 | pass | `100.100.10.0/24`, ICMP | CyberCore preserve lab management ICMP |
| 61 | pass | `100.100.60.10` → `100.100.10.12`, any protocol | CyberCore preserve existing test-host management exception |
| 62 | block | `100.100.10.0/24`, any protocol | CyberCore deny lab management subnet |
| 70–73 | block | `100.100.20.10`, TCP 22 / 443 / 55000 / 9200 | CyberCore deny lab Wazuh management TCP PORT |

Deployed rule identities, for matching native filterlog tracker fields:

| Sequence | Native UUID |
| --- | --- |
| 50 | `446fe580-9995-420f-a3a4-4fd0d398c372` |
| 51 | `8932238e-3b40-449b-92f5-d1c44926abed` |
| 52 | `5218ba12-3b41-4dd3-a70a-dbd554c626a6` |
| 55 | `18557e65-d272-4b4a-821e-86b089249a91` |
| 56 | `e2ff5812-7b15-477b-9e39-9e16caff25c3` |
| 60 | `420c7e76-5d02-4635-9a7e-b4c3c3917e67` |
| 61 | `23b1f133-8961-4f2c-92fe-dfdc919e71c5` |
| 62 | `b24d5c70-dc05-471f-a047-01e2cc2d9b26` |
| 70 | `590f4f7a-2ef6-43d4-9446-430f4a7c8778` |
| 71 | `b4e6f900-9552-49ed-b029-66eb457c05d6` |
| 72 | `81c04778-f35d-44b8-9243-309568d42939` |
| 73 | `a87f398c-e170-453f-a71d-8a3a2a9dbf09` |

The existing sequence-100 rule still allows `100.100.60.0/22` to
`100.100.20.10:1514/TCP`. Existing DHCP rules, public web access, CyberCore
HTTP/3000 allowances, and other explicit service rules remain in place.
Firewall state is not globally flushed; these changes govern new connections.

Two existing maintenance exceptions need an ownership review:

- `100.100.60.10` → Proxmox `100.100.10.12`: every protocol/port. The original
  rule had no description and no logging; its explicit preserved entry now logs.
- `100.100.60.10` → backup server `100.100.20.30`: every protocol/port, with the
  existing description `Allow Test Server -> Backup Server` and logging.

These exceptions are retained trust relationships, not general student access.
No broad management allowance was added for the workspace. Administrative SSH
can use the existing management-side Proxmox hop, with both host keys verified.

## Validation and rollback

The native models were validated before saving. Syslog templates passed
`syslog-ng -s`; loaded firewall rules passed `pfctl -nf /tmp/rules.debug`, and
all 12 expected rule identities were found in the active ruleset.

Real TCP probes from gateway CT 110811's network namespace confirmed:

| Check | Before | After |
| --- | --- | --- |
| Firewall `100.100.10.1:22` and `:443` | reachable | blocked |
| Wazuh dashboard `100.100.20.10:443` | reachable | blocked |
| Wazuh API `100.100.20.10:55000` | not tested | blocked |
| Proxmox `100.100.10.13:8006` | blocked | blocked |
| Wazuh agent ingestion `100.100.20.10:1514` | reachable | reachable |
| CyberCore `100.100.20.50:80` | reachable | reachable |
| Public HTTPS | reachable | reachable |
| DNS through `100.100.60.1` | not tested | resolves |

The DNS/NTP preservation entries additionally retain those services on the
firewall's management address. Actual logged denies included pilot gateway
`100.100.62.68` to Wazuh management ports and Proxmox 8006. Two established
syslog connections use `100.100.20.1` as their source. Sender counters showed
18,432 firewall/IDS messages written and 76 authentication messages written,
with zero queued, dropped, or truncated messages at the sampled time.

A temporary native alert rule restricted to pilot gateway `100.100.62.68` and
firewall `100.100.60.1` verified packet detection. One controlled ping produced
an EVE `wire/pcap` ICMP alert at `2026-09-08T01:39:48.303384Z`, signature
`CyberCore benign monitoring validation`, SID `4294967294`, action `allowed`.
The same event entered Suricata syslog. One normal DNS packet also matched the
temporary address-scoped rule. The rule was then removed from native
configuration and compiled rules; the production rules passed another real
`suricata -T` before reload.

Wazuh requires the accompanying
[program-scoped JSON decoder](cybercore-infrastructure-decoders.xml) for
Suricata EVE inside a syslog wrapper. Raw EVE alone matched its native rule,
but the wrapped event initially had no decoder. After that decoder was
activated, exactly one sanitized replay of the original ICMP event was emitted
through the router's normal `suricata` syslog program, marked
`cybercore_validation_replay: true`. Wazuh indexed it at
`2026-09-08T01:47:39.094Z` under native rule **86601**, level **3**, with receiver
location **100.100.20.1**. This separately verifies real packet detection and
the corrected syslog → decoder → searchable-alert path; the replay was not a
second packet detection.

After the production boundary rule was activated, a bounded test made 54 TCP
connection attempts from the pilot gateway to blocked Wazuh HTTPS in 27.03
seconds, with **54 blocked and zero connected**. Wazuh indexed the corresponding
infrastructure-boundary escalation, rule **111901**, at
`2026-09-08T01:47:39.098Z`. No authentication or application payload was sent.

Suricata used approximately 1 GB before rule reloads. Capture reported 21,497
cumulative kernel drops by the first five-minute sample; the count stayed flat
over the next 274,473 packets. Twenty further drops occurred in the later
validation/production reload interval. A final stable production sample saw
4,416 packets in 10.03 seconds with **zero additional drops**. These are bounded
observations, not a claim of lossless capture. Monitor counter deltas during a
busy class and around rule reloads.

Protected on-router configuration backups:

- `/root/cybercore-monitoring-backup-20260908T012725Z/config.xml`: before the
  initial monitoring and boundary change.
- `/root/cybercore-monitoring-backup-20260908T013627Z/config.xml`: before adding
  the explicit firewall DNS/NTP preservation entries.
- `/root/cybercore-monitoring-backup-20260908T014317Z/config.xml`: before
  enabling the tested daily IDS update schedule.

Backup directories are mode 0700 and configuration files are mode 0600. They
contain the complete device configuration and must remain on the protected
router; they are not repository artifacts. Prefer reverting the named native
model entries through OPNsense's configuration history. If restoring a whole
backup, first check for later administrator changes, then regenerate the
affected templates and reload the corresponding services and filter. Preserve
current administrative access; do not overwrite concurrent configuration edits.

The lane gateway audit covered CT 110811: IPv4 INPUT/FORWARD default DROP,
private/management destination denies, narrow Wazuh 1514 and CyberCore 80
allowances, IPv6 disabled, and no local denial log rule. The cluster contained
270 running lane gateways across nine nodes. This sample does not certify all
270 gateway configurations or all same-lane isolation paths.

References: [OPNsense logging](https://docs.opnsense.org/manual/settingsmenu.html#logging),
[OPNsense IDS](https://docs.opnsense.org/manual/ips.html),
[OPNsense Wazuh plugin](https://docs.opnsense.org/manual/wazuh-agent.html),
[Wazuh upgrade compatibility](https://documentation.wazuh.com/current/upgrade-guide/index.html).
