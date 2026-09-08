# Live infrastructure monitoring verification

Deployment date: September 7, 2026 (America/Phoenix); the final checks occurred
September 8 UTC. This is the recorded result of this deployment, not a continuous
health guarantee.

## Scope and effective configuration

The additive `CyberCoreInfrastructure` group is active on all twelve inventoried
agents, with their previous groups preserved:

| Systems | Agent IDs |
| --- | --- |
| Proxmox nodes 0, 1, 2, 3, 4, 5, 6, 10 and 11 | `001,002,003,006,007,008,225,226,227` |
| CyberCore, NetBox and Heimdall | `012,010,011` |

Every agent was active and its effective configuration contained the 900-second
FIM interval, targeted identity/persistence paths and realtime `/var/spool/cron`
monitoring. CyberCore additionally had realtime user SSH and user systemd paths,
application source/configuration monitoring, and its sanitized security JSONL
collector. No effective FIM path had file-content diffs enabled.

The Wazuh manager has targeted local identity, persistence and Wazuh configuration
FIM, plus a TCP 514 receiver bound to `100.100.20.10`, accepting only the router's
`100.100.20.1` sender. The router
uses native syslog and its existing Suricata service; it does not appear as a new
agent. See [the router configuration and rollback record](opnsense-monitoring.md).

## Evidence

- A temporary non-configuration file `/etc/ssh/.cybercore-fim-probe` on node 3
  generated indexed file-added, modified and deleted alerts (`554`, `550`, `553`).
  The probe was removed. Hashes and metadata were present; file contents were not.
- Real router SSH authentication reached the Wazuh index with source location
  `100.100.20.1`. Native firewall correlation `87702` also reached the index.
- New connections from the sampled lane gateway were denied to router management,
  Wazuh management and Proxmox management. Wazuh TCP 1514, CyberCore HTTP, public
  HTTPS and router DNS still worked. The router record contains the exact tests.

- A real HEAD request for `/.git/HEAD` returned 404 and produced indexed rule
  `111934` (level 7) for CyberCore agent `012` at `2026-09-08T01:47:11.128Z`.
  The event contained the fixed classification `probe_vcs` and safe route
  `/[probe_vcs]`; the query string was absent. This verified application writing,
  the agent collector, the authenticated-location rule and indexing together.
- The router generated a real wire/PCAP ICMP IDS alert at
  `2026-09-08T01:39:48.303384Z` using a temporary address-scoped rule. After that
  rule was removed and the syslog decoder was installed, one explicitly marked
  replay of its harmless metadata traversed router syslog, Wazuh and the index.
  It appeared as native Suricata rule `86601` at `2026-09-08T01:47:39.094Z`, with
  receiver location `100.100.20.1` and `cybercore_validation_replay:true`.
  The network record separates packet detection from this delivery test.
- Fifty-four TCP connection attempts from gateway `100.100.62.68` to Wazuh
  management `100.100.20.10:443` completed in 27.03 seconds: all failed to connect.
  Their real firewall logs produced one indexed custom boundary escalation
  `111901` (level 12) at `2026-09-08T01:47:39.098Z`. Two native `87702` alerts
  were also retained. No authentication or application data was sent.
- All 52 fixtures, including negative origin/decoder cases and native firewall
  counter behavior, passed the manager's actual `wazuh-logtest`; the additional
  same-source authentication burst test passed. Native configuration/decoder/
  rule syntax checks passed before activation. The application changes had
  passed 49 focused security-event and audit tests.

## Service health at verification

Wazuh manager, indexer, Filebeat and dashboard were active, with successful main
process exit status. Filebeat's output test passed. The indexer was green with
zero unassigned shards and zero pending tasks.

CT 210 had approximately 201.8 GiB free disk out of 250.9 GiB, and 10.1 GiB of
available memory out of 16 GiB. Analysis queues and the receiver queue were empty.
The receiver's discarded-event counter was zero. Analysisd had 8,700 historical
dropped events; that counter remained unchanged while another 1,706 events
arrived. This does not establish when those earlier drops occurred or recover
their contents. Watch queue/drop counters and ingestion freshness under load.
Router capture also had historical/startup/reload drops. A stable final sample
received 4,416 packets in 10.03 seconds with no new capture drops. Neither sample
establishes lossless capture during a busy class.

## What to watch

| Signal | Investigation focus |
| --- | --- |
| Infrastructure agent disconnected | Host reachability, stopped agent, tampering or resource exhaustion |
| Root/admin authentication, failed login bursts | Unexpected source, account or time; correlate with planned work |
| SSH keys, sudo/PAM, cron or systemd changes | New persistence or privilege changes; compare with approved maintenance |
| Proxmox users, storage, network and firewall changes | Unexpected privileges or access between lab and infrastructure |
| CyberCore denied actions, admin changes and audit-write failures | Role abuse, account takeover or a broken audit trail |
| CyberCore sensitive-path probes and server errors | Repeated probing, unusual sources and affected routes |
| Router management blocks and IDS alerts | Unexpected boundary access or signatures; distinguish exercises from infrastructure targeting |
| Collection drops, stale events, disk and service health | Blind spots caused by logging failures or excessive lab traffic |

## Practical limits and retained policy

Router IDS covers traffic crossing `vlan060_lab`, including Windows traffic that
crosses that interface. Same-lane traffic and traffic on other interfaces are
outside that capture scope. Endpoint agents provide host activity independently.
No extra sensor VM, traffic mirror or Windows capture driver was deployed.

Lane gateways use NAT. A router source such as `100.100.62.68` identifies a lane
gateway, not a student by itself. Correlate the lane/VM assignment and timestamp.
The gateway audit sampled CT 110811; it did not certify every running gateway.

Existing broad maintenance exceptions for `100.100.60.10` to Proxmox
`100.100.10.12` and backup server `100.100.20.30` were preserved. Their ownership
and continued need should be reviewed. Rules were applied without flushing all
firewall states, so existing established connections were not forcibly ended.

Alerts appear in Wazuh. This deployment does not configure email/Slack paging,
automatic active response, or an independent availability monitor for Wazuh
itself. Student administrators can disable or forge telemetry on their own VMs;
infrastructure-side observations remain necessary.
The application's reserved drop notices work only while its log remains writable.
A full or inaccessible disk needs independent monitoring; the unavailable file
cannot carry its own failure alert.

## Change control and rollback

The application code and this pack are committed in CyberCore. The live checkout
is synchronized by a verified Git bundle and fast-forward, without an external
push. Dashboard artifacts remain in the explicitly ignored
`infrastructure/wazuh-dashboards/` directory.

Protected manager backups include:

- `/var/ossec/backup/cybercore-infrastructure-20260908T012505Z/agent.conf`:
  the original new group's empty profile.
- `/var/ossec/backup/cybercore-infrastructure-20260908T013018Z/agent.conf`:
  the profile before the final user SSH/systemd and cron additions.
- `/var/ossec/backup/cybercore-infrastructure-20260908T012617Z/ossec.conf`:
  the manager configuration before syslog and local FIM additions.
- `/var/ossec/backup/cybercore-rules-20260908T014549Z/`:
  the previous rules before the final decoder, origin guard and boundary rule.

Rule/decoder staging also creates dated `cybercore-rules-*` backups and restores
the previous files if native validation fails. Validate any rollback with the
manager's own parsers before restarting. Preserve unrelated later changes and
the agents' original group memberships when removing this additive profile.
