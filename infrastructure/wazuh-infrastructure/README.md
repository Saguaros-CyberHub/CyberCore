# Infrastructure monitoring for CyberCore

This pack adds targeted infrastructure file monitoring and a sanitized CyberCore
security feed to the existing Wazuh 4.14.1 installation. It creates no sensor VMs,
traffic mirrors, packet capture services, firewall changes, or automatic blocking.

## Deployment scope

Create the additive group `CyberCoreInfrastructure` and assign it only to the
inventoried infrastructure agents. Preserve their existing groups and put this
group last so its explicit settings take precedence. The profile also uses exact
agent-name filters; adding it to a student agent will not apply these blocks.

| Host | Registered name | Agent IDs at the September 7 inventory |
| --- | --- | --- |
| Proxmox nodes | `cyberhub-node-0` through `cyberhub-node-6`, `cyberhub-node-10`, `cyberhub-node-11` | `001,002,003,006,007,008,225,226,227` |
| CyberCore | `250-CyberCore` | `012` |
| NetBox | `251-netbox` | `010` |
| Heimdall | `252-heimdall-dashboard` | `011` |

Confirm IDs against names before assigning the group. Wazuh manager `000` does
not receive an agent group; its local monitoring configuration and external
availability checks need separate validation. No router agent was registered at
the initial inventory.

`agent.conf` adds identity, persistence, Wazuh configuration, selected Proxmox
cluster/network/firewall files, and CyberCore source/configuration paths. File
hashes and metadata are collected; file contents and diffs are disabled, including
for existing inherited FIM paths. This avoids copying secrets from `.env`, keys,
cluster credentials, or Wazuh enrollment files into alerts.

The 900-second scheduled interval applies to **all merged FIM paths**, including
the existing `/etc` and binary directories. Check scan duration and host overhead
after rollout; increase the interval if scans are expensive. Real-time watches
cover selected local directories. Individual files and cluster-backed `/etc/pve`
still require scheduled verification; do not assume inotify sees remote cluster
writes. Newly created wildcard paths are discovered during scheduled scans.

Only the nine exact `lrm_status` runtime paths are ignored. Node 1 produced 8,635
alerts for this HA status file in the sampled 24 hours. Users, firewall rules,
storage configuration, VM configuration, and other `/etc/pve` files remain subject
to their existing coverage. This pack deliberately does not add blanket realtime
monitoring of all student VM configuration churn.

The existing journal collectors already supply Proxmox authentication/system
events. This pack does not duplicate them or install auditd on the hypervisors.
CyberCore already has an auditd collector. Do not enable broad process-argument
auditing merely to increase volume: enrollment commands and administrative tools
may carry credentials.

## CyberCore security feed and rules

The application writer creates `/app/logs/security-YYYY-MM-DD.jsonl`, exposed on
the host at `/home/cactus-admin/CyberCore/logs/security-YYYY-MM-DD.jsonl`. Only this
feed is added to the CyberCore agent. The writer uses an explicit schema of safe
action codes, outcomes, opaque actor/target identifiers, source IP, trusted route
patterns and status codes. It excludes request bodies, query strings, headers,
cookies, passwords, freeform metadata and exception text. Do not substitute raw
application/Caddy logs for this feed; historical logs may contain request tokens.
The discriminator is `cybercore_event` (`audit`, `http` or `health`), deliberately
not `event_type`: Wazuh's built-in Suricata rules claim JSON with that generic key.

`cybercore-infrastructure-rules.xml` adds these groups of alerts:

| Signal | Rule | Level | Interpretation |
| --- | --- | --- | --- |
| Infrastructure agent disconnected | `111900` | 10 | Known infrastructure agent stopped checking in; investigate host/network/agent health |
| Routine audit action | `111921` | 3 | Searchable activity, including expected student lifecycle actions |
| Audit database write failed | `111922` | 8 | Security summary survived but the application's audit record did not |
| Denied/failed audit action | `111923` | 5 | Review the action and role |
| Authentication failure | `111924` | 5 | Individual failed or denied authentication |
| Repeated authentication failure | `111925` | 10 | Starting threshold: 10 matching events within 120 seconds from one source |
| Admin account/configuration action | `111926` | 5 | Review against planned administrative changes |
| Security feed dropped events | `111929` | 8 | Capacity, backpressure, rejected event or storage availability issue |
| HTTP missing route | `111930` | 3 | Routine low-priority visibility |
| HTTP unauthorized/rate-limited | `111931,111932` | 5 | Review role and rate context |
| HTTP server error | `111933` | 7 | Application availability or input-triggered error |
| Sensitive-file/exploit probe | `111934` | 7 | Request classified without storing its raw path |
| Probe received HTTP 2xx | `111935` | 8 | Verify route handling; 2xx alone does not prove sensitive data was exposed |

These are additive rules. Existing FIM, SSH/PAM, auditd and Proxmox authentication
rules retain their built-in definitions. No rule in this pack suppresses those
detections. The repeated-authentication threshold is a tunable starting point:
many users can share a proxy/NAT source. Verify the application's trusted proxy
configuration before using `srcip` to attribute a person or impose restrictions.

For trusted application incident routing, require both `agent.id:012` and
`rule.groups:application_security`. Student administrators can forge or disable
their own endpoint telemetry. A matching integration label or file path alone
does not establish that a student-origin event came from CyberCore.

## Validate and activate

Run the portable checks in the checkout:

```bash
python3 infrastructure/wazuh-infrastructure/verify.py
```

Stage a copy of `agent.conf` outside the active group filename, preserve the prior
configuration, and validate with the manager's own parser before activating it:

```bash
/var/ossec/bin/verify-agent-conf -f /path/to/staged/agent.conf
```

Stage the rules as a new file under `/var/ossec/etc/rules/`; do not replace
`local_rules.xml` or built-in files. Keep its owner/group consistent with existing
rule files. Run `/var/ossec/bin/wazuh-analysisd -t` before a controlled manager
restart. Existing custom IDs must not collide with `111900` or `111920-111935`.

After staging the rules, run the sandbox tests on the manager:

```bash
python3 /path/to/staged/verify.py --manager-tests
```

The tests exercise 20 representative events plus same-source authentication
correlation through `wazuh-logtest`. They do not send production alerts, change
configuration, stop services or call external APIs. Negative cases keep student
disconnects, misleading host-name prefixes and unrelated log locations at their
built-in rule instead of promoting them to an infrastructure outage.

After activation, verify group synchronization and each agent's effective FIM
configuration. Confirm a new sanitized application event reaches the index as
agent `012`; check the actual decoded fields and rule ID. A harmless temporary
file in an explicitly monitored local directory can verify FIM creation/change/
deletion, with a recognizable test filename and immediate cleanup. Do not edit
real secrets, SSH configuration, cluster configuration or student files to test.

Agent disconnection remains the manager's existing 15-minute threshold with zero
additional delay. Zero here means alert immediately once considered disconnected.
Use logtest for the rule first; coordinate any real service-stop test so a test
outage is identifiable and the agent is promptly restarted. No component can
prove its own total outage through itself: Wazuh manager/indexer/dashboard and
CyberCore availability need independent probes.

## Router boundary coverage

The trusted existing router is the enforcement/observation point for traffic
that traverses it. Import actual OPNsense firewall events and IDS alerts from
that router before claiming those dashboards have coverage. No such receiver is
configured by this pack. Do not open a syslog listener to all student networks.

Known lane gateways NAT `10.42.x.x` to `100.100.60.0/22`; the sampled lane uses
`100.100.62.68`. Router events therefore identify the lane gateway. Correlate its
lease/lane mapping and timestamp to investigate the originating VM. Never treat
an OS choice as a trust boundary: Windows and Kali student machines are both
untrusted when students administer them.

Prioritize attempts to reach infrastructure in `100.100.10.0/24` and
`100.100.20.0/24`, particularly management services. Distinguish blocked attempts
from unexpected allowed connections. Preserve explicit required services such
as Wazuh TCP 1514 and CyberCore HTTP/HTTPS. Exercise traffic inside authorized
lanes does not justify automatic blocking of an entire NAT gateway.

For future filterlog escalation, first validate actual logs with the installed
decoder. Wazuh's built-in pf rule `87701` is intentionally unlogged and feeds
`87702` repeated-source correlation. A generic child of `87701` can change the
matching chain; avoid introducing one blindly. An additive child of `87702`
can promote repeated blocks whose final destination is management, but it must
say "repeated blocks including a management destination": the built-in counter
groups by source, not by management destination. No unverified boundary rule is
installed by this pack.

## Primary references

- [Wazuh centralized configuration and precedence](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [FIM attributes, real-time limits, simple regex ignores and no-diff settings](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Wazuh global agent disconnection settings](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)
- [Wazuh rule syntax and correlation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh logtest sandbox](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [Wazuh 4.14.1 agent/FIM built-in rules](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0015-ossec_rules.xml)
- [Wazuh 4.14.1 Proxmox authentication rules](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0495-proxmox-ve_rules.xml)
- [Wazuh 4.14.1 pf firewall rules](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0540-pfsense_rules.xml)
- [Wazuh 4.14.1 native agent health messages](https://github.com/wazuh/wazuh/blob/v4.14.1/src/error_messages/error_messages.h)
