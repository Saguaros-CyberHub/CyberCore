# Infrastructure monitoring for CyberCore

This folder contains targeted infrastructure file monitoring, a sanitized CyberCore
security feed, and Wazuh 4.14.1 rules. The companion deployment configures the
existing OPNsense router for alert-only IDS, native log forwarding, and explicit
lab-to-management firewall restrictions. It uses existing machines without new
sensor VMs or traffic mirrors.

See [OPNsense monitoring and boundary configuration](opnsense-monitoring.md) for
the router settings, and [deployment verification](deployment-verification.md)
for the configuration applied and the checks completed on the running systems.

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
| Repeated lane gateway blocks include infrastructure | `111901` | 12 | Native firewall correlation ended on a Proxmox subnet or Wazuh destination; review attempts and required service connectivity |
| Routine audit action | `111921` | 3 | Searchable activity, including expected student lifecycle actions |
| Audit database write failed | `111922` | 8 | Security summary survived but the application's audit record did not |
| Denied/failed audit action | `111923` | 5 | Review the action and role |
| Authentication failure | `111924` | 5 | Individual failed or denied authentication |
| Repeated authentication failure | `111925` | 10 | Starting threshold: 10 matching events within 120 seconds from one source |
| Admin account/configuration action | `111926` | 5 | Review against planned administrative changes |
| Security feed dropped events | `111929` | 8 | Reserved health records report quota, backpressure or rejected events while the JSONL file remains writable |
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
If the security file or disk is unavailable, the writer cannot append its own
health event there. Its safe stderr notice and in-process drop statistics remain
available, but independent service/storage monitoring must detect that failure;
rule `111929` cannot guarantee an alert through the unavailable file.

For trusted application incident routing, require both `agent.id:012` and
`rule.groups:application_security`. Student administrators can forge or disable
their own endpoint telemetry. Rule `111920` therefore matches the full incoming
location `(250-CyberCore) any->/home/cactus-admin/CyberCore/logs/security-YYYY-MM-DD.jsonl`,
using the authenticated agent name and its current registration IP value (`any`).
Wazuh strips that prefix later when writing the alert JSON. A bare-path logtest
would miss this distinction; fixtures include the full prefix and reject student
prefixes and bare paths. If agent `012` is re-registered with a different name or
registration IP, update this explicit rule guard and rerun the tests.

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

Stage the rules as a new file under `/var/ossec/etc/rules/` and
`cybercore-infrastructure-decoders.xml` under `/var/ossec/etc/decoders/`; preserve
`local_rules.xml` and built-in files. Keep owner/group consistent with existing
configuration files. Run `/var/ossec/bin/wazuh-analysisd -t` before a controlled manager
restart. Existing custom IDs must not collide with `111900-111901` or `111920-111935`.

After staging the rules, run the sandbox tests on the manager:

```bash
python3 /path/to/staged/verify.py --manager-tests
```

The tests exercise 52 fixtures plus same-source authentication correlation
through `wazuh-logtest`. They do not send production alerts, change
configuration, stop services or call external APIs. Negative cases keep student
disconnects, misleading host-name prefixes and unrelated log locations at their
built-in rule instead of promoting them to an infrastructure outage.
The boundary fixtures retain actual observed blocked-packet bodies (with normalized
syslog headers), cover all nine Proxmox IPs and both Wazuh management services,
and verify allowed connections stay at the native level-zero rule. Repeated-event
fixtures check matches at events 18, 36 and 54, exactly as the unmodified native
correlation behaves in this sandbox. Phase 3 reports a matched rule even when
its ignore timer suppresses production emission; it does not prove that an alert
was written. Verify the configured 240-second suppression interval separately
with controlled blocked connections and the resulting real alert records.
Decoder tests check raw EVE JSON and RFC3164 Suricata messages with/without a PID,
preserve native rule `86601` and the numeric signature ID, and reject unrelated
program names and plain service text.

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

The existing router is the enforcement and observation point for traffic crossing
the lab boundary. The companion deployment sends native firewall, IDS and
authentication logs over TCP from `100.100.20.1` to `100.100.20.10:514`; the Wazuh
receiver accepts only that router source. The agent profile and rule XML alone
do not install these router/receiver settings. Their exact native configuration
is recorded in [opnsense-monitoring.md](opnsense-monitoring.md); actual indexed
event verification is recorded in [deployment-verification.md](deployment-verification.md).

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

Observed filterlog bodies for lane gateway `100.100.62.68` blocked from Wazuh
TCP 55000/443 and Proxmox TCP 8006 were verified against the installed 4.14.1
decoder. Native forwarding uses RFC3164; the retained local RFC5424 samples have
only their headers normalized for these tests. Router socket checks confirmed
TCP forwarding from `100.100.20.1` to the manager's port 514. Verify real indexed
events carry that source location before claiming end-to-end boundary coverage.

Wazuh's built-in pf rule `87701` is intentionally unlogged and feeds `87702`
repeated-source correlation. Rule `111901` is a child of **87702**, preserving
its 18-block/45-second counter. It has its own 240-second suppression interval:
the engine does not inherit the parent's ignore timer on the final matched rule.
Native and infrastructure escalations have separate suppression state. The rule
also requires trusted router location `100.100.20.1`, lane source `100.100.60.0/22`, and a final destination
in `100.100.10.0/24` or exactly `100.100.20.10`. The two destination entries are
an OR list. It says "repeated blocks include infrastructure destination" because
earlier blocks in the counter can target other destinations. This detects
attempts or required-service connectivity failures, not a proven compromise.
An allowed Wazuh 1514 or CyberCore 443 connection remains at the unalerted native
pass rule; unrelated blocked traffic retains native correlation.

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
- [Production analysisd applies ignore to the final matched rule](https://github.com/wazuh/wazuh/blob/v4.14.1/src/analysisd/analysisd.c)
- [Logtest records generated_rule before its ignore check](https://github.com/wazuh/wazuh/blob/v4.14.1/src/analysisd/logtest.c)
