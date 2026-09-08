# Monitoring the CyberCore college cyber range

Protect shared infrastructure and keep classes usable while preserving evidence of
what happened inside each exercise. A student running an exploit against their
assigned target is expected; the same activity against Proxmox, CyberCore,
another student's lane, or an external organization needs investigation.

This is a proposed operating plan, not a claim that every source or alert below
is configured. Imported dashboards visualize indexed data; they do not enable
collectors, create notifications, or enforce network isolation.

## 1. Establish ownership and scope first

- Keep separate policies for `StudentVM`, production services, hypervisors,
  network devices, and the Wazuh service itself. These are monitoring scopes;
  the existing Wazuh groups need not be renamed.
- Associate every lane with its course, exercise, owner, authorized targets,
  start/end time, VMIDs, and gateway addresses. Keep the authoritative mapping
  in CyberCore, outside student-controlled guests.
- Use readable agent names such as `cle-cybr400-inperson-10811-vm-610811`, but
  retain the lane UUID, Wazuh agent ID, and deployment lifetime for historical
  correlation. VMIDs and names can be reused after destruction.
- Record approved CALDERA operations and test windows. Annotate expected exercise
  findings rather than suppressing everything from an attack VM.
- Synchronize clocks on hosts, guests, firewall, CyberCore, and Wazuh. Keep UTC
  timestamps in evidence and display the local timezone for class operations.

## 2. Prioritized monitoring checklist

The priority here is an operational recommendation, independent of Wazuh's
numeric rule level. A large alert count alone does not establish compromise.

| Priority | Watch for | Sources needed | First response |
| --- | --- | --- | --- |
| **Immediate** | Successful lane access to an unauthorized management service, another lane, or a prohibited external target | OPNsense rule/connection logs, endpoint network events, CyberCore lane/address history | Confirm destination, rule, lane, and exercise authorization; investigate the isolation boundary |
| **Immediate** | Unexpected admin login, API token creation, permission elevation, MFA change, or destructive action on shared systems | CyberCore and identity-provider audit events; Proxmox, OPNsense, Wazuh, and OS authentication/admin logs | Verify actor and maintenance window; preserve the relevant audit trail |
| **Immediate** | Malware, persistence, credential theft, or security-tool tampering on production infrastructure | Defender/Sysmon, Linux audit/auth logs, FIM, Wazuh service events | Escalate to the platform operator and assess affected shared services |
| **Immediate** | Loss of cluster quorum, unavailable storage, exhausted disk, or widespread loss of telemetry during class | Proxmox/Ceph metrics and logs; Wazuh queues/indexer health; service probes | Restore visibility or availability and identify affected classes |
| **Same class period** | Repeated blocked attempts toward management networks or other lanes | Logged boundary deny rules; network IDS where deployed | Check for a misconfigured exercise, broad scanner, or deliberate boundary probing |
| **Same class period** | Password spraying, new privileged accounts, suspicious remote logins, unexpected scheduled tasks/services | Windows Security/System events, SSH/sudo/auditd, identity-provider events | Correlate user, target, process, and exercise scope |
| **Same class period** | Agent stopped, logs cleared, audit policy disabled, enrollment failing, or running VMs without coverage | Wazuh API/status, OS events, CyberCore deployment inventory/jobs | Distinguish approved shutdown/reset from collection failure or tampering |
| **Same class period** | Unusual outbound volume, DNS behavior, external scanning, mining, or long-lived unexpected connections | OPNsense flows, resolver logs, IDS, process/network events | Check against the lab brief and package/update traffic; inspect the owning lane |
| **Daily** | Failed lane creation/destruction, stale registrations, orphaned VMs, backup failures, capacity trends | CyberCore job/audit logs; Proxmox tasks; Wazuh cleanup status; backup/metrics systems | Resolve operations failures before the next class |
| **Weekly** | Vulnerabilities, unexpected software/listeners, configuration drift, stale templates, and permission creep | Wazuh inventory, vulnerability detection, SCA/FIM, platform change history | Patch production first; document intentionally vulnerable exercise images |

Do not apply blanket automatic IP blocking to student exercises. Shared NAT
addresses can represent an entire lane, and a detection may be the lesson's
intended outcome. Define specific response rules for shared production systems
and have an operator confirm scope before containment.

## 3. Collect useful endpoint evidence

**Windows baseline:** collect Security, System, Application, and Defender
Operational events. Configure audit categories for logon, account/group changes,
and policy changes; collection cannot recover events the OS never generated.
Useful examples include 4624/4625 (logon success/failure), 4720 (account creation),
4728/4732/4756 (group membership additions), 4719 (audit policy changes), and
1102 (Security log cleared). Interpret the target group and logon type rather
than treating every occurrence as malicious. [Microsoft audit policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration),
[Microsoft event queries](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/securityevent).

**Windows investigation profile:** add a reviewed Sysmon configuration for process
creation, selected network connections, DNS queries, and persistence-related
activity. Sysmon network collection needs explicit configuration. Collect the
Sysmon Operational channel; add PowerShell Operational and Script Block Logging
only after addressing the enrollment caveat below. Pilot the profile before
applying it to hundreds of endpoints. [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1).

**Enrollment and rollout:** Deploy the updated [telemetry installer](wazuh-agent-telemetry.md)
before enabling command/script collection broadly. The updated dispatcher sends
enrollment keys through guest stdin and keeps them out of executable source and
process arguments. Older CyberCore versions embedded those keys in executed
scripts; encoded PowerShell did not conceal them. Validate retries with logging
already enabled. Do not collect `client.keys`, passwords, tokens, or private key
contents, and do not disable an existing security logger to hide installer secrets.

**Linux:** collect SSH, sudo, authentication, service failures, and the relevant
journal or `/var/log/auth.log` / `/var/log/secure` for the distribution. Add
targeted auditd rules for privilege use and changes to accounts, SSH authorization,
sudoers, service definitions, and scheduled tasks. Broad execution auditing can
be expensive and can record credentials; apply the enrollment caveat first.
[Wazuh OS log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html),
[Wazuh auditd configuration](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html).

**Inventory and drift:** track packages, running processes, listening ports, and
critical configuration changes. Monitor selected configuration directories with
FIM, not whole disks, build caches, student home directories, or constantly
changing log directories. Keep intentionally vulnerable templates in an exercise
baseline so their findings do not bury production patch work.
[Wazuh inventory](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/index.html),
[vulnerability detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html).

## 4. Network, platform, and coverage visibility

- Forward selected OPNsense firewall, authentication, configuration, and service
  logs through an appropriately secured collector. Verify certificate identities
  when using TLS and test the decoder against actual received messages.
  [OPNsense remote logging](https://docs.opnsense.org/manual/settingsmenu.html#logging).
- Keep logged denies for management and cross-lane boundaries; selectively log
  permitted access to sensitive services. A firewall pass entry is permission
  evidence, not proof that a TCP session or application login succeeded.
- Use flow records for volume and top talkers, resolver logs for DNS, and IDS
  alerts for network detections. Wazuh endpoint alerts alone do not represent all
  traffic. OPNsense Insight requires its NetFlow exporter to be configured.
  [OPNsense Insight](https://docs.opnsense.org/manual/how-tos/insight.html).
- OPNsense sees translated lane gateway addresses, such as `100.100.62.68`.
  Preserve gateway-to-lane mappings over time; correlate gateway/endpoint evidence
  to identify the guest. A NAT source address alone does not identify a student.
- Compare **running VMs expected to have an agent** with current Wazuh API
  registrations and last check-in, excluding approved offline/destroyed lanes.
  Unique agents appearing in alerts is an activity measure, not fleet coverage.
- Track collection freshness separately for endpoint security, firewall, DNS,
  identity, and application sources. Test a benign expected event end to end;
  zero alerts can mean either quiet activity or a broken data path.
- Monitor CyberCore login/API errors, latency, database availability, Docker
  restarts, lane job duration/failure, teardown cleanup backlog, and backup age.
  Produce sanitized structured audit events for admin and deployment actions
  that existing logs do not cover; agent installation alone does not add them.
- Monitor hypervisor CPU contention, memory pressure, storage latency/free space,
  Ceph health, quorum, failed tasks, and backup restoration results. Use Proxmox
  metrics for continuous capacity graphs and Wazuh for associated security/log
  events. [Proxmox administration guide, External Metric Server](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf).

## 5. Starting thresholds to tune against real classes

These are proposed starting points, not configured monitors or vendor defaults.
Deduplicate by lane/host and check exercise schedules before paging.

| Signal | Initial threshold | Adjustment |
| --- | --- | --- |
| Unauthorized successful access to production or another lane | Any confirmed occurrence | Exclude only documented, narrow service allowances |
| Repeated boundary denies | 20 attempts from one lane in 5 minutes | Baseline scanning exercises; group repeated packets into one investigation |
| Production authentication failures | 10 failures per account or source in 5 minutes | Correlate later success and multi-account spraying; account for shared NAT |
| Unexpected agent loss | Production: 5 minutes; running student VM: 15 minutes | Respect actual Wazuh keepalive/status intervals and planned VM shutdowns |
| New agent never reports | 10 minutes after the guest installer starts the service | Inspect service state, TCP 1514 reachability, enrollment, and manager health |
| Wazuh event drops or missing source freshness | Any sustained drops for 5 minutes or missed expected heartbeat | Quiet alert sources require a separate heartbeat/synthetic event |
| Wazuh disk pressure | Warn below 25% free; escalate below 15% or under 24 hours forecast headroom | Respond before configured indexer watermarks; measure growth and I/O |
| Production CPU or memory pressure | More than 85% for 15 minutes | Correlate queue delay, swapping, response time, and class startup bursts |
| Outbound traffic anomaly | More than 3 times that course's normal class-period baseline | Account for image/package downloads; investigate destinations and processes |
| Agent cleanup backlog | Oldest pending removal over 30 minutes | Account for known manager downtime and retry state; retain job evidence |

## 6. Capacity, retention, and access

Size by concurrently running agents, observed events per second, document size,
and class startup bursts, not student headcount alone. Wazuh's all-in-one
quickstart targets up to 100 endpoints; larger environments warrant evaluating
a distributed deployment. Giving CT 210 16 GB RAM does not by itself establish
capacity for hundreds of busy student VMs. [Wazuh sizing guidance](https://documentation.wazuh.com/current/quickstart.html).

Start with alerts plus targeted source collection. Raw event archives also
include events that did not generate alerts; archiving and dashboard indexing
are separate settings, and archives are disabled by default. Measure a full
class period before expanding them. Monitor received/processed/dropped events,
agent queues, manager queues, Filebeat output, indexer health, and disk growth.
[Wazuh archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html),
[manager queues](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html).

A starting retention proposal is 30 days of searchable exercise alerts, 90 days
of production security alerts, and 7 days of selected raw exercise evidence.
These periods require an approved local policy and measured storage capacity;
they are not legal requirements or existing settings. Different lifetimes need
separate index routing/policies if data currently shares the same daily index.
Configure index lifecycle policies, manager local-log retention, and backup
retention separately; rotation is not a deletion deadline. Test restores and
keep a measured storage reserve. [Wazuh index lifecycle management](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html).

Give platform administrators the complete view and instructors only the classes
they supervise. If students receive access, enforce index/document permissions
and Wazuh API authorization; a saved dashboard filter or tenant alone is not a
data-access boundary. Use authenticated server-side ownership mappings when
designing student access, because student administrators can alter guest labels.
Avoid student names in shared dashboard titles; retain identity correlation in a
restricted system. Explain collected telemetry and retention to learners, restrict
exports and raw command content, and audit administrative access.
[Wazuh role and document permissions](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).

## 7. Rollout order

1. Confirm infrastructure agent coverage, boundary logging, ownership mappings,
   source freshness, backups, and operator escalation ownership.
2. Pilot Windows and Linux collection on one lane; resolve enrollment secret
   capture before richer command/script logging, and verify benign test events.
3. Measure a busy class, tune noisy rules by exercise scope, and set retention.
4. Expand by course; review dropped events, disk growth, student access, and
   instructor usefulness after each wave.
5. Exercise an agent outage, a failed enrollment, a harmless denied boundary
   connection, and a lane teardown; verify detection and cleanup end to end.
