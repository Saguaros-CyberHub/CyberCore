# Atomic adversaries and a lane SOC workbench

This adds curated Caldera profiles and a Kibana workbench for investigating the
events they produce. The dashboard reads actual Windows telemetry. A matching
hunt is evidence to investigate; it is not proof that an attack succeeded.

## Update the adversaries

Deploy the updated CyberCore app from the repository on the CyberCore host:

```bash
docker compose up -d --build app
```

In the course **Blue Team Board**, select **Author attacks**, then **Update
CyberCore profiles**. This creates new profiles and updates existing managed
profiles in the shared Caldera catalog. It does not launch an operation. Profiles
keep their stable IDs, so existing selections continue to refer to them. Clone a
managed profile under a new ID if you want to keep your own edits across updates.

The report shows missing abilities and execution prerequisites. An incomplete
profile is skipped: if its previous version exists, that version remains. Do not
interpret a skipped update as an updated exercise. Caldera's Atomic plugin must
have loaded its abilities before seeding; rebuilding the Caldera image is only
necessary if its vendored Atomic data is absent or you intentionally change the
pin in `infrastructure/caldera/Dockerfile`.

The resolver selects an exact technique, platform, plugin and named test. Atomic
ability IDs are resolved from the running catalog because they depend on the
contents of the pinned Atomic test. It does not substitute a different test just
because that test implements the same technique. Stockpile fact-producing steps
remain where later steps need their output.

For a read-only preview, the staff endpoint is
`POST /api/cle/courses/<course-id>/incidents/authoring/adversary-pack` with JSON
`{"dry_run":true}` using your normal CyberCore session. The same endpoint with
`{}` applies complete profiles. The UI uses this authenticated endpoint.

Five existing Windows profiles are revised, three Windows profiles are added,
and the Linux survey retains its Stockpile preference:

| Profile | Sequence and evidence to investigate |
| --- | --- |
| Foothold survey | Atomic native user, host, process, network and domain discovery; investigate command lines and surrounding activity. |
| Credential harvest | Local file/registry search, vault enumeration and a comsvcs LSASS dump attempt; distinguish enumeration and attempts from recovered credentials. |
| SMB and WMI lateral move | Stockpile reachability, Atomic share discovery, SMB copy and WMI execution; correlate both hosts, logons and remote agent activity. |
| Defence tamper and persist | Security-process discovery, Defender change attempt, registry modification, Startup shortcut and a scheduled task. |
| Stage and exfiltrate | Atomic file/share discovery followed by Stockpile file discovery, staging, archive and upload; the producer steps supply facts for later steps. |
| **New: PowerShell foothold and reconnaissance** | Encoded PowerShell surrogate followed by actual user, process, account, connection and file discovery. |
| **New: Domain and share reconnaissance** | Domain accounts/groups, controller/computer discovery and locally published shares; useful for contextual hunting rather than automatic high-severity alerts. |
| **New: Logon persistence through native tools** | User/host/security discovery, a Startup shortcut and a PowerShell-created task; Calculator is the execution surrogate. |
| Foothold survey (Linux) | Existing discovery profile; needs Linux telemetry outside this Windows workbench. |

Lateral movement needs valid lane credentials and learned access relationships;
they are not manufactured by the pack. `Remote Host Ping` is tagged **T1016** by
the pinned Stockpile catalog and must precede SMB/WMI. Staging needs a seeded
`file.sensitive.extension` and exercise documents. Persistence creation does not
force a logon or prove its scheduled action executed. Read each profile's
prerequisites and cleanup notes before launching it.

## Paste the dashboard installer into a running lane

Open the **Linux shell on the lane's ELK VM**. Open
[`scripts/lane-elk/install-lane-soc.sh`](../scripts/lane-elk/install-lane-soc.sh),
copy the entire file, and paste it into that shell. The file is self-contained;
the lane does not need a repository checkout or a GitHub connection. Python 3.8+
must already be installed. This is shell code, not a Kibana Dev Tools request.

Alternatively, copy the Python file to the ELK VM and run:

```bash
python3 install_lane_soc.py \
  --kibana-url http://127.0.0.1:5601 \
  --elasticsearch-url http://127.0.0.1:9200
```

The installer targets **Elasticsearch and Kibana 7.17.x**, matching this lane's
Winlogbeat 7.17.6 integration. It checks versions before writing. It installs a
namespaced dashboard and saved searches, exports detection rules, and reports
which rule installation and telemetry checks passed. The workbench includes 22
saved hunts and 15 detection rules covering suspicious PowerShell, persistence,
credential-access attempts, defense changes, remote shells and authentication
bursts. It does not reboot the lane or change its event retention, security
settings, or Winlogbeat output.

For a secured lane, supply credentials through environment variables, not
command-line arguments. Use the existing account with the required saved-object
and detection privileges:

```bash
read -r -p 'Elastic username: ' LANE_ELK_USERNAME
read -r -s -p 'Elastic password: ' LANE_ELK_PASSWORD
printf '\n'
export LANE_ELK_USERNAME LANE_ELK_PASSWORD
python3 install_lane_soc.py \
  --kibana-url https://elk.cybercore.lan:5601 \
  --elasticsearch-url https://elk.cybercore.lan:9200 \
  --ca-cert /path/to/lane-ca.pem
unset LANE_ELK_USERNAME LANE_ELK_PASSWORD
```

Use `--space <space-id>` for an existing Kibana space, `--rules off` for dashboard
and hunt installation only, and `--export-only` to generate artifacts without
contacting either server. `--help` describes authentication overrides and the
other options. The dashboard is named **Lane SOC | Windows operations**; the
installer prints its URL. More CLI and tuning details are in the
[installer reference](../scripts/lane-elk/README.md).

## Alerts on the default GOAD lane

The current GOAD ELK configuration disables Elasticsearch security. The
dashboard and saved hunts work there, but **Elastic Security's detection engine
does not**. The installer reports this and exports the rules for later import;
it does not report saved searches as active alerts.

Elastic 7.17's documented prerequisites include enabled Elasticsearch security,
HTTPS between Kibana and Elasticsearch, a persistent Kibana encrypted-saved-object
key, and appropriate permissions. Enabling those settings also requires updating
each Winlogbeat client's authentication and trust settings, so doing only the
server half can stop ingestion. Follow the
[Elastic detection prerequisites](https://www.elastic.co/guide/en/security/7.17/detections-permissions-section.html)
for the lane before re-running the installer to enable rules.

Notifications through email, Slack, or other connectors are separate from
creating detection alerts. This installer does not configure outbound messaging.

## Collect evidence before running a profile

Check the dashboard's telemetry health and the install report before launching
an exercise. Confirm recent events from every intended target. Winlogbeat already
collects Security, Sysmon, Windows PowerShell, and WMI-Activity channels, but a
subscribed channel does not mean Windows is configured to produce every event.

For an existing Windows lane host, use the optional
[`enable-lane-detection-telemetry.ps1`](../scripts/enable-lane-detection-telemetry.ps1)
in elevated **Windows PowerShell 5.1**. It enables selected audit policies,
process command-line auditing, and script-block logging with a backup for
rollback. Its header documents check-only and restore usage. Run it on each
Windows exercise target, including the domain controllers for Kerberos events.
It preserves your Sysmon and Winlogbeat configurations.

The bundled SwiftOnSecurity Sysmon configuration disables ProcessAccess events
(event 10) and image loads (event 7). A memory-access or DLL-loading hunt needs
appropriate collection filters before it can work. The dashboard cannot recover
events that were never collected. Command-line evidence can still show a dump
attempt, but it does not prove that memory was successfully read.

The existing `event-log-reduction.ps1` vulnerability script intentionally disables
some of these logging settings. Domain Group Policy can also override local
policy. Recheck effective collection after either is applied. New Windows
PowerShell sessions are needed to verify the script-block setting.

## Use it like an analyst

1. Capture a quiet baseline with normal logons and administration. Check host
   coverage and ingestion delays; choose a time range covering the exercise.
2. Run one complete profile on the intended lane. Preserve its operation ID and
   start/end times separately from the analyst dashboard.
3. Pivot from a process to its parent, command line, user, host, and nearby
   authentication, registry, task/service, file, and network events. Correlate
   by process GUID when available; a PID alone can be reused.
4. Compare a saved hunt's results with ordinary activity before enabling or
   tightening a rule. Scope exceptions to the verified management process,
   account, or host rather than excluding an entire shell or technique.
5. Compare evidence with Caldera's individual link results. A scheduled ability,
   a successful command, an observable event, and an alert are four separate
   outcomes. Record execution failures and missing telemetry as such.

These are starting detections with triage notes, not universal ATT&CK coverage.
Windows telemetry does not cover the Linux survey profile; that requires a
separate Linux collection pipeline. Host discovery is often ordinary admin
activity, network events alone do not prove exfiltration, and disabled or absent
audit channels leave gaps. Repeated threshold matches may need tuning during
longer exercises.

## Validation and references

Local tests cover catalog selection, refresh behavior, permissions, UI reporting,
dashboard references, installer HTTP behavior, and failure paths. These tests do
not replace importing into the running lane and observing a real operation.

- [Caldera 5.3 adversary create/update API](https://github.com/mitre/caldera/blob/5.3.0/app/api/v2/handlers/adversary_api.py)
- [Atomic Red Team pinned source](https://github.com/redcanaryco/atomic-red-team/tree/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics)
- [Kibana 7.17 saved-object API](https://www.elastic.co/guide/en/kibana/7.17/saved-objects-api-bulk-create.html)
- [Elastic 7.17 detection rule API](https://www.elastic.co/guide/en/security/7.17/rules-api-create.html)
- [Microsoft process command-line auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [Windows PowerShell logging policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell)
