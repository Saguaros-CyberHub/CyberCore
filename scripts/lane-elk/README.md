# Lane SOC dashboard installer

Run on the lane's **ELK Linux VM** with Python 3.8+ and Elasticsearch/Kibana **7.17.x**. This bundle is deliberately version specific; it stops before writes on other versions.

```bash
bash install-lane-soc.sh
```

Alternatively, copy the **entire** contents of [`install-lane-soc.sh`](install-lane-soc.sh) into a Bash terminal. The script contains its Python implementation; it downloads no code or packages. No sudo is needed when the current account can reach ELK and write `./lane-soc-output`.

For a checked-out repository:

```bash
python3 scripts/lane-elk/install_lane_soc.py
```

The default endpoints are `http://127.0.0.1:5601` and `http://127.0.0.1:9200`, the default Kibana space is `default`, and the source is `winlogbeat-*`. For other endpoints or an **existing** space:

```bash
python3 install_lane_soc.py \
  --kibana-url https://elk.example:5601 \
  --elasticsearch-url https://elk.example:9200 \
  --space training --index 'winlogbeat-*' --ca-cert /path/to/ca.pem
```

For basic authentication, supply `LANE_ELK_USERNAME` and `LANE_ELK_PASSWORD` in the environment. `LANE_ELK_API_KEY` takes an encoded Elasticsearch API key; `LANE_ELK_BEARER_TOKEN` accepts a bearer token. Optional `LANE_KIBANA_*` and `LANE_ELASTICSEARCH_*` versions override the shared credential independently. Secrets are excluded from generated artifacts. TLS certificate validation is on by default; `--insecure` is an explicit opt-out. Redirects are refused; use the final service URL, including a reverse-proxy base path if needed.

## What it creates

- A 24-hour operations dashboard with event volume by channel, host freshness, reporting-host count, successful/failed authentication, process executions, persistence events, destination addresses and a raw event timeline.
- Twenty-two behavior/domain hunts, available under `Lane SOC | Hunt` in Discover. Hunts include ECS and raw Windows event fields; aggregation fields prefer mapped ECS fields and fall back to mapped Windows fields.
- Fifteen detection rules with investigation guidance, false-positive notes and required telemetry: encoded PowerShell, PowerShell downloads, command-shell/PowerShell task registration, startup shortcuts, service installs from writable paths, Run keys, permanent WMI subscriptions, registry hive export, COM services memory dumps, LSASS access, Defender preference changes, log clearing, remote-management shells and repeated authentication failures.
- When the Detection Engine is available, an actual alert queue and alert counts by rule, using the exact `.siem-signals-<space>` alias. Behavior evidence counts are explicitly separate from detection alerts.

The dashboard's host table shows hosts with events **within the selected time window**, not all expected lane machines. An absent host must be checked against lane inventory. These panels use genuine endpoint events; no synthetic attack labels or tool-name matching are used.

## Native alerts on the default lane

GOAD lanes run Elasticsearch with security disabled. **The dashboard and hunts install, but native Elastic Security detections cannot run in that configuration.** The installer reports that condition and writes reviewable, disabled rules to `lane-soc-output/detection-rules.ndjson`. It does not silently enable security or restart services; changing security also requires reconfiguring every shipper's authentication.

For a separately configured secure stack, the installer checks security, Detection Engine authentication/privileges/encryption key and source-index privileges. Elastic also requires HTTPS between Kibana and Elasticsearch; the installer cannot inspect that internal server connection. Follow the [7.17 prerequisites](https://www.elastic.co/guide/en/security/7.17/detections-permissions-section.html) before enabling native detections. Kibana rules execute with the privileges of the user/API key that last edited them. Confirm the rule's execution status and source-index access in **Security → Rules** after installation; API acceptance is not proof that alerts have fired.

`--rules auto` (default) creates enabled rules only after readiness checks pass; `--rules off` creates dashboard/hunts and only exports rules; `--rules disabled` creates disabled rules; `--rules enabled` explicitly enables this bundle's rules. Explicit enabled/disabled requests return exit code 2 if prerequisites are unavailable while still installing the dashboard and hunts. A partial rule failure also returns 2 and leaves details in the report. No notification connectors are created; notifications require separate connector configuration and appropriate licensing.

Reruns replace only the bundle's namespaced dashboard/hunt objects after checking ownership. Duplicate a dashboard before customizing it. Existing rules retain your query, schedule, severity, exceptions, connectors and enabled state on `auto` reruns; only documentation is refreshed. Explicit `enabled`/`disabled` overrides the state. New rule logic is available in the generated NDJSON for review; it does not overwrite local tuning. No indices, documents, existing unrelated dashboards or rules are deleted.

## Telemetry and tuning

On each Windows VM, the separate [`enable-lane-detection-telemetry.ps1`](../enable-lane-detection-telemetry.ps1) helper can enable script-block logging, process command-line auditing and selected Windows security audit policies. Read its guidance and use `-CheckOnly` to inspect a host. It is optional and does not alter the existing Sysmon or Winlogbeat configuration. The `event-log-reduction.ps1` option conflicts with collecting this evidence.

The installer queries field mappings and recent telemetry, reports absent event families, and writes host freshness to `install-report.json`. Mappings alone do not prove populated data. No recent events is a prompt to investigate, not proof an audit policy is disabled. The default Sysmon policy excludes ProcessAccess, so the LSASS access rule needs an explicit sensor-policy extension/reload; the COM services command-line rule provides separate attempt visibility without that event. WMI subscription, registry, startup-file and network rules also depend on their Sysmon event types surviving sensor filters. Defender Operational is not subscribed by the default collector; the Defender rule detects a requested change through PowerShell evidence, not confirmed protection state.

Validate by noting one profile execution's host/time, locating raw events in its hunt, and checking rule execution/alert output if native detections are available. Process commands and script blocks can show attempts that fail; a script block can contain functions never invoked. Ordinary discovery, staging, archiving and network connections are investigation evidence and do not automatically warrant an alert.

Rules run every five minutes with a seven-minute event-time lookback and a 100-alert execution cap. More than seven minutes of ingestion delay can miss an event; bursts can hit the cap. Baseline routine administration, scope exceptions narrowly, and adjust schedule/lookback/thresholds to the lane. `source.ip` is used for failed-logon grouping when mapped; otherwise the raw `winlog.event_data.IpAddress` is used. Queries with leading wildcards require Kibana's `query:allowLeadingWildcards` setting to permit them. The installer does not change that global preference.

## Review and checks

```bash
python3 install_lane_soc.py --export-only --output-dir ./review
python3 -m unittest discover -s scripts/lane-elk -p 'test_*.py' -v
```

Offline export makes no network requests. Files produced: `saved-objects.ndjson`, `detection-rules.ndjson`, `detection-notes.md`, `install-report.json`. Saved objects are authored for the documented 7.17 saved-object creation API; use this installer for version checks/ownership protection rather than importing them into another major release.

Tests use a local HTTP mock for version rejection, spaces/auth, security-off fallback, native rule upserts, preserving tuning, ownership conflicts and partial failures. They do not replace a live Kibana UI smoke test. Regenerate the pasteable after changing Python source with `python scripts/lane-elk/build_pasteable.py`.

Primary API references: [saved objects](https://www.elastic.co/guide/en/kibana/7.17/saved-objects-api-bulk-create.html), [create rule](https://www.elastic.co/guide/en/security/7.17/rules-api-create.html), [update rule](https://www.elastic.co/guide/en/security/7.17/rules-api-update.html), [privileges](https://www.elastic.co/guide/en/security/7.17/privileges-api-overview.html), [signal index](https://www.elastic.co/guide/en/security/7.17/index-api-overview.html).
