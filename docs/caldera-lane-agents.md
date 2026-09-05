# Caldera agents from the Blue Team Board

Open **CLE > Course > Blue Team Board > Caldera Agent** as a course instructor
or administrator. Select a running lane, its Windows or Linux QEMU VM, and click
**Install Agent**. The job continues if you close the dialog. Reopen it to see
progress and the agent's last check-in.

The picker checks live VM power in Proxmox. A lane retained as `suspended`
after a provisioning error can still provide a running VM for Caldera; its
saved deployment status is shown separately. Installing an agent does not mark
the deployment healthy or clear its error. Ordinary suspended lanes and
stopped, paused or unverified VMs remain unavailable. A Proxmox connection
failure is shown as an unavailable power check, rather than as no deployed lanes.

Click **Open Caldera console**, then select the displayed `lane-<lane UUID>`
group when creating a Caldera operation. A completed installation means the
server received a fresh check-in from that specific agent. Existing running
operations that accept its group may also select a newly connected agent.

The install uses the VM's QEMU guest agent with its existing elevated guest
execution context. It downloads Sandcat directly over HTTPS and starts a visible,
named process with local logs. Repeating the install restarts only that managed
agent. It does not install a startup service; after reboot, use **Install Agent**
again. Supported guest architectures are amd64 and arm64.

On Windows, installation uses `Set-MpPreference` to request turning off Microsoft Defender
real-time monitoring, behavior monitoring, downloaded-file scanning, script
scanning, block-at-first-seen and potentially unwanted application blocking on
the selected lab VM. It also uses `Add-MpPreference` to exclude only the managed
agent folder while preserving existing exclusions. It reads back the preferences,
effective real-time protection state and folder exclusion before downloading.
When some protections remain enabled but the exact agent folder exclusion is
present, installation continues with a notice listing the remaining settings and
Tamper Protection state. It still requires the agent to download, start and check
in to Caldera before reporting success. Applied changes remain after installation,
including a failed download; the dialog
states this behavior before installation. Already configured settings are left
alone. If Defender management commands are absent, the installer continues with
the download. Command errors, an unverifiable real-time state or an unverified
agent folder exclusion stop installation with an explanatory error. Other security products and application-control
policies require their own management controls.

To re-enable these Defender protections afterward, run elevated PowerShell on
the VM and remove the exact agent folder exclusion shown in the install output:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableBlockAtFirstSeen $false -PUAProtection Enabled
Remove-MpPreference -ExclusionPath '<agent folder shown in the install output>'
```

Windows or managed policy may re-enable protection independently, which can block
the agent again. See Microsoft's
[Defender PowerShell reference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference).

## Deployment

Set the existing environment values on the deployment:

```dotenv
CALDERA_HOST=caldera.saguaroscyberhub.org
CALDERA_AUTHORING_UPSTREAM=caldera:8888
COOKIE_DOMAIN=.saguaroscyberhub.org
```

Keep the existing `CALDERA_SSO_SECRET` and `CALDERA_API_KEY_RED` configured.
The red API key remains between server containers; guests and browsers never
receive it. The central image now includes Sandcat and Go and needs a rebuild:

```sh
docker compose build app caldera
docker compose up -d --force-recreate app caldera caddy
```

Recreation ensures Caddy reads the updated agent routes and remounts its
configuration file after a Git update. An app-only restart, or `up -d` with
an unchanged Caddy service, can leave the previous console-only gate running.

Route the hostname through the existing Caddy service. A tunnel or upstream
authentication proxy must let `/agent/*` reach Caddy without a browser login or
challenge. Caddy authorizes those requests using a per-VM capability and only
for beacon, payload download and upload. Console and API requests retain the
CyberCore instructor/admin login gate. No Caldera host port is published.

Guest DNS must resolve the hostname to a reachable HTTPS endpoint with a trusted
certificate. The lane gateway must permit outbound HTTPS. An explicit lane
**Internet: Off** disables forwarding and must be enabled before installing.
The V3 gateway blocks most management subnet traffic, so pointing the hostname
at a management address can still fail even with Internet enabled. Missing
`internet_enabled` on an older lane is treated as unknown; the connection is
tested through installation and check-in.

## Status and troubleshooting

- **Download returns 401:** the request may still be reaching the console login
  gate. With the updated repository on the server, refresh just Caddy:

  ```sh
  docker compose up -d --no-deps --force-recreate caddy
  ```

  Then retry **Install Agent**. To check the public routing without an agent
  credential, use this deliberately invalid path:

  ```sh
  curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://caldera.saguaroscyberhub.org/agent/not-a-token/file/download
  ```

  The updated Caddy route returns **404** for that malformed path. If it still
  returns **401**, check that the hostname's tunnel reaches this Caddy service
  and that an upstream login policy is not intercepting `/agent/*`.
- **Install Agent download returns 404:** if the agent route is working, an older
  Caldera image may still be running without Sandcat. Updating only the app or
  Caddy does not rebuild Caldera. From the updated repository on the server:

  ```sh
  docker compose build caldera
  docker compose up -d --no-deps --force-recreate caldera
  ```

  Wait for Caldera to report **All systems ready**, then retry **Install Agent**.
  If the download still fails, inspect `docker compose logs --since 5m caldera`
  immediately after the attempt. Caldera also returns 404 when payload compilation
  fails; recent download/build errors are more useful than old startup warnings.
- **Guest agent unavailable:** start/install the QEMU guest agent in the VM.
- **Download failed:** check DNS, HTTPS routing, certificate trust and proxy access.
- **Could not turn off Microsoft Defender protections:** check the
  target VM's Tamper Protection and managed policy. The installer verifies the
  effective real-time state, scanning preferences and exact folder exclusion,
  and names any settings that could not be verified. It proceeds with an
  installation notice when the exact agent folder exclusion is present and the
  real-time state is known, even if Tamper Protection keeps other protections on.
  A configured folder exclusion can allow the agent through antivirus scanning;
  other endpoint controls can still block it. See Microsoft's
  [exclusion scope documentation](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure).
- **Windows security software blocked Sandcat:** Windows errors 225/226 (including
  an `OpenRead` error saying the file contains a virus or potentially unwanted
  software) indicate an endpoint security block. On the target VM, review
  **Windows Security > Virus & threat protection > Protection history**, or the
  installed security product's console. Match the detection to the attempted
  Sandcat download under `%ProgramData%\CyberCore\Caldera\<group>\<agent ID>\`.
  Allow the intended agent under the lab's approved endpoint policy, then retry
  **Install Agent** to download it again. For Defender, see Microsoft's
  [Protection History guidance](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app).
- **Started but no check-in:** check guest logs and outbound HTTPS. A script's
successful exit alone is not reported as a connected agent.
- **Interrupted install:** after five minutes the job can be retried. Agent jobs
  and token hashes are stored in the existing lane JSON configuration; no SQL
  migration is required.

Linux files are under `/opt/CyberCore/Caldera/<group>/<agent ID>/`.
Windows files are under `%ProgramData%\CyberCore\Caldera\<group>\<agent ID>\`.
The executable is named `mitre-sandcat` or `mitre-sandcat.exe`; logs are beside it.
Other endpoint security controls may still prevent the executable from starting
after Defender real-time protection is turned off.

Each VM receives a random capability; CyberCore stores its hash. Reinstalling
that VM rotates its capability without changing other VMs' credentials. Active
lanes and retained provisioning failures use the same scoped agent gate. A
retained suspended lane must still have the agent's VM running to authenticate;
stopping that VM revokes its access. Other inactive lane states cannot authenticate. Destroying
a lane removes its running processes, although historical agent records may
remain visible in Caldera.

Manual Caldera operations are separate from CyberCore's incident engine and
automatic grading. The incident engine's existing Caldera launch gate is unchanged.

## Validation

Run the focused `caldera-agent*`, `caldera-lane-agents`, container, authoring-access
and Blue Team Board tests from `front-end/test`. Set `CADDY_BIN` to a Caddy 2.10.2
binary to exercise the actual reverse proxy against local mock services.
A production image build and a real lane check-in must still be verified on the
deployment; local tests do not establish cluster connectivity.
