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
docker compose up -d app caldera caddy
```

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

- **Guest agent unavailable:** start/install the QEMU guest agent in the VM.
- **Download failed:** check DNS, HTTPS routing, certificate trust and proxy access.
- **Started but no check-in:** check guest logs and outbound HTTPS. A script's
successful exit alone is not reported as a connected agent.
- **Interrupted install:** after five minutes the job can be retried. Agent jobs
  and token hashes are stored in the existing lane JSON configuration; no SQL
  migration is required.

Linux files are under `/opt/CyberCore/Caldera/<group>/<agent ID>/`.
Windows files are under `%ProgramData%\CyberCore\Caldera\<group>\<agent ID>\`.
The executable is named `mitre-sandcat` or `mitre-sandcat.exe`; logs are beside it.
Guest security software may prevent the executable from starting; the installer
does not change security software settings.

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
