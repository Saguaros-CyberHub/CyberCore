# Central Wazuh agents from the Admin Dashboard

Open **Admin Dashboard > Active Lanes > Deploy Wazuh agents**. Select lanes,
select matching machine names, then review the individual VM targets and press
**Install selected agents**. This uses the same selection flow as the CALDERA
classroom batch installer, with access to lanes across courses and challenges.
Only administrators can read this inventory or submit installations.

Agents are downloaded and installed on running VMs using the existing elevated
QEMU Guest Agent execution path. No Wazuh agent needs to be present in the VM
template. A working QEMU Guest Agent, supported guest OS, package download
connectivity and a route to the central manager are required.

Windows supports x86 and amd64 guests. Linux supports amd64 and arm64 guests
using systemd, Python 3, and either apt/dpkg or RPM packages. Unsupported guests
report an installation error; the installer does not add those prerequisites.

## Configure the central server

Deploy the Wazuh manager, indexer and dashboard separately, then set these values
in the CyberCore deployment environment:

```dotenv
WAZUH_MANAGER=wazuh-manager.example.edu
WAZUH_API_URL=https://wazuh-manager.example.edu:55000
WAZUH_API_USERNAME=cybercore-agents
WAZUH_API_PASSWORD=REPLACE_WITH_API_PASSWORD
WAZUH_AGENT_VERSION=X.Y.Z-1
WAZUH_DASHBOARD_URL=https://wazuh.example.edu
```

Replace `X.Y.Z-1` with an available package version compatible with your manager.
There is no implicit latest version. Use an API account permitted to list agents,
create agents and read their enrollment keys. CyberCore holds that account's
credentials; each VM receives only its own agent enrollment key.

To assign lane agents to an existing Wazuh group, set:

```dotenv
WAZUH_AGENT_GROUP=StudentVM
```

Create and configure that exact, case-sensitive group in Wazuh first. The API
account also needs `group:read`, `agent:modify_group` and
`group:modify_assignments` for the relevant agents and group. CyberCore checks
the group before queuing a batch and before enrolling each agent, then verifies
assignment before running the guest installer. Retries retain the agent's
identity and existing group memberships. Leaving this optional setting empty
keeps the manager's default grouping. CyberCore imports API-issued keys, so it
assigns groups through the manager API rather than installer auto-enrollment.
See [Wazuh agent grouping](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html).

The API connection verifies HTTPS certificates. For a private certificate
authority, set `WAZUH_API_CA_FILE` to a PEM path inside the app container and
copy the verified public CA certificate to `secrets/wazuh-api-ca.pem` on the
Docker host, beside the base Compose file. This must be a regular PEM file.
The `secrets` directory is ignored by Git and is outside the app's build context;
pulling the repository or rebuilding the app does not copy this certificate.

[`docker-compose.yml`](../docker-compose.yml) includes the read-only certificate
mount directly. Standard `docker compose` commands mount the host file at
`/run/secrets/wazuh-api-ca.pem`; no Wazuh override selection is needed. The
mount definition stays in Git, while `.env` and the public certificate remain
deployment files. The PEM must exist before starting `app`, including on a fresh
deployment, because the main Compose file requires this mount.

`create_host_path: false` makes a missing source fail during deployment instead
of creating a directory where the PEM should be. The `Z` label allows the app
to read this dedicated file on SELinux hosts such as Rocky Linux; Docker ignores
the label on hosts without SELinux. See the
[Docker bind-mount reference](https://docs.docker.com/reference/compose-file/services/#volumes).

```dotenv
WAZUH_API_CA_FILE=/run/secrets/wazuh-api-ca.pem
```

If a previous setup added `docker-compose.wazuh.yml` to `COMPOSE_FILE`, remove
that entry after setting the CA path above. Preserve any other deployment
overrides; the deprecated Wazuh override file has been removed.

The stock Wazuh 4.14 API certificate identifies `localhost`. When connecting by
an IP address, a CA file alone cannot resolve that name mismatch. Prefer an API
certificate issued for its reachable hostname or IP. To retain the stock
certificate, independently verify its SHA-256 fingerprint in the container's
console, trust that exact public certificate with `WAZUH_API_CA_FILE`, and set:

```dotenv
WAZUH_API_SERVER_NAME=localhost
```

This sets the certificate identity expected by the HTTPS client while connecting
to the address in `WAZUH_API_URL`. Certificate-chain, expiry and identity checks
remain enabled. Reverify and replace the trusted certificate when it is renewed.

Recreate the app after pulling the updated main Compose file:

```sh
docker compose up -d --no-deps --force-recreate app
```

Subsequent `docker compose build app` and `docker compose up -d app` commands
include the mount automatically. A bind-mount change alone does not require
rebuilding the image.

If the app reports `Could not read WAZUH_API_CA_FILE`, check the host file and
the path visible to the app from the deployment directory. These commands do
not print API credentials or certificate contents:

```sh
ls -ld ./secrets/wazuh-api-ca.pem
docker compose exec -T app node -e 'const fs=require("node:fs");const p=process.env.WAZUH_API_CA_FILE;console.log("CA path:",p);try{console.log("Regular file:",fs.statSync(p).isFile());console.log("Readable bytes:",fs.readFileSync(p).length)}catch(e){console.log("Read error:",e.code)}'
```

`ENOENT` means the path is missing, `EISDIR` means it points to a directory,
and `EACCES` indicates a permissions or SELinux access problem. For a missing
path, also check that the app was recreated with the updated main Compose file.
Copying the file to a workstation alone does not make it available on the Docker
host.

Lane VMs need outbound HTTPS to `packages.wazuh.com` and TCP 1514 to the manager.
The app needs HTTPS access to the manager API, normally TCP 55000. This flow
imports API-issued client keys, so guest access to enrollment port 1515 is not
required. Before installation, CyberCore verifies the selected VM's lane gateway
and adds a rule for that lane's subnets to reach only the configured manager on
TCP 1514. This exception precedes the gateway's private-network drops and is
persisted for gateway restarts. Other firewall rules remain in place. The app
needs its existing Proxmox node SSH access to execute this gateway update.

Automatic gateway access supports ordinary v1/v2/v3 lane gateways with verified
deployment metadata and interfaces. Internet-disabled and malware analysis lanes
are refused. Upstream firewalls must also permit the manager connection; this
action changes only the selected lane gateway.

Use a stable IPv4 manager address or a hostname resolving to one IPv4 address.
The rule is restricted to that resolved address. If the manager address changes,
review the existing tagged rule and restart hook before retrying; CyberCore
reports conflicting destinations instead of expanding access automatically.

Packages and their SHA-512 checksums are downloaded from Wazuh's separate
official package and checksum directories. Both Windows and Linux downloads
are checked before installation. A failed job identifies the download,
checksum, package, configuration or service stage without exposing guest
output or enrollment keys. On Windows, MSI installation details are saved in
`C:\ProgramData\CyberCore\Wazuh\install.log` once MSI execution begins.

## Selection, progress and retries

- Match machine names across selected lanes without regard to case. Review
  individual VM checkboxes to omit exceptions. Unknown platforms require a
  Windows or Linux selection before submission.
- Live Proxmox power checks determine which guests can receive an agent.
  Gateways and LXC containers are excluded. A running VM retained after a failed
  lane deployment can be selected without clearing the lane's deployment error.
- Each request accepts at most 200 VMs. Four installations run concurrently per
  app process; additional jobs queue. Per-VM job state is stored in lane config.
- Closing the modal does not cancel accepted jobs. Reopening it fetches persisted
  progress and current agent status. Retry failed targets through the same picker.
- Completion means the manager reports the expected agent as active with a fresh
  check-in. It does not verify that every desired log source is configured or
  that events have reached the indexer.

The queue dispatcher runs in the app process. Restarting the app interrupts
dispatch; expired queued or running records become retryable. Finish active
batches before restarting the app. Jobs do not contain enrollment keys or the
manager API password.

## Existing agents and telemetry

Agent identities include the lane and VM identity, so repeated hostnames and
overlapping lane IP ranges do not combine different machines into one agent.
Retries reuse the stored managed identity where available. An existing enrolled
agent with a different manager or identity is reported as a conflict instead of
being reassigned by this batch action. Plan migration of existing lane-local SIEM
agents separately.

Installations create a persistent Wazuh service. They do not change Defender
settings. Configure log collection, Windows audit policy, Sysmon and Linux audit
sources for the intended exercises using Wazuh's configuration tools. No new
active-response policy is enabled by the CyberCore batch workflow.

This Admin action is an explicit batch operation. The existing GOAD deployment
scripts continue to install agents for a selected lane-local SIEM extension;
central automatic enrollment on future deployments is a separate lifecycle hook.

## Implementation

- `front-end/public/js/admin/admin-wazuh.js`: selection modal and status polling.
- `front-end/src/routes/admin/wazuh-agents.js`: admin authorization, inventory
  resolution, batch validation and audit recording.
- `front-end/src/utils/wazuh-lane-agents.js`: bounded queue, per-VM claims,
  guest execution and check-in verification.
- `front-end/src/utils/wazuh-client.js`: authenticated HTTPS manager API client.
- `front-end/src/utils/wazuh-agent-scripts.js`: Windows and Linux installers.
- `front-end/src/utils/wazuh-gateway-access.js`: verified, persistent manager
  TCP 1514 access on the selected lane gateway.

Enrollment follows Wazuh's documented [API client-key workflow](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-manager-API/requesting-the-key.html)
and [key import procedure](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-manager-API/importing-the-key.html).
