# 🧠 CyberCore

CyberCore is the **control plane** for **CyberHub**, a cyber-education platform
run by Cyber Saguaros. It's a single Node.js/Express application that serves the
hub UI, is the system of record for users and labs, and orchestrates a Proxmox VE
cluster to spin up isolated, per-user lab environments called **lanes**.

> **📚 Full documentation lives at [docs.saguaroscyberhub.org](https://docs.saguaroscyberhub.org)**
> (source: [Saguaros-CyberHub/CyberHub-Docs](https://github.com/Saguaros-CyberHub/CyberHub-Docs)).
> Start with the [Overview](https://docs.saguaroscyberhub.org/Overview/01-overview/).
> This README is just the map and the quick start.

## What it actually is

- A **modular monolith**: one Express process ([front-end/src/server.js](front-end/src/server.js))
  that discovers feature **modules** and **plugins** from the filesystem at boot
  and mounts their routes.
- The **orchestrator**: it talks directly to the **Proxmox VE** API to clone VMs,
  carves per-user isolated networks out of **Proxmox SDN (VXLAN)**, and wires up
  remote access through **Apache Guacamole** and optionally **Tailscale**.
- The **system of record**: **PostgreSQL** holds users, groups, modules,
  resources, allocations, badges, VM templates/instances, events, and lanes;
  **Redis** holds sessions and caches.

The core concept is the **lane** — one user's private VXLAN network plus the VMs
attached to it (a gateway, a Kali box, and the challenge's targets). Almost
everything here exists to create, manage, and tear down lanes.

## Architecture at a glance

```mermaid
flowchart TB
  U["Learner / Instructor / Admin<br/>(browser)"] --> CADDY["Caddy<br/>TLS + reverse proxy"]
  CADDY --> APP["CyberCore (Express app)<br/>hub UI + API + orchestration"]
  APP --> PG[("PostgreSQL<br/>cybercore_db + plugin DBs")]
  APP --> RDS[("Redis<br/>sessions + cache")]
  APP -->|clone VMs / apply SDN| PVE["Proxmox VE cluster"]
  APP -->|register consoles| GUAC["Apache Guacamole"]
  APP -->|per-lane keys| TS["Tailscale (optional)"]
```

Full diagrams and the boot/request lifecycles are in
[Architecture](https://docs.saguaroscyberhub.org/Overview/02-architecture/).

## Repository layout

| Path | What lives there |
|------|------------------|
| [front-end/](front-end/) | The Express control-plane app — this *is* CyberCore. |
| [front-end/src/](front-end/src/) | Server, module/plugin loaders, routes, middleware, orchestration utils. |
| [front-end/modules/](front-end/modules/) | Feature modules (`crucible`, `cyberlabs`, …) and their nested plugins (`ciab`, `cle`). |
| [front-end/migrations/](front-end/migrations/) | Incremental SQL migrations for `cybercore_db` (applied manually). |
| [config/postgres/](config/postgres/) | First-boot database init (fresh volume only). |
| [config/](config/) | Caddy, Guacamole, n8n, and site configuration. |
| [challenges/](challenges/) | Source for self-contained vulnerable-app challenges (e.g. CyberSaguaros). |
| [docker-compose.yml](docker-compose.yml) | The deployment stack. |

## Quick start

```bash
# 1. Configure
cp example.env .env
#    …then fill in every REPLACE_ME (DB creds, JWT_SECRET, SESSION_SECRET,
#    PROXMOX_*, GUAC_*, etc. — see the Deployment & Ops doc:
#    https://docs.saguaroscyberhub.org/Overview/09-deployment-and-ops/)

# 2. Launch the stack (app + postgres + redis + guacamole + caddy + …)
docker compose up -d

# 3. Watch it come up
docker compose logs -f app
```

On first boot against an empty database volume, the `config/postgres/*` scripts
seed `cybercore_db` (schema, first admin from `ADMIN_EMAIL`, module rows); the
app then loads modules/plugins (creating `clinic_db` / `cle_db`) and starts
listening. Caddy serves the hub — a domain name in `CYBERHUB_HOST` gets automatic
HTTPS; `:80` runs HTTP-only for LAN/offline use
([Offline Mode](https://docs.saguaroscyberhub.org/Overview/11-offline-mode/)).

A step-by-step walkthrough lives in the
[Quickstart Guide](https://docs.saguaroscyberhub.org/Setup/Quickstart%20Guide/).

## The modules

Discovered from [front-end/modules/](front-end/modules/) and registered in the
`cybercore_module` table:

| Module | Status | Notes |
|--------|--------|-------|
| 🔥 **The Crucible** | active | CTF-style range; the flagship lane consumer. Hosts the CiaB and CLE plugins. |
| CyberLabs · The Forge · Saguaros University · The Library · CyberWiki · The Archive | scaffolding | Registered; most currently serve placeholder pages. |

Plugins (both under Crucible): **Clinic-in-a-Box** (AI risk-assessment training,
`clinic_db`) and **Cyber Learning Environment** (instructor course tooling,
`cle_db`). See [Plugins: CiaB & CLE](https://docs.saguaroscyberhub.org/Overview/10-plugins/).

## Documentation index

Hosted at **[docs.saguaroscyberhub.org](https://docs.saguaroscyberhub.org)**;
written in [Saguaros-CyberHub/CyberHub-Docs](https://github.com/Saguaros-CyberHub/CyberHub-Docs).

| # | Doc |
|---|-----|
| 01 | [Overview](https://docs.saguaroscyberhub.org/Overview/01-overview/) — what CyberCore is, glossary, system map |
| 02 | [Architecture](https://docs.saguaroscyberhub.org/Overview/02-architecture/) — components, boot, request lifecycle |
| 03 | [Data Model](https://docs.saguaroscyberhub.org/Overview/03-data-model/) — databases, ER map, table reference |
| 04 | [Modules & Plugins](https://docs.saguaroscyberhub.org/Overview/04-modules-and-plugins/) — the loader, adding features |
| 05 | [Lanes & Provisioning](https://docs.saguaroscyberhub.org/Overview/05-lanes-and-provisioning/) — the lane lifecycle |
| 06 | [Networking](https://docs.saguaroscyberhub.org/Overview/06-networking/) — subnet schemes, Tailscale, Guacamole |
| 07 | [Crucible & Challenges](https://docs.saguaroscyberhub.org/Overview/07-crucible-challenges/) — challenges vs. events |
| 08 | [Auth & Security](https://docs.saguaroscyberhub.org/Overview/08-auth-and-security/) — JWT, roles, MFA, rate limits |
| 09 | [Deployment & Ops](https://docs.saguaroscyberhub.org/Overview/09-deployment-and-ops/) — the compose stack, env, logging |
| 10 | [Plugins: CiaB & CLE](https://docs.saguaroscyberhub.org/Overview/10-plugins/) — the two shipped plugins |
| 11 | [Offline Mode](https://docs.saguaroscyberhub.org/Overview/11-offline-mode/) — LAN / air-gapped operation |
| — | [Quickstart Guide](https://docs.saguaroscyberhub.org/Setup/Quickstart%20Guide/) — set up CyberHub locally |

## Contributing

- Keep route handlers thin; put infrastructure logic in `src/utils/`.
- Write idempotent migrations — the loader re-runs plugin migrations every boot.
- **When you change how a subsystem works, open a matching PR against
  [CyberHub-Docs](https://github.com/Saguaros-CyberHub/CyberHub-Docs)** and link it
  from your CyberCore PR. The docs are only useful if they stay honest.

## License

See [LICENSE](LICENSE).
