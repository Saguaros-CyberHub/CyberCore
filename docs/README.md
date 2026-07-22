# CyberCore Documentation

CyberCore is the control-plane application for **CyberHub** — a cyber-education
platform that provisions isolated, per-user lab environments ("lanes") on a
Proxmox cluster and presents them through a single web hub.

This directory is the source of truth for how the system is built and why. If
something here disagrees with the code, the code wins — please open a PR to fix
the doc.

## Reading order

Start at the top and work down. The first three are the foundation; the rest
are subsystem deep-dives you can read on demand.

| # | Doc | What it covers |
|---|-----|----------------|
| 01 | [Overview](01-overview.md) | What CyberCore is, the glossary, and the top-level system diagram. **Start here.** |
| 02 | [Architecture](02-architecture.md) | Components, the boot sequence, and the request lifecycle. |
| 03 | [Data Model](03-data-model.md) | The databases, the entity-relationship map, and a key-table reference. |
| 04 | [Modules & Plugins](04-modules-and-plugins.md) | The manifest-driven loader and how to add a module or plugin. |
| 05 | [Lanes & Provisioning](05-lanes-and-provisioning.md) | The lane lifecycle and the Proxmox/SDN deploy sequence. |
| 06 | [Networking](06-networking.md) | Subnet schemes v1/v2/v3, lane gateways, Tailscale, and Guacamole consoles. |
| 07 | [Crucible & Challenges](07-crucible-challenges.md) | The challenge catalog vs. live events, and attachable challenges. |
| 08 | [Auth & Security](08-auth-and-security.md) | JWT/session auth, roles, MFA, rate limiting, and signed URLs. |
| 09 | [Deployment & Ops](09-deployment-and-ops.md) | The Docker Compose stack, environment variables, and offline mode. |
| 10 | [Plugins: CiaB & CLE](10-plugins.md) | The two shipped plugins and what they add. |

Also: [offline-mode.md](11-offline-mode.md) — running CyberHub on a LAN or
air-gapped machine without public HTTPS.

## Conventions used in these docs

- **Code references** are relative paths, e.g. [src/server.js](../front-end/src/server.js).
- **Tables** are named with their database prefix (`cybercore_*` live in the
  main database; `clinic_*`/`cle_*` live in their plugin databases).
- Diagrams are [Mermaid](https://mermaid.js.org/) fenced code blocks so they
  render on GitHub and in most Markdown viewers.
