# CyberHub Infrastrure

This is the folder containing all the infrastructure-related scripts, Ansible playbooks, Docker Compose files, etc.

## Provisioning & lifecycle scripts

These scripts bring a clean Proxmox host up to a running CyberCore and manage its lifecycle. Run them from the repo root, as root. `install.sh`/`setup.sh` live in `scripts/`; `start.sh`/`stop.sh` live at the project root:

1. **`scripts/install.sh`** — bootstraps a Proxmox VE host: creates the API user/token, SSH keys, the orchestrator VM (runs the docker compose stack), the per-module **L2** transit bridges, and writes `config/site.json` + `.env`. It calls `scripts/setup.sh --infra` automatically at the end (set `SKIP_SETUP=1` to defer).
2. **`scripts/setup.sh`** — post-install production readiness. Fills any remaining secrets, hardens permissions, validates configs, and on a Proxmox node creates the module transit gateways (`--gateways`) and lab templates (`--templates`); `--infra` does both. Idempotent; re-run any time.
3. **`start.sh` / `stop.sh`** (project root) — bring the docker compose stack and the transit-gateway LXCs up/down together (`--stack-only` / `--gateways-only` to scope).

### Network fabric: SDN, transit gateways & lane gateways

Two independent layers do two jobs: **SDN/VXLAN** gives each lane an isolated L2 segment, and the **gateway LXCs** provide L3 (routing/NAT/DHCP/firewall) and chain those segments out to the infrastructure. Every packet from a challenge VM to the internet crosses **two gateway LXCs**, each doing NAT + a restrictive firewall — a compromised VM must break two routers to reach anything real.

```
challenge VMs ─ lane VNet (SDN/VXLAN, L2) ─ lane-gw LXC ─ module transit net (/16, L2) ─ module-gw LXC ─ vmbr0 ─ infra/internet
   192.18.0.x        per-lane isolated         192.18.0.1        100.10x.0.0/16              100.10x.0.1
```

**1. SDN VXLAN — L2 isolation (app-managed, not the playbooks).**
When a lab is created, `front-end/src/utils/lab-network-provision.js` reserves a VXLAN block (one id per lane), creates a Proxmox SDN zone (`type: vxlan`) with one VNet per lane, then `PUT /cluster/sdn` to apply. Each VNet materializes as a bridge on the nodes and is its own broadcast domain over VXLAN — so hundreds of lanes can all reuse `192.18.0.0/24` without colliding, and lanes stay L2-isolated even across nodes. (`install.sh` preflight checks the SDN API for this reason.)

**2. Module transit gateway — per-module L3 boundary (one Alpine LXC per module).**
Built from `{module}-gateway.yml`. `lan0` owns the module gateway IP on the module's **pure-L2 bridge** (the host bridge has no IP/NAT); `wan0` uplinks to `vmbr0`/infra. It runs dnsmasq (DHCP+DNS), chrony (NTP), and iptables that NAT the `/16` out `wan0` and enforce **anti-breakout** — `FORWARD` from `lan0` to `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, the mgmt net, *all* module `/16`s, and the VPN range is dropped; only internet egress + return traffic passes. It also lets the Guacamole host reach lane gateways on `3389`/`22` for remote-desktop DNAT.

**3. Lane gateway — per-lane L3 boundary (one Alpine LXC cloned per lane).**
Cloned from `{module}-lane-gw-template.yml` and re-IP'd at deploy. `lan0` → the lane's SDN VNet, owns `192.18.0.1/24`, serves DHCP/DNS to the challenge VMs. `wan0` → the module transit net, with an address derived deterministically from the lane's `vxlan_id` mapped into the module `/16` (`front-end/src/utils/lane-networking.js`), default route = the module gateway. So the lane gateway NATs `192.18.0.0/24` → transit, and the module gateway NATs transit → infra (double NAT, two-tier isolation). Same hardened firewall, plus per-lane DNAT rules so Guacamole reaches specific VMs (e.g. `3389`→`192.18.0.10`).

**Scheme variants.**
- **v1 (transit-gateway model, primary):** lane-gw `wan0` on the module `/16`, routed through the module gateway. This is what the module transit gateways exist for.
- **v2 (VMID 1694):** lane-gw `wan0` goes **directly** onto the v2 lab network (`100.100.60.0/24`, VLAN 60 on `vmbr0`), bypassing the module transit gateway. Simpler, single NAT — used by challenges not yet adapted to run behind the module gateways.
- **v3 (VMID 1695):** segmented DMZ — two SDN VNets per lane (external + internal, internal tag = `vxlan_id + 4,000,000`) and a 3-NIC lane gateway (`wan0`/`ext0`/`int0`) that drops all ext↔int traffic, so an attacker must pivot through a dual-homed host (GOAD/AD topology).

### `proxmox-templates/gateway-templates/` layout

The three module gateways and three lane-gateway templates share one copy of their logic. Each per-module file is a thin wrapper that sets only its `module_name` / `module_subnet_base` and imports the shared tasks/handlers/vars from `_common/`:

| Module | Subnet | Gateway playbook | Lane-gw template |
|---|---|---|---|
| cyberlabs | `100.101.0.0/16` | `cyberlabs-gateway.yml` | `cyberlabs-lane-gw-template.yml` |
| crucible | `100.102.0.0/16` | `crucible-gateway.yml` | `crucible-lane-gw-template.yml` |
| forge | `100.103.0.0/16` | `forge-gateway.yml` | `forge-lane-gw-template.yml` |

- `_common/module-gateway-{tasks,handlers,vars}.yml` — shared body for the module transit gateways.
- `_common/lane-gw-{tasks,handlers,vars}.yml` — shared body for the lane-gateway templates.

Edit shared behavior in `_common/`; edit a module's subnet only in its wrapper. Run standalone with e.g. `ansible-playbook crucible-gateway.yml`, or let `setup.sh --gateways` create and configure them. Both wrappers gate `/etc/network/interfaces` behind `manage_interfaces` (setup passes `false`, since Proxmox manages the LXC's addressing).

## Virtualization

![alt text](https://github.com/echumley/Saguaros-CyberHub/blob/main/resources/images/CyberHub-Virtualization-v1.0.png?raw=true)

## CyberHub Bare-Metal Cluster

The CyberHub bare-metal cluster will each host a set of nested virtualization environments to better segment the various sub-modules (ie. CyberLabs, The Forge, etc.) along with numerous services to ensure smooth and secure operation of the entire project. This may include non-open-source software as these modules can each be ran on their own (see standalone configurations in the modules' directories (planned - WIP)) and it eases adminstrative strain to maintain the physical CyberHub infrastructure.

### Internal Services

*NOTE: These services may live as VMs on the CyberHub bare-metal cluster or in the nested Docker Swarm cluster/K3s cluster.*

- Active Directory
- SIEM/SOAR (ideally Splunk Enterprise)
- Change management software
- Logging stack
- Network monitoring
- OS download/update caching
- Reverse proxy
- NetBox Labs Enterprise
- Password manager
- Secrets manager

## Network Layout

This is a general layout of the network.

![Saguaros CyberLab Network](https://github.com/echumley/Saguaros-CyberHub/blob/main/resources/images/CyberLabs-Network-v1.0.png?raw=true)

*NOTE: The CyberHub heavily utilizes network segmentation via SDNs, VLANs, and VXLANs*

### Subnets

`100.64-99.0.0/16` - Student project infrastructure \
`100.100.0.0/16` - CyberCore & CyberHub infrastructure \
`100.101.0.0/16` - CyberLabs infrastructure \
`100.102.0.0/16` - Crucible infrastructure \
`100.103.0.0/16` - Forge infrastructure \
`100.104-114.0.0/16` - Unused \
`100.115-127.0.0/16` - Remote site infrastructure

### VLANs

`x.x.10.0/24` on `VLAN 10`: Management Network - Remote server management, admin web UIs, switches, etc. \
`x.x.20.0/24` on `VLAN 20`: Internal Services Network - Homepage, SEIM, authentication stack, etc. \
`x.x.30.0/24` on `VLAN 30`: Trusted Network - Admin VPN access & only subnet with routes to all major services. \
`x.x.40.0/24` on `VLAN 40`: WiFi Network - WiFi network in the case of local CTF events. \
`x.x.50.0/24` on `VLAN 50`: DMZ Network - All externally-facing services, reverse proxies, VPN endpoints, etc. \
`x.x.60.0/24` on `VLAN 60`: Lab Networks - Used for testing of new services/infrastructure, admin projects, etc. \
`x.x.70.0/24` on `VLAN 70`: Quarantine Network \
`x.x.80.0/24` on `VLAN 80`:  \
`x.x.90.0/24` on `VLAN 90`:  \
`x.x.99.0/24` on `VLAN 99`: Ceph Network (not routed)

### IP Spacing

#### 100.x.10.0/24: Management services

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.2-9`: Networking devices (Switches, downstream routers, APs, etc.) \
`x.x.x.10-19`: Compute servers 1 (Hypervisors & networking ports) \
`x.x.x.20-29`: Compute servers 2 \
`x.x.x.30-39`: Compute servers 3 \
`x.x.x.40-49`: Compute servers 4 \
`x.x.x.50-59`: Compute servers 5 \
`x.x.x.60-69`: Storage servers \
`x.x.x.70-79`: Remote server management 1 \
`x.x.x.80-89`: Remote server management 2 \
`x.x.x.90-98`: Remote server management 3 \
`x.x.x.99`: OOB Management Server (infrastructure dependant) \
`x.x.x.100-254`: DHCP

#### 100.x.20.0/24: Internal services

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.2-9`: Logging services (Loki, Grafana, Prometheus, etc.) \
`x.x.x.10-19`: SIEM & SOAR services (Wazuh, Zeek, TheHive, etc.) \
`x.x.x.20-29`: Authentication services (LDAP, FreeIPA, Keycloack, etc.) \
`x.x.x.30-39`: Backup services \
`x.x.x.40-49`: Network storage shares \
`x.x.x.50`: CyberCore \
`x.x.x.51-99`: Others \
`x.x.x.100-254`: DHCP

#### 100.x.30.0/24: Trusted network & VPN access

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.2-99`: Workstations/trusted devices \
`x.x.x.100-254`: Administrator VPN endpoints

#### 100.x.40.0/24: WiFi-connected devices

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.2-9`: WAPs \
`x.x.x.10-254`: DHCP

#### 10.x.50.0/24: DMZ for externally facing services

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.2-9`: Unused \
`x.x.x.10`: DMZ reverse proxy
`x.x.x.11-99`: Unused \
`x.x.x.100-254`: DHCP

#### 100.x.60.0/24: Lab network

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.100-254`: DHCP

#### 100.x.70.0/24: External services

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.2-9`: External access (Traefik, Crowdsec, etc.) \
`x.x.x.10-99`: CyberHub services (ctfd, Moodle, etc.) \
`x.x.x.100-254`: DHCP

#### 100.x.90.0/24: Quarantine

`x.x.x.1`: VLAN/subnet gateway \
`x.x.x.99-254`: DHCP

## Architecture Overview

![CyberHub Architecture](https://github.com/echumley/Saguaros-CyberHub/blob/main/resources/images/CyberHub-Architecture-v1.0.png?raw=true)

## Network Traffic Flow

![CyberHub Traffic Flow](https://github.com/echumley/Saguaros-CyberHub/blob/main/resources/images/CyberHub%20Traffick%20v1.2.png?raw=true)

## Proxmox Organization

### VM IDs

The VM IDs to be set are combinations of the VLAN the VM is connected to and the VM's IPv4 address. The first number of the 3-digit number is the VLAN divided by 10, while the second and third numbers are the IP address's last octet which is to be kept below 3 digits.

Example: VM ID of 210 means that the VM lives on VLAN 20 and has an IPv4 address ending in .10.

### Template Organization

Keep template organization by numbering based on the VLAN

- Base image templates: `1000-1099`
- Management templates: `1100-1199`
- Internal service templates: `1200-1299`
- Trusted service templates: `1300-1399`
- WiFi service templates: `1400-1499`
- DMZ service templates: `1500-1599`
- Lab service templates: `1600-1999`
- Miscellaneous templates: `+2000`

## SSH Keys

Utilize separate keys for each service, but during the initial deployment we're utilizing three sets of SSH key pairs: \
NOTE: These keys are not publically available, and until we implement a better secret manager, just create these keys or modify the Ansible/Docker/Terraform config files.

- `saguaros-admin-key`
- `saguaros-crucible-key`
- `saguaros-ansible-key`