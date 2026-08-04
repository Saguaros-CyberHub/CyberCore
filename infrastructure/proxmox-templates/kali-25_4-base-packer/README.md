# Kali 2025.4 Proxmox template (Packer + cloud-init)

Builds a Kali Rolling template on Proxmox with xfce and xrdp, which picks up its
hostname, user account, password and IP configuration from Proxmox's cloud-init
drive at first boot. Clones are reached over RDP through Guacamole
(`rdp.saguaroscyberhub.org`).

This is the Packer equivalent of `front-end/scripts/bake-kali-template.sh`. That
script bakes VMID 1699 from Kali's `cloud-generic` qcow2 by driving cloud-init on
the node itself; this builds from the installer ISO and is reproducible from a
workstation. The guest ends up configured the same way on purpose — same `kali`
account, same xrdp/xfce wiring, same lane-gateway DNS unit — so lane tooling
does not care which one produced the template.

| | `bake-kali-template.sh` | this |
| --- | --- | --- |
| Source image | Kali `cloud-generic` qcow2 | Kali installer ISO |
| Runs on | the Proxmox node, as root | any workstation, over the API |
| Configured by | a cloud-init snippet | preseed + shell provisioners |
| Pre-seal check | inside the script, via `rbd map` | `scripts/verify.sh`, in the guest |

## Prerequisites

- Packer 1.11+ (`packer version`)
- The Kali installer ISO uploaded to a Proxmox storage with `iso` content
  enabled, e.g. `cephfs:iso/kali-linux-2025.4-installer-amd64.iso`
- A Proxmox API token whose role includes `VM.Allocate`, `VM.Config.*`,
  `VM.Monitor`, `VM.Audit`, `VM.PowerMgmt`, `Datastore.AllocateSpace` and
  `Datastore.Audit` (also `Sys.Modify` if the node uses a bridge with VLANs)
- **Two-way reachability on the build VLAN** — see below. This is the one
  prerequisite that is easy to miss and it stalls the build at the ISO menu.

## Build

```sh
cp credentials.auto.pkrvars.hcl.example credentials.auto.pkrvars.hcl
$EDITOR credentials.auto.pkrvars.hcl

packer init .
packer validate .
packer build .
```

Expect 25–40 minutes for `kali_toolset = "default"`, 60–90 for `"large"`.
`credentials.auto.pkrvars.hcl` is loaded automatically by virtue of the
`.auto.pkrvars.hcl` suffix and is gitignored.

## The build VLAN has to reach *you*

Packer serves the preseed over HTTP from the machine running `packer build`, and
the build VM fetches it with `preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/`.
So `vlan_tag` needs:

- outbound HTTPS/HTTP to `http.kali.org` (or set `kali_mirror_host` to a local
  mirror), and
- a route **back** to your workstation on `http_port_min`–`http_port_max`
  (8600–8610 by default), with the host firewall open on that range.

If your workstation is multi-homed, Packer can advertise the wrong address in
`{{ .HTTPIP }}`. Pin it with `http_bind_address`.

The symptom of getting this wrong is a build that sits at "Waiting for SSH"
forever while the installer console shows a stalled preseed download. Watch it
with `qm terminal <vm_id>` (`^O` to exit) — the VM has a serial console, so this
works from the first second of boot.

## How a build gets off the ground

1. `boot_command` presses `<esc>` at Kali's isolinux menu to reach the `boot:`
   prompt, then types `install` plus the preseed URL and `console=ttyS0`. It is
   typed blind: the VM has `vga = serial0` and no emulated graphics adapter, so
   there is nothing to look at until the kernel takes over the serial port.
2. debian-installer fetches `/preseed.cfg`, rendered at build time from
   `http/preseed.cfg.pkrtpl` — which is why the account it creates cannot drift
   from `ssh_username`.
3. The preseed installs a **`standard` system only**, plus `qemu-guest-agent`,
   `cloud-init` and `openssh-server`. Its `late_command` grants the build user
   NOPASSWD sudo so Packer's provisioners can work over a plain SSH session.
4. Packer resolves the VM's IP through the guest agent and connects.
5. `scripts/*.sh` install the desktop, xrdp, cloud-init config and the tool
   metapackage.
6. `scripts/verify.sh` asserts the template is actually usable, and fails the
   build if not.
7. `scripts/cleanup.sh` generalizes the image. It must be last — it revokes the
   build user's sudo and deletes the SSH host keys.

### Why the heavy lifting is not in the preseed

The desktop, xrdp and `kali-linux-default` could all be `pkgsel/include` lines.
They are not, because a debian-installer that hits a mirror problem or a debconf
prompt at that stage stops on a console nobody is watching, and Packer just
reports an SSH timeout 60 minutes later. Run from a provisioner, the same
failure lands in Packer's output with the apt error attached.

## Partitioning: one ext4 root, no swap partition

`http/preseed.cfg.pkrtpl` uses a custom `expert_recipe` rather than the stock
`atomic` one. `atomic` lays down root **then** swap, and cloud-init's `growpart`
can only extend the *last* partition on a disk — so a clone given a 128G disk
would silently stay at the template's 64G root. Root is therefore the last (and
only) partition, and `verify.sh` asserts that so a future edit cannot quietly
regress it.

Swap comes back as zram (`zram-tools`, 25% of RAM), which costs nothing in the
image and sizes itself to whatever memory a clone is given.

## Cloud-init

Proxmox defaults Linux guests to `citype=nocloud`, which cloud-init reads
natively — so unlike the Windows template there is **no post-build
`qm set --citype` step**. `cloud_init = true` in `kali-25_4.pkr.hcl` attaches the
drive at build time and clones inherit it.

`files/cloud-init/99-cybercore.cfg` does three things that matter:

- **Pins `datasource_list`** to `[NoCloud, ConfigDrive, None]`. Left unpinned,
  cloud-init probes the EC2/Azure/GCE metadata endpoints on every boot, and on
  an isolated lane VLAN that is ~2 minutes of timeouts before the desktop
  appears.
- **Sets `default_user.name`**, which is the fallback when the Proxmox Cloud-Init
  *User* field is left empty. Unlike the Windows/Cloudbase-Init template, the
  User field here **does** work: Proxmox writes `user:` into its nocloud
  user-data and cloud-init creates that account.
- **Enables `growpart`** on `/`.

`scripts/configure-cloud-init.sh` also reduces `/etc/network/interfaces` to a
loopback stub that sources `interfaces.d/`. d-i writes a DHCP stanza for `ens18`
there, and cloud-init's `eni` renderer writes its own into
`interfaces.d/50-cloud-init`; with both present a Proxmox-assigned static IP
loses to the DHCP stanza. Reducing the file makes cloud-init's the only one.

### DNS on a lane

`cybercore-resolv-gw.service` publishes the default route's address (the lane
gateway, which runs the split-horizon dnsmasq for the AD zone) into `resolvconf`
on every boot. It is derived at runtime because the gateway address is per-lane,
and it covers the deploy paths that assign a **static** IP, where there is no
dhclient to publish DNS.

`cleanup.sh` restores `/etc/resolv.conf` as a symlink into `/run/resolvconf/`.
This is not cosmetic: anything that opens that path with `O_TRUNC` replaces the
symlink with a regular file, after which resolvconf still tracks DHCP-supplied
servers internally but has nowhere to publish them — every clone then boots with
an empty `resolv.conf` while IP and routing look perfectly healthy. That bug has
shipped from this lineage once already.

## verify.sh, and why it exists

A previous Kali template shipped a 0-byte
`/usr/lib/x86_64-linux-gnu/libjpeg.so.62.4.0` from a torn mirror write. xrdp died
on every connection with `error while loading shared libraries: file too short`.
Nothing about that is visible from `qm config`, and students found it.

`scripts/verify.sh` runs before cleanup, on the live system, and fails the build
rather than sealing a bad template. It checks libjpeg's size and xrdp's whole
link map, that xrdp and sesman are listening on 3389/3350, that `startxfce4`
exists and `startwm.sh` actually launches it, that every unit a clone depends on
is enabled, that the cloud-init config is in place with no `disable-network-config`
fragment surviving, that root is still the last partition, that the requested
metapackage installed cleanly, and that there is disk headroom left.

On failure the build VM is left running so it can be inspected.

## Air-gapped / slow mirror

Set `kali_mirror_host` and `kali_mirror_directory` to a local mirror, or
`apt_proxy` to an apt-cacher-ng instance. `apt_proxy` is applied for the build
only — `cleanup.sh` removes `/etc/apt/apt.conf.d/01-cybercore-build-proxy`
before the template is sealed, so clones do not inherit a proxy they cannot
reach.

## If the boot command does nothing

`boot_command` assumes Kali's BIOS boot path is isolinux, where `<esc>` gives a
`boot:` prompt. If a future ISO switches to GRUB for BIOS as well, the menu will
not respond to `<esc>` and the build will sit at the menu until `ssh_timeout`.
The GRUB equivalent is `<c>` for a command line, or `<e>` to edit the highlighted
entry — check with `qm terminal <vm_id>` and adjust.

## Security notes

- The build password is served **in cleartext over plain HTTP** inside the
  preseed. That is tolerable only because the build VM is short-lived and the
  build VLAN is isolated. It is also stored unhashed in
  `credentials.auto.pkrvars.hcl` (gitignored).
- The build account is **not** removed — it is the fallback login on a clone and
  the account lane tooling expects. `cleanup.sh` revokes its NOPASSWD sudo, so
  on a clone it is an ordinary `sudo`-group user whose password comes from
  cloud-init. Until a clone's first boot completes it still holds the build
  password, which anyone with this repo's vars file knows.
- SSH host keys, `machine-id`, the systemd random seed and credential secret are
  all deleted during cleanup so each clone generates its own.
- Root login is disabled, in the preseed and in `sshd_config.d/10-cybercore.conf`.
- The Cloud-Init password reaches a clone in cleartext on the config drive, and
  also sits in `/etc/pve/qemu-server/<vmid>.conf`, in `qm cloudinit dump <vmid>
  user`, and in cluster config backups. Nothing here changes that; see the
  Windows template's README for the fuller discussion, which applies equally.
