# Windows 11 Proxmox template (Packer + Cloudbase-Init)

Builds a generalized Windows 11 template on Proxmox that picks up its hostname,
administrator account and SSH keys from Proxmox's cloud-init drive at first boot.

## Prerequisites

- Packer 1.11+ (`packer version`)
- Both ISOs uploaded to a Proxmox storage with `iso` content enabled:
  - a Windows 11 ISO
  - `virtio-win.iso` — must have `virtio-win-guest-tools.exe` at its root
- A Proxmox API token whose role includes `VM.Allocate`, `VM.Config.*`,
  `VM.Monitor`, `VM.Audit`, `VM.PowerMgmt`, `Datastore.AllocateSpace` and
  `Datastore.Audit` (also `Sys.Modify` if the node uses a bridge with VLANs)
- Outbound HTTPS from the build VLAN, or a Cloudbase-Init MSI pre-staged in
  `files/installers/` (see below)

## Build

```sh
cp credentials.auto.pkrvars.hcl.example credentials.auto.pkrvars.hcl
$EDITOR credentials.auto.pkrvars.hcl

packer init .
packer validate .
packer build .
```

Expect roughly 40–60 minutes. `credentials.auto.pkrvars.hcl` is loaded
automatically by virtue of the `.auto.pkrvars.hcl` suffix.

## How a build actually gets off the ground

The fragile part of any Windows Packer build is the window between "the ISO
boots" and "Packer can run a provisioner". Here it goes:

1. `boot_command` gets past the *Press any key to boot from CD* prompt.
2. Windows Setup finds `autounattend.xml` on the `PACKERDATA` CD, which is
   generated at build time from `answer-files/autounattend.xml.pkrtpl` — that is
   why the build account cannot drift from `winrm_username`.
3. `DriverPaths` injects the virtio-scsi driver, without which Setup reports no
   disks. This is also why the three CD-ROMs are on IDE/SATA and only the system
   disk is on virtio-scsi: WinPE has no inbox virtio driver.
4. At first logon, `scripts/bootstrap.ps1` runs from the same CD. It installs
   `virtio-win-guest-tools` (the QEMU guest agent — Packer resolves the VM's IP
   through it, because `qemu_agent = true`) and then `configure-winrm.ps1`.
5. Only now can Packer connect. Provisioners run with `elevated_user`, since a
   plain WinRM logon cannot drive DISM, AppX provisioning or Sysprep.
6. Sysprep runs last, with `/quit` rather than `/shutdown`. The `proxmox-iso`
   builder has no `shutdown_command` hook and powers the VM off itself once the
   final provisioner returns, so `/shutdown` would drop the WinRM session
   mid-provisioner and fail the build.

If a build hangs, the two logs worth reading first are
`C:\Windows\Temp\bootstrap.log` and `C:\Windows\Panther\`. Set
`PACKER_LOG=1` and watch the console via the Proxmox web UI.

## Air-gapped / no outbound HTTPS

`install-cloudbase-init.ps1` downloads the MSI from cloudbase.it. If the build
VLAN cannot reach it, drop the file in `files/installers/` first:

```
files/installers/CloudbaseInitSetup_Stable_x64.msi
```

Any other `.msi` in that directory is installed silently by
`install-software.ps1`, in filename order. OpenSSH comes from Windows Update and
is skipped with a warning if unreachable.

## Cloudbase-Init

The MSI's stock configuration targets OpenStack's HTTP metadata service, which
Proxmox does not run — Proxmox attaches cloud-init as an ISO on a CD-ROM. The
configs in `files/cloudbase-init/` replace it with `ConfigDriveService`, and are
copied into place during the build.

Two configs, two runs:

- `cloudbase-init-unattend.conf` — one pass from the specialize stage of
  `answer-files/sysprep-unattend.xml`, before the logon screen. Grows the volume
  to the clone's disk size and creates the administrator account.
- `cloudbase-init.conf` — the service proper, on every subsequent boot.

To use a clone, set the cloud-init fields on the VM (user, password, SSH keys,
IP config) and start it. The username defaults to `Administrator`.

## Editing the answer file

Edit `answer-files/autounattend.xml.pkrtpl`, never a generated copy. `${...}` in
that file is a Packer template variable, so avoid introducing a literal `${`
anywhere else in it.

## Security notes

- WinRM is configured with `AllowUnencrypted` and Basic auth. This is only
  tolerable because the build VM is short-lived, sits on an isolated VLAN, and is
  generalized afterwards. Do not lift `configure-winrm.ps1` into anything that
  survives the build.
- The build account and its cleartext autologon password are removed by
  `cleanup.ps1` and then generalized away by Sysprep.
- SSH host keys are deleted during the build so each clone generates its own.
