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
3. Setup partitions and installs with no driver injection at all: the system disk
   and every CD-ROM sit on buses WinPE has inbox drivers for. That is a
   deliberate constraint, not laziness — see *Why the system disk is SATA* below.
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

## Why the system disk is SATA and not virtio-scsi

virtio-scsi is the faster bus and the obvious choice, but Windows ships no driver
for it, and on this ISO (Win 11 25H2, build 26200) every way of injecting one is
a dead end:

| Mechanism | Result |
| --- | --- |
| `Microsoft-Windows-PnpCustomizationsWinPE` / `DriverPaths` | Aborts Setup after ~3s with `0x80070057 - 0x40030` |
| `drvload` from `RunSynchronous` | Reaches WinPE only; deployed OS bugchecks `INACCESSIBLE_BOOT_DEVICE (0x7B)` |
| `$WinPEDriver$` on the Packer CD | Works in principle, but needs driver files staged out of the virtio ISO by hand |
| Clicking *Load driver* in Setup | Works, both halves — but it is a human clicking a button |

`DriverPaths` is what nearly every Proxmox Packer template uses and it is the one
that should be right. It does not survive the "ConX" setup engine introduced in
24H2. `setuperr.log`:

```
CSI    E_INVALIDARG from CWcmStateNodeCore::GetOrCreateChildOneLevel(
       node name = PathAndCredentials, name in handler = 0, childNode = NULL)
MOUPG  CDlpActionWinpeInitialization::ExecuteRoutine(224): Result = 0x80070057
```

Confirmed by A/B on build 26200: block present, Setup aborts; block absent, the
install runs to completion. Declaring `xmlns:wcm` on the root element rather than
inline — the obvious suspect, since the error is a key-resolution failure and
`wcm:keyValue` is that key — makes no difference.

AHCI is an inbox driver, so nothing needs injecting and nothing can fail. That is
the whole reason for the choice. Expect somewhat lower IOPS than virtio-scsi
under heavy disk load; for a lab desktop template it is not the bottleneck.

### Getting a clone onto virtio-scsi anyway

The template is not stuck on SATA. `virtio-win-guest-tools` installs during the
build and `bootstrap.ps1` stages the full virtio driver set into the driver
store, so `vioscsi` is present in the image. Moving a clone across is a bus
change on the clone, after which it boots normally:

```sh
qm set <vmid> --scsihw virtio-scsi-single
qm set <vmid> --scsi0 <storage>:<disk>     # detach from sata0, attach as scsi0
```

Do this on a clone, not on the template.

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

The account Cloudbase-Init manages is `username` in those two configs, which is
kept equal to `winrm_username` (`cactus-user`). That account already exists in
the template, so Cloudbase-Init resets its password rather than creating it.

### The Cloud-Init *User* field does nothing

Only the **Password**, **SSH key**, **DNS** and **IP config** fields have any
effect. The account name comes from `username` in the configs and nothing else:
Proxmox does not put `admin_username` in `meta_data.json`, so Cloudbase-Init
falls back to the config value every time.

This is worth knowing because the failure is silent and looks like Cloud-Init is
broken. The default `username=Administrator` produces exactly that: Cloud-Init
reports success while the machine stays unreachable, because the built-in
`Administrator` is disabled on Windows by default.

```
CreateUserPlugin  Setting password for existing user "Administrator"
                  Cannot create a user logon session for user: "Administrator":
                  "This user can't sign in because this account is currently disabled."
SetUserPasswordPlugin  Password succesfully updated for user Administrator
```

The password really was set — on an account that cannot log in. Pointing
`username` at the enabled build account is what makes the Password field
meaningful. A knock-on effect of the same mistake is
`SetUserSSHPublicKeysPlugin` dying with `FileNotFoundError` from `get_user_home`,
because an account that has never logged on has no `ProfileList` entry.

These warnings in the same log are benign — Proxmox emits Linux-flavoured
cloud-config that Cloudbase-Init has no equivalent for, and the fields that
matter arrive through `meta_data.json` instead:

```
Plugin 'password' is currently not supported
Plugin 'ssh_authorized_keys' is currently not supported
Plugin 'chpasswd' is currently not supported
```

### Two manual steps per template

Neither can be set by the Packer builder, and the symptom of skipping either is
the same: you edit the Cloud-Init fields, boot the clone, and nothing changes.

**1. Attach a cloud-init drive.** `cloud_init = true` in `windows-11.pkr.hcl`
does this at build time. A clone whose Cloud-Init tab says *No CloudInit Drive
found* came from a template built before that setting existed:

```sh
qm set <vmid> --ide2 <vm-disk-pool>:cloudinit
```

**2. Set `citype` to `configdrive2`.** Required, and verified necessary on this
cluster — do not assume Proxmox infers it from `ostype`:

```sh
qm set <vmid> --citype configdrive2
qm config <vmid> | grep citype      # confirm
```

Cloudbase-Init's `ConfigDriveService` reads the OpenStack config-drive layout
(`openstack/latest/meta_data.json`). The `nocloud` format puts `meta-data` and
`user-data` at the drive root instead, which that service cannot parse — it finds
a drive, reads nothing useful, and reports success having changed nothing.

The Packer plugin (v1.2.3) has `cloud_init`, `cloud_init_storage_pool` and
`cloud_init_disk_type`, but no `citype`, so this is a post-build step. Do it on
the template once and clones inherit it.

Then set the Cloud-Init fields (user, password, SSH keys, IP config) and boot.
If it still does nothing, the log that says why is:

```
C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init-unattend.log
```

### Hiding the config drive (temporary)

The config drive Cloudbase-Init reads is a CD-ROM the clone mounts as `D:`, and
`D:\openstack\latest\user_data` holds the Cloud-Init password **in cleartext**.
That is not a Proxmox misconfiguration and cannot be hashed away:
`SetUserPasswordPlugin` sets the Windows password through an API that takes a
cleartext string, unlike Linux cloud-init writing a crypt hash into `/etc/shadow`.

`install-config-drive-hide.ps1` registers a `CyberCore-HideConfigDrive` scheduled
task that runs `C:\Windows\Setup\Scripts\Hide-ConfigDrive.ps1` at every boot,
waits for Cloudbase-Init to finish, and `mountvol /D`s the letter away. Log:

```
C:\Windows\Temp\hide-config-drive.log
```

**This is a speed bump, not a security boundary.** The account it hides the drive
from is a local Administrator, so `mountvol` or a raw read of `\\.\CdRom0` gets it
straight back. It is an accepted trade for now, not a solution. The two real
fixes, in order of value:

1. Stop putting a *reusable* credential on the drive. Provisioning currently
   passes the student's platform password as `cipassword`, so reading that file
   yields their portal login, not just a VM login.
2. Strip the drive at the hypervisor once Cloudbase-Init has applied it, and
   re-attach only when a password actually changes.

The drive is deliberately left attached. Cloudbase-Init re-reads it on every
boot, and a changed Cloud-Init field — which produces a new instance ID — is the
only thing that makes a new password take effect. Detaching the device would
break "change the password in the portal, reboot, log in with it".

To back the whole thing out, delete `scripts/install-config-drive-hide.ps1`,
`files/config-drive/`, and the two provisioners referencing them in
`windows-11.pkr.hcl`. Clones built from an existing template also need
`Unregister-ScheduledTask -TaskName CyberCore-HideConfigDrive`.

## Editing the answer file

Edit `answer-files/autounattend.xml.pkrtpl`, never a generated copy. `${...}` in
that file is a Packer template variable, so avoid introducing a literal `${`
anywhere else in it.

## Security notes

- WinRM is configured with `AllowUnencrypted` and Basic auth. This is only
  tolerable because the build VM is short-lived, sits on an isolated VLAN, and is
  generalized afterwards. Do not lift `configure-winrm.ps1` into anything that
  survives the build.
- The build account is **not** removed. Sysprep `/generalize` resets the SID and
  machine identity but leaves local accounts alone, and `cleanup.ps1` only clears
  the autologon registry values. `winrm_username` therefore ships in the template
  and is the account clones are administered through; its build password is
  overwritten by Cloudbase-Init on first boot from the Proxmox Cloud-Init field.
  Anyone who can read this repo's vars file knows the password a clone has until
  that first boot completes.
- SSH host keys are deleted during the build so each clone generates its own.
- The Cloud-Init password reaches the clone in cleartext on the config drive and
  is re-read on every boot. `CyberCore-HideConfigDrive` only removes the drive
  letter — see [Hiding the config drive](#hiding-the-config-drive-temporary) for
  what that does and does not buy. The same cleartext also sits in
  `/etc/pve/qemu-server/<vmid>.conf`, in `qm cloudinit dump <vmid> user`, and in
  cluster config backups, none of which this task touches.
