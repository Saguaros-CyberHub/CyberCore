packer {
    required_plugins {
        proxmox = {
            version = "~> 1.2"
            source  = "github.com/hashicorp/proxmox"
        }
    }
}

locals {
    # Rendered into the answer-file ISO so the account the unattend creates and the
    # account Packer authenticates with can never drift apart.
    autounattend = templatefile("${path.root}/answer-files/autounattend.xml.pkrtpl", {
        winrm_username      = var.winrm_username
        winrm_password      = var.winrm_password
        windows_image_name  = var.windows_image_name
        windows_product_key = var.windows_product_key
        timezone            = var.timezone
    })
}

source "proxmox-iso" "windows_11" {
    proxmox_url = var.proxmox_url
    username    = var.proxmox_username
    token       = var.proxmox_token
    node        = var.proxmox_node

    insecure_skip_tls_verify = true

    vm_id                = var.vm_id
    vm_name              = var.template_name
    template_description = "Windows 11 template built automatically with Packer"
    tags                 = "packer;windows11;cloudbase-init"

    machine = "q35"
    bios    = "ovmf"
    os      = "win11"
    cpu_type = "host"
    cores   = var.cores
    sockets = 1
    memory  = var.memory

    # Proxmox names this "virtio", not "virtio-gpu". It maps to QEMU's virtio-vga,
    # which keeps a VGA-compatible mode, so WinPE and Setup stay visible on the
    # console before any driver exists; the accelerated path arrives later when
    # virtio-win-guest-tools installs the display driver at first logon.
    vga {
        type   = "virtio"
        memory = 32
    }

    # Inert while the system disk is SATA -- no SCSI disks are attached for it to
    # control. Kept because clones inherit it, so a clone moved onto virtio-scsi
    # already has the right controller.
    scsi_controller = "virtio-scsi-pci"



    # CD-ROMs must sit on a bus WinPE has an inbox driver for, so anything Setup
    # reads itself (the install media, the virtio media, the answer file) goes on
    # IDE/SATA. q35 exposes only two IDE slots, hence SATA for the extra two.
    boot_iso {
        type         = "ide"
        iso_file     = var.windows_iso
        iso_checksum = "none"
        unmount      = true
    }

    additional_iso_files {
        type         = "sata"
        iso_file     = var.virtio_iso
        iso_checksum = "none"
        unmount      = true
    }

    additional_iso_files {
        type = "sata"
        cd_content = {
            "autounattend.xml"    = local.autounattend
            "bootstrap.ps1"       = file("${path.root}/scripts/bootstrap.ps1")
            "configure-winrm.ps1" = file("${path.root}/scripts/configure-winrm.ps1")
        }
        cd_label         = "PACKERDATA"
        iso_storage_pool = var.iso_storage_pool
        unmount          = true
    }

    # SATA, not virtio-scsi, and this is a deliberate trade rather than an
    # oversight. Any virtio storage bus needs a driver Windows does not ship, and
    # all three ways of injecting one are dead ends on this ISO: DriverPaths
    # aborts Setup outright on the 24H2+ ConX engine, $WinPEDriver$ needs driver
    # files staged out of the virtio ISO by hand, and drvload reaches WinPE but
    # not the deployed image, which then bugchecks 0x7B. AHCI is inbox, so
    # nothing has to be injected and nothing can fail.
    #
    # virtio-win-guest-tools still installs during provisioning and bootstrap.ps1
    # stages the whole driver set into the driver store, so the template does
    # contain vioscsi. A clone can be moved to virtio-scsi afterwards and will
    # boot; it is just not how the template itself is built.
    disks {
        type         = "sata"
        disk_size    = var.disk_size
        storage_pool = var.disk_storage_pool
        cache_mode   = "writeback"
    }

    network_adapters {
        model    = "virtio"
        bridge   = var.network_bridge
        vlan_tag = var.vlan_tag
    }

    efi_config {
        efi_storage_pool  = var.disk_storage_pool
        pre_enrolled_keys = true
        efi_type          = "4m"
    }

    tpm_config {
        tpm_storage_pool = var.disk_storage_pool
        tpm_version      = "v2.0"
    }

    # Attaches the cloud-init CD-ROM to the template, which clones then inherit.
    # The builder does not add one on its own, and without it the whole
    # Cloudbase-Init half of this template is inert: the clone boots, finds no
    # config drive, and sits at a logon prompt with no account to log into. The
    # Proxmox UI shows "No CloudInit Drive found" on the clone.
    #
    # It is a small disk image rather than an ISO, so it has to live on a storage
    # that accepts images -- the VM disk pool, not the ISO/cephfs one.
    #
    # THIS IS ONLY HALF THE JOB. The drive also has to be in configdrive2 format,
    # because Cloudbase-Init's ConfigDriveService reads the OpenStack layout and
    # cannot parse nocloud. Plugin v1.2.3 exposes cloud_init,
    # cloud_init_storage_pool and cloud_init_disk_type but NOT citype, so it is a
    # post-build step on the template:
    #     qm set <vmid> --citype configdrive2
    # Do not assume Proxmox infers this from ostype=win11; it was verified not to
    # here. Skipping it looks exactly like skipping the drive entirely -- edits to
    # the Cloud-Init fields simply have no effect on the clone. See the README.
    cloud_init              = true
    cloud_init_storage_pool = var.disk_storage_pool

    # Packer discovers the VM's IP through the agent. bootstrap.ps1 installs
    # virtio-win-guest-tools (which provides it) at first logon, before WinRM opens.
    qemu_agent = true

    communicator   = "winrm"
    winrm_username = var.winrm_username
    winrm_password = var.winrm_password
    winrm_timeout  = "2h"
    winrm_use_ssl  = false
    winrm_insecure = true

    boot_wait = "3s"

    # "Press any key to boot from CD" gives a ~5s window. One keystroke after a
    # fixed wait is a race; repeat it until the window has certainly passed.
    boot_command = [
        "<spacebar><wait1s>",
        "<spacebar><wait1s>",
        "<spacebar><wait1s>",
        "<spacebar><wait1s>",
        "<spacebar>"
    ]
}

build {
    name = "windows-11-proxmox"

    sources = [
        "source.proxmox-iso.windows_11"
    ]

    provisioner "powershell" {
        inline = [
            "New-Item -ItemType Directory -Force -Path C:\\Windows\\Setup\\Scripts | Out-Null",
            "New-Item -ItemType Directory -Force -Path C:\\Windows\\Temp\\cloudbase-init | Out-Null",
            "New-Item -ItemType Directory -Force -Path C:\\Windows\\Temp\\config-drive | Out-Null",
            "New-Item -ItemType Directory -Force -Path C:\\Windows\\Temp\\installers | Out-Null"
        ]
    }

    # Staged under C:\Windows\Setup\Scripts, not C:\Windows\Temp, because
    # cleanup.ps1 empties Temp and runs immediately before Sysprep.
    provisioner "file" {
        source      = "answer-files/sysprep-unattend.xml"
        destination = "C:/Windows/Setup/Scripts/sysprep-unattend.xml"
    }

    provisioner "file" {
        source      = "files/cloudbase-init/"
        destination = "C:/Windows/Temp/cloudbase-init/"
    }

    # TEMPORARY -- paired with the install-config-drive-hide.ps1 provisioner
    # below. Remove both together.
    provisioner "file" {
        source      = "files/config-drive/"
        destination = "C:/Windows/Temp/config-drive/"
    }

    provisioner "file" {
        source      = "files/installers/"
        destination = "C:/Windows/Temp/installers/"
    }

    # elevated_user runs each script as a scheduled task with a full admin token.
    # A plain WinRM network logon cannot drive DISM, AppX provisioning, or Sysprep.
    provisioner "powershell" {
        script            = "scripts/remove-bloat.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }

    provisioner "powershell" {
        script            = "scripts/install-software.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }

    provisioner "powershell" {
        script            = "scripts/configure-windows.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }

    provisioner "windows-restart" {
        restart_timeout = "30m"
    }

    provisioner "powershell" {
        script            = "scripts/install-cloudbase-init.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }

    # TEMPORARY -- hides the cleartext Cloud-Init password from students who open
    # This PC on a clone. A speed bump, not a boundary; the account it hides from
    # is a local Administrator and can undo it. Runs after Cloudbase-Init is
    # installed so the task it registers can key off that service. Remove this
    # and the files/config-drive/ provisioner above to back it out.
    provisioner "powershell" {
        script            = "scripts/install-config-drive-hide.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }

    provisioner "powershell" {
        script            = "scripts/cleanup.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }

    # Must be last. Uses Sysprep /quit rather than /shutdown: the proxmox builder
    # has no shutdown_command hook and powers the VM off itself once provisioning
    # returns, so /shutdown would kill the WinRM session mid-provisioner and fail
    # the build. /quit generalizes and returns, then the builder shuts down cleanly.
    provisioner "powershell" {
        script            = "scripts/sysprep.ps1"
        elevated_user     = var.winrm_username
        elevated_password = var.winrm_password
    }
}
