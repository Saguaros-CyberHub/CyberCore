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

    cores    = var.cores
    sockets  = 1
    memory   = var.memory
    cpu_type = "host"

    # CD-ROMs must sit on a bus WinPE has an inbox driver for. Windows Setup has no
    # virtio-scsi driver until autounattend.xml injects it, so anything Setup must
    # read itself (the install media, the virtio media, the answer file) goes on
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

    disks {
        type         = "scsi"
        disk_size    = var.disk_size
        storage_pool = var.disk_storage_pool
        cache_mode   = "writeback"
        io_thread    = true
    }

    scsi_controller = "virtio-scsi-single"

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
