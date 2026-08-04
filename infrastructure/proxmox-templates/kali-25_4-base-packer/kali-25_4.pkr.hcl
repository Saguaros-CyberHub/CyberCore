packer {
    required_plugins {
        proxmox = {
        version = "~> 1.2"
        source  = "github.com/hashicorp/proxmox"
        }
    }
}

locals {
    # Served to the debian-installer over Packer's built-in HTTP server. Rendered
    # rather than static so the account the preseed creates and the account
    # Packer authenticates with can never drift apart -- same trick the Windows
    # template plays with autounattend.xml.
    preseed = templatefile("${path.root}/http/preseed.cfg.pkrtpl", {
        username        = var.ssh_username
        password        = var.ssh_password
        hostname        = "kali"
        locale          = var.locale
        keyboard_layout = var.keyboard_layout
        timezone        = var.timezone
        mirror_host     = var.kali_mirror_host
        mirror_directory = var.kali_mirror_directory
        apt_proxy       = var.apt_proxy
    })
}

source "proxmox-iso" "kali_2025_4" {
    # Proxmox API connection
    proxmox_url = var.proxmox_url
    username    = var.proxmox_username
    token       = var.proxmox_token
    node        = var.proxmox_node

    insecure_skip_tls_verify = true

    # Final template identity
    vm_id                = var.vm_id
    vm_name              = var.template_name
    template_name        = var.template_name
    template_description = "Kali Linux 2025.4 template (xfce + xrdp) built automatically with Packer"
    tags                 = "packer;kali;cloud-init"

    # VM hardware
    machine  = "q35"
    bios     = "seabios"
    os       = "l26"

    cpu_type = "host"
    sockets = 1
    cores   = var.cores
    memory  = var.memory

    # No VGA at all -- the Proxmox console is the serial port, matching what
    # bake-kali-template.sh produces. scripts/configure-system.sh points the
    # installed system's GRUB and getty at ttyS0 so `qm terminal` and the noVNC
    # console still work on a clone. The installer is driven the same way via
    # console=ttyS0 in the boot command.
    vga {
        type   = "serial0"
    }

    serials = ["socket"]

    # Storage controller
    scsi_controller = "virtio-scsi-single"

    # Guest integration. Packer resolves the build VM's IP through the agent,
    # which the preseed installs and enables via pkgsel/include.
    qemu_agent = true

    # Cloud-init drive added to the final template. Proxmox defaults Linux
    # guests to citype=nocloud, which cloud-init reads natively, so unlike the
    # Windows template there is no post-build `qm set --citype` step.
    cloud_init              = true
    cloud_init_storage_pool = var.disk_storage_pool
    cloud_init_disk_type    = "ide"

    # Kali installer ISO. On SCSI rather than IDE so it cannot collide with the
    # cloud-init drive for an IDE slot; debian-installer has virtio-scsi built
    # into its kernel, so the media is readable from the first second.
    boot_iso {
        type         = "scsi"
        iso_file     = var.kali_iso
        iso_checksum = var.kali_iso_checksum
        unmount      = true
    }

    # Primary network interface
    network_adapters {
        model    = "virtio"
        bridge   = var.network_bridge
        vlan_tag = var.vlan_tag
        firewall = false
    }

    # Primary system disk
    disks {
        type         = "scsi"
        disk_size    = var.disk_size
        storage_pool = var.disk_storage_pool
        format       = "raw"
        discard      = true
        io_thread    = true
    }

    # Preseed delivery. Packer serves this from the machine running the build,
    # so that machine has to be reachable from vlan_tag -- see the README.
    http_content = {
        "/preseed.cfg" = local.preseed
    }
    http_bind_address = var.http_bind_address
    http_port_min     = var.http_port_min
    http_port_max     = var.http_port_max

    # Kali's BIOS boot path is isolinux. <esc> at the menu drops to a `boot:`
    # prompt where a label plus kernel arguments can be typed blind, which is
    # what makes this work with no VGA output to look at.
    #
    # `auto=true priority=critical` suppresses every question the preseed does
    # not answer instead of hanging on it, and everything after `---` is passed
    # through to the installed system's kernel command line.
    boot_wait = "10s"
    boot_command = [
        "<esc><wait>",
        "install ",
        "auto=true ",
        "priority=critical ",
        "preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
        "netcfg/choose_interface=auto ",
        "console-setup/ask_detect=false ",
        "--- console=ttyS0,115200n8 ",
        "<enter>"
    ]

    communicator = "ssh"
    ssh_username = var.ssh_username
    ssh_password = var.ssh_password
    # The base install runs unattended for 10-25 min depending on mirror speed
    # before sshd exists to connect to.
    ssh_timeout             = "60m"
    ssh_handshake_attempts  = 100
}

build {
    name = "kali-2025.4-proxmox"

    sources = [
        "source.proxmox-iso.kali_2025_4"
    ]

    # Config fragments are staged in /tmp first because the file provisioner
    # runs as the unprivileged build user; the scripts sudo them into place.
    provisioner "shell" {
        inline = ["mkdir -p /tmp/cybercore"]
    }

    provisioner "file" {
        source      = "files/"
        destination = "/tmp/cybercore/"
    }

    # NOPASSWD sudo comes from the preseed's late_command. cleanup.sh revokes it
    # before the template is sealed.
    provisioner "shell" {
        execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
        environment_vars = [
            "DEBIAN_FRONTEND=noninteractive",
            "KALI_TOOLSET=${var.kali_toolset}",
            "BUILD_USER=${var.ssh_username}",
            "APT_PROXY=${var.apt_proxy}",
            "TEMPLATE_NAME=${var.template_name}",
            "TEMPLATE_VMID=${var.vm_id}"
        ]
        scripts = [
            "scripts/install-desktop.sh",
            "scripts/configure-xrdp.sh",
            "scripts/configure-cloud-init.sh",
            "scripts/configure-system.sh"
        ]
        # kali-linux-large can run past an hour on a slow mirror.
        timeout = "90m"
    }

    # Fails the build rather than sealing a template with the defects that have
    # actually shipped before (truncated libjpeg, xrdp not listening). Runs
    # before cleanup so its findings are based on the live, fully-configured
    # system.
    provisioner "shell" {
        execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
        environment_vars = [
            "BUILD_USER=${var.ssh_username}",
            "TEMPLATE_NAME=${var.template_name}",
            "TEMPLATE_VMID=${var.vm_id}",
            "KALI_TOOLSET=${var.kali_toolset}"
        ]
        script = "scripts/verify.sh"
    }

    # Must be last: it removes the build user's sudo rights, the SSH host keys
    # and the machine-id, so nothing may run over this SSH session afterwards.
    provisioner "shell" {
        execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
        environment_vars = [
            "BUILD_USER=${var.ssh_username}"
        ]
        script = "scripts/cleanup.sh"
        # cloud-init clean and fstrim both tear down state this session depends
        # on; a dropped connection here means success, not failure.
        expect_disconnect = true
    }
}
