############################################
# modules/proxmox-vm/main.tf
############################################

resource "proxmox_vm_qemu" "vm" {
  name        = var.hostname
  target_node = var.node_name

  # Assumes you have a template in Proxmox whose name matches template_key.
  # You can swap this for a numeric VMID if you prefer.
  clone = var.template_key

  pool   = var.pool
  tags   = join(";", var.tags)      # telmate/proxmox uses semicolon-separated tags
  onboot = true

  os_type = "cloud-init"
  agent   = 1

  sockets = 1
  cores   = var.cores
  memory  = var.memory_mb

  scsihw = "virtio-scsi-pci"

  disk {
    slot    = 0
    size    = "${var.disk_size_gb}G"
    type    = "scsi"
    storage = var.storage
  }

  network {
    model  = "virtio"
    bridge = var.network_bridge
    tag    = var.network_tag
  }

  ipconfig0 = var.ipconfig0

  # Optional: if you re-run apply with changed module code, don't
  # constantly recreate the VM just because of network/disk drifts.
  lifecycle {
    ignore_changes = [
      disk,
      network,
    ]
  }
}