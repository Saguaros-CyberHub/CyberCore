############################################
# modules/proxmox-vm/outputs.tf
############################################

output "vmid" {
  value       = proxmox_vm_qemu.vm.vmid
  description = "Proxmox VMID of the created VM."
}

output "hostname" {
  value       = proxmox_vm_qemu.vm.name
  description = "Hostname of the VM."
}

output "node_name" {
  value       = proxmox_vm_qemu.vm.target_node
  description = "Node on which this VM is running."
}

# This depends on your provider version; many expose 'ipconfig0' only.
# If your version exposes IP addresses in attributes, wire them here.
output "ip_addresses" {
  value       = [proxmox_vm_qemu.vm.ipconfig0]
  description = "IP configuration of the VM (raw ipconfig0 for now)."
}