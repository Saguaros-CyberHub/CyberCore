############################################
# main.tf  (generic CyberHub VM deployer)
############################################

locals {
  # Decode VM specs from JSON
  vm_specs = try(jsondecode(var.vm_specs_json), [])

  # Tag base for all resources
  tag_base = "${var.module_key}:${var.context_id}"

  # Handy map for for_each
  vm_map = {
    for vm in local.vm_specs :
    vm.hostname => vm
  }
}

############################################
# Network / VXLAN (shared)
############################################

module "network" {
  # was "./modules/network"
  source = "./network"

  vxlan_id   = var.vxlan_id
  module_key = var.module_key
  context_id = var.context_id
}

############################################
# VM deployment(s)
############################################

module "vm" {
  # was "./modules/proxmox-vm"
  source = "./proxmox-vm"

  # One module instance per VM spec
  for_each = local.vm_map

  template_key = each.value.template_key
  hostname     = each.value.hostname
  role         = try(each.value.role, "primary")

  # Shared inputs
  context_id = var.context_id
  module_key = var.module_key

  node_name = try(each.value.proxmox_node, var.default_proxmox_node)
  pool      = try(each.value.pool, var.default_vm_pool)

  vxlan_id       = var.vxlan_id
  # match outputs you define in network module
  network_bridge = module.network.bridge_name
  network_tag    = module.network.vxlan_tag

  tags = concat(
    try(each.value.tags, []),
    [
      local.tag_base,
      "module:${var.module_key}",
      "context:${var.context_id}",
      "role:${try(each.value.role, "primary")}"
    ]
  )
}

############################################
# Outputs
############################################

output "vxlan_id" {
  value       = var.vxlan_id
  description = "VXLAN/VNI for this deployment."
}

output "context_id" {
  value       = var.context_id
  description = "Unique ID for this deployment (lane, lab request, or project)."
}

output "vm_details" {
  description = "Per-VM outputs from the proxmox-vm module."
  value = {
    for k, m in module.vm :
    k => {
      vmid     = try(m.vmid, null)
      hostname = try(m.hostname, null)
      node     = try(m.node_name, null)
      ips      = try(m.ip_addresses, [])
    }
  }
}