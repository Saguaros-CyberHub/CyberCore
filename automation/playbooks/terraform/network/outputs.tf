############################################
# modules/network/outputs.tf
############################################

output "bridge" {
  value       = local.bridge_name
  description = "Bridge name to attach VMs to."
}

output "tag" {
  value       = local.network_tag
  description = "VLAN/VXLAN tag associated with this deployment."
}