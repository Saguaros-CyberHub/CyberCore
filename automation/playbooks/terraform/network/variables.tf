############################################
# modules/network/variables.tf
############################################

variable "vxlan_id" {
  type        = number
  description = "VXLAN/VNI tag for this deployment."
}

variable "module_key" {
  type        = string
  description = "Module key (crucible, cyberlabs, forge)."
}

variable "context_id" {
  type        = string
  description = "Per-deployment unique identifier."
}

# If you later decide to create SDN/VNet resources via another provider
# or scripts, you can add variables here.
variable "base_bridge" {
  type        = string
  description = "Base Proxmox bridge to use for overlays."
  default     = "vmbr0"
}