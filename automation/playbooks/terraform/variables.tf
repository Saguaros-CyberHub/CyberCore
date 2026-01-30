############################################
# variables.tf (top-level Terraform)
############################################

# Which CyberHub module is calling this deployment.
# Valid values today: "crucible", "cyberlabs", "forge"
variable "module_key" {
  type        = string
  description = "Logical CyberHub module using this deployment."

  validation {
    condition     = contains(["crucible", "cyberlabs", "forge"], var.module_key)
    error_message = "module_key must be one of: crucible, cyberlabs, forge."
  }
}

# Unique ID for this deployment:
# - Crucible: lane_id
# - CyberLabs: vm_request_id
# - Forge: project_id / sandbox_id
variable "context_id" {
  type        = string
  description = "Per-deployment unique identifier (lane, lab request, or project)."

  validation {
    condition     = length(trimspace(var.context_id)) > 0
    error_message = "context_id must be a non-empty string (UUID or similar)."
  }
}

# Deterministic VXLAN/VNI for this deployment.
# This is passed directly into the network module.
variable "vxlan_id" {
  type        = number
  description = "VXLAN/VNI number for this deployment."

  validation {
    condition     = var.vxlan_id >= 1 && var.vxlan_id <= 16777215
    error_message = "vxlan_id must be between 1 and 16777215."
  }
}

# JSON-encoded list of VM specs coming from n8n.
# Example:
# [
#   {
#     "template_key": "metasploitable2-template",
#     "hostname": "metasploitable2-basic.local",
#     "role": "primary",
#     "tags": ["single_vm"]
#   }
# ]
variable "vm_specs_json" {
  type        = string
  description = "JSON-encoded list of VM specs (template_key, hostname, role, tags, etc.)."
  default     = "[]"
}

# Default Proxmox node and pool; can be overridden per-VM in vm_specs_json.
variable "default_proxmox_node" {
  type        = string
  description = "Default Proxmox node to deploy on (used if vm spec does not override)."
  default     = "pve1"
}

variable "default_vm_pool" {
  type        = string
  description = "Default Proxmox pool to attach VMs to (used if vm spec does not override)."
  default     = "cyberhub"
}

# Optional: how long this deployment should live (minutes).
# Used by n8n to schedule destroys / cleanups, not by Terraform itself.
variable "runtime_minutes" {
  type        = number
  description = "Max runtime in minutes for this deployment."
  default     = 180
}

############################################
# Proxmox provider auth vars
# (normally injected from environment in tf-run.sh)
############################################

variable "pm_api_url" {
  type        = string
  description = "Proxmox API URL (e.g., https://pve1.example.com:8006/api2/json)."
}

variable "pm_api_token_id" {
  type        = string
  description = "Proxmox API token ID (e.g., 'terraform@pve!cyberhub')."
}

variable "pm_api_token_secret" {
  type        = string
  description = "Proxmox API token secret."
  sensitive   = true
}

variable "pm_tls_insecure" {
  type        = bool
  description = "Allow insecure TLS to Proxmox API."
  default     = true
}