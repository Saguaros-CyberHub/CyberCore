############################################
# modules/proxmox-vm/variables.tf
############################################

variable "template_key" {
  type        = string
  description = "Name/ID of the Proxmox template to clone from."
}

variable "hostname" {
  type        = string
  description = "Hostname for this VM."
}

variable "role" {
  type        = string
  description = "Logical role (primary, dc, ws, kali, etc.)."
  default     = "primary"
}

variable "context_id" {
  type        = string
  description = "Parent context ID (lane_id, vm_request_id, project_id, etc.)."
}

variable "module_key" {
  type        = string
  description = "Module key (crucible, cyberlabs, forge)."
}

variable "node_name" {
  type        = string
  description = "Proxmox node on which to create the VM."
}

variable "pool" {
  type        = string
  description = "Proxmox pool name."
}

variable "vxlan_id" {
  type        = number
  description = "VXLAN/VLAN tag for this VM."
}

variable "network_bridge" {
  type        = string
  description = "Bridge to connect VM network to."
}

variable "network_tag" {
  type        = number
  description = "Network tag (normally same as vxlan_id)."
}

# Basic sizing defaults; override via tfvars if needed per template/role.
variable "cores" {
  type        = number
  description = "Number of vCPU cores."
  default     = 2
}

variable "memory_mb" {
  type        = number
  description = "RAM in MiB."
  default     = 2048
}

variable "disk_size_gb" {
  type        = number
  description = "Disk size in GiB for the cloned VM."
  default     = 20
}

variable "storage" {
  type        = string
  description = "Proxmox storage to use for the disk."
  default     = "local-lvm"
}

# Cloud-init / IP config — you can customize later.
variable "ipconfig0" {
  type        = string
  description = "Proxmox ipconfig0 string (e.g. 'ip=dhcp' or 'ip=10.0.0.10/24,gw=10.0.0.1')."
  default     = "ip=dhcp"
}

variable "tags" {
  type        = list(string)
  description = "Additional tags/notes for this VM."
  default     = []
}