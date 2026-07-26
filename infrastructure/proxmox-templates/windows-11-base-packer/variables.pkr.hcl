variable "proxmox_url" {
  type        = string
  description = "Proxmox API endpoint, e.g. https://pve.example.com:8006/api2/json"
}

variable "proxmox_username" {
  type        = string
  description = "API token ID, e.g. packer@pve!packer-token"
}

variable "proxmox_token" {
  type      = string
  sensitive = true
}

variable "proxmox_node" {
  type        = string
  description = "Node the build VM is created on."
}

variable "windows_iso" {
  type        = string
  description = "Proxmox volume ID of the Windows 11 ISO, e.g. local:iso/Win11_25H2_English_x64.iso"
}

variable "virtio_iso" {
  type        = string
  description = "Proxmox volume ID of the virtio-win ISO. Must have virtio-win-guest-tools.exe at its root."
}

variable "iso_storage_pool" {
  type        = string
  default     = "local"
  description = "Storage pool holding ISO content. The generated answer-file ISO is uploaded here."
}

variable "disk_storage_pool" {
  type    = string
  default = "local-lvm"
}

variable "vm_id" {
  type    = number
  default = 9000
}

variable "template_name" {
  type    = string
  default = "windows-11-cloudbase-template"
}

variable "disk_size" {
  type    = string
  default = "80G"
}

variable "cores" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 8192
}

variable "network_bridge" {
  type    = string
  default = "vmbr0"
}

variable "vlan_tag" {
  type        = string
  default     = "40"
  description = "Build-time VLAN. Needs outbound HTTPS unless installers are pre-staged in files/installers/."
}

# Must match the /IMAGE/NAME of an edition present in the ISO's install.wim.
# Check with: dism /Get-WimInfo /WimFile:D:\sources\install.wim
variable "windows_image_name" {
  type    = string
  default = "Windows 11 Pro"
}

# Generic edition-selection key. Not a licence -- it only stops Setup asking.
# Must correspond to windows_image_name.
variable "windows_product_key" {
  type    = string
  default = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
}

variable "timezone" {
  type    = string
  default = "UTC"
}

variable "winrm_username" {
  type        = string
  default     = "packer"
  description = "Local admin created by autounattend.xml, removed by Sysprep. Rendered into the answer file so it cannot drift."
}

variable "winrm_password" {
  type      = string
  sensitive = true
}
