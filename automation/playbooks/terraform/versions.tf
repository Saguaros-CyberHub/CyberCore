############################################
# versions.tf
############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    proxmox = {
      source  = "telmate/proxmox"
      version = ">= 3.0.0"
    }
  }
}