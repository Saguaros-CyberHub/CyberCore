############################################
# modules/network/main.tf
############################################

locals {
  # You can get fancy later, e.g. mapping vxlan_id into VLAN ranges, etc.
  bridge_name = var.base_bridge

  # For now, just reuse vxlan_id as the tag.
  network_tag = var.vxlan_id
}

# If you ever want to manage SDN constructs via some other provider or
# external script, you'd add resources here. For now it's just naming.