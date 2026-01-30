############################################
# providers.tf
############################################

# These are normally injected via environment variables:
#   PM_API_URL
#   PM_API_TOKEN_ID
#   PM_API_TOKEN_SECRET
# or as TF_VAR_* equivalents.

provider "proxmox" {
  pm_api_url          = var.pm_api_url
  pm_api_token_id     = var.pm_api_token_id
  pm_api_token_secret = var.pm_api_token_secret

  pm_tls_insecure = var.pm_tls_insecure
}