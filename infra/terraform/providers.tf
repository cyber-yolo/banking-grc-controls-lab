# Providers are the plugins that talk to the APIs.
# Authentication: both reuse the Azure CLI session (`az login`).
# No secret, no service principal, nothing to store.
provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  # The evidence storage account has shared keys disabled (evidence integrity,
  # docs/08-evidence-handling.md). Terraform must then use Entra ID for storage.
  storage_use_azuread = true

  features {
    resource_group {
      # Lab choice: `terraform destroy` also removes resources created by hand
      # or by Sentinel (content hub solutions) inside the lab resource group.
      # In production this stays true to protect against accidental deletion.
      prevent_deletion_if_contains_resources = false
    }
    log_analytics_workspace {
      # Skip the 14-day soft delete: lab data must not survive teardown and the
      # same workspace name must be reusable for a re-run.
      permanently_delete_on_destroy = true
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

# Read-only lookups (no resource created).
data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}
