# Core of the lab: one resource group, one Log Analytics workspace, Sentinel on top.
# Everything Terraform creates lives in this resource group, except the
# subscription-level policy assignments and budget, and the tenant-level Entra
# objects (diagnostic setting, Conditional Access): see docs/06-lab-setup.md.

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.prefix}-grc"
  location = var.location
  tags     = local.tags

  lifecycle {
    # Fails the plan early if enabled_rules names a rule that has no sheet.
    precondition {
      condition     = length(local.unknown_rules) == 0
      error_message = "enabled_rules contains IDs with no sheet in detections/rules: ${join(", ", local.unknown_rules)}"
    }
  }
}

# The workspace stores the logs (CTL-010). Sentinel is a layer on this workspace.
resource "azurerm_log_analytics_workspace" "lab" {
  name                = "law-${var.prefix}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"        # pay per GB; covered by the Sentinel trial
  retention_in_days   = var.retention_days # CTL-010-A2, see RA-001
  daily_quota_gb      = var.daily_quota_gb # cost guardrail, see docs/07-cost-guardrails.md
  tags                = local.tags
}

# Enabling Sentinel on the workspace. This starts the 31-day free trial clock:
# apply only on day 0 of the plan (docs/05-roadmap.md).
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "lab" {
  workspace_id = azurerm_log_analytics_workspace.lab.id
}
