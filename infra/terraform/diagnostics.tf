# Diagnostic settings send platform logs to the workspace.

# Azure control plane (who created or deleted what in the subscription) -> AzureActivity.
# Feeds DET-009.
resource "azurerm_monitor_diagnostic_setting" "activity" {
  name                       = "diag-${var.prefix}-activity"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}

# Entra ID sign-ins and directory changes -> SigninLogs, AuditLogs.
# Feeds DET-004, DET-005, DET-006, DET-010, DET-011.
# Off by default: it needs Entra ID P1/P2 (E5 trial) and a directory role, and it
# is a tenant-level setting that survives the resource group. `count = 0` means
# "do not create"; `count = 1` means "create one".
resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  count                      = var.connect_entra_logs ? 1 : 0
  name                       = "diag-${var.prefix}-entra"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category = "SignInLogs"
  }
  enabled_log {
    category = "AuditLogs"
  }
  # NonInteractiveUserSignInLogs left out on purpose: high volume, no rule uses it.
}
