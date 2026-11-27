# Values printed after apply. Marked sensitive when they are identifiers, so
# that they do not end up in a screenshot by accident (`terraform output -raw`
# still shows them on request).

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.lab.name
}

output "workspace_customer_id" {
  description = "Workspace ID for the collector (-WorkspaceId) and az monitor log-analytics query."
  value       = azurerm_log_analytics_workspace.lab.workspace_id
  sensitive   = true
}

output "evidence_storage_account" {
  value = azurerm_storage_account.evidence.name
}

output "deployed_rules" {
  value = sort(keys(azurerm_sentinel_alert_rule_scheduled.rule))
}

output "defender_plans_pinned_free" {
  description = "Defender for Cloud plans kept on the Free tier by Terraform (CTL-015-A3)."
  value       = sort(keys(azurerm_security_center_subscription_pricing.free))
}
