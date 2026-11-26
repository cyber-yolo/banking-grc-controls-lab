# Data connectors for Microsoft 365 sources.
#
# Default path (manage_connectors_with_terraform = false): install the
# "Microsoft 365" and "Microsoft Defender XDR" solutions from the Sentinel
# content hub and switch the connectors on in the portal (docs/06-lab-setup.md).
# Microsoft now ships connectors through content hub; the Terraform resources
# below call the older connector API. They are kept as an option and tested in
# Phase 1: if they fail or behave differently from the portal, the portal wins
# and the result is recorded in TC-200.

resource "azurerm_sentinel_data_connector_office_365" "m365" {
  count                      = var.manage_connectors_with_terraform ? 1 : 0
  name                       = "dc-${var.prefix}-office365"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  exchange_enabled           = true
  sharepoint_enabled         = true
  teams_enabled              = false # no Teams rule in this lab
}

# Defender XDR incidents and alerts, including Purview DLP alerts (DET-001).
# Raw advanced hunting tables are NOT streamed (billed ingestion).
resource "azurerm_sentinel_data_connector_microsoft_threat_protection" "xdr" {
  count                      = var.manage_connectors_with_terraform ? 1 : 0
  name                       = "dc-${var.prefix}-defender-xdr"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
}
