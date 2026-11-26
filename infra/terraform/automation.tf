# Automation rules.
#
# Phase 1 to 4: only AR-900, created at the start of Phase 5 for TC-240.
# Phase 4 adds AR-001 to AR-003 with their playbooks (playbooks/README.md).

resource "azurerm_sentinel_automation_rule" "teardown" {
  count = var.enable_teardown_rule && contains(keys(local.enabled_rules), "DET-009") ? 1 : 0

  name                       = uuidv5("url", "${var.prefix}/AR-900")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  display_name               = "AR-900 Close planned teardown incidents (TC-240)"
  order                      = 1
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  # Condition in the API's own JSON format: incident raised by DET-009.
  # Shape TO VERIFY against the provider documentation at build time.
  condition_json = jsonencode([{
    conditionType = "Property"
    conditionProperties = {
      propertyName   = "IncidentRelatedAnalyticRuleIds"
      operator       = "Contains"
      propertyValues = [azurerm_sentinel_alert_rule_scheduled.rule["DET-009"].id]
    }
  }])

  action_incident {
    order                  = 1
    status                 = "Closed"
    classification         = "BenignPositive_SuspiciousButExpected"
    classification_comment = "Planned teardown of the lab (TC-240)."
  }
}
