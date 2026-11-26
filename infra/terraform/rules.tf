# One scheduled analytics rule per enabled sheet in detections/rules.
# for_each creates one resource per map entry; each.key is "DET-xxx",
# each.value is the decoded YAML sheet.

resource "azurerm_sentinel_alert_rule_scheduled" "rule" {
  for_each = local.enabled_rules

  # The API wants a stable unique name. uuidv5() derives a UUID from a text,
  # so the same rule always gets the same name, with no random provider.
  name                       = uuidv5("url", "${var.prefix}/${each.key}")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  display_name               = "${each.key} ${each.value.name}"
  description                = "${trimspace(each.value.banking_scenario)} ATT&CK: ${join(", ", each.value.attack)}. Source: detections/rules/${each.key}.yaml"
  severity                   = each.value.severity
  enabled                    = true

  # The KQL file is a template: ${name} tokens are replaced from the sheet
  # parameters plus the global internal_domain.
  query = templatefile(
    "${local.rules_dir}/${each.value.query_file}",
    merge({ internal_domain = var.internal_domain }, each.value.parameters)
  )
  query_frequency   = each.value.query_frequency
  query_period      = each.value.query_period
  trigger_operator  = "GreaterThan"
  trigger_threshold = each.value.trigger_threshold

  tactics    = each.value.tactics
  techniques = each.value.techniques # parent IDs only; sub-techniques stay in the sheet

  # One alert per query result row, so each user or IP gets its own alert.
  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      entity_matching_method  = "AllEntities"
      reopen_closed_incidents = false
    }
  }

  dynamic "entity_mapping" {
    for_each = each.value.entities
    content {
      entity_type = entity_mapping.value.entity_type
      field_mapping {
        identifier  = entity_mapping.value.identifier
        column_name = entity_mapping.value.column
      }
    }
  }

  # Sentinel validates the query against the workspace schema at creation:
  # the onboarding must exist first. Terraform infers it from the reference
  # above; depends_on makes the diagnostic settings explicit too.
  depends_on = [
    azurerm_monitor_diagnostic_setting.activity,
    azurerm_monitor_aad_diagnostic_setting.entra,
  ]
}
