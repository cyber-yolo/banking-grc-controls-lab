# Policy as code (CTL-013 and tagging).
#
# Built-in definitions are looked up by display name, so no definition ID is
# written in the repository. If Microsoft renames a definition, the plan fails
# with "not found": update the display name here.

data "azurerm_policy_definition" "allowed_locations" {
  display_name = "Allowed locations"
}

data "azurerm_policy_definition" "allowed_locations_rg" {
  display_name = "Allowed locations for resource groups"
}

# CTL-013: resources may only be created in Swiss or EU regions (effect deny).
resource "azurerm_subscription_policy_assignment" "ctl013_locations" {
  name                 = "ctl-013-allowed-locations"
  display_name         = "CTL-013 Allowed locations"
  description          = "Data residency: Swiss and EU regions only. Source: controls/sheets/CTL-013.yaml"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.allowed_locations.id
  enforce              = true

  parameters = jsonencode({
    listOfAllowedLocations = { value = var.allowed_locations }
  })
}

resource "azurerm_subscription_policy_assignment" "ctl013_locations_rg" {
  name                 = "ctl-013-allowed-locations-rg"
  display_name         = "CTL-013 Allowed locations for resource groups"
  description          = "Data residency for resource groups. Source: controls/sheets/CTL-013.yaml"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.allowed_locations_rg.id
  enforce              = true

  parameters = jsonencode({
    listOfAllowedLocations = { value = var.allowed_locations }
  })
}

# A custom definition, written here, to show the full policy-as-code cycle:
# every resource must carry the owner and expires_on tags (audit only).
resource "azurerm_policy_definition" "require_lab_tags" {
  name         = "grc-require-owner-expires-tags"
  display_name = "GRC lab: require owner and expires_on tags"
  description  = "Audits resources without the owner or expires_on tag. Supports the teardown review."
  policy_type  = "Custom"
  mode         = "Indexed"

  policy_rule = jsonencode({
    if = {
      anyOf = [
        { field = "tags['owner']", exists = "false" },
        { field = "tags['expires_on']", exists = "false" },
      ]
    }
    then = { effect = "audit" }
  })
}

resource "azurerm_subscription_policy_assignment" "require_lab_tags" {
  name                 = "grc-require-lab-tags"
  display_name         = "GRC lab: require owner and expires_on tags"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_definition.require_lab_tags.id
}
