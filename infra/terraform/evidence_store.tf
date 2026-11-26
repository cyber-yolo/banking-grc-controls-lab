# Evidence store: where hashed evidence runs are archived during the campaign.
#
# Integrity measures in the lab: Entra ID authentication only (no shared keys),
# blob versioning (an overwrite keeps the previous version), soft delete, TLS 1.2,
# no public access. A bank would add a LOCKED time-based immutability policy
# (WORM). It is not used here on purpose: a locked policy prevents deleting the
# account until retention expires, which breaks the teardown and the zero-cost
# rule. Documented in docs/08-evidence-handling.md.

resource "azurerm_storage_account" "evidence" {
  name                            = "st${var.prefix}ev${var.storage_suffix}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  tags                            = local.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_storage_container" "evidence" {
  name                  = "evidence"
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"
}

# The signed-in maintainer may write evidence (az storage blob upload-batch --auth-mode login).
resource "azurerm_role_assignment" "evidence_writer" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}
