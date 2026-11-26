# Where Terraform keeps its state (the list of what it created, with IDs).
#
# Lab choice: LOCAL state, the default. The file terraform.tfstate is written in
# this folder, is git-ignored, and is archived outside the repo at teardown.
# It contains subscription, tenant and resource IDs: never commit it.
#
# A team or a bank would use a remote backend (state in an Azure Storage
# account with locking and versioning). Example, not enabled:
#
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "rg-tfstate"
#     storage_account_name = "<storage-account>"
#     container_name       = "tfstate"
#     key                  = "banking-grc-lab.tfstate"
#     use_azuread_auth     = true
#   }
# }
