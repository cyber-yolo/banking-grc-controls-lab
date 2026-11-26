# Which Terraform and which provider versions this code is written for.
# "~> 4.0" means: any 4.x release, never 5.0 (a major version can break code).
# The exact versions picked at `terraform init` are recorded in
# .terraform.lock.hcl, which IS committed so every run uses the same builds.
terraform {
  required_version = ">= 1.9.0" # 1.9+: a validation may refer to another variable

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # Entra ID objects (Conditional Access policies, CTL-001 and CTL-002).
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}
