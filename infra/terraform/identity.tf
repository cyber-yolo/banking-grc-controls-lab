# Conditional Access policies for CTL-001 and CTL-002.
#
# Off by default (manage_conditional_access = false): a wrong Conditional
# Access policy can lock every account out of the tenant. Before switching on:
#   1. Create the two break-glass accounts by hand (CTL-004) and put their
#      object IDs in terraform.tfvars (git-ignored).
#   2. Start with conditional_access_state = "enabledForReportingButNotEnforced"
#      (report-only), check the sign-in logs for a few days, then "enabled".
# Creating these policies needs the Conditional Access Administrator role, and
# the Azure CLI sign-in may lack the Graph permission to do it: TO VERIFY at
# Phase 1. Fallback: create them in the portal with the same names and settings.

resource "azuread_conditional_access_policy" "ctl001_mfa" {
  count        = var.manage_conditional_access ? 1 : 0
  display_name = "CTL-001 Require MFA for all users"
  state        = var.conditional_access_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

resource "azuread_conditional_access_policy" "ctl002_legacy" {
  count        = var.manage_conditional_access ? 1 : 0
  display_name = "CTL-002 Block legacy authentication"
  state        = var.conditional_access_state

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}
