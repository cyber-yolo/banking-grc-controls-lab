# Inputs. Values are set in terraform.tfvars (git-ignored), copied from
# terraform.tfvars.example. Validation blocks catch mistakes before any API call.

variable "subscription_id" {
  description = "Azure subscription ID of the lab (free account)."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant ID of the lab."
  type        = string
}

variable "prefix" {
  description = "Short prefix used in every resource name."
  type        = string
  default     = "bgcl"

  validation {
    condition     = can(regex("^[a-z0-9]{3,8}$", var.prefix))
    error_message = "prefix: 3 to 8 lower-case letters or digits."
  }
}

variable "location" {
  description = "Azure region. Switzerland North fits the CH/LU banking story; West Europe is the fallback."
  type        = string
  default     = "switzerlandnorth"

  validation {
    condition     = contains(["switzerlandnorth", "westeurope", "francecentral", "northeurope"], var.location)
    error_message = "location: use a European region listed in variables.tf."
  }
}

variable "owner" {
  description = "Owner tag (a role, not a personal e-mail)."
  type        = string
  default     = "lab-maintainer"
}

variable "expires_on" {
  description = "Planned teardown date, YYYY-MM-DD. Written as a tag on every resource."
  type        = string

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}$", var.expires_on))
    error_message = "expires_on: format YYYY-MM-DD."
  }
}

variable "daily_quota_gb" {
  description = "Hard daily ingestion cap of the workspace, in GB. Ingestion stops for the day when reached."
  type        = number
  default     = 0.5

  validation {
    condition     = var.daily_quota_gb > 0 && var.daily_quota_gb <= 1
    error_message = "daily_quota_gb: between 0 and 1 GB for this lab (cost guardrail)."
  }
}

variable "retention_days" {
  description = "Workspace retention. Up to 90 days is included with Sentinel (TO VERIFY)."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_days >= 30 && var.retention_days <= 90
    error_message = "retention_days: 30 to 90."
  }
}

variable "budget_amount" {
  description = "Monthly budget amount, in the subscription currency. Alerts only, it does not stop spending."
  type        = number
  default     = 5
}

variable "budget_start_date" {
  description = "Budget start, first day of the current month, RFC 3339 (2026-12-01T00:00:00Z)."
  type        = string

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-01T00:00:00Z$", var.budget_start_date))
    error_message = "budget_start_date: first day of a month, e.g. 2026-12-01T00:00:00Z."
  }
}

variable "budget_contact_emails" {
  description = "Addresses that receive budget alerts (a lab mailbox)."
  type        = list(string)

  validation {
    condition     = length(var.budget_contact_emails) > 0
    error_message = "budget_contact_emails: at least one address."
  }
}

variable "connect_entra_logs" {
  description = "Export Entra ID SignInLogs and AuditLogs to the workspace. Needs Entra ID P1/P2 and Global or Security Administrator."
  type        = bool
  default     = false
}

variable "manage_connectors_with_terraform" {
  description = "Create the Office 365 and Defender XDR connectors from Terraform instead of the portal (see connectors.tf)."
  type        = bool
  default     = false
}

variable "internal_domain" {
  description = "Lab e-mail domain, used by DET-002 to tell internal from external forwarding."
  type        = string
}

variable "enabled_rules" {
  description = "Analytics rules to deploy, by ID (DET-xxx). Add a rule only once its table has data."
  type        = list(string)
  default     = []
}

variable "enable_teardown_rule" {
  description = "Create AR-900 (auto-close DET-009 incidents). Phase 5 only, for TC-240."
  type        = bool
  default     = false
}

variable "allowed_locations" {
  description = "CTL-013: Azure regions where resources may be created."
  type        = list(string)
  default     = ["switzerlandnorth", "switzerlandwest", "westeurope", "northeurope", "francecentral", "germanywestcentral"]

  validation {
    condition     = contains(var.allowed_locations, var.location)
    error_message = "allowed_locations must contain var.location, or the lab's own resources would be denied."
  }
}

variable "storage_suffix" {
  description = "4 to 8 lower-case letters or digits making the evidence storage account name globally unique."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{4,8}$", var.storage_suffix))
    error_message = "storage_suffix: 4 to 8 lower-case letters or digits."
  }
}

variable "manage_conditional_access" {
  description = "Create the CTL-001 and CTL-002 Conditional Access policies from Terraform (see identity.tf)."
  type        = bool
  default     = false
}

variable "conditional_access_state" {
  description = "State of the Conditional Access policies: report-only first, then enabled."
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], var.conditional_access_state)
    error_message = "conditional_access_state: enabled, disabled or enabledForReportingButNotEnforced."
  }
}

variable "break_glass_object_ids" {
  description = "Object IDs of the two break-glass accounts (CTL-004), excluded from Conditional Access. Set in terraform.tfvars only."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.break_glass_object_ids) <= 2
    error_message = "break_glass_object_ids: at most two accounts (CTL-001-A2)."
  }
}

variable "manage_defender_plans" {
  description = "CTL-015: pin the Defender for Cloud plans in defender_free_plans to the Free tier (cost guardrail)."
  type        = bool
  default     = true
}

variable "defender_free_plans" {
  description = "Defender for Cloud plans pinned to Free. CloudPosture Free is foundational CSPM."
  type        = list(string)
  default     = ["CloudPosture", "VirtualMachines", "StorageAccounts", "KeyVaults", "Arm", "AppServices", "SqlServers", "Containers"]

  validation {
    condition     = contains(var.defender_free_plans, "CloudPosture")
    error_message = "defender_free_plans must contain CloudPosture (foundational CSPM, CTL-015-A3)."
  }

  validation {
    condition = alltrue([for p in var.defender_free_plans : contains([
      "AI", "Api", "AppServices", "Arm", "CloudPosture", "ContainerRegistry", "Containers", "CosmosDbs", "Dns",
      "KeyVaults", "KubernetesService", "OpenSourceRelationalDatabases", "SqlServers", "SqlServerVirtualMachines",
      "StorageAccounts", "VirtualMachines",
    ], p)])
    error_message = "defender_free_plans: unknown plan name (see the list in variables.tf)."
  }
}

variable "manage_security_contact" {
  description = "CTL-015: set the Defender for Cloud security contact to the first budget address."
  type        = bool
  default     = true
}
