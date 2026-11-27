# Defender for Cloud (CTL-015): foundational CSPM only, which is free.
#
# Foundational CSPM (secure score, Microsoft cloud security benchmark,
# recommendations) is on for every subscription once the Microsoft.Security
# resource provider is registered; azurerm registers it by default. Defender for
# Cloud also assigns the benchmark initiative ("ASC Default") by itself: it is
# NOT managed here, to avoid two owners for the same assignment. CTL-015-A2
# checks that it exists.
#
# What Terraform does here is a cost guardrail: every plan listed in
# var.defender_free_plans is pinned to the Free tier. If someone enables a paid
# plan in the portal, the next `terraform plan` shows the drift and `apply`
# turns it off again. There is deliberately no variable to choose "Standard".

resource "azurerm_security_center_subscription_pricing" "free" {
  for_each = var.manage_defender_plans ? toset(var.defender_free_plans) : toset([])

  tier          = "Free"
  resource_type = each.value
}

# Security contact: Defender for Cloud e-mails high-severity alerts here. Also
# clears the recommendation "Subscriptions should have a contact email address
# for security issues". Uses the first budget address (a lab mailbox).
resource "azurerm_security_center_contact" "lab" {
  count = var.manage_security_contact ? 1 : 0

  name                = "default"
  email               = var.budget_contact_emails[0]
  alert_notifications = true
  alerts_to_admins    = true
}
