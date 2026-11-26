# Budget alerts on the whole subscription. A budget sends e-mails; it never
# stops resources. The hard stops are the free account spending limit and the
# workspace daily cap. Support of budgets on the free account offer: TO VERIFY.
resource "azurerm_consumption_budget_subscription" "lab" {
  name            = "budget-${var.prefix}"
  subscription_id = data.azurerm_subscription.current.id
  amount          = var.budget_amount
  time_grain      = "Monthly"

  time_period {
    start_date = var.budget_start_date
  }

  # One notification block per threshold on actual spend.
  # `dynamic` repeats the block for each value of the list.
  dynamic "notification" {
    for_each = [50, 80, 100]
    content {
      enabled        = true
      threshold      = notification.value
      operator       = "GreaterThanOrEqualTo"
      threshold_type = "Actual"
      contact_emails = var.budget_contact_emails
    }
  }

  # Early warning on forecast spend.
  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThan"
    threshold_type = "Forecasted"
    contact_emails = var.budget_contact_emails
  }
}
