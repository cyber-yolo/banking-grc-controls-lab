# Cost guardrails

Objective: zero out-of-pocket cost. Figures collected at design time (November 2026) are **TO VERIFY** on the official pages on the day the lab starts. Record the date of the check here.

| Item | Free offer used | Main risk | Guardrail |
|---|---|---|---|
| Azure subscription | Free account: credit for 30 days, spending limit on | Upgrading removes the protection | Never upgrade; check "spending limit: on" at day 0 |
| Sentinel and Log Analytics | Sentinel free trial, 31 days on a new workspace, daily volume included (TO VERIFY) | Ingestion after day 31 | Daily cap `daily_quota_gb` (0.5 GB); teardown before day 30 |
| Retention | 90 days included with Sentinel (TO VERIFY) | Longer retention billed | `retention_days` maximum 90 (RA-001) |
| Azure Policy | Free for Azure resources (TO VERIFY) | None expected | |
| Defender for Cloud | Foundational CSPM free; paid plans not enabled | Enabling a Defender plan by mistake | No plan resource in Terraform; check the plans page at day 0 and day 21 |
| Evidence storage | A few MB, LRS, cents at most, within credit | Forgotten account after teardown | In the resource group, removed by destroy |
| Logic Apps | Pay per action, cents | Loops, recurrence | Incident-triggered only |
| Entra ID P2 features (PIM, access reviews) | Included in the E5 trial (TO VERIFY) | None | |
| Microsoft 365 Copilot | Not used (paid add-on) | | RA-003 |
| M365 E5 trial | 30 days | Converts to paid with a payment method and auto-renew | No payment method; auto-renew off |

## Controls in code

1. Workspace `daily_quota_gb`: hard daily ingestion cap.
2. Subscription budget with alerts at 50, 80, 100 % and forecast. A budget alerts, it does not stop spending.
3. One resource group, removed by `terraform destroy`.
4. `expires_on` tag on every resource, audited by the custom policy in `policy.tf`.

## If the Azure free account is not available

The free account is one per person. Options: Azure for Students if eligible; pay-as-you-go with budget 5 and cap 0.1 GB/day (small but not zero: needs an explicit decision); or stop at Phase 0 and publish the design, the verified references and the offline-testable controls (CTL-007-A2, CTL-014, CTL-016).
