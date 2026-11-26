# Assumptions and limits

## Assumptions

| ID | Assumption | Checked by | If wrong |
|---|---|---|---|
| A-01 | The Azure free account is available to the maintainer | Phase 1 | See `07-cost-guardrails.md` |
| A-02 | The E5 trial includes Entra ID P2 (PIM, access reviews) and Purview DLP | Phase 1 | CTL-003 and CTL-005 become manual or BLOCKED |
| A-03 | Graph endpoints and `$expand` options in `collectors/items.csv` work as written | First collector run | Fix `items.csv`, note in CHANGELOG |
| A-04 | Security & Compliance PowerShell returns the DLP fields the evaluator reads (`Mode`, `ExchangeLocation`, `AccessScope`, `ContentContainsSensitiveInformation`) | TC-317 | Adjust CTL-009 assertions |
| A-05 | PIM activation justification is in `AuditLogs.ResultReason` | TC-306 | Adjust `queries/CTL-003-pim-activations.kql` |
| A-06 | Terraform under an Azure CLI sign-in can create Conditional Access policies | Phase 2 | Portal fallback, same names |
| A-07 | Microsoft 365 Copilot is not available in the trial | Phase 1 | If available, CTL-008 becomes testable, RA-003 closed |

## Limits

- **Not legal advice, not a compliance claim.** The lab shows how assurance is built and evidenced, on a fictitious bank.
- Scale: three users, about 30 days. Operating effectiveness over a year, sampling of populations and segregation of duties are simulated.
- One vendor stack (Microsoft). Concentration risk is recorded in the register, not mitigated.
- Endpoint and network telemetry are out of scope except the Windows 11 VM used for Endpoint DLP.
- References not yet verified (`verified_on: null` everywhere at v0.1).
