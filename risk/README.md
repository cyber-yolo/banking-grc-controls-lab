# Risk register and risk acceptances

`risk-register.csv` links each risk to the scenarios it comes from and the controls that reduce it. Ratings are qualitative (Low, Medium, High) and are **lab judgements** for illustration, not a bank's risk appetite.

A **risk acceptance** (`acceptances/RA-xxx.md`) is written when a control is knowingly weaker than the requirement it maps to. It records the gap, why it is accepted, the compensating measures, who decides, and when it expires. This is the part of GRC that tooling does not decide: someone accountable has to.

| ID | Gap | Expires |
|---|---|---|
| [RA-001](acceptances/RA-001.md) | Log retention 90 days | End of lab campaign |
| [RA-002](acceptances/RA-002.md) | MFA not phishing-resistant | End of lab campaign |
| [RA-003](acceptances/RA-003.md) | No Microsoft 365 Copilot licence: AI data protection only partly testable | End of lab campaign |
