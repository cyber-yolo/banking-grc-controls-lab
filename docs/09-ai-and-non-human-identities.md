# AI agents and non-human identities

## Why this is a control domain of its own

In a bank's tenant, non-human identities (app registrations, service principals, managed identities, automation accounts) usually outnumber staff accounts, are rarely reviewed, and often hold broad, long-lived credentials. AI agents add to them: an agent that summarises KYC documents or drafts client replies acts through an identity with access to mail, files or CRM data.

Supervisors do not need an AI-specific rule to expect control here. DORA asks to identify ICT assets and accounts (Art. 8) and to limit access to what is needed (Art. 9(4)(c)); the RTS on ICT risk management has identity management and access control articles (Art. 20 and 21 of Delegated Regulation (EU) 2024/1774); FINMA Circular 2023/1 expects identity and access management within ICT risk management. The AI Act adds deployer duties for high-risk systems (human oversight, monitoring, keeping logs), and FINMA guidance on AI (08/2024, TO VERIFY) expects an inventory and risk classification.

## What the lab checks

| Question | Control | Evidence | Assertion |
|---|---|---|---|
| Does every app have an accountable owner? | CTL-006 | Graph `applications` with owners | CTL-006-A1 |
| Are secrets short-lived? | CTL-006 | `passwordCredentials` dates | CTL-006-A2 (180 days) |
| Does any app request dangerous application permissions without a risk acceptance? | CTL-006 | `requiredResourceAccess` joined with Graph app roles | CTL-006-A3 |
| Is every AI agent identity inventoried, and every inventoried agent real? | CTL-007 | Tag `ai-agent` vs `ai-governance/ai-system-inventory.csv` | CTL-007-A1 |
| Is each AI system classified with an owner and human oversight? | CTL-007 | Inventory | CTL-007-A2 |
| Does any agent hold high-risk permissions? | CTL-007 | as CTL-006 | CTL-007-A3 |
| Is a new credential on an app detected? | CTL-006, CTL-007 | AuditLogs | DET-013 |
| Is consent to a mail or file app detected? | CTL-006 | AuditLogs | DET-010 |
| Can client data reach an AI assistant? | CTL-008 | Purview DLP | manual, RA-003 |

## Known limits

- Microsoft Entra Agent ID and Copilot Studio agent identities were in preview at design time. Whether they appear as service principals with a stable marker is TO VERIFY; the `ai-agent` tag works for any app registration and is the lab convention.
- Requested permissions are checked, not granted ones (one call per service principal, later improvement).
- Managed identities have no secrets but can hold roles: covered only through Azure role assignments, not yet checked.
- The high-risk permission list is a lab choice in `tools/evaluate_controls.py`, to review.
