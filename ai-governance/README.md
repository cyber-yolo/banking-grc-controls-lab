# AI governance

## AI system inventory

`ai-system-inventory.csv` lists every AI system the lab bank uses or plans to use, whether or not it has an identity in Entra ID. CTL-007 checks it against the app registrations tagged `ai-agent`.

| Column | Meaning |
|---|---|
| `ai_act_role` | `provider` or `deployer` (AI Act terms). A bank using a vendor model is usually a deployer |
| `ai_act_risk_class` | `prohibited`, `high`, `limited`, `minimal`. Creditworthiness of natural persons is high-risk (Annex III point 5(b)); fraud detection is excluded from that point |
| `entra_app_name` | Display name of the app registration, empty if the system has no Entra identity |
| `human_oversight` | Who can stop or override the system, and how |
| `status` | `planned`, `live`, `retired`, `out-of-scope` |

AI-002 is deliberately an out-of-scope example: it shows how a high-risk system is recorded even when the lab cannot run it.

## Why identities are the control point

An AI agent that reads mail, files or CRM data acts through an identity: an app registration, a managed identity or, in newer Microsoft offerings, an agent identity. Inventory, least privilege, credential hygiene and logging of that identity are the parts a bank can evidence today with standard tooling (CTL-006, CTL-007, DET-010, DET-013), whatever the model behind it.

See [`docs/09-ai-and-non-human-identities.md`](../docs/09-ai-and-non-human-identities.md).
