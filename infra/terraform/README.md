# Terraform

Status: written, `terraform validate` passes (azurerm 4.x, azuread 3.x), **never applied**.

New to Terraform? Read the five-minute model below, then the files in the order given.

## Five-minute model

- You **describe** the resources you want in `.tf` files. You do not write the steps to create them.
- `terraform plan` compares the description with what exists (recorded in the **state** file) and prints what it would add, change or destroy. Nothing is changed.
- `terraform apply` does what the plan says, after you type `yes` (or applies a saved plan file).
- `terraform destroy` removes everything recorded in the state. This is the teardown of the lab.
- The **providers** (`azurerm` for Azure, `azuread` for Entra ID) are the plugins that translate the description into API calls.

## Files, in reading order

| File | What it does |
|---|---|
| `versions.tf` | Terraform and provider versions |
| `providers.tf` | Azure and Entra login (reuses `az login`), lab-specific provider settings |
| `backend.tf` | Where the state lives: local, git-ignored. Remote backend shown as an example |
| `variables.tf` | Inputs with validation (cost guardrails are enforced here) |
| `terraform.tfvars.example` | Template of your values. Copy to `terraform.tfvars`, never commit it |
| `locals.tf` | Tags, and loading of the rule sheets from `detections/rules/` |
| `main.tf` | Resource group, Log Analytics workspace (daily cap), Sentinel onboarding |
| `defender.tf` | Defender for Cloud: plans pinned to Free (foundational CSPM only, CTL-015), security contact |
| `policy.tf` | Azure Policy: CTL-013 allowed locations (built-in, looked up by name), custom tag policy |
| `evidence_store.tf` | Storage account and container for evidence runs, no shared keys, versioning |
| `identity.tf` | Optional Conditional Access policies CTL-001 and CTL-002, report-only first |
| `diagnostics.tf` | Azure activity log and Entra ID logs sent to the workspace |
| `budget.tf` | Subscription budget with e-mail alerts |
| `connectors.tf` | Optional Microsoft 365 and Defender XDR connectors (portal by default) |
| `rules.tf` | One analytics rule per enabled sheet, built with `for_each` |
| `automation.tf` | AR-900 teardown automation rule (Phase 5) |
| `outputs.tf` | Names printed after apply |

## Commands

```bash
az login --tenant <tenant-id>
az account set --subscription <subscription-id>

terraform init                 # downloads the provider, writes .terraform.lock.hcl (commit it)
terraform fmt -recursive       # formats the code
terraform validate             # checks syntax and types, offline
terraform plan -out tfplan     # read it: only "to add" on the first run
terraform apply tfplan
terraform destroy              # teardown, read the plan before typing yes
```

## Design choices

| Choice | Why | Alternative for a bank |
|---|---|---|
| Local state | One person, one lab, no extra storage resource to pay or forget | Remote backend in Azure Storage with locking |
| Azure CLI authentication | No secret to create or leak | Workload identity federation from CI |
| Rules read from YAML | One source of truth reviewed in pull requests; portal never edited by hand | Same, plus a CI deployment job |
| Connectors in the portal by default | Content hub is Microsoft's current path; Terraform connector resources use an older API | Content hub solution deployment by API |
| `prevent_deletion_if_contains_resources = false` | Teardown must remove everything | `true` |
| No module | Fewer concepts to learn for a single lab | Modules per workspace or per tenant |
| Built-in policies looked up by display name | No definition ID in the repository | Same, or pinned IDs in a private repo |
| No locked immutability on evidence | Teardown must stay possible | Locked WORM retention |
| Conditional Access off by default, report-only first | A wrong policy can lock out the tenant | Change process with a pilot group |
| Defender plans pinned to Free, no "Standard" option in the code | Zero cost; drift to a paid plan shows in `plan` | Plans chosen per workload, Defender CSPM paid plan for attack paths |
| PIM role settings not in Terraform | No azuread 3.x resource for directory role policies found (TO VERIFY); portal or Graph | Graph-based pipeline or a provider resource if one exists |

## Known points to verify in Phase 0 and 1

- Block and argument names in provider 4.x (`incident`, `event_grouping`, `condition_json`): `terraform validate` will say.
- Whether the free account offer supports subscription budgets.
- Entra diagnostic setting needs a directory role on top of the subscription Owner role.
- Creating Conditional Access policies with an Azure CLI sign-in (Graph permission of the CLI): see `identity.tf`.
- Built-in policy display names "Allowed locations" and "Allowed locations for resource groups" still current.
- Defender plan updates can conflict when applied in parallel (HTTP 409). If it happens, re-run with `terraform apply -parallelism=1`.
- `azurerm_security_center_contact` argument names in provider 4.x (`name`, `alert_notifications`, `alerts_to_admins`).
