# Lab setup and teardown runbook

Status: draft, not executed. Each step gets a tick, a UTC time and a note in the run log (`evidence/run-log.md`, git-ignored).

## 0. Before any clock starts

- [ ] Workstation: Terraform 1.9+, Azure CLI with the log-analytics extension, Git, Python 3.10+, PowerShell 7, Microsoft Graph PowerShell SDK, ExchangeOnlineManagement.
- [ ] `python tools/validate_repo.py`, `python -m pytest -q`, `terraform validate` pass.
- [ ] Offer terms re-read and `07-cost-guardrails.md` updated with the date of the check.
- [ ] Calendar: day 0, day 21 (final export starts), day 25 (teardown), day 28 (last check).

## 1. Tenant (shared with the DLP lab rebuild)

- [ ] M365 E5 trial tenant: 1 admin, 2 users, mailboxes. Tenant name and domain recorded locally only.
- [ ] Data location shown in the admin center recorded in `third-parties/register-of-information.csv` (TP-001, TP-002).
- [ ] Unified audit log on.
- [ ] Break-glass accounts `bg-01`, `bg-02` created, cloud-only, permanent Global Administrator, passwords stored offline. Their object IDs go in `terraform.tfvars` only.
- [ ] MFA registered for user1, user2 and admin.

## 2. Azure subscription

- [ ] Azure free account linked to the lab tenant. Spending limit ON. **Never** upgrade.
- [ ] `az login --tenant <tenant-id>`; `az account show` shows the lab subscription.

## 3. Terraform apply (day 0)

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # fill locally, git-ignored
terraform init
terraform plan -out tfplan                       # read it: only "to add"
terraform apply tfplan
```

Created: resource group, workspace, Sentinel onboarding, activity diagnostic setting, budget, policy assignments (CTL-013, tags), custom policy definition, evidence storage account and container, role assignment. Outside the resource group (remember at teardown): subscription policy assignments, budget, and later the Entra diagnostic setting and Conditional Access policies.

## 4. Connectors and first evidence run

| Connector | Method | Check |
|---|---|---|
| Entra ID logs | `connect_entra_logs = true`, apply | `SigninLogs \| take 5` |
| Microsoft 365 | Content hub, Exchange and SharePoint | `OfficeActivity \| take 5` |
| Defender XDR | Content hub, incidents and alerts only | `SecurityIncident \| take 5` |
| Azure Activity | Terraform | `AzureActivity \| take 5` |

Then the baseline:

```powershell
./collectors/Collect-Evidence.ps1 -ResourceGroup rg-bgcl-grc -Workspace law-bgcl -WorkspaceId <workspace-customer-id>
python tools/evaluate_controls.py --run evidence/runs/<run> --out reports/results-<run>.json
python tools/build_report.py --results reports/results-<run>.json
```

Admin consent for the collector's read-only Graph scopes is given once, by the lab admin, at the first `Connect-MgGraph`.

## 5. Identity controls (Phase 2)

1. Conditional Access: `manage_conditional_access = true`, state report-only, apply. After 2 to 3 days of sign-in logs without unexpected impact, `conditional_access_state = "enabled"`, apply. If Terraform cannot create the policies (permission), create them in the portal with the same names.
2. PIM (CTL-003), in Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles > Settings, for each tier-0 role (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security Administrator):
   - Activation: maximum 4 hours; require MFA (or an authentication context) and a justification.
   - Global Administrator and Privileged Role Administrator: require approval, approver user2 (the lab "IAM lead"). The approver must not be the requester.
   - Assignment: do not allow permanent eligible assignment, expire after 180 days (365 maximum).
   - Then make admin eligible (not active) for Security Administrator and Global Administrator, end date 180 days ahead.
   - Check: run the collector for `RoleManagementPolicies` and the evaluator; CTL-003-A4 to A7 must PASS.
3. Access review on privileged roles (CTL-005): Identity governance > Access reviews, scope "Microsoft Entra roles", eligible and active assignments, quarterly, 7 days, reviewer user2, justification required, auto-apply results, "If reviewers don't respond: remove access".
4. Defender for Cloud (CTL-015): applied by Terraform (`defender.tf`). Two days later, open Defender for Cloud > Recommendations and Regulatory compliance; run the collector for `SecureScores`, `PolicyAssignments`, `DefenderPlans`, `RegulatoryComplianceStandards`, `SecurityAssessments`; update `posture/remediation-register.csv` with the High and Medium findings actually seen (TC-329).
5. App registrations for the tests: `app-grc-collector`, `app-agent-kyc-summary` (tag `ai-agent`), and the deliberately non-compliant `app-test-orphan`, `app-agent-shadow` (deleted after TC-311 and TC-313).

## 6. Rules, playbooks, tabletop

Enable rules in batches once their tables have data (`enabled_rules`). Playbooks per `playbooks/README.md`. Tabletop TT-001 per `testing/tabletop/TT-001.md`.

## 7. Teardown (Phase 6)

- [ ] Final collector run, evaluated, archived (zip with manifest) outside the repo and uploaded to the evidence container **before** destroy, then downloaded again and hash-checked.
- [ ] Redacted extracts in `evidence-public/`, reviewed.
- [ ] TC-240 (see `detections/` and `testing/detection-test-matrix.csv`).
- [ ] `terraform destroy` reviewed and applied.
- [ ] Portal: resource group gone; no policy assignment named CTL-013 or grc-* left; budget gone.
- [ ] Entra: diagnostic setting gone; Conditional Access CTL-001 and CTL-002 removed or disabled; test app registrations deleted; access review deleted.
- [ ] Cost Management checked 48 hours later.
- [ ] Local `terraform.tfstate*`, `tfplan`, `terraform.tfvars` archived outside the repo or deleted.
