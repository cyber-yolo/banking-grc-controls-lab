# Playbooks (SOAR)

Response module of the lab. PB-003 (human approval before containment) is also the lab's illustration of human oversight of automation (REQ-AIA-04).

Status: **design only**. Logic App definitions are built in Phase 4, exported as ARM JSON into `playbooks/<PB-ID>/azuredeploy.json`, and deployed by Terraform.

## Principles

1. **Managed identity only.** No client secret, no stored password. Each playbook has a system-assigned identity with the minimum role.
2. **Human in the loop for containment.** A playbook may enrich and notify on its own. Any action on an account (revoke sessions, disable) needs an analyst approval, as a bank SOC would require.
3. **Lab accounts only.** PB-003 refuses to act on the lab admin account (allow-list of target UPNs in a parameter).
4. **Every run is evidence.** Run history is exported before teardown (`docs/08-evidence-handling.md`).

## Catalogue

| ID | Name | Trigger | Actions | Identity and permissions | Test |
|---|---|---|---|---|---|
| PB-001 | Enrich and comment | Microsoft Sentinel incident (via AR-001) | Read incident entities; for each account, query `SigninLogs` (last 24 h: sign-ins, IPs, failures) and `SecurityAlert` (DLP alerts last 7 days); write a summary comment on the incident; add tag `enriched` | Microsoft Sentinel Responder on the workspace resource group; Log Analytics Reader on the workspace | TC-231 |
| PB-002 | Notify the SOC mailbox | Incident with severity High (via AR-002) | Send an e-mail to the lab SOC mailbox with title, severity, entities, incident link; add tag `notified` | Sentinel Responder; Office 365 Outlook connection signed in with a lab mailbox (the only stored connection, documented as a limit) | TC-232 |
| PB-003 | Contain account with approval | Manual run from the incident, or AR-003 for DET-002, DET-003, DET-005, DET-010 | Send an approval e-mail (Approve or Reject) to the SOC mailbox; on Approve, revoke the user's sign-in sessions (Microsoft Graph `revokeSignInSessions`), comment and set incident status Active with tag `contained`; on Reject or timeout (1 h), comment only | Sentinel Responder; Graph application permission `User.RevokeSessions.All` granted to the managed identity (TO VERIFY: least-privilege permission name) | TC-233 |

Why revoke sessions and not disable the account: revocation is reversible within minutes and keeps the account usable after a password reset; disabling an account in a bank has HR and business continuity impact and belongs to a human decision. Disabling can be added as a second approved step later.

## Permissions to grant (Phase 4)

| Principal | Role or permission | Scope | Why |
|---|---|---|---|
| Azure Security Insights (Sentinel service principal) | Microsoft Sentinel Automation Contributor | Resource group holding the playbooks | Lets automation rules run playbooks |
| PB-00x managed identity | Microsoft Sentinel Responder | Workspace resource group | Comment, tag, change incident status |
| PB-001 managed identity | Log Analytics Reader | Workspace | Run enrichment queries |
| PB-003 managed identity | Graph `User.RevokeSessions.All` (application) | Tenant | Revoke sessions. Granted by the admin with a script, documented and removed at teardown |

## Build method (Phase 4)

1. Build PB-001 in the Logic Apps designer (Consumption plan, region of the workspace), trigger "Microsoft Sentinel incident", connection authenticated with the managed identity.
2. Export the template, replace every ID by a parameter, save as `playbooks/PB-001/azuredeploy.json`.
3. Deploy it from Terraform with `azurerm_resource_group_template_deployment` and remove the hand-built copy.
4. Run `tools/validate_repo.py`: no GUID or subscription path may remain in the template.

This order (portal first, then code) is deliberate: Logic App workflow JSON is hard to write by hand, and the export gives a correct starting point.
