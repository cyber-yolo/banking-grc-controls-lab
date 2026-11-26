# banking-grc-controls-lab

> **Independent lab. Synthetic data and lab accounts only.** Not affiliated with any bank, financial institution, supervisor, employer or client. Regulatory references are paraphrased for traceability, are **not legal advice**, and stay marked TO VERIFY until checked against the official text. Every identity, mailbox and document is fictitious.

**GRC engineering for banks in Switzerland and Luxembourg / EU**: regulatory requirements mapped to concrete Microsoft controls, with evidence collected from the platforms themselves, evaluated by code, and reported with its limits.

## The problem this lab works on

A bank in scope of DORA, or supervised by FINMA, has to show that its controls exist **and work**. In practice that proof is often a spreadsheet filled by hand once a year. This repository treats control assurance as an engineering problem:

```text
Regulation -> Requirement -> Control -> Evidence -> Assertion -> Result -> Gap or risk acceptance -> Dashboard
 (DORA,FINMA)  (REQ-xxx)    (CTL-xxx)  (EV-xxx,      (CTL-xxx-An)  (PASS,     (RA-xxx, decided by    (per domain,
                                        collected)                  FAIL,      an accountable role)  per jurisdiction)
                                                                    NO_EVIDENCE)
```

Automation does the collecting and the checking. It does not decide whether a gap is acceptable, whether an incident is major, or whether a reference reads the way it is mapped: those decisions are recorded, with a role, a date and an expiry.

## Regulatory scope

| Layer | Instruments | File |
|---|---|---|
| EU base | DORA (Regulation (EU) 2022/2554) and the RTS on ICT risk management (Delegated Regulation (EU) 2024/1774); AI Act (Regulation (EU) 2024/1689 as amended in 2026); EBA guidelines; GDPR; NIS2 as cross-reference only (DORA is the sector-specific act for banks) | `requirements/eu-*.yaml` |
| Luxembourg | Law of 5 April 1993 on the financial sector (professional secrecy); CSSF Circulars 20/750, 22/806, 25/882, 12/552 as amended | `requirements/lu-cssf.yaml` |
| Switzerland | FINMA Circular 2023/1 (operational risks and resilience), FINMA Circular 2018/3 (outsourcing), FINMA guidance on cyber attack reporting and on AI; Banking Act Art. 47; Federal Act on Data Protection and its ordinance | `requirements/ch-finma.yaml` |

56 requirements: 22 in scope, 25 partly, 9 explicitly out with a reason. See [`docs/02-regulatory-scope.md`](docs/02-regulatory-scope.md) for applicability (which rule binds which entity) and the verification protocol.

## Controls

16 controls in 9 domains, each with an owner role, a reviewer role, mapped requirements, evidence items, machine-checked assertions and two tests (design and operating effectiveness).

| Domain | Controls |
|---|---|
| Identity and access | CTL-001 MFA for all users, CTL-002 legacy authentication blocked |
| Privileged access | CTL-003 just-in-time access (PIM), CTL-004 emergency access accounts, CTL-005 periodic access review |
| Non-human and AI agent identities | CTL-006 app and service principal hygiene, CTL-007 AI agent inventory and least privilege |
| Data protection | CTL-008 client data kept out of AI assistants, CTL-009 client identifiers blocked in external e-mail |
| Logging and detection | CTL-010 logs centralised and retained, CTL-011 detection coverage of banking scenarios |
| Incident management | CTL-012 classification and reporting readiness (DORA, FINMA, GDPR, FADP clocks) |
| Data residency | CTL-013 Swiss and EU regions only (Azure Policy) |
| Third-party risk | CTL-014 register of information |
| Cloud posture and governance | CTL-015 secure score baseline, CTL-016 framework governance and risk acceptances |

Full matrix: [`docs/traceability-matrix.md`](docs/traceability-matrix.md) (generated). Current status: [`reports/compliance-dashboard.md`](reports/compliance-dashboard.md) (generated).

## What is in it

| Layer | Content | Folder |
|---|---|---|
| Regulation | Paraphrased requirements with reference, confidence and lab scope | `requirements/` |
| Controls | Control sheets, catalogue, test matrix | `controls/`, `testing/` |
| Evidence | Read-only collectors (Graph, Azure, Purview), KQL effectiveness queries | `collectors/`, `queries/` |
| Assurance | Evaluator with 32 assertions, unit tests on synthetic fixtures, dashboard and matrix generator | `tools/`, `tests/`, `reports/` |
| Risk | Risk register, risk acceptances, banking threat scenarios | `risk/`, `scenarios/` |
| AI governance | AI system inventory, agent identity controls | `ai-governance/` |
| Third parties | Reduced register of information, exit plan outlines | `third-parties/` |
| Incident readiness | Classification worksheet, reporting clocks, tabletop | `incident-response/`, `testing/tabletop/` |
| Detection and response | 13 Sentinel analytics rules mapped to MITRE ATT&CK and to controls, 3 playbook designs | `detections/`, `playbooks/` |
| Infrastructure as code | Terraform: workspace, Sentinel, diagnostics, budget, rules, Azure Policy, evidence store, optional Conditional Access | `infra/terraform/` |

## Status

Nothing is claimed as tested until evidence exists.

| Area | Status |
|---|---|
| Requirements | Draft, `verified_on: null` in every file: all references TO VERIFY |
| Controls and assertions | Written; evaluator unit-tested on synthetic data only |
| Collectors | Written, **never run** against a tenant |
| Terraform | `terraform validate` passes; **never applied** |
| Detection rules | Written, **not run** |
| Control tests TC-301 to TC-332, detection tests TC-200 to TC-240 | NOT RUN |
| Lab tenant and Azure subscription | Not created |

## Sister repository

[banking-dlp-controls-lab](https://github.com/cyber-yolo/banking-dlp-controls-lab): Purview DLP for banking data (13 tests run on a previous tenant). Its policy PV-POL-001 becomes control CTL-009 here, and its planned Endpoint DLP tests feed CTL-008.

## Quick start (offline, no tenant needed)

```bash
pip install -r requirements-dev.txt
python tools/validate_repo.py          # catalogue consistency and leak scan
python -m pytest -q                    # evaluator on synthetic evidence
python tools/evaluate_controls.py --run tests/fixtures/fail   # see what failing controls look like
python tools/build_report.py           # regenerate matrix and dashboard

cd infra/terraform
terraform init -backend=false && terraform validate
```

Lab deployment: [`docs/06-lab-setup.md`](docs/06-lab-setup.md). New to Terraform: [`infra/terraform/README.md`](infra/terraform/README.md).

## Non-negotiable rules

1. No real customer, employee, account or document data. Ever.
2. No secrets, tokens, tenant IDs, subscription IDs, object IDs, workspace IDs, lab domain or internal URLs in git. Placeholders only: `<tenant-id>`, `<lab-domain>`, `<subscription-id>`.
3. No Terraform state, plan files, `terraform.tfvars` or raw evidence in git.
4. No regulatory reference written from memory without TO VERIFY. No claim of compliance: the lab shows how assurance is built, not that anyone complies.
5. Collectors are read-only. Attack simulation stays at the level needed to produce a log line on the lab's own accounts.

## Licence

Code: MIT. Documentation: CC BY 4.0. See [`LICENSE`](LICENSE).
