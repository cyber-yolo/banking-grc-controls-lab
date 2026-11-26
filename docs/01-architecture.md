# Architecture

## Assurance chain

```text
 requirements/*.yaml        controls/sheets/CTL-*.yaml          collectors/items.csv
 REQ-DORA-05  ───────────▶  CTL-001  ──── evidence ─────────▶  EV-001 ConditionalAccessPolicies (Graph)
 REQ-CH-01                  owner, reviewer, tests             EV-002 KqlMfaCoverage (Log Analytics)
 REQ-NIS2-03 ...            assertions CTL-001-A1..A3                    │
                                  │                                      ▼
                                  │                    collectors/Collect-Evidence.ps1 (read-only)
                                  │                    evidence/runs/<UTC>/ *.json + manifest.json (SHA-256)
                                  ▼                                      │
                       tools/evaluate_controls.py  ◀─────────────────────┘
                       PASS / FAIL / NO_EVIDENCE per assertion
                       EFFECTIVE / DESIGN_ONLY / NOT_EFFECTIVE / ... per control
                                  │
             ┌────────────────────┼─────────────────────────┐
             ▼                    ▼                         ▼
 reports/compliance-dashboard.md  reports/control-status.csv  risk/acceptances/RA-xxx.md
 (per domain, per jurisdiction)   (spreadsheet, Power BI)     (human decision on gaps)
```

`docs/traceability-matrix.md` is generated from the same files, so the matrix in the documentation can never drift from the controls that are actually checked (CI fails if it does).

## Lab platform

```text
 Microsoft 365 E5 trial tenant (shared with the DLP lab rebuild)
 ├── Entra ID: users, break-glass accounts, Conditional Access, PIM, access reviews, app registrations, AI agent apps
 ├── Purview: DLP PV-POL-001 (CTL-009), Copilot / Endpoint DLP (CTL-008)
 └── Unified audit log
        │ connectors and diagnostic settings
        ▼
 Azure free subscription, one resource group rg-<prefix>-grc
 ├── Log Analytics workspace (daily cap, 90-day retention) + Microsoft Sentinel (DET-001..013)
 ├── Storage account for evidence (Entra auth only, versioning)
 ├── Azure Policy assignments at subscription scope (CTL-013, tags)
 ├── Defender for Cloud foundational CSPM (free, CTL-015)
 └── Budget alerts
        ▲
        │ az login, Connect-MgGraph (delegated, read-only scopes)
 Maintainer workstation (Windows 11): Terraform, collectors, evaluator, Windows 11 VM for Endpoint DLP (CTL-008)
```

## Why one repository

The detection and response design (Sentinel rules, playbooks) was first drafted as a separate lab. It is now a module of this repository: a detection is evidence that a detective control operates (CTL-011), and each rule sheet names the controls it supports (`controls:` key). See [`decisions/ADR-001-single-repository.md`](decisions/ADR-001-single-repository.md).

## Repository map

```text
requirements/      regulation, paraphrased, with references and confidence
controls/          control sheets and catalogue
collectors/        read-only evidence collection (PowerShell) and item list
queries/           KQL for operating effectiveness
tools/             validator, evaluator, report generator
tests/             evaluator unit tests and synthetic fixtures
reports/           generated dashboard (committed after review)
risk/              risk register and risk acceptances
scenarios/         banking threat scenarios
ai-governance/     AI system inventory
third-parties/     register of information, exit plans
incident-response/ classification worksheet, reporting clocks
detections/        Sentinel analytics rules (YAML sheet + KQL)
playbooks/         SOAR designs
testing/           test strategy, test matrices, tabletops
infra/terraform/   lab infrastructure
evidence-public/   redacted extracts only
docs/              design documents and decision records
```
