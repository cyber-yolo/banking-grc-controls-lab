# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer, pre-1.0 minor versions map to roadmap milestones.

## [Unreleased]

### Added

- Privileged access management deepened (CTL-003): PIM role settings collected from Graph (`RoleManagementPolicies`) and checked by six new assertions: MFA and justification on activation, 4-hour maximum, approval for Global Administrator and Privileged Role Administrator, eligibility that expires, at most four Global Administrators, no tier-0 assignment outside PIM (new KQL `queries/CTL-003-direct-assignments.kql`).
- Access review (CTL-005): three new assertions on auto-apply and default deny, independent reviewer, and a completed instance in the last 92 days.
- Cloud security posture management (CTL-015): Microsoft cloud security benchmark assignment, Defender plans all on the Free tier, benchmark assessed in regulatory compliance, and recommendation remediation tracked to verified closure in `posture/remediation-register.csv` with service levels by severity. Five new assertions.
- Terraform `defender.tf`: Defender for Cloud plans pinned to Free (cost guardrail), security contact.
- Requirement REQ-RMF-07 (RTS 2024/1774 Art. 11, secure configuration baselines), TO VERIFY.
- `validate_repo.py` checks the remediation register; nine new evaluator tests.

- Regulatory scope: EU base (DORA and RTS on ICT risk management, AI Act, NIS2 as cross-reference, EBA guidelines, GDPR), Luxembourg (financial sector law, CSSF circulars) and Switzerland (FINMA circulars and guidance, Banking Act, FADP). 56 requirements, all references TO VERIFY.
- Control catalogue CTL-001 to CTL-016 with machine-checked assertions, evidence items and design and effectiveness tests (TC-301 to TC-332, NOT RUN).
- Evidence collectors (PowerShell, read-only) and evaluator (Python) with synthetic fixtures and unit tests.
- Traceability matrix and compliance dashboard generator.
- Risk register, three risk acceptances, AI system inventory, reduced register of information.
- Banking threat scenarios SCN-G01 to SCN-G05.
- Detection and response module taken over from the unpublished Sentinel lab design: DET-001 to DET-011, new DET-012 and DET-013, playbook designs PB-001 to PB-003, each rule linked to the controls it evidences.
- Terraform (validated, not applied): workspace with daily cap, Sentinel, diagnostic settings, budget, analytics rules from YAML, Azure Policy (CTL-013 and tagging), evidence storage, optional Conditional Access (CTL-001, CTL-002).
- CI: YAML and Markdown lint, catalogue and leak checks, evaluator tests, traceability check, Terraform fmt and validate, gitleaks.
