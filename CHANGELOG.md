# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer, pre-1.0 minor versions map to roadmap milestones.

## [Unreleased]

### Added

- Regulatory scope: EU base (DORA and RTS on ICT risk management, AI Act, NIS2 as cross-reference, EBA guidelines, GDPR), Luxembourg (financial sector law, CSSF circulars) and Switzerland (FINMA circulars and guidance, Banking Act, FADP). 56 requirements, all references TO VERIFY.
- Control catalogue CTL-001 to CTL-016 with machine-checked assertions, evidence items and design and effectiveness tests (TC-301 to TC-332, NOT RUN).
- Evidence collectors (PowerShell, read-only) and evaluator (Python) with synthetic fixtures and unit tests.
- Traceability matrix and compliance dashboard generator.
- Risk register, three risk acceptances, AI system inventory, reduced register of information.
- Banking threat scenarios SCN-G01 to SCN-G05.
- Detection and response module taken over from the unpublished Sentinel lab design: DET-001 to DET-011, new DET-012 and DET-013, playbook designs PB-001 to PB-003, each rule linked to the controls it evidences.
- Terraform (validated, not applied): workspace with daily cap, Sentinel, diagnostic settings, budget, analytics rules from YAML, Azure Policy (CTL-013 and tagging), evidence storage, optional Conditional Access (CTL-001, CTL-002).
- CI: YAML and Markdown lint, catalogue and leak checks, evaluator tests, traceability check, Terraform fmt and validate, gitleaks.
