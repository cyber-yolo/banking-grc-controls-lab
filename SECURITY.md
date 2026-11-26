# Security policy

## Scope

This repository contains documentation, a requirements and controls catalogue, evidence collectors, detection rules, Terraform code and redacted lab evidence. It must never contain real personal data, banking data, secrets, Terraform state, raw evidence, or identifiers of a tenant or subscription.

## Reporting

If you find a secret, an identifier or any content that could identify a real organisation or person:

1. Do **not** open a public issue quoting it.
2. Use GitHub private vulnerability reporting (Security tab > Report a vulnerability).
3. The maintainer removes the content, rewrites history if needed (`git filter-repo`), rotates or deletes anything exposed and records the incident without reproducing the data.

Target response: acknowledgement within 5 working days.

## Preventive controls

| Control | Where |
|---|---|
| Secret scanning and push protection | GitHub repository settings |
| gitleaks on every push and PR | `.github/workflows/ci.yml` |
| Leak scan: GUIDs, Azure resource paths, non-example e-mail addresses, Terraform state | `tools/validate_repo.py` |
| Collectors read-only (Graph `*.Read.*` scopes, GET calls, `Get-*` cmdlets) | `collectors/` |
| Evaluator masks user principal names in every result | `tools/evaluate_controls.py` |
| State, plans, tfvars, raw evidence git-ignored | `.gitignore` |
| PR security checklist | `.github/pull_request_template.md` |
| Branch protection on `main` (PR required, CI green) | GitHub rulesets, set by the maintainer |

## Out of scope

Detection evasion techniques, offensive tooling and attacks against anything other than the maintainer's own lab accounts are out of scope and will not be accepted.
