## Summary

Closes #

## Type

- [ ] Requirement (REQ) added or corrected
- [ ] Control (CTL), assertion or evidence item
- [ ] Detection rule (DET), playbook (PB)
- [ ] Risk (RSK) or risk acceptance (RA)
- [ ] Terraform
- [ ] Evidence run or test result
- [ ] Docs, CI

## Traceability

- Requirement(s):
- Control(s):
- Test case(s):
- Evidence run and manifest (if a result is claimed):

## Regulatory references

- [ ] Every new or changed reference was read on the official text, or is marked TO VERIFY
- [ ] No article, paragraph or margin number written from memory without TO VERIFY

## Security checklist (mandatory)

- [ ] No real personal, customer, employee or banking data
- [ ] No secret, token, password, certificate or connection string
- [ ] No tenant ID, subscription ID, workspace ID, object ID, resource path, lab domain or personal e-mail (placeholders only)
- [ ] No `terraform.tfstate`, plan file, `terraform.tfvars` or raw `evidence/` file
- [ ] Screenshots and extracts redacted per `docs/08-evidence-handling.md`
- [ ] Untested items are labelled as such
- [ ] `python tools/validate_repo.py`, `python -m pytest -q` and `python tools/build_report.py --check` pass; `terraform fmt -check` and `terraform validate` pass if `infra/` changed
