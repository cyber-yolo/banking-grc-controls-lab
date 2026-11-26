# Detections

Detection and response module of the lab. A detection is evidence that a detective control operates: each sheet lists the controls it supports (`controls:`), and CTL-011 checks that every banking scenario in `scenarios/scenarios.yaml` has at least one deployed rule with a passed positive test.

Each analytics rule is two files in `rules/`:

- `DET-xxx.yaml`: the rule sheet (scenario, ATT&CK mapping, thresholds, entities, tests, false positives, response).
- `DET-xxx.kql`: the query. `${name}` tokens are filled by Terraform `templatefile()` from the sheet's `parameters` and from the global `internal_domain`. To paste a query into the portal by hand, replace the tokens first.

Terraform reads the sheets directly (`infra/terraform/rules.tf`): the YAML is the single source of truth, the portal is never edited by hand. `catalog.csv` is a flat index checked against the sheets by `tools/validate_repo.py`.

## Coverage

| Rule | Banking scenario | ATT&CK | Table | Severity | Controls |
|---|---|---|---|---|---|
| DET-001 | Series of DLP alerts on client banking data by one user (link with PV-POL-001) | T1048 | SecurityAlert | High | CTL-009, CTL-011 |
| DET-002 | Mailbox forwarding to an external domain | T1114.003 | OfficeActivity | Medium | CTL-009, CTL-011 |
| DET-003 | Inbox rule hiding payment or fraud e-mails (BEC payment fraud) | T1564.008 | OfficeActivity | High | CTL-011 |
| DET-004 | Password spray on staff accounts | T1110.003 | SigninLogs | Medium | CTL-001, CTL-011 |
| DET-005 | Successful sign-in after failures | T1110.001, T1078.004 | SigninLogs | High | CTL-001, CTL-011 |
| DET-006 | Privileged Entra ID role assigned | T1098.003 | AuditLogs | High | CTL-003, CTL-011 |
| DET-007 | Mass download of a client library | T1530, T1213.002 | OfficeActivity | Medium | CTL-009, CTL-011 |
| DET-008 | Anonymous or guest link on a client site | T1537 | OfficeActivity | Medium | CTL-009, CTL-011 |
| DET-009 | Log pipeline or SIEM rule deleted | T1562.008 | AzureActivity | High | CTL-010, CTL-011 |
| DET-010 | Consent to an app with mail or file permissions | T1528 | AuditLogs | Medium | CTL-006, CTL-011 |
| DET-011 | MFA fatigue (optional) | T1621 | SigninLogs | Medium | CTL-001, CTL-011 |
| DET-012 | Break-glass account used | T1078.004 | SigninLogs | High | CTL-004, CTL-011 |
| DET-013 | New credential on an app or AI agent identity | T1098.001 | AuditLogs | Medium | CTL-006, CTL-007, CTL-011 |

Tactics covered: Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Collection, Exfiltration. Not covered on purpose: execution, lateral movement and command and control, which need endpoint or network telemetry this lab does not collect.

## Sheet rules

- `techniques` holds parent IDs only (what the Sentinel API accepts in Terraform). Sub-techniques go in `attack`, each with its parent in `techniques`.
- `thresholds.lab` is what the lab runs; `thresholds.production_starting_point` is an assumption for discussion, never a tuned value.
- `assumptions` lists every field value not yet observed. A rule cannot reach `validated` while an assumption is open.
- Test IDs follow `docs/04-conventions.md`: DET-n has TC-(199 + 2n) positive and TC-(200 + 2n) negative.
- A rule is enabled only once its table has data (Sentinel rejects a query on a missing table).

## Adding a rule

1. Copy an existing sheet and query, take the next DET number.
2. Fill every key, including `controls`; add the row to `catalog.csv`.
3. `python tools/validate_repo.py`.
4. Add the test rows to `testing/detection-test-matrix.csv`.
