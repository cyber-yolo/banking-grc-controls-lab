# Banking threat scenarios

`scenarios.yaml` is the source. Each scenario links risks (`risk/risk-register.csv`), controls (`controls/`) and detections (`detections/`). CTL-011 checks that every scenario has at least one deployed detection.

| ID | Scenario | Controls | Detections |
|---|---|---|---|
| SCN-G01 | Insider sends client IBANs to a personal address | CTL-009, CTL-011, CTL-012 | DET-001, DET-002 |
| SCN-G02 | Mass download or anonymous sharing of a client library | CTL-009, CTL-013, CTL-011 | DET-007, DET-008 |
| SCN-G03 | Privileged access abused to switch off controls | CTL-003, CTL-004, CTL-005, CTL-010, CTL-011 | DET-006, DET-009, DET-012 |
| SCN-G04 | Account takeover then payment fraud (BEC) | CTL-001, CTL-002, CTL-011 | DET-003, DET-004, DET-005, DET-011 |
| SCN-G05 | AI agent or integration identity abused | CTL-006, CTL-007, CTL-008, CTL-011 | DET-010, DET-013 |

The `G` in the IDs keeps them apart from the sister repo's `SCN-0xx` scenarios.
