# Cloud posture remediation register

`remediation-register.csv` tracks every Defender for Cloud recommendation of severity High or Medium that is unhealthy on the lab subscription, from detection to verified closure (CTL-015).

| Column | Values |
|---|---|
| `id` | `REM-nnn`, never reused |
| `recommendation` | Recommendation display name, exactly as Defender for Cloud shows it (the evaluator matches on it) |
| `decision` | `fix` or `accept` |
| `owner_role` | A role, never a person's name |
| `ticket` | Change or issue reference, empty in the lab until a GitHub issue is opened |
| `risk_acceptance` | `RA-nnn` when `decision` is `accept`; the record must exist in `risk/acceptances/` |
| `status` | `open` or `closed` |
| `closed_on` | `YYYY-MM-DD` when `status` is `closed` |
| `origin` | `anticipated` (written before the first run) or `run:<run id>` (seen in an evidence run) |
| `notes` | Free text, no resource ID |

## Rules checked by the evaluator

- **CTL-015-A5**: every unhealthy High or Medium recommendation in the evidence has a row. Low severity is reported in the portal but not tracked here (lab choice).
- **CTL-015-A6**: a `fix` row still open after its service level fails (High 30 days, Medium 90 days, Low 180 days, counted from Defender's first evaluation date); a `closed` row whose recommendation is still unhealthy fails, so closure is proven by the next evidence run, not by the register; an `accept` row needs a risk acceptance record.

`validate_repo.py` checks the columns and allowed values on every commit.

## Rows at v0.1

REM-001 and REM-002 are **anticipated**: they are the recommendations a new subscription with one owner is expected to show. They are not observed findings. After the first evidence run (TC-329), confirm the exact names, set `origin` to the run ID, and add any other High or Medium finding.
