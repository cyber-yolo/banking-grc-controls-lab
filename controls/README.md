# Controls

One sheet per control in `sheets/CTL-xxx.yaml`. `catalog.csv` is a flat index checked against the sheets by `tools/validate_repo.py`. The generated cross-reference is in [`../docs/traceability-matrix.md`](../docs/traceability-matrix.md).

## Sheet keys

| Key | Meaning |
|---|---|
| `type` | `preventive`, `detective`, `corrective`, `directive` |
| `automation` | `automated` (all evidence by API), `semi-automated` (API plus human review), `manual` |
| `owner_role`, `reviewer_role` | First line runs it, second line challenges it |
| `risks`, `requirements` | IDs from `risk/risk-register.csv` and `requirements/` |
| `implementation.terraform` | File that configures it, or `null` when configured by hand |
| `evidence` | `EV-xxx` with an `item` from `collectors/items.csv` |
| `assertions` | Machine-checked statements, `test: design` or `test: effectiveness`; implemented in `tools/evaluate_controls.py` |
| `tests` | `design` TC-(299 + 2n) and `effectiveness` TC-(300 + 2n) |
| `detections` | Sentinel rules that see a failure or abuse of this control |
| `limits` | What the control does not cover in the lab |

## Adding a control

1. Copy a sheet, take the next number, fill every key.
2. Add evidence items to `collectors/items.csv` and, for assertions, a function decorated with `@assertion("CTL-xxx-An")` in `tools/evaluate_controls.py`, with a pass and a fail case in `tests/fixtures/`.
3. Add the row to `catalog.csv` and the two rows to `testing/control-test-matrix.csv`.
4. `python tools/validate_repo.py && python -m pytest -q && python tools/build_report.py`.

The unit tests refuse an assertion declared in a sheet but not implemented, and the reverse.
