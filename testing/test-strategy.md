# Test strategy

Two families of tests, two ranges of IDs, one rule: no result without evidence.

| Family | What it proves | IDs | Matrix |
|---|---|---|---|
| Control tests | A control is designed as stated (design) and works over time (operating effectiveness) | TC-301 to TC-332 | `control-test-matrix.csv` |
| Detection tests | A threat action produces a log event, the event reaches the workspace, the rule raises the right incident | TC-200 to TC-240 | `detection-test-matrix.csv` |

The sister repository uses TC-001 to TC-118; the ranges never overlap.

## Design versus operating effectiveness

This is the distinction auditors make, and the lab keeps it:

- **Test of design** (odd TC-3xx): is the control configured so that, if it runs, it meets its objective? Mostly a configuration export checked by assertions (for example CTL-001-A1: an enabled MFA policy for all users exists).
- **Test of operating effectiveness** (even TC-3xx): did the control actually operate over a period? Mostly logs (for example CTL-001-A3: 99 % of sign-ins over 7 days satisfied MFA) or a deliberate attempt that must fail (TC-304, TC-326).

A control is reported `EFFECTIVE` only when both kinds of assertion PASS. Configuration alone gives `DESIGN_ONLY`.

## Execution rules

1. Record the UTC time of every action and the evidence run ID (`evidence/runs/<timestamp>`).
2. Evaluate with `python tools/evaluate_controls.py --run <run> --out reports/results-<run>.json`; never edit a result by hand.
3. A FAIL stays in the matrix with its analysis; a fix creates a new run, it does not overwrite the FAIL.
4. A sample is stated with its size and period ("200 sign-ins over 7 days"), never as "all".
5. Detection tests follow the rules of the detection module: wait one full rule period plus the ingestion delay measured in TC-200, run positive and negative tests twice.
6. Manual controls (CTL-008, CTL-012) need a reviewer sign-off in the run sheet; in the lab the maintainer signs both roles and says so.

## Status values

`NOT RUN`, `PASS`, `FAIL`, `BLOCKED` (prerequisite missing, for example Copilot licence), `N/A`.
