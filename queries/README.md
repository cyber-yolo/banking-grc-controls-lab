# Effectiveness queries

KQL run by the collector (`kql` items in `collectors/items.csv`) to measure whether a control operated over a period. Each query returns one small summary row or one row per table; the evaluator reads the column names used here, so a change to a column name needs the matching change in `tools/evaluate_controls.py`.

Field values assumed but not yet observed (for example where PIM writes the justification) are listed in `docs/10-assumptions-and-limits.md`.
