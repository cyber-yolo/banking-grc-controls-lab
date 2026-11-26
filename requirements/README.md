# Requirements catalogue

One YAML file per instrument. Each entry is a **paraphrase** of a requirement, written for traceability. It is not the legal text and never replaces it. Always read the official text at `source_url`.

## Fields

| Field | Meaning |
|---|---|
| `id` | `REQ-<FRAMEWORK>-<nn>`, stable, never reused |
| `reference` | Article, paragraph, section or margin number in the official text |
| `topic` | Own-words summary of what is required |
| `confidence` | Author's confidence that `reference` points to the right place: `high`, `medium`, `low` |
| `lab_scope` | `in` (a control covers it), `partial` (a control covers part of it), `out` (not covered, `note` says why) |
| `note` | Limits, interpretation, open points |

File-level fields: `instrument`, `source_url`, `applies_from`, `verified_on`.

## Verification rule

`verified_on: null` means **nobody has yet checked these references against the official text**. Every reference in such a file is TO VERIFY, whatever its `confidence`. The maintainer sets `verified_on` (UTC date) only after reading each entry against the source, and records corrections in the CHANGELOG. `low` confidence entries must be checked before any public claim is made about them.

`tools/validate_repo.py` refuses an `in` or `partial` requirement that no control maps, and an `out` requirement without a `note`.
