# Evidence handling

Trials end and tenants are deleted. Evidence that is not exported before day 25 is lost: the main lesson of the sister repo.

## Lifecycle of an evidence run

1. **Collect**: `collectors/Collect-Evidence.ps1` writes `evidence/runs/<UTC>/` (git-ignored), one envelope per item plus `manifest.json` (SHA-256 per file, repository commit).
2. **Evaluate**: `tools/evaluate_controls.py --run <dir> --out reports/results-<run>.json`.
3. **Archive**: zip the run folder with its results; upload to the evidence container (`az storage blob upload-batch --auth-mode login --account-name <account> -d evidence/<run> -s evidence/runs/<run>`); keep an offline copy. Versioning keeps any overwritten blob.
4. **Verify**: recompute the hashes of the downloaded copy and compare with the manifest.
5. **Publish**: only the dashboard (`reports/compliance-dashboard.md`, counts and masked names) and redacted extracts in `evidence-public/`.

## Integrity: what the lab does and what a bank would do

| Measure | Lab | Bank |
|---|---|---|
| Hash at collection | SHA-256 manifest | Same, signed |
| Storage | Versioning, soft delete 7 days, Entra auth only | Locked time-based immutability (WORM) for the retention period |
| Who can write | The maintainer | Collection identity only, no human write access |
| Chain of custody | Run ID, commit, operator role | Ticketed, segregated |

The lab does **not** use a locked immutability policy: it would prevent deleting the storage account until retention expires, which breaks teardown and the zero-cost rule.

## Detection test exports

| Item | How | Raw file |
|---|---|---|
| Query result proving the event | Rule query over the test window, CSV | `evidence/<TC>/query-<ts>.csv` |
| Incident | Screenshot and JSON via the API | `evidence/<TC>/incident-<ts>.png`, `.json` |
| Ingestion delay | `extend Ingested = ingestion_time()` | in the CSV |
| Playbook run | Logic App run history | `evidence/<TC>/pb-run-<ts>.json` |

Lab-wide before teardown: analytics rules as deployed, `terraform show -json` (outside the repo, contains IDs), workspace usage per table and day, Cost Management export.

## Redaction before anything goes to `evidence-public/`

Remove or mask: tenant ID, subscription ID, workspace ID, object IDs, resource IDs (`/subscriptions/<id>/...`), incident and alert GUIDs, lab domain, user principal names (keep `user1`, `bg-01`), workstation IP, browser address and status bars. Strip PNG metadata. `tools/validate_repo.py` fails on any GUID or `/subscriptions/` path that is not a placeholder: a safety net, not a substitute for review.
