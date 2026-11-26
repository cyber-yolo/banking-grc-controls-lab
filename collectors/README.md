# Evidence collectors

`Collect-Evidence.ps1` reads `items.csv` and collects each evidence item **read-only**. One run writes one folder `evidence/runs/<UTC timestamp>/` (git-ignored) with one JSON envelope per item and a `manifest.json` holding the SHA-256 of every file.

## Why PowerShell for collection and Python for evaluation

- Collection talks to Microsoft APIs from the maintainer's Windows workstation: the Microsoft Graph PowerShell SDK, the Azure CLI and Security & Compliance PowerShell are the supported, signed-in tools, with delegated read-only scopes and no stored secret.
- Evaluation is pure logic on JSON files: Python, testable offline in CI with synthetic fixtures (`tests/fixtures/`).

## Prerequisites

| Tool | Install | Used for |
|---|---|---|
| PowerShell 7 | `winget install Microsoft.PowerShell` | the script |
| Microsoft Graph PowerShell SDK | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` | `graph` items |
| ExchangeOnlineManagement | `Install-Module ExchangeOnlineManagement -Scope CurrentUser` | `ipps` items (Purview DLP) |
| Azure CLI with the log-analytics extension | `winget install Microsoft.AzureCLI`, `az extension add --name log-analytics` | `az`, `az-rest`, `kql` items |

## Item methods

| Method | Source | Notes |
|---|---|---|
| `graph` | Microsoft Graph v1.0, paged | Delegated scopes listed in `permission`; admin consent once in the lab |
| `az` | Azure CLI command | `{resource_group}`, `{workspace}` filled from parameters |
| `az-rest` | Azure Resource Manager GET | `{subscription}` from `az account show` |
| `kql` | Log Analytics query from `queries/` | Needs `-WorkspaceId` |
| `ipps` | Security & Compliance PowerShell `Get-*` cmdlet | |
| `repo` | A file of this repository | Read directly by the evaluator |
| `manual` | A record filled by a person | Reviewed, not machine-checked |

## Rules

1. Never run the collector against a tenant other than the lab.
2. Never commit `evidence/`. Public extracts go through the redaction rules in `docs/08-evidence-handling.md`.
3. A failed item writes an envelope with `status: error`; the evaluator reports `NO_EVIDENCE` for its assertions instead of guessing.
4. Endpoints, permissions and API versions marked TO VERIFY in `items.csv` are confirmed on the first run (TC-301 and following) and the file is corrected.
