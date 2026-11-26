# Conventions

## Identifiers

| Prefix | Object | Example | Note |
|---|---|---|---|
| `REQ-<FW>-nn` | Requirement | REQ-DORA-05 | Never reused, even if deleted |
| `CTL-nnn` | Control | CTL-003 | One YAML sheet each |
| `CTL-nnn-An` | Assertion | CTL-003-A1 | Implemented in `tools/evaluate_controls.py` |
| `EV-nnn` | Evidence item reference in a sheet | EV-001 | Points to an `item` of `collectors/items.csv` |
| `RSK-nn` | Risk | RSK-02 | `risk/risk-register.csv` |
| `RA-nnn` | Risk acceptance | RA-001 | `risk/acceptances/` |
| `SCN-Gnn` | Banking threat scenario | SCN-G05 | `G` avoids collision with the sister repo's SCN-0xx |
| `DET-nnn` | Analytics rule | DET-012 | |
| `PB-nnn`, `AR-nnn` | Playbook, automation rule | PB-001 | |
| `TC-2nn` | Detection test | TC-223 | DET-n: TC-(199 + 2n) positive, TC-(200 + 2n) negative |
| `TC-3nn` | Control test | TC-305 | CTL-n: TC-(299 + 2n) design, TC-(300 + 2n) effectiveness |
| `TT-nnn` | Tabletop exercise | TT-001 | |
| `TP-nnn` | ICT third-party arrangement | TP-003 | |
| `AI-nnn` | AI system | AI-001 | |
| `PV-POL-nnn` | Purview policy | PV-POL-001 | Defined in the sister repo |

## Lab naming

Break-glass accounts `bg-01`, `bg-02`. Users `user1`, `user2`, `admin`. AI agent apps `app-agent-<purpose>`, tagged `ai-agent`. Risk acceptance on an app: tag `grc-ra:RA-xxx`.

## Azure resource names

`<type>-<prefix>-<purpose>`, lower case, prefix in `terraform.tfvars` (default `bgcl`). Tags `project`, `environment = lab`, `owner`, `expires_on`, `managed_by` on every resource.

## Times

UTC, ISO 8601 (`2026-12-03T14:05Z`). Local time in brackets with its zone when useful.

## Commits

Imperative subject under 72 characters, scope prefix when useful (`controls:`, `requirements:`, `detections:`, `infra:`, `docs:`). Merge by squash.
